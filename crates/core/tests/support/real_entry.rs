//! rootless 系の結合試験（`rootless`・`rootless_file_owner`・`rootless_uid_mapping`）が、代役の init ではなく
//! 実エントリポイントを exec まで通すための共有部品（CORE-6・SEC-5・SEC-1・CORE-5・REPAIR-3・REPAIR-12。
//! TASK-40.4 追補・#2012）。
//!
//! # 背景
//! 制限適用の証跡 `LaunchReady` が無い起動は exec の手前で fail-closed に拒否される（#1714）。そのため従来の
//! rootless 系試験は、exec の代わりに中間プロセスやテストバイナリ自身でコンテナの振る舞いを演じていた。
//! 本モジュールは `StagePipeline::with_landlock` を載せたステージ列で exec まで到達させ、試験バイナリ自身を
//! rootfs の `/entry` へコピーして `--entry <mode>` で再入させる（実エントリポイント）。
//!
//! # 取り込み方
//! 各テストのクレート直下（`#[cfg(target_os = "linux")]`）で `#[path = "support/real_entry.rs"] mod real_entry;`
//! として取り込む。`tests/support/` には `main.rs` が無いため cargo の自動検出の対象にならない。
//!
//! # 契約
//! - 実エントリポイントの標準入出力は `/dev/null` へ置換される（`StdioNulling::ALL`）ため、観測値は pivot 後の
//!   `/` 直下の報告ファイル（`/entry-report`。`key=value` 行。最終行は `done=1`）へ書き、ホスト側は
//!   `<rootfs>/entry-report` として読む。rename は使わない（Landlock の REFER 権限に依存しないため）
//! - Landlock の ABI 6 以上（Linux 6.12 以上）を要する。満たさない環境は検出の失敗で panic（失敗）にし、
//!   検証せずに成功する分岐は持たない（ci.md「実機前提テスト」）
//! - 失敗はすべて panic。待ちはすべて期限つき（REPAIR-5）で、外部入力（報告ファイル）の長さ・行数に上限を設ける

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fandhe_container_core::dev_mounts::ImplicitDevMounts;
use fandhe_container_core::exec::{
    ContainerChild, DevptsGidSource, Entrypoint, StagePipeline,
    spawn_container_with_stages_and_devices,
};
use fandhe_container_core::landlock::{
    LandlockRuleset, build_path_rules_with_dev, detect_landlock_abi,
};
use fandhe_container_core::oci_runtime::parse_config_bytes;
use fandhe_container_core::rootless::IdMapSet;

/// コンテナ内のエントリポイントのパス（rootfs の `/entry`）。
pub const ENTRY_PATH: &str = "/entry";
/// エントリポイントが書く報告ファイルの名前（コンテナ内では `/entry-report`）。
pub const REPORT_FILE: &str = "entry-report";
/// 報告ファイル全体の上限（バイト）。無制限の読み取りを避ける。
const REPORT_MAX_BYTES: u64 = 16 * 1024;
/// 報告ファイルの行数の上限。
const REPORT_MAX_LINES: usize = 128;

fn mkdir(path: &Path) {
    std::fs::create_dir_all(path).unwrap_or_else(|e| panic!("mkdir {}: {e}", path.display()));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
}

/// `host` のファイルを rootfs 内の同じ絶対パスへ（実体の内容を通常ファイルとして）コピーする。
fn copy_into(rootfs: &Path, host: &Path, mode: u32) {
    let dest = rootfs.join(host.strip_prefix("/").expect("absolute path"));
    mkdir(dest.parent().expect("parent"));
    let _ = std::fs::remove_file(&dest);
    std::fs::copy(host, &dest)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", host.display(), dest.display()));
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("chmod {}: {e}", dest.display()));
}

/// ELF64（リトルエンディアン）の `PT_INTERP`（動的ローダのパス）を返す。範囲は `get()` で検査する。
fn elf_interp(exe: &[u8]) -> Option<String> {
    let u16_at = |o: usize| Some(u16::from_le_bytes(exe.get(o..o + 2)?.try_into().ok()?));
    let u32_at = |o: usize| Some(u32::from_le_bytes(exe.get(o..o + 4)?.try_into().ok()?));
    let u64_at = |o: usize| Some(u64::from_le_bytes(exe.get(o..o + 8)?.try_into().ok()?));
    if exe.get(0..4)? != b"\x7fELF" {
        return None;
    }
    let phoff = usize::try_from(u64_at(0x20)?).ok()?;
    let phentsize = usize::from(u16_at(0x36)?);
    let phnum = usize::from(u16_at(0x38)?);
    for i in 0..phnum {
        let base = phoff.checked_add(i.checked_mul(phentsize)?)?;
        if u32_at(base)? == 3 {
            let off = usize::try_from(u64_at(base + 8)?).ok()?;
            let len = usize::try_from(u64_at(base + 32)?).ok()?;
            let raw = exe.get(off..off.checked_add(len)?)?;
            let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            return String::from_utf8(raw.get(..end)?.to_vec()).ok();
        }
    }
    None
}

/// 自プロセスに読み込み済みの共有ライブラリの実パス（`/proc/self/maps` から。重複なし）。
fn loaded_libraries(exe: &Path) -> Vec<PathBuf> {
    let maps = std::fs::read_to_string("/proc/self/maps").expect("read /proc/self/maps");
    let mut libs: Vec<PathBuf> = Vec::new();
    for line in maps.lines() {
        let Some(path) = line.split_whitespace().nth(5) else {
            continue;
        };
        let p = PathBuf::from(path);
        if !path.starts_with('/')
            || p == exe
            || ["/dev/", "/proc/", "/sys/", "/tmp/", "/memfd:"]
                .iter()
                .any(|pre| path.starts_with(pre))
            || libs.contains(&p)
        {
            continue;
        }
        if std::fs::metadata(&p).is_ok_and(|m| m.is_file()) {
            libs.push(p);
        }
    }
    libs
}

/// 試験バイナリ自身を rootfs の `/entry` へ置き、動的ローダと読み込み済みの共有ライブラリを同じ絶対パスへ
/// コピーする。`rootfs/proc`（pivot 後に proc を載せる先）も作る。戻り値は config の `env` に渡す
/// `LD_LIBRARY_PATH` の値。
pub fn install_entry(rootfs: &Path) -> String {
    mkdir(rootfs);
    mkdir(&rootfs.join("proc"));
    let exe = std::env::current_exe().expect("current_exe");
    let exe = std::fs::canonicalize(exe).expect("canonicalize exe");
    let dest = rootfs.join(ENTRY_PATH.trim_start_matches('/'));
    std::fs::copy(&exe, &dest).expect("copy the entrypoint binary");
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
        .expect("chmod the entrypoint");

    let bytes = std::fs::read(&exe).expect("read exe");
    let mut lib_dirs: Vec<String> = Vec::new();
    if let Some(interp) = elf_interp(&bytes) {
        // ローダは PT_INTERP のパスのまま（シンボリックリンクを辿らず）rootfs 内で開かれるため、
        // 実体の内容をそのパスへ置く。
        copy_into(rootfs, Path::new(&interp), 0o755);
    }
    for lib in loaded_libraries(&exe) {
        copy_into(rootfs, &lib, 0o755);
        if let Some(dir) = lib.parent().and_then(Path::to_str)
            && !lib_dirs.iter().any(|d| d == dir)
        {
            lib_dirs.push(dir.to_string());
        }
    }
    lib_dirs.join(":")
}

/// 実エントリポイントの argv（`/entry --entry <mode>`）。`config.json` の `process.args` と
/// `entrypoint_from` の入力に使う。
pub fn entry_args(mode: &str) -> Vec<String> {
    vec![
        ENTRY_PATH.to_string(),
        "--entry".to_string(),
        mode.to_string(),
    ]
}

/// 実エントリポイントの環境変数（`PATH=/` と、コピーした共有ライブラリの `LD_LIBRARY_PATH`）。
pub fn entry_env(ld_library_path: &str) -> Vec<String> {
    vec![
        "PATH=/".to_string(),
        format!("LD_LIBRARY_PATH={ld_library_path}"),
    ]
}

/// argv の先頭をパスとする `Entrypoint` を作る（`rootless` は launcher が受け取った `LaunchSpec` の
/// `args` / `env`、他の 2 本は `entry_args` / `entry_env` を渡す）。検証（NUL・件数・長さ）は `Entrypoint::new` が行う。
pub fn entrypoint_from(args: &[String], env: &[String]) -> Entrypoint {
    let path = args.first().expect("argv must not be empty");
    Entrypoint::new(path, args, env).expect("entrypoint")
}

/// `root.readonly=false`・追加 mounts なしの config から、実カーネルの ABI を検出して Landlock ruleset を作る
/// （fork 前に親が作る）。専用の `/dev` を pivot 前に載せるため `/dev/shm` を除く暗黙の許可を足す
/// （`fork_exec_isolation` の `landlock-exec` と同じ。#1657）。
pub fn landlock_ruleset() -> LandlockRuleset {
    let json = r#"{"ociVersion":"1.2.0","root":{"path":"rootfs","readonly":false},"mounts":[]}"#;
    let config = parse_config_bytes(json.as_bytes()).expect("valid config");
    let support = detect_landlock_abi()
        .unwrap_or_else(|e| panic!("Landlock ABI 6+ is required for this test: {e}"));
    build_path_rules_with_dev(
        &support,
        config.root(),
        config.mounts(),
        ImplicitDevMounts::WithoutShm,
    )
    .unwrap_or_else(|e| panic!("landlock rules: {e}"))
}

/// `with_landlock` を載せたステージ列で実エントリポイントを PID 1 として起動する。呼び出し元は分離
/// （`isolate_rootless_subordinate`）済みの単一スレッドプロセスであること。失敗は panic。
pub fn spawn_real_entry(rootfs: &Path, entry: &Entrypoint, gid_map: &IdMapSet) -> ContainerChild {
    let stages = StagePipeline::new()
        .with_landlock(landlock_ruleset())
        .unwrap_or_else(|e| panic!("register landlock: {e}"));
    spawn_container_with_stages_and_devices(
        rootfs,
        entry,
        stages,
        DevptsGidSource::Rootless(gid_map),
    )
    .unwrap_or_else(|e| panic!("spawn the real entrypoint: {e}"))
}

/// 自プロセスの `/proc/self/status` の `key`（コロン付き）の値（先頭・末尾の空白を除く）。
fn status_value(key: &str) -> String {
    std::fs::read_to_string("/proc/self/status")
        .map(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
                .unwrap_or_else(|| "missing".to_string())
        })
        .unwrap_or_else(|e| format!("error:{:?}", e.kind()))
}

/// 実エントリポイント側の共通観測（`pid`・実効 `uid` / `gid`・`nonewprivs`・`seccomp`）。
pub fn entry_observations() -> Vec<(&'static str, String)> {
    let id = |key: &str| {
        status_value(key)
            .split_whitespace()
            .nth(1)
            .unwrap_or("missing")
            .to_string()
    };
    vec![
        ("pid", std::process::id().to_string()),
        ("uid", id("Uid:")),
        ("gid", id("Gid:")),
        ("nonewprivs", status_value("NoNewPrivs:")),
        ("seccomp", status_value("Seccomp:")),
    ]
}

/// 実エントリポイント側: `/entry-report` へ `key=value` 行と最後の `done=1` を書く（`create_new`。`sync_all` 済み）。
pub fn write_report(lines: &[(&str, String)]) {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(Path::new("/").join(REPORT_FILE))
        .unwrap_or_else(|e| panic!("create /{REPORT_FILE}: {e}"));
    let mut text = String::new();
    for (k, v) in lines {
        text.push_str(&format!("{k}={v}\n"));
    }
    text.push_str("done=1\n");
    f.write_all(text.as_bytes())
        .unwrap_or_else(|e| panic!("write /{REPORT_FILE}: {e}"));
    f.sync_all()
        .unwrap_or_else(|e| panic!("sync /{REPORT_FILE}: {e}"));
}

/// ホスト側: `path` の報告ファイルが `done=1` まで書き終わっていれば読んで返す（無ければ・書きかけなら `None`）。
/// 大きさ・行数に上限を設け、重複キー・未知の書式は panic にする（外部入力として扱う）。
pub fn try_read_report(path: &Path) -> Option<BTreeMap<String, String>> {
    use std::io::Read as _;
    let f = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    f.take(REPORT_MAX_BYTES)
        .read_to_string(&mut text)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    text.lines()
        .any(|l| l == "done=1")
        .then(|| parse_report(&text))
}

/// ホスト側: `path` の報告ファイルを `done=1` が現れるまで `limit` を上限にポーリングして読む（REPAIR-5）。
pub fn read_report(path: &Path, limit: Duration) -> BTreeMap<String, String> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(report) = try_read_report(path) {
            return report;
        }
        assert!(
            Instant::now() < deadline,
            "{} did not reach done=1 within {limit:?}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn parse_report(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (i, line) in text.lines().enumerate() {
        assert!(i < REPORT_MAX_LINES, "too many report lines");
        let (k, v) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("malformed report line {line:?}"));
        assert!(
            map.insert(k.to_string(), v.to_string()).is_none(),
            "duplicate report key {k:?}"
        );
    }
    map
}
