//! rootless 系の結合試験（`rootless`・`rootless_file_owner`・`rootless_uid_mapping`）と `production_launcher` の
//! rootfs 構築の共有部品、および rootless 系が代役の init ではなく実エントリポイントを exec まで通すための共有部品（CORE-6・SEC-5・SEC-1・CORE-5・REPAIR-3・REPAIR-12。
//! TASK-40.4 追補・#2012）。
//!
//! # 背景
//! 制限適用の証跡 `LaunchReady` が無い起動は exec の手前で fail-closed に拒否される（#1714）。そのため従来の
//! rootless 系試験は、exec の代わりに中間プロセスやテストバイナリ自身でコンテナの振る舞いを演じていた。
//! 本モジュールは試験バイナリ自身を rootfs の `/entry` へコピーして `--entry <mode>` で再入させる
//! （実エントリポイント）ための部品を持つ。exec まで到達させるステージ列（`with_landlock` 入り）は本番 launcher が組む。
//!
//! # 本番 launcher 経由の部品（#2246）
//! `rootless`・`rootless_file_owner`・`rootless_uid_mapping`（#2391）は本番 `ProductionLauncher` を通すため、launcher の組み立て
//! （`rootless_launcher`）・単一スレッドへの戻りの待ち（`wait_single_thread`）・範囲写像の期待値
//! （`helper_mappings`）・rootfs 構築（`install_entry`・`write_rootless_config`）をここに集約する。
//! 本番 launcher 経由でも観測値は `/entry-report` のファイルで受ける（実エントリポイントの標準入出力は
//! `/dev/null` へ置換されるため）。直接ステージ経路の部品（`entrypoint_from`・`landlock_ruleset`）は `seccomp` だけが使う。
//!
//! # 取り込み方
//! 各テストのクレート直下（`#[cfg(target_os = "linux")]`）で `#[path = "support/real_entry.rs"] mod real_entry;`
//! として取り込む。`tests/support/` には `main.rs` が無いため cargo の自動検出の対象にならない。
//!
//! # 契約
//! - 実エントリポイントの標準入出力は `/dev/null` へ置換される（`StdioNulling::ALL`。本番 launcher と直接ステージ経路の両方）ため、観測値は pivot 後の
//!   `/` 直下の報告ファイル（`/entry-report`。`key=value` 行。最終行は `done=1`）へ書き、ホスト側は
//!   `<rootfs>/entry-report` として読む。rename は使わない（Landlock の REFER 権限に依存しないため）
//! - Landlock の ABI 6 以上（Linux 6.12 以上）を要する。満たさない環境は検出の失敗で panic（失敗）にし、
//!   検証せずに成功する分岐は持たない（ci.md「実機前提テスト」）
//! - 失敗はすべて panic。待ちはすべて期限つき（REPAIR-5）で、外部入力（報告ファイル）の長さ・行数に上限を設ける
//! - 実エントリポイントには寿命の上限を付ける（#2250・#2436・CORE-1・REPAIR-5）。`arm_entry_lifetime` が見張りスレッドを
//!   起こし、上限（`process.env` の `ENTRY_LIFETIME_ENV`。無い・範囲外なら `ENTRY_LIFETIME_MAX_SECS`）に達したら
//!   `EXIT_ENTRY_LIFETIME_EXPIRED` で自ら終わる。PID 1 が終わればカーネルが PID namespace ごと落とすため、ハーネスが
//!   固まる・外から殺されてもホストに残るのは上限までになる。無期限にはしない（fail-closed）

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::audit_log::{AuditRecord, AuditSink};
use fandhe_container_core::dev_mounts::ImplicitDevMounts;
use fandhe_container_core::exec::{Entrypoint, IsolationPrivilege};
use fandhe_container_core::landlock::{LandlockRuleset, build_path_rules_with_dev};
use fandhe_container_core::oci_runtime::{
    ProcessLauncher, ProductionLauncher, SubordinateIdSource, parse_config_bytes,
};
use fandhe_container_core::rootless::{
    IdMapSet, SubIdOwner, load_subordinate_ids, rootless_mapping,
};
use fandhe_container_core::traits::TraitError;

/// 前提欠如を `PRECONDITION FAILED` の 1 行目で失敗させる共有部品（#2888・REPAIR-12）。本モジュールを取り込む試験が
/// `real_entry::precondition` として使う（`production_launcher` の委譲 cgroup・範囲写像の検査と各 `main` の自己照合）。
#[path = "precondition.rs"]
pub mod precondition;

/// コンテナ内のエントリポイントのパス（rootfs の `/entry`）。
pub const ENTRY_PATH: &str = "/entry";
/// エントリポイントが書く報告ファイルの名前（コンテナ内では `/entry-report`）。
#[allow(dead_code)] // 本番 launcher 経由の試験（`production_launcher`）は使わない
pub const REPORT_FILE: &str = "entry-report";
/// 報告ファイル全体の上限（バイト）。無制限の読み取りを避ける。
#[allow(dead_code)] // 本番 launcher 経由の試験（`production_launcher`）は使わない
const REPORT_MAX_BYTES: u64 = 16 * 1024;
/// 報告ファイルの行数の上限。
#[allow(dead_code)] // 本番 launcher 経由の試験（`production_launcher`）は使わない
const REPORT_MAX_LINES: usize = 128;

/// `path` までの祖先を 1 階層ずつ `lstat` して非 symlink のディレクトリだけを許容し、無ければ `create_dir` で作って
/// 0755 にする（`create_dir_all` は途中の symlink を辿るため使わない。基点の bundle は呼び出し元が 0700 で排他作成済み。
/// #2324・SEC-2）。rootfs 構築の 4 本の試験（`production_launcher`・`rootless`・`rootless_file_owner`・
/// `rootless_uid_mapping`）が共有する。失敗は panic。
pub fn mkdir(path: &Path) {
    let mut chain: Vec<&Path> = path.ancestors().filter(|a| a.parent().is_some()).collect();
    chain.reverse();
    for dir in chain {
        match std::fs::symlink_metadata(dir) {
            Ok(md) => assert!(
                md.is_dir() && !md.file_type().is_symlink(),
                "{} exists and is not a plain directory",
                dir.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
            }
            Err(e) => panic!("lstat {}: {e}", dir.display()),
        }
    }
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
pub fn elf_interp(exe: &[u8]) -> Option<String> {
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

/// 試験バイナリ自身を `rootfs/<dest_name>`（0755）へ置き、動的ローダと読み込み済みの共有ライブラリを同じ絶対パスへ
/// コピーする。`rootfs` と `dirs`（rootfs 直下のディレクトリ名。`proc` など）を先に作る。作成の順序は
/// 「ディレクトリ → バイナリ → ローダ・共有ライブラリ」。戻り値は config の `env` に渡す `LD_LIBRARY_PATH` の値。
/// `production_launcher`（`/probe`）と rootless 系 3 本（`/entry`）が配置名とディレクトリ構成だけを変えて呼ぶ。
pub fn install_binary_at(rootfs: &Path, dest_name: &str, dirs: &[&str]) -> String {
    mkdir(rootfs);
    for d in dirs {
        mkdir(&rootfs.join(d));
    }
    let exe = std::env::current_exe().expect("current_exe");
    let exe = std::fs::canonicalize(exe).expect("canonicalize exe");
    let dest = rootfs.join(dest_name);
    std::fs::copy(&exe, &dest).expect("copy the test binary");
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
        .expect("chmod the test binary");

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

/// 試験バイナリ自身を rootfs の `/entry` へ置く（実エントリポイント）。`rootfs/proc`（pivot 後に proc を載せる先）と
/// `rootfs/dev`（暗黙の /dev のマウント先。無いと本番 launcher が fail-closed で拒否する）も作る。戻り値は config の `env` に渡す `LD_LIBRARY_PATH` の値。
#[allow(dead_code)] // 取り込み元によっては使わない（`production_launcher` は `install_binary_at` を直接呼ぶ）
pub fn install_entry(rootfs: &Path) -> String {
    install_binary_at(rootfs, ENTRY_PATH.trim_start_matches('/'), &["proc", "dev"])
}

/// rootless 系 3 本（`rootless`・`rootless_file_owner`・`rootless_uid_mapping`）が本番 `ProductionLauncher` へ渡す最小の `config.json` を
/// `bundle/config.json` へ書く（`create_new`）。`root.readonly=false`・`process.user` 0/0・`cwd` `/`・namespaces は
/// pid / mount / uts / ipc / user。`linux.uidMappings` は書かない（start が拒否する。写像は launcher の責務）。
/// `args` / `env` は `entry_args` / `entry_env` を渡す。
#[allow(dead_code)] // 取り込み元によっては使わない（`production_launcher`・`seccomp` は使わない）
pub fn write_rootless_config(bundle: &Path, hostname: &str, args: &[String], env: &[String]) {
    let config = serde_json::json!({
        "ociVersion": "1.2.0",
        "root": {"path": "rootfs", "readonly": false},
        "process": {
            "user": {"uid": 0, "gid": 0},
            "args": args,
            "env": env,
            "cwd": "/"
        },
        "hostname": hostname,
        "linux": {"namespaces": [
            {"type": "pid"}, {"type": "mount"}, {"type": "uts"}, {"type": "ipc"}, {"type": "user"}
        ]}
    });
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(bundle.join("config.json"))
        .expect("create config.json");
    f.write_all(&serde_json::to_vec(&config).expect("serialize config"))
        .expect("write config.json");
}

/// 実エントリポイントの argv（`/entry --entry <mode>`）。`config.json` の `process.args` と
/// `entrypoint_from` の入力に使う。
#[allow(dead_code)] // 本番 launcher 経由の試験（`production_launcher`）は使わない
pub fn entry_args(mode: &str) -> Vec<String> {
    vec![
        ENTRY_PATH.to_string(),
        "--entry".to_string(),
        mode.to_string(),
    ]
}

/// 実エントリポイントの環境変数（`PATH=/` と、コピーした共有ライブラリの `LD_LIBRARY_PATH`）。
#[allow(dead_code)] // 本番 launcher 経由の試験（`production_launcher`）は使わない
pub fn entry_env(ld_library_path: &str) -> Vec<String> {
    vec![
        "PATH=/".to_string(),
        format!("LD_LIBRARY_PATH={ld_library_path}"),
    ]
}

/// argv の先頭をパスとする `Entrypoint` を作る（`rootless` は launcher が受け取った `LaunchSpec` の
/// `args` / `env`、他の 2 本は `entry_args` / `entry_env` を渡す）。検証（NUL・件数・長さ）は `Entrypoint::new` が行う。
#[allow(dead_code)] // 直接ステージ経路を使う `seccomp` だけが使う（本番 launcher 経由の試験は使わない）
pub fn entrypoint_from(args: &[String], env: &[String]) -> Entrypoint {
    let path = args.first().expect("argv must not be empty");
    Entrypoint::new(path, args, env).expect("entrypoint")
}

/// `root.readonly=false`・追加 mounts なしの config から、実カーネルの ABI を検出して Landlock ruleset を作る
/// （fork 前に親が作る）。専用の `/dev` を pivot 前に載せるため `/dev/shm` を除く暗黙の許可を足す
/// （`fork_exec_isolation` の `landlock-exec` と同じ。#1657）。
#[allow(dead_code)] // 直接ステージ経路を使う `seccomp` だけが使う（本番 launcher 経由の試験は使わない）
pub fn landlock_ruleset() -> LandlockRuleset {
    let json = r#"{"ociVersion":"1.2.0","root":{"path":"rootfs","readonly":false},"mounts":[]}"#;
    let config = parse_config_bytes(json.as_bytes()).expect("valid config");
    let support = precondition::landlock_support();
    build_path_rules_with_dev(
        &support,
        config.root(),
        config.mounts(),
        ImplicitDevMounts::WithoutShm,
    )
    .unwrap_or_else(|e| panic!("landlock rules: {e}"))
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
#[allow(dead_code)] // 本番 launcher 経由の試験（`production_launcher`）は使わない
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
#[allow(dead_code)] // 本番 launcher 経由の試験（`production_launcher`）は使わない
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
#[allow(dead_code)] // 本番 launcher 経由の試験（`production_launcher`）は使わない
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
#[allow(dead_code)] // 本番 launcher 経由の試験（`production_launcher`）は使わない
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

#[allow(dead_code)] // 本番 launcher 経由の試験（`production_launcher`）は使わない
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

/// 監査レコードをメモリへ追記するだけの sink（本試験群は監査内容を照合しない。監査の配送は別の試験が担う）。
pub struct MemSink(Mutex<Vec<String>>);

impl AuditSink for MemSink {
    fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(format!("{record:?}"));
        Ok(())
    }
}

/// rootless 系の試験が `start` へ渡す本番 `ProductionLauncher` を組む（CORE-6・SEC-5。#2246）。
/// `subordinate` が false なら `RootlessSingleId`（`0 <euid> 1`）、true なら `RootlessSubordinateIds`
/// （`SubordinateIdSource::system(USER)`。`/etc/subuid`・`/etc/subgid` の範囲写像。`uidmap` が要る）。
/// cgroup には参加させない（config に `linux.resources`・`cgroupsPath` が無いため `cgroup_join_source` 不要）。
/// root で `RootlessSubordinateIds` を組むと `PermissionDenied` で拒否される（SEC-5。root 実行時の照合用に
/// `Result` のまま返す）。
#[allow(dead_code)] // 取り込み元によっては使わない（`production_launcher`・`seccomp` は使わない）
pub fn build_rootless_launcher(subordinate: bool) -> Result<ProductionLauncher, TraitError> {
    let builder =
        ProductionLauncher::builder().audit_sink(Arc::new(MemSink(Mutex::new(Vec::new()))));
    if subordinate {
        builder
            .privilege(IsolationPrivilege::RootlessSubordinateIds)
            .subordinate_ids(SubordinateIdSource::system(std::env::var("USER").ok())?)
            .build()
    } else {
        builder
            .privilege(IsolationPrivilege::RootlessSingleId)
            .build()
    }
}

/// `build_rootless_launcher` の失敗を panic（失敗）にした版。opt-in 時に前提（`USER`・`uidmap`・自ユーザーの行）が
/// 無ければここで失敗する。
#[allow(dead_code)] // 取り込み元によっては使わない
pub fn rootless_launcher(subordinate: bool) -> Arc<dyn ProcessLauncher> {
    Arc::new(
        build_rootless_launcher(subordinate)
            .unwrap_or_else(|e| panic!("build production launcher: {e:?}")),
    )
}

/// 呼び出しプロセスが単一スレッドに戻るのを待つ（`ProductionLauncher` は単一スレッドを要求し、複数スレッドなら
/// `FailedPrecondition` で拒否する。join 済みスレッドの消滅は僅かに遅れ得る。REPAIR-5 で期限つき）。
#[allow(dead_code)] // 取り込み元によっては使わない
pub fn wait_single_thread() {
    let deadline = Instant::now() + Duration::from_secs(30);
    while status_value("Threads:") != "1" {
        assert!(
            Instant::now() < deadline,
            "the test process must be single-threaded before a launch"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// `/etc/subuid`・`/etc/subgid` の自ユーザー行から、launcher と同じ規則で範囲写像の期待値を求める。
/// 所有者の照合は subuid・subgid のどちらにも `euid`（と `USER`）を使う（launcher の `resolve_privilege` と同じ。
/// shadow-utils の subgid の第 1 欄はユーザー名か uid で、gid ではない）。
#[allow(dead_code)] // 取り込み元によっては使わない
pub fn helper_mappings(euid: u32, egid: u32) -> (IdMapSet, IdMapSet) {
    // 前提（USER・helper・自ユーザーの行）の欠如は、回帰と見分けられる 1 行目で失敗させる（#2888）。
    precondition::require_subordinate_ids(euid);
    let name = std::env::var("USER").ok();
    let owner = SubIdOwner::new(euid, name).expect("subid owner");
    let uranges = load_subordinate_ids(Path::new("/etc/subuid"), &owner).expect("load /etc/subuid");
    let granges = load_subordinate_ids(Path::new("/etc/subgid"), &owner).expect("load /etc/subgid");
    assert!(
        !uranges.is_empty() && !granges.is_empty(),
        "helper case requires subuid/subgid entries for the current user"
    );
    (
        rootless_mapping(euid, &uranges).expect("uid range mapping"),
        rootless_mapping(egid, &granges).expect("gid range mapping"),
    )
}

/// 実エントリポイントの寿命の上限（秒）を渡す `process.env` のキー（#2250・#2436・CORE-1・REPAIR-5）。
/// 値は試験自身が bundle の config に書く（`lifetime_env`）。
#[allow(dead_code)] // production_launcher・seccomp は使わない
pub const ENTRY_LIFETIME_ENV: &str = "FANDHE_CONTAINER_TEST_ENTRY_LIFETIME_SECS";

/// 寿命の上限として受け付ける最大（秒）。env が無い・範囲外のときもこの値で打ち切り、無期限にはしない。
#[allow(dead_code)] // production_launcher・seccomp は使わない
pub const ENTRY_LIFETIME_MAX_SECS: u64 = 3600;

/// 実エントリポイントが寿命の上限で自ら終わったときの終了コード。`EXIT_SETUP_FAILED`(125)・
/// `EXIT_EXEC_NOT_EXECUTABLE`(126)・`EXIT_EXEC_NOT_FOUND`(127) と重ならず、kill の `Signaled(9)` とも区別できる。
#[allow(dead_code)] // production_launcher・seccomp は使わない
pub const EXIT_ENTRY_LIFETIME_EXPIRED: i32 = 75;

/// config の `process.env` に足す寿命の上限の 1 行（`KEY=秒`）。
#[allow(dead_code)] // production_launcher・seccomp は使わない
pub fn lifetime_env(lifetime: Duration) -> String {
    format!("{ENTRY_LIFETIME_ENV}={}", lifetime.as_secs())
}

/// `process.env` から寿命の上限（秒）を読む。不在・解析不能・`1..=ENTRY_LIFETIME_MAX_SECS` の外は
/// `ENTRY_LIFETIME_MAX_SECS`（無期限にしない）。
#[allow(dead_code)] // production_launcher・seccomp は使わない
pub fn entry_lifetime_from_env() -> u64 {
    std::env::var(ENTRY_LIFETIME_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| (1..=ENTRY_LIFETIME_MAX_SECS).contains(s))
        .unwrap_or(ENTRY_LIFETIME_MAX_SECS)
}

/// 実エントリポイント（exec 後のコンテナ PID 1）の先頭で呼ぶ。見張りスレッドが寿命の上限まで眠り、来たら
/// `EXIT_ENTRY_LIFETIME_EXPIRED` で自ら終わる。処理自体が固まった場合にも効く。見張りを起こせなければ、
/// 上限なしで進まず報告を書く前に非 0 で終わる（fail-closed。ホスト側は期待した終了・報告が無く失敗になる）。
/// 戻り値は採用した上限（秒）で、報告の `lifetime_secs` に載せる。
#[allow(dead_code)] // production_launcher・seccomp は使わない
pub fn arm_entry_lifetime() -> u64 {
    let secs = entry_lifetime_from_env();
    let spawned = std::thread::Builder::new()
        .name("entry-lifetime".to_string())
        .spawn(move || {
            std::thread::sleep(Duration::from_secs(secs));
            std::process::exit(EXIT_ENTRY_LIFETIME_EXPIRED);
        });
    if spawned.is_err() {
        std::process::exit(EXIT_ENTRY_LIFETIME_EXPIRED);
    }
    secs
}
