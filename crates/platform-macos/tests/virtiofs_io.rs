//! virtiofs 共有の read / write / readdir 結合試験（MAC-1・IO-5・TASK-65.4・MS-5）。
//!
//! IO-5 の「3 OS での read/write/readdir 疎通」のうち macOS（Virtualization.framework）の分と、
//! TASK-65.3 のゲスト mount 指示と報告の契約（`guest_mount`）の実機 e2e を兼ねる。大文字小文字衝突・
//! Unicode 正規化・長パス（IO-5 の他の期待）は対象外。他 OS では `#![cfg]` により 0 件になる。
//!
//! 二層構成:
//! - 既定集合: プローブ行の解釈・fixture・spec 組み立てなど VM 生成前に確定する経路を具体値で検証する。
//! - 実機テスト（`#[ignore]`）: macOS 13 以上・`com.apple.security.virtualization` 付き署名・
//!   `fandhe.virtiofs=` 指示と下記プローブ契約を実装したゲスト資産を要する。手順は AGENTS.md「実機前提テスト」節。
//!
//! プローブ契約（ゲスト init が実装する。ゲスト出力は untrusted として扱う）:
//! - `fandhe-guest-test: virtiofs-io v1 op=read value=<in/read.txt の 1 行目>`
//! - `fandhe-guest-test: virtiofs-io v1 op=readdir entries=<in/dir の名前のカンマ区切り>`
//! - `fandhe-guest-test: virtiofs-io v1 op=write result=done`（`out/write.txt` へ書いて sync 後）
//! - 失敗時 `... op=<op> result=error`、最後に `fandhe-guest-test: virtiofs-io v1 done`
//! - 名前空間 `fandhe-guest-test: virtiofs-io`（末尾に空白 1 つ）で始まる行はすべてプローブ行とみなし、上記の形に
//!   復号できないもの（版数違い・未知 op・空 value・上限超過・非 UTF-8 等）は位置によらず不正とする。
//!
//! 接頭辞は `guest_mount::REPORT_PREFIX`（`fandhe-guest: ...`）と先頭から食い違うため、mount 報告の走査に誤認されない。
//! read / readdir はコンソール報告、write だけは共有ファイルで検証し、write 経路の故障が他の判定を巻き込まない。
#![cfg(target_os = "macos")]

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fandhe_container_platform_macos::config::{
    BlockDeviceSpec, ConsoleLogPath, DeviceConfigSpec, DiskImagePath, SerialConsoleSink,
    VmConfigSpec, build_vz_configuration,
};
use fandhe_container_platform_macos::console_log::TRUNCATION_MARKER;
use fandhe_container_platform_macos::guest_mount::{self, GuestMountPoint};
use fandhe_container_platform_macos::virtiofs::{
    ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsSharesSpec, VirtiofsTag,
};
use fandhe_container_platform_macos::vm::{OpTimeouts, Vm, VmState};

/// プローブ行の名前空間。これで始まる行は版数によらずプローブ行として扱う（契約外なら不正）。
const PROBE_NAMESPACE: &str = "fandhe-guest-test: virtiofs-io ";
/// 本テストが解釈する版（v1）の接頭辞。`PROBE_NAMESPACE` で始まる。
const PROBE_PREFIX: &str = "fandhe-guest-test: virtiofs-io v1 ";
const SHARE_TAG: &str = "fandhe-io";
const GUEST_MOUNT: &str = "/mnt/fandhe/io";
const MAX_PROBE_LINE_BYTES: usize = 256;
const WRITE_LINE: &str = "fandhe-virtiofs-write-v1";
const WRITE_LINES: usize = 4096;
const MAX_OUT_ENTRIES: usize = 16;

static COUNTER: AtomicU64 = AtomicU64::new(0);

// 以下 Scratch / env_path / tail_lossy は vm_boot.rs からの複製（共通化は vm_boot.rs を巻き込むため別タスク）。

/// テストごとの新規ディレクトリ（0700）。`keep` が false なら `Drop` で削除する。
struct Scratch {
    dir: PathBuf,
    keep: bool,
}

impl Scratch {
    fn new(tag: &str, keep: bool) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(base).expect("create tmp base");
        let base = base.canonicalize().expect("canonicalize tmp base");
        for _ in 0..100 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = base.join(format!("{tag}-{}-{nanos}-{n}", std::process::id()));
            if std::fs::create_dir(&dir).is_ok() {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod scratch dir");
                return Self { dir, keep };
            }
        }
        panic!("could not create a fresh scratch directory");
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = self.dir.join(name);
        std::fs::write(&p, bytes).expect("write fixture");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
            .expect("chmod fixture");
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

fn tail_lossy(bytes: &[u8], max: usize) -> String {
    let start = bytes.len().saturating_sub(max);
    String::from_utf8_lossy(bytes.get(start..).unwrap_or_default()).into_owned()
}

/// ホストが起動前に共有へ置く fixture。
struct Fixture {
    share_dir: PathBuf,
    read_value: String,
    expected_entries: BTreeSet<String>,
}

/// `share/in/read.txt`・`share/in/dir/{a,b,c}-<nonce>`・空の `share/out/` を作る。
fn prepare_fixture(s: &Scratch) -> Fixture {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nonce = format!("{:x}{nanos:08x}{n:x}", std::process::id());
    let share_dir = s.dir.join("share");
    let dir = share_dir.join("in").join("dir");
    std::fs::create_dir_all(&dir).expect("create in/dir");
    std::fs::create_dir(share_dir.join("out")).expect("create out");
    let read_value = format!("fandhe-read-{nonce}");
    std::fs::write(
        share_dir.join("in").join("read.txt"),
        format!("{read_value}\n"),
    )
    .expect("write read.txt");
    std::fs::write(dir.join(format!("a-{nonce}")), b"a").expect("write a");
    std::fs::write(dir.join(format!("b-{nonce}")), b"b").expect("write b");
    std::fs::create_dir(dir.join(format!("c-{nonce}"))).expect("create c");
    let expected_entries = ["a", "b", "c"]
        .iter()
        .map(|p| format!("{p}-{nonce}"))
        .collect();
    Fixture {
        share_dir,
        read_value,
        expected_entries,
    }
}

/// コンソールログ・RW 共有・ゲスト mount 指定つきの spec。
fn probe_spec(
    s: &Scratch,
    f: &Fixture,
    kernel: &Path,
    initrd: Option<&Path>,
    disk: Option<&Path>,
    cmdline: &str,
) -> VmConfigSpec {
    let log = s.dir.join("console.log");
    let blocks = disk
        .iter()
        .map(|p| BlockDeviceSpec::root(DiskImagePath::try_new(p).expect("disk image path")))
        .collect();
    let devices = DeviceConfigSpec::try_new(
        blocks,
        Some(SerialConsoleSink::LogFile(
            ConsoleLogPath::try_new(&log).expect("console log path"),
        )),
    )
    .expect("device spec");
    let shares = VirtiofsSharesSpec::try_new(vec![
        VirtiofsShareSpec::new(
            VirtiofsTag::try_new(SHARE_TAG).expect("tag"),
            SharedDirectoryPath::try_new(&f.share_dir).expect("share dir"),
            ShareAccess::ReadWrite,
        )
        .with_guest_mount(GuestMountPoint::try_new(GUEST_MOUNT).expect("mount point")),
    ])
    .expect("shares");
    VmConfigSpec::from_parts(kernel, initrd, cmdline)
        .expect("spec")
        .with_devices(devices)
        .expect("with_devices")
        .with_shared_directories(shares)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProbeItem {
    Read(String),
    Readdir(String),
    Write,
    OpError(String),
    Done,
}

/// 1 行の分類結果。名前空間を持つ行は `Other` にならない（取りこぼしを不正として表に出すため）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProbeLine {
    /// プローブ名前空間で始まらない行（カーネル出力等）。無視してよい。
    Other,
    /// プローブ名前空間で始まるが契約の形に復号できない行。fail-closed で不正とする。
    Malformed,
    Item(ProbeItem),
}

/// 1 行を分類する。名前空間の判定は行頭の生バイトで先に行い、その後の上限超過・非 UTF-8・
/// 版数違い・未知 op・空 value はすべて `Malformed` とする（無視して見逃さない）。
fn parse_probe_line(line: &[u8]) -> ProbeLine {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if !line.starts_with(PROBE_NAMESPACE.as_bytes()) {
        return ProbeLine::Other;
    }
    if line.len() > MAX_PROBE_LINE_BYTES {
        return ProbeLine::Malformed;
    }
    decode_probe_item(line).map_or(ProbeLine::Malformed, ProbeLine::Item)
}

/// 名前空間を持つ行を v1 の契約どおりに復号する。形が崩れていれば `None`。
fn decode_probe_item(line: &[u8]) -> Option<ProbeItem> {
    let text = std::str::from_utf8(line).ok()?;
    let rest = text.strip_prefix(PROBE_PREFIX)?;
    if rest == "done" {
        return Some(ProbeItem::Done);
    }
    let rest = rest.strip_prefix("op=")?;
    let (op, field) = rest.split_once(' ')?;
    if field == "result=error" {
        return matches!(op, "read" | "readdir" | "write")
            .then(|| ProbeItem::OpError(op.to_string()));
    }
    match (op, field) {
        ("read", f) => f
            .strip_prefix("value=")
            .filter(|v| !v.is_empty())
            .map(|v| ProbeItem::Read(v.to_string())),
        ("readdir", f) => f
            .strip_prefix("entries=")
            .filter(|v| !v.is_empty())
            .map(|v| ProbeItem::Readdir(v.to_string())),
        ("write", "result=done") => Some(ProbeItem::Write),
        _ => None,
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ProbeLog {
    read: Option<String>,
    readdir: Option<String>,
    write_done: bool,
    errors: Vec<String>,
    done: bool,
    /// 同じ op の重複報告・done の重複・done 以降の後続報告・全 op 報告前の done・
    /// 復号できないプローブ行（矛盾の有無・位置によらず不正として扱う）。
    invalid: bool,
}

impl ProbeLog {
    /// 指定 op の失敗報告（`result=error`）があるか。
    fn has_error(&self, op: &str) -> bool {
        self.errors.iter().any(|e| e == op)
    }

    /// 指定 op の報告（成功値または失敗）が出ているか。
    fn reported(&self, op: &str) -> bool {
        let ok = match op {
            "read" => self.read.is_some(),
            "readdir" => self.readdir.is_some(),
            _ => self.write_done,
        };
        ok || self.has_error(op)
    }
}

/// コンソールログが書き出しスレッドの上限（`MAX_CONSOLE_LOG_BYTES`）で打ち切られたか。
/// 区切り文は上限到達時に末尾へ 1 回だけ書かれ、以後ゲスト出力は破棄されるため、
/// 末尾が区切り文ならプローブ行の後続は観測できない。
fn log_truncated(bytes: &[u8]) -> bool {
    bytes.ends_with(TRUNCATION_MARKER)
}

/// ログ全体を畳み込む。プローブ契約（AGENTS.md「最後に done」）に従い、次を `invalid`
/// （fail-closed）とする: op ごとの重複報告・done の重複・done 以降の後続報告・
/// read / readdir / write の全報告が揃う前の done・名前空間を持つが復号できない行（done の前後とも）。
///
/// ログは生バイトのまま `\n` で行に分割する（lossy 変換すると非 UTF-8 のプローブ行が置換文字で
/// 受理されてしまうため）。行末の `\r` は `parse_probe_line` が除く。
fn parse_probe_log(log: impl AsRef<[u8]>) -> ProbeLog {
    let mut out = ProbeLog::default();
    for line in log.as_ref().split(|b| *b == b'\n') {
        let item = match parse_probe_line(line) {
            ProbeLine::Other => continue,
            ProbeLine::Malformed => {
                out.invalid = true;
                continue;
            }
            ProbeLine::Item(item) => item,
        };
        if out.done {
            // done は最終行でなければならない（重複 done も後続報告もここで弾く）。
            out.invalid = true;
            continue;
        }
        match item {
            // 成功・失敗を合わせて op ごとに 1 回だけ報告できる。2 回目は種別によらず不正。
            ProbeItem::Read(v) => {
                out.invalid |= out.reported("read");
                out.read = Some(v);
            }
            ProbeItem::Readdir(v) => {
                out.invalid |= out.reported("readdir");
                out.readdir = Some(v);
            }
            ProbeItem::Write => {
                out.invalid |= out.reported("write");
                out.write_done = true;
            }
            ProbeItem::OpError(op) => {
                out.invalid |= out.reported(&op);
                out.errors.push(op);
            }
            ProbeItem::Done => {
                out.invalid |= !["read", "readdir", "write"]
                    .iter()
                    .all(|op| out.reported(op));
                out.done = true;
            }
        }
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
struct EntriesMismatch {
    missing: BTreeSet<String>,
    extra: BTreeSet<String>,
    /// 報告内で 2 回以上現れたエントリ（集合化で潰れるため別枠で検出する）。
    duplicate: BTreeSet<String>,
}

/// 期待集合と報告（カンマ区切り）を比較し、不足と余剰の両方を返す。
fn compare_entries(expected: &BTreeSet<String>, reported: &str) -> Result<(), EntriesMismatch> {
    let mut got: BTreeSet<String> = BTreeSet::new();
    let mut duplicate: BTreeSet<String> = BTreeSet::new();
    for e in reported.split(',').filter(|e| !e.is_empty()) {
        if !got.insert(e.to_string()) {
            duplicate.insert(e.to_string());
        }
    }
    let missing: BTreeSet<String> = expected.difference(&got).cloned().collect();
    let extra: BTreeSet<String> = got.difference(expected).cloned().collect();
    if missing.is_empty() && extra.is_empty() && duplicate.is_empty() {
        Ok(())
    } else {
        Err(EntriesMismatch {
            missing,
            extra,
            duplicate,
        })
    }
}

fn resolve_probe_timeout(raw: Option<String>) -> Result<Duration, String> {
    match raw {
        None => Ok(Duration::from_secs(60)),
        Some(v) => v
            .parse::<u64>()
            .ok()
            .filter(|n| (1..=600).contains(n))
            .map(Duration::from_secs)
            .ok_or_else(|| {
                "FANDHE_CONTAINER_MACOS_VM_PROBE_TIMEOUT_SECS must be an integer in 1..=600"
                    .to_string()
            }),
    }
}

/// VM 停止後に `out/write.txt` を検証する。ゲストは untrusted のため、停止後に symlink を拒否し、
/// 読み込みは期待長 + 1 バイトで打ち切る。
fn verify_write(share_dir: &Path) -> Result<(), String> {
    let out = share_dir.join("out");
    // out/ 自体がゲストにより symlink へ差し替えられていないかを先に確認する（read_dir は symlink を辿るため）。
    let out_meta = std::fs::symlink_metadata(&out).map_err(|e| format!("stat out: {e}"))?;
    if !out_meta.file_type().is_dir() {
        return Err("out is not a real directory".to_string());
    }
    let mut names = Vec::new();
    for ent in std::fs::read_dir(&out)
        .map_err(|e| format!("read_dir out: {e}"))?
        .take(MAX_OUT_ENTRIES + 1)
    {
        names.push(ent.map_err(|e| format!("read_dir entry: {e}"))?.file_name());
    }
    if names.len() > MAX_OUT_ENTRIES || names.iter().any(|n| n != "write.txt") {
        return Err(format!("unexpected entries in out/: {names:?}"));
    }
    let path = out.join("write.txt");
    let meta = std::fs::symlink_metadata(&path).map_err(|e| format!("stat write.txt: {e}"))?;
    if !meta.file_type().is_file() {
        return Err("write.txt is not a regular file".to_string());
    }
    let expected = format!("{WRITE_LINE}\n").repeat(WRITE_LINES).into_bytes();
    let mut got = Vec::new();
    std::fs::File::open(&path)
        .map_err(|e| format!("open write.txt: {e}"))?
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut got)
        .map_err(|e| format!("read write.txt: {e}"))?;
    if got != expected {
        return Err(format!(
            "write.txt content mismatch (got {} bytes, expected {})",
            got.len(),
            expected.len()
        ));
    }
    Ok(())
}

struct ProbeOutcome {
    fixture: Fixture,
    log: ProbeLog,
    console_tail: String,
    write_check: Result<(), String>,
}

/// 実機で VM を起動してプローブを走らせ、停止後に結果を集める。
fn boot_and_probe(tag: &str) -> ProbeOutcome {
    let kernel = env_path("FANDHE_CONTAINER_MACOS_VM_KERNEL").unwrap_or_else(|| {
        panic!(
            "FANDHE_CONTAINER_MACOS_VM_KERNEL is required. Optional: FANDHE_CONTAINER_MACOS_VM_INITRD, \
             FANDHE_CONTAINER_MACOS_VM_DISK_IMAGE, FANDHE_CONTAINER_MACOS_VM_CMDLINE (default \"console=hvc0\"), \
             FANDHE_CONTAINER_MACOS_VM_PROBE_TIMEOUT_SECS (1-600, default 60). See AGENTS.md."
        )
    });
    let initrd = env_path("FANDHE_CONTAINER_MACOS_VM_INITRD");
    let disk = env_path("FANDHE_CONTAINER_MACOS_VM_DISK_IMAGE");
    let cmdline = std::env::var("FANDHE_CONTAINER_MACOS_VM_CMDLINE")
        .unwrap_or_else(|_| "console=hvc0".to_string());
    let timeout =
        resolve_probe_timeout(std::env::var("FANDHE_CONTAINER_MACOS_VM_PROBE_TIMEOUT_SECS").ok())
            .unwrap_or_else(|e| panic!("{e}"));

    let s = Scratch::new(tag, true);
    let fixture = prepare_fixture(&s);
    let spec = probe_spec(
        &s,
        &fixture,
        &kernel,
        initrd.as_deref(),
        disk.as_deref(),
        &cmdline,
    );
    let log_path = s.dir.join("console.log");
    eprintln!("virtiofs_io: console log at {}", log_path.display());
    let vm = match Vm::launch(&spec, OpTimeouts::default()) {
        Ok(vm) => vm,
        Err(e) => panic!("launch failed: code={} message={}", e.code(), e.message()),
    };

    // ログの大きさは書き出しスレッドが MAX_CONSOLE_LOG_BYTES で打ち切るため、読み込みは有界。
    let deadline = Instant::now() + timeout;
    let mut last = Vec::new();
    loop {
        if let Ok(bytes) = std::fs::read(&log_path) {
            last = bytes;
        }
        if parse_probe_log(&last).done {
            break;
        }
        if log_truncated(&last) {
            // 上限後のゲスト出力は破棄されるため、待っても done は観測できない。明示的に失敗させる。
            let _ = vm.stop();
            panic!(
                "console log hit the size limit before the probe done line; console tail:\n{}",
                tail_lossy(&last, 4096)
            );
        }
        if Instant::now() >= deadline {
            let _ = vm.stop();
            panic!(
                "probe done line not observed within {timeout:?}; console tail:\n{}",
                tail_lossy(&last, 4096)
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // ゲストとの TOCTOU を避けるため、停止を確認してから共有の中身を検証する。
    vm.stop().expect("stop");
    assert_eq!(vm.state(), VmState::Stopped);
    if let Ok(bytes) = std::fs::read(&log_path) {
        last = bytes;
    }
    // done 検出後〜停止までにゲスト出力が上限へ達すると、done の後の重複報告・エラーが破棄される。
    // 停止後に読み直したログでも打ち切りを拒否する（fail-closed）。
    assert!(
        !log_truncated(&last),
        "console log hit the size limit after the probe done line; later guest output was lost; console tail:\n{}",
        tail_lossy(&last, 4096)
    );
    let write_check = verify_write(&fixture.share_dir);
    ProbeOutcome {
        log: parse_probe_log(&last),
        console_tail: tail_lossy(&last, 4096),
        write_check,
        fixture,
    }
}

/// MAC-1・IO-5・TASK-65.4: プローブ用 spec（RW 共有＋ゲスト mount）が VZ 設定へ読み戻せる。
#[test]
fn mac1_io5_probe_spec_builds_with_rw_share_and_guest_mount() {
    let s = Scratch::new("probe-spec", false);
    let kernel = s.file("vmlinux", b"dummy");
    let f = prepare_fixture(&s);
    let spec = probe_spec(&s, &f, &kernel, None, None, "console=hvc0");
    let cfg = match build_vz_configuration(&spec) {
        Ok(c) => c,
        Err(e) => panic!("build failed: {e}"),
    };
    let shares = cfg.shared_directories();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].tag, "fandhe-io");
    assert!(!shares[0].read_only);
    assert_eq!(
        shares[0].path.as_ref().and_then(|p| p.canonicalize().ok()),
        f.share_dir.canonicalize().ok()
    );
    assert_eq!(
        cfg.command_line().as_deref(),
        Some("console=hvc0 fandhe.virtiofs=fandhe-io:/mnt/fandhe/io:rw")
    );
}

/// MAC-1・IO-5・TASK-65.4: プローブ行は mount 報告の走査（`fandhe-guest:`）に誤認されない。
#[test]
fn mac1_io5_probe_prefix_does_not_overlap_mount_report_prefix() {
    assert!(PROBE_PREFIX.starts_with(PROBE_NAMESPACE));
    assert!(!PROBE_NAMESPACE.starts_with(guest_mount::REPORT_PREFIX));
    assert!(!guest_mount::REPORT_PREFIX.starts_with(PROBE_NAMESPACE));
    assert!(!PROBE_PREFIX.starts_with(guest_mount::REPORT_PREFIX));
    assert!(!guest_mount::REPORT_PREFIX.starts_with(PROBE_PREFIX));
    for line in [
        "fandhe-guest-test: virtiofs-io v1 op=read value=abc",
        "fandhe-guest-test: virtiofs-io v1 done",
    ] {
        assert!(guest_mount::parse_report_line(line.as_bytes()).is_none());
    }
}

/// MAC-1・IO-5・TASK-65.4: プローブ行の解釈を具体値で固定する。
#[test]
fn mac1_io5_parse_probe_line_cases() {
    let p = |s: &str| parse_probe_line(s.as_bytes());
    let pre = PROBE_PREFIX;
    assert_eq!(
        p(&format!("{pre}op=read value=tok1")),
        ProbeLine::Item(ProbeItem::Read("tok1".into()))
    );
    assert_eq!(
        p(&format!("{pre}op=readdir entries=a-1,b-1,c-1")),
        ProbeLine::Item(ProbeItem::Readdir("a-1,b-1,c-1".into()))
    );
    assert_eq!(
        p(&format!("{pre}op=write result=done")),
        ProbeLine::Item(ProbeItem::Write)
    );
    assert_eq!(
        p(&format!("{pre}op=readdir result=error")),
        ProbeLine::Item(ProbeItem::OpError("readdir".into()))
    );
    assert_eq!(p(&format!("{pre}done")), ProbeLine::Item(ProbeItem::Done));
    // CRLF は許容する。
    assert_eq!(
        p(&format!("{pre}op=read value=tok1\r")),
        ProbeLine::Item(ProbeItem::Read("tok1".into()))
    );
    // 名前空間を持たない行・行頭以外に現れた接頭辞は無視する。
    assert_eq!(p("[    0.1] virtio-fs: probe"), ProbeLine::Other);
    assert_eq!(p(&format!("x {pre}op=read value=tok1")), ProbeLine::Other);
    // 名前空間を持つが契約外の行は不正: 上限超過・未知 op・空 value・未知の field・
    // done の後ろの余剰・版数違い・版数なし・非 UTF-8。
    let long = format!("{pre}op=read value={}", "a".repeat(MAX_PROBE_LINE_BYTES));
    assert_eq!(p(&long), ProbeLine::Malformed);
    assert_eq!(
        p(&format!("{pre}op=chmod result=error")),
        ProbeLine::Malformed
    );
    assert_eq!(p(&format!("{pre}op=chmod value=x")), ProbeLine::Malformed);
    assert_eq!(p(&format!("{pre}op=read value=")), ProbeLine::Malformed);
    assert_eq!(p(&format!("{pre}op=write result=ok")), ProbeLine::Malformed);
    assert_eq!(p(&format!("{pre}op=read")), ProbeLine::Malformed);
    assert_eq!(p(&format!("{pre}done now")), ProbeLine::Malformed);
    assert_eq!(p(pre), ProbeLine::Malformed);
    assert_eq!(
        p("fandhe-guest-test: virtiofs-io v2 op=read value=tok1"),
        ProbeLine::Malformed
    );
    assert_eq!(
        p("fandhe-guest-test: virtiofs-io done"),
        ProbeLine::Malformed
    );
    let mut non_utf8 = format!("{pre}op=read value=").into_bytes();
    non_utf8.push(0xff);
    assert_eq!(parse_probe_line(&non_utf8), ProbeLine::Malformed);
}

/// MAC-1・IO-5・TASK-65.4: 同じ op の重複報告は不正として扱う（fail-closed）。
#[test]
fn mac1_io5_parse_probe_log_rejects_duplicate_or_conflicting_reports() {
    let pre = PROBE_PREFIX;
    let ok = parse_probe_log(format!(
        "kernel noise\n{pre}op=read value=t\n{pre}op=readdir entries=a\n{pre}op=write result=done\n{pre}done\n"
    ));
    assert_eq!(ok.read.as_deref(), Some("t"));
    assert!(ok.write_done && ok.done && !ok.invalid);
    let dup = parse_probe_log(format!("{pre}op=read value=t\n{pre}op=read value=u\n"));
    assert!(dup.invalid);
    let dup_w = parse_probe_log(format!(
        "{pre}op=write result=done\n{pre}op=write result=done\n"
    ));
    assert!(dup_w.invalid);
}

/// MAC-1・IO-5・TASK-65.4: done は全 op 報告後の最終行でなければ不正（fail-closed）。
#[test]
fn mac1_io5_parse_probe_log_requires_done_last_and_complete() {
    let pre = PROBE_PREFIX;
    let body =
        format!("{pre}op=read value=t\n{pre}op=readdir entries=a\n{pre}op=write result=done\n");
    // 全 op の報告後に done が 1 回だけなら有効。
    let ok = parse_probe_log(format!("{body}{pre}done\n"));
    assert!(ok.done && !ok.invalid);
    // 失敗報告も「報告済み」として数える。
    let err = parse_probe_log(format!(
        "{pre}op=read result=error\n{pre}op=readdir result=error\n{pre}op=write result=error\n{pre}done\n"
    ));
    assert!(err.done && !err.invalid);
    // 失敗報告の重複、および成功と失敗の混在も同じ op の重複として不正。
    let dup_err = parse_probe_log(format!(
        "{pre}op=read result=error\n{pre}op=read result=error\n"
    ));
    assert!(dup_err.invalid);
    let mixed = parse_probe_log(format!(
        "{pre}op=write result=done\n{pre}op=write result=error\n"
    ));
    assert!(mixed.invalid);
    // 上限到達で打ち切られたログは末尾の区切り文で判別できる。
    let mut cut = b"noise".to_vec();
    cut.extend_from_slice(TRUNCATION_MARKER);
    assert!(log_truncated(&cut));
    assert!(!log_truncated(b"noise"));
    // 早過ぎる done。
    let early = parse_probe_log(format!("{pre}op=read value=t\n{pre}done\n"));
    assert!(early.done && early.invalid);
    // done の重複。
    let dup = parse_probe_log(format!("{body}{pre}done\n{pre}done\n"));
    assert!(dup.invalid);
    // done 以降の後続報告（エラー含む）。
    let late = parse_probe_log(format!("{body}{pre}done\n{pre}op=write result=error\n"));
    assert!(late.invalid);
}

/// MAC-1・IO-5・TASK-65.4: 復号できないプローブ行は done の前後とも不正（fail-closed）。
#[test]
fn mac1_io5_parse_probe_log_rejects_malformed_probe_lines() {
    let pre = PROBE_PREFIX;
    let body =
        format!("{pre}op=read value=t\n{pre}op=readdir entries=a\n{pre}op=write result=done\n");
    // 名前空間を持たない行は混ざっても有効のまま。
    let noise = parse_probe_log(format!(
        "[    0.1] boot\n{body}random output\n{pre}done\nreboot: Power down\n"
    ));
    assert_eq!(noise.read.as_deref(), Some("t"));
    assert_eq!(noise.readdir.as_deref(), Some("a"));
    assert!(noise.write_done && noise.done && !noise.invalid);
    // done の後の未知 op・形式崩れ・版数違い。
    for late in [
        format!("{pre}op=chmod result=error"),
        format!("{pre}op=read value="),
        "fandhe-guest-test: virtiofs-io v2 done".to_string(),
    ] {
        let log = parse_probe_log(format!("{body}{pre}done\n{late}\n"));
        assert!(log.done && log.invalid, "after done: {late}");
    }
    // done の前に現れた形式崩れも、他の報告が揃っていても不正。
    let early = parse_probe_log(format!("{pre}op=write result=ok\n{body}{pre}done\n"));
    assert!(early.done && early.write_done && early.invalid);
    // 非 UTF-8 の値を持つプローブ行は生バイトのまま判定し、置換文字で受理しない。
    let mut raw = format!("{pre}op=read value=t").into_bytes();
    raw.push(0xff);
    raw.extend_from_slice(
        format!("\n{pre}op=readdir entries=a\n{pre}op=write result=done\n{pre}done\n").as_bytes(),
    );
    let bad = parse_probe_log(&raw);
    assert_eq!(bad.read, None);
    assert!(bad.done && bad.invalid);
    // 非 UTF-8 のカーネル出力（名前空間を持たない行）は無視し、CRLF の行も受理する。
    let mut crlf = vec![0xff, 0xfe, b'\n'];
    crlf.extend_from_slice(
        format!("{body}{pre}done\n")
            .replace('\n', "\r\n")
            .as_bytes(),
    );
    let ok = parse_probe_log(&crlf);
    assert_eq!(ok.read.as_deref(), Some("t"));
    assert!(ok.done && !ok.invalid);
}

/// MAC-1・IO-5・TASK-65.4: 不足と余剰の両方を検出する。
#[test]
fn mac1_io5_compare_entries_detects_missing_and_extra() {
    let set = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
    let exp = set(&["a", "b", "c"]);
    assert_eq!(compare_entries(&exp, "c,a,b"), Ok(()));
    assert_eq!(
        compare_entries(&exp, "a,b"),
        Err(EntriesMismatch {
            missing: set(&["c"]),
            extra: set(&[]),
            duplicate: set(&[])
        })
    );
    assert_eq!(
        compare_entries(&exp, "a,b,c,d"),
        Err(EntriesMismatch {
            missing: set(&[]),
            extra: set(&["d"]),
            duplicate: set(&[])
        })
    );
    assert_eq!(
        compare_entries(&exp, "a,x"),
        Err(EntriesMismatch {
            missing: set(&["b", "c"]),
            extra: set(&["x"]),
            duplicate: set(&[])
        })
    );
    assert_eq!(
        compare_entries(&exp, ""),
        Err(EntriesMismatch {
            missing: exp.clone(),
            extra: set(&[]),
            duplicate: set(&[])
        })
    );
    assert_eq!(
        compare_entries(&exp, "a,a,b,c"),
        Err(EntriesMismatch {
            missing: set(&[]),
            extra: set(&[]),
            duplicate: set(&["a"])
        })
    );
}

/// MAC-1・IO-5・TASK-65.4: fixture のレイアウト。
#[test]
fn mac1_io5_prepare_fixture_layout() {
    let s = Scratch::new("fixture", false);
    let f = prepare_fixture(&s);
    let read = std::fs::read_to_string(f.share_dir.join("in/read.txt")).expect("read.txt");
    assert_eq!(read, format!("{}\n", f.read_value));
    let nonce = f.read_value.strip_prefix("fandhe-read-").expect("prefix");
    assert!(!nonce.is_empty() && nonce.bytes().all(|b| b.is_ascii_hexdigit()));
    let names: BTreeSet<String> = std::fs::read_dir(f.share_dir.join("in/dir"))
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, f.expected_entries);
    assert_eq!(names.len(), 3);
    assert_eq!(
        std::fs::read_dir(f.share_dir.join("out"))
            .expect("out")
            .count(),
        0
    );
}

/// MAC-1・IO-5・TASK-65.4: 実機テストの期限は 1..=600 秒（既定 60）。
#[test]
fn mac1_io5_probe_timeout_bounds() {
    assert_eq!(resolve_probe_timeout(None), Ok(Duration::from_secs(60)));
    assert_eq!(
        resolve_probe_timeout(Some("1".into())),
        Ok(Duration::from_secs(1))
    );
    assert_eq!(
        resolve_probe_timeout(Some("600".into())),
        Ok(Duration::from_secs(600))
    );
    for bad in ["0", "601", "abc", ""] {
        assert!(resolve_probe_timeout(Some(bad.into())).is_err(), "{bad}");
    }
}

/// MAC-1・IO-5・TASK-65.4: 停止後の write 検証は symlink・余剰エントリ・内容不一致を拒否する。
#[test]
fn mac1_io5_verify_write_rejects_symlink_extra_entries_and_bad_content() {
    let s = Scratch::new("verify-write", false);
    let f = prepare_fixture(&s);
    let out = f.share_dir.join("out");
    assert!(verify_write(&f.share_dir).is_err(), "missing write.txt");
    let good = format!("{WRITE_LINE}\n").repeat(WRITE_LINES);
    std::fs::write(out.join("write.txt"), &good).expect("write");
    assert_eq!(verify_write(&f.share_dir), Ok(()));
    std::fs::write(out.join("write.txt"), format!("{good}x")).expect("write");
    assert!(verify_write(&f.share_dir).is_err(), "trailing bytes");
    std::fs::remove_file(out.join("write.txt")).expect("rm");
    let target = s.file("outside.txt", good.as_bytes());
    std::os::unix::fs::symlink(&target, out.join("write.txt")).expect("symlink");
    assert!(verify_write(&f.share_dir).is_err(), "symlink");
    std::fs::remove_file(out.join("write.txt")).expect("rm");
    std::fs::write(out.join("write.txt"), &good).expect("write");
    std::fs::write(out.join("extra"), b"x").expect("extra");
    assert!(verify_write(&f.share_dir).is_err(), "extra entry");
    // out/ 自体を symlink へ差し替えた場合も拒否する。
    let moved = s.dir.join("moved_out");
    std::fs::rename(&out, &moved).expect("rename out");
    std::os::unix::fs::symlink(&moved, &out).expect("symlink out");
    assert!(verify_write(&f.share_dir).is_err(), "symlinked out dir");
}

/// MAC-1・IO-5・TASK-65.4: ゲストが共有の `in/read.txt` を read できる。
#[test]
#[ignore = "requires real macOS 13+ with Virtualization.framework, a test binary codesigned with com.apple.security.virtualization, and a guest init implementing fandhe.virtiofs directives and the virtiofs-io probe; see AGENTS.md"]
fn mac1_io5_virtiofs_read_on_real_macos() {
    let o = boot_and_probe("virtiofs-read");
    assert!(
        !o.log.has_error("read"),
        "op=read reported result=error; console tail:\n{}",
        o.console_tail
    );
    assert_eq!(
        o.log.read.as_deref(),
        Some(o.fixture.read_value.as_str()),
        "op=read: expected {:?}; console tail:\n{}",
        o.fixture.read_value,
        o.console_tail
    );
    assert!(
        !o.log.invalid,
        "invalid probe reports (duplicate, out of order or malformed):\n{}",
        o.console_tail
    );
}

/// MAC-1・IO-5・TASK-65.4: ゲストが `out/write.txt` を write でき、ホストから期待内容で読める。
#[test]
#[ignore = "requires real macOS 13+ with Virtualization.framework, a test binary codesigned with com.apple.security.virtualization, and a guest init implementing fandhe.virtiofs directives and the virtiofs-io probe; see AGENTS.md"]
fn mac1_io5_virtiofs_write_on_real_macos() {
    let o = boot_and_probe("virtiofs-write");
    assert!(
        o.log.write_done && !o.log.has_error("write"),
        "op=write not reported done; console tail:\n{}",
        o.console_tail
    );
    assert!(
        !o.log.invalid,
        "invalid probe reports (duplicate, out of order or malformed):\n{}",
        o.console_tail
    );
    assert_eq!(
        o.write_check,
        Ok(()),
        "out/write.txt verification failed; console tail:\n{}",
        o.console_tail
    );
}

/// MAC-1・IO-5・TASK-65.4: ゲストが `in/dir` を readdir でき、エントリ集合が fixture と一致する。
#[test]
#[ignore = "requires real macOS 13+ with Virtualization.framework, a test binary codesigned with com.apple.security.virtualization, and a guest init implementing fandhe.virtiofs directives and the virtiofs-io probe; see AGENTS.md"]
fn mac1_io5_virtiofs_readdir_on_real_macos() {
    let o = boot_and_probe("virtiofs-readdir");
    assert!(
        !o.log.has_error("readdir"),
        "op=readdir reported result=error; console tail:\n{}",
        o.console_tail
    );
    assert!(
        !o.log.invalid,
        "invalid probe reports (duplicate, out of order or malformed):\n{}",
        o.console_tail
    );
    let reported = o.log.readdir.as_deref().unwrap_or_else(|| {
        panic!(
            "op=readdir not reported; expected {:?}; console tail:\n{}",
            o.fixture.expected_entries, o.console_tail
        )
    });
    if let Err(m) = compare_entries(&o.fixture.expected_entries, reported) {
        panic!(
            "op=readdir mismatch: {m:?} (expected {:?}, got {reported:?}); console tail:\n{}",
            o.fixture.expected_entries, o.console_tail
        );
    }
}
