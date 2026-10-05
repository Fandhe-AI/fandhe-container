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
use fandhe_container_platform_macos::guest_mount::{self, GuestMountPoint};
use fandhe_container_platform_macos::virtiofs::{
    ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsSharesSpec, VirtiofsTag,
};
use fandhe_container_platform_macos::vm::{OpTimeouts, Vm, VmState};

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

/// 1 行がプローブ行なら復号する。行頭一致のみ受理し、上限超過・未知 op・空 value は無視する。
fn parse_probe_line(line: &[u8]) -> Option<ProbeItem> {
    if line.len() > MAX_PROBE_LINE_BYTES {
        return None;
    }
    let line = line.strip_suffix(b"\r").unwrap_or(line);
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
    /// 同じ op の重複報告（矛盾の有無によらず不正として扱う）。
    invalid: bool,
}

impl ProbeLog {
    /// 指定 op の失敗報告（`result=error`）があるか。
    fn has_error(&self, op: &str) -> bool {
        self.errors.iter().any(|e| e == op)
    }
}

/// ログ全体を畳み込む。op ごとの重複報告は `invalid`（fail-closed）。
fn parse_probe_log(text: &str) -> ProbeLog {
    let mut out = ProbeLog::default();
    for line in text.lines() {
        match parse_probe_line(line.as_bytes()) {
            Some(ProbeItem::Read(v)) => {
                out.invalid |= out.read.replace(v).is_some();
            }
            Some(ProbeItem::Readdir(v)) => {
                out.invalid |= out.readdir.replace(v).is_some();
            }
            Some(ProbeItem::Write) => {
                out.invalid |= out.write_done;
                out.write_done = true;
            }
            Some(ProbeItem::OpError(op)) => out.errors.push(op),
            Some(ProbeItem::Done) => out.done = true,
            None => {}
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
        if parse_probe_log(&String::from_utf8_lossy(&last)).done {
            break;
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
    let write_check = verify_write(&fixture.share_dir);
    ProbeOutcome {
        log: parse_probe_log(&String::from_utf8_lossy(&last)),
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
        Some(ProbeItem::Read("tok1".into()))
    );
    assert_eq!(
        p(&format!("{pre}op=readdir entries=a-1,b-1,c-1")),
        Some(ProbeItem::Readdir("a-1,b-1,c-1".into()))
    );
    assert_eq!(
        p(&format!("{pre}op=write result=done")),
        Some(ProbeItem::Write)
    );
    assert_eq!(
        p(&format!("{pre}op=readdir result=error")),
        Some(ProbeItem::OpError("readdir".into()))
    );
    assert_eq!(p(&format!("{pre}done")), Some(ProbeItem::Done));
    // CRLF は許容する。
    assert_eq!(
        p(&format!("{pre}op=read value=tok1\r")),
        Some(ProbeItem::Read("tok1".into()))
    );
    // 行頭以外に現れた接頭辞は無視する。
    assert_eq!(p(&format!("x {pre}op=read value=tok1")), None);
    // 上限超過・未知 op・空 value は無視する。
    let long = format!("{pre}op=read value={}", "a".repeat(MAX_PROBE_LINE_BYTES));
    assert_eq!(p(&long), None);
    assert_eq!(p(&format!("{pre}op=chmod result=error")), None);
    assert_eq!(p(&format!("{pre}op=read value=")), None);
}

/// MAC-1・IO-5・TASK-65.4: 同じ op の重複報告は不正として扱う（fail-closed）。
#[test]
fn mac1_io5_parse_probe_log_rejects_duplicate_or_conflicting_reports() {
    let pre = PROBE_PREFIX;
    let ok = parse_probe_log(&format!(
        "kernel noise\n{pre}op=read value=t\n{pre}op=write result=done\n{pre}done\n"
    ));
    assert_eq!(ok.read.as_deref(), Some("t"));
    assert!(ok.write_done && ok.done && !ok.invalid);
    let dup = parse_probe_log(&format!("{pre}op=read value=t\n{pre}op=read value=u\n"));
    assert!(dup.invalid);
    let dup_w = parse_probe_log(&format!(
        "{pre}op=write result=done\n{pre}op=write result=done\n"
    ));
    assert!(dup_w.invalid);
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
        "duplicate probe reports:\n{}",
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
        "duplicate probe reports:\n{}",
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
        "duplicate probe reports:\n{}",
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
