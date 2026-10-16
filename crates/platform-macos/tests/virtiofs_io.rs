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
//! プローブ契約（行の形・名前空間・順序・起動条件）の SSOT は `guest_probe` モジュール。実装は
//! `crates/guest-init`（#1876）で、`VmConfigSpec::with_guest_test(GuestTestMode::VirtiofsIo)` が付ける
//! 予約キー `fandhe.guest-test=virtiofs-io` で有効になる（利用者のコマンドラインでは指定できない）。
//! ゲスト出力は untrusted として扱い、復号・照合は `guest_probe` の関数に任せる（3 OS の単体テストで固定済み）。
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
use fandhe_container_platform_macos::guest_mount::{GuestMountPoint, GuestTestMode};
use fandhe_container_platform_macos::guest_probe::{
    GUEST_MOUNT, ProbeLog, SHARE_TAG, WRITE_LINE, WRITE_LINES, compare_entries, parse_probe_log,
};
use fandhe_container_platform_macos::virtiofs::{
    ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsSharesSpec, VirtiofsTag,
};
use fandhe_container_platform_macos::vm::{OpTimeouts, Vm, VmState};

const MAX_OUT_ENTRIES: usize = 16;
/// VM 破棄後、コンソールログの書き出しスレッドが EOF で終わるのを待つ上限（REPAIR-5）。
const CONSOLE_LOG_SETTLE_TIMEOUT: Duration = Duration::from_secs(30);

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
        .with_guest_test(GuestTestMode::VirtiofsIo)
}
/// コンソールログが書き出しスレッドの上限（`MAX_CONSOLE_LOG_BYTES`）で打ち切られたか。
/// 区切り文は上限到達時に末尾へ 1 回だけ書かれ、以後ゲスト出力は破棄されるため、
/// 末尾が区切り文ならプローブ行の後続は観測できない。
fn log_truncated(bytes: &[u8]) -> bool {
    bytes.ends_with(TRUNCATION_MARKER)
}

/// コンソールログの書き出しスレッド（`console_log`）がログを閉じ終えるまで待つ。
///
/// 書き出しスレッドはログへの排他 advisory lock（unix では `flock(2)`）を EOF でファイルを閉じるまで
/// 保持する（`console_log` モジュールの「排他」）。EOF は VM と設定が解放され serial の書き込み端が
/// すべて閉じたときに来るため、`Vm` を破棄した後に lock を取れれば、ゲスト出力はすべてファイルへ
/// 反映済みで以後増えない。期限内に取れなければ不完全なログで判定しないよう `Err` を返す（fail-closed）。
fn wait_console_log_settled(path: &Path, timeout: Duration) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("open console log: {e}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        match file.try_lock() {
            // 取得した lock は `file` の drop で解放される。
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(format!("lock console log: {e}"));
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "console log writer did not finish within {timeout:?}"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
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
    // stop は VM の停止だけを待ち、pipe からログへの書き出しは非同期に続く。VM を破棄して書き込み端を
    // 閉じ、書き出しスレッドの終了（lock の解放）を確認してから確定したログで最終判定する。
    drop(vm);
    if let Err(e) = wait_console_log_settled(&log_path, CONSOLE_LOG_SETTLE_TIMEOUT) {
        panic!("{e}; console tail:\n{}", tail_lossy(&last, 4096));
    }
    last = std::fs::read(&log_path).expect("read settled console log");
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
        Some(
            "console=hvc0 fandhe.virtiofs=fandhe-io:/mnt/fandhe/io:rw fandhe.guest-test=virtiofs-io"
        )
    );
}

/// MAC-1・IO-5・TASK-65.4: 上限到達で打ち切られたログは末尾の区切り文で判別できる。
#[test]
fn mac1_io5_log_truncation_is_detected_by_marker() {
    let mut cut = b"noise".to_vec();
    cut.extend_from_slice(TRUNCATION_MARKER);
    assert!(log_truncated(&cut));
    assert!(!log_truncated(b"noise"));
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

/// MAC-1・IO-5・TASK-65.4・REPAIR-5: ログの確定待ちは書き出し側の lock 解放で完了し、
/// 解放されなければ期限で失敗する。
#[test]
fn mac1_io5_wait_console_log_settled_follows_writer_lock() {
    let s = Scratch::new("settle", false);
    let log = s.file("console.log", b"boot\n");
    // 書き出しスレッドの代役: 別の open で排他 lock を保持し、200ms 後に閉じる。
    let writer = std::fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .expect("open writer");
    writer.lock().expect("writer lock");
    assert_eq!(
        wait_console_log_settled(&log, Duration::from_millis(100)),
        Err("console log writer did not finish within 100ms".to_string())
    );
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        drop(writer);
    });
    assert_eq!(
        wait_console_log_settled(&log, Duration::from_secs(10)),
        Ok(())
    );
    release.join().expect("release thread");
    // ログが無ければ待たずに失敗する。
    let missing = s.dir.join("missing.log");
    assert!(
        wait_console_log_settled(&missing, Duration::from_secs(1))
            .is_err_and(|e| e.starts_with("open console log: "))
    );
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
