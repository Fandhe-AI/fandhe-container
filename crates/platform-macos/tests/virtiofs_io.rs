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
//! 補助関数（Scratch・VM 起動後の done 行待ち・停止・ログの確定待ち〔#3416〕・期限）は `tests/support/virtiofs_harness.rs` に共通化し、
//! その単体試験は `tests/virtiofs_harness.rs`（MAC-1・REPAIR-1・#3099）。
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
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use fandhe_container_platform_macos::config::{
    BlockDeviceSpec, ConsoleLogPath, DeviceConfigSpec, DiskImagePath, SerialConsoleSink,
    VmConfigSpec, build_vz_configuration,
};
use fandhe_container_platform_macos::guest_mount::{GuestMountPoint, GuestTestMode};
use fandhe_container_platform_macos::guest_probe::{
    GUEST_MOUNT, ProbeLog, SHARE_TAG, WRITE_LINE, WRITE_LINES, compare_entries, parse_probe_log,
};
use fandhe_container_platform_macos::virtiofs::{
    ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsSharesSpec, VirtiofsTag,
};

#[path = "support/common.rs"]
mod common;
use common::{COUNTER, Scratch, tail_lossy};
#[path = "support/virtiofs_harness.rs"]
mod harness;
#[path = "support/vm_guest.rs"]
mod vm_guest;
use harness::{launch_until_done, resolve_probe_timeout};

const MAX_OUT_ENTRIES: usize = 16;
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

/// kernel 未設定時の panic 文言（必須・任意の環境変数の一覧）。
const KERNEL_HELP: &str = "FANDHE_CONTAINER_MACOS_VM_KERNEL is required. Optional: FANDHE_CONTAINER_MACOS_VM_INITRD, \
             FANDHE_CONTAINER_MACOS_VM_DISK_IMAGE, FANDHE_CONTAINER_MACOS_VM_CMDLINE (default \"console=hvc0\"), \
             FANDHE_CONTAINER_MACOS_VM_PROBE_TIMEOUT_SECS (1-600, default 60). See AGENTS.md.";

/// 実機で VM を起動してプローブを走らせ、停止後に結果を集める。
fn boot_and_probe(tag: &str) -> ProbeOutcome {
    let assets = vm_guest::GuestAssets::from_env(KERNEL_HELP);
    let timeout =
        resolve_probe_timeout(std::env::var("FANDHE_CONTAINER_MACOS_VM_PROBE_TIMEOUT_SECS").ok())
            .unwrap_or_else(|e| panic!("{e}"));

    let s = Scratch::new(tag, true);
    let fixture = prepare_fixture(&s);
    let spec = probe_spec(
        &s,
        &fixture,
        &assets.kernel,
        assets.initrd.as_deref(),
        assets.disk.as_deref(),
        &assets.cmdline,
    );
    let log_path = s.dir.join("console.log");
    eprintln!("virtiofs_io: console log at {}", log_path.display());
    let last = launch_until_done(&spec, &log_path, "probe", timeout, |b| {
        parse_probe_log(b).done
    });
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
