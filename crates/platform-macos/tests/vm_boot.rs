//! `fandhe-container-platform-macos` の結合試験（MAC-1・TASK-64.6・MS-5）。
//!
//! 本番では `fandhe-container-plugin-macos`（TASK-115）が `Vm::launch` を呼ぶ。本ファイルはその入口を
//! crate 外から公開 API だけで検証する。他 OS では `#![cfg]` により test target は 0 件になる
//! （他 OS でテストが走っているように見せない。REPAIR-3）。
//!
//! 二層構成:
//! - 既定集合（`cargo test --workspace`・macOS CI）: VM 生成より前に確定する経路だけを具体値で検証する。
//!   GitHub ホステッドの macOS runner は entitlement を持たないため、VM 生成まで到達する試験は置かない。
//! - 実機起動テスト（`#[ignore]`）: 実機 macOS 13 以上・`com.apple.security.virtualization` 付き署名・
//!   ゲスト資産（TASK-64.hdep2・#362 の方式で別途用意）を要する。資産は呼び出し側が用意したものを信頼する
//!   前提で、本 crate はダウンロードも同梱もしない。手順は AGENTS.md「実機前提テスト」節。
#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fandhe_container_platform_macos::config::{
    BlockDeviceId, BlockDeviceSpec, ConfigError, ConsoleLogPath, CpuCount, DeviceConfigSpec,
    DiskImagePath, MEMORY_ALIGNMENT_BYTES, MemorySize, SerialConsoleSink, VmConfigSpec,
    build_vz_configuration,
};
use fandhe_container_platform_macos::virtiofs::{
    ShareAccess, SharedDirectoryPath, VirtiofsShareSpec, VirtiofsSharesSpec, VirtiofsTag,
};
use fandhe_container_platform_macos::vm::{OpTimeouts, Vm, VmEvent, VmState};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// テストごとの新規ディレクトリ（0700）。`keep` が false なら `Drop` で削除する（実機テストはログを残す）。
struct Scratch {
    dir: PathBuf,
    keep: bool,
}

impl Scratch {
    /// `CARGO_TARGET_TMPDIR` 配下に新規作成する。`create_dir` は既存に失敗するため、他のディレクトリを
    /// 再利用・削除しない。親に symlink を含めないよう canonicalize した基点を使う。
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

    /// 0600 のファイルを作る。
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

/// ダミー kernel とコンソールログ付きの最小 spec（VM 生成までは到達しない用途）。
fn spec_with_console(s: &Scratch) -> (VmConfigSpec, PathBuf) {
    let kernel = s.file("vmlinux", b"dummy");
    let log = s.dir.join("console.log");
    let devices = DeviceConfigSpec::try_new(
        vec![],
        Some(SerialConsoleSink::LogFile(
            ConsoleLogPath::try_new(&log).expect("console log path"),
        )),
    )
    .expect("device spec");
    let spec = VmConfigSpec::from_parts(&kernel, None, "console=hvc0")
        .expect("spec")
        .with_devices(devices)
        .expect("with_devices");
    (spec, log)
}

/// MAC-1・TASK-64.6: CPU 数が VZ の許容範囲外なら、副作用（コンソールログの作成）の前に
/// `config.cpu_count_out_of_range` で拒否される。
#[test]
fn mac1_launch_rejects_cpu_count_out_of_range_before_side_effects() {
    let s = Scratch::new("cpu", false);
    let (mut spec, log) = spec_with_console(&s);
    spec.cpus = CpuCount::try_new(u32::MAX).expect("cpu count");
    let err = Vm::launch(&spec, OpTimeouts::default())
        .err()
        .expect("launch must fail");
    assert_eq!(err.code(), "config.cpu_count_out_of_range");
    assert!(!log.exists(), "console log must not be created");
}

/// MAC-1・TASK-64.6: メモリ量が VZ の許容範囲外なら `config.memory_size_out_of_range` で拒否され、
/// コンソールログは作られない。
#[test]
fn mac1_launch_rejects_memory_size_out_of_range_before_side_effects() {
    let s = Scratch::new("mem", false);
    let (mut spec, log) = spec_with_console(&s);
    spec.memory = MemorySize::try_new(!(MEMORY_ALIGNMENT_BYTES - 1)).expect("memory size");
    let err = Vm::launch(&spec, OpTimeouts::default())
        .err()
        .expect("launch must fail");
    assert_eq!(err.code(), "config.memory_size_out_of_range");
    assert!(!log.exists(), "console log must not be created");
}

/// MAC-1・ERR-1・TASK-64.6: `PlatformError` の表示は `code: message` の形で、内側のエラーを `source` に持つ。
#[test]
fn mac1_platform_error_display_and_source() {
    let s = Scratch::new("err", false);
    let (mut spec, _log) = spec_with_console(&s);
    spec.cpus = CpuCount::try_new(u32::MAX).expect("cpu count");
    let err = Vm::launch(&spec, OpTimeouts::default())
        .err()
        .expect("launch must fail");
    assert_eq!(
        err.to_string(),
        format!("{}: {}", err.code(), err.message())
    );
    assert!(std::error::Error::source(&err).is_some());
}

/// MAC-1・TASK-64.6: 公開 API の `build_vz_configuration` が、読み取り専用ディスク・識別子・
/// コンソールを設定へ反映する（VM 生成は行わないため entitlement に依存しない）。
#[test]
fn mac1_build_vz_configuration_public_api_reads_back() {
    let s = Scratch::new("build", false);
    let kernel = s.file("vmlinux", b"dummy");
    let initrd = s.file("initrd.img", b"dummy");
    let img = s.file("root.img", &vec![0u8; 1024 * 1024]);
    let log = s.dir.join("console.log");
    let mut disk = BlockDeviceSpec::root(DiskImagePath::try_new(&img).expect("disk path"));
    disk.read_only = true;
    disk.id = Some(BlockDeviceId::try_new("root").expect("device id"));
    let devices = DeviceConfigSpec::try_new(
        vec![disk],
        Some(SerialConsoleSink::LogFile(
            ConsoleLogPath::try_new(&log).expect("console log path"),
        )),
    )
    .expect("device spec");
    let spec = VmConfigSpec::from_parts(&kernel, Some(&initrd), "console=hvc0 root=/dev/vda")
        .expect("spec")
        .with_devices(devices)
        .expect("with_devices");
    let cfg = match build_vz_configuration(&spec) {
        Ok(c) => c,
        Err(e) => panic!("build failed: {e}"),
    };
    assert_eq!(cfg.cpu_count(), 2);
    assert_eq!(cfg.memory_size(), 1024 * 1024 * 1024);
    assert_eq!(
        cfg.command_line().as_deref(),
        Some("console=hvc0 root=/dev/vda")
    );
    let devs = cfg.block_devices();
    assert_eq!(devs.len(), 1);
    assert_eq!(
        devs[0].path.as_ref().and_then(|p| p.canonicalize().ok()),
        img.canonicalize().ok()
    );
    assert!(devs[0].read_only);
    assert_eq!(devs[0].id, "root");
    assert_eq!(cfg.serial_port_count(), 1);
    assert!(log.exists());
}

/// MAC-1・SEC-4・TASK-65.1: ReadOnly 共有にも共有範囲外経路の検査（symlink の範囲外リンク先・
/// ハードリンク）を適用する。公開 API の `build_vz_configuration` で、検査に失敗する間は拒否され、
/// 経路を取り除くと受理されて読み取り専用として読み戻せる。
#[test]
fn mac1_build_vz_configuration_readonly_share_escape_checks() {
    let s = Scratch::new("ro-share", false);
    let kernel = s.file("vmlinux", b"dummy");
    let shared = s.dir.join("shared");
    std::fs::create_dir(&shared).expect("create shared dir");
    std::fs::write(shared.join("data.txt"), b"d").expect("write shared file");
    let outside = s.file("outside.txt", b"o");
    let spec = VmConfigSpec::from_parts(&kernel, None, "console=hvc0")
        .expect("spec")
        .with_shared_directories(
            VirtiofsSharesSpec::try_new(vec![VirtiofsShareSpec::new(
                VirtiofsTag::try_new("ro").expect("tag"),
                SharedDirectoryPath::try_new(&shared).expect("shared path"),
                ShareAccess::ReadOnly,
            )])
            .expect("shares"),
        );

    // 範囲外を指す symlink がある間は拒否する。
    let link = shared.join("escape");
    std::os::unix::fs::symlink(&outside, &link).expect("symlink");
    match build_vz_configuration(&spec) {
        Err(e) => {
            assert_eq!(e.code(), "config.shared_dir_symlink_escapes");
            assert_eq!(
                e,
                ConfigError::SharedDirSymlinkEscapes {
                    path: link.clone(),
                    share_dir: shared.clone(),
                }
            );
        }
        Ok(_) => panic!("ReadOnly share with an escaping symlink must be rejected"),
    }
    std::fs::remove_file(&link).expect("remove symlink");

    // 共有範囲外のファイルへのハードリンク（リンク数 2）がある間も拒否する。
    let hard = shared.join("hard");
    std::fs::hard_link(&outside, &hard).expect("hard link");
    match build_vz_configuration(&spec) {
        Err(e) => {
            assert_eq!(e.code(), "config.shared_dir_hardlinked_file");
            assert_eq!(
                e,
                ConfigError::SharedDirHardlinkedFile {
                    path: hard.clone(),
                    links: 2,
                    share_dir: shared.clone(),
                }
            );
        }
        Ok(_) => panic!("ReadOnly share with a hard-linked file must be rejected"),
    }
    std::fs::remove_file(&hard).expect("remove hard link");

    // 経路を取り除くと受理され、読み取り専用の共有として反映される。
    let cfg = match build_vz_configuration(&spec) {
        Ok(c) => c,
        Err(e) => panic!("clean ReadOnly share must be accepted: {e}"),
    };
    let shares = cfg.shared_directories();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].tag, "ro");
    assert!(shares[0].read_only);
    assert_eq!(
        shares[0].path.as_ref().and_then(|p| p.canonicalize().ok()),
        shared.canonicalize().ok()
    );
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

/// 必須のゲストカーネルパスを読む。無ければ panic する（黙って成功させない）。
fn require_kernel() -> PathBuf {
    env_path("FANDHE_CONTAINER_MACOS_VM_KERNEL").unwrap_or_else(|| {
        panic!(
            "FANDHE_CONTAINER_MACOS_VM_KERNEL (absolute path to a guest kernel) and \
             FANDHE_CONTAINER_MACOS_VM_READY_MARKER (a string the guest prints only after boot completes) \
             are required. Optional: FANDHE_CONTAINER_MACOS_VM_INITRD, FANDHE_CONTAINER_MACOS_VM_DISK_IMAGE, \
             FANDHE_CONTAINER_MACOS_VM_CMDLINE (default \"console=hvc0\"), \
             FANDHE_CONTAINER_MACOS_VM_BOOT_MARKER (default \"Linux version\"), \
             FANDHE_CONTAINER_MACOS_VM_BOOT_TIMEOUT_SECS (1-600, default 60). See AGENTS.md."
        )
    })
}

/// ブートマーカーを決める。未指定は既定値、空文字列は拒否する。
///
/// 空マーカーは `contains` が常に true になり、ゲストが何も出力しなくても起動確認を通過してしまうため（MAC-1）。
fn resolve_boot_marker(raw: Option<String>) -> Result<String, String> {
    match raw {
        None => Ok("Linux version".to_string()),
        Some(m) if m.is_empty() => {
            Err("boot marker must not be empty (it would match any console output)".to_string())
        }
        Some(m) => Ok(m),
    }
}

/// 起動完了マーカーを決める。既定値は無く、未指定・空文字列は拒否する。
///
/// `Linux version` のような起動初期のマーカーだけでは、直後にゲストが停止しても成功してしまう。
/// ゲスト資産が起動完了後にだけ出力する文字列を呼び出し側に必ず指定させる（MAC-1）。
fn resolve_ready_marker(raw: Option<String>) -> Result<String, String> {
    match raw {
        None => Err("FANDHE_CONTAINER_MACOS_VM_READY_MARKER is required".to_string()),
        Some(m) if m.is_empty() => Err("ready marker must not be empty".to_string()),
        Some(m) => Ok(m),
    }
}

/// ブートマーカーと起動完了マーカーの重複を拒否する。
///
/// 一致・包含関係にあると起動初期の出力だけで両方が成立し、起動完了前にゲストが停止しても通ってしまう（MAC-1）。
fn validate_marker_pair(boot: &str, ready: &str) -> Result<(), String> {
    if boot.contains(ready) || ready.contains(boot) {
        return Err(format!(
            "boot marker {boot:?} and ready marker {ready:?} must not be equal or contain one another"
        ));
    }
    Ok(())
}

/// ブートマーカーの出現より後に起動完了マーカーが現れたかを返す。
///
/// 起動完了マーカーはブートマーカー末尾以降だけを探索し、順序（ブート後に起動完了）を保証する（MAC-1）。
fn markers_observed_in_order(text: &str, boot: &str, ready: &str) -> bool {
    text.find(boot)
        .and_then(|pos| text.get(pos + boot.len()..))
        .is_some_and(|rest| rest.contains(ready))
}

#[test]
fn mac1_marker_pair_rejects_overlap() {
    assert!(validate_marker_pair("Linux version", "Linux version").is_err());
    assert!(validate_marker_pair("Linux version", "Linux").is_err());
    assert!(validate_marker_pair("Linux", "Linux version 6").is_err());
    assert!(validate_marker_pair("Linux version", "login:").is_ok());
}

#[test]
fn mac1_ready_marker_must_follow_boot_marker() {
    let (b, r) = ("Linux version", "login:");
    assert!(markers_observed_in_order(
        "Linux version 6.1\nlogin: ",
        b,
        r
    ));
    assert!(!markers_observed_in_order(
        "login: \nLinux version 6.1",
        b,
        r
    ));
    assert!(!markers_observed_in_order("Linux version 6.1", b, r));
    assert!(!markers_observed_in_order("login:", b, r));
}

#[test]
fn mac1_ready_marker_is_required_and_non_empty() {
    assert!(resolve_ready_marker(None).is_err());
    assert!(resolve_ready_marker(Some(String::new())).is_err());
    assert_eq!(
        resolve_ready_marker(Some("login:".to_string())),
        Ok("login:".to_string())
    );
}

#[test]
fn mac1_boot_marker_rejects_empty_and_defaults_when_unset() {
    assert_eq!(resolve_boot_marker(None), Ok("Linux version".to_string()));
    assert_eq!(
        resolve_boot_marker(Some("login:".to_string())),
        Ok("login:".to_string())
    );
    assert!(resolve_boot_marker(Some(String::new())).is_err());
}

/// 末尾の最大 `max` バイトを文字列にする（失敗時の診断用）。
fn tail_lossy(bytes: &[u8], max: usize) -> String {
    let start = bytes.len().saturating_sub(max);
    String::from_utf8_lossy(bytes.get(start..).unwrap_or_default()).into_owned()
}

/// MAC-1・TASK-64.6: 実機で最小 VM を起動し、コンソールにブートマーカーと起動完了マーカーが出て、停止できる。
///
/// 実機前提のため既定集合から分離している（CI 通過のための弱体化ではない）。必要なもの: 実機 macOS 13 以上、
/// `com.apple.security.virtualization` 付きで署名したテストバイナリ、ゲスト資産（#362 の方式）。
#[test]
#[ignore = "requires real macOS 13+ with Virtualization.framework, a test binary codesigned with com.apple.security.virtualization, and guest assets (TASK-64.hdep2); see AGENTS.md"]
fn mac1_minimal_vm_boots_and_stops_on_real_macos() {
    let kernel = require_kernel();
    let initrd = env_path("FANDHE_CONTAINER_MACOS_VM_INITRD");
    let disk = env_path("FANDHE_CONTAINER_MACOS_VM_DISK_IMAGE");
    let cmdline = std::env::var("FANDHE_CONTAINER_MACOS_VM_CMDLINE")
        .unwrap_or_else(|_| "console=hvc0".to_string());
    let marker = resolve_boot_marker(std::env::var("FANDHE_CONTAINER_MACOS_VM_BOOT_MARKER").ok())
        .expect("invalid FANDHE_CONTAINER_MACOS_VM_BOOT_MARKER");
    let ready_marker =
        resolve_ready_marker(std::env::var("FANDHE_CONTAINER_MACOS_VM_READY_MARKER").ok())
            .expect("invalid FANDHE_CONTAINER_MACOS_VM_READY_MARKER");
    validate_marker_pair(&marker, &ready_marker).expect("invalid marker pair");
    let boot_secs: u64 =
        match std::env::var("FANDHE_CONTAINER_MACOS_VM_BOOT_TIMEOUT_SECS") {
            Ok(v) => v.parse().ok().filter(|n| (1..=600).contains(n)).expect(
                "FANDHE_CONTAINER_MACOS_VM_BOOT_TIMEOUT_SECS must be an integer in 1..=600",
            ),
            Err(_) => 60,
        };

    // 失敗時の診断のためコンソールログは残す。
    let s = Scratch::new("vm-boot", true);
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
    let spec = VmConfigSpec::from_parts(&kernel, initrd.as_deref(), &cmdline)
        .expect("spec")
        .with_devices(devices)
        .expect("with_devices");
    let timeouts = OpTimeouts::try_new(
        Duration::from_secs(30),
        Duration::from_secs(15),
        Duration::from_secs(5),
    )
    .expect("timeouts");

    eprintln!("vm_boot: console log at {}", log.display());
    let vm = match Vm::launch(&spec, timeouts) {
        Ok(vm) => vm,
        Err(e) => panic!("launch failed: code={} message={}", e.code(), e.message()),
    };
    assert_eq!(vm.state(), VmState::Running);

    // イベントは有界回数だけ読む。実機での並び順は未確認のため、Running への遷移が 1 回以上あることだけを見る。
    let mut saw_running = false;
    for _ in 0..16 {
        match vm.recv_event(Duration::from_millis(200)) {
            Some(VmEvent::StateChanged {
                to: VmState::Running,
                ..
            }) => {
                saw_running = true;
                break;
            }
            Some(_) => {}
            None => break,
        }
    }
    assert!(saw_running, "no StateChanged to Running event observed");

    // ログの大きさは書き出しスレッドが MAX_CONSOLE_LOG_BYTES で打ち切るため、読み込みは有界。
    let started = Instant::now();
    let deadline = started + Duration::from_secs(boot_secs);
    let mut last = Vec::new();
    let found = loop {
        if let Ok(bytes) = std::fs::read(&log) {
            last = bytes;
        }
        let text = String::from_utf8_lossy(&last);
        if markers_observed_in_order(&text, &marker, &ready_marker) {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    if !found {
        let msg = format!(
            "boot marker {marker:?} and ready marker {ready_marker:?} not observed in order (boot then ready) within {boot_secs}s; console tail:\n{}",
            tail_lossy(&last, 4096)
        );
        let _ = vm.stop();
        panic!("{msg}");
    }
    println!(
        "vm_boot: boot marker observed (marker={marker:?}, ready_marker={ready_marker:?}, elapsed_ms={})",
        started.elapsed().as_millis()
    );

    // 起動完了後もゲストが停止・異常終了していないことを確認してから停止する。
    assert_eq!(vm.state(), VmState::Running, "guest stopped after boot");
    vm.stop().expect("stop");
    assert_eq!(vm.state(), VmState::Stopped);
}
