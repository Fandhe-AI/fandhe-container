//! macOS（HVF）で実 Linux カーネルを `/init` まで起動する実機前提の結合試験（MVM-5・MVM-1・REPAIR-5・REPAIR-12・TASK-192・#3986）。
//! `--ignored` 指定時だけ走る。`tests/kernel_boot.rs` の `arm64`（KVM。#3897・#3898）の macOS 対応物で、`hvf_microvm.rs`（#3799）が
//! 合成 arm64 Image で確かめた `HvfMicroVm::assemble` → `start` → ゲスト起因の停止 → `stop` を、利用者が用意した
//! 実 Linux の arm64 `Image` と最小 initrd（`scripts/build-microvm-test-initrd.sh`）で通す。人間担当の #3988 が実機で実行する。
//!
//! 必要環境: Apple Silicon の macOS 15 以降、`com.apple.security.hypervisor` 付きの ad-hoc 署名（`tests/hvf.entitlements`）、
//! 非圧縮の arm64 `Image`、`MICROVM_TEST_INITRD_ARCH=aarch64 make microvm-test-initrd-build` の出力。root は不要。
//! 手順は `docs/verification/real-machine-tests.md` の `hvf_kernel_boot` の項。1 プロセス 1 VM のため `--test-threads=1` で実行する。
//! 環境変数: `FANDHE_CONTAINER_MICROVM_KERNEL`（必須）・`_INITRD`（既定 `target/microvm-test-initrd/aarch64/initrd.cpio`）・
//! `_CMDLINE`（既定 `console=ttyS0 rdinit=/init`。末尾に `panic=0` を足す）・`_BOOT_TIMEOUT_SECS`（1..=600、既定 60）。
//!
//! 観測手段: ゲストの `/init` がシリアル（ns16550a の MMIO）へ書く固定文字列（`MARKER`）を行単位でちょうど 1 回数え、停止理由が
//! `StopReason::GuestShutdown`（`/init` の `reboot(RESTART)` → PSCI SYSTEM_RESET → `hvc` の exit）、エラー 0 件、UART の取りこぼし
//! 0 バイトであることを具体値で照合する。`ttyS0 at MMIO 0x9000000 (irq = N, ...)` の行から、シリアルが割り込みで結線されている
//! こと（`N != 0`）も見る。期限切れで `stop` した `Requested` は合格にしない。負の対照は initrd 無しで、期限まで止まらないことを見る。
//! 起点 vCPU は `HvfStopReport` に無いため照合しない（`kernel_boot` の KVM 版との差）。
//!
//! 全体期限（REPAIR-5）: `.cargo/config.toml` の watchdog は `--ignored` を素通しするため、本試験自身の `Watchdog`
//! （超過で `hvf_kernel_boot: WATCHDOG EXPIRED` と終了コード 124）・ポーリング期限・`stop` の期限・外側の `recv_timeout` が層になる。
//! 前提欠如は skip せず `hvf_kernel_boot: PRECONDITION FAILED (test environment, not a regression)` で落とす。
//!
//! 既知のリスク（起動が止まったときの切り分け。いずれも試験を緩めず、原因ごとに別 issue にする）:
//! - 実カーネルは合成 Image が踏まなかった exit（システムレジスタの trap・SMC・ISV=0 の data abort）を踏みうる。`hvf_loop` は
//!   これらを fail-closed で `Failed(..)` にする。`Failed(..)` は device model 側の問題であり、試験の欠陥ではない。
//! - 実カーネルでの I-cache の clean の要否は未確認（`hvf/microvm.rs` の範囲外の項目・#3988）。起動できないときの切り分け先。
//! - 内側の期限で panic すると起動スレッドが残り、同じプロセスの次の試験は VM の作成で `FailedPrecondition` になりうる。
//!   `stop` の期限切れでは RAM がリークして同じプロセスで作り直せない。いずれも先に出た失敗を原因として読む。
//! - `guest/kernel/` の Kconfig が本試験の Image に適するかは確かめていない（適すると書かない）。
//!
//! 未実装（REPAIR-3）: virtio-block の block-read を割り込み trigger 2 構成（edge / LevelHigh）で起動する試験は、HVF 側が
//! `QueueNotify` を処理する経路（#3908）が無いため足していない。vCPU 2 台（#3998）・UART の入出力（#3987）はこの試験の上に足す。
//! 実機での実行と記録は #3988（人間担当）。Agent は実カーネルでの起動を確かめていない。
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

#[path = "support/guest_boot.rs"]
mod guest_boot;

use fandhe_container_microvm::arm64_layout::{ARM64_SERIAL_BASE, Arm64Layout};
use fandhe_container_microvm::boot_arm64::Arm64ImageHeader;
use fandhe_container_microvm::error::MicrovmErrorCode;
use fandhe_container_microvm::hvf::{HvfMicroVm, HvfMicroVmConfig, VcpuThreadConfig, VmWithGic};
use fandhe_container_microvm::hvf_loop::{ExitCounts, ExitKind};
use fandhe_container_microvm::interrupt::IrqTrigger;
use fandhe_container_microvm::stop::StopReason;
use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
use fandhe_container_microvm::virtio_net::MemoryNetBackend;
use guest_boot::{
    MARKER, TtyAddress, TtyReport, count_marker_lines, escape_tail, force_panic_zero,
    parse_tty_report, read_bounded,
};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

/// `console=ttyS0` で FDT の `ns16550a` を 8250 のコンソールに選び、`rdinit=/init` で initrd の `/init` を起動する。
const DEFAULT_CMDLINE: &str = "console=ttyS0 rdinit=/init";
const DEFAULT_TIMEOUT_SECS: u64 = 60;
const RAM_SIZE: u64 = 256 << 20;
const KERNEL_CAP: u64 = fandhe_container_microvm::boot_x86::MAX_KERNEL_IMAGE_BYTES;
const INITRD_CAP: u64 = 64 << 20;
/// シリアル出力の蓄積上限（無制限確保の防止）。
const OUTPUT_CAP: usize = 4 << 20;
/// `stop` の期限（`stop` 自身の上限 60 秒以内）。
const STOP_DEADLINE: Duration = Duration::from_secs(10);
/// 外側の `recv_timeout` が内側（起動スレッドの全体）より余裕を持つための上乗せ。
const SLACK: Duration = Duration::from_secs(15);
/// `Watchdog` が内側の期限（`boot_timeout + STOP_DEADLINE + SLACK`）より後に効くための上乗せ。
const WATCHDOG_MARGIN: Duration = Duration::from_secs(30);
const TAIL_BYTES: usize = 4096;

/// 前提欠如の panic の 1 行目（CI・人間が見分ける固定形式）。
fn precondition(reason: &str) -> ! {
    panic!("hvf_kernel_boot: PRECONDITION FAILED (test environment, not a regression): {reason}")
}

/// 試験全体の期限。内側の `recv_timeout` より必ず長い。固定値にしないのは、`_BOOT_TIMEOUT_SECS` が最大 600 秒で、
/// 負の対照が既定 60 秒を使い切るため（REPAIR-5）。
fn overall_deadline(boot_timeout_secs: u64) -> Duration {
    Duration::from_secs(boot_timeout_secs) + STOP_DEADLINE + SLACK + WATCHDOG_MARGIN
}

/// 期限 watchdog。panic しても止めて join する RAII ガード（`hvf_microvm.rs` と同じ形）。
struct Watchdog(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);

impl Watchdog {
    fn start(deadline: Duration) -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        let f = Arc::clone(&flag);
        let h = std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < deadline {
                if f.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            eprintln!("hvf_kernel_boot: WATCHDOG EXPIRED");
            std::process::exit(124);
        });
        Watchdog(flag, Some(h))
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
        if let Some(h) = self.1.take() {
            let _ = h.join();
        }
    }
}

/// 起動の入力（前提の検査はすべてテストスレッドで済ませる）。
struct Inputs {
    kernel: Vec<u8>,
    initrd: Option<Vec<u8>>,
    cmdline: String,
    secs: u64,
}

/// 前提を検査して入力を作る。欠如は skip せず `precondition` で落とす。`with_initrd` が偽なら initrd を読まない（負の対照）。
/// 呼び出し順: 期限の解釈 → watchdog の開始（`start_watchdog`）→ 本関数。ここでの読み込みは上限つき・`O_NONBLOCK`。
fn inputs(with_initrd: bool, secs: u64) -> Inputs {
    let kernel_path = match std::env::var("FANDHE_CONTAINER_MICROVM_KERNEL") {
        Ok(p) if !p.is_empty() => p,
        _ => precondition("FANDHE_CONTAINER_MICROVM_KERNEL is not set (path to an arm64 Image)"),
    };
    let kernel = read_bounded(Path::new(&kernel_path), KERNEL_CAP)
        .unwrap_or_else(|e| precondition(&format!("kernel image: {e}")));
    if let Err(e) = Arm64ImageHeader::parse(&kernel) {
        precondition(&format!(
            "kernel image is not an uncompressed arm64 Image: {e}"
        ));
    }
    let initrd = with_initrd.then(|| {
        let path = match std::env::var("FANDHE_CONTAINER_MICROVM_INITRD") {
            Ok(p) if !p.is_empty() => std::path::PathBuf::from(p),
            _ => Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/microvm-test-initrd/aarch64/initrd.cpio"),
        };
        read_bounded(&path, INITRD_CAP).unwrap_or_else(|e| {
            precondition(&format!(
                "initrd (run `MICROVM_TEST_INITRD_ARCH=aarch64 make microvm-test-initrd-build`): {e}"
            ))
        })
    });
    let cmdline = guest_boot::validate_cmdline_or(
        std::env::var("FANDHE_CONTAINER_MICROVM_CMDLINE")
            .ok()
            .as_deref(),
        DEFAULT_CMDLINE,
    )
    .unwrap_or_else(|e| precondition(&e));
    Inputs {
        kernel,
        initrd,
        cmdline: force_panic_zero(&cmdline),
        secs,
    }
}

/// 環境変数の期限を解釈する。不正は前提欠如。
fn boot_timeout_secs() -> u64 {
    guest_boot::parse_boot_timeout_or(
        std::env::var("FANDHE_CONTAINER_MICROVM_BOOT_TIMEOUT_SECS")
            .ok()
            .as_deref(),
        DEFAULT_TIMEOUT_SECS,
    )
    .unwrap_or_else(|e| precondition(&e))
}

/// 配置（virtio 窓 0・既定のシリアル）。block・net は載せない（HVF 側の `QueueNotify` の処理が未実装。#3908）。
fn layout(vcpus: u32) -> Arm64Layout {
    Arm64Layout::new(RAM_SIZE, vcpus, 0)
        .and_then(Arm64Layout::with_default_serial)
        .unwrap_or_else(|e| panic!("hvf_kernel_boot: layout: {e}"))
}

/// 環境の前提（権限）を、組み立てとは別に先に確かめる。権限不足だけを環境の問題とし、それ以外の失敗はそのまま出す（#3989）。
fn require_vm_with_gic(layout: &Arm64Layout) {
    match VmWithGic::create(layout) {
        Ok(vm) => drop(vm),
        Err(e) if e.code() == MicrovmErrorCode::PermissionDenied => precondition(&e.to_string()),
        Err(e) => panic!("hvf_kernel_boot: gic: {e}"),
    }
}

/// 起動 1 回の結果。
struct Outcome {
    reason: StopReason,
    vcpu_count: u32,
    errors: u64,
    exits: u64,
    per_vcpu_exits: Vec<u64>,
    output: Vec<u8>,
    uart_dropped: u64,
    timed_out: bool,
    elapsed: Duration,
    /// exit の種別ごとの回数（診断・#3988 の判断材料。値は assert しない）。
    wfx: u64,
    vtimer: u64,
    data_abort: u64,
    hvc: u64,
}

impl Outcome {
    fn diag(&self) -> String {
        format!(
            "reason={:?} vcpus={} errors={} exits={} per_vcpu_exits={:?} wfx={} vtimer={} data_abort={} hvc={} \
             timed_out={} elapsed={:?} uart_dropped={} output_len={} output_tail=\"{}\"",
            self.reason,
            self.vcpu_count,
            self.errors,
            self.exits,
            self.per_vcpu_exits,
            self.wfx,
            self.vtimer,
            self.data_abort,
            self.hvc,
            self.timed_out,
            self.elapsed,
            self.uart_dropped,
            self.output.len(),
            escape_tail(&self.output, TAIL_BYTES)
        )
    }
}

/// 起動して停止まで見る。`RunningHvfMicroVm` は `!Send` なので、組み立てから停止までこのスレッドの中で完結させる。
/// `kernel_boot` の `boot` と同じ順序: `serial_console` を start の前に取り、10 ms ごとに取り出し、期限切れでも必ず `stop` する。
fn boot(inp: Inputs, vcpus: u32) -> Result<Outcome, String> {
    let started = Instant::now();
    let boot_timeout = Duration::from_secs(inp.secs);
    let counts = Arc::new(ExitCounts::new());
    let config: HvfMicroVmConfig<MemoryBlockBackend, MemoryNetBackend> = HvfMicroVmConfig {
        layout: layout(vcpus),
        vcpus,
        kernel: inp.kernel,
        initrd: inp.initrd,
        cmdline: inp.cmdline,
        block: Vec::new(),
        net: Vec::new(),
        vcpu: VcpuThreadConfig {
            observer: Some(counts.clone()),
            ..Default::default()
        },
        serial: true,
    };
    let vm = HvfMicroVm::assemble(config).map_err(|e| format!("assemble failed: {e}"))?;
    let serial = vm
        .serial_console()
        .ok_or_else(|| "serial console is not enabled".to_string())?;
    let running = vm.start().map_err(|e| format!("start failed: {e}"))?;
    let mut output: Vec<u8> = Vec::new();
    let mut timed_out = false;
    loop {
        let chunk = serial
            .take_output()
            .map_err(|e| format!("take_output failed: {e}"))?;
        output.extend_from_slice(&chunk);
        if output.len() > OUTPUT_CAP {
            return Err("guest serial output exceeded the test cap".into());
        }
        if running.is_finished() {
            break;
        }
        if started.elapsed() >= boot_timeout {
            timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // 期限切れでも必ず stop で vCPU を回収する（REPAIR-5）。
    let report = running
        .stop(STOP_DEADLINE)
        .map_err(|e| format!("stop failed: {e}"))?;
    // 停止までの出力を取り切る。
    let tail = serial
        .take_output()
        .map_err(|e| format!("take_output failed: {e}"))?;
    output.extend_from_slice(&tail);
    let uart_dropped = serial
        .stats()
        .map_err(|e| format!("uart stats failed: {e}"))?
        .dropped_bytes;
    Ok(Outcome {
        reason: report.reason,
        vcpu_count: report.vcpu_count,
        errors: report.stats.errors,
        exits: report.stats.exits,
        per_vcpu_exits: report.per_vcpu.iter().map(|s| s.exits).collect(),
        output,
        uart_dropped,
        timed_out,
        elapsed: started.elapsed(),
        wfx: counts.count(ExitKind::Wfx),
        vtimer: counts.count(ExitKind::Vtimer),
        data_abort: counts.count(ExitKind::DataAbort),
        hvc: counts.count(ExitKind::Hvc),
    })
}

/// 別スレッドで `boot` を回し、外側の `recv_timeout` で必ず戻る。
fn run_boot(inp: Inputs, vcpus: u32) -> (Outcome, Duration) {
    let secs = inp.secs;
    let boot_timeout = Duration::from_secs(secs);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(boot(inp, vcpus));
    });
    match rx.recv_timeout(boot_timeout + STOP_DEADLINE + SLACK) {
        Ok(Ok(o)) => (o, boot_timeout),
        Ok(Err(e)) => panic!("hvf_kernel_boot: boot sequence failed: {e}"),
        Err(e) => panic!("hvf_kernel_boot: DEADLINE EXCEEDED ({e}) after {secs}s boot budget"),
    }
}

/// 陽性。`/init` の reboot（PSCI SYSTEM_RESET）が `GuestShutdown` で止まり、marker がちょうど 1 回出る。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_kernel_boot_real_kernel_reaches_init_and_shuts_down() {
    let secs = boot_timeout_secs();
    let _wd = Watchdog::start(overall_deadline(secs));
    let inp = inputs(true, secs);
    require_vm_with_gic(&layout(1));
    let (o, boot_timeout) = run_boot(inp, 1);
    let diag = o.diag();
    assert_eq!(o.reason, StopReason::GuestShutdown, "stop reason: {diag}");
    assert_eq!(o.vcpu_count, 1, "vcpu count: {diag}");
    assert_eq!(o.errors, 0, "run errors: {diag}");
    assert!(!o.timed_out, "boot timed out: {diag}");
    assert!(o.elapsed < boot_timeout, "elapsed over budget: {diag}");
    assert_eq!(
        count_marker_lines(&o.output, MARKER),
        1,
        "init marker must appear exactly once: {diag}"
    );
    assert_eq!(o.uart_dropped, 0, "uart dropped bytes: {diag}");
    // ポーリングへの退行の検出。irq = 0 は DT に interrupts が無い印。値は virq なので != 0 だけを見る。
    let irq = match parse_tty_report(&o.output, "ttyS0") {
        TtyReport::Found {
            address: TtyAddress::Mmio(base),
            irq,
        } => {
            assert_eq!(base, ARM64_SERIAL_BASE, "ttyS0 MMIO base: {diag}");
            irq
        }
        other => panic!("ttyS0 report not found exactly once as MMIO: {other:?}: {diag}"),
    };
    assert_ne!(
        irq, 0,
        "ttyS0 is polled (irq = 0); serial interrupt wiring regressed: {diag}"
    );
    eprintln!(
        "hvf_kernel_boot: ok arch=aarch64 reason=guest_shutdown ttys0_irq={irq} elapsed_ms={} exits={} wfx={} vtimer={} data_abort={} hvc={} per_vcpu={:?}",
        o.elapsed.as_millis(),
        o.exits,
        o.wfx,
        o.vtimer,
        o.data_abort,
        o.hvc,
        o.per_vcpu_exits
    );
}

/// 負の対照。initrd が無いと rootfs の mount に失敗して panic し、`panic=0` でループするので期限まで止まらない。
/// 既定 60 秒を使い切る。陽性と同じ実行・同じカーネルで回すこと（対照の結果が陽性の `GuestShutdown` の意味を裏づける）。
/// `Failed(..)` が出たら device model 側の別 issue。カーネルは `CONFIG_PANIC_TIMEOUT=0` かつ組み込み initramfs 無しが前提。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_kernel_boot_without_initrd_does_not_shut_down() {
    let secs = boot_timeout_secs();
    let _wd = Watchdog::start(overall_deadline(secs));
    let inp = inputs(false, secs);
    require_vm_with_gic(&layout(1));
    let (o, _) = run_boot(inp, 1);
    let diag = o.diag();
    assert_ne!(o.reason, StopReason::GuestShutdown, "stop reason: {diag}");
    assert_eq!(o.reason, StopReason::Requested, "stop reason: {diag}");
    assert!(o.timed_out, "expected budget exhaustion: {diag}");
    assert_eq!(o.vcpu_count, 1, "vcpu count: {diag}");
    assert_eq!(o.errors, 0, "run errors: {diag}");
    assert_eq!(
        count_marker_lines(&o.output, MARKER),
        0,
        "init marker must not appear without an initrd: {diag}"
    );
    assert_eq!(o.uart_dropped, 0, "uart dropped bytes: {diag}");
}

/// watchdog の期限は、内側（起動スレッド全体）の期限より常に長い（既定と最大の 2 点。REPAIR-5・MVM-5）。
#[test]
fn mvm5_3986_overall_deadline_exceeds_inner_budget() {
    let inner = |secs: u64| Duration::from_secs(secs) + STOP_DEADLINE + SLACK;
    assert_eq!(overall_deadline(60), Duration::from_secs(115));
    assert_eq!(overall_deadline(600), Duration::from_secs(655));
    for secs in [1, 60, 600] {
        assert!(overall_deadline(secs) > inner(secs), "{secs}");
        assert_eq!(overall_deadline(secs) - inner(secs), WATCHDOG_MARGIN);
    }
}

/// 試験の配置は virtio 窓 0・シリアルあり・vCPU 数の指定どおりで、FDT の virtio の割り込みの既定は edge-rising のまま
/// （block-read の 2 構成の試験は #3908 の後で足す）。
#[test]
fn mvm5_3986_layout_without_virtio_is_valid() {
    let l = layout(1);
    assert_eq!(l.vcpus, 1);
    assert_eq!(l.virtio_mmio_count, 0);
    assert_eq!(
        l.serial.expect("default serial window").base.raw(),
        ARM64_SERIAL_BASE
    );
    assert_eq!(l.virtio_spi_trigger, IrqTrigger::EdgeRising);
    assert_eq!(layout(2).vcpus, 2);
}
