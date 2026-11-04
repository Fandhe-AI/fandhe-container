//! macOS の最小 microVM の起動から停止までの通し試験（MVM-5・MVM-1・MVM-4・REPAIR-12・TASK-192.17・#3799・#3782）。
//! Linux の `tests/microvm.rs`（#700・TASK-75.5）の macOS 対応物で、`HvfMicroVm::assemble` → `start` → ゲスト起因の停止 → `stop` を
//! FDT・起動レジスタ・virtio-mmio・シリアル・PSCI まで一貫して観測する。部品ごとの試験は `hvf_device.rs` が担う。
//!
//! 観測手段: 合成の arm64 Image（`support/arm64_image.rs`）自身が起動状態を検証し、結果を「exit の並び」「シリアル出力」
//! 「停止理由」へ写す。正の試験は全一致のときだけシリアルへ `OK\n` を書き、負の対照（virtio-block 無し）は書き込み 0 回で終わる。
//! 正負とも停止理由は `GuestShutdown` で、「シャットダウンできた＝成功」とはみなさず、区別は exit の並びと出力で行う。
//! 書き先を空き virtio 窓の観測器ではなくシリアルにしたのは、`assemble` が virtio の窓数と block + net の個数の一致を要求し、
//! 製品の構成外の登録（`dispatcher()` への後付け）を避けるため。
//! `hvf_device.rs` の `synthetic_image*` との重複は意図的に解消しない（1 PR・1 関心事。REPAIR-1 の後続候補）。
//!
//! 必要環境: Apple Silicon の macOS 15 以降、`com.apple.security.hypervisor` 付きの ad-hoc 署名。root は不要。
//! 手順は AGENTS.md「実機前提テスト」の `hvf_microvm` の項。1 プロセス 1 VM のため `--test-threads=1` で実行する。
//! 期限 watchdog つき（REPAIR-5。超過は `hvf_microvm: WATCHDOG EXPIRED` と終了コード 124）。実機の記録は人間担当の #3803。
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

#[path = "support/arm64_image.rs"]
mod arm64_image;

use arm64_image::{BOOT_CHECK_CODE, image_with_code};
use fandhe_container_microvm::arm64_layout::{
    ARM64_SERIAL_BASE, ARM64_VIRTIO_MMIO_BASE, Arm64Layout,
};
use fandhe_container_microvm::error::MicrovmErrorCode;
use fandhe_container_microvm::hvf::{
    HvVm, HvfMicroVm, HvfMicroVmConfig, HvfStopReport, VcpuThreadConfig, VmWithGic,
};
use fandhe_container_microvm::hvf_loop::{ExitKind, VcpuExitObserver};
use fandhe_container_microvm::stop::StopReason;
use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
use fandhe_container_microvm::virtio_net::MemoryNetBackend;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 試験全体の期限。ハングを失敗として残す（REPAIR-5）。
const DEADLINE: Duration = Duration::from_secs(30);
/// ゲストが SYSTEM_OFF に達するまでの待ちの上限。
const FINISH_WAIT: Duration = Duration::from_secs(10);

/// 環境の前提（権限・macOS 15 以降）を、組み立てとは別に先に確かめる。macOS 14 の `Unimplemented` は前提欠如ではない。
fn require_vm_with_gic(layout: &Arm64Layout) {
    match VmWithGic::create(layout) {
        Ok(vm) => drop(vm),
        Err(e) if e.code() == MicrovmErrorCode::Unimplemented => panic!("hvf_microvm: gic: {e}"),
        Err(e) => {
            panic!("hvf_microvm: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    }
}

/// VM を作る。解放の観測（解放漏れなら 2 個目の作成が `FailedPrecondition`）にも使う。
fn create_vm_or_precondition() -> HvVm {
    match HvVm::create() {
        Ok(vm) => vm,
        Err(e) => {
            panic!("hvf_microvm: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    }
}

/// 期限 watchdog。panic しても止めて join する RAII ガード。
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
            eprintln!("hvf_microvm: WATCHDOG EXPIRED");
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

/// exit の並びを記録する観測器（上限 64 件。ブロックしない）。
#[derive(Debug, Default)]
struct ExitSeq(Mutex<Vec<ExitKind>>);

impl ExitSeq {
    fn snapshot(&self) -> Vec<ExitKind> {
        self.0.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

impl VcpuExitObserver for ExitSeq {
    fn on_exit(&self, kind: ExitKind) {
        if let Ok(mut v) = self.0.lock()
            && v.len() < 64
        {
            v.push(kind);
        }
    }
}

type Config = HvfMicroVmConfig<MemoryBlockBackend, MemoryNetBackend>;

/// 起動確認ゲストを載せた構成（vCPU 1・シリアルあり・net なし）。`block` は virtio-block の台数。
fn config(layout: Arm64Layout, block: usize, observer: Arc<ExitSeq>) -> Config {
    HvfMicroVmConfig {
        vcpus: layout.vcpus,
        layout,
        kernel: image_with_code(&BOOT_CHECK_CODE),
        initrd: None,
        cmdline: "console=ttyS0".to_string(),
        block: (0..block)
            .map(|_| MemoryBlockBackend::new(512 * 1024, false).unwrap())
            .collect(),
        net: Vec::new(),
        vcpu: VcpuThreadConfig {
            observer: Some(observer),
            ..Default::default()
        },
        serial: true,
    }
}

/// start してゲストが SYSTEM_OFF に達するのを待ち、stop する。(exit の並び, シリアル出力, 停止報告) を返す。
fn run_boot_check(
    vm: HvfMicroVm<MemoryBlockBackend, MemoryNetBackend>,
    seq: &ExitSeq,
) -> (Vec<ExitKind>, Vec<u8>, HvfStopReport) {
    let console = vm.serial_console().expect("serial console is enabled");
    let running = vm.start().unwrap();

    let mut out = Vec::new();
    let start = Instant::now();
    while !running.is_finished() {
        assert!(
            start.elapsed() < FINISH_WAIT,
            "hvf_microvm: guest did not reach SYSTEM_OFF"
        );
        out.extend(console.take_output().unwrap());
        std::thread::sleep(Duration::from_millis(10));
    }
    let report = running.stop(Duration::from_secs(1)).unwrap();
    // 追加の出力が無いことも確かめるため、少し待ってからもう一度取り出す。
    std::thread::sleep(Duration::from_millis(100));
    out.extend(console.take_output().unwrap());
    let exits = seq.snapshot();
    eprintln!(
        "hvf_microvm: boot_check: exits={exits:?} output={out:?} reason={:?} stats={:?}",
        report.reason, report.stats
    );
    (exits, out, report)
}

/// 正の試験: FDT・virtio-block の MagicValue と DeviceID をゲストが確かめ、全一致のときだけシリアルへ `OK\n` を書いて SYSTEM_OFF。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_microvm_boots_minimal_device_model_and_stops() {
    let _wd = Watchdog::start(DEADLINE);
    let layout = Arm64Layout::new(64 << 20, 1, 1)
        .unwrap()
        .with_default_serial()
        .unwrap();
    // ゲストの機械語に固定した配置との一致。
    assert_eq!(
        layout.virtio_mmio_window(0).unwrap().base.raw(),
        0x0a00_0000
    );
    assert_eq!(ARM64_VIRTIO_MMIO_BASE, 0x0a00_0000);
    assert_eq!(layout.serial.unwrap().base.raw(), 0x0900_0000);
    assert_eq!(ARM64_SERIAL_BASE, 0x0900_0000);
    require_vm_with_gic(&layout);

    let seq = Arc::new(ExitSeq::default());
    let vm = HvfMicroVm::assemble(config(layout, 1, Arc::clone(&seq))).unwrap();

    // ゲストの検証の前提がホスト側でも成り立つ: x0 = FDT の GPA、その位置に BE の 0xd00dfeed、block が 1 台。
    assert_eq!(vm.boot_registers().x0, vm.loaded().fdt.base.raw());
    let mut magic = [0u8; 4];
    vm.read_guest(vm.loaded().fdt.base.raw(), &mut magic)
        .unwrap();
    assert_eq!(magic, 0xd00d_feedu32.to_be_bytes());
    assert_eq!(vm.devices().len(), 1);

    let (exits, out, report) = run_boot_check(vm, &seq);
    // MagicValue 読み・DeviceID 読み・THR への strb 3 回（すべて data abort）・SYSTEM_OFF の HVC。
    assert_eq!(
        exits,
        vec![
            ExitKind::DataAbort,
            ExitKind::DataAbort,
            ExitKind::DataAbort,
            ExitKind::DataAbort,
            ExitKind::DataAbort,
            ExitKind::Hvc,
        ]
    );
    assert_eq!(out, b"OK\n");
    assert_eq!(report.reason, StopReason::GuestShutdown);

    // stop の後に VM を作り直せる（解放漏れなら FailedPrecondition）。
    drop(create_vm_or_precondition());
}

/// 負の対照: virtio-block が無い同じゲストは MagicValue が一致せず、書き込み 0 回で SYSTEM_OFF に至る（検査が効いている証拠）。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_microvm_boot_check_fails_without_block_device() {
    let _wd = Watchdog::start(DEADLINE);
    let layout = Arm64Layout::new(64 << 20, 1, 0)
        .unwrap()
        .with_default_serial()
        .unwrap();
    require_vm_with_gic(&layout);

    let seq = Arc::new(ExitSeq::default());
    let vm = HvfMicroVm::assemble(config(layout, 0, Arc::clone(&seq))).unwrap();
    assert_eq!(vm.devices().len(), 0);

    let (exits, out, report) = run_boot_check(vm, &seq);
    // 窓 0 は未登録で、読み出しは 0xFFFF_FFFF（MagicValue 不一致）。MagicValue 読み 1 回の後に fail へ分岐する。
    assert_eq!(exits, vec![ExitKind::DataAbort, ExitKind::Hvc]);
    assert_eq!(out, b"");
    assert_eq!(report.reason, StopReason::GuestShutdown);

    drop(create_vm_or_precondition());
}
