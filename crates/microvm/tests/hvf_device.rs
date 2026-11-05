//! Hypervisor.framework 実機前提の試験（MVM-5・MVM-1・TASK-192.1・#3783・TASK-192.3・#3789・TASK-192.12・#3792・TASK-192.13・#3795・TASK-192.10・#3793・TASK-192.11・#3794・TASK-192.15・#3797・TASK-192.16・#3798・#3882・#3887・#3891）。`--ignored` 指定時だけ走る。
//! 必要環境: Apple Silicon の macOS 15 以降、`com.apple.security.hypervisor` 付きの ad-hoc 署名。root は不要。
//! 手順は docs/verification/real-machine-tests.md の `hvf_device` の項。ゲストを走らせない試験は待ちがなく、vCPU を
//! 走らせる試験は期限 watchdog を持つ（REPAIR-5）。1 プロセス 1 VM のため `--test-threads=1` で実行する。
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use fandhe_container_microvm::arm64_layout::{
    ARM64_BOOT_CPU_MPIDR, ARM64_PPI_INTID_BASE, ARM64_TIMER_VIRT_PPI, Arm64Layout,
    check_virtual_timer_intid,
};
use fandhe_container_microvm::error::MicrovmErrorCode;
use fandhe_container_microvm::esr::{
    AccessDirection, EsrClass, WfxKind, decode_esr, instruction_length,
};
use fandhe_container_microvm::guest_memory::{GuestAddress, GuestMemoryBacking};
use fandhe_container_microvm::hvf::{
    GicApi, HostMapping, HvVcpu, HvVm, HvfGic, HvfGuestRam, VmWithGic,
};
use fandhe_container_microvm::hvf_abi::{
    HVF_DEFAULT_IPA_LIMIT, HvGicIntid, HvReg, HvSysReg, HvVcpuExit, IrouterRoute, MemoryFlags,
    decode_irouter,
};
use fandhe_container_microvm::hvf_wake::{SpiWakeTarget, spi_wake_target};
use fandhe_container_microvm::interrupt::InterruptLine;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// 合成 arm64 Image の正本（`tests/support/arm64_image.rs`。plugin-microvm の E2E と共有。複製しない・#3800）。
#[path = "support/arm64_image.rs"]
mod arm64_image;
use arm64_image::{synthetic_image, synthetic_image_with_code};

/// VM を作る。権限不足・hypervisor 不可は環境の問題として、決まった 1 行目で失敗させる。
/// それ以外（解放漏れの `FailedPrecondition` など）は回帰なので、環境の問題と表示しない（#3989）。
fn create_vm_or_precondition() -> HvVm {
    match HvVm::create() {
        Ok(vm) => vm,
        Err(e)
            if matches!(
                e.code(),
                MicrovmErrorCode::PermissionDenied | MicrovmErrorCode::Unimplemented
            ) =>
        {
            panic!("hvf_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
        Err(e) => panic!("hvf_device: vm: {e}"),
    }
}

/// GIC つきの VM を作る。権限不足だけを環境の問題として決まった 1 行目で失敗させる。
/// macOS 14 の `Unimplemented` と GIC の呼び出しの失敗（定数の誤りなど）は、そのままの失敗として出す（#3989）。
fn create_vm_with_gic_or_precondition(layout: &Arm64Layout) -> VmWithGic {
    match VmWithGic::create(layout) {
        Ok(vm) => vm,
        Err(e) if e.code() == MicrovmErrorCode::PermissionDenied => {
            panic!("hvf_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
        Err(e) => panic!("hvf_device: gic: {e}"),
    }
}

#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_create_map_unmap_vm() {
    let vm = create_vm_or_precondition();

    // 1 プロセス 1 VM: 2 個目は拒否される。
    assert_eq!(
        HvVm::create().unwrap_err().code(),
        MicrovmErrorCode::FailedPrecondition
    );

    let page = HostMapping::page_size().unwrap();
    let host = HostMapping::new(page).unwrap();
    let mapping = vm
        .map(host, 0, 0x4000_0000, page, MemoryFlags::RWX)
        .unwrap();
    mapping.unmap().unwrap();

    // forget しても backing は所有されたままリークするだけで、VM の破棄後も munmap されない（寿命契約）。
    let host2 = HostMapping::new(page).unwrap();
    let leaked = vm
        .map(host2, 0, 0x5000_0000, page, MemoryFlags::RWX)
        .unwrap();
    std::mem::forget(leaked);

    // drop 後は作り直せる。
    drop(vm);
    let again = HvVm::create().unwrap();
    drop(again);
}

/// `hvf_device_vcpu_regs_roundtrip` の全体期限。`run` が戻らないハングを失敗として残す（REPAIR-5）。
const VCPU_DEADLINE: Duration = Duration::from_secs(10);

#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_vcpu_regs_roundtrip() {
    let layout = Arm64Layout::new(4 << 20, 1, 0).unwrap();
    let vgic = create_vm_with_gic_or_precondition(&layout);
    let vm = vgic.vm();
    let page = HostMapping::page_size().unwrap();
    let mut host = HostMapping::new(page).unwrap();
    // `b .`（自分自身への無条件分岐）: ゲストは永久に回り続け、停止は canceller だけが担う。
    host.write_bytes(0, &0x1400_0000u32.to_le_bytes()).unwrap();
    let mapping = vm
        .map(host, 0, 0x4000_0000, page, MemoryFlags::RWX)
        .unwrap();

    let mut vcpu = vgic.create_vcpu().unwrap();
    let x0 = HvReg::x(0).unwrap();
    vcpu.set_reg(x0, 0x1122_3344_5566_7788).unwrap();
    assert_eq!(vcpu.get_reg(x0).unwrap(), 0x1122_3344_5566_7788);
    vcpu.set_reg(HvReg::PC, 0x4000_0000).unwrap();
    assert_eq!(vcpu.get_reg(HvReg::PC).unwrap(), 0x4000_0000);
    // 0x3c5: M[3:0] = 0b0101（EL1h）と DAIF の 4 ビット（0x3c0）。
    vcpu.set_reg(HvReg::CPSR, 0x3c5).unwrap();
    assert_eq!(vcpu.get_reg(HvReg::CPSR).unwrap(), 0x3c5);
    // bit 31 は RES1、Aff0 = 1。フレームワークがゲストに見せる値を加工する可能性は #3803 で観測する。
    vcpu.set_sys_reg(HvSysReg::MPIDR_EL1, 0x8000_0001).unwrap();
    assert_eq!(vcpu.get_sys_reg(HvSysReg::MPIDR_EL1).unwrap(), 0x8000_0001);

    // 別スレッドから停止する。run の前の cancel は保留される（#3803）が、run 中に届く停止を確かめるため、
    // 再送で競合に依存しない形にする。
    let done = Arc::new(AtomicBool::new(false));
    let canceller = vcpu.canceller();
    let stopper = {
        let done = Arc::clone(&done);
        let canceller = canceller.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            while !done.load(Ordering::Acquire) {
                canceller.cancel().unwrap();
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };
    // run が戻らないハングの歯止め（REPAIR-5）。
    let watchdog_done = Arc::clone(&done);
    let watchdog = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        while start.elapsed() < VCPU_DEADLINE {
            if watchdog_done.load(Ordering::Acquire) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        eprintln!("hvf_device: WATCHDOG EXPIRED");
        std::process::exit(124);
    });

    let exit = vcpu.run_once(VCPU_DEADLINE);
    done.store(true, Ordering::Release);
    stopper.join().unwrap();
    watchdog.join().unwrap();
    assert_eq!(exit.unwrap(), HvVcpuExit::Canceled);

    // 破棄後の cancel は破棄済みの id へ送らず拒否される。
    drop(vcpu);
    assert_eq!(
        canceller.cancel().unwrap_err().code(),
        MicrovmErrorCode::FailedPrecondition
    );
    mapping.unmap().unwrap();
}

/// ゲスト RAM（4 MiB）を IPA 0x4000_0000 に登録し、`GuestMemory` 越しのコピーと範囲外の拒否、
/// drop 後の再登録を確かめる（TASK-192.4・#3787・MVM-5・MVM-1）。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_guest_ram_map_and_copy() {
    const BASE: u64 = 0x4000_0000;
    const SIZE: u64 = 4 << 20;
    let vm = create_vm_or_precondition();
    let base = GuestAddress::new(BASE);

    let mut ram = HvfGuestRam::new(SIZE).unwrap();
    // 登録前に書いた内容が登録後も見える。
    ram.write(0, &[0xaa, 0xbb]).unwrap();
    let mut mem = ram.register(&vm, base, HVF_DEFAULT_IPA_LIMIT).unwrap();
    let mut head = [0u8; 2];
    mem.read_at(base, &mut head).unwrap();
    assert_eq!(head, [0xaa, 0xbb]);

    let mid = GuestAddress::new(BASE + 0x1234);
    mem.write_at(mid, &[1, 2, 3, 4, 5]).unwrap();
    let mut got = [0u8; 5];
    mem.read_at(mid, &mut got).unwrap();
    assert_eq!(got, [1, 2, 3, 4, 5]);

    let u = GuestAddress::new(BASE + 0x2000);
    mem.write_u64_le(u, 0x1122_3344_5566_7788).unwrap();
    assert_eq!(mem.read_u64_le(u).unwrap(), 0x1122_3344_5566_7788);

    // 範囲外（末尾をはみ出す・base より下）は拒否される。
    let mut four = [0u8; 4];
    let tail = GuestAddress::new(BASE + SIZE - 2);
    assert_eq!(
        mem.read_at(tail, &mut four).unwrap_err().code(),
        MicrovmErrorCode::InvalidArgument
    );
    assert_eq!(
        mem.read_at(GuestAddress::new(BASE - 1), &mut four)
            .unwrap_err()
            .code(),
        MicrovmErrorCode::InvalidArgument
    );

    // drop で unmap されるため、同じ IPA へ再登録できる。
    drop(mem);
    let again = HvfGuestRam::new(SIZE)
        .unwrap()
        .register(&vm, base, HVF_DEFAULT_IPA_LIMIT)
        .unwrap();
    drop(again);
    drop(vm);
}
/// `hvf_device_vcpu_thread_runs_and_cancels` の全体期限。ハングを失敗として残す（REPAIR-5）。
const VCPU_THREAD_DEADLINE: Duration = Duration::from_secs(20);

/// vCPU 専用スレッドの実行ループ（TASK-192.9・#3791・MVM-5・MVM-1・REPAIR-5）。
/// (A) `b .` のゲストが別スレッドからの停止要求で 1 秒以内に `Requested` で終わる。
/// (B) X0 = 未知の関数 ID（0x8400_00ff）の `hvc #0` は PSCI が NOT_SUPPORTED を返して再開し、VM は止まらず、停止要求で `Requested` になる（観測器の HVC は 1 件）。
/// 1 プロセス 1 VM のため、VM は 1 回だけ作って 2 場面を順に走らせる。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_vcpu_thread_runs_and_cancels() {
    use fandhe_container_microvm::hvf::hvc::HvcHandler;
    use fandhe_container_microvm::hvf::mmio::MmioHandler;
    use fandhe_container_microvm::hvf::timer::TimerHandler;
    use fandhe_container_microvm::hvf::{ExitHandlers, VcpuThread, VcpuThreadConfig};
    use fandhe_container_microvm::hvf_loop::{ExitCounts, ExitKind};
    use fandhe_container_microvm::stop::StopReason;
    use std::time::Instant;

    const BASE: u64 = 0x4000_0000;
    let finished = Arc::new(AtomicBool::new(false));
    // アサーションが失敗（panic）しても watchdog を止めて join する RAII ガード。
    struct WatchdogGuard(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);
    impl Drop for WatchdogGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
            if let Some(h) = self.1.take() {
                let _ = h.join();
            }
        }
    }
    let _guard = {
        let flag = Arc::clone(&finished);
        let h = std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < VCPU_THREAD_DEADLINE {
                if flag.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            eprintln!("hvf_device: WATCHDOG EXPIRED");
            std::process::exit(124);
        });
        WatchdogGuard(Arc::clone(&finished), Some(h))
    };

    let layout = Arm64Layout::new(4 << 20, 1, 0).unwrap();
    let vm = Arc::new(create_vm_with_gic_or_precondition(&layout));
    let page = HostMapping::page_size().unwrap();
    let mut host = HostMapping::new(page).unwrap();
    // オフセット 0: `b .`。オフセット 0x100: `hvc #0` の後に `b .`。
    host.write_bytes(0, &0x1400_0000u32.to_le_bytes()).unwrap();
    host.write_bytes(0x100, &0xD400_0002u32.to_le_bytes())
        .unwrap();
    host.write_bytes(0x104, &0x1400_0000u32.to_le_bytes())
        .unwrap();
    let mapping = vm.vm().map(host, 0, BASE, page, MemoryFlags::RWX).unwrap();

    let handlers = || ExitHandlers {
        mmio: MmioHandler::new(),
        hvc: HvcHandler::new(),
        timer: TimerHandler::new(),
    };
    let setup = |pc: u64, x0: u64| {
        move |vcpu: &mut fandhe_container_microvm::hvf::HvVcpu<'_>| {
            vcpu.set_reg(HvReg::PC, pc)?;
            vcpu.set_reg(HvReg::x(0).unwrap(), x0)?;
            // EL1h と DAIF のマスク。
            vcpu.set_reg(HvReg::CPSR, 0x3c5)
        }
    };

    // 場面 A: 停止要求で 1 秒以内に Requested。
    let counts = Arc::new(ExitCounts::new());
    let config = VcpuThreadConfig {
        observer: Some(counts.clone()),
        ..VcpuThreadConfig::default()
    };
    let handle = VcpuThread::spawn(Arc::clone(&vm), setup(BASE, 0), handlers(), config).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(!handle.is_finished());
    let t = Instant::now();
    let report = handle.stop(Duration::from_secs(1)).unwrap();
    assert_eq!(report.reason, StopReason::Requested);
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert_eq!(counts.count(ExitKind::Hvc), 0);

    // 場面 B: 未知の関数 ID の HVC は NOT_SUPPORTED で再開し、VM は止まらない。
    let counts = Arc::new(ExitCounts::new());
    let config = VcpuThreadConfig {
        observer: Some(counts.clone()),
        ..VcpuThreadConfig::default()
    };
    let handle = VcpuThread::spawn(
        Arc::clone(&vm),
        setup(BASE + 0x100, 0x8400_00ff),
        handlers(),
        config,
    )
    .unwrap();
    let start = Instant::now();
    while counts.count(ExitKind::Hvc) < 1 && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(counts.count(ExitKind::Hvc), 1);
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !handle.is_finished(),
        "unknown psci id must not stop the vm"
    );
    let report = handle.stop(Duration::from_secs(1)).unwrap();
    assert_eq!(report.reason, StopReason::Requested);
    assert_eq!(counts.count(ExitKind::Hvc), 1);

    // スレッドが持っていた Arc は stop の Ok で解放済み。
    mapping.unmap().unwrap();
    drop(vm);
}

/// `hv_gic_*` の実行時解決（`dlsym`）と照会 API を確かめる（TASK-192.3・#3789・MVM-5・MVM-4）。
/// macOS 14 では `UNIMPLEMENTED: hypervisor GIC requires macOS 15 or later` で落ちる（dyld のエラーは出ない）。
/// 待ちを持たない同期の照会だけなので watchdog は不要。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_gic_symbols_resolve() {
    let api = match GicApi::get() {
        Ok(api) => api,
        Err(e) => panic!("hvf_device: gic: {e}"),
    };
    let dist = api.distributor_size().unwrap();
    let dist_align = api.distributor_base_alignment().unwrap();
    let redist = api.redistributor_size().unwrap();
    let redist_align = api.redistributor_base_alignment().unwrap();
    let (spi_base, spi_count) = api.spi_interrupt_range().unwrap();
    eprintln!(
        "hvf_device: gic: distributor size={dist} align={dist_align}, redistributor size={redist} align={redist_align}, spi base={spi_base} count={spi_count}"
    );
    assert!(dist > 0 && redist > 0);
    assert!(dist_align.is_power_of_two() && redist_align.is_power_of_two());
    assert!(spi_base >= 32 && spi_count > 0);

    let timer = api.intid(HvGicIntid::EL1_VIRTUAL_TIMER).unwrap().get();
    eprintln!("hvf_device: EL1_VIRTUAL_TIMER intid={timer}");
    assert!((16..=31).contains(&timer));
}

/// GIC を vCPU より前に作れること、virtual timer の intid が FDT と一致すること、アラインの違反が
/// VM を作る前に `InvalidArgument` で拒否されることを確かめる（TASK-192.12・#3792・MVM-5・MVM-1）。
/// 同期呼び出しのみでゲストを走らせないため watchdog は不要。1 プロセス 1 VM のため VM は常に 1 個ずつ。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_gic_create_before_vcpu() {
    let layout = Arm64Layout::new(4 << 20, 1, 0).unwrap();

    let gic = match HvfGic::probe(&layout) {
        Ok(g) => g,
        Err(e) => panic!("hvf_device: gic: {e}"),
    };
    let g = gic.geometry();
    eprintln!(
        "hvf_device: gic create: distributor size={} align={}, redistributor size={} align={}, virtual timer intid={}",
        g.dist_size,
        g.dist_align,
        g.redist_size_per_cpu,
        g.redist_align,
        gic.virtual_timer_intid()
    );
    check_virtual_timer_intid(gic.virtual_timer_intid()).unwrap();
    assert_eq!(
        gic.virtual_timer_intid(),
        ARM64_PPI_INTID_BASE + ARM64_TIMER_VIRT_PPI
    );

    // アラインの違反は VM を作る前に拒否される（直後に VM を作れる = 取り残しがない）。
    let mut bad = layout.clone();
    bad.gic_dist.base =
        fandhe_container_microvm::guest_memory::GuestAddress::new(bad.gic_dist.base.raw() + 1);
    assert_eq!(
        VmWithGic::create(&bad).unwrap_err().code(),
        MicrovmErrorCode::InvalidArgument
    );
    drop(create_vm_or_precondition());

    // 正しい配置: GIC を作ってから vCPU を作れる。
    let vgic = create_vm_with_gic_or_precondition(&layout);
    let mut vcpu = vgic.create_vcpu().unwrap();
    vcpu.set_sys_reg(HvSysReg::MPIDR_EL1, u64::from(ARM64_BOOT_CPU_MPIDR))
        .unwrap();
    let mpidr = vcpu.get_sys_reg(HvSysReg::MPIDR_EL1).unwrap();
    eprintln!("hvf_device: gic create: MPIDR_EL1 readback={mpidr:#x}");
    // affinity（Aff0..Aff2 = bit 0..23）が FDT の cpu@0 の reg と一致する。
    assert_eq!(mpidr & 0x00ff_ffff, u64::from(ARM64_BOOT_CPU_MPIDR));
    drop(vcpu);
    drop(vgic);
}

/// `hvf_device_spi_reaches_guest` のゲストプログラム（arm64。`llvm-mc -triple=aarch64` で符号化した命令語）。
///
/// 手順: GICR_WAKER の ProcessorSleep を下ろす → GICD_CTLR(ARE_NS|EnableGrp1) → INTID 48 を group 1・edge・
/// 優先度 0x80・affinity 0 にして有効化 → CPU interface(SRE・PMR・IGRPEN1) → 窓 + `SPI_READY_OFFSET` へ書いて
/// 準備完了を知らせる → `wfi` → `ICC_IAR1_EL1` を読み、1023(spurious) なら `wfi` へ戻る → 読んだ INTID を
/// virtio-mmio の窓(0x0a00_0000。未 map)へ書く → EOIR → `b .`。
/// GIC つきの構成では WFI は exit しない(#3803)。ホストが初期化の完了を知る手段は、この準備完了の書き込みだけである。
/// 基底アドレス(GICD 0x0800_0000・GICR 0x0820_0000・窓 0x0a00_0000)と INTID 48 はコード中に固定してあり、
/// 試験本体が `Arm64Layout` の値と一致することを先に assert する。PSTATE.I はマスクのまま(CPSR 0x3c5)。
const SPI_GUEST_CODE: [u32; 37] = [
    0xD2A1_0001, // movz x1, #0x0800, lsl #16        ; GICD
    0xD2A1_0402, // movz x2, #0x0820, lsl #16        ; GICR RD_base
    0xD2A1_4003, // movz x3, #0x0a00, lsl #16        ; virtio-mmio の窓
    0xB940_1444, // ldr  w4, [x2, #0x14]             ; GICR_WAKER
    0x121E_7884, // and  w4, w4, #~2                 ; ProcessorSleep = 0
    0xB900_1444, // str  w4, [x2, #0x14]
    0xB940_1444, // ldr  w4, [x2, #0x14]
    0x3717_FFE4, // tbnz w4, #2, .-4                 ; ChildrenAsleep が 0 になるまで
    0x5280_0264, // movz w4, #0x13                   ; ARE_NS | EnableGrp1A | EnableGrp1
    0xB900_0024, // str  w4, [x1]                    ; GICD_CTLR
    0xB940_0024, // ldr  w4, [x1]
    0x37FF_FFE4, // tbnz w4, #31, .-4                ; RWP が 0 になるまで
    0x52A0_0024, // movz w4, #1, lsl #16             ; INTID 48 = bit 16
    0xB900_8424, // str  w4, [x1, #0x84]             ; GICD_IGROUPR1: group 1
    0x5280_0044, // movz w4, #2
    0xB90C_0C24, // str  w4, [x1, #0xc0c]            ; GICD_ICFGR3 の INTID 48: edge
    0x5280_1004, // movz w4, #0x80
    0x3910_C024, // strb w4, [x1, #0x430]            ; GICD_IPRIORITYR48
    0xF930_C03F, // str  xzr, [x1, #0x6180]          ; GICD_IROUTER48 = affinity 0
    0x52A0_0024, // movz w4, #1, lsl #16
    0xB901_0424, // str  w4, [x1, #0x104]            ; GICD_ISENABLER1
    0xD538_CCA4, // mrs  x4, ICC_SRE_EL1
    0xB240_0084, // orr  x4, x4, #1                  ; SRE
    0xD518_CCA4, // msr  ICC_SRE_EL1, x4
    0xD503_3FDF, // isb
    0xD280_1FE4, // movz x4, #0xff
    0xD518_4604, // msr  ICC_PMR_EL1, x4
    0xD280_0024, // movz x4, #1
    0xD518_CCE4, // msr  ICC_IGRPEN1_EL1, x4
    0xD503_3FDF, // isb
    SPI_READY_STORE,
    0xD503_207F, // wfi                              ; loop:
    0xD538_CC00, // mrs  x0, ICC_IAR1_EL1
    0xF10F_FC1F, // cmp  x0, #1023
    0x54FF_FFA0, // b.eq loop                        ; spurious なら待ち直す
    0xB900_0060, // str  w0, [x3]                    ; MMIO exit: 読んだ INTID を書く
    0xD518_CC20, // msr  ICC_EOIR1_EL1, x0
];

/// 末尾の `b .`（`SPI_GUEST_CODE` の後ろへ置く）。
const SPI_GUEST_HALT: u32 = 0x1400_0000;

/// `str w4, [x3, #4]`。ゲストが GIC の初期化を終えたことを窓 + `SPI_READY_OFFSET` への書き込みで知らせる。
const SPI_READY_STORE: u32 = 0xB900_0464;
/// 準備完了の書き込みの窓の中のオフセット（INTID の書き込みは 0）。
const SPI_READY_OFFSET: u64 = 4;

/// 全体期限（`hvf_device_spi_reaches_guest`）。
const SPI_DEADLINE: Duration = Duration::from_secs(20);
/// 再開した vCPU が `wfi` で寝るまで注入を待つ幅。早すぎても pending のまま `wfi` を素通りするだけで、失敗にはならない。
const SPI_INJECT_DELAY: Duration = Duration::from_millis(50);
/// `run_once` の期限切れの診断を出す時間を残すため、watchdog を遅らせる幅。
const SPI_WATCHDOG_MARGIN: Duration = Duration::from_secs(5);
/// vCPU の exit 回数の上限（無限ループの歯止め）。
const SPI_MAX_EXITS: u32 = 256;

/// `SPI_GUEST_CODE` のどの待ちで止まったかを PC から決める（#3803 の切り分け用）。
/// 命令の番号は `SPI_GUEST_CODE` の並びに対応する（`GICR_WAKER` の待ち 6〜7、`GICD_CTLR` の RWP の待ち 10〜11）。
fn spi_stuck_stage(pc: u64, base: u64) -> &'static str {
    const WFI: u32 = 0xD503_207F;
    let wfi = SPI_GUEST_CODE.iter().position(|w| *w == WFI).unwrap() as u64;
    match pc.wrapping_sub(base) / 4 {
        6 | 7 => "gicr-waker",
        10 | 11 => "gicd-rwp",
        i if i == wfi || i == wfi + 1 => "wfi",
        _ => "other",
    }
}

/// ホストの `GicSpiLine::trigger`（edge の SPI）が、ゲストの `ICC_IAR1_EL1` で設定した INTID として読めることを確かめる。
/// 注入は製品の経路と同じく、vCPU が `hv_vcpu_run` の中で `wfi` している間に vCPU 以外のスレッドから行う。
/// 契機は WFI の exit ではなく準備完了の書き込みである（GIC つきの構成では WFI は exit しない。#3803・#3994）。
/// TASK-192.13・#3795・MVM-5・MVM-1。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_spi_reaches_guest() {
    const BASE: u64 = 0x4000_0000;
    const WINDOW: u64 = 0x0a00_0000;
    let layout = Arm64Layout::new(4 << 20, 1, 1).unwrap();
    // ゲストコードに固定した値と配置の一致。
    assert_eq!(layout.gic_dist.base.raw(), 0x0800_0000);
    assert_eq!(layout.gic_redist.base.raw(), 0x0820_0000);
    assert_eq!(layout.virtio_mmio_window(0).unwrap().base.raw(), WINDOW);
    assert_eq!(layout.ram.base.raw(), BASE);

    let vgic = create_vm_with_gic_or_precondition(&layout);
    let line = vgic.spi_line(&layout, 0).unwrap();
    assert_eq!(line.intid(), 48);
    let (spi_base, spi_count) = vgic.gic().spi_range();
    eprintln!(
        "hvf_device: spi: range base={spi_base} count={spi_count} intid={}",
        line.intid()
    );

    let page = HostMapping::page_size().unwrap();
    let mut host = HostMapping::new(page).unwrap();
    for (i, w) in SPI_GUEST_CODE.iter().chain([&SPI_GUEST_HALT]).enumerate() {
        host.write_bytes(i * 4, &w.to_le_bytes()).unwrap();
    }
    let mapping = vgic
        .vm()
        .map(host, 0, BASE, page, MemoryFlags::RWX)
        .unwrap();

    let mut vcpu = vgic.create_vcpu().unwrap();
    vcpu.set_sys_reg(HvSysReg::MPIDR_EL1, u64::from(ARM64_BOOT_CPU_MPIDR))
        .unwrap();
    vcpu.set_reg(HvReg::PC, BASE).unwrap();
    // 0x3c5: EL1h・DAIF マスク（例外ベクタ不要。ICC_IAR1_EL1 はマスク中でも読める）。
    vcpu.set_reg(HvReg::CPSR, 0x3c5).unwrap();

    // 実行が戻らないハングの歯止め（REPAIR-5）。panic でも止まる RAII で持ち、`run_once` の期限より後に効かせる。
    // 手書きの watchdog は panic の後も動き続け、次の試験の途中でプロセスを終わらせていた（#3803）。
    let watchdog = Watchdog::start(SPI_DEADLINE + SPI_WATCHDOG_MARGIN);

    let mut delivered: Option<u64> = None;
    let mut injector: Option<std::thread::JoinHandle<Result<(), String>>> = None;
    let mut wfi_exits = 0u32;
    for _ in 0..SPI_MAX_EXITS {
        let exit = match vcpu.run_once(SPI_DEADLINE) {
            Ok(e) => e,
            Err(e) => {
                // 期限切れの後も vCPU は持ち主のスレッドで読める。どの待ちで止まったかを PC で区別する。
                let pc = vcpu.get_reg(HvReg::PC);
                let x4 = vcpu.get_reg(HvReg::x(4).unwrap());
                let stage = pc
                    .as_ref()
                    .map_or("unknown", |pc| spi_stuck_stage(*pc, BASE));
                eprintln!("hvf_device: spi: stuck stage={stage} pc={pc:x?} x4={x4:x?}");
                panic!("hvf_device: spi: run failed: {e}");
            }
        };
        let HvVcpuExit::Exception(ex) = exit else {
            panic!("hvf_device: spi: unexpected exit {exit:?}");
        };
        match decode_esr(ex.syndrome) {
            // GIC つきの構成では来ない(#3803)。exit する環境でも止まらないよう、命令を進めて再開する。
            // 1 ms 待つのは、`SPI_INJECT_DELAY` の注入より先に `SPI_MAX_EXITS` を使い切らないため。
            EsrClass::Wfx(WfxKind::Wfi) => {
                wfi_exits += 1;
                std::thread::sleep(Duration::from_millis(1));
                let pc = vcpu.get_reg(HvReg::PC).unwrap();
                let len = instruction_length(ex.syndrome).bytes();
                vcpu.set_reg(HvReg::PC, pc + len).unwrap();
            }
            EsrClass::DataAbort(da)
                if ex.physical_address == WINDOW + SPI_READY_OFFSET
                    && da.direction == AccessDirection::Write =>
            {
                assert!(injector.is_none(), "hvf_device: spi: ready written twice");
                // ゲストが IROUTER48(affinity 0)を書いた後の読み戻し(#3960・MVM-5)。IRM=0・affinity 0 なら宛先は vCPU 0。
                match vgic.spi_routing(line.intid()) {
                    Ok(raw) => {
                        eprintln!("hvf_device: spi: irouter48={raw:#x}");
                        assert_eq!(
                            decode_irouter(raw),
                            IrouterRoute::Affinity(0),
                            "hvf_device: spi: irouter48 is not affinity 0"
                        );
                        assert_eq!(spi_wake_target(Some(raw), None, 1), SpiWakeTarget::Vcpu(0));
                    }
                    Err(e) => eprintln!("hvf_device: spi: irouter48 unavailable: {e}"),
                }
                // vCPU スレッド以外からの注入(スレッドの制約の観測)。下の再開で vCPU が `wfi` へ入った後に届く。
                let l2 = line.clone();
                injector = Some(std::thread::spawn(move || {
                    std::thread::sleep(SPI_INJECT_DELAY);
                    let r = l2.trigger();
                    eprintln!("hvf_device: spi: set_spi from non-vcpu thread: {r:?}");
                    r.map_err(|e| e.to_string())
                }));
                let pc = vcpu.get_reg(HvReg::PC).unwrap();
                let len = instruction_length(ex.syndrome).bytes();
                vcpu.set_reg(HvReg::PC, pc + len).unwrap();
            }
            EsrClass::DataAbort(da)
                if ex.physical_address == WINDOW && da.direction == AccessDirection::Write =>
            {
                let reg = HvReg::x(da.register.get()).unwrap();
                delivered = Some(vcpu.get_reg(reg).unwrap() & 0xffff_ffff);
                break;
            }
            other => panic!(
                "hvf_device: spi: unexpected guest exit {other:?} pa={:#x} syndrome={:#x}",
                ex.physical_address, ex.syndrome
            ),
        }
    }
    drop(watchdog);

    let Some(value) = delivered else {
        panic!("hvf_device: spi: did not reach the guest within {SPI_MAX_EXITS} exits");
    };
    eprintln!("hvf_device: spi: guest read intid={value}");
    eprintln!("hvf_device: spi: wfi exits={wfi_exits}");
    assert_ne!(value, 1023, "spurious intid: spi did not reach the guest");
    assert_eq!(value, 48);
    assert_eq!(value, u64::from(line.intid()));
    let injector = injector.expect("hvf_device: spi: value arrived before the ready write");
    if let Err(e) = injector.join().unwrap() {
        panic!("hvf_device: spi: set_spi from a non-vcpu thread failed: {e}");
    }

    drop(vcpu);
    mapping.unmap().unwrap();
    drop(vgic);
}
/// PSCI のゲストコード（IPA 0x4000_0000 から）。VERSION を呼び、1.0 なら SYSTEM_OFF を呼ぶ。不一致・続行時は `b .`。
const PSCI_GUEST_CODE: [u32; 9] = [
    0xD2B0_8000, // 0x00: movz x0, #0x8400, lsl #16   ; PSCI_VERSION
    0xD400_0002, // 0x04: hvc  #0
    0xD2A0_0021, // 0x08: movz x1, #0x1, lsl #16      ; 0x0001_0000
    0xEB01_001F, // 0x0c: cmp  x0, x1
    0x5400_0081, // 0x10: b.ne 0x20
    0xD2B0_8000, // 0x14: movz x0, #0x8400, lsl #16
    0xF280_0100, // 0x18: movk x0, #0x8               ; SYSTEM_OFF
    0xD400_0002, // 0x1c: hvc  #0
    0x1400_0000, // 0x20: b    .
];

/// `hvf_device_psci_version_then_system_off` の全体期限。
const PSCI_DEADLINE: Duration = Duration::from_secs(20);

/// PSCI（HVC）の最小実装（TASK-192.11・#3794・MVM-5・MVM-1・REPAIR-5）。
/// 段 1: HVC の exit 時点の PC が HVC の次の命令であること（`handle_hvc` の仮定）を観測し、VERSION の応答を直接確かめる。
/// 段 2: 専用スレッドの実行ループで VERSION → SYSTEM_OFF を通し、`GuestShutdown` と exit の並び `[hvc, hvc]` を確かめる。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_psci_version_then_system_off() {
    use fandhe_container_microvm::hvf::hvc::{HvcHandler, handle_hvc};
    use fandhe_container_microvm::hvf::mmio::MmioHandler;
    use fandhe_container_microvm::hvf::timer::TimerHandler;
    use fandhe_container_microvm::hvf::{ExitHandlers, VcpuThread, VcpuThreadConfig};
    use fandhe_container_microvm::hvf_loop::{ExitAction, ExitKind, VcpuExitObserver};
    use fandhe_container_microvm::stop::StopReason;
    use std::sync::Mutex;
    use std::time::Instant;

    const BASE: u64 = 0x4000_0000;

    // exit の並びを記録する観測器（上限つき。ブロックしない）。
    #[derive(Debug, Default)]
    struct ExitSeq(Mutex<Vec<ExitKind>>);
    impl VcpuExitObserver for ExitSeq {
        fn on_exit(&self, kind: ExitKind) {
            if let Ok(mut v) = self.0.lock()
                && v.len() < 64
            {
                v.push(kind);
            }
        }
    }

    let finished = Arc::new(AtomicBool::new(false));
    struct WatchdogGuard(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);
    impl Drop for WatchdogGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
            if let Some(h) = self.1.take() {
                let _ = h.join();
            }
        }
    }
    let _guard = {
        let flag = Arc::clone(&finished);
        let h = std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < PSCI_DEADLINE {
                if flag.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            eprintln!("hvf_device: WATCHDOG EXPIRED");
            std::process::exit(124);
        });
        WatchdogGuard(Arc::clone(&finished), Some(h))
    };

    let layout = Arm64Layout::new(4 << 20, 1, 0).unwrap();
    let vm = Arc::new(create_vm_with_gic_or_precondition(&layout));
    let page = HostMapping::page_size().unwrap();
    let mut host = HostMapping::new(page).unwrap();
    for (i, w) in PSCI_GUEST_CODE.iter().enumerate() {
        host.write_bytes(i * 4, &w.to_le_bytes()).unwrap();
    }
    let mapping = vm.vm().map(host, 0, BASE, page, MemoryFlags::RWX).unwrap();

    // 段 1: PC の観測と VERSION の応答。
    {
        let mut vcpu = vm.create_vcpu().unwrap();
        vcpu.set_reg(HvReg::PC, BASE).unwrap();
        vcpu.set_reg(HvReg::CPSR, 0x3c5).unwrap();
        let exit = vcpu.run_once(PSCI_DEADLINE).unwrap();
        let HvVcpuExit::Exception(ex) = exit else {
            panic!("hvf_device: psci: unexpected exit {exit:?}");
        };
        assert_eq!(decode_esr(ex.syndrome), EsrClass::Hvc { imm16: 0 });
        let pc = vcpu.get_reg(HvReg::PC).unwrap();
        eprintln!(
            "hvf_device: psci: pc at hvc exit = {pc:#x} (hvc at {:#x})",
            BASE + 4
        );
        assert_eq!(
            pc,
            BASE + 8,
            "hvc exit pc must point past the hvc instruction; handle_hvc assumes it"
        );
        let action = handle_hvc(&mut vcpu, &mut HvcHandler::new(), 0, &ex).unwrap();
        assert!(matches!(action, ExitAction::Continue));
        assert_eq!(vcpu.get_reg(HvReg::x(0).unwrap()).unwrap(), 0x0001_0000);
        assert_eq!(vcpu.get_reg(HvReg::PC).unwrap(), BASE + 8);
    }

    // 段 2: 実行ループで VERSION → SYSTEM_OFF。
    let seq = Arc::new(ExitSeq::default());
    let config = VcpuThreadConfig {
        observer: Some(seq.clone()),
        ..VcpuThreadConfig::default()
    };
    let handlers = ExitHandlers {
        mmio: MmioHandler::new(),
        hvc: HvcHandler::new(),
        timer: TimerHandler::new(),
    };
    let handle = VcpuThread::spawn(
        Arc::clone(&vm),
        |vcpu: &mut fandhe_container_microvm::hvf::HvVcpu<'_>| {
            vcpu.set_reg(HvReg::PC, BASE)?;
            vcpu.set_reg(HvReg::CPSR, 0x3c5)
        },
        handlers,
        config,
    )
    .unwrap();
    let start = Instant::now();
    while !handle.is_finished() && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(handle.is_finished(), "guest did not shut down within 5s");
    let report = handle.stop(Duration::from_secs(1)).unwrap();
    assert_eq!(report.reason, StopReason::GuestShutdown);
    let seen = seq.0.lock().unwrap().clone();
    assert_eq!(seen, vec![ExitKind::Hvc, ExitKind::Hvc]);

    mapping.unmap().unwrap();
    drop(vm);
}

/// PSCI の CPU_ON・CPU_OFF・AFFINITY_INFO のゲストコード（IPA 0x4000_0000 から。`llvm-mc -triple=aarch64 -show-encoding` で符号化）。
/// CPU_ON(0) → CPU_ON(1) → CPU_OFF → AFFINITY_INFO(0) → VERSION の順に `hvc #0` を呼ぶ。最後の VERSION は継続の証跡。
const PSCI_CPU_GUEST_CODE: [u32; 20] = [
    0xd2b0_8000, // 0x00: movz x0,#0x8400,lsl16
    0xf280_0060, // 0x04: movk x0,#3 ; CPU_ON
    0xd280_0001, // 0x08: movz x1,#0
    0xd280_0002, // 0x0c: movz x2,#0
    0xd400_0002, // 0x10: hvc
    0xd2b0_8000, // 0x14: movz x0,#0x8400,lsl16
    0xf280_0060, // 0x18: movk x0,#3 ; CPU_ON
    0xd280_0021, // 0x1c: movz x1,#1
    0xd400_0002, // 0x20: hvc
    0xd2b0_8000, // 0x24: movz x0,#0x8400,lsl16
    0xf280_0040, // 0x28: movk x0,#2 ; CPU_OFF
    0xd400_0002, // 0x2c: hvc
    0xd2b0_8000, // 0x30: movz x0,#0x8400,lsl16
    0xf280_0080, // 0x34: movk x0,#4 ; AFFINITY_INFO
    0xd280_0001, // 0x38: movz x1,#0
    0xd280_0002, // 0x3c: movz x2,#0
    0xd400_0002, // 0x40: hvc
    0xd2b0_8000, // 0x44: movz x0,#0x8400,lsl16 ; VERSION
    0xd400_0002, // 0x48: hvc
    0x1400_0000, // 0x4c: b .
];

/// 1 vCPU 構成の既定ハンドラで、CPU_ON・CPU_OFF・AFFINITY_INFO の応答がゲストの X0 へ戻り、実行が継続することを確かめる。
/// CPU_ON(0)=ALREADY_ON(-4)、CPU_ON(存在しない対象)=INVALID_PARAMETERS(-2)、CPU_OFF=DENIED(-3)、AFFINITY_INFO(0)=ON(0)。
/// 各呼び出しの後に次の HVC へ到達すること（最後は VERSION=1.0）で継続を確認する。MVM-5・MVM-1・REPAIR-12・#3883。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_psci_cpu_power_responses() {
    use fandhe_container_microvm::hvf::hvc::{HvcHandler, handle_hvc};
    use fandhe_container_microvm::hvf_loop::ExitAction;

    // 全体期限の watchdog（REPAIR-5）。run_once の期限が効かない場合も WATCHDOG EXPIRED と終了コード 124 で失敗する。
    let _wd = Watchdog::start(Duration::from_secs(60));
    const BASE: u64 = 0x4000_0000;
    let layout = Arm64Layout::new(4 << 20, 1, 0).unwrap();
    let vm = create_vm_with_gic_or_precondition(&layout);
    let page = HostMapping::page_size().unwrap();
    let mut host = HostMapping::new(page).unwrap();
    for (i, w) in PSCI_CPU_GUEST_CODE.iter().enumerate() {
        host.write_bytes(i * 4, &w.to_le_bytes()).unwrap();
    }
    let mapping = vm.vm().map(host, 0, BASE, page, MemoryFlags::RWX).unwrap();

    let mut vcpu = vm.create_vcpu().unwrap();
    vcpu.set_reg(HvReg::PC, BASE).unwrap();
    vcpu.set_reg(HvReg::CPSR, 0x3c5).unwrap();
    let mut handler = HvcHandler::new();
    // (期待する X0 の下位 32 ビット, 呼び出しの名前)
    let expected: [(u32, &str); 5] = [
        (0xFFFF_FFFC, "CPU_ON(0) ALREADY_ON"),
        (0xFFFF_FFFE, "CPU_ON(1) INVALID_PARAMETERS"),
        (0xFFFF_FFFD, "CPU_OFF DENIED"),
        (0, "AFFINITY_INFO(0) ON"),
        (0x0001_0000, "VERSION 1.0 (continuation)"),
    ];
    for (want, name) in expected {
        let exit = vcpu.run_once(PSCI_DEADLINE).unwrap();
        let HvVcpuExit::Exception(ex) = exit else {
            panic!("hvf_device: psci_cpu: unexpected exit {exit:?} before {name}");
        };
        assert_eq!(decode_esr(ex.syndrome), EsrClass::Hvc { imm16: 0 });
        let action = handle_hvc(&mut vcpu, &mut handler, 0, &ex).unwrap();
        assert!(matches!(action, ExitAction::Continue), "{name}");
        let x0 = vcpu.get_reg(HvReg::x(0).unwrap()).unwrap();
        assert_eq!(x0 as u32, want, "{name}: x0 = {x0:#x}");
    }

    drop(vcpu);
    mapping.unmap().unwrap();
}

/// `hvf_device_mmio_reaches_virtio_mmio` のゲストプログラム（arm64。`llvm-mc -triple=aarch64 -show-encoding` で符号化）。
///
/// MagicValue（offset 0）と Version（offset 4）を `ldr w` で読み、期待値（0x7472_6976）と比べる。一致なら窓 1 の offset 0 へ
/// 目印 0x600d と Version を続けて書き、不一致なら 0xbad を書く。Version の書き込みが 2 回目の書き込みとして届くことで、
/// 「PC が二重に進んで命令が飛ぶ」「IPA の下位ビットが落ちて Version が MagicValue に化ける」を判別できる。
const MMIO_GUEST_CODE: [u32; 14] = [
    0xD2A1_4000, // movz x0, #0x0a00, lsl #16        ; 窓 0（virtio-block）
    0xB940_0001, // ldr  w1, [x0]                    ; MagicValue
    0x528D_2EC2, // movz w2, #0x6976                 ; 期待値の下位（負の対照は 0x6977 に差し替える）
    0x72AE_8E42, // movk w2, #0x7472, lsl #16
    0xB940_0404, // ldr  w4, [x0, #4]                ; Version
    0x6B02_003F, // cmp  w1, w2
    0x5400_00A1, // b.ne bad
    0x528C_01A3, // movz w3, #0x600d
    0xB902_0003, // str  w3, [x0, #0x200]            ; 窓 1 の offset 0
    0xB902_0004, // str  w4, [x0, #0x200]
    0x1400_0000, // b .
    0x5281_75A3, // bad: movz w3, #0xbad
    0xB902_0003, // str  w3, [x0, #0x200]
    0x1400_0000, // b .
];
/// 負の対照用に差し替える `movz w2, #0x6977`（期待値を 0x7472_6977 にする）。
const MMIO_GUEST_MOVZ_WRONG: u32 = 0x528D_2EE2;

/// MMIO の data abort がデバイスモデルへ届き、読み出し値がレジスタへ戻り、PC が進むことを確かめる。
/// virtio-block（窓 0）の MagicValue / Version を読み、窓 1 の観測器へゲストが書いた値を具体値で照合する。
/// 不一致の負の対照（期待値を 1 ずらした同じゲスト）も回す。実機で未観測の前提（PC の自動前進の有無・IPA の下位ビット）は
/// 値の食い違いとして失敗する（記録は人間担当の #3803）。TASK-192.10・#3793・MVM-5・MVM-1。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_mmio_reaches_virtio_mmio() {
    use fandhe_container_microvm::dispatch::{ExitDispatcher, MmioDevice};
    use fandhe_container_microvm::hvf::hvc::HvcHandler;
    use fandhe_container_microvm::hvf::mmio::MmioHandler;
    use fandhe_container_microvm::hvf::timer::TimerHandler;
    use fandhe_container_microvm::hvf::{ExitHandlers, VcpuThread, VcpuThreadConfig};
    use fandhe_container_microvm::hvf_loop::{ExitCounts, ExitKind};
    use fandhe_container_microvm::stop::StopReason;
    use fandhe_container_microvm::virtio_block::{MemoryBlockBackend, VirtioBlock};
    use fandhe_container_microvm::virtio_mmio::{
        MmioReadOutcome, MmioWriteOutcome, VirtioMmioTransport,
    };
    use std::sync::Mutex;
    use std::time::Instant;

    const BASE: u64 = 0x4000_0000;
    /// 観測器の記録の上限（ゲストが連打してもホストのメモリを増やさない）。
    const MAX_RECORDS: usize = 16;

    /// 窓 1 に置く観測器。書き込みを `(offset, 4 バイトの値)` で記録し、読み出しは 0。
    struct Recorder(Arc<Mutex<Vec<(u64, u32)>>>);
    impl MmioDevice for Recorder {
        fn read(&self, _offset: u64, data: &mut [u8]) -> MmioReadOutcome {
            data.fill(0);
            MmioReadOutcome::Handled
        }
        fn write(&mut self, offset: u64, data: &[u8]) -> MmioWriteOutcome {
            let mut v = [0u8; 4];
            for (d, s) in v.iter_mut().zip(data.iter()) {
                *d = *s;
            }
            let mut g = self.0.lock().unwrap();
            if g.len() < MAX_RECORDS {
                g.push((offset, u32::from_le_bytes(v)));
            }
            MmioWriteOutcome::Handled
        }
    }

    // 全体期限の watchdog（REPAIR-5）。
    let finished = Arc::new(AtomicBool::new(false));
    struct WatchdogGuard(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);
    impl Drop for WatchdogGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
            if let Some(h) = self.1.take() {
                let _ = h.join();
            }
        }
    }
    let _guard = {
        let flag = Arc::clone(&finished);
        let h = std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < VCPU_THREAD_DEADLINE {
                if flag.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            eprintln!("hvf_device: WATCHDOG EXPIRED");
            std::process::exit(124);
        });
        WatchdogGuard(Arc::clone(&finished), Some(h))
    };

    let layout = Arm64Layout::new(4 << 20, 1, 2).unwrap();
    let win0 = layout.virtio_mmio_window(0).unwrap().base.raw();
    let win1 = layout.virtio_mmio_window(1).unwrap().base.raw();
    // ゲストコードに固定した値と配置の一致。
    assert_eq!(win0, 0x0a00_0000);
    assert_eq!(win1, 0x0a00_0200);
    assert_eq!(layout.ram.base.raw(), BASE);

    let vm = Arc::new(create_vm_with_gic_or_precondition(&layout));
    let page = HostMapping::page_size().unwrap();
    // 場面 A のコードは BASE、場面 B（期待値を差し替えた同じゲスト）は BASE + page。
    let mut host_a = HostMapping::new(page).unwrap();
    let mut host_b = HostMapping::new(page).unwrap();
    for (i, w) in MMIO_GUEST_CODE.iter().enumerate() {
        host_a.write_bytes(i * 4, &w.to_le_bytes()).unwrap();
        let w_b = if i == 2 { MMIO_GUEST_MOVZ_WRONG } else { *w };
        host_b.write_bytes(i * 4, &w_b.to_le_bytes()).unwrap();
    }
    let map_a = vm
        .vm()
        .map(host_a, 0, BASE, page, MemoryFlags::RWX)
        .unwrap();
    let map_b = vm
        .vm()
        .map(host_b, 0, BASE + page as u64, page, MemoryFlags::RWX)
        .unwrap();

    // 1 場面を走らせ、観測器の記録が `expect.len()` 件になるまで待って停止する。
    let run = |pc: u64, expect: &[(u64, u32)]| -> u64 {
        let records = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = ExitDispatcher::new();
        let block = VirtioMmioTransport::new(VirtioBlock::new(
            MemoryBlockBackend::new(16 * 512, false).unwrap(),
        ))
        .unwrap();
        dispatcher
            .register_mmio(win0, 0x200, Box::new(block))
            .unwrap();
        dispatcher
            .register_mmio(win1, 0x200, Box::new(Recorder(Arc::clone(&records))))
            .unwrap();
        let handlers = ExitHandlers {
            mmio: MmioHandler::with_dispatcher(dispatcher),
            hvc: HvcHandler::new(),
            timer: TimerHandler::new(),
        };
        let counts = Arc::new(ExitCounts::new());
        let config = VcpuThreadConfig {
            observer: Some(counts.clone()),
            ..VcpuThreadConfig::default()
        };
        let setup = move |vcpu: &mut fandhe_container_microvm::hvf::HvVcpu<'_>| {
            vcpu.set_reg(HvReg::PC, pc)?;
            // EL1h と DAIF のマスク。
            vcpu.set_reg(HvReg::CPSR, 0x3c5)
        };
        let handle = VcpuThread::spawn(Arc::clone(&vm), setup, handlers, config).unwrap();
        let start = Instant::now();
        while records.lock().unwrap().len() < expect.len()
            && !handle.is_finished()
            && start.elapsed() < Duration::from_secs(5)
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        // 余計な書き込みが続いていないことを見るため少し待つ。
        std::thread::sleep(Duration::from_millis(100));
        let got = records.lock().unwrap().clone();
        eprintln!("hvf_device: mmio: pc={pc:#x} records={got:x?}");
        let report = handle.stop(Duration::from_secs(1)).unwrap();
        assert_eq!(report.reason, StopReason::Requested);
        assert_eq!(got.as_slice(), expect);
        counts.count(ExitKind::DataAbort)
    };

    // 場面 A（正）: MagicValue が一致 → 0x600d、続けて Version(2)。data abort は読み 2 + 書き 2。
    let aborts = run(BASE, &[(0, 0x600d), (0, 2)]);
    eprintln!("hvf_device: mmio: scenario A data aborts={aborts}");
    assert_eq!(aborts, 4);
    // 場面 B（負の対照）: 期待値を 0x7472_6977 にしたゲストは不一致の目印 0xbad だけを書く。
    let aborts = run(BASE + page as u64, &[(0, 0xbad)]);
    eprintln!("hvf_device: mmio: scenario B data aborts={aborts}");
    assert_eq!(aborts, 3);

    map_a.unmap().unwrap();
    map_b.unmap().unwrap();
    drop(vm);
}

/// 組み立ての試験の全体期限。ハングを失敗として残す（REPAIR-5）。
const ASSEMBLE_DEADLINE: Duration = Duration::from_secs(30);

/// 期限 watchdog（超過は `hvf_device: WATCHDOG EXPIRED` と終了コード 124）。panic しても止めて join する RAII ガード。
struct Watchdog(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);

impl Watchdog {
    fn start(deadline: Duration) -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        let f = Arc::clone(&flag);
        let h = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while start.elapsed() < deadline {
                if f.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            eprintln!("hvf_device: WATCHDOG EXPIRED");
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

fn assemble_config(
    layout: Arm64Layout,
    kernel: Vec<u8>,
    block: usize,
    serial: bool,
) -> fandhe_container_microvm::hvf::HvfMicroVmConfig<
    fandhe_container_microvm::virtio_block::MemoryBlockBackend,
    fandhe_container_microvm::virtio_net::MemoryNetBackend,
> {
    use fandhe_container_microvm::hvf::{HvfMicroVmConfig, VcpuThreadConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    HvfMicroVmConfig {
        vcpus: layout.vcpus,
        layout,
        kernel,
        initrd: None,
        cmdline: "console=ttyAMA0".to_string(),
        block: (0..block)
            .map(|_| MemoryBlockBackend::new(512 * 1024, false).unwrap())
            .collect(),
        net: Vec::new(),
        vcpu: VcpuThreadConfig::default(),
        serial,
    }
}

/// 環境の前提（権限・macOS 15 以降）を、組み立てとは別に先に確かめる。
fn require_vm_with_gic(layout: &Arm64Layout) {
    drop(create_vm_with_gic_or_precondition(layout));
}

/// microVM 構成体の組み立て（TASK-192.15・#3797・MVM-5・MVM-1）。
/// vcpus が上限 + 1 と構成・layout の不一致で `InvalidArgument`（資源を作る前）、正しい構成の組み立てで vCPU 0 の X0・PC・CPSR・MPIDR_EL1 の読み戻しが期待値と
/// 一致し、SCTLR_EL1 の M・C が 0、ゲスト RAM の FDT の位置に BE の `0xd00dfeed`、デバイスの窓と SPI が期待どおりであること、
/// drop の後に VM を作り直せること（解放の観測）を確かめる。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_assemble_sets_boot_registers() {
    use fandhe_container_microvm::arm64_layout::ARM64_VIRTIO_MMIO_BASE;
    use fandhe_container_microvm::boot_arm64::{
        ARM64_BOOT_CPSR, ARM64_MPIDR_AFFINITY_MASK, SCTLR_EL1_C, SCTLR_EL1_M,
    };
    use fandhe_container_microvm::hvf::HvfMicroVm;

    let _wd = Watchdog::start(ASSEMBLE_DEADLINE);
    let layout = Arm64Layout::new(64 << 20, 1, 1).unwrap();
    require_vm_with_gic(&layout);

    // 1. vcpus が上限 + 1、構成と layout の不一致は、資源を作る前に InvalidArgument（#3884）。直後に VM を作れる = 何も作っていない。
    let over = fandhe_container_microvm::hvf_abi::HVF_MAX_VCPUS + 1;
    let mut too_many = Arm64Layout::new(64 << 20, 1, 1).unwrap();
    too_many.vcpus = over;
    let mut cfg = assemble_config(too_many, synthetic_image(true), 1, false);
    cfg.vcpus = over;
    let e = HvfMicroVm::assemble(cfg).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    assert_eq!(e.message(), "too many vcpus for the hvf backend");
    drop(create_vm_or_precondition());
    let mut cfg = assemble_config(
        Arm64Layout::new(64 << 20, 1, 1).unwrap(),
        synthetic_image(true),
        1,
        false,
    );
    cfg.vcpus = 2;
    let e = HvfMicroVm::assemble(cfg).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    assert_eq!(e.message(), "vcpu layout does not match the configuration");
    drop(create_vm_or_precondition());

    // 2. 正しい構成。
    let vm =
        HvfMicroVm::assemble(assemble_config(layout, synthetic_image(true), 1, false)).unwrap();

    // 3. 起動レジスタ（生の値は #3803 の記録用に出す）。
    let boot = *vm.boot_registers();
    eprintln!(
        "hvf_device: boot x0={:#x} pc={:#x} cpsr={:#x} mpidr_el1={:#x} sctlr_el1={:#x}",
        boot.x0, boot.pc, boot.cpsr, boot.mpidr, boot.sctlr
    );
    assert_eq!(boot.x0, vm.loaded().fdt.base.raw());
    assert_eq!(boot.pc, vm.loaded().kernel.base.raw());
    assert_eq!(boot.pc, 0x4000_0000 + 0x8_0000);
    assert_eq!(boot.cpsr, ARM64_BOOT_CPSR);
    assert_eq!(boot.cpsr, 0x3c5);
    assert_eq!(
        boot.mpidr & ARM64_MPIDR_AFFINITY_MASK,
        u64::from(ARM64_BOOT_CPU_MPIDR)
    );
    assert_eq!(boot.sctlr & (SCTLR_EL1_M | SCTLR_EL1_C), 0);

    // 4. FDT の先頭は BE の 0xd00dfeed。
    let mut magic = [0u8; 4];
    vm.read_guest(vm.loaded().fdt.base.raw(), &mut magic)
        .unwrap();
    assert_eq!(magic, 0xd00d_feedu32.to_be_bytes());

    // 5. デバイス: block 1 台。窓 0x0a00_0000、SPI 16 -> INTID 48。
    let devices = vm.devices();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].window.base.raw(), ARM64_VIRTIO_MMIO_BASE);
    assert_eq!(devices[0].window.base.raw(), 0x0a00_0000);
    assert_eq!(devices[0].spi_intid, 48);

    // 6. start までゲストは走らない（vCPU スレッドはゲートで待機中）。start の後は `b .` のゲストが走り続け、stop は `Requested`。
    std::thread::sleep(Duration::from_millis(200));
    assert!(!vm.is_vcpu_finished());
    let running = vm.start().unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(!running.is_finished());
    let report = running.stop(Duration::from_secs(1)).unwrap();
    assert_eq!(
        report.reason,
        fandhe_container_microvm::stop::StopReason::Requested
    );

    // 7. stop（vCPU の破棄 -> デバイス -> RAM の unmap -> VM の破棄）の後に VM を作り直せる。
    drop(create_vm_or_precondition());
}

/// vCPU 1..N（AP）を parked で作る（#3884・MVM-5・MVM-1・REPAIR-5）。vcpus = 2 の assemble が成功し、vCPU 1 の `MPIDR_EL1` の
/// affinity が `arm64_vcpu_mpidr_affinity(1)` に一致し、start の後も AP は exit 0 件のまま走らず、stop で 2 台とも回収される。
/// 同じプロセスで、vcpus = 2 を start せず drop した後にも、vcpus = 1 の再 assemble → start → stop ができる。
/// 期限 watchdog 30 秒つき（超過は `hvf_device: WATCHDOG EXPIRED` と終了コード 124）。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_smp_parked_ap_assemble_and_stop() {
    use fandhe_container_microvm::arm64_layout::arm64_vcpu_mpidr_affinity;
    use fandhe_container_microvm::boot_arm64::ARM64_MPIDR_AFFINITY_MASK;
    use fandhe_container_microvm::hvf::HvfMicroVm;
    use fandhe_container_microvm::stop::StopReason;
    use std::time::Instant;

    let _wd = Watchdog::start(ASSEMBLE_DEADLINE);
    let layout2 = Arm64Layout::new(64 << 20, 2, 1).unwrap();
    require_vm_with_gic(&layout2);

    // 1. vcpus = 2 の assemble が成功し、各 vCPU の MPIDR_EL1 の affinity が FDT の cpu@N の reg と一致する。
    let vm = HvfMicroVm::assemble(assemble_config(
        layout2.clone(),
        synthetic_image(true),
        1,
        false,
    ))
    .unwrap();
    let mpidrs = vm.vcpu_mpidrs().to_vec();
    eprintln!(
        "hvf_device: smp: mpidr vcpu0={:#x} vcpu1={:#x}",
        mpidrs[0], mpidrs[1]
    );
    assert_eq!(mpidrs.len(), 2);
    assert_eq!(mpidrs[0], vm.boot_registers().mpidr);
    assert_eq!(
        mpidrs[0] & ARM64_MPIDR_AFFINITY_MASK,
        u64::from(ARM64_BOOT_CPU_MPIDR)
    );
    assert_eq!(
        mpidrs[1] & ARM64_MPIDR_AFFINITY_MASK,
        u64::from(arm64_vcpu_mpidr_affinity(1).unwrap())
    );

    // 2. start の後、BSP は `b .` で走り続け、AP は parked のまま（exit 0 件）。stop は 2 台とも回収する。
    let running = vm.start().unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(!running.is_finished());
    let t = Instant::now();
    let report = running.stop(Duration::from_secs(1)).unwrap();
    eprintln!(
        "hvf_device: smp: stop elapsed_us={} vcpus={} per_vcpu={:?}",
        t.elapsed().as_micros(),
        report.vcpu_count,
        report.per_vcpu
    );
    assert_eq!(report.reason, StopReason::Requested);
    assert_eq!(report.vcpu_count, 2);
    assert_eq!(report.per_vcpu.len(), 2);
    assert!(report.per_vcpu[0].runs >= 1);
    assert_eq!(report.per_vcpu[1].runs, 0);
    assert_eq!(report.per_vcpu[1].exits, 0);

    // 3. start しないまま drop（AP は parked のまま回収される）→ 同じプロセスで vcpus = 1 を組み立て直して stop まで通る。
    let vm =
        HvfMicroVm::assemble(assemble_config(layout2, synthetic_image(true), 1, false)).unwrap();
    drop(vm);
    let layout1 = Arm64Layout::new(64 << 20, 1, 1).unwrap();
    let vm =
        HvfMicroVm::assemble(assemble_config(layout1, synthetic_image(true), 1, false)).unwrap();
    assert_eq!(vm.vcpu_mpidrs().len(), 1);
    let running = vm.start().unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let report = running.stop(Duration::from_secs(1)).unwrap();
    assert_eq!(report.reason, StopReason::Requested);
    assert_eq!(report.vcpu_count, 1);
}

/// CPU_ON で AP を起動するゲスト（コードはヘッダ直後の offset 0x40 から置く。左のコメントはコード先頭からのバイト位置）。
/// 符号は `llvm-mc -triple=aarch64`（`-filetype=obj` で分岐を解決し `llvm-objdump -d` で確認）。命令を足すときは分岐（`b.ne`・`b.eq`・`cbz`・`b`）と
/// `adr` の相対オフセットを必ず再計算し、`flag`（8 バイト境界）の位置も保つこと。観測器は窓 1（0x0a00_0200）に置く。
///
/// BSP（vCPU 0）: `adr x20, ap_entry` → CPU_ON_64(target=1, entry=ap_entry, ctx=0x0123_4567_89ab_cdef) の結果を窓 1 の offset 0x00 へ書く →
/// AFFINITY_INFO_64(1, 0) が 0（ON）になるまで回し（上限つき）、値を 0x08 へ → 2 回目の CPU_ON の結果（期待は ALREADY_ON = -4）を 0x10 へ →
/// RAM の `flag` に 1 を書いて AP を進め → AFFINITY_INFO が 1（OFF）になるまで回し（上限つき）、値を 0x18 へ → SYSTEM_OFF。
/// 上限超過は 0xbad を 0xf8 へ書いて `b .`。
/// AP（vCPU 1）: `ap_entry` で `x0`（context_id）を退避し、`MPIDR_EL1` を 0x100、context_id を 0x108 へ書く → `flag` が 1 になるまで回り →
/// CPU_OFF。戻ってきたら失敗として 0xbad を 0x1f8 へ書く。
const SMP_CPU_ON_GUEST_CODE: [u32; 72] = [
    0x1000_06D4, // 0x00 adr  x20, ap_entry (+0xd8)
    0xD2B8_8000, // 0x04 movz x0, #0xc400, lsl #16
    0xF280_0060, // 0x08 movk x0, #3                 ; CPU_ON_64 = 0xC400_0003
    0xD280_0021, // 0x0c mov  x1, #1                 ; target = affinity(1)
    0xAA14_03E2, // 0x10 mov  x2, x20                ; entry
    0xD299_BDE3, // 0x14 movz x3, #0xcdef
    0xF2B1_3563, // 0x18 movk x3, #0x89ab, lsl #16
    0xF2C8_ACE3, // 0x1c movk x3, #0x4567, lsl #32
    0xF2E0_2463, // 0x20 movk x3, #0x0123, lsl #48   ; context_id = 0x0123_4567_89ab_cdef
    0xD400_0002, // 0x24 hvc  #0
    0xD2A1_4015, // 0x28 movz x21, #0x0a00, lsl #16
    0xF901_02A0, // 0x2c str  x0, [x21, #0x200]      ; 窓 1 offset 0x00 = CPU_ON の結果
    0xD288_480A, // 0x30 movz x10, #0x4240
    0xF2A0_01EA, // 0x34 movk x10, #0xf, lsl #16     ; 回数の上限 1_000_000
    0xD2B8_8000, // 0x38 wait_on: movz x0, #0xc400, lsl #16
    0xF280_0080, // 0x3c movk x0, #4                 ; AFFINITY_INFO_64
    0xD280_0021, // 0x40 mov  x1, #1
    0xD280_0002, // 0x44 mov  x2, #0
    0xD400_0002, // 0x48 hvc  #0
    0xB400_0080, // 0x4c cbz  x0, on_ok (+0x10)
    0xF100_054A, // 0x50 subs x10, x10, #1
    0x54FF_FF21, // 0x54 b.ne wait_on (-0x1c)
    0x1400_001D, // 0x58 b    fail (+0x74)
    0xF901_06A0, // 0x5c on_ok: str x0, [x21, #0x208] ; offset 0x08 = AFFINITY_INFO（ON = 0）
    0xD2B8_8000, // 0x60 movz x0, #0xc400, lsl #16
    0xF280_0060, // 0x64 movk x0, #3
    0xD280_0021, // 0x68 mov  x1, #1
    0xAA14_03E2, // 0x6c mov  x2, x20
    0xD280_0003, // 0x70 mov  x3, #0
    0xD400_0002, // 0x74 hvc  #0                     ; 2 回目の CPU_ON
    0xF901_0AA0, // 0x78 str  x0, [x21, #0x210]      ; offset 0x10 = ALREADY_ON（-4）
    0x1000_04E5, // 0x7c adr  x5, flag (+0x9c)
    0xD280_0026, // 0x80 mov  x6, #1
    0xF900_00A6, // 0x84 str  x6, [x5]               ; AP を進める
    0xD288_480A, // 0x88 movz x10, #0x4240
    0xF2A0_01EA, // 0x8c movk x10, #0xf, lsl #16
    0xD2B8_8000, // 0x90 wait_off: movz x0, #0xc400, lsl #16
    0xF280_0080, // 0x94 movk x0, #4
    0xD280_0021, // 0x98 mov  x1, #1
    0xD280_0002, // 0x9c mov  x2, #0
    0xD400_0002, // 0xa0 hvc  #0
    0xF100_041F, // 0xa4 cmp  x0, #1
    0x5400_0080, // 0xa8 b.eq off_ok (+0x10)
    0xF100_054A, // 0xac subs x10, x10, #1
    0x54FF_FF01, // 0xb0 b.ne wait_off (-0x20)
    0x1400_0006, // 0xb4 b    fail (+0x18)
    0xF901_0EA0, // 0xb8 off_ok: str x0, [x21, #0x218] ; offset 0x18 = AFFINITY_INFO（OFF = 1）
    0xD2B0_8000, // 0xbc movz x0, #0x8400, lsl #16
    0xF280_0100, // 0xc0 movk x0, #8                 ; SYSTEM_OFF
    0xD400_0002, // 0xc4 hvc  #0
    0x1400_0000, // 0xc8 b    .
    0xD281_75A6, // 0xcc fail: movz x6, #0xbad
    0xF901_7EA6, // 0xd0 str  x6, [x21, #0x2f8]      ; offset 0xf8 = 失敗の目印
    0x1400_0000, // 0xd4 b    .
    0xAA00_03E9, // 0xd8 ap_entry: mov x9, x0        ; context_id を退避
    0xD538_00A1, // 0xdc mrs  x1, mpidr_el1
    0xD2A1_4015, // 0xe0 movz x21, #0x0a00, lsl #16
    0xF901_82A1, // 0xe4 str  x1, [x21, #0x300]      ; offset 0x100 = MPIDR_EL1
    0xF901_86A9, // 0xe8 str  x9, [x21, #0x308]      ; offset 0x108 = context_id
    0x1000_0165, // 0xec adr  x5, flag (+0x2c)
    0xF940_00A6, // 0xf0 wait_flag: ldr x6, [x5]
    0xB4FF_FFE6, // 0xf4 cbz  x6, wait_flag (-0x4)
    0xD2B0_8000, // 0xf8 movz x0, #0x8400, lsl #16
    0xF280_0040, // 0xfc movk x0, #2                 ; CPU_OFF
    0xD400_0002, // 0x100 hvc #0
    0xD281_75A6, // 0x104 movz x6, #0xbad            ; CPU_OFF から戻ったら失敗
    0xF901_FEA6, // 0x108 str  x6, [x21, #0x3f8]     ; offset 0x1f8 = 失敗の目印
    0x1400_0000, // 0x10c b    .
    0xD503_201F, // 0x110 nop
    0xD503_201F, // 0x114 nop                        ; flag を 8 バイト境界にする
    0x0000_0000, // 0x118 flag（下位）
    0x0000_0000, // 0x11c flag（上位）
];

/// HVF の SMP: ゲストの PSCI CPU_ON で AP（vCPU 1）が起動する（#3891・MVM-5・MVM-1・REPAIR-5）。
///
/// 本番の配線（`HvfMicroVm::assemble` → `start`）を通す。vCPU 0 のゲストが CPU_ON で vCPU 1 を起動し、vCPU 1 のゲストが自分の
/// `MPIDR_EL1` と entry 時の X0（context_id。32 bit に収まらない値）を観測器の MMIO 窓へ書く。照合（具体値）:
/// CPU_ON の結果 0・AFFINITY_INFO が ON（0）・2 回目の CPU_ON が ALREADY_ON（-4）・CPU_OFF の後の AFFINITY_INFO が OFF（1）・
/// AP の MPIDR_EL1 の affinity が `arm64_vcpu_mpidr_affinity(1)`・AP の X0 が渡した context_id・失敗の目印（0xbad）が無いこと・
/// 停止理由が `GuestShutdown`・AP が 1 回以上 run したこと・停止の後に VM を作り直せること。生の値は
/// `hvf_device: smp_cpu_on:` の行に出す（記録は #3803）。AP の `mrs mpidr_el1` が SysReg の trap になる場合は fail-closed
/// （`Failed(Unimplemented)`）で落ちる。それ自体が #3803 で記録すべき観測事項。期限 watchdog 30 秒つき。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_smp_cpu_on_boots_ap() {
    use fandhe_container_microvm::arm64_layout::arm64_vcpu_mpidr_affinity;
    use fandhe_container_microvm::boot_arm64::ARM64_MPIDR_AFFINITY_MASK;
    use fandhe_container_microvm::dispatch::MmioDevice;
    use fandhe_container_microvm::hvf::HvfMicroVm;
    use fandhe_container_microvm::stop::StopReason;
    use fandhe_container_microvm::virtio_mmio::{MmioReadOutcome, MmioWriteOutcome};
    use std::sync::Mutex;
    use std::time::Instant;

    const WINDOW: u64 = 0x0a00_0200;
    const CTX: u64 = 0x0123_4567_89ab_cdef;
    /// 観測器の記録の上限（ゲストが連打してもホストのメモリを増やさない）。
    const MAX_RECORDS: usize = 16;

    /// 窓 1 の観測器。書き込みを `(offset, 最大 8 バイトの値)` で記録し、読み出しは 0。
    struct Recorder(Arc<Mutex<Vec<(u64, u64)>>>);
    impl MmioDevice for Recorder {
        fn read(&self, _offset: u64, data: &mut [u8]) -> MmioReadOutcome {
            data.fill(0);
            MmioReadOutcome::Handled
        }
        fn write(&mut self, offset: u64, data: &[u8]) -> MmioWriteOutcome {
            let mut v = [0u8; 8];
            for (d, s) in v.iter_mut().zip(data.iter()) {
                *d = *s;
            }
            let mut g = self.0.lock().unwrap();
            if g.len() < MAX_RECORDS {
                g.push((offset, u64::from_le_bytes(v)));
            }
            MmioWriteOutcome::Handled
        }
    }

    let _wd = Watchdog::start(ASSEMBLE_DEADLINE);
    let layout = Arm64Layout::new(64 << 20, 2, 1).unwrap();
    require_vm_with_gic(&layout);
    let vm = HvfMicroVm::assemble(assemble_config(
        layout,
        synthetic_image_with_code(true, &SMP_CPU_ON_GUEST_CODE),
        1,
        false,
    ))
    .unwrap();
    let records = Arc::new(Mutex::new(Vec::new()));
    vm.dispatcher()
        .lock()
        .unwrap()
        .register_mmio(WINDOW, 0x200, Box::new(Recorder(Arc::clone(&records))))
        .unwrap();

    let running = vm.start().unwrap();
    let begin = Instant::now();
    while !running.is_finished() && begin.elapsed() < Duration::from_secs(15) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(running.is_finished(), "guest did not reach SYSTEM_OFF");
    let report = running.stop(Duration::from_secs(2)).unwrap();
    let got = records.lock().unwrap().clone();
    eprintln!(
        "hvf_device: smp_cpu_on: records={got:x?} reason={:?} per_vcpu={:?}",
        report.reason, report.per_vcpu
    );
    let at = |offset: u64| got.iter().find(|(o, _)| *o == offset).map(|(_, v)| *v);

    assert_eq!(report.reason, StopReason::GuestShutdown);
    assert_eq!(report.vcpu_count, 2);
    assert!(report.per_vcpu[1].runs >= 1, "vcpu 1 never ran");
    assert_eq!(at(0xf8), None, "vcpu 0 hit a loop limit");
    assert_eq!(at(0x1f8), None, "vcpu 1 returned from CPU_OFF");
    assert_eq!(at(0x00), Some(0), "CPU_ON result");
    assert_eq!(at(0x08), Some(0), "AFFINITY_INFO after CPU_ON (ON)");
    assert_eq!(
        at(0x10),
        Some(0xFFFF_FFFF_FFFF_FFFC),
        "second CPU_ON (ALREADY_ON)"
    );
    assert_eq!(at(0x18), Some(1), "AFFINITY_INFO after CPU_OFF (OFF)");
    assert_eq!(
        at(0x100).map(|m| m & ARM64_MPIDR_AFFINITY_MASK),
        Some(u64::from(arm64_vcpu_mpidr_affinity(1).unwrap())),
        "MPIDR_EL1 seen by vcpu 1"
    );
    assert_eq!(at(0x108), Some(CTX), "context_id seen as X0 by vcpu 1");

    // 停止の後に VM を作り直せる（解放の観測）。
    drop(create_vm_or_precondition());
}

/// AP の CPU_OFF → 再 CPU_ON の往復で SCTLR_EL1.I が落ちることを観測するゲスト（#3936・MVM-5・MVM-1。コードの符号は
/// `clang --target=aarch64-linux-gnu -c` で組んだ 76 語。命令を足すときは再生成する）。
///
/// BSP（vCPU 0）: CPU_ON(1) → 結果を窓 1 の offset 0x00 へ → RAM の `cnt` が 1 になるまで待つ（上限つき）→ AFFINITY_INFO が OFF（1）に
/// なるまで待つ → 再 CPU_ON の結果を 0x08 へ → `cnt` が 2 → OFF を待つ → SYSTEM_OFF。上限超過は 0xbad を 0xf8 へ書いて `b .`。
/// AP（vCPU 1）: 1 回目の entry で SCTLR_EL1 を 0x100 へ書き、I（bit 12）を立てて読み戻した値を 0x110 へ、`cnt` = 1 にして CPU_OFF。
/// 2 回目の entry（`cnt` != 0）で entry 時点の SCTLR_EL1 を 0x108 へ書き、`cnt` = 2 にして CPU_OFF。戻ったら 0xbad を 0x1f8 へ。
const SMP_CPU_ON_ICACHE_GUEST_CODE: [u32; 76] = [
    0x10000634, 0xD2A14015, 0x10000905, 0x94000011, 0xF90102A0, 0xD2800028, 0x94000015, 0x9400001D,
    0x9400000C, 0xF90106A0, 0xD2800048, 0x94000010, 0x94000018, 0xD2B08000, 0xF2800100, 0xD4000002,
    0x14000000, 0xD28175A6, 0xF9017EA6, 0x14000000, 0xD2B88000, 0xF2800060, 0xD2800021, 0xAA1403E2,
    0xD2800003, 0xD4000002, 0xD65F03C0, 0xD288480A, 0xF2A001EA, 0xF94000A7, 0xEB0800FF, 0x54000080,
    0xF100054A, 0x54FFFF81, 0x17FFFFEF, 0xD65F03C0, 0xD288480A, 0xF2A001EA, 0xD2B88000, 0xF2800080,
    0xD2800021, 0xD2800002, 0xD4000002, 0xF100041F, 0x54000080, 0xF100054A, 0x54FFFF01, 0x17FFFFE2,
    0xD65F03C0, 0xD2A14015, 0x10000305, 0xD5381001, 0xF94000A7, 0xB5000147, 0xF90182A1, 0xB2740021,
    0xD5181001, 0xD5033FDF, 0xD5381002, 0xF9018AA2, 0xD2800027, 0xF90000A7, 0x14000004, 0xF90186A1,
    0xD2800047, 0xF90000A7, 0xD2B08000, 0xF2800040, 0xD4000002, 0xD28175A6, 0xF901FEA6, 0x14000000,
    0xD503201F, 0xD503201F, 0x00000000, 0x00000000,
];

/// HVF の SMP: I-cache を有効にして CPU_OFF した AP を再 CPU_ON すると、entry 時点の SCTLR_EL1.I が 0 になる
/// （#3936・MVM-5・MVM-1。DEN0022 の CPU_ON 後の状態。`sctlr_for_cpu_on` の HVF への書き込みと読み戻しを通した照合）。
///
/// 照合（具体値）: 1 回目の entry の I = 0・ゲストが立てた直後の I = 1・再 CPU_ON の結果 0・2 回目の entry の I = 0（M・C・EE も 0）・
/// 停止理由 `GuestShutdown`・失敗の目印（0xbad）が無いこと。生の値は `hvf_device: smp_icache:` の行に出す（記録は #3803）。
/// 期限 watchdog 30 秒つき。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_smp_cpu_on_clears_icache() {
    use fandhe_container_microvm::dispatch::MmioDevice;
    use fandhe_container_microvm::hvf::HvfMicroVm;
    use fandhe_container_microvm::stop::StopReason;
    use fandhe_container_microvm::virtio_mmio::{MmioReadOutcome, MmioWriteOutcome};
    use std::sync::Mutex;
    use std::time::Instant;

    const WINDOW: u64 = 0x0a00_0200;
    const MAX_RECORDS: usize = 16;
    /// SCTLR_EL1 の M・C・I・EE。
    const SCTLR_M: u64 = 1;
    const SCTLR_C: u64 = 1 << 2;
    const SCTLR_I: u64 = 1 << 12;
    const SCTLR_EE: u64 = 1 << 25;

    /// 窓 1 の観測器。書き込みを `(offset, 最大 8 バイトの値)` で記録し、読み出しは 0。
    struct Recorder(Arc<Mutex<Vec<(u64, u64)>>>);
    impl MmioDevice for Recorder {
        fn read(&self, _offset: u64, data: &mut [u8]) -> MmioReadOutcome {
            data.fill(0);
            MmioReadOutcome::Handled
        }
        fn write(&mut self, offset: u64, data: &[u8]) -> MmioWriteOutcome {
            let mut v = [0u8; 8];
            for (d, s) in v.iter_mut().zip(data.iter()) {
                *d = *s;
            }
            let mut g = self.0.lock().unwrap();
            if g.len() < MAX_RECORDS {
                g.push((offset, u64::from_le_bytes(v)));
            }
            MmioWriteOutcome::Handled
        }
    }

    let _wd = Watchdog::start(ASSEMBLE_DEADLINE);
    let layout = Arm64Layout::new(64 << 20, 2, 1).unwrap();
    require_vm_with_gic(&layout);
    let vm = HvfMicroVm::assemble(assemble_config(
        layout,
        synthetic_image_with_code(true, &SMP_CPU_ON_ICACHE_GUEST_CODE),
        1,
        false,
    ))
    .unwrap();
    let records = Arc::new(Mutex::new(Vec::new()));
    vm.dispatcher()
        .lock()
        .unwrap()
        .register_mmio(WINDOW, 0x200, Box::new(Recorder(Arc::clone(&records))))
        .unwrap();

    let running = vm.start().unwrap();
    let begin = Instant::now();
    while !running.is_finished() && begin.elapsed() < Duration::from_secs(15) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(running.is_finished(), "guest did not reach SYSTEM_OFF");
    let report = running.stop(Duration::from_secs(2)).unwrap();
    let got = records.lock().unwrap().clone();
    eprintln!(
        "hvf_device: smp_icache: records={got:x?} reason={:?} per_vcpu={:?}",
        report.reason, report.per_vcpu
    );
    let at = |offset: u64| got.iter().find(|(o, _)| *o == offset).map(|(_, v)| *v);

    assert_eq!(report.reason, StopReason::GuestShutdown);
    assert_eq!(at(0xf8), None, "vcpu 0 hit a loop limit");
    assert_eq!(at(0x1f8), None, "vcpu 1 returned from CPU_OFF");
    assert_eq!(at(0x00), Some(0), "first CPU_ON result");
    assert_eq!(at(0x08), Some(0), "second CPU_ON result");
    let first = at(0x100).expect("first entry SCTLR_EL1");
    let after_set = at(0x110).expect("SCTLR_EL1 after the guest set I");
    let second = at(0x108).expect("second entry SCTLR_EL1");
    assert_eq!(first & SCTLR_I, 0, "I set at the first CPU_ON");
    assert_eq!(after_set & SCTLR_I, SCTLR_I, "guest could not set I");
    assert_eq!(
        second & (SCTLR_M | SCTLR_C | SCTLR_I | SCTLR_EE),
        0,
        "M/C/I/EE not cleared at re-CPU_ON"
    );

    drop(create_vm_or_precondition());
}

/// microVM の start / stop と停止・drop 時の資源の解放（TASK-192.16・#3798・MVM-5・MVM-1・REPAIR-5）。
/// (A) 自己ループのゲストの start → stop が `Requested`、(B) その直後に同じプロセスで再 assemble → start → stop ができる
/// （資源の解放の観測。解放漏れなら 2 回目の `HvVm::create` が `FailedPrecondition`）、(C) PSCI SYSTEM_OFF のゲストが
/// `GuestShutdown` で終わり stop がその理由を返す、(D) 走行中の `RunningHvfMicroVm` の drop の後、(E) start しない
/// `HvfMicroVm` の drop の後にも再 assemble できる。期限 watchdog 30 秒つき（超過は `hvf_device: WATCHDOG EXPIRED` と終了コード 124）。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_start_stop_microvm() {
    use fandhe_container_microvm::hvf::HvfMicroVm;
    use fandhe_container_microvm::stop::StopReason;
    use std::time::Instant;

    let _wd = Watchdog::start(ASSEMBLE_DEADLINE);
    let layout = Arm64Layout::new(64 << 20, 1, 1).unwrap();
    require_vm_with_gic(&layout);

    // (A) 自己ループのゲスト: start → 走り続ける → stop が Requested。
    let vm = HvfMicroVm::assemble(assemble_config(
        layout.clone(),
        synthetic_image(true),
        1,
        false,
    ))
    .unwrap();
    let running = vm.start().unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(!running.is_finished());
    let t = Instant::now();
    let report = running.stop(Duration::from_secs(1)).unwrap();
    eprintln!(
        "hvf_device: start_stop: stop reason={:?} stats={:?} stop_elapsed={:?}",
        report.reason,
        report.stats,
        t.elapsed()
    );
    assert_eq!(report.reason, StopReason::Requested);
    assert!(report.stats.runs > 0);

    // (B) 同じプロセスで再 assemble → start → stop。
    let vm = HvfMicroVm::assemble(assemble_config(
        layout.clone(),
        synthetic_image(true),
        1,
        false,
    ))
    .unwrap();
    let running = vm.start().unwrap();
    let report = running.stop(Duration::from_secs(1)).unwrap();
    assert_eq!(report.reason, StopReason::Requested);

    // (C) SYSTEM_OFF のゲスト: x0 = 0x8400_0008（PSCI SYSTEM_OFF）→ hvc #0。
    let off = [0xD280_0100u32, 0xF2B0_8000, 0xD400_0002];
    let vm = HvfMicroVm::assemble(assemble_config(
        layout.clone(),
        synthetic_image_with_code(true, &off),
        1,
        false,
    ))
    .unwrap();
    let running = vm.start().unwrap();
    let begin = Instant::now();
    while !running.is_finished() && begin.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(running.is_finished(), "guest did not reach SYSTEM_OFF");
    let report = running.stop(Duration::from_secs(1)).unwrap();
    assert_eq!(report.reason, StopReason::GuestShutdown);

    // (D) 走行中の drop の後も作り直せる。
    let vm = HvfMicroVm::assemble(assemble_config(
        layout.clone(),
        synthetic_image(true),
        1,
        false,
    ))
    .unwrap();
    let running = vm.start().unwrap();
    std::thread::sleep(Duration::from_millis(100));
    drop(running);

    // (E) start しない drop の後も作り直せる（ゲストは走らない）。
    let vm = HvfMicroVm::assemble(assemble_config(
        layout.clone(),
        synthetic_image(true),
        1,
        false,
    ))
    .unwrap();
    drop(vm);
    let vm =
        HvfMicroVm::assemble(assemble_config(layout, synthetic_image(true), 1, false)).unwrap();
    drop(vm);
    drop(create_vm_or_precondition());
}

/// シリアル出力の確認用ゲスト付き Image。ヘッダの code0 は `b #64`（ヘッダ 64 バイトを飛び越える）、offset 64 から
/// `movz x0, #0x0900, lsl #16`（0xD2A1_2000）・`movz w1, #0x58`（0x5280_0B01。`'X'`）・`strb w1, [x0]`（0x3900_0001。THR）・
/// `b .`（0x1400_0000）。`SharedUartMmio` は 1 バイト幅しか受けないので `strb` を使う。符号は
/// `llvm-mc -triple=aarch64 -show-encoding` が使えない環境では、`MMIO_GUEST_CODE` の `movz x0, #0x0a00, lsl #16 = 0xD2A1_4000`
/// （imm16 は bit 5 から。0x0900 << 5 = 0x12000）との差分計算で照合した。
fn serial_guest_image() -> Vec<u8> {
    let mut img = synthetic_image(true);
    img[0..4].copy_from_slice(&0x1400_0010u32.to_le_bytes());
    let code = [0xD2A1_2000u32, 0x5280_0B01, 0x3900_0001, 0x1400_0000];
    for (i, w) in code.iter().enumerate() {
        img[64 + i * 4..64 + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    img
}

/// シリアル（ns16550a の MMIO）の結線（#3882・MVM-5・MVM-1）。
/// `serial = false` で `layout.serial` が `Some` の不一致が資源を作る前に `InvalidArgument` になること、シリアルありの組み立てで
/// ゲストが `0x0900_0000` の THR へ `strb` で書いた `b'X'` が `serial_console().take_output()` で `b"X"` として得られること、
/// stop の後に VM を作り直せることを確かめる。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_assemble_serial_output() {
    use fandhe_container_microvm::arm64_layout::MmioRegion;
    use fandhe_container_microvm::hvf::HvfMicroVm;

    let _wd = Watchdog::start(ASSEMBLE_DEADLINE);
    let layout = Arm64Layout::new(64 << 20, 1, 0)
        .unwrap()
        .with_default_serial()
        .unwrap();
    require_vm_with_gic(&layout);

    // 1. 負の対照: layout.serial = Some なのに serial = false は資源を作る前に拒否される（直後に VM を作れる）。
    let e = HvfMicroVm::assemble(assemble_config(
        layout.clone(),
        serial_guest_image(),
        0,
        false,
    ))
    .unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    drop(create_vm_or_precondition());

    // 2. シリアルありの組み立て。
    let vm = HvfMicroVm::assemble(assemble_config(layout, serial_guest_image(), 0, true)).unwrap();
    assert_eq!(
        vm.layout().serial,
        Some(MmioRegion::new(0x0900_0000, 0x1000))
    );
    assert_eq!(vm.devices().len(), 0);
    let console = vm.serial_console().expect("serial console is enabled");
    // start gate（#3798）: start するまでゲストは走らないため、出力は空のまま。
    assert!(console.take_output().unwrap().is_empty());
    let running = vm.start().unwrap();

    // 3. ゲストの書いた 1 バイトが取り出せる（5 秒を上限に 10 ms 刻みで集め、その後 100 ms で追加が無いことも確かめる）。
    let start = std::time::Instant::now();
    let mut out = Vec::new();
    while out.is_empty() && start.elapsed() < Duration::from_secs(5) {
        out.extend(console.take_output().unwrap());
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(100));
    out.extend(console.take_output().unwrap());
    eprintln!("hvf_device: serial: output={out:?}");
    assert_eq!(out, b"X");

    // 4. stop の後に VM を作り直せる。
    running.stop(Duration::from_secs(5)).unwrap();
    drop(create_vm_or_precondition());
}

/// 途中失敗の後の再 assemble（TASK-192.15・#3797・MVM-5・REPAIR-3）。
/// GIC の配置違反（VM を作る前）と不正 Image（VM・GIC・RAM を作った後）の失敗が資源を残さず、同じプロセスで正常な assemble が
/// 成功すること、`map_shared` の対応付けが VM を生かしておくこと（所有側の `Arc` を落としても作り直せない）を確かめる。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_assemble_retries_after_failure() {
    use fandhe_container_microvm::hvf::HvfMicroVm;

    let _wd = Watchdog::start(ASSEMBLE_DEADLINE);
    let layout = Arm64Layout::new(64 << 20, 1, 1).unwrap();
    require_vm_with_gic(&layout);

    // 1. GIC の配置違反: VM を作る前に InvalidArgument。
    let mut bad_gic = Arm64Layout::new(64 << 20, 1, 1).unwrap();
    bad_gic.gic_dist.base = GuestAddress::new(bad_gic.gic_dist.base.raw() + 1);
    let e = HvfMicroVm::assemble(assemble_config(bad_gic, synthetic_image(true), 1, false))
        .unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);

    // 2. 不正 Image（magic 違反）: VM・GIC・RAM を作った後の失敗。
    let e = HvfMicroVm::assemble(assemble_config(
        layout.clone(),
        synthetic_image(false),
        1,
        false,
    ))
    .unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);

    // 3. 解放済みなので正常な assemble が成功する（解放漏れなら 2 回目の HvVm::create が FailedPrecondition）。
    let vm =
        HvfMicroVm::assemble(assemble_config(layout, synthetic_image(true), 1, false)).unwrap();
    drop(vm);
    drop(create_vm_or_precondition());

    // 4. map_shared の対応付けは Arc<HvVm> を保持する: 所有側の Arc を落としても VM は残り、作り直せない。
    let vm = Arc::new(create_vm_or_precondition());
    let page = HostMapping::page_size().unwrap();
    let host = HostMapping::new(page).unwrap();
    let mapping = vm
        .map_shared(host, 0, 0x4000_0000, page, MemoryFlags::RWX)
        .unwrap();
    drop(vm);
    assert_eq!(
        HvVm::create().unwrap_err().code(),
        MicrovmErrorCode::FailedPrecondition
    );
    mapping.unmap().unwrap();
    drop(create_vm_or_precondition());
}

/// `hvf_device_vtimer_wakes_wfi` の場面 A のゲストプログラム（arm64。`llvm-mc -triple=aarch64 -mattr=+v8.4a
/// -filetype=obj` + `llvm-objdump -d` で符号化・確認した命令語。オフセット 0）。
///
/// 手順: GICR_WAKER → GICD_CTLR → 再配置フレームの SGI_base(RD_base + 0x10000) で PPI 27(EL1 仮想タイマー)を
/// group 1・優先度 0x80 で有効化 → CPU interface → `CNTV_CVAL_EL0 = CNTVCT_EL0 + CNTFRQ_EL0 / 100`（10 ms 後）・
/// `CNTV_CTL_EL0 = 1` → `wfi`、`ICC_IAR1_EL1` が 1023(spurious) なら `wfi` へ戻る → タイマーを止めて読んだ INTID を
/// MMIO 窓(0x0a00_0000)へ書く → EOIR → `b .`。基底アドレスはコード中に固定し、試験本体が `Arm64Layout` と一致を先に確かめる。
const VTIMER_GUEST_CODE: [u32; 44] = [
    0xD2A1_0001,
    0xD2A1_0402,
    0xD2A1_4003,
    0x9140_4045,
    0xB940_1444,
    0x121E_7884,
    0xB900_1444,
    0xB940_1444,
    0x3717_FFE4,
    0x5280_0264,
    0xB900_0024,
    0xB940_0024,
    0x37FF_FFE4,
    0x52A1_0004,
    0xB900_80A4,
    0x5280_1006,
    0x3910_6CA6,
    0xB901_00A4,
    0xD538_CCA4,
    0xB240_0084,
    0xD518_CCA4,
    0xD503_3FDF,
    0xD280_1FE4,
    0xD518_4604,
    0xD280_0024,
    0xD518_CCE4,
    0xD503_3FDF,
    0xD53B_E006,
    0xD280_0C87,
    0x9AC7_08C6,
    0xD53B_E047,
    0x8B06_00E7,
    0xD51B_E347,
    0xD280_0024,
    0xD51B_E324,
    0xD503_3FDF,
    0xD503_207F,
    0xD538_CC00,
    0xF10F_FC1F,
    0x54FF_FFA0,
    0xD51B_E33F,
    0xB900_0060,
    0xD518_CC20,
    0x1400_0000,
];

/// 場面 B のゲスト(オフセット 0x200): `CNTV_CVAL_EL0 = u64::MAX`・`CNTV_CTL_EL0 = 1`(発火しない)にして `wfi` を繰り返す。
/// ほかの命令で止まりようがないので、exit せずに走り続けていれば `wfi` で待っている。
const VTIMER_IDLE_CODE: [u32; 7] = [
    0x9280_0007,
    0xD51B_E347,
    0xD280_0024,
    0xD51B_E324,
    0xD503_3FDF,
    0xD503_207F,
    0x17FF_FFFF,
];

/// 場面 A の vCPU の exit 回数の上限（PPI が届かない場合を watchdog と別の行で識別するための歯止め）。
const VTIMER_MAX_EXITS: u32 = 4096;
/// `hvf_device_vtimer_wakes_wfi` の全体期限。
const VTIMER_DEADLINE: Duration = Duration::from_secs(20);
/// 場面 B でゲストを待たせる長さ。実行の区切り（`VCPU_RUN_SLICE`。100 ms）の 2 回分を超える。
const VTIMER_IDLE: Duration = Duration::from_millis(300);

/// WFI の待ちと vtimer の処理（TASK-192.14・#3796・MVM-5・MVM-1・REPAIR-5）。
/// GIC つきの構成では WFI も `VTIMER_ACTIVATED` も exit せず、PPI は framework が pending にする（#3803・#3994）。
/// `timer::handle_wfx` / `handle_vtimer` は exit した場合のために残し、回数は観測の行で出す。
/// (A) CNTV に 10 ms 後の期限を設定して `wfi` で待つゲストが起き、PPI の INTID を MMIO 窓へ書く
/// （ホストが 1 秒以内に観測する）。ホストが回す手動ループで、MMIO のスタブに依存しない。
/// (B) 発火しないタイマーで `wfi` を繰り返すゲストを `VcpuThread` + 本物の `TimerHandler` で走らせ、
/// 実行の区切りを 2 回以上またいで待ち続けることと、待っている最中の停止要求で 1 秒以内に `Requested` で止まることを確かめる。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_vtimer_wakes_wfi() {
    use fandhe_container_microvm::hvf::hvc::HvcHandler;
    use fandhe_container_microvm::hvf::mmio::MmioHandler;
    use fandhe_container_microvm::hvf::timer::{self, TimerHandler};
    use fandhe_container_microvm::hvf::{ExitHandlers, VcpuThread, VcpuThreadConfig};
    use fandhe_container_microvm::hvf_loop::{ExitCounts, ExitKind};
    use fandhe_container_microvm::stop::StopReason;
    use std::time::Instant;

    const BASE: u64 = 0x4000_0000;
    const WINDOW: u64 = 0x0a00_0000;
    let finished = Arc::new(AtomicBool::new(false));
    // アサーションが失敗（panic）しても watchdog を止めて join する RAII ガード。
    struct WatchdogGuard(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);
    impl Drop for WatchdogGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
            if let Some(h) = self.1.take() {
                let _ = h.join();
            }
        }
    }
    let _guard = {
        let flag = Arc::clone(&finished);
        let h = std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < VTIMER_DEADLINE {
                if flag.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            eprintln!("hvf_device: WATCHDOG EXPIRED");
            std::process::exit(124);
        });
        WatchdogGuard(Arc::clone(&finished), Some(h))
    };

    let layout = Arm64Layout::new(4 << 20, 1, 1).unwrap();
    // ゲストコードに固定した値と配置の一致。
    assert_eq!(layout.gic_dist.base.raw(), 0x0800_0000);
    assert_eq!(layout.gic_redist.base.raw(), 0x0820_0000);
    assert_eq!(layout.virtio_mmio_window(0).unwrap().base.raw(), WINDOW);
    assert_eq!(layout.ram.base.raw(), BASE);
    let vm = Arc::new(create_vm_with_gic_or_precondition(&layout));
    let ppi = vm.gic().virtual_timer_intid();
    assert_eq!(ppi, ARM64_PPI_INTID_BASE + ARM64_TIMER_VIRT_PPI);

    let page = HostMapping::page_size().unwrap();
    let mut host = HostMapping::new(page).unwrap();
    for (i, w) in VTIMER_GUEST_CODE.iter().enumerate() {
        host.write_bytes(i * 4, &w.to_le_bytes()).unwrap();
    }
    for (i, w) in VTIMER_IDLE_CODE.iter().enumerate() {
        host.write_bytes(0x200 + i * 4, &w.to_le_bytes()).unwrap();
    }
    let mapping = vm.vm().map(host, 0, BASE, page, MemoryFlags::RWX).unwrap();

    // 場面 A: ホストが回すループ。
    {
        let mut vcpu = vm.create_vcpu().unwrap();
        vcpu.set_sys_reg(HvSysReg::MPIDR_EL1, u64::from(ARM64_BOOT_CPU_MPIDR))
            .unwrap();
        vcpu.set_reg(HvReg::PC, BASE).unwrap();
        vcpu.set_reg(HvReg::CPSR, 0x3c5).unwrap();
        let mut handler = TimerHandler::new();
        let (mut wfx, mut vtimer) = (0u32, 0u32);
        let mut first_wfx_pc: Option<u64> = None;
        let mut delivered: Option<u64> = None;
        let start = Instant::now();
        for _ in 0..VTIMER_MAX_EXITS {
            let exit = match vcpu.run_once(VTIMER_DEADLINE) {
                Ok(e) => e,
                Err(e) => panic!("hvf_device: vtimer: run failed: {e}"),
            };
            match exit {
                HvVcpuExit::VtimerActivated => {
                    vtimer += 1;
                    timer::handle_vtimer(&mut vcpu, &mut handler).unwrap();
                }
                HvVcpuExit::Exception(ex) => match decode_esr(ex.syndrome) {
                    EsrClass::Wfx(kind) => {
                        wfx += 1;
                        if first_wfx_pc.is_none() {
                            let pc = vcpu.get_reg(HvReg::PC).unwrap();
                            first_wfx_pc = Some(pc);
                            eprintln!("hvf_device: vtimer: pc at wfi exit={pc:#x} kind={kind:?}");
                        }
                        timer::handle_wfx(&mut vcpu, &mut handler, kind, &ex).unwrap();
                    }
                    EsrClass::DataAbort(da)
                        if ex.physical_address == WINDOW
                            && da.direction == AccessDirection::Write =>
                    {
                        let reg = HvReg::x(da.register.get()).unwrap();
                        delivered = Some(vcpu.get_reg(reg).unwrap() & 0xffff_ffff);
                        break;
                    }
                    other => panic!(
                        "hvf_device: vtimer: unexpected guest exit {other:?} pa={:#x} syndrome={:#x}",
                        ex.physical_address, ex.syndrome
                    ),
                },
                other => panic!("hvf_device: vtimer: unexpected exit {other:?}"),
            }
        }
        let elapsed = start.elapsed();
        let stats = handler.stats();
        let Some(value) = delivered else {
            panic!(
                "hvf_device: vtimer: guest did not take the timer interrupt within {VTIMER_MAX_EXITS} exits (wfx={wfx} vtimer={vtimer} stats={stats:?})"
            );
        };
        eprintln!(
            "hvf_device: vtimer: guest read intid={value} elapsed_ms={} wfx={wfx} vtimer={vtimer} unmasks={} masked={}",
            elapsed.as_millis(),
            stats.vtimer_unmasks,
            handler.vtimer_masked()
        );
        assert_eq!(value, u64::from(ppi));
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        drop(vcpu);
    }

    // 場面 B: VcpuThread と本物のハンドラ。待っている最中の停止要求。
    let counts = Arc::new(ExitCounts::new());
    let config = VcpuThreadConfig {
        observer: Some(counts.clone()),
        ..VcpuThreadConfig::default()
    };
    let handlers = ExitHandlers {
        mmio: MmioHandler::new(),
        hvc: HvcHandler::new(),
        timer: TimerHandler::new(),
    };
    let setup = |vcpu: &mut fandhe_container_microvm::hvf::HvVcpu<'_>| {
        vcpu.set_sys_reg(HvSysReg::MPIDR_EL1, u64::from(ARM64_BOOT_CPU_MPIDR))?;
        vcpu.set_reg(HvReg::PC, BASE + 0x200)?;
        vcpu.set_reg(HvReg::CPSR, 0x3c5)
    };
    let handle = VcpuThread::spawn(Arc::clone(&vm), setup, handlers, config).unwrap();
    // WFI の exit は同期点にならない(#3803)。待ち続けたことは停止後の実行期限の回数で確かめる。
    std::thread::sleep(VTIMER_IDLE);
    eprintln!(
        "hvf_device: vtimer: idle wfx in {}ms={}",
        VTIMER_IDLE.as_millis(),
        counts.count(ExitKind::Wfx)
    );
    assert!(!handle.is_finished());
    let t = Instant::now();
    let report = handle.stop(Duration::from_secs(1)).unwrap();
    assert_eq!(report.reason, StopReason::Requested);
    let stop_elapsed = t.elapsed();
    assert!(
        report.stats.deadline_exceeded >= 2,
        "guest did not stay in wfi: {:?}",
        report.stats
    );
    // 停止要求が WFI の待ちを起こす(#3887)。所要には vCPU の破棄とスレッドの終了を含む。超えるなら #3803 で切り分けて緩める。
    eprintln!(
        "hvf_device: vtimer: stop_elapsed_us={}",
        stop_elapsed.as_micros()
    );
    assert!(stop_elapsed < Duration::from_secs(1), "{stop_elapsed:?}");
    assert!(
        stop_elapsed < fandhe_container_microvm::hvf_abi::WFI_WAIT_MAX,
        "{stop_elapsed:?}"
    );
    assert_eq!(counts.count(ExitKind::Vtimer), 0);

    mapping.unmap().unwrap();
    drop(vm);
}
/// `hvf_device_spi_wakes_wfi` の標本数と全体期限。
const SPI_WAKE_SAMPLES: usize = 12;
const SPI_WAKE_DEADLINE: Duration = Duration::from_secs(20);
/// 準備完了の後、vCPU が `wfi` で寝るまで注入を待つ幅。早すぎても遅れの標本が小さくなるだけで、失敗にはならない。
const SPI_WAKE_SETTLE: Duration = Duration::from_millis(5);

/// `wfi` で待つゲストへ SPI の注入が速やかに届くこと（#3887・#3994・MVM-5・MVM-1・REPAIR-5）。
/// `SPI_GUEST_CODE` の末尾（EOIR）の後ろへ「準備完了の書き込みへ戻る `b`」を足し、INTID 48 を繰り返し受けられるゲストにする。
/// GIC つきの構成では WFI は exit せず `hv_vcpu_run` の中で待つ（#3803）。起こせるのは注入と、`VCPU_RUN_SLICE`（100 ms）の
/// 区切りの cancel だけである。準備完了を待ってから非 vCPU スレッドで `GicSpiLine::trigger` を呼び、その時刻からゲストが
/// INTID を MMIO 窓へ書くまでの遅れを測る。注入で起きなければ遅れは区切りまでの 0〜100 ms に散るため、全標本が
/// `WFI_WAIT_MAX`（10 ms）未満で中央値がその半分未満であることを照合する（実機で不安定なら #3803 で緩める）。
/// 同じ INTID への `set_spi(true)` の繰り返しがそのつど届くことの観測も兼ねる。`VcpuThread` と本物のハンドラを使う。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_spi_wakes_wfi() {
    use fandhe_container_microvm::dispatch::{ExitDispatcher, MmioDevice};
    use fandhe_container_microvm::hvf::hvc::HvcHandler;
    use fandhe_container_microvm::hvf::mmio::MmioHandler;
    use fandhe_container_microvm::hvf::timer::TimerHandler;
    use fandhe_container_microvm::hvf::{ExitHandlers, VcpuThread, VcpuThreadConfig};
    use fandhe_container_microvm::hvf_abi::WFI_WAIT_MAX;
    use fandhe_container_microvm::hvf_loop::{ExitCounts, ExitKind};
    use fandhe_container_microvm::stop::StopReason;
    use fandhe_container_microvm::virtio_mmio::{MmioReadOutcome, MmioWriteOutcome};
    use std::sync::Mutex;
    use std::time::Instant;

    const BASE: u64 = 0x4000_0000;
    const WINDOW: u64 = 0x0a00_0000;

    /// 準備完了の回数と、INTID の書き込みの時刻と値を記録する観測器（件数の上限つき）。
    struct Recorder {
        ready: Arc<AtomicU64>,
        samples: Arc<Mutex<Vec<(Instant, u32)>>>,
    }
    impl MmioDevice for Recorder {
        fn read(&self, _offset: u64, data: &mut [u8]) -> MmioReadOutcome {
            data.fill(0);
            MmioReadOutcome::Handled
        }
        fn write(&mut self, offset: u64, data: &[u8]) -> MmioWriteOutcome {
            let now = Instant::now();
            if offset == SPI_READY_OFFSET {
                self.ready.fetch_add(1, Ordering::AcqRel);
                return MmioWriteOutcome::Handled;
            }
            let mut v = [0u8; 4];
            for (d, s) in v.iter_mut().zip(data.iter()) {
                *d = *s;
            }
            let mut g = self.samples.lock().unwrap();
            if g.len() < SPI_WAKE_SAMPLES + 4 {
                g.push((now, u32::from_le_bytes(v)));
            }
            MmioWriteOutcome::Handled
        }
    }

    let finished = Arc::new(AtomicBool::new(false));
    struct WatchdogGuard(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);
    impl Drop for WatchdogGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
            if let Some(h) = self.1.take() {
                let _ = h.join();
            }
        }
    }
    let _guard = {
        let flag = Arc::clone(&finished);
        let h = std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < SPI_WAKE_DEADLINE {
                if flag.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            eprintln!("hvf_device: WATCHDOG EXPIRED");
            std::process::exit(124);
        });
        WatchdogGuard(Arc::clone(&finished), Some(h))
    };

    let layout = Arm64Layout::new(4 << 20, 1, 1).unwrap();
    // ゲストコードに固定した値と配置の一致。
    assert_eq!(layout.gic_dist.base.raw(), 0x0800_0000);
    assert_eq!(layout.gic_redist.base.raw(), 0x0820_0000);
    assert_eq!(layout.virtio_mmio_window(0).unwrap().base.raw(), WINDOW);
    assert_eq!(layout.ram.base.raw(), BASE);
    let vm = Arc::new(create_vm_with_gic_or_precondition(&layout));
    let line = vm.spi_line(&layout, 0).unwrap();
    assert_eq!(line.intid(), 48);

    // ゲスト = SPI_GUEST_CODE + `b ready`。`b` の imm26 は (ready の命令番号 - `b` の命令番号)（命令数単位、負は 26 ビットの 2 の補数）。
    let loop_idx = SPI_GUEST_CODE
        .iter()
        .position(|w| *w == SPI_READY_STORE)
        .unwrap() as i64;
    let b_idx = SPI_GUEST_CODE.len() as i64;
    let b_word = 0x1400_0000u32 | (((loop_idx - b_idx) as u32) & 0x03ff_ffff);
    let page = HostMapping::page_size().unwrap();
    let mut host = HostMapping::new(page).unwrap();
    for (i, w) in SPI_GUEST_CODE.iter().chain([&b_word]).enumerate() {
        host.write_bytes(i * 4, &w.to_le_bytes()).unwrap();
    }
    let mapping = vm.vm().map(host, 0, BASE, page, MemoryFlags::RWX).unwrap();

    let records = Arc::new(Mutex::new(Vec::new()));
    let ready = Arc::new(AtomicU64::new(0));
    let mut dispatcher = ExitDispatcher::new();
    dispatcher
        .register_mmio(
            WINDOW,
            0x200,
            Box::new(Recorder {
                ready: Arc::clone(&ready),
                samples: Arc::clone(&records),
            }),
        )
        .unwrap();
    let handlers = ExitHandlers {
        mmio: MmioHandler::with_dispatcher(dispatcher),
        hvc: HvcHandler::new(),
        timer: TimerHandler::new(),
    };
    let counts = Arc::new(ExitCounts::new());
    let config = VcpuThreadConfig {
        observer: Some(counts.clone()),
        ..VcpuThreadConfig::default()
    };
    let setup = |vcpu: &mut fandhe_container_microvm::hvf::HvVcpu<'_>| {
        vcpu.set_sys_reg(HvSysReg::MPIDR_EL1, u64::from(ARM64_BOOT_CPU_MPIDR))?;
        vcpu.set_reg(HvReg::PC, BASE)?;
        vcpu.set_reg(HvReg::CPSR, 0x3c5)
    };
    let handle = VcpuThread::spawn(Arc::clone(&vm), setup, handlers, config).unwrap();

    // 標本 i の注入の前に、ゲストの (i + 1) 回目の準備完了を待つ（EOIR の後なので前の標本の処理は終わっている）。
    let wait_ready = |n: u64| {
        let t = Instant::now();
        while ready.load(Ordering::Acquire) < n && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_micros(200));
        }
        assert!(
            ready.load(Ordering::Acquire) >= n,
            "hvf_device: spi_wake: guest never signalled ready ({n})"
        );
    };
    let mut delays: Vec<Duration> = Vec::new();
    for i in 0..SPI_WAKE_SAMPLES {
        wait_ready(i as u64 + 1);
        std::thread::sleep(SPI_WAKE_SETTLE);
        let l2 = line.clone();
        let sent = std::thread::spawn(move || {
            let at = Instant::now();
            l2.trigger().unwrap();
            at
        })
        .join()
        .unwrap();
        let t = Instant::now();
        let got = loop {
            if let Some(&(at, v)) = records.lock().unwrap().get(i) {
                break (at, v);
            }
            assert!(
                t.elapsed() < Duration::from_secs(5),
                "hvf_device: spi_wake: guest did not take sample {i}"
            );
            std::thread::sleep(Duration::from_micros(100));
        };
        assert_eq!(got.1, 48, "spurious or wrong intid at sample {i}");
        delays.push(got.0.saturating_duration_since(sent));
    }
    let report = handle.stop(Duration::from_secs(1)).unwrap();
    assert_eq!(report.reason, StopReason::Requested);

    delays.sort();
    let p50 = delays[delays.len() / 2];
    let max = *delays.last().unwrap();
    eprintln!(
        "hvf_device: spi_wake: samples={} p50_us={} max_us={} wfx={}",
        delays.len(),
        p50.as_micros(),
        max.as_micros(),
        counts.count(ExitKind::Wfx)
    );
    assert!(max < WFI_WAIT_MAX, "max delay {max:?} >= WFI_WAIT_MAX");
    assert!(
        p50 < WFI_WAIT_MAX / 2,
        "p50 delay {p50:?} >= WFI_WAIT_MAX / 2 (spi did not wake the guest in wfi)"
    );

    mapping.unmap().unwrap();
    drop(vm);
}

/// `b .`（期限切れ用）・`hvc #0`・`b .` のゲスト。
const CANCEL_GUEST_CODE: [u32; 3] = [0x1400_0000, 0xD400_0002, 0x1400_0000];

/// 保留の `cancel` の試験の共通部。ゲストを載せた vCPU を `body` へ渡す（`body` の第 2 引数はゲストの先頭の IPA）。
fn with_cancel_guest(deadline: Duration, body: impl FnOnce(&mut HvVcpu<'_>, u64)) {
    const BASE: u64 = 0x4000_0000;
    let _watchdog = Watchdog::start(deadline);
    let layout = Arm64Layout::new(4 << 20, 1, 0).unwrap();
    let vgic = create_vm_with_gic_or_precondition(&layout);
    let page = HostMapping::page_size().unwrap();
    let mut host = HostMapping::new(page).unwrap();
    for (i, w) in CANCEL_GUEST_CODE.iter().enumerate() {
        host.write_bytes(i * 4, &w.to_le_bytes()).unwrap();
    }
    let mapping = vgic
        .vm()
        .map(host, 0, BASE, page, MemoryFlags::RWX)
        .unwrap();
    let mut vcpu = vgic.create_vcpu().unwrap();
    vcpu.set_reg(HvReg::CPSR, 0x3c5).unwrap();
    body(&mut vcpu, BASE);
    drop(vcpu);
    mapping.unmap().unwrap();
}

/// HVC の exit を 1 回受けることを確かめる（`Canceled` なら保留の `cancel` が漏れている）。
fn assert_reaches_hvc(vcpu: &mut HvVcpu<'_>, hvc_at: u64) {
    vcpu.set_reg(HvReg::PC, hvc_at).unwrap();
    let exit = vcpu.run_once(VCPU_DEADLINE).unwrap();
    let HvVcpuExit::Exception(ex) = exit else {
        panic!("hvf_device: pending_cancel: unexpected exit {exit:?}");
    };
    assert_eq!(decode_esr(ex.syndrome), EsrClass::Hvc { imm16: 0 });
    assert_eq!(vcpu.get_reg(HvReg::PC).unwrap(), hvc_at + 4);
}

/// 期限切れの run の次の通常の run が `Canceled` にならないこと（#3845・MVM-5・REPAIR-5）。
///
/// 監視スレッドの `cancel` が run の戻りの直後に届く窓は狙って作れないため、期限切れを繰り返し、
/// `run_once` が保留を捨てる経路を毎回通して、状態が壊れないことと次の run がゲストへ入ることを確かめる。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_deadline_then_normal_run() {
    const REPEATS: u32 = 20;
    with_cancel_guest(Duration::from_secs(30), |vcpu, base| {
        for _ in 0..REPEATS {
            vcpu.set_reg(HvReg::PC, base).unwrap();
            let e = vcpu.run_once(Duration::from_millis(20)).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
            assert_reaches_hvc(vcpu, base + 4);
        }
        eprintln!("hvf_device: pending_cancel: deadline then normal run x{REPEATS}");
    });
}

/// run の前の `cancel` は何回呼んでも 1 回の `Canceled` にまとまること（#3845・MVM-5）。
///
/// `run_once` が保留を捨てる処理（`cancel` を足して 1 回 run する）は、保留が数えられないことに依存する。
/// 数えられるなら 2 回目の run も `Canceled` になり、ここで落ちる。PC が動かないことも確かめる。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_device_pending_cancels_collapse() {
    const CANCELS: u32 = 3;
    with_cancel_guest(Duration::from_secs(30), |vcpu, base| {
        let hvc_at = base + 4;
        vcpu.set_reg(HvReg::PC, hvc_at).unwrap();
        let canceller = vcpu.canceller();
        for _ in 0..CANCELS {
            canceller.cancel().unwrap();
        }
        assert_eq!(vcpu.run_once(VCPU_DEADLINE).unwrap(), HvVcpuExit::Canceled);
        assert_eq!(vcpu.get_reg(HvReg::PC).unwrap(), hvc_at);
        assert_reaches_hvc(vcpu, hvc_at);
        eprintln!("hvf_device: pending_cancel: {CANCELS} cancels collapsed into one");
    });
}
