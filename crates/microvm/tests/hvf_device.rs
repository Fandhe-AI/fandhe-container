//! Hypervisor.framework 実機前提の試験（MVM-5・MVM-1・TASK-192.1・#3783・TASK-192.3・#3789・TASK-192.12・#3792・TASK-192.13・#3795・TASK-192.10・#3793・TASK-192.11・#3794・TASK-192.15・#3797）。`--ignored` 指定時だけ走る。
//! 必要環境: Apple Silicon の macOS 15 以降、`com.apple.security.hypervisor` 付きの ad-hoc 署名。root は不要。
//! 手順は AGENTS.md「実機前提テスト」の `hvf_device` の項。ゲストを走らせない試験は待ちがなく、vCPU を
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
use fandhe_container_microvm::hvf::{GicApi, HostMapping, HvVm, HvfGic, HvfGuestRam, VmWithGic};
use fandhe_container_microvm::hvf_abi::{
    HVF_DEFAULT_IPA_LIMIT, HvGicIntid, HvReg, HvSysReg, HvVcpuExit, MemoryFlags,
};
use fandhe_container_microvm::interrupt::InterruptLine;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// VM を作る。権限不足・hypervisor 不可は環境の問題として、決まった 1 行目で失敗させる。
fn create_vm_or_precondition() -> HvVm {
    match HvVm::create() {
        Ok(vm) => vm,
        Err(e) => {
            panic!("hvf_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    }
}

/// GIC つきの VM を作る。前提欠如（権限不足など）は決まった 1 行目で失敗させる。
/// macOS 14 の `Unimplemented` は前提欠如ではなく、そのままの失敗として出す。
fn create_vm_with_gic_or_precondition(layout: &Arm64Layout) -> VmWithGic {
    match VmWithGic::create(layout) {
        Ok(vm) => vm,
        Err(e) if e.code() == MicrovmErrorCode::Unimplemented => panic!("hvf_device: gic: {e}"),
        Err(e) => {
            panic!("hvf_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
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

    // 別スレッドから停止する。run の前の cancel が次の run を即戻すかは未確認のため、
    // run 中に届く再送で競合に依存しない形にする。
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
/// 優先度 0x80・affinity 0 にして有効化 → CPU interface(SRE・PMR・IGRPEN1) → `wfi` → `ICC_IAR1_EL1` を読み、
/// 1023(spurious) なら `wfi` へ戻る → 読んだ INTID を virtio-mmio の窓(0x0a00_0000。未 map)へ書く → EOIR → `b .`。
/// 基底アドレス(GICD 0x0800_0000・GICR 0x0820_0000・窓 0x0a00_0000)と INTID 48 はコード中に固定してあり、
/// 試験本体が `Arm64Layout` の値と一致することを先に assert する。PSTATE.I はマスクのまま(CPSR 0x3c5)。
const SPI_GUEST_CODE: [u32; 36] = [
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
    0xD503_207F, // wfi                              ; loop:
    0xD538_CC00, // mrs  x0, ICC_IAR1_EL1
    0xF10F_FC1F, // cmp  x0, #1023
    0x54FF_FFA0, // b.eq loop                        ; spurious なら待ち直す
    0xB900_0060, // str  w0, [x3]                    ; MMIO exit: 読んだ INTID を書く
    0xD518_CC20, // msr  ICC_EOIR1_EL1, x0
];

/// 末尾の `b .`（`SPI_GUEST_CODE` の後ろへ置く）。
const SPI_GUEST_HALT: u32 = 0x1400_0000;

/// 全体期限（`hvf_device_spi_reaches_guest`）。
const SPI_DEADLINE: Duration = Duration::from_secs(20);
/// vCPU の exit 回数の上限（無限ループの歯止め）。
const SPI_MAX_EXITS: u32 = 256;

/// ホストの `GicSpiLine::trigger`（edge の SPI）が、ゲストの `ICC_IAR1_EL1` で設定した INTID として読めることを確かめる。
/// あわせて `hv_gic_set_spi` を vCPU 以外のスレッドから呼べるかを観測する（結果の記録は人間担当の #3803）。
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

    // 実行が戻らないハングの歯止め（REPAIR-5）。
    let done = Arc::new(AtomicBool::new(false));
    let watchdog_done = Arc::clone(&done);
    let watchdog = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        while start.elapsed() < SPI_DEADLINE {
            if watchdog_done.load(Ordering::Acquire) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        eprintln!("hvf_device: WATCHDOG EXPIRED");
        std::process::exit(124);
    });

    let mut delivered: Option<u64> = None;
    let mut off_thread: Option<Result<(), String>> = None;
    for _ in 0..SPI_MAX_EXITS {
        let exit = match vcpu.run_once(SPI_DEADLINE) {
            Ok(e) => e,
            Err(e) => panic!("hvf_device: spi: run failed: {e}"),
        };
        let HvVcpuExit::Exception(ex) = exit else {
            panic!("hvf_device: spi: unexpected exit {exit:?}");
        };
        match decode_esr(ex.syndrome) {
            EsrClass::Wfx(WfxKind::Wfi) => {
                if off_thread.is_none() {
                    // vCPU スレッド以外からの注入(スレッドの制約の観測)。
                    let l2 = line.clone();
                    let r = std::thread::spawn(move || l2.trigger()).join().unwrap();
                    eprintln!("hvf_device: spi: set_spi from non-vcpu thread: {r:?}");
                    let failed = r.is_err();
                    off_thread = Some(r.map_err(|e| e.to_string()));
                    if failed {
                        // 到達の確認は vCPU スレッドからの注入で続ける。
                        line.trigger().unwrap();
                    }
                }
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
    done.store(true, Ordering::Release);
    watchdog.join().unwrap();

    let Some(value) = delivered else {
        panic!("hvf_device: spi: did not reach the guest within {SPI_MAX_EXITS} exits");
    };
    eprintln!("hvf_device: spi: guest read intid={value}");
    assert_ne!(value, 1023, "spurious intid: spi did not reach the guest");
    assert_eq!(value, 48);
    assert_eq!(value, u64::from(line.intid()));
    if let Some(Err(e)) = off_thread {
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

/// 合成の arm64 Image。先頭の命令は `b .`（自分自身への分岐）で、ゲストはその場で走り続ける。
/// ヘッダ（64 バイト）: offset 0 = code0、8 = text_offset、16 = image_size、24 = flags、56 = magic（`ARM\x64`）。
fn synthetic_image(magic_ok: bool) -> Vec<u8> {
    use fandhe_container_microvm::boot_arm64::ARM64_IMAGE_MAGIC;
    let mut img = vec![0u8; 4096];
    img[0..4].copy_from_slice(&0x1400_0000u32.to_le_bytes());
    img[8..16].copy_from_slice(&0x8_0000u64.to_le_bytes());
    img[16..24].copy_from_slice(&4096u64.to_le_bytes());
    // flags = 0（リトルエンディアン・ページサイズ未指定）のまま。
    let magic = if magic_ok { ARM64_IMAGE_MAGIC } else { 0 };
    img[56..60].copy_from_slice(&magic.to_le_bytes());
    img
}

fn assemble_config(
    layout: Arm64Layout,
    kernel: Vec<u8>,
    block: usize,
) -> fandhe_container_microvm::hvf::HvfMicroVmConfig<
    fandhe_container_microvm::virtio_block::MemoryBlockBackend,
    fandhe_container_microvm::virtio_net::MemoryNetBackend,
> {
    use fandhe_container_microvm::hvf::{HvfMicroVmConfig, VcpuThreadConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    HvfMicroVmConfig {
        layout,
        kernel,
        initrd: None,
        cmdline: "console=ttyAMA0".to_string(),
        block: (0..block)
            .map(|_| MemoryBlockBackend::new(512 * 1024, false).unwrap())
            .collect(),
        net: Vec::new(),
        vcpu: VcpuThreadConfig::default(),
    }
}

/// 環境の前提（権限・macOS 15 以降）を、組み立てとは別に先に確かめる。
fn require_vm_with_gic(layout: &Arm64Layout) {
    drop(create_vm_with_gic_or_precondition(layout));
}

/// microVM 構成体の組み立て（TASK-192.15・#3797・MVM-5・MVM-1）。
/// vcpus = 2 が `Unimplemented`（資源を作る前）、正しい構成の組み立てで vCPU 0 の X0・PC・CPSR・MPIDR_EL1 の読み戻しが期待値と
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

    // 1. vcpus = 2 は資源を作る前に Unimplemented。直後に VM を作れる = 何も作っていない。
    let mut two = Arm64Layout::new(64 << 20, 1, 1).unwrap();
    two.vcpus = 2;
    let e = HvfMicroVm::assemble(assemble_config(two, synthetic_image(true), 1)).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::Unimplemented);
    drop(create_vm_or_precondition());

    // 2. 正しい構成。
    let vm = HvfMicroVm::assemble(assemble_config(layout, synthetic_image(true), 1)).unwrap();

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

    // 6. `b .` のゲストは走り続ける。
    std::thread::sleep(Duration::from_millis(200));
    assert!(!vm.is_vcpu_finished());

    // 7. drop（vCPU の停止 -> RAM の unmap -> VM の破棄）の後に VM を作り直せる。
    drop(vm);
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
    let e = HvfMicroVm::assemble(assemble_config(bad_gic, synthetic_image(true), 1)).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);

    // 2. 不正 Image（magic 違反）: VM・GIC・RAM を作った後の失敗。
    let e = HvfMicroVm::assemble(assemble_config(layout.clone(), synthetic_image(false), 1))
        .unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);

    // 3. 解放済みなので正常な assemble が成功する（解放漏れなら 2 回目の HvVm::create が FailedPrecondition）。
    let vm = HvfMicroVm::assemble(assemble_config(layout, synthetic_image(true), 1)).unwrap();
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
