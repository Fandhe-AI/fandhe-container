//! Hypervisor.framework 実機前提の試験（MVM-5・MVM-1・TASK-192.1・#3783・TASK-192.3・#3789・TASK-192.12・#3792）。`--ignored` 指定時だけ走る。
//! 必要環境: Apple Silicon の macOS 15 以降、`com.apple.security.hypervisor` 付きの ad-hoc 署名。root は不要。
//! 手順は AGENTS.md「実機前提テスト」の `hvf_device` の項。ゲストを走らせない試験は待ちがなく、vCPU を
//! 走らせる試験は期限 watchdog を持つ（REPAIR-5）。1 プロセス 1 VM のため `--test-threads=1` で実行する。
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use fandhe_container_microvm::arm64_layout::{
    ARM64_BOOT_CPU_MPIDR, ARM64_PPI_INTID_BASE, ARM64_TIMER_VIRT_PPI, Arm64Layout,
    check_virtual_timer_intid,
};
use fandhe_container_microvm::error::MicrovmErrorCode;
use fandhe_container_microvm::guest_memory::{GuestAddress, GuestMemoryBacking};
use fandhe_container_microvm::hvf::{GicApi, HostMapping, HvVm, HvfGic, HvfGuestRam, VmWithGic};
use fandhe_container_microvm::hvf_abi::{
    HVF_DEFAULT_IPA_LIMIT, HvGicIntid, HvReg, HvSysReg, HvVcpuExit, MemoryFlags,
};
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
/// (B) `hvc #0` のゲストは HVC のスタブが `Unimplemented` を返し、`Failed(Unimplemented)` で終わって分類が HVC だったと観測される。
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
    {
        let finished = Arc::clone(&finished);
        std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < VCPU_THREAD_DEADLINE {
                if finished.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            eprintln!("hvf_device: WATCHDOG EXPIRED");
            std::process::exit(124);
        });
    }

    let vm = Arc::new(create_vm_or_precondition());
    let page = HostMapping::page_size().unwrap();
    let mut host = HostMapping::new(page).unwrap();
    // オフセット 0: `b .`。オフセット 0x100: `hvc #0` の後に `b .`。
    host.write_bytes(0, &0x1400_0000u32.to_le_bytes()).unwrap();
    host.write_bytes(0x100, &0xD400_0002u32.to_le_bytes())
        .unwrap();
    host.write_bytes(0x104, &0x1400_0000u32.to_le_bytes())
        .unwrap();
    let mapping = vm.map(host, 0, BASE, page, MemoryFlags::RWX).unwrap();

    let handlers = || ExitHandlers {
        mmio: MmioHandler::new(),
        hvc: HvcHandler::new(),
        timer: TimerHandler::new(),
    };
    let setup = |pc: u64| {
        move |vcpu: &mut fandhe_container_microvm::hvf::HvVcpu<'_>| {
            vcpu.set_reg(HvReg::PC, pc)?;
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
    let handle = VcpuThread::spawn(Arc::clone(&vm), setup(BASE), handlers(), config).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(!handle.is_finished());
    let t = Instant::now();
    let report = handle.stop(Duration::from_secs(1)).unwrap();
    assert_eq!(report.reason, StopReason::Requested);
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert_eq!(counts.count(ExitKind::Hvc), 0);

    // 場面 B: HVC のスタブで Failed(Unimplemented)。
    let counts = Arc::new(ExitCounts::new());
    let config = VcpuThreadConfig {
        observer: Some(counts.clone()),
        ..VcpuThreadConfig::default()
    };
    let handle =
        VcpuThread::spawn(Arc::clone(&vm), setup(BASE + 0x100), handlers(), config).unwrap();
    let start = Instant::now();
    while !handle.is_finished() && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(handle.is_finished());
    let report = handle.stop(Duration::from_secs(1)).unwrap();
    assert_eq!(
        report.reason,
        StopReason::Failed(MicrovmErrorCode::Unimplemented)
    );
    assert_eq!(counts.count(ExitKind::Hvc), 1);

    // スレッドが持っていた Arc は stop の Ok で解放済み。
    mapping.unmap().unwrap();
    finished.store(true, Ordering::Release);
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
