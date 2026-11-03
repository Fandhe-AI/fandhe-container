//! Hypervisor.framework 実機前提の試験（MVM-5・MVM-1・TASK-192.1・#3783）。`--ignored` 指定時だけ走る。
//! 必要環境: Apple Silicon の macOS 15 以降、`com.apple.security.hypervisor` 付きの ad-hoc 署名。root は不要。
//! 手順は AGENTS.md「実機前提テスト」の `hvf_device` の項。ゲストを走らせない試験は待ちがなく、vCPU を
//! 走らせる試験は期限 watchdog を持つ（REPAIR-5）。1 プロセス 1 VM のため `--test-threads=1` で実行する。
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use fandhe_container_microvm::error::MicrovmErrorCode;
use fandhe_container_microvm::hvf::{HostMapping, HvVm};
use fandhe_container_microvm::hvf_abi::{HvReg, HvSysReg, HvVcpuExit, MemoryFlags};
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
    let vm = create_vm_or_precondition();
    let page = HostMapping::page_size().unwrap();
    let mut host = HostMapping::new(page).unwrap();
    // `b .`（自分自身への無条件分岐）: ゲストは永久に回り続け、停止は canceller だけが担う。
    host.write_bytes(0, &0x1400_0000u32.to_le_bytes()).unwrap();
    let mapping = vm
        .map(host, 0, 0x4000_0000, page, MemoryFlags::RWX)
        .unwrap();

    let mut vcpu = vm.create_vcpu().unwrap();
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

    let exit = vcpu.run();
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
