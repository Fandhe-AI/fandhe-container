//! `/dev/kvm` 実機前提の試験（MVM-1・TASK-74.1.1・TASK-74.1.2・TASK-74.4.1）。`--ignored` 指定時だけ走る。
//! 必要環境: Linux・`/dev/kvm` の読み書き権限（`kvm` グループ等）。root は不要。
#![cfg(target_os = "linux")]

use fandhe_container_microvm::device::KvmDevice;
use fandhe_container_microvm::error::MicrovmErrorCode;
use std::os::fd::{AsFd as _, AsRawFd as _};

#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_open_and_create_vm() {
    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    assert_eq!(dev.api_version().unwrap(), 12);
    let vm1 = dev.create_vm().unwrap();
    assert!(vm1.as_fd().as_raw_fd() >= 0);
    let vm2 = dev.create_vm().unwrap();
    assert_ne!(vm1.as_fd().as_raw_fd(), vm2.as_fd().as_raw_fd());
}

/// MVM-1・TASK-74.1.2: vCPU の作成・id の重複・範囲外 id。
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_create_vcpu() {
    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    let vm = dev.create_vm().unwrap();
    let v0 = vm.create_vcpu(0).unwrap();
    let v1 = vm.create_vcpu(1).unwrap();
    assert_eq!(v0.id(), 0);
    assert_eq!(v1.id(), 1);
    assert_ne!(v0.as_fd().as_raw_fd(), v1.as_fd().as_raw_fd());
    assert_eq!(
        vm.create_vcpu(0).unwrap_err().code(),
        MicrovmErrorCode::AlreadyExists
    );
    assert_eq!(
        vm.create_vcpu(u32::MAX).unwrap_err().code(),
        MicrovmErrorCode::InvalidArgument
    );
}
/// MVM-1・TASK-74.4.1: 実機の `KVM_RUN` でゲストコード（`mov al,0x42; out 0x10,al; hlt`）が実行され、
/// IO exit と HLT exit が型つきで返ること（x86_64）。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_run_guest_code() {
    use fandhe_container_microvm::exit::{IoDirection, VcpuExit};
    use std::sync::mpsc;
    use std::time::Duration;

    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    // REPAIR-5: 止まった vCPU スレッドが残っても、期限切れでテストごと失敗にする。
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(dev.probe_guest_execution());
    });
    let probe = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("probe_guest_execution did not finish within 30s")
        .unwrap();
    assert_eq!(
        probe.exits,
        vec![
            VcpuExit::Io {
                direction: IoDirection::Out,
                port: 0x10,
                size: 1,
                count: 1,
                data: vec![0x42],
            },
            VcpuExit::Hlt,
        ]
    );
}

/// aarch64 では自己診断が未実装であること（型検査と fail-closed の確認）。
#[cfg(not(target_arch = "x86_64"))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_run_guest_code() {
    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    assert_eq!(
        dev.probe_guest_execution().unwrap_err().code(),
        MicrovmErrorCode::Unimplemented
    );
}

/// REPAIR-5・REPAIR-4・MVM-1・TASK-74.4.1: 無限ループのゲストは期限で中断され `DeadlineExceeded` になり、
/// 統計と記録器に残る。中断後も同じ vCPU で再実行できる。診断は呼び出しスレッドが `SIGUSR2` を
/// ブロックした状態で走り、それでも中断が届く（実行中だけ解除して復元する）。x86_64 のみ。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_run_deadline_interrupts_spinning_guest() {
    use fandhe_container_microvm::device::RunOutcome;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let start = Instant::now();
        let probe = dev.probe_deadline_interrupt(Duration::from_millis(200), 2);
        let _ = tx.send((probe, start.elapsed()));
    });
    let (probe, elapsed) = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("probe_deadline_interrupt did not finish within 30s");
    let probe = probe.unwrap();
    assert!(elapsed < Duration::from_secs(5));
    assert!(probe.kick_mask_restored, "SIGUSR2 mask must be restored");
    assert_eq!(
        (
            probe.stats.runs,
            probe.stats.deadline_exceeded,
            probe.stats.exits
        ),
        (2, 2, 0)
    );
    assert!(probe.stats.total_elapsed >= Duration::from_millis(400));
    assert_eq!(probe.records.len(), 2);
    assert_eq!(probe.records[0].outcome, RunOutcome::DeadlineExceeded);
    assert_eq!(probe.records[0].vcpu_id, 0);
}

/// aarch64 では未実装であること。
#[cfg(not(target_arch = "x86_64"))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_run_deadline_interrupts_spinning_guest() {
    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    assert_eq!(
        dev.probe_deadline_interrupt(std::time::Duration::from_millis(200), 2)
            .unwrap_err()
            .code(),
        MicrovmErrorCode::Unimplemented
    );
}
