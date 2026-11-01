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
