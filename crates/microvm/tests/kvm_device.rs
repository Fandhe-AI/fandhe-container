//! `/dev/kvm` 実機前提の試験（MVM-1・TASK-74.1.1）。`--ignored` 指定時だけ走る。
//! 必要環境: Linux・`/dev/kvm` の読み書き権限（`kvm` グループ等）。root は不要。
#![cfg(target_os = "linux")]

use fandhe_container_microvm::device::KvmDevice;
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
