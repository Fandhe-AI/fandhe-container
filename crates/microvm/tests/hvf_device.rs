//! Hypervisor.framework 実機前提の試験（MVM-5・MVM-1・TASK-192.1・#3783）。`--ignored` 指定時だけ走る。
//! 必要環境: Apple Silicon の macOS 15 以降、`com.apple.security.hypervisor` 付きの ad-hoc 署名。root は不要。
//! 手順は AGENTS.md「実機前提テスト」の `hvf_device` の項。`hv_*` は同期呼び出しでゲストを走らせないため、
//! 期限スレッドは置かない（REPAIR-5 の対象となる待ちがない）。
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use fandhe_container_microvm::error::MicrovmErrorCode;
use fandhe_container_microvm::hvf::{HostMapping, HvVm};
use fandhe_container_microvm::hvf_abi::MemoryFlags;

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
