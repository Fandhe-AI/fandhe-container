//! KVM 側の実機前提試験が、失敗を「前提欠如」か「回帰」かに振り分ける判定の正本（MVM-1・REPAIR-4・#3992）。
//!
//! 役割: `KvmDevice::open` や aarch64 の `MicroVm::assemble` の `Err` を、コードを見ずに全部
//! `PRECONDITION FAILED (test environment, not a regression)` にすると、ioctl 番号や定数の誤りの
//! ような製品側の回帰まで環境の問題に見える（HVF 側で #3803 に起きた。#3989・#3990 で HVF だけ絞った）。
//! ここでは環境を示すエラーコードだけを前提欠如にし、それ以外は `<試験名>: open: ...` /
//! `<試験名>: assemble: ...` の別の 1 行目で落とす。未知のコードは回帰側へ落とす（fail-closed）。
//!
//! 取り込み方（`support/bzimage.rs` と同じ `#[path]` 共有。複製しない）:
//! - `crates/microvm/tests/{kvm_device,microvm,kernel_boot,kvm_precondition_support}.rs`:
//!   `#[path = "support/kvm_precondition.rs"] mod kvm_precondition;`
//! - `crates/plugin-microvm/tests/e2e.rs`:
//!   `#[path = "../../microvm/tests/support/kvm_precondition.rs"] mod kvm_precondition;`
//!
//! `fandhe_container_microvm::error` だけに依存する（`KvmDevice` は Linux 限定のため参照しない）。
//!
//! 分類の根拠（`crates/microvm/src/device.rs` の errno 写像を読んだ結果）:
//! - `open`: `NotFound`（ENOENT。`/dev/kvm` が無い）・`PermissionDenied`（EACCES・EPERM）・
//!   `Unimplemented`（対応外の OS / アーキテクチャ）が環境。`FailedPrecondition`（API 版が 12 でない・
//!   KVM デバイスでない）と `Internal` は ioctl 番号や定数の誤りがここに出るため回帰側。
//! - `assemble`（aarch64）: GICv3 が無い・`KVM_CAP_ARM_PSCI_0_2`・`KVM_CAP_DEVICE_CTRL` が無い場合は
//!   `FailedPrecondition` で、`#[ignore]` の文言が定める環境の前提のため `PermissionDenied` と
//!   `FailedPrecondition` を環境とする。
//!
//! 残余（既知の限界。コードでは分離できない）:
//! - `assemble` の回帰の一部（vGIC の EBUSY・irqfd の EAGAIN・ENOTTY の `not a KVM VM fd`）も
//!   `FailedPrecondition` で、前提欠如の行になる。message の部分一致は採らない。行の末尾に `{e}` が残る。
//! - `/dev/kvm` のノードはあるがドライバが無い場合の ENXIO・ENODEV は `Internal` で、`open:` の
//!   回帰の行に出る。`os error N` が残るので判別できる。

use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};

/// `KvmDevice::open` の失敗コードが環境（`/dev/kvm` が無い・権限が無い・対応外のホスト）を示すか。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn is_open_environment_code(code: MicrovmErrorCode) -> bool {
    matches!(
        code,
        MicrovmErrorCode::NotFound
            | MicrovmErrorCode::PermissionDenied
            | MicrovmErrorCode::Unimplemented
    )
}

/// aarch64 の `MicroVm::assemble` の失敗コードが環境（権限・GICv3 や KVM capability の欠如）を示すか。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn is_assemble_environment_code(code: MicrovmErrorCode) -> bool {
    matches!(
        code,
        MicrovmErrorCode::PermissionDenied | MicrovmErrorCode::FailedPrecondition
    )
}

fn precondition_line(test: &str, e: &MicrovmError) -> String {
    format!("{test}: PRECONDITION FAILED (test environment, not a regression): {e}")
}

/// `KvmDevice::open` の `Err` から panic の 1 行目を組み立てる。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn open_failure_line(test: &str, e: &MicrovmError) -> String {
    if is_open_environment_code(e.code()) {
        precondition_line(test, e)
    } else {
        format!("{test}: open: {e}")
    }
}

/// aarch64 の `MicroVm::assemble` の `Err` から panic の 1 行目を組み立てる。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn assemble_failure_line(test: &str, e: &MicrovmError) -> String {
    if is_assemble_environment_code(e.code()) {
        precondition_line(test, e)
    } else {
        format!("{test}: assemble: {e}")
    }
}
