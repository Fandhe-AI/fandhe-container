//! fandhe-container-microvm: KVM 直接制御・最小 virtio デバイスモデル（Linux オプション）。
//!
//! 実装済み（TASK-74.1.1・MVM-1。Linux のみ）: `/dev/kvm` のオープン・API 版数 12 の確認・`KVM_CREATE_VM` による
//! VM fd の取得（`error` は OS 非依存、`device` は Linux 限定）、TASK-74.1.2・MVM-1: `KVM_CREATE_VCPU` による
//! vCPU fd の取得（x86_64・aarch64。aarch64 は初期化 ioctl も発行するが型検査のみで実行は未検証）。
//! TASK-74.4.1・MVM-1: `KVM_RUN` による vCPU 実行（`device::VcpuFd::run_once`。VM exit は `exit::VcpuExit`。
//! x86_64 は `device::KvmDevice::probe_guest_execution` で実機のゲストコード実行を確認できる）。
//! TASK-74.2.1・MVM-1: virtio-mmio の共通トランスポート（`virtio_mmio`。OS 非依存・unsafe なし）。
//! 未実装: virtqueue の処理（TASK-74.2.2・74.3.1）・割り込み配送（TASK-74.2.3・74.3.2）・MMIO exit の振り分け（TASK-74.4.2。#883）・ゲストメモリ（アクセス型は TASK-74.1 配下の後続 sub-issue、mmap と KVM 登録は TASK-75.1。docs/design/microvm-memory-ownership.md）・レジスタ設定（REPAIR-3）。exit のデバイスへのディスパッチ（#883）・vCPU の停止（#883 / TASK-75）も未実装。実行時は `fandhe-container-plugin-microvm`（TASK-117）が
//! 本 crate を別プロセスとして動かす。PLUG-1 区分は plugin 境界の外側（バックエンド実装ライブラリ。crate-naming.md）。
//! `unsafe` は `src/sys.rs` に限る。rust-vmm 系クレートへの依存は禁止（MVM-4・.claude/rules/dependency-policy.md）。

#[cfg(target_os = "linux")]
pub mod device;
pub mod error;
pub mod exit;
#[cfg(target_os = "linux")]
mod sys;
pub mod virtio_mmio;
