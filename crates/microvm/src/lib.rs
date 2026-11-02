//! fandhe-container-microvm: KVM 直接制御・最小 virtio デバイスモデル（Linux オプション）。
//!
//! 実装済み（TASK-74.1.1・MVM-1。Linux のみ）: `/dev/kvm` のオープン・API 版数 12 の確認・`KVM_CREATE_VM` による
//! VM fd の取得（`error` は OS 非依存、`device` は Linux 限定）、TASK-74.1.2・MVM-1: `KVM_CREATE_VCPU` による
//! vCPU fd の取得（x86_64・aarch64。aarch64 は初期化 ioctl も発行するが型検査のみで実行は未検証）。
//! TASK-74.4.1・MVM-1: `KVM_RUN` による vCPU 実行（`device::VcpuFd::run_once`。VM exit は `exit::VcpuExit`。
//! x86_64 は `device::KvmDevice::probe_guest_execution` で実機のゲストコード実行を確認できる）。
//! TASK-74.4.2・MVM-1: VM exit（MMIO / PIO）のデバイスモデルへの振り分けと IN・MMIO read の応答の書き戻し
//! （`dispatch`。OS 非依存・unsafe なし。`device::VcpuFd::handle_exit`・実機確認は `device::KvmDevice::probe_exit_dispatch`）。
//! TASK-74.2.1・MVM-1: virtio-mmio の共通トランスポート（`virtio_mmio`。OS 非依存・unsafe なし）。
//! TASK-74.2.2・MVM-1: ゲストメモリのアクセス型（`guest_memory`。単一領域・heap backing）・split virtqueue（`virtqueue`）・
//! virtio-block（`virtio_block`。read/write/flush。いずれも OS 非依存・unsafe なし）。
//! TASK-74.2.3・MVM-1・MVM-4: virtio-block の割り込み通知（`interrupt`。OS 非依存。`InterruptLine`・`IoEventSpec`・
//! `complete_block_notify`）と、KVM の ioeventfd（ゲストの `QueueNotify` を VM exit なしで受ける）・irqfd（eventfd への書き込みを
//! GSI の割り込みに変える）・in-kernel irqchip（`irq`・`device::VmFd::{create_irqchip, register_irqfd, register_ioeventfd}`。Linux のみ。
//! x86_64 は `device::KvmDevice::probe_queue_interrupt` で実機確認できる）。
//! TASK-74.3.1・MVM-1: virtio-net の receiveq / transmitq の処理とパケット送受信（`virtio_net`。OS 非依存・unsafe なし）。
//! TASK-74.3.2・MVM-1: virtio-net の割り込み通知（`interrupt::complete_net_notify`。キュー番号で rx / tx を振り分ける）。
//! 未実装: aarch64 の vGIC・resamplefd による level の再注入・
//! eventfd を待つ常駐のイベントループ（TASK-75）・TAP などの net 実 backend（TASK-75 / TASK-117）・virtio-net の ctrl vq / MQ / オフロード / MRG_RXBUF・ゲストメモリの mmap backing と KVM 登録（TASK-75.1。docs/design/microvm-memory-ownership.md）・レジスタ設定（REPAIR-3）。vCPU の外部からの停止（TASK-75）・PIO の具体デバイスも未実装。実行時は `fandhe-container-plugin-microvm`（TASK-117）が
//! 本 crate を別プロセスとして動かす。PLUG-1 区分は plugin 境界の外側（バックエンド実装ライブラリ。crate-naming.md）。
//!
//! # 組み込む側への注意（REPAIR-5・MVM-4）
//! - 対応は glibc（`target_env = "gnu"`）の LP64 の x86_64・aarch64 だけ。musl などは `ioctl` の `request` の型が
//!   異なるため `Unsupported` で fail-closed する。
//! - `device::VcpuFd::run_once` は初回に `SIGUSR2` へ何もしない handler を入れ、プロセス全体の設定として元へ戻さない
//!   （`KVM_RUN` の期限切れで vCPU スレッドを中断するため）。組み込むプロセスは `SIGUSR2` を他の用途に使わないこと。
//!   既に別の handler や SIG_IGN があるときは上書きせず `FailedPrecondition`（EBUSY）で失敗する。
//!
//! `unsafe` は `src/sys.rs` に限り、crate 全体の `#![deny(unsafe_code)]` と `sys` だけへの `allow` で
//! 機械的に担保する（REPAIR-9・TASK-74.5）。rust-vmm 系クレートへの依存は禁止（MVM-4・.claude/rules/dependency-policy.md）。

#![deny(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod device;
pub mod dispatch;
pub mod error;
pub mod exit;
pub mod guest_memory;
pub mod interrupt;
#[cfg(target_os = "linux")]
pub mod irq;
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod sys;
pub mod virtio_block;
pub mod virtio_mmio;
pub mod virtio_net;
pub mod virtqueue;
