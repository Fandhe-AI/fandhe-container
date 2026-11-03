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
//! TASK-75.1・MVM-1: ゲストメモリの初期化（`microvm`。匿名 mmap の backing と `KVM_SET_USER_MEMORY_REGION` による登録。Linux のみ。
//! docs/design/microvm-memory-ownership.md）。
//! TASK-75.2・MVM-1: VM 構成体の組み立て（`microvm::MicroVm::assemble`。VM・irqchip・ゲストメモリ・virtio デバイス群の MMIO 窓と
//! GSI・vCPU 群を 1 つに束ねる。x86_64 のみ。ioeventfd の結線は後続）。
//! TASK-75.3.1・MVM-1: x86_64 のカーネル・initrd・cmdline のゲストメモリへのロード（`boot_x86`。OS 非依存・unsafe なし。
//! Linux x86 Boot Protocol の bzImage と boot_params・e820。`microvm::MicroVm::load_kernel` が入口）。
//! TASK-75.3.2・MVM-1: vCPU 0 のレジスタ初期化とカーネルのエントリからの実行開始（`boot_x86::BootCpuState`・`write_boot_tables`・
//! `device::VcpuFd::set_boot_state` / `regs`・`microvm::MicroVm::setup_boot_vcpu`。x86_64 のみ。long mode・GPA 0..4 GiB の恒等写像・
//! RSI = boot_params。`unsafe` は `sys` の `KVM_{GET,SET}_{REGS,SREGS}` のみ）。
//! TASK-75.4.1・MVM-1: `microvm::MicroVm::start` / `RunningMicroVm::stop`（vCPU 0 の実行ループ・停止要求のポーリング・
//! 停止時の fd・mmap・irqfd の後始末。ゲスト起因の終了は `microvm::StopReason` で報告。`unsafe` なし）。
//! TASK-75.4.2・#887・MVM-1・ERR-1: 起動途中の失敗でも取得済みの fd・mmap・irqfd を解放し、エラーは `error::MicrovmError`（`<CODE>: <message>`）で返す（期限切れの文字列表現は `TIMEOUT`。`unsafe` 追加なし）。
//! #3744・MVM-1・REPAIR-5: 停止の期限切れで切り離した vCPU スレッドの終了を期限つきで観測する `microvm::VcpuExitWatch`（`RunningMicroVm::exit_watch`。`unsafe` なし）。
//! TASK-75.5・#3739・MVM-1: 8250 / 16550 互換の最小 UART のレジスタモデル（`uart`。OS 非依存・`unsafe` なし。IRQ は出さない）。
//! #3740・MVM-1: UART を COM1（0x3f8〜0x3ff）の PIO へ結線（`microvm::DeviceBus`）し、THR 出力を上限つきバッファから
//! ホストが取り出す（`uart::SerialConsole`・`microvm::{MicroVm, RunningMicroVm}::serial_console`）。IRQ 4・ゲスト入力は未実装。
//! 未実装: aarch64 の vGIC・resamplefd による level の再注入・
//! ioeventfd 経由の通知ループ（現状は MMIO exit 経由。TASK-75）・TAP などの net 実 backend（TASK-75 / TASK-117）・virtio-net の ctrl vq / MQ / オフロード / MRG_RXBUF・CPUID / MSR / FPU / LAPIC の設定と AP の起動（REPAIR-3。実カーネルの起動完走に必要）。他スレッドからの即時停止（kick）も未実装。実行時は `fandhe-container-plugin-microvm`（TASK-117）が
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

pub mod boot_x86;
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
pub mod microvm;
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod sys;
pub mod uart;
pub mod virtio_block;
pub mod virtio_mmio;
pub mod virtio_net;
pub mod virtqueue;
