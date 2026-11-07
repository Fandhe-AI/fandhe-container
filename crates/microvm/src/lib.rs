//! fandhe-container-microvm: KVM・Hypervisor.framework の直接制御と最小 virtio デバイスモデル（microVM オプション）。
//!
//! 3 OS 展開方針（MVM-5）: 実装済みのバックエンドは Linux の KVM と macOS の Hypervisor.framework（TASK-192。aarch64。実機確認は合成ゲストまで。
//! 下の「macOS バックエンド」節）。Windows（WHP）は将来オプションで MVP には実装しない。Windows の扱いと、バックエンドの配置（本 crate の中に `cfg(target_os = ...)` で置く。
//! 2026-11-03 決定）は、`docs/architecture.md` の「microVM の 3 OS 展開方針（MVM-5）」節を正とする。
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
//! #3698: `register_ioeventfd` が返す `irq::IoEventFd` は VM fd の dup を所有し、`microvm::MicroVm::assemble` が各 virtio デバイスのキューへ結び、
//! `start` が eventfd を期限つきの `poll(2)` で待つ通知スレッドを起動する。
//! TASK-74.3.1・MVM-1: virtio-net の receiveq / transmitq の処理とパケット送受信（`virtio_net`。OS 非依存・unsafe なし）。
//! TASK-74.3.2・MVM-1: virtio-net の割り込み通知（`interrupt::complete_net_notify`。キュー番号で rx / tx を振り分ける）。
//! TASK-75.1・MVM-1: ゲストメモリの初期化（`microvm`。匿名 mmap の backing と `KVM_SET_USER_MEMORY_REGION` による登録。Linux のみ。
//! docs/design/microvm-memory-ownership.md）。
//! TASK-75.2・MVM-1: VM 構成体の組み立て（`microvm::MicroVm::assemble`。VM・irqchip・ゲストメモリ・virtio デバイス群の MMIO 窓と
//! GSI・vCPU 群を 1 つに束ねる。ここは x86_64 の分岐で、aarch64 は #3696 の段落。ioeventfd の結線は後続）。
//! TASK-75.3.1・MVM-1: x86_64 のカーネル・initrd・cmdline のゲストメモリへのロード（`boot_x86`。OS 非依存・unsafe なし。
//! Linux x86 Boot Protocol の bzImage と boot_params・e820。`microvm::MicroVm::load_kernel` が入口）。
//! TASK-75.3.2・MVM-1: vCPU 0 のレジスタ初期化とカーネルのエントリからの実行開始（`boot_x86::BootCpuState`・`write_boot_tables`・
//! `device::VcpuFd::set_boot_state` / `regs`・`microvm::MicroVm::setup_boot_vcpu`。ここは x86_64 の分岐で、aarch64 は #3696 の段落。long mode・GPA 0..4 GiB の恒等写像・
//! RSI = boot_params。`unsafe` は `sys` の `KVM_{GET,SET}_{REGS,SREGS}` のみ）。
//! TASK-75.4.1・MVM-1: `microvm::MicroVm::start` / `RunningMicroVm::stop`（vCPU 0 の実行ループ・停止要求のポーリング・
//! 停止時の fd・mmap・irqfd の後始末。ゲスト起因の終了は `microvm::StopReason` で報告。`unsafe` なし）。
//! TASK-75.4.2・#887・MVM-1・ERR-1: 起動途中の失敗でも取得済みの fd・mmap・irqfd を解放し、エラーは `error::MicrovmError`（`<CODE>: <message>`）で返す（期限切れの文字列表現は `TIMEOUT`。`unsafe` 追加なし）。
//! #3744・MVM-1・REPAIR-5: 停止の期限切れで切り離した vCPU スレッドの終了を期限つきで観測する `microvm::VcpuExitWatch`（`RunningMicroVm::exit_watch`。`unsafe` なし）。
//! TASK-75.5・#3739・MVM-1: 8250 / 16550 互換の最小 UART のレジスタモデル（`uart`。OS 非依存・`unsafe` なし。IRQ は出さない）。
//! #3734・MVM-1: 起動用の MSR・FPU の設定（`boot_x86::boot_msrs`・`X86FpuState`・`device::VcpuFd::{set_msrs, msrs, set_fpu, fpu}`。`unsafe` 追加なし）。
//! #3740・MVM-1: UART を COM1（0x3f8〜0x3ff）の PIO へ結線（`microvm::DeviceBus`）し、THR 出力を上限つきバッファから
//! ホストが取り出す（`uart::SerialConsole`・`microvm::{MicroVm, RunningMicroVm}::serial_console`）。ゲスト入力は受信 FIFO あり（#3893）、x86 の IRQ 4 は未実装。
//! #3735・MVM-1: BSP の LAPIC の LVT LINT0 = ExtINT・LINT1 = NMI（`lapic_x86`・`device::VcpuFd::{set_boot_lints, lapic_lints}`。`unsafe` 追加なし）。
//! #4025・MVM-1・MVM-5・REPAIR-5: ゲスト RAM を複数スレッドで共有するスロット（`guest_memory_slot`。Linux と macOS aarch64。`unsafe` なし。macOS のゲスト RAM の所有は #4027 で `hvf::microvm` が使う。clone の結線は #4028 で済み）。
//! #4026・MVM-1・MVM-5: virtio-block の QueueNotify を処理する route（`interrupt::QueueNotifyRoute`・`BlockQueueNotifyRoute`。Linux と macOS aarch64。`unsafe` なし。macOS の結線は #4028 で済み）。
//! #4029・MVM-1・MVM-5: virtio-net の QueueNotify を処理する route（`interrupt::NetQueueNotifyRoute`。Linux と macOS aarch64。`unsafe` なし。macOS の結線済み。ホスト側の到着による受信は #4030）。
//! TASK-192.5・#3784・MVM-5・MVM-1: arm64 ゲスト向け FDT（DTB v17）の組み立て器（`fdt`。OS 非依存・`unsafe` なし）。
//! TASK-192.7・#3790・MVM-5・MVM-1: arm64 の Image・initrd・FDT の配置と起動レジスタの値（`boot_arm64`。OS 非依存・`unsafe` なし）。
//! TASK-192.10・#3793・MVM-5・MVM-1: macOS の MMIO の data abort を `VcpuExit::Mmio` へ写す純関数群（`mmio_abort`。OS 非依存・`unsafe` なし）。
//! TASK-192.8・#3785・MVM-5: arm64 の ESR（例外 syndrome）の復号（`esr`。OS 非依存・`unsafe` なし）。
//! TASK-192.1・#3783・MVM-5: macOS（Apple Silicon）の Hypervisor.framework の VM・ゲストメモリ（`hvf`・`hvf_abi`。
//! `hvf_abi` は OS 非依存の純関数。macOS かつ aarch64 のみ `hvf::{HvVm, HostMapping, GuestMapping}`）。
//! TASK-192.2・#3786・MVM-5: vCPU・レジスタ・exit・vtimer（`hvf_abi` の `HvReg`・`HvSysReg`・`HvVcpuExit`・`decode_exit`。
//! macOS かつ aarch64 のみ `hvf::{HvVcpu, VcpuCanceller}`）。
//! TASK-192.9・#3791・MVM-5・MVM-1・REPAIR-5: macOS の vCPU 専用スレッドと実行ループ・exit の分類・期限つきの停止（`hvf_loop` は OS 非依存の
//! コアで、偽の実行体の単体テストが全 OS で走る。macOS かつ aarch64 のみ `hvf::{VcpuThread, VcpuHandle}`。exit ごとの処理
//! `hvf::hvc` は #3794 で PSCI を実装済み（`psci`。OS 非依存）。`hvf::mmio` は #3793 で実装済み。WFI の exit と vtimer の exit は GIC つきでは来ないため処理を持たず、`hvf_loop` が `Failed(Unimplemented)` で止める（#4039。WFE 系は PC を進めて続行）。残る制限は各ファイルの「未実装」節）。`StopReason` は `stop` へ移した（`microvm::StopReason` として再公開。`unsafe` なし）。
//! #3737・MVM-1: AP（vCPU 1 以上）を `KVM_MP_STATE_UNINITIALIZED` で作り、BSP からの INIT/SIPI で起動する（`smp_x86`・
//! `device::VcpuFd::{mp_state, set_mp_state}`・`microvm::MicroVm::write_ap_startup_code`。`unsafe` は `sys` の `KVM_{GET,SET}_MP_STATE` のみ）。
//! #3888・MVM-1: x86_64 の MP テーブルの生成（`mptable_x86`。OS 非依存・`unsafe` なし。`microvm::MicroVm::load_kernel` が `[639 KiB, 640 KiB)` へ書き e820 で予約し、AP を Linux にオンラインにする）。
//! #3696・MVM-1: **aarch64 の KVM も MVM-1 の対象**（spec の MVM-1 は Linux〔KVM〕でアーキテクチャを除外しない。実機の調達先の node4・DGX Spark も aarch64。TASK-151）。
//! vGICv3（`KVM_CREATE_DEVICE`。`device::VgicV3`）・irqfd の GSI = SPI 番号の写像・`MicroVm::assemble` の aarch64 分岐（vCPU 1..N。AP は `KVM_ARM_VCPU_POWER_OFF` で作り PSCI CPU_ON で起こす〔#3899。実機未確認〕。FDT の配置は
//! `load_kernel`、起動レジスタは `setup_boot_vcpu`〔`KVM_SET_ONE_REG`〕）・start / stop を実装済み（`unsafe` は `sys` の `KVM_CREATE_DEVICE`・
//! `KVM_{SET,GET}_DEVICE_ATTR`・`KVM_{SET,GET}_ONE_REG` のみ。実機〔KVM aarch64〕での実行は未検証で、実機前提試験は `kvm_device_arm64_*`）。
//! aarch64 は PSCI 0.2（`KVM_ARM_VCPU_PSCI_0_2`）を有効にし、`KVM_EXIT_SYSTEM_EVENT` の SHUTDOWN / RESET を `GuestShutdown` に分類済み（#3896）。シリアルは MMIO（#3898）で、割り込みは SPI 1 の `KVM_IRQ_LINE`（#3943。実機確認は #3781）で結線済み。
//! level の virtio SPI は `Unimplemented` で拒否する（REPAIR-3）。
//! 未実装: resamplefd による level の再注入・
//! ioeventfd 経由の通知ループ（現状は MMIO exit 経由。TASK-75）・TAP などの net 実 backend（TASK-75 / TASK-117）・virtio-net の ctrl vq / MQ / オフロード / MRG_RXBUF・AP のスレッド駆動・他スレッドからの即時停止（kick）は #3738・#3736 で実装済み。virtio-net の受信は期限ごとのポーラー（#3742）で処理し、`start` は virtio-net を含む構成でも起動する（#3743。backend の到着通知は将来仕様。REPAIR-3）。実行時は `fandhe-container-plugin-microvm`（TASK-117）が
//! 本 crate を別プロセスとして動かす。PLUG-1 区分は plugin 境界の外側（バックエンド実装ライブラリ。crate-naming.md）。
//!
//! # 組み込む側への注意（REPAIR-5・MVM-4）
//! - 対応は glibc（`target_env = "gnu"`）の LP64 の x86_64・aarch64 だけ。musl などは `ioctl` の `request` の型が
//!   異なるため `Unsupported` で fail-closed する。
//! - `device::VcpuFd::run_once` は初回に `SIGUSR2` へ何もしない handler を入れ、プロセス全体の設定として元へ戻さない
//!   （`KVM_RUN` の期限切れで vCPU スレッドを中断するため）。組み込むプロセスは `SIGUSR2` を他の用途に使わないこと。
//!   既に別の handler や SIG_IGN があるときは上書きせず `FailedPrecondition`（EBUSY）で失敗する。
//!
//! `unsafe` は `src/sys.rs`（Linux）・`src/sys/hvf.rs`（macOS）に限り、crate 全体の `#![deny(unsafe_code)]` と `sys` だけへの `allow` で
//! 機械的に担保する（REPAIR-9・TASK-74.5）。rust-vmm 系クレートへの依存は禁止（MVM-4・.claude/rules/dependency-policy.md）。
//! TASK-192.12・#3792・MVM-5・MVM-1: GICv3 の作成順序の型による強制と配置・timer の照合（macOS の `hvf::gic`・OS 非依存の `arm64_layout::check_gic_geometry`）。
//! TASK-192.15・#3797・MVM-5・MVM-1: macOS の microVM 構成体（`hvf::microvm::HvfMicroVm`。OS 非依存の `hvf_abi::check_assemble_input`・`boot_arm64::check_boot_readback`、`HvfGuestRam::register_shared`）。unsafe は増やさない（sys/hvf.rs は借用か `Arc<HvVm>` を保持する対応付けの追加のみ）。
//! TASK-192.16・#3798・MVM-5・MVM-1・REPAIR-5: macOS の microVM の start / stop と停止・drop 時の資源の解放順序（OS 非依存コアは `hvf_lifecycle`。`hvf_loop` の start gate。macOS かつ aarch64 のみ `hvf::{RunningHvfMicroVm, HvfStopReport}`。unsafe は増やさない）。
//! TASK-192.4・#3787・MVM-5・MVM-1: macOS のゲスト RAM（`hvf::memory`。匿名 mmap と `hv_vm_map` による対応付け。unsafe は sys/hvf.rs のみ）。
//!
//! # macOS バックエンド（TASK-192・MVM-5）
//! 対象は `cfg(all(target_os = "macos", target_arch = "aarch64"))`（macOS 15 以降・Apple Silicon。GICv3 の API の版による）。
//! `hvf` は macOS かつ aarch64 のときだけ存在するため、ここでは rustdoc のリンクにしない。実機（macOS 27.2・Apple M4 Max）で合成ゲストの試験が通った（記録は #3803）。
//! 実 Linux ゲストは未確認（#3988）。FFI は `sys/hvf.rs` の自前宣言で、新しい依存は足していない（MVM-4）。
//!
//! 実装済み:
//! - VM・ゲスト RAM・vCPU・GICv3 の実行時解決（`sys/hvf.rs`・`hvf::memory`・`hvf::gic`。#3783・#3786・#3787・#3789・#3792・#3795）
//! - vCPU 専用スレッドと実行ループ・exit の分類（`hvf_loop`・`hvf::vcpu`。#3791）と、MMIO・HVC（PSCI）・WFI / vtimer の処理
//!   （`hvf::mmio`・`hvf::hvc`。#3793・#3794・#3883）
//! - microVM 構成体と start / stop・停止時の資源の解放順序（`hvf::microvm`・`hvf_lifecycle`。#3797・#3798・#3882）
//! - UART の SPI 割り込みと入力（#3892・#3893）
//! - `fandhe-container-plugin-microvm` の start / stop への結線（#3800・#3927）
//! - SMP（vCPU 1 以上の作成と PSCI `CPU_ON` による AP の起動。#3884・#3891）
//! - `run_once` の期限切れ後の cancel 漏れの是正（#3845）
//!
//! 未実装（正は各ファイルの「未実装」節。実装済みを装わない。REPAIR-3）:
//! - virtio-block の QueueNotify の配線は #4028 で済み。virtio-net の QueueNotify の配線は #4029 で済み（ホスト側の到着による受信は #4030）。TIMEOUT 後のゲスト RAM の回収は #4032 で実装済み（vCPU スレッドの終了時。実機未確認 #4034）
//! - big-endian ゲスト

#![deny(unsafe_code)]

pub mod arm64_layout;
pub mod boot_arm64;
pub mod boot_x86;
pub mod cpuid_x86;
#[cfg(target_os = "linux")]
pub mod device;
pub mod dispatch;
pub mod error;
pub mod esr;
pub mod exit;
pub mod fdt;
pub mod guest_memory;
#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
pub mod guest_memory_slot;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod hvf;
pub mod hvf_abi;
pub mod hvf_lifecycle;
pub mod hvf_loop;
pub mod hvf_smp;
pub mod hvf_wake;
pub mod interrupt;
#[cfg(target_os = "linux")]
pub mod irq;
pub mod lapic_x86;
#[cfg(target_os = "linux")]
pub mod microvm;
pub mod mmio_abort;
pub mod mptable_x86;
pub mod psci;
pub mod smp_x86;
pub mod spi;
pub mod stop;
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod sys;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(unsafe_code)]
#[path = "sys/hvf.rs"]
mod sys;
pub mod sysreg_os_lock;
pub mod uart;
pub mod virtio_block;
pub mod virtio_mmio;
pub mod virtio_net;
pub mod virtqueue;
