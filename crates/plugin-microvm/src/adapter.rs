//! 要求ハンドラ（`frame_loop::RequestHandler` の実装）。TASK-117.1・#710、TASK-117.2・#711。PLUG-1・MVM-1・REPAIR-3。
//!
//! 呼び出し元: `main.rs` が `frame_loop::serve_until` へ渡す。core 側 proxy（#1869 の設計）が送る要求の先頭要素
//! （操作名）で分岐する暫定契約（本体 `Vec<String>`。型つき本体への置換は #1869 の設計・承認と実装 issue の起票は #2232）。
//! microVM 本体の操作は [`MicrovmBackend`] 越しに `fandhe-container-microvm` へ委譲する。backend は OS で分かれる:
//! Linux は `KvmBackend`（同時 4 台・x86 bzImage）、macOS の aarch64 は `HvfBackend`（Hypervisor.framework。同時 1 台・
//! arm64 Image・cmdline は 2047 バイトまで。TASK-192.18・#3800・MVM-5）、それ以外（macOS x86_64・Windows）は常に
//! `UNIMPLEMENTED` の `UnsupportedBackend`。上限（同時台数・cmdline）は OS ではなく backend の性質として
//! [`MicrovmBackend::VM_LIMIT`]・[`MicrovmBackend::CMDLINE_MAX_BYTES`] が持つ。
//!
//! # 操作（暫定ワイヤー契約・spec 未規定）
//! | 操作 | 要求 | 応答 |
//! | ---- | ---- | ---- |
//! | ping | `["ping"]` | `["pong"]` |
//! | start | `["start", id, kernel_path, initrd_path または "", cmdline, vcpus, mem_mib]`（ちょうど 7 要素） | `["running"]` |
//! | stop | `["stop", id]`（ちょうど 2 要素） | `["stopped", <停止理由の固定名>]` |
//!
//! 上記以外（kill・delete・state・I/O 系の名前を含む）は `UNIMPLEMENTED`（実装済みを装わない。REPAIR-3）。
//! 現時点の `vcpus` は 1 のみ受ける（2 以上は microvm 側が未実装のため `UNIMPLEMENTED`）。block / net は付けない。
//!
//! # I/O パスは境界を通らない（MVM-1）
//! UDS が運ぶのは制御操作（ping / start / stop）だけ。デバイスモデル（virtio-mmio・virtqueue・block / net backend）と
//! vCPU の exit 処理は plugin プロセス内の `fandhe-container-microvm` が担い、デバイスの読み書きのために RPC を発行する
//! 経路は持たない（受理する操作の集合は [`ACCEPTED_OPS`] で機械照合する）。
//!
//! # 入力検証と資源
//! 要素数 → id → 重複・上限 → 数値 → パス → イメージ読み込み → backend の順で fail-closed に検証する。エラー文言は固定で、
//! id・パス・cmdline・I/O エラー文言を反射しない。イメージは symlink・非通常ファイルを拒否し、上限を読む前に判定する。
//! unix では `/` から要素ごとに `openat(O_NOFOLLOW)` で辿り、祖先の symlink も拒否する（SEC-1。#3748）。
//! 同時 VM 数は backend ごとの [`MicrovmBackend::VM_LIMIT`]（既定は [`MAX_VMS`]）で抑える。停止は [`STOP_DEADLINE`]（RPC 期限より短い。REPAIR-5）。
//!
//! # 注意・残余（REPAIR-3）
//! - plugin プロセスは SIGUSR2 を使わない（microvm の `run_once` がプロセス全体の handler を入れる）。
//! - stop が `TIMEOUT` の後、vCPU スレッドが自力で終わるまで資源（ゲスト RAM・fd）が残る。backend から終了を観測できないため、
//!   期限切れで切り離した VM は、終了を観測するまで [`MicrovmBackend::VM_LIMIT`] の計数に残す（`detached`。資源上限。REPAIR-5）。
//!   終了の観測は `stop` の前に取った [`MicrovmBackend::ExitWatch`] への待たない照会（`VcpuExitWatch::state`。待ちの期限は 0）で行い、
//!   契機は `start` 要求の上限判定の直前と [`MicrovmRuntimeAdapter::reclaim_detached`] の明示呼び出しだけ（監視スレッドは持たない。#3745）。
//!   終了（`Released`）を観測したものだけ枠を返し、観測できない間は返さない（fail-closed）。
//! - 残余: `KVM_RUN` や ioctl の中で D 状態のまま戻らない vCPU スレッドは `Pending` のままで枠は返らない（回復は plugin の再起動）。
//!   microvm 側で memslot の削除に失敗した場合は、`Released` でもゲスト RAM の mapping が残りうる（microvm 側の fail-closed の既存仕様）。
//!   macOS（`HvfBackend`）では TIMEOUT の後に `detached` が生じ、枠は返らない（`Pending` 固定）。microvm が TIMEOUT 時にゲスト RAM の
//!   対応付けをリークし、プロセスが終わるまで同じプロセスで VM を作り直せないため。回収は plugin の再起動で、後から回収する件は #3908。
//!   `UnsupportedBackend`（macOS x86_64・Windows）では VM を作れないため `detached` は生じない。
//! - macOS の Hypervisor.framework は 1 プロセスに 1 VM（#3783）。上限 1 の 2 台目は `RESOURCE_EXHAUSTED`（`too many microVMs`）で拒否する。
//!   シリアル出力の取り出し・block / net・SMP は未接続。実機の記録は人間担当の #3803。
//! - イメージ読み込みは別スレッドで走らせ [`IMAGE_READ_DEADLINE`] で `TIMEOUT` にする（REPAIR-5）。期限切れのスレッドは取り消せず、
//!   I/O が戻るまで読み込みの枠（`MAX_INFLIGHT_READS`。adapter ごとの計数器で、本番は 1 adapter のためプロセス全体の上限と等価。#3900）を保持する。枠が尽きると、I/O が戻るまで（戻らなければ plugin の再起動まで）
//!   `RESOURCE_EXHAUSTED` になる。
//! - 呼び出し側は symlink を含まないパスを渡す
//!   （祖先の symlink は unix で拒否される。macOS の `/tmp`・`/var`、merged-usr の `/lib` なども拒否される。`/` は信頼する起点）。
//!   Windows は祖先を検査せず、lstat の失敗の分類（`map_lstat_error`）も best-effort（reparse point は未検査。Windows の backend は `UnsupportedBackend` で `start` が `UNIMPLEMENTED` のため VM は起動しない）。
//! - 実 Linux カーネルの起動完走は保証しない（CPUID・MSR・LAPIC・virtio-net rx 等は microvm 側の未実装）。実 KVM の通しは `tests/e2e.rs` の `#[ignore]` 試験（TASK-117.4・#713）、実 Hypervisor.framework の通しは同じ `tests/e2e.rs` の macOS aarch64 の `#[ignore]` 試験（TASK-192.18・#3800）。

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use fandhe_container_microvm::boot_x86::{
    CMDLINE_CAPACITY, MAX_INITRD_BYTES, MAX_KERNEL_IMAGE_BYTES,
};
use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};
use fandhe_container_plugin::{PluginError, PluginErrorCode, UDS_RPC_TIMEOUT_DEFAULT};

use crate::frame_loop::RequestHandler;

/// ヘルスチェック操作名。
pub const OP_PING: &str = "ping";
/// microVM 起動操作名。
pub const OP_START: &str = "start";
/// microVM 停止操作名。
pub const OP_STOP: &str = "stop";
/// 受理する操作の全集合（I/O 風の操作を含まないことを試験で照合する。MVM-1）。
pub const ACCEPTED_OPS: [&str; 3] = [OP_PING, OP_START, OP_STOP];
/// `ping` の応答。
pub const REPLY_PONG: &str = "pong";
/// `start` 成功の応答。
pub const REPLY_RUNNING: &str = "running";
/// `stop` 成功の応答の先頭要素。
pub const REPLY_STOPPED: &str = "stopped";

/// 同時に動かす VM 数の既定の上限（資源枯渇対策。Linux の KVM の値）。backend ごとの実効値は [`MicrovmBackend::VM_LIMIT`]。
pub const MAX_VMS: usize = 4;
/// RPC 期限から差し引く応答の余裕。
pub const RESPONSE_MARGIN: Duration = Duration::from_secs(2);
/// 1 台の停止の期限。RPC 期限から `RESPONSE_MARGIN` を引いた値（8 秒）未満かつ microvm の停止期限上限以下。
pub const STOP_DEADLINE: Duration = Duration::from_secs(5);
/// イメージ 1 件の読み取りの期限（kernel と initrd の 2 件で RPC 期限 - 余裕に収める。REPAIR-5）。
pub const IMAGE_READ_DEADLINE: Duration = Duration::from_secs(3);
/// 終了時の一括停止の合計予算。
pub const STOP_ALL_BUDGET: Duration = Duration::from_secs(4);

/// cmdline 本文の最大バイト数の既定（x86 boot protocol の `CMDLINE_CAPACITY` は NUL 込みの容量のため 1 引く）。
const X86_CMDLINE_MAX_BYTES: usize = CMDLINE_CAPACITY as usize - 1;

const _: () = assert!(MAX_VMS >= 1);
const _: () = assert!(X86_CMDLINE_MAX_BYTES as u64 + 1 == CMDLINE_CAPACITY);

const _: () = assert!(
    STOP_DEADLINE.as_secs() + RESPONSE_MARGIN.as_secs() < UDS_RPC_TIMEOUT_DEFAULT.as_secs()
);

const _: () = assert!(
    2 * IMAGE_READ_DEADLINE.as_secs() + RESPONSE_MARGIN.as_secs()
        <= UDS_RPC_TIMEOUT_DEFAULT.as_secs()
);

const ID_MAX_BYTES: usize = 255;
const PATH_MAX_BYTES: usize = 4096;
const VCPUS_MAX_DIGITS: usize = 10;
const MEM_MAX_DIGITS: usize = 20;

const MSG_MALFORMED: &str = "malformed request";
const MSG_UNIMPLEMENTED: &str = "operation is not implemented";
const MSG_BAD_ID: &str = "invalid container id";
const MSG_BAD_PATH: &str = "invalid image path";
const MSG_BAD_NUMBER: &str = "invalid numeric argument";
const MSG_BAD_CMDLINE: &str = "invalid kernel cmdline";
const MSG_MULTI_VCPU: &str = "multiple vCPUs are not implemented";
const MSG_EXISTS: &str = "microVM already exists";
const MSG_LIMIT: &str = "too many microVMs";
/// 画像読み込みスレッドの上限到達（VM 数の上限 `MSG_LIMIT` とは別物）。
const MSG_READ_LIMIT: &str = "too many in-flight image reads";
const MSG_NOT_FOUND: &str = "microVM not found";
const MSG_NOT_REGULAR: &str = "image must be a regular file";
const MSG_TOO_LARGE: &str = "image too large";
const MSG_READ_FAILED: &str = "failed to read image";
/// 祖先が symlink または非ディレクトリ（SEC-1。#3748）。パスは載せない。
const MSG_BAD_ANCESTOR: &str = "image path ancestor must be a real directory";
#[cfg(all(
    unix,
    not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))
))]
const MSG_UNSUPPORTED_VERIFY: &str = "image path verification is not supported on this platform";

/// 起動に必要な検証済みの値（読み込み済みイメージを持ち、パスは含まない）。
#[derive(Debug)]
pub struct BootSpec {
    /// vCPU 数。
    pub vcpus: u32,
    /// ゲスト RAM のバイト数。
    pub mem_bytes: u64,
    /// カーネルイメージ（x86 は bzImage、arm64 は Image。形式の検証は backend 側）。
    pub kernel: Vec<u8>,
    /// initrd（無ければ `None`）。
    pub initrd: Option<Vec<u8>>,
    /// ユーザー指定の cmdline。
    pub cmdline: String,
}

/// 切り離した VM の終了観測の結果（PLUG-1・REPAIR-5・#3745）。真偽値にせず、将来の状態を足せる形にする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DetachedState {
    /// 終了を観測できていない（資源が残っている可能性。枠を返さない）。
    Pending,
    /// vCPU スレッドが VM の資源を解放済み（枠を返してよい）。
    Released,
}

/// microVM 本体への委譲境界。3 OS でビルドでき、KVM なしの試験で差し替えられる。
pub trait MicrovmBackend {
    /// 同時に動かせる VM 数の上限（切り離し中の VM を含む）。上限は OS ではなく backend の性質で、既定は Linux（KVM）の
    /// [`MAX_VMS`]。Hypervisor.framework は 1 プロセス 1 VM のため 1 に上書きする（#3783・#3800）。
    const VM_LIMIT: usize = MAX_VMS;
    /// cmdline 本文の最大バイト数。既定は x86 の 4095。arm64 は FDT の `bootargs` の上限 2047 に上書きする。
    /// kernel と initrd の上限は全 backend 共通の `boot_x86::{MAX_KERNEL_IMAGE_BYTES, MAX_INITRD_BYTES}` で、
    /// arm64 側（`boot_arm64`・`check_assemble_input`）も同じ値を使う（#3790）。
    const CMDLINE_MAX_BYTES: usize = X86_CMDLINE_MAX_BYTES;
    /// 実行中 VM のハンドル。
    type Running;
    /// `stop` の後も有効な終了観測ハンドル。期限切れで切り離した VM の枠を返してよいかの判定に使う（#3745）。
    type ExitWatch;
    /// 起動する。失敗時は資源が解放済みであること（microvm 側の保証）。
    fn start(&mut self, spec: BootSpec) -> Result<Self::Running, MicrovmError>;
    /// `deadline` 以内に停止し、理由の固定名を返す。`vm` は成否に関わらず消費される。
    fn stop(&mut self, vm: Self::Running, deadline: Duration)
    -> Result<&'static str, MicrovmError>;
    /// 終了観測ハンドルを取る。`stop` が `vm` を消費するため、**`stop` に渡す前**に取ること。
    fn exit_watch(&self, vm: &Self::Running) -> Self::ExitWatch;
    /// 終了を待たずに照会する（ブロックしない契約。RPC 期限を消費しない）。未知の状態は `Pending` に倒す（fail-closed）。
    fn exit_state(&self, watch: &Self::ExitWatch) -> DetachedState;
}

/// `VcpuExitState` を adapter の状態へ写す。`Running` と将来追加される未知の状態は `Pending`（fail-closed）。
#[cfg(target_os = "linux")]
fn classify_exit_state(s: fandhe_container_microvm::microvm::VcpuExitState) -> DetachedState {
    use fandhe_container_microvm::microvm::VcpuExitState;
    match s {
        VcpuExitState::Exited(_) | VcpuExitState::ExitedAbnormally => DetachedState::Released,
        _ => DetachedState::Pending,
    }
}

/// Linux の KVM backend。`/dev/kvm` は初回 start で 1 回だけ開く。
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct KvmBackend {
    kvm: Option<fandhe_container_microvm::device::KvmDevice>,
}

#[cfg(target_os = "linux")]
impl MicrovmBackend for KvmBackend {
    type Running = fandhe_container_microvm::microvm::RunningMicroVm;
    type ExitWatch = fandhe_container_microvm::microvm::VcpuExitWatch;

    fn start(&mut self, spec: BootSpec) -> Result<Self::Running, MicrovmError> {
        use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
        use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
        use fandhe_container_microvm::virtio_net::MemoryNetBackend;

        if self.kvm.is_none() {
            self.kvm = Some(fandhe_container_microvm::device::KvmDevice::open()?);
        }
        let kvm = self.kvm.as_ref().ok_or_else(|| {
            MicrovmError::new(MicrovmErrorCode::Internal, "KVM device unavailable")
        })?;
        let mut vm = MicroVm::<MemoryBlockBackend, MemoryNetBackend>::assemble(
            kvm,
            MicroVmConfig {
                vcpu_count: spec.vcpus,
                mem_size: spec.mem_bytes,
                block: Vec::new(),
                net: Vec::new(),
            },
        )?;
        let loaded = vm.load_kernel(&spec.kernel, spec.initrd.as_deref(), &spec.cmdline)?;
        vm.start(&loaded)
    }

    fn stop(
        &mut self,
        vm: Self::Running,
        deadline: Duration,
    ) -> Result<&'static str, MicrovmError> {
        vm.stop(deadline).map(|r| r.reason.as_str())
    }

    fn exit_watch(&self, vm: &Self::Running) -> Self::ExitWatch {
        vm.exit_watch()
    }

    fn exit_state(&self, watch: &Self::ExitWatch) -> DetachedState {
        classify_exit_state(watch.state())
    }
}

/// macOS（Apple Silicon）の Hypervisor.framework backend（TASK-192.18・#3800・MVM-5・PLUG-1）。
///
/// 呼び出し元は `main.rs`（`default_backend()`）。`fandhe_container_microvm::hvf::{HvfMicroVm, RunningHvfMicroVm}`（#3797・#3798）へ
/// 委譲し、arm64 Image のヘッダ検証は microvm の `load_arm64`（#3790）に任せて adapter では重複させない。
/// block / net / シリアルは付けない（Linux の `KvmBackend` と同じ。シリアル出力の取り出しは範囲外）。vCPU は 1 のみ。
/// Hypervisor.framework は 1 プロセスに 1 VM のため [`MicrovmBackend::VM_LIMIT`] は 1（#3783）。
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default)]
pub struct HvfBackend;

/// `HvfBackend` の終了観測ハンドル。常に `Pending`（fail-closed）を返す。
///
/// microvm は stop が TIMEOUT のときゲスト RAM の対応付けを意図的にリークし、プロセスが終わるまで同じプロセスで VM を
/// 作り直せない。終了を観測できないうえ枠を返してはいけないため `Pending` 固定とする。回収は plugin の再起動で、
/// 後から回収する件は #3908。帰結: TIMEOUT の後の start は assemble の `FailedPrecondition` ではなく `RESOURCE_EXHAUSTED`。
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub struct HvfExitWatch(());

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl MicrovmBackend for HvfBackend {
    const VM_LIMIT: usize = 1;
    const CMDLINE_MAX_BYTES: usize = fandhe_container_microvm::arm64_layout::ARM64_MAX_BOOTARGS;

    type Running = fandhe_container_microvm::hvf::RunningHvfMicroVm<
        fandhe_container_microvm::virtio_block::MemoryBlockBackend,
        fandhe_container_microvm::virtio_net::MemoryNetBackend,
    >;
    type ExitWatch = HvfExitWatch;

    fn start(&mut self, spec: BootSpec) -> Result<Self::Running, MicrovmError> {
        use fandhe_container_microvm::arm64_layout::Arm64Layout;
        use fandhe_container_microvm::hvf::{HvfMicroVm, HvfMicroVmConfig, VcpuThreadConfig};
        use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
        use fandhe_container_microvm::virtio_net::MemoryNetBackend;

        let layout = Arm64Layout::new(spec.mem_bytes, spec.vcpus, 0)?;
        let config = HvfMicroVmConfig::<MemoryBlockBackend, MemoryNetBackend> {
            layout,
            kernel: spec.kernel,
            initrd: spec.initrd,
            cmdline: spec.cmdline,
            block: Vec::new(),
            net: Vec::new(),
            vcpu: VcpuThreadConfig::default(),
            serial: false,
        };
        HvfMicroVm::assemble(config)?.start()
    }

    fn stop(
        &mut self,
        vm: Self::Running,
        deadline: Duration,
    ) -> Result<&'static str, MicrovmError> {
        vm.stop(deadline).map(|r| r.reason.as_str())
    }

    fn exit_watch(&self, _vm: &Self::Running) -> Self::ExitWatch {
        HvfExitWatch(())
    }

    fn exit_state(&self, _watch: &Self::ExitWatch) -> DetachedState {
        DetachedState::Pending
    }
}

/// Linux でも macOS aarch64 でもない OS（macOS x86_64・Windows）の backend。start は常に `UNIMPLEMENTED`（fail-closed）。
#[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
#[derive(Debug, Default)]
pub struct UnsupportedBackend;

/// 到達不能な実行中ハンドル（`UnsupportedBackend` では VM を作れない）。
#[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
#[derive(Debug)]
pub enum NeverRunning {}

#[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
impl MicrovmBackend for UnsupportedBackend {
    type Running = NeverRunning;
    type ExitWatch = NeverRunning;

    fn start(&mut self, _spec: BootSpec) -> Result<Self::Running, MicrovmError> {
        Err(MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "microVM is not supported on this platform",
        ))
    }

    fn stop(
        &mut self,
        vm: Self::Running,
        _deadline: Duration,
    ) -> Result<&'static str, MicrovmError> {
        match vm {}
    }

    fn exit_watch(&self, vm: &Self::Running) -> Self::ExitWatch {
        match *vm {}
    }

    fn exit_state(&self, watch: &Self::ExitWatch) -> DetachedState {
        match *watch {}
    }
}

/// `main.rs` が使う OS 既定の backend 型。
#[cfg(target_os = "linux")]
pub type DefaultBackend = KvmBackend;
/// `main.rs` が使う OS 既定の backend 型。
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub type DefaultBackend = HvfBackend;
/// `main.rs` が使う OS 既定の backend 型。
#[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
pub type DefaultBackend = UnsupportedBackend;

/// OS 既定の backend を作る。
pub fn default_backend() -> DefaultBackend {
    DefaultBackend::default()
}

/// microvm のエラーを plugin のエラーへ写す唯一の関数。
///
/// message は microvm の固定文言（パス・入力値を含まない契約）をそのまま使う。未知の分類は `Internal`（fail-closed）。
pub fn to_plugin_error(e: &MicrovmError) -> PluginError {
    let code = match e.code() {
        MicrovmErrorCode::NotFound => PluginErrorCode::NotFound,
        MicrovmErrorCode::PermissionDenied => PluginErrorCode::PermissionDenied,
        MicrovmErrorCode::FailedPrecondition => PluginErrorCode::FailedPrecondition,
        MicrovmErrorCode::ResourceExhausted => PluginErrorCode::ResourceExhausted,
        MicrovmErrorCode::Unimplemented => PluginErrorCode::Unimplemented,
        MicrovmErrorCode::InvalidArgument => PluginErrorCode::InvalidArgument,
        MicrovmErrorCode::AlreadyExists => PluginErrorCode::AlreadyExists,
        MicrovmErrorCode::Internal => PluginErrorCode::Internal,
        MicrovmErrorCode::DeadlineExceeded => PluginErrorCode::Timeout,
        _ => PluginErrorCode::Internal,
    };
    PluginError::new(code, e.message())
}

fn perr(code: PluginErrorCode, msg: &'static str) -> PluginError {
    PluginError::new(code, msg)
}

fn invalid(msg: &'static str) -> PluginError {
    perr(PluginErrorCode::InvalidArgument, msg)
}

/// core の `ContainerId` と同じ規則（空・`.`・`..` 不可、255 バイト以下、`[A-Za-z0-9._-]`）。
fn validate_id(id: &str) -> Result<(), PluginError> {
    let ok = !id.is_empty()
        && id != "."
        && id != ".."
        && id.len() <= ID_MAX_BYTES
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok { Ok(()) } else { Err(invalid(MSG_BAD_ID)) }
}

/// 絶対パスで `RootDir` と `Normal` だけからなること（`.`・`..`・prefix・NUL を拒否）。
fn validate_path(p: &str) -> Result<&Path, PluginError> {
    if p.is_empty() || p.len() > PATH_MAX_BYTES || p.contains('\0') {
        return Err(invalid(MSG_BAD_PATH));
    }
    let path = Path::new(p);
    // `components()` は中間の `.` を畳むため、生の区切りでも `.`・`..` を拒否する。
    let dotted = |seg: &str| seg == "." || seg == "..";
    if p.split('/').any(dotted) {
        return Err(invalid(MSG_BAD_PATH));
    }
    // Windows の区切りは バックスラッシュ。ここでも `.`・`..` を拒否する。
    #[cfg(windows)]
    if p.split('\\').any(dotted) {
        return Err(invalid(MSG_BAD_PATH));
    }
    // Windows の絶対パスはドライブ prefix や UNC を伴うため、その OS でだけ `Prefix` を許す。
    let component_ok = |c: Component<'_>| match c {
        Component::RootDir | Component::Normal(_) => true,
        #[cfg(windows)]
        Component::Prefix(_) => true,
        _ => false,
    };
    if !path.is_absolute() || !path.components().all(component_ok) {
        return Err(invalid(MSG_BAD_PATH));
    }
    Ok(path)
}

/// 数字のみ（`+`・空白・空を拒否）の 10 進数を `u64` へ変換する。
fn parse_digits(s: &str, max_digits: usize) -> Result<u64, PluginError> {
    if s.is_empty() || s.len() > max_digits || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(MSG_BAD_NUMBER));
    }
    s.parse::<u64>().map_err(|_| invalid(MSG_BAD_NUMBER))
}

#[derive(Debug, Clone, Copy)]
enum ImageKind {
    Kernel,
    Initrd,
}

/// イメージを読む。symlink・非通常ファイルを拒否し、上限は読む前（metadata）と読み込み中（`take`）で二重に判定する。
///
/// lstat と open の間の差し替えは unix で dev / ino の照合により検出する。unix では `/` から要素ごとに
/// `O_NOFOLLOW` で辿って祖先の symlink を拒否し（`sys::open_regular_nofollow`。#3748）、Windows は祖先を検査しない（残余）。
/// lstat の段の失敗も open の段と同じ分類にする（`map_lstat_error`。#3890）。
///
/// 応答しない FUSE 等で同期 I/O が止まっても RPC ハンドラ全体を止めないよう、実処理は別スレッドで走らせ
/// [`IMAGE_READ_DEADLINE`] で打ち切る（REPAIR-5）。期限切れのスレッドは detach し、I/O の復帰後に自力で終わる。
/// 枠は I/O が戻るまで保持し、`limiter`（adapter ごと）で生存中の読み込みが `MAX_INFLIGHT_READS` に達すると `RESOURCE_EXHAUSTED` になる。
fn read_image(
    limiter: &ReadLimiter,
    path: &Path,
    cap: u64,
    kind: ImageKind,
) -> Result<Vec<u8>, PluginError> {
    let slot = limiter.acquire()?;
    let (tx, rx) = std::sync::mpsc::channel();
    let owned = path.to_path_buf();
    let spawned = std::thread::Builder::new()
        .name("microvm-read-image".into())
        .spawn(move || {
            let r = read_image_blocking(&owned, cap, kind);
            // 読み込みが実際に終わってから枠を返す（期限切れ後も止まった I/O は枠を保持し続ける）。
            drop(slot);
            let _ = tx.send(r);
        });
    if spawned.is_err() {
        // spawn 失敗時はクロージャごと slot が破棄され、枠は Drop で返る。
        return Err(perr(PluginErrorCode::Internal, MSG_READ_FAILED));
    }
    match rx.recv_timeout(IMAGE_READ_DEADLINE) {
        Ok(r) => r,
        Err(_) => Err(perr(PluginErrorCode::Timeout, "image read timed out")),
    }
}

/// 実行中（期限切れで detach 済みを含む）の読み込みスレッド数の上限（REPAIR-5・リソース上限）。
/// 枠は adapter ごとに持つ（本番は 1 プロセス 1 adapter のためプロセス全体の上限と等価。#3900）。
const MAX_INFLIGHT_READS: usize = 8;

/// 読み込みスレッドの枠の計数器。adapter が所有し、`read_image` へ渡す（#3900）。
///
/// 以前はプロセス全体の static だったため、同じ試験バイナリ内で並列に走る別 adapter の読み込みと枠を取り合い、
/// 並列度が高いと `start` が `RESOURCE_EXHAUSTED` になる間欠失敗の原因になっていた。
/// 計数器は `Arc` で reader スレッドにも渡すため、期限切れで detach したスレッドが adapter より長生きしても有効。
#[derive(Clone, Debug)]
struct ReadLimiter {
    counter: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    max: usize,
}

impl ReadLimiter {
    fn new(max: usize) -> Self {
        Self {
            counter: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max,
        }
    }

    /// 枠を取る。上限到達時のメッセージは VM 数の上限（`MSG_LIMIT`）と区別する。
    fn acquire(&self) -> Result<ReadSlot, PluginError> {
        use std::sync::atomic::Ordering;
        let max = self.max;
        self.counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max).then_some(n + 1)
            })
            .map(|_| ReadSlot(std::sync::Arc::clone(&self.counter)))
            .map_err(|_| perr(PluginErrorCode::ResourceExhausted, MSG_READ_LIMIT))
    }
}

/// 読み込みスレッドの枠。Drop で返す。
struct ReadSlot(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Drop for ReadSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// イメージ読み取りの `io::Error` を固定文言の `PluginError` へ写す（パス・OS の文言は載せない。ERR-1）。
fn map_io(e: std::io::Error, kind: ImageKind) -> PluginError {
    match e.kind() {
        std::io::ErrorKind::NotFound => match kind {
            ImageKind::Kernel => perr(PluginErrorCode::NotFound, "kernel image not found"),
            ImageKind::Initrd => perr(PluginErrorCode::NotFound, "initrd image not found"),
        },
        std::io::ErrorKind::PermissionDenied => perr(
            PluginErrorCode::PermissionDenied,
            "permission denied reading image",
        ),
        _ => perr(PluginErrorCode::Internal, MSG_READ_FAILED),
    }
}

/// `sys::open_regular_nofollow` の失敗を写す。入力不正（`INVALID_ARGUMENT`）にするのは「実体ではない」
/// （ELOOP / ENOTDIR。`sys::is_not_real_entry`）だけで、EMFILE・EIO・ENAMETOOLONG 等は `INTERNAL`
/// （NotFound / PermissionDenied は従来どおり）。`read_image_blocking` から呼ぶ（ERR-1・SEC-1・#3841）。
#[cfg(unix)]
fn map_nofollow_error(e: crate::sys::NoFollowOpenError, kind: ImageKind) -> PluginError {
    use crate::sys::{NoFollowOpenError as E, is_not_real_entry};
    match e {
        E::InvalidPath => invalid(MSG_BAD_PATH),
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        E::Unsupported => perr(PluginErrorCode::Unimplemented, MSG_UNSUPPORTED_VERIFY),
        E::Ancestor(io) if is_not_real_entry(&io) => invalid(MSG_BAD_ANCESTOR),
        E::Leaf(io) if is_not_real_entry(&io) => invalid(MSG_NOT_REGULAR),
        E::Ancestor(io) | E::Leaf(io) => map_io(io, kind),
    }
}

/// `symlink_metadata` の失敗を写す。open の段の `map_nofollow_error` と同じ入力不正には同じ
/// `INVALID_ARGUMENT` と固定文言を返す（ERR-1・SEC-1・#3890。`read_image_blocking` から呼ぶ）。
///
/// ENOTDIR は `ErrorKind` で、ELOOP は sys の定数で判定する。lstat の失敗には祖先 / 最終要素の区別が無く、2 つの文言を
/// 分ける手がかりはパスの形（末尾区切り）だけで、`ErrorKind` は std が OS ごとに errno を写した結果だから。
/// - `NotADirectory`: 末尾区切りありは最終要素がディレクトリでない（`MSG_NOT_REGULAR`）、なしは
///   祖先が実ディレクトリでない（`MSG_BAD_ANCESTOR`）。`file/x/` のように両方当てはまる場合は前者になる。
/// - ELOOP（`sys::is_not_real_entry`。unix のみ）: 祖先の symlink の解決の失敗（`MSG_BAD_ANCESTOR`）。
/// - それ以外は従来どおり `map_io`（`map_io` 自体は他の失敗にも使うため変えない）。
///
/// Windows は祖先を検査せず（残余）、この分類は best-effort（祖先が通常ファイルなら OS が
/// `NOT_FOUND` 相当を返しうる。Windows では試験していない）。
fn map_lstat_error(e: std::io::Error, path: &Path, kind: ImageKind) -> PluginError {
    match e.kind() {
        std::io::ErrorKind::NotADirectory => {
            if ends_with_separator(path) {
                invalid(MSG_NOT_REGULAR)
            } else {
                invalid(MSG_BAD_ANCESTOR)
            }
        }
        // `ErrorKind::FilesystemLoop` は固定 toolchain で unstable のため ELOOP は sys の定数で判定する。
        // ENOTDIR は上で処理済みなので、ここに来る `is_not_real_entry` は ELOOP だけ。
        #[cfg(unix)]
        _ if crate::sys::is_not_real_entry(&e) => invalid(MSG_BAD_ANCESTOR),
        _ => map_io(e, kind),
    }
}

/// 生のパスの最後のバイトが区切り文字か（`Path::components()` は末尾の区切りを畳むため使えない）。
fn ends_with_separator(path: &Path) -> bool {
    path.as_os_str()
        .as_encoded_bytes()
        .last()
        .is_some_and(|b| std::path::is_separator(char::from(*b)))
}

fn read_image_blocking(path: &Path, cap: u64, kind: ImageKind) -> Result<Vec<u8>, PluginError> {
    let map_io = |e: std::io::Error| map_io(e, kind);
    let lmeta = std::fs::symlink_metadata(path).map_err(|e| map_lstat_error(e, path, kind))?;
    if !lmeta.file_type().is_file() {
        return Err(invalid(MSG_NOT_REGULAR));
    }
    if lmeta.len() > cap {
        return Err(invalid(MSG_TOO_LARGE));
    }
    #[cfg(unix)]
    let file =
        { crate::sys::open_regular_nofollow(path).map_err(|e| map_nofollow_error(e, kind))? };
    // Windows: 祖先は検査しない（残余。モジュール doc 参照）。
    #[cfg(not(unix))]
    let file = std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(map_io)?;
    let fmeta = file.metadata().map_err(map_io)?;
    if !fmeta.file_type().is_file() {
        return Err(invalid(MSG_NOT_REGULAR));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fmeta.dev() != lmeta.dev() || fmeta.ino() != lmeta.ino() {
            return Err(invalid(MSG_NOT_REGULAR));
        }
    }
    let mut buf = Vec::new();
    file.take(cap.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(map_io)?;
    if buf.len() as u64 > cap {
        return Err(invalid(MSG_TOO_LARGE));
    }
    Ok(buf)
}

/// 一括停止の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopAllReport {
    /// 正常に止めた台数。
    pub stopped: usize,
    /// 停止に失敗した台数（期限切れ含む）。
    pub failed: usize,
    /// 予算切れで止めなかった台数。
    pub remaining: usize,
}

/// microVM 制御のアダプタ。実行中 VM をプロセス内メモリの登録簿で持つ（永続化しない）。
#[derive(Debug)]
pub struct MicrovmRuntimeAdapter<B: MicrovmBackend> {
    backend: B,
    vms: BTreeMap<String, B::Running>,
    /// 停止が期限切れで切り離された（終了未観測の）VM の観測ハンドル。件数を [`MicrovmBackend::VM_LIMIT`] の計数に含める。
    /// `vms.len() + detached.len() <= B::VM_LIMIT` が保たれるため、長さは上限で抑えられる。
    detached: Vec<B::ExitWatch>,
    /// イメージ読み込みスレッドの枠（adapter ごと。#3900）。
    reads: ReadLimiter,
}

impl<B: MicrovmBackend> MicrovmRuntimeAdapter<B> {
    /// backend を指定してアダプタを作る。
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            vms: BTreeMap::new(),
            detached: Vec::new(),
            reads: ReadLimiter::new(MAX_INFLIGHT_READS),
        }
    }

    /// 読み込み枠の上限を指定して作る（試験用。#3900）。
    #[cfg(test)]
    fn with_read_limiter(backend: B, reads: ReadLimiter) -> Self {
        Self {
            reads,
            ..Self::new(backend)
        }
    }

    /// 停止期限切れで切り離したまま終了未観測の VM 数。
    pub fn detached(&self) -> usize {
        self.detached.len()
    }

    /// 終了を観測できた切り離し VM の枠を返し、返した件数を返す。待たない照会のみ（O(VM_LIMIT)。冪等）。
    /// `start` の上限判定の直前から呼ばれる（#3745・REPAIR-5）。
    pub fn reclaim_detached(&mut self) -> usize {
        let before = self.detached.len();
        let backend = &self.backend;
        self.detached
            .retain(|w| backend.exit_state(w) == DetachedState::Pending);
        before - self.detached.len()
    }

    /// 登録中の VM 数。
    pub fn len(&self) -> usize {
        self.vms.len()
    }

    /// 登録が空か。
    pub fn is_empty(&self) -> bool {
        self.vms.is_empty()
    }

    /// 全 VM を `budget` 内で登録順に止める。予算切れ以降の VM は 1ms の期限で停止要求だけ出して切り離す。各 VM の期限は `min(STOP_DEADLINE, 残り予算)`。
    pub fn stop_all(&mut self, budget: Duration) -> StopAllReport {
        let started = Instant::now();
        let mut report = StopAllReport {
            stopped: 0,
            failed: 0,
            remaining: 0,
        };
        let ids: Vec<String> = self.vms.keys().cloned().collect();
        for id in ids {
            let left = budget.saturating_sub(started.elapsed());
            let Some(vm) = self.vms.remove(&id) else {
                continue;
            };
            if left.is_zero() {
                // 予算切れ: Drop に任せると 1 台ごとに最大 5 秒待つため、停止要求だけ出して切り離す（1ms で打ち切る。REPAIR-5）。
                let watch = self.backend.exit_watch(&vm);
                if let Err(e) = self.backend.stop(vm, Duration::from_millis(1)) {
                    self.note_stop_error(&e, watch);
                }
                report.remaining += 1;
                continue;
            }
            let watch = self.backend.exit_watch(&vm);
            match self.backend.stop(vm, left.min(STOP_DEADLINE)) {
                Ok(_) => report.stopped += 1,
                Err(e) => {
                    self.note_stop_error(&e, watch);
                    report.failed += 1;
                }
            }
        }
        report
    }

    /// 停止が期限切れなら VM は切り離されただけで資源が残るため、観測ハンドルを計数に残す。それ以外のエラーでは捨てる。
    fn note_stop_error(&mut self, e: &MicrovmError, watch: B::ExitWatch) {
        if e.code() == MicrovmErrorCode::DeadlineExceeded {
            self.detached.push(watch);
        }
    }

    fn do_start(&mut self, body: &[String]) -> Result<Vec<String>, PluginError> {
        let [_, id, kernel, initrd, cmdline, vcpus, mem_mib] = body else {
            return Err(invalid(MSG_MALFORMED));
        };
        validate_id(id)?;
        if self.vms.contains_key(id.as_str()) {
            return Err(perr(PluginErrorCode::AlreadyExists, MSG_EXISTS));
        }
        self.reclaim_detached();
        if self.vms.len().saturating_add(self.detached.len()) >= B::VM_LIMIT {
            return Err(perr(PluginErrorCode::ResourceExhausted, MSG_LIMIT));
        }
        let vcpus = parse_digits(vcpus, VCPUS_MAX_DIGITS)?;
        let mem_mib = parse_digits(mem_mib, MEM_MAX_DIGITS)?;
        let mem_bytes = mem_mib
            .checked_mul(1 << 20)
            .filter(|b| *b > 0)
            .ok_or_else(|| invalid(MSG_BAD_NUMBER))?;
        if vcpus == 0 || vcpus > u64::from(u32::MAX) {
            return Err(invalid(MSG_BAD_NUMBER));
        }
        if vcpus != 1 {
            return Err(perr(PluginErrorCode::Unimplemented, MSG_MULTI_VCPU));
        }
        if cmdline.len() > B::CMDLINE_MAX_BYTES {
            return Err(invalid(MSG_BAD_CMDLINE));
        }
        let kernel_path = validate_path(kernel)?;
        let initrd_path = if initrd.is_empty() {
            None
        } else {
            Some(validate_path(initrd)?)
        };
        let kernel_bytes = read_image(
            &self.reads,
            kernel_path,
            MAX_KERNEL_IMAGE_BYTES,
            ImageKind::Kernel,
        )?;
        let initrd_bytes = match initrd_path {
            Some(p) => Some(read_image(
                &self.reads,
                p,
                MAX_INITRD_BYTES.min(mem_bytes),
                ImageKind::Initrd,
            )?),
            None => None,
        };
        let spec = BootSpec {
            vcpus: 1,
            mem_bytes,
            kernel: kernel_bytes,
            initrd: initrd_bytes,
            cmdline: cmdline.clone(),
        };
        let running = self.backend.start(spec).map_err(|e| to_plugin_error(&e))?;
        self.vms.insert(id.clone(), running);
        Ok(vec![REPLY_RUNNING.to_string()])
    }

    fn do_stop(&mut self, body: &[String]) -> Result<Vec<String>, PluginError> {
        let [_, id] = body else {
            return Err(invalid(MSG_MALFORMED));
        };
        validate_id(id)?;
        let vm = self
            .vms
            .remove(id.as_str())
            .ok_or_else(|| perr(PluginErrorCode::NotFound, MSG_NOT_FOUND))?;
        let watch = self.backend.exit_watch(&vm);
        let reason = match self.backend.stop(vm, STOP_DEADLINE) {
            Ok(r) => r,
            Err(e) => {
                self.note_stop_error(&e, watch);
                return Err(to_plugin_error(&e));
            }
        };
        Ok(vec![REPLY_STOPPED.to_string(), reason.to_string()])
    }

    /// 構造化ログ 1 行（id・パス・cmdline は載せない。REPAIR-4）。書き込み失敗は無視する。
    fn log(op: &str, started: Instant, vms: usize, result: &Result<Vec<String>, PluginError>) {
        use std::io::Write;
        let elapsed_us = started.elapsed().as_micros();
        let line = match result {
            Ok(_) => format!(
                "level=info op=plugin.microvm.{op} outcome=ok elapsed_us={elapsed_us} vms={vms}"
            ),
            Err(e) => format!(
                "level=error op=plugin.microvm.{op} outcome=error code={} elapsed_us={elapsed_us} vms={vms}",
                e.code().as_str()
            ),
        };
        let _ = writeln!(std::io::stderr(), "{line}");
    }
}

impl<B: MicrovmBackend> RequestHandler for MicrovmRuntimeAdapter<B> {
    fn handle(&mut self, body: &[String]) -> Result<Vec<String>, PluginError> {
        match body.first().map(String::as_str) {
            Some(OP_PING) if body.len() == 1 => Ok(vec![REPLY_PONG.to_string()]),
            Some(OP_PING) => Err(invalid(MSG_MALFORMED)),
            Some(OP_START) => {
                let started = Instant::now();
                let r = self.do_start(body);
                Self::log("start", started, self.vms.len(), &r);
                r
            }
            Some(OP_STOP) => {
                let started = Instant::now();
                let r = self.do_stop(body);
                Self::log("stop", started, self.vms.len(), &r);
                r
            }
            _ => Err(perr(PluginErrorCode::Unimplemented, MSG_UNIMPLEMENTED)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `open_regular_nofollow` の errno を固定文言へ写す（ERR-1・SEC-1・#3841）。ELOOP / ENOTDIR だけが入力不正。
    #[cfg(all(
        unix,
        any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )
    ))]
    #[test]
    fn sec1_err1_3841_nofollow_errno_mapping() {
        use crate::sys::NoFollowOpenError as E;
        use std::io::Error;
        #[cfg(target_os = "linux")]
        let (eloop, enametoolong, etimedout) = (40, 36, 110);
        #[cfg(target_os = "macos")]
        let (eloop, enametoolong, etimedout) = (62, 63, 60);
        let k = ImageKind::Kernel;
        let got = |e: PluginError| (e.code(), e.message().to_string());
        for n in [eloop, 20] {
            assert_eq!(
                got(map_nofollow_error(
                    E::Ancestor(Error::from_raw_os_error(n)),
                    k
                )),
                (
                    PluginErrorCode::InvalidArgument,
                    MSG_BAD_ANCESTOR.to_string()
                )
            );
            assert_eq!(
                got(map_nofollow_error(E::Leaf(Error::from_raw_os_error(n)), k)),
                (
                    PluginErrorCode::InvalidArgument,
                    MSG_NOT_REGULAR.to_string()
                )
            );
        }
        for (n, code, msg) in [
            (2, PluginErrorCode::NotFound, "kernel image not found"),
            (
                13,
                PluginErrorCode::PermissionDenied,
                "permission denied reading image",
            ),
            (
                1,
                PluginErrorCode::PermissionDenied,
                "permission denied reading image",
            ),
            (24, PluginErrorCode::Internal, MSG_READ_FAILED),
            (5, PluginErrorCode::Internal, MSG_READ_FAILED),
            (enametoolong, PluginErrorCode::Internal, MSG_READ_FAILED),
            (etimedout, PluginErrorCode::Internal, MSG_READ_FAILED),
        ] {
            let want = (code, msg.to_string());
            assert_eq!(
                got(map_nofollow_error(
                    E::Ancestor(Error::from_raw_os_error(n)),
                    k
                )),
                want,
                "ancestor {n}"
            );
            assert_eq!(
                got(map_nofollow_error(E::Leaf(Error::from_raw_os_error(n)), k)),
                want,
                "leaf {n}"
            );
        }
        assert_eq!(
            got(map_nofollow_error(
                E::Leaf(Error::from_raw_os_error(2)),
                ImageKind::Initrd
            )),
            (
                PluginErrorCode::NotFound,
                "initrd image not found".to_string()
            )
        );
        assert_eq!(
            got(map_nofollow_error(E::InvalidPath, k)),
            (PluginErrorCode::InvalidArgument, MSG_BAD_PATH.to_string())
        );
    }

    /// 画像読み込みの枠が尽きたとき、VM 数上限と区別できる文言で RESOURCE_EXHAUSTED になる（REPAIR-5・MVM-5）。
    #[test]
    fn read_slot_limit_uses_distinct_message() {
        let limiter = ReadLimiter::new(1);
        let held = limiter.acquire().expect("first slot");
        let e = limiter.acquire().err().expect("limit");
        assert_eq!(e.code(), PluginErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "too many in-flight image reads");
        assert_ne!(e.message(), MSG_LIMIT);
        drop(held);
        drop(limiter.acquire().expect("slot returned"));
    }

    /// #3900・REPAIR-5・REPAIR-12: 読み込み枠は adapter ごと。枠を使い切った adapter の start は失敗し、
    /// 別の adapter は影響を受けず、枠を返せば元の adapter も成功する。既定の上限は 8。
    #[test]
    fn repair5_repair12_3900_read_slots_are_per_adapter() {
        assert_eq!(MAX_INFLIGHT_READS, 8);
        let t = Tmp::new("slots3900");
        let k = t.file("k", b"KERNEL");
        let limiter = ReadLimiter::new(MAX_INFLIGHT_READS);
        let mut a =
            MicrovmRuntimeAdapter::with_read_limiter(FakeBackend::default(), limiter.clone());
        let held: Vec<ReadSlot> = (0..MAX_INFLIGHT_READS)
            .map(|_| limiter.acquire().expect("slot"))
            .collect();
        let e = a.handle(&start_req("vm1", &k)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "too many in-flight image reads");
        assert_ne!(e.message(), MSG_LIMIT);
        assert_eq!(a.backend.starts, 0);
        assert!(a.is_empty());
        // 別 adapter（既定の new）は影響を受けない。
        let mut b = adapter();
        assert_eq!(b.handle(&start_req("vm1", &k)).expect("b"), s(&["running"]));
        assert_eq!(b.backend.starts, 1);
        assert_eq!(b.len(), 1);
        // 枠を返せば元の adapter も成功する。
        drop(held);
        assert_eq!(a.handle(&start_req("vm1", &k)).expect("a"), s(&["running"]));
        assert_eq!(a.backend.starts, 1);
        // 既定の new の上限は 8（9 個目で RESOURCE_EXHAUSTED）。
        let d = ReadLimiter::new(MAX_INFLIGHT_READS);
        let _h: Vec<ReadSlot> = (0..8).map(|_| d.acquire().expect("slot")).collect();
        assert_eq!(
            d.acquire().err().expect("9th").code(),
            PluginErrorCode::ResourceExhausted
        );
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// KVM に触れない試験用 backend。
    #[derive(Default)]
    struct FakeBackend {
        /// 終了を観測済みにした VM の id（後から vCPU スレッドが終わった模擬。#3745）。
        exited: std::collections::BTreeSet<u32>,
        starts: usize,
        start_err: Option<MicrovmErrorCode>,
        stop_err: Option<MicrovmErrorCode>,
        reason: &'static str,
    }

    impl MicrovmBackend for FakeBackend {
        type Running = u32;
        type ExitWatch = u32;
        fn start(&mut self, _spec: BootSpec) -> Result<u32, MicrovmError> {
            self.starts += 1;
            match self.start_err {
                Some(c) => Err(MicrovmError::new(c, "fake")),
                None => Ok(u32::try_from(self.starts).expect("small")),
            }
        }
        fn exit_watch(&self, vm: &u32) -> u32 {
            *vm
        }
        fn exit_state(&self, watch: &u32) -> DetachedState {
            if self.exited.contains(watch) {
                DetachedState::Released
            } else {
                DetachedState::Pending
            }
        }
        fn stop(&mut self, _vm: u32, _d: Duration) -> Result<&'static str, MicrovmError> {
            match self.stop_err {
                Some(c) => Err(MicrovmError::new(c, "fake")),
                None => Ok(if self.reason.is_empty() {
                    "requested"
                } else {
                    self.reason
                }),
            }
        }
    }

    /// 一時ディレクトリ（成否に関わらず Drop で削除）。
    struct Tmp(std::path::PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("fc-pm-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).expect("mkdir");
            // 祖先の symlink を拒否するため正規化する（macOS の `/var` → `/private/var`。#3748）。
            Self(std::fs::canonicalize(&p).expect("canonicalize"))
        }
        fn file(&self, name: &str, data: &[u8]) -> String {
            let p = self.0.join(name);
            std::fs::write(&p, data).expect("write");
            p.to_string_lossy().into_owned()
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn start_req(id: &str, kernel: &str) -> Vec<String> {
        s(&["start", id, kernel, "", "console=ttyS0", "1", "64"])
    }

    fn adapter() -> MicrovmRuntimeAdapter<FakeBackend> {
        MicrovmRuntimeAdapter::new(FakeBackend::default())
    }

    /// MVM-1・PLUG-1: ping は pong を返し、余分な要素は固定文言で拒否する（入力値を反射しない）。
    #[test]
    fn mvm1_plug1_ping_returns_pong_and_rejects_extra() {
        let mut a = adapter();
        assert_eq!(a.handle(&s(&["ping"])).expect("ping"), s(&["pong"]));
        let e = a.handle(&s(&["ping", "SECRETARG"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(e.message(), "malformed request");
    }

    /// PLUG-1・REPAIR-3: 未実装の操作と I/O 風の操作名は UNIMPLEMENTED。受理集合は ping / start / stop ちょうど。
    #[test]
    fn task117_2_mvm1_plug1_unknown_and_io_ops_are_unimplemented() {
        assert_eq!(ACCEPTED_OPS, ["ping", "start", "stop"]);
        let mut a = adapter();
        for op in [
            "kill",
            "delete",
            "state",
            "read",
            "write",
            "mmio",
            "virtqueue",
            "block_io",
            "net_tx",
            "SECRETOP",
        ] {
            let e = a.handle(&s(&[op, "x"])).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::Unimplemented, "{op}");
            assert_eq!(e.message(), "operation is not implemented");
        }
    }

    /// MVM-1・PLUG-1: start 成功 → stop で reason が返り、登録が外れる。
    #[test]
    fn task117_2_mvm1_start_then_stop_roundtrip() {
        let t = Tmp::new("roundtrip");
        let k = t.file("k", b"KERNEL");
        let mut a = adapter();
        assert_eq!(
            a.handle(&start_req("vm1", &k)).expect("start"),
            s(&["running"])
        );
        assert_eq!(a.len(), 1);
        assert_eq!(a.backend.starts, 1);
        assert_eq!(
            a.handle(&s(&["stop", "vm1"])).expect("stop"),
            s(&["stopped", "requested"])
        );
        assert!(a.is_empty());
        a.backend.reason = "guest_shutdown";
        a.handle(&start_req("vm1", &k)).expect("restart");
        assert_eq!(
            a.handle(&s(&["stop", "vm1"])).expect("stop"),
            s(&["stopped", "guest_shutdown"])
        );
    }

    /// 重複 id は ALREADY_EXISTS（backend は呼ばれない）、上限超過は RESOURCE_EXHAUSTED。
    #[test]
    fn task117_2_mvm1_duplicate_and_limit() {
        let t = Tmp::new("limit");
        let k = t.file("k", b"K");
        let mut a = adapter();
        a.handle(&start_req("a", &k)).expect("a");
        let e = a.handle(&start_req("a", &k)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::AlreadyExists);
        assert_eq!(a.backend.starts, 1);
        for i in 1..MAX_VMS {
            a.handle(&start_req(&format!("v{i}"), &k)).expect("fill");
        }
        let e = a.handle(&start_req("over", &k)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::ResourceExhausted);
    }

    /// 未登録 id の stop は NOT_FOUND。期限切れは TIMEOUT で登録は外れる。
    #[test]
    fn task117_2_mvm1_stop_errors() {
        let t = Tmp::new("stoperr");
        let k = t.file("k", b"K");
        let mut a = adapter();
        let e = a.handle(&s(&["stop", "nope"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::NotFound);
        assert_eq!(e.message(), "microVM not found");
        a.handle(&start_req("a", &k)).expect("start");
        a.backend.stop_err = Some(MicrovmErrorCode::DeadlineExceeded);
        let e = a.handle(&s(&["stop", "a"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        assert!(a.is_empty());
        assert_eq!(a.detached(), 1);
    }

    /// 停止期限切れの VM は終了未確認のため MAX_VMS の枠を空けない（資源上限。REPAIR-5）。
    #[test]
    fn task117_2_mvm1_timed_out_stop_keeps_slot() {
        let t = Tmp::new("detached");
        let k = t.file("k", b"K");
        let mut a = adapter();
        a.backend.stop_err = Some(MicrovmErrorCode::DeadlineExceeded);
        for i in 0..MAX_VMS {
            a.handle(&start_req(&format!("v{i}"), &k)).expect("start");
            let e = a.handle(&s(&["stop", &format!("v{i}")])).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::Timeout);
        }
        assert!(a.is_empty());
        assert_eq!(a.detached(), MAX_VMS);
        let e = a.handle(&start_req("over", &k)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::ResourceExhausted);
        assert_eq!(a.backend.starts, MAX_VMS);
    }

    /// 切り離した VM の終了を観測したら枠が返り、同じ枠で新しい start が通る。返る枠は観測した分だけ（#3745・PLUG-1・REPAIR-5）。
    #[test]
    fn mvm1_repair5_3745_detached_slot_returned_after_exit_observed() {
        let t = Tmp::new("reclaim");
        let k = t.file("k", b"K");
        let mut a = adapter();
        a.backend.stop_err = Some(MicrovmErrorCode::DeadlineExceeded);
        for i in 0..MAX_VMS {
            a.handle(&start_req(&format!("v{i}"), &k)).expect("start");
            a.handle(&s(&["stop", &format!("v{i}")])).unwrap_err();
        }
        assert_eq!(a.detached(), MAX_VMS);
        let e = a.handle(&start_req("over", &k)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::ResourceExhausted);
        assert_eq!(a.backend.starts, MAX_VMS);
        a.backend.exited.insert(1);
        a.handle(&start_req("new", &k)).expect("slot returned");
        assert_eq!(a.detached(), MAX_VMS - 1);
        assert_eq!(a.len(), 1);
        assert_eq!(a.backend.starts, MAX_VMS + 1);
        let e = a.handle(&start_req("again", &k)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::ResourceExhausted);
    }

    /// 終了を観測できない間は枠を返さず、MAX_VMS を超える start を拒否し続ける（fail-closed。#3745）。
    #[test]
    fn mvm1_repair5_3745_pending_detached_keeps_slot() {
        let t = Tmp::new("pending");
        let k = t.file("k", b"K");
        let mut a = adapter();
        a.backend.stop_err = Some(MicrovmErrorCode::DeadlineExceeded);
        for i in 0..MAX_VMS {
            a.handle(&start_req(&format!("v{i}"), &k)).expect("start");
            a.handle(&s(&["stop", &format!("v{i}")])).unwrap_err();
        }
        for _ in 0..2 {
            let e = a.handle(&start_req("over", &k)).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::ResourceExhausted);
            assert_eq!(a.detached(), MAX_VMS);
            assert_eq!(a.backend.starts, MAX_VMS);
        }
    }

    /// `reclaim_detached` は観測できた件数を返し、冪等（#3745）。
    #[test]
    fn mvm1_3745_reclaim_detached_returns_count() {
        let t = Tmp::new("reclaimcount");
        let k = t.file("k", b"K");
        let mut a = adapter();
        a.backend.stop_err = Some(MicrovmErrorCode::DeadlineExceeded);
        for i in 0..3 {
            a.handle(&start_req(&format!("v{i}"), &k)).expect("start");
            a.handle(&s(&["stop", &format!("v{i}")])).unwrap_err();
        }
        assert_eq!(a.reclaim_detached(), 0);
        a.backend.exited.extend([1, 2]);
        assert_eq!(a.reclaim_detached(), 2);
        assert_eq!(a.detached(), 1);
        assert_eq!(a.reclaim_detached(), 0);
    }

    /// `stop_all` の予算内の経路と予算切れの経路の両方で、期限切れの VM の観測ハンドルを残す（#3745）。
    #[test]
    fn mvm1_3745_stop_all_timeout_tracks_watch() {
        let t = Tmp::new("stopall3745");
        let k = t.file("k", b"K");
        for budget in [Duration::from_secs(10), Duration::ZERO] {
            let mut a = adapter();
            for i in 0..2 {
                a.handle(&start_req(&format!("v{i}"), &k)).expect("start");
            }
            a.backend.stop_err = Some(MicrovmErrorCode::DeadlineExceeded);
            a.stop_all(budget);
            assert_eq!(a.detached(), 2);
            a.backend.exited.extend([1, 2]);
            assert_eq!(a.reclaim_detached(), 2);
            assert_eq!(a.detached(), 0);
        }
    }

    /// 期限切れ以外の停止エラーは切り離しにならない（#3745）。
    #[test]
    fn mvm1_3745_non_timeout_stop_error_not_detached() {
        let t = Tmp::new("nontimeout");
        let k = t.file("k", b"K");
        let mut a = adapter();
        a.handle(&start_req("a", &k)).expect("start");
        a.backend.stop_err = Some(MicrovmErrorCode::Internal);
        a.handle(&s(&["stop", "a"])).unwrap_err();
        assert_eq!(a.detached(), 0);
    }

    /// `VcpuExitState` の写像。`Exited(StopReport)` は `StopReport` が `#[non_exhaustive]` で crate 外から組めないため扱えない
    /// （microvm 側の #3744 の試験が `Exited` の記録を照合済み）。
    #[cfg(target_os = "linux")]
    #[test]
    fn mvm1_3745_classify_exit_state() {
        use fandhe_container_microvm::microvm::VcpuExitState;
        assert_eq!(
            classify_exit_state(VcpuExitState::Running),
            DetachedState::Pending
        );
        assert_eq!(
            classify_exit_state(VcpuExitState::ExitedAbnormally),
            DetachedState::Released
        );
    }

    /// backend の start 失敗は登録されず、code が写される。
    #[test]
    fn task117_2_mvm1_start_failure_not_registered() {
        let t = Tmp::new("startfail");
        let k = t.file("k", b"K");
        let mut a = adapter();
        a.backend.start_err = Some(MicrovmErrorCode::Unimplemented);
        let e = a.handle(&start_req("a", &k)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unimplemented);
        assert!(a.is_empty());
    }

    /// 入力検証の境界。エラー文言に入力値が含まれない。
    #[test]
    fn task117_2_plug1_validation_boundaries() {
        let t = Tmp::new("valid");
        let k = t.file("k", b"K");
        let mut a = adapter();
        let bad =
            |a: &mut MicrovmRuntimeAdapter<FakeBackend>, b: Vec<String>, code: PluginErrorCode| {
                let e = a.handle(&b).unwrap_err();
                assert_eq!(e.code(), code, "{b:?}");
                assert!(!e.message().contains("SECRETARG"), "{}", e.message());
            };
        bad(&mut a, s(&["start", "a"]), PluginErrorCode::InvalidArgument);
        bad(&mut a, s(&["stop"]), PluginErrorCode::InvalidArgument);
        bad(
            &mut a,
            s(&["stop", "a", "b"]),
            PluginErrorCode::InvalidArgument,
        );
        let long = "a".repeat(256);
        for id in [".", "..", "", long.as_str(), "SECRETARG/x", "a b"] {
            bad(&mut a, start_req(id, &k), PluginErrorCode::InvalidArgument);
        }
        let rel = |p: &str| s(&["start", "a", p, "", "", "1", "64"]);
        for p in ["SECRETARG", "/a/../etc/x", "/a/./b", "/a\0b", ""] {
            bad(&mut a, rel(p), PluginErrorCode::InvalidArgument);
        }
        let num = |v: &str, m: &str| s(&["start", "a", &k, "", "", v, m]);
        for (v, m) in [
            ("0", "64"),
            ("+1", "64"),
            ("x", "64"),
            ("1", "0"),
            ("1", "SECRETARG"),
            ("1", "18446744073709551615"),
            ("1", ""),
        ] {
            bad(&mut a, num(v, m), PluginErrorCode::InvalidArgument);
        }
        bad(&mut a, num("2", "64"), PluginErrorCode::Unimplemented);
        let big = "x".repeat(CMDLINE_CAPACITY as usize);
        bad(
            &mut a,
            s(&["start", "a", &k, "", &big, "1", "64"]),
            PluginErrorCode::InvalidArgument,
        );
        assert_eq!(a.backend.starts, 0);
    }

    /// read_image: 存在しない・ディレクトリ・symlink・上限超過・正常。
    #[test]
    fn task117_2_plug1_read_image_cases() {
        let t = Tmp::new("img");
        let f = t.file("ok", b"abcd");
        let p = Path::new(&f);
        assert_eq!(
            read_image(
                &ReadLimiter::new(MAX_INFLIGHT_READS),
                p,
                4,
                ImageKind::Kernel
            )
            .expect("ok"),
            b"abcd".to_vec()
        );
        let e = read_image(
            &ReadLimiter::new(MAX_INFLIGHT_READS),
            p,
            3,
            ImageKind::Kernel,
        )
        .unwrap_err();
        assert_eq!(
            (e.code(), e.message()),
            (PluginErrorCode::InvalidArgument, "image too large")
        );
        let e = read_image(
            &ReadLimiter::new(MAX_INFLIGHT_READS),
            &t.0.join("missing"),
            4,
            ImageKind::Kernel,
        )
        .unwrap_err();
        assert_eq!(
            (e.code(), e.message()),
            (PluginErrorCode::NotFound, "kernel image not found")
        );
        let e = read_image(
            &ReadLimiter::new(MAX_INFLIGHT_READS),
            &t.0.join("missing"),
            4,
            ImageKind::Initrd,
        )
        .unwrap_err();
        assert_eq!(e.message(), "initrd image not found");
        let e = read_image(
            &ReadLimiter::new(MAX_INFLIGHT_READS),
            &t.0,
            4,
            ImageKind::Kernel,
        )
        .unwrap_err();
        assert_eq!(
            (e.code(), e.message()),
            (
                PluginErrorCode::InvalidArgument,
                "image must be a regular file"
            )
        );
        #[cfg(unix)]
        {
            let link = t.0.join("link");
            std::os::unix::fs::symlink(&f, &link).expect("symlink");
            let e = read_image(
                &ReadLimiter::new(MAX_INFLIGHT_READS),
                &link,
                4,
                ImageKind::Kernel,
            )
            .unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        }
    }

    /// SEC-1・PLUG-1（#3748）: 祖先が symlink のイメージパスは `INVALID_ARGUMENT` で拒否し、応答にパスを含めない。
    #[cfg(unix)]
    #[test]
    fn sec1_3748_start_rejects_symlinked_ancestor_without_path() {
        let t = Tmp::new("anc");
        std::fs::create_dir(t.0.join("real")).expect("mkdir");
        let real = t.file("real/kernel", b"K");
        std::os::unix::fs::symlink(t.0.join("real"), t.0.join("link")).expect("symlink");
        let via_link = format!("{}/link/kernel", t.0.display());
        let mut a = adapter();
        let e = a.handle(&start_req("a", &via_link)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(e.message(), MSG_BAD_ANCESTOR);
        assert!(!e.message().contains(&*t.0.to_string_lossy()));
        assert!(!e.message().contains("link/kernel"));
        assert_eq!(a.backend.starts, 0);
        assert!(a.is_empty());
        // 陽性対照: 同じ実体を実パスで渡せば従来どおり起動する。
        assert_eq!(
            a.handle(&start_req("a", &real)).expect("ok"),
            s(&["running"])
        );
        assert_eq!(a.backend.starts, 1);
    }

    /// SEC-1（#3748）: initrd だけ祖先が symlink でも拒否し、VM は起動しない。
    #[cfg(unix)]
    #[test]
    fn sec1_3748_start_rejects_symlinked_ancestor_in_initrd() {
        let t = Tmp::new("ancinit");
        std::fs::create_dir(t.0.join("real")).expect("mkdir");
        t.file("real/initrd", b"I");
        let k = t.file("kernel", b"K");
        std::os::unix::fs::symlink(t.0.join("real"), t.0.join("link")).expect("symlink");
        let via_link = format!("{}/link/initrd", t.0.display());
        let mut a = adapter();
        let req = s(&["start", "a", &k, &via_link, "console=ttyS0", "1", "64"]);
        let e = a.handle(&req).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(e.message(), MSG_BAD_ANCESTOR);
        assert_eq!(a.backend.starts, 0);
    }

    /// ERR-1・SEC-1（#3890）: lstat の失敗の写像（実 errno 経由で `ErrorKind` への写しも確かめる）。
    #[cfg(all(unix, any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn err1_sec1_3890_lstat_error_mapping() {
        let eloop = if cfg!(target_os = "linux") { 40 } else { 62 };
        let m = |errno: i32, p: &str, k: ImageKind| {
            let e = map_lstat_error(std::io::Error::from_raw_os_error(errno), Path::new(p), k);
            (e.code(), e.message().to_string())
        };
        let k = ImageKind::Kernel;
        let inv = PluginErrorCode::InvalidArgument;
        assert_eq!(m(20, "/a/f/", k), (inv, MSG_NOT_REGULAR.to_string()));
        assert_eq!(m(20, "/a/f/x", k), (inv, MSG_BAD_ANCESTOR.to_string()));
        assert_eq!(m(eloop, "/a/b/k", k), (inv, MSG_BAD_ANCESTOR.to_string()));
        assert_eq!(m(eloop, "/a/b/k/", k), (inv, MSG_BAD_ANCESTOR.to_string()));
        assert_eq!(
            m(2, "/x", k),
            (
                PluginErrorCode::NotFound,
                "kernel image not found".to_string()
            )
        );
        assert_eq!(
            m(2, "/x", ImageKind::Initrd),
            (
                PluginErrorCode::NotFound,
                "initrd image not found".to_string()
            )
        );
        for errno in [13, 1] {
            assert_eq!(
                m(errno, "/x", k),
                (
                    PluginErrorCode::PermissionDenied,
                    "permission denied reading image".to_string()
                )
            );
        }
        for errno in [24, 5] {
            assert_eq!(
                m(errno, "/x", k),
                (PluginErrorCode::Internal, MSG_READ_FAILED.to_string())
            );
        }
    }

    /// ERR-1・SEC-1（#3890）: 通常ファイルに末尾 `/` を付けると `MSG_NOT_REGULAR`（パスは載らない）。
    #[cfg(unix)]
    #[test]
    fn err1_sec1_3890_read_image_trailing_slash_on_file_is_not_regular() {
        let t = Tmp::new("tslash");
        let f = t.file("kernel", b"K");
        let e = read_image(
            &ReadLimiter::new(MAX_INFLIGHT_READS),
            Path::new(&format!("{f}/")),
            4,
            ImageKind::Kernel,
        )
        .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(e.message(), MSG_NOT_REGULAR);
        assert!(!e.message().contains(&*t.0.to_string_lossy()));
    }

    /// ERR-1・SEC-1（#3890）: start の RPC 境界でも末尾 `/` は `MSG_NOT_REGULAR` で拒否し VM を起動しない。
    #[cfg(unix)]
    #[test]
    fn err1_sec1_3890_start_rejects_trailing_slash_without_path() {
        let t = Tmp::new("tslashstart");
        let f = t.file("kernel", b"K");
        let mut a = adapter();
        let e = a.handle(&start_req("a", &format!("{f}/"))).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(e.message(), MSG_NOT_REGULAR);
        assert!(!e.message().contains(&*t.0.to_string_lossy()));
        assert_eq!(a.backend.starts, 0);
        assert!(a.is_empty());
        // 陽性対照: 末尾 `/` なしなら起動する。
        assert_eq!(a.handle(&start_req("a", &f)).expect("ok"), s(&["running"]));
        assert_eq!(a.backend.starts, 1);
    }

    /// ERR-1・SEC-1（#3890）: 祖先が通常ファイルのパスは `MSG_BAD_ANCESTOR`。
    #[cfg(unix)]
    #[test]
    fn err1_sec1_3890_read_image_regular_file_ancestor_is_bad_ancestor() {
        let t = Tmp::new("fileanc");
        let f = t.file("file", b"K");
        for kind in [ImageKind::Kernel, ImageKind::Initrd] {
            let e = read_image(
                &ReadLimiter::new(MAX_INFLIGHT_READS),
                Path::new(&format!("{f}/x")),
                4,
                kind,
            )
            .unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
            assert_eq!(e.message(), MSG_BAD_ANCESTOR);
            assert!(!e.message().contains(&*t.0.to_string_lossy()));
        }
    }

    /// ERR-1・SEC-1（#3890）: 祖先の symlink がループするパスは `MSG_BAD_ANCESTOR`。
    #[cfg(unix)]
    #[test]
    fn err1_sec1_3890_read_image_symlink_loop_ancestor_is_bad_ancestor() {
        let t = Tmp::new("loopanc");
        std::os::unix::fs::symlink(t.0.join("b"), t.0.join("a")).expect("symlink");
        std::os::unix::fs::symlink(t.0.join("a"), t.0.join("b")).expect("symlink");
        let p = t.0.join("a").join("k");
        let e = read_image(
            &ReadLimiter::new(MAX_INFLIGHT_READS),
            &p,
            4,
            ImageKind::Kernel,
        )
        .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(e.message(), MSG_BAD_ANCESTOR);
        assert!(!e.message().contains(&*t.0.to_string_lossy()));
    }

    /// to_plugin_error: 全分類の写像（DeadlineExceeded は TIMEOUT）。
    #[test]
    fn task117_2_mvm1_error_mapping_covers_all_codes() {
        for c in MicrovmErrorCode::ALL {
            let got = to_plugin_error(&MicrovmError::new(c, "m")).code();
            let want = match c {
                MicrovmErrorCode::DeadlineExceeded => PluginErrorCode::Timeout,
                other => PluginErrorCode::from_code_str(other.as_str()).expect("same name"),
            };
            assert_eq!(got, want, "{c:?}");
        }
        assert_eq!(
            to_plugin_error(&MicrovmError::new(MicrovmErrorCode::DeadlineExceeded, "m"))
                .code()
                .as_str(),
            "TIMEOUT"
        );
    }

    /// stop_all: 予算内で全台停止、予算 0 では remaining に数える。
    #[test]
    fn task117_2_mvm1_stop_all() {
        let t = Tmp::new("stopall");
        let k = t.file("k", b"K");
        let mut a = adapter();
        a.handle(&start_req("a", &k)).expect("a");
        a.handle(&start_req("b", &k)).expect("b");
        let r = a.stop_all(Duration::ZERO);
        assert_eq!(
            r,
            StopAllReport {
                stopped: 0,
                failed: 0,
                remaining: 2
            }
        );
        // 予算切れの VM も登録簿から外して停止要求を出す（Drop の待ちを残さない）。
        assert!(a.is_empty());
        let r = a.stop_all(STOP_ALL_BUDGET);
        assert_eq!(
            r,
            StopAllReport {
                stopped: 0,
                failed: 0,
                remaining: 0
            }
        );
    }

    /// Linux でも macOS aarch64 でもない OS: start は UNIMPLEMENTED。
    #[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
    #[test]
    fn task117_2_mvm1_unsupported_backend_start_is_unimplemented() {
        let t = Tmp::new("unsupported");
        let k = t.file("k", b"K");
        let mut a = MicrovmRuntimeAdapter::new(default_backend());
        let e = a.handle(&start_req("a", &k)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unimplemented);
    }

    /// 上限 1・arm64 の cmdline 上限（2047）を持つ試験用 backend（`HvfBackend` と同じ定数。実機に触れない。TASK-192.18・#3800）。
    #[derive(Default)]
    struct SingleVmArm64(FakeBackend);

    impl MicrovmBackend for SingleVmArm64 {
        const VM_LIMIT: usize = 1;
        const CMDLINE_MAX_BYTES: usize = 2047;
        type Running = u32;
        type ExitWatch = u32;
        fn start(&mut self, spec: BootSpec) -> Result<u32, MicrovmError> {
            self.0.start(spec)
        }
        fn stop(&mut self, vm: u32, d: Duration) -> Result<&'static str, MicrovmError> {
            self.0.stop(vm, d)
        }
        fn exit_watch(&self, vm: &u32) -> u32 {
            self.0.exit_watch(vm)
        }
        fn exit_state(&self, w: &u32) -> DetachedState {
            self.0.exit_state(w)
        }
    }

    /// MVM-5・PLUG-1（#3800）: 上限 1 の backend は 2 台目を `too many microVMs` で拒否し、stop すれば再び start できる。
    /// TIMEOUT で切り離した VM が `Pending` の間は枠が返らず、start は拒否され続ける。
    #[test]
    fn mvm5_3800_single_vm_backend_rejects_second_start() {
        let t = Tmp::new("single3800");
        let k = t.file("k", b"K");
        let mut a = MicrovmRuntimeAdapter::new(SingleVmArm64::default());
        assert_eq!(a.handle(&start_req("a", &k)).expect("1st"), s(&["running"]));
        let e = a.handle(&start_req("b", &k)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "too many microVMs");
        assert_eq!(a.backend.0.starts, 1);
        assert_eq!(
            a.handle(&s(&["stop", "a"])).expect("stop"),
            s(&["stopped", "requested"])
        );
        assert_eq!(
            a.handle(&start_req("b", &k)).expect("again"),
            s(&["running"])
        );
        // TIMEOUT: 切り離され、Pending の間は枠が返らない。
        a.backend.0.stop_err = Some(MicrovmErrorCode::DeadlineExceeded);
        let e = a.handle(&s(&["stop", "b"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        assert_eq!(a.detached(), 1);
        for _ in 0..2 {
            let e = a.handle(&start_req("c", &k)).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::ResourceExhausted);
            assert_eq!(e.message(), "too many microVMs");
        }
        assert_eq!(a.backend.0.starts, 2);
    }

    /// MVM-5・MVM-1（#3800）: cmdline の上限は backend ごと。既定（x86）は 4095 まで、arm64 の backend は 2047 まで。
    /// 拒否はイメージを読む前（存在しないパスでも `invalid kernel cmdline`）で、backend の start は呼ばれない。
    #[test]
    fn mvm5_3800_cmdline_limit_is_per_backend() {
        let t = Tmp::new("cmdline3800");
        let k = t.file("k", b"K");
        let req =
            |len: usize, kernel: &str| s(&["start", "a", kernel, "", &"x".repeat(len), "1", "64"]);
        let mut x86 = adapter();
        let e = x86.handle(&req(4096, &k)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(e.message(), "invalid kernel cmdline");
        assert_eq!(x86.handle(&req(4095, &k)).expect("4095"), s(&["running"]));

        let mut arm = MicrovmRuntimeAdapter::new(SingleVmArm64::default());
        let e = arm.handle(&req(2048, "/nonexistent/kernel")).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(e.message(), "invalid kernel cmdline");
        assert_eq!(arm.backend.0.starts, 0);
        assert_eq!(arm.handle(&req(2047, &k)).expect("2047"), s(&["running"]));
    }

    /// 既定の上限は Linux（KVM）の値のまま（MVM-1。Linux の挙動を変えない回帰）。
    #[test]
    fn mvm5_3800_default_limits_are_kvm_values() {
        assert_eq!(<FakeBackend as MicrovmBackend>::VM_LIMIT, 4);
        assert_eq!(<FakeBackend as MicrovmBackend>::CMDLINE_MAX_BYTES, 4095);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mvm5_3800_kvm_backend_keeps_default_limits() {
        assert_eq!(<KvmBackend as MicrovmBackend>::VM_LIMIT, 4);
        assert_eq!(<KvmBackend as MicrovmBackend>::CMDLINE_MAX_BYTES, 4095);
    }

    /// macOS aarch64: `HvfBackend` の上限・既定 backend・終了観測（`hv_*` を呼ばないので署名なしの既定集合で走る）。
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn mvm5_3800_hvf_backend_limits_and_default() {
        assert_eq!(<HvfBackend as MicrovmBackend>::VM_LIMIT, 1);
        assert_eq!(<HvfBackend as MicrovmBackend>::CMDLINE_MAX_BYTES, 2047);
        assert_eq!(
            std::any::type_name::<DefaultBackend>(),
            std::any::type_name::<HvfBackend>()
        );
        let b = HvfBackend;
        assert_eq!(b.exit_state(&HvfExitWatch(())), DetachedState::Pending);
    }
}
