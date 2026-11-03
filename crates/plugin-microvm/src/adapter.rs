//! 要求ハンドラ（`frame_loop::RequestHandler` の実装）。TASK-117.1・#710、TASK-117.2・#711。PLUG-1・MVM-1・REPAIR-3。
//!
//! 呼び出し元: `main.rs` が `frame_loop::serve_until` へ渡す。core 側 proxy（#1869 の設計）が送る要求の先頭要素
//! （操作名）で分岐する暫定契約（本体 `Vec<String>`。型つき本体への置換は #1869 の設計・承認と実装 issue の起票は #2232）。
//! microVM 本体の操作は [`MicrovmBackend`] 越しに `fandhe-container-microvm` へ委譲する（Linux は `KvmBackend`、他 OS は
//! 常に `UNIMPLEMENTED` の `UnsupportedBackend`）。
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
//! 同時 VM 数は [`MAX_VMS`] で抑える。停止は [`STOP_DEADLINE`]（RPC 期限より短い。REPAIR-5）。
//!
//! # 注意・残余（REPAIR-3）
//! - plugin プロセスは SIGUSR2 を使わない（microvm の `run_once` がプロセス全体の handler を入れる）。
//! - stop が `TIMEOUT` の後、vCPU スレッドが自力で終わるまで資源（ゲスト RAM・fd）が残る。backend から終了を観測できないため、
//!   期限切れで切り離した VM は [`MAX_VMS`] の計数に残し続け（`detached`）、枠を空けない（資源上限。REPAIR-5）。枠が尽きたら plugin の再起動で回復する。
//! - 応答しないファイルシステム上のイメージ読み込みは期限で打ち切れない。祖先ディレクトリの symlink は検査しない（最終要素のみ）。
//! - 実 Linux カーネルの起動完走は保証しない（CPUID・MSR・LAPIC・virtio-net rx 等は microvm 側の未実装）。実 KVM の通しは `tests/e2e.rs` の `#[ignore]` 試験（TASK-117.4・#713）。

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

/// 同時に動かす VM 数の上限（資源枯渇対策）。
pub const MAX_VMS: usize = 4;
/// RPC 期限から差し引く応答の余裕。
pub const RESPONSE_MARGIN: Duration = Duration::from_secs(2);
/// 1 台の停止の期限。RPC 期限から `RESPONSE_MARGIN` を引いた値（8 秒）未満かつ microvm の停止期限上限以下。
pub const STOP_DEADLINE: Duration = Duration::from_secs(5);
/// イメージ 1 件の読み取りの期限（kernel と initrd の 2 件で RPC 期限 - 余裕に収める。REPAIR-5）。
pub const IMAGE_READ_DEADLINE: Duration = Duration::from_secs(3);
/// 終了時の一括停止の合計予算。
pub const STOP_ALL_BUDGET: Duration = Duration::from_secs(4);

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

/// 起動に必要な検証済みの値（読み込み済みイメージを持ち、パスは含まない）。
#[derive(Debug)]
pub struct BootSpec {
    /// vCPU 数。
    pub vcpus: u32,
    /// ゲスト RAM のバイト数。
    pub mem_bytes: u64,
    /// bzImage。
    pub kernel: Vec<u8>,
    /// initrd（無ければ `None`）。
    pub initrd: Option<Vec<u8>>,
    /// ユーザー指定の cmdline。
    pub cmdline: String,
}

/// microVM 本体への委譲境界。3 OS でビルドでき、KVM なしの試験で差し替えられる。
pub trait MicrovmBackend {
    /// 実行中 VM のハンドル。
    type Running;
    /// 起動する。失敗時は資源が解放済みであること（microvm 側の保証）。
    fn start(&mut self, spec: BootSpec) -> Result<Self::Running, MicrovmError>;
    /// `deadline` 以内に停止し、理由の固定名を返す。`vm` は成否に関わらず消費される。
    fn stop(&mut self, vm: Self::Running, deadline: Duration)
    -> Result<&'static str, MicrovmError>;
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
}

/// 非 Linux の backend。start は常に `UNIMPLEMENTED`（fail-closed）。
#[cfg(not(target_os = "linux"))]
#[derive(Debug, Default)]
pub struct UnsupportedBackend;

/// 到達不能な実行中ハンドル（非 Linux では VM を作れない）。
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub enum NeverRunning {}

#[cfg(not(target_os = "linux"))]
impl MicrovmBackend for UnsupportedBackend {
    type Running = NeverRunning;

    fn start(&mut self, _spec: BootSpec) -> Result<Self::Running, MicrovmError> {
        Err(MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "microVM is only supported on Linux",
        ))
    }

    fn stop(
        &mut self,
        vm: Self::Running,
        _deadline: Duration,
    ) -> Result<&'static str, MicrovmError> {
        match vm {}
    }
}

/// `main.rs` が使う OS 既定の backend 型。
#[cfg(target_os = "linux")]
pub type DefaultBackend = KvmBackend;
/// `main.rs` が使う OS 既定の backend 型。
#[cfg(not(target_os = "linux"))]
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
/// lstat と open の間の差し替えは unix で dev / ino の照合により検出する。祖先ディレクトリの symlink は検査しない（残余）。
///
/// 応答しない FUSE 等で同期 I/O が止まっても RPC ハンドラ全体を止めないよう、実処理は別スレッドで走らせ
/// [`IMAGE_READ_DEADLINE`] で打ち切る（REPAIR-5）。期限切れのスレッドは detach し、I/O の復帰後に自力で終わる。
fn read_image(path: &Path, cap: u64, kind: ImageKind) -> Result<Vec<u8>, PluginError> {
    let slot = ReadSlot::acquire()?;
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
const MAX_INFLIGHT_READS: usize = 8;
static INFLIGHT_READS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 読み込みスレッドの枠。Drop で返す。上限到達時は `RESOURCE_EXHAUSTED`。
struct ReadSlot(&'static std::sync::atomic::AtomicUsize);

impl ReadSlot {
    fn acquire() -> Result<Self, PluginError> {
        Self::acquire_from(&INFLIGHT_READS, MAX_INFLIGHT_READS)
    }

    /// 計数器と上限を指定して枠を取る。上限到達時のメッセージは VM 数の上限（`MSG_LIMIT`）と区別する。
    fn acquire_from(
        counter: &'static std::sync::atomic::AtomicUsize,
        max: usize,
    ) -> Result<Self, PluginError> {
        use std::sync::atomic::Ordering;
        counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max).then_some(n + 1)
            })
            .map(|_| ReadSlot(counter))
            .map_err(|_| perr(PluginErrorCode::ResourceExhausted, MSG_READ_LIMIT))
    }
}

impl Drop for ReadSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// `open` が FIFO 等で止まらないよう付ける `O_NONBLOCK`（Linux 0o4000・macOS 0x4）。通常ファイルの読み取りには影響しない。
#[cfg(target_os = "linux")]
const OPEN_NONBLOCK: i32 = 0o4000;
#[cfg(all(unix, not(target_os = "linux")))]
const OPEN_NONBLOCK: i32 = 0x4;

fn read_image_blocking(path: &Path, cap: u64, kind: ImageKind) -> Result<Vec<u8>, PluginError> {
    let map_io = |e: std::io::Error| match e.kind() {
        std::io::ErrorKind::NotFound => match kind {
            ImageKind::Kernel => perr(PluginErrorCode::NotFound, "kernel image not found"),
            ImageKind::Initrd => perr(PluginErrorCode::NotFound, "initrd image not found"),
        },
        std::io::ErrorKind::PermissionDenied => perr(
            PluginErrorCode::PermissionDenied,
            "permission denied reading image",
        ),
        _ => perr(PluginErrorCode::Internal, MSG_READ_FAILED),
    };
    let lmeta = std::fs::symlink_metadata(path).map_err(map_io)?;
    if !lmeta.file_type().is_file() {
        return Err(invalid(MSG_NOT_REGULAR));
    }
    if lmeta.len() > cap {
        return Err(invalid(MSG_TOO_LARGE));
    }
    let mut oo = std::fs::OpenOptions::new();
    oo.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        oo.custom_flags(OPEN_NONBLOCK);
    }
    let file = oo.open(path).map_err(map_io)?;
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
    /// 停止が期限切れで切り離された（終了未確認の）VM 数。[`MAX_VMS`] の計数に含める。
    detached: usize,
}

impl<B: MicrovmBackend> MicrovmRuntimeAdapter<B> {
    /// backend を指定してアダプタを作る。
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            vms: BTreeMap::new(),
            detached: 0,
        }
    }

    /// 停止期限切れで切り離したまま終了未確認の VM 数。
    pub fn detached(&self) -> usize {
        self.detached
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
                if let Err(e) = self.backend.stop(vm, Duration::from_millis(1)) {
                    self.note_stop_error(&e);
                }
                report.remaining += 1;
                continue;
            }
            match self.backend.stop(vm, left.min(STOP_DEADLINE)) {
                Ok(_) => report.stopped += 1,
                Err(e) => {
                    self.note_stop_error(&e);
                    report.failed += 1;
                }
            }
        }
        report
    }

    /// 停止が期限切れなら VM は切り離されただけで資源が残るため、計数に残す。
    fn note_stop_error(&mut self, e: &MicrovmError) {
        if e.code() == MicrovmErrorCode::DeadlineExceeded {
            self.detached = self.detached.saturating_add(1);
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
        if self.vms.len().saturating_add(self.detached) >= MAX_VMS {
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
        if cmdline.len() as u64 >= CMDLINE_CAPACITY {
            return Err(invalid(MSG_BAD_CMDLINE));
        }
        let kernel_path = validate_path(kernel)?;
        let initrd_path = if initrd.is_empty() {
            None
        } else {
            Some(validate_path(initrd)?)
        };
        let kernel_bytes = read_image(kernel_path, MAX_KERNEL_IMAGE_BYTES, ImageKind::Kernel)?;
        let initrd_bytes = match initrd_path {
            Some(p) => Some(read_image(
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
        let reason = match self.backend.stop(vm, STOP_DEADLINE) {
            Ok(r) => r,
            Err(e) => {
                self.note_stop_error(&e);
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

    /// 画像読み込みの枠が尽きたとき、VM 数上限と区別できる文言で RESOURCE_EXHAUSTED になる（REPAIR-5・MVM-5）。
    #[test]
    fn read_slot_limit_uses_distinct_message() {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let held = ReadSlot::acquire_from(&COUNTER, 1).expect("first slot");
        let e = ReadSlot::acquire_from(&COUNTER, 1).err().expect("limit");
        assert_eq!(e.code(), PluginErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "too many in-flight image reads");
        assert_ne!(e.message(), MSG_LIMIT);
        drop(held);
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// KVM に触れない試験用 backend。
    #[derive(Default)]
    struct FakeBackend {
        starts: usize,
        start_err: Option<MicrovmErrorCode>,
        stop_err: Option<MicrovmErrorCode>,
        reason: &'static str,
    }

    impl MicrovmBackend for FakeBackend {
        type Running = u32;
        fn start(&mut self, _spec: BootSpec) -> Result<u32, MicrovmError> {
            self.starts += 1;
            match self.start_err {
                Some(c) => Err(MicrovmError::new(c, "fake")),
                None => Ok(7),
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
            Self(p)
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
            read_image(p, 4, ImageKind::Kernel).expect("ok"),
            b"abcd".to_vec()
        );
        let e = read_image(p, 3, ImageKind::Kernel).unwrap_err();
        assert_eq!(
            (e.code(), e.message()),
            (PluginErrorCode::InvalidArgument, "image too large")
        );
        let e = read_image(&t.0.join("missing"), 4, ImageKind::Kernel).unwrap_err();
        assert_eq!(
            (e.code(), e.message()),
            (PluginErrorCode::NotFound, "kernel image not found")
        );
        let e = read_image(&t.0.join("missing"), 4, ImageKind::Initrd).unwrap_err();
        assert_eq!(e.message(), "initrd image not found");
        let e = read_image(&t.0, 4, ImageKind::Kernel).unwrap_err();
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
            let e = read_image(&link, 4, ImageKind::Kernel).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        }
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

    /// 非 Linux: start は UNIMPLEMENTED。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn task117_2_mvm1_unsupported_backend_start_is_unimplemented() {
        let t = Tmp::new("unsupported");
        let k = t.file("k", b"K");
        let mut a = MicrovmRuntimeAdapter::new(default_backend());
        let e = a.handle(&start_req("a", &k)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unimplemented);
    }
}
