//! `/dev/kvm` のオープンと VM fd の作成（TASK-74.1.1・MVM-1・MVM-4。Linux のみ）。
//!
//! 将来の起動フロー（TASK-75）・`fandhe-container-plugin-microvm`（TASK-117）から呼ばれる入口。
//! [`KvmDevice`] が `/dev/kvm` を `O_RDWR | O_CLOEXEC` で開き、API 版数 12 を確認してから
//! [`KvmDevice::create_vm`] で [`VmFd`] を返し、[`VmFd::create_vcpu`] で [`VcpuFd`] を返す（TASK-74.1.2）。
//! TASK-74.4.1 で [`VcpuFd::run_once`]（`KVM_RUN` を 1 回発行して VM exit を [`VcpuExit`] で返す）と、
//! 実機で実行を示す自己診断 [`KvmDevice::probe_guest_execution`] を足した。
//! TASK-74.4.2（#883）で exit のデバイスへの振り分けと IN・MMIO read の応答の書き戻し（[`VcpuFd::handle_exit`]。
//! 振り分け先は `crate::dispatch`）と、実機で確かめる自己診断 [`KvmDevice::probe_exit_dispatch`] を足した。
//! ゲストメモリ（アクセス型は TASK-74.1 配下の後続 sub-issue、mmap と KVM 登録は TASK-75.1。docs/design/microvm-memory-ownership.md）・
//! レジスタ設定・vCPU の外部からの停止要求（一時停止・
//! 終了通知。TASK-75）は未実装で、後続の TASK-74・TASK-75 が [`VmFd`]・[`VcpuFd`]（いずれも `AsFd`）を使って足す（REPAIR-3）。
//! `run_once` は期限つき（`immediate_exit` とシグナルで中断し `DeadlineExceeded`。REPAIR-5）で、結果と所要時間を
//! [`RunStats`]・[`RunObserver`] へ残す（REPAIR-4）。
//! 失敗は panic せず [`MicrovmError`]（ERR-1）で返す。`unsafe` は `crate::sys` に閉じる。
//!
//! # アーキテクチャ別の vCPU 作成
//! - x86_64: `KVM_CREATE_VCPU` だけで vCPU fd が使える。レジスタ設定は TASK-74.4 / TASK-75
//! - aarch64: `KVM_CREATE_VCPU` の後に VM fd へ `KVM_ARM_PREFERRED_TARGET`、vCPU fd へ `KVM_ARM_VCPU_INIT`
//!   （features はすべて 0）を発行して初期化済みの vCPU を返す。未初期化だと `KVM_RUN` が ENOEXEC で失敗する。
//!   features（PSCI 等）の選択は TASK-75 で再検討する。aarch64 はネイティブ CI が無く型検査のみで実行は未検証
//!
//! aarch64 の machine type（IPA サイズ）は既定の 0 を使う。指定は TASK-75 で再検討する。
//! [`KvmDevice`]・[`VmFd`]・[`VcpuFd`] は `OwnedFd` を持つため `Send` / `Sync`。

#![cfg(target_os = "linux")]

use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::dispatch::{DispatchOutcome, ExitDispatcher};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::exit::{self, VcpuExit};
use crate::sys::{self, SysError};

/// 本番で開くデバイスパス（固定リテラル。外部入力は届かない）。
const KVM_PATH: &str = "/dev/kvm";

// errno（Linux 共通。x86_64・aarch64 で同値）。`io::ErrorKind` で分類できないものだけ使う。
const EPERM: i32 = 1;
const ENOMEM: i32 = 12;
const EEXIST: i32 = 17;
const ENOEXEC: i32 = 8;
const EAGAIN: i32 = 11;
const EINTR: i32 = 4;
const EINVAL: i32 = 22;
const EACCES: i32 = 13;
const ENFILE: i32 = 23;
const EMFILE: i32 = 24;
const ENOTTY: i32 = 25;

/// 開いた `/dev/kvm`。
#[derive(Debug)]
pub struct KvmDevice {
    fd: OwnedFd,
}

/// `KVM_CREATE_VM` で得た VM fd。drop で close される。
#[derive(Debug)]
pub struct VmFd {
    fd: OwnedFd,
    /// `KVM_GET_VCPU_MMAP_SIZE` の検証済みの値（`create_vcpu` の `kvm_run` の mmap に使う）。
    vcpu_mmap_size: usize,
}

/// `KVM_CREATE_VCPU` で得た vCPU fd と、その `kvm_run` 領域の mmap。drop で munmap・close される。
#[derive(Debug)]
pub struct VcpuFd {
    // フィールドの宣言順 = drop 順。mmap（run）を fd より先に解く。
    run: sys::KvmRunMap,
    fd: OwnedFd,
    id: u32,
    stats: RunStats,
    observer: Option<Arc<dyn RunObserver>>,
}

/// `KVM_RUN` 1 回の結果の分類（計装用。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// VM exit で戻った。値は exit の種別名（`io` / `mmio` / `hlt` 等）。
    Exit(&'static str),
    /// シグナル等で中断された（EINTR / EAGAIN）。
    Interrupted,
    /// 期限を超えて `immediate_exit` とシグナルで中断した（REPAIR-5）。
    DeadlineExceeded,
    /// ioctl または復号の失敗。
    Error(MicrovmErrorCode),
}

/// `KVM_RUN` 1 回の記録（結果と所要時間。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunRecord {
    /// 実行した vCPU の id。
    pub vcpu_id: u32,
    /// 結果。
    pub outcome: RunOutcome,
    /// `KVM_RUN` の発行から戻るまでの時間。
    pub elapsed: Duration,
}

/// 実行結果の記録器。呼び出し側（将来の plugin-microvm・TASK-117 等）が構造化ログやメトリクスへ接続する。
/// `record` は `KVM_RUN` が戻った直後に vCPU スレッドから同期で呼ばれるため、ブロックしないこと。
pub trait RunObserver: Send + Sync + std::fmt::Debug {
    /// 1 回の `KVM_RUN` の記録を受け取る。
    fn record(&self, record: &RunRecord);
}

/// [`VcpuFd`] ごとの累積の実行統計（観測器が無くても取れる。REPAIR-4）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunStats {
    /// 発行回数。
    pub runs: u64,
    /// VM exit で戻った回数。
    pub exits: u64,
    /// 中断（EINTR / EAGAIN）の回数。
    pub interrupted: u64,
    /// 期限超過の回数。
    pub deadline_exceeded: u64,
    /// 失敗の回数。
    pub errors: u64,
    /// 所要時間の合計。
    pub total_elapsed: Duration,
}

fn exit_kind(e: &VcpuExit) -> &'static str {
    match e {
        VcpuExit::Io { .. } => "io",
        VcpuExit::Mmio { .. } => "mmio",
        VcpuExit::Hlt => "hlt",
        VcpuExit::Shutdown => "shutdown",
        VcpuExit::FailEntry { .. } => "fail_entry",
        VcpuExit::InternalError { .. } => "internal_error",
        VcpuExit::Interrupted => "interrupted",
        VcpuExit::Other { .. } => "other",
    }
}

/// 期限監視スレッドが超過後に `kick`（シグナル）を繰り返す間隔。
const KICK_INTERVAL: Duration = Duration::from_millis(10);
/// `run_once` の期限の上限（異常な値で実質無期限になるのを防ぐ）。
pub const RUN_DEADLINE_MAX: Duration = Duration::from_secs(3600);

/// [`KvmDevice::probe_guest_execution`] の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestExecutionProbe {
    /// 観測した VM exit（`Interrupted` を除く、起きた順）。期待は `[Io{Out, 0x10, 1, 1, [0x42]}, Hlt]`。
    pub exits: Vec<VcpuExit>,
    /// `KVM_RUN` が中断（EINTR / EAGAIN）で戻って再実行した回数。
    pub interrupted: u32,
}

/// [`KvmDevice::probe_exit_dispatch`] の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitDispatchProbe {
    /// 観測した VM exit（`Interrupted` を除く、起きた順）。
    pub exits: Vec<VcpuExit>,
    /// 記録用ポートデバイス（ポート 0x11 から）へ書かれた `(基底からのオフセット, 値)`。IN・MMIO read の
    /// 応答がゲストへ届いた証拠（ゲストが受け取った値をそのまま OUT する）。
    pub port_writes: Vec<(u16, u8)>,
}

/// [`KvmDevice::probe_deadline_interrupt`] の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadlineProbe {
    /// vCPU の累積統計。
    pub stats: RunStats,
    /// 各 `run_once` の記録（起きた順）。
    pub records: Vec<RunRecord>,
    /// 診断中は呼び出しスレッドで `SIGUSR2` をブロックしており、戻った後にブロック状態が復元されていたか。
    pub kick_mask_restored: bool,
}

#[cfg(target_arch = "x86_64")]
#[derive(Debug, Default)]
struct CollectingObserver(std::sync::Mutex<Vec<RunRecord>>);

#[cfg(target_arch = "x86_64")]
impl RunObserver for CollectingObserver {
    fn record(&self, record: &RunRecord) {
        if let Ok(mut v) = self.0.lock() {
            v.push(*record);
        }
    }
}

/// 自己診断の `KVM_RUN` の最大発行回数（`Interrupted` の再実行を含む）。
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const PROBE_MAX_RUNS: usize = 8;

/// 自己診断の `KVM_RUN` 1 回の期限（超過は `DeadlineExceeded` で失敗。REPAIR-5）。
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const PROBE_RUN_DEADLINE: Duration = Duration::from_secs(5);

/// `KVM_GET_VCPU_MMAP_SIZE` の上限（外部入力として検証する。実機は 12 KiB 程度）。
const VCPU_MMAP_MAX: usize = 1 << 20;

fn validate_mmap_size(n: usize) -> Result<usize, MicrovmError> {
    if !(exit::RUN_MIN_LEN..=VCPU_MMAP_MAX).contains(&n) || !n.is_multiple_of(sys::GUEST_PAGE_SIZE)
    {
        return Err(MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            format!("unexpected KVM vCPU mmap size {n}"),
        ));
    }
    Ok(n)
}

/// `KVM_RUN` の errno の分類。EINTR / EAGAIN は正常系の [`VcpuExit::Interrupted`]。
fn classify_run_error(e: SysError) -> Result<VcpuExit, MicrovmError> {
    match e {
        SysError::Unsupported => Err(MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "KVM is not supported on this architecture",
        )),
        SysError::Os(EINTR) | SysError::Os(EAGAIN) => Ok(VcpuExit::Interrupted),
        SysError::Os(ENOTTY) => Err(MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "not a KVM vCPU fd",
        )),
        SysError::Os(ENOEXEC) => Err(MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "vCPU not initialized",
        )),
        SysError::Os(ENOMEM) => Err(MicrovmError::new(
            MicrovmErrorCode::ResourceExhausted,
            "resource exhausted running vCPU",
        )),
        SysError::Os(n) => Err(MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("KVM_RUN failed (os error {n})"),
        )),
    }
}

impl VcpuFd {
    /// 作成時に指定した vCPU id。
    pub fn id(&self) -> u32 {
        self.id
    }

    /// 累積の実行統計。
    pub fn stats(&self) -> RunStats {
        self.stats
    }

    /// 実行結果の記録器を接続する（以後の `run_once` ごとに呼ばれる。REPAIR-4）。
    pub fn set_observer(&mut self, observer: Arc<dyn RunObserver>) {
        self.observer = Some(observer);
    }

    /// `KVM_RUN` を 1 回発行し、戻った理由（VM exit）を返す。ループは呼び出し側が組む。
    ///
    /// `timeout` を超えてもゲストが exit しないときは、別スレッドが `kvm_run.immediate_exit` を立てて
    /// 呼び出しスレッドへ `SIGUSR2` を送り（何もしない handler を `sigaction` で入れる。既存の別 handler があれば
    /// 失敗にする）、`KVM_RUN` を中断して `DeadlineExceeded` を返す（REPAIR-5）。監視スレッドは戻る前に
    /// 必ず join し、`immediate_exit` は下ろす。`timeout` は 0 より大きく [`RUN_DEADLINE_MAX`] 以下。
    /// EINTR / EAGAIN は [`VcpuExit::Interrupted`]（再実行できる）。exit のデバイスへの振り分けと
    /// IN・MMIO 読み出しの応答の書き戻しは [`VcpuFd::handle_exit`] が担う（次の `run_once` の前に呼ぶ）。結果と所要時間は統計と記録器へ残す（REPAIR-4）。
    pub fn run_once(&mut self, timeout: Duration) -> Result<VcpuExit, MicrovmError> {
        let start = Instant::now();
        let result = self.run_bounded(timeout);
        let elapsed = start.elapsed();
        let outcome = match &result {
            Ok(VcpuExit::Interrupted) => RunOutcome::Interrupted,
            Ok(e) => RunOutcome::Exit(exit_kind(e)),
            Err(e) if e.code() == MicrovmErrorCode::DeadlineExceeded => {
                RunOutcome::DeadlineExceeded
            }
            Err(e) => RunOutcome::Error(e.code()),
        };
        self.stats.runs += 1;
        self.stats.total_elapsed = self.stats.total_elapsed.saturating_add(elapsed);
        match outcome {
            RunOutcome::Exit(_) => self.stats.exits += 1,
            RunOutcome::Interrupted => self.stats.interrupted += 1,
            RunOutcome::DeadlineExceeded => self.stats.deadline_exceeded += 1,
            RunOutcome::Error(_) => self.stats.errors += 1,
        }
        if let Some(o) = &self.observer {
            o.record(&RunRecord {
                vcpu_id: self.id,
                outcome,
                elapsed,
            });
        }
        result
    }

    /// `run_once` が返した `exit`（`Io` / `Mmio`）を `dispatcher` の該当デバイスへ振り分け、ゲストの読み出し
    /// （IN・MMIO read）の応答があれば `kvm_run` 領域へ書き戻す（TASK-74.4.2・MVM-1）。
    ///
    /// 読み出しは書き戻さないと次の `KVM_RUN` で命令が完了しないため、ループは
    /// `run_once` → `handle_exit` → `run_once` の順で組む。`exit` は直前の `run_once` の戻り値でなければならず、
    /// dispatch の前に領域の現在の exit（アドレス / ポート・幅・回数・向き・書き込みデータ）と照合し、食い違えばデバイスにも領域にも触れず `Internal`（fail-closed）。`Io` / `Mmio` 以外の exit は `InvalidArgument`。
    /// どのデバイスにも当たらないアクセスはエラーにせず `DispatchOutcome::Unhandled`（読み出しは 0xFF 埋め）で返す。
    pub fn handle_exit(
        &mut self,
        exit: &VcpuExit,
        dispatcher: &mut ExitDispatcher,
    ) -> Result<DispatchOutcome, MicrovmError> {
        exit::ensure_exit_matches_area(&self.run, exit)?;
        let outcome = dispatcher.dispatch(exit)?;
        if let Some(response) = outcome.read_response() {
            match exit {
                VcpuExit::Io { .. } => exit::complete_io_in(&mut self.run, response)?,
                VcpuExit::Mmio { .. } => exit::complete_mmio_read(&mut self.run, response)?,
                _ => {}
            }
        }
        Ok(outcome)
    }

    fn run_bounded(&mut self, timeout: Duration) -> Result<VcpuExit, MicrovmError> {
        if timeout.is_zero() || timeout > RUN_DEADLINE_MAX {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "KVM_RUN deadline out of range",
            ));
        }
        sys::install_kick_handler().map_err(|e| match e {
            SysError::Unsupported => MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
            SysError::Os(n) => MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                format!("cannot install vCPU kick handler (os error {n})"),
            ),
        })?;
        // 呼び出しスレッドが SIGUSR2 をブロックしていても中断が届くよう、実行中だけ解除する（drop で復元）。
        let _unblocked = sys::KickUnblocked::new().map_err(|e| match e {
            SysError::Unsupported => MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
            SysError::Os(n) => MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                format!("cannot unblock vCPU kick signal (os error {n})"),
            ),
        })?;
        let target = sys::ThreadId::current();
        let timed_out = AtomicBool::new(false);
        let (tx, rx) = mpsc::channel::<()>();
        let run = &self.run;
        let fd = self.fd.as_fd();
        let timed_out_ref = &timed_out;
        let outcome = std::thread::scope(|scope| {
            let watchdog = std::thread::Builder::new()
                .name("kvm-run-deadline".into())
                .spawn_scoped(scope, move || {
                    if let Err(RecvTimeoutError::Timeout) = rx.recv_timeout(timeout) {
                        timed_out_ref.store(true, Ordering::SeqCst);
                        let _ = run.set_immediate_exit(true);
                        // シグナルが ioctl 突入前に届いても immediate_exit が効くが、取りこぼしに備えて繰り返す。
                        loop {
                            let _ = target.kick();
                            if !matches!(
                                rx.recv_timeout(KICK_INTERVAL),
                                Err(RecvTimeoutError::Timeout)
                            ) {
                                break;
                            }
                        }
                    }
                })
                .map_err(|_| {
                    MicrovmError::new(
                        MicrovmErrorCode::ResourceExhausted,
                        "cannot spawn KVM_RUN deadline thread",
                    )
                })?;
            let r = sys::kvm_run(fd);
            drop(tx);
            let _ = watchdog.join();
            Ok::<_, MicrovmError>(r)
        })?;
        let expired = timed_out.load(Ordering::SeqCst);
        if expired {
            // 監視スレッドは join 済み。次回の実行を妨げないよう下ろす。
            let _ = self.run.set_immediate_exit(false);
        }
        match outcome {
            Ok(()) => exit::decode_exit(&self.run),
            Err(e) => match classify_run_error(e) {
                Ok(VcpuExit::Interrupted) if expired => Err(MicrovmError::new(
                    MicrovmErrorCode::DeadlineExceeded,
                    "KVM_RUN deadline exceeded",
                )),
                other => other,
            },
        }
    }
}

impl AsFd for VcpuFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// vCPU 作成の段（errno 分類のメッセージ切り替え用）。`PreferredTarget`・`VcpuInit` は aarch64 だけが使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
enum VcpuStage {
    Create,
    PreferredTarget,
    VcpuInit,
    Mmap,
}

fn classify_vcpu_error(stage: VcpuStage, e: SysError) -> MicrovmError {
    let name = match stage {
        VcpuStage::Create => "KVM_CREATE_VCPU",
        VcpuStage::PreferredTarget => "KVM_ARM_PREFERRED_TARGET",
        VcpuStage::VcpuInit => "KVM_ARM_VCPU_INIT",
        VcpuStage::Mmap => "mmap of kvm_run",
    };
    match e {
        SysError::Unsupported => MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "KVM is not supported on this architecture",
        ),
        SysError::Os(EINVAL) if stage == VcpuStage::Create => {
            MicrovmError::new(MicrovmErrorCode::InvalidArgument, "invalid vCPU id")
        }
        SysError::Os(EEXIST) => {
            MicrovmError::new(MicrovmErrorCode::AlreadyExists, "vCPU id already exists")
        }
        SysError::Os(ENOTTY) => {
            MicrovmError::new(MicrovmErrorCode::FailedPrecondition, "not a KVM VM fd")
        }
        SysError::Os(n) if n == EACCES || n == EPERM => MicrovmError::new(
            MicrovmErrorCode::PermissionDenied,
            "permission denied creating vCPU",
        ),
        SysError::Os(n) if n == ENOMEM || n == EMFILE || n == ENFILE => MicrovmError::new(
            MicrovmErrorCode::ResourceExhausted,
            format!("resource exhausted creating vCPU (os error {n})"),
        ),
        SysError::Os(n) => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("{name} failed (os error {n})"),
        ),
    }
}

impl VmFd {
    /// `KVM_CREATE_VCPU` で vCPU を作る（aarch64 は続けて初期化する。モジュール doc 参照）。
    /// id の上限は検証せずカーネルの EINVAL（`InvalidArgument`）に任せる。重複は `AlreadyExists`。
    /// 初期化に失敗したときは作成済みの fd を drop で close する。
    pub fn create_vcpu(&self, id: u32) -> Result<VcpuFd, MicrovmError> {
        let fd = sys::kvm_create_vcpu(self.fd.as_fd(), u64::from(id))
            .map_err(|e| classify_vcpu_error(VcpuStage::Create, e))?;
        #[cfg(target_arch = "aarch64")]
        {
            let init = sys::kvm_arm_preferred_target(self.fd.as_fd())
                .map_err(|e| classify_vcpu_error(VcpuStage::PreferredTarget, e))?;
            sys::kvm_arm_vcpu_init(fd.as_fd(), &init)
                .map_err(|e| classify_vcpu_error(VcpuStage::VcpuInit, e))?;
        }
        let run = sys::KvmRunMap::map(fd.as_fd(), self.vcpu_mmap_size)
            .map_err(|e| classify_vcpu_error(VcpuStage::Mmap, e))?;
        Ok(VcpuFd {
            run,
            fd,
            id,
            stats: RunStats::default(),
            observer: None,
        })
    }
}

impl AsFd for VmFd {
    /// `KVM_CREATE_VCPU` が借用する。
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn classify_open_error(e: &io::Error) -> MicrovmError {
    match e.kind() {
        io::ErrorKind::NotFound => {
            MicrovmError::new(MicrovmErrorCode::NotFound, "KVM device not found")
        }
        io::ErrorKind::PermissionDenied => MicrovmError::new(
            MicrovmErrorCode::PermissionDenied,
            "permission denied opening KVM device",
        ),
        _ => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!(
                "failed to open KVM device (os error {})",
                e.raw_os_error().unwrap_or(0)
            ),
        ),
    }
}

fn classify_create_vm_error(e: SysError) -> MicrovmError {
    match e {
        SysError::Unsupported => MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "KVM is not supported on this architecture",
        ),
        SysError::Os(n) if n == EACCES || n == EPERM => MicrovmError::new(
            MicrovmErrorCode::PermissionDenied,
            "permission denied creating VM",
        ),
        SysError::Os(n) if n == ENOMEM || n == EMFILE || n == ENFILE => MicrovmError::new(
            MicrovmErrorCode::ResourceExhausted,
            format!("resource exhausted creating VM (os error {n})"),
        ),
        SysError::Os(n) => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("KVM_CREATE_VM failed (os error {n})"),
        ),
    }
}

impl KvmDevice {
    /// `/dev/kvm` を開き、KVM API 版数が 12 であることを確かめる。
    pub fn open() -> Result<KvmDevice, MicrovmError> {
        Self::open_at(Path::new(KVM_PATH))
    }

    /// 任意のパスを KVM デバイスとして開く（試験・将来の差し替え用）。エラーの `message` にパスは載せない。
    pub fn open_at(path: &Path) -> Result<KvmDevice, MicrovmError> {
        // std は Linux で O_CLOEXEC を付ける。KVM は O_RDWR が必要。
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| classify_open_error(&e))?;
        let dev = KvmDevice {
            fd: OwnedFd::from(file),
        };
        let v = dev.api_version()?;
        if v != sys::consts::KVM_API_VERSION {
            return Err(MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                format!(
                    "unsupported KVM API version {v} (expected {})",
                    sys::consts::KVM_API_VERSION
                ),
            ));
        }
        Ok(dev)
    }

    /// `KVM_GET_API_VERSION` の値。KVM デバイスでない fd（ENOTTY 等）は `FailedPrecondition`。
    pub fn api_version(&self) -> Result<i32, MicrovmError> {
        sys::kvm_get_api_version(self.fd.as_fd()).map_err(|e| match e {
            SysError::Unsupported => MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
            SysError::Os(_) => {
                MicrovmError::new(MicrovmErrorCode::FailedPrecondition, "not a KVM device")
            }
        })
    }

    /// `KVM_CREATE_VM`（machine type 0）で VM fd を作る。
    pub fn create_vm(&self) -> Result<VmFd, MicrovmError> {
        sys::kvm_create_vm(self.fd.as_fd(), 0)
            .map_err(classify_create_vm_error)
            .and_then(|fd| {
                let n = sys::kvm_get_vcpu_mmap_size(self.fd.as_fd()).map_err(|e| match e {
                    SysError::Unsupported => MicrovmError::new(
                        MicrovmErrorCode::Unimplemented,
                        "KVM is not supported on this architecture",
                    ),
                    SysError::Os(n) => MicrovmError::new(
                        MicrovmErrorCode::Internal,
                        format!("KVM_GET_VCPU_MMAP_SIZE failed (os error {n})"),
                    ),
                })?;
                Ok(VmFd {
                    fd,
                    vcpu_mmap_size: validate_mmap_size(n)?,
                })
            })
    }

    /// 自己診断: 固定の 5 バイトのゲストコード（`mov al,0x42; out 0x10,al; hlt`）を 1 ページに置いて
    /// 実際に `KVM_RUN` し、観測した VM exit を返す（TASK-74.4.1・MVM-1。x86_64 のみ）。
    ///
    /// x86_64 のリセット状態（CS:IP = F000:FFF0、線形 0xFFFFFFF0）のまま GPA `0xFFFFF000` に置いた 1 ページから
    /// 実行され、レジスタ設定は不要。ゲストのコードは固定のリテラルで外部入力は届かない。VM・ページ・vCPU の
    /// 寿命はこの関数の中で完結する（戻る前に vCPU、登録ページ、VM の順に解放する）。
    /// 将来 `fandhe-container-plugin-microvm`（TASK-117）の利用可否の確認にも使える。汎用のゲストメモリは
    /// #696（TASK-75.1）の担当でこれは別物。ゲストが想定どおり終わらないときは 1 回 5 秒の期限で中断して失敗にする
    /// （最大 8 回でも打ち切る）。他 arch は `Unimplemented`。
    pub fn probe_guest_execution(&self) -> Result<GuestExecutionProbe, MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            self.probe_guest_execution_x86_64()
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Err(MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "guest execution probe is only implemented for x86_64",
            ))
        }
    }

    /// 自己診断: ゲストコード（`in al,0x10; out 0x11,al; mov al,[0x2000]; out 0x12,al; hlt`）を実際に `KVM_RUN` し、
    /// PIO の IN と MMIO read の応答が `handle_exit` でゲストへ書き戻されることを確かめる（TASK-74.4.2・MVM-1。
    /// x86_64 のみ）。ポート 0x10 は固定値 `0x5A`、GPA `0x2000` の MMIO は固定値 `0xA5` を返し、ポート 0x11・0x12
    /// への OUT が記録される。ページ・vCPU の扱いと期限は [`KvmDevice::probe_guest_execution`] と同じ。
    /// 他 arch は `Unimplemented`。
    pub fn probe_exit_dispatch(&self) -> Result<ExitDispatchProbe, MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            self.probe_exit_dispatch_x86_64()
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Err(MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "exit dispatch probe is only implemented for x86_64",
            ))
        }
    }

    /// 無限ループ（`jmp $`）のゲストを `runs` 回 `deadline` で中断させ、統計と記録を返す（REPAIR-5・REPAIR-4・MVM-1。
    /// x86_64 のみ。他 arch は `Unimplemented`）。呼び出しスレッドの `SIGUSR2` を診断中ブロックして最悪条件で確かめる。各回は必ず `DeadlineExceeded` で戻ることを期待し、
    /// 想定外の結果は `Internal` で失敗にする。`runs` は 1〜8、`deadline` は `run_once` と同じ範囲。
    pub fn probe_deadline_interrupt(
        &self,
        deadline: Duration,
        runs: u32,
    ) -> Result<DeadlineProbe, MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            self.probe_deadline_interrupt_x86_64(deadline, runs)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (deadline, runs);
            Err(MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "deadline probe is only implemented for x86_64",
            ))
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn probe_deadline_interrupt_x86_64(
        &self,
        deadline: Duration,
        runs: u32,
    ) -> Result<DeadlineProbe, MicrovmError> {
        const GPA: u64 = 0xFFFF_F000;
        if runs == 0 || runs > 8 {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "probe run count out of range",
            ));
        }
        let internal = |what: &str, e: SysError| match e {
            SysError::Unsupported => MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
            SysError::Os(n) => MicrovmError::new(
                MicrovmErrorCode::Internal,
                format!("{what} failed (os error {n})"),
            ),
        };
        // 最も厳しい条件（SIGUSR2 をブロックしたスレッド）で期限が効くことを確かめる。
        let blocked = sys::KickUnblocked::blocked_for_probe()
            .map_err(|e| internal("signal mask change", e))?;
        let vm = self.create_vm()?;
        let mut page = sys::GuestPage::new().map_err(|e| internal("guest page allocation", e))?;
        // jmp $
        page.write_at(0xFF0, &[0xEB, 0xFE]).map_err(|()| {
            MicrovmError::new(
                MicrovmErrorCode::Internal,
                "guest code does not fit the page",
            )
        })?;
        let registered = sys::register_single_page(vm.fd.as_fd(), 0, GPA, page)
            .map_err(|(e, _page)| internal("KVM_SET_USER_MEMORY_REGION", e))?;
        let mut vcpu = vm.create_vcpu(0)?;
        let obs = Arc::new(CollectingObserver::default());
        vcpu.set_observer(obs.clone());
        let mut result = Ok(());
        for _ in 0..runs {
            match vcpu.run_once(deadline) {
                Err(e) if e.code() == MicrovmErrorCode::DeadlineExceeded => {}
                Err(e) => {
                    result = Err(e);
                    break;
                }
                Ok(_) => {
                    result = Err(MicrovmError::new(
                        MicrovmErrorCode::Internal,
                        "spinning guest exited before the deadline",
                    ));
                    break;
                }
            }
        }
        let stats = vcpu.stats();
        drop(vcpu);
        drop(registered);
        drop(vm);
        let restored =
            sys::KickUnblocked::kick_is_blocked().map_err(|e| internal("signal mask query", e))?;
        drop(blocked);
        result?;
        let records = obs.0.lock().map(|v| v.clone()).unwrap_or_default();
        Ok(DeadlineProbe {
            stats,
            records,
            kick_mask_restored: restored,
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn probe_exit_dispatch_x86_64(&self) -> Result<ExitDispatchProbe, MicrovmError> {
        use crate::dispatch::{MmioDevice, PortIoDevice, PortIoOutcome};
        use crate::virtio_mmio::{MmioReadOutcome, MmioWriteOutcome};
        use std::sync::Mutex;

        // in al,0x10 / out 0x11,al / mov al,[0x2000] (16 ビット moffs) / out 0x12,al / hlt
        const CODE: [u8; 10] = [0xE4, 0x10, 0xE6, 0x11, 0xA0, 0x00, 0x20, 0xE6, 0x12, 0xF4];
        const GPA: u64 = 0xFFFF_F000;
        const CODE_OFFSET: usize = 0xFF0;
        const IN_VALUE: u8 = 0x5A;
        const MMIO_VALUE: u8 = 0xA5;

        /// 読み出しで固定値を返すポートデバイス。
        struct ConstPort(u8);
        impl PortIoDevice for ConstPort {
            fn read(&mut self, _offset: u16, data: &mut [u8]) -> PortIoOutcome {
                data.fill(self.0);
                PortIoOutcome::Handled
            }
            fn write(&mut self, _offset: u16, _data: &[u8]) -> PortIoOutcome {
                PortIoOutcome::Ignored
            }
        }
        /// 書き込みを記録するポートデバイス。
        struct RecordPort(Arc<Mutex<Vec<(u16, u8)>>>);
        impl PortIoDevice for RecordPort {
            fn read(&mut self, _offset: u16, data: &mut [u8]) -> PortIoOutcome {
                data.fill(0);
                PortIoOutcome::Ignored
            }
            fn write(&mut self, offset: u16, data: &[u8]) -> PortIoOutcome {
                if let (Ok(mut log), Some(b)) = (self.0.lock(), data.first()) {
                    log.push((offset, *b));
                }
                PortIoOutcome::Handled
            }
        }
        /// 読み出しで固定値を返す MMIO デバイス。
        struct ConstMmio(u8);
        impl MmioDevice for ConstMmio {
            fn read(&self, _offset: u64, data: &mut [u8]) -> MmioReadOutcome {
                data.fill(self.0);
                MmioReadOutcome::Handled
            }
            fn write(&mut self, _offset: u64, _data: &[u8]) -> MmioWriteOutcome {
                MmioWriteOutcome::Handled
            }
        }

        let internal = |what: &str, e: SysError| match e {
            SysError::Unsupported => MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
            SysError::Os(n) => MicrovmError::new(
                MicrovmErrorCode::Internal,
                format!("{what} failed (os error {n})"),
            ),
        };
        let writes = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = ExitDispatcher::new();
        dispatcher.register_pio(0x10, 1, Box::new(ConstPort(IN_VALUE)))?;
        dispatcher.register_pio(0x11, 2, Box::new(RecordPort(Arc::clone(&writes))))?;
        dispatcher.register_mmio(0x2000, 0x10, Box::new(ConstMmio(MMIO_VALUE)))?;
        // 宣言順の逆が drop 順: vcpu → registered → vm。明示 drop で順序を固定する。
        let vm = self.create_vm()?;
        let mut page = sys::GuestPage::new().map_err(|e| internal("guest page allocation", e))?;
        page.write_at(CODE_OFFSET, &CODE).map_err(|()| {
            MicrovmError::new(
                MicrovmErrorCode::Internal,
                "guest code does not fit the page",
            )
        })?;
        let registered = sys::register_single_page(vm.fd.as_fd(), 0, GPA, page)
            .map_err(|(e, _page)| internal("KVM_SET_USER_MEMORY_REGION", e))?;
        let mut vcpu = vm.create_vcpu(0)?;
        let outcome = run_probe_loop(|| {
            let exit = vcpu.run_once(PROBE_RUN_DEADLINE)?;
            if matches!(exit, VcpuExit::Io { .. } | VcpuExit::Mmio { .. }) {
                vcpu.handle_exit(&exit, &mut dispatcher)?;
            }
            Ok(exit)
        });
        drop(vcpu);
        drop(registered);
        drop(vm);
        let (exits, _interrupted) = outcome?;
        let port_writes = writes.lock().map(|v| v.clone()).unwrap_or_default();
        Ok(ExitDispatchProbe { exits, port_writes })
    }

    #[cfg(target_arch = "x86_64")]
    fn probe_guest_execution_x86_64(&self) -> Result<GuestExecutionProbe, MicrovmError> {
        const CODE: [u8; 5] = [0xB0, 0x42, 0xE6, 0x10, 0xF4];
        const GPA: u64 = 0xFFFF_F000;
        const CODE_OFFSET: usize = 0xFF0;
        let internal = |what: &str, e: SysError| match e {
            SysError::Unsupported => MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
            SysError::Os(n) => MicrovmError::new(
                MicrovmErrorCode::Internal,
                format!("{what} failed (os error {n})"),
            ),
        };
        // 宣言順の逆が drop 順: vcpu → registered → vm。明示 drop で順序を固定する。
        let vm = self.create_vm()?;
        let mut page = sys::GuestPage::new().map_err(|e| internal("guest page allocation", e))?;
        page.write_at(CODE_OFFSET, &CODE).map_err(|()| {
            MicrovmError::new(
                MicrovmErrorCode::Internal,
                "guest code does not fit the page",
            )
        })?;
        let registered = sys::register_single_page(vm.fd.as_fd(), 0, GPA, page)
            .map_err(|(e, _page)| internal("KVM_SET_USER_MEMORY_REGION", e))?;
        let mut vcpu = vm.create_vcpu(0)?;
        let outcome = run_probe_loop(|| vcpu.run_once(PROBE_RUN_DEADLINE));
        drop(vcpu);
        drop(registered);
        drop(vm);
        let (exits, interrupted) = outcome?;
        Ok(GuestExecutionProbe { exits, interrupted })
    }
}

/// 自己診断のループ本体。`Hlt` で完了したときだけ `Ok`、回数上限（[`PROBE_MAX_RUNS`]）に達しても
/// `Hlt` に至らなければ `Internal` で失敗にする（fail-closed。TASK-74.4.1・MVM-1・REPAIR-5）。
#[cfg(target_arch = "x86_64")]
fn run_probe_loop(
    mut run: impl FnMut() -> Result<VcpuExit, MicrovmError>,
) -> Result<(Vec<VcpuExit>, u32), MicrovmError> {
    let mut exits = Vec::new();
    let mut interrupted = 0u32;
    for _ in 0..PROBE_MAX_RUNS {
        match run()? {
            VcpuExit::Interrupted => interrupted += 1,
            VcpuExit::Hlt => {
                exits.push(VcpuExit::Hlt);
                return Ok((exits, interrupted));
            }
            other => exits.push(other),
        }
    }
    Err(MicrovmError::new(
        MicrovmErrorCode::Internal,
        "guest did not halt within the probe run limit",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MVM-1: 上限まで `Interrupted` だけ、または `Hlt` 以外だけなら完了扱いにせず `Internal` で失敗する。
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn probe_loop_fails_when_run_limit_reached_without_hlt() {
        let mut calls = 0usize;
        let e = run_probe_loop(|| {
            calls += 1;
            Ok(VcpuExit::Interrupted)
        })
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
        assert_eq!(e.message(), "guest did not halt within the probe run limit");
        assert_eq!(calls, 8);
        let e = run_probe_loop(|| Ok(VcpuExit::Shutdown)).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
    }

    /// MVM-1: `Interrupted` を挟んでも `Hlt` で完了すれば `Ok`。
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn probe_loop_completes_on_hlt_after_interrupts() {
        let mut seq = vec![VcpuExit::Hlt, VcpuExit::Interrupted, VcpuExit::Interrupted];
        let (exits, interrupted) = run_probe_loop(|| Ok(seq.pop().unwrap())).unwrap();
        assert_eq!(exits, vec![VcpuExit::Hlt]);
        assert_eq!(interrupted, 2);
    }

    #[test]
    fn open_missing_path_is_not_found() {
        let p = std::env::temp_dir().join(format!(
            "fandhe-microvm-missing-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        let e = KvmDevice::open_at(&p).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::NotFound);
        assert_eq!(e.message(), "KVM device not found");
    }

    /// MVM-1: KVM でないデバイスは ioctl が ENOTTY で失敗し FailedPrecondition（unsafe 経路を KVM 無しで通す）。
    #[test]
    fn open_dev_null_is_failed_precondition() {
        let e = KvmDevice::open_at(Path::new("/dev/null")).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "not a KVM device");
    }

    #[test]
    fn classify_open_error_table() {
        let c = |e: io::Error| classify_open_error(&e).code();
        assert_eq!(
            c(io::Error::from(io::ErrorKind::NotFound)),
            MicrovmErrorCode::NotFound
        );
        assert_eq!(
            c(io::Error::from_raw_os_error(EACCES)),
            MicrovmErrorCode::PermissionDenied
        );
        assert_eq!(
            c(io::Error::from_raw_os_error(EPERM)),
            MicrovmErrorCode::PermissionDenied
        );
        assert_eq!(
            c(io::Error::from_raw_os_error(5)),
            MicrovmErrorCode::Internal
        );
        let m = classify_open_error(&io::Error::from_raw_os_error(5));
        assert_eq!(m.message(), "failed to open KVM device (os error 5)");
    }

    #[test]
    fn classify_create_vm_error_table() {
        let c = |e| classify_create_vm_error(e).code();
        assert_eq!(c(SysError::Os(EACCES)), MicrovmErrorCode::PermissionDenied);
        assert_eq!(c(SysError::Os(EPERM)), MicrovmErrorCode::PermissionDenied);
        assert_eq!(c(SysError::Os(ENOMEM)), MicrovmErrorCode::ResourceExhausted);
        assert_eq!(c(SysError::Os(EMFILE)), MicrovmErrorCode::ResourceExhausted);
        assert_eq!(c(SysError::Os(ENFILE)), MicrovmErrorCode::ResourceExhausted);
        assert_eq!(c(SysError::Unsupported), MicrovmErrorCode::Unimplemented);
        let m = classify_create_vm_error(SysError::Os(22));
        assert_eq!(m.code(), MicrovmErrorCode::Internal);
        assert_eq!(m.message(), "KVM_CREATE_VM failed (os error 22)");
    }

    /// 権限なしファイルは非 root で PermissionDenied。root では対照も成功するので期待値を対照に合わせる。
    #[test]
    fn open_unreadable_file_matches_std_behavior() {
        use std::os::unix::fs::PermissionsExt as _;
        let p = std::env::temp_dir().join(format!("fandhe-microvm-perm-{}", std::process::id()));
        std::fs::write(&p, b"").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        let std_denied = OpenOptions::new().read(true).write(true).open(&p).is_err();
        let r = KvmDevice::open_at(&p);
        std::fs::remove_file(&p).unwrap();
        let e = r.unwrap_err();
        if std_denied {
            assert_eq!(e.code(), MicrovmErrorCode::PermissionDenied);
        } else {
            assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        }
    }

    /// MVM-1: KVM の VM fd でない fd への `KVM_CREATE_VCPU` は ENOTTY で FailedPrecondition（KVM 無しで unsafe 経路を通す）。
    #[test]
    fn create_vcpu_on_non_vm_fd_is_failed_precondition() {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap();
        let vm = VmFd {
            fd: OwnedFd::from(f),
            vcpu_mmap_size: 4096 * 3,
        };
        let e = vm.create_vcpu(0).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "not a KVM VM fd");
    }

    /// MVM-1: vCPU mmap サイズの検証表。
    #[test]
    fn validate_mmap_size_table() {
        assert_eq!(validate_mmap_size(12288).unwrap(), 12288);
        for n in [0, 4095, 4097, 2 << 20, 12289] {
            let e = validate_mmap_size(n).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
            assert_eq!(e.message(), format!("unexpected KVM vCPU mmap size {n}"));
        }
    }

    /// MVM-1: KVM_RUN のエラー分類表。
    #[test]
    fn classify_run_error_table() {
        assert_eq!(
            classify_run_error(SysError::Os(EINTR)).unwrap(),
            VcpuExit::Interrupted
        );
        assert_eq!(
            classify_run_error(SysError::Os(EAGAIN)).unwrap(),
            VcpuExit::Interrupted
        );
        let cases = [
            (
                SysError::Os(ENOTTY),
                MicrovmErrorCode::FailedPrecondition,
                "not a KVM vCPU fd",
            ),
            (
                SysError::Os(ENOEXEC),
                MicrovmErrorCode::FailedPrecondition,
                "vCPU not initialized",
            ),
            (
                SysError::Os(ENOMEM),
                MicrovmErrorCode::ResourceExhausted,
                "resource exhausted running vCPU",
            ),
            (
                SysError::Os(14),
                MicrovmErrorCode::Internal,
                "KVM_RUN failed (os error 14)",
            ),
            (
                SysError::Unsupported,
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
        ];
        for (e, code, msg) in cases {
            let err = classify_run_error(e).unwrap_err();
            assert_eq!(err.code(), code);
            assert_eq!(err.message(), msg);
        }
    }

    #[test]
    fn classify_vcpu_error_table() {
        let c = classify_vcpu_error;
        let m = c(VcpuStage::Create, SysError::Os(EINVAL));
        assert_eq!(m.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(m.message(), "invalid vCPU id");
        let m = c(VcpuStage::Create, SysError::Os(EEXIST));
        assert_eq!(m.code(), MicrovmErrorCode::AlreadyExists);
        assert_eq!(m.message(), "vCPU id already exists");
        let m = c(VcpuStage::VcpuInit, SysError::Os(ENOTTY));
        assert_eq!(m.code(), MicrovmErrorCode::FailedPrecondition);
        assert_eq!(m.message(), "not a KVM VM fd");
        for n in [EACCES, EPERM] {
            let m = c(VcpuStage::Create, SysError::Os(n));
            assert_eq!(m.code(), MicrovmErrorCode::PermissionDenied);
        }
        for n in [ENOMEM, EMFILE, ENFILE] {
            let m = c(VcpuStage::Create, SysError::Os(n));
            assert_eq!(m.code(), MicrovmErrorCode::ResourceExhausted);
        }
        let m = c(VcpuStage::Create, SysError::Unsupported);
        assert_eq!(m.code(), MicrovmErrorCode::Unimplemented);
        // aarch64 の初期化段の EINVAL は id の誤りではなく Internal。
        let m = c(VcpuStage::PreferredTarget, SysError::Os(EINVAL));
        assert_eq!(m.code(), MicrovmErrorCode::Internal);
        assert_eq!(m.message(), "KVM_ARM_PREFERRED_TARGET failed (os error 22)");
        let m = c(VcpuStage::VcpuInit, SysError::Os(5));
        assert_eq!(m.message(), "KVM_ARM_VCPU_INIT failed (os error 5)");
        let m = c(VcpuStage::Create, SysError::Os(5));
        assert_eq!(m.message(), "KVM_CREATE_VCPU failed (os error 5)");
    }
}
