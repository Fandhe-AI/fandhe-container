//! macOS の vCPU 実行ループ・exit の分類・期限つきの停止の OS 非依存コア（TASK-192.9・#3791・MVM-5・MVM-1・REPAIR-5）。`unsafe` なし。
//!
//! 役割: Hypervisor.framework の vCPU は作ったスレッドに束縛される（`hv_vcpu_run`・レジスタ操作・destroy は作成スレッドから呼ぶ）。
//! 専用スレッドで vCPU を作って所有し、`run` → exit の分類 → 振り分け、を繰り返す論理と、停止要求（`AtomicBool` ＋ kick）、
//! 作成待ち・停止待ちの期限、exit の種別と回数の観測（REPAIR-4）をここに置く。`hv_*` を呼ばないため、偽の実行体
//! （[`VcpuExec`]）と偽の kick（[`VcpuKick`]）で Linux の PR CI でも単体試験が走る（macOS の PR CI は型検査のみ）。
//!
//! 呼び出し元は `hvf::vcpu`（macOS かつ aarch64 限定。`HvVcpu` に [`VcpuExec`] を、`VcpuCanceller` に [`VcpuKick`] を実装して
//! [`spawn_loop`] と [`run_loop`] を使う）。Linux 版の先例は `microvm::MicroVm::start` / `RunningMicroVm::stop`（#886）で、
//! 終了理由の語彙は `crate::stop::StopReason` を共有する。
//!
//! # 契約
//! - 停止: `LoopHandle::stop` は停止フラグ（`Release`）を立ててから kick する。ループは `Canceled` の戻りでフラグ（`Acquire`）を
//!   確かめて抜ける。kick が実行より先に届いたときの取りこぼしに備え、待つ間も一定間隔で kick し直す。
//! - 期限: 作成待ち・停止待ち・drop の待ちはいずれも期限つき。期限切れは待っていたスレッドを切り離し、`DeadlineExceeded`
//!   （表記 `TIMEOUT`）で返す。無期限の `join` はしない。
//! - fail-closed: 未知の exit・未対応の例外クラスは推測で続行せず VM を止める（[`run_loop`] の表）。
//!
//! # 未実装（REPAIR-3）
//! 複数 vCPU・AP の起動・SysReg trap の処理。exit ごとの実処理は MMIO が #3793、PSCI / HVC が #3794、WFI / vtimer が #3796。

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::esr::{EsrClass, decode_esr};
use crate::hvf_abi::{HvRunStats, HvVcpuExit, HvVcpuExitException};
use crate::stop::StopReason;

/// `run` 1 回あたりの期限の既定値（Linux の `VCPU_POLL_INTERVAL` に相当）。停止要求は kick で即時に届くため、この間隔には依らない。
/// 期限切れは正常系（`wfi` の待ち等で戻らない実行）として継続する。
pub const VCPU_RUN_SLICE: Duration = Duration::from_millis(100);
/// [`LoopHandle::stop`] の期限の上限（異常な値で実質無期限になるのを防ぐ。REPAIR-5）。
pub const VCPU_STOP_DEADLINE_MAX: Duration = Duration::from_secs(60);
/// vCPU スレッドの作成待ちの期限の既定値。上限は [`VCPU_STOP_DEADLINE_MAX`] と同じ。
pub const VCPU_CREATE_DEADLINE_DEFAULT: Duration = Duration::from_secs(5);
/// [`LoopHandle`] が `stop` を経ずに drop されたときに、スレッドの終了を待つ上限。
const DROP_STOP_WAIT: Duration = Duration::from_secs(5);
/// 停止待ちの間に kick を打ち直す間隔（実行より先に届いた kick の取りこぼし対策）。
const KICK_INTERVAL: Duration = Duration::from_millis(10);
/// 報告を送った後のスレッドの終了を待つ上限（報告が最後の動作のため通常は即時）。
const JOIN_WAIT: Duration = Duration::from_secs(1);

/// `hv_vcpu_run` の戻りをゲスト由来の意味で分類したもの（untrusted な値の写し）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HvExit {
    /// `hv_vcpus_exit` による停止要求（または取りこぼした kick の後着）。
    Canceled,
    /// ゲストの例外。`class` は ESR の EC・ISS による分類で、`exception` は生の syndrome・VA・IPA。
    /// PC を進める量は `esr::instruction_length(exception.syndrome)` で得る。
    Exception {
        /// ESR の分類。
        class: EsrClass,
        /// フレームワークが返した例外情報そのまま。
        exception: HvVcpuExitException,
    },
    /// vtimer の発火（マスクされて戻った）。
    VtimerActivated,
    /// 未知の exit reason（生値）。fail-closed で VM を止める。
    Unknown(u32),
}

/// exit の種別（観測用の固定名つき。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitKind {
    /// 停止要求。
    Canceled,
    /// ISV=1 の data abort（MMIO）。
    DataAbort,
    /// ISV=0 の data abort（命令の復号情報なし）。
    DataAbortUnsupported,
    /// HVC。
    Hvc,
    /// SMC。
    Smc,
    /// WFI / WFE 系。
    Wfx,
    /// システムレジスタ trap。
    Sysreg,
    /// 上記以外の例外クラス。
    ExceptionOther,
    /// vtimer の発火。
    Vtimer,
    /// 未知の exit reason。
    Unknown,
}

impl ExitKind {
    /// 全 variant（宣言順）。
    pub const ALL: [ExitKind; 10] = [
        ExitKind::Canceled,
        ExitKind::DataAbort,
        ExitKind::DataAbortUnsupported,
        ExitKind::Hvc,
        ExitKind::Smc,
        ExitKind::Wfx,
        ExitKind::Sysreg,
        ExitKind::ExceptionOther,
        ExitKind::Vtimer,
        ExitKind::Unknown,
    ];

    /// 構造化ログ・メトリクス用の固定名。
    pub const fn as_str(self) -> &'static str {
        match self {
            ExitKind::Canceled => "canceled",
            ExitKind::DataAbort => "data_abort",
            ExitKind::DataAbortUnsupported => "data_abort_unsupported",
            ExitKind::Hvc => "hvc",
            ExitKind::Smc => "smc",
            ExitKind::Wfx => "wfx",
            ExitKind::Sysreg => "sysreg",
            ExitKind::ExceptionOther => "exception_other",
            ExitKind::Vtimer => "vtimer",
            ExitKind::Unknown => "unknown",
        }
    }

    const fn index(self) -> usize {
        match self {
            ExitKind::Canceled => 0,
            ExitKind::DataAbort => 1,
            ExitKind::DataAbortUnsupported => 2,
            ExitKind::Hvc => 3,
            ExitKind::Smc => 4,
            ExitKind::Wfx => 5,
            ExitKind::Sysreg => 6,
            ExitKind::ExceptionOther => 7,
            ExitKind::Vtimer => 8,
            ExitKind::Unknown => 9,
        }
    }
}

impl HvExit {
    /// 観測用の種別。
    pub fn kind(&self) -> ExitKind {
        match self {
            HvExit::Canceled => ExitKind::Canceled,
            HvExit::VtimerActivated => ExitKind::Vtimer,
            HvExit::Unknown(_) => ExitKind::Unknown,
            HvExit::Exception { class, .. } => match class {
                EsrClass::Wfx(_) => ExitKind::Wfx,
                EsrClass::Hvc { .. } => ExitKind::Hvc,
                EsrClass::Smc { .. } => ExitKind::Smc,
                EsrClass::SysReg(_) => ExitKind::Sysreg,
                EsrClass::DataAbort(_) => ExitKind::DataAbort,
                EsrClass::DataAbortUnsupported { .. } => ExitKind::DataAbortUnsupported,
                EsrClass::Other { .. } => ExitKind::ExceptionOther,
            },
        }
    }
}

/// `hv_vcpu_run` の戻り（`HvVcpuExit`）を分類する純関数。全入力を panic なしで写す（ゲスト由来の untrusted な値）。
pub fn classify_exit(exit: &HvVcpuExit) -> HvExit {
    match exit {
        HvVcpuExit::Canceled => HvExit::Canceled,
        HvVcpuExit::VtimerActivated => HvExit::VtimerActivated,
        HvVcpuExit::Unknown(v) => HvExit::Unknown(*v),
        HvVcpuExit::Exception(e) => HvExit::Exception {
            class: decode_esr(e.syndrome),
            exception: *e,
        },
    }
}

/// exit の種別と回数の観測口（REPAIR-4。Linux の `RunObserver` に相当）。
///
/// vCPU スレッドから同期で呼ばれるため、実装はブロックしないこと（ログ・メトリクスへの非同期な受け渡しに留める）。
pub trait VcpuExitObserver: Send + Sync + fmt::Debug {
    /// 分類した exit 1 件ごと、振り分けの前に呼ばれる。
    fn on_exit(&self, kind: ExitKind);
}

/// 種別ごとに数えるだけの [`VcpuExitObserver`]。
#[derive(Debug, Default)]
pub struct ExitCounts {
    counts: [AtomicU64; 10],
}

impl ExitCounts {
    /// 空の集計を作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// 種別ごとの回数。
    pub fn count(&self, kind: ExitKind) -> u64 {
        self.counts
            .get(kind.index())
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }
}

impl VcpuExitObserver for ExitCounts {
    fn on_exit(&self, kind: ExitKind) {
        if let Some(c) = self.counts.get(kind.index()) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// exit ハンドラが [`run_loop`] へ返す次の動作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitAction {
    /// ゲストを再開する。PC の更新はハンドラの責務（`esr::instruction_length`）。
    Continue,
    /// ループを抜ける（PSCI SYSTEM_OFF の `GuestShutdown` 等）。
    Stop(StopReason),
}

/// vCPU の実行体（`HvVcpu` の抽象）。スレッドに束縛されるため `Send` は要求しない。
pub trait VcpuExec {
    /// ゲストを `slice` まで走らせ、戻った理由を返す。`slice` の期限切れは `DeadlineExceeded`（正常系）。
    fn run(&mut self, slice: Duration) -> Result<HvVcpuExit, MicrovmError>;
    /// 累積の実行統計。
    fn stats(&self) -> HvRunStats;
}

/// 他スレッドから実行を止める手段（`VcpuCanceller` の抽象）。
pub trait VcpuKick: Send + Sync + 'static {
    /// 実行中の `run` を `Canceled` で戻させる。vCPU 破棄後は `FailedPrecondition`（呼び出し側は無視してよい）。
    fn kick(&self) -> Result<(), MicrovmError>;
}

fn err(code: MicrovmErrorCode, msg: &'static str) -> MicrovmError {
    MicrovmError::new(code, msg)
}

/// 実行ループ本体。終了理由を返す。
///
/// | 状況 | 動作 |
/// | ---- | ---- |
/// | 各回の先頭で停止フラグ | `Requested` |
/// | `Err(DeadlineExceeded)`（1 回分の期限切れ） | 続行（正常系） |
/// | その他の `Err(e)` | `Failed(e.code())` |
/// | `Canceled` かつ停止フラグ | `Requested` |
/// | `Canceled` でフラグなし（取りこぼした kick の後着） | 続行 |
/// | `Unknown` | `Failed(Internal)` |
/// | SysReg / ISV=0 の data abort / 未知の EC | `Failed(Unimplemented)`（esr の fail-closed 契約。REPAIR-3） |
/// | それ以外 | `dispatch` の結果（`Continue` / `Stop(r)` / `Err(e)` → `Failed(e.code())`） |
///
/// 分類した exit は、振り分けの前に `observer` へ記録する。
pub fn run_loop<E, D>(
    exec: &mut E,
    stop: &AtomicBool,
    slice: Duration,
    observer: Option<&dyn VcpuExitObserver>,
    mut dispatch: D,
) -> StopReason
where
    E: VcpuExec,
    D: FnMut(&mut E, &HvExit) -> Result<ExitAction, MicrovmError>,
{
    loop {
        if stop.load(Ordering::Acquire) {
            return StopReason::Requested;
        }
        let raw = match exec.run(slice) {
            Ok(raw) => raw,
            Err(e) if e.code() == MicrovmErrorCode::DeadlineExceeded => continue,
            Err(e) => return StopReason::Failed(e.code()),
        };
        let exit = classify_exit(&raw);
        if let Some(o) = observer {
            o.on_exit(exit.kind());
        }
        match &exit {
            HvExit::Canceled => {
                if stop.load(Ordering::Acquire) {
                    return StopReason::Requested;
                }
            }
            HvExit::Unknown(_) => return StopReason::Failed(MicrovmErrorCode::Internal),
            HvExit::Exception {
                class:
                    EsrClass::SysReg(_) | EsrClass::DataAbortUnsupported { .. } | EsrClass::Other { .. },
                ..
            } => return StopReason::Failed(MicrovmErrorCode::Unimplemented),
            _ => match dispatch(exec, &exit) {
                Ok(ExitAction::Continue) => {}
                Ok(ExitAction::Stop(r)) => return r,
                Err(e) => return StopReason::Failed(e.code()),
            },
        }
    }
}

/// vCPU スレッドの終了報告。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct VcpuStopReport {
    /// 終了理由。
    pub reason: StopReason,
    /// 累積の実行統計。
    pub stats: HvRunStats,
    /// スレッド開始から終了までの時間。
    pub elapsed: Duration,
}

/// ログ配送キューの上限（行数）。満杯のときは行を捨てる（REPAIR-5）。
const LOG_QUEUE_CAP: usize = 256;

/// 上限つきの非ブロッキングなログ配送。
///
/// 期限つき操作（`spawn_loop`・`stop`）や終了報告の経路が、書き込み先（stderr が満杯の pipe 等）の応答に
/// 左右されないよう、専用スレッドへ `try_send` するだけにする。満杯・スレッド不在のときは行を捨てる
/// （REPAIR-5・MVM-1）。
struct LogSink {
    tx: SyncSender<String>,
}

impl LogSink {
    /// `out` へ 1 行ずつ書く配送スレッドを起動する。起動できなければ `None`。
    fn start<W: std::io::Write + Send + 'static>(mut out: W, cap: usize) -> Option<Self> {
        let (tx, rx) = mpsc::sync_channel::<String>(cap);
        std::thread::Builder::new()
            .name("hvf-log".to_string())
            .spawn(move || {
                while let Ok(line) = rx.recv() {
                    drop(writeln!(out, "{line}"));
                }
            })
            .ok()?;
        Some(Self { tx })
    }

    /// 待たずに積む。満杯・切断なら捨てて `false`。
    fn emit(&self, line: String) -> bool {
        self.tx.try_send(line).is_ok()
    }
}

fn log_line(args: fmt::Arguments<'_>) {
    static SINK: std::sync::OnceLock<Option<LogSink>> = std::sync::OnceLock::new();
    let sink = SINK.get_or_init(|| LogSink::start(std::io::stderr(), LOG_QUEUE_CAP));
    if let Some(sink) = sink {
        let _ = sink.emit(args.to_string());
    }
}

/// 構造化ログ 1 行分の (level, outcome, code 付記) を終了理由から作る。
fn outcome_fields(reason: StopReason) -> (&'static str, &'static str, String) {
    match reason {
        StopReason::Failed(c) => ("error", "error", format!(" code={}", c.as_str())),
        _ => ("info", "ok", String::new()),
    }
}

/// スレッド内の `body` へ渡す開始の合図。`ready` か `fail` のどちらかで作成結果を呼び出し元へ返す。
pub struct LoopStart<K> {
    tx: SyncSender<Result<K, MicrovmError>>,
    stop: Arc<AtomicBool>,
}

impl<K> LoopStart<K> {
    /// 作成に成功した。`kick` を呼び出し元へ渡し、停止フラグを返す（[`run_loop`] の `stop` に渡す）。
    /// 呼び出し元が作成待ちの期限を過ぎていた場合も停止フラグは返り、フラグは既に立っている。
    pub fn ready(self, kick: K) -> Arc<AtomicBool> {
        // 受け手が期限切れで去っていても送信は失敗するだけ（容量 1 でブロックしない）。
        let _ = self.tx.send(Ok(kick));
        self.stop
    }

    /// 作成に失敗した。エラーをそのまま呼び出し元へ返す。
    pub fn fail(self, e: MicrovmError) {
        let _ = self.tx.send(Err(e));
    }
}

/// 起動済みの vCPU スレッドの操作口。`stop` で期限つきに止める。
pub struct LoopHandle<K: VcpuKick> {
    stop: Arc<AtomicBool>,
    kick: Arc<K>,
    rx: Receiver<VcpuStopReport>,
    join: Option<JoinHandle<()>>,
}

impl<K: VcpuKick> fmt::Debug for LoopHandle<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoopHandle")
            .field("finished", &self.is_finished())
            .finish_non_exhaustive()
    }
}

/// vCPU スレッドを起動し、`body` が `ready` / `fail` を呼ぶまで `create_deadline` だけ待つ。
///
/// `body` はスレッド内で vCPU を作って所有し、[`run_loop`] を回して `(終了理由, 統計)` を返す。vCPU は `body` の中で drop して
/// から戻ること（`stop` が `Ok` で戻った時点で vCPU が破棄済みである根拠）。`create_deadline` は 0 超 [`VCPU_STOP_DEADLINE_MAX`]
/// 以下（`InvalidArgument`）。期限切れは停止フラグを立ててスレッドを切り離し `DeadlineExceeded` を返す（遅れて `ready` しても
/// ループ先頭の検査で即 `Requested` になり、ゲストは走らない）。
pub fn spawn_loop<K, F>(
    name: &str,
    create_deadline: Duration,
    body: F,
) -> Result<LoopHandle<K>, MicrovmError>
where
    K: VcpuKick,
    F: FnOnce(LoopStart<K>) -> (StopReason, HvRunStats) + Send + 'static,
{
    if create_deadline.is_zero() || create_deadline > VCPU_STOP_DEADLINE_MAX {
        return Err(err(
            MicrovmErrorCode::InvalidArgument,
            "vcpu create deadline must be in (0, 60s]",
        ));
    }
    // `Builder::spawn` は NUL を含む名前で呼び出し元スレッドが panic する（MVM-5・REPAIR-5）ため、先に検査する。
    if name.contains('\0') {
        return Err(err(
            MicrovmErrorCode::InvalidArgument,
            "vcpu thread name must not contain NUL",
        ));
    }
    let stop = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<K, MicrovmError>>(1);
    let (report_tx, report_rx) = mpsc::sync_channel::<VcpuStopReport>(1);
    let start = LoopStart {
        tx: ready_tx,
        stop: Arc::clone(&stop),
    };
    let join = std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            let started = Instant::now();
            let (reason, stats) = body(start);
            let elapsed = started.elapsed();
            let (level, outcome, code) = outcome_fields(reason);
            log_line(format_args!(
                "level={level} op=hvf.vcpu_loop outcome={outcome} reason={}{code} runs={} exits={} deadline_exceeded={} errors={} elapsed_us={}",
                reason.as_str(),
                stats.runs,
                stats.exits,
                stats.deadline_exceeded,
                stats.errors,
                elapsed.as_micros()
            ));
            // 報告が最後の動作。受け手が去っていても失敗するだけ。
            let _ = report_tx.send(VcpuStopReport {
                reason,
                stats,
                elapsed,
            });
        })
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::OutOfMemory => err(
                MicrovmErrorCode::ResourceExhausted,
                "failed to spawn the vcpu thread: resource exhausted",
            ),
            _ => err(MicrovmErrorCode::Internal, "failed to spawn the vcpu thread"),
        })?;
    match ready_rx.recv_timeout(create_deadline) {
        Ok(Ok(kick)) => Ok(LoopHandle {
            stop,
            kick: Arc::new(kick),
            rx: report_rx,
            join: Some(join),
        }),
        Ok(Err(e)) => {
            log_line(format_args!(
                "level=error op=hvf.vcpu_create outcome=error code={}",
                e.code().as_str()
            ));
            Err(e)
        }
        Err(RecvTimeoutError::Timeout) => {
            stop.store(true, Ordering::Release);
            log_line(format_args!(
                "level=error op=hvf.vcpu_create outcome=error code={}",
                MicrovmErrorCode::DeadlineExceeded.as_str()
            ));
            // JoinHandle は切り離す（無期限の join はしない）。
            drop(join);
            Err(err(
                MicrovmErrorCode::DeadlineExceeded,
                "vcpu thread did not become ready within deadline",
            ))
        }
        Err(RecvTimeoutError::Disconnected) => {
            log_line(format_args!(
                "level=error op=hvf.vcpu_create outcome=error code={}",
                MicrovmErrorCode::Internal.as_str()
            ));
            Err(err(
                MicrovmErrorCode::Internal,
                "vcpu thread ended before it became ready",
            ))
        }
    }
}

/// 終わったスレッドを、`JOIN_WAIT` と停止期限 `deadline_end` の早い方まで待って回収する
/// （残り時間が無ければ待たずに切り離す。REPAIR-5・MVM-1）。
fn reap(join: JoinHandle<()>, deadline_end: Instant) {
    let end = (Instant::now() + JOIN_WAIT).min(deadline_end);
    while !join.is_finished() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(1));
    }
    if join.is_finished() {
        drop(join.join());
    }
}

impl<K: VcpuKick> LoopHandle<K> {
    /// スレッドが既に終わったか（ゲスト起因の終了を含む）。
    pub fn is_finished(&self) -> bool {
        self.join.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// 停止を要求し、`deadline` まで終了報告を待つ。
    ///
    /// `deadline` は 0 超 [`VCPU_STOP_DEADLINE_MAX`] 以下（`InvalidArgument`）。停止フラグを立てて kick し、待つ間も
    /// 10ms ごとに kick し直す（`run` の前の kick が効くかは未確認のため。#3803）。ゲスト起因で既に終わって
    /// いたときは、その理由を返す。期限切れはスレッドを切り離して `DeadlineExceeded`（`TIMEOUT`）。
    /// `Ok` で戻った時点で vCPU は破棄済み。
    pub fn stop(mut self, deadline: Duration) -> Result<VcpuStopReport, MicrovmError> {
        if deadline.is_zero() || deadline > VCPU_STOP_DEADLINE_MAX {
            return Err(err(
                MicrovmErrorCode::InvalidArgument,
                "vcpu stop deadline must be in (0, 60s]",
            ));
        }
        let started = Instant::now();
        let end = started + deadline;
        self.stop.store(true, Ordering::Release);
        let result = loop {
            // 破棄後の FailedPrecondition 等は終了の途中経過であり、報告の側が結果を持つため無視する。
            let _ = self.kick.kick();
            let now = Instant::now();
            if now >= end {
                break Err(err(
                    MicrovmErrorCode::DeadlineExceeded,
                    "vcpu thread did not stop within deadline",
                ));
            }
            match self.rx.recv_timeout((end - now).min(KICK_INTERVAL)) {
                Ok(report) => break Ok(report),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    break Err(err(
                        MicrovmErrorCode::Internal,
                        "vcpu thread ended without a report",
                    ));
                }
            }
        };
        // 切り離す場合も含め、Drop の待ちを二重に走らせない。
        if let Some(join) = self.join.take() {
            if result.is_ok() || matches!(&result, Err(e) if e.code() == MicrovmErrorCode::Internal)
            {
                reap(join, end);
            } else {
                drop(join);
            }
        }
        let elapsed_us = started.elapsed().as_micros();
        match &result {
            Ok(r) => {
                let (level, outcome, code) = outcome_fields(r.reason);
                log_line(format_args!(
                    "level={level} op=hvf.vcpu_stop outcome={outcome} reason={}{code} elapsed_us={elapsed_us}",
                    r.reason.as_str()
                ));
            }
            Err(e) => log_line(format_args!(
                "level=error op=hvf.vcpu_stop outcome=error code={} elapsed_us={elapsed_us}",
                e.code().as_str()
            )),
        }
        result
    }
}

impl<K: VcpuKick> Drop for LoopHandle<K> {
    /// `stop` を経ずに drop されたとき、停止を要求して `DROP_STOP_WAIT` まで終了を待つ（過ぎたら切り離す）。
    fn drop(&mut self) {
        let Some(join) = self.join.take() else {
            return;
        };
        self.stop.store(true, Ordering::Release);
        let end = Instant::now() + DROP_STOP_WAIT;
        while !join.is_finished() && Instant::now() < end {
            let _ = self.kick.kick();
            // 報告が届くか切断されるか、間隔が過ぎるまで待つ。
            let _ = self.rx.recv_timeout(KICK_INTERVAL);
        }
        if join.is_finished() {
            drop(join.join());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::esr::WfxKind;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;

    fn exc(syndrome: u64) -> HvVcpuExit {
        HvVcpuExit::Exception(HvVcpuExitException {
            syndrome,
            virtual_address: 0,
            physical_address: 0,
        })
    }

    const HVC0: u64 = 0x5A00_0000;
    const SMC0: u64 = 0x5E00_0000;
    const WFI: u64 = 0x0600_0000;
    const SYSREG: u64 = 0x6200_0000;
    const DABT_ISV1: u64 = 0x9300_0000;
    const DABT_ISV0: u64 = 0x9200_0000;
    const OTHER_EC: u64 = 0x8200_0000;

    /// 永久にブロックする書き込み先。
    struct BlockedWriter(Arc<std::sync::Barrier>);

    impl std::io::Write for BlockedWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            // 解放されない Barrier（2 者待ちに 1 者のみ）で永久に待つ。
            self.0.wait();
            Ok(0)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// REPAIR-5・MVM-1: 書き込み先が止まっていても emit は待たず、上限を超えた行は捨てる。
    #[test]
    fn repair5_mvm1_3791_log_sink_never_blocks_on_stuck_writer() {
        let sink = LogSink::start(BlockedWriter(Arc::new(std::sync::Barrier::new(2))), 4)
            .expect("log thread starts");
        let t = Instant::now();
        let accepted = (0..1000).filter(|i| sink.emit(format!("line {i}"))).count();
        assert!(t.elapsed() < Duration::from_secs(1), "emit blocked");
        // 配送スレッドが 1 行を持ったまま止まり、キュー 4 行が埋まる。残りは捨てられる。
        assert!((4..=5).contains(&accepted), "accepted={accepted}");
    }

    /// REPAIR-5・MVM-1: 停止期限の残りが無ければ、終わっていないスレッドを待たずに切り離す。
    #[test]
    fn repair5_mvm1_3791_reap_detaches_immediately_when_deadline_passed() {
        let join = std::thread::spawn(|| std::thread::sleep(Duration::from_secs(3)));
        let t = Instant::now();
        reap(join, Instant::now());
        assert!(
            t.elapsed() < Duration::from_millis(500),
            "{:?}",
            t.elapsed()
        );
    }

    /// REPAIR-5・MVM-1: 残り時間が JOIN_WAIT より短ければ、その残りまでしか待たない。
    #[test]
    fn repair5_mvm1_3791_reap_waits_only_remaining_deadline() {
        let join = std::thread::spawn(|| std::thread::sleep(Duration::from_secs(3)));
        let t = Instant::now();
        reap(join, Instant::now() + Duration::from_millis(100));
        let e = t.elapsed();
        assert!(
            e >= Duration::from_millis(100) && e < Duration::from_millis(700),
            "{e:?}"
        );
    }

    /// MVM-5: syndrome と reason の分類。
    #[test]
    fn mvm5_3791_classify_exit_maps_every_reason() {
        let kind = |e: HvVcpuExit| classify_exit(&e).kind();
        assert_eq!(kind(exc(HVC0)), ExitKind::Hvc);
        assert_eq!(kind(exc(SMC0)), ExitKind::Smc);
        assert_eq!(kind(exc(WFI)), ExitKind::Wfx);
        assert_eq!(kind(exc(SYSREG)), ExitKind::Sysreg);
        assert_eq!(kind(exc(DABT_ISV1)), ExitKind::DataAbort);
        assert_eq!(kind(exc(DABT_ISV0)), ExitKind::DataAbortUnsupported);
        assert_eq!(kind(exc(OTHER_EC)), ExitKind::ExceptionOther);
        assert_eq!(kind(HvVcpuExit::Canceled), ExitKind::Canceled);
        assert_eq!(kind(HvVcpuExit::VtimerActivated), ExitKind::Vtimer);
        assert_eq!(kind(HvVcpuExit::Unknown(7)), ExitKind::Unknown);
        assert_eq!(classify_exit(&HvVcpuExit::Unknown(7)), HvExit::Unknown(7));
        match classify_exit(&exc(HVC0)) {
            HvExit::Exception {
                class: EsrClass::Hvc { imm16 },
                exception,
            } => {
                assert_eq!(imm16, 0);
                assert_eq!(exception.syndrome, HVC0);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            classify_exit(&exc(WFI)),
            HvExit::Exception {
                class: EsrClass::Wfx(WfxKind::Wfi),
                ..
            }
        ));
    }

    /// MVM-5: 固定名が重複せず、回数が種別ごとに数えられる。
    #[test]
    fn mvm5_3791_exit_kind_names_and_counts() {
        let names: Vec<&str> = ExitKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(
            names,
            [
                "canceled",
                "data_abort",
                "data_abort_unsupported",
                "hvc",
                "smc",
                "wfx",
                "sysreg",
                "exception_other",
                "vtimer",
                "unknown"
            ]
        );
        for (i, k) in ExitKind::ALL.iter().enumerate() {
            assert_eq!(k.index(), i);
        }
        let c = ExitCounts::new();
        c.on_exit(ExitKind::Hvc);
        c.on_exit(ExitKind::Hvc);
        c.on_exit(ExitKind::Smc);
        assert_eq!(c.count(ExitKind::Hvc), 2);
        assert_eq!(c.count(ExitKind::Smc), 1);
        assert_eq!(c.count(ExitKind::Wfx), 0);
    }

    /// 台本どおりに戻る偽の実行体（`hv_*` を呼ばない）。
    struct ScriptedExec {
        script: VecDeque<(bool, Result<HvVcpuExit, MicrovmError>)>,
        stop: Arc<AtomicBool>,
        runs: usize,
    }

    impl ScriptedExec {
        fn new(stop: &Arc<AtomicBool>, steps: Vec<Result<HvVcpuExit, MicrovmError>>) -> Self {
            Self {
                script: steps.into_iter().map(|s| (false, s)).collect(),
                stop: Arc::clone(stop),
                runs: 0,
            }
        }

        /// `n` 件目（0 始まり）を返す前に停止フラグを立てる。
        fn stop_before(mut self, n: usize) -> Self {
            if let Some(step) = self.script.get_mut(n) {
                step.0 = true;
            }
            self
        }
    }

    impl VcpuExec for ScriptedExec {
        fn run(&mut self, _slice: Duration) -> Result<HvVcpuExit, MicrovmError> {
            self.runs += 1;
            match self.script.pop_front() {
                Some((set_stop, r)) => {
                    if set_stop {
                        self.stop.store(true, Ordering::Release);
                    }
                    r
                }
                None => Err(err(MicrovmErrorCode::Internal, "script exhausted")),
            }
        }

        fn stats(&self) -> HvRunStats {
            HvRunStats::default()
        }
    }

    fn deadline_err() -> MicrovmError {
        err(MicrovmErrorCode::DeadlineExceeded, "slice")
    }

    fn run_script(
        steps: Vec<Result<HvVcpuExit, MicrovmError>>,
        stop_at: Option<usize>,
        action: Result<ExitAction, MicrovmError>,
    ) -> (StopReason, usize, usize, Arc<ExitCounts>) {
        let stop = Arc::new(AtomicBool::new(false));
        let mut exec = ScriptedExec::new(&stop, steps);
        if let Some(n) = stop_at {
            exec = exec.stop_before(n);
        }
        let counts = Arc::new(ExitCounts::new());
        let mut dispatched = 0usize;
        let reason = run_loop(
            &mut exec,
            &stop,
            Duration::from_millis(1),
            Some(counts.as_ref()),
            |_, _| {
                dispatched += 1;
                action.clone()
            },
        );
        (reason, exec.runs, dispatched, counts)
    }

    const CONT: Result<ExitAction, MicrovmError> = Ok(ExitAction::Continue);

    /// REPAIR-5: 最初から停止フラグが立っていれば一度も走らせない。
    #[test]
    fn mvm5_3791_run_loop_stop_flag_before_first_run() {
        let stop = AtomicBool::new(true);
        let mut exec = ScriptedExec::new(&Arc::new(AtomicBool::new(false)), vec![]);
        let r = run_loop(&mut exec, &stop, Duration::from_millis(1), None, |_, _| {
            CONT
        });
        assert_eq!(r, StopReason::Requested);
        assert_eq!(exec.runs, 0);
    }

    /// 1 回分の期限切れは続行し、Canceled + フラグで Requested になる。
    #[test]
    fn mvm5_3791_run_loop_deadline_then_canceled_is_requested() {
        let (r, runs, dispatched, counts) = run_script(
            vec![Err(deadline_err()), Ok(HvVcpuExit::Canceled)],
            Some(1),
            CONT,
        );
        assert_eq!(r, StopReason::Requested);
        assert_eq!((runs, dispatched), (2, 0));
        assert_eq!(counts.count(ExitKind::Canceled), 1);
    }

    /// HVC をスタブが `Unimplemented` で返すと `Failed(Unimplemented)` で止まり、観測器は hvc を 1 と数える。
    #[test]
    fn mvm5_3791_run_loop_handler_error_fails_closed() {
        let (r, runs, dispatched, counts) = run_script(
            vec![Ok(exc(HVC0))],
            None,
            Err(err(MicrovmErrorCode::Unimplemented, "hvc")),
        );
        assert_eq!(r, StopReason::Failed(MicrovmErrorCode::Unimplemented));
        assert_eq!((runs, dispatched), (1, 1));
        assert_eq!(counts.count(ExitKind::Hvc), 1);
    }

    #[test]
    fn mvm5_3791_run_loop_handler_stop_is_reported() {
        let (r, _, dispatched, _) = run_script(
            vec![Ok(exc(HVC0))],
            None,
            Ok(ExitAction::Stop(StopReason::GuestShutdown)),
        );
        assert_eq!(r, StopReason::GuestShutdown);
        assert_eq!(dispatched, 1);
    }

    #[test]
    fn mvm5_3791_run_loop_continue_then_next_exit() {
        let (r, runs, dispatched, counts) = run_script(
            vec![Ok(exc(WFI)), Ok(HvVcpuExit::VtimerActivated), Ok(exc(SMC0))],
            None,
            CONT,
        );
        // 台本が尽きると Internal で止まる。
        assert_eq!(r, StopReason::Failed(MicrovmErrorCode::Internal));
        assert_eq!((runs, dispatched), (4, 3));
        assert_eq!(counts.count(ExitKind::Wfx), 1);
        assert_eq!(counts.count(ExitKind::Vtimer), 1);
        assert_eq!(counts.count(ExitKind::Smc), 1);
    }

    /// 未知の reason は Internal、未対応の例外クラスは Unimplemented で、dispatch は呼ばれない。
    #[test]
    fn mvm5_3791_run_loop_unsupported_exits_fail_closed() {
        let (r, _, dispatched, counts) = run_script(vec![Ok(HvVcpuExit::Unknown(7))], None, CONT);
        assert_eq!(r, StopReason::Failed(MicrovmErrorCode::Internal));
        assert_eq!(dispatched, 0);
        assert_eq!(counts.count(ExitKind::Unknown), 1);
        for syndrome in [OTHER_EC, SYSREG, DABT_ISV0] {
            let (r, _, dispatched, _) = run_script(vec![Ok(exc(syndrome))], None, CONT);
            assert_eq!(r, StopReason::Failed(MicrovmErrorCode::Unimplemented));
            assert_eq!(dispatched, 0);
        }
    }

    #[test]
    fn mvm5_3791_run_loop_run_error_is_failed() {
        let (r, _, _, _) = run_script(
            vec![Err(err(MicrovmErrorCode::PermissionDenied, "x"))],
            None,
            CONT,
        );
        assert_eq!(r, StopReason::Failed(MicrovmErrorCode::PermissionDenied));
    }

    /// 取りこぼした kick の後着（フラグなしの Canceled）は続行する。
    #[test]
    fn mvm5_3791_run_loop_canceled_without_flag_continues() {
        let (r, runs, dispatched, _) = run_script(vec![Ok(HvVcpuExit::Canceled)], None, CONT);
        assert_eq!(runs, 2); // 続行して 2 回目で台本が尽きる
        assert_eq!(dispatched, 0);
        assert_eq!(r, StopReason::Failed(MicrovmErrorCode::Internal));
    }

    #[derive(Debug)]
    struct FakeKick(Arc<AtomicUsize>);

    impl VcpuKick for FakeKick {
        fn kick(&self) -> Result<(), MicrovmError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// 停止フラグを見て終わる、素直な body。
    fn responsive_body(
        kicks: Arc<AtomicUsize>,
        exited: Arc<AtomicBool>,
    ) -> impl FnOnce(LoopStart<FakeKick>) -> (StopReason, HvRunStats) + Send + 'static {
        move |start| {
            let stop = start.ready(FakeKick(kicks));
            while !stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(1));
            }
            exited.store(true, Ordering::SeqCst);
            (StopReason::Requested, HvRunStats::default())
        }
    }

    const LONG: Duration = Duration::from_secs(5);

    #[test]
    fn mvm5_3791_loop_handle_stops_with_requested_and_kicks() {
        let kicks = Arc::new(AtomicUsize::new(0));
        let exited = Arc::new(AtomicBool::new(false));
        let h = spawn_loop(
            "hvf-test",
            LONG,
            responsive_body(Arc::clone(&kicks), Arc::clone(&exited)),
        )
        .unwrap();
        let report = h.stop(LONG).unwrap();
        assert_eq!(report.reason, StopReason::Requested);
        assert!(kicks.load(Ordering::SeqCst) >= 1);
        assert!(exited.load(Ordering::SeqCst));
    }

    /// REPAIR-5: 停止フラグを無視する body に対し、期限切れは `TIMEOUT` の構造化エラー。
    #[test]
    fn mvm5_3791_stop_deadline_expired_is_timeout() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let h = spawn_loop::<FakeKick, _>("hvf-test", LONG, move |start| {
            let _stop = start.ready(FakeKick(Arc::new(AtomicUsize::new(0))));
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap();
        let e = h.stop(Duration::from_millis(50)).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        assert_eq!(e.code().as_str(), "TIMEOUT");
        assert!(e.to_string().starts_with("TIMEOUT: "), "{e}");
        assert_eq!(e.message(), "vcpu thread did not stop within deadline");
        let _ = release_tx.send(());
    }

    #[test]
    fn mvm5_3791_create_deadline_expired_is_timeout() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let e = spawn_loop::<FakeKick, _>("hvf-test", Duration::from_millis(50), move |start| {
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
            // 遅れて ready しても停止フラグは既に立っている。
            let stop = start.ready(FakeKick(Arc::new(AtomicUsize::new(0))));
            assert!(stop.load(Ordering::Acquire));
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        let _ = release_tx.send(());
    }

    #[test]
    fn mvm5_3791_create_failure_propagates_code() {
        let e = spawn_loop::<FakeKick, _>("hvf-test", LONG, |start| {
            start.fail(err(MicrovmErrorCode::PermissionDenied, "denied"));
            (
                StopReason::Failed(MicrovmErrorCode::PermissionDenied),
                HvRunStats::default(),
            )
        })
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::PermissionDenied);
        assert_eq!(e.message(), "denied");
    }

    /// NUL を含むスレッド名は panic せず `InvalidArgument`（MVM-5・REPAIR-5）。
    #[test]
    fn mvm5_3791_nul_in_thread_name_is_rejected_without_panic() {
        let e = spawn_loop::<FakeKick, _>("hvf\0test", LONG, |_| {
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), "vcpu thread name must not contain NUL");
    }

    #[test]
    fn mvm5_3791_invalid_deadlines_are_rejected() {
        let e = spawn_loop::<FakeKick, _>("hvf-test", Duration::ZERO, |_| {
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        let kicks = Arc::new(AtomicUsize::new(0));
        let exited = Arc::new(AtomicBool::new(false));
        for bad in [
            Duration::ZERO,
            VCPU_STOP_DEADLINE_MAX + Duration::from_secs(1),
        ] {
            let h = spawn_loop(
                "hvf-test",
                LONG,
                responsive_body(Arc::clone(&kicks), Arc::clone(&exited)),
            )
            .unwrap();
            let e = h.stop(bad).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        }
    }

    /// ゲスト起因で既に終わっていたときは、その理由を返す。
    #[test]
    fn mvm5_3791_stop_after_guest_ended_returns_its_reason() {
        let h = spawn_loop::<FakeKick, _>("hvf-test", LONG, |start| {
            let _stop = start.ready(FakeKick(Arc::new(AtomicUsize::new(0))));
            (
                StopReason::Failed(MicrovmErrorCode::Unimplemented),
                HvRunStats::default(),
            )
        })
        .unwrap();
        let end = Instant::now() + LONG;
        while !h.is_finished() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(h.is_finished());
        let report = h.stop(LONG).unwrap();
        assert_eq!(
            report.reason,
            StopReason::Failed(MicrovmErrorCode::Unimplemented)
        );
    }

    #[test]
    fn mvm5_3791_panicking_body_is_internal() {
        let h = spawn_loop::<FakeKick, _>("hvf-test", LONG, |start| {
            let _stop = start.ready(FakeKick(Arc::new(AtomicUsize::new(0))));
            panic!("injected panic for the vcpu thread test");
        })
        .unwrap();
        let e = h.stop(LONG).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
    }

    #[test]
    fn mvm5_3791_body_ending_before_ready_is_internal() {
        let e = spawn_loop::<FakeKick, _>("hvf-test", LONG, |_start| {
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
    }

    /// drop だけでも停止を要求して終了を待つ。
    #[test]
    fn mvm5_3791_drop_requests_stop_and_waits() {
        let kicks = Arc::new(AtomicUsize::new(0));
        let exited = Arc::new(AtomicBool::new(false));
        let h = spawn_loop(
            "hvf-test",
            LONG,
            responsive_body(Arc::clone(&kicks), Arc::clone(&exited)),
        )
        .unwrap();
        let t = Instant::now();
        drop(h);
        assert!(exited.load(Ordering::SeqCst));
        assert!(t.elapsed() < DROP_STOP_WAIT);
    }
}
