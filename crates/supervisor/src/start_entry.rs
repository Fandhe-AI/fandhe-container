//! supervisor の bin の入口: 起動 → 結果の返却 → 監視（`monitor` / restart）を 1 プロセスで行う処理順
//! （TASK-157 追補・#1717・SUP-1・SUP-3・MS-9。関連: CORE-1・CORE-2・CORE-3・SEC-1・SEC-4・REPAIR-3・REPAIR-4・REPAIR-5・D-19）。
//!
//! 呼び出し元は `src/main.rs`（`run_main`）。CLI（#1718）が [`crate::start_contract`] の契約で起動し、結果チャネル
//! （stdout の pipe）の 1 行を読む。#1314 のオーナー判断（配置 1-A・cgroup 3-ii）により、`oci_runtime::start`
//! （Created → Running の予約と記録）を呼ぶ層は CLI から本入口へ移った。
//!
//! # 処理順（[`run_start`] と [`run_supervised`]）
//! 0. 結果チャネルの検証（stdout が FIFO か。`run_main`）／1. argv の解析（[`crate::start_contract::StartArgs`]）／
//!    2. スレッド数が 1 か（`oci_runtime::start` の前提。以後のスレッドは手順 3〜8 の作業スレッド〔入口は待つだけ〕と手順 10 以降のログ捕捉・restart のワーカーに限る）／
//! 3. 状態の事前確認（Created・pid なし・cgroup 未記録。副作用なし）／4. [`StartDeps::check_launcher_available`]
//!    （副作用なし。本番 launcher が無い間はここで `UNIMPLEMENTED` で止まる）／5. cgroup の連鎖
//!    （[`StartDeps::prepare_cgroup`]）／6. 監査 sink（[`StartDeps::build_audit_sink`]。fork の前）／7. launcher の構築と
//!    [`SpecCapturingLauncher`] での包み／8. `oci_runtime::start`／9. `FCSUP1 OK <pid>` の報告／
//!    10. `SupervisedState::attach` → [`supervise_with_restart`]。
//!
//! 手順 3・4 は cgroup の連鎖（手順 5）より前に置く。スコープの追記は 1 回限りで取り消す API が無いため、
//! launcher が使えない場合や状態が Created でない場合に、スコープを残さずに止める。
//!
//! # 期限と報告の後の後始末（fail-closed。#1541 と同じ要求・REPAIR-5）
//! 手順 3〜8 は作業スレッドで行い、入口は `result_deadline` から [`REPORT_RESERVE`] を引いた時点まで結果を待つ
//! （手順 2 の確認の後に作るスレッドで、入口は Condvar で待つだけでロックを持たない）。報告は期限までに必ず 1 回書き、
//! 後始末は報告の後に行う（契約は [`crate::start_contract`] の「報告の後の後始末」）。
//! - 手順 5〜7 の失敗: 作った cgroup を [`StartDeps::release_cgroup`] で消す。
//! - `start` の失敗（Timeout を含む）は、状態を読み直して分ける。
//!   - Created に戻っている（launch の失敗・launcher 自身が期限内に返した Timeout 等。core の `start` が予約を戻し、
//!     子を terminate 済み）: 予約の解放と core のワーカー完了を確かめてから cgroup を消す。
//!   - 予約（Running・pid なし）が残る（呼び出し境界の期限超過）: 本入口が終了すると core の後始末スレッドごと
//!     消えるため、`recover_interrupted_start` を約 50ms 刻みで再試行して Created へ戻し、`take_unreaped_processes`
//!     で引き取ったハンドルを terminate する。戻せたら cgroup を消し、戻せなければ cgroup を消さない。
//! - 期限超過: `INTERNAL`（[`DEADLINE_EXCEEDED_MESSAGE`]）を報告し、作業スレッドの完了を有限の期限まで待って、
//!   後から成功していれば起動したプロセスを terminate して `Stopped` を記録する。
//! - 後始末を確かめられなければ終了コードは `INTERNAL`。後始末自体の失敗は元のエラーを隠さず、構造化ログ（stderr）に出す。
//! - 失敗した start の後もスコープは記録されたまま残る（core に記録済みの配置から連鎖を再開する API が無い）。
//!   同じコンテナの再 start は手順 3 で `FailedPrecondition` になる。
//!
//! # 未実装（REPAIR-3）
//! core の本番 `ProcessLauncher`（#1715 の Phase B。`oci_runtime/launcher.rs`・`SelfBoundedLaunch`・状態 pipe 等）が
//! main に無いため、`ProductionStartDeps` は手順 4 で `UNIMPLEMENTED` を返す（実機でコンテナは起動しない）。
//! Phase B が入ったら `check_launcher_available` / `build_launcher` を差し替え、`IsolationPrivilege` を launcher の
//! 構成から渡す。それ以外の処理順・報告・後始末・relaunch のアダプタは本ファイルで確定済みで、フェイクの
//! [`StartDeps`] を使う試験（`tests/start_entry.rs`）が照合する。

use std::io::Write;
use std::num::{NonZeroU8, NonZeroU32};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_core::oci_runtime::{
    LAUNCHER_REPLY_GRACE, LaunchSpec, LaunchedProcess, LifecycleOp, OciRuntimeError,
    ProcessLauncher, StartTimeouts, exit_code_for, recover_interrupted_start, start,
    take_unreaped_processes,
};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ContainerStatus, ErrorCode, GetStateRequest, StartRequest,
    StateRecord, StateRevision, StateStore, SupervisionState, TraitError, UpdateStateRequest,
};

use crate::log_pipeline::CaptureHub;
use crate::logs::LogSink;
use crate::restart::{
    LateOrphans, LauncherRelauncher, Relauncher, RestartConfig, RestartPolicy,
    SpecCapturingLauncher, SuperviseOutcome, supervise_with_restart,
};
use crate::run::{MonitorConfig, StderrLogObserver, StopToken};
use crate::start_contract::StartReport;
use crate::state::SupervisedState;

/// 監視ループの 1 回の `wait` の上限（restart レイテンシに効くため短くする）。
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// `recover_interrupted_start` の再試行間隔。
const RECOVER_RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// 起動手順の副作用を持つ部分の注入点（フェイクと本番の差し替えはここ 1 か所）。
///
/// 呼ばれる順は [`run_start`] の doc の手順 4〜7 と §後始末のとおり。
pub trait StartDeps {
    /// 手順 4: 本番 launcher を作れるかの事前確認（副作用なし）。使えなければ `Unimplemented` 等で fail-closed。
    fn check_launcher_available(&self) -> Result<(), TraitError>;

    /// 手順 5: cgroup の連鎖（スコープの記録 → mkdir → 制限 → 参加フック）。`observed` は事前確認済みのレコード。
    /// 成功した cgroup は実装が保持し、[`Self::release_cgroup`] と [`Self::build_launcher`] が使う。
    ///
    /// 記録したスコープの instance（`CgroupScope::instance`）を返す（スコープを記録しない実装は `None`）。
    /// 入口は launch の時点（core の起動権の予約の後）のレコードとこれを照合し、同じ ID の削除・再作成で世代が
    /// 変わっていれば launch しない（CORE-2・CORE-3・SEC-1）。
    fn prepare_cgroup(
        &mut self,
        store: &dyn StateStore,
        observed: &StateRecord,
    ) -> Result<Option<StateRevision>, TraitError>;

    /// 手順 6: 監査 sink を構築する（fork の前。SEC-4）。実装が保持し [`Self::build_launcher`] が使う。
    fn build_audit_sink(&mut self) -> Result<(), TraitError>;

    /// 手順 6: コンテナの stdout / stderr の記録先（ログ sink）を開く（fork の前。TASK-164 追補・#1471・SUP-7）。
    ///
    /// `Some` を返すと、入口は捕捉ハブ（[`CaptureHub`]）を作り、起動・再起動のたびに新プロセスの出力を行単位で
    /// この sink へ流す。開けなければ失敗させる（ログ喪失を黙って許さない。ERR-1・REPAIR-4）。既定は `None`
    /// （出力は記録せず読み捨てる。フェイクの [`StartDeps`] は上書きしなくてよい）。
    fn open_log_sink(&mut self, id: &ContainerId) -> Result<Option<Arc<dyn LogSink>>, TraitError> {
        let _ = id;
        Ok(None)
    }

    /// 手順 7: launcher を構築する（保持している cgroup の参加フックと監査 sink を使う）。
    fn build_launcher(&mut self) -> Result<Arc<dyn ProcessLauncher>, TraitError>;

    /// 作った cgroup を消す（`remove_child`）。mkdir 前なら何もしない。
    fn release_cgroup(&mut self) -> Result<(), TraitError>;
}

/// 起動に成功したコンテナの、監視に必要なもの。
#[must_use = "the launched process must be monitored and reaped by its owner"]
pub struct Running {
    /// 起動済みプロセスのハンドル（回収責任は監視側。CORE-1）。
    pub process: Box<dyn LaunchedProcess>,
    /// restart の再 launch（start で使った launcher と `LaunchSpec` をそのまま使う。SUP-3）。
    pub relauncher: Arc<dyn Relauncher>,
    /// start が返したレコードの cgroup の instance（無ければ `None`）。回収後の `Stopped` 記録で、同じ ID の
    /// 削除・再作成による別インスタンスのレコードを上書きしないための照合に使う（CORE-2・SEC-1）。
    pub instance: Option<StateRevision>,
    /// コンテナ出力の捕捉ハブ（ログ sink を開いたときだけ。`run_supervised` が初回の出力を渡し、全終了経路で畳む。
    /// 再起動後の出力は `relauncher` が同じハブへ渡す。TASK-164 追補・#1471・SUP-7）。
    pub logs: Option<Arc<CaptureHub>>,
}

/// spec を捕捉できなかったときの再 launch（常に失敗させる。fail-closed）。
struct NoSpecRelauncher;

impl Relauncher for NoSpecRelauncher {
    fn relaunch(&self, _timeout: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        Err(TraitError::new(
            ErrorCode::Internal,
            "launch spec was not captured",
        ))
    }
}

/// 書き込みを別スレッドで行い、期限までに終わらなければ `TimedOut` を返す書き手（REPAIR-5）。
///
/// 読み手が止まって pipe が満杯でも、呼び出し側は期限で次へ進める（起動済みプロセスの監視・回収を止めない）。
/// 期限後も書き込みスレッドは残り得るが、完了すれば終わる。1 回の `write_all` を 1 スレッドで行うため、
/// 単一スレッド前提の区間（`oci_runtime::start` より前）の成功経路では使わない。
pub struct BoundedWriter<W: Write + Send + 'static> {
    inner: Arc<Mutex<W>>,
    deadline: Duration,
    /// 全体の期限（`Some` なら 1 回の上限を残り時間で切り詰める）。
    until: Option<Instant>,
}

impl<W: Write + Send + 'static> BoundedWriter<W> {
    /// `deadline` を 1 回の書き込みの上限にして包む。
    pub fn new(inner: W, deadline: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
            deadline,
            until: None,
        }
    }

    /// 以後の書き込みの上限を `min(deadline, until までの残り)` にする（報告を内部上限内に収める。REPAIR-5）。
    pub fn limit_until(&mut self, until: Option<Instant>) {
        self.until = until;
    }
}

/// 1 回の書き込みの上限: `min(base, until までの残り)`（`until` が `None` なら `base`、過ぎていれば 0）。
fn write_limit(base: Duration, until: Option<Instant>, now: Instant) -> Duration {
    until.map_or(base, |u| base.min(u.saturating_duration_since(now)))
}

impl<W: Write + Send + 'static> Write for BoundedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_all(buf)?;
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        let inner = Arc::clone(&self.inner);
        let data = buf.to_vec();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("supervisor-write".into())
            .spawn(move || {
                let mut guard = inner.lock().unwrap_or_else(PoisonError::into_inner);
                let result = guard.write_all(&data).and_then(|()| guard.flush());
                let _ = tx.send(result);
            })
            .map_err(|_| std::io::Error::other("failed to spawn the write thread"))?;
        match rx.recv_timeout(write_limit(self.deadline, self.until, Instant::now())) {
            Ok(result) => result,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "write deadline exceeded",
            )),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // 各 `write_all` が flush まで行う。
        Ok(())
    }
}

/// 構造化ログを stderr に 1 行出す（値は固定語彙だけ。入力値・OS のエラー文字列は載せない。REPAIR-4）。
///
/// stderr の読み手が止まっても回収・監視を止めないよう、[`crate::stderr_sink`] の専用スレッドへ渡すだけで待たない
/// （キューが満杯なら捨てる。REPAIR-5）。
fn log_event(event: &'static str, code: Option<ErrorCode>) {
    let code = code.map(|c| c.as_str()).unwrap_or("");
    let line =
        format!("{{\"component\":\"supervisor\",\"event\":\"{event}\",\"code\":\"{code}\"}}\n");
    // 満杯・書き込み失敗でも処理は止めない（ログの欠落は許す）。
    let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
}

/// 回収を確かめられなかったハンドルの保管先（`Drop` は回収しないため、捨てずに保持する。REPAIR-5）。
static STRANDED: Mutex<Vec<Box<dyn LaunchedProcess>>> = Mutex::new(Vec::new());

fn keep_stranded(process: Box<dyn LaunchedProcess>) {
    STRANDED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(process);
}

/// [`terminate_bounded`] の実行スレッドと待ち手の間の受け渡し状態（同じ Mutex で守る）。
enum TerminateSlot {
    /// 実行スレッドの結果待ち。
    Pending,
    /// 実行スレッドの結果（`Err` ならハンドルを返す）。
    Done(Result<(), (ErrorCode, Box<dyn LaunchedProcess>)>),
    /// 待ち手が期限で待ちをやめた（または結果を取り出した）。
    Abandoned,
}

/// 実行スレッドの終了時に [`LateOrphans`] へ通知するガード。
struct LateWorkerGuard(LateOrphans);

impl Drop for LateWorkerGuard {
    fn drop(&mut self) {
        self.0.worker_finished();
    }
}

/// [`terminate_bounded`] の失敗。
enum TerminateFailure {
    /// 期限内に `Err` で戻った（または実行スレッドを作れなかった）。ハンドルは手元にあり再試行できる。
    Returned(Box<dyn LaunchedProcess>),
    /// 期限内に戻らなかった。ハンドルは実行スレッドが持つ（`Err` で戻れば [`STRANDED`] へ入る）。
    Pending,
}

/// ハンドルの所有権を別スレッドへ渡して `terminate` を呼び、呼び出し境界でも期限を強制する（REPAIR-5）。
///
/// 実装が `timeout` を守らず戻らない場合も、本関数は `timeout` に猶予を足した時点で `Pending` を返す。
/// 回収を確かめられたら回収した pid を返す。`Err` で戻ったハンドルは捨てずに返す（再試行のため）。
/// 実行スレッドは `late` に登録し、待ちを打ち切った後に terminate が成功したら pid を `late` に積む
/// （restart の後始末と同じ仕組み。呼び出し側は [`LateOrphans::wait_settled`] の後に `take_reaped` で受け取る）。
fn terminate_bounded(
    process: Box<dyn LaunchedProcess>,
    timeout: Duration,
    late: &LateOrphans,
) -> Result<NonZeroU32, TerminateFailure> {
    let pid = process.pid();
    let cell = Arc::new(Mutex::new(Some(process)));
    // 結果の引き渡しと待ちの放棄を同じ Mutex 配下で決める（期限後に戻ったハンドルを必ず保管先へ移す。CORE-1・REPAIR-5）。
    let shared: Arc<(Mutex<TerminateSlot>, Condvar)> =
        Arc::new((Mutex::new(TerminateSlot::Pending), Condvar::new()));
    let (worker_cell, worker_shared, worker_late) =
        (Arc::clone(&cell), Arc::clone(&shared), late.clone());
    late.worker_started();
    let spawned = std::thread::Builder::new()
        .name("supervisor-terminate".into())
        .spawn(move || {
            // 全経路（panic を含む）で実行スレッドの終了を通知する。
            let _finished = LateWorkerGuard(worker_late.clone());
            let taken = worker_cell
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            let Some(p) = taken else {
                return;
            };
            let result = p.terminate(timeout).map_err(|e| e.code());
            let (lock, cvar) = &*worker_shared;
            let mut slot = lock.lock().unwrap_or_else(PoisonError::into_inner);
            if matches!(*slot, TerminateSlot::Abandoned) {
                // 受け手は待ちをやめた。`Err` のハンドルは捨てずに保管し、`Ok` は回収済みの pid を残す。
                drop(slot);
                match result {
                    Ok(()) => worker_late.push_reaped(pid),
                    Err(_) => keep_stranded(p),
                }
                return;
            }
            *slot = TerminateSlot::Done(result.map_err(|code| (code, p)));
            cvar.notify_all();
        });
    if spawned.is_err() {
        late.worker_finished();
        log_event("terminate_thread_failed", None);
        let left = cell.lock().unwrap_or_else(PoisonError::into_inner).take();
        return Err(left.map_or(TerminateFailure::Pending, TerminateFailure::Returned));
    }
    let deadline = Instant::now().checked_add(timeout.saturating_add(LAUNCHER_REPLY_GRACE));
    let (lock, cvar) = &*shared;
    let mut slot = lock.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        match std::mem::replace(&mut *slot, TerminateSlot::Abandoned) {
            TerminateSlot::Done(Ok(())) => return Ok(pid),
            TerminateSlot::Done(Err((code, p))) => {
                drop(slot);
                log_event("handle_terminate_failed", Some(code));
                return Err(TerminateFailure::Returned(p));
            }
            other => *slot = other,
        }
        let now = Instant::now();
        let remaining = match deadline {
            Some(d) if d > now => d - now,
            _ => {
                // 同じロックの下で放棄を記す。以後に戻った結果は実行スレッドが保管する。
                *slot = TerminateSlot::Abandoned;
                drop(slot);
                log_event("handle_terminate_timed_out", Some(ErrorCode::Timeout));
                return Err(TerminateFailure::Pending);
            }
        };
        slot = cvar
            .wait_timeout(slot, remaining)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

/// [`terminate_bounded`] を、`Err` で戻ったハンドルについて 1 回だけ再試行する。回収できたらその pid。
///
/// 再試行も失敗したハンドルは [`STRANDED`] に保管する（`Drop` で捨てて子を孤児化させない）。
/// 待ちを打ち切った後に成功した回収は、もう 1 回分の期限（`timeout`＋猶予）まで待って pid を返す。
/// 1 回の待ちは `timeout`＋猶予で打ち切るため、全体も有限時間で終わる（REPAIR-5）。
fn terminate_retrying(process: Box<dyn LaunchedProcess>, timeout: Duration) -> Option<NonZeroU32> {
    let pid = process.pid();
    let late = LateOrphans::default();
    let mut process = process;
    for _ in 0..2 {
        match terminate_bounded(process, timeout, &late) {
            Ok(pid) => return Some(pid),
            Err(TerminateFailure::Pending) => {
                // 待ちを打ち切った後に成功した回収も、もう 1 回分の期限まで待って受け取る（Stopped 記録の対象。
                // SUP-1・CORE-2）。それでも戻らなければ確かめられなかった扱い。
                let settled = late.wait_settled(timeout.saturating_add(LAUNCHER_REPLY_GRACE));
                if settled && late.take_reaped().contains(&pid) {
                    log_event("handle_terminated_late", None);
                    return Some(pid);
                }
                return None;
            }
            Err(TerminateFailure::Returned(p)) => process = p,
        }
    }
    keep_stranded(process);
    None
}

fn op_err(e: TraitError) -> OciRuntimeError {
    OciRuntimeError::from_trait_error(LifecycleOp::Start, e)
}

/// 報告 1 行を書いて flush する。
fn write_report(out: &mut dyn Write, report: &StartReport) -> std::io::Result<()> {
    out.write_all(report.encode().as_bytes())?;
    out.flush()
}

/// cgroup を消す。失敗は元のエラーを隠さずにログへ出し、`false` を返す（後始末の成否へ反映する）。
fn release_logged(deps: &mut dyn StartDeps) -> bool {
    match deps.release_cgroup() {
        Ok(()) => true,
        Err(e) => {
            log_event("cgroup_release_failed", Some(e.code()));
            false
        }
    }
}

/// 期限までに起動の結果が出なかったときの報告の message。
pub const DEADLINE_EXCEEDED_MESSAGE: &str = "start did not finish within the result deadline; the container stays reserved until cleanup ends";

/// 期限超過の報告を書くために、結果待ちを `result_deadline` より手前で打ち切る幅（報告の書き込みに残す時間）。
pub const REPORT_RESERVE: Duration = Duration::from_secs(1);

/// 起動の計測に使う操作名（`OpRecorder`。REPAIR-4）。
pub const START_OP: &str = "supervisor.start";

/// 手順 3〜9（報告まで）と、報告の後の後始末。成功なら `Running`、失敗なら終了コード。
///
/// 起動処理（手順 3〜8）は作業スレッドで行い、本関数は `deadline` から [`REPORT_RESERVE`] を引いた時点まで結果を
/// 待つ。報告（`out` への 1 行）は期限までに必ず 1 回書き、失敗後の後始末（予約・cgroup の解放・terminate・
/// `Stopped` の記録）は報告の後に行う（REPAIR-5。core の API を変えずに起動処理全体へ期限を課す）。
/// - 期限内に成功: `OK <pid>` を報告して `Ok(Running)`（報告の書き込みに失敗しても監視は続ける）。
/// - 期限内に失敗: そのエラーを報告してから後始末する。後始末を確かめられなければ終了コードは `Internal`。
/// - 期限超過: `INTERNAL`（[`DEADLINE_EXCEEDED_MESSAGE`]）を報告し、作業スレッドの完了を `result_deadline` の長さ
///   まで待つ。後から成功していれば起動したプロセスを terminate して `Stopped` を記録し、失敗していれば同じ後始末を
///   する。終了コードは `Internal`。それでも戻らなければ待つのをやめる（プロセスの終了で作業スレッドも終わる）。
///
/// 起動の成否とレイテンシは `recorder` の [`START_OP`] に記録し、本関数の最後に構造化ログ 1 行
/// （[`start_metrics_line`]）で出す。
pub fn run_start(
    deps: Box<dyn StartDeps + Send>,
    store: &Arc<dyn StateStore>,
    recorder: &Arc<OpRecorder>,
    req: &StartRequest,
    timeouts: &StartTimeouts,
    out: &mut dyn Write,
) -> Result<Running, NonZeroU8> {
    let deadline = Instant::now().checked_add(crate::start_contract::result_deadline(timeouts));
    run_start_until(deps, store, recorder, req, timeouts, deadline, out)
}

/// [`run_start`] の全体の期限を呼び出し側が渡す版（bin の入口は同じ期限で報告の書き込みも切り詰める）。
pub fn run_start_until(
    deps: Box<dyn StartDeps + Send>,
    store: &Arc<dyn StateStore>,
    recorder: &Arc<OpRecorder>,
    req: &StartRequest,
    timeouts: &StartTimeouts,
    deadline: Option<Instant>,
    out: &mut dyn Write,
) -> Result<Running, NonZeroU8> {
    let result = start_reporting(deps, store, recorder, req, timeouts, deadline, out);
    // 満杯・書き込み失敗でも処理は止めない（ログの欠落は許す）。
    let _ = crate::stderr_sink::stderr().emit(start_metrics_line(recorder).into_bytes());
    result
}

/// [`run_start_until`] の本体（計測ログの出力を除く）。
fn start_reporting(
    deps: Box<dyn StartDeps + Send>,
    store: &Arc<dyn StateStore>,
    recorder: &Arc<OpRecorder>,
    req: &StartRequest,
    timeouts: &StartTimeouts,
    deadline: Option<Instant>,
    out: &mut dyn Write,
) -> Result<Running, NonZeroU8> {
    let worker = match StartWorker::spawn(deps, store, recorder, req, *timeouts) {
        Ok(w) => w,
        Err(e) => {
            let err = op_err(e);
            report(out, &StartReport::failed(&err));
            return Err(err.exit_code());
        }
    };
    let wait_until = deadline.map(|d| d.checked_sub(REPORT_RESERVE).unwrap_or(d));
    if let Some((deps, attempt)) = worker.wait_until(wait_until) {
        return match attempt {
            Attempt::Started(running) => {
                report(
                    out,
                    &StartReport::Started {
                        pid: running.process.pid(),
                    },
                );
                Ok(running)
            }
            Attempt::Failed { error, cleanup } => {
                report(out, &StartReport::failed(&error));
                if cleanup_after_report(deps, store.as_ref(), req.id(), timeouts, cleanup) {
                    Err(error.exit_code())
                } else {
                    Err(exit_code_for(ErrorCode::Internal))
                }
            }
        };
    }
    // 期限超過: 先に報告し、作業スレッドの結果を有限の期限まで待ってから後始末する。
    let overdue = OciRuntimeError::new(
        LifecycleOp::Start,
        ErrorCode::Internal,
        DEADLINE_EXCEEDED_MESSAGE,
    );
    log_event("start_deadline_exceeded", Some(ErrorCode::Timeout));
    report(out, &StartReport::failed(&overdue));
    let late_until = Instant::now().checked_add(crate::start_contract::result_deadline(timeouts));
    match worker.wait_or_abandon(late_until) {
        Some((_deps, Attempt::Started(running))) => {
            // 報告済みは INTERNAL のため、起動したものを残さない（CORE-1・SUP-1）。
            let Running {
                process, instance, ..
            } = running;
            match terminate_retrying(process, timeouts.terminate()) {
                Some(pid) => {
                    log_event("late_start_terminated", None);
                    // 終了コードは既に Internal。記録の失敗はログに残る。
                    let _ = mark_stopped(store, req.id(), instance, &[pid]);
                }
                None => log_event("late_start_terminate_failed", None),
            }
        }
        Some((deps, Attempt::Failed { cleanup, .. })) => {
            let _ = cleanup_after_report(deps, store.as_ref(), req.id(), timeouts, cleanup);
        }
        None => {
            // 作業スレッドがまだ戻らない（放棄は待ちの打ち切りと同じロックの下で記した）。以後に戻った結果は
            // 作業スレッドが後始末する（プロセスの終了まで）。
            log_event("start_worker_abandoned", Some(ErrorCode::Timeout));
        }
    }
    Err(exit_code_for(ErrorCode::Internal))
}

/// 報告 1 行を書く（失敗はログに出すだけで、監視・後始末は続ける）。
fn report(out: &mut dyn Write, report: &StartReport) {
    if write_report(out, report).is_err() {
        log_event("report_failed", None);
    }
}

/// 起動の計測結果の構造化ログ 1 行（JSON。キーは英語・値は検証済みの操作名と数値のみ。REPAIR-4）。
///
/// `{"component":"supervisor","event":"start_metrics","ops":[{"op":"supervisor.start","success":1,"failure":0,
/// "p95_us":120,"max_us":150}],"dropped_records":0}` の形（標本が無ければ `p95_us`・`max_us` は `null`）。
pub fn start_metrics_line(recorder: &OpRecorder) -> String {
    let ops: Vec<String> = recorder
        .snapshot()
        .iter()
        .map(|op| {
            let (p95, max) = op
                .latency()
                .map_or(("null".to_owned(), "null".to_owned()), |l| {
                    (
                        l.p95().as_micros().to_string(),
                        l.max().as_micros().to_string(),
                    )
                });
            format!(
                "{{\"op\":\"{}\",\"success\":{},\"failure\":{},\"p95_us\":{p95},\"max_us\":{max}}}",
                op.name().as_str(),
                op.success(),
                op.failure()
            )
        })
        .collect();
    format!(
        "{{\"component\":\"supervisor\",\"event\":\"start_metrics\",\"ops\":[{}],\"dropped_records\":{}}}\n",
        ops.join(","),
        recorder.dropped_records()
    )
}

/// 作業スレッドで行った起動の結果（報告の材料と、報告の後の後始末に要るもの）。
enum Attempt {
    Started(Running),
    Failed {
        error: OciRuntimeError,
        cleanup: Cleanup,
    },
}

/// 報告の後に行う後始末の種類。
enum Cleanup {
    /// cgroup の準備より前の失敗（後始末なし）。
    Nothing,
    /// cgroup の準備・監査 sink・launcher の構築の失敗（作った cgroup を消す）。
    ReleaseCgroup,
    /// `start` が失敗（Timeout を含む。予約が残れば Created へ戻し、予約の解放と core のワーカー完了を確かめ、
    /// 未回収のハンドルを terminate してから cgroup を消す）。
    AfterFailure(Arc<dyn ProcessLauncher>, Vec<Box<dyn LaunchedProcess>>),
}

/// 起動の作業スレッドと入口の間の受け渡し状態（同じ Mutex で守る）。
enum WorkerSlot {
    Pending,
    Done(Box<dyn StartDeps + Send>, Attempt),
    /// 入口が結果を取り出した、または待つのをやめた（以後の結果は作業スレッドが後始末する）。
    Abandoned,
}

/// 起動処理（手順 3〜8）を行う作業スレッド。
struct StartWorker {
    shared: Arc<(Mutex<WorkerSlot>, Condvar)>,
}

impl StartWorker {
    fn spawn(
        deps: Box<dyn StartDeps + Send>,
        store: &Arc<dyn StateStore>,
        recorder: &Arc<OpRecorder>,
        req: &StartRequest,
        timeouts: StartTimeouts,
    ) -> Result<Self, TraitError> {
        let shared = Arc::new((Mutex::new(WorkerSlot::Pending), Condvar::new()));
        let worker_shared = Arc::clone(&shared);
        let (store, recorder, req) = (Arc::clone(store), Arc::clone(recorder), req.clone());
        // 起動は作業スレッドが行い、入口は Condvar で待つだけでロックを持たない（core の launch も別スレッドで行われる）。
        std::thread::Builder::new()
            .name("supervisor-start".into())
            .spawn(move || {
                let mut deps = deps;
                let started = Instant::now();
                let attempt = attempt_start(deps.as_mut(), &store, &recorder, &req, &timeouts);
                let outcome = if matches!(attempt, Attempt::Started(_)) {
                    OpOutcome::Success
                } else {
                    OpOutcome::Failure
                };
                if let Ok(name) = OpName::new(START_OP) {
                    let _ = recorder.record(&name, outcome, started.elapsed());
                }
                let (lock, cvar) = &*worker_shared;
                let mut slot = lock.lock().unwrap_or_else(PoisonError::into_inner);
                if matches!(*slot, WorkerSlot::Abandoned) {
                    drop(slot);
                    abandoned_cleanup(deps, &store, req.id(), &timeouts, attempt);
                    return;
                }
                *slot = WorkerSlot::Done(deps, attempt);
                cvar.notify_all();
            })
            .map_err(|_| {
                TraitError::new(ErrorCode::Internal, "failed to spawn the start worker")
            })?;
        Ok(Self { shared })
    }

    /// `until` まで結果を待ち、出ていれば取り出す（`None` は無期限）。
    fn wait_until(&self, until: Option<Instant>) -> Option<(Box<dyn StartDeps + Send>, Attempt)> {
        let (lock, cvar) = &*self.shared;
        let mut slot = lock.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if matches!(*slot, WorkerSlot::Done(..)) {
                // 取り出した後は Abandoned にして二重に取り出さない。
                return match std::mem::replace(&mut *slot, WorkerSlot::Abandoned) {
                    WorkerSlot::Done(deps, attempt) => Some((deps, attempt)),
                    _ => None,
                };
            }
            let wait = match until {
                Some(u) => match u.checked_duration_since(Instant::now()) {
                    Some(r) if !r.is_zero() => r,
                    _ => return None,
                },
                None => Duration::from_secs(3600),
            };
            slot = cvar
                .wait_timeout(slot, wait)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// [`Self::wait_until`] と同じだが、期限までに結果が出なければ同じロックの下で放棄を記して `None` を返す
    /// （打ち切りと放棄の間に格納された結果を捨てない。以後の結果は作業スレッドが後始末する）。
    fn wait_or_abandon(
        &self,
        until: Option<Instant>,
    ) -> Option<(Box<dyn StartDeps + Send>, Attempt)> {
        let (lock, cvar) = &*self.shared;
        let mut slot = lock.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if matches!(*slot, WorkerSlot::Done(..)) {
                return match std::mem::replace(&mut *slot, WorkerSlot::Abandoned) {
                    WorkerSlot::Done(deps, attempt) => Some((deps, attempt)),
                    _ => None,
                };
            }
            let wait = match until {
                Some(u) => match u.checked_duration_since(Instant::now()) {
                    Some(r) if !r.is_zero() => r,
                    _ => {
                        *slot = WorkerSlot::Abandoned;
                        return None;
                    }
                },
                None => Duration::from_secs(3600),
            };
            slot = cvar
                .wait_timeout(slot, wait)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

/// 入口が待つのをやめた後に作業スレッドが戻ったときの後始末（best effort。プロセスの終了までに終われば行う）。
fn abandoned_cleanup(
    deps: Box<dyn StartDeps + Send>,
    store: &Arc<dyn StateStore>,
    id: &ContainerId,
    timeouts: &StartTimeouts,
    attempt: Attempt,
) {
    match attempt {
        Attempt::Started(running) => {
            // 入口の期限後の成功と同じく、terminate できたら照合つきで Stopped を記録する（SUP-1・CORE-2）。
            if let Some(pid) = terminate_retrying(running.process, timeouts.terminate()) {
                let _ = mark_stopped(store, id, running.instance, &[pid]);
            }
        }
        Attempt::Failed { cleanup, .. } => {
            let _ = cleanup_after_report(deps, store.as_ref(), id, timeouts, cleanup);
        }
    }
}

/// 報告の後の後始末。確かめられたら `true`（確かめられなければ cgroup は消さない。CORE-1・CORE-2）。
fn cleanup_after_report(
    mut deps: Box<dyn StartDeps + Send>,
    store: &dyn StateStore,
    id: &ContainerId,
    timeouts: &StartTimeouts,
    cleanup: Cleanup,
) -> bool {
    let confirmed = match cleanup {
        Cleanup::Nothing => return true,
        Cleanup::ReleaseCgroup => return release_logged(deps.as_mut()),
        Cleanup::AfterFailure(launcher, pending) => {
            settle_failed_start(store, &launcher, id, timeouts, pending)
        }
    };
    if confirmed {
        // cgroup の削除の失敗も後始末の失敗として返す（終了コードを INTERNAL にする。CORE-3）。
        release_logged(deps.as_mut())
    } else {
        // 予約か子が残り得る。cgroup は消さない（子が入っている可能性がある）。
        log_event("start_cleanup_unconfirmed", Some(ErrorCode::Internal));
        false
    }
}

/// 手順 3〜8（作業スレッドで実行）。後始末は行わず、要る後始末の種類を返す。
fn attempt_start(
    deps: &mut dyn StartDeps,
    store_arc: &Arc<dyn StateStore>,
    recorder: &OpRecorder,
    req: &StartRequest,
    timeouts: &StartTimeouts,
) -> Attempt {
    let fail = |e: TraitError, cleanup: Cleanup| Attempt::Failed {
        error: op_err(e),
        cleanup,
    };
    let store: &dyn StateStore = store_arc.as_ref();
    // 3: 副作用なしの事前確認。
    let observed = match store.get(&GetStateRequest::new(req.id().clone())) {
        Ok(r) => r,
        Err(e) => return fail(e, Cleanup::Nothing),
    };
    let status = observed.status();
    if status.state() != ContainerState::Created || status.pid().is_some() {
        return fail(
            TraitError::new(
                ErrorCode::FailedPrecondition,
                "container is not in created state",
            ),
            Cleanup::Nothing,
        );
    }
    if observed.cgroup().is_some() {
        return fail(
            TraitError::new(
                ErrorCode::FailedPrecondition,
                "cgroup scope is already recorded; delete and recreate the container",
            ),
            Cleanup::Nothing,
        );
    }
    // 4: 副作用なしで launcher の可用性を確かめる。
    if let Err(e) = deps.check_launcher_available() {
        return fail(e, Cleanup::Nothing);
    }
    // 5〜7: ここから先の失敗は、作った cgroup を報告の後に消す。
    let prepared = match deps.prepare_cgroup(store, &observed) {
        Ok(instance) => instance,
        Err(e) => return fail(e, Cleanup::ReleaseCgroup),
    };
    if let Err(e) = deps.build_audit_sink() {
        return fail(e, Cleanup::ReleaseCgroup);
    }
    let logs = match deps.open_log_sink(req.id()) {
        // 記録先が無くても出力パイプは読み捨てる（読まないとコンテナの write が詰まる。SUP-1・SUP-7・REPAIR-5）。
        Ok(sink) => Some(Arc::new(CaptureHub::new(sink.unwrap_or_else(|| {
            Arc::new(crate::logs::DiscardLogSink) as Arc<dyn LogSink>
        })))),
        Err(e) => return fail(e, Cleanup::ReleaseCgroup),
    };
    let inner = match deps.build_launcher() {
        Ok(l) => l,
        Err(e) => return fail(e, Cleanup::ReleaseCgroup),
    };
    let checked: Arc<dyn ProcessLauncher> = Arc::new(InstanceCheckedLauncher {
        inner: Arc::clone(&inner),
        store: Arc::clone(store_arc),
        id: req.id().clone(),
        expected: prepared,
    });
    let capturing = Arc::new(SpecCapturingLauncher::new(checked));
    let launcher: Arc<dyn ProcessLauncher> = capturing.clone();
    // 8
    match start(store, recorder, &launcher, req, timeouts) {
        Ok(started) => {
            let (record, process) = started.into_parts();
            let instance = record.cgroup().map(|c| c.instance());
            let relauncher: Arc<dyn Relauncher> = match capturing.captured_spec() {
                Some(spec) => {
                    let relauncher = LauncherRelauncher::new(inner, spec);
                    match &logs {
                        Some(hub) => Arc::new(relauncher.with_capture(Arc::clone(hub))),
                        None => Arc::new(relauncher),
                    }
                }
                None => Arc::new(NoSpecRelauncher),
            };
            Attempt::Started(Running {
                process,
                relauncher,
                instance,
                logs,
            })
        }
        // Timeout を含むすべての失敗を同じ確認に通す。呼び出し境界の期限超過なら予約（Running・pid なし）が残るので
        // 回復し、launcher 自身が期限内に Timeout 等を返したなら core が予約を Created へ戻し済みなので解放を確かめる。
        // 記録の失敗後に terminate も失敗・超過した場合、core はハンドルを未回収レジストリに残して返す。
        // レジストリが空でも、core の後始末スレッドがハンドルを保持中・予約が Running のまま残る場合があるため、
        // 報告の後に状態と core の予約の解放を確かめてから cgroup を消す（CORE-1・CORE-2・CORE-3）。
        Err(e) => Attempt::Failed {
            error: e,
            cleanup: Cleanup::AfterFailure(launcher, take_unreaped_processes()),
        },
    }
}
/// launch の時点で、レコードの cgroup の instance が [`StartDeps::prepare_cgroup`] の準備した世代と一致するかを
/// 確かめてから内側の launcher へ委ねる（CORE-2・CORE-3・SEC-1）。
///
/// core の `start` は起動権の予約（revision 照合つきの Created → Running〔pid なし〕）を済ませてから launch を呼び、
/// 予約中のレコードは delete が拒否する。そのためこの時点の照合で、準備の後・予約の前に同じ ID が削除・再作成された
/// 場合（別世代の bundle を旧世代の cgroup で起動する経路）を漏れなく拒否できる。拒否すると core は予約を Created へ
/// 戻し、入口は準備した cgroup を消す。
struct InstanceCheckedLauncher {
    inner: Arc<dyn ProcessLauncher>,
    store: Arc<dyn StateStore>,
    id: ContainerId,
    expected: Option<StateRevision>,
}

impl ProcessLauncher for InstanceCheckedLauncher {
    /// 内側の launcher の時間上限の守り方を転送する（転送しないと `SelfBounded` が `CallerBounded` へ
    /// 降格し、単一スレッドを要求する本番 launcher が拒否される。REPAIR-5・#1816）。
    fn launch_mode(&self) -> fandhe_container_core::oci_runtime::LaunchMode {
        self.inner.launch_mode()
    }

    /// 内側の launcher の監査 sink を転送する(転送しないと既定の `None` になり、start の設定検証での拒否が
    /// 本番で監査に記録されず黙って落ちる。SEC-4・#1915)。
    fn rejection_audit_sink(&self) -> Option<&dyn fandhe_container_core::audit_log::AuditSink> {
        self.inner.rejection_audit_sink()
    }

    /// 内側の launcher の「子が残り得る」判定を転送する(転送しないと既定の `false` になり、回収できなかった
    /// 子が残るのに起動予約が戻る。CORE-2)。
    fn last_launch_may_have_left_process(&self) -> bool {
        self.inner.last_launch_may_have_left_process()
    }

    fn launch(
        &self,
        spec: &LaunchSpec,
        timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        let record = self.store.get(&GetStateRequest::new(self.id.clone()))?;
        if record.cgroup().map(|c| c.instance()) != self.expected {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "the container was recreated after its cgroup was prepared",
            ));
        }
        self.inner.launch(spec, timeout)
    }

    fn confirm_no_process(&self, id: &ContainerId, timeout: Duration) -> Result<(), TraitError> {
        self.inner.confirm_no_process(id, timeout)
    }
}

/// `start` 失敗後に予約を Created へ戻し、未回収のハンドル（`extra` と登録済み分）を terminate する。
/// 両方済んだら `true`。
fn recover_after_timeout(
    store: &dyn StateStore,
    launcher: &Arc<dyn ProcessLauncher>,
    id: &ContainerId,
    timeouts: &StartTimeouts,
    extra: Vec<Box<dyn LaunchedProcess>>,
) -> bool {
    let limit = timeouts
        .terminate()
        .saturating_add(timeouts.confirm())
        .saturating_add(LAUNCHER_REPLY_GRACE.saturating_mul(2));
    let started = Instant::now();
    let mut recovered = false;
    loop {
        match recover_interrupted_start(store, launcher, id, timeouts) {
            Ok(_) => {
                recovered = true;
                break;
            }
            // core の後始末スレッドが予約を保持している間だけ再試行する。
            Err(e) if e.code() == ErrorCode::FailedPrecondition && started.elapsed() < limit => {
                std::thread::sleep(RECOVER_RETRY_INTERVAL);
            }
            Err(e) => {
                log_event("recover_failed", Some(e.code()));
                break;
            }
        }
    }
    let mut all_reaped = true;
    for p in extra.into_iter().chain(take_unreaped_processes()) {
        if terminate_retrying(p, timeouts.terminate()).is_none() {
            all_reaped = false;
        }
    }
    recovered && all_reaped
}

/// 記録の失敗など Timeout 以外で `start` が失敗した後に、cgroup を消してよいかを確かめる。確かめられたら `true`。
///
/// - 状態が Created 以外（Running の予約が残る等）や読めない場合は [`recover_after_timeout`] で戻す。
/// - Created でも、core の後始末スレッドがハンドルを保持したまま予約を解放していない場合がある。
///   `recover_interrupted_start` が「回復対象なし」で戻る（＝予約が解放済み）まで待ってから、
///   登録済みの未回収ハンドルを terminate する。待ちは上限つき（REPAIR-5）。
fn settle_failed_start(
    store: &dyn StateStore,
    launcher: &Arc<dyn ProcessLauncher>,
    id: &ContainerId,
    timeouts: &StartTimeouts,
    pending: Vec<Box<dyn LaunchedProcess>>,
) -> bool {
    let reverted = store
        .get(&GetStateRequest::new(id.clone()))
        .is_ok_and(|r| r.status().state() == ContainerState::Created && r.status().pid().is_none());
    if !reverted {
        return recover_after_timeout(store, launcher, id, timeouts, pending);
    }
    let limit = timeouts
        .terminate()
        .saturating_add(LAUNCHER_REPLY_GRACE.saturating_mul(2));
    let started = Instant::now();
    let idle = loop {
        match recover_interrupted_start(store, launcher, id, timeouts) {
            // Created のため回復対象は無い。予約が解放済みで、core のワーカーも残っていない。
            Err(e)
                if e.code() == ErrorCode::FailedPrecondition
                    && e.message() == "no interrupted start reservation to recover" =>
            {
                break true;
            }
            Err(e) if e.code() == ErrorCode::FailedPrecondition && started.elapsed() < limit => {
                std::thread::sleep(RECOVER_RETRY_INTERVAL);
            }
            Err(e) => {
                log_event("start_settle_failed", Some(e.code()));
                break false;
            }
            // Created から回復が成功することはない。想定外は確かめられなかった扱いにする。
            Ok(_) => break false,
        }
    };
    let mut all_reaped = true;
    for p in pending.into_iter().chain(take_unreaped_processes()) {
        if terminate_retrying(p, timeouts.terminate()).is_none() {
            all_reaped = false;
        }
    }
    idle && all_reaped
}

/// 返ってきたハンドルを terminate して回収を確かめる（CORE-1・REPAIR-5）。
///
/// 全件確かめられたかと、回収を確かめられた pid の一覧を返す。
fn dispose(
    process: Option<Box<dyn LaunchedProcess>>,
    late: Option<&LateOrphans>,
    timeouts: &StartTimeouts,
) -> (bool, Vec<NonZeroU32>) {
    let mut ok = true;
    let mut reaped = Vec::new();
    if let Some(p) = process {
        match terminate_retrying(p, timeouts.terminate()) {
            Some(pid) => {
                log_event("handle_terminated", None);
                reaped.push(pid);
            }
            None => ok = false,
        }
    }
    if let Some(late) = late {
        if !late.wait_settled(timeouts.terminate().saturating_add(LAUNCHER_REPLY_GRACE)) {
            log_event("late_orphans_unsettled", None);
            ok = false;
        }
        // supervise_with_restart の待ちが期限を過ぎた後に terminate が成功した分（記録が Running のまま残り得る）も
        // 照合つきの Stopped 記録の対象に含める（SUP-1・CORE-2）。
        reaped.extend(late.take_reaped());
        for (p, _reason) in late.take() {
            match terminate_retrying(p, timeouts.terminate()) {
                Some(pid) => {
                    log_event("handle_terminated", None);
                    reaped.push(pid);
                }
                None => ok = false,
            }
        }
    }
    (ok, reaped)
}

/// [`mark_stopped`] の試行回数と間隔（全体は数百 ms で、後始末の期限に比べ十分短い）。
const MARK_STOPPED_ATTEMPTS: u32 = 3;
const MARK_STOPPED_RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// 回収を確かめられたハンドルに対応する Running の記録を、`Stopped` に落として監視権を解除する
/// （inspect が死んだ pid を生存中と表示せず、delete が拒否されないようにする。SUP-1・CORE-2）。
///
/// 同じ ID が回収中に削除・再作成されていても別インスタンスを上書きしないよう、試行ごとに最新レコードを読み直し、
/// 次を満たすときだけ書く（SEC-1）: cgroup の instance が start 時と一致／状態が Running で pid が回収済みの pid
/// のいずれか／`supervisor_pid` が無いか自プロセス。書き込みは読んだ revision への楽観的排他。
/// 読み取り・書き込みの失敗（health の更新との revision 競合等）は [`MARK_STOPPED_ATTEMPTS`] 回まで再試行する。
/// 記録できたか、照合に合わず書くべき記録が無ければ `true`、最後まで失敗したら `false`（呼び出し側が INTERNAL に
/// する）。
fn mark_stopped(
    store: &Arc<dyn StateStore>,
    id: &ContainerId,
    instance: Option<StateRevision>,
    reaped: &[NonZeroU32],
) -> bool {
    if reaped.is_empty() {
        return true;
    }
    for attempt in 1..=MARK_STOPPED_ATTEMPTS {
        match try_mark_stopped(store.as_ref(), id, instance, reaped) {
            Ok(()) => return true,
            Err(code) => {
                log_event("mark_stopped_failed", Some(code));
                if attempt < MARK_STOPPED_ATTEMPTS {
                    std::thread::sleep(MARK_STOPPED_RETRY_INTERVAL);
                }
            }
        }
    }
    false
}

/// [`mark_stopped`] の 1 回の試行。照合に合わなければ書かずに `Ok`（別インスタンス・別の監視者の記録）。
fn try_mark_stopped(
    store: &dyn StateStore,
    id: &ContainerId,
    instance: Option<StateRevision>,
    reaped: &[NonZeroU32],
) -> Result<(), ErrorCode> {
    let record = store
        .get(&GetStateRequest::new(id.clone()))
        .map_err(|e| e.code())?;
    let status = record.status();
    let same_instance = record.cgroup().map(|c| c.instance()) == instance;
    let same_process = status.state() == ContainerState::Running
        && status.pid().is_some_and(|p| reaped.contains(&p));
    let ours = record
        .supervision()
        .supervisor_pid()
        .is_none_or(|p| p.get() == std::process::id());
    if !(same_instance && same_process && ours) {
        log_event("mark_stopped_skipped", None);
        return Ok(());
    }
    let supervision = SupervisionState::new(None, record.health(), record.restart_count());
    let req = UpdateStateRequest::new(
        ContainerStatus::stopped(id.clone(), None),
        record.revision(),
    )
    .with_supervision(supervision);
    store.update(&req).map(drop).map_err(|e| e.code())
}

/// 回収の結果を終了コードにまとめる。確かめられたものは `Stopped` を記録し、`code` を返す。回収または記録を
/// 確かめられなければ `Internal`。
fn finish_disposed(
    store: &Arc<dyn StateStore>,
    id: &ContainerId,
    instance: Option<StateRevision>,
    disposed: (bool, Vec<NonZeroU32>),
    code: u8,
) -> u8 {
    let (ok, reaped) = disposed;
    if ok && mark_stopped(store, id, instance, &reaped) {
        code
    } else {
        exit_code_for(ErrorCode::Internal).get()
    }
}

/// 手順 10: 監視と restart。返り値は supervisor プロセスの終了コード（0 = 記録して正常に終わった）。
///
/// 監視の結果が返したハンドルの所有者は本入口なので、終了の前に terminate して回収を確かめる。
/// 回収を確かめられれば、対応する Running の記録を `Stopped` に落とす（`mark_stopped`）。
/// 回収を確かめられなければ `Internal` の非 0 で終わる。
///
/// コンテナ出力の捕捉（TASK-164 追補・#1471・SUP-7・SUP-1）: `running.logs` があれば、監視の前に初回プロセスの
/// `take_output` を捕捉ハブへ渡し（読み取りスレッドは `start` の完了後にここで初めて作る）、全終了経路で
/// ハブを畳んで末尾の行を sink へ flush する。捕捉を開始できなければ、読み取り側を捨てるとコンテナが
/// SIGPIPE を受けるため、起動したプロセスを回収して非 0 で終わる（fail-closed）。
pub fn run_supervised(
    store: Arc<dyn StateStore>,
    id: ContainerId,
    running: Running,
    restart: RestartPolicy,
    timeouts: &StartTimeouts,
    stop: &StopToken,
) -> u8 {
    let Running {
        process,
        relauncher,
        instance,
        logs,
    } = running;
    // 捕捉ハブが無いときは読み取り側を取り出さない（取り出して捨てるとコンテナが SIGPIPE を受ける）。
    if let Some(hub) = &logs
        && let Some(output) = process.take_output()
        && let Err(e) = hub.attach(output)
    {
        log_event("log_capture_failed", Some(e.code()));
        let disposed = dispose(Some(process), None, timeouts);
        return finish_disposed(
            &store,
            &id,
            instance,
            disposed,
            exit_code_for(e.code()).get(),
        );
    }
    let code = supervise_running(
        store, id, process, relauncher, instance, restart, timeouts, stop,
    );
    if let Some(hub) = logs {
        // 失敗（集計内の error_code を含む）は finish が構造化ログへ報告する。
        let _ = hub.finish(timeouts.terminate());
    }
    code
}

/// [`run_supervised`] の監視と回収の本体（出力の捕捉は呼び出し側が担う）。
// 理由: 入口 `run_supervised` が受けた store・id・process・relauncher・instance・restart・timeouts・stop は
// いずれも独立に所有・借用の区別が要る値で、束ねる型を作ると呼び出し側の分解コードが増えるだけのため引数のまま渡す。
#[allow(clippy::too_many_arguments)]
fn supervise_running(
    store: Arc<dyn StateStore>,
    id: ContainerId,
    process: Box<dyn LaunchedProcess>,
    relauncher: Arc<dyn Relauncher>,
    instance: Option<StateRevision>,
    restart: RestartPolicy,
    timeouts: &StartTimeouts,
    stop: &StopToken,
) -> u8 {
    let mut state = match SupervisedState::attach(Arc::clone(&store), id.clone()) {
        Ok(s) => s,
        Err(e) => {
            log_event("attach_failed", Some(e.code()));
            let disposed = dispose(Some(process), None, timeouts);
            return finish_disposed(
                &store,
                &id,
                instance,
                disposed,
                exit_code_for(e.code()).get(),
            );
        }
    };
    let configs = MonitorConfig::new(POLL_INTERVAL).and_then(|m| {
        RestartConfig::new(restart)
            .with_terminate_timeout(timeouts.terminate())
            .map(|r| (m, r))
    });
    let (monitor_config, restart_config) = match configs {
        Ok(c) => c,
        Err(e) => {
            log_event("config_invalid", Some(e.code()));
            let disposed = dispose(Some(process), None, timeouts);
            return finish_disposed(
                &store,
                &id,
                instance,
                disposed,
                exit_code_for(e.code()).get(),
            );
        }
    };
    let outcome = supervise_with_restart(
        &mut state,
        process,
        &relauncher,
        &monitor_config,
        &restart_config,
        stop,
        &StderrLogObserver,
    );
    match outcome {
        Err(e) => {
            // 起動ハンドルは supervise_with_restart に移っており、ここでは回収できない。
            log_event("supervise_failed", Some(e.code()));
            exit_code_for(e.code()).get()
        }
        Ok(SuperviseOutcome::Finished { .. }) => 0,
        Ok(SuperviseOutcome::Stopped { process, late, .. }) => {
            let disposed = dispose(process, Some(&late), timeouts);
            finish_disposed(&store, &id, instance, disposed, 0)
        }
        Ok(SuperviseOutcome::RelaunchFailed { error, late, .. }) => {
            log_event("restart_failed", Some(error.code()));
            let disposed = dispose(None, Some(&late), timeouts);
            finish_disposed(
                &store,
                &id,
                instance,
                disposed,
                exit_code_for(error.code()).get(),
            )
        }
        Ok(SuperviseOutcome::RestartUnrecorded {
            error,
            late,
            reaped,
            ..
        }) => {
            log_event("restart_failed", Some(error.code()));
            // supervise_with_restart の中で終了を確認できた新プロセスも、記録が Running のまま残り得るので
            // 照合つきの Stopped 記録の対象に含める（SUP-1・CORE-2）。
            let (ok, mut pids) = dispose(None, Some(&late), timeouts);
            pids.extend(reaped);
            finish_disposed(
                &store,
                &id,
                instance,
                (ok, pids),
                exit_code_for(error.code()).get(),
            )
        }
        Ok(SuperviseOutcome::MonitorFailed { process, .. }) => {
            log_event("monitor_failed", None);
            let disposed = dispose(process, None, timeouts);
            finish_disposed(
                &store,
                &id,
                instance,
                disposed,
                exit_code_for(ErrorCode::Internal).get(),
            )
        }
        Ok(SuperviseOutcome::MonitorError { error, process, .. }) => {
            log_event("monitor_error", Some(error.code()));
            let disposed = dispose(Some(process), None, timeouts);
            finish_disposed(
                &store,
                &id,
                instance,
                disposed,
                exit_code_for(error.code()).get(),
            )
        }
    }
}
#[cfg(target_os = "linux")]
pub use linux::{ProductionStartDeps, run_main};

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::fs::File;
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::FileTypeExt as _;
    use std::path::PathBuf;
    use std::process::ExitCode;

    use fandhe_container_core::audit_log::FileAuditSink;
    use fandhe_container_core::cgroups::{CgroupLimitPlan, DelegatedCgroup, StartCgroup};
    use fandhe_container_core::exec::IsolationPrivilege;

    use super::*;
    use crate::start_contract::StartArgs;

    /// 結果チャネルの書き込みの期限（読み手が読まず pipe が満杯でも監視へ進むため。REPAIR-5）。
    const REPORT_WRITE_DEADLINE: Duration = Duration::from_secs(5);
    /// stderr への報告 1 行（結果チャネルが使えないとき）と、終了前のログの書き出しを待つ期限（REPAIR-5）。
    const STDERR_DEADLINE: Duration = Duration::from_secs(1);

    /// 本番の [`StartDeps`]。core の本番 `ProcessLauncher`（#1715 の Phase B）が無い間、手順 4 で `UNIMPLEMENTED` を返す。
    pub struct ProductionStartDeps {
        root: PathBuf,
        /// Phase B で launcher の構成から渡す。`None` の間は cgroup の連鎖へ進まない。
        privilege: Option<IsolationPrivilege>,
        delegated: Option<DelegatedCgroup>,
        start_cgroup: Option<StartCgroup>,
        audit: Option<FileAuditSink>,
    }

    impl ProductionStartDeps {
        /// 状態ルート（`--root`）から作る。launcher の構成（権限モデル）は Phase B で渡す。
        pub fn new(root: PathBuf) -> Self {
            Self {
                root,
                privilege: None,
                delegated: None,
                start_cgroup: None,
                audit: None,
            }
        }
    }

    impl StartDeps for ProductionStartDeps {
        fn check_launcher_available(&self) -> Result<(), TraitError> {
            Err(TraitError::new(
                ErrorCode::Unimplemented,
                "production process launcher is not available yet",
            ))
        }

        fn prepare_cgroup(
            &mut self,
            store: &dyn StateStore,
            observed: &StateRecord,
        ) -> Result<Option<StateRevision>, TraitError> {
            let Some(privilege) = self.privilege else {
                return Err(TraitError::new(
                    ErrorCode::Unimplemented,
                    "isolation privilege is not configured",
                ));
            };
            let to_trait = |e: fandhe_container_core::cgroups::CgroupError| {
                TraitError::new(e.code, "failed to prepare the container cgroup")
            };
            let delegated = DelegatedCgroup::detect().map_err(to_trait)?;
            let plan = CgroupLimitPlan::for_privilege(privilege);
            let recorder = OpRecorder::new();
            let prepared = delegated
                .record_scope(store, observed)
                .and_then(|r| r.create_cgroup())
                .map_err(to_trait)?;
            // mkdir の後の段（制限・参加フック）の失敗は core が巻き戻さないため、作った cgroup を消してから返す
            // （削除は有限回の再試行。削除の失敗もエラーに含める。CORE-3）。
            let name = prepared.cgroup().name().clone();
            let start_cgroup = match prepared
                .apply_limits(&recorder, &plan)
                .and_then(|l| l.into_join())
            {
                Ok(c) => c,
                Err(e) => {
                    return Err(match remove_named_bounded(&delegated, &name) {
                        Ok(()) => TraitError::new(e.code, "failed to prepare the container cgroup"),
                        Err(code) => TraitError::new(
                            e.code,
                            format!(
                                "failed to prepare the container cgroup; removing it also failed: {}",
                                code.as_str()
                            ),
                        ),
                    });
                }
            };
            let instance = start_cgroup.record().cgroup().map(|c| c.instance());
            self.start_cgroup = Some(start_cgroup);
            self.delegated = Some(delegated);
            Ok(instance)
        }

        fn build_audit_sink(&mut self) -> Result<(), TraitError> {
            self.audit = Some(crate::exec::default_audit_sink(Some(self.root.clone()))?);
            Ok(())
        }

        /// 暫定の配置: `--root` 配下の `logs/`（0700）に `<id>.log`（既定 1MiB × 3 世代）を置く。ログのディレクトリ契約は
        /// `logs` コマンド側（#1543）で確定する事項で、確定したらここを合わせる。
        fn open_log_sink(
            &mut self,
            id: &ContainerId,
        ) -> Result<Option<Arc<dyn LogSink>>, TraitError> {
            use std::os::unix::fs::DirBuilderExt as _;
            let dir = self.root.join("logs");
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => {
                    return Err(TraitError::new(
                        ErrorCode::Internal,
                        "failed to create the log directory",
                    ));
                }
            }
            let config = crate::logs::RotationConfig::new(
                crate::logs::rotating::DEFAULT_LOG_FILE_BYTES,
                crate::logs::rotating::DEFAULT_LOG_GENERATIONS,
            )?;
            let sink = crate::logs::RotatingFileSink::open(&dir, id, config)?;
            Ok(Some(Arc::new(sink)))
        }

        fn build_launcher(&mut self) -> Result<Arc<dyn ProcessLauncher>, TraitError> {
            // Phase B: ここで start_cgroup の参加フックと audit を launcher へ渡す。
            Err(TraitError::new(
                ErrorCode::Unimplemented,
                "production process launcher is not available yet",
            ))
        }

        fn release_cgroup(&mut self) -> Result<(), TraitError> {
            let (Some(delegated), Some(start_cgroup)) =
                (self.delegated.as_ref(), self.start_cgroup.as_ref())
            else {
                return Ok(());
            };
            delegated
                .remove_child(start_cgroup.cgroup())
                .map_err(|e| TraitError::new(e.code, "failed to remove the container cgroup"))
        }
    }

    /// 準備途中の cgroup の削除の試行回数と間隔（全体で数百 ms。有限）。
    const CGROUP_REMOVE_ATTEMPTS: u32 = 5;
    const CGROUP_REMOVE_RETRY_INTERVAL: Duration = Duration::from_millis(50);

    /// 名前で開き直したコンテナ用 cgroup を、有限回の再試行で消す（既に無ければ成功）。失敗はそのコード。
    fn remove_named_bounded(
        delegated: &DelegatedCgroup,
        name: &fandhe_container_core::cgroups::CgroupName,
    ) -> Result<(), ErrorCode> {
        let mut last = ErrorCode::Internal;
        for attempt in 1..=CGROUP_REMOVE_ATTEMPTS {
            let result = match delegated.open_child(name) {
                Ok(None) => return Ok(()),
                Ok(Some(child)) => delegated.remove_child(&child),
                Err(e) => Err(e),
            };
            match result {
                Ok(()) => return Ok(()),
                Err(e) => last = e.code,
            }
            if attempt < CGROUP_REMOVE_ATTEMPTS {
                std::thread::sleep(CGROUP_REMOVE_RETRY_INTERVAL);
            }
        }
        log_event("cgroup_remove_failed", Some(last));
        Err(last)
    }

    /// 結果チャネル（stdout）を複製して取り、FIFO であることを確かめる（std の安全な API のみ）。
    fn open_result_channel() -> Result<File, TraitError> {
        let fd = std::io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| {
                TraitError::new(ErrorCode::InvalidArgument, "result channel is unavailable")
            })?;
        let file = File::from(fd);
        let is_fifo = file
            .metadata()
            .map(|m| m.file_type().is_fifo())
            .unwrap_or(false);
        if !is_fifo {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "stdout must be a pipe for the result channel",
            ));
        }
        Ok(file)
    }

    /// `/proc/self/task` のスレッド数が 1 か（`oci_runtime::start` の前提）。
    fn is_single_threaded() -> bool {
        std::fs::read_dir("/proc/self/task")
            .map(|d| d.take(2).count() == 1)
            .unwrap_or(false)
    }

    /// supervisor の bin の入口（`src/main.rs` から呼ぶ）。`args` はプログラム名を除いた argv。
    ///
    /// 終了の前に、それまでの stderr のログが書かれるのを期限つきで待つ（読み手が止まっていても期限で終わる）。
    pub fn run_main<I: IntoIterator<Item = OsString>>(args: I) -> ExitCode {
        let code = run_main_inner(args);
        let _ = crate::stderr_sink::flush_stderr(STDERR_DEADLINE);
        code
    }

    fn run_main_inner<I: IntoIterator<Item = OsString>>(args: I) -> ExitCode {
        // 0: 結果チャネル。不正なら報告できないので stderr に固定スキーマの JSON を出して終わる。
        let mut out = match open_result_channel() {
            Ok(f) => BoundedWriter::new(f, REPORT_WRITE_DEADLINE),
            Err(e) => {
                let err = op_err(e);
                let mut line = Vec::new();
                if err.write_json_line(&mut line).is_ok() {
                    // 期限つき（stderr の読み手が止まっていても終了できる。REPAIR-5）。
                    let _ = crate::stderr_sink::stderr().emit_and_wait(line, STDERR_DEADLINE);
                }
                return ExitCode::from(err.exit_code().get());
            }
        };
        let fail = |out: &mut BoundedWriter<File>, err: OciRuntimeError| -> ExitCode {
            if write_report(out, &StartReport::failed(&err)).is_err() {
                log_event("report_failed", None);
            }
            ExitCode::from(err.exit_code().get())
        };
        // 0b: execve は dumpable を 1 に戻す。特権ランチャー経由（ambient capability・AT_SECURE なし）で昇格した
        // supervisor を同一 uid の親が ptrace して capability を奪えないよう、入口で改めて 0 にする（SUP-14・#1719）。
        if let Err(e) = crate::sys::set_dumpable(false) {
            return fail(
                &mut out,
                op_err(TraitError::new(
                    ErrorCode::Internal,
                    format!("PR_SET_DUMPABLE failed: {}", e.kind()),
                )),
            );
        }
        // 1
        let args = match StartArgs::parse(args) {
            Ok(a) => a,
            Err(e) => return fail(&mut out, op_err(e)),
        };
        // 2
        if !is_single_threaded() {
            return fail(
                &mut out,
                op_err(TraitError::new(
                    ErrorCode::Internal,
                    "supervisor must start single-threaded",
                )),
            );
        }
        let timeouts = StartTimeouts::default();
        let store = match crate::state::open_default_store(Some(args.root.clone())) {
            Ok(s) => s,
            Err(e) => return fail(&mut out, op_err(e)),
        };
        let req = StartRequest::new(args.id.clone());
        let deps = Box::new(ProductionStartDeps::new(args.root));
        // 回復・回収と報告の書き込みで同じ期限を共有し、報告を内部上限内に収める（REPAIR-5）。
        let deadline =
            Instant::now().checked_add(crate::start_contract::result_deadline(&timeouts));
        out.limit_until(deadline);
        let running = match run_start_until(
            deps,
            &store,
            &Arc::new(OpRecorder::new()),
            &req,
            &timeouts,
            deadline,
            &mut out,
        ) {
            Ok(r) => r,
            Err(code) => return ExitCode::from(code.get()),
        };
        // 報告は 1 行だけ書く契約。複製は閉じるが、fd 1 自体は std の stdout が持つため pipe は開いたまま
        // （CLI は EOF ではなく 1 行の受信で完了とみなす。fd を閉じるには unsafe が要るため行わない）。
        drop(out);
        let code = run_supervised(
            store,
            args.id,
            running,
            args.restart,
            &timeouts,
            &StopToken::new(),
        );
        ExitCode::from(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::{
        CreateStateRequest, DeleteStateRequest, DeleteStateResponse, ListStateRequest, StateList,
    };

    /// `launch_mode` だけを答えるフェイク（転送の照合用。#1816・REPAIR-5）。
    struct SelfBoundedFake;

    /// 何も記録しない sink(同一性の照合用。#1915)。
    struct FakeSink;

    impl fandhe_container_core::audit_log::AuditSink for FakeSink {
        fn record(
            &self,
            _: &fandhe_container_core::audit_log::AuditRecord,
        ) -> Result<(), TraitError> {
            Ok(())
        }
    }

    static FAKE_SINK: FakeSink = FakeSink;

    impl ProcessLauncher for SelfBoundedFake {
        fn rejection_audit_sink(&self) -> Option<&dyn fandhe_container_core::audit_log::AuditSink> {
            Some(&FAKE_SINK)
        }

        fn launch_mode(&self) -> fandhe_container_core::oci_runtime::LaunchMode {
            fandhe_container_core::oci_runtime::LaunchMode::SelfBounded
        }

        fn launch(
            &self,
            _spec: &LaunchSpec,
            _timeout: Duration,
        ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
    }

    /// 使われない `StateStore`（`launch_mode` の転送の照合では store に触れない）。
    struct UnusedStore;

    impl StateStore for UnusedStore {
        fn create(&self, _: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn update(&self, _: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn get(&self, _: &GetStateRequest) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn list(&self, _: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn delete(&self, _: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
    }

    /// REPAIR-5・#1816: `InstanceCheckedLauncher` は内側の `launch_mode` を転送する（既定の降格をしない）。
    #[test]
    fn repair5_instance_checked_launcher_forwards_launch_mode() {
        use fandhe_container_core::oci_runtime::LaunchMode;
        let wrapped = InstanceCheckedLauncher {
            inner: Arc::new(SelfBoundedFake),
            store: Arc::new(UnusedStore),
            id: ContainerId::new("c1").expect("id"),
            expected: None,
        };
        assert_eq!(wrapped.launch_mode(), LaunchMode::SelfBounded);
    }

    /// SEC-4・#1915: `InstanceCheckedLauncher` は内側の監査 sink を転送する(同一の sink が返る)。
    #[test]
    fn sec4_instance_checked_launcher_forwards_rejection_audit_sink() {
        let wrapped = InstanceCheckedLauncher {
            inner: Arc::new(SelfBoundedFake),
            store: Arc::new(UnusedStore),
            id: ContainerId::new("c1").expect("id"),
            expected: None,
        };
        let got = wrapped.rejection_audit_sink().expect("forwarded sink");
        let want: &dyn fandhe_container_core::audit_log::AuditSink = &FAKE_SINK;
        assert!(std::ptr::addr_eq(got, want));
    }

    /// terminate が呼び出し側の期限より遅れて成功する起動ハンドル。
    struct SlowOk(u32, Duration);

    impl LaunchedProcess for SlowOk {
        fn pid(&self) -> NonZeroU32 {
            NonZeroU32::new(self.0).unwrap()
        }
        fn wait(
            &self,
            _: Duration,
        ) -> Result<Option<fandhe_container_core::oci_runtime::ProcessExit>, TraitError> {
            Ok(None)
        }
        fn terminate(&self, _: Duration) -> Result<(), TraitError> {
            std::thread::sleep(self.1);
            Ok(())
        }
    }

    /// SUP-1・CORE-2・REPAIR-5: 待ちの期限を過ぎてから terminate が成功しても、もう 1 回分の期限内なら回収済みの pid
    /// を返す（Stopped 記録の対象にする）。それより遅ければ確かめられなかった扱い（`None`）。
    #[test]
    fn sup1_terminate_retrying_returns_late_reaped_pid() {
        let timeout = Duration::from_millis(10);
        let late = timeout + LAUNCHER_REPLY_GRACE + Duration::from_millis(300);
        assert_eq!(
            terminate_retrying(Box::new(SlowOk(91, late)), timeout).map(NonZeroU32::get),
            Some(91)
        );
        let too_late = (timeout + LAUNCHER_REPLY_GRACE) * 2 + Duration::from_millis(500);
        assert_eq!(
            terminate_retrying(Box::new(SlowOk(92, too_late)), timeout),
            None
        );
    }

    /// REPAIR-5: 報告の書き込み上限は `min(5s, 残り)`。期限を過ぎていれば 0、期限が無ければ 5s。
    #[test]
    fn repair5_write_limit_is_capped_by_remaining_time() {
        let base = Duration::from_secs(5);
        let now = Instant::now();
        assert_eq!(write_limit(base, None, now), base);
        assert_eq!(
            write_limit(base, Some(now + Duration::from_secs(9)), now),
            base
        );
        assert_eq!(
            write_limit(base, Some(now + Duration::from_secs(2)), now),
            Duration::from_secs(2)
        );
        assert_eq!(
            write_limit(base, Some(now), now + Duration::from_secs(1)),
            Duration::ZERO
        );
    }
}
