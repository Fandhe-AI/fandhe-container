//! supervisor の bin の入口: 起動 → 結果の返却 → 監視（`monitor` / restart）を 1 プロセスで行う処理順
//! （TASK-157 追補・#1717・SUP-1・SUP-3・MS-9。関連: CORE-1・CORE-2・CORE-3・SEC-1・SEC-4・REPAIR-3・REPAIR-4・REPAIR-5・D-19）。
//!
//! 呼び出し元は `src/main.rs`（`run_main`）。CLI（#1718）が [`crate::start_contract`] の契約で起動し、結果チャネル
//! （stdout の pipe）の 1 行を読む。#1314 のオーナー判断（配置 1-A・cgroup 3-ii）により、`oci_runtime::start`
//! （Created → Running の予約と記録）を呼ぶ層は CLI から本入口へ移った。
//!
//! # 処理順（[`run_start`] と [`run_supervised`]）
//! 0a. 継承 fd（fd 3 以降）を閉じる（ランチャーと同じ処理。結果チャネルの複製より前。#2070）／
//! 0. 結果チャネルの検証（stdout が FIFO か。`run_main`）／1. argv の解析（[`crate::start_contract::StartArgs`]）／
//! 2. スレッド数が 1 か（`oci_runtime::start` の前提。以後のスレッドは手順 3〜7 の作業スレッド〔入口は待つだけ〕と
//!    手順 10 以降のログ捕捉・restart のワーカーに限る）／
//!    2b. supervisor の構造化ログの保存先を開き、`stderr_sink` の書き先を差し替える（レコードがあるときだけ。期限つきの
//!    作業スレッドで行い終了を確認してから進む。失敗は fail-closed。保存先と上限は [`crate::supervisor_log`]。#2067・REPAIR-4）／
//! 3. 状態の事前確認（Created・pid なし・cgroup 未記録。副作用なし）／4. [`StartDeps::check_launcher_available`]
//!    （副作用なし。権限モデルと Landlock ABI を確かめ、満たさなければここで止まる）／5. cgroup の連鎖
//!    （[`StartDeps::prepare_cgroup`]）／6. 監査 sink（[`StartDeps::build_audit_sink`]。fork の前）・ログ sink／
//!    7. launcher の構築と [`SpecCapturingLauncher`] での包み／8. `oci_runtime::start`（**入口スレッドが直接行う**）／
//!    9. `FCSUP1 OK <pid>` の報告／10. `SupervisedState::attach` → [`supervise_with_restart`]。
//!
//! 手順 3・4 は cgroup の連鎖（手順 5）より前に置く。スコープの追記は 1 回限りで取り消す API が無いため、
//! launcher が使えない場合や状態が Created でない場合に、スコープを残さずに止める。
//!
//! # 手順 8 を入口スレッドで行う理由（CORE-1・REPAIR-5・#1819）
//! 本番 launcher（`oci_runtime::ProductionLauncher`）は `LaunchMode::SelfBounded` を宣言し、fork の前に呼び出し
//! プロセスが単一スレッドであることを確かめる（満たさなければ副作用なしで `FailedPrecondition`）。そのため手順 3〜7
//! だけを作業スレッドで行い、作業スレッドを `join` で終了させてから、入口スレッドが手順 8 を直接呼ぶ
//! （`join` が返った直後は `/proc/self/task` にまだ残り得るため、`SelfBounded` の launcher の前に短く待つ）。
//! 状態の読み取り・bundle の検証・所有ロック・起動権の予約（`claim_start`。`StateStore` と bundle のファイル I/O）は
//! 作業スレッドの末尾で行うため、入口は期限で待ち切れる（FUSE 上の bundle が止まっても報告できる。REPAIR-5）。入口
//! スレッドが行うのは launcher の呼び出しと Running の記録（`launch_claimed`）だけで、launch の後の状態 I/O は
//! 期限つきの別スレッドで実行して打ち切る（`deadline_store`。止まっても期限内に報告し、残る予約は報告の後に回復する）。
//! 手順 8 の上限は launcher 自身が守る。入口は launch の前に [`crate::start_contract::launch_step_budget`] が期限内に
//! 残っているかを確かめ、足りなければ launch しない。手順 8 より前に常駐スレッドを作らないよう、成功経路の
//! 手順 3〜7 では `log_event`（`stderr_sink` の常駐スレッドを作る）を呼ばない。
//!
//! # 期限と報告の後の後始末（fail-closed。#1541 と同じ要求・REPAIR-5）
//! 手順 3〜7 は作業スレッドで行い、入口は `result_deadline` から [`REPORT_RESERVE`] を引いた時点まで結果を待つ
//! （手順 2 の確認の後に作るスレッドで、入口は Condvar で待つだけでロックを持たない）。報告は期限までに必ず 1 回書き、
//! 後始末は報告の後に行う（契約は [`crate::start_contract`] の「報告の後の後始末」）。
//! - 手順 5〜7 の失敗: 作った cgroup を [`StartDeps::release_cgroup`] で消す。
//! - `start` の失敗（Timeout を含む）は、状態を読み直して分ける。
//!   - Created に戻っている（launch の失敗・launcher 自身が期限内に返した Timeout 等。core の `start` が予約を戻し、
//!     子を terminate 済み）: 予約の解放と core のワーカー完了を確かめてから cgroup を消す。
//!   - 予約（Running・pid なし）が残る（呼び出し境界の期限超過や、回収を確かめられなかった launch の失敗）:
//!     `recover_interrupted_start` を約 50ms 刻みで再試行して Created へ戻し、`take_unreaped_processes` で
//!     引き取ったハンドルを terminate する。戻せたら cgroup を消し、戻せなければ cgroup を消さない。
//! - 手順 3〜7 の期限超過、または手順 8 の見込みが残らない: `INTERNAL`（[`DEADLINE_EXCEEDED_MESSAGE`]）を報告する。
//!   launch はしない。作業スレッドが後から準備を終えたら、launch せずに作った cgroup を消す。
//! - 後始末を確かめられなければ終了コードは `INTERNAL`。後始末自体の失敗は元のエラーを隠さず、構造化ログ（stderr）に出す。
//! - 失敗した start の後もスコープは記録されたまま残る（core に記録済みの配置から連鎖を再開する API が無い）。
//!   同じコンテナの再 start は手順 3 で `FailedPrecondition` になる。
//!
//! # 未実装・残余（REPAIR-3）
//! - **restart の再 launch**: 本番 launcher の結線は済んでいる（start と同じ launcher と `LaunchSpec` を使う）が、
//!   再 launch は `fandhe-relaunch` スレッドや `stderr_sink` の常駐スレッドが存在する状態で呼ばれるため、本番 launcher が
//!   `FailedPrecondition` で拒否し、`RelaunchFailed` で終わる（fail-closed。子は作られない）。単一スレッドの呼び出し
//!   スレッドで再 launch する再構成は #2043（SUP-3・CORE-1）で行う。
//! - 権限モデルは `RootlessSingleId` のみ（実効 uid が 0 の rootful 起動は手順 4 で拒否する。SEC-5）。
//!
//! フェイクの [`StartDeps`] を使う試験（`tests/start_entry.rs`）が処理順・報告・後始末・relaunch のアダプタを照合し、
//! 実プロセスでの通し（bin → 本番 launcher → `monitor`）は `tests/supervisor_bin_real.rs`（実機前提・`--ignored`）が照合する。

use std::io::Write;
use std::num::{NonZeroU8, NonZeroU32};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_core::oci_runtime::{
    ClaimedStart, LAUNCHER_REPLY_GRACE, LaunchMode, LaunchedProcess, LifecycleOp, OciRuntimeError,
    ProcessLauncher, StartTimeouts, claim_start, exit_code_for, launch_claimed,
    recover_interrupted_start, take_unreaped_processes,
};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ContainerStatus, ErrorCode, GetStateRequest, StartRequest,
    StateRecord, StateRevision, StateStore, SupervisionState, TraitError, UpdateStateRequest,
};

use crate::deadline_store::{DeadlineStore, LateWrites};
use crate::log_pipeline::CaptureHub;
use crate::logs::LogSink;
use crate::restart::{
    LateOrphans, LauncherRelauncher, Relauncher, RestartConfig, RestartPolicy,
    SpecCapturingLauncher, SuperviseOutcome, supervise_with_restart,
};
use crate::run::{MonitorConfig, StderrLogObserver, StopToken};
use crate::start_contract::{StartReport, launch_step_budget};
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
/// 準備（手順 3〜7）は作業スレッドで行い、本関数は `deadline` から [`REPORT_RESERVE`] を引いた時点まで結果を
/// 待つ。準備が済んだら作業スレッドの終了を確かめ、入口スレッドが手順 8（`oci_runtime::start`）を直接行う
/// （本番 launcher は単一スレッドの呼び出しを要求するため。モジュール doc「手順 8 を入口スレッドで行う理由」）。
/// 報告（`out` への 1 行）は期限までに必ず 1 回書き、失敗後の後始末（予約・cgroup の解放・terminate）は報告の後に
/// 行う（REPAIR-5。core の API を変えずに起動処理全体へ期限を課す）。
/// - 期限内に成功: `OK <pid>` を報告して `Ok(Running)`（報告の書き込みに失敗しても監視は続ける）。
/// - 期限内に失敗: そのエラーを報告してから後始末する。後始末を確かめられなければ終了コードは `Internal`。
/// - 準備の期限超過、または手順 8 の見込み（[`launch_step_budget`]）が残らない: `INTERNAL`
///   （[`DEADLINE_EXCEEDED_MESSAGE`]）を報告する。launch はしない。作業スレッドが後から準備を終えたら、作った
///   cgroup を消す（`result_deadline` の長さまで待つ。それでも戻らなければ待つのをやめる）。終了コードは `Internal`。
///
/// 起動の成否とレイテンシは `recorder` の [`START_OP`] に記録し（準備と手順 8 を合わせた時間）、本関数の最後に
/// 構造化ログ 1 行（[`start_metrics_line`]）で出す。
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
    // 満杯・書き込み失敗でも処理は止めない（ログの欠落は許す）。手順 8 の後なので常駐スレッドを作ってよい。
    let _ = crate::stderr_sink::stderr().emit(start_metrics_line(recorder).into_bytes());
    result
}

/// 手順 8 の前に、期限内に手順 8 の見込み（[`launch_step_budget`]）が残っているか。
///
/// 残り時間は `deadline − REPORT_RESERVE`（報告の書き込みに残す幅）まで。見込みは手順 8 の予算に、launch の前の
/// 作業スレッド消滅の待ち（[`START_WORKER_EXIT_WAIT`]）を加えたもの。期限が無ければ（加算があふれる巨大な
/// 上限）常に残っているとみなす。
fn has_launch_budget(deadline: Option<Instant>, timeouts: &StartTimeouts) -> bool {
    let Some(deadline) = deadline else {
        return true;
    };
    let limit = deadline.checked_sub(REPORT_RESERVE).unwrap_or(deadline);
    // launch の前に作業スレッドの消滅を最大 START_WORKER_EXIT_WAIT まで待つため、その分も見込みに含める。
    Instant::now()
        .checked_add(launch_step_budget(timeouts))
        .and_then(|t| t.checked_add(START_WORKER_EXIT_WAIT))
        .is_some_and(|end| end <= limit)
}

/// 準備の結果から手順 8 を行う（入口スレッドで呼ぶ。作業スレッドは終了済み）。
fn launch_after_prepare(
    outcome: PrepareOutcome,
    (worker_exited, worker_tid): (bool, Option<NonZeroU32>),
    store: &Arc<dyn StateStore>,
    recorder: &OpRecorder,
    timeouts: &StartTimeouts,
    deadline: Option<Instant>,
) -> Attempt {
    let prepared = match outcome {
        PrepareOutcome::Failed { error, cleanup } => return Attempt::Failed { error, cleanup },
        PrepareOutcome::Ready(p) => p,
    };
    if !worker_exited {
        // 作業スレッドが異常終了した。launch の前提（単一スレッド）を確かめられないため進まない。
        return Attempt::Failed {
            error: op_err(TraitError::new(
                ErrorCode::Internal,
                "the start worker terminated abnormally",
            )),
            // 予約を持つ claim を落とすと pid なしの Running が残り、cgroup だけ消えて回復が cgroup を失う。
            // 報告の後に予約を戻してから cgroup を消す（戻せなければ cgroup を残す。CORE-2）。
            cleanup: discard_prepared(prepared),
        };
    }
    if !has_launch_budget(deadline, timeouts) {
        // 期限内に終わらない launch を始めない（子を作ってから期限を超えない。REPAIR-5）。
        log_event("start_launch_skipped", Some(ErrorCode::Timeout));
        let cleanup = discard_prepared(prepared);
        return Attempt::Failed {
            error: OciRuntimeError::new(
                LifecycleOp::Start,
                ErrorCode::Internal,
                DEADLINE_EXCEEDED_MESSAGE,
            ),
            cleanup,
        };
    }
    if prepared.launcher.launch_mode() == LaunchMode::SelfBounded {
        wait_task_gone(worker_tid, START_WORKER_EXIT_WAIT);
    }
    launch_prepared(prepared, store, recorder, timeouts, deadline)
}

/// 起動の計測を [`START_OP`] に記録する（準備の開始から手順 8 の終わりまで）。
fn record_start(recorder: &OpRecorder, started: Instant, success: bool) {
    let outcome = if success {
        OpOutcome::Success
    } else {
        OpOutcome::Failure
    };
    if let Ok(name) = OpName::new(START_OP) {
        let _ = recorder.record(&name, outcome, started.elapsed());
    }
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
    let started = Instant::now();
    let worker = match StartWorker::spawn(deps, store, req, *timeouts) {
        Ok(w) => w,
        Err(e) => {
            let err = op_err(e);
            record_start(recorder, started, false);
            report(out, &StartReport::failed(&err));
            return Err(err.exit_code());
        }
    };
    let wait_until = deadline.map(|d| d.checked_sub(REPORT_RESERVE).unwrap_or(d));
    if let Some((deps, outcome)) = worker.wait_until(wait_until) {
        // 作業スレッドは結果を渡した直後に終わる。launch の前に終了を確かめる（単一スレッドの要求。CORE-1）。
        let worker_exited = worker.join();
        let attempt =
            launch_after_prepare(outcome, worker_exited, store, recorder, timeouts, deadline);
        record_start(recorder, started, matches!(attempt, Attempt::Started(_)));
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
                if cleanup_after_report(deps, store, req.id(), timeouts, cleanup) {
                    Err(error.exit_code())
                } else {
                    Err(exit_code_for(ErrorCode::Internal))
                }
            }
        };
    }
    // 準備の期限超過: 先に報告し、作業スレッドの結果を有限の期限まで待ってから後始末する。launch はしない。
    let overdue = OciRuntimeError::new(
        LifecycleOp::Start,
        ErrorCode::Internal,
        DEADLINE_EXCEEDED_MESSAGE,
    );
    log_event("start_deadline_exceeded", Some(ErrorCode::Timeout));
    record_start(recorder, started, false);
    report(out, &StartReport::failed(&overdue));
    let late_until = Instant::now().checked_add(crate::start_contract::result_deadline(timeouts));
    match worker.wait_or_abandon(late_until) {
        Some((deps, outcome)) => {
            abandoned_cleanup(deps, store, req.id(), timeouts, outcome);
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

/// 手順 8 まで行った起動の結果（報告の材料と、報告の後の後始末に要るもの）。
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
    /// cgroup の準備・監査 sink・launcher の構築の失敗、または launch しなかった場合（作った cgroup を消す）。
    ReleaseCgroup,
    /// `start` が失敗（Timeout を含む。予約が残れば Created へ戻し、予約の解放と core のワーカー完了を確かめ、
    /// 未回収のハンドルを terminate してから cgroup を消す）。
    ///
    /// 第 3 要素は期限で打ち切った状態 I/O の完了待ちと、遅れて成功した記録の受け渡し口。遅れた Running・pid ありの
    /// 記録は、子の回収を確かめてから照合して Created へ戻す（CORE-2・REPAIR-5）。
    AfterFailure(
        Arc<dyn ProcessLauncher>,
        Vec<Box<dyn LaunchedProcess>>,
        Arc<LateWrites>,
    ),
    /// launch しなかった準備済みの起動権の予約を、報告の後に Created へ戻す（`StateStore` の更新は報告を
    /// 止め得るため報告の前に行わない。REPAIR-5）。戻せたら cgroup を消し、戻せなければ消さない。
    DiscardClaim(Box<ClaimedStart>),
}

/// 手順 8（`oci_runtime::start`）に要るもの。準備（手順 3〜7）の成功の結果。
struct Prepared {
    /// 内側の launcher（restart の再 launch が同じものを使う。起動の経路を 2 つにしない。SUP-3）。
    inner: Arc<dyn ProcessLauncher>,
    /// `LaunchSpec` を捕捉する包み（restart の再 launch が start で検証済みの spec を再利用する）。
    capturing: Arc<SpecCapturingLauncher>,
    /// `start` へ渡す launcher（`capturing` を trait object にしたもの）。
    launcher: Arc<dyn ProcessLauncher>,
    /// コンテナ出力の捕捉ハブ。
    logs: Option<Arc<CaptureHub>>,
    /// 起動権の予約済みの状態（bundle の検証・所有ロック・予約の更新は作業スレッドで済ませてある。#1819）。
    claimed: Box<ClaimedStart>,
}

/// 作業スレッドで行った準備（手順 3〜7）の結果。
enum PrepareOutcome {
    /// 準備が済んだ。入口スレッドが手順 8 を行う。
    Ready(Prepared),
    Failed {
        error: OciRuntimeError,
        cleanup: Cleanup,
    },
}

/// 作業スレッドが入口へ渡す結果（`deps` は後始末のために返す）。
type Finished = (Box<dyn StartDeps + Send>, PrepareOutcome);

/// 作業スレッドと入口の間の受け渡し状態（同じ Mutex で守る）。
enum WorkerSlot {
    Pending,
    Done(Box<dyn StartDeps + Send>, PrepareOutcome),
    /// 入口が結果を取り出した、または待つのをやめた（以後の結果は作業スレッドが後始末する）。
    Abandoned,
}

/// 準備（手順 3〜7）を行う作業スレッド。
struct StartWorker {
    shared: Arc<(Mutex<WorkerSlot>, Condvar)>,
    handle: std::thread::JoinHandle<()>,
    /// 作業スレッドの tid（作業スレッドが最初に書く。0 は不明。`join` の後に `/proc/self/task` から消えるのを待つため）。
    tid: Arc<AtomicU32>,
}

/// 作業スレッドのスレッド名。
const START_WORKER_NAME: &str = "supervisor-start";

/// `join` の後も `/proc/self/task` に作業スレッドが残り得る間の待ちの上限（通常は数十 µs で消える）。
const START_WORKER_EXIT_WAIT: Duration = Duration::from_secs(1);

impl StartWorker {
    fn spawn(
        deps: Box<dyn StartDeps + Send>,
        store: &Arc<dyn StateStore>,
        req: &StartRequest,
        timeouts: StartTimeouts,
    ) -> Result<Self, TraitError> {
        let shared = Arc::new((Mutex::new(WorkerSlot::Pending), Condvar::new()));
        let worker_shared = Arc::clone(&shared);
        let (store, req) = (Arc::clone(store), req.clone());
        let tid = Arc::new(AtomicU32::new(0));
        let worker_tid = Arc::clone(&tid);
        // 準備は作業スレッドが行い、入口は Condvar で待つだけでロックを持たない。手順 8 は作業スレッドの終了後に
        // 入口スレッドが行う（単一スレッドの要求。core の launch の別スレッド実行は CallerBounded の launcher だけ）。
        let handle = std::thread::Builder::new()
            .name(START_WORKER_NAME.into())
            .spawn(move || {
                worker_tid.store(current_tid(), Ordering::Release);
                let mut deps = deps;
                let outcome = prepare_start(deps.as_mut(), &store, &req);
                let (lock, cvar) = &*worker_shared;
                let mut slot = lock.lock().unwrap_or_else(PoisonError::into_inner);
                if matches!(*slot, WorkerSlot::Abandoned) {
                    drop(slot);
                    abandoned_cleanup(deps, &store, req.id(), &timeouts, outcome);
                    return;
                }
                *slot = WorkerSlot::Done(deps, outcome);
                cvar.notify_all();
            })
            .map_err(|_| {
                TraitError::new(ErrorCode::Internal, "failed to spawn the start worker")
            })?;
        Ok(Self {
            shared,
            handle,
            tid,
        })
    }

    /// 作業スレッドの終了を待つ。結果を渡した直後に終わるため待ちは短い。返り値は正常に終わったかと、作業スレッドの tid
    /// （不明なら `None`）。異常終了（panic）なら正常でない。
    fn join(self) -> (bool, Option<NonZeroU32>) {
        let tid = NonZeroU32::new(self.tid.load(Ordering::Acquire));
        (self.handle.join().is_ok(), tid)
    }

    /// `until` まで結果を待ち、出ていれば取り出す（`None` は無期限）。
    fn wait_until(&self, until: Option<Instant>) -> Option<Finished> {
        let (lock, cvar) = &*self.shared;
        let mut slot = lock.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if matches!(*slot, WorkerSlot::Done { .. }) {
                // 取り出した後は Abandoned にして二重に取り出さない。
                return match std::mem::replace(&mut *slot, WorkerSlot::Abandoned) {
                    WorkerSlot::Done(deps, outcome) => Some((deps, outcome)),
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
    fn wait_or_abandon(&self, until: Option<Instant>) -> Option<Finished> {
        let (lock, cvar) = &*self.shared;
        let mut slot = lock.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if matches!(*slot, WorkerSlot::Done { .. }) {
                return match std::mem::replace(&mut *slot, WorkerSlot::Abandoned) {
                    WorkerSlot::Done(deps, outcome) => Some((deps, outcome)),
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

/// 呼び出しスレッドの tid（Linux の `/proc/thread-self` の指す `<pid>/task/<tid>` から取る。取れなければ 0）。
#[cfg(target_os = "linux")]
fn current_tid() -> u32 {
    std::fs::read_link("/proc/thread-self")
        .ok()
        .and_then(|p| p.file_name().and_then(|n| n.to_str()?.parse::<u32>().ok()))
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn current_tid() -> u32 {
    0
}

/// tid のスレッドが自プロセスの `/proc/self/task` に残っているか（Linux 以外では常に `false`）。
///
/// `pthread_join` はカーネルがスレッド ID を消した時点で返り、タスクの解放（スレッド数の減算）は少し後になり得る。
/// 本番 launcher は `/proc/self/status` のスレッド数が 1 であることを要求するため、launch の前に消えるのを待つ。
#[cfg(target_os = "linux")]
fn task_present(tid: NonZeroU32) -> bool {
    std::path::Path::new("/proc/self/task")
        .join(tid.to_string())
        .exists()
}

#[cfg(not(target_os = "linux"))]
fn task_present(_tid: NonZeroU32) -> bool {
    false
}

/// 作業スレッド（`tid`）が消えるまで、最大 `limit` だけ短く待つ（消えなくても進む。拒否の判断は launcher が行う）。
///
/// 待ちの中では [`log_event`] を呼ばない（`stderr_sink` の常駐スレッドを作ると単一スレッドの前提を壊すため）。
fn wait_task_gone(tid: Option<NonZeroU32>, limit: Duration) {
    let Some(tid) = tid else {
        return;
    };
    let until = Instant::now().checked_add(limit);
    while task_present(tid) {
        if until.is_some_and(|u| Instant::now() >= u) {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// launch しない準備済みの結果を捨てる後始末へ変える（I/O はしない）。予約の解放は報告の後に
/// [`cleanup_after_report`] が行い、戻せたら cgroup を消す。戻せなければ cgroup を消さない（予約が Running・pid
/// なしで残るため `recover_interrupted_start` での回復を待つ。CORE-2・REPAIR-5）。
fn discard_prepared(prepared: Prepared) -> Cleanup {
    Cleanup::DiscardClaim(prepared.claimed)
}

/// 入口が待つのをやめた後に作業スレッドが戻ったとき（または期限超過の報告の後に結果が出たとき）の後始末。
///
/// launch はしない。準備が済んだ結果（`Ready`）は作った cgroup を消し、失敗の結果はその後始末を行う
/// （best effort。プロセスの終了までに終われば行う）。
fn abandoned_cleanup(
    deps: Box<dyn StartDeps + Send>,
    store: &Arc<dyn StateStore>,
    id: &ContainerId,
    timeouts: &StartTimeouts,
    outcome: PrepareOutcome,
) {
    let cleanup = match outcome {
        PrepareOutcome::Ready(prepared) => discard_prepared(prepared),
        PrepareOutcome::Failed { cleanup, .. } => cleanup,
    };
    let _ = cleanup_after_report(deps, store, id, timeouts, cleanup);
}
/// `f`（状態ストア・cgroup への I/O を含む後始末の全体）を作業スレッドで実行し、`limit` まで結果を待つ。
/// `f` が `true` を返したと確認できたら `true`。
///
/// 期限内に確認できない場合・スレッドを作れない場合・`f` が `false` の場合は `false`（予約と cgroup は残し、
/// `recover_interrupted_start` での回復に委ねる）。期限後も作業スレッドは `f` を最後まで実行する（プロセスの
/// 終了まで）。そのため、遅れて成功する予約の解放の後の cgroup の削除など、`f` の後半も取りこぼさない。
/// 状態ストア（FUSE・ストレージ上の `FileStateStore` の fsync 等）が止まっても、入口は無期限に止まらない
/// （REPAIR-5・CORE-2）。
fn run_bounded<F>(name: &str, limit: Duration, f: F) -> bool
where
    F: FnOnce() -> bool + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let _ = tx.send(f());
        });
    spawned.is_ok() && rx.recv_timeout(limit).unwrap_or(false)
}

/// 失敗後の後始末（遅れた書き込みの完了待ち・修復・確認・terminate・cgroup の削除）を期限つきで行う上限。
///
/// 内側の待ち（`wait_settled`・`recover_after_timeout`・`settle_failed_start`・`terminate_retrying`）の各上限の
/// 合計に余裕を足す。超えたら確かめられない扱いにし、cgroup を残して失敗終了する（REPAIR-5）。
fn after_failure_limit(timeouts: &StartTimeouts) -> Duration {
    let step = timeouts
        .terminate()
        .saturating_add(timeouts.confirm())
        .saturating_add(LAUNCHER_REPLY_GRACE.saturating_mul(2));
    crate::start_contract::result_deadline(timeouts).saturating_add(step.saturating_mul(3))
}

/// 報告の後の後始末。確かめられたら `true`（確かめられなければ cgroup は消さない。CORE-1・CORE-2）。
///
/// 状態ストアに触れる後始末はすべて作業スレッドで行い、待ちを有限にする（[`run_bounded`]。REPAIR-5）。
fn cleanup_after_report(
    mut deps: Box<dyn StartDeps + Send>,
    store: &Arc<dyn StateStore>,
    id: &ContainerId,
    timeouts: &StartTimeouts,
    cleanup: Cleanup,
) -> bool {
    match cleanup {
        Cleanup::Nothing => true,
        Cleanup::ReleaseCgroup => release_logged(deps.as_mut()),
        Cleanup::DiscardClaim(claimed) => {
            // `release` は `StateStore::update` を同期実行する。解放と、成功した場合の cgroup の削除を同じ作業
            // スレッドで行い、期限後に遅れて解放が成功しても cgroup が Created の記録つきで残らないようにする。
            let store = Arc::clone(store);
            let confirmed = run_bounded(
                "supervisor-claim-release",
                crate::start_contract::result_deadline(timeouts),
                move || {
                    if claimed.release(store.as_ref()).is_ok() {
                        release_logged(deps.as_mut())
                    } else {
                        // 予約が残り得る。cgroup は消さない。
                        log_event("start_claim_release_failed", Some(ErrorCode::Internal));
                        false
                    }
                },
            );
            if !confirmed {
                log_event("start_claim_release_unconfirmed", Some(ErrorCode::Internal));
            }
            confirmed
        }
        Cleanup::AfterFailure(launcher, pending, late) => {
            let (store, id, timeouts_owned) = (Arc::clone(store), id.clone(), *timeouts);
            let confirmed = run_bounded(
                "supervisor-cleanup",
                after_failure_limit(timeouts),
                move || {
                    if settle_after_late_writes(
                        store.as_ref(),
                        &launcher,
                        &id,
                        &timeouts_owned,
                        pending,
                        &late,
                    ) {
                        // cgroup の削除の失敗も後始末の失敗として返す（終了コードを INTERNAL にする。CORE-3）。
                        release_logged(deps.as_mut())
                    } else {
                        // 予約か子が残り得る。cgroup は消さない（子が入っている可能性がある）。
                        log_event("start_cleanup_unconfirmed", Some(ErrorCode::Internal));
                        false
                    }
                },
            );
            if !confirmed {
                log_event(
                    "start_cleanup_unbounded_or_failed",
                    Some(ErrorCode::Internal),
                );
            }
            confirmed
        }
    }
}

/// 手順 3〜7（作業スレッドで実行）。後始末は行わず、要る後始末の種類を返す。
///
/// 成功経路では [`log_event`] を呼ばない（手順 8 の前に常駐スレッドを作らない。モジュール doc）。
fn prepare_start(
    deps: &mut dyn StartDeps,
    store_arc: &Arc<dyn StateStore>,
    req: &StartRequest,
) -> PrepareOutcome {
    let fail = |e: TraitError, cleanup: Cleanup| PrepareOutcome::Failed {
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
    let capturing = Arc::new(SpecCapturingLauncher::new(Arc::clone(&inner)));
    let launcher: Arc<dyn ProcessLauncher> = capturing.clone();
    // 起動権の予約（状態の読み取り・bundle の検証・所有ロック・予約の更新）。ファイル I/O を含むため、入口が期限で
    // 待ち切れる作業スレッドで行う。ここまでで launcher は呼ばない（REPAIR-5・CORE-2）。
    let claimed = match claim_start(store, launcher.as_ref(), req) {
        Ok(c) => Box::new(c),
        // 予約は取れていない（状態は Created のまま）。作った cgroup だけを消す。
        Err(e) => {
            return PrepareOutcome::Failed {
                error: e,
                cleanup: Cleanup::ReleaseCgroup,
            };
        }
    };
    // 世代の照合。予約中のレコードは delete が拒否するため、予約の後にここで照合すれば、準備の後・予約の前に同じ ID が
    // 削除・再作成された場合を漏れなく拒否できる。launch 時に `store.get` を入口スレッドで行うと期限の保護から外れる
    // ため、作業スレッドで済ませる（CORE-2・CORE-3・SEC-1・REPAIR-5）。
    let matches = store
        .get(&GetStateRequest::new(req.id().clone()))
        .map(|r| r.cgroup().map(|c| c.instance()) == prepared);
    match matches {
        Ok(true) => {}
        other => {
            let error = match other {
                Err(e) => op_err(e),
                _ => op_err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "the container was recreated after its cgroup was prepared",
                )),
            };
            // 予約は報告の後に戻す（ここでは I/O を足さない）。
            return PrepareOutcome::Failed {
                error,
                cleanup: Cleanup::DiscardClaim(claimed),
            };
        }
    }
    PrepareOutcome::Ready(Prepared {
        inner,
        capturing,
        launcher,
        logs,
        claimed,
    })
}

/// 手順 8（入口スレッドで実行）。`oci_runtime::launch_claimed` を呼び、成功なら監視に要るものを、失敗なら後始末の種類を返す。
fn launch_prepared(
    prepared: Prepared,
    store_arc: &Arc<dyn StateStore>,
    recorder: &OpRecorder,
    timeouts: &StartTimeouts,
    deadline: Option<Instant>,
) -> Attempt {
    let Prepared {
        inner,
        capturing,
        launcher,
        logs,
        claimed,
    } = prepared;
    // launch の後の状態 I/O（Running の記録・失敗時の予約の解放）は期限（報告の書き込み分を除く）で打ち切る。
    // 打ち切られて残る予約は報告の後の後始末が回復する（REPAIR-5・CORE-2）。
    // 保存が期限で打ち切られると core は子の terminate を始める。その待ち（terminate と応答猶予）も報告の前に
    // 収まるよう、保存の期限をその分だけ前倒しする（REPAIR-5）。
    let terminate_reserve = timeouts.terminate().saturating_add(LAUNCHER_REPLY_GRACE);
    let until = deadline.map(|d| {
        d.checked_sub(REPORT_RESERVE)
            .and_then(|t| t.checked_sub(terminate_reserve))
            .unwrap_or(d)
    });
    let bounded = DeadlineStore::new(Arc::clone(store_arc), until);
    let late = bounded.late_writes();
    // 8（予約は作業スレッドで済ませてある。ここは launcher の呼び出しと Running の記録だけ）
    match launch_claimed(&bounded, recorder, &launcher, *claimed, timeouts) {
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
            cleanup: Cleanup::AfterFailure(launcher, take_unreaped_processes(), late),
        },
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

/// 打ち切った状態 I/O の完了を待ち、遅れて成功した Running・pid ありの記録を修復してから
/// [`settle_failed_start`] で確かめる（CORE-2・REPAIR-5）。確かめられたら `true`。
///
/// 遅れた `update` が後から成功すると、core の予約の解放（revision 不一致）が外れ、回収済みの pid が Running のまま
/// 残る（`recover_interrupted_start` は pid ありを回復しない）。そこで完了を待ち、子の回収と不在確認を済ませてから、
/// 記録が遅れた書き込みのままのときだけ Created へ戻す。待ちが上限を超えたら、後から書かれ得るため確かめられない
/// 扱いにする（cgroup を消さない）。
fn settle_after_late_writes(
    store: &dyn StateStore,
    launcher: &Arc<dyn ProcessLauncher>,
    id: &ContainerId,
    timeouts: &StartTimeouts,
    pending: Vec<Box<dyn LaunchedProcess>>,
    late: &LateWrites,
) -> bool {
    let settled = late.wait_settled(timeouts.terminate().saturating_add(LAUNCHER_REPLY_GRACE));
    if !settled {
        log_event("late_store_write_unsettled", Some(ErrorCode::Timeout));
    }
    let commits = late.take_commits();
    if commits.is_empty() {
        return settle_failed_start(store, launcher, id, timeouts, pending) && settled;
    }
    // 遅れた記録がある。先に子を回収し、不在を確かめてから記録を戻す。
    let mut reaped = true;
    for p in pending.into_iter().chain(take_unreaped_processes()) {
        if terminate_retrying(p, timeouts.terminate()).is_none() {
            reaped = false;
        }
    }
    let mut repaired = reaped && launcher.confirm_no_process(id, timeouts.confirm()).is_ok();
    if repaired {
        for commit in &commits {
            if let Err(code) = revert_late_running(store, id, commit) {
                log_event("late_running_revert_failed", Some(code));
                repaired = false;
            }
        }
    }
    settle_failed_start(store, launcher, id, timeouts, Vec::new()) && settled && repaired
}

/// 遅れて成功した Running の記録が（revision・pid とも）そのまま残っていれば Created へ戻す。
/// 別の更新や再作成で変わっていれば書かない（別インスタンスを上書きしない。SEC-1）。
fn revert_late_running(
    store: &dyn StateStore,
    id: &ContainerId,
    commit: &StateRecord,
) -> Result<(), ErrorCode> {
    let record = store
        .get(&GetStateRequest::new(id.clone()))
        .map_err(|e| e.code())?;
    let status = record.status();
    let same = record.revision() == commit.revision()
        && status.state() == ContainerState::Running
        && status.pid().is_some()
        && status.pid() == commit.status().pid();
    if !same {
        return Ok(());
    }
    store
        .update(&UpdateStateRequest::new(
            ContainerStatus::created(id.clone(), None),
            record.revision(),
        ))
        .map(drop)
        .map_err(|e| e.code())
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
/// [`mark_stopped`] 全体の待ちの上限（REPAIR-5）。
const MARK_STOPPED_LIMIT: Duration = Duration::from_secs(10);

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
    // 読み書きは `StateStore` の同期呼び出し（FUSE・ストレージの停止で止まり得る）のため、作業スレッドで行い待ちを
    // 有限にする。期限を過ぎたら記録できなかった扱い（INTERNAL）で終わる。遅れて成功する書き込みは `Stopped` で
    // 照合つきのため害はない（REPAIR-5）。
    let (store, id, reaped) = (Arc::clone(store), id.clone(), reaped.to_vec());
    run_bounded("supervisor-mark-stopped", MARK_STOPPED_LIMIT, move || {
        for attempt in 1..=MARK_STOPPED_ATTEMPTS {
            match try_mark_stopped(store.as_ref(), &id, instance, &reaped) {
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
    })
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

    use fandhe_container_core::audit_log::AuditSink;
    use fandhe_container_core::cgroups::{CgroupLimitPlan, ContainerCgroup, DelegatedCgroup};
    use fandhe_container_core::exec::IsolationPrivilege;
    use fandhe_container_core::landlock::detect_landlock_abi;
    use fandhe_container_core::oci_runtime::ProductionLauncher;

    use super::*;
    use crate::privilege::{MAX_STATUS_BYTES, parse_proc_status};
    use crate::start_contract::StartArgs;

    /// 結果チャネルの書き込みの期限（読み手が読まず pipe が満杯でも監視へ進むため。REPAIR-5）。
    const REPORT_WRITE_DEADLINE: Duration = Duration::from_secs(5);
    /// stderr への報告 1 行（結果チャネルが使えないとき）と、終了前のログの書き出しを待つ期限（REPAIR-5）。
    const STDERR_DEADLINE: Duration = Duration::from_secs(1);
    /// supervisor ログの準備（手順 2b）を待つ上限（全体期限から報告の予約分を引いた残りでさらに絞る）。
    const LOG_PREPARE_DEADLINE: Duration = Duration::from_secs(5);

    /// 本番の [`StartDeps`]。core の本番 `ProcessLauncher`（`oci_runtime::ProductionLauncher`）へ結線する
    /// （#1819・SUP-1・CORE-1・CORE-2・CORE-3・CORE-5・SEC-1・SEC-4・SEC-5）。
    ///
    /// 呼び出し元は [`run_main`]（手順 4〜7 を作業スレッドで呼ぶ）。権限モデルは自プロセスの資格情報から決め、
    /// 手順 4 で権限モデルと Landlock ABI を副作用なしで確かめる。cgroup の参加フックと監査 sink は launcher の
    /// 構築器へ渡し、restart の再 launch も同じ launcher を使う（起動の経路を 2 つにしない。SUP-3）。
    pub struct ProductionStartDeps {
        root: PathBuf,
        /// 自プロセスの資格情報から決めた権限モデル。決められなければ手順 4 がそのエラーで止める。
        privilege: Result<IsolationPrivilege, TraitError>,
        cgroup: Option<HeldCgroup>,
        audit: Option<Arc<dyn AuditSink>>,
    }

    /// 手順 5 で作った cgroup（`release_cgroup` と launcher の参加フックの源で共有する）。
    struct HeldCgroup {
        delegated: DelegatedCgroup,
        cgroup: Arc<ContainerCgroup>,
    }

    /// `/proc/self/status` の内容から launcher の権限モデルを決める（純関数。#1819・SEC-5・CORE-6）。
    ///
    /// real / effective / saved / fs のいずれかの uid が 0 なら rootful で、core の本番 launcher が
    /// `RootfulHostRoot` を `Unimplemented` で拒否するのと揃えて、同じコードで拒否する（コンテナ内 root を
    /// ホスト root に写す起動を作らない）。それ以外は `RootlessSingleId`（特権ランチャーの ambient capability 経由でも
    /// uid は非 root）。読めない・壊れた入力は fail-closed に `FailedPrecondition`。
    fn privilege_for_status(text: &str) -> Result<IsolationPrivilege, TraitError> {
        let snapshot = parse_proc_status(text)
            .map_err(|e| TraitError::new(e.code, "failed to read the process credentials"))?;
        let uid = snapshot.uid;
        if [uid.real, uid.effective, uid.saved, uid.fs].contains(&0) {
            return Err(TraitError::new(
                ErrorCode::Unimplemented,
                "rootful start is not supported by the production launcher",
            ));
        }
        Ok(IsolationPrivilege::RootlessSingleId)
    }

    /// `/proc/self/status` を上限つきで読む。
    fn read_self_status() -> Result<String, TraitError> {
        use std::io::Read as _;
        let unreadable = || {
            TraitError::new(
                ErrorCode::FailedPrecondition,
                "process status is unreadable",
            )
        };
        let mut text = String::new();
        let limit = u64::try_from(MAX_STATUS_BYTES + 1).unwrap_or(u64::MAX);
        File::open("/proc/self/status")
            .and_then(|f| f.take(limit).read_to_string(&mut text))
            .map_err(|_| unreadable())?;
        Ok(text)
    }

    impl ProductionStartDeps {
        /// 状態ルート（`--root`）から作る。権限モデルは自プロセスの資格情報から決める（`/proc/self/status` は
        /// dumpable 0 の影響を受ける `/proc/self` の所有者ではなく、内容を読む）。
        pub fn new(root: PathBuf) -> Self {
            let privilege = read_self_status().and_then(|text| privilege_for_status(&text));
            Self {
                root,
                privilege,
                cgroup: None,
                audit: None,
            }
        }
    }

    impl StartDeps for ProductionStartDeps {
        /// 権限モデルが決められること、Landlock ABI が 6 以上であることを確かめる（副作用なし）。launcher は同じ条件を
        /// fork の前に拒否するが、cgroup の連鎖（取り消せないスコープの追記）の前に止めるためここで前倒しする（CORE-5）。
        /// `ProductionLauncherBuilder::build` は child subreaper 化の副作用を持つため、ここでは呼ばない。
        fn check_launcher_available(&self) -> Result<(), TraitError> {
            self.privilege.clone()?;
            detect_landlock_abi().map(drop).map_err(|e| {
                TraitError::new(
                    e.code,
                    "Landlock ABI 6 or newer is required to start a container",
                )
            })
        }

        fn prepare_cgroup(
            &mut self,
            store: &dyn StateStore,
            observed: &StateRecord,
        ) -> Result<Option<StateRevision>, TraitError> {
            let privilege = self.privilege.clone()?;
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
            // 参加フックは起動のたびに `ContainerCgroup::join_hook` で作り直す（launcher の `cgroup_join_source`。
            // `CgroupJoin` は Clone でなく、restart の再 launch でも使うため）。ここで取り出した最初のフックは使わない。
            let (cgroup, _first_join, _record, _report) = start_cgroup.into_parts();
            self.cgroup = Some(HeldCgroup {
                delegated,
                cgroup: Arc::new(cgroup),
            });
            Ok(instance)
        }

        fn build_audit_sink(&mut self) -> Result<(), TraitError> {
            let sink = crate::exec::default_audit_sink(Some(self.root.clone()))?;
            self.audit = Some(Arc::new(sink));
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

        /// 権限モデル・監査 sink・cgroup の参加フックの源を渡して `ProductionLauncher` を作る
        /// （core の launcher が必須値の欠落を `InvalidArgument` で拒否する）。呼び出しプロセスは child subreaper に
        /// なる。launch の単一スレッド要求は入口が満たす（モジュール doc「手順 8 を入口スレッドで行う理由」）。
        fn build_launcher(&mut self) -> Result<Arc<dyn ProcessLauncher>, TraitError> {
            let privilege = self.privilege.clone()?;
            let (Some(held), Some(audit)) = (self.cgroup.as_ref(), self.audit.as_ref()) else {
                return Err(TraitError::new(
                    ErrorCode::Internal,
                    "the launcher was built before its prerequisites",
                ));
            };
            let source = Arc::clone(&held.cgroup);
            let launcher = ProductionLauncher::builder()
                .privilege(privilege)
                .audit_sink(Arc::clone(audit))
                .cgroup_join_source(move || source.join_hook())
                .build()?;
            Ok(Arc::new(launcher))
        }

        fn release_cgroup(&mut self) -> Result<(), TraitError> {
            let Some(held) = self.cgroup.as_ref() else {
                return Ok(());
            };
            held.delegated
                .remove_child(&held.cgroup)
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

    /// 手順 2b: `id` のレコードがあるときだけ supervisor ログ（`<root>/@supervisor-logs/<id>.log`）を開き、
    /// `stderr_sink` の書き先へ差し込む（#2067・REPAIR-4）。
    ///
    /// レコードが無い（`NotFound`）場合は何もせず先へ進む（詳細なエラーは手順 3 が報告する。打ち間違えた ID のために
    /// `delete` で消せないログを作らない）。レコードの取得が `Timeout` 等で失敗したら保存先を確定できないため
    /// 失敗として返す。開くのに失敗したら呼び出し側が fail-closed で報告する（ログ喪失を黙って
    /// 許さない。同じ ID の supervisor が生存中なら `FailedPrecondition`）。
    ///
    /// 状態ストアの取得とログのディレクトリ走査・ローテーション・`sync_dir` は保存先の I/O が止まりうるため、
    /// 作業スレッドで行い `until` まで待つ（REPAIR-5）。成功時は作業スレッドを `join` で終了させてから返すため、
    /// 後続の `oci_runtime::start` の単一スレッド要求を満たす。期限超過時は `Timeout` を返す（作業スレッドは
    /// 残るが、呼び出し側は launch せず失敗を報告して終わる）。
    fn prepare_supervisor_log(
        store: &Arc<dyn StateStore>,
        root: &std::path::Path,
        id: &ContainerId,
        until: Option<Instant>,
    ) -> Result<(), TraitError> {
        let (store, root, id) = (Arc::clone(store), root.to_path_buf(), id.clone());
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::Builder::new()
            .name("fandhe-suplog".into())
            .spawn(move || {
                let _ = tx.send(open_supervisor_log(&store, &root, &id));
            })
            .map_err(|_| {
                TraitError::new(
                    ErrorCode::Internal,
                    "failed to spawn the log prepare worker",
                )
            })?;
        let until = until.map(|d| d.checked_sub(REPORT_RESERVE).unwrap_or(d));
        let limit = write_limit(LOG_PREPARE_DEADLINE, until, Instant::now());
        match rx.recv_timeout(limit) {
            Ok(result) => {
                // 送信は作業スレッドの最後の処理。join で OS スレッドの終了まで確認する（単一スレッドの回復）。
                let _ = handle.join();
                result
            }
            Err(_) => Err(TraitError::new(
                ErrorCode::Timeout,
                "supervisor log preparation timed out",
            )),
        }
    }

    /// [`prepare_supervisor_log`] の本体（作業スレッドで実行する）。
    fn open_supervisor_log(
        store: &Arc<dyn StateStore>,
        root: &std::path::Path,
        id: &ContainerId,
    ) -> Result<(), TraitError> {
        if !record_exists(store.as_ref(), id)? {
            return Ok(());
        }
        // ストアが受理した（親 symlink 解決済みの）状態ルートの下に置く。生の `--root` だと、ストアは受理するのに
        // RotatingFileSink が root 所有でない symlink を拒否して fail-closed になる。ストアが示せなければ引数を使う。
        let log_root = supervisor_log_root(store, root);
        let writer = crate::supervisor_log::open(log_root, id)?;
        crate::stderr_sink::install_stderr_writer(Box::new(writer))
    }

    /// `id` のレコードがあるか。`NotFound` だけを「なし」とし、`Timeout`（`@lock` 待ち）等の取得失敗は
    /// 保存先を確定できないのでそのまま返す（ログが null の stderr へ流れるのを防ぐ fail-closed。#2067・REPAIR-4）。
    fn record_exists(store: &dyn StateStore, id: &ContainerId) -> Result<bool, TraitError> {
        match store.get(&GetStateRequest::new(id.clone())) {
            Ok(_) => Ok(true),
            Err(e) if e.code() == ErrorCode::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// supervisor ログを置く状態ルート。ストアの `host_state_root()`（検査済み）を優先し、無ければ引数の root。
    fn supervisor_log_root<'a>(
        store: &'a Arc<dyn StateStore>,
        root: &'a std::path::Path,
    ) -> &'a std::path::Path {
        store.host_state_root().unwrap_or(root)
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
        // 0a: 継承 fd（fd 3 以降）を閉じる（特権ランチャーと同じ処理。SEC-1・SUP-14・#2070）。CLI の直接起動は
        // CLOEXEC の無い親由来の fd を閉じないため、ここで契約上の fd 0〜2 だけにする。結果チャネルの複製
        // （F_DUPFD_CLOEXEC で 3 以上の fd を作る）より前でなければ結果チャネルを壊すため、最初の文に置く。
        // 失敗しても結果チャネルは試み、開けたら INTERNAL を報告して起動へ進まない（fail-closed）。
        let close_result = crate::sys::close_fds_from(crate::start_contract::FIRST_INHERITED_FD);
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
        if let Err(e) = close_result {
            return fail(
                &mut out,
                op_err(TraitError::new(
                    ErrorCode::Internal,
                    format!("closing inherited fds failed: {}", e.kind()),
                )),
            );
        }
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
        // 回復・回収と報告の書き込みで同じ期限を共有し、報告を内部上限内に収める（REPAIR-5）。
        let deadline =
            Instant::now().checked_add(crate::start_contract::result_deadline(&timeouts));
        out.limit_until(deadline);
        // 2b: supervisor の構造化ログの保存先を開き、stderr の出口の書き先を差し替える（#2067・REPAIR-4）。
        // 期限つきの作業スレッドで行い、終了を確認してから先へ進む。開けなければ fail-closed で、手順 3 より前に止まる。
        if let Err(e) = prepare_supervisor_log(&store, &args.root, &args.id, deadline) {
            return fail(&mut out, op_err(e));
        }
        let deps = Box::new(ProductionStartDeps::new(args.root));
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use fandhe_container_core::traits::{
            CreateStateRequest, DeleteStateRequest, DeleteStateResponse, ListStateRequest,
            StateList,
        };

        /// 資格情報だけを変えた `/proc/self/status` の fixture（必須項目は縮退後の非特権プロセス相当）。
        fn status(uid: &str, gid: &str) -> String {
            format!(
                "Name:\tx\nUid:\t{uid}\nGid:\t{gid}\nGroups:\t\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\n"
            )
        }

        /// SEC-5・CORE-6・#1819: 4 つ組の uid がすべて非 root なら `RootlessSingleId`。
        #[test]
        fn sec5_non_root_uid_selects_rootless_single_id() {
            assert_eq!(
                privilege_for_status(&status("1000\t1000\t1000\t1000", "1000\t1000\t1000\t1000")),
                Ok(IsolationPrivilege::RootlessSingleId)
            );
        }

        /// SEC-5・#1819: real / effective / saved / fs のどれかが 0 なら rootful として、core の launcher と同じ
        /// `Unimplemented`（固定文言）で副作用の前に拒否する。
        #[test]
        fn sec5_any_root_uid_is_rejected_as_unimplemented() {
            for uid in [
                "0\t1000\t1000\t1000",
                "1000\t0\t1000\t1000",
                "1000\t1000\t0\t1000",
                "1000\t1000\t1000\t0",
                "0\t0\t0\t0",
            ] {
                let e = privilege_for_status(&status(uid, "1000\t1000\t1000\t1000"))
                    .expect_err("rootful must be rejected");
                assert_eq!(e.code(), ErrorCode::Unimplemented, "uid: {uid}");
                assert_eq!(
                    e.message(),
                    "rootful start is not supported by the production launcher"
                );
            }
        }

        /// REPAIR-4・#2067: 親が symlink の `--root` でも、ログはストアの解決済み状態ルートの下に開ける。
        #[cfg(unix)]
        #[test]
        fn repair4_log_root_follows_store_host_state_root_through_symlink() {
            let base = std::env::temp_dir().join(format!("fc-slog-{}", std::process::id()));
            let real = base.join("real");
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&real).expect("mkdir");
            {
                use std::os::unix::fs::PermissionsExt as _;
                for d in [&base, &real] {
                    std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))
                        .expect("chmod");
                }
            }
            let link_parent = base.join("link");
            std::os::unix::fs::symlink(&base, &link_parent).expect("symlink");
            let raw_root = link_parent.join("real");
            let store = crate::state::open_default_store(Some(raw_root.clone())).expect("store");
            let log_root = supervisor_log_root(&store, &raw_root).to_path_buf();
            let id = ContainerId::new("c1").expect("id");
            let opened = crate::supervisor_log::open(&log_root, &id);
            let _ = std::fs::remove_dir_all(&base);
            assert!(
                opened.is_ok(),
                "log must open under the store root: {:?}",
                opened.err()
            );
        }

        /// 指定の結果を返す `get` だけのストア（他は到達しない）。
        struct GetOnly(Result<(), ErrorCode>);
        impl StateStore for GetOnly {
            fn create(&self, _: &CreateStateRequest) -> Result<StateRecord, TraitError> {
                Err(TraitError::new(ErrorCode::Internal, "unused"))
            }
            fn update(&self, _: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
                Err(TraitError::new(ErrorCode::Internal, "unused"))
            }
            fn get(&self, _: &GetStateRequest) -> Result<StateRecord, TraitError> {
                match self.0 {
                    Ok(()) => StateRecord::new(
                        ContainerStatus::created(ContainerId::new("c1").expect("id"), None),
                        std::env::temp_dir().join("b"),
                        StateRevision::from_raw(1),
                    ),
                    Err(c) => Err(TraitError::new(c, "fake")),
                }
            }
            fn list(&self, _: &ListStateRequest) -> Result<StateList, TraitError> {
                Err(TraitError::new(ErrorCode::Internal, "unused"))
            }
            fn delete(&self, _: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
                Err(TraitError::new(ErrorCode::Internal, "unused"))
            }
        }

        /// REPAIR-4・#2067: レコードなし（`NotFound`）だけが「なし」。`Timeout` 等の取得失敗はエラーで返す。
        #[test]
        fn repair4_record_exists_distinguishes_not_found_from_get_failure() {
            let id = ContainerId::new("c1").expect("id");
            assert_eq!(record_exists(&GetOnly(Ok(())), &id), Ok(true));
            assert_eq!(
                record_exists(&GetOnly(Err(ErrorCode::NotFound)), &id),
                Ok(false)
            );
            let e = record_exists(&GetOnly(Err(ErrorCode::Timeout)), &id)
                .expect_err("timeout must not be treated as absent");
            assert_eq!(e.code(), ErrorCode::Timeout);
        }

        /// SEC-5・#1819: 壊れた・欠けた入力は fail-closed に拒否し、入力値を文言へ埋め込まない。
        #[test]
        fn sec5_malformed_status_fails_closed() {
            for text in ["", "Uid:\t1000\n", "Name:\tx\nUid:\tabc\n"] {
                let e = privilege_for_status(text).expect_err("must be rejected");
                assert_eq!(e.code(), ErrorCode::FailedPrecondition, "text: {text:?}");
                assert_eq!(e.message(), "failed to read the process credentials");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// REPAIR-5・CORE-2: 止まった後始末は期限で `false` になり、遅れて終わった処理は放棄後も最後まで走る。
    #[test]
    fn repair5_run_bounded_times_out_but_lets_late_work_finish() {
        let done = Arc::new(AtomicU32::new(0));
        let flag = Arc::clone(&done);
        let started = Instant::now();
        let ok = run_bounded("test-bounded", Duration::from_millis(50), move || {
            std::thread::sleep(Duration::from_millis(300));
            flag.store(1, Ordering::SeqCst);
            true
        });
        assert!(!ok);
        assert!(started.elapsed() < Duration::from_millis(250));
        assert_eq!(done.load(Ordering::SeqCst), 0);
        let end = Instant::now() + Duration::from_secs(5);
        while done.load(Ordering::SeqCst) == 0 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(done.load(Ordering::SeqCst), 1);
    }

    /// 期限内に終われば結果をそのまま返す。
    #[test]
    fn repair5_run_bounded_returns_the_result_within_the_limit() {
        assert!(run_bounded("test-bounded", Duration::from_secs(5), || true));
        assert!(!run_bounded("test-bounded", Duration::from_secs(5), || {
            false
        }));
    }
}
