//! supervisor の bin の入口: 起動 → 結果の返却 → 監視（`monitor` / restart）を 1 プロセスで行う処理順
//! （TASK-157 追補・#1717・SUP-1・SUP-3・MS-9。関連: CORE-1・CORE-2・CORE-3・SEC-1・SEC-4・REPAIR-3・REPAIR-4・REPAIR-5・D-19）。
//!
//! 呼び出し元は `src/main.rs`（`run_main`）。CLI（#1718）が [`crate::start_contract`] の契約で起動し、結果チャネル
//! （stdout の pipe）の 1 行を読む。#1314 のオーナー判断（配置 1-A・cgroup 3-ii）により、`oci_runtime::start`
//! （Created → Running の予約と記録）を呼ぶ層は CLI から本入口へ移った。
//!
//! # 処理順（[`run_start`] と [`run_supervised`]）
//! 0a. 継承 fd（fd 3 以降）を閉じ、fd 0〜2 が開いていることを確かめる（ランチャーと同じ処理。結果チャネルの複製より前。
//!    #2070・#2132。fd 0〜2 は Rust std が `main` より前に `/dev/null` で埋めるため、実 bin では確認が通る多層防御の backstop）／
//! 0. 結果チャネルの検証（stdout が FIFO か。`run_main`）／1. argv の解析（[`crate::start_contract::StartArgs`]）／
//! 2. スレッド数が 1 か（`oci_runtime::start` の前提。以後のスレッドは手順 3〜7 の作業スレッド〔入口は待つだけ〕と
//!    手順 10 以降のログ捕捉・restart のワーカーと、制御チャネルの accept スレッド〔`control`。#2058〕に限る）／
//!    2b. supervisor の構造化ログの保存先を開き、`stderr_sink` の書き先を差し替える（レコードがあるときだけ。期限つきの
//!    作業スレッドで行い終了を確認してから進む。失敗は fail-closed。保存先と上限は [`crate::supervisor_log`]。#2067・REPAIR-4）／
//! 3. 状態の事前確認（Created・pid なし・cgroup 未記録。副作用なし。Running・pid なしの予約が残っていれば
//!    [`StartDeps::recover_interrupted`] で Created へ戻して `FailedPrecondition` を報告する。#2011）／4. [`StartDeps::check_launcher_available`]
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
//! - 別プロセスの supervisor が落ちて予約（Running・pid なし）だけが残った場合、次の `start` は手順 3 で
//!   [`StartDeps::recover_interrupted`] を呼ぶ（core が記録済みの cgroup 配置から残存を確かめ、居れば止めて Created へ戻す。
//!   CLI は状態を書かず、回復は supervisor が行う）。戻した後もその start は続けず、`FailedPrecondition`
//!   （`delete` と再作成を促す）を報告する。回復に失敗したらそのエラーを報告し、予約は残る（再試行できる）。
//!
//! # 未実装・残余（REPAIR-3）
//! - **restart の再 launch**: 本番 launcher の結線は済んでいる（start と同じ launcher と `LaunchSpec` を使う）が、
//!   再 launch は `fandhe-relaunch` スレッドや `stderr_sink` の常駐スレッドが存在する状態で呼ばれるため、本番 launcher が
//!   `FailedPrecondition` で拒否し、`RelaunchFailed` で終わる（fail-closed。子は作られない）。単一スレッドの呼び出し
//!   スレッドで再 launch する再構成は #2043（SUP-3・CORE-1）で行う。
//!   制御チャネルの accept スレッドも #2043 で止める対象に 1 本増える（停止の口は `control::server::ControlServer::shutdown`）。
//! - CLI の `stop`・`kill` からのシグナル送信は `control`（制御チャネル。#2058）が受け、CLI の `stop` は結線済み（#2059）。`kill` への結線（#1902）と
//!   明示的な stop の意図の伝達（SUP-9）は未実装。
//! - 権限モデルは rootless のみ（実効 uid が 0 の rootful 起動は手順 4 で拒否する。SEC-5）。1 対 1 の `RootlessSingleId` か
//!   範囲写像の `RootlessSubordinateIds` かは `/etc/subuid`・`/etc/subgid` の設定で選ぶ（#2243・CORE-6。規則と所有者名の
//!   取得は `id_model`）。
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
    ContainerId, ContainerState, ContainerStatus, ErrorCode, ExplicitStop, GetStateRequest,
    StartRequest, StateRecord, StateRevision, StateStore, SupervisionState, TraitError,
    UpdateStateRequest,
};

use crate::deadline_store::{DeadlineStore, LateWrites};
use crate::log_pipeline::CaptureHub;
use crate::logs::LogSink;
use crate::restart::{
    LateOrphans, LauncherRelauncher, Relauncher, RestartConfig, RestartPolicy,
    SpecCapturingLauncher, SuperviseOutcome, supervise_with_restart,
};
use crate::run::{MonitorConfig, StderrLogObserver, StopToken};
use crate::seccomp_notify::SeccompNotifyHub;
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

    /// seccomp の通知に応答するハブ（SEC-4・REPAIR-5・#2025）。`Some` を返す実装は、launcher を `UserNotif` 版の filter で
    /// 構築し、入口が起動・再起動のたびに listener を受け取ってハブへ渡す。既定は `None`（従来の ERRNO 版。通知なし）。
    fn seccomp_hub(&self) -> Option<Arc<SeccompNotifyHub>> {
        None
    }

    /// 手順 7: launcher を構築する（保持している cgroup の参加フックと監査 sink を使う）。
    fn build_launcher(&mut self) -> Result<Arc<dyn ProcessLauncher>, TraitError>;

    /// 作った cgroup を消す（`remove_child`）。mkdir 前なら何もしない。
    fn release_cgroup(&mut self) -> Result<(), TraitError>;

    /// 手順 3: 前の supervisor が start の途中で落ち、起動権の予約（Running・pid なし）だけが残っているコンテナを、
    /// Created へ戻す（別プロセスからの回復。`oci_runtime::recover_interrupted_start`。#2011・CORE-2・SEC-1）。
    ///
    /// 成功しても入口はその start を続けない（記録済みの配置から連鎖を再開する API が無いため。モジュール doc）。
    /// 既定実装は回復の手段を持たないため fail-closed で `Unimplemented`（フェイクの [`StartDeps`] は上書きしなくてよい）。
    /// cgroup の連鎖には触れない（スコープは記録済みで、`prepare_cgroup` / `release_cgroup` は呼ばれない）。
    fn recover_interrupted(
        &mut self,
        store: &dyn StateStore,
        id: &ContainerId,
        timeouts: &StartTimeouts,
    ) -> Result<(), TraitError> {
        let _ = (store, id, timeouts);
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "recovering an interrupted start is not supported",
        ))
    }
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
    /// seccomp の通知への応答ハブ（`StartDeps::seccomp_hub` が `Some` のときだけ。`run_supervised` が初回の listener を
    /// 渡し、全終了経路で畳む。再起動後の listener は `relauncher` が同じハブへ渡す。SEC-4・#2025）。
    pub seccomp: Option<Arc<SeccompNotifyHub>>,
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

/// `dev.tty.legacy_tiocsti` の観測値が警告対象なら、固定の 1 行を `sink` へ待たずに入れる（CORE-5・SEC-1・REPAIR-4・
/// REPAIR-5・#2008）。対象外なら何もせず `None`。キュー満杯でも待たず、結果は起動の可否に使わない。
fn log_legacy_tiocsti_to(
    sink: &crate::stderr_sink::StderrSink,
    state: fandhe_container_core::legacy_tiocsti::LegacyTiocsti,
) -> Option<crate::stderr_sink::EmitOutcome> {
    let line = fandhe_container_core::legacy_tiocsti::warning_line(state)?;
    Some(sink.emit(format!("{line}\n").into_bytes()))
}

/// start の成功後に `dev.tty.legacy_tiocsti` の警告を supervisor のログ（`@supervisor-logs`）へ 1 行残す（#2008）。
///
/// core の出力（fd 2 が AF_UNIX の socket のときだけ届く）は CLI の `start`（stderr が null）では捨てられるため、
/// supervisor が自分で観測して残す。`stderr_sink` の常駐スレッドを作るので、単一スレッド前提の区間が終わった後
/// （`oci_runtime::start` の成功後）にだけ呼ぶ。fd 2 が socket の構成では core の出力と重複するが、出力先が別なので
/// 許容する。restart の再 launch では再出力しない（host のグローバルな値で、初回に記録済みのため）。
/// 結線の検証: `observe` で観測値を差し替えられる（`run_start_until_observing`）。結合試験
/// `tests/start_tiocsti_wiring.rs` が別プロセスで共有 sink へ届くことを照合する（REPAIR-12）。
fn log_legacy_tiocsti(observe: fn() -> fandhe_container_core::legacy_tiocsti::LegacyTiocsti) {
    let _ = log_legacy_tiocsti_to(crate::stderr_sink::stderr(), observe());
}

/// launch が評価した監査の網羅(`launchIsolation.auditCoverage`)が縮退していれば、固定の警告 1 行を `sink` へ待たずに入れる
/// (SEC-4・REPAIR-4・REPAIR-5・#2027)。縮退していない・評価の記録が無いときは何もせず `None`。
/// キュー満杯でも待たず、結果は起動の可否に使わない。
fn log_audit_coverage_to(
    sink: &crate::stderr_sink::StderrSink,
    record: Option<&fandhe_container_core::launch_isolation::LaunchIsolationRecord>,
) -> Option<crate::stderr_sink::EmitOutcome> {
    use fandhe_container_core::launch_isolation::RecordedAuditCoverage;
    let RecordedAuditCoverage::Evaluated { coverage, .. } = record?.audit_coverage() else {
        return None;
    };
    let line = coverage.log_line()?;
    Some(sink.emit(format!("{line}\n").into_bytes()))
}

/// 縮退の監査記録(層 `audit_coverage`)を記録先へ書けなかった launch なら、固定の診断行 1 行を `sink` へ待たずに入れる
/// (SEC-4・REPAIR-4・REPAIR-5・#2468)。失敗していない・評価の記録が無いときは何もせず `None`。結果は起動の可否に使わない。
fn log_audit_coverage_record_failed_to(
    sink: &crate::stderr_sink::StderrSink,
    record: Option<&fandhe_container_core::launch_isolation::LaunchIsolationRecord>,
) -> Option<crate::stderr_sink::EmitOutcome> {
    let line = record?.audit_coverage_record().log_line()?;
    Some(sink.emit(format!("{line}\n").into_bytes()))
}

/// start の成功後に、launch が評価した監査の網羅の縮退警告を supervisor のログ(`@supervisor-logs`)へ 1 行残す(#2027)。
///
/// core の launch 中の出力(`emit_diagnostic_line`)は fd 2 が AF_UNIX の socket のときだけ届き、CLI の `start`(stderr が
/// null)では捨てられるため、`legacy_tiocsti` と同じく成功後に supervisor が起動結果の評価値から出し直す。
/// `stderr_sink` の常駐スレッドを作るので、単一スレッド前提の区間が終わった後にだけ呼ぶ。restart の再 launch では
/// 再出力しない(初回に記録済み)。
fn log_audit_coverage(process: &dyn LaunchedProcess) {
    let _ = log_audit_coverage_to(crate::stderr_sink::stderr(), process.launch_isolation());
    // 縮退の行に続けて、その監査記録を書けなかった事実を出す(core が fd 2 へ出す順と同じ。#2468)。
    let _ = log_audit_coverage_record_failed_to(
        crate::stderr_sink::stderr(),
        process.launch_isolation(),
    );
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
    run_start_until_observing(
        deps,
        store,
        recorder,
        req,
        timeouts,
        deadline,
        out,
        fandhe_container_core::legacy_tiocsti::read_host,
    )
}

/// [`run_start_until`] の `dev.tty.legacy_tiocsti` の観測を差し替えられる版（試験用の継ぎ目。#2008・REPAIR-12）。
///
/// 本番は [`run_start_until`] 経由で `read_host` を渡す。起動成功の経路から共有の `stderr_sink` へ警告が届く
/// 結線を、host の sysctl に依らず結合試験で確かめるために公開する。
#[doc(hidden)]
// 理由: `run_start_until` と同じ deps・store・recorder・req・timeouts・各 sink に read_host を足した入力で、
// 結合試験が個別に差し替えるため束ねる型を作らず引数のまま渡す。
#[allow(clippy::too_many_arguments)]
pub fn run_start_until_observing(
    deps: Box<dyn StartDeps + Send>,
    store: &Arc<dyn StateStore>,
    recorder: &Arc<OpRecorder>,
    req: &StartRequest,
    timeouts: &StartTimeouts,
    deadline: Option<Instant>,
    out: &mut dyn Write,
    observe: fn() -> fandhe_container_core::legacy_tiocsti::LegacyTiocsti,
) -> Result<Running, NonZeroU8> {
    let result = start_reporting(deps, store, recorder, req, timeouts, deadline, out, observe);
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
// 理由: 入口 `run_start_until` が受けた値を分解せずそのまま渡す本体で、束ねる型を作ると
// 呼び出し側の組み立てコードが増えるだけのため引数のまま渡す。
#[allow(clippy::too_many_arguments)]
fn start_reporting(
    deps: Box<dyn StartDeps + Send>,
    store: &Arc<dyn StateStore>,
    recorder: &Arc<OpRecorder>,
    req: &StartRequest,
    timeouts: &StartTimeouts,
    deadline: Option<Instant>,
    out: &mut dyn Write,
    observe: fn() -> fandhe_container_core::legacy_tiocsti::LegacyTiocsti,
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
        // Started 以外はここで確定する。Started はハブへの引き渡しまで含めた最終結果で記録する（二重計上しない。REPAIR-4）。
        if !matches!(attempt, Attempt::Started(_)) {
            record_start(recorder, started, false);
        }
        return match attempt {
            Attempt::Started(running) => {
                // 応答ハブの開始を成功報告の前に済ませる（報告の後に失敗すると、CLI へ成功を返したコンテナを
                // 回収して非 0 で終えることになるため。失敗なら回収して ERR を報告する。ERR-1・ERR-2・SEC-4）。
                #[cfg(target_os = "linux")]
                let running =
                    match attach_seccomp_before_report(running, store, req.id(), timeouts, out) {
                        Ok(r) => r,
                        Err(code) => {
                            record_start(recorder, started, false);
                            return Err(code);
                        }
                    };
                record_start(recorder, started, true);
                report(
                    out,
                    &StartReport::Started {
                        pid: running.process.pid(),
                    },
                );
                log_legacy_tiocsti(observe);
                log_audit_coverage(running.process.as_ref());
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

/// 成功報告の前に seccomp の応答ハブへ初回の listener を渡す。ハブが無い・渡し済みなら何もしない。
/// 渡せなければ ERR 行を先に書いてから（回収の待ちで CLI が報告を取り逃さないため）起動したプロセスを回収して
/// `Stopped` を記録し、終了コードを返す（fail-closed）。
#[cfg(target_os = "linux")]
fn attach_seccomp_before_report(
    running: Running,
    store: &Arc<dyn StateStore>,
    id: &ContainerId,
    timeouts: &StartTimeouts,
    out: &mut dyn Write,
) -> Result<Running, NonZeroU8> {
    let Some(hub) = running.seccomp.clone() else {
        return Ok(running);
    };
    if hub.is_attached() {
        return Ok(running);
    }
    let attached = match running.process.take_seccomp_listener() {
        Some(listener) => hub.attach(listener),
        None => Err(TraitError::new(
            ErrorCode::Internal,
            "the seccomp listener was not delivered",
        )),
    };
    let Err(e) = attached else {
        return Ok(running);
    };
    log_event("seccomp_notify_failed", Some(e.code()));
    let error = op_err(e);
    report(out, &StartReport::failed(&error));
    let Running {
        process, instance, ..
    } = running;
    let disposed = dispose(Some(process), None, timeouts);
    let code = finish_disposed(store, id, instance, disposed, error.exit_code().get());
    let code = NonZeroU8::new(code).unwrap_or_else(|| exit_code_for(ErrorCode::Internal));
    Err(code)
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
    /// seccomp の通知への応答ハブ。
    seccomp: Option<Arc<SeccompNotifyHub>>,
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
                let outcome = prepare_start(deps.as_mut(), &store, &req, &timeouts);
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
    timeouts: &StartTimeouts,
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
    // 前の supervisor が落ちて残った起動権の予約(Running・pid なし)は、記録済みの cgroup 配置で残存を確かめて
    // Created へ戻す(#2011)。戻した後もこの start は続けない: 配置は記録済みで連鎖を再開できないため、
    // `delete` と再作成を促す(下の「スコープ記録済み」の拒否と同じ理由)。cgroup には触れない。
    if status.state() == ContainerState::Running && status.pid().is_none() {
        return match deps.recover_interrupted(store, req.id(), timeouts) {
            Ok(()) => fail(
                TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "an interrupted start was recovered; delete and recreate the container",
                ),
                Cleanup::Nothing,
            ),
            Err(e) => fail(e, Cleanup::Nothing),
        };
    }
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
    let seccomp = deps.seccomp_hub();
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
        seccomp,
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
        seccomp,
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
                    let mut relauncher = LauncherRelauncher::new(inner, spec);
                    if let Some(hub) = &logs {
                        relauncher = relauncher.with_capture(Arc::clone(hub));
                    }
                    if let Some(hub) = &seccomp {
                        relauncher = relauncher.with_seccomp(Arc::clone(hub));
                    }
                    Arc::new(relauncher)
                }
                None => Arc::new(NoSpecRelauncher),
            };
            Attempt::Started(Running {
                process,
                relauncher,
                instance,
                logs,
                seccomp,
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

/// [`finish_disposed`] に加え、`explicit_stop_pending`（再 launch 中に受理した明示 stop が未記録）なら、回収と
/// `Stopped` の記録を確かめられた後に世代を照合して「明示 stop 済み」を残す（#2440・SUP-9・SUP-3・契約 14）。
/// 回収を確かめられなかった場合は記録を動かさず、残せなかった場合は `Internal`（fail-closed。残さないと
/// `unless-stopped` が停止済みのコンテナを再起動対象にしてしまう）。
fn finish_disposed_explicit(
    store: &Arc<dyn StateStore>,
    id: &ContainerId,
    instance: Option<StateRevision>,
    disposed: (bool, Vec<NonZeroU32>),
    code: u8,
    explicit_stop_pending: bool,
) -> u8 {
    let internal = exit_code_for(ErrorCode::Internal).get();
    let (ok, reaped) = disposed;
    if !(ok && mark_stopped(store, id, instance, &reaped)) {
        return internal;
    }
    if explicit_stop_pending && !persist_explicit_stop(store, id, instance) {
        return internal;
    }
    code
}

/// [`persist_explicit_stop`] の待ちの上限（REPAIR-5）。
const PERSIST_EXPLICIT_STOP_LIMIT: Duration = Duration::from_secs(10);

/// `Stopped` の記録へ「明示 stop 済み」を書き足す。cgroup の instance が start 時と一致し、`Stopped` で、
/// 他の監視者が居ない記録だけに書く（同じ ID の再作成・別処理の再起動を取り違えない。SEC-1）。別世代・別の監視者の
/// 記録、または start 時の instance が無く世代を識別できない場合も書かずに `true`（`mark_stopped` と同じ扱い）。`Stopped` でない・読み書きが続けて失敗したら `false`。
fn persist_explicit_stop(
    store: &Arc<dyn StateStore>,
    id: &ContainerId,
    instance: Option<StateRevision>,
) -> bool {
    let (store, id) = (Arc::clone(store), id.clone());
    run_bounded(
        "supervisor-persist-explicit-stop",
        PERSIST_EXPLICIT_STOP_LIMIT,
        move || {
            for attempt in 1..=MARK_STOPPED_ATTEMPTS {
                match try_persist_explicit_stop(store.as_ref(), &id, instance) {
                    Ok(()) => return true,
                    Err(code) => {
                        log_event("persist_explicit_stop_failed", Some(code));
                        if attempt < MARK_STOPPED_ATTEMPTS {
                            std::thread::sleep(MARK_STOPPED_RETRY_INTERVAL);
                        }
                    }
                }
            }
            false
        },
    )
}

/// [`persist_explicit_stop`] の 1 回の試行。
fn try_persist_explicit_stop(
    store: &dyn StateStore,
    id: &ContainerId,
    instance: Option<StateRevision>,
) -> Result<(), ErrorCode> {
    let record = store
        .get(&GetStateRequest::new(id.clone()))
        .map_err(|e| e.code())?;
    // 世代の識別子（start 時の instance）が無い場合は `None == None` で別世代と取り違えるため、内容の一致に
    // 頼らず書かずに中止する（fail-closed。SEC-1・契約 14。`write_explicit_stop` と同じ扱い）。
    let Some(instance) = instance else {
        log_event("persist_explicit_stop_skipped_no_instance", None);
        return Ok(());
    };
    let same_instance = record.cgroup().map(|c| c.instance()) == Some(instance);
    let foreign = record
        .supervision()
        .supervisor_pid()
        .is_some_and(|p| p.get() != std::process::id());
    if !same_instance || foreign {
        log_event("persist_explicit_stop_skipped", None);
        return Ok(());
    }
    if record.status().state() != ContainerState::Stopped {
        return Err(ErrorCode::FailedPrecondition);
    }
    let req = UpdateStateRequest::new(record.status().clone(), record.revision())
        .with_supervision(record.supervision())
        .with_explicit_stop(ExplicitStop::Recorded);
    store.update(&req).map(drop).map_err(|e| e.code())
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
        seccomp,
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
    // seccomp の listener を取り出して応答ハブへ渡す（応答者のいない USER_NOTIF は拒否対象の syscall を止めるため、
    // 受け取れない・スレッドを作れないときは起動したプロセスを回収して非 0 で終わる。fail-closed。SEC-4・#2025）。
    #[cfg(target_os = "linux")]
    if let Some(hub) = &seccomp
        && !hub.is_attached()
    {
        let attached = match process.take_seccomp_listener() {
            Some(listener) => hub.attach(listener),
            None => Err(TraitError::new(
                ErrorCode::Internal,
                "the seccomp listener was not delivered",
            )),
        };
        if let Err(e) = attached {
            log_event("seccomp_notify_failed", Some(e.code()));
            let disposed = dispose(Some(process), None, timeouts);
            return finish_disposed(
                &store,
                &id,
                instance,
                disposed,
                exit_code_for(e.code()).get(),
            );
        }
    }
    let code = supervise_running(
        store, id, process, relauncher, instance, restart, timeouts, stop,
    );
    // コンテナの回収の後に畳む（利用者が消えて listener が Closed になり、スレッドが終わる）。
    if let Some(hub) = seccomp {
        let _ = hub.finish(timeouts.terminate().min(crate::logs::MAX_DRAIN_TIMEOUT));
    }
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
        Ok(SuperviseOutcome::Stopped {
            process,
            late,
            explicit_stop_pending,
            ..
        }) => {
            let disposed = dispose(process, Some(&late), timeouts);
            finish_disposed_explicit(&store, &id, instance, disposed, 0, explicit_stop_pending)
        }
        Ok(SuperviseOutcome::RelaunchFailed {
            error,
            late,
            explicit_stop_pending,
            ..
        }) => {
            log_event("restart_failed", Some(error.code()));
            let disposed = dispose(None, Some(&late), timeouts);
            finish_disposed_explicit(
                &store,
                &id,
                instance,
                disposed,
                exit_code_for(error.code()).get(),
                explicit_stop_pending,
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
        Ok(SuperviseOutcome::ExplicitStopUnrecorded { error, .. }) => {
            // 再起動はしていない。明示 stop を state.json に残せなかったことを非 0 で知らせる（fail-closed。#2440・SUP-9）。
            log_event("explicit_stop_unrecorded", Some(error.code()));
            exit_code_for(error.code()).get()
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
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;

    use fandhe_container_core::audit_log::{
        AuditCoveragePolicy, AuditRecord, AuditSink, KernelAuditProbe, assess,
    };
    use fandhe_container_core::cgroups::{
        CgroupLimitPlan, ContainerCgroup, DelegatedCgroup, ResourceLimitPlan,
    };
    use fandhe_container_core::exec::IsolationPrivilege;
    use fandhe_container_core::landlock::detect_landlock_abi;
    use fandhe_container_core::oci_runtime::{
        LinuxResourceLimits, ProductionLauncher, ProductionLauncherBuilder, SubordinateIdSource,
        load_resource_limits, load_resource_limits_audited,
    };
    use fandhe_container_core::traits::ContainerLogPath;

    use super::*;
    use crate::container_options::ContainerOptions;
    use crate::id_model::{
        RootlessIdResolution, SYSTEM_PASSWD, SYSTEM_SUBGID, SYSTEM_SUBUID,
        resolve_rootless_id_source,
    };
    use crate::privilege::{MAX_STATUS_BYTES, parse_proc_status};
    use crate::start_contract::StartArgs;

    /// fd 0〜2 がすべて開いているか（SEC-1・SUP-14・SUP-1・#2132）。
    ///
    /// 閉じていると後続の open が fd 0〜2 に割り当たり、結果チャネルの乗っ取りやログの状態ファイルへの混入を招く。
    /// `is_open` は `crate::sys::fd_is_open` を渡す（試験では偽の述語）。特権ランチャーと同じ文言で拒否する。
    fn check_stdio_open(is_open: impl Fn(i32) -> bool) -> Result<(), TraitError> {
        if (0..3).all(is_open) {
            Ok(())
        } else {
            Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "stdin, stdout and stderr must be open",
            ))
        }
    }

    /// 結果チャネルの書き込みの期限（読み手が読まず pipe が満杯でも監視へ進むため。REPAIR-5）。
    const REPORT_WRITE_DEADLINE: Duration = Duration::from_secs(5);
    /// stderr への報告 1 行（結果チャネルが使えないとき）と、終了前のログの書き出しを待つ期限（REPAIR-5）。
    const STDERR_DEADLINE: Duration = Duration::from_secs(1);
    /// supervisor ログの準備（手順 2b）を待つ上限（全体期限から報告の予約分を引いた残りでさらに絞る）。
    const LOG_PREPARE_DEADLINE: Duration = Duration::from_secs(5);

    /// start の検証の拒否の記録先を包み、記録できなかったことを固定語彙の構造化ログへ残す（SEC-4・REPAIR-4・#2481）。
    ///
    /// 呼び出し元は core の `claim_start`（bind・sysfs・rootfs の固定の違反〔#2623〕の拒否。結果は `let _ =` で捨てられる）。運べない種類や helper の
    /// 失敗は内側が `Err` で返すので、ここで 1 行出してから同じ `Err` を返す（拒否の結果は変えない）。`log_event` は
    /// `stderr_sink` の常駐スレッドを作るが、拒否の記録は必ず start の失敗の直前で起き launch に進まないため、
    /// 「手順 8 の前の成功経路では `log_event` を呼ばない」規則に触れない。
    struct ObservedRejectionSink {
        inner: Arc<dyn AuditSink>,
    }

    impl ObservedRejectionSink {
        /// 失敗なら `log` へ固定のイベント名とコードを渡してから、同じ結果を返す（`log` は試験で差し替える）。
        fn observe(
            result: Result<(), TraitError>,
            log: impl FnOnce(&'static str, Option<ErrorCode>),
        ) -> Result<(), TraitError> {
            if let Err(e) = &result {
                log("rejection_audit_record_failed", Some(e.code()));
            }
            result
        }
    }

    impl AuditSink for ObservedRejectionSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            Self::observe(self.inner.record(record), log_event)
        }

        fn record_until(
            &self,
            record: &AuditRecord,
            deadline: std::time::Instant,
        ) -> Result<(), TraitError> {
            Self::observe(self.inner.record_until(record, deadline), log_event)
        }
    }

    /// 本番の [`StartDeps`]。core の本番 `ProcessLauncher`（`oci_runtime::ProductionLauncher`）へ結線する
    /// （#1819・SUP-1・CORE-1・CORE-2・CORE-3・CORE-5・SEC-1・SEC-4・SEC-5）。
    ///
    /// 呼び出し元は [`run_main`]（手順 4〜7 を作業スレッドで呼ぶ）。権限モデルは自プロセスの資格情報から決め、
    /// 手順 4 で権限モデルと Landlock ABI を副作用なしで確かめる。cgroup の参加フックと監査 sink は launcher の
    /// 構築器へ渡し、restart の再 launch も同じ launcher を使う（起動の経路を 2 つにしない。SUP-3）。
    pub struct ProductionStartDeps {
        root: PathBuf,
        /// 自プロセスの資格情報と subuid / subgid の設定から決めた権限モデル。決められなければ手順 4 がそのエラーで止める。
        privilege: Result<LaunchPrivilege, TraitError>,
        /// 資格情報の検証だけで決めた権限モデル（rootful の拒否のみ。subuid / subgid・passwd に依存しない）。
        /// 残存確認の launcher（`recover_interrupted`）はこちらだけを使う（CORE-2・CORE-6）。
        recovery_privilege: Result<IsolationPrivilege, TraitError>,
        cgroup: Option<HeldCgroup>,
        audit: Option<Arc<dyn AuditSink>>,
        /// launcher の回収点（`wait` / `terminate`。複数スレッドから呼ばれる）が出す補助の `exit_signal` 監査だけの記録先
        /// （`with_exit_audit_sink`。入口が単一スレッドの間に作った `ControlAuditRelay`。SEC-4・ESC-06・#2236）。
        /// 無ければ `audit`（`FileAuditSink`）を使う。
        exit_audit: Option<Arc<dyn AuditSink>>,
        /// start の検証（`claim_start` の bind・sysfs・rootfs の固定の違反の拒否）が出す mount 層の拒否だけの記録先
        /// （`with_rejection_audit_sink`。`ObservedRejectionSink` で包んだ `ControlAuditRelay`。SEC-4・#2481）。
        /// 無ければ `audit`（`FileAuditSink`）を使う。
        rejection_audit: Option<Arc<dyn AuditSink>>,
        /// 退避で一緒に移す同伴プロセスの PID（監査 helper。`DelegatedCgroup::with_companions`）。
        companions: Vec<u32>,
        /// seccomp の通知に応答するハブ（`with_seccomp_hub`。持つときだけ start の launcher が USER_NOTIF 版になる。#2025）。
        seccomp: Option<Arc<SeccompNotifyHub>>,
        /// 監査の網羅を満たせない環境への方針（`with_audit_policy`。既定 `BestEffort`。SEC-4・#2027）。
        audit_policy: AuditCoveragePolicy,
        /// 起動オプション（`with_container_options`。`--ipc`・`--shm-size`・`--tmpfs`・secrets / configs。SUP-12・#2625）。
        /// 既定（指定なし）は従来の動作と同じ。
        container_options: ContainerOptions,
        /// CRI ログの書き先（`with_cri_log_path`。`--cri-log-path`。CRI-2・SUP-4・#2671）。指定があれば `open_log_sink` が
        /// `@container-logs` に加えて CRI 形式でここへも追記する。
        cri_log_path: Option<ContainerLogPath>,
    }

    /// 決めた権限モデルと、範囲写像のときの入力元（#2243・CORE-6）。
    #[derive(Clone)]
    struct LaunchPrivilege {
        privilege: IsolationPrivilege,
        /// `RootlessSubordinateIds` のときだけ `Some`（core の launcher 構築が取り違えを拒否する）。
        subordinate: Option<SubordinateIdSource>,
    }

    /// 手順 5 で作った cgroup（`release_cgroup` と launcher の参加フックの源で共有する）。
    struct HeldCgroup {
        delegated: DelegatedCgroup,
        cgroup: Arc<ContainerCgroup>,
        /// 制限ファイルへ書いた `linux.resources`。launcher が fork の前に config の値との一致を確かめる
        /// （手順 5 と手順 8 の間の書き換え対策。#2019・CORE-3・SEC-1）。
        applied_resources: Option<LinuxResourceLimits>,
    }

    /// `/proc/self/status` の内容から launcher の権限モデルを決める（純関数。#1819・SEC-5・CORE-6）。
    ///
    /// real / effective / saved / fs のいずれかの uid が 0 なら rootful で、core の本番 launcher が
    /// `RootfulHostRoot` を `Unimplemented` で拒否するのと揃えて、同じコードで拒否する（コンテナ内 root を
    /// ホスト root に写す起動を作らない）。それ以外は `RootlessSingleId`（特権ランチャーの ambient capability 経由でも
    /// uid は非 root）。rootful を許すかは #2241 で判断待ち（`docs/design/rootful-host-root.md`）。読めない・壊れた入力は fail-closed に `FailedPrecondition`。
    ///
    /// ここでは rootful の拒否と 1 対 1 写像の既定だけを決める。範囲写像（`RootlessSubordinateIds`）への切り替えは
    /// `resolve_launch_privilege` が subuid / subgid の設定で行う（選択規則は `crate::id_model` の module doc。#2243）。
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

    /// `/proc/self/status` の内容と 3 つの設定ファイルから権限モデルを決める（#2243・CORE-6・SEC-5）。
    ///
    /// 手順: rootful を拒否（`privilege_for_status`）→ `passwd` から実効 uid の名前を得る（無ければ `getent`）→ subuid / subgid を
    /// 分類 → `select_rootless_id_model`。名前は passwd、無ければ NSS(`getent`。#2390)。範囲写像のときは probe したのと同じ subuid / subgid を読む `SubordinateIdSource` を添える（`resolve_rootless_id_source`。pull の展開と共有。#2389）（helper の有無は
    /// ここでは見ず、core の launcher 構築が検証する。縮退しない）。構造化ログは出さない（手順 8 より前に常駐スレッドを
    /// 作らない制約のため。選んだモデルは子の `uid_map` のほか、launch が残す `state.json` の `launchIsolation.id_mapping` と `inspect` の `idMapping` で確かめられる。#2388）。
    fn resolve_launch_privilege(
        status_text: &str,
        passwd: &Path,
        subuid: &Path,
        subgid: &Path,
    ) -> Result<LaunchPrivilege, TraitError> {
        let single = privilege_for_status(status_text)?;
        let snapshot = parse_proc_status(status_text)
            .map_err(|e| TraitError::new(e.code, "failed to read the process credentials"))?;
        let (real, effective) = (snapshot.uid.real, snapshot.uid.effective);
        match resolve_rootless_id_source(real, effective, passwd, subuid, subgid)? {
            RootlessIdResolution::SingleId => Ok(LaunchPrivilege {
                privilege: single,
                subordinate: None,
            }),
            RootlessIdResolution::SubordinateIds(source) => Ok(LaunchPrivilege {
                privilege: IsolationPrivilege::RootlessSubordinateIds,
                subordinate: Some(source),
            }),
        }
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
            let status = read_self_status();
            let recovery_privilege = status.clone().and_then(|text| privilege_for_status(&text));
            let privilege = status.and_then(|text| {
                resolve_launch_privilege(
                    &text,
                    Path::new(SYSTEM_PASSWD),
                    Path::new(SYSTEM_SUBUID),
                    Path::new(SYSTEM_SUBGID),
                )
            });
            Self {
                root,
                privilege,
                recovery_privilege,
                cgroup: None,
                audit: None,
                exit_audit: None,
                rejection_audit: None,
                companions: Vec::new(),
                seccomp: None,
                audit_policy: AuditCoveragePolicy::default(),
                container_options: ContainerOptions::default(),
                cri_log_path: None,
            }
        }

        /// CRI ログの書き先（`--cri-log-path`）を設定する（CRI-2・SUP-4・#2671）。
        ///
        /// `open_log_sink` が手順 6 で開く。特権ランチャー経由（effective / permitted の capability あり）では
        /// `Unimplemented` で拒否する（`CAP_DAC_OVERRIDE` で任意のパスへ追記できてしまうため。
        /// [`crate::logs::cri::deny_elevated_capabilities`]）。
        #[must_use]
        pub fn with_cri_log_path(mut self, path: Option<ContainerLogPath>) -> Self {
            self.cri_log_path = path;
            self
        }

        /// 起動オプション（`--ipc`・`--shm-size`・`--tmpfs`・secrets / configs）を設定する（SUP-12・CORE-5・#2625）。
        ///
        /// 手順 4 が矛盾（`--ipc=host` と `--shm-size` 等。ファイルは読まない）を cgroup の連鎖より前に拒否し、手順 7 の
        /// `build_launcher` が [`ContainerOptions::launch_options`] を本番 launcher へ渡す。restart の再 launch も同じ
        /// launcher を使うので同じ指定が効く。ホストの secrets のファイルは手順 7 で一度だけ読み、launcher が保持する
        /// （supervisor は non-dumpable。範囲写像の経路で holder が継承するメモリの露出は未解決で #2628）。
        /// CLI からの受け渡しは未実装（`run_main` は既定のまま。REPAIR-3）。
        #[must_use]
        pub fn with_container_options(mut self, options: ContainerOptions) -> Self {
            self.container_options = options;
            self
        }

        /// 監査の網羅を満たせない環境への方針を設定する（`--audit-policy`。start と restart の再 launch が同じ launcher を
        /// 使うので同じ方針が効く。SEC-4・#2027）。
        #[must_use]
        pub fn with_audit_policy(mut self, policy: AuditCoveragePolicy) -> Self {
            self.audit_policy = policy;
            self
        }

        /// 回収点の `exit_signal` 監査（SIGSYS 終了の補助記録。#2004）の記録先を設定する（SEC-4・ESC-06・#2236）。
        ///
        /// 回収点は監視スレッドなど複数スレッドから呼ばれ、`FileAuditSink` の fork 隔離が使えない（rootless では代替経路も
        /// 失敗する）。入口が単一スレッドの間に作った `ControlAuditRelay` を渡す。launch の時点の記録（監査網羅の縮退・
        /// pre-pivot の違反）は単一スレッドなので `build_audit_sink` の `FileAuditSink` のままにする（relay は閉じた表の理由つきの
        /// `Mount` 以外の理由つきの層を運べない）。start の検証（bind・sysfs）の拒否は作業スレッドで出るため
        /// [`Self::with_rejection_audit_sink`] で別に渡す。
        #[must_use]
        pub fn with_exit_audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
            self.exit_audit = Some(sink);
            self
        }

        /// start の検証（`claim_start` の bind mount の元・sysfs）の拒否の記録先を設定する（SEC-4・#2481）。
        ///
        /// この検証は作業スレッド `supervisor-start` で走り、入口スレッドが待つ間のため複数スレッドになる。
        /// `FileAuditSink` は主経路を試せず、rootless では代替経路（`CAP_AUDIT_WRITE` 要）も失敗して拒否が残らない。
        /// 入口が単一スレッドの間に作った `ControlAuditRelay`（理由なしの `Mount` を運べる）を渡す。記録の失敗は
        /// 固定語彙の構造化ログへ残す（`ObservedRejectionSink`）。回復用の launcher（launch も検証もしない）には渡さない。
        #[must_use]
        pub fn with_rejection_audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
            self.rejection_audit = Some(Arc::new(ObservedRejectionSink { inner: sink }));
            self
        }

        /// seccomp の通知に応答するハブを持たせる。持たせると start の launcher が ERRNO 側を `UserNotif` にし、
        /// 入口が listener をハブへ渡す（SEC-4・REPAIR-5・#2025）。持たせなければ従来の ERRNO 版のまま。
        #[must_use]
        pub fn with_seccomp_hub(mut self, hub: Arc<SeccompNotifyHub>) -> Self {
            self.seccomp = Some(hub);
            self
        }

        /// 決めた権限モデル（範囲写像なら入力元つき）を設定した launcher 構築器（構築の箇所をここ 1 つにする。
        /// start と restart の再 launch が同じ設定を使う。SUP-3・CORE-6）。
        ///
        /// `with_mapping` が偽のときは範囲写像の入力元（subuid / subgid・helper）を渡さず、権限モデルも
        /// `RootlessSingleId` にする。残存確認だけの launcher（`recover_interrupted`）は namespace も写像も作らず、
        /// helper（`newuidmap` / `newgidmap`）の検証に依存させない（前の supervisor の死後に uidmap が壊れても、
        /// 記録済みの cgroup 経由の後始末が止まらないように。CORE-2・CORE-6）。
        fn launcher_builder(
            &self,
            with_mapping: bool,
        ) -> Result<ProductionLauncherBuilder, TraitError> {
            // 範囲写像なしのときは資格情報の検証だけで決める。subuid / subgid・passwd の検証結果
            // （`self.privilege`）には依存しない。
            let (privilege, subordinate) = if with_mapping {
                let decided = self.privilege.clone()?;
                (decided.privilege, decided.subordinate)
            } else {
                (self.recovery_privilege.clone()?, None)
            };
            let builder = ProductionLauncher::builder()
                .privilege(privilege)
                .audit_coverage_policy(self.audit_policy);
            // 応答者（ハブ）がいるときの start の launcher だけが USER_NOTIF にする。残存確認の launcher は launch しない
            // が、同じく応答者がいない構成は ERRNO のまま（応答者のいない USER_NOTIF は拒否対象の syscall を止める）。
            let builder = if with_mapping && self.seccomp.is_some() {
                builder.seccomp_errno_delivery(
                    fandhe_container_core::seccomp::ErrnoDelivery::UserNotif,
                )
            } else {
                builder
            };
            Ok(match subordinate {
                Some(source) => builder.subordinate_ids(source),
                None => builder,
            })
        }

        /// cgroup の退避で自プロセスと一緒に移す同伴プロセス（入口が fork した監査 helper）の PID を宣言する。
        #[must_use]
        pub fn with_companions(mut self, pids: Vec<u32>) -> Self {
            self.companions = pids;
            self
        }
    }

    impl StartDeps for ProductionStartDeps {
        fn seccomp_hub(&self) -> Option<Arc<SeccompNotifyHub>> {
            self.seccomp.clone()
        }

        /// 権限モデルが決められること、Landlock ABI が 6 以上であることを確かめる（副作用なし）。launcher は同じ条件を
        /// fork の前に拒否するが、cgroup の連鎖（取り消せないスコープの追記）の前に止めるためここで前倒しする（CORE-5）。
        /// `ProductionLauncherBuilder::build` は child subreaper 化の副作用を持つため、ここでは呼ばない。
        fn check_launcher_available(&self) -> Result<(), TraitError> {
            self.privilege.clone()?;
            // 起動オプションの矛盾は cgroup の連鎖の前に拒否する（ファイルは読まない純粋な検証。手順 7 が変換の本体）。
            self.container_options.implicit_dev_mounts()?;
            // 確実な層（seccomp の ERRNO 側の USER_NOTIF）の応答者が無い構成は起動しない（fail-closed。SEC-4・#2027）。
            if self.seccomp.is_none() {
                return Err(seccomp_audit_unavailable());
            }
            let support = detect_landlock_abi().map_err(|e| {
                TraitError::new(
                    e.code,
                    "Landlock ABI 6 or newer is required to start a container",
                )
            })?;
            // 厳格モードの縮退は cgroup の連鎖（取り消せないスコープの追記）の前に拒否する。launcher も fork の前に同じ判定を
            // 持つ（観測の時点がずれる場合の多重防御。SEC-4・#2027）。
            precheck_audit_coverage(
                &KernelAuditProbe::read_host(),
                support.audit_mode().into(),
                self.audit_policy,
            )
        }

        fn prepare_cgroup(
            &mut self,
            store: &dyn StateStore,
            observed: &StateRecord,
        ) -> Result<Option<StateRevision>, TraitError> {
            let privilege = self.privilege.clone()?.privilege;
            let to_trait = |e: fandhe_container_core::cgroups::CgroupError| {
                TraitError::new(e.code, "failed to prepare the container cgroup")
            };
            let delegated = DelegatedCgroup::detect()
                .map_err(to_trait)?
                .with_companions(&self.companions);
            // 手順 5 の時点の config から `linux.resources` を読み、cgroup v2 の型の計画にする（#2019）。
            // 範囲外の値は create でも拒否済みだが、書き換えに備えここでも同じ変換で検証する。mkdir の前に
            // 失敗させるので後始末は要らない。
            // destination の拒否（create 後の書き換え = TOCTOU）は、本番で最初に拒否される点なので監査へ記録する
            // （#2594・SEC-4・OCI-4）。
            let resources = resource_limits_for_start(
                observed.bundle(),
                observed.status().id(),
                self.rejection_audit.as_ref(),
            )?;
            let mut plan = CgroupLimitPlan::for_privilege(privilege);
            if let Some(limits) = &resources {
                let resource_plan = ResourceLimitPlan::try_from(limits).map_err(|e| {
                    TraitError::new(
                        e.code,
                        "linux.resources has a value outside the cgroup v2 range",
                    )
                })?;
                plan = plan.with_resources(resource_plan);
            }
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
                applied_resources: resources,
            });
            Ok(instance)
        }

        fn build_audit_sink(&mut self) -> Result<(), TraitError> {
            let sink = crate::exec::default_audit_sink(Some(self.root.clone()))?;
            self.audit = Some(Arc::new(sink));
            Ok(())
        }

        /// `--root` 配下の `@container-logs/`（0700。[`crate::logs::container_log_dir`]）に `<id>.log`（既定 1MiB × 3 世代）を
        /// 置く。`logs` コマンド（CLI）が同じ定義で読む（#1543・SUP-7）。
        fn open_log_sink(
            &mut self,
            id: &ContainerId,
        ) -> Result<Option<Arc<dyn LogSink>>, TraitError> {
            use std::os::unix::fs::DirBuilderExt as _;
            let dir = crate::logs::container_log_dir(&self.root);
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
            let config = crate::logs::container_log_rotation_config();
            let sink = crate::logs::RotatingFileSink::open(&dir, id, config)?;
            let Some(cri_path) = &self.cri_log_path else {
                return Ok(Some(Arc::new(sink)));
            };
            // 権限の確認は CRI ログを開く直前に行う（ambient capability つきで利用者指定のパスを開かない。fail-closed）。
            crate::logs::cri::deny_elevated_capabilities(&read_self_status()?)?;
            let cri_sink = crate::logs::cri::CriFileSink::open(cri_path)?;
            Ok(Some(Arc::new(crate::logs::cri::TeeLogSink::new(
                Arc::new(sink),
                Arc::new(cri_sink),
            ))))
        }

        /// 権限モデル・監査 sink・cgroup の参加フックの源を渡して `ProductionLauncher` を作る
        /// （core の launcher が必須値の欠落を `InvalidArgument` で拒否する）。呼び出しプロセスは child subreaper に
        /// なる。launch の単一スレッド要求は入口が満たす（モジュール doc「手順 8 を入口スレッドで行う理由」）。
        fn build_launcher(&mut self) -> Result<Arc<dyn ProcessLauncher>, TraitError> {
            let (Some(held), Some(audit)) = (self.cgroup.as_ref(), self.audit.as_ref()) else {
                return Err(TraitError::new(
                    ErrorCode::Internal,
                    "the launcher was built before its prerequisites",
                ));
            };
            let source = Arc::clone(&held.cgroup);
            let builder = self.launcher_builder(true)?.audit_sink(Arc::clone(audit));
            let builder = match &self.exit_audit {
                Some(sink) => builder.exit_audit_sink(Arc::clone(sink)),
                None => builder,
            };
            let builder = match &self.rejection_audit {
                Some(sink) => builder.rejection_audit_sink(Arc::clone(sink)),
                None => builder,
            };
            // 起動オプションの変換（secrets のファイル読み取りを含む）は fork 前の単一スレッドのこの手順で行う。失敗は
            // 手順 5〜7 の他の失敗と同じ経路で後始末される（SUP-12・#2625）。
            let launch_options = self.container_options.launch_options()?;
            let launcher = builder
                .launch_options(launch_options)
                .cgroup_join_source(move || source.join_hook())
                .applied_resource_limits(held.applied_resources.clone())
                .build()?;
            Ok(Arc::new(launcher))
        }

        /// 参加フックの源を持たない `ProductionLauncher` で `recover_interrupted_start` を呼ぶ(launch はしないので
        /// 参加フックは要らず、`prepare_cgroup` も通さない。記録済みの配置で残存を確かめる)。構築は child subreaper
        /// 化の副作用を持つが、この経路は直後に fail-closed で終わる。
        fn recover_interrupted(
            &mut self,
            store: &dyn StateStore,
            id: &ContainerId,
            timeouts: &StartTimeouts,
        ) -> Result<(), TraitError> {
            let audit = crate::exec::default_audit_sink(Some(self.root.clone()))?;
            let launcher: Arc<dyn ProcessLauncher> = Arc::new(
                self.launcher_builder(false)?
                    .audit_sink(Arc::new(audit))
                    .build()?,
            );
            recover_interrupted_start(store, &launcher, id, timeouts).map(drop)
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

    /// 確実な層の記録先を作れないときの拒否（固定文言。元のエラーの詳細は載せない。SEC-4・#2027）。
    fn seccomp_audit_unavailable() -> TraitError {
        TraitError::new(
            ErrorCode::FailedPrecondition,
            "the seccomp audit record path is unavailable",
        )
    }

    /// 確実な層（seccomp の ERRNO 側 40 件を USER_NOTIF で記録する経路）の記録先が作れたかを判定する（純関数）。
    /// 作れなければ `FailedPrecondition` で起動を拒否する（fail-closed。記録先なしで続行しない。SEC-4・#2027）。
    pub(crate) fn require_seccomp_audit_sink(
        sink: Result<Arc<dyn AuditSink>, ErrorCode>,
    ) -> Result<Arc<dyn AuditSink>, TraitError> {
        sink.map_err(|_| seccomp_audit_unavailable())
    }

    /// 手順 4 の前倒し判定（純関数）。カーネル監査頼みの層が縮退していて、方針が厳格なら拒否する（SEC-4・#2027）。
    pub(crate) fn precheck_audit_coverage(
        probe: &KernelAuditProbe,
        landlock: fandhe_container_core::launch_isolation::RecordedLandlockAudit,
        policy: AuditCoveragePolicy,
    ) -> Result<(), TraitError> {
        assess(probe, landlock).enforce(policy)
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
        // 0a の続き: fd 0〜2 が閉じていれば結果チャネルを信用できないため、使わず stderr（開いていれば）の JSON だけで終わる
        // （SEC-1・SUP-14・#2132）。Rust std は Linux で `main` の前に閉じた fd 0〜2 を `/dev/null` で埋めるので、実 bin では
        // 通常ここへ届かない（std の初期化を通らない入口からの呼び出しへの backstop）。埋められた fd 1 は
        // `open_result_channel` の FIFO 検査が拒否する。
        if let Err(e) = check_stdio_open(crate::sys::fd_is_open) {
            let err = op_err(e);
            let mut line = Vec::new();
            if err.write_json_line(&mut line).is_ok() {
                let _ = crate::stderr_sink::stderr().emit_and_wait(line, STDERR_DEADLINE);
            }
            return ExitCode::from(err.exit_code().get());
        }
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
        // 結果の期限の起点は記録経路の確認(`probe`)の前に置く。`probe` は最大 `AUDIT_PROBE_ALLOWANCE` ほど待ち得るが、
        // その分は `result_deadline` に見込み済みで、CLI の受信期限(同じ起点 + 猶予)にも含まれる(SEC-4・REPAIR-5・#2027)。
        let deadline =
            Instant::now().checked_add(crate::start_contract::result_deadline(&timeouts));
        out.limit_until(deadline);
        // 制御チャネルの認証境界の拒否の記録先（SEC-4）。制御チャネルのサーバスレッドは監視スレッドと並行して動くため、
        // 複数スレッドでは `FileAuditSink` の隔離（fork）が使えない。そこで監査専用の helper プロセスを fork し、以後の
        // 記録はそこへ渡して期限付きで永続化する（`ControlAuditRelay`）。`spawn` は単一スレッドのときだけ成功するので、
        // `run_start_until` が `stderr_sink` の常駐スレッドを作る前のここで作る（launch の単一スレッド要求にも触れない。
        // helper は fork 子で親にスレッドを増やさない）。失敗の記録は常駐スレッドを作れる launch の後まで保留する。
        let relay = crate::exec::default_audit_sink(Some(args.root.clone()))
            .and_then(fandhe_container_core::audit_log::ControlAuditRelay::spawn)
            // sink と helper を作れただけでは記録できるとは限らない（`@audit.log` がディレクトリ等だと記録時に初めて失敗する）。
            // 起動前に helper へ保存先を開かせ、期限つきで確かめる。開けなければ記録経路なしとして起動を拒否する（SEC-4・#2027）。
            .and_then(|relay| relay.probe().map(|()| relay))
            .map_err(|e| e.code());
        // helper は fork 時点で委譲 cgroup に属するため、cgroup の準備（自プロセスの退避）へ同伴プロセスとして宣言し、
        // 一緒に退避リーフへ移す（宣言しないと「他のプロセスがいる」として起動が拒否される。CORE-3・SUP-1）。
        let companions: Vec<u32> = relay.as_ref().map(|r| vec![r.pid()]).unwrap_or_default();
        // 以後の記録の通り道（relay）を共有できる形にする。記録先を作れなかった（確認用の記録も通らなかった）場合も
        // ここでは返さない: 手順 3 の中断起動の回復(`recover_interrupted`。CORE-2)を先に通すため、ハブなしの deps で
        // 進める。ハブが無いと手順 4 の `check_launcher_available` が確実な層を満たせないとして拒否するので、cgroup にも
        // launch にも触れる前に止まる(fail-closed。新規の launch は監査経路が必須のまま。SEC-4・#2027)。
        let audit: Option<Arc<dyn fandhe_container_core::audit_log::AuditSink>> =
            require_seccomp_audit_sink(relay.map(|relay| {
                Arc::new(relay) as Arc<dyn fandhe_container_core::audit_log::AuditSink>
            }))
            .ok();
        // seccomp の通知への応答ハブ（SEC-4・REPAIR-5・#2025）。スレッドは attach まで作らないので、launch の単一スレッド要求に
        // 触れない。
        let deps = ProductionStartDeps::new(args.root.clone())
            .with_companions(companions)
            .with_audit_policy(args.audit_policy)
            .with_cri_log_path(args.cri_log_path.clone());
        let deps = Box::new(match &audit {
            // relay は launcher の回収点（複数スレッド）の `exit_signal` 監査の記録先にも渡す（#2236）。
            // start の検証（bind・sysfs）の拒否も作業スレッド（複数スレッド）で出るため relay へ渡す（#2481）。
            Some(audit) => deps
                .with_exit_audit_sink(Arc::clone(audit))
                .with_rejection_audit_sink(Arc::clone(audit))
                .with_seccomp_hub(Arc::new(SeccompNotifyHub::new(
                    Arc::clone(audit),
                    args.id.clone(),
                    crate::seccomp_notify::NotifyConfig::default(),
                ))),
            None => deps,
        });
        // 2b: supervisor の構造化ログの保存先を開き、stderr の出口の書き先を差し替える（#2067・REPAIR-4）。
        // 期限つきの作業スレッドで行い、終了を確認してから先へ進む。開けなければ fail-closed で、手順 3 より前に止まる。
        if let Err(e) = prepare_supervisor_log(&store, &args.root, &args.id, deadline) {
            return fail(&mut out, op_err(e));
        }
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
        // 制御チャネル（CLI からのシグナル送信を受ける UDS。SUP-1・SEC-1・#2058）。launch（手順 8。単一スレッド要求）と
        // 報告の後に作るのでスレッドの制約に触れない。作成に失敗したら install が停止を要求し、既存の停止経路が
        // コンテナを終了させて Stopped を記録する（停止できないコンテナを残さない）。
        let stop = StopToken::new();
        // 記録先が無い構成は手順 4 で拒否済み(起動していない)ので、ここへ届くときは `Some`。
        let (running, control) =
            crate::control::install(&args.root, &args.id, running, &stop, audit);
        let code = run_supervised(store, args.id, running, args.restart, &timeouts, &stop);
        // 制御チャネルの作成に失敗していたら、回収に成功しても非 0 で終える（SUP-1）。
        let code = control.exit_code(code);
        // サーバスレッドを止めてからソケットを消す（RAII）。
        drop(control);
        ExitCode::from(code)
    }

    /// 手順 5 で `config.json` を読み直し、`linux.resources` を取り出す（#2019）。`rejection_audit` があれば
    /// `mounts[].destination` の拒否を mount 層の監査へ記録する（#2594・SEC-4・OCI-4）。
    ///
    /// 本番では `check_launcher_available`（手順 4）が relay の無い構成を先に拒否するため `None` には到達しないが、
    /// `None` のときも従来どおり同じ検証をする。返すエラーは記録の有無・成否で変わらない（fail-closed）。
    /// 手順 8 の `build_spec` も同じ記録先を使うが、手順 5 で拒否されれば手順 8 には進まないので 1 回の start で高々 1 件。
    fn resource_limits_for_start(
        bundle: &std::path::Path,
        id: &fandhe_container_core::traits::ContainerId,
        rejection_audit: Option<&Arc<dyn AuditSink>>,
    ) -> Result<Option<LinuxResourceLimits>, TraitError> {
        match rejection_audit {
            Some(sink) => load_resource_limits_audited(bundle, id, sink.as_ref()),
            None => load_resource_limits(bundle),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// 一時ディレクトリに passwd / subuid / subgid を置き、`resolve_launch_privilege` を呼ぶ。
        fn resolve_with(
            tag: &str,
            passwd: Option<&str>,
            subuid: Option<&str>,
            subgid: Option<&str>,
            uids: &str,
        ) -> Result<LaunchPrivilege, TraitError> {
            let dir = std::env::temp_dir().join(format!("fc-idm-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let put = |name: &str, body: Option<&str>| {
                let p = dir.join(name);
                if let Some(b) = body {
                    std::fs::write(&p, b).unwrap();
                }
                p
            };
            let (pw, su, sg) = (
                put("passwd", passwd),
                put("subuid", subuid),
                put("subgid", subgid),
            );
            let r =
                resolve_launch_privilege(&status(uids, "1000\t1000\t1000\t1000"), &pw, &su, &sg);
            let _ = std::fs::remove_dir_all(&dir);
            r
        }

        const ALICE: &str = "alice:x:1000:1000::/home/alice:/bin/sh\n";
        const UIDS: &str = "1000\t1000\t1000\t1000";

        /// CORE-6・SEC-5・#2243: 名前で書かれた両ファイルの行があれば範囲写像（入力元つき）。
        #[test]
        fn core6_subordinate_selected_by_name_rows() {
            let r = resolve_with(
                "sub",
                Some(ALICE),
                Some("alice:100000:65536\n"),
                Some("alice:100000:65536\n"),
                UIDS,
            )
            .unwrap();
            assert_eq!(r.privilege, IsolationPrivilege::RootlessSubordinateIds);
            assert!(r.subordinate.is_some());
        }

        /// CORE-6: passwd が無くても数値 uid の行なら範囲写像になる。
        #[test]
        fn core6_subordinate_selected_by_numeric_rows_without_passwd() {
            let r = resolve_with(
                "num",
                None,
                Some("1000:100000:65536\n"),
                Some("1000:100000:65536\n"),
                UIDS,
            )
            .unwrap();
            assert_eq!(r.privilege, IsolationPrivilege::RootlessSubordinateIds);
        }

        /// CORE-6: 設定の無いホストは従来どおり 1 対 1（入力元なし）。
        #[test]
        fn core6_single_when_no_configuration() {
            for subuid in [None, Some("bob:100000:65536\n")] {
                let r = resolve_with("single", Some(ALICE), subuid, None, UIDS).unwrap();
                assert_eq!(r.privilege, IsolationPrivilege::RootlessSingleId);
                assert!(r.subordinate.is_none());
            }
        }

        /// SEC-5: 片側だけ・解析不正・名前の規則違反は fail-closed（Single へ縮退しない）。
        #[test]
        fn sec5_partial_malformed_and_bad_name_are_rejected() {
            let e = resolve_with(
                "part",
                Some(ALICE),
                Some("alice:100000:65536\n"),
                None,
                UIDS,
            )
            .err()
            .unwrap();
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(e.message(), "subordinate id configuration is incomplete");
            let e = resolve_with("bad", Some(ALICE), Some("alice:x:y\n"), None, UIDS)
                .err()
                .unwrap();
            assert_eq!(e.message(), "subordinate id configuration is unreadable");
            let e = resolve_with(
                "name",
                Some("a b:x:1000:1000::/h:/bin/sh\n"),
                None,
                None,
                UIDS,
            )
            .err()
            .unwrap();
            assert_eq!(
                e.message(),
                "the owner name is not usable for subordinate ids"
            );
        }

        struct OkSink;
        impl AuditSink for OkSink {
            fn record(
                &self,
                _: &fandhe_container_core::audit_log::AuditRecord,
            ) -> Result<(), TraitError> {
                Ok(())
            }
        }

        /// 記録を溜める試験用 sink。
        struct CollectSink(Mutex<Vec<AuditRecord>>);
        impl AuditSink for CollectSink {
            fn record(&self, r: &AuditRecord) -> Result<(), TraitError> {
                self.0.lock().unwrap().push(r.clone());
                Ok(())
            }
        }

        /// SEC-4・OCI-4（#2594）: 手順 5 の読み直しで destination（遡り・`/`・相対 `..`）が拒否されたら、
        /// mount 層・`path` なし・コンテナ ID つきで 1 件記録する。sink が無くても code・message は同じ。
        #[test]
        fn sec4_2594_step5_destination_rejection_is_audited() {
            use fandhe_container_core::audit_log::AuditEvent;
            use fandhe_container_core::traits::ContainerId;
            for (i, dest) in ["/../..", "/", "run/../../.."].into_iter().enumerate() {
                let dir = std::env::temp_dir().join(format!("fc-2594-{}-{i}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(dir.join("rootfs")).unwrap();
                let cfg = format!(
                    r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs"}},"process":{{"user":{{"uid":0,"gid":0}},"args":["/bin/true"],"cwd":"/"}},"mounts":[{{"destination":"{dest}","type":"bind","source":"/srv/x","options":["bind","rw"]}}]}}"#
                );
                std::fs::write(dir.join("config.json"), cfg).unwrap();
                let id = ContainerId::new("c2594").unwrap();
                let sink = Arc::new(CollectSink(Mutex::new(Vec::new())));
                let dynsink: Arc<dyn AuditSink> = sink.clone();
                let err = resource_limits_for_start(&dir, &id, Some(&dynsink)).unwrap_err();
                let plain = resource_limits_for_start(&dir, &id, None).unwrap_err();
                let _ = std::fs::remove_dir_all(&dir);
                assert_eq!(err.code(), ErrorCode::InvalidArgument, "{dest}");
                assert_eq!(err.code(), plain.code());
                assert_eq!(err.message(), plain.message());
                let recs = sink.0.lock().unwrap();
                assert_eq!(recs.len(), 1, "{dest}");
                assert_eq!(recs[0].container_id(), Some(&id));
                assert!(matches!(
                    recs[0].event(),
                    AuditEvent::Mount {
                        path: None,
                        reason: None
                    }
                ));
            }
        }

        /// SEC-4・#2594: 本番の `prepare_cgroup` は手順 5 の読み直しを `rejection_audit` つきで呼ぶ。実際の
        /// `prepare_cgroup` は委譲 cgroup が要り CI で回せないため、結線はソースで固定する。
        #[test]
        fn sec4_2594_prepare_cgroup_passes_rejection_audit_to_the_reload() {
            let src = include_str!("start_entry.rs");
            let production = src.split("#[cfg(test)]").next().unwrap_or(src);
            let prepare = production
                .find("fn prepare_cgroup(")
                .expect("prepare_cgroup");
            let call = production[prepare..]
                .find("resource_limits_for_start(")
                .map(|p| p + prepare)
                .expect("prepare_cgroup reloads the limits through the audited helper");
            assert!(production[call..].contains("self.rejection_audit.as_ref()"));
            assert!(!production[prepare..].contains("load_resource_limits(observed"));
        }

        /// SEC-4・#2027: 確実な層の記録先を作れなければ `FailedPrecondition` の固定文言で起動を拒否し、作れていれば
        /// 同じ sink をそのまま返す。
        #[test]
        fn sec4_2027_seccomp_audit_sink_unavailable_refuses_start() {
            let err = require_seccomp_audit_sink(Err(ErrorCode::PermissionDenied))
                .err()
                .expect("refused");
            assert_eq!(err.code(), ErrorCode::FailedPrecondition);
            assert_eq!(
                err.message(),
                "the seccomp audit record path is unavailable"
            );
            let sink: Arc<dyn AuditSink> = Arc::new(OkSink);
            let got = require_seccomp_audit_sink(Ok(Arc::clone(&sink))).expect("kept");
            assert!(Arc::ptr_eq(&sink, &got));
        }

        /// SEC-4・#2027: 応答者（ハブ）の無い本番の deps は手順 4 で拒否する（確実な層を満たせない構成は起動しない）。
        #[test]
        fn sec4_2027_deps_without_seccomp_hub_refuse_at_step_4() {
            let mut deps = ProductionStartDeps::new(std::env::temp_dir());
            deps.privilege = Ok(LaunchPrivilege {
                privilege: IsolationPrivilege::RootlessSingleId,
                subordinate: None,
            });
            let err = deps.check_launcher_available().unwrap_err();
            assert_eq!(err.code(), ErrorCode::FailedPrecondition);
            assert_eq!(
                err.message(),
                "the seccomp audit record path is unavailable"
            );
        }

        /// SEC-4・#2027: 前倒し判定。縮退（`kill_process` が記録されない・Landlock ABI 6）は厳格モードだけが拒否し、
        /// 既定では通す。全項目が揃っていれば厳格モードでも通る。
        #[test]
        fn sec4_2027_precheck_audit_coverage_by_policy() {
            use fandhe_container_core::launch_isolation::RecordedLandlockAudit;
            let mut degraded = KernelAuditProbe::all_clear();
            degraded.actions_logged = Some("kill_thread trap errno".to_owned());
            let abi6 = RecordedLandlockAudit::Unavailable { detected_abi: 6 };
            let abi7 = RecordedLandlockAudit::KernelAuditRequested;
            assert!(
                precheck_audit_coverage(&degraded, abi6, AuditCoveragePolicy::BestEffort).is_ok()
            );
            let err =
                precheck_audit_coverage(&degraded, abi6, AuditCoveragePolicy::Strict).unwrap_err();
            assert_eq!(err.code(), ErrorCode::FailedPrecondition);
            assert_eq!(
                err.message(),
                "audit coverage is degraded and the strict audit policy refuses to start"
            );
            assert!(
                precheck_audit_coverage(
                    &KernelAuditProbe::all_clear(),
                    abi7,
                    AuditCoveragePolicy::Strict
                )
                .is_ok()
            );
        }

        /// SEC-5: rootful は従来どおり UNIMPLEMENTED（設定ファイルに依らない）。
        #[test]
        fn sec5_rootful_still_rejected_before_any_file_is_read() {
            let e = resolve_with("root", Some(ALICE), None, None, "0\t0\t0\t0")
                .err()
                .unwrap();
            assert_eq!(e.code(), ErrorCode::Unimplemented);
        }

        /// REPAIR-1・SUP-3: launcher の構築器は 1 か所（start と restart の再 launch が同じ設定を使う）。
        #[test]
        fn launcher_builder_is_constructed_in_one_place() {
            let src = include_str!("start_entry.rs");
            let production = src.split("#[cfg(test)]").next().unwrap_or(src);
            assert_eq!(
                production.matches("ProductionLauncher::builder()").count(),
                1
            );
        }

        /// CORE-2・CORE-6: 中断した start の回復用 launcher は、helper が無くても構築できる（写像の検証に依存しない）。
        /// 新規 start 用は helper の検証で拒否される。
        #[test]
        fn recovery_launcher_does_not_validate_mapping_helpers() {
            struct NullSink;
            impl AuditSink for NullSink {
                fn record(
                    &self,
                    _: &fandhe_container_core::audit_log::AuditRecord,
                ) -> Result<(), TraitError> {
                    Ok(())
                }
            }
            let dir = std::env::temp_dir().join(format!("fc-rec-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let missing = dir.join("absent");
            let source = SubordinateIdSource::with_paths(
                Some("alice".to_owned()),
                &missing,
                &missing,
                &missing,
                &missing,
                Duration::from_secs(5),
            )
            .unwrap();
            let mut deps = ProductionStartDeps::new(dir.clone());
            deps.privilege = Ok(LaunchPrivilege {
                privilege: IsolationPrivilege::RootlessSubordinateIds,
                subordinate: Some(source),
            });
            deps.recovery_privilege = Ok(IsolationPrivilege::RootlessSingleId);
            let sink: Arc<dyn AuditSink> = Arc::new(NullSink);
            let strict = deps
                .launcher_builder(true)
                .unwrap()
                .audit_sink(Arc::clone(&sink))
                .build();
            assert!(strict.is_err());
            let recovery = deps
                .launcher_builder(false)
                .unwrap()
                .audit_sink(sink)
                .build();
            assert!(recovery.is_ok());
            // subuid / subgid の設定が壊れて `privilege` が Err でも、回復用の構築器は作れる（CORE-2・CORE-6）。
            deps.privilege = Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "subordinate id configuration is unusable",
            ));
            assert!(deps.launcher_builder(true).is_err());
            assert!(deps.launcher_builder(false).is_ok());
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// SEC-1・SUP-1・#2132: fd 0〜2 のどれかが閉じていれば FAILED_PRECONDITION、すべて開いていれば通る。
        #[test]
        fn stdio_check_rejects_any_closed_standard_fd() {
            assert!(check_stdio_open(|_| true).is_ok());
            for closed in 0..3 {
                let e = check_stdio_open(|fd| fd != closed).unwrap_err();
                assert_eq!(e.code(), ErrorCode::FailedPrecondition);
                assert_eq!(e.message(), "stdin, stdout and stderr must be open");
            }
        }
        use fandhe_container_core::traits::{
            CreateStateRequest, DeleteStateRequest, DeleteStateResponse, ListStateRequest,
            StateList,
        };

        /// SEC-4・SUP-1・#2058: 監査中継は単一スレッドでしか作れないため、`run_start_until`（`stderr_sink` の常駐スレッドを
        /// 作る）より前に生成する。実プロセスの単一スレッド条件はテストハーネス（複数スレッド）では再現できないので、
        /// 入口の呼び出し順をソースで固定し、前後が入れ替わる退行（接続拒否が監査へ届かなくなる）を検出する。
        #[test]
        fn sec4_audit_relay_is_spawned_before_the_first_logging_thread() {
            let src = include_str!("start_entry.rs");
            // テスト自身の文字列リテラルに一致しないよう、`run_main_inner` の本体から探す(宣言はテストより前にある)。
            let body = src
                .find("fn run_main_inner<")
                .expect("run_main_inner in the entry");
            let entry = src[body..]
                .find("let relay = crate::exec::default_audit_sink(")
                .map(|p| p + body)
                .expect("relay construction in the entry");
            assert!(
                entry < src.find("mod tests").unwrap_or(usize::MAX),
                "relay construction must be found in the production code"
            );
            let spawn = src[entry..]
                .find("ControlAuditRelay::spawn")
                .map(|p| p + entry)
                .expect("relay spawn in the entry");
            let run = src[entry..]
                .find("run_start_until(\n")
                .map(|p| p + entry)
                .expect("run_start_until call in the entry");
            assert!(spawn < run, "relay must be spawned before run_start_until");
            // CORE-3・SUP-1: helper は委譲 cgroup に属するため、deps へ同伴プロセスとして宣言してから起動する。
            let deps = src[entry..]
                .find(".with_companions(companions)")
                .map(|p| p + entry)
                .expect("companions declared to the start deps");
            assert!(
                spawn < deps && deps < run,
                "helper must be declared as a cgroup companion before run_start_until"
            );
        }

        /// SEC-4・ESC-06・#2236: 本番の入口は relay を launcher の回収点の記録先（`exit_audit_sink`）へ渡し、launch の時点の
        /// 記録先（`audit_sink`）は `FileAuditSink` のままにする。実プロセスの結線は単一スレッド条件のためソースで固定する。
        #[test]
        fn sec4_2236_relay_is_wired_to_the_exit_audit_only() {
            let src = include_str!("start_entry.rs");
            let production = src.split("#[cfg(test)]").next().unwrap_or(src);
            let entry = production
                .find("fn run_main_inner<")
                .expect("run_main_inner in the entry");
            let wire = production[entry..]
                .find(".with_exit_audit_sink(Arc::clone(audit))")
                .map(|p| p + entry)
                .expect("relay is passed as the exit audit sink");
            let run = production[entry..]
                .find("run_start_until(\n")
                .map(|p| p + entry)
                .expect("run_start_until call in the entry");
            assert!(wire < run, "relay must be wired before run_start_until");
            let build = production
                .find("fn build_launcher(")
                .expect("build_launcher");
            let body = &production[build..];
            let exit = body
                .find("builder.exit_audit_sink(Arc::clone(sink))")
                .expect("exit audit sink passed to the launcher builder");
            let main = body
                .find(".audit_sink(Arc::clone(audit))")
                .expect("launch-time audit sink");
            assert!(main < exit);
            // 回復用の launcher は launch しないので、exit 監査の記録先を渡さない。
            let recover = production
                .find("self.launcher_builder(false)?")
                .expect("recover_interrupted builds the recovery launcher");
            let recover_end = production[recover..]
                .find("recover_interrupted_start(store")
                .map(|p| p + recover)
                .expect("recovery call follows the builder");
            assert!(!production[recover..recover_end].contains("exit_audit_sink("));
        }

        /// SEC-4・#2481: 本番の入口は relay を start の検証の拒否の記録先（`rejection_audit_sink`）へ渡し、回復用の
        /// launcher には渡さない。実プロセスの結線は単一スレッド条件のためソースで固定する。
        #[test]
        fn sec4_2481_relay_is_wired_to_the_rejection_point() {
            let src = include_str!("start_entry.rs");
            let production = src.split("#[cfg(test)]").next().unwrap_or(src);
            let entry = production
                .find("fn run_main_inner<")
                .expect("run_main_inner in the entry");
            let wire = production[entry..]
                .find(".with_rejection_audit_sink(Arc::clone(audit))")
                .map(|p| p + entry)
                .expect("relay is passed as the rejection audit sink");
            let run = production[entry..]
                .find("run_start_until(\n")
                .map(|p| p + entry)
                .expect("run_start_until call in the entry");
            assert!(wire < run, "relay must be wired before run_start_until");
            let build = production
                .find("fn build_launcher(")
                .expect("build_launcher");
            assert!(production[build..].contains("builder.rejection_audit_sink(Arc::clone(sink))"));
            let recover = production
                .find("self.launcher_builder(false)?")
                .expect("recover_interrupted builds the recovery launcher");
            let recover_end = production[recover..]
                .find("recover_interrupted_start(store")
                .map(|p| p + recover)
                .expect("recovery call follows the builder");
            assert!(!production[recover..recover_end].contains("rejection_audit_sink("));
        }

        /// 失敗する内側の sink（記録のたびに固定のエラーを返す）。
        struct FailingSink(ErrorCode);

        impl AuditSink for FailingSink {
            fn record(&self, _: &AuditRecord) -> Result<(), TraitError> {
                Err(TraitError::new(self.0, "fake"))
            }
        }

        fn mount_record() -> AuditRecord {
            use fandhe_container_core::audit_log::{AuditEvent, AuditPid, AuditTimestamp};
            AuditRecord::new(
                AuditTimestamp::from_unix_duration(Duration::new(1, 0)),
                AuditPid::new(1).unwrap(),
                AuditEvent::Mount {
                    path: None,
                    reason: None,
                },
            )
        }

        /// SEC-4・REPAIR-4・#2481: 失敗のときだけ、固定のイベント名と内側のエラーコードで 1 回ログを出す。
        #[test]
        fn sec4_2481_observe_logs_only_failures_with_fixed_vocabulary() {
            let seen = std::cell::RefCell::new(Vec::new());
            let log = |event: &'static str, code: Option<ErrorCode>| {
                seen.borrow_mut().push((event, code));
            };
            assert!(ObservedRejectionSink::observe(Ok(()), log).is_ok());
            assert!(seen.borrow().is_empty());
            let e = ObservedRejectionSink::observe(
                Err(TraitError::new(ErrorCode::InvalidArgument, "x")),
                log,
            )
            .unwrap_err();
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
            assert_eq!(
                seen.borrow().as_slice(),
                [(
                    "rejection_audit_record_failed",
                    Some(ErrorCode::InvalidArgument)
                )]
            );
        }

        /// SEC-4・#2481: 包みは内側の成否をそのまま返す（失敗のログは `log_event` が担い、結果は覆さない）。
        #[test]
        fn sec4_2481_observed_rejection_sink_passes_results_through() {
            let ok = ObservedRejectionSink {
                inner: Arc::new(OkSink),
            };
            assert!(ok.record(&mount_record()).is_ok());
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            assert!(ok.record_until(&mount_record(), deadline).is_ok());
            let failing = ObservedRejectionSink {
                inner: Arc::new(FailingSink(ErrorCode::InvalidArgument)),
            };
            assert_eq!(
                failing.record(&mount_record()).unwrap_err().code(),
                ErrorCode::InvalidArgument
            );
            assert_eq!(
                failing
                    .record_until(&mount_record(), deadline)
                    .unwrap_err()
                    .code(),
                ErrorCode::InvalidArgument
            );
        }

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
    use fandhe_container_core::traits::{
        CreateStateRequest, DeleteStateRequest, DeleteStateResponse, ListStateRequest, StateList,
    };

    /// 試験用の cgroup 記録（世代の識別子 instance = 7）。
    fn test_placement() -> fandhe_container_core::traits::CgroupPlacement {
        fandhe_container_core::traits::CgroupPlacement::new(
            fandhe_container_core::traits::CgroupScope::new("/user.slice/x.scope").unwrap(),
            StateRevision::from_raw(7),
        )
    }

    /// 試験用の start 時 instance（[`test_placement`] と同じ世代）。
    fn test_instance() -> Option<StateRevision> {
        Some(StateRevision::from_raw(7))
    }

    /// 1 レコードを持つメモリ上のストア（`update` は status・監視・明示 stop を反映して revision を進める）。
    struct OneRecord(Mutex<StateRecord>);

    impl OneRecord {
        fn stopped() -> Arc<Self> {
            let rec = StateRecord::new(
                ContainerStatus::stopped(ContainerId::new("c1").expect("id"), None),
                std::env::temp_dir().join("b"),
                StateRevision::from_raw(1),
            )
            .expect("record")
            .with_cgroup(test_placement());
            Arc::new(Self(Mutex::new(rec)))
        }
    }

    impl StateStore for OneRecord {
        fn create(&self, _: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "unused"))
        }
        fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            let mut g = self.0.lock().unwrap();
            if g.revision() != req.expected_revision() {
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
            }
            let explicit = req.explicit_stop().unwrap_or(g.explicit_stop());
            let next = StateRecord::new(
                req.status().clone(),
                g.bundle().to_path_buf(),
                StateRevision::from_raw(g.revision().value() + 1),
            )
            .expect("record")
            .with_cgroup(test_placement())
            .with_supervision(req.supervision().unwrap_or_else(|| g.supervision()))
            .with_explicit_stop(explicit);
            *g = next.clone();
            Ok(next)
        }
        fn get(&self, _: &GetStateRequest) -> Result<StateRecord, TraitError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn list(&self, _: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "unused"))
        }
        fn delete(&self, _: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "unused"))
        }
    }

    /// SUP-9・SUP-3・契約 14・#2440: 再 launch 中に受理した明示 stop が未記録のまま回収だけ後始末で完了した経路
    /// （最初の terminate 失敗後の再試行成功、待ち切れず後始末で回収完了）では、回収確認後に明示 stop を残し、
    /// `unless-stopped` の再開が再起動対象にしない。
    #[test]
    fn sup9_2440_pending_explicit_stop_is_persisted_after_disposal() {
        use crate::restart::{NoRestartReason, RestartDecision, evaluate_resume};
        let id = ContainerId::new("c1").expect("id");
        let st = OneRecord::stopped();
        let store: Arc<dyn StateStore> = st.clone();
        assert_eq!(
            finish_disposed_explicit(&store, &id, test_instance(), (true, vec![]), 0, true),
            0
        );
        let rec = st.0.lock().unwrap().clone();
        assert_eq!(rec.explicit_stop(), ExplicitStop::Recorded);
        assert_eq!(rec.status().state(), ContainerState::Stopped);
        assert_eq!(
            evaluate_resume(
                crate::restart::RestartPolicy::UnlessStopped,
                rec.explicit_stop()
            ),
            RestartDecision::DoNotRestart {
                reason: NoRestartReason::ExplicitStop
            }
        );
    }

    /// SUP-9・#2440: 回収を確かめられなければ明示 stop を残さず非 0（INTERNAL）。pending でなければ記録を動かさない。
    #[test]
    fn sup9_2440_explicit_stop_not_persisted_when_disposal_unconfirmed_or_not_pending() {
        let id = ContainerId::new("c1").expect("id");
        let internal = exit_code_for(ErrorCode::Internal).get();
        let st = OneRecord::stopped();
        let store: Arc<dyn StateStore> = st.clone();
        assert_eq!(
            finish_disposed_explicit(&store, &id, test_instance(), (false, vec![]), 0, true),
            internal
        );
        assert_eq!(
            st.0.lock().unwrap().explicit_stop(),
            ExplicitStop::NotRecorded
        );
        assert_eq!(
            finish_disposed_explicit(&store, &id, test_instance(), (true, vec![]), 0, false),
            0
        );
        assert_eq!(
            st.0.lock().unwrap().explicit_stop(),
            ExplicitStop::NotRecorded
        );
    }

    /// SUP-9・SUP-3・SEC-1・契約 14・#2440: start 時の instance も記録の cgroup も無い（`None == None`）ときは
    /// 同一世代とみなさず、明示 stop を書かない（同じ ID で再作成された新世代の unless-stopped を止めない）。
    #[test]
    fn sup9_2440_persist_skips_when_no_generation_identifier() {
        let id = ContainerId::new("c1").expect("id");
        let st = OneRecord::stopped();
        *st.0.lock().unwrap() = StateRecord::new(
            ContainerStatus::stopped(id.clone(), None),
            std::env::temp_dir().join("b"),
            StateRevision::from_raw(1),
        )
        .expect("record");
        let store: Arc<dyn StateStore> = st.clone();
        assert_eq!(
            finish_disposed_explicit(&store, &id, None, (true, vec![]), 0, true),
            0
        );
        assert_eq!(
            st.0.lock().unwrap().explicit_stop(),
            ExplicitStop::NotRecorded
        );
    }

    /// SUP-9・#2440: 記録が `Stopped` でない（残せない）なら fail-closed で非 0。
    #[test]
    fn sup9_2440_persist_fails_closed_when_record_not_stopped() {
        let id = ContainerId::new("c1").expect("id");
        let st = OneRecord::stopped();
        *st.0.lock().unwrap() = StateRecord::new(
            ContainerStatus::running(id.clone(), NonZeroU32::new(43)),
            std::env::temp_dir().join("b"),
            StateRevision::from_raw(1),
        )
        .expect("record")
        .with_cgroup(test_placement());
        let store: Arc<dyn StateStore> = st.clone();
        assert_eq!(
            finish_disposed_explicit(&store, &id, test_instance(), (true, vec![]), 0, true),
            exit_code_for(ErrorCode::Internal).get()
        );
    }

    /// 書かれたバイト列を共有する書き手(#2008 の試験用)。
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const LEGACY_LINE: &str = r#"{"level":"warn","event":"legacy_tiocsti_enabled","sysctl":"dev.tty.legacy_tiocsti","value":1}"#;

    /// CORE-5・SEC-1・REPAIR-4(#2008): 有効のとき固定 1 行が改行付きでログへ入る。
    #[test]
    fn sup_core5_2008_enabled_logs_exact_line() {
        use crate::stderr_sink::{EmitOutcome, StderrSink};
        use fandhe_container_core::legacy_tiocsti::LegacyTiocsti;
        let buf = SharedBuf::default();
        let sink = StderrSink::spawn(buf.clone(), 4);
        assert_eq!(
            log_legacy_tiocsti_to(&sink, LegacyTiocsti::Enabled),
            Some(EmitOutcome::Queued)
        );
        assert_eq!(sink.flush(Duration::from_secs(5)), EmitOutcome::Written);
        assert_eq!(
            buf.0.lock().unwrap().as_slice(),
            format!("{LEGACY_LINE}\n").as_bytes()
        );
    }

    /// SEC-4・REPAIR-4(#2027): 縮退した監査の網羅の評価値は固定 1 行が改行付きでログへ入り、縮退なし・記録なしでは入らない。
    #[test]
    fn sec4_2027_degraded_audit_coverage_reaches_the_supervisor_log() {
        use crate::stderr_sink::{EmitOutcome, StderrSink};
        use fandhe_container_core::audit_log::{
            AuditCoverage, AuditCoveragePolicy, DegradeReason, KernelAuditLayerStatus,
        };
        use fandhe_container_core::launch_isolation::{
            LaunchIsolationRecord, RecordedLandlock, RecordedRule, RecordedTarget, RootIdentity,
        };
        let base = || {
            LaunchIsolationRecord::from_parts(
                RootIdentity::new(44, 1234),
                RecordedLandlock::new(0xFFFF, vec![RecordedRule::new(RecordedTarget::Root, 0x7)])
                    .unwrap(),
            )
        };
        let degraded = base().with_audit_coverage(
            AuditCoveragePolicy::BestEffort,
            AuditCoverage::new(
                KernelAuditLayerStatus::Degraded(DegradeReason::SeccompKillNotLogged),
                KernelAuditLayerStatus::Degraded(DegradeReason::LandlockAuditAbiTooOld),
            ),
        );
        let buf = SharedBuf::default();
        let sink = StderrSink::spawn(buf.clone(), 4);
        assert_eq!(
            log_audit_coverage_to(&sink, Some(&degraded)),
            Some(EmitOutcome::Queued)
        );
        assert_eq!(sink.flush(Duration::from_secs(5)), EmitOutcome::Written);
        assert_eq!(
            buf.0.lock().unwrap().as_slice(),
            concat!(
                r#"{"component":"core.audit","operation":"audit_coverage","outcome":"degraded","#,
                r#""seccomp_kill":"seccomp_kill_not_logged","landlock":"landlock_audit_abi_too_old"}"#,
                "\n"
            )
            .as_bytes()
        );
        let clear = base().with_audit_coverage(
            AuditCoveragePolicy::BestEffort,
            AuditCoverage::new(
                KernelAuditLayerStatus::Requested,
                KernelAuditLayerStatus::Requested,
            ),
        );
        assert_eq!(log_audit_coverage_to(&sink, Some(&clear)), None);
        assert_eq!(log_audit_coverage_to(&sink, Some(&base())), None);
        assert_eq!(log_audit_coverage_to(&sink, None), None);
    }

    /// SEC-4・REPAIR-4(#2468): 縮退の監査記録を書けなかった launch だけが、縮退の行に続けて記録失敗の固定 1 行をログへ入れる。
    #[test]
    fn sec4_repair4_2468_record_failure_reaches_the_supervisor_log() {
        use crate::stderr_sink::{EmitOutcome, StderrSink};
        use fandhe_container_core::audit_log::{
            AuditCoverage, AuditCoveragePolicy, DegradeReason, KernelAuditLayerStatus,
        };
        use fandhe_container_core::launch_isolation::{
            LaunchIsolationRecord, RecordedLandlock, RecordedRule, RecordedTarget, RootIdentity,
        };
        let base = || {
            LaunchIsolationRecord::from_parts(
                RootIdentity::new(44, 1234),
                RecordedLandlock::new(0xFFFF, vec![RecordedRule::new(RecordedTarget::Root, 0x7)])
                    .unwrap(),
            )
        };
        let degraded = base().with_audit_coverage(
            AuditCoveragePolicy::BestEffort,
            AuditCoverage::new(
                KernelAuditLayerStatus::Degraded(DegradeReason::SeccompKillNotLogged),
                KernelAuditLayerStatus::Degraded(DegradeReason::LandlockAuditAbiTooOld),
            ),
        );
        let degraded_line = concat!(
            r#"{"component":"core.audit","operation":"audit_coverage","outcome":"degraded","#,
            r#""seccomp_kill":"seccomp_kill_not_logged","landlock":"landlock_audit_abi_too_old"}"#,
            "\n"
        );
        let failed_line = concat!(
            r#"{"component":"core.audit","operation":"audit_coverage_record","outcome":"failed"}"#,
            "\n"
        );

        // 記録に失敗した起動: 縮退の行 + 記録失敗の行。
        let failed = degraded
            .clone()
            .with_audit_coverage_record_failed()
            .unwrap();
        let buf = SharedBuf::default();
        let sink = StderrSink::spawn(buf.clone(), 4);
        assert_eq!(
            log_audit_coverage_to(&sink, Some(&failed)),
            Some(EmitOutcome::Queued)
        );
        assert_eq!(
            log_audit_coverage_record_failed_to(&sink, Some(&failed)),
            Some(EmitOutcome::Queued)
        );
        assert_eq!(sink.flush(Duration::from_secs(5)), EmitOutcome::Written);
        assert_eq!(
            buf.0.lock().unwrap().as_slice(),
            format!("{degraded_line}{failed_line}").as_bytes()
        );

        // 記録に成功した縮退・縮退なし・評価なし・記録なしでは記録失敗の行は入らない。
        let buf = SharedBuf::default();
        let sink = StderrSink::spawn(buf.clone(), 4);
        let clear = base().with_audit_coverage(
            AuditCoveragePolicy::BestEffort,
            AuditCoverage::new(
                KernelAuditLayerStatus::Requested,
                KernelAuditLayerStatus::Requested,
            ),
        );
        for r in [Some(&degraded), Some(&clear), Some(&base()), None] {
            assert_eq!(log_audit_coverage_record_failed_to(&sink, r), None);
        }
        assert_eq!(
            log_audit_coverage_to(&sink, Some(&degraded)),
            Some(EmitOutcome::Queued)
        );
        assert_eq!(sink.flush(Duration::from_secs(5)), EmitOutcome::Written);
        assert_eq!(buf.0.lock().unwrap().as_slice(), degraded_line.as_bytes());
    }

    /// CORE-5(#2008): 対象外の状態では何も入れない。
    #[test]
    fn sup_core5_2008_non_applicable_logs_nothing() {
        use crate::stderr_sink::StderrSink;
        use fandhe_container_core::legacy_tiocsti::LegacyTiocsti;
        for state in [
            LegacyTiocsti::Absent,
            LegacyTiocsti::Disabled,
            LegacyTiocsti::Unexpected,
            LegacyTiocsti::ReadFailed {
                kind: std::io::ErrorKind::PermissionDenied,
            },
        ] {
            let buf = SharedBuf::default();
            let sink = StderrSink::spawn(buf.clone(), 4);
            assert_eq!(log_legacy_tiocsti_to(&sink, state), None, "{state:?}");
            let _ = sink.flush(Duration::from_secs(5));
            assert!(buf.0.lock().unwrap().is_empty(), "{state:?}");
        }
    }

    /// REPAIR-5(#2008)・REPAIR-12(#2538): 書き手が止まりキューが満杯でも待たずに `QueueFull` で戻る。
    ///
    /// 専用スレッドが 1 行目を取り出す時刻は呼び出し側の emit と順序が決まっていない。取り出しが遅れると
    /// 後半の emit の途中で空きができ、最後が `Queued` になる（macOS CI で観測）。書き手に入ったことを
    /// 待ってから連続 emit し、空きの位置を固定する(#1970 と同じ対策)。
    #[test]
    fn sup_repair5_2008_full_queue_does_not_block() {
        use crate::stderr_sink::test_support::stuck;
        use crate::stderr_sink::{EmitOutcome, StderrSink};
        use fandhe_container_core::legacy_tiocsti::LegacyTiocsti;
        let (release, arrived, writer) = stuck();
        let sink = StderrSink::spawn(writer, 1);
        assert_eq!(
            log_legacy_tiocsti_to(&sink, LegacyTiocsti::Enabled),
            Some(EmitOutcome::Queued)
        );
        arrived
            .recv_timeout(Duration::from_secs(5))
            .expect("the drain thread must reach the stuck writer");
        // キューは空・容量 1。ここから先は専用スレッドが戻らないので結果が決まる。
        let started = Instant::now();
        let outcomes: Vec<_> = (0..8)
            .map(|_| log_legacy_tiocsti_to(&sink, LegacyTiocsti::Enabled))
            .collect();
        assert!(started.elapsed() < Duration::from_secs(1));
        let mut expected = vec![Some(EmitOutcome::Queued)];
        expected.extend(std::iter::repeat_n(Some(EmitOutcome::QueueFull), 7));
        assert_eq!(outcomes, expected);
        drop(release);
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
