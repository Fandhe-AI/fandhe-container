//! supervisor の bin の入口: 起動 → 結果の返却 → 監視（`monitor` / restart）を 1 プロセスで行う処理順
//! （TASK-157 追補・#1717・SUP-1・SUP-3・MS-9。関連: CORE-1・CORE-2・CORE-3・SEC-1・SEC-4・REPAIR-3・REPAIR-4・REPAIR-5・D-19）。
//!
//! 呼び出し元は `src/main.rs`（`run_main`）。CLI（#1718）が [`crate::start_contract`] の契約で起動し、結果チャネル
//! （stdout の pipe）の 1 行を読む。#1314 のオーナー判断（配置 1-A・cgroup 3-ii）により、`oci_runtime::start`
//! （Created → Running の予約と記録）を呼ぶ層は CLI から本入口へ移った。
//!
//! # 処理順（[`run_start`] と [`run_supervised`]）
//! 0. 結果チャネルの検証（stdout が FIFO か。`run_main`）／1. argv の解析（[`crate::start_contract::StartArgs`]）／
//!    2. スレッド数が 1 か（`oci_runtime::start` の前提。以後ログ捕捉・restart のワーカーは手順 10 以降に限る）／
//! 3. 状態の事前確認（Created・pid なし・cgroup 未記録。副作用なし）／4. [`StartDeps::check_launcher_available`]
//!    （副作用なし。本番 launcher が無い間はここで `UNIMPLEMENTED` で止まる）／5. cgroup の連鎖
//!    （[`StartDeps::prepare_cgroup`]）／6. 監査 sink（[`StartDeps::build_audit_sink`]。fork の前）／7. launcher の構築と
//!    [`SpecCapturingLauncher`] での包み／8. `oci_runtime::start`／9. `FCSUP1 OK <pid>` の報告／
//!    10. `SupervisedState::attach` → [`supervise_with_restart`]。
//!
//! 手順 3・4 は cgroup の連鎖（手順 5）より前に置く。スコープの追記は 1 回限りで取り消す API が無いため、
//! launcher が使えない場合や状態が Created でない場合に、スコープを残さずに止める。
//!
//! # 報告より前の失敗の後始末（fail-closed。#1541 と同じ要求）
//! - `Timeout` 以外: 予約を Created へ戻すことと子の terminate は core の `start` が行う。本入口は作った cgroup を
//!   [`StartDeps::release_cgroup`] で消してから ERR を報告する。
//! - `start` が `Timeout`: 予約（Running・pid なし）が残る。本入口が終了すると core の後始末スレッドごと消えるため、
//!   `recover_interrupted_start` を約 50ms 刻みで再試行して Created へ戻し、`take_unreaped_processes` で引き取った
//!   ハンドルを terminate する。戻せたら cgroup を消して ERR `TIMEOUT`、戻せなければ cgroup を消さずに ERR `INTERNAL`。
//! - 後始末自体の失敗は元のエラーを隠さず、構造化ログ（stderr）に出す。
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
use std::num::NonZeroU8;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    LAUNCHER_REPLY_GRACE, LaunchedProcess, LifecycleOp, OciRuntimeError, ProcessLauncher,
    StartTimeouts, exit_code_for, recover_interrupted_start, start, take_unreaped_processes,
};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ErrorCode, GetStateRequest, StartRequest, StateRecord, StateStore,
    TraitError,
};

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
    fn prepare_cgroup(
        &mut self,
        store: &dyn StateStore,
        observed: &StateRecord,
    ) -> Result<(), TraitError>;

    /// 手順 6: 監査 sink を構築する（fork の前。SEC-4）。実装が保持し [`Self::build_launcher`] が使う。
    fn build_audit_sink(&mut self) -> Result<(), TraitError>;

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

/// 構造化ログを stderr に 1 行出す（値は固定語彙だけ。入力値・OS のエラー文字列は載せない。REPAIR-4）。
fn log_event(event: &'static str, code: Option<ErrorCode>) {
    let code = code.map(|c| c.as_str()).unwrap_or("");
    eprintln!("{{\"component\":\"supervisor\",\"event\":\"{event}\",\"code\":\"{code}\"}}");
}

fn op_err(e: TraitError) -> OciRuntimeError {
    OciRuntimeError::from_trait_error(LifecycleOp::Start, e)
}

/// 報告 1 行を書いて flush する。
fn write_report(out: &mut dyn Write, report: &StartReport) -> std::io::Result<()> {
    out.write_all(report.encode().as_bytes())?;
    out.flush()
}

/// 後始末の失敗を、元のエラーを隠さずにログへ出す。
fn release_logged(deps: &mut dyn StartDeps) {
    if let Err(e) = deps.release_cgroup() {
        log_event("cgroup_release_failed", Some(e.code()));
    }
}

/// 手順 3〜9（報告まで）。成功なら `Running`、失敗なら報告済みの終了コード。
///
/// 報告（`out` への 1 行）は成功・失敗とも本関数が書く。報告の書き込みに失敗しても（EPIPE 等）監視は続けるため
/// 成功は `Ok(Running)` を返し、ログに `report_failed` を出す。
pub fn run_start(
    deps: &mut dyn StartDeps,
    store: &dyn StateStore,
    recorder: &OpRecorder,
    req: &StartRequest,
    timeouts: &StartTimeouts,
    out: &mut dyn Write,
) -> Result<Running, NonZeroU8> {
    match start_sequence(deps, store, recorder, req, timeouts) {
        Ok(running) => {
            let report = StartReport::Started {
                pid: running.process.pid(),
            };
            if write_report(out, &report).is_err() {
                log_event("report_failed", None);
            }
            Ok(running)
        }
        Err(err) => {
            if write_report(out, &StartReport::failed(&err)).is_err() {
                log_event("report_failed", None);
            }
            Err(err.exit_code())
        }
    }
}

fn start_sequence(
    deps: &mut dyn StartDeps,
    store: &dyn StateStore,
    recorder: &OpRecorder,
    req: &StartRequest,
    timeouts: &StartTimeouts,
) -> Result<Running, OciRuntimeError> {
    // 3: 副作用なしの事前確認。
    let observed = store
        .get(&GetStateRequest::new(req.id().clone()))
        .map_err(op_err)?;
    let status = observed.status();
    if status.state() != ContainerState::Created || status.pid().is_some() {
        return Err(op_err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container is not in created state",
        )));
    }
    if observed.cgroup().is_some() {
        return Err(op_err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "cgroup scope is already recorded; delete and recreate the container",
        )));
    }
    // 4: 副作用なしで launcher の可用性を確かめる。
    deps.check_launcher_available().map_err(op_err)?;
    // 5〜7: ここから先の失敗は、作った cgroup を消してから返す。
    if let Err(e) = deps.prepare_cgroup(store, &observed) {
        release_logged(deps);
        return Err(op_err(e));
    }
    if let Err(e) = deps.build_audit_sink() {
        release_logged(deps);
        return Err(op_err(e));
    }
    let inner = match deps.build_launcher() {
        Ok(l) => l,
        Err(e) => {
            release_logged(deps);
            return Err(op_err(e));
        }
    };
    let capturing = Arc::new(SpecCapturingLauncher::new(Arc::clone(&inner)));
    let launcher: Arc<dyn ProcessLauncher> = capturing.clone();
    // 8
    match start(store, recorder, &launcher, req, timeouts) {
        Ok(started) => {
            let (_record, process) = started.into_parts();
            let relauncher: Arc<dyn Relauncher> = match capturing.captured_spec() {
                Some(spec) => Arc::new(LauncherRelauncher::new(inner, spec)),
                None => Arc::new(NoSpecRelauncher),
            };
            Ok(Running {
                process,
                relauncher,
            })
        }
        Err(e) if e.code() == ErrorCode::Timeout => {
            if recover_after_timeout(store, &launcher, req.id(), timeouts) {
                release_logged(deps);
                Err(e)
            } else {
                // 予約か子が残り得る。cgroup は消さない（子が入っている可能性がある）。
                Err(OciRuntimeError::new(
                    LifecycleOp::Start,
                    ErrorCode::Internal,
                    "start timed out and cleanup could not be confirmed; a reservation or child process may remain",
                ))
            }
        }
        Err(e) => {
            release_logged(deps);
            Err(e)
        }
    }
}

/// `start` の `Timeout` 後に予約を Created へ戻し、未回収のハンドルを terminate する。両方済んだら `true`。
fn recover_after_timeout(
    store: &dyn StateStore,
    launcher: &Arc<dyn ProcessLauncher>,
    id: &ContainerId,
    timeouts: &StartTimeouts,
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
    for p in take_unreaped_processes() {
        if let Err(e) = p.terminate(timeouts.terminate()) {
            log_event("unreaped_terminate_failed", Some(e.code()));
            all_reaped = false;
        }
    }
    recovered && all_reaped
}

/// 返ってきたハンドルを terminate して回収を確かめる。全件確かめられたら `true`（CORE-1・REPAIR-5）。
fn dispose(
    process: Option<Box<dyn LaunchedProcess>>,
    late: Option<&LateOrphans>,
    timeouts: &StartTimeouts,
) -> bool {
    let mut ok = true;
    if let Some(p) = process {
        match p.terminate(timeouts.terminate()) {
            Ok(()) => log_event("handle_terminated", None),
            Err(e) => {
                log_event("handle_terminate_failed", Some(e.code()));
                ok = false;
            }
        }
    }
    if let Some(late) = late {
        if !late.wait_settled(timeouts.terminate().saturating_add(LAUNCHER_REPLY_GRACE)) {
            log_event("late_orphans_unsettled", None);
            ok = false;
        }
        for (p, _reason) in late.take() {
            match p.terminate(timeouts.terminate()) {
                Ok(()) => log_event("handle_terminated", None),
                Err(e) => {
                    log_event("handle_terminate_failed", Some(e.code()));
                    ok = false;
                }
            }
        }
    }
    ok
}

/// 手順 10: 監視と restart。返り値は supervisor プロセスの終了コード（0 = 記録して正常に終わった）。
///
/// 監視の結果が返したハンドルの所有者は本入口なので、終了の前に terminate して回収を確かめる。
/// 回収を確かめられなければ `Internal` の非 0 で終わる。
pub fn run_supervised(
    store: Arc<dyn StateStore>,
    id: ContainerId,
    running: Running,
    restart: RestartPolicy,
    timeouts: &StartTimeouts,
    stop: &StopToken,
) -> u8 {
    let internal = exit_code_for(ErrorCode::Internal).get();
    let Running {
        process,
        relauncher,
    } = running;
    let mut state = match SupervisedState::attach(store, id) {
        Ok(s) => s,
        Err(e) => {
            log_event("attach_failed", Some(e.code()));
            let reaped = dispose(Some(process), None, timeouts);
            return if reaped {
                exit_code_for(e.code()).get()
            } else {
                internal
            };
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
            let reaped = dispose(Some(process), None, timeouts);
            return if reaped {
                exit_code_for(e.code()).get()
            } else {
                internal
            };
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
            if dispose(process, Some(&late), timeouts) {
                0
            } else {
                internal
            }
        }
        Ok(SuperviseOutcome::RelaunchFailed { error, late, .. })
        | Ok(SuperviseOutcome::RestartUnrecorded { error, late, .. }) => {
            log_event("restart_failed", Some(error.code()));
            if dispose(None, Some(&late), timeouts) {
                exit_code_for(error.code()).get()
            } else {
                internal
            }
        }
        Ok(SuperviseOutcome::MonitorFailed { process, .. }) => {
            log_event("monitor_failed", None);
            dispose(process, None, timeouts);
            internal
        }
        Ok(SuperviseOutcome::MonitorError { error, process, .. }) => {
            log_event("monitor_error", Some(error.code()));
            if dispose(Some(process), None, timeouts) {
                exit_code_for(error.code()).get()
            } else {
                internal
            }
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
        ) -> Result<(), TraitError> {
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
            let chain = delegated
                .record_scope(store, observed)
                .and_then(|r| r.create_cgroup())
                .and_then(|p| p.apply_limits(&recorder, &plan))
                .and_then(|l| l.into_join())
                .map_err(to_trait);
            let start_cgroup = chain?;
            self.start_cgroup = Some(start_cgroup);
            self.delegated = Some(delegated);
            Ok(())
        }

        fn build_audit_sink(&mut self) -> Result<(), TraitError> {
            self.audit = Some(crate::exec::default_audit_sink(Some(self.root.clone()))?);
            Ok(())
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
    pub fn run_main<I: IntoIterator<Item = OsString>>(args: I) -> ExitCode {
        // 0: 結果チャネル。不正なら報告できないので stderr に固定スキーマの JSON を出して終わる。
        let mut out = match open_result_channel() {
            Ok(f) => f,
            Err(e) => {
                let err = op_err(e);
                let _ = err.write_json_line(&mut std::io::stderr());
                return ExitCode::from(err.exit_code().get());
            }
        };
        let fail = |out: &mut File, err: OciRuntimeError| -> ExitCode {
            if write_report(out, &StartReport::failed(&err)).is_err() {
                log_event("report_failed", None);
            }
            ExitCode::from(err.exit_code().get())
        };
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
        let mut deps = ProductionStartDeps::new(args.root);
        let running = match run_start(
            &mut deps,
            store.as_ref(),
            &OpRecorder::new(),
            &req,
            &timeouts,
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
