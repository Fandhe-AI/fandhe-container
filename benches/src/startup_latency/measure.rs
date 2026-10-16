//! 起動レイテンシの計測本体（Linux・x86_64 / aarch64 限定。TASK-190・REPAIR-8・REPAIR-5・CORE-10）。
//!
//! 1 試行は「core の `oci_runtime::create` → `systemd-run --user --scope` で supervisor の bin を起動 → 結果チャネルの
//! `FCSUP1 OK` を読み終える」までで、CLI は経由しない。supervisor は本番 launcher（#1819）まで到達するため、分離
//! （user namespace・cgroup・Landlock）込みの起動を測る。分離を弱める経路は持たず、失敗は失敗として数える（REPAIR-3）。
//!
//! # 後始末（core の `delete` を使わない理由）
//! ベンチのプロセスは試行ごとの systemd スコープの外にいるため、`delete` は委譲スコープの照合で
//! `FailedPrecondition` になる（#2049 の観察と同じ）。記録済みのスコープを外から開く core の API の変更は
//! #1314 の決定の変更にあたるため範囲外とし、状態・cgroup・プローブの消滅を検証してから状態ルートごと消す。
//! 検証できなければ ID を `leftover_ids` に積み、以後の試行を止めて非ゼロで終わる（fail-closed）。

use super::StartupLatencyError;
use super::args::Plan;
use super::bin_check::{verify_executable, verify_work_base};
use super::bundle::build_bundle;
use super::output::{Failures, Params, RunResult, Sample, render_json};
use super::probe_env::effective_uid;
use super::report::{ReportOutcome, classify, spawn_report_reader};
use fandhe_container_core::cgroups::CgroupName;
use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{StartTimeouts, create};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, CreateRequest, GetStateRequest, StateStore,
};
use fandhe_container_supervisor::start_contract::cli_receive_deadline;
use fandhe_container_supervisor::state::open_default_store;
use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

/// supervisor の終了を待つ上限（成功時はコンテナの終了を待って 0 で終わる）。
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);
/// kill 後の回収を待つ上限。
const REAP_TIMEOUT: Duration = Duration::from_secs(10);
/// cgroup の消滅・プローブの消滅を待つ上限。
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
/// systemd のスコープ GC を待つ短い猶予（その後は空の cgroup を自分で消す）。
const CGROUP_GC_GRACE: Duration = Duration::from_millis(500);
const POLL: Duration = Duration::from_millis(20);

fn io_err(what: &'static str, e: &std::io::Error) -> StartupLatencyError {
    StartupLatencyError::new("io-error", format!("{what} failed ({:?})", e.kind()))
}

/// 1 試行で起きた失敗の種別。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fail {
    Create,
    Spawn,
    ReportErr(&'static str),
    ReportTimeout,
    ReportEof,
    ReportInvalid,
    SupervisorExit,
}

/// 試行後の状態の期待値。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// OK を受けた: `Stopped`。
    Stopped,
    /// ERR を受けた: `Created` かつ pid なし。
    Created,
    /// 期限切れ・EOF・不正: 何でもよい（残っていれば強制的に掃除する）。
    Any,
}

struct Trial {
    sample: Option<Sample>,
    fails: Vec<Fail>,
    leftover: bool,
}

struct Ctx<'a> {
    plan: &'a Plan,
    work: &'a Path,
    bundle: &'a Path,
    nonce: &'a str,
    deadline: Instant,
    /// 結果 1 行を待つ上限（実機では `cli_receive_deadline`。試験では短くする）。
    report_timeout: Duration,
}

impl Ctx<'_> {
    /// 待ちの期限を全体の残り時間で切り詰める（最低 1 秒は残して後始末の判定を可能にする）。
    /// 最低 1 秒と固定の後始末期限があるため切り詰めだけでは超過を防げず、超過は試行の後と結果の公開前にも
    /// 照合する（`run_trials`。REPAIR-5）。
    fn cap(&self, d: Duration) -> Duration {
        d.min(
            self.deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_secs(1)),
        )
    }
}

enum ExitWait {
    Exited(Option<i32>),
    TimedOut { reaped: bool },
}

/// 子の終了を期限つきで待つ。超過したら kill して回収を `REAP_TIMEOUT` まで待つ（REPAIR-5）。
fn wait_for_exit(child: &mut Child, timeout: Duration) -> ExitWait {
    let until = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return ExitWait::Exited(status.code()),
            Ok(None) => {}
            Err(_) => return ExitWait::TimedOut { reaped: false },
        }
        if Instant::now() >= until {
            break;
        }
        std::thread::sleep(POLL);
    }
    let _ = child.kill();
    let reap_until = Instant::now() + REAP_TIMEOUT;
    while Instant::now() < reap_until {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return ExitWait::TimedOut { reaped: true };
        }
        std::thread::sleep(POLL);
    }
    ExitWait::TimedOut { reaped: false }
}

/// `ErrorKind::NotFound` か、走査中にプロセスが消えたことを示す `ESRCH`（raw os error 3）か。
fn is_gone(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(3)
}

/// `path` が存在しないと確かめられたときだけ `true`。権限エラー等で確認できない場合は `false`（REPAIR-5）。
fn path_gone(path: &Path) -> bool {
    matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}

/// `/proc` を走査し、この実行の nonce を引数に持つプローブの数を数える。
/// 列挙・読み取りの失敗（走査中に消えたプロセスを除く）は確認不能として `None` を返し、0 件と扱わない（REPAIR-5）。
fn probe_count(nonce: &str) -> Option<usize> {
    let dir = std::fs::read_dir("/proc").ok()?;
    let needle = nonce.as_bytes();
    let mut count = 0usize;
    for entry in dir {
        let entry = entry.ok()?;
        let is_pid = entry
            .file_name()
            .to_str()
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if !is_pid {
            continue;
        }
        match std::fs::read(entry.path().join("cmdline")) {
            Ok(c) => {
                if !needle.is_empty() && c.windows(needle.len()).any(|w| w == needle) {
                    count += 1;
                }
            }
            Err(e) if is_gone(&e) => {}
            Err(_) => return None,
        }
    }
    Some(count)
}

fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= until {
            return cond();
        }
        std::thread::sleep(POLL);
    }
}

/// `cgroup.events` の `populated` を読む（子孫 cgroup を含めた在籍の有無）。
/// `Some(true)` は子孫を含め在籍あり、`Some(false)` は空、`None` は読めない・解釈できない。
/// cgroup が既に消えている場合は空として `Some(false)` を返す。読み取り失敗を空と扱わない（REPAIR-5）。
fn read_populated(dir: &Path) -> Option<bool> {
    match std::fs::read_to_string(dir.join("cgroup.events")) {
        Ok(s) => s
            .lines()
            .find_map(|l| match l.strip_prefix("populated ")?.trim() {
                "1" => Some(true),
                "0" => Some(false),
                _ => None,
            }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && path_gone(dir) => Some(false),
        Err(_) => None,
    }
}

/// 子孫 cgroup を含めて空になるまで待つ（空でなければ `cgroup.kill` で落とす）。空になった（または元から空）なら `true`。
/// 判定は `cgroup.events` の `populated`（子孫を含む）で行う。supervisor・コンテナは子 cgroup に移るため、
/// 直下の `cgroup.procs` だけでは残存を見落とす。読み取り失敗は後始末失敗として `false`。
fn kill_and_drain(dir: &Path) -> bool {
    match read_populated(dir) {
        Some(false) => return true,
        None => return false,
        Some(true) => {}
    }
    let _ = std::fs::write(dir.join("cgroup.kill"), "1");
    wait_until(CLEANUP_TIMEOUT, || read_populated(dir) == Some(false))
}

/// コンテナの cgroup（ベンチが作った `fc-<id>@<instance>` だけ）を消す。消えた（または元から無い）なら `true`。
fn remove_container_cgroup(dir: &Path) -> bool {
    if wait_until(CGROUP_GC_GRACE, || path_gone(dir)) {
        return true;
    }
    if !kill_and_drain(dir) {
        return false;
    }
    let _ = std::fs::remove_dir(dir);
    path_gone(dir)
}

/// `base` 配下（深さ `depth` まで）から名前が `name` のディレクトリを探す。
/// `Ok(None)` は存在しないと確かめられた場合だけ。読み取り失敗（権限等）は `Err` で確認不能を表す（REPAIR-5）。
fn find_dir(base: &Path, name: &str, depth: u32) -> Result<Option<PathBuf>, std::io::Error> {
    let direct = base.join(name);
    match std::fs::metadata(&direct) {
        Ok(m) if m.is_dir() => return Ok(Some(direct)),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if depth == 0 {
        return Ok(None);
    }
    let entries = match std::fs::read_dir(base) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) if is_gone(&e) => continue,
            Err(e) => return Err(e),
        };
        match entry.file_type() {
            Ok(t) if t.is_dir() => {
                if let Some(found) = find_dir(&entry.path(), name, depth - 1)? {
                    return Ok(Some(found));
                }
            }
            Ok(_) => {}
            Err(e) if is_gone(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// 試行ごとの systemd スコープの名前（`--unit` に渡す。実行ごとに一意な ID から作る）。
fn scope_unit(id_str: &str) -> String {
    format!("fcsl-scope-{id_str}")
}

/// 試行後の状態の照合結果。
struct Settled {
    /// 状態・cgroup・プローブが期待どおりで、状態ルートを消せた。
    ok: bool,
    /// 記録されたワークロードの終了コード（`Stopped` のとき成功判定に使う。未記録なら `None`）。
    workload_exit: Option<i32>,
}

/// supervisor を起動して待っているプロセス（実機では `systemd-run` の子）。
trait Waiter {
    /// 終了を期限つきで待つ。超過したら kill して回収を待つ（REPAIR-5）。
    fn wait_exit(&mut self, timeout: Duration) -> ExitWait;
    /// スコープ内に残る全プロセスを止めて空になったことを確かめる。空（または元から無い）なら `true`。
    fn stop_scope(&mut self) -> bool;
}

/// 起動できた supervisor。
struct Launched {
    rx: Receiver<(Vec<u8>, Instant)>,
    waiter: Box<dyn Waiter>,
}

/// 起動に失敗した（スコープに何も残っていないと確かめられたか）。
struct SpawnFailed {
    clean: bool,
}

/// create に成功した試行の情報。
struct Created<H> {
    id_str: String,
    root: PathBuf,
    t0: Instant,
    create_elapsed: Duration,
    handle: H,
}

enum CreateOutcome<H> {
    Created(Created<H>),
    /// create に失敗した（`leftover`: 状態ルートを消せなかった）。
    Failed {
        id_str: String,
        leftover: bool,
    },
}

/// 試行の実機依存部分（create・supervisor の起動・後始末の検証）。結合試験では差し替える（REPAIR-12）。
trait Host {
    type Handle;
    fn create(
        &self,
        ctx: &Ctx<'_>,
        n: u32,
    ) -> Result<CreateOutcome<Self::Handle>, StartupLatencyError>;
    fn spawn(
        &self,
        ctx: &Ctx<'_>,
        created: &Created<Self::Handle>,
    ) -> Result<Launched, SpawnFailed>;
    fn settle(&self, ctx: &Ctx<'_>, created: &Created<Self::Handle>, expect: Expect) -> Settled;
}

/// 実機の `Host`。
struct RealHost {
    euid: u32,
}

struct RealHandle {
    store: Arc<dyn StateStore>,
    id: ContainerId,
}

struct RealWaiter {
    child: Child,
    euid: u32,
    unit: String,
}

impl RealWaiter {
    /// ユーザーマネージャ配下のスコープ（`<unit>.scope`）の cgroup を探す。
    fn scope_dir(&self) -> Result<Option<PathBuf>, std::io::Error> {
        let base = PathBuf::from(format!(
            "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service",
            uid = self.euid
        ));
        find_dir(&base, &format!("{}.scope", self.unit), 3)
    }
}

impl Waiter for RealWaiter {
    fn wait_exit(&mut self, timeout: Duration) -> ExitWait {
        wait_for_exit(&mut self.child, timeout)
    }

    /// waiter（`systemd-run`）だけでなくスコープ内の supervisor・子孫も `cgroup.kill` で止める。
    fn stop_scope(&mut self) -> bool {
        match self.scope_dir() {
            Ok(Some(dir)) => kill_and_drain(&dir),
            Ok(None) => true,
            // スコープの有無を確認できない場合は後始末の成功と扱わない（fail-closed）。
            Err(_) => false,
        }
    }
}

impl Host for RealHost {
    type Handle = RealHandle;

    fn create(
        &self,
        ctx: &Ctx<'_>,
        n: u32,
    ) -> Result<CreateOutcome<RealHandle>, StartupLatencyError> {
        let id_str = format!("fcsl{}t{n}", std::process::id());
        let root = ctx.work.join(format!("state-{n}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .map_err(|e| io_err("create state root", &e))?;
        let store = open_default_store(Some(root.clone()))
            .map_err(|_| StartupLatencyError::new("io-error", "open the state store failed"))?;
        let id = ContainerId::new(id_str.clone())
            .map_err(|_| StartupLatencyError::new("invalid-args", "container id is invalid"))?;
        let req = CreateRequest::new(id.clone(), ctx.bundle.to_path_buf())
            .map_err(|_| StartupLatencyError::new("invalid-args", "create request is invalid"))?;
        // 計測区間の始点: create を呼ぶ直前。
        let t0 = Instant::now();
        let created = create(store.as_ref(), &OpRecorder::new(), &req);
        let create_elapsed = t0.elapsed();
        if created.is_err() {
            let leftover = std::fs::remove_dir_all(&root).is_err();
            return Ok(CreateOutcome::Failed { id_str, leftover });
        }
        Ok(CreateOutcome::Created(Created {
            id_str,
            root,
            t0,
            create_elapsed,
            handle: RealHandle { store, id },
        }))
    }

    fn spawn(&self, ctx: &Ctx<'_>, created: &Created<RealHandle>) -> Result<Launched, SpawnFailed> {
        let unit = scope_unit(&created.id_str);
        let mut child = Command::new(&ctx.plan.systemd_run)
            .args(["--user", "--scope", "--quiet", "-p", "Delegate=yes"])
            .arg(format!("--unit={unit}"))
            .arg("--")
            .arg(&ctx.plan.supervisor_bin)
            .arg("start")
            .arg("--root")
            .arg(&created.root)
            .arg(&created.id_str)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .process_group(0)
            .spawn()
            // 起動できていないので、残るのは Created の状態だけ（settle が検証する）。
            .map_err(|_| SpawnFailed { clean: true })?;
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let mut waiter = RealWaiter {
                child,
                euid: self.euid,
                unit,
            };
            let reaped = matches!(
                waiter.wait_exit(Duration::from_millis(1)),
                ExitWait::Exited(_) | ExitWait::TimedOut { reaped: true }
            );
            let stopped = waiter.stop_scope();
            return Err(SpawnFailed {
                clean: reaped && stopped,
            });
        };
        Ok(Launched {
            rx: spawn_report_reader(stdout),
            waiter: Box::new(RealWaiter {
                child,
                euid: self.euid,
                unit,
            }),
        })
    }

    /// 試行後の状態・cgroup・プローブを検証し、全部満たしたときだけ状態ルートを消す。
    fn settle(&self, ctx: &Ctx<'_>, created: &Created<RealHandle>, expect: Expect) -> Settled {
        let RealHandle { store, id } = &created.handle;
        let Ok(record) = store.get(&GetStateRequest::new(id.clone())) else {
            return Settled {
                ok: false,
                workload_exit: None,
            };
        };
        let workload_exit = record.status().exit_code();
        let state_ok = match expect {
            Expect::Stopped => record.status().state() == ContainerState::Stopped,
            Expect::Created => {
                record.status().state() == ContainerState::Created
                    && record.status().pid().is_none()
            }
            Expect::Any => true,
        };
        let mut ok = state_ok;
        if let Some(placement) = record.cgroup() {
            match CgroupName::for_instance(id, placement.instance()) {
                Ok(name) => {
                    let scope = placement.scope().as_str().trim_start_matches('/');
                    let dir = Path::new("/sys/fs/cgroup").join(scope).join(name.as_str());
                    ok &= remove_container_cgroup(&dir);
                }
                Err(_) => ok = false,
            }
        }
        let probes_gone = wait_until(ctx.cap(CLEANUP_TIMEOUT), || {
            probe_count(ctx.nonce) == Some(0)
        });
        ok &= probes_gone;
        if ok {
            ok = std::fs::remove_dir_all(&created.root).is_ok();
        }
        Settled { ok, workload_exit }
    }
}

fn run_trial<H: Host>(
    host: &H,
    ctx: &Ctx<'_>,
    n: u32,
) -> Result<(Trial, String), StartupLatencyError> {
    let created = match host.create(ctx, n)? {
        CreateOutcome::Created(c) => c,
        CreateOutcome::Failed { id_str, leftover } => {
            return Ok((
                Trial {
                    sample: None,
                    fails: vec![Fail::Create],
                    leftover,
                },
                id_str,
            ));
        }
    };
    let id_str = created.id_str.clone();
    let mut fails = Vec::new();
    let Launched { rx, mut waiter } = match host.spawn(ctx, &created) {
        Ok(l) => l,
        Err(SpawnFailed { clean }) => {
            fails.push(Fail::Spawn);
            let leftover = !(clean && host.settle(ctx, &created, Expect::Created).ok);
            return Ok((
                Trial {
                    sample: None,
                    fails,
                    leftover,
                },
                id_str,
            ));
        }
    };
    let outcome = classify(rx.recv_timeout(ctx.cap(ctx.report_timeout)));

    let mut sample = None;
    let (expect_exit, expect_state) = match outcome {
        ReportOutcome::Started { at, .. } => {
            sample = Some(Sample {
                total: at.duration_since(created.t0),
                create: created.create_elapsed,
            });
            (Some(0), Expect::Stopped)
        }
        ReportOutcome::Failed { code, exit_code } => {
            fails.push(Fail::ReportErr(code));
            (Some(i32::from(exit_code)), Expect::Created)
        }
        ReportOutcome::Timeout => {
            fails.push(Fail::ReportTimeout);
            (None, Expect::Any)
        }
        ReportOutcome::Eof => {
            fails.push(Fail::ReportEof);
            (None, Expect::Any)
        }
        ReportOutcome::Invalid => {
            fails.push(Fail::ReportInvalid);
            (None, Expect::Any)
        }
    };
    let mut reaped = true;
    match waiter.wait_exit(ctx.cap(EXIT_TIMEOUT)) {
        ExitWait::Exited(code) => {
            if let Some(expected) = expect_exit
                && code != Some(expected)
            {
                fails.push(Fail::SupervisorExit);
            }
        }
        ExitWait::TimedOut { reaped: r } => {
            fails.push(Fail::SupervisorExit);
            reaped = r;
        }
    }
    // waiter だけでなくスコープ内の supervisor も止めて空を確かめる。残っていれば後始末失敗（以後の試行を止める）。
    let scope_clean = waiter.stop_scope();
    let mut settled_ok = false;
    if reaped && scope_clean {
        let settled = host.settle(ctx, &created, expect_state);
        settled_ok = settled.ok;
        // 起動報告のあとに exec や動的ローダが失敗した標本を有効にしない（終了コード 0 を要求。計測の終点は変えない）。
        if expect_state == Expect::Stopped && settled.workload_exit != Some(0) {
            fails.push(Fail::SupervisorExit);
        }
    }
    if !fails.is_empty() || !settled_ok {
        sample = None;
    }
    Ok((
        Trial {
            sample,
            fails,
            leftover: !settled_ok,
        },
        id_str,
    ))
}
fn tally(failures: &mut Failures, fails: &[Fail], leftover: bool) {
    for f in fails {
        match f {
            Fail::Create => failures.create += 1,
            Fail::Spawn => failures.spawn += 1,
            Fail::ReportErr(code) => {
                failures.report_err += 1;
                *failures.report_err_codes.entry(code).or_insert(0) += 1;
            }
            Fail::ReportTimeout => failures.report_timeout += 1,
            Fail::ReportEof => failures.report_eof += 1,
            Fail::ReportInvalid => failures.report_invalid += 1,
            Fail::SupervisorExit => failures.supervisor_exit += 1,
        }
    }
    if leftover {
        failures.cleanup += 1;
    }
}

fn deadline_exceeded() -> StartupLatencyError {
    StartupLatencyError::new(
        "deadline-exceeded",
        "the overall deadline passed before all trials finished",
    )
}

/// 試行を直列に回して結果を集める。残りが出たら以後の試行は行わない。
///
/// 全体の期限は各試行の前に加えて、各試行の後始末まで終えた直後にも照合する。超過した実行は成功結果と metric を
/// 公開せず `deadline-exceeded` で失敗する（REPAIR-5）。後始末の残りがあるときはそちらの失敗を優先して返す。
fn run_trials<H: Host>(host: &H, ctx: &Ctx<'_>) -> Result<RunResult, StartupLatencyError> {
    let mut samples = Vec::new();
    let mut failures = Failures::default();
    let mut leftover_ids = Vec::new();
    let total = ctx.plan.warmup.saturating_add(ctx.plan.trials);
    for n in 0..total {
        if Instant::now() >= ctx.deadline {
            return Err(deadline_exceeded());
        }
        let (trial, id) = run_trial(host, ctx, n)?;
        tally(&mut failures, &trial.fails, trial.leftover);
        if n >= ctx.plan.warmup
            && let Some(s) = trial.sample
        {
            samples.push(s);
        }
        if trial.leftover {
            leftover_ids.push(id);
            break;
        }
        if Instant::now() > ctx.deadline {
            return Err(deadline_exceeded());
        }
    }
    let timeouts = StartTimeouts::default();
    Ok(RunResult {
        params: Params {
            trials: ctx.plan.trials,
            warmup: ctx.plan.warmup,
            timeout_secs: ctx.plan.timeout_secs,
            report_timeout_ms: u64::try_from(cli_receive_deadline(&timeouts).as_millis())
                .unwrap_or(u64::MAX),
            exit_timeout_ms: u64::try_from(EXIT_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
            cleanup_timeout_ms: u64::try_from(CLEANUP_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
        },
        samples,
        failures,
        leftover_ids,
        arch: std::env::consts::ARCH,
    })
}

/// 計測を実行する。入口（`startup_latency::execute`）から呼ばれる。
pub fn run(mut plan: Plan) -> Result<super::Execution, StartupLatencyError> {
    let euid = effective_uid().ok_or_else(|| {
        StartupLatencyError::new(
            "unsupported-environment",
            "cannot determine the effective uid",
        )
    })?;
    if euid == 0 {
        // rootful の起動は supervisor が拒否する（SEC-5）。
        return Err(StartupLatencyError::new(
            "unsupported-environment",
            "must run as a non-root user",
        ));
    }
    // 検証済みの実体パスで置き換え、起動には字面のパスを使わない（symlink 解決途中の差し替え対策）。
    plan.supervisor_bin = verify_executable(&plan.supervisor_bin, euid)?;
    plan.systemd_run = verify_executable(&plan.systemd_run, euid)?;

    // 作業ディレクトリの親は全祖先の所有者・書き込み権限を検証し、実体パスだけを使う。
    let base: PathBuf = verify_work_base(
        &match &plan.work_dir {
            Some(d) => d.clone(),
            None => std::env::temp_dir(),
        },
        euid,
    )?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let dir_name = format!("fandhe-startup-latency-{pid}-{nanos}");
    let work = base.join(&dir_name);
    // 排他作成（既存なら失敗）。0700 で他ユーザーから隔離する。
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&work)
        .map_err(|e| io_err("create work dir", &e))?;

    let nonce = format!("{pid:x}{nanos:x}");
    let result = build_bundle(&work, &nonce).and_then(|bundle| {
        let ctx = Ctx {
            plan: &plan,
            work: &work,
            bundle: &bundle,
            nonce: &nonce,
            deadline: Instant::now() + Duration::from_secs(plan.timeout_secs),
            report_timeout: cli_receive_deadline(&StartTimeouts::default()),
        };
        run_trials(&RealHost { euid }, &ctx)
    });
    let keep = matches!(&result, Ok(r) if !r.leftover_ids.is_empty());
    if keep {
        // 調査用に残す。相対名だけを出す（絶対パスを出さない）。
        eprintln!("startup_latency: leftover resources; work dir kept as {dir_name}");
    } else {
        let _ = std::fs::remove_dir_all(&work);
    }
    let result = result?;
    let json = render_json(&result)?;
    Ok(super::Execution::Done {
        clean: result.is_clean(),
        json,
        output: plan.output,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Mutex;
    use std::sync::mpsc;

    /// 1 試行ぶんの筋書き（実機依存部分の応答）。
    #[derive(Clone)]
    struct Script {
        /// 結果 1 行。`None` は届かない（送信側を握ったまま）。
        report: Option<&'static [u8]>,
        exit: ExitScript,
        stop_ok: bool,
        settle_ok: bool,
        workload_exit: Option<i32>,
        /// 後始末で待つ時間（期限超過の再現用）。
        settle_delay: Duration,
    }

    #[derive(Clone, Copy)]
    enum ExitScript {
        Exited(i32),
        TimedOut,
    }

    impl Script {
        fn ok() -> Self {
            Self {
                report: Some(b"FCSUP1 OK 4242\n"),
                exit: ExitScript::Exited(0),
                stop_ok: true,
                settle_ok: true,
                workload_exit: Some(0),
                settle_delay: Duration::ZERO,
            }
        }
    }

    struct FakeWaiter {
        script: Script,
        _keep: Option<mpsc::Sender<(Vec<u8>, Instant)>>,
    }

    impl Waiter for FakeWaiter {
        fn wait_exit(&mut self, _timeout: Duration) -> ExitWait {
            match self.script.exit {
                ExitScript::Exited(c) => ExitWait::Exited(Some(c)),
                ExitScript::TimedOut => ExitWait::TimedOut { reaped: true },
            }
        }

        fn stop_scope(&mut self) -> bool {
            self.script.stop_ok
        }
    }

    struct FakeHost {
        scripts: Vec<Script>,
        created: Mutex<Vec<u32>>,
        settled: Mutex<Vec<Expect>>,
    }

    impl FakeHost {
        fn new(scripts: Vec<Script>) -> Self {
            Self {
                scripts,
                created: Mutex::new(Vec::new()),
                settled: Mutex::new(Vec::new()),
            }
        }

        fn script(&self, created: &Created<usize>) -> Script {
            self.scripts
                .get(created.handle)
                .cloned()
                .expect("script for the trial")
        }
    }

    impl Host for FakeHost {
        type Handle = usize;

        fn create(
            &self,
            _ctx: &Ctx<'_>,
            n: u32,
        ) -> Result<CreateOutcome<usize>, StartupLatencyError> {
            self.created.lock().expect("lock").push(n);
            Ok(CreateOutcome::Created(Created {
                id_str: format!("fake{n}"),
                root: PathBuf::from("/nonexistent"),
                t0: Instant::now(),
                create_elapsed: Duration::from_micros(100),
                handle: usize::try_from(n).expect("index"),
            }))
        }

        fn spawn(&self, _ctx: &Ctx<'_>, created: &Created<usize>) -> Result<Launched, SpawnFailed> {
            let script = self.script(created);
            std::thread::sleep(Duration::from_millis(1));
            let (rx, keep) = match script.report {
                Some(bytes) => (spawn_report_reader(Cursor::new(bytes.to_vec())), None),
                None => {
                    let (tx, rx) = mpsc::channel();
                    (rx, Some(tx))
                }
            };
            Ok(Launched {
                rx,
                waiter: Box::new(FakeWaiter {
                    script,
                    _keep: keep,
                }),
            })
        }

        fn settle(&self, _ctx: &Ctx<'_>, created: &Created<usize>, expect: Expect) -> Settled {
            let script = self.script(created);
            self.settled.lock().expect("lock").push(expect);
            std::thread::sleep(script.settle_delay);
            Settled {
                ok: script.settle_ok,
                workload_exit: script.workload_exit,
            }
        }
    }

    fn plan(trials: u32, warmup: u32) -> Plan {
        Plan {
            trials,
            warmup,
            timeout_secs: 60,
            supervisor_bin: PathBuf::from("/nonexistent/supervisor"),
            systemd_run: PathBuf::from("/nonexistent/systemd-run"),
            work_dir: None,
            output: None,
        }
    }

    fn run_with(
        scripts: Vec<Script>,
        trials: u32,
        warmup: u32,
        deadline: Duration,
    ) -> (FakeHost, Result<RunResult, StartupLatencyError>) {
        let host = FakeHost::new(scripts);
        let p = plan(trials, warmup);
        let ctx = Ctx {
            plan: &p,
            work: Path::new("/nonexistent"),
            bundle: Path::new("/nonexistent"),
            nonce: "n",
            deadline: Instant::now() + deadline,
            report_timeout: Duration::from_millis(50),
        };
        let r = run_trials(&host, &ctx);
        (host, r)
    }

    /// 正常終了: 標本は計測回数ぶん・失敗 0・metric が出る（REPAIR-12・CORE-10）。
    #[test]
    fn normal_trials_collect_samples_and_emit_the_metric() {
        let (host, r) = run_with(vec![Script::ok(); 3], 2, 1, Duration::from_secs(30));
        let r = r.expect("run");
        assert_eq!(r.samples.len(), 2);
        assert_eq!(r.failures.total(), 0);
        assert!(r.leftover_ids.is_empty());
        assert!(r.is_clean());
        assert_eq!(*host.created.lock().expect("lock"), vec![0, 1, 2]);
        assert_eq!(
            *host.settled.lock().expect("lock"),
            vec![Expect::Stopped; 3]
        );
        let json = render_json(&r).expect("render");
        assert!(
            json.contains("\"startup_create_to_supervisor_ok_p95_ms\""),
            "{json}"
        );
    }

    /// 報告期限切れ: 失敗として数え、標本を採らず、metric を空にする。後始末が済めば試行は続く。
    #[test]
    fn report_timeout_is_counted_and_empties_metrics() {
        let mut timeout = Script::ok();
        timeout.report = None;
        timeout.exit = ExitScript::TimedOut;
        let (host, r) = run_with(vec![timeout, Script::ok()], 2, 0, Duration::from_secs(30));
        let r = r.expect("run");
        assert_eq!(r.failures.report_timeout, 1);
        assert_eq!(r.failures.supervisor_exit, 1);
        assert_eq!(r.samples.len(), 1);
        assert!(!r.is_clean());
        assert_eq!(
            *host.settled.lock().expect("lock"),
            vec![Expect::Any, Expect::Stopped]
        );
        assert!(render_json(&r).expect("render").contains("\"metrics\":{},"));
    }

    /// ワークロードの非ゼロ終了: 起動報告が OK でも失敗として数え、標本を採らず metric を空にする。
    #[test]
    fn nonzero_workload_exit_is_a_failure() {
        let mut bad = Script::ok();
        bad.workload_exit = Some(127);
        let mut unrecorded = Script::ok();
        unrecorded.workload_exit = None;
        let (_, r) = run_with(vec![bad, unrecorded], 2, 0, Duration::from_secs(30));
        let r = r.expect("run");
        assert_eq!(r.failures.supervisor_exit, 2);
        assert!(r.samples.is_empty());
        assert!(!r.is_clean());
        assert!(render_json(&r).expect("render").contains("\"metrics\":{},"));
    }

    /// 後始末の失敗: 以後の試行を止め、ID を残りに積み、metric を出さない。
    #[test]
    fn settle_failure_stops_trials_and_suppresses_metrics() {
        let mut broken = Script::ok();
        broken.settle_ok = false;
        let (host, r) = run_with(
            vec![Script::ok(), broken, Script::ok(), Script::ok()],
            4,
            0,
            Duration::from_secs(30),
        );
        let r = r.expect("run");
        assert_eq!(r.leftover_ids, vec!["fake1".to_string()]);
        assert_eq!(r.failures.cleanup, 1);
        assert_eq!(*host.created.lock().expect("lock"), vec![0, 1]);
        assert!(!r.is_clean());
        assert!(render_json(&r).expect("render").contains("\"metrics\":{},"));
    }

    /// スコープに supervisor が残る（止められない）: 後始末失敗として打ち切り、状態を消す settle には進まない。
    #[test]
    fn residual_scope_is_a_cleanup_failure() {
        let mut stuck = Script::ok();
        stuck.stop_ok = false;
        let (host, r) = run_with(vec![stuck, Script::ok()], 2, 0, Duration::from_secs(30));
        let r = r.expect("run");
        assert_eq!(r.leftover_ids, vec!["fake0".to_string()]);
        assert_eq!(r.failures.cleanup, 1);
        assert_eq!(*host.created.lock().expect("lock"), vec![0]);
        assert!(host.settled.lock().expect("lock").is_empty());
        assert!(r.samples.is_empty());
    }

    /// 全体期限: 最終試行が期限を超えて終わったら成功結果を返さない（REPAIR-5）。
    #[test]
    fn overrunning_the_deadline_in_the_last_trial_fails() {
        let mut slow = Script::ok();
        slow.settle_delay = Duration::from_millis(200);
        let (host, r) = run_with(vec![slow], 1, 0, Duration::from_millis(100));
        assert_eq!(r.expect_err("must fail").code, "deadline-exceeded");
        assert_eq!(*host.settled.lock().expect("lock"), vec![Expect::Stopped]);
    }
}
/// 実際の子プロセスとファイルシステムに対する期限・回収・後始末判定の試験（REPAIR-5・REPAIR-12・CORE-10）。
/// `Host` のスタブ越しではなく、`wait_for_exit`・`probe_count`・`read_populated`・`kill_and_drain` を直接呼ぶ。
/// root・実 cgroup・systemd は使わず、スタブの子プロセス（`sh`）と一時ディレクトリの擬似 `cgroup.events` で照合する。
/// 実 cgroup を要する通し確認は実機前提（AGENTS.md の `startup_latency` 節。CI では走らない）。
#[cfg(test)]
mod real_process_tests {
    use super::*;

    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let p =
                std::env::temp_dir().join(format!("fc-sl-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir(&p).expect("mkdir");
            Self(p)
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sh(script: &str, extra: &[&str]) -> Child {
        Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh")
    }

    /// `sleep 30` を直接起動する（シェルを挟まないため、kill が孫を孤児にしない）。`arg0` を指定すると
    /// cmdline の先頭にその値が載る（nonce の走査の試験用）。
    fn sleeper(arg0: Option<&str>) -> Child {
        let mut cmd = Command::new("sleep");
        cmd.arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(a) = arg0 {
            cmd.arg0(a);
        }
        cmd.spawn().expect("spawn sleep")
    }

    #[test]
    fn child_exit_code_is_reported_before_the_deadline() {
        let mut child = sh("exit 3", &[]);
        match wait_for_exit(&mut child, Duration::from_secs(10)) {
            ExitWait::Exited(code) => assert_eq!(code, Some(3)),
            ExitWait::TimedOut { .. } => panic!("must not time out"),
        }
    }

    #[test]
    fn overdue_child_is_killed_and_reaped() {
        let mut child = sleeper(None);
        let started = Instant::now();
        match wait_for_exit(&mut child, Duration::from_millis(150)) {
            ExitWait::TimedOut { reaped } => assert!(reaped, "killed child must be reaped"),
            ExitWait::Exited(_) => panic!("must time out"),
        }
        assert!(started.elapsed() < Duration::from_secs(10));
        // 回収済みなら再度 try_wait しても終了状態が返る。
        assert!(matches!(child.try_wait(), Ok(Some(_))));
    }

    #[test]
    fn probe_count_sees_a_live_probe_and_not_a_reaped_one() {
        let nonce = format!(
            "fc-sl-nonce-{}-{}",
            std::process::id(),
            Tmp::new("n").0.display()
        );
        // nonce を arg0 に載せた sleep を直接起動する（シェル経由だと kill がシェルだけを終わらせ、孫の sleep が残る）。
        let mut child = sleeper(Some(&nonce));
        assert!(wait_until(Duration::from_secs(5), || probe_count(&nonce) == Some(1)));
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(probe_count(&nonce), Some(0));
    }

    #[test]
    fn populated_flag_is_read_from_cgroup_events() {
        let t = Tmp::new("pop");
        std::fs::write(t.0.join("cgroup.events"), "populated 1\nfrozen 0\n").expect("write");
        assert_eq!(read_populated(&t.0), Some(true));
        std::fs::write(t.0.join("cgroup.events"), "populated 0\nfrozen 0\n").expect("write");
        assert_eq!(read_populated(&t.0), Some(false));
        std::fs::write(t.0.join("cgroup.events"), "garbage\n").expect("write");
        assert_eq!(read_populated(&t.0), None);
    }

    /// 読めない（ファイルが無いがディレクトリは在る）状態は空と扱わず、後始末失敗になる。
    #[test]
    fn unreadable_cgroup_is_a_cleanup_failure_not_empty() {
        let t = Tmp::new("unr");
        assert_eq!(read_populated(&t.0), None);
        assert!(!kill_and_drain(&t.0));
    }

    #[test]
    fn already_empty_cgroup_drains_without_kill_and_vanished_one_is_gone() {
        let t = Tmp::new("emp");
        std::fs::write(t.0.join("cgroup.events"), "populated 0\n").expect("write");
        assert!(kill_and_drain(&t.0));
        // 空なら cgroup.kill は書かれない。
        assert!(!t.0.join("cgroup.kill").exists());
        let gone = t.0.join("absent");
        assert_eq!(read_populated(&gone), Some(false));
        assert!(path_gone(&gone));
        assert!(remove_container_cgroup(&gone));
        assert_eq!(find_dir(&t.0, "absent", 2).expect("find"), None);
    }

    /// 在籍ありなら `cgroup.kill` へ "1" を書き、空になったら成功する。
    #[test]
    fn populated_cgroup_gets_a_kill_request_then_drains() {
        let t = Tmp::new("kill");
        std::fs::write(t.0.join("cgroup.events"), "populated 1\n").expect("write");
        let dir = t.0.clone();
        let h = std::thread::spawn(move || {
            wait_until(Duration::from_secs(5), || dir.join("cgroup.kill").exists());
            std::fs::write(dir.join("cgroup.events"), "populated 0\n").expect("write");
        });
        assert!(kill_and_drain(&t.0));
        h.join().expect("join");
        assert_eq!(
            std::fs::read_to_string(t.0.join("cgroup.kill")).expect("read"),
            "1"
        );
    }
}
