//! scope 取得だけを測る診断モード（`--scope-only`。TASK-190 追補・#2124・CORE-10・REPAIR-8）。
//!
//! 起動 p95 の本計測は、systemd の transient scope 取得（`systemd-run --user --scope` の D-Bus の往復）の費用を含む
//! （#2089）。p95 が悪化したとき、製品側（core の create・supervisor・ランチャー）の回帰か、systemd・D-Bus の揺れかを
//! 切り分けるため、本計測と同じ包み込み（`scope_wrap::scoped_noop_command`）で自明なコマンド
//! （自分自身の `--startup-latency-noop`）だけを起動し、`systemd-run` の起動から終了を回収するまでを測る。
//!
//! # 位置づけ（REPAIR-3）
//! - 診断であって metric ではない。結果 JSON の `metrics` は常に空で、`bench-check-manual`・`bench-baseline-manual` の
//!   入力にならない（metric の集合が一致せず 2 で拒否される）。統計は `summary`（p50・p95・max）に入れる
//! - 本計測の p95 と並べて読む。両方悪化なら systemd・D-Bus の揺れ、本計測だけ悪化なら製品側の回帰
//! - 前処理・後始末は本計測（`measure::run`）と同じ規律（root 拒否・中断シグナルのブロック・出力先と実行ファイルの検証・
//!   scope の cgroup の消滅確認・全体の期限）に従う。実機前提（Linux・非 root・`systemd-run --user`）で CI では実行しない

use super::StartupLatencyError;
use super::args::ScopePlan;
use super::bin_check::{verify_executable, verify_output_target};
use super::measure::{
    CGROUP_GC_GRACE, CLEANUP_TIMEOUT, ExitWait, block_error, deadline_exceeded, find_dir,
    interrupted, interrupted_error, kill_and_drain, wait_for_exit, wait_until,
};
use super::output::ms;
use super::probe_env::{detect_host_kind, effective_uid};
use super::scope_wrap::{scoped_noop_command, user_manager_env};
use super::stats::summarize;
use crate::sys;
use std::fmt::Write as _;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

const METHOD: &str = "scope-only/systemd-run-user-scope/noop";
/// 1 試行で子（`systemd-run` と noop）の終了を待つ上限。自明なコマンドなので本計測の `EXIT_TIMEOUT` より短い。
const TRIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// 1 回の起動の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OneRun {
    /// `systemd-run` を起動できなかった。
    SpawnFailed,
    /// 終了した（終了コード。シグナル死は `None`）。
    Exited(Option<i32>),
    /// 期限切れ（kill して回収できたか）。
    TimedOut { reaped: bool },
}

/// 実機依存部分（起動と後始末の確認）。筋書きの試験では差し替える（REPAIR-12）。
trait ScopeHost {
    fn run_one(&self, unit: &str, timeout: Duration) -> OneRun;
    /// scope の cgroup が消えている（または落として消えた）なら `true`。確認できなければ `false`（fail-closed）。
    fn settle(&self, unit: &str) -> bool;
}

/// 失敗の内訳。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Failures {
    spawn: u32,
    exit: u32,
    timeout: u32,
    cleanup: u32,
}

impl Failures {
    fn total(&self) -> u32 {
        self.spawn
            .saturating_add(self.exit)
            .saturating_add(self.timeout)
            .saturating_add(self.cleanup)
    }
}

/// 診断の結果。
#[derive(Debug)]
struct Outcome {
    trials: u32,
    warmup: u32,
    timeout_secs: u64,
    samples: Vec<Duration>,
    failures: Failures,
    leftover_ids: Vec<String>,
}

impl Outcome {
    fn is_clean(&self) -> bool {
        self.failures.total() == 0 && self.leftover_ids.is_empty()
    }
}

/// 試行を直列に回す。残りが出たら以後の試行は行わない。全体の期限・中断の扱いは本計測と同じ（REPAIR-5）。
fn run_trials<H: ScopeHost>(
    host: &H,
    plan: &ScopePlan,
    nonce: &str,
    deadline: Instant,
) -> Result<Outcome, StartupLatencyError> {
    let mut samples = Vec::new();
    let mut failures = Failures::default();
    let mut leftover_ids = Vec::new();
    let total = plan.warmup.saturating_add(plan.trials);
    for n in 0..total {
        if interrupted() {
            return Err(interrupted_error());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(deadline_exceeded());
        }
        let unit = format!("fcsl{nonce}s{n}");
        // 残り時間で待ちを切り詰める（最低 1 秒は残して後始末の判定を可能にする）。
        let timeout = TRIAL_TIMEOUT.min(
            deadline
                .saturating_duration_since(now)
                .max(Duration::from_secs(1)),
        );
        let t0 = Instant::now();
        let run = host.run_one(&unit, timeout);
        let elapsed = t0.elapsed();
        // 起動できなかった場合も scope が残っていないことを確かめる。
        let settled = host.settle(&unit);
        let mut stop = !settled;
        match run {
            OneRun::SpawnFailed => failures.spawn += 1,
            OneRun::Exited(Some(0)) => {
                if n >= plan.warmup {
                    samples.push(elapsed);
                }
            }
            OneRun::Exited(_) => failures.exit += 1,
            OneRun::TimedOut { reaped } => {
                failures.timeout += 1;
                stop |= !reaped;
            }
        }
        if !settled {
            failures.cleanup += 1;
        }
        if interrupted() {
            return Err(interrupted_error());
        }
        if stop {
            leftover_ids.push(unit);
            break;
        }
        if Instant::now() > deadline {
            return Err(deadline_exceeded());
        }
    }
    Ok(Outcome {
        trials: plan.trials,
        warmup: plan.warmup,
        timeout_secs: plan.timeout_secs,
        samples,
        failures,
        leftover_ids,
    })
}

/// 結果 JSON を組み立てる。`metrics` は常に空（回帰ゲート・基準値の入力にしない）。
fn render(o: &Outcome, arch: &str, host_kind: &str) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "{{\"schema_version\":1,\"kind\":\"diagnostic\",\"metrics\":{{}},\"method\":\"{METHOD}\",\"aggregate\":\"p95-nearest-rank\",\
\"params\":{{\"trials\":{},\"warmup\":{},\"timeout_secs\":{},\"trial_timeout_ms\":{}}},",
        o.trials,
        o.warmup,
        o.timeout_secs,
        TRIAL_TIMEOUT.as_millis()
    );
    match summarize(&o.samples) {
        Some(s) => {
            let _ = write!(
                out,
                "\"summary\":{{\"samples\":{},\"p50_ms\":{},\"p95_ms\":{},\"max_ms\":{}}},",
                s.samples,
                ms(s.p50),
                ms(s.p95),
                ms(s.max)
            );
        }
        None => out.push_str("\"summary\":null,"),
    }
    out.push_str("\"trials\":[");
    for (i, d) in o.samples.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{{\"total_ms\":{}}}", ms(*d));
    }
    let f = &o.failures;
    let _ = write!(
        out,
        "],\"failures\":{{\"total\":{},\"spawn\":{},\"exit\":{},\"timeout\":{},\"cleanup\":{}}},\"leftover_ids\":[",
        f.total(),
        f.spawn,
        f.exit,
        f.timeout,
        f.cleanup
    );
    for (i, id) in o.leftover_ids.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{id}\"");
    }
    let _ = writeln!(out, "],\"arch\":\"{arch}\",\"host_kind\":\"{host_kind}\"}}");
    out
}

/// 実機の `ScopeHost`。
struct RealHost {
    euid: u32,
    systemd_run: PathBuf,
    /// 自分自身の実行ファイル（`/proc/self/exe` を検証した実体パス）。scope の中で `--startup-latency-noop` を起動する。
    program: PathBuf,
    xdg_runtime_dir: std::ffi::OsString,
}

impl RealHost {
    /// ユーザーマネージャ配下の scope（`<unit>.scope`）の cgroup を探す（`measure::RealWaiter::scope_dir` と同じ場所）。
    fn scope_dir(&self, unit: &str) -> Result<Option<PathBuf>, std::io::Error> {
        let base = PathBuf::from(format!(
            "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service",
            uid = self.euid
        ));
        find_dir(&base, &format!("{unit}.scope"), 3)
    }
}

impl ScopeHost for RealHost {
    fn run_one(&self, unit: &str, timeout: Duration) -> OneRun {
        let Some(mut cmd) = scoped_noop_command(
            &self.systemd_run,
            unit,
            &self.program,
            &self.xdg_runtime_dir,
        ) else {
            return OneRun::SpawnFailed;
        };
        // 親がブロックした中断シグナルを子へ継承させない。
        sys::unblock_termination_signals_in_child(&mut cmd);
        let Ok(mut child) = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
        else {
            return OneRun::SpawnFailed;
        };
        match wait_for_exit(&mut child, timeout) {
            ExitWait::Exited(code) => OneRun::Exited(code),
            ExitWait::TimedOut { reaped } => OneRun::TimedOut { reaped },
        }
    }

    fn settle(&self, unit: &str) -> bool {
        let gone = |h: &Self| matches!(h.scope_dir(unit), Ok(None));
        // systemd のスコープ GC を短く待ち、残っていれば cgroup.kill で落として消滅を待つ。
        if wait_until(CGROUP_GC_GRACE, || gone(self)) {
            return true;
        }
        match self.scope_dir(unit) {
            Ok(Some(dir)) => kill_and_drain(&dir) && wait_until(CLEANUP_TIMEOUT, || gone(self)),
            Ok(None) => true,
            // scope の有無を確認できない場合は後始末の成功と扱わない（fail-closed）。
            Err(_) => false,
        }
    }
}

/// 診断を実行する。入口（`startup_latency::execute`）から呼ばれる。前処理の順序は `measure::run` と同じ。
pub fn run(mut plan: ScopePlan) -> Result<super::Execution, StartupLatencyError> {
    let euid = effective_uid().ok_or_else(|| {
        StartupLatencyError::new(
            "unsupported-environment",
            "cannot determine the effective uid",
        )
    })?;
    if euid == 0 {
        return Err(StartupLatencyError::new(
            "unsupported-environment",
            "must run as a non-root user",
        ));
    }
    // 中断シグナルをブロックし、各待ち点で保留を確かめる（スレッドを作る前に呼ぶ。REPAIR-5）。
    sys::block_termination_signals().map_err(|e| block_error(&e))?;
    if let Some(out) = &plan.output {
        plan.output = Some(verify_output_target(out, euid)?);
    }
    let systemd_run = verify_executable(&plan.systemd_run, euid)?;
    // 自分自身を scope の中で noop として起動する。字面のパスではなく検証済みの実体パスだけを使う。
    let self_exe = std::fs::read_link("/proc/self/exe").map_err(|_| {
        StartupLatencyError::new("io-error", "cannot resolve the current executable")
    })?;
    let program = verify_executable(&self_exe, euid)?;
    let xdg_runtime_dir = user_manager_env(std::env::var_os("XDG_RUNTIME_DIR").as_deref(), euid)?;

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let nonce = format!("{:x}{nanos:x}", std::process::id());
    let host = RealHost {
        euid,
        systemd_run,
        program,
        xdg_runtime_dir,
    };
    let deadline = Instant::now() + Duration::from_secs(plan.timeout_secs);
    let outcome = run_trials(&host, &plan, &nonce, deadline)?;
    let json = render(&outcome, std::env::consts::ARCH, detect_host_kind());
    Ok(super::Execution::Done {
        clean: outcome.is_clean(),
        json,
        output: plan.output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Script {
        runs: RefCell<Vec<OneRun>>,
        settle: bool,
        units: RefCell<Vec<String>>,
    }

    impl Script {
        fn new(runs: Vec<OneRun>, settle: bool) -> Self {
            Self {
                runs: RefCell::new(runs),
                settle,
                units: RefCell::new(Vec::new()),
            }
        }
    }

    impl ScopeHost for Script {
        fn run_one(&self, unit: &str, _timeout: Duration) -> OneRun {
            self.units.borrow_mut().push(unit.to_string());
            let mut r = self.runs.borrow_mut();
            if r.is_empty() {
                OneRun::Exited(Some(0))
            } else {
                r.remove(0)
            }
        }
        fn settle(&self, _unit: &str) -> bool {
            self.settle
        }
    }

    fn plan(trials: u32, warmup: u32) -> ScopePlan {
        ScopePlan {
            trials,
            warmup,
            timeout_secs: 600,
            systemd_run: PathBuf::from("/usr/bin/systemd-run"),
            output: None,
        }
    }

    fn go(host: &Script, p: &ScopePlan) -> Result<Outcome, StartupLatencyError> {
        run_trials(host, p, "n0", Instant::now() + Duration::from_secs(600))
    }

    /// CORE-10: 正常なら warmup を除いた試行数ぶんの標本が入り、unit 名は nonce と番号を含む。
    #[test]
    fn clean_run_collects_samples_after_warmup() {
        let host = Script::new(vec![], true);
        let o = go(&host, &plan(20, 2)).expect("run");
        assert_eq!(o.samples.len(), 20);
        assert!(o.is_clean());
        assert_eq!(host.units.borrow().len(), 22);
        assert_eq!(host.units.borrow()[0], "fcsln0s0");
        assert_eq!(host.units.borrow()[21], "fcsln0s21");
        let json = render(&o, "x86_64", "vm");
        assert!(json.starts_with(
            "{\"schema_version\":1,\"kind\":\"diagnostic\",\"metrics\":{},\"method\":\"scope-only/systemd-run-user-scope/noop\","
        ));
        assert!(json.contains("\"summary\":{\"samples\":20,"));
        assert!(json.ends_with(
            "\"failures\":{\"total\":0,\"spawn\":0,\"exit\":0,\"timeout\":0,\"cleanup\":0},\"leftover_ids\":[],\"arch\":\"x86_64\",\"host_kind\":\"vm\"}\n"
        ));
    }

    /// REPAIR-8: systemd-run が非 0 で終わる試行は失敗として数え、標本に入れない。metrics は空のまま、clean でない。
    #[test]
    fn non_zero_exit_is_counted_and_metrics_stay_empty() {
        let host = Script::new(vec![OneRun::Exited(Some(1)), OneRun::SpawnFailed], true);
        let o = go(&host, &plan(20, 0)).expect("run");
        assert_eq!(o.samples.len(), 18);
        assert_eq!(
            o.failures,
            Failures {
                spawn: 1,
                exit: 1,
                timeout: 0,
                cleanup: 0
            }
        );
        assert!(!o.is_clean());
        let json = render(&o, "aarch64", "unknown");
        assert!(json.contains("\"metrics\":{},"));
        assert!(json.contains("\"failures\":{\"total\":2,\"spawn\":1,\"exit\":1,"));
    }

    /// REPAIR-5: scope が消えない（確認できない）なら ID を積んで以後の試行を止める。
    #[test]
    fn leftover_scope_stops_the_run() {
        let host = Script::new(vec![], false);
        let o = go(&host, &plan(20, 0)).expect("run");
        assert_eq!(o.leftover_ids, vec!["fcsln0s0".to_string()]);
        assert_eq!(host.units.borrow().len(), 1);
        assert_eq!(o.failures.cleanup, 1);
        assert!(!o.is_clean());
        assert!(render(&o, "x86_64", "vm").contains("\"leftover_ids\":[\"fcsln0s0\"]"));
    }

    /// REPAIR-5: 期限切れの子を回収できなければ止める。回収できたなら続ける。
    #[test]
    fn timed_out_child_counts_and_unreaped_stops() {
        let host = Script::new(vec![OneRun::TimedOut { reaped: true }], true);
        let o = go(&host, &plan(20, 0)).expect("run");
        assert_eq!((o.failures.timeout, o.samples.len()), (1, 19));
        let host = Script::new(vec![OneRun::TimedOut { reaped: false }], true);
        let o = go(&host, &plan(20, 0)).expect("run");
        assert_eq!(o.leftover_ids.len(), 1);
        assert_eq!(host.units.borrow().len(), 1);
    }

    /// REPAIR-5: 全体の期限を過ぎていれば、試行を始めずに deadline-exceeded。
    #[test]
    fn expired_deadline_fails_before_the_first_trial() {
        let host = Script::new(vec![], true);
        let e = run_trials(&host, &plan(20, 0), "n0", Instant::now()).expect_err("expired");
        assert_eq!(e.code, "deadline-exceeded");
        assert!(host.units.borrow().is_empty());
    }
}
