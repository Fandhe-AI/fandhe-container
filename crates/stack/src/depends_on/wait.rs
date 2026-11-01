//! `depends_on` の `started` 条件の待機（STACK-2・TASK-150.2・#590）。
//!
//! `plan_startup`（TASK-150.1）が作った [`StartupStep`] の待ち条件を、観測のポーリングで満たしてから
//! 呼び出し元へ制御を返す。呼び出し元は `up`（TASK-155）の予定で、ステップごとに
//! [`wait_for_step`] が `Ok` を返してから依存元を起動する（待ってから起動する順序の保証はこの契約）。
//!
//! `started` の意味: compose の `service_started` と PoC-17 に合わせ、「起動が試みられたことの確認のみ
//! で liveness は問わない」。観測が [`DependencyObservation::Running`] または
//! [`DependencyObservation::Stopped`]（開始後に終了した）なら満たし、Absent・Creating・Created
//! では満たさずポーリングを続ける。
//!
//! 境界: stack は core に依存しない（`compose-convert -> stack` が確定済みで、core を引き込まないため。
//! `docs/architecture.md`）。状態ストアの読み取りは [`DependencyObserver`] の背後に置き、本番の
//! アダプタ（core の `ContainerState` から [`DependencyObservation`] への写像を含む）は TASK-155 が作る。
//! 本モジュールにアダプタは無い（実装済みを装わない。REPAIR-3）。core の `HealthStatus` を直接使うかは
//! #591（healthy）か TASK-155 で再検討し、そのとき [`DependencyObservation`] を拡張する。
//!
//! 未実装: `healthy`（state.json ポーリング。#591）、healthy 未達のタイムアウト（#592。本モジュールの
//! [`DependencyWaitError::WaitTimeout`] と [`WaitPolicy`] を再利用し、別 variant を足さない）、
//! `completed`。これらの条件は黙って満たしたことにせず [`DependencyWaitError::UnsupportedCondition`] で止める。
//!
//! エラーにはサービス名と条件だけを入れ、`Service`（`env` に資格情報を含みうる）の内容は出さない。
//! 待ちには必ず期限がある（REPAIR-5）。

use std::fmt;
use std::time::{Duration, Instant};

use super::{DependencyWait, StartupStep};
use crate::schema::DependsOnCondition;

/// `WaitPolicy::timeout` の上限（暫定 1 時間）。外部設定の巨大値で実質無期限になるのを防ぐ。
pub const MAX_WAIT_TIMEOUT: Duration = Duration::from_secs(3600);

/// 依存先コンテナの観測結果。
///
/// core の `ContainerState`（Creating / Created / Running / Stopped）に対応する。記録が無い場合は
/// `Absent`。#591 で health を足すため `#[non_exhaustive]`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DependencyObservation {
    /// 記録が無い（まだ create されていない）。
    Absent,
    /// 作成中。
    Creating,
    /// 作成済みで未開始。
    Created,
    /// 稼働中。
    Running,
    /// 開始後に停止した（PoC-17 の exited 相当。`started` は満たす）。
    Stopped,
}

impl DependencyObservation {
    /// `started` 条件を満たすか（compose の `service_started`。Running と Stopped のみ true）。
    pub fn satisfies_started(self) -> bool {
        matches!(self, Self::Running | Self::Stopped)
    }
}

/// 観測の失敗。`message` は固定の英語で、資格情報・環境変数を含めない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserveError {
    code: &'static str,
    message: &'static str,
}

impl ObserveError {
    /// 機械可読なコードと固定メッセージから作る。
    pub fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// 固定の英語メッセージ。
    pub fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for ObserveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ObserveError {}

/// 依存先の状態を読む入口（状態ストアの背後。本番のアダプタは TASK-155）。
///
/// 実装の契約:
/// - (a) `service` は TOML 由来の外部入力。パス要素にする前に実装側で検証する（パストラバーサル防止）。
/// - (b) 今回の up が create したコンテナの観測だけを返し、前回の実行の古い記録を返さない
///   （古い状態で満たしてしまうのを防ぐ。create で得た同一性の照合は実装側の責務）。
/// - (c) ブロックする実装は短い上限を持つ（REPAIR-5）。
pub trait DependencyObserver {
    /// `service` の現在の観測を返す。
    fn observe(&mut self, service: &str) -> Result<DependencyObservation, ObserveError>;
}

/// 時計（supervisor の `HealthcheckClock` と同形。試験では偽物を差し込む）。
pub trait WaitClock {
    /// 現在時刻。
    fn now(&self) -> Instant;
    /// `deadline` まで眠る（過ぎていれば即戻る）。
    fn sleep_until(&mut self, deadline: Instant);
}

/// 実時計。
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl WaitClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep_until(&mut self, deadline: Instant) {
        std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
    }
}

/// 待ちの方針（ポーリング間隔と、依存先 1 件あたりの期限）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitPolicy {
    poll_interval: Duration,
    timeout: Duration,
}

impl WaitPolicy {
    /// 検証して作る。`poll_interval`・`timeout` は 0 より大きく、`poll_interval <= timeout <=
    /// MAX_WAIT_TIMEOUT` でなければ [`DependencyWaitError::InvalidPolicy`]（fail-closed）。
    pub fn new(poll_interval: Duration, timeout: Duration) -> Result<Self, DependencyWaitError> {
        if poll_interval.is_zero()
            || timeout.is_zero()
            || poll_interval > timeout
            || timeout > MAX_WAIT_TIMEOUT
        {
            return Err(DependencyWaitError::InvalidPolicy);
        }
        Ok(Self {
            poll_interval,
            timeout,
        })
    }

    /// ポーリング間隔。
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// 依存先 1 件あたりの期限。
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl Default for WaitPolicy {
    /// 暫定値（PoC-17 の poll 100ms・timeout 15s）。spec は数値を固定していない。
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(100),
            timeout: Duration::from_secs(15),
        }
    }
}

/// 待機のエラー（STACK-2）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DependencyWaitError {
    /// 期限内に条件を満たさなかった。#592 は healthy でも本 variant を再利用する。
    WaitTimeout {
        service: String,
        dependency: String,
        condition: DependsOnCondition,
    },
    /// 未対応の条件（healthy は #591、completed は未実装）。黙って満たしたことにしない。
    UnsupportedCondition {
        service: String,
        dependency: String,
        condition: DependsOnCondition,
    },
    /// 観測に失敗した（再試行せず返す）。
    Observe {
        service: String,
        dependency: String,
        source: ObserveError,
    },
    /// `WaitPolicy` が不正。
    InvalidPolicy,
}

impl DependencyWaitError {
    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        match self {
            Self::WaitTimeout { .. } => "DEPENDENCY_WAIT_TIMEOUT",
            Self::UnsupportedCondition { .. } => "DEPENDENCY_CONDITION_UNSUPPORTED",
            Self::Observe { .. } => "DEPENDENCY_OBSERVE_FAILED",
            Self::InvalidPolicy => "INVALID_ARGUMENT",
        }
    }

    /// 固定の英語メッセージ（名前は含めない）。
    pub fn message(&self) -> &'static str {
        match self {
            Self::WaitTimeout { .. } => "timed out waiting for a dependency condition",
            Self::UnsupportedCondition { .. } => "dependency condition is not supported yet",
            Self::Observe { .. } => "failed to observe a dependency",
            Self::InvalidPolicy => "invalid wait policy",
        }
    }
}

fn condition_name(c: DependsOnCondition) -> &'static str {
    match c {
        DependsOnCondition::Started => "started",
        DependsOnCondition::Healthy => "healthy",
        DependsOnCondition::Completed => "completed",
    }
}

impl fmt::Display for DependencyWaitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WaitTimeout {
                service,
                dependency,
                condition,
            }
            | Self::UnsupportedCondition {
                service,
                dependency,
                condition,
            } => write!(
                f,
                "{}: {} -> {} ({})",
                self.message(),
                service,
                dependency,
                condition_name(*condition)
            ),
            Self::Observe {
                service,
                dependency,
                source,
            } => write!(
                f,
                "{}: {} -> {} ({})",
                self.message(),
                service,
                dependency,
                source.code()
            ),
            Self::InvalidPolicy => f.write_str(self.message()),
        }
    }
}

impl std::error::Error for DependencyWaitError {}

/// 依存先ひとつ分の待ち結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitOutcome {
    /// 依存先のサービス名。
    pub dependency: String,
    /// 待った条件。
    pub condition: DependsOnCondition,
    /// observe を呼んだ回数。
    pub polls: u32,
    /// 待ち開始から満たすまでの時間。
    pub elapsed: Duration,
    /// 条件を満たした時点の観測。
    pub observed: DependencyObservation,
}

/// ステップ全体の待ち結果（依存先の名前昇順）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WaitReport {
    /// 依存先ごとの結果。
    pub outcomes: Vec<WaitOutcome>,
}

/// `step` の待ち条件をすべて満たすまで待つ（STACK-2・TASK-150.2）。
///
/// `Ok` を返してから呼び出し元が `step.service()` を起動する。healthy・completed が 1 件でもあれば
/// observe を呼ぶ前に [`DependencyWaitError::UnsupportedCondition`] を返す。期限は依存先ごとに持つ。
pub fn wait_for_step(
    step: &StartupStep,
    observer: &mut impl DependencyObserver,
    clock: &mut impl WaitClock,
    policy: &WaitPolicy,
) -> Result<WaitReport, DependencyWaitError> {
    // 部分的に待ってから失敗させないため、先に全件の条件を検査する。
    if let Some(w) = step
        .waits()
        .iter()
        .find(|w| w.condition() != DependsOnCondition::Started)
    {
        return Err(DependencyWaitError::UnsupportedCondition {
            service: step.service().to_string(),
            dependency: w.service().to_string(),
            condition: w.condition(),
        });
    }
    let mut report = WaitReport::default();
    for w in step.waits() {
        report
            .outcomes
            .push(wait_started(step.service(), w, observer, clock, policy)?);
    }
    Ok(report)
}

fn timeout_error(service: &str, wait: &DependencyWait) -> DependencyWaitError {
    DependencyWaitError::WaitTimeout {
        service: service.to_string(),
        dependency: wait.service().to_string(),
        condition: wait.condition(),
    }
}

fn wait_started(
    service: &str,
    wait: &DependencyWait,
    observer: &mut impl DependencyObserver,
    clock: &mut impl WaitClock,
    policy: &WaitPolicy,
) -> Result<WaitOutcome, DependencyWaitError> {
    let start = clock.now();
    let deadline = start
        .checked_add(policy.timeout())
        .ok_or(DependencyWaitError::InvalidPolicy)?;
    let mut polls: u32 = 0;
    loop {
        // 観測開始前に期限を過ぎていれば観測せず失敗にする（REPAIR-5）。
        if clock.now() > deadline {
            return Err(timeout_error(service, wait));
        }
        let observed =
            observer
                .observe(wait.service())
                .map_err(|source| DependencyWaitError::Observe {
                    service: service.to_string(),
                    dependency: wait.service().to_string(),
                    source,
                })?;
        polls = polls.saturating_add(1);
        let now = clock.now();
        // 観測が期限をまたいだ結果は成功と見なさない（REPAIR-5）。
        if now > deadline {
            return Err(timeout_error(service, wait));
        }
        if observed.satisfies_started() {
            return Ok(WaitOutcome {
                dependency: wait.service().to_string(),
                condition: wait.condition(),
                polls,
                elapsed: now.saturating_duration_since(start),
                observed,
            });
        }
        if now >= deadline {
            return Err(timeout_error(service, wait));
        }
        let next = now
            .checked_add(policy.poll_interval())
            .map_or(deadline, |t| t.min(deadline));
        clock.sleep_until(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::depends_on::plan_startup;
    use crate::schema::ComposeToml;
    use std::collections::{BTreeMap, VecDeque};

    struct FakeClock {
        now: Instant,
        sleeps: Vec<Duration>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                now: Instant::now(),
                sleeps: Vec::new(),
            }
        }
    }

    impl WaitClock for FakeClock {
        fn now(&self) -> Instant {
            self.now
        }
        fn sleep_until(&mut self, deadline: Instant) {
            let d = deadline.saturating_duration_since(self.now);
            self.sleeps.push(d);
            self.now = self.now.max(deadline);
        }
    }

    /// サービスごとの台本。尽きたら最後の値を返す。
    #[derive(Default)]
    struct FakeObserver {
        scripts: BTreeMap<String, VecDeque<Result<DependencyObservation, ObserveError>>>,
        calls: Vec<String>,
    }

    impl FakeObserver {
        fn script(mut self, svc: &str, obs: &[DependencyObservation]) -> Self {
            self.scripts
                .insert(svc.into(), obs.iter().copied().map(Ok).collect());
            self
        }
    }

    impl DependencyObserver for FakeObserver {
        fn observe(&mut self, service: &str) -> Result<DependencyObservation, ObserveError> {
            self.calls.push(service.to_string());
            let q = self.scripts.get_mut(service).expect("script");
            if q.len() > 1 {
                q.pop_front().expect("non-empty")
            } else {
                q.front().cloned().expect("non-empty")
            }
        }
    }

    /// `app` が `deps` を条件つきで待つステップを作る。
    fn step(deps: &[(&str, &str)]) -> StartupStep {
        let mut toml = String::from("[project]\nname = \"t\"\n[services.app]\nimage = \"x\"\n");
        if !deps.is_empty() {
            toml.push_str("[services.app.depends_on]\n");
        }
        for (d, c) in deps {
            toml.push_str(&format!("{d} = \"{c}\"\n"));
        }
        for (d, _) in deps {
            toml.push_str(&format!("[services.{d}]\nimage = \"x\"\n"));
        }
        let parsed: ComposeToml = toml::from_str(&toml).unwrap();
        let plan = plan_startup(&parsed.services).unwrap();
        plan.steps()
            .iter()
            .find(|s| s.service() == "app")
            .unwrap()
            .clone()
    }

    use DependencyObservation as O;

    #[test]
    fn stack_2_started_satisfied_on_first_running() {
        let s = step(&[("db", "started")]);
        let mut obs = FakeObserver::default().script("db", &[O::Running]);
        let mut clock = FakeClock::new();
        let r = wait_for_step(&s, &mut obs, &mut clock, &WaitPolicy::default()).unwrap();
        assert_eq!(r.outcomes.len(), 1);
        assert_eq!(r.outcomes[0].polls, 1);
        assert_eq!(r.outcomes[0].elapsed, Duration::ZERO);
        assert!(clock.sleeps.is_empty());
    }

    #[test]
    fn stack_2_started_waits_through_absent_creating_created() {
        let s = step(&[("db", "started")]);
        let mut obs =
            FakeObserver::default().script("db", &[O::Absent, O::Creating, O::Created, O::Running]);
        let mut clock = FakeClock::new();
        let r = wait_for_step(&s, &mut obs, &mut clock, &WaitPolicy::default()).unwrap();
        assert_eq!(r.outcomes[0].polls, 4);
        assert_eq!(r.outcomes[0].elapsed, Duration::from_millis(300));
        assert_eq!(r.outcomes[0].observed, O::Running);
        assert_eq!(clock.sleeps, vec![Duration::from_millis(100); 3]);
    }

    #[test]
    fn stack_2_started_accepts_stopped() {
        let s = step(&[("db", "started")]);
        let mut obs = FakeObserver::default().script("db", &[O::Created, O::Stopped]);
        let mut clock = FakeClock::new();
        let r = wait_for_step(&s, &mut obs, &mut clock, &WaitPolicy::default()).unwrap();
        assert_eq!(r.outcomes[0].observed, O::Stopped);
        assert_eq!(r.outcomes[0].polls, 2);
    }

    #[test]
    fn stack_2_observation_mapping() {
        assert!(!O::Absent.satisfies_started());
        assert!(!O::Creating.satisfies_started());
        assert!(!O::Created.satisfies_started());
        assert!(O::Running.satisfies_started());
        assert!(O::Stopped.satisfies_started());
    }

    #[test]
    fn stack_2_started_timeout() {
        let s = step(&[("db", "started")]);
        let mut obs = FakeObserver::default().script("db", &[O::Created]);
        let mut clock = FakeClock::new();
        let policy = WaitPolicy::new(Duration::from_millis(300), Duration::from_secs(1)).unwrap();
        let err = wait_for_step(&s, &mut obs, &mut clock, &policy).unwrap_err();
        assert_eq!(
            err,
            DependencyWaitError::WaitTimeout {
                service: "app".into(),
                dependency: "db".into(),
                condition: DependsOnCondition::Started,
            }
        );
        assert_eq!(err.code(), "DEPENDENCY_WAIT_TIMEOUT");
        assert_eq!(
            clock.sleeps,
            vec![
                Duration::from_millis(300),
                Duration::from_millis(300),
                Duration::from_millis(300),
                Duration::from_millis(100)
            ]
        );
        assert_eq!(obs.calls.len(), 5);
    }

    /// 呼ばれるたびに台本の時刻を返す時計（期限境界の再現用）。
    struct ScriptedClock {
        times: std::cell::RefCell<VecDeque<Instant>>,
    }

    impl WaitClock for ScriptedClock {
        fn now(&self) -> Instant {
            let mut q = self.times.borrow_mut();
            if q.len() > 1 {
                q.pop_front().expect("non-empty")
            } else {
                *q.front().expect("non-empty")
            }
        }
        fn sleep_until(&mut self, _deadline: Instant) {}
    }

    /// 期限をまたいで返った Running は成功にせず WaitTimeout になる（REPAIR-5）。
    #[test]
    fn stack_2_running_observed_after_deadline_is_timeout() {
        let s = step(&[("db", "started")]);
        let mut obs = FakeObserver::default().script("db", &[O::Running]);
        let t0 = Instant::now();
        // start, 観測前, 観測後（15.1 秒）
        let mut clock = ScriptedClock {
            times: std::cell::RefCell::new(VecDeque::from([
                t0,
                t0,
                t0 + Duration::from_millis(15_100),
            ])),
        };
        let policy = WaitPolicy::new(Duration::from_millis(300), Duration::from_secs(15)).unwrap();
        let err = wait_for_step(&s, &mut obs, &mut clock, &policy).unwrap_err();
        assert_eq!(err.code(), "DEPENDENCY_WAIT_TIMEOUT");
        assert_eq!(obs.calls.len(), 1);
    }

    /// sleep 復帰が遅れて観測前に期限を過ぎたら観測せず WaitTimeout になる。
    #[test]
    fn stack_2_deadline_passed_before_observe_is_timeout_without_poll() {
        let s = step(&[("db", "started")]);
        let mut obs = FakeObserver::default().script("db", &[O::Running]);
        let t0 = Instant::now();
        let mut clock = ScriptedClock {
            times: std::cell::RefCell::new(VecDeque::from([
                t0,
                t0 + Duration::from_millis(15_100),
            ])),
        };
        let policy = WaitPolicy::new(Duration::from_millis(300), Duration::from_secs(15)).unwrap();
        let err = wait_for_step(&s, &mut obs, &mut clock, &policy).unwrap_err();
        assert_eq!(err.code(), "DEPENDENCY_WAIT_TIMEOUT");
        assert!(obs.calls.is_empty());
    }

    #[test]
    fn stack_2_observe_error_propagates_without_retry() {
        let s = step(&[("db", "started")]);
        let mut obs = FakeObserver::default();
        obs.scripts.insert(
            "db".into(),
            VecDeque::from([Err(ObserveError::new(
                "STATE_READ_FAILED",
                "state read failed",
            ))]),
        );
        let mut clock = FakeClock::new();
        let err = wait_for_step(&s, &mut obs, &mut clock, &WaitPolicy::default()).unwrap_err();
        assert_eq!(err.code(), "DEPENDENCY_OBSERVE_FAILED");
        assert_eq!(obs.calls.len(), 1);
        assert!(clock.sleeps.is_empty());
    }

    #[test]
    fn stack_2_healthy_and_completed_rejected_before_polling() {
        for c in ["healthy", "completed"] {
            let s = step(&[("a", "started"), ("b", c)]);
            let mut obs = FakeObserver::default()
                .script("a", &[O::Running])
                .script("b", &[O::Running]);
            let mut clock = FakeClock::new();
            let err = wait_for_step(&s, &mut obs, &mut clock, &WaitPolicy::default()).unwrap_err();
            assert_eq!(err.code(), "DEPENDENCY_CONDITION_UNSUPPORTED");
            assert!(obs.calls.is_empty());
        }
    }

    #[test]
    fn stack_2_multiple_dependencies_waited_in_name_order() {
        let s = step(&[("zeta", "started"), ("alpha", "started")]);
        let mut obs = FakeObserver::default()
            .script("alpha", &[O::Created, O::Running])
            .script("zeta", &[O::Running]);
        let mut clock = FakeClock::new();
        let r = wait_for_step(&s, &mut obs, &mut clock, &WaitPolicy::default()).unwrap();
        assert_eq!(obs.calls, vec!["alpha", "alpha", "zeta"]);
        assert_eq!(r.outcomes[0].dependency, "alpha");
        assert_eq!(r.outcomes[1].dependency, "zeta");
    }

    #[test]
    fn stack_2_empty_waits_no_poll() {
        let s = step(&[]);
        let mut obs = FakeObserver::default();
        let mut clock = FakeClock::new();
        let r = wait_for_step(&s, &mut obs, &mut clock, &WaitPolicy::default()).unwrap();
        assert!(r.outcomes.is_empty());
        assert!(obs.calls.is_empty());
        assert!(clock.sleeps.is_empty());
    }

    #[test]
    fn stack_2_policy_validation() {
        let ms = Duration::from_millis;
        assert!(WaitPolicy::new(Duration::ZERO, ms(10)).is_err());
        assert!(WaitPolicy::new(ms(10), Duration::ZERO).is_err());
        assert!(WaitPolicy::new(ms(20), ms(10)).is_err());
        assert!(WaitPolicy::new(ms(10), MAX_WAIT_TIMEOUT + ms(1)).is_err());
        assert!(WaitPolicy::new(ms(10), MAX_WAIT_TIMEOUT).is_ok());
        let d = WaitPolicy::default();
        assert_eq!(d.poll_interval(), ms(100));
        assert_eq!(d.timeout(), Duration::from_secs(15));
    }

    #[test]
    fn stack_2_wait_error_text() {
        let e = DependencyWaitError::WaitTimeout {
            service: "app".into(),
            dependency: "db".into(),
            condition: DependsOnCondition::Started,
        };
        assert_eq!(e.message(), "timed out waiting for a dependency condition");
        assert_eq!(
            e.to_string(),
            "timed out waiting for a dependency condition: app -> db (started)"
        );
        assert_eq!(
            DependencyWaitError::InvalidPolicy.code(),
            "INVALID_ARGUMENT"
        );
    }
}
