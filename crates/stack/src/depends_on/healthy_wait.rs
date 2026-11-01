//! `healthy` 条件の state.json ポーリング待機（STACK-2・TASK-150.3・#591）。
//!
//! 呼び出し元は `cli::up`（TASK-155.1・#618）で、[`StartupStep`] の `healthy` 条件の依存先を
//! 期限つきで待ち、すべて healthy になったときだけ依存元の起動を許可する。supervisor
//! （SUP-4・TASK-161）が state.json の `health` へ書く値（`starting` / `healthy` /
//! `unhealthy`。core の `HealthStatus::as_str`）を [`HealthSource`] 越しに観測する。
//!
//! 期限到達のエラー化（#592）: [`require_healthy_dependencies`] が `Blocked` を
//! [`DependencyWaitError::WaitTimeout`]（code `DEPENDENCY_WAIT_TIMEOUT`・終了コード 7）へ写す。
//! `Err` なら呼び出し元は依存元を起動しない。
//!
//! 未実装（実装済みを装わない。REPAIR-3）:
//! - 本番の [`HealthSource`]（core の `StateStore` で state.json を読む実装とサービス名から
//!   コンテナ ID への対応づけ）は `up`（TASK-155）の配線で作る。stack は core に依存しないため、
//!   ここでは I/O を持たない抽象だけを置く（`stack -> core` の依存追加は承認事項）。
//! - `started`（#590）・`completed` の待機。本ゲートは `healthy` 条件だけを判定するので、
//!   ステップ全体の起動可否は `up` が他の条件の結果と合わせて決める。
//!
//! 有界性（REPAIR-5）: 待ちは必ず期限で終わる。間隔・期限は 0 を拒否し上限を持つ。
//! 外部入力（health の文字列）は完全一致で解釈し、未知の値は healthy とみなさない
//! （fail-closed）。残余: 監視権を取る前に古い世代の `healthy` を読む窓は、新しいコンテナを
//! 作る `up` では前の世代が無いため生じない。エラーにはサービス名と固定の英語文だけを入れる。

use std::fmt;
use std::time::{Duration, Instant};

use crate::depends_on::StartupStep;
use crate::depends_on::wait::{DependencyWaitError, ObserveError};
use crate::schema::DependsOnCondition;

/// state.json の `health` に対応する観測値（core の `HealthStatus` の文字列と 1 対 1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObservedHealth {
    /// healthcheck の判定前。
    Starting,
    /// healthy。
    Healthy,
    /// unhealthy。
    Unhealthy,
}

impl ObservedHealth {
    /// state.json 上の文字列。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
        }
    }

    /// 完全一致（大文字小文字を区別）で解釈する。未知の値は `None`。
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "starting" => Some(Self::Starting),
            "healthy" => Some(Self::Healthy),
            "unhealthy" => Some(Self::Unhealthy),
            _ => None,
        }
    }
}

/// [`HealthSource`] の失敗（固定の英語 code / message だけを持つ。パス・内部の本文は載せない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthSourceError {
    code: &'static str,
    message: &'static str,
}

impl HealthSourceError {
    /// 固定の code と message から作る。
    pub fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    /// 機械可読なコード。
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// 固定の英語メッセージ。
    pub fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for HealthSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for HealthSourceError {}

/// 依存先の health を 1 回読む抽象（本番実装は `up`〔TASK-155〕が `StateStore` で作る）。
pub trait HealthSource {
    /// `Ok(None)` は記録が無い、または health 未設定（判定前として扱う）。
    fn observe(&mut self, service: &str) -> Result<Option<ObservedHealth>, HealthSourceError>;
}

/// 単調な時計と待ち（試験では偽の時計を注入する）。
pub trait PollClock {
    /// 基準時刻からの経過。単調増加。
    fn now(&self) -> Duration;
    /// `d` だけ待つ。
    fn sleep(&mut self, d: Duration);
}

/// 本番用の時計（`Instant` と `thread::sleep`）。
#[derive(Debug, Clone, Copy)]
pub struct MonotonicClock {
    origin: Instant,
}

impl MonotonicClock {
    /// 現在を基準時刻にして作る。
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl PollClock for MonotonicClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// ポリシーの検証エラー。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HealthyWaitPolicyError {
    /// 間隔が 0、または上限超え。
    InvalidPollInterval,
    /// 期限が 0、または上限超え。
    InvalidTimeout,
}

impl HealthyWaitPolicyError {
    /// 機械可読なコード。
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidPollInterval => "INVALID_POLL_INTERVAL",
            Self::InvalidTimeout => "INVALID_TIMEOUT",
        }
    }

    /// 固定の英語メッセージ。
    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidPollInterval => "poll interval must be in 1ns..=60s",
            Self::InvalidTimeout => "timeout must be in 1ns..=3600s",
        }
    }
}

impl fmt::Display for HealthyWaitPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for HealthyWaitPolicyError {}

/// ポーリング間隔と全体の期限（`Default` は `cli::up` 用の暫定値。spec は数値を固定していない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthyWaitPolicy {
    poll_interval: Duration,
    timeout: Duration,
}

impl Default for HealthyWaitPolicy {
    /// 暫定値（間隔 500ms・期限 15s。`WaitPolicy` の既定の期限に合わせる）。
    fn default() -> Self {
        Self {
            poll_interval: Self::DEFAULT_POLL_INTERVAL,
            timeout: Duration::from_secs(15),
        }
    }
}

impl HealthyWaitPolicy {
    /// 推奨の間隔。
    pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);
    /// 間隔の上限。
    pub const MAX_POLL_INTERVAL: Duration = Duration::from_secs(60);
    /// 期限の上限。
    pub const MAX_TIMEOUT: Duration = Duration::from_secs(3600);

    /// 0 と上限超えを拒否して作る（ビジーループと無期限の待ちを防ぐ。REPAIR-5）。
    pub fn new(poll_interval: Duration, timeout: Duration) -> Result<Self, HealthyWaitPolicyError> {
        if poll_interval.is_zero() || poll_interval > Self::MAX_POLL_INTERVAL {
            return Err(HealthyWaitPolicyError::InvalidPollInterval);
        }
        if timeout.is_zero() || timeout > Self::MAX_TIMEOUT {
            return Err(HealthyWaitPolicyError::InvalidTimeout);
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

    /// 全体の期限。
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// 1 つの依存先を待った結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HealthyWaitOutcome {
    /// healthy を観測した。
    Healthy {
        service: String,
        polls: u64,
        elapsed: Duration,
    },
    /// 期限までに healthy にならなかった（[`require_healthy_dependencies`] がエラーへ写像する）。
    DeadlineReached {
        service: String,
        last_observed: Option<ObservedHealth>,
        polls: u64,
    },
}

impl HealthyWaitOutcome {
    /// 待った依存先のサービス名。
    pub fn service(&self) -> &str {
        match self {
            Self::Healthy { service, .. } | Self::DeadlineReached { service, .. } => service,
        }
    }
}

/// 待機の失敗（source が読めなかった）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HealthyWaitError {
    /// 観測に失敗した。読めない状態は healthy とみなさず、すぐ待ちを終える。
    Source {
        service: String,
        error: HealthSourceError,
    },
}

impl HealthyWaitError {
    /// 機械可読なコード。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Source { .. } => "HEALTH_SOURCE_FAILED",
        }
    }

    /// 固定の英語メッセージ。
    pub fn message(&self) -> &'static str {
        match self {
            Self::Source { .. } => "failed to observe dependency health",
        }
    }
}

impl fmt::Display for HealthyWaitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source { service, error } => {
                write!(f, "{}: {} ({})", self.message(), service, error)
            }
        }
    }
}

impl std::error::Error for HealthyWaitError {}

/// 1 つの依存先を `deadline`（`clock.now()` 基準の絶対値）まで待つ。
///
/// `Unhealthy` / `Starting` / 記録なしは期限まで待つ（STACK-2 は「healthy にならなければ
/// タイムアウト後にエラー」。supervisor の集約で unhealthy から戻りうる）。
pub fn wait_until_healthy(
    service: &str,
    deadline: Duration,
    source: &mut dyn HealthSource,
    clock: &mut dyn PollClock,
    policy: &HealthyWaitPolicy,
) -> Result<HealthyWaitOutcome, HealthyWaitError> {
    let start = clock.now();
    let mut polls: u64 = 0;
    let mut last_observed: Option<ObservedHealth> = None;
    loop {
        // 観測前の期限確認（先の依存先が期限を使い切った場合に後続の観測へ進まない。REPAIR-5）。
        if clock.now() >= deadline {
            return Ok(HealthyWaitOutcome::DeadlineReached {
                service: service.to_string(),
                last_observed,
                polls,
            });
        }
        polls = polls.saturating_add(1);
        let observed = source
            .observe(service)
            .map_err(|error| HealthyWaitError::Source {
                service: service.to_string(),
                error,
            })?;
        last_observed = observed;
        let now = clock.now();
        // 観測後の期限確認（観測中・sleep の遅れで期限を超えたら healthy でも許可しない）。
        if now >= deadline {
            return Ok(HealthyWaitOutcome::DeadlineReached {
                service: service.to_string(),
                last_observed,
                polls,
            });
        }
        if observed == Some(ObservedHealth::Healthy) {
            return Ok(HealthyWaitOutcome::Healthy {
                service: service.to_string(),
                polls,
                elapsed: now.saturating_sub(start),
            });
        }
        clock.sleep(policy.poll_interval.min(deadline.saturating_sub(now)));
    }
}

/// [`gate_healthy_dependencies`] の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HealthyGate {
    /// healthy 条件の依存先がすべて healthy（0 件を含む）。依存元の起動を許可する。
    Permitted { waited: Vec<HealthyWaitOutcome> },
    /// 期限内に healthy にならなかった依存先がある。起動を許可しない（[`HealthyGate::into_result`] がエラー化する）。
    /// 中身は `DeadlineReached`。
    Blocked(HealthyWaitOutcome),
}

impl HealthyGate {
    /// 結果をエラーへ写す（STACK-2）。`Blocked` は `service`（依存元）から見た
    /// [`DependencyWaitError::WaitTimeout`]（condition は healthy）にする。
    pub fn into_result(
        self,
        service: &str,
    ) -> Result<Vec<HealthyWaitOutcome>, DependencyWaitError> {
        match self {
            Self::Permitted { waited } => Ok(waited),
            Self::Blocked(outcome) => Err(DependencyWaitError::WaitTimeout {
                service: service.to_string(),
                dependency: outcome.service().to_string(),
                condition: DependsOnCondition::Healthy,
            }),
        }
    }
}

/// [`gate_healthy_dependencies`] の結果をエラー化して返す（STACK-2・TASK-150.4・#592）。
///
/// 呼び出し元は `cli::up`（TASK-155.1・#618）。`Err` が返ったら依存元を起動せず、
/// [`DependencyWaitError::exit_code`] の非ゼロ終了コードで止める（期限切れは 7、観測失敗は 1）。
/// source の失敗は `DependencyWaitError::Observe` に写す（読めない状態を healthy とみなさない）。
/// 待ちの有界性は `policy`（ステップ共通の期限）が保証する（REPAIR-5）。
pub fn require_healthy_dependencies(
    step: &StartupStep,
    source: &mut dyn HealthSource,
    clock: &mut dyn PollClock,
    policy: &HealthyWaitPolicy,
) -> Result<Vec<HealthyWaitOutcome>, DependencyWaitError> {
    gate_healthy_dependencies(step, source, clock, policy)
        .map_err(|e| match e {
            HealthyWaitError::Source { service, error } => DependencyWaitError::Observe {
                service: step.service().to_string(),
                dependency: service,
                source: ObserveError::new(error.code(), error.message()),
            },
        })?
        .into_result(step.service())
}

/// ステップの `healthy` 条件の依存先だけを依存先名の昇順に待つ。
///
/// 期限はステップ全体で 1 つ（呼び出し時刻 + `policy.timeout`）で、合計の待ちを収める。
/// `started` / `completed` は観測しない（#590・未実装）。
pub fn gate_healthy_dependencies(
    step: &StartupStep,
    source: &mut dyn HealthSource,
    clock: &mut dyn PollClock,
    policy: &HealthyWaitPolicy,
) -> Result<HealthyGate, HealthyWaitError> {
    let deadline = clock.now().saturating_add(policy.timeout);
    let mut waited = Vec::new();
    for w in step
        .waits()
        .iter()
        .filter(|w| w.condition() == DependsOnCondition::Healthy)
    {
        let outcome = wait_until_healthy(w.service(), deadline, source, clock, policy)?;
        if matches!(outcome, HealthyWaitOutcome::DeadlineReached { .. }) {
            return Ok(HealthyGate::Blocked(outcome));
        }
        waited.push(outcome);
    }
    Ok(HealthyGate::Permitted { waited })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::depends_on::plan_startup;
    use crate::schema::ComposeToml;
    use std::collections::VecDeque;

    struct FakeClock {
        now: Duration,
        sleeps: Vec<Duration>,
    }
    impl FakeClock {
        fn new() -> Self {
            Self {
                now: Duration::ZERO,
                sleeps: vec![],
            }
        }
    }
    impl PollClock for FakeClock {
        fn now(&self) -> Duration {
            self.now
        }
        fn sleep(&mut self, d: Duration) {
            self.sleeps.push(d);
            self.now += d;
        }
    }

    type Obs = Result<Option<ObservedHealth>, HealthSourceError>;

    /// 台本どおりに返し、尽きたら最後の値を返し続ける。呼ばれた名前を記録する。
    struct Script {
        values: VecDeque<Obs>,
        last: Obs,
        calls: Vec<String>,
    }
    impl Script {
        fn new(v: Vec<Option<ObservedHealth>>) -> Self {
            let last = v.last().copied().map(Ok).unwrap_or(Ok(None));
            Self {
                values: v.into_iter().map(Ok).collect(),
                last,
                calls: vec![],
            }
        }
    }
    impl HealthSource for Script {
        fn observe(&mut self, s: &str) -> Obs {
            self.calls.push(s.to_string());
            self.values.pop_front().unwrap_or(self.last)
        }
    }

    /// サービスごとに台本を持つ source（第 2 要素は観測順の記録）。
    struct PerService(Vec<(&'static str, Script)>, Vec<String>);
    impl HealthSource for PerService {
        fn observe(&mut self, s: &str) -> Obs {
            self.1.push(s.to_string());
            match self.0.iter_mut().find(|(n, _)| *n == s) {
                Some((_, sc)) => sc.observe(s),
                None => Ok(None),
            }
        }
    }

    use ObservedHealth::{Healthy, Starting, Unhealthy};

    fn pol(i: u64, t: u64) -> HealthyWaitPolicy {
        HealthyWaitPolicy::new(Duration::from_millis(i), Duration::from_millis(t)).unwrap()
    }
    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn stack_2_first_poll_healthy() {
        let mut s = Script::new(vec![Some(Healthy)]);
        let mut c = FakeClock::new();
        let r = wait_until_healthy("db", ms(1000), &mut s, &mut c, &pol(100, 1000)).unwrap();
        assert_eq!(
            r,
            HealthyWaitOutcome::Healthy {
                service: "db".into(),
                polls: 1,
                elapsed: Duration::ZERO
            }
        );
        assert!(c.sleeps.is_empty());
    }

    #[test]
    fn stack_2_waits_through_none_and_starting() {
        let mut s = Script::new(vec![None, None, Some(Starting), Some(Healthy)]);
        let mut c = FakeClock::new();
        let r = wait_until_healthy("db", ms(1000), &mut s, &mut c, &pol(100, 1000)).unwrap();
        assert_eq!(
            r,
            HealthyWaitOutcome::Healthy {
                service: "db".into(),
                polls: 4,
                elapsed: ms(300)
            }
        );
        assert_eq!(c.sleeps, vec![ms(100); 3]);
    }

    #[test]
    fn stack_2_unhealthy_can_recover() {
        let mut s = Script::new(vec![Some(Unhealthy), Some(Healthy)]);
        let mut c = FakeClock::new();
        let r = wait_until_healthy("db", ms(1000), &mut s, &mut c, &pol(100, 1000)).unwrap();
        assert!(matches!(r, HealthyWaitOutcome::Healthy { polls: 2, .. }));
    }

    #[test]
    fn stack_2_always_unhealthy_hits_deadline() {
        let mut s = Script::new(vec![Some(Unhealthy)]);
        let mut c = FakeClock::new();
        let r = wait_until_healthy("db", ms(1000), &mut s, &mut c, &pol(100, 1000)).unwrap();
        assert_eq!(
            r,
            HealthyWaitOutcome::DeadlineReached {
                service: "db".into(),
                last_observed: Some(Unhealthy),
                polls: 10
            }
        );
        assert_eq!(c.sleeps.iter().sum::<Duration>(), ms(1000));
    }

    #[test]
    fn stack_2_deadline_not_multiple_of_interval() {
        let mut s = Script::new(vec![Some(Starting)]);
        let mut c = FakeClock::new();
        let r = wait_until_healthy("db", ms(1000), &mut s, &mut c, &pol(300, 1000)).unwrap();
        assert_eq!(c.sleeps, vec![ms(300), ms(300), ms(300), ms(100)]);
        assert!(matches!(
            r,
            HealthyWaitOutcome::DeadlineReached {
                polls: 4,
                last_observed: Some(Starting),
                ..
            }
        ));
    }

    #[test]
    fn stack_2_always_none_hits_deadline() {
        let mut s = Script::new(vec![None]);
        let mut c = FakeClock::new();
        let r = wait_until_healthy("db", ms(200), &mut s, &mut c, &pol(100, 200)).unwrap();
        assert_eq!(
            r,
            HealthyWaitOutcome::DeadlineReached {
                service: "db".into(),
                last_observed: None,
                polls: 2
            }
        );
    }

    #[test]
    fn stack_2_source_error_ends_immediately() {
        let mut s = Script::new(vec![]);
        s.values.push_back(Err(HealthSourceError::new(
            "STATE_CORRUPT",
            "state is corrupt",
        )));
        let mut c = FakeClock::new();
        let e = wait_until_healthy("db", ms(1000), &mut s, &mut c, &pol(100, 1000)).unwrap_err();
        assert_eq!(e.code(), "HEALTH_SOURCE_FAILED");
        assert_eq!(e.message(), "failed to observe dependency health");
        assert_eq!(s.calls.len(), 1);
        assert!(c.sleeps.is_empty());
    }

    #[test]
    fn stack_2_observed_health_parse_is_exact() {
        for (t, v) in [
            ("starting", Starting),
            ("healthy", Healthy),
            ("unhealthy", Unhealthy),
        ] {
            assert_eq!(ObservedHealth::parse(t), Some(v));
            assert_eq!(v.as_str(), t);
        }
        for bad in ["Healthy", "HEALTHY", " healthy", "", "ok", "healthy\n"] {
            assert_eq!(ObservedHealth::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn stack_2_policy_validation() {
        let d = Duration::from_millis;
        let e = |i, t| HealthyWaitPolicy::new(i, t).unwrap_err().code();
        assert_eq!(e(Duration::ZERO, d(10)), "INVALID_POLL_INTERVAL");
        assert_eq!(e(Duration::from_secs(61), d(10)), "INVALID_POLL_INTERVAL");
        assert_eq!(e(d(10), Duration::ZERO), "INVALID_TIMEOUT");
        assert_eq!(e(d(10), Duration::from_secs(3601)), "INVALID_TIMEOUT");
        assert!(HealthyWaitPolicy::new(Duration::from_nanos(1), Duration::from_nanos(1)).is_ok());
        assert!(HealthyWaitPolicy::new(Duration::from_secs(60), Duration::from_secs(3600)).is_ok());
    }

    fn step_of(toml_src: &str, name: &str) -> StartupStep {
        let parsed: ComposeToml = toml::from_str(toml_src).unwrap();
        let plan = plan_startup(&parsed.services).unwrap();
        plan.steps()
            .iter()
            .find(|s| s.service() == name)
            .unwrap()
            .clone()
    }

    const TWO: &str = r#"
[project]
name = "t"
[services.app]
image = "x"
[services.app.depends_on]
a = "healthy"
b = "healthy"
c = "started"
d = "completed"
[services.a]
image = "x"
[services.b]
image = "x"
[services.c]
image = "x"
[services.d]
image = "x"
"#;

    #[test]
    fn stack_2_gate_no_healthy_conditions_is_permitted_without_polling() {
        let step = step_of(
            "[project]\nname=\"t\"\n[services.app]\nimage=\"x\"\n[services.app.depends_on]\nc=\"started\"\n[services.c]\nimage=\"x\"\n",
            "app",
        );
        let mut s = PerService(vec![], vec![]);
        let mut c = FakeClock::new();
        let g = gate_healthy_dependencies(&step, &mut s, &mut c, &pol(100, 1000)).unwrap();
        assert_eq!(g, HealthyGate::Permitted { waited: vec![] });
        assert!(s.1.is_empty());
    }

    #[test]
    fn stack_2_gate_waits_healthy_only_in_name_order() {
        let step = step_of(TWO, "app");
        let mut s = PerService(
            vec![
                ("a", Script::new(vec![Some(Healthy)])),
                ("b", Script::new(vec![Some(Healthy)])),
            ],
            vec![],
        );
        let mut c = FakeClock::new();
        let g = gate_healthy_dependencies(&step, &mut s, &mut c, &pol(100, 1000)).unwrap();
        assert!(matches!(g, HealthyGate::Permitted { ref waited } if waited.len() == 2));
        assert_eq!(s.1, vec!["a", "b"]);
    }

    #[test]
    fn stack_2_gate_blocks_and_skips_later_dependencies() {
        let step = step_of(TWO, "app");
        let mut s = PerService(
            vec![
                ("a", Script::new(vec![Some(Unhealthy)])),
                ("b", Script::new(vec![Some(Healthy)])),
            ],
            vec![],
        );
        let mut c = FakeClock::new();
        let g = gate_healthy_dependencies(&step, &mut s, &mut c, &pol(100, 1000)).unwrap();
        match g {
            HealthyGate::Blocked(HealthyWaitOutcome::DeadlineReached {
                service,
                last_observed,
                ..
            }) => {
                assert_eq!(service, "a");
                assert_eq!(last_observed, Some(Unhealthy));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(!s.1.iter().any(|n| n == "b"));
    }

    #[test]
    fn stack_2_gate_shares_one_deadline() {
        let step = step_of(TWO, "app");
        // a は 8 回目（700ms 後）に healthy。b は常に starting。
        let mut a = vec![Some(Starting); 7];
        a.push(Some(Healthy));
        let mut s = PerService(
            vec![
                ("a", Script::new(a)),
                ("b", Script::new(vec![Some(Starting)])),
            ],
            vec![],
        );
        let mut c = FakeClock::new();
        let g = gate_healthy_dependencies(&step, &mut s, &mut c, &pol(100, 1000)).unwrap();
        assert!(matches!(g, HealthyGate::Blocked(_)));
        assert_eq!(c.sleeps.iter().sum::<Duration>(), ms(1000));
        // b に使えたのは残り 300ms のみ（700・800・900ms の 3 回。1000ms は期限で観測しない）
        let b_polls = s.1.iter().filter(|n| *n == "b").count();
        assert_eq!(b_polls, 3);
    }

    #[test]
    fn stack_2_healthy_timeout_is_wait_timeout_error() {
        for v in [Unhealthy, Starting] {
            let step = step_of(TWO, "app");
            let mut s = PerService(
                vec![
                    ("a", Script::new(vec![Some(v)])),
                    ("b", Script::new(vec![Some(Healthy)])),
                ],
                vec![],
            );
            let mut c = FakeClock::new();
            let e =
                require_healthy_dependencies(&step, &mut s, &mut c, &pol(100, 1000)).unwrap_err();
            assert_eq!(
                e,
                DependencyWaitError::WaitTimeout {
                    service: "app".into(),
                    dependency: "a".into(),
                    condition: DependsOnCondition::Healthy,
                }
            );
            assert_eq!(e.code(), "DEPENDENCY_WAIT_TIMEOUT");
            assert_eq!(e.exit_code().get(), 7);
            assert_eq!(
                e.to_string(),
                "timed out waiting for a dependency condition: app -> a (healthy)"
            );
            assert!(!s.1.iter().any(|n| n == "b"));
        }
        // 記録なしのままでも同じ。
        let step = step_of(TWO, "app");
        let mut s = PerService(vec![], vec![]);
        let mut c = FakeClock::new();
        let e = require_healthy_dependencies(&step, &mut s, &mut c, &pol(100, 500)).unwrap_err();
        assert_eq!(e.exit_code().get(), 7);
    }

    #[test]
    fn stack_2_require_healthy_permitted_returns_outcomes() {
        let step = step_of(TWO, "app");
        let mut s = PerService(
            vec![
                ("a", Script::new(vec![Some(Healthy)])),
                ("b", Script::new(vec![Some(Healthy)])),
            ],
            vec![],
        );
        let mut c = FakeClock::new();
        let r = require_healthy_dependencies(&step, &mut s, &mut c, &pol(100, 1000)).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].service(), "a");
        assert_eq!(r[1].service(), "b");
        // healthy 条件が無いステップは観測せず Ok(空)。
        let step = step_of(TWO, "a");
        let mut s = PerService(vec![], vec![]);
        let r = require_healthy_dependencies(&step, &mut s, &mut c, &pol(100, 1000)).unwrap();
        assert!(r.is_empty());
        assert!(s.1.is_empty());
    }

    #[test]
    fn stack_2_require_healthy_source_error_maps_to_observe() {
        struct Failing;
        impl HealthSource for Failing {
            fn observe(&mut self, _: &str) -> Obs {
                Err(HealthSourceError::new("STATE_CORRUPT", "bad state"))
            }
        }
        let step = step_of(TWO, "app");
        let mut c = FakeClock::new();
        let e =
            require_healthy_dependencies(&step, &mut Failing, &mut c, &pol(100, 1000)).unwrap_err();
        match &e {
            DependencyWaitError::Observe {
                service,
                dependency,
                source,
            } => {
                assert_eq!(service, "app");
                assert_eq!(dependency, "a");
                assert_eq!(source.code(), "STATE_CORRUPT");
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(e.code(), "DEPENDENCY_OBSERVE_FAILED");
        assert_eq!(e.exit_code().get(), 1);
    }

    #[test]
    fn stack_2_into_result_maps_gate() {
        let p = HealthyGate::Permitted { waited: vec![] };
        assert_eq!(p.into_result("app").unwrap(), vec![]);
        let b = HealthyGate::Blocked(HealthyWaitOutcome::DeadlineReached {
            service: "a".into(),
            last_observed: None,
            polls: 3,
        });
        assert_eq!(b.into_result("app").unwrap_err().exit_code().get(), 7);
    }
}
