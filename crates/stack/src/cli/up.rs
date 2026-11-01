//! `up`: 依存グラフのトポロジカル順でサービスを起動し、宣言したネットワークへ接続する
//! （STACK-8・STACK-2・TASK-155.1・TASK-155.2・#618・#619）。
//!
//! 呼び出し元は CLI の `up` サブコマンド（結線は未実装。#3639）。profiles で絞った
//! `BTreeMap<String, Service>` を受ける（`plan_startup` と同じ理由）。
//! 流れ: `plan_startup`（循環・未定義の依存先は起動ゼロで失敗）→ `completed` 条件の事前検査
//! （未対応なので起動ゼロで失敗）→ `plan_networks`（`[networks]` の検証。失敗は起動ゼロ・用意ゼロ）
//! → 参照されるネットワークを名前の昇順に [`NetworkProvisioner::ensure`]（失敗は起動ゼロ）
//! → 計画の各ステップで、healthy 条件の待ち → started 条件の待ち
//! → [`ServiceLauncher::launch`]。待ちはそれぞれの方針の期限で有界（REPAIR-5）。
//!
//! 途中で失敗したら最初のエラーで止め、ロールバックはしない（停止・ネットワークの片付けは
//! `down`〔#620〕の責務）。[`UpFailure::launched`] に起動済みのサービス名を起動順で、
//! [`UpFailure::networks`] に用意済みのネットワークを返す。
//!
//! 実装済みを装わない（REPAIR-3）。未実装（#3639 で追跡）:
//! - 本番の [`ServiceLauncher`]（CLI の create → start を子プロセスで呼ぶ。`Service::create_option_args` を使う。
//!   TASK-157・SUP-1）。ネットワークの契約は [`ServiceLauncher`] の (e)
//! - 本番の [`NetworkProvisioner`]（`network create` と存在確認）、実 netns への接続の実機確認
//! - 本番の `DependencyObserver` / `HealthSource`（core の state.json 読み取り）
//! - CLI 結線（`cli -> stack` の依存辺はユーザー承認事項）、TOML parse の入口と入力サイズの上限検証
//! - `completed` 条件の待機（未対応として止める）、`logs`（#622）
//! - 1 サービスの複数ネットワーク（CLI の `--network` が 1 回までのため拒否）、rootful（D13 待ち）
//!
//! 外部入力の扱い: サービス名と `Service` は TOML 由来。本モジュールはシェルもパスも組み立てず
//! ポートへ渡すだけで、検証は実装側の責務（契約は [`ServiceLauncher`]）。エラーと報告には
//! `Service` の内容（`env` に資格情報を含みうる）を入れない。

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU8;
use std::time::{Duration, Instant};

use crate::depends_on::wait::{
    DependencyObserver, DependencyWaitError, SystemClock, WaitClock, WaitPolicy, WaitReport,
    wait_for_step,
};
use crate::depends_on::{
    DependsOnError, HealthSource, HealthyWaitOutcome, HealthyWaitPolicy, MonotonicClock, PollClock,
    StartupStep, plan_startup, require_healthy_dependencies,
};
use crate::schema::{DependsOnCondition, Network, Service};

mod network;

pub use network::{
    NetworkAttachment, NetworkDriver, NetworkPlan, NetworkPlanError, NetworkProvisionError,
    NetworkProvisioner, NetworkRequest, ProvisionOutcome, ProvisionedNetwork, plan_networks,
};

/// 起動の失敗（[`ServiceLauncher`] が返す）。固定文字列だけを持ち、動的な値は入れない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchError {
    code: &'static str,
    message: &'static str,
}

impl LaunchError {
    /// 機械可読な `code` と固定の英語 `message` で作る。
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

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for LaunchError {}

/// 起動したサービスの結果（アダプタが返す識別子つき）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchedService {
    service: String,
    container_id: String,
}

impl LaunchedService {
    /// サービス名と、アダプタが払い出した識別子で作る。
    pub fn new(service: impl Into<String>, container_id: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            container_id: container_id.into(),
        }
    }

    /// サービス名。
    pub fn service(&self) -> &str {
        &self.service
    }

    /// アダプタが返した識別子。
    pub fn container_id(&self) -> &str {
        &self.container_id
    }
}

/// `up` への入力（profiles で絞った services とトップレベルの networks）。
#[derive(Debug, Clone, Copy)]
pub struct UpProject<'a> {
    /// 起動対象のサービス。
    pub services: &'a BTreeMap<String, Service>,
    /// `[networks.<name>]`。
    pub networks: &'a BTreeMap<String, Network>,
}

/// [`ServiceLauncher::launch`] への要求（将来の項目追加で trait を壊さないための束）。
#[derive(Clone, Copy)]
pub struct LaunchRequest<'a> {
    service: &'a str,
    spec: &'a Service,
    network: Option<NetworkAttachment<'a>>,
}

impl fmt::Debug for LaunchRequest<'_> {
    /// `spec` は `env` に資格情報を含みうるため出さない。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaunchRequest")
            .field("service", &self.service)
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl<'a> LaunchRequest<'a> {
    /// 起動するサービス名。
    pub fn service(&self) -> &'a str {
        self.service
    }

    /// サービス定義（`env` に資格情報を含みうる。`{:?}` で出さない）。
    pub fn spec(&self) -> &'a Service {
        self.spec
    }

    /// 接続先のネットワーク。`None` なら指定なし（CLI の既定 `none`）。
    pub fn network(&self) -> Option<NetworkAttachment<'a>> {
        self.network
    }
}

/// 1 サービスの create から start までを行う入口（本番は監視プロセス起動 API〔TASK-157・SUP-1〕経由）。
///
/// 実装の契約:
/// - (a) `service` は TOML 由来の外部入力。ID・パス要素にする前に実装側で検証する（パストラバーサル防止）。
/// - (b) 返すのは今回の `up` が作ったものだけ（前回の実行の記録を返さない）。
/// - (c) ブロックする実装は短い上限を持つ（REPAIR-5）。
/// - (d) `spec` は資格情報（`env`）を含みうる。ログ・エラーへ `{:?}` で出さない。
/// - (e) `network` があれば CLI の `create` に `--network <name>`（[`NetworkAttachment::create_option_args`]）
///   を付ける。rootless かつユーザー定義名のときは、`up` の `--pasta-path` / `--pasta-path-search` を
///   `create` と同じ pasta の検証と FCOPT1 の `pasta` の記録へ通し、それ以外の組み合わせで
///   pasta のフラグが指定されたら `InvalidArgument` にする（実装は #3639）。
pub trait ServiceLauncher {
    /// `request` のサービスを起動する。成功したら識別子つきの結果を返す。
    fn launch(&mut self, request: &LaunchRequest<'_>) -> Result<LaunchedService, LaunchError>;
}

/// `up` の待ち方針（started と healthy）。
///
/// 既定値は暫定で、spec は数値を固定していない（STACK-2）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpPolicy {
    /// started 条件の待ち方針。
    pub started: WaitPolicy,
    /// healthy 条件の待ち方針。
    pub healthy: HealthyWaitPolicy,
}

/// 実時計（`wait` 用の `SystemClock` と `healthy` 用の `MonotonicClock` を束ねる）。
///
/// 状態を持つだけの小さな型で、I/O はスリープのみ。試験では偽の時計を代わりに渡す。
#[derive(Debug, Clone, Copy, Default)]
pub struct UpClock {
    system: SystemClock,
    monotonic: MonotonicClock,
}

impl UpClock {
    /// 現在を基準に作る。
    pub fn new() -> Self {
        Self::default()
    }
}

impl WaitClock for UpClock {
    fn now(&self) -> Instant {
        WaitClock::now(&self.system)
    }

    fn sleep_until(&mut self, deadline: Instant) {
        self.system.sleep_until(deadline);
    }
}

impl PollClock for UpClock {
    fn now(&self) -> Duration {
        PollClock::now(&self.monotonic)
    }

    fn sleep(&mut self, d: Duration) {
        self.monotonic.sleep(d);
    }
}

/// 1 ステップ（1 サービス）の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpStepReport {
    launched: LaunchedService,
    network: Option<String>,
    healthy: Vec<HealthyWaitOutcome>,
    started: WaitReport,
}

impl UpStepReport {
    /// 起動したサービスの結果。
    pub fn launched(&self) -> &LaunchedService {
        &self.launched
    }

    /// このステップで渡した接続先のネットワーク名。
    pub fn network(&self) -> Option<&str> {
        self.network.as_deref()
    }

    /// 起動前に待った healthy 条件の結果（依存先名の昇順）。
    pub fn healthy_waits(&self) -> &[HealthyWaitOutcome] {
        &self.healthy
    }

    /// 起動前に待った started 条件の結果。
    pub fn started_waits(&self) -> &WaitReport {
        &self.started
    }
}

/// `up` の成功結果（起動順）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UpReport {
    steps: Vec<UpStepReport>,
    networks: Vec<ProvisionedNetwork>,
}

impl UpReport {
    /// 用意したネットワーク（用意した順＝名前の昇順）。
    pub fn networks(&self) -> &[ProvisionedNetwork] {
        &self.networks
    }

    /// 起動順のステップ結果。
    pub fn steps(&self) -> &[UpStepReport] {
        &self.steps
    }

    /// 起動したサービス名（起動順）。
    pub fn service_names(&self) -> impl Iterator<Item = &str> {
        self.steps.iter().map(|s| s.launched.service())
    }
}

/// `up` のエラー。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpError {
    /// 起動順の計画に失敗した（循環・未定義の依存先）。
    Plan(DependsOnError),
    /// 依存先の待ちに失敗した（期限切れ・未対応の条件・観測失敗・方針不正）。
    Wait(DependencyWaitError),
    /// `[networks]` の検証に失敗した（起動ゼロ・用意ゼロ）。
    Network(NetworkPlanError),
    /// ネットワークの用意に失敗した（起動ゼロ）。
    NetworkProvision {
        network: String,
        source: NetworkProvisionError,
    },
    /// サービスの起動に失敗した。
    Launch {
        service: String,
        source: LaunchError,
    },
    /// 計画にあるサービスが map に無い（計画上は起きない内部不整合）。
    Internal { service: String },
}

impl UpError {
    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Plan(e) => e.code(),
            Self::Wait(e) => e.code(),
            Self::Network(e) => e.code(),
            Self::NetworkProvision { .. } => "NETWORK_PROVISION_FAILED",
            Self::Launch { .. } => "SERVICE_LAUNCH_FAILED",
            Self::Internal { .. } => "INTERNAL",
        }
    }

    /// 固定の英語メッセージ（サービス名は含めない）。
    pub fn message(&self) -> &'static str {
        match self {
            Self::Plan(e) => e.message(),
            Self::Wait(e) => e.message(),
            Self::Network(e) => e.message(),
            Self::NetworkProvision { .. } => "failed to provision a network",
            Self::Launch { .. } => "failed to launch a service",
            Self::Internal { .. } => "internal inconsistency in the startup plan",
        }
    }

    /// プロセスの非ゼロ終了コード（ERR-2）。
    ///
    /// stack は core に依存しないため、core の表（`INVALID_ARGUMENT`=2・`INTERNAL`=1 ほか）と同じ値を
    /// ここに持つ（`DependencyWaitError::exit_code` と同じ扱い）。`NonZeroU8` で 0 の失敗を表せない。
    pub fn exit_code(&self) -> NonZeroU8 {
        match self {
            Self::Plan(_) => NonZeroU8::new(2).unwrap_or(NonZeroU8::MIN),
            Self::Wait(e) => e.exit_code(),
            Self::Network(e) => e.exit_code(),
            Self::NetworkProvision { .. } | Self::Launch { .. } | Self::Internal { .. } => {
                NonZeroU8::MIN
            }
        }
    }
}

impl fmt::Display for UpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(e) => e.fmt(f),
            Self::Wait(e) => e.fmt(f),
            Self::Network(e) => e.fmt(f),
            Self::NetworkProvision { network, source } => {
                write!(f, "{}: {} ({})", self.message(), network, source.code())
            }
            Self::Launch { service, source } => {
                write!(f, "{}: {} ({})", self.message(), service, source.code())
            }
            Self::Internal { service } => write!(f, "{}: {}", self.message(), service),
        }
    }
}

impl std::error::Error for UpError {}

/// `up` の失敗。エラーと、それまでに起動したサービス名（起動順）を返す（ロールバックはしない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpFailure {
    error: UpError,
    launched: Vec<String>,
    networks: Vec<ProvisionedNetwork>,
}

impl UpFailure {
    /// 失敗までに用意したネットワーク。`down`（#620）の片付けの目安。
    pub fn networks(&self) -> &[ProvisionedNetwork] {
        &self.networks
    }

    /// 失敗の原因。
    pub fn error(&self) -> &UpError {
        &self.error
    }

    /// 失敗までに起動したサービス名（起動順）。`down`（#620）の対象の目安。
    pub fn launched(&self) -> &[String] {
        &self.launched
    }
}

impl fmt::Display for UpFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (launched: {})", self.error, self.launched.len())
    }
}

impl std::error::Error for UpFailure {}

/// `completed` 条件は未対応。部分起動してから止めないよう、起動前に全ステップを検査する。
fn precheck(steps: &[StartupStep]) -> Result<(), UpError> {
    for step in steps {
        if let Some(w) = step
            .waits()
            .iter()
            .find(|w| w.condition() == DependsOnCondition::Completed)
        {
            return Err(UpError::Wait(DependencyWaitError::UnsupportedCondition {
                service: step.service().to_string(),
                dependency: w.service().to_string(),
                condition: w.condition(),
            }));
        }
    }
    Ok(())
}

/// 依存グラフのトポロジカル順にサービスを起動し、宣言したネットワークへ接続する
/// （STACK-8・TASK-155.1・TASK-155.2）。
///
/// 順序は `plan_startup` の結果そのもの。事前検査（循環・未定義・`completed`・`[networks]`）に
/// 失敗したら何も用意も起動もしない。ネットワークの用意は最初の launch より前に名前の昇順で行う。
/// 各ステップで healthy → started の順に待ち、すべて成功したときだけ `launcher` を呼ぶ。
/// 途中失敗は最初のエラーで止める（`UpFailure` は大きいため `Box` で返す）。
pub fn up<L, N, O, H, C>(
    project: &UpProject<'_>,
    launcher: &mut L,
    provisioner: &mut N,
    observer: &mut O,
    health: &mut H,
    clock: &mut C,
    policy: &UpPolicy,
) -> Result<UpReport, Box<UpFailure>>
where
    L: ServiceLauncher,
    N: NetworkProvisioner,
    O: DependencyObserver,
    H: HealthSource,
    C: WaitClock + PollClock,
{
    let services = project.services;
    let fail = |error: UpError, launched: Vec<String>| {
        Box::new(UpFailure {
            error,
            launched,
            networks: vec![],
        })
    };
    let plan = plan_startup(services).map_err(|e| fail(UpError::Plan(e), vec![]))?;
    precheck(plan.steps()).map_err(|e| fail(e, vec![]))?;
    let net_plan =
        plan_networks(services, project.networks).map_err(|e| fail(UpError::Network(e), vec![]))?;

    let mut report = UpReport::default();
    for request in net_plan.requests() {
        match provisioner.ensure(&request) {
            Ok(p) => report.networks.push(p),
            Err(source) => {
                return Err(Box::new(UpFailure {
                    error: UpError::NetworkProvision {
                        network: request.name.to_string(),
                        source,
                    },
                    launched: vec![],
                    networks: report.networks,
                }));
            }
        }
    }

    let mut launched: Vec<String> = Vec::new();
    for step in plan.steps() {
        let name = step.service();
        let with_nets = |error: UpError, launched: Vec<String>| {
            Box::new(UpFailure {
                error,
                launched,
                networks: report.networks.clone(),
            })
        };
        let healthy = require_healthy_dependencies(step, health, clock, &policy.healthy)
            .map_err(|e| with_nets(UpError::Wait(e), launched.clone()))?;
        let started = wait_for_step(
            &step.retain_condition(DependsOnCondition::Started),
            observer,
            clock,
            &policy.started,
        )
        .map_err(|e| with_nets(UpError::Wait(e), launched.clone()))?;
        let Some(spec) = services.get(name) else {
            return Err(with_nets(
                UpError::Internal {
                    service: name.to_string(),
                },
                launched,
            ));
        };
        let attachment = net_plan.attachment_for(name);
        let result = launcher
            .launch(&LaunchRequest {
                service: name,
                spec,
                network: attachment,
            })
            .map_err(|source| {
                with_nets(
                    UpError::Launch {
                        service: name.to_string(),
                        source,
                    },
                    launched.clone(),
                )
            })?;
        launched.push(name.to_string());
        report.steps.push(UpStepReport {
            launched: result,
            network: attachment.map(|a| a.name().to_string()),
            healthy,
            started,
        });
    }
    Ok(report)
}
