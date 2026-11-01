//! `up` のネットワーク接続の結合試験（STACK-8・TASK-155.2・#619・NET-6・REPAIR-12）。
//!
//! 公開 API（`cli::up` と注入ポート）だけで、(1) 各サービスの launch に渡る接続指示が
//! `[services.x].networks` のとおりであること、(2) 接続先が launch より前に用意済みであること、
//! (3) 検証・用意の失敗では起動ゼロであること、(4) 秘密値が出ないことを偽の世界で具体値照合する。
//! 実プロセスを起動しないため既定のテスト集合で走り、実機前提テストへの分離は不要。
//!
//! 範囲外（#3639 で追跡）: 実 netns / pasta への接続の確認。本番 launcher が入った後に
//! cli の rootless + pasta の実機前提試験で行う（必要環境: Linux・非 root・pasta・AppArmor の緩和。
//! STACK-8・NET-9）。

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::time::{Duration, Instant};

use fandhe_container_stack::cli::{
    LaunchError, LaunchRequest, LaunchedService, NetworkProvisionError, NetworkProvisioner,
    NetworkRequest, ProvisionOutcome, ProvisionedNetwork, ServiceLauncher, UpFailure, UpPolicy,
    UpProject, UpReport, up,
};
use fandhe_container_stack::depends_on::wait::{
    DependencyObservation, DependencyObserver, ObserveError, WaitClock, WaitPolicy,
};
use fandhe_container_stack::depends_on::{
    HealthSource, HealthSourceError, HealthyWaitPolicy, ObservedHealth, PollClock,
};
use fandhe_container_stack::schema::ComposeToml;

const NETWORKED: &str = include_str!("../testdata/up_network.toml");

/// 仮想時計。待ちは発生しないが trait を満たすために必要。
struct Clk(Instant);
impl PollClock for Clk {
    fn now(&self) -> Duration {
        Duration::ZERO
    }
    fn sleep(&mut self, _: Duration) {}
}
impl WaitClock for Clk {
    fn now(&self) -> Instant {
        self.0
    }
    fn sleep_until(&mut self, _: Instant) {}
}

/// すべての依存先が即座に running / healthy。
struct Ready;
impl DependencyObserver for Ready {
    fn observe(&mut self, _: &str) -> Result<DependencyObservation, ObserveError> {
        Ok(DependencyObservation::Running)
    }
}
impl HealthSource for Ready {
    fn observe(&mut self, _: &str) -> Result<Option<ObservedHealth>, HealthSourceError> {
        Ok(Some(ObservedHealth::Healthy))
    }
}

/// 用意したネットワークと launch の記録（launcher と provisioner の兼用）。
#[derive(Default)]
struct World {
    provisioned: Vec<(String, bool)>,
    fail_on: Option<&'static str>,
    attached: BTreeMap<String, Option<String>>,
    args: BTreeMap<String, Vec<OsString>>,
    launch_order: Vec<String>,
    /// launch 時点で接続先が用意済みでなかった組。
    violations: Vec<String>,
}

struct Net<'a>(&'a std::cell::RefCell<World>);
impl NetworkProvisioner for Net<'_> {
    fn ensure(
        &mut self,
        req: &NetworkRequest<'_>,
    ) -> Result<ProvisionedNetwork, NetworkProvisionError> {
        let mut w = self.0.borrow_mut();
        if w.fail_on == Some(req.name) {
            return Err(NetworkProvisionError::new("TEST_PROVISION", "test failure"));
        }
        w.provisioned.push((req.name.to_string(), req.external));
        let outcome = if req.external {
            ProvisionOutcome::External
        } else {
            ProvisionOutcome::Created
        };
        Ok(ProvisionedNetwork::new(req.name, outcome))
    }
}
struct Launch<'a>(&'a std::cell::RefCell<World>);
impl ServiceLauncher for Launch<'_> {
    fn launch(&mut self, req: &LaunchRequest<'_>) -> Result<LaunchedService, LaunchError> {
        let mut w = self.0.borrow_mut();
        let net = req.network().map(|a| a.name().to_string());
        if let Some(n) = &net {
            if !w.provisioned.iter().any(|(p, _)| p == n) {
                w.violations.push(format!("{}:{n}", req.service()));
            }
            let args = req.network().map(|a| a.create_option_args());
            w.args
                .insert(req.service().to_string(), args.unwrap_or_default());
        }
        w.attached.insert(req.service().to_string(), net);
        w.launch_order.push(req.service().to_string());
        Ok(LaunchedService::new(req.service(), "id"))
    }
}

fn policy() -> UpPolicy {
    UpPolicy {
        started: WaitPolicy::new(Duration::from_millis(100), Duration::from_secs(1)).unwrap(),
        healthy: HealthyWaitPolicy::new(Duration::from_millis(100), Duration::from_secs(1))
            .unwrap(),
    }
}

fn run(src: &str, world: World) -> (Result<UpReport, Box<UpFailure>>, World) {
    let parsed: ComposeToml = toml::from_str(src).unwrap();
    let cell = std::cell::RefCell::new(world);
    let result = up(
        &UpProject {
            services: &parsed.services,
            networks: &parsed.networks,
        },
        &mut Launch(&cell),
        &mut Net(&cell),
        &mut Ready,
        &mut Ready,
        &mut Clk(Instant::now()),
        &policy(),
    );
    (result, cell.into_inner())
}

fn assert_nothing_happened(w: &World) {
    assert!(w.provisioned.is_empty(), "provisioned: {:?}", w.provisioned);
    assert!(w.launch_order.is_empty(), "launched: {:?}", w.launch_order);
}

/// STACK-8・TASK-155.2: 接続指示が宣言どおりで、接続先は launch より前に用意済み（受け入れ条件 A）。
#[test]
fn stack_8_up_attaches_services_to_declared_networks() {
    let (res, w) = run(NETWORKED, World::default());
    let report = res.unwrap();
    let expect: BTreeMap<String, Option<String>> = [
        ("api", Some("backend")),
        ("cache", Some("shared")),
        ("db", Some("backend")),
        ("web", Some("frontend")),
        ("worker", None),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.map(str::to_string)))
    .collect();
    assert_eq!(w.attached, expect);
    // 名前の昇順で、各ネットワークをちょうど 1 回だけ用意する（未参照の unused は用意しない）。
    assert_eq!(
        w.provisioned,
        vec![
            ("backend".to_string(), false),
            ("frontend".to_string(), false),
            ("shared".to_string(), true),
        ]
    );
    assert!(w.violations.is_empty(), "{:?}", w.violations);
    assert_eq!(
        w.args.get("api"),
        Some(&vec![
            OsString::from("--network"),
            OsString::from("backend")
        ])
    );
    assert!(!w.args.contains_key("worker"));
    let got: Vec<_> = report
        .networks()
        .iter()
        .map(|n| (n.name(), n.outcome()))
        .collect();
    assert_eq!(
        got,
        vec![
            ("backend", ProvisionOutcome::Created),
            ("frontend", ProvisionOutcome::Created),
            ("shared", ProvisionOutcome::External),
        ]
    );
    let steps: BTreeSet<_> = report
        .steps()
        .iter()
        .map(|s| (s.launched().service(), s.network()))
        .collect();
    assert!(steps.contains(&("worker", None)));
    assert!(steps.contains(&("web", Some("frontend"))));
    // 起動順は依存順（db → api → web、db → worker）を保つ。
    let pos = |n: &str| w.launch_order.iter().position(|x| x == n).unwrap();
    assert!(pos("db") < pos("api") && pos("api") < pos("web") && pos("db") < pos("worker"));
}

/// STACK-8: external は存在確認の要求として渡り、結果は External。
#[test]
fn stack_8_external_network_is_not_created() {
    let (res, w) = run(NETWORKED, World::default());
    let report = res.unwrap();
    assert!(w.provisioned.contains(&("shared".to_string(), true)));
    let shared = report
        .networks()
        .iter()
        .find(|n| n.name() == "shared")
        .unwrap();
    assert_eq!(shared.outcome(), ProvisionOutcome::External);
}

/// STACK-8: 参照されない定義は用意しない。
#[test]
fn stack_8_unreferenced_network_is_not_provisioned() {
    let (_, w) = run(NETWORKED, World::default());
    assert!(!w.provisioned.iter().any(|(n, _)| n == "unused"));
}

fn single(net_lines: &str, svc_net: &str) -> String {
    format!(
        "[services.a]\nimage = \"x\"\nnetworks = [{svc_net}]\n[services.b]\nimage = \"x\"\n{net_lines}"
    )
}

/// STACK-8: 未定義の参照は起動ゼロ・用意ゼロ（終了コード 2）。
#[test]
fn stack_8_undefined_network_launches_nothing() {
    let (res, w) = run(&single("", "\"nope\""), World::default());
    let f = res.unwrap_err();
    assert_eq!(f.error().code(), "NETWORK_NOT_DEFINED");
    assert_eq!(f.error().exit_code().get(), 2);
    assert_nothing_happened(&w);
}

/// STACK-8: 2 件以上は起動ゼロ（終了コード 8）。
#[test]
fn stack_8_multiple_networks_launches_nothing() {
    let (res, w) = run(
        &single("[networks.n]\n[networks.m]\n", "\"n\", \"m\""),
        World::default(),
    );
    let f = res.unwrap_err();
    assert_eq!(f.error().code(), "MULTIPLE_NETWORKS_UNSUPPORTED");
    assert_eq!(f.error().exit_code().get(), 8);
    assert_nothing_happened(&w);
}

/// STACK-8: 未対応 driver は起動ゼロ（終了コード 8）。
#[test]
fn stack_8_unsupported_driver_launches_nothing() {
    let (res, w) = run(
        &single("[networks.n]\ndriver = \"overlay\"\n", "\"n\""),
        World::default(),
    );
    let f = res.unwrap_err();
    assert_eq!(f.error().code(), "NETWORK_DRIVER_UNSUPPORTED");
    assert_eq!(f.error().exit_code().get(), 8);
    assert_nothing_happened(&w);
}

/// STACK-8: 予約名（host）は起動ゼロ（終了コード 2）。
#[test]
fn stack_8_reserved_network_name_launches_nothing() {
    let (res, w) = run(&single("[networks.host]\n", "\"host\""), World::default());
    let f = res.unwrap_err();
    assert_eq!(f.error().code(), "INVALID_NETWORK_NAME");
    assert_eq!(f.error().exit_code().get(), 2);
    assert_nothing_happened(&w);
}

/// STACK-8: 用意の失敗は起動ゼロで、用意済み分を報告する。
#[test]
fn stack_8_provision_failure_launches_nothing_and_reports_created() {
    let world = World {
        fail_on: Some("frontend"),
        ..World::default()
    };
    let (res, w) = run(NETWORKED, world);
    let f = res.unwrap_err();
    assert_eq!(f.error().code(), "NETWORK_PROVISION_FAILED");
    assert_eq!(f.error().exit_code().get(), 1);
    assert!(w.launch_order.is_empty());
    let got: Vec<_> = f
        .networks()
        .iter()
        .map(|n| (n.name(), n.outcome()))
        .collect();
    assert_eq!(got, vec![("backend", ProvisionOutcome::Created)]);
    assert!(f.launched().is_empty());
}

/// STACK-8・SEC-1: ネットワーク系のエラーと LaunchRequest の Debug に env の秘密値が出ない。
#[test]
fn stack_8_network_error_does_not_leak_service_env() {
    let src = "[services.a]\nimage = \"x\"\nnetworks = [\"nope\"]\n\
               [services.a.env]\nTOKEN = \"DUMMY_SECRET_VALUE\"\n";
    let (res, _) = run(src, World::default());
    let f = res.unwrap_err();
    let text = format!("{f} {f:?} {}", f.error());
    assert!(!text.contains("DUMMY_SECRET_VALUE"), "{text}");

    let ok = "[services.a]\nimage = \"x\"\nnetworks = [\"n\"]\n[networks.n]\n\
              [services.a.env]\nTOKEN = \"DUMMY_SECRET_VALUE\"\n";
    let parsed: ComposeToml = toml::from_str(ok).unwrap();
    let plan =
        fandhe_container_stack::cli::plan_networks(&parsed.services, &parsed.networks).unwrap();
    assert_eq!(plan.attachment_for("a").unwrap().name(), "n");
}
