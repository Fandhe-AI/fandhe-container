//! `fandhe_container_stack::schema` の公開パス経由の結合試験（STACK-1・TASK-149.2・#584・TASK-149.3・#585・TASK-149.4.1・#862・TASK-149.4.2・#863・REPAIR-12）。
//!
//! 6 テーブル（project・services・networks・volumes・secrets・configs）の読み込みと、
//! 書き出し・再読み込みの往復を具体値で照合する。parse / serialize の公開入口は
//! 後続のため、`toml` を直接使う。

use fandhe_container_stack::schema::{
    ComposeToml, Config, DependsOnCondition, Deploy, DeployResources, Healthcheck, Network,
    Project, ResourceLimits, ResourceReservations, Secret, Service, Volume,
};

const DOC: &str = r#"
[project]
name = "demo"

[services.web]
image = "example/web:1"
ports = ["8080:8080/tcp"]

[services.web.depends_on]
db = "healthy"

[services.db]
image = "example/db:1"

[networks.backend]
driver = "bridge"

[volumes.models]
driver = "io-share"
external = true

[secrets.api_key]
file = "./secrets/api_key"

[configs.app]
file = "./app.conf"
"#;

/// STACK-1: 公開パスから 6 テーブルを具体値で読める。
#[test]
fn stack_1_public_api_parses_six_tables() {
    let parsed: ComposeToml = toml::from_str(DOC).expect("valid document");

    assert_eq!(
        parsed.project,
        Some(Project {
            name: Some("demo".into())
        })
    );
    assert_eq!(parsed.services.len(), 2);
    assert_eq!(
        parsed.services.get("web"),
        Some(&Service {
            image: Some("example/web:1".into()),
            ports: vec!["8080:8080/tcp".into()],
            depends_on: [("db".to_string(), DependsOnCondition::Healthy)].into(),
            ..Service::default()
        })
    );
    assert_eq!(
        parsed.networks.get("backend"),
        Some(&Network {
            driver: Some("bridge".into()),
            external: None
        })
    );
    assert_eq!(
        parsed.volumes.get("models"),
        Some(&Volume {
            driver: Some("io-share".into()),
            external: Some(true)
        })
    );
    assert_eq!(
        parsed.secrets.get("api_key"),
        Some(&Secret {
            file: Some("./secrets/api_key".into()),
            external: None
        })
    );
    assert_eq!(
        parsed.configs.get("app"),
        Some(&Config {
            file: Some("./app.conf".into()),
            external: None
        })
    );
}

/// STACK-1: 書き出して読み直すと一致し、出力は決定的である。
#[test]
fn stack_1_public_api_roundtrip_is_stable() {
    let parsed: ComposeToml = toml::from_str(DOC).expect("valid document");
    let text = toml::to_string(&parsed).expect("serialize");
    let back: ComposeToml = toml::from_str(&text).expect("reparse");
    assert_eq!(back, parsed);
    assert_eq!(toml::to_string(&back).expect("serialize again"), text);
    assert!(
        text.contains("driver = \"io-share\""),
        "unexpected output: {text}"
    );
    assert!(
        text.contains("db = \"healthy\""),
        "unexpected output: {text}"
    );
    assert!(
        text.contains("file = \"./secrets/api_key\""),
        "unexpected output: {text}"
    );
}

/// STACK-1: 空文書は既定値で、書き出しは空文字列になる。
#[test]
fn stack_1_public_api_empty_document() {
    let parsed: ComposeToml = toml::from_str("").expect("empty document");
    assert_eq!(parsed, ComposeToml::default());
    assert_eq!(toml::to_string(&parsed).expect("serialize"), "");
}

/// STACK-1: 未知キー（トップレベル・リソース内）は拒否する。
#[test]
fn stack_1_public_api_rejects_unknown_keys() {
    assert!(toml::from_str::<ComposeToml>("profiles = [\"dev\"]").is_err());
    assert!(toml::from_str::<ComposeToml>("[secrets.k]\nfiel = \"x\"\n").is_err());
}

/// STACK-1・STACK-10・GPU-1・TASK-149.4.1: 拡張フィールドを公開パスで読み、往復できる。
#[test]
fn stack_1_public_api_service_extended_fields() {
    let doc = r#"
[services.gpu]
restart = "always"
devices = ["nvidia.com/gpu=all"]
profiles = ["gpu"]

[services.gpu.ulimits]
nofile = "1024:2048"
"#;
    let parsed: ComposeToml = toml::from_str(doc).expect("valid");
    let svc = &parsed.services["gpu"];
    assert_eq!(svc.restart.as_deref(), Some("always"));
    assert_eq!(svc.devices, vec!["nvidia.com/gpu=all".to_string()]);
    assert_eq!(svc.profiles, vec!["gpu".to_string()]);
    assert_eq!(
        svc.ulimits.get("nofile").map(String::as_str),
        Some("1024:2048")
    );
    let text = toml::to_string(&parsed).expect("serialize");
    let again: ComposeToml = toml::from_str(&text).expect("reparse");
    assert_eq!(again, parsed);
}

/// STACK-1・TASK-149.4.2(#863): 公開パスから healthcheck と入れ子の deploy.resources を読み、往復が一致する。
#[test]
fn stack_1_public_api_healthcheck_and_deploy_resources() {
    let doc = r#"
[services.gpu]
image = "example/gpu:1"

[services.gpu.healthcheck]
test = ["/bin/check"]
interval = "10s"
retries = 5

[services.gpu.deploy.resources.limits]
memory = "1G"

[services.gpu.deploy.resources.reservations]
devices = ["nvidia.com/gpu=all"]
"#;
    let parsed: ComposeToml = toml::from_str(doc).expect("parse");
    let svc = parsed.services.get("gpu").expect("gpu");
    assert_eq!(
        svc.healthcheck,
        Some(Healthcheck {
            test: Some(vec!["/bin/check".into()]),
            interval: Some("10s".into()),
            retries: Some(5),
            ..Healthcheck::default()
        })
    );
    assert_eq!(
        svc.deploy,
        Some(Deploy {
            resources: Some(DeployResources {
                limits: Some(ResourceLimits {
                    cpus: None,
                    memory: Some("1G".into()),
                }),
                reservations: Some(ResourceReservations {
                    devices: vec!["nvidia.com/gpu=all".into()],
                }),
            }),
        })
    );
    let text = toml::to_string(&parsed).expect("serialize");
    assert_eq!(
        toml::from_str::<ComposeToml>(&text).expect("reparse"),
        parsed
    );
}
