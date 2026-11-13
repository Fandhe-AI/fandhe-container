//! `up` の入力側の部品の結合試験（STACK-8・STACK-1・CLI-4・SEC-1・REPAIR-12・TASK-155・#3639）。
//!
//! 公開 API だけで、TOML の読み込み（`parse_compose_toml`）から `ProjectName` /
//! `ServiceContainerId` の生成、`create_argv` / `start_argv` の組み立てまでを通し、
//! 具体的な引数列と不正入力の拒否を照合する。実プロセスを起動しないため既定のテスト集合で走る。

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use fandhe_container_stack::cli::up::{
    CreateArgsError, CreateArgvContext, IdentityError, ProjectName, ServiceContainerId,
    create_argv, start_argv,
};
use fandhe_container_stack::toml_input::{
    MAX_STACK_TOML_BYTES, TomlInputError, parse_compose_toml,
};

const STACK: &str = r#"
[project]
name = "shop"

[services.web]
image = "example/web:1"
tmpfs = ["/run"]
ports = ["8080:80"]
shm_size = "64m"
[services.web.env]
MODE = "-prod"
[services.web.ulimits]
nofile = "1024:2048"

[services.bad]
image = "example/bad:1"
security_opt = ["seccomp=unconfined"]

[services.cmd]
image = "example/cmd:1"
command = ["sh"]

[services.vol]
image = "example/vol:1"
volumes = ["a:/b"]
"#;

fn root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from("C:\\store")
    } else {
        PathBuf::from("/store")
    }
}

fn strs(v: &[OsString]) -> Vec<String> {
    v.iter().map(|s| s.to_string_lossy().into_owned()).collect()
}

fn run(name: &str) -> Result<(ServiceContainerId, Vec<OsString>), CreateArgsError> {
    let stack = parse_compose_toml(STACK).expect("fixture parses");
    let project = ProjectName::new("shop").expect("project name is valid");
    let id = ServiceContainerId::derive(&project, name).expect("service name is valid");
    let bundle = root().join("b");
    let image_root = root();
    let ctx = CreateArgvContext {
        id: &id,
        project_dir: Path::new("proj"),
        bundle: &bundle,
        image_root: &image_root,
        unpack: false,
    };
    let argv = create_argv(&stack.services[name], None, &ctx)?;
    Ok((id, argv))
}

#[test]
fn stack8_toml_to_create_and_start_argv_is_exact() {
    let (id, argv) = run("web").unwrap();
    let bundle = root().join("b");
    let want: Vec<String> = [
        "create",
        "--env",
        "MODE=-prod",
        "--ulimit",
        "nofile=1024:2048",
        "--shm-size",
        "64m",
        "--tmpfs",
        "/run",
        "--publish",
        "8080:80",
        "--bundle",
        &bundle.to_string_lossy(),
        "--image-root",
        &root().to_string_lossy(),
        "--image",
        "example/web:1",
        "--",
        "shop.web",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    assert_eq!(strs(&argv), want);
    assert_eq!(id.as_str(), "shop.web");
    assert_eq!(strs(&start_argv(&id)), ["start", "--", "shop.web"]);
}

#[test]
fn sec1_weakening_security_opt_and_unsupported_fields_are_rejected() {
    let err = run("bad").unwrap_err();
    assert_eq!(
        err,
        CreateArgsError::Invalid {
            field: "security_opt"
        }
    );
    assert_eq!((err.code(), err.exit_code().get()), ("INVALID_ARGUMENT", 2));
    // command は bundle の config.json へ入るため create の argv では拒否されない（#4638）。
    assert!(run("cmd").is_ok());
    let err = run("vol").unwrap_err();
    assert_eq!(err, CreateArgsError::Unsupported { field: "volumes" });
    assert_eq!((err.code(), err.exit_code().get()), ("UNIMPLEMENTED", 8));
}

#[test]
fn stack8_invalid_names_and_toml_are_rejected() {
    for bad in ["", "Shop", "a.b", "-a", "a/b", "a b"] {
        assert_eq!(
            ProjectName::new(bad),
            Err(IdentityError::InvalidProject),
            "{bad:?}"
        );
    }
    let project = ProjectName::new("shop").unwrap();
    for bad in ["", "web/1", "../x", "a b"] {
        assert_eq!(
            ServiceContainerId::derive(&project, bad),
            Err(IdentityError::InvalidService),
            "{bad:?}"
        );
    }
    assert_eq!(
        parse_compose_toml("[services.x]\nunknown_key = 1\n").unwrap_err(),
        TomlInputError::Syntax
    );
    let huge = " ".repeat(MAX_STACK_TOML_BYTES + 1);
    assert_eq!(
        parse_compose_toml(&huge).unwrap_err(),
        TomlInputError::TooLarge
    );
}

// ---- `up()` を偽のポートで駆動する（R8・#4638） ----

use std::cell::RefCell;
use std::rc::Rc;

use fandhe_container_stack::cli::up::{
    LaunchError, LaunchRequest, LaunchedService, NetworkProvisionError, NetworkProvisioner,
    NetworkRequest, ProvisionOutcome, ProvisionedNetwork, ServiceLauncher, UpClock, UpPolicy,
    UpProject, up,
};
use fandhe_container_stack::depends_on::wait::{
    DependencyObservation, DependencyObserver, ObserveError,
};
use fandhe_container_stack::depends_on::{HealthSource, HealthSourceError, ObservedHealth};

const ORDERED: &str = r#"
[networks.backend]

[services.web]
image = "example/web:1"
networks = ["backend"]
[services.web.depends_on]
db = "started"

[services.db]
image = "example/db:1"
networks = ["backend"]
"#;

/// 呼ばれた順に create / start の argv を記録する偽の launcher。`fail_on` のサービスは失敗する。
struct Recorder {
    project: ProjectName,
    calls: Vec<Vec<String>>,
    fail_on: Option<&'static str>,
    started: Rc<RefCell<Vec<String>>>,
}

impl ServiceLauncher for Recorder {
    fn launch(&mut self, request: &LaunchRequest<'_>) -> Result<LaunchedService, LaunchError> {
        let id = ServiceContainerId::derive(&self.project, request.service()).expect("id");
        let bundle = root().join("b");
        let image_root = root();
        let ctx = CreateArgvContext {
            id: &id,
            project_dir: Path::new("proj"),
            bundle: &bundle,
            image_root: &image_root,
            unpack: true,
        };
        if self.fail_on == Some(request.service()) {
            return Err(LaunchError::new("INTERNAL", "boom")
                .with_exit_code(std::num::NonZeroU8::new(3).unwrap()));
        }
        let c = create_argv(request.spec(), request.network(), &ctx)
            .map_err(|e| e.to_launch_error())?;
        self.calls.push(strs(&c));
        self.calls.push(strs(&start_argv(&id)));
        self.started.borrow_mut().push(request.service().to_owned());
        Ok(LaunchedService::new(request.service(), id.as_str()))
    }
}

struct Net;
impl NetworkProvisioner for Net {
    fn ensure(
        &mut self,
        r: &NetworkRequest<'_>,
    ) -> Result<ProvisionedNetwork, NetworkProvisionError> {
        Ok(ProvisionedNetwork::new(r.name, ProvisionOutcome::Created))
    }
}

/// 起動済みのサービスだけ Running と観測する（今回の up が作ったものに限る契約）。
struct Obs(Rc<RefCell<Vec<String>>>);
impl DependencyObserver for Obs {
    fn observe(&mut self, s: &str) -> Result<DependencyObservation, ObserveError> {
        Ok(if self.0.borrow().iter().any(|x| x == s) {
            DependencyObservation::Running
        } else {
            DependencyObservation::Absent
        })
    }
}
struct NoHealth;
impl HealthSource for NoHealth {
    fn observe(&mut self, _: &str) -> Result<Option<ObservedHealth>, HealthSourceError> {
        Ok(None)
    }
}

type Driven = (Result<Vec<Vec<String>>, (String, u8)>, Vec<String>);

fn drive(fail_on: Option<&'static str>) -> Driven {
    let stack = parse_compose_toml(ORDERED).expect("parse");
    let started = Rc::new(RefCell::new(Vec::new()));
    let mut launcher = Recorder {
        project: ProjectName::new("shop").unwrap(),
        calls: vec![],
        fail_on,
        started: started.clone(),
    };
    let project = UpProject {
        services: &stack.services,
        networks: &stack.networks,
    };
    let mut clock = UpClock::new();
    let r = up(
        &project,
        &mut launcher,
        &mut Net,
        &mut Obs(started.clone()),
        &mut NoHealth,
        &mut clock,
        &UpPolicy::default(),
    );
    let out = match r {
        Ok(_) => Ok(launcher.calls.clone()),
        Err(f) => Err((f.error().code().to_owned(), f.error().exit_code().get())),
    };
    let order = started.borrow().clone();
    (out, order)
}

/// STACK-8・STACK-2・#4638: 依存順（db → web）に create / start の argv が並び、ネットワークが付く。
#[test]
fn stack8_4638_up_creates_and_starts_in_dependency_order() {
    let (r, order) = drive(None);
    let calls = r.expect("up");
    assert_eq!(order, ["db", "web"]);
    assert_eq!(calls[0].last().map(String::as_str), Some("shop.db"));
    assert_eq!(calls[1], ["start", "--", "shop.db"]);
    assert_eq!(calls[2].last().map(String::as_str), Some("shop.web"));
    assert_eq!(calls[3], ["start", "--", "shop.web"]);
    for create in [&calls[0], &calls[2]] {
        let at = create
            .iter()
            .position(|a| a == "--network")
            .expect("network");
        assert_eq!(create[at + 1], "backend");
        assert!(create.iter().any(|a| a == "--unpack"));
    }
}

/// STACK-8・ERR-2・#4638: create の失敗で以降は呼ばれず、子の終了コードが UpError に運ばれる。
#[test]
fn stack8_4638_up_stops_at_first_failure_and_carries_exit_code() {
    let (r, order) = drive(Some("db"));
    let (code, exit) = r.expect_err("fails");
    assert_eq!((code.as_str(), exit), ("SERVICE_LAUNCH_FAILED", 3));
    assert!(order.is_empty());
}
