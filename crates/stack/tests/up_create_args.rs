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
    let err = run("cmd").unwrap_err();
    assert_eq!(err, CreateArgsError::Unsupported { field: "command" });
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
