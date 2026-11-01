//! `--profile` 引数・環境変数解析の結合試験（STACK-10・TASK-187.1・#631・REPAIR-12）。
//!
//! 公開 API だけで、引数による環境変数の上書き・返却集合の照合・不正入力の構造化エラー
//! （code / message / exit_code）を具体値で確認する。サービスの判定（#632）は末尾の試験。範囲外: CLI 結線（#3639）。

use std::ffi::OsStr;

use fandhe_container_stack::profile_filter::{
    ActiveProfiles, ProfileArgError, ProfileLimit, ProfileOrigin, resolve_active_profiles,
};

fn run(flags: &[&str], env: Option<&str>) -> Result<ActiveProfiles, ProfileArgError> {
    resolve_active_profiles(flags.iter().map(OsStr::new), env.map(OsStr::new))
}

#[test]
fn stack_10_flags_override_env_through_public_api() {
    let set = run(&["dev", "debug"], Some("prod,other")).unwrap();
    assert_eq!(set.len(), 2);
    assert!(set.contains("dev"));
    assert!(set.contains("debug"));
    assert!(!set.contains("prod"));
    assert!(!set.contains("other"));
    assert_eq!(set.iter().collect::<Vec<_>>(), ["debug", "dev"]);
}

#[test]
fn stack_10_env_used_when_no_flags() {
    let set = run(&[], Some("dev, debug ,,dev")).unwrap();
    assert_eq!(set.len(), 2);
    assert!(set.contains("dev"));
    assert!(set.contains("debug"));
    assert!(!set.contains("prod"));
}

#[test]
fn stack_10_empty_when_nothing_given() {
    assert!(run(&[], None).unwrap().is_empty());
    assert!(run(&[], Some(" , ")).unwrap().is_empty());
}

#[test]
fn stack_10_invalid_name_is_structured_error() {
    let err = run(&["bad name"], None).unwrap_err();
    assert_eq!(
        err,
        ProfileArgError::InvalidName {
            origin: ProfileOrigin::Flag,
            index: 0
        }
    );
    assert_eq!(err.code(), "INVALID_PROFILE_NAME");
    assert_eq!(err.message(), "invalid profile name");
    assert_eq!(err.exit_code().get(), 2);
    assert_eq!(err.to_string(), "invalid profile name: --profile #0");

    let err = run(&[], Some("ok1,*")).unwrap_err();
    assert_eq!(
        err,
        ProfileArgError::InvalidName {
            origin: ProfileOrigin::Env,
            index: 1
        }
    );
}

#[test]
fn stack_10_limit_exceeded_is_structured_error() {
    let long = "a".repeat(65);
    let err = run(&[&long], None).unwrap_err();
    assert_eq!(
        err,
        ProfileArgError::LimitExceeded {
            limit: ProfileLimit::NameBytes
        }
    );
    assert_eq!(err.code(), "PROFILE_LIMIT_EXCEEDED");
    assert_eq!(err.message(), "profile limit exceeded");
    assert_eq!(err.exit_code().get(), 2);
}

#[cfg(unix)]
#[test]
fn stack_10_non_utf8_is_structured_error() {
    use std::os::unix::ffi::OsStrExt;
    let bad = OsStr::from_bytes(&[0x66, 0xff]);
    let err = resolve_active_profiles([bad], None).unwrap_err();
    assert_eq!(
        err,
        ProfileArgError::NotUtf8 {
            origin: ProfileOrigin::Flag,
            index: 0
        }
    );
    assert_eq!(err.code(), "PROFILE_NOT_UTF8");
    assert_eq!(err.message(), "profile value is not valid UTF-8");
}
mod enabled_services {
    use std::ffi::OsStr;

    use fandhe_container_stack::profile_filter::{
        ServiceSelectError, resolve_active_profiles, select_enabled_services,
    };
    use fandhe_container_stack::schema::ComposeToml;

    const TOML: &str = r#"
[services.web]
image = "web:1"

[services.debug]
image = "dbg:1"
profiles = ["dbg"]

[services.trace]
image = "trace:1"
profiles = ["dbg"]

[services.dev]
image = "dev:1"
profiles = ["dev"]
"#;

    fn project() -> ComposeToml {
        toml::from_str(TOML).unwrap()
    }

    fn names(flags: &[&str], targets: &[&str]) -> Result<Vec<String>, ServiceSelectError> {
        let p = project();
        let active = resolve_active_profiles(flags.iter().map(OsStr::new), None).unwrap();
        let e = select_enabled_services(&p.services, &active, targets.iter().copied())?;
        Ok(e.select(&p.services).into_keys().collect())
    }

    #[test]
    fn stack_10_no_flags_no_targets_only_profileless() {
        assert_eq!(names(&[], &[]).unwrap(), ["web"]);
    }

    #[test]
    fn stack_10_profile_flag_enables_matching() {
        assert_eq!(names(&["dev"], &[]).unwrap(), ["dev", "web"]);
    }

    #[test]
    fn stack_10_target_profiles_join_active_set() {
        assert_eq!(names(&[], &["debug"]).unwrap(), ["debug", "trace", "web"]);
    }

    #[test]
    fn stack_10_unknown_target_is_structured_error() {
        let err = names(&[], &["nope"]).unwrap_err();
        assert_eq!(err.code(), "UNKNOWN_SERVICE");
        assert_eq!(err.exit_code().get(), 2);
    }
}
