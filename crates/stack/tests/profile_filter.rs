//! `--profile` 引数・環境変数解析の結合試験（STACK-10・TASK-187.1・#631・REPAIR-12）。
//!
//! 公開 API だけで、引数による環境変数の上書き・返却集合の照合・不正入力の構造化エラー
//! （code / message / exit_code）を具体値で確認する。範囲外: サービスの判定（#632）・CLI 結線（#3639）。

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
