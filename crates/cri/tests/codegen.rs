//! build.rs のコード生成の機械照合（TASK-56.3・#426・CRI-3・REPAIR-12）。
//!
//! 受け入れ条件「`cargo build` で `OUT_DIR` に生成コードが出る」を、生成物を文字列として読んで照合する。
//! 生成物は `include!` しない（実行時の依存は TASK-56.4〔#427〕・TASK-108.1〔#453〕まで入れないため）。

const GENERATED: &str = include_str!(concat!(env!("OUT_DIR"), "/runtime.v1.rs"));

fn assert_contains(needle: &str) {
    assert!(
        GENERATED.contains(needle),
        "generated code must contain: {needle}"
    );
}

#[test]
fn task_56_3_generated_file_is_not_empty() {
    assert!(
        GENERATED.len() > 10_000,
        "generated file too small: {}",
        GENERATED.len()
    );
}

#[test]
fn task_56_3_generates_runtime_service_server_and_client() {
    for n in [
        "pub mod runtime_service_server",
        "pub mod runtime_service_client",
        "pub trait RuntimeService",
    ] {
        assert_contains(n);
    }
}

#[test]
fn task_56_3_generates_image_service_server_and_client() {
    for n in [
        "pub mod image_service_server",
        "pub mod image_service_client",
        "pub trait ImageService",
    ] {
        assert_contains(n);
    }
}

#[test]
fn task_56_3_generates_messages() {
    for n in [
        "pub struct VersionRequest",
        "pub struct RunPodSandboxRequest",
    ] {
        assert_contains(n);
    }
}
