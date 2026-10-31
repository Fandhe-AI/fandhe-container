//! build: と Docker ソケット bind が外部手順の案内つきエラーになることの結合試験
//! （STACK-7・TASK-154.1・#614・D-16・REPAIR-12）。`docs/spec` は参照しない。

use fandhe_container_compose_convert::classify::{IncompatibleGuidance, KeyClass};
use fandhe_container_compose_convert::compose_convert::parse_compose_yaml;
use fandhe_container_compose_convert::convert::ValueDrops;
use fandhe_container_compose_convert::key_scan::collect_key_occurrences;
use fandhe_container_compose_convert::report::{ErrorFreeBlocker, FileConversionReport};

const FIXTURE: &str = include_str!("fixtures/build_guidance.yaml");

fn report() -> FileConversionReport {
    let doc = parse_compose_yaml(FIXTURE).expect("fixture parses");
    FileConversionReport::from_parsed(collect_key_occurrences(&doc), ValueDrops::new())
}

fn blocker(r: &FileConversionReport, path: &str) -> (u64, Option<IncompatibleGuidance>) {
    r.error_free()
        .blockers()
        .iter()
        .find_map(|b| match b {
            ErrorFreeBlocker::ErrorClassKey {
                key_path,
                class: KeyClass::ErrorIncompatible,
                occurrences,
                guidance,
            } if key_path == path => Some((*occurrences, *guidance)),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no blocker for {path}"))
}

/// STACK-7: build を含むフィクスチャは案内つきのエラーになる。
#[test]
fn stack7_build_fixture_errors_with_guidance() {
    let r = report();
    assert!(!r.error_free().is_error_free());
    let (n, g) = blocker(&r, "services.*.build");
    assert_eq!(n, 2);
    let g = g.expect("guidance");
    assert_eq!(g.code(), "external-build");
    assert!(g.message().contains("image"));
    assert!(g.message().contains("external tool"));
}

/// STACK-7・D-16: short / long のソケット bind はどちらも案内つき。
#[test]
fn stack7_socket_binds_error_with_guidance() {
    let r = report();
    let (n, g) = blocker(&r, "services.*.volumes");
    assert_eq!(n, 2);
    assert_eq!(g, Some(IncompatibleGuidance::DockerSocket));
    assert_eq!(blocker(&r, "services.*.privileged").1, None);
}

/// SEC: 案内と判定にサービス名・build context が漏れない。
#[test]
fn stack7_guidance_does_not_leak_values() {
    let dbg = format!("{:?}", report().error_free());
    for marker in ["buildsvcmarker", "ctxmarker", "shortsock", "longsock"] {
        assert!(!dbg.contains(marker), "{marker}");
    }
}
