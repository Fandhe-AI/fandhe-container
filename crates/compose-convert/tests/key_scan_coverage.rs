//! 合成フィクスチャで `unrecognized` 0 件と 4 分類の網羅を機械照合する結合試験
//! （STACK-3・TASK-151.6・#601・REPAIR-12）。`docs/spec` は参照しない。
//!
//! 走査器 `key_scan` → `KeyOccurrences` → `FileConversionReport` の経路を外から呼ぶ。

use std::collections::BTreeSet;

use fandhe_container_compose_convert::classify::KeyClass;
use fandhe_container_compose_convert::compose_convert::parse_compose_yaml;
use fandhe_container_compose_convert::convert::{ValueDrops, convert_top_level};
use fandhe_container_compose_convert::key_scan::collect_key_occurrences;
use fandhe_container_compose_convert::report::{
    ErrorFreeBlocker, FileConversionReport, KeyOccurrences,
};

const COVERAGE: &str = include_str!("fixtures/key_coverage.yaml");
const CLEAN: &str = include_str!("fixtures/key_clean.yaml");

fn scan(yaml: &str) -> KeyOccurrences {
    collect_key_occurrences(&parse_compose_yaml(yaml).expect("fixture parses"))
}

fn unrecognized_paths(o: &KeyOccurrences) -> Vec<String> {
    o.iter()
        .filter(|(_, e)| e.class == KeyClass::Unrecognized)
        .map(|(p, _)| p.to_string())
        .collect()
}

/// STACK-3: 合成フィクスチャの集合で分類表に一致しないキーが 0 件。
#[test]
fn stack3_synthetic_fixtures_have_zero_unrecognized() {
    for (name, text) in [("key_coverage", COVERAGE), ("key_clean", CLEAN)] {
        let o = scan(text);
        assert!(!o.overflowed(), "{name}: overflowed");
        assert_eq!(
            o.unrecognized_count(),
            0,
            "{name}: unrecognized paths {:?}",
            unrecognized_paths(&o)
        );
    }
}

/// STACK-3: 4 分類がすべてフィクスチャに現れ、Unrecognized は現れない。
#[test]
fn stack3_synthetic_fixtures_cover_four_classes() {
    let mut seen = BTreeSet::new();
    for text in [COVERAGE, CLEAN] {
        for (_, e) in scan(text).iter() {
            seen.insert(e.class.as_str());
        }
    }
    let want: BTreeSet<&str> = [
        "convert",
        "warning",
        "error-incompatible",
        "error-unsupported-yet",
    ]
    .into_iter()
    .collect();
    assert_eq!(seen, want);
}

/// STACK-3・D-16: 代表的なパスの分類と出現数を具体値で照合する。
#[test]
fn stack3_key_paths_spot_check() {
    let o = scan(COVERAGE);
    let cases: [(&str, KeyClass, u64); 9] = [
        ("services.*", KeyClass::Convert, 2),
        ("services.*.image", KeyClass::Convert, 2),
        ("services.*.network_mode", KeyClass::ErrorIncompatible, 2),
        ("services.*.volumes", KeyClass::ErrorIncompatible, 2),
        ("x-common", KeyClass::Warning, 1),
        ("version", KeyClass::Warning, 1),
        ("profiles", KeyClass::ErrorUnsupportedYet, 1),
        (
            "services.*.deploy.resources.reservations.devices",
            KeyClass::Convert,
            1,
        ),
        (
            "services.*.deploy.placement",
            KeyClass::ErrorIncompatible,
            1,
        ),
    ];
    for (path, class, n) in cases {
        let e = o.get(path).unwrap_or_else(|| panic!("{path} not recorded"));
        assert_eq!((e.class, e.occurrences), (class, n), "{path}");
    }
    // 降りない段のキーは記録されない。
    for path in [
        "services.*.healthcheck.test",
        "services.*.deploy.resources.limits.cpus",
        "x-common.restart",
        "services.*.environment.ENVMARKER_NAME",
    ] {
        assert!(o.get(path).is_none(), "{path} must not be recorded");
    }
}

/// STACK-3: error-incompatible の 3 行（build・privileged・deploy.placement）がフィクスチャに現れる。
#[test]
fn stack3_incompatible_table_rows_exercised() {
    let o = scan(COVERAGE);
    for path in [
        "services.*.build",
        "services.*.privileged",
        "services.*.deploy.placement",
    ] {
        assert_eq!(
            o.get(path).map(|e| e.class),
            Some(KeyClass::ErrorIncompatible),
            "{path}"
        );
    }
}

/// STACK-3: convert と warning だけのフィクスチャは error_free と判定される。
#[test]
fn stack3_clean_fixture_is_error_free() {
    let doc = parse_compose_yaml(CLEAN).expect("fixture parses");
    let mut drops = ValueDrops::new();
    let _ = convert_top_level(&doc, &mut drops);
    let report = FileConversionReport::from_parsed(collect_key_occurrences(&doc), drops);
    let verdict = report.error_free();
    assert!(verdict.is_error_free(), "{:?}", verdict.blockers());
    assert!(verdict.blockers().is_empty());
}

/// REPAIR-12: 表に無いキーは検出される（0 件の確認が判別力を持つことの陽性対照）。
#[test]
fn stack3_unknown_key_is_detected() {
    let doc = parse_compose_yaml(
        "services:\n  a:\n    image: x\n    no_such_key: 1\nx-common:\n  foo: 1\n",
    )
    .expect("parses");
    let o = collect_key_occurrences(&doc);
    assert_eq!(o.unrecognized_count(), 1);
    assert!(o.get("x-common.foo").is_none());
    let report = FileConversionReport::from_parsed(o, ValueDrops::new());
    let verdict = report.error_free();
    assert!(!verdict.is_error_free());
    assert!(verdict.blockers().iter().any(|b| matches!(
        b,
        ErrorFreeBlocker::ErrorClassKey { key_path, class: KeyClass::Unrecognized, occurrences: 1 }
            if key_path == "services.*.no_such_key"
    )));
}

/// SEC: 記録したパスと判定にユーザー定義名・環境変数名が混ざらない。
#[test]
fn stack3_key_paths_do_not_contain_user_names() {
    let doc = parse_compose_yaml(COVERAGE).expect("parses");
    let o = collect_key_occurrences(&doc);
    let verdict_dbg = format!(
        "{:?}",
        FileConversionReport::from_parsed(o.clone(), ValueDrops::new()).error_free()
    );
    for marker in ["svcmarker", "ENVMARKER_NAME", "front", "token"] {
        assert!(o.iter().all(|(p, _)| !p.contains(marker)), "{marker}");
        assert!(!verdict_dbg.contains(marker), "{marker}");
    }
}
