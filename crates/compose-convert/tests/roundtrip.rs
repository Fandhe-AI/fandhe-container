//! `ComposeToml` の往復検証（STACK-5・TASK-152.1・#605・MS-12。計測は STACK-4 の #606）。
//!
//! 役割: 変換直後の `ComposeToml`（`out`）を TOML に直列化して再パースした `rt` が `rt == out` になることを、
//! 既定モードと `--downgrade` モードの合成フィクスチャで確かめる。対象は前提（エラー分類キー 0 件・
//! unrecognized 0 件・`value_drops` 0 件。格下げモードは許可したキーを除く）を満たすファイルだけで、
//! 満たさないファイルは対象に数えない（件数 0 や陰性対照の素通りを具体値で防ぐ）。
//!
//! 呼び出す公開 API の流れは `entry` と同じ: `load_input_dir` → `parse_compose_yaml` →
//! `collect_key_occurrences` / `convert_top_level` → `FileConversionReport`。ディレクトリ単位で回すので、
//! フィクスチャを置き換えれば同じ判定を流用できる。実コーパス（14 件）での実行と妥当性判断は #607（人間担当）。
//! 既定フィクスチャは `depends_on`・`ulimits`・`healthcheck`・`deploy`（GPU 予約）が変換器へ未結線のため
//! 「全対象キー＋GPU」を網羅していない（REPAIR-3。結線後に足す）。
//! 失敗メッセージには TOML 本文・値を出さない（env の値が入りうるため。SEC-1）。

use std::path::PathBuf;

use fandhe_container_compose_convert::classify::{KeyClass, classify_key_path};
use fandhe_container_compose_convert::compose_convert::parse_compose_yaml;
use fandhe_container_compose_convert::convert::{ValueDrops, convert_top_level};
use fandhe_container_compose_convert::downgrade::{DowngradeSet, parse_downgrade_value};
use fandhe_container_compose_convert::input_scan::load_input_dir;
use fandhe_container_compose_convert::key_scan::collect_key_occurrences;
use fandhe_container_compose_convert::report::FileConversionReport;
use fandhe_container_stack::schema::ComposeToml;

fn fixture_dir(parts: &[&str]) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for part in ["tests", "fixtures", "roundtrip"].iter().chain(parts) {
        p = p.join(part);
    }
    p
}

fn convert_one(text: &str) -> (FileConversionReport, ComposeToml) {
    let doc = parse_compose_yaml(text).expect("fixture must parse");
    let mut drops = ValueDrops::new();
    let out = convert_top_level(&doc, &mut drops);
    let report = FileConversionReport::from_parsed(collect_key_occurrences(&doc), drops);
    (report, out)
}

/// 直列化して再パースする。失敗は種別だけを出す。
fn roundtrip(out: &ComposeToml) -> ComposeToml {
    let text = toml::to_string(out).expect("serialize must succeed");
    toml::from_str::<ComposeToml>(&text).expect("reparse must succeed")
}

/// 前提（往復検証の対象か）の判定。格下げモードでは許可集合を渡す。
fn is_target(report: &FileConversionReport, set: Option<&DowngradeSet>) -> bool {
    let verdict = match set {
        Some(s) => report.error_free_with_downgrade(s),
        None => report.error_free(),
    };
    verdict.is_error_free()
        && report.value_drops.is_empty()
        && report.key_occurrences.unrecognized_count() == 0
}

#[derive(Debug, PartialEq, Eq)]
struct Summary {
    files: usize,
    targets: usize,
    passed: usize,
}

fn run_dir(parts: &[&str], mode: &str, set: Option<&DowngradeSet>) -> Summary {
    let inputs = load_input_dir(&fixture_dir(parts)).expect("fixture dir must load");
    let mut s = Summary {
        files: inputs.len(),
        targets: 0,
        passed: 0,
    };
    for input in &inputs {
        let (report, out) = convert_one(input.text());
        if !is_target(&report, set) {
            continue;
        }
        s.targets += 1;
        if roundtrip(&out) == out {
            s.passed += 1;
        } else {
            eprintln!("roundtrip mismatch: file={}", input.path().display());
        }
    }
    println!(
        "roundtrip: mode={mode} files={} targets={} passed={}",
        s.files, s.targets, s.passed
    );
    s
}

fn default_fixture() -> (FileConversionReport, ComposeToml) {
    let text = include_str!("fixtures/roundtrip/default/synthetic-full-coverage.yaml");
    convert_one(text)
}

/// 既定モードの合成フィクスチャ 1 件で往復が 100% 成功し、変換結果が空でないこと。
/// STACK-5・TASK-152.1・#605。
#[test]
fn stack5_605_default_mode_synthetic_fixture_roundtrip() {
    let s = run_dir(&["default"], "default", None);
    assert_eq!(
        s,
        Summary {
            files: 1,
            targets: 1,
            passed: 1
        }
    );

    let (_, out) = default_fixture();
    assert_ne!(out, ComposeToml::default());
    assert_eq!(out.services.len(), 2);
    assert_eq!(
        out.project.as_ref().and_then(|p| p.name.as_deref()),
        Some("roundtrip-sample")
    );
    let web = &out.services["web"];
    assert_eq!(web.image.as_deref(), Some("example.invalid/web:1"));
    assert_eq!(
        web.command.as_deref(),
        Some(&["serve".to_string(), "--port".into(), "80".into()][..])
    );
    assert_eq!(web.env.len(), 2);
    assert_eq!(web.labels.len(), 2);
    assert_eq!(web.ports.len(), 2);
    assert_eq!(web.volumes.len(), 2);
    assert_eq!(web.devices, vec!["nvidia.com/gpu=0".to_string()]);
    assert_eq!(out.services["worker"].command.as_deref(), Some(&[][..]));
    assert_eq!(out.networks.len(), 1);
    assert_eq!(out.volumes.len(), 2);
    assert_eq!(out.secrets.len(), 1);
    assert_eq!(out.configs.len(), 1);
}

/// 既定フィクスチャの全キーが convert か warning であること（分類が動いたら原因が分かる失敗にする）。
/// STACK-5・TASK-152.1・#605。
#[test]
fn stack5_605_default_fixture_keys_are_convert_or_warning() {
    let (report, _) = default_fixture();
    let mut n = 0;
    for (path, e) in report.key_occurrences.iter() {
        assert!(!e.class.is_error(), "{path}: reclassified as error");
        n += 1;
    }
    assert!(n >= 20, "too few keys scanned: {n}");
}

/// 格下げモードの合成フィクスチャ 3 件が、格下げ後に前提を満たし往復で一致すること。
/// STACK-5・STACK-3・TASK-152.1・#605。
#[test]
fn stack5_605_downgrade_mode_synthetic_fixtures_roundtrip() {
    let keys = [
        "services.*.hostname",
        "services.*.user",
        "services.*.extra_hosts",
        "services.*.platform",
        "services.*.domainname",
        "services.*.pull_policy",
    ];
    for k in keys {
        assert_eq!(
            classify_key_path(k),
            KeyClass::ErrorUnsupportedYet,
            "{k}: reclassified; update this test's fixture"
        );
    }
    let set = parse_downgrade_value(&keys.join(",")).unwrap();

    let inputs = load_input_dir(&fixture_dir(&["downgrade"])).unwrap();
    assert_eq!(inputs.len(), 3);
    for input in &inputs {
        let (report, _) = convert_one(input.text());
        assert!(!report.error_free().is_error_free(), "downgrade not needed");
        assert!(!report.downgraded(&set).is_empty());
    }
    let s = run_dir(&["downgrade"], "downgrade", Some(&set));
    assert_eq!(
        s,
        Summary {
            files: 3,
            targets: 3,
            passed: 3
        }
    );

    let pull = inputs
        .iter()
        .find(|i| i.path().ends_with("pull-policy-multi-service.yaml"))
        .unwrap();
    let (report, _) = convert_one(pull.text());
    assert_eq!(
        report.downgraded(&set),
        vec![("services.*.pull_policy".to_string(), 2)]
    );
}

/// 陰性対照: value_drops があるファイルは既定・格下げのどちらでも対象から外れる。
/// STACK-5・TASK-152.1・#605。
#[test]
fn stack5_605_negative_control_excluded_from_targets() {
    let text = include_str!("fixtures/roundtrip/negative/host-path-device.yaml");
    let (report, _) = convert_one(text);
    assert_eq!(report.value_drops.get("services.*.devices"), 1);
    let set = parse_downgrade_value("services.*.hostname").unwrap();
    assert!(!is_target(&report, None));
    assert!(!is_target(&report, Some(&set)));
    assert_eq!(
        run_dir(&["negative"], "negative", None),
        Summary {
            files: 1,
            targets: 0,
            passed: 0
        }
    );
}

/// 比較が自明に真でないこと: 1 フィールドが違えば不一致になる。
/// STACK-5・TASK-152.1・#605。
#[test]
fn stack5_605_roundtrip_detects_mismatch() {
    let (_, out) = default_fixture();
    let mut rt = roundtrip(&out);
    assert_eq!(rt, out);
    rt.services.get_mut("web").unwrap().image = Some("example.invalid/other:9".to_string());
    assert_ne!(rt, out);
}
