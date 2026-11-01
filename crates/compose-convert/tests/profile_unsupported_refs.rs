//! サービス間参照キー 4 種の `error-unsupported-yet` 分類と TOML 非出力の突き合わせテスト
//! （TASK-188.1・#635・STACK-10・STACK-3・MS-12・REPAIR-12）。
//!
//! 役割: compose-spec のサービス間参照（`links`・`extends`・`network_mode: service:<name>`・
//! `volumes_from`）は STACK-1 の TOML スキーマに行き先が無く、STACK-3 の変換で止まるため
//! `profiles` の判定（STACK-10）まで到達しない。この性質を、フィクスチャを変換の流れ
//! （読み込み → 走査 → 変換 → レポートの `error_free` 判定。`entry` と同じ順序）に通して照合する。
//! `classify.rs` の `stack10_service_reference_keys_are_unsupported_yet` はキーパス単位の表の照合で、
//! 本ファイルは 1 ファイル 1 キーで、そのキーだけが関門を止めることまで固定する。
//!
//! 「TOML 未生成」の定義: TOML の書き出しは未実装（REPAIR-3）で stdout は常に空のため、空であることは
//! 証拠にしない。代わりに (a) `error_free` が偽、(b) blocker が対象キーの 1 件だけ、
//! (c) 変換結果の TOML に対象キー名と参照先のマーカーが現れない（スキーマに行き先が無い）、を照合する。
//!
//! 配置: issue は `crates/stack/tests/` を挙げるが、対象の API は本 crate にあり、依存は
//! compose-convert -> stack の一方向（crate-naming.md 決定 5）のため、本 crate に置く。

use std::path::{Path, PathBuf};

use fandhe_container_compose_convert::classify::{
    KeyClass, classify_key_path, classify_network_mode_value,
};
use fandhe_container_compose_convert::compose_convert::parse_compose_yaml;
use fandhe_container_compose_convert::convert::{ValueDrops, convert_top_level};
use fandhe_container_compose_convert::input_scan::load_input_dir;
use fandhe_container_compose_convert::key_scan::collect_key_occurrences;
use fandhe_container_compose_convert::report::{ErrorFreeBlocker, FileConversionReport};
use fandhe_container_stack::schema::ComposeToml;

/// (ファイル stem, 期待キーパス)。フィクスチャを足したらここも足す。
const EXPECTED: &[(&str, &str)] = &[
    ("links", "services.*.links"),
    ("extends_service", "services.*.extends"),
    ("extends_top", "extends"),
    ("network_mode_service", "services.*.network_mode"),
    ("volumes_from", "services.*.volumes_from"),
];

/// 対象キー名（直列化結果に現れてはならない）。
const KEY_NAMES: &[&str] = &["links", "extends", "network_mode", "volumes_from"];
const MARKER: &str = "refmarker";

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("unsupported_refs")
}

fn pipeline(yaml: &str) -> (FileConversionReport, ComposeToml) {
    let doc = parse_compose_yaml(yaml).unwrap();
    let mut drops = ValueDrops::new();
    let toml = convert_top_level(&doc, &mut drops);
    let report = FileConversionReport::from_parsed(collect_key_occurrences(&doc), drops);
    (report, toml)
}

fn expected_path(stem: &str) -> &'static str {
    EXPECTED
        .iter()
        .find(|(s, _)| *s == stem)
        .unwrap_or_else(|| panic!("{stem}: not in EXPECTED"))
        .1
}

/// 表の前提（今も unsupported-yet であること）。崩れたら原因が分かる失敗にする。
fn assert_still_unsupported() {
    for (_, p) in EXPECTED {
        assert_eq!(
            classify_key_path(p),
            KeyClass::ErrorUnsupportedYet,
            "{p}: reclassified; update this test's fixture"
        );
    }
    assert_eq!(
        classify_network_mode_value(Some("service:refmarker")),
        KeyClass::ErrorUnsupportedYet
    );
}

/// 1 フィクスチャについて (a)(b)(c) を照合する。
fn check(stem: &str, yaml: &str) {
    let key = expected_path(stem);
    let (report, toml) = pipeline(yaml);

    // (a) 関門
    let verdict = report.error_free();
    assert!(!verdict.is_error_free(), "{stem}: gate must stay closed");

    // (b) 理由は対象キー 1 件だけ
    assert_eq!(
        verdict.blockers(),
        &[ErrorFreeBlocker::ErrorClassKey {
            key_path: key.to_string(),
            class: KeyClass::ErrorUnsupportedYet,
            occurrences: 1,
            guidance: None,
        }],
        "{stem}: blockers"
    );
    let occ = report
        .key_occurrences
        .get(key)
        .unwrap_or_else(|| panic!("{stem}: key not recorded"));
    assert_eq!(occ.class, KeyClass::ErrorUnsupportedYet, "{stem}");
    assert_eq!(occ.occurrences, 1, "{stem}");
    assert_eq!(report.key_occurrences.unrecognized_count(), 0, "{stem}");
    assert!(report.value_drops.is_empty(), "{stem}: value drops");
    // 対象キー以外は変換できるキーだけ（対象だけが関門を止めている）
    for (p, o) in report.key_occurrences.iter() {
        if p != key {
            assert_eq!(o.class, KeyClass::Convert, "{stem}: {p}");
        }
    }

    // (c) スキーマに行き先が無い
    let text = toml::to_string(&toml).expect("serialize");
    for k in KEY_NAMES {
        assert!(!text.contains(k), "{stem}: TOML contains key name {k}");
    }
    assert!(!text.contains(MARKER), "{stem}: TOML contains marker");
}

fn check_file(stem: &str) {
    assert_still_unsupported();
    let path = fixture_dir().join(format!("{stem}.yaml"));
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("{stem}: read fixture"));
    check(stem, &yaml);
}

/// ディレクトリ単位: 件数と stem の取りこぼし・重複が無く、全件が照合を通る。
/// STACK-10・TASK-188.1・#635。
#[test]
fn stack10_635_fixture_dir_matches_expected_table() {
    assert_still_unsupported();
    let inputs = load_input_dir(&fixture_dir()).expect("load fixtures");
    assert_eq!(inputs.len(), EXPECTED.len());
    let mut seen: Vec<String> = Vec::new();
    for input in &inputs {
        let stem = input
            .path()
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("stem")
            .to_string();
        check(&stem, input.text());
        seen.push(stem);
    }
    seen.sort();
    let mut want: Vec<String> = EXPECTED.iter().map(|(s, _)| s.to_string()).collect();
    want.sort();
    assert_eq!(seen, want);
}

/// STACK-10・TASK-188.1・#635: `links`。
#[test]
fn stack10_635_links_is_unsupported_yet_and_no_toml() {
    check_file("links");
}

/// STACK-10・TASK-188.1・#635: `extends`（サービス内とトップレベルの両方）。
#[test]
fn stack10_635_extends_is_unsupported_yet_and_no_toml() {
    check_file("extends_service");
    check_file("extends_top");
}

/// STACK-10・TASK-188.1・#635: `network_mode: service:<name>`。
#[test]
fn stack10_635_network_mode_service_is_unsupported_yet_and_no_toml() {
    check_file("network_mode_service");
}

/// STACK-10・TASK-188.1・#635: `volumes_from`。
#[test]
fn stack10_635_volumes_from_is_unsupported_yet_and_no_toml() {
    check_file("volumes_from");
}

/// 陰性対照: 参照キーを除いた同じ構成は関門を通る（他の部分が理由で落ちていないことの確認）。
/// STACK-10・TASK-188.1・#635。
#[test]
fn stack10_635_baseline_without_ref_is_error_free() {
    let (report, _) = pipeline("services:\n  web:\n    image: x\n");
    assert!(report.error_free().is_error_free());
}
