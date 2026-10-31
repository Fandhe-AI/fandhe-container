//! `--downgrade` の受理・拒否の境界値と、格下げしたキーの値が TOML へ漏れないことの単体テスト
//! （TASK-182.3・#629・STACK-3・MS-12・REPAIR-12・SEC-1）。
//!
//! 役割: #627（解析と許可判定）・#628（終了コード 2）が入れた `downgrade` / `report` / `report_json` の
//! 公開 API を通し、既存の `#[cfg(test)]` が埋めていない隙間（全体長の境界・検査の優先順位・空白と正規形の
//! 境界・fail-closed の blocker・表由来の TOML 非出力・JSON 行の全文）を固定する。
//! 他 PR が同じファイルを編集して衝突しないよう、独立した結合試験ファイルに置く。
//!
//! 分類が移りやすいキー（`security_opt` 等）は YAML へ直書きせず、直書きするキーは分類を事前に確かめる。

use fandhe_container_compose_convert::classify::{KEY_CLASS_TABLE, KeyClass, classify_key_path};
use fandhe_container_compose_convert::compose_convert::{
    ComposeParseErrorCode, parse_compose_yaml,
};
use fandhe_container_compose_convert::conversion_rate::ConversionRateTally;
use fandhe_container_compose_convert::convert::{ValueDrops, convert_top_level};
use fandhe_container_compose_convert::downgrade::{
    DowngradeArgError, DowngradeSet, MAX_DOWNGRADE_KEY_BYTES, MAX_DOWNGRADE_KEYS,
    MAX_DOWNGRADE_VALUE_BYTES, parse_downgrade_value,
};
use fandhe_container_compose_convert::key_scan::collect_key_occurrences;
use fandhe_container_compose_convert::report::{
    ErrorFreeBlocker, FileConversionReport, KeyOccurrences, MAX_KEY_PATHS,
};
use fandhe_container_compose_convert::report_json::{file_line, summary_line};
use fandhe_container_stack::schema::ComposeToml;

const HOSTNAME: &str = "services.*.hostname";
const USER: &str = "services.*.user";
const NETWORK_MODE: &str = "services.*.network_mode";
const EXTRA_HOSTS: &str = "services.*.extra_hosts";

/// YAML へ直書きするキーが今も unsupported-yet であることを確かめる（分類が移ったら原因が分かる失敗にする）。
fn assert_still_unsupported(keys: &[&str]) {
    for k in keys {
        assert_eq!(
            classify_key_path(k),
            KeyClass::ErrorUnsupportedYet,
            "{k}: reclassified; update this test's fixture"
        );
    }
}

fn pipeline(yaml: &str) -> (FileConversionReport, ComposeToml) {
    let doc = parse_compose_yaml(yaml).unwrap();
    let mut drops = ValueDrops::new();
    let toml = convert_top_level(&doc, &mut drops);
    let report = FileConversionReport::from_parsed(collect_key_occurrences(&doc), drops);
    (report, toml)
}

fn set(v: &str) -> DowngradeSet {
    parse_downgrade_value(v).unwrap()
}

/// 全体長のちょうど（受理）と +1（TooLong）。正しいキーでも全体長の検査が先に効く。
/// STACK-3・TASK-182.3・#629: 既存は超過側のみだった。
#[test]
fn stack3_629_value_bytes_exact_limit_accepted() {
    let pad = " ".repeat(MAX_DOWNGRADE_VALUE_BYTES - HOSTNAME.len());
    let exact = format!("{HOSTNAME}{pad}");
    assert_eq!(exact.len(), MAX_DOWNGRADE_VALUE_BYTES);
    let s = parse_downgrade_value(&exact).unwrap();
    assert_eq!(s.len(), 1);
    assert!(s.contains(HOSTNAME));
    let over = format!("{exact} ");
    assert_eq!(over.len(), MAX_DOWNGRADE_VALUE_BYTES + 1);
    assert_eq!(
        parse_downgrade_value(&over),
        Err(DowngradeArgError::TooLong)
    );
}

/// 違反が重なったときの優先順位と要素番号。
/// STACK-3・TASK-182.3・#629・REPAIR-12。
#[test]
fn stack3_629_first_violation_wins_with_index() {
    assert_still_unsupported(&[HOSTNAME, USER]);
    let valid256 = vec![HOSTNAME; MAX_DOWNGRADE_KEYS].join(",");
    let long = "a".repeat(MAX_DOWNGRADE_KEY_BYTES + 1);

    // 空の要素 256 個: 件数の検査より前の要素で空の検査が効く。
    assert_eq!(
        parse_downgrade_value(&",".repeat(MAX_DOWNGRADE_KEYS)),
        Err(DowngradeArgError::EmptyItem { index: 0 })
    );
    // 256 個の後の 257 番目は、空でも不可キーでも件数の検査が先に効く。
    assert_eq!(
        parse_downgrade_value(&format!("{valid256},")),
        Err(DowngradeArgError::TooManyKeys)
    );
    assert_eq!(
        parse_downgrade_value(&format!("{valid256},services.*.privileged")),
        Err(DowngradeArgError::TooManyKeys)
    );
    // 長すぎる要素の番号。
    assert_eq!(
        parse_downgrade_value(&format!("{HOSTNAME},{USER},{long}")),
        Err(DowngradeArgError::KeyTooLong { index: 2 })
    );
    // 前の要素の誤りが後ろの誤りに勝つ。
    assert_eq!(
        parse_downgrade_value(&format!("services.*.privileged,{long}")),
        Err(DowngradeArgError::NotDowngradable {
            index: 0,
            class: KeyClass::ErrorIncompatible,
            key_path: Some("services.*.privileged"),
        })
    );
    // 全体長の検査は他より先に効く。
    assert_eq!(
        parse_downgrade_value(&",".repeat(MAX_DOWNGRADE_VALUE_BYTES + 1)),
        Err(DowngradeArgError::TooLong)
    );
}

/// ASCII 空白だけを除くこと・正規形でない表記の拒否・入力を運ばないこと。
/// STACK-3・TASK-182.3・#629・SEC-1。
#[test]
fn stack3_629_trim_and_non_normalized_paths() {
    assert_still_unsupported(&[HOSTNAME, NETWORK_MODE]);
    let s = parse_downgrade_value(" \t services.*.hostname \r\n").unwrap();
    assert_eq!(s.iter().collect::<Vec<_>>(), vec![HOSTNAME]);

    let unrecognized = Err(DowngradeArgError::NotDowngradable {
        index: 0,
        class: KeyClass::Unrecognized,
        key_path: None,
    });
    for bad in [
        "\u{3000}services.*.hostname",
        "services.*.HOSTNAME",
        "services.web.hostname",
        "services.*.hostname.x",
        "services.*.hostname*",
    ] {
        assert_eq!(parse_downgrade_value(bad), unrecognized, "{bad:?}");
    }
    assert_eq!(
        parse_downgrade_value("services.*.x-foo"),
        Err(DowngradeArgError::NotDowngradable {
            index: 0,
            class: KeyClass::Warning,
            key_path: None,
        })
    );
    assert_eq!(
        parse_downgrade_value("services.*"),
        Err(DowngradeArgError::NotDowngradable {
            index: 0,
            class: KeyClass::Convert,
            key_path: Some("services.*"),
        })
    );
    // 静的には受理される（ファイルごとの判定は別のテスト）。
    assert!(
        parse_downgrade_value(NETWORK_MODE)
            .unwrap()
            .contains(NETWORK_MODE)
    );

    // 入力の目印がエラーのどの表現にも出ない。
    let e = parse_downgrade_value("leak-sentinel-629").unwrap_err();
    assert!(!format!("{e:?}").contains("leak-sentinel"));
    assert!(!e.message().contains("leak-sentinel"));
}

/// 格下げしても、パース失敗・溢れは blocker に残る（fail-closed）。
/// STACK-3・TASK-182.3・#629・REPAIR-12。
#[test]
fn stack3_629_downgrade_does_not_clear_fail_closed_blockers() {
    assert_still_unsupported(&[HOSTNAME]);
    let dg = set(HOSTNAME);

    let failed = FileConversionReport::parse_failed(ComposeParseErrorCode::InvalidArgument);
    assert!(failed.downgraded(&dg).is_empty());
    assert_eq!(
        failed.error_free_with_downgrade(&dg).blockers(),
        &[ErrorFreeBlocker::ParseFailed(
            ComposeParseErrorCode::InvalidArgument
        )]
    );

    // 溢れ: hostname を先に記録し、異なる convert のパスで上限を超えるまで埋める。
    let mut occ = KeyOccurrences::new();
    occ.record(HOSTNAME, KeyClass::ErrorUnsupportedYet);
    for i in 0..MAX_KEY_PATHS {
        occ.record(&format!("services.*.filler-{i}"), KeyClass::Convert);
    }
    assert!(occ.overflowed());
    let over = FileConversionReport::from_parsed(occ, ValueDrops::new());
    assert_eq!(over.downgraded(&dg), vec![(HOSTNAME.to_string(), 1)]);
    assert_eq!(
        over.error_free_with_downgrade(&dg).blockers(),
        &[ErrorFreeBlocker::KeyOccurrencesOverflow]
    );
    assert_eq!(
        over.error_free().blockers(),
        &[
            ErrorFreeBlocker::ErrorClassKey {
                key_path: HOSTNAME.to_string(),
                class: KeyClass::ErrorUnsupportedYet,
                occurrences: 1,
                guidance: None,
            },
            ErrorFreeBlocker::KeyOccurrencesOverflow,
        ]
    );
}

/// 格下げ可能な全キーが、値つきで書かれても TOML へ出ない（表から実行時に導出する）。
/// `services.*.deploy.*` は deploy 自体が未変換で ValueDrops に載り error_free にならないため対象外。
/// STACK-3・TASK-182.3・#629・SEC-1。
#[test]
fn stack3_629_downgradable_keys_never_reach_toml() {
    let rows: Vec<&str> = KEY_CLASS_TABLE
        .iter()
        .filter(|(p, c)| {
            *c == KeyClass::ErrorUnsupportedYet
                && (!p.contains('.')
                    || (p.starts_with("services.*.") && p.matches('.').count() == 2))
        })
        .map(|(p, _)| *p)
        .collect();
    assert!(rows.len() >= 20, "table-derived rows: {}", rows.len());

    let base = "name: demo\nservices:\n  web:\n    image: nginx:1.27\n";
    let mut top = String::from("name: demo\n");
    let mut svc = String::from("services:\n  web:\n    image: nginx:1.27\n");
    for (i, p) in rows.iter().enumerate() {
        let leaf = p.rsplit('.').next().unwrap();
        if p.contains('.') {
            svc.push_str(&format!("    {leaf}: leak-sentinel-{i}\n"));
        } else {
            top.push_str(&format!("{leaf}: leak-sentinel-{i}\n"));
        }
    }
    let target = format!("{top}{svc}");

    let (base_report, base_toml) = pipeline(base);
    assert!(base_report.error_free().is_error_free());
    let (report, toml_value) = pipeline(&target);
    for p in &rows {
        let o = report
            .key_occurrences
            .get(p)
            .unwrap_or_else(|| panic!("{p}"));
        assert_eq!(
            (o.class, o.occurrences),
            (KeyClass::ErrorUnsupportedYet, 1),
            "{p}"
        );
    }
    assert!(report.value_drops.is_empty());

    assert_eq!(toml_value, base_toml);
    let text = toml::to_string(&toml_value).unwrap();
    assert_eq!(text, toml::to_string(&base_toml).unwrap());
    assert!(!text.contains("leak-sentinel"));

    let dg = set(&rows.join(","));
    let mut sorted: Vec<&str> = rows.clone();
    sorted.sort_unstable();
    assert_eq!(
        report.downgraded(&dg),
        sorted
            .iter()
            .map(|p| (p.to_string(), 1))
            .collect::<Vec<_>>()
    );
    assert!(report.error_free_with_downgrade(&dg).is_error_free());
    assert!(!report.error_free().is_error_free());
}

/// `downgraded` のキーと件数、ファイルごとの分類での判定（重い分類に上がったキーは格下げされない）。
/// STACK-3・TASK-182.3・#629。
#[test]
fn stack3_629_downgraded_report_per_file_classes() {
    assert_still_unsupported(&[HOSTNAME, USER, NETWORK_MODE, EXTRA_HOSTS]);
    let dg = set(&[HOSTNAME, USER, NETWORK_MODE, EXTRA_HOSTS].join(","));

    // ファイル A: network_mode が service: と host で、同じパスの中の重い方が勝つ。
    let (a, _) = pipeline(
        "services:\n  a:\n    image: x\n    hostname: ha\n    user: ua\n    network_mode: 'service:b'\n  b:\n    image: x\n    hostname: hb\n    network_mode: host\n",
    );
    assert_eq!(
        a.downgraded(&dg),
        vec![(HOSTNAME.to_string(), 2), (USER.to_string(), 1)]
    );
    assert_eq!(
        a.error_free_with_downgrade(&dg).blockers(),
        &[ErrorFreeBlocker::ErrorClassKey {
            key_path: NETWORK_MODE.to_string(),
            class: KeyClass::ErrorIncompatible,
            occurrences: 2,
            guidance: None,
        }]
    );
    assert_eq!(a.error_free().blockers().len(), 3);

    // ファイル B: service: だけなら unsupported-yet のままで格下げできる。TOML は変わらない。
    let (b, b_toml) = pipeline("services:\n  a:\n    image: x\n    network_mode: 'service:x'\n");
    assert_eq!(b.downgraded(&dg), vec![(NETWORK_MODE.to_string(), 1)]);
    assert!(b.error_free_with_downgrade(&dg).is_error_free());
    let (_, plain_toml) = pipeline("services:\n  a:\n    image: x\n");
    assert_eq!(b_toml, plain_toml);
}

/// `downgraded` を含むレポート行の全文一致と、入力値・サービス名が出ないこと。
/// STACK-3・TASK-182.3・#629・SEC-1。
#[test]
fn stack3_629_file_line_downgraded_json_exact() {
    assert_still_unsupported(&[HOSTNAME, USER]);
    let dg = set(&format!("{HOSTNAME},{USER}"));
    let (clean, _) = pipeline(
        "services:\n  secretsvc-629:\n    image: x\n    hostname: leak-sentinel-a\n    user: leak-sentinel-b\n",
    );
    let (d, v) = (clean.downgraded(&dg), clean.error_free_with_downgrade(&dg));
    let l1 = file_line("f", &clean, &clean.error_free(), Some((&d, &v)));
    assert_eq!(
        l1,
        "{\"kind\":\"file\",\"file_id\":\"f\",\"parse_error\":null,\"counts\":{\"convert\":{\"keys\":3,\"occurrences\":3},\"warning\":{\"keys\":0,\"occurrences\":0},\"error-incompatible\":{\"keys\":0,\"occurrences\":0},\"error-unsupported-yet\":{\"keys\":2,\"occurrences\":2},\"unrecognized\":{\"keys\":0,\"occurrences\":0}},\"key_occurrences\":[{\"key_path\":\"services\",\"class\":\"convert\",\"occurrences\":1},{\"key_path\":\"services.*\",\"class\":\"convert\",\"occurrences\":1},{\"key_path\":\"services.*.hostname\",\"class\":\"error-unsupported-yet\",\"occurrences\":1},{\"key_path\":\"services.*.image\",\"class\":\"convert\",\"occurrences\":1},{\"key_path\":\"services.*.user\",\"class\":\"error-unsupported-yet\",\"occurrences\":1}],\"key_occurrences_overflowed\":false,\"value_drops\":{},\"value_drops_total\":0,\"downgraded\":{\"services.*.hostname\":1,\"services.*.user\":1},\"error_free\":false,\"error_free_blockers\":[{\"kind\":\"error-class-key\",\"key_path\":\"services.*.hostname\",\"class\":\"error-unsupported-yet\",\"occurrences\":1},{\"kind\":\"error-class-key\",\"key_path\":\"services.*.user\",\"class\":\"error-unsupported-yet\",\"occurrences\":1}],\"error_free_with_downgrade\":true,\"error_free_with_downgrade_blockers\":[]}\n"
    );

    let (blocked, _) = pipeline(
        "services:\n  secretsvc-629:\n    image: x\n    hostname: leak-sentinel-a\n    privileged: true\n",
    );
    let (d, v) = (
        blocked.downgraded(&dg),
        blocked.error_free_with_downgrade(&dg),
    );
    let l2 = file_line("f", &blocked, &blocked.error_free(), Some((&d, &v)));
    assert_eq!(
        l2,
        "{\"kind\":\"file\",\"file_id\":\"f\",\"parse_error\":null,\"counts\":{\"convert\":{\"keys\":3,\"occurrences\":3},\"warning\":{\"keys\":0,\"occurrences\":0},\"error-incompatible\":{\"keys\":1,\"occurrences\":1},\"error-unsupported-yet\":{\"keys\":1,\"occurrences\":1},\"unrecognized\":{\"keys\":0,\"occurrences\":0}},\"key_occurrences\":[{\"key_path\":\"services\",\"class\":\"convert\",\"occurrences\":1},{\"key_path\":\"services.*\",\"class\":\"convert\",\"occurrences\":1},{\"key_path\":\"services.*.hostname\",\"class\":\"error-unsupported-yet\",\"occurrences\":1},{\"key_path\":\"services.*.image\",\"class\":\"convert\",\"occurrences\":1},{\"key_path\":\"services.*.privileged\",\"class\":\"error-incompatible\",\"occurrences\":1}],\"key_occurrences_overflowed\":false,\"value_drops\":{},\"value_drops_total\":0,\"downgraded\":{\"services.*.hostname\":1},\"error_free\":false,\"error_free_blockers\":[{\"kind\":\"error-class-key\",\"key_path\":\"services.*.hostname\",\"class\":\"error-unsupported-yet\",\"occurrences\":1},{\"kind\":\"error-class-key\",\"key_path\":\"services.*.privileged\",\"class\":\"error-incompatible\",\"occurrences\":1}],\"error_free_with_downgrade\":false,\"error_free_with_downgrade_blockers\":[{\"kind\":\"error-class-key\",\"key_path\":\"services.*.privileged\",\"class\":\"error-incompatible\",\"occurrences\":1}]}\n"
    );

    assert_eq!(
        summary_line(2, 0, Some(1), 0, &ConversionRateTally::new().finish()),
        "{\"kind\":\"summary\",\"files\":2,\"error_free_files\":0,\"error_free_with_downgrade_files\":1,\"parse_failed_files\":0,\"toml_output\":\"unimplemented\",\"conversion_rate\":{\"basis\":\"occurrences-excluding-warning\",\"convert_occurrences\":0,\"warning_occurrences\":0,\"error_incompatible_occurrences\":0,\"error_unsupported_yet_occurrences\":0,\"unrecognized_occurrences\":0,\"total_occurrences\":0,\"rate_percent\":null,\"threshold_percent\":80,\"verdict\":\"indeterminate\",\"lower_bound_convert_occurrences\":0,\"lower_bound_rate_percent\":null,\"lower_bound_verdict\":\"indeterminate\",\"indeterminate_reasons\":[\"no-key-occurrences\"]}}\n"
    );
    for l in [&l1, &l2] {
        assert!(!l.contains("secretsvc-629") && !l.contains("leak-sentinel"));
    }
}
