//! 追加 6 キー（container_name・working_dir・cap_drop・security_opt・stdin_open・tty）の
//! 変換前後の値一致と変換可率の入力への反映を公開 API で照合する結合試験
//! （STACK-6・STACK-4・TASK-153.4・#612・MS-12・REPAIR-12）。
//!
//! 経路: `parse_compose_yaml` → `convert_top_level`（値一致・TOML 往復）と、
//! `key_scan` → `FileConversionReport` → `report_json::file_line`（変換可率の分子 = convert の出現数）。
//! `cap_add` は CRI の add_capabilities の受け入れがオーナー判断待ち（#2666・SEC-1）で変換しないため、
//! 本試験では陰性対照として「率の分子に入らず error-unsupported-yet のまま」を固定する。
//! 失敗メッセージには TOML 本文や drop した値を出さない（SEC-1）。

use fandhe_container_compose_convert::classify::KeyClass;
use fandhe_container_compose_convert::compose_convert::{
    ComposeDocument, ComposeValue, parse_compose_yaml,
};
use fandhe_container_compose_convert::convert::{ValueDrops, convert_top_level};
use fandhe_container_compose_convert::key_scan::collect_key_occurrences;
use fandhe_container_compose_convert::report::FileConversionReport;
use fandhe_container_compose_convert::report_json::file_line;
use fandhe_container_stack::schema::ComposeToml;

const FIXTURE: &str = include_str!("fixtures/stack6_added_keys.yaml");

const ADDED_KEYS: [&str; 6] = [
    "container_name",
    "working_dir",
    "cap_drop",
    "security_opt",
    "stdin_open",
    "tty",
];

fn convert(yaml: &str) -> (ComposeDocument, ComposeToml, ValueDrops) {
    let doc = parse_compose_yaml(yaml).expect("fixture parses");
    let mut drops = ValueDrops::new();
    let t = convert_top_level(&doc, &mut drops);
    (doc, t, drops)
}

fn report_line(yaml: &str) -> (FileConversionReport, String) {
    let (doc, _t, drops) = convert(yaml);
    let report = FileConversionReport::from_parsed(collect_key_occurrences(&doc), drops);
    let verdict = report.error_free();
    let line = file_line("stack6", &report, &verdict, None);
    (report, line)
}

fn strings(v: &ComposeValue) -> Vec<String> {
    v.as_sequence()
        .expect("sequence")
        .iter()
        .map(|e| e.as_str().expect("string").to_string())
        .collect()
}

/// STACK-6・TASK-153.4: 6 キーすべてで、変換前の YAML の値と変換後の `Service` の値が一致する。
#[test]
fn stack6_added_keys_values_match_source() {
    let (doc, t, drops) = convert(FIXTURE);
    assert!(drops.is_empty());
    for name in ["web", "worker"] {
        let src = doc
            .get("services")
            .and_then(|s| s.as_mapping())
            .and_then(|m| m.get(name))
            .and_then(|s| s.as_mapping())
            .expect("service");
        let dst = &t.services[name];
        assert_eq!(
            src.get("container_name").and_then(|v| v.as_str()),
            dst.container_name.as_deref(),
            "{name}: container_name"
        );
        assert_eq!(
            src.get("working_dir").and_then(|v| v.as_str()),
            dst.working_dir.as_deref(),
            "{name}: working_dir"
        );
        assert_eq!(
            strings(src.get("cap_drop").expect("cap_drop")),
            dst.cap_drop,
            "{name}: cap_drop"
        );
        assert_eq!(
            strings(src.get("security_opt").expect("security_opt")),
            dst.security_opt,
            "{name}: security_opt"
        );
        assert_eq!(
            src.get("stdin_open").and_then(|v| v.as_bool()),
            dst.stdin_open,
            "{name}: stdin_open"
        );
        assert_eq!(
            src.get("tty").and_then(|v| v.as_bool()),
            dst.tty,
            "{name}: tty"
        );
    }
    // 具体値（REPAIR-12）。
    let (web, worker) = (&t.services["web"], &t.services["worker"]);
    assert_eq!(web.container_name.as_deref(), Some("fixed-web"));
    assert_eq!(worker.working_dir.as_deref(), Some("/srv"));
    assert_eq!(web.cap_drop, ["ALL", "NET_RAW"]);
    assert_eq!(worker.cap_drop, ["CHOWN"]);
    assert_eq!(web.security_opt, ["no-new-privileges:true"]);
    assert_eq!((web.stdin_open, web.tty), (Some(true), Some(false)));
    assert_eq!((worker.stdin_open, worker.tty), (Some(false), Some(true)));
}

/// STACK-6・TASK-153.4: TOML へ往復しても値が保たれ、明示した false が None に化けない。
#[test]
fn stack6_added_keys_roundtrip_through_toml() {
    let (_doc, t, _drops) = convert(FIXTURE);
    let text = toml::to_string(&t).expect("serialize");
    let back: ComposeToml = toml::from_str(&text).expect("deserialize");
    assert_eq!(back, t);
    assert_eq!(back.services["web"].tty, Some(false));
    assert_eq!(back.services["worker"].stdin_open, Some(false));
    assert_eq!(back.services["web"].cap_drop, ["ALL", "NET_RAW"]);
    for key in ADDED_KEYS {
        assert!(text.contains(&format!("{key} = ")), "toml lacks key {key}");
    }
}

/// STACK-4・STACK-6・TASK-153.4: 6 キーが convert 分類として出現数 2（2 サービス分）で記録され、
/// 変換可率の分子（convert の出現数）に入る。他の分類は 0 件。
#[test]
fn stack6_added_keys_counted_as_convert_in_rate_inputs() {
    let (doc, _t, _d) = convert(FIXTURE);
    let occ = collect_key_occurrences(&doc);
    for key in ADDED_KEYS {
        let path = format!("services.*.{key}");
        let e = occ.get(&path).expect("recorded");
        assert_eq!((e.class, e.occurrences), (KeyClass::Convert, 2), "{path}");
    }
    let (report, line) = report_line(FIXTURE);
    assert!(report.error_free().is_error_free());
    // 寄与の内訳: services(1) + services.*(2) + services.*.image(2) + 6 キー x 2 = 17 出現、キー数は 9。
    assert!(
        line.contains("\"convert\":{\"keys\":9,\"occurrences\":17}"),
        "convert counts"
    );
    for class in [
        "error-unsupported-yet",
        "error-incompatible",
        "unrecognized",
    ] {
        assert!(
            line.contains(&format!("\"{class}\":{{\"keys\":0,\"occurrences\":0}}")),
            "{class} must be zero"
        );
    }
}

/// STACK-6・SEC-1・TASK-153.4 の陰性対照: cap_add は変換されず、率の分子に入らず、error_free を妨げる。
#[test]
fn stack6_cap_add_stays_out_of_rate_numerator() {
    let yaml = format!("{FIXTURE}    cap_add: [NET_ADMIN]\n");
    let (doc, t, drops) = convert(&yaml);
    assert!(drops.is_empty());
    let text = toml::to_string(&t).expect("serialize");
    assert!(!text.contains("cap_add"));
    let e = collect_key_occurrences(&doc)
        .get("services.*.cap_add")
        .expect("recorded");
    assert_eq!((e.class, e.occurrences), (KeyClass::ErrorUnsupportedYet, 1));
    let (report, line) = report_line(&yaml);
    assert!(!report.error_free().is_error_free());
    assert!(line.contains("\"error-unsupported-yet\":{\"keys\":1,\"occurrences\":1}"));
    assert!(line.contains("\"convert\":{\"keys\":9,\"occurrences\":17}"));
}

/// STACK-6・TASK-153.4 の陰性対照: 不正な型の値は drop され、値は記録に載らず error_free を妨げる。
#[test]
fn stack6_malformed_added_key_is_dropped() {
    let yaml = "services:\n  a:\n    image: x\n    tty: \"secret-marker\"\n";
    let (_doc, t, drops) = convert(yaml);
    assert_eq!(drops.get("services.*.tty"), 1);
    assert_eq!(t.services["a"].tty, None);
    let (report, line) = report_line(yaml);
    assert!(!report.error_free().is_error_free());
    assert!(!line.contains("secret-marker"));
}
