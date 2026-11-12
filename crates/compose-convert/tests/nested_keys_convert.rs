//! `depends_on`・`ulimits`・`healthcheck`・`deploy`（GPU 予約を含む）の結線が `error_free` と
//! 変換可率の下限に反映されることの結合試験（STACK-3・STACK-4・STACK-9・REPAIR-12・#3612）。
//!
//! 変換できた分は `value_drops` に残らず、変換できなかった分だけが分類表のキーパスで残ることを具体値で見る。

use fandhe_container_compose_convert::compose_convert::parse_compose_yaml;
use fandhe_container_compose_convert::conversion_rate::ConversionRateTally;
use fandhe_container_compose_convert::convert::{ValueDrops, convert_top_level};
use fandhe_container_compose_convert::key_scan::collect_key_occurrences;
use fandhe_container_compose_convert::report::FileConversionReport;

const CLEAN: &str = "\
services:
  a:
    image: example.invalid/a:1
    depends_on:
      b:
        condition: service_healthy
    ulimits:
      nofile: 1024
    healthcheck:
      test: [\"CMD\", \"/bin/true\"]
      interval: 5s
    deploy:
      resources:
        limits:
          cpus: \"1\"
          memory: 64M
        reservations:
          devices:
            - driver: nvidia
              capabilities: [gpu]
              device_ids: [\"0\"]
  b:
    image: example.invalid/b:1
";

fn report_of(text: &str) -> FileConversionReport {
    let doc = parse_compose_yaml(text).expect("parse");
    let occ = collect_key_occurrences(&doc);
    let mut drops = ValueDrops::new();
    let _toml = convert_top_level(&doc, &mut drops);
    FileConversionReport::from_parsed(occ, drops)
}

/// 変換できた 4 キーと GPU 予約は drop が 0 で、`error_free` かつ下限が convert と一致する。
#[test]
fn stack3_nested_keys_keep_file_error_free() {
    let r = report_of(CLEAN);
    assert!(r.value_drops.is_empty());
    assert!(r.error_free().is_error_free());
    let mut t = ConversionRateTally::new();
    t.add(&r);
    let out = t.finish();
    assert_eq!(out.lower_bound_convert, out.convert);
    assert!(out.convert > 0);
}

/// 陰性対照: `NONE` の healthcheck は drop 1 件で `error_free` にならず、下限は 1 出現分だけ減る。
#[test]
fn stack3_unconvertible_healthcheck_lowers_bound() {
    let text = CLEAN.replace("test: [\"CMD\", \"/bin/true\"]", "test: [NONE]");
    let r = report_of(&text);
    assert_eq!(r.value_drops.get("services.*.healthcheck"), 1);
    assert!(!r.error_free().is_error_free());
    let occ = r
        .key_occurrences
        .get("services.*.healthcheck")
        .map(|e| e.occurrences);
    assert_eq!(occ, Some(1));
    let mut t = ConversionRateTally::new();
    t.add(&r);
    let out = t.finish();
    assert_eq!(out.lower_bound_convert, out.convert - 1);
}
