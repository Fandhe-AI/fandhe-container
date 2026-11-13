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

/// STACK-9・STACK-3: GPU 予約の `options` は変換したうえで drop 1 件を残し、`error_free` にならない。
#[test]
fn stack9_device_options_blocks_error_free() {
    let text = CLEAN.replace(
        "              device_ids: [\"0\"]\n",
        "              device_ids: [\"0\"]\n              options:\n                foo: bar\n",
    );
    let r = report_of(&text);
    assert_eq!(
        r.value_drops
            .get("services.*.deploy.resources.reservations.devices"),
        1
    );
    assert!(!r.error_free().is_error_free());
}

/// STACK-3・#4637: 降りない 5 か所の `x-*` は drop に数えず `error_free` を保ち、Warning として記録する。
/// 変換可率では warning が分母にだけ入る（下限は convert と一致のまま）。
#[test]
fn stack3_extension_keys_in_unscanned_levels_keep_error_free() {
    let text = CLEAN
        .replace("      interval: 5s\n", "      interval: 5s\n      x-h: 1\n")
        .replace(
            "        condition: service_healthy\n",
            "        condition: service_healthy\n        x-d: 1\n",
        )
        .replace(
            "      nofile: 1024\n",
            "      nofile:\n        soft: 1024\n        hard: 2048\n        x-u: 1\n",
        )
        .replace(
            "          memory: 64M\n",
            "          memory: 64M\n          x-l: 1\n",
        )
        .replace(
            "              device_ids: [\"0\"]\n",
            "              device_ids: [\"0\"]\n              x-g: 1\n",
        );
    let r = report_of(&text);
    assert!(r.value_drops.is_empty(), "{:?}", r.value_drops);
    assert!(r.error_free().is_error_free());
    for p in [
        "services.*.healthcheck.x-h",
        "services.*.depends_on.*.x-d",
        "services.*.ulimits.*.x-u",
        "services.*.deploy.resources.limits.x-l",
        "services.*.deploy.resources.reservations.devices.x-g",
    ] {
        let e = r.key_occurrences.get(p).unwrap_or_else(|| panic!("{p}"));
        assert_eq!(e.occurrences, 1, "{p}");
    }
    let mut t = ConversionRateTally::new();
    t.add(&r);
    let out = t.finish();
    assert_eq!(out.warning, 5);
    assert_eq!(out.lower_bound_convert, out.convert);
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
