//! 展開済み compose 文書のキー走査器（TASK-151.7・#602・STACK-3・MS-12）。
//!
//! 役割: [`ComposeDocument`] を歩き、各キーを正規形のキーパスで [`KeyOccurrences`] に記録する。
//! [`crate::classify`] の「呼び出し側との契約」を満たす側で、[`crate::entry`]（bin）が変換の前に呼ぶ。
//! 走査器が無いまま `error_free` を出すと `privileged` 等を含むファイルが通る（fail-open）ため、bin と同時に入れた。
//!
//! # 走査規則
//!
//! - 出現ごとに 1 件 [`KeyOccurrences::record`] する。同じパスで分類が混ざれば記録側が重い方へ寄せる。
//! - ユーザー定義名（サービス名・ネットワーク名等）はパスに入れず `*` にする。最後のセグメントが `x-` で始まる
//!   キーは `x-*` に正規化する（拡張名は利用者が決める識別子で、出力に載せないため）。
//! - トップレベルは各キーを [`classify_key_path`] で分類する。`services` / `networks` / `volumes` / `secrets` /
//!   `configs` がマッピングなら子を `<t>.*`（Convert）として数え、子のキーを `<t>.*.<key>` として分類する。
//!   `services.*.network_mode` は値で [`classify_network_mode_value`] を引く。
//!   `services.*.deploy` は子（`placement`・`replicas` 等）を `services.*.deploy.<key>` として分類し、
//!   `resources` だけは表にある `limits` / `reservations` / `reservations.devices` を明示的に数えて止まる。
//! - 降りないもの: [`crate::classify::UNSCANNED_KEY_PREFIXES`] の配下（healthcheck・environment・labels・ulimits・
//!   depends_on・`deploy.resources` の汎用の子）、シーケンスの中、上記以外のマッピングの中。これらの子の検査は
//!   型を知る変換側（[`crate::convert`]）が `value_drops` に記録する。
//! - 再帰しない（固定の深さのループ）。入力の大きさはパーサーの上限と [`crate::report::MAX_KEY_PATHS`] で抑える。
//!
//! # 未実装（REPAIR-3）
//!
//! - Docker ソケットの bind（[`crate::classify::is_docker_socket_bind`]）の結線は未実装（STACK-7）。

use crate::classify::{classify_key_path, classify_network_mode_value};
use crate::compose_convert::{ComposeDocument, ComposeValue};
use crate::report::KeyOccurrences;

/// 名前を表すテーブル型のトップレベルキー。
const NAME_TABLES: [&str; 5] = ["services", "networks", "volumes", "secrets", "configs"];

/// キー 1 件のセグメントを正規形にする。`x-` で始まる拡張キーは `x-*` にする。
fn segment(key: &str) -> &str {
    if key.starts_with("x-") { "x-*" } else { key }
}

fn record_path(occ: &mut KeyOccurrences, path: &str) {
    occ.record(path, classify_key_path(path));
}

/// `doc` のキーを走査して出現を数える。値は読むが、保持も出力もしない。
pub fn scan_key_occurrences(doc: &ComposeDocument) -> KeyOccurrences {
    let mut occ = KeyOccurrences::new();
    for (key, value) in doc.root().iter() {
        let top = segment(key);
        record_path(&mut occ, top);
        if NAME_TABLES.contains(&key) {
            scan_table(&mut occ, key, value);
        }
    }
    occ
}

/// 名前つき定義のテーブル（`services` 等）を走査する。マッピングでなければ何もしない
/// （型違いの扱いは `convert_top_level` が `value_drops` に記録する）。
fn scan_table(occ: &mut KeyOccurrences, table: &str, value: &ComposeValue) {
    let Some(defs) = value.as_mapping() else {
        return;
    };
    let wildcard = format!("{table}.*");
    for (_, def) in defs.iter() {
        record_path(occ, &wildcard);
        let Some(fields) = def.as_mapping() else {
            continue;
        };
        for (field, fvalue) in fields.iter() {
            let path = format!("{wildcard}.{}", segment(field));
            if table == "services" {
                scan_service_field(occ, field, &path, fvalue);
            } else {
                record_path(occ, &path);
            }
        }
    }
}

fn scan_service_field(occ: &mut KeyOccurrences, field: &str, path: &str, value: &ComposeValue) {
    match field {
        "network_mode" => {
            occ.record(path, classify_network_mode_value(value.as_str()));
        }
        "deploy" => {
            record_path(occ, path);
            scan_deploy(occ, path, value);
        }
        _ => record_path(occ, path),
    }
}

/// `services.*.deploy` の子を走査する。`resources` は表にある行だけを数えて止まる。
fn scan_deploy(occ: &mut KeyOccurrences, deploy_path: &str, value: &ComposeValue) {
    let Some(children) = value.as_mapping() else {
        return;
    };
    for (child, cvalue) in children.iter() {
        let path = format!("{deploy_path}.{}", segment(child));
        record_path(occ, &path);
        if child != "resources" {
            continue;
        }
        let Some(res) = cvalue.as_mapping() else {
            continue;
        };
        for part in ["limits", "reservations"] {
            if let Some(pv) = res.get(part) {
                let part_path = format!("{path}.{part}");
                record_path(occ, &part_path);
                if part == "reservations"
                    && pv.as_mapping().and_then(|m| m.get("devices")).is_some()
                {
                    record_path(occ, &format!("{part_path}.devices"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::KeyClass;
    use crate::compose_convert::parse_compose_yaml;

    fn scan(yaml: &str) -> KeyOccurrences {
        let doc = parse_compose_yaml(yaml).expect("fixture parses");
        scan_key_occurrences(&doc)
    }

    fn rows(occ: &KeyOccurrences) -> Vec<(String, &'static str, u64)> {
        occ.iter()
            .map(|(p, e)| (p.to_string(), e.class.as_str(), e.occurrences))
            .collect()
    }

    /// STACK-3・REPAIR-12: 分類表の全 Convert 行・代表のエラー行に触れる合成 YAML の完全な一覧。
    #[test]
    fn full_listing_of_synthetic_document() {
        let occ = scan(
            r#"
name: p
version: "3"
x-common: {a: 1}
include: [a.yaml]
services:
  web:
    image: busybox
    privileged: true
    network_mode: host
    x-foo: 1
    environment: {K: v}
    healthcheck: {test: [CMD, "true"]}
    deploy:
      placement: {}
      replicas: 2
      resources:
        limits: {cpus: "1"}
        reservations:
          devices: []
  db:
    image: pg
    network_mode: "service:web"
networks:
  n: {driver: bridge, ipam: {}}
  m:
volumes:
  v: {external: true}
secrets:
  s: {file: ./f}
configs:
  c: {file: ./f}
"#,
        );
        let expected: Vec<(&str, &str, u64)> = vec![
            ("configs", "convert", 1),
            ("configs.*", "convert", 1),
            ("configs.*.file", "convert", 1),
            ("include", "error-unsupported-yet", 1),
            ("name", "convert", 1),
            ("networks", "convert", 1),
            ("networks.*", "convert", 2),
            ("networks.*.driver", "convert", 1),
            ("networks.*.ipam", "unrecognized", 1),
            ("secrets", "convert", 1),
            ("secrets.*", "convert", 1),
            ("secrets.*.file", "convert", 1),
            ("services", "convert", 1),
            ("services.*", "convert", 2),
            ("services.*.deploy", "convert", 1),
            ("services.*.deploy.placement", "error-incompatible", 1),
            ("services.*.deploy.replicas", "error-unsupported-yet", 1),
            ("services.*.deploy.resources", "convert", 1),
            ("services.*.deploy.resources.limits", "convert", 1),
            ("services.*.deploy.resources.reservations", "convert", 1),
            (
                "services.*.deploy.resources.reservations.devices",
                "convert",
                1,
            ),
            ("services.*.environment", "convert", 1),
            ("services.*.healthcheck", "convert", 1),
            ("services.*.image", "convert", 2),
            ("services.*.network_mode", "error-incompatible", 2),
            ("services.*.privileged", "error-incompatible", 1),
            ("services.*.x-*", "warning", 1),
            ("version", "warning", 1),
            ("volumes", "convert", 1),
            ("volumes.*", "convert", 1),
            ("volumes.*.external", "convert", 1),
            ("x-*", "warning", 1),
        ];
        let expected: Vec<(String, &str, u64)> = expected
            .into_iter()
            .map(|(p, c, n)| (p.to_string(), c, n))
            .collect();
        assert_eq!(rows(&occ), expected);
    }

    /// STACK-3: 未走査の接頭辞の子は記録に現れない。
    #[test]
    fn unscanned_children_are_not_recorded() {
        let occ = scan(
            r#"
services:
  a:
    healthcheck: {test: [CMD], interval: 1s}
    environment: {FOO: bar}
    labels: {l: v}
    ulimits: {nofile: 1}
    depends_on: {b: {condition: service_started}}
    deploy:
      resources:
        limits: {cpus: "1", memory: 1g}
"#,
        );
        for (p, _, _) in rows(&occ) {
            for bad in [
                "healthcheck.",
                "environment.",
                "labels.",
                "ulimits.",
                "depends_on.",
                "limits.",
            ] {
                assert!(!p.contains(bad), "{p}");
            }
        }
    }

    /// SEC-1: ユーザー定義名・拡張名はキーパスに現れない。
    #[test]
    fn user_defined_names_never_appear() {
        let occ = scan(
            r#"
x-svc-marker-7f3a: {a: 1}
services:
  svc-marker-7f3a:
    image: i
    x-ext-marker-7f3a: 1
networks:
  net-marker-7f3a: {driver: bridge, x-net-marker-7f3a: 1}
"#,
        );
        for (p, _, _) in rows(&occ) {
            assert!(!p.contains("marker"), "{p}");
        }
        assert_eq!(occ.get("x-*").map(|e| e.class), Some(KeyClass::Warning));
        assert_eq!(
            occ.get("services.*.x-*").map(|e| e.class),
            Some(KeyClass::Warning)
        );
        assert_eq!(
            occ.get("networks.*.x-*").map(|e| e.class),
            Some(KeyClass::Warning)
        );
    }

    /// STACK-3・STACK-10: network_mode は値で分類する。
    #[test]
    fn network_mode_by_value() {
        let class = |v: &str| {
            let occ = scan(&format!("services:\n  a:\n    network_mode: {v}\n"));
            occ.get("services.*.network_mode").map(|e| e.class)
        };
        assert_eq!(class("host"), Some(KeyClass::ErrorIncompatible));
        assert_eq!(class("\"container:x\""), Some(KeyClass::ErrorIncompatible));
        assert_eq!(class("\"service:db\""), Some(KeyClass::ErrorUnsupportedYet));
        assert_eq!(class("5"), Some(KeyClass::ErrorUnsupportedYet));
    }

    /// STACK-3: 同じキーが複数サービスにあれば出現数が増える。
    #[test]
    fn occurrences_count_per_service() {
        let occ = scan("services:\n  a: {image: x}\n  b: {image: y}\n");
        assert_eq!(occ.get("services.*.image").map(|e| e.occurrences), Some(2));
        assert_eq!(occ.get("services.*").map(|e| e.occurrences), Some(2));
    }

    /// STACK-3: 未知のキーは Unrecognized（fail-closed）。
    #[test]
    fn unknown_keys_are_unrecognized() {
        let occ = scan("bogus: 1\nservices:\n  a: {bogus2: 1}\n");
        assert_eq!(occ.unrecognized_count(), 2);
    }
}
