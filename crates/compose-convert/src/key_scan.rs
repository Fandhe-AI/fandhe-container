//! compose 文書のキーパス走査器（TASK-151.6・#601・STACK-3・REPAIR-12・MS-12）。
//!
//! 役割: [`crate::compose_convert::parse_compose_yaml`] が返した展開済み文書を歩き、出会ったキーを
//! ユーザー定義名を `*` にした正規形のパスにして [`crate::classify::classify_key_path`] で分類し、
//! [`KeyOccurrences`] に集計する。呼び出し元は #601 の結合試験（`unrecognized` 0 件の機械照合）、
//! bin（#602）のレポート出力、`--downgrade`（TASK-182）を想定する。値の検証・変換は
//! [`crate::convert`] と `ValueDrops` の担当で、本モジュールは値を集計にも返り値にも載せない
//! （`environment` に資格情報が入りうるため）。
//!
//! # 降下規則（分類表 [`crate::classify::KEY_CLASS_TABLE`] から導き、表とずれないようにする）
//!
//! 1. トップレベルの各キーを記録する。
//! 2. 値がマッピングで、表に `<P>.*` の行がある階層（`services`・`networks`・`volumes`・`secrets`・
//!    `configs`）は、子キーをユーザー定義名とみなして `<P>.*` で記録し、その値へ降りる。名前はパスに入れない。
//! 3. それ以外のマッピングは、表に `<P>.` で始まる行があるときだけ子 `<P>.<key>` を記録して降りる。
//!    表に行のある段より下には降りない（`healthcheck`・`environment`・`labels`・`ulimits`・`depends_on`・
//!    `deploy.resources.limits` の中身・`x-*` の中身。[`crate::classify::UNSCANNED_KEY_PREFIXES`] と整合）。
//!    表に無い子（例 `deploy.resources.foo`）は記録して Unrecognized になる（fail-closed）。
//! 4. シーケンスとスカラーには降りない（要素の変換は `convert` の担当）。型が想定と違っても panic しない。
//! 5. `services.*.network_mode` は値で分類を重くする（`host`・`container:` は error-incompatible）。
//! 6. `services.*.volumes` の short syntax の要素が Docker ソケットの bind なら、`services.*.volumes` を
//!    error-incompatible として重く記録する（記録は 1 回）（D-16。long syntax のソケット検出は未対応。REPAIR-3）。
//!
//! 再帰の深さはパーサーの深さ予算に、異なるパスの数は [`crate::report::MAX_KEY_PATHS`] に縛られる。

use crate::classify::{
    KEY_CLASS_TABLE, KeyClass, classify_key_path, classify_network_mode_value,
    is_docker_socket_bind,
};
use crate::compose_convert::{ComposeDocument, ComposeMapping, ComposeValue};
use crate::report::KeyOccurrences;

const NETWORK_MODE: &str = "services.*.network_mode";
const SERVICE_VOLUMES: &str = "services.*.volumes";

/// 文書を走査してキーパス別の分類と出現数を集計する。値は集計に載せない。
pub fn collect_key_occurrences(doc: &ComposeDocument) -> KeyOccurrences {
    let mut occ = KeyOccurrences::new();
    scan_mapping(doc.root(), None, &mut occ);
    occ
}

/// 表に `prefix.` で始まる行があるか（その段に降りてよいか）。
fn table_has_prefix(prefix: &str) -> bool {
    KEY_CLASS_TABLE.iter().any(|(p, _)| {
        p.strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('.'))
    })
}

/// 表に `path` の行そのものがあるか。
fn table_has_row(path: &str) -> bool {
    KEY_CLASS_TABLE.iter().any(|(p, _)| *p == path)
}

/// 入力キー 1 個分をパスの 1 セグメントにする。`.`・`*`・`%` を符号化し、キー内の区切り文字や
/// ワイルドカードが分類表の階層として解釈されて fail-closed を回避されるのを防ぐ（STACK-3）。
/// 符号化後のセグメントは表のどの行にも一致せず、末尾セグメントの `x-` 判定にも `.` で割れない。
fn escape_segment(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for c in key.chars() {
        match c {
            '%' => out.push_str("%25"),
            '.' => out.push_str("%2E"),
            '*' => out.push_str("%2A"),
            c => out.push(c),
        }
    }
    out
}

/// `parent`（正規形。トップレベルは `None`）の子キーを記録し、降りてよい値へ再帰する。
fn scan_mapping(map: &ComposeMapping, parent: Option<&str>, occ: &mut KeyOccurrences) {
    // 親に `<parent>.*` の行があれば、子キーはユーザー定義名として `*` に潰す。
    let wildcard = parent.is_some_and(|p| table_has_row(&format!("{p}.*")));
    for (key, value) in map.iter() {
        let path = match (parent, wildcard) {
            (None, _) => escape_segment(key),
            (Some(p), true) => format!("{p}.*"),
            (Some(p), false) => format!("{p}.{}", escape_segment(key)),
        };
        record_entry(&path, value, occ);
        if let ComposeValue::Mapping(child) = value
            && table_has_prefix(&path)
        {
            scan_mapping(child, Some(&path), occ);
        }
    }
}

/// 1 キーを分類して記録する。値で分類が決まる 2 つのキーだけ値を引く。
fn record_entry(path: &str, value: &ComposeValue, occ: &mut KeyOccurrences) {
    let mut class = classify_key_path(path);
    if path == NETWORK_MODE {
        class = class.heavier(classify_network_mode_value(value.as_str()));
    }
    if path == SERVICE_VOLUMES {
        let has_socket = value.as_sequence().is_some_and(|items| {
            items
                .iter()
                .any(|v| v.as_str().is_some_and(is_docker_socket_bind))
        });
        if has_socket {
            class = class.heavier(KeyClass::ErrorIncompatible);
        }
    }
    // 出現数を正確に保つため、キーごとに 1 回だけ記録する。
    occ.record(path, class);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose_convert::parse_compose_yaml;

    fn scan(yaml: &str) -> KeyOccurrences {
        collect_key_occurrences(&parse_compose_yaml(yaml).expect("fixture parses"))
    }

    /// STACK-3: サービス名は `*` に潰れ、名前はパスに入らない。
    #[test]
    fn service_names_collapse_to_wildcard() {
        let o = scan("services:\n  svcmarker:\n    image: a\n  other:\n    image: b\n");
        assert_eq!(o.get("services.*").map(|e| e.occurrences), Some(2));
        assert_eq!(o.get("services.*.image").map(|e| e.occurrences), Some(2));
        assert!(o.iter().all(|(p, _)| !p.contains("svcmarker")));
        assert_eq!(o.unrecognized_count(), 0);
    }

    /// STACK-3: 想定外の型でも panic せず、降りない。
    #[test]
    fn non_mapping_containers_do_not_descend() {
        let o = scan("services: 3\nnetworks:\n  n:\nvolumes: [a]\n");
        assert_eq!(o.get("services").map(|e| e.occurrences), Some(1));
        assert_eq!(o.get("networks.*").map(|e| e.occurrences), Some(1));
        assert_eq!(o.get("volumes").map(|e| e.occurrences), Some(1));
        assert_eq!(o.unrecognized_count(), 0);
        let o = scan("services:\n  a:\n    deploy: []\n");
        assert!(o.get("services.*.deploy").is_some());
    }

    /// REPAIR-12: 表に行のある段より下には降りない。表に無い子は fail-closed で Unrecognized。
    #[test]
    fn descends_only_where_table_has_rows() {
        let o = scan(
            "services:\n  a:\n    deploy:\n      resources:\n        limits:\n          cpus: '1'\n",
        );
        assert!(o.get("services.*.deploy.resources.limits").is_some());
        assert!(o.get("services.*.deploy.resources.limits.cpus").is_none());
        assert_eq!(o.unrecognized_count(), 0);
        let o = scan("services:\n  a:\n    deploy:\n      resources:\n        foo: 1\n");
        assert_eq!(o.unrecognized_count(), 1);
    }

    /// STACK-3: キー内の `.`・`*` を階層として解釈させて fail-closed を回避できない。
    #[test]
    fn dotted_or_star_keys_stay_unrecognized() {
        let o = scan("\"services.*.image\": x\nservices:\n  a:\n    \"unknown.x-note\": 1\n");
        assert_eq!(o.unrecognized_count(), 2);
        assert!(o.get("services.*.image").is_none());
        assert!(o.get("services").is_some());
    }

    /// STACK-3・D-16: ソケット bind があっても volumes の出現数は 1 回につき 1。
    #[test]
    fn socket_volumes_counted_once() {
        let o = scan("services:\n  a:\n    volumes:\n      - /var/run/docker.sock:/s\n");
        let e = o.get(SERVICE_VOLUMES).expect("recorded");
        assert_eq!((e.class, e.occurrences), (KeyClass::ErrorIncompatible, 1));
    }

    /// STACK-3・D-16: network_mode の値で分類が重くなる。文字列でない値は unsupported-yet。
    #[test]
    fn network_mode_value_raises_class() {
        let o =
            scan("services:\n  a:\n    network_mode: host\n  b:\n    network_mode: 'service:a'\n");
        let e = o.get(NETWORK_MODE).expect("recorded");
        assert_eq!((e.class, e.occurrences), (KeyClass::ErrorIncompatible, 2));
        let o = scan("services:\n  a:\n    network_mode: 3\n");
        assert_eq!(
            o.get(NETWORK_MODE).map(|e| e.class),
            Some(KeyClass::ErrorUnsupportedYet)
        );
    }
}
