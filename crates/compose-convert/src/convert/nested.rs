//! `depends_on`・`ulimits`・`healthcheck` の変換（STACK-3・TASK-151 追補・#3612）。
//!
//! 呼び出し元は [`super::convert_service`]。いずれも `key_scan` が中身へ降りない段（`UNSCANNED_KEY_PREFIXES`）
//! のため、表せない値・未知の子キーはここで分類表のキーパスの drop として数える（fail-closed）。
//! ただし compose-spec が `^x-` を許す位置（`healthcheck` 直下・`depends_on` の long 形の条件・`ulimits` の
//! `{soft, hard}`）の `x-*` は無視してよいキーのため drop に数えない。`key_scan` が Warning として記録する
//! （`EXTENSION_KEY_PARENTS`。#4637）。
//! 記録には値・依存先名・ulimit 名・コマンドを載せない（`test` に資格情報が入りうる。SEC-1）。
//!
//! 値の実効性の検証は実行側に残す（ulimit は supervisor の `Ulimit::parse`、healthcheck は
//! `HealthcheckDefinition::parse`、依存先の存在・循環は stack の depends_on の計画〔STACK-2・STACK-10〕）。

use std::collections::BTreeMap;

use fandhe_container_stack::schema::{DependsOnCondition, Healthcheck};

use super::{MAX_LIST_ITEMS, P_DEPENDS_ON, P_HEALTHCHECK, P_ULIMITS, ValueDrops};
use crate::compose_convert::{ComposeNumber, ComposeValue};

fn valid_name(s: &str) -> bool {
    !s.is_empty() && !s.contains('\0')
}

/// `depends_on`。short（名前のリスト）は `Started`、long（マッピング）は `condition` を写す。
///
/// 未知の `condition` は `Started` へ読み替えず依存ごと出さない。`required: false`・`restart: true`・
/// 未知キーは表現先が無いため drop 1 件にして、依存そのものは condition つきで残す（起動前に止まる安全側）。
pub(super) fn convert_depends_on(
    v: &ComposeValue,
    drops: &mut ValueDrops,
) -> BTreeMap<String, DependsOnCondition> {
    let mut out = BTreeMap::new();
    match v {
        ComposeValue::Null => {}
        ComposeValue::Sequence(items) if items.len() <= MAX_LIST_ITEMS => {
            for item in items {
                match item {
                    ComposeValue::String(s) if valid_name(s) && !out.contains_key(s.as_str()) => {
                        out.insert(s.clone(), DependsOnCondition::Started);
                    }
                    _ => drops.note(P_DEPENDS_ON),
                }
            }
        }
        ComposeValue::Mapping(m) if m.len() <= MAX_LIST_ITEMS => {
            for (name, def) in m.iter() {
                let Some(def) = def.as_mapping().filter(|_| valid_name(name)) else {
                    drops.note(P_DEPENDS_ON);
                    continue;
                };
                let mut cond = Some(DependsOnCondition::Started);
                for (k, val) in def.iter() {
                    if k.starts_with("x-") {
                        continue;
                    }
                    match (k, val) {
                        ("condition", ComposeValue::String(c)) => {
                            cond = match c.as_str() {
                                "service_started" => Some(DependsOnCondition::Started),
                                "service_healthy" => Some(DependsOnCondition::Healthy),
                                "service_completed_successfully" => {
                                    Some(DependsOnCondition::Completed)
                                }
                                _ => None,
                            };
                            if cond.is_none() {
                                drops.note(P_DEPENDS_ON);
                            }
                        }
                        ("required", ComposeValue::Bool(true))
                        | ("restart", ComposeValue::Bool(false)) => {}
                        _ => {
                            if k == "condition" {
                                cond = None;
                            }
                            drops.note(P_DEPENDS_ON);
                        }
                    }
                }
                if let Some(c) = cond {
                    out.insert(name.to_string(), c);
                }
            }
        }
        _ => drops.note(P_DEPENDS_ON),
    }
    out
}

/// ulimit の 1 項目（整数・`-1`・数字だけの文字列）。`:` を含む文字列は soft:hard と誤読されるため受けない。
fn ulimit_item(v: &ComposeValue) -> Option<String> {
    match v {
        ComposeValue::Number(ComposeNumber::PosInt(n)) => Some(n.to_string()),
        ComposeValue::Number(ComposeNumber::NegInt(-1)) => Some("-1".to_string()),
        ComposeValue::String(s)
            if s == "-1" || (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())) =>
        {
            Some(s.clone())
        }
        _ => None,
    }
}

/// `ulimits`。値は `"<soft>[:<hard>]"`。名前は `^[a-z]+$`（`--ulimit name=value` への差し込みを防ぐ）。
///
/// `soft <= hard` と許可リストの検証は supervisor の `Ulimit::parse` の責務。
pub(super) fn convert_ulimits(
    v: &ComposeValue,
    drops: &mut ValueDrops,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    match v {
        ComposeValue::Null => {}
        ComposeValue::Mapping(m) if m.len() <= MAX_LIST_ITEMS => {
            for (name, val) in m.iter() {
                let value = match val {
                    // `x-*` は無視してよいキー。除いた残りがちょうど soft・hard の 2 キーのときだけ受ける。
                    ComposeValue::Mapping(d)
                        if d.iter().filter(|(k, _)| !k.starts_with("x-")).count() == 2 =>
                    {
                        match (
                            d.get("soft").and_then(ulimit_item),
                            d.get("hard").and_then(ulimit_item),
                        ) {
                            (Some(s), Some(h)) => Some(format!("{s}:{h}")),
                            _ => None,
                        }
                    }
                    other => ulimit_item(other),
                };
                let name_ok = !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase());
                match value {
                    Some(s) if name_ok => {
                        out.insert(name.to_string(), s);
                    }
                    _ => drops.note(P_ULIMITS),
                }
            }
        }
        _ => drops.note(P_ULIMITS),
    }
    out
}

/// `test` を argv へ正規化する。表せなければ `None`（healthcheck 全体を出さない）。
fn convert_test(v: &ComposeValue) -> Option<Vec<String>> {
    let shell = |s: &str| vec!["/bin/sh".to_string(), "-c".to_string(), s.to_string()];
    match v {
        ComposeValue::String(s) if valid_name(s) => Some(shell(s)),
        ComposeValue::Sequence(items) if items.len() <= MAX_LIST_ITEMS => {
            let strs = items
                .iter()
                .map(|i| match i {
                    ComposeValue::String(s) if !s.contains('\0') => Some(s.as_str()),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()?;
            match strs.split_first()? {
                (&"CMD", rest) if !rest.is_empty() => {
                    Some(rest.iter().map(|s| s.to_string()).collect())
                }
                (&"CMD-SHELL", [one]) => Some(shell(one)),
                _ => None,
            }
        }
        _ => None,
    }
}

fn time_string(v: &ComposeValue) -> Option<String> {
    match v {
        ComposeValue::String(s) if valid_name(s) => Some(s.clone()),
        _ => None,
    }
}

fn retries(v: &ComposeValue) -> Option<i64> {
    match v {
        ComposeValue::Number(ComposeNumber::PosInt(n)) => i64::try_from(*n).ok(),
        ComposeValue::Number(ComposeNumber::NegInt(n)) => Some(*n),
        ComposeValue::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse().ok()
        }
        _ => None,
    }
}

/// `healthcheck`。`CMD` は剥がし、`CMD-SHELL` と文字列形は `["/bin/sh", "-c", s]` にする（シェル文字列を連結しない）。
///
/// `NONE`・`disable: true`・解釈できない `test` は検査の意味が変わるため healthcheck 全体を `None` にして
/// drop 1 件とする。`start_interval`・未知キーは drop 1 件で残りを変換する。
/// 制限: イメージの `SHELL` 指定は反映しない。名前指定の argv[0] は解決せずそのまま渡す（#2439 の判断待ち）。
pub(super) fn convert_healthcheck(v: &ComposeValue, drops: &mut ValueDrops) -> Option<Healthcheck> {
    let m = match v {
        ComposeValue::Null => return None,
        ComposeValue::Mapping(m) if m.len() <= MAX_LIST_ITEMS => m,
        _ => {
            drops.note(P_HEALTHCHECK);
            return None;
        }
    };
    let mut hc = Healthcheck::default();
    let mut invalid = false;
    for (k, val) in m.iter() {
        if k.starts_with("x-") {
            continue;
        }
        let ok = match k {
            "test" => match convert_test(val) {
                Some(t) => {
                    hc.test = Some(t);
                    true
                }
                None => {
                    invalid = true;
                    false
                }
            },
            "interval" => time_string(val).map(|s| hc.interval = Some(s)).is_some(),
            "timeout" => time_string(val).map(|s| hc.timeout = Some(s)).is_some(),
            "start_period" => time_string(val)
                .map(|s| hc.start_period = Some(s))
                .is_some(),
            "retries" => retries(val).map(|n| hc.retries = Some(n)).is_some(),
            "disable" => {
                let ok = matches!(val, ComposeValue::Bool(false));
                invalid |= !ok;
                ok
            }
            _ => false,
        };
        if !ok {
            drops.note(P_HEALTHCHECK);
        }
    }
    if invalid { None } else { Some(hc) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose_convert::parse_compose_yaml;

    fn val(yaml: &str) -> ComposeValue {
        parse_compose_yaml(&format!("k: {yaml}\n"))
            .unwrap()
            .get("k")
            .unwrap()
            .clone()
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// STACK-3・STACK-2: short / long と condition の写し。
    #[test]
    fn stack3_depends_on_short_and_long() {
        let mut d = ValueDrops::new();
        let o = convert_depends_on(&val("[a, b]"), &mut d);
        assert_eq!(o.get("a"), Some(&DependsOnCondition::Started));
        assert_eq!(o.len(), 2);
        assert!(d.is_empty());
        let o = convert_depends_on(
            &val(
                "{a: {condition: service_healthy, required: true}, b: {condition: service_completed_successfully}, c: {}}",
            ),
            &mut d,
        );
        assert_eq!(o.get("a"), Some(&DependsOnCondition::Healthy));
        assert_eq!(o.get("b"), Some(&DependsOnCondition::Completed));
        assert_eq!(o.get("c"), Some(&DependsOnCondition::Started));
        assert!(d.is_empty());
    }

    /// STACK-3: 表せない値は drop。未知 condition は依存ごと出さない。
    #[test]
    fn stack3_depends_on_drops() {
        let mut d = ValueDrops::new();
        let o = convert_depends_on(&val("[a, a, 1, '']"), &mut d);
        assert_eq!(o.len(), 1);
        assert_eq!(d.get(P_DEPENDS_ON), 3);
        let mut d = ValueDrops::new();
        let o = convert_depends_on(&val("{a: {condition: bogus}}"), &mut d);
        assert!(o.is_empty());
        assert_eq!(d.get(P_DEPENDS_ON), 1);
        let mut d = ValueDrops::new();
        let o = convert_depends_on(
            &val("{a: {required: false}, b: {restart: true}, c: {x-y: 1}, d: ~, e: 1}"),
            &mut d,
        );
        assert_eq!(
            o.keys().cloned().collect::<Vec<_>>(),
            strs(&["a", "b", "c"])
        );
        // `c: {x-y: 1}` の `x-y` は拡張キーのため drop に数えない（変更前は 5 件）。
        assert_eq!(d.get(P_DEPENDS_ON), 4);
        let mut d = ValueDrops::new();
        assert!(convert_depends_on(&val("3"), &mut d).is_empty());
        assert_eq!(d.get(P_DEPENDS_ON), 1);
        let mut d = ValueDrops::new();
        assert!(convert_depends_on(&val("~"), &mut d).is_empty());
        assert!(d.is_empty());
    }

    /// STACK-3: ulimits の写しと drop。
    #[test]
    fn stack3_ulimits() {
        let mut d = ValueDrops::new();
        let o = convert_ulimits(
            &val("{nofile: 1024, core: -1, nproc: '65536', stack: {soft: 1, hard: 2}}"),
            &mut d,
        );
        assert_eq!(o.get("nofile").map(String::as_str), Some("1024"));
        assert_eq!(o.get("core").map(String::as_str), Some("-1"));
        assert_eq!(o.get("nproc").map(String::as_str), Some("65536"));
        assert_eq!(o.get("stack").map(String::as_str), Some("1:2"));
        assert!(d.is_empty());
        let mut d = ValueDrops::new();
        let o = convert_ulimits(
            &val(
                "{a: '1:2', b: -2, c: 1.5, d: {soft: 1}, e: {soft: 1, hard: 2, x: 3}, F: 1, g=h: 1, ok: 3}",
            ),
            &mut d,
        );
        assert_eq!(o.len(), 1);
        assert_eq!(d.get(P_ULIMITS), 7);
    }

    /// STACK-3・#4637: 降りない段の `x-*` は drop に数えない。`x-` でない未知キーは従来どおり数える。
    #[test]
    fn stack3_extension_keys_are_not_drops() {
        let (h, d) = hc("{test: [CMD, a], x-note: 1}");
        assert!(h.is_some() && d.is_empty());
        let mut d = ValueDrops::new();
        let o = convert_depends_on(&val("{a: {condition: service_healthy, x-n: 1}}"), &mut d);
        assert_eq!(o.get("a"), Some(&DependsOnCondition::Healthy));
        assert!(d.is_empty());
        // 依存先名が `x-` で始まっても拡張キーではない（サービス名）。
        let o = convert_depends_on(&val("{x-db: {condition: service_started}}"), &mut d);
        assert_eq!(o.get("x-db"), Some(&DependsOnCondition::Started));
        assert!(d.is_empty());
        let mut d = ValueDrops::new();
        let o = convert_ulimits(&val("{stack: {soft: 1, hard: 2, x-n: 1}}"), &mut d);
        assert_eq!(o.get("stack").map(String::as_str), Some("1:2"));
        assert!(d.is_empty());
        // 欠けた soft・未知キーは従来どおり drop。ulimit 名の `x-` は名前検証で落ちる。
        let o = convert_ulimits(
            &val("{a: {soft: 1, x-n: 1}, b: {soft: 1, hard: 2, foo: 1}, x-c: 3}"),
            &mut d,
        );
        assert!(o.is_empty());
        assert_eq!(d.get(P_ULIMITS), 3);
    }

    fn hc(yaml: &str) -> (Option<Healthcheck>, ValueDrops) {
        let mut d = ValueDrops::new();
        (convert_healthcheck(&val(yaml), &mut d), d)
    }

    /// STACK-3・SUP-4: test の正規化。
    #[test]
    fn stack3_healthcheck_test_forms() {
        let t = |y: &str| hc(y).0.unwrap().test;
        assert_eq!(
            t("{test: [CMD, /bin/true, -x]}"),
            Some(strs(&["/bin/true", "-x"]))
        );
        assert_eq!(
            t("{test: [CMD-SHELL, 'a | b']}"),
            Some(strs(&["/bin/sh", "-c", "a | b"]))
        );
        assert_eq!(
            t("{test: 'pg_isready'}"),
            Some(strs(&["/bin/sh", "-c", "pg_isready"]))
        );
        assert_eq!(t("{interval: 5s}"), None);
        for bad in [
            "{test: [CMD]}",
            "{test: [NONE]}",
            "{test: []}",
            "{test: [X, a]}",
            "{test: [CMD, 1]}",
            "{test: ''}",
            "{test: 1}",
            "{test: [CMD-SHELL, a, b]}",
            "{test: [CMD, a], disable: true}",
            "{test: [CMD, a], disable: 1}",
            "3",
        ] {
            let (h, d) = hc(bad);
            assert!(h.is_none(), "{bad}");
            assert_eq!(d.get(P_HEALTHCHECK), 1, "{bad}");
        }
        let (h, d) = hc("{test: [CMD, a], disable: false}");
        assert!(h.is_some() && d.is_empty());
        let (h, d) = hc("~");
        assert!(h.is_none() && d.is_empty());
    }

    /// STACK-3: 時間・retries・未知キー。
    #[test]
    fn stack3_healthcheck_fields() {
        let (h, d) =
            hc("{test: [CMD, a], interval: 30s, timeout: 5s, start_period: 10s, retries: 3}");
        let h = h.unwrap();
        assert_eq!(h.interval.as_deref(), Some("30s"));
        assert_eq!(h.timeout.as_deref(), Some("5s"));
        assert_eq!(h.start_period.as_deref(), Some("10s"));
        assert_eq!(h.retries, Some(3));
        assert!(d.is_empty());
        let (h, _) = hc("{retries: -1}");
        assert_eq!(h.unwrap().retries, Some(-1));
        let (h, _) = hc("{retries: '4'}");
        assert_eq!(h.unwrap().retries, Some(4));
        let (h, d) = hc("{retries: 1.5, interval: 5, timeout: 1s, start_interval: 1s, x-a: 1}");
        let h = h.unwrap();
        assert_eq!(
            (h.retries, h.interval, h.timeout.as_deref()),
            (None, None, Some("1s"))
        );
        // `x-a` は拡張キーのため数えない（変更前は 4 件）。
        assert_eq!(d.get(P_HEALTHCHECK), 3);
        let (h, d) = hc("{retries: 3x}");
        assert!(h.unwrap().retries.is_none());
        assert_eq!(d.get(P_HEALTHCHECK), 1);
    }

    /// SEC-1: 記録に値が載らない。
    #[test]
    fn sec1_drops_do_not_contain_values() {
        let (_, d) = hc("{test: [NONE, SENTINEL_SECRET_42]}");
        assert!(!format!("{d:?}").contains("SENTINEL_SECRET_42"));
    }
}
