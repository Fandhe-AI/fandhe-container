//! `deploy.resources` と GPU 予約の変換（STACK-3・STACK-9・TASK-151 追補・#3612）。
//!
//! 呼び出し元は [`super::convert_service`]。`key_scan` が降りる段（`deploy`・`resources`・`reservations`
//! 直下）の未知の子・範囲外の子（`replicas`・`placement`・`reservations.cpus` 等）は `key_scan` が記録済みの
//! ため、ここでは数えず無視する（二重計上の回避。格下げしたキーを TOML に出さない契約とも整合）。
//! `limits` の中身は `key_scan` が降りないので、未知の子（`pids` 等）は drop として数える。
//!
//! 判断（Agent の記録）: `limits.cpus` の有限の Float だけは例外として `{}` 表示の文字列へ写す
//! （compose-spec 上 number で、`cpus: 0.5` が一般的。数値の意味だけが重要）。他の Float は drop のまま。
//! GPU の予約をまたぐ重複名は先の 1 件だけ残し、除いた分を drop に数える（GPU の意味を黙って変えない）。

use std::collections::BTreeSet;

use fandhe_container_stack::schema::{
    Deploy, DeployResources, ResourceLimits, ResourceReservations,
};

use super::{
    MAX_LIST_ITEMS, P_DEPLOY, P_DEPLOY_LIMITS, P_DEPLOY_RESERVATIONS, P_DEPLOY_RESOURCES,
    ValueDrops,
};
use crate::compose_convert::{ComposeNumber, ComposeValue};
use crate::gpu_reservation::{ComposeNode, DEVICES_KEY_PATH, convert_gpu_reservations};

/// GPU 予約の検出器へ YAML 値を渡すための読み取り口（#3612。`ComposeValue` の同名メソッドへ委譲）。
impl ComposeNode for ComposeValue {
    fn as_str(&self) -> Option<&str> {
        ComposeValue::as_str(self)
    }
    fn as_u64(&self) -> Option<u64> {
        ComposeValue::as_u64(self)
    }
    fn as_sequence(&self) -> Option<&[Self]> {
        ComposeValue::as_sequence(self)
    }
    fn is_mapping(&self) -> bool {
        ComposeValue::is_mapping(self)
    }
    fn get(&self, key: &str) -> Option<&Self> {
        ComposeValue::get(self, key)
    }
}

fn cpus(v: &ComposeValue) -> Option<String> {
    match v {
        ComposeValue::String(s) if !s.is_empty() && !s.contains('\0') => Some(s.clone()),
        ComposeValue::Number(ComposeNumber::PosInt(n)) => Some(n.to_string()),
        ComposeValue::Number(ComposeNumber::Float(f)) if f.is_finite() => Some(f.to_string()),
        _ => None,
    }
}

fn memory(v: &ComposeValue) -> Option<String> {
    match v {
        ComposeValue::String(s) if !s.is_empty() && !s.contains('\0') => Some(s.clone()),
        ComposeValue::Number(ComposeNumber::PosInt(n)) => Some(n.to_string()),
        _ => None,
    }
}

fn convert_limits(v: &ComposeValue, drops: &mut ValueDrops) -> Option<ResourceLimits> {
    let m = match v {
        ComposeValue::Null => return None,
        ComposeValue::Mapping(m) if m.len() <= MAX_LIST_ITEMS => m,
        _ => {
            drops.note(P_DEPLOY_LIMITS);
            return None;
        }
    };
    let mut out = ResourceLimits::default();
    for (k, val) in m.iter() {
        // compose-spec が許す拡張キー。無視してよいので drop に数えず、key_scan が Warning で記録する。
        if k.starts_with("x-") {
            continue;
        }
        let ok = match k {
            "cpus" => cpus(val).map(|s| out.cpus = Some(s)).is_some(),
            "memory" => memory(val).map(|s| out.memory = Some(s)).is_some(),
            _ => false,
        };
        if !ok {
            drops.note(P_DEPLOY_LIMITS);
        }
    }
    (out != ResourceLimits::default()).then_some(out)
}

/// 変換器が参照する GPU 予約の属性（これ以外は TOML に表せないため drop に数える）。
const GPU_ATTRS: [&str; 4] = ["driver", "capabilities", "count", "device_ids"];

/// 各予約エントリの未対応属性（`options`・未知キー）を 1 キー 1 件で `DEVICES_KEY_PATH` へ数える
/// （STACK-3 の fail-closed。検出器は参照しないキーを見ないため、ここで補う）。`x-*` は無視してよい
/// 拡張キーなので数えず、`key_scan` が Warning で記録する（#4637）。
///
/// 判断（Agent の記録）: 未知フィールドの検査を検出段（`gpu_reservation`）へ移さないのは、公開トレイト
/// `ComposeNode` にキーの列挙が無く、移すにはトレイトの変更が要るため。`options` 付きの予約は変換したまま
/// drop を 1 件残す。`value_drops` が空でなくなり `error_free` が false になるので TOML は出力されず、
/// `--downgrade` でも blocker に残るため、`options` を黙って落とした設定が使われることはない。検出段で
/// 対象外になった要素（例 `driver: amd`）の未知キーは、要素の理由 1 件と属性 1 件で二重に数える。
/// 再評価の条件: `ComposeNode` にキー列挙を足す変更が入るとき、予約ごと対象外にする案も併せて見直す。
fn note_unsupported_device_attrs(devices: &ComposeValue, drops: &mut ValueDrops) {
    let Some(items) = devices.as_sequence() else {
        return;
    };
    if items.len() > MAX_LIST_ITEMS {
        return;
    }
    for item in items {
        if let ComposeValue::Mapping(m) = item {
            for (k, _) in m.iter() {
                if !GPU_ATTRS.contains(&k) && !k.starts_with("x-") {
                    drops.note(DEVICES_KEY_PATH);
                }
            }
        }
    }
}

fn convert_reservations(v: &ComposeValue, drops: &mut ValueDrops) -> Option<ResourceReservations> {
    let m = match v {
        ComposeValue::Null => return None,
        ComposeValue::Mapping(m) => m,
        _ => {
            drops.note(P_DEPLOY_RESERVATIONS);
            return None;
        }
    };
    let devices = m.get("devices")?;
    if matches!(devices, ComposeValue::Null) {
        return None;
    }
    let conv = convert_gpu_reservations(devices);
    drops.note_many(DEVICES_KEY_PATH, conv.drop_count());
    note_unsupported_device_attrs(devices, drops);
    let mut seen = BTreeSet::new();
    let mut names = Vec::new();
    for name in conv.devices() {
        if seen.insert(name.clone()) {
            names.push(name);
        } else {
            drops.note(DEVICES_KEY_PATH);
        }
    }
    (!names.is_empty()).then_some(ResourceReservations { devices: names })
}

/// `deploy`。`resources` の `limits`・`reservations.devices` だけを写し、空なら `None`。
pub(super) fn convert_deploy(v: &ComposeValue, drops: &mut ValueDrops) -> Option<Deploy> {
    let m = match v {
        ComposeValue::Null => return None,
        ComposeValue::Mapping(m) => m,
        _ => {
            drops.note(P_DEPLOY);
            return None;
        }
    };
    let res = match m.get("resources")? {
        ComposeValue::Null => return None,
        ComposeValue::Mapping(r) => r,
        _ => {
            drops.note(P_DEPLOY_RESOURCES);
            return None;
        }
    };
    let limits = res.get("limits").and_then(|l| convert_limits(l, drops));
    let reservations = res
        .get("reservations")
        .and_then(|r| convert_reservations(r, drops));
    if limits.is_none() && reservations.is_none() {
        return None;
    }
    Some(Deploy {
        resources: Some(DeployResources {
            limits,
            reservations,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose_convert::parse_compose_yaml;

    fn conv(yaml: &str) -> (Option<Deploy>, ValueDrops) {
        let v = parse_compose_yaml(&format!("k: {yaml}\n"))
            .unwrap()
            .get("k")
            .unwrap()
            .clone();
        let mut d = ValueDrops::new();
        (convert_deploy(&v, &mut d), d)
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// STACK-3: limits の写し。Float の例外と NaN の drop。
    #[test]
    fn stack3_limits() {
        let (o, d) = conv("{resources: {limits: {cpus: 0.5, memory: 512M}}}");
        let l = o.unwrap().resources.unwrap().limits.unwrap();
        assert_eq!(l.cpus.as_deref(), Some("0.5"));
        assert_eq!(l.memory.as_deref(), Some("512M"));
        assert!(d.is_empty());
        let (o, _) = conv("{resources: {limits: {cpus: '2.5', memory: 1024}}}");
        let l = o.unwrap().resources.unwrap().limits.unwrap();
        assert_eq!(
            (l.cpus.as_deref(), l.memory.as_deref()),
            (Some("2.5"), Some("1024"))
        );
        let (o, _) = conv("{resources: {limits: {cpus: 2}}}");
        assert_eq!(
            o.unwrap()
                .resources
                .unwrap()
                .limits
                .unwrap()
                .cpus
                .as_deref(),
            Some("2")
        );
        let (o, d) = conv("{resources: {limits: {cpus: [1], pids: 5, memory: 1.5}}}");
        assert!(o.is_none());
        assert_eq!(d.get(P_DEPLOY_LIMITS), 3);
        // x-* は数えない。x- でない未知キーは従来どおり数える。
        let (o, d) = conv("{resources: {limits: {cpus: 1, x-n: 1}}}");
        assert!(o.is_some() && d.is_empty());
        let (_, d) = conv("{resources: {limits: {cpus: 1, pids: 1}}}");
        assert_eq!(d.get(P_DEPLOY_LIMITS), 1);
    }

    /// STACK-3: 型不一致は各パスで drop。非 resources の子は key_scan の責務で数えない。
    #[test]
    fn stack3_type_mismatch_paths() {
        assert_eq!(conv("[]").1.get(P_DEPLOY), 1);
        assert_eq!(conv("{resources: 1}").1.get(P_DEPLOY_RESOURCES), 1);
        assert_eq!(conv("{resources: {limits: 1}}").1.get(P_DEPLOY_LIMITS), 1);
        assert_eq!(
            conv("{resources: {reservations: 1}}")
                .1
                .get(P_DEPLOY_RESERVATIONS),
            1
        );
        let (o, d) = conv("{replicas: 2, placement: {}, resources: {reservations: {cpus: 1}}}");
        assert!(o.is_none() && d.is_empty());
        let (o, d) = conv("{}");
        assert!(o.is_none() && d.is_empty());
    }

    fn gpu(extra: &str) -> (Option<Deploy>, ValueDrops) {
        conv(&format!(
            "{{resources: {{reservations: {{devices: [{{driver: nvidia, capabilities: [gpu]{extra}}}]}}}}}}"
        ))
    }

    /// STACK-9: GPU 予約の変換と drop。
    #[test]
    fn stack9_gpu_reservations() {
        let names = |o: Option<Deploy>| o.unwrap().resources.unwrap().reservations.unwrap().devices;
        let (o, d) = gpu(", device_ids: ['0', '1']");
        assert_eq!(names(o), strs(&["nvidia.com/gpu=0", "nvidia.com/gpu=1"]));
        assert!(d.is_empty());
        assert_eq!(names(gpu(", count: all").0), strs(&["nvidia.com/gpu=all"]));
        assert_eq!(names(gpu("").0), strs(&["nvidia.com/gpu=all"]));
        let (o, d) = gpu(", count: 1");
        assert!(o.is_none());
        assert_eq!(d.get(DEVICES_KEY_PATH), 1);
        let (o, d) = conv("{resources: {reservations: {devices: ~}}}");
        assert!(o.is_none() && d.is_empty());
    }

    /// STACK-3・STACK-9: `options` や未知キーは黙って捨てず drop に数える。
    #[test]
    fn stack9_unsupported_device_attrs_are_dropped() {
        let (o, d) = gpu(", options: {foo: bar}");
        assert_eq!(d.get(DEVICES_KEY_PATH), 1);
        assert!(o.is_some());
        let (_, d) = gpu(", options: {a: b}, unknown: 1");
        assert_eq!(d.get(DEVICES_KEY_PATH), 2);
        // x-* は数えない（変更前は 1 件）。
        let (o, d) = gpu(", x-note: 1");
        assert!(o.is_some() && d.is_empty());
        // 検出段で対象外の要素（driver: amd）は要素の理由 1 件 + 未知キー 1 件で 2 件。
        let (o, d) = conv(
            "{resources: {reservations: {devices: [{driver: amd, capabilities: [gpu], options: {a: b}}]}}}",
        );
        assert!(o.is_none());
        assert_eq!(d.get(DEVICES_KEY_PATH), 2);
    }

    /// STACK-9: 予約をまたぐ重複は先の 1 件を残して drop。
    #[test]
    fn stack9_duplicate_across_reservations() {
        let (o, d) = conv(
            "{resources: {reservations: {devices: [{driver: nvidia, capabilities: [gpu]}, {driver: nvidia, capabilities: [gpu]}]}}}",
        );
        let r = o.unwrap().resources.unwrap().reservations.unwrap();
        assert_eq!(r.devices, strs(&["nvidia.com/gpu=all"]));
        assert_eq!(d.get(DEVICES_KEY_PATH), 1);
    }
}
