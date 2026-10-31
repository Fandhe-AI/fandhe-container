//! パース済みの compose モデル（[`ComposeValue`]）から、スカラーと short syntax のキーを
//! `fandhe-container-stack` の TOML 型へ変換する（STACK-3・TASK-151.3.1・#864・MS-12）。
//!
//! 呼び出し元は #599（変換レポート）と #602（bin の結線）。型が合わない値・分割できない値・TOML に
//! 表せない属性は黙って捨てず、[`ValueDrops`] へ分類表のキーパスで件数を記録する（fail-closed）。
//! 記録には値・環境変数名・サービス名を載せない（`environment` に資格情報が入りうるため）。
//!
//! long syntax のマッピング要素（ports・volumes・secrets・configs・tmpfs・devices）は
//! [`crate::long_syntax`]（#865）の変換へ回し、表せない要素は要素ごと drop として記録する（結線は #599）。
//! スタブの範囲（REPAIR-3）: `depends_on`・`ulimits`・`healthcheck`・`deploy` は本 issue で変換せず、
//! [`ServiceConversion::unhandled`] に分類表のパスで載せる（呼び出し側が黙って通さないため。担当は後続）。
//! `Float` は元の書き方を復元できないため文字列へ直さず drop する。

use std::collections::BTreeMap;

use fandhe_container_stack::schema::{
    ComposeToml, Config, Network, Project, Secret, Service, Volume,
};

use crate::compose_convert::{ComposeDocument, ComposeMapping, ComposeNumber, ComposeValue};
use crate::long_syntax::{LongSyntaxKey, convert_long_syntax_element};
use crate::shell_split::{ShellSplitError, split_command};

/// リスト・マッピングの要素数の上限。確保の前に確かめる（DoS 対策）。
pub const MAX_LIST_ITEMS: usize = 4096;

const P_NAME: &str = "name";
const P_SERVICE: &str = "services.*";
const P_IMAGE: &str = "services.*.image";
const P_CONTAINER_NAME: &str = "services.*.container_name";
const P_WORKING_DIR: &str = "services.*.working_dir";
const P_COMMAND: &str = "services.*.command";
const P_ENTRYPOINT: &str = "services.*.entrypoint";
const P_ENVIRONMENT: &str = "services.*.environment";
const P_ENV_FILE: &str = "services.*.env_file";
const P_PORTS: &str = "services.*.ports";
const P_NETWORKS: &str = "services.*.networks";
const P_VOLUMES: &str = "services.*.volumes";
const P_RESTART: &str = "services.*.restart";
const P_SECRETS: &str = "services.*.secrets";
const P_CONFIGS: &str = "services.*.configs";
const P_LABELS: &str = "services.*.labels";
const P_SHM_SIZE: &str = "services.*.shm_size";
const P_TMPFS: &str = "services.*.tmpfs";
const P_DEVICES: &str = "services.*.devices";
const P_PROFILES: &str = "services.*.profiles";
const P_TOP_NETWORK: &str = "networks.*";
const P_TOP_NETWORK_DRIVER: &str = "networks.*.driver";
const P_TOP_NETWORK_EXTERNAL: &str = "networks.*.external";
const P_TOP_VOLUME: &str = "volumes.*";
const P_TOP_VOLUME_DRIVER: &str = "volumes.*.driver";
const P_TOP_VOLUME_EXTERNAL: &str = "volumes.*.external";
const P_TOP_SECRET: &str = "secrets.*";
const P_TOP_SECRET_FILE: &str = "secrets.*.file";
const P_TOP_SECRET_EXTERNAL: &str = "secrets.*.external";
const P_TOP_CONFIG: &str = "configs.*";
const P_TOP_CONFIG_FILE: &str = "configs.*.file";
const P_TOP_CONFIG_EXTERNAL: &str = "configs.*.external";

/// drop の記録に使うキーパスの全件（分類表の Convert 行と一致することを試験で照合する）。
pub const DROP_KEY_PATHS: &[&str] = &[
    P_NAME,
    P_SERVICE,
    P_IMAGE,
    P_CONTAINER_NAME,
    P_WORKING_DIR,
    P_COMMAND,
    P_ENTRYPOINT,
    P_ENVIRONMENT,
    P_ENV_FILE,
    P_PORTS,
    P_NETWORKS,
    P_VOLUMES,
    P_RESTART,
    P_SECRETS,
    P_CONFIGS,
    P_LABELS,
    P_SHM_SIZE,
    P_TMPFS,
    P_DEVICES,
    P_PROFILES,
    P_TOP_NETWORK,
    P_TOP_NETWORK_DRIVER,
    P_TOP_NETWORK_EXTERNAL,
    P_TOP_VOLUME,
    P_TOP_VOLUME_DRIVER,
    P_TOP_VOLUME_EXTERNAL,
    P_TOP_SECRET,
    P_TOP_SECRET_FILE,
    P_TOP_SECRET_EXTERNAL,
    P_TOP_CONFIG,
    P_TOP_CONFIG_FILE,
    P_TOP_CONFIG_EXTERNAL,
];

/// 変換できずに捨てた値の件数（分類表のキーパス別）。値・名前は載せない。
///
/// レポートの形・`error_free` の判定は [`crate::report`]（#599）。GPU 予約の drop（`gpu_reservation`）も
/// 同じ記録先へ足される前提。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValueDrops {
    counts: BTreeMap<&'static str, u64>,
}

impl ValueDrops {
    /// 空の記録。
    pub fn new() -> Self {
        Self::default()
    }

    /// `key_path` の drop を 1 件足す。
    pub fn note(&mut self, key_path: &'static str) {
        let c = self.counts.entry(key_path).or_insert(0);
        *c = c.saturating_add(1);
    }

    /// `key_path` の drop を `n` 件まとめて足す（加算は飽和。`n == 0` は記録を作らない）。
    ///
    /// GPU 予約の `GpuReservationConversion::drop_count()` を `gpu_reservation::DEVICES_KEY_PATH` へ
    /// 足す統合点（STACK-3・STACK-9）。`deploy` の変換と GPU 予約の実加算の結線は未実装（REPAIR-3）。
    pub fn note_many(&mut self, key_path: &'static str, n: u64) {
        if n == 0 {
            return;
        }
        let c = self.counts.entry(key_path).or_insert(0);
        *c = c.saturating_add(n);
    }

    /// `key_path` の件数。
    pub fn get(&self, key_path: &str) -> u64 {
        self.counts.get(key_path).copied().unwrap_or(0)
    }

    /// `(キーパス, 件数)` をキーパス順に返す。
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        self.counts.iter().map(|(k, v)| (*k, *v))
    }

    /// 記録が無いか。
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// 全件数の合計。
    pub fn total(&self) -> u64 {
        self.counts.values().fold(0u64, |a, b| a.saturating_add(*b))
    }
}

/// 1 サービスの変換結果。
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ServiceConversion {
    /// 変換したサービス。定義がマッピングでなければ `None`。
    pub service: Option<Service>,
    /// 本 issue では変換せず見送った convert キー（分類表のパス）。呼び出し側が黙って通さないこと。
    pub unhandled: Vec<&'static str>,
}

/// スカラーを文字列へ直す。文字列・真偽値・整数のみ。Float・NUL を含む文字列は `None`。
pub fn scalar_to_string(v: &ComposeValue) -> Option<String> {
    match v {
        ComposeValue::String(s) if !s.contains('\0') => Some(s.clone()),
        ComposeValue::Bool(b) => Some(b.to_string()),
        ComposeValue::Number(ComposeNumber::PosInt(n)) => Some(n.to_string()),
        ComposeValue::Number(ComposeNumber::NegInt(n)) => Some(n.to_string()),
        _ => None,
    }
}

/// `command` / `entrypoint`。文字列は分割し、リストは文字列・整数の要素のみ。
/// 1 つでも変換できなければキー全体を出さない（argv は要素を落とすと意味が変わる）。
pub fn convert_argv(
    v: &ComposeValue,
    path: &'static str,
    drops: &mut ValueDrops,
) -> Option<Vec<String>> {
    let out = match v {
        // null は「指定なし」を表す有効な値で、変換先では None で表せる（drop に数えない）。
        ComposeValue::Null => return None,
        ComposeValue::String(s) => match split_command(s) {
            Ok(v) => Some(v),
            // 空文字列は「イメージの既定を打ち消す」意味なので、None（キー無し）と区別して `[]` にする。
            Err(ShellSplitError::Empty) => Some(Vec::new()),
            Err(_) => None,
        },
        ComposeValue::Sequence(items) if items.len() <= MAX_LIST_ITEMS => items
            .iter()
            .map(scalar_for_argv)
            .collect::<Option<Vec<_>>>(),
        _ => None,
    };
    if out.is_none() {
        drops.note(path);
    }
    out
}

fn scalar_for_argv(v: &ComposeValue) -> Option<String> {
    match v {
        ComposeValue::Bool(_) => None,
        other => scalar_to_string(other),
    }
}

/// `environment` / `labels`。マッピング形とリスト形を受け、要素単位で drop を記録する。
pub fn convert_kv(
    v: &ComposeValue,
    path: &'static str,
    drops: &mut ValueDrops,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    match v {
        ComposeValue::Null => {}
        ComposeValue::Mapping(m) if m.len() <= MAX_LIST_ITEMS => {
            for (k, val) in m.iter() {
                // null は空文字列へ読み替える（stack の契約。compose ではホスト環境から取る意味で異なる）。
                let value = match val {
                    ComposeValue::Null => Some(String::new()),
                    other => scalar_to_string(other),
                };
                match value {
                    Some(s) if !k.is_empty() && !k.contains('\0') => {
                        out.insert(k.to_string(), s);
                    }
                    _ => drops.note(path),
                }
            }
        }
        ComposeValue::Sequence(items) if items.len() <= MAX_LIST_ITEMS => {
            for item in items {
                let Some(ComposeValue::String(s)) = Some(item) else {
                    drops.note(path);
                    continue;
                };
                if s.contains('\0') {
                    drops.note(path);
                    continue;
                }
                let (k, val) = s.split_once('=').unwrap_or((s.as_str(), ""));
                if k.is_empty() || out.contains_key(k) {
                    drops.note(path);
                } else {
                    out.insert(k.to_string(), val.to_string());
                }
            }
        }
        _ => drops.note(path),
    }
    out
}

/// 文字列（または文字列・整数）の要素のリスト。単独の文字列は `allow_scalar` のとき 1 要素として受ける。
fn string_items(
    v: &ComposeValue,
    path: &'static str,
    allow_scalar: bool,
    allow_int: bool,
    long: Option<LongSyntaxKey>,
    drops: &mut ValueDrops,
) -> Vec<String> {
    let one = |item: &ComposeValue| -> Option<String> {
        match item {
            ComposeValue::String(s) if !s.is_empty() && !s.contains('\0') => Some(s.clone()),
            ComposeValue::Number(_) if allow_int => scalar_to_string(item),
            _ => None,
        }
    };
    match v {
        ComposeValue::String(_) if allow_scalar => match one(v) {
            Some(s) => vec![s],
            None => {
                drops.note(path);
                Vec::new()
            }
        },
        ComposeValue::Sequence(items) if items.len() <= MAX_LIST_ITEMS => {
            let mut out = Vec::new();
            for item in items {
                // long syntax のマッピング要素は #865 の変換へ回す。drop はここで 1 回だけ数える
                // （下の `one` も Mapping に None を返すため、先に分岐して二重計上を防ぐ）。
                if let (Some(k), ComposeValue::Mapping(m)) = (long, item) {
                    match convert_long_syntax_element(k, m) {
                        Ok(c) => out.push(c.short_syntax),
                        Err(d) => drops.note(d.key_path()),
                    }
                    continue;
                }
                match one(item) {
                    Some(s) => out.push(s),
                    None => drops.note(path),
                }
            }
            out
        }
        // 値なしのキー（YAML null）は「項目なし」。convert_argv・convert_kv と同じく drop に数えない。
        ComposeValue::Null => Vec::new(),
        _ => {
            drops.note(path);
            Vec::new()
        }
    }
}

/// `env_file`。文字列・文字列のリスト。マッピング要素（long syntax）は表せないため drop（long syntax の変換は回さない）。
pub fn convert_env_file(v: &ComposeValue, drops: &mut ValueDrops) -> Vec<String> {
    string_items(v, P_ENV_FILE, true, false, None, drops)
}

/// `ports` の short syntax。マッピング要素は long syntax の変換へ回す（表せなければ drop）。
pub fn convert_ports(v: &ComposeValue, drops: &mut ValueDrops) -> Vec<String> {
    string_items(v, P_PORTS, false, true, Some(LongSyntaxKey::Ports), drops)
}

/// `volumes` の short syntax。マッピング要素は long syntax の変換へ回す（表せなければ drop）。
pub fn convert_volumes(v: &ComposeValue, drops: &mut ValueDrops) -> Vec<String> {
    string_items(
        v,
        P_VOLUMES,
        false,
        false,
        Some(LongSyntaxKey::Volumes),
        drops,
    )
}

/// `secrets` の short syntax。マッピング要素は long syntax の変換へ回す（表せなければ drop）。
pub fn convert_secrets(v: &ComposeValue, drops: &mut ValueDrops) -> Vec<String> {
    string_items(
        v,
        P_SECRETS,
        false,
        false,
        Some(LongSyntaxKey::Secrets),
        drops,
    )
}

/// `configs` の short syntax。マッピング要素は long syntax の変換へ回す（表せなければ drop）。
pub fn convert_configs(v: &ComposeValue, drops: &mut ValueDrops) -> Vec<String> {
    string_items(
        v,
        P_CONFIGS,
        false,
        false,
        Some(LongSyntaxKey::Configs),
        drops,
    )
}

/// `tmpfs` の short syntax（単独の文字列も 1 要素）。マッピング要素は long syntax の変換へ回す（表せなければ drop）。
pub fn convert_tmpfs(v: &ComposeValue, drops: &mut ValueDrops) -> Vec<String> {
    string_items(v, P_TMPFS, true, false, Some(LongSyntaxKey::Tmpfs), drops)
}

/// `devices` の short syntax。`Service.devices` は CDI 完全修飾名専用のため、ホストパス形
/// （`/dev/dri:/dev/dri` 等）は出力せず drop に記録する。マッピング要素は long syntax の変換へ回す（表せなければ drop）。
pub fn convert_devices(v: &ComposeValue, drops: &mut ValueDrops) -> Vec<String> {
    string_items(
        v,
        P_DEVICES,
        false,
        false,
        Some(LongSyntaxKey::Devices),
        drops,
    )
    .into_iter()
    .filter(|s| {
        let ok = is_cdi_qualified_name(s);
        if !ok {
            drops.note(P_DEVICES);
        }
        ok
    })
    .collect()
}

/// CDI 完全修飾名 `vendor/class=name` か。ホストパス形（`/dev/x:/dev/x`）を区別するための判定。
fn is_cdi_qualified_name(s: &str) -> bool {
    let Some((kind, name)) = s.split_once('=') else {
        return false;
    };
    let Some((vendor, class)) = kind.split_once('/') else {
        return false;
    };
    let part_ok = |p: &str| {
        let b = p.as_bytes();
        matches!((b.first(), b.last()), (Some(f), Some(l))
            if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric())
            && b.iter()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
    };
    part_ok(vendor) && part_ok(class) && crate::gpu_reservation::is_valid_cdi_device_name(name)
}

/// `profiles`。文字列のリスト（単独の文字列も 1 要素）。
pub fn convert_profiles(v: &ComposeValue, drops: &mut ValueDrops) -> Vec<String> {
    string_items(v, P_PROFILES, true, false, None, drops)
}

/// サービスの `networks`。リスト形は名前、マッピング形はキーが名前。属性つきは名前だけ残して記録する。
pub fn convert_service_networks(v: &ComposeValue, drops: &mut ValueDrops) -> Vec<String> {
    match v {
        ComposeValue::Mapping(m) if m.len() <= MAX_LIST_ITEMS => {
            let mut out = Vec::new();
            for (name, attrs) in m.iter() {
                if name.is_empty() || name.contains('\0') {
                    drops.note(P_NETWORKS);
                    continue;
                }
                out.push(name.to_string());
                let has_attrs = match attrs {
                    ComposeValue::Null => false,
                    ComposeValue::Mapping(a) => !a.is_empty(),
                    _ => true,
                };
                if has_attrs {
                    drops.note(P_NETWORKS);
                }
            }
            out
        }
        _ => string_items(v, P_NETWORKS, false, false, None, drops),
    }
}

fn convert_nonempty_string(
    v: &ComposeValue,
    path: &'static str,
    drops: &mut ValueDrops,
) -> Option<String> {
    match v {
        ComposeValue::String(s) if !s.is_empty() && !s.contains('\0') => Some(s.clone()),
        _ => {
            drops.note(path);
            None
        }
    }
}

fn convert_shm_size(v: &ComposeValue, drops: &mut ValueDrops) -> Option<String> {
    match v {
        ComposeValue::String(s) if !s.is_empty() && !s.contains('\0') => Some(s.clone()),
        ComposeValue::Number(ComposeNumber::PosInt(n)) => Some(n.to_string()),
        _ => {
            drops.note(P_SHM_SIZE);
            None
        }
    }
}

/// サービス 1 件を変換する。キーは出現順に見て、扱わないキー（warning・error 系ほか）は無視する
/// （分類の集計は #599 / #601 の責務）。
pub fn convert_service(service: &ComposeValue, drops: &mut ValueDrops) -> ServiceConversion {
    let Some(map) = service.as_mapping() else {
        drops.note(P_SERVICE);
        return ServiceConversion {
            service: None,
            unhandled: Vec::new(),
        };
    };
    let mut out = Service::default();
    let mut unhandled = Vec::new();
    for (key, v) in map.iter() {
        match key {
            "image" => out.image = convert_nonempty_string(v, P_IMAGE, drops),
            "container_name" => {
                out.container_name = convert_nonempty_string(v, P_CONTAINER_NAME, drops)
            }
            "working_dir" => out.working_dir = convert_nonempty_string(v, P_WORKING_DIR, drops),
            "command" => out.command = convert_argv(v, P_COMMAND, drops),
            "entrypoint" => out.entrypoint = convert_argv(v, P_ENTRYPOINT, drops),
            "environment" => out.env = convert_kv(v, P_ENVIRONMENT, drops),
            "labels" => out.labels = convert_kv(v, P_LABELS, drops),
            "env_file" => out.env_files = convert_env_file(v, drops),
            "ports" => out.ports = convert_ports(v, drops),
            "volumes" => out.volumes = convert_volumes(v, drops),
            "secrets" => out.secrets = convert_secrets(v, drops),
            "configs" => out.configs = convert_configs(v, drops),
            "tmpfs" => out.tmpfs = convert_tmpfs(v, drops),
            "devices" => out.devices = convert_devices(v, drops),
            "profiles" => out.profiles = convert_profiles(v, drops),
            "networks" => out.networks = convert_service_networks(v, drops),
            "restart" => out.restart = convert_nonempty_string(v, P_RESTART, drops),
            "shm_size" => out.shm_size = convert_shm_size(v, drops),
            "depends_on" => unhandled.push("services.*.depends_on"),
            "ulimits" => unhandled.push("services.*.ulimits"),
            "healthcheck" => unhandled.push("services.*.healthcheck"),
            "deploy" => unhandled.push("services.*.deploy"),
            _ => {}
        }
    }
    ServiceConversion {
        service: Some(out),
        unhandled,
    }
}

/// 定義テーブルの 1 要素（null かマッピング）を取り出す。それ以外は drop。
fn definition<'a>(
    v: &'a ComposeValue,
    path: &'static str,
    drops: &mut ValueDrops,
) -> Option<Option<&'a ComposeMapping>> {
    match v {
        ComposeValue::Null => Some(None),
        ComposeValue::Mapping(m) => Some(Some(m)),
        _ => {
            drops.note(path);
            None
        }
    }
}

fn opt_string(
    m: Option<&ComposeMapping>,
    key: &str,
    path: &'static str,
    drops: &mut ValueDrops,
) -> Option<String> {
    let v = m?.get(key)?;
    match v {
        ComposeValue::String(s) if !s.contains('\0') => Some(s.clone()),
        _ => {
            drops.note(path);
            None
        }
    }
}

fn opt_bool(
    m: Option<&ComposeMapping>,
    key: &str,
    path: &'static str,
    drops: &mut ValueDrops,
) -> Option<bool> {
    let v = m?.get(key)?;
    match v {
        ComposeValue::Bool(b) => Some(*b),
        _ => {
            drops.note(path);
            None
        }
    }
}

/// トップレベルの `name`・`networks`・`volumes`・`secrets`・`configs`・`services` を変換する。
/// `services` の `unhandled`（本 issue で見送った convert キー）は黙って捨てず、`drops` へ分類表のパスで記録する。
pub fn convert_top_level(doc: &ComposeDocument, drops: &mut ValueDrops) -> ComposeToml {
    let mut toml = ComposeToml::default();
    if let Some(v) = doc.get("name") {
        match v {
            ComposeValue::String(s) if !s.is_empty() && !s.contains('\0') => {
                toml.project = Some(Project {
                    name: Some(s.clone()),
                });
            }
            _ => drops.note(P_NAME),
        }
    }
    for_each_entry(doc.get("services"), P_SERVICE, drops, |name, v, drops| {
        let conv = convert_service(v, drops);
        for path in conv.unhandled {
            drops.note(path);
        }
        if let Some(s) = conv.service {
            toml.services.insert(name.to_string(), s);
        }
    });
    for_each_entry(
        doc.get("networks"),
        P_TOP_NETWORK,
        drops,
        |name, v, drops| {
            if let Some(m) = definition(v, P_TOP_NETWORK, drops) {
                toml.networks.insert(
                    name.to_string(),
                    Network {
                        driver: opt_string(m, "driver", P_TOP_NETWORK_DRIVER, drops),
                        external: opt_bool(m, "external", P_TOP_NETWORK_EXTERNAL, drops),
                    },
                );
            }
        },
    );
    for_each_entry(doc.get("volumes"), P_TOP_VOLUME, drops, |name, v, drops| {
        if let Some(m) = definition(v, P_TOP_VOLUME, drops) {
            toml.volumes.insert(
                name.to_string(),
                Volume {
                    driver: opt_string(m, "driver", P_TOP_VOLUME_DRIVER, drops),
                    external: opt_bool(m, "external", P_TOP_VOLUME_EXTERNAL, drops),
                },
            );
        }
    });
    for_each_entry(doc.get("secrets"), P_TOP_SECRET, drops, |name, v, drops| {
        if let Some(m) = definition(v, P_TOP_SECRET, drops) {
            toml.secrets.insert(
                name.to_string(),
                Secret {
                    file: opt_string(m, "file", P_TOP_SECRET_FILE, drops),
                    external: opt_bool(m, "external", P_TOP_SECRET_EXTERNAL, drops),
                },
            );
        }
    });
    for_each_entry(doc.get("configs"), P_TOP_CONFIG, drops, |name, v, drops| {
        if let Some(m) = definition(v, P_TOP_CONFIG, drops) {
            toml.configs.insert(
                name.to_string(),
                Config {
                    file: opt_string(m, "file", P_TOP_CONFIG_FILE, drops),
                    external: opt_bool(m, "external", P_TOP_CONFIG_EXTERNAL, drops),
                },
            );
        }
    });
    toml
}

/// トップレベルのテーブル（マッピング）を要素ごとに回す。マッピング以外・要素数超過は 1 件 drop。
fn for_each_entry<F>(
    table: Option<&ComposeValue>,
    path: &'static str,
    drops: &mut ValueDrops,
    mut f: F,
) where
    F: FnMut(&str, &ComposeValue, &mut ValueDrops),
{
    let Some(table) = table else { return };
    match table {
        ComposeValue::Null => {}
        ComposeValue::Mapping(m) if m.len() <= MAX_LIST_ITEMS => {
            for (name, v) in m.iter() {
                f(name, v, drops);
            }
        }
        _ => drops.note(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{KeyClass, classify_key_path};
    use crate::compose_convert::parse_compose_yaml;

    fn svc(yaml: &str) -> (Service, ValueDrops, Vec<&'static str>) {
        let doc = parse_compose_yaml(&format!("services:\n  s:\n{yaml}")).unwrap();
        let mut drops = ValueDrops::new();
        let v = doc.get("services").unwrap().get("s").unwrap();
        let c = convert_service(v, &mut drops);
        (c.service.unwrap(), drops, c.unhandled)
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// STACK-3: command の文字列形は引数配列へ分割される（受け入れ条件 A）。
    #[test]
    fn stack3_command_string_is_split_into_argv() {
        let (s, d, _) = svc("    command: npm run dev\n");
        assert_eq!(s.command, Some(strs(&["npm", "run", "dev"])));
        assert!(d.is_empty());
    }

    /// STACK-3: command / entrypoint の null は None で drop に数えない。引用だけの空語は [""]。
    #[test]
    fn stack3_argv_null_and_quoted_empty() {
        let (s, d, _) = svc("    command: null\n    entrypoint: null\n");
        assert_eq!(s.command, None);
        assert_eq!(s.entrypoint, None);
        assert!(d.is_empty());
        let (s, d, _) = svc("    command: '\"\"'\n    entrypoint: ['']\n");
        assert_eq!(s.command, Some(strs(&[""])));
        assert_eq!(s.entrypoint, Some(strs(&[""])));
        assert!(d.is_empty());
    }

    /// STACK-3: 値なしのキー（null）は項目なしで、drop に数えない。
    #[test]
    fn stack3_null_lists_are_empty_without_drops() {
        let (s, d, _) = svc("    ports:\n    volumes:\n    env_file:\n    tmpfs:\n    profiles:\n");
        assert!(s.ports.is_empty());
        assert!(s.volumes.is_empty());
        assert!(s.env_files.is_empty());
        assert!(s.tmpfs.is_empty());
        assert!(s.profiles.is_empty());
        assert!(d.is_empty());
    }

    /// STACK-3・GPU-1: devices のホストパス形は出力せず drop に記録する。
    #[test]
    fn stack3_devices_host_path_is_dropped() {
        let (s, d, _) = svc("    devices: ['/dev/dri:/dev/dri', 'nvidia.com/gpu=0']\n");
        assert_eq!(s.devices, strs(&["nvidia.com/gpu=0"]));
        assert_eq!(d.get(P_DEVICES), 1);
    }

    /// STACK-3: 引用つきの分割。
    #[test]
    fn stack3_command_string_with_quotes() {
        let (s, _, _) = svc("    command: \"sh -c 'echo \\\"hi there\\\"'\"\n");
        assert_eq!(s.command, Some(strs(&["sh", "-c", "echo \"hi there\""])));
    }

    /// STACK-3: entrypoint も同じ規則。
    #[test]
    fn stack3_entrypoint_string_is_split() {
        let (s, _, _) = svc("    entrypoint: /bin/app --flag\n");
        assert_eq!(s.entrypoint, Some(strs(&["/bin/app", "--flag"])));
    }

    /// STACK-3: リストはそのまま、空リストは Some(空)。
    #[test]
    fn stack3_command_list_is_kept_and_empty_list_kept() {
        let (s, d, _) = svc("    command: [a, 'b c', 3]\n    entrypoint: []\n");
        assert_eq!(s.command, Some(strs(&["a", "b c", "3"])));
        assert_eq!(s.entrypoint, Some(Vec::new()));
        assert!(d.is_empty());
        let t = toml_of(&s);
        assert!(t.contains("entrypoint = []"), "{t}");
    }

    fn toml_of(s: &Service) -> String {
        let mut c = ComposeToml::default();
        c.services.insert("s".into(), s.clone());
        toml::to_string(&c).unwrap()
    }

    /// STACK-3: 分割できない command は出さずに 1 件記録。
    #[test]
    fn stack3_unsplittable_command_is_recorded() {
        for y in [
            "echo a && echo b",
            "echo $(id)",
            "echo `id`",
            "\"abc",
            "abc\\\\",
        ] {
            let (s, d, _) = svc(&format!("    command: \"{}\"\n", y.replace('"', "\\\"")));
            assert_eq!(s.command, None, "{y}");
            assert_eq!(d.get(P_COMMAND), 1, "{y}");
        }
    }

    /// STACK-3: リストにマッピング要素があればキー全体を出さず 1 件記録。
    #[test]
    fn stack3_command_list_with_mapping_element_is_recorded() {
        let (s, d, _) = svc("    command: [a, {x: y}]\n");
        assert_eq!(s.command, None);
        assert_eq!(d.get(P_COMMAND), 1);
    }

    /// STACK-3: environment のマッピング形（受け入れ条件 B）。
    #[test]
    fn stack3_environment_mapping_form() {
        let (s, d, _) =
            svc("    environment:\n      A: x\n      B: true\n      C: 8080\n      D:\n");
        assert_eq!(s.env.get("A").map(String::as_str), Some("x"));
        assert_eq!(s.env.get("B").map(String::as_str), Some("true"));
        assert_eq!(s.env.get("C").map(String::as_str), Some("8080"));
        assert_eq!(s.env.get("D").map(String::as_str), Some(""));
        assert!(d.is_empty());
    }

    /// STACK-3: environment のリスト形。
    #[test]
    fn stack3_environment_list_form() {
        let (s, d, _) = svc("    environment: [A=1, B=x=y, C]\n");
        assert_eq!(s.env.get("A").map(String::as_str), Some("1"));
        assert_eq!(s.env.get("B").map(String::as_str), Some("x=y"));
        assert_eq!(s.env.get("C").map(String::as_str), Some(""));
        assert!(d.is_empty());
    }

    /// STACK-3: 不正な要素だけが記録され、他は変換される。
    #[test]
    fn stack3_environment_invalid_entries_are_recorded() {
        let (s, d, _) = svc("    environment: [A=1, =x, 5, A=2]\n");
        assert_eq!(s.env.len(), 1);
        assert_eq!(s.env.get("A").map(String::as_str), Some("1"));
        assert_eq!(d.get(P_ENVIRONMENT), 3);
        let (s, d, _) = svc("    environment:\n      F: 1.5\n      M: {x: y}\n      OK: v\n");
        assert_eq!(s.env.len(), 1);
        assert_eq!(d.get(P_ENVIRONMENT), 2);
    }

    /// STACK-3: env_file のスカラー形とリスト形、long syntax は記録。
    #[test]
    fn stack3_env_file_scalar_and_list() {
        let (s, _, _) = svc("    env_file: .env\n");
        assert_eq!(s.env_files, strs(&[".env"]));
        let (s, _, _) = svc("    env_file: [a.env, b.env]\n");
        assert_eq!(s.env_files, strs(&["a.env", "b.env"]));
        let (s, d, _) =
            svc("    env_file:\n      - c.env\n      - {path: x.env, required: false}\n");
        assert_eq!(s.env_files, strs(&["c.env"]));
        assert_eq!(d.get(P_ENV_FILE), 1);
    }

    /// STACK-3: labels のマッピング形とリスト形。
    #[test]
    fn stack3_labels_mapping_and_list_form() {
        let (s, _, _) = svc("    labels:\n      a: b\n      n:\n      t: true\n      i: 3\n");
        assert_eq!(s.labels.get("a").map(String::as_str), Some("b"));
        assert_eq!(s.labels.get("n").map(String::as_str), Some(""));
        assert_eq!(s.labels.get("t").map(String::as_str), Some("true"));
        assert_eq!(s.labels.get("i").map(String::as_str), Some("3"));
        let (s, d, _) = svc("    labels: [k=v, only]\n");
        assert_eq!(s.labels.get("k").map(String::as_str), Some("v"));
        assert_eq!(s.labels.get("only").map(String::as_str), Some(""));
        assert!(d.is_empty());
    }

    /// STACK-3: image・restart・shm_size・profiles・networks。
    #[test]
    fn stack3_misc_scalars() {
        let (s, d, _) = svc(
            "    image: busybox:1.36\n    restart: always\n    shm_size: 67108864\n    profiles: [dev]\n    networks: [a, b]\n",
        );
        assert_eq!(s.image.as_deref(), Some("busybox:1.36"));
        assert_eq!(s.restart.as_deref(), Some("always"));
        assert_eq!(s.shm_size.as_deref(), Some("67108864"));
        assert_eq!(s.profiles, strs(&["dev"]));
        assert_eq!(s.networks, strs(&["a", "b"]));
        assert!(d.is_empty());
        let (s, d, _) = svc(
            "    image: \"\"\n    restart: {x: y}\n    shm_size: 1.5\n    networks:\n      front:\n      back:\n        aliases: [x]\n",
        );
        assert_eq!(s.image, None);
        assert_eq!(s.restart, None);
        assert_eq!(s.shm_size, None);
        assert_eq!(s.networks, strs(&["front", "back"]));
        assert_eq!(d.get(P_IMAGE), 1);
        assert_eq!(d.get(P_RESTART), 1);
        assert_eq!(d.get(P_SHM_SIZE), 1);
        assert_eq!(d.get(P_NETWORKS), 1);
    }

    /// STACK-6・TASK-153.1（#609）: container_name・working_dir は空でない文字列だけを受ける。
    #[test]
    fn stack6_container_name_and_working_dir_are_converted() {
        let (s, d, _) = svc("    container_name: web-1\n    working_dir: /srv/app\n");
        assert_eq!(s.container_name.as_deref(), Some("web-1"));
        assert_eq!(s.working_dir.as_deref(), Some("/srv/app"));
        assert!(d.is_empty());
        let t = toml_of(&s);
        assert!(t.contains("container_name = \"web-1\""), "{t}");
        assert!(t.contains("working_dir = \"/srv/app\""), "{t}");
    }

    /// STACK-6・TASK-153.1（#609）: 不正な型・空文字列は出力せず drop を 1 件記録し、値は記録に載せない。
    #[test]
    fn stack6_invalid_container_name_and_working_dir_are_recorded() {
        for line in [
            "    container_name: \"\"\n",
            "    container_name: 123\n",
            "    container_name: [a]\n",
        ] {
            let (s, d, _) = svc(line);
            assert_eq!(s.container_name, None, "{line}");
            assert_eq!(d.get(P_CONTAINER_NAME), 1, "{line}");
            assert_eq!(d.total(), 1, "{line}");
        }
        for line in [
            "    working_dir: \"\"\n",
            "    working_dir: {x: y}\n",
            "    working_dir: 1.5\n",
            "    working_dir:\n",
        ] {
            let (s, d, _) = svc(line);
            assert_eq!(s.working_dir, None, "{line}");
            assert_eq!(d.get(P_WORKING_DIR), 1, "{line}");
            assert_eq!(d.total(), 1, "{line}");
        }
        let (_, d, _) = svc("    container_name: [dummy-name-marker]\n");
        assert!(!format!("{d:?}").contains("dummy-name-marker"));
    }

    /// STACK-3: short syntax の 6 キーと、マッピング要素の記録（long syntax は #599 で結線済み）。
    #[test]
    fn stack3_short_syntax_lists() {
        let (s, d, _) = svc(
            "    ports: ['8080:80', 9090]\n    volumes: ['m:/m:ro']\n    secrets: [s1]\n    configs: [c1]\n    tmpfs: /run\n    devices: ['nvidia.com/gpu=all']\n",
        );
        assert_eq!(s.ports, strs(&["8080:80", "9090"]));
        assert_eq!(s.volumes, strs(&["m:/m:ro"]));
        assert_eq!(s.secrets, strs(&["s1"]));
        assert_eq!(s.configs, strs(&["c1"]));
        assert_eq!(s.tmpfs, strs(&["/run"]));
        assert_eq!(s.devices, strs(&["nvidia.com/gpu=all"]));
        assert!(d.is_empty());
        let (s, d, _) = svc(
            "    ports:\n      - '1:1'\n      - {target: 80}\n    volumes:\n      - {type: bind}\n",
        );
        // {target: 80} は short syntax と等価なので変換される（#865）。{type: bind} は必須項目が無く drop。
        assert_eq!(s.ports, strs(&["1:1", "80"]));
        assert_eq!(d.get(P_PORTS), 0);
        assert_eq!(d.get(P_VOLUMES), 1);
    }

    /// STACK-3: long syntax のマッピング要素は変換器へ結線され、表せない要素だけ drop に 1 件ずつ数える。
    #[test]
    fn stack3_long_syntax_mapping_elements_are_wired() {
        let (s, d, _) = svc(
            "    ports:\n      - {target: 80, published: 8080, protocol: tcp}\n      - {target: 81, mode: host}\n    volumes:\n      - {type: tmpfs, target: /t}\n    secrets:\n      - {source: api_key}\n    tmpfs:\n      - {target: /x}\n    devices:\n      - {source: a}\n",
        );
        assert_eq!(s.ports, strs(&["8080:80/tcp"]));
        assert_eq!(s.secrets, strs(&["api_key"]));
        assert!(s.volumes.is_empty() && s.tmpfs.is_empty() && s.devices.is_empty());
        assert_eq!(d.get(P_PORTS), 1);
        assert_eq!(d.get(P_VOLUMES), 1);
        assert_eq!(d.get(P_TMPFS), 1);
        assert_eq!(d.get(P_DEVICES), 1);
        assert_eq!(d.get(P_SECRETS), 0);
        assert_eq!(d.total(), 4);
    }

    /// STACK-3: long syntax を回さないキー（env_file）のマッピング要素は従来どおり drop 1 件。
    #[test]
    fn stack3_env_file_mapping_still_dropped() {
        let (s, d, _) = svc("    env_file:\n      - {path: a.env}\n");
        assert!(s.env_files.is_empty());
        assert_eq!(d.get(P_ENV_FILE), 1);
        assert_eq!(d.total(), 1);
    }

    /// STACK-3: long syntax の key_path は convert の drop キーパス表に含まれる。
    #[test]
    fn stack3_long_syntax_paths_match_convert_paths() {
        for k in [
            LongSyntaxKey::Ports,
            LongSyntaxKey::Volumes,
            LongSyntaxKey::Secrets,
            LongSyntaxKey::Configs,
            LongSyntaxKey::Tmpfs,
            LongSyntaxKey::Devices,
        ] {
            assert!(DROP_KEY_PATHS.contains(&k.key_path()), "{}", k.key_path());
        }
    }

    /// STACK-3: note_many は 0 件で記録を作らず、飽和加算する。
    #[test]
    fn stack3_value_drops_note_many() {
        let mut d = ValueDrops::new();
        d.note_many(P_PORTS, 0);
        assert!(d.is_empty());
        d.note_many(P_PORTS, 3);
        assert_eq!(d.get(P_PORTS), 3);
        d.note_many(P_PORTS, u64::MAX);
        assert_eq!(d.get(P_PORTS), u64::MAX);
    }

    /// STACK-3: Float は文字列へ直さず記録する。
    #[test]
    fn stack3_float_values_are_recorded() {
        let (s, d, _) = svc("    environment:\n      F: 1.0\n    command: [1.5]\n");
        assert!(s.env.is_empty());
        assert_eq!(s.command, None);
        assert_eq!(d.get(P_ENVIRONMENT), 1);
        assert_eq!(d.get(P_COMMAND), 1);
    }

    /// STACK-3: 見送った convert キーは unhandled に載り TOML に出ない。
    #[test]
    fn stack3_unhandled_keys_are_reported() {
        let (s, _, u) = svc(
            "    depends_on: [a]\n    ulimits: {nofile: 1}\n    healthcheck: {test: x}\n    deploy: {}\n",
        );
        assert_eq!(
            u,
            vec![
                "services.*.depends_on",
                "services.*.ulimits",
                "services.*.healthcheck",
                "services.*.deploy"
            ]
        );
        assert_eq!(s, Service::default());
    }

    /// STACK-3・REPAIR-12: drop のパスはすべて分類表の Convert 行。
    #[test]
    fn stack3_drop_paths_are_convert_rows() {
        for p in DROP_KEY_PATHS {
            assert_eq!(classify_key_path(p), KeyClass::Convert, "{p}");
        }
    }

    /// STACK-3: 記録に値・環境変数名を含まない。
    #[test]
    fn stack3_drops_do_not_contain_values() {
        let (_, d, _) =
            svc("    environment:\n      SECRET_NAME: 1.5\n      X: {k: dummy-secret-value}\n");
        let dump = format!("{d:?}");
        assert!(!dump.contains("dummy-secret-value"));
        assert!(!dump.contains("SECRET_NAME"));
        assert_eq!(d.total(), 2);
    }

    /// STACK-3: トップレベルの変換。
    #[test]
    fn stack3_top_level() {
        let doc = parse_compose_yaml(
            "name: proj\nservices:\n  a:\n    image: x\nnetworks:\n  n:\n    driver: bridge\n  e:\n    external: true\nvolumes:\n  v:\nsecrets:\n  s:\n    file: ./s.txt\nconfigs:\n  c:\n    external: true\n",
        )
        .unwrap();
        let mut d = ValueDrops::new();
        let t = convert_top_level(&doc, &mut d);
        assert_eq!(t.project.unwrap().name.as_deref(), Some("proj"));
        assert_eq!(t.services["a"].image.as_deref(), Some("x"));
        assert_eq!(t.networks["n"].driver.as_deref(), Some("bridge"));
        assert_eq!(t.networks["e"].external, Some(true));
        assert!(t.volumes.contains_key("v"));
        assert_eq!(t.secrets["s"].file.as_deref(), Some("./s.txt"));
        assert_eq!(t.configs["c"].external, Some(true));
        assert!(d.is_empty());
        let doc = parse_compose_yaml("name: 3\nnetworks:\n  n:\n    driver: 1\n").unwrap();
        let mut d = ValueDrops::new();
        let _ = convert_top_level(&doc, &mut d);
        assert_eq!(d.get(P_NAME), 1);
        assert_eq!(d.get(P_TOP_NETWORK_DRIVER), 1);
    }

    /// STACK-3: 見送った convert キーはトップレベル変換でも drops に残る。
    #[test]
    fn stack3_top_level_records_unhandled() {
        let doc = parse_compose_yaml(
            "services:\n  a:\n    image: x\n    depends_on: [b]\n    deploy:\n      resources:\n        limits: {cpus: '1'}\n",
        )
        .unwrap();
        let mut d = ValueDrops::new();
        let t = convert_top_level(&doc, &mut d);
        assert_eq!(t.services["a"].image.as_deref(), Some("x"));
        assert_eq!(d.get("services.*.depends_on"), 1);
        assert_eq!(d.get("services.*.deploy"), 1);
        assert_eq!(d.total(), 2);
    }

    /// STACK-3: 空文字列の command / entrypoint は `Some([])`（既定の打ち消し）で、drop ではない。
    #[test]
    fn stack3_empty_command_clears_default() {
        let (s, d, _) = svc("    command: \"\"\n    entrypoint: ''\n");
        assert_eq!(s.command, Some(Vec::new()));
        assert_eq!(s.entrypoint, Some(Vec::new()));
        assert!(d.is_empty());
        let (s, d, _) = svc("    command: 'a \"b'\n");
        assert_eq!(s.command, None);
        assert_eq!(d.get(P_COMMAND), 1);
    }
}
