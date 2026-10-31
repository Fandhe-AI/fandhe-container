//! マッピング配列キー（long syntax）の stack short syntax への変換（TASK-151.3.2・#865・STACK-3・MS-12）。
//!
//! 役割: compose の `ports`・`volumes`・`secrets`・`configs`・`tmpfs`・`devices` の配列要素がマッピング
//! （long syntax）のとき、`fandhe-container-stack` の `Service`（どれも short syntax の `Vec<String>`）へ
//! 載せられる文字列へ正規化する純粋関数を提供する。呼び出し元は #864 / #598 の変換器の結線と、drop を
//! `value_drops` に加算する #599 を想定する（本モジュールは結線しない。`compose_convert.rs` は #864 と
//! 衝突しうるため触らない。`gpu_reservation` と同じ独立モジュール方式）。`Sequence` の振り分け
//! （文字列・数値は #864、マッピングは本モジュール、それ以外は drop）も結線側の責務である。
//!
//! 規則（REPAIR-3・安全側）: compose-spec の定義で short 形式と等価になる組み合わせだけを変換し、
//! 表せないフィールド・既定と異なる値を 1 つでも持つ要素は部分変換せず要素ごと [`LongSyntaxDrop`] で返す。
//! spec（`04-behavior/api-stack.md` STACK-3）は long syntax を全件 drop と定めており、本実装は
//! その等価な部分集合だけを変換する点で差がある。この差は spec 側の確認待ちである。
//! 値の意味検証（ポート範囲・パスの `..`・CDI 名）はしない（`up`・CLI・core の責務）。
//! drop は値・キー名を持たない（値に秘密が入りうるため）。

use crate::compose_convert::{ComposeMapping, ComposeNumber, ComposeValue};

/// `services.*.ports` のキーパス（`classify` の Convert 葉と一致）。
pub const PORTS_KEY_PATH: &str = "services.*.ports";
/// `services.*.volumes` のキーパス。
pub const VOLUMES_KEY_PATH: &str = "services.*.volumes";
/// `services.*.secrets` のキーパス。
pub const SECRETS_KEY_PATH: &str = "services.*.secrets";
/// `services.*.configs` のキーパス。
pub const CONFIGS_KEY_PATH: &str = "services.*.configs";
/// `services.*.tmpfs` のキーパス。
pub const TMPFS_KEY_PATH: &str = "services.*.tmpfs";
/// `services.*.devices` のキーパス。
pub const DEVICES_KEY_PATH: &str = "services.*.devices";

/// 文字列フィールド 1 件の上限バイト数（確保前の検証。DoS 防止）。
pub const MAX_LONG_SYNTAX_FIELD_BYTES: usize = 4096;

/// long syntax を持ちうる配列キー。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LongSyntaxKey {
    /// `ports`。
    Ports,
    /// `volumes`。
    Volumes,
    /// `secrets`。
    Secrets,
    /// `configs`。
    Configs,
    /// `tmpfs`（compose-spec にマッピング形式なし）。
    Tmpfs,
    /// `devices`（compose-spec にマッピング形式なし）。
    Devices,
}

impl LongSyntaxKey {
    /// 変換レポートに載せるキーパス。
    pub fn key_path(self) -> &'static str {
        match self {
            Self::Ports => PORTS_KEY_PATH,
            Self::Volumes => VOLUMES_KEY_PATH,
            Self::Secrets => SECRETS_KEY_PATH,
            Self::Configs => CONFIGS_KEY_PATH,
            Self::Tmpfs => TMPFS_KEY_PATH,
            Self::Devices => DEVICES_KEY_PATH,
        }
    }
}

/// 要素を short syntax へ変換できない理由（値を含まない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LongSyntaxDropReason {
    /// compose-spec にマッピング形式が無いキー（tmpfs・devices）。
    NoLongSyntax,
    /// short で表せない、または未知のフィールドがある。
    UnsupportedField,
    /// フィールドの型が違う。
    FieldTypeMismatch,
    /// 必須フィールドが無い。
    MissingRequiredField,
    /// 値が出力の区切り文字・空白・制御文字を含む、または空。
    DelimiterInValue,
    /// 値が上限を超える。
    ValueTooLong,
    /// ポート値が `N` / `N-M`（ASCII 数字）でない。
    InvalidPortValue,
    /// protocol が tcp / udp でない。
    InvalidProtocol,
    /// mode が ingress 以外。
    PortModeNotIngress,
    /// host_ip が IPv4 の形でない（IPv6 を含む）。
    HostIpUnsupported,
    /// host_ip があるが published が無い。
    HostIpWithoutPublished,
    /// volumes の type が volume / bind 以外。
    VolumeTypeUnsupported,
    /// source が short では別の種別に解釈されうる、または名前の形でない。
    SourceAmbiguous,
    /// bind.create_host_path が false。
    BindCreateHostPathFalse,
    /// short で表せない volume / bind のオプション。
    VolumeOptionUnsupported,
}

/// 変換できなかった要素 1 件の記録。`value_drops` へ足す材料（値・キー名は持たない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongSyntaxDrop {
    /// 対象の配列キー。
    pub key: LongSyntaxKey,
    /// 理由。
    pub reason: LongSyntaxDropReason,
}

impl LongSyntaxDrop {
    /// 変換レポート用のキーパス。
    pub fn key_path(&self) -> &'static str {
        self.key.key_path()
    }
}

impl std::fmt::Display for LongSyntaxDrop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("long syntax element cannot be represented in short syntax")
    }
}

impl std::error::Error for LongSyntaxDrop {}

type R<T> = Result<T, LongSyntaxDrop>;

fn drop_of(key: LongSyntaxKey, reason: LongSyntaxDropReason) -> LongSyntaxDrop {
    LongSyntaxDrop { key, reason }
}

/// 変換に成功した要素 1 件。将来フィールドを足せるよう文字列ではなく構造体で返す（REPAIR-3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertedElement {
    /// 変換後の short syntax 文字列（secrets / configs は名前）。
    pub short_syntax: String,
}

/// マッピング 1 件を short syntax へ変換する。表せなければ要素ごと `Err`（部分変換しない）。
pub fn convert_long_syntax_element(
    key: LongSyntaxKey,
    element: &ComposeMapping,
) -> R<ConvertedElement> {
    let short_syntax = match key {
        LongSyntaxKey::Ports => convert_port(element)?,
        LongSyntaxKey::Volumes => convert_volume(element)?,
        LongSyntaxKey::Secrets => convert_source_only(LongSyntaxKey::Secrets, element)?,
        LongSyntaxKey::Configs => convert_source_only(LongSyntaxKey::Configs, element)?,
        LongSyntaxKey::Tmpfs | LongSyntaxKey::Devices => {
            return Err(drop_of(key, LongSyntaxDropReason::NoLongSyntax));
        }
    };
    Ok(ConvertedElement { short_syntax })
}

fn check_keys(key: LongSyntaxKey, m: &ComposeMapping, allowed: &[&str]) -> R<()> {
    if m.iter().all(|(k, _)| allowed.contains(&k)) {
        Ok(())
    } else {
        Err(drop_of(key, LongSyntaxDropReason::UnsupportedField))
    }
}

/// 文字列フィールドを取り出す。空・長すぎ・制御文字・空白・`:` を含むものは drop。
fn str_field<'a>(key: LongSyntaxKey, m: &'a ComposeMapping, name: &str) -> R<Option<&'a str>> {
    let Some(v) = m.get(name) else {
        return Ok(None);
    };
    let Some(s) = v.as_str() else {
        return Err(drop_of(key, LongSyntaxDropReason::FieldTypeMismatch));
    };
    if s.len() > MAX_LONG_SYNTAX_FIELD_BYTES {
        return Err(drop_of(key, LongSyntaxDropReason::ValueTooLong));
    }
    if s.is_empty()
        || s.chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == ':')
    {
        return Err(drop_of(key, LongSyntaxDropReason::DelimiterInValue));
    }
    Ok(Some(s))
}

fn required<T>(key: LongSyntaxKey, v: Option<T>) -> R<T> {
    v.ok_or(drop_of(key, LongSyntaxDropReason::MissingRequiredField))
}

/// `N` または `N-M`（ASCII 数字のみ）の正規化。数値は 10 進文字列にする。
fn port_value(key: LongSyntaxKey, m: &ComposeMapping, name: &str) -> R<Option<String>> {
    let invalid = || drop_of(key, LongSyntaxDropReason::InvalidPortValue);
    match m.get(name) {
        None => Ok(None),
        Some(ComposeValue::Number(ComposeNumber::PosInt(n))) => Ok(Some(n.to_string())),
        Some(ComposeValue::String(s)) => {
            if s.len() > MAX_LONG_SYNTAX_FIELD_BYTES {
                return Err(drop_of(key, LongSyntaxDropReason::ValueTooLong));
            }
            let parts = s.split('-');
            let ok = parts.clone().count() <= 2
                && parts
                    .into_iter()
                    .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
            if ok {
                Ok(Some(s.clone()))
            } else {
                Err(invalid())
            }
        }
        Some(_) => Err(invalid()),
    }
}

fn convert_port(m: &ComposeMapping) -> R<String> {
    let key = LongSyntaxKey::Ports;
    check_keys(
        key,
        m,
        &["target", "published", "host_ip", "protocol", "mode"],
    )?;
    let target = required(key, port_value(key, m, "target")?)?;
    let published = port_value(key, m, "published")?;
    let host_ip = match m.get("host_ip") {
        None => None,
        Some(v) => {
            let s = v
                .as_str()
                .ok_or(drop_of(key, LongSyntaxDropReason::FieldTypeMismatch))?;
            if s.len() > MAX_LONG_SYNTAX_FIELD_BYTES {
                return Err(drop_of(key, LongSyntaxDropReason::ValueTooLong));
            }
            if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return Err(drop_of(key, LongSyntaxDropReason::HostIpUnsupported));
            }
            Some(s)
        }
    };
    let protocol = match m.get("protocol") {
        None => None,
        Some(v) => match v.as_str() {
            Some(p @ ("tcp" | "udp")) => Some(p),
            Some(_) => return Err(drop_of(key, LongSyntaxDropReason::InvalidProtocol)),
            None => return Err(drop_of(key, LongSyntaxDropReason::FieldTypeMismatch)),
        },
    };
    if let Some(v) = m.get("mode") {
        match v.as_str() {
            Some("ingress") => {}
            Some(_) => return Err(drop_of(key, LongSyntaxDropReason::PortModeNotIngress)),
            None => return Err(drop_of(key, LongSyntaxDropReason::FieldTypeMismatch)),
        }
    }
    if host_ip.is_some() && published.is_none() {
        return Err(drop_of(key, LongSyntaxDropReason::HostIpWithoutPublished));
    }
    let mut out = String::new();
    if let Some(ip) = host_ip {
        out.push_str(ip);
        out.push(':');
    }
    if let Some(p) = published {
        out.push_str(&p);
        out.push(':');
    }
    out.push_str(&target);
    if let Some(p) = protocol {
        out.push('/');
        out.push_str(p);
    }
    Ok(out)
}

/// 名前付きボリュームの名前の形（先頭が英数字、残りは英数字と `_` `.` `-`）。
fn is_volume_name(s: &str) -> bool {
    let mut it = s.chars();
    matches!(it.next(), Some(c) if c.is_ascii_alphanumeric())
        && it.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// short syntax で名前付きボリュームと区別できるホストパスの形。
/// compose の規則に合わせ、`/` `.` `~` で始まるもの（`.` `..` `.env` を含む）を受ける。
fn is_host_path(s: &str) -> bool {
    s.starts_with(['/', '.', '~'])
}

fn convert_volume(m: &ComposeMapping) -> R<String> {
    let key = LongSyntaxKey::Volumes;
    check_keys(
        key,
        m,
        &["type", "source", "target", "read_only", "bind", "volume"],
    )?;
    let ty = required(key, str_field(key, m, "type")?)?;
    let source = str_field(key, m, "source")?;
    let target = required(key, str_field(key, m, "target")?)?;
    let read_only = match m.get("read_only") {
        None => false,
        Some(v) => v
            .as_bool()
            .ok_or(drop_of(key, LongSyntaxDropReason::FieldTypeMismatch))?,
    };
    let sub = |name: &str| -> R<Option<&ComposeMapping>> {
        match m.get(name) {
            None => Ok(None),
            Some(v) => v
                .as_mapping()
                .map(Some)
                .ok_or(drop_of(key, LongSyntaxDropReason::FieldTypeMismatch)),
        }
    };
    let unsupported = || drop_of(key, LongSyntaxDropReason::UnsupportedField);
    let option_unsupported = || drop_of(key, LongSyntaxDropReason::VolumeOptionUnsupported);
    let ambiguous = || drop_of(key, LongSyntaxDropReason::SourceAmbiguous);
    let mut out = String::new();
    match ty {
        "volume" => {
            if sub("bind")?.is_some() {
                return Err(unsupported());
            }
            if sub("volume")?.is_some_and(|v| !v.is_empty()) {
                return Err(option_unsupported());
            }
            match source {
                Some(s) => {
                    if !is_volume_name(s) {
                        return Err(ambiguous());
                    }
                    out.push_str(s);
                    out.push(':');
                }
                // 匿名ボリュームに `:ro` を付けると target が source に読まれるため表せない。
                None if read_only => return Err(option_unsupported()),
                None => {}
            }
        }
        "bind" => {
            if sub("volume")?.is_some() {
                return Err(unsupported());
            }
            if let Some(b) = sub("bind")? {
                for (k, v) in b.iter() {
                    if k != "create_host_path" {
                        return Err(option_unsupported());
                    }
                    match v.as_bool() {
                        Some(true) => {}
                        Some(false) => {
                            return Err(drop_of(
                                key,
                                LongSyntaxDropReason::BindCreateHostPathFalse,
                            ));
                        }
                        None => {
                            return Err(drop_of(key, LongSyntaxDropReason::FieldTypeMismatch));
                        }
                    }
                }
            }
            let s = required(key, source)?;
            if !is_host_path(s) {
                return Err(ambiguous());
            }
            out.push_str(s);
            out.push(':');
        }
        _ => return Err(drop_of(key, LongSyntaxDropReason::VolumeTypeUnsupported)),
    }
    out.push_str(target);
    if read_only {
        out.push_str(":ro");
    }
    Ok(out)
}

/// secrets / configs: `source` だけを持つ要素を名前へ正規化する（target・uid・gid・mode は drop）。
fn convert_source_only(key: LongSyntaxKey, m: &ComposeMapping) -> R<String> {
    check_keys(key, m, &["source"])?;
    let s = required(key, str_field(key, m, "source")?)?;
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::LongSyntaxDropReason as D;
    use super::LongSyntaxKey::*;
    use super::*;
    use crate::classify::{KeyClass, classify_key_path};
    use crate::compose_convert::parse_compose_yaml;

    /// YAML 1 要素（マッピング）を読む。
    fn el(yaml: &str) -> ComposeMapping {
        let doc = parse_compose_yaml(&format!("x: {yaml}\n")).unwrap();
        doc.get("x").unwrap().as_mapping().unwrap().clone()
    }

    fn ok(key: LongSyntaxKey, yaml: &str) -> String {
        convert_long_syntax_element(key, &el(yaml))
            .unwrap()
            .short_syntax
    }

    fn err(key: LongSyntaxKey, yaml: &str) -> D {
        convert_long_syntax_element(key, &el(yaml))
            .unwrap_err()
            .reason
    }

    /// STACK-3・REPAIR-12: ports の変換。
    #[test]
    fn ports_convert() {
        assert_eq!(
            ok(Ports, "{target: 80, published: 8080, protocol: tcp}"),
            "8080:80/tcp"
        );
        assert_eq!(ok(Ports, "{target: 80}"), "80");
        assert_eq!(
            ok(
                Ports,
                "{target: \"8000-8001\", published: \"9000-9001\", protocol: udp}"
            ),
            "9000-9001:8000-8001/udp"
        );
        assert_eq!(
            ok(
                Ports,
                "{target: 80, published: \"8080\", host_ip: 127.0.0.1, mode: ingress}"
            ),
            "127.0.0.1:8080:80"
        );
    }

    /// STACK-3・REPAIR-12: ports の drop。
    #[test]
    fn ports_drop() {
        assert_eq!(
            err(Ports, "{target: 80, mode: host}"),
            D::PortModeNotIngress
        );
        assert_eq!(err(Ports, "{target: 80, name: web}"), D::UnsupportedField);
        assert_eq!(
            err(Ports, "{target: 80, app_protocol: http}"),
            D::UnsupportedField
        );
        assert_eq!(
            err(Ports, "{target: 80, published: 80, host_ip: \"::1\"}"),
            D::HostIpUnsupported
        );
        assert_eq!(err(Ports, "{target: 1.5}"), D::InvalidPortValue);
        assert_eq!(err(Ports, "{target: -1}"), D::InvalidPortValue);
        assert_eq!(err(Ports, "{target: true}"), D::InvalidPortValue);
        assert_eq!(err(Ports, "{target: ~}"), D::InvalidPortValue);
        assert_eq!(err(Ports, "{target: \"80/udp\"}"), D::InvalidPortValue);
        assert_eq!(
            err(Ports, "{target: 80, protocol: sctp}"),
            D::InvalidProtocol
        );
        assert_eq!(err(Ports, "{published: 80}"), D::MissingRequiredField);
        assert_eq!(
            err(Ports, "{target: 80, host_ip: 127.0.0.1}"),
            D::HostIpWithoutPublished
        );
    }

    /// STACK-3・REPAIR-12: volumes の変換。
    #[test]
    fn volumes_convert() {
        assert_eq!(
            ok(
                Volumes,
                "{type: volume, source: models, target: /models, read_only: true}"
            ),
            "models:/models:ro"
        );
        assert_eq!(ok(Volumes, "{type: volume, target: /cache}"), "/cache");
        assert_eq!(
            ok(Volumes, "{type: bind, source: ./data, target: /data}"),
            "./data:/data"
        );
        assert_eq!(
            ok(
                Volumes,
                "{type: bind, source: /h, target: /d, read_only: true, bind: {create_host_path: true}}"
            ),
            "/h:/d:ro"
        );
    }

    /// STACK-3・REPAIR-12: bind の source が `.` `..` と dotted 名でも host path として受理する。
    #[test]
    fn bind_dot_sources_accepted() {
        assert_eq!(ok(Volumes, "{type: bind, source: ., target: /d}"), ".:/d");
        assert_eq!(
            ok(
                Volumes,
                "{type: bind, source: .., target: /d, read_only: true}"
            ),
            "..:/d:ro"
        );
        assert_eq!(
            ok(Volumes, "{type: bind, source: .env, target: /d}"),
            ".env:/d"
        );
    }

    /// STACK-3・REPAIR-12: volumes の drop。
    #[test]
    fn volumes_drop() {
        let cases: [(&str, D); 14] = [
            ("{type: bind, source: data, target: /d}", D::SourceAmbiguous),
            (
                "{type: volume, source: ./x, target: /d}",
                D::SourceAmbiguous,
            ),
            (
                "{type: bind, source: /h, target: /d, bind: {create_host_path: false}}",
                D::BindCreateHostPathFalse,
            ),
            (
                "{type: bind, source: /h, target: /d, bind: {propagation: rshared}}",
                D::VolumeOptionUnsupported,
            ),
            (
                "{type: bind, source: /h, target: /d, bind: {selinux: z}}",
                D::VolumeOptionUnsupported,
            ),
            (
                "{type: volume, source: v, target: /d, volume: {nocopy: true}}",
                D::VolumeOptionUnsupported,
            ),
            (
                "{type: volume, source: v, target: /d, volume: {subpath: a}}",
                D::VolumeOptionUnsupported,
            ),
            (
                "{type: volume, source: v, target: /d, consistency: cached}",
                D::UnsupportedField,
            ),
            ("{type: tmpfs, target: /t}", D::VolumeTypeUnsupported),
            (
                "{type: image, source: i, target: /t}",
                D::VolumeTypeUnsupported,
            ),
            (
                "{type: bind, source: \"C:\\\\x\", target: /d}",
                D::DelimiterInValue,
            ),
            (
                "{type: volume, source: v, target: /d, read_only: \"yes\"}",
                D::FieldTypeMismatch,
            ),
            // 匿名ボリュームの ro は short で別の意味になるため表さない。
            (
                "{type: volume, target: /c, read_only: true}",
                D::VolumeOptionUnsupported,
            ),
            ("{type: bind, source: /h}", D::MissingRequiredField),
        ];
        for (y, want) in cases {
            assert_eq!(err(Volumes, y), want, "{y}");
        }
    }

    /// STACK-3・REPAIR-12: secrets / configs。
    #[test]
    fn secrets_and_configs() {
        assert_eq!(ok(Secrets, "{source: api_key}"), "api_key");
        assert_eq!(ok(Configs, "{source: app_conf}"), "app_conf");
        for k in [Secrets, Configs] {
            for f in ["target: /x", "uid: \"1\"", "gid: \"1\"", "mode: 292"] {
                assert_eq!(err(k, &format!("{{source: s, {f}}}")), D::UnsupportedField);
            }
            assert_eq!(err(k, "{}"), D::MissingRequiredField);
            assert_eq!(err(k, "{source: 1}"), D::FieldTypeMismatch);
        }
    }

    /// STACK-3・REPAIR-12: tmpfs / devices はマッピング形式が無く、常に drop。
    #[test]
    fn tmpfs_and_devices_always_drop() {
        assert_eq!(err(Tmpfs, "{target: /run}"), D::NoLongSyntax);
        assert_eq!(
            err(Devices, "{source: /dev/x, target: /dev/x}"),
            D::NoLongSyntax
        );
    }

    /// 長すぎる source は drop される。
    #[test]
    fn oversized_field_is_dropped() {
        let big = "a".repeat(MAX_LONG_SYNTAX_FIELD_BYTES + 1);
        assert_eq!(err(Secrets, &format!("{{source: {big}}}")), D::ValueTooLong);
    }

    /// STACK-3: drop のキーパスは classify の Convert 葉と一致する。
    #[test]
    fn key_paths_match_classify_table() {
        for k in [Ports, Volumes, Secrets, Configs, Tmpfs, Devices] {
            assert_eq!(classify_key_path(k.key_path()), KeyClass::Convert, "{k:?}");
        }
        let d = convert_long_syntax_element(Tmpfs, &el("{a: b}")).unwrap_err();
        assert_eq!(d.key_path(), "services.*.tmpfs");
    }
}
