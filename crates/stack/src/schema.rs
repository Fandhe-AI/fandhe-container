//! 独自 TOML スキーマのトップレベル型（STACK-1・CLI-4。TASK-149.2・#584）。
//!
//! `[project]`・`[services.<name>]`・`[networks.<name>]`・`[volumes.<name>]`・
//! `[secrets.<name>]`・`[configs.<name>]` の 6 テーブルに対応する。土台は PoC-16 の
//! converter スキーマで、`fandhe-container-compose-convert` が本モジュールの型へ一方向に
//! 依存して compose.yaml を変換する。
//!
//! - トップレベルに `profiles` は置かない。STACK-10 が使うのはサービスごとの `profiles`
//!   だけで、STACK-1 のトップレベルは上記 6 テーブルに限られるため。
//! - すべての構造体は `deny_unknown_fields` で未知キー・typo を拒否する（fail-closed）。
//! - 本モジュールの型は値を検証しない。`file` のパス正規化・`driver` の許可判断・
//!   入力サイズの上限検証は、読み込み側（parse の入口・`up` 等）の責務である。
//! - parse / serialize の公開入口はまだ無い（TASK-149.3 以降）。テストは `toml` を直接使う。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// 独自 TOML スキーマのトップレベル（STACK-1）。
///
/// map は `BTreeMap` とし、出力順を決定的にして往復比較（STACK-5・#587）を安定させる。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposeToml {
    /// `[project]`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<Project>,
    /// `[services.<name>]`。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub services: BTreeMap<String, Service>,
    /// `[networks.<name>]`。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub networks: BTreeMap<String, Network>,
    /// `[volumes.<name>]`。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub volumes: BTreeMap<String, Volume>,
    /// `[secrets.<name>]`。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, Secret>,
    /// `[configs.<name>]`。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub configs: BTreeMap<String, Config>,
}

/// `[project]` テーブル。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    /// プロジェクト名。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// `[services.<name>]` テーブル。
///
/// スタブ: 現時点ではフィールドを持たない。基本フィールド（image・command・depends_on 等）は
/// TASK-149.3（#585）、拡張フィールド（restart・devices・profiles・healthcheck・
/// deploy.resources 等）は TASK-149.4（#862・#863）で足す（STACK-1）。
/// `deny_unknown_fields` のため、フィールドが入るまで `[services.<name>]` にキーを
/// 書くと parse は失敗する（未対応キーを黙って捨てない意図した挙動）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {}

/// `[networks.<name>]` テーブル。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// ネットワーク driver 名（未検証）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    /// 既存リソースを参照するか。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external: Option<bool>,
}

/// `[volumes.<name>]` テーブル。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Volume {
    /// ボリューム driver 名（例: `io-share`。未検証）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    /// 既存リソースを参照するか。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external: Option<bool>,
}

/// `[secrets.<name>]` テーブル。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Secret {
    /// 供給元ファイルのパス（未検証。正規化と範囲確認は使う側の責務）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// 既存リソースを参照するか。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external: Option<bool>,
}

/// `[configs.<name>]` テーブル。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// 供給元ファイルのパス（未検証。正規化と範囲確認は使う側の責務）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// 既存リソースを参照するか。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
[project]
name = "demo"

[services.web]

[networks.backend]
driver = "bridge"

[volumes.models]
driver = "io-share"

[secrets.api_key]
file = "./secrets/api_key"

[configs.app]
file = "./app.conf"
"#;

    fn full_value() -> ComposeToml {
        ComposeToml {
            project: Some(Project {
                name: Some("demo".into()),
            }),
            services: BTreeMap::from([("web".into(), Service {})]),
            networks: BTreeMap::from([(
                "backend".into(),
                Network {
                    driver: Some("bridge".into()),
                    external: None,
                },
            )]),
            volumes: BTreeMap::from([(
                "models".into(),
                Volume {
                    driver: Some("io-share".into()),
                    external: None,
                },
            )]),
            secrets: BTreeMap::from([(
                "api_key".into(),
                Secret {
                    file: Some("./secrets/api_key".into()),
                    external: None,
                },
            )]),
            configs: BTreeMap::from([(
                "app".into(),
                Config {
                    file: Some("./app.conf".into()),
                    external: None,
                },
            )]),
        }
    }

    /// STACK-1・TASK-149.2: 6 テーブルすべてを読める。
    #[test]
    fn stack_1_parses_all_top_level_tables() {
        let parsed: ComposeToml = toml::from_str(FULL).expect("valid document");
        assert_eq!(parsed, full_value());
    }

    /// STACK-1・TASK-149.2: 空文書は既定値になる。
    #[test]
    fn stack_1_empty_document_is_default() {
        let parsed: ComposeToml = toml::from_str("").expect("empty document");
        assert_eq!(parsed, ComposeToml::default());
    }

    /// STACK-1・TASK-149.2: 書き出して読み直すと一致し、空 map・None は出力に現れない。
    #[test]
    fn stack_1_top_level_roundtrip() {
        let value = full_value();
        let text = toml::to_string(&value).expect("serialize");
        let back: ComposeToml = toml::from_str(&text).expect("reparse");
        assert_eq!(back, value);

        let mut sparse = value;
        sparse.networks.clear();
        sparse.project = None;
        let text = toml::to_string(&sparse).expect("serialize sparse");
        assert!(!text.contains("networks"), "unexpected output: {text}");
        assert!(!text.contains("project"), "unexpected output: {text}");
    }

    /// STACK-1・TASK-149.2: トップレベルの未知キーは拒否する。
    #[test]
    fn stack_1_rejects_unknown_top_level_key() {
        assert!(toml::from_str::<ComposeToml>("profiles = [\"dev\"]").is_err());
        assert!(toml::from_str::<ComposeToml>("foo = 1").is_err());
    }

    /// STACK-1・TASK-149.2: リソース内の typo は拒否する。
    #[test]
    fn stack_1_rejects_unknown_key_in_resource() {
        let doc = "[networks.backend]\ndrvier = \"bridge\"\n";
        assert!(toml::from_str::<ComposeToml>(doc).is_err());
    }

    /// STACK-1・TASK-149.2: `Service` はスタブのため、フィールドが入るまでキーを拒否する。
    /// #585 でフィールドを足したら、このテストは受理側の試験へ置き換える（弱体化ではない）。
    #[test]
    fn stack_1_service_stub_rejects_fields_until_defined() {
        let doc = "[services.web]\nimage = \"x\"\n";
        assert!(toml::from_str::<ComposeToml>(doc).is_err());
    }
}
