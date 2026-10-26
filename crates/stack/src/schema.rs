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
//! - parse / serialize の公開入口はまだ無い（担当は後続。STACK-1）。テストは `toml` を直接使う。

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

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

/// `[services.<name>]` テーブル（STACK-1・TASK-149.3・#585）。
///
/// 基本フィールド 10 個を持つ。拡張フィールド（restart・devices・profiles・healthcheck・
/// deploy.resources 等）は TASK-149.4（#862・#863）で足す。`deny_unknown_fields` のため、
/// 未定義のキー（拡張フィールドと typo）は今も拒否する（fail-closed）。
///
/// 値は検証しない。`env_files`・`volumes` のホスト側パス（`..`・symlink を含む範囲外参照）、
/// `ports`、`image` の参照形式の検証と、`command` / `entrypoint` をシェルへ連結せず配列のまま
/// exec へ渡すことは、読み込み側（parse の入口・`up`〔TASK-155〕・supervisor）の責務である。
/// 空のコレクションは「キーが無い」と同じ意味のため出力から省く。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    /// イメージ参照（未検証）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// 起動コマンド（配列のみ。compose の文字列形は変換器〔TASK-151〕が配列へ正規化する）。
    ///
    /// PoC-16 の `Vec<String>` と違い `Option` とする。キー無し（イメージの既定を使う）と
    /// `[]`（既定を打ち消す）の意味が違い、書き出しで `[]` が消えると意味が変わるため。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// エントリポイント。`command` と同じく `Option` で `[]` を保つ。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    /// 環境変数（compose の `environment` に当たる）。
    ///
    /// 値を持たない compose の `KEY` だけの形は表せない（変換器が空文字列に読み替える）。
    /// 値に資格情報が入りうる。`Debug` を derive しているため `{:?}` をログ・エラーに出さない。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// 環境変数ファイルのパス（compose の `env_file` に当たる。未検証）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_files: Vec<String>,
    /// ポート公開（short syntax の文字列。例: `8080:8080/tcp`）。long syntax は変換器が正規化する。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<String>,
    /// 参加するネットワーク名（`[networks.<name>]` の名前を参照する）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<String>,
    /// ボリューム・bind mount（short syntax。例: `models:/models:ro`）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<String>,
    /// 依存サービス名から起動条件への対応（STACK-2・TASK-150 が起動順に使う）。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub depends_on: BTreeMap<String, DependsOnCondition>,
    /// ラベル。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl Service {
    /// このサービスの環境変数・env ファイル・ラベルを、CLI の `create` の引数列へ写す(SUP-12・CLI-1・CLI-4・#2713)。
    ///
    /// 返すのは `--env-file <path>`(`env_files`。相対パスは `project_dir` 起点で解決)、`--env <KEY=VALUE>`(`env`。
    /// キー昇順)、`--label <KEY=VALUE>`(`labels`。キー昇順)の列で、`up`(TASK-155)が CLI の `create` を呼ぶ想定に
    /// 合わせた argv の断片である。stack が cli・supervisor・core へ依存する新しい辺を作らないよう、値の検証
    /// (キーの形式・件数・長さ・env ファイルの読み取り)は受け取る CLI 側が既存のパーサで一元的に行う。
    /// `ulimit`・`tmpfs` はスキーマに無い(#586・#862)ため含めない。`up` からの結線は TASK-155 の後続(REPAIR-3)。
    ///
    /// 値に資格情報が入りうるため、戻り値を `{:?}` でログ・エラーに出さない。`env_files` の絶対パスや `..` を含む
    /// パスは検証しない(読むのは CLI が利用者の権限で行う。範囲外参照の扱いは `up` の責務)。
    pub fn create_option_args(&self, project_dir: &Path) -> Vec<OsString> {
        let mut args = Vec::new();
        for file in &self.env_files {
            args.push(OsString::from("--env-file"));
            args.push(project_dir.join(file).into_os_string());
        }
        for (key, value) in &self.env {
            args.push(OsString::from("--env"));
            args.push(OsString::from(format!("{key}={value}")));
        }
        for (key, value) in &self.labels {
            args.push(OsString::from("--label"));
            args.push(OsString::from(format!("{key}={value}")));
        }
        args
    }
}

/// `depends_on` の起動条件（STACK-1・D-17 論点 2）。
///
/// `Default` は持たない。compose で condition を省いたときの既定（`started`）を補うのは
/// 変換器であり、型が黙って補わない。compose の綴り（`service_healthy` 等）は受け付けない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DependsOnCondition {
    /// 依存先の起動を待つ（compose の `service_started`）。
    Started,
    /// 依存先が healthy になるまで待つ（compose の `service_healthy`）。
    Healthy,
    /// 依存先が正常終了するまで待つ（compose の `service_completed_successfully`）。
    Completed,
}

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

    /// SUP-12・CLI-4(#2713): env・env_files・labels が create の引数列に具体値で写る(env ファイルは project_dir 起点)。
    #[test]
    fn sup12_service_create_option_args() {
        let service = Service {
            env: BTreeMap::from([("B".into(), "2".into()), ("A".into(), "x=y".into())]),
            env_files: vec![".env".into(), "/abs/other.env".into()],
            labels: BTreeMap::from([("tier".into(), "web".into())]),
            ..Service::default()
        };
        let args: Vec<String> = service
            .create_option_args(Path::new("/proj"))
            .into_iter()
            .map(|a| a.into_string().expect("utf-8"))
            .collect();
        assert_eq!(
            args,
            [
                "--env-file",
                "/proj/.env",
                "--env-file",
                "/abs/other.env",
                "--env",
                "A=x=y",
                "--env",
                "B=2",
                "--label",
                "tier=web",
            ]
        );
        assert!(
            Service::default()
                .create_option_args(Path::new("/proj"))
                .is_empty()
        );
    }

    const FULL: &str = r#"
[project]
name = "demo"

[services.web]
image = "example/web:1"
command = ["serve", "--port", "8080"]
entrypoint = []
env_files = [".env"]
ports = ["8080:8080/tcp"]
networks = ["backend"]
volumes = ["models:/models:ro"]

[services.web.env]
MODE = "dummy"

[services.web.depends_on]
db = "healthy"

[services.web.labels]
tier = "front"

[networks.backend]
driver = "bridge"

[volumes.models]
driver = "io-share"

[secrets.api_key]
file = "./secrets/api_key"

[configs.app]
file = "./app.conf"
"#;

    fn web_service() -> Service {
        Service {
            image: Some("example/web:1".into()),
            command: Some(vec!["serve".into(), "--port".into(), "8080".into()]),
            entrypoint: Some(vec![]),
            env: BTreeMap::from([("MODE".into(), "dummy".into())]),
            env_files: vec![".env".into()],
            ports: vec!["8080:8080/tcp".into()],
            networks: vec!["backend".into()],
            volumes: vec!["models:/models:ro".into()],
            depends_on: BTreeMap::from([("db".into(), DependsOnCondition::Healthy)]),
            labels: BTreeMap::from([("tier".into(), "front".into())]),
        }
    }

    fn full_value() -> ComposeToml {
        ComposeToml {
            project: Some(Project {
                name: Some("demo".into()),
            }),
            services: BTreeMap::from([("web".into(), web_service())]),
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
        assert!(!text.contains("[networks"), "unexpected output: {text}");
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

    /// STACK-1・TASK-149.3: 基本フィールド 10 個を具体値で読める。
    #[test]
    fn stack_1_service_basic_fields_parse() {
        let parsed: ComposeToml = toml::from_str(FULL).expect("valid document");
        assert_eq!(parsed.services.get("web"), Some(&web_service()));
    }

    /// STACK-1・TASK-149.3: `depends_on` は 3 つの条件を名前から条件への map で受ける。
    #[test]
    fn stack_1_depends_on_conditions_map() {
        let doc =
            "[services.s]\ndepends_on = { a = \"started\", b = \"healthy\", c = \"completed\" }\n";
        let parsed: ComposeToml = toml::from_str(doc).expect("valid");
        assert_eq!(
            parsed.services["s"].depends_on,
            BTreeMap::from([
                ("a".to_string(), DependsOnCondition::Started),
                ("b".to_string(), DependsOnCondition::Healthy),
                ("c".to_string(), DependsOnCondition::Completed),
            ])
        );
    }

    /// STACK-1・TASK-149.3: compose の綴り・未知の条件・配列の短縮形は拒否する。
    #[test]
    fn stack_1_depends_on_rejects_compose_spelling_and_list() {
        for doc in [
            "[services.s]\ndepends_on = { a = \"service_healthy\" }\n",
            "[services.s]\ndepends_on = { a = \"ready\" }\n",
            "[services.s]\ndepends_on = [\"db\"]\n",
        ] {
            assert!(toml::from_str::<ComposeToml>(doc).is_err(), "{doc}");
        }
    }

    /// STACK-1・TASK-149.3: サービス内の typo は拒否する。
    #[test]
    fn stack_1_service_rejects_unknown_key() {
        assert!(toml::from_str::<ComposeToml>("[services.web]\nimgae = \"x\"\n").is_err());
    }

    /// STACK-1・TASK-149.3: `command = []` は `Some(vec![])` で保たれ、キー無しは `None`。
    #[test]
    fn stack_1_command_empty_list_is_preserved() {
        let doc = "[services.s]\ncommand = []\nentrypoint = []\n";
        let parsed: ComposeToml = toml::from_str(doc).expect("valid");
        let svc = &parsed.services["s"];
        assert_eq!(svc.command, Some(vec![]));
        assert_eq!(svc.entrypoint, Some(vec![]));
        let text = toml::to_string(&parsed).expect("serialize");
        assert!(text.contains("command = []"), "unexpected output: {text}");
        assert!(
            text.contains("entrypoint = []"),
            "unexpected output: {text}"
        );

        let none: ComposeToml = toml::from_str("[services.s]\n").expect("valid");
        assert_eq!(none.services["s"].command, None);
        let text = toml::to_string(&none).expect("serialize");
        assert!(!text.contains("command"), "unexpected output: {text}");
    }

    /// STACK-1・TASK-149.3: 空のコレクションと `None` は書き出しに現れない。
    #[test]
    fn stack_1_service_empty_collections_are_omitted() {
        let text = toml::to_string(&Service::default()).expect("serialize");
        assert_eq!(text, "");
    }
}
