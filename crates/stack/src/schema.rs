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
/// 基本フィールド 10 個に加え、`healthcheck` と `deploy.resources`（TASK-149.4.2・#863）を持つ。
/// 残りの拡張フィールド（restart・devices・profiles 等）は TASK-149.4（#862）で足す。
/// `deny_unknown_fields` のため、未定義のキー（未追加の拡張フィールドと typo）は今も拒否する
/// （fail-closed）。
///
/// 値は検証しない。`env_files`・`volumes` のホスト側パス（`..`・symlink を含む範囲外参照）、
/// `ports`、`image` の参照形式の検証と、`command` / `entrypoint` をシェルへ連結せず配列のまま
/// exec へ渡すことは、読み込み側（parse の入口・`up`〔TASK-155〕・supervisor）の責務である。
/// `healthcheck` の時間文字列・`retries` の検証は supervisor の `HealthcheckDefinition::parse`（SUP-4）、
/// `deploy.resources` の `cpus`・`memory`・CDI 名の検証は `up`（TASK-155）と gpu 側の責務である。
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
    /// ヘルスチェック定義（STACK-1・TASK-149.4.2・#863）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<Healthcheck>,
    /// `[services.<name>.deploy]`（STACK-1・TASK-149.4.2・#863。`resources` のみ）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deploy: Option<Deploy>,
}

/// `[services.<name>.healthcheck]`（STACK-1・CLI-4・TASK-149.4.2・#863）。
///
/// supervisor の healthcheck 定義（SUP-4。`crates/supervisor/src/healthcheck.rs`）へ写す前段の
/// 未検証の型で、`up`（TASK-155）が結線する。時間は文字列のまま持ち、解釈と範囲検査は
/// supervisor の `HealthcheckDefinition::parse` が行う。`retries` は supervisor に合わせて
/// 符号付き整数で受け、負値の拒否も supervisor の構造化エラーに任せる。
/// `test` は argv の配列のみ（compose の文字列形・`CMD` / `CMD-SHELL` / `NONE` の正規化は変換器
/// 〔TASK-151〕の責務）で、シェルへ連結しない。`disable`・`start_interval` は表現先が無く拒否する。
/// `test` に資格情報が入りうるため `{:?}` をログ・エラーに出さない。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Healthcheck {
    /// 実行する argv。`command` と同じく `Option` にして `[]` とキー無しの違いを往復で保つ。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test: Option<Vec<String>>,
    /// 実行間隔（時間文字列。例: `30s`。未検証）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    /// 1 回の実行の期限（時間文字列。未検証）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    /// unhealthy と判定する連続失敗回数（未検証。負値も型の段階では受ける）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<i64>,
    /// 起動直後に失敗を数えない猶予（時間文字列。未検証）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_period: Option<String>,
}

/// `[services.<name>.deploy]`。STACK-1 の範囲は `resources` だけで、`placement`・`replicas` 等は
/// 足さず拒否する（TASK-149.4.2・#863）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deploy {
    /// リソースの上限と予約。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<DeployResources>,
}

/// `[services.<name>.deploy.resources]`（STACK-1・TASK-149.4.2・#863）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployResources {
    /// 上限（`limits`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<ResourceLimits>,
    /// 予約（`reservations`。STACK-1 の範囲は GPU の `devices` だけ）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservations: Option<ResourceReservations>,
}

/// `deploy.resources.limits`。`pids` 等は範囲外で拒否する。値は未検証（検証は `up`・TASK-155）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// CPU 上限（文字列のまま。例: `2.5`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<String>,
    /// メモリ上限（文字列のまま。例: `512M`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
}

/// `deploy.resources.reservations`（STACK-1・STACK-9）。
///
/// TASK-156（`crates/compose-convert` の GPU 予約変換）が変換結果を書く先である。
/// `cpus`・`memory`・`generic_resources` は範囲外で拒否する。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceReservations {
    /// 予約する GPU 等の CDI 完全修飾名（例: `nvidia.com/gpu=0`）。
    ///
    /// compose の構造（driver・count・device_ids・capabilities）は持たず、`count: N` 等を一意な
    /// CDI 名へ決める規則は変換側（STACK-9・TASK-156）にある。stack は文字列を解釈・検証しない。
    /// `Service.devices`（#862）とは別のフィールドで、GPU 予約の出力先はこちらである。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<String>,
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
        // 期待値の env ファイルのパスも `Path::join` で組み立てる（Windows では区切りが `\` になるため。CLI-1）。
        let joined = |file: &str| {
            Path::new("/proj")
                .join(file)
                .into_os_string()
                .into_string()
                .expect("utf-8")
        };
        assert_eq!(
            args,
            [
                "--env-file",
                joined(".env").as_str(),
                "--env-file",
                joined("/abs/other.env").as_str(),
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
            healthcheck: None,
            deploy: None,
        }
    }

    const HC_DEPLOY: &str = r#"
[services.web]
image = "example/web:1"

[services.web.healthcheck]
test = ["/bin/check", "--quick"]
interval = "30s"
timeout = "5s"
retries = 3
start_period = "10s"

[services.web.deploy.resources.limits]
cpus = "2.5"
memory = "512M"

[services.web.deploy.resources.reservations]
devices = ["nvidia.com/gpu=0", "nvidia.com/gpu=all"]
"#;

    /// STACK-1・TASK-149.4.2(#863): healthcheck の 5 フィールドが具体値で読める。
    #[test]
    fn stack_1_healthcheck_fields_parse() {
        let doc: ComposeToml = toml::from_str(HC_DEPLOY).expect("parse");
        let svc = doc.services.get("web").expect("web");
        assert_eq!(
            svc.healthcheck,
            Some(Healthcheck {
                test: Some(vec!["/bin/check".into(), "--quick".into()]),
                interval: Some("30s".into()),
                timeout: Some("5s".into()),
                retries: Some(3),
                start_period: Some("10s".into()),
            })
        );
    }

    /// STACK-1・TASK-149.4.2(#863): deploy.resources の入れ子と reservations.devices に届く。
    #[test]
    fn stack_1_deploy_resources_nested_parse() {
        let doc: ComposeToml = toml::from_str(HC_DEPLOY).expect("parse");
        let svc = doc.services.get("web").expect("web");
        assert_eq!(
            svc.deploy,
            Some(Deploy {
                resources: Some(DeployResources {
                    limits: Some(ResourceLimits {
                        cpus: Some("2.5".into()),
                        memory: Some("512M".into()),
                    }),
                    reservations: Some(ResourceReservations {
                        devices: vec!["nvidia.com/gpu=0".into(), "nvidia.com/gpu=all".into()],
                    }),
                }),
            })
        );
        let devices = &svc
            .deploy
            .as_ref()
            .and_then(|d| d.resources.as_ref())
            .and_then(|r| r.reservations.as_ref())
            .expect("reservations")
            .devices;
        assert_eq!(devices.len(), 2);
    }

    /// STACK-1・TASK-149.4.2(#863): 往復が一致し決定的で、空テーブルの Some も保たれる。
    #[test]
    fn stack_1_healthcheck_deploy_roundtrip() {
        let doc: ComposeToml = toml::from_str(HC_DEPLOY).expect("parse");
        let text = toml::to_string(&doc).expect("serialize");
        let again: ComposeToml = toml::from_str(&text).expect("reparse");
        assert_eq!(again, doc);
        assert_eq!(toml::to_string(&again).expect("serialize"), text);

        let empty = Service {
            healthcheck: Some(Healthcheck::default()),
            deploy: Some(Deploy::default()),
            ..Service::default()
        };
        let text = toml::to_string(&empty).expect("serialize");
        let back: Service = toml::from_str(&text).expect("reparse");
        assert_eq!(back, empty);
        assert_eq!(toml::to_string(&Service::default()).expect("serialize"), "");
    }

    /// STACK-1・TASK-149.4.2(#863): `test = []` は Some(空)、キー無しは None。
    #[test]
    fn stack_1_healthcheck_test_empty_list_preserved() {
        let hc: Healthcheck = toml::from_str("test = []").expect("parse");
        assert_eq!(hc.test, Some(vec![]));
        assert!(
            toml::to_string(&hc)
                .expect("serialize")
                .contains("test = []")
        );
        let none: Healthcheck = toml::from_str("").expect("parse");
        assert_eq!(none.test, None);
    }

    /// STACK-1・TASK-149.4.2(#863): retries は符号付きで受ける(拒否は supervisor の parse の責務)。
    #[test]
    fn stack_1_healthcheck_retries_signed() {
        let hc: Healthcheck = toml::from_str("retries = -1").expect("parse");
        assert_eq!(hc.retries, Some(-1));
    }

    /// STACK-1・TASK-149.4.2(#863): 範囲外のキー・typo・形の違う値は拒否する(fail-closed)。
    #[test]
    fn stack_1_healthcheck_deploy_reject_unknown_keys() {
        let bad = [
            "[healthcheck]\nintreval = \"1s\"\n",
            "[healthcheck]\ndisable = true\n",
            "[healthcheck]\nstart_interval = \"1s\"\n",
            "[deploy]\nplacement = {}\n",
            "[deploy]\nreplicas = 2\n",
            "[deploy.resources.limits]\npids = 10\n",
            "[deploy.resources.reservations]\ncpus = \"1\"\n",
            "[deploy.resources.reservations]\ndevices = \"nvidia.com/gpu=all\"\n",
            "[deploy.resources.reservations]\ndevices = [{ driver = \"nvidia\" }]\n",
        ];
        for doc in bad {
            assert!(toml::from_str::<Service>(doc).is_err(), "accepted: {doc}");
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
