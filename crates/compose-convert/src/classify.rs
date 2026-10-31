//! compose のキー分類テーブル（TASK-151.2・#596・STACK-3・STACK-10・MS-12）。
//!
//! [`crate::compose_convert`] が読んだ単一モデルのキーパスを、STACK-3 の 4 分類
//! （convert / warning / error-incompatible / error-unsupported-yet）と、どれにも当たらない
//! `unrecognized` に振り分ける純粋関数と表を持つ。後段（TOML 変換 #598・value_drops #599・
//! 走査 #600・`--downgrade` TASK-182）が呼ぶ。
//!
//! # 呼び出し側との契約
//!
//! 呼び出し側の走査器は `key_walk`（TASK-151.7・#602）。降下規則はそちらの `//!` を参照。
//!
//! - 引数のパスは、ユーザー定義名（サービス名・ネットワーク名・環境変数名等）を `*` にした正規形
//!   （例 `services.*.privileged`）。この関数は正規化しない。識別子を集計に混ぜないための走査側の責務。
//! - 表と同じ粒度のパスで分類する。Convert の入れ物キー（`healthcheck`・`deploy.resources.limits` 等）の
//!   子は型で変換するため渡さない（渡すと Unrecognized）。降りない接頭辞は [`UNSCANNED_KEY_PREFIXES`]。
//! - `deploy` の子（`placement`・`replicas` 等）と `network_mode` の値は走査側が明示的に引く
//!   （値は [`classify_network_mode_value`]）。
//! - 同じキーパスで分類が混ざったら [`KeyClass::heavier`] で重い方へ寄せる（fail-closed）。
//! - [`KeyClass::is_error`] は Unrecognized でも true。表に無いキーを黙って通さない（fail-closed）。
//!
//! # PoC-16 との違い
//!
//! - 表を列挙できる const にした（受け入れ条件との機械照合のため。REPAIR-12）。
//! - トップレベル `profiles` は stack スキーマに行き先が無い（#584）ため ErrorUnsupportedYet。
//! - `network_mode: service:<name>` は ErrorUnsupportedYet。STACK-10 の期待欄と TASK-188 (5) に従う
//!   （PoC README は error-incompatible としており、spec 側の食い違い）。
//! - 分類の重さは `Ord` の宣言順ではなく [`KeyClass::severity`] で明示する。
//! - `x-` は最後のセグメントが `x-` で始まるときだけ Warning（非正規パスを Warning に化けさせない）。

use std::fmt;

/// キーの分類。語彙は STACK-3 と一致する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyClass {
    /// TOML へそのまま変換できる。
    Convert,
    /// 変換結果に影響しないため警告のみ。
    Warning,
    /// Docker Engine 固有の機構に依存し、変換できない（D-16）。
    ErrorIncompatible,
    /// 現スキーマ・現実装では対応していない（将来対応の余地あり）。
    ErrorUnsupportedYet,
    /// 表のどれにも当たらない。エラー扱い。
    Unrecognized,
}

impl KeyClass {
    /// 変換レポートに出す固定の語彙。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Convert => "convert",
            Self::Warning => "warning",
            Self::ErrorIncompatible => "error-incompatible",
            Self::ErrorUnsupportedYet => "error-unsupported-yet",
            Self::Unrecognized => "unrecognized",
        }
    }

    /// エラーとして扱う分類か（Unrecognized を含む。STACK-5）。
    pub fn is_error(self) -> bool {
        matches!(
            self,
            Self::ErrorIncompatible | Self::ErrorUnsupportedYet | Self::Unrecognized
        )
    }

    /// 重さ。convert < warning < unsupported-yet < unrecognized < incompatible。
    pub fn severity(self) -> u8 {
        match self {
            Self::Convert => 0,
            Self::Warning => 1,
            Self::ErrorUnsupportedYet => 2,
            Self::Unrecognized => 3,
            Self::ErrorIncompatible => 4,
        }
    }

    /// 重い方を返す。同じキーパスで分類が混ざったときに使う。
    pub fn heavier(self, other: Self) -> Self {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }
}

impl fmt::Display for KeyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 分類表。キーパスはユーザー定義名を `*` にした形。Unrecognized の行は置かない。
pub const KEY_CLASS_TABLE: &[(&str, KeyClass)] = &[
    // Convert: stack スキーマ（ComposeToml）のフィールドと一対一に対応するキー。
    ("name", KeyClass::Convert),
    ("services", KeyClass::Convert),
    ("services.*", KeyClass::Convert),
    ("networks", KeyClass::Convert),
    ("networks.*", KeyClass::Convert),
    ("networks.*.driver", KeyClass::Convert),
    ("networks.*.external", KeyClass::Convert),
    ("volumes", KeyClass::Convert),
    ("volumes.*", KeyClass::Convert),
    ("volumes.*.driver", KeyClass::Convert),
    ("volumes.*.external", KeyClass::Convert),
    ("secrets", KeyClass::Convert),
    ("secrets.*", KeyClass::Convert),
    ("secrets.*.file", KeyClass::Convert),
    ("secrets.*.external", KeyClass::Convert),
    ("configs", KeyClass::Convert),
    ("configs.*", KeyClass::Convert),
    ("configs.*.file", KeyClass::Convert),
    ("configs.*.external", KeyClass::Convert),
    ("services.*.image", KeyClass::Convert),
    ("services.*.command", KeyClass::Convert),
    ("services.*.entrypoint", KeyClass::Convert),
    ("services.*.environment", KeyClass::Convert),
    ("services.*.env_file", KeyClass::Convert),
    ("services.*.ports", KeyClass::Convert),
    ("services.*.networks", KeyClass::Convert),
    ("services.*.volumes", KeyClass::Convert),
    ("services.*.depends_on", KeyClass::Convert),
    ("services.*.healthcheck", KeyClass::Convert),
    ("services.*.restart", KeyClass::Convert),
    ("services.*.secrets", KeyClass::Convert),
    ("services.*.configs", KeyClass::Convert),
    ("services.*.labels", KeyClass::Convert),
    ("services.*.ulimits", KeyClass::Convert),
    ("services.*.shm_size", KeyClass::Convert),
    ("services.*.tmpfs", KeyClass::Convert),
    ("services.*.devices", KeyClass::Convert),
    ("services.*.profiles", KeyClass::Convert),
    ("services.*.deploy", KeyClass::Convert),
    ("services.*.deploy.resources", KeyClass::Convert),
    ("services.*.deploy.resources.limits", KeyClass::Convert),
    (
        "services.*.deploy.resources.reservations",
        KeyClass::Convert,
    ),
    (
        "services.*.deploy.resources.reservations.devices",
        KeyClass::Convert,
    ),
    // Warning: 変換結果に影響しない互換キー（x-* は表でなく規則で判定する）。
    ("version", KeyClass::Warning),
    // ErrorIncompatible: Docker Engine 固有の機構に依存する（D-16）。
    ("services.*.build", KeyClass::ErrorIncompatible),
    ("services.*.privileged", KeyClass::ErrorIncompatible),
    ("services.*.deploy.placement", KeyClass::ErrorIncompatible),
    // ErrorUnsupportedYet: 現スキーマに行き先が無い。黙って落とさずエラーにする。
    ("include", KeyClass::ErrorUnsupportedYet),
    ("extends", KeyClass::ErrorUnsupportedYet),
    ("profiles", KeyClass::ErrorUnsupportedYet),
    // PR #337 の指摘で Warning から再分類した 13 キー（STACK-3）。
    ("services.*.container_name", KeyClass::ErrorUnsupportedYet),
    ("services.*.hostname", KeyClass::ErrorUnsupportedYet),
    ("services.*.domainname", KeyClass::ErrorUnsupportedYet),
    ("services.*.mac_address", KeyClass::ErrorUnsupportedYet),
    ("services.*.scale", KeyClass::ErrorUnsupportedYet),
    ("services.*.pull_policy", KeyClass::ErrorUnsupportedYet),
    ("services.*.isolation", KeyClass::ErrorUnsupportedYet),
    ("services.*.oom_kill_disable", KeyClass::ErrorUnsupportedYet),
    ("services.*.oom_score_adj", KeyClass::ErrorUnsupportedYet),
    ("services.*.cgroup_parent", KeyClass::ErrorUnsupportedYet),
    ("services.*.stdin_open", KeyClass::ErrorUnsupportedYet),
    ("services.*.tty", KeyClass::ErrorUnsupportedYet),
    ("services.*.platform", KeyClass::ErrorUnsupportedYet),
    // その他の未対応キー。
    ("services.*.extends", KeyClass::ErrorUnsupportedYet),
    ("services.*.network_mode", KeyClass::ErrorUnsupportedYet),
    ("services.*.user", KeyClass::ErrorUnsupportedYet),
    ("services.*.working_dir", KeyClass::ErrorUnsupportedYet),
    ("services.*.cap_add", KeyClass::ErrorUnsupportedYet),
    ("services.*.cap_drop", KeyClass::ErrorUnsupportedYet),
    ("services.*.security_opt", KeyClass::ErrorUnsupportedYet),
    ("services.*.read_only", KeyClass::ErrorUnsupportedYet),
    ("services.*.logging", KeyClass::ErrorUnsupportedYet),
    ("services.*.dns", KeyClass::ErrorUnsupportedYet),
    ("services.*.dns_search", KeyClass::ErrorUnsupportedYet),
    ("services.*.dns_opt", KeyClass::ErrorUnsupportedYet),
    ("services.*.sysctls", KeyClass::ErrorUnsupportedYet),
    ("services.*.extra_hosts", KeyClass::ErrorUnsupportedYet),
    ("services.*.stop_signal", KeyClass::ErrorUnsupportedYet),
    (
        "services.*.stop_grace_period",
        KeyClass::ErrorUnsupportedYet,
    ),
    ("services.*.init", KeyClass::ErrorUnsupportedYet),
    ("services.*.pid", KeyClass::ErrorUnsupportedYet),
    ("services.*.ipc", KeyClass::ErrorUnsupportedYet),
    ("services.*.uts", KeyClass::ErrorUnsupportedYet),
    ("services.*.group_add", KeyClass::ErrorUnsupportedYet),
    ("services.*.links", KeyClass::ErrorUnsupportedYet),
    ("services.*.external_links", KeyClass::ErrorUnsupportedYet),
    ("services.*.expose", KeyClass::ErrorUnsupportedYet),
    ("services.*.deploy.replicas", KeyClass::ErrorUnsupportedYet),
    (
        "services.*.deploy.restart_policy",
        KeyClass::ErrorUnsupportedYet,
    ),
    (
        "services.*.deploy.update_config",
        KeyClass::ErrorUnsupportedYet,
    ),
    (
        "services.*.deploy.endpoint_mode",
        KeyClass::ErrorUnsupportedYet,
    ),
    ("services.*.deploy.labels", KeyClass::ErrorUnsupportedYet),
    ("services.*.blkio_config", KeyClass::ErrorUnsupportedYet),
    ("services.*.cpus", KeyClass::ErrorUnsupportedYet),
    ("services.*.mem_limit", KeyClass::ErrorUnsupportedYet),
    ("services.*.mem_reservation", KeyClass::ErrorUnsupportedYet),
    ("services.*.cpu_shares", KeyClass::ErrorUnsupportedYet),
    (
        "services.*.device_cgroup_rules",
        KeyClass::ErrorUnsupportedYet,
    ),
    ("services.*.volumes_from", KeyClass::ErrorUnsupportedYet),
];

/// 分類表が子キーへ降りないと宣言するキーパスの接頭辞（未走査の明示）。
pub const UNSCANNED_KEY_PREFIXES: &[&str] = &[
    "services.*.healthcheck",
    "services.*.deploy.resources",
    "services.*.environment",
    "services.*.labels",
    "services.*.ulimits",
    "services.*.depends_on",
];

/// 静的な分類。表 → 最後のセグメントが `x-` なら Warning → それ以外は Unrecognized。
pub fn classify_key_path(path: &str) -> KeyClass {
    if let Some((_, class)) = KEY_CLASS_TABLE.iter().find(|(p, _)| *p == path) {
        return *class;
    }
    match path.rsplit('.').next() {
        Some(last) if last.starts_with("x-") => KeyClass::Warning,
        _ => KeyClass::Unrecognized,
    }
}

/// `services.*.network_mode` の値による分類。`None` は文字列でない値。値は戻り値に載せない。
pub fn classify_network_mode_value(value: Option<&str>) -> KeyClass {
    match value {
        Some(v) if v == "host" || v.starts_with("container:") => KeyClass::ErrorIncompatible,
        _ => KeyClass::ErrorUnsupportedYet,
    }
}

/// Docker ソケットの bind mount か（D-16 の影響指標）。値は保持しない。結線は #598。
///
/// short syntax（`source:target[:mode]`）のマウント元（最初の `:` より前）がソケットのパス全体と
/// 一致するときだけ true。マウント先だけの一致や `docker.sock.backup` のような接頭辞一致は false。
/// `:` を含まない項目は匿名ボリュームのため false。
pub fn is_docker_socket_bind(volume_entry: &str) -> bool {
    const SOCKET_SOURCES: [&str; 2] = ["/var/run/docker.sock", "//./pipe/docker_engine"];
    match volume_entry.split_once(':') {
        Some((source, _)) => SOCKET_SOURCES.contains(&source),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECLASSIFIED_13: [&str; 13] = [
        "container_name",
        "hostname",
        "domainname",
        "mac_address",
        "scale",
        "pull_policy",
        "isolation",
        "oom_kill_disable",
        "oom_score_adj",
        "cgroup_parent",
        "stdin_open",
        "tty",
        "platform",
    ];

    fn rows_of(class: KeyClass) -> Vec<&'static str> {
        KEY_CLASS_TABLE
            .iter()
            .filter(|(_, c)| *c == class)
            .map(|(p, _)| *p)
            .collect()
    }

    /// STACK-3: 再分類した 13 キーは表の行として error-unsupported-yet。
    #[test]
    fn stack3_reclassified_13_keys_are_unsupported_yet() {
        assert_eq!(RECLASSIFIED_13.len(), 13);
        for k in RECLASSIFIED_13 {
            let p = format!("services.*.{k}");
            assert!(KEY_CLASS_TABLE.iter().any(|(t, _)| *t == p), "{p}");
            assert_eq!(classify_key_path(&p), KeyClass::ErrorUnsupportedYet, "{p}");
        }
    }

    /// STACK-10・TASK-188 (5): サービス間参照のキーは error-unsupported-yet。
    #[test]
    fn stack10_service_reference_keys_are_unsupported_yet() {
        for p in [
            "services.*.links",
            "services.*.external_links",
            "extends",
            "services.*.extends",
            "services.*.volumes_from",
            "services.*.network_mode",
        ] {
            assert_eq!(classify_key_path(p), KeyClass::ErrorUnsupportedYet, "{p}");
        }
        assert_eq!(
            classify_network_mode_value(Some("service:db")),
            KeyClass::ErrorUnsupportedYet
        );
    }

    /// STACK-3・D-16: network_mode の値による分類。
    #[test]
    fn stack3_network_mode_value() {
        assert_eq!(
            classify_network_mode_value(Some("host")),
            KeyClass::ErrorIncompatible
        );
        assert_eq!(
            classify_network_mode_value(Some("container:abc")),
            KeyClass::ErrorIncompatible
        );
        for v in [
            Some("bridge"),
            Some("none"),
            None,
            Some("hostx"),
            Some("Container:x"),
        ] {
            assert_eq!(
                classify_network_mode_value(v),
                KeyClass::ErrorUnsupportedYet,
                "{v:?}"
            );
        }
    }

    /// STACK-3・D-16: error-incompatible の行は 3 つだけ。
    #[test]
    fn stack3_d16_incompatible_set() {
        assert_eq!(
            rows_of(KeyClass::ErrorIncompatible),
            [
                "services.*.build",
                "services.*.privileged",
                "services.*.deploy.placement"
            ]
        );
    }

    /// STACK-3: Warning の行は version だけ。x-* は規則。非正規パスは Warning にならない。
    #[test]
    fn stack3_warning_only_version_and_x() {
        assert_eq!(rows_of(KeyClass::Warning), ["version"]);
        for p in ["x-common", "services.*.x-foo", "networks.*.x-bar"] {
            assert_eq!(classify_key_path(p), KeyClass::Warning, "{p}");
        }
        for p in [
            "services.x-web.privileged",
            "x-common.foo",
            "services.web.image",
        ] {
            assert_eq!(classify_key_path(p), KeyClass::Unrecognized, "{p}");
        }
    }

    /// STACK-1: Convert のキーは stack スキーマ（Service / ComposeToml）の項目に対応する。
    #[test]
    fn stack1_convert_keys_mirror_stack_schema() {
        let mut svc: Vec<&str> = rows_of(KeyClass::Convert)
            .into_iter()
            .filter_map(|p| p.strip_prefix("services.*."))
            .filter(|k| !k.contains('.'))
            .collect();
        svc.sort_unstable();
        let mut want = vec![
            "image",
            "command",
            "entrypoint",
            "environment",
            "env_file",
            "ports",
            "networks",
            "volumes",
            "depends_on",
            "healthcheck",
            "restart",
            "secrets",
            "configs",
            "labels",
            "ulimits",
            "shm_size",
            "tmpfs",
            "devices",
            "profiles",
            "deploy",
        ];
        want.sort_unstable();
        assert_eq!(svc, want);
        for t in [
            "name", "services", "networks", "volumes", "secrets", "configs",
        ] {
            assert_eq!(classify_key_path(t), KeyClass::Convert, "{t}");
        }
    }

    /// STACK-3: 表に無い・入れ物の子は Unrecognized。トップレベル profiles は unsupported-yet。
    #[test]
    fn stack3_unrecognized_fallthrough() {
        for p in [
            "",
            "unknown",
            "services.*.models",
            "services.*.healthcheck.test",
        ] {
            assert_eq!(classify_key_path(p), KeyClass::Unrecognized, "{p:?}");
        }
        assert_eq!(classify_key_path("profiles"), KeyClass::ErrorUnsupportedYet);
    }

    /// REPAIR-12: 表の整合（重複なし・往復一致・Unrecognized/x-/空セグメントの行なし）。
    #[test]
    fn repair12_table_integrity() {
        for (i, (p, c)) in KEY_CLASS_TABLE.iter().enumerate() {
            assert!(
                KEY_CLASS_TABLE[i + 1..].iter().all(|(q, _)| q != p),
                "dup {p}"
            );
            assert_eq!(classify_key_path(p), *c, "{p}");
            assert_ne!(*c, KeyClass::Unrecognized, "{p}");
            assert!(
                p.split('.').all(|s| !s.is_empty() && !s.starts_with("x-")),
                "{p}"
            );
        }
    }

    /// STACK-3: 語彙・重さ・is_error。
    #[test]
    fn stack3_class_labels_and_severity() {
        let all = [
            (KeyClass::Convert, "convert", false),
            (KeyClass::Warning, "warning", false),
            (KeyClass::ErrorUnsupportedYet, "error-unsupported-yet", true),
            (KeyClass::Unrecognized, "unrecognized", true),
            (KeyClass::ErrorIncompatible, "error-incompatible", true),
        ];
        for (n, (c, s, e)) in all.iter().enumerate() {
            assert_eq!(c.as_str(), *s);
            assert_eq!(c.to_string(), *s);
            assert_eq!(c.is_error(), *e);
            assert_eq!(usize::from(c.severity()), n);
        }
        assert_eq!(
            KeyClass::ErrorUnsupportedYet.heavier(KeyClass::ErrorIncompatible),
            KeyClass::ErrorIncompatible
        );
        assert_eq!(
            KeyClass::ErrorIncompatible.heavier(KeyClass::Warning),
            KeyClass::ErrorIncompatible
        );
    }

    /// D-16: Docker ソケットの bind mount の検出。
    #[test]
    fn stack3_docker_socket_bind() {
        assert!(is_docker_socket_bind(
            "/var/run/docker.sock:/var/run/docker.sock"
        ));
        assert!(is_docker_socket_bind(
            "//./pipe/docker_engine://./pipe/docker_engine"
        ));
        assert!(!is_docker_socket_bind("./data:/data"));
        assert!(!is_docker_socket_bind(
            "/var/run/docker.sock.backup:/backup"
        ));
        assert!(!is_docker_socket_bind("./dummy:/var/run/docker.sock"));
        assert!(!is_docker_socket_bind("/var/run/docker.sock"));
    }
}
