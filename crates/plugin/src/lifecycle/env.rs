//! plugin 子プロセスへ追加で渡す環境変数の検証と保持（#1858・#1319・PLUG-7・PLUG-11・PLUG-12）。
//!
//! 役割: `OneShotPlugin::with_env` から呼ばれ、呼び出し側（core）が明示した名前と値の組を検証し、
//! 検証済みの値だけを持つ型 `PluginEnvVars` にする。`plugin_command`（都度起動・常駐の共通の
//! `Command` 組み立て口）が `env_clear()` の後にこの組を設定する。
//!
//! 契約:
//! - 既定は空。子に渡るのは `FANDHE_CONTAINER_PLUGIN_SOCKET` だけで、親の環境は暗黙に継承しない。
//!   親から引き継ぎたい値は呼び出し側のコードが明示して読み、名前と値で渡す。
//! - 名前は `[A-Za-z_][A-Za-z0-9_]*`。予約接頭辞 `FANDHE_CONTAINER_PLUGIN_`（socket の変数の偽装を防ぐ）と、
//!   動的リンカに効く `LD_`・`DYLD_`（ライブラリ注入を防ぐ）は ASCII の大文字小文字を区別せず拒否する。
//! - 値は NUL を含まない。件数・名前・値・合計の上限は公開定数で示す。
//! - 検証順は 件数 → 合計 → 各要素（名前の形・長さ → 予約接頭辞 → 値の長さ → NUL）→ 重複。
//! - エラー文言と `Debug` に値を載せない（値は資格情報になり得る）。エラー文言には名前も載せない。
//!
//! 対象外: どの plugin に何を渡すか（#1869）、Windows ホスト用の変数（#1415）。

use crate::error::{PluginError, PluginErrorCode};
use std::ffi::OsString;
use std::fmt;

/// 追加する環境変数の件数上限。
pub const ONE_SHOT_ENV_MAX_COUNT: usize = 32;
/// 名前 1 件のバイト数上限。
pub const ONE_SHOT_ENV_NAME_MAX_BYTES: usize = 128;
/// 値 1 件のバイト数上限（`OsStr::as_encoded_bytes` の長さ）。
pub const ONE_SHOT_ENV_VALUE_MAX_BYTES: usize = 4096;
/// 全件の `名前の長さ + 値の長さ` の合計上限（区切りの `=` は数えない）。
pub const ONE_SHOT_ENV_MAX_BYTES: usize = 16384;

/// 拒否する名前の接頭辞（ASCII の大文字小文字を区別しない）。
const RESERVED_PREFIXES: [&str; 3] = ["FANDHE_CONTAINER_PLUGIN_", "LD_", "DYLD_"];

/// 検証済みの追加環境変数の組。値は `Debug` に出さない。
#[derive(Clone, Default)]
pub(super) struct PluginEnvVars(Vec<(String, OsString)>);

impl PluginEnvVars {
    pub(super) fn iter(&self) -> impl Iterator<Item = (&str, &OsString)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }
}

impl fmt::Debug for PluginEnvVars {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginEnvVars")
            .field("names", &self.0.iter().map(|(k, _)| k).collect::<Vec<_>>())
            .finish()
    }
}

fn invalid(msg: &'static str) -> PluginError {
    PluginError::new(PluginErrorCode::InvalidArgument, msg)
}

fn name_is_valid(name: &str) -> bool {
    if name.is_empty() || name.len() > ONE_SHOT_ENV_NAME_MAX_BYTES {
        return false;
    }
    let mut bytes = name.bytes();
    let first_ok = bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
    first_ok && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn name_is_reserved(name: &str) -> bool {
    RESERVED_PREFIXES.iter().any(|p| {
        name.get(..p.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(p))
    })
}

/// 名前と値の組を検証して `PluginEnvVars` にする。違反は `InvalidArgument`（固定文言）。
pub(super) fn validate(vars: Vec<(String, OsString)>) -> Result<PluginEnvVars, PluginError> {
    const SIZE_MSG: &str = "plugin environment variables exceed the allowed count or size";
    if vars.len() > ONE_SHOT_ENV_MAX_COUNT {
        return Err(invalid(SIZE_MSG));
    }
    let mut total: usize = 0;
    for (name, value) in &vars {
        total = total
            .checked_add(name.len())
            .and_then(|t| t.checked_add(value.len()))
            .ok_or_else(|| invalid(SIZE_MSG))?;
    }
    if total > ONE_SHOT_ENV_MAX_BYTES {
        return Err(invalid(SIZE_MSG));
    }
    for (name, value) in &vars {
        if !name_is_valid(name) {
            return Err(invalid("plugin environment variable name is invalid"));
        }
        if name_is_reserved(name) {
            return Err(invalid("plugin environment variable name is reserved"));
        }
        let bytes = value.as_encoded_bytes();
        if bytes.len() > ONE_SHOT_ENV_VALUE_MAX_BYTES {
            return Err(invalid(
                "plugin environment variable value exceeds the allowed size",
            ));
        }
        if bytes.contains(&0) {
            return Err(invalid("plugin environment variable value contains NUL"));
        }
    }
    for (i, (a, _)) in vars.iter().enumerate() {
        if vars.iter().skip(i + 1).any(|(b, _)| a == b) {
            return Err(invalid("plugin environment variable name is duplicated"));
        }
    }
    Ok(PluginEnvVars(vars))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(n: &str, val: &str) -> (String, OsString) {
        (n.to_string(), OsString::from(val))
    }

    fn err_msg(vars: Vec<(String, OsString)>) -> String {
        let e = validate(vars).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        e.message().to_string()
    }

    #[test]
    fn plug7_env_name_rules() {
        for ok in ["_OK", "A1_b", "HOME"] {
            assert!(validate(vec![v(ok, "x")]).is_ok(), "{ok}");
        }
        let long_ok = "A".repeat(128);
        assert!(validate(vec![v(&long_ok, "")]).is_ok());
        let invalid_msg = "plugin environment variable name is invalid";
        for bad in ["", "1A", "A-B", "A=B"] {
            assert_eq!(err_msg(vec![v(bad, "x")]), invalid_msg, "{bad}");
        }
        assert_eq!(err_msg(vec![v(&"A".repeat(129), "")]), invalid_msg);
    }

    #[test]
    fn plug7_env_reserved_prefixes() {
        let m = "plugin environment variable name is reserved";
        for bad in [
            "FANDHE_CONTAINER_PLUGIN_X",
            "FANDHE_CONTAINER_PLUGIN_SOCKET",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "ld_preload",
        ] {
            assert_eq!(err_msg(vec![v(bad, "x")]), m, "{bad}");
        }
    }

    #[test]
    fn plug7_env_value_rules() {
        assert!(validate(vec![v("A", "")]).is_ok());
        assert!(validate(vec![v("A", &"x".repeat(4096))]).is_ok());
        assert_eq!(
            err_msg(vec![v("A", &"x".repeat(4097))]),
            "plugin environment variable value exceeds the allowed size"
        );
        assert_eq!(
            err_msg(vec![v("A", "a\0b")]),
            "plugin environment variable value contains NUL"
        );
    }

    #[test]
    fn plug7_env_count_and_total_boundaries() {
        let size_msg = "plugin environment variables exceed the allowed count or size";
        let many = |n: usize| (0..n).map(|i| v(&format!("V{i}"), "")).collect::<Vec<_>>();
        assert!(validate(many(32)).is_ok());
        assert_eq!(err_msg(many(33)), size_msg);

        let four = |val_len: usize| {
            ["A", "B", "C", "D"]
                .iter()
                .map(|n| v(n, &"x".repeat(val_len)))
                .collect::<Vec<_>>()
        };
        // 4 * (1 + 4095) = 16384 ちょうど
        assert!(validate(four(4095)).is_ok());
        let mut over = four(4095);
        over.push(v("E", ""));
        assert_eq!(err_msg(over), size_msg);
    }

    #[test]
    fn plug7_env_duplicates() {
        assert_eq!(
            err_msg(vec![v("A", "1"), v("A", "2")]),
            "plugin environment variable name is duplicated"
        );
        assert!(validate(vec![v("A", "1"), v("a", "2")]).is_ok());
    }

    #[test]
    fn plug7_env_debug_hides_values() {
        let vars = validate(vec![v("HOME", "s3cr3t-value")]).unwrap();
        let dbg = format!("{vars:?}");
        assert!(dbg.contains("HOME"));
        assert!(!dbg.contains("s3cr3t-value"));
    }
}
