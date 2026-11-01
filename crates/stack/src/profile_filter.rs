//! `profiles` の起動対象絞り込みのうち、`--profile` 引数と環境変数の解析（STACK-10・TASK-187.1・#631）。
//!
//! 呼び出し元は CLI の `up` 結線（#3639）。結線側が argv から `--profile` の値を集め、環境変数
//! [`PROFILES_ENV`] を読んで [`resolve_active_profiles`] へ渡す。本モジュールは `std::env` も argv も
//! 読まない純関数で、アクティブなプロファイル集合 [`ActiveProfiles`] だけを返す。
//! サービスの有効判定と `up <service>` の明示指定による追加は後続の #632（TASK-187.2）、
//! `depends_on` による無効サービス参照の拒否は #633（TASK-187.3）が担う。
//!
//! 規則（compose の文書化された挙動に合わせる。出典: compose-spec `15-profiles.md` の名前の正規表現と、
//! docker compose の `--profile` / `COMPOSE_PROFILES`。オフラインで書いたため一次情報の再確認は #632 で行う）:
//! - `--profile` が 1 つ以上あればそれだけを使い、環境変数は見ない（合算しない。不正な値でも無視する）。
//! - `--profile` が無いときだけ環境変数をカンマで分割し、前後の空白を除き、空要素を飛ばす。
//! - `--profile` の値はカンマで分割しない。1 値が 1 名前で、カンマを含めば名前不正になる。
//! - 名前は `[a-zA-Z0-9][a-zA-Z0-9_.-]+`（2 文字以上）。fail-closed のため 1 文字の名前は拒否する。
//! - `--profile '*'`（docker compose CLI のワイルドカード拡張）は未対応で名前不正として拒否する（REPAIR-3）。
//!
//! 環境変数名は `COMPOSE_PROFILES` ではなく `FANDHE_CONTAINER_PROFILES` とする（本リポの慣例。
//! `COMPOSE_PROFILES` を受けるかはオーナー判断待ち）。

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::num::NonZeroU8;

/// プロファイルを渡す環境変数名（結線側 #3639 が参照する）。
pub const PROFILES_ENV: &str = "FANDHE_CONTAINER_PROFILES";

/// 環境変数の生の値の最大バイト数（分割前に検査する。無制限確保による DoS の防止）。
pub const MAX_PROFILES_ENV_BYTES: usize = 16 * 1024;

/// 生の要素数（`--profile` の個数、または環境変数の空でない要素数）の上限。重複除去より前に数える。
pub const MAX_ACTIVE_PROFILES: usize = 256;

/// プロファイル名 1 つの最大バイト数（文字の検査より先に見る）。
pub const MAX_PROFILE_NAME_BYTES: usize = 64;

/// アクティブなプロファイルの集合（重複なし・昇順）。#632 が有効サービスの判定に使う。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActiveProfiles(BTreeSet<String>);

impl ActiveProfiles {
    /// `name` がアクティブか。
    pub fn contains(&self, name: &str) -> bool {
        self.0.contains(name)
    }

    /// 名前を昇順で返す。
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    /// 件数。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 空（プロファイル未指定）か。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// 値の由来。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileOrigin {
    /// `--profile` 引数。
    Flag,
    /// 環境変数 [`PROFILES_ENV`]。
    Env,
}

/// 超過した上限。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileLimit {
    /// 環境変数のバイト長。
    EnvBytes,
    /// 要素数。
    Count,
    /// 名前のバイト長。
    NameBytes,
}

/// 解析の失敗。`Display` は untrusted な値を出さず、由来と 0 始まりの位置だけを出す
/// （制御文字・双方向制御文字による端末の偽装と、環境変数の値の漏えいを避ける）。
/// `index` は `--profile` では引数の位置、環境変数では空要素を除いた要素の位置。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileArgError {
    /// UTF-8 でない。
    NotUtf8 {
        /// 由来。
        origin: ProfileOrigin,
        /// 位置。
        index: usize,
    },
    /// 名前の文字種が規則に合わない。
    InvalidName {
        /// 由来。
        origin: ProfileOrigin,
        /// 位置。
        index: usize,
    },
    /// 上限超過。
    LimitExceeded {
        /// 超過した上限。
        limit: ProfileLimit,
    },
}

impl ProfileArgError {
    /// 機械可読なコード。
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotUtf8 { .. } => "PROFILE_NOT_UTF8",
            Self::InvalidName { .. } => "INVALID_PROFILE_NAME",
            Self::LimitExceeded { .. } => "PROFILE_LIMIT_EXCEEDED",
        }
    }

    /// 固定の英語メッセージ。
    pub fn message(&self) -> &'static str {
        match self {
            Self::NotUtf8 { .. } => "profile value is not valid UTF-8",
            Self::InvalidName { .. } => "invalid profile name",
            Self::LimitExceeded { .. } => "profile limit exceeded",
        }
    }

    /// 使い方エラーの終了コード（core の `INVALID_ARGUMENT` と同じ 2）。
    pub fn exit_code(&self) -> NonZeroU8 {
        NonZeroU8::new(2).unwrap_or(NonZeroU8::MIN)
    }
}

fn place(origin: ProfileOrigin, index: usize) -> String {
    match origin {
        ProfileOrigin::Flag => format!("--profile #{index}"),
        ProfileOrigin::Env => format!("{PROFILES_ENV} item #{index}"),
    }
}

impl fmt::Display for ProfileArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8 { origin, index } | Self::InvalidName { origin, index } => {
                write!(f, "{}: {}", self.message(), place(*origin, *index))
            }
            Self::LimitExceeded { limit } => {
                let what = match limit {
                    ProfileLimit::EnvBytes => "environment value bytes",
                    ProfileLimit::Count => "item count",
                    ProfileLimit::NameBytes => "name bytes",
                };
                write!(f, "{}: {what}", self.message())
            }
        }
    }
}

impl std::error::Error for ProfileArgError {}

/// 名前が規則（`[a-zA-Z0-9][a-zA-Z0-9_.-]+`、64 バイト以下）に合うか。長さを先に見る。
fn check_name(name: &str) -> Result<(), NameFault> {
    if name.len() > MAX_PROFILE_NAME_BYTES {
        return Err(NameFault::TooLong);
    }
    let mut chars = name.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let mut rest = 0usize;
    let rest_ok = chars.all(|c| {
        rest += 1;
        c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
    });
    if first_ok && rest_ok && rest >= 1 {
        Ok(())
    } else {
        Err(NameFault::Invalid)
    }
}

enum NameFault {
    TooLong,
    Invalid,
}

fn add_name(
    set: &mut BTreeSet<String>,
    name: &str,
    origin: ProfileOrigin,
    index: usize,
) -> Result<(), ProfileArgError> {
    match check_name(name) {
        Ok(()) => {
            set.insert(name.to_owned());
            Ok(())
        }
        Err(NameFault::TooLong) => Err(ProfileArgError::LimitExceeded {
            limit: ProfileLimit::NameBytes,
        }),
        Err(NameFault::Invalid) => Err(ProfileArgError::InvalidName { origin, index }),
    }
}

/// `--profile` の値（複数）と環境変数の値からアクティブ集合を作る（STACK-10）。
///
/// `cli_values` が 1 件以上なら環境変数は見ない。0 件なら `env_value`（未設定は `None`）を
/// カンマ分割して使う。どちらも無ければ空集合（`profiles` を持たないサービスだけが有効になる）。
pub fn resolve_active_profiles<'a, I>(
    cli_values: I,
    env_value: Option<&OsStr>,
) -> Result<ActiveProfiles, ProfileArgError>
where
    I: IntoIterator<Item = &'a OsStr>,
{
    let mut set = BTreeSet::new();
    let mut count = 0usize;
    for (index, raw) in cli_values.into_iter().enumerate() {
        count += 1;
        if count > MAX_ACTIVE_PROFILES {
            return Err(ProfileArgError::LimitExceeded {
                limit: ProfileLimit::Count,
            });
        }
        let name = raw.to_str().ok_or(ProfileArgError::NotUtf8 {
            origin: ProfileOrigin::Flag,
            index,
        })?;
        add_name(&mut set, name, ProfileOrigin::Flag, index)?;
    }
    if count > 0 {
        return Ok(ActiveProfiles(set));
    }
    let Some(env) = env_value else {
        return Ok(ActiveProfiles(set));
    };
    if env.len() > MAX_PROFILES_ENV_BYTES {
        return Err(ProfileArgError::LimitExceeded {
            limit: ProfileLimit::EnvBytes,
        });
    }
    let text = env.to_str().ok_or(ProfileArgError::NotUtf8 {
        origin: ProfileOrigin::Env,
        index: 0,
    })?;
    let items = text.split(',').map(str::trim).filter(|s| !s.is_empty());
    for (index, item) in items.enumerate() {
        if index >= MAX_ACTIVE_PROFILES {
            return Err(ProfileArgError::LimitExceeded {
                limit: ProfileLimit::Count,
            });
        }
        add_name(&mut set, item, ProfileOrigin::Env, index)?;
    }
    Ok(ActiveProfiles(set))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn run(f: &[&str], env: Option<&str>) -> Result<Vec<String>, ProfileArgError> {
        let f: Vec<OsString> = f.iter().map(OsString::from).collect();
        let env = env.map(OsString::from);
        resolve_active_profiles(f.iter().map(OsString::as_os_str), env.as_deref())
            .map(|a| a.iter().map(str::to_owned).collect())
    }

    #[test]
    fn stack_10_multiple_profile_flags_build_set() {
        assert_eq!(run(&["dev", "debug"], None).unwrap(), ["debug", "dev"]);
    }

    #[test]
    fn stack_10_env_value_builds_set() {
        assert_eq!(run(&[], Some("dev, debug ,,")).unwrap(), ["debug", "dev"]);
    }

    #[test]
    fn stack_10_flags_override_env() {
        assert_eq!(run(&["a1"], Some("b1,c1")).unwrap(), ["a1"]);
    }

    #[test]
    fn stack_10_flags_ignore_invalid_env() {
        assert_eq!(run(&["a1"], Some("*,!")).unwrap(), ["a1"]);
    }

    #[test]
    fn stack_10_no_flag_no_env_is_empty() {
        assert!(run(&[], None).unwrap().is_empty());
        assert!(run(&[], Some("")).unwrap().is_empty());
        assert!(run(&[], Some(" , ,")).unwrap().is_empty());
    }

    #[test]
    fn stack_10_duplicates_are_deduplicated() {
        assert_eq!(run(&["dev", "dev"], None).unwrap(), ["dev"]);
        assert_eq!(run(&[], Some("dev,dev")).unwrap(), ["dev"]);
    }

    #[test]
    fn stack_10_rejects_invalid_names() {
        for bad in ["", "a,b", "*", "-dev", "dev!", "de v", "a", "_x"] {
            assert_eq!(
                run(&["ok1", bad], None),
                Err(ProfileArgError::InvalidName {
                    origin: ProfileOrigin::Flag,
                    index: 1
                }),
                "{bad:?}"
            );
        }
        assert_eq!(
            run(&[], Some("ok1, *")),
            Err(ProfileArgError::InvalidName {
                origin: ProfileOrigin::Env,
                index: 1
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn stack_10_rejects_non_utf8() {
        use std::os::unix::ffi::OsStrExt;
        let bad = OsStr::from_bytes(&[0xff, 0xfe]);
        assert_eq!(
            resolve_active_profiles([bad], None),
            Err(ProfileArgError::NotUtf8 {
                origin: ProfileOrigin::Flag,
                index: 0
            })
        );
        assert_eq!(
            resolve_active_profiles([], Some(bad)),
            Err(ProfileArgError::NotUtf8 {
                origin: ProfileOrigin::Env,
                index: 0
            })
        );
    }

    #[test]
    fn stack_10_limits_boundaries() {
        let ok = "a".repeat(MAX_PROFILE_NAME_BYTES);
        assert_eq!(run(&[&ok], None).unwrap(), [ok.as_str()]);
        let long = "a".repeat(MAX_PROFILE_NAME_BYTES + 1);
        assert_eq!(
            run(&[&long], None),
            Err(ProfileArgError::LimitExceeded {
                limit: ProfileLimit::NameBytes
            })
        );
        let names: Vec<String> = (0..=MAX_ACTIVE_PROFILES).map(|i| format!("p{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        assert_eq!(
            run(&refs[..MAX_ACTIVE_PROFILES], None).unwrap().len(),
            MAX_ACTIVE_PROFILES
        );
        assert_eq!(
            run(&refs, None),
            Err(ProfileArgError::LimitExceeded {
                limit: ProfileLimit::Count
            })
        );
        assert_eq!(
            run(&[], Some(&refs.join(","))),
            Err(ProfileArgError::LimitExceeded {
                limit: ProfileLimit::Count
            })
        );
        let big = " ".repeat(MAX_PROFILES_ENV_BYTES + 1);
        assert_eq!(
            run(&[], Some(&big)),
            Err(ProfileArgError::LimitExceeded {
                limit: ProfileLimit::EnvBytes
            })
        );
        let edge = " ".repeat(MAX_PROFILES_ENV_BYTES);
        assert!(run(&[], Some(&edge)).unwrap().is_empty());
    }

    #[test]
    fn stack_10_error_code_message_exit_code() {
        let e = [
            (
                ProfileArgError::NotUtf8 {
                    origin: ProfileOrigin::Flag,
                    index: 0,
                },
                "PROFILE_NOT_UTF8",
                "profile value is not valid UTF-8",
            ),
            (
                ProfileArgError::InvalidName {
                    origin: ProfileOrigin::Env,
                    index: 0,
                },
                "INVALID_PROFILE_NAME",
                "invalid profile name",
            ),
            (
                ProfileArgError::LimitExceeded {
                    limit: ProfileLimit::Count,
                },
                "PROFILE_LIMIT_EXCEEDED",
                "profile limit exceeded",
            ),
        ];
        for (err, code, msg) in e {
            assert_eq!(err.code(), code);
            assert_eq!(err.message(), msg);
            assert_eq!(err.exit_code().get(), 2);
        }
    }

    #[test]
    fn stack_10_display_does_not_echo_name() {
        let err = run(&["bad\u{1b}[31m!"], None).unwrap_err();
        assert_eq!(err.to_string(), "invalid profile name: --profile #0");
        let err = run(&[], Some("ok1,\u{202e}x")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid profile name: FANDHE_CONTAINER_PROFILES item #1"
        );
    }
}
