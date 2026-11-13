//! サービスの `env` を子の argv に載せず、非公開の env ファイル経由で `create` に渡す（STACK-8・SEC-1・#4734）。
//!
//! `Service.env` の値には資格情報が入りうる。`--env KEY=VALUE` で渡すと `/proc/<pid>/cmdline` から別 UID にも読めるため、
//! bundle の `env/` 配下（0700）へ 0600・`O_CREAT|O_EXCL|O_NOFOLLOW` で書いた一時ファイルを `--env-file` で渡す。
//! ファイルは [`InlineEnvGuard`] の Drop（成功・失敗・期限切れ・panic のいずれでも）で消す。
//!
//! `create` の `--env-file` 解析（`EnvFile::parse`）で表せない値（改行・CR・NUL・先頭が空白 / `#` / BOM のキー等）は
//! [`render_inline_env`] が `INVALID_ARGUMENT` にする（事前検査と書き出しの双方で同じ関数を使う）。
//! 優先順位は `ベース < env ファイル（指定順）< -e` なので、生成ファイルは `env_files` の末尾に置き、`env` が勝つ意味を保つ。

use std::collections::BTreeMap;
use std::path::PathBuf;

use fandhe_container_core::traits::ErrorCode;
use fandhe_container_oci::layer::extract::ExtractRoot;
use fandhe_container_stack::schema::Service;
use fandhe_container_supervisor::container_options::env::EnvFile;

use super::bundle::write_private;
use crate::error::CliError;

/// 生成する env ファイルの名前（bundle の `env/` 直下。利用者の `<n>.env` の複製とは重ならない）。
pub(super) const INLINE_ENV_NAME: &str = "inline.env";

fn unrepresentable() -> CliError {
    CliError::new(
        ErrorCode::InvalidArgument,
        "service env cannot be expressed as an env file (env)",
    )
}

/// `env` を `KEY=VALUE\n` の列に直す。`EnvFile::parse` と往復できない値は拒否する（値は文言に含めない）。
pub(super) fn render_inline_env(env: &BTreeMap<String, String>) -> Result<String, CliError> {
    let mut out = String::new();
    for (k, v) in env {
        let bad_key = k.is_empty()
            || k.contains(['=', '\0', '\n', '\r'])
            || k.starts_with(|c: char| c.is_whitespace() || c == '#' || c == '\u{feff}');
        if bad_key || v.contains(['\0', '\n', '\r']) {
            return Err(unrepresentable());
        }
        out.push_str(k);
        out.push('=');
        out.push_str(v);
        out.push('\n');
    }
    // 件数・長さの上限も `create` と同じ解析で確かめる。
    EnvFile::parse(&out).map_err(|e| CliError::new(e.code(), e.message()))?;
    Ok(out)
}

/// 子の `create` に渡す定義: `env` を空にし、あれば生成ファイルを `env_files` の末尾に足す。
pub(super) fn argv_spec(spec: &Service) -> Service {
    let mut s = spec.clone();
    if !s.env.is_empty() {
        s.env.clear();
        s.env_files.push(INLINE_ENV_NAME.to_owned());
    }
    s
}

/// 生成した env ファイルの所有者。Drop で消す。
#[derive(Debug)]
pub(super) struct InlineEnvGuard {
    env_dir: PathBuf,
}

impl Drop for InlineEnvGuard {
    fn drop(&mut self) {
        if let Ok(root) = ExtractRoot::open_existing_dir(&self.env_dir) {
            let _ = root.unlink_child_file(INLINE_ENV_NAME);
        }
    }
}

/// `env_dir` に生成ファイルを書く。`env` が空なら何も作らず `None`。
pub(super) fn write_inline_env(
    env_dir: &std::path::Path,
    env: &BTreeMap<String, String>,
) -> Result<Option<InlineEnvGuard>, CliError> {
    if env.is_empty() {
        return Ok(None);
    }
    let body = render_inline_env(env)?;
    let internal = || CliError::new(ErrorCode::Internal, "failed to prepare the service bundle");
    let root = ExtractRoot::open_existing_dir(env_dir).map_err(|_| internal())?;
    // 書き込み中に失敗しても残さないよう、作成の前にガードを持つ（不在の unlink は成功）。
    let guard = InlineEnvGuard {
        env_dir: env_dir.to_path_buf(),
    };
    write_private(&root, INLINE_ENV_NAME, body.as_bytes())?;
    Ok(Some(guard))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_supervisor::container_options::env::EnvSet;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    /// STACK-8・SEC-1: 生成した本文は `EnvFile::parse` と往復で一致する（値の前後の空白・`=`・`#` を含む）。
    #[test]
    fn stack8_sec1_inline_env_round_trips_through_env_file_parse() {
        let e = env(&[
            ("A", "plain"),
            ("B", " lead and trail "),
            ("C", "x=y#z"),
            ("D", ""),
        ]);
        let body = render_inline_env(&e).expect("render");
        let file = EnvFile::parse(&body).expect("parse");
        let got = EnvSet::resolve(&[], &[file], &[])
            .expect("resolve")
            .to_env_strings();
        let mut want: Vec<String> = e.iter().map(|(k, v)| format!("{k}={v}")).collect();
        want.sort();
        let mut got = got;
        got.sort();
        assert_eq!(got, want);
    }

    /// STACK-8・SEC-1: 表せない値は INVALID_ARGUMENT で、文言に値を含めない。
    #[test]
    fn stack8_sec1_inline_env_rejects_unrepresentable() {
        for (k, v) in [
            ("K", "a\nb"),
            ("K", "a\rb"),
            ("K", "a\0b"),
            ("", "v"),
            ("A=B", "v"),
            (" K", "v"),
            ("#K", "v"),
            ("\u{feff}K", "v"),
            ("K\nL", "v"),
        ] {
            let e = render_inline_env(&env(&[(k, v)])).expect_err("reject");
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{k:?}");
            assert!(!e.message().contains("a\nb"));
        }
    }

    /// STACK-8・SEC-1: 子の argv に env の値もキーも `--env` も載らず、`--env-file` だけが付く。
    #[test]
    fn stack8_sec1_argv_never_carries_env_values() {
        use fandhe_container_stack::cli::up::{
            CreateArgvContext, ProjectName, ServiceContainerId, create_argv,
        };
        let spec = Service {
            image: Some("x".to_owned()),
            env: env(&[("TOKEN", "s3cr3t-value")]),
            ..Service::default()
        };
        let id =
            ServiceContainerId::derive(&ProjectName::new("p").expect("project"), "s").expect("id");
        let ctx = CreateArgvContext {
            id: &id,
            project_dir: std::path::Path::new("/b/env"),
            bundle: std::path::Path::new("/b"),
            image_root: std::path::Path::new("/i"),
            unpack: true,
        };
        let argv = create_argv(&argv_spec(&spec), None, &ctx).expect("argv");
        let joined: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            joined
                .iter()
                .all(|a| !a.contains("s3cr3t") && !a.contains("TOKEN"))
        );
        assert!(!joined.iter().any(|a| a == "--env"));
        let i = joined
            .iter()
            .position(|a| a == "--env-file")
            .expect("env-file");
        assert_eq!(
            joined.get(i + 1).map(String::as_str),
            Some("/b/env/inline.env")
        );
    }

    /// SEC-1: 0600 で作り、Drop で消える。既存があれば排他作成で失敗する。
    #[test]
    fn sec1_inline_env_file_is_private_and_removed_on_drop() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("fc-inline-env-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let e = env(&[("K", "v")]);
        let g = write_inline_env(&dir, &e).expect("write").expect("some");
        let p = dir.join(INLINE_ENV_NAME);
        let mode = std::fs::metadata(&p).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read_to_string(&p).expect("read"), "K=v\n");
        assert!(write_inline_env(&dir, &e).is_err(), "O_EXCL");
        drop(g);
        // 2 回目の失敗側のガードも既に Drop 済みなので、ファイルは残らない。
        assert!(!p.exists());
        assert!(
            write_inline_env(&dir, &BTreeMap::new())
                .expect("empty")
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
