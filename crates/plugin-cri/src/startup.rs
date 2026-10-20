//! 起動引数の解析（TASK-114.1・#457・TASK-114.3.1・#849・PLUG-1）。
//!
//! 呼び出し元は `main.rs` のみ。argv は外部入力として扱い、件数と合計バイト数を
//! `ONE_SHOT_ARGS_MAX_*`（plugin 境界機構と同じ上限）で検証してから解釈する。
//! 診断は固定文言のみで、引数の値は含めない。
//! 受ける形は `--help`（単独）・`--socket <PATH>`・`--socket=<PATH>`。socket パスは絶対パスで `..` を含まないこと
//! だけをここで検証し、配置ディレクトリの所有者・0700・symlink・`sun_path` 長は bind 側（`UdsListener::bind`）に任せる。
//! 既定の socket パスの解決は未定義（spec に定めが無い。#459・#1869 で決める）ため、引数なしは成功を装わず失敗させる（REPAIR-3）。

use std::ffi::OsString;
use std::path::{Component, PathBuf};

use fandhe_container_plugin::{
    ONE_SHOT_ARGS_MAX_BYTES, ONE_SHOT_ARGS_MAX_COUNT, PluginError, PluginErrorCode,
};

/// 未知の引数・`--help` の誤用に対する固定文言。
pub const MSG_UNEXPECTED_ARGUMENT: &str = "unexpected argument";
/// 件数・バイト数の上限超過に対する固定文言。
pub const MSG_ARGS_TOO_LARGE: &str = "too many or too long arguments";
/// `--socket` の値の欠落・重複・不正なパスに対する固定文言。
pub const MSG_INVALID_SOCKET: &str = "invalid --socket argument";
/// 既定の socket パスが未定義であることを伝える固定文言（成功終了で実装済みを装わない。REPAIR-3）。
pub const MSG_SOCKET_DEFAULT_UNDEFINED: &str =
    "default socket path is not defined yet; pass --socket <PATH>";

/// 解析結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Invocation {
    /// `--help`: usage を出して終了する。
    Help,
    /// 引数なし: 既定の socket が未定義のため起動できない（`main.rs` が `UNIMPLEMENTED` にする）。
    Run,
    /// `--socket <PATH>`: 指定の UDS で RuntimeService をサーブする（`server::serve`）。
    Serve {
        /// 検証済み（絶対パス・`..` なし・NUL なし）の socket パス。
        socket: PathBuf,
    },
}

/// usage（末尾改行つき 1 行）。
pub fn usage() -> &'static str {
    "usage: fandhe-container-plugin-cri [--help] | --socket <PATH>\n"
}

fn invalid(msg: &'static str) -> PluginError {
    PluginError::new(PluginErrorCode::InvalidArgument, msg)
}

/// socket パスを検証する（空でない・NUL なし・絶対・`..` なし）。
fn validate_socket(value: OsString) -> Result<PathBuf, PluginError> {
    #[cfg(unix)]
    let has_nul = {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().contains(&0)
    };
    #[cfg(not(unix))]
    let has_nul = value.to_string_lossy().contains('\0');
    let path = PathBuf::from(value);
    if path.as_os_str().is_empty()
        || has_nul
        || !path.is_absolute()
        || path.components().any(|c| matches!(c, Component::ParentDir))
    {
        return Err(invalid(MSG_INVALID_SOCKET));
    }
    Ok(path)
}

/// 引数（`argv[0]` を除く）を解析する。
///
/// `--help` がちょうど 1 個だけなら `Help`、引数なしなら `Run`、`--socket` がちょうど 1 回なら `Serve`、
/// それ以外は `InvalidArgument`。
pub fn parse_args<I: IntoIterator<Item = OsString>>(args: I) -> Result<Invocation, PluginError> {
    let mut count = 0usize;
    let mut bytes = 0usize;
    let mut all = Vec::new();
    for a in args {
        count = count.saturating_add(1);
        bytes = bytes.saturating_add(a.len());
        if count > ONE_SHOT_ARGS_MAX_COUNT || bytes > ONE_SHOT_ARGS_MAX_BYTES {
            return Err(invalid(MSG_ARGS_TOO_LARGE));
        }
        all.push(a);
    }
    let mut help = false;
    let mut other = false;
    let mut socket: Option<PathBuf> = None;
    let mut socket_error = false;
    let mut iter = all.into_iter();
    while let Some(a) = iter.next() {
        if a == "--help" && !help {
            help = true;
            continue;
        }
        let value = if a == "--socket" {
            // 値の欠落は不正（None のまま下で socket_error になる）。
            iter.next()
        } else if let Some(v) = a.to_str().and_then(|s| s.strip_prefix("--socket=")) {
            Some(OsString::from(v))
        } else {
            other = true;
            continue;
        };
        if socket.is_some() || socket_error {
            socket_error = true;
            continue;
        }
        match value.map(validate_socket) {
            Some(Ok(p)) => socket = Some(p),
            _ => socket_error = true,
        }
    }
    if other || (help && (socket.is_some() || socket_error)) {
        return Err(invalid(MSG_UNEXPECTED_ARGUMENT));
    }
    if socket_error {
        return Err(invalid(MSG_INVALID_SOCKET));
    }
    Ok(match (help, socket) {
        (true, _) => Invocation::Help,
        (false, Some(socket)) => Invocation::Serve { socket },
        (false, None) => Invocation::Run,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(a: &[&str]) -> Result<Invocation, PluginError> {
        parse_args(a.iter().map(OsString::from))
    }

    fn msg(r: Result<Invocation, PluginError>) -> (PluginErrorCode, String) {
        let e = r.expect_err("must fail");
        (e.code(), e.message().to_string())
    }

    /// PLUG-1: 引数なしは Run。
    #[test]
    fn no_args_is_run() {
        assert_eq!(p(&[]).expect("ok"), Invocation::Run);
    }

    #[test]
    fn help_alone_is_help() {
        assert_eq!(p(&["--help"]).expect("ok"), Invocation::Help);
    }

    #[test]
    fn unexpected_arguments_are_rejected() {
        for a in [
            &["--help", "--help"][..],
            &["--foo"],
            &["positional"],
            &["--help", "x"],
            &["x", "--help"],
        ] {
            assert_eq!(
                msg(p(a)),
                (
                    PluginErrorCode::InvalidArgument,
                    MSG_UNEXPECTED_ARGUMENT.to_string()
                ),
                "args: {a:?}"
            );
        }
    }

    #[test]
    fn too_many_args_are_rejected() {
        let v = vec![OsString::from("a"); ONE_SHOT_ARGS_MAX_COUNT + 1];
        assert_eq!(
            msg(parse_args(v)),
            (
                PluginErrorCode::InvalidArgument,
                MSG_ARGS_TOO_LARGE.to_string()
            )
        );
    }

    #[test]
    fn too_long_arg_is_rejected() {
        let v = vec![OsString::from("a".repeat(ONE_SHOT_ARGS_MAX_BYTES + 1))];
        assert_eq!(
            msg(parse_args(v)),
            (
                PluginErrorCode::InvalidArgument,
                MSG_ARGS_TOO_LARGE.to_string()
            )
        );
    }

    #[test]
    fn usage_is_fixed() {
        assert_eq!(
            usage(),
            "usage: fandhe-container-plugin-cri [--help] | --socket <PATH>\n"
        );
    }

    /// PLUG-1: `--socket` は 2 つの形で受ける。
    #[test]
    #[cfg(unix)]
    fn socket_both_forms_serve() {
        let want = Invocation::Serve {
            socket: PathBuf::from("/run/x/s.sock"),
        };
        assert_eq!(p(&["--socket", "/run/x/s.sock"]).expect("ok"), want);
        assert_eq!(p(&["--socket=/run/x/s.sock"]).expect("ok"), want);
    }

    #[test]
    fn invalid_socket_values_are_rejected_without_echo() {
        for a in [
            &["--socket"][..],
            &["--socket="],
            &["--socket", ""],
            &["--socket", "rel/s.sock"],
            &["--socket=/a/../b.sock"],
            &["--socket", "/a/s.sock", "--socket", "/b/s.sock"],
            &["--socket", "/a/s.sock", "--socket=/b/s.sock"],
        ] {
            assert_eq!(
                msg(p(a)),
                (
                    PluginErrorCode::InvalidArgument,
                    MSG_INVALID_SOCKET.to_string()
                ),
                "args: {a:?}"
            );
        }
    }

    #[test]
    fn help_with_socket_is_rejected() {
        for a in [
            &["--help", "--socket", "/a/s"][..],
            &["--socket=/a/s", "--help"],
        ] {
            assert_eq!(
                msg(p(a)),
                (
                    PluginErrorCode::InvalidArgument,
                    MSG_UNEXPECTED_ARGUMENT.to_string()
                ),
                "args: {a:?}"
            );
        }
    }
}
