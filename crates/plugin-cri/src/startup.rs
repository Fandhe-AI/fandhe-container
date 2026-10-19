//! 起動引数の解析（TASK-114.1・#457・PLUG-1）。
//!
//! 呼び出し元は `main.rs` のみ。argv は外部入力として扱い、件数と合計バイト数を
//! `ONE_SHOT_ARGS_MAX_*`（plugin 境界機構と同じ上限）で検証してから解釈する。
//! 診断は固定文言のみで、引数の値は含めない。
//! 将来 `--socket` などの引数を足す場所は TASK-114.3（#459）。それまで受けるのは `--help` だけ。

use std::ffi::OsString;

use fandhe_container_plugin::{
    ONE_SHOT_ARGS_MAX_BYTES, ONE_SHOT_ARGS_MAX_COUNT, PluginError, PluginErrorCode,
};

/// 未知の引数・`--help` の誤用に対する固定文言。
pub const MSG_UNEXPECTED_ARGUMENT: &str = "unexpected argument";
/// 件数・バイト数の上限超過に対する固定文言。
pub const MSG_ARGS_TOO_LARGE: &str = "too many or too long arguments";
/// サーバー未実装を伝える固定文言（成功終了で実装済みを装わない。REPAIR-3）。
pub const MSG_NOT_IMPLEMENTED: &str = "cri plugin server is not implemented yet";

/// 解析結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Invocation {
    /// `--help`: usage を出して終了する。
    Help,
    /// 引数なし: サーバーとして起動する（現状は未実装）。
    Run,
}

/// usage（末尾改行つき 1 行）。
pub fn usage() -> &'static str {
    "usage: fandhe-container-plugin-cri [--help]\n"
}

/// 引数（`argv[0]` を除く）を解析する。
///
/// `--help` がちょうど 1 個だけなら `Help`、引数なしなら `Run`、それ以外は `InvalidArgument`。
pub fn parse_args<I: IntoIterator<Item = OsString>>(args: I) -> Result<Invocation, PluginError> {
    let mut count = 0usize;
    let mut bytes = 0usize;
    let mut help = false;
    let mut other = false;
    for a in args {
        count = count.saturating_add(1);
        bytes = bytes.saturating_add(a.len());
        if count > ONE_SHOT_ARGS_MAX_COUNT || bytes > ONE_SHOT_ARGS_MAX_BYTES {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                MSG_ARGS_TOO_LARGE,
            ));
        }
        if a == "--help" && !help {
            help = true;
        } else {
            other = true;
        }
    }
    if other {
        return Err(PluginError::new(
            PluginErrorCode::InvalidArgument,
            MSG_UNEXPECTED_ARGUMENT,
        ));
    }
    Ok(if help {
        Invocation::Help
    } else {
        Invocation::Run
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
        assert_eq!(usage(), "usage: fandhe-container-plugin-cri [--help]\n");
    }
}
