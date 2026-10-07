//! `create` / `start` の argv 解析（TASK-79.2.1・CLI-1・MS-6）。
//!
//! `commands::run` が先頭のグローバルオプション（`--root`）とサブコマンド名の後ろを渡して呼ぶ純粋関数群。
//! ファイルシステムにも環境にも触れず、値の意味検証（絶対パス・ID の文字種）は core の型
//! （`ContainerId`・`CreateRequest`・`StateRoot`）に委ねる（検査の二重実装を避ける。SEC-1）。
//! 構文は runc 互換: `fandhe-container [--root <dir>] create --bundle <dir> <id>` / `... start <id>`。
//! 解析失敗の理由は呼び出し元で固定文言に落とし、引数値を出力へ埋め込まない（インジェクション回避）。

use std::ffi::OsString;
use std::path::PathBuf;

/// グローバルオプション（サブコマンドより前）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct GlobalArgs {
    /// `--root`（状態ルートの上書き）。未指定は core の既定解決。
    pub(super) root: Option<PathBuf>,
}

/// `create` の引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CreateArgs {
    pub(super) bundle: PathBuf,
    pub(super) id: String,
}

/// `start` の引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StartArgs {
    pub(super) id: String,
}

/// 解析失敗（使い方エラー）。理由は呼び出し元で固定文言に写す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UsageError;

/// 先頭のグローバルオプションを読み、残り（サブコマンド名以降）を返す。
///
/// 現状のグローバルオプションは `--root <dir>` のみ。重複・値欠落は使い方エラー。
pub(super) fn parse_global(args: Vec<OsString>) -> Result<(GlobalArgs, Vec<OsString>), UsageError> {
    let mut global = GlobalArgs::default();
    let mut it = args.into_iter().peekable();
    while it.peek().is_some_and(|a| a == "--root") {
        it.next();
        let value = it.next().ok_or(UsageError)?;
        if global.root.is_some() {
            return Err(UsageError);
        }
        global.root = Some(PathBuf::from(value));
    }
    Ok((global, it.collect()))
}

/// `create --bundle <dir> <id>` を解析する（`--bundle` は必須・順不同・`--` 以降は位置引数）。
pub(super) fn parse_create(args: Vec<OsString>) -> Result<CreateArgs, UsageError> {
    let mut bundle: Option<PathBuf> = None;
    let mut positional: Vec<OsString> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--" {
            positional.extend(it.by_ref());
            break;
        } else if a == "--bundle" {
            let value = it.next().ok_or(UsageError)?;
            if bundle.is_some() {
                return Err(UsageError);
            }
            bundle = Some(PathBuf::from(value));
        } else if is_option_like(&a) {
            return Err(UsageError);
        } else {
            positional.push(a);
        }
    }
    let id = single_id(positional)?;
    Ok(CreateArgs {
        bundle: bundle.ok_or(UsageError)?,
        id,
    })
}

/// `start <id>` を解析する。
pub(super) fn parse_start(args: Vec<OsString>) -> Result<StartArgs, UsageError> {
    let mut positional: Vec<OsString> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--" {
            positional.extend(it.by_ref());
            break;
        } else if is_option_like(&a) {
            return Err(UsageError);
        } else {
            positional.push(a);
        }
    }
    Ok(StartArgs {
        id: single_id(positional)?,
    })
}

/// `-` で始まる UTF-8 引数はオプションとして扱う（未知オプションを ID と取り違えない）。
/// 非 UTF-8 は位置引数として残り、`single_id` で拒否される。
fn is_option_like(a: &OsString) -> bool {
    a.to_str().is_some_and(|s| s.starts_with('-'))
}

/// 位置引数がちょうど 1 個の UTF-8 文字列であることを確かめる。
fn single_id(mut positional: Vec<OsString>) -> Result<String, UsageError> {
    if positional.len() != 1 {
        return Err(UsageError);
    }
    positional
        .pop()
        .and_then(|v| v.into_string().ok())
        .ok_or(UsageError)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<OsString> {
        a.iter().map(OsString::from).collect()
    }

    /// CLI-1: グローバル `--root` は先頭のみ読み、残りを返す。
    #[test]
    fn cli1_parse_global_root() {
        let (g, rest) = parse_global(v(&["--root", "/r", "start", "a"])).expect("ok");
        assert_eq!(g.root, Some(PathBuf::from("/r")));
        assert_eq!(rest, v(&["start", "a"]));
        let (g, rest) = parse_global(v(&["start"])).expect("ok");
        assert_eq!(g.root, None);
        assert_eq!(rest, v(&["start"]));
    }

    /// CLI-1: `--root` の値欠落・重複は使い方エラー。
    #[test]
    fn cli1_parse_global_rejects_missing_and_duplicate() {
        assert_eq!(parse_global(v(&["--root"])), Err(UsageError));
        assert_eq!(
            parse_global(v(&["--root", "/a", "--root", "/b", "start"])),
            Err(UsageError)
        );
    }

    /// CLI-1: create の正常系（順不同・`--` 以降は位置引数）。
    #[test]
    fn cli1_parse_create_ok() {
        let expect = CreateArgs {
            bundle: PathBuf::from("/b"),
            id: "c1".into(),
        };
        assert_eq!(
            parse_create(v(&["--bundle", "/b", "c1"])),
            Ok(expect.clone())
        );
        assert_eq!(
            parse_create(v(&["c1", "--bundle", "/b"])),
            Ok(expect.clone())
        );
        assert_eq!(parse_create(v(&["--bundle", "/b", "--", "c1"])), Ok(expect));
        assert_eq!(
            parse_create(v(&["--bundle", "/b", "--", "-x"])).map(|a| a.id),
            Ok("-x".to_string())
        );
    }

    /// CLI-1: create の異常系（bundle 欠落・値欠落・重複・未知オプション・位置引数の過不足）。
    #[test]
    fn cli1_parse_create_rejects_invalid() {
        for a in [
            v(&["c1"]),
            v(&["--bundle"]),
            v(&["--bundle", "/b"]),
            v(&["--bundle", "/a", "--bundle", "/b", "c1"]),
            v(&["--bundle", "/b", "--unknown", "c1"]),
            v(&["--bundle", "/b", "c1", "c2"]),
            v(&[]),
        ] {
            assert_eq!(parse_create(a), Err(UsageError));
        }
    }

    /// CLI-1: start の正常系と異常系。
    #[test]
    fn cli1_parse_start() {
        assert_eq!(parse_start(v(&["c1"])), Ok(StartArgs { id: "c1".into() }));
        assert_eq!(
            parse_start(v(&["--", "-c"])),
            Ok(StartArgs { id: "-c".into() })
        );
        for a in [v(&[]), v(&["a", "b"]), v(&["--all", "a"]), v(&["-a"])] {
            assert_eq!(parse_start(a), Err(UsageError));
        }
    }

    /// CLI-1: 非 UTF-8 の ID は使い方エラー。
    #[cfg(unix)]
    #[test]
    fn cli1_parse_start_rejects_non_utf8_id() {
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(
            parse_start(vec![OsString::from_vec(vec![0x66, 0xff])]),
            Err(UsageError)
        );
    }
}
