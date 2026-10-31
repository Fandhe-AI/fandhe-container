//! compose の `command` / `entrypoint` の文字列形（short syntax）を引数配列へ分割する（STACK-3・TASK-151.3.1・MS-12）。
//!
//! 呼び出し元は [`crate::convert`] の command / entrypoint 変換。分割できない入力は部分的に出さず
//! [`ShellSplitError`] を返し、呼び出し側が `value_drops` へ記録する（fail-closed）。
//!
//! 判断（#597・TASK-151.hdep2 のオーナー判断 2026-10-10）: shlex は採らず、compose-go が使う
//! go-shellwords v1.0.12 の `Parse`（ParseEnv・ParseBacktick は無効）と同じ規則を自作する。
//! go-shellwords（MIT）のコードは写さず、挙動の仕様とテストベクタで合わせている（帰属表示を要さない形）。
//! shlex との違いは `&&` 等の演算子の扱い、ダブルクォート内の `\`、`#` がコメントでないこと、`\r` が区切りなこと。
//!
//! 規則: 区切りは引用外の空白・タブ・CR・LF。`\` は（シングルクォート外で）次の 1 文字をそのまま取る。
//! シングルクォート内は何も解釈しない。引用外の `;&|<>`・`$(`・バッククォート・括弧、閉じていない引用符、
//! NUL は失敗にする。括弧 `)` は compose と扱いが違いうるため記録する側へ倒している。

/// 語の数の上限。入力長の上限は前段で効いているが、語の数でも確保を抑える（DoS 対策）。
pub const MAX_SHELL_ARGS: usize = 4096;

/// 分割できなかった理由。入力の断片は持たない（値に資格情報が入りうるため）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShellSplitError {
    /// 閉じていない引用符。
    UnclosedQuote,
    /// 末尾に `\` だけが残った。
    TrailingBackslash,
    /// 引用外の `;` `&` `|` `<` `>`。
    ShellOperator,
    /// 引用外の `$(` またはバッククォート。
    CommandSubstitution,
    /// 引用外の括弧。
    UnquotedParen,
    /// NUL を含む（argv に渡せない）。
    NulByte,
    /// 語が無い（空・空白だけ・空の引用だけ）。
    Empty,
    /// 語の数が [`MAX_SHELL_ARGS`] を超えた。
    TooManyArgs,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    Single,
    Double,
}

/// 文字列を引数配列へ分割する。入力長に比例する 1 回の走査で、再帰しない。
pub fn split_command(input: &str) -> Result<Vec<String>, ShellSplitError> {
    if input.contains('\0') {
        return Err(ShellSplitError::NulByte);
    }
    let mut args: Vec<String> = Vec::new();
    let mut cur = String::new();
    // 引用で囲った空の語も 1 語として数えるための印。
    let mut in_word = false;
    let mut quote = Quote::None;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match quote {
            Quote::Single => {
                if c == '\'' {
                    quote = Quote::None;
                } else {
                    cur.push(c);
                }
            }
            Quote::Double => match c {
                '"' => quote = Quote::None,
                '\\' => match chars.next() {
                    Some(n) => cur.push(n),
                    None => return Err(ShellSplitError::TrailingBackslash),
                },
                _ => cur.push(c),
            },
            Quote::None => match c {
                ' ' | '\t' | '\r' | '\n' => {
                    if in_word {
                        push_arg(&mut args, std::mem::take(&mut cur))?;
                        in_word = false;
                    }
                }
                '\\' => match chars.next() {
                    Some(n) => {
                        cur.push(n);
                        in_word = true;
                    }
                    None => return Err(ShellSplitError::TrailingBackslash),
                },
                '\'' => {
                    quote = Quote::Single;
                    in_word = true;
                }
                '"' => {
                    quote = Quote::Double;
                    in_word = true;
                }
                ';' | '&' | '|' | '<' | '>' => return Err(ShellSplitError::ShellOperator),
                '`' => return Err(ShellSplitError::CommandSubstitution),
                '$' if chars.peek() == Some(&'(') => {
                    return Err(ShellSplitError::CommandSubstitution);
                }
                '(' | ')' => return Err(ShellSplitError::UnquotedParen),
                _ => {
                    cur.push(c);
                    in_word = true;
                }
            },
        }
    }
    if quote != Quote::None {
        return Err(ShellSplitError::UnclosedQuote);
    }
    if in_word {
        push_arg(&mut args, cur)?;
    }
    match args.as_slice() {
        [] => Err(ShellSplitError::Empty),
        [only] if only.is_empty() => Err(ShellSplitError::Empty),
        _ => Ok(args),
    }
}

fn push_arg(args: &mut Vec<String>, arg: String) -> Result<(), ShellSplitError> {
    if args.len() >= MAX_SHELL_ARGS {
        return Err(ShellSplitError::TooManyArgs);
    }
    args.push(arg);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> Vec<String> {
        split_command(s).unwrap()
    }

    /// STACK-3: 基本の分割。
    #[test]
    fn stack3_split_basic() {
        assert_eq!(ok("npm run dev"), ["npm", "run", "dev"]);
        assert_eq!(ok("a\tb\r\nc"), ["a", "b", "c"]);
        assert_eq!(ok("  a   b  "), ["a", "b"]);
        assert_eq!(ok("日本語 テスト"), ["日本語", "テスト"]);
    }

    /// STACK-3: #597 の照合ベクタ。
    #[test]
    fn stack3_split_597_vectors() {
        assert_eq!(
            split_command("echo a && echo b"),
            Err(ShellSplitError::ShellOperator)
        );
        assert_eq!(ok(r#""a\b""#), ["ab"]);
        assert_eq!(ok("foo #bar"), ["foo", "#bar"]);
    }

    /// STACK-3: 引用とエスケープ。
    #[test]
    fn stack3_split_quotes_and_escapes() {
        assert_eq!(ok(r"a\ b"), ["a b"]);
        assert_eq!(ok(r"'a\b'"), [r"a\b"]);
        assert_eq!(ok(r#"a """#), ["a", ""]);
        assert_eq!(ok(r#"'a'b"c""#), ["abc"]);
        assert_eq!(ok("echo $HOME"), ["echo", "$HOME"]);
        assert_eq!(ok(r#""$(id)""#), ["$(id)"]);
        assert_eq!(ok("'a|b'"), ["a|b"]);
        assert_eq!(ok(r"a\|b"), ["a|b"]);
        assert_eq!(
            ok(r#"sh -c 'echo "hi there"'"#),
            ["sh", "-c", "echo \"hi there\""]
        );
    }

    /// STACK-3: 失敗にする入力。
    #[test]
    fn stack3_split_rejects() {
        for s in ["a;b", "a|b", "a<b", "a>b", "a&b"] {
            assert_eq!(split_command(s), Err(ShellSplitError::ShellOperator), "{s}");
        }
        assert_eq!(
            split_command("echo $(id)"),
            Err(ShellSplitError::CommandSubstitution)
        );
        assert_eq!(
            split_command("echo `id`"),
            Err(ShellSplitError::CommandSubstitution)
        );
        assert_eq!(split_command("(a)"), Err(ShellSplitError::UnquotedParen));
        assert_eq!(split_command("\"abc"), Err(ShellSplitError::UnclosedQuote));
        assert_eq!(split_command("'abc"), Err(ShellSplitError::UnclosedQuote));
        assert_eq!(
            split_command("abc\\"),
            Err(ShellSplitError::TrailingBackslash)
        );
        assert_eq!(split_command("x\0y"), Err(ShellSplitError::NulByte));
        assert_eq!(split_command(""), Err(ShellSplitError::Empty));
        assert_eq!(split_command("   "), Err(ShellSplitError::Empty));
        assert_eq!(split_command("\"\""), Err(ShellSplitError::Empty));
    }

    /// STACK-3: 語の数の上限境界。
    #[test]
    fn stack3_split_arg_limit() {
        let at = vec!["a"; MAX_SHELL_ARGS].join(" ");
        assert_eq!(ok(&at).len(), MAX_SHELL_ARGS);
        let over = vec!["a"; MAX_SHELL_ARGS + 1].join(" ");
        assert_eq!(split_command(&over), Err(ShellSplitError::TooManyArgs));
    }
}
