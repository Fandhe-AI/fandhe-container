//! 統一 CLI の基本コマンド（create / start / stop / delete / list / logs）の入口（TASK-79.1・CLI-1）。
//!
//! `main.rs`（bin `fandhe-container`）から [`run`] が呼ばれ、argv の先頭をコマンド名として判定する。
//! 各コマンド本体は未実装で、既知のコマンドも `UNIMPLEMENTED` を返して非ゼロ終了する（実装済みを装わない。REPAIR-3）。
//!
//! 将来仕様（本骨格の範囲外）:
//! - create / start: TASK-79.2.1（#866）。Linux は core を直接呼ぶ。
//! - stop / delete: TASK-79.2.2（#867）。
//! - list / logs: TASK-79.3（#640）。
//! - macOS / Windows は plugin 発見機構経由で呼び、platform-* へは直接依存しない: TASK-79.4（#641・PLUG-4）。
//! - エラー形式（`code` / `message`）の確定: TASK-95（ERR 系）。ここの [`CliExit`] は最小の先取り。

use std::ffi::OsString;

/// 基本コマンド（CLI-1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Create,
    Start,
    Stop,
    Delete,
    List,
    Logs,
}

impl Command {
    /// 全基本コマンド（コマンド名の列挙順の SSOT）。
    pub const ALL: [Command; 6] = [
        Command::Create,
        Command::Start,
        Command::Stop,
        Command::Delete,
        Command::List,
        Command::Logs,
    ];

    /// CLI 上のコマンド名。
    pub fn as_str(self) -> &'static str {
        match self {
            Command::Create => "create",
            Command::Start => "start",
            Command::Stop => "stop",
            Command::Delete => "delete",
            Command::List => "list",
            Command::Logs => "logs",
        }
    }

    /// コマンド名から判定する（完全一致・大文字小文字を区別）。未知は `None`。
    pub fn parse(name: &str) -> Option<Command> {
        Command::ALL.into_iter().find(|c| c.as_str() == name)
    }
}

/// 使い方エラーの終了コード。
pub const EXIT_USAGE: u8 = 2;
/// 未実装コマンドの終了コード。
pub const EXIT_UNIMPLEMENTED: u8 = 3;

/// [`run`] の結果。終了コードと機械可読なエラー（`code` / `message`。固定の英語文言のみ）を持つ。
#[derive(Debug, Clone, PartialEq, Eq)]
///
/// フィールドは非公開で、この module 内の固定文言からのみ構築できる。
/// そのため [`CliExit::to_json_line`] はエスケープなしで常に妥当な JSON を返す。
pub struct CliExit {
    exit_code: u8,
    code: &'static str,
    message: &'static str,
}

impl CliExit {
    /// プロセスの終了コード。
    pub fn exit_code(&self) -> u8 {
        self.exit_code
    }

    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// 英語の固定メッセージ。
    pub fn message(&self) -> &'static str {
        self.message
    }

    /// stderr へ出す 1 行 JSON。値は固定文言のみ（構築経路が module 内に限られる）でエスケープ不要。
    pub fn to_json_line(&self) -> String {
        format!(
            "{{\"code\":\"{}\",\"message\":\"{}\"}}",
            self.code, self.message
        )
    }
}

/// argv（プログラム名を除く）を解釈して実行する。現時点では常に失敗を返す（本体は未実装）。
///
/// 引数値は出力へ埋め込まない（インジェクション回避）。
pub fn run<I: IntoIterator<Item = OsString>>(args: I) -> CliExit {
    let usage = CliExit {
        exit_code: EXIT_USAGE,
        code: "INVALID_ARGUMENT",
        message: "usage: fandhe-container <create|start|stop|delete|list|logs>",
    };
    let mut it = args.into_iter();
    let Some(first) = it.next() else {
        return usage;
    };
    let Some(name) = first.to_str() else {
        return usage;
    };
    match Command::parse(name) {
        Some(_) => CliExit {
            exit_code: EXIT_UNIMPLEMENTED,
            code: "UNIMPLEMENTED",
            message: "command is not implemented yet",
        },
        None => usage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    /// CLI-1: 6 コマンド名が列挙値に対応する。
    #[test]
    fn cli1_parse_known_commands() {
        assert_eq!(Command::parse("create"), Some(Command::Create));
        assert_eq!(Command::parse("start"), Some(Command::Start));
        assert_eq!(Command::parse("stop"), Some(Command::Stop));
        assert_eq!(Command::parse("delete"), Some(Command::Delete));
        assert_eq!(Command::parse("list"), Some(Command::List));
        assert_eq!(Command::parse("logs"), Some(Command::Logs));
    }

    /// CLI-1: 全コマンド名の並び。
    #[test]
    fn cli1_all_names_order() {
        let names: Vec<&str> = Command::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names, ["create", "start", "stop", "delete", "list", "logs"]);
    }

    /// CLI-1: 未知名・大文字小文字違い・空は None。
    #[test]
    fn cli1_parse_unknown() {
        assert_eq!(Command::parse("run"), None);
        assert_eq!(Command::parse("Create"), None);
        assert_eq!(Command::parse(""), None);
    }

    /// CLI-1: 引数なし・未知コマンドは使い方エラー。
    #[test]
    fn cli1_run_usage_errors() {
        for a in [args(&[]), args(&["run"]), args(&[""])] {
            let r = run(a);
            assert_eq!(r.exit_code(), 2);
            assert_eq!(r.code(), "INVALID_ARGUMENT");
        }
    }

    /// CLI-1: 既知コマンドは未実装として非ゼロ終了。
    #[test]
    fn cli1_run_known_is_unimplemented() {
        for c in Command::ALL {
            let r = run(args(&[c.as_str()]));
            assert_eq!(r.exit_code(), 3);
            assert_eq!(r.code(), "UNIMPLEMENTED");
        }
    }

    /// 出力は固定文言の 1 行 JSON。
    #[test]
    fn json_line_is_fixed() {
        let r = run(args(&["create"]));
        assert_eq!(
            r.to_json_line(),
            "{\"code\":\"UNIMPLEMENTED\",\"message\":\"command is not implemented yet\"}"
        );
    }
}
