//! 統一 CLI の基本コマンド（create / start / stop / delete / list / logs）の入口（TASK-79.1・TASK-79.2.1・TASK-79.2.2・CLI-1・MS-6）。
//!
//! `main.rs`（bin `fandhe-container`）から [`run`] が呼ばれ、argv の先頭（グローバル `--root` の後）をコマンド名として判定する。
//! `create` / `start` は core の `oci_runtime::create` / `start` を直接呼ぶ（TASK-79.2.1・#866。`create_start` module）。
//! ただし本番の `ProcessLauncher` が未提供のため、`start` は `UNIMPLEMENTED`（終了コード 8）で失敗する（REPAIR-3）。
//! `stop` / `delete` は core の `oci_runtime::kill`（SIGTERM）/ `delete` を直接呼ぶ（TASK-79.2.2・#867。`stop_delete` module）。
//! 本番の `ProcessSignaler`・cgroup remover が未提供のため、pid ありの対象への `stop` や cgroup 配置つきの `delete` は
//! `UNIMPLEMENTED`（8）で失敗する（REPAIR-3）。
//! `list` は core の状態ストアを読んで stdout へタブ区切りで一覧を出し、`logs` は引数・ID・存在確認までを行う
//! （TASK-79.3・#640。`list_logs` module）。ログ内容の読み出しは未実装で、対象が存在しても `UNIMPLEMENTED`（8）で
//! 失敗する（REPAIR-3）。
//! 終了コードは core の ERR-2 表（`OCI_EXIT_*`）に揃える。
//!
//! 将来仕様（本実装の範囲外）:
//! - start の実プロセス起動: supervisor 経由の launcher（TASK-157・TASK-37〜39）。
//! - stop の猶予 → SIGKILL・本番 signaler / cgroup remover の結線: supervisor 経由（TASK-157）。
//! - logs の内容読み出し・list の JSON 出力: ログ契約と crate 境界の決定後（`list_logs` module の doc 参照。TASK-95・TASK-98）。
//! - macOS / Windows は plugin 発見機構経由（TASK-79.4・#641・PLUG-4。`plugin_backend` module）。発見 → 登録 → 信頼性検証までを
//!   配線済みで、platform-* へは直接依存しない（`make check-cli-backend-deps`）。非 Linux の信頼性検証（PLUG-11）・plugin の
//!   起動と RPC（TASK-114・TASK-125）は未実装のため、非 Linux の全コマンドは候補なしで `FAILED_PRECONDITION`（5）、
//!   候補ありでも `UNIMPLEMENTED`（8）か `PERMISSION_DENIED`（6）で fail-closed に失敗する。
//! - エラー形式（`code` / `message`）の確定: TASK-95（ERR 系）。ここの [`CliExit`] は最小の先取り。

use std::ffi::OsString;
use std::io::Write;

use fandhe_container_core::oci_runtime::{
    OCI_EXIT_INVALID_ARGUMENT, OCI_EXIT_UNIMPLEMENTED, OciRuntimeError, exit_code_for,
};
use fandhe_container_core::traits::ErrorCode;

mod args;
mod create_start;
mod list_logs;
mod plugin_backend;
mod stop_delete;

use args::{
    parse_create, parse_delete, parse_global, parse_list, parse_logs, parse_start, parse_stop,
};

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

/// 使い方エラーの終了コード（core の ERR-2 表の `INVALID_ARGUMENT`）。
pub const EXIT_USAGE: u8 = OCI_EXIT_INVALID_ARGUMENT.get();
/// 未実装コマンドの終了コード（core の ERR-2 表の `UNIMPLEMENTED`）。
pub const EXIT_UNIMPLEMENTED: u8 = OCI_EXIT_UNIMPLEMENTED.get();

/// [`run`] の結果。終了コードと、失敗時の機械可読なエラー（`code` / `message`）を持つ。
///
/// 固定文言の失敗（[`CliExit::Usage`]・[`CliExit::Unimplemented`]）は閉じた列挙で、文言は本 module の
/// 定数のみ（外部から任意の文字列・終了コードを構築できないためエスケープ不要・失敗に 0 も指定できない）。
/// core 由来の失敗は `OciRuntimeError::write_json_line`（serde_json）で出力する（JSON を手組みしない。REPAIR-2）。
#[derive(Debug)]
pub enum CliExit {
    /// 成功（終了コード 0。OCI の create / start / stop / delete は成功時に何も出さない。`list` のみ stdout へ一覧を出す）。
    Success,
    /// 使い方エラー（終了コード 2・`INVALID_ARGUMENT`）。
    Usage,
    /// 未実装コマンド（終了コード 8・`UNIMPLEMENTED`）。
    Unimplemented,
    /// core のライフサイクル操作の失敗（ERR-2。終了コードは `OciRuntimeError::exit_code`）。
    Runtime(OciRuntimeError),
    /// core の状態ストア操作の失敗（`list` / `logs`。ライフサイクル操作ではないため `op` を持たない）。
    ///
    /// 終了コードは core の `exit_code_for`、`message` は本 module の固定文言表（[`failure_message`]）で、
    /// core の `TraitError::message` は出力へ流さない（エスケープ不要の定数のみ）。
    Failed(ErrorCode),
    /// 状態ルート（ストアのディレクトリ）が存在しない（終了コード 3・`NOT_FOUND`）。
    ///
    /// コンテナ不在（[`CliExit::Failed`] の `NotFound`、文言 `container not found`）と区別するための専用値で、
    /// `list` / `logs` が状態ストアを開く段階の `NotFound` だけに使う（コンテナ ID を参照していない失敗）。
    StateRootNotFound,
}

impl CliExit {
    /// プロセスの終了コード。
    pub fn exit_code(&self) -> u8 {
        match self {
            CliExit::Success => 0,
            CliExit::Usage => EXIT_USAGE,
            CliExit::Unimplemented => EXIT_UNIMPLEMENTED,
            CliExit::Runtime(e) => e.exit_code().get(),
            CliExit::Failed(c) => exit_code_for(*c).get(),
            CliExit::StateRootNotFound => exit_code_for(ErrorCode::NotFound).get(),
        }
    }

    /// 失敗の機械可読なエラーコード文字列（成功は `None`）。
    pub fn code(&self) -> Option<&'static str> {
        match self {
            CliExit::Success => None,
            CliExit::Usage => Some("INVALID_ARGUMENT"),
            CliExit::Unimplemented => Some("UNIMPLEMENTED"),
            CliExit::Runtime(e) => Some(e.code().as_str()),
            CliExit::Failed(c) => Some(c.as_str()),
            CliExit::StateRootNotFound => Some(ErrorCode::NotFound.as_str()),
        }
    }

    /// stderr へ失敗の 1 行 JSON（LF 終端）を書く。成功では何も書かない。
    ///
    /// 行本体と LF を 1 つのバッファにまとめ、1 回の `write_all` で書く。`writeln!` は書式の断片ごとに
    /// write を分けうるため、stderr を共有する他プロセスの出力が行の途中へ入るのを避ける（ERR-1）。
    pub fn write_stderr(&self, out: &mut dyn Write) -> std::io::Result<()> {
        // 文言は引用符・バックスラッシュ・改行を含まない定数のみ（テストで固定）。
        let fixed = |code: &str, message: &str| {
            format!("{{\"code\":\"{code}\",\"message\":\"{message}\"}}\n")
        };
        match self {
            CliExit::Success => Ok(()),
            CliExit::Usage => out.write_all(fixed("INVALID_ARGUMENT", USAGE_MESSAGE).as_bytes()),
            CliExit::Unimplemented => {
                out.write_all(fixed("UNIMPLEMENTED", UNIMPLEMENTED_MESSAGE).as_bytes())
            }
            CliExit::Runtime(e) => e.write_json_line(out),
            CliExit::Failed(c) => out.write_all(fixed(c.as_str(), failure_message(*c)).as_bytes()),
            CliExit::StateRootNotFound => out.write_all(
                fixed(ErrorCode::NotFound.as_str(), STATE_ROOT_NOT_FOUND_MESSAGE).as_bytes(),
            ),
        }
    }
}

const USAGE_MESSAGE: &str = "usage: fandhe-container <create|start|stop|delete|list|logs>";
const STATE_ROOT_NOT_FOUND_MESSAGE: &str = "state root not found";
const UNIMPLEMENTED_MESSAGE: &str = "command is not implemented yet";

/// [`CliExit::Failed`] の固定文言表。引用符・バックスラッシュ・制御文字を含まない定数のみ（テストで固定）。
/// `ErrorCode` は `#[non_exhaustive]` のため、未知のコードは汎用文言に落とす。
fn failure_message(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::InvalidArgument => "invalid argument",
        ErrorCode::NotFound => "container not found",
        ErrorCode::AlreadyExists => "already exists",
        ErrorCode::FailedPrecondition => "failed precondition",
        ErrorCode::Unimplemented => "not implemented on this platform",
        ErrorCode::PermissionDenied => "permission denied",
        ErrorCode::Timeout => "operation timed out",
        ErrorCode::Unavailable => "unavailable",
        _ => "operation failed",
    }
}

fn usage() -> CliExit {
    CliExit::Usage
}

/// argv（プログラム名を除く）を解釈して実行する。
///
/// `create` / `start` / `stop` / `delete` / `list` / `logs` は core を呼ぶ（TASK-79.2.1・TASK-79.2.2・TASK-79.3）。
/// `list` の一覧は process の stdout へ出す。引数値は出力へ埋め込まない（インジェクション回避）。
pub fn run<I: IntoIterator<Item = OsString>>(args: I) -> CliExit {
    run_to(args, &mut std::io::stdout())
}

/// [`run`] と同じだが、`list` の出力先を `stdout` で指定する（テストと将来の出力先切替の入口）。
pub fn run_to<I: IntoIterator<Item = OsString>>(args: I, stdout: &mut dyn Write) -> CliExit {
    let Ok((global, rest)) = parse_global(args.into_iter().collect()) else {
        return usage();
    };
    let mut it = rest.into_iter();
    let Some(first) = it.next() else {
        return usage();
    };
    let Some(command) = first.to_str().and_then(Command::parse) else {
        return usage();
    };
    let tail: Vec<OsString> = it.collect();
    match command {
        Command::Create => match parse_create(tail) {
            Ok(a) => create_start::run_create(&global, &a),
            Err(_) => usage(),
        },
        Command::Start => match parse_start(tail) {
            Ok(a) => create_start::run_start(&global, &a),
            Err(_) => usage(),
        },
        Command::Stop => match parse_stop(tail) {
            Ok(a) => stop_delete::run_stop(&global, &a),
            Err(_) => usage(),
        },
        Command::Delete => match parse_delete(tail) {
            Ok(a) => stop_delete::run_delete(&global, &a),
            Err(_) => usage(),
        },
        Command::List => match parse_list(tail) {
            Ok(a) => list_logs::run_list(&global, &a, stdout),
            Err(_) => usage(),
        },
        Command::Logs => match parse_logs(tail) {
            Ok(a) => list_logs::run_logs(&global, &a),
            Err(_) => usage(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    fn stderr_of(e: &CliExit) -> String {
        let mut buf = Vec::new();
        e.write_stderr(&mut buf).expect("write");
        String::from_utf8(buf).expect("utf8")
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

    /// CLI-1: 引数なし・未知コマンド・引数不足の create / start は使い方エラー（2）。
    #[test]
    fn cli1_run_usage_errors() {
        for a in [
            args(&[]),
            args(&["run"]),
            args(&[""]),
            args(&["--root", "/r"]),
            args(&["create"]),
            args(&["start"]),
            args(&["stop"]),
            args(&["delete"]),
            args(&["stop", "a", "b"]),
            args(&["delete", "--x", "a"]),
            args(&["logs"]),
            args(&["logs", "a", "b"]),
            args(&["logs", "--x", "a"]),
            args(&["list", "x"]),
            args(&["list", "--all"]),
        ] {
            let r = run(a);
            assert_eq!(r.exit_code(), 2);
            assert_eq!(r.code(), Some("INVALID_ARGUMENT"));
        }
    }

    /// ERR-2: logs の不正 ID は状態ルートを開く前に INVALID_ARGUMENT（2）で拒否される。
    #[test]
    fn err2_logs_rejects_invalid_id() {
        for id in ["a/b", "..", "a b"] {
            let r = run(args(&["logs", id]));
            assert_eq!(r.exit_code(), 2);
            assert_eq!(r.code(), Some("INVALID_ARGUMENT"));
        }
    }

    /// ERR-1・ERR-2: 固定文言表の全コードで、文言は JSON 安全で終了コードが core の表と一致する。
    #[test]
    fn err2_failed_messages_are_json_safe_and_exit_codes_match() {
        let codes = [
            (ErrorCode::InvalidArgument, 2),
            (ErrorCode::NotFound, 3),
            (ErrorCode::AlreadyExists, 4),
            (ErrorCode::FailedPrecondition, 5),
            (ErrorCode::Unimplemented, 8),
            (ErrorCode::Internal, 1),
            (ErrorCode::PermissionDenied, 6),
            (ErrorCode::Timeout, 7),
            (ErrorCode::Unavailable, 9),
        ];
        for (code, exit) in codes {
            let m = failure_message(code);
            assert!(!m.is_empty());
            assert!(
                m.chars().all(|c| !c.is_control() && c != '"' && c != '\\'),
                "{m:?}"
            );
            assert_eq!(CliExit::Failed(code).exit_code(), exit);
            assert_eq!(CliExit::Failed(code).code(), Some(code.as_str()));
        }
    }

    /// ERR-1: 固定文言の失敗は行本体と LF を 1 回の write で書く（他の出力が行の途中へ入らない）。
    #[test]
    fn err1_write_stderr_emits_fixed_line_in_single_write() {
        struct Counting(Vec<Vec<u8>>);
        impl Write for Counting {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.push(buf.to_vec());
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for (exit, line) in [
            (
                CliExit::Usage,
                "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"usage: fandhe-container <create|start|stop|delete|list|logs>\"}\n",
            ),
            (
                CliExit::Unimplemented,
                "{\"code\":\"UNIMPLEMENTED\",\"message\":\"command is not implemented yet\"}\n",
            ),
            (
                CliExit::Failed(ErrorCode::NotFound),
                "{\"code\":\"NOT_FOUND\",\"message\":\"container not found\"}\n",
            ),
            (
                CliExit::StateRootNotFound,
                "{\"code\":\"NOT_FOUND\",\"message\":\"state root not found\"}\n",
            ),
        ] {
            let mut out = Counting(Vec::new());
            exit.write_stderr(&mut out).expect("write");
            assert_eq!(out.0, vec![line.as_bytes().to_vec()]);
        }
    }

    /// 出力: 成功は 0 バイト、固定文言は 1 行 JSON、core 由来は op 付き 1 行 JSON。
    #[test]
    fn err2_write_stderr_formats() {
        assert_eq!(stderr_of(&CliExit::Success), "");
        assert_eq!(CliExit::Success.exit_code(), 0);
        assert_eq!(
            stderr_of(&CliExit::Unimplemented),
            "{\"code\":\"UNIMPLEMENTED\",\"message\":\"command is not implemented yet\"}\n"
        );
        let e = OciRuntimeError::new(
            fandhe_container_core::oci_runtime::LifecycleOp::Start,
            fandhe_container_core::traits::ErrorCode::NotFound,
            "missing",
        );
        let exit = CliExit::Runtime(e);
        assert_eq!(exit.exit_code(), 3);
        assert_eq!(
            stderr_of(&exit),
            "{\"op\":\"start\",\"code\":\"NOT_FOUND\",\"message\":\"missing\"}\n"
        );
    }
}
