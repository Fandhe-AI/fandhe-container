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
//! `setup` は OS 固有設定のステップ提示で `setup` module にのみ委譲する（日常操作コマンドは OS 固有設定を持たない。TASK-80.1・CLI-2）。
//! 終了コードは core の ERR-2 表（`OCI_EXIT_*`）に揃える。
//!
//! OS 固有設定の分離規則（CLI-2・TASK-80.2）:
//! - `crate::setup` を参照してよいのは `run_setup` のみ。`commands/` 配下の module は setup の型・関数を import しない。
//! - 日常操作側の `cfg(target_os)`（`create_start::open_store`・`plugin_backend`）は CLI-1・PLUG-4 のバックエンド振り分けで、
//!   OS 固有設定ではないため CLI-2 の対象外。非 Linux の失敗文言は plugin 前提の不成立であり、OS 設定や setup 実行を要求しない。
//! - 分離の単体テストは `setup::tests::cli2_daily_commands_do_not_request_os_setup`（TASK-80.3）。
//!
//! 将来仕様（本実装の範囲外）:
//! - start の実プロセス起動: supervisor 経由の launcher（TASK-157・TASK-37〜39）。
//! - stop の猶予 → SIGKILL・本番 signaler / cgroup remover の結線: supervisor 経由（TASK-157）。
//! - logs の内容読み出し・list の JSON 出力: ログ契約と crate 境界の決定後（`list_logs` module の doc 参照。TASK-95・TASK-98）。
//! - macOS / Windows は plugin 発見機構経由（TASK-79.4・#641・PLUG-4。`plugin_backend` module）。発見 → 登録 → 信頼性検証までを
//!   配線済みで、platform-* へは直接依存しない（`make check-cli-backend-deps`）。非 Linux の信頼性検証（PLUG-11）・plugin の
//!   起動と RPC（TASK-114・TASK-125）は未実装のため、非 Linux の全コマンドは候補なしで `FAILED_PRECONDITION`（5）、
//!   候補ありでも `UNIMPLEMENTED`（8）か `PERMISSION_DENIED`（6）で fail-closed に失敗する。
//! - エラー形式: 全コマンドの失敗は [`CliExit`] 経由で構造化エラー（`code` / `message`・非ゼロ終了コード）に統一済み（TASK-95.2・ERR-1）。
//!   ライフサイクル操作の失敗のみ ERR-2 の `op` 付き形式を保つ。JSON Lines への統一は ERR-4（TASK-98）。

use std::ffi::OsString;
use std::io::Write;

use fandhe_container_core::oci_runtime::{
    OCI_EXIT_INVALID_ARGUMENT, OCI_EXIT_UNIMPLEMENTED, OciRuntimeError,
};
use fandhe_container_core::traits::ErrorCode;

use crate::error::CliError;

mod args;
mod create_start;
mod list_logs;
// Linux は plugin を介さず core を直接呼ぶため、本番ビルドでは除外する（単体テストは OS 非依存ロジックの検証に使う）。
#[cfg(any(not(target_os = "linux"), test))]
mod plugin_backend;
mod stop_delete;

use args::{
    parse_create, parse_delete, parse_global, parse_list, parse_logs, parse_setup, parse_start,
    parse_stop,
};

/// コマンドの区分（CLI-2・TASK-80.2）。日常操作は OS 固有設定を持たず、OS 固有設定は `setup` にのみ置く。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKind {
    /// 日常操作（create / start / stop / delete / list / logs）。`crate::setup` を参照しない。
    Daily,
    /// OS 固有設定のセットアップ（`setup`）。
    Setup,
}

/// 基本コマンド（CLI-1）と setup（CLI-2）。日常操作か否かの区分は [`Command::kind`] で判定する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Create,
    Start,
    Stop,
    Delete,
    List,
    Logs,
    /// OS 固有設定のセットアップ（TASK-80.1・CLI-2。日常操作ではない）。
    Setup,
}

impl Command {
    /// 全コマンド（コマンド名の列挙順の SSOT）。
    pub const ALL: [Command; 7] = [
        Command::Create,
        Command::Start,
        Command::Stop,
        Command::Delete,
        Command::List,
        Command::Logs,
        Command::Setup,
    ];

    /// 日常操作コマンドのみ（`ALL` から `Setup` を除いたもの。分離の照合の列挙元。TASK-80.2・TASK-80.3）。
    pub const DAILY: [Command; 6] = [
        Command::Create,
        Command::Start,
        Command::Stop,
        Command::Delete,
        Command::List,
        Command::Logs,
    ];

    /// コマンドの区分。ワイルドカードを使わず、コマンド追加時に分類漏れをコンパイルエラーにする。
    pub fn kind(self) -> CommandKind {
        match self {
            Command::Create
            | Command::Start
            | Command::Stop
            | Command::Delete
            | Command::List
            | Command::Logs => CommandKind::Daily,
            Command::Setup => CommandKind::Setup,
        }
    }

    /// CLI 上のコマンド名。
    pub fn as_str(self) -> &'static str {
        match self {
            Command::Create => "create",
            Command::Start => "start",
            Command::Stop => "stop",
            Command::Delete => "delete",
            Command::List => "list",
            Command::Logs => "logs",
            Command::Setup => "setup",
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
/// 失敗は構造化エラー型だけで表す（ERR-1・TASK-95.2）。ライフサイクル操作の失敗は `op` 付きの
/// [`OciRuntimeError`]（ERR-2）、それ以外の全失敗は [`CliError`]（`code` / `message`）で、どちらも終了コードは
/// `NonZeroU8` 由来のため「終了コード 0 の失敗」を表現できない。JSON は両型の出力処理に集約し、本 module では手組みしない（REPAIR-2）。
/// `CliError` の固定文言は本 module の定数のみで、argv・パス・コンテナ ID を出力へ埋め込まない。
#[derive(Debug)]
pub enum CliExit {
    /// 成功（終了コード 0。OCI の create / start / stop / delete は成功時に何も出さない。`list` のみ stdout へ一覧を出す）。
    Success,
    /// core のライフサイクル操作の失敗（ERR-2。`op` 付き。終了コードは `OciRuntimeError::exit_code`）。
    ///
    /// `op` は観測側（結合テスト・parity スクリプト）が参照するため、`CliError` へ寄せず ERR-2 の形式を保つ。
    Runtime(OciRuntimeError),
    /// それ以外の全失敗（使い方エラー・未実装・状態ストア操作・setup。ERR-1。`op` を持たない）。
    Error(CliError),
}

impl CliExit {
    /// 使い方エラー（終了コード 2・`INVALID_ARGUMENT`）。
    pub(crate) fn usage() -> Self {
        CliExit::Error(CliError::new(ErrorCode::InvalidArgument, USAGE_MESSAGE))
    }

    /// 未実装コマンド（終了コード 8・`UNIMPLEMENTED`）。
    pub(crate) fn unimplemented() -> Self {
        CliExit::Error(CliError::new(
            ErrorCode::Unimplemented,
            UNIMPLEMENTED_MESSAGE,
        ))
    }

    /// core の状態ストア操作等の失敗（`list` / `logs` / `setup`。ライフサイクル操作ではないため `op` を持たない）。
    ///
    /// 終了コードは core の `exit_code_for`、`message` は本 module の固定文言表（[`failure_message`]）で、
    /// core の `TraitError::message` は出力へ流さない（エスケープ不要の定数のみ）。
    pub(crate) fn failed(code: ErrorCode) -> Self {
        CliExit::Error(CliError::new(code, failure_message(code)))
    }

    /// 状態ルート（ストアのディレクトリ）が存在しない（終了コード 3・`NOT_FOUND`）。
    ///
    /// コンテナ不在（`failed(NotFound)`、文言 `container not found`）と区別するための専用値で、
    /// `list` / `logs` が状態ストアを開く段階の `NotFound` だけに使う（コンテナ ID を参照していない失敗）。
    pub(crate) fn state_root_not_found() -> Self {
        CliExit::Error(CliError::new(
            ErrorCode::NotFound,
            STATE_ROOT_NOT_FOUND_MESSAGE,
        ))
    }

    /// プロセスの終了コード。
    pub fn exit_code(&self) -> u8 {
        match self {
            CliExit::Success => 0,
            CliExit::Runtime(e) => e.exit_code().get(),
            CliExit::Error(e) => e.exit_code().get(),
        }
    }

    /// 失敗の機械可読なエラーコード文字列（成功は `None`）。
    pub fn code(&self) -> Option<&'static str> {
        match self {
            CliExit::Success => None,
            CliExit::Runtime(e) => Some(e.code().as_str()),
            CliExit::Error(e) => Some(e.code_str()),
        }
    }

    /// stderr へ失敗の 1 行 JSON（LF 終端）を書く。成功では何も書かない。
    ///
    /// 行本体と LF を 1 つのバッファにまとめ、1 回の `write_all` で書く（`CliError::write_stderr`・
    /// `OciRuntimeError::write_json_line`）。`writeln!` は書式の断片ごとに write を分けうるため、
    /// stderr を共有する他プロセスの出力が行の途中へ入るのを避ける（ERR-1）。
    pub fn write_stderr(&self, out: &mut dyn Write) -> std::io::Result<()> {
        match self {
            CliExit::Success => Ok(()),
            CliExit::Runtime(e) => e.write_json_line(out),
            CliExit::Error(e) => e.write_stderr(out),
        }
    }
}

const USAGE_MESSAGE: &str = "usage: fandhe-container <create|start|stop|delete|list|logs|setup>";
const STATE_ROOT_NOT_FOUND_MESSAGE: &str = "state root not found";
const UNIMPLEMENTED_MESSAGE: &str = "command is not implemented yet";

/// [`CliExit::failed`] の固定文言表。引用符・バックスラッシュ・制御文字を含まない定数のみ（テストで固定）。
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
    CliExit::usage()
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
        Command::Setup => run_setup(tail, stdout),
    }
}

/// `setup` の実行。`crate::setup` を参照する唯一の箇所（CLI-2・TASK-80.2）。
///
/// `GlobalArgs` を受け取らない（setup は状態ルート・plugin 探索設定を使わず、グローバルオプションは受理して無視する）。
fn run_setup(tail: Vec<OsString>, stdout: &mut dyn Write) -> CliExit {
    match parse_setup(tail) {
        Ok(_) => crate::setup::run(stdout),
        Err(_) => usage(),
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
        assert_eq!(Command::parse("setup"), Some(Command::Setup));
    }

    /// CLI-2: `setup` だけが `Setup` 区分で、他 6 件は日常操作。
    #[test]
    fn cli2_command_kind_classification() {
        let daily: Vec<&str> = Command::ALL
            .iter()
            .filter(|c| c.kind() == CommandKind::Daily)
            .map(|c| c.as_str())
            .collect();
        assert_eq!(daily, ["create", "start", "stop", "delete", "list", "logs"]);
        assert_eq!(Command::Setup.kind(), CommandKind::Setup);
    }

    /// CLI-2: `DAILY` は `ALL` から `Setup` を除いたものと一致する。
    #[test]
    fn cli2_daily_is_all_minus_setup() {
        let names: Vec<&str> = Command::DAILY.iter().map(|c| c.as_str()).collect();
        assert_eq!(names, ["create", "start", "stop", "delete", "list", "logs"]);
        let rest: Vec<Command> = Command::ALL
            .into_iter()
            .filter(|c| *c != Command::Setup)
            .collect();
        assert_eq!(rest, Command::DAILY.to_vec());
    }

    /// CLI-1: 全コマンド名の並び。
    #[test]
    fn cli1_all_names_order() {
        let names: Vec<&str> = Command::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            names,
            ["create", "start", "stop", "delete", "list", "logs", "setup"]
        );
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
            args(&["setup", "x"]),
            args(&["setup", "--x"]),
        ] {
            let r = run(a);
            assert_eq!(r.exit_code(), 2);
            assert_eq!(r.code(), Some("INVALID_ARGUMENT"));
        }
    }

    /// 受け入れ検査（ERR-1）: 失敗が非ゼロ終了コード・LF 終端 1 行の `code` / `message` JSON であり、
    /// `code()` と行内の `code` が一致する。
    fn assert_structured_failure(exit: &CliExit, expected_exit: u8, expected_code: &str) {
        assert_ne!(exit.exit_code(), 0);
        assert_eq!(exit.exit_code(), expected_exit);
        assert_eq!(exit.code(), Some(expected_code));
        let line = stderr_of(exit);
        assert!(line.ends_with("\"}\n"), "{line:?}");
        assert_eq!(line.matches('\n').count(), 1, "{line:?}");
        assert!(
            line.starts_with(&format!("{{\"code\":\"{expected_code}\",\"message\":\"")),
            "{line:?}"
        );
    }

    /// ERR-1・TASK-95.2: 全コマンド（`Command::ALL`）の解析段階のエラー終了が、構造化エラー形式かつ非ゼロ終了コード（2）になる。
    /// ワイルドカード無しの match で、コマンド追加時に argv の割り当て漏れをコンパイルエラーにする。
    #[test]
    fn err1_all_commands_error_exit_is_structured_and_nonzero() {
        let usage_line = "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"usage: fandhe-container <create|start|stop|delete|list|logs|setup>\"}\n";
        let mut covered = Vec::new();
        for command in Command::ALL {
            // 状態ストアを開く前（引数解析）で失敗する argv。OS に依存しない。
            let argv: Vec<&str> = match command {
                Command::Create => vec!["create"],
                Command::Start => vec!["start"],
                Command::Stop => vec!["stop", "a", "b"],
                Command::Delete => vec!["delete", "--x", "a"],
                Command::List => vec!["list", "x"],
                Command::Logs => vec!["logs"],
                Command::Setup => vec!["setup", "x"],
            };
            assert_eq!(argv[0], command.as_str());
            let exit = run(args(&argv));
            assert_structured_failure(&exit, 2, "INVALID_ARGUMENT");
            assert_eq!(stderr_of(&exit), usage_line, "{argv:?}");
            covered.push(command.as_str());
        }
        assert_eq!(
            covered,
            ["create", "start", "stop", "delete", "list", "logs", "setup"]
        );
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
            assert_eq!(CliExit::failed(code).exit_code(), exit);
            assert_eq!(CliExit::failed(code).code(), Some(code.as_str()));
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
                CliExit::usage(),
                "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"usage: fandhe-container <create|start|stop|delete|list|logs|setup>\"}\n",
            ),
            (
                CliExit::unimplemented(),
                "{\"code\":\"UNIMPLEMENTED\",\"message\":\"command is not implemented yet\"}\n",
            ),
            (
                CliExit::failed(ErrorCode::NotFound),
                "{\"code\":\"NOT_FOUND\",\"message\":\"container not found\"}\n",
            ),
            (
                CliExit::state_root_not_found(),
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
            stderr_of(&CliExit::unimplemented()),
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

    /// Linux 経路の `run_to` 境界の単体テスト（TASK-79.5・#642・CLI-1）。
    ///
    /// 本番入口（引数解析 → 状態ストア open → core 呼び出し → `CliExit` への写像 → `write_stderr`）を
    /// 6 コマンドそれぞれ直接呼んで検証する。本番 launcher / signaler は fail-closed のため
    /// プロセス起動・シグナル送信は発生しない。全呼び出しは `invoke` が `--root <TmpDir>` を強制し、
    /// 利用者の実状態ルートへ触れない。環境変数は変更しない（並列テストとの競合回避）。
    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct TmpDir(PathBuf);

        impl TmpDir {
            fn new(tag: &str) -> Self {
                static SEQ: AtomicUsize = AtomicUsize::new(0);
                let n = SEQ.fetch_add(1, Ordering::SeqCst);
                let p = std::env::temp_dir()
                    .join(format!("fc-cli-cmd-{tag}-{}-{n}", std::process::id()));
                std::fs::create_dir_all(&p).expect("mkdir");
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
                        .expect("chmod");
                }
                Self(p)
            }

            fn state_root(&self) -> PathBuf {
                self.0.join("state")
            }
        }

        impl Drop for TmpDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        /// 状態ルートを 0700 で先に作る（ストアは他者に開かれた権限のルートを PERMISSION_DENIED で拒否する）。
        fn make_state_root(root: &Path) {
            use std::os::unix::fs::PermissionsExt;
            std::fs::create_dir_all(root).expect("root");
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }

        fn make_bundle(base: &TmpDir) -> PathBuf {
            let b = base.0.join("bundle");
            std::fs::create_dir_all(b.join("rootfs")).expect("rootfs");
            std::fs::write(
                b.join("config.json"),
                r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
            )
            .expect("config");
            b
        }

        /// `run_to` の観測結果（終了コード・エラーコード・stdout・stderr）。
        struct Outcome {
            exit: u8,
            code: Option<&'static str>,
            stdout: String,
            stderr: String,
        }

        /// 先頭に `--root <root>` を必ず付けて `run_to` を呼ぶ（実状態ルートを汚さないための強制）。
        fn invoke(root: &Path, argv: &[&str]) -> Outcome {
            let mut full: Vec<OsString> = vec![OsString::from("--root"), root.into()];
            full.extend(argv.iter().map(OsString::from));
            let mut out = Vec::new();
            let r = run_to(full, &mut out);
            Outcome {
                exit: r.exit_code(),
                code: r.code(),
                stdout: String::from_utf8(out).expect("utf8"),
                stderr: stderr_of(&r),
            }
        }

        /// 失敗 JSON が LF 終端の 1 行であることを確認し、`op` / `code` を取り出す（`message` は core 文言依存のため見ない）。
        fn op_and_code(stderr: &str) -> (String, String) {
            assert!(stderr.ends_with('\n'), "{stderr:?}");
            assert_eq!(stderr.matches('\n').count(), 1, "{stderr:?}");
            let field = |key: &str| -> String {
                let pat = format!("\"{key}\":\"");
                let start = stderr.find(&pat).map(|i| i + pat.len()).unwrap_or(0);
                let tail = stderr.get(start..).unwrap_or("");
                tail.split('"').next().unwrap_or("").to_owned()
            };
            (field("op"), field("code"))
        }

        fn create_ok(base: &TmpDir, id: &str) {
            let bundle = make_bundle(base);
            let o = invoke(
                &base.state_root(),
                &["create", "--bundle", bundle.to_str().expect("utf8"), id],
            );
            assert_eq!((o.exit, o.stderr.as_str()), (0, ""), "{}", o.stderr);
        }

        fn failure(op: &str, code: &str) -> (String, String) {
            (op.to_owned(), code.to_owned())
        }

        /// CLI-1・OCI-4・ERR-2: create は成功で無出力、重複は ALREADY_EXISTS（4）、不正 ID は使い方エラー（2）。
        #[test]
        fn cli1_run_create_on_linux() {
            let base = TmpDir::new("create");
            let root = base.state_root();
            let bundle = make_bundle(&base);
            let b = bundle.to_str().expect("utf8");

            let o = invoke(&root, &["create", "--bundle", b, "c1"]);
            assert_eq!(o.exit, 0);
            assert_eq!(o.code, None);
            assert_eq!((o.stdout.as_str(), o.stderr.as_str()), ("", ""));
            assert!(root.join("c1").join("state.json").is_file());

            let o = invoke(&root, &["create", "--bundle", b, "c1"]);
            assert_eq!(o.exit, 4);
            assert_eq!(op_and_code(&o.stderr), failure("create", "ALREADY_EXISTS"));

            let o = invoke(&root, &["create", "--bundle", b, "a/b"]);
            assert_eq!((o.exit, o.code), (2, Some("INVALID_ARGUMENT")));
        }

        /// CLI-1・ERR-2・REPAIR-3: start は未作成で NOT_FOUND（3）、作成済みでも launcher 未提供のため UNIMPLEMENTED（8）で
        /// 状態は Created のまま。
        #[test]
        fn cli1_run_start_on_linux() {
            let base = TmpDir::new("start");
            let root = base.state_root();

            let o = invoke(&root, &["start", "c1"]);
            assert_eq!(o.exit, 3);
            assert_eq!(op_and_code(&o.stderr), failure("start", "NOT_FOUND"));

            create_ok(&base, "c1");
            let o = invoke(&root, &["start", "c1"]);
            assert_eq!(o.exit, 8);
            assert_eq!(op_and_code(&o.stderr), failure("start", "UNIMPLEMENTED"));

            let o = invoke(&root, &["list"]);
            assert_eq!(o.stdout, "ID\tSTATUS\tPID\nc1\tcreated\t-\n");

            let o = invoke(&root, &["start", "a/b"]);
            assert_eq!((o.exit, o.code), (2, Some("INVALID_ARGUMENT")));
        }

        /// CLI-1・OCI-6・ERR-2: stop は未作成で NOT_FOUND（3）、pid なしの Created は FAILED_PRECONDITION（5）。
        /// 失敗 JSON の op は core に Stop が無いため `kill`。
        #[test]
        fn cli1_run_stop_on_linux() {
            let base = TmpDir::new("stop");
            let root = base.state_root();

            let o = invoke(&root, &["stop", "c1"]);
            assert_eq!(o.exit, 3);
            assert_eq!(op_and_code(&o.stderr), failure("kill", "NOT_FOUND"));

            create_ok(&base, "c1");
            let o = invoke(&root, &["stop", "c1"]);
            assert_eq!(o.exit, 5);
            assert_eq!(
                op_and_code(&o.stderr),
                failure("kill", "FAILED_PRECONDITION")
            );
            assert!(root.join("c1").join("state.json").is_file());

            let o = invoke(&root, &["stop", "a/b"]);
            assert_eq!((o.exit, o.code), (2, Some("INVALID_ARGUMENT")));
        }

        /// CLI-1・OCI-6・ERR-2: delete は作成済みで成功し state.json が消え、再実行は NOT_FOUND（3）。`--force` も成功する。
        #[test]
        fn cli1_run_delete_on_linux() {
            let base = TmpDir::new("delete");
            let root = base.state_root();

            let o = invoke(&root, &["delete", "c1"]);
            assert_eq!(o.exit, 3);
            assert_eq!(op_and_code(&o.stderr), failure("delete", "NOT_FOUND"));

            create_ok(&base, "c1");
            let o = invoke(&root, &["delete", "c1"]);
            assert_eq!(o.exit, 0);
            assert_eq!((o.stdout.as_str(), o.stderr.as_str()), ("", ""));
            assert!(!root.join("c1").join("state.json").exists());

            assert_eq!(invoke(&root, &["delete", "c1"]).exit, 3);

            create_ok(&base, "c1");
            let o = invoke(&root, &["delete", "--force", "c1"]);
            assert_eq!(o.exit, 0);
            assert!(!root.join("c1").join("state.json").exists());
        }

        /// CLI-1: list は空ストアでヘッダのみ、複数件は ID 昇順のタブ区切りで stdout へ出す。
        #[test]
        fn cli1_run_list_on_linux() {
            let base = TmpDir::new("list");
            let root = base.state_root();

            make_state_root(&root);
            let o = invoke(&root, &["list"]);
            assert_eq!(o.exit, 0);
            assert_eq!(o.stdout, "ID\tSTATUS\tPID\n");
            assert_eq!(o.stderr, "");

            create_ok(&base, "b2");
            create_ok(&base, "a1");
            let o = invoke(&root, &["list"]);
            assert_eq!(o.exit, 0);
            assert_eq!(
                o.stdout,
                "ID\tSTATUS\tPID\na1\tcreated\t-\nb2\tcreated\t-\n"
            );
            assert_eq!(o.stderr, "");
        }

        /// CLI-1・ERR-2・REPAIR-3: logs は未作成で NOT_FOUND（3）、作成済みでも内容読み出し未実装で UNIMPLEMENTED（8）。
        #[test]
        fn cli1_run_logs_on_linux() {
            let base = TmpDir::new("logs");
            let root = base.state_root();
            make_state_root(&root);

            let o = invoke(&root, &["logs", "c1"]);
            assert_eq!(o.exit, 3);
            assert_eq!(
                o.stderr,
                "{\"code\":\"NOT_FOUND\",\"message\":\"container not found\"}\n"
            );

            create_ok(&base, "c1");
            let o = invoke(&root, &["logs", "c1"]);
            assert_eq!(o.exit, 8);
            assert_eq!(
                o.stderr,
                "{\"code\":\"UNIMPLEMENTED\",\"message\":\"command is not implemented yet\"}\n"
            );
            assert_eq!(o.stdout, "");

            let o = invoke(&root, &["logs", "a/b"]);
            assert_eq!(o.exit, 2);
            assert_eq!(
                o.stderr,
                "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"invalid argument\"}\n"
            );
        }

        /// ERR-2: 状態ルートの親が無いとき、list / logs は専用の NOT_FOUND、他 4 コマンドは op 付き NOT_FOUND になり、
        /// 親ディレクトリは作られない。
        #[test]
        fn err2_state_root_parent_missing_on_linux() {
            let base = TmpDir::new("noparent");
            let parent = base.0.join("no-parent");
            let root = parent.join("state");
            let bundle = make_bundle(&base);
            let b = bundle.to_str().expect("utf8");

            for argv in [&["list"][..], &["logs", "c1"][..]] {
                let o = invoke(&root, argv);
                assert_eq!(o.exit, 3, "{argv:?}");
                assert_eq!(
                    o.stderr,
                    "{\"code\":\"NOT_FOUND\",\"message\":\"state root not found\"}\n"
                );
            }

            let cases: [(&[&str], &str); 4] = [
                (&["create", "--bundle", b, "c1"], "create"),
                (&["start", "c1"], "start"),
                (&["stop", "c1"], "kill"),
                (&["delete", "c1"], "delete"),
            ];
            for (argv, op) in cases {
                let o = invoke(&root, argv);
                assert_eq!(o.exit, 3, "{argv:?}");
                assert_eq!(op_and_code(&o.stderr), failure(op, "NOT_FOUND"), "{argv:?}");
            }
            assert!(!parent.exists());
        }

        /// SEC-1: 引用符・バックスラッシュ・改行を含む入力値は出力へ反射されず、stderr は 1 行のまま。
        #[test]
        fn sec1_argument_values_are_not_reflected() {
            let base = TmpDir::new("reflect");
            let root = base.state_root();
            make_state_root(&root);
            let evil = "x\"\\\ninj";
            for argv in [
                vec!["start", evil],
                vec!["stop", evil],
                vec!["delete", evil],
                vec!["logs", evil],
                vec![evil],
            ] {
                let o = invoke(&root, &argv);
                assert_eq!(o.exit, 2, "{argv:?}");
                assert_eq!(o.stdout, "");
                assert!(!o.stderr.contains("inj"), "{:?}", o.stderr);
                assert_eq!(o.stderr.matches('\n').count(), 1, "{:?}", o.stderr);
            }
        }

        /// ERR-1・TASK-95.2: 解析通過後の実行時エラーも全コマンドで構造化エラー形式かつ非ゼロ終了コードになる
        /// （`setup` は Linux で失敗しないため、`run_for(Other)` の失敗を同じ検査に通す）。
        #[test]
        fn err1_all_commands_runtime_error_exit_is_structured_and_nonzero() {
            let base = TmpDir::new("err1rt");
            let root = base.state_root();
            let missing_root = base.0.join("no-parent").join("state");
            let bundle = make_bundle(&base);
            let b = bundle.to_str().expect("utf8");

            let check = |o: &Outcome, exit: u8, code: &str| {
                assert_ne!(o.exit, 0, "{}", o.stderr);
                assert_eq!(o.exit, exit, "{}", o.stderr);
                assert_eq!(o.code, Some(code), "{}", o.stderr);
                assert!(o.stderr.ends_with("\"}\n"), "{:?}", o.stderr);
                assert_eq!(o.stderr.matches('\n').count(), 1, "{:?}", o.stderr);
                assert!(
                    o.stderr.contains(&format!("\"code\":\"{code}\"")),
                    "{:?}",
                    o.stderr
                );
                assert!(o.stderr.contains("\"message\":\""), "{:?}", o.stderr);
            };

            create_ok(&base, "c1");
            // create: 重複。
            let o = invoke(&root, &["create", "--bundle", b, "c1"]);
            check(&o, 4, "ALREADY_EXISTS");
            // start / stop / delete: 未作成。
            for argv in [
                &["start", "none"][..],
                &["stop", "none"],
                &["delete", "none"],
            ] {
                check(&invoke(&root, argv), 3, "NOT_FOUND");
            }
            // list: 状態ルート不在（固定文言で完全一致）。
            let o = invoke(&missing_root, &["list"]);
            check(&o, 3, "NOT_FOUND");
            assert_eq!(
                o.stderr,
                "{\"code\":\"NOT_FOUND\",\"message\":\"state root not found\"}\n"
            );
            // logs: 未作成（固定文言で完全一致）。
            let o = invoke(&root, &["logs", "none"]);
            check(&o, 3, "NOT_FOUND");
            assert_eq!(
                o.stderr,
                "{\"code\":\"NOT_FOUND\",\"message\":\"container not found\"}\n"
            );
            // setup: 対応外 OS 区分は UNIMPLEMENTED（8）。
            let mut sink = Vec::new();
            let exit = crate::setup::run_for(crate::setup::SetupPlatform::Other, &mut sink);
            assert_structured_failure(&exit, 8, "UNIMPLEMENTED");
            assert_eq!(
                stderr_of(&exit),
                "{\"code\":\"UNIMPLEMENTED\",\"message\":\"not implemented on this platform\"}\n"
            );
        }

        /// REPAIR-12・CLI-1: `Command::ALL` の全コマンドに Linux 経路のシナリオがあることを、
        /// ワイルドカード無しの match（コマンド追加でコンパイルエラーになる）で機械照合する。
        #[test]
        fn cli1_all_commands_have_linux_scenario() {
            let base = TmpDir::new("all");
            let root = base.state_root();
            let bundle = make_bundle(&base);
            let b = bundle.to_str().expect("utf8").to_owned();
            let mut covered = Vec::new();
            for command in Command::ALL {
                // (argv, 期待終了コード, 期待 code(), 期待 stdout)
                let (argv, exit, code, stdout): (Vec<&str>, u8, Option<&str>, &str) = match command
                {
                    Command::Create => (vec!["create", "--bundle", &b, "m1"], 0, None, ""),
                    Command::Start => (vec!["start", "none"], 3, Some("NOT_FOUND"), ""),
                    Command::Stop => (vec!["stop", "none"], 3, Some("NOT_FOUND"), ""),
                    Command::Delete => (vec!["delete", "none"], 3, Some("NOT_FOUND"), ""),
                    Command::List => (vec!["list"], 0, None, "ID\tSTATUS\tPID\nm1\tcreated\t-\n"),
                    Command::Logs => (vec!["logs", "none"], 3, Some("NOT_FOUND"), ""),
                    Command::Setup => (vec!["setup"], 0, None, ""),
                };
                assert_eq!(argv[0], command.as_str());
                let o = invoke(&root, &argv);
                assert_eq!(o.exit, exit, "{argv:?}");
                assert_eq!(o.code, code, "{argv:?}");
                assert_eq!(o.stdout, stdout, "{argv:?}");
                covered.push(command.as_str());
            }
            assert_eq!(
                covered,
                ["create", "start", "stop", "delete", "list", "logs", "setup"]
            );
        }
    }
}
