//! 統一 CLI の基本コマンド（create / start / stop / delete / list / logs / inspect / state / image / system）の入口（TASK-79.1・TASK-79.2.1・TASK-79.2.2・CLI-1・MS-6）。
//!
//! `main.rs`（bin `fandhe-container`）から [`run`] が呼ばれ、argv の先頭（グローバル `--root` の後）をコマンド名として判定する。
//! `create` / `start` は core の `oci_runtime::create` / `start` を直接呼ぶ（TASK-79.2.1・#866。`create_start` module）。
//! ただし `start` は core を呼ばず、CLI と同じディレクトリの supervisor の bin を起動して結果の 1 行を期限付きで受け取る
//! （#1718・`supervisor_start` module）。supervisor は core の本番 launcher（#1715・#1819）でコンテナのプロセスを起動する（rootless のみ。
//! rootful は `UNIMPLEMENTED`（8）。実機での通し確認は #2062）。同じディレクトリに supervisor が無ければ `FAILED_PRECONDITION`（5）で失敗する（REPAIR-3）。
//! `kill <id> [<signal>]`（#1902）は同じ core の `kill` を意図なしの `production_signaler` で呼び、シグナルを 1 回送るだけ（`stop_delete` module）。
//! `stop` / `delete` は core の `oci_runtime::kill`（既定 SIGTERM。`--signal` で上書き。#2775）/ `delete` を直接呼ぶ（TASK-79.2.2・#867。`stop_delete` module）。
//! `stop` の本番 `ProcessSignaler` は supervisor の制御チャネル経由（`stop_delete::production_signaler`。#2059・SEC-1）で、
//! supervisor に届かなければ構造化エラー（UNAVAILABLE 等）で失敗する。非 Linux は `UNIMPLEMENTED`（8）で fail-closed（REPAIR-3）。
//! `inspect <id>` は supervisor の `inspect::inspect` が整形した 1 行 JSON（起動時に適用した capability 集合を含む。#2775）を
//! stdout へ出す（`list_logs` module）。`create --cap-drop <CAP>`・`create --read-only` は起動オプション文書（`create_options`）経由で launch に届く。
//! `list` は core の状態ストアを読んで stdout へタブ区切りで一覧を出し、`logs` は存在確認の後に supervisor の
//! `logs::read_container_log_with` でコンテナログ（`<state_root>/@container-logs`）を古い順に stdout へ出す
//! （`--follow` / `--tail` / `--stream` / `--escape` つき。TASK-79.3・#640・#1543・#2447。`list_logs` module）。
//! `image ls` / `system df` / `image rm [--force]` / `image tag` は oci の管理 API（`image_management`）を呼ぶ（#2221・CLI-1・OCI-7。`image` module）。
//! イメージストアの root は必須オプション `--image-root`。参照テーブルの永続化が oci 側で未実装のため、現状は `image ls` が
//! 常にヘッダのみ・`image rm` が常に `NOT_FOUND` になる。既定 root・非 Linux の実行経路・`image prune` は未配線
//! （詳細は `image` module の doc。REPAIR-3）。
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
//! - start: uid 0 の起動（`RootfulHostRoot`。現状は `UNIMPLEMENTED`。#2241 のオーナー判断待ち）。
//! - stop の猶予 → SIGKILL（#1545）・stop の意図の伝達（SUP-9）。
//! - list の JSON 出力: serde 系の配線か core の公開ライタが前提（`list_logs` module の doc 参照。TASK-95・TASK-98）。
//! - macOS / Windows は plugin 発見機構経由（TASK-79.4・#641・PLUG-4。`plugin_backend` module）。発見 → 登録 → 信頼性検証までを
//!   配線済みで、platform-* へは直接依存しない（`make check-cli-backend-deps`）。信頼性検証（PLUG-11）は macOS が実装済み（拒否は
//!   `PERMISSION_DENIED`（6））、Windows はホストで検証しない（`--plugin-path-search` で候補があると `UNIMPLEMENTED`（8））。
//!   許可済みハッシュ一覧（#1868）と plugin の起動と RPC（#1869 の設計〔docs/design/plugin-backend-wiring.md。承認待ち〕・TASK-125）は
//!   未実装のため、非 Linux の全コマンドは候補なしで `FAILED_PRECONDITION`（5）、
//!   候補ありでも `PERMISSION_DENIED`（6）か `UNIMPLEMENTED`（8）で fail-closed に失敗する。plugin 解決の失敗の
//!   `message` は `plugin_backend` の固定文言表で、「未導入」と「信頼性検証の拒否」を区別できる。create 系はそのまま、
//!   `list` / `logs` は `list_logs::store_open_failure` が表との完全一致で拾って出す（setup は plugin 解決を通らず対象外。C1）。
//! - エラー形式: 全コマンドの失敗は [`CliExit`] 経由で構造化エラー（`code` / `message`・非ゼロ終了コード）に統一済み（TASK-95.2・ERR-1）。
//!   ライフサイクル操作の失敗のみ ERR-2 の `op` 付き形式を保つ。JSON Lines への統一は ERR-4（TASK-98）。

use std::ffi::OsString;
use std::io::Write;

use fandhe_container_core::oci_runtime::{
    OCI_EXIT_INVALID_ARGUMENT, OCI_EXIT_UNIMPLEMENTED, OciRuntimeError,
};
use fandhe_container_core::traits::{ErrorCode, TraitError};

use fandhe_container_supervisor::logs::FOLLOW_OUTRAN_MESSAGE;

use crate::doctor::DoctorExitStatus;
use crate::error::CliError;

mod args;
mod create_network;
mod create_options;
mod create_pasta;
mod create_start;
mod image;
mod image_refs;
mod kill_signal;
mod list_logs;
mod oci_recorder;
mod ref_reconcile;
// Linux は plugin を介さず core を直接呼ぶため、本番ビルドでは除外する（単体テストは OS 非依存ロジックの検証に使う）。
#[cfg(any(not(target_os = "linux"), test))]
mod plugin_backend;
mod stop_delete;
// start の実処理（supervisor の起動と結果の受信）。unix 固有の std API を使うため Linux の本番ビルドだけに含める。
#[cfg(target_os = "linux")]
mod supervisor_start;

use args::{
    parse_create, parse_delete, parse_doctor, parse_global, parse_image, parse_inspect, parse_kill,
    parse_list, parse_logs, parse_setup, parse_start, parse_state, parse_stop, parse_system,
};

/// コマンドの区分（CLI-2・TASK-80.2）。日常操作は OS 固有設定を持たず、OS 固有設定は `setup` にのみ置く。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKind {
    /// 日常操作（create / start / stop / kill / delete / list / logs / image / system）。`crate::setup` を参照しない。
    Daily,
    /// OS 固有設定のセットアップ（`setup`）。
    Setup,
    /// 読み取り専用の診断（`doctor`。#2133・NET-10・CORE-3）。日常操作でも OS 設定でもなく、`crate::setup` を参照しない。
    Diagnostic,
}

/// 基本コマンド（CLI-1）と setup（CLI-2）。日常操作か否かの区分は [`Command::kind`] で判定する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Create,
    Start,
    Stop,
    /// 指定シグナルを 1 回送る（`kill <id> [<signal>]`。終了は待たず状態も変えない。#1902・CLI-1）。
    Kill,
    Delete,
    List,
    Logs,
    /// コンテナ状態の機械可読な出力(`inspect <id>`。supervisor の `inspect::InspectReport` を 1 行 JSON で出す。
    /// 起動時に適用した capability 集合を含む。#2775・CLI-1・SUP-11・SEC-1)。
    Inspect,
    /// OCI Runtime Spec の state の項目へ寄せた機械可読な状態(`state <id>`。supervisor の `inspect::InspectReport` を
    /// `ociVersion`・`id`・`status`・`pid`・`bundle`・`annotations` の 1 行 JSON で出す。SUP-11 の拡張項目は `inspect` だけ。#1903・CLI-1・SUP-11)。
    State,
    /// イメージ管理（`image ls` / `image rm` / `image tag`。#2221・#2316・CLI-1・OCI-7。サブコマンドは `args::ImageArgs`）。
    Image,
    /// システム情報（`system df`。#2221・CLI-1・OCI-7。サブコマンドは `args::SystemArgs`）。
    System,
    /// OS 固有設定のセットアップ（TASK-80.1・CLI-2。日常操作ではない）。
    Setup,
    /// 読み取り専用の診断（NET-10・CORE-3。#2133。状態ルートを開かず plugin も解決しない）。
    Doctor,
}

impl Command {
    /// 全コマンド（コマンド名の列挙順の SSOT）。
    pub const ALL: [Command; 13] = [
        Command::Create,
        Command::Start,
        Command::Stop,
        Command::Kill,
        Command::Delete,
        Command::List,
        Command::Logs,
        Command::Inspect,
        Command::State,
        Command::Image,
        Command::System,
        Command::Setup,
        Command::Doctor,
    ];

    /// 日常操作コマンドのみ（`ALL` から `Setup` と `Doctor` を除いたもの。分離の照合の列挙元。TASK-80.2・TASK-80.3）。
    pub const DAILY: [Command; 11] = [
        Command::Create,
        Command::Start,
        Command::Stop,
        Command::Kill,
        Command::Delete,
        Command::List,
        Command::Logs,
        Command::Inspect,
        Command::State,
        Command::Image,
        Command::System,
    ];

    /// コマンドの区分。ワイルドカードを使わず、コマンド追加時に分類漏れをコンパイルエラーにする。
    pub fn kind(self) -> CommandKind {
        match self {
            Command::Create
            | Command::Start
            | Command::Stop
            | Command::Kill
            | Command::Delete
            | Command::List
            | Command::Logs
            | Command::Inspect
            | Command::State
            | Command::Image
            | Command::System => CommandKind::Daily,
            Command::Setup => CommandKind::Setup,
            Command::Doctor => CommandKind::Diagnostic,
        }
    }

    /// CLI 上のコマンド名。
    pub fn as_str(self) -> &'static str {
        match self {
            Command::Create => "create",
            Command::Start => "start",
            Command::Stop => "stop",
            Command::Kill => "kill",
            Command::Delete => "delete",
            Command::List => "list",
            Command::Logs => "logs",
            Command::Inspect => "inspect",
            Command::State => "state",
            Command::Image => "image",
            Command::System => "system",
            Command::Setup => "setup",
            Command::Doctor => "doctor",
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
    /// `doctor` の診断が済んだ（#2133）。診断は stdout へ JSON Lines で書き済みで、終了コードは
    /// [`DoctorExitStatus::code`](crate::doctor::DoctorExitStatus::code)（0 / 3 / 4、書き込み失敗は 1）。stderr には何も書かない。
    Diagnosed(DoctorExitStatus),
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
    /// 非 Linux の plugin 解決失敗だけは `list_logs::store_open_failure` が先に拾い、`plugin_backend` の固定文言表を使う。
    pub(crate) fn failed(code: ErrorCode) -> Self {
        CliExit::Error(CliError::new(code, failure_message(code)))
    }

    /// 状態ルートの親ディレクトリが存在しない（終了コード 3・`NOT_FOUND`）。
    ///
    /// core の `FileStateStore::open` は状態ルート自体が無ければ 0700 で作るため、開く段階の `NotFound` は
    /// 「状態ルートの親が無い」ときだけ出る（#1607 E1・ERR-1）。コンテナ不在（`failed(NotFound)`、文言
    /// `container not found`）と区別するための専用値で、`list` / `logs` が状態ストアを開く段階の
    /// `NotFound` だけに使う（コンテナ ID を参照していない失敗）。
    pub(crate) fn state_root_parent_not_found() -> Self {
        CliExit::Error(CliError::new(
            ErrorCode::NotFound,
            STATE_ROOT_PARENT_NOT_FOUND_MESSAGE,
        ))
    }

    /// 状態ストアに破損レコードがあり、`list` が fail-closed で失敗した（OCI-5・ERR-1・#1607 E3）。
    ///
    /// `code` は list が返したエラーのもの（終了コードもそれに従う）。文言だけを回復手段を示す固定文言に替える。
    /// ID・パスは含めない。呼び出し元は core の `find_corrupted` で破損の存在を確かめた場合に限る。
    pub(crate) fn state_store_corrupted(code: ErrorCode) -> Self {
        CliExit::Error(CliError::new(code, STATE_STORE_CORRUPTED_MESSAGE))
    }

    /// `logs` のコンテナログ読み出しの失敗（#1543・CLI-1・SUP-7）。コードは supervisor の読み出しが返したもの
    /// （`Internal` / `Unavailable` / `FailedPrecondition`）で、終了コードはそれに従う。文言は固定表のみ
    /// （`e` のメッセージは出さない。`Unavailable` のうち追従が追いつかない場合だけ、supervisor の固定文言との完全一致で
    /// 専用の文言へ写す）。ログ側の `NotFound` は「コンテナ不在」と誤報しないよう `Internal` へ寄せる。
    pub(crate) fn container_log_failed(e: &TraitError) -> Self {
        let code = e.code();
        let message = match code {
            ErrorCode::Unavailable if e.message() == FOLLOW_OUTRAN_MESSAGE => {
                CONTAINER_LOG_OUTRAN_MESSAGE
            }
            ErrorCode::Unavailable => CONTAINER_LOG_ROTATING_MESSAGE,
            ErrorCode::FailedPrecondition => CONTAINER_LOG_LIMIT_MESSAGE,
            _ => CONTAINER_LOG_UNREADABLE_MESSAGE,
        };
        let code = match code {
            ErrorCode::Unavailable | ErrorCode::FailedPrecondition => code,
            _ => ErrorCode::Internal,
        };
        CliExit::Error(CliError::new(code, message))
    }

    /// プロセスの終了コード。
    pub fn exit_code(&self) -> u8 {
        match self {
            CliExit::Success => 0,
            CliExit::Runtime(e) => e.exit_code().get(),
            CliExit::Error(e) => e.exit_code().get(),
            CliExit::Diagnosed(s) => s.code(),
        }
    }

    /// 失敗の機械可読なエラーコード文字列（成功は `None`）。
    pub fn code(&self) -> Option<&'static str> {
        match self {
            CliExit::Success => None,
            CliExit::Runtime(e) => Some(e.code().as_str()),
            CliExit::Error(e) => Some(e.code_str()),
            CliExit::Diagnosed(_) => None,
        }
    }

    /// stderr へ失敗の 1 行 JSON（LF 終端）を書く。成功では何も書かない。
    ///
    /// 行本体と LF を 1 つのバッファにまとめ、`write_all` で全量を書こうとする（`CliError::write_stderr`・
    /// `OciRuntimeError::write_json_line`）。`writeln!` は書式の断片ごとに write を分けうるための措置で、
    /// 他プロセスの出力との不可分性は保証しない（部分書き込みでは複数回の write に分かれうる。
    /// `O_APPEND` の共有ログへの 1 回の write〔`create_start::write_ops_once`〕とは別。ERR-1）。
    pub fn write_stderr(&self, out: &mut dyn Write) -> std::io::Result<()> {
        match self {
            CliExit::Success | CliExit::Diagnosed(_) => Ok(()),
            CliExit::Runtime(e) => e.write_json_line(out),
            CliExit::Error(e) => e.write_stderr(out),
        }
    }
}

const USAGE_MESSAGE: &str = "usage: fandhe-container <create|start|stop|kill|delete|list|logs|inspect|state|image|system|setup|doctor>";
const STATE_ROOT_PARENT_NOT_FOUND_MESSAGE: &str = "parent of the state root not found";
/// 回復手段（core の `purge_corrupted`）を管理操作名で示す。通常ファイルの entry や中身のある state.json ディレクトリは core が FailedPrecondition で拒否するため、拒否時は管理者による確認・手動回復を促す（core の削除防御は維持）。CLI に purge サブコマンドは無い（実在しない名を案内しない）。
const STATE_STORE_CORRUPTED_MESSAGE: &str = "state store has a corrupted record; recover it with the purge_corrupted management operation, or if that is refused, ask an administrator to inspect and repair it manually";
const UNIMPLEMENTED_MESSAGE: &str = "command is not implemented yet";
const CONTAINER_LOG_UNREADABLE_MESSAGE: &str = "container log could not be read";
const CONTAINER_LOG_ROTATING_MESSAGE: &str = "container log is rotating; retry";
const CONTAINER_LOG_LIMIT_MESSAGE: &str = "container log exceeds the read limit";
const CONTAINER_LOG_OUTRAN_MESSAGE: &str = "container log rotated faster than it could be followed";

/// [`CliExit::failed`] の固定文言表（`ErrorCode::ALL` と同数。`Internal` も明示。試験が網羅と
/// 重複なしを照合する。REPAIR-1・ERR-1）。引用符・バックスラッシュ・制御文字を含まない定数のみ。
const FAILURE_MESSAGES: [(ErrorCode, &str); 10] = [
    (ErrorCode::InvalidArgument, "invalid argument"),
    (ErrorCode::NotFound, "container not found"),
    (ErrorCode::AlreadyExists, "already exists"),
    (ErrorCode::FailedPrecondition, "failed precondition"),
    (ErrorCode::Unimplemented, "not implemented on this platform"),
    (ErrorCode::Internal, "operation failed"),
    (ErrorCode::PermissionDenied, "permission denied"),
    (ErrorCode::Timeout, "operation timed out"),
    (ErrorCode::Unavailable, "unavailable"),
    (ErrorCode::ResourceExhausted, "resource exhausted"),
];

/// [`CliExit::failed`] の固定文言を表から引く。`ErrorCode` は `#[non_exhaustive]` のため、
/// 表に無い将来の code は汎用文言（`Internal` と同じ）に落とす。
fn failure_message(code: ErrorCode) -> &'static str {
    FAILURE_MESSAGES
        .iter()
        .find(|(c, _)| *c == code)
        .map_or("operation failed", |(_, m)| m)
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
    // `--pasta-path` / `--pasta-path-search` は create だけに効く。他のサブコマンド（setup・doctor を含む）では
    // 黙って受けずに拒否する（rootless-network.md 12.4・NET-9・CLI-1・#3199）。
    if global.pasta.is_some() && !matches!(command, Command::Create) {
        return CliExit::Error(CliError::new(
            ErrorCode::InvalidArgument,
            create_pasta::MSG_FLAG_NOT_CREATE,
        ));
    }
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
        Command::Kill => match parse_kill(tail) {
            Ok(a) => stop_delete::run_kill(&global, &a),
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
            Ok(a) => list_logs::run_logs(&global, &a, stdout),
            Err(_) => usage(),
        },
        Command::Inspect => match parse_inspect(tail) {
            Ok(a) => list_logs::run_inspect(&global, &a, stdout),
            Err(_) => usage(),
        },
        Command::State => match parse_state(tail) {
            Ok(a) => list_logs::run_state(&global, &a, stdout),
            Err(_) => usage(),
        },
        Command::Image => match parse_image(tail) {
            Ok(a) => image::run_image(&global, &a, stdout),
            Err(_) => usage(),
        },
        Command::System => match parse_system(tail) {
            Ok(a) => image::run_system(&global, &a, stdout),
            Err(_) => usage(),
        },
        Command::Setup => run_setup(tail, stdout),
        Command::Doctor => run_doctor(tail, stdout),
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

/// `doctor` の実行（#2133・NET-10・CORE-3）。状態ルートも plugin も使わないため `GlobalArgs` を受け取らない
/// （グローバルオプションは受理して無視する。`setup` と同じ）。診断は `stdout` へ書き、stderr は使わない。
fn run_doctor(tail: Vec<OsString>, stdout: &mut dyn Write) -> CliExit {
    match parse_doctor(tail) {
        Ok(_) => CliExit::Diagnosed(crate::doctor::run(stdout)),
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
        assert_eq!(Command::parse("kill"), Some(Command::Kill));
        assert_eq!(Command::parse("delete"), Some(Command::Delete));
        assert_eq!(Command::parse("list"), Some(Command::List));
        assert_eq!(Command::parse("logs"), Some(Command::Logs));
        assert_eq!(Command::parse("inspect"), Some(Command::Inspect));
        assert_eq!(Command::parse("state"), Some(Command::State));
        assert_eq!(Command::parse("image"), Some(Command::Image));
        assert_eq!(Command::parse("system"), Some(Command::System));
        assert_eq!(Command::parse("setup"), Some(Command::Setup));
        assert_eq!(Command::parse("doctor"), Some(Command::Doctor));
    }

    /// CLI-2: `setup` だけが `Setup` 区分、`doctor` だけが `Diagnostic` 区分で、他 11 件は日常操作。
    #[test]
    fn cli2_command_kind_classification() {
        let daily: Vec<&str> = Command::ALL
            .iter()
            .filter(|c| c.kind() == CommandKind::Daily)
            .map(|c| c.as_str())
            .collect();
        assert_eq!(
            daily,
            [
                "create", "start", "stop", "kill", "delete", "list", "logs", "inspect", "state",
                "image", "system"
            ]
        );
        assert_eq!(Command::Setup.kind(), CommandKind::Setup);
        assert_eq!(Command::Doctor.kind(), CommandKind::Diagnostic);
    }

    /// CLI-2: `DAILY` は `ALL` から `Setup` と `Doctor` を除いたものと一致する。
    #[test]
    fn cli2_daily_is_all_minus_setup() {
        let names: Vec<&str> = Command::DAILY.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            names,
            [
                "create", "start", "stop", "kill", "delete", "list", "logs", "inspect", "state",
                "image", "system"
            ]
        );
        let rest: Vec<Command> = Command::ALL
            .into_iter()
            .filter(|c| !matches!(c.kind(), CommandKind::Setup | CommandKind::Diagnostic))
            .collect();
        assert_eq!(rest, Command::DAILY.to_vec());
    }

    /// CLI-1: 全コマンド名の並び。
    #[test]
    fn cli1_all_names_order() {
        let names: Vec<&str> = Command::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            names,
            [
                "create", "start", "stop", "kill", "delete", "list", "logs", "inspect", "state",
                "image", "system", "setup", "doctor"
            ]
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
            args(&["kill"]),
            args(&["kill", "a", "b", "c"]),
            args(&["kill", "--x", "c1"]),
            args(&["kill", "-9", "c1"]),
            args(&["delete"]),
            args(&["stop", "a", "b"]),
            args(&["delete", "--x", "a"]),
            args(&["logs"]),
            args(&["logs", "a", "b"]),
            args(&["logs", "--x", "a"]),
            args(&["list", "x"]),
            args(&["list", "--all"]),
            args(&["image"]),
            args(&["image", "bogus"]),
            args(&["image", "ls"]),
            args(&["image", "ls", "--image-root", "rel"]),
            args(&["image", "rm", "x"]),
            args(&["image", "tag", "x"]),
            args(&["system"]),
            args(&["system", "bogus"]),
            args(&["system", "df"]),
            args(&["setup", "x"]),
            args(&["setup", "--x"]),
            args(&["doctor", "x"]),
            args(&["doctor", "--x"]),
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
        let usage_line = "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"usage: fandhe-container <create|start|stop|kill|delete|list|logs|inspect|state|image|system|setup|doctor>\"}\n";
        let mut covered = Vec::new();
        for command in Command::ALL {
            // 状態ストアを開く前（引数解析）で失敗する argv。OS に依存しない。
            let argv: Vec<&str> = match command {
                Command::Create => vec!["create"],
                Command::Start => vec!["start"],
                Command::Stop => vec!["stop", "a", "b"],
                Command::Kill => vec!["kill"],
                Command::Delete => vec!["delete", "--x", "a"],
                Command::List => vec!["list", "x"],
                Command::Logs => vec!["logs"],
                Command::Inspect => vec!["inspect"],
                Command::State => vec!["state"],
                Command::Image => vec!["image", "bogus"],
                Command::System => vec!["system", "bogus"],
                Command::Setup => vec!["setup", "x"],
                Command::Doctor => vec!["doctor", "x"],
            };
            assert_eq!(argv[0], command.as_str());
            let exit = run(args(&argv));
            assert_structured_failure(&exit, 2, "INVALID_ARGUMENT");
            assert_eq!(stderr_of(&exit), usage_line, "{argv:?}");
            covered.push(command.as_str());
        }
        assert_eq!(
            covered,
            [
                "create", "start", "stop", "kill", "delete", "list", "logs", "inspect", "state",
                "image", "system", "setup", "doctor"
            ]
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
            (ErrorCode::ResourceExhausted, 10),
        ];
        assert_eq!(codes.len(), ErrorCode::ALL.len());
        assert_eq!(FAILURE_MESSAGES.len(), ErrorCode::ALL.len());
        for c in ErrorCode::ALL {
            assert!(codes.iter().any(|(k, _)| *k == c), "{}", c.as_str());
            let hits = FAILURE_MESSAGES.iter().filter(|(k, _)| *k == c).count();
            assert_eq!(hits, 1, "{}", c.as_str());
        }
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

    /// ERR-1: 固定文言の失敗は行本体と LF がモックの出力先へ 1 回の write で渡ることを確認する（他プロセスとの不可分性の保証ではない）。
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
                "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"usage: fandhe-container <create|start|stop|kill|delete|list|logs|inspect|state|image|system|setup|doctor>\"}\n",
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
                CliExit::state_root_parent_not_found(),
                "{\"code\":\"NOT_FOUND\",\"message\":\"parent of the state root not found\"}\n",
            ),
            (
                CliExit::state_store_corrupted(ErrorCode::Internal),
                "{\"code\":\"INTERNAL\",\"message\":\"state store has a corrupted record; recover it with the purge_corrupted management operation, or if that is refused, ask an administrator to inspect and repair it manually\"}\n",
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
    /// 6 コマンドそれぞれ直接呼んで検証する。本番 launcher は fail-closed のため
    /// プロセス起動は発生せず、signaler は supervisor 不在で UNAVAILABLE になりシグナル送信は発生しない。全呼び出しは `invoke` が `--root <TmpDir>` を強制し、
    /// 利用者の実状態ルートへ触れない。環境変数は変更しない（並列テストとの競合回避）。
    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// 空のイメージストアに対する `system df` の出力（固定 9 行。値はすべて 0）。
        const SYSTEM_DF_EMPTY: &str = "KEY\tVALUE\nimages.count\t0\nimages.bytes\t0\nimages.reclaimable_bytes\t0\nimages.missing_blobs\t0\ncache.blob_count\t0\ncache.bytes\t0\ncache.unregistered_count\t0\ncache.unregistered_bytes\t0\ncache.foreign_entries\t0\n";

        struct TmpDir(
            PathBuf,
            #[allow(dead_code)] crate::scratch_root::ScratchDir, // 保持が目的（drop で親を消す）
        );

        impl TmpDir {
            fn new(tag: &str) -> Self {
                static SEQ: AtomicUsize = AtomicUsize::new(0);
                let n = SEQ.fetch_add(1, Ordering::SeqCst);
                let scratch = crate::scratch_root::ScratchDir::new(
                    "fc-cli-cmd",
                    std::time::Duration::from_secs(10),
                );
                let p = scratch.path().join(format!("{tag}-{n}"));
                std::fs::create_dir(&p).expect("mkdir");
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
                        .expect("chmod");
                }
                Self(p, scratch)
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

        /// CLI-1・SUP-11(#2775): created のコンテナの inspect は 1 行の JSON(末尾 LF)で、キー順は固定、
        /// start 前なので capabilities は null。不在は NOT_FOUND(3)。
        #[test]
        fn cli1_inspect_prints_one_line_json_on_linux() {
            let base = TmpDir::new("inspect");
            let root = base.state_root();
            create_ok(&base, "i1");
            let o = invoke(&root, &["inspect", "i1"]);
            assert_eq!((o.exit, o.stderr.as_str()), (0, ""), "{}", o.stderr);
            assert!(o.stdout.ends_with("}\n"), "{:?}", o.stdout);
            assert_eq!(o.stdout.matches('\n').count(), 1, "{:?}", o.stdout);
            assert!(
                o.stdout
                    .starts_with("{\"id\":\"i1\",\"status\":\"created\",\"pid\":null,"),
                "{:?}",
                o.stdout
            );
            assert!(
                o.stdout
                    .ends_with(",\"explicitStop\":\"not_recorded\",\"capabilities\":null,\"rootReadonly\":null}\n"),
                "{:?}",
                o.stdout
            );
            let o = invoke(&root, &["inspect", "none"]);
            assert_eq!((o.exit, o.code), (3, Some("NOT_FOUND")));
            assert_eq!(o.stdout, "");
        }

        /// CLI-1・SUP-11(#1903): created のコンテナの state は OCI の項目だけの 1 行 JSON(末尾 LF)。
        /// start 前なので pid は省かれる。不在は NOT_FOUND(3)、不正 ID は INVALID_ARGUMENT(2)。状態は書き換えない。
        #[test]
        fn cli1_state_prints_oci_state_on_linux() {
            let base = TmpDir::new("state");
            let root = base.state_root();
            create_ok(&base, "s1");
            let o = invoke(&root, &["state", "s1"]);
            assert_eq!((o.exit, o.stderr.as_str()), (0, ""), "{}", o.stderr);
            assert_eq!(o.stdout.matches('\n').count(), 1, "{:?}", o.stdout);
            assert!(
                o.stdout.starts_with(
                    "{\"ociVersion\":\"1.3.0\",\"id\":\"s1\",\"status\":\"created\",\"bundle\":\"/"
                ),
                "{:?}",
                o.stdout
            );
            // Linux の create は既定の `network none` を文書に書くため、作成世代の注釈だけを持つ(#1873・D4)。
            assert!(
                o.stdout
                    .contains(",\"annotations\":{\"io.fandhe.container.options-generation\":\""),
                "{:?}",
                o.stdout
            );
            assert!(o.stdout.ends_with("\"}}\n"), "{:?}", o.stdout);
            assert!(!o.stdout.contains("\"pid\""), "{:?}", o.stdout);
            // 読み取りだけなので 2 回目も同じ出力(revision を進めない)。
            let again = invoke(&root, &["state", "s1"]);
            assert_eq!(again.stdout, o.stdout);
            let o = invoke(&root, &["state", "none"]);
            assert_eq!((o.exit, o.code), (3, Some("NOT_FOUND")));
            assert_eq!(o.stdout, "");
            let o = invoke(&root, &["state", "bad/id"]);
            assert_eq!((o.exit, o.code), (2, Some("INVALID_ARGUMENT")));
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

        /// CLI-1・ERR-2・REPAIR-3: start は未作成で NOT_FOUND（3）。作成済みでも、テスト実行ファイルの隣に
        /// 固定名の supervisor が無いため FAILED_PRECONDITION（5）で、状態は Created・pid なしのまま（Running を残さない。#1541）。
        #[test]
        fn cli1_run_start_on_linux() {
            let base = TmpDir::new("start");
            let root = base.state_root();

            let o = invoke(&root, &["start", "c1"]);
            assert_eq!(o.exit, 3);
            assert_eq!(op_and_code(&o.stderr), failure("start", "NOT_FOUND"));

            create_ok(&base, "c1");
            let o = invoke(&root, &["start", "c1"]);
            assert_eq!(o.exit, 5);
            assert_eq!(
                op_and_code(&o.stderr),
                failure("start", "FAILED_PRECONDITION")
            );
            assert_eq!(
                (o.stdout.as_str(), o.code),
                ("", Some("FAILED_PRECONDITION"))
            );

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

        /// CLI-1・ERR-2・#1902: kill は未作成で NOT_FOUND（3）、pid なしの Created は FAILED_PRECONDITION（5）、
        /// 不正な ID・シグナルは INVALID_ARGUMENT（2）。失敗 JSON の op は `kill`。
        #[test]
        fn cli1_run_kill_on_linux() {
            let base = TmpDir::new("kill");
            let root = base.state_root();

            let o = invoke(&root, &["kill", "c1"]);
            assert_eq!(o.exit, 3);
            assert_eq!(op_and_code(&o.stderr), failure("kill", "NOT_FOUND"));

            create_ok(&base, "c1");
            for argv in [&["kill", "c1"][..], &["kill", "c1", "KILL"]] {
                let o = invoke(&root, argv);
                assert_eq!(o.exit, 5, "{argv:?}");
                assert_eq!(
                    op_and_code(&o.stderr),
                    failure("kill", "FAILED_PRECONDITION")
                );
            }
            assert!(root.join("c1").join("state.json").is_file());

            let o = invoke(&root, &["kill", "a/b"]);
            assert_eq!((o.exit, o.code), (2, Some("INVALID_ARGUMENT")));
            let o = invoke(&root, &["kill", "c1", "BOGUS"]);
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

        /// CLI-1・SUP-7・ERR-2: logs は未作成で NOT_FOUND（3）、作成済みでログが無ければ空の成功（0）、
        /// 世代をまたぐログは古い順にバイト単位で出る。symlink の世代は INTERNAL（1）の固定文言。
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
            assert_eq!((o.exit, o.stdout.as_str(), o.stderr.as_str()), (0, "", ""));

            let dir = fandhe_container_supervisor::logs::container_log_dir(&root);
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::create_dir_all(&dir).expect("logdir");
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
            }
            std::fs::write(dir.join("c1.log.2"), b"stdout a\n").expect("g2");
            std::fs::write(dir.join("c1.log.1"), b"stderr b\n").expect("g1");
            std::fs::write(dir.join("c1.log"), b"stdout c\x1b[0m\n").expect("cur");
            std::fs::write(dir.join("c1.log.lock"), b"").expect("lock");
            let o = invoke(&root, &["logs", "c1"]);
            assert_eq!(o.exit, 0);
            assert_eq!(o.stdout, "stdout a\nstderr b\nstdout c\x1b[0m\n");
            assert_eq!(o.stderr, "");

            std::fs::remove_file(dir.join("c1.log.1")).expect("rm");
            std::fs::write(dir.join("target"), b"secret\n").expect("target");
            std::os::unix::fs::symlink(dir.join("target"), dir.join("c1.log.1")).expect("link");
            let o = invoke(&root, &["logs", "c1"]);
            assert_eq!(o.exit, 1);
            assert_eq!(o.stdout, "");
            assert_eq!(
                o.stderr,
                "{\"code\":\"INTERNAL\",\"message\":\"container log could not be read\"}\n"
            );

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
                    "{\"code\":\"NOT_FOUND\",\"message\":\"parent of the state root not found\"}\n"
                );
            }

            let cases: [(&[&str], &str); 5] = [
                (&["create", "--bundle", b, "c1"], "create"),
                (&["start", "c1"], "start"),
                (&["stop", "c1"], "kill"),
                (&["kill", "c1"], "kill"),
                (&["delete", "c1"], "delete"),
            ];
            for (argv, op) in cases {
                let o = invoke(&root, argv);
                assert_eq!(o.exit, 3, "{argv:?}");
                assert_eq!(op_and_code(&o.stderr), failure(op, "NOT_FOUND"), "{argv:?}");
            }
            assert!(!parent.exists());
        }

        /// CLI-1・#1607 E2: 親があり状態ルートが無いとき、list は終了コード 0・ヘッダのみで、
        /// ルートを 0700 で作る（読み取り専用コマンドでも open が作る副作用の機械照合。親は作らない）。
        #[test]
        fn cli1_list_creates_absent_state_root_on_linux() {
            use std::os::unix::fs::PermissionsExt;
            let base = TmpDir::new("absentroot");
            let root = base.state_root();
            assert!(!root.exists());
            let o = invoke(&root, &["list"]);
            assert_eq!(o.exit, 0, "{}", o.stderr);
            assert_eq!(o.stdout, "ID\tSTATUS\tPID\n");
            assert_eq!(o.stderr, "");
            assert!(root.is_dir());
            let mode = std::fs::metadata(&root).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }

        /// ERR-1・OCI-5・#1607 E3: 破損レコードがあると list は回復手段を示す固定文言で失敗し、
        /// 回復（purge_corrupted）後は成功に戻る。内容破損は INTERNAL（1）、非ディレクトリ entry は PERMISSION_DENIED（6）。
        #[test]
        fn err1_list_corrupted_record_points_to_recovery_on_linux() {
            use fandhe_container_core::state_store::{FileStateStore, StateRoot};
            use fandhe_container_core::traits::ContainerId;
            let base = TmpDir::new("corrupt");
            let root = base.state_root();
            create_ok(&base, "c1");
            std::fs::write(root.join("c1").join("state.json"), "{").expect("corrupt");

            let o = invoke(&root, &["list"]);
            assert_eq!(o.exit, 1);
            assert_eq!(o.code, Some("INTERNAL"));
            assert_eq!(
                o.stderr,
                "{\"code\":\"INTERNAL\",\"message\":\"state store has a corrupted record; recover it with the purge_corrupted management operation, or if that is refused, ask an administrator to inspect and repair it manually\"}\n"
            );
            assert_eq!(o.stdout, "ID\tSTATUS\tPID\n");

            let store = FileStateStore::open(StateRoot::from_override(root.clone()).expect("root"))
                .expect("open");
            store
                .purge_corrupted(&ContainerId::new("c1").expect("id"))
                .expect("purge");
            let o = invoke(&root, &["list"]);
            assert_eq!((o.exit, o.stderr.as_str()), (0, ""));

            std::fs::write(root.join("zz"), "x").expect("file");
            let o = invoke(&root, &["list"]);
            assert_eq!(o.exit, 6);
            assert_eq!(
                o.stderr,
                "{\"code\":\"PERMISSION_DENIED\",\"message\":\"state store has a corrupted record; recover it with the purge_corrupted management operation, or if that is refused, ask an administrator to inspect and repair it manually\"}\n"
            );
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
                vec!["kill", evil],
                vec!["kill", "c1", evil],
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
                &["kill", "none"],
                &["delete", "none"],
            ] {
                check(&invoke(&root, argv), 3, "NOT_FOUND");
            }
            // list: 状態ルート不在（固定文言で完全一致）。
            let o = invoke(&missing_root, &["list"]);
            check(&o, 3, "NOT_FOUND");
            assert_eq!(
                o.stderr,
                "{\"code\":\"NOT_FOUND\",\"message\":\"parent of the state root not found\"}\n"
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
            // image / system 用のイメージストア root（空。blobs/sha256 だけ作る）。
            let images = base.0.join("images");
            std::fs::create_dir_all(images.join("blobs").join("sha256")).expect("images");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&images, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
            }
            let ir = images.to_str().expect("utf8").to_owned();
            let mut covered = Vec::new();
            for command in Command::ALL {
                // (argv, 期待終了コード, 期待 code(), 期待 stdout)
                let (argv, exit, code, stdout): (Vec<&str>, u8, Option<&str>, &str) = match command
                {
                    Command::Create => (vec!["create", "--bundle", &b, "m1"], 0, None, ""),
                    Command::Start => (vec!["start", "none"], 3, Some("NOT_FOUND"), ""),
                    Command::Stop => (vec!["stop", "none"], 3, Some("NOT_FOUND"), ""),
                    Command::Kill => (vec!["kill", "none"], 3, Some("NOT_FOUND"), ""),
                    Command::Delete => (vec!["delete", "none"], 3, Some("NOT_FOUND"), ""),
                    Command::List => (vec!["list"], 0, None, "ID\tSTATUS\tPID\nm1\tcreated\t-\n"),
                    Command::Logs => (vec!["logs", "none"], 3, Some("NOT_FOUND"), ""),
                    Command::Inspect => (vec!["inspect", "none"], 3, Some("NOT_FOUND"), ""),
                    Command::State => (vec!["state", "none"], 3, Some("NOT_FOUND"), ""),
                    Command::Image => (
                        vec!["image", "ls", "--image-root", &ir],
                        0,
                        None,
                        "REPOSITORY\tTAG\tDIGEST\tSIZE\tMISSING\n",
                    ),
                    Command::System => (
                        vec!["system", "df", "--image-root", &ir],
                        0,
                        None,
                        SYSTEM_DF_EMPTY,
                    ),
                    Command::Setup => (
                        vec!["setup"],
                        0,
                        None,
                        "{\"step\":\"privileged-launcher-install\",\"requires_admin\":true,\"status\":\"manual\",\"condition\":\"rootful\",\"instructions\":\"rootful only; rootless (default) needs no install. As root, run scripts/install-privileged-launcher.sh --launcher <file> --launcher-sha256 <hex> --supervisor <file> --supervisor-sha256 <hex> --cli <file> --cli-sha256 <hex> [--dest-dir <absolute path>] (default dest-dir /usr/local/libexec/fandhe-container). fandhe-container does not run it. See docs/setup/linux.md\"}\n",
                    ),
                    // doctor の終了コードと出力は実行環境に依る（0 / 3 / 4）。具体値は doctor 側の単体テストと
                    // 結合試験で固定し、ここでは診断の終了であること・stderr が空であることだけを照合する。
                    Command::Doctor => {
                        let o = invoke(&root, &["doctor"]);
                        assert!([0, 3, 4].contains(&o.exit), "doctor exit {}", o.exit);
                        assert_eq!(o.code, None);
                        covered.push(command.as_str());
                        continue;
                    }
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
                [
                    "create", "start", "stop", "kill", "delete", "list", "logs", "inspect",
                    "state", "image", "system", "setup", "doctor"
                ]
            );
        }
    }
}
/// `create` の `--network`・`--add-host`・`--dns` を argv から通す試験(NET-12・CLI-1・ERR-1・#1871)。
///
/// cfg で絞らず 3 OS で走る。存在しない `--root` を渡し、拒否が状態ルートの作成より前であることも照合する。
#[cfg(test)]
mod net12_argv_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 存在しない状態ルートを返す(作られていないことを後で照合する)。
    fn fresh_root() -> std::path::PathBuf {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("fc-cli-net12-{}-{n}", std::process::id()))
    }

    /// `create` を実行し (終了コード, code, stderr) を返す。状態ルートが作られていないことも確かめる。
    fn create(extra: &[&str]) -> (u8, Option<&'static str>, String) {
        create_checked(extra, true)
    }

    /// `create` の本体。`root_must_be_absent` が偽なら状態ルートの有無を問わない(検証を通った指定は後段で作られ得る)。
    fn create_checked(
        extra: &[&str],
        root_must_be_absent: bool,
    ) -> (u8, Option<&'static str>, String) {
        let root = fresh_root();
        let mut full: Vec<OsString> = vec!["--root".into(), root.clone().into(), "create".into()];
        full.extend(extra.iter().map(OsString::from));
        full.extend(["--bundle", "/nonexistent-bundle", "c1"].map(OsString::from));
        let mut out = Vec::new();
        let r = run_to(full, &mut out);
        let mut buf = Vec::new();
        r.write_stderr(&mut buf).expect("write");
        let stderr = String::from_utf8(buf).expect("utf8");
        if root_must_be_absent {
            assert!(!root.exists(), "state root must not be created: {extra:?}");
        } else {
            let _ = std::fs::remove_dir_all(&root);
        }
        (r.exit_code(), r.code(), stderr)
    }

    fn assert_invalid(extra: &[&str], leak: &str) {
        let (exit, code, stderr) = create(extra);
        assert_eq!(exit, 2, "{extra:?}: {stderr}");
        assert_eq!(code, Some("INVALID_ARGUMENT"), "{extra:?}");
        assert!(stderr.ends_with('\n'), "{stderr:?}");
        assert_eq!(stderr.matches('\n').count(), 1, "{stderr:?}");
        if !leak.is_empty() {
            assert!(!stderr.contains(leak), "{extra:?} leaked: {stderr}");
        }
    }

    fn assert_unimplemented(extra: &[&str]) {
        let (exit, code, stderr) = create(extra);
        assert_eq!(exit, 8, "{extra:?}: {stderr}");
        assert_eq!(code, Some("UNIMPLEMENTED"), "{extra:?}");
    }

    /// 形式の検証と結線の拒否を通ったこと。Linux は後段(存在しない bundle)で止まり `UNIMPLEMENTED` ではない。
    /// 非 Linux は network 系の指定を固定文言で `UNIMPLEMENTED` にする(状態ルートは作られない)。
    fn assert_past_network_validation(extra: &[&str]) {
        let (exit, code, stderr) = create_checked(extra, !cfg!(target_os = "linux"));
        if cfg!(target_os = "linux") {
            assert_ne!(code, Some("UNIMPLEMENTED"), "{extra:?}: {stderr}");
            assert_ne!(code, Some("INVALID_ARGUMENT"), "{extra:?}: {stderr}");
        } else {
            assert_eq!((exit, code), (8, Some("UNIMPLEMENTED")), "{extra:?}");
        }
    }

    /// TASK-186 の不正入力 8 種(空値・IP でない・空白・ハイフン・ラベル長・総長・改行・制御文字)。
    #[test]
    fn net12_invalid_inputs_rejected_before_any_side_effect() {
        let l63 = "a".repeat(63);
        let l64 = "a".repeat(64);
        let l62 = "a".repeat(62);
        let l61 = "a".repeat(61);
        let host254 = format!("{l63}.{l63}.{l63}.{l62}:192.0.2.1");
        let host253 = format!("{l63}.{l63}.{l63}.{l61}:192.0.2.1");
        let label64 = format!("{l64}:192.0.2.1");
        assert_invalid(&["--add-host", ":192.0.2.1"], "");
        assert_invalid(&["--dns", ""], "");
        assert_invalid(&["--add-host", "web:999.1.1.1"], "999");
        assert_invalid(&["--dns", "example.com"], "example");
        assert_invalid(&["--add-host", "my host:192.0.2.1"], "my host");
        assert_invalid(&["--dns", " 192.0.2.1"], "192.0.2.1");
        assert_invalid(&["--add-host", "-web:192.0.2.1"], "-web");
        assert_invalid(&["--add-host", "web-:192.0.2.1"], "web-");
        assert_invalid(&["--add-host", &label64], &l64);
        assert_invalid(&["--add-host", &host254], &l63);
        assert_past_network_validation(&["--add-host", &host253]);
        assert_invalid(&["--add-host", "web:192.0.2.1\n10.0.0.9 evil"], "evil");
        assert_invalid(&["--dns", "127.0.0.1\nnameserver 8.8.8.8"], "8.8.8.8");
        assert_invalid(&["--add-host", "web\t:192.0.2.1"], "web");
        assert_invalid(&["--add-host", "we\u{1b}b:192.0.2.1"], "we");
    }

    /// `name:::1` は最初の `:` で分割され IPv6 として受理される(検証後に UNIMPLEMENTED)。
    #[test]
    fn net12_add_host_splits_at_first_colon() {
        assert_past_network_validation(&["--add-host", "name:::1"]);
        assert_invalid(&["--add-host", "name::::1"], "");
    }

    /// none では loopback 以外の `--dns` を作成前に拒否する。
    #[test]
    fn net12_none_rejects_non_loopback_dns() {
        assert_invalid(&["--network", "none", "--dns", "192.0.2.1"], "192.0.2.1");
        assert_past_network_validation(&["--network", "none", "--dns", "127.0.0.1"]);
        // 省略は none 扱い(D4)。非 loopback の `--dns` は create の時点で拒否する。
        assert_invalid(&["--dns", "192.0.2.1"], "192.0.2.1");
    }

    /// `--network` の判定と使い方エラー、値が正しくても UNIMPLEMENTED。
    #[test]
    fn net12_network_flag_cases() {
        assert_invalid(&["--network", "bridge"], "");
        assert_unimplemented(&["--network", "container:x"]);
        assert_past_network_validation(&["--network", "host"]);
        assert_past_network_validation(&["--network", "none"]);
        // 使い方エラーは exit 2 の INVALID_ARGUMENT(状態ルートは作られない)。
        assert_invalid(&["--network", "a", "--network", "b"], "");
        assert_invalid(&["--add-host"], "");
    }

    /// NET-9・NET-3(#3200): 不正な `-p` は作成前に INVALID_ARGUMENT(状態ルートは作られず、入力値は出ない)。
    #[test]
    fn net9_publish_invalid_specs_rejected() {
        let n = ["--network", "mynet"];
        for bad in ["[::1]:80:80", "::1:80:80", "80:80/sctp", "0:80", "1-2:80"] {
            let leak = bad.split(':').next().unwrap_or("");
            let argv = [n[0], n[1], "-p", bad];
            assert_invalid(&argv, if leak.len() > 2 { leak } else { "sctp" });
        }
    }

    /// NET-9(#3200): ユーザー定義名と組でない `-p` は INVALID_ARGUMENT(none / host / 指定なし)。
    #[test]
    fn net9_publish_requires_user_defined_network() {
        assert_invalid(&["-p", "8080:80"], "");
        assert_invalid(&["--network", "none", "-p", "8080:80"], "");
        assert_invalid(&["--network", "host", "--publish", "8080:80"], "");
    }

    /// NET-9(#3200): 正しい `-p` + ユーザー定義名は、結線(#1873・#1940)まで UNIMPLEMENTED(受理して捨てない)。
    #[test]
    fn net9_publish_valid_is_unimplemented_until_wired() {
        // 判定順は `check_network_options`(権限モデルの解決: publish が使えない場合の拒否)→ pasta の場所 →
        // `UNIMPLEMENTED`。組み合わせごとに具体値で期待する(NET-9・#3199・#3200)。
        // 非 Linux は権限モデルが `Unavailable` で、pasta の判定より前に `UNIMPLEMENTED` になる。
        // Linux の root は rootful で `UNIMPLEMENTED`、非 root は rootless で pasta 未指定の `FAILED_PRECONDITION`。
        #[cfg(not(target_os = "linux"))]
        let want = (
            "UNIMPLEMENTED",
            "port publishing is not supported on this platform yet",
        );
        #[cfg(target_os = "linux")]
        let want = if std::fs::read_to_string("/proc/self/status")
            .is_ok_and(|s| s.lines().any(|l| l.starts_with("Uid:\t0\t")))
        {
            (
                "UNIMPLEMENTED",
                super::create_network::PUBLISH_ROOTFUL_MESSAGE,
            )
        } else {
            ("FAILED_PRECONDITION", "pasta path is not configured")
        };
        for extra in [
            ["--network", "mynet", "-p", "8080:80"],
            ["--network", "mynet", "--publish", "127.0.0.1:8080:80/udp"],
        ] {
            let (exit, code, stderr) = create(&extra);
            assert_eq!(code, Some(want.0), "{extra:?}: {stderr}");
            assert_ne!(exit, 0, "{extra:?}");
            assert!(stderr.contains(want.1), "{extra:?}: {stderr}");
        }
    }

    /// NET-9(#3200): 件数と 1 件の長さの超過は使い方エラー。
    #[test]
    fn net9_publish_usage_limits() {
        let long = "1".repeat(65);
        assert_invalid(&["--network", "mynet", "-p", long.as_str()], "");
        let mut many: Vec<&str> = vec!["--network", "mynet"];
        for _ in 0..65 {
            many.extend(["-p", "8080:80"]);
        }
        assert_invalid(&many, "");
    }
}
