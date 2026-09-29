//! SIGKILL 耐性テスト（IO-3・TASK-18）用の、子プロセスとして起動するサーバー
//! エントリポイント（TASK-18.1.1・#825）。
//!
//! 役割: `fandhe-container-io` の write-back サーバー（`WritebackSettings::bind` →
//! `accept` → `serve`）を 1 接続だけ処理する実行ファイルとして包み、テスト側が
//! 子プロセスとして起動して SIGKILL で強制終了できるようにする。
//! 呼び出し元は `tests/crash_safety.rs`（TASK-18.1.2 = #826・TASK-18.2 = #95 が拡張）。
//!
//! これはテスト専用の起動ツールであり、本番サーバーではない（REPAIR-3）。
//! 専用 feature `crash-test-server` でのみビルドされ、リリース成果物には入らない。
//! 引数はテストが渡す信頼できるホスト側の設定値として扱う（ゲスト由来の入力ではない）が、
//! パス・名前・数値の検証は io crate の既存実装（`UdsServer::bind`・`AppendFileSink::open_in`・
//! `parse_batch_size` 等）に任せる。
//!
//! # 引数
//!
//! - `--socket <path>`（必須）: bind する UDS。親ディレクトリは 0700、パスは未存在であること
//!   （SIGKILL 後はソケットが残るため、試行ごとに新しいパスを使う）
//! - `--data-dir <dir>` / `--file <name>`（必須）: 出力ファイル（`SinkOpenMode::CreateNew`）
//! - `--batch-size` / `--unflushed-max-frames` / `--unflushed-max-bytes`（任意）
//!
//! # 準備完了の合図
//!
//! bind 成功後、標準出力へ `READY` を 1 行出して flush する。呼び出し側はこの行を期限付きで
//! 待ってから connect する。
//!
//! # 終了コード
//!
//! | code | 意味 |
//! | ---- | ---- |
//! | 0 | `serve` がピアの切断（`UNAVAILABLE`）で終わった |
//! | 2 | 引数エラー |
//! | 3 | 起動処理の失敗（sink open・bind・accept の失敗やタイムアウト） |
//! | 4 | `serve` が `UNAVAILABLE` 以外のエラーで終わった |
//! | 5 | 未対応 OS（Linux / macOS 以外） |
//!
//! 終了時は標準エラーへ JSON を 1 行出す（SIGKILL 時は出ない）。accept・recv・send は
//! すべて `MAX_IO_TIMEOUT` で打ち切るため、孤児プロセスが無期限に残らない（REPAIR-5）。

use std::process::ExitCode;

/// 終了コード: 正常終了（ピア切断）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
const EXIT_OK: u8 = 0;
/// 終了コード: 引数エラー。
#[cfg(any(target_os = "linux", target_os = "macos"))]
const EXIT_USAGE: u8 = 2;
/// 終了コード: 起動処理の失敗。
#[cfg(any(target_os = "linux", target_os = "macos"))]
const EXIT_STARTUP: u8 = 3;
/// 終了コード: `serve` が切断以外で終了。
#[cfg(any(target_os = "linux", target_os = "macos"))]
const EXIT_SERVE: u8 = 4;
/// 終了コード: 未対応 OS。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const EXIT_UNSUPPORTED: u8 = 5;

/// JSON 文字列リテラルの中身用に `"`・`\`・制御文字だけをエスケープする（serde 非依存）。
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod app {
    use std::ffi::OsString;
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::ExitCode;

    use fandhe_container_io::{
        AppendFileSink, BATCH_SIZE_OPTION, IoError, IoErrorCode, IoTimeout, MAX_IO_TIMEOUT,
        NoopServerObserver, SinkOpenMode, UNFLUSHED_MAX_BYTES_OPTION, UNFLUSHED_MAX_FRAMES_OPTION,
        WritebackSettings, WritebackStats, WritebackTimeouts, parse_batch_size,
        parse_unflushed_limit,
    };

    use super::{EXIT_OK, EXIT_SERVE, EXIT_STARTUP, EXIT_USAGE, json_escape};

    /// 受け付ける引数（オプション名と値で 1 個ずつ数える）の個数上限。
    const MAX_ARGS: usize = 16;
    const SOCKET_OPTION: &str = "--socket";
    const DATA_DIR_OPTION: &str = "--data-dir";
    const FILE_OPTION: &str = "--file";

    /// 解析済みの起動引数。
    #[derive(Debug)]
    pub struct ServerArgs {
        socket: PathBuf,
        data_dir: PathBuf,
        file: String,
        batch_size: Option<String>,
        unflushed_frames: Option<String>,
        unflushed_bytes: Option<String>,
    }

    /// 値やパスを含めない `InvalidArgument`（ログ汚染の防止）。
    fn invalid(msg: &str) -> IoError {
        IoError::new(IoErrorCode::InvalidArgument, msg)
    }

    /// 引数列を解析する。重複・不明な引数・値の欠落・非 UTF-8 の値・個数超過は
    /// `InvalidArgument`。
    pub fn parse_args(args: impl Iterator<Item = OsString>) -> Result<ServerArgs, IoError> {
        let mut socket = None;
        let mut data_dir = None;
        let mut file = None;
        let mut batch_size = None;
        let mut frames = None;
        let mut bytes = None;

        let mut it = args.take(MAX_ARGS + 1);
        let mut count = 0usize;
        while let Some(opt) = it.next() {
            let opt = opt
                .into_string()
                .map_err(|_| invalid("option must be valid UTF-8"))?;
            let value = it
                .next()
                .ok_or_else(|| invalid("option requires a value"))?;
            count += 2;
            if count > MAX_ARGS {
                return Err(invalid("too many arguments"));
            }
            match opt.as_str() {
                SOCKET_OPTION => {
                    if socket.replace(PathBuf::from(value)).is_some() {
                        return Err(invalid("duplicate option"));
                    }
                }
                DATA_DIR_OPTION => {
                    if data_dir.replace(PathBuf::from(value)).is_some() {
                        return Err(invalid("duplicate option"));
                    }
                }
                FILE_OPTION
                | BATCH_SIZE_OPTION
                | UNFLUSHED_MAX_FRAMES_OPTION
                | UNFLUSHED_MAX_BYTES_OPTION => {
                    let value = value
                        .into_string()
                        .map_err(|_| invalid("option value must be valid UTF-8"))?;
                    let slot = match opt.as_str() {
                        FILE_OPTION => &mut file,
                        BATCH_SIZE_OPTION => &mut batch_size,
                        UNFLUSHED_MAX_FRAMES_OPTION => &mut frames,
                        _ => &mut bytes,
                    };
                    if slot.replace(value).is_some() {
                        return Err(invalid("duplicate option"));
                    }
                }
                _ => return Err(invalid("unknown option")),
            }
        }

        Ok(ServerArgs {
            socket: socket.ok_or_else(|| invalid("--socket is required"))?,
            data_dir: data_dir.ok_or_else(|| invalid("--data-dir is required"))?,
            file: file.ok_or_else(|| invalid("--file is required"))?,
            batch_size,
            unflushed_frames: frames,
            unflushed_bytes: bytes,
        })
    }

    fn stats_json(s: &WritebackStats) -> String {
        format!(
            "{{\"frames_received\":{},\"acks_sent\":{},\"flush_acks_sent\":{},\"persist_succeeded\":{},\"persist_failed\":{},\"auto_flushes\":{},\"discarded_pending_frames\":{}}}",
            s.frames_received,
            s.acks_sent,
            s.flush_acks_sent,
            s.persist_succeeded,
            s.persist_failed,
            s.auto_flushes,
            s.discarded_pending_frames
        )
    }

    /// 終了理由を標準エラーへ JSON 1 行で出す（機械可読な code / message。ERR 系）。
    fn report_exit(err: &IoError, stats: Option<&WritebackStats>) {
        let stats = stats.map_or_else(|| "null".to_string(), stats_json);
        eprintln!(
            "{{\"event\":\"exit\",\"code\":\"{}\",\"message\":\"{}\",\"stats\":{}}}",
            err.code().as_str(),
            json_escape(err.message()),
            stats
        );
    }

    /// 終了コードと理由。`serve` の終了は常にエラー（ピア切断を含む）なので、
    /// 起動〜終了の全経路をこの型で返す。
    struct Exit {
        code: u8,
        error: IoError,
        stats: Option<WritebackStats>,
    }

    fn startup_failure(error: IoError) -> Exit {
        Exit {
            code: EXIT_STARTUP,
            error,
            stats: None,
        }
    }

    fn usage_failure(error: IoError) -> Exit {
        Exit {
            code: EXIT_USAGE,
            error,
            stats: None,
        }
    }

    fn run_server(args: &ServerArgs) -> Exit {
        let batch = match &args.batch_size {
            Some(v) => match parse_batch_size(v) {
                Ok(b) => b,
                Err(e) => return usage_failure(e),
            },
            None => WritebackSettings::default().batch_config(),
        };
        let limit = match parse_unflushed_limit(
            args.unflushed_frames.as_deref(),
            args.unflushed_bytes.as_deref(),
        ) {
            Ok(l) => l,
            Err(e) => return usage_failure(e),
        };
        let settings = WritebackSettings::new(batch).with_unflushed_limit(limit);

        // READY を出す前に起動エラーをすべて確定させるため、sink を bind より先に開く。
        let mut sink =
            match AppendFileSink::open_in(&args.data_dir, &args.file, SinkOpenMode::CreateNew) {
                Ok(s) => s,
                Err(e) => return startup_failure(e),
            };
        let mut bound = match settings.bind(&args.socket, NoopServerObserver) {
            Ok(b) => b,
            Err(e) => return startup_failure(e),
        };

        let mut out = std::io::stdout();
        if writeln!(out, "READY").and_then(|()| out.flush()).is_err() {
            return startup_failure(IoError::new(IoErrorCode::Internal, "failed to write READY"));
        }

        let timeout = match IoTimeout::new(MAX_IO_TIMEOUT) {
            Ok(t) => t,
            Err(e) => return startup_failure(e),
        };
        let mut conn = match bound.accept(timeout, NoopServerObserver) {
            Ok(c) => c,
            Err(e) => return startup_failure(e),
        };
        let report = conn.serve(
            &mut sink,
            WritebackTimeouts {
                recv: timeout,
                send: timeout,
            },
        );
        let code = if report.end.code() == IoErrorCode::Unavailable {
            EXIT_OK
        } else {
            EXIT_SERVE
        };
        Exit {
            code,
            error: report.end,
            stats: Some(report.stats),
        }
    }

    pub fn run() -> ExitCode {
        let args = match parse_args(std::env::args_os().skip(1)) {
            Ok(a) => a,
            Err(e) => {
                report_exit(&e, None);
                return ExitCode::from(EXIT_USAGE);
            }
        };
        let exit = run_server(&args);
        report_exit(&exit.error, exit.stats.as_ref());
        ExitCode::from(exit.code)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() -> ExitCode {
    app::run()
}

/// 未対応 OS: `UdsServer` は Linux / macOS 専用（IO-1）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() -> ExitCode {
    eprintln!(
        "{{\"event\":\"exit\",\"code\":\"UNIMPLEMENTED\",\"message\":\"{}\",\"stats\":null}}",
        json_escape("crash_test_server requires a UDS server (Linux or macOS)")
    );
    ExitCode::from(EXIT_UNSUPPORTED)
}
