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
//! - `--sink <append-file|deferred>`（任意。既定 `append-file`）: 書き込み先の sink。
//!   `append-file` は製品の `AppendFileSink`（通常 ACK は `write()` 完了後に返る）。
//!   `deferred` は試験専用の `DeferredPersistSink` で、`BatchSink::persist` が呼ばれるまで
//!   書き込みをメモリに保持しファイルへは書かない（TASK-18 追補・#1832）。これにより
//!   「ACK 済みだが未書き込み」の状態を作り、`persist` の有無で SIGKILL 後の結果が変わる
//!   対照を成立させる。製品の ACK 順序・`serve_connection`・`AppendFileSink` は変えない
//!   （試験専用 sink はこの bin の中だけにあり、リリース成果物には入らない）
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
//! | 0 | `serve` がフレーム境界でのピア切断（`UNAVAILABLE`・正常切断）で終わった |
//! | 2 | 引数エラー |
//! | 3 | 起動処理の失敗（sink open・bind・accept の失敗やタイムアウト） |
//! | 4 | `serve` が正常切断以外（フレーム途中の切断・接続リセット・その他のエラー）で終わった |
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
/// 終了コード: `serve` が正常切断以外で終了。
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
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::time::Instant;

    use fandhe_container_io::{
        AppendFileSink, BATCH_SIZE_OPTION, Batch, BatchSink, IoError, IoErrorCode, IoTimeout,
        MAX_IO_TIMEOUT, NoopServerObserver, SinkOpenMode, SinkPersistReport, SinkWriteReport,
        UNFLUSHED_MAX_BYTES_OPTION, UNFLUSHED_MAX_FRAMES_OPTION, WritebackSettings, WritebackStats,
        WritebackTimeouts, decode_request, parse_batch_size, parse_unflushed_limit,
        persist_support,
    };

    use super::{EXIT_OK, EXIT_SERVE, EXIT_STARTUP, EXIT_USAGE, json_escape};

    /// 受け付ける引数（オプション名と値で 1 個ずつ数える）の個数上限。
    const MAX_ARGS: usize = 16;
    const SOCKET_OPTION: &str = "--socket";
    const DATA_DIR_OPTION: &str = "--data-dir";
    const FILE_OPTION: &str = "--file";
    const SINK_OPTION: &str = "--sink";
    /// `DeferredPersistSink` が `persist` まで保持するバイト数の上限（無制限確保の防止）。
    /// 試験の書き込み量（30 件 × 8 バイト程度）より十分大きい値にする。
    const DEFERRED_BUFFER_CAP: usize = 1024 * 1024;

    /// 書き込み先 sink の種別。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SinkKind {
        /// 製品の `AppendFileSink`。
        AppendFile,
        /// 試験専用の `DeferredPersistSink`（`persist` までファイルへ書かない）。
        Deferred,
    }

    /// 解析済みの起動引数。
    #[derive(Debug)]
    pub struct ServerArgs {
        socket: PathBuf,
        data_dir: PathBuf,
        file: String,
        batch_size: Option<String>,
        unflushed_frames: Option<String>,
        unflushed_bytes: Option<String>,
        sink: SinkKind,
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
        let mut sink = None;

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
                SINK_OPTION => {
                    let kind = match value.to_str() {
                        Some("append-file") => SinkKind::AppendFile,
                        Some("deferred") => SinkKind::Deferred,
                        _ => return Err(invalid("unknown sink kind")),
                    };
                    if sink.replace(kind).is_some() {
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
            sink: sink.unwrap_or(SinkKind::AppendFile),
        })
    }

    /// 試験専用 sink（`--sink deferred`）。`write_batch` は body をメモリへ積むだけで、
    /// `persist` が呼ばれて初めてファイルへ書き `sync_all` する。
    ///
    /// 役割: 通常 ACK がバッチ書き込み後に返っても、FLUSH ACK の前に `persist` が走らなければ
    /// SIGKILL でデータが失われる状態（spec の PoC の「ACK 済みで未書き込み」）を再現する。
    /// `tests/crash_safety.rs` が、`persist` を経る場合（FLUSH ACK 後に kill）と経ない場合
    /// （通常 ACK のみで kill）の結果差を検証する（IO-3・IO-2）。製品コードではない（REPAIR-3）。
    pub struct DeferredPersistSink {
        file: std::fs::File,
        pending: Vec<u8>,
    }

    impl DeferredPersistSink {
        /// `dir/name` を `create_new` で空のまま作る（READY 前に作るため、未フラッシュ時の
        /// ディスク照合は「0 バイト = 全件欠落」になる）。`name` はディレクトリ区切り・`..`・
        /// NUL・空を拒否する（既存ファイル・symlink の上書きも `create_new` が拒否する）。
        pub fn create_in(dir: &Path, name: &str) -> Result<Self, IoError> {
            let bad =
                name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']);
            if bad {
                return Err(invalid("invalid file name"));
            }
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(name))
                .map_err(|e| {
                    IoError::new(
                        IoErrorCode::Internal,
                        format!("deferred sink open failed ({:?})", e.kind()),
                    )
                })?;
            Ok(Self {
                file,
                pending: Vec::new(),
            })
        }

        /// 未 persist のバイト数（ユニットテスト用）。
        #[cfg(test)]
        fn pending_len(&self) -> usize {
            self.pending.len()
        }
    }

    impl BatchSink for DeferredPersistSink {
        fn write_batch(&mut self, batch: &Batch) -> Result<SinkWriteReport, IoError> {
            let mut frames = 0usize;
            let mut bytes = 0u64;
            for frame in batch.frames() {
                let body = decode_request(frame)?.body();
                let next = self.pending.len().saturating_add(body.len());
                if next > DEFERRED_BUFFER_CAP {
                    return Err(IoError::new(
                        IoErrorCode::Internal,
                        "deferred sink buffer cap exceeded",
                    ));
                }
                self.pending.extend_from_slice(body);
                frames += 1;
                bytes += u64::try_from(body.len()).unwrap_or(0);
            }
            Ok(SinkWriteReport::new(frames, bytes))
        }

        fn persist(&mut self) -> Result<SinkPersistReport, IoError> {
            // 非対応環境では本体の試験と同じく FLUSH ACK 経路で失敗させる（Unimplemented）
            if !persist_support().is_supported() {
                return Err(IoError::new(
                    IoErrorCode::Unimplemented,
                    "persist is not supported on this platform (IO-2)",
                ));
            }
            let start = Instant::now();
            let io_err = |e: std::io::Error| {
                IoError::new(
                    IoErrorCode::Internal,
                    format!("deferred sink persist failed ({:?})", e.kind()),
                )
            };
            self.file.write_all(&self.pending).map_err(io_err)?;
            self.file.sync_all().map_err(io_err)?;
            self.pending.clear();
            Ok(SinkPersistReport::new(start.elapsed()))
        }
    }

    /// `run_server` が保持する sink（`serve` を型ごとに呼び分けるための列挙）。
    enum ServerSink {
        Append(AppendFileSink),
        Deferred(DeferredPersistSink),
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

    /// フレーム境界での正常なピア切断（1 バイトも読めていない EOF）のメッセージ。
    /// `crates/io/src/server.rs` の `read_exact_with` が返す文言と一致させる
    /// （`crates/io/tests/server.rs` の drain 後の recv テストが同じ文言を固定している）。
    const CLEAN_DISCONNECT_MESSAGE: &str =
        "peer closed the connection before sending a complete frame header";

    /// `serve` の終了理由が「フレーム境界での正常な切断」かを判定する。
    /// `UNAVAILABLE` にはフレーム途中の切断・接続リセット・poison 済み接続も含まれるため、
    /// コードだけでは判定せず、メッセージで正常切断だけを選ぶ（IO-3。不完全なフレームでの
    /// 切断を正常終了にすると後続のクラッシュ耐性試験が異常終了を見逃す）。
    fn is_clean_peer_disconnect(end: &IoError) -> bool {
        end.code() == IoErrorCode::Unavailable && end.message() == CLEAN_DISCONNECT_MESSAGE
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
        let mut sink = match args.sink {
            SinkKind::AppendFile => {
                match AppendFileSink::open_in(&args.data_dir, &args.file, SinkOpenMode::CreateNew) {
                    Ok(s) => ServerSink::Append(s),
                    Err(e) => return startup_failure(e),
                }
            }
            SinkKind::Deferred => {
                match DeferredPersistSink::create_in(&args.data_dir, &args.file) {
                    Ok(s) => ServerSink::Deferred(s),
                    Err(e) => return startup_failure(e),
                }
            }
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
        let timeouts = WritebackTimeouts {
            recv: timeout,
            send: timeout,
        };
        let report = match &mut sink {
            ServerSink::Append(s) => conn.serve(s, timeouts),
            ServerSink::Deferred(s) => conn.serve(s, timeouts),
        };
        let code = if is_clean_peer_disconnect(&report.end) {
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use fandhe_container_io::{
            BatchBuffer, BatchConfig, FrameKind, InFlightLimit, PushOutcome, SendQueue,
            WireRequestId, encode_request,
        };

        fn args(list: &[&str]) -> Result<ServerArgs, IoError> {
            parse_args(list.iter().map(OsString::from))
        }

        const BASE: [&str; 6] = ["--socket", "/x/s", "--data-dir", "/x", "--file", "d.bin"];

        /// IO-3・#1832: `--sink` の既定は append-file、指定・重複・不明値を検証する。
        #[test]
        fn sink_option_parsing() {
            assert_eq!(args(&BASE).unwrap().sink, SinkKind::AppendFile);
            let mut with = BASE.to_vec();
            with.extend(["--sink", "deferred"]);
            assert_eq!(args(&with).unwrap().sink, SinkKind::Deferred);
            let mut dup = with.clone();
            dup.extend(["--sink", "deferred"]);
            assert_eq!(args(&dup).unwrap_err().code(), IoErrorCode::InvalidArgument);
            let mut bad = BASE.to_vec();
            bad.extend(["--sink", "nope"]);
            assert_eq!(args(&bad).unwrap_err().code(), IoErrorCode::InvalidArgument);
        }

        fn temp_dir(tag: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!("fcio-dps-{}-{tag}", std::process::id()));
            // 前回の残骸の上で進めない（REPAIR-12・#3375）。
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        /// request id 8 バイト + body 8 バイトの Write フレーム 1 件のバッチを作る。
        /// フレームは `SendQueue` が払い出した id から `encode_request` で組み立てる（REPAIR-2）。
        fn one_write_batch(seq: u64) -> Batch {
            let mut queue = SendQueue::new(InFlightLimit::new(1).unwrap());
            let registered = queue.register(FrameKind::Write).unwrap();
            let id = WireRequestId::from(registered.id());
            let frame = encode_request(FrameKind::Write, id, &seq.to_le_bytes()).unwrap();
            let mut buf = BatchBuffer::new(BatchConfig::new(1).unwrap());
            match buf.push(frame).unwrap() {
                PushOutcome::Ready(b) => b,
                other => panic!("batch_size=1 must fire immediately, got {other:?}"),
            }
        }

        /// IO-3・#1832: `write_batch` 後は `persist` まで 0 バイト、`persist` 後に全件が見える。
        #[test]
        fn deferred_sink_writes_only_on_persist() {
            let dir = temp_dir("persist");
            let mut sink = DeferredPersistSink::create_in(&dir, "d.bin").unwrap();
            for seq in 0..3u64 {
                sink.write_batch(&one_write_batch(seq)).unwrap();
            }
            let path = dir.join("d.bin");
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
            assert_eq!(sink.pending_len(), 24);
            if persist_support().is_supported() {
                sink.persist().unwrap();
                assert_eq!(std::fs::metadata(&path).unwrap().len(), 24);
                assert_eq!(sink.pending_len(), 0);
            } else {
                assert_eq!(
                    sink.persist().unwrap_err().code(),
                    IoErrorCode::Unimplemented
                );
            }
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// セキュリティ: ファイル名の区切り・`..` を拒否し、既存ファイルは上書きしない。
        #[test]
        fn deferred_sink_rejects_bad_names_and_existing_files() {
            let dir = temp_dir("names");
            for name in ["", ".", "..", "a/b", "..\\x", "../x"] {
                assert!(
                    DeferredPersistSink::create_in(&dir, name).is_err(),
                    "{name}"
                );
            }
            DeferredPersistSink::create_in(&dir, "ok.bin").unwrap();
            assert!(DeferredPersistSink::create_in(&dir, "ok.bin").is_err());
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// IO-3・TASK-18.1.1: 正常切断だけが終了コード 0 の対象になる。
        #[test]
        fn only_clean_disconnect_is_ok() {
            let clean = IoError::new(IoErrorCode::Unavailable, CLEAN_DISCONNECT_MESSAGE);
            assert!(is_clean_peer_disconnect(&clean));
            for msg in [
                "peer closed the connection in the middle of a frame header",
                "peer closed the connection before sending a complete frame body",
                "peer connection is unavailable: connection reset",
            ] {
                let e = IoError::new(IoErrorCode::Unavailable, msg);
                assert!(!is_clean_peer_disconnect(&e), "{msg}");
            }
            let other = IoError::new(IoErrorCode::Internal, CLEAN_DISCONNECT_MESSAGE);
            assert!(!is_clean_peer_disconnect(&other));
        }
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
