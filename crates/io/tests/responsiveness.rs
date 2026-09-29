//! REPAIR-5（結合試験の応答性）: タイムアウト内 ACK 到達・未到達検出試験
//! （TASK-85.1・#119、TASK-85.2・#120。親 #118）。
//!
//! [`fandhe_container_io::client::PipelineClient`]（TASK-12）と
//! [`fandhe_container_io::server::UdsServer`] / [`fandhe_container_io::writeback::serve_connection`]
//! （TASK-13）を実際の UDS 上で結合し、
//!
//! - 正常系（#119・TASK-85.1）: 送信した全リクエストについて
//!   [`AGENTS.md`]「推奨タイムアウト値」（REPAIR-5・REPAIR-10 (c)）が定める
//!   5〜10 秒のタイムアウト設定の範囲内で ACK が届くことを確かめる
//! - 異常系（#120・TASK-85.2）: ACK を意図的に送信しないサーバーに対して、
//!   クライアントの ACK 待ちがタイムアウトとして検出され、かつテスト自体が
//!   無限に待たずタイムアウト秒数（＋固定の猶予）で打ち切られることを確かめる
//!
//! の両方を扱う。PoC-8 では ACK 未送信（BREAK-1）がビルドでも整合性テスト
//! でも検出できず、ハングとしてしか現れなかった（PoC-12 でタイムアウト保護
//! 付き結合試験により検出を確認）。本ファイルはその再発を防ぐ結合試験。
//!
//! ## 異常系の受け入れ条件 2 の解釈（#120）
//!
//! 異常系テストは ACK 待ちそのものをタイムアウトさせる（＝検出したいもの）
//! ため、テストの所要時間は必然的に「タイムアウト秒数 ≒ elapsed」になる。
//! したがって「テスト自体が無限に待たずタイムアウト秒数内で終了する」ことは
//! 「厳密にタイムアウト未満で終わる」ではなく、**「ACK 待ちの所要時間が
//! `timeout - ABSENT_ACK_TOLERANCE` 以上 `timeout + HANG_GUARD_GRACE` 未満で
//! あり、シナリオ全体が三段の watchdog（準備段階は `REQUEST_COUNT * timeout +
//! HANG_GUARD_GRACE`、ACK 待ちへの遷移は準備段階の
//! 期限 + `HANG_GUARD_GRACE`、ACK 待ち段階は待機開始通知の受信時刻から
//! `timeout + HANG_GUARD_GRACE` での `recv_timeout`）で上限を機械的に
//! 保証されている」**と解釈する
//! （`mod unix::repair5_missing_ack_is_detected_as_timeout` 参照）。
//!
//! 当初は client スレッド全体（`connect` の最大 5 秒リトライ＋送信＋
//! `recv_ack` のタイムアウト待ち）を単一の `timeout + HANG_GUARD_GRACE` の
//! watchdog でしか保護していなかったため、`bind` / `accept` 側が数秒
//! 遅延すると `connect` 自体は成功していても watchdog が先に発火し、
//! ACK タイムアウト検出がハングしたかのように誤って panic し得た
//! （cursor Bugbot 指摘・codex P2 指摘・#1124）。本ファイルは
//! 準備段階（`connect` 完了・送信完了まで）と ACK 待ち段階を別々の期限で
//! 管理することでこれを解消する。準備段階の期限には複数件の送信（各 send は
//! 最大 `timeout` まで掛かり得る）の予算を含める（codex P2 指摘・#1124）。
//! `connect` / `accept` は client スレッドの起動前にテスト本体上で済ませ、
//! サーバー側の待ち（`accept`・受信）は、それが依存する client 側の工程の
//! 完了後に始める（ACK を返さないサーバーは準備段階の完了後に起動する）
//! ことで、client 側の予算内の遅延でサーバーが先にタイムアウトしないように
//! する（codex P2 指摘・#1124）。ACK 待ち段階の期限は
//! 準備完了通知とは別チャネルの待機開始通知（client 側トランスポートが
//! `recv_frame` の `deadline` を確定した直後に送る）の受信時刻を起点にし、
//! `recv_ack` 呼び出し前のスケジューリング遅延が期限を食い潰さないように
//! する（codex P2 指摘・#1124）。
//!
//! タイムアウト秒数は環境変数 `FANDHE_CONTAINER_TEST_TIMEOUT_SECS` で上書きでき、
//! 未設定時の既定値は [`DEFAULT_TEST_TIMEOUT_SECS`]（10 秒）。CI の
//! `integration-test` ジョブはこの env に `"10"` を渡す（TASK-87.1・#40）。
//! 本ファイルが、この env を読んで `Duration` を組み立てる最初の消費側コードに
//! なる（AGENTS.md 78 行の「消費側コードは存在せず」は本 PR で解消される）。

// `Duration` / `IoTimeout` は `response_timeout`（下記。UDS 対応 OS のみ）
// でのみ使う。Windows では `response_timeout` ごとコンパイル対象外になる
// ため、import も同じ cfg で揃える（未使用 import を clippy `-D warnings`
// で検出させない）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use fandhe_container_io::IoTimeout;

/// タイムアウト秒数を上書きする環境変数名（TASK-87.1・#40 が CI 側で設定する
/// env と同名。REPAIR-5・REPAIR-10 (c)）。
const TEST_TIMEOUT_ENV: &str = "FANDHE_CONTAINER_TEST_TIMEOUT_SECS";

/// 環境変数未設定時の既定タイムアウト秒数。AGENTS.md「推奨タイムアウト値」
/// （REPAIR-5・REPAIR-10 (c)）の推奨レンジ（5〜10 秒）の上限で、CI の
/// `integration-test` ジョブが渡す値（TASK-87.1・#40）とも一致する。
const DEFAULT_TEST_TIMEOUT_SECS: u64 = 10;

/// 許容するタイムアウト秒数の下限（AGENTS.md「推奨タイムアウト値」の下限。
/// PoC-8 実測に基づく）。
const MIN_TEST_TIMEOUT_SECS: u64 = 5;

/// 許容するタイムアウト秒数の上限。[`fandhe_container_io::MAX_IO_TIMEOUT`]
/// （10 秒）とも一致させ、`IoTimeout::new` が拒否する範囲を先に検出できるように
/// する。
const MAX_TEST_TIMEOUT_SECS: u64 = 10;

/// `FANDHE_CONTAINER_TEST_TIMEOUT_SECS` の生の値（`std::env::var` の結果を
/// `Option<&str>` へ変換したもの）から、許容範囲（[`MIN_TEST_TIMEOUT_SECS`]〜
/// [`MAX_TEST_TIMEOUT_SECS`]）に収まる秒数を取り出す純関数（env を直接触らない。
/// クランプはせず、範囲外は fail-closed で拒否する。#120 の異常系テストからも
/// 同じ関数を使う想定）。
///
/// - `None`（env 未設定）: [`DEFAULT_TEST_TIMEOUT_SECS`] を返す
/// - `Some(s)`: 前後の空白を trim した上で `u64` として解析し、
///   `MIN_TEST_TIMEOUT_SECS..=MAX_TEST_TIMEOUT_SECS` の範囲内であれば秒数を返す。
///   空文字・非数値・範囲外は `Err` を返す
fn parse_test_timeout_secs(raw: Option<&str>) -> Result<u64, String> {
    let raw = match raw {
        None => return Ok(DEFAULT_TEST_TIMEOUT_SECS),
        Some(raw) => raw,
    };
    let trimmed = raw.trim();
    let parsed: u64 = trimmed.parse().map_err(|_| {
        format!(
            "{TEST_TIMEOUT_ENV} must be an integer in {MIN_TEST_TIMEOUT_SECS}..={MAX_TEST_TIMEOUT_SECS} seconds (got {raw:?})"
        )
    })?;
    if !(MIN_TEST_TIMEOUT_SECS..=MAX_TEST_TIMEOUT_SECS).contains(&parsed) {
        return Err(format!(
            "{TEST_TIMEOUT_ENV} must be an integer in {MIN_TEST_TIMEOUT_SECS}..={MAX_TEST_TIMEOUT_SECS} seconds (got {raw:?})"
        ));
    }
    Ok(parsed)
}

/// `FANDHE_CONTAINER_TEST_TIMEOUT_SECS` を読み、応答待ちに使う
/// [`IoTimeout`] を組み立てる。範囲外・非数値の値が設定されていた場合は
/// 明示メッセージで panic させる（fail-closed。誤った値のまま無期限相当の
/// 動作へフォールバックしない）。
///
/// `std::env::set_var` は使わない（edition 2024 では `unsafe` になる上、
/// 並列実行される他のテストと競合しうるため）。そのため env 依存の分岐は
/// 本関数からは検証せず、[`parse_test_timeout_secs`] のユニットテスト
/// （境界値テスト。下記）で検証する。
///
/// 呼び出し元は `mod unix`（下記）に限る。UDS 未対応 OS（Windows）では
/// `mod unix` ごとコンパイル対象外になるため、本関数も同じ cfg で
/// 揃える（`dead_code` を Windows の clippy `-D warnings` で検出させない）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn response_timeout() -> IoTimeout {
    let raw = match std::env::var(TEST_TIMEOUT_ENV) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("{TEST_TIMEOUT_ENV} must be valid unicode")
        }
    };
    let secs =
        parse_test_timeout_secs(raw.as_deref()).unwrap_or_else(|message| panic!("{message}"));
    IoTimeout::new(Duration::from_secs(secs))
        .unwrap_or_else(|err| panic!("{secs}s must be a valid IoTimeout: {err}"))
}

/// [`parse_test_timeout_secs`] の境界値テスト（REPAIR-12: 期待値は具体値）。
/// 全 OS で実行する（cfg なし）。
#[test]
fn repair5_timeout_setting_defaults_to_10s_when_unset() {
    assert_eq!(parse_test_timeout_secs(None), Ok(10));
}

#[test]
fn repair5_timeout_setting_accepts_lower_bound_5s() {
    assert_eq!(parse_test_timeout_secs(Some("5")), Ok(5));
}

#[test]
fn repair5_timeout_setting_accepts_upper_bound_10s() {
    assert_eq!(parse_test_timeout_secs(Some("10")), Ok(10));
}

#[test]
fn repair5_timeout_setting_trims_surrounding_whitespace() {
    assert_eq!(parse_test_timeout_secs(Some(" 7 ")), Ok(7));
}

#[test]
fn repair5_timeout_setting_rejects_values_below_minimum() {
    assert!(parse_test_timeout_secs(Some("4")).is_err());
    assert!(parse_test_timeout_secs(Some("0")).is_err());
}

#[test]
fn repair5_timeout_setting_rejects_values_above_maximum() {
    assert!(parse_test_timeout_secs(Some("11")).is_err());
}

#[test]
fn repair5_timeout_setting_rejects_empty_and_non_numeric() {
    assert!(parse_test_timeout_secs(Some("")).is_err());
    assert!(parse_test_timeout_secs(Some("abc")).is_err());
    assert!(parse_test_timeout_secs(Some("-1")).is_err());
    assert!(parse_test_timeout_secs(Some("18446744073709551616")).is_err());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use std::io::{Read, Write};
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_io::client::{InFlightLimit, PipelineClient};
    use fandhe_container_io::observe::{NoopSendObserver, NoopServerObserver};
    use fandhe_container_io::protocol::{Frame, FrameHeader, FrameKind};
    use fandhe_container_io::transport::{FrameReceiver, FrameSender, IoTimeout};
    use fandhe_container_io::writeback::{
        AppendFileSink, SinkOpenMode, WritebackTimeouts, serve_connection,
    };
    use fandhe_container_io::{
        AckReceipt, BatchConfig, FRAME_HEADER_LEN, IoError, IoErrorCode, ReceiveLimits,
        UdsConnection, UdsServer, decode_request,
    };

    use super::response_timeout;

    /// [`repair5_missing_ack_is_detected_as_timeout`]（#120）が下限として許容
    /// する誤差。`SO_RCVTIMEO`（`recv_frame` が内部で使うソケットタイムアウト）
    /// は多くの実装で切り上げのため早期復帰しない前提だが、スケジューラ遅延
    /// による多少の前倒しは許容する。
    const ABSENT_ACK_TOLERANCE: Duration = Duration::from_millis(100);

    /// 同テストが上限（watchdog の待ち時間・ACK 待ちの所要時間の上限判定）に
    /// 使う猶予。CI ランナーのスケジューラ揺らぎを吸収しつつ、
    /// 「無限に待たない」ことを機械的に保証できる範囲に収める。
    const HANG_GUARD_GRACE: Duration = Duration::from_secs(2);

    /// [`connect`] が接続を試みる上限秒数。`connect` は
    /// [`connect_and_accept`] からテスト本体（main スレッド）上で、client
    /// スレッドの起動より前に呼ばれるため、この予算は watchdog の各段階や
    /// サーバー側の待ちとは重ならない（cursor Bugbot 指摘・codex P2 指摘・
    /// #1124: 以前は client スレッド内で `connect` していたため、`connect`
    /// の予算と watchdog・サーバー側 `accept` の期限を整合させる必要があった）。
    const CONNECT_RETRY_BUDGET: Duration = Duration::from_secs(5);

    /// テストごとに固有かつ短いソケットディレクトリを作る（`tests/writeback.rs`
    /// の `TempSocketDir` と同じ理由・同じ実装。`sun_path` の長さ上限のため
    /// 接頭辞を短く保つ）。
    struct TempSocketDir {
        path: PathBuf,
    }

    impl TempSocketDir {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let dir = std::env::temp_dir().join(format!("fcio-rs-{pid}-{n}"));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .expect("must be able to create a temp dir for the socket");
            Self { path: dir }
        }

        fn socket_path(&self) -> PathBuf {
            self.path.join("s.sock")
        }

        fn output_path(&self) -> PathBuf {
            self.path.join("out.bin")
        }

        /// [`Self::output_path`] を作り直して（既存なら切り詰めて）開いた sink。
        /// ディレクトリハンドル相対で開き、そのハンドルを親として持つため、
        /// macOS でも FlushAck の前提（親ディレクトリの同期）を満たす（IO-2・TASK-15.3）。
        fn output_sink(&self) -> AppendFileSink {
            AppendFileSink::open_in(&self.path, "out.bin", SinkOpenMode::CreateOrTruncate)
                .expect("seek to end must succeed")
        }
    }

    impl Drop for TempSocketDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// `path` へ接続し、期限（5 秒固定。`UdsServer::bind` の直後は accept 側が
    /// 追いつくまでの短いリトライが必要なだけで、応答待ちのタイムアウトとは
    /// 別物のため [`response_timeout`] は使わない。`tests/writeback.rs` の
    /// `connect` と同じ方針）で接続を試みる。
    fn connect(path: &std::path::Path) -> UnixStream {
        let deadline = Instant::now() + CONNECT_RETRY_BUDGET;
        loop {
            match UnixStream::connect(path) {
                Ok(stream) => return stream,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(err) => panic!("client failed to connect: {err}"),
            }
        }
    }

    /// テスト本体（main スレッド）上で `connect` → `accept` を順に行い、接続済み
    /// の client 側 [`UnixStream`] とサーバー側 [`UdsConnection`] の組を返す。
    ///
    /// 本ファイルの各テストは、client スレッド・サーバースレッドを起動する
    /// **前に**本関数で接続を確立する（codex P2 指摘・#1124）。`server` は
    /// `UdsServer::bind` 済み（`UnixListener::bind` の時点で `listen()` 済み）
    /// のため、`connect` は accept を待たずに backlog へ積まれて成功し、続く
    /// `accept` は既に待機中の接続を取り出すだけで即座に返る。client スレッド
    /// 内で `connect` し、別スレッドで `accept(timeout)` を並行に待つ構成では、
    /// client スレッドの起動・実行が `timeout` 以上遅れるとサーバー側の
    /// `accept` が先にタイムアウトし、検証対象（ACK の到達・未到達）とは
    /// 無関係にテストが失敗し得た。本関数の `accept` はスレッド間の
    /// スケジューリングに依存しない。
    fn connect_and_accept(
        server: &mut UdsServer<NoopServerObserver>,
        path: &std::path::Path,
        timeout: IoTimeout,
    ) -> (UnixStream, UdsConnection<NoopServerObserver>) {
        let stream = connect(path);
        let connection = server
            .accept(timeout, NoopServerObserver)
            .expect("server must accept the already-queued client connection");
        (stream, connection)
    }

    /// [`PipelineClient`] が要求する client 側トランスポート（`FrameSender` +
    /// `FrameReceiver`）の、テスト内での代用実装。
    ///
    /// client 側の UDS `connect` を経由した具象実装（`PipelineClient` との
    /// 本番結合）はまだ無いため（`tests/writeback.rs` の `send_write` の
    /// コメントと同じ理由）、std の [`UnixStream`] を薄くラップして代用する
    /// （REPAIR-3: スタブであることを明示）。
    ///
    /// `crate::transport` モジュールドキュメントの P1-3 契約（送受信いずれかが
    /// 一度でも `Err` を返した接続は以後使用不可）を守るため、`poisoned` が
    /// 真になった後は実際の読み書きを一切行わず [`IoErrorCode::Unavailable`]
    /// を返す。
    ///
    /// `recv_frame` は呼び出し全体（ヘッダ＋本体）で 1 つの `deadline` を持ち、
    /// `read_with_deadline` が生の `read` 呼び出しのたびに残り時間を
    /// `deadline` から再計算してソケットタイムアウトへ設定し直す（codex P0
    /// 指摘・#1121: `read_exact` 1 回に対して 1 度だけ設定すると、相手が
    /// `deadline` 未満の間隔で細切れ送信を続けた場合、個々の `read` は
    /// タイムアウトせずに済んでしまい、呼び出し全体としては `deadline` を
    /// 超えて待ち続け得る。REPAIR-5 の「応答待ちの有限時間打ち切り」に反する
    /// ため、`read` 1 回ごとに `deadline` との差分を見て打ち切る）。
    ///
    /// `recv_started` を設定した場合（[`Self::with_recv_started_notifier`]）、
    /// 最初の `recv_frame` 呼び出しで自身の `deadline` を確定した**後に**
    /// 1 度だけ通知する。[`repair5_missing_ack_is_detected_as_timeout`] の
    /// ACK 待ち段階 watchdog がこの通知の受信時刻を期限の起点にするための
    /// フック（codex P2 指摘・#1124）。`deadline` 確定後に送るため、通知の
    /// 受信時刻は常に `deadline` の起点以後になり、`recv_ack` 呼び出し前の
    /// スケジューリング遅延が watchdog の期限を食い潰さない。
    struct UnixStreamTransport {
        stream: UnixStream,
        poisoned: bool,
        recv_started: Option<mpsc::Sender<()>>,
    }

    impl UnixStreamTransport {
        fn new(stream: UnixStream) -> Self {
            Self {
                stream,
                poisoned: false,
                recv_started: None,
            }
        }

        /// 最初の `recv_frame` が `deadline` を確定した時点で `notifier` へ
        /// 1 度だけ通知するトランスポートを作る（型の doc 参照）。
        fn with_recv_started_notifier(stream: UnixStream, notifier: mpsc::Sender<()>) -> Self {
            Self {
                stream,
                poisoned: false,
                recv_started: Some(notifier),
            }
        }

        fn map_io_error(err: &std::io::Error) -> IoError {
            use std::io::ErrorKind;
            match err.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                    IoError::new(IoErrorCode::Timeout, "transport i/o timed out")
                }
                ErrorKind::UnexpectedEof | ErrorKind::BrokenPipe | ErrorKind::ConnectionReset => {
                    IoError::new(IoErrorCode::Unavailable, "transport connection is closed")
                }
                _ => IoError::new(
                    IoErrorCode::Internal,
                    format!("unexpected transport i/o error: {}", err.kind()),
                ),
            }
        }

        /// macOS では、相手がすでに接続を閉じたソケットに対して
        /// `set_read_timeout` / `set_write_timeout` を呼ぶと `EINVAL`
        /// （`ErrorKind::InvalidInput` かつ `raw_os_error()` を伴う）を返す
        /// （cursor Bugbot 指摘・#1121）。本番の `fandhe_container_io::server`
        /// の `is_peer_shutdown_einval`／`SET_TIMEOUT_EINVAL_MEANS_PEER_SHUTDOWN`
        /// と同じ観測に基づく判定で、このテスト用トランスポートでも同じ結論
        /// （`Unavailable`）へ写す。std が合成する `InvalidInput`（例:
        /// ゼロ `Duration` を渡した場合）は `raw_os_error()` を持たないため
        /// この判定には掛からず、`map_io_error` 経由で `Internal` のまま返る
        /// （`map_io_error` 自体には組み込まない理由: read/write 自体の
        /// エラーは OS を問わず素直に分類したいため、タイムアウト設定の
        /// 失敗経路だけに限定して適用する）。
        fn is_peer_shutdown_einval(err: &std::io::Error) -> bool {
            cfg!(target_os = "macos")
                && err.kind() == std::io::ErrorKind::InvalidInput
                && err.raw_os_error().is_some()
        }

        /// `set_read_timeout` / `set_write_timeout` の失敗を変換する
        /// （[`Self::is_peer_shutdown_einval`] なら `Unavailable`、それ以外は
        /// [`Self::map_io_error`] へ委譲）。
        fn map_set_timeout_error(err: std::io::Error) -> IoError {
            if Self::is_peer_shutdown_einval(&err) {
                IoError::new(IoErrorCode::Unavailable, "transport connection is closed")
            } else {
                Self::map_io_error(&err)
            }
        }
    }

    impl FrameSender for UnixStreamTransport {
        type Frame = Frame;

        fn send_frame(&mut self, frame: &Frame, timeout: IoTimeout) -> Result<(), IoError> {
            if self.poisoned {
                return Err(IoError::new(
                    IoErrorCode::Unavailable,
                    "transport is poisoned after a previous i/o error",
                ));
            }
            let deadline = Instant::now() + timeout.as_duration();
            let result = self.write_with_deadline(&frame.encode(), deadline);
            if result.is_err() {
                self.poisoned = true;
            }
            result
        }
    }

    impl FrameReceiver for UnixStreamTransport {
        type Frame = Frame;

        fn recv_frame(&mut self, timeout: IoTimeout) -> Result<Frame, IoError> {
            if self.poisoned {
                return Err(IoError::new(
                    IoErrorCode::Unavailable,
                    "transport is poisoned after a previous i/o error",
                ));
            }

            let deadline = Instant::now() + timeout.as_duration();
            // `deadline` 確定後に通知する（順序を逆にすると、通知の受信側が
            // `deadline` の起点より前の時刻を watchdog の起点にし得る）。
            // 受信側が既に居なくても本来の受信処理には影響させない。
            if let Some(notifier) = self.recv_started.take() {
                let _ = notifier.send(());
            }

            let result = (|| {
                let mut header_bytes = [0u8; FRAME_HEADER_LEN];
                self.read_with_deadline(&mut header_bytes, deadline)?;
                let header = FrameHeader::from_bytes(header_bytes)?;

                let mut body = vec![0u8; header.body_len()];
                self.read_with_deadline(&mut body, deadline)?;
                Frame::decode_body(header, &body)
            })();

            if result.is_err() {
                self.poisoned = true;
            }
            result
        }
    }

    impl UnixStreamTransport {
        /// `buf` を読み切るまで、生の `read` 呼び出しのたびに `deadline` から
        /// 残り時間を再計算してソケットタイムアウトへ設定し直す（`recv_frame`
        /// のヘッダ・本体読み取りで共有するヘルパー）。
        ///
        /// `read_exact` を 1 回だけ呼んで `set_read_timeout` も 1 回だけ設定
        /// する実装（旧版）は、相手が `deadline` 未満の間隔で細切れ送信を
        /// 続けた場合に `read_exact` 内部の個々の `read` はどれもタイムアウト
        /// せずに済んでしまい、呼び出し全体では `deadline` を大幅に超えて
        /// 待ち続け得た（codex P0 指摘・#1121。REPAIR-5「応答待ちの有限時間
        /// 打ち切り」に反する）。本実装は `read` 1 回ごとに `deadline` との
        /// 差分を見て打ち切るため、細切れ送信でも合計待ち時間が `deadline`
        /// を超えない。
        fn read_with_deadline(&mut self, buf: &mut [u8], deadline: Instant) -> Result<(), IoError> {
            let mut filled = 0usize;
            while filled < buf.len() {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|d| !d.is_zero())
                    .ok_or_else(|| {
                        IoError::new(IoErrorCode::Timeout, "deadline already elapsed")
                    })?;
                self.stream
                    .set_read_timeout(Some(remaining))
                    .map_err(Self::map_set_timeout_error)?;
                match self.stream.read(&mut buf[filled..]) {
                    Ok(0) => {
                        return Err(IoError::new(
                            IoErrorCode::Unavailable,
                            "transport connection is closed",
                        ));
                    }
                    Ok(n) => filled += n,
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(err) => return Err(Self::map_io_error(&err)),
                }
            }
            Ok(())
        }

        /// `buf` を書き切るまで、生の `write` 呼び出しのたびに `deadline` から
        /// 残り時間を再計算してソケットタイムアウトへ設定し直す
        /// （[`Self::read_with_deadline`] の書き込み側対応。`send_frame` から
        /// 呼ばれる）。
        ///
        /// `set_write_timeout` を 1 回だけ設定して `write_all` を 1 回呼ぶ
        /// 実装（旧版）は、相手が `deadline` 未満の間隔で少しずつしか読み
        /// 進めない場合に `write_all` 内部の個々の `write` はどれもタイム
        /// アウトせずに済んでしまい、呼び出し全体では `deadline` を大幅に
        /// 超えて待ち続け得た（codex P0 指摘・#1121。REPAIR-5「応答待ちの
        /// 有限時間打ち切り」に反する）。本実装は `write` 1 回ごとに
        /// `deadline` との差分を見て打ち切るため、相手が細切れにしか読ま
        /// なくても合計待ち時間が `deadline` を超えない。
        fn write_with_deadline(&mut self, buf: &[u8], deadline: Instant) -> Result<(), IoError> {
            let mut sent = 0usize;
            while sent < buf.len() {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|d| !d.is_zero())
                    .ok_or_else(|| {
                        IoError::new(IoErrorCode::Timeout, "deadline already elapsed")
                    })?;
                self.stream
                    .set_write_timeout(Some(remaining))
                    .map_err(Self::map_set_timeout_error)?;
                match self.stream.write(&buf[sent..]) {
                    Ok(0) => {
                        return Err(IoError::new(
                            IoErrorCode::Unavailable,
                            "transport connection is closed",
                        ));
                    }
                    Ok(n) => sent += n,
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(err) => return Err(Self::map_io_error(&err)),
                }
            }
            Ok(())
        }
    }

    /// TASK-85.1・REPAIR-5・IO-1・#119: 既定バッチサイズ（64 件）で 64 件を
    /// 送ると、全件の ACK がタイムアウト設定の範囲内に届く。ACK はバッチ満了
    /// （64 件）でしか返らないため（`writeback.rs` D3）、先に 64 件すべてを
    /// 送ってから受信する。
    ///
    /// 各リクエストの送信時刻は `send_started`（id ごとの `Instant`）に記録し、
    /// 対応する ACK 受信時刻との差分（`send` から `recv_ack` までの実際の
    /// 往復時間）で判定する（codex P1 指摘・#1121: 計測開始を全 64 件の
    /// `send` 完了後に置くと、先行リクエストの ACK がタイムアウトを超えて
    /// 遅延していても「受信開始後にタイムアウト内で届いた」ことしか検証でき
    /// ず、REPAIR-5 の「送信した全リクエストの ACK がタイムアウト内に届く」
    /// という受け入れ条件を取りこぼす）。
    ///
    /// 接続は [`connect_and_accept`] でスレッド起動前に確立する。全体の所要
    /// 時間 `total` の起点 `started` はサーバースレッド（`serve_connection`）の
    /// 起動より前に取る: サーバーの受信待ち（`WritebackTimeouts::recv`、
    /// 1 フレームごとに `timeout`）の区間はすべて `started` 以後に収まるため、
    /// client 側の遅延でサーバーの受信待ちがタイムアウトする状況では必ず
    /// `total >= timeout` となり、本テスト自身の判定でも失敗扱いになる
    /// （サーバーが検証対象と無関係な理由で先に失敗することがない。codex
    /// P2 指摘・#1124）。
    #[test]
    fn repair5_all_acks_arrive_within_timeout_default_batch_64() {
        let timeout = response_timeout();
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let output_path = dir.output_path();

        let mut server =
            UdsServer::bind(&socket_path, ReceiveLimits::default(), NoopServerObserver)
                .expect("bind must succeed on a private, empty path");

        let (stream, mut connection) = connect_and_accept(&mut server, &socket_path, timeout);

        let mut sink = dir.output_sink();

        let writeback_timeouts = WritebackTimeouts {
            recv: timeout,
            send: timeout,
        };
        // サーバースレッドの起動より前に取る（本関数 doc 参照）。
        let started = Instant::now();
        let server_thread = std::thread::spawn(move || {
            serve_connection(
                &mut connection,
                BatchConfig::default(),
                &mut sink,
                writeback_timeouts,
            )
        });

        let client_thread = std::thread::spawn(move || {
            let transport = UnixStreamTransport::new(stream);
            let mut client =
                PipelineClient::new(transport, InFlightLimit::default(), NoopSendObserver);

            let mut send_started: Vec<Instant> = Vec::with_capacity(64);
            for id in 0..64u64 {
                send_started.push(Instant::now());
                client
                    .send(FrameKind::Write, &id.to_le_bytes(), timeout)
                    .unwrap_or_else(|err| panic!("send must succeed for id {id}: {err}"));
            }

            let mut acked_ids = Vec::with_capacity(64);
            let mut per_ack_elapsed = Vec::with_capacity(64);
            for _ in 0..64 {
                let receipt = client
                    .recv_ack(timeout)
                    .expect("recv_ack must succeed within the timeout");
                // IO-1・IO-2・TASK-15.1（#85）: Write に対する ACK は通常 ACK
                // （`AckReceipt::Write`）でなければならない。種別は判別フィールド
                // ではなくバリアントで表現されるため、バリアントで確かめる。
                let AckReceipt::Write(write_ack) = receipt else {
                    panic!("expected a Write ack (FrameKind::Ack), got {receipt:?}");
                };
                assert_eq!(write_ack.request().kind(), FrameKind::Write);
                let acked_id = write_ack.request().id().get();
                let send_time = send_started.get(acked_id as usize).unwrap_or_else(|| {
                    panic!("acked id {acked_id} must have a recorded send time")
                });
                per_ack_elapsed.push(send_time.elapsed());
                acked_ids.push(acked_id);
            }
            let total = started.elapsed();
            let ack_metrics = *client.ack_metrics();
            // client（内部の UnixStream を含む）をこのスレッド内で明示的に drop
            // し、サーバー側が client スレッドとの join を待たずとも EOF を
            // 検出できるようにする（`tests/writeback.rs` と同じ理由。client を
            // 呼び出し元スレッドへ持ち出して drop を遅らせると、
            // `serve_connection` がまだ開いたままの接続に対して次のフレームを
            // 待ち続け、タイムアウトで終わってしまう）。
            drop(client);

            (acked_ids, per_ack_elapsed, total, ack_metrics)
        });

        let (acked_ids, per_ack_elapsed, total, ack_metrics) =
            client_thread.join().expect("client thread must not panic");

        assert_eq!(acked_ids, (0..64u64).collect::<Vec<_>>());
        assert_eq!(ack_metrics.success_count(), 64);
        assert_eq!(ack_metrics.transport_failure_count(), 0);
        let max_wait = ack_metrics
            .wait_latency()
            .max()
            .expect("wait_latency must have at least one sample");
        assert!(
            max_wait < timeout.as_duration(),
            "max ack wait latency {max_wait:?} must be under the {:?} timeout",
            timeout.as_duration()
        );
        for (index, elapsed) in per_ack_elapsed.iter().enumerate() {
            assert!(
                *elapsed < timeout.as_duration(),
                "send-to-ack round trip for the request acked at recv position #{index} took \
                 {elapsed:?}, which must be under the {:?} timeout",
                timeout.as_duration()
            );
        }
        assert!(
            total < timeout.as_duration(),
            "total time from before the server started to the last ack {total:?} must be under \
             the {:?} timeout",
            timeout.as_duration()
        );

        // client スレッド内ですでに client（と内部の UnixStream）を drop
        // 済みのため、サーバー側はすでに EOF（Unavailable）で終わっているはず。
        let report = server_thread.join().expect("server thread must not panic");
        assert_eq!(report.stats.acks_sent, 64);
        assert_eq!(report.stats.batches_written, 1);
        assert_eq!(report.stats.discarded_pending_frames, 0);
        assert_eq!(report.end.code(), IoErrorCode::Unavailable);

        let expected: Vec<u8> = (0..64u64).flat_map(|id| id.to_le_bytes()).collect();
        let contents = std::fs::read(&output_path).expect("must read output file");
        assert_eq!(contents, expected);
    }

    /// TASK-85.1・REPAIR-5・IO-1・#119（3.5 節の追加シナリオ）:
    /// `batch_size = 1` で 1 件ずつ送受信を往復させても、各往復がタイムアウト
    /// 設定の範囲内に完了する（1 リクエストごとの応答性の確認）。
    ///
    /// 接続は [`connect_and_accept`] でスレッド起動前に確立する。最初の往復
    /// の起点はサーバースレッドの起動より前に取った `started` とし、サーバー
    /// の最初の受信待ち（起動から id 0 の到着まで）を id 0 の往復の計測窓に
    /// 収める（`repair5_all_acks_arrive_within_timeout_default_batch_64` と
    /// 同じ理由。codex P2 指摘・#1124）。
    #[test]
    fn repair5_each_request_ack_arrives_within_timeout_batch_1() {
        let timeout = response_timeout();
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();

        let mut server =
            UdsServer::bind(&socket_path, ReceiveLimits::default(), NoopServerObserver)
                .expect("bind must succeed on a private, empty path");

        const REQUEST_COUNT: u64 = 16;

        let (stream, mut connection) = connect_and_accept(&mut server, &socket_path, timeout);

        let mut sink = dir.output_sink();

        let config = BatchConfig::new(1).expect("1 must be a valid batch size");
        let writeback_timeouts = WritebackTimeouts {
            recv: timeout,
            send: timeout,
        };
        // サーバースレッドの起動より前に取る（本関数 doc 参照）。
        let started = Instant::now();
        let server_thread = std::thread::spawn(move || {
            serve_connection(&mut connection, config, &mut sink, writeback_timeouts)
        });

        let client_thread = std::thread::spawn(move || {
            let transport = UnixStreamTransport::new(stream);
            let mut client =
                PipelineClient::new(transport, InFlightLimit::default(), NoopSendObserver);

            let mut acked_ids = Vec::with_capacity(REQUEST_COUNT as usize);
            for id in 0..REQUEST_COUNT {
                // id 0 はサーバー起動前の `started` を起点にする（本関数 doc 参照）。
                let round_started = if id == 0 { started } else { Instant::now() };
                client
                    .send(FrameKind::Write, &id.to_le_bytes(), timeout)
                    .unwrap_or_else(|err| panic!("send must succeed for id {id}: {err}"));
                let receipt = client
                    .recv_ack(timeout)
                    .unwrap_or_else(|err| panic!("recv_ack must succeed for id {id}: {err}"));
                let round_elapsed = round_started.elapsed();
                assert!(
                    round_elapsed < timeout.as_duration(),
                    "round-trip for id {id} took {round_elapsed:?}, which must be under the {:?} timeout",
                    timeout.as_duration()
                );
                // IO-1・IO-2・TASK-15.1（#85）: 上と同じく、通常 ACK
                // （`AckReceipt::Write`）であることをバリアントで確かめる。
                let AckReceipt::Write(write_ack) = receipt else {
                    panic!("expected a Write ack (FrameKind::Ack) for id {id}, got {receipt:?}");
                };
                assert_eq!(write_ack.request().kind(), FrameKind::Write);
                acked_ids.push(write_ack.request().id().get());
            }
            (acked_ids, *client.ack_metrics())
        });

        let (acked_ids, ack_metrics) = client_thread.join().expect("client thread must not panic");
        assert_eq!(acked_ids, (0..REQUEST_COUNT).collect::<Vec<_>>());
        assert_eq!(ack_metrics.success_count(), REQUEST_COUNT);
        assert_eq!(ack_metrics.transport_failure_count(), 0);

        let report = server_thread.join().expect("server thread must not panic");
        assert_eq!(report.stats.acks_sent, REQUEST_COUNT);
        assert_eq!(report.stats.batches_written, REQUEST_COUNT);
    }

    /// client 側トランスポート代用実装（[`UnixStreamTransport`]）自体の単体
    /// テスト: 相手が接続を閉じた状態で `recv_frame` を呼ぶと
    /// [`IoErrorCode::Unavailable`] を返し、以後の呼び出しも
    /// （P1-3 契約どおり）`Unavailable` のまま使用不可になる。
    #[test]
    fn repair5_transport_reports_unavailable_after_peer_closes() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();

        let mut server =
            UdsServer::bind(&socket_path, ReceiveLimits::default(), NoopServerObserver)
                .expect("bind must succeed on a private, empty path");

        // 接続を確立してから（[`connect_and_accept`]）、client が読み始める前に
        // サーバー側の接続を落とし、client 側を確定的に EOF させる。以前は
        // client スレッドの `recv_frame` とサーバー側の `accept` を並行に
        // 走らせていたため、client スレッドの起動が遅れると `accept` が先に
        // タイムアウトし得た（codex P2 指摘・#1124）。EOF 済みのソケットに
        // 対する `recv_frame` は即座に返るため、スレッドを分ける必要もない。
        let (stream, connection) =
            connect_and_accept(&mut server, &socket_path, response_timeout());
        drop(connection);

        let mut transport = UnixStreamTransport::new(stream);
        let first = transport.recv_frame(response_timeout());
        let second = transport.recv_frame(response_timeout());
        let poisoned = transport.poisoned;
        assert_eq!(
            first
                .expect_err("recv_frame must fail once the peer has closed")
                .code(),
            IoErrorCode::Unavailable
        );
        assert_eq!(
            second
                .expect_err("recv_frame after poisoning must still fail")
                .code(),
            IoErrorCode::Unavailable
        );
        assert!(poisoned);
    }

    /// [`spawn_silent_server`] が受信・記録する 1 件分の request（owned。
    /// [`fandhe_container_io::payload::RequestEnvelope`] はフレームを借用する
    /// ため、サーバースレッドの戻り値としてそのままは返せない）。
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SilentServerRequest {
        kind: FrameKind,
        id: u64,
        body: Vec<u8>,
    }

    /// PoC-8 の BREAK-1（ACK 未送信）をテスト内で再現するスタブ用サーバー
    /// （REPAIR-3: 実装済みを装わない。本番の `serve_connection` には
    /// 「ACK を送らない」切り替え口を追加しない。あくまでテストローカルの
    /// 代用実装）。
    ///
    /// `expected_count` 件のフレームを受信・検証するだけで、
    /// [`fandhe_container_io::transport::FrameSender::send_frame`] を一度も
    /// 呼ばない。これにより「リクエストは届いたが ACK が返らなかった」ことを
    /// 「リクエスト自体が届かなかった」ことと区別できる。
    ///
    /// `connection` は呼び出し元が [`connect_and_accept`] で accept 済みの
    /// ものを受け取り、呼び出し元は client スレッドの準備段階（全件の送信）
    /// の完了通知を受け取った**後に**本関数を呼ぶ。したがって本スレッドが
    /// `recv_frame(timeout)` を始める時点で `expected_count` 件のフレームは
    /// すでにソケットのバッファに届いており、各受信は即座に返る
    /// （client が先に接続を閉じても、バッファ済みのデータは EOF より前に
    /// 読める）。サーバー側の `accept` / 受信待ちを client の準備段階と
    /// 並行に走らせると、client スレッドの起動・送信が `timeout` 以上
    /// 遅れた場合（準備段階の予算 `REQUEST_COUNT * timeout +
    /// HANG_GUARD_GRACE` の範囲内でも）サーバーが先にタイムアウトし、ACK
    /// 未送信の検証とは無関係にテストが失敗し得た（cursor Bugbot 指摘・
    /// codex P2 指摘・#1124）。
    ///
    /// `done_rx` で呼び出し元（テスト本体）からの完了通知を待ってから
    /// `connection` を drop する（サーバー側でさらに `recv_frame(timeout)`
    /// を回すと、サーバーのタイムアウトとクライアントのタイムアウトが
    /// ほぼ同時刻に競合し、アサーションが不安定になるため、受信後は完了
    /// 通知待ちに専念する）。待ちは `recv()`（無期限）で行う: `done_tx` は
    /// 呼び出し元スレッドのスタック上にあり、呼び出し元がどのような経路
    /// （正常終了・アサーション失敗による panic・watchdog 発火）で終わっても
    /// unwind により drop されるため、`done_tx` が送信されないまま
    /// 呼び出し元が終了すれば `recv()` は即座に `Err` を返す。本スレッドは
    /// critical path 上になく、呼び出し元は watchdog 通過後にしか join
    /// しないため、無期限の `recv()` にしても「無限に待たない」という
    /// 受け入れ条件（本ファイル冒頭 `//!`）には抵触しない（codex P2 指摘
    /// 対応・#1124: 固定時間の先行タイマーに依存せず、完了通知まで接続を
    /// 維持する）。
    fn spawn_silent_server(
        mut connection: UdsConnection<NoopServerObserver>,
        timeout: IoTimeout,
        expected_count: usize,
        done_rx: mpsc::Receiver<()>,
    ) -> std::thread::JoinHandle<Vec<SilentServerRequest>> {
        std::thread::spawn(move || {
            let mut received = Vec::with_capacity(expected_count);
            for _ in 0..expected_count {
                let frame = connection
                    .recv_frame(timeout)
                    .expect("silent server must receive the expected request frame");
                let envelope = decode_request(&frame)
                    .expect("silent server must receive a well-formed request frame");
                received.push(SilentServerRequest {
                    kind: envelope.kind(),
                    id: envelope.id().get(),
                    body: envelope.body().to_vec(),
                });
            }

            // 意図的に send_frame を一度も呼ばない（BREAK-1 相当）。
            let _ = done_rx.recv();
            drop(connection);

            received
        })
    }

    /// `handle` の join を最大 `limit` だけ待つ（REPAIR-5: critical path 上に
    /// 上限なしの `join()` を置かない）。
    ///
    /// join() 自体は無期限にブロックするため、別スレッドへ隔離してその結果を
    /// `recv_timeout(limit)` で待つ。期限内に終わらなければ `None` を返す
    /// （隔離したスレッドは対象スレッドが終わるまで残るが、テストプロセスの
    /// 終了とともに回収される）。期限内に終われば `join()` の結果（対象
    /// スレッドの panic payload を含む）をそのまま返す。
    fn join_within<T: Send + 'static>(
        handle: std::thread::JoinHandle<T>,
        limit: Duration,
    ) -> Option<std::thread::Result<T>> {
        let (join_tx, join_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = join_tx.send(handle.join());
        });
        join_rx.recv_timeout(limit).ok()
    }

    /// TASK-85.2・REPAIR-5・BREAK-1・#120: ACK を意図的に送信しないサーバー
    /// （[`spawn_silent_server`]）に対して送信した場合、クライアントの
    /// `recv_ack` がタイムアウトとして検出され（[`IoErrorCode::Timeout`]）、
    /// 以後クライアントが失効（poison）して送受信を拒否することを確かめる。
    ///
    /// 受け入れ条件 2（テスト自体が無限に待たずタイムアウト秒数内で終了する
    /// こと）の解釈は本ファイル冒頭の `//!` を参照。本テストは main 側で
    /// 三段の watchdog を持つ:
    ///
    /// 1. 準備段階（3 件の送信。各送信は最大 `timeout` まで掛かり得る）は
    ///    readiness 通知を `REQUEST_COUNT * timeout + HANG_GUARD_GRACE`
    ///    （client スレッド起動前の時刻を起点にした絶対期限）まで待つ
    /// 2. ACK 待ちへの遷移（readiness 送信から transport の `recv_frame` が
    ///    `deadline` を確定するまで）は、別チャネルの wait_started 通知を
    ///    準備段階の絶対期限 + `HANG_GUARD_GRACE` まで待つ
    /// 3. ACK 待ち段階（`recv_ack(timeout)`）は、wait_started の受信時刻を
    ///    起点に `timeout + HANG_GUARD_GRACE` まで client スレッドの結果を待つ
    ///
    /// のいずれも critical path 上に上限なしの `recv()` / `join()` を置かない
    /// （REPAIR-5）。当初は単一の `timeout + HANG_GUARD_GRACE` の watchdog で
    /// スレッド全体（`connect` を含む）を保護していたため、`bind` / `accept`
    /// 側が数秒遅延すると `connect` 自体は成功していても watchdog が先に
    /// 発火し、ACK タイムアウト検出がハングしたかのように誤って panic し得た
    /// （cursor Bugbot 指摘・codex P2 指摘・#1124）。また readiness の送信
    /// 時刻を ACK 待ち段階の起点にしていた版では、`recv_ack` 呼び出しまでの
    /// スケジューリング遅延が期限を食い潰し得たため、3. の起点を
    /// transport 内の待機開始時点へ移した（codex P2 指摘・#1124）。
    ///
    /// サーバー側の待ちはいずれも、それが依存する client 側の工程の完了後に
    /// 始める（codex P2 指摘・#1124）: `connect` / `accept` は client
    /// スレッドの起動前に [`connect_and_accept`] で済ませ、ACK を返さない
    /// サーバー（[`spawn_silent_server`]）は準備段階の完了通知を受け取った
    /// 後に起動する。これにより、準備段階の予算内の遅延でサーバーの
    /// `accept` / 受信が先にタイムアウトすることがない。
    #[test]
    fn repair5_missing_ack_is_detected_as_timeout() {
        let timeout = response_timeout();
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();

        const REQUEST_COUNT: u64 = 3;

        // `server`（listener）はテスト終了まで保持する（accept 済みの接続とは
        // 独立だが、途中で drop してソケットファイルを片付ける理由もない）。
        let mut server =
            UdsServer::bind(&socket_path, ReceiveLimits::default(), NoopServerObserver)
                .expect("bind must succeed on a private, empty path");
        let (stream, connection) = connect_and_accept(&mut server, &socket_path, timeout);

        // 準備段階の完了通知（readiness）と ACK 待ちの開始通知（wait_started）
        // は別チャネルに分ける（codex P2 指摘・#1124）。readiness は準備段階
        // watchdog の終点、wait_started は ACK 待ち段階 watchdog の起点にのみ
        // 使う。1 つの通知で両方を兼ねると、通知を送ってから `recv_ack` が
        // 実際に待ちへ入るまでのスケジューリング遅延が ACK 待ち段階の期限を
        // 食い潰し、`recv_ack` が正常にタイムアウトを返しても watchdog が
        // 先に発火し得た。
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (wait_started_tx, wait_started_rx) = mpsc::channel::<()>();
        // 準備段階の期限の起点。client スレッドの起動より前に取り、スレッド
        // 起動の遅延も準備段階の予算に含める（`connect` は上で完了済みのため
        // 予算に含めない）。
        let setup_started = Instant::now();
        let client_thread = std::thread::spawn(move || {
            // wait_started は transport が `recv_frame` の `deadline` を確定
            // した直後に送る（`UnixStreamTransport` の doc 参照）。client
            // スレッド側で `recv_ack` の直前に送るより後ろ、すなわち実際の
            // ACK 待ちの起点そのものに通知位置を寄せる。
            let transport =
                UnixStreamTransport::with_recv_started_notifier(stream, wait_started_tx);
            let mut client =
                PipelineClient::new(transport, InFlightLimit::default(), NoopSendObserver);

            for id in 0..REQUEST_COUNT {
                client
                    .send(FrameKind::Write, &id.to_le_bytes(), timeout)
                    .unwrap_or_else(|err| panic!("send must succeed for id {id}: {err}"));
            }

            // 準備段階（connect・送信）完了を main 側の watchdog へ通知する。
            // 送信に失敗した場合はこのスレッドが上の unwrap_or_else で既に
            // panic しているため、ここへ到達するのは準備が成功した場合のみ。
            let _ = ready_tx.send(());

            // `elapsed`（下記の受け入れ条件 2 判定に使う所要時間）は
            // `recv_ack` 呼び出し直前に記録する。transport 内の `deadline`
            // 確定はこれより後のため、`elapsed` は ACK 待ちの実所要時間を
            // 過小評価しない（上限判定側に倒れる）。
            let wait_started = Instant::now();
            let first_recv_ack = client.recv_ack(timeout);
            let elapsed = wait_started.elapsed();

            let first_err_code = first_recv_ack
                .expect_err("recv_ack must fail once the ack wait exceeds the timeout")
                .code();
            let is_poisoned_after_timeout = client.is_poisoned();
            let ack_metrics_after_timeout = *client.ack_metrics();

            // 失効後の 2 回目の呼び出しも P1-3 契約どおり Unavailable で
            // 拒否されることを確かめる（poison の効果が持続する）。
            let second_recv_ack_code = client.recv_ack(timeout).map(|_| ()).unwrap_err().code();
            let send_after_poison_code = client
                .send(FrameKind::Write, &REQUEST_COUNT.to_le_bytes(), timeout)
                .map(|_| ())
                .unwrap_err()
                .code();
            let ack_metrics_after_second_call = *client.ack_metrics();

            // client（内部の UnixStream を含む）をこのスレッド内で drop し、
            // サーバー側の完了通知待ちが早く終われるようにする
            // （`repair5_all_acks_arrive_within_timeout_default_batch_64` と
            // 同じ理由）。
            drop(client);

            (
                first_err_code,
                elapsed,
                is_poisoned_after_timeout,
                ack_metrics_after_timeout,
                second_recv_ack_code,
                send_after_poison_code,
                ack_metrics_after_second_call,
            )
        });

        // hang guard（watchdog）その 1: 準備段階（REQUEST_COUNT 件の送信）の
        // 完了通知を、送信分の予算（各 send は最大 `timeout` まで掛かり得る
        // ため `REQUEST_COUNT * timeout`）+ 猶予を上限に待つ（本関数 doc
        // 参照。critical path 上に上限なしの recv() を置かない）。送信分を
        // 含めていないと、3 件の送信が詰まった場合に実際にはまだ送信中
        // （＝ハングではない）にもかかわらず watchdog が誤って「準備段階が
        // ハングした」と判定し得る（codex P2 指摘・#1124）。`connect` は
        // client スレッドの起動前に完了済みのため予算に含めない。
        let ready_budget = timeout.as_duration() * (REQUEST_COUNT as u32) + HANG_GUARD_GRACE;
        let ready_deadline = setup_started + ready_budget;
        if ready_rx
            .recv_timeout(ready_deadline.saturating_duration_since(Instant::now()))
            .is_err()
        {
            // client スレッドが準備段階中に panic した場合は送信側が drop
            // されて即座にここへ来る。panic メッセージをそのまま伝えるため
            // join 結果を確認するが、join() を直接無期限に呼ぶと送信が真に
            // ハングしているケースで join() 自体が無期限停止し、
            // REPAIR-5（有限時間でのハング検出）に違反する（codex レビュー
            // P0 指摘・#1124）。`join_within` で上限付きにする。
            match join_within(client_thread, HANG_GUARD_GRACE) {
                Some(Ok(_)) => panic!(
                    "client thread finished without signalling readiness within \
                     {ready_budget:?} (send setup did not complete in time)"
                ),
                Some(Err(payload)) => std::panic::resume_unwind(payload),
                None => panic!(
                    "client thread did not finish within {ready_budget:?} + \
                     {HANG_GUARD_GRACE:?} after readiness notification was not \
                     received; send setup appears hung \
                     (timeout detection is not working)"
                ),
            }
        }

        // 準備段階（全件の送信）が完了したので、ACK を返さないサーバーを
        // ここで起動する。送信済みのフレームはソケットのバッファに届いて
        // いるため、サーバーの `recv_frame(timeout)` は即座に返り、client の
        // 準備段階の予算内の遅延でサーバーが先にタイムアウトすることはない
        // （[`spawn_silent_server`] doc 参照。codex P2 指摘・#1124）。
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let server_thread =
            spawn_silent_server(connection, timeout, REQUEST_COUNT as usize, done_rx);

        // hang guard（watchdog）その 2: readiness から ACK 待ち開始
        // （transport の `recv_frame` が `deadline` を確定した時点）までの
        // 遷移を上限付きで待つ。この区間は通知送信と `recv_ack` 冒頭の
        // 検査だけでブロッキング処理を含まないが、critical path 上に上限なし
        // の recv() を置かないため期限を設ける。期限は準備段階と同じ絶対
        // 期限 `ready_deadline` に `HANG_GUARD_GRACE` を足した時刻とし、
        // readiness の受信時刻を起点にしない: 準備段階が早く終わった分の
        // 予算をこの区間へ回し、区間内のスケジューリング遅延だけで
        // 誤ってハングと判定しないようにする（codex P2 指摘・#1124）。
        // readiness がどれほど遅れても `ready_deadline` 前に届いている
        // ため、この区間には最低でも `HANG_GUARD_GRACE` が残る。
        let wait_started_deadline = ready_deadline + HANG_GUARD_GRACE;
        if wait_started_rx
            .recv_timeout(wait_started_deadline.saturating_duration_since(Instant::now()))
            .is_err()
        {
            // 送信側（transport）が通知せずに drop された場合（`recv_ack` が
            // transport へ到達せずに返った場合を含む）もここへ来る。ACK 待ち
            // 自体が始まらなかったことはタイムアウト検出の検証が成立して
            // いないことを意味するため、正常終了でも失敗として扱う。
            match join_within(client_thread, HANG_GUARD_GRACE) {
                Some(Ok(_)) => panic!(
                    "client thread finished without ever starting the ack wait \
                     (recv_ack did not reach the transport); the missing-ack \
                     scenario was not exercised"
                ),
                Some(Err(payload)) => std::panic::resume_unwind(payload),
                None => panic!(
                    "ack wait did not start within {HANG_GUARD_GRACE:?} of the setup \
                     deadline ({ready_budget:?}) after readiness was signalled; the \
                     transition into recv_ack appears hung"
                ),
            }
        }
        // ACK 待ち段階の起点: wait_started を main 側で受信した時刻。
        // transport は `deadline` 確定後に通知を送るため、この時刻は常に
        // transport 側の `deadline` の起点以後になる。したがって `recv_ack`
        // 呼び出し前のどんなスケジューリング遅延も、main 側の期限を先に
        // 進めることはない（codex P2 指摘・#1124）。
        let ack_wait_started = Instant::now();

        // hang guard（watchdog）その 3: client_thread の結果を上限付きで待つ。
        // critical path 上に上限なしの recv()・join() を置かない
        // （REPAIR-5・本ファイル冒頭 `//!` の受け入れ条件 2 の解釈）。
        //
        // 期限は `ack_wait_started + timeout + HANG_GUARD_GRACE`。transport の
        // `deadline`（≦ `ack_wait_started + timeout`）を過ぎても結果が返らない
        // こと、すなわち ACK 未送信を検出できずに待ち続けていることを
        // `HANG_GUARD_GRACE` 以内に検出する。起点が実際の待機開始以後に
        // 揃ったため、以前の `ACK_WAIT_SCHEDULING_SLACK`（`recv_ack` 呼び出し
        // 前の遅延を吸収する追加猶予）は不要になり、期限は下記の `elapsed`
        // 上限判定（`timeout + HANG_GUARD_GRACE`）と同じ幅に揃う。
        let watchdog_budget = timeout.as_duration() + HANG_GUARD_GRACE;
        let watchdog_deadline = ack_wait_started + watchdog_budget;
        let client_result = join_within(
            client_thread,
            watchdog_deadline.saturating_duration_since(Instant::now()),
        )
        .unwrap_or_else(|| {
            panic!(
                "missing-ack detection did not complete within {watchdog_budget:?} of \
                 the ack wait starting; timeout detection is not working \
                 (hung instead of erroring)"
            )
        });
        let (
            first_err_code,
            elapsed,
            is_poisoned_after_timeout,
            ack_metrics_after_timeout,
            second_recv_ack_code,
            send_after_poison_code,
            ack_metrics_after_second_call,
        ) = client_result.expect("client thread must not panic");

        // 検出: recv_ack はタイムアウトとして検出しなければならない。
        assert_eq!(first_err_code, IoErrorCode::Timeout);

        // 所要時間の下限・上限: 実際に待ったことを示しつつ、無限には待たない。
        let lower_bound = timeout.as_duration().saturating_sub(ABSENT_ACK_TOLERANCE);
        assert!(
            elapsed >= lower_bound,
            "ack wait elapsed {elapsed:?} must be at least {lower_bound:?} \
             (timeout {:?} minus tolerance {ABSENT_ACK_TOLERANCE:?})",
            timeout.as_duration()
        );
        let upper_bound = timeout.as_duration() + HANG_GUARD_GRACE;
        assert!(
            elapsed < upper_bound,
            "ack wait elapsed {elapsed:?} must be under {upper_bound:?} \
             (timeout {:?} plus grace {HANG_GUARD_GRACE:?})",
            timeout.as_duration()
        );

        // 失効（P1-3 契約）とメトリクス。
        assert!(is_poisoned_after_timeout);
        assert_eq!(ack_metrics_after_timeout.transport_failure_count(), 1);
        assert_eq!(ack_metrics_after_timeout.success_count(), 0);

        // 失効後の 2 回目以降の呼び出しは Unavailable で拒否され続ける。
        assert_eq!(second_recv_ack_code, IoErrorCode::Unavailable);
        assert_eq!(send_after_poison_code, IoErrorCode::Unavailable);
        assert_eq!(ack_metrics_after_second_call.rejected_poisoned_count(), 1);

        // サーバー側: 完了を通知して受信内容を回収する（サーバーは準備段階の
        // 完了後に起動し、バッファ済みの REQUEST_COUNT 件を読むだけなので、
        // client の ACK 待ち（`timeout` 秒）の間に受信を終えているはず。
        // 通知が既に受理不能でも送信失敗は無視する ― その場合サーバー
        // スレッドは受信の失敗で既に終了している）。
        //
        // `done_tx.send(())` はサーバースレッドが `done_rx.recv()` へ実際に
        // 到達したことまでは保証しない。受信処理側が何らかの理由で停止して
        // いれば、このあと `server_thread.join()` を直接無期限に呼ぶと
        // watchdog 通過後でも CI をハングさせ得る（REPAIR-5 違反。codex P0
        // 指摘・#1124）。client スレッドの watchdog と同じく `join_within` で
        // `HANG_GUARD_GRACE` を上限に待つ。
        let _ = done_tx.send(());
        let received = match join_within(server_thread, HANG_GUARD_GRACE) {
            Some(join_result) => join_result.expect("silent server thread must not panic"),
            None => panic!(
                "silent server thread did not finish within {HANG_GUARD_GRACE:?} after \
                 the completion notification was sent; receive handling appears hung \
                 (timeout detection is not working)"
            ),
        };

        assert_eq!(received.len(), REQUEST_COUNT as usize);
        for (index, request) in received.iter().enumerate() {
            let expected_id = index as u64;
            assert_eq!(request.kind, FrameKind::Write);
            assert_eq!(request.id, expected_id);
            assert_eq!(request.body, expected_id.to_le_bytes().to_vec());
        }
    }
}

/// 非対応 OS（Windows）では `UdsServer::bind` が常に `Unimplemented` を返す
/// ことを確認する（`tests/writeback.rs`・`tests/server.rs` と同じ方針。
/// 3 OS すべてでテスト集合を空にしないため。上記のタイムアウト設定テストは
/// cfg なしで全 OS 実行されるため、本テストが無くてもテスト集合が空になる
/// ことはないが、UDS 未対応の扱いを明示するために置く）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn repair5_uds_bind_is_unimplemented_on_unsupported_os() {
    use fandhe_container_io::{IoErrorCode, NoopServerObserver, ReceiveLimits, UdsServer};

    let path = std::env::temp_dir().join("fcio-rs-unsupported.sock");
    let err = UdsServer::bind(&path, ReceiveLimits::default(), NoopServerObserver)
        .expect_err("bind must be unimplemented on unsupported OS");
    assert_eq!(err.code(), IoErrorCode::Unimplemented);
}
