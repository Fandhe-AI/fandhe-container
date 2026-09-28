//! REPAIR-5（結合試験の応答性）: 正常系タイムアウト内 ACK 到達試験
//! （TASK-85.1・#119・親 #118）。
//!
//! [`fandhe_container_io::client::PipelineClient`]（TASK-12）と
//! [`fandhe_container_io::server::UdsServer`] / [`fandhe_container_io::writeback::serve_connection`]
//! （TASK-13）を実際の UDS 上で結合し、送信した全リクエストについて
//! [`AGENTS.md`]「推奨タイムアウト値」（REPAIR-5・REPAIR-10 (c)）が定める
//! 5〜10 秒のタイムアウト設定の範囲内で ACK が届くことを確かめる。PoC-8 では
//! ACK 未送信（BREAK-1）がビルドでも整合性テストでも検出できず、ハングとして
//! しか現れなかった。本ファイルはその再発を防ぐ結合試験の土台であり、正常系
//! （本 issue #119・TASK-85.1）のみを扱う。異常系（ACK を意図的に止めて
//! タイムアウトで検出するケース）は #120（TASK-85.2）が同じファイルへ追加する
//! 前提で、タイムアウト設定ヘルパーと [`unix::UnixStreamTransport`] は
//! そちらからも再利用できる形にしてある。
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
    use std::time::{Duration, Instant};

    use fandhe_container_io::client::{InFlightLimit, PipelineClient};
    use fandhe_container_io::observe::{NoopSendObserver, NoopServerObserver};
    use fandhe_container_io::protocol::{Frame, FrameHeader, FrameKind};
    use fandhe_container_io::transport::{FrameReceiver, FrameSender, IoTimeout};
    use fandhe_container_io::writeback::{AppendFileSink, WritebackTimeouts, serve_connection};
    use fandhe_container_io::{
        BatchConfig, FRAME_HEADER_LEN, IoError, IoErrorCode, ReceiveLimits, UdsServer,
    };

    use super::response_timeout;

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
        let deadline = Instant::now() + Duration::from_secs(5);
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
    struct UnixStreamTransport {
        stream: UnixStream,
        poisoned: bool,
    }

    impl UnixStreamTransport {
        fn new(stream: UnixStream) -> Self {
            Self {
                stream,
                poisoned: false,
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

            let result = (|| {
                let deadline = Instant::now() + timeout.as_duration();

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
    #[test]
    fn repair5_all_acks_arrive_within_timeout_default_batch_64() {
        let timeout = response_timeout();
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let output_path = dir.output_path();

        let mut server =
            UdsServer::bind(&socket_path, ReceiveLimits::default(), NoopServerObserver)
                .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let stream = connect(&connect_path);
            let transport = UnixStreamTransport::new(stream);
            let mut client =
                PipelineClient::new(transport, InFlightLimit::default(), NoopSendObserver);

            let started = Instant::now();
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
                assert_eq!(receipt.ack_kind(), FrameKind::Ack);
                let acked_id = receipt.request().id().get();
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

        let mut connection = server
            .accept(timeout, NoopServerObserver)
            .expect("server must accept the client connection within the timeout");

        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&output_path)
            .expect("must open output file");
        let mut sink = AppendFileSink::new(file).expect("seek to end must succeed");

        let writeback_timeouts = WritebackTimeouts {
            recv: timeout,
            send: timeout,
        };
        let server_thread = std::thread::spawn(move || {
            serve_connection(
                &mut connection,
                BatchConfig::default(),
                &mut sink,
                writeback_timeouts,
            )
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
            "total time from the first send to the last ack {total:?} must be under the {:?} timeout",
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
    #[test]
    fn repair5_each_request_ack_arrives_within_timeout_batch_1() {
        let timeout = response_timeout();
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let output_path = dir.output_path();

        let mut server =
            UdsServer::bind(&socket_path, ReceiveLimits::default(), NoopServerObserver)
                .expect("bind must succeed on a private, empty path");

        const REQUEST_COUNT: u64 = 16;

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let stream = connect(&connect_path);
            let transport = UnixStreamTransport::new(stream);
            let mut client =
                PipelineClient::new(transport, InFlightLimit::default(), NoopSendObserver);

            let mut acked_ids = Vec::with_capacity(REQUEST_COUNT as usize);
            for id in 0..REQUEST_COUNT {
                let round_started = Instant::now();
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
                assert_eq!(receipt.ack_kind(), FrameKind::Ack);
                acked_ids.push(receipt.request().id().get());
            }
            (acked_ids, *client.ack_metrics())
        });

        let mut connection = server
            .accept(timeout, NoopServerObserver)
            .expect("server must accept the client connection within the timeout");

        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&output_path)
            .expect("must open output file");
        let mut sink = AppendFileSink::new(file).expect("seek to end must succeed");

        let config = BatchConfig::new(1).expect("1 must be a valid batch size");
        let writeback_timeouts = WritebackTimeouts {
            recv: timeout,
            send: timeout,
        };
        let server_thread = std::thread::spawn(move || {
            serve_connection(&mut connection, config, &mut sink, writeback_timeouts)
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

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let stream = connect(&connect_path);
            let mut transport = UnixStreamTransport::new(stream);
            let first = transport.recv_frame(response_timeout());
            let second = transport.recv_frame(response_timeout());
            (first, second, transport.poisoned)
        });

        // accept してすぐに接続を落とし、client 側を EOF させる。
        let connection = server
            .accept(response_timeout(), NoopServerObserver)
            .expect("server must accept the client connection within the timeout");
        drop(connection);

        let (first, second, poisoned) = client_thread.join().expect("client thread must not panic");
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
