#![cfg(test)]
//! PoC-8（`03-poc/ai-self-repair`）BREAK-1（ACK 未送信）・BREAK-2（フレーム長破壊）
//! 相当の破壊を、本番の [`serve_connection`]・[`PipelineClient`] を実際に動かして
//! 送受信経路へ注入する結合試験（TASK-89.1・REPAIR-7・IO-1・MS-1・#122）。
//!
//! ## 既存テストとの役割分担
//!
//! - `tests/frame_integrity.rs`（TASK-83.1・REPAIR-2・#116）: BREAK-2 を
//!   [`Frame::decode`] / [`Frame::decode_body`] の単体レベルで確認済み
//!   （送受信経路そのものは経由しない）
//! - `tests/responsiveness.rs`（TASK-85・REPAIR-5・#118）: BREAK-1 を、テスト内で
//!   手書きした「ACK を返さないスタブサーバー」（`spawn_silent_server`。`recv_frame`
//!   のみを実装し `send_frame` を一度も呼ばない）で確認済み
//! - **本ファイルで新たに示すこと**: 本番の [`serve_connection`] を実際に動かし、
//!   その送受信経路へ破壊を注入する（エンドツーエンド）。破壊ごとに、同じハーネス
//!   から注入だけを外した対照テストを置き、「常に失敗するハーネスでも 100% 検出に
//!   見えてしまう」状態を排除する
//!
//! ## 注入の方針（REPAIR-3: 実装済みを装わない）
//!
//! 本番の [`serve_connection`] には「ACK を送らない」切り替え口を追加しない。
//! BREAK-1 はテストローカルのデコレータ（[`unix_common::AckDropping`]。全 OS 共通
//! なので `mod unix` の外に置く）が [`FrameSender::send_frame`] の呼び出しを
//! 横取りして [`FrameKind::Ack`] / [`FrameKind::FlushAck`] を握りつぶす形で注入する。
//! BREAK-2 は [`tamper_declared_len`]（`tests/frame_integrity.rs` の同名関数と同じ
//! 手法。ヘッダを自己整合的な〔`header_crc` を新しい `payload_len` に対して正しく
//! 再計算した〕ものへ丸ごと差し替える）でワイヤー上のバイト列を改ざんしてから
//! [`MemEnd::send_raw`] で送る。
//!
//! ## トランスポート
//!
//! - 全 OS 共通: インメモリの双方向バイトパイプ（[`mem_pipe`]・[`MemEnd`]）。BREAK-1・
//!   BREAK-2 の両方をこの上で確認する。UDS の `bind` が `Unimplemented` になる
//!   Windows でも実行できる
//! - unix 限定（`mod unix`）: 実 UDS 上で BREAK-2 のみ確認する（本番の
//!   [`crate::server::UdsServer`] / [`crate::server::UdsConnection`] を実際に使う
//!   経路の確認。BREAK-1 の UDS 経路は既存の `tests/responsiveness.rs` でカバー
//!   済みのため、ここでは複製しない）
//!
//! ## 検出機構と本ファイルのビヘイビア対応
//!
//! - BREAK-2 →（申告長と実長の食い違いを `header_crc`＋本体チェックサムで検出。
//!   REPAIR-2・IO-1。TASK-83 相当）→ [`IoErrorCode::DataLoss`]
//! - BREAK-1 →（応答待ちの有限時間打ち切り。REPAIR-5・IO-1。TASK-85 相当）→
//!   [`IoErrorCode::Timeout`]
//!
//! CI ステージ 3（`cargo test --workspace --test '*'`）が本ファイルを自動的に
//! 拾う。CI 上での 100% 検出の実証レポートは #123（TASK-89.2）、人間による妥当性
//! 判断は #124（TASK-89.h1）が扱う（本ファイルの範囲外）。
//!
//! ## テストビルド限定であることの確認（受け入れ基準 1）
//!
//! 本ファイルは `crates/io/tests/` 配下の結合テストターゲットであり、Cargo は
//! これを `kind = ["test"]` として扱う（`cargo metadata` で確認できる。
//! `AGENTS.md`「新機能追加時に更新すべきテスト一覧」参照）ため lib・release
//! 成果物にはリンクされない。先頭の `#![cfg(test)]` は結合テストでは常に真だが、
//! ビルド設定として明示するために付ける。注入コード（[`AckDropping`]・
//! [`tamper_declared_len`]・[`MemEnd`] 等）はすべて本ファイル内に閉じており、
//! `crates/io/src/` には一切存在しない（`git grep` で確認可能）。

use std::sync::mpsc;
use std::time::{Duration, Instant};

use fandhe_container_io::client::{InFlightLimit, MAX_IN_FLIGHT_LIMIT, PipelineClient, SendQueue};
use fandhe_container_io::observe::NoopSendObserver;
use fandhe_container_io::payload::{WireRequestId, decode_ack, decode_request, encode_request};
use fandhe_container_io::protocol::{Frame, FrameHeader, FrameKind};
use fandhe_container_io::transport::{FrameReceiver, FrameSender, IoTimeout};
use fandhe_container_io::writeback::{
    BatchSink, SinkWriteReport, WritebackTimeouts, serve_connection,
};
use fandhe_container_io::{AckReceipt, BatchConfig, FRAME_HEADER_LEN, IoError, IoErrorCode};

/// タイムアウト秒数を上書きする環境変数名（`tests/responsiveness.rs` と同名。
/// REPAIR-5・REPAIR-10 (c)）。
const TEST_TIMEOUT_ENV: &str = "FANDHE_CONTAINER_TEST_TIMEOUT_SECS";

/// 環境変数未設定時の既定タイムアウト秒数（`tests/responsiveness.rs` と同じ値。
/// AGENTS.md「推奨タイムアウト値」の上限で、CI が渡す値と一致する）。
const DEFAULT_TEST_TIMEOUT_SECS: u64 = 10;

/// 許容するタイムアウト秒数の下限（`tests/responsiveness.rs` と同じ）。
const MIN_TEST_TIMEOUT_SECS: u64 = 5;

/// 許容するタイムアウト秒数の上限（[`fandhe_container_io::transport::MAX_IO_TIMEOUT`]
/// と一致させる。`tests/responsiveness.rs` と同じ）。
const MAX_TEST_TIMEOUT_SECS: u64 = 10;

/// 同テストが watchdog に使う猶予（`tests/responsiveness.rs` の
/// `HANG_GUARD_GRACE` と同じ値・同じ理由）。
const HANG_GUARD_GRACE: Duration = Duration::from_secs(2);

/// `FANDHE_CONTAINER_TEST_TIMEOUT_SECS` の生の値から許容範囲の秒数を取り出す
/// 純関数（`tests/responsiveness.rs` の同名関数のローカルコピー。env を直接
/// 触らないため独立したユニットテストで境界値を確認できる）。
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

/// `FANDHE_CONTAINER_TEST_TIMEOUT_SECS` を読み、応答待ちに使う [`IoTimeout`] を
/// 組み立てる（`tests/responsiveness.rs` の同名関数と同じ方針。範囲外・非数値は
/// fail-closed で panic させる）。
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
/// `tests/responsiveness.rs` と同じ関数の独立コピーのため、同じ観点を最低限
/// 確認する（全 OS で実行）。
#[test]
fn repair7_timeout_setting_defaults_to_10s_when_unset() {
    assert_eq!(parse_test_timeout_secs(None), Ok(10));
}

#[test]
fn repair7_timeout_setting_accepts_boundary_values() {
    assert_eq!(parse_test_timeout_secs(Some("5")), Ok(5));
    assert_eq!(parse_test_timeout_secs(Some("10")), Ok(10));
}

#[test]
fn repair7_timeout_setting_rejects_out_of_range_and_non_numeric() {
    assert!(parse_test_timeout_secs(Some("4")).is_err());
    assert!(parse_test_timeout_secs(Some("11")).is_err());
    assert!(parse_test_timeout_secs(Some("abc")).is_err());
}

/// `handle` の join を最大 `limit` だけ待つ（REPAIR-5: critical path 上に上限なしの
/// `join()` を置かない。`tests/responsiveness.rs` の同名関数と同じ実装）。
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

/// [`MemEnd`] が未検証のバイト列を無制限に溜め込まないための上限
/// （security.md「不安全な設計」観点: ヘッダが読めるまでは境界が分からないため、
/// バッファ自体の総量に別途上限を設ける）。本ファイルで使うペイロードは
/// いずれも数十バイトのため、通常の試験では到達しない。
const MAX_MEM_BUFFERED_BYTES: usize = 1024 * 1024;

/// インメモリの双方向バイトパイプの片側（[`mem_pipe`] 参照）。
///
/// `crate::transport::FrameSender` / `FrameReceiver` をテストプロセス内で満たす
/// 代用トランスポート（REPAIR-3: 本番のトランスポート実装ではない）。
/// `tests/frame_integrity.rs` の `stream_read_frame` と同じ「申告された長さぶん
/// だけを読む」ストリーム読みの契約を、`recv_frame` 呼び出しをまたいで
/// 持ち越せるバッファ付きで再現する。
///
/// `crate::transport` モジュールドキュメントの P1-3 契約（送受信いずれかが一度
/// でも `Err` を返した接続は以後使用不可）を守るため、`poisoned` が真になった
/// 後は実際の送受信を一切行わず [`IoErrorCode::Unavailable`] を返す。
struct MemEnd {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    poisoned: bool,
}

/// 双方向のインメモリパイプを 1 組作る（`(a, b)` の `a` へ送った内容は `b` の
/// 受信に、`b` へ送った内容は `a` の受信に現れる）。一方を drop すると、他方の
/// 次の受信が [`IoErrorCode::Unavailable`] になる（`mpsc::Sender` の drop による
/// 切断検知。実ソケットの EOF と同じ意味論）。
fn mem_pipe() -> (MemEnd, MemEnd) {
    let (a_tx, a_rx) = mpsc::channel();
    let (b_tx, b_rx) = mpsc::channel();
    (
        MemEnd {
            tx: a_tx,
            rx: b_rx,
            buf: Vec::new(),
            poisoned: false,
        },
        MemEnd {
            tx: b_tx,
            rx: a_rx,
            buf: Vec::new(),
            poisoned: false,
        },
    )
}

impl MemEnd {
    /// BREAK-2 の改ざん済みバイト列を送るテスト用の入口（正常なフレームは
    /// [`FrameSender::send_frame`] 経由で送れる）。
    fn send_raw(&mut self, bytes: &[u8]) -> Result<(), IoError> {
        if self.poisoned {
            return Err(unavailable());
        }
        match self.tx.send(bytes.to_vec()) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.poisoned = true;
                Err(unavailable())
            }
        }
    }

    /// `self.buf` が少なくとも `needed` バイトになるまで、`deadline` を上限に
    /// 受信チャンクを積み増す。
    fn fill_buf_until(&mut self, needed: usize, deadline: Instant) -> Result<(), IoError> {
        while self.buf.len() < needed {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| IoError::new(IoErrorCode::Timeout, "mem pipe deadline elapsed"))?;
            match self.rx.recv_timeout(remaining) {
                Ok(chunk) => {
                    if self.buf.len().saturating_add(chunk.len()) > MAX_MEM_BUFFERED_BYTES {
                        return Err(IoError::new(
                            IoErrorCode::ResourceExhausted,
                            "mem pipe buffered bytes exceeded the test limit",
                        ));
                    }
                    self.buf.extend_from_slice(&chunk);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(IoError::new(
                        IoErrorCode::Timeout,
                        "mem pipe recv timed out",
                    ));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(unavailable());
                }
            }
        }
        Ok(())
    }
}

fn unavailable() -> IoError {
    IoError::new(
        IoErrorCode::Unavailable,
        "mem pipe is poisoned or the peer has disconnected",
    )
}

impl FrameSender for MemEnd {
    type Frame = Frame;

    fn send_frame(&mut self, frame: &Frame, _timeout: IoTimeout) -> Result<(), IoError> {
        self.send_raw(&frame.encode())
    }
}

impl FrameReceiver for MemEnd {
    type Frame = Frame;

    fn recv_frame(&mut self, timeout: IoTimeout) -> Result<Frame, IoError> {
        if self.poisoned {
            return Err(unavailable());
        }
        let deadline = Instant::now() + timeout.as_duration();
        let result = (|| {
            self.fill_buf_until(FRAME_HEADER_LEN, deadline)?;
            let (header_bytes, _) = self
                .buf
                .split_first_chunk::<FRAME_HEADER_LEN>()
                .ok_or_else(|| {
                    IoError::new(IoErrorCode::Internal, "buffered bytes shorter than header")
                })?;
            let header = FrameHeader::from_bytes(*header_bytes)?;
            let body_len = header.body_len();
            let total = FRAME_HEADER_LEN
                .checked_add(body_len)
                .ok_or_else(|| IoError::new(IoErrorCode::Internal, "frame length overflowed"))?;
            self.fill_buf_until(total, deadline)?;
            let body: Vec<u8> = self.buf[FRAME_HEADER_LEN..total].to_vec();
            self.buf.drain(..total);
            Frame::decode_body(header, &body)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

/// [`BatchSink`] のインメモリ実装: 受け取った各 `Write` の body を到着順に
/// 追記する（`crates/io/src/writeback.rs` の `AppendFileSink::write_batch` と
/// 同じ「到着順に body を書く」意味論を、ファイルではなく `Vec<u8>` へ写す）。
struct MemSink {
    written: Vec<u8>,
}

impl MemSink {
    fn new() -> Self {
        Self {
            written: Vec::new(),
        }
    }
}

impl BatchSink for MemSink {
    fn write_batch(
        &mut self,
        batch: &fandhe_container_io::batch::Batch,
    ) -> Result<SinkWriteReport, IoError> {
        let mut frames_written: usize = 0;
        let mut bytes_written: u64 = 0;
        for frame in batch.frames() {
            let envelope = decode_request(frame)?;
            self.written.extend_from_slice(envelope.body());
            frames_written = frames_written
                .checked_add(1)
                .ok_or_else(|| IoError::new(IoErrorCode::Internal, "frames_written overflowed"))?;
            let body_len = u64::try_from(envelope.body().len())
                .map_err(|_| IoError::new(IoErrorCode::Internal, "body length overflowed"))?;
            bytes_written = bytes_written
                .checked_add(body_len)
                .ok_or_else(|| IoError::new(IoErrorCode::Internal, "bytes_written overflowed"))?;
        }
        Ok(SinkWriteReport::new(frames_written, bytes_written))
    }
}

/// PoC-8 の BREAK-1（ACK 未送信）をテスト内で再現するデコレータ（REPAIR-3:
/// 実装済みを装わない。本番の [`serve_connection`] には「ACK を送らない」切り替え
/// 口を追加しない。あくまでテストローカルの代用実装）。
///
/// サーバー側の接続（`T: FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>`）
/// を包み、[`FrameKind::Ack`] / [`FrameKind::FlushAck`] の [`FrameSender::send_frame`]
/// 呼び出しだけを黙って捨てて `Ok(())` を返す。サーバーは ACK を送ったつもりでいるが
/// （[`fandhe_container_io::writeback::WritebackStats::acks_sent`] は増える）、相手には
/// 届かない。それ以外の種別（`Write`・`Flush`）はそのまま委譲し、[`FrameReceiver::recv_frame`]
/// も一切変更せずに委譲する。
struct AckDropping<T> {
    inner: T,
}

impl<T> AckDropping<T> {
    fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> FrameSender for AckDropping<T>
where
    T: FrameSender<Frame = Frame>,
{
    type Frame = Frame;

    fn send_frame(&mut self, frame: &Frame, timeout: IoTimeout) -> Result<(), IoError> {
        if matches!(frame.kind(), FrameKind::Ack | FrameKind::FlushAck) {
            // BREAK-1 相当: ACK フレームを実際には送らずに捨てる。
            return Ok(());
        }
        self.inner.send_frame(frame, timeout)
    }
}

impl<T> FrameReceiver for AckDropping<T>
where
    T: FrameReceiver<Frame = Frame>,
{
    type Frame = Frame;

    fn recv_frame(&mut self, timeout: IoTimeout) -> Result<Frame, IoError> {
        self.inner.recv_frame(timeout)
    }
}

/// `encoded`（[`Frame::encode`] の出力）の先頭 [`FRAME_HEADER_LEN`] バイトを、
/// 種別はそのまま・ペイロード長だけを `declared` に差し替えた、自己整合的な
/// （`header_crc` を新しい `payload_len` に対して正しく再計算した）ヘッダへ
/// 丸ごと入れ替えたコピーを返す（`tests/frame_integrity.rs` の同名関数と同じ
/// 手法のローカルコピー。BREAK-2 の「長さの申告だけを嘘にする」性質をワイヤー
/// レベルで再現する）。
fn tamper_declared_len(encoded: &[u8], declared: u32) -> Vec<u8> {
    let (header_bytes, rest) = encoded
        .split_first_chunk::<FRAME_HEADER_LEN>()
        .expect("encoded frame must contain a full fixed-length header");
    let original_header =
        FrameHeader::from_bytes(*header_bytes).expect("original encoded header must be valid");
    let tampered_header = FrameHeader::new(original_header.kind(), declared)
        .expect("declared length must be within MAX_PAYLOAD_LEN for this helper");

    let mut tampered = Vec::with_capacity(FRAME_HEADER_LEN + rest.len());
    tampered.extend_from_slice(&tampered_header.to_bytes());
    tampered.extend_from_slice(rest);
    tampered
}

/// `value` に対応する [`WireRequestId`] を作る（`tests/writeback.rs` の `wire_id`
/// ヘルパーと同じ理由・同じ実装。`WireRequestId::from_wire` は非公開のため、
/// client 側の採番経路〔[`SendQueue::register`]〕を経由して作る）。
fn wire_id(value: u64) -> WireRequestId {
    let limit = InFlightLimit::new(MAX_IN_FLIGHT_LIMIT).expect("MAX_IN_FLIGHT_LIMIT must be valid");
    let mut queue = SendQueue::new(limit);
    let mut last = None;
    for _ in 0..=value {
        let registered = queue
            .register(FrameKind::Write)
            .expect("register must succeed");
        last = Some(registered.id());
    }
    WireRequestId::from(last.expect("loop runs at least once"))
}

fn short_timeout() -> IoTimeout {
    IoTimeout::new(Duration::from_millis(200)).expect("200ms must be a valid timeout")
}

/// TASK-89.1・REPAIR-5・#122（対照）: [`AckDropping`] を挟まない通常の
/// [`serve_connection`] に対して 1 件 `Write` を送ると、ACK が期待どおりの
/// タイムアウト内に届く。
#[test]
fn repair7_repair5_break1_control_ack_arrives_without_injection() {
    let timeout = response_timeout();
    let (client_end, server_end) = mem_pipe();
    let mut sink = MemSink::new();
    let config = BatchConfig::new(1).expect("1 must be a valid batch size");
    let timeouts = WritebackTimeouts {
        recv: timeout,
        send: timeout,
    };

    let server_thread = std::thread::spawn(move || {
        let mut connection = server_end;
        serve_connection(&mut connection, config, &mut sink, timeouts)
    });

    let client_thread = std::thread::spawn(move || {
        let mut client =
            PipelineClient::new(client_end, InFlightLimit::default(), NoopSendObserver);
        client
            .send(FrameKind::Write, b"break1-payload", timeout)
            .expect("send must succeed");
        let receipt = client
            .recv_ack(timeout)
            .expect("recv_ack must succeed without injection");
        let is_poisoned = client.is_poisoned();
        drop(client);
        (receipt, is_poisoned)
    });

    let (receipt, is_poisoned) = client_thread.join().expect("client thread must not panic");
    let AckReceipt::Write(write_ack) = receipt else {
        panic!("expected a Write ack, got {receipt:?}");
    };
    assert_eq!(write_ack.request().kind(), FrameKind::Write);
    assert!(!is_poisoned);

    let report = join_within(server_thread, timeout.as_duration() + HANG_GUARD_GRACE)
        .expect("server thread must finish within the watchdog")
        .expect("server thread must not panic");
    assert_eq!(report.stats.batches_written, 1);
    assert_eq!(report.stats.acks_sent, 1);
    assert_eq!(report.stats.discarded_pending_frames, 0);
    assert_eq!(report.end.code(), IoErrorCode::Unavailable);
}

/// TASK-89.1・REPAIR-5・BREAK-1・#122: サーバー側の接続を [`AckDropping`] で
/// 包むと、`Write` はサーバーへ届き書き込まれる（`batches_written == 1`・
/// `acks_sent == 1`。サーバーは ACK を送ったつもり）のに、その ACK は相手に
/// 届かず、クライアントの [`PipelineClient::recv_ack`] が
/// [`IoErrorCode::Timeout`] として検出する。
///
/// サーバー側の 2 回目の `recv_frame`（ACK 送出後、次のフレームを待つ）が
/// クライアントの ACK 待ちタイムアウトと同時に競合しないよう、サーバー側の
/// 受信タイムアウトは意図的に短く（[`short_timeout`]）設定する。これにより
/// サーバーは確定的に先にタイムアウトし、クライアント側の検証対象（ACK 未到達の
/// 検出）と無関係な理由でテストが不安定になることを避ける。
///
/// サーバーが自身の短いタイムアウトで先に `serve_connection` を終えると、
/// `AckDropping`（と内部の `server_end`）がスレッド終了時に drop され、
/// `mpsc::Sender` が 1 つ減る。`MemEnd` の送受信は `mpsc::channel` の
/// 送信側がすべて drop されたときに初めて「切断」（`Unavailable`）になる
/// ため、これを `keepalive_tx`（`server_end.tx` の clone）で 1 つ余分に
/// 保持し、クライアント側の ACK 待ちが「サーバーが早く終わったことによる
/// 見せかけの切断」ではなく、本来検出したい `recv_ack` 自体の
/// タイムアウト（[`IoErrorCode::Timeout`]）として決定的に終わるようにする。
#[test]
fn repair7_repair5_break1_ack_dropping_server_detected_as_timeout() {
    let timeout = response_timeout();
    let (client_end, server_end) = mem_pipe();
    let keepalive_tx = server_end.tx.clone();
    let mut sink = MemSink::new();
    let config = BatchConfig::new(1).expect("1 must be a valid batch size");
    let timeouts = WritebackTimeouts {
        recv: short_timeout(),
        send: short_timeout(),
    };

    let server_thread = std::thread::spawn(move || {
        let mut connection = AckDropping::new(server_end);
        serve_connection(&mut connection, config, &mut sink, timeouts)
    });

    let client_thread = std::thread::spawn(move || {
        let mut client =
            PipelineClient::new(client_end, InFlightLimit::default(), NoopSendObserver);
        client
            .send(FrameKind::Write, b"break1-payload", timeout)
            .expect("send must succeed");

        let wait_started = Instant::now();
        let first_err = client
            .recv_ack(timeout)
            .expect_err("recv_ack must fail once the ack wait exceeds the timeout")
            .code();
        let elapsed = wait_started.elapsed();
        let is_poisoned = client.is_poisoned();
        (first_err, elapsed, is_poisoned)
    });

    let (first_err, elapsed, is_poisoned) =
        join_within(client_thread, timeout.as_duration() + HANG_GUARD_GRACE)
            .expect("client thread must finish within the watchdog")
            .expect("client thread must not panic");

    assert_eq!(first_err, IoErrorCode::Timeout);
    assert!(
        elapsed + Duration::from_millis(100) >= timeout.as_duration(),
        "ack wait elapsed {elapsed:?} must be close to the {:?} timeout",
        timeout.as_duration()
    );
    assert!(
        elapsed < timeout.as_duration() + HANG_GUARD_GRACE,
        "ack wait elapsed {elapsed:?} must not exceed timeout + grace"
    );
    assert!(is_poisoned);

    let report = join_within(
        server_thread,
        short_timeout().as_duration() + HANG_GUARD_GRACE,
    )
    .expect("server thread must finish within the watchdog (short server timeout)")
    .expect("server thread must not panic");
    // サーバーは Write を受理して書き込み、ACK を送ったつもりでいる
    // （BREAK-1 の本質: 「リクエストは届いたが ACK が届かない」ことを、
    // 「リクエスト自体が届かなかった」ことと区別する）。
    assert_eq!(report.stats.batches_written, 1);
    assert_eq!(report.stats.acks_sent, 1);
    assert_eq!(report.end.code(), IoErrorCode::Timeout);
    drop(keepalive_tx);
}

/// TASK-89.1・REPAIR-2・#122（対照）: 改ざんしていない正常なフレームを
/// [`MemEnd::send_raw`] 経由で送ると、サーバーはバッチを書き込み ACK を返す。
#[test]
fn repair7_repair2_break2_control_well_formed_frame_is_written() {
    let timeout = short_timeout();
    let (mut client_end, server_end) = mem_pipe();
    let mut sink = MemSink::new();
    let config = BatchConfig::new(1).expect("1 must be a valid batch size");
    let timeouts = WritebackTimeouts {
        recv: timeout,
        send: timeout,
    };

    let frame = encode_request(FrameKind::Write, wire_id(0), b"break2-frame-payload")
        .expect("encode_request must succeed");
    client_end
        .send_raw(&frame.encode())
        .expect("send_raw must succeed");

    let server_thread = std::thread::spawn(move || {
        serve_connection(&mut { server_end }, config, &mut sink, timeouts)
    });

    let ack = client_end
        .recv_frame(timeout)
        .expect("client must receive the ack for the well-formed frame");
    let ack_envelope = decode_ack(&ack).expect("ack frame must decode");
    assert_eq!(ack_envelope.kind(), FrameKind::Ack);
    assert_eq!(ack_envelope.id().get(), 0);

    drop(client_end);
    let report = join_within(server_thread, timeout.as_duration() + HANG_GUARD_GRACE)
        .expect("server thread must finish within the watchdog")
        .expect("server thread must not panic");
    assert_eq!(report.stats.batches_written, 1);
    assert_eq!(report.stats.acks_sent, 1);
}

/// TASK-89.1・REPAIR-2・BREAK-2・#122: 申告長を実ペイロード長 − 1 に偽った
/// フレームを送ると、サーバーの本番受信経路（[`MemEnd::recv_frame`] が模す
/// ストリーム読み）がチェックサム再計算の不一致で [`IoErrorCode::DataLoss`]
/// として拒否し、`Write` は一切処理されない。
#[test]
fn repair7_repair2_break2_declared_len_shorter_rejected_by_server() {
    let timeout = short_timeout();
    let (mut client_end, server_end) = mem_pipe();
    let mut sink = MemSink::new();
    let config = BatchConfig::default();
    let timeouts = WritebackTimeouts {
        recv: timeout,
        send: timeout,
    };

    const PAYLOAD: &[u8] = b"break2-frame-payload"; // 20 bytes
    let frame =
        encode_request(FrameKind::Write, wire_id(0), PAYLOAD).expect("encode_request must succeed");
    let encoded = frame.encode();
    let shorter = u32::try_from(PAYLOAD.len() - 1).expect("small length fits in u32");
    let tampered = tamper_declared_len(&encoded, shorter);
    client_end
        .send_raw(&tampered)
        .expect("send_raw must succeed");

    let server_thread = std::thread::spawn(move || {
        serve_connection(&mut { server_end }, config, &mut sink, timeouts)
    });

    let report = join_within(server_thread, timeout.as_duration() + HANG_GUARD_GRACE)
        .expect("server thread must finish within the watchdog")
        .expect("server thread must not panic");

    assert_eq!(report.end.code(), IoErrorCode::DataLoss);
    assert_eq!(report.stats.frames_received, 0);
    assert_eq!(report.stats.batches_written, 0);
    assert_eq!(report.stats.acks_sent, 0);

    // クライアント側は ACK を受け取れない（サーバーが Write を処理していない
    // ため）。検証の主眼はサーバー側の拒否（上記）。
    let client_result = client_end.recv_frame(timeout);
    assert!(client_result.is_err(), "client must not receive an ack");
}

/// security.md「情報漏えい」観点（`tests/frame_integrity.rs` の同名ケースに
/// 倣う）: BREAK-2 の拒否エラーメッセージにペイロード内容が含まれない。
#[test]
fn repair7_repair2_break2_error_message_omits_payload_content() {
    let timeout = short_timeout();
    let (mut client_end, mut server_end) = mem_pipe();
    let mut sink = MemSink::new();
    let config = BatchConfig::default();
    let timeouts = WritebackTimeouts {
        recv: timeout,
        send: timeout,
    };

    const PAYLOAD: &[u8] = b"break2-frame-payload";
    let frame =
        encode_request(FrameKind::Write, wire_id(0), PAYLOAD).expect("encode_request must succeed");
    let encoded = frame.encode();
    let shorter = u32::try_from(PAYLOAD.len() - 1).expect("small length fits in u32");
    let tampered = tamper_declared_len(&encoded, shorter);
    client_end
        .send_raw(&tampered)
        .expect("send_raw must succeed");

    let report = serve_connection(&mut server_end, config, &mut sink, timeouts);
    assert_eq!(report.end.code(), IoErrorCode::DataLoss);
    assert!(
        !report
            .end
            .message()
            .contains(std::str::from_utf8(PAYLOAD).expect("payload fixture must be valid UTF-8"))
    );

    drop(client_end);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use fandhe_container_io::observe::NoopServerObserver;
    use fandhe_container_io::payload::{decode_ack, encode_request};
    use fandhe_container_io::protocol::{FRAME_HEADER_LEN, Frame, FrameHeader, FrameKind};
    use fandhe_container_io::writeback::WritebackTimeouts;
    use fandhe_container_io::{BatchConfig, IoErrorCode, ReceiveLimits, UdsServer};

    /// `stream` からフレームを 1 つ読み取る（クライアント側の簡易受信ヘルパー。
    /// `tests/responsiveness.rs` の `UnixStreamTransport::recv_frame` と同じ
    /// 「申告長ぶんだけ読む」方針の簡易版。本テストではサーバーから返る ACK を
    /// 読んで内容を確かめるためだけに使う）。
    fn read_one_frame(stream: &mut UnixStream, timeout: Duration) -> Frame {
        stream
            .set_read_timeout(Some(timeout))
            .expect("set_read_timeout must succeed");
        let mut header_bytes = [0u8; FRAME_HEADER_LEN];
        stream
            .read_exact(&mut header_bytes)
            .expect("must read the fixed-length frame header");
        let header = FrameHeader::from_bytes(header_bytes).expect("header must decode");
        let mut body = vec![0u8; header.body_len()];
        stream
            .read_exact(&mut body)
            .expect("must read the frame body");
        Frame::decode_body(header, &body).expect("frame body must decode")
    }

    use super::{
        HANG_GUARD_GRACE, MemSink, join_within, response_timeout, tamper_declared_len, wire_id,
    };

    /// `tests/responsiveness.rs` / `tests/writeback.rs` の `TempSocketDir` と同じ
    /// 理由・同じ実装（`sun_path` の長さ上限のため接頭辞を短く保つ）。
    struct TempSocketDir {
        path: PathBuf,
    }

    impl TempSocketDir {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let dir = std::env::temp_dir().join(format!("fcio-bd-{pid}-{n}"));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .expect("must be able to create a temp dir for the socket");
            Self { path: dir }
        }

        fn socket_path(&self) -> PathBuf {
            self.path.join("s.sock")
        }
    }

    impl Drop for TempSocketDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// `path` へ接続を試みる（`tests/responsiveness.rs` の `connect` と同じ方針。
    /// 5 秒固定のリトライ予算で、応答待ちのタイムアウトとは別物）。
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

    /// TASK-89.1・REPAIR-2・#122（対照・UDS）: 実 UDS 上で正しいバイト列を送ると
    /// サーバー（本番の [`fandhe_container_io::server::UdsConnection`]）が
    /// バッチを書き込む。その後クライアント側を drop すると、サーバーは EOF
    /// （[`IoErrorCode::Unavailable`]）で終わる。
    #[test]
    fn repair7_repair2_break2_uds_control_well_formed_frame_is_written() {
        let timeout = response_timeout();
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();

        let mut server =
            UdsServer::bind(&socket_path, ReceiveLimits::default(), NoopServerObserver)
                .expect("bind must succeed on a private, empty path");
        let stream = connect(&socket_path);
        let mut connection = server
            .accept(timeout, NoopServerObserver)
            .expect("server must accept the already-queued client connection");

        const PAYLOAD: &[u8] = b"break2-uds-payload";
        let frame = encode_request(FrameKind::Write, wire_id(0), PAYLOAD)
            .expect("encode_request must succeed");
        let mut stream = stream;
        stream
            .set_write_timeout(Some(timeout.as_duration()))
            .expect("set_write_timeout must succeed");
        stream
            .write_all(&frame.encode())
            .expect("write_all must succeed for a well-formed frame");

        let config = BatchConfig::new(1).expect("1 must be a valid batch size");
        let timeouts = WritebackTimeouts {
            recv: timeout,
            send: timeout,
        };
        let mut sink = MemSink::new();
        let server_thread = std::thread::spawn(move || {
            fandhe_container_io::writeback::serve_connection(
                &mut connection,
                config,
                &mut sink,
                timeouts,
            )
        });

        // サーバーが返す ACK を読んでから接続を閉じる（先に drop すると、
        // サーバーの ACK 送出が閉じた相手への書き込みとして失敗し、
        // acks_sent が 0 のまま終わってしまう）。
        let ack = read_one_frame(&mut stream, timeout.as_duration());
        let ack_envelope = decode_ack(&ack).expect("ack frame must decode");
        assert_eq!(ack_envelope.kind(), FrameKind::Ack);
        assert_eq!(ack_envelope.id().get(), 0);
        drop(stream);

        let report = join_within(server_thread, timeout.as_duration() + HANG_GUARD_GRACE)
            .expect("server thread must finish within the watchdog")
            .expect("server thread must not panic");
        assert_eq!(report.stats.batches_written, 1);
        assert_eq!(report.stats.acks_sent, 1);
        assert_eq!(report.end.code(), IoErrorCode::Unavailable);
    }

    /// TASK-89.1・REPAIR-2・BREAK-2・#122（UDS）: 実 UDS 上で申告長を偽った
    /// バイト列を送ると、本番の受信経路（[`fandhe_container_io::server::UdsConnection::recv_frame`]）
    /// がチェックサム再計算の不一致で [`IoErrorCode::DataLoss`] として拒否する。
    #[test]
    fn repair7_repair2_break2_uds_declared_len_shorter_rejected_by_production_recv() {
        let timeout = response_timeout();
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();

        let mut server =
            UdsServer::bind(&socket_path, ReceiveLimits::default(), NoopServerObserver)
                .expect("bind must succeed on a private, empty path");
        let stream = connect(&socket_path);
        let mut connection = server
            .accept(timeout, NoopServerObserver)
            .expect("server must accept the already-queued client connection");

        const PAYLOAD: &[u8] = b"break2-uds-payload"; // 18 bytes
        let frame = encode_request(FrameKind::Write, wire_id(0), PAYLOAD)
            .expect("encode_request must succeed");
        let encoded = frame.encode();
        let shorter = u32::try_from(PAYLOAD.len() - 1).expect("small length fits in u32");
        let tampered = tamper_declared_len(&encoded, shorter);

        let mut stream = stream;
        stream
            .set_write_timeout(Some(timeout.as_duration()))
            .expect("set_write_timeout must succeed");
        stream
            .write_all(&tampered)
            .expect("write_all must succeed for the tampered frame");
        drop(stream);

        let config = BatchConfig::default();
        let timeouts = WritebackTimeouts {
            recv: timeout,
            send: timeout,
        };
        let mut sink = MemSink::new();
        let server_thread = std::thread::spawn(move || {
            fandhe_container_io::writeback::serve_connection(
                &mut connection,
                config,
                &mut sink,
                timeouts,
            )
        });

        let report = join_within(server_thread, timeout.as_duration() + HANG_GUARD_GRACE)
            .expect("server thread must finish within the watchdog")
            .expect("server thread must not panic");
        assert_eq!(report.end.code(), IoErrorCode::DataLoss);
        assert_eq!(report.stats.frames_received, 0);
        assert_eq!(report.stats.batches_written, 0);
        assert_eq!(report.stats.acks_sent, 0);
    }
}
