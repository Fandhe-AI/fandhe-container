//! UDS 上の長さ接頭辞フレームの送受信ループ（TASK-116.2・#393。PLUG-1・WIN-1・REPAIR-5）。
//!
//! `main.rs`（バイナリ入口）が `UdsStream::connect` で core の listener へ接続した後、本モジュールの
//! [`serve`] を呼ぶ。core 側 proxy（`ResidentPlugin`。TASK-114）は 1 本の接続で要求を順次往復させる。
//! 本モジュールは `fandhe-container-plugin` の `frame`・`message`・`transport` の公開 API だけで受信を組み、
//! 共有 crate は変更しない。
//!
//! # アイドル待ちの 2 段階受信
//! `UdsStream::read_frame` の失敗（`Timeout` 含む）は接続を使用不可にするため、要求間隔が長い常駐モードの
//! アイドル待ちには使えない。そこで生の `Read` で [`IDLE_POLL`] 周期のポーリングを行い、
//! 最初の 1 バイトが届いた時点からフレーム全体の合計期限 [`FRAME_DEADLINE`] を課す（少量ずつ送る
//! 引き延ばしへの対策。REPAIR-5）。ヘッダ検証（CRC・version・長さ上限）後に本体を小さな塊で確保し、
//! 無制限の確保を避ける。アイドル中は相手の切断（EOF）で終了するため、孤児プロセスにならない。
//!
//! # エラー方針（fail-closed）
//! 転送・フレーム不正、エンベロープ復号失敗、プロトコル違反（plugin へ届いた `Response` / `Error`）は
//! 境界がずれうるため応答せず切断する（[`serve`] が `Err`）。妥当な要求でハンドラが失敗した場合のみ、
//! 同じ `MessageId` の `Error` 応答を返して継続する。1 プロセス = 1 接続のため、不正フレームの影響は
//! その接続に閉じる。
//!
//! # 未実装範囲（REPAIR-3）
//! 本体型 `Vec<String>`（先頭要素が操作名）は spec 未規定の暫定契約で、型つき本体への置換は TASK-114 で確定する。
//! 既定ハンドラ [`UnimplementedHandler`] は全操作に `UNIMPLEMENTED` を返す（アダプタ未結線時・テスト用。
//! 実ハンドラは `adapter::WindowsRuntimeAdapter`・#394）。ヘルスチェック（`ping`）は adapter が応答する（#396）。
//!
//! # シャットダウン（TASK-116.5・#396）
//! [`serve_until`] は停止フラグ（SIGTERM。`sys::install_sigterm_flag`）を、フレームを 1 バイトも
//! 受けていない間だけ [`IDLE_POLL`] ごとに確認し、立っていれば [`LoopExit::ShutdownRequested`] で抜ける。
//! 受信途中のフレームは打ち切らず [`FRAME_DEADLINE`] 内で受け切って応答する（境界ずれ防止）。
//! 呼び出し側（`main.rs`）が抜けた後に共有マウントを解除して終了する。
//!
//! 対応 ID: TASK-116・PLUG-1・PLUG-2・PLUG-5・WIN-1・REPAIR-2・REPAIR-3・REPAIR-5・REPAIR-12。

use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use fandhe_container_plugin::{
    ControlMessage, FRAME_HEADER_LEN, Frame, FrameHeader, MessageId, PluginError, PluginErrorCode,
    RpcTimeout, UDS_RPC_TIMEOUT_DEFAULT, UdsStream, decode_message, encode_message,
};

/// アイドル待ちの read ポーリング周期。停止フラグの確認周期でもある（検知遅れの上限。#396）。
pub const IDLE_POLL: Duration = Duration::from_secs(1);

/// 最初の 1 バイトを受けてからフレーム全体を受け切るまでの合計期限（REPAIR-5）。
pub const FRAME_DEADLINE: Duration = UDS_RPC_TIMEOUT_DEFAULT;

/// 要求本体（文字列配列）の要素数上限。外部入力の検証用。
pub const REQUEST_BODY_MAX_ITEMS: usize = 64;

/// 本体を読む際の 1 回あたりの確保単位（ヘッダ検証後も確保を段階的にする）。
const BODY_CHUNK: usize = 64 * 1024;

/// 応答の符号化失敗時に返す固定文言（入力断片を載せない）。
const MSG_ENCODE_FAILED: &str = "failed to encode response";

/// 要求ハンドラの境界。`body` は先頭要素が操作名・以降が引数の暫定契約（TASK-114 で型つき本体へ置換）。
///
/// `Err` は同じ `MessageId` の `Error` 応答になる。メッセージに入力値を含めないこと（外部入力の反射防止）。
pub trait RequestHandler {
    /// 1 要求を処理して応答本体を返す。
    fn handle(&mut self, body: &[String]) -> Result<Vec<String>, PluginError>;
}

impl<F> RequestHandler for F
where
    F: FnMut(&[String]) -> Result<Vec<String>, PluginError>,
{
    fn handle(&mut self, body: &[String]) -> Result<Vec<String>, PluginError> {
        self(body)
    }
}

/// 全操作に `UNIMPLEMENTED` を返す既定ハンドラ。実装済みを装わない（REPAIR-3）。
/// 実ハンドラは `adapter::WindowsRuntimeAdapter`（#394・TASK-116.3）で、本型はテスト用に残す。
#[derive(Debug, Default, Clone, Copy)]
pub struct UnimplementedHandler;

impl RequestHandler for UnimplementedHandler {
    fn handle(&mut self, _body: &[String]) -> Result<Vec<String>, PluginError> {
        Err(PluginError::new(
            PluginErrorCode::Unimplemented,
            "operation is not implemented",
        ))
    }
}

/// ループの正常終了要因。将来の要因追加に備え `non_exhaustive`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoopExit {
    /// 相手（core）が接続を閉じた。
    PeerClosed,
    /// 停止フラグ（SIGTERM）が立った（TASK-116.5・#396。WIN-1）。
    ShutdownRequested,
}

fn error_frame(id: MessageId, error: PluginError) -> Result<Frame, PluginError> {
    encode_message(&ControlMessage::<Vec<String>>::Error { id, error })
}

/// 受信フレーム 1 つを処理して応答フレームを作る（I/O なしの純粋関数）。
///
/// `Ok` は送るべき応答（`Response` または `Error`）。`Err` は「応答せず切断」を意味する
/// （エンベロープ復号失敗・plugin 宛てではない `Response` / `Error`・未知 variant。PLUG-1）。
pub fn handle_frame<H: RequestHandler>(
    frame: &Frame,
    handler: &mut H,
) -> Result<Frame, PluginError> {
    let msg = decode_message::<Vec<String>>(frame)?;
    let (id, body) = match msg {
        ControlMessage::Request { id, body } => (id, body),
        // plugin は要求の受け手であり、Response / Error が届くのはプロトコル違反。
        ControlMessage::Response { .. } | ControlMessage::Error { .. } => {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "unexpected message kind for plugin",
            ));
        }
        _ => {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "unknown message kind",
            ));
        }
    };
    let result = if body.is_empty() || body.len() > REQUEST_BODY_MAX_ITEMS {
        Err(PluginError::new(
            PluginErrorCode::InvalidArgument,
            "request body must have 1 to 64 items",
        ))
    } else {
        handler.handle(&body)
    };
    let reply = match result {
        Ok(out) => encode_message(&ControlMessage::Response { id, body: out }),
        Err(e) => error_frame(id, e),
    };
    match reply {
        Ok(f) => Ok(f),
        // 応答が大きすぎる等。同じ ID の固定文言 Error へ差し替える。
        Err(_) => error_frame(
            id,
            PluginError::new(PluginErrorCode::Internal, MSG_ENCODE_FAILED),
        ),
    }
}

/// [`recv_frame`] の結果。
#[derive(Debug)]
enum Recv {
    Frame(Frame),
    /// フレーム境界での正常な EOF。
    Closed,
    /// 停止フラグが立った（フレームを 1 バイトも受けていない時点のみ）。
    Shutdown,
    /// 切断済み接続の生 I/O が拒否された（`io_timeout_unrestored`）。`read_frame` へフォールバックする。
    RawUnusable,
}

fn is_idle(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

/// io エラー文言は環境依存でパス等を含みうるため載せず、固定文言にする。
fn io_err() -> PluginError {
    PluginError::new(PluginErrorCode::Unavailable, "frame read failed")
}

fn timeout_err() -> PluginError {
    PluginError::new(PluginErrorCode::Timeout, "frame receive deadline exceeded")
}

/// テスト用の薄いラッパー（決して立たない停止フラグで [`recv_frame_until`] を呼ぶ）。
#[cfg(test)]
fn recv_frame<R: Read>(r: &mut R, deadline: Duration) -> Result<Recv, PluginError> {
    recv_frame_until(r, deadline, &AtomicBool::new(false))
}

/// フレーム 1 つを 2 段階で受信する。`r` の read 期限は呼び出し側が [`IDLE_POLL`] 程度に設定しておく。
/// `stop` は 1 バイトも受けていない間（`got == 0`）だけ確認する。
fn recv_frame_until<R: Read>(
    r: &mut R,
    deadline: Duration,
    stop: &AtomicBool,
) -> Result<Recv, PluginError> {
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    let mut got = 0usize;
    let mut started: Option<Instant> = None;
    while got < FRAME_HEADER_LEN {
        if started.is_some_and(|t| t.elapsed() >= deadline) {
            return Err(timeout_err());
        }
        if got == 0 && stop.load(Ordering::SeqCst) {
            return Ok(Recv::Shutdown);
        }
        let Some(slot) = hdr.get_mut(got..) else {
            return Err(PluginError::new(PluginErrorCode::Internal, "header index"));
        };
        match r.read(slot) {
            Ok(0) if got == 0 => return Ok(Recv::Closed),
            Ok(0) => {
                return Err(PluginError::new(
                    PluginErrorCode::Unavailable,
                    "connection closed inside a frame header",
                ));
            }
            Ok(n) => {
                got = got.saturating_add(n);
                started.get_or_insert_with(Instant::now);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted || is_idle(e.kind()) => {}
            Err(e) if got == 0 && e.kind() == io::ErrorKind::NotConnected => {
                return Ok(Recv::RawUnusable);
            }
            Err(_) => return Err(io_err()),
        }
    }
    let started = started.unwrap_or_else(Instant::now);
    // 検証（CRC → version → 長さ上限）を通るまで本体用の確保はしない。
    let header = FrameHeader::from_bytes(hdr)?;
    let total = header.body_len();
    let mut body: Vec<u8> = Vec::new();
    while body.len() < total {
        if started.elapsed() >= deadline {
            return Err(timeout_err());
        }
        let have = body.len();
        let want = total.saturating_sub(have).min(BODY_CHUNK);
        body.resize(have.saturating_add(want), 0);
        let Some(slot) = body.get_mut(have..) else {
            return Err(PluginError::new(PluginErrorCode::Internal, "body index"));
        };
        match r.read(slot) {
            Ok(0) => {
                return Err(PluginError::new(
                    PluginErrorCode::Unavailable,
                    "connection closed inside a frame body",
                ));
            }
            Ok(n) => body.truncate(have.saturating_add(n)),
            Err(e) if e.kind() == io::ErrorKind::Interrupted || is_idle(e.kind()) => {
                body.truncate(have);
            }
            Err(_) => return Err(io_err()),
        }
    }
    Ok(Recv::Frame(Frame::decode_body(header, &body)?))
}

/// [`Recv::RawUnusable`] 後の代替受信（`read_frame`）の結果。
#[derive(Debug)]
enum Fallback {
    Frame(Frame),
    Exit(LoopExit),
}

/// 代替受信の期限。通常のポーリングと同じ [`IDLE_POLL`] で、停止フラグの検知遅れを抑える（WIN-1）。
fn fallback_timeout() -> Result<RpcTimeout, PluginError> {
    RpcTimeout::new(IDLE_POLL)
}

/// 代替受信の結果を分類する（I/O なしの純粋関数）。
///
/// 切断済みで読み切った（`Unavailable`）はフレーム境界の切断として `PeerClosed`。期限切れ（`Timeout`）は
/// 停止フラグが立っていれば `ShutdownRequested`、立っていなければ `Err`（接続は使用不可になるため fail-closed）。
fn fallback_outcome(
    res: Result<Frame, PluginError>,
    stop: &AtomicBool,
) -> Result<Fallback, PluginError> {
    match res {
        Ok(f) => Ok(Fallback::Frame(f)),
        Err(e) if e.code() == PluginErrorCode::Unavailable => {
            Ok(Fallback::Exit(LoopExit::PeerClosed))
        }
        Err(e) if e.code() == PluginErrorCode::Timeout && stop.load(Ordering::SeqCst) => {
            Ok(Fallback::Exit(LoopExit::ShutdownRequested))
        }
        Err(e) => Err(e),
    }
}

/// 接続済み `stream` 上で要求を順次処理する（受信 → [`handle_frame`] → 送信の繰り返し）。
///
/// 相手の正常切断で `Ok(LoopExit::PeerClosed)`。転送・フレーム不正・プロトコル違反・送信失敗は `Err`
/// （呼び出し側が接続を捨てて異常終了する。fail-closed）。
pub fn serve<H: RequestHandler>(
    stream: &mut UdsStream,
    handler: &mut H,
) -> Result<LoopExit, PluginError> {
    serve_until(stream, handler, &AtomicBool::new(false))
}

/// [`serve`] に停止フラグを加えたもの。`stop` が立つと次の受信境界で `Ok(LoopExit::ShutdownRequested)`
/// を返す（TASK-116.5・#396）。検知遅れは最大 [`IDLE_POLL`]。
pub fn serve_until<H: RequestHandler>(
    stream: &mut UdsStream,
    handler: &mut H,
    stop: &AtomicBool,
) -> Result<LoopExit, PluginError> {
    stream.set_io_timeout(IDLE_POLL)?;
    loop {
        let frame = match recv_frame_until(stream, FRAME_DEADLINE, stop)? {
            Recv::Frame(f) => f,
            Recv::Shutdown => return Ok(LoopExit::ShutdownRequested),
            Recv::Closed => return Ok(LoopExit::PeerClosed),
            Recv::RawUnusable => {
                // 代替経路でも受信前に停止フラグを確認し、受信期限は IDLE_POLL に絞る（WIN-1・REPAIR-5）。
                if stop.load(Ordering::SeqCst) {
                    return Ok(LoopExit::ShutdownRequested);
                }
                match fallback_outcome(stream.read_frame(fallback_timeout()?), stop)? {
                    Fallback::Frame(f) => f,
                    Fallback::Exit(exit) => return Ok(exit),
                }
            }
        };
        let reply = handle_frame(&frame, handler)?;
        stream.write_frame(&reply, RpcTimeout::default())?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(id: u64, body: &[&str]) -> Frame {
        let body: Vec<String> = body.iter().map(|s| s.to_string()).collect();
        encode_message(&ControlMessage::Request {
            id: MessageId::new(id),
            body,
        })
        .expect("encode")
    }

    fn echo(b: &[String]) -> Result<Vec<String>, PluginError> {
        Ok(b.to_vec())
    }

    fn decoded(f: &Frame) -> ControlMessage<Vec<String>> {
        decode_message(f).expect("decode")
    }

    #[test]
    fn task116_2_plug1_request_gets_response_with_same_id() {
        let r = handle_frame(&req(7, &["op", "a"]), &mut echo).expect("reply");
        match decoded(&r) {
            ControlMessage::Response { id, body } => {
                assert_eq!(id.get(), 7);
                assert_eq!(body, vec!["op".to_string(), "a".to_string()]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn task116_2_plug1_handler_error_becomes_error_reply() {
        let mut h = |_: &[String]| Err(PluginError::new(PluginErrorCode::NotFound, "nope"));
        let r = handle_frame(&req(3, &["x"]), &mut h).expect("reply");
        match decoded(&r) {
            ControlMessage::Error { id, error } => {
                assert_eq!(id.get(), 3);
                assert_eq!(error.code(), PluginErrorCode::NotFound);
                assert_eq!(error.message(), "nope");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn task116_2_plug1_empty_or_oversized_body_is_invalid_argument() {
        let big: Vec<&str> = (0..=REQUEST_BODY_MAX_ITEMS).map(|_| "a").collect();
        for f in [req(1, &[]), req(2, &big)] {
            match decoded(&handle_frame(&f, &mut echo).expect("reply")) {
                ControlMessage::Error { error, .. } => {
                    assert_eq!(error.code(), PluginErrorCode::InvalidArgument);
                    assert_eq!(error.message(), "request body must have 1 to 64 items");
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn task116_2_plug1_malformed_or_wrong_kind_disconnects() {
        let bad = Frame::new(b"not json".to_vec()).expect("frame");
        let e = handle_frame(&bad, &mut echo).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        let unknown =
            Frame::new(br#"{"request":{"id":1,"body":["a"],"extra":1}}"#.to_vec()).expect("frame");
        assert_eq!(
            handle_frame(&unknown, &mut echo).unwrap_err().code(),
            PluginErrorCode::InvalidArgument
        );
        let resp = encode_message(&ControlMessage::Response {
            id: MessageId::new(1),
            body: vec!["a".to_string()],
        })
        .expect("encode");
        let e = handle_frame(&resp, &mut echo).unwrap_err();
        assert_eq!(e.message(), "unexpected message kind for plugin");
    }

    #[test]
    fn task116_2_plug1_oversized_reply_becomes_internal_error() {
        let mut h = |_: &[String]| Ok(vec!["a".repeat(17 * 1024 * 1024)]);
        match decoded(&handle_frame(&req(9, &["x"]), &mut h).expect("reply")) {
            ControlMessage::Error { id, error } => {
                assert_eq!(id.get(), 9);
                assert_eq!(error.code(), PluginErrorCode::Internal);
                assert_eq!(error.message(), MSG_ENCODE_FAILED);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn task116_2_plug1_unimplemented_handler() {
        match decoded(&handle_frame(&req(5, &["op"]), &mut UnimplementedHandler).expect("r")) {
            ControlMessage::Error { error, .. } => {
                assert_eq!(error.code(), PluginErrorCode::Unimplemented);
                assert_eq!(error.message(), "operation is not implemented");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// 1 回の read で最大 `step` バイトだけ返し、尽きたら EOF、先頭 `idle` 回は WouldBlock を返す読み手。
    /// `stall` が真なら 1 バイト以上読んだ後は永遠に WouldBlock（引き延ばしの模擬）。
    struct Chunky {
        data: Vec<u8>,
        pos: usize,
        step: usize,
        idle: usize,
        stall: bool,
    }

    impl Read for Chunky {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.idle > 0 {
                self.idle -= 1;
                return Err(io::ErrorKind::WouldBlock.into());
            }
            if self.stall && self.pos > 0 {
                std::thread::sleep(Duration::from_millis(5));
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let rest = self.data.get(self.pos..).unwrap_or(&[]);
            let n = rest.len().min(self.step).min(buf.len());
            let src = rest.get(..n).unwrap_or(&[]);
            if let Some(dst) = buf.get_mut(..n) {
                dst.copy_from_slice(src);
            }
            self.pos += n;
            Ok(n)
        }
    }

    fn chunky(data: Vec<u8>, step: usize, idle: usize) -> Chunky {
        Chunky {
            data,
            pos: 0,
            step,
            idle,
            stall: false,
        }
    }

    const LONG: Duration = Duration::from_secs(5);

    #[test]
    fn task116_2_plug1_recv_reassembles_split_frame_after_idle() {
        let f = req(1, &["op"]);
        let mut r = chunky(f.encode(), 3, 2);
        match recv_frame(&mut r, LONG).expect("recv") {
            Recv::Frame(got) => assert_eq!(got.payload(), f.payload()),
            other => panic!("unexpected {other:?}"),
        }
        // 境界での EOF は正常切断。
        assert!(matches!(
            recv_frame(&mut r, LONG).expect("recv"),
            Recv::Closed
        ));
    }

    #[test]
    fn task116_2_plug1_recv_rejects_bad_header() {
        let mut bytes = req(1, &["op"]).encode();
        if let Some(b) = bytes.get_mut(5) {
            *b ^= 0xff; // header CRC を壊す
        }
        let e = recv_frame(&mut chunky(bytes, 64, 0), LONG).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::DataLoss);
    }

    #[test]
    fn task116_2_plug1_recv_truncated_frame_is_unavailable() {
        let mut bytes = req(1, &["op"]).encode();
        bytes.truncate(bytes.len() - 2);
        let e = recv_frame(&mut chunky(bytes, 64, 0), LONG).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        let e = recv_frame(&mut chunky(vec![1, 2, 3], 64, 0), LONG).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
    }

    #[test]
    fn task116_2_plug1_recv_checksum_mismatch_is_data_loss() {
        let mut bytes = req(1, &["op"]).encode();
        if let Some(b) = bytes.last_mut() {
            *b ^= 0x01;
        }
        let e = recv_frame(&mut chunky(bytes, 64, 0), LONG).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::DataLoss);
    }

    #[test]
    fn task116_2_plug1_recv_deadline_after_first_byte_is_timeout() {
        let mut r = chunky(vec![1, 2, 3, 4], 1, 0);
        r.stall = true;
        let e = recv_frame(&mut r, Duration::from_millis(30)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
    }

    /// 3 回目の read でフラグを立てる読み手（WouldBlock を返し続ける）。
    struct Flagger<'a> {
        stop: &'a AtomicBool,
        reads: usize,
        flag_at: usize,
    }

    impl Read for Flagger<'_> {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            if self.reads >= self.flag_at {
                self.stop.store(true, Ordering::SeqCst);
            }
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    #[test]
    fn task116_5_win1_idle_stop_flag_returns_shutdown() {
        let stop = AtomicBool::new(false);
        let mut r = Flagger {
            stop: &stop,
            reads: 0,
            flag_at: 3,
        };
        assert!(matches!(
            recv_frame_until(&mut r, LONG, &stop).expect("recv"),
            Recv::Shutdown
        ));
        assert_eq!(r.reads, 3);
    }

    #[test]
    fn task116_5_win1_fallback_timeout_is_short() {
        assert_eq!(
            fallback_timeout().expect("timeout").as_duration(),
            IDLE_POLL
        );
    }

    #[test]
    fn task116_5_win1_fallback_timeout_with_stop_is_shutdown() {
        let timeout = || Err(PluginError::new(PluginErrorCode::Timeout, "t"));
        let stop = AtomicBool::new(true);
        assert!(matches!(
            fallback_outcome(timeout(), &stop).expect("outcome"),
            Fallback::Exit(LoopExit::ShutdownRequested)
        ));
        let idle = AtomicBool::new(false);
        let e = fallback_outcome(timeout(), &idle).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        let closed = Err(PluginError::new(PluginErrorCode::Unavailable, "c"));
        assert!(matches!(
            fallback_outcome(closed, &idle).expect("outcome"),
            Fallback::Exit(LoopExit::PeerClosed)
        ));
        assert!(matches!(
            fallback_outcome(Ok(req(1, &["op"])), &idle).expect("outcome"),
            Fallback::Frame(_)
        ));
    }

    #[test]
    fn task116_5_win1_flag_set_before_receive_reads_nothing() {
        let stop = AtomicBool::new(true);
        let mut r = chunky(req(1, &["op"]).encode(), 64, 0);
        assert!(matches!(
            recv_frame_until(&mut r, LONG, &stop).expect("recv"),
            Recv::Shutdown
        ));
        assert_eq!(r.pos, 0);
    }

    /// 1 回目の read の後に停止フラグを立てる読み手（受信途中に SIGTERM が届く状況の模擬）。
    struct SetAfterFirst<'a> {
        inner: Chunky,
        stop: &'a AtomicBool,
    }

    impl Read for SetAfterFirst<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.stop.store(true, Ordering::SeqCst);
            Ok(n)
        }
    }

    #[test]
    fn task116_5_win1_flag_set_mid_frame_still_completes_frame() {
        let stop = AtomicBool::new(false);
        let f = req(1, &["op"]);
        // 1 バイトずつ届く最中にフラグが立っても、フレームは受け切る（境界ずれ防止）。
        let mut r = SetAfterFirst {
            inner: chunky(f.encode(), 1, 0),
            stop: &stop,
        };
        match recv_frame_until(&mut r, LONG, &stop).expect("recv") {
            Recv::Frame(got) => assert_eq!(got.payload(), f.payload()),
            other => panic!("unexpected {other:?}"),
        }
        assert!(stop.load(Ordering::SeqCst));
    }
}
