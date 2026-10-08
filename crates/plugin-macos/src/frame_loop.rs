//! UDS 上の長さ接頭辞フレームの送受信ループ（TASK-115.2・#386。PLUG-1・MAC-1・REPAIR-5）。
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
//! [`UnimplementedHandler`] は未結線時・テスト用の全操作 `UNIMPLEMENTED` ハンドラで、実運用の要求は
//! `adapter::MacosRuntimeAdapter`（#387）が処理する。
//!
//! # シャットダウン（TASK-115.5・#389）
//! [`serve_until`] は停止フラグ（SIGTERM で立つ。`crate::sys`）を、フレーム受信の先頭（1 バイトも受けていない間）
//! で確認し、立っていれば [`LoopExit::ShutdownRequested`] で抜ける。受信途中のフレームは打ち切らず
//! [`FRAME_DEADLINE`] 内で受け切って応答する（境界ずれを作らない）。検知の遅れは最大 [`IDLE_POLL`]。
//! 要求処理中に届いた場合は、その応答後の次の受信で検知する。
//!
//! 対応 ID: TASK-115・PLUG-1・PLUG-2・PLUG-5・MAC-1・REPAIR-2・REPAIR-3・REPAIR-5・REPAIR-12。

use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use fandhe_container_plugin::{
    ControlMessage, FRAME_HEADER_LEN, Frame, FrameHeader, MessageId, PluginError, PluginErrorCode,
    RpcTimeout, UDS_RPC_TIMEOUT_DEFAULT, UdsStream, decode_message, encode_message,
};

/// アイドル待ちの read ポーリング周期。停止フラグ確認の周期でもある（最大検知遅れ。TASK-115.5）。
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
/// 実運用では `adapter::MacosRuntimeAdapter`（#387・TASK-115.3）が差し替える。
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

/// ループの正常終了要因。要因の追加に備えて `non_exhaustive`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoopExit {
    /// 相手（core）が接続を閉じた。
    PeerClosed,
    /// 停止フラグ（SIGTERM）が立った（TASK-115.5・MAC-1）。
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
    /// 切断済み接続の生 I/O が拒否された（`io_timeout_unrestored`）。`read_frame` へフォールバックする。
    RawUnusable,
    /// 受信開始前に停止フラグが立っていた。
    Shutdown,
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

/// 停止フラグを持たない（決して立たない）受信。既存テスト用の薄いラッパー。
#[cfg(test)]
fn recv_frame<R: Read>(r: &mut R, deadline: Duration) -> Result<Recv, PluginError> {
    recv_frame_until(r, deadline, &AtomicBool::new(false))
}

/// フレーム 1 つを 2 段階で受信する。`r` の read 期限は呼び出し側が [`IDLE_POLL`] 程度に設定しておく。
///
/// `stop` は 1 バイトも受けていない間だけ read の前に確認する（受信途中は打ち切らない。TASK-115.5）。
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
    // 固定長の作業バッファへ読み、実際に読めたバイト数だけを body へ追記する。
    // 読むたびに body を 0 埋めで伸ばすと、1 バイトずつ送る相手に対し 1 回ごとに最大 64 KiB の
    // 初期化が走り、許容上限のフレームで処理量が増幅するため（zero-fill の繰り返しを避ける）。
    let mut chunk = vec![0u8; BODY_CHUNK];
    while body.len() < total {
        if started.elapsed() >= deadline {
            return Err(timeout_err());
        }
        let want = total.saturating_sub(body.len()).min(BODY_CHUNK);
        let Some(slot) = chunk.get_mut(..want) else {
            return Err(PluginError::new(PluginErrorCode::Internal, "body index"));
        };
        match r.read(slot) {
            Ok(0) => {
                return Err(PluginError::new(
                    PluginErrorCode::Unavailable,
                    "connection closed inside a frame body",
                ));
            }
            Ok(n) => {
                let Some(got) = chunk.get(..n.min(want)) else {
                    return Err(PluginError::new(PluginErrorCode::Internal, "body index"));
                };
                body.extend_from_slice(got);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted || is_idle(e.kind()) => {}
            Err(_) => return Err(io_err()),
        }
    }
    // 最後の read が期限後に返った場合も、フレーム全体の合計期限（REPAIR-5）を超えた成功は返さない。
    if started.elapsed() >= deadline {
        return Err(timeout_err());
    }
    let frame = Frame::decode_body(header, &body)?;
    // デコード（チェックサム検証）に時間を要して期限を超えた場合も同様にタイムアウトとする。
    if started.elapsed() >= deadline {
        return Err(timeout_err());
    }
    Ok(Recv::Frame(frame))
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

/// [`serve`] に停止フラグを加えた版（TASK-115.5）。`stop` が立つと次の受信境界で
/// `Ok(LoopExit::ShutdownRequested)` を返す。呼び出し側（`main.rs`）が `stop_all` で VM を停止する。
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
            Recv::RawUnusable => match stream.read_frame(RpcTimeout::default()) {
                Ok(f) => f,
                // 切断済みで読み切った。フレーム境界の切断として扱う。
                Err(e) if e.code() == PluginErrorCode::Unavailable => {
                    return Ok(LoopExit::PeerClosed);
                }
                Err(e) => return Err(e),
            },
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
    fn task115_2_plug1_request_gets_response_with_same_id() {
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
    fn task115_2_plug1_handler_error_becomes_error_reply() {
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
    fn task115_2_plug1_empty_or_oversized_body_is_invalid_argument() {
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
    fn task115_2_plug1_malformed_or_wrong_kind_disconnects() {
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
    fn task115_2_plug1_oversized_reply_becomes_internal_error() {
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
    fn task115_2_plug1_unimplemented_handler() {
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

    /// TASK-115.5・MAC-1: アイドル中（WouldBlock 連続）に停止フラグが立てば Shutdown。
    #[test]
    fn task115_5_mac1_recv_idle_then_flag_is_shutdown() {
        struct FlagOnIdle<'a> {
            stop: &'a AtomicBool,
            reads: usize,
        }
        impl Read for FlagOnIdle<'_> {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                self.reads += 1;
                if self.reads == 3 {
                    self.stop.store(true, Ordering::SeqCst);
                }
                Err(io::ErrorKind::WouldBlock.into())
            }
        }
        let stop = AtomicBool::new(false);
        let mut r = FlagOnIdle {
            stop: &stop,
            reads: 0,
        };
        assert!(matches!(
            recv_frame_until(&mut r, LONG, &stop).expect("recv"),
            Recv::Shutdown
        ));
        assert_eq!(r.reads, 3);
    }

    /// TASK-115.5・MAC-1: 受信前からフラグが立っていれば、データが届いていても読まない。
    #[test]
    fn task115_5_mac1_recv_flag_set_before_read_does_not_read() {
        let mut r = chunky(req(1, &["op"]).encode(), 1024, 0);
        let stop = AtomicBool::new(true);
        assert!(matches!(
            recv_frame_until(&mut r, LONG, &stop).expect("recv"),
            Recv::Shutdown
        ));
        assert_eq!(r.pos, 0);
    }

    /// TASK-115.5・MAC-1: 受信途中（1 バイト以上）にフラグが立ってもフレームは完成する。
    #[test]
    fn task115_5_mac1_recv_flag_mid_frame_completes_frame() {
        struct FlagAfterFirst<'a> {
            inner: Chunky,
            stop: &'a AtomicBool,
        }
        impl Read for FlagAfterFirst<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let n = self.inner.read(buf)?;
                self.stop.store(true, Ordering::SeqCst);
                Ok(n)
            }
        }
        let f = req(1, &["op"]);
        let stop = AtomicBool::new(false);
        let mut r = FlagAfterFirst {
            inner: chunky(f.encode(), 3, 0),
            stop: &stop,
        };
        match recv_frame_until(&mut r, LONG, &stop).expect("recv") {
            Recv::Frame(got) => assert_eq!(got.payload(), f.payload()),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn task115_2_plug1_recv_reassembles_split_frame_after_idle() {
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
    fn task115_2_plug1_recv_rejects_bad_header() {
        let mut bytes = req(1, &["op"]).encode();
        if let Some(b) = bytes.get_mut(5) {
            *b ^= 0xff; // header CRC を壊す
        }
        let e = recv_frame(&mut chunky(bytes, 64, 0), LONG).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::DataLoss);
    }

    #[test]
    fn task115_2_plug1_recv_truncated_frame_is_unavailable() {
        let mut bytes = req(1, &["op"]).encode();
        bytes.truncate(bytes.len() - 2);
        let e = recv_frame(&mut chunky(bytes, 64, 0), LONG).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        let e = recv_frame(&mut chunky(vec![1, 2, 3], 64, 0), LONG).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
    }

    #[test]
    fn task115_2_plug1_recv_checksum_mismatch_is_data_loss() {
        let mut bytes = req(1, &["op"]).encode();
        if let Some(b) = bytes.last_mut() {
            *b ^= 0x01;
        }
        let e = recv_frame(&mut chunky(bytes, 64, 0), LONG).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::DataLoss);
    }

    /// 最後の read が期限を跨いで成功しても、フレーム全体の期限超過はタイムアウトにする（REPAIR-5）。
    struct SlowLast {
        data: Vec<u8>,
        pos: usize,
        delay: Duration,
    }

    impl Read for SlowLast {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let rest = self.data.get(self.pos..).unwrap_or(&[]);
            // 末尾まで読み切る read だけ遅延させる。
            if rest.len() <= buf.len() && self.pos > 0 {
                std::thread::sleep(self.delay);
            }
            let n = rest.len().min(buf.len());
            if let (Some(dst), Some(src)) = (buf.get_mut(..n), rest.get(..n)) {
                dst.copy_from_slice(src);
            }
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn task115_2_plug1_recv_deadline_exceeded_by_last_read_is_timeout() {
        let bytes = req(1, &["op"]).encode();
        let mut r = SlowLast {
            data: bytes,
            pos: 0,
            delay: Duration::from_millis(80),
        };
        // ヘッダは 1 回で読み、本体の最終 read が期限（30ms）を超える。
        let e = recv_frame(&mut r, Duration::from_millis(30)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
    }

    #[test]
    fn task115_2_plug1_recv_deadline_after_first_byte_is_timeout() {
        let mut r = chunky(vec![1, 2, 3, 4], 1, 0);
        r.stall = true;
        let e = recv_frame(&mut r, Duration::from_millis(30)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
    }
}
