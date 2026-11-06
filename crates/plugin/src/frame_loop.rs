//! UDS 上の長さ接頭辞フレームの送受信ループ（plugin 側の共通実装。#3774。PLUG-1・PLUG-12・REPAIR-1・REPAIR-5）。
//!
//! plugin-macos（TASK-115.2・#386・TASK-115.5・#389）と plugin-microvm（TASK-117.1・#710・#3747）で重複
//! していた受信ループを、#3773 のオーナー判断（案 a: 既存の本 crate へ置く。
//! <https://github.com/Fandhe-AI/fandhe-container/issues/3773#issuecomment-6595749900>）に従って移した。
//! 切り替え済みは plugin-microvm と plugin-windows（#3776）。plugin-macos は #3775 で扱う。
//! Windows 版だけが持っていた `handle_with_stop`・受信途中の停止・停止フラグで中断できる送信・
//! 代替受信の短い期限は、既定を従来の挙動にした拡張として本モジュールへ取り込んだ
//! （[`RequestHandler::handle_with_stop`] の既定実装と [`ShutdownPolicy`]。非破壊）。
//!
//! 各 plugin の `main.rs` が `UdsStream::connect` で core の listener へ接続した後、[`serve_until`]
//! （停止の粒度を選ぶときは [`serve_until_with`]）を呼ぶ。
//! core は `UdsListener::bind` する側で本モジュールを使わず、plugin 側に bind / listen は持たない（PLUG-12）。
//! 1 本の接続で要求を順次往復させる。
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
//! 本体型 `Vec<String>`（先頭要素が操作名）は spec 未規定の暫定契約で、型つき本体への置換は #1869 の設計（承認と実装 issue の起票は #2232）で確定する。
//! [`UnimplementedHandler`] は未結線時・テスト用の全操作 `UNIMPLEMENTED` ハンドラで、実運用の要求は
//! 各 plugin の adapter が処理する。
//!
//! # シャットダウン（#3747。PLUG-1・REPAIR-5）
//! 停止の粒度は [`ShutdownPolicy`] で選ぶ。検知の遅れは最大 [`IDLE_POLL`]。本モジュールは OS に依存せず
//! cfg を持たない（SIGTERM を登録しない OS ではフラグが立たず、[`serve`] と同じく切断でだけ終わる）。
//!
//! - [`ShutdownPolicy::CompleteFrame`]（[`serve_until`] の既定。#3747）: 停止フラグはフレーム受信の先頭
//!   （1 バイトも受けていない間）だけで確認し、立っていれば [`LoopExit::ShutdownRequested`] で抜ける。
//!   受信途中のフレームは打ち切らず [`FRAME_DEADLINE`] 内で受け切って応答する（境界ずれを作らない）。
//!   要求の処理中に届いたシグナルは、その応答の後の次の受信で検知する。
//!   残余: フラグを見た後に届いた要求は read しないが、フラグが立つ直前の 1 回の read（最大 [`IDLE_POLL`]）の
//!   間に届いたバイトは、そのフレームとして処理されうる。
//! - [`ShutdownPolicy::DiscardInProgress`]（plugin-windows。TASK-116.5・#396・WIN-2）: 受信中（ヘッダ・本体の
//!   途中を含む）も毎回の read の前に確認し、立っていれば受信途中のフレームを応答せず破棄して抜ける
//!   （途中で止まった相手に [`FRAME_DEADLINE`] まで待たされ、終了時の後始末が猶予を超えるのを防ぐ）。
//!   要求処理中に立った場合は [`RequestHandler::handle_with_stop`] でハンドラへ伝える。応答送信も
//!   [`IDLE_POLL`] ごとに確認し、相手が読まず詰まっていても未送信分を破棄して抜ける。
//!   破棄したら必ず [`LoopExit::ShutdownRequested`] で抜け、同じ接続で受信を続けない（境界ずれを作らない）。
//!
//! # PLUG-4 との関係
//! core は既定 feature `plugin` で本 crate に依存するため、core の rlib は本変更で main と変わる。
//! これは共有 crate の変更であり plugin の追加ではない（`make plug4-core-invariance` は plugin crate の
//! 新規追加を判定対象とするため、本変更は対象外）。
//!
//! 対応 ID: PLUG-1・PLUG-4・PLUG-12・REPAIR-1・REPAIR-2・REPAIR-3・REPAIR-5・REPAIR-12。
//! 単体試験の名前の元は plugin-microvm の `task117_1_*`（TASK-117.1・#710・#3747）。

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::{
    ControlMessage, FRAME_HEADER_LEN, Frame, FrameHeader, MessageId, PluginError, PluginErrorCode,
    RpcTimeout, UDS_RPC_TIMEOUT_DEFAULT, UdsStream, decode_message, encode_message,
};

/// アイドル待ちの read ポーリング周期。相手の切断を検知する周期。
pub const IDLE_POLL: Duration = Duration::from_secs(1);

/// 最初の 1 バイトを受けてからフレーム全体を受け切るまでの合計期限（REPAIR-5）。
pub const FRAME_DEADLINE: Duration = UDS_RPC_TIMEOUT_DEFAULT;

/// 要求本体（文字列配列）の要素数上限。外部入力の検証用。
pub const REQUEST_BODY_MAX_ITEMS: usize = 64;

/// 本体を読む際の 1 回あたりの確保単位（ヘッダ検証後も確保を段階的にする）。
const BODY_CHUNK: usize = 64 * 1024;

/// 応答の符号化失敗時に返す固定文言（入力断片を載せない）。
const MSG_ENCODE_FAILED: &str = "failed to encode response";

/// 要求ハンドラの境界。`body` は先頭要素が操作名・以降が引数の暫定契約（#1869 の設計で型つき本体へ置換）。
///
/// `Err` は同じ `MessageId` の `Error` 応答になる。メッセージに入力値を含めないこと（外部入力の反射防止）。
pub trait RequestHandler {
    /// 1 要求を処理して応答本体を返す。
    fn handle(&mut self, body: &[String]) -> Result<Vec<String>, PluginError>;

    /// 停止フラグ付きで 1 要求を処理する（TASK-116.5・#396・#3776）。既定は [`Self::handle`] へ委譲する。
    /// 実装は処理中に `stop` を確認して早期に打ち切り、終了時の後始末へ時間を残せる（WIN-2・REPAIR-5）。
    fn handle_with_stop(
        &mut self,
        body: &[String],
        _stop: &AtomicBool,
    ) -> Result<Vec<String>, PluginError> {
        self.handle(body)
    }
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
/// 実運用では各 plugin の adapter が差し替える。
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
    /// 呼び出し側の停止フラグ（SIGTERM 等）が立った。新しい要求は受けない（#3747）。
    ShutdownRequested,
}

/// 停止フラグを受信・送信のどの粒度で見るか（#3776。WIN-2・REPAIR-5）。将来の追加に備え `non_exhaustive`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ShutdownPolicy {
    /// フレームの先頭（1 バイトも受けていない間）だけで確認し、受信を始めたフレームは受け切って応答する。
    #[default]
    CompleteFrame,
    /// 受信・送信の途中でも毎回確認し、未完了のフレームは破棄して [`LoopExit::ShutdownRequested`] にする。
    DiscardInProgress,
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
    handle_frame_with(frame, handler, None)
}

/// [`handle_frame`] に停止フラグを渡せる版。`stop` があればハンドラの `handle_with_stop` へ伝える。
fn handle_frame_with<H: RequestHandler>(
    frame: &Frame,
    handler: &mut H,
    stop: Option<&AtomicBool>,
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
        // 同一 crate 内では `ControlMessage` の `non_exhaustive` が効かず到達不能になるが、将来の種別追加で
        // 未知の種別を成功扱いしない fail-closed を保つため残す（移植前は別 crate から見て必須だった腕）。
        #[allow(unreachable_patterns)]
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
    } else if let Some(stop) = stop {
        handler.handle_with_stop(&body, stop)
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

/// [`recv_frame_until`] の結果。
#[derive(Debug)]
enum Recv {
    Frame(Frame),
    /// 停止フラグが立っていた（方針により、受信を始める前、または受信途中のフレームを破棄済み）。
    Shutdown,
    /// フレーム境界での正常な EOF。
    Closed,
    /// 切断済み接続の生 I/O が拒否された（`io_timeout_unrestored`、または既定期限を掛けられなかった接続。#3981）。`read_frame` へフォールバックする。
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

/// 停止フラグを見ない [`recv_frame_until`] の薄い包み（単体試験用）。
#[cfg(test)]
fn recv_frame<R: Read>(r: &mut R, deadline: Duration) -> Result<Recv, PluginError> {
    recv_frame_until(
        r,
        deadline,
        &AtomicBool::new(false),
        ShutdownPolicy::CompleteFrame,
    )
}

/// フレーム 1 つを 2 段階で受信する。`r` の read 期限は呼び出し側が [`IDLE_POLL`] 程度に設定しておく。
///
/// `stop` は `policy` に従って確認する。`CompleteFrame` は 1 バイトも受けていない間だけ（受信途中の
/// フレームは打ち切らない）、`DiscardInProgress` はヘッダ・本体の途中も含めて確認し未完了フレームを破棄する。
fn recv_frame_until<R: Read>(
    r: &mut R,
    deadline: Duration,
    stop: &AtomicBool,
    policy: ShutdownPolicy,
) -> Result<Recv, PluginError> {
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    let mut got = 0usize;
    let mut started: Option<Instant> = None;
    while got < FRAME_HEADER_LEN {
        if started.is_some_and(|t| t.elapsed() >= deadline) {
            return Err(timeout_err());
        }
        if (got == 0 || policy == ShutdownPolicy::DiscardInProgress) && stop.load(Ordering::SeqCst)
        {
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
        if policy == ShutdownPolicy::DiscardInProgress && stop.load(Ordering::SeqCst) {
            return Ok(Recv::Shutdown);
        }
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

/// 応答送信の結果。
#[derive(Debug, PartialEq, Eq)]
enum Send {
    /// 全量を送り終えた。
    Done,
    /// 送信途中に停止フラグが立った（未送信分は破棄。接続は呼び出し側が閉じる）。
    Shutdown,
}

/// 応答フレームを [`IDLE_POLL`] 周期で停止フラグを確認しながら送る（`DiscardInProgress` 用。WIN-2・REPAIR-5・#396）。
///
/// 相手が読まず送信が詰まっても、停止フラグが立てば最大 [`IDLE_POLL`] で `Send::Shutdown` を返し、
/// 5 秒の終了猶予内に後始末へ進めるようにする。合計期限 `deadline` 超過は `Timeout`。
/// `w` の write 期限は呼び出し側が [`IDLE_POLL`] 程度に設定しておく（`serve_until_with` が設定済み）。
fn send_frame_until<W: Write>(
    w: &mut W,
    frame: &Frame,
    deadline: Duration,
    stop: &AtomicBool,
) -> Result<Send, PluginError> {
    let encoded = frame.encode();
    let started = Instant::now();
    let mut sent = 0usize;
    while sent < encoded.len() {
        if stop.load(Ordering::SeqCst) {
            return Ok(Send::Shutdown);
        }
        if started.elapsed() >= deadline {
            return Err(PluginError::new(
                PluginErrorCode::Timeout,
                "frame send deadline exceeded",
            ));
        }
        let Some(rest) = encoded.get(sent..) else {
            return Err(PluginError::new(PluginErrorCode::Internal, "send index"));
        };
        match w.write(rest) {
            Ok(0) => {
                return Err(PluginError::new(
                    PluginErrorCode::Unavailable,
                    "connection closed while sending a frame",
                ));
            }
            Ok(n) => sent = sent.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted || is_idle(e.kind()) => {}
            Err(_) => {
                return Err(PluginError::new(
                    PluginErrorCode::Unavailable,
                    "frame write failed",
                ));
            }
        }
    }
    Ok(Send::Done)
}

/// [`Recv::RawUnusable`] 後の代替受信（`read_frame`）の結果（`DiscardInProgress` 用）。
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

/// [`serve`] に停止フラグを足したもの（#3747。PLUG-1・REPAIR-5）。[`ShutdownPolicy::CompleteFrame`] 固定。
///
/// 呼び出し側（各 plugin の `main.rs`）が SIGTERM 等で立つ停止フラグを渡す。フラグが立つと次の受信境界で
/// `Ok(LoopExit::ShutdownRequested)` を返し、新しい要求は read しない。呼び出し側が `stop_all` で VM を止める。
pub fn serve_until<H: RequestHandler>(
    stream: &mut UdsStream,
    handler: &mut H,
    stop: &AtomicBool,
) -> Result<LoopExit, PluginError> {
    serve_until_with(stream, handler, stop, ShutdownPolicy::CompleteFrame)
}

/// [`serve_until`] の停止の粒度を `policy` で選べる版（#3776。WIN-2・REPAIR-5）。
///
/// `DiscardInProgress` では受信途中の破棄・`handle_with_stop` による処理中の打ち切り・停止フラグで中断できる
/// 応答送信・短い期限（[`IDLE_POLL`]）の代替受信を使う。
pub fn serve_until_with<H: RequestHandler>(
    stream: &mut UdsStream,
    handler: &mut H,
    stop: &AtomicBool,
    policy: ShutdownPolicy,
) -> Result<LoopExit, PluginError> {
    stream.set_io_timeout(IDLE_POLL)?;
    let discard = policy == ShutdownPolicy::DiscardInProgress;
    loop {
        let frame = match recv_frame_until(stream, FRAME_DEADLINE, stop, policy)? {
            Recv::Frame(f) => f,
            Recv::Shutdown => return Ok(LoopExit::ShutdownRequested),
            Recv::Closed => return Ok(LoopExit::PeerClosed),
            Recv::RawUnusable if discard => {
                // 代替経路でも受信前に停止フラグを確認し、受信期限は IDLE_POLL に絞る（WIN-1・REPAIR-5）。
                if stop.load(Ordering::SeqCst) {
                    return Ok(LoopExit::ShutdownRequested);
                }
                match fallback_outcome(stream.read_frame(fallback_timeout()?), stop)? {
                    Fallback::Frame(f) => f,
                    Fallback::Exit(exit) => return Ok(exit),
                }
            }
            Recv::RawUnusable => match stream.read_frame(RpcTimeout::default()) {
                Ok(f) => f,
                // 切断済みで読み切った。フレーム境界の切断として扱う。
                Err(e) if e.code() == PluginErrorCode::Unavailable => {
                    return Ok(LoopExit::PeerClosed);
                }
                Err(e) => return Err(e),
            },
        };
        let reply = handle_frame_with(&frame, handler, Some(stop))?;
        if discard {
            if let Send::Shutdown = send_frame_until(stream, &reply, FRAME_DEADLINE, stop)? {
                return Ok(LoopExit::ShutdownRequested);
            }
        } else {
            stream.write_frame(&reply, RpcTimeout::default())?;
        }
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
    fn plug1_frame_loop_request_gets_response_with_same_id() {
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
    fn plug1_frame_loop_handler_error_becomes_error_reply() {
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
    fn plug1_frame_loop_empty_or_oversized_body_is_invalid_argument() {
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
    fn plug1_frame_loop_malformed_or_wrong_kind_disconnects() {
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
    fn plug1_frame_loop_oversized_reply_becomes_internal_error() {
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
    fn plug1_frame_loop_unimplemented_handler() {
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

    /// PLUG-1・REPAIR-5: アイドル中（WouldBlock 連続）に停止フラグが立てば Shutdown。
    #[test]
    fn task117_plug1_repair5_recv_idle_then_flag_is_shutdown() {
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
            recv_frame_until(&mut r, LONG, &stop, ShutdownPolicy::CompleteFrame).expect("recv"),
            Recv::Shutdown
        ));
        assert_eq!(r.reads, 3);
    }

    /// PLUG-1・REPAIR-5: 受信前からフラグが立っていれば、データが届いていても読まない。
    #[test]
    fn task117_plug1_repair5_recv_flag_set_before_read_does_not_read() {
        let mut r = chunky(req(1, &["op"]).encode(), 1024, 0);
        let stop = AtomicBool::new(true);
        assert!(matches!(
            recv_frame_until(&mut r, LONG, &stop, ShutdownPolicy::CompleteFrame).expect("recv"),
            Recv::Shutdown
        ));
        assert_eq!(r.pos, 0);
    }

    /// PLUG-1・REPAIR-5: 受信途中（1 バイト以上）にフラグが立ってもフレームは完成する。
    #[test]
    fn task117_plug1_repair5_recv_flag_mid_frame_completes_frame() {
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
        match recv_frame_until(&mut r, LONG, &stop, ShutdownPolicy::CompleteFrame).expect("recv") {
            Recv::Frame(got) => assert_eq!(got.payload(), f.payload()),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn plug1_frame_loop_recv_reassembles_split_frame_after_idle() {
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
    fn plug1_frame_loop_recv_rejects_bad_header() {
        let mut bytes = req(1, &["op"]).encode();
        if let Some(b) = bytes.get_mut(5) {
            *b ^= 0xff; // header CRC を壊す
        }
        let e = recv_frame(&mut chunky(bytes, 64, 0), LONG).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::DataLoss);
    }

    #[test]
    fn plug1_frame_loop_recv_truncated_frame_is_unavailable() {
        let mut bytes = req(1, &["op"]).encode();
        bytes.truncate(bytes.len() - 2);
        let e = recv_frame(&mut chunky(bytes, 64, 0), LONG).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        let e = recv_frame(&mut chunky(vec![1, 2, 3], 64, 0), LONG).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
    }

    #[test]
    fn plug1_frame_loop_recv_checksum_mismatch_is_data_loss() {
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
    fn plug1_frame_loop_recv_deadline_exceeded_by_last_read_is_timeout() {
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
    fn plug1_frame_loop_recv_deadline_after_first_byte_is_timeout() {
        let mut r = chunky(vec![1, 2, 3, 4], 1, 0);
        r.stall = true;
        let e = recv_frame(&mut r, Duration::from_millis(30)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
    }

    // ---- ShutdownPolicy::DiscardInProgress（plugin-windows から移した試験。TASK-116.5・#396・#3776）----

    const DISCARD: ShutdownPolicy = ShutdownPolicy::DiscardInProgress;

    /// `flag_at` 回目の read でフラグを立てる読み手（WouldBlock を返し続ける）。
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
    fn task116_5_win1_idle_stop_flag_returns_shutdown() {
        let stop = AtomicBool::new(false);
        let mut r = Flagger {
            stop: &stop,
            reads: 0,
            flag_at: 3,
        };
        assert!(matches!(
            recv_frame_until(&mut r, LONG, &stop, DISCARD).expect("recv"),
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
            recv_frame_until(&mut r, LONG, &stop, DISCARD).expect("recv"),
            Recv::Shutdown
        ));
        assert_eq!(r.pos, 0);
    }

    #[test]
    fn task116_5_win1_flag_set_mid_frame_discards_and_shuts_down() {
        let stop = AtomicBool::new(false);
        let f = req(1, &["op"]);
        // 1 バイトずつ届く最中にフラグが立ったら、未完了フレームは破棄して Shutdown（#396）。
        let mut r = SetAfterFirst {
            inner: chunky(f.encode(), 1, 0),
            stop: &stop,
        };
        assert!(matches!(
            recv_frame_until(&mut r, LONG, &stop, DISCARD).expect("recv"),
            Recv::Shutdown
        ));
        assert!(r.inner.pos < f.encode().len());
    }

    /// 停止フラグが立った時点で本体の途中なら、期限（FRAME_DEADLINE 相当）を待たず Shutdown になる。
    #[test]
    fn task116_5_win1_stalled_partial_body_with_stop_shuts_down_quickly() {
        let stop = AtomicBool::new(false);
        let f = req(1, &["op"]);
        let bytes = f.encode();
        let hdr_len = FRAME_HEADER_LEN;
        // ヘッダ + 本体の一部だけ届いて以降は停止する相手。
        let mut r = SetAfterFirst {
            inner: Chunky {
                data: bytes.get(..hdr_len + 1).unwrap_or(&[]).to_vec(),
                pos: 0,
                step: hdr_len + 1,
                idle: 0,
                stall: true,
            },
            stop: &stop,
        };
        let started = Instant::now();
        assert!(matches!(
            recv_frame_until(&mut r, Duration::from_secs(30), &stop, DISCARD).expect("recv"),
            Recv::Shutdown
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// ヘッダの途中で止まった相手でも、停止フラグが立てば期限を待たず Shutdown になる。
    #[test]
    fn task116_5_win1_stalled_partial_header_with_stop_shuts_down_quickly() {
        let stop = AtomicBool::new(false);
        let mut r = SetAfterFirst {
            inner: Chunky {
                data: vec![1, 2, 3],
                pos: 0,
                step: 3,
                idle: 0,
                stall: true,
            },
            stop: &stop,
        };
        let started = Instant::now();
        assert!(matches!(
            recv_frame_until(&mut r, Duration::from_secs(30), &stop, DISCARD).expect("recv"),
            Recv::Shutdown
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// 常に WouldBlock を返す（相手が読まず送信が詰まった状態）。`stop` があれば初回 write で立てる。
    struct Stalled<'a> {
        stop: Option<&'a AtomicBool>,
    }

    impl Write for Stalled<'_> {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            if let Some(s) = self.stop {
                s.store(true, Ordering::SeqCst);
            }
            Err(io::ErrorKind::WouldBlock.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn reply() -> Frame {
        error_frame(
            MessageId::new(1),
            PluginError::new(PluginErrorCode::Internal, "x"),
        )
        .expect("encode")
    }

    #[test]
    fn task116_5_win2_stalled_send_with_stop_shuts_down() {
        let stop = AtomicBool::new(false);
        let mut w = Stalled { stop: Some(&stop) };
        let out = send_frame_until(&mut w, &reply(), Duration::from_secs(30), &stop).expect("send");
        assert_eq!(out, Send::Shutdown);
    }

    #[test]
    fn task116_5_win2_flag_set_before_send_writes_nothing() {
        let stop = AtomicBool::new(true);
        let mut buf: Vec<u8> = Vec::new();
        let out =
            send_frame_until(&mut buf, &reply(), Duration::from_secs(30), &stop).expect("send");
        assert_eq!(out, Send::Shutdown);
        assert!(buf.is_empty());
    }

    #[test]
    fn task116_5_win2_send_writes_full_frame() {
        let stop = AtomicBool::new(false);
        let f = reply();
        let mut buf: Vec<u8> = Vec::new();
        let out = send_frame_until(&mut buf, &f, Duration::from_secs(30), &stop).expect("send");
        assert_eq!(out, Send::Done);
        assert_eq!(buf, f.encode());
    }

    #[test]
    fn task116_5_win2_stalled_send_without_stop_times_out() {
        let stop = AtomicBool::new(false);
        let mut w = Stalled { stop: None };
        let err = send_frame_until(&mut w, &reply(), Duration::from_millis(20), &stop)
            .expect_err("timeout");
        assert_eq!(err.code(), PluginErrorCode::Timeout);
    }

    // ---- 方針の対比と新設の確認（#3776。REPAIR-5）----

    /// 受信途中にフラグが立っても、`CompleteFrame` はフレームを完成させ、`DiscardInProgress` は破棄する。
    #[test]
    fn task3776_policy_contrast_flag_mid_frame() {
        let f = req(1, &["op"]);
        for (policy, expect_frame) in [(ShutdownPolicy::CompleteFrame, true), (DISCARD, false)] {
            let stop = AtomicBool::new(false);
            let mut r = SetAfterFirst {
                inner: chunky(f.encode(), 3, 0),
                stop: &stop,
            };
            match recv_frame_until(&mut r, LONG, &stop, policy).expect("recv") {
                Recv::Frame(got) => {
                    assert!(expect_frame, "{policy:?}");
                    assert_eq!(got.payload(), f.payload());
                }
                Recv::Shutdown => assert!(!expect_frame, "{policy:?}"),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    /// 最後の read が期限を跨いだ場合の期限再確認は、`DiscardInProgress` でも有効（windows に新しく入る堅牢化）。
    #[test]
    fn task116_5_repair5_discard_policy_deadline_exceeded_by_last_read_is_timeout() {
        let mut r = SlowLast {
            data: req(1, &["op"]).encode(),
            pos: 0,
            delay: Duration::from_millis(80),
        };
        let stop = AtomicBool::new(false);
        let e = recv_frame_until(&mut r, Duration::from_millis(30), &stop, DISCARD).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
    }

    /// `handle_with_stop` の既定実装は `handle` へ委譲し、`handle_frame_with` は stop を伝える。
    #[test]
    fn task3776_handle_with_stop_default_delegates_and_stop_is_passed() {
        struct Plain {
            via_handle: usize,
        }
        impl RequestHandler for Plain {
            fn handle(&mut self, b: &[String]) -> Result<Vec<String>, PluginError> {
                self.via_handle += 1;
                Ok(b.to_vec())
            }
        }
        struct Override(Option<bool>);
        impl RequestHandler for Override {
            fn handle(&mut self, _b: &[String]) -> Result<Vec<String>, PluginError> {
                Err(PluginError::new(
                    PluginErrorCode::Internal,
                    "must not be used",
                ))
            }
            fn handle_with_stop(
                &mut self,
                b: &[String],
                stop: &AtomicBool,
            ) -> Result<Vec<String>, PluginError> {
                self.0 = Some(stop.load(Ordering::SeqCst));
                Ok(b.to_vec())
            }
        }
        let stop = AtomicBool::new(true);
        let mut d = Plain { via_handle: 0 };
        handle_frame_with(&req(1, &["op"]), &mut d, Some(&stop)).expect("reply");
        assert_eq!(d.via_handle, 1);
        let mut o = Override(None);
        let reply = handle_frame_with(&req(2, &["op"]), &mut o, Some(&stop)).expect("reply");
        assert_eq!(o.0, Some(true));
        assert!(matches!(decoded(&reply), ControlMessage::Response { .. }));
    }
}
