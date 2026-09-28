//! [`crate::protocol::Frame`] のペイロード内部レイアウト（request id・ACK の対応付け）
//! を定める（TASK-12.2・IO-1・#74）。
//!
//! [`crate::protocol`] はペイロードを不透明なバイト列として扱い、request id の
//! ワイヤー表現・種別ごとのペイロード長制約は TASK-12・TASK-13（またはそれらの
//! 後続 sub-issue）が定めるとしていた（[`crate::protocol`] モジュールドキュメント
//! 参照）。本モジュールがその定義を担う。
//!
//! # #74（TASK-12.2）が定めるペイロード形式
//!
//! | 種別 | ペイロード | 制約 |
//! | ---- | ---------- | ---- |
//! | [`crate::protocol::FrameKind::Write`] | `[request_id: u64 LE][body...]` | `body.len() ≤ `[`MAX_WRITE_BODY_LEN`] |
//! | [`crate::protocol::FrameKind::Flush`] | `[request_id: u64 LE]` | ちょうど [`REQUEST_ID_WIRE_LEN`]（8 バイト。body は空） |
//! | [`crate::protocol::FrameKind::Ack`] / [`crate::protocol::FrameKind::FlushAck`] | `[request_id: u64 LE]` | ちょうど [`ACK_PAYLOAD_LEN`]（8 バイト） |
//!
//! # ヘッダを変えない理由（フレームヘッダの ID フィールドとの受入基準のずれ）
//!
//! TASK-12 系の受入基準は「フレームヘッダの ID フィールドで対応付ける」という
//! 書き方をしているが、[`crate::protocol::FrameHeader`] は
//! `[version][kind][payload_len][header_crc]` の固定 10 バイトで確定済み
//! （2026-09-28 オーナー決定・#67・#115・#1108）であり、ヘッダに request id を
//! 追加するのはワイヤー互換を壊す変更（`PROTOCOL_VERSION` の繰り上げが必要）かつ
//! I/O 契約（IO-1）の設計変更にあたる。本 crate では「送信時の識別子」を
//! ペイロード先頭 8 バイトの固定オフセットに置く request id として受入基準を
//! 満たす（#74 実装計画・spec 側の記述とのずれは本リポの Issue へ報告する。
//! out-of-scope-tracking）。
//!
//! # ACK に status バイトを持たせない理由
//!
//! サーバー側の失敗は接続再利用禁止契約（P1-3。`crates/io/src/transport.rs`
//! モジュールドキュメント）により接続断で伝わるため、ACK 自体に成功/失敗を
//! 示す status バイトを持たせる必要がない。あとから status を追加するのは
//! ワイヤー形式の変更にあたり `PROTOCOL_VERSION` を上げる必要がある
//! （PoC-2 の `status(0=OK)` をあえて再現しない理由）。
//!
//! # `PROTOCOL_VERSION` を据え置く理由
//!
//! [`crate::protocol::Frame`] のペイロードはこれまで「不透明なバイト列」として
//! 未定義だった（意味づけがされていなかった）ため、本モジュールが初めてその
//! レイアウトを定める。ヘッダ・フレーム全体のバイトレイアウトは変わらないため、
//! `PROTOCOL_VERSION`（ワイヤー形式のバージョン）は `1` のまま据え置く。
//!
//! # 想定する呼び出し元
//!
//! - [`crate::client::PipelineClient::send`]（TASK-12.1・#73）が
//!   [`encode_request`] で id を埋め込んだフレームを組み立てる
//! - [`crate::client::PipelineClient::recv_ack`]（TASK-12.2・#74）が
//!   [`decode_ack`] で受信 ACK を検証する
//! - バッチ write-back サーバー本体（TASK-13.2・#77・#820）が [`decode_request`]・
//!   [`encode_ack`] で同じ形式を読み書きする想定（本モジュールはクライアント・
//!   サーバー双方から使われるため `client.rs` ではなく独立モジュールに置く）
//!
//! ワイヤーに載せるのは連番（`u64`）のみで、[`crate::client::RequestId`] が
//! 内部に持つ発行元キュー識別子（`QueueId`）はメモリ内の区別にのみ使い、
//! ワイヤー上には一切現れない（[`crate::client`] モジュールドキュメント参照）。

use crate::client::RequestId;
use crate::error::{IoError, IoErrorCode};
use crate::protocol::{Frame, FrameKind, MAX_PAYLOAD_LEN};

/// ペイロード先頭に置く request id のワイヤー上のバイト数（`u64` LE）。
pub const REQUEST_ID_WIRE_LEN: usize = 8;

/// [`FrameKind::Ack`] / [`FrameKind::FlushAck`] のペイロード長（request id のみ。
/// body を持たない）。
pub const ACK_PAYLOAD_LEN: usize = REQUEST_ID_WIRE_LEN;

/// [`FrameKind::Write`] の body に許される最大長。
///
/// ペイロード全体の上限（[`MAX_PAYLOAD_LEN`]）から request id 分
/// （[`REQUEST_ID_WIRE_LEN`]）を差し引いた値。
pub const MAX_WRITE_BODY_LEN: u32 = MAX_PAYLOAD_LEN - REQUEST_ID_WIRE_LEN as u32;

/// [`MAX_WRITE_BODY_LEN`] + request id 分がちょうど [`MAX_PAYLOAD_LEN`] に
/// 一致することをコンパイル時に保証する（定数の食い違いを防ぐ）。
const _: () = assert!(MAX_WRITE_BODY_LEN + REQUEST_ID_WIRE_LEN as u32 == MAX_PAYLOAD_LEN);

/// [`RequestId`] のワイヤー表現（連番部分のみ。`u64`）。
///
/// [`RequestId`] が内部に持つ発行元キュー識別子（`QueueId`。メモリ内の区別にのみ
/// 使う）を捨てた値で、ペイロードへ実際に載るバイト列はこの値の LE 表現
/// （[`REQUEST_ID_WIRE_LEN`] バイト）のみ。crate 外から任意の値を作れないよう、
/// 構築は [`From<RequestId>`] 経由に限る（デコード側〔[`decode_request`]・
/// [`decode_ack`]〕はワイヤー由来の `u64` から専用のコンストラクタ
/// （非公開）を使う）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WireRequestId(u64);

impl WireRequestId {
    /// 連番部分を `u64` として返す。
    pub fn get(self) -> u64 {
        self.0
    }

    /// ワイヤー由来の `u64`（untrusted）から復元する（[`decode_request`]・
    /// [`decode_ack`] のみが使う）。
    fn from_wire(value: u64) -> Self {
        Self(value)
    }
}

impl From<RequestId> for WireRequestId {
    /// [`RequestId`] の連番部分だけを取り出す（発行元キュー識別子は捨てる）。
    fn from(value: RequestId) -> Self {
        Self(value.get())
    }
}

/// `body` の長さが `kind` に許される範囲かを検証する（[`encode_request`] が使う）。
fn validate_request_body_len(kind: FrameKind, body_len: usize) -> Result<(), IoError> {
    match kind {
        FrameKind::Write => {
            if body_len as u128 > MAX_WRITE_BODY_LEN as u128 {
                return Err(IoError::new(
                    IoErrorCode::InvalidArgument,
                    format!(
                        "write body length {body_len} exceeds MAX_WRITE_BODY_LEN ({MAX_WRITE_BODY_LEN})"
                    ),
                ));
            }
            Ok(())
        }
        FrameKind::Flush => {
            if body_len != 0 {
                return Err(IoError::new(
                    IoErrorCode::InvalidArgument,
                    format!("flush frame must not carry a body, got {body_len} byte(s)"),
                ));
            }
            Ok(())
        }
        FrameKind::Ack | FrameKind::FlushAck => Err(IoError::new(
            IoErrorCode::InvalidArgument,
            "encode_request only accepts Write/Flush frame kinds; use encode_ack for Ack/FlushAck",
        )),
    }
}

/// request id を埋め込んだ [`Frame`] を組み立てる（[`crate::client::PipelineClient::send`]
/// が使う）。
///
/// `kind` は [`FrameKind::Write`] / [`FrameKind::Flush`] のみ受理する。それ以外
/// （[`FrameKind::Ack`] / [`FrameKind::FlushAck`]）や、`Write` で `body.len()` が
/// [`MAX_WRITE_BODY_LEN`] を超える場合、`Flush` で `body` が空でない場合は
/// [`IoErrorCode::InvalidArgument`] を返す。
pub fn encode_request(kind: FrameKind, id: WireRequestId, body: &[u8]) -> Result<Frame, IoError> {
    validate_request_body_len(kind, body.len())?;

    let mut payload = Vec::with_capacity(REQUEST_ID_WIRE_LEN + body.len());
    payload.extend_from_slice(&id.get().to_le_bytes());
    payload.extend_from_slice(body);
    Frame::new(kind, payload)
}

/// [`encode_request`] が組み立てたフレームを復元する（サーバー側〔TASK-13.2〕・
/// 往復テストが使う）。
///
/// `frame.kind()` が [`FrameKind::Write`] / [`FrameKind::Flush`] 以外の場合、または
/// ペイロードが [`REQUEST_ID_WIRE_LEN`] バイト未満の場合は
/// [`IoErrorCode::InvalidArgument`] を返す。`frame` は untrusted なトランスポート
/// 由来の値でありうるため、添字アクセスではなく `split_first_chunk` で読む。
pub fn decode_request(frame: &Frame) -> Result<RequestEnvelope<'_>, IoError> {
    let kind = frame.kind();
    match kind {
        FrameKind::Write | FrameKind::Flush => {}
        FrameKind::Ack | FrameKind::FlushAck => {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "decode_request only accepts Write/Flush frame kinds; use decode_ack for Ack/FlushAck",
            ));
        }
    }

    let (id_bytes, body) = frame
        .payload()
        .split_first_chunk::<REQUEST_ID_WIRE_LEN>()
        .ok_or_else(|| {
            IoError::new(
                IoErrorCode::InvalidArgument,
                format!(
                    "request payload shorter than {REQUEST_ID_WIRE_LEN} bytes: {} byte(s)",
                    frame.payload().len()
                ),
            )
        })?;

    if kind == FrameKind::Flush && !body.is_empty() {
        return Err(IoError::new(
            IoErrorCode::InvalidArgument,
            format!(
                "flush frame must not carry a body, got {} byte(s)",
                body.len()
            ),
        ));
    }

    let id = WireRequestId::from_wire(u64::from_le_bytes(*id_bytes));
    Ok(RequestEnvelope { kind, id, body })
}

/// [`decode_request`] が返す、検証済みの request（種別・request id・body への
/// 借用）。フレームより長生きしない（body はフレームのペイロードを指す借用）。
#[derive(Debug, Clone, Copy)]
pub struct RequestEnvelope<'a> {
    kind: FrameKind,
    id: WireRequestId,
    body: &'a [u8],
}

impl<'a> RequestEnvelope<'a> {
    /// このリクエストのフレーム種別（`Write` / `Flush`）を返す。
    pub fn kind(&self) -> FrameKind {
        self.kind
    }

    /// このリクエストの request id を返す。
    pub fn id(&self) -> WireRequestId {
        self.id
    }

    /// body（`Flush` の場合は常に空）への参照を返す。
    pub fn body(&self) -> &'a [u8] {
        self.body
    }
}

/// ACK フレーム（request id のみ）を組み立てる（サーバー側〔TASK-13.2〕・
/// テスト用の mock ACK 送信元が使う）。
///
/// `kind` は [`FrameKind::Ack`] / [`FrameKind::FlushAck`] のみ受理する。それ以外
/// （[`FrameKind::Write`] / [`FrameKind::Flush`]）の場合は
/// [`IoErrorCode::InvalidArgument`] を返す。
pub fn encode_ack(kind: FrameKind, id: WireRequestId) -> Result<Frame, IoError> {
    match kind {
        FrameKind::Ack | FrameKind::FlushAck => {}
        FrameKind::Write | FrameKind::Flush => {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "encode_ack only accepts Ack/FlushAck frame kinds; use encode_request for Write/Flush",
            ));
        }
    }
    Frame::new(kind, id.get().to_le_bytes().to_vec())
}

/// [`encode_ack`] が組み立てたフレームを復元する
/// （[`crate::client::PipelineClient::recv_ack`] が使う。TASK-12.2・#74）。
///
/// `frame` は untrusted なサーバー由来の入力として扱う。`frame.kind()` が
/// [`FrameKind::Ack`] / [`FrameKind::FlushAck`] 以外の場合、またはペイロード長が
/// [`ACK_PAYLOAD_LEN`]（8 バイト）とちょうど一致しない場合（短くても長くても）は
/// [`IoErrorCode::InvalidArgument`] を返す。添字アクセスではなく `<[u8; N]>::try_from`
/// で読む。
pub fn decode_ack(frame: &Frame) -> Result<AckEnvelope, IoError> {
    let kind = frame.kind();
    match kind {
        FrameKind::Ack | FrameKind::FlushAck => {}
        FrameKind::Write | FrameKind::Flush => {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "decode_ack only accepts Ack/FlushAck frame kinds; use decode_request for Write/Flush",
            ));
        }
    }

    let payload = frame.payload();
    let id_bytes = <[u8; ACK_PAYLOAD_LEN]>::try_from(payload).map_err(|_| {
        IoError::new(
            IoErrorCode::InvalidArgument,
            format!(
                "ack payload length must be exactly {ACK_PAYLOAD_LEN} bytes, got {} byte(s)",
                payload.len()
            ),
        )
    })?;

    let id = WireRequestId::from_wire(u64::from_le_bytes(id_bytes));
    Ok(AckEnvelope { kind, id })
}

/// [`decode_ack`] が返す、検証済みの ACK（種別・request id）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckEnvelope {
    kind: FrameKind,
    id: WireRequestId,
}

impl AckEnvelope {
    /// この ACK のフレーム種別（`Ack` / `FlushAck`）を返す。
    pub fn kind(&self) -> FrameKind {
        self.kind
    }

    /// この ACK が対応付ける request id を返す。
    pub fn id(&self) -> WireRequestId {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_id(value: u64) -> WireRequestId {
        WireRequestId::from_wire(value)
    }

    /// TASK-12.2・IO-1: `encode_request`（Write）→ `decode_request` が往復し、
    /// ペイロード先頭 8 バイトが request id の LE 表現になる（id=0x0102 →
    /// 先頭 `[0x02,0x01,0,0,0,0,0,0]`）。
    #[test]
    fn io1_encode_request_write_layout_and_round_trip() {
        let frame = encode_request(FrameKind::Write, wire_id(0x0102), b"hello")
            .expect("encode_request must succeed");
        assert_eq!(
            frame.payload()[..REQUEST_ID_WIRE_LEN],
            [0x02, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(&frame.payload()[REQUEST_ID_WIRE_LEN..], b"hello");

        let decoded = decode_request(&frame).expect("decode_request must succeed");
        assert_eq!(decoded.kind(), FrameKind::Write);
        assert_eq!(decoded.id().get(), 0x0102);
        assert_eq!(decoded.body(), b"hello");
    }

    /// TASK-12.2・IO-1: `encode_request`（Flush）は body を持たず、
    /// ペイロード長はちょうど [`REQUEST_ID_WIRE_LEN`]。
    #[test]
    fn io1_encode_request_flush_round_trip() {
        let frame =
            encode_request(FrameKind::Flush, wire_id(7), &[]).expect("encode_request must succeed");
        assert_eq!(frame.payload().len(), REQUEST_ID_WIRE_LEN);

        let decoded = decode_request(&frame).expect("decode_request must succeed");
        assert_eq!(decoded.kind(), FrameKind::Flush);
        assert_eq!(decoded.id().get(), 7);
        assert_eq!(decoded.body(), b"");
    }

    /// TASK-12.2・IO-1: `Flush` に空でない body を渡すと `encode_request` は
    /// `InvalidArgument` で拒否する。
    #[test]
    fn io1_encode_request_rejects_flush_with_body() {
        let err = encode_request(FrameKind::Flush, wire_id(1), b"x")
            .expect_err("flush with a body must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// TASK-12.2・IO-1: `Write` の body が `MAX_WRITE_BODY_LEN + 1` の場合は
    /// `InvalidArgument` で拒否する（長さだけで検証し、実確保はしない）。
    #[test]
    fn io1_encode_request_rejects_write_body_over_max() {
        // 64 MiB の実確保を避けるため、長さ判定用のヘルパーを直接呼ぶ。
        let err = validate_request_body_len(FrameKind::Write, MAX_WRITE_BODY_LEN as usize + 1)
            .expect_err("body length over MAX_WRITE_BODY_LEN must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        // 境界値（ちょうど MAX_WRITE_BODY_LEN）は受理される。
        validate_request_body_len(FrameKind::Write, MAX_WRITE_BODY_LEN as usize)
            .expect("body length exactly at MAX_WRITE_BODY_LEN must be accepted");
    }

    /// TASK-12.2・IO-1: `encode_request` / `decode_request` は `Ack`/`FlushAck` を
    /// 拒否する。
    #[test]
    fn io1_encode_decode_request_reject_ack_kinds() {
        let err = encode_request(FrameKind::Ack, wire_id(1), &[])
            .expect_err("Ack must be rejected by encode_request");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let ack_frame = encode_ack(FrameKind::Ack, wire_id(1)).expect("encode_ack must succeed");
        let err =
            decode_request(&ack_frame).expect_err("Ack frame must be rejected by decode_request");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// TASK-12.2・IO-1: `encode_ack`（Ack・FlushAck 両方）→ `decode_ack` が往復する。
    #[test]
    fn io1_encode_ack_round_trip_both_kinds() {
        for kind in [FrameKind::Ack, FrameKind::FlushAck] {
            let frame = encode_ack(kind, wire_id(42)).expect("encode_ack must succeed");
            assert_eq!(frame.payload().len(), ACK_PAYLOAD_LEN);

            let decoded = decode_ack(&frame).expect("decode_ack must succeed");
            assert_eq!(decoded.kind(), kind);
            assert_eq!(decoded.id().get(), 42);
        }
    }

    /// TASK-12.2・IO-1: `encode_ack` / `decode_ack` は `Write`/`Flush` を拒否する。
    #[test]
    fn io1_encode_decode_ack_reject_request_kinds() {
        let err = encode_ack(FrameKind::Write, wire_id(1))
            .expect_err("Write must be rejected by encode_ack");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let write_frame = encode_request(FrameKind::Write, wire_id(1), b"x")
            .expect("encode_request must succeed");
        let err = decode_ack(&write_frame).expect_err("Write frame must be rejected by decode_ack");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// TASK-12.2・IO-1: ACK ペイロードが 7 / 9 / 0 バイトの場合は `decode_ack` が
    /// `InvalidArgument` で拒否する（短くても長くても拒否）。
    #[test]
    fn io1_decode_ack_rejects_malformed_payload_len() {
        for len in [0usize, 7, 9] {
            let frame =
                Frame::new(FrameKind::Ack, vec![0u8; len]).expect("Frame::new must succeed");
            let err = decode_ack(&frame)
                .expect_err(&format!("ack payload of {len} byte(s) must be rejected"));
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        }
    }

    /// TASK-12.2・IO-1: `decode_request` はペイロードが `REQUEST_ID_WIRE_LEN` 未満
    /// （request id すら入っていない）の場合に `InvalidArgument` で拒否する。
    #[test]
    fn io1_decode_request_rejects_payload_shorter_than_request_id() {
        let frame = Frame::new(FrameKind::Write, vec![0u8; 3]).expect("Frame::new must succeed");
        let err = decode_request(&frame)
            .expect_err("payload shorter than REQUEST_ID_WIRE_LEN must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// TASK-12.2・IO-1: `WireRequestId::from(RequestId)` は発行元キュー識別子を
    /// 捨てて連番部分だけを取り出す（`crate::client::SendQueue` 経由で確認）。
    #[test]
    fn io1_wire_request_id_from_request_id_drops_queue_id() {
        use crate::client::{InFlightLimit, SendQueue};
        use crate::protocol::FrameKind as Fk;

        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut queue = SendQueue::new(limit);
        let request = queue.register(Fk::Write).expect("register must succeed");

        let wire_id = WireRequestId::from(request.id());
        assert_eq!(wire_id.get(), request.id().get());
    }
}
