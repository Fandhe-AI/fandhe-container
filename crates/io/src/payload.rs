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
//! # v2（#3161・IO-1・REPAIR-2）が足すファイル操作のペイロード形式
//!
//! `docs/design/io-protocol.md` の F4・F10 で確定した形式。すべて整数は LE。
//!
//! | 種別 | ペイロード | 制約 |
//! | ---- | ---------- | ---- |
//! | [`crate::protocol::FrameKind::Create`] | `[id u64][path_len u16][path: UTF-8]` | `payload_len == `[`CREATE_FIXED_LEN`]` + path_len`、`1 ≤ path_len ≤ `[`MAX_GUEST_PATH_BYTES`] |
//! | [`crate::protocol::FrameKind::WriteFile`] | `[id u64][handle u64][body...]` | 1 バイト以上 [`MAX_WRITE_FILE_BODY_LEN`] 以下（空の body は構造違反） |
//! | [`crate::protocol::FrameKind::Close`] | `[id u64][handle u64]` | ちょうど [`CLOSE_PAYLOAD_LEN`]（16 バイト） |
//! | [`crate::protocol::FrameKind::Nack`] | `[id u64][code u8][reason u16]` | ちょうど [`NACK_PAYLOAD_LEN`]（11 バイト）。code は 1〜3 のみ |
//!
//! ハンドルは `Create` フレームの request id そのもの（F6）なのでワイヤー上は
//! [`WireRequestId`] で表す。復号は長さと UTF-8 だけを見る純関数で、`Create` の
//! パスの構文（`..`・絶対パス等）は検証しない（F5。サーバーのディスパッチ時に
//! [`crate::guest_path::GuestPath::parse`] が行う）。したがって復号済みのパスは
//! 未検証の構文として扱うこと（ファイルシステムや `Path::join` へ渡さない）。
//! エラー文にはペイロードの中身（パス等）を入れず、数値だけを入れる（F10）。
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
//! v2 でも `Ack` 自体はこの方針を維持する。ファイル操作モードの要求単位の失敗
//! だけを別の種別 [`crate::protocol::FrameKind::Nack`] で返す（F8）。
//!
//! 単一 sink モード（v1 と同じ意味論）のサーバー側の失敗は接続再利用禁止契約（P1-3。`crates/io/src/transport.rs`
//! モジュールドキュメント）により接続断で伝わるため、ACK 自体に成功/失敗を
//! 示す status バイトを持たせる必要がない。あとから status を追加するのは
//! ワイヤー形式の変更にあたり `PROTOCOL_VERSION` を上げる必要がある
//! （PoC-2 の `status(0=OK)` をあえて再現しない理由）。
//!
//! # `PROTOCOL_VERSION` の繰り上げ（v2）
//!
//! v1 ではペイロードの意味づけを本モジュールが初めて定めただけでフレーム全体の
//! バイトレイアウトは変わらなかったため版を据え置いた。v2（#3161・F2）は
//! 種別 5〜8 の追加でワイヤー形式が変わるため `PROTOCOL_VERSION` を 2 に上げた。
//! ヘッダ 10 バイトとトレーラのレイアウトは同じで、v1 のヘッダは
//! [`crate::protocol::FrameHeader::from_bytes`] が `Unimplemented` で拒否する。
//!
//! # 想定する呼び出し元
//!
//! - [`crate::client::PipelineClient::send`]（TASK-12.1・#73）が
//!   [`encode_request`] で id を埋め込んだフレームを組み立てる
//! - [`crate::client::PipelineClient::recv_ack`]（TASK-12.2・#74）が
//!   [`decode_ack`] で受信 ACK を検証する
//! - v2 の [`encode_create`] 等は `PipelineClient` の型つき API（#3162。実装済み）と
//!   ファイル操作モードのサーバー（`file_serve`。#3163。実装済み）が使い、本モジュールは
//!   符号化と復号だけを提供する
//! - バッチ write-back サーバー本体（TASK-13.2・#77・#820）が [`decode_request`]・
//!   [`encode_ack`] で同じ形式を読み書きする想定（本モジュールはクライアント・
//!   サーバー双方から使われるため `client.rs` ではなく独立モジュールに置く）
//!
//! ワイヤーに載せるのは連番（`u64`）のみで、[`crate::client::RequestId`] が
//! 内部に持つ発行元キュー識別子（`QueueId`）はメモリ内の区別にのみ使い、
//! ワイヤー上には一切現れない（[`crate::client`] モジュールドキュメント参照）。

use crate::client::RequestId;
use crate::error::{IoError, IoErrorCode};
use crate::guest_path::{GuestPath, MAX_GUEST_PATH_BYTES};
pub use crate::nack_reason::{NackReason, UnknownNackReason};
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

/// [`FrameKind::Create`] の固定部のバイト数（id 8 + path_len 2）。
pub const CREATE_FIXED_LEN: usize = REQUEST_ID_WIRE_LEN + 2;

/// [`FrameKind::Create`] のペイロードの最大長（固定部 + [`MAX_GUEST_PATH_BYTES`]）。
pub const MAX_CREATE_PAYLOAD_LEN: usize = CREATE_FIXED_LEN + MAX_GUEST_PATH_BYTES;

/// ハンドル（`Create` の request id）のワイヤー上のバイト数。
pub const FILE_HANDLE_WIRE_LEN: usize = REQUEST_ID_WIRE_LEN;

/// [`FrameKind::WriteFile`] の固定部のバイト数（id 8 + handle 8）。
pub const WRITE_FILE_FIXED_LEN: usize = REQUEST_ID_WIRE_LEN + FILE_HANDLE_WIRE_LEN;

/// [`FrameKind::WriteFile`] の body に許される最大長（1 バイト以上。空は構造違反）。
pub const MAX_WRITE_FILE_BODY_LEN: u32 = MAX_PAYLOAD_LEN - WRITE_FILE_FIXED_LEN as u32;

/// [`FrameKind::Close`] のペイロード長（id 8 + handle 8）。
pub const CLOSE_PAYLOAD_LEN: usize = REQUEST_ID_WIRE_LEN + FILE_HANDLE_WIRE_LEN;

/// [`FrameKind::Nack`] のペイロード長（id 8 + code 1 + reason 2）。
pub const NACK_PAYLOAD_LEN: usize = REQUEST_ID_WIRE_LEN + 3;

const _: () = assert!(MAX_WRITE_FILE_BODY_LEN + WRITE_FILE_FIXED_LEN as u32 == MAX_PAYLOAD_LEN);
// path_len は u16 で運ぶため、上限が u16 に収まることを固定する。
const _: () = assert!(MAX_GUEST_PATH_BYTES <= u16::MAX as usize);
const _: () = assert!(MAX_CREATE_PAYLOAD_LEN <= MAX_PAYLOAD_LEN as usize);

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
        FrameKind::Create | FrameKind::WriteFile | FrameKind::Close | FrameKind::Nack => {
            Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "encode_request only accepts Write/Flush frame kinds; use encode_create/encode_write_file/encode_close/encode_nack for file operations",
            ))
        }
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
        FrameKind::Create | FrameKind::WriteFile | FrameKind::Close | FrameKind::Nack => {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "decode_request only accepts Write/Flush frame kinds; use decode_create/decode_write_file/decode_close/decode_nack for file operations",
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
        FrameKind::Write
        | FrameKind::Flush
        | FrameKind::Create
        | FrameKind::WriteFile
        | FrameKind::Close
        | FrameKind::Nack => {
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
        FrameKind::Write
        | FrameKind::Flush
        | FrameKind::Create
        | FrameKind::WriteFile
        | FrameKind::Close
        | FrameKind::Nack => {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "decode_ack only accepts Ack/FlushAck frame kinds; use decode_request for Write/Flush (Nack is decoded by decode_nack)",
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
// ---------------------------------------------------------------------------
// v2 ファイル操作（#3161・IO-1・REPAIR-2）
// ---------------------------------------------------------------------------

fn invalid(message: impl Into<String>) -> IoError {
    IoError::new(IoErrorCode::InvalidArgument, message.into())
}

/// `frame.kind()` が `expected` と一致することを確かめる（取り違えの拒否）。
fn expect_kind(frame: &Frame, expected: FrameKind, who: &str) -> Result<(), IoError> {
    if frame.kind() == expected {
        Ok(())
    } else {
        Err(invalid(format!("{who} only accepts {expected:?} frames")))
    }
}

/// `[id u64]` を先頭から読み、残りを返す（短ければ `InvalidArgument`）。
fn split_wire_id<'a>(payload: &'a [u8], who: &str) -> Result<(WireRequestId, &'a [u8]), IoError> {
    let (id_bytes, rest) = payload
        .split_first_chunk::<REQUEST_ID_WIRE_LEN>()
        .ok_or_else(|| {
            invalid(format!(
                "{who} payload shorter than {REQUEST_ID_WIRE_LEN} bytes: {} byte(s)",
                payload.len()
            ))
        })?;
    Ok((
        WireRequestId::from_wire(u64::from_le_bytes(*id_bytes)),
        rest,
    ))
}

/// [`FrameKind::Create`] フレームを組み立てる（クライアント側。`PipelineClient::create`
/// が使う。#3162）。
///
/// `path` は構文検証済みの [`GuestPath`] なので長さは 1〜[`MAX_GUEST_PATH_BYTES`] に
/// 収まるが、防御として `u16` への変換と上限を再確認し、違反なら
/// [`IoErrorCode::InvalidArgument`] を返す（panic しない）。
pub fn encode_create(id: WireRequestId, path: &GuestPath) -> Result<Frame, IoError> {
    let bytes = path.as_str().as_bytes();
    let path_len = u16::try_from(bytes.len())
        .ok()
        .filter(|len| (1..=MAX_GUEST_PATH_BYTES).contains(&usize::from(*len)))
        .ok_or_else(|| {
            invalid(format!(
                "create path length {} is outside 1..={MAX_GUEST_PATH_BYTES}",
                bytes.len()
            ))
        })?;
    let mut payload = Vec::with_capacity(CREATE_FIXED_LEN + bytes.len());
    payload.extend_from_slice(&id.get().to_le_bytes());
    payload.extend_from_slice(&path_len.to_le_bytes());
    payload.extend_from_slice(bytes);
    Frame::new(FrameKind::Create, payload)
}

/// [`decode_create`] が返す、検証済みの Create 要求（フレームへの借用）。
///
/// `path` は長さと UTF-8 だけを検証した値で、構文（`..`・絶対パス等）は未検証。
/// ファイルシステムへ渡す前に [`GuestPath::parse`] を通すこと（F5）。
#[derive(Debug, Clone, Copy)]
pub struct CreateEnvelope<'a> {
    id: WireRequestId,
    path: &'a str,
}

impl<'a> CreateEnvelope<'a> {
    /// この要求の request id（兼ハンドル。F6）。
    pub fn id(&self) -> WireRequestId {
        self.id
    }

    /// 構文未検証のパス文字列（長さ 1〜[`MAX_GUEST_PATH_BYTES`]・UTF-8 は検証済み）。
    pub fn path(&self) -> &'a str {
        self.path
    }
}

/// [`FrameKind::Create`] フレームを復元する（サーバー側。`file_serve` が使う。#3163）。
///
/// 検証順: (1) 固定部 [`CREATE_FIXED_LEN`] バイト以上、(2) `path_len` が
/// 1〜[`MAX_GUEST_PATH_BYTES`]、(3) 残りがちょうど `path_len` バイト（短くても
/// 長くても拒否）、(4) UTF-8。いずれも新しい確保なしに借用で返す。違反は
/// [`IoErrorCode::InvalidArgument`]（フレーム構造の違反。接続全体の失効の根拠）。
pub fn decode_create(frame: &Frame) -> Result<CreateEnvelope<'_>, IoError> {
    expect_kind(frame, FrameKind::Create, "decode_create")?;
    let (id, rest) = split_wire_id(frame.payload(), "create")?;
    let (len_bytes, path_bytes) = rest
        .split_first_chunk::<2>()
        .ok_or_else(|| invalid("create payload shorter than its fixed part"))?;
    let path_len = usize::from(u16::from_le_bytes(*len_bytes));
    if !(1..=MAX_GUEST_PATH_BYTES).contains(&path_len) {
        return Err(invalid(format!(
            "create path_len {path_len} is outside 1..={MAX_GUEST_PATH_BYTES}"
        )));
    }
    if path_bytes.len() != path_len {
        return Err(invalid(format!(
            "create path_len {path_len} does not match the {} path byte(s) present",
            path_bytes.len()
        )));
    }
    let path = std::str::from_utf8(path_bytes).map_err(|_| invalid("create path is not UTF-8"))?;
    Ok(CreateEnvelope { id, path })
}

/// body の長さが [`FrameKind::WriteFile`] に許される範囲（1〜[`MAX_WRITE_FILE_BODY_LEN`]）
/// かを検証する（[`encode_write_file`] が確保の前に使う）。
fn validate_write_file_body_len(body_len: usize) -> Result<(), IoError> {
    if body_len == 0 {
        return Err(invalid("write_file body must not be empty"));
    }
    if body_len as u128 > MAX_WRITE_FILE_BODY_LEN as u128 {
        return Err(invalid(format!(
            "write_file body length {body_len} exceeds MAX_WRITE_FILE_BODY_LEN ({MAX_WRITE_FILE_BODY_LEN})"
        )));
    }
    Ok(())
}

/// [`FrameKind::WriteFile`] フレームを組み立てる。`body` は 1 バイト以上
/// [`MAX_WRITE_FILE_BODY_LEN`] 以下。違反は確保の前に [`IoErrorCode::InvalidArgument`]。
pub fn encode_write_file(
    id: WireRequestId,
    handle: WireRequestId,
    body: &[u8],
) -> Result<Frame, IoError> {
    validate_write_file_body_len(body.len())?;
    let mut payload = Vec::with_capacity(WRITE_FILE_FIXED_LEN + body.len());
    payload.extend_from_slice(&id.get().to_le_bytes());
    payload.extend_from_slice(&handle.get().to_le_bytes());
    payload.extend_from_slice(body);
    Frame::new(FrameKind::WriteFile, payload)
}

/// [`decode_write_file`] が返す、検証済みの WriteFile 要求（フレームへの借用）。
#[derive(Debug, Clone, Copy)]
pub struct WriteFileEnvelope<'a> {
    id: WireRequestId,
    handle: WireRequestId,
    body: &'a [u8],
}

impl<'a> WriteFileEnvelope<'a> {
    /// この要求の request id。
    pub fn id(&self) -> WireRequestId {
        self.id
    }

    /// 書き込み先のハンドル（`Create` の request id）。
    pub fn handle(&self) -> WireRequestId {
        self.handle
    }

    /// 1 バイト以上の本体。
    pub fn body(&self) -> &'a [u8] {
        self.body
    }
}

/// [`FrameKind::WriteFile`] フレームを復元する。固定部 [`WRITE_FILE_FIXED_LEN`] 未満
/// または body が空なら [`IoErrorCode::InvalidArgument`]。body の上限は
/// [`Frame`] の構築時点でペイロード全体が [`MAX_PAYLOAD_LEN`] 以下に制限されている
/// ため自動的に [`MAX_WRITE_FILE_BODY_LEN`] 以下になる。
pub fn decode_write_file(frame: &Frame) -> Result<WriteFileEnvelope<'_>, IoError> {
    expect_kind(frame, FrameKind::WriteFile, "decode_write_file")?;
    let (id, rest) = split_wire_id(frame.payload(), "write_file")?;
    let (handle, body) = split_wire_id(rest, "write_file handle")?;
    if body.is_empty() {
        return Err(invalid("write_file body must not be empty"));
    }
    Ok(WriteFileEnvelope { id, handle, body })
}

/// [`FrameKind::Close`] フレームを組み立てる。
pub fn encode_close(id: WireRequestId, handle: WireRequestId) -> Result<Frame, IoError> {
    let mut payload = Vec::with_capacity(CLOSE_PAYLOAD_LEN);
    payload.extend_from_slice(&id.get().to_le_bytes());
    payload.extend_from_slice(&handle.get().to_le_bytes());
    Frame::new(FrameKind::Close, payload)
}

/// [`decode_close`] が返す、検証済みの Close 要求。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseEnvelope {
    id: WireRequestId,
    handle: WireRequestId,
}

impl CloseEnvelope {
    /// この要求の request id。
    pub fn id(&self) -> WireRequestId {
        self.id
    }

    /// 解放するハンドル（`Create` の request id）。
    pub fn handle(&self) -> WireRequestId {
        self.handle
    }
}

/// [`FrameKind::Close`] フレームを復元する。ペイロードはちょうど
/// [`CLOSE_PAYLOAD_LEN`] バイト（短くても長くても [`IoErrorCode::InvalidArgument`]）。
pub fn decode_close(frame: &Frame) -> Result<CloseEnvelope, IoError> {
    expect_kind(frame, FrameKind::Close, "decode_close")?;
    let payload = frame.payload();
    let exact = <[u8; CLOSE_PAYLOAD_LEN]>::try_from(payload).map_err(|_| {
        invalid(format!(
            "close payload length must be exactly {CLOSE_PAYLOAD_LEN} bytes, got {} byte(s)",
            payload.len()
        ))
    })?;
    let (id, rest) = split_wire_id(&exact, "close")?;
    let (handle, _) = split_wire_id(rest, "close handle")?;
    Ok(CloseEnvelope { id, handle })
}

/// [`FrameKind::Nack`] の大分類（`docs/design/io-protocol.md` F10）。
///
/// code の追加は版の繰り上げを伴うため `#[non_exhaustive]` を付けず、網羅性を
/// コンパイラに検査させる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NackCode {
    /// 要求の中身が不正（パス構文・祖先・未知ハンドル等）。
    InvalidArgument = 1,
    /// 既に存在する（`Exists`・大文字小文字 / 正規化の衝突）。
    AlreadyExists = 2,
    /// 資源の上限（開けるファイル数・デバイス数・追跡パス数）。
    ResourceExhausted = 3,
}

impl NackCode {
    /// ワイヤー上のバイト値。
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// F10 の対応表どおりに写した [`IoErrorCode`]（観測の `nack_code` 用）。
    pub fn io_error_code(self) -> IoErrorCode {
        match self {
            Self::InvalidArgument => IoErrorCode::InvalidArgument,
            Self::AlreadyExists => IoErrorCode::AlreadyExists,
            Self::ResourceExhausted => IoErrorCode::ResourceExhausted,
        }
    }
}

impl TryFrom<u8> for NackCode {
    type Error = IoError;

    /// 未知の code（0 と 4 以上）は [`IoErrorCode::InvalidArgument`]（プロトコル違反）。
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::InvalidArgument),
            2 => Ok(Self::AlreadyExists),
            3 => Ok(Self::ResourceExhausted),
            other => Err(invalid(format!("unknown nack code byte: {other}"))),
        }
    }
}

/// [`FrameKind::Nack`] フレームを組み立てる（サーバー側。`file_serve` が使う。#3163）。
/// 自由文字列を持たない（パス等をワイヤーへ返さない。F10）。
pub fn encode_nack(
    id: WireRequestId,
    code: NackCode,
    reason: NackReason,
) -> Result<Frame, IoError> {
    let mut payload = Vec::with_capacity(NACK_PAYLOAD_LEN);
    payload.extend_from_slice(&id.get().to_le_bytes());
    payload.push(code.as_u8());
    payload.extend_from_slice(&reason.wire_value().to_le_bytes());
    Frame::new(FrameKind::Nack, payload)
}

/// [`decode_nack`] が返す、検証済みの Nack。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NackEnvelope {
    id: WireRequestId,
    code: NackCode,
    reason: NackReason,
}

impl NackEnvelope {
    /// 失敗した要求の request id。
    pub fn id(&self) -> WireRequestId {
        self.id
    }

    /// 大分類。
    pub fn code(&self) -> NackCode {
        self.code
    }

    /// 理由（未知の値は [`NackReason::Other`]）。
    pub fn reason(&self) -> NackReason {
        self.reason
    }
}

/// [`FrameKind::Nack`] フレームを復元する（クライアント側。`PipelineClient::recv_ack`
/// が使う。#3162）。
/// ペイロードはちょうど [`NACK_PAYLOAD_LEN`] バイト。未知の code は
/// [`IoErrorCode::InvalidArgument`]（プロトコル違反として接続を失効させる根拠）。
pub fn decode_nack(frame: &Frame) -> Result<NackEnvelope, IoError> {
    expect_kind(frame, FrameKind::Nack, "decode_nack")?;
    let payload = frame.payload();
    let exact = <[u8; NACK_PAYLOAD_LEN]>::try_from(payload).map_err(|_| {
        invalid(format!(
            "nack payload length must be exactly {NACK_PAYLOAD_LEN} bytes, got {} byte(s)",
            payload.len()
        ))
    })?;
    let (id, rest) = split_wire_id(&exact, "nack")?;
    let (code_byte, reason_bytes) = rest
        .split_first()
        .ok_or_else(|| invalid("nack payload missing code"))?;
    let reason_bytes =
        <[u8; 2]>::try_from(reason_bytes).map_err(|_| invalid("nack payload missing reason"))?;
    let code = NackCode::try_from(*code_byte)?;
    let reason = NackReason::from_wire(u16::from_le_bytes(reason_bytes));
    Ok(NackEnvelope { id, code, reason })
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
    // ----- v2 ファイル操作（#3161・IO-1・REPAIR-2） -----

    fn gp(path: &str) -> GuestPath {
        GuestPath::parse(path).expect("valid guest path")
    }

    /// 独立計算（ビット単位の CRC-32C）で求めた golden vector。実装の関数から
    /// 期待値を導かず、リテラルで照合する。
    #[test]
    fn io1_v2_create_golden_vector() {
        let frame = encode_create(wire_id(1), &gp("a/b")).expect("encode_create");
        assert_eq!(
            frame.encode(),
            vec![
                0x02, 0x05, 0x0d, 0x00, 0x00, 0x00, 0xf8, 0xf5, 0xd1, 0x04, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x61, 0x2f, 0x62, 0x65, 0x35, 0x2f, 0xc2
            ]
        );
    }

    #[test]
    fn io1_v2_write_file_golden_vector() {
        let frame = encode_write_file(wire_id(2), wire_id(1), b"xy").expect("encode_write_file");
        assert_eq!(
            frame.encode(),
            vec![
                0x02, 0x06, 0x12, 0x00, 0x00, 0x00, 0x1d, 0x2f, 0xc2, 0x4a, 0x02, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x79,
                0x72, 0x35, 0x47, 0x59
            ]
        );
    }

    #[test]
    fn io1_v2_close_golden_vector() {
        let frame = encode_close(wire_id(3), wire_id(1)).expect("encode_close");
        assert_eq!(
            frame.encode(),
            vec![
                0x02, 0x07, 0x10, 0x00, 0x00, 0x00, 0x30, 0x63, 0xb4, 0xcd, 0x03, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd9, 0x27,
                0xa3, 0x89
            ]
        );
    }

    #[test]
    fn io1_v2_nack_golden_vector() {
        let frame = encode_nack(wire_id(1), NackCode::AlreadyExists, NackReason::Exists)
            .expect("encode_nack");
        assert_eq!(
            frame.encode(),
            vec![
                0x02, 0x08, 0x0b, 0x00, 0x00, 0x00, 0x07, 0x3d, 0xa7, 0xdd, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 0x00, 0x0f, 0x1c, 0x27, 0xf3
            ]
        );
    }

    /// 4 種別が encode → Frame::encode → Frame::decode → decode_* で往復する。
    #[test]
    fn io1_v2_file_frames_round_trip_through_wire() {
        let wire = |f: Frame| Frame::decode(&f.encode()).expect("frame decode");

        let create = wire(encode_create(wire_id(7), &gp("dir/file.txt")).expect("create"));
        let env = decode_create(&create).expect("decode_create");
        assert_eq!(env.id().get(), 7);
        assert_eq!(env.path(), "dir/file.txt");

        let write = wire(encode_write_file(wire_id(8), wire_id(7), b"hello").expect("write"));
        let env = decode_write_file(&write).expect("decode_write_file");
        assert_eq!((env.id().get(), env.handle().get()), (8, 7));
        assert_eq!(env.body(), b"hello");

        let close = wire(encode_close(wire_id(9), wire_id(7)).expect("close"));
        let env = decode_close(&close).expect("decode_close");
        assert_eq!((env.id().get(), env.handle().get()), (9, 7));

        let nack = wire(
            encode_nack(
                wire_id(7),
                NackCode::ResourceExhausted,
                NackReason::OpenFilesLimit,
            )
            .expect("nack"),
        );
        let env = decode_nack(&nack).expect("decode_nack");
        assert_eq!(env.id().get(), 7);
        assert_eq!(env.code(), NackCode::ResourceExhausted);
        assert_eq!(env.reason(), NackReason::OpenFilesLimit);
    }

    fn create_payload(path_len_field: u16, path: &[u8]) -> Frame {
        let mut payload = 1u64.to_le_bytes().to_vec();
        payload.extend_from_slice(&path_len_field.to_le_bytes());
        payload.extend_from_slice(path);
        Frame::new(FrameKind::Create, payload).expect("frame")
    }

    /// Create の path_len と実長の境界（0・1・4096・4097、±1 の不一致、固定部未満、
    /// UTF-8 違反）。
    #[test]
    fn io1_v2_decode_create_boundaries() {
        // path_len = 0 / 4097 は拒否
        let err = decode_create(&create_payload(0, b"")).expect_err("path_len 0");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        let long = vec![b'a'; MAX_GUEST_PATH_BYTES + 1];
        let err = decode_create(&create_payload(4097, &long)).expect_err("path_len 4097");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        // 1 と 4096 は受理
        let one = create_payload(1, b"a");
        let env = decode_create(&one).expect("path_len 1");
        assert_eq!(env.path(), "a");
        let max = vec![b'a'; MAX_GUEST_PATH_BYTES];
        let frame = create_payload(4096, &max);
        assert_eq!(frame.payload().len(), MAX_CREATE_PAYLOAD_LEN);
        assert_eq!(
            decode_create(&frame).expect("path_len 4096").path().len(),
            4096
        );

        // 実長が 1 短い / 1 長い
        let err = decode_create(&create_payload(3, b"ab")).expect_err("one short");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        let err = decode_create(&create_payload(3, b"abcd")).expect_err("one long");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        // 固定部 10 バイト未満（9 バイト）
        let short = Frame::new(FrameKind::Create, vec![0u8; 9]).expect("frame");
        let err = decode_create(&short).expect_err("9 byte payload");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        // UTF-8 でない
        let err = decode_create(&create_payload(1, &[0xff])).expect_err("not utf-8");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        assert!(!err.message().contains("255"));
    }

    /// Create は構文（`..` 等）を検証しない（F5。構文は dispatch 時の担当）。
    #[test]
    fn io1_v2_decode_create_does_not_judge_path_syntax() {
        let dots = create_payload(2, b"..");
        let env = decode_create(&dots).expect("syntax is not checked");
        assert_eq!(env.path(), "..");
    }

    #[test]
    fn io1_v2_decode_write_file_boundaries() {
        for len in [15usize, 16] {
            let frame = Frame::new(FrameKind::WriteFile, vec![0u8; len]).expect("frame");
            let err = decode_write_file(&frame).expect_err("short or empty body");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        }
        let frame = Frame::new(FrameKind::WriteFile, vec![0u8; 17]).expect("frame");
        assert_eq!(decode_write_file(&frame).expect("17 bytes").body().len(), 1);

        validate_write_file_body_len(MAX_WRITE_FILE_BODY_LEN as usize)
            .expect("max body is accepted");
        let err = validate_write_file_body_len(MAX_WRITE_FILE_BODY_LEN as usize + 1)
            .expect_err("max + 1");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        let err = encode_write_file(wire_id(1), wire_id(1), &[]).expect_err("empty body");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    #[test]
    fn io1_v2_decode_close_and_nack_require_exact_length() {
        for len in [15usize, 17] {
            let frame = Frame::new(FrameKind::Close, vec![0u8; len]).expect("frame");
            let err = decode_close(&frame).expect_err("close length");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        }
        for len in [10usize, 12] {
            let frame = Frame::new(FrameKind::Nack, vec![0u8; len]).expect("frame");
            let err = decode_nack(&frame).expect_err("nack length");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        }
    }

    fn nack_frame(code: u8, reason: u16) -> Frame {
        let mut payload = 1u64.to_le_bytes().to_vec();
        payload.push(code);
        payload.extend_from_slice(&reason.to_le_bytes());
        Frame::new(FrameKind::Nack, payload).expect("frame")
    }

    #[test]
    fn io1_v2_nack_code_and_reason_handling() {
        for code in [0u8, 4, 0xFF] {
            let err = decode_nack(&nack_frame(code, 1)).expect_err("unknown code");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        }
        for reason in [0u16, 12, 0xFFFF] {
            let env = decode_nack(&nack_frame(1, reason)).expect("unknown reason is accepted");
            assert!(matches!(env.reason(), NackReason::Other(_)));
            assert_eq!(env.reason().wire_value(), reason);
        }
        for reason in 1u16..=11 {
            let parsed = NackReason::from_wire(reason);
            assert!(!matches!(parsed, NackReason::Other(_)), "reason {reason}");
            assert_eq!(parsed.wire_value(), reason);
        }
        assert_eq!(NackReason::from_wire(5), NackReason::Exists);
        assert_eq!(NackCode::try_from(2).expect("2"), NackCode::AlreadyExists);
    }

    /// 取り違え: 各 decode_* は他の種別を拒否し、既存の encode/decode_request・
    /// encode/decode_ack も 5〜8 を拒否する。
    #[test]
    fn io1_v2_kind_mixups_are_rejected() {
        let create = encode_create(wire_id(1), &gp("a")).expect("create");
        let write = encode_write_file(wire_id(2), wire_id(1), b"x").expect("write");
        let close = encode_close(wire_id(3), wire_id(1)).expect("close");
        let nack = encode_nack(
            wire_id(1),
            NackCode::InvalidArgument,
            NackReason::PathSyntax,
        )
        .expect("nack");

        assert!(decode_create(&write).is_err());
        assert!(decode_write_file(&close).is_err());
        assert!(decode_close(&nack).is_err());
        assert!(decode_nack(&create).is_err());

        for frame in [&create, &write, &close, &nack] {
            assert!(decode_request(frame).is_err());
            assert!(decode_ack(frame).is_err());
        }
        for kind in [
            FrameKind::Create,
            FrameKind::WriteFile,
            FrameKind::Close,
            FrameKind::Nack,
        ] {
            let err = encode_request(kind, wire_id(1), b"x").expect_err("encode_request");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
            let err = encode_ack(kind, wire_id(1)).expect_err("encode_ack");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        }
    }
}
