//! パイプライン送信・バッチ ACK で使うフレームヘッダの newtype（TASK-11.2・IO-1・
//! REPAIR-2・MS-1・#69）。
//!
//! ヘッダは固定長 5 バイト（`[kind: u8][payload_len: u32 LE]`）で、種別
//! （[`FrameKind`]）とペイロード長（[`PayloadLen`]）だけを持つ。PoC-8
//! （`03-poc/ai-self-repair` の BREAK-2）で `data_len` を 1 バイト少なく申告する
//! 壊れ方が `cargo build` を素通りした反省から、構築時に上限検証済みの値しか
//! 表現できない型として組み立てる（REPAIR-2）。
//!
//! request id・ACK status はヘッダに含めない。それらのペイロード側レイアウトと、
//! 種別ごとのペイロード長制約（例: 制御フレームは長さ 0）は、本モジュールでは扱わず
//! TASK-12・TASK-13（またはそれらの後続 sub-issue）が定める（REPAIR-3: 実装済みを
//! 装わない）。本モジュールが検証するのは (a) 種別が既知の値であること、
//! (b) ペイロード長が [`MAX_PAYLOAD_LEN`] 以下であること、(c) [`Frame`] 全体の
//! チェックサムが一致すること、の 3 点。ペイロードは不透明なバイト列として扱う。
//!
//! [`FrameHeader`] は [`crate::transport::WireFrame`] を実装しない。`WireFrame` は
//! フレーム全体（ヘッダ + ペイロード + チェックサム。[`Frame`]）を表す型のための
//! 境界であり、ヘッダ単体はその構成要素の 1 つに過ぎないため。[`Frame::decode`] は
//! 受信バイト列の先頭 [`FRAME_HEADER_LEN`] バイトを [`FrameHeader::from_bytes`] で
//! 検証してからペイロード長ぶんのバッファを確保する（DoS 対策。security.md）。

use crate::error::{IoError, IoErrorCode};
use crate::transport::{WireFrame, sealed};

/// ペイロード長の上限（64 MiB = 67_108_864 バイト）。
///
/// PoC-2（`03-poc/io-layer-redesign`）・linux-real-machine 版の `MAX_DATA_LEN` を
/// 根拠とする。`fandhe-container-plugin` の境界機構（plugin-framed）が使う
/// 16 MiB 上限とは別の境界のため流用しない。この値は暫定であり、#70・#71・
/// TASK-12・TASK-13 で見直してよい（REPAIR-3）。
pub const MAX_PAYLOAD_LEN: u32 = 64 * 1024 * 1024;

/// `MAX_PAYLOAD_LEN + 1` が `u32` の範囲を超えないことをコンパイル時に保証する。
const _: () = assert!(MAX_PAYLOAD_LEN < u32::MAX);

/// 固定長ヘッダのバイト数（種別 1 バイト + ペイロード長 4 バイト）。
pub const FRAME_HEADER_LEN: usize = 5;

/// フレームの種別（IO-1・IO-2）。
///
/// `#[repr(u8)]` でワイヤー上のバイト値と一致させる。`0` はゼロ埋めバッファの
/// 誤解釈を検出するための予約値で、いずれのバリアントにも割り当てない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum FrameKind {
    /// パイプライン送信の書き込みフレーム。ペイロードのレイアウト（request id 等）は
    /// TASK-12・TASK-13（またはそれらの後続 sub-issue）が定める。
    Write = 1,
    /// 書き込みフレームに対する ACK。バッファリング時点（受信プロセスが
    /// フレームを受理したこと）までを保証し、永続化は保証しない（IO-1）。
    Ack = 2,
    /// FLUSH バリア。これ以前に受理した書き込みの永続化を要求する（IO-2）。
    /// PoC-2 の `FLUSH_MARKER`（id に埋め込む番兵値）は再現せず、種別フィールドで
    /// 表現する。
    Flush = 3,
    /// FLUSH バリアに対する ACK。バリア以前に受理した書き込みが永続化済みで
    /// あることを保証する（IO-2）。[`Self::Ack`] とは保証範囲が異なるため
    /// 別バリアントとして区別する。
    FlushAck = 4,
}

impl FrameKind {
    /// ワイヤー上のバイト値を返す。
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl From<FrameKind> for u8 {
    fn from(value: FrameKind) -> Self {
        value.as_u8()
    }
}

impl TryFrom<u8> for FrameKind {
    type Error = IoError;

    /// 未知のバイト値（`0` を含む）は [`IoErrorCode::InvalidArgument`] を返す。
    /// 既定値へ丸めたり黙って無視したりしない（security.md「インジェクション」観点）。
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Write),
            2 => Ok(Self::Ack),
            3 => Ok(Self::Flush),
            4 => Ok(Self::FlushAck),
            other => Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("unknown frame kind byte: {other}"),
            )),
        }
    }
}

/// 検証済みのペイロード長（[`MAX_PAYLOAD_LEN`] 以下であることが構築時に保証される）。
///
/// フィールドは非公開で、[`Self::new`] を経由しない限り値を作れない
/// （REPAIR-2: 壊れた値を表現できない型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PayloadLen(u32);

impl PayloadLen {
    /// `len` が [`MAX_PAYLOAD_LEN`] 以下であれば受理する（`0` も受理する）。
    /// 超過する場合は [`IoErrorCode::InvalidArgument`] を返す。
    pub fn new(len: u32) -> Result<Self, IoError> {
        if len > MAX_PAYLOAD_LEN {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("payload length {len} exceeds MAX_PAYLOAD_LEN ({MAX_PAYLOAD_LEN})"),
            ));
        }
        Ok(Self(len))
    }

    /// 検証済みのペイロード長を `u32` として返す。
    pub fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for PayloadLen {
    type Error = IoError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<usize> for PayloadLen {
    type Error = IoError;

    /// 送信側が `data.len(): usize` から直接構築するための変換。
    /// `u32` に収まらない場合も [`MAX_PAYLOAD_LEN`] 超過と同じ
    /// [`IoErrorCode::InvalidArgument`] にまとめる（呼び出し側の分岐を単純にする）。
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        let len = u32::try_from(value).map_err(|_| {
            IoError::new(
                IoErrorCode::InvalidArgument,
                format!("payload length {value} exceeds MAX_PAYLOAD_LEN ({MAX_PAYLOAD_LEN})"),
            )
        })?;
        Self::new(len)
    }
}

/// フレームの固定長ヘッダ（種別・ペイロード長のみ。IO-1・REPAIR-2）。
///
/// request id・ACK status は含まない（TASK-12・TASK-13 がペイロード側のレイアウトを
/// 定める）。フィールドは非公開で、[`Self::new`] / [`Self::from_bytes`] を経由しない
/// 限り値を作れない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameHeader {
    kind: FrameKind,
    payload_len: PayloadLen,
}

impl FrameHeader {
    /// 種別とペイロード長（`u32`）からヘッダを作る。
    ///
    /// `payload_len` が [`MAX_PAYLOAD_LEN`] を超える場合は
    /// [`IoErrorCode::InvalidArgument`] を返す。
    pub fn new(kind: FrameKind, payload_len: u32) -> Result<Self, IoError> {
        Ok(Self {
            kind,
            payload_len: PayloadLen::new(payload_len)?,
        })
    }

    /// フレーム種別を返す。
    pub fn kind(&self) -> FrameKind {
        self.kind
    }

    /// 検証済みのペイロード長を返す。
    pub fn payload_len(&self) -> PayloadLen {
        self.payload_len
    }

    /// ヘッダを `[kind: u8][payload_len: u32 LE]` の固定長配列へ変換する。
    /// 添字アクセスを避けるため分割代入で組み立てる（coding-rust「外部入力」節）。
    pub fn to_bytes(&self) -> [u8; FRAME_HEADER_LEN] {
        let [l0, l1, l2, l3] = self.payload_len.get().to_le_bytes();
        [self.kind.as_u8(), l0, l1, l2, l3]
    }

    /// 固定長配列からヘッダを復元する。
    ///
    /// 未知の種別バイト・[`MAX_PAYLOAD_LEN`] を超えるペイロード長は
    /// [`IoErrorCode::InvalidArgument`] として拒否する。`bytes` は untrusted な
    /// トランスポート由来の入力を想定し、添字アクセスではなく分割代入で読む。
    pub fn from_bytes(bytes: [u8; FRAME_HEADER_LEN]) -> Result<Self, IoError> {
        let [kind_byte, l0, l1, l2, l3] = bytes;
        let kind = FrameKind::try_from(kind_byte)?;
        let payload_len = PayloadLen::new(u32::from_le_bytes([l0, l1, l2, l3]))?;
        Ok(Self { kind, payload_len })
    }
}

/// チェックサムのバイト数（CRC-32C・4 バイト）。
pub const CHECKSUM_LEN: usize = 4;

/// フレーム全体（ヘッダ + ペイロード + チェックサム）の最大バイト数。
pub const MAX_FRAME_LEN: usize = FRAME_HEADER_LEN + MAX_PAYLOAD_LEN as usize + CHECKSUM_LEN;

/// [`Frame`] のチェックサム（CRC-32C。TASK-11.3・IO-1・REPAIR-2）。
///
/// フィールドは非公開で、公開コンストラクタを持たない。crate 内（[`Frame::new`]・
/// [`Frame::decode_body`]）でヘッダ＋ペイロードから計算した値のみが
/// この型の値になり、呼び出し側が任意の値を注入することはできない
/// （REPAIR-2: 壊れた値を表現できない型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameChecksum(u32);

impl FrameChecksum {
    /// ワイヤー上の CRC-32C 値（`u32`）を返す。
    pub fn get(self) -> u32 {
        self.0
    }
}

/// ヘッダ・ペイロード・チェックサムから成るフレーム全体（TASK-11.3・IO-1・
/// REPAIR-2・#70）。
///
/// # 不変条件
/// - `header.payload_len().get() as usize == payload.len()`
/// - `checksum` は `header.to_bytes() ‖ payload` に対する CRC-32C と一致する
///
/// フィールドは非公開で、[`Self::new`]・[`Self::decode`]・[`Self::decode_body`] を
/// 経由しない限り値を作れない。ペイロードは不透明なバイト列として扱い、
/// request id・ACK status 等のレイアウトはこの型の関知するところではない
/// （TASK-12・TASK-13 の責務）。
///
/// `Debug` は手書きし、ペイロード内容を出力しない（最大 64 MiB のバッファを
/// ログ・panic メッセージへ出さない。[`crate::error::IoError`] の
/// 「message にペイロード内容を含めない」契約と整合させる）。
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    header: FrameHeader,
    payload: Vec<u8>,
    checksum: FrameChecksum,
}

impl Frame {
    /// 種別とペイロードからフレームを作る。
    ///
    /// `payload.len()` が [`MAX_PAYLOAD_LEN`] を超える場合は
    /// [`IoErrorCode::InvalidArgument`] を返す。チェックサムはヘッダ＋ペイロードから
    /// 自動計算され、呼び出し側が指定する余地はない。
    pub fn new(kind: FrameKind, payload: Vec<u8>) -> Result<Self, IoError> {
        let header = FrameHeader::new(kind, PayloadLen::try_from(payload.len())?.get())?;
        let checksum = Self::compute_checksum(&header, &payload);
        Ok(Self {
            header,
            payload,
            checksum,
        })
    }

    /// ヘッダとペイロードから CRC-32C を計算する（ヘッダも対象に含める。
    /// 種別・長さフィールドの破壊も検出するため。ペイロードのみだと BREAK-2 の
    /// ような「長さの嘘」に対し、送信側バグと整合したチェックサムが通る余地がある）。
    fn compute_checksum(header: &FrameHeader, payload: &[u8]) -> FrameChecksum {
        let mut crc = crate::checksum::Crc32c::new();
        crc.update(&header.to_bytes());
        crc.update(payload);
        FrameChecksum(crc.finalize())
    }

    /// フレームの種別を返す。
    pub fn kind(&self) -> FrameKind {
        self.header.kind()
    }

    /// フレームのヘッダを返す。
    pub fn header(&self) -> FrameHeader {
        self.header
    }

    /// ペイロードへの参照を返す。
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// ペイロードを所有権ごと取り出す。
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    /// フレームのチェックサムを返す。
    pub fn checksum(&self) -> FrameChecksum {
        self.checksum
    }

    /// フレームをワイヤーフォーマット
    /// `[header: FRAME_HEADER_LEN B][payload: N B][checksum: CHECKSUM_LEN B LE]`
    /// へ直列化する。
    ///
    /// `Frame` はすでに長さ検証済みの型のため、ここでの `Vec` 手組みは
    /// 「検証済みの値からのみ生成する」という REPAIR-2 の趣旨に反しない
    /// （公開コンストラクタが生の `Vec<u8>` を任意に受け付けるわけではない）。
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len() + CHECKSUM_LEN);
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.checksum.0.to_le_bytes());
        bytes
    }

    /// 検証済みのヘッダと、それに続く「ペイロード + チェックサム」の本体から
    /// フレームを復元する（受信側の 2 段階デコード API の後段。TASK-12・TASK-13 が
    /// 使う想定）。
    ///
    /// # 検証順序
    /// 1. `header.payload_len()` から期待される本体長（`payload_len + CHECKSUM_LEN`）を
    ///    `checked_add` で算出し、オーバーフロー時は [`IoErrorCode::InvalidArgument`]
    /// 2. `body.len()` が期待長と一致しなければ [`IoErrorCode::InvalidArgument`]
    ///    （チェックサム不一致とは別コード）
    /// 3. `body` をペイロードと受信チェックサムに分割し、ヘッダ＋ペイロードから
    ///    再計算した CRC-32C と比較。不一致なら [`IoErrorCode::DataLoss`]
    ///
    /// `body` は untrusted なトランスポート由来の入力を想定し、添字アクセスではなく
    /// `split_last_chunk` で読む。
    pub fn decode_body(header: FrameHeader, body: &[u8]) -> Result<Self, IoError> {
        let payload_len = usize::try_from(header.payload_len().get()).map_err(|_| {
            IoError::new(
                IoErrorCode::InvalidArgument,
                "payload length does not fit in usize on this platform",
            )
        })?;
        let expected_len = payload_len.checked_add(CHECKSUM_LEN).ok_or_else(|| {
            IoError::new(
                IoErrorCode::InvalidArgument,
                "payload length + checksum length overflows",
            )
        })?;

        if body.len() != expected_len {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!(
                    "frame body length mismatch: expected {expected_len} bytes, got {} bytes",
                    body.len()
                ),
            ));
        }

        let (payload, checksum_bytes) =
            body.split_last_chunk::<CHECKSUM_LEN>().ok_or_else(|| {
                IoError::new(
                    IoErrorCode::InvalidArgument,
                    "frame body shorter than checksum length",
                )
            })?;

        let received_checksum = u32::from_le_bytes(*checksum_bytes);
        let expected_checksum = Self::compute_checksum(&header, payload);

        if received_checksum != expected_checksum.0 {
            return Err(IoError::new(
                IoErrorCode::DataLoss,
                format!(
                    "frame checksum mismatch: expected {:#010x}, got {:#010x}",
                    expected_checksum.0, received_checksum
                ),
            ));
        }

        Ok(Self {
            header,
            payload: payload.to_vec(),
            checksum: expected_checksum,
        })
    }

    /// ヘッダから始まる完全なワイヤーバイト列からフレームを復元する
    /// （[`Self::decode_body`] の一括版）。
    ///
    /// 先頭 [`FRAME_HEADER_LEN`] バイトを [`FrameHeader::from_bytes`] で検証してから
    /// 残りを [`Self::decode_body`] に渡すため、上限検証前にペイロード用の
    /// アロケーションは行わない（DoS 対策。security.md）。
    pub fn decode(bytes: &[u8]) -> Result<Self, IoError> {
        let (header_bytes, body) =
            bytes
                .split_first_chunk::<FRAME_HEADER_LEN>()
                .ok_or_else(|| {
                    IoError::new(
                        IoErrorCode::InvalidArgument,
                        "frame is shorter than the fixed header length",
                    )
                })?;
        let header = FrameHeader::from_bytes(*header_bytes)?;
        Self::decode_body(header, body)
    }
}

impl core::fmt::Debug for Frame {
    /// ペイロード内容を出力しない。長さ・種別・チェックサムのみを表示する
    /// （security.md「情報漏えい」観点。message/Debug にペイロード内容を含めない）。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Frame")
            .field("kind", &self.header.kind())
            .field("payload_len", &self.payload.len())
            .field("checksum", &format_args!("{:#010x}", self.checksum.0))
            .finish()
    }
}

impl sealed::Sealed for Frame {}
impl WireFrame for Frame {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::crc32c;

    /// IO-1・REPAIR-2: `PayloadLen::new(0)` は受理され、値は 0。
    #[test]
    fn io1_payload_len_accepts_zero() {
        let len = PayloadLen::new(0).expect("zero must be accepted");
        assert_eq!(len.get(), 0);
    }

    /// IO-1・REPAIR-2: `PayloadLen::new(MAX_PAYLOAD_LEN)` は受理され、値は 67_108_864。
    #[test]
    fn io1_payload_len_accepts_max() {
        let len = PayloadLen::new(MAX_PAYLOAD_LEN).expect("MAX_PAYLOAD_LEN must be accepted");
        assert_eq!(len.get(), 67_108_864);
    }

    /// IO-1・REPAIR-2: `MAX_PAYLOAD_LEN + 1` は `InvalidArgument` として拒否される。
    #[test]
    fn io1_payload_len_rejects_max_plus_one() {
        let err = PayloadLen::new(MAX_PAYLOAD_LEN + 1).expect_err("must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1: `u32::MAX` は `InvalidArgument` として拒否される。
    #[test]
    fn io1_payload_len_rejects_u32_max() {
        let err = PayloadLen::new(u32::MAX).expect_err("u32::MAX must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1: `TryFrom<usize>` の境界値（0・MAX・MAX+1・usize::MAX）を確認する。
    #[test]
    fn io1_payload_len_try_from_usize_boundaries() {
        let zero = PayloadLen::try_from(0usize).expect("0 must be accepted");
        assert_eq!(zero.get(), 0);

        let max = PayloadLen::try_from(MAX_PAYLOAD_LEN as usize).expect("MAX must be accepted");
        assert_eq!(max.get(), MAX_PAYLOAD_LEN);

        let over = PayloadLen::try_from(MAX_PAYLOAD_LEN as usize + 1)
            .expect_err("MAX + 1 must be rejected");
        assert_eq!(over.code(), IoErrorCode::InvalidArgument);

        let usize_max = PayloadLen::try_from(usize::MAX).expect_err("usize::MAX must be rejected");
        assert_eq!(usize_max.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・IO-2: 全種別で `as_u8` と `TryFrom<u8>` が往復し、`Ack` と `FlushAck` の
    /// バイト値が異なる（保証範囲の違いを型レベルで区別できていることの確認）。
    #[test]
    fn io1_frame_kind_round_trips_all_variants() {
        assert_eq!(FrameKind::Write.as_u8(), 1);
        assert_eq!(FrameKind::Ack.as_u8(), 2);
        assert_eq!(FrameKind::Flush.as_u8(), 3);
        assert_eq!(FrameKind::FlushAck.as_u8(), 4);

        assert_eq!(
            FrameKind::try_from(1u8).expect("1 is Write"),
            FrameKind::Write
        );
        assert_eq!(FrameKind::try_from(2u8).expect("2 is Ack"), FrameKind::Ack);
        assert_eq!(
            FrameKind::try_from(3u8).expect("3 is Flush"),
            FrameKind::Flush
        );
        assert_eq!(
            FrameKind::try_from(4u8).expect("4 is FlushAck"),
            FrameKind::FlushAck
        );

        assert_ne!(FrameKind::Ack.as_u8(), FrameKind::FlushAck.as_u8());
    }

    /// IO-1: 予約値 `0`・未知値 `5`・`0xFF` は `InvalidArgument` として拒否される。
    #[test]
    fn io1_frame_kind_rejects_unknown_bytes() {
        for byte in [0u8, 5, 0xFF] {
            let err = FrameKind::try_from(byte).expect_err("unknown byte must be rejected");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        }
    }

    /// IO-1・REPAIR-2: `FrameHeader::new` の境界値（0・MAX は Ok、MAX+1・u32::MAX は Err）。
    #[test]
    fn io1_frame_header_new_boundaries() {
        let zero = FrameHeader::new(FrameKind::Write, 0).expect("0 must be accepted");
        assert_eq!(zero.kind(), FrameKind::Write);
        assert_eq!(zero.payload_len().get(), 0);

        let max = FrameHeader::new(FrameKind::Write, MAX_PAYLOAD_LEN)
            .expect("MAX_PAYLOAD_LEN must be accepted");
        assert_eq!(max.payload_len().get(), MAX_PAYLOAD_LEN);

        let over = FrameHeader::new(FrameKind::Write, MAX_PAYLOAD_LEN + 1)
            .expect_err("MAX + 1 must be rejected");
        assert_eq!(over.code(), IoErrorCode::InvalidArgument);

        let err_max =
            FrameHeader::new(FrameKind::Flush, u32::MAX).expect_err("u32::MAX must be rejected");
        assert_eq!(err_max.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1: `to_bytes()` が `[kind][payload_len: LE]` のレイアウトになる
    /// （0x0102_0304 → LE で 04 03 02 01）。
    #[test]
    fn io1_frame_header_to_bytes_layout() {
        let header = FrameHeader::new(FrameKind::Write, 0x0102_0304)
            .expect("valid header must be constructed");
        assert_eq!(header.to_bytes(), [0x01, 0x04, 0x03, 0x02, 0x01]);
    }

    /// IO-1・REPAIR-2: 全種別・長さ 0 / MAX で `to_bytes` → `from_bytes` が往復する。
    #[test]
    fn io1_frame_header_from_bytes_round_trip() {
        for kind in [
            FrameKind::Write,
            FrameKind::Ack,
            FrameKind::Flush,
            FrameKind::FlushAck,
        ] {
            for len in [0u32, MAX_PAYLOAD_LEN] {
                let header = FrameHeader::new(kind, len).expect("valid header");
                let bytes = header.to_bytes();
                let decoded = FrameHeader::from_bytes(bytes).expect("round trip must succeed");
                assert_eq!(decoded, header);
                assert_eq!(decoded.kind(), kind);
                assert_eq!(decoded.payload_len().get(), len);
            }
        }
    }

    /// IO-1: 未知の種別バイト（`0`・`0xFF`）を含むヘッダは `from_bytes` で拒否される。
    #[test]
    fn io1_frame_header_from_bytes_rejects_unknown_kind() {
        let zero_kind =
            FrameHeader::from_bytes([0, 0, 0, 0, 0]).expect_err("kind byte 0 must be rejected");
        assert_eq!(zero_kind.code(), IoErrorCode::InvalidArgument);

        let unknown_kind = FrameHeader::from_bytes([0xFF, 0, 0, 0, 0])
            .expect_err("kind byte 0xFF must be rejected");
        assert_eq!(unknown_kind.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・REPAIR-2: BREAK-2（PoC-8）を模した、上限を超えるペイロード長申告は
    /// `from_bytes` で拒否される。
    #[test]
    fn io1_frame_header_from_bytes_rejects_len_over_max() {
        let [l0, l1, l2, l3] = (MAX_PAYLOAD_LEN + 1).to_le_bytes();
        let over_max = FrameHeader::from_bytes([FrameKind::Write.as_u8(), l0, l1, l2, l3])
            .expect_err("MAX_PAYLOAD_LEN + 1 must be rejected");
        assert_eq!(over_max.code(), IoErrorCode::InvalidArgument);

        let u32_max = FrameHeader::from_bytes([FrameKind::Write.as_u8(), 0xFF, 0xFF, 0xFF, 0xFF])
            .expect_err("u32::MAX must be rejected");
        assert_eq!(u32_max.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・REPAIR-2: 全種別・ペイロード長 0 と小サイズで `encode` → `decode` が
    /// 往復する。
    #[test]
    fn io1_frame_round_trips_all_kinds() {
        for kind in [
            FrameKind::Write,
            FrameKind::Ack,
            FrameKind::Flush,
            FrameKind::FlushAck,
        ] {
            for payload in [Vec::new(), b"abc12".to_vec()] {
                let frame = Frame::new(kind, payload.clone()).expect("Frame::new must succeed");
                let encoded = frame.encode();
                let decoded = Frame::decode(&encoded).expect("decode must succeed");
                assert_eq!(decoded.kind(), kind);
                assert_eq!(decoded.payload(), payload.as_slice());
                assert_eq!(decoded.checksum(), frame.checksum());
            }
        }
    }

    /// IO-1・REPAIR-2: 固定入力（Write・`b"abc"`）の `encode` 結果を具体値で照合する。
    /// レイアウトは `[kind][payload_len LE][payload][checksum LE]`。
    #[test]
    fn io1_frame_encode_layout() {
        let frame = Frame::new(FrameKind::Write, b"abc".to_vec()).expect("Frame::new");
        let encoded = frame.encode();

        // ヘッダ: kind=1(Write), payload_len=3(LE)
        assert_eq!(&encoded[0..5], &[1, 3, 0, 0, 0]);
        // ペイロード
        assert_eq!(&encoded[5..8], b"abc");
        // チェックサム: ヘッダ(5B) ‖ ペイロード(3B) に対する CRC-32C の LE 表現
        let expected_crc = crc32c(&[1, 3, 0, 0, 0, b'a', b'b', b'c']);
        assert_eq!(&encoded[8..12], &expected_crc.to_le_bytes());
        assert_eq!(encoded.len(), 12);
    }

    /// IO-1・REPAIR-2（受け入れ条件 1）: PoC-8 BREAK-2 相当（送信側が申告する
    /// ペイロード長を実長 − 1 にする破壊）を模した入力を `decode_body` に渡すと
    /// `DataLoss` として拒否される。
    ///
    /// 正しいフレーム（長さ N）を作った上で、ヘッダの申告長だけを N-1 に書き換え、
    /// 本体（body）はオリジナルの後続 `(N-1)+CHECKSUM_LEN` バイトのまま渡す
    /// （= 本来の payload 先頭 N-1 バイト + 本来の payload 最終バイト + checksum
    /// 先頭 3 バイトが「ペイロード」として解釈される）ことで、
    /// 長さ検証は通るがチェックサムは一致しない状況を作る。
    #[test]
    fn repair2_decode_detects_break2_short_declared_len() {
        let original_payload = b"hello".to_vec(); // N = 5
        let frame = Frame::new(FrameKind::Write, original_payload.clone()).expect("Frame::new");
        let encoded = frame.encode();
        let (_header_bytes, body) = encoded
            .split_first_chunk::<FRAME_HEADER_LEN>()
            .expect("encoded frame must have a header");

        // 申告長を N-1 = 4 に書き換えたヘッダ（BREAK-2: 長さの嘘）。
        let short_header = FrameHeader::new(FrameKind::Write, (original_payload.len() - 1) as u32)
            .expect("short header must be valid");

        // body を「短い申告長 (N-1) + CHECKSUM_LEN」ぶんだけに切り詰める。これで
        // 長さ検証（InvalidArgument）は通過し、本来の payload 最終バイト＋checksum
        // 先頭バイト群が「ペイロード」として誤解釈されるためチェックサムが
        // 一致しない状況になる（BREAK-2: 長さの嘘がヘッダ層だけでは検出できない）。
        let short_body_len = (original_payload.len() - 1) + CHECKSUM_LEN;
        let short_body = body
            .get(..short_body_len)
            .expect("body must be at least short_body_len bytes");

        let err = Frame::decode_body(short_header, short_body)
            .expect_err("short declared length must be rejected as data loss");
        assert_eq!(err.code(), IoErrorCode::DataLoss);
    }

    /// IO-1・REPAIR-2: ペイロードの 1 ビット反転は `DataLoss` として拒否される。
    #[test]
    fn repair2_decode_rejects_flipped_payload_bit() {
        let frame = Frame::new(FrameKind::Write, b"hello".to_vec()).expect("Frame::new");
        let mut encoded = frame.encode();
        // ペイロード領域（header 5B の直後）の 1 バイト目、最下位ビットを反転する。
        encoded[5] ^= 0x01;

        let err = Frame::decode(&encoded).expect_err("flipped bit must be rejected");
        assert_eq!(err.code(), IoErrorCode::DataLoss);
    }

    /// IO-1・REPAIR-2: 種別バイトを別の有効な種別へ差し替えると `DataLoss` になる
    /// （チェックサムがヘッダも対象にしていることの確認）。
    #[test]
    fn repair2_decode_rejects_kind_swapped_to_valid_kind() {
        let frame = Frame::new(FrameKind::Write, b"hello".to_vec()).expect("Frame::new");
        let mut encoded = frame.encode();
        encoded[0] = FrameKind::Ack.as_u8();

        let err = Frame::decode(&encoded).expect_err("kind swap must be rejected");
        assert_eq!(err.code(), IoErrorCode::DataLoss);
    }

    /// IO-1・REPAIR-2: トレーラ（チェックサム）の 1 バイト改変は `DataLoss` になる。
    #[test]
    fn repair2_decode_rejects_corrupted_checksum() {
        let frame = Frame::new(FrameKind::Write, b"hello".to_vec()).expect("Frame::new");
        let mut encoded = frame.encode();
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;

        let err = Frame::decode(&encoded).expect_err("corrupted checksum must be rejected");
        assert_eq!(err.code(), IoErrorCode::DataLoss);
    }

    /// IO-1: 一括 `decode` で余剰・不足バイトは `InvalidArgument`（チェックサム不一致
    /// とは別コードであること）。
    #[test]
    fn io1_decode_rejects_length_mismatch() {
        let frame = Frame::new(FrameKind::Write, b"hello".to_vec()).expect("Frame::new");
        let encoded = frame.encode();

        let mut truncated = encoded.clone();
        truncated.pop();
        let err = Frame::decode(&truncated).expect_err("truncated body must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let mut extended = encoded.clone();
        extended.push(0);
        let err = Frame::decode(&extended).expect_err("extended body must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        // decode_body 単体でも body 長不一致を InvalidArgument として拒否する。
        let (header_bytes, body) = encoded
            .split_first_chunk::<FRAME_HEADER_LEN>()
            .expect("encoded frame must have a header");
        let header = FrameHeader::from_bytes(*header_bytes).expect("header must decode");
        let mut short_body = body.to_vec();
        short_body.pop();
        let err = Frame::decode_body(header, &short_body)
            .expect_err("short body must be rejected as invalid argument");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1: ヘッダ長未満（5 バイト未満）の入力は `InvalidArgument` になる。
    #[test]
    fn io1_decode_rejects_truncated_header() {
        let err = Frame::decode(&[1, 0, 0, 0]).expect_err("4 bytes must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let err = Frame::decode(&[]).expect_err("empty input must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// security.md「情報漏えい」観点: `Debug` 出力にペイロード内容（マーカー文字列）が
    /// 含まれない。
    #[test]
    fn io1_frame_debug_omits_payload() {
        let frame = Frame::new(FrameKind::Write, b"SECRET_MARKER".to_vec()).expect("Frame::new");
        let debug_output = format!("{frame:?}");
        assert!(!debug_output.contains("SECRET_MARKER"));
        assert!(debug_output.contains("Write"));
        assert!(debug_output.contains("13")); // payload_len
    }

    /// IO-1: `Frame` が `WireFrame`（`Sealed + Send + Debug`）境界を満たす。
    #[test]
    fn io1_frame_implements_wire_frame() {
        fn assert_wire<T: WireFrame>() {}
        assert_wire::<Frame>();
    }
}
