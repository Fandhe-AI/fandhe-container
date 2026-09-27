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
//! ヘッダ・ペイロード・チェックサムから成るフレーム全体の型・エンコード / デコードは
//! TASK-11.3（#70）が担当する（REPAIR-3: 実装済みを装わない）。種別ごとの
//! ペイロード長制約（例: 制御フレームは長さ 0）も本モジュールでは設けず、#70 の
//! 責務とする。本モジュールが検証するのは (a) 種別が既知の値であること、
//! (b) ペイロード長が [`MAX_PAYLOAD_LEN`] 以下であること、の 2 点のみ。
//!
//! [`FrameHeader`] は [`crate::transport::WireFrame`] を実装しない。`WireFrame` は
//! フレーム全体（ヘッダ + ペイロード + チェックサム）を表す型のための境界であり、
//! ヘッダ単体はその構成要素の 1 つに過ぎないため。TASK-12・TASK-13 の送受信実装は、
//! 受信バイト列の先頭 [`FRAME_HEADER_LEN`] バイトを [`FrameHeader::from_bytes`] で
//! 検証してからペイロード長ぶんのバッファを確保する想定（DoS 対策。security.md）。

use crate::error::{IoError, IoErrorCode};

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
    /// TASK-11.3（#70）が定める。
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
/// request id・ACK status は含まない（TASK-11.3・#70 がペイロード側のレイアウトを
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
