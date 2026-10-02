//! plugin 境界の長さ接頭辞フレーム（TASK-107.2・PLUG-2・PLUG-5・REPAIR-1・REPAIR-2・MS-3・#245）。
//!
//! core と plugin プロセスが UDS 上で交わす制御面メッセージを運ぶフレームの、固定長ヘッダ・
//! トレーラ・チェックサムを「壊れた値を表現できない」型として定義する。ペイロード（serde_json）の
//! 解釈は TASK-107.3（#247）、UDS の読み書き・タイムアウトは #248〜#250 の責務で、本モジュールは
//! 純粋なデータ型のみを持ち I/O を行わない。
//!
//! # ワイヤーレイアウト（version 1。整数はすべてリトルエンディアン）
//!
//! ```text
//! [version: u8][payload_len: u32][header_crc: u32] | [payload: N B] | [checksum: u32]
//!  └────────────── ヘッダ 9 バイト ─────────────┘                    └ トレーラ 4 バイト ┘
//! ```
//!
//! - `header_crc`: 先頭 5 バイト（`version`・`payload_len`）の CRC-32C。ヘッダ単体で検証でき、
//!   化けた `payload_len` を信用した巨大確保・読み待ちを防ぐ。
//! - `checksum`（トレーラ）: 「ヘッダ先頭 5 バイト ‖ ペイロード」の CRC-32C。`header_crc` を含む
//!   ヘッダ全体を対象にしてはならない。CRC は `M ‖ CRC(M)` を処理した後のレジスタ状態が `M` に
//!   よらず一定（residue）になるため、自己整合に作り直したヘッダへ差し替えてもトレーラが変わらず、
//!   長さフィールドの破壊を検出できなくなる（`docs/design/io-protocol.md` の注意と同じ）。
//! - 種別（kind）は持たない。メッセージ種別は JSON ペイロード側のタグで表す（#247）。
//!   ヘッダへフィールドを足す場合は [`PROTOCOL_VERSION`] を上げる（REPAIR-3）。
//!
//! # 受信の想定手順（2 段階デコード。実際の読み取りは #248 以降で実装。REPAIR-3）
//!
//! 1. ヘッダ [`FRAME_HEADER_LEN`] バイトを読み、[`FrameHeader::from_bytes`] で検証する
//!    （header_crc → version → 長さ上限の順。先に検証した項目が壊れていれば後続を信用しない）。
//! 2. [`FrameHeader::body_len`] バイトだけ確保して読み、[`Frame::decode_body`] で検証する。
//!
//! # 信頼境界
//!
//! CRC-32C は偶発的破損の検出用で、改ざん耐性（真正性）はない。接続の保護は
//! UDS の所有者・peer credential 検証（PLUG-12・TASK-123・124）に委ねる。

use std::fmt;

use crate::checksum::Crc32c;
use crate::error::{PluginError, PluginErrorCode};

/// 現行のフレーム版数。版ずれはフレームごとに検出し、ネゴシエーションは行わない。
pub const PROTOCOL_VERSION: u8 = 1;
/// ヘッダの固定長（`version` 1 + `payload_len` 4 + `header_crc` 4）。
pub const FRAME_HEADER_LEN: usize = 9;
/// トレーラ（チェックサム）の固定長。
pub const CHECKSUM_LEN: usize = 4;
/// ペイロード長の上限（16 MiB）。PoC-13（plugin-framed。MS-3 の plugin 境界機構〔TASK-107〕で採用）の上限を根拠とする暫定値で、
/// TASK-113 の再計測で見直しうる（REPAIR-3）。io 共有層の上限（64 MiB）とは別の境界で、流用しない。
pub const MAX_PAYLOAD_LEN: u32 = 16 * 1024 * 1024;
/// フレーム全体の最大長（ヘッダ + 最大ペイロード + トレーラ）。
pub const MAX_FRAME_LEN: usize = FRAME_HEADER_LEN + MAX_PAYLOAD_LEN as usize + CHECKSUM_LEN;

/// ヘッダ先頭の CRC 対象部分（`version` + `payload_len`）の長さ。
const HEADER_PREFIX_LEN: usize = 5;

const _: () = assert!(MAX_PAYLOAD_LEN < u32::MAX);
const _: () = assert!(usize::BITS >= 32);

/// 検証済みのペイロード長。[`MAX_PAYLOAD_LEN`] 超の値は構築できない（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PayloadLen(u32);

impl PayloadLen {
    /// 上限を検証して生成する。0 は受理する。
    pub fn new(len: u32) -> Result<Self, PluginError> {
        if len > MAX_PAYLOAD_LEN {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                format!("payload length {len} exceeds maximum {MAX_PAYLOAD_LEN}"),
            ));
        }
        Ok(Self(len))
    }

    /// 長さをバイト数で返す。
    pub fn get(&self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for PayloadLen {
    type Error = PluginError;

    fn try_from(len: u32) -> Result<Self, Self::Error> {
        Self::new(len)
    }
}

impl TryFrom<usize> for PayloadLen {
    type Error = PluginError;

    fn try_from(len: usize) -> Result<Self, Self::Error> {
        match u32::try_from(len) {
            Ok(v) => Self::new(v),
            Err(_) => Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                format!("payload length {len} exceeds maximum {MAX_PAYLOAD_LEN}"),
            )),
        }
    }
}

/// ヘッダ先頭 5 バイト（`version`・`payload_len`）を組み立てる。
fn header_prefix(len: PayloadLen) -> [u8; HEADER_PREFIX_LEN] {
    let l = len.get().to_le_bytes();
    [PROTOCOL_VERSION, l[0], l[1], l[2], l[3]]
}

/// バイト列の CRC-32C を計算する（ヘッダ接頭部用）。
fn crc_of(bytes: &[u8]) -> u32 {
    let mut c = Crc32c::new();
    c.update(bytes);
    c.finalize()
}

/// 検証済みフレームヘッダ（9 バイト固定長）。ペイロード長が上限内であることを型で保証する。
///
/// 受信側は [`FrameHeader::from_bytes`] を通ったヘッダの [`FrameHeader::body_len`] だけを
/// 読み取りサイズに使う（検証前の申告長で確保しない。PLUG-2・REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameHeader {
    payload_len: PayloadLen,
}

impl FrameHeader {
    /// ペイロード長からヘッダを生成する。上限超過は `InvalidArgument`。
    pub fn new(payload_len: u32) -> Result<Self, PluginError> {
        Ok(Self {
            payload_len: PayloadLen::new(payload_len)?,
        })
    }

    /// ペイロード長を返す。
    pub fn payload_len(&self) -> PayloadLen {
        self.payload_len
    }

    /// ヘッダ後に続く本体（ペイロード + トレーラ）のバイト数。受信側の読み取りサイズ。
    pub fn body_len(&self) -> usize {
        // `payload_len` は MAX_PAYLOAD_LEN 以下で、usize は 32 bit 以上のため溢れない。
        self.payload_len.get() as usize + CHECKSUM_LEN
    }

    /// ワイヤー表現（9 バイト）へ直列化する。
    pub fn to_bytes(&self) -> [u8; FRAME_HEADER_LEN] {
        let p = header_prefix(self.payload_len);
        let crc = crc_of(&p).to_le_bytes();
        [p[0], p[1], p[2], p[3], p[4], crc[0], crc[1], crc[2], crc[3]]
    }

    /// ワイヤー表現から復号する。
    ///
    /// 検証順序: `header_crc` 不一致は `DataLoss`、`version` 不一致は `Unimplemented`、
    /// 長さ上限超過は `InvalidArgument`。先に検証した項目が壊れていれば後続を信用しない。
    pub fn from_bytes(bytes: [u8; FRAME_HEADER_LEN]) -> Result<Self, PluginError> {
        let [v, l0, l1, l2, l3, c0, c1, c2, c3] = bytes;
        let expected = crc_of(&[v, l0, l1, l2, l3]);
        let actual = u32::from_le_bytes([c0, c1, c2, c3]);
        if expected != actual {
            return Err(PluginError::new(
                PluginErrorCode::DataLoss,
                format!(
                    "frame header checksum mismatch: expected {expected:#010x}, got {actual:#010x}"
                ),
            ));
        }
        if v != PROTOCOL_VERSION {
            return Err(PluginError::new(
                PluginErrorCode::Unimplemented,
                format!("unsupported frame version {v}; supported version is {PROTOCOL_VERSION}"),
            ));
        }
        Self::new(u32::from_le_bytes([l0, l1, l2, l3]))
    }
}

/// フレーム本体のチェックサム。公開コンストラクタを持たず、値は [`Frame`] が計算した
/// ものか、検証を通ったものに限る（任意値を注入できない。REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameChecksum(u32);

impl FrameChecksum {
    /// チェックサム値を返す。
    pub fn get(&self) -> u32 {
        self.0
    }

    /// 「ヘッダ先頭 5 バイト ‖ ペイロード」の CRC-32C を計算する。
    fn compute(len: PayloadLen, payload: &[u8]) -> Self {
        let mut c = Crc32c::new();
        c.update(&header_prefix(len));
        c.update(payload);
        Self(c.finalize())
    }
}

/// 検証済みフレーム（ヘッダ・ペイロード・チェックサム）。フィールドは非公開で、
/// [`Frame::new`] か [`Frame::decode`] / [`Frame::decode_body`] 経由でのみ作れる。
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    header: FrameHeader,
    payload: Vec<u8>,
    checksum: FrameChecksum,
}

// ペイロードは秘密情報を含みうるため、`Debug` では長さとチェックサムのみ出す。
impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("payload_len", &self.header.payload_len.get())
            .field("checksum", &self.checksum)
            .finish()
    }
}

impl Frame {
    /// ペイロードからフレームを生成する。長さ超過は `InvalidArgument`。
    /// チェックサムは自動計算され、外部から注入できない。
    pub fn new(payload: Vec<u8>) -> Result<Self, PluginError> {
        let len = PayloadLen::try_from(payload.len())?;
        let checksum = FrameChecksum::compute(len, &payload);
        Ok(Self {
            header: FrameHeader { payload_len: len },
            payload,
            checksum,
        })
    }

    /// ヘッダを返す。
    pub fn header(&self) -> FrameHeader {
        self.header
    }

    /// ペイロードを返す。
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// ペイロードを取り出す。
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    /// チェックサムを返す。
    pub fn checksum(&self) -> FrameChecksum {
        self.checksum
    }

    /// ワイヤー表現（ヘッダ ‖ ペイロード ‖ トレーラ）へ直列化する。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len() + CHECKSUM_LEN);
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.checksum.0.to_le_bytes());
        out
    }

    /// 2 段階デコードの後段。検証済みヘッダと本体（ペイロード ‖ トレーラ）から復号する。
    ///
    /// `body.len()` が [`FrameHeader::body_len`] と異なれば `InvalidArgument`、
    /// トレーラ不一致は `DataLoss`。ペイロードの複製は全検証の通過後のみ行う。
    pub fn decode_body(header: FrameHeader, body: &[u8]) -> Result<Self, PluginError> {
        if body.len() != header.body_len() {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                format!(
                    "frame body length mismatch: expected {}, got {}",
                    header.body_len(),
                    body.len()
                ),
            ));
        }
        let Some((payload, trailer)) =
            body.split_at_checked(body.len().saturating_sub(CHECKSUM_LEN))
        else {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "frame body shorter than trailer",
            ));
        };
        let Ok(trailer) = <[u8; CHECKSUM_LEN]>::try_from(trailer) else {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "frame trailer has invalid length",
            ));
        };
        let actual = u32::from_le_bytes(trailer);
        let expected = FrameChecksum::compute(header.payload_len, payload);
        if expected.0 != actual {
            return Err(PluginError::new(
                PluginErrorCode::DataLoss,
                format!(
                    "frame checksum mismatch: expected {:#010x}, got {actual:#010x}",
                    expected.0
                ),
            ));
        }
        Ok(Self {
            header,
            payload: payload.to_vec(),
            checksum: expected,
        })
    }

    /// 一括版デコード。短すぎる入力・余剰バイトは `InvalidArgument`。
    pub fn decode(bytes: &[u8]) -> Result<Self, PluginError> {
        let Some((head, body)) = bytes.split_at_checked(FRAME_HEADER_LEN) else {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                format!(
                    "frame shorter than header: {} < {FRAME_HEADER_LEN}",
                    bytes.len()
                ),
            ));
        };
        let Ok(head) = <[u8; FRAME_HEADER_LEN]>::try_from(head) else {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "frame header has invalid length",
            ));
        };
        let header = FrameHeader::from_bytes(head)?;
        Self::decode_body(header, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_of<T: fmt::Debug>(r: Result<T, PluginError>) -> PluginErrorCode {
        match r {
            Ok(v) => panic!("expected error, got {v:?}"),
            Err(e) => e.code(),
        }
    }

    /// 自己整合な CRC を付けた手組みヘッダ。
    fn raw_header(version: u8, len: u32) -> [u8; FRAME_HEADER_LEN] {
        let l = len.to_le_bytes();
        let p = [version, l[0], l[1], l[2], l[3]];
        let c = crc_of(&p).to_le_bytes();
        [p[0], p[1], p[2], p[3], p[4], c[0], c[1], c[2], c[3]]
    }

    #[test]
    fn repair2_payload_len_accepts_zero_and_max() {
        assert_eq!(PayloadLen::new(0).unwrap().get(), 0);
        assert_eq!(PayloadLen::new(MAX_PAYLOAD_LEN).unwrap().get(), 16_777_216);
    }

    #[test]
    fn repair2_payload_len_rejects_max_plus_one() {
        assert_eq!(
            code_of(PayloadLen::new(MAX_PAYLOAD_LEN + 1)),
            PluginErrorCode::InvalidArgument
        );
        assert_eq!(
            code_of(PayloadLen::try_from(MAX_PAYLOAD_LEN as usize + 1)),
            PluginErrorCode::InvalidArgument
        );
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn repair2_payload_len_rejects_usize_over_u32() {
        assert_eq!(
            code_of(PayloadLen::try_from(u32::MAX as usize + 1)),
            PluginErrorCode::InvalidArgument
        );
    }

    #[test]
    fn repair2_frame_header_new_rejects_len_over_max() {
        assert_eq!(
            code_of(FrameHeader::new(MAX_PAYLOAD_LEN + 1)),
            PluginErrorCode::InvalidArgument
        );
        assert!(FrameHeader::new(MAX_PAYLOAD_LEN).is_ok());
        assert_eq!(MAX_FRAME_LEN, 9 + 16_777_216 + 4);
    }

    #[test]
    fn plug2_frame_header_roundtrip() {
        let h = FrameHeader::new(1234).unwrap();
        let bytes = h.to_bytes();
        assert_eq!(&bytes[..5], &[1, 0xD2, 0x04, 0, 0]);
        assert_eq!(FrameHeader::from_bytes(bytes).unwrap(), h);
        assert_eq!(h.body_len(), 1238);
    }

    #[test]
    fn plug2_frame_header_matches_self_consistent_raw_header() {
        let bytes = FrameHeader::new(0).unwrap().to_bytes();
        assert_eq!(&bytes[..5], &[1, 0, 0, 0, 0]);
        assert_eq!(bytes, raw_header(1, 0));
    }

    #[test]
    fn repair2_from_bytes_rejects_corrupted_header_crc() {
        let good = FrameHeader::new(77).unwrap().to_bytes();
        for byte in 0..FRAME_HEADER_LEN {
            for bit in 0..8 {
                let mut b = good;
                b[byte] ^= 1 << bit;
                assert_eq!(
                    code_of(FrameHeader::from_bytes(b)),
                    PluginErrorCode::DataLoss,
                    "byte {byte} bit {bit}"
                );
            }
        }
    }

    #[test]
    fn repair2_from_bytes_rejects_oversized_len_with_valid_crc() {
        assert_eq!(
            code_of(FrameHeader::from_bytes(raw_header(1, MAX_PAYLOAD_LEN + 1))),
            PluginErrorCode::InvalidArgument
        );
    }

    #[test]
    fn plug2_from_bytes_rejects_unknown_version() {
        let e = FrameHeader::from_bytes(raw_header(2, 8)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unimplemented);
        assert!(e.message().contains('2') && e.message().contains('1'));
    }

    #[test]
    fn plug2_frame_encode_decode_roundtrip() {
        for n in [0usize, 1, 5, 255, 4096] {
            let payload: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let f = Frame::new(payload.clone()).unwrap();
            let wire = f.encode();
            assert_eq!(wire.len(), FRAME_HEADER_LEN + n + CHECKSUM_LEN);
            let d = Frame::decode(&wire).unwrap();
            assert_eq!(d.payload(), payload.as_slice());
            assert_eq!(d, f);
            assert_eq!(d.into_payload(), payload);
        }
    }

    #[test]
    fn repair2_decode_detects_flipped_payload_bit() {
        let wire = Frame::new(b"hello plugin".to_vec()).unwrap().encode();
        for i in FRAME_HEADER_LEN..wire.len() - CHECKSUM_LEN {
            for bit in 0..8 {
                let mut w = wire.clone();
                w[i] ^= 1 << bit;
                assert_eq!(code_of(Frame::decode(&w)), PluginErrorCode::DataLoss);
            }
        }
    }

    #[test]
    fn repair2_decode_detects_flipped_trailer_bit() {
        let wire = Frame::new(b"hello plugin".to_vec()).unwrap().encode();
        for i in wire.len() - CHECKSUM_LEN..wire.len() {
            for bit in 0..8 {
                let mut w = wire.clone();
                w[i] ^= 1 << bit;
                assert_eq!(code_of(Frame::decode(&w)), PluginErrorCode::DataLoss);
            }
        }
    }

    /// BREAK-2 相当: 申告長を偽り header_crc を再計算しても、トレーラが接頭 5 バイトを
    /// 対象にしているため拒否される。
    #[test]
    fn repair2_decode_rejects_length_lie() {
        let wire = Frame::new(b"0123456789".to_vec()).unwrap().encode();
        let mut lie = wire.clone();
        lie[..FRAME_HEADER_LEN].copy_from_slice(&raw_header(1, 9));
        // 申告長が 1 バイト短いため、一括版は本体長不一致で拒否する。
        assert_eq!(
            code_of(Frame::decode(&lie)),
            PluginErrorCode::InvalidArgument
        );
        // 申告長に合わせて本体を切り詰めた場合はトレーラ不一致（DataLoss）。
        let header = FrameHeader::from_bytes(raw_header(1, 9)).unwrap();
        let body = &wire[FRAME_HEADER_LEN..wire.len() - 1];
        assert_eq!(
            code_of(Frame::decode_body(header, body)),
            PluginErrorCode::DataLoss
        );
    }

    #[test]
    fn repair2_decode_body_rejects_body_len_mismatch() {
        let header = FrameHeader::new(4).unwrap();
        assert_eq!(
            code_of(Frame::decode_body(header, &[0u8; 7])),
            PluginErrorCode::InvalidArgument
        );
        assert_eq!(
            code_of(Frame::decode_body(header, &[0u8; 9])),
            PluginErrorCode::InvalidArgument
        );
    }

    #[test]
    fn repair2_decode_rejects_short_and_trailing_bytes() {
        assert_eq!(
            code_of(Frame::decode(&[1, 0, 0])),
            PluginErrorCode::InvalidArgument
        );
        let mut wire = Frame::new(b"abc".to_vec()).unwrap().encode();
        wire.push(0);
        assert_eq!(
            code_of(Frame::decode(&wire)),
            PluginErrorCode::InvalidArgument
        );
    }

    #[test]
    fn plug2_frame_debug_omits_payload() {
        let f = Frame::new(b"secret-token-value".to_vec()).unwrap();
        let s = format!("{f:?}");
        assert!(!s.contains("secret"));
        assert!(s.contains("payload_len: 18"));
    }
}
