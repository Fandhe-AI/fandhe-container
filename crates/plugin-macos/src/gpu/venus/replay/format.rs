//! 記録ファイルのバイナリ形式（GPU-6・TASK-172.5・REPAIR-2）。
//!
//! 全フィールドリトルエンディアン。固定長ヘッダ（[`RecordingHeader`]）と、長さ接頭辞・チェック
//! サムつきのレコード（[`RecordHeader`]＋ペイロード＋CRC-32C）の繰り返し。符号化・復号はこの型経由に
//! 限り、呼び出し側が生の `Vec<u8>` を手で組まない。上限は確保の前に検証する。
//! 形式の表は `docs/design/venus-decoder-poc.md` を参照。

use super::checksum::crc32c;
use super::error::VenusReplayError;

/// ファイル先頭の識別子。
pub const MAGIC: [u8; 8] = *b"FCVNSREC";
/// 現行のフォーマット版数。
pub const FORMAT_VERSION: u16 = 1;
/// ファイルヘッダ長（バイト）。
pub const FILE_HEADER_LEN: usize = 20;
/// レコードヘッダ長（バイト）。
pub const RECORD_HEADER_LEN: usize = 12;
/// レコード末尾のチェックサム長（バイト）。
pub const RECORD_CHECKSUM_LEN: usize = 4;
/// 1 レコードのペイロード長上限（16 MiB）。
pub const MAX_RECORD_PAYLOAD_LEN: u32 = 16 * 1024 * 1024;
/// レコード件数の上限。
pub const MAX_RECORD_COUNT: u32 = 65_536;
/// ファイル全体長の上限（256 MiB）。
pub const MAX_RECORDING_LEN: u64 = 256 * 1024 * 1024;

/// レコード種別。ホスト→ゲスト reply・期待出力は番号を予約するのみで未対応（REPAIR-3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    /// ゲストが 1 回に提出したコマンドストリームのバッファ。
    GuestCommandStream = 1,
}

impl RecordKind {
    fn from_raw(raw: u8) -> Result<Self, VenusReplayError> {
        match raw {
            1 => Ok(Self::GuestCommandStream),
            _ => Err(VenusReplayError::UnknownKind { raw }),
        }
    }
}

fn take(buf: &[u8], at: usize, n: usize) -> Result<&[u8], VenusReplayError> {
    let err = VenusReplayError::Truncated {
        needed: n,
        remaining: buf.len().saturating_sub(at),
    };
    let end = at.checked_add(n).ok_or(err)?;
    buf.get(at..end).ok_or(err)
}

fn le_u16(s: &[u8]) -> Result<u16, VenusReplayError> {
    let a: [u8; 2] = s.try_into().map_err(|_| VenusReplayError::Truncated {
        needed: 2,
        remaining: s.len(),
    })?;
    Ok(u16::from_le_bytes(a))
}

fn le_u32(s: &[u8]) -> Result<u32, VenusReplayError> {
    let a: [u8; 4] = s.try_into().map_err(|_| VenusReplayError::Truncated {
        needed: 4,
        remaining: s.len(),
    })?;
    Ok(u32::from_le_bytes(a))
}

/// ファイルヘッダ（20 バイト固定長）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordingHeader {
    pub record_count: u32,
}

impl RecordingHeader {
    /// 固定長へ符号化する（チェックサム付き）。
    pub fn encode(&self) -> [u8; FILE_HEADER_LEN] {
        let mut out = [0u8; FILE_HEADER_LEN];
        let (head, crc_slot) = out.split_at_mut(16);
        let (magic, rest) = head.split_at_mut(8);
        magic.copy_from_slice(&MAGIC);
        let (ver, rest) = rest.split_at_mut(2);
        ver.copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        let (flags, count) = rest.split_at_mut(2);
        flags.copy_from_slice(&0u16.to_le_bytes());
        count.copy_from_slice(&self.record_count.to_le_bytes());
        let crc = crc32c(&[head]);
        crc_slot.copy_from_slice(&crc.to_le_bytes());
        out
    }

    /// 先頭から復号する。magic・版数・flags・チェックサム・件数上限を検証する。
    pub fn decode(buf: &[u8]) -> Result<Self, VenusReplayError> {
        let raw = take(buf, 0, FILE_HEADER_LEN)?;
        if take(raw, 0, 8)? != MAGIC {
            return Err(VenusReplayError::BadMagic);
        }
        let version = le_u16(take(raw, 8, 2)?)?;
        if version != FORMAT_VERSION {
            return Err(VenusReplayError::UnsupportedVersion { raw: version });
        }
        let flags = le_u16(take(raw, 10, 2)?)?;
        if flags != 0 {
            return Err(VenusReplayError::InvalidFlags { raw: flags });
        }
        let expected = le_u32(take(raw, 16, 4)?)?;
        let actual = crc32c(&[take(raw, 0, 16)?]);
        if expected != actual {
            return Err(VenusReplayError::HeaderChecksum { expected, actual });
        }
        let record_count = le_u32(take(raw, 12, 4)?)?;
        if record_count > MAX_RECORD_COUNT {
            return Err(VenusReplayError::TooManyRecords {
                requested: u64::from(record_count),
                max: u64::from(MAX_RECORD_COUNT),
            });
        }
        Ok(Self { record_count })
    }
}

/// レコードヘッダ（12 バイト固定長）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub kind: RecordKind,
    pub seqno: u32,
    pub payload_len: u32,
}

impl RecordHeader {
    pub fn encode(&self) -> [u8; RECORD_HEADER_LEN] {
        let mut out = [0u8; RECORD_HEADER_LEN];
        let (k, rest) = out.split_at_mut(4);
        if let Some(b) = k.first_mut() {
            *b = self.kind as u8;
        }
        let (seq, len) = rest.split_at_mut(4);
        seq.copy_from_slice(&self.seqno.to_le_bytes());
        len.copy_from_slice(&self.payload_len.to_le_bytes());
        out
    }

    /// `buf` の `at` から復号する。予約バイト・kind・ペイロード長上限を検証する。
    pub fn decode(buf: &[u8], at: usize) -> Result<Self, VenusReplayError> {
        let raw = take(buf, at, RECORD_HEADER_LEN)?;
        let kind_byte = take(raw, 0, 1)?.first().copied().unwrap_or(0);
        let kind = RecordKind::from_raw(kind_byte)?;
        if take(raw, 1, 3)?.iter().any(|&b| b != 0) {
            return Err(VenusReplayError::ReservedNonZero);
        }
        let seqno = le_u32(take(raw, 4, 4)?)?;
        let payload_len = le_u32(take(raw, 8, 4)?)?;
        if payload_len > MAX_RECORD_PAYLOAD_LEN {
            return Err(VenusReplayError::PayloadTooLarge {
                requested: u64::from(payload_len),
                max: u64::from(MAX_RECORD_PAYLOAD_LEN),
            });
        }
        Ok(Self {
            kind,
            seqno,
            payload_len,
        })
    }

    /// ヘッダ＋ペイロードの CRC-32C。
    pub fn checksum(&self, payload: &[u8]) -> u32 {
        crc32c(&[&self.encode(), payload])
    }
}

/// 復号・検証済みのレコード 1 件（ペイロードは入力の借用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordView<'a> {
    pub header: RecordHeader,
    pub payload: &'a [u8],
}

/// `at` のレコードを検証して返し、次レコードの位置を併せて返す。
pub(crate) fn decode_record(
    buf: &[u8],
    at: usize,
    expected_seqno: u32,
) -> Result<(RecordView<'_>, usize), VenusReplayError> {
    let header = RecordHeader::decode(buf, at)?;
    if header.seqno != expected_seqno {
        return Err(VenusReplayError::SequenceMismatch {
            expected: expected_seqno,
            actual: header.seqno,
        });
    }
    let body_at = at.saturating_add(RECORD_HEADER_LEN);
    let payload_len =
        usize::try_from(header.payload_len).map_err(|_| VenusReplayError::PayloadTooLarge {
            requested: u64::from(header.payload_len),
            max: u64::from(MAX_RECORD_PAYLOAD_LEN),
        })?;
    let payload = take(buf, body_at, payload_len)?;
    let crc_at = body_at.saturating_add(payload_len);
    let expected = le_u32(take(buf, crc_at, RECORD_CHECKSUM_LEN)?)?;
    let actual = header.checksum(payload);
    if expected != actual {
        return Err(VenusReplayError::RecordChecksum {
            seqno: header.seqno,
            expected,
            actual,
        });
    }
    Ok((
        RecordView { header, payload },
        crc_at.saturating_add(RECORD_CHECKSUM_LEN),
    ))
}
