//! 記録ファイルの構造化エラー（GPU-6・TASK-172.5・REPAIR-2・ERR-1）。
//!
//! 記録・検証・再生の各段階（[`super::RecordingWriter`]・[`super::validate`]・[`super::replay`]）が返す。
//! 記録ファイルは別マシンから持ち込まれる untrusted 入力のため、ファイル内容のバイト列はメッセージへ
//! 埋め込まず数値のみを出す。`code()` は機械可読な `venus_replay.*`、`message()` は英語。

use std::fmt;

use super::super::VenusWireError;

/// 記録・検証・再生の失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VenusReplayError {
    /// 入力が途中で尽きた。
    Truncated { needed: usize, remaining: usize },
    /// マジック不一致（記録ファイルではない）。
    BadMagic,
    /// 未知のフォーマット版数。
    UnsupportedVersion { raw: u16 },
    /// 定義外の flags。
    InvalidFlags { raw: u16 },
    /// 予約バイトが 0 でない。
    ReservedNonZero,
    /// 未対応のレコード種別。
    UnknownKind { raw: u8 },
    /// seqno が 0 起点の連番でない。
    SequenceMismatch { expected: u32, actual: u32 },
    /// ペイロード長が上限超過。
    PayloadTooLarge { requested: u64, max: u64 },
    /// レコード件数が上限超過。
    TooManyRecords { requested: u64, max: u64 },
    /// ファイル全体長が上限超過。
    RecordingTooLarge { requested: u64, max: u64 },
    /// ヘッダのチェックサム不一致。
    HeaderChecksum { expected: u32, actual: u32 },
    /// レコードのチェックサム不一致。
    RecordChecksum {
        seqno: u32,
        expected: u32,
        actual: u32,
    },
    /// 宣言件数を読み終えた後に余剰バイトがある。
    TrailingBytes { extra: usize },
    /// 再生対象レコードの先頭が venus コマンドとして不正。
    Wire { seqno: u32, source: VenusWireError },
    /// 再生バックエンドが提出を拒否した。
    Backend { seqno: u32 },
    /// 読み込み先のパスが通常ファイルでない（symlink・ディレクトリ・FIFO・デバイス）。
    NotRegularFile,
    /// 書き出し・読み込みの I/O 失敗。
    Io { kind: std::io::ErrorKind },
}

impl VenusReplayError {
    /// 機械可読なエラーコード（`venus_replay.*`）。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Truncated { .. } => "venus_replay.truncated",
            Self::BadMagic => "venus_replay.bad_magic",
            Self::UnsupportedVersion { .. } => "venus_replay.unsupported_version",
            Self::InvalidFlags { .. } => "venus_replay.invalid_flags",
            Self::ReservedNonZero => "venus_replay.reserved_nonzero",
            Self::UnknownKind { .. } => "venus_replay.unknown_kind",
            Self::SequenceMismatch { .. } => "venus_replay.sequence_mismatch",
            Self::PayloadTooLarge { .. } => "venus_replay.payload_too_large",
            Self::TooManyRecords { .. } => "venus_replay.too_many_records",
            Self::RecordingTooLarge { .. } => "venus_replay.recording_too_large",
            Self::HeaderChecksum { .. } => "venus_replay.header_checksum",
            Self::RecordChecksum { .. } => "venus_replay.record_checksum",
            Self::TrailingBytes { .. } => "venus_replay.trailing_bytes",
            Self::Wire { .. } => "venus_replay.wire",
            Self::Backend { .. } => "venus_replay.backend",
            Self::NotRegularFile => "venus_replay.not_regular_file",
            Self::Io { .. } => "venus_replay.io",
        }
    }

    /// 人間可読の英語メッセージ（入力バイト列は含めない）。
    pub fn message(&self) -> String {
        match self {
            Self::Truncated { needed, remaining } => {
                format!("recording truncated: need {needed} bytes, {remaining} remaining")
            }
            Self::BadMagic => "recording magic mismatch".to_string(),
            Self::UnsupportedVersion { raw } => format!("unsupported recording version {raw}"),
            Self::InvalidFlags { raw } => format!("undefined recording flags set: {raw:#x}"),
            Self::ReservedNonZero => "reserved bytes are not zero".to_string(),
            Self::UnknownKind { raw } => format!("unknown record kind {raw}"),
            Self::SequenceMismatch { expected, actual } => {
                format!("record seqno {actual} where {expected} expected")
            }
            Self::PayloadTooLarge { requested, max } => {
                format!("payload length {requested} exceeds limit {max}")
            }
            Self::TooManyRecords { requested, max } => {
                format!("record count {requested} exceeds limit {max}")
            }
            Self::RecordingTooLarge { requested, max } => {
                format!("recording length {requested} exceeds limit {max}")
            }
            Self::HeaderChecksum { expected, actual } => {
                format!("header checksum mismatch: expected {expected:#010x}, got {actual:#010x}")
            }
            Self::RecordChecksum {
                seqno,
                expected,
                actual,
            } => format!(
                "record {seqno} checksum mismatch: expected {expected:#010x}, got {actual:#010x}"
            ),
            Self::TrailingBytes { extra } => format!("{extra} trailing bytes after last record"),
            Self::Wire { seqno, source } => {
                format!(
                    "record {seqno} is not a valid venus command: {}",
                    source.message()
                )
            }
            Self::Backend { seqno } => format!("replay backend rejected record {seqno}"),
            Self::NotRegularFile => "recording is not a regular file".to_string(),
            Self::Io { kind } => format!("i/o error: {kind}"),
        }
    }
}

impl fmt::Display for VenusReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for VenusReplayError {}
