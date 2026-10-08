//! コマンドストリームの記録器（GPU-6・TASK-172.5）。
//!
//! 1 段目（GPU 付き Linux 実機＋治具 VMM。#725）がゲストの提出バッファごとに [`RecordingWriter::append`]
//! を呼び、[`RecordingWriter::finish`] で記録ファイルとして書き出す。ヘッダに件数を持つため本体は
//! メモリ上に溜める（ファイル全体長の上限つき）。実機側の記録フック配線は #888・#725（未実装）。
//! ワークロード由来のデータを含みうるため、実ストリームはリポジトリにコミットしない。

use std::io::Write;

use super::error::VenusReplayError;
use super::format::{
    FILE_HEADER_LEN, MAX_RECORD_COUNT, MAX_RECORD_PAYLOAD_LEN, MAX_RECORDING_LEN,
    RECORD_CHECKSUM_LEN, RECORD_HEADER_LEN, RecordHeader, RecordKind, RecordingHeader,
};

/// 記録ファイルの書き出し器。
#[derive(Debug)]
pub struct RecordingWriter<W: Write> {
    out: W,
    body: Vec<u8>,
    count: u32,
}

impl<W: Write> RecordingWriter<W> {
    pub fn new(out: W) -> Self {
        Self {
            out,
            body: Vec::new(),
            count: 0,
        }
    }

    /// ゲストの提出バッファ 1 個を追記する。長さ・件数・全体長の上限を確保前に検証する。
    pub fn append(&mut self, stream: &[u8]) -> Result<(), VenusReplayError> {
        let len = u64::try_from(stream.len()).unwrap_or(u64::MAX);
        let too_large = VenusReplayError::PayloadTooLarge {
            requested: len,
            max: u64::from(MAX_RECORD_PAYLOAD_LEN),
        };
        if len > u64::from(MAX_RECORD_PAYLOAD_LEN) {
            return Err(too_large);
        }
        if self.count >= MAX_RECORD_COUNT {
            return Err(VenusReplayError::TooManyRecords {
                requested: u64::from(self.count) + 1,
                max: u64::from(MAX_RECORD_COUNT),
            });
        }
        let record_len = (RECORD_HEADER_LEN + RECORD_CHECKSUM_LEN) as u64 + len;
        let total = (FILE_HEADER_LEN as u64)
            .saturating_add(self.body.len() as u64)
            .saturating_add(record_len);
        if total > MAX_RECORDING_LEN {
            return Err(VenusReplayError::RecordingTooLarge {
                requested: total,
                max: MAX_RECORDING_LEN,
            });
        }
        let header = RecordHeader {
            kind: RecordKind::GuestCommandStream,
            seqno: self.count,
            payload_len: u32::try_from(stream.len()).map_err(|_| too_large)?,
        };
        self.body.extend_from_slice(&header.encode());
        self.body.extend_from_slice(stream);
        self.body
            .extend_from_slice(&header.checksum(stream).to_le_bytes());
        self.count += 1;
        Ok(())
    }

    /// ヘッダと全レコードを書き出して書き出し先を返す。
    pub fn finish(mut self) -> Result<W, VenusReplayError> {
        let header = RecordingHeader {
            record_count: self.count,
        };
        let io = |e: std::io::Error| VenusReplayError::Io { kind: e.kind() };
        self.out.write_all(&header.encode()).map_err(io)?;
        self.out.write_all(&self.body).map_err(io)?;
        self.out.flush().map_err(io)?;
        Ok(self.out)
    }
}
