//! 記録の検証と再生ハーネス（GPU-6・TASK-172.5）。
//!
//! 2 段目（Apple Silicon Mac。VMM なし）が記録ファイルを自前デコーダへ流し込むための入口。
//! [`validate`] が全レコードのチェックサムまで走査して [`ValidatedRecording`] を作り、[`replay`] は
//! その型しか受け取らない（再生前の完全性検証を型で強制。REPAIR-2）。再生は全レコード先頭の
//! コマンドヘッダ（`parse_command_header`）を先に検査し、1 件でも不正なら 1 件も提出しない。
//!
//! 未実装（REPAIR-3）: コマンド引数のパースと Vulkan ディスパッチ（TASK-177.x）。lavapipe /
//! MoltenVK で compute を実行して記録時の結果と照合する実行バックエンドは [`ReplayBackend`] の
//! 差し替え点のみで、Vulkan バインディング方式の承認待ち。[`CollectingBackend`] は提出内容を
//! 保持する模擬で、実行はしない。

use super::super::{CommandType, WireReader, parse_command_header};
use super::error::VenusReplayError;
use super::format::{
    FILE_HEADER_LEN, MAX_RECORDING_LEN, RecordView, RecordingHeader, decode_record,
};

/// 検証済みの記録。[`validate`] からのみ作れる。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRecording<'a> {
    records: Vec<RecordView<'a>>,
}

impl<'a> ValidatedRecording<'a> {
    pub fn records(&self) -> &[RecordView<'a>] {
        &self.records
    }
}

/// 記録ファイルのバイト列を最後まで検証する（再生に入る前の完全性検査）。
pub fn validate(bytes: &[u8]) -> Result<ValidatedRecording<'_>, VenusReplayError> {
    let total = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if total > MAX_RECORDING_LEN {
        return Err(VenusReplayError::RecordingTooLarge {
            requested: total,
            max: MAX_RECORDING_LEN,
        });
    }
    let header = RecordingHeader::decode(bytes)?;
    // 件数はヘッダ復号で上限（65536）検証済みなので確保してよい。
    let mut records = Vec::with_capacity(usize::try_from(header.record_count).unwrap_or(0));
    let mut at = FILE_HEADER_LEN;
    for seqno in 0..header.record_count {
        let (rec, next) = decode_record(bytes, at, seqno)?;
        records.push(rec);
        at = next;
    }
    let extra = bytes.len().saturating_sub(at);
    if extra != 0 {
        return Err(VenusReplayError::TrailingBytes { extra });
    }
    Ok(ValidatedRecording { records })
}

/// 再生先。将来の lavapipe / MoltenVK 実行バックエンドの差し替え点（未実装。TASK-177.x）。
pub trait ReplayBackend {
    /// 記録された提出バッファ 1 個を渡す。
    fn submit(&mut self, seqno: u32, stream: &[u8]) -> Result<(), VenusReplayError>;
}

/// 再生結果の要約。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaySummary {
    pub records: usize,
    pub total_bytes: u64,
    /// 各レコード先頭のコマンド種別（記録順）。
    pub first_commands: Vec<CommandType>,
}

/// 検証済みの記録を順に再生する。先に全レコードの先頭ヘッダを検査し、不正なら何も提出しない。
pub fn replay<B: ReplayBackend>(
    rec: &ValidatedRecording<'_>,
    backend: &mut B,
) -> Result<ReplaySummary, VenusReplayError> {
    let mut first_commands = Vec::with_capacity(rec.records.len());
    let mut total_bytes = 0u64;
    for r in &rec.records {
        let mut rd = WireReader::new(r.payload);
        let h = parse_command_header(&mut rd).map_err(|source| VenusReplayError::Wire {
            seqno: r.header.seqno,
            source,
        })?;
        first_commands.push(h.command);
        total_bytes = total_bytes.saturating_add(u64::from(r.header.payload_len));
    }
    for r in &rec.records {
        backend.submit(r.header.seqno, r.payload)?;
    }
    Ok(ReplaySummary {
        records: rec.records.len(),
        total_bytes,
        first_commands,
    })
}

/// 提出内容を保持するだけの模擬バックエンド（テストと 2 段目の差分確認用）。
#[derive(Debug, Default)]
pub struct CollectingBackend {
    pub submitted: Vec<(u32, Vec<u8>)>,
}

impl ReplayBackend for CollectingBackend {
    fn submit(&mut self, seqno: u32, stream: &[u8]) -> Result<(), VenusReplayError> {
        self.submitted.push((seqno, stream.to_vec()));
        Ok(())
    }
}
