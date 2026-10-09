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

use std::io::Read;
use std::path::Path;

use super::super::{CommandType, WireReader, parse_command_header};
use super::error::VenusReplayError;
use super::format::{
    FILE_HEADER_LEN, MAX_RECORDING_LEN, RECORD_CHECKSUM_LEN, RECORD_HEADER_LEN, RecordView,
    RecordingHeader, decode_record,
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
    // 件数はヘッダ復号で上限（65536）検証済みだが、本体が空でも過大に確保しないよう、
    // 1 レコードの最小長（16 バイト）で残りバイト数に照らして頭打ちにする。
    let mut records = Vec::with_capacity(record_capacity_budget(
        header.record_count,
        bytes.len().saturating_sub(FILE_HEADER_LEN),
    ));
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

/// 件数による `Vec` 確保の予算: `min(件数, 残りバイト / 1 レコードの最小長)`。
/// 最小長はレコードヘッダ + チェックサム（空ペイロード）の 16 バイト。
pub(crate) fn record_capacity_budget(record_count: u32, remaining_bytes: usize) -> usize {
    let by_count = usize::try_from(record_count).unwrap_or(usize::MAX);
    by_count.min(remaining_bytes / (RECORD_HEADER_LEN + RECORD_CHECKSUM_LEN))
}

/// `declared_len`（stat 等で得た宣言長）を上限検証してから `reader` を読み切る。
/// 宣言後に伸びた入力にも備え、上限 + 1 バイトで読み込みを打ち切る。
pub(crate) fn read_bounded<R: Read>(
    reader: R,
    declared_len: u64,
) -> Result<Vec<u8>, VenusReplayError> {
    read_bounded_with_limit(reader, declared_len, MAX_RECORDING_LEN)
}

/// [`read_bounded`] の上限を引数にした本体（テストで小さな上限を使うため分離）。
pub(crate) fn read_bounded_with_limit<R: Read>(
    reader: R,
    declared_len: u64,
    max: u64,
) -> Result<Vec<u8>, VenusReplayError> {
    let too_large = |requested| VenusReplayError::RecordingTooLarge { requested, max };
    if declared_len > max {
        return Err(too_large(declared_len));
    }
    let mut buf = Vec::with_capacity(usize::try_from(declared_len).unwrap_or(0));
    reader
        .take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| VenusReplayError::Io { kind: e.kind() })?;
    let got = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    if got > max {
        return Err(too_large(got));
    }
    Ok(buf)
}

/// 記録ファイルを上限つきで読む（2 段目の入口。続けて [`validate`] に渡す）。
///
/// 開く前に `symlink_metadata` で通常ファイルであることを確かめ（FIFO の open は書き手が現れるまで
/// ブロックするため）、開いた後も fd の `metadata` で再確認し、長さを読み込み前に検証する。
/// 残存リスク: 検査から open までの間に FIFO や symlink へ差し替えられると open がブロックしたり
/// symlink の先を読んだりしうる（`O_NOFOLLOW | O_NONBLOCK` の `sys` ラッパーは未導入。TOCTOU を
/// 塞いだとは主張しない）。運用者が自分で指定したパスを読む PoC の道具としての前提。
pub fn read_recording_file(path: &Path) -> Result<Vec<u8>, VenusReplayError> {
    let io = |e: std::io::Error| VenusReplayError::Io { kind: e.kind() };
    let before = std::fs::symlink_metadata(path).map_err(io)?;
    if !before.file_type().is_file() {
        return Err(VenusReplayError::NotRegularFile);
    }
    let file = std::fs::File::open(path).map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() {
        return Err(VenusReplayError::NotRegularFile);
    }
    read_bounded(file, meta.len())
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
