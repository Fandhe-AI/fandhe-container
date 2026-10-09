//! 受理した `SUBMIT_3D` の本体を記録ファイルへ溜める記録器（GPU-6・REPAIR-2・REPAIR-12・TASK-172 F6・#1602）。
//!
//! 役割: 治具が受理してゲストへ ACK を返した提出 1 回を、`fandhe_container_plugin_macos::gpu::venus::replay::RecordingWriter`
//! （FCVNSREC 形式。設計書 7 章）の 1 レコードにする。呼び出し元は `launch`（`--record` 指定時に `session` の提出フック経由で
//! [`SubmitRecorder::on_submit`] を呼び、終了時に [`SubmitRecorder::finish`] する。Linux 限定）と結合試験。本モジュール自体は
//! ファイルに触れず、3 OS でビルドされる。ファイルの作成（`create_new` + `0600`）は `launch` が担う。
//!
//! なぜ治具側にラッパーがあるか: `RecordingWriter` の上限（1 レコード 16 MiB・65,536 件・全体 256 MiB）は製品 crate の定数で、
//! 差し替えられない。製品 crate をテストのために変えないため、上限を注入できるこのラッパーで先に検査する。既定の
//! [`RecorderLimits`] では `RecordingWriter` 側の検査と一致する。
//!
//! 挙動: 上限に達したら記録だけを止める（以降の提出は小さくても記録しない）。セッションは続き、停止は [`RecordOutcome::Stopped`]
//! を 1 回だけ返す。記録の失敗を成功と装わない（[`SubmitRecorder::finish`] は書き出しの `Result` と集計を返す）。
//!
//! メモリ: `RecordingWriter` は本体をメモリに溜めてから `finish` で書くため、ホストのメモリは最大
//! [`RecorderLimits::max_total_len`]（既定 256 MiB）＋ヘッダまで増えうる。治具の `SUBMIT_3D` 本体は
//! `ctrl::MAX_SUBMIT_3D_PAYLOAD_LEN`（4064 バイト）が上限なので 1 件の上限（`payload_too_large`）には実運用で達せず、
//! 65,536 件 × (4064 + 16) は 256 MiB を超えるため `recording_too_large` が `too_many_records` より先に効きうる。
//!
//! 記録しないもの（未実装。REPAIR-3）: 共有メモリ上のリングの中身（F5.2b の後。設計書 10.4.5）、reply、期待出力。
//! 本体が空の提出（`size=0`）も 1 レコードにする。`validate` は空ペイロードを通すが、`replay` の段で拒否されうる。
//! 書き出しに失敗したファイルはヘッダの件数と本体が合わず、`validate` が `truncated` 等で拒否する。

use std::io::Write;

use fandhe_container_plugin_macos::gpu::venus::replay::{
    FILE_HEADER_LEN, MAX_RECORD_COUNT, MAX_RECORD_PAYLOAD_LEN, MAX_RECORDING_LEN,
    RECORD_CHECKSUM_LEN, RECORD_HEADER_LEN, RecordingWriter, VenusReplayError,
};

use crate::adapter::Submit3d;
use crate::log;

/// 記録の上限。各値は 0 より大きく、`replay` 形式の定数（16 MiB・65,536 件・256 MiB）以下。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecorderLimits {
    max_record_len: u32,
    max_records: u32,
    max_total_len: u64,
}

impl Default for RecorderLimits {
    fn default() -> Self {
        Self {
            max_record_len: MAX_RECORD_PAYLOAD_LEN,
            max_records: MAX_RECORD_COUNT,
            max_total_len: MAX_RECORDING_LEN,
        }
    }
}

impl RecorderLimits {
    /// 範囲外（0・形式の定数超え・`max_total_len` がファイルヘッダ長未満）は `None`。
    /// 提出ゼロでも `finish` はヘッダを書くため、全体長の上限はヘッダ長以上でなければ約束を守れない。
    pub fn new(max_record_len: u32, max_records: u32, max_total_len: u64) -> Option<Self> {
        let ok = max_record_len > 0
            && max_record_len <= MAX_RECORD_PAYLOAD_LEN
            && max_records > 0
            && max_records <= MAX_RECORD_COUNT
            && max_total_len >= FILE_HEADER_LEN as u64
            && max_total_len <= MAX_RECORDING_LEN;
        ok.then_some(Self {
            max_record_len,
            max_records,
            max_total_len,
        })
    }

    /// 1 レコードの本体長の上限。
    pub fn max_record_len(&self) -> u32 {
        self.max_record_len
    }
    /// レコード件数の上限。
    pub fn max_records(&self) -> u32 {
        self.max_records
    }
    /// ファイル全体長の上限（ファイルヘッダを含む）。
    pub fn max_total_len(&self) -> u64 {
        self.max_total_len
    }
}

/// 記録を止めた理由（固定語彙。ログと集計行に出す）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// 1 レコードの本体が上限を超えた。
    PayloadTooLarge,
    /// 件数が上限に達した。
    TooManyRecords,
    /// 全体長が上限を超える。
    RecordingTooLarge,
    /// `RecordingWriter` が上の 3 つ以外の理由で追記を拒否した。
    WriterRejected,
}

impl StopReason {
    /// ログに出す固定語彙。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PayloadTooLarge => "payload_too_large",
            Self::TooManyRecords => "too_many_records",
            Self::RecordingTooLarge => "recording_too_large",
            Self::WriterRejected => "writer_rejected",
        }
    }

    fn from_error(e: &VenusReplayError) -> Self {
        match e {
            VenusReplayError::PayloadTooLarge { .. } => Self::PayloadTooLarge,
            VenusReplayError::TooManyRecords { .. } => Self::TooManyRecords,
            VenusReplayError::RecordingTooLarge { .. } => Self::RecordingTooLarge,
            _ => Self::WriterRejected,
        }
    }
}

/// [`SubmitRecorder::record`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// 1 レコードとして追記した。
    Recorded,
    /// 今回の提出で上限に達して止めた（記録は追記していない）。停止ごとに 1 回だけ返る。
    Stopped(StopReason),
    /// 停止済みのため捨てた。
    Skipped,
}

/// 終了時の集計。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordSummary {
    /// 記録した件数。
    pub records: u32,
    /// 停止後に捨てた提出の件数。
    pub skipped: u64,
    /// 停止した理由（止まらなければ `None`）。
    pub stopped: Option<StopReason>,
}

/// `SUBMIT_3D` の本体を上限つきで `RecordingWriter` へ追記する記録器。
#[derive(Debug)]
pub struct SubmitRecorder<W: Write> {
    writer: RecordingWriter<W>,
    limits: RecorderLimits,
    records: u32,
    total_len: u64,
    skipped: u64,
    stopped: Option<StopReason>,
}

impl<W: Write> SubmitRecorder<W> {
    /// `out` へは [`Self::finish`] まで何も書かない。
    pub fn new(out: W, limits: RecorderLimits) -> Self {
        Self {
            writer: RecordingWriter::new(out),
            limits,
            records: 0,
            total_len: FILE_HEADER_LEN as u64,
            skipped: 0,
            stopped: None,
        }
    }

    /// 本体 1 個を記録する。上限は確保の前に checked 演算で検査する。
    pub fn record(&mut self, payload: &[u8]) -> RecordOutcome {
        if self.stopped.is_some() {
            self.skipped = self.skipped.saturating_add(1);
            return RecordOutcome::Skipped;
        }
        let len = u64::try_from(payload.len()).unwrap_or(u64::MAX);
        if len > u64::from(self.limits.max_record_len) {
            return self.stop(StopReason::PayloadTooLarge);
        }
        if self.records >= self.limits.max_records {
            return self.stop(StopReason::TooManyRecords);
        }
        let framing = (RECORD_HEADER_LEN + RECORD_CHECKSUM_LEN) as u64;
        let total = self
            .total_len
            .checked_add(framing)
            .and_then(|t| t.checked_add(len));
        let Some(total) = total.filter(|t| *t <= self.limits.max_total_len) else {
            return self.stop(StopReason::RecordingTooLarge);
        };
        match self.writer.append(payload) {
            Ok(()) => {
                self.records += 1;
                self.total_len = total;
                RecordOutcome::Recorded
            }
            Err(e) => self.stop(StopReason::from_error(&e)),
        }
    }

    /// `session` の提出フック用。記録し、今回停止したときだけ `record_stopped` のログ行を返す。
    pub fn on_submit(&mut self, submit: &Submit3d) -> Option<String> {
        match self.record(&submit.payload) {
            RecordOutcome::Stopped(reason) => Some(log::record_stopped_line(reason, self.records)),
            RecordOutcome::Recorded | RecordOutcome::Skipped => None,
        }
    }

    /// それまでに記録した分を書き出す。書き出しの `Result` は集計と別に返し、失敗を成功と装わない。
    pub fn finish(self) -> (Result<W, VenusReplayError>, RecordSummary) {
        let summary = RecordSummary {
            records: self.records,
            skipped: self.skipped,
            stopped: self.stopped,
        };
        (self.writer.finish(), summary)
    }

    fn stop(&mut self, reason: StopReason) -> RecordOutcome {
        self.stopped = Some(reason);
        RecordOutcome::Stopped(reason)
    }
}

#[cfg(test)]
mod tests;
