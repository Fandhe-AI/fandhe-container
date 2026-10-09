//! venus コマンドストリームの記録と再生ハーネス（GPU-6・TASK-172.5・#889。REPAIR-2）。
//!
//! 1 段目（GPU 付き Linux 実機＋治具 VMM）でゲストの Mesa venus が提出したバッファを
//! [`RecordingWriter`] で保存し、2 段目（Apple Silicon Mac）で [`validate`]→[`replay`] により VMM なしに
//! 自前デコーダ（親モジュールの `parse_command_header`）へ流し込む。壊れたファイルは再生前に
//! 検出する（ヘッダ・長さ接頭辞・CRC-32C。CRC は偶発的破損の検出で改ざん耐性はない）。
//!
//! 2 段目の呼び出し順は [`read_recording_file`]（通常ファイルのみ・上限つき読み込み）→ [`validate`] →
//! [`replay`]。`validate` は受け取り済みの `&[u8]` を検査するだけで、確保前の長さ検証は
//! `read_recording_file` が担う。
//!
//! 記録単位は「提出バッファ 1 個」。venus wire はコマンド長を持たず引数パーサ無しには境界を切れ
//! ないため、長さはレコード側で持つ。配置は issue 記載の `poc/` ではなく既存骨格の隣（理由は
//! `docs/design/venus-decoder-poc.md`）。
//!
//! 未実装（REPAIR-3）: lavapipe / MoltenVK での compute 実行と結果照合（受け入れ条件 2。Vulkan
//! バインディング方式の承認と TASK-177.x のディスパッチが前提）、reply・期待出力レコード、
//! 実機側の記録フック（#888・#725）。

mod checksum;
mod error;
mod format;
mod player;
mod recorder;

pub use error::VenusReplayError;
pub use format::{
    FILE_HEADER_LEN, FORMAT_VERSION, MAGIC, MAX_RECORD_COUNT, MAX_RECORD_PAYLOAD_LEN,
    MAX_RECORDING_LEN, RECORD_CHECKSUM_LEN, RECORD_HEADER_LEN, RecordHeader, RecordKind,
    RecordView, RecordingHeader,
};
pub use player::{
    CollectingBackend, ReplayBackend, ReplaySummary, ValidatedRecording, read_recording_file,
    replay, validate,
};
pub use recorder::RecordingWriter;

#[cfg(test)]
mod tests;
