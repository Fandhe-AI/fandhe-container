//! fandhe-container-plugin: plugin 境界機構（UDS・長さ接頭辞フレーム・gRPC・常駐/都度起動・信頼性検証）。
//!
//! 現状はエラー型（`error`。TASK-107.1・#244）と長さ接頭辞フレームのヘッダ・チェックサム型
//! （`frame`。TASK-107.2・#245）のみ実装済み。ペイロード（serde_json）・transport・UDS・
//! タイムアウト・gRPC は未実装（#247〜#251・TASK-108 ほか。REPAIR-3）。
//! 本体は G8（TASK-107 が crate 本体、TASK-108 が gRPC〔tonic〕境界、TASK-110・TASK-113・TASK-122〜124）で
//! 実装する。plugin 発見・登録（TASK-109）の成果物は `fandhe-container-core` 側に置かれ、本 crate ではない。
//! PLUG-1 区分は core・plugin 双方が依存する境界基盤ライブラリ（crate-naming.md 決定 4）。

pub(crate) mod checksum;
pub mod error;
pub mod frame;

pub use error::{PLUGIN_ERROR_MESSAGE_MAX_BYTES, PluginError, PluginErrorCode};
pub use frame::{
    CHECKSUM_LEN, FRAME_HEADER_LEN, Frame, FrameChecksum, FrameHeader, MAX_FRAME_LEN,
    MAX_PAYLOAD_LEN, PROTOCOL_VERSION, PayloadLen,
};
