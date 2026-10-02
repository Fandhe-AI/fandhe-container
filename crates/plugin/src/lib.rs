//! fandhe-container-plugin: plugin 境界機構（UDS・長さ接頭辞フレーム・gRPC・常駐/都度起動・信頼性検証）。
//!
//! 現状はエラー型（`error`。TASK-107.1・#244）と UDS listener（`transport`。TASK-107.4・#248）のみ
//! 実装済み。フレーム・シリアライズ・client 接続・タイムアウト・gRPC・PLUG-12 の保護（権限・peer 認証。
//! TASK-123・TASK-124）は未実装（#245・#247・#249〜#251・TASK-108 ほか。REPAIR-3）。
//! 本体は G8（TASK-107 が crate 本体、TASK-108 が gRPC〔tonic〕境界、TASK-110・TASK-113・TASK-122〜124）で
//! 実装する。plugin 発見・登録（TASK-109）の成果物は `fandhe-container-core` 側に置かれ、本 crate ではない。
//! PLUG-1 区分は core・plugin 双方が依存する境界基盤ライブラリ（crate-naming.md 決定 4）。

pub mod error;
pub mod transport;

pub use error::{PLUGIN_ERROR_MESSAGE_MAX_BYTES, PluginError, PluginErrorCode};
pub use transport::{UDS_ACCEPT_TIMEOUT_MAX, UdsListener, UdsStream};
