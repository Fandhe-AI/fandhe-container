//! fandhe-container-plugin: plugin 境界機構（UDS・長さ接頭辞フレーム・gRPC・常駐/都度起動・信頼性検証）。
//!
//! 現状はエラー型（`error`。TASK-107.1・#244）、長さ接頭辞フレームのヘッダ・チェックサム型
//! （`frame`。TASK-107.2・#245）、制御メッセージの serde_json 符号化・復号（`message`。
//! TASK-107.3・#247）と UDS listener（`transport`。TASK-107.4・#248。配置検証・peer 認証・I/O 期限を含む）と UDS client 接続
//! （`UdsStream::connect`。TASK-107.5・#249）、フレーム単位の ACK/RPC 待機タイムアウト
//! （`RpcTimeout`・`UdsStream::read_frame` / `write_frame`。TASK-107.6・#250）と runtime directory の解決・作成・検証
//! （`uds_security`。TASK-123.1・#286。socket 名・`sun_path` 長の bind 前検証は TASK-123.3・#288）、
//! 既存 socket パスの lstat 検証・stale socket 再 bind（`uds_security`。TASK-123.2・#287）と
//! 都度起動モード（`lifecycle`。TASK-110.1・#258）と
//! OS 別 RSS サンプラー（`rss`。TASK-112.1・#265）と
//! XDG 未設定時のフォールバック（TASK-123.4・#289）と常駐モード（`lifecycle`。TASK-110.2・#259）のみ実装済み。
//! モード選択 API（`lifecycle`。TASK-110.3・#260）は実装済み。gRPC と
//! PLUG-12 の peer 認証（TASK-124）は Linux の SO_PEERCRED（`uds_security::verify_peer`。TASK-124.1・#292）と
//! macOS の `getpeereid` 経路（TASK-124.2・#293）が実装・検証済みで、
//! 別 UID 接続拒否の結合試験（TASK-124.4・#295。実機前提の 2 件は人間が実行）と peer 認証が最初の読み書きより前であることの照合テスト（TASK-124.6・#1389）も追加済みで、
//! 拒否した接続の監査イベント通知（`audit`。TASK-124.5・#1388・SEC-4）も実装済みで、永続的な監査ログへの配線は core 側 proxy（TASK-114）で未実装（Windows は WIN-1 により固有実装を持たない旨を `uds_security` に文書化済み。TASK-124.3・#294。TASK-108 ほか。REPAIR-3）。
//! 本体は G8（TASK-107 が crate 本体、TASK-108 が gRPC〔tonic〕境界、TASK-110・TASK-113・TASK-122〜124）で
//! 実装する。plugin 発見・登録（TASK-109）の成果物は `fandhe-container-core` 側に置かれ、本 crate ではない。
//! PLUG-1 区分は core・plugin 双方が依存する境界基盤ライブラリ（crate-naming.md 決定 4）。

pub mod audit;
pub(crate) mod checksum;
pub mod error;
pub mod frame;
pub mod lifecycle;
pub mod message;
pub mod rss;
#[cfg(unix)]
pub(crate) mod sys;
pub mod transport;
pub mod uds_security;

pub use audit::{
    JsonLinesPeerAuthObserver, MAX_PEER_AUTH_AUDIT_LOG_BUFFER_BYTES, PEER_AUTH_AUDIT_LOG_CAPACITY,
    PeerAuthObserver, PeerAuthOp, PeerAuthRejectReason, PeerAuthRejection,
};
pub use error::{PLUGIN_ERROR_MESSAGE_MAX_BYTES, PluginError, PluginErrorCode};
pub use frame::{
    CHECKSUM_LEN, FRAME_HEADER_LEN, Frame, FrameChecksum, FrameHeader, MAX_FRAME_LEN,
    MAX_PAYLOAD_LEN, PROTOCOL_VERSION, PayloadLen,
};
pub use lifecycle::{
    ONE_SHOT_ARGS_MAX_BYTES, ONE_SHOT_ARGS_MAX_COUNT, ONE_SHOT_EXIT_TIMEOUT, ONE_SHOT_REAP_TIMEOUT,
    ONE_SHOT_STDERR_DRAIN_TIMEOUT, ONE_SHOT_STDERR_MAX_BYTES, ONE_SHOT_STDERR_STOP_TIMEOUT,
    ONE_SHOT_TIMEOUT_DEFAULT, ONE_SHOT_TIMEOUT_MAX, OneShotOutcome, OneShotPlugin, OneShotRecord,
    OneShotStderr, OneShotSummary, OneShotTermination, OneShotTimeout, PLUGIN_SOCKET_ENV,
    PluginCallOutcome, PluginCallRecord, PluginMode, PluginModeKind, PluginSession,
    PluginSessionShutdown, RESIDENT_EXIT_DETECT_TIMEOUT, RESIDENT_START_TIMEOUT_DEFAULT,
    RESIDENT_START_TIMEOUT_MAX, ResidentCallRecord, ResidentPlugin, ResidentShutdown,
    ResidentShutdownError, ResidentStartTimeout, ResidentState, call_once, call_once_observed,
};
pub use message::{ControlMessage, MessageId, decode_message, encode_message};
pub use rss::{RssSample, RssSource};
pub use transport::{
    RpcTimeout, UDS_ACCEPT_TIMEOUT_MAX, UDS_CONNECT_TIMEOUT_MAX, UDS_DEFAULT_IO_TIMEOUT,
    UDS_RPC_TIMEOUT_DEFAULT, UDS_RPC_TIMEOUT_MAX, UdsListener, UdsStream,
};
pub use uds_security::{
    ONE_SHOT_SWEEP_MAX_ENTRIES, ONE_SHOT_SWEEP_MAX_SCAN, OneShotSweep, RUNTIME_DIR_NAME, RuntimeDir,
};
