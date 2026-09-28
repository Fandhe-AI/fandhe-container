//! I/O 共有層（パイプライン送信・バッチ write-back・フラッシュバリア・FS 正規化）。
//! ホストとゲストの間のファイル共有プロトコル（IO-1）の土台（TASK-11.1・#68・MS-1）。
//!
//! 送受信の抽象トレイト（[`transport`]）・構造化エラー（[`error`]）・フレームヘッダ
//! newtype とチェックサム付きフレーム全体型（[`protocol`]。TASK-11.2・#69・
//! TASK-11.3・#70）・バッチ集約バッファ（[`batch`]。TASK-13.1・#76）に加え、
//! パイプライン送信クライアントの送信キュー（[`client::SendQueue`]・
//! [`client::PipelineClient`]。TASK-12.1・#73）と、送信イベントを記録する観測フック
//! （[`observe`]。TASK-12.1・#73 codex 指摘対応。REPAIR-4・REPAIR-5）を持つ。
//! トランスポートの具象実装（UDS・vsock・named pipe 等）・
//! ディスク書き込み・ACK 返却はまだない（REPAIR-3。スタブの明示）。
//! [`protocol::Frame`] はヘッダ・ペイロード・CRC-32C チェックサムのエンコード /
//! デコードを提供するが、request id のワイヤー表現・ACK status のペイロード
//! レイアウト、種別ごとのペイロード長制約は TASK-12.2（#74）・TASK-13（または
//! それらの後続 sub-issue）が定める。ACK フレームの受信・対応付け・タイムアウト付き
//! 待機は TASK-12.2（#74）が [`client`] モジュールへ追加する。
//! [`batch::BatchBuffer`] は受信した `Write` フレームを既定 64 件（設定可能）単位で
//! 集約するメモリ内ロジックのみを提供し、UDS 受信ループ・ディスク書き込み・ACK 送出は
//! TASK-13.2 系の後続 sub-issue が担う。受信フレームの長さ・件数を本体バッファ確保前に
//! 上限検証する受理判定ゲート（[`recv_limits::ReceiveLimits`]・TASK-13.4・#796）も
//! 持つ。バッチ write-back サーバー本体（TASK-13）もこの crate のトレイト・型を
//! 組み合わせる形で後続タスクが追加する。
//!
//! PLUG-1 区分は core（`fandhe-container-plugin` の境界機構とは別に、コアの一部として
//! 直接リンクされる）。crate 名 `fandhe-container-io` は
//! `docs/design/crate-naming.md`（TASK-1・REPAIR-1）で確定済み。依存方向は
//! `core → io` であり、本 crate は `fandhe-container-core` に依存しない
//! （`docs/architecture.md`「依存関係グラフ」）。

pub mod batch;
mod checksum;
pub mod client;
pub mod error;
pub mod observe;
pub mod protocol;
pub mod recv_limits;
pub mod transport;

pub use batch::{
    Batch, BatchBuffer, BatchConfig, BatchTrigger, DEFAULT_BATCH_SIZE, MAX_BATCH_SIZE, PushOutcome,
};
pub use client::{
    DEFAULT_IN_FLIGHT_LIMIT, InFlightLimit, InFlightRequest, LATENCY_HISTOGRAM_BUCKETS,
    LatencyStats, MAX_IN_FLIGHT_LIMIT, PipelineClient, RequestId, SendMetrics, SendOutcome,
    SendQueue,
};
pub use error::{IoError, IoErrorCode};
pub use observe::{
    DEFAULT_SEND_LOG_CAPACITY, JsonLinesSendObserver, MAX_SEND_LOG_BUFFER_BYTES,
    MAX_SEND_LOG_CAPACITY, MAX_SEND_LOG_MESSAGE_BYTES, NoopSendObserver, SendEvent, SendEventError,
    SendObserver,
};
pub use protocol::{
    CHECKSUM_LEN, FRAME_HEADER_LEN, Frame, FrameChecksum, FrameHeader, FrameKind, MAX_FRAME_LEN,
    MAX_PAYLOAD_LEN, PROTOCOL_VERSION, PayloadLen,
};
pub use recv_limits::{AdmittedHeader, MAX_RECV_PENDING_FRAMES, ReceiveLimits};
pub use transport::{
    FrameReceiver, FrameSender, FrameTransport, IoTimeout, MAX_IO_TIMEOUT, WireFrame,
};
