//! I/O 共有層（パイプライン送信・バッチ write-back・フラッシュバリア・FS 正規化）。
//! ホストとゲストの間のファイル共有プロトコル（IO-1）の土台（TASK-11.1・#68・MS-1）。
//!
//! 送受信の抽象トレイト（[`transport`]）・構造化エラー（[`error`]）・フレームヘッダ
//! newtype とチェックサム付きフレーム全体型（[`protocol`]。TASK-11.2・#69・
//! TASK-11.3・#70）・バッチ集約バッファ（[`batch`]。TASK-13.1・#76）に加え、
//! パイプライン送信クライアントの送信キュー（[`client::SendQueue`]・
//! [`client::PipelineClient`]。TASK-12.1・#73）と、送信イベントを記録する観測フック
//! （[`observe`]。TASK-12.1・#73 codex 指摘対応。REPAIR-4・REPAIR-5）を持つ。
//! トランスポートの具象実装のうち、UDS のサーバー側（Linux / macOS）は
//! TASK-13.2.1（#820）で実装済み（[`server::UdsServer`]・
//! [`server::UdsConnection`]。accept・送受信のイベントは
//! [`observe::ServerObserver`] へ通知する）。クライアント側の UDS `connect` と
//! [`client::PipelineClient`] との本番結合・vsock・named pipe はまだない
//! （REPAIR-3。スタブの明示）。
//! [`protocol::Frame`] のペイロード内部レイアウト（request id・ACK の対応付け）は
//! [`payload`] モジュール（TASK-12.2・#74）が定める。[`client::PipelineClient::send`]
//! はこの形式で request id を埋め込み、[`client::PipelineClient::recv_ack`]
//! （TASK-12.2・#74）が送信順で ACK を検証・対応付けし、タイムアウト付きで待つ。
//! `recv_ack` が返す通常 ACK と FLUSH ACK は [`barrier`] モジュール
//! （TASK-15.1・#85・IO-1・IO-2）が別の型（[`barrier::WriteAck`] /
//! [`barrier::FlushAck`]）として区別し、取り違えをコンパイル時に検出できる
//! ようにする。[`client::PipelineClient::flush`] は FLUSH フレームを送信し、
//! [`barrier::FlushBarrier`] を返す。
//! [`batch::BatchBuffer`] は受信した `Write` フレームを既定 64 件（設定可能）単位で
//! 集約するメモリ内ロジックのみを提供する。その集約結果を実際にディスクへ書き込み、
//! 書き込み完了後に通常 ACK を返すところまでは [`writeback`] モジュール
//! （TASK-13.2.2・#822）がつなぐ（[`writeback::serve_connection`]・
//! [`writeback::AppendFileSink`]）。FLUSH バリアの永続化に使う Linux 用の
//! `syncfs(2)` FFI ラッパー（`sys` モジュール・非公開。TASK-15.2.1・#823）は
//! `writeback` の `Flush` 受信時に [`writeback::BatchSink::persist`] 経由で
//! 呼ばれ、成功したときだけ FlushAck を返す（IO-2・TASK-15.2.2・#824。
//! 失敗・タイムアウト・Linux 5.8 未満・非 Linux は FlushAck なしで終了。対応可否は
//! [`barrier::persist_support`] で判定する。非 Linux の代替は TASK-15.3・#88）。受信フレームの長さ・件数を
//! 本体バッファ確保前に上限検証する受理判定ゲート
//! （[`recv_limits::ReceiveLimits`]・TASK-13.4・#796）も持つ。UDS 受信ループの
//! 受付ループ（accept → 次の accept）・同時接続数の上限は後続 sub-issue が担う。
//! `--batch-size` 相当の設定 API（CLI / 設定の文字列から検証済み
//! [`batch::BatchConfig`] と [`recv_limits::ReceiveLimits`] を単一の入口から
//! 導く）は [`settings`] モジュール（TASK-13.3・#78）が提供する。
//! FS 正規化層は、大文字小文字を区別しないホスト（APFS / NTFS）とゲスト
//! （ext4）の差異による黙った上書きを防ぐため、ゲスト相対パスの大文字小文字
//! 衝突を検出する（[`fs_normalize::CaseCollisionSet`]・
//! [`fs_normalize::check_case_collisions`]・TASK-19.1・IO-5・#99）。サーバーの
//! 書き込み経路への組み込みは #100（TASK-19.2）、パス長 260 超の検証は
//! TASK-20、Unicode 正規化（NFC / NFD）は #103（TASK-21.h1）の方針決定後に
//! TASK-21 でそれぞれ後続実装する
//! （REPAIR-3。本 crate はまだこれらを呼び出していない）。
//!
//! PLUG-1 区分は core（`fandhe-container-plugin` の境界機構とは別に、コアの一部として
//! 直接リンクされる）。crate 名 `fandhe-container-io` は
//! `docs/design/crate-naming.md`（TASK-1・REPAIR-1）で確定済み。依存方向は
//! `core → io` であり、本 crate は `fandhe-container-core` に依存しない
//! （`docs/architecture.md`「依存関係グラフ」）。

pub mod barrier;
pub mod batch;
mod checksum;
pub mod client;
pub mod error;
pub mod fs_normalize;
pub mod observe;
pub mod payload;
pub mod protocol;
pub mod recv_limits;
pub mod server;
pub mod settings;
mod sys;
pub mod transport;
pub mod writeback;

pub use barrier::{AckReceipt, FlushAck, FlushBarrier, PersistSupport, WriteAck, persist_support};
pub use batch::{
    Batch, BatchBuffer, BatchConfig, BatchTrigger, DEFAULT_BATCH_SIZE, MAX_BATCH_SIZE, PushOutcome,
};
pub use client::{
    AckMetrics, AckOutcome, DEFAULT_IN_FLIGHT_LIMIT, InFlightLimit, InFlightRequest,
    LATENCY_HISTOGRAM_BUCKETS, LatencyStats, MAX_IN_FLIGHT_LIMIT, PipelineClient, RequestId,
    SendMetrics, SendOutcome, SendQueue,
};
pub use error::{IoError, IoErrorCode};
pub use fs_normalize::{CaseCollisionSet, MAX_COLLISION_MESSAGE_PATH_CHARS, check_case_collisions};
pub use observe::{
    AckEvent, AckEventError, DEFAULT_SEND_LOG_CAPACITY, JsonLinesSendObserver,
    JsonLinesServerObserver, MAX_SEND_LOG_BUFFER_BYTES, MAX_SEND_LOG_CAPACITY,
    MAX_SEND_LOG_MESSAGE_BYTES, MAX_SERVER_AUDIT_LOG_BUFFER_BYTES, NoopSendObserver,
    NoopServerObserver, SERVER_AUDIT_LOG_CAPACITY, SendEvent, SendEventError, SendObserver,
    ServerEvent, ServerObserver, ServerOp, ServerOutcome,
};
pub use payload::{
    ACK_PAYLOAD_LEN, AckEnvelope, MAX_WRITE_BODY_LEN, REQUEST_ID_WIRE_LEN, RequestEnvelope,
    WireRequestId, decode_ack, decode_request, encode_ack, encode_request,
};
pub use protocol::{
    CHECKSUM_LEN, FRAME_HEADER_LEN, Frame, FrameChecksum, FrameHeader, FrameKind, MAX_FRAME_LEN,
    MAX_PAYLOAD_LEN, PROTOCOL_VERSION, PayloadLen,
};
pub use recv_limits::{
    AdmittedHeader, MAX_CONTROL_PAYLOAD_LEN, MAX_RECV_PENDING_FRAMES, ReceiveLimits,
};
pub use server::{UdsConnection, UdsServer};
pub use settings::{
    BATCH_SIZE_OPTION, BATCH_SIZE_SETTING_KEY, BoundConnection, BoundWriteback,
    MAX_BATCH_SIZE_ARG_LEN, WritebackSettings, parse_batch_size,
};
pub use transport::{
    FrameReceiver, FrameSender, FrameTransport, IoTimeout, MAX_IO_TIMEOUT, WireFrame,
};
pub use writeback::{
    AppendFileSink, BatchSink, SinkPersistReport, SinkWriteReport, WritebackReport, WritebackStats,
    WritebackTimeouts, serve_connection,
};
