//! I/O 共有層（パイプライン送信・バッチ write-back・フラッシュバリア・FS 正規化）。
//! ホストとゲストの間のファイル共有プロトコル（IO-1）の土台（TASK-11.1・#68・MS-1）。
//!
//! 送受信の抽象トレイト（[`transport`]）・構造化エラー（[`error`]）・フレームヘッダ
//! newtype とチェックサム付きフレーム全体型（[`protocol`]。TASK-11.2・#69・
//! TASK-11.3・#70）に加え、パイプライン送信クライアントの送信キュー
//! （[`client::SendQueue`]・[`client::PipelineClient`]。TASK-12.1・#73）と、送信
//! イベントを外部のログ・メトリクス基盤へ出力する観測フック（[`observe`]。
//! TASK-12.1・#73 codex 指摘対応。REPAIR-4）を持つ。
//! トランスポートの具象実装（UDS・vsock・named pipe 等）はまだない（REPAIR-3。
//! スタブの明示）。[`protocol::Frame`] はヘッダ・ペイロード・CRC-32C チェックサムの
//! エンコード / デコードを提供するが、request id のワイヤー表現・ACK status の
//! ペイロードレイアウト、種別ごとのペイロード長制約は TASK-12.2（#74）・TASK-13
//! （またはそれらの後続 sub-issue）が定める。ACK フレームの受信・対応付け・
//! タイムアウト付き待機は TASK-12.2（#74）が [`client`] モジュールへ追加する。
//! バッチ write-back サーバー（TASK-13）の本体もこの crate のトレイトを実装する形で
//! 後続タスクが追加する。
//!
//! PLUG-1 区分は core（`fandhe-container-plugin` の境界機構とは別に、コアの一部として
//! 直接リンクされる）。crate 名 `fandhe-container-io` は
//! `docs/design/crate-naming.md`（TASK-1・REPAIR-1）で確定済み。依存方向は
//! `core → io` であり、本 crate は `fandhe-container-core` に依存しない
//! （`docs/architecture.md`「依存関係グラフ」）。

mod checksum;
pub mod client;
pub mod error;
pub mod observe;
pub mod protocol;
pub mod transport;

pub use client::{
    DEFAULT_IN_FLIGHT_LIMIT, InFlightLimit, InFlightRequest, MAX_IN_FLIGHT_LIMIT, PipelineClient,
    RequestId, SendOutcome, SendQueue,
};
pub use error::{IoError, IoErrorCode};
pub use observe::{
    JsonLinesSendObserver, NoopSendObserver, SendEvent, SendEventError, SendObserver,
};
pub use protocol::{
    CHECKSUM_LEN, FRAME_HEADER_LEN, Frame, FrameChecksum, FrameHeader, FrameKind, MAX_FRAME_LEN,
    MAX_PAYLOAD_LEN, PayloadLen,
};
pub use transport::{
    FrameReceiver, FrameSender, FrameTransport, IoTimeout, MAX_IO_TIMEOUT, WireFrame,
};
