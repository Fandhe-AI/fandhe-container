//! I/O 共有層（パイプライン送信・バッチ write-back・フラッシュバリア・FS 正規化）。
//! ホストとゲストの間のファイル共有プロトコル（IO-1）の土台（TASK-11.1・#68・MS-1）。
//!
//! 現状は送受信の抽象トレイト（[`transport`]）・構造化エラー（[`error`]）・フレーム
//! ヘッダ newtype とチェックサム付きフレーム全体型（[`protocol`]。TASK-11.2・#69・
//! TASK-11.3・#70）を持つ雛形で、トランスポートの具象実装（UDS・vsock・named pipe
//! 等）はない（REPAIR-3。スタブの明示）。[`protocol::Frame`] はヘッダ・ペイロード・
//! CRC-32C チェックサムのエンコード / デコードを提供するが、request id・ACK status の
//! ペイロードレイアウト、種別ごとのペイロード長制約は TASK-12・TASK-13（またはそれらの
//! 後続 sub-issue）が定める。パイプライン送信クライアント（TASK-12）・バッチ
//! write-back サーバー（TASK-13）の本体はこの crate のトレイトを実装する形で
//! 後続タスクが追加する。
//!
//! PLUG-1 区分は core（`fandhe-container-plugin` の境界機構とは別に、コアの一部として
//! 直接リンクされる）。crate 名 `fandhe-container-io` は
//! `docs/design/crate-naming.md`（TASK-1・REPAIR-1）で確定済み。依存方向は
//! `core → io` であり、本 crate は `fandhe-container-core` に依存しない
//! （`docs/architecture.md`「依存関係グラフ」）。

mod checksum;
pub mod error;
pub mod protocol;
pub mod transport;

pub use error::{IoError, IoErrorCode};
pub use protocol::{
    CHECKSUM_LEN, FRAME_HEADER_LEN, Frame, FrameChecksum, FrameHeader, FrameKind, MAX_FRAME_LEN,
    MAX_PAYLOAD_LEN, PayloadLen,
};
pub use transport::{
    FrameReceiver, FrameSender, FrameTransport, IoTimeout, MAX_IO_TIMEOUT, WireFrame,
};
