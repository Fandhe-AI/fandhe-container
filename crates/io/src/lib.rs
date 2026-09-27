//! I/O 共有層（パイプライン送信・バッチ write-back・フラッシュバリア・FS 正規化）。
//! ホストとゲストの間のファイル共有プロトコル（IO-1）の土台（TASK-11.1・#68・MS-1）。
//!
//! 現状は送受信の抽象トレイト（[`transport`]）と構造化エラー（[`error`]）のみを持つ
//! 雛形で、トランスポートの具象実装（UDS・vsock・named pipe 等）はない（REPAIR-3。
//! スタブの明示）。フレーム型（ヘッダ newtype・チェックサム）は TASK-11.2（#69）・
//! TASK-11.3（#70）で [`transport`] とは別のモジュールに追加する。パイプライン送信
//! クライアント（TASK-12）・バッチ write-back サーバー（TASK-13）の本体はこの crate の
//! トレイトを実装する形で後続タスクが追加する。
//!
//! PLUG-1 区分は core（`fandhe-container-plugin` の境界機構とは別に、コアの一部として
//! 直接リンクされる）。crate 名 `fandhe-container-io` は
//! `docs/design/crate-naming.md`（TASK-1・REPAIR-1）で確定済み。依存方向は
//! `core → io` であり、本 crate は `fandhe-container-core` に依存しない
//! （`docs/architecture.md`「依存関係グラフ」）。

pub mod error;
pub mod transport;

pub use error::{IoError, IoErrorCode};
pub use transport::{
    FrameReceiver, FrameSender, FrameTransport, IoTimeout, MAX_IO_TIMEOUT, WireFrame,
};
