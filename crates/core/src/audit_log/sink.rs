//! 監査レコードの記録先トレイト（SEC-4・TASK-41.4・#195）。
//!
//! # 役割と契約
//!
//! seccomp・Landlock・マウント検証/API の各フックが、組み立てた [`AuditRecord`] を渡す先の抽象。
//! 3 レイヤー共有の境界で、TASK-41.2（#193）・41.3（#194）も再利用する想定。
//!
//! - 実装（ファイル追記・カーネル監査連携等）は TASK-41.5 系（#839）・#840 の担当で、本 crate には
//!   既定実装を置かない（REPAIR-3: 実装済みを装わない）
//! - `record` が `Err` を返しても、呼び出し側は拒否の判定を覆さない（fail-closed）
//! - 実装は拒否経路を止めないこと。ブロックし得る I/O はタイムアウトまたは非同期化する
//!   （REPAIR-5。実装側の責務）
//! - 記録内容のパスは生バイトのまま渡る。改行・制御文字のエスケープは書き込み側の責務（ログ注入対策）

use crate::traits::TraitError;

use super::AuditRecord;

/// 監査レコードの記録先。
pub trait AuditSink: Send + Sync {
    /// レコードを 1 件記録する。失敗は構造化エラーで返す（panic しない）。
    fn record(&self, record: &AuditRecord) -> Result<(), TraitError>;
}
