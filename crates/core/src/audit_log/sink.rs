//! 監査レコードの記録先トレイト（SEC-4・TASK-41.4・#195）。
//!
//! # 役割と契約
//!
//! seccomp・Landlock・マウント検証/API・plugin 信頼検証・exec 対象の各フックが、組み立てた [`AuditRecord`]
//! を渡す先の抽象（全レイヤー共有の境界）。
//!
//! - ファイル追記（`AuditFileWriter`・#839）とカーネル監査フォールバック（`KernelAuditFallback`・#840）の
//!   書き込み部品は実装済みだが、本トレイトを実装して両者を束ねる本番用 sink の実体は無い
//!   （本 crate には既定実装を置かない。REPAIR-3: 実装済みを装わない）
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
