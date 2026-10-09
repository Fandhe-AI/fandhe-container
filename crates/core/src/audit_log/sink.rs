//! 監査レコードの記録先トレイト（SEC-4・TASK-41.4・#195）。
//!
//! # 役割と契約
//!
//! seccomp・Landlock・マウント検証/API・plugin 信頼検証・exec 対象の各フックが、組み立てた [`AuditRecord`]
//! を渡す先の抽象（全レイヤー共有の境界）。
//!
//! - 本番用 sink は core の `FileAuditSink`（#1594）。ファイル追記（`AuditFileWriter`・#839）とカーネル監査
//!   フォールバック（`KernelAuditFallback`・#840）を束ねる。利用者が supervisor に限られず、`StateStore` の既定実装も
//!   core に置く前例（TASK-31）に揃えて core に置く。別の記録先は本トレイトの別実装として差し替える。
//!   両経路が失敗したときの stderr 通知は、失敗の詳細を持つ本番 sink が 1 回だけ出す（`AuditDelivery::SinkFailed` から
//!   は再構成できないため、呼び出し側は出さない）。本番以外の sink の通知は各実装の責務
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
