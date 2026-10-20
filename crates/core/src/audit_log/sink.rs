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
//!   は再構成できないため、呼び出し側は出さない）。本番 sink は子プロセスで出せなかったとき（fork できない・
//!   未回収の子が上限・子の異常終了等）も上限付きの短命スレッドで出し直し、出力先が期限を超えて詰まっている
//!   場合だけ出さない（`FileAuditSink` のモジュール doc「両経路失敗時」）。本番以外の sink の通知は各実装の責務
//! - `record` が `Err` を返しても、呼び出し側は拒否の判定を覆さない（fail-closed）
//! - 実装は拒否経路を止めないこと。ブロックし得る I/O はタイムアウトまたは非同期化する
//!   （REPAIR-5。実装側の責務）
//! - 記録内容のパスは生バイトのまま渡る。改行・制御文字のエスケープは書き込み側の責務（ログ注入対策）

use std::time::Instant;

use crate::traits::{ErrorCode, TraitError};

use super::AuditRecord;

/// 監査レコードの記録先。
pub trait AuditSink: Send + Sync {
    /// レコードを 1 件記録する。失敗は構造化エラーで返す（panic しない）。
    fn record(&self, record: &AuditRecord) -> Result<(), TraitError>;

    /// [`Self::record`] を、絶対期限 `deadline` を超えて待たない約束で行う(REPAIR-5・SEC-4)。
    ///
    /// 呼び出し元: 入口の単一期限から待ちを導く経路(`oci_runtime` の launch の縮退記録など)。既定実装は期限切れなら
    /// 何もせず `Timeout` を返し、そうでなければ `record` に委ねる(待ちの上限は `record` 側の既定のまま)。
    /// 待ちを期限へ絞れる実装(`FileAuditSink`・`ControlAuditRelay`)は上書きする。
    fn record_until(&self, record: &AuditRecord, deadline: Instant) -> Result<(), TraitError> {
        if Instant::now() >= deadline {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "the audit record was not delivered within the deadline",
            ));
        }
        self.record(record)
    }
}
