//! net の `NetOpRecorder` を CLI の `OpRecorder` へ橋渡しするアダプタ（REPAIR-4・NET-6・CLI-1・#3066）。
//!
//! 呼び出し元は `network.rs` の `network create` / `network rm` / `network ls`。`NetworkStore::open_with_recorder` へ
//! 渡し、定義ストアの open / create / list / remove の結果と所要時間を、1 回のコマンドごとに作る `OpRecorder` へ
//! `network.store.*` の名前で記録する。記録はコマンド末尾の `export_ops` が構造化ログ（`FANDHE_CONTAINER_OP_LOG`）へ出す。
//!
//! 写像: 操作名は `NetOpKind::as_str`（固定文字列）、結果は成功 / 失敗の 2 値。記録の失敗は無視し、操作の結果は変えない。
//! 置き場所は `oci_recorder` と同じ判断（操作を本番で呼び `OpRecorder` を持つ crate に置く。#1860）。

use std::fmt;
use std::sync::Arc;

use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_net::instrument::{NetOpOutcome, NetOpRecorder, NetOpSample};

/// `OpRecorder` へ書き込む `NetOpRecorder`。
pub(super) struct CliNetRecorder(Arc<OpRecorder>);

impl CliNetRecorder {
    pub(super) fn new(recorder: Arc<OpRecorder>) -> Self {
        Self(recorder)
    }
}

impl fmt::Debug for CliNetRecorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CliNetRecorder").finish_non_exhaustive()
    }
}

impl NetOpRecorder for CliNetRecorder {
    fn record_net_op(&self, sample: &NetOpSample) {
        let Ok(name) = OpName::new(sample.kind().as_str()) else {
            return;
        };
        let outcome = match sample.outcome() {
            NetOpOutcome::Success => OpOutcome::Success,
            _ => OpOutcome::Failure,
        };
        let _ = self.0.record(&name, outcome, sample.latency());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_net::instrument::NetOpKind;
    use std::time::Duration;

    /// REPAIR-4・NET-6: 名前は固定文字列、成功 / 失敗が別に数えられる。
    #[test]
    fn repair4_net_store_names_and_outcomes() {
        let rec = Arc::new(OpRecorder::new());
        let bridge = CliNetRecorder::new(Arc::clone(&rec));
        let d = Duration::from_millis(3);
        bridge.record_net_op(&NetOpSample::new(
            NetOpKind::NetworkStoreCreate,
            NetOpOutcome::Success,
            d,
        ));
        bridge.record_net_op(&NetOpSample::new(
            NetOpKind::NetworkStoreCreate,
            NetOpOutcome::Failure,
            d,
        ));
        let snap = rec.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].name().as_str(), "network.store.create");
        assert_eq!((snap[0].success(), snap[0].failure()), (1, 1));
    }
}
