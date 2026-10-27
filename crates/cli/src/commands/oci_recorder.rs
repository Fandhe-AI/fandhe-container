//! oci の `OciOpRecorder` を CLI の `OpRecorder` へ橋渡しするアダプタ（REPAIR-4・OCI-1・CLI-1・#2968）。
//!
//! 呼び出し元は `image.rs` の `image ls` / `image rm` / `image tag` / `system df`。`ImageStore::with_recorder` へ
//! 渡し、oci 内の操作（イメージストアの排他取得・一覧・df・rm・tag など）を、CLI の `with_ops` が 1 回のコマンドごとに
//! 作る `OpRecorder` へ `oci.*` の名前で記録する。記録は `with_ops` の `export_ops` が構造化ログへ出す。
//!
//! 置き場所の判断（#1860）: アダプタは操作を本番で呼び `OpRecorder` を持つ crate に置く原則に従い、cli に置く。
//! plugin-cri の `CoreOciRecorder` と同じ写像だが、共通化すると cli と plugin-cri の間に計装だけのための依存辺が
//! 要るため、現状は重複させて両側の試験で同じ具体値（名前 22 種・結果）を固定する。
//!
//! 写像: 操作名は `OciOpKind::as_str`（固定文字列）、結果は成功 / 失敗の 2 値。エラー code は名前に混ぜず落とす
//! （操作名の種類数が掛け算で増え、`OpRecorder` の `MAX_TRACKED_OPS` を圧迫するため。分類は CLI のエラー出力に残る）。
//! 記録の失敗は無視し、操作の結果は変えない。
//!
//! # 未実装・前提
//!
//! CLI に `pull` サブコマンドは無く（pull は plugin-cri の `PullImage` 経由）、展開も CLI は呼ばない。pull・展開の
//! 経路が CLI に入った時点で、同じアダプタを `ImageRootfsSource::with_recorder` 等へ渡す（OCI-1）。

use std::fmt;
use std::sync::Arc;

use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_oci::instrument::{OciOpOutcome, OciOpRecorder, OciOpSample};

/// `OpRecorder` へ書き込む `OciOpRecorder`。
pub(super) struct CliOciRecorder(Arc<OpRecorder>);

impl CliOciRecorder {
    pub(super) fn new(recorder: Arc<OpRecorder>) -> Self {
        Self(recorder)
    }
}

impl fmt::Debug for CliOciRecorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CliOciRecorder").finish_non_exhaustive()
    }
}

impl OciOpRecorder for CliOciRecorder {
    fn record_oci_op(&self, sample: &OciOpSample) {
        let Ok(name) = OpName::new(sample.kind().as_str()) else {
            return;
        };
        let outcome = match sample.outcome() {
            OciOpOutcome::Success => OpOutcome::Success,
            _ => OpOutcome::Failure,
        };
        let _ = self.0.record(&name, outcome, sample.latency());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_oci::error::OciErrorCode;
    use fandhe_container_oci::instrument::OciOpKind;
    use std::time::Duration;

    fn sample(kind: OciOpKind, outcome: OciOpOutcome) -> OciOpSample {
        let code = (outcome == OciOpOutcome::Failure).then_some(OciErrorCode::Timeout);
        OciOpSample::new(kind, outcome, code, Duration::from_millis(5))
    }

    /// REPAIR-4・OCI-1: 全 22 種の操作名が plugin-cri の写像と同じ具体値になる。
    #[test]
    fn repair4_oci_names_match_plugin_cri_mapping() {
        let table = [
            (OciOpKind::AuthenticateAnonymous, "oci.auth.anonymous"),
            (OciOpKind::AuthenticateBasic, "oci.auth.basic"),
            (OciOpKind::AuthenticateBearer, "oci.auth.bearer"),
            (OciOpKind::Authenticate, "oci.auth"),
            (OciOpKind::FetchManifest, "oci.manifest.fetch"),
            (OciOpKind::FetchBlob, "oci.blob.fetch"),
            (OciOpKind::VerifyBlobDigest, "oci.blob.verify"),
            (OciOpKind::DecompressLayer, "oci.layer.decompress"),
            (OciOpKind::ExtractLayer, "oci.layer.extract"),
            (OciOpKind::ListImages, "oci.image.list"),
            (OciOpKind::DiskUsage, "oci.image.df"),
            (OciOpKind::RemoveImage, "oci.image.rm"),
            (OciOpKind::AcquireImageStoreLock, "oci.store.lock"),
            (OciOpKind::BeginPull, "oci.pull.begin"),
            (OciOpKind::LeaseBlob, "oci.pull.lease"),
            (OciOpKind::ReleaseBlobLease, "oci.pull.release"),
            (OciOpKind::PublishPull, "oci.pull.publish"),
            (OciOpKind::AbortPull, "oci.pull.abort"),
            (OciOpKind::PruneImages, "oci.image.prune"),
            (OciOpKind::TagImage, "oci.image.tag"),
            (OciOpKind::RecoverPendingDeletion, "oci.image.gc_recover"),
            (OciOpKind::RecoverStalePulls, "oci.pull.gc_recover"),
        ];
        let rec = Arc::new(OpRecorder::new());
        let bridge = CliOciRecorder::new(Arc::clone(&rec));
        for (kind, _) in table {
            bridge.record_oci_op(&sample(kind, OciOpOutcome::Success));
        }
        let snap = rec.snapshot();
        assert_eq!(snap.len(), 22);
        for (_, name) in table {
            let stats = snap
                .iter()
                .find(|s| s.name().as_str() == name)
                .unwrap_or_else(|| panic!("missing {name}"));
            assert_eq!((stats.success(), stats.failure()), (1, 0), "{name}");
        }
    }

    /// REPAIR-4: 失敗は failure に数え、エラー code は名前に混ざらない。
    #[test]
    fn repair4_failure_counts_without_error_code_in_name() {
        let rec = Arc::new(OpRecorder::new());
        let bridge = CliOciRecorder::new(Arc::clone(&rec));
        bridge.record_oci_op(&sample(OciOpKind::RemoveImage, OciOpOutcome::Failure));
        bridge.record_oci_op(&sample(OciOpKind::RemoveImage, OciOpOutcome::Success));
        let snap = rec.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].name().as_str(), "oci.image.rm");
        assert_eq!((snap[0].success(), snap[0].failure()), (1, 1));
    }
}
