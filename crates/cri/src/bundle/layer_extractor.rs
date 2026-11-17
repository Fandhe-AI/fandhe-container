//! 範囲写像（user namespace の中の展開）でレイヤーを展開する注入点（SEC-5・OCI-1・OCI-7・CORE-6・REPAIR-3・REPAIR-5。
//! #4848。親 issue #4777）。
//!
//! マルチスレッドの plugin-cri は user namespace に入れず、`ChownInUserNamespace` の展開は oci の開始前の検証
//! （初期 user namespace でないこと）で `FAILED_PRECONDITION` になる。この展開は再 exec した単一スレッドの helper
//! （`fandhe-container-plugin-cri` の `userns_helper`。展開モード）が行い、plugin-cri は依存方向（plugin-cri → cri）の
//! 都合で cri から直接呼べない。そこで `SubordinateTreeRemover`（削除の注入点）と同じ形の本トレイトを注入点にする。
//!
//! 呼び出し元: [`crate::image_pull::OciImagePuller`]（pull の `unpack/entry/rootfs`）と [`super::ImageRootfsSource`]
//! （create の bundle `rootfs/`）。分岐は [`super::needs_userns_removal`]（削除と共通の述語）が真のときだけで、偽（`Keep` 等）の
//! ときは従来のホスト側の展開をそのまま通す。真なのに実装（extractor と remover の両方）が注入されていなければ、ホスト側の
//! 展開へ縮退せず、展開先を作る前に `FAILED_PRECONDITION` で拒否する（fail-closed。消せない木を作らない）。
//!
//! 実装は plugin-cri の `UsernsLayerExtractor` の 1 つだけ。対応表の切り替え（`ChownInUserNamespace` を返す）は H6（#4801）、特殊ビットの保持は #4849。

use crate::error::CriError;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use fandhe_container_oci::error::OciError;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use fandhe_container_oci::layer::extract::{
    ExtractLimits, ExtractOptions, ExtractRoot, ImageLayer,
};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use crate::adapter::ReleaseBudget;

/// 親で検証済みの blob を、範囲写像の user namespace の中で空の展開先へ展開する注入点。
///
/// 実装は展開先を fd で受け（パスは受けない）、写像は呼び出し側から受けず helper が参加に使ったものを使う。
/// 期限切れ・失敗は縮退せず返す。
///
/// `ancestor` は特殊ビット保持（`PreserveIfChowned`）の閉じ込めを判定する 0700 の祖先（create は bundle ディレクトリ、
/// pull は `None` で展開の根自身の 0700 で判定する。#4849・SEC-5・SEC-1）。呼び出し側の契約: 祖先は 0700・`root` と同じ
/// 所有 uid（helper の名前空間から見た値）で、展開中に `root` を祖先の外へ動かさない。`Err` のとき展開先は途中まで書かれており、呼び出し側が破棄する（oci の契約と同じ）。
/// 同期 API（CRI の worker スレッド・pull の blocking 区間から呼ぶ）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub trait SubordinateLayerExtractor: Send + Sync + std::fmt::Debug {
    /// `layers`（重ねる順）を空の展開先 `root` へ展開する。
    // 展開の入力（レイヤー・展開先・祖先・上限・設定）と期限を 1 呼び出しで渡す注入点（引数をまとめる型は作らない）。
    #[allow(clippy::too_many_arguments)]
    fn extract_layers(
        &self,
        layers: &[ImageLayer<'_>],
        root: &ExtractRoot,
        ancestor: Option<&ExtractRoot>,
        max_uncompressed_layer_bytes: u64,
        limits: ExtractLimits,
        options: &ExtractOptions,
        budget: &ReleaseBudget<'_>,
    ) -> Result<(), OciError>;
}

/// extractor（または remover）が無いときの拒否（ホスト側の展開へ縮退しない）。
pub(crate) fn missing_extractor() -> CriError {
    CriError::failed_precondition("subordinate-owned layer extraction is not available")
}

/// 注入された extractor の展開を計測して `recorder` へ渡す（REPAIR-4・#4848）。helper 内は `NoopOciOpRecorder` のため、
/// 親が `OciOpKind::ExtractLayer` を記録する。成功は oci のホスト側の展開と同じくレイヤーごとに 1 件（所要時間は全体を
/// 層数で割った平均。helper は層ごとの時間を返さない）、失敗は層を特定できないため 1 件の `Failure`。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) fn record_userns_extract(
    recorder: &dyn fandhe_container_oci::instrument::OciOpRecorder,
    layer_count: usize,
    started: std::time::Instant,
    result: &Result<(), OciError>,
) {
    use fandhe_container_oci::instrument::{OciOpKind, OciOpOutcome, OciOpSample};
    let elapsed = started.elapsed();
    match result {
        Ok(()) => {
            let n = u32::try_from(layer_count).unwrap_or(u32::MAX).max(1);
            for _ in 0..layer_count {
                recorder.record_oci_op(&OciOpSample::new(
                    OciOpKind::ExtractLayer,
                    OciOpOutcome::Success,
                    None,
                    elapsed / n,
                ));
            }
        }
        Err(e) => recorder.record_oci_op(&OciOpSample::new(
            OciOpKind::ExtractLayer,
            OciOpOutcome::Failure,
            Some(e.code()),
            elapsed,
        )),
    }
}

#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use std::sync::Mutex;
    use std::time::Instant;

    use fandhe_container_oci::error::{OciError, OciErrorCode};
    use fandhe_container_oci::instrument::{OciOpOutcome, OciOpRecorder, OciOpSample};

    use super::record_userns_extract;

    #[derive(Debug, Default)]
    struct Collect(Mutex<Vec<OciOpSample>>);

    impl OciOpRecorder for Collect {
        fn record_oci_op(&self, s: &OciOpSample) {
            self.0.lock().unwrap().push(*s);
        }
    }

    /// REPAIR-4・#4848: 成功は層ごとに 1 件、失敗は分類つきの 1 件の `ExtractLayer` を記録する。
    #[test]
    fn repair4_4848_userns_extract_is_recorded() {
        let rec = Collect::default();
        record_userns_extract(&rec, 3, Instant::now(), &Ok(()));
        {
            let v = rec.0.lock().unwrap();
            assert_eq!(v.len(), 3);
            assert!(v.iter().all(|s| s.outcome() == OciOpOutcome::Success));
        }
        let rec = Collect::default();
        let err = Err(OciError::new(OciErrorCode::Timeout, "x"));
        record_userns_extract(&rec, 3, Instant::now(), &err);
        let v = rec.0.lock().unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].outcome(), OciOpOutcome::Failure);
        assert_eq!(v[0].error_code(), Some(OciErrorCode::Timeout));
    }
}
