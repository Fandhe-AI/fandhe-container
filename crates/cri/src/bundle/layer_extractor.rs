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
//! 実装は plugin-cri の `UsernsLayerExtractor` の 1 つだけ。対応表の切り替え（`ChownInUserNamespace` を返す）は H6（#4801）で、
//! それまで本番では通らない。

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
/// 期限切れ・失敗は縮退せず返す。`Err` のとき展開先は途中まで書かれており、呼び出し側が破棄する（oci の契約と同じ）。
/// 同期 API（CRI の worker スレッド・pull の blocking 区間から呼ぶ）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub trait SubordinateLayerExtractor: Send + Sync + std::fmt::Debug {
    /// `layers`（重ねる順）を空の展開先 `root` へ展開する。
    fn extract_layers(
        &self,
        layers: &[ImageLayer<'_>],
        root: &ExtractRoot,
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
