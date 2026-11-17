//! 範囲写像（user namespace の中の展開）で作った subuid 所有の木を消す注入点（SEC-5・OCI-7・CORE-6・REPAIR-4・REPAIR-5。
//! #4800。親 issue #4777 の H3）。
//!
//! `ChownInUserNamespace` で展開した木はホストから見ると subuid の所有になり、ホスト uid の `unlinkat`・`chmod` は
//! `EPERM` で失敗しうる（`docs/design/oci-layer-special-bits.md`）。消せるのは同じ写像の user namespace の中だけで、
//! その namespace へ入る再 exec helper（`fandhe-container-plugin-cri` の `userns_helper`。削除モード）は plugin-cri 側にあり、
//! cri からは依存できない（依存方向は plugin-cri → cri）。そこで本トレイトを注入点にする。
//!
//! 呼び出し元: [`super::ImageRootfsSource`]（`release_bounded` と展開失敗時の後始末）と [`crate::image_pull::OciImagePuller`]
//! （pull の `unpack/` の後始末）。分岐は [`needs_userns_removal`] が真のときだけで、偽（`Keep` 等）のときは従来の
//! ホスト側の削除をそのまま通す。真なのに実装が注入されていなければ、ホスト側の削除へ縮退せず `FAILED_PRECONDITION`
//! で拒否する（部分的に消して残骸を増やさない。fail-closed）。
//!
//! 実装は plugin-cri の `UsernsTreeRemover` の 1 つだけ。切り替え（対応表が `ChownInUserNamespace` を返す）は H6（#4801）で有効化済み。

use fandhe_container_oci::layer::extract::{ExtractOptions, OwnershipPolicy};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use crate::adapter::ReleaseBudget;
use crate::error::CriError;

/// 消す対象（親ディレクトリの fd 直下の固定名。任意のパス・名前は受けない。SEC-1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemovalTarget {
    /// bundle ディレクトリ（`<bundles>/<id>`）直下の `rootfs`。
    BundleRootfs,
    /// pull ディレクトリ（`staging/<id>`）直下の `unpack`。
    PullUnpack,
}

/// 範囲写像の user namespace の中から、親ディレクトリ fd の直下の木を消す注入点。
///
/// 実装は symlink を辿らず・マウントをまたがず、`parent` の外を消さないこと。期限切れ・失敗は縮退せず固定文言の
/// [`CriError`] で返し、消した分は残って再実行が続きから消す（冪等）。同期 API（CRI の worker スレッド・pull の
/// blocking 区間から呼ぶ）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub trait SubordinateTreeRemover: Send + Sync + std::fmt::Debug {
    /// `parent`（ディレクトリ fd）の直下の `target` の固定名の木を消す（不在は成功）。
    fn remove_child_tree(
        &self,
        parent: std::os::fd::BorrowedFd<'_>,
        target: RemovalTarget,
        budget: &ReleaseBudget<'_>,
    ) -> Result<(), CriError>;
}

/// 展開設定が範囲写像の user namespace の中での展開（木が subuid 所有になりうる）か。
pub fn needs_userns_removal(opts: &ExtractOptions) -> bool {
    matches!(opts.ownership, OwnershipPolicy::ChownInUserNamespace { .. })
}

/// remover が無いときの拒否（ホスト側の削除へ縮退しない）。
pub(crate) fn missing_remover() -> CriError {
    CriError::failed_precondition("subordinate-owned tree removal is not available")
}

#[cfg(test)]
mod tests {
    use fandhe_container_oci::layer::extract::{ExtractOptions, OwnershipPolicy};

    use super::*;

    /// SEC-5・OCI-7・#4800: 範囲写像でない展開設定（既定の `Keep`）は helper の削除へ回さない。
    #[test]
    fn sec5_4800_keep_ownership_does_not_need_userns_removal() {
        assert!(!needs_userns_removal(&ExtractOptions::default()));
        assert!(!needs_userns_removal(
            &ExtractOptions::new().with_ownership(OwnershipPolicy::Keep)
        ));
    }
}
