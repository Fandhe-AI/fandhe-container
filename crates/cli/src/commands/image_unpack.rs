//! core の `ImageRootfsUnpacker` を oci の `ImageStore` で満たす本番アダプタ（OCI-7・OCI-1・SEC-1・#2377）。
//!
//! # 役割と呼び出し元
//!
//! `create_start::create_container_with_image` が、`create --image-root <dir> --image <ref> --unpack` のときだけ
//! `ContainerImage::with_unpacker` へ渡す。core の `create_with_image` が展開先（core が作って fd で保持する空の
//! ディレクトリ。Linux では `/proc/self/fd/N`）を作り、参照を登録したうえで [`ImageRootfsUnpacker::unpack`] を呼ぶ。
//! 展開の成功後に core が最終の名前へ公開し、失敗・中断では core が展開物と参照を巻き戻す。core は oci に依存しない
//! （`docs/architecture.md`）ため、両方に依存できる上位の cli が manifest からレイヤーを引いて oci の展開へ渡す。
//!
//! # 手順
//!
//! 1. `ImageManifestDigest` を oci の `Digest` にする
//! 2. [`ImageStore::image_layers`] で下位から順のレイヤー（blob・mediaType・diff_id）を引く。ストアの排他は
//!    この呼び出しの内側で取って返す前に解放する（展開の全体にわたって保持しない。REPAIR-5）
//! 3. 各 blob を [`ImageStore::open_verified_layer`] で fd 起点に開き、同じハンドルで信頼条件・digest・サイズを確かめる。
//!    合計サイズが [`MAX_IMAGE_BYTES`] を超えたら展開の前に `ResourceExhausted`
//! 4. 展開先の `/proc/self/fd/N` を [`ExtractRoot::open_proc_fd_link`] で開く（core の契約どおり最後の要素の symlink を辿り、
//!    以降は fd 起点・リンク非追従）
//! 5. `extract_image_layers_bounded_in` で重ねて展開する。展開後 tar の sha256 を `diff_ids` と突合し、期限
//!    ([`UNPACK_DEADLINE`]) をエントリ単位で確かめる
//!
//! エラーは固定文言の `TraitError`（`image::Stage::Unpack`）に写し、パス・OS のエラー文字列・イメージ名を含めない。
//!
//! # 所有者と特殊ビット（SEC-5）
//!
//! 展開の選択肢は既定の `ExtractOptions::new()`（所有者は `Keep`、特殊ビットは `Strip`）で、cri の本番の既定と同じ。
//! 木は実行ユーザー（実効 uid）所有になるため、core の後始末・回収の権限は既定の `ImageRootfsPrivilege::HostEffectiveIds`
//! （`ContainerImage`・`DeleteOptions`・`ReapOptions` の既定）と一致する。rootful でイメージ由来の所有者・setuid を
//! ホストへ持ち込まない。
//!
//! # 未実装・簡易実装（実装済みを装わない。REPAIR-3）
//!
//! - rootless の user namespace の中での展開（`OwnershipPolicy::ChownInUserNamespace`）と、
//!   `ImageRootfsPrivilege::SubordinateIds` の配線は未実装（#482・#2792）。subuid 範囲の写像が要るイメージ
//!   （root 以外の所有者を持つ層）を、イメージ由来の所有者のまま展開する経路は無い
//! - overlay の下位層による展開の省略は未実装（`mount(2)` の `unsafe` が要る。create ごとに展開のコストがかかる）
//! - oci の `OciOpRecorder` による計装は未配線（`NoopOciOpRecorder`）。CLI の `OpRecorder` への橋渡し
//!   （`oci_recorder::CliOciRecorder`）は `Arc<OpRecorder>` が要り、イメージつき create の `Runtime` は所有で持つため
//! - 置き場所は暫定。#2315 の判断（`docs/design/image-store-adapter-placement.md` の論点 2。オーナー承認待ち）が出たら、
//!   `image_refs::StoreImageRefs` と同じくこの module をそのまま移せる（外部へ公開する型は無い）
//! - CRI・plugin 経由の create への配線は #2791

use std::path::Path;
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{
    ImageManifestDigest, ImageRootfsUnpacked, ImageRootfsUnpacker,
};
use fandhe_container_core::traits::TraitError;
use fandhe_container_oci::error::{OciError, OciErrorCode};
use fandhe_container_oci::image_management::ImageStore;
use fandhe_container_oci::instrument::NoopOciOpRecorder;
use fandhe_container_oci::layer::DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES;
use fandhe_container_oci::layer::extract::{
    ExtractBudget, ExtractLimits, ExtractOptions, ExtractRoot, ImageLayer,
    extract_image_layers_bounded_in,
};
use fandhe_container_oci::reference::Digest;

use super::image::{Stage, trait_failure};

/// 圧縮 blob の合計サイズの上限（cri の `DEFAULT_MAX_IMAGE_BYTES` と同値の 16 GiB）。
pub(super) const MAX_IMAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// 展開全体の期限（エントリ単位で確かめる。超過は `Timeout`。REPAIR-5）。
pub(super) const UNPACK_DEADLINE: Duration = Duration::from_secs(10 * 60);

/// `ImageStore` を借りて `ImageRootfsUnpacker` を満たすアダプタ。
pub(super) struct StoreImageRootfsUnpacker<'a> {
    store: &'a ImageStore,
}

impl<'a> StoreImageRootfsUnpacker<'a> {
    pub(super) fn new(store: &'a ImageStore) -> Self {
        Self { store }
    }

    fn unpack_inner(
        &self,
        manifest: &ImageManifestDigest,
        rootfs: &Path,
    ) -> Result<ImageRootfsUnpacked, OciError> {
        let digest = Digest::parse(manifest.as_str())?;
        let layers = self.store.image_layers(&digest)?;
        // 展開の前に全レイヤーを開いて検証する（合計サイズの上限は I/O より前に課す）。
        let mut total: u64 = 0;
        let mut verified = Vec::with_capacity(layers.layers().len());
        for layer in layers.layers() {
            let blob = self.store.open_verified_layer(layer)?;
            total = total.saturating_add(blob.size());
            if total > MAX_IMAGE_BYTES {
                return Err(OciError::new(
                    OciErrorCode::ResourceExhausted,
                    "image layers exceed the size limit",
                ));
            }
            verified.push(blob);
        }
        let root = ExtractRoot::open_proc_fd_link(rootfs)?;
        let image_layers: Vec<ImageLayer<'_>> = verified
            .iter()
            .zip(layers.layers())
            .map(|(blob, l)| ImageLayer::new(blob, l.media_type(), l.diff_id()))
            .collect();
        let mut budget = ExtractBudget::new();
        if let Some(deadline) = Instant::now().checked_add(UNPACK_DEADLINE) {
            budget = budget.with_deadline(deadline);
        }
        let extracted = extract_image_layers_bounded_in(
            &NoopOciOpRecorder,
            &image_layers,
            &root,
            DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES,
            ExtractLimits::default(),
            &ExtractOptions::new(),
            &budget,
        )?;
        let mut unpacked = ImageRootfsUnpacked::default();
        unpacked.layers = extracted.len();
        Ok(unpacked)
    }
}

impl ImageRootfsUnpacker for StoreImageRootfsUnpacker<'_> {
    fn unpack(
        &self,
        manifest: &ImageManifestDigest,
        rootfs: &Path,
    ) -> Result<ImageRootfsUnpacked, TraitError> {
        self.unpack_inner(manifest, rootfs)
            .map_err(|e| trait_failure(&e, Stage::Unpack))
    }
}

#[cfg(test)]
mod tests;
