//! `ImageStore` からレイヤー展開に必要な情報（blob・mediaType・diff_id）を引く読み取り口（OCI-7・OCI-1・#2377）。
//!
//! # 役割と呼び出し元
//!
//! 本番の `ImageRootfsUnpacker`（cli の `image_unpack`。core の `create_with_image` が呼ぶ）が、manifest digest から
//! 「下位から順のレイヤー一覧」を得るための入口。在庫（`@image-inventory.json`）は config と layers の digest、
//! および v2 以降は layers ごとの `mediaType` を持つ。`rootfs.diff_ids` は在庫に持たず、登録済みの config blob を
//! 読み直して得る（真実源を config の 1 か所に保ち、在庫の肥大化を避ける）。
//!
//! # 手順と信頼境界
//!
//! 1. [`ImageStore::lock`] の期限つき排他の中で構成を複製し、**ガードをすぐ手放す**。展開の全体にわたって排他を
//!    保持しない（呼び出し元が参照を登録済みで、GC から blob は守られる。REPAIR-5）
//! 2. 在庫に無ければ `NotFound`、`mediaType` が未記録（v1 の在庫・旧経路の登録）なら `FailedPrecondition`
//!    （再 pull で埋まる。黙って推測しない）
//! 3. config blob は検査済み root の fd 起点（`open_cached_blob`）で開き、同じハンドルで信頼条件を確かめ、上限つきで
//!    1 回だけ読み、**読んだバイト列そのもの**の sha256 を config digest と照合してから `rootfs.diff_ids` を解析する
//! 4. layers・`mediaType`・`diff_ids` の件数が一致しなければ `DataLoss`
//!
//! 返す [`StoredImageLayer::blob_path`] は情報用で、**開くのには使わない**。blob は [`ImageStore::open_verified_layer`]
//! が fd 起点で開き、同じハンドルで信頼条件・digest・サイズを確かめる（パスの開き直しによる差し替えを避ける。#4283）。
//!
//! エラーメッセージは固定の英語で、パスや OS のエラー文字列を含めない。

use std::io::Read as _;
use std::path::PathBuf;

use super::{IMAGE_STORE_BLOB_DIR, ImageStore};
use crate::config::{MAX_CONFIG_BYTES, parse_image_config_rootfs};
use crate::error::{OciError, OciErrorCode};
use crate::layer::{BlobFileFacts, VerifiedLayerBlob, check_blob_trust, verify_bytes_digest};
use crate::reference::Digest;

fn err(code: OciErrorCode, msg: &'static str) -> OciError {
    OciError::new(code, msg)
}

/// 展開に使うレイヤー 1 件（manifest の並び。非網羅）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StoredImageLayer {
    digest: Digest,
    media_type: String,
    diff_id: Digest,
    blob_path: PathBuf,
}

impl StoredImageLayer {
    /// 圧縮 blob の digest。
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// manifest の descriptor の `mediaType`（受理表の閉じた集合のどれか）。
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// config の `rootfs.diff_ids` の対応する要素（展開後 tar の sha256）。
    pub fn diff_id(&self) -> &Digest {
        &self.diff_id
    }

    /// blob の位置（`<root>/blobs/sha256/<hex>`）。**情報用**で、開くのには使わない
    /// （[`ImageStore::open_verified_layer`] が fd 起点で開く）。
    pub fn blob_path(&self) -> &std::path::Path {
        &self.blob_path
    }
}

/// [`ImageStore::image_layers`] の結果（非網羅）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StoredImageLayers {
    manifest: Digest,
    config: Digest,
    layers: Vec<StoredImageLayer>,
}

impl StoredImageLayers {
    /// 引いた manifest の digest。
    pub fn manifest(&self) -> &Digest {
        &self.manifest
    }

    /// config blob の digest。
    pub fn config(&self) -> &Digest {
        &self.config
    }

    /// 下位から順のレイヤー。
    pub fn layers(&self) -> &[StoredImageLayer] {
        &self.layers
    }
}

impl ImageStore {
    /// `manifest` のレイヤー一覧（blob の位置・mediaType・diff_id）を返す（OCI-7・OCI-1・#2377）。
    ///
    /// 手順と契約はモジュール doc。エラー: 在庫に無ければ `NotFound`、`mediaType` 未記録は `FailedPrecondition`、
    /// 排他の期限切れは `Timeout`、config の信頼条件違反は `FailedPrecondition`、config の digest 不一致・件数の
    /// 不一致・不正な内容は `DataLoss`、config が上限超え・レイヤー数が上限超えは `ResourceExhausted`。
    pub fn image_layers(&self, manifest: &Digest) -> Result<StoredImageLayers, OciError> {
        // 排他は構成の複製に必要な間だけ取る（展開の全体にわたって保持しない。REPAIR-5）。
        let composition = {
            let guard = self.lock()?;
            guard
                .composition(manifest)
                .cloned()
                .ok_or_else(|| err(OciErrorCode::NotFound, "image not found"))?
        };
        let Some(media_types) = composition.layer_media_types() else {
            return Err(err(
                OciErrorCode::FailedPrecondition,
                "image layer media types are not recorded; pull the image again",
            ));
        };
        let layers = composition.layers();
        if layers.len() > crate::manifest::MAX_LAYERS {
            return Err(err(
                OciErrorCode::ResourceExhausted,
                "too many layers in the image",
            ));
        }
        let diff_ids = self.read_config_diff_ids(composition.config())?;
        if layers.len() != media_types.len() || layers.len() != diff_ids.len() {
            return Err(err(
                OciErrorCode::DataLoss,
                "image layer count does not match the config",
            ));
        }
        let out = layers
            .iter()
            .zip(media_types)
            .zip(&diff_ids)
            .map(|((digest, media_type), diff_id)| {
                let hex = digest
                    .as_str()
                    .strip_prefix("sha256:")
                    .ok_or_else(|| err(OciErrorCode::Internal, "unsupported digest algorithm"))?;
                let mut blob_path = self.root().to_path_buf();
                blob_path.extend(IMAGE_STORE_BLOB_DIR);
                blob_path.push(hex);
                Ok(StoredImageLayer {
                    digest: digest.clone(),
                    media_type: media_type.clone(),
                    diff_id: diff_id.clone(),
                    blob_path,
                })
            })
            .collect::<Result<Vec<_>, OciError>>()?;
        Ok(StoredImageLayers {
            manifest: manifest.clone(),
            config: composition.config().clone(),
            layers: out,
        })
    }

    /// レイヤーの blob を検査済み root の fd 起点で開き、同じハンドルで信頼条件・digest・サイズを確かめて返す
    /// （パスは開き直さない。OCI-1・OCI-7・SEC-1・#4283）。
    ///
    /// サイズは開いたハンドルの fstat の値（digest の照合がサイズの改ざんも検出する）。呼び出し元が合計サイズの
    /// 上限を課すときは、返った [`VerifiedLayerBlob::size`] で確かめる。
    pub fn open_verified_layer(
        &self,
        layer: &StoredImageLayer,
    ) -> Result<VerifiedLayerBlob, OciError> {
        let owner = self.root_owner()?;
        let file = self.open_cached_blob(layer.digest())?;
        let size = file
            .metadata()
            .map_err(|_| err(OciErrorCode::DataLoss, "layer blob could not be inspected"))?
            .len();
        VerifiedLayerBlob::from_file(file, layer.digest(), size, owner)
    }

    /// config blob を信頼条件つきで上限まで 1 回だけ読み、読んだ本文の digest を照合してから `diff_ids` を解析する。
    fn read_config_diff_ids(&self, config: &Digest) -> Result<Vec<Digest>, OciError> {
        let untrusted = || {
            err(
                OciErrorCode::FailedPrecondition,
                "cached image config is not trusted",
            )
        };
        let owner = self.root_owner()?;
        let mut file = self.open_cached_blob(config)?;
        let facts = BlobFileFacts::from_file(&file).ok_or_else(untrusted)?;
        check_blob_trust(&facts, owner).map_err(|_| untrusted())?;
        let mut body = Vec::new();
        (&mut file)
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| err(OciErrorCode::DataLoss, "image config could not be read"))?;
        if body.len() as u64 > MAX_CONFIG_BYTES {
            return Err(err(
                OciErrorCode::ResourceExhausted,
                "image config exceeds the size limit",
            ));
        }
        verify_bytes_digest(&body, config)
            .map_err(|_| err(OciErrorCode::DataLoss, "image config failed validation"))?;
        let rootfs = parse_image_config_rootfs(&body)?;
        Ok(rootfs.diff_ids().to_vec())
    }
}
