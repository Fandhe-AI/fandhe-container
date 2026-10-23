//! create / delete が OCI-7 のイメージ参照テーブルを更新するための依存注入口（TASK-183.8.1・OCI-7・MS-4）。
//!
//! # 役割と呼び出し元
//!
//! `image rm` / `image prune` の GC が「使用中」を判定する正の情報源は、イメージストアの参照テーブル
//! （`fandhe-container-oci` の `ReferenceTable`）であり、`StateStore` ではない（OCI-7）。コンテナの
//! ライフサイクル側からそのテーブルを更新するための契約が [`ContainerImageRefs`] で、
//! `create::create_with_image` が「参照登録 → rootfs の使用 → 状態作成」の順に、
//! `delete::delete_releasing_image_ref` が「状態削除 → 参照解除」の順に呼ぶ。
//!
//! # 依存の向き
//!
//! core は oci に依存しない（oci は core より上の層。`docs/architecture.md`）。そのため oci の型は使えず、
//! 本ファイルのトレイトを oci 側（または両方に依存する上位 crate）が `ImageStore` で満たす。
//! `ContainerId` と oci の `ContainerRefId` は同じ規則、[`ImageManifestDigest`] は oci の `Digest::parse` と
//! 同じ形（`sha256:` ＋ 64 桁の小文字 hex）だけを受けるので、アダプタの変換は失敗しない。
//! 本番のアダプタは cli の `image_refs::StoreImageRefs`（暫定の置き場所。#2315）で、CLI の `create --image-root --image` / `delete --image-root` が配線する。plugin 経由の配線は未実装（REPAIR-3）。
//! 上位のアダプタは [`ContainerImageRefs`] と [`ImageRootfsUnpacker`] の両方を `ImageStore` で満たし、
//! `ContainerImage::new(..).with_unpacker(..)` で create へ渡す（展開の順序・展開先の作成・後始末は core の担当。#2342・#2315）。

use super::image_rootfs::{HOST_PRIVILEGE, ImageRootfsPrivilege, ImageRootfsUnpacker};
use crate::traits::{ContainerId, ErrorCode, TraitError};

/// manifest digest の文字列の長さ（`sha256:` ＋ 64 桁）。
const MANIFEST_DIGEST_LEN: usize = 7 + 64;

/// 検証済みの manifest digest（`sha256:<64 桁の小文字 hex>`）。
///
/// 参照テーブルのキー（oci の `Digest`）と同じ形だけを表現できるようにし、アダプタでの再パースが
/// 失敗しないことを型で保証する。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImageManifestDigest(String);

impl ImageManifestDigest {
    /// 文字列を検証して作る。形式違反は [`ErrorCode::InvalidArgument`]。
    pub fn new(value: &str) -> Result<Self, TraitError> {
        let ok = value.len() == MANIFEST_DIGEST_LEN
            && value.strip_prefix("sha256:").is_some_and(|hex| {
                hex.bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
            });
        if !ok {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "manifest digest must be sha256:<64 lowercase hex>",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    /// 検証済みの文字列表現。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// [`ContainerImageRefs::register`] の結果（将来の拡張に備え非網羅）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageRefRegistration {
    /// 新しく登録した。
    Registered,
    /// 同じ ID が同じ manifest で既に登録されていた。
    AlreadyRegistered,
}

/// [`ContainerImageRefs::release`] の結果（将来の拡張に備え非網羅）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageRefRelease {
    /// 参照を外した。
    Released,
    /// 登録が無かった（bundle を直に指定して作ったコンテナ等。成功扱い）。
    NotRegistered,
}

/// 参照の登録世代（不透明な識別子）。
///
/// 同じ ID の参照が外されて登録し直されると別の値になる（再利用しない）。delete が「自分が消した
/// コンテナに属する参照」だけを外し、同じ ID で再作成されたコンテナの参照を巻き込まないために使う
/// （OCI-7・TASK-183.8.1）。値の採番は [`ContainerImageRefs`] の実装の責務で、同一 ID の登録ごとに
/// 単調に増える等、過去の値を再発行しないこと。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImageRefGeneration(u64);

impl ImageRefGeneration {
    /// 実装側の採番値から作る。
    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// 採番値。
    pub fn as_raw(&self) -> u64 {
        self.0
    }
}

/// コンテナからイメージ manifest への参照の登録・解除（OCI-7・TASK-183.8.1）。
///
/// 契約:
///
/// - 各呼び出しの内側でイメージストア単位の排他を取り、返る前に解放する。`StateStore` の操作や
///   start の所有ロックをまたいで保持しない。待機には期限を持つ（REPAIR-5）
/// - `register`: manifest が在庫に無ければ [`ErrorCode::NotFound`]、同じ ID が別の manifest を
///   指していれば [`ErrorCode::AlreadyExists`]。同じ manifest なら
///   [`ImageRefRegistration::AlreadyRegistered`]
/// - `release`: 登録が無ければ [`ImageRefRelease::NotRegistered`]。ID だけで外すので、自分が直前に
///   `register` した参照の巻き戻し（create の失敗経路）にだけ使う
/// - `bind`: `id` の現在の登録を「状態作成まで済んだ参照」として確定する（create が状態作成の成功直後に
///   呼ぶ）。未確定の登録だけが対象で、登録が無ければ [`ErrorCode::NotFound`]。確定は、登録しただけで
///   状態作成前に止まった create の参照を、並行する別の状態の delete が誤って外さないための目印である。
///   確定した登録の世代を返す。create は確定の後に状態の存在を確かめ、確定の前に並行する delete が状態を消していたら
///   この世代で `release_if` して参照の取り残しを防ぐ。状態の revision は使わない（start 等の更新で変わり、delete 時の照合が外れるため。#2265 の指摘）。
///   同じ ID の確定済みの登録は高々 1 件で（確定済みの間は `register` が `AlreadyRegistered` を返し
///   create が拒否される）、状態が存在する間それは現在の状態に属する
/// - `registration`: `id` の現在の登録のうち、確定済みのものの世代。登録が無い・未確定のときは `None`
///   （delete 用。状態作成まで済んだ参照だけを返す）
/// - `release_if`: 登録世代が `expected` のときだけ外す（比較と解除は 1 回の排他の内側）。世代が違う・
///   登録が無ければ何もせず [`ImageRefRelease::NotRegistered`]（delete 用。同じ ID の再作成を巻き込まない）
/// - エラーメッセージにパス・OS のエラー文字列を含めない
pub trait ContainerImageRefs {
    /// `id` から `manifest` への参照を登録する。
    fn register(
        &self,
        id: &ContainerId,
        manifest: &ImageManifestDigest,
    ) -> Result<ImageRefRegistration, TraitError>;

    /// `id` の参照を外す。
    fn release(&self, id: &ContainerId) -> Result<ImageRefRelease, TraitError>;

    /// `id` の現在の登録を、状態作成まで済んだ参照として確定する。
    fn bind(&self, id: &ContainerId) -> Result<ImageRefGeneration, TraitError>;

    /// `id` の登録のうち確定済みのものの世代を返す。無ければ `None`。
    fn registration(&self, id: &ContainerId) -> Result<Option<ImageRefGeneration>, TraitError>;

    /// `id` の登録世代が `expected` と一致するときだけ参照を外す。
    fn release_if(
        &self,
        id: &ContainerId,
        expected: ImageRefGeneration,
    ) -> Result<ImageRefRelease, TraitError>;
}

/// create に渡す「どのイメージを使うか」の束（`create::create_with_image` の引数）。
#[derive(Clone, Copy)]
pub struct ContainerImage<'a> {
    refs: &'a dyn ContainerImageRefs,
    manifest: &'a ImageManifestDigest,
    unpacker: Option<&'a dyn ImageRootfsUnpacker>,
    /// core が作る rootfs の木を消す権限（既定はホストの実効 ID。#2540）。
    rootfs_privilege: &'a ImageRootfsPrivilege,
}

impl<'a> ContainerImage<'a> {
    /// 参照テーブルの入口と、使うイメージの manifest を束ねる。
    pub fn new(refs: &'a dyn ContainerImageRefs, manifest: &'a ImageManifestDigest) -> Self {
        Self {
            refs,
            manifest,
            unpacker: None,
            rootfs_privilege: &HOST_PRIVILEGE,
        }
    }

    /// 展開器が作る木の所有者（subuid 所有か）に合わせた、木を消す権限を指定する（SEC-5・#2540）。
    ///
    /// `SubordinateIds` を渡すと、create の失敗時の後始末と公開済みの孤児の回収が userns の中で木を消し、
    /// 状態レコードの `imageRootfs.ownership` に `subordinate` を記録する（delete は
    /// [`crate::oci_runtime::DeleteOptions`] で同じ権限を渡す）。展開器を足さない場合は使われない。
    pub fn with_rootfs_privilege(mut self, privilege: &'a ImageRootfsPrivilege) -> Self {
        self.rootfs_privilege = privilege;
        self
    }

    /// レイヤーを rootfs へ展開する展開器を足す（#2342）。指定しない場合、bundle の rootfs は
    /// 展開済みの前提で、create は従来どおり検証だけを行う。
    pub fn with_unpacker(mut self, unpacker: &'a dyn ImageRootfsUnpacker) -> Self {
        self.unpacker = Some(unpacker);
        self
    }

    pub(super) fn rootfs_privilege(&self) -> &'a ImageRootfsPrivilege {
        self.rootfs_privilege
    }

    pub(super) fn unpacker(&self) -> Option<&'a dyn ImageRootfsUnpacker> {
        self.unpacker
    }

    pub(super) fn refs(&self) -> &'a dyn ContainerImageRefs {
        self.refs
    }

    pub(super) fn manifest(&self) -> &'a ImageManifestDigest {
        self.manifest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// OCI-7: 小文字 hex 64 桁の sha256 だけを受ける。
    #[test]
    fn oci7_manifest_digest_accepts_canonical_form() {
        let d = ImageManifestDigest::new(GOOD).expect("valid");
        assert_eq!(d.as_str(), GOOD);
    }

    /// OCI-7: 大文字・長さ違い・別アルゴリズム・空は InvalidArgument。
    #[test]
    fn oci7_manifest_digest_rejects_malformed() {
        let upper = format!("sha256:{}", GOOD[7..].to_uppercase());
        let short = &GOOD[..GOOD.len() - 1];
        let sha512 = GOOD.replace("sha256", "sha512");
        for bad in [upper.as_str(), short, sha512.as_str(), ""] {
            let err = ImageManifestDigest::new(bad).expect_err("must fail");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{bad}");
        }
    }
}
