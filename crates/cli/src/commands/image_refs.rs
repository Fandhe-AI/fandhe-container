//! core の `ContainerImageRefs` を oci の `ImageStore` で満たす本番アダプタ（OCI-7・TASK-183.8 追補・#2315）。
//!
//! # 役割と呼び出し元
//!
//! `create_start::run_create` が `create_with_image` へ、`stop_delete::run_delete` が
//! `delete_releasing_image_ref` へ渡す。core は oci に依存しない（`docs/architecture.md`）ため、両方に
//! 依存できる上位の cli がトレイトの 5 メソッドを `ImageStore` の入口へ変換する。世代・確定・世代つき解除の
//! 原子性は `ImageStore` の排他の内側にあり、ここでは ID・digest・世代・エラーの変換だけを行う。
//!
//! # 置き場所
//!
//! 置き場所のオーナー判断は #2315 で未取得で、既存の依存辺（`cli → oci`・`cli → core`）だけで足りる cli に
//! 暫定で置いた。判断で別 crate に決まったら、この module をそのまま移せる（外部へ公開する型は無い）。
//!
//! # 排他の契約
//!
//! 各呼び出しは `ImageStore` の期限つきの排他（`IMAGE_STORE_LOCK_TIMEOUT`）を内側で取り、返る前に解放する。
//! `StateStore` の操作や start の所有ロックをまたいで保持しない（REPAIR-5）。
//!
//! # #854 との分担
//!
//! 状態作成まで進まず未確定のまま残った参照の回収は、oci の `reconcile_container_refs`（状態ストアの結果を
//! 照合用の probe で写す）と `release_unbound_container_ref_if` が担う。前提は「進行中の create が無いこと」で、
//! 常駐デーモンを持たない CLI にはその時点が無い。起動点と probe の配線は後続の issue の担当で、本アダプタは
//! トレイトの 5 メソッドだけを満たす（回収はトレイトに含めない）。delete で `--image-root` を省くと確定済みの
//! 参照が残り、回収は照合を待つ（安全側の誤り方で、データは消えない）。
//!
//! # 未実装（実装済みを装わない。REPAIR-3）
//!
//! - レイヤーの展開（本番の展開器）は #2377。展開器なしの `ContainerImage` を使うため、bundle の rootfs は展開済みの前提
//! - manifest の在庫の永続化は #2380。新しく起動した CLI のストアは在庫が空なので、`register` は常に `NOT_FOUND`
//! - タグ参照（`name:tag`）の解決はしない。`--image` は manifest digest だけを受ける

use fandhe_container_core::oci_runtime::{
    ContainerImageRefs, ImageManifestDigest, ImageRefGeneration, ImageRefRegistration,
    ImageRefRelease,
};
use fandhe_container_core::traits::{ContainerId, TraitError};
use fandhe_container_oci::error::OciError;
use fandhe_container_oci::image_management::{
    ContainerRefGeneration, ContainerRefId, ContainerRefRegistration, ContainerRefRelease,
    ImageStore,
};
use fandhe_container_oci::reference::Digest;

use super::image::{Stage, trait_failure};

/// `ImageStore` を借りて `ContainerImageRefs` を満たすアダプタ。
pub(super) struct StoreImageRefs<'a> {
    store: &'a ImageStore,
}

impl<'a> StoreImageRefs<'a> {
    pub(super) fn new(store: &'a ImageStore) -> Self {
        Self { store }
    }
}

fn fail(e: OciError) -> TraitError {
    trait_failure(&e, Stage::Refs)
}

fn ref_id(id: &ContainerId) -> Result<ContainerRefId, TraitError> {
    ContainerRefId::new(id.as_str()).map_err(fail)
}

fn release_result(r: ContainerRefRelease) -> ImageRefRelease {
    match r {
        ContainerRefRelease::Released(_) => ImageRefRelease::Released,
        _ => ImageRefRelease::NotRegistered,
    }
}

impl ContainerImageRefs for StoreImageRefs<'_> {
    fn register(
        &self,
        id: &ContainerId,
        manifest: &ImageManifestDigest,
    ) -> Result<ImageRefRegistration, TraitError> {
        let id = ref_id(id)?;
        let digest = Digest::parse(manifest.as_str()).map_err(fail)?;
        let r = self
            .store
            .register_container_ref(&id, &digest)
            .map_err(fail)?;
        Ok(match r {
            ContainerRefRegistration::Registered => ImageRefRegistration::Registered,
            _ => ImageRefRegistration::AlreadyRegistered,
        })
    }

    fn release(&self, id: &ContainerId) -> Result<ImageRefRelease, TraitError> {
        let r = self
            .store
            .release_container_ref(&ref_id(id)?)
            .map_err(fail)?;
        Ok(release_result(r))
    }

    fn bind(&self, id: &ContainerId) -> Result<ImageRefGeneration, TraitError> {
        let g = self.store.bind_container_ref(&ref_id(id)?).map_err(fail)?;
        Ok(ImageRefGeneration::from_raw(g.as_raw()))
    }

    fn registration(&self, id: &ContainerId) -> Result<Option<ImageRefGeneration>, TraitError> {
        let g = self
            .store
            .container_ref_registration(&ref_id(id)?)
            .map_err(fail)?;
        Ok(g.map(|g| ImageRefGeneration::from_raw(g.as_raw())))
    }

    fn release_if(
        &self,
        id: &ContainerId,
        expected: ImageRefGeneration,
    ) -> Result<ImageRefRelease, TraitError> {
        let r = self
            .store
            .release_container_ref_if(
                &ref_id(id)?,
                ContainerRefGeneration::from_raw(expected.as_raw()),
            )
            .map_err(fail)?;
        Ok(release_result(r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::ErrorCode;
    use fandhe_container_oci::image_management::ManifestComposition;

    const MANIFEST: &str =
        "sha256:a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
    const OTHER: &str = "sha256:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
    const CONFIG: &str = "sha256:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";

    /// 一意な一時ディレクトリ（終了時に削除）。
    pub(crate) struct Tmp(std::path::PathBuf);

    impl Tmp {
        pub(crate) fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("fandhe-cli-imgrefs-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("dir");
            Self(dir)
        }
        pub(crate) fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// 在庫に manifest を登録済みのストアを作る。
    fn seeded(root: &std::path::Path, manifests: &[&str]) -> ImageStore {
        let store = ImageStore::open(root).expect("open");
        for m in manifests {
            store
                .lock()
                .expect("lock")
                .register_manifest(
                    Digest::parse(m).expect("digest"),
                    ManifestComposition::new(Digest::parse(CONFIG).expect("config"), vec![])
                        .expect("comp"),
                )
                .expect("register manifest");
        }
        store
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).expect("id")
    }

    fn mdigest(s: &str) -> ImageManifestDigest {
        ImageManifestDigest::new(s).expect("manifest")
    }

    /// OCI-7: register の結果（新規・同一 manifest の再登録・別 manifest・在庫外）。
    #[test]
    fn oci7_register_outcomes() {
        let tmp = Tmp::new("register");
        let store = seeded(tmp.path(), &[MANIFEST, OTHER]);
        let refs = StoreImageRefs::new(&store);
        assert_eq!(
            refs.register(&cid("c1"), &mdigest(MANIFEST)).expect("new"),
            ImageRefRegistration::Registered
        );
        assert_eq!(
            refs.register(&cid("c1"), &mdigest(MANIFEST))
                .expect("again"),
            ImageRefRegistration::AlreadyRegistered
        );
        let err = refs
            .register(&cid("c1"), &mdigest(OTHER))
            .expect_err("different manifest");
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
        let missing = "sha256:d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2";
        let err = refs
            .register(&cid("c2"), &mdigest(missing))
            .expect_err("not in inventory");
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(err.message(), "image not found");
    }

    /// OCI-7: registration は bind 前が None、bind 後が Some(世代)。
    #[test]
    fn oci7_registration_is_none_until_bound() {
        let tmp = Tmp::new("bind");
        let store = seeded(tmp.path(), &[MANIFEST]);
        let refs = StoreImageRefs::new(&store);
        refs.register(&cid("c1"), &mdigest(MANIFEST))
            .expect("register");
        assert_eq!(refs.registration(&cid("c1")).expect("unbound"), None);
        let g = refs.bind(&cid("c1")).expect("bind");
        assert_eq!(refs.registration(&cid("c1")).expect("bound"), Some(g));
    }

    /// OCI-7: release_if は世代違いで外さず、一致で外す。外して登録し直すと世代は変わる。
    #[test]
    fn oci7_release_if_checks_generation_and_never_reissues() {
        let tmp = Tmp::new("gen");
        let store = seeded(tmp.path(), &[MANIFEST]);
        let refs = StoreImageRefs::new(&store);
        refs.register(&cid("c1"), &mdigest(MANIFEST))
            .expect("register");
        let g1 = refs.bind(&cid("c1")).expect("bind");
        let wrong = ImageRefGeneration::from_raw(g1.as_raw() + 1000);
        assert_eq!(
            refs.release_if(&cid("c1"), wrong).expect("wrong"),
            ImageRefRelease::NotRegistered
        );
        assert_eq!(refs.registration(&cid("c1")).expect("kept"), Some(g1));
        assert_eq!(
            refs.release_if(&cid("c1"), g1).expect("match"),
            ImageRefRelease::Released
        );
        assert_eq!(refs.registration(&cid("c1")).expect("gone"), None);

        refs.register(&cid("c1"), &mdigest(MANIFEST))
            .expect("re-register");
        let g2 = refs.bind(&cid("c1")).expect("bind again");
        assert_ne!(g1, g2);
        assert_eq!(
            refs.release(&cid("c1")).expect("release"),
            ImageRefRelease::Released
        );
        assert_eq!(
            refs.release(&cid("c1")).expect("twice"),
            ImageRefRelease::NotRegistered
        );
    }

    /// REPAIR-4・OCI-7: エラーの message は固定文言だけで、ID・パスを含まない。
    #[test]
    fn oci7_error_messages_are_fixed_strings() {
        let tmp = Tmp::new("msg");
        let store = seeded(tmp.path(), &[]);
        let refs = StoreImageRefs::new(&store);
        let id = cid("secret-container-id");
        let err = refs
            .register(&id, &mdigest(MANIFEST))
            .expect_err("not found");
        assert_eq!(err.message(), "image not found");
        let root = tmp.path().to_string_lossy().into_owned();
        assert!(!err.message().contains("secret-container-id"));
        assert!(!err.message().contains(&root));
        let err = refs.bind(&id).expect_err("no registration");
        assert!(!err.message().contains("secret-container-id"));
        assert!(!err.message().contains(&root));
    }
}
