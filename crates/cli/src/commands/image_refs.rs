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
//! - manifest の在庫の永続化は #2380 で oci 側に実装済み（`ImageStore::lock` が読み直す）。ただし本番で在庫を埋める経路
//!   （pull → `ImageStore` の配線）が未実装のため、本番のストアの在庫は空で、`register` は常に `NOT_FOUND`
//! - タグ参照（`name:tag`）の解決はしない。`--image` は manifest digest だけを受ける

use fandhe_container_core::oci_runtime::{
    ContainerImageRefs, ImageManifestDigest, ImageRefGeneration, ImageRefRegistration,
    ImageRefRelease,
};
use fandhe_container_core::state_store::StateRoot;
use fandhe_container_core::traits::{ContainerId, TraitError};
use fandhe_container_oci::error::OciError;
use fandhe_container_oci::image_management::{
    ContainerRefGeneration, ContainerRefId, ContainerRefRegistration, ContainerRefRelease,
    ImageStore,
};
use fandhe_container_oci::reference::Digest;

use super::image::{Stage, trait_failure};

/// 状態ルートの識別子（参照キーの接頭辞）を作る。
///
/// イメージストアは状態ルートをまたいで共有できる（`--root` と `--image-root` は独立）。参照キーが
/// `ContainerId` だけだと、別の状態ルートの同名コンテナの delete が他方の参照を外してしまう（OCI-7 の
/// 使用中イメージ保護の欠落）。そこで正規化済みの状態ルートのパスから決定的な 32 桁の小文字 hex
/// （FNV-1a 64 を異なる初期値で 2 本。暗号学的ハッシュではなく、同一利用者の状態ルート同士の区別用）
/// を作り、キーを `<hex>.<id>` にする。
pub(super) fn state_scope(root: &StateRoot) -> String {
    let bytes = root.path().as_os_str().as_encoded_bytes();
    state_hash(bytes)
}

/// 32 桁の小文字 hex（FNV-1a 64 を異なる初期値で 2 本）。
fn state_hash(bytes: &[u8]) -> String {
    fn fnv1a(seed: u64, bytes: &[u8]) -> u64 {
        bytes.iter().fold(seed, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    }
    format!(
        "{:016x}{:016x}",
        fnv1a(0xcbf2_9ce4_8422_2325, bytes),
        fnv1a(0x8422_2325_cbf2_9ce4, bytes)
    )
}

/// `ImageStore` を借りて `ContainerImageRefs` を満たすアダプタ。参照キーは状態ルートごとに分ける。
pub(super) struct StoreImageRefs<'a> {
    store: &'a ImageStore,
    scope: &'a str,
}

impl<'a> StoreImageRefs<'a> {
    /// `scope` は [`state_scope`] の戻り値（`[0-9a-f]` のみ）。
    pub(super) fn new(store: &'a ImageStore, scope: &'a str) -> Self {
        Self { store, scope }
    }

    fn ref_id(&self, id: &ContainerId) -> Result<ContainerRefId, TraitError> {
        ContainerRefId::new(&ref_key(self.scope, id.as_str())).map_err(fail)
    }
}

/// 参照キーの上限（`ContainerRefId` と同じ 255 バイト）。
const REF_KEY_MAX: usize = 255;

/// 状態ルートの `scope` とコンテナ ID から参照キーを作る（create / delete / 停止中スナップショットで共有）。
///
/// 通常は `<scope>.<id>`。接頭辞を足すと 255 バイトを超える長い ID（223 バイト以上）は
/// `<scope>-<id の 32 桁 hex>` に畳む。区切りが `.` と `-` で違うため、通常形と畳んだ形は衝突しない。
/// 結果は常に `[A-Za-z0-9._-]` かつ 255 バイト以下で、変換は失敗しない。
pub(super) fn ref_key(scope: &str, id: &str) -> String {
    let plain = format!("{scope}.{id}");
    if plain.len() <= REF_KEY_MAX {
        return plain;
    }
    format!("{scope}-{}", state_hash(id.as_bytes()))
}

fn fail(e: OciError) -> TraitError {
    trait_failure(&e, Stage::Refs)
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
        let id = self.ref_id(id)?;
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
            .release_container_ref(&self.ref_id(id)?)
            .map_err(fail)?;
        Ok(release_result(r))
    }

    fn bind(&self, id: &ContainerId) -> Result<ImageRefGeneration, TraitError> {
        let g = self
            .store
            .bind_container_ref(&self.ref_id(id)?)
            .map_err(fail)?;
        Ok(ImageRefGeneration::from_raw(g.as_raw()))
    }

    fn registration(&self, id: &ContainerId) -> Result<Option<ImageRefGeneration>, TraitError> {
        let g = self
            .store
            .container_ref_registration(&self.ref_id(id)?)
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
                &self.ref_id(id)?,
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
    const SCOPE: &str = "00000000000000000000000000000001";
    const CONFIG: &str = "sha256:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";

    /// 一意な一時ディレクトリ（終了時に削除）。
    pub(crate) struct Tmp(std::path::PathBuf);

    impl Tmp {
        pub(crate) fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("fandhe-cli-imgrefs-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("dir");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
            }
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
        let refs = StoreImageRefs::new(&store, SCOPE);
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
        let refs = StoreImageRefs::new(&store, SCOPE);
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
        let refs = StoreImageRefs::new(&store, SCOPE);
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

    /// OCI-7: 状態ルートが違えば同じコンテナ ID でも参照は別物で、他方の delete は外さない。
    #[test]
    fn oci7_refs_are_scoped_per_state_root() {
        let tmp = Tmp::new("scope");
        let store = seeded(tmp.path(), &[MANIFEST]);
        let a = StoreImageRefs::new(&store, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let b = StoreImageRefs::new(&store, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        a.register(&cid("c1"), &mdigest(MANIFEST)).expect("a");
        let g = a.bind(&cid("c1")).expect("bind");
        assert_eq!(b.registration(&cid("c1")).expect("b none"), None);
        assert_eq!(
            b.release(&cid("c1")).expect("b release"),
            ImageRefRelease::NotRegistered
        );
        assert_eq!(a.registration(&cid("c1")).expect("kept"), Some(g));
    }

    /// OCI-7: 223 バイト以上・255 バイトの長い ID も register / bind / release が通り、別 ID と混ざらない。
    #[test]
    fn oci7_long_ids_round_trip() {
        let tmp = Tmp::new("long");
        let store = seeded(tmp.path(), &[MANIFEST]);
        let refs = StoreImageRefs::new(&store, SCOPE);
        for len in [222usize, 223, 254, 255] {
            let a = cid(&"a".repeat(len));
            let b = cid(&format!("{}b", "a".repeat(len - 1)));
            refs.register(&a, &mdigest(MANIFEST)).expect("register");
            let g = refs.bind(&a).expect("bind");
            assert_eq!(refs.registration(&a).expect("reg"), Some(g));
            assert_eq!(refs.registration(&b).expect("other"), None);
            assert_eq!(
                refs.release(&a).expect("release"),
                ImageRefRelease::Released
            );
        }
        assert!(ref_key(SCOPE, &"a".repeat(255)).len() <= 255);
        assert_ne!(
            ref_key(SCOPE, &"a".repeat(255)),
            ref_key(SCOPE, &"a".repeat(254))
        );
    }

    /// OCI-7: 状態ルートの識別子は決定的で、パスが違えば変わり、キー全体が ID の上限に収まる。
    #[test]
    fn oci7_state_scope_is_deterministic_and_distinct() {
        let r1 = StateRoot::from_override(std::env::temp_dir().join("a")).expect("r1");
        let r2 = StateRoot::from_override(std::env::temp_dir().join("b")).expect("r2");
        assert_eq!(state_scope(&r1), state_scope(&r1));
        assert_ne!(state_scope(&r1), state_scope(&r2));
        assert_eq!(state_scope(&r1).len(), 32);
    }

    /// REPAIR-4・OCI-7: エラーの message は固定文言だけで、ID・パスを含まない。
    #[test]
    fn oci7_error_messages_are_fixed_strings() {
        let tmp = Tmp::new("msg");
        let store = seeded(tmp.path(), &[]);
        let refs = StoreImageRefs::new(&store, SCOPE);
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
