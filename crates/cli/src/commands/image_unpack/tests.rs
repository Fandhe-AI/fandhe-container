//! `StoreImageRootfsUnpacker` と `create --unpack` の配線の試験（OCI-7・OCI-1・OCI-2・SEC-1・#2377）。
//!
//! 実際の `ImageStore`（pull の公開経路で種入れ）・`FileStateStore`・`StoreImageRefs` を使い、core の
//! `create_with_image` を通す。期待値は具体値で書く。

// 本物の pull 経路で多層イメージを作る共有 fixture（結合試験 `binary_entry.rs` と共有）。
// Windows は `ImageStore` を開けない（入口で拒否）ため、fixture を使う試験は unix だけにある。
#[cfg(unix)]
#[path = "../../../tests/support/image_fixture.rs"]
mod image_fixture;

#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(unix)]
use fandhe_container_core::audit_log::FileAuditSink;
#[cfg(unix)]
use fandhe_container_core::observability::OpRecorder;
#[cfg(unix)]
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
#[cfg(unix)]
use fandhe_container_core::traits::{ContainerId, CreateRequest, ErrorCode};
use fandhe_container_oci::image_management::ImageStore;

#[cfg(unix)]
use super::*;
#[cfg(unix)]
use crate::commands::create_start::{CreateImage, Runtime, create_container_with_image_reclaiming};
#[cfg(unix)]
use crate::commands::image_refs::state_scope;
#[cfg(unix)]
use image_fixture::{Entry, seed_image, tar_of};

/// テスト用の一意な一時ディレクトリ（Drop で削除）。
struct TmpDir(
    PathBuf,
    // 保持が目的（drop で親を消す。tmpfiles の flock 走査から守る共有部品は Linux の試験用）。
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    crate::scratch_root::ScratchDir,
);

impl TmpDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        #[cfg(target_os = "linux")]
        let scratch = crate::scratch_root::ScratchDir::new(
            "fc-cli-unpack",
            std::time::Duration::from_secs(10),
        );
        #[cfg(target_os = "linux")]
        let base = scratch.path().to_path_buf();
        #[cfg(not(target_os = "linux"))]
        let base = std::env::temp_dir();
        let p = base.join(format!("fc-cli-unpack-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir(&p).expect("mkdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        #[cfg(target_os = "linux")]
        return Self(p, scratch);
        #[cfg(not(target_os = "linux"))]
        Self(p)
    }

    #[cfg(unix)]
    fn images(&self) -> ImageStore {
        let root = self.0.join("images");
        std::fs::create_dir_all(root.join("blobs").join("sha256")).expect("images");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        ImageStore::open(&root).expect("open images")
    }

    #[cfg(unix)]
    /// `rootfs/` の無い bundle（展開器が作る）。
    fn bundle(&self) -> PathBuf {
        let b = self.0.join("bundle");
        std::fs::create_dir_all(&b).expect("bundle");
        std::fs::write(
            b.join("config.json"),
            r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
        )
        .expect("config");
        b
    }

    #[cfg(unix)]
    fn state(&self) -> FileStateStore {
        let root = StateRoot::from_override(self.0.join("state")).expect("root");
        FileStateStore::open(root).expect("open state")
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn id(s: &str) -> ContainerId {
    ContainerId::new(s).expect("id")
}

#[cfg(unix)]
fn runtime(st: FileStateStore) -> Runtime {
    Runtime {
        audit: Box::new(FileAuditSink::in_state_store(&st)),
        store: Box::new(st),
        recorder: Arc::new(OpRecorder::new()),
    }
}

#[cfg(unix)]
fn create_image(
    _base: &TmpDir,
    rt: &Runtime,
    images: ImageStore,
    manifest: &Digest,
) -> CreateImage {
    CreateImage {
        store: images,
        manifest: ImageManifestDigest::new(manifest.as_str()).expect("manifest"),
        scope: state_scope(rt.store.as_ref()).expect("scope"),
        legacy_scope: None,
        unpack: true,
    }
}

#[cfg(unix)]
fn refs_of(images: &ImageStore, manifest: &Digest) -> usize {
    images
        .lock()
        .expect("lock")
        .manifest_references(manifest)
        .count()
}

#[cfg(unix)]
fn leftover_staging(bundle: &Path) -> Vec<String> {
    std::fs::read_dir(bundle)
        .expect("read bundle")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".fandhe-unpack-") || n == "rootfs")
        .collect()
}

#[cfg(target_os = "linux")]
mod linux {
    use super::image_fixture::three_layer_tars;
    use super::*;
    use fandhe_container_core::oci_runtime::{
        CgroupRemoval, ContainerCgroupRemover, delete_releasing_image_ref,
    };
    use fandhe_container_core::traits::{
        CgroupScope, DeleteRequest, GetStateRequest, StateRevision, TraitError,
    };

    /// 状態ストアを持たない cgroup 削除役（Created のコンテナは配置を持たないため呼ばれない）。
    struct NoCgroup;

    impl ContainerCgroupRemover for NoCgroup {
        fn scope(&self) -> Result<CgroupScope, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }

        fn remove(
            &self,
            _id: &ContainerId,
            _instance: StateRevision,
        ) -> Result<CgroupRemoval, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
    }

    /// 3 層（上位が下位を上書きし、whiteout を含む）の展開結果を具体値で照合し、delete で rootfs と参照が消える。
    #[test]
    fn oci7_oci1_2377_multi_layer_unpack_creates_rootfs_and_delete_removes_it() {
        let base = TmpDir::new("multi");
        let images = base.images();
        let seeded = seed_image(&images, "p1", &three_layer_tars(), None, true);
        let rt = runtime(base.state());
        let image = create_image(&base, &rt, images, &seeded.manifest);
        let bundle = base.bundle();
        let req = CreateRequest::new(id("c1"), bundle.clone()).expect("req");
        create_container_with_image_reclaiming(&rt, &image, &req).expect("create");

        let rootfs = bundle.join("rootfs");
        assert_eq!(std::fs::read(rootfs.join("etc/os")).expect("os"), b"upper");
        assert_eq!(std::fs::read(rootfs.join("app.txt")).expect("app"), b"app");
        assert_eq!(
            std::fs::read(rootfs.join("old/keep.txt")).expect("keep"),
            b"keep"
        );
        assert!(!rootfs.join("old/gone.txt").exists(), "whiteout は効く");
        assert!(!rootfs.join("old/.wh.gone.txt").exists());
        assert_eq!(refs_of(&image.store, &seeded.manifest), 1);
        let state = rt
            .store
            .get(&GetStateRequest::new(id("c1")))
            .expect("state");
        assert_eq!(
            state.status().state(),
            fandhe_container_core::traits::ContainerState::Created
        );

        // 展開器の戻り値（展開した層の数）。
        let unpack_rec = Arc::new(OpRecorder::new());
        let unpacker = StoreImageRootfsUnpacker::new(&image.store, &unpack_rec);
        let dir = base.0.join("direct");
        std::fs::create_dir(&dir).expect("dir");
        let link = open_dir_link(&dir);
        let unpacked = unpacker
            .unpack(&image.manifest, Path::new(&link.1))
            .expect("unpack");
        assert_eq!(unpacked.layers, 3);
        drop(link);
        // 検証は層ごとに 1 回、oci の計装が CLI の記録先へ届く（REPAIR-4）。
        let verify = unpack_rec
            .snapshot_op(
                &fandhe_container_core::observability::OpName::new("oci.blob.verify")
                    .expect("name"),
            )
            .expect("verify op recorded");
        assert_eq!((verify.success(), verify.failure()), (3, 0));

        let refs = crate::commands::image_refs::StoreImageRefs::new(&image.store, &image.scope);
        let del = DeleteRequest::new(id("c1"));
        delete_releasing_image_ref(rt.store.as_ref(), &rt.recorder, &NoCgroup, &refs, &del)
            .expect("delete");
        assert!(!rootfs.exists(), "delete は core 所有の rootfs を消す");
        assert_eq!(refs_of(&image.store, &seeded.manifest), 0);
    }

    /// 記録先 `rt.recorder` の操作の (成功, 失敗)。未記録は None。
    fn op_counts(rt: &Runtime, name: &str) -> Option<(u64, u64)> {
        let n = fandhe_container_core::observability::OpName::new(name).expect("name");
        rt.recorder
            .snapshot_op(&n)
            .map(|o| (o.success(), o.failure()))
    }

    /// REPAIR-4・OCI-1・#3042: 本番の create 経路の展開が `Runtime` の記録先へ oci.* を記録する。
    #[test]
    fn repair4_oci1_3042_unpack_via_create_records_oci_ops_on_runtime_recorder() {
        let base = TmpDir::new("rec-ok");
        let images = base.images();
        let seeded = seed_image(&images, "r1", &three_layer_tars(), None, true);
        let rt = runtime(base.state());
        let image = create_image(&base, &rt, images, &seeded.manifest);
        let bundle = base.bundle();
        let req = CreateRequest::new(id("c1"), bundle).expect("req");
        create_container_with_image_reclaiming(&rt, &image, &req).expect("create");
        assert_eq!(op_counts(&rt, "oci.blob.verify"), Some((3, 0)));
        assert_eq!(op_counts(&rt, "oci.layer.extract"), Some((3, 0)));
        // fixture の層は非圧縮 tar のため展開（decompress）は記録されない。
        assert_eq!(op_counts(&rt, "oci.layer.decompress"), None);
    }

    /// REPAIR-4・OCI-1・#3042: 展開の失敗も `Runtime` の記録先に失敗として数える。
    #[test]
    fn repair4_oci1_3042_unpack_failure_counts_failure_on_runtime_recorder() {
        let base = TmpDir::new("rec-fail");
        let images = base.images();
        let seeded = seed_image(&images, "r2", &three_layer_tars(), Some(1), true);
        let rt = runtime(base.state());
        let image = create_image(&base, &rt, images, &seeded.manifest);
        let req = CreateRequest::new(id("c1"), base.bundle()).expect("req");
        create_container_with_image_reclaiming(&rt, &image, &req).expect_err("must fail");
        assert_eq!(op_counts(&rt, "oci.blob.verify"), Some((3, 0)));
        assert_eq!(op_counts(&rt, "oci.layer.extract"), Some((1, 1)));
    }

    /// 2 層目の diff_id が食い違う（1 層目は展開済み）と DataLoss で失敗し、参照 0 件・rootfs と staging が残らない。
    #[test]
    fn oci7_2377_mid_layer_failure_rolls_back_ref_and_rootfs() {
        let base = TmpDir::new("midfail");
        let images = base.images();
        let seeded = seed_image(&images, "p2", &three_layer_tars(), Some(1), true);
        let rt = runtime(base.state());
        let image = create_image(&base, &rt, images, &seeded.manifest);
        let bundle = base.bundle();
        let req = CreateRequest::new(id("c1"), bundle.clone()).expect("req");
        let e = create_container_with_image_reclaiming(&rt, &image, &req).expect_err("must fail");
        assert_eq!(e.message(), "image layer failed verification");
        assert_eq!(refs_of(&image.store, &seeded.manifest), 0);
        assert_eq!(leftover_staging(&bundle), Vec::<String>::new());
        let got = rt.store.get(&GetStateRequest::new(id("c1")));
        assert_eq!(got.expect_err("no state").code(), ErrorCode::NotFound);
    }

    /// mediaType が未記録の在庫は FailedPrecondition で失敗し、参照 0 件に戻る。
    #[test]
    fn oci7_2377_unrecorded_media_types_fail_and_roll_back() {
        let base = TmpDir::new("nomt");
        let images = base.images();
        let seeded = seed_image(&images, "p3", &three_layer_tars(), None, false);
        let rt = runtime(base.state());
        let image = create_image(&base, &rt, images, &seeded.manifest);
        let bundle = base.bundle();
        let req = CreateRequest::new(id("c1"), bundle.clone()).expect("req");
        let e = create_container_with_image_reclaiming(&rt, &image, &req).expect_err("must fail");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(
            e.message().contains("pull the image again"),
            "{}",
            e.message()
        );
        assert_eq!(refs_of(&image.store, &seeded.manifest), 0);
        assert_eq!(leftover_staging(&bundle), Vec::<String>::new());
    }

    /// 既存の rootfs がある bundle では、展開器つきの create は ALREADY_EXISTS で失敗する。
    #[test]
    fn oci7_2377_unpack_refuses_existing_rootfs() {
        let base = TmpDir::new("exists");
        let images = base.images();
        let seeded = seed_image(
            &images,
            "p4",
            &[tar_of(&[Entry::File("a", b"a")])],
            None,
            true,
        );
        let rt = runtime(base.state());
        let image = create_image(&base, &rt, images, &seeded.manifest);
        let bundle = base.bundle();
        std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
        let req = CreateRequest::new(id("c1"), bundle.clone()).expect("req");
        let e = create_container_with_image_reclaiming(&rt, &image, &req).expect_err("must fail");
        assert_eq!(e.code(), ErrorCode::AlreadyExists);
        assert_eq!(refs_of(&image.store, &seeded.manifest), 0);
    }

    /// 残りの許容サイズを超える blob は、読む前に ResourceExhausted で拒否する（OCI-1・REPAIR-5）。
    #[test]
    fn oci1_2377_layer_over_remaining_budget_is_rejected_before_reading() {
        use fandhe_container_oci::error::OciErrorCode;
        use fandhe_container_oci::instrument::NoopOciOpRecorder;
        let base = TmpDir::new("budget");
        let images = base.images();
        let seeded = seed_image(
            &images,
            "p7",
            &[tar_of(&[Entry::File("a", b"a")])],
            None,
            true,
        );
        let layers = images.image_layers(&seeded.manifest).expect("layers");
        let layer = layers.layers().first().expect("layer");
        let e = images
            .open_verified_layer_bounded(&NoopOciOpRecorder, layer, 1)
            .expect_err("over budget");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        images
            .open_verified_layer_bounded(&NoopOciOpRecorder, layer, u64::MAX)
            .expect("within budget");
    }

    /// 期限は blob の検証より前から数える。期限 0 では検証（blob の open）に進まず Timeout（REPAIR-5）。
    #[test]
    fn repair5_2377_deadline_covers_blob_verification() {
        let base = TmpDir::new("deadline");
        let images = base.images();
        let seeded = seed_image(
            &images,
            "p8",
            &[tar_of(&[Entry::File("a", b"a")])],
            None,
            true,
        );
        let rec = Arc::new(OpRecorder::new());
        let unpacker = StoreImageRootfsUnpacker::new(&images, &rec);
        let manifest = ImageManifestDigest::new(seeded.manifest.as_str()).expect("manifest");
        let e = unpacker
            .unpack_within(&manifest, &base.0, Duration::ZERO)
            .expect_err("expired");
        assert_eq!(e.code(), OciErrorCode::Timeout);
        assert_eq!(e.message(), "image unpack deadline exceeded");
    }

    /// `/proc/self/fd/N` 以外の展開先は InvalidArgument（パスで開き直さない）。
    #[test]
    fn sec1_2377_unpack_rejects_non_fd_destination() {
        let base = TmpDir::new("path");
        let images = base.images();
        let seeded = seed_image(
            &images,
            "p5",
            &[tar_of(&[Entry::File("a", b"a")])],
            None,
            true,
        );
        let rec = Arc::new(OpRecorder::new());
        let unpacker = StoreImageRootfsUnpacker::new(&images, &rec);
        let manifest = ImageManifestDigest::new(seeded.manifest.as_str()).expect("manifest");
        let e = unpacker.unpack(&manifest, &base.0).expect_err("plain path");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        let unknown = ImageManifestDigest::new(Digest::sha256_of(b"nope").as_str()).expect("m");
        let e = unpacker.unpack(&unknown, &base.0).expect_err("unknown");
        assert_eq!(e.code(), ErrorCode::NotFound);
    }

    /// 開いたディレクトリの fd と、その `/proc/self/fd/N` の経路（fd は返した値の drop で閉じる）。
    fn open_dir_link(dir: &Path) -> (std::fs::File, String) {
        use std::os::fd::AsRawFd as _;
        let f = std::fs::File::open(dir).expect("open dir");
        let link = format!("/proc/self/fd/{}", f.as_raw_fd());
        (f, link)
    }
}

/// Linux 以外では、展開器つきの create は core が作成の前に Unimplemented で拒否し、何も作られない。
#[cfg(all(unix, not(target_os = "linux")))]
#[test]
fn oci7_2377_unpack_is_unimplemented_off_linux_and_creates_nothing() {
    let base = TmpDir::new("nonlinux");
    let images = base.images();
    let seeded = seed_image(
        &images,
        "p6",
        &[tar_of(&[Entry::File("a", b"a")])],
        None,
        true,
    );
    let rt = runtime(base.state());
    let image = create_image(&base, &rt, images, &seeded.manifest);
    let bundle = base.bundle();
    let req = CreateRequest::new(id("c1"), bundle.clone()).expect("req");
    let e: fandhe_container_core::oci_runtime::OciRuntimeError =
        create_container_with_image_reclaiming(&rt, &image, &req).expect_err("must fail");
    assert_eq!(e.code(), ErrorCode::Unimplemented);
    assert_eq!(refs_of(&image.store, &seeded.manifest), 0);
    assert_eq!(leftover_staging(&bundle), Vec::<String>::new());
}

/// Windows では `ImageStore::open` 自体が Windows ホストの恒久拒否（`FailedPrecondition`。#4333・#4377）を
/// 返すため、展開器つきの create に到達する前にストアを開けない（入口の拒否契約。OCI-7・3 OS 対応）。
#[cfg(not(unix))]
#[test]
fn oci7_2377_image_store_open_is_rejected_on_non_unix() {
    let base = TmpDir::new("windows");
    let root = base.0.join("images");
    std::fs::create_dir_all(root.join("blobs").join("sha256")).expect("images");
    let e = ImageStore::open(&root).expect_err("must fail");
    assert_eq!(
        e.code(),
        fandhe_container_oci::error::OciErrorCode::FailedPrecondition
    );
}
