//! plugin-cri の `create` / `delete` が OCI-7 のイメージ参照を登録・解除し、`RemoveImage` が使用中のイメージを
//! 拒否することの結合試験（OCI-7・CRI-2・CRI-1・REPAIR-12。#2791）。
//!
//! 1 つの在庫 root（oci の `ImageStore`）を `CoreLifecycleRuntime`・`PersistentImageStore`・`CriImageService` が共有する
//! 構成で、実際の `RemoveImage` の経路（`CriImageService::remove_image` → `PersistentImageStore::remove_resolving`）を通す。
//! レジストリにも root にも出ない（一時ディレクトリ・固定の manifest だけ）。`CreateContainer` から実行層への
//! annotation の受け渡し自体は cri 側の試験（`runtime_service_container`）が担保する。
#![cfg(unix)]

#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    CleanupOutcome, ContainerId, ContainerRuntime, CreateRequest, DeleteRequest, ErrorCode,
    GetStateRequest, StateStore,
};
use fandhe_container_cri::adapter::CRI_IMAGE_ID_ANNOTATION;
use fandhe_container_cri::image_service::{CriImageService, ImageRecord, ImageStore as _};
use fandhe_container_cri::runtime::v1::{self, image_service_server::ImageService as _};
use fandhe_container_oci::image_management::{
    ImageStore as OciStore, ImageTagSource, ManifestComposition, TagKey,
};
use fandhe_container_oci::reference::{Digest, RegistryHost, Repository, Tag};
use fandhe_container_plugin_cri::adapter::CoreLifecycleRuntime;
use fandhe_container_plugin_cri::image_inventory::PersistentImageStore;
use tonic::{Code, Request};

const MANIFEST: &str = "sha256:a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
const CONFIG: &str = "sha256:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
const IMAGE_ROOT_KEY: &str = "io.fandhe.container.image-root";

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp(tag: &str) -> Tmp {
    let d = exclusive_dir::create_in(&std::env::temp_dir(), &format!("fc-plugin-cri-{tag}"))
        .expect("tmp dir");
    Tmp(std::fs::canonicalize(d).expect("canonicalize"))
}

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).expect("id")
}

fn make_bundle(dir: &Path) -> PathBuf {
    let bundle = dir.join("bundle");
    std::fs::create_dir(&bundle).expect("bundle");
    std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
    std::fs::write(
        bundle.join("config.json"),
        r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .expect("config");
    bundle
}

/// 在庫 root（0700）を作り、manifest を 1 件登録して CRI の記録も 1 件入れる。
struct Fixture {
    _tmp: Tmp,
    dir: PathBuf,
    images_root: PathBuf,
    bundle: PathBuf,
    persistent: Arc<PersistentImageStore>,
}

fn fixture(tag: &str) -> Fixture {
    let t = tmp(tag);
    let dir = t.0.clone();
    let bundle = make_bundle(&dir);
    let images_root = {
        let p = dir.join("images");
        exclusive_mkdir(&p);
        p
    };
    let oci = OciStore::open(&images_root).expect("open oci");
    oci.lock()
        .expect("lock")
        .register_manifest(
            Digest::parse(MANIFEST).expect("manifest"),
            ManifestComposition::new(Digest::parse(CONFIG).expect("config"), vec![]).expect("comp"),
        )
        .expect("register manifest");
    // 下位メソッドの登録は保存されない（次の排他取得でディスクに置き換わる）。在庫・タグを変える入口の `tag_image` が
    // 在庫全体を 1 回保存するので、それを使って別ストア（runtime が開く）から見える状態にする。
    oci.tag_image(
        &ImageTagSource::Manifest(Digest::parse(MANIFEST).expect("manifest")),
        TagKey::new(
            RegistryHost::parse("registry.example").expect("host"),
            Repository::parse("lib/app").expect("repo"),
            Tag::parse("seed").expect("tag"),
        ),
    )
    .expect("persist inventory");
    let persistent = Arc::new(PersistentImageStore::open(&images_root).expect("persistent"));
    persistent
        .upsert(
            ImageRecord::new(
                CONFIG,
                vec!["docker.io/library/busybox:1.36".to_owned()],
                vec![],
                4096,
            )
            .expect("record"),
        )
        .expect("upsert");
    Fixture {
        _tmp: t,
        dir,
        images_root,
        bundle,
        persistent,
    }
}

fn exclusive_mkdir(p: &Path) {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(p)
        .expect("mkdir 0700");
}

fn store(dir: &Path) -> Arc<dyn StateStore> {
    let root = StateRoot::resolve(Some(dir.join("state"))).expect("root");
    Arc::new(FileStateStore::open(root).expect("open state"))
}

fn runtime(dir: &Path, images_root: &Path) -> CoreLifecycleRuntime {
    CoreLifecycleRuntime::new(store(dir))
        .with_image_store_root(images_root.to_path_buf())
        .with_cleanup_warning_sink(Arc::new(|_| {}))
}

fn create_req(f: &Fixture, id: &str, image_id: Option<&str>) -> CreateRequest {
    let req = CreateRequest::new(cid(id), f.bundle.clone()).expect("req");
    match image_id {
        Some(v) => req.with_annotations(
            fandhe_container_core::traits::Annotations::new([(
                CRI_IMAGE_ID_ANNOTATION.to_owned(),
                v.to_owned(),
            )])
            .expect("annotations"),
        ),
        None => req,
    }
}

fn container_refs(images_root: &Path) -> Vec<String> {
    let oci = OciStore::open(images_root).expect("open oci");
    let guard = oci.lock().expect("lock");
    guard
        .manifest_references(&Digest::parse(MANIFEST).expect("manifest"))
        .containers
        .iter()
        .map(|c| c.as_str().to_owned())
        .collect()
}

async fn remove_image(svc: &CriImageService, reference: &str) -> Result<(), tonic::Status> {
    svc.remove_image(Request::new(v1::RemoveImageRequest {
        image: Some(v1::ImageSpec {
            image: reference.to_owned(),
            ..Default::default()
        }),
    }))
    .await
    .map(|_| ())
}

async fn list_count(svc: &CriImageService) -> usize {
    svc.list_images(Request::new(v1::ListImagesRequest::default()))
        .await
        .expect("list")
        .into_inner()
        .images
        .len()
}

/// OCI-7・CRI-2・CRI-1（#2791）: CRI 経由で作ったコンテナが使うイメージの `RemoveImage` は拒否され、
/// `RemoveContainer`（delete）の後は同じ `RemoveImage` が成功する。
#[tokio::test]
async fn oci7_cri2_2791_remove_image_is_refused_while_container_exists() {
    let f = fixture("refs-flow");
    let rt = runtime(&f.dir, &f.images_root);
    let svc = CriImageService::with_store(Arc::clone(&f.persistent) as _);

    rt.create(&create_req(&f, "c1", Some(CONFIG)))
        .expect("create with image");

    // 参照は `<scope(32 桁 hex)>.c1` で 1 件登録・確定され、状態記録に image root が残る。
    let refs = container_refs(&f.images_root);
    assert_eq!(refs.len(), 1, "{refs:?}");
    let (scope, id) = refs[0].split_once('.').expect("scope.id");
    assert_eq!(id, "c1");
    assert_eq!(scope.len(), 32);
    assert!(
        scope
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    let st = store(&f.dir);
    let record = st.get(&GetStateRequest::new(cid("c1"))).expect("state");
    assert_eq!(
        record.annotations().get(IMAGE_ROOT_KEY),
        f.images_root.to_str()
    );

    // RemoveImage は ID でもタグでも FAILED_PRECONDITION（固定文言）。記録は 1 件残る。
    for reference in [CONFIG, "docker.io/library/busybox:1.36"] {
        let e = remove_image(&svc, reference).await.expect_err("in use");
        assert_eq!(e.code(), Code::FailedPrecondition, "{reference}");
        assert_eq!(e.message(), "image is in use by a container");
    }
    assert_eq!(list_count(&svc).await, 1);

    // delete は参照を外し、応答の image_ref は Removed。
    let resp = rt.delete(&DeleteRequest::new(cid("c1"))).expect("delete");
    assert_eq!(resp.image_ref(), CleanupOutcome::Removed);
    assert!(container_refs(&f.images_root).is_empty());

    remove_image(&svc, CONFIG)
        .await
        .expect("remove after delete");
    assert_eq!(list_count(&svc).await, 0);
}

/// OCI-7（#2791）: タグだけの参照（コンテナ参照なし）では `RemoveImage` を拒否しない。
#[tokio::test]
async fn oci7_cri2_2791_tag_only_reference_does_not_block_remove() {
    let f = fixture("refs-tag-only");
    let svc = CriImageService::with_store(Arc::clone(&f.persistent) as _);
    remove_image(&svc, CONFIG).await.expect("remove");
    assert_eq!(list_count(&svc).await, 0);
}

/// OCI-7（#2791）: annotation の無い create / delete は参照を作らず、`image_ref` は `NotApplicable`。
#[test]
fn oci7_cri2_2791_create_without_image_id_registers_nothing() {
    let f = fixture("refs-none");
    let rt = runtime(&f.dir, &f.images_root);
    rt.create(&create_req(&f, "c1", None)).expect("create");
    assert!(container_refs(&f.images_root).is_empty());
    let resp = rt.delete(&DeleteRequest::new(cid("c1"))).expect("delete");
    assert_eq!(resp.image_ref(), CleanupOutcome::NotApplicable);
}

/// OCI-7（#2791・fail-closed）: 在庫に無い image ID の create は `NOT_FOUND` で、状態も参照も作らない。
/// 不正な形式の image ID は `INVALID_ARGUMENT`。
#[test]
fn oci7_cri2_2791_create_with_unknown_or_invalid_image_id_fails_closed() {
    let f = fixture("refs-unknown");
    let rt = runtime(&f.dir, &f.images_root);
    let other = format!("sha256:{}", "d".repeat(64));
    let e = rt
        .create(&create_req(&f, "c1", Some(&other)))
        .expect_err("unknown");
    assert_eq!(
        (e.code(), e.message()),
        (ErrorCode::NotFound, "image not found")
    );
    let e = rt
        .create(&create_req(&f, "c2", Some("../etc/passwd")))
        .expect_err("invalid");
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert!(container_refs(&f.images_root).is_empty());
    for id in ["c1", "c2"] {
        let e = store(&f.dir)
            .get(&GetStateRequest::new(cid(id)))
            .expect_err("no state");
        assert_eq!(e.code(), ErrorCode::NotFound, "{id}");
    }
}

/// OCI-7（#2791・fail-closed）: 記録した image root が設定済みの root と食い違う delete は状態を消さずに
/// `FAILED_PRECONDITION` で失敗し、正しい root に戻すと消せる。
#[test]
fn oci7_cri2_2791_delete_with_mismatched_image_root_keeps_state() {
    let f = fixture("refs-mismatch");
    let rt = runtime(&f.dir, &f.images_root);
    rt.create(&create_req(&f, "c1", Some(CONFIG)))
        .expect("create");

    let other_root = f.dir.join("other-images");
    exclusive_mkdir(&other_root);
    let wrong = runtime(&f.dir, &other_root);
    let e = wrong
        .delete(&DeleteRequest::new(cid("c1")))
        .expect_err("mismatch");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(
        e.message(),
        "recorded image store root does not match the configured one"
    );
    store(&f.dir)
        .get(&GetStateRequest::new(cid("c1")))
        .expect("state kept");
    assert_eq!(container_refs(&f.images_root).len(), 1);

    let resp = rt.delete(&DeleteRequest::new(cid("c1"))).expect("delete");
    assert_eq!(resp.image_ref(), CleanupOutcome::Removed);
    assert!(container_refs(&f.images_root).is_empty());
}
