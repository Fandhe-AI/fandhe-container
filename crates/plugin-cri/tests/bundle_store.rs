//! 本番の bundle 供給の組み立て（`bundle_provider_in`）の結合試験（CRI-2・OCI-4・SEC-1・REPAIR-12。#2433）。
//!
//! 一時ディレクトリを状態ルートに見立てる（実際の `production()` は環境の状態ルートを使うため、ここでは触れない）。
//! 展開の中身の検証は `fandhe-container-cri` の `tests/bundle_image_rootfs.rs` が担う。unix 限定。

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use fandhe_container_cri::adapter::BundleRequest;
use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::runtime::v1::{
    ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig,
};
use fandhe_container_plugin_cri::adapter::bundle_provider_in;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "fandhe-plugin-cri-bundle-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&p).expect("mkdir");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).expect("chmod");
        // bundle の置き場は symlink を含む root を拒否する（SEC-1）。macOS の一時ディレクトリは
        // `/var` → `/private/var` の symlink 配下にあるため、正規パスに揃えてから渡す（#2537 と同じ扱い）。
        Self(fs::canonicalize(&p).expect("canonicalize"))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn mode(p: &std::path::Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn container(image: &str) -> ContainerConfig {
    ContainerConfig {
        metadata: Some(ContainerMetadata {
            name: "c".into(),
            attempt: 0,
        }),
        image: Some(ImageSpec {
            image: image.into(),
            ..Default::default()
        }),
        command: vec!["/bin/true".into()],
        ..Default::default()
    }
}

/// CRI-2・SEC-1: 置き場が 0700 で作られ、本番 provider が組み立てられる。
#[test]
fn cri2_bundle_store_directories_are_private() {
    let tmp = TempDir::new("ok");
    bundle_provider_in(&tmp.0).expect("provider");
    for rel in [".cri", ".cri/bundles", ".cri/images"] {
        assert_eq!(mode(&tmp.0.join(rel)), 0o700, "{rel}");
    }
    // 2 回目（既存の置き場）も成功する。
    bundle_provider_in(&tmp.0).expect("again");
}

/// CRI-2: 本番 provider は UNIMPLEMENTED の固定スタブではなく、未取得の image ID を NOT_FOUND にする。
/// 在庫を渡さない形ではタグを解決できず UNIMPLEMENTED。どちらも bundle は残らない。
#[test]
fn cri2_production_provider_reaches_the_image_cache() {
    let tmp = TempDir::new("codes");
    let p = bundle_provider_in(&tmp.0).expect("provider");
    let pod = PodSandboxConfig::default();
    let id = format!("sha256:{}", "a".repeat(64));
    let c = container(&id);
    let e = p
        .prepare(&BundleRequest::new("ctr1", "sb", &pod, &c))
        .unwrap_err();
    assert_eq!(e.code(), CriErrorCode::NotFound);
    let c = container("docker.io/library/alpine:3.20");
    let e = p
        .prepare(&BundleRequest::new("ctr2", "sb", &pod, &c))
        .unwrap_err();
    assert_eq!(e.code(), CriErrorCode::Unimplemented);
    assert_eq!(fs::read_dir(tmp.0.join(".cri/bundles")).unwrap().count(), 0);
}

/// SEC-1: group / other に権限のある既存の置き場、symlink の置き場は消さずに拒否する（fail-closed）。
#[test]
fn sec1_untrusted_bundle_store_is_rejected() {
    let tmp = TempDir::new("mode");
    fs::create_dir_all(tmp.0.join(".cri/bundles")).unwrap();
    fs::set_permissions(tmp.0.join(".cri"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(
        tmp.0.join(".cri/bundles"),
        fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    let e = bundle_provider_in(&tmp.0).map(|_| ()).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert!(tmp.0.join(".cri/bundles").is_dir());

    let tmp = TempDir::new("link");
    let real = tmp.0.join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(tmp.0.join(".cri")).unwrap();
    fs::set_permissions(tmp.0.join(".cri"), fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&real, tmp.0.join(".cri/bundles")).unwrap();
    let e = bundle_provider_in(&tmp.0).map(|_| ()).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert!(real.is_dir());
}

/// CRI-2・CRI-3（#2592）: 在庫を渡した形では、未知のタグ・短縮名は UNIMPLEMENTED ではなく NOT_FOUND になり、
/// 在庫へ登録したタグは image ID へ解決されてキャッシュの照会（未取得の NOT_FOUND）まで進む。bundle は残らない。
#[test]
fn cri3_provider_with_store_resolves_tags() {
    use fandhe_container_cri::image_service::{ImageRecord, ImageStore, InMemoryImageStore};
    use fandhe_container_plugin_cri::adapter::bundle_provider_with;
    use std::sync::Arc;

    let tmp = TempDir::new("store");
    let store = Arc::new(InMemoryImageStore::new());
    let p = bundle_provider_with(&tmp.0, Some(store.clone() as Arc<dyn ImageStore>), None)
        .expect("provider");
    let pod = PodSandboxConfig::default();

    let c = container("alpine:3.20");
    let e = p
        .prepare(&BundleRequest::new("ctr1", "sb", &pod, &c))
        .unwrap_err();
    assert_eq!(e.code(), CriErrorCode::NotFound);
    assert_eq!(e.message(), "image reference is not found");

    // 登録したタグは解決され、キャッシュに無いイメージは「キャッシュに無い」の NOT_FOUND になる（文言が変わる）。
    let id = format!("sha256:{}", "b".repeat(64));
    store
        .upsert(
            ImageRecord::new(
                id,
                vec!["docker.io/library/alpine:3.20".to_owned()],
                vec![],
                10,
            )
            .unwrap(),
        )
        .unwrap();
    let e = p
        .prepare(&BundleRequest::new("ctr2", "sb", &pod, &c))
        .unwrap_err();
    assert_eq!(e.code(), CriErrorCode::NotFound);
    assert_eq!(e.message(), "image is not present in the local cache");
    assert_eq!(fs::read_dir(tmp.0.join(".cri/bundles")).unwrap().count(), 0);
}
