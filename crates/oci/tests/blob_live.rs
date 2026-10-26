//! Docker Hub からの blob 取得の実接続テスト（TASK-51.4・OCI-1・MS-4 の受け入れ基準）。
//!
//! 外向き HTTPS が必要でレート制限の影響も受けるため既定のテスト集合から外す。Docker Hub は blob を CDN へ
//! リダイレクトするため、手動リダイレクト追従（Authorization 非送信・公開 IP のみ）の実網検証も兼ねる。
//! 実行: `cargo test -p fandhe-container-oci --test blob_live -- --ignored`

use fandhe_container_oci::manifest::Platform;
use fandhe_container_oci::reference::ImageReference;
use fandhe_container_oci::registry::{RegistryClient, RegistryClientConfig, RegistryEndpoint};

/// 指定イメージの config と全レイヤーを取得し、各ファイル長が descriptor.size と一致することを確認する。
fn fetch_all(image: &str) -> usize {
    let client = RegistryClient::new(&RegistryClientConfig::default()).expect("client");
    let r = ImageReference::parse(image).expect("parse");
    let ep = RegistryEndpoint::new(r.registry().clone());
    let auth = client
        .authenticate_anonymous(&ep, r.repository())
        .expect("token");
    let platform = Platform::host().expect("host platform");
    let resolved = client
        .fetch_manifest(&ep, r.repository(), r.reference(), &auth, &platform)
        .expect("manifest");
    let dir = std::env::temp_dir().join(format!(
        "fandhe-oci-blob-live-{}-{}",
        std::process::id(),
        image.replace(['/', ':'], "_")
    ));
    std::fs::create_dir_all(&dir).expect("mkdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let mut descriptors = vec![resolved.manifest.config.clone()];
    descriptors.extend(resolved.manifest.layers.iter().cloned());
    // 書き込み先は検査済み root の fd 起点の writer（#2765）。同じ digest は 1 回だけ取得する。
    let store = fandhe_container_oci::image_management::ImageStore::open(&dir).expect("store");
    let mut session = store.begin_pull_generated().expect("begin pull");
    let mut seen = std::collections::HashSet::new();
    for d in descriptors.iter() {
        if !seen.insert(d.digest.clone()) {
            continue;
        }
        let mut w = session.open_staged_blob(&d.digest).expect("writer");
        let got = client
            .fetch_blob(&ep, r.repository(), d, &auth, &mut w)
            .expect("blob");
        assert_eq!(got.size, d.size);
        w.commit().expect("commit");
        let v = session
            .verify_staged_blob(&d.digest, d.size)
            .expect("verify");
        assert_eq!(v.size, d.size);
    }
    session.abort().expect("abort");
    let _ = std::fs::remove_dir_all(&dir);
    resolved.manifest.layers.len()
}

/// OCI-1: 単一レイヤーの公開イメージ（alpine）の config とレイヤーを取得できる。
#[test]
#[ignore = "requires outbound HTTPS access to registry-1.docker.io (OCI-1)"]
fn docker_hub_alpine_single_layer_blobs() {
    assert_eq!(fetch_all("alpine"), 1);
}

/// OCI-1: 複数レイヤーの公開イメージ（nginx:alpine）の config と全レイヤーを取得できる。
#[test]
#[ignore = "requires outbound HTTPS access to registry-1.docker.io (OCI-1)"]
fn docker_hub_nginx_multi_layer_blobs() {
    assert!(fetch_all("nginx:alpine") > 1);
}
