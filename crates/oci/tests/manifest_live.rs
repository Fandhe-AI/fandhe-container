//! Docker Hub からの manifest 取得と platform 解決の実接続テスト（TASK-51.3・OCI-1・MS-4 の受け入れ基準）。
//!
//! 外向き HTTPS が必要でレート制限の影響も受けるため既定のテスト集合から外す。
//! 実行: `cargo test -p fandhe-container-oci --test manifest_live -- --ignored`

use fandhe_container_oci::manifest::Platform;
use fandhe_container_oci::reference::ImageReference;
use fandhe_container_oci::registry::{RegistryClient, RegistryClientConfig, RegistryEndpoint};

/// OCI-1: library/alpine の index からホスト platform の manifest を解決でき、layers が 1 件以上ある。
#[test]
#[ignore = "requires outbound HTTPS access to registry-1.docker.io (OCI-1)"]
fn docker_hub_alpine_resolves_host_platform() {
    let client = RegistryClient::new(&RegistryClientConfig::default()).expect("client");
    let r = ImageReference::parse("alpine").expect("parse");
    let ep = RegistryEndpoint::new(r.registry().clone());
    let auth = client
        .authenticate_anonymous(&ep, r.repository())
        .expect("token");
    let platform = Platform::host().expect("host platform");
    let resolved = client
        .fetch_manifest(&ep, r.repository(), r.reference(), &auth, &platform)
        .expect("manifest");
    assert!(resolved.from_index);
    assert!(!resolved.manifest.layers.is_empty());
}
