//! Docker Hub への匿名トークン取得の実接続テスト（TASK-51.2・OCI-1 の受け入れ基準 1）。
//!
//! 外向き HTTPS が必要でレート制限の影響も受けるため既定のテスト集合から外す。
//! 実行: `cargo test -p fandhe-container-oci --test token_live -- --ignored`

use fandhe_container_oci::auth::RegistryAuth;
use fandhe_container_oci::reference::ImageReference;
use fandhe_container_oci::registry::{RegistryClient, RegistryClientConfig, RegistryEndpoint};
use std::time::Instant;

/// OCI-1: registry-1.docker.io で library/alpine の匿名 pull トークンを得られる。
#[test]
#[ignore = "requires outbound HTTPS access to registry-1.docker.io (OCI-1)"]
fn docker_hub_anonymous_token() {
    let client = RegistryClient::new(&RegistryClientConfig::default()).expect("client");
    let r = ImageReference::parse("alpine").expect("parse");
    let ep = RegistryEndpoint::new(r.registry().clone());
    match client
        .authenticate_anonymous(&ep, r.repository())
        .expect("token")
    {
        RegistryAuth::Bearer(t) => assert!(!t.is_expired(Instant::now())),
        other => panic!("expected bearer, got {other:?}"),
    }
}
