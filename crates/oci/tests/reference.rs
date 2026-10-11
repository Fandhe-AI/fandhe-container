//! イメージ参照の解析から接続先 URL の組み立てまでの結合試験（OCI-1・TASK-51.1）。
//!
//! 公開 API（`ImageReference`・`RegistryEndpoint`）だけを通し、実ネットワーク接続は使わない。
//! 期待値はすべて具体値で照合する。

use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::reference::{Digest, ImageReference, Reference};
use fandhe_container_oci::registry::RegistryEndpoint;

const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// OCI-1: Docker Hub の短縮形から manifest URL を組み立てる。
#[test]
fn docker_hub_short_name_builds_manifest_url() {
    let image = ImageReference::parse("alpine:3.20").expect("parse");
    let endpoint = RegistryEndpoint::new(image.registry().clone());
    assert_eq!(endpoint.base_url(), "https://registry-1.docker.io/v2/");
    assert_eq!(
        endpoint.manifest_url(image.repository(), image.reference()),
        "https://registry-1.docker.io/v2/library/alpine/manifests/3.20"
    );
}

/// OCI-1: digest 指定の参照から manifest・blob の URL を組み立てる。
#[test]
fn digest_reference_builds_manifest_and_blob_urls() {
    let input = format!("ghcr.io:8443/org/repo:v1@sha256:{HEX}");
    let image = ImageReference::parse(&input).expect("parse");
    let Reference::Digest(digest) = image.reference() else {
        panic!("digest must take precedence over tag");
    };
    assert_eq!(digest.as_str(), format!("sha256:{HEX}"));
    let endpoint = RegistryEndpoint::new(image.registry().clone());
    assert_eq!(
        endpoint.manifest_url(image.repository(), image.reference()),
        format!("https://ghcr.io:8443/v2/org/repo/manifests/sha256:{HEX}")
    );
    assert_eq!(
        endpoint.blob_url(image.repository(), digest),
        format!("https://ghcr.io:8443/v2/org/repo/blobs/sha256:{HEX}")
    );
}

/// OCI-1: 不正入力は InvalidArgument で拒否され、URL を組み立てられない。
#[test]
fn malformed_inputs_are_rejected() {
    let too_long = "a".repeat(5000);
    let bad = [
        "",
        "https://evil.example/app",
        "user@evil.example/app",
        "ghcr.io/org/../repo",
        "ghcr.io/Org/Repo",
        "ghcr.io/org/repo:",
        "ghcr.io/org/repo@sha256:abc",
        "ghcr.io/org/repo@md5:00",
        "ghcr.io:0/org/repo",
        "ghcr.io:65536/org/repo",
        "app name",
        too_long.as_str(),
    ];
    for input in bad {
        let err = ImageReference::parse(input).expect_err(input);
        assert_eq!(err.code(), OciErrorCode::InvalidArgument, "{input}");
    }
    assert_eq!(
        Digest::parse("sha256:ABCDEF").expect_err("upper").code(),
        OciErrorCode::InvalidArgument
    );
}

/// OCI-1: 長い連続ハイフンを含む repository を受理し、URL に反映する。
#[test]
fn long_hyphen_repository_is_accepted() {
    let name = format!("a{}b", "-".repeat(65));
    let image = ImageReference::parse(&format!("ghcr.io/{name}:t")).expect("parse");
    let endpoint = RegistryEndpoint::new(image.registry().clone());
    assert_eq!(
        endpoint.manifest_url(image.repository(), image.reference()),
        format!("https://ghcr.io/v2/{name}/manifests/t")
    );
}
