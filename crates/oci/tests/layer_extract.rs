//! レイヤー tar 展開の公開 API 結合試験（TASK-52.3・OCI-1・#409）。
//! digest 検証（TASK-52.1）→ gzip 展開（TASK-52.2）→ tar 展開の連結を、外向き通信なしで具体値で確認する。

use std::fmt::Write as _;
use std::io::Write;

use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::layer::extract::{ExtractLimits, extract_layer_blob};
use fandhe_container_oci::layer::verify_blob_digest;
use fandhe_container_oci::reference::Digest;
use sha2::{Digest as _, Sha256};

fn sha(data: &[u8]) -> Digest {
    let mut s = String::from("sha256:");
    for b in Sha256::digest(data) {
        write!(s, "{b:02x}").unwrap();
    }
    Digest::parse(&s).unwrap()
}

fn layer_gz() -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, data) in [
        ("etc/os-release", &b"ID=test\n"[..]),
        ("bin/sh", &b"#!"[..]),
    ] {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o755);
        h.set_cksum();
        b.append_data(&mut h, name, data).unwrap();
    }
    let tar_bytes = b.into_inner().unwrap();
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(&tar_bytes).unwrap();
    e.finish().unwrap()
}

/// OCI-1: 検証済み blob を展開でき、内容と件数が一致する。上限超過は ResourceExhausted。
#[test]
fn oci1_verify_then_extract() {
    let z = layer_gz();
    let base = std::env::temp_dir().join(format!("fc-oci-tar-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let root = base.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let blob = base.join("layer.tar.gz");
    std::fs::write(&blob, &z).unwrap();

    verify_blob_digest(&blob, &sha(&z), 1 << 20).unwrap();
    let r =
        extract_layer_blob(&blob, &root, 1 << 20, ExtractLimits::new(10, 100, 1 << 30)).unwrap();
    assert_eq!((r.entries, r.bytes), (2, 10));
    assert_eq!(
        std::fs::read(root.join("etc/os-release")).unwrap(),
        b"ID=test\n"
    );
    assert_eq!(std::fs::read(root.join("bin/sh")).unwrap(), b"#!");

    let root2 = base.join("root2");
    std::fs::create_dir_all(&root2).unwrap();
    let e = extract_layer_blob(&blob, &root2, 1 << 20, ExtractLimits::new(1, 100, 1 << 30))
        .unwrap_err();
    assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    std::fs::remove_dir_all(&base).unwrap();
}
