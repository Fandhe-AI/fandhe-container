//! レイヤー gzip 展開の公開 API 結合試験（TASK-52.2・OCI-1・#407）。
//! digest 検証（TASK-52.1）→ gzip 展開の連結と上限超過を、外向き通信なしで具体値で確認する。

use std::fmt::Write as _;
use std::io::Write;

use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::layer::{decompress_layer_to_writer, verify_blob_digest};
use fandhe_container_oci::reference::Digest;
use sha2::{Digest as _, Sha256};

#[path = "support/test_root.rs"]
mod test_root;

fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn sha(data: &[u8]) -> Digest {
    let mut s = String::from("sha256:");
    for b in Sha256::digest(data) {
        write!(s, "{b:02x}").unwrap();
    }
    Digest::parse(&s).unwrap()
}

/// OCI-1: digest 検証後に展開でき、内容が一致する。上限 - 1 では中断する。
#[test]
fn oci1_verify_then_decompress() {
    let tar_like: Vec<u8> = (0..2048u32).map(|i| (i % 253) as u8).collect();
    let z = gz(&tar_like);
    let dir = test_root::test_root("fc-oci-gz-it", "verify");
    let p = dir.join("layer.tar.gz");
    std::fs::write(&p, &z).unwrap();
    let v = verify_blob_digest(&p, &sha(&z), 1 << 20).unwrap();
    assert_eq!(v.size, z.len() as u64);
    let mut out = Vec::new();
    let r = decompress_layer_to_writer(&p, 4096, &mut out).unwrap();
    assert_eq!(r.size, 2048);
    assert_eq!(out, tar_like);
    let mut out = Vec::new();
    let e = decompress_layer_to_writer(&p, 2047, &mut out).unwrap_err();
    assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    assert_eq!(e.code().as_str(), "RESOURCE_EXHAUSTED");
    assert_eq!(out.len(), 2047);
}
