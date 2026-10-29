//! 取得済み blob の digest 検証の公開 API 結合試験（TASK-52.1・OCI-1・MS-4・REPAIR-12。外向き通信なし）。
//!
//! 外部 crate として `layer::verify_blob_digest` / `verify_blob_digest_with` を呼び、
//! 一致・改ざん拒否・サイズ上限・計装記録を具体値で照合する。

use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::instrument::{OciOpKind, OciOpOutcome, OciOpRecorder, OciOpSample};
use fandhe_container_oci::layer::{verify_blob_digest, verify_blob_digest_with};
use fandhe_container_oci::reference::Digest;
use std::sync::Mutex;

#[path = "support/test_root.rs"]
mod test_root;
use test_root::{TestRoot, test_root, test_root_at};

const ABC: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

#[derive(Debug, Default)]
struct Collect(Mutex<Vec<OciOpSample>>);

impl OciOpRecorder for Collect {
    fn record_oci_op(&self, s: &OciOpSample) {
        if let Ok(mut v) = self.0.lock() {
            v.push(*s);
        }
    }
}

fn tmp_dir(tag: &str) -> TestRoot {
    test_root("fc-oci-digest-it", tag)
}

/// OCI-1: 一致・改ざん・サイズ上限を公開 API だけで確認する。
#[test]
fn oci1_public_api_match_tamper_and_limit() {
    let d = tmp_dir("main");
    let p = d.join("blob");
    let expected = Digest::parse(ABC).expect("digest");

    std::fs::write(&p, b"abc").expect("write");
    let v = verify_blob_digest(&p, &expected, 3).expect("match");
    assert_eq!(v.digest.as_str(), ABC);
    assert_eq!(v.size, 3);

    std::fs::write(&p, b"abd").expect("write");
    let e = verify_blob_digest(&p, &expected, 3).expect_err("tampered");
    assert_eq!(e.code(), OciErrorCode::DataLoss);
    assert_eq!(e.code().as_str(), "DATA_LOSS");

    std::fs::write(&p, b"abc").expect("write");
    let e = verify_blob_digest(&p, &expected, 2).expect_err("limit");
    assert_eq!(e.code(), OciErrorCode::ResourceExhausted);

    let e = verify_blob_digest(&d.join("none"), &expected, 3).expect_err("missing");
    assert_eq!(e.code(), OciErrorCode::NotFound);
    std::fs::remove_dir_all(&d).expect("cleanup");
}

/// REPAIR-4: 計装 API が成功と DataLoss を 1 件ずつ記録する。
#[test]
fn oci1_public_api_records_samples() {
    let d = tmp_dir("rec");
    let p = d.join("blob");
    std::fs::write(&p, b"abc").expect("write");
    let c = Collect::default();
    let ok = Digest::parse(ABC).expect("digest");
    let bad = Digest::parse(&format!("sha256:{}", "0".repeat(64))).expect("digest");
    verify_blob_digest_with(&c, &p, &ok, 10).expect("ok");
    verify_blob_digest_with(&c, &p, &bad, 10).expect_err("mismatch");
    let v = c.0.lock().expect("lock");
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].kind(), OciOpKind::VerifyBlobDigest);
    assert_eq!(v[0].kind().as_str(), "oci.blob.verify");
    assert_eq!(v[0].outcome(), OciOpOutcome::Success);
    assert_eq!(v[1].outcome(), OciOpOutcome::Failure);
    assert_eq!(v[1].error_code(), Some(OciErrorCode::DataLoss));
    drop(v);
    std::fs::remove_dir_all(&d).expect("cleanup");
}

/// OCI-7・REPAIR-12（#3298）: 前回の残骸（ファイルと入れ子のディレクトリ）があっても空で作り直され、
/// 同名ファイルを排他作成でき、drop で消える。
#[test]
fn oci7_repair12_test_root_clears_stale_residue() {
    let p = std::env::temp_dir().join(format!("fc-oci-digest-it-residue-{}", std::process::id()));
    std::fs::create_dir_all(p.join("sub").join("inner")).expect("mkdir residue");
    std::fs::write(p.join("blob"), b"stale").expect("stale blob");
    std::fs::write(p.join("sub").join("inner").join("x"), b"stale").expect("stale inner");

    let root = test_root_at(p.clone());
    assert_eq!(std::fs::read_dir(&p).expect("read_dir").count(), 0);
    std::fs::File::create_new(root.join("blob")).expect("exclusive create over stale name");
    drop(root);
    assert!(!p.exists());
}
