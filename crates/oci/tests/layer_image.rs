//! `mediaType` による入口の選択と `rootfs.diff_ids` の突合の公開 API 結合試験（#2017・OCI-1・TASK-52 追補）。
//! image config の解析 → 件数の照合 → gzip / 非圧縮の展開 → diff_id の突合を、外向き通信なしで具体値で確認する。

use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};

use fandhe_container_oci::config::parse_image_config_rootfs;
use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::layer::extract::{
    ExtractLimits, ImageLayer, extract_image_layers, image_layers_from,
};
use fandhe_container_oci::layer::verify_blob_digest;
use fandhe_container_oci::manifest::{Descriptor, ParsedManifest, parse_manifest};
use fandhe_container_oci::reference::Digest;
use sha2::{Digest as _, Sha256};

const TAR: &str = "application/vnd.oci.image.layer.v1.tar";
const TAR_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const TAR_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

fn sha(data: &[u8]) -> Digest {
    let mut s = String::from("sha256:");
    for b in Sha256::digest(data) {
        write!(s, "{b:02x}").unwrap();
    }
    Digest::parse(&s).unwrap()
}

/// 通常ファイルだけの tar（非圧縮）。
fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, data) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, *data).unwrap();
    }
    b.into_inner().unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(data).unwrap();
    z.finish().unwrap()
}

struct Tmp {
    base: PathBuf,
}

impl Tmp {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!("fc-oci-image-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("root")).unwrap();
        Self { base }
    }

    fn root(&self) -> PathBuf {
        self.base.join("root")
    }

    /// blob を書き、圧縮後の digest を検証した上でパスを返す（呼び出し契約）。
    fn blob(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.base.join(name);
        std::fs::write(&p, bytes).unwrap();
        verify_blob_digest(&p, &sha(bytes), 1 << 20).unwrap();
        p
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn limits() -> ExtractLimits {
    ExtractLimits::new(100, 1 << 20, 1 << 30, 1 << 20)
}

fn root_is_empty(root: &Path) -> bool {
    std::fs::read_dir(root).unwrap().next().is_none()
}

/// 指定の layer descriptor を持つ manifest を `parse_manifest` で作り、layers を取り出す。
fn descriptors(layers: &[(&str, Digest, u64)]) -> Vec<Descriptor> {
    let zero = format!("sha256:{}", "0".repeat(64));
    let list = layers
        .iter()
        .map(|(m, d, n)| format!(r#"{{"mediaType":"{m}","digest":"{d}","size":{n}}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{zero}","size":1}},"layers":[{list}]}}"#
    );
    match parse_manifest(body.as_bytes(), None).unwrap() {
        ParsedManifest::Image(m) => m.layers,
        _ => panic!("expected an image manifest"),
    }
}

fn config_for(ids: &[&Digest]) -> Vec<u8> {
    let list = ids
        .iter()
        .map(|d| format!("\"{d}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"{{"rootfs":{{"type":"layers","diff_ids":[{list}]}}}}"#).into_bytes()
}

/// OCI-1: gzip と非圧縮を混ぜた 2 レイヤーが、diff_id の一致で重なって展開され、結果に diff_id が載る。
#[test]
fn oci1_mixed_gzip_and_plain_layers_extract_with_matching_diff_ids() {
    let t = Tmp::new("mixed");
    let t1 = tar_of(&[("a", b"A1"), ("b", b"B1")]);
    let t2 = tar_of(&[("a", b"A2")]);
    let (d1, d2) = (sha(&t1), sha(&t2));
    let b1 = t.blob("l1.tar.gz", &gzip(&t1));
    let b2 = t.blob("l2.tar", &t2);
    let layers = [
        ImageLayer::new(&b1, TAR_GZIP, &d1),
        ImageLayer::new(&b2, TAR, &d2),
    ];
    let r = extract_image_layers(&layers, &t.root(), 1 << 20, limits()).unwrap();
    assert_eq!(std::fs::read(t.root().join("a")).unwrap(), b"A2");
    assert_eq!(std::fs::read(t.root().join("b")).unwrap(), b"B1");
    assert_eq!(
        r.iter().map(|l| l.diff_id.clone()).collect::<Vec<_>>(),
        vec![d1, d2]
    );
}

/// OCI-1: config → 件数の照合 → 展開の一連の経路（Docker の mediaType を含む）。
#[test]
fn oci1_config_to_extract_end_to_end() {
    let t = Tmp::new("e2e");
    let t1 = tar_of(&[("f", b"hello")]);
    let d1 = sha(&t1);
    let gz = gzip(&t1);
    let b1 = t.blob("l1.tar.gz", &gz);
    let cfg = parse_image_config_rootfs(&config_for(&[&d1])).unwrap();
    let desc = descriptors(&[(
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        sha(&gz),
        gz.len() as u64,
    )]);
    let paths = [b1.as_path()];
    let layers = image_layers_from(&desc, &paths, &cfg).unwrap();
    extract_image_layers(&layers, &t.root(), 1 << 20, limits()).unwrap();
    assert_eq!(std::fs::read(t.root().join("f")).unwrap(), b"hello");
}

/// OCI-1: 展開後 tar が 1 バイト違えば DataLoss。最初のレイヤーなら root は空のまま。
#[test]
fn oci1_diff_id_mismatch_is_data_loss_and_root_untouched() {
    let t = Tmp::new("mismatch");
    let good = tar_of(&[("f", b"hello")]);
    let tampered = tar_of(&[("f", b"hellp")]);
    let expected = sha(&good);
    // 圧縮後の digest は改変後の blob に合わせて検証を通す（改変は diff_id でしか検出できない）。
    let b1 = t.blob("l1.tar.gz", &gzip(&tampered));
    let layers = [ImageLayer::new(&b1, TAR_GZIP, &expected)];
    let e = extract_image_layers(&layers, &t.root(), 1 << 20, limits()).unwrap_err();
    assert_eq!(e.code(), OciErrorCode::DataLoss);
    assert_eq!(e.message(), "layer diff_id does not match the image config");
    assert!(root_is_empty(&t.root()));
}

/// OCI-1: 件数の不一致（blob・descriptor・diff_ids のどれか）は I/O より前に DataLoss。
#[test]
fn oci1_layer_count_mismatch_is_data_loss() {
    let t = Tmp::new("count");
    let t1 = tar_of(&[("f", b"x")]);
    let d1 = sha(&t1);
    let b1 = t.blob("l1.tar", &t1);
    let desc_one = descriptors(&[(TAR, sha(&t1), t1.len() as u64)]);
    let paths = [b1.as_path()];
    let cfg_two = parse_image_config_rootfs(&config_for(&[&d1, &d1])).unwrap();
    let cfg_zero = parse_image_config_rootfs(&config_for(&[])).unwrap();
    for cfg in [&cfg_two, &cfg_zero] {
        let e = image_layers_from(&desc_one, &paths, cfg).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        assert_eq!(e.message(), "layer count does not match rootfs.diff_ids");
    }
    let cfg_one = parse_image_config_rootfs(&config_for(&[&d1])).unwrap();
    let e = image_layers_from(&desc_one, &[], &cfg_one).unwrap_err();
    assert_eq!(e.code(), OciErrorCode::DataLoss);
}

/// OCI-1: zstd などの未対応 mediaType は Unimplemented で、root に触れる前に拒否する。
#[test]
fn oci1_unsupported_media_type_is_rejected_before_any_io() {
    let t = Tmp::new("zstd");
    let t1 = tar_of(&[("f", b"x")]);
    let d1 = sha(&t1);
    let b1 = t.blob("l1.tar", &t1);
    // 2 層目だけ未対応でも、1 層目も展開しない。
    let layers = [
        ImageLayer::new(&b1, TAR, &d1),
        ImageLayer::new(&b1, TAR_ZSTD, &d1),
    ];
    let e = extract_image_layers(&layers, &t.root(), 1 << 20, limits()).unwrap_err();
    assert_eq!(e.code(), OciErrorCode::Unimplemented);
    assert!(root_is_empty(&t.root()));
}

/// OCI-1: gzip の blob を tar と宣言しても推測で開かず、成功しない。
#[test]
fn oci1_gzip_blob_declared_as_plain_tar_fails() {
    let t = Tmp::new("liar");
    let t1 = tar_of(&[("f", b"x")]);
    let d1 = sha(&t1);
    let b1 = t.blob("l1.tar.gz", &gzip(&t1));
    let layers = [ImageLayer::new(&b1, TAR, &d1)];
    assert!(extract_image_layers(&layers, &t.root(), 1 << 20, limits()).is_err());
}

/// OCI-1: 非圧縮レイヤーにも展開後サイズの上限が課される。
#[test]
fn oci1_plain_layer_size_limit_is_enforced() {
    let t = Tmp::new("limit");
    let t1 = tar_of(&[("f", &[0u8; 4096])]);
    let d1 = sha(&t1);
    let b1 = t.blob("l1.tar", &t1);
    let layers = [ImageLayer::new(&b1, TAR, &d1)];
    let e = extract_image_layers(&layers, &t.root(), 1024, limits()).unwrap_err();
    assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
}
