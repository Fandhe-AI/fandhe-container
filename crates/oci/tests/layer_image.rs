//! `mediaType` による入口の選択と `rootfs.diff_ids` の突合の公開 API 結合試験（#2017・#2309・OCI-1・TASK-52 追補）。
//! image config の解析 → 件数・対応の照合 → gzip / 非圧縮の展開 → diff_id の突合を、外向き通信なしで具体値で確認する。
//!
//! 展開の入口は `VerifiedLayerBlob`（`open_blob_nofollow` で開き、同じハンドルで信頼条件と digest を確かめた値）だけを
//! 受ける。その構築は非 Unix で `Unimplemented` になる（API 自体が fail-closed）ため、blob を使う試験は
//! `#[cfg(unix)]` にする。特定 OS の試験を飛ばして CI を通すためではなく、非 Unix 側は
//! `oci1_verified_layer_blob_is_unimplemented_off_unix` と blob の要らないレイヤー 0 の試験で確かめる。

use std::fmt::Write as _;
#[cfg(unix)]
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use fandhe_container_oci::config::parse_image_config_rootfs;
use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::layer::VerifiedLayerBlob;
use fandhe_container_oci::layer::extract::{ExtractLimits, extract_image_layers};
#[cfg(unix)]
use fandhe_container_oci::layer::extract::{
    ExtractOptions, SpecialBitsPolicy, extract_image_layers_with_options, remove_extracted_tree,
};
#[cfg(unix)]
use fandhe_container_oci::layer::extract::{ImageLayer, image_layers_from};
#[cfg(unix)]
use fandhe_container_oci::manifest::{Descriptor, ParsedManifest, parse_manifest};
use fandhe_container_oci::reference::Digest;
use sha2::{Digest as _, Sha256};

#[cfg(unix)]
const TAR: &str = "application/vnd.oci.image.layer.v1.tar";
#[cfg(unix)]
const TAR_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
#[cfg(unix)]
const TAR_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

fn sha(data: &[u8]) -> Digest {
    let mut s = String::from("sha256:");
    for b in Sha256::digest(data) {
        write!(s, "{b:02x}").unwrap();
    }
    Digest::parse(&s).unwrap()
}

/// 通常ファイルだけの tar（非圧縮）。
#[cfg(unix)]
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

#[cfg(unix)]
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

    /// blob を 0600 で書き、パスを返す（umask に依らず信頼条件を満たす）。
    #[cfg(unix)]
    fn write_blob(&self, name: &str, bytes: &[u8]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let p = self.base.join(name);
        std::fs::write(&p, bytes).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    }

    /// blob を書き、自分の uid で信頼条件と圧縮後の digest を同じハンドルで検証した値を返す（呼び出し契約）。
    #[cfg(unix)]
    fn blob(&self, name: &str, bytes: &[u8]) -> VerifiedLayerBlob {
        let p = self.write_blob(name, bytes);
        VerifiedLayerBlob::open(&p, &sha(bytes), bytes.len() as u64, my_uid(&p)).unwrap()
    }
}

/// 試験が作ったファイルの所有者（= 自分の uid）。
#[cfg(unix)]
fn my_uid(p: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(p).unwrap().uid()
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
#[cfg(unix)]
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

#[cfg(unix)]
fn config_for(ids: &[&Digest]) -> Vec<u8> {
    let list = ids
        .iter()
        .map(|d| format!("\"{d}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"{{"rootfs":{{"type":"layers","diff_ids":[{list}]}}}}"#).into_bytes()
}

/// OCI-1: gzip と非圧縮を混ぜた 2 レイヤーが、diff_id の一致で重なって展開され、結果に diff_id が載る。
#[cfg(unix)]
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
#[cfg(unix)]
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
    let blobs = [&b1];
    let layers = image_layers_from(&desc, &blobs, &cfg).unwrap();
    extract_image_layers(&layers, &t.root(), 1 << 20, limits()).unwrap();
    assert_eq!(std::fs::read(t.root().join("f")).unwrap(), b"hello");
}

/// OCI-1: 展開後 tar が 1 バイト違えば DataLoss。最初のレイヤーなら root は空のまま。
#[cfg(unix)]
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
#[cfg(unix)]
#[test]
fn oci1_layer_count_mismatch_is_data_loss() {
    let t = Tmp::new("count");
    let t1 = tar_of(&[("f", b"x")]);
    let d1 = sha(&t1);
    let b1 = t.blob("l1.tar", &t1);
    let desc_one = descriptors(&[(TAR, sha(&t1), t1.len() as u64)]);
    let blobs = [&b1];
    let cfg_two = parse_image_config_rootfs(&config_for(&[&d1, &d1])).unwrap();
    let cfg_zero = parse_image_config_rootfs(&config_for(&[])).unwrap();
    for cfg in [&cfg_two, &cfg_zero] {
        let e = image_layers_from(&desc_one, &blobs, cfg).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        assert_eq!(e.message(), "layer count does not match rootfs.diff_ids");
    }
    let cfg_one = parse_image_config_rootfs(&config_for(&[&d1])).unwrap();
    let e = image_layers_from(&desc_one, &[], &cfg_one).unwrap_err();
    assert_eq!(e.code(), OciErrorCode::DataLoss);
}

/// OCI-1: zstd などの未対応 mediaType は Unimplemented で、root に触れる前に拒否する。
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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

/// OCI-1: レイヤー 0 のイメージは空の rootfs として正常に終わり、root には何も作らない。
#[test]
fn oci1_zero_layer_image_yields_empty_result() {
    let t = Tmp::new("zero");
    let r = extract_image_layers(&[], &t.root(), 1 << 20, limits()).unwrap();
    assert_eq!(r.len(), 0);
    assert!(root_is_empty(&t.root()));
}

/// OCI-1: レイヤー 0 でも root が空でなければ従来どおり拒否する。
#[test]
fn oci1_zero_layer_image_rejects_non_empty_root() {
    let t = Tmp::new("zero-dirty");
    std::fs::write(t.root().join("stale"), b"x").unwrap();
    let e = extract_image_layers(&[], &t.root(), 1 << 20, limits()).unwrap_err();
    assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
}

/// OCI-1: 存在しない root はレイヤー 0 でも拒否する。
#[test]
fn oci1_zero_layer_image_rejects_missing_root() {
    let t = Tmp::new("zero-missing");
    let missing = t.root().join("nope");
    assert!(extract_image_layers(&[], &missing, 1 << 20, limits()).is_err());
}

/// OCI-1: 非 Unix では `VerifiedLayerBlob` を構築できず、開かずに `Unimplemented`（fail-closed）。
#[cfg(not(unix))]
#[test]
fn oci1_verified_layer_blob_is_unimplemented_off_unix() {
    let t = Tmp::new("off-unix");
    let p = t.base.join("l1.tar");
    std::fs::write(&p, b"x").unwrap();
    let e = VerifiedLayerBlob::open(&p, &sha(b"x"), 1, 0).unwrap_err();
    assert_eq!(e.code(), OciErrorCode::Unimplemented);
}

/// OCI-1・#2309: 検証の後に同じパスへ別の内容を被せても、検証済みハンドルの内容が展開される。
#[cfg(unix)]
#[test]
fn oci1_blob_swapped_after_verification_is_not_extracted() {
    let t = Tmp::new("swap");
    let t1 = tar_of(&[("a", b"A1")]);
    let d1 = sha(&t1);
    let b1 = t.blob("l1.tar", &t1);
    // 検証後に rename で別の内容（同じ長さ）のファイルを被せる。
    let evil = t.write_blob("evil.tar", &tar_of(&[("a", b"B2")]));
    std::fs::rename(&evil, t.base.join("l1.tar")).unwrap();
    let layers = [ImageLayer::new(&b1, TAR, &d1)];
    let r = extract_image_layers(&layers, &t.root(), 1 << 20, limits()).unwrap();
    assert_eq!(std::fs::read(t.root().join("a")).unwrap(), b"A1");
    assert_eq!(r[0].diff_id, d1);
}

/// OCI-1・#2309: descriptor の digest か size が blob と違えば、I/O の前に DataLoss で root は空のまま。
#[cfg(unix)]
#[test]
fn oci1_image_layers_from_rejects_descriptor_blob_mismatch() {
    let t = Tmp::new("desc-mismatch");
    let t1 = tar_of(&[("f", b"x")]);
    let t2 = tar_of(&[("f", b"y")]);
    let d1 = sha(&t1);
    let b1 = t.blob("l1.tar", &t1);
    let cfg = parse_image_config_rootfs(&config_for(&[&d1])).unwrap();
    let blobs = [&b1];
    let wrong_digest = descriptors(&[(TAR, sha(&t2), t1.len() as u64)]);
    let wrong_size = descriptors(&[(TAR, sha(&t1), t1.len() as u64 + 1)]);
    for desc in [&wrong_digest, &wrong_size] {
        let e = image_layers_from(desc, &blobs, &cfg).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        assert_eq!(
            e.message(),
            "layer blob does not match the manifest descriptor"
        );
    }
    assert!(root_is_empty(&t.root()));
}

/// OCI-1・#2309: symlink の blob と所有者違いの blob は、検証済み値を作る段階で拒否される。
#[cfg(unix)]
#[test]
fn oci1_symlink_and_foreign_owner_blobs_are_rejected_before_extract() {
    let t = Tmp::new("untrusted");
    let t1 = tar_of(&[("f", b"x")]);
    let real = t.write_blob("real.tar", &t1);
    let link = t.base.join("link.tar");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let uid = my_uid(&real);
    let e = VerifiedLayerBlob::open(&link, &sha(&t1), t1.len() as u64, uid).unwrap_err();
    assert_eq!(e.code(), OciErrorCode::InvalidArgument);
    assert_eq!(e.message(), "blob path is not a regular file");
    let e = VerifiedLayerBlob::open(&real, &sha(&t1), t1.len() as u64, uid ^ 1).unwrap_err();
    assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "blob has an unexpected owner");
}

/// OCI-1・#2323: 既定の選択肢（Keep + Strip）の `_with_options` は `extract_image_layers` と同じ結果になる。
#[cfg(unix)]
#[test]
fn oci1_with_options_default_matches_extract_image_layers() {
    let t = Tmp::new("opts-default");
    let t1 = tar_of(&[("a", b"A1")]);
    let d1 = sha(&t1);
    let b1 = t.blob("l1.tar", &t1);
    let layers = [ImageLayer::new(&b1, TAR, &d1)];
    let r = extract_image_layers_with_options(
        &fandhe_container_oci::instrument::NoopOciOpRecorder,
        &layers,
        &t.root(),
        1 << 20,
        limits(),
        &ExtractOptions::new(),
    )
    .unwrap();
    assert_eq!(std::fs::read(t.root().join("a")).unwrap(), b"A1");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].diff_id, d1);
}

/// OCI-1・SEC-5・#2323: 不正な組み合わせ（PreserveIfChowned + Keep）は root に触れる前に InvalidArgument。
#[cfg(unix)]
#[test]
fn oci1_with_options_rejects_preserve_without_ownership_mapping() {
    let t = Tmp::new("opts-bad");
    let t1 = tar_of(&[("a", b"A1")]);
    let d1 = sha(&t1);
    let b1 = t.blob("l1.tar", &t1);
    let layers = [ImageLayer::new(&b1, TAR, &d1)];
    let opts = ExtractOptions::new().with_special_bits(SpecialBitsPolicy::PreserveIfChowned);
    for l in [&layers[..], &[][..]] {
        let e = extract_image_layers_with_options(
            &fandhe_container_oci::instrument::NoopOciOpRecorder,
            l,
            &t.root(),
            1 << 20,
            limits(),
            &opts,
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
        assert!(root_is_empty(&t.root()));
    }
}

/// OCI-1・#2323: 0555 のディレクトリと symlink を含む木を消せ、symlink の先は残る。
#[cfg(unix)]
#[test]
fn oci1_remove_extracted_tree_removes_readonly_dirs_and_keeps_symlink_target() {
    use std::os::unix::fs::PermissionsExt as _;
    let t = Tmp::new("remove");
    let outside = t.base.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("keep"), b"k").unwrap();
    let tree = t.base.join("tree");
    std::fs::create_dir_all(tree.join("etc/sub")).unwrap();
    std::fs::write(tree.join("etc/sub/f"), b"x").unwrap();
    std::os::unix::fs::symlink(&outside, tree.join("etc/link")).unwrap();
    std::fs::set_permissions(tree.join("etc/sub"), std::fs::Permissions::from_mode(0o555)).unwrap();
    std::fs::set_permissions(tree.join("etc"), std::fs::Permissions::from_mode(0o555)).unwrap();
    remove_extracted_tree(&tree).unwrap();
    assert!(!tree.exists());
    assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"k");
    // 存在しない木は冪等に成功する。
    remove_extracted_tree(&tree).unwrap();
}

/// OCI-1・SEC-5・#2598: 所有者に `r` が無い（0000）ディレクトリと、0555 の下の 0000 を含む木も消せ、外は残る。
#[cfg(unix)]
#[test]
fn oci1_remove_extracted_tree_removes_0000_dirs_and_keeps_outside() {
    use std::os::unix::fs::PermissionsExt as _;
    let t = Tmp::new("remove0000");
    let outside = t.base.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("keep"), b"k").unwrap();
    let tree = t.base.join("tree");
    std::fs::create_dir_all(tree.join("a/z")).unwrap();
    std::fs::create_dir_all(tree.join("ro/z")).unwrap();
    std::fs::write(tree.join("ro/z/f"), b"x").unwrap();
    std::os::unix::fs::symlink(&outside, tree.join("link")).unwrap();
    for (p, m) in [("ro/z", 0o000), ("ro", 0o555), ("a/z", 0o000), ("a", 0o000)] {
        std::fs::set_permissions(tree.join(p), std::fs::Permissions::from_mode(m)).unwrap();
    }
    remove_extracted_tree(&tree).unwrap();
    assert!(std::fs::symlink_metadata(&tree).is_err());
    assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"k");
}
