//! `ImageStore::image_layers` / `open_verified_layer` と `ExtractRoot::open_proc_fd_link` の結合試験
//! （OCI-7・OCI-1・SEC-1・#2377）。
//!
//! 種入れは pull の本物の経路（`begin_pull` → `open_staged_blob` → `commit` → `verify_staged_blob` → `publish`）で
//! 行い、公開 API だけを通して具体値で照合する。

// Windows ホストは設計上 `ImageStore` を開けない（#4333・#2428 案 C）ため unix に限る。
#![cfg(unix)]

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

#[path = "support/test_root.rs"]
mod test_root;

use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::image_management::{
    ImageStore, ManifestComposition, PullId, PullPublishRequest,
};
use fandhe_container_oci::reference::Digest;
use sha2::{Digest as _, Sha256};

const TAR: &str = "application/vnd.oci.image.layer.v1.tar";
const TAR_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

fn sha_of(data: &[u8]) -> Digest {
    let mut hex = String::new();
    for b in Sha256::digest(data) {
        hex.push_str(&format!("{b:02x}"));
    }
    Digest::parse(&format!("sha256:{hex}")).expect("digest")
}

fn hex(d: &Digest) -> String {
    d.as_str().trim_start_matches("sha256:").to_string()
}

struct Root(test_root::TestRoot);

impl Root {
    fn new(tag: &str) -> Self {
        // 排他作成（0700）の共有部品。既存の名前は消さず辿らない。Drop は自分が作ったパスだけを消す。
        let r = test_root::test_root("fc-oci-layers", tag);
        fs::create_dir_all(r.join("blobs").join("sha256")).expect("mkdir");
        Root(r)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn blob(&self, d: &Digest) -> PathBuf {
        self.0.join("blobs").join("sha256").join(hex(d))
    }
}

fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, data) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, *data).expect("append");
    }
    b.into_inner().expect("tar")
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(data).expect("gzip");
    z.finish().expect("gzip")
}

/// 3 層（非圧縮 2 + gzip 1）のイメージ。
struct Fixture {
    manifest: Digest,
    config: Digest,
    layers: Vec<Digest>,
    diff_ids: Vec<Digest>,
}

/// config 本文を作る。`diff_ids` を差し替えて件数や内容の不一致を再現できる。
fn config_body(diff_ids: &[Digest]) -> Vec<u8> {
    let ids: Vec<String> = diff_ids
        .iter()
        .map(|d| format!("\"{}\"", d.as_str()))
        .collect();
    format!(
        r#"{{"rootfs":{{"type":"layers","diff_ids":[{}]}}}}"#,
        ids.join(",")
    )
    .into_bytes()
}

fn stage(s: &mut fandhe_container_oci::image_management::PullSession, d: &Digest, data: &[u8]) {
    let mut w = s.open_staged_blob(d).expect("writer");
    w.write_all(data).expect("write");
    w.commit().expect("commit");
    s.verify_staged_blob(d, 1 << 20).expect("verify");
}

/// 本物の pull 経路で種入れする。`media_types` を `None` にすると mediaType 未記録（v1 相当）で登録する。
fn seed(
    store: &ImageStore,
    id: &str,
    media_types: Option<Vec<&str>>,
    diff_override: Option<Vec<Digest>>,
) -> Fixture {
    let tars = [
        tar_of(&[("a.txt", b"one")]),
        tar_of(&[("b.txt", b"two")]),
        tar_of(&[("c.txt", b"three")]),
    ];
    let diff_ids: Vec<Digest> = tars.iter().map(|t| sha_of(t)).collect();
    let blobs = [tars[0].clone(), tars[1].clone(), gzip(&tars[2])];
    let layers: Vec<Digest> = blobs.iter().map(|b| sha_of(b)).collect();
    let config = config_body(diff_override.as_deref().unwrap_or(&diff_ids));
    let config_digest = sha_of(&config);
    let mut s = store
        .begin_pull(PullId::new(id).expect("id"))
        .expect("begin");
    stage(&mut s, &config_digest, &config);
    for (d, b) in layers.iter().zip(&blobs) {
        stage(&mut s, d, b);
    }
    let mut comp = ManifestComposition::new(config_digest.clone(), layers.clone()).expect("comp");
    if let Some(m) = media_types {
        comp = comp
            .with_layer_media_types(m.into_iter().map(str::to_owned).collect())
            .expect("media types");
    }
    let manifest = sha_of(format!("manifest-{id}").as_bytes());
    s.publish(PullPublishRequest::new(manifest.clone(), comp))
        .expect("publish");
    Fixture {
        manifest,
        config: config_digest,
        layers,
        diff_ids,
    }
}

/// OCI-7・OCI-1: 3 層の digest・mediaType・diff_id が manifest の並びで返り、blob_path は `blobs/sha256/<hex>`。
#[test]
fn oci7_oci1_2377_image_layers_returns_ordered_layers() {
    let root = Root::new("ok");
    let store = ImageStore::open(root.path()).expect("open");
    let f = seed(&store, "l-1", Some(vec![TAR, TAR, TAR_GZIP]), None);
    let got = store.image_layers(&f.manifest).expect("layers");
    let canonical_root = fs::canonicalize(root.path()).expect("canonicalize root");
    assert_eq!(got.manifest(), &f.manifest);
    assert_eq!(got.config(), &f.config);
    assert_eq!(got.layers().len(), 3);
    let types: Vec<&str> = got.layers().iter().map(|l| l.media_type()).collect();
    assert_eq!(types, vec![TAR, TAR, TAR_GZIP]);
    for (i, l) in got.layers().iter().enumerate() {
        assert_eq!(l.digest(), &f.layers[i]);
        assert_eq!(l.diff_id(), &f.diff_ids[i]);
        // ストアは root を正規化して持つ（macOS の一時ディレクトリは `/var` -> `/private/var` の symlink）ため、
        // 期待値も正規化した root から組み立てる。
        assert_eq!(
            l.blob_path(),
            canonical_root
                .join("blobs")
                .join("sha256")
                .join(hex(&f.layers[i]))
        );
    }
    // 排他を保持して返さない（直後に別の lock が取れる）。
    drop(store.lock().expect("lock after image_layers"));
}

/// OCI-7: 在庫に無い manifest は NotFound。
#[test]
fn oci7_2377_image_layers_unknown_manifest_is_not_found() {
    let root = Root::new("nf");
    let store = ImageStore::open(root.path()).expect("open");
    let e = store.image_layers(&sha_of(b"nope")).expect_err("missing");
    assert_eq!(e.code(), OciErrorCode::NotFound);
}

/// OCI-7: mediaType が未記録（v1 相当）の manifest は FailedPrecondition。
#[test]
fn oci7_2377_image_layers_without_media_types_is_failed_precondition() {
    let root = Root::new("nomt");
    let store = ImageStore::open(root.path()).expect("open");
    let f = seed(&store, "l-2", None, None);
    let e = store.image_layers(&f.manifest).expect_err("unrecorded");
    assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
}

/// OCI-1・SEC-1: config blob を書き換える（digest 不一致）と DataLoss。
#[test]
fn oci1_2377_image_layers_tampered_config_is_data_loss() {
    let root = Root::new("cfgdig");
    let store = ImageStore::open(root.path()).expect("open");
    let f = seed(&store, "l-3", Some(vec![TAR, TAR, TAR_GZIP]), None);
    let p = root.blob(&f.config);
    let mut body = fs::read(&p).expect("read");
    body.push(b' ');
    fs::write(&p, body).expect("tamper");
    let e = store.image_layers(&f.manifest).expect_err("tampered");
    assert_eq!(e.code(), OciErrorCode::DataLoss);
}

/// OCI-1: config の diff_ids の件数が layers と違うと DataLoss。
#[test]
fn oci1_2377_image_layers_diff_id_count_mismatch_is_data_loss() {
    let root = Root::new("cnt");
    let store = ImageStore::open(root.path()).expect("open");
    let two = vec![sha_of(b"x"), sha_of(b"y")];
    let f = seed(&store, "l-4", Some(vec![TAR, TAR, TAR_GZIP]), Some(two));
    let e = store.image_layers(&f.manifest).expect_err("mismatch");
    assert_eq!(e.code(), OciErrorCode::DataLoss);
}

/// SEC-1: config が group 書き込み可だと信頼条件違反で FailedPrecondition（読まない）。
#[test]
fn sec1_2377_image_layers_untrusted_config_is_rejected() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = Root::new("trust");
    let store = ImageStore::open(root.path()).expect("open");
    let f = seed(&store, "l-5", Some(vec![TAR, TAR, TAR_GZIP]), None);
    fs::set_permissions(root.blob(&f.config), fs::Permissions::from_mode(0o666)).expect("chmod");
    let e = store.image_layers(&f.manifest).expect_err("untrusted");
    assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
}

/// OCI-7・OCI-1・STACK-8・#4638: `image_process_config` は在庫の config の `config` 節（無ければ空）を返し、
/// 在庫に無い manifest は NotFound、書き換えた config は DataLoss、group 書き込み可の config は FailedPrecondition。
#[test]
fn oci7_4638_image_process_config_reads_verified_config() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = Root::new("proc");
    let store = ImageStore::open(root.path()).expect("open");
    let f = seed(&store, "p-1", Some(vec![TAR, TAR, TAR_GZIP]), None);
    let got = store.image_process_config(&f.manifest).expect("process");
    assert!(got.entrypoint().is_empty());
    assert!(got.cmd().is_empty());
    assert_eq!(got.working_dir(), "");
    let e = store
        .image_process_config(&sha_of(b"nope"))
        .expect_err("missing");
    assert_eq!(e.code(), OciErrorCode::NotFound);
    let p = root.blob(&f.config);
    fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).expect("chmod");
    let e = store
        .image_process_config(&f.manifest)
        .expect_err("untrusted");
    assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).expect("chmod back");
    let mut body = fs::read(&p).expect("read");
    body.push(b' ');
    fs::write(&p, body).expect("tamper");
    let e = store
        .image_process_config(&f.manifest)
        .expect_err("tampered");
    assert_eq!(e.code(), OciErrorCode::DataLoss);
}

/// OCI-7: `open_verified_layer` は正しい blob を開き、書き換えた blob は DataLoss になる。
#[test]
fn oci7_2377_open_verified_layer_detects_tampering() {
    let root = Root::new("blob");
    let store = ImageStore::open(root.path()).expect("open");
    let f = seed(&store, "l-6", Some(vec![TAR, TAR, TAR_GZIP]), None);
    let got = store.image_layers(&f.manifest).expect("layers");
    let ok = store
        .open_verified_layer(&got.layers()[0])
        .expect("verified");
    assert_eq!(ok.digest(), &f.layers[0]);
    assert_eq!(
        ok.size(),
        fs::metadata(root.blob(&f.layers[0])).expect("meta").len()
    );
    let p = root.blob(&f.layers[1]);
    let mut b = fs::read(&p).expect("read");
    let last = b.len() - 1;
    b[last] ^= 0xff;
    fs::write(&p, b).expect("tamper");
    let e = store
        .open_verified_layer(&got.layers()[1])
        .expect_err("tampered");
    assert_eq!(e.code(), OciErrorCode::DataLoss);
}

#[cfg(target_os = "linux")]
mod proc_fd {
    use std::os::fd::AsRawFd as _;
    use std::path::Path;

    use fandhe_container_oci::error::OciErrorCode;
    use fandhe_container_oci::layer::extract::ExtractRoot;

    /// OCI-7・SEC-1: 開いたディレクトリの `/proc/self/fd/N` を開け、同じ実体として識別される。
    #[test]
    fn sec1_2377_open_proc_fd_link_opens_the_same_directory() {
        let dir = std::fs::File::open(std::env::temp_dir()).expect("open");
        let link = format!("/proc/self/fd/{}", dir.as_raw_fd());
        let root = ExtractRoot::open_proc_fd_link(Path::new(&link)).expect("open link");
        use std::os::unix::fs::MetadataExt as _;
        let m = dir.metadata().expect("meta");
        assert_eq!(root.identity().expect("identity"), (m.dev(), m.ino()));
    }

    /// SEC-1: 字句が `/proc/self/fd/<10 進>` でないパスは InvalidArgument。
    #[test]
    fn sec1_2377_open_proc_fd_link_rejects_other_paths() {
        for p in [
            "/proc/self/fd/3/x",
            "/tmp/x",
            "/proc/1/fd/3",
            "/proc/self/fd/",
            "/proc/self/fd/+3",
            "/proc/self/fd/../fd/3",
            "proc/self/fd/3",
            "/proc/self/fd/12345678901",
        ] {
            let e = ExtractRoot::open_proc_fd_link(Path::new(p)).expect_err(p);
            assert_eq!(e.code(), OciErrorCode::InvalidArgument, "{p}");
        }
    }

    /// SEC-1: 通常ファイルの fd を指すリンクは拒否され、既存の `open_existing_dir` は同じリンクを開けない（対照）。
    #[test]
    fn sec1_2377_open_proc_fd_link_rejects_non_directory_and_existing_entry_differs() {
        let file = std::fs::File::open("/proc/self/exe").expect("open");
        let link = format!("/proc/self/fd/{}", file.as_raw_fd());
        let e = ExtractRoot::open_proc_fd_link(Path::new(&link)).expect_err("file");
        assert_ne!(e.code(), OciErrorCode::Internal);
        let dir = std::fs::File::open(std::env::temp_dir()).expect("open");
        let dlink = format!("/proc/self/fd/{}", dir.as_raw_fd());
        assert!(ExtractRoot::open_existing_dir(Path::new(&dlink)).is_err());
    }
}
