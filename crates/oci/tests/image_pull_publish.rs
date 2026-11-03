//! pull の公開とロールバックの結合試験（OCI-7・TASK-183.10・#475）。
//!
//! 公開 API だけを通し、公開完了までイメージが `image ls` に現れないこと、公開の途中で失敗すると
//! 自分のリースが解放されステージングが消えることを照合する。

use std::fs;
use std::path::PathBuf;

use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::image_management::{
    BlobReuse, ImageStore, ManifestComposition, PullId, PullPublishRequest, StagingCleanup, TagKey,
};
use fandhe_container_oci::reference::{Digest, RegistryHost, Repository, Tag};
use sha2::{Digest as _, Sha256};

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

struct Root(PathBuf);

impl Root {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("fc-oci-pub-it-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(p.join("blobs").join("sha256")).expect("mkdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        Root(p)
    }
    fn blob(&self, d: &Digest) -> PathBuf {
        self.0.join("blobs").join("sha256").join(hex(d))
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tag() -> TagKey {
    TagKey::new(
        RegistryHost::parse("example.com").expect("host"),
        Repository::parse("lib/app").expect("repo"),
        Tag::parse("v1").expect("tag"),
    )
}

/// OCI-7: 公開が完了するまで `image ls` に現れず、完了後に 1 件現れてステージングは消える。
#[test]
fn oci7_image_appears_only_after_publish() {
    let root = Root::new("ok");
    let store = ImageStore::open(&root.0).expect("open");
    let mut s = store
        .begin_pull(PullId::new("it-1").expect("id"))
        .expect("begin");
    let cfg = sha_of(b"config");
    let layer = sha_of(b"layer");
    for (d, data) in [(&cfg, &b"config"[..]), (&layer, &b"layer"[..])] {
        let mut w = s.open_staged_blob(d).expect("writer");
        std::io::Write::write_all(&mut w, data).expect("write");
        w.commit().expect("commit");
        s.verify_staged_blob(d, 1024).expect("verify");
    }
    let staged = s.staging_dir().to_path_buf();
    {
        let g = store.lock().expect("lock");
        assert_eq!(g.list_images(&root.0).expect("ls").entries.len(), 0);
    }
    let comp = ManifestComposition::new(cfg.clone(), vec![layer.clone()]).expect("comp");
    let m = sha_of(b"manifest");
    let out = s
        .publish(PullPublishRequest::new(m.clone(), comp).with_tag(tag()))
        .expect("publish");
    assert_eq!(out.staging, StagingCleanup::Removed);
    assert!(!staged.exists());
    let g = store.lock().expect("lock");
    let list = g.list_images(&root.0).expect("ls");
    assert_eq!(list.entries.len(), 1);
    assert_eq!(list.entries[0].digest, m);
    assert_eq!(list.entries[0].size_bytes, 11);
    assert_eq!(fs::read(root.blob(&cfg)).expect("read"), b"config");
}

/// OCI-7: 公開の途中で失敗すると、自分のリースが解放されステージングが消え、一覧には何も現れない。
#[test]
fn oci7_failed_publish_rolls_back_lease_and_staging() {
    let root = Root::new("fail");
    let cached = sha_of(b"cached");
    fs::write(root.blob(&cached), b"cached").expect("write");
    let store = ImageStore::open(&root.0).expect("open");
    let mut s = store
        .begin_pull(PullId::new("it-2").expect("id"))
        .expect("begin");
    let BlobReuse::Leased(_t) = s.lease_existing_blob(&cached).expect("lease") else {
        panic!("expected Leased");
    };
    let cfg = sha_of(b"config");
    let mut w = s.open_staged_blob(&cfg).expect("writer");
    std::io::Write::write_all(&mut w, b"config").expect("write");
    w.commit().expect("commit");
    s.verify_staged_blob(&cfg, 1024).expect("verify");
    let staged = s.staging_dir().to_path_buf();
    // 宛先をディレクトリにして移動を失敗させる。
    fs::create_dir(root.blob(&cfg)).expect("mkdir dst");
    let comp = ManifestComposition::new(cfg.clone(), vec![cached.clone()]).expect("comp");
    let e = s
        .publish(PullPublishRequest::new(sha_of(b"manifest"), comp).with_tag(tag()))
        .expect_err("must fail");
    assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    assert!(!staged.exists());
    let g = store.lock().expect("lock");
    assert_eq!(g.blob_references(&cached).leases, vec![]);
    assert_eq!(g.list_images(&root.0).expect("ls").entries.len(), 0);
    assert_eq!(g.manifests().count(), 0);
}
