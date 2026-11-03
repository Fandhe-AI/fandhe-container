//! `ImageStore::lock` のガードを経由しない単体の `ReferenceTable` で永続化操作を呼べないことの結合試験
//! （OCI-7・SEC-1・ERR-1・#2701）。
//!
//! 本番ビルド（lib が `cfg(test)` なし）では、排他区間で検査済みの root を持たないテーブルの rm・prune・
//! 復旧は `FailedPrecondition` で拒否され、信頼検査なしの root やジャーナルの検査抜きで blob の削除が
//! 動く経路を公開 API から閉じる。拒否は何も変えない（テーブルもディスクも）。

use std::fs;
use std::path::PathBuf;

use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::image_management::{
    ImageRmOptions, ImageRmTarget, ManifestComposition, ReferenceTable, StoppedContainers, TagKey,
};
use fandhe_container_oci::reference::{Digest, RegistryHost, Repository, Tag};

fn d(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
}

const MESSAGE: &str =
    "image store operation requires the exclusive section of an opened ImageStore";

fn root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("fc-oci-guard-it-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("blobs").join("sha256")).expect("mkdir");
    fs::write(
        root.join("blobs")
            .join("sha256")
            .join(format!("{:02x}", 0x11u8).repeat(32)),
        b"blob",
    )
    .expect("blob");
    root
}

fn table() -> (ReferenceTable, TagKey) {
    let mut t = ReferenceTable::new();
    t.register_manifest(
        d(0xa0),
        ManifestComposition::new(d(0xc1), vec![d(0x11)]).expect("comp"),
    )
    .expect("manifest");
    let tag = TagKey::new(
        RegistryHost::parse("registry.example").expect("host"),
        Repository::parse("lib/app").expect("repo"),
        Tag::parse("v1").expect("tag"),
    );
    t.register_tag(tag.clone(), &d(0xa0)).expect("tag");
    (t, tag)
}

/// OCI-7・SEC-1・#2701: 単体テーブルの rm・prune・復旧は `FailedPrecondition` で拒否され、何も変えない。
#[test]
fn unguarded_table_rejects_rm_prune_and_recovery() {
    let root = root("unguarded");
    let (mut t, tag) = table();

    let e = t
        .execute_image_rm(
            &root,
            &ImageRmTarget::Tag(tag.clone()),
            &ImageRmOptions::default(),
            &StoppedContainers::new(),
        )
        .expect_err("rm");
    assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(e.message(), MESSAGE);

    let e = t.execute_image_prune(&root).expect_err("prune");
    assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(e.message(), MESSAGE);

    let e = t.resume_pending_deletion(&root).expect_err("resume");
    assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(e.message(), MESSAGE);

    assert_eq!(t.manifests().count(), 1);
    assert_eq!(t.tags().count(), 1);
    assert_eq!(fs::read_dir(&root).expect("read").count(), 1);
    assert!(
        root.join("blobs")
            .join("sha256")
            .join(format!("{:02x}", 0x11u8).repeat(32))
            .is_file()
    );
    let _ = fs::remove_dir_all(&root);
}

/// OCI-7・#2701: 読み取り専用の `disk_usage`・`list_images` は単体テーブルでも拒否されない。
#[test]
fn unguarded_table_still_serves_read_only_usage() {
    let root = root("readonly");
    let (t, _tag) = table();
    t.disk_usage(&root).expect("disk_usage");
    t.list_images(&root).expect("list_images");
    let _ = fs::remove_dir_all(&root);
}

/// OCI-7・SEC-1・#2701: ガードを drop した後に複製で取り出した単体テーブルも、rm・prune・復旧を拒否される。
#[test]
fn detached_clone_of_guarded_table_rejects_persisting_ops() {
    use fandhe_container_oci::image_management::ImageStore;

    let root = root("detached");
    // 所有者・権限の検査を通すため root を 0700 にする。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let store = ImageStore::open(&root).expect("open");
    let (src, tag) = table();
    let mut detached = {
        let mut guard = store.lock().expect("lock");
        let (d0, comp) = src
            .manifests()
            .next()
            .map(|(d, c)| (d.clone(), c.clone()))
            .expect("m");
        guard.register_manifest(d0.clone(), comp).expect("manifest");
        guard.register_tag(tag.clone(), &d0).expect("tag");
        (*guard).clone()
    };

    let e = detached
        .execute_image_rm(
            &root,
            &ImageRmTarget::Tag(tag),
            &ImageRmOptions::default(),
            &StoppedContainers::new(),
        )
        .expect_err("rm");
    assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(e.message(), MESSAGE);
    let e = detached.execute_image_prune(&root).expect_err("prune");
    assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    let e = detached.resume_pending_deletion(&root).expect_err("resume");
    assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    let _ = fs::remove_dir_all(&root);
}
