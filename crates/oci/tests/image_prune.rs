//! `image prune` の結合試験（OCI-7・TASK-183.7・#476）。
//!
//! `ImageStore::lock` のガード越しの公開 API だけで受け入れ条件 1〜3 と排他区間の内側でしか動かないことを確かめる。
//! 停止中コンテナの実際の `start` での確認は TASK-184（#664・#665）の担当。

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::image_management::{
    ContainerRefId, ImageStore, ManifestComposition, ReferenceTable, TagKey,
};
use fandhe_container_oci::reference::{Digest, RegistryHost, Repository, Tag};

fn d(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
}

fn blob(root: &Path, n: u8) -> PathBuf {
    root.join("blobs")
        .join("sha256")
        .join(format!("{n:02x}").repeat(32))
}

struct Fixture {
    root: PathBuf,
    store: ImageStore,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

// A(0xa0): c1 + 10,11 / B(0xb0): c2 + 10,12 / C(0xc0): c3 + 13。A は停止中コンテナ、B はタグ、C は無参照。
fn fixture(name: &str) -> Fixture {
    let root = std::env::temp_dir().join(format!("fc-oci-prune-it-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("blobs").join("sha256")).expect("mkdir");
    for n in [0xc1u8, 0x10, 0x11, 0xc2, 0x12, 0xc3, 0x13] {
        fs::write(blob(&root, n), vec![1u8; 16]).expect("write");
    }
    let mut t = ReferenceTable::new();
    for (m, c, ls) in [
        (0xa0u8, 0xc1u8, vec![0x10u8, 0x11]),
        (0xb0, 0xc2, vec![0x10, 0x12]),
        (0xc0, 0xc3, vec![0x13]),
    ] {
        t.register_manifest(
            d(m),
            ManifestComposition::new(d(c), ls.into_iter().map(d).collect()).expect("comp"),
        )
        .expect("register");
    }
    t.register_container(ContainerRefId::new("stopped").expect("id"), &d(0xa0))
        .expect("container");
    t.register_tag(
        TagKey::new(
            RegistryHost::parse("registry.example").expect("host"),
            Repository::parse("lib/app").expect("repo"),
            Tag::parse("v1").expect("tag"),
        ),
        &d(0xb0),
    )
    .expect("tag");
    let store = ImageStore::with_table(&root, t)
        .expect("store")
        .with_timeout(Duration::from_millis(100));
    Fixture { root, store }
}

#[test]
fn oci7_prune_through_store_guard_meets_acceptance() {
    let f = fixture("accept");
    let mut g = f.store.lock().expect("lock");
    let out = g.execute_image_prune(f.store.root()).expect("prune");
    assert_eq!(out.removed_manifests, vec![d(0xc0)]);
    assert_eq!(out.deleted_blobs, vec![d(0x13), d(0xc3)]);
    assert_eq!(out.reclaimed_bytes, 32);
    // 停止中コンテナの manifest の構成 blob はすべて残る。
    for n in [0xc1u8, 0x10, 0x11] {
        assert!(blob(&f.root, n).exists());
    }
    // 共有レイヤーとタグ付きイメージの blob も残る。
    for n in [0xc2u8, 0x12] {
        assert!(blob(&f.root, n).exists());
    }
    assert!(!blob(&f.root, 0xc3).exists());
    assert!(!blob(&f.root, 0x13).exists());
    assert_eq!(g.manifests().count(), 2);
}

#[test]
fn oci7_prune_only_runs_inside_exclusive_section() {
    let f = fixture("excl");
    let g = f.store.lock().expect("lock");
    let other = f.store.lock();
    assert_eq!(other.err().map(|e| e.code()), Some(OciErrorCode::Timeout));
    assert!(blob(&f.root, 0x13).exists());
    assert_eq!(g.manifests().count(), 3);
}
