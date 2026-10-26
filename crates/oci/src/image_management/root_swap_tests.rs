//! 検査後に root が差し替えられても、永続化操作が検査済みの実体に閉じ込められる試験（OCI-7・SEC-1・#2638）。
//!
//! `ImageStore::lock` の入口の再検査（`reverify_root`）は差し替えを検出して拒否するが、検査から使用までの
//! 隙間は検出できない。そこで `RootHandle`（root の fd 起点の `openat2` / `*at`）が、隙間に差し替えが
//! 入っても差し替え後のディレクトリへ書かず・消さないことを、決定的に差し替えを再現して具体値で照合する。
//! fd 起点は Linux の x86_64 / aarch64 だけなので、試験も同じ cfg に限る（他の OS は従来のパス起点＋
//! 入口の再検査で、既存の `oci7_sec1_lock_rejects_swapped_root` が見る）。

#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::gc_journal::{
    DeletionDurability, GcJournal, STALE_TMP_PREFIXES, reap_stale_tmp, write_journal,
};
use super::store::test_hook::set_after_reverify;
use super::usage::blob_path;
use super::{
    ContainerRefId, ImageStore, ImageTagSource, ManifestComposition, ReferenceTable, TagKey,
};
use crate::error::OciErrorCode;
use crate::reference::{Digest, RegistryHost, Repository, Tag};

fn d(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
}

fn tk(t: &str) -> TagKey {
    TagKey::new(
        RegistryHost::parse("registry.example").expect("host"),
        Repository::parse("lib/app").expect("repo"),
        Tag::parse(t).expect("tag"),
    )
}

fn temp_root(label: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let p = std::env::temp_dir().join(format!(
        "fc-oci-swap-{}-{}-{label}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("mkdir");
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
    p
}

/// `root` を `moved` へ移し、同じパスに 0700 の空ディレクトリ（おとり）を置く。
fn swap_root(root: &Path, moved: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::rename(root, moved).expect("move root");
    fs::create_dir(root).expect("decoy root");
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("chmod decoy");
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// manifest 0xa0（config 0xc1・layer 0x11）だけを入れたストア。
fn seeded(root: &Path) -> ImageStore {
    let mut t = ReferenceTable::new();
    t.register_manifest(
        d(0xa0),
        ManifestComposition::new(d(0xc1), vec![d(0x11)]).expect("comp"),
    )
    .expect("manifest");
    ImageStore::with_table(root, t)
        .expect("open")
        .with_timeout(Duration::from_millis(500))
}

/// OCI-7・SEC-1・#2638: 再検査の直後に root を差し替えても、コンテナ参照は検査済みの root にだけ保存され、
/// おとりは空のまま。次の `lock` は入口の再検査で `Internal` になる。
#[test]
fn oci7_sec1_root_swapped_after_reverify_keeps_container_refs_in_verified_root() {
    let root = temp_root("refs");
    let moved = root.with_extension("moved");
    let store = seeded(&root);
    let (r, m) = (root.clone(), moved.clone());
    set_after_reverify(move || swap_root(&r, &m));
    let id = ContainerRefId::new("c2").expect("id");
    store
        .register_container_ref(&id, &d(0xa0))
        .expect("register");

    assert_eq!(names(&root), Vec::<String>::new());
    assert_eq!(names(&moved), vec!["@container-refs.json", "@lock"]);
    let reopened = ImageStore::open(&moved).expect("reopen moved");
    let guard = reopened.lock().expect("lock moved");
    assert_eq!(guard.container_refs.len(), 1);
    assert_eq!(
        guard.container_refs.get(&id).map(|e| &e.manifest),
        Some(&d(0xa0))
    );
    drop(guard);

    let Err(e) = store.lock() else {
        panic!("a swapped root must be rejected at the entrance")
    };
    assert_eq!(e.code(), OciErrorCode::Internal);
    assert_eq!(e.message(), "image store root changed after open");
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&moved);
}

/// OCI-7・SEC-1・#2638: 在庫（タグ）の保存も検査済みの root にだけ届く。
#[test]
fn oci7_sec1_root_swapped_after_reverify_keeps_inventory_in_verified_root() {
    let root = temp_root("inv");
    let moved = root.with_extension("moved");
    let store = seeded(&root);
    let (r, m) = (root.clone(), moved.clone());
    set_after_reverify(move || swap_root(&r, &m));
    store
        .tag_image(&ImageTagSource::Manifest(d(0xa0)), tk("v1"))
        .expect("tag");

    assert_eq!(names(&root), Vec::<String>::new());
    assert_eq!(names(&moved), vec!["@image-inventory.json", "@lock"]);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&moved);
}

/// OCI-7・SEC-1・#2638: 排他区間の中で root が差し替わった後の削除の復旧（ジャーナルの読み・blob の削除・
/// ジャーナルの消滅）は、検査済みの root にだけ作用し、おとりの同名の blob は内容 `decoy` のまま残る。
#[test]
fn oci7_sec1_gc_after_root_swap_touches_only_verified_root() {
    let root = temp_root("gc");
    let moved = root.with_extension("moved");
    fs::create_dir_all(root.join("blobs").join("sha256")).expect("blobs");
    for n in [0x11u8, 0xc1] {
        fs::write(blob_path(&root, &d(n)).expect("path"), b"real").expect("blob");
    }
    let store = seeded(&root);
    let mut guard = store.lock().expect("lock");
    write_journal(
        store.handle(),
        &GcJournal {
            manifests: vec![d(0xa0)],
            untag: Vec::new(),
            delete_blobs: vec![d(0x11), d(0xc1)],
            attempts: 0,
        },
    )
    .expect("journal");

    // 区間の中で root を差し替え、おとりに同名の blob を置く。
    swap_root(&root, &moved);
    fs::create_dir_all(root.join("blobs").join("sha256")).expect("decoy blobs");
    for n in [0x11u8, 0xc1] {
        fs::write(blob_path(&root, &d(n)).expect("path"), b"decoy").expect("decoy blob");
    }

    let out = guard
        .resume_pending_deletion_at(store.handle())
        .expect("resume")
        .expect("journal was present");
    assert_eq!(out.deleted_blobs, vec![d(0x11), d(0xc1)]);
    assert_eq!(out.removed_manifests, vec![d(0xa0)]);
    assert_eq!(out.durability, DeletionDurability::Confirmed);

    for n in [0x11u8, 0xc1] {
        assert_eq!(
            fs::read(blob_path(&root, &d(n)).expect("path")).expect("decoy kept"),
            b"decoy"
        );
        assert!(fs::symlink_metadata(blob_path(&moved, &d(n)).expect("path")).is_err());
    }
    assert_eq!(names(&root), vec!["blobs"]);
    assert_eq!(
        names(&moved),
        vec!["@image-inventory.json", "@lock", "blobs"]
    );
    drop(guard);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&moved);
}

/// OCI-7・SEC-1・#2638: 区間の中で root が差し替わった後の `execute_image_prune` は、渡された root が区間の
/// root と別のディレクトリなら `InvalidArgument` で拒否し、どちらにも何も書かない・消さない。
#[test]
fn oci7_sec1_prune_with_swapped_root_path_is_rejected() {
    let root = temp_root("prune");
    let moved = root.with_extension("moved");
    fs::create_dir_all(root.join("blobs").join("sha256")).expect("blobs");
    fs::write(blob_path(&root, &d(0x11)).expect("path"), b"real").expect("blob");
    let store = seeded(&root);
    let mut guard = store.lock().expect("lock");
    swap_root(&root, &moved);
    fs::create_dir_all(root.join("blobs").join("sha256")).expect("decoy blobs");
    fs::write(blob_path(&root, &d(0x11)).expect("path"), b"decoy").expect("decoy blob");

    let e = guard.execute_image_prune(&root).expect_err("mismatch");
    assert_eq!(e.code(), OciErrorCode::InvalidArgument);
    assert_eq!(
        fs::read(blob_path(&root, &d(0x11)).expect("path")).expect("decoy"),
        b"decoy"
    );
    assert_eq!(
        fs::read(blob_path(&moved, &d(0x11)).expect("path")).expect("real"),
        b"real"
    );
    assert_eq!(names(&root), vec!["blobs"]);
    drop(guard);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&moved);
}

/// OCI-7・SEC-1・#2638: 書き込み途中の残骸の回収も検査済みの root にだけ作用し、おとりの同名ファイルは残る。
#[test]
fn oci7_sec1_reap_stale_tmp_after_root_swap_touches_only_verified_root() {
    let root = temp_root("reap");
    let moved = root.with_extension("moved");
    let store = seeded(&root);
    let guard = store.lock().expect("lock");
    let stale = "@gc-pending.json.tmp-1-1";
    fs::write(root.join(stale), b"partial").expect("stale");
    swap_root(&root, &moved);
    fs::write(root.join(stale), b"decoy").expect("decoy stale");

    reap_stale_tmp(store.handle(), STALE_TMP_PREFIXES);

    assert!(fs::symlink_metadata(moved.join(stale)).is_err());
    assert_eq!(fs::read(root.join(stale)).expect("decoy kept"), b"decoy");
    drop(guard);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&moved);
}
/// `root` に `blobs/sha256/<hex>` を `len` バイトで置く（`blobs/sha256` が無ければ作る）。
fn put_blob(root: &Path, n: u8, len: usize) {
    let p = blob_path(root, &d(n)).expect("blob path");
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir blobs");
    fs::write(p, vec![0u8; len]).expect("write blob");
}

/// `root` に `staging/<pull>/<file>` を `len` バイトで置く。
fn put_staged(root: &Path, pull: &str, file: &str, len: usize) {
    let dir = root.join("staging").join(pull);
    fs::create_dir_all(&dir).expect("mkdir staging");
    fs::write(dir.join(file), vec![0u8; len]).expect("write staged");
}

/// OCI-7・SEC-1・#2695: 排他区間を取った後に root を差し替えても、`disk_usage` / `list_images` は検査済みの
/// 実体（本物の値）だけを数える。おとりの別サイズの blob・staging は数えず、おとりには何も書かない。
#[test]
fn oci7_sec1_usage_after_root_swap_counts_only_verified_root() {
    let root = temp_root("usage");
    let moved = root.with_extension("moved");
    let store = seeded(&root);
    put_blob(&root, 0xc1, 10);
    put_blob(&root, 0x11, 1000);
    put_staged(&root, "p1", "aa", 777);
    let guard = store.lock().expect("lock");
    swap_root(&root, &moved);
    put_blob(&root, 0xc1, 5000);
    put_blob(&root, 0x11, 7000);
    put_blob(&root, 0x99, 999);
    put_staged(&root, "p9", "zz", 55);
    let decoy_before = names(&root.join("blobs").join("sha256"));
    let real_before = names(&moved.join("blobs").join("sha256"));

    let df = guard.disk_usage_at(store.handle()).expect("df");
    assert_eq!(df.images.count, 1);
    assert_eq!(df.images.bytes, 1010);
    assert_eq!(df.images.reclaimable_bytes, 1010);
    assert_eq!(df.images.missing_blobs, 0);
    assert_eq!(df.cache.blob_count, 2);
    assert_eq!(df.cache.bytes, 1010);
    assert_eq!(df.cache.unregistered_count, 0);
    assert_eq!(df.staging.pulls, 1);
    assert_eq!(df.staging.file_count, 1);
    assert_eq!(df.staging.bytes, 777);

    let ls = guard.list_images_at(store.handle()).expect("ls");
    assert_eq!(ls.entries.len(), 1);
    assert_eq!(ls.entries[0].digest, d(0xa0));
    assert_eq!(ls.entries[0].size_bytes, 1010);
    assert!(ls.entries[0].missing_blobs.is_empty());

    // 読み取りは何も書かず・消さない。
    assert_eq!(names(&root.join("blobs").join("sha256")), decoy_before);
    assert_eq!(names(&moved.join("blobs").join("sha256")), real_before);
    assert_eq!(
        fs::metadata(blob_path(&root, &d(0x99)).expect("path"))
            .expect("decoy blob")
            .len(),
        999
    );
    drop(guard);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&moved);
}

/// OCI-7・SEC-1・#2695: 再検査の直後に root が差し替えられた排他区間では、公開 API に差し替え後のパスを渡すと
/// `InvalidArgument` で拒否し、同じ実体（移動先）のパスなら本物の値を返す。
#[test]
fn oci7_sec1_usage_with_swapped_root_path_is_rejected() {
    let root = temp_root("usage-path");
    let moved = root.with_extension("moved");
    let store = seeded(&root);
    put_blob(&root, 0xc1, 10);
    put_blob(&root, 0x11, 1000);
    let (r, m) = (root.clone(), moved.clone());
    set_after_reverify(move || swap_root(&r, &m));
    let guard = store.lock().expect("lock");
    put_blob(&root, 0xc1, 5000);

    let msg = "root does not match the image store root of this exclusive section";
    let e = guard.list_images(&root).expect_err("decoy path (ls)");
    assert_eq!(e.code(), OciErrorCode::InvalidArgument);
    assert_eq!(e.message(), msg);
    let e = guard.disk_usage(&root).expect_err("decoy path (df)");
    assert_eq!(e.code(), OciErrorCode::InvalidArgument);
    assert_eq!(e.message(), msg);
    assert_eq!(guard.disk_usage(&moved).expect("df").images.bytes, 1010);
    assert_eq!(
        guard.list_images(&moved).expect("ls").entries[0].size_bytes,
        1010
    );
    drop(guard);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&moved);
}

/// OCI-7・SEC-1・#2695: ガードの内側で取った展開後サイズの計画は、ガードを手放して root が差し替えられても
/// 検査済みの実体のレイヤーだけを読み、差し替え後のパスは `InvalidArgument` で拒否する。
#[test]
fn oci7_sec1_expanded_measure_after_root_swap_reads_only_verified_root() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    fn gz(len: usize) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(&vec![1u8; len]).expect("gz write");
        e.finish().expect("gz finish")
    }
    let root = temp_root("expanded");
    let moved = root.with_extension("moved");
    let store = seeded(&root);
    let p = blob_path(&root, &d(0x11)).expect("path");
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    fs::write(&p, gz(3000)).expect("real layer");
    let plan = {
        let guard = store.lock().expect("lock");
        guard.expanded_size_plan()
    };
    swap_root(&root, &moved);
    let q = blob_path(&root, &d(0x11)).expect("path");
    fs::create_dir_all(q.parent().expect("parent")).expect("mkdir decoy");
    fs::write(&q, gz(40)).expect("decoy layer");

    let u = plan.measure(&moved).expect("measure moved");
    assert_eq!(u.expanded_bytes, 3000);
    assert_eq!(u.measured_layers, 1);
    assert_eq!(u.missing_layers, 0);
    let e = plan.measure(&root).expect_err("decoy path");
    assert_eq!(e.code(), OciErrorCode::InvalidArgument);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&moved);
}
