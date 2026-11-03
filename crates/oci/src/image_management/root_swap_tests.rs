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
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use sha2::{Digest as _, Sha256};

use super::gc_journal::{
    DeletionDurability, GcJournal, STALE_TMP_PREFIXES, reap_stale_tmp, write_journal,
};
use super::pull::StagingCleanup;
use super::store::test_hook::set_after_reverify;
use super::usage::blob_path;
use super::{
    ContainerRefId, ImageStore, ImageTagSource, ManifestComposition, PullId, PullPublishRequest,
    ReferenceTable, TagKey,
};
use crate::error::OciErrorCode;
use crate::reference::{Digest, RegistryHost, Repository, Tag};
use crate::registry::test_support::fetch_blob_with_hook;

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

fn pid(s: &str) -> PullId {
    PullId::new(s).expect("pull id")
}

fn sha_of(data: &[u8]) -> Digest {
    let hex: String = Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Digest::parse(&format!("sha256:{hex}")).expect("digest")
}

fn open_store(root: &Path) -> ImageStore {
    ImageStore::open(root)
        .expect("open")
        .with_timeout(Duration::from_millis(500))
}

/// `open_verified_staged_blob` で開いたハンドルの全内容を読む。
fn read_verified(s: &super::pull::PullSession<'_>, d: &Digest) -> Vec<u8> {
    use std::io::Read as _;
    let mut body = Vec::new();
    s.open_verified_staged_blob(d)
        .expect("open verified")
        .read_to_end(&mut body)
        .expect("read");
    body
}

/// 検証済みの 1 blob を持つ pull を作る（`staging/p1/<hex>` に `layer-bytes`）。
fn verified_pull(store: &ImageStore) -> (super::pull::PullSession<'_>, Digest, String) {
    let mut s = store.begin_pull(pid("p1")).expect("begin");
    let layer = sha_of(b"layer-bytes");
    let mut w = s.open_staged_blob(&layer).expect("writer");
    w.write_all(b"layer-bytes").expect("write");
    w.commit().expect("commit");
    s.verify_staged_blob(&layer, 1 << 20).expect("verify");
    let hex = layer.to_string().replace("sha256:", "");
    (s, layer, hex)
}

/// OCI-7・SEC-1・CRI-3・#2893: 検証後に `<root>/staging` を別名へ移して同名のおとりを置いても、
/// 検証後の読み取りは検証済みの blob を返し、おとりは読まれず無傷である。
#[test]
fn oci7_sec1_staging_swapped_after_verify_reads_verified_blob() {
    let root = temp_root("stg-swap");
    let store = open_store(&root);
    let (s, layer, hex) = verified_pull(&store);
    let moved = root.join("staging-moved");
    fs::rename(root.join("staging"), &moved).expect("move staging");
    let decoy = root.join("staging").join("p1");
    fs::create_dir_all(&decoy).expect("decoy");
    fs::write(decoy.join(&hex), b"decoy-bytes").expect("decoy blob");
    assert_eq!(read_verified(&s, &layer), b"layer-bytes");
    assert_eq!(fs::read(decoy.join(&hex)).expect("intact"), b"decoy-bytes");
    drop(s);
    let _ = fs::remove_dir_all(&root);
}

/// OCI-7・SEC-1・CRI-3・#2893: 検証後に pull ディレクトリ（`staging/p1`）を別名へ移して同名のおとりを置いても、
/// 検証後の読み取りは検証済みの blob を返し、おとりは無傷である。
#[test]
fn oci7_sec1_pull_dir_swapped_after_verify_reads_verified_blob() {
    let root = temp_root("pd-swap");
    let store = open_store(&root);
    let (s, layer, hex) = verified_pull(&store);
    let staging = root.join("staging");
    fs::rename(staging.join("p1"), staging.join("p1-moved")).expect("move pull dir");
    fs::create_dir(staging.join("p1")).expect("decoy");
    fs::write(staging.join("p1").join(&hex), b"decoy-bytes").expect("decoy blob");
    assert_eq!(read_verified(&s, &layer), b"layer-bytes");
    assert_eq!(
        fs::read(staging.join("p1").join(&hex)).expect("intact"),
        b"decoy-bytes"
    );
    drop(s);
    let _ = fs::remove_dir_all(&root);
}

/// OCI-7・SEC-1・CRI-3・#2893: 取得の途中で `staging/p1` がおとりへ差し替わると、パス起点の副作用へ進む前の
/// `check_staging_dir_current` が `Internal` で拒否し、差し替え前は通る。
#[test]
fn oci7_sec1_check_staging_dir_current_rejects_swapped_pull_dir() {
    let root = temp_root("chk-cur");
    let store = open_store(&root);
    let (s, _layer, _hex) = verified_pull(&store);
    s.check_staging_dir_current().expect("unswapped");
    let staging = root.join("staging");
    fs::rename(staging.join("p1"), staging.join("p1-moved")).expect("move pull dir");
    fs::create_dir(staging.join("p1")).expect("decoy");
    let e = s.check_staging_dir_current().unwrap_err();
    assert_eq!(e.code(), OciErrorCode::Internal);
    assert_eq!(e.message(), "image store root changed after open");
    assert!(names(&staging.join("p1")).is_empty());
    drop(s);
    let _ = fs::remove_dir_all(&root);
}

/// OCI-7・SEC-1・#2694: `begin_pull` の排他区間の直後に root が差し替わっても、staging・pull ディレクトリ・
/// `@pull.lock` は検査済みの root にだけ作られ、おとりは空のまま。`open_staged_blob` の書き込み先も検査済みの
/// root の pull ディレクトリ（#2765）で、検証後の読み取り（`open_verified_staged_blob`。#2893）は検査済みの
/// root の検証済み blob を返し（同名のおとりは読まない）、次の `lock` は入口の再検査で `Internal` になる。
#[test]
fn oci7_sec1_root_swapped_during_begin_pull_keeps_staging_in_verified_root() {
    let root = temp_root("bp");
    let moved = root.with_extension("moved");
    let store = open_store(&root);
    let (r, m) = (root.clone(), moved.clone());
    set_after_reverify(move || swap_root(&r, &m));
    let mut s = store.begin_pull(pid("p1")).expect("begin");

    assert_eq!(names(&root), Vec::<String>::new());
    assert_eq!(names(&moved), vec!["@lock", "staging"]);
    assert_eq!(names(&moved.join("staging")), vec!["p1"]);
    assert_eq!(names(&moved.join("staging").join("p1")), vec!["@pull.lock"]);
    let data = b"layer-bytes";
    let layer = sha_of(data);
    let mut w = s.open_staged_blob(&layer).expect("writer");
    w.write_all(data).expect("write");
    w.commit().expect("commit");
    let hex = layer.to_string().replace("sha256:", "");
    assert_eq!(
        fs::read(moved.join("staging").join("p1").join(&hex)).expect("written to verified"),
        data
    );
    assert_eq!(names(&root), Vec::<String>::new());
    s.verify_staged_blob(&layer, 1 << 20).expect("verify");
    let decoy_dir = root.join("staging").join("p1");
    fs::create_dir_all(&decoy_dir).expect("decoy pull dir");
    fs::write(decoy_dir.join(&hex), b"decoy-bytes").expect("decoy blob");
    assert_eq!(read_verified(&s, &layer), b"layer-bytes");
    assert_eq!(
        fs::read(decoy_dir.join(&hex)).expect("decoy intact"),
        b"decoy-bytes"
    );
    let Err(e) = store.lock() else {
        panic!("a swapped root must be rejected at the entrance")
    };
    assert_eq!(e.code(), OciErrorCode::Internal);
    assert_eq!(e.message(), "image store root changed after open");
    drop(s);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&moved);
}

/// OCI-7・SEC-1・#2694: 公開の排他区間の直後に root が差し替わっても、blob は検査済みの root の
/// `blobs/sha256` へ公開され（内容一致・リンク数 1）、staging は消え、おとりには何も作られない。
#[test]
fn oci7_sec1_root_swapped_during_publish_links_blob_into_verified_root() {
    use std::os::unix::fs::MetadataExt;
    let root = temp_root("pub");
    let moved = root.with_extension("moved");
    let store = open_store(&root);
    let mut s = store.begin_pull(pid("p1")).expect("begin");
    let (cfg_data, layer_data) = (b"config-bytes".as_slice(), b"layer-bytes".as_slice());
    let (cfg, layer) = (sha_of(cfg_data), sha_of(layer_data));
    for (dg, data) in [(&cfg, cfg_data), (&layer, layer_data)] {
        let mut w = s.open_staged_blob(dg).expect("writer");
        w.write_all(data).expect("write");
        w.commit().expect("commit");
        s.verify_staged_blob(dg, 1 << 20).expect("verify");
    }
    let (r, m) = (root.clone(), moved.clone());
    set_after_reverify(move || swap_root(&r, &m));
    let comp = ManifestComposition::new(cfg.clone(), vec![layer.clone()]).expect("comp");
    let out = s
        .publish(PullPublishRequest::new(d(0xa0), comp))
        .expect("publish");

    let mut expected = vec![cfg.clone(), layer.clone()];
    expected.sort();
    assert_eq!(out.moved_blobs, expected);
    assert_eq!(out.staging, StagingCleanup::Removed);
    for (dg, data) in [(&cfg, cfg_data), (&layer, layer_data)] {
        let p = blob_path(&moved, dg).expect("path");
        assert_eq!(fs::read(&p).expect("published"), data);
        assert_eq!(fs::metadata(&p).expect("meta").nlink(), 1);
    }
    assert_eq!(names(&moved.join("staging")), Vec::<String>::new());
    assert_eq!(names(&root), Vec::<String>::new());
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&moved);
}

/// OCI-7・SEC-1・#2694: 中止の排他区間の直後に root が差し替わっても、消えるのは検査済みの root の
/// `staging/<id>` だけで、おとりの同名ディレクトリの中身は内容 `decoy` のまま残る。
#[test]
fn oci7_sec1_root_swapped_during_abort_removes_only_verified_staging() {
    let root = temp_root("abort");
    let moved = root.with_extension("moved");
    let store = open_store(&root);
    let s = store.begin_pull(pid("p1")).expect("begin");
    let (r, m) = (root.clone(), moved.clone());
    set_after_reverify(move || {
        swap_root(&r, &m);
        let dir = r.join("staging").join("p1");
        fs::create_dir_all(&dir).expect("decoy staging");
        fs::write(dir.join("sentinel"), b"decoy").expect("decoy file");
    });
    let out = s.abort().expect("abort");

    assert_eq!(out.staging, StagingCleanup::Removed);
    assert_eq!(names(&moved.join("staging")), Vec::<String>::new());
    assert_eq!(
        fs::read(root.join("staging").join("p1").join("sentinel")).expect("decoy kept"),
        b"decoy"
    );
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&moved);
}

/// OCI-7・SEC-1・#2694: 回収 GC の排他区間の直後に root が差し替わっても、回収されるのは検査済みの root の
/// 残骸だけで、おとりの同名の残骸（`@pull.lock` と `x`）には触れない。
#[test]
fn oci7_sec1_root_swapped_during_recover_stale_pulls_reclaims_only_verified_root() {
    let root = temp_root("recover");
    let moved = root.with_extension("moved");
    let store = open_store(&root);
    drop(store.begin_pull(pid("p1")).expect("begin"));
    let (r, m) = (root.clone(), moved.clone());
    set_after_reverify(move || {
        swap_root(&r, &m);
        let dir = r.join("staging").join("p1");
        fs::create_dir_all(&dir).expect("decoy staging");
        fs::write(dir.join("@pull.lock"), b"").expect("decoy lock");
        fs::write(dir.join("x"), b"decoy").expect("decoy file");
    });
    let out = store.recover_stale_pulls().expect("recover");

    assert_eq!(out.reclaimed(), &[pid("p1")]);
    assert_eq!(names(&moved.join("staging")), Vec::<String>::new());
    assert_eq!(
        names(&root.join("staging").join("p1")),
        vec!["@pull.lock", "x"]
    );
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&moved);
}

/// OCI-7・SEC-1・#2694: キャッシュ済み blob のリース登録の排他区間の直後に root が差し替わると、fd 側では
/// blob が見えるがパス側はおとりになる。`Leased` に存在しないパスを載せず `Internal` で拒否する。
#[test]
fn oci7_sec1_lease_rejects_root_swapped_after_reverify() {
    let root = temp_root("lease");
    let moved = root.with_extension("moved");
    let store = open_store(&root);
    let mut s = store.begin_pull(pid("p1")).expect("begin");
    let layer = sha_of(b"cached");
    let hex = layer.to_string().replace("sha256:", "");
    let dir = root.join("blobs").join("sha256");
    fs::create_dir_all(&dir).expect("blob dir");
    fs::write(dir.join(&hex), b"cached").expect("blob");
    let (r, m) = (root.clone(), moved.clone());
    set_after_reverify(move || swap_root(&r, &m));

    let e = s.lease_existing_blob(&layer).expect_err("swapped root");
    assert_eq!(e.code(), OciErrorCode::Internal);
    assert_eq!(e.message(), "image store root changed after open");
    assert_eq!(names(&root), Vec::<String>::new());
    assert!(moved.join("blobs").join("sha256").join(&hex).is_file());
    drop(s);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&moved);
}

/// 取得の途中で差し替える試験の共通の準備: 本物のストアの pull `p1` と、digest・本文・writer を返す。
fn fetch_setup(label: &str) -> (PathBuf, ImageStore, Vec<u8>) {
    let root = temp_root(label);
    let store = open_store(&root);
    (root, store, b"layer-bytes-for-fetch".to_vec())
}

/// OCI-7・SEC-1・OCI-1（#2765）: root 全体が `begin_pull` の後・書き込みの前に差し替わっても、fetcher の書き込みは
/// 保持している検査済みの pull ディレクトリへ届く。おとりの root は空のまま、完全な内容が `moved` 側に確定し、
/// 検証・公開も `moved` 側の `blobs/sha256` へ通る（#2694 で残っていた隙間が閉じたことの機械照合）。
#[test]
fn oci7_sec1_fetch_after_root_swap_writes_into_verified_root() {
    use std::os::unix::fs::MetadataExt;
    let (root, store, data) = fetch_setup("fetch");
    let moved = root.with_extension("moved");
    let mut s = store.begin_pull(pid("p1")).expect("begin");
    let layer = sha_of(&data);
    swap_root(&root, &moved);
    let mut w = s.open_staged_blob(&layer).expect("writer");
    fetch_blob_with_hook(&mut w, &data, || {}).expect("fetch");
    w.commit().expect("commit");

    assert_eq!(names(&root), Vec::<String>::new());
    let hex = layer.to_string().replace("sha256:", "");
    let staged = moved.join("staging").join("p1").join(&hex);
    assert_eq!(fs::read(&staged).expect("staged"), data);
    assert_eq!(fs::metadata(&staged).expect("meta").nlink(), 1);
    assert_eq!(
        names(&moved.join("staging").join("p1")),
        vec!["@pull.lock".to_string(), hex.clone()]
    );
    s.verify_staged_blob(&layer, 1 << 20).expect("verify");
    let comp = ManifestComposition::new(layer.clone(), Vec::new()).expect("comp");
    // 公開の入口の再検査は差し替えを検出して拒否する（fail-closed）。おとりへは何も作られない。
    let _ = s.publish(PullPublishRequest::new(d(0xa0), comp));
    assert_eq!(names(&root), Vec::<String>::new());
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&moved);
}

/// OCI-7・SEC-1（#2765）: 取得の途中（本文の前半を書いた後）に `<root>/staging/<id>` が symlink へ差し替わっても、
/// 書き込みは開いたままの検査済みの実体へ届く。symlink の向こうの外部ディレクトリは空のまま、確定した blob は
/// 完全な内容（リンク数 1）で、`.part` は残らない。
#[test]
fn oci7_sec1_pull_dir_swapped_to_symlink_during_fetch_writes_into_verified_root() {
    use std::os::unix::fs::MetadataExt;
    let (root, store, data) = fetch_setup("fetch-pd");
    let outside = temp_root("fetch-pd-out");
    let mut s = store.begin_pull(pid("p1")).expect("begin");
    let layer = sha_of(&data);
    let mut w = s.open_staged_blob(&layer).expect("writer");
    let (r, o) = (root.clone(), outside.clone());
    fetch_blob_with_hook(&mut w, &data, move || {
        let pd = r.join("staging").join("p1");
        fs::rename(&pd, r.join("staging").join("p1.moved")).expect("move pull dir");
        std::os::unix::fs::symlink(&o, &pd).expect("symlink");
    })
    .expect("fetch");
    w.commit().expect("commit");

    assert_eq!(names(&outside), Vec::<String>::new());
    let hex = layer.to_string().replace("sha256:", "");
    let real = root.join("staging").join("p1.moved");
    assert_eq!(fs::read(real.join(&hex)).expect("staged"), data);
    assert_eq!(fs::metadata(real.join(&hex)).expect("meta").nlink(), 1);
    assert_eq!(names(&real), vec!["@pull.lock".to_string(), hex]);
    drop(s);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&outside);
}

/// OCI-7・SEC-1（#2765）: 取得の途中で `<root>/staging` 自身が、おとり（`p1/` を持つ外部ディレクトリ）への
/// symlink に差し替わっても、書き込みは検査済みの実体へ届き、おとりの `p1/` は空のまま。
#[test]
fn oci7_sec1_staging_swapped_to_symlink_during_fetch_writes_into_verified_root() {
    let (root, store, data) = fetch_setup("fetch-st");
    let outside = temp_root("fetch-st-out");
    fs::create_dir(outside.join("p1")).expect("decoy pull dir");
    let mut s = store.begin_pull(pid("p1")).expect("begin");
    let layer = sha_of(&data);
    let mut w = s.open_staged_blob(&layer).expect("writer");
    let (r, o) = (root.clone(), outside.clone());
    fetch_blob_with_hook(&mut w, &data, move || {
        fs::rename(r.join("staging"), r.join("staging.moved")).expect("move staging");
        std::os::unix::fs::symlink(&o, r.join("staging")).expect("symlink");
    })
    .expect("fetch");
    w.commit().expect("commit");

    assert_eq!(names(&outside.join("p1")), Vec::<String>::new());
    let hex = layer.to_string().replace("sha256:", "");
    assert_eq!(
        fs::read(root.join("staging.moved").join("p1").join(&hex)).expect("staged"),
        data
    );
    drop(s);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&outside);
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
