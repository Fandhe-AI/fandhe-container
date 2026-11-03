//! root 配下の別マウント（`EXDEV`）と `openat2` の拒否の原因を示す試験（OCI-7・SEC-1・ERR-1・#2701）。
//!
//! 実マウントなしで `RESOLVE_NO_XDEV` の拒否を決定的に再現するため、`root_handle::test_hook` で指定した
//! 相対名の解決を `EXDEV` にする。rm・prune・lock が `FailedPrecondition` と固定メッセージ
//! （`MOUNT_CROSSING_MESSAGE`）で止まり、テーブルもディスクも変えず、復旧がジャーナルに触れないことを
//! 具体値で照合する。実マウントでの確認は `tests/image_store_xdev.rs`（実機前提・`--ignored`）。
//! fd 起点は Linux の x86_64 / aarch64 だけなので、試験も同じ cfg に限る。

#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::gc_journal::{GC_JOURNAL_FILE_NAME, GcJournal, write_journal};
use super::remove::{ImageRmOptions, ImageRmTarget, StoppedContainers};
use super::root_handle::{MOUNT_CROSSING_MESSAGE, openat2_unavailable, test_hook::fail_xdev};
use super::usage::blob_path;
use super::{ImageStore, ManifestComposition, ReferenceTable, TagKey};
use crate::error::{OciError, OciErrorCode};
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
        "fc-oci-xdev-{}-{}-{label}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("mkdir");
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
    p
}

/// manifest 0xa0（config 0xc1・layer 0x11）を入れ、blob をディスクに置いたストア。`tagged` ならタグ v1 も付ける。
fn seeded(root: &Path, tagged: bool) -> ImageStore {
    fs::create_dir_all(root.join("blobs").join("sha256")).expect("blobs");
    for n in [0x11u8, 0xc1] {
        fs::write(blob_path(root, &d(n)).expect("path"), b"real").expect("blob");
    }
    let mut t = ReferenceTable::new();
    t.register_manifest(
        d(0xa0),
        ManifestComposition::new(d(0xc1), vec![d(0x11)]).expect("comp"),
    )
    .expect("manifest");
    if tagged {
        t.register_tag(tk("v1"), &d(0xa0)).expect("tag");
    }
    ImageStore::with_table(root, t)
        .expect("open")
        .with_timeout(Duration::from_millis(500))
}

fn assert_mount_crossing(e: &OciError) {
    assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(e.message(), MOUNT_CROSSING_MESSAGE);
}

fn rm_v1(g: &mut ReferenceTable, root: &Path) -> OciError {
    g.execute_image_rm(
        root,
        &ImageRmTarget::Tag(tk("v1")),
        &ImageRmOptions::default(),
        &StoppedContainers::new(),
    )
    .expect_err("xdev")
}

fn blobs_remain(root: &Path) {
    for n in [0x11u8, 0xc1] {
        assert!(blob_path(root, &d(n)).expect("path").is_file());
    }
}

/// OCI-7・SEC-1・ERR-1・#2701: `blobs/sha256` が別マウントなら rm は `FailedPrecondition` で止まり、
/// テーブル（manifest・タグ）も blob も残り、ジャーナルは作られない。
#[test]
fn oci7_xdev_rm_stops_before_any_change() {
    let root = temp_root("rm");
    let store = seeded(&root, true);
    let mut g = store.lock().expect("lock");
    let _x = fail_xdev(&["blobs/sha256"]);
    let e = rm_v1(&mut g, &root);
    assert_mount_crossing(&e);
    assert_eq!(g.manifests().count(), 1);
    assert_eq!(g.tags().count(), 1);
    blobs_remain(&root);
    assert!(!root.join(GC_JOURNAL_FILE_NAME).exists());
    drop(g);
    let _ = fs::remove_dir_all(&root);
}

/// OCI-7・SEC-1・ERR-1・#2701: prune も同様に、何も変えずに `FailedPrecondition` で止まる。
#[test]
fn oci7_xdev_prune_stops_before_any_change() {
    let root = temp_root("prune");
    let store = seeded(&root, false);
    let mut g = store.lock().expect("lock");
    let _x = fail_xdev(&["blobs/sha256"]);
    let e = g.execute_image_prune(&root).expect_err("xdev");
    assert_mount_crossing(&e);
    assert_eq!(g.manifests().count(), 1);
    blobs_remain(&root);
    assert!(!root.join(GC_JOURNAL_FILE_NAME).exists());
    drop(g);
    let _ = fs::remove_dir_all(&root);
}

/// OCI-7・SEC-1・ERR-1・#2701: ジャーナルが残る状態で `blobs/sha256` が別マウントなら、`lock` と
/// `recover_pending_deletion` は `FailedPrecondition` で止まり、ジャーナルのバイト列（`attempts` を含む）を
/// 変えない（再試行回数を消費して断念に近づけない）。
#[test]
fn oci7_xdev_recovery_keeps_journal_untouched() {
    let root = temp_root("recover");
    let store = seeded(&root, false);
    {
        let _g = store.lock().expect("lock");
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
    }
    let before = fs::read(root.join(GC_JOURNAL_FILE_NAME)).expect("journal bytes");
    let _x = fail_xdev(&["blobs/sha256"]);
    let Err(e) = store.lock() else {
        panic!("lock must fail")
    };
    assert_mount_crossing(&e);
    let Err(e) = store.recover_pending_deletion() else {
        panic!("recover must fail")
    };
    assert_mount_crossing(&e);
    assert_eq!(
        fs::read(root.join(GC_JOURNAL_FILE_NAME)).expect("journal bytes"),
        before
    );
    blobs_remain(&root);
    let _ = fs::remove_dir_all(&root);
}

/// OCI-7・SEC-1・ERR-1・#2701: `@lock` が別マウント（bind mount）なら `lock` は `FailedPrecondition`。
#[test]
fn oci7_xdev_lock_file_is_rejected() {
    let root = temp_root("lockfile");
    let store = seeded(&root, false);
    let _x = fail_xdev(&["@lock"]);
    let Err(e) = store.lock() else {
        panic!("lock must fail")
    };
    assert_mount_crossing(&e);
    let _ = fs::remove_dir_all(&root);
}

/// OCI-7・SEC-1・ERR-1・#2701: `@gc-pending.json` が別マウントなら、"pending deletion" という誤った原因ではなく
/// マウント越えとして拒否される（区間の中の rm と、次の lock の両方）。
#[test]
fn oci7_xdev_journal_name_is_reported_as_mount_crossing() {
    let root = temp_root("journal-name");
    let store = seeded(&root, true);
    let mut g = store.lock().expect("lock");
    let _x = fail_xdev(&[GC_JOURNAL_FILE_NAME]);
    let e = rm_v1(&mut g, &root);
    assert_mount_crossing(&e);
    drop(g);
    let Err(e) = store.lock() else {
        panic!("lock must fail")
    };
    assert_mount_crossing(&e);
    let _ = fs::remove_dir_all(&root);
}

/// OCI-7・SEC-1・ERR-1・#2701: `openat2` の `ENOSYS`（古いカーネル）と `EPERM`（seccomp）を文言で見分ける。
#[test]
fn oci7_openat2_unavailable_distinguishes_enosys_and_eperm() {
    let a = openat2_unavailable(true);
    assert_eq!(a.code(), OciErrorCode::Unimplemented);
    assert_eq!(
        a.message(),
        "openat2 is not available (ENOSYS): the image store requires Linux 5.6 or later, or a seccomp profile that allows openat2"
    );
    let b = openat2_unavailable(false);
    assert_eq!(b.code(), OciErrorCode::Unimplemented);
    assert_eq!(
        b.message(),
        "openat2 was denied (EPERM), likely by a seccomp profile of the enclosing container runtime; the image store requires openat2"
    );
}

/// OCI-7・SEC-1・ERR-1・#2701: `map_root_io` は `EXDEV` だけをマウント越えに写し、他は fallback を返す。
#[test]
fn oci7_map_root_io_maps_only_exdev() {
    use super::root_handle::map_root_io;
    let fallback = || OciError::new(OciErrorCode::Internal, "fallback");
    let e = map_root_io(&std::io::Error::from_raw_os_error(18), fallback);
    assert_mount_crossing(&e);
    let e = map_root_io(&std::io::Error::from_raw_os_error(2), fallback);
    assert_eq!(e.code(), OciErrorCode::Internal);
    assert_eq!(e.message(), "fallback");
}
