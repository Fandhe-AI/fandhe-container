//! `support/scratch_root.rs` の `ScratchDir` の挙動固定（#2958・CORE-5・REPAIR-12）。
//!
//! 既定のテスト集合の `oci_*` 等が使う保護済み親が、親への共有 flock の保持（tmpfiles の排他 flock を
//! 弾く）と、子ディレクトリの製品側ロックとの非干渉を満たすことを具体値で確かめる。Linux 限定。
#![cfg(target_os = "linux")]

#[path = "support/scratch_root.rs"]
mod scratch_root;

use scratch_root::ScratchDir;
use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

const DL: Duration = Duration::from_secs(10);

#[test]
fn scratch_dir_is_0700_and_held_by_shared_flock() {
    let s = ScratchDir::new("fandhe-scratch-guard", DL);
    let mode = std::fs::metadata(s.path())
        .expect("meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
    let other = std::fs::File::open(s.path()).expect("open");
    let err = other
        .try_lock()
        .expect_err("exclusive lock must be refused");
    assert!(matches!(err, std::fs::TryLockError::WouldBlock));
}

#[test]
fn child_directory_is_lockable_exclusively() {
    let s = ScratchDir::new("fandhe-scratch-guard", DL);
    let child = s.path().join("bundle");
    std::fs::create_dir(&child).expect("mkdir");
    let f = std::fs::File::open(&child).expect("open");
    f.try_lock().expect("child exclusive lock must succeed");
}

#[test]
fn scratch_dirs_are_distinct_and_removed_on_drop() {
    let a = ScratchDir::new("fandhe-scratch-guard", DL);
    let b = ScratchDir::new("fandhe-scratch-guard", DL);
    assert_ne!(a.path(), b.path());
    let pa = a.path().to_path_buf();
    drop(a);
    let err = std::fs::metadata(&pa).expect_err("removed");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    drop(b);
}
