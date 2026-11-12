//! `flock_release::release_lock_file_with`・`release_lock_file` の振る舞いを、6 crate で同じ
//! 試験ケースにより照合する共有部品（群 B。REPAIR-1・REPAIR-5・OCI-5・CORE-2・#4566。判断は #4532 の案 C）。
//!
//! 取り込み元（6 crate）: `crates/{core,oci,cri,plugin-cri,supervisor,net}/src/lib.rs`
//! （grep: `flock_release_with_cases`）。net も #4571 で他の 5 crate と同じ形になり取り込む。
//! 取り込み方・一時ディレクトリの用意・変更時の規則は `flock_release_cases.rs`（群 A）と同じ。
//! 試験専用で製品バイナリ・rlib には入らない。

use crate::flock_release::{
    LockRelease, release_lock_file, release_lock_file_with, shared_case_dir,
};
use std::cell::Cell;
use std::fs::{File, TryLockError};
use std::path::Path;

fn open(path: &Path) -> File {
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .expect("open lock file")
}

/// unlock は close より前に 1 回だけ呼ばれ、その時点でロックはまだ保持され `File` は開いている。
#[test]
fn repair1_oci5_4566_release_with_calls_unlock_once_while_open() {
    let (_guard, dir) = shared_case_dir("with-once");
    let path = dir.join("lock");
    let file = open(&path);
    file.try_lock().unwrap();

    let calls = Cell::new(0u32);
    let held_in_closure = Cell::new(false);
    let open_in_closure = Cell::new(false);
    let result = release_lock_file_with(file, |f| {
        calls.set(calls.get() + 1);
        held_in_closure.set(matches!(
            open(&path).try_lock(),
            Err(TryLockError::WouldBlock)
        ));
        open_in_closure.set(f.metadata().is_ok());
        f.unlock()
    });

    assert_eq!(result, LockRelease::Unlocked);
    assert_eq!(calls.get(), 1);
    assert!(held_in_closure.get());
    assert!(open_in_closure.get());
    assert!(open(&path).try_lock().is_ok());
}

/// unlock が失敗しても close は続き、結果は `UnlockFailed`（close でロックが外れる）。
#[test]
fn repair1_oci5_4566_release_with_unlock_failure_still_closes() {
    let (_guard, dir) = shared_case_dir("with-fail");
    let path = dir.join("lock");
    let file = open(&path);
    file.try_lock().unwrap();
    let result = release_lock_file_with(file, |_| Err(std::io::Error::other("injected")));
    assert_eq!(result, LockRelease::UnlockFailed);
    assert!(open(&path).try_lock().is_ok());
}

/// 製品の入口 `release_lock_file` は実際に unlock するので、複製 fd が生きていてもロックが外れる。
#[test]
fn repair1_oci5_4566_release_lock_file_releases_despite_duplicate_fd() {
    let (_guard, dir) = shared_case_dir("with-prod");
    let path = dir.join("lock");
    let file = open(&path);
    file.try_lock().unwrap();
    let dup = file.try_clone().unwrap();
    assert_eq!(release_lock_file(file), LockRelease::Unlocked);
    assert!(open(&path).try_lock().is_ok());
    drop(dup);
}
