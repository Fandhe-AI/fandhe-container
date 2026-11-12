//! `flock_release::ExplicitUnlockFile` の `new` と `Drop` の振る舞いを、複製した 6 crate で同じ試験ケースにより
//! 照合する共有部品（群 A。REPAIR-1・REPAIR-5・OCI-5・CORE-2・#4566。判断は #4532 の案 C）。
//!
//! 役割: core・oci・cri・plugin-cri・supervisor・net の各 `src/flock_release.rs` は同じ約 50 行の RAII を独立に
//! 持つ（共有の下位 crate は置かない判断）。片方だけ直す漏れを検出するため、各 crate の `lib.rs` が
//! `#[path]` で本ファイルを `#[cfg(test)]` のモジュールとして取り込み、`crate::flock_release` に対して同じ
//! 試験を走らせる。試験専用で製品バイナリ・rlib には入らない。Cargo の依存の辺も増やさない。
//!
//! 取り込み元（6 crate）: `crates/{core,oci,cri,plugin-cri,supervisor,net}/src/lib.rs`
//! （grep: `flock_release_cases`）。6 crate すべてが `flock_release_with_cases.rs`（群 B）も
//! 取り込む（net も #4571 で同じ形になった）。
//!
//! 各 crate は `crate::flock_release::shared_case_dir(tag)` を試験専用で用意する（一時ディレクトリの作り方が
//! crate ごとに違うため、本ファイルの外に置く）。規則を変えるときは本ファイルと 6 か所を同じ PR で直す。
//! 詳細は `docs/design/flock-release-audit.md`。待ちは無く、すべて `try_lock`（待たない）で判定する。

use crate::flock_release::{ExplicitUnlockFile, shared_case_dir};
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

/// 陽性対照: 素の `File` は drop（close）だけでは、複製 fd が残る間ロックが外れない。
/// これが成り立たない環境では、以降の「外れる」の照合が意味を持たない。
#[test]
fn repair1_oci5_4566_plain_close_keeps_lock_while_duplicate_alive() {
    let (_guard, dir) = shared_case_dir("plain");
    let path = dir.join("lock");
    let plain = open(&path);
    plain.try_lock().unwrap();
    let dup = plain.try_clone().unwrap();
    drop(plain);
    assert!(matches!(
        open(&path).try_lock(),
        Err(TryLockError::WouldBlock)
    ));
    drop(dup);
    assert!(open(&path).try_lock().is_ok());
}

/// `new` は包むだけで、生きている間はロックを保持し、drop で外れる。
#[test]
fn repair1_oci5_4566_new_keeps_lock_until_drop() {
    let (_guard, dir) = shared_case_dir("new");
    let path = dir.join("lock");
    let file = open(&path);
    file.try_lock().unwrap();
    let wrapped = ExplicitUnlockFile::new(file);
    assert!(matches!(
        open(&path).try_lock(),
        Err(TryLockError::WouldBlock)
    ));
    drop(wrapped);
    assert!(open(&path).try_lock().is_ok());
}

/// `Drop` は明示 unlock するので、同じ OFD の複製 fd が生きていてもロックが外れる。
#[test]
fn repair1_oci5_4566_drop_releases_despite_duplicate_fd() {
    let (_guard, dir) = shared_case_dir("dup");
    let path = dir.join("lock");
    let file = open(&path);
    file.try_lock().unwrap();
    let dup = file.try_clone().unwrap();
    drop(ExplicitUnlockFile::new(file));
    assert!(open(&path).try_lock().is_ok());
    drop(dup);
}
