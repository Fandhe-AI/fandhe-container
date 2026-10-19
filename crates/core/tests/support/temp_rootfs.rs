//! root で動きうる実機前提テストの一時 rootfs・一時ディレクトリを、排他的かつ symlink を辿らずに作る共有ヘルパー。
//!
//! 各テストバイナリが `#[path = "support/temp_rootfs.rs"] mod temp_rootfs;` で取り込む（`real_entry.rs` と同じ形。
//! `tests/support/` 直下は cargo の自動検出の対象外）。製品コードからは使われない。
//!
//! 背景: 共有の `std::env::temp_dir()` 上の PID だけから決まる固定名を `remove_dir_all` で消して
//! `create_dir_all` で作り直すと、削除と再作成の間に別ユーザーが置いた symlink を root が辿り、
//! rootfs 検証の前にホスト側の別ディレクトリへ `proc`・`sys`・`dev` 等を作りうる（#2324・#2288。SEC-2・CORE-5）。
//!
//! 契約:
//! - [`exclusive_temp_dir`] は PID・時刻・試行番号つきの一意名を `DirBuilder` で排他作成し、既存パスは削除も採用もしない。
//! - [`create_dir_chain`] は `create_dir` で 1 階層ずつ作り、既存は symlink でないディレクトリに限って許容する。
//! - 失敗はすべて panic（試験の前提崩れを握りつぶさない）。後始末は呼び出し側の `Drop` が、自分で作ったパスだけを消す。

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

/// 名前衝突時の再試行の上限。
const MAX_ATTEMPTS: u32 = 16;

/// 一時ディレクトリを排他作成して返す。作成時は 0700 で、直後に `mode` へ合わせる（従来の実効モードを保つため）。
// 取り込み元のテストバイナリによっては使わないため（`create_dir_chain` だけを使う試験がある）。
#[allow(dead_code)]
pub fn exclusive_temp_dir(prefix: &str, mode: u32) -> PathBuf {
    let tmp = fs::canonicalize(std::env::temp_dir()).expect("canonicalize temp_dir");
    for attempt in 0..MAX_ATTEMPTS {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let path = tmp.join(format!("{prefix}-{}-{nanos}-{attempt}", std::process::id()));
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                    .expect("chmod exclusive temp dir");
                return path;
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("exclusively create {}: {e}", path.display()),
        }
    }
    panic!("could not exclusively create a temp dir for prefix {prefix}");
}

/// `base` 配下に `rel` の各要素を 1 階層ずつ `create_dir` で作り、末端のパスを返す。
///
/// 既存要素は `symlink_metadata`（辿らない）が symlink でないディレクトリと答える場合だけ許容する。
// 取り込み元のテストバイナリによっては使わないため（想定外の取り込み先への備え）。
#[allow(dead_code)]
pub fn create_dir_chain(base: &Path, rel: &[&str]) -> PathBuf {
    let mut cur = base.to_path_buf();
    for comp in rel {
        assert!(
            !comp.is_empty() && *comp != ".." && *comp != "." && !comp.contains('/'),
            "invalid path component: {comp:?}"
        );
        cur.push(comp);
        match fs::create_dir(&cur) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                let md = fs::symlink_metadata(&cur).expect("lstat existing component");
                assert!(
                    md.is_dir() && !md.file_type().is_symlink(),
                    "{} exists and is not a plain directory",
                    cur.display()
                );
            }
            Err(e) => panic!("create_dir {}: {e}", cur.display()),
        }
    }
    cur
}
