//! OCI レイヤーの whiteout（`.wh.<name>`）の検出と、下位レイヤー実体の削除（TASK-53.1〜53.3・OCI-2・MS-4・#412〜#414）。
//!
//! 上位レイヤーは下位のファイルを消すために、同じディレクトリへ `.wh.<name>` という空エントリを置く。
//! 本モジュールは次の部品を `layer::extract` へ提供する。
//!
//! - `classify`: tar エントリの最終コンポーネントを whiteout / 不透明マーカー / 通常名へ分類する。
//!   `extract_one_layer` のパス 1（収集・検証）とパス 3（展開。マーカーは書かずに読み飛ばす）が各エントリに対して呼ぶ。
//! - `remove_tree_nofollow`: symlink を追従せずに実体（ファイル・symlink・ディレクトリの木）を再帰削除する。
//!   パス 2（whiteout の適用）と、パス 3 で下位レイヤー由来のノードを置き換えるとき（image-spec の
//!   「Changeset over existing files」）に `Extractor` から呼ばれる。
//! - `remove_dir_contents_nofollow`: 不透明ディレクトリ（`.wh..wh..opq`。TASK-53.2・#413）用に、ディレクトリ自体は
//!   残して直下の全エントリを再帰削除する。パス 2 で `Extractor::apply_markers` から呼ばれる。
//!
//! root への閉じ込め・別表記の衝突検出（IO-5）・同一レイヤーの実体を消さないこと（パス 2 はパス 3 の前に
//! 走るため、消すのは常に下位レイヤー由来の実体）は呼び出し側 `layer::extract` が担う。ここでの削除は
//! 「呼ばれた時点の実体」を消す。

use std::fs;
use std::path::Path;

use crate::error::{OciError, OciErrorCode};
use crate::layer::extract::{err, map_fs_err};

/// whiteout マーカーの接頭辞。
const WHITEOUT_PREFIX: &[u8] = b".wh.";
/// 不透明ディレクトリのマーカー名（処理部品は `remove_dir_contents_nofollow`。TASK-53.2）。
const OPAQUE_MARKER: &[u8] = b".wh..wh..opq";
/// `.wh..wh.` で始まる名前は image-spec が予約する（`.wh..wh..opq` 以外は拒否する）。
const RESERVED_PREFIX: &[u8] = b".wh..wh.";
/// 1 コンポーネントの最大バイト数（`NAME_MAX`）。
const MAX_NAME_BYTES: usize = 255;
/// 再帰削除の深さ上限（作成時のコンポーネント数上限 256 に余裕を足した防御値）。
const MAX_REMOVE_DEPTH: usize = 300;

/// tar エントリの最終コンポーネントの分類結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum NameClass {
    /// whiteout ではない通常の名前。
    Regular,
    /// `.wh.<target>`。同じディレクトリの `target` を下位レイヤーから消す。
    Whiteout { target: Vec<u8> },
    /// `.wh..wh..opq`（不透明ディレクトリ。中身の削除は `remove_dir_contents_nofollow`・TASK-53.2）。
    Opaque,
}

/// 最終コンポーネント（バイト列）を分類する。
///
/// 不正な whiteout（対象が空・`.`・`..`・`/` や NUL を含む・長すぎる、`.wh..wh.` の未知の予約名）は
/// `InvalidArgument` で拒否する（`.wh...` を `..` の whiteout として解釈し親を消す事故を防ぐ）。
/// `extract_one_layer` が各エントリの最終コンポーネントに対して呼ぶ（TASK-53.3）。
pub(crate) fn classify(name: &[u8]) -> Result<NameClass, OciError> {
    if name == OPAQUE_MARKER {
        return Ok(NameClass::Opaque);
    }
    if name.starts_with(RESERVED_PREFIX) {
        return Err(err(
            OciErrorCode::InvalidArgument,
            "whiteout name uses a reserved prefix",
        ));
    }
    let Some(target) = name.strip_prefix(WHITEOUT_PREFIX) else {
        return Ok(NameClass::Regular);
    };
    if target.is_empty()
        || target == b"."
        || target == b".."
        || target.len() > MAX_NAME_BYTES
        || target.contains(&b'/')
        || target.contains(&0)
    {
        return Err(err(
            OciErrorCode::InvalidArgument,
            "whiteout target name is invalid",
        ));
    }
    Ok(NameClass::Whiteout {
        target: target.to_vec(),
    })
}

/// `path` の実体を symlink を追従せずに再帰削除する。存在しなければ成功（冪等）。
///
/// symlink はリンク自体だけを消し、リンク先は触らない。所有者の rwx が欠けるディレクトリ（0555・0000 等）は
/// 先に権限を戻してから中身を消す。深さは `MAX_REMOVE_DEPTH` で打ち切る（`ResourceExhausted`）。
pub(crate) fn remove_tree_nofollow(path: &Path) -> Result<(), OciError> {
    remove_at(path, 0)
}

/// `path` のディレクトリ自体は残し、直下の全エントリを symlink を追従せず再帰削除する（OCI-2・TASK-53.2・#413）。
///
/// 存在しなければ成功（冪等）。`path` が symlink・非ディレクトリなら `FailedPrecondition`（追従しない）。
/// 所有者の rwx が欠けるディレクトリ（0555・0000）は権限を戻してから消す。mode の復元は呼び出し側の遅延 mode
/// （`Extractor::finish_dirs`）が担う。再帰の深さは `MAX_REMOVE_DEPTH`。
pub(crate) fn remove_dir_contents_nofollow(path: &Path) -> Result<(), OciError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(map_fs_err(&e)),
    };
    if !meta.is_dir() {
        return Err(err(
            OciErrorCode::FailedPrecondition,
            "opaque directory is not a directory",
        ));
    }
    make_dir_removable(path, &meta)?;
    for entry in fs::read_dir(path).map_err(|e| map_fs_err(&e))? {
        let entry = entry.map_err(|e| map_fs_err(&e))?;
        remove_at(&entry.path(), 1)?;
    }
    Ok(())
}

fn remove_at(path: &Path, depth: usize) -> Result<(), OciError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(map_fs_err(&e)),
    };
    if !meta.is_dir() {
        return remove_file_best_effort(path, &meta);
    }
    if depth >= MAX_REMOVE_DEPTH {
        return Err(err(
            OciErrorCode::ResourceExhausted,
            "directory tree to remove is too deep",
        ));
    }
    make_dir_removable(path, &meta)?;
    for entry in fs::read_dir(path).map_err(|e| map_fs_err(&e))? {
        let entry = entry.map_err(|e| map_fs_err(&e))?;
        remove_at(&entry.path(), depth + 1)?;
    }
    fs::remove_dir(path).map_err(|e| map_fs_err(&e))
}

#[cfg(unix)]
fn make_dir_removable(path: &Path, meta: &fs::Metadata) -> Result<(), OciError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = meta.permissions().mode();
    if mode & 0o700 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700))
            .map_err(|e| map_fs_err(&e))?;
    }
    Ok(())
}

#[cfg(not(unix))]
// unix 側とシグネチャ（Result）をそろえ、呼び出し側を cfg 分岐させないため。
#[allow(clippy::unnecessary_wraps)]
fn make_dir_removable(_path: &Path, _meta: &fs::Metadata) -> Result<(), OciError> {
    Ok(())
}

/// ファイル / symlink を消す。Windows の読み取り専用属性で失敗した場合は属性を外して再試行する。
#[cfg(unix)]
fn remove_file_best_effort(path: &Path, _meta: &fs::Metadata) -> Result<(), OciError> {
    fs::remove_file(path).map_err(|e| map_fs_err(&e))
}

#[cfg(not(unix))]
fn remove_file_best_effort(path: &Path, meta: &fs::Metadata) -> Result<(), OciError> {
    if fs::remove_file(path).is_ok() {
        return Ok(());
    }
    let mut perms = meta.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    fs::set_permissions(path, perms).map_err(|e| map_fs_err(&e))?;
    fs::remove_file(path).map_err(|e| map_fs_err(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid(name: &[u8]) {
        let e = classify(name).expect_err("must be rejected");
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
    }

    /// OCI-2: `.wh.<name>` は whiteout、それ以外は通常名。
    #[test]
    fn oci2_classify_whiteout_and_regular() {
        assert_eq!(
            classify(b".wh.foo").unwrap(),
            NameClass::Whiteout {
                target: b"foo".to_vec()
            }
        );
        assert_eq!(
            classify(b".wh..hidden").unwrap(),
            NameClass::Whiteout {
                target: b".hidden".to_vec()
            }
        );
        assert_eq!(classify(b"foo").unwrap(), NameClass::Regular);
        assert_eq!(classify(b".whfoo").unwrap(), NameClass::Regular);
        assert_eq!(classify(b".wh").unwrap(), NameClass::Regular);
    }

    /// OCI-2: 不透明マーカーは分類のみ（処理は TASK-53.2）。未知の `.wh..wh.` 予約名は拒否。
    #[test]
    fn oci2_classify_opaque_and_reserved() {
        assert_eq!(classify(b".wh..wh..opq").unwrap(), NameClass::Opaque);
        invalid(b".wh..wh.plnk");
        invalid(b".wh..wh.");
    }

    /// OCI-2: 対象が空・`.`・`..`・`/`・NUL・過長の whiteout は拒否する。
    #[test]
    fn oci2_classify_rejects_invalid_targets() {
        invalid(b".wh.");
        invalid(b".wh..");
        invalid(b".wh...");
        invalid(b".wh.a/b");
        invalid(b".wh.a\0b");
        let mut long = b".wh.".to_vec();
        long.extend(std::iter::repeat_n(b'a', 256));
        invalid(&long);
    }

    // ---- 不透明ディレクトリ（TASK-53.2・OCI-2・#413） ----

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("fc-opq-{tag}-{}", std::process::id()));
        let _ = remove_tree_nofollow(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// OCI-2: 子ファイル・子ディレクトリ・深いツリーを消し、`path` 自体は残る。
    #[test]
    fn oci2_remove_contents_keeps_dir_and_clears_children() {
        let d = tmpdir("a");
        fs::write(d.join("f"), b"1").unwrap();
        fs::create_dir_all(d.join("s/t")).unwrap();
        fs::write(d.join("s/t/g"), b"2").unwrap();
        remove_dir_contents_nofollow(&d).unwrap();
        assert!(d.is_dir());
        assert_eq!(fs::read_dir(&d).unwrap().count(), 0);
        remove_tree_nofollow(&d).unwrap();
    }

    /// OCI-2: 存在しない path は成功、通常ファイルは FailedPrecondition。
    #[test]
    fn oci2_remove_contents_missing_ok_and_file_rejected() {
        let d = tmpdir("b");
        remove_dir_contents_nofollow(&d.join("none")).unwrap();
        fs::write(d.join("f"), b"x").unwrap();
        let e = remove_dir_contents_nofollow(&d.join("f")).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(fs::read(d.join("f")).unwrap(), b"x");
        remove_tree_nofollow(&d).unwrap();
    }

    /// OCI-2: 0000 のトップ・0555 の子を消せ、symlink は追従しない。
    #[test]
    #[cfg(unix)]
    fn oci2_remove_contents_unix_modes_and_symlinks() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tmpdir("c");
        let outside = d.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep"), b"k").unwrap();
        let top = d.join("top");
        fs::create_dir_all(top.join("ro")).unwrap();
        fs::write(top.join("ro/c"), b"c").unwrap();
        std::os::unix::fs::symlink(&outside, top.join("lnk")).unwrap();
        fs::set_permissions(top.join("ro"), fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(&top, fs::Permissions::from_mode(0o000)).unwrap();
        remove_dir_contents_nofollow(&top).unwrap();
        assert_eq!(fs::read_dir(&top).unwrap().count(), 0);
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"k");
        std::os::unix::fs::symlink(&outside, d.join("l2")).unwrap();
        let e = remove_dir_contents_nofollow(&d.join("l2")).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"k");
        remove_tree_nofollow(&d).unwrap();
    }
}
