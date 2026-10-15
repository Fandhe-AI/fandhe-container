//! OCI レイヤーの whiteout（`.wh.<name>`）の検出と、下位レイヤー実体の削除（TASK-53.1・OCI-2・MS-4・#412）。
//!
//! 上位レイヤーは下位のファイルを消すために、同じディレクトリへ `.wh.<name>` という空エントリを置く。
//! 本モジュールは次の 2 つの部品を `layer::extract` へ提供する。
//!
//! - `classify`: tar エントリの最終コンポーネントを whiteout / 不透明マーカー / 通常名へ分類する。
//! - `remove_tree_nofollow`: symlink を追従せずに実体（ファイル・symlink・ディレクトリの木）を再帰削除する。
//!   root への閉じ込め・別表記の衝突検出（IO-5）は呼び出し側 `Extractor::remove_whiteout_target` が担う。
//!
//! # 未実装（実装済みを装わない。REPAIR-3）
//!
//! 本モジュールは部品のみで、展開パイプライン `extract_one_layer` からはまだ呼ばれない。
//!
//! - 展開パイプラインへの統合（TASK-53.3・#414）。同一レイヤー内で whiteout より先に作ったエントリを
//!   消さない（image-spec は whiteout を下位レイヤーのリソースにのみ適用すると定める）ための世代管理も
//!   そこで行う。ここでの削除は「呼ばれた時点の root 内の実体」を消す。
//! - 不透明ディレクトリ `.wh..wh..opq` の処理（TASK-53.2・#413）。`classify` は `Opaque` と分類するだけ。

use std::fs;
use std::path::Path;

use crate::error::{OciError, OciErrorCode};
use crate::layer::extract::{err, map_fs_err};

/// whiteout マーカーの接頭辞。
const WHITEOUT_PREFIX: &[u8] = b".wh.";
/// 不透明ディレクトリのマーカー名（TASK-53.2 が処理する）。
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
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum NameClass {
    /// whiteout ではない通常の名前。
    Regular,
    /// `.wh.<target>`。同じディレクトリの `target` を下位レイヤーから消す。
    Whiteout { target: Vec<u8> },
    /// `.wh..wh..opq`（不透明ディレクトリ。TASK-53.2 の担当）。
    Opaque,
}

/// 最終コンポーネント（バイト列）を分類する。
///
/// 不正な whiteout（対象が空・`.`・`..`・`/` や NUL を含む・長すぎる、`.wh..wh.` の未知の予約名）は
/// `InvalidArgument` で拒否する（`.wh...` を `..` の whiteout として解釈し親を消す事故を防ぐ）。
/// TASK-53.3 で `extract_one_layer` から呼ぶまで未接続。
#[cfg_attr(not(test), allow(dead_code))]
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
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn remove_tree_nofollow(path: &Path) -> Result<(), OciError> {
    remove_at(path, 0)
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
}
