//! 起動オプション文書の置き場と読み書き(SUP-12・CLI-1・SEC-1・REPAIR-5・#2713)。
//!
//! # 役割と呼び出し文脈
//!
//! 文書の形は [`document`](super::document)。置き場所は `<state_root>/@container-options/<id>`(ディレクトリは
//! 0700、ファイルは 0600)で、`--root` と `<id>` だけから導く(supervisor の起動契約・`start_client`・ランチャーは
//! 変えない)。書くのは CLI の `create`、読むのは supervisor の `start`(`start_entry` の手順 2c)、消すのは CLI の
//! `delete`。ファイルが無ければ既定値で動く(plugin-cri や従来のコンテナは書かない)。ファイルがあって壊れている・
//! 権限が不正なら fail-closed で拒否する。
//!
//! # 外部入力の扱い
//!
//! 読み取りは symlink を辿らず(`O_NOFOLLOW`)、端末を制御端末にせず(`O_NOCTTY`)、FIFO で止まらない
//! (`O_NONBLOCK`)。開いた fd を fstat し、通常ファイル・所有者が実効 uid・group / other のビットなし・サイズが上限以下で
//! あることを確かめてから、上限つき(`take`)で読む。エラーの文言は固定の英語で、パス・errno を含めない。
//! 上限なしの待ち(FUSE 上の状態ルート等)は呼び出し側(`start_entry`)が期限つきの作業スレッドで包む(REPAIR-5)。
//!
//! # 残余(REPAIR-3)
//!
//! 同じ利用者が同じ ID で `create` を並行に実行すると片方の文書が消えうる。plugin-cri の create は残骸を掃除しない
//! ため、CLI で作ったコンテナの delete 後の掃除に失敗した ID を CRI で作り直すと残骸が効きうる(後続)。
//! Linux 以外では実効 uid を得られず `FailedPrecondition` で拒否する(CLI の create は Linux のローカル実行のみ)。

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use fandhe_container_core::traits::ContainerId;
use fandhe_container_core::traits::types::{ErrorCode, TraitError};

use super::document::{ContainerOptionsDocument, OPTIONS_DOC_MAX_BYTES};

/// 状態ルート直下の文書ディレクトリ名(`@container-logs` と同じ命名)。
pub const OPTIONS_DIR_NAME: &str = "@container-options";

fn err(code: ErrorCode, message: &'static str) -> TraitError {
    TraitError::new(code, message)
}

fn io_failed(_: std::io::Error) -> TraitError {
    err(ErrorCode::Internal, "container options file I/O failed")
}

/// 文書ディレクトリの絶対パス。
pub fn options_dir(root: &Path) -> PathBuf {
    root.join(OPTIONS_DIR_NAME)
}

/// 文書ファイルのパス。
pub fn options_path(root: &Path, id: &ContainerId) -> PathBuf {
    options_dir(root).join(id.as_str())
}

/// 書き込んだ文書の識別(巻き戻しで別の文書を消さないための inode 照合に使う)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrittenOptions {
    dev: u64,
    ino: u64,
}

/// 開いたファイルの fstat 相当の検査(純関数。値の注入で試験できる)。
pub fn check_file_meta(
    is_file: bool,
    owner_uid: u32,
    mode: u32,
    len: u64,
    expected_uid: u32,
) -> Result<(), TraitError> {
    if !is_file || owner_uid != expected_uid || mode & 0o077 != 0 {
        return Err(err(
            ErrorCode::PermissionDenied,
            "the container options file is not private to the current user",
        ));
    }
    if len > OPTIONS_DOC_MAX_BYTES as u64 {
        return Err(err(
            ErrorCode::InvalidArgument,
            "the container options file is too large",
        ));
    }
    Ok(())
}

#[cfg(unix)]
mod imp {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};

    use super::*;
    use crate::control::listener::{check_dir_meta, effective_uid};

    /// `<root>/@container-options/` を用意する(無ければ 0700 で作り、あれば所有者・権限・種別を検証する)。
    /// 戻り値は検証済みのディレクトリのパス。
    fn ensure_dir(root: &Path, uid: u32) -> Result<PathBuf, TraitError> {
        let dir = options_dir(root);
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_failed(e)),
        }
        // symlink を辿らない lstat で検査する(差し替えられた symlink を拒否する)。
        let meta = std::fs::symlink_metadata(&dir).map_err(io_failed)?;
        check_dir_meta(meta.is_dir(), meta.uid(), meta.mode(), uid)?;
        Ok(dir)
    }

    /// 文書を新規作成する(既存なら `AlreadyExists`)。0600・`O_EXCL`・`O_NOFOLLOW`。
    pub fn write_new(
        root: &Path,
        id: &ContainerId,
        doc: &ContainerOptionsDocument,
    ) -> Result<WrittenOptions, TraitError> {
        let uid = effective_uid()?;
        let dir = ensure_dir(root, uid)?;
        let path = dir.join(id.as_str());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(crate::container_options::env::O_NOCTTY | no_follow())
            .open(&path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    err(
                        ErrorCode::AlreadyExists,
                        "the container options file already exists",
                    )
                } else {
                    io_failed(e)
                }
            })?;
        let meta = file.metadata().map_err(io_failed)?;
        let written = WrittenOptions {
            dev: meta.dev(),
            ino: meta.ino(),
        };
        let result = file
            .write_all(&doc.encode())
            .and_then(|()| file.sync_all())
            .map_err(io_failed);
        if let Err(e) = result {
            // 書きかけを残さない(自分が作った inode だけを消す)。
            let _ = remove_if_same(root, id, &written);
            return Err(e);
        }
        Ok(written)
    }

    /// `O_NOFOLLOW`(`logs::rotating` と同じ値の取り方に揃える)。
    fn no_follow() -> i32 {
        crate::logs::rotating::NOFOLLOW_FLAG
    }

    /// 文書を読む。無ければ `Ok(None)`。所有者・権限・種別・サイズが不正なら拒否する。
    pub fn read(
        root: &Path,
        id: &ContainerId,
    ) -> Result<Option<ContainerOptionsDocument>, TraitError> {
        let path = options_path(root, id);
        let file = match crate::logs::rotating::open_read_nofollow_nonblocking(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            // symlink(ELOOP)・その他の open 失敗は拒否する(パス・errno は出さない)。
            Err(_) => {
                return Err(err(
                    ErrorCode::InvalidArgument,
                    "the container options file cannot be opened",
                ));
            }
        };
        let meta = file.metadata().map_err(io_failed)?;
        check_file_meta(
            meta.is_file(),
            meta.uid(),
            meta.mode(),
            meta.len(),
            effective_uid()?,
        )?;
        read_bounded(file).map(Some)
    }

    fn read_bounded(file: File) -> Result<ContainerOptionsDocument, TraitError> {
        let mut bytes = Vec::new();
        file.take(OPTIONS_DOC_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_failed)?;
        ContainerOptionsDocument::decode(&bytes)
    }

    /// `written` と同じ inode のときだけ消す(巻き戻し用)。違う・無いときは何もしない。
    pub fn remove_if_same(
        root: &Path,
        id: &ContainerId,
        written: &WrittenOptions,
    ) -> Result<(), TraitError> {
        let path = options_path(root, id);
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.dev() == written.dev && m.ino() == written.ino => {
                std::fs::remove_file(&path).map_err(io_failed)
            }
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_failed(e)),
        }
    }

    /// 文書を消す(無ければ成功)。delete と、record の無い残骸の掃除に使う。
    pub fn remove(root: &Path, id: &ContainerId) -> Result<(), TraitError> {
        match std::fs::remove_file(options_path(root, id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_failed(e)),
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use super::*;

    fn unsupported() -> TraitError {
        err(
            ErrorCode::Unimplemented,
            "container options files are not supported on this platform",
        )
    }

    pub fn write_new(
        _root: &Path,
        _id: &ContainerId,
        _doc: &ContainerOptionsDocument,
    ) -> Result<WrittenOptions, TraitError> {
        Err(unsupported())
    }

    pub fn read(
        _root: &Path,
        _id: &ContainerId,
    ) -> Result<Option<ContainerOptionsDocument>, TraitError> {
        Err(unsupported())
    }

    pub fn remove_if_same(
        _root: &Path,
        _id: &ContainerId,
        _written: &WrittenOptions,
    ) -> Result<(), TraitError> {
        Err(unsupported())
    }

    pub fn remove(_root: &Path, _id: &ContainerId) -> Result<(), TraitError> {
        Err(unsupported())
    }
}

pub use imp::{read, remove, remove_if_same, write_new};

#[cfg(all(test, unix, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fcopt-store-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    fn id(s: &str) -> ContainerId {
        ContainerId::new(s).expect("id")
    }

    fn doc() -> ContainerOptionsDocument {
        ContainerOptionsDocument::new(
            vec!["nofile=1024:2048".into()],
            vec!["A=1".into()],
            None,
            None,
            vec![],
        )
        .expect("doc")
    }

    /// SUP-12・SEC-1: 0600 のファイルが 0700 のディレクトリに作られ、読み戻せる。無ければ `None`。
    #[test]
    fn sup12_options_store_write_read_modes() {
        let root = tmp("rw");
        assert_eq!(read(&root, &id("c1")).expect("read"), None);
        write_new(&root, &id("c1"), &doc()).expect("write");
        let dir_mode = std::fs::metadata(options_dir(&root)).expect("dir").mode() & 0o777;
        let file_mode = std::fs::metadata(options_path(&root, &id("c1")))
            .expect("file")
            .mode()
            & 0o777;
        assert_eq!((dir_mode, file_mode), (0o700, 0o600));
        assert_eq!(read(&root, &id("c1")).expect("read"), Some(doc()));
        assert_eq!(
            std::fs::read(options_path(&root, &id("c1"))).expect("bytes"),
            doc().encode()
        );
        let e = write_new(&root, &id("c1"), &doc()).expect_err("exists");
        assert_eq!(e.code(), ErrorCode::AlreadyExists);
        remove(&root, &id("c1")).expect("remove");
        remove(&root, &id("c1")).expect("remove again");
        assert_eq!(read(&root, &id("c1")).expect("read"), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// SEC-1: symlink・group 可読・FIFO・上限超過の文書は読まずに拒否する(FIFO で止まらない)。
    #[test]
    fn sec1_options_store_read_rejections() {
        let root = tmp("rej");
        write_new(&root, &id("seed"), &doc()).expect("seed");
        let dir = options_dir(&root);
        // symlink
        std::fs::write(root.join("target"), doc().encode()).expect("target");
        symlink(root.join("target"), dir.join("lnk")).expect("symlink");
        assert_eq!(
            read(&root, &id("lnk")).expect_err("symlink").code(),
            ErrorCode::InvalidArgument
        );
        // 0644
        write_new(&root, &id("open"), &doc()).expect("write");
        std::fs::set_permissions(dir.join("open"), std::fs::Permissions::from_mode(0o644))
            .expect("chmod");
        assert_eq!(
            read(&root, &id("open")).expect_err("mode").code(),
            ErrorCode::PermissionDenied
        );
        // 上限超過
        let big = dir.join("big");
        std::fs::write(&big, vec![b'x'; OPTIONS_DOC_MAX_BYTES + 1]).expect("big");
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(
            read(&root, &id("big")).expect_err("big").code(),
            ErrorCode::InvalidArgument
        );
        // 壊れた中身
        let junk = dir.join("junk");
        std::fs::write(&junk, b"nonsense").expect("junk");
        std::fs::set_permissions(&junk, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(
            read(&root, &id("junk")).expect_err("junk").message(),
            "options document has an unknown header"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// SEC-1: `remove_if_same` は別の inode(差し替えられた文書)を消さない。
    #[test]
    fn sec1_options_store_remove_if_same_keeps_other_inode() {
        let root = tmp("same");
        let written = write_new(&root, &id("c1"), &doc()).expect("write");
        let path = options_path(&root, &id("c1"));
        std::fs::remove_file(&path).expect("unlink");
        write_new(&root, &id("c1"), &doc()).expect("rewrite");
        remove_if_same(&root, &id("c1"), &written).expect("noop");
        assert!(path.exists(), "a different inode must survive");
        let current = std::fs::metadata(&path).expect("meta");
        let same = WrittenOptions {
            dev: current.dev(),
            ino: current.ino(),
        };
        remove_if_same(&root, &id("c1"), &same).expect("remove");
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// SEC-1: 検査の純関数(所有者違い・サイズ超過)。
    #[test]
    fn sec1_options_check_file_meta() {
        assert!(check_file_meta(true, 1000, 0o100600, 10, 1000).is_ok());
        assert_eq!(
            check_file_meta(true, 0, 0o100600, 10, 1000)
                .expect_err("owner")
                .code(),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            check_file_meta(false, 1000, 0o100600, 10, 1000)
                .expect_err("kind")
                .code(),
            ErrorCode::PermissionDenied
        );
    }
}
