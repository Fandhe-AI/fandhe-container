//! 検査済みのイメージストア root を指すハンドル（OCI-7・SEC-1・REPAIR-3・#2638）。
//!
//! # 役割と呼び出し元
//!
//! `ImageStore::lock` / create ゲートの入口は `reverify_root` で root の差し替えを検出して拒否する（#2547）。
//! ただし検査から使用までの間に root が別のディレクトリへ差し替えられると、`self.root` からパスを組み
//! 直す操作は差し替え後のディレクトリへ届く（TOCTOU）。本モジュールは、`ImageStore::open` が検査した
//! root を開いたまま持ち、排他区間の中の永続化操作（`@lock`・`@container-refs.json`・
//! `@image-inventory.json`・`@gc-pending.json` とその一時ファイル・`blobs/sha256/<hex>` の削除）を
//! その fd 起点の `openat2` / `*at` に閉じ込める。差し替えが起きても書き込み・削除は検査済みの実体にだけ
//! 届き、差し替え後のディレクトリには何も書かず何も消さない（入口の検出と区間内の閉じ込めの 2 層）。
//! 呼び出し元は `store`（open・lock・create ゲート）・`container_ref_persist`・`inventory_persist`・
//! `gc_journal`・`remove`・`prune`。名前は定数か検証済みの hex の 1 コンポーネントに限る
//! （外部入力からパスを組まない。`sys::at::component_cstring` が入口で再検証する）。
//!
//! # 方式と `cfg` の局所化
//!
//! `cfg` は本モジュールの中だけに置き、永続化モジュールには `cfg(target_os)` / `cfg(target_arch)` を書かない。
//!
//! - Linux の x86_64 / aarch64: root の fd を `OwnedFd` で持つ。名前の解決は
//!   `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV` 付きの `openat2` で、
//!   最後の要素も `O_NOFOLLOW` で辿らない。`openat2`（Linux 5.6 以降）が使えない環境（`ENOSYS`・seccomp による
//!   `EPERM`）では `ImageStore::open` が `Unimplemented` で拒否し、パス起点へは縮退しない（fail-closed）。
//! - その他の unix（macOS・Linux の他アーキテクチャ）と Windows: 正規パスを持つ従来のパス起点の実装で、
//!   差し替えは入口の再検査だけで検出する。macOS は本番経路が `ImageStore::open` に届かず（cli の
//!   `non_linux_failure`）、`openat` 系の定数・FFI・libc 照合を足す根拠が無い。Windows の ACL は #2428 の
//!   方式判断待ち。Linux の他アーキテクチャは `sys::at` の定数・番号を確かめていない。
//!
//! # 移していない操作（実装済みを装わない。REPAIR-3）
//!
//! `usage*` の読み取り（件数・サイズの集計）と `pull` / `pull_recovery` の staging・公開はパス起点のまま
//! である。根拠と追跡 issue は `docs/design/image-store-root-trust.md` の論点 3 を参照。

use std::path::{Path, PathBuf};

use crate::error::{OciError, OciErrorCode};

fn root_inaccessible() -> OciError {
    OciError::new(OciErrorCode::Internal, "image store root is not accessible")
}

/// 検査済み root へのハンドル。`ImageStore` が `Arc` で保持し、`ReferenceTable` の排他区間にも渡す。
#[derive(Debug)]
pub(crate) struct RootHandle {
    path: PathBuf,
    /// 開いた時点の root の (dev, ino)。入口の再検査が差し替えの検出に使う。
    #[cfg(unix)]
    id: (u64, u64),
    /// fd 起点の実装だけが持つ root の fd。パス起点の実装は `path` から都度組み立てる。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    inner: imp::Inner,
}

impl RootHandle {
    /// 開いた root の正規パス（表示・照合用。操作の起点には使わない）。
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// 開いた時点の root の (dev, ino)。
    #[cfg(unix)]
    pub(crate) fn id(&self) -> (u64, u64) {
        self.id
    }

    /// `p` が本ハンドルの root と同じディレクトリか（unix は dev / ino、他はパス比較）。
    pub(crate) fn matches(&self, p: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(p).is_ok_and(|m| (m.dev(), m.ino()) == self.id)
        }
        #[cfg(not(unix))]
        {
            let norm: PathBuf = p.components().collect();
            norm == self.path
        }
    }

    /// 信頼検査をしない単体テーブル用に、パスから開く（検査は `ImageStore::open` の担当）。
    ///
    /// 末尾が symlink・非ディレクトリなら拒否する。
    pub(crate) fn open_unchecked(path: &Path) -> Result<Self, OciError> {
        let path: PathBuf = path.components().collect();
        let meta = std::fs::symlink_metadata(&path).map_err(|e| {
            let code = if e.kind() == std::io::ErrorKind::NotFound {
                OciErrorCode::NotFound
            } else {
                OciErrorCode::Internal
            };
            OciError::new(code, "image store root is not accessible")
        })?;
        if !meta.is_dir() {
            return Err(OciError::new(
                OciErrorCode::FailedPrecondition,
                "image store root is not a directory",
            ));
        }
        Self::open_dir(path, None)
    }
}

// ---------------------------------------------------------------------------
// Linux の x86_64 / aarch64: root の fd 起点
// ---------------------------------------------------------------------------
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod imp {
    use std::ffi::{CString, OsStr, OsString};
    use std::fs::{File, Metadata};
    use std::io;
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::unix::fs::MetadataExt as _;
    use std::path::PathBuf;

    use super::{OciError, OciErrorCode, RootHandle, root_inaccessible};
    use crate::sys::at::{
        self, ELOOP, ENOSYS, ENOTDIR, EPERM, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW,
        O_NONBLOCK, O_PATH, O_RDONLY, O_WRONLY, RESOLVE_IN_ROOT, RESOLVE_NO_MAGICLINKS,
        RESOLVE_NO_SYMLINKS, RESOLVE_NO_XDEV,
    };

    /// root の fd。
    pub(super) type Inner = OwnedFd;

    /// 名前解決で常に付ける制約。root の外・symlink・マウント越えへ出ない。
    const RESOLVE: u64 =
        RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;

    /// blob 置き場の相対パス。
    const BLOB_DIR: [&str; 2] = ["blobs", "sha256"];

    /// blob 置き場の検査で使う文言（`usage::checked_dir` と同じ code・文言を保つ）。
    fn blob_dir_not_plain() -> OciError {
        OciError::new(
            OciErrorCode::FailedPrecondition,
            "blob directory is not a plain directory",
        )
    }

    fn blob_dir_stat_failed() -> OciError {
        OciError::new(OciErrorCode::Internal, "failed to stat blob directory")
    }

    fn errno(e: &io::Error) -> Option<i32> {
        e.raw_os_error()
    }

    impl RootHandle {
        /// `path`（正規パス）を開く。`expected` があれば開いた実体の (dev, ino) と一致することを確かめる。
        pub(super) fn open_dir(
            path: PathBuf,
            expected: Option<(u64, u64)>,
        ) -> Result<Self, OciError> {
            let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| root_inaccessible())?;
            let fd = at::openat2(
                None,
                &c,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
                0,
                0,
            )
            .map_err(|e| match errno(&e) {
                Some(ENOSYS | EPERM) => OciError::new(
                    OciErrorCode::Unimplemented,
                    "image store requires openat2 (Linux 5.6 or later)",
                ),
                _ => root_inaccessible(),
            })?;
            let meta = File::from(fd.try_clone().map_err(|_| root_inaccessible())?)
                .metadata()
                .map_err(|_| root_inaccessible())?;
            let id = (meta.dev(), meta.ino());
            if expected.is_some_and(|x| x != id) {
                return Err(OciError::new(
                    OciErrorCode::Internal,
                    "image store root changed while opening",
                ));
            }
            Ok(Self {
                path,
                id,
                inner: fd,
            })
        }

        fn open_at(&self, rel: &std::ffi::CStr, flags: u64, mode: u64) -> io::Result<OwnedFd> {
            at::openat2(
                Some(self.inner.as_fd()),
                rel,
                flags | O_CLOEXEC,
                mode,
                RESOLVE,
            )
        }

        fn name_cstr(name: &OsStr) -> io::Result<CString> {
            at::component_cstring(name)
        }

        /// root 自身のメタデータ（開いた fd の fstat。パスの差し替えに影響されない）。
        #[cfg(unix)]
        pub(crate) fn root_meta(&self) -> io::Result<Metadata> {
            File::from(self.inner.try_clone()?).metadata()
        }

        /// 直下の名前のメタデータ。symlink は辿らず symlink 自身のものを返す。無ければ `None`。
        pub(crate) fn stat_name(&self, name: impl AsRef<OsStr>) -> io::Result<Option<Metadata>> {
            let n = Self::name_cstr(name.as_ref())?;
            match self.open_at(&n, O_PATH | O_NOFOLLOW, 0) {
                Ok(fd) => File::from(fd).metadata().map(Some),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// ロックファイルを開く（無ければ 0600 で作る）。symlink は `ELOOP`、ディレクトリは `EISDIR`。
        pub(crate) fn open_lock(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
            let n = Self::name_cstr(name.as_ref())?;
            self.open_at(&n, O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0o600)
                .map(File::from)
        }

        /// 読み取りで開く。無ければ `None`。symlink は `ELOOP`。FIFO で止まらないよう `O_NONBLOCK`。
        pub(crate) fn open_read(&self, name: impl AsRef<OsStr>) -> io::Result<Option<File>> {
            let n = Self::name_cstr(name.as_ref())?;
            match self.open_at(&n, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0) {
                Ok(fd) => Ok(Some(File::from(fd))),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// 新規ファイルを 0600 で排他作成する（既存なら `AlreadyExists`）。
        pub(crate) fn create_new(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
            let n = Self::name_cstr(name.as_ref())?;
            self.open_at(&n, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
                .map(File::from)
        }

        /// 直下の名前を付け替える（`to` があれば原子的に置き換える）。
        pub(crate) fn rename(
            &self,
            from: impl AsRef<OsStr>,
            to: impl AsRef<OsStr>,
        ) -> io::Result<()> {
            at::renameat_names(
                self.inner.as_fd(),
                from.as_ref(),
                self.inner.as_fd(),
                to.as_ref(),
            )
        }

        /// 直下の名前を unlink する（ディレクトリは消さない）。
        pub(crate) fn unlink(&self, name: impl AsRef<OsStr>) -> io::Result<()> {
            at::unlinkat_name(self.inner.as_fd(), name.as_ref(), false)
        }

        /// root ディレクトリを fsync する。
        pub(crate) fn sync(&self) -> io::Result<()> {
            File::from(self.inner.try_clone()?).sync_all()
        }

        /// 直下の名前の一覧（最大 `limit` 件。`.` と `..` は除く）。
        ///
        /// dup ではなく新しい open file description を開いて走査する（dup はファイル位置を共有し、
        /// 2 回目以降の走査が空になる）。
        pub(crate) fn list_names(&self, limit: usize) -> io::Result<Vec<OsString>> {
            let dot = at::relative_cstring::<&str>(&[])?;
            let dir = self.open_at(&dot, O_RDONLY | O_DIRECTORY, 0)?;
            let mut out = Vec::new();
            let mut buf = vec![0u8; 8192];
            while out.len() < limit {
                let n = at::getdents64(dir.as_fd(), &mut buf)?;
                if n == 0 {
                    break;
                }
                let chunk = buf.get(..n).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "malformed directory entry")
                })?;
                at::for_each_dirent(chunk, |name| {
                    if out.len() < limit {
                        out.push(OsString::from_vec(name.to_vec()));
                    }
                })?;
            }
            Ok(out)
        }

        /// `blobs/sha256` を開く。両方が通常ディレクトリなら `Some`、どちらかが無ければ `None`、
        /// symlink・非ディレクトリは `FailedPrecondition`（`usage::check_blob_dirs` と同じ判定）。
        pub(crate) fn open_blob_dir(&self) -> Result<Option<BlobDir>, OciError> {
            let rel = at::relative_cstring(&BLOB_DIR).map_err(|_| blob_dir_stat_failed())?;
            match self.open_at(&rel, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0) {
                Ok(fd) => Ok(Some(BlobDir(fd))),
                Err(e) => match errno(&e) {
                    Some(ELOOP | ENOTDIR) => Err(blob_dir_not_plain()),
                    _ if e.kind() == io::ErrorKind::NotFound => Ok(None),
                    _ => Err(blob_dir_stat_failed()),
                },
            }
        }
    }

    /// 開いた `blobs/sha256`。
    #[derive(Debug)]
    pub(crate) struct BlobDir(OwnedFd);

    impl BlobDir {
        /// blob のメタデータ（symlink は辿らない）。無ければ `None`。
        pub(crate) fn stat(&self, hex: &str) -> io::Result<Option<Metadata>> {
            let n = at::component_cstring(OsStr::new(hex))?;
            match at::openat2(
                Some(self.0.as_fd()),
                &n,
                O_PATH | O_NOFOLLOW | O_CLOEXEC,
                0,
                RESOLVE,
            ) {
                Ok(fd) => File::from(fd).metadata().map(Some),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// blob を unlink する。
        pub(crate) fn unlink(&self, hex: &str) -> io::Result<()> {
            at::unlinkat_name(self.0.as_fd(), OsStr::new(hex), false)
        }

        /// ディレクトリを fsync する。
        pub(crate) fn sync(&self) -> io::Result<()> {
            File::from(self.0.try_clone()?).sync_all()
        }
    }
}

// ---------------------------------------------------------------------------
// その他の unix と Windows: パス起点（従来の実装）
// ---------------------------------------------------------------------------
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod imp {
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File, Metadata, OpenOptions};
    use std::io;
    use std::path::PathBuf;

    use super::{OciError, RootHandle, root_inaccessible};
    use crate::image_management::usage::{blob_dir, check_blob_dirs};

    fn opts_mode(opts: &mut OpenOptions) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = opts;
    }

    impl RootHandle {
        /// `path`（正規パス）を記録する。`expected` があれば現在の (dev, ino) と一致することを確かめる。
        pub(super) fn open_dir(
            path: PathBuf,
            expected: Option<(u64, u64)>,
        ) -> Result<Self, OciError> {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let m = fs::symlink_metadata(&path).map_err(|_| root_inaccessible())?;
                let id = (m.dev(), m.ino());
                if expected.is_some_and(|x| x != id) {
                    return Err(OciError::new(
                        super::OciErrorCode::Internal,
                        "image store root changed while opening",
                    ));
                }
                Ok(Self { path, id })
            }
            #[cfg(not(unix))]
            {
                let _ = (expected, root_inaccessible as fn() -> OciError);
                Ok(Self { path })
            }
        }

        /// root 自身のメタデータ（パスの lstat）。
        #[cfg(unix)]
        pub(crate) fn root_meta(&self) -> io::Result<Metadata> {
            fs::symlink_metadata(&self.path)
        }

        /// 直下の名前のメタデータ（symlink は辿らない）。無ければ `None`。
        pub(crate) fn stat_name(&self, name: impl AsRef<OsStr>) -> io::Result<Option<Metadata>> {
            match fs::symlink_metadata(self.path.join(name.as_ref())) {
                Ok(m) => Ok(Some(m)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// ロックファイルを開く（無ければ 0600 で作る）。
        pub(crate) fn open_lock(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
            let mut opts = OpenOptions::new();
            opts.create(true).truncate(false).write(true);
            opts_mode(&mut opts);
            opts.open(self.path.join(name.as_ref()))
        }

        /// 読み取りで開く。無ければ `None`。
        pub(crate) fn open_read(&self, name: impl AsRef<OsStr>) -> io::Result<Option<File>> {
            match File::open(self.path.join(name.as_ref())) {
                Ok(f) => Ok(Some(f)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// 新規ファイルを排他作成する。
        pub(crate) fn create_new(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            opts_mode(&mut opts);
            opts.open(self.path.join(name.as_ref()))
        }

        /// 直下の名前を付け替える。
        pub(crate) fn rename(
            &self,
            from: impl AsRef<OsStr>,
            to: impl AsRef<OsStr>,
        ) -> io::Result<()> {
            fs::rename(self.path.join(from.as_ref()), self.path.join(to.as_ref()))
        }

        /// 直下の名前を unlink する。
        pub(crate) fn unlink(&self, name: impl AsRef<OsStr>) -> io::Result<()> {
            fs::remove_file(self.path.join(name.as_ref()))
        }

        /// root ディレクトリを fsync する（Windows は std で開けないため何もしない）。
        pub(crate) fn sync(&self) -> io::Result<()> {
            #[cfg(unix)]
            {
                File::open(&self.path)?.sync_all()
            }
            #[cfg(not(unix))]
            {
                Ok(())
            }
        }

        /// 直下の名前の一覧（最大 `limit` 件）。
        pub(crate) fn list_names(&self, limit: usize) -> io::Result<Vec<OsString>> {
            Ok(fs::read_dir(&self.path)?
                .flatten()
                .take(limit)
                .map(|e| e.file_name())
                .collect())
        }

        /// `blobs/sha256` を検査して開く（無ければ `None`）。
        pub(crate) fn open_blob_dir(&self) -> Result<Option<BlobDir>, OciError> {
            Ok(check_blob_dirs(&self.path)?.then(|| BlobDir(blob_dir(&self.path))))
        }
    }

    /// `blobs/sha256` のパス。
    #[derive(Debug)]
    pub(crate) struct BlobDir(PathBuf);

    impl BlobDir {
        /// blob のメタデータ（symlink は辿らない）。無ければ `None`。
        pub(crate) fn stat(&self, hex: &str) -> io::Result<Option<Metadata>> {
            match fs::symlink_metadata(self.0.join(hex)) {
                Ok(m) => Ok(Some(m)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// blob を unlink する。
        pub(crate) fn unlink(&self, hex: &str) -> io::Result<()> {
            fs::remove_file(self.0.join(hex))
        }

        /// ディレクトリを fsync する（Windows は何もしない）。
        pub(crate) fn sync(&self) -> io::Result<()> {
            #[cfg(unix)]
            {
                File::open(&self.0)?.sync_all()
            }
            #[cfg(not(unix))]
            {
                Ok(())
            }
        }
    }
}

pub(crate) use imp::BlobDir;

impl RootHandle {
    /// 正規化済みのパスと検査時の (dev, ino) から開く（`ImageStore::open` が信頼検査の後に呼ぶ）。
    #[cfg(unix)]
    pub(crate) fn open_checked(path: PathBuf, id: (u64, u64)) -> Result<Self, OciError> {
        Self::open_dir(path, Some(id))
    }

    /// 正規化済みのパスから開く（非 unix は dev / ino を持たない）。
    #[cfg(not(unix))]
    pub(crate) fn open_checked(path: PathBuf) -> Result<Self, OciError> {
        Self::open_dir(path, None)
    }

    /// `blobs/sha256` の検査（`usage::check_blob_dirs` と同じ判定。root の fd 起点）。
    pub(crate) fn check_blob_dirs(&self) -> Result<bool, OciError> {
        Ok(self.open_blob_dir()?.is_some())
    }
}

/// 試験用: パスから検査なしでハンドルを開く（永続化層の関数へ渡す）。
#[cfg(test)]
pub(super) fn rh(p: &Path) -> RootHandle {
    RootHandle::open_unchecked(p).expect("open root handle")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp_root(label: &str) -> PathBuf {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "fc-oci-roothandle-{}-{}-{label}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).expect("mkdir");
        p
    }

    fn sorted(h: &RootHandle) -> Vec<String> {
        let mut v: Vec<String> = h
            .list_names(100)
            .expect("list")
            .into_iter()
            .map(|n| n.to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// OCI-7・SEC-1・#2638: 名前の一覧は何度呼んでも同じ結果（位置を共有しない）。
    #[test]
    fn oci7_list_names_is_repeatable() {
        let r = temp_root("list");
        std::fs::write(r.join("a"), b"1").expect("a");
        std::fs::write(r.join("b"), b"2").expect("b");
        let h = RootHandle::open_unchecked(&r).expect("open");
        assert_eq!(sorted(&h), vec!["a", "b"]);
        assert_eq!(sorted(&h), vec!["a", "b"]);
        assert_eq!(h.list_names(1).expect("limited").len(), 1);
        let _ = std::fs::remove_dir_all(&r);
    }

    /// OCI-7・SEC-1・#2638: `stat_name` は symlink を辿らず、symlink 自身を返す。
    #[cfg(unix)]
    #[test]
    fn oci7_stat_name_does_not_follow_symlink() {
        let r = temp_root("stat");
        std::fs::write(r.join("target"), b"x").expect("target");
        std::os::unix::fs::symlink(r.join("target"), r.join("lnk")).expect("link");
        let h = RootHandle::open_unchecked(&r).expect("open");
        let m = h.stat_name("lnk").expect("stat").expect("some");
        assert!(m.file_type().is_symlink());
        assert!(
            h.stat_name("target")
                .expect("stat")
                .expect("some")
                .is_file()
        );
        assert!(h.stat_name("missing").expect("stat").is_none());
        let _ = std::fs::remove_dir_all(&r);
    }

    /// OCI-7・SEC-1・#2638: `blobs/sha256` が symlink なら `FailedPrecondition`、無ければ `None`。
    #[cfg(unix)]
    #[test]
    fn oci7_open_blob_dir_rejects_symlink() {
        let r = temp_root("blobdir");
        let h = RootHandle::open_unchecked(&r).expect("open");
        assert!(h.open_blob_dir().expect("absent").is_none());
        let other = temp_root("blobdir-other");
        std::fs::create_dir_all(r.join("blobs")).expect("blobs");
        std::os::unix::fs::symlink(&other, r.join("blobs").join("sha256")).expect("link");
        let e = h.open_blob_dir().expect_err("symlinked");
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "blob directory is not a plain directory");
        let _ = std::fs::remove_dir_all(&r);
        let _ = std::fs::remove_dir_all(&other);
    }

    /// OCI-7・SEC-1・#2638: root を別名へ移して空のディレクトリを置いても、ハンドルは元の実体を指す。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn oci7_handle_follows_moved_root() {
        let r = temp_root("moved");
        let h = RootHandle::open_unchecked(&r).expect("open");
        let moved = r.with_file_name(format!(
            "{}-moved",
            r.file_name().expect("name").to_string_lossy()
        ));
        std::fs::rename(&r, &moved).expect("rename");
        std::fs::create_dir(&r).expect("decoy");
        h.create_new("f").expect("create").sync_all().expect("sync");
        assert_eq!(std::fs::read_dir(&r).expect("decoy dir").count(), 0);
        assert!(moved.join("f").is_file());
        assert!(!h.matches(&r));
        let _ = std::fs::remove_dir_all(&r);
        let _ = std::fs::remove_dir_all(&moved);
    }
}
