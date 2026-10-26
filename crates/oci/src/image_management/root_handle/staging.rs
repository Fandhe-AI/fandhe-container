//! 検査済み root の fd 起点の staging 操作（`StagingDir` / `PullDir`。OCI-7・SEC-1・REPAIR-3・#2694）。
//!
//! # 役割と呼び出し元
//!
//! `pull::PullSession`（staging の作成・`@pull.lock`・blob の検証・公開・中止）と `pull_recovery`
//! （クラッシュで残った staging の走査と回収）が、`<root>/staging/<pull-id>/` に対する操作を
//! `RootHandle` の検査済み root の fd 起点で行うための口である。入口の `reverify_root` の後に root が
//! 別のディレクトリへ差し替えられても、作成・書き込み・削除は検査済みの実体にだけ届き、おとりには届かない
//! （`root_handle` のモジュール doc の「入口の検出と区間内の閉じ込めの 2 層」の続き）。
//!
//! - `StagingDir`: 開いた `<root>/staging`。pull ディレクトリの作成・列挙・削除の起点。
//! - `PullDir`: 開いた `<root>/staging/<pull-id>`。`@pull.lock`・ステージングした blob の stat / open / unlink と、
//!   `BlobDir`（`blobs/sha256`）への公開（`link_from` / `rename_from`）の元になる。
//!
//! 名前は定数（`staging`・`@pull.lock`）・検証済みの `PullId`・検証済み digest の hex の 1 コンポーネントに限り、
//! `sys::at::component_cstring` が入口で再検証する（外部入力からパスを組まない）。
//!
//! # 方式と `cfg` の局所化
//!
//! `root_handle` と同じ分割（`cfg(target_os/arch)` は本ファイルと `root_handle.rs` の中だけ）。Linux の
//! x86_64 / aarch64 は root の fd からの `openat2`（`RESOLVE_IN_ROOT | NO_SYMLINKS | NO_MAGICLINKS | NO_XDEV`、
//! 最後の要素も `O_NOFOLLOW`）と `*at`。それ以外はパス起点の従来実装で、差し替えは入口の再検査だけで検出する。
//!
//! # 移していないもの
//!
//! fetcher（`RegistryClient::fetch_blob`）が書く先は `PullSession::staged_blob_path` が返すパスである
//! （fetcher の API がパスを受け取るため）。`PullDir::matches_path` で、そのパスが保持している pull ディレクトリと
//! 同じ実体を指すことを確かめる用途に限って使う。

pub(crate) use imp::{PullDir, StagingDir};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod imp {
    use std::ffi::{OsStr, OsString};
    use std::fs::{File, Metadata};
    use std::io;
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;

    use super::super::imp::RESOLVE;
    use crate::error::{OciError, OciErrorCode};
    use crate::image_management::PullId;
    use crate::image_management::root_handle::RootHandle;
    use crate::sys::at::{
        self, ELOOP, ENOTDIR, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_NONBLOCK,
        O_PATH, O_RDONLY, O_WRONLY,
    };

    /// ストア root 直下の staging ディレクトリ名。
    const STAGING: &str = "staging";

    fn open_in(dir: &OwnedFd, name: &OsStr, flags: u64, mode: u64) -> io::Result<OwnedFd> {
        let n = at::component_cstring(name)?;
        at::openat2(Some(dir.as_fd()), &n, flags | O_CLOEXEC, mode, RESOLVE)
    }

    /// 直下の名前のメタデータ（`O_PATH | O_NOFOLLOW`。symlink は辿らず symlink 自身を返す）。無ければ `None`。
    fn stat_in(dir: &OwnedFd, name: &OsStr) -> io::Result<Option<Metadata>> {
        match open_in(dir, name, O_PATH | O_NOFOLLOW, 0) {
            Ok(fd) => File::from(fd).metadata().map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// 直下の名前の一覧（最大 `limit` 件）。新しい open file description で走査するため、何度呼んでも同じ結果になる。
    fn list_in(dir: &OwnedFd, limit: usize) -> io::Result<Vec<OsString>> {
        let dot = at::relative_cstring::<&str>(&[])?;
        let fd = at::openat2(
            Some(dir.as_fd()),
            &dot,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC,
            0,
            RESOLVE,
        )?;
        let mut out = Vec::new();
        let mut buf = vec![0u8; 8192];
        while out.len() < limit {
            let n = at::getdents64(fd.as_fd(), &mut buf)?;
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

    fn open_dir_in(dir: &OwnedFd, name: &OsStr) -> io::Result<OwnedFd> {
        open_in(dir, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0)
    }

    fn not_plain(e: &io::Error) -> bool {
        matches!(e.raw_os_error(), Some(ELOOP | ENOTDIR))
    }

    impl RootHandle {
        /// `<root>/staging` を開く。無ければ `None`。symlink・非ディレクトリは `FailedPrecondition`
        /// （文言は呼び出し側の契約に合わせて `not_dir_msg`）。
        pub(crate) fn open_staging_dir(
            &self,
            not_dir_msg: &'static str,
        ) -> Result<Option<StagingDir>, OciError> {
            match self.open_at(
                &at::component_cstring(OsStr::new(STAGING)).map_err(|_| stage_stat_failed())?,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW,
                0,
            ) {
                Ok(fd) => Ok(Some(StagingDir(fd))),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) if not_plain(&e) => {
                    Err(OciError::new(OciErrorCode::FailedPrecondition, not_dir_msg))
                }
                Err(_) => Err(stage_stat_failed()),
            }
        }

        /// `<root>/staging` を開く。無ければ 0700 で作る（並行する別の作成者に先を越されたら開き直して検査する）。
        pub(crate) fn ensure_staging_dir(&self) -> Result<StagingDir, OciError> {
            const NOT_DIR: &str = "staging is not a directory";
            if let Some(s) = self.open_staging_dir(NOT_DIR)? {
                return Ok(s);
            }
            match at::mkdirat_name(self.inner.as_fd(), OsStr::new(STAGING), 0o700) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(_) => {
                    return Err(OciError::new(
                        OciErrorCode::Internal,
                        "failed to create staging",
                    ));
                }
            }
            self.open_staging_dir(NOT_DIR)?
                .ok_or_else(stage_stat_failed)
        }
    }

    fn stage_stat_failed() -> OciError {
        OciError::new(OciErrorCode::Internal, "failed to stat staging")
    }

    /// 開いた `<root>/staging`。
    #[derive(Debug)]
    pub(crate) struct StagingDir(OwnedFd);

    impl StagingDir {
        /// `<id>` を 0700 で作って開く（既にあれば `AlreadyExists`）。
        pub(crate) fn create_pull_dir(&self, id: &PullId) -> io::Result<PullDir> {
            at::mkdirat_name(self.0.as_fd(), OsStr::new(id.as_str()), 0o700)?;
            self.open_pull_dir(id).inspect_err(|_| {
                // 作ったばかりで他者はまだ使っていない。開けなかった空ディレクトリを残さない。
                let _ = self.remove_pull_dir(id);
            })
        }

        /// `<id>` を開く（symlink・非ディレクトリは `InvalidInput`、無ければ `NotFound`）。
        pub(crate) fn open_pull_dir(&self, id: &PullId) -> io::Result<PullDir> {
            open_dir_in(&self.0, OsStr::new(id.as_str()))
                .map(PullDir)
                .map_err(|e| {
                    if not_plain(&e) {
                        io::Error::new(io::ErrorKind::InvalidInput, "pull entry is not a directory")
                    } else {
                        e
                    }
                })
        }

        /// 直下の名前のメタデータ（symlink は辿らない）。無ければ `None`。
        pub(crate) fn stat_name(&self, name: &OsStr) -> io::Result<Option<Metadata>> {
            stat_in(&self.0, name)
        }

        /// 直下の名前の一覧（最大 `limit` 件）。
        pub(crate) fn list_names(&self, limit: usize) -> io::Result<Vec<OsString>> {
            list_in(&self.0, limit)
        }

        /// 空の `<id>` ディレクトリを消す（`rmdir`）。
        pub(crate) fn remove_pull_dir(&self, id: &PullId) -> io::Result<()> {
            at::unlinkat_name(self.0.as_fd(), OsStr::new(id.as_str()), true)
        }
    }

    /// 開いた `<root>/staging/<pull-id>`。
    #[derive(Debug)]
    pub(crate) struct PullDir(pub(in crate::image_management::root_handle) OwnedFd);

    impl PullDir {
        /// ディレクトリ自身のメタデータ（開いた fd の fstat。所有者の取得に使う）。
        pub(crate) fn dir_meta(&self) -> io::Result<Metadata> {
            File::from(self.0.try_clone()?).metadata()
        }

        /// `@pull.lock` を 0600 で排他作成する（既存なら `AlreadyExists`。symlink は辿らない）。
        pub(crate) fn create_lock(&self, name: &str) -> io::Result<File> {
            open_in(
                &self.0,
                OsStr::new(name),
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                0o600,
            )
            .map(File::from)
        }

        /// 生存確認のために `@pull.lock` を開く（作成しない・symlink は辿らない・FIFO で止まらない）。
        pub(crate) fn open_lock_for_probe(&self, name: &str) -> io::Result<File> {
            open_in(
                &self.0,
                OsStr::new(name),
                O_RDONLY | O_NOFOLLOW | O_NONBLOCK,
                0,
            )
            .map(File::from)
        }

        /// 直下の名前のメタデータ（symlink は辿らない）。無ければ `None`。
        pub(crate) fn stat_name(&self, name: &str) -> io::Result<Option<Metadata>> {
            stat_in(&self.0, OsStr::new(name))
        }

        /// 直下の blob を symlink を辿らず読み取りで開く（FIFO で止まらないよう `O_NONBLOCK`）。無ければ
        /// `NotFound`、symlink・非ディレクトリの途中要素は `InvalidInput`。
        pub(crate) fn open_nofollow(&self, name: &str) -> io::Result<File> {
            open_in(
                &self.0,
                OsStr::new(name),
                O_RDONLY | O_NOFOLLOW | O_NONBLOCK,
                0,
            )
            .map(File::from)
            .map_err(|e| {
                if not_plain(&e) {
                    io::Error::new(io::ErrorKind::InvalidInput, "blob is not a plain file")
                } else {
                    e
                }
            })
        }

        /// 直下の名前を unlink する（ディレクトリは消さない）。
        pub(crate) fn unlink(&self, name: &str) -> io::Result<()> {
            at::unlinkat_name(self.0.as_fd(), OsStr::new(name), false)
        }

        /// 直下の名前の一覧（最大 `limit` 件）。
        pub(crate) fn list_names(&self, limit: usize) -> io::Result<Vec<OsString>> {
            list_in(&self.0, limit)
        }

        /// 直下の名前を symlink を辿らず木ごと消す（無ければ成功）。
        pub(crate) fn remove_child_tree(&self, name: &OsStr) -> io::Result<()> {
            crate::layer::remove_name_tree(self.0.as_fd(), name)
                .map_err(|e| io::Error::other(e.message().to_owned()))
        }

        /// `p`（パスで辿った pull ディレクトリ）が、この fd と同じ実体か（dev / ino の照合）。
        pub(crate) fn matches_path(&self, p: &Path) -> bool {
            let Ok(mine) = self.dir_meta() else {
                return false;
            };
            std::fs::metadata(p).is_ok_and(|m| (m.dev(), m.ino()) == (mine.dev(), mine.ino()))
        }
    }
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod imp {
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File, Metadata, OpenOptions};
    use std::io;
    use std::path::{Path, PathBuf};

    use crate::error::{OciError, OciErrorCode};
    use crate::image_management::PullId;
    use crate::image_management::root_handle::RootHandle;

    const STAGING: &str = "staging";

    fn stat_path(p: &Path) -> io::Result<Option<Metadata>> {
        match fs::symlink_metadata(p) {
            Ok(m) => Ok(Some(m)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn list_path(p: &Path, limit: usize) -> io::Result<Vec<OsString>> {
        // 各エントリの読み取りエラーは捨てず伝播する（不完全な一覧を成功として返さない。OCI-7）。
        let mut out = Vec::new();
        for e in fs::read_dir(p)?.take(limit) {
            out.push(e?.file_name());
        }
        Ok(out)
    }

    fn stage_stat_failed() -> OciError {
        OciError::new(OciErrorCode::Internal, "failed to stat staging")
    }

    impl RootHandle {
        /// `<root>/staging` を調べる。無ければ `None`。symlink・非ディレクトリは `FailedPrecondition`。
        pub(crate) fn open_staging_dir(
            &self,
            not_dir_msg: &'static str,
        ) -> Result<Option<StagingDir>, OciError> {
            let p = self.path.join(STAGING);
            match stat_path(&p) {
                Ok(Some(m)) if m.is_dir() => Ok(Some(StagingDir(p))),
                Ok(Some(_)) => Err(OciError::new(OciErrorCode::FailedPrecondition, not_dir_msg)),
                Ok(None) => Ok(None),
                Err(_) => Err(stage_stat_failed()),
            }
        }

        /// `<root>/staging` を調べる。無ければ 0700 で作る。
        pub(crate) fn ensure_staging_dir(&self) -> Result<StagingDir, OciError> {
            const NOT_DIR: &str = "staging is not a directory";
            if let Some(s) = self.open_staging_dir(NOT_DIR)? {
                return Ok(s);
            }
            match make_dir(&self.path.join(STAGING)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(_) => {
                    return Err(OciError::new(
                        OciErrorCode::Internal,
                        "failed to create staging",
                    ));
                }
            }
            self.open_staging_dir(NOT_DIR)?
                .ok_or_else(stage_stat_failed)
        }
    }

    fn make_dir(path: &Path) -> io::Result<()> {
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut b = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(path)
    }

    /// `<root>/staging` のパス。
    #[derive(Debug)]
    pub(crate) struct StagingDir(PathBuf);

    impl StagingDir {
        /// `<id>` を 0700 で作って返す（既にあれば `AlreadyExists`）。
        pub(crate) fn create_pull_dir(&self, id: &PullId) -> io::Result<PullDir> {
            let p = self.0.join(id.as_str());
            make_dir(&p)?;
            Ok(PullDir(p))
        }

        /// `<id>` を調べて返す（symlink・非ディレクトリは `InvalidInput`、無ければ `NotFound`）。
        pub(crate) fn open_pull_dir(&self, id: &PullId) -> io::Result<PullDir> {
            let p = self.0.join(id.as_str());
            match fs::symlink_metadata(&p)? {
                m if m.is_dir() => Ok(PullDir(p)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "pull entry is not a directory",
                )),
            }
        }

        /// 直下の名前のメタデータ（symlink は辿らない）。無ければ `None`。
        pub(crate) fn stat_name(&self, name: &OsStr) -> io::Result<Option<Metadata>> {
            stat_path(&self.0.join(name))
        }

        /// 直下の名前の一覧（最大 `limit` 件）。
        pub(crate) fn list_names(&self, limit: usize) -> io::Result<Vec<OsString>> {
            list_path(&self.0, limit)
        }

        /// 空の `<id>` ディレクトリを消す。
        pub(crate) fn remove_pull_dir(&self, id: &PullId) -> io::Result<()> {
            fs::remove_dir(self.0.join(id.as_str()))
        }
    }

    /// `<root>/staging/<pull-id>` のパス。
    #[derive(Debug)]
    pub(crate) struct PullDir(pub(in crate::image_management::root_handle) PathBuf);

    impl PullDir {
        /// ディレクトリ自身のメタデータ（lstat。所有者の取得は unix だけが使う）。
        #[cfg(unix)]
        pub(crate) fn dir_meta(&self) -> io::Result<Metadata> {
            fs::symlink_metadata(&self.0)
        }

        /// `@pull.lock` を 0600 で排他作成する。
        pub(crate) fn create_lock(&self, name: &str) -> io::Result<File> {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            opts.open(self.0.join(name))
        }

        /// 生存確認のために `@pull.lock` を開く（作成しない。Windows の `LockFileEx` は読み書き権限が要る）。
        pub(crate) fn open_lock_for_probe(&self, name: &str) -> io::Result<File> {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(false)
                .open(self.0.join(name))
        }

        /// 直下の名前のメタデータ（symlink は辿らない）。無ければ `None`。
        pub(crate) fn stat_name(&self, name: &str) -> io::Result<Option<Metadata>> {
            stat_path(&self.0.join(name))
        }

        /// 直下の blob を symlink を辿らず読み取りで開く（unix のみ。Windows の検証はパスで開く）。
        /// 無ければ `NotFound`、通常ファイルでなければ `InvalidInput`。
        #[cfg(unix)]
        pub(crate) fn open_nofollow(&self, name: &str) -> io::Result<File> {
            crate::layer::open_blob_nofollow(&self.0.join(name)).map_err(|e| match e.code() {
                OciErrorCode::NotFound => io::Error::new(io::ErrorKind::NotFound, "blob not found"),
                OciErrorCode::InvalidArgument | OciErrorCode::FailedPrecondition => {
                    io::Error::new(io::ErrorKind::InvalidInput, "blob is not a plain file")
                }
                _ => io::Error::other("failed to open blob"),
            })
        }

        /// 直下の名前を unlink する。
        pub(crate) fn unlink(&self, name: &str) -> io::Result<()> {
            fs::remove_file(self.0.join(name))
        }

        /// 直下の名前の一覧（最大 `limit` 件）。
        pub(crate) fn list_names(&self, limit: usize) -> io::Result<Vec<OsString>> {
            list_path(&self.0, limit)
        }

        /// 直下の名前を木ごと消す（symlink は辿らず、ディレクトリ以外は `remove_file`）。
        pub(crate) fn remove_child_tree(&self, name: &OsStr) -> io::Result<()> {
            let p = self.0.join(name);
            if fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir()) {
                fs::remove_dir_all(&p)
            } else {
                fs::remove_file(&p)
            }
        }

        /// パス起点の実装は同じパスを辿るため常に真（差し替えは入口の再検査だけで検出する）。
        pub(crate) fn matches_path(&self, _p: &Path) -> bool {
            true
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::RootHandle;
    use crate::image_management::PullId;

    /// OCI-7・SEC-1・#2694: pull ディレクトリ直下の名前が symlink でも `stat_name` は `ELOOP` にせず、
    /// symlink 自身を返す（呼び出し側が通常ファイルでないものとして拒否・再取得できる）。
    #[test]
    fn oci7_stat_name_returns_symlink_itself_not_error() {
        let r = std::env::temp_dir().join(format!("fc-oci-staging-stat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        std::fs::create_dir_all(&r).expect("mkdir");
        let h = RootHandle::open_unchecked(&r).expect("open");
        let staging = h.ensure_staging_dir().expect("staging");
        let id = PullId::new("1-2-3").expect("id");
        let pd = staging.create_pull_dir(&id).expect("pull dir");
        let dir = r.join("staging").join("1-2-3");
        std::fs::write(r.join("target"), b"x").expect("target");
        std::os::unix::fs::symlink(r.join("target"), dir.join("abc")).expect("link");
        std::fs::write(dir.join("reg"), b"y").expect("reg");

        let m = pd.stat_name("abc").expect("no error").expect("some");
        assert!(m.file_type().is_symlink());
        assert!(!m.is_file());
        assert!(pd.stat_name("reg").expect("ok").expect("some").is_file());
        assert!(pd.stat_name("none").expect("ok").is_none());
        let _ = std::fs::remove_dir_all(&r);
    }
}
