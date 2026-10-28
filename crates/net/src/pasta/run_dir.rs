//! pasta の PID ファイルの置き場所 `<state_root>/@pasta/<container-id>/` の作成・古い `pid` の掃除・削除
//! （NET-9・SEC-1・REPAIR-5・#1938。`docs/design/rootless-network.md` 12.8）。
//!
//! - 呼び出し元: supervisor の launch（手順 8。#1940）が [`PastaRunDir::prepare`] で作り、
//!   [`super::process::spawn_pasta`] に渡す。stop では [`PastaRunDir::remove`]、CLI の delete は残骸だけを
//!   [`remove_pasta_run_dir`] で消す（記録の pid でのプロセスの探索・kill はしない。pid の再利用を避ける。12.10）。
//! - 状態ルートは `BorrowedFd` で受ける（パス文字列を受けない）。作成・検査・削除はすべて fd 起点
//!   （`/proc/thread-self/fd/<N>/…` の magic link と `openat(O_NOFOLLOW)`）で行い、パスを再解決しない。
//!   最終要素の symlink は mkdir でも unlink でも辿らない。
//! - `@pasta`・`<id>` は 0700・所有者は実効 UID。既存でも基準外（種別・所有者・`mode & 0o077`）なら
//!   `FailedPrecondition` とし、chmod で直さない（fail-closed）。
//! - 既存の `pid` は通常ファイル・所有者 euid・nlink 1 のときだけ消す。それ以外（symlink・ディレクトリ・FIFO 等）は
//!   `FailedPrecondition`。古い値が残ると準備完了の判定を誤らせるため、spawn の前に必ず消す。
//! - 残余: 同じ UID による差し替えは信頼の範囲内（防がない）。
//! - Linux 以外では [`PastaRunDir`] を作れない（`prepare` は Linux のみ。CLI-1）。
//!
//! エラーの message は固定の英文で、パス・container id を含まない（ERR-1）。

use std::path::{Path, PathBuf};

use crate::error::{NetError, NetErrorCode};

/// 置き場所の親ディレクトリ名（状態ルート直下）。
pub const PASTA_DIR_NAME: &str = "@pasta";
/// PID ファイル名。
pub const PASTA_PID_FILE_NAME: &str = "pid";
/// container id の最大バイト数（core の `ContainerId` に合わせる）。
pub const CONTAINER_ID_MAX_BYTES: usize = 255;

/// container id が不正（空・長すぎる・使えない文字・`.` / `..`）。
pub const MSG_ID_INVALID: &str =
    "container id must be 1 to 255 bytes of [A-Za-z0-9._-] and not . or ..";
/// 状態ルートの絶対パスを得られない（削除済みなど）。
pub const MSG_ROOT_PATH: &str = "state root path could not be resolved";
/// PID ファイルのパスが不正（相対・長すぎる・制御文字）。
pub const MSG_PID_PATH: &str = "pasta pid file path is invalid";
/// 置き場所のディレクトリが基準外（種別・所有者・権限）。
pub const MSG_DIR_UNTRUSTED: &str =
    "pasta run directory must be a directory owned by the current user with mode 0700";
/// 既存の `pid` が消してよい形でない。
pub const MSG_PID_ENTRY: &str =
    "existing pasta pid entry is not a regular file owned by the current user with one link";
/// 資源枯渇。
pub const MSG_RESOURCE: &str = "resource exhausted while preparing the pasta run directory";
/// 権限不足。
pub const MSG_DENIED: &str = "permission denied while preparing the pasta run directory";
/// 分類できない失敗。
pub const MSG_INTERNAL: &str = "internal error while preparing the pasta run directory";
/// ディレクトリに余分なエントリが残っている。
pub const MSG_NOT_EMPTY: &str = "pasta run directory is not empty";
/// Linux 以外では使えない。
pub const MSG_UNSUPPORTED_OS: &str = super::binary::MSG_UNSUPPORTED_OS;

/// container id の検証（core の `ContainerId` と同じ規則。パス要素に使うための最小規則）。
pub fn validate_container_id(id: &str) -> Result<(), NetError> {
    let ok = !id.is_empty()
        && id.len() <= CONTAINER_ID_MAX_BYTES
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(NetError::new(NetErrorCode::InvalidArgument, MSG_ID_INVALID))
    }
}

/// 作成済みの置き場所（`@pasta/<id>/`）。
///
/// spawn の前に [`PastaRunDir::prepare`] で作る。`pid_path` を pasta の `-P` に渡し、準備完了の判定はこの型が
/// 保持するディレクトリ fd 経由で `pid` を読む。
#[derive(Debug)]
pub struct PastaRunDir {
    pid_path: PathBuf,
    #[cfg(target_os = "linux")]
    held: imp::Held,
}

impl PastaRunDir {
    /// pasta に渡す PID ファイルの絶対パス。
    pub fn pid_path(&self) -> &Path {
        &self.pid_path
    }
}

#[cfg(target_os = "linux")]
impl PastaRunDir {
    /// 置き場所を作る（既存なら検査して再利用し、古い `pid` を消す）。
    pub fn prepare(
        state_root: std::os::fd::BorrowedFd<'_>,
        container_id: &str,
    ) -> Result<Self, NetError> {
        imp::prepare(state_root, container_id)
    }

    /// `pid` と `<id>` ディレクトリを消す（存在しなければ成功扱い）。
    pub fn remove(self) -> Result<(), NetError> {
        imp::remove(&self.held)
    }

    /// 準備完了の判定用: `<id>` ディレクトリの fd 経由で `pid` を読み取り用に開くためのパス。
    pub(super) fn pid_open_path(&self) -> PathBuf {
        imp::pid_open_path(&self.held)
    }
}

/// CLI の delete が残骸を消す入口。`@pasta/<id>/` が無ければ成功。記録の pid でのプロセスの探索・kill はしない。
#[cfg(target_os = "linux")]
pub fn remove_pasta_run_dir(
    state_root: std::os::fd::BorrowedFd<'_>,
    container_id: &str,
) -> Result<(), NetError> {
    imp::remove_existing(state_root, container_id)
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use crate::sys::{self, SysError};
    use std::ffi::CString;
    use std::fs::{DirBuilder, File, Metadata};
    use std::io;
    use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};

    fn err(code: NetErrorCode, msg: &'static str) -> NetError {
        NetError::new(code, msg)
    }

    #[derive(Debug)]
    pub(super) struct Held {
        pasta_dir: OwnedFd,
        id_dir: OwnedFd,
        id: String,
    }

    fn map_io(e: &io::Error) -> NetError {
        match e.raw_os_error() {
            Some(x) if x == sys::EACCES || x == sys::EPERM => {
                err(NetErrorCode::PermissionDenied, MSG_DENIED)
            }
            Some(x) if x == sys::EMFILE || x == sys::ENFILE || x == sys::ENOMEM || x == 28 => {
                err(NetErrorCode::ResourceExhausted, MSG_RESOURCE)
            }
            _ => err(NetErrorCode::Internal, MSG_INTERNAL),
        }
    }

    fn map_sys(e: SysError) -> NetError {
        match e {
            SysError::Os(x) if x == sys::EACCES || x == sys::EPERM => {
                err(NetErrorCode::PermissionDenied, MSG_DENIED)
            }
            SysError::Os(x) if x == sys::EMFILE || x == sys::ENFILE || x == sys::ENOMEM => {
                err(NetErrorCode::ResourceExhausted, MSG_RESOURCE)
            }
            // symlink・ディレクトリでないもの。
            SysError::Os(x) if x == sys::ELOOP || x == sys::ENOTDIR => {
                err(NetErrorCode::FailedPrecondition, MSG_DIR_UNTRUSTED)
            }
            _ => err(NetErrorCode::Internal, MSG_INTERNAL),
        }
    }

    fn stat(fd: &OwnedFd) -> Result<Metadata, NetError> {
        fd.try_clone()
            .and_then(|c| File::from(c).metadata())
            .map_err(|e| map_io(&e))
    }

    fn proc_path(fd: BorrowedFd<'_>, name: &str) -> String {
        format!("/proc/thread-self/fd/{}/{}", fd.as_raw_fd(), name)
    }

    /// `parent` 直下の `name` を開いて基準（ディレクトリ・所有者 euid・`mode & 0o077 == 0`）を確かめる。
    /// 無ければ `None`。
    fn open_checked(
        parent: BorrowedFd<'_>,
        name: &str,
        euid: u32,
    ) -> Result<Option<OwnedFd>, NetError> {
        let cname = CString::new(name).map_err(|_| err(NetErrorCode::Internal, MSG_INTERNAL))?;
        let fd = match sys::open_dir_nofollow_at(parent, &cname) {
            Ok(fd) => fd,
            Err(SysError::Os(x)) if x == sys::ENOENT => return Ok(None),
            Err(e) => return Err(map_sys(e)),
        };
        let m = stat(&fd)?;
        if !m.is_dir() || m.uid() != euid || m.mode() & 0o077 != 0 {
            return Err(err(NetErrorCode::FailedPrecondition, MSG_DIR_UNTRUSTED));
        }
        Ok(Some(fd))
    }

    fn ensure_dir(parent: BorrowedFd<'_>, name: &str, euid: u32) -> Result<OwnedFd, NetError> {
        match DirBuilder::new()
            .mode(0o700)
            .create(proc_path(parent, name))
        {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(map_io(&e)),
        }
        open_checked(parent, name, euid)?.ok_or_else(|| err(NetErrorCode::Internal, MSG_INTERNAL))
    }

    /// 既存の `pid` を、消してよい形のときだけ消す。無ければ何もしない。
    fn remove_stale_pid(id_dir: BorrowedFd<'_>, euid: u32) -> Result<(), NetError> {
        let name = CString::new(PASTA_PID_FILE_NAME)
            .map_err(|_| err(NetErrorCode::Internal, MSG_INTERNAL))?;
        let fd = match sys::open_path_nofollow_at(id_dir, &name) {
            Ok(fd) => fd,
            Err(SysError::Os(x)) if x == sys::ENOENT => return Ok(()),
            Err(e) => return Err(map_sys(e)),
        };
        let m = stat(&fd)?;
        if !m.is_file() || m.uid() != euid || m.nlink() != 1 {
            return Err(err(NetErrorCode::FailedPrecondition, MSG_PID_ENTRY));
        }
        match std::fs::remove_file(proc_path(id_dir, PASTA_PID_FILE_NAME)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(map_io(&e)),
        }
    }

    pub(super) fn prepare(
        state_root: BorrowedFd<'_>,
        container_id: &str,
    ) -> Result<PastaRunDir, NetError> {
        validate_container_id(container_id)?;
        let root_path =
            std::fs::read_link(format!("/proc/thread-self/fd/{}", state_root.as_raw_fd()))
                .map_err(|_| err(NetErrorCode::FailedPrecondition, MSG_ROOT_PATH))?;
        let deleted = root_path.to_str().is_none_or(|s| s.ends_with(" (deleted)"));
        if !root_path.is_absolute() || deleted {
            return Err(err(NetErrorCode::FailedPrecondition, MSG_ROOT_PATH));
        }
        let pid_path = root_path
            .join(PASTA_DIR_NAME)
            .join(container_id)
            .join(PASTA_PID_FILE_NAME);
        super::super::binary::check_shape(&pid_path)
            .map_err(|_| err(NetErrorCode::InvalidArgument, MSG_PID_PATH))?;

        let euid = sys::effective_uid();
        let pasta_dir = ensure_dir(state_root, PASTA_DIR_NAME, euid)?;
        let id_dir = ensure_dir(pasta_dir.as_fd(), container_id, euid)?;
        remove_stale_pid(id_dir.as_fd(), euid)?;
        Ok(PastaRunDir {
            pid_path,
            held: Held {
                pasta_dir,
                id_dir,
                id: container_id.to_owned(),
            },
        })
    }

    pub(super) fn pid_open_path(h: &Held) -> PathBuf {
        PathBuf::from(proc_path(h.id_dir.as_fd(), PASTA_PID_FILE_NAME))
    }

    fn rmdir_id(pasta_dir: BorrowedFd<'_>, id: &str) -> Result<(), NetError> {
        match std::fs::remove_dir(proc_path(pasta_dir, id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            // ENOTEMPTY（39）
            Err(e) if e.raw_os_error() == Some(39) => {
                Err(err(NetErrorCode::FailedPrecondition, MSG_NOT_EMPTY))
            }
            Err(e) => Err(map_io(&e)),
        }
    }

    pub(super) fn remove(h: &Held) -> Result<(), NetError> {
        let euid = sys::effective_uid();
        remove_stale_pid(h.id_dir.as_fd(), euid)?;
        rmdir_id(h.pasta_dir.as_fd(), &h.id)
    }

    pub(super) fn remove_existing(
        state_root: BorrowedFd<'_>,
        container_id: &str,
    ) -> Result<(), NetError> {
        validate_container_id(container_id)?;
        let euid = sys::effective_uid();
        let Some(pasta_dir) = open_checked(state_root, PASTA_DIR_NAME, euid)? else {
            return Ok(());
        };
        let Some(id_dir) = open_checked(pasta_dir.as_fd(), container_id, euid)? else {
            return Ok(());
        };
        remove_stale_pid(id_dir.as_fd(), euid)?;
        drop(id_dir);
        rmdir_id(pasta_dir.as_fd(), container_id)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::sync::atomic::{AtomicU32, Ordering};

    static N: AtomicU32 = AtomicU32::new(0);

    /// 一意な一時ディレクトリ（状態ルート役）を作る。
    fn root() -> (PathBuf, std::fs::File) {
        let p = std::env::temp_dir().join(format!(
            "pasta-run-dir-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("root");
        let f = std::fs::File::open(&p).expect("open root");
        (p, f)
    }

    #[test]
    fn prepare_creates_private_dirs_and_pid_path() {
        let (p, f) = root();
        let d = PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare");
        let canon = std::fs::canonicalize(&p).expect("canon");
        assert_eq!(d.pid_path(), canon.join("@pasta/c1/pid"));
        for sub in ["@pasta", "@pasta/c1"] {
            let mode = std::fs::metadata(p.join(sub))
                .expect("md")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "{sub}");
        }
        d.remove().expect("remove");
        assert!(!p.join("@pasta/c1").exists());
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn prepare_removes_stale_regular_pid() {
        let (p, f) = root();
        let d = PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare");
        drop(d);
        std::fs::write(p.join("@pasta/c1/pid"), b"4242\n").expect("write");
        let d = PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare again");
        assert!(!p.join("@pasta/c1/pid").exists());
        d.remove().expect("remove");
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn prepare_rejects_symlink_and_directory_pid() {
        let (p, f) = root();
        drop(PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare"));
        symlink("/etc/passwd", p.join("@pasta/c1/pid")).expect("symlink");
        let e = PastaRunDir::prepare(f.as_fd(), "c1").expect_err("symlink pid");
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.message(), MSG_PID_ENTRY);
        assert!(p.join("@pasta/c1/pid").symlink_metadata().is_ok());
        std::fs::remove_file(p.join("@pasta/c1/pid")).expect("rm");
        std::fs::create_dir(p.join("@pasta/c1/pid")).expect("mkdir");
        let e = PastaRunDir::prepare(f.as_fd(), "c1").expect_err("dir pid");
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn prepare_rejects_loose_or_symlinked_dirs() {
        let (p, f) = root();
        drop(PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare"));
        std::fs::set_permissions(p.join("@pasta"), std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        let e = PastaRunDir::prepare(f.as_fd(), "c1").expect_err("loose");
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.message(), MSG_DIR_UNTRUSTED);
        std::fs::set_permissions(p.join("@pasta"), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        std::fs::remove_dir_all(p.join("@pasta/c1")).expect("rm");
        std::fs::create_dir(p.join("elsewhere")).expect("mkdir");
        symlink(p.join("elsewhere"), p.join("@pasta/c1")).expect("symlink");
        let e = PastaRunDir::prepare(f.as_fd(), "c1").expect_err("symlinked id dir");
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn container_id_validation_table() {
        for ok in ["a", "A.b_c-9", &"x".repeat(255)] {
            validate_container_id(ok).expect(ok);
        }
        for bad in ["", ".", "..", "a/b", "a b", "é", &"x".repeat(256), "a\n"] {
            let e = validate_container_id(bad).expect_err(bad);
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            assert_eq!(e.message(), MSG_ID_INVALID);
        }
    }

    #[test]
    fn remove_pasta_run_dir_is_idempotent() {
        let (p, f) = root();
        remove_pasta_run_dir(f.as_fd(), "c1").expect("no @pasta");
        let d = PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare");
        std::fs::write(p.join("@pasta/c1/pid"), b"1\n").expect("write");
        drop(d);
        remove_pasta_run_dir(f.as_fd(), "c1").expect("remove");
        assert!(!p.join("@pasta/c1").exists());
        remove_pasta_run_dir(f.as_fd(), "c1").expect("again");
        let _ = std::fs::remove_dir_all(&p);
    }
}
