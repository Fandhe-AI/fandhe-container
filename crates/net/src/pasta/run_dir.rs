//! pasta の PID ファイルの置き場所 `<state_root>/@pasta/<container-id>/` の作成・古い `pid` の掃除・削除
//! （NET-9・SEC-1・REPAIR-5・#1938。`docs/design/rootless-network.md` 12.8）。
//!
//! - 呼び出し元: supervisor の launch（手順 8。#1940）が `PastaRunDir::prepare` で作り、
//!   [`super::process::spawn_pasta`] に渡す。stop では `PastaRunDir::remove`、CLI の delete は残骸だけを
//!   `remove_pasta_run_dir` で消す（記録の pid でのプロセスの探索・kill はしない。pid の再利用を避ける。12.10）。
//! - 状態ルートは `BorrowedFd` で受ける（パス文字列を受けない）。作成・検査・削除はすべて fd 起点
//!   （`/proc/thread-self/fd/<N>/…` の magic link と `openat(O_NOFOLLOW)`）で行い、パスを再解決しない。
//!   最終要素の symlink は mkdir でも unlink でも辿らない。
//! - `@pasta`・`<id>` は 0700・所有者は実効 UID。既存でも基準外（種別・所有者・`mode & 0o077`）なら
//!   `FailedPrecondition` とし、chmod で直さない（fail-closed）。
//! - 既存の `pid` は通常ファイル・所有者 euid・nlink 1 のときだけ消す。それ以外（symlink・ディレクトリ・FIFO 等）は
//!   `FailedPrecondition`。古い値が残ると準備完了の判定を誤らせるため、spawn の前に必ず消す。
//! - 古い `pid` の削除は、呼び出し元が prepare の前に観測した同一性（[`RunDirExpectation`]。#3355・CORE-2・REPAIR-5）
//!   と開いた fd の `(st_dev, st_ino)` が一致するときだけ行う。別物なら `FailedPrecondition` で何も消さない。
//!   自分が今作ったディレクトリでは古い `pid` を消さない。`prepare` は観測と本処理を続けて行う薄い包みで、
//!   観測と本処理の間を他者が書き換えうる文脈では排他の下で `prepare_expecting` を使う。
//! - 削除も照合した置き場所に束縛する（#3411・CORE-2・REPAIR-5）。`PastaRunDir::remove` は保持 fd の同一性、
//!   `remove_pasta_run_dir_expecting` は呼び出し元が控えた同一性、`remove_pasta_run_dir` は自分の観測に束縛する。
//!   中身（`pid`）は照合済みの fd 起点で消し、最後の `rmdir` の直前に親の fd 起点で名前の先の同一性を取り直す。
//!   別物（作り直された新しい世代・symlink・非ディレクトリ）なら [`RunDirRemoval::NotOurs`] で何も消さない。
//! - 残余（REPAIR-3。supervisor のコンテナ単位のプロセス間ロックが担う範囲）: 観測より前に止まった worker は
//!   新しい世代を「既存」として観測する／同じ既存ディレクトリを 2 者が観測すると同一性が等しく判別できない／
//!   照合から unlink までの間は原理的に窓が残る（unlink-if-inode の syscall が無い）。
//!   削除側でも、`rmdir` の直前の再照合から `rmdir` までの窓は残る（rmdir-by-fd・rmdir-if-inode の syscall が無い）。
//!   `rmdir` は空のディレクトリしか消さないため、影響はその窓の中で作られ、まだ `pid` の無い新しい
//!   ディレクトリに限られる。この窓もコンテナ単位のプロセス間ロックが担う。
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
/// 観測の後で置き場所が作り直された／作られた（別世代）。何も消さずに終える。
pub const MSG_DIR_REPLACED: &str = "pasta run directory changed while it was being prepared";
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

/// 置き場所ディレクトリの同一性 `(st_dev, st_ino)`（#3355・CORE-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunDirIdentity {
    dev: u64,
    ino: u64,
}

impl RunDirIdentity {
    /// デバイス番号。
    pub fn dev(&self) -> u64 {
        self.dev
    }
    /// inode 番号。
    pub fn ino(&self) -> u64 {
        self.ino
    }
}

/// 呼び出し元が prepare の前に観測した `@pasta/<id>` の状態（#3355・CORE-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunDirExpectation {
    /// 観測時点で無かった。
    Absent,
    /// 観測時点でこの同一性のディレクトリがあった。
    Existing(RunDirIdentity),
}

/// 削除の結果（#3411・CORE-2・REPAIR-5）。照合した置き場所だけを消し、別物には触れない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunDirRemoval {
    /// 照合した置き場所を消した。
    Removed,
    /// 消す対象が無かった（照合した置き場所は既に名前から外れていた）。
    Absent,
    /// 名前の先が照合した実体と別物（作り直された・symlink・ディレクトリでない）。何も消していない。
    NotOurs,
}

/// 作成済みの置き場所（`@pasta/<id>/`）。
///
/// spawn の前に `PastaRunDir::prepare` で作る。`pid_path` を pasta の `-P` に渡し、準備完了の判定はこの型が
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
    ///
    /// `observe_run_dir` と `prepare_expecting` を続けて呼ぶ薄い包み。観測と本処理の間を他者が書き換えうる
    /// 文脈では、排他の下で `prepare_expecting` を使う（#3355）。
    pub fn prepare(
        state_root: std::os::fd::BorrowedFd<'_>,
        container_id: &str,
    ) -> Result<Self, NetError> {
        let expected = observe_run_dir(state_root, container_id)?;
        Self::prepare_expecting(state_root, container_id, expected)
    }

    /// 事前の観測 `expected` と照合しながら置き場所を作る。既存のディレクトリが観測と別物なら
    /// `FailedPrecondition`（[`MSG_DIR_REPLACED`]）で何も消さない。作ったばかりなら古い `pid` は消さない。
    pub fn prepare_expecting(
        state_root: std::os::fd::BorrowedFd<'_>,
        container_id: &str,
        expected: RunDirExpectation,
    ) -> Result<Self, NetError> {
        imp::prepare_expecting(state_root, container_id, expected)
    }

    /// 保持している `<id>` ディレクトリ fd の同一性。
    pub fn identity(&self) -> RunDirIdentity {
        self.held.identity
    }

    /// `pid` と `<id>` ディレクトリを消す。保持している fd の同一性に束縛し、名前の先が別物なら
    /// [`RunDirRemoval::NotOurs`] で何も消さない（#3411）。
    pub fn remove(self) -> Result<RunDirRemoval, NetError> {
        imp::remove(&self.held)
    }

    /// 準備完了の判定用: `<id>` ディレクトリの fd 経由で `pid` を読み取り用に開くためのパス。
    pub(super) fn pid_open_path(&self) -> PathBuf {
        imp::pid_open_path(&self.held)
    }
}

/// prepare の前に `@pasta/<id>` の状態を観測する（無ければ `Absent`）。基準外は `FailedPrecondition`。
#[cfg(target_os = "linux")]
pub fn observe_run_dir(
    state_root: std::os::fd::BorrowedFd<'_>,
    container_id: &str,
) -> Result<RunDirExpectation, NetError> {
    imp::observe(state_root, container_id)
}

/// 控えた同一性 `expected` と一致する `@pasta/<id>/` だけを消す（#3411・CORE-2・REPAIR-5）。
/// 別物は [`RunDirRemoval::NotOurs`] で何も消さない（`pid` にも触れない）。supervisor の後始末が使う。
#[cfg(target_os = "linux")]
pub fn remove_pasta_run_dir_expecting(
    state_root: std::os::fd::BorrowedFd<'_>,
    container_id: &str,
    expected: RunDirIdentity,
) -> Result<RunDirRemoval, NetError> {
    imp::remove_expecting(state_root, container_id, expected)
}

/// CLI の delete が残骸を消す入口。`@pasta/<id>/` が無ければ成功。記録の pid でのプロセスの探索・kill はしない。
///
/// 観測（`observe_run_dir`）と `remove_pasta_run_dir_expecting` を続けて呼ぶ薄い包み。観測から削除までの間に
/// 置き場所が替わったら `FailedPrecondition`（[`MSG_DIR_REPLACED`]）で何も消さない（#3411）。
#[cfg(target_os = "linux")]
pub fn remove_pasta_run_dir(
    state_root: std::os::fd::BorrowedFd<'_>,
    container_id: &str,
) -> Result<(), NetError> {
    imp::remove_existing(state_root, container_id, &mut || {})
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
        pub(super) identity: RunDirIdentity,
    }

    fn identity_of(m: &Metadata) -> RunDirIdentity {
        RunDirIdentity {
            dev: m.dev(),
            ino: m.ino(),
        }
    }

    pub(super) fn observe(
        state_root: BorrowedFd<'_>,
        container_id: &str,
    ) -> Result<RunDirExpectation, NetError> {
        validate_container_id(container_id)?;
        let euid = sys::effective_uid();
        let Some(pasta_dir) = open_checked(state_root, PASTA_DIR_NAME, euid)? else {
            return Ok(RunDirExpectation::Absent);
        };
        let Some(id_dir) = open_checked(pasta_dir.as_fd(), container_id, euid)? else {
            return Ok(RunDirExpectation::Absent);
        };
        Ok(RunDirExpectation::Existing(identity_of(&stat(&id_dir)?)))
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

    /// 無ければ作って開く。戻りの `bool` は「今回作ったか」。
    fn ensure_dir(
        parent: BorrowedFd<'_>,
        name: &str,
        euid: u32,
    ) -> Result<(OwnedFd, bool), NetError> {
        let created = match DirBuilder::new()
            .mode(0o700)
            .create(proc_path(parent, name))
        {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(map_io(&e)),
        };
        let fd = open_checked(parent, name, euid)?
            .ok_or_else(|| err(NetErrorCode::Internal, MSG_INTERNAL))?;
        Ok((fd, created))
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

    pub(super) fn prepare_expecting(
        state_root: BorrowedFd<'_>,
        container_id: &str,
        expected: RunDirExpectation,
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
        let (pasta_dir, _) = ensure_dir(state_root, PASTA_DIR_NAME, euid)?;
        let (id_dir, created) = ensure_dir(pasta_dir.as_fd(), container_id, euid)?;
        let identity = identity_of(&stat(&id_dir)?);
        if !created {
            // 既存を再利用する場合だけ、観測と同一のときに限って古い pid を消す。
            if expected != RunDirExpectation::Existing(identity) {
                return Err(err(NetErrorCode::FailedPrecondition, MSG_DIR_REPLACED));
            }
            remove_stale_pid(id_dir.as_fd(), euid)?;
        }
        Ok(PastaRunDir {
            pid_path,
            held: Held {
                pasta_dir,
                id_dir,
                id: container_id.to_owned(),
                identity,
            },
        })
    }

    pub(super) fn pid_open_path(h: &Held) -> PathBuf {
        PathBuf::from(proc_path(h.id_dir.as_fd(), PASTA_PID_FILE_NAME))
    }

    /// 照合済みの `id_dir` の中身を消し、親の fd 起点で名前の先の同一性を取り直してから `rmdir` する。
    /// `before_rmdir` は試験が窓の中で置き場所を作り直すための差し込み口（製品経路は何もしない）。
    fn remove_bound(
        pasta_dir: BorrowedFd<'_>,
        id_dir: BorrowedFd<'_>,
        id: &str,
        identity: RunDirIdentity,
        euid: u32,
        before_rmdir: &mut dyn FnMut(),
    ) -> Result<RunDirRemoval, NetError> {
        remove_stale_pid(id_dir, euid)?;
        before_rmdir();
        match std::fs::symlink_metadata(proc_path(pasta_dir, id)) {
            Ok(m) if m.is_dir() && identity_of(&m) == identity => {}
            Ok(_) => return Ok(RunDirRemoval::NotOurs),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(RunDirRemoval::Absent),
            Err(e) => return Err(map_io(&e)),
        }
        match std::fs::remove_dir(proc_path(pasta_dir, id)) {
            Ok(()) => Ok(RunDirRemoval::Removed),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(RunDirRemoval::Absent),
            // ENOTEMPTY（39）
            Err(e) if e.raw_os_error() == Some(39) => {
                Err(err(NetErrorCode::FailedPrecondition, MSG_NOT_EMPTY))
            }
            Err(e) => Err(map_io(&e)),
        }
    }

    pub(super) fn remove(h: &Held) -> Result<RunDirRemoval, NetError> {
        remove_held_with_hook(h, &mut || {})
    }

    pub(super) fn remove_held_with_hook(
        h: &Held,
        hook: &mut dyn FnMut(),
    ) -> Result<RunDirRemoval, NetError> {
        remove_bound(
            h.pasta_dir.as_fd(),
            h.id_dir.as_fd(),
            &h.id,
            h.identity,
            sys::effective_uid(),
            hook,
        )
    }

    pub(super) fn remove_expecting(
        state_root: BorrowedFd<'_>,
        container_id: &str,
        expected: RunDirIdentity,
    ) -> Result<RunDirRemoval, NetError> {
        remove_expecting_with_hook(state_root, container_id, expected, &mut || {})
    }

    pub(super) fn remove_expecting_with_hook(
        state_root: BorrowedFd<'_>,
        container_id: &str,
        expected: RunDirIdentity,
        hook: &mut dyn FnMut(),
    ) -> Result<RunDirRemoval, NetError> {
        validate_container_id(container_id)?;
        let euid = sys::effective_uid();
        let Some(pasta_dir) = open_checked(state_root, PASTA_DIR_NAME, euid)? else {
            return Ok(RunDirRemoval::Absent);
        };
        let cname =
            CString::new(container_id).map_err(|_| err(NetErrorCode::Internal, MSG_INTERNAL))?;
        let id_dir = match sys::open_dir_nofollow_at(pasta_dir.as_fd(), &cname) {
            Ok(fd) => fd,
            Err(SysError::Os(x)) if x == sys::ENOENT => return Ok(RunDirRemoval::Absent),
            // symlink・ディレクトリでないものは別物として触れない。
            Err(SysError::Os(x)) if x == sys::ELOOP || x == sys::ENOTDIR => {
                return Ok(RunDirRemoval::NotOurs);
            }
            Err(e) => return Err(map_sys(e)),
        };
        let m = stat(&id_dir)?;
        if identity_of(&m) != expected {
            return Ok(RunDirRemoval::NotOurs);
        }
        if !m.is_dir() || m.uid() != euid || m.mode() & 0o077 != 0 {
            return Err(err(NetErrorCode::FailedPrecondition, MSG_DIR_UNTRUSTED));
        }
        remove_bound(
            pasta_dir.as_fd(),
            id_dir.as_fd(),
            container_id,
            expected,
            euid,
            hook,
        )
    }

    pub(super) fn remove_existing(
        state_root: BorrowedFd<'_>,
        container_id: &str,
        hook: &mut dyn FnMut(),
    ) -> Result<(), NetError> {
        match observe(state_root, container_id)? {
            RunDirExpectation::Absent => Ok(()),
            RunDirExpectation::Existing(i) => {
                match remove_expecting_with_hook(state_root, container_id, i, hook)? {
                    RunDirRemoval::Removed | RunDirRemoval::Absent => Ok(()),
                    RunDirRemoval::NotOurs => {
                        Err(err(NetErrorCode::FailedPrecondition, MSG_DIR_REPLACED))
                    }
                }
            }
        }
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
        assert_eq!(d.remove().expect("remove"), RunDirRemoval::Removed);
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

    fn write_pid(p: &Path, body: &[u8]) {
        std::fs::write(p.join("@pasta/c1/pid"), body).expect("write pid");
    }

    /// NET-9・CORE-2: 観測が Absent なのに既存の dir があれば何も消さず拒否する。
    #[test]
    fn net9_core2_prepare_refuses_dir_created_after_absent_observation() {
        let (p, f) = root();
        let exp = observe_run_dir(f.as_fd(), "c1").expect("observe");
        assert_eq!(exp, RunDirExpectation::Absent);
        drop(PastaRunDir::prepare(f.as_fd(), "c1").expect("other generation"));
        write_pid(&p, b"4242\n");
        let e = PastaRunDir::prepare_expecting(f.as_fd(), "c1", exp).expect_err("replaced");
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.message(), MSG_DIR_REPLACED);
        assert_eq!(
            std::fs::read(p.join("@pasta/c1/pid")).expect("pid"),
            b"4242\n"
        );
        let _ = std::fs::remove_dir_all(&p);
    }

    /// NET-9・CORE-2: 旧い prepare が、作り直された dir の新しい pid を消さない。
    #[test]
    fn net9_core2_stale_prepare_keeps_pid_of_recreated_dir() {
        let (p, f) = root();
        drop(PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare"));
        let exp = observe_run_dir(f.as_fd(), "c1").expect("observe");
        // 旧 inode を退避して生かし、inode の再利用で同一に見えないようにする。
        std::fs::rename(p.join("@pasta/c1"), p.join("@pasta/old")).expect("rename");
        std::fs::create_dir(p.join("@pasta/c1")).expect("recreate");
        std::fs::set_permissions(p.join("@pasta/c1"), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        write_pid(&p, b"4242\n");
        let e = PastaRunDir::prepare_expecting(f.as_fd(), "c1", exp).expect_err("stale");
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.message(), MSG_DIR_REPLACED);
        assert_eq!(
            std::fs::read(p.join("@pasta/c1/pid")).expect("pid"),
            b"4242\n"
        );
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn net9_prepare_expecting_matching_identity_removes_stale_pid() {
        let (p, f) = root();
        drop(PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare"));
        write_pid(&p, b"1\n");
        let exp = observe_run_dir(f.as_fd(), "c1").expect("observe");
        let d = PastaRunDir::prepare_expecting(f.as_fd(), "c1", exp).expect("prepare");
        assert!(!p.join("@pasta/c1/pid").exists());
        assert_eq!(RunDirExpectation::Existing(d.identity()), exp);
        drop(d);
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn net9_prepare_on_absent_creates_private_dir_with_identity() {
        use std::os::unix::fs::MetadataExt as _;
        let (p, f) = root();
        let d = PastaRunDir::prepare_expecting(f.as_fd(), "c1", RunDirExpectation::Absent)
            .expect("prepare");
        let m = std::fs::symlink_metadata(p.join("@pasta/c1")).expect("md");
        assert_eq!(m.permissions().mode() & 0o777, 0o700);
        assert_eq!((d.identity().dev(), d.identity().ino()), (m.dev(), m.ino()));
        drop(d);
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn net9_observe_rejects_symlinked_or_loose_dir() {
        let (p, f) = root();
        drop(PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare"));
        std::fs::set_permissions(p.join("@pasta"), std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        let e = observe_run_dir(f.as_fd(), "c1").expect_err("loose");
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        std::fs::set_permissions(p.join("@pasta"), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        std::fs::remove_dir_all(p.join("@pasta/c1")).expect("rm");
        std::fs::create_dir(p.join("elsewhere")).expect("mkdir");
        symlink(p.join("elsewhere"), p.join("@pasta/c1")).expect("symlink");
        let e = observe_run_dir(f.as_fd(), "c1").expect_err("symlink");
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        let _ = std::fs::remove_dir_all(&p);
    }

    /// 窓を再現する: 置き場所を退避し、同名の 0700 の空ディレクトリを作る。
    fn replace_dir(p: &Path, keep: &str) {
        std::fs::rename(p.join("@pasta/c1"), p.join("@pasta").join(keep)).expect("rename");
        std::fs::create_dir(p.join("@pasta/c1")).expect("recreate");
        std::fs::set_permissions(p.join("@pasta/c1"), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
    }

    #[test]
    fn net9_core2_remove_keeps_empty_dir_recreated_after_prepare() {
        let (p, f) = root();
        let d = PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare");
        replace_dir(&p, "old-keep");
        assert_eq!(d.remove().expect("remove"), RunDirRemoval::NotOurs);
        assert!(p.join("@pasta/c1").is_dir());
        assert!(p.join("@pasta/old-keep").is_dir());
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn net9_core2_remove_keeps_pid_of_dir_recreated_after_prepare() {
        let (p, f) = root();
        let d = PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare");
        replace_dir(&p, "old-keep");
        write_pid(&p, b"4242\n");
        assert_eq!(d.remove().expect("remove"), RunDirRemoval::NotOurs);
        assert_eq!(
            std::fs::read(p.join("@pasta/c1/pid")).expect("pid"),
            b"4242\n"
        );
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn net9_core2_remove_rechecks_identity_just_before_rmdir() {
        let (p, f) = root();
        let d = PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare");
        std::fs::write(p.join("@pasta/c1/pid"), b"1\n").expect("old pid");
        let mut hook = || {
            replace_dir(&p, "old-keep");
            write_pid(&p, b"4242\n");
        };
        let r = imp::remove_held_with_hook(&d.held, &mut hook).expect("remove");
        assert_eq!(r, RunDirRemoval::NotOurs);
        assert_eq!(
            std::fs::read(p.join("@pasta/c1/pid")).expect("pid"),
            b"4242\n"
        );
        assert!(!p.join("@pasta/old-keep/pid").exists());
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn net9_core2_remove_expecting_stale_identity_keeps_new_dir_and_pid() {
        let (p, f) = root();
        let d = PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare");
        let old = d.identity();
        drop(d);
        std::fs::write(p.join("@pasta/c1/pid"), b"1\n").expect("old pid");
        replace_dir(&p, "old-keep");
        write_pid(&p, b"4242\n");
        let r = remove_pasta_run_dir_expecting(f.as_fd(), "c1", old).expect("remove");
        assert_eq!(r, RunDirRemoval::NotOurs);
        assert_eq!(
            std::fs::read(p.join("@pasta/c1/pid")).expect("pid"),
            b"4242\n"
        );
        assert_eq!(
            std::fs::read(p.join("@pasta/old-keep/pid")).expect("old pid"),
            b"1\n"
        );
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn net9_core2_remove_expecting_matching_identity_removes() {
        let (p, f) = root();
        let d = PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare");
        let id = d.identity();
        drop(d);
        write_pid(&p, b"1\n");
        let r = remove_pasta_run_dir_expecting(f.as_fd(), "c1", id).expect("remove");
        assert_eq!(r, RunDirRemoval::Removed);
        assert!(!p.join("@pasta/c1").exists());
        let r = remove_pasta_run_dir_expecting(f.as_fd(), "c1", id).expect("again");
        assert_eq!(r, RunDirRemoval::Absent);
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn net9_remove_expecting_symlink_entry_is_not_ours() {
        let (p, f) = root();
        let d = PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare");
        let id = d.identity();
        drop(d);
        std::fs::remove_dir(p.join("@pasta/c1")).expect("rm");
        std::fs::create_dir(p.join("elsewhere")).expect("mkdir");
        symlink(p.join("elsewhere"), p.join("@pasta/c1")).expect("symlink");
        let r = remove_pasta_run_dir_expecting(f.as_fd(), "c1", id).expect("remove");
        assert_eq!(r, RunDirRemoval::NotOurs);
        assert!(
            p.join("@pasta/c1")
                .symlink_metadata()
                .expect("md")
                .is_symlink()
        );
        assert!(p.join("elsewhere").is_dir());
        let _ = std::fs::remove_dir_all(&p);
    }

    #[test]
    fn net9_core2_cli_remove_refuses_dir_replaced_in_window() {
        let (p, f) = root();
        drop(PastaRunDir::prepare(f.as_fd(), "c1").expect("prepare"));
        let mut hook = || {
            replace_dir(&p, "old-keep");
            write_pid(&p, b"4242\n");
        };
        let e = imp::remove_existing(f.as_fd(), "c1", &mut hook).expect_err("replaced");
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.message(), MSG_DIR_REPLACED);
        assert_eq!(
            std::fs::read(p.join("@pasta/c1/pid")).expect("pid"),
            b"4242\n"
        );
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
