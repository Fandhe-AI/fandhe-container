//! `linux.namespaces[].path` による pod の user・ipc namespace への参加（join）の検証と fd 固定
//! （CRI-2・CORE-3・SEC-1・SEC-5・OCI-4。#2674）。
//!
//! # 役割と呼び出し元
//!
//! `start` が config の `linux.namespaces[]` から `NamespaceJoin::paths_of` と `pin` を呼び、`user` と `ipc` の
//! path を **組** で受ける。検証済みの fd を [`LaunchSpec`](super::LaunchSpec) に載せ、本番 launcher が
//! 中間プロセス I の分離で `setns(2)` に使う（`exec::isolate_join`）。pid・mount・uts・network・cgroup・time の
//! path、片方だけの path は従来どおり `Unimplemented` で拒否する（fail-closed）。
//!
//! # なぜ user と ipc の組か
//!
//! カーネルの `ipcns_install` は、参加先を所有する user namespace と呼び出し側の現在の user namespace の両方で
//! `CAP_SYS_ADMIN` を要求する。新しい user namespace を作った後では参加先は兄弟の所有になり、作る前は初期
//! user namespace で権限が無いため、非特権ではどちらの順でも `EPERM` になる。pod の user namespace に先に参加し、
//! その所有する ipc namespace に参加する形だけが成立する（k8s の pod 単位の userns と同じ形）。
//!
//! # 検証（すべて fork・予約の前。メッセージは固定文言でパスを含めない）
//!
//! | 検査 | 不合格 |
//! | ---- | ------ |
//! | パスが絶対・`..` なし・4096 バイト以内 | `InvalidArgument` |
//! | 開けない（不在・終了済み） | `FailedPrecondition`（権限不足は `PermissionDenied`） |
//! | `fstatfs` が nsfs でない / `NS_GET_NSTYPE` が宣言した種別と違う | `InvalidArgument` |
//! | user: 呼び出し側自身の namespace / 親が呼び出し側の namespace でない / 作成者 uid が euid と違う | `PermissionDenied` |
//! | ipc: 所有する user namespace が join する user namespace と違う（ホストの ipc・別所有の ipc） | `PermissionDenied` |
//!
//! パスは 1 回だけ開いて fd に固定し、検査と使用は同じ fd で行う（`/proc/<pid>/ns/*` は pid が再利用されると
//! 別の実体を指すため、開いた後にパスで再解決しない。TOCTOU を閉じる。SEC-1）。fd を持つ間は参加先の
//! namespace が生き続け、`delete`・プロセスの終了で解放される。
//!
//! # 未実装・残余（REPAIR-3）
//!
//! - 供給元（pod の保持役）は未実装で、cri は当面パスを出さない（本番では共有されない）。保持役は #2675 の pod の
//!   netns と共有する設計の後続 issue。
//! - pid の共有（`shareProcessNamespace`）は未対応。コンテナの init が PID 1 であることを制限適用の証跡の前提に
//!   している（`exec::check_establish_preconditions`・`Pid1Target`）ため、既存の pid namespace への参加と両立しない。
//! - `/dev/shm`（POSIX shm）は共有されない（core がコンテナごとの tmpfs を載せる）。SysV IPC と POSIX mqueue が
//!   共有される。

use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::Arc;

use super::config::{NamespaceKind, OciConfig};
use crate::traits::{ErrorCode, TraitError};

#[cfg(target_os = "linux")]
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

/// パス長の上限（`CONFIG_MAX_PATH_BYTES` と同値）。
#[cfg(target_os = "linux")]
const PATH_MAX_BYTES: usize = 4096;

/// 検証済みの pod の user・ipc namespace の fd の組（Linux のみ。他 OS では作れない）。
///
/// `LaunchSpec` に載り、restart の再 launch でも同じ fd を使う（clone は fd を共有する）。同一性は fd の同一性。
#[derive(Debug, Clone)]
pub struct NamespaceJoin {
    #[cfg(target_os = "linux")]
    user: Arc<OwnedFd>,
    #[cfg(target_os = "linux")]
    ipc: Arc<OwnedFd>,
    /// Linux 以外では構築できないことを型で表す。
    #[cfg(not(target_os = "linux"))]
    never: std::convert::Infallible,
}

impl PartialEq for NamespaceJoin {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(target_os = "linux")]
        {
            Arc::ptr_eq(&self.user, &other.user) && Arc::ptr_eq(&self.ipc, &other.ipc)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = other;
            match self.never {}
        }
    }
}

impl Eq for NamespaceJoin {}

fn unsupported_path() -> TraitError {
    TraitError::new(
        ErrorCode::Unimplemented,
        "start does not support yet: linux.namespaces[].path (only a user and ipc pair)",
    )
}

impl NamespaceJoin {
    /// config の `linux.namespaces[]` の path の形だけを検査する（I/O なし。start が必須 namespace の検査より前に呼ぶ）。
    ///
    /// path が無ければ `Ok(None)`。`user` と `ipc` の path が **両方** あり、各種別がちょうど 1 件ずつなら
    /// `Ok(Some((user, ipc)))`。他の種別の path・片方だけの path は `Unimplemented`、同じ種別の重複
    /// （path 付きと無しの混在を含む）は `InvalidArgument`。
    pub(super) fn paths_of(config: &OciConfig) -> Result<Option<(&Path, &Path)>, TraitError> {
        let (mut user, mut ipc): (Option<&Path>, Option<&Path>) = (None, None);
        for ns in config.namespaces() {
            let Some(path) = ns.path() else { continue };
            let slot = match ns.kind() {
                NamespaceKind::User => &mut user,
                NamespaceKind::Ipc => &mut ipc,
                _ => return Err(unsupported_path()),
            };
            if slot.replace(path).is_some() {
                return Err(TraitError::new(
                    ErrorCode::InvalidArgument,
                    "linux.namespaces has a duplicate entry with a path",
                ));
            }
        }
        let (user, ipc) = match (user, ipc) {
            (None, None) => return Ok(None),
            (Some(user), Some(ipc)) => (user, ipc),
            _ => return Err(unsupported_path()),
        };
        // path 付きの種別に path 無しの同種別が混ざると、どちらを採るか曖昧になる（fail-closed）。
        let count = |k: NamespaceKind| config.namespaces().iter().filter(|n| n.kind() == k).count();
        if count(NamespaceKind::User) != 1 || count(NamespaceKind::Ipc) != 1 {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "linux.namespaces has a duplicate user or ipc entry",
            ));
        }
        Ok(Some((user, ipc)))
    }

    /// user・ipc namespace のパスを開き、素性を照合して fd に固定する（モジュール doc の表）。
    #[cfg(target_os = "linux")]
    pub(super) fn pin(user_path: &Path, ipc_path: &Path) -> Result<Self, TraitError> {
        use crate::sys::{self, NsFlag};
        let invalid = |m: &'static str| TraitError::new(ErrorCode::InvalidArgument, m);
        let denied = |m: &'static str| TraitError::new(ErrorCode::PermissionDenied, m);
        let inspect = |_: sys::SysError| {
            TraitError::new(ErrorCode::Internal, "failed to inspect a namespace")
        };
        check_path(user_path)?;
        check_path(ipc_path)?;
        let user = open_ns(user_path)?;
        let ipc = open_ns(ipc_path)?;
        for (fd, flag) in [(&user, NsFlag::User), (&ipc, NsFlag::Ipc)] {
            if sys::fs_type(fd.as_fd()).map_err(inspect)? != sys::NSFS_MAGIC {
                return Err(invalid("a namespace path is not a namespace file"));
            }
            if sys::ns_type(fd.as_fd()).map_err(inspect)? != flag.bits() {
                return Err(invalid("a namespace path has an unexpected namespace type"));
            }
        }
        // 呼び出し側（supervisor）自身の user namespace。参加先がこれの直下の子であることを要する。
        let caller = open_ns(Path::new("/proc/self/ns/user"))?;
        let caller_id = identity(caller.as_fd())?;
        if identity(user.as_fd())? == caller_id {
            return Err(denied(
                "the pod user namespace must differ from the caller's own",
            ));
        }
        let parent = sys::ns_parent(user.as_fd()).map_err(|e| match e {
            sys::SysError::Os(errno) if errno == sys::EPERM => {
                denied("the pod user namespace is not a child of the caller's")
            }
            other => inspect(other),
        })?;
        if identity(parent.as_fd())? != caller_id {
            return Err(denied(
                "the pod user namespace is not a direct child of the caller's",
            ));
        }
        if sys::ns_owner_uid(user.as_fd()).map_err(inspect)? != sys::effective_uid() {
            return Err(denied(
                "the pod user namespace is not owned by the launching user",
            ));
        }
        // ipc は join する user namespace が所有するものに限る（ホストの ipc・別所有の ipc を拒否する）。
        let ipc_owner = sys::ns_owner_userns(ipc.as_fd()).map_err(|e| match e {
            sys::SysError::Os(errno) if errno == sys::EPERM => {
                denied("the pod ipc namespace is not owned by the pod user namespace")
            }
            other => inspect(other),
        })?;
        if identity(ipc_owner.as_fd())? != identity(user.as_fd())? {
            return Err(denied(
                "the pod ipc namespace is not owned by the pod user namespace",
            ));
        }
        Ok(Self {
            user: Arc::new(user),
            ipc: Arc::new(ipc),
        })
    }

    /// 非 Linux は namespace を固定できない（`Unimplemented`。fail-closed。CLI-1）。
    #[cfg(not(target_os = "linux"))]
    pub(super) fn pin(_user_path: &Path, _ipc_path: &Path) -> Result<Self, TraitError> {
        Err(unsupported_path())
    }

    /// 試験専用: 検証を通さずに任意の fd から作る（launcher の分離設定の分岐を、実際の namespace なしで確かめる）。
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn for_test(user: OwnedFd, ipc: OwnedFd) -> Self {
        Self {
            user: Arc::new(user),
            ipc: Arc::new(ipc),
        }
    }

    /// 固定した user namespace の fd（`setns` 専用。中間プロセス I が使う）。
    #[cfg(target_os = "linux")]
    pub(crate) fn user_fd(&self) -> BorrowedFd<'_> {
        self.user.as_fd()
    }

    /// 固定した ipc namespace の fd（`setns` 専用）。
    #[cfg(target_os = "linux")]
    pub(crate) fn ipc_fd(&self) -> BorrowedFd<'_> {
        self.ipc.as_fd()
    }
}

/// 絶対パスで `..` を含まず上限以内であること（NUL は config の段で拒否済み）。
#[cfg(target_os = "linux")]
fn check_path(path: &Path) -> Result<(), TraitError> {
    let bad = path.as_os_str().len() > PATH_MAX_BYTES
        || !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir));
    if bad {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "a namespace path must be absolute without .. components and within the length limit",
        ));
    }
    Ok(())
}

/// パスを開いて fd に固定する（開けなければ `FailedPrecondition`。権限不足は `PermissionDenied`）。
#[cfg(target_os = "linux")]
fn open_ns(path: &Path) -> Result<OwnedFd, TraitError> {
    use std::os::unix::ffi::OsStrExt as _;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        TraitError::new(ErrorCode::InvalidArgument, "a namespace path contains NUL")
    })?;
    crate::sys::open_ns_file(&c).map_err(|e| match e {
        crate::sys::SysError::Os(errno)
            if errno == crate::sys::EACCES || errno == crate::sys::EPERM =>
        {
            TraitError::new(
                ErrorCode::PermissionDenied,
                "a namespace path cannot be opened: permission denied",
            )
        }
        _ => TraitError::new(
            ErrorCode::FailedPrecondition,
            "a namespace path cannot be opened",
        ),
    })
}

/// namespace の同一性（nsfs の `st_dev`・`st_ino`）。
#[cfg(target_os = "linux")]
fn identity(fd: BorrowedFd<'_>) -> Result<(u64, u64), TraitError> {
    use std::os::unix::fs::MetadataExt as _;
    let file = std::fs::File::from(
        fd.try_clone_to_owned()
            .map_err(|_| TraitError::new(ErrorCode::Internal, "failed to inspect a namespace"))?,
    );
    let meta = file
        .metadata()
        .map_err(|_| TraitError::new(ErrorCode::Internal, "failed to inspect a namespace"))?;
    Ok((meta.dev(), meta.ino()))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn pin(user: &str, ipc: &str) -> Result<NamespaceJoin, TraitError> {
        NamespaceJoin::pin(Path::new(user), Path::new(ipc))
    }

    fn code(r: Result<NamespaceJoin, TraitError>) -> ErrorCode {
        r.expect_err("must be rejected").code()
    }

    /// CRI-2・CORE-3・SEC-1: 呼び出し側自身の namespace への join は fork の前に `PermissionDenied`。
    #[test]
    fn own_namespaces_are_rejected_as_permission_denied() {
        assert_eq!(
            code(pin("/proc/self/ns/user", "/proc/self/ns/ipc")),
            ErrorCode::PermissionDenied
        );
    }

    /// ipc に別種別（uts）の namespace を指すと `InvalidArgument`。
    #[test]
    fn wrong_namespace_type_is_invalid_argument() {
        assert_eq!(
            code(pin("/proc/self/ns/user", "/proc/self/ns/uts")),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            code(pin("/proc/self/ns/ipc", "/proc/self/ns/ipc")),
            ErrorCode::InvalidArgument
        );
    }

    /// nsfs でない通常ファイルは `InvalidArgument`。
    #[test]
    fn regular_file_is_invalid_argument() {
        let dir = std::env::temp_dir().join(format!("ns-join-reg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("f");
        std::fs::write(&file, b"x").expect("write");
        let f = file.to_str().expect("utf8");
        assert_eq!(
            code(pin(f, "/proc/self/ns/ipc")),
            ErrorCode::InvalidArgument
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// 不在のパスは `FailedPrecondition`（終了済みの pod の保持役など）。
    #[test]
    fn missing_path_is_failed_precondition() {
        assert_eq!(
            code(pin("/proc/2147483647/ns/user", "/proc/2147483647/ns/ipc")),
            ErrorCode::FailedPrecondition
        );
    }

    /// 相対パス・`..`・長さ上限超過は `InvalidArgument`（開く前）。
    #[test]
    fn malformed_paths_are_invalid_argument() {
        for bad in [
            "proc/self/ns/user".to_owned(),
            "/proc/self/../self/ns/user".to_owned(),
            format!("/{}", "a".repeat(PATH_MAX_BYTES)),
        ] {
            assert_eq!(
                code(pin(&bad, "/proc/self/ns/ipc")),
                ErrorCode::InvalidArgument
            );
        }
        let at_limit = format!("/{}", "a".repeat(PATH_MAX_BYTES - 1));
        assert_eq!(
            code(pin(&at_limit, "/proc/self/ns/ipc")),
            ErrorCode::FailedPrecondition
        );
    }
}
