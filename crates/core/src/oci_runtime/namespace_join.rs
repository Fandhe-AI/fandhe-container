//! `linux.namespaces[].path` による pod の user・ipc（と任意で network）namespace への参加（join）の検証と fd 固定
//! （CRI-2・CORE-3・SEC-1・SEC-5・NET-3・OCI-4。#2674・#2872）。
//!
//! # 役割と呼び出し元
//!
//! `start` が config の `linux.namespaces[]` から `NamespaceJoin::paths_of` と `pin` を呼び、`user` と `ipc` の
//! path を **組** で受ける。network の path は user と ipc の組に **足す形でだけ** 受ける（#2872。設計 #2838 の H7）。
//! 検証済みの fd を [`LaunchSpec`](super::LaunchSpec) に載せ、本番 launcher が中間プロセス I の分離で `setns(2)`
//! に使う（`exec::isolate_join`。順は user → ipc → net）。pid・mount・uts・cgroup・time の path、片方だけの path、
//! network 単独（user・ipc の組なし）の path は従来どおり `Unimplemented` で拒否する（fail-closed）。
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
//! | net: 所有する user namespace が join する user namespace と違う（別 pod の userns 所有） | `PermissionDenied` |
//! | net: 所有者が呼び出し側自身の user namespace、またはそれより外側（ホストの netns・init userns 所有） | `Unimplemented`（#2241 の判断まで受けない） |
//!
//! 検査は user → ipc → net の順で、user の検査が先に通ること。受理と拒否は閉じた語彙
//! （[`PodNamespaceJoinOutcome`](crate::audit_log::PodNamespaceJoinOutcome)）で監査に残す（SEC-4）。
//!
//! パスは 1 回だけ開いて fd に固定し、検査と使用は同じ fd で行う（`/proc/<pid>/ns/*` は pid が再利用されると
//! 別の実体を指すため、開いた後にパスで再解決しない。TOCTOU を閉じる。SEC-1）。fd を持つ間は参加先の
//! namespace が生き続け、`delete`・プロセスの終了で解放される。
//!
//! # パスの形式を `/proc/<pid>/ns/*` に限らない理由（#2776。CORE-3・SEC-5）
//!
//! core はここで形式検査（`/proc/<pid>/ns/{user,ipc,net}` の完全一致）を足さない。
//!
//! 1. core は汎用の OCI runtime の入口である。OCI の `linux.namespaces[].path` は bind mount した nsfs ファイル
//!    （`/run/user/<uid>/…`・`/run/netns/<name>` 等）も許し、netns の join（user と ipc の組に net を足す形。#2872 で実装済み）も同じ形を使う。
//! 2. 認可の正はパスの形ではなく、1 回だけ開いて固定した fd の素性（nsfs・種別・自身でないこと・親子・作成者 uid・
//!    ipc の所有者）である。形を限っても pid の再利用や「どの pod の pid か」は core には判断できず、core は
//!    sandbox を知らない。それは cri の責務で、cri は保持役の pid からだけパスを作る（`PodNamespacePaths` の契約）。
//! 3. `/proc/<pid>/ns/*` 自体が magic link で、形を限っても最終要素の magic link を辿ること（`open_ns_file`）は
//!    無くならない。辿った先は fd で検証する。
//! 4. `cri2_start_rejects_pod_join_to_own_namespaces` 等の試験と production_launcher のシナリオ W は、
//!    `/proc/self/ns/*` を `pin` の素性検査まで通して `PermissionDenied` と監査記録（SEC-4）を照合している。
//!    形式検査を足すと素性検査の前に `InvalidArgument` で止まり、この監査の網羅が失われる。
//!
//! # 供給元（cri・supervisor の保持役。CRI-2・CORE-3・NET-3）
//!
//! パスの供給元は実装済みである。namespace の確立 API（`pod_holder::establish_pod_namespaces`。#2870）、
//! 保持役のプロセス（supervisor の bin の `pod-holder` モード。#2874）、plugin-cri の本番の保持役 provider と
//! その注入（Linux・非 root の本番構成。#2877）が揃っている。cri は自 sandbox の記録の保持役の pid からだけ
//! `/proc/<pid>/ns/{user,ipc,net}` を作って渡す（`PodNamespacePaths`。#2776・#2876・#2878）ため、pod 内の
//! コンテナは user・ipc・net を共有する。provider を注入しない構成（rootful 等）ではパスを出さず、コンテナごとの
//! 新しい namespace になる。
//!
//! # 未実装・残余（REPAIR-3）
//!
//! - init（呼び出し側）の user namespace 所有の netns（rootful・ホストの netns）への join は、この pod join では受けない
//!   （`Unimplemented`）。rootful のユーザー定義ネットワークの init 所有 netns は、起動オプションから入る別の入口
//!   （`pinned_net`。D12・#3069。user namespace の作成前に参加する）で受ける。`RootfulHostRoot` は #2241 で恒久拒否のまま。
//! - pid の共有（`shareProcessNamespace`）は未対応。コンテナの init が PID 1 であることを制限適用の証跡の前提に
//!   している（`exec::check_establish_preconditions`・`Pid1Target`）ため、既存の pid namespace への参加と両立しない。
//! - `/dev/shm`（POSIX shm）は共有されない（core がコンテナごとの tmpfs を載せる）。SysV IPC と POSIX mqueue が
//!   共有される。
//! - 周辺の未完: 保持役の素性の永続化と再起動後の再採用は #2940、rootless の本番 PodNetworkProvider（pasta）は #2879。

mod pinned_net;

use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::Arc;

use super::config::{NamespaceKind, OciConfig};
use crate::audit_log::PodNamespaceJoinOutcome;
use crate::traits::{ErrorCode, TraitError};

pub use pinned_net::{NetnsJoinTarget, PinnedNetnsJoin};

#[cfg(target_os = "linux")]
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

/// パス長の上限（`CONFIG_MAX_PATH_BYTES` と同値）。
#[cfg(target_os = "linux")]
const PATH_MAX_BYTES: usize = 4096;

/// config から取り出した join の path の組（I/O なし。`paths_of` の結果）。
///
/// `user` と `ipc` は常にある（組）。`net` は pod の netns も共有するときだけ（#2872）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct JoinPaths<'a> {
    pub(super) user: &'a Path,
    pub(super) ipc: &'a Path,
    pub(super) net: Option<&'a Path>,
}

/// `pin` の拒否。監査に残す結果は、素性検査による拒否のときだけ `Some`（開けない path・I/O の失敗・非 Linux は `None`）。
#[derive(Debug)]
pub(super) struct PinRejection {
    pub(super) error: TraitError,
    pub(super) outcome: Option<PodNamespaceJoinOutcome>,
}

impl PinRejection {
    #[cfg(target_os = "linux")]
    fn new(code: ErrorCode, message: &'static str, outcome: PodNamespaceJoinOutcome) -> Self {
        Self {
            error: TraitError::new(code, message),
            outcome: Some(outcome),
        }
    }

    #[cfg(target_os = "linux")]
    fn silent(error: TraitError) -> Self {
        Self {
            error,
            outcome: None,
        }
    }
}

impl From<TraitError> for PinRejection {
    fn from(error: TraitError) -> Self {
        Self {
            error,
            outcome: None,
        }
    }
}

/// 検証済みの pod の user・ipc（と任意で net）namespace の fd の組（Linux のみ。他 OS では作れない）。
///
/// `LaunchSpec` に載り、restart の再 launch でも同じ fd を使う（clone は fd を共有する）。同一性は fd の同一性。
#[derive(Debug, Clone)]
pub struct NamespaceJoin {
    #[cfg(target_os = "linux")]
    user: Arc<OwnedFd>,
    #[cfg(target_os = "linux")]
    ipc: Arc<OwnedFd>,
    /// pod の netns（#2872）。`Some` のとき `net_identity` も `Some`。
    #[cfg(target_os = "linux")]
    net: Option<Arc<OwnedFd>>,
    /// pin 時に取った net の (dev, ino)。exec 直前の同期点が PID 1 の netns と照合する（D8。SEC-1）。
    #[cfg(target_os = "linux")]
    net_identity: Option<(u64, u64)>,
    /// Linux 以外では構築できないことを型で表す。
    #[cfg(not(target_os = "linux"))]
    never: std::convert::Infallible,
}

impl PartialEq for NamespaceJoin {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(target_os = "linux")]
        {
            let same_net = match (&self.net, &other.net) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            };
            Arc::ptr_eq(&self.user, &other.user) && Arc::ptr_eq(&self.ipc, &other.ipc) && same_net
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
        "start does not support yet: linux.namespaces[].path (only a user and ipc pair, optionally with network)",
    )
}

impl NamespaceJoin {
    /// config の `linux.namespaces[]` の path の形だけを検査する（I/O なし。start が network の突き合わせと必須 namespace の
    /// 検査より前に呼ぶ）。
    ///
    /// path が無ければ `Ok(None)`。`user` と `ipc` の path が **両方** あり、各種別がちょうど 1 件ずつなら
    /// `Ok(Some(..))`（`network` の path は任意で、あるときは network のエントリもちょうど 1 件）。他の種別の path・
    /// user と ipc の片方だけの path・network 単独の path は `Unimplemented`、同じ種別の重複（path 付きと無しの混在を含む）は
    /// `InvalidArgument`。
    pub(super) fn paths_of(config: &OciConfig) -> Result<Option<JoinPaths<'_>>, TraitError> {
        let (mut user, mut ipc, mut net): (Option<&Path>, Option<&Path>, Option<&Path>) =
            (None, None, None);
        for ns in config.namespaces() {
            let Some(path) = ns.path() else { continue };
            let slot = match ns.kind() {
                NamespaceKind::User => &mut user,
                NamespaceKind::Ipc => &mut ipc,
                NamespaceKind::Network => &mut net,
                _ => return Err(unsupported_path()),
            };
            if slot.replace(path).is_some() {
                return Err(TraitError::new(
                    ErrorCode::InvalidArgument,
                    "linux.namespaces has a duplicate entry with a path",
                ));
            }
        }
        let (user, ipc) = match (user, ipc, net) {
            (None, None, None) => return Ok(None),
            (Some(user), Some(ipc), _) => (user, ipc),
            _ => return Err(unsupported_path()),
        };
        // path 付きの種別に path 無しの同種別が混ざると、どちらを採るか曖昧になる（fail-closed）。
        let count = |k: NamespaceKind| config.namespaces().iter().filter(|n| n.kind() == k).count();
        if count(NamespaceKind::User) != 1
            || count(NamespaceKind::Ipc) != 1
            || (net.is_some() && count(NamespaceKind::Network) != 1)
        {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "linux.namespaces has a duplicate user, ipc or network entry",
            ));
        }
        Ok(Some(JoinPaths { user, ipc, net }))
    }

    /// user・ipc（と任意で net）namespace のパスを開き、素性を照合して fd に固定する（モジュール doc の表）。
    ///
    /// 拒否は [`PinRejection`] で、素性検査による拒否には監査に残す結果が付く。
    #[cfg(target_os = "linux")]
    pub(super) fn pin(
        paths: JoinPaths<'_>,
    ) -> Result<(Self, PodNamespaceJoinOutcome), PinRejection> {
        use crate::sys::{self, NsFlag};
        use PodNamespaceJoinOutcome as O;
        let inspect = |_: sys::SysError| {
            PinRejection::silent(TraitError::new(
                ErrorCode::Internal,
                "failed to inspect a namespace",
            ))
        };
        let JoinPaths {
            user: user_path,
            ipc: ipc_path,
            net: net_path,
        } = paths;
        let malformed = |r: Result<(), TraitError>| {
            r.map_err(|e| PinRejection {
                error: e,
                outcome: Some(O::PathMalformed),
            })
        };
        malformed(check_path(user_path))?;
        malformed(check_path(ipc_path))?;
        if let Some(net_path) = net_path {
            malformed(check_path(net_path))?;
        }
        let user = open_ns(user_path)?;
        let ipc = open_ns(ipc_path)?;
        let net = net_path.map(open_ns).transpose()?;
        let mut typed: Vec<(&OwnedFd, NsFlag)> = vec![(&user, NsFlag::User), (&ipc, NsFlag::Ipc)];
        if let Some(net) = &net {
            typed.push((net, NsFlag::Net));
        }
        for (fd, flag) in typed {
            if sys::fs_type(fd.as_fd()).map_err(inspect)? != sys::NSFS_MAGIC {
                return Err(PinRejection::new(
                    ErrorCode::InvalidArgument,
                    "a namespace path is not a namespace file",
                    O::NotNamespaceFile,
                ));
            }
            if sys::ns_type(fd.as_fd()).map_err(inspect)? != flag.bits() {
                return Err(PinRejection::new(
                    ErrorCode::InvalidArgument,
                    "a namespace path has an unexpected namespace type",
                    O::NotNamespaceFile,
                ));
            }
        }
        // 呼び出し側（supervisor）自身の user namespace。参加先がこれの直下の子であることを要する。
        let caller = open_ns(Path::new("/proc/self/ns/user"))?;
        let caller_id = identity(caller.as_fd())?;
        let user_id = identity(user.as_fd())?;
        if user_id == caller_id {
            return Err(PinRejection::new(
                ErrorCode::PermissionDenied,
                "the pod user namespace must differ from the caller's own",
                O::UserIsOwn,
            ));
        }
        let parent = sys::ns_parent(user.as_fd()).map_err(|e| match e {
            sys::SysError::Os(errno) if errno == sys::EPERM => PinRejection::new(
                ErrorCode::PermissionDenied,
                "the pod user namespace is not a child of the caller's",
                O::UserNotChild,
            ),
            other => inspect(other),
        })?;
        if identity(parent.as_fd())? != caller_id {
            return Err(PinRejection::new(
                ErrorCode::PermissionDenied,
                "the pod user namespace is not a direct child of the caller's",
                O::UserNotChild,
            ));
        }
        if sys::ns_owner_uid(user.as_fd()).map_err(inspect)? != sys::effective_uid() {
            return Err(PinRejection::new(
                ErrorCode::PermissionDenied,
                "the pod user namespace is not owned by the launching user",
                O::UserOwnerMismatch,
            ));
        }
        // ipc は join する user namespace が所有するものに限る（ホストの ipc・別所有の ipc を拒否する）。
        let ipc_owner = sys::ns_owner_userns(ipc.as_fd()).map_err(|e| match e {
            sys::SysError::Os(errno) if errno == sys::EPERM => PinRejection::new(
                ErrorCode::PermissionDenied,
                "the pod ipc namespace is not owned by the pod user namespace",
                O::IpcOwnerMismatch,
            ),
            other => inspect(other),
        })?;
        if identity(ipc_owner.as_fd())? != user_id {
            return Err(PinRejection::new(
                ErrorCode::PermissionDenied,
                "the pod ipc namespace is not owned by the pod user namespace",
                O::IpcOwnerMismatch,
            ));
        }
        // net は pod の user namespace が所有するものに限る(SEC-5)。呼び出し側自身(または外側)の user namespace 所有の
        // netns(rootless 本番ではホストの netns)は、rootful の扱い(#2241)が決まるまで受けない(`Unimplemented`)。
        // それ以外(別 pod の userns の所有など)は取り違えで `PermissionDenied`。
        let net_identity = match &net {
            None => None,
            Some(net) => {
                let not_pod_owned = || {
                    PinRejection::new(
                        ErrorCode::Unimplemented,
                        "a network namespace not owned by a pod user namespace is not supported yet",
                        O::NetNotPodOwned,
                    )
                };
                let owner = sys::ns_owner_userns(net.as_fd()).map_err(|e| match e {
                    sys::SysError::Os(errno) if errno == sys::EPERM => not_pod_owned(),
                    other => inspect(other),
                })?;
                let owner_id = identity(owner.as_fd())?;
                if owner_id == caller_id {
                    return Err(not_pod_owned());
                }
                if owner_id != user_id {
                    return Err(PinRejection::new(
                        ErrorCode::PermissionDenied,
                        "the pod network namespace is not owned by the pod user namespace",
                        O::NetOwnerMismatch,
                    ));
                }
                Some(identity(net.as_fd())?)
            }
        };
        let outcome = if net.is_some() {
            O::AcceptedUserIpcNet
        } else {
            O::AcceptedUserIpc
        };
        Ok((
            Self {
                user: Arc::new(user),
                ipc: Arc::new(ipc),
                net: net.map(Arc::new),
                net_identity,
            },
            outcome,
        ))
    }

    /// 非 Linux は namespace を固定できない（`Unimplemented`。fail-closed。CLI-1）。
    #[cfg(not(target_os = "linux"))]
    pub(super) fn pin(
        _paths: JoinPaths<'_>,
    ) -> Result<(Self, PodNamespaceJoinOutcome), PinRejection> {
        Err(PinRejection::from(unsupported_path()))
    }

    /// 試験専用: 検証を通さずに任意の fd から作る（launcher の分離設定の分岐を、実際の namespace なしで確かめる）。
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn for_test(user: OwnedFd, ipc: OwnedFd) -> Self {
        Self {
            user: Arc::new(user),
            ipc: Arc::new(ipc),
            net: None,
            net_identity: None,
        }
    }

    /// 試験専用: net の fd つき(素性は fd から取る)。
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn for_test_with_net(user: OwnedFd, ipc: OwnedFd, net: OwnedFd) -> Self {
        let net_identity = identity(net.as_fd()).ok();
        Self {
            user: Arc::new(user),
            ipc: Arc::new(ipc),
            net: Some(Arc::new(net)),
            net_identity,
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

    /// 固定した net namespace の fd（pod の netns も共有するときだけ。`setns` 専用。#2872）。
    #[cfg(target_os = "linux")]
    pub(crate) fn net_fd(&self) -> Option<BorrowedFd<'_>> {
        self.net.as_ref().map(|n| n.as_fd())
    }

    /// pin 時に取った net namespace の素性。exec 直前の同期点が PID 1 の netns と照合する（D8。#2872）。
    #[cfg(target_os = "linux")]
    pub(crate) fn net_identity(&self) -> Option<crate::exec::NetnsIdentity> {
        self.net_identity
            .map(|(dev, ino)| crate::exec::NetnsIdentity::from_parts(dev, ino))
    }

    /// net も join するか。
    #[cfg(target_os = "linux")]
    pub(crate) fn has_net(&self) -> bool {
        self.net.is_some()
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
fn open_ns(path: &Path) -> Result<OwnedFd, PinRejection> {
    use std::os::unix::ffi::OsStrExt as _;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        PinRejection::new(
            ErrorCode::InvalidArgument,
            "a namespace path contains NUL",
            PodNamespaceJoinOutcome::PathMalformed,
        )
    })?;
    crate::sys::open_ns_file(&c).map_err(|e| match e {
        crate::sys::SysError::Os(errno)
            if errno == crate::sys::EACCES || errno == crate::sys::EPERM =>
        {
            PinRejection::new(
                ErrorCode::PermissionDenied,
                "a namespace path cannot be opened: permission denied",
                PodNamespaceJoinOutcome::OpenDenied,
            )
        }
        _ => PinRejection::silent(TraitError::new(
            ErrorCode::FailedPrecondition,
            "a namespace path cannot be opened",
        )),
    })
}

/// namespace の同一性（nsfs の `st_dev`・`st_ino`）。
#[cfg(target_os = "linux")]
fn identity(fd: BorrowedFd<'_>) -> Result<(u64, u64), PinRejection> {
    use std::os::unix::fs::MetadataExt as _;
    let fail = || {
        PinRejection::silent(TraitError::new(
            ErrorCode::Internal,
            "failed to inspect a namespace",
        ))
    };
    let file = std::fs::File::from(fd.try_clone_to_owned().map_err(|_| fail())?);
    let meta = file.metadata().map_err(|_| fail())?;
    Ok((meta.dev(), meta.ino()))
}

/// `identity` の `TraitError` 版。`pod_holder` が使う（監査の結果を持たない呼び出し側向け）。
#[cfg(target_os = "linux")]
pub(super) fn identity_plain(fd: BorrowedFd<'_>) -> Result<(u64, u64), TraitError> {
    identity(fd).map_err(|r| r.error)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn pin(user: &str, ipc: &str) -> Result<NamespaceJoin, TraitError> {
        pin_net(user, ipc, None)
    }

    fn pin_net(user: &str, ipc: &str, net: Option<&str>) -> Result<NamespaceJoin, TraitError> {
        NamespaceJoin::pin(JoinPaths {
            user: Path::new(user),
            ipc: Path::new(ipc),
            net: net.map(Path::new),
        })
        .map(|(join, _)| join)
        .map_err(|r| r.error)
    }

    fn outcome_of(user: &str, ipc: &str, net: Option<&str>) -> Option<PodNamespaceJoinOutcome> {
        NamespaceJoin::pin(JoinPaths {
            user: Path::new(user),
            ipc: Path::new(ipc),
            net: net.map(Path::new),
        })
        .err()
        .and_then(|r| r.outcome)
    }

    fn code(r: Result<NamespaceJoin, TraitError>) -> ErrorCode {
        r.expect_err("must be rejected").code()
    }

    fn config_with(namespaces: &str) -> OciConfig {
        let json = format!(
            r#"{{"ociVersion":"1.0.2","root":{{"path":"rootfs"}},
            "process":{{"user":{{"uid":0,"gid":0}},"args":["/bin/true"],"cwd":"/"}},
            "linux":{{"namespaces":[{namespaces}]}}}}"#
        );
        super::super::config::parse_config_bytes(json.as_bytes()).expect("config")
    }

    const U: &str = r#"{"type":"user","path":"/proc/1/ns/user"}"#;
    const I: &str = r#"{"type":"ipc","path":"/proc/1/ns/ipc"}"#;
    const N: &str = r#"{"type":"network","path":"/proc/1/ns/net"}"#;

    fn paths_of(parts: &[&str]) -> Result<Option<JoinPaths<'static>>, TraitError> {
        // 返り値が config を借りるため、試験では config を leak して 'static にする(試験専用)。
        let config: &'static OciConfig = Box::leak(Box::new(config_with(&parts.join(","))));
        NamespaceJoin::paths_of(config)
    }

    /// CORE-3・SEC-5・NET-3・#2872: user と ipc の組は net の有無を問わず受け、net 単独・片方だけ・他種別は
    /// `Unimplemented`、重複は `InvalidArgument`。
    #[test]
    fn net3_2872_paths_of_accepts_only_the_user_ipc_pair_with_optional_net() {
        assert_eq!(paths_of(&[r#"{"type":"pid"}"#]).unwrap(), None);
        let pair = paths_of(&[U, I]).unwrap().expect("pair");
        assert_eq!(pair.user, Path::new("/proc/1/ns/user"));
        assert_eq!(pair.ipc, Path::new("/proc/1/ns/ipc"));
        assert_eq!(pair.net, None);
        let triple = paths_of(&[U, I, N]).unwrap().expect("triple");
        assert_eq!(triple.net, Some(Path::new("/proc/1/ns/net")));
        for parts in [&[N][..], &[U][..], &[I, N][..], &[U, N][..], &[I][..]] {
            let err = paths_of(parts).unwrap_err();
            assert_eq!(err.code(), ErrorCode::Unimplemented);
            assert_eq!(
                err.message(),
                "start does not support yet: linux.namespaces[].path (only a user and ipc pair, optionally with network)"
            );
        }
        let uts = r#"{"type":"uts","path":"/proc/1/ns/uts"}"#;
        assert_eq!(
            paths_of(&[U, I, uts]).unwrap_err().code(),
            ErrorCode::Unimplemented
        );
        for parts in [
            &[U, I, N, N][..],
            &[U, I, N, r#"{"type":"network"}"#][..],
            &[U, I, r#"{"type":"user"}"#][..],
        ] {
            assert_eq!(
                paths_of(parts).unwrap_err().code(),
                ErrorCode::InvalidArgument
            );
        }
    }

    /// NET-3・SEC-1・SEC-4(#2872): net の path の形の不正・種別違い・不在は、user・ipc と同じコードで拒否し、素性検査の
    /// 拒否には監査の結果(閉じた語彙)が付く。開けない path は結果なし。
    #[test]
    fn net3_2872_bad_net_path_is_rejected_with_the_audit_outcome() {
        let own_u = "/proc/self/ns/user";
        let own_i = "/proc/self/ns/ipc";
        for bad in [
            "proc/self/ns/net".to_owned(),
            "/proc/self/../self/ns/net".to_owned(),
            format!("/{}", "a".repeat(PATH_MAX_BYTES)),
        ] {
            assert_eq!(
                code(pin_net(own_u, own_i, Some(&bad))),
                ErrorCode::InvalidArgument
            );
            assert_eq!(
                outcome_of(own_u, own_i, Some(&bad)),
                Some(PodNamespaceJoinOutcome::PathMalformed)
            );
        }
        assert_eq!(
            code(pin_net(own_u, own_i, Some("/proc/self/ns/uts"))),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            outcome_of(own_u, own_i, Some("/proc/self/ns/uts")),
            Some(PodNamespaceJoinOutcome::NotNamespaceFile)
        );
        assert_eq!(
            code(pin_net(own_u, own_i, Some("/proc/2147483647/ns/net"))),
            ErrorCode::FailedPrecondition
        );
        assert_eq!(
            outcome_of(own_u, own_i, Some("/proc/2147483647/ns/net")),
            None
        );
        // net が正しい種別でも user の自身検査が先に効く(net の検査に届かない)。
        assert_eq!(
            code(pin_net(own_u, own_i, Some("/proc/self/ns/net"))),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            outcome_of(own_u, own_i, Some("/proc/self/ns/net")),
            Some(PodNamespaceJoinOutcome::UserIsOwn)
        );
    }

    /// 実機: 保持役の代わりの `unshare --user --map-root-user --ipc --net sleep` を起動して、その `/proc/<pid>/ns/*` を
    /// join 先に使う(非特権 user namespace。`kernel.apparmor_restrict_unprivileged_userns` の緩和が要るホストがある)。
    /// 期限つきで回収する(REPAIR-5)。前提が欠ければ skip せず固定行で失敗する。
    struct FakeHolder {
        child: std::process::Child,
    }

    impl FakeHolder {
        fn spawn() -> Self {
            let mut child = std::process::Command::new("unshare")
                .args(["--user", "--map-root-user", "--ipc", "--net", "sleep", "30"])
                .spawn()
                .expect("PRECONDITION FAILED: unshare(1) is required");
            // unshare が namespace に入るまで待つ(`/proc/<pid>/ns/net` が自分と異なる素性になる)。
            let me = std::fs::read_link("/proc/self/ns/net").expect("own netns");
            let path = format!("/proc/{}/ns/net", child.id());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                if std::fs::read_link(&path).is_ok_and(|l| l != me) {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("PRECONDITION FAILED: the holder did not enter its namespaces");
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Self { child }
        }

        fn ns(&self, kind: &str) -> String {
            format!("/proc/{}/ns/{kind}", self.child.id())
        }
    }

    impl Drop for FakeHolder {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// 実機(`--ignored`)。CORE-3・SEC-5・NET-3・SEC-4・#2872: pod の userns 所有の net は受理し(素性が一致し、結果は
    /// `pod_join_accepted_user_ipc_net`)、呼び出し側所有の net は `Unimplemented`、別の holder(別 userns)所有の net は
    /// `PermissionDenied`、net に uts は `InvalidArgument`。
    #[test]
    #[ignore = "needs unprivileged user namespaces and unshare(1); run with --ignored (#2872)"]
    fn net3_2872_real_holder_net_join_identity_and_ownership() {
        use std::os::unix::fs::MetadataExt as _;
        let a = FakeHolder::spawn();
        let b = FakeHolder::spawn();
        let (a_user, a_ipc, a_net, a_uts) = (a.ns("user"), a.ns("ipc"), a.ns("net"), a.ns("uts"));
        let b_net = b.ns("net");
        let (user_p, ipc_p) = (Path::new(&a_user), Path::new(&a_ipc));
        fn with<'a>(user: &'a Path, ipc: &'a Path, net: &'a str) -> JoinPaths<'a> {
            JoinPaths {
                user,
                ipc,
                net: Some(Path::new(net)),
            }
        }
        let with_net = |net| with(user_p, ipc_p, net);
        let (join, outcome) = NamespaceJoin::pin(with_net(&a_net)).expect("accepted");
        assert_eq!(outcome, PodNamespaceJoinOutcome::AcceptedUserIpcNet);
        assert!(join.net_fd().is_some());
        let meta = std::fs::metadata(&a_net).expect("stat");
        assert_eq!(
            join.net_identity.expect("identity"),
            (meta.dev(), meta.ino())
        );
        // user・ipc だけなら net は持たない。
        let (pair, outcome) = NamespaceJoin::pin(JoinPaths {
            net: None,
            ..with_net(&a_net)
        })
        .expect("pair");
        assert_eq!(outcome, PodNamespaceJoinOutcome::AcceptedUserIpc);
        assert!(pair.net_fd().is_none());
        // 呼び出し側自身の userns 所有の netns は受けない。
        let own = NamespaceJoin::pin(with_net("/proc/self/ns/net")).expect_err("host netns");
        assert_eq!(own.error.code(), ErrorCode::Unimplemented);
        assert_eq!(own.outcome, Some(PodNamespaceJoinOutcome::NetNotPodOwned));
        // 別 pod(別 userns)の netns は取り違えとして拒否する。
        let other = NamespaceJoin::pin(with_net(&b_net)).expect_err("other pod netns");
        assert_eq!(other.error.code(), ErrorCode::PermissionDenied);
        assert_eq!(
            other.outcome,
            Some(PodNamespaceJoinOutcome::NetOwnerMismatch)
        );
        let uts = NamespaceJoin::pin(with_net(&a_uts)).expect_err("uts as net");
        assert_eq!(uts.error.code(), ErrorCode::InvalidArgument);
        assert_eq!(uts.outcome, Some(PodNamespaceJoinOutcome::NotNamespaceFile));
        println!("net3_2872: pod netns join identity and ownership verified");
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
        let scratch =
            crate::scratch_root::ScratchDir::new("ns-join-reg", std::time::Duration::from_secs(10));
        let file = scratch.path().join("f");
        std::fs::write(&file, b"x").expect("write");
        let f = file.to_str().expect("utf8");
        assert_eq!(
            code(pin(f, "/proc/self/ns/ipc")),
            ErrorCode::InvalidArgument
        );
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
