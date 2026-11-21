//! `linux.namespaces[].path` による pod の user・ipc（と任意で network）namespace への参加（join）の検証と fd 固定
//! （CRI-2・CORE-3・SEC-1・SEC-5・NET-3・OCI-4。#2674・#2872）。
//!
//! # 役割と呼び出し元
//!
//! `start` が config の `linux.namespaces[]` から `NamespaceJoin::paths_of` と `pin` を呼び、`user` と `ipc` の
//! path を **組** で受ける。network と pid の path は user と ipc の組に **足す形でだけ** 受ける（net は #2872。設計 #2838 の H7。
//! pid は #4809。設計 #2903 の P1）。検証済みの fd を [`LaunchSpec`](super::LaunchSpec) に載せ、本番 launcher が中間プロセス I
//! の分離で `setns(2)` に使う（`exec::isolate_join`。順は user → ipc → net → pid）。mount・uts・cgroup・time の path、片方だけの
//! path、network・pid 単独（user・ipc の組なし）の path は従来どおり `Unimplemented` で拒否する（fail-closed）。
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
//! | pid: 所有する user namespace が join する user namespace と違う | `PermissionDenied` |
//! | pid: 呼び出し側自身の pid namespace / 親（`NS_GET_PARENT`）が呼び出し側の pid namespace でない | `PermissionDenied` |
//!
//! 検査は user → ipc → net → pid の順で、user の検査が先に通ること。受理と拒否は閉じた語彙
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
//! - pid の path は受けて `setns(pid)` まで行う（#4809）が、`setns(pid)` は以後に fork した子にだけ効き、その子は
//!   参加先の PID 1 ではない。init の mount 分離の証跡は「joined pid ns の init」の種別で、pin 時に取った pid ns の
//!   素性（`pid_identity`）との一致を PID 1 の代わりに求める（`exec::check_establish_preconditions`・#4812）。exec・
//!   healthcheck の対象の固定（`Pid1Target`）は、launch の記録に残した同じ素性（`LaunchIsolationRecord::pod_pid_ns`）で
//!   launch pidfd の経路でだけ対象を受け、記録 pid から開く縮退経路を拒否する（#4813）。reapply の pid ns の照合も記録した
//!   素性で行う。cri は #4817 まで pid の path を出さない。
//! - pid の参加先は path の代わりに起動オプションの `PinnedPidTarget`（pid の TARGET。`pid_target` モジュール。#4819）でも
//!   受ける。対象の launch pidfd で固定した fd を pid 欄へ入れ、検査は path と同じ。path との併用は `InvalidArgument`。
//! - `/dev/shm`（POSIX shm）は、起動オプションの `PodShmSource`（supervisor の argv `--pod-shm`。`pod_shm` モジュール。
//!   #4822・S2）を受けたときだけ pod で共有する（init が保持役の mount namespace の tmpfs を複製して載せる。`exec::pod_shm`）。
//!   指定が無ければ共有されず、core がコンテナごとの tmpfs を載せる。本番の指定元（plugin-cri が保持役の pid と READY の
//!   素性から組む配線）は S3（#4823）で未実装。SysV IPC と POSIX mqueue は ipc の join で共有される。
//! - 周辺の未完: 保持役の素性の永続化と再起動後の再採用は #2940、rootless の本番 PodNetworkProvider（pasta）は #2879。

mod pid_target;
mod pinned_net;
mod pod_shm;

use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::Arc;

use super::config::{NamespaceKind, OciConfig};
use crate::audit_log::PodNamespaceJoinOutcome;
use crate::traits::{ErrorCode, TraitError};

pub use pid_target::PinnedPidTarget;
pub use pinned_net::{NetnsJoinTarget, PinnedNetnsJoin};
pub use pod_shm::{PinnedPodShm, PodShmSource};

#[cfg(target_os = "linux")]
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

/// パス長の上限（`CONFIG_MAX_PATH_BYTES` と同値）。
#[cfg(target_os = "linux")]
const PATH_MAX_BYTES: usize = 4096;

/// config から取り出した join の path の組（I/O なし。`paths_of` の結果）。
///
/// `user` と `ipc` は常にある（組）。`net` は pod の netns も共有するときだけ（#2872）、`pid` は pod の pid ns も
/// 共有するときだけ（#4809）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct JoinPaths<'a> {
    pub(super) user: &'a Path,
    pub(super) ipc: &'a Path,
    pub(super) net: Option<&'a Path>,
    pub(super) pid: Option<&'a Path>,
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
    /// pod の pid namespace（#4809）。`setns` は中間プロセスで行い、以後に fork した init だけが入る。
    /// `Some` のとき `pid_identity` も `Some`。
    #[cfg(target_os = "linux")]
    pid: Option<Arc<OwnedFd>>,
    /// pin 時に取った pid の (dev, ino)。init の establish と証跡の再検証が、参加した init の pid ns と照合する（#4812）。
    #[cfg(target_os = "linux")]
    pid_identity: Option<(u64, u64)>,
    /// Linux 以外では構築できないことを型で表す。
    #[cfg(not(target_os = "linux"))]
    never: std::convert::Infallible,
}

impl PartialEq for NamespaceJoin {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(target_os = "linux")]
        {
            let same = |a: &Option<Arc<OwnedFd>>, b: &Option<Arc<OwnedFd>>| match (a, b) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            };
            Arc::ptr_eq(&self.user, &other.user)
                && Arc::ptr_eq(&self.ipc, &other.ipc)
                && same(&self.net, &other.net)
                && same(&self.pid, &other.pid)
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
        "start does not support yet: linux.namespaces[].path (only a user and ipc pair, optionally with network and pid)",
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
        let (mut user, mut ipc, mut net, mut pid): (
            Option<&Path>,
            Option<&Path>,
            Option<&Path>,
            Option<&Path>,
        ) = (None, None, None, None);
        for ns in config.namespaces() {
            let Some(path) = ns.path() else { continue };
            let slot = match ns.kind() {
                NamespaceKind::User => &mut user,
                NamespaceKind::Ipc => &mut ipc,
                NamespaceKind::Network => &mut net,
                NamespaceKind::Pid => &mut pid,
                _ => return Err(unsupported_path()),
            };
            if slot.replace(path).is_some() {
                return Err(TraitError::new(
                    ErrorCode::InvalidArgument,
                    "linux.namespaces has a duplicate entry with a path",
                ));
            }
        }
        let (user, ipc) = match (user, ipc, net.or(pid)) {
            (None, None, None) => return Ok(None),
            (Some(user), Some(ipc), _) => (user, ipc),
            _ => return Err(unsupported_path()),
        };
        // path 付きの種別に path 無しの同種別が混ざると、どちらを採るか曖昧になる（fail-closed）。
        let count = |k: NamespaceKind| config.namespaces().iter().filter(|n| n.kind() == k).count();
        if count(NamespaceKind::User) != 1
            || count(NamespaceKind::Ipc) != 1
            || (net.is_some() && count(NamespaceKind::Network) != 1)
            || (pid.is_some() && count(NamespaceKind::Pid) != 1)
        {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "linux.namespaces has a duplicate user, ipc, network or pid entry",
            ));
        }
        Ok(Some(JoinPaths {
            user,
            ipc,
            net,
            pid,
        }))
    }

    /// user・ipc（と任意で net）namespace のパスを開き、素性を照合して fd に固定する（モジュール doc の表）。
    ///
    /// `pid_target`（pid の TARGET。#4819）は pid の path と排他で、固定済みの fd を `Arc` で共有して pid 欄に入れる。以降の検査
    /// （nsfs・種別・所有 userns・親の pid ns）と素性の取得は path の場合と同じ。
    ///
    /// 拒否は [`PinRejection`] で、素性検査による拒否には監査に残す結果が付く。
    #[cfg(target_os = "linux")]
    pub(super) fn pin(
        paths: JoinPaths<'_>,
        pid_target: Option<&PinnedPidTarget>,
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
            pid: pid_path,
        } = paths;
        let malformed = |r: Result<(), TraitError>| {
            r.map_err(|e| PinRejection {
                error: e,
                outcome: Some(O::PathMalformed),
            })
        };
        malformed(check_path(user_path))?;
        malformed(check_path(ipc_path))?;
        for extra in [net_path, pid_path].into_iter().flatten() {
            malformed(check_path(extra))?;
        }
        let user = open_ns(user_path)?;
        let ipc = open_ns(ipc_path)?;
        let net = net_path.map(open_ns).transpose()?;
        // pid の参加先は path か、起動オプションの TARGET（固定済みの fd。#4819）のどちらか一方だけ。
        let pid: Option<Arc<OwnedFd>> = match (pid_path, pid_target) {
            (Some(path), None) => Some(Arc::new(open_ns(path)?)),
            (None, Some(target)) => Some(Arc::clone(target.ns())),
            (None, None) => None,
            (Some(_), Some(_)) => {
                return Err(PinRejection::from(TraitError::new(
                    ErrorCode::InvalidArgument,
                    "a pid namespace target cannot be combined with a pid namespace path",
                )));
            }
        };
        let mut typed: Vec<(&OwnedFd, NsFlag)> = vec![(&user, NsFlag::User), (&ipc, NsFlag::Ipc)];
        if let Some(net) = &net {
            typed.push((net, NsFlag::Net));
        }
        if let Some(pid) = &pid {
            typed.push((pid.as_ref(), NsFlag::Pid));
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
        // netns(rootless 本番ではホストの netns)は、受けない(`Unimplemented`。rootful 本体は #2241 の決定で別途恒久拒否済みで、これは netns の参加の未対応)。
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
        // pid は pod の user namespace が所有し、呼び出し側の pid namespace の直下の子であるものに限る（#4809。SEC-5）。
        // `setns(pid)` は以後に fork した子だけを入れるため、自身・孫以下・無関係の pid ns を親子で弾く。
        if let Some(pid) = &pid {
            let owner_mismatch = || {
                PinRejection::new(
                    ErrorCode::PermissionDenied,
                    "the pod pid namespace is not owned by the pod user namespace",
                    O::PidOwnerMismatch,
                )
            };
            let owner = sys::ns_owner_userns(pid.as_fd()).map_err(|e| match e {
                sys::SysError::Os(errno) if errno == sys::EPERM => owner_mismatch(),
                other => inspect(other),
            })?;
            if identity(owner.as_fd())? != user_id {
                return Err(owner_mismatch());
            }
            let not_child = || {
                PinRejection::new(
                    ErrorCode::PermissionDenied,
                    "the pod pid namespace is not a direct child of the caller's",
                    O::PidNotChild,
                )
            };
            let caller_pid = open_ns(Path::new("/proc/self/ns/pid"))?;
            let caller_pid_id = identity(caller_pid.as_fd())?;
            if identity(pid.as_fd())? == caller_pid_id {
                return Err(not_child());
            }
            let parent = sys::ns_parent(pid.as_fd()).map_err(|e| match e {
                sys::SysError::Os(errno) if errno == sys::EPERM => not_child(),
                other => inspect(other),
            })?;
            if identity(parent.as_fd())? != caller_pid_id {
                return Err(not_child());
            }
        }
        let pid_identity = pid.as_ref().map(|p| identity(p.as_fd())).transpose()?;
        let outcome = match (net.is_some(), pid.is_some()) {
            (false, false) => O::AcceptedUserIpc,
            (true, false) => O::AcceptedUserIpcNet,
            (false, true) => O::AcceptedUserIpcPid,
            (true, true) => O::AcceptedUserIpcNetPid,
        };
        Ok((
            Self {
                user: Arc::new(user),
                ipc: Arc::new(ipc),
                net: net.map(Arc::new),
                net_identity,
                pid,
                pid_identity,
            },
            outcome,
        ))
    }

    /// 非 Linux は namespace を固定できない（`Unimplemented`。fail-closed。CLI-1）。
    #[cfg(not(target_os = "linux"))]
    pub(super) fn pin(
        _paths: JoinPaths<'_>,
        _pid_target: Option<&PinnedPidTarget>,
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
            pid: None,
            pid_identity: None,
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
            pid: None,
            pid_identity: None,
        }
    }

    /// 試験専用: pid の fd つき(素性は fd から取る。#4819)。
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn for_test_with_pid(user: OwnedFd, ipc: OwnedFd, pid: OwnedFd) -> Self {
        let pid_identity = identity(pid.as_fd()).ok();
        Self {
            user: Arc::new(user),
            ipc: Arc::new(ipc),
            net: None,
            net_identity: None,
            pid: Some(Arc::new(pid)),
            pid_identity,
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

    /// 固定した pid namespace の fd（pod の pid ns も共有するときだけ。`setns` 専用。#4809）。
    #[cfg(target_os = "linux")]
    pub(crate) fn pid_fd(&self) -> Option<BorrowedFd<'_>> {
        self.pid.as_ref().map(|p| p.as_fd())
    }

    /// pin 時に取った pid namespace の素性。init の establish と証跡の再検証が照合する（#4812）。
    #[cfg(target_os = "linux")]
    pub(crate) fn pid_identity(&self) -> Option<crate::exec::PidNsIdentity> {
        self.pid_identity
            .map(|(dev, ino)| crate::exec::PidNsIdentity::from_parts(dev, ino))
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
        NamespaceJoin::pin(
            JoinPaths {
                user: Path::new(user),
                ipc: Path::new(ipc),
                net: net.map(Path::new),
                pid: None,
            },
            None,
        )
        .map(|(join, _)| join)
        .map_err(|r| r.error)
    }

    fn outcome_of(user: &str, ipc: &str, net: Option<&str>) -> Option<PodNamespaceJoinOutcome> {
        NamespaceJoin::pin(
            JoinPaths {
                user: Path::new(user),
                ipc: Path::new(ipc),
                net: net.map(Path::new),
                pid: None,
            },
            None,
        )
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
    const P: &str = r#"{"type":"pid","path":"/proc/1/ns/pid"}"#;

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
                "start does not support yet: linux.namespaces[].path (only a user and ipc pair, optionally with network and pid)"
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

    /// CRI-2・CORE-3・SEC-5・#4809: pid の path は user と ipc の組に足す形でだけ受け（net の有無を問わない）、
    /// pid 単独・片方だけとの組は `Unimplemented`、重複は `InvalidArgument`。
    #[test]
    fn cri2_core3_4809_paths_of_accepts_pid_only_with_the_user_ipc_pair() {
        let with_pid = paths_of(&[U, I, P]).unwrap().expect("pid");
        assert_eq!(with_pid.pid, Some(Path::new("/proc/1/ns/pid")));
        assert_eq!(with_pid.net, None);
        let all = paths_of(&[U, I, N, P]).unwrap().expect("all");
        assert_eq!(all.net, Some(Path::new("/proc/1/ns/net")));
        assert_eq!(all.pid, Some(Path::new("/proc/1/ns/pid")));
        assert_eq!(paths_of(&[U, I]).unwrap().expect("pair").pid, None);
        for parts in [&[P][..], &[U, P][..], &[I, P][..], &[N, P][..]] {
            assert_eq!(
                paths_of(parts).unwrap_err().code(),
                ErrorCode::Unimplemented
            );
        }
        for (parts, msg) in [
            (
                &[U, I, P, P][..],
                "linux.namespaces has a duplicate entry with a path",
            ),
            (
                &[U, I, P, r#"{"type":"pid"}"#][..],
                "linux.namespaces has a duplicate user, ipc, network or pid entry",
            ),
        ] {
            let err = paths_of(parts).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert_eq!(err.message(), msg);
        }
    }

    fn pin_pid(
        user: &str,
        ipc: &str,
        pid: &str,
    ) -> Result<(NamespaceJoin, PodNamespaceJoinOutcome), PinRejection> {
        NamespaceJoin::pin(
            JoinPaths {
                user: Path::new(user),
                ipc: Path::new(ipc),
                net: None,
                pid: Some(Path::new(pid)),
            },
            None,
        )
    }

    /// CRI-2・CORE-3・SEC-5・#4819: pid の path と TARGET の併用は、固定文言の `InvalidArgument`（監査は出さない）。
    #[test]
    fn cri2_4819_pid_path_with_target_is_rejected() {
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn");
        let pidfd = crate::sys::pidfd_open(child.id()).expect("pidfd");
        let null = || -> OwnedFd { std::fs::File::open("/dev/null").expect("open").into() };
        let target = PinnedPidTarget::for_test(pidfd, null(), (1, 2));
        let e = NamespaceJoin::pin(
            JoinPaths {
                user: Path::new("/proc/self/ns/user"),
                ipc: Path::new("/proc/self/ns/ipc"),
                net: None,
                pid: Some(Path::new("/proc/self/ns/pid")),
            },
            Some(&target),
        )
        .expect_err("must be rejected");
        assert_eq!(e.error.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            e.error.message(),
            "a pid namespace target cannot be combined with a pid namespace path"
        );
        assert_eq!(e.outcome, None);
        let _ = child.kill();
        let _ = child.wait();
    }

    /// CRI-2・SEC-5・SEC-4・#4809: pid に別種別の namespace を指すと `InvalidArgument`（監査は `NotNamespaceFile`）、
    /// 形の不正は `PathMalformed`。種別の検査は user の自身検査より先に効く。
    #[test]
    fn cri2_sec5_4809_pid_path_type_and_shape_are_checked() {
        let (u, i) = ("/proc/self/ns/user", "/proc/self/ns/ipc");
        let e = pin_pid(u, i, "/proc/self/ns/ipc").expect_err("ipc as pid");
        assert_eq!(e.error.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            e.error.message(),
            "a namespace path has an unexpected namespace type"
        );
        assert_eq!(e.outcome, Some(PodNamespaceJoinOutcome::NotNamespaceFile));
        let e = pin_pid(u, i, "proc/self/ns/pid").expect_err("relative");
        assert_eq!(e.error.code(), ErrorCode::InvalidArgument);
        assert_eq!(e.outcome, Some(PodNamespaceJoinOutcome::PathMalformed));
        // 正しい種別でも user の自身検査が先に効く（pid の検査に届かない）。
        let e = pin_pid(u, i, "/proc/self/ns/pid").expect_err("own");
        assert_eq!(e.outcome, Some(PodNamespaceJoinOutcome::UserIsOwn));
    }

    /// 実機: 保持役の代わりの `unshare --user --map-root-user --ipc --net sleep` を起動して、その `/proc/<pid>/ns/*` を
    /// join 先に使う(非特権 user namespace。`kernel.apparmor_restrict_unprivileged_userns` の緩和が要るホストがある)。
    /// 期限つきで回収する(REPAIR-5)。前提が欠ければ skip せず固定行で失敗する。
    struct FakeHolder {
        child: std::process::Child,
    }

    impl FakeHolder {
        fn spawn() -> Self {
            Self::spawn_with(
                &["--user", "--map-root-user", "--ipc", "--net", "sleep", "30"],
                "net",
            )
        }

        /// pid namespace も作る保持役（`--pid --fork`。unshare 自身は外に残り、`pid_for_children` が新しい pid ns を指す。
        /// `inner` が真なら、その中でさらに `unshare --pid --fork` して孫の pid ns を作る。#4809）。
        fn spawn_pid(inner: bool) -> Self {
            // `--kill-child`: 段の unshare が回収されたら子も SIGKILL で消える（Drop は直接の子しか待たないため）。
            let mut args = vec![
                "--user",
                "--map-root-user",
                "--ipc",
                "--pid",
                "--fork",
                "--kill-child",
            ];
            if inner {
                args.extend(["unshare", "--pid", "--fork", "--kill-child"]);
            }
            args.extend(["sleep", "30"]);
            Self::spawn_with(&args, "pid_for_children")
        }

        fn spawn_with(args: &[&str], wait_kind: &str) -> Self {
            let mut child = std::process::Command::new("unshare")
                .args(args)
                .spawn()
                .expect("PRECONDITION FAILED: unshare(1) is required");
            // unshare が namespace に入るまで待つ(`/proc/<pid>/ns/<kind>` が自分と異なる素性になる)。
            let me = std::fs::read_link(format!("/proc/self/ns/{wait_kind}")).expect("own ns");
            let path = format!("/proc/{}/ns/{wait_kind}", child.id());
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
                pid: None,
            }
        }
        let with_net = |net| with(user_p, ipc_p, net);
        let (join, outcome) = NamespaceJoin::pin(with_net(&a_net), None).expect("accepted");
        assert_eq!(outcome, PodNamespaceJoinOutcome::AcceptedUserIpcNet);
        assert!(join.net_fd().is_some());
        let meta = std::fs::metadata(&a_net).expect("stat");
        assert_eq!(
            join.net_identity.expect("identity"),
            (meta.dev(), meta.ino())
        );
        // user・ipc だけなら net は持たない。
        let (pair, outcome) = NamespaceJoin::pin(
            JoinPaths {
                net: None,
                ..with_net(&a_net)
            },
            None,
        )
        .expect("pair");
        assert_eq!(outcome, PodNamespaceJoinOutcome::AcceptedUserIpc);
        assert!(pair.net_fd().is_none());
        // 呼び出し側自身の userns 所有の netns は受けない。
        let own = NamespaceJoin::pin(with_net("/proc/self/ns/net"), None).expect_err("host netns");
        assert_eq!(own.error.code(), ErrorCode::Unimplemented);
        assert_eq!(own.outcome, Some(PodNamespaceJoinOutcome::NetNotPodOwned));
        // 別 pod(別 userns)の netns は取り違えとして拒否する。
        let other = NamespaceJoin::pin(with_net(&b_net), None).expect_err("other pod netns");
        assert_eq!(other.error.code(), ErrorCode::PermissionDenied);
        assert_eq!(
            other.outcome,
            Some(PodNamespaceJoinOutcome::NetOwnerMismatch)
        );
        let uts = NamespaceJoin::pin(with_net(&a_uts), None).expect_err("uts as net");
        assert_eq!(uts.error.code(), ErrorCode::InvalidArgument);
        assert_eq!(uts.outcome, Some(PodNamespaceJoinOutcome::NotNamespaceFile));
        println!("net3_2872: pod netns join identity and ownership verified");
    }

    /// `pid` の直下の子の pid を期限つきで待つ（`/proc/<pid>/task/<pid>/children`）。
    fn first_child(pid: u32) -> u32 {
        let path = format!("/proc/{pid}/task/{pid}/children");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(c) = std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| s.split_whitespace().next().and_then(|t| t.parse().ok()))
            {
                return c;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "PRECONDITION FAILED: the holder did not fork its child"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// 実機(`--ignored`)。CRI-2・CORE-3・SEC-5・SEC-4・#4809: pod の userns 所有で呼び出し側の直下の子の pid ns は受理し
    /// （結果は `pod_join_accepted_user_ipc_pid`）、別 userns 所有は `PidOwnerMismatch`、孫の pid ns は `PidNotChild`、
    /// 呼び出し側自身の pid ns は所有者の検査で `PidOwnerMismatch`。受理した fd で user → ipc → pid の順に `setns` した後に
    /// fork した子の `/proc/thread-self/ns/pid` の素性が対象の pid ns と一致する。
    #[test]
    #[ignore = "needs unprivileged user namespaces and unshare(1); run with --ignored (#4809)"]
    fn cri2_core3_4809_real_holder_pid_join_identity_and_ownership() {
        use std::os::unix::fs::MetadataExt as _;
        let a = FakeHolder::spawn_pid(false);
        let b = FakeHolder::spawn_pid(false);
        let nested = FakeHolder::spawn_pid(true);
        let (a_user, a_ipc, a_pid) = (a.ns("user"), a.ns("ipc"), a.ns("pid_for_children"));
        let (join, outcome) = pin_pid(&a_user, &a_ipc, &a_pid).expect("accepted");
        assert_eq!(outcome, PodNamespaceJoinOutcome::AcceptedUserIpcPid);
        let target = std::fs::metadata(&a_pid).expect("stat");
        let pid_fd = join.pid_fd().expect("pid fd");
        assert_eq!(identity(pid_fd).ok(), Some((target.dev(), target.ino())));

        let other = pin_pid(&a_user, &a_ipc, &b.ns("pid_for_children")).expect_err("other pod");
        assert_eq!(other.error.code(), ErrorCode::PermissionDenied);
        assert_eq!(
            other.outcome,
            Some(PodNamespaceJoinOutcome::PidOwnerMismatch)
        );
        let own = pin_pid(&a_user, &a_ipc, "/proc/self/ns/pid").expect_err("own pid ns");
        assert_eq!(own.outcome, Some(PodNamespaceJoinOutcome::PidOwnerMismatch));
        // 孫: nested の unshare の子（中段の unshare）の pid_for_children は、nested の pid ns の子。
        let middle = first_child(nested.child.id());
        let grandchild_ns = format!("/proc/{middle}/ns/pid_for_children");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        // 両方が読めて素性が異なるときだけ準備完了（unshare から fork までの間は読み取りが失敗し得る）。
        let ready = || match (
            std::fs::read_link(&grandchild_ns),
            std::fs::read_link(format!("/proc/{middle}/ns/pid")),
        ) {
            (Ok(inner), Ok(outer)) => inner != outer,
            _ => false,
        };
        while !ready() {
            assert!(
                std::time::Instant::now() < deadline,
                "PRECONDITION FAILED: no inner pid ns"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let deep =
            pin_pid(&nested.ns("user"), &nested.ns("ipc"), &grandchild_ns).expect_err("grandchild");
        assert_eq!(deep.error.code(), ErrorCode::PermissionDenied);
        assert_eq!(
            deep.error.message(),
            "the pod pid namespace is not a direct child of the caller's"
        );
        assert_eq!(deep.outcome, Some(PodNamespaceJoinOutcome::PidNotChild));

        // join の後に fork した子の pid ns の素性。子は確保をしない（多スレッドの試験から fork するため）。
        let want = (target.dev(), target.ino());
        let child = crate::sys::fork_single_threaded_with(
            || true,
            || {
                use crate::sys::{self, NsFlag};
                if sys::setns_fd(join.user_fd(), NsFlag::User).is_err() {
                    return 10;
                }
                if sys::setns_fd(join.ipc_fd(), NsFlag::Ipc).is_err() {
                    return 11;
                }
                if sys::setns_fd(pid_fd, NsFlag::Pid).is_err() {
                    return 12;
                }
                let Ok(grand) = sys::fork_single_threaded_with(
                    || true,
                    || {
                        let Ok(me) = sys::open_ns_file(c"/proc/thread-self/ns/pid") else {
                            return 21;
                        };
                        if !matches!(identity(me.as_fd()), Ok(id) if id == want) {
                            return 22;
                        }
                        joined_init_establish(join.pid_identity())
                    },
                    23,
                ) else {
                    return 13;
                };
                wait_exit(grand)
            },
            19,
        )
        .expect("fork");
        assert_eq!(
            wait_exit(child),
            0,
            "joined child must enter the target pid ns and pass the joined init evidence"
        );
        println!(
            "cri2_core3_4809: pod pid ns join identity, ownership and the forked child verified"
        );
        println!(
            "cri2_core3_4812: joined pid ns init (not PID 1) established mount isolation with the pinned identity"
        );
    }

    /// #4812: 参加した pid ns で fork した子（参加先の PID 1 ではない）が、固定した素性で `establish` を通り、証跡の
    /// 再検証も通ること。別の素性は `unshare` の前に固定の理由で拒否される。戻り値は子の終了コード（0 が成功）。
    ///
    /// 使い捨ての子プロセスから呼ぶ（成功すると呼んだプロセスの mount ns が変わる）。glibc の `fork` は malloc の
    /// ロックを子で作り直すため、子での確保（status の読み取り）は詰まらない。
    fn joined_init_establish(pinned: Option<crate::exec::PidNsIdentity>) -> i32 {
        use crate::exec::{IsolationStage, MountIsolation, PidNsIdentity};
        if std::process::id() == 1 {
            return 31;
        }
        let Some(pinned) = pinned else {
            return 32;
        };
        match MountIsolation::establish_with(None, Some(PidNsIdentity::from_parts(0, 0))) {
            Err(e)
                if e.message
                    == "the joined PID namespace does not match the pod PID namespace pinned at launch" =>
                {}
            _ => return 33,
        }
        // 従来の経路（PID 1 を求める）では拒否される。
        if MountIsolation::establish_with(None, None).is_ok() {
            return 34;
        }
        let Ok(evidence) = MountIsolation::establish_with(None, Some(pinned)) else {
            return 35;
        };
        if evidence.verify_caller(IsolationStage::MountProc).is_err() {
            return 36;
        }
        0
    }

    /// 保持役の代わり（`unshare --user --map-root-user --mount`）。`mount_shm` が真なら自分の mount ns の `/dev/shm` に
    /// pod の共有と同じ定義（`size=64m,nosuid,nodev,noexec,mode=1777`）の tmpfs を載せて待つ。偽なら何も載せない
    /// （ホストの `/dev/shm` がそのまま見える保持役。素性の照合が効くことの確認用）。
    fn spawn_shm_holder(mount_shm: bool) -> FakeHolder {
        spawn_shm_holder_with(mount_shm, "size=64m,nosuid,nodev,noexec,mode=1777")
    }

    /// [`spawn_shm_holder`] の tmpfs のマウントオプションを指定する版（属性の拒否の試験で `noexec` を外す）。
    fn spawn_shm_holder_with(mount_shm: bool, shm_opts: &str) -> FakeHolder {
        use std::io::BufRead as _;
        // 準備完了は mount の成功の後に子が出す 1 行で知る。ホストの `/dev/shm` も多くは tmpfs のため、mountinfo の
        // 「tmpfs がある」では mount の前の継承したマウントでも成立してしまう（REPAIR-12）。
        let script = if mount_shm {
            format!("mount -t tmpfs -o {shm_opts} tmpfs /dev/shm && echo ready && exec sleep 30")
        } else {
            "echo ready && exec sleep 30".to_owned()
        };
        let mut holder = FakeHolder {
            child: std::process::Command::new("unshare")
                .args([
                    "--user",
                    "--map-root-user",
                    "--mount",
                    "--propagation",
                    "private",
                ])
                .args(["sh", "-c", &script])
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("PRECONDITION FAILED: unshare(1) is required"),
        };
        let stdout = holder.child.stdout.take().expect("holder stdout");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        let line = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("PRECONDITION FAILED: the holder did not set up its mount namespace");
        assert_eq!(
            line, "ready\n",
            "PRECONDITION FAILED: the holder did not set up its mount namespace"
        );
        holder
    }

    /// 実機(`--ignored`)。CRI-2・CORE-3・SEC-5・SEC-1・CORE-5・#4806・#4822（S2）: 本番の複製の関数
    /// （`exec::pod_shm::clone_from_holder`。init の pivot 前段が呼ぶ）が、非特権の user + mount namespace で通ること。
    ///
    /// 保持役の代わりが自分の mount ns の `/dev/shm` に tmpfs（`size=64m,nosuid,nodev,noexec,mode=1777`）を載せる。
    /// コンテナの init の代わり（保持役の userns へ参加し、`unshare(CLONE_NEWNS)` で自分の mount ns を作った fork 子）が、
    /// 保持役の mnt ns の fd と READY 相当の素性（保持役の `/dev/shm` の `(st_dev, st_ino)`）を渡して複製を取り、自分の
    /// mnt ns へ戻って `move_mount` で載せ先へ付ける。具体値で照合するもの: 往復の後に mnt ns・cwd が元のまま、載せた先の
    /// `nosuid,nodev,noexec`（`fstatfs`）・mountinfo の `size=65536k`・両方向の内容の一致（`holder` / `init`）。素性が違う
    /// 期待値は `PermissionDenied` で拒否して何も載せず、保持役が tmpfs を載せていない（ホストの `/dev/shm` に解決する）場合も
    /// 同じ固定文言で拒否する。いずれも試験プロセスの mount ns には何も付かない。
    #[test]
    #[ignore = "needs unprivileged user namespaces, unshare(1) and mount(8); run with --ignored (#4806, #4822)"]
    fn cri2_core3_4806_shm_clone_via_holder_mnt_ns() {
        use crate::sys::{self, NsFlag};
        use std::ffi::CString;
        use std::os::unix::fs::MetadataExt as _;
        let (_scratch, dir) = crate::test_support::scratch_child("fandhe-shm-poc", "d");
        let dir = dir.canonicalize().expect("canonical scratch");
        let dst = dir.join("shm-dst");
        std::fs::create_dir_all(&dst).expect("mkdir dst");
        let dst_s = dst.to_str().expect("utf8").to_owned();
        let denied_message =
            "the pod /dev/shm in the holder mount namespace is not the expected tmpfs";

        let holder = spawn_shm_holder(true);
        let hpid = holder.child.id();
        // READY 相当の素性（保持役の `/dev/shm` の tmpfs のルート）。保持役の root 越しに fd なしで読む。
        let meta = std::fs::metadata(format!("/proc/{hpid}/root/dev/shm")).expect("holder shm");
        let expected = (meta.dev(), meta.ino());
        std::fs::write(format!("/proc/{hpid}/root/dev/shm/from-holder"), "holder")
            .expect("write on the holder side");
        let open_ns = |pid: u32, kind: &str| {
            sys::open_ns_file(&CString::new(format!("/proc/{pid}/ns/{kind}")).expect("c"))
                .unwrap_or_else(|e| panic!("open the holder {kind} ns: {e:?}"))
        };
        let (user, mnt) = (open_ns(hpid, "user"), open_ns(hpid, "mnt"));
        let dst_c = CString::new(dst_s.clone()).expect("c");
        let child = sys::fork_single_threaded_with(
            || true,
            || {
                if sys::setns_fd(user.as_fd(), NsFlag::User).is_err() {
                    return 10;
                }
                if sys::unshare_namespaces(&[NsFlag::Mount]).is_err() {
                    return 11;
                }
                if sys::mount_root_private_recursive().is_err() {
                    return 12;
                }
                if std::env::set_current_dir(&dir).is_err() {
                    return 13;
                }
                let own_ns = std::fs::read_link("/proc/thread-self/ns/mnt").ok();
                // 本番の複製（保持役の mnt ns へ入って複製し、戻る）。
                let Ok(clone) = crate::exec::clone_from_holder(mnt.as_fd(), expected) else {
                    return 14;
                };
                if std::fs::read_link("/proc/thread-self/ns/mnt").ok() != own_ns {
                    return 15;
                }
                if std::env::current_dir().ok().as_deref() != Some(dir.as_path()) {
                    return 16;
                }
                // 自分の mnt ns で載せる。
                let Ok(dst_fd) = sys::open_dir_path_nofollow(None, &dst_c) else {
                    return 19;
                };
                if sys::move_mount_empty_path(clone.as_fd(), dst_fd.as_fd()).is_err() {
                    return 20;
                }
                let Ok(top) = sys::open_dir_path_nofollow(None, &dst_c) else {
                    return 21;
                };
                match sys::mount_flags(top.as_fd()) {
                    Ok(f) if f.is_valid() && f.is_nosuid() && f.is_nodev() && f.is_noexec() => {}
                    _ => return 22,
                }
                let Ok(info) = std::fs::read_to_string("/proc/thread-self/mountinfo") else {
                    return 23;
                };
                let sized = info.lines().any(|l| {
                    l.split_whitespace().nth(4) == Some(dst_s.as_str())
                        && l.contains(" - tmpfs ")
                        && l.contains("size=65536k")
                });
                if !sized {
                    return 24;
                }
                match std::fs::read_to_string(dst.join("from-holder")) {
                    Ok(text) if text == "holder" => {}
                    _ => return 25,
                }
                if std::fs::write(dst.join("from-init"), "init").is_err() {
                    return 26;
                }
                // 素性の違う期待値は固定文言で拒否され、往復の後も mnt ns は元のまま。
                match crate::exec::clone_from_holder(mnt.as_fd(), (expected.0, expected.1 + 1)) {
                    Err(e)
                        if e.code == ErrorCode::PermissionDenied
                            && e.message == denied_message
                            && e.violation.as_ref().map(|v| v.reason)
                                == Some(crate::exec::ViolationReason::PodShmIdentityMismatch) => {}
                    _ => return 30,
                }
                if std::fs::read_link("/proc/thread-self/ns/mnt").ok() != own_ns {
                    return 31;
                }
                0
            },
            29,
        )
        .expect("fork");
        assert_eq!(
            wait_exit(child),
            0,
            "the round trip, attributes, contents and the identity refusal must hold"
        );
        assert_eq!(
            std::fs::read_to_string(format!("/proc/{hpid}/root/dev/shm/from-init"))
                .expect("read on the holder side"),
            "init"
        );

        // 保持役が tmpfs を載せていない（`/dev/shm` がホストのものに解決する）と、同じ固定文言で拒否される。
        let bare = spawn_shm_holder(false);
        let bpid = bare.child.id();
        let (buser, bmnt) = (open_ns(bpid, "user"), open_ns(bpid, "mnt"));
        let child = sys::fork_single_threaded_with(
            || true,
            || {
                if sys::setns_fd(buser.as_fd(), NsFlag::User).is_err() {
                    return 10;
                }
                if sys::unshare_namespaces(&[NsFlag::Mount]).is_err() {
                    return 11;
                }
                if sys::mount_root_private_recursive().is_err() {
                    return 12;
                }
                let own_ns = std::fs::read_link("/proc/thread-self/ns/mnt").ok();
                match crate::exec::clone_from_holder(bmnt.as_fd(), expected) {
                    Err(e)
                        if e.code == ErrorCode::PermissionDenied && e.message == denied_message => {
                    }
                    _ => return 40,
                }
                if std::fs::read_link("/proc/thread-self/ns/mnt").ok() != own_ns {
                    return 41;
                }
                0
            },
            29,
        )
        .expect("fork");
        assert_eq!(
            wait_exit(child),
            0,
            "a holder without its own tmpfs must be refused, not cloned"
        );

        // pin（start が fork の前に呼ぶ検証）も実 namespace で照合する。join の user namespace を所有者とする mnt ns は受理し、
        // 別の保持役（別の user namespace）の mnt ns は `PermissionDenied` と専用の監査の結果で拒否する。
        {
            use super::pod_shm::{PinnedPodShm, PodShmSource};
            let (user_path, ipc_path) = (
                format!("/proc/{bpid}/ns/user"),
                format!("/proc/{bpid}/ns/ipc"),
            );
            let paths = JoinPaths {
                user: Path::new(&user_path),
                ipc: Path::new(&ipc_path),
                net: None,
                pid: None,
            };
            let own_ipc = || open_ns(std::process::id(), "ipc");
            let source = PodShmSource::new(
                std::path::PathBuf::from(format!("/proc/{bpid}/ns/mnt")),
                1,
                1,
            )
            .expect("source");
            let same_holder = NamespaceJoin::for_test(open_ns(bpid, "user"), own_ipc());
            PinnedPodShm::pin(&source, Some(&same_holder), Some(&paths))
                .expect("the holder's own mount namespace is accepted");
            let other_holder = NamespaceJoin::for_test(open_ns(hpid, "user"), own_ipc());
            let e = PinnedPodShm::pin(&source, Some(&other_holder), Some(&paths))
                .expect_err("a mount namespace of another user namespace");
            assert_eq!(e.error.code(), ErrorCode::PermissionDenied);
            assert_eq!(
                e.outcome,
                Some(PodNamespaceJoinOutcome::PodShmOwnerMismatch)
            );
        }

        // 試験プロセスの mount ns には付いていない（載せ先は init の mount ns だけ）。
        let own_info = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        assert!(
            !own_info
                .lines()
                .any(|l| l.split_whitespace().nth(4) == Some(dst_s.as_str())),
            "the clone leaked into the caller's mount namespace"
        );
        assert!(
            !dst.join("from-init").exists(),
            "the target stays empty on the host"
        );
        drop(bare);
        drop(holder);
        println!(
            "cri2_core3_4806: the production pod /dev/shm clone (setns + open_tree + move_mount) works unprivileged"
        );
    }

    /// 実機(`--ignored`)。CRI-2・SEC-1・SEC-4・#4822: 素性は一致するが `noexec` の無い tmpfs を保持役が載せている場合、
    /// 複製は属性の拒否の固定文言と理由語 `pod_shm_identity_mismatch` で失敗し、mnt ns は往復後も元のまま。
    #[test]
    #[ignore = "needs unprivileged user namespaces, unshare(1) and mount(8); run with --ignored (#4822)"]
    fn cri2_sec1_4822_shm_clone_refuses_tmpfs_without_noexec() {
        use crate::sys::{self, NsFlag};
        use std::ffi::CString;
        use std::os::unix::fs::MetadataExt as _;
        let holder = spawn_shm_holder_with(true, "size=64m,nosuid,nodev,mode=1777");
        let hpid = holder.child.id();
        let meta = std::fs::metadata(format!("/proc/{hpid}/root/dev/shm")).expect("holder shm");
        let expected = (meta.dev(), meta.ino());
        let open_ns = |kind: &str| {
            sys::open_ns_file(&CString::new(format!("/proc/{hpid}/ns/{kind}")).expect("c"))
                .unwrap_or_else(|e| panic!("open the holder {kind} ns: {e:?}"))
        };
        let (user, mnt) = (open_ns("user"), open_ns("mnt"));
        let child = sys::fork_single_threaded_with(
            || true,
            || {
                if sys::setns_fd(user.as_fd(), NsFlag::User).is_err() {
                    return 10;
                }
                if sys::unshare_namespaces(&[NsFlag::Mount]).is_err() {
                    return 11;
                }
                if sys::mount_root_private_recursive().is_err() {
                    return 12;
                }
                let own_ns = std::fs::read_link("/proc/thread-self/ns/mnt").ok();
                match crate::exec::clone_from_holder(mnt.as_fd(), expected) {
                    Err(e)
                        if e.code == ErrorCode::PermissionDenied
                            && e.message
                                == "the pod /dev/shm is not a tmpfs with nosuid, nodev and noexec"
                            && e.violation.as_ref().map(|v| v.reason)
                                == Some(crate::exec::ViolationReason::PodShmIdentityMismatch) => {}
                    _ => return 40,
                }
                if std::fs::read_link("/proc/thread-self/ns/mnt").ok() != own_ns {
                    return 41;
                }
                0
            },
            29,
        )
        .expect("fork");
        assert_eq!(
            wait_exit(child),
            0,
            "a tmpfs without noexec must be refused with the attribute message and the audit reason"
        );
        drop(holder);
        println!(
            "cri2_sec1_4822: a pod /dev/shm tmpfs without noexec is refused with pod_shm_identity_mismatch"
        );
    }

    /// 子を期限つき（20 秒）で回収して終了コードを返す（異常終了・期限切れは 255）。
    fn wait_exit(pid: u32) -> i32 {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            match crate::sys::wait_pid_nohang(pid) {
                Ok(Some(status)) if status & 0x7f == 0 => return (status >> 8) & 0xff,
                Ok(Some(_)) => return 255,
                Ok(None) | Err(crate::sys::SysError::Os(crate::sys::EINTR)) => {}
                Err(_) => return 255,
            }
            if std::time::Instant::now() >= deadline {
                let _ = crate::sys::kill_pid(pid, crate::sys::Signal::Kill);
                return 255;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
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
