//! pod の保持役が、pod で共有する user・ipc・net・mount namespace を確立する公開 API(Linux 限定。
//! CRI-2・CORE-3・SEC-5・NET-2。#2870・#4808。設計は #2838 と `docs/design/pod-namespace-holder.md`)。
//!
//! # 役割と呼び出し元
//!
//! pod の ipc 共有(#2674)は core 側の join(`NamespaceJoin`・`exec::isolate_join`)まで実装済みだが、join 先の
//! namespace を作って持ち続ける供給元が無かった。本モジュールはその土台(H1)で、supervisor の bin の
//! `pod-holder` モード(H2・#2874)が、exec された単一スレッドのプロセスから [`establish_pod_namespaces`] を
//! 呼ぶ。保持役のプロセス自体(READY フレーム・stdin EOF / SIGTERM での終了)は本モジュールの範囲外で未実装
//! (REPAIR-3)。後で `NamespaceJoin::pin` と `exec::isolate_join` が要求する条件(user namespace の親子・作成者 uid・
//! ipc の所有・写像の完全一致。SEC-5)を満たす namespace をここで作る。
//!
//! # 手順(権限モデルの解決は launch と同じ `resolve_privilege` を使う)
//!
//! 1. 入口の検査(すべて副作用の前): 単一スレッド・`RootfulHostRoot` の拒否・入力元の整合
//! 2. user(写像つき)→ ipc → net → mount の順に作る(mount は pod の userns が所有し、`/` は再帰 private。#4808)。`RootlessSingleId` は `exec::isolate` の `unshare(2)` 1 回、
//!    `RootlessSubordinateIds` は `exec::isolate_rootless_subordinate`(holder・mapper 経由。呼び出しプロセスは
//!    dumpable にならない。#2374)
//! 3. `/proc/self/{uid,gid}_map` を読み戻し、計画と **完全一致** することを照合する(不一致は成功値を返さない)
//! 4. ipc・net・mount の所有者が新しい user namespace であることを fd で照合し(`NS_GET_USERNS`)、各 namespace の
//!    素性を報告する
//!
//! # pod-init の空の root(#4808。O2)
//!
//! [`create_pod_root`] は、呼び出しプロセスの mount namespace に接続しない tmpfs(`nosuid,nodev,noexec`・空)を作り、
//! fd で返す([`PodRoot`])。保持役は段 1 で確立した後に自分を再 exec して継承した fd を閉じるため、段 2 で
//! capability を落とす前に呼んで持ち続ける。pod-init(P5)はこのマウントへ移って `pivot_root` する前提で、保持役
//! 自身の root は変わらない(マウントを木に付けないため。mount namespace は確立時の private な複製のまま)。
//!
//! # pod の `/dev/shm`(#4821。O6 の案 A の S1)
//!
//! [`mount_pod_shm`] は、確立した mount namespace の `/dev/shm` に pod で共有する tmpfs(コンテナの既定と同じ 64 MiB・
//! `nosuid,nodev,noexec`・mode 1777)を載せ、tmpfs のルートの素性を返す。保持役は段 2 で capability を落とす前に呼び、
//! 素性を READY に載せる。コンテナの init はこの mount namespace へ入って複製を取る(S2・#4822。`exec::pod_shm`)。
//!
//! # 契約(呼び出し側の義務)
//!
//! - **単一スレッドから呼ぶ**(`CLONE_NEWUSER` の条件。満たさなければ副作用なしで `FailedPrecondition`)
//! - **機密をメモリに置いたまま呼ばない**: 範囲写像の holder は呼び出し時点のメモリの COW 複製を持ち、release
//!   まで dumpable である(#2546)。保持役は秘密を持たないこと
//! - **失敗したプロセスは破棄する**(写像は write-once で戻せない)
//! - 範囲写像の経路は Linux 6.9 以降が要る(`exec::isolate_rootless_subordinate` の helper の停止手段。緩めない)
//! - **[`mount_pod_shm`] は確立済みの mount namespace の中でだけ呼ぶ**: `/` が再帰 private な、pod の userns 所有の
//!   mount namespace でなければ、載せたマウントが他の namespace へ伝播しうる。検証に通らなかったときもマウントは
//!   残るので、そのプロセスは破棄する（保持役は失敗で終了し、mount namespace ごと消える）
//! - **`lo` は本 API が up にする**: netns の作成直後に `lo` を up にし、up にできなければエラー(fail-closed)。
//!   保持役(H2)が重複して up にしたり、up でない前提で組んだりしない
//!
//! # 未実装・残余(REPAIR-3)
//!
//! - 保持役のプロセス(`pod-holder` モード。READY フレーム・終了条件・fd の整理)は #2874
//! - `NamespaceJoin` の net 対応(user + ipc + net の join)は #2872
//! - `RootfulHostRoot` は #2241 の決定（D1 A）で恒久拒否し `PermissionDenied`
//!
//! エラーは `TraitError` で返し、文言は固定の英語でパス・pid・errno・写像の値を含めない(REPAIR-4)。

use std::os::fd::AsFd as _;

use super::SubordinateIdSource;
use super::launcher::{SubordinateIds, resolve_privilege};
use super::namespace_join::identity_plain as identity;
use crate::exec::{
    IdMapping, IsolationConfig, IsolationPrivilege, Namespace, NamespaceSet, plan,
    plan_rootless_subordinate,
};
use crate::rootless::{IdKind, ProcHandle, RootlessError, TargetPid};
use crate::sys;
use crate::traits::{ErrorCode, TraitError};

const MSG_MULTI_THREADED: &str = "the pod holder must be called from a single-threaded process";
const MSG_ROOTFUL: &str = "the rootful privilege model is permanently refused by policy (SEC-5)";
const MSG_MAP_MISMATCH: &str = "the pod holder id mapping does not match the expected mapping";
const MSG_NOT_OWNED: &str = "the pod holder namespaces are not owned by the pod user namespace";
const MSG_NOT_NEW: &str = "the pod holder user namespace was not created";
const MSG_INSPECT: &str = "failed to inspect the pod holder namespaces";
const MSG_TIMEOUT: &str = "the pod holder namespaces were not established within the timeout";
const MSG_DENIED: &str = "permission denied while establishing the pod holder namespaces";
const MSG_PRECONDITION: &str = "a precondition for the pod holder namespaces was not met";
const MSG_FAILED: &str = "failed to establish the pod holder namespaces";

/// nsfs 上の namespace の素性(`st_dev`・`st_ino`)。保持役の READY フレームの材料(#2874)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceIdentity {
    dev: u64,
    ino: u64,
}

impl NamespaceIdentity {
    /// nsfs の `st_dev`。
    pub fn dev(&self) -> u64 {
        self.dev
    }

    /// nsfs の `st_ino`。
    pub fn ino(&self) -> u64 {
        self.ino
    }
}

/// [`establish_pod_namespaces`] の成功結果(照合済み。将来拡張できるよう `non_exhaustive`)。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PodHolderNamespaces {
    privilege: IsolationPrivilege,
    uid_map: Vec<IdMapping>,
    gid_map: Vec<IdMapping>,
    user: NamespaceIdentity,
    ipc: NamespaceIdentity,
    net: NamespaceIdentity,
    mnt: NamespaceIdentity,
}

impl PodHolderNamespaces {
    /// 実際に使った権限モデル。
    pub fn privilege(&self) -> IsolationPrivilege {
        self.privilege
    }

    /// 読み戻して計画との一致を確かめた uid 写像。
    pub fn uid_map(&self) -> &[IdMapping] {
        &self.uid_map
    }

    /// 読み戻して計画との一致を確かめた gid 写像。
    pub fn gid_map(&self) -> &[IdMapping] {
        &self.gid_map
    }

    /// 新しい user namespace の素性。
    pub fn user(&self) -> NamespaceIdentity {
        self.user
    }

    /// 新しい ipc namespace の素性(所有者は [`Self::user`])。
    pub fn ipc(&self) -> NamespaceIdentity {
        self.ipc
    }

    /// 新しい net namespace の素性(所有者は [`Self::user`])。
    pub fn net(&self) -> NamespaceIdentity {
        self.net
    }

    /// 新しい mount namespace の素性(所有者は [`Self::user`]。`/` は再帰 private。#4808)。
    pub fn mnt(&self) -> NamespaceIdentity {
        self.mnt
    }

    /// `lo` が up か。作成直後に up にできなければ確立自体が失敗するため、成功値では常に `true`(NET-2)。
    pub fn loopback_up(&self) -> bool {
        true
    }
}

/// 副作用の前の権限モデルの検査(純関数)。`RootfulHostRoot` は #2241 の決定（D1 A）で恒久拒否し `PermissionDenied`。
fn check_request(privilege: IsolationPrivilege) -> Result<(), TraitError> {
    match privilege {
        IsolationPrivilege::RootfulHostRoot => {
            Err(TraitError::new(ErrorCode::PermissionDenied, MSG_ROOTFUL))
        }
        _ => Ok(()),
    }
}

/// 計画から導いた期待する写像(純関数。`SingleId` は自 ID をコンテナ 0 へ 1 行、範囲写像は解決済みの行)。
fn expected_id_maps(
    euid: u32,
    egid: u32,
    subordinate: Option<&SubordinateIds>,
) -> (Vec<IdMapping>, Vec<IdMapping>) {
    match subordinate {
        Some(ids) => (ids.uid.entries().to_vec(), ids.gid.entries().to_vec()),
        None => (
            vec![IdMapping {
                container_id: 0,
                host_id: euid,
                count: 1,
            }],
            vec![IdMapping {
                container_id: 0,
                host_id: egid,
                count: 1,
            }],
        ),
    }
}

/// 読み戻した写像が期待と構造上一致するか(行数・順序・`container_id`・`count`)を照合する(SEC-5)。
///
/// 確立後の呼び出し側は新しい user namespace の内側にいるため、`/proc/self/{uid,gid}_map` の `host_id` は
/// 開いた側の namespace を基準に報告され、ホスト側の計画値とは一致しない場合がある。そのため `host_id` は比較しない
/// (範囲写像の `host_id` は `apply_id_maps` が書き込み時にホスト側で読み戻して照合済み。単一 ID は計画の 1 行を
/// カーネルが書いたもの)。
fn verify_id_maps(
    read: impl Fn(IdKind) -> Result<Vec<IdMapping>, RootlessError>,
    uid: &[IdMapping],
    gid: &[IdMapping],
) -> Result<(), TraitError> {
    for (kind, expected) in [(IdKind::Uid, uid), (IdKind::Gid, gid)] {
        let got = read(kind).map_err(|e| TraitError::new(e.code, MSG_INSPECT))?;
        let shape = |v: &[IdMapping]| -> Vec<(u32, u32)> {
            v.iter().map(|e| (e.container_id, e.count)).collect()
        };
        if shape(&got) != shape(expected) {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                MSG_MAP_MISMATCH,
            ));
        }
    }
    Ok(())
}

/// `ExecError` を固定文言の `TraitError` へ写す(code は保つ。パス・errno・値は外へ出さない)。
fn map_exec_error(e: &crate::exec::ExecError) -> TraitError {
    let message = match e.code {
        ErrorCode::Timeout => MSG_TIMEOUT,
        ErrorCode::PermissionDenied => MSG_DENIED,
        ErrorCode::FailedPrecondition => MSG_PRECONDITION,
        _ => MSG_FAILED,
    };
    TraitError::new(e.code, message)
}

/// pod で共有する user(写像つき)・ipc・net namespace を確立し、照合して素性を返す。
///
/// 呼び出し元は保持役(H2・#2874)。権限モデルの解決は launch と同じ(`RootlessSingleId` は `subordinate_ids` を
/// 渡さない、`RootlessSubordinateIds` は必須。取り違えは `InvalidArgument`)。契約(単一スレッド・機密なし・失敗時は
/// プロセスを破棄・`lo` を up にする)はモジュール doc を参照。
pub fn establish_pod_namespaces(
    privilege: IsolationPrivilege,
    subordinate_ids: Option<SubordinateIdSource>,
) -> Result<PodHolderNamespaces, TraitError> {
    // 1. 入口の検査(すべて副作用の前)。
    if !sys::self_is_single_threaded() {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            MSG_MULTI_THREADED,
        ));
    }
    check_request(privilege)?;
    let (euid, egid) = (sys::effective_uid(), sys::effective_gid());
    let subordinate = resolve_privilege(privilege, subordinate_ids, euid, egid)?;
    let config = IsolationConfig {
        namespaces: NamespaceSet::empty()
            .with(Namespace::User)
            .with(Namespace::Ipc)
            .with(Namespace::Net)
            .with(Namespace::Mount),
        hostname: None,
    };
    let (expected_uid, expected_gid) = expected_id_maps(euid, egid, subordinate.as_ref());

    // 2. 確立。開始前の user namespace の素性と dumpable を記録する。
    let before_user = identity_of(c"/proc/self/ns/user")?;
    let was_non_dumpable = matches!(sys::is_dumpable(), Ok(false));
    match subordinate {
        None => {
            let p = plan(&config).map_err(|e| map_exec_error(&e))?;
            crate::exec::isolate(&p).map_err(|e| map_exec_error(&e))?;
        }
        Some(ids) => {
            let p = plan_rootless_subordinate(&config, ids.uid, ids.gid, ids.writer, ids.timeout)
                .map_err(|e| map_exec_error(&e))?;
            crate::exec::isolate_rootless_subordinate(&p).map_err(|e| map_exec_error(&e))?;
        }
    }
    // 戻す方向にだけ動かす(dumpable の方針そのものは保持役側の判断。#2874)。
    if was_non_dumpable {
        sys::set_non_dumpable().map_err(|_| TraitError::new(ErrorCode::Internal, MSG_FAILED))?;
    }

    // 3. 写像の読み戻しと完全一致の照合。
    verify_id_maps(
        |kind| {
            let target = TargetPid::new(std::process::id())?;
            crate::rootless::read_id_map_of(&ProcHandle::open(target)?, kind)
        },
        &expected_uid,
        &expected_gid,
    )?;

    // 4. 所有の照合(fd を 1 回だけ開き、検査と報告に同じ fd を使う)。
    let inspect = |_: sys::SysError| TraitError::new(ErrorCode::Internal, MSG_INSPECT);
    let user = open_self_ns(c"/proc/self/ns/user")?;
    let ipc = open_self_ns(c"/proc/self/ns/ipc")?;
    let net = open_self_ns(c"/proc/self/ns/net")?;
    let mnt = open_self_ns(c"/proc/self/ns/mnt")?;
    let user_id = identity(user.as_fd())?;
    if user_id == before_user {
        return Err(TraitError::new(ErrorCode::PermissionDenied, MSG_NOT_NEW));
    }
    for fd in [&ipc, &net, &mnt] {
        let owner = sys::ns_owner_userns(fd.as_fd()).map_err(|e| match e {
            sys::SysError::Os(errno) if errno == sys::EPERM => {
                TraitError::new(ErrorCode::PermissionDenied, MSG_NOT_OWNED)
            }
            other => inspect(other),
        })?;
        if identity(owner.as_fd())? != user_id {
            return Err(TraitError::new(ErrorCode::PermissionDenied, MSG_NOT_OWNED));
        }
    }
    let ident = |(dev, ino)| NamespaceIdentity { dev, ino };
    Ok(PodHolderNamespaces {
        privilege,
        uid_map: expected_uid,
        gid_map: expected_gid,
        user: ident(user_id),
        ipc: ident(identity(ipc.as_fd())?),
        net: ident(identity(net.as_fd())?),
        mnt: ident(identity(mnt.as_fd())?),
    })
}

const MSG_ROOT_CREATE: &str = "failed to create the pod root";
const MSG_ROOT_ATTRS: &str = "the pod root does not have the expected mount attributes";
const MSG_ROOT_NOT_EMPTY: &str = "the pod root is not empty";

/// pod-init が動く空の root(切り離した tmpfs のマウントの fd。#4808)。drop で閉じるとカーネルがマウントを破棄する。
#[derive(Debug)]
pub struct PodRoot {
    fd: std::os::fd::OwnedFd,
}

/// [`PodRoot`] のマウントの属性(`fstatfs` の `f_flags` を読み直した値)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PodRootAttrs {
    /// `nosuid`。
    pub nosuid: bool,
    /// `nodev`。
    pub nodev: bool,
    /// `noexec`。
    pub noexec: bool,
}

impl PodRoot {
    /// マウントのルートを指す fd(close-on-exec)。
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// マウントの属性を読み直す。
    pub fn attrs(&self) -> Result<PodRootAttrs, TraitError> {
        let flags = sys::mount_flags(self.fd.as_fd())
            .map_err(|_| TraitError::new(ErrorCode::Internal, MSG_INSPECT))?;
        if !flags.is_valid() {
            return Err(TraitError::new(ErrorCode::Internal, MSG_INSPECT));
        }
        Ok(PodRootAttrs {
            nosuid: flags.is_nosuid(),
            nodev: flags.is_nodev(),
            noexec: flags.is_noexec(),
        })
    }
}

/// pod-init の空の root を作る(`nosuid,nodev,noexec`・mode 0o755・64 KiB の tmpfs。どこにも接続しない。#4808)。
///
/// 呼び出しスレッドの mount namespace を所有する user namespace の `CAP_SYS_ADMIN` が要る(保持役は確立の後、
/// capability を落とす前に呼ぶ)。作った直後に属性(3 つとも付く)と中身(0 件)を確かめ、合わなければ返さない
/// (fail-closed)。
pub fn create_pod_root() -> Result<PodRoot, TraitError> {
    let fd = sys::new_detached_tmpfs(sys::PodRootTmpfsCreate::new()).map_err(|e| match e {
        sys::SysError::Os(errno) if errno == sys::EPERM => {
            TraitError::new(ErrorCode::PermissionDenied, MSG_DENIED)
        }
        sys::SysError::Unsupported => TraitError::new(ErrorCode::Unimplemented, MSG_ROOT_CREATE),
        _ => TraitError::new(ErrorCode::Internal, MSG_ROOT_CREATE),
    })?;
    let root = PodRoot { fd };
    let attrs = root.attrs()?;
    if !(attrs.nosuid && attrs.nodev && attrs.noexec) {
        return Err(TraitError::new(ErrorCode::Internal, MSG_ROOT_ATTRS));
    }
    if root_entry_count(&root)? != 0 {
        return Err(TraitError::new(ErrorCode::Internal, MSG_ROOT_NOT_EMPTY));
    }
    Ok(root)
}

/// root の直下のエントリ数(`.`・`..` を除く)。fd の magic link から開く(パスの再解決をしない)。
pub fn root_entry_count(root: &PodRoot) -> Result<usize, TraitError> {
    use std::os::fd::AsRawFd as _;
    let dir = std::fs::read_dir(format!("/proc/self/fd/{}", root.fd.as_raw_fd()))
        .map_err(|_| TraitError::new(ErrorCode::Internal, MSG_INSPECT))?;
    let mut n = 0usize;
    for entry in dir {
        entry.map_err(|_| TraitError::new(ErrorCode::Internal, MSG_INSPECT))?;
        n = n.saturating_add(1);
    }
    Ok(n)
}

const MSG_SHM_TARGET: &str = "the pod /dev/shm mount point is not usable";
const MSG_SHM_MOUNT: &str = "failed to mount the pod /dev/shm";
const MSG_SHM_VERIFY: &str = "the pod /dev/shm does not have the expected attributes";

/// 保持役の mount ns で pod の `/dev/shm` を載せる場所（保持役自身の mount ns の中の固定パス。外部入力ではない）。
pub(crate) const POD_SHM_PATH: &std::ffi::CStr = c"/dev/shm";

/// 保持役の mount ns に載せた pod の `/dev/shm`（tmpfs のルート）の素性（`st_dev`・`st_ino`。CRI-2・CORE-3・SEC-5・#4821）。
///
/// `st_dev` は tmpfs の superblock ごとに一意なので、コンテナの init が保持役の mnt ns へ入って開いた `/dev/shm` が
/// この tmpfs かを照合できる（S2・#4822）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PodShm {
    dev: u64,
    ino: u64,
}

impl PodShm {
    /// tmpfs のルートの `st_dev`。
    pub fn dev(&self) -> u64 {
        self.dev
    }

    /// tmpfs のルートの `st_ino`。
    pub fn ino(&self) -> u64 {
        self.ino
    }
}

/// 保持役の mount ns の `/dev/shm` に、pod で共有する tmpfs を載せる（CRI-2・CORE-3・SEC-5・#4821。S1）。
///
/// 中身はコンテナの既定の `/dev/shm`（[`crate::tmpfs::TmpfsMountSpec::default_dev_shm`]。64 MiB・`nosuid,nodev,noexec`・
/// mode 1777。#1654）と同じ定義から作る。呼び出し元は保持役の段 2 で、[`establish_pod_namespaces`] で作った mount ns
/// （`/` は再帰 private のため、載せたマウントはホストへ伝播しない）の中から、pod の userns の capability を落とす前に呼ぶ。
///
/// 載せ先は `O_NOFOLLOW` で開いたディレクトリの fd のまま `move_mount` へ渡す。載せた後に同じパスを開き直し、載せた
/// マウントのルートと同じ素性であること・属性 3 つ・mode 1777 を確かめ、合わなければ返さない（fail-closed）。
/// ホストに `/dev/shm` のディレクトリが無い構成は `FailedPrecondition`。マウントの fd は返さない（マウントは mount ns に
/// 残り、保持役が開いたままにする fd を増やさない）。
pub fn mount_pod_shm() -> Result<PodShm, TraitError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let spec = crate::tmpfs::TmpfsMountSpec::default_dev_shm()?;
    let create = sys::TmpfsCreate {
        mode: spec.mode.bits(),
        size: spec.size.map(|s| s.bytes()),
        flags: sys::TmpfsMountFlags {
            read_only: spec.read_only,
            exec: spec.exec,
        },
    };
    let target = sys::open_dir_path_nofollow(None, POD_SHM_PATH)
        .map_err(|_| TraitError::new(ErrorCode::FailedPrecondition, MSG_SHM_TARGET))?;
    let mounted = sys::mount_tmpfs_on(target.as_fd(), create).map_err(|e| match e {
        sys::SysError::Os(errno) if errno == sys::EPERM => {
            TraitError::new(ErrorCode::PermissionDenied, MSG_DENIED)
        }
        sys::SysError::Unsupported => TraitError::new(ErrorCode::Unimplemented, MSG_SHM_MOUNT),
        _ => TraitError::new(ErrorCode::Internal, MSG_SHM_MOUNT),
    })?;
    let verify = || TraitError::new(ErrorCode::Internal, MSG_SHM_VERIFY);
    let meta = |fd: std::os::fd::BorrowedFd<'_>| {
        let file = std::fs::File::from(fd.try_clone_to_owned().map_err(|_| verify())?);
        file.metadata().map_err(|_| verify())
    };
    let ours = meta(mounted.as_fd())?;
    let top = sys::open_dir_path_nofollow(None, POD_SHM_PATH).map_err(|_| verify())?;
    let seen = meta(top.as_fd())?;
    let flags = sys::mount_flags(top.as_fd()).map_err(|_| verify())?;
    let attrs_ok = flags.is_valid() && flags.is_nosuid() && flags.is_nodev() && flags.is_noexec();
    if (seen.dev(), seen.ino()) != (ours.dev(), ours.ino())
        || !attrs_ok
        || seen.permissions().mode() & 0o7777 != spec.mode.bits()
    {
        return Err(verify());
    }
    Ok(PodShm {
        dev: ours.dev(),
        ino: ours.ino(),
    })
}

const MSG_POD_INIT: &str = "failed to start the pod init";
const MSG_POD_INIT_STOP: &str = "the pod init did not stop within the limit";

/// pod の PID 1（pod-init）のハンドル（CRI-2・CORE-3・SEC-5・SEC-1・#4815。O2）。
///
/// 保持役が [`spawn_pod_init`] で 1 回だけ作る。pidfd で同一性を固定し、終了の観測（[`Self::has_exited`]）と停止
/// （[`Self::kill_and_reap`]）に使う。drop では止めない（保持役の終了時は pod-init の `PR_SET_PDEATHSIG` が止める）。
#[derive(Debug)]
pub struct PodInit {
    pid: u32,
    pidfd: std::os::fd::OwnedFd,
}

impl PodInit {
    /// pod-init の pid（保持役の pid namespace から見た値）。
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// pod-init が終了したか（pidfd が読み取り可能になったか。待たない）。
    pub fn has_exited(&self) -> Result<bool, TraitError> {
        sys::poll_readable(self.pidfd.as_fd(), 0)
            .map_err(|_| TraitError::new(ErrorCode::Internal, MSG_INSPECT))
    }

    /// 停止の合図（`stop` が読める。保持役では stdin の EOF か入力）か、pod-init の終了の、先に起きたほうまで待つ。
    ///
    /// ponytail: 2 つの fd を 1 回の poll で待つラッパーを足さず、`stop` を 1 秒の期限で待つたびに pidfd を見る。pod-init の
    /// 終了の検出は最大 1 秒遅れる（保持役の終了と `SANDBOX_NOTREADY` の判定には十分。速さが要るなら 2 fd の poll を足す）。
    pub fn wait_stop_or_exit(
        &self,
        stop: std::os::fd::BorrowedFd<'_>,
    ) -> Result<PodHolderWake, TraitError> {
        loop {
            if self.has_exited()? {
                return Ok(PodHolderWake::PodInitExited);
            }
            match sys::poll_readable(stop, 1000) {
                Ok(true) => return Ok(PodHolderWake::StopReadable),
                Ok(false) | Err(sys::SysError::Os(sys::EINTR)) => {}
                Err(_) => return Err(TraitError::new(ErrorCode::Internal, MSG_INSPECT)),
            }
        }
    }

    /// pod-init へ SIGKILL を送り、`limit` まで回収を待つ（pid ns ごと止まる。REPAIR-5）。
    pub fn kill_and_reap(&self, limit: std::time::Duration) -> Result<(), TraitError> {
        let _ = sys::pidfd_send_signal(self.pidfd.as_fd(), sys::Signal::Kill);
        reap_within(self.pid, limit)
    }
}

/// 直接の子 `pid` の回収を `limit` まで待つ（REPAIR-5）。
fn reap_within(pid: u32, limit: std::time::Duration) -> Result<(), TraitError> {
    let deadline = std::time::Instant::now() + limit;
    loop {
        match sys::wait_pid_nohang(pid) {
            Ok(Some(_)) => return Ok(()),
            Ok(None) | Err(sys::SysError::Os(sys::EINTR)) => {}
            Err(_) => return Err(TraitError::new(ErrorCode::Internal, MSG_POD_INIT_STOP)),
        }
        if std::time::Instant::now() >= deadline {
            return Err(TraitError::new(ErrorCode::Timeout, MSG_POD_INIT_STOP));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// pod-init の初期化の完了（ACK）を待つ上限と、失敗時に回収を待つ上限（REPAIR-5）。
const POD_INIT_START_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);
/// pod-init が初期化を終えたときに ACK の pipe へ書く 1 バイト。
const POD_INIT_ACK: u8 = b'R';

/// ACK の pipe の読み端から [`POD_INIT_ACK`] を `limit` まで待つ。EOF（子が初期化の途中で終わった）・期限切れ・
/// 別の値は `false`。
fn wait_pod_init_ack(ack: &std::io::PipeReader, limit: std::time::Duration) -> bool {
    use std::io::Read as _;
    let deadline = std::time::Instant::now() + limit;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let ms = i32::try_from(left.as_millis()).unwrap_or(i32::MAX);
        match sys::poll_readable(ack.as_fd(), ms) {
            Ok(true) => break,
            Ok(false) if left.is_zero() => return false,
            Ok(false) | Err(sys::SysError::Os(sys::EINTR)) => {}
            Err(_) => return false,
        }
    }
    let mut byte = [0u8; 1];
    loop {
        match (&*ack).read(&mut byte) {
            Ok(1) => return byte[0] == POD_INIT_ACK,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            _ => return false,
        }
    }
}

/// [`PodInit::wait_stop_or_exit`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PodHolderWake {
    /// 停止の合図の fd が読める（EOF を含む）。
    StopReadable,
    /// pod-init が終了した（その pid ns では以後 fork できない）。
    PodInitExited,
}

/// 保持役が pod の pid namespace を作り、pod-init を PID 1 として fork する（CRI-2・CORE-3・SEC-5・SEC-1・#4815。O2）。
///
/// 呼び出し元は保持役の段 2（単一スレッド・pod の userns の capability を落とす前）。手順:
///
/// 1. `unshare(CLONE_NEWPID)`。呼び出し側自身は移らず、以後に fork する子が新しい pid ns に入る
///    （`/proc/self/ns/pid_for_children` が新しい ns を指す。#2776 のパスの供給元）
/// 2. 1 回だけ fork する。新しい pid ns の最初のプロセスが PID 1 になる（Linux v6.12 の `kernel/pid.c` の `alloc_pid`
///    〔228〜241 行。新しい ns の最初の割り当ては 1〕と `kernel/fork.c` の `copy_process`〔2558〜2560 行。PID 1 が
///    `child_reaper`〕）
/// 3. 子（pod-init）は、親の死で SIGKILL が届くようにしてから親の生存を pidfd で確かめ、自分の mount ns を作って
///    `/` を再帰 private にし、空の root（[`PodRoot`]）を `/` の上に付けて `pivot_root(".", ".")` で移り、旧 root を
///    切り離す。自分の mount ns を作るのは、`pivot_root` が同じ root を持つプロセスの root をすべて差し替えるため
///    （`fs/namespace.c` の `pivot_root` の `chroot_fs_refs`。保持役の root を変えない）
/// 4. pod-init は `SIGCHLD` を無視にして孤児を自動で回収させ（`kernel/signal.c` の `do_notify_parent`）、
///    capability をすべて落とし、non-dumpable であることを確かめ、fd をすべて閉じてから待つだけになる
///
/// 4 の後に pod-init は ACK の pipe へ 1 バイト書いてから閉じる。親は ACK を期限つきで待ち、EOF（`pod_init_main` の
/// 失敗の終了）・期限切れなら子を SIGKILL して回収してからエラーを返す（READY より前に失敗させる。fail-closed）。
/// `pidfd_open` の失敗でも子を止めて回収する（未回収の子の pid は再利用されないため `kill` で宛先を取り違えない）。
///
/// pod-init が死ぬとその pid ns では以後 fork できない（`kernel/pid_namespace.c` の `zap_pid_ns_processes` 179 行の
/// `disable_pid_allocation` と `kernel/pid.c` の `alloc_pid` 277 行。ns の残りのプロセスも SIGKILL で止まる）。保持役は
/// [`PodInit::has_exited`] で監視し、死んだら自分も終わる（fail-closed）。
pub fn spawn_pod_init(root: &PodRoot) -> Result<PodInit, TraitError> {
    let fail = |code| TraitError::new(code, MSG_POD_INIT);
    if !sys::self_is_single_threaded() {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            MSG_MULTI_THREADED,
        ));
    }
    let parent = sys::pidfd_open(std::process::id()).map_err(|_| fail(ErrorCode::Internal))?;
    sys::unshare_namespaces(&[sys::NsFlag::Pid]).map_err(|e| match e {
        sys::SysError::Os(errno) if errno == sys::EPERM => {
            TraitError::new(ErrorCode::PermissionDenied, MSG_DENIED)
        }
        _ => fail(ErrorCode::Internal),
    })?;
    let (ack_r, ack_w) = std::io::pipe().map_err(|_| fail(ErrorCode::Internal))?;
    let pid = sys::fork_single_threaded(
        || pod_init_main(parent.as_fd(), root.fd.as_fd(), &ack_w),
        POD_INIT_PANIC_EXIT,
    )
    .map_err(|_| fail(ErrorCode::Internal))?;
    // 親の書き端を閉じ、子が ACK の前に終わったら EOF で分かるようにする。
    drop(ack_w);
    let pidfd = match sys::pidfd_open(pid) {
        Ok(fd) => fd,
        Err(_) => {
            let _ = sys::kill_pid(pid, sys::Signal::Kill);
            let _ = reap_within(pid, POD_INIT_START_LIMIT);
            return Err(fail(ErrorCode::Internal));
        }
    };
    let init = PodInit { pid, pidfd };
    if !wait_pod_init_ack(&ack_r, POD_INIT_START_LIMIT) {
        let _ = init.kill_and_reap(POD_INIT_START_LIMIT);
        return Err(fail(ErrorCode::Internal));
    }
    Ok(init)
}

/// pod-init の panic 時の終了コード。
const POD_INIT_PANIC_EXIT: i32 = 70;

/// pod-init の本体（fork した子で動く。戻り値は失敗時の終了コードで、成功すれば戻らない）。
fn pod_init_main(
    parent: std::os::fd::BorrowedFd<'_>,
    root: std::os::fd::BorrowedFd<'_>,
    ack: &std::io::PipeWriter,
) -> i32 {
    if sys::set_parent_death_sigkill().is_err() {
        return 71;
    }
    // 設定より前に親が死んでいたらシグナルは届かないため、ここで確かめる。
    if !matches!(sys::poll_readable(parent, 0), Ok(false)) {
        return 72;
    }
    if sys::unshare_namespaces(&[sys::NsFlag::Mount]).is_err() {
        return 73;
    }
    if sys::mount_root_private_recursive().is_err() {
        return 74;
    }
    let Ok(old_root) = sys::open_dir_path_nofollow(None, c"/") else {
        return 75;
    };
    if sys::move_mount_empty_path(root, old_root.as_fd()).is_err() {
        return 76;
    }
    if sys::change_dir_fd(root).is_err()
        || sys::pivot_root_dot().is_err()
        || sys::change_dir_fd(old_root.as_fd()).is_err()
        || sys::umount_cwd_detach().is_err()
        || std::env::set_current_dir("/").is_err()
    {
        return 77;
    }
    drop(old_root);
    if sys::ignore_child_signal().is_err() {
        return 79;
    }
    if sys::cap_ambient_clear_all().is_err()
        || sys::cap_set_thread(sys::ThreadCaps {
            effective: [0; 2],
            permitted: [0; 2],
            inheritable: [0; 2],
        })
        .is_err()
    {
        return 80;
    }
    if !matches!(sys::is_dumpable(), Ok(false)) {
        return 81;
    }
    // ACK の書き端だけを残して閉じ、初期化の完了を知らせてから最後の 1 本も閉じる。
    if sys::close_fds_from_except(0, ack.as_fd()).is_err() {
        return 78;
    }
    {
        use std::io::Write as _;
        if (&*ack).write_all(&[POD_INIT_ACK]).is_err() {
            return 82;
        }
    }
    if sys::close_fds_from(0).is_err() {
        return 78;
    }
    // ponytail: 待つだけ。孤児の回収はカーネルが自動で行う（SIGCHLD を無視にした）ため起きる必要が無い。
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// 自プロセスの namespace を開く(固定の `/proc/self/ns/*` のみ。外部入力は使わない)。
fn open_self_ns(path: &std::ffi::CStr) -> Result<std::os::fd::OwnedFd, TraitError> {
    sys::open_ns_file(path).map_err(|_| TraitError::new(ErrorCode::Internal, MSG_INSPECT))
}

/// 固定パスの namespace の素性。
fn identity_of(path: &std::ffi::CStr) -> Result<(u64, u64), TraitError> {
    let fd = open_self_ns(path)?;
    identity(fd.as_fd())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(c: u32, h: u32, n: u32) -> IdMapping {
        IdMapping {
            container_id: c,
            host_id: h,
            count: n,
        }
    }

    /// SEC-5・CRI-2: SingleId の期待する写像は自 ID をコンテナ 0 へ 1 行。
    #[test]
    fn sec5_2870_expected_maps_single_id() {
        let (u, g) = expected_id_maps(1000, 1001, None);
        assert_eq!(u, vec![m(0, 1000, 1)]);
        assert_eq!(g, vec![m(0, 1001, 1)]);
    }

    /// 照合は行の構造の一致(過不足・順序・container_id・count の違いを拒否。host_id は比較しない)。
    #[test]
    fn sec5_2870_verify_id_maps_requires_exact_match() {
        let uid = vec![m(0, 1000, 1), m(1, 100000, 65536)];
        let gid = vec![m(0, 1000, 1)];
        let reader = |u: Vec<IdMapping>, g: Vec<IdMapping>| {
            move |k: IdKind| {
                Ok(match k {
                    IdKind::Uid => u.clone(),
                    IdKind::Gid => g.clone(),
                })
            }
        };
        assert_eq!(
            verify_id_maps(reader(uid.clone(), gid.clone()), &uid, &gid),
            Ok(())
        );
        let bad: [(Vec<IdMapping>, Vec<IdMapping>); 5] = [
            (vec![m(0, 1000, 2), m(1, 100000, 65536)], gid.clone()),
            (uid.clone(), vec![m(1, 1000, 1)]),
            (
                vec![m(0, 1000, 1), m(1, 100000, 65536), m(65537, 5, 1)],
                gid.clone(),
            ),
            (vec![m(0, 1000, 1)], gid.clone()),
            (vec![m(1, 100000, 65536), m(0, 1000, 1)], gid.clone()),
        ];
        // host_id は開いた側の namespace 基準で変わりうるため、違っていても受理する。
        assert_eq!(
            verify_id_maps(
                reader(vec![m(0, 0, 1), m(1, 1, 65536)], vec![m(0, 0, 1)]),
                &uid,
                &gid
            ),
            Ok(())
        );
        for (u, g) in bad {
            let err = verify_id_maps(reader(u, g), &uid, &gid).expect_err("mismatch");
            assert_eq!(err.code(), ErrorCode::FailedPrecondition);
            assert_eq!(err.message(), MSG_MAP_MISMATCH);
        }
    }

    /// 読み取りの失敗はエラー(固定文言)。
    #[test]
    fn sec5_2870_verify_id_maps_propagates_read_failure() {
        let read = |_: IdKind| -> Result<Vec<IdMapping>, RootlessError> {
            TargetPid::new(0).map(|_| Vec::new())
        };
        let err = verify_id_maps(read, &[], &[]).expect_err("read failure");
        assert_eq!(err.message(), MSG_INSPECT);
    }

    /// libtest はマルチスレッドのため、確立は副作用なしで `FailedPrecondition`(固定文言)。
    #[test]
    fn core3_2870_multi_threaded_caller_is_rejected() {
        let err = establish_pod_namespaces(IsolationPrivilege::RootlessSingleId, None)
            .expect_err("multi-threaded");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), MSG_MULTI_THREADED);
    }

    /// rootful は #2241 の決定で恒久拒否（`PermissionDenied`）。
    #[test]
    fn sec5_2870_rootful_is_permission_denied() {
        let err = check_request(IsolationPrivilege::RootfulHostRoot).expect_err("rootful");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(err.message(), MSG_ROOTFUL);
        assert_eq!(check_request(IsolationPrivilege::RootlessSingleId), Ok(()));
    }

    /// 入力元の取り違えは launch と同じ解決で `InvalidArgument`。
    #[test]
    fn sec5_2870_source_mismatch_is_invalid_argument() {
        let missing =
            resolve_privilege(IsolationPrivilege::RootlessSubordinateIds, None, 1000, 1000)
                .expect_err("source required");
        assert_eq!(missing.code(), ErrorCode::InvalidArgument);
        let source = SubordinateIdSource::system(None).expect("source");
        let extra = resolve_privilege(
            IsolationPrivilege::RootlessSingleId,
            Some(source),
            1000,
            1000,
        )
        .expect_err("source forbidden");
        assert_eq!(extra.code(), ErrorCode::InvalidArgument);
    }

    /// 失敗の写像は固定文言のみで、パス・数字を含まない。
    #[test]
    fn repair4_2870_error_mapping_is_fixed_text() {
        use crate::exec::{ExecError, IsolationStage};
        let allowed = [MSG_TIMEOUT, MSG_DENIED, MSG_PRECONDITION, MSG_FAILED];
        for code in [
            ErrorCode::Timeout,
            ErrorCode::PermissionDenied,
            ErrorCode::FailedPrecondition,
            ErrorCode::Internal,
            ErrorCode::InvalidArgument,
        ] {
            let e = ExecError::new(code, IsolationStage::Unshare, "open /etc/subuid failed: 42");
            let t = map_exec_error(&e);
            assert_eq!(t.code(), code);
            assert!(allowed.contains(&t.message()), "{}", t.message());
            assert!(!t.message().contains('/') && !t.message().chars().any(|c| c.is_ascii_digit()));
        }
    }
}
