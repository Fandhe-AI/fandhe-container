//! pod で共有する `/dev/shm` の複製と rootfs への載せ込み（CRI-2・CORE-3・SEC-1・SEC-5・CORE-5。#4822・S2）。
//!
//! # 役割と呼び出し文脈
//!
//! 保持役は自分の mount namespace の `/dev/shm` に pod で共有する tmpfs を載せ、その素性を READY で報告する
//! （`oci_runtime::pod_holder::mount_pod_shm`。#4821・S1）。本モジュールは、コンテナの init が
//! 「[`create_default_devices`](super::create_default_devices) の後・[`mount_tmpfs`](super::mount_tmpfs) の前」に
//! （[`run_pre_pivot`](super::process) の `MountTmpfs` の枠で。新しい段・`IsolationStage` は足さない）その tmpfs を
//! 複製して rootfs の `/dev/shm` に載せる。呼び出し元は `RealPrePivotOps::mount_pod_shm`。
//!
//! ```text
//! 自分の mnt ns の fd・`/`・`.` を控える
//!   -> setns(保持役の mnt ns)            # v6.12 の open_tree(OPEN_TREE_CLONE) は呼び出し側の今の mnt ns のマウントしか複製できない
//!   -> /dev/shm を開く -> 素性・tmpfs・属性 3 つを同じ fd で照合 -> open_tree で複製
//!   -> setns(自分の mnt ns)              # 失敗したらパス操作を一切せずに終わる
//!   -> `/` の素性が往復前と同じ・cwd を戻す
//!   -> rootfs の dev/shm を fd 起点で開き、shared でないこと・移動していないことを確かめて move_mount
//!   -> 載せた後に開き直して、素性・属性・shared でないことを再照合
//! ```
//!
//! # 契約（不変条件）
//!
//! - **開いた fd のまま照合する**: 保持役の mnt ns で開いた `/dev/shm` の `(st_dev, st_ino)` が launch の固定時に受けた
//!   READY の素性と一致し、tmpfs で、`nosuid,nodev,noexec` であることを、**複製するのと同じ fd** で確かめる。pod の tmpfs が
//!   載っていない（保持役が別物・途中で外れた）と同じパスはホストの `/dev/shm` に解決するため、この照合が崩れると
//!   ホストの `/dev/shm` を複製してコンテナへ見せてしまう。パスは再解決しない
//! - **往復の失敗は後続のパス操作をしない**: 保持役の mnt ns に居る間はパスの解決先が別の木。戻れなければ固定文言のエラーで
//!   終え、呼び出し側（init。単一スレッド）はプロセスごと破棄する。戻れた後も `/` の素性（`st_dev`・`st_ino`・mount ID）が
//!   往復前と同じことを確かめてから cwd を戻す（`setns` は root と cwd を対象 ns の root へ置き換えるため）
//! - **後始末は無い**: 載せるのは init 専用の mnt ns の rootfs で、init の破棄でマウントごと消える。pod の tmpfs へは
//!   書かず外さない（保持役の ns のマウントは複製だけで、元は変わらない）。`dev/shm` のディレクトリは `create_default_devices` が
//!   載せた `/dev` の tmpfs の中にだけ作る（ホストの rootfs へ書かない）
//! - **伝播させない**: 載せ先のマウントが shared でないこと（ホストへ伝播しない）と、載せた後の複製が shared でないことを確かめる
//! - 必要なカーネル: Linux 5.2 以降（新マウント API）。未対応は縮退せず `Unimplemented`
//! - 呼び出しスレッドは `MountIsolation::establish` と同じスレッド。`CAP_SYS_ADMIN`（pod の user namespace。mnt ns の `setns` は
//!   対象 ns を所有する user namespace と呼び出し側の user namespace の両方で `CAP_SYS_ADMIN` と `CAP_SYS_CHROOT` を要る）は
//!   ステージ列が capability を落とす前の pivot 前段にだけある
//!
//! # 未実装・残余（REPAIR-3）
//!
//! 本番の指定元は S3（#4823）の経路（cri が `StartRequest::with_pod_shm` へ載せ、plugin-cri が supervisor の argv へ写す）。core の `start` は指定が launcher と食い違えば fork の前に `FailedPrecondition` で拒否する。

use std::ffi::OsStr;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use crate::sys::{self, MountTreeScope, NsFlag};
use crate::tmpfs::TmpfsMountSet;
use crate::traits::types::ErrorCode;

use super::tmpfs::{check_dev_order, open_chain, root_display, verify_mounted};
use super::{
    DeviceReport, ExecError, IsolationStage, MountIsolation, PreparedRootfs, ViolationReason,
    fd_mount_id, fd_still_at, mount_is_shared,
};

/// pivot 前段の `MountTmpfs` の枠で動く（新しい段を足さない）。
const STAGE: IsolationStage = IsolationStage::MountTmpfs;

/// 保持役の mount namespace の `/dev/shm`（`pod_holder::mount_pod_shm` が載せる場所と同じ。共有して複製しない）。
use crate::oci_runtime::pod_holder::POD_SHM_PATH;

/// pivot 前段へ渡す pod の共有 `/dev/shm` の指定（launch が start の固定結果から組む。CRI-2・#4822）。
#[derive(Clone, Copy)]
pub(crate) struct PodShmSetup<'a> {
    mnt_ns: BorrowedFd<'a>,
    expected: (u64, u64),
}

impl<'a> PodShmSetup<'a> {
    /// `mnt_ns` は start が 1 回だけ開いて検証した保持役の mount namespace の fd、`expected` は READY が報告した tmpfs の
    /// ルートの `(st_dev, st_ino)`。
    pub(crate) fn new(mnt_ns: BorrowedFd<'a>, expected: (u64, u64)) -> Self {
        Self { mnt_ns, expected }
    }
}

/// 素性・種別・属性の不一致。理由語 `pod_shm_identity_mismatch` を運び、親が層 `mount` の監査に 1 件記録する
/// （SEC-4・#4822。`launch_status` の段 `mount_tmpfs` の許可リスト経由）。`message` は子側の診断用で親へは運ばれない。
fn mismatch(message: &'static str) -> ExecError {
    let mut e = ExecError::from_violation_at(ViolationReason::PodShmIdentityMismatch, None, STAGE);
    e.message = message.to_string();
    e
}

/// 権限不足（監査対象の違反ではない）。
fn denied(message: &'static str) -> ExecError {
    ExecError::new(ErrorCode::PermissionDenied, STAGE, message)
}

fn internal(message: &'static str) -> ExecError {
    ExecError::new(ErrorCode::Internal, STAGE, message)
}

/// ディレクトリ fd の `(st_dev, st_ino)`（fd の `fstat`。パスは見ない）。
fn dev_ino(fd: BorrowedFd<'_>) -> Result<(u64, u64), ExecError> {
    use std::os::unix::fs::MetadataExt as _;
    let dup = fd
        .try_clone_to_owned()
        .map_err(|e| ExecError::from_io(&e, STAGE, "duplicate a pod shm directory fd"))?;
    let meta = std::fs::File::from(dup)
        .metadata()
        .map_err(|e| ExecError::from_io(&e, STAGE, "fstat a pod shm directory fd"))?;
    Ok((meta.dev(), meta.ino()))
}

/// 開いた fd が tmpfs で、`nosuid,nodev,noexec` であることを確かめる（同じ fd で。fail-closed）。
fn check_tmpfs_attrs(fd: BorrowedFd<'_>) -> Result<(), ExecError> {
    let magic = sys::fs_type(fd).map_err(|e| ExecError::from_sys(e, STAGE, "fstatfs(pod shm)"))?;
    let flags =
        sys::mount_flags(fd).map_err(|e| ExecError::from_sys(e, STAGE, "fstatfs(pod shm)"))?;
    if magic != sys::TMPFS_MAGIC
        || !(flags.is_valid() && flags.is_nosuid() && flags.is_nodev() && flags.is_noexec())
    {
        return Err(mismatch(
            "the pod /dev/shm is not a tmpfs with nosuid, nodev and noexec",
        ));
    }
    Ok(())
}

/// 保持役の mount namespace の中で `/dev/shm` を開き、素性・種別・属性を同じ fd で照合してから複製する。
///
/// 呼び出し側は保持役の mnt ns へ入っている間にだけ呼ぶ（`clone_from_holder`）。
fn clone_in_holder(expected: (u64, u64)) -> Result<OwnedFd, ExecError> {
    let src = sys::open_dir_path_nofollow(None, POD_SHM_PATH).map_err(|_| {
        ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            "the pod /dev/shm cannot be opened in the holder mount namespace",
        )
    })?;
    if dev_ino(src.as_fd())? != expected {
        return Err(mismatch(
            "the pod /dev/shm in the holder mount namespace is not the expected tmpfs",
        ));
    }
    check_tmpfs_attrs(src.as_fd())?;
    let verified = sys::verify_bind_source_fd(src)
        .map_err(|_| internal("the pod /dev/shm is not a directory"))?;
    let clone = sys::open_tree_clone_bind(&verified, MountTreeScope::MountOnly)
        .map_err(|e| ExecError::from_sys(e, STAGE, "open_tree(pod /dev/shm)"))?;
    // 複製が元と同じ実体・属性であることを、載せる前にも確かめる（複製の取り違えを載せない）。
    if dev_ino(clone.as_fd())? != expected {
        return Err(mismatch(
            "the cloned pod /dev/shm is not the expected tmpfs",
        ));
    }
    check_tmpfs_attrs(clone.as_fd())?;
    Ok(clone)
}

/// 保持役の mount namespace（`mnt_ns`）へ入って pod の `/dev/shm` を複製し、自分の mount namespace へ戻る。
///
/// 戻り値は切り離したマウントの fd（まだどこにも接続していない）。モジュール doc の手順と不変条件のとおり。戻れなかったとき
/// は、以降のパス操作をせずにエラーを返す（呼び出し元の init は破棄される）。
pub(crate) fn clone_from_holder(
    mnt_ns: BorrowedFd<'_>,
    expected: (u64, u64),
) -> Result<OwnedFd, ExecError> {
    let open_here = |path: &std::ffi::CStr| {
        sys::open_dir_path_nofollow(None, path)
            .map_err(|e| ExecError::from_sys(e, STAGE, "open a directory before the round trip"))
    };
    let own_ns = sys::open_ns_file(c"/proc/thread-self/ns/mnt")
        .map_err(|e| ExecError::from_sys(e, STAGE, "open the own mount namespace"))?;
    let root_before = open_here(c"/")?;
    let cwd_before = open_here(c".")?;
    let root_id_before = (
        dev_ino(root_before.as_fd())?,
        fd_mount_id(&root_before, STAGE)?,
    );
    sys::setns_fd(mnt_ns, NsFlag::Mount).map_err(|e| match e {
        sys::SysError::Os(errno) if errno == sys::EPERM => {
            denied("permission denied to join the holder mount namespace")
        }
        other => ExecError::from_sys(other, STAGE, "setns(holder mount namespace)"),
    })?;
    // 保持役の ns に居る間の結果。失敗でも必ず戻ってから返す。
    let cloned = clone_in_holder(expected);
    // 戻れなければ、パスが別の木に解決される状態のまま何もしない（固定文言で終える）。
    sys::setns_fd(own_ns.as_fd(), NsFlag::Mount).map_err(|_| {
        internal("failed to return to the own mount namespace after cloning the pod /dev/shm")
    })?;
    let cloned = cloned?;
    let root_after = open_here(c"/")?;
    if (
        dev_ino(root_after.as_fd())?,
        fd_mount_id(&root_after, STAGE)?,
    ) != root_id_before
    {
        return Err(internal(
            "the root directory changed during the pod /dev/shm round trip",
        ));
    }
    sys::change_dir_fd(cwd_before.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "restore the working directory"))?;
    Ok(cloned)
}

/// 複製した `/dev/shm` を rootfs（新しい mount top）の `dev/shm` へ載せ、載せた後に素性・属性・伝播を再照合する。
fn attach(root: BorrowedFd<'_>, cloned: OwnedFd, expected: (u64, u64)) -> Result<(), ExecError> {
    let rootfs = root_display(root);
    let names = [OsStr::new("dev"), OsStr::new("shm")];
    let subject = names.iter().fold(rootfs.clone(), |p, n| p.join(n));
    // `dev` は `create_default_devices` が載せた tmpfs の中なので、作るのはその中だけ（ホストの rootfs へ書かない）。
    let dir = open_chain(root, &rootfs, &names, Some(&mut Vec::new()))?;
    let shared = |violation| ExecError::from_violation_at(violation, Some(&subject), STAGE);
    if mount_is_shared(&dir, STAGE)? {
        return Err(shared(ViolationReason::TargetOnSharedMount));
    }
    if !fd_still_at(&dir, &subject) {
        return Err(shared(ViolationReason::TargetMoved));
    }
    sys::move_mount_empty_path(cloned.as_fd(), dir.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "move_mount(pod /dev/shm)"))?;
    verify_mounted(root, &rootfs, &names, "/dev/shm", &dir, &cloned)?;
    // 載せた先の最上位が、期待する tmpfs の複製のままで、ホストへ伝播しないこと。
    let top = open_chain(root, &rootfs, &names, None)?;
    if dev_ino(top.as_fd())? != expected {
        return Err(mismatch(
            "the attached pod /dev/shm is not the expected tmpfs",
        ));
    }
    check_tmpfs_attrs(top.as_fd())?;
    if mount_is_shared(&top, STAGE)? {
        return Err(shared(ViolationReason::TargetOnSharedMount));
    }
    Ok(())
}

/// pod の共有 `/dev/shm` を rootfs の `dev/shm` へ載せる（`create_default_devices` の後・`mount_tmpfs` の前。モジュール doc）。
///
/// `isolation` の証跡が現在の状態と一致しなければ副作用なしに拒否する。`devices` は同じ rootfs の `create_default_devices` の
/// 結果で、`dev` が今もその tmpfs であることを確かめてから何かを作る（先に載せると `/dev` の tmpfs に覆い隠される）。
pub(super) fn mount_pod_shm(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    devices: &DeviceReport,
    setup: PodShmSetup<'_>,
) -> Result<(), ExecError> {
    isolation.verify_caller(STAGE)?;
    // `/dev/shm` は `/dev` 配下の宛先のため、tmpfs と同じ順序の証跡で強制する（既定の `/dev/shm` の件で `check_dev_order` を呼ぶ）。
    let mut order = TmpfsMountSet::new();
    order
        .ensure_default_dev_shm()
        .map_err(|_| internal("failed to prepare the /dev order check for the pod /dev/shm"))?;
    check_dev_order(prepared.new_root(), &order, Some(devices))?;
    let cloned = clone_from_holder(setup.mnt_ns, setup.expected)?;
    attach(prepared.new_root(), cloned, setup.expected)
}
