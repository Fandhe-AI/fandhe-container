//! rootfs の `/sys` への読み取り専用の sysfs の供給（TASK-29 追補・#2020・SEC-2・OCI-4・CORE-1）。
//!
//! # 役割と呼び出し文脈
//!
//! `mounts[]` の `{"destination":"/sys","type":"sysfs"}` を検証済みの [`SysfsMountSpec`] に変えたもの
//! （`oci_runtime::start` が検証し、本番 launcher が `PrePivotSetup::sysfs` へ渡す）を、pivot 前段の
//! `run_pre_pivot` が「`verify_pinned` の直後・`create_default_devices` の前」で適用する。procfs を
//! `prepare_rootfs` が `rootfs/proc` に載せるのと対の位置で、`readonly_paths`（`/sys` の再帰 ro bind）より前に
//! 載せるため、その保護は本段が載せたマウントの上に重なる（#2005 の順序）。
//!
//! ```text
//! prepare_rootfs -> verify_pinned -> mount_sysfs(&isolation, &prepared, &spec) -> create_default_devices
//!   -> ... -> readonly_paths -> masked_paths -> pivot_root
//! ```
//!
//! 本関数の成功の証跡（[`SysfsReport`]）は `run_pre_pivot` が保持して `masked_paths` 段へ渡す。証跡を受けた構成でだけ、
//! `masked_paths` が `/sys/devices/virtual/powercap`・`/sys/firmware`・`/sys/devices/system/cpu/cpuN/thermal_throttle`
//! （存在するもの）を読み取り専用の空 tmpfs で覆う（#2014）。覆いは本段の事後検証（`check_sysfs_tree`）より後に載る。
//!
//! # 供給方式（事前に決める。縮退しない）
//!
//! 呼び出しスレッドの user namespace が初期 namespace かどうか（`/proc/thread-self/ns/user` の inode が
//! `USER_NS_INIT_INO` か）で、[`select_sysfs_source`] が方式を**事前に**決める。
//!
//! | 方式 | 条件 | 動作 |
//! | -- | -- | -- |
//! | [`SysfsSource::Fresh`] | 初期 user namespace（ホスト root。試験経路） | 新しい sysfs を `ro,nosuid,nodev,noexec` で `mount(2)` |
//! | [`SysfsSource::HostReadOnlyRbind`] | それ以外（rootless。本番の `start` 経路は常にここ） | ホストの `/sys` を再帰 bind し、切り離したまま再帰で `ro,noexec`（`nosuid`・`nodev` は常時）を付けてから載せる |
//!
//! 新しい sysfs の `mount(2)` は、その network namespace を所有する user namespace の `CAP_SYS_ADMIN` を要する。
//! コンテナは自前の network namespace を持たない（`start` が `network` namespace を `UNIMPLEMENTED` で拒否）ため、
//! user namespace の中では新しい sysfs を載せられない。結果で選ぶ縮退（`EPERM` で rbind へ移る）は、想定外の拒否
//! （LSM 等）を隠すため採らない。選んだ方式が失敗したら、もう一方へは移らず失敗で止める（fail-closed）。
//! コンテナ自身の network namespace を作れるようになったら、user namespace の中でも新しい sysfs を載せる選び方へ
//! 見直す（将来仕様。REPAIR-3）。
//!
//! # 契約
//!
//! - **fd 起点**: [`PreparedRootfs`] の新しい mount top の fd から `sys` を `O_PATH|O_DIRECTORY|O_NOFOLLOW` で開く。
//!   rootfs の `sys` は作らない（無い・symlink・非ディレクトリは `path_missing`・`path_symlink_or_not_directory` の
//!   違反記録つきで拒否。procfs と同じ「自動作成しない」契約）。宛先は常に `/sys` で、利用者由来の文字列は
//!   `mount(2)` に渡らない（source・fstype は静的、data は NULL）
//! - **ホストへ伝播させない**: マウント直前に宛先のマウントが shared でないことを確かめる
//! - **属性を付けてから見せる**: rbind は切り離した複製に属性を付けてから載せる（属性の無い状態をコンテナへ見せない）
//! - **事後条件**: 載せた後に `sys` を開き直し、そのマウントが sysfs で、`/sys` とその配下のすべてのマウントが
//!   `ro,nosuid,nodev,noexec` であることを mountinfo で確かめる（[`check_sysfs_tree`]）。満たさなければ
//!   `FailedPrecondition`。rbind はホストの `/sys` 配下のマウント（cgroup2・securityfs・bpf 等）を持ち込むため、
//!   その一つでも rw なら起動しない。`exec::setns` の「コンテナの中から cgroupfs に書けない」前提はこの再帰 ro と
//!   `CAP_SYS_ADMIN` の削減・seccomp の mount 系の拒否に支えられる
//! - **rbind の最上位の ro は user namespace の root から外せる（ホステッド runner での観測。#2305・#2789）**:
//!   `platform-ci`（ubuntu-latest。GitHub ホステッド runner、イメージ ubuntu-24.04・20261012.334.1、カーネルは同イメージの
//!   リリースノートの `6.17.0-1022-azure`。一次の記録は CI の step summary の `kernel:` 行）の初回（PR #2781・run 40271388345）で、
//!   ホストの `/sys` が rw のとき、防御なし（全 capability・seccomp なし）の `mount_setattr(attr_clr=MOUNT_ATTR_RDONLY)` は
//!   最上位の ro を外せた（`ro_clear_errno=0`・`top_ro_after_clear=false`）。複製に後から付けた ro には `MNT_LOCK_READONLY` が立たない。
//!   子マウント 19 件は ro のまま（`children_ro_after_clear=true`。再帰では外していない）。外した後の書き込み用 `open` は
//!   観測した 4 パスで `EACCES` だったが、これはホストの root 所有ファイルの DAC によるもので、ro の代わりになる保証ではない。
//!   防御あり（組み込みの `CapabilityDrop`・`Seccomp` 段の通過後）は `EPERM` で拒否された（`ro_clear_defended_errno=1`）。
//!   観測はホステッド runner の 1 回分で、一般化しない。rootful 経路と別カーネルの実測は #2305・#1621（人間担当）に残る。
//!   ro をロックさせる緩和策は別判断で、ここでは行わない
//! - **/sys の ro を保つ前提**: コンテナ内から最上位の ro が外されないことは次の 2 つだけに依存する。(1) CapabilityDrop の
//!   許可集合に `CAP_SYS_ADMIN` が無いこと（`ContainerCapabilities` は OCI 既定の部分集合だけを表し add の経路が無い）、
//!   (2) 既定の seccomp が `mount_setattr` と mount 系（`mount`・`umount2`・`open_tree`・`move_mount`・`fsopen`・`fsconfig`・
//!   `fsmount`・`fspick`）を `ERRNO(EPERM)`（supervisor 経路は `USER_NOTIF` で `-EPERM`）で拒否すること。両段は
//!   `StagePipeline` の組み込みの固定段でフックでは差し替えられない。前提を固定する試験（名前のみ記す）:
//!   `seccomp` の `bpf_tests::sec2_sysfs_ro_premise_native_filter_denies_mount_family_with_eperm`、
//!   `capabilities` の `tests::sec2_sysfs_ro_premise_default_caps_lack_sys_admin`・`tests::sec1_oci_default_mask_matches_docker_capeff`・
//!   `tests::sec1_container_capabilities_restrict_only_subsets`、`exec/stages.rs` の `core1_empty_pipeline_applies_builtin_stages`
//! - **前提の崩れの検出（CI）**: `tests/sysfs_mount.rs` の `ro-clear` シナリオは `platform-ci`（ubuntu）で成功行
//!   `… defended errno=1 (root=false)` を照合する。防御ありの試行が `EPERM` 以外になれば試験自身と CI の成功行の照合が失敗し、
//!   capability 集合や seccomp の変更・段の順序の崩れを実カーネルで検出する。防御なしの値は測定値のため assert しない
//!   （手順は `docs/verification/rootless-sysfs-readonly.md`）
//! - **失敗時**: 後始末の umount はしない。呼び出し側はプロセスを破棄する（`crate::exec` のモジュール doc の契約）
//! - **同一スレッド**: `MountIsolation::establish` と同じスレッドで呼ぶ
//!
//! # runc・moby との差（未確認を含む）
//!
//! runc は rootless で sysfs を rbind に差し替えると理解しているが、差し替えの条件と縮退の有無は一次資料で確かめきれて
//! いない（REPAIR-3）。本実装は条件を事前に決め、縮退しない点が確実な差である。
//!
//! # 単体テスト
//!
//! 副作用は [`SysfsOps`] に集約し、単体テストは記録つきの差し替えで呼び出し順と値を照合する。実機での挙動は
//! 結合試験 `tests/sysfs_mount.rs`（`-- --ignored`）で確認する。

use std::ffi::CString;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::path::Path;

use crate::oci_runtime::SysfsMountSpec;
use crate::sys::{self, BindMountAttrs, MountTreeScope, SysError};
use crate::traits::types::ErrorCode;

use super::{
    ExecError, IsolationStage, MountIsolation, PreparedRootfs, USER_NS_INIT_INO, ViolationReason,
    fd_mount_id, mount_is_shared, read_thread_mountinfo, thread_ns_link,
};

const STAGE: IsolationStage = IsolationStage::MountSysfs;

/// 宛先の表示用（違反記録の対象。コンテナ内の固定パス）。
const DESTINATION: &str = "/sys";

/// `/sys` の供給方式（[`select_sysfs_source`] が事前に決める）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SysfsSource {
    /// 新しい sysfs を `ro,nosuid,nodev,noexec` でマウントした（初期 user namespace）。
    Fresh,
    /// ホストの `/sys` を再帰 bind し、再帰で読み取り専用にして載せた（user namespace の中）。
    HostReadOnlyRbind,
}

/// [`mount_sysfs`] の成功結果（将来の拡張に備えた非網羅の構造体）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SysfsReport {
    /// 採った供給方式。
    pub source: SysfsSource,
}

/// 呼び出しスレッドの user namespace の inode から供給方式を決める（純関数）。
///
/// 初期 user namespace（`USER_NS_INIT_INO`）なら新しい sysfs、それ以外はホストの `/sys` の読み取り専用 rbind。
pub fn select_sysfs_source(user_ns_inode: u64) -> SysfsSource {
    if user_ns_inode == USER_NS_INIT_INO {
        SysfsSource::Fresh
    } else {
        SysfsSource::HostReadOnlyRbind
    }
}

/// [`probe_clear_sysfs_readonly_for_test`] の前提検査（純関数）: PID 1 で、user namespace の inode が読め、かつ
/// 供給方式が [`SysfsSource::HostReadOnlyRbind`] になる（初期 user namespace ではない）こと。
#[cfg(feature = "escape-probe")]
fn clear_probe_precondition(pid: u32, user_ns_inode: Option<u64>) -> bool {
    pid == 1
        && user_ns_inode
            .is_some_and(|ino| select_sysfs_source(ino) == SysfsSource::HostReadOnlyRbind)
}

/// 試験専用: コンテナ内の `/sys` の最上位のマウントから、`mount_setattr` で ro を外せるかを試して結果を返す
/// （SEC-2・SEC-1・#2305 の P2-1 の測定）。
///
/// 呼び出し元は結合試験 `tests/sysfs_mount.rs` の `ro-clear` シナリオ（防御なしの測定は `StageKind::CgroupJoin` のフック、
/// 防御ありの測定は組み込みの制限段の通過後のクロージャ）。通常ビルドには含まれず（`escape-probe` feature 限定）、`#[doc(hidden)]`。
///
/// fail-closed の前提検査: PID 1 で、かつ rbind 経路の user namespace（初期 user namespace ではない）でなければ syscall を
/// 発行せず `FailedPrecondition` を返す。ホスト root の初期 user namespace で `/sys` の ro を外す経路を作らないための検査で、
/// 防御なしの測定のため `Seccomp: 2` は要求しない。対象は `O_PATH|O_DIRECTORY|O_NOFOLLOW` で開いた `/sys` の fd で、
/// mount 系の syscall にパス文字列は渡さない。外せた場合の変更は呼び出したコンテナの mount namespace 内の複製マウントに限り、
/// 子の終了で消える（ホストの `/sys` は変わらない）。
///
/// # 将来仕様（記録のみ）
///
/// 測定後に廃止するか、恒久的な試験へ置き換える（REPAIR-3）。ただし `platform-ci` の `ro-clear` 照合
/// （`defended errno=1`）が /sys の ro を保つ前提（`CAP_SYS_ADMIN` の削減・seccomp の mount 系の拒否）の継続検出に
/// 使われている（#2533・#2789）。廃止・置き換えは、その検出役を別の試験へ移してから行う。
#[cfg(feature = "escape-probe")]
#[doc(hidden)]
pub fn probe_clear_sysfs_readonly_for_test() -> Result<super::seccomp::ProbeOutcome, ExecError> {
    let inode = thread_ns_link("user")
        .ok()
        .and_then(|l| parse_user_ns_inode(&l));
    if !clear_probe_precondition(std::process::id(), inode) {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            "probe_clear_sysfs_readonly_for_test must run as PID 1 in a non-initial user namespace",
        ));
    }
    let sys_dir = sys::open_dir_path_nofollow(None, c"/sys")
        .map_err(|e| ExecError::from_sys(e, STAGE, "open /sys for the ro-clear probe"))?;
    Ok(super::seccomp::ProbeOutcome::from_result(
        sys::clear_mount_read_only_probe(sys_dir.as_fd()),
    ))
}

/// `/proc/thread-self/ns/user` のリンク先（`user:[inode]`）の inode。書式に反すれば `None`。
fn parse_user_ns_inode(link: &str) -> Option<u64> {
    link.strip_prefix("user:[")?.strip_suffix(']')?.parse().ok()
}

/// 副作用の差し込み点（本番は実 syscall、単体テストは記録つき）。
trait SysfsOps {
    /// 呼び出しスレッドの user namespace の inode。
    fn user_ns_inode(&self) -> Result<u64, ExecError>;
    /// 宛先のマウントが shared propagation か。
    fn is_shared(&self, dir: &OwnedFd) -> Result<bool, ExecError>;
    /// 新しい sysfs を宛先へ載せる。
    fn mount_fresh(&self, dir: &OwnedFd) -> Result<(), ExecError>;
    /// ホストの `/sys` の再帰 ro bind を宛先へ載せる。
    fn mount_rbind(&self, dir: &OwnedFd) -> Result<(), ExecError>;
    /// 載せた後の `sys`（開き直したもの）が事後条件を満たすか。
    fn verify_mounted(&self, reopened: &OwnedFd) -> Result<(), ExecError>;
}

/// 本番の差し込み先。
struct RealOps;

impl SysfsOps for RealOps {
    fn user_ns_inode(&self) -> Result<u64, ExecError> {
        let link = thread_ns_link("user").map_err(|_| {
            ExecError::new(
                ErrorCode::FailedPrecondition,
                STAGE,
                "cannot read /proc/thread-self/ns/user",
            )
        })?;
        parse_user_ns_inode(&link).ok_or_else(|| {
            ExecError::new(
                ErrorCode::FailedPrecondition,
                STAGE,
                "unexpected format of /proc/thread-self/ns/user",
            )
        })
    }

    fn is_shared(&self, dir: &OwnedFd) -> Result<bool, ExecError> {
        mount_is_shared(dir, STAGE)
    }

    fn mount_fresh(&self, dir: &OwnedFd) -> Result<(), ExecError> {
        // fd が指す実体へマウントする（`/proc/thread-self/fd/N` は fd の dentry へ解決される。数値だけから組む）。
        let target =
            CString::new(format!("/proc/thread-self/fd/{}", dir.as_raw_fd())).map_err(|_| {
                ExecError::new(
                    ErrorCode::Internal,
                    STAGE,
                    "failed to build the fd path of the sysfs mount target",
                )
            })?;
        sys::mount_sysfs_at(&target).map_err(|e| ExecError::from_sys(e, STAGE, "mount(sysfs)"))
    }

    fn mount_rbind(&self, dir: &OwnedFd) -> Result<(), ExecError> {
        let sys_err = |what: &'static str| move |e: SysError| ExecError::from_sys(e, STAGE, what);
        let host = sys::verify_host_sysfs_fd().map_err(sys_err("open(host /sys)"))?;
        let tree =
            sys::open_tree_clone_host_sysfs(&host).map_err(sys_err("open_tree(host /sys)"))?;
        // 切り離したまま属性を付ける（nosuid・nodev は常時）。`attr_clr` の入口は無く、ロック済みの属性は外さない。
        sys::set_bind_mount_attrs(
            tree.as_fd(),
            BindMountAttrs {
                read_only: true,
                noexec: true,
            },
            MountTreeScope::Recursive,
        )
        .map_err(sys_err("mount_setattr(host /sys)"))?;
        sys::move_mount_empty_path(tree.as_fd(), dir.as_fd())
            .map_err(sys_err("move_mount(host /sys)"))
    }

    fn verify_mounted(&self, reopened: &OwnedFd) -> Result<(), ExecError> {
        let mnt_id = fd_mount_id(reopened, STAGE)?;
        let info = read_thread_mountinfo(STAGE)?;
        check_sysfs_tree(&info, mnt_id)
            .map_err(|msg| ExecError::new(ErrorCode::FailedPrecondition, STAGE, msg))
    }
}

/// rootfs の `/sys` に読み取り専用の sysfs を供給する（`mounts[]` の sysfs。モジュール doc 参照）。
///
/// `isolation` は [`MountIsolation::establish`] の証跡、`prepared` は [`super::prepare_rootfs`] の結果。
/// 失敗した場合、呼び出し側はプロセスを破棄する（後始末の umount はしない）。
pub fn mount_sysfs(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    spec: &SysfsMountSpec,
) -> Result<SysfsReport, ExecError> {
    isolation.verify_caller(STAGE)?;
    mount_sysfs_with(&RealOps, prepared.new_root(), spec)
}

/// [`mount_sysfs`] の証跡検証後の本体（単体テストは証跡を偽造せず、差し替えた [`SysfsOps`] で呼ぶ）。
fn mount_sysfs_with<O: SysfsOps>(
    ops: &O,
    new_root: BorrowedFd<'_>,
    spec: &SysfsMountSpec,
) -> Result<SysfsReport, ExecError> {
    // 区間の末尾で一度だけ `SysfsApplyFailed` を付け、状態 pipe で親へ届けて監査へ記録させる（SEC-4・#2020）。
    // 対象の検査の拒否（symlink・shared 等）は既に自分の理由を持つため上書きしない。
    mount_sysfs_inner(ops, new_root, spec).map_err(|e| {
        e.or_violation(
            ViolationReason::SysfsApplyFailed,
            Some(Path::new(DESTINATION)),
        )
    })
}

fn mount_sysfs_inner<O: SysfsOps>(
    ops: &O,
    new_root: BorrowedFd<'_>,
    spec: &SysfsMountSpec,
) -> Result<SysfsReport, ExecError> {
    // 型が `ro,nosuid,nodev,noexec` を常に真にする。外す入口は無いが、不変条件を明示して退行を検出する。
    debug_assert!(spec.read_only() && spec.nosuid() && spec.nodev() && spec.noexec());
    let source = select_sysfs_source(ops.user_ns_inode()?);
    let dir = open_sys_dir(new_root)?;
    if ops.is_shared(&dir)? {
        return Err(ExecError::from_violation_at(
            ViolationReason::TargetOnSharedMount,
            Some(Path::new(DESTINATION)),
            STAGE,
        ));
    }
    match source {
        SysfsSource::Fresh => ops.mount_fresh(&dir)?,
        SysfsSource::HostReadOnlyRbind => ops.mount_rbind(&dir)?,
    }
    // 載せた後に同じ要素を開き直す（マウントを越えて新しいマウントの top に着地する）。固定後に名前の位置が
    // 差し替えられていれば、開き直した先は sysfs でなく事後条件で拒否される。
    let reopened = open_sys_dir(new_root)?;
    ops.verify_mounted(&reopened)?;
    Ok(SysfsReport { source })
}

/// `new_root` 直下の `sys` を `O_PATH|O_DIRECTORY|O_NOFOLLOW` で開く（作成しない）。
fn open_sys_dir(new_root: BorrowedFd<'_>) -> Result<OwnedFd, ExecError> {
    sys::open_dir_path_nofollow(Some(new_root), c"sys").map_err(|e| match e {
        // O_DIRECTORY|O_NOFOLLOW では symlink も ENOTDIR になる。ELOOP は念のため残す。
        SysError::Os(sys::ELOOP) | SysError::Os(sys::ENOTDIR) => ExecError::from_violation_at(
            ViolationReason::PathSymlinkOrNotDirectory,
            Some(Path::new(DESTINATION)),
            STAGE,
        ),
        SysError::Os(sys::ENOENT) => ExecError::from_violation_at(
            ViolationReason::PathMissing,
            Some(Path::new(DESTINATION)),
            STAGE,
        ),
        other => ExecError::from_sys(other, STAGE, "openat(sys)"),
    })
}

/// mountinfo の 1 行の必要な部分。
pub(super) struct Entry<'a> {
    pub(super) id: u64,
    /// 親マウントの mount ID（2 列目）。部分木を親子関係で辿るために使う（#2823）。
    pub(super) parent: u64,
    pub(super) options: &'a str,
    pub(super) fstype: &'a str,
}

/// 区切り `-` の前の固定フィールド数（`id parent major:minor root mount_point options`）。
const FIXED_FIELDS: usize = 6;

/// mountinfo の 1 行を解く（`path_masks` の `/sys` 部分木の事後検証と共有。#2233）。
pub(super) fn parse_entry(line: &str) -> Option<Entry<'_>> {
    let fields: Vec<&str> = line.split(' ').collect();
    let sep = fields
        .iter()
        .skip(FIXED_FIELDS)
        .position(|f| *f == "-")?
        .checked_add(FIXED_FIELDS)?;
    Some(Entry {
        id: fields.first()?.parse().ok()?,
        parent: fields.get(1)?.parse().ok()?,
        options: fields.get(5)?,
        fstype: fields.get(sep.checked_add(1)?)?,
    })
}

/// `top_mnt_id` のマウントとその子孫（parent ID で辿る）を、先頭に top を置いて返す（純関数。fail-closed。#2823・SEC-1・CORE-2）。
///
/// マウントポイントのパス文字列の前方一致では、top の下に隠れた同じ点の下側の行や、
/// 隠れた別の木の同じ接頭辞の行まで含めて取り違える。`bind_mounts::subtree_members` と同じく親子関係で降りる。
/// top の不在は `missing`、mount ID の重複は固定の英文で拒否する。反復は行数で頭打ちにし、循環した親 ID でも終わる。
pub(super) fn subtree_entries<'a>(
    entries: &'a [Entry<'a>],
    top_mnt_id: u64,
    missing: &'static str,
) -> Result<Vec<&'a Entry<'a>>, &'static str> {
    let mut tops = entries.iter().filter(|e| e.id == top_mnt_id);
    let top = tops.next().ok_or(missing)?;
    if tops.next().is_some() {
        return Err("duplicate mount ID in /proc/thread-self/mountinfo");
    }
    let mut members: Vec<&Entry<'_>> = vec![top];
    let mut ids = vec![top.id];
    for _ in 0..entries.len() {
        let before = ids.len();
        for e in entries {
            if !ids.contains(&e.id) && ids.contains(&e.parent) {
                ids.push(e.id);
                members.push(e);
            }
        }
        if ids.len() == before {
            break;
        }
    }
    Ok(members)
}

/// 載せた `/sys` の事後条件（純関数。fail-closed）。
///
/// `top_mnt_id` のマウントが sysfs で、その子孫（parent ID で辿る。#2823）を含むすべてのマウントの per-mount options が
/// `ro,nosuid,nodev,noexec` を持つことを確かめる。書式に反する行・該当行なし・同じ mount ID の重複は拒否する。
/// 返す文字列は固定の英文で、mountinfo の値（パス・オプション）を含めない。
fn check_sysfs_tree(info: &str, top_mnt_id: u64) -> Result<(), &'static str> {
    const MALFORMED: &str = "malformed line in /proc/thread-self/mountinfo";
    let mut entries = Vec::new();
    for line in info.lines() {
        entries.push(parse_entry(line).ok_or(MALFORMED)?);
    }
    let members = subtree_entries(
        &entries,
        top_mnt_id,
        "no mount entry found for the sysfs mount",
    )?;
    let top = members
        .first()
        .ok_or("no mount entry found for the sysfs mount")?;
    if top.fstype != "sysfs" {
        return Err("the /sys mount is not a sysfs");
    }
    for e in &members {
        let has = |flag: &str| e.options.split(',').any(|o| o == flag);
        if !(has("ro") && has("nosuid") && has("nodev") && has("noexec")) {
            return Err("a mount under /sys is not ro,nosuid,nodev,noexec");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci_runtime::{OciConfig, parse_config_bytes};
    use std::cell::RefCell;

    /// SEC-2・SEC-1（#2305）: ro を外す試験用入口の前提検査。PID 1 かつ初期でない user namespace のときだけ通る。
    #[cfg(feature = "escape-probe")]
    #[test]
    fn sec2_clear_probe_precondition_requires_pid1_in_non_initial_userns() {
        assert!(clear_probe_precondition(1, Some(USER_NS_INIT_INO + 1)));
        assert!(!clear_probe_precondition(1, Some(USER_NS_INIT_INO)));
        assert!(!clear_probe_precondition(2, Some(USER_NS_INIT_INO + 1)));
        assert!(!clear_probe_precondition(1, None));
    }

    fn spec() -> SysfsMountSpec {
        let v = serde_json::json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "mounts": [{"destination": "/sys", "type": "sysfs", "options": ["ro"]}],
        });
        let cfg: OciConfig = parse_config_bytes(v.to_string().as_bytes()).expect("config");
        SysfsMountSpec::from_mounts(cfg.mounts())
            .expect("valid")
            .expect("present")
    }

    /// 呼び出し順を記録する差し込み。
    struct Fake {
        inode: u64,
        shared: bool,
        verify_fails: bool,
        calls: RefCell<Vec<&'static str>>,
    }

    impl Fake {
        fn new(inode: u64) -> Self {
            Self {
                inode,
                shared: false,
                verify_fails: false,
                calls: RefCell::new(Vec::new()),
            }
        }
        fn log(&self, what: &'static str) {
            self.calls.borrow_mut().push(what);
        }
    }

    impl SysfsOps for Fake {
        fn user_ns_inode(&self) -> Result<u64, ExecError> {
            self.log("user_ns_inode");
            Ok(self.inode)
        }
        fn is_shared(&self, _: &OwnedFd) -> Result<bool, ExecError> {
            self.log("is_shared");
            Ok(self.shared)
        }
        fn mount_fresh(&self, _: &OwnedFd) -> Result<(), ExecError> {
            self.log("mount_fresh");
            Ok(())
        }
        fn mount_rbind(&self, _: &OwnedFd) -> Result<(), ExecError> {
            self.log("mount_rbind");
            Ok(())
        }
        fn verify_mounted(&self, _: &OwnedFd) -> Result<(), ExecError> {
            self.log("verify_mounted");
            if self.verify_fails {
                return Err(ExecError::new(
                    ErrorCode::FailedPrecondition,
                    STAGE,
                    "verify failed",
                ));
            }
            Ok(())
        }
    }

    /// `sys` を持つ一時ディレクトリ（O_PATH で開いた fd を new_root の代わりにする）。
    struct Root {
        dir: std::path::PathBuf,
        fd: OwnedFd,
    }

    impl Root {
        fn new(name: &str, make_sys: impl FnOnce(&Path)) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "fandhe-sysfs-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            // 一意名（PID＋ナノ秒）を `create_dir` で排他的に作り、既存パスを再利用しない（SEC-2）。
            std::fs::create_dir(&dir).expect("mkdir");
            make_sys(&dir);
            let c = CString::new(dir.to_str().expect("utf8")).expect("cstr");
            let fd = sys::open_dir_path_nofollow(None, &c).expect("open root");
            Self { dir, fd }
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn with_sys(dir: &Path) {
        std::fs::create_dir(dir.join("sys")).expect("sys");
    }

    /// SEC-2・OCI-4: 方式の選択は user namespace の inode で決まる（初期 → Fresh、それ以外 → rbind）。
    #[test]
    fn sec2_oci4_select_source_by_user_ns_inode() {
        assert_eq!(select_sysfs_source(0xEFFF_FFFD), SysfsSource::Fresh);
        assert_eq!(select_sysfs_source(4_026_531_837), SysfsSource::Fresh);
        assert_eq!(
            select_sysfs_source(4_026_532_000),
            SysfsSource::HostReadOnlyRbind
        );
        assert_eq!(select_sysfs_source(0), SysfsSource::HostReadOnlyRbind);
        assert_eq!(
            parse_user_ns_inode("user:[4026531837]"),
            Some(4_026_531_837)
        );
        assert_eq!(parse_user_ns_inode("pid:[1]"), None);
        assert_eq!(parse_user_ns_inode("user:[x]"), None);
    }

    /// SEC-2・OCI-4: 初期 user namespace は新しい sysfs のみ（rbind へ移らない）。順序は選択 → 宛先 → shared → 載せる → 検証。
    #[test]
    fn sec2_oci4_fresh_path_order() {
        let root = Root::new("fresh", with_sys);
        let ops = Fake::new(USER_NS_INIT_INO);
        let report = mount_sysfs_with(&ops, root.fd.as_fd(), &spec()).expect("ok");
        assert_eq!(report.source, SysfsSource::Fresh);
        assert_eq!(
            *ops.calls.borrow(),
            [
                "user_ns_inode",
                "is_shared",
                "mount_fresh",
                "verify_mounted"
            ]
        );
    }

    /// SEC-2・OCI-4: user namespace の中はホストの読み取り専用 rbind のみ（新しい sysfs を試さない）。
    #[test]
    fn sec2_oci4_rbind_path_order() {
        let root = Root::new("rbind", with_sys);
        let ops = Fake::new(4_026_532_001);
        let report = mount_sysfs_with(&ops, root.fd.as_fd(), &spec()).expect("ok");
        assert_eq!(report.source, SysfsSource::HostReadOnlyRbind);
        assert_eq!(
            *ops.calls.borrow(),
            [
                "user_ns_inode",
                "is_shared",
                "mount_rbind",
                "verify_mounted"
            ]
        );
    }

    /// SEC-2: 事後条件を満たさなければ失敗で返す（成功を装わない）。
    #[test]
    fn sec2_post_condition_failure_is_reported() {
        let root = Root::new("postfail", with_sys);
        let mut ops = Fake::new(4_026_532_001);
        ops.verify_fails = true;
        let err = mount_sysfs_with(&ops, root.fd.as_fd(), &spec()).expect_err("must fail");
        assert_eq!(
            (err.code, err.stage, err.message.as_str()),
            (
                ErrorCode::FailedPrecondition,
                IsolationStage::MountSysfs,
                "verify failed"
            )
        );
        // 事後検証の失敗は専用の理由で子の状態 pipe 経由の監査へ届く（SEC-4・#2020）。
        let v = err.violation.as_ref().expect("violation");
        assert_eq!(v.reason, ViolationReason::SysfsApplyFailed);
        assert_eq!(v.reason.as_str(), "sysfs_apply_failed");
    }

    /// SEC-1: 宛先が shared のマウント上なら何も載せずに拒否する。
    #[test]
    fn sec1_shared_destination_is_rejected_before_mounting() {
        let root = Root::new("shared", with_sys);
        let mut ops = Fake::new(USER_NS_INIT_INO);
        ops.shared = true;
        let err = mount_sysfs_with(&ops, root.fd.as_fd(), &spec()).expect_err("must fail");
        assert_eq!(err.stage, IsolationStage::MountSysfs);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::TargetOnSharedMount)
        );
        assert_eq!(*ops.calls.borrow(), ["user_ns_inode", "is_shared"]);
    }

    /// SEC-2: `sys` が無い・symlink・非ディレクトリなら、作らず違反記録つきで拒否する（何も載せない）。
    #[test]
    fn sec2_missing_or_non_directory_sys_is_rejected() {
        type Case = (&'static str, fn(&Path), ViolationReason);
        let cases: [Case; 3] = [
            ("missing", |_| {}, ViolationReason::PathMissing),
            (
                "symlink",
                |d| std::os::unix::fs::symlink("/", d.join("sys")).expect("symlink"),
                ViolationReason::PathSymlinkOrNotDirectory,
            ),
            (
                "file",
                |d| std::fs::write(d.join("sys"), b"x").expect("file"),
                ViolationReason::PathSymlinkOrNotDirectory,
            ),
        ];
        for (name, make, reason) in cases {
            let root = Root::new(name, make);
            let ops = Fake::new(USER_NS_INIT_INO);
            let err = mount_sysfs_with(&ops, root.fd.as_fd(), &spec()).expect_err(name);
            assert_eq!(err.stage, IsolationStage::MountSysfs, "{name}");
            assert_eq!(
                err.violation.as_ref().map(|v| v.reason),
                Some(reason),
                "{name}"
            );
            assert_eq!(*ops.calls.borrow(), ["user_ns_inode"], "{name}");
        }
        // 自動作成していない（rootfs に書かない）。
        let root = Root::new("nocreate", |_| {});
        let _ = mount_sysfs_with(&Fake::new(USER_NS_INIT_INO), root.fd.as_fd(), &spec());
        assert!(!root.dir.join("sys").exists());
    }

    fn line(id: u64, mp: &str, opts: &str, fstype: &str) -> String {
        linep(id, 1, mp, opts, fstype)
    }

    fn linep(id: u64, parent: u64, mp: &str, opts: &str, fstype: &str) -> String {
        format!("{id} {parent} 0:5 / {mp} {opts} master:1 - {fstype} {fstype} rw")
    }

    /// SEC-2: 事後条件の判定。配下の 1 件でも rw なら拒否し、最上位が sysfs でなければ拒否する。
    #[test]
    fn sec2_check_sysfs_tree_judges_every_mount_under_sys() {
        let ro = "ro,nosuid,nodev,noexec,relatime";
        let ok = [
            line(10, "/r/sys", ro, "sysfs"),
            linep(11, 10, "/r/sys/fs/cgroup", ro, "cgroup2"),
            line(12, "/r/sysx", "rw,relatime", "tmpfs"),
            line(13, "/r/proc", "rw,nosuid", "proc"),
        ]
        .join("\n");
        assert_eq!(check_sysfs_tree(&ok, 10), Ok(()));
        // 配下の rw は拒否（`/r/sysx` は配下ではないので影響しない）。
        let child_rw = [
            line(10, "/r/sys", ro, "sysfs"),
            linep(
                11,
                10,
                "/r/sys/fs/cgroup",
                "rw,nosuid,nodev,noexec",
                "cgroup2",
            ),
        ]
        .join("\n");
        assert_eq!(
            check_sysfs_tree(&child_rw, 10),
            Err("a mount under /sys is not ro,nosuid,nodev,noexec")
        );
        // 最上位に必須フラグが欠ける。
        for missing in [
            "rw,nosuid,nodev,noexec",
            "ro,nodev,noexec",
            "ro,nosuid,noexec",
            "ro,nosuid,nodev",
        ] {
            assert_eq!(
                check_sysfs_tree(&line(10, "/r/sys", missing, "sysfs"), 10),
                Err("a mount under /sys is not ro,nosuid,nodev,noexec"),
                "{missing}"
            );
        }
        // 最上位が sysfs でない。
        assert_eq!(
            check_sysfs_tree(&line(10, "/r/sys", ro, "tmpfs"), 10),
            Err("the /sys mount is not a sysfs")
        );
        // 該当行なし・重複・壊れた行。
        assert_eq!(
            check_sysfs_tree(&line(10, "/r/sys", ro, "sysfs"), 99),
            Err("no mount entry found for the sysfs mount")
        );
        let dup = [
            line(10, "/r/sys", ro, "sysfs"),
            line(10, "/r/sys", ro, "sysfs"),
        ]
        .join("\n");
        assert_eq!(
            check_sysfs_tree(&dup, 10),
            Err("duplicate mount ID in /proc/thread-self/mountinfo")
        );
        assert_eq!(
            check_sysfs_tree("garbage line", 10),
            Err("malformed line in /proc/thread-self/mountinfo")
        );
    }

    /// SEC-1・CORE-2（#2823）: 隠れた行・別の木の同接頭辞の行は数えず、top の子孫だけを判定する。
    #[test]
    fn sec1_2823_check_sysfs_tree_follows_parent_ids_not_path_prefix() {
        let ro = "ro,nosuid,nodev,noexec";
        let rw = "rw,relatime";
        let hidden = [
            linep(5, 1, "/r/sys", rw, "tmpfs"),
            linep(10, 5, "/r/sys", ro, "sysfs"),
            linep(11, 10, "/r/sys/fs/cgroup", ro, "cgroup2"),
            linep(20, 2, "/r/sys/other", rw, "tmpfs"),
            linep(21, 2, "/r/sysx", rw, "tmpfs"),
        ]
        .join("\n");
        assert_eq!(check_sysfs_tree(&hidden, 10), Ok(()));
        let grand = [
            linep(10, 1, "/r/sys", ro, "sysfs"),
            linep(11, 10, "/r/sys/a", ro, "cgroup2"),
            linep(12, 11, "/r/sys/a/b", rw, "tmpfs"),
        ]
        .join("\n");
        assert_eq!(
            check_sysfs_tree(&grand, 10),
            Err("a mount under /sys is not ro,nosuid,nodev,noexec")
        );
        let cyc = [
            linep(10, 12, "/r/sys", ro, "sysfs"),
            linep(11, 10, "/r/sys/a", ro, "cgroup2"),
            linep(12, 11, "/r/sys/b", ro, "cgroup2"),
        ]
        .join("\n");
        assert_eq!(check_sysfs_tree(&cyc, 10), Ok(()));
    }
}
