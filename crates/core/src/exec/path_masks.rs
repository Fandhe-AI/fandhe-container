//! 読み取り専用にするパスの固定集合を pivot の前に適用する（SEC-2・CORE-1・CORE-5・SEC-5・TASK-29 追補・#1850）。
//!
//! # 役割と呼び出し文脈
//!
//! 対象の定義は [`crate::path_masks`]（`/proc` 配下の 5 件と `/sys`）。本モジュールは適用側で、
//! `process::run_pre_pivot` の `readonly_paths` 段から呼ばれる。ESC-04（`/sys` の `release_agent`）・
//! ESC-05（`/proc/sys`・`/proc/sysrq-trigger`）が前提にする「書き込めない」状態を作る。
//!
//! ```text
//! prepare_rootfs -> (create_default_devices -> mount_tmpfs -> inject_files -> mount_binds) -> apply_readonly_paths -> pivot_root
//! ```
//!
//! **`setup` の有無によらず常に走る**（`inject_files` までは `setup` 指定時のみ）。外す入口は作らない
//! （`PrePivotSetup` にフラグを足さない）。注入などが `/proc`・`/sys` に触れた後に最後に閉じるため、
//! `inject_files` の後・`pivot_root` の前に置く。
//!
//! # 契約
//!
//! - **fd 起点**: `PreparedRootfs` の新しい mount top の fd から 1 要素ずつ `O_PATH|O_NOFOLLOW` で辿る。
//!   途中の要素の symlink・非ディレクトリは違反記録付きで拒否し、パス文字列を再解決しない
//! - **対象の種別**: 許すのはディレクトリと通常ファイルだけ（`/sys` はディレクトリのみ）。symlink などは拒否する
//! - **存在しない対象は飛ばす**: `ENOENT` は件数（`skipped`）に数える。カーネル構成で無い項目がある
//! - **bind と読み取り専用化**: 対象を自分自身へ再帰 bind し（`/proc/thread-self/fd/N` 経由）、保持した親 fd
//!   から同名で開き直した新しい mount top へ `mount_setattr(MOUNT_ATTR_RDONLY)` を掛ける。開き直した fd が bind
//!   対象と同じ `(st_dev, st_ino)` で、マウント ID が変わり、系譜が正しいことを確かめる（本番ビルド）。
//!   `attr_clr` = 0 のため、user namespace でロックされた `nosuid`・`nodev`・`noexec` は落とさない。
//!   未対応カーネル（Linux 5.12 未満）は `unimplemented` で拒否し、`mount(2)` へ縮退しない
//! - **事後条件**: mountinfo の per-mount options に `ro` があることを確かめ、無ければ `FailedPrecondition`
//! - **fail-closed**: 1 件でも失敗したら即 `Err` で、後続は処理しない。呼び出し元（子）はプロセスを破棄する
//!   契約で、失敗時の後始末（umount）はしない（`prepare_rootfs` と同じ）
//! - **順序**: [`crate::path_masks::READONLY_PROC_PATHS`] の並び -> `/sys`
//! - **同一スレッド**: `MountIsolation::establish` と同じスレッドで呼ぶ
//!
//! # Landlock との関係
//!
//! 書き込み禁止は VFS の読み取り専用マウントが担う。`/proc/*` と `/sys` は OCI の `mounts[]` に現れないので、
//! Landlock 側の `WriteRestrictionShadowed` の判定には影響せず、ルールも足さない。Landlock は加算的で、
//! 読み取り専用マウントを緩めることもできない。書き込み open は VFS の読み取り専用マウント検査が Landlock の
//! `file_open` フックより前に走るため `EROFS` が返る見込みだが、実機で確認する（結合試験 `readonly_paths`）。
//!
//! # rootless の注意
//!
//! single-id mapping の user namespace では `/proc/sys/kernel/core_pattern`・`/proc/sysrq-trigger` はホストの
//! root 所有でユーザーに写像されないため、書き込み open は読み取り専用マウントの検査より先にパーミッション検査で
//! `EACCES` になる可能性が高い。rootless の `/proc` 配下は mountinfo の `ro` を主な保証とする。
//!
//! # `/proc`・`/sys` のマウントとの順序（#2005・SEC-2・ESC-04・ESC-05）
//!
//! - procfs は `prepare_rootfs`（`run_pre_pivot` の 2 番目の段）が pivot **前**に `rootfs/proc` へマウント済みで、本段の
//!   再帰 bind と `MOUNT_ATTR_RDONLY` はその procfs の上に新しいマウントを作る。保護は見えている実 procfs に効く
//! - launch 経路では pivot 後に `/proc`・`/sys` へマウントしない（後からマウントすると保護のマウントを覆い隠す）。
//!   コンテナ内のプロセスは seccomp の mount 拒否と `CAP_SYS_ADMIN` の除去で `/proc` を載せ直せない
//! - `mounts[]` の sysfs（`exec::mount_sysfs`。#2020）は `verify_pinned` の直後（本段より前）に載せ済みで、本段の再帰 bind と
//!   `MOUNT_ATTR_RDONLY` はその sysfs（またはホストの `/sys` の rbind）の上に載る。OCI `mounts[]` の proc を受ける場合も、
//!   本段より前に載せなければならない
//! - 順序は `run_pre_pivot` の 1 か所で固定し、単体テスト `core1_run_pre_pivot_order_is_fixed` と、結合試験
//!   `readonly_paths`・`masked_paths` の最上位マウントの照合（親が見えている procfs であること）で検査する
//!
//! # 未実装（REPAIR-3: 実装済みを装わない）
//!
//! - 読み取り専用化の側の `/sys` 配下の個別項目（moby の `ReadonlyPaths` に無い）。`/sys` は mount top だけを読み取り専用にする。
//!   利用者指定の tmpfs・注入ファイル・bind は型の段で `/sys` 配下を拒否し（#2233・SEC-2）、残る子マウント（供給した rbind の子）は
//!   ro 済み。top だけの RDONLY で足りることを、RDONLY 後に部分木の全マウントの `ro` を観測して担保する（無ければ起動を止める）
//!   sysfs の供給は `exec::mount_sysfs`（#2020。`mounts[]` に sysfs がある起動のみ。本段より前に載せる）。`/sys/firmware` 等の
//!   覆いは後段の `masked_paths` が担う（`exec::masked_paths`。#2014）
//! - `/proc` の供給（procfs マウント）。現状は本段より後に procfs をマウントする実装がない。将来 OCI `mounts[]`
//!   等で procfs を `/proc` に載せる場合は、`/sys` と同様に本段より前に載せること（後から載せると読み取り専用の bind が隠れる）
//!
//! 記録の `stage` キー（#3121・SEC-4・ERR-4）: 経路検査の拒否は汎用理由（`path_symlink_or_not_directory` 等）で
//! 記録されるが、親が `ExecError::stage` の段 `mount_readonly_paths` を記録の末尾（`container_id` の後ろ）に載せるため、
//! 記録だけで段が分かる。
//!
//! # 監査（SEC-4）
//!
//! 対象を固定して検査を通った後の、保護を載せる操作（bind・開き直し・新しいマウントの確認・`mount_setattr`・
//! `ro` の観測）の失敗には、違反の理由 `readonly_path_apply_failed`（種別 `protected_path_apply`。`ExecError::code`
//! は errno 由来のまま）を付ける。子は状態 pipe でこの理由を親へ返し、親が層 `mount` の記録を 1 件書く
//! （`exec/launch_status.rs`。`container_id` つき・パスなし。#2013）。環境起因（古いカーネル・LSM）と rootfs の内容
//! 起因を親は区別できず、SEC-4 は記録漏れを許さないため、どちらも記録する（理由トークンは経路検査の拒否と分ける）。
//! 経路検査の拒否（`path_symlink_or_not_directory`・`target_on_shared_mount`・`target_moved`）は既存の汎用理由のまま。
//! マウント前のシステムエラー（`fstat`・`dup`・定義の不正）は違反なしの失敗で、記録しない。`ENOENT` で飛ばす
//! 挙動は変わらない。
//!
//! # 単体テストの安全策
//!
//! bind・`mount_setattr`・事後条件の観測は `cfg(test)` では dry-run に差し替わる（`rootfs.rs` の
//! `bind_syscall` と `inject.rs` の `read_only_syscall` と同じ流儀）。実機での挙動は結合試験
//! `tests/readonly_paths.rs`（`-- --ignored`）で確認する。

use std::ffi::{CStr, CString, OsStr};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use crate::path_masks::{self, ProtectedPath};
use crate::sys::{self, SysError};
use crate::traits::types::ErrorCode;

use super::tmpfs::root_display;
use super::{
    ExecError, IsolationStage, MountIsolation, PreparedRootfs, ViolationReason, fd_mount_id,
    fd_still_at, mount_is_shared, open_error,
};

const STAGE: IsolationStage = IsolationStage::MountReadonlyPaths;

/// [`apply_readonly_paths`] の成功結果（将来の拡張に備えた非網羅の構造体）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) struct ReadonlyPathsReport {
    /// 読み取り専用にして事後検証した対象の件数。
    pub(super) applied: usize,
    /// 存在しないため飛ばした対象の件数。
    pub(super) skipped: usize,
}

/// 1 件の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Applied,
    Skipped,
}

/// 固定集合を `prepared` の mount top 配下に適用する。
///
/// [`MountIsolation`] の証跡が現在の状態と一致しなければ副作用なしに拒否する（fail-closed）。契約はモジュール doc。
pub(super) fn apply_readonly_paths(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    extra: &[ProtectedPath],
) -> Result<ReadonlyPathsReport, ExecError> {
    isolation.verify_caller(STAGE)?;
    apply_at_with(prepared.new_root(), extra)
}

/// 固定集合だけを適用する（単体テスト用の短縮形）。
#[cfg(test)]
fn apply_at(root: BorrowedFd<'_>) -> Result<ReadonlyPathsReport, ExecError> {
    apply_at_with(root, &[])
}

/// [`apply_readonly_paths`] の証跡検証後の本体（単体テストは偽 rootfs の fd を渡す）。
fn apply_at_with(
    root: BorrowedFd<'_>,
    extra: &[ProtectedPath],
) -> Result<ReadonlyPathsReport, ExecError> {
    let rootfs = root_display(root);
    let mut report = ReadonlyPathsReport {
        applied: 0,
        skipped: 0,
    };
    for target in path_masks::readonly_targets(extra) {
        let (path, dir_only) = (target.path, target.dir_only);
        let names = path_masks::components(path).ok_or_else(|| {
            ExecError::new(
                ErrorCode::Internal,
                STAGE,
                format!("the read-only path definition {path} is not canonical"),
            )
        })?;
        match apply_one(root, &rootfs, path, &names, dir_only)? {
            Outcome::Applied => report.applied += 1,
            Outcome::Skipped => report.skipped += 1,
        }
    }
    Ok(report)
}

/// 対象 1 件。`names` は `path` の要素列、`dir_only` が真ならディレクトリだけを許す。
fn apply_one(
    root: BorrowedFd<'_>,
    rootfs: &Path,
    path: &str,
    names: &[&str],
    dir_only: bool,
) -> Result<Outcome, ExecError> {
    let os_names: Vec<&OsStr> = names.iter().map(OsStr::new).collect();
    let subject = os_names.iter().fold(rootfs.to_path_buf(), |p, n| p.join(n));
    let violation = |r: ViolationReason| ExecError::from_violation_at(r, Some(&subject), STAGE);
    let Some((leaf_name, parent_names)) = names.split_last() else {
        return Err(ExecError::new(
            ErrorCode::Internal,
            STAGE,
            "a read-only path definition is empty",
        ));
    };

    // 途中の要素は 1 要素ずつ O_PATH|O_DIRECTORY|O_NOFOLLOW で辿る（不在は飛ばし、symlink・非ディレクトリは拒否）。
    let mut cur: Option<OwnedFd> = None;
    for (i, name) in parent_names.iter().enumerate() {
        let c = c_name(name, path)?;
        let parent = cur.as_ref().map_or(root, |f| f.as_fd());
        match sys::open_dir_path_nofollow(Some(parent), &c) {
            Ok(fd) => cur = Some(fd),
            Err(SysError::Os(sys::ENOENT)) => return Ok(Outcome::Skipped),
            Err(e) => {
                let upto = os_names.get(..=i).unwrap_or(&[]);
                return Err(open_error(e, true, rootfs, upto).at_stage(STAGE));
            }
        }
    }
    let parent = cur.as_ref().map_or(root, |f| f.as_fd());

    let c_leaf = c_name(leaf_name, path)?;
    let leaf = match sys::open_path_nofollow(parent, &c_leaf) {
        Ok(fd) => fd,
        Err(SysError::Os(sys::ENOENT)) => return Ok(Outcome::Skipped),
        Err(e) => return Err(ExecError::from_sys(e, STAGE, &format!("openat({path})"))),
    };
    let leaf_meta = fd_metadata(&leaf, &format!("fstat({path})"))?;
    let kind = leaf_meta.file_type();
    if !(kind.is_dir() || (!dir_only && kind.is_file())) {
        return Err(violation(ViolationReason::PathSymlinkOrNotDirectory));
    }
    if mount_is_shared(&leaf, STAGE)? {
        return Err(violation(ViolationReason::TargetOnSharedMount));
    }
    if !fd_still_at(&leaf, &subject) {
        return Err(violation(ViolationReason::TargetMoved));
    }
    let before_mnt_id = fd_mount_id(&leaf, STAGE)?;

    let target = fd_magic_path(&leaf)?;

    // 対象を固定して検査を通った後の、保護を載せる操作と事後検証。ここでの失敗は違反の理由を持たないため、
    // 区間の末尾で一度だけ `ReadonlyPathApplyFailed` を付ける（既に `target_moved` 等を持つ失敗は上書きしない。
    // 呼び出し点の取りこぼしを防ぐ。SEC-4・#2013）。
    let apply = || -> Result<Outcome, ExecError> {
        bind_syscall(&target)
            .map_err(|e| ExecError::from_sys(e, STAGE, &format!("mount(MS_BIND on {path})")))?;

        // bind 前に得た fd は下層の dentry を指す。保持した親 fd から同名で開き直し、新しい mount top を得る。
        let reopened = sys::open_path_nofollow(parent, &c_leaf)
            .map_err(|e| ExecError::from_sys(e, STAGE, &format!("openat({path}) after bind")))?;
        let reopened_meta = fd_metadata(&reopened, &format!("fstat({path}) after bind"))?;
        if (leaf_meta.dev(), leaf_meta.ino()) != (reopened_meta.dev(), reopened_meta.ino()) {
            return Err(violation(ViolationReason::TargetMoved));
        }
        check_new_mount(&reopened, before_mnt_id, &violation)?;

        read_only_syscall(reopened.as_fd()).map_err(|e| {
            ExecError::from_sys(
                e,
                STAGE,
                &format!("mount_setattr(MOUNT_ATTR_RDONLY on {path})"),
            )
        })?;
        if !observe_read_only(&reopened)? {
            return Err(ExecError::new(
                ErrorCode::FailedPrecondition,
                STAGE,
                format!("the mount at {path} is not read-only after mount_setattr"),
            ));
        }
        if path == path_masks::READONLY_SYS_PATH && !observe_subtree_read_only(&reopened)? {
            return Err(ExecError::new(
                ErrorCode::FailedPrecondition,
                STAGE,
                format!("a mount under {path} is not read-only after mount_setattr"),
            ));
        }
        Ok(Outcome::Applied)
    };
    apply().map_err(|e| e.or_violation(ViolationReason::ReadonlyPathApplyFailed, Some(&subject)))
}

/// 要素名を NUL 終端文字列にする（定義は定数のため NUL を含まないが、`unwrap` を避けて拒否する）。
fn c_name(name: &str, path: &str) -> Result<CString, ExecError> {
    CString::new(name).map_err(|_| {
        ExecError::new(
            ErrorCode::Internal,
            STAGE,
            format!("the read-only path definition {path} contains NUL"),
        )
    })
}

/// fd を指す `/proc/thread-self/fd/N`（bind 先に使う magic link。パス文字列を再解決しない）。
fn fd_magic_path(fd: &OwnedFd) -> Result<CString, ExecError> {
    CString::new(format!("/proc/thread-self/fd/{}", fd.as_raw_fd())).map_err(|_| {
        ExecError::new(
            ErrorCode::Internal,
            STAGE,
            "failed to build the fd path of a read-only target",
        )
    })
}

/// `O_PATH` fd でも取れる `fstat`（fd は消費しない）。
fn fd_metadata(fd: &OwnedFd, what: &str) -> Result<std::fs::Metadata, ExecError> {
    let dup = fd
        .try_clone()
        .map_err(|e| ExecError::from_io(&e, STAGE, "dup"))?;
    std::fs::File::from(dup)
        .metadata()
        .map_err(|e| ExecError::from_io(&e, STAGE, what))
}

/// bind が新しいマウントを作ったこと（マウント ID が変わり、系譜が正しいこと）の確認。
///
/// `cfg(test)` の dry-run では bind が作られないため省略する（`prepare_rootfs` と同じ）。
#[cfg(not(test))]
fn check_new_mount(
    reopened: &OwnedFd,
    before_mnt_id: u64,
    violation: &dyn Fn(ViolationReason) -> ExecError,
) -> Result<(), ExecError> {
    let new_mnt_id = fd_mount_id(reopened, STAGE)?;
    if new_mnt_id == before_mnt_id {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            "the read-only path bind mount did not create a new mount",
        ));
    }
    let info = super::read_thread_mountinfo(STAGE)?;
    if !super::rootfs::bind_lineage_ok(&info, before_mnt_id, new_mnt_id) {
        return Err(violation(ViolationReason::TargetMoved));
    }
    Ok(())
}

/// dry-run: 何も確認しない。
#[cfg(test)]
fn check_new_mount(
    _reopened: &OwnedFd,
    _before_mnt_id: u64,
    _violation: &dyn Fn(ViolationReason) -> ExecError,
) -> Result<(), ExecError> {
    Ok(())
}

/// 対象の自己 bind（`MS_BIND | MS_REC`）。本番ビルドでは [`sys::bind_mount_recursive`]。
#[cfg(not(test))]
fn bind_syscall(target: &CStr) -> Result<(), SysError> {
    sys::bind_mount_recursive(target)
}

/// dry-run: `mount(2)` を呼ばず、bind 対象の実体（fd のリンク先）を記録するだけにする。
#[cfg(test)]
fn bind_syscall(target: &CStr) -> Result<(), SysError> {
    if let Some(e) = tests::BIND_FAIL.with(|f| f.take()) {
        return Err(e);
    }
    let resolved = std::fs::read_link(target.to_string_lossy().as_ref())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    tests::EVENTS.with(|e| e.borrow_mut().push(("bind", resolved)));
    Ok(())
}

/// 開き直した mount top のマウントを fd 起点で読み取り専用にする。本番ビルドでは [`sys::set_mount_read_only`]。
#[cfg(not(test))]
fn read_only_syscall(mount_top: BorrowedFd<'_>) -> Result<(), SysError> {
    sys::set_mount_read_only(mount_top)
}

/// dry-run: `mount_setattr(2)` を呼ばず、対象の実体を記録する。故障注入は `RO_FAIL`。
#[cfg(test)]
fn read_only_syscall(mount_top: BorrowedFd<'_>) -> Result<(), SysError> {
    if let Some(e) = tests::RO_FAIL.with(|f| f.take()) {
        return Err(e);
    }
    let resolved = std::fs::read_link(format!("/proc/thread-self/fd/{}", mount_top.as_raw_fd()))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    tests::EVENTS.with(|e| e.borrow_mut().push(("ro", resolved)));
    Ok(())
}

/// `dir` が属するマウントが読み取り専用かを観測する（mountinfo の per-mount options の `ro`）。
#[cfg(not(test))]
fn observe_read_only(dir: &OwnedFd) -> Result<bool, ExecError> {
    let mnt_id = fd_mount_id(dir, STAGE)?;
    let info = super::read_thread_mountinfo(STAGE)?;
    super::mount_is_read_only_in(&info, mnt_id).map_err(|e| e.at_stage(STAGE))
}

/// `dir`（`/sys` の新しい mount top）とその配下のすべてのマウントが読み取り専用かを観測する（#2233・SEC-2）。
///
/// top だけに RDONLY を掛けても、先に載った子マウントは rw のまま残る。利用者の tmpfs・注入・bind は
/// 型の段で `/sys` 配下を拒否するが、別経路が足されても pivot 前に検出するための多層防御。
#[cfg(not(test))]
fn observe_subtree_read_only(dir: &OwnedFd) -> Result<bool, ExecError> {
    let mnt_id = fd_mount_id(dir, STAGE)?;
    let info = super::read_thread_mountinfo(STAGE)?;
    match check_subtree_read_only(&info, mnt_id) {
        Ok(()) => Ok(true),
        Err(SUBTREE_RW) => Ok(false),
        Err(m) => Err(ExecError::new(ErrorCode::FailedPrecondition, STAGE, m)),
    }
}

/// dry-run: 実マウントが無いため、`FORCE_RW` でなければ読み取り専用とみなす。
#[cfg(test)]
fn observe_subtree_read_only(_dir: &OwnedFd) -> Result<bool, ExecError> {
    Ok(!tests::FORCE_RW.with(|c| c.get()))
}

/// 部分木に `ro` の無いマウントがあるときの固定文言。
const SUBTREE_RW: &str = "a mount under the target has no ro option";

/// `top_mnt_id` のマウントとそのマウントポイント以下の全マウントに `ro` があるかの判定（純関数。fail-closed）。
///
/// 書式に反する行・top の不在・mount ID の重複は拒否する。配下は parent ID で辿るため、前方一致だけの兄弟（`/sysx`）や隠れた行は数えない（#2823・SEC-1・CORE-2）。
/// 返す文字列は固定の英文で mountinfo の値を含めない。
fn check_subtree_read_only(info: &str, top_mnt_id: u64) -> Result<(), &'static str> {
    let mut entries = Vec::new();
    for line in info.lines() {
        entries.push(
            super::sysfs::parse_entry(line)
                .ok_or("malformed line in /proc/thread-self/mountinfo")?,
        );
    }
    let members =
        super::sysfs::subtree_entries(&entries, top_mnt_id, "no mount entry found for the mount")?;
    for e in members {
        if !e.options.split(',').any(|o| o == "ro") {
            return Err(SUBTREE_RW);
        }
    }
    Ok(())
}

/// dry-run: 実マウントが無いため、既定は読み取り専用を観測したことにする（失敗経路は `FORCE_RW` で作る）。
#[cfg(test)]
fn observe_read_only(_dir: &OwnedFd) -> Result<bool, ExecError> {
    Ok(!tests::FORCE_RW.with(|c| c.get()))
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::os::unix::fs::symlink;

    use super::super::tmpfs::tests::Tmp;
    use super::*;
    use crate::exec::tests::override_shared;

    thread_local! {
        /// dry-run が記録した `("bind" | "ro", 実体のパス)`（テストスレッドごと）。
        pub(super) static EVENTS: RefCell<Vec<(&'static str, String)>> =
            const { RefCell::new(Vec::new()) };
        /// 次の `bind_syscall` に返させる失敗。
        pub(super) static BIND_FAIL: Cell<Option<SysError>> = const { Cell::new(None) };
        /// 次の `read_only_syscall` に返させる失敗（未対応カーネル等の注入用）。
        pub(super) static RO_FAIL: Cell<Option<SysError>> = const { Cell::new(None) };
        /// `observe_read_only` に読み取り専用でないと観測させる。
        pub(super) static FORCE_RW: Cell<bool> = const { Cell::new(false) };
    }

    fn reset() {
        EVENTS.with(|e| e.borrow_mut().clear());
        BIND_FAIL.with(|f| f.set(None));
        RO_FAIL.with(|f| f.set(None));
        FORCE_RW.with(|f| f.set(false));
    }

    fn take_events() -> Vec<(&'static str, String)> {
        EVENTS.with(|e| std::mem::take(&mut *e.borrow_mut()))
    }

    /// 全対象が存在する偽 rootfs。
    fn full_rootfs(tag: &str) -> Tmp {
        let tmp = Tmp::new(tag);
        for d in ["proc/bus", "proc/fs", "proc/irq", "proc/sys", "sys"] {
            std::fs::create_dir_all(tmp.0.join(d)).expect("mkdir");
        }
        std::fs::write(tmp.0.join("proc/sysrq-trigger"), b"").expect("file");
        tmp
    }

    fn pair(tmp: &Tmp, kind: &'static str, rel: &str) -> (&'static str, String) {
        (kind, tmp.0.join(rel).to_string_lossy().into_owned())
    }

    /// SEC-2・CORE-5（#1850）: 5 件と `/sys` が定義順に bind され、直後に読み取り専用にされる。
    #[test]
    fn sec2_applies_all_six_targets_in_order_bind_then_read_only() {
        reset();
        let _shared = override_shared(false);
        let tmp = full_rootfs("ro-all");
        let fd = tmp.fd();
        let report = apply_at(fd.as_fd()).expect("apply");
        assert_eq!(report.applied, 6);
        assert_eq!(report.skipped, 0);
        let mut want = Vec::new();
        for rel in [
            "proc/bus",
            "proc/fs",
            "proc/irq",
            "proc/sys",
            "proc/sysrq-trigger",
            "sys",
        ] {
            want.push(pair(&tmp, "bind", rel));
            want.push(pair(&tmp, "ro", rel));
        }
        assert_eq!(take_events(), want);
    }

    /// SEC-2（#1852）: config 由来の対象は固定集合の後ろに処理され、不在は飛ばされ、固定集合との重複は 1 度だけ。
    #[test]
    fn sec2_config_targets_follow_fixed_set_and_missing_are_skipped() {
        reset();
        let _shared = override_shared(false);
        let tmp = full_rootfs("ro-extra");
        std::fs::create_dir_all(tmp.0.join("data/x")).expect("mkdir");
        let fd = tmp.fd();
        let extra: Vec<ProtectedPath> = ["/data/x", "/absent", "/proc/sys", "/data/x/"]
            .iter()
            .map(|p| ProtectedPath::parse(p, 4096).expect("valid"))
            .collect();
        let report = apply_at_with(fd.as_fd(), &extra).expect("apply");
        assert_eq!((report.applied, report.skipped), (7, 1));
        let events = take_events();
        assert_eq!(events.len(), 14);
        assert_eq!(events[10], pair(&tmp, "bind", "sys"));
        assert_eq!(
            &events[12..],
            &[pair(&tmp, "bind", "data/x"), pair(&tmp, "ro", "data/x")]
        );
    }

    /// SEC-2（#1850）: 存在しない対象は飛ばされ、件数が報告される。
    #[test]
    fn sec2_missing_targets_are_skipped_and_counted() {
        reset();
        let _shared = override_shared(false);
        let tmp = Tmp::new("ro-missing");
        std::fs::create_dir_all(tmp.0.join("proc/sys")).expect("mkdir");
        let fd = tmp.fd();
        let report = apply_at(fd.as_fd()).expect("apply");
        assert_eq!(report.applied, 1);
        assert_eq!(report.skipped, 5);
        assert_eq!(
            take_events(),
            vec![pair(&tmp, "bind", "proc/sys"), pair(&tmp, "ro", "proc/sys")]
        );
        // 親の `proc` が無い構成でも全件を飛ばして成功する。
        reset();
        let empty = Tmp::new("ro-empty");
        let fd = empty.fd();
        let report = apply_at(fd.as_fd()).expect("apply empty");
        assert_eq!((report.applied, report.skipped), (0, 6));
        assert_eq!(take_events(), vec![]);
    }

    /// SEC-2（#1850）: 対象が symlink なら拒否し、後続の対象は処理されない。
    #[test]
    fn sec2_symlink_target_is_rejected_and_stops_later_targets() {
        reset();
        let _shared = override_shared(false);
        let tmp = full_rootfs("ro-symlink");
        std::fs::remove_dir(tmp.0.join("proc/irq")).expect("rm");
        symlink("/etc", tmp.0.join("proc/irq")).expect("symlink");
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd()).expect_err("symlink");
        assert_eq!(err.stage, IsolationStage::MountReadonlyPaths);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathSymlinkOrNotDirectory)
        );
        // 先行の 2 件（bus・fs）は処理済みで、irq 以降は処理されない。
        assert_eq!(
            take_events(),
            vec![
                pair(&tmp, "bind", "proc/bus"),
                pair(&tmp, "ro", "proc/bus"),
                pair(&tmp, "bind", "proc/fs"),
                pair(&tmp, "ro", "proc/fs"),
            ]
        );
    }

    /// SEC-2（#1850）: `/sys` が symlink、または通常ファイルのときは拒否する。途中の `proc` が symlink でも拒否する。
    #[test]
    fn sec2_sys_symlink_or_file_and_proc_symlink_are_rejected() {
        let _shared = override_shared(false);
        reset();
        let tmp = full_rootfs("ro-sys-link");
        std::fs::remove_dir(tmp.0.join("sys")).expect("rm");
        symlink("/sys", tmp.0.join("sys")).expect("symlink");
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd()).expect_err("sys symlink");
        assert_eq!(err.stage, IsolationStage::MountReadonlyPaths);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathSymlinkOrNotDirectory)
        );

        reset();
        let tmp = full_rootfs("ro-sys-file");
        std::fs::remove_dir(tmp.0.join("sys")).expect("rm");
        std::fs::write(tmp.0.join("sys"), b"").expect("file");
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd()).expect_err("sys file");
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathSymlinkOrNotDirectory)
        );

        reset();
        let tmp = Tmp::new("ro-proc-link");
        symlink("/proc", tmp.0.join("proc")).expect("symlink");
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd()).expect_err("proc symlink");
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathSymlinkOrNotDirectory)
        );
        assert_eq!(take_events(), vec![]);
    }

    /// SEC-2（#1850）: shared propagation 上の対象は bind する前に拒否する。
    #[test]
    fn sec2_shared_mount_target_is_rejected_before_bind() {
        reset();
        let _shared = override_shared(true);
        let tmp = full_rootfs("ro-shared");
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd()).expect_err("shared");
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::TargetOnSharedMount)
        );
        assert_eq!(err.stage, IsolationStage::MountReadonlyPaths);
        assert_eq!(take_events(), vec![]);
    }

    /// SEC-2（#1850）: bind の失敗は `MountReadonlyPaths` 段のエラーで、以降の対象は処理されない。
    #[test]
    fn sec2_bind_failure_is_fail_closed() {
        reset();
        let _shared = override_shared(false);
        let tmp = full_rootfs("ro-bind-fail");
        BIND_FAIL.with(|f| f.set(Some(SysError::Os(sys::EINVAL))));
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd()).expect_err("bind");
        assert_eq!(err.stage, IsolationStage::MountReadonlyPaths);
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(
            err.message
                .starts_with("mount(MS_BIND on /proc/bus) failed")
        );
        assert_eq!(take_events(), vec![]);
    }

    /// SEC-2（#1850）: 読み取り専用化の失敗（未対応カーネル）は `unimplemented` で拒否し、縮退しない。
    #[test]
    fn sec2_read_only_failure_is_unimplemented_and_stops() {
        reset();
        let _shared = override_shared(false);
        let tmp = full_rootfs("ro-ro-fail");
        RO_FAIL.with(|f| f.set(Some(SysError::Unsupported)));
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd()).expect_err("ro");
        assert_eq!(err.stage, IsolationStage::MountReadonlyPaths);
        assert_eq!(err.code, ErrorCode::Unimplemented);
        assert!(
            err.message
                .starts_with("mount_setattr(MOUNT_ATTR_RDONLY on /proc/bus) failed")
        );
        // bind は済んでいるが、後続の対象は処理されない。
        assert_eq!(take_events(), vec![pair(&tmp, "bind", "proc/bus")]);
    }

    /// 子の失敗を状態 pipe の往復で親へ運び、層 `mount` の記録 1 件（パスなし・`container_id` つき）を照合する。
    /// 戻り値は `(親が復元した ExecError, 記録の理由)`。
    fn relay_and_record(err: &ExecError) -> (ExecError, Option<String>) {
        use crate::audit_log::mount::tests::VecSink;
        use crate::audit_log::{AuditDelivery, AuditLayer};
        use crate::exec::launch_status::{LaunchAudit, PrePivotStep, relay_failure_for_test};
        use crate::traits::ContainerId;

        let sink = VecSink::new(false);
        let id = ContainerId::new("c1").expect("id");
        let out = relay_failure_for_test(
            PrePivotStep::ReadonlyPaths,
            err,
            LaunchAudit {
                sink: &sink,
                container: Some(&id),
            },
        )
        .expect_err("rejected");
        let recs = sink.snapshot();
        if out.delivery == AuditDelivery::NotApplicable {
            assert_eq!(recs.len(), 0);
            return (out.error, None);
        }
        assert_eq!(out.delivery, AuditDelivery::Recorded);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].layer(), AuditLayer::Mount);
        assert_eq!(recs[0].path(), None);
        assert_eq!(recs[0].container_id().map(ContainerId::as_str), Some("c1"));
        // #3121: 汎用理由でも記録だけで段が分かる。
        assert_eq!(
            recs[0].stage().map(|s| s.as_str()),
            Some("mount_readonly_paths")
        );
        let reason = recs[0].reason().map(|r| r.as_str().to_string());
        (out.error, reason)
    }

    /// SEC-4・SEC-2（#2013）: bind の失敗・読み取り専用化の失敗（未対応カーネル）・事後条件の失敗のそれぞれに
    /// `readonly_path_apply_failed` が付き、`code`・`stage`・`message` は従来のまま。状態 pipe の往復を経て親で
    /// 層 `mount` の記録 1 件になり、`ErrorCode` も保たれる。
    #[test]
    fn sec4_2013_apply_failures_carry_reason_and_reach_the_audit_record() {
        for (case, code) in [
            ("bind", ErrorCode::FailedPrecondition),
            ("ro", ErrorCode::Unimplemented),
            ("post", ErrorCode::FailedPrecondition),
        ] {
            reset();
            let _shared = override_shared(false);
            let tmp = full_rootfs("ro-apply-audit");
            match case {
                "bind" => BIND_FAIL.with(|f| f.set(Some(SysError::Os(sys::EINVAL)))),
                "ro" => RO_FAIL.with(|f| f.set(Some(SysError::Unsupported))),
                _ => FORCE_RW.with(|f| f.set(true)),
            }
            let fd = tmp.fd();
            let err = apply_at(fd.as_fd()).expect_err(case);
            assert_eq!(err.code, code, "{case}");
            assert_eq!(err.stage, IsolationStage::MountReadonlyPaths, "{case}");
            assert_eq!(
                err.violation.as_ref().map(|v| v.reason),
                Some(ViolationReason::ReadonlyPathApplyFailed),
                "{case}"
            );
            let (restored, reason) = relay_and_record(&err);
            assert_eq!(
                reason.as_deref(),
                Some("readonly_path_apply_failed"),
                "{case}"
            );
            assert_eq!(restored.code, code, "{case}");
            assert_eq!(restored.stage, IsolationStage::MountReadonlyPaths);
            assert_eq!(
                restored.message,
                "failed to apply a read-only path protection"
            );
        }
    }

    /// SEC-4・SEC-2（#2013）: `config.json` 由来の対象（固定集合が不在の rootfs に `/data/x` だけを置く）の
    /// 適用失敗も同じ理由で記録され、メッセージに対象のパスが出る。
    #[test]
    fn sec4_2013_config_target_apply_failure_is_recorded() {
        reset();
        let _shared = override_shared(false);
        let tmp = Tmp::new("ro-extra-audit");
        std::fs::create_dir_all(tmp.0.join("data/x")).expect("mkdir");
        BIND_FAIL.with(|f| f.set(Some(SysError::Os(sys::EINVAL))));
        let extra = [ProtectedPath::parse("/data/x", 4096).expect("valid")];
        let fd = tmp.fd();
        let err = apply_at_with(fd.as_fd(), &extra).expect_err("bind");
        assert!(
            err.message.starts_with("mount(MS_BIND on /data/x) failed"),
            "{}",
            err.message
        );
        let (_, reason) = relay_and_record(&err);
        assert_eq!(reason.as_deref(), Some("readonly_path_apply_failed"));
    }

    /// SEC-4（#2013）: 経路検査の拒否（symlink）は既存の汎用理由のまま記録され、適用失敗の理由に置き換わらない。
    #[test]
    fn sec4_2013_path_check_rejection_keeps_generic_reason() {
        reset();
        let _shared = override_shared(false);
        let tmp = full_rootfs("ro-symlink-audit");
        std::fs::remove_dir(tmp.0.join("proc/irq")).expect("rm");
        symlink("/etc", tmp.0.join("proc/irq")).expect("symlink");
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd()).expect_err("symlink");
        let (restored, reason) = relay_and_record(&err);
        assert_eq!(reason.as_deref(), Some("path_symlink_or_not_directory"));
        assert_eq!(restored.stage, IsolationStage::MountReadonlyPaths);
    }

    /// SEC-2（#1850）: 事後条件（読み取り専用が観測できない）の失敗は `FailedPrecondition`。
    #[test]
    fn sec2_postcondition_failure_is_failed_precondition() {
        reset();
        let _shared = override_shared(false);
        let tmp = full_rootfs("ro-post");
        FORCE_RW.with(|f| f.set(true));
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd()).expect_err("post");
        assert_eq!(err.stage, IsolationStage::MountReadonlyPaths);
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message,
            "the mount at /proc/bus is not read-only after mount_setattr"
        );
        assert_eq!(take_events().len(), 2);
    }

    /// mountinfo の 1 行（id parent dev root mp opts - fstype src super）。
    fn mi(id: u64, mp: &str, opts: &str) -> String {
        mip(id, 1, mp, opts)
    }

    /// 親 mount ID を指定できる `mi`。
    fn mip(id: u64, parent: u64, mp: &str, opts: &str) -> String {
        format!("{id} {parent} 0:1 / {mp} {opts} - sysfs sysfs rw\n")
    }

    /// SEC-2・#2233: top だけ ro で子が rw の部分木は拒否し、全部 ro なら通す。
    #[test]
    fn sec2_subtree_read_only_check() {
        let all_ro = [
            mi(10, "/sys", "ro,nosuid"),
            mip(11, 10, "/sys/fs/cgroup", "ro"),
        ]
        .concat();
        assert_eq!(check_subtree_read_only(&all_ro, 10), Ok(()));
        let child_rw = [mi(10, "/sys", "ro"), mip(11, 10, "/sys/x", "rw,nosuid")].concat();
        assert_eq!(check_subtree_read_only(&child_rw, 10), Err(SUBTREE_RW));
        // 前方一致だけの兄弟 /sysx は部分木に数えない。
        let sibling = [mi(10, "/sys", "ro"), mi(11, "/sysx", "rw")].concat();
        assert_eq!(check_subtree_read_only(&sibling, 10), Ok(()));
        assert_eq!(
            check_subtree_read_only(&all_ro, 99),
            Err("no mount entry found for the mount")
        );
        let dup = [mi(10, "/sys", "ro"), mi(10, "/sys", "ro")].concat();
        assert_eq!(
            check_subtree_read_only(&dup, 10),
            Err("duplicate mount ID in /proc/thread-self/mountinfo")
        );
        assert_eq!(
            check_subtree_read_only("garbage\n", 10),
            Err("malformed line in /proc/thread-self/mountinfo")
        );
    }

    /// SEC-1・CORE-2（#2823）: 隠れた下側の行・別の木の同接頭辞の行は数えず、子孫の rw は拒否する。
    #[test]
    fn sec2_2823_subtree_read_only_follows_parent_ids() {
        let hidden = [
            mip(5, 1, "/sys", "rw"),
            mip(10, 5, "/sys", "ro"),
            mip(11, 10, "/sys/a", "ro"),
            mip(20, 2, "/sys/other", "rw"),
        ]
        .concat();
        assert_eq!(check_subtree_read_only(&hidden, 10), Ok(()));
        let grand = [
            mip(10, 1, "/sys", "ro"),
            mip(11, 10, "/sys/a", "ro"),
            mip(12, 11, "/sys/a/b", "rw"),
        ]
        .concat();
        assert_eq!(check_subtree_read_only(&grand, 10), Err(SUBTREE_RW));
    }
}
