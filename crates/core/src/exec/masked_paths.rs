//! 覆うパスの固定集合を pivot の前に適用する（SEC-2・CORE-1・CORE-5・SEC-5・TASK-29 追補・#1851）。
//!
//! # 役割と呼び出し文脈
//!
//! 対象の定義は [`crate::path_masks`]（`/proc` 配下の 10 件。`/proc/kcore`・`/proc/keys`・`/proc/sched_debug` 等）。
//! 本モジュールは適用側で、`process::run_pre_pivot` の `masked_paths` 段から呼ばれる。OCI の `linux.maskedPaths`
//! 相当を、`config.json` に関係なく常に適用する固定集合にする（オーナー判断 2026-10-12・#1315）。
//!
//! ```text
//! prepare_rootfs -> create_default_devices -> (mount_tmpfs -> inject_files)
//!   -> apply_readonly_paths -> apply_masked_paths -> pivot_root
//! ```
//!
//! # 覆い方
//!
//! - **ファイル**: 検証済みの `/dev/null`（[`NullNodeSource`]。`create_default_devices` が載せた `/dev` の tmpfs のノードを
//!   fd 起点で開き、`fstat` で文字デバイス 1:3 と確かめた fd）を `open_tree`（`AT_RECURSIVE` なし）で 1 ノード複製し、
//!   `move_mount` で対象の上に載せる。ホストの `/dev/null` をパスで開き直さない。複製は `/dev` の tmpfs のマウント属性を
//!   継承する。**`nodev` を足してはならない**（付けるとノードを開けず `EACCES` になる）。`nosuid`・`noexec` を足さない理由は
//!   `sys::open_tree_clone` の方針（文字デバイス 1 個で exec・setuid の対象にならない）に従う。デバイスノードの bind には
//!   `mount_setattr` を掛けない（#1676）
//! - **ディレクトリ**: 読み取り専用・`nosuid`・`nodev`・`noexec` の空 tmpfs（モード 0755・4 KiB）を載せる。`ro` は作成時に
//!   fsconfig と属性の両方で付くため、`set_mount_read_only` は使わない
//! - 通常ファイル・ディレクトリ以外（symlink・デバイス等）は覆わず違反記録付きで拒否する
//!
//! # 順序
//!
//! `readonly_paths` の後・`pivot_root` の前に置く。読み取り専用化は対象を再帰 bind（`MS_REC`）するため、先に覆うと
//! 複製した子マウントに `ro` が付かない（`set_mount_read_only` は再帰しない）。現在の 2 つの集合は互いに素だが、
//! 将来 `/proc/sys` 配下に覆う項目が入っても壊れないよう「読み取り専用化 -> 覆う」の順にする。覆いのマウントは
//! tmpfs が作成時に `ro` を持つので後から掛けても失われない。`/dev` が載っている必要があるため
//! `create_default_devices` より後である。順序は `run_pre_pivot` の 1 か所に固定し、外す入口は作らない。
//!
//! procfs は `prepare_rootfs` が pivot 前に `rootfs/proc` へマウント済みで、覆いはその実 procfs の上に載る（#2005・SEC-2）。
//! pivot 後に `/proc` へマウントし直すと覆いが隠れるため行わない。`mounts[]` の sysfs（`exec::mount_sysfs`。#2020）も本段より前に載せる。
//!
//! # `setup` なしの最小構成では適用しない
//!
//! 検証済みの `/dev/null` は `create_default_devices` が作るため、`setup`（`PrePivotSetup`）指定時にだけ存在する。
//! 本番の起動経路（`IntermediateSpec.setup` は `Option` でない）は常に `setup` を渡すので、型で「本番では常に適用」が
//! 保証される。`spawn_container*` の `setup = None` の最小構成は専用 `/dev` が無く、ファイルの覆いに使える検証済みの
//! ノードが無いため、段を飛ばす（ディレクトリだけ覆う部分適用は「実装済みを装わない」に反し、ホストの `/dev/null` を
//! パスで開く案は禁止）。`escape_suite` は `setup` なしのため影響を受けない。固定集合つきの入口への切り替えは #1853。
//!
//! # 契約
//!
//! - **fd 起点**: `PreparedRootfs` の新しい mount top の fd から 1 要素ずつ `O_PATH|O_NOFOLLOW` で辿る。途中の要素の
//!   symlink・非ディレクトリは違反記録付きで拒否し、パス文字列を再解決しない
//! - **存在しない対象は飛ばす**: `ENOENT` は件数（`skipped`）に数える（カーネル構成で無い項目がある）
//! - **ホストへ伝播させない**: 対象が shared propagation の上にある、または固定後に移動していれば、載せる前に拒否する
//! - **事後条件**: 開き直した対象が新しいマウントで、自分のマウントそのものであること（ファイルは文字デバイス 1:3、
//!   ディレクトリは tmpfs で mountinfo に `ro`・`nosuid`・`nodev`・`noexec`）を確かめる
//! - **fail-closed**: 1 件でも失敗したら即 `Err` で、後続は処理しない。失敗時の後始末（umount）はしない
//!   （呼び出し元の子はプロセスごと破棄する契約。`apply_readonly_paths`・`prepare_rootfs` と同じ）。未対応カーネル
//!   （Linux 5.2 未満）は `mount(2)` へ縮退せず `Unimplemented`
//! - **同一スレッド**: `MountIsolation::establish` と同じスレッドで呼ぶ。seccomp の適用前に呼ぶ
//!
//! # Landlock との関係
//!
//! 覆いは VFS のマウントで、Landlock のルールを足さない（`exec::path_masks` と同じ）。
//!
//! # 未実装（REPAIR-3: 実装済みを装わない）
//!
//! - `/sys` 配下の項目（`/sys/firmware` 等）。`/sys` 配下の覆いは #2014 で扱う（sysfs の供給は #2020 で実装済み）
//! - 記録に段のフィールドを足すこと: 経路検査の拒否は汎用理由で記録され、記録の理由だけでは段が分からない
//!   （段は返る `ExecError::stage` に載る）。段のフィールドは #653（TASK-98.2）の共通ログ型の範囲
//!
//! # 監査（SEC-4）
//!
//! 対象を固定して検査を通った後の、覆いを載せる操作（`open_tree`・`move_mount`・tmpfs のマウント・開き直し・事後検証）
//! の失敗には、違反の理由 `masked_path_apply_failed`（種別 `protected_path_apply`。`ExecError::code` は errno 由来の
//! まま）を付ける。子は状態 pipe でこの理由を親へ返し、親が層 `mount` の記録を 1 件書く（`exec/launch_status.rs`。
//! `container_id` つき・パスなし。#2013）。環境起因と rootfs の内容起因を親は区別できず、SEC-4 は記録漏れを許さない
//! ため、どちらも記録する。経路検査の拒否と `check_bound_null` の `target_moved` は既存の汎用理由のまま。マウント前の
//! システムエラーは違反なしの失敗で、記録しない。
//!
//! # 単体テストの安全策
//!
//! `open_tree`・`move_mount`・tmpfs のマウントと事後条件の観測は `cfg(test)` では dry-run に差し替わる。実機での挙動は
//! 結合試験 `tests/masked_paths.rs`（`-- --ignored`）で確認する。

use std::ffi::{CString, OsStr};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;

use crate::path_masks::{self, MaskMethod, ProtectedPath, TargetKind};
use crate::sys::{self, SysError};
use crate::traits::types::ErrorCode;

use super::devices::NullNodeSource;
use super::tmpfs::{MountObservation, check_new_tmpfs, root_display};
use super::{
    ExecError, IsolationStage, MountIsolation, PreparedRootfs, ViolationReason, fd_mount_id,
    fd_still_at, mount_is_shared, open_error,
};

const STAGE: IsolationStage = IsolationStage::MountMaskedPaths;

/// 覆い用 tmpfs のルートのモード。
const MASK_TMPFS_MODE: u32 = 0o755;
/// 覆い用 tmpfs のサイズ（バイト。読み取り専用で書けないため最小の 1 ページ）。
const MASK_TMPFS_SIZE: u64 = 4096;

/// 覆い用 tmpfs の作成パラメータ（読み取り専用・`noexec`。`nosuid`・`nodev` は型が常時付与する）。
const MASK_TMPFS: sys::TmpfsCreate = sys::TmpfsCreate {
    mode: MASK_TMPFS_MODE,
    size: Some(MASK_TMPFS_SIZE),
    flags: sys::TmpfsMountFlags {
        read_only: true,
        exec: false,
    },
};

/// 覆い用 tmpfs の mountinfo に必須の per-mount options。
const MASK_TMPFS_OPTIONS: [&str; 4] = ["ro", "nosuid", "nodev", "noexec"];

/// [`apply_masked_paths`] の成功結果（将来の拡張に備えた非網羅の構造体）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) struct MaskedPathsReport {
    /// 覆って事後検証した対象の件数。
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
pub(super) fn apply_masked_paths(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    null: &NullNodeSource,
    extra: &[ProtectedPath],
) -> Result<MaskedPathsReport, ExecError> {
    isolation.verify_caller(STAGE)?;
    apply_at_with(prepared.new_root(), null, extra)
}

/// 固定集合だけを適用する（単体テスト用の短縮形）。
#[cfg(test)]
fn apply_at(root: BorrowedFd<'_>, null: &NullNodeSource) -> Result<MaskedPathsReport, ExecError> {
    apply_at_with(root, null, &[])
}

/// [`apply_masked_paths`] の証跡検証後の本体（単体テストは偽 rootfs の fd を渡す）。
fn apply_at_with(
    root: BorrowedFd<'_>,
    null: &NullNodeSource,
    extra: &[ProtectedPath],
) -> Result<MaskedPathsReport, ExecError> {
    let rootfs = root_display(root);
    let mut report = MaskedPathsReport {
        applied: 0,
        skipped: 0,
    };
    for path in path_masks::masked_targets(extra) {
        let names = path_masks::components(path).ok_or_else(|| {
            ExecError::new(
                ErrorCode::Internal,
                STAGE,
                format!("the masked path definition {path} is not canonical"),
            )
        })?;
        match apply_one(root, &rootfs, path, &names, null)? {
            Outcome::Applied => report.applied += 1,
            Outcome::Skipped => report.skipped += 1,
        }
    }
    Ok(report)
}

/// 対象 1 件。`names` は `path` の要素列。
fn apply_one(
    root: BorrowedFd<'_>,
    rootfs: &Path,
    path: &str,
    names: &[&str],
    null: &NullNodeSource,
) -> Result<Outcome, ExecError> {
    let os_names: Vec<&OsStr> = names.iter().map(OsStr::new).collect();
    let subject = os_names.iter().fold(rootfs.to_path_buf(), |p, n| p.join(n));
    let violation = |r: ViolationReason| ExecError::from_violation_at(r, Some(&subject), STAGE);
    let Some((leaf_name, parent_names)) = names.split_last() else {
        return Err(ExecError::new(
            ErrorCode::Internal,
            STAGE,
            "a masked path definition is empty",
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
    let Some(method) = path_masks::mask_method(target_kind(&leaf_meta)) else {
        return Err(violation(ViolationReason::PathSymlinkOrNotDirectory));
    };
    if mount_is_shared(&leaf, STAGE)? {
        return Err(violation(ViolationReason::TargetOnSharedMount));
    }
    if !fd_still_at(&leaf, &subject) {
        return Err(violation(ViolationReason::TargetMoved));
    }
    let before_mnt_id = fd_mount_id(&leaf, STAGE)?;

    // 対象を固定して検査を通った後の、覆いを載せる操作と事後検証。ここでの失敗は違反の理由を持たないため、
    // 一度だけ `MaskedPathApplyFailed` を付ける（`check_bound_null` の `target_moved` 等は上書きしない。SEC-4・#2013）。
    let applied = match method {
        MaskMethod::BindDevNull => bind_dev_null(
            parent,
            &c_leaf,
            &leaf,
            before_mnt_id,
            path,
            null,
            &violation,
        ),
        MaskMethod::EmptyTmpfs => mount_empty_tmpfs(parent, &c_leaf, &leaf, before_mnt_id, path),
    };
    applied.map_err(|e| e.or_violation(ViolationReason::MaskedPathApplyFailed, Some(&subject)))?;
    Ok(Outcome::Applied)
}

/// `fstat` の種別を [`TargetKind`] に写す。
fn target_kind(meta: &std::fs::Metadata) -> TargetKind {
    let ft = meta.file_type();
    if ft.is_dir() {
        TargetKind::Dir
    } else if ft.is_file() {
        TargetKind::File
    } else {
        TargetKind::Other
    }
}

/// ファイルの対象に検証済みの `/dev/null` の複製を載せ、開き直して事後検証する。
fn bind_dev_null(
    parent: BorrowedFd<'_>,
    c_leaf: &CString,
    leaf: &OwnedFd,
    before_mnt_id: u64,
    path: &str,
    null: &NullNodeSource,
    violation: &dyn Fn(ViolationReason) -> ExecError,
) -> Result<(), ExecError> {
    // 複製は 1 ノードにつき 1 回（`move_mount` が消費するため使い回さない）。
    let tree = clone_null_syscall(null).map_err(|e| bind_api_error(e, "open_tree", path))?;
    move_mount_syscall(tree.as_fd(), leaf.as_fd(), path)
        .map_err(|e| bind_api_error(e, "move_mount", path))?;
    let reopened = sys::open_path_nofollow(parent, c_leaf)
        .map_err(|e| ExecError::from_sys(e, STAGE, &format!("openat({path}) after mask")))?;
    check_bound_null(&reopened, &tree, before_mnt_id, path, violation)
}

/// ディレクトリの対象に読み取り専用の空 tmpfs を載せ、開き直して事後検証する。
fn mount_empty_tmpfs(
    parent: BorrowedFd<'_>,
    c_leaf: &CString,
    leaf: &OwnedFd,
    before_mnt_id: u64,
    path: &str,
) -> Result<(), ExecError> {
    let mount_fd = super::tmpfs::mount_tmpfs_syscall(leaf.as_fd(), MASK_TMPFS)
        .map_err(|e| ExecError::from_sys(e, STAGE, &format!("mount(tmpfs on {path})")))?;
    let after = sys::open_dir_path_nofollow(Some(parent), c_leaf)
        .map_err(|e| ExecError::from_sys(e, STAGE, &format!("openat({path}) after mask")))?;
    let observed = observe_tmpfs(before_mnt_id, &after, &mount_fd)?;
    check_new_tmpfs(observed, path, STAGE)?;
    let options_ok = observe_options(&after, &MASK_TMPFS_OPTIONS)?;
    if !options_ok {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!("the tmpfs at {path} does not have ro,nosuid,nodev,noexec after mount"),
        ));
    }
    Ok(())
}

/// `open_tree`・`move_mount` の失敗をエラーにする。`Unsupported`（`ENOSYS`）は縮退せず `Unimplemented`。
fn bind_api_error(e: SysError, op: &str, path: &str) -> ExecError {
    if matches!(e, SysError::Unsupported) {
        return ExecError::new(
            ErrorCode::Unimplemented,
            STAGE,
            "masking a file requires the new mount API (open_tree, move_mount; Linux 5.2 or later)",
        );
    }
    ExecError::from_sys(e, STAGE, &format!("{op}({path})"))
}

/// 要素名を NUL 終端文字列にする（定義は定数のため NUL を含まないが、`unwrap` を避けて拒否する）。
fn c_name(name: &str, path: &str) -> Result<CString, ExecError> {
    CString::new(name).map_err(|_| {
        ExecError::new(
            ErrorCode::Internal,
            STAGE,
            format!("the masked path definition {path} contains NUL"),
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

/// `info`（mountinfo）の `mnt_id` の行の per-mount options に `required` がすべて含まれるか（純関数）。
///
/// 書式に反する行・該当行なし・同じ ID の行が複数ある場合はエラー（fail-closed）。
fn mount_has_options(info: &str, mnt_id: u64, required: &[&str]) -> Result<bool, ExecError> {
    let malformed = || {
        ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            "malformed line in /proc/thread-self/mountinfo",
        )
    };
    let mut found: Option<bool> = None;
    for line in info.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let id: u64 = fields
            .first()
            .and_then(|f| f.parse().ok())
            .ok_or_else(malformed)?;
        if id != mnt_id {
            continue;
        }
        if found.is_some() {
            return Err(ExecError::new(
                ErrorCode::FailedPrecondition,
                STAGE,
                "duplicate mount ID in /proc/thread-self/mountinfo",
            ));
        }
        let options = fields.get(5).ok_or_else(malformed)?;
        let have: Vec<&str> = options.split(',').collect();
        found = Some(required.iter().all(|r| have.contains(r)));
    }
    found.ok_or_else(|| {
        ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            "no mount entry found for the masked path",
        )
    })
}

/// 開き直した対象が属するマウントの per-mount options に `required` がすべてあるかを観測する。
#[cfg(not(test))]
fn observe_options(dir: &OwnedFd, required: &[&str]) -> Result<bool, ExecError> {
    let mnt_id = fd_mount_id(dir, STAGE)?;
    let info = super::read_thread_mountinfo(STAGE)?;
    mount_has_options(&info, mnt_id, required)
}

/// dry-run: 実マウントが無いため、既定は満たしたことにする（失敗経路は `FORCE_BAD_OPTIONS` で作る）。
#[cfg(test)]
fn observe_options(_dir: &OwnedFd, _required: &[&str]) -> Result<bool, ExecError> {
    Ok(!tests::FORCE_BAD_OPTIONS.with(|c| c.get()))
}

/// tmpfs 載せ替え後の観測値。
#[cfg(not(test))]
fn observe_tmpfs(
    before_mnt_id: u64,
    after: &OwnedFd,
    own: &OwnedFd,
) -> Result<MountObservation, ExecError> {
    Ok(MountObservation {
        magic: sys::fs_type(after.as_fd())
            .map_err(|e| ExecError::from_sys(e, STAGE, "fstatfs(masked tmpfs)"))?,
        before_mnt_id,
        after_mnt_id: fd_mount_id(after, STAGE)?,
        own_mnt_id: fd_mount_id(own, STAGE)?,
    })
}

/// dry-run: 「別マウントの tmpfs で自分のマウント」を観測したことにする（実機の検証は結合試験で行う）。
#[cfg(test)]
fn observe_tmpfs(
    _before_mnt_id: u64,
    _after: &OwnedFd,
    _own: &OwnedFd,
) -> Result<MountObservation, ExecError> {
    Ok(MountObservation {
        magic: sys::TMPFS_MAGIC,
        before_mnt_id: 1,
        after_mnt_id: 2,
        own_mnt_id: 2,
    })
}

/// 複製元の `/dev/null` を 1 ノード複製する。本番ビルドでは [`sys::open_tree_clone`]。
#[cfg(not(test))]
fn clone_null_syscall(null: &NullNodeSource) -> Result<OwnedFd, SysError> {
    sys::open_tree_clone(&null.0)
}

/// dry-run: 新マウント API を呼ばず記録し、検証済みの fd の複製を返す。
#[cfg(test)]
fn clone_null_syscall(null: &NullNodeSource) -> Result<OwnedFd, SysError> {
    if let Some(e) = tests::CLONE_FAIL.with(|f| f.take()) {
        return Err(e);
    }
    tests::EVENTS.with(|e| e.borrow_mut().push(("clone", String::new())));
    null.0
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| SysError::Os(sys::EBADF))
}

/// 複製を対象の上に載せる。本番ビルドでは [`sys::move_mount_empty_path`]。
#[cfg(not(test))]
fn move_mount_syscall(
    from: BorrowedFd<'_>,
    to: BorrowedFd<'_>,
    _path: &str,
) -> Result<(), SysError> {
    sys::move_mount_empty_path(from, to)
}

/// dry-run: `move_mount(2)` を呼ばず、載せ先の実体を記録する。
#[cfg(test)]
fn move_mount_syscall(
    _from: BorrowedFd<'_>,
    to: BorrowedFd<'_>,
    _path: &str,
) -> Result<(), SysError> {
    if let Some(e) = tests::MOVE_FAIL.with(|f| f.take()) {
        return Err(e);
    }
    use std::os::fd::AsRawFd as _;
    let resolved = std::fs::read_link(format!("/proc/thread-self/fd/{}", to.as_raw_fd()))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    tests::EVENTS.with(|e| e.borrow_mut().push(("bind_null", resolved)));
    Ok(())
}

/// 載せた後の再確認: 開き直した対象が文字デバイス 1:3 で、新しいマウントで、自分の複製のマウントであること。
#[cfg(not(test))]
fn check_bound_null(
    reopened: &OwnedFd,
    tree: &OwnedFd,
    before_mnt_id: u64,
    path: &str,
    violation: &dyn Fn(ViolationReason) -> ExecError,
) -> Result<(), ExecError> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    let meta = fd_metadata(reopened, &format!("fstat({path}) after mask"))?;
    let (major, minor) = sys::HostDeviceNode::Null.major_minor();
    if !meta.file_type().is_char_device() || meta.rdev() != sys::makedev(major, minor) {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!("the masked file {path} is not the null device after mask"),
        ));
    }
    let after_mnt_id = fd_mount_id(reopened, STAGE)?;
    if after_mnt_id == before_mnt_id {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!("no new mount is present at {path} after mask"),
        ));
    }
    if after_mnt_id != fd_mount_id(tree, STAGE)? {
        return Err(violation(ViolationReason::TargetMoved));
    }
    Ok(())
}

/// dry-run: 何も確認しない（実機の検証は結合試験で行う）。
#[cfg(test)]
fn check_bound_null(
    _reopened: &OwnedFd,
    _tree: &OwnedFd,
    _before_mnt_id: u64,
    _path: &str,
    _violation: &dyn Fn(ViolationReason) -> ExecError,
) -> Result<(), ExecError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::os::unix::fs::symlink;

    use super::super::tmpfs::tests::{Tmp, take_calls};
    use super::*;
    use crate::exec::devices::NullNodeSource;
    use crate::exec::tests::override_shared;

    thread_local! {
        /// dry-run が記録した `("clone" | "bind_null", 実体のパス)`（テストスレッドごと）。
        pub(super) static EVENTS: RefCell<Vec<(&'static str, String)>> =
            const { RefCell::new(Vec::new()) };
        pub(super) static CLONE_FAIL: Cell<Option<SysError>> = const { Cell::new(None) };
        pub(super) static MOVE_FAIL: Cell<Option<SysError>> = const { Cell::new(None) };
        pub(super) static FORCE_BAD_OPTIONS: Cell<bool> = const { Cell::new(false) };
    }

    fn reset() {
        EVENTS.with(|e| e.borrow_mut().clear());
        CLONE_FAIL.with(|f| f.set(None));
        MOVE_FAIL.with(|f| f.set(None));
        FORCE_BAD_OPTIONS.with(|f| f.set(false));
        let _ = take_calls();
    }

    fn take_events() -> Vec<(&'static str, String)> {
        EVENTS.with(|e| std::mem::take(&mut *e.borrow_mut()))
    }

    /// 検証済みの `/dev/null`（ホストのノードを検証して使う。非特権でも作れる）。
    fn null_source() -> NullNodeSource {
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        NullNodeSource(
            sys::verify_device_node_fd(OwnedFd::from(file), sys::HostDeviceNode::Null)
                .expect("verify"),
        )
    }

    /// ファイルの対象。
    const FILES: [&str; 6] = [
        "proc/interrupts",
        "proc/kcore",
        "proc/keys",
        "proc/latency_stats",
        "proc/sched_debug",
        "proc/timer_list",
    ];
    /// ディレクトリの対象。
    const DIRS: [&str; 3] = ["proc/acpi", "proc/asound", "proc/scsi"];

    /// 全対象が存在する偽 rootfs（`timer_stats` は新しいカーネルで無いので作らない）。
    fn full_rootfs(tag: &str) -> Tmp {
        let tmp = Tmp::new(tag);
        for d in DIRS {
            std::fs::create_dir_all(tmp.0.join(d)).expect("mkdir");
        }
        for f in FILES {
            std::fs::write(tmp.0.join(f), b"").expect("file");
        }
        std::fs::write(tmp.0.join("proc/timer_stats"), b"").expect("file");
        tmp
    }

    fn bind(tmp: &Tmp, rel: &str) -> [(&'static str, String); 2] {
        [
            ("clone", String::new()),
            ("bind_null", tmp.0.join(rel).to_string_lossy().into_owned()),
        ]
    }

    /// SEC-2（#1851）: ファイル 7 件は `/dev/null` の複製を載せ、ディレクトリ 3 件は読み取り専用 tmpfs を載せる。
    #[test]
    fn sec2_masks_files_with_dev_null_and_dirs_with_ro_tmpfs() {
        reset();
        let _shared = override_shared(false);
        let tmp = full_rootfs("mask-all");
        let fd = tmp.fd();
        let report = apply_at(fd.as_fd(), &null_source()).expect("apply");
        assert_eq!((report.applied, report.skipped), (10, 0));
        // ファイルは定義順（interrupts, kcore, keys, latency_stats, sched_debug, timer_list, timer_stats）。
        let mut want = Vec::new();
        for rel in [
            "proc/interrupts",
            "proc/kcore",
            "proc/keys",
            "proc/latency_stats",
            "proc/sched_debug",
            "proc/timer_list",
            "proc/timer_stats",
        ] {
            want.extend(bind(&tmp, rel));
        }
        assert_eq!(take_events(), want);
        // ディレクトリ 3 件は ro・noexec の tmpfs（nosuid・nodev は型が常時付与）。
        let calls = take_calls();
        assert_eq!(calls.len(), 3);
        let want_attr = u64::from(MASK_TMPFS.flags.attr_bits());
        for (call, rel) in calls.iter().zip(DIRS) {
            assert_eq!(call.0, tmp.0.join(rel).to_string_lossy());
            assert_eq!(call.1, want_attr);
            assert_eq!(call.2, "mode=0755,size=4096");
        }
    }

    /// SEC-2（#1851）: 覆い用 tmpfs の属性は `ro`・`nosuid`・`nodev`・`noexec` を含む。
    #[test]
    fn sec2_mask_tmpfs_attr_bits_are_ro_nosuid_nodev_noexec() {
        let bits = MASK_TMPFS.flags.attr_bits();
        for (name, flag) in [
            ("rdonly", 0x1),
            ("nosuid", 0x2),
            ("nodev", 0x4),
            ("noexec", 0x8),
        ] {
            assert_eq!(bits & flag, flag, "{name}");
        }
    }

    /// SEC-2（#1851）: 存在しない対象は飛ばされ、親の `proc` が無い構成でも全件を飛ばして成功する。
    #[test]
    fn sec2_missing_targets_are_skipped_and_counted() {
        reset();
        let _shared = override_shared(false);
        let tmp = Tmp::new("mask-missing");
        std::fs::create_dir_all(tmp.0.join("proc/scsi")).expect("mkdir");
        std::fs::write(tmp.0.join("proc/kcore"), b"").expect("file");
        let fd = tmp.fd();
        let report = apply_at(fd.as_fd(), &null_source()).expect("apply");
        assert_eq!((report.applied, report.skipped), (2, 8));
        assert_eq!(take_events(), bind(&tmp, "proc/kcore").to_vec());
        assert_eq!(take_calls().len(), 1);

        reset();
        let empty = Tmp::new("mask-empty");
        let fd = empty.fd();
        let report = apply_at(fd.as_fd(), &null_source()).expect("apply empty");
        assert_eq!((report.applied, report.skipped), (0, 10));
        assert_eq!(take_events(), vec![]);
    }

    /// SEC-2（#1851）: 対象が symlink なら拒否し、後続の対象は処理されない。
    #[test]
    fn sec2_symlink_target_is_rejected_and_stops_later_targets() {
        reset();
        let _shared = override_shared(false);
        let tmp = full_rootfs("mask-symlink");
        std::fs::remove_dir(tmp.0.join("proc/asound")).expect("rm");
        symlink("/etc", tmp.0.join("proc/asound")).expect("symlink");
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd(), &null_source()).expect_err("symlink");
        assert_eq!(err.stage, IsolationStage::MountMaskedPaths);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathSymlinkOrNotDirectory)
        );
        // 先行の `acpi` だけが処理済みで、`asound` 以降は処理されない。
        assert_eq!(take_events(), vec![]);
        assert_eq!(take_calls().len(), 1);
    }

    /// SEC-2（#1851）: 途中の `proc` が symlink でも拒否する。
    #[test]
    fn sec2_proc_symlink_is_rejected() {
        reset();
        let _shared = override_shared(false);
        let tmp = Tmp::new("mask-proc-link");
        symlink("/proc", tmp.0.join("proc")).expect("symlink");
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd(), &null_source()).expect_err("proc symlink");
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathSymlinkOrNotDirectory)
        );
        assert_eq!(take_events(), vec![]);
    }

    /// SEC-2（#1851）: shared propagation 上の対象は載せる前に拒否する。
    #[test]
    fn sec2_shared_mount_target_is_rejected_before_mounting() {
        reset();
        let _shared = override_shared(true);
        let tmp = full_rootfs("mask-shared");
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd(), &null_source()).expect_err("shared");
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::TargetOnSharedMount)
        );
        assert_eq!(err.stage, IsolationStage::MountMaskedPaths);
        assert_eq!(take_events(), vec![]);
        assert_eq!(take_calls().len(), 0);
    }

    /// SEC-2（#1851）: `open_tree` の失敗はそのまま段 `MountMaskedPaths` のエラーで、後続は処理されない。
    #[test]
    fn sec2_clone_failure_is_fail_closed() {
        reset();
        let _shared = override_shared(false);
        let tmp = full_rootfs("mask-clone-fail");
        CLONE_FAIL.with(|f| f.set(Some(SysError::Os(sys::EINVAL))));
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd(), &null_source()).expect_err("clone");
        assert_eq!(err.stage, IsolationStage::MountMaskedPaths);
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(
            err.message
                .starts_with("open_tree(/proc/interrupts) failed"),
            "{}",
            err.message
        );
        assert_eq!(take_events(), vec![]);
    }

    /// SEC-2（#1851）: 未対応カーネル（`move_mount` が使えない）は `Unimplemented` で拒否し、縮退しない。
    #[test]
    fn sec2_unsupported_kernel_is_unimplemented() {
        reset();
        let _shared = override_shared(false);
        let tmp = full_rootfs("mask-unsupported");
        MOVE_FAIL.with(|f| f.set(Some(SysError::Unsupported)));
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd(), &null_source()).expect_err("unsupported");
        assert_eq!(err.stage, IsolationStage::MountMaskedPaths);
        assert_eq!(err.code, ErrorCode::Unimplemented);
        assert_eq!(take_events(), vec![("clone", String::new())]);
    }

    /// SEC-2（#1851）: tmpfs の per-mount options が満たされなければ `FailedPrecondition`。
    #[test]
    fn sec2_tmpfs_option_postcondition_failure_is_failed_precondition() {
        reset();
        let _shared = override_shared(false);
        let tmp = Tmp::new("mask-bad-options");
        std::fs::create_dir_all(tmp.0.join("proc/acpi")).expect("mkdir");
        FORCE_BAD_OPTIONS.with(|f| f.set(true));
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd(), &null_source()).expect_err("options");
        assert_eq!(err.stage, IsolationStage::MountMaskedPaths);
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message,
            "the tmpfs at /proc/acpi does not have ro,nosuid,nodev,noexec after mount"
        );
    }

    /// 子の失敗を状態 pipe の往復で親へ運び、層 `mount` の記録 1 件（パスなし・`container_id` つき）を照合する。
    fn relay_and_record(err: &ExecError) -> (ExecError, String) {
        use crate::audit_log::mount::tests::VecSink;
        use crate::audit_log::{AuditDelivery, AuditLayer};
        use crate::exec::launch_status::{LaunchAudit, PrePivotStep, relay_failure_for_test};
        use crate::traits::ContainerId;

        let sink = VecSink::new(false);
        let id = ContainerId::new("c1").expect("id");
        let out = relay_failure_for_test(
            PrePivotStep::MaskedPaths,
            err,
            LaunchAudit {
                sink: &sink,
                container: Some(&id),
            },
        )
        .expect_err("rejected");
        assert_eq!(out.delivery, AuditDelivery::Recorded);
        let recs = sink.snapshot();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].layer(), AuditLayer::Mount);
        assert_eq!(recs[0].path(), None);
        assert_eq!(recs[0].container_id().map(ContainerId::as_str), Some("c1"));
        let reason = recs[0].reason().map(|r| r.as_str().to_string());
        (out.error, reason.expect("reason"))
    }

    /// SEC-4・SEC-2（#2013）: ファイルの覆い（`open_tree` の失敗・`move_mount` の未対応カーネル）とディレクトリの覆い
    /// （tmpfs の事後条件）の失敗に `masked_path_apply_failed` が付き、`code` は従来のまま。状態 pipe の往復を経て
    /// 親で層 `mount` の記録 1 件になり、`ErrorCode` も保たれる。
    #[test]
    fn sec4_2013_apply_failures_carry_reason_and_reach_the_audit_record() {
        for (case, code) in [
            ("clone", ErrorCode::FailedPrecondition),
            ("move", ErrorCode::Unimplemented),
            ("tmpfs_options", ErrorCode::FailedPrecondition),
        ] {
            reset();
            let _shared = override_shared(false);
            let tmp = if case == "tmpfs_options" {
                let tmp = Tmp::new("mask-apply-audit-dir");
                std::fs::create_dir_all(tmp.0.join("proc/acpi")).expect("mkdir");
                FORCE_BAD_OPTIONS.with(|f| f.set(true));
                tmp
            } else {
                let tmp = full_rootfs("mask-apply-audit-file");
                match case {
                    "clone" => CLONE_FAIL.with(|f| f.set(Some(SysError::Os(sys::EINVAL)))),
                    _ => MOVE_FAIL.with(|f| f.set(Some(SysError::Unsupported))),
                }
                tmp
            };
            let fd = tmp.fd();
            let err = apply_at(fd.as_fd(), &null_source()).expect_err(case);
            assert_eq!(err.code, code, "{case}");
            assert_eq!(err.stage, IsolationStage::MountMaskedPaths, "{case}");
            assert_eq!(
                err.violation.as_ref().map(|v| v.reason),
                Some(ViolationReason::MaskedPathApplyFailed),
                "{case}"
            );
            let (restored, reason) = relay_and_record(&err);
            assert_eq!(reason, "masked_path_apply_failed", "{case}");
            assert_eq!(restored.code, code, "{case}");
            assert_eq!(restored.stage, IsolationStage::MountMaskedPaths);
            assert_eq!(restored.message, "failed to apply a masked path protection");
        }
    }

    /// SEC-4・SEC-2（#2013）: `config.json` 由来の対象（`/data/x`）の覆いの失敗も同じ理由で記録される。
    #[test]
    fn sec4_2013_config_target_apply_failure_is_recorded() {
        reset();
        let _shared = override_shared(false);
        let tmp = Tmp::new("mask-extra-audit");
        std::fs::create_dir_all(tmp.0.join("data")).expect("mkdir");
        std::fs::write(tmp.0.join("data/x"), b"").expect("file");
        CLONE_FAIL.with(|f| f.set(Some(SysError::Os(sys::EINVAL))));
        let extra = [ProtectedPath::parse("/data/x", 4096).expect("valid")];
        let fd = tmp.fd();
        let err = apply_at_with(fd.as_fd(), &null_source(), &extra).expect_err("clone");
        assert!(
            err.message.starts_with("open_tree(/data/x) failed"),
            "{}",
            err.message
        );
        let (_, reason) = relay_and_record(&err);
        assert_eq!(reason, "masked_path_apply_failed");
    }

    /// SEC-4（#2013）: 経路検査の拒否（symlink）は既存の汎用理由のまま記録される。
    #[test]
    fn sec4_2013_path_check_rejection_keeps_generic_reason() {
        reset();
        let _shared = override_shared(false);
        let tmp = full_rootfs("mask-symlink-audit");
        std::fs::remove_dir(tmp.0.join("proc/asound")).expect("rm");
        symlink("/etc", tmp.0.join("proc/asound")).expect("symlink");
        let fd = tmp.fd();
        let err = apply_at(fd.as_fd(), &null_source()).expect_err("symlink");
        let (_, reason) = relay_and_record(&err);
        assert_eq!(reason, "path_symlink_or_not_directory");
    }

    /// SEC-2（#1851）: mountinfo の per-mount options の判定（具体値）。
    #[test]
    fn sec2_mount_has_options_parses_mountinfo() {
        let info = "\
41 29 0:36 / /proc/acpi ro,nosuid,nodev,noexec - tmpfs tmpfs ro,size=4k,mode=755\n\
42 29 0:37 / /proc/scsi ro,nosuid,nodev,relatime - tmpfs tmpfs ro\n";
        let req = ["ro", "nosuid", "nodev", "noexec"];
        assert!(mount_has_options(info, 41, &req).expect("41"));
        assert!(!mount_has_options(info, 42, &req).expect("42"));
        assert!(mount_has_options(info, 43, &req).is_err());
        assert!(mount_has_options("x y\n", 41, &req).is_err());
        let dup = format!("{info}41 29 0:36 / /x ro - tmpfs tmpfs ro\n");
        assert!(mount_has_options(&dup, 41, &req).is_err());
    }
}
