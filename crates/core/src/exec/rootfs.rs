//! `pivot_root(2)` による rootfs 切替と旧 root の後始末（CORE-1・TASK-27.3・#135・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! `crate::exec` の最小実行フロー第 2 段。新しい PID namespace の PID 1 が
//! [`MountIsolation::establish`] で自分だけの mount namespace を作った後に、次の 2 段を順に通す
//! （呼び出し元は TASK-29 の `oci_runtime` と fork 段〔#831〕を想定。基本デバイスノード作成
//! 〔#834・TASK-27.6〕や CDI hook〔TASK-127〕は 2 段の間に差し込む）。
//!
//! ```text
//! MountIsolation::establish()
//!   -> prepare_rootfs(&isolation, rootfs) -> PreparedRootfs   // 自己 bind + rootfs/proc へ procfs
//!   -> pivot_root(&isolation, prepared)   -> PivotReport      // rootfs 切替 + 旧 root 切り離し
//! ```
//!
//! # 契約
//!
//! - **順序は型で強制する**: [`PreparedRootfs`] は [`prepare_rootfs`] だけが作り、[`pivot_root`]
//!   だけが（消費して）受け取る。`/proc` は pivot **前**に rootfs 配下へマウントする。rootless
//!   （非 init user namespace 所有の mount namespace）では、同じ mount namespace に完全に見える
//!   procfs が既にあるときだけ新規 procfs のマウントが許され（カーネルの `mnt_already_visible`）、
//!   旧 root を切り離した後には候補が無いため、pivot 後のマウントには頼れない
//! - **`put_old` ディレクトリを作らない**: `pivot_root(".", ".")` 方式を採る。PoC-3 の固定名
//!   `.old_root` は共有 rootfs で `pivot_root` の ENOENT 競合を起こした（TASK-27.3）
//! - **旧 root を残さない**: 旧 root は `MNT_DETACH` で mount namespace から外し、旧 root を指す fd を
//!   直ちに drop し、cwd を新 root の `/` へ移す。旧 root の fd・cwd が残るとホストへ到達できる脱出
//!   経路になる（CVE-2024-21626 型）。事後条件（`/` の実体・mountinfo に旧 root が無いこと）を
//!   検証し、満たさなければ fail-closed で失敗する
//! - **ホスト root は拒否する**: rootfs が `/` の指定は意味がなく危険なため
//!   `ViolationReason::RootfsIsHostRoot` で拒否する
//! - **既存サブマウントは拒否する**: `MS_BIND | MS_REC` は rootfs 配下の既存マウントも複製する。
//!   複製されたサブマウントが 1 つでもあれば `ViolationReason::RootfsHasSubmounts` で拒否する
//!   （許可リストは空。ホスト領域への bind mount が pivot 後も到達可能になるのを防ぐ）。
//!   `/proc` は検査後に自分でマウントする
//! - **同一スレッド**: 呼び出しスレッドだけが新しい mount namespace にいるため、
//!   [`MountIsolation::establish`]・[`prepare_rootfs`]・[`pivot_root`] は同じスレッドで呼ぶ
//! - **失敗時はプロセスを破棄する**: bind mount・procfs マウント・pivot の途中で失敗しても
//!   マウントを元へ戻す手段は無い（`crate::exec` のモジュール doc の契約）
//! - **未対応**: rootfs のマウントポイント（`proc` ディレクトリ）の自動作成は行わない。無ければ
//!   `ViolationReason::PathMissing` で拒否する（OCI mounts の適用は TASK-127 の範囲）。rootfs の
//!   digest 検証は OCI イメージ系 TASK の範囲
//!
//! # 単体テストの安全策
//!
//! `mount(2)`・`pivot_root(2)` は `cfg(test)` では dry-run に差し替わる（`bind_syscall`・
//! `switch_root`）。root で `cargo test` を実行してもホストの mount namespace へは届かない。
//! 実機での挙動は結合試験 `tests/pivot_root_isolation.rs`（`-- --ignored`）で確認する。

use std::ffi::{CStr, CString, OsStr};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};

use crate::sys::{self, SysError};
use crate::traits::types::ErrorCode;

use super::{
    ExecError, IsolationStage, MountIsolation, ViolationReason, fd_mount_id, fd_still_at,
    mount_is_shared, mount_proc_at_dir, open_error, pin_rootfs, read_thread_mountinfo,
};

/// [`prepare_rootfs`] が返す、pivot 可能な rootfs の証。[`pivot_root`] だけが受け取る（消費する）。
///
/// 保持しているのは、自己 bind 済み（=マウントポイント）の rootfs の新しい mount top を指す
/// O_PATH fd。中身は非公開で、`Clone` も実装しない。`!Send`・`!Sync`: mount namespace に入って
/// いるのは呼び出しスレッドだけのため、別スレッドで `pivot_root` させない。
#[derive(Debug)]
pub struct PreparedRootfs {
    /// bind mount の新しい mount top（`pivot_root` の new_root）。
    new_root: OwnedFd,
    /// `new_root` が属するマウントの ID（bind 前の下層マウントとは異なる）。
    new_root_mnt_id: u64,
    /// `!Send`・`!Sync` にするための印。
    _not_send: std::marker::PhantomData<*const ()>,
}

/// [`pivot_root`] の結果。将来の拡張（ステージ列・監査ログ）に備えて非網羅の構造体にする。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PivotReport {
    /// 新しい `/` のマウント ID（`/proc/thread-self/mountinfo` の先頭フィールド）。
    pub new_root_mnt_id: u64,
    /// 旧 root を切り離し、mountinfo から消えたことを確認済みか。成功した [`pivot_root`] では常に真。
    pub old_root_detached: bool,
    /// pivot 前にマウントした `/proc` が新しい `/proc` になっているか。成功時は常に真。
    pub proc_mounted: bool,
}

/// rootfs を pivot 可能にする（自己 bind + rootfs 配下への `/proc` マウント）。
///
/// 呼び出し側が [`MountIsolation::establish`] で得た証跡を提示し、現在の状態と一致する場合だけ
/// 進む（[`crate::exec::mount_proc`] と同じ fail-closed）。手順（副作用は手順 6 以降）:
///
/// 1. `rootfs` が絶対パスで NUL・`..` を含まず、`/` そのものでない
/// 2. `/` から rootfs までを `openat(O_PATH|O_DIRECTORY|O_NOFOLLOW)` で 1 要素ずつ辿って fd で固定
///    する（祖先・rootfs 自体の symlink・非ディレクトリは拒否）。以後はパス文字列で再解決しない
/// 3. `rootfs/proc` がディレクトリ（symlink でない）として存在する
/// 4. 固定した rootfs のマウントが shared propagation でなく、固定後に移動されていない
/// 5. rootfs を自分自身へ再帰 bind mount してマウントポイントにする（`pivot_root` の new_root 要件）
/// 6. bind 前に得た fd は下層の dentry を指すため、保持した親 fd から同じ名前で開き直し、bind で
///    できた新しい mount top を得る（マウント ID が変わったこと、開き直した fd が bind 対象と同じ
///    `(st_dev, st_ino)` であること、新マウントの親が bind 元のマウントであることを確認する）
/// 7. bind が複製した rootfs 配下の既存マウントが 1 つでもあれば拒否する（`RootfsHasSubmounts`）
/// 8. 新しい mount top 起点で `proc` を開き直し、procfs をマウントする
pub fn prepare_rootfs(
    isolation: &MountIsolation,
    rootfs: &Path,
) -> Result<PreparedRootfs, ExecError> {
    isolation.verify_caller(IsolationStage::PrepareRootfs)?;
    prepare_rootfs_verified(rootfs)
}

/// [`prepare_rootfs`] の証跡検証後の本体。単体テストは証跡を偽造せずに直接呼ぶ
/// （`mount(2)` は `cfg(test)` では dry-run）。
fn prepare_rootfs_verified(rootfs: &Path) -> Result<PreparedRootfs, ExecError> {
    const STAGE: IsolationStage = IsolationStage::PrepareRootfs;
    let violation = |r: ViolationReason| ExecError::from_violation_at(r, Some(rootfs), STAGE);
    validate_rootfs_path(rootfs)?;
    let pinned = pin_rootfs(rootfs).map_err(|e| e.at_stage(STAGE))?;
    let proc_path = rootfs.join("proc");
    // 副作用（bind）の前に `proc` の検査を済ませ、拒否のときに bind を残さない。bind 後にも
    // 新しい mount top 起点でもう一度開く（rootfs の内容はイメージ由来の非信頼データ）。
    drop(open_proc_dir(pinned.dir.as_fd(), rootfs)?);
    if mount_is_shared(&pinned.dir, STAGE)? {
        return Err(violation(ViolationReason::RootfsOnSharedMount));
    }
    if !fd_still_at(&pinned.dir, rootfs) {
        return Err(violation(ViolationReason::RootfsMoved));
    }
    let before_mnt_id = fd_mount_id(&pinned.dir, STAGE)?;

    let c_target = fd_path(&pinned.dir)?;
    bind_syscall(&c_target).map_err(|e| ExecError::from_sys(e, STAGE, "mount(MS_BIND)"))?;

    // 保持した親 fd から同じ名前で開き直す。通常要素の lookup はマウントを越えて新しい mount
    // top に着地する（bind 前の fd のままでは `pivot_root(".", ".")` が EINVAL になる）。
    // 文字列で `/` から再解決しない（差し替えの TOCTOU を作らない）。
    let (Some(parent), Some(leaf)) = (pinned.parent.as_ref(), pinned.leaf.as_ref()) else {
        // rootfs が `/` の指定は手順 1 で拒否済み。ここへ来たら内部の不整合として拒否する。
        return Err(violation(ViolationReason::RootfsIsHostRoot));
    };
    let new_root = sys::open_dir_path_nofollow(Some(parent.as_fd()), leaf)
        .map_err(|e| open_error(e, false, rootfs, &[]).at_stage(STAGE))?;
    let new_root_mnt_id = fd_mount_id(&new_root, STAGE)?;
    // dry-run（`cfg(test)`）では bind mount が実際には作られないため比較しない。
    if !cfg!(test) {
        check_bind_created_mount(before_mnt_id, new_root_mnt_id)?;
    }
    // 開き直しは名前の再解決のため、bind と開き直しの間に別プロセスが名前を差し替えて別の
    // ディレクトリ（別のマウント）を置いていても着地し得る。マウント ID の変化だけでは同一性を
    // 保証できないため、開き直した fd が bind 対象と同じ実体であること、および（本番では）
    // 新しいマウントが bind 元のマウントの上に作られたものであることを確認する。
    check_reopened_is_bind_of(
        &pinned.dir,
        &new_root,
        before_mnt_id,
        new_root_mnt_id,
        rootfs,
    )?;

    // `MS_BIND | MS_REC` は rootfs 配下の既存マウントも新しい mount 木へ複製する。ホスト領域への
    // bind mount が含まれていると pivot 後も到達できてしまうため、複製されたサブマウントは
    // 1 つでも拒否する（許可リストは空。`/proc` はこの後に自分でマウントするので対象外）。
    // `cfg(test)` の dry-run では bind が作られないため検査しない。
    if !cfg!(test) {
        let info = read_thread_mountinfo(STAGE)?;
        check_no_submounts(&info, new_root_mnt_id, rootfs)?;
    }

    let proc_dir = open_proc_dir(new_root.as_fd(), rootfs)?;
    mount_proc_at_dir(&proc_dir, &proc_path, STAGE)?;
    Ok(PreparedRootfs {
        new_root,
        new_root_mnt_id,
        _not_send: std::marker::PhantomData,
    })
}

/// rootfs 指定の形式検証（副作用なし）。相対パス・NUL・`..`・`/` そのもの（ホスト root）を
/// 違反記録付きで拒否する。
fn validate_rootfs_path(rootfs: &Path) -> Result<(), ExecError> {
    let violation = |r: ViolationReason| {
        ExecError::from_violation_at(r, Some(rootfs), IsolationStage::PrepareRootfs)
    };
    if !rootfs.is_absolute() {
        return Err(violation(ViolationReason::PathNotAbsolute));
    }
    if rootfs.as_os_str().as_bytes().contains(&0) {
        return Err(violation(ViolationReason::PathContainsNul));
    }
    if rootfs
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(violation(ViolationReason::PathParentComponent));
    }
    if !rootfs
        .components()
        .any(|c| matches!(c, Component::Normal(_)))
    {
        return Err(violation(ViolationReason::RootfsIsHostRoot));
    }
    Ok(())
}

/// `root_fd`（rootfs の fd）の直下の `proc` を `O_NOFOLLOW` で開く。symlink・非ディレクトリ・
/// 不在は違反記録付きで拒否する（対象は `rootfs/proc`）。
fn open_proc_dir(root_fd: BorrowedFd<'_>, rootfs: &Path) -> Result<OwnedFd, ExecError> {
    sys::open_dir_path_nofollow(Some(root_fd), c"proc")
        .map_err(|e| open_error(e, true, rootfs, &[OsStr::new("proc")]))
        .map_err(|e| e.at_stage(IsolationStage::PrepareRootfs))
}

/// fd を指す `/proc/thread-self/fd/N`（マウント先に使う magic link。パス文字列を再解決しない）。
fn fd_path(fd: &OwnedFd) -> Result<CString, ExecError> {
    CString::new(format!("/proc/thread-self/fd/{}", fd.as_raw_fd())).map_err(|_| {
        ExecError::new(
            ErrorCode::Internal,
            IsolationStage::PrepareRootfs,
            "failed to build the fd path of the rootfs",
        )
    })
}

/// bind mount が新しいマウントを作ったこと（マウント ID が変わったこと）の確認。変わっていなければ、
/// 開き直した fd が下層を指したままで `pivot_root(".", ".")` が失敗する（または意図しない実体を
/// 切り替える）ため、fail-closed でシステムエラーにする。
fn check_bind_created_mount(before: u64, after: u64) -> Result<(), ExecError> {
    if before == after {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::PrepareRootfs,
            "the rootfs bind mount did not create a new mount",
        ));
    }
    Ok(())
}

/// fd が指すディレクトリの `(st_dev, st_ino)`。`/proc/thread-self/fd/N` は fd の dentry へ解決される
/// ため、bind mount の mount top は下層と同じ組を返す。
fn fd_dev_ino(fd: &OwnedFd) -> std::io::Result<(u64, u64)> {
    let m = std::fs::metadata(format!("/proc/thread-self/fd/{}", fd.as_raw_fd()))?;
    Ok((m.dev(), m.ino()))
}

/// mountinfo から `mnt_id` のマウントの親マウント ID（第 2 フィールド）を取り出す。行が無い・
/// 重複・書式不正は `None`（呼び出し側で fail-closed）。
fn mount_parent_in(info: &str, mnt_id: u64) -> Option<u64> {
    let mut found = None;
    for line in info.lines() {
        let mut f = line.split(' ');
        let id: u64 = f.next()?.parse().ok()?;
        let parent: u64 = f.next()?.parse().ok()?;
        if id == mnt_id {
            if found.is_some() {
                return None;
            }
            found = Some(parent);
        }
    }
    found
}

/// `mountinfo` に `root_mnt_id` の子孫マウント（親 ID を辿って到達するもの）が 1 つでもあれば
/// `RootfsHasSubmounts` で拒否する（純関数）。パス文字列ではなくマウント ID の親子関係で判定する
/// ため、mountinfo のエスケープやパス差異の影響を受けない。書式不正な行は fail-closed で拒否する
/// （壊れた行を黙って飛ばして「サブマウント無し」と誤判定しない）。
fn check_no_submounts(info: &str, root_mnt_id: u64, rootfs: &Path) -> Result<(), ExecError> {
    const STAGE: IsolationStage = IsolationStage::PrepareRootfs;
    let malformed = || {
        ExecError::new(
            ErrorCode::Internal,
            STAGE,
            "malformed line in /proc/thread-self/mountinfo",
        )
    };
    let mut edges: Vec<(u64, u64)> = Vec::new();
    for line in info.lines() {
        let mut f = line.split(' ');
        let id: u64 = f
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or_else(malformed)?;
        let parent: u64 = f
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or_else(malformed)?;
        edges.push((id, parent));
    }
    // 直接の子があれば孫以降も存在し得るが、1 つでも子があれば拒否するため直接の子だけ見れば足りる
    // （子の子は必ず子を経由する）。
    if edges
        .iter()
        .any(|&(id, parent)| parent == root_mnt_id && id != root_mnt_id)
    {
        return Err(ExecError::from_violation_at(
            ViolationReason::RootfsHasSubmounts,
            Some(rootfs),
            STAGE,
        ));
    }
    Ok(())
}

/// bind 後に開き直した `reopened` が、bind 対象 `pinned`（bind 前に固定した fd）と同じ実体で、
/// かつ今回の bind が作った新しいマウントであることを確認する（fail-closed。CORE-1）。
///
/// - `(st_dev, st_ino)` が `pinned` と一致する（別ディレクトリへの差し替えを検出する）
/// - 本番ビルドでは、新しいマウントの親が bind 元のマウント（`before_mnt_id`）である
///   （bind は元のディレクトリの上にマウントされるため。`cfg(test)` の dry-run では bind が
///   作られないので省略する）
fn check_reopened_is_bind_of(
    pinned: &OwnedFd,
    reopened: &OwnedFd,
    before_mnt_id: u64,
    new_mnt_id: u64,
    rootfs: &Path,
) -> Result<(), ExecError> {
    const STAGE: IsolationStage = IsolationStage::PrepareRootfs;
    let swapped =
        || ExecError::from_violation_at(ViolationReason::RootfsMoved, Some(rootfs), STAGE);
    let stat_err = |e: std::io::Error| ExecError::from_io(&e, STAGE, "stat(rootfs fd)");
    let want = fd_dev_ino(pinned).map_err(stat_err)?;
    let got = fd_dev_ino(reopened).map_err(stat_err)?;
    if want != got {
        return Err(swapped());
    }
    if !cfg!(test) {
        let info = read_thread_mountinfo(STAGE)?;
        if mount_parent_in(&info, new_mnt_id) != Some(before_mnt_id) {
            return Err(swapped());
        }
    }
    Ok(())
}

/// rootfs を新しい `/` にし、旧 root を切り離す。
///
/// [`MountIsolation::establish`] の証跡を提示し、[`prepare_rootfs`] が返した [`PreparedRootfs`] を
/// 消費する。手順:
///
/// 1. 旧 root（`/`）を O_PATH fd で開き、マウント ID を記録する
/// 2. `fchdir(new_root)` → `pivot_root(".", ".")` → `fchdir(旧 root)` → `umount2(".", MNT_DETACH)`
///    → `chdir("/")`（旧 root を新 root の上に積んでから、cwd を旧 root に戻して切り離す。
///    `establish` が `/` を再帰 private にしているため、runc のような `MS_SLAVE|MS_REC` は不要で、
///    切り離しがホストへ伝播しない）
/// 3. 旧 root の fd を drop する
/// 4. 事後条件を検証する: `/` が新 root と同じ実体で、mountinfo に旧 root が無く、新 root が `/` に
///    ある。満たさなければ `FailedPrecondition`（fail-closed。呼び出し元はプロセスを破棄する）
///
/// 各手順の失敗はマウントを戻せない。呼び出し元はそのプロセスを破棄する。
pub fn pivot_root(
    isolation: &MountIsolation,
    prepared: PreparedRootfs,
) -> Result<PivotReport, ExecError> {
    isolation.verify_caller(IsolationStage::PivotRoot)?;
    pivot_root_verified(prepared)
}

/// [`pivot_root`] の証跡検証後の本体。`switch_root` は `cfg(test)` では dry-run。
fn pivot_root_verified(prepared: PreparedRootfs) -> Result<PivotReport, ExecError> {
    const STAGE: IsolationStage = IsolationStage::PivotRoot;
    let old_root = sys::open_dir_path_nofollow(None, c"/")
        .map_err(|e| ExecError::from_sys(e, STAGE, "openat(old root)"))?;
    let old_mnt_id = fd_mount_id(&old_root, STAGE)?;
    if old_mnt_id == prepared.new_root_mnt_id {
        // bind で新しいマウントを作っていれば旧 root とは別になる。同一なら pivot しない。
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            "the new root is on the same mount as the old root",
        ));
    }
    switch_root(prepared.new_root.as_fd(), old_root.as_fd())?;
    // 旧 root を指す fd が残ると、`openat(fd, "etc/...")` でホストへ到達できる。
    drop(old_root);

    let root_meta = std::fs::metadata("/").map_err(|e| ExecError::from_io(&e, STAGE, "stat(/)"))?;
    let new_root_meta = std::fs::File::from(
        prepared
            .new_root
            .try_clone()
            .map_err(|e| ExecError::from_io(&e, STAGE, "dup(new root)"))?,
    )
    .metadata()
    .map_err(|e| ExecError::from_io(&e, STAGE, "fstat(new root)"))?;
    let root_is_new_root =
        (root_meta.dev(), root_meta.ino()) == (new_root_meta.dev(), new_root_meta.ino());
    let mountinfo = read_thread_mountinfo(STAGE)?;
    check_pivot_postconditions(
        &mountinfo,
        old_mnt_id,
        prepared.new_root_mnt_id,
        root_is_new_root,
    )?;
    Ok(PivotReport {
        new_root_mnt_id: prepared.new_root_mnt_id,
        old_root_detached: true,
        proc_mounted: true,
    })
}

/// 事後条件の検証（純関数）。`mountinfo` は `/proc/thread-self/mountinfo`、`root_is_new_root` は
/// `/` の (dev, ino) が新 root の fd と一致したか。書式に反する行は 1 行でもあればエラー
/// （fail-closed。壊れた行を黙って飛ばして「旧 root は無い」と誤判定しない）。
fn check_pivot_postconditions(
    mountinfo: &str,
    old_mnt_id: u64,
    new_mnt_id: u64,
    root_is_new_root: bool,
) -> Result<(), ExecError> {
    let fail = |msg: &str| {
        ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::PivotRoot,
            msg,
        )
    };
    if !root_is_new_root {
        return Err(fail("/ is not the prepared new root after pivot_root"));
    }
    let mut new_root_at_slash = false;
    for line in mountinfo.lines() {
        let mut fields = line.split(' ');
        let id: u64 = fields
            .next()
            .and_then(|f| f.parse().ok())
            .ok_or_else(|| fail("malformed line in /proc/thread-self/mountinfo"))?;
        // 先頭から 5 番目のフィールドがマウントポイント（id parent major:minor root mount_point）。
        let mount_point = fields
            .nth(3)
            .ok_or_else(|| fail("malformed line in /proc/thread-self/mountinfo"))?;
        if id == old_mnt_id {
            return Err(fail("the old root is still mounted after pivot_root"));
        }
        if id == new_mnt_id && mount_point == "/" {
            new_root_at_slash = true;
        }
    }
    if !new_root_at_slash {
        return Err(fail("the new root is not mounted at / after pivot_root"));
    }
    Ok(())
}

/// [`prepare_rootfs`] の bind mount。本番ビルドでは [`sys::bind_mount_recursive`]。
#[cfg(not(test))]
fn bind_syscall(target: &CStr) -> Result<(), SysError> {
    sys::bind_mount_recursive(target)
}

/// テストビルドの dry-run 差し込み点。`mount(2)` を呼ばず、マウント先を記録するだけにする。
#[cfg(test)]
fn bind_syscall(target: &CStr) -> Result<(), SysError> {
    tests::DRY_RUN_BINDS.with(|b| b.borrow_mut().push(target.to_string_lossy().into_owned()));
    Ok(())
}

/// 切替の syscall 列（`fchdir(new)` → `pivot_root(".", ".")` → `fchdir(old)` →
/// `umount2(".", MNT_DETACH)` → `chdir("/")`）。本番ビルドの実装。
#[cfg(not(test))]
fn switch_root(new_root: BorrowedFd<'_>, old_root: BorrowedFd<'_>) -> Result<(), ExecError> {
    const STAGE: IsolationStage = IsolationStage::PivotRoot;
    let fail = |what: &'static str| move |e: SysError| ExecError::from_sys(e, STAGE, what);
    sys::change_dir_fd(new_root).map_err(fail("fchdir(new root)"))?;
    sys::pivot_root_dot().map_err(fail("pivot_root"))?;
    // pivot 後の cwd をカーネル実装の挙動に依存させず、切り離す旧 root に合わせる。
    sys::change_dir_fd(old_root).map_err(fail("fchdir(old root)"))?;
    sys::umount_cwd_detach().map_err(fail("umount2(MNT_DETACH)"))?;
    std::env::set_current_dir("/").map_err(|e| ExecError::from_io(&e, STAGE, "chdir(/)"))
}

/// テストビルドの dry-run 差し込み点。`pivot_root(2)` 等を呼ばず、呼ばれたことだけを記録する。
#[cfg(test)]
fn switch_root(_new_root: BorrowedFd<'_>, _old_root: BorrowedFd<'_>) -> Result<(), ExecError> {
    tests::DRY_RUN_SWITCHES.with(|s| *s.borrow_mut() += 1);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::PathBuf;

    use super::*;
    use crate::exec::{IsolationViolation, thread_ns_link};

    thread_local! {
        /// dry-run の `bind_syscall` が記録したマウント先（テストスレッドごと）。
        pub(super) static DRY_RUN_BINDS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        /// dry-run の `switch_root` が呼ばれた回数（テストスレッドごと）。
        pub(super) static DRY_RUN_SWITCHES: RefCell<u32> = const { RefCell::new(0) };
    }

    /// dry-run の記録を取り出して空にする（libtest のワーカースレッド再利用で前のテストの記録が
    /// 漏れないよう、照合は必ずこの関数で取り出して行う）。
    fn take_dry_runs() -> (Vec<String>, Vec<String>, u32) {
        let binds = DRY_RUN_BINDS.with(|b| std::mem::take(&mut *b.borrow_mut()));
        let mounts = crate::exec::tests::take_dry_run_mounts();
        let switches = DRY_RUN_SWITCHES.with(|s| std::mem::take(&mut *s.borrow_mut()));
        (binds, mounts, switches)
    }

    /// テスト用の一時ディレクトリ（drop で削除）。
    struct Tmp(PathBuf);

    impl Tmp {
        fn new(label: &str) -> Self {
            let base = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("fandhe-rootfs-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).unwrap();
            Self(base)
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn violation_of(err: &ExecError) -> (&'static str, &'static str, &'static str, Option<String>) {
        let v: &IsolationViolation = err.violation.as_ref().expect("violation record");
        (
            v.kind.as_str(),
            v.reason.as_str(),
            v.behavior_id,
            v.subject.as_ref().map(|s| s.as_str().to_string()),
        )
    }

    /// CORE-1: rootfs 指定の形式不正（相対・NUL・`..`・ホスト root）を、段 `PrepareRootfs` の
    /// 違反記録付きで副作用なしに拒否する。
    #[test]
    fn core1_prepare_rootfs_rejects_bad_paths() {
        take_dry_runs();
        let cases = [
            ("rel/rootfs", "path_not_absolute", "rel/rootfs"),
            ("/tmp/ro\0ot", "path_contains_nul", "/tmp/ro\\u{0}ot"),
            ("/tmp/a/../b", "path_parent_component", "/tmp/a/../b"),
        ];
        for (path, reason, subject) in cases {
            let err = prepare_rootfs_verified(Path::new(path)).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{reason}");
            assert_eq!(err.stage, IsolationStage::PrepareRootfs, "{reason}");
            assert_eq!(
                violation_of(&err),
                ("mount_target", reason, "CORE-1", Some(subject.to_string())),
                "{reason}"
            );
        }
        for path in ["/", "/.", "//"] {
            let err = prepare_rootfs_verified(Path::new(path)).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{path}");
            assert_eq!(err.stage, IsolationStage::PrepareRootfs, "{path}");
            assert_eq!(err.message, "rootfs must not be the host root '/'");
            let (kind, reason, id, _) = violation_of(&err);
            assert_eq!(
                (kind, reason, id),
                ("rootfs_pivot", "rootfs_is_host_root", "CORE-1")
            );
        }
        assert_eq!(take_dry_runs(), (vec![], vec![], 0));
    }

    /// CORE-1: rootfs の祖先・rootfs/proc の symlink、`proc` の不在は副作用なしに拒否する
    /// （symlink 経由で procfs をホスト側ディレクトリへ被せない）。
    #[test]
    fn core1_prepare_rootfs_rejects_symlink_and_missing_proc() {
        take_dry_runs();
        let t = Tmp::new("reject");
        let host_dir = t.0.join("host");
        std::fs::create_dir_all(&host_dir).unwrap();
        // rootfs A: proc が symlink（ホスト側ディレクトリを指す）。
        let a = t.0.join("a");
        std::fs::create_dir_all(&a).unwrap();
        std::os::unix::fs::symlink(&host_dir, a.join("proc")).unwrap();
        // rootfs B: proc が無い。
        let b = t.0.join("b");
        std::fs::create_dir_all(&b).unwrap();
        // rootfs C: rootfs 自体が symlink。
        let c = t.0.join("c");
        std::os::unix::fs::symlink(&b, &c).unwrap();
        // rootfs D: 不在。
        let d = t.0.join("d");
        let s = |p: &Path| Some(p.to_str().unwrap().to_string());
        let cases = [
            (
                a.clone(),
                "path_symlink_or_not_directory",
                s(&a.join("proc")),
            ),
            (b.clone(), "path_missing", s(&b.join("proc"))),
            (c.clone(), "rootfs_symlink_or_not_directory", s(&c)),
            (d.clone(), "rootfs_missing", s(&d)),
        ];
        for (rootfs, reason, subject) in cases {
            let err = prepare_rootfs_verified(&rootfs).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{reason}");
            assert_eq!(err.stage, IsolationStage::PrepareRootfs, "{reason}");
            assert_eq!(
                violation_of(&err),
                ("mount_target", reason, "CORE-1", subject),
                "{reason}"
            );
        }
        assert_eq!(take_dry_runs(), (vec![], vec![], 0));
    }

    /// CORE-1: 有効な rootfs は shared propagation 上なら違反記録付きで拒否し、そうでなければ
    /// dry-run の bind と procfs マウントまで進む（実行環境の propagation に応じてどちらかを照合）。
    #[test]
    fn core1_prepare_rootfs_reaches_dry_run_mounts_or_rejects_shared() {
        take_dry_runs();
        let t = Tmp::new("valid");
        let rootfs = t.0.join("root");
        std::fs::create_dir_all(rootfs.join("proc")).unwrap();
        match prepare_rootfs_verified(&rootfs) {
            Ok(prepared) => {
                let (binds, mounts, switches) = take_dry_runs();
                assert_eq!(binds.len(), 1, "{binds:?}");
                assert!(binds[0].starts_with("/proc/thread-self/fd/"), "{binds:?}");
                assert_eq!(mounts.len(), 1, "{mounts:?}");
                assert!(mounts[0].starts_with("/proc/thread-self/fd/"), "{mounts:?}");
                assert_eq!(switches, 0);
                drop(prepared);
            }
            Err(err) => {
                assert_eq!(err.stage, IsolationStage::PrepareRootfs);
                assert_eq!(
                    violation_of(&err),
                    (
                        "shared_propagation",
                        "rootfs_on_shared_mount",
                        "CORE-1",
                        Some(rootfs.to_str().unwrap().to_string())
                    )
                );
                assert_eq!(take_dry_runs(), (vec![], vec![], 0));
            }
        }
    }

    /// テストプロセスの現在の値で作った証跡（PID 1 ではないため検証は失敗する）。
    fn evidence_of_current_thread() -> MountIsolation {
        MountIsolation {
            mnt_ns: thread_ns_link("mnt").unwrap(),
            pid_ns: thread_ns_link("pid").unwrap(),
            _not_send: std::marker::PhantomData,
        }
    }

    /// CORE-1: PID 1 でない呼び出しは、`prepare_rootfs` / `pivot_root` とも副作用なしに拒否し、
    /// 失敗した段を記録する。
    #[test]
    fn core1_rootfs_steps_reject_caller_that_is_not_pid1() {
        take_dry_runs();
        let iso = evidence_of_current_thread();
        let t = Tmp::new("pid1");
        let rootfs = t.0.join("root");
        std::fs::create_dir_all(rootfs.join("proc")).unwrap();
        let err = prepare_rootfs(&iso, &rootfs).unwrap_err();
        assert_eq!(err.stage, IsolationStage::PrepareRootfs);
        assert_eq!(
            violation_of(&err),
            (
                "evidence_mismatch",
                "evidence_caller_not_pid1",
                "CORE-1",
                None
            )
        );

        let prepared = PreparedRootfs {
            new_root: sys::open_dir_path_nofollow(None, c"/").unwrap(),
            new_root_mnt_id: 0,
            _not_send: std::marker::PhantomData,
        };
        let err = pivot_root(&iso, prepared).unwrap_err();
        assert_eq!(err.stage, IsolationStage::PivotRoot);
        assert_eq!(
            violation_of(&err),
            (
                "evidence_mismatch",
                "evidence_caller_not_pid1",
                "CORE-1",
                None
            )
        );
        assert_eq!(take_dry_runs(), (vec![], vec![], 0));
    }

    /// CORE-1: new root が旧 root と同じマウント（bind 未実施）なら、`pivot_root(2)` の dry-run にも
    /// 到達せずに拒否する。
    #[test]
    fn core1_pivot_rejects_new_root_on_old_root_mount() {
        take_dry_runs();
        let root = sys::open_dir_path_nofollow(None, c"/").unwrap();
        let mnt_id = fd_mount_id(&root, IsolationStage::PivotRoot).unwrap();
        let prepared = PreparedRootfs {
            new_root: root,
            new_root_mnt_id: mnt_id,
            _not_send: std::marker::PhantomData,
        };
        let err = pivot_root_verified(prepared).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::PivotRoot);
        assert_eq!(
            err.message,
            "the new root is on the same mount as the old root"
        );
        assert!(err.violation.is_none());
        assert_eq!(take_dry_runs(), (vec![], vec![], 0));
    }

    const MOUNTINFO_OK: &str = "\
36 1 8:1 /rootfs / rw,relatime - ext4 /dev/sda1 rw
40 36 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw
";

    /// CORE-1: 事後条件は、`/` が新 root と同じ実体・旧 root のマウント ID が無い・新 root が `/` に
    /// ある場合だけ通る。
    #[test]
    fn core1_pivot_postconditions() {
        assert!(check_pivot_postconditions(MOUNTINFO_OK, 7, 36, true).is_ok());

        let err = check_pivot_postconditions(MOUNTINFO_OK, 7, 36, false).unwrap_err();
        assert_eq!(
            err.message,
            "/ is not the prepared new root after pivot_root"
        );
        assert_eq!(err.stage, IsolationStage::PivotRoot);
        assert_eq!(err.code, ErrorCode::FailedPrecondition);

        // 旧 root（ID 40 とする）が mountinfo に残っている。
        let err = check_pivot_postconditions(MOUNTINFO_OK, 40, 36, true).unwrap_err();
        assert_eq!(
            err.message,
            "the old root is still mounted after pivot_root"
        );

        // 新 root が `/` にない（ID 99 は存在しない）。
        let err = check_pivot_postconditions(MOUNTINFO_OK, 7, 99, true).unwrap_err();
        assert_eq!(
            err.message,
            "the new root is not mounted at / after pivot_root"
        );
        // 新 root のマウントポイントが `/` でない。
        let err = check_pivot_postconditions(MOUNTINFO_OK, 7, 40, true).unwrap_err();
        assert_eq!(
            err.message,
            "the new root is not mounted at / after pivot_root"
        );

        // 書式不正の行は、旧 root の有無に関わらず拒否する。
        for bad in ["x 1 8:1 / / rw - ext4 a rw\n", "36\n", ""] {
            let info = format!("{MOUNTINFO_OK}{bad}");
            let res = check_pivot_postconditions(&info, 7, 36, true);
            if bad.is_empty() {
                assert!(res.is_ok());
            } else {
                assert_eq!(
                    res.unwrap_err().message,
                    "malformed line in /proc/thread-self/mountinfo",
                    "{bad:?}"
                );
            }
        }
    }

    /// CORE-1: 開き直した fd が bind 対象と別ディレクトリなら拒否する（名前差し替えの TOCTOU）。
    #[test]
    fn core1_reopen_rejects_swapped_directory() {
        let a = Tmp::new("reopen-a");
        let b = Tmp::new("reopen-b");
        let open = |p: &Path| {
            sys::open_dir_path_nofollow(None, &CString::new(p.as_os_str().as_bytes()).unwrap())
                .unwrap()
        };
        let fa = open(&a.0);
        let fa2 = open(&a.0);
        let fb = open(&b.0);
        assert!(check_reopened_is_bind_of(&fa, &fa2, 1, 2, &a.0).is_ok());
        let err = check_reopened_is_bind_of(&fa, &fb, 1, 2, &a.0).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::PrepareRootfs);
    }

    /// CORE-1: mountinfo から親マウント ID を取り出す。
    #[test]
    fn core1_mount_parent_in_reads_second_field() {
        let info = "10 1 8:1 / / rw - ext4 /dev/sda1 rw\n11 10 0:5 / /proc rw - proc proc rw\n";
        assert_eq!(mount_parent_in(info, 11), Some(10));
        assert_eq!(mount_parent_in(info, 12), None);
        assert_eq!(mount_parent_in("10 1 a\n10 2 b\n", 10), None);
    }

    /// CORE-1: 新 root の直下に既存マウントが複製されていれば拒否し、無ければ通す。
    #[test]
    fn core1_check_no_submounts_rejects_cloned_mounts() {
        let rootfs = Path::new("/r");
        let clean = "10 1 8:1 / / rw - ext4 /dev/sda1 rw\n20 10 8:1 /r /r rw - ext4 /dev/sda1 rw\n";
        assert!(check_no_submounts(clean, 20, rootfs).is_ok());
        let dirty = format!("{clean}21 20 8:1 /home /r/mnt/host rw - ext4 /dev/sda1 rw\n");
        let err = check_no_submounts(&dirty, 20, rootfs).unwrap_err();
        assert_eq!(
            violation_of(&err),
            (
                "rootfs_pivot",
                "rootfs_has_submounts",
                "CORE-1",
                Some("/r".to_string())
            )
        );
        assert_eq!(err.stage, IsolationStage::PrepareRootfs);
        let err = check_no_submounts("bad line\n", 20, rootfs).unwrap_err();
        assert_eq!(err.message, "malformed line in /proc/thread-self/mountinfo");
    }

    /// CORE-1: bind 後にマウント ID が変わっていなければ拒否する。
    #[test]
    fn core1_bind_reopen_requires_new_mount_id() {
        assert!(check_bind_created_mount(10, 11).is_ok());
        let err = check_bind_created_mount(10, 10).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::PrepareRootfs);
        assert_eq!(
            err.message,
            "the rootfs bind mount did not create a new mount"
        );
    }
}
