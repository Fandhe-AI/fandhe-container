//! `pivot_root(2)` による rootfs 切替と旧 root の後始末（CORE-1・TASK-27.3・#135・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! `crate::exec` の最小実行フロー第 2 段。新しい PID namespace の PID 1 が
//! [`MountIsolation::establish`] で自分だけの mount namespace を作った後に、次の 2 段を順に通す
//! （呼び出し元は TASK-29 の `oci_runtime` と fork 段〔#831〕を想定。基本デバイスノード作成
//! 〔[`super::create_default_devices`]・#834・TASK-27.6〕や CDI hook〔TASK-127〕は 2 段の間に差し込む）。
//!
//! ```text
//! MountIsolation::establish()
//!   -> prepare_rootfs(&isolation, rootfs) -> PreparedRootfs   // 自己 bind -> nodev -> rootfs/proc へ procfs
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
//! - **外部 inode へのハードリンクは拒否する**: rootfs 内の非ディレクトリが rootfs の外にもリンク
//!   を持つ（`st_nlink` が rootfs 内のリンク数を超える）と、pivot 後の書き込みで外部ファイルが
//!   変わる。bind 前に走査し `ViolationReason::RootfsHasExternalHardlink` で拒否する
//! - **自己 bind のマウントは常に `nodev`（#1676・SEC-1・CORE-1・TASK-27.3）**: 初回の `MS_BIND` は
//!   フラグを無視するため、イメージが `/dev` 以外に同梱したデバイスノードが開けてしまう。そこで bind 後に
//!   開き直した mount top の fd へ `mount_setattr(2)`（`sys::set_mount_nodev`。Linux 5.12 以降。`ENOSYS` は
//!   `Unimplemented` で拒否し `mount(2)` へ縮退しない）で `nodev` を足し、`fstatfs` の `ST_NODEV` で事後検証する。
//!   - mount top 1 枚だけ・再帰なし。submount は拒否済みのため rootfs 全体を覆う。`/dev` の tmpfs・devpts・
//!     rootless の基本デバイスの bind（#1660）は後から別のマウントとして載るので `nodev` にならず、既定の
//!     デバイスノード 6 種は使える。procfs も同様
//!   - rootful・rootless を問わず常に掛ける（オーナー判断 2026-10-10）。user namespace の種類で分岐しないため、
//!     入れ子の user namespace の中で動く構成でも黙って外れない。rootless（非初期 user ns）では mount namespace を
//!     所有する user ns の `CAP_SYS_ADMIN` で足せる。付与・事後検証の失敗は `EPERM` を含め fail-closed で拒否する
//!   - Linux 5.12 の要件は Landlock ABI 6（Linux 6.12 以降。CORE-5）の前提に含まれる
//!   - CDI `deviceNodes`（TASK-127・#547）を `/dev` 以外へ置くと、この `nodev` で開けなくなる。配置先は TASK-127 で決める
//!   - 多層防御のもう一方であるデバイス cgroup は #1677 で扱う
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
//! `mount(2)`・`mount_setattr(2)`・`pivot_root(2)` は `cfg(test)` では dry-run に差し替わる
//! （`bind_syscall`・`nodev_syscall`・`switch_root`）。root で `cargo test` を実行してもホストの mount namespace へは届かない。
//! shared propagation の判定（`mount_is_shared`）も `cfg(test)` で差し込めるようにし、実行環境（CI の ubuntu は shared）に
//! 依らず nodev の順序・値・失敗経路を照合する（#1676）。
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

impl PreparedRootfs {
    /// 新しい mount top を指す O_PATH fd の借用。`super::create_default_devices` が、パス文字列を
    /// 再解決せずこの fd 起点で `dev` を開くために使う（TASK-27.6）。
    pub(super) fn new_root(&self) -> BorrowedFd<'_> {
        self.new_root.as_fd()
    }
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
    /// rootfs の自己 bind に `nodev` を足し、`ST_NODEV` を事後検証済みか（#1676・SEC-1・REPAIR-4）。
    /// rootful・rootless を問わず常に付与する（オーナー判断 2026-10-10）ため、成功した [`pivot_root`] では常に真。
    /// 付与済みであることの証跡として呼び出し側が記録・照合できるよう残す。
    pub rootfs_nodev: bool,
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
/// 7. mount top に `nodev` を足し、`ST_NODEV` を事後検証する（#1676。rootful・rootless とも）
/// 8. bind が複製した rootfs 配下の既存マウントが 1 つでもあれば拒否する（`RootfsHasSubmounts`）
/// 9. 新しい mount top 起点で `proc` を開き直し、procfs をマウントする
pub fn prepare_rootfs(
    isolation: &MountIsolation,
    rootfs: &Path,
) -> Result<PreparedRootfs, ExecError> {
    isolation.verify_caller(IsolationStage::PrepareRootfs)?;
    prepare_rootfs_verified(rootfs)
}

/// rootfs の mount top が `nodev` であることの事後検証（純関数。fail-closed）。`ST_VALID` が無い値は信用しない。
fn check_rootfs_is_nodev(flags: sys::MountFlags) -> Result<(), ExecError> {
    if !flags.is_valid() || !flags.is_nodev() {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::PrepareRootfs,
            "the rootfs mount is not nodev after mount_setattr",
        ));
    }
    Ok(())
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
    // bind の前（副作用なし）に、rootfs の外へ inode を共有するハードリンクが無いことを確認する。
    check_no_external_hardlinks(Path::new(OsStr::from_bytes(c_target.as_bytes())), rootfs)?;
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

    // 初回の `MS_BIND` はフラグを無視するため、検証済みの mount top の fd へ `nodev` を足す（#1676・SEC-1）。
    // rootful・rootless を問わず常に掛ける（オーナー判断 2026-10-10）。`/dev` の tmpfs を載せる前に済ませる。
    // submount は下で拒否するので mount top 1 枚で rootfs 全体を覆う。失敗（`EPERM`・`ENOSYS` 等）は縮退しない。
    nodev_syscall(new_root.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "mount_setattr(MOUNT_ATTR_NODEV)"))?;
    // dry-run（`cfg(test)`）では実マウントが無く、ホストの一時領域の nodev 有無で結果が揺れるため検証しない。
    if !cfg!(test) {
        let flags = sys::mount_flags(new_root.as_fd())
            .map_err(|e| ExecError::from_sys(e, STAGE, "fstatfs(rootfs)"))?;
        check_rootfs_is_nodev(flags)?;
    }

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

/// mountinfo の 1 行から `(id, parent, major:minor)` を取り出す。書式不正は `None`。
fn mount_ids_dev(line: &str) -> Option<(u64, u64, &str)> {
    let mut f = line.split(' ');
    let id: u64 = f.next()?.parse().ok()?;
    let parent: u64 = f.next()?.parse().ok()?;
    let dev = f.next()?;
    Some((id, parent, dev))
}

/// bind 後の新マウントが今回の bind 由来であることを、bind 元の同一性と親子関係で別々に確認する
/// （純関数。fail-closed）。
///
/// - 同一性: 新マウントと bind 前のマウントが同じ `major:minor`（同じ superblock）である
/// - 親子関係: 新マウントの親が bind 前のマウント自身、またはその親である。rootfs が既存の
///   マウントポイントのとき、カーネルは新マウントを bind 前のマウントの上（親 = bind 前のマウント）
///   にも、それを載せているマウントの上（親 = bind 前のマウントの親）にも作り得るため、
///   親 ID が bind 前のマウント ID に一致することだけを要求しない
fn bind_lineage_ok(info: &str, before_mnt_id: u64, new_mnt_id: u64) -> bool {
    let mut before = None;
    let mut new = None;
    for line in info.lines() {
        let Some((id, parent, dev)) = mount_ids_dev(line) else {
            return false;
        };
        if id == before_mnt_id {
            if before.is_some() {
                return false;
            }
            before = Some((parent, dev));
        }
        if id == new_mnt_id {
            if new.is_some() {
                return false;
            }
            new = Some((parent, dev));
        }
    }
    let (Some((before_parent, before_dev)), Some((new_parent, new_dev))) = (before, new) else {
        return false;
    };
    before_dev == new_dev && (new_parent == before_mnt_id || new_parent == before_parent)
}

/// 走査するエントリ数の上限（巨大 rootfs による無制限の時間・メモリ消費を防ぐ）。
const HARDLINK_SCAN_MAX_ENTRIES: usize = 4_000_000;

/// rootfs 内の非ディレクトリが、rootfs の外にもハードリンクを持たないことを確認する（CORE-1）。
///
/// rootfs と同じファイルシステム上の外部 inode へのハードリンクは、pivot 後の書き込みで外部ファイル
/// を書き換えられる経路になる（サブマウントの拒否では防げない）。rootfs 配下を走査し、`st_nlink > 1`
/// の inode ごとに rootfs 内で見つかったリンク数を数え、`st_nlink` に満たなければ外部にもリンクが
/// あるとみなして拒否する。rootfs 内で完結するリンク（レイヤ展開由来）は許可する。別デバイスの
/// ディレクトリ（既存サブマウント）へは降りない（bind が複製した場合は別途拒否する）。エントリ数が
/// 上限を超える・読み取れない場合も fail-closed で拒否する。`root` は固定した rootfs fd の
/// `/proc/thread-self/fd/N`（パス文字列を再解決しない）。
fn check_no_external_hardlinks(root: &Path, rootfs: &Path) -> Result<(), ExecError> {
    use std::collections::HashMap;
    const STAGE: IsolationStage = IsolationStage::PrepareRootfs;
    let reject = || {
        ExecError::from_violation_at(
            ViolationReason::RootfsHasExternalHardlink,
            Some(rootfs),
            STAGE,
        )
    };
    let io_err = |e: std::io::Error| ExecError::from_io(&e, STAGE, "scan(rootfs hardlinks)");
    let root_dev = std::fs::metadata(root).map_err(io_err)?.dev();
    let mut seen: HashMap<(u64, u64), (u64, u64)> = HashMap::new();
    let mut stack = vec![root.to_path_buf()];
    let mut entries = 0usize;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).map_err(io_err)? {
            let entry = entry.map_err(io_err)?;
            entries += 1;
            if entries > HARDLINK_SCAN_MAX_ENTRIES {
                return Err(ExecError::new(
                    ErrorCode::FailedPrecondition,
                    STAGE,
                    "rootfs has too many entries to scan for hard links",
                ));
            }
            let meta = std::fs::symlink_metadata(entry.path()).map_err(io_err)?;
            if meta.is_dir() {
                if meta.dev() == root_dev {
                    stack.push(entry.path());
                }
            } else if meta.nlink() > 1 {
                let slot = seen
                    .entry((meta.dev(), meta.ino()))
                    .or_insert((meta.nlink(), 0));
                slot.1 += 1;
            }
        }
    }
    if seen.values().any(|&(nlink, found)| found < nlink) {
        return Err(reject());
    }
    Ok(())
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
/// - 本番ビルドでは、bind 元の同一性（同じ `major:minor` のデバイス）と親子関係（[`bind_lineage_ok`]）
///   を別々に検証する（`cfg(test)` の dry-run では bind が作られないので省略する）
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
        if !bind_lineage_ok(&info, before_mnt_id, new_mnt_id) {
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
        rootfs_nodev: true,
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

/// [`prepare_rootfs`] の `nodev` 付与。本番ビルドでは [`sys::set_mount_nodev`]。
#[cfg(not(test))]
fn nodev_syscall(mount_top: BorrowedFd<'_>) -> Result<(), SysError> {
    sys::set_mount_nodev(mount_top)
}

/// テストビルドの dry-run 差し込み点。`mount_setattr(2)` を呼ばず、呼び出しの文脈を記録するだけにする。
#[cfg(test)]
fn nodev_syscall(mount_top: BorrowedFd<'_>) -> Result<(), SysError> {
    if let Some(e) = tests::DRY_RUN_NODEV_FAIL.with(|f| f.take()) {
        return Err(e);
    }
    let rec = tests::NodevCall {
        fd: mount_top.as_raw_fd(),
        params: sys::rootfs_nodev_call_params(),
        binds_seen: tests::DRY_RUN_BINDS.with(|b| b.borrow().len()),
        mounts_seen: crate::exec::tests::peek_dry_run_mounts_len(),
    };
    tests::DRY_RUN_NODEV.with(|n| n.borrow_mut().push(rec));
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
        /// dry-run の `nodev_syscall` の記録（テストスレッドごと）。
        pub(super) static DRY_RUN_NODEV: RefCell<Vec<NodevCall>> = const { RefCell::new(Vec::new()) };
        /// 次の `nodev_syscall` に返させる失敗（`ENOSYS` 相当の注入用）。
        pub(super) static DRY_RUN_NODEV_FAIL: std::cell::Cell<Option<SysError>> =
            const { std::cell::Cell::new(None) };
    }

    /// shared propagation の判定を `shared` に固定して `prepare_rootfs_verified` を呼ぶ（呼び出し後に戻す）。
    fn prepare_with_shared(rootfs: &Path, shared: bool) -> Result<PreparedRootfs, ExecError> {
        crate::exec::tests::DRY_RUN_SHARED.with(|s| s.set(Some(shared)));
        let result = prepare_rootfs_verified(rootfs);
        crate::exec::tests::DRY_RUN_SHARED.with(|s| s.set(None));
        result
    }

    /// dry-run の `nodev_syscall` が記録した 1 回分の呼び出し。
    #[derive(Debug)]
    pub(super) struct NodevCall {
        pub(super) fd: i32,
        /// `(attr_set, attr_clr, propagation, userns_fd, flags, size)`。
        pub(super) params: (u64, u64, u64, u64, u32, usize),
        /// 呼び出し時点の bind の dry-run 件数。
        pub(super) binds_seen: usize,
        /// 呼び出し時点の procfs の dry-run マウント件数。
        pub(super) mounts_seen: usize,
    }

    fn take_nodev_calls() -> Vec<NodevCall> {
        DRY_RUN_NODEV_FAIL.with(|f| f.set(None));
        DRY_RUN_NODEV.with(|n| std::mem::take(&mut *n.borrow_mut()))
    }

    /// dry-run の記録を取り出して空にする（libtest のワーカースレッド再利用で前のテストの記録が
    /// 漏れないよう、照合は必ずこの関数で取り出して行う）。
    fn take_dry_runs() -> (Vec<String>, Vec<String>, u32) {
        let binds = DRY_RUN_BINDS.with(|b| std::mem::take(&mut *b.borrow_mut()));
        let mounts = crate::exec::tests::take_dry_run_mounts();
        let switches = DRY_RUN_SWITCHES.with(|s| std::mem::take(&mut *s.borrow_mut()));
        (binds, mounts, switches)
    }

    /// テスト用の一時ディレクトリ。`.0` は guard と同じパスで、削除は guard の drop が行う（#1298）。
    struct Tmp(
        PathBuf,
        #[allow(dead_code)] crate::test_support::TestTempDir,
    );

    impl Tmp {
        fn new(label: &str) -> Self {
            let guard = crate::test_support::TestTempDir::new(&format!("rootfs-{label}"))
                .expect("create exclusive temp dir");
            Self(guard.path().to_path_buf(), guard)
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

    /// CORE-1・SEC-1（#1676）: 有効な rootfs は（shared でなければ）dry-run の bind と procfs マウントまで進む。
    /// 順序は bind -> nodev -> procfs で、nodev はちょうど 1 回・mount top の fd 起点・固定値（rootful・rootless の
    /// 区別なく常に掛ける。オーナー判断 2026-10-10）。shared の判定は差し込み点で固定し、実行環境の propagation に
    /// 依らず必ずこの分岐を照合する。
    #[test]
    fn core1_prepare_rootfs_reaches_dry_run_mounts() {
        take_dry_runs();
        take_nodev_calls();
        let t = Tmp::new("valid");
        let rootfs = t.0.join("root");
        std::fs::create_dir_all(rootfs.join("proc")).unwrap();
        let prepared = prepare_with_shared(&rootfs, false).expect("prepare");
        let (binds, mounts, switches) = take_dry_runs();
        let calls = take_nodev_calls();
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!((calls[0].binds_seen, calls[0].mounts_seen), (1, 0));
        assert_eq!(calls[0].fd, prepared.new_root.as_raw_fd());
        assert_eq!(calls[0].params, (0x4, 0, 0, 0, 0x1000, 32));
        assert_eq!(calls[0].params.4 & 0x8000, 0);
        assert_eq!(binds.len(), 1, "{binds:?}");
        assert!(binds[0].starts_with("/proc/thread-self/fd/"), "{binds:?}");
        assert_eq!(mounts.len(), 1, "{mounts:?}");
        assert!(mounts[0].starts_with("/proc/thread-self/fd/"), "{mounts:?}");
        assert_eq!(switches, 0);
    }

    /// CORE-1・SEC-1（#1676）: shared propagation 上の rootfs は違反記録付きで拒否し、bind・nodev・procfs の
    /// いずれも呼ばない（副作用の前に止まる）。
    #[test]
    fn core1_prepare_rootfs_rejects_shared_before_nodev() {
        take_dry_runs();
        take_nodev_calls();
        let t = Tmp::new("shared");
        let rootfs = t.0.join("root");
        std::fs::create_dir_all(rootfs.join("proc")).unwrap();
        let err = prepare_with_shared(&rootfs, true).unwrap_err();
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
        assert_eq!(take_nodev_calls().len(), 0);
    }

    /// SEC-1（#1676）: nodev 付与の失敗は縮退せず拒否し、procfs へ進まない。`ENOSYS`（`Unsupported`）は
    /// `Unimplemented`、rootless で起こり得る `EPERM` は `PermissionDenied`（`mount(2)` へ縮退せず、nodev なしでも
    /// 進まない。オーナー判断 2026-10-10 の fail-closed）。bind は済んでいる（プロセスごと破棄する契約）。
    #[test]
    fn core1_prepare_rootfs_nodev_failure_is_fail_closed() {
        const EPERM: i32 = 1;
        let cases = [
            (
                SysError::Unsupported,
                ErrorCode::Unimplemented,
                "mount_setattr(MOUNT_ATTR_NODEV) failed: not supported by the kernel or the target architecture"
                    .to_string(),
            ),
            (
                SysError::Os(EPERM),
                ErrorCode::PermissionDenied,
                format!(
                    "mount_setattr(MOUNT_ATTR_NODEV) failed: {}",
                    std::io::Error::from_raw_os_error(EPERM)
                ),
            ),
        ];
        for (injected, code, message) in cases {
            take_dry_runs();
            take_nodev_calls();
            let t = Tmp::new("nodev-fail");
            let rootfs = t.0.join("root");
            std::fs::create_dir_all(rootfs.join("proc")).unwrap();
            DRY_RUN_NODEV_FAIL.with(|f| f.set(Some(injected)));
            let err = prepare_with_shared(&rootfs, false).unwrap_err();
            DRY_RUN_NODEV_FAIL.with(|f| f.set(None));
            assert_eq!(err.stage, IsolationStage::PrepareRootfs, "{injected:?}");
            assert_eq!(err.code, code, "{injected:?}");
            assert!(err.violation.is_none(), "{err:?}");
            assert_eq!(err.message, message, "{injected:?}");
            let (binds, mounts, switches) = take_dry_runs();
            assert_eq!(
                (binds.len(), mounts.len(), switches),
                (1, 0, 0),
                "{injected:?}"
            );
            assert_eq!(take_nodev_calls().len(), 0, "{injected:?}");
        }
    }

    /// SEC-1（#1676）: 事後検証は `ST_NODEV` と `ST_VALID` の両方を要求する。
    #[test]
    fn core1_sec1_check_rootfs_is_nodev() {
        assert!(check_rootfs_is_nodev(sys::MountFlags::from_bits(0x20 | 0x4)).is_ok());
        for bits in [0x20, 0x4, 0] {
            let err = check_rootfs_is_nodev(sys::MountFlags::from_bits(bits)).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "{bits:#x}");
            assert_eq!(err.stage, IsolationStage::PrepareRootfs, "{bits:#x}");
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

    /// CORE-1: bind 元の同一性（デバイス）と親子関係を別々に検証する。rootfs が既存マウントポイント
    /// （新マウントの親が bind 前マウントの親）でも通り、別デバイス・無関係な親・行の欠落は拒否する。
    #[test]
    fn core1_bind_lineage_checks_device_and_parent_separately() {
        let base = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n";
        // 親 = bind 前のマウント。
        let a = format!(
            "{base}10 1 8:1 /r /r rw - ext4 /dev/sda1 rw\n11 10 8:1 /r /r rw - ext4 /dev/sda1 rw\n"
        );
        assert!(bind_lineage_ok(&a, 10, 11));
        // 親 = bind 前マウントの親（rootfs が既存マウントポイント）。
        let b = format!(
            "{base}10 1 8:1 /r /r rw - ext4 /dev/sda1 rw\n11 1 8:1 /r /r rw - ext4 /dev/sda1 rw\n"
        );
        assert!(bind_lineage_ok(&b, 10, 11));
        // 別デバイスの差し替え。
        let c = format!(
            "{base}10 1 8:1 /r /r rw - ext4 /dev/sda1 rw\n11 10 8:2 / /r rw - ext4 /dev/sda2 rw\n"
        );
        assert!(!bind_lineage_ok(&c, 10, 11));
        // 無関係な親。
        let d = format!(
            "{base}10 1 8:1 /r /r rw - ext4 /dev/sda1 rw\n11 77 8:1 /r /r rw - ext4 /dev/sda1 rw\n"
        );
        assert!(!bind_lineage_ok(&d, 10, 11));
        // 行の欠落・書式不正・重複。
        assert!(!bind_lineage_ok(base, 10, 11));
        assert!(!bind_lineage_ok("x y z\n", 10, 11));
        let dup = format!("{a}11 10 8:1 /r /r rw - ext4 /dev/sda1 rw\n");
        assert!(!bind_lineage_ok(&dup, 10, 11));
    }

    /// CORE-1: rootfs 内で完結するハードリンクは許可し、rootfs 外にもリンクがあれば拒否する。
    #[test]
    fn core1_external_hardlink_is_rejected() {
        let t = Tmp::new("hardlink");
        let root = t.0.join("root");
        let outside = t.0.join("outside");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/a"), b"x").unwrap();
        std::fs::hard_link(root.join("etc/a"), root.join("etc/b")).unwrap();
        // rootfs 内で完結するリンクは許可。
        assert!(check_no_external_hardlinks(&root, &root).is_ok());
        // 外部ファイルへのハードリンクを rootfs に置く。
        std::fs::write(&outside, b"secret").unwrap();
        std::fs::hard_link(&outside, root.join("etc/leak")).unwrap();
        let err = check_no_external_hardlinks(&root, &root).unwrap_err();
        assert_eq!(err.stage, IsolationStage::PrepareRootfs);
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            violation_of(&err),
            (
                "rootfs_pivot",
                "rootfs_has_external_hardlink",
                "CORE-1",
                Some(root.to_str().unwrap().to_string())
            )
        );
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
