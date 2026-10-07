//! rootfs 配下への tmpfs マウント（SUP-12・TASK-169.2・MS-9。`--shm-size` / `--tmpfs`）。
//!
//! # 役割と呼び出し文脈
//!
//! supervisor の `container_options` が解析した [`TmpfsMountSet`] を、`crate::exec` の最小実行フローの
//! 「[`prepare_rootfs`](super::prepare_rootfs) の後・[`pivot_root`](super::pivot_root) の前」で実マウントする。
//! `/dev/shm` を含む場合は [`create_default_devices`](super::create_default_devices) の後に呼ぶ。
//!
//! ```text
//! prepare_rootfs -> create_default_devices -> mount_tmpfs(&isolation, &prepared, &set) -> pivot_root
//! ```
//!
//! # 契約
//!
//! - **fd 起点**: [`PreparedRootfs`] の新しい mount top の fd から、正規化済みのマウント先を 1 要素ずつ
//!   `O_PATH|O_DIRECTORY|O_NOFOLLOW` で辿る。存在しない要素は 0755 で作り、同じ方法で開き直す。
//!   symlink・非ディレクトリは `path_symlink_or_not_directory` の違反記録付きで拒否する（rootfs の外へ
//!   マウントしない）。パス文字列で `mount(2)` しない（`/proc/thread-self/fd/N` 経由）
//! - **ホストへ伝播させない**: マウント直前に対象マウントが shared propagation でないことを確認する
//! - **移動検査**: fd 固定後にマウント先（または祖先）が改名・移動・削除されていないことを、マウント
//!   直前に fd の現在の位置で確かめる（`mount_proc` と同じ `fd_still_at`。`target_moved` の違反記録付きで
//!   拒否）。移動後の実体へマウントして rootfs 内の別の場所を覆わないようにする
//! - **フラグ・data**: `nosuid`・`nodev` は常に付与し外せない。data は [`TmpfsMountSpec::data_string`]
//!   （型付きフィールドのみ）で、利用者文字列は渡さない
//! - **事後条件**: マウント後に同じ要素を開き直し（作成はしない）、`statfs` が tmpfs であることを
//!   確かめる（fail-closed）
//! - **失敗時はプロセスを破棄する**: 途中のマウントは巻き戻さない（`crate::exec` のモジュール doc の契約）。
//!   マウントは呼び出しスレッド専用の mount namespace に閉じ、プロセスの破棄で消える。自動作成した
//!   マウント先ディレクトリ（0755・空）は rootfs に残る（後段の検査で拒否した場合も削除しない）
//! - **同一スレッド**: `MountIsolation::establish` と同じスレッドで呼ぶ
//!
//! # 未対応（REPAIR-3: 実装済みを装わない）
//!
//! 本番 launcher・CLI・stack（TOML）からの配線（TASK-79・TASK-169 の後続）、`--shm-size` 未指定時の
//! `/dev/shm` 既定 64 MiB の常時マウント、OCI `mounts[]` 全般（TASK-127・TASK-29 系）。
//!
//! # 単体テストの安全策
//!
//! `mount(2)` は `cfg(test)` では dry-run に差し替わる（`mount_tmpfs_syscall`）。実機での挙動は結合試験
//! `tests/tmpfs_mount.rs`（`-- --ignored`）で確認する。

use std::ffi::{CString, OsStr};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::path::PathBuf;

use crate::sys::{self, SysError};
use crate::tmpfs::{TmpfsMountSet, TmpfsMountSpec};
use crate::traits::types::ErrorCode;

use super::{
    ExecError, IsolationStage, MountIsolation, PreparedRootfs, ViolationReason, fd_still_at,
    mount_is_shared, open_error,
};

const STAGE: IsolationStage = IsolationStage::MountTmpfs;

/// 作成するマウント先ディレクトリのモード。
const DIR_MODE: u32 = 0o755;

/// 適用した tmpfs 1 件の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TmpfsMountOutcome {
    /// コンテナ内のマウント先（正規化済み）。
    pub destination: String,
    /// 指定したサイズ（バイト）。`None` はカーネル既定。
    pub size: Option<u64>,
    /// 読み取り専用でマウントしたか。
    pub read_only: bool,
    /// 実行を許したか（偽なら `noexec`）。
    pub exec: bool,
}

/// [`mount_tmpfs`] の成功結果（将来の拡張に備えた非網羅の構造体）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TmpfsReport {
    /// 指定順に適用した結果。
    pub mounts: Vec<TmpfsMountOutcome>,
}

/// `set` の tmpfs を rootfs（`prepared` の新しい mount top）配下へ指定順にマウントする。
///
/// [`MountIsolation`] の証跡が現在の状態と一致しなければ副作用なしに拒否する（fail-closed）。
/// 詳細な契約はモジュール doc を参照。
pub fn mount_tmpfs(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    set: &TmpfsMountSet,
) -> Result<TmpfsReport, ExecError> {
    isolation.verify_caller(STAGE)?;
    mount_tmpfs_at(prepared.new_root(), set, &|dir| mount_is_shared(dir, STAGE))
}

/// [`mount_tmpfs`] の証跡検証後の本体。`root` は rootfs（新しい mount top）の fd、`is_shared` は
/// マウント先が shared propagation かの判定（単体テストは host の mountinfo に依存しないよう差し替える）。
fn mount_tmpfs_at(
    root: BorrowedFd<'_>,
    set: &TmpfsMountSet,
    is_shared: &dyn Fn(&OwnedFd) -> Result<bool, ExecError>,
) -> Result<TmpfsReport, ExecError> {
    let rootfs = root_display(root);
    let mut mounts = Vec::with_capacity(set.mounts().len());
    for spec in set.mounts() {
        apply_one(root, &rootfs, spec, is_shared)?;
        mounts.push(TmpfsMountOutcome {
            destination: spec.destination.as_str().to_owned(),
            size: spec.size.map(|s| s.bytes()),
            read_only: spec.read_only,
            exec: spec.exec,
        });
    }
    Ok(TmpfsReport { mounts })
}

fn apply_one(
    root: BorrowedFd<'_>,
    rootfs: &std::path::Path,
    spec: &TmpfsMountSpec,
    is_shared: &dyn Fn(&OwnedFd) -> Result<bool, ExecError>,
) -> Result<(), ExecError> {
    let names: Vec<&OsStr> = spec
        .destination
        .as_str()
        .split('/')
        .filter(|e| !e.is_empty())
        .map(OsStr::new)
        .collect();
    let dir = open_chain(root, rootfs, &names, Missing::Create)?;
    let subject = names.iter().fold(rootfs.to_path_buf(), |p, n| p.join(n));
    if is_shared(&dir)? {
        return Err(ExecError::from_violation_at(
            ViolationReason::TargetOnSharedMount,
            Some(&subject),
            STAGE,
        ));
    }
    // fd 固定後に別プロセスがマウント先（または祖先）を改名・移動・削除していれば拒否する
    // （`mount_proc_at_dir` と同じ検査）。この確認から mount(2) までに移動された場合も、マウントは
    // 呼び出しスレッド専用の mount namespace に閉じ、事後条件（`verify_mounted`）が名前の位置に
    // tmpfs が無いことを検出して失敗させる。
    if !fd_still_at(&dir, &subject) {
        return Err(ExecError::from_violation_at(
            ViolationReason::TargetMoved,
            Some(&subject),
            STAGE,
        ));
    }
    let target =
        CString::new(format!("/proc/thread-self/fd/{}", dir.as_raw_fd())).map_err(|_| {
            ExecError::new(
                ErrorCode::Internal,
                STAGE,
                "failed to build the fd path of the tmpfs mount target",
            )
        })?;
    let data = CString::new(spec.data_string()).map_err(|_| {
        ExecError::new(
            ErrorCode::Internal,
            STAGE,
            "failed to build the tmpfs mount data",
        )
    })?;
    let flags = sys::TmpfsMountFlags {
        read_only: spec.read_only,
        exec: spec.exec,
    };
    mount_tmpfs_syscall(&target, flags, &data).map_err(|e| {
        ExecError::from_sys(
            e,
            STAGE,
            &format!("mount(tmpfs on {})", spec.destination.as_str()),
        )
    })?;
    verify_mounted(root, rootfs, &names, spec)
}

/// [`open_chain`] が存在しない要素をどう扱うか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Missing {
    /// 0755 で作ってから同じ方法で開き直す（マウント先の準備）。
    Create,
    /// 作らずに `path_missing` の違反記録付きで拒否する（事後検証。副作用を持たせない）。
    Reject,
}

/// `root` から `names` を 1 要素ずつ `O_PATH|O_DIRECTORY|O_NOFOLLOW` で開く。無い要素の扱いは `missing`。
fn open_chain(
    root: BorrowedFd<'_>,
    rootfs: &std::path::Path,
    names: &[&OsStr],
    missing: Missing,
) -> Result<OwnedFd, ExecError> {
    use std::os::unix::ffi::OsStrExt as _;
    let mut cur: Option<OwnedFd> = None;
    for name in names {
        let c = CString::new(name.as_bytes()).map_err(|_| {
            ExecError::from_violation_at(ViolationReason::PathContainsNul, Some(rootfs), STAGE)
        })?;
        let parent = cur.as_ref().map_or(root, |f| f.as_fd());
        let next = match sys::open_dir_path_nofollow(Some(parent), &c) {
            Ok(fd) => fd,
            Err(SysError::Os(sys::ENOENT)) if missing == Missing::Create => {
                match sys::mkdir_at(parent, &c, DIR_MODE) {
                    Ok(()) | Err(SysError::Os(sys::EEXIST)) => {}
                    Err(e) => return Err(ExecError::from_sys(e, STAGE, "mkdirat(mount target)")),
                }
                // 競合で先に作られた場合も、開き直しで種別（symlink・非ディレクトリ）を検証する。
                sys::open_dir_path_nofollow(Some(parent), &c)
                    .map_err(|e| open_error(e, true, rootfs, names).at_stage(STAGE))?
            }
            Err(e) => return Err(open_error(e, true, rootfs, names).at_stage(STAGE)),
        };
        cur = Some(next);
    }
    cur.ok_or_else(|| {
        ExecError::new(
            ErrorCode::InvalidArgument,
            STAGE,
            "tmpfs mount destination is empty",
        )
    })
}

/// マウント後に同じ要素を開き直し、tmpfs であることを確かめる。本体は cfg で差し替わる
/// `fstatfs_magic_at` を介すだけで、`cfg(test)` の分岐は持たない（判定本体 [`check_tmpfs_magic`] は単体で試験する）。
fn verify_mounted(
    root: BorrowedFd<'_>,
    rootfs: &std::path::Path,
    names: &[&OsStr],
    spec: &TmpfsMountSpec,
) -> Result<(), ExecError> {
    let magic = fstatfs_magic_at(root, rootfs, names)?;
    check_tmpfs_magic(magic, spec.destination.as_str())
}

#[cfg(not(test))]
fn fstatfs_magic_at(
    root: BorrowedFd<'_>,
    rootfs: &std::path::Path,
    names: &[&OsStr],
) -> Result<i64, ExecError> {
    let dir = open_chain(root, rootfs, names, Missing::Reject)?;
    sys::fs_type(dir.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "fstatfs(tmpfs mount target)"))
}

/// dry-run: 実マウントが無いため tmpfs のマジックを返す（実機の検証は結合試験で行う）。
#[cfg(test)]
fn fstatfs_magic_at(
    _root: BorrowedFd<'_>,
    _rootfs: &std::path::Path,
    _names: &[&OsStr],
) -> Result<i64, ExecError> {
    Ok(sys::TMPFS_MAGIC)
}

/// 事後条件の判定（純関数）。`statfs.f_type` が tmpfs でなければ拒否する。
fn check_tmpfs_magic(magic: i64, destination: &str) -> Result<(), ExecError> {
    if magic == sys::TMPFS_MAGIC {
        return Ok(());
    }
    Err(ExecError::new(
        ErrorCode::FailedPrecondition,
        STAGE,
        format!("the mount at {destination} is not tmpfs after mount"),
    ))
}

/// 違反記録の対象表示用に rootfs の実パスを得る（取れなければ固定文字列）。
fn root_display(root: BorrowedFd<'_>) -> PathBuf {
    std::fs::read_link(format!("/proc/thread-self/fd/{}", root.as_raw_fd()))
        .unwrap_or_else(|_| PathBuf::from("<rootfs>"))
}

#[cfg(not(test))]
fn mount_tmpfs_syscall(
    target: &std::ffi::CStr,
    flags: sys::TmpfsMountFlags,
    data: &std::ffi::CStr,
) -> Result<(), SysError> {
    sys::mount_tmpfs_at(target, flags, data)
}

/// dry-run: `mount(2)` を呼ばず、(解決したマウント先・フラグ・data) を記録する。
#[cfg(test)]
fn mount_tmpfs_syscall(
    target: &std::ffi::CStr,
    flags: sys::TmpfsMountFlags,
    data: &std::ffi::CStr,
) -> Result<(), SysError> {
    let resolved = std::fs::read_link(target.to_string_lossy().as_ref())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    tests::CALLS.with(|c| {
        c.borrow_mut()
            .push((resolved, flags.bits(), data.to_string_lossy().into_owned()))
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::symlink;

    thread_local! {
        pub(super) static CALLS: std::cell::RefCell<Vec<(String, u64, String)>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    fn take_calls() -> Vec<(String, u64, String)> {
        CALLS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::fs::canonicalize(std::env::temp_dir())
                .expect("tmp")
                .join(format!("fandhe-tmpfs-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).expect("mkdir");
            Self(p)
        }
        fn fd(&self) -> OwnedFd {
            sys::open_dir_path_nofollow(
                None,
                &CString::new(self.0.to_str().expect("utf8")).expect("c"),
            )
            .expect("open")
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn set(specs: &[(&str, Option<u64>)]) -> TmpfsMountSet {
        let mut s = TmpfsMountSet::new();
        for (d, size) in specs {
            let size = size.map(|b| crate::tmpfs::TmpfsSize::from_bytes(b).expect("size"));
            s.push(TmpfsMountSpec::new(d, size).expect("spec"))
                .expect("push");
        }
        s
    }

    fn not_shared(_: &OwnedFd) -> Result<bool, ExecError> {
        Ok(false)
    }

    /// SUP-12・TASK-169.2: 指定順に適用し、フラグ・data が具体値で一致し、先を自動作成する。
    #[test]
    fn sup12_task169_2_applies_in_order_and_creates_targets() {
        let tmp = Tmp::new("order");
        let _ = take_calls();
        let fd = tmp.fd();
        let s = set(&[("/dev/shm", Some(65536)), ("/scratch/a", None)]);
        let report = mount_tmpfs_at(fd.as_fd(), &s, &not_shared).expect("mount");
        let calls = take_calls();
        let nosuid_nodev_noexec = 2 | 4 | 8;
        assert_eq!(
            calls,
            vec![
                (
                    tmp.0.join("dev/shm").to_string_lossy().into_owned(),
                    nosuid_nodev_noexec,
                    "mode=1777,size=65536".to_owned()
                ),
                (
                    tmp.0.join("scratch/a").to_string_lossy().into_owned(),
                    nosuid_nodev_noexec,
                    "mode=1777".to_owned()
                ),
            ]
        );
        assert!(tmp.0.join("dev/shm").is_dir());
        assert!(tmp.0.join("scratch/a").is_dir());
        assert_eq!(report.mounts.len(), 2);
        assert_eq!(report.mounts[0].destination, "/dev/shm");
        assert_eq!(report.mounts[0].size, Some(65536));
        assert_eq!(report.mounts[1].size, None);
    }

    /// SUP-12・TASK-169.2: 途中要素が symlink なら rootfs の外へ出さず違反記録付きで拒否する。
    #[test]
    fn sup12_task169_2_rejects_symlink_component() {
        let tmp = Tmp::new("symlink");
        let _ = take_calls();
        std::fs::create_dir_all(tmp.0.join("outside")).expect("outside");
        symlink(tmp.0.join("outside"), tmp.0.join("link")).expect("symlink");
        let fd = tmp.fd();
        let err = mount_tmpfs_at(fd.as_fd(), &set(&[("/link/x", None)]), &not_shared)
            .expect_err("symlink");
        assert_eq!(err.stage, IsolationStage::MountTmpfs);
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathSymlinkOrNotDirectory)
        );
        assert!(take_calls().is_empty());
        assert!(!tmp.0.join("outside/x").exists());
    }

    /// SUP-12・TASK-169.2: shared propagation 上では mount せずに拒否する。
    #[test]
    fn sup12_task169_2_rejects_shared_mount() {
        let tmp = Tmp::new("shared");
        let _ = take_calls();
        let fd = tmp.fd();
        let err =
            mount_tmpfs_at(fd.as_fd(), &set(&[("/run", None)]), &|_| Ok(true)).expect_err("shared");
        assert_eq!(err.stage, IsolationStage::MountTmpfs);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::TargetOnSharedMount)
        );
        assert!(take_calls().is_empty());
    }

    /// SUP-12・TASK-169.2: fd 固定後にマウント先が改名されたら、移動後の実体へ mount せず
    /// `target_moved` の違反記録付きで拒否する（propagation 判定の差し込み点で改名して窓を再現する）。
    #[test]
    fn sup12_task169_2_rejects_target_moved_after_pin() {
        let tmp = Tmp::new("moved");
        let _ = take_calls();
        let fd = tmp.fd();
        let (from, to) = (tmp.0.join("run"), tmp.0.join("elsewhere"));
        let err = mount_tmpfs_at(fd.as_fd(), &set(&[("/run", None)]), &|_| {
            std::fs::rename(&from, &to).expect("rename");
            Ok(false)
        })
        .expect_err("moved");
        assert_eq!(err.stage, IsolationStage::MountTmpfs);
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::TargetMoved)
        );
        assert_eq!(take_calls(), Vec::new());
    }

    /// SUP-12・TASK-169.2: 事後検証の開き直しは無い要素を作らず `path_missing` で拒否する。
    #[test]
    fn sup12_task169_2_reject_mode_does_not_create_missing() {
        let tmp = Tmp::new("nocreate");
        let fd = tmp.fd();
        let names = [OsStr::new("a"), OsStr::new("b")];
        let err = open_chain(fd.as_fd(), &tmp.0, &names, Missing::Reject).expect_err("missing");
        assert_eq!(err.stage, IsolationStage::MountTmpfs);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathMissing)
        );
        assert!(!tmp.0.join("a").exists());
        open_chain(fd.as_fd(), &tmp.0, &names, Missing::Create).expect("create");
        assert!(tmp.0.join("a/b").is_dir());
    }

    /// SUP-12・TASK-169.2: 読み取り専用・exec 許可のフラグが反映される。
    #[test]
    fn sup12_task169_2_flags_reflect_spec() {
        let tmp = Tmp::new("flags");
        let _ = take_calls();
        let fd = tmp.fd();
        let mut s = TmpfsMountSet::new();
        let mut spec = TmpfsMountSpec::new("/ro", None).expect("spec");
        spec.read_only = true;
        spec.exec = true;
        s.push(spec).expect("push");
        mount_tmpfs_at(fd.as_fd(), &s, &not_shared).expect("mount");
        // MS_RDONLY(1)|MS_NOSUID(2)|MS_NODEV(4)、noexec なし。
        assert_eq!(take_calls().first().map(|c| c.1), Some(1 | 2 | 4));
    }

    /// SUP-12・TASK-169.2: 事後条件は tmpfs のマジックだけを通す。
    #[test]
    fn sup12_task169_2_post_condition_requires_tmpfs_magic() {
        assert!(check_tmpfs_magic(0x0102_1994, "/run").is_ok());
        let err = check_tmpfs_magic(0xEF53, "/run").expect_err("ext4");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::MountTmpfs);
    }
}
