//! secrets / configs の注入（SUP-12・TASK-169.4.2・SEC-1・MS-9）。専用 tmpfs へ書き込み、read-only にする。
//!
//! # 役割と呼び出し文脈
//!
//! supervisor の `container_options` が解析した [`InjectedFileSet`] を、`crate::exec` の最小実行フローの
//! 「[`mount_tmpfs`](super::mount_tmpfs) の後・[`pivot_root`](super::pivot_root) の前」で注入する。
//!
//! ```text
//! prepare_rootfs -> create_default_devices -> mount_tmpfs -> inject_files(&isolation, &prepared, &set) -> pivot_root
//! ```
//!
//! 親ディレクトリごとに専用 tmpfs を 1 つ作り（rw・`nosuid,nodev,noexec`）、その tmpfs のルート fd の直下へ
//! 内容を書いてから read-only にする。コンテナ内からは書き込み・削除・`chmod` がすべて `EROFS` で
//! 拒否される（`CAP_SYS_ADMIN` と `mount_setattr`・`mount` の seccomp 拒否により ro を外せない。SEC-1）。
//!
//! # 契約
//!
//! - **内容の置き場**: 書き込み先は事後検証で「マウント前とは別マウントの tmpfs」と確かめた tmpfs ルートの
//!   fd だけ。rootfs（ホスト上のディレクトリ）へ内容が書かれる経路を作らない（内容がホストのディスクに
//!   残らないことの中核の不変条件）。作成は `O_EXCL|O_NOFOLLOW`、モードは作成後に `fchmod` で設定する
//! - **fd 起点・移動検査**: 親ディレクトリは [`mount_tmpfs`](super::mount_tmpfs) と同じ `open_chain` で 1 要素ずつ
//!   辿り（symlink・非ディレクトリは違反記録付きで拒否）、shared propagation 上へはマウントせず、固定後の
//!   移動を検査する。既存の**空でない**ディレクトリは覆い隠さず拒否する（fail-closed）
//! - **read-only 化**: `mount_setattr(2)` + `MOUNT_ATTR_RDONLY` を、`fsmount` で得た自分のマウントのルート fd に
//!   `AT_EMPTY_PATH` で掛ける（#1620）。パス文字列（`/proc/thread-self/fd/N`）を経由せず再解決の余地がない。
//!   `attr_clr` = 0 のためロック済みの `nosuid,nodev,noexec` を落とさない。立つのはマウント単位の `ro` で、同じ
//!   superblock の別マウントは作らないため `EROFS` の保証は変わらない。書き込み用の fd は閉じてから呼ぶ
//!   （残っていると `EBUSY`）。未対応カーネル（Linux 5.12 未満）は `unimplemented` で拒否し `mount(2)` へ縮退しない。
//!   ro 化した後に mountinfo の per-mount options に `ro` があることを確かめ、無ければ失敗する
//! - **エラー message**: 内容は含めない。マウント先・ファイル名は [`display_destination`] のエスケープと
//!   切り詰めを通す（ログ注入の防止）
//! - **失敗時の後始末**: [`mount_tmpfs`](super::mount_tmpfs) と同じ（`roll_back`）。この呼び出しでマウントした
//!   tmpfs を新しい順に外し、自分で作ったディレクトリだけを消す。umount の失敗は元のエラーの message に
//!   `; cleanup failed: ...` として併記する（REPAIR-4）。呼び出し後もプロセスは破棄する
//! - **同一スレッド**: `MountIsolation::establish` と同じスレッドで呼ぶ
//!
//! # 未対応（REPAIR-3: 実装済みを装わない）
//!
//! 本番 launcher・CLI・stack（TOML）からの配線、uid / gid 指定、単一ファイルの bind 注入（既存ディレクトリへ
//! 1 ファイルだけ見せる）、利用者 tmpfs の配下への注入（`/run` を tmpfs にした上で `/run/secrets` を注入する
//! 構成は [`InjectedFileSet::check_against_tmpfs`] が拒否する）、tmpfs のスワップ退避の抑止（`noswap`。
//! カーネル版数依存）、メモリ上の内容のゼロ化。
//!
//! # 単体テストの安全策
//!
//! `mount(2)` 系・`mount_setattr(2)`・`umount2(2)` は `cfg(test)` では dry-run に差し替わる。このとき実 tmpfs が無いため、
//! ファイルは一時ディレクトリ配下（rootfs の代わり）へ作られる（単体テスト限定の挙動）。実機での挙動は結合試験
//! `tests/inject_files.rs`（`-- --ignored`）で確認する。

use std::ffi::{CString, OsStr};
use std::io::Write as _;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;

use crate::injected_files::{InjectedFileSet, InjectedGroup};
use crate::sys::{self, SysError};
use crate::traits::types::ErrorCode;

use super::tmpfs::{
    Applied, display_destination, mount_tmpfs_syscall, open_chain, roll_back, root_display,
    tmpfs_mount_error, verify_mounted, with_rollback_failures,
};
use super::{
    ExecError, IsolationStage, MountIsolation, PreparedRootfs, ViolationReason, fd_still_at,
    mount_is_shared,
};

const STAGE: IsolationStage = IsolationStage::InjectFiles;

/// 注入用 tmpfs の新マウント API 失敗を `InjectFiles` 段のエラーにする。`tmpfs_mount_error` は段を
/// `MountTmpfs` に固定するため、ここで付け替える（後続の `open_chain`・`verify_mounted` と同じ扱い。
/// SUP-12・TASK-169 追補・#1472）。
fn inject_mount_error(e: SysError, destination: &str) -> ExecError {
    tmpfs_mount_error(e, destination).at_stage(STAGE)
}

/// 注入したファイル 1 件の結果（内容は含めない）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InjectedFileOutcome {
    /// ファイル名（最終要素）。
    pub name: String,
    /// 設定したモード。
    pub mode: u32,
}

/// 注入したディレクトリ（専用 tmpfs）1 件の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InjectedDirectoryOutcome {
    /// コンテナ内のマウント先（正規化済み）。
    pub destination: String,
    /// 置いたファイル（指定順）。
    pub files: Vec<InjectedFileOutcome>,
    /// read-only で事後検証できたか（成功時は常に真）。
    pub read_only: bool,
}

/// [`inject_files`] の成功結果（将来の拡張に備えた非網羅の構造体。内容は含めない）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InjectReport {
    /// 適用したディレクトリ（初出順）。
    pub directories: Vec<InjectedDirectoryOutcome>,
}

/// `set` を rootfs（`prepared` の新しい mount top）配下へ注入する。
///
/// [`MountIsolation`] の証跡が現在の状態と一致しなければ副作用なしに拒否する（fail-closed）。
/// 詳細な契約はモジュール doc を参照。
pub fn inject_files(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    set: &InjectedFileSet,
) -> Result<InjectReport, ExecError> {
    isolation.verify_caller(STAGE)?;
    inject_files_at(prepared.new_root(), set, &|dir| mount_is_shared(dir, STAGE))
}

/// [`inject_files`] の証跡検証後の本体（`mount_tmpfs_at` と同じ構成。`is_shared` は単体テストが差し替える）。
fn inject_files_at(
    root: BorrowedFd<'_>,
    set: &InjectedFileSet,
    is_shared: &dyn Fn(&OwnedFd) -> Result<bool, ExecError>,
) -> Result<InjectReport, ExecError> {
    let rootfs = root_display(root);
    let groups = set.groups();
    let mut directories = Vec::with_capacity(groups.len());
    let mut applied: Vec<Applied<'_>> = Vec::with_capacity(groups.len());
    for group in &groups {
        let mut state = Applied {
            names: group
                .directory
                .split('/')
                .filter(|e| !e.is_empty())
                .map(OsStr::new)
                .collect(),
            created: Vec::new(),
            mounted: None,
        };
        let result = apply_group(root, &rootfs, group, &mut state, is_shared);
        applied.push(state);
        match result {
            Ok(outcome) => directories.push(outcome),
            Err(e) => {
                let failures = roll_back(root, &rootfs, &applied);
                return Err(with_rollback_failures(e, &failures));
            }
        }
    }
    Ok(InjectReport { directories })
}

fn apply_group(
    root: BorrowedFd<'_>,
    rootfs: &std::path::Path,
    group: &InjectedGroup<'_>,
    state: &mut Applied<'_>,
    is_shared: &dyn Fn(&OwnedFd) -> Result<bool, ExecError>,
) -> Result<InjectedDirectoryOutcome, ExecError> {
    let names = state.names.clone();
    let dir = open_chain(root, rootfs, &names, Some(&mut state.created))
        .map_err(|e| e.at_stage(STAGE))?;
    let subject = names.iter().fold(rootfs.to_path_buf(), |p, n| p.join(n));
    let shown = display_destination(group.directory);
    // 自分で作ったディレクトリは空と分かっている。既存なら、内容を黙って覆い隠さないよう空を要求する。
    let created_here = state.created.last() == Some(&names.len().saturating_sub(1));
    if !created_here {
        ensure_empty(&dir, &shown)?;
    }
    if is_shared(&dir)? {
        return Err(ExecError::from_violation_at(
            ViolationReason::TargetOnSharedMount,
            Some(&subject),
            STAGE,
        ));
    }
    if !fd_still_at(&dir, &subject) {
        return Err(ExecError::from_violation_at(
            ViolationReason::TargetMoved,
            Some(&subject),
            STAGE,
        ));
    }
    // 書き込み中は rw。`nosuid,nodev,noexec` は常に付く。
    let create = sys::TmpfsCreate {
        mode: 0o755,
        size: Some(group.tmpfs_size),
        flags: sys::TmpfsMountFlags {
            read_only: false,
            exec: false,
        },
    };
    // 付け替え直後に自分のマウントの fd を保持する（事後検証に通らなくても後始末が外せる）。
    let mount_fd = mount_tmpfs_syscall(dir.as_fd(), create)
        .map_err(|e| inject_mount_error(e, group.directory))?;
    let tmpfs_root = &*state.mounted.insert(mount_fd);
    verify_mounted(root, rootfs, &names, group.directory, &dir, tmpfs_root)
        .map_err(|e| e.at_stage(STAGE))?;

    let mut files = Vec::with_capacity(group.files.len());
    for f in &group.files {
        write_file(
            tmpfs_root.as_fd(),
            f.file_name(),
            f.content().as_bytes(),
            f.mode().bits(),
        )
        .map_err(|e| e.with_file(&display_destination(f.destination().as_str())))?;
        files.push(InjectedFileOutcome {
            name: f.file_name().to_owned(),
            mode: f.mode().bits(),
        });
    }

    // 書き込み用の fd は `write_file` が閉じ済み（残っていると `EBUSY`）。fd 起点で ro にする（#1620）。
    read_only_syscall(tmpfs_root.as_fd()).map_err(|e| {
        ExecError::from_sys(
            e,
            STAGE,
            &format!("mount_setattr(MOUNT_ATTR_RDONLY on {shown})"),
        )
    })?;
    if !observe_read_only(tmpfs_root)? {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!("the mount at {shown} is not read-only after mount_setattr"),
        ));
    }
    Ok(InjectedDirectoryOutcome {
        destination: group.directory.to_owned(),
        files,
        read_only: true,
    })
}

/// 書き込み失敗の文脈（どのファイルか）を段階的に付けるための内部エラー。内容は持たない。
struct WriteError {
    what: &'static str,
    err: WriteErrKind,
}

enum WriteErrKind {
    Sys(SysError),
    Io(std::io::Error),
    Name,
}

impl WriteError {
    fn with_file(self, shown: &str) -> ExecError {
        let what = format!("{} {shown}", self.what);
        match self.err {
            WriteErrKind::Sys(e) => ExecError::from_sys(e, STAGE, &what),
            WriteErrKind::Io(e) => ExecError::from_io(&e, STAGE, &what),
            WriteErrKind::Name => ExecError::new(
                ErrorCode::InvalidArgument,
                STAGE,
                format!("invalid file name for {shown}"),
            ),
        }
    }
}

/// tmpfs ルート `parent` の直下へ 1 ファイルを `O_EXCL` で作り、内容を書いて最終モードへ設定する。
fn write_file(
    parent: BorrowedFd<'_>,
    name: &str,
    content: &[u8],
    mode: u32,
) -> Result<(), WriteError> {
    let c_name = CString::new(name).map_err(|_| WriteError {
        what: "create",
        err: WriteErrKind::Name,
    })?;
    let fd = sys::create_file_excl_at(parent, &c_name, 0o600).map_err(|e| WriteError {
        what: "create",
        err: WriteErrKind::Sys(e),
    })?;
    let mut file = std::fs::File::from(fd);
    file.write_all(content).map_err(|e| WriteError {
        what: "write",
        err: WriteErrKind::Io(e),
    })?;
    // umask の影響を受けないよう、作成後に fchmod で指定モードへ設定する。
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|e| WriteError {
            what: "chmod",
            err: WriteErrKind::Io(e),
        })?;
    Ok(())
}

/// 既存ディレクトリが空であることを確かめる（空でない・読めないなら拒否）。
fn ensure_empty(dir: &OwnedFd, shown: &str) -> Result<(), ExecError> {
    let path = format!("/proc/thread-self/fd/{}", dir.as_raw_fd());
    let mut entries = std::fs::read_dir(&path)
        .map_err(|e| ExecError::from_io(&e, STAGE, &format!("read_dir({shown})")))?;
    match entries.next() {
        None => Ok(()),
        Some(Ok(_)) => Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!("the injected files directory {shown} is not empty"),
        )),
        Some(Err(e)) => Err(ExecError::from_io(&e, STAGE, &format!("read_dir({shown})"))),
    }
}

/// `dir` が属するマウントが read-only かを観測する（cfg で差し替わる）。
#[cfg(not(test))]
fn observe_read_only(dir: &OwnedFd) -> Result<bool, ExecError> {
    let mnt_id = super::fd_mount_id(dir, STAGE)?;
    let info = super::read_thread_mountinfo(STAGE)?;
    super::mount_is_read_only_in(&info, mnt_id).map_err(|e| e.at_stage(STAGE))
}

/// dry-run: 実マウントが無いため、既定は read-only を観測したことにする（失敗経路は `FORCE_RW` で作る）。
#[cfg(test)]
fn observe_read_only(_dir: &OwnedFd) -> Result<bool, ExecError> {
    Ok(!tests::FORCE_RW.with(|c| c.get()))
}

/// `tmpfs_root`（自分のマウントのルート fd）のマウントを fd 起点で read-only にする（cfg で差し替わる）。
#[cfg(not(test))]
fn read_only_syscall(tmpfs_root: BorrowedFd<'_>) -> Result<(), SysError> {
    sys::set_mount_read_only(tmpfs_root)
}

/// dry-run: `mount_setattr(2)` を呼ばず、(fd の実体・本番と同じ引数の組) を記録する。
/// 故障注入（`READ_ONLY_FAIL`）で未対応カーネル等の失敗も作れる。
#[cfg(test)]
fn read_only_syscall(tmpfs_root: BorrowedFd<'_>) -> Result<(), SysError> {
    if let Some(e) = tests::READ_ONLY_FAIL.with(|f| f.take()) {
        return Err(e);
    }
    let resolved = std::fs::read_link(format!("/proc/thread-self/fd/{}", tmpfs_root.as_raw_fd()))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    tests::READ_ONLY_CALLS.with(|c| {
        c.borrow_mut()
            .push((resolved, sys::read_only_call_params()))
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tmpfs::tests::{Tmp, take_calls, take_umounts};
    use super::*;
    use crate::injected_files::{InjectedContent, InjectedFileMode, InjectedFileSpec};
    use std::os::unix::fs::{MetadataExt as _, symlink};

    thread_local! {
        pub(super) static READ_ONLY_CALLS: std::cell::RefCell<Vec<(String, ReadOnlyParams)>> =
            const { std::cell::RefCell::new(Vec::new()) };
        /// 次の `read_only_syscall` に返させる失敗（未対応カーネル等の注入用）。
        pub(super) static READ_ONLY_FAIL: std::cell::Cell<Option<SysError>> =
            const { std::cell::Cell::new(None) };
        pub(super) static FORCE_RW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// `(attr_set, attr_clr, propagation, userns_fd, flags, size)`。
    type ReadOnlyParams = (u64, u64, u64, u64, u32, usize);

    fn take_read_only_calls() -> Vec<(String, ReadOnlyParams)> {
        READ_ONLY_CALLS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    const SENTINEL: &str = "SENTINEL-DUMMY-VALUE";

    fn set(files: &[(&str, &str, u32)]) -> InjectedFileSet {
        let mut s = InjectedFileSet::new();
        for (dest, body, mode) in files {
            let spec = InjectedFileSpec::new(
                dest,
                InjectedContent::from_bytes(body.as_bytes().to_vec()).expect("content"),
                InjectedFileMode::new(*mode).expect("mode"),
            )
            .expect("spec");
            s.push(spec).expect("push");
        }
        s
    }

    fn not_shared(_: &OwnedFd) -> Result<bool, ExecError> {
        Ok(false)
    }

    fn reset() {
        let _ = (take_calls(), take_umounts(), take_read_only_calls());
        FORCE_RW.with(|c| c.set(false));
        READ_ONLY_FAIL.with(|c| c.set(None));
    }

    /// SUP-12・TASK-169.4.2・#1620: ディレクトリごとに rw マウント → 書き込み → `mount_setattr` で ro にし、
    /// フラグ・data・モード・内容が具体値で一致する。
    #[test]
    fn sup12_task169_4_2_mounts_writes_and_sets_read_only() {
        let tmp = Tmp::new("inject-ok");
        reset();
        let fd = tmp.fd();
        let s = set(&[
            ("/run/secrets/db", SENTINEL, 0o400),
            ("/etc/app/conf", "k=v", 0o444),
            ("/run/secrets/api", "", 0o444),
        ]);
        let report = inject_files_at(fd.as_fd(), &s, &not_shared).expect("inject");
        let rw = 2 | 4 | 8;
        assert_eq!(
            take_calls(),
            vec![
                (
                    tmp.0.join("run/secrets").to_string_lossy().into_owned(),
                    rw,
                    "mode=0755,size=65536".to_owned()
                ),
                (
                    tmp.0.join("etc/app").to_string_lossy().into_owned(),
                    rw,
                    "mode=0755,size=65536".to_owned()
                ),
            ]
        );
        assert_eq!(
            take_read_only_calls(),
            vec![
                (
                    tmp.0.join("run/secrets").to_string_lossy().into_owned(),
                    (1, 0, 0, 0, 0x1000, 32)
                ),
                (
                    tmp.0.join("etc/app").to_string_lossy().into_owned(),
                    (1, 0, 0, 0, 0x1000, 32)
                ),
            ]
        );
        assert_eq!(
            std::fs::read_to_string(tmp.0.join("run/secrets/db")).expect("read"),
            SENTINEL
        );
        let meta = std::fs::metadata(tmp.0.join("run/secrets/db")).expect("meta");
        assert_eq!(meta.mode() & 0o7777, 0o400);
        assert_eq!(
            std::fs::metadata(tmp.0.join("etc/app/conf"))
                .expect("meta")
                .mode()
                & 0o7777,
            0o444
        );
        assert_eq!(report.directories.len(), 2);
        assert_eq!(report.directories[0].destination, "/run/secrets");
        assert!(report.directories[0].read_only);
        assert_eq!(
            report.directories[0].files,
            vec![
                InjectedFileOutcome {
                    name: "db".to_owned(),
                    mode: 0o400
                },
                InjectedFileOutcome {
                    name: "api".to_owned(),
                    mode: 0o444
                },
            ]
        );
        assert!(!format!("{report:?}").contains("SENTINEL"));
    }

    /// SUP-12・TASK-169.4.2: 親ディレクトリの途中が symlink なら違反記録付きで拒否し、先に何も作らない。
    #[test]
    fn sup12_task169_4_2_rejects_symlink_component() {
        let tmp = Tmp::new("inject-symlink");
        reset();
        std::fs::create_dir_all(tmp.0.join("outside")).expect("outside");
        symlink(tmp.0.join("outside"), tmp.0.join("link")).expect("symlink");
        let fd = tmp.fd();
        let err = inject_files_at(
            fd.as_fd(),
            &set(&[("/link/x/f", SENTINEL, 0o444)]),
            &not_shared,
        )
        .expect_err("symlink");
        assert_eq!(err.stage, IsolationStage::InjectFiles);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathSymlinkOrNotDirectory)
        );
        assert!(take_calls().is_empty());
        assert_eq!(
            std::fs::read_dir(tmp.0.join("outside"))
                .expect("dir")
                .count(),
            0
        );
        assert!(!err.message.contains("SENTINEL"));
    }

    /// SUP-12・TASK-169.4.2: shared propagation 上へはマウントしない。
    #[test]
    fn sup12_task169_4_2_rejects_shared_mount() {
        let tmp = Tmp::new("inject-shared");
        reset();
        let fd = tmp.fd();
        let err = inject_files_at(fd.as_fd(), &set(&[("/run/s/f", "x", 0o444)]), &|_| Ok(true))
            .expect_err("shared");
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::TargetOnSharedMount)
        );
        assert!(take_calls().is_empty());
        assert!(!tmp.0.join("run/s/f").exists());
    }

    /// SUP-12・TASK-169.4.2: 固定後にマウント先が改名されたら `target_moved` で拒否する。
    #[test]
    fn sup12_task169_4_2_rejects_target_moved_after_pin() {
        let tmp = Tmp::new("inject-moved");
        reset();
        let fd = tmp.fd();
        let (from, to) = (tmp.0.join("run"), tmp.0.join("elsewhere"));
        let err = inject_files_at(fd.as_fd(), &set(&[("/run/f", "x", 0o444)]), &|_| {
            std::fs::rename(&from, &to).expect("rename");
            Ok(false)
        })
        .expect_err("moved");
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::TargetMoved)
        );
        assert!(take_calls().is_empty());
    }

    /// SUP-12・TASK-169.4.2: 既存の空でないディレクトリは覆い隠さず拒否し、中身を残す。
    #[test]
    fn sup12_task169_4_2_rejects_non_empty_existing_directory() {
        let tmp = Tmp::new("inject-nonempty");
        reset();
        std::fs::create_dir_all(tmp.0.join("run/secrets")).expect("dir");
        std::fs::write(tmp.0.join("run/secrets/keep"), b"x").expect("keep");
        let fd = tmp.fd();
        let err = inject_files_at(
            fd.as_fd(),
            &set(&[("/run/secrets/a", "x", 0o444)]),
            &not_shared,
        )
        .expect_err("non-empty");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message,
            "the injected files directory /run/secrets is not empty"
        );
        assert!(take_calls().is_empty());
        assert_eq!(
            std::fs::read(tmp.0.join("run/secrets/keep")).expect("keep"),
            b"x"
        );
        // 既存の空ディレクトリなら受け入れる。
        std::fs::remove_file(tmp.0.join("run/secrets/keep")).expect("rm");
        inject_files_at(
            fd.as_fd(),
            &set(&[("/run/secrets/a", "x", 0o444)]),
            &not_shared,
        )
        .expect("empty existing");
    }

    /// SUP-12・TASK-169.4.2: ro 化の後に read-only を観測できなければ失敗する（fail-closed）。
    #[test]
    fn sup12_task169_4_2_fails_when_not_read_only_after_mount_setattr() {
        let tmp = Tmp::new("inject-rw");
        reset();
        FORCE_RW.with(|c| c.set(true));
        let fd = tmp.fd();
        let err = inject_files_at(
            fd.as_fd(),
            &set(&[("/run/s/f", SENTINEL, 0o444)]),
            &not_shared,
        )
        .expect_err("rw");
        FORCE_RW.with(|c| c.set(false));
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message,
            "the mount at /run/s is not read-only after mount_setattr"
        );
        // 失敗したので、マウントした tmpfs を外す。
        assert_eq!(
            take_umounts(),
            vec![tmp.0.join("run/s").to_string_lossy().into_owned()]
        );
    }

    /// SUP-12・TASK-169.4.2: 後続のディレクトリが失敗したら先の tmpfs を外し、既存の内容を残す。
    #[test]
    fn sup12_task169_4_2_failure_rolls_back_earlier_mounts() {
        let tmp = Tmp::new("inject-rollback");
        reset();
        std::fs::create_dir_all(tmp.0.join("pre")).expect("pre");
        std::fs::write(tmp.0.join("pre/keep"), b"x").expect("keep");
        std::fs::create_dir_all(tmp.0.join("outside")).expect("outside");
        symlink(tmp.0.join("outside"), tmp.0.join("link")).expect("symlink");
        let fd = tmp.fd();
        let s = set(&[("/scratch/a/f", "x", 0o444), ("/link/b/f", "x", 0o444)]);
        let err = inject_files_at(fd.as_fd(), &s, &not_shared).expect_err("second fails");
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathSymlinkOrNotDirectory)
        );
        assert_eq!(
            take_umounts(),
            vec![tmp.0.join("scratch/a").to_string_lossy().into_owned()]
        );
        assert_eq!(std::fs::read(tmp.0.join("pre/keep")).expect("keep"), b"x");
        assert_eq!(
            std::fs::read_dir(tmp.0.join("outside"))
                .expect("dir")
                .count(),
            0
        );
    }

    /// SUP-12・TASK-169.4.2: マウント先は message でエスケープされ、内容は出ない。
    #[test]
    fn sup12_task169_4_2_messages_are_escaped_and_content_free() {
        let tmp = Tmp::new("inject-escape");
        reset();
        let fd = tmp.fd();
        std::fs::create_dir_all(tmp.0.join("d\nlevel=error")).expect("dir");
        std::fs::write(tmp.0.join("d\nlevel=error/keep"), b"x").expect("keep");
        let s = set(&[("/d\nlevel=error/f", SENTINEL, 0o444)]);
        let err = inject_files_at(fd.as_fd(), &s, &not_shared).expect_err("non-empty");
        assert_eq!(
            err.message,
            "the injected files directory /d\\nlevel=error is not empty"
        );
        assert!(!err.message.contains("SENTINEL"));
    }

    /// SUP-12・TASK-169 追補: 新マウント API の失敗は段が InjectFiles で返る（MountTmpfs ではない）。
    #[test]
    fn sup12_task169_mount_failure_reports_inject_files_stage() {
        let unsupported = inject_mount_error(SysError::Unsupported, "/d");
        assert_eq!(unsupported.stage, IsolationStage::InjectFiles);
        assert_eq!(unsupported.code, ErrorCode::Unimplemented);
        let denied = inject_mount_error(SysError::Os(sys::EPERM), "/d");
        assert_eq!(denied.stage, IsolationStage::InjectFiles);
    }

    /// SUP-12・TASK-169・#1620: 未対応カーネル（`ENOSYS`）は `unimplemented` で拒否し、`mount(2)` へ縮退せず、
    /// この呼び出しでマウントした tmpfs は外す。
    #[test]
    fn sup12_task169_read_only_unsupported_kernel_is_unimplemented() {
        let tmp = Tmp::new("inject-ro-unsupported");
        reset();
        READ_ONLY_FAIL.with(|c| c.set(Some(SysError::Unsupported)));
        let fd = tmp.fd();
        let err = inject_files_at(
            fd.as_fd(),
            &set(&[("/run/s/f", SENTINEL, 0o444)]),
            &not_shared,
        )
        .expect_err("unsupported");
        READ_ONLY_FAIL.with(|c| c.set(None));
        assert_eq!(err.code, ErrorCode::Unimplemented);
        assert_eq!(err.stage, IsolationStage::InjectFiles);
        assert_eq!(
            err.message,
            "mount_setattr(MOUNT_ATTR_RDONLY on /run/s) failed: not supported by the kernel or the target architecture"
        );
        assert!(take_read_only_calls().is_empty());
        assert_eq!(
            take_umounts(),
            vec![tmp.0.join("run/s").to_string_lossy().into_owned()]
        );
    }

    /// SUP-12・TASK-169・#1620: 権限不足は `permission_denied` で報告する。
    #[test]
    fn sup12_task169_read_only_eperm_is_reported() {
        let tmp = Tmp::new("inject-ro-eperm");
        reset();
        READ_ONLY_FAIL.with(|c| c.set(Some(SysError::Os(sys::EPERM))));
        let fd = tmp.fd();
        let err = inject_files_at(fd.as_fd(), &set(&[("/run/s/f", "x", 0o444)]), &not_shared)
            .expect_err("eperm");
        READ_ONLY_FAIL.with(|c| c.set(None));
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.stage, IsolationStage::InjectFiles);
    }

    /// REPAIR-4・SUP-12・TASK-169・#1620: 後始末の umount 失敗は inject の元のエラーにも併記される。
    #[test]
    fn repair4_sup12_inject_roll_back_failure_is_appended() {
        let tmp = Tmp::new("inject-rbfail");
        reset();
        FORCE_RW.with(|c| c.set(true));
        super::super::tmpfs::tests::UMOUNT_FAIL.with(|f| f.set(Some(SysError::Os(sys::EPERM))));
        let fd = tmp.fd();
        let err = inject_files_at(fd.as_fd(), &set(&[("/run/s/f", "x", 0o444)]), &not_shared)
            .expect_err("rw");
        super::super::tmpfs::tests::UMOUNT_FAIL.with(|f| f.set(None));
        FORCE_RW.with(|c| c.set(false));
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::InjectFiles);
        assert_eq!(
            err.message,
            "the mount at /run/s is not read-only after mount_setattr; cleanup failed: umount2(/run/s) failed: Operation not permitted (os error 1)"
        );
    }
}
