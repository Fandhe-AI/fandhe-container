//! コンテナ起動時の基本デバイスノード 6 種の作成（CORE-1・TASK-27.6・#834・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! `docker export` 由来の rootfs には `/dev/null` 等が入っておらず、これらが無いとプログラムが
//! 異常終了する（PoC-15 で `iperf3 -s` が SIGSEGV する事象を確認）。OCI Runtime Spec の
//! default devices に相当する 6 種（`null`・`zero`・`full`・`random`・`urandom`・`tty`）を、
//! CDI の deviceNodes（GPU 系・TASK-127）とは独立した常設の責務として rootfs の `dev` 直下へ作る。
//!
//! `crate::exec` の最小実行フロー第 3 段。呼び出し元は TASK-29 の `oci_runtime` と fork 段（#831）を
//! 想定し、次の順で通す。
//!
//! ```text
//! prepare_rootfs(&isolation, rootfs) -> PreparedRootfs
//!   -> create_default_devices(&isolation, &prepared) -> DeviceReport   // 本モジュール
//!   -> pivot_root(&isolation, prepared)
//! ```
//!
//! `prepare_rootfs` の `check_no_submounts` はサブマウントを 1 つも許さないため、`dev` への
//! マウント系の処理は入れられず、ノード作成は「準備の後・切替の前」に置く。
//!
//! # 契約
//!
//! - **fd 起点**: [`PreparedRootfs`] の新しい mount top の fd から `dev` を `O_NOFOLLOW|O_DIRECTORY`
//!   で開き、以後は `mknodat(dirfd, <静的な 1 要素の名前>)` だけで作る。パス文字列を連結しない。
//!   `dev` が symlink・非ディレクトリなら `path_symlink_or_not_directory` の違反記録付きで拒否する
//!   （rootfs の外へ作らない）。`dev` が無ければ rootfs 配下に作る
//! - **既存ノードは上書きしない・検証する**: `mknodat` の `EEXIST` は、既存エントリを `O_PATH|O_NOFOLLOW`
//!   で開いた fd に対して文字デバイス・`rdev`・モード（0666）を検証し、すべて一致したときだけ
//!   [`DeviceNodeStatus::AlreadyPresent`] とする。通常ファイル・別デバイス・symlink・モード不一致は
//!   `FailedPrecondition`（段 `CreateDevices`）で拒否し、変更はしない（イメージ内の偽ノードを通さない）
//! - **モード補正**: `mknodat` のモードは umask で削られるため、作成に成功したノードだけを
//!   `O_PATH|O_NOFOLLOW` で開き直し、文字デバイス・`rdev` の一致を検証した fd に対して magic link
//!   経由で 0666 に補正する（作成直後の差し替えで別 inode の権限を変えない）
//! - **rootless は fail-closed**: 非特権 user namespace では文字デバイスの `mknod(2)` が `EPERM` になり、
//!   `PermissionDenied`（段 `CreateDevices`）で拒否する。黙ってデバイス無しで起動させない
//! - **失敗時はプロセスを破棄する**: 作成済みノードは片付けない（`crate::exec` のモジュール doc の契約）
//! - **同一スレッド**: `MountIsolation::establish` と同じスレッドで呼ぶ
//!
//! # 未対応（REPAIR-3: 実装済みを装わない）
//!
//! - rootless 向けのホスト `/dev/*` の bind mount による供給（runc 相当。CORE-6・SEC-5 と整理する
//!   後続タスク）。本実装の rootless 経路は `PermissionDenied` で止まる
//! - `nodev` マウント上の rootfs の検出（stat は通るがデバイスは開けない）
//! - `/dev/console`・`/dev/ptmx`・`/dev/pts`・`/dev/shm`・`/dev/fd` 等の OCI default の残り
//!   （TASK-127・TASK-29 の範囲）
//!
//! # 単体テストの安全策
//!
//! `mknodat(2)` は `cfg(test)` では dry-run に差し替わる（`mknod_syscall`）。root で `cargo test` を
//! 実行してもホストへ実ノードを作らない。実機での挙動は結合試験 `tests/default_devices.rs`
//! （`-- --ignored`）で確認する。

use std::ffi::{CStr, OsStr};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::{
    DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};

use crate::sys::{self, SysError};
use crate::traits::types::ErrorCode;

use super::{ExecError, IsolationStage, MountIsolation, PreparedRootfs, open_error};

const STAGE: IsolationStage = IsolationStage::CreateDevices;

/// 作成する 1 種のデバイスノードの定義。
struct DefaultDevice {
    /// `dev` 直下の名前（`/` を含まない静的な 1 要素）。
    name: &'static CStr,
    major: u32,
    minor: u32,
    mode: u32,
}

/// OCI Runtime Spec の default devices（文字デバイス・モード 0666）。CDI の deviceNodes は
/// 別責務（TASK-127）で、ここへ任意の major/minor を受け付ける経路は作らない。
const DEFAULT_DEVICES: [DefaultDevice; 6] = [
    DefaultDevice {
        name: c"null",
        major: 1,
        minor: 3,
        mode: 0o666,
    },
    DefaultDevice {
        name: c"zero",
        major: 1,
        minor: 5,
        mode: 0o666,
    },
    DefaultDevice {
        name: c"full",
        major: 1,
        minor: 7,
        mode: 0o666,
    },
    DefaultDevice {
        name: c"random",
        major: 1,
        minor: 8,
        mode: 0o666,
    },
    DefaultDevice {
        name: c"urandom",
        major: 1,
        minor: 9,
        mode: 0o666,
    },
    DefaultDevice {
        name: c"tty",
        major: 5,
        minor: 0,
        mode: 0o666,
    },
];

/// 1 ノードの結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceNodeStatus {
    /// 今回作成した。
    Created,
    /// 既に存在し、文字デバイス・`rdev`・モードが期待どおりと検証済みのため何も変更していない。
    AlreadyPresent,
}

/// [`create_default_devices`] が処理した 1 ノードの結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceNodeOutcome {
    /// `dev` 直下の名前。
    pub name: &'static str,
    /// 主デバイス番号。
    pub major: u32,
    /// 副デバイス番号。
    pub minor: u32,
    /// 期待するモード（下位 12 ビット）。
    pub mode: u32,
    /// 作成したか、既存だったか。
    pub status: DeviceNodeStatus,
}

/// [`create_default_devices`] の成功結果（将来の拡張に備えた非網羅の構造体）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceReport {
    /// 6 種の結果（定義順: null・zero・full・random・urandom・tty）。
    pub nodes: Vec<DeviceNodeOutcome>,
}

/// rootfs の `dev` 直下へ基本デバイスノード 6 種を作る。
///
/// [`prepare_rootfs`](super::prepare_rootfs) の後、[`pivot_root`](super::pivot_root) の前に呼ぶ。
/// [`MountIsolation`] の証跡が現在の状態と一致しなければ副作用なしに拒否する（fail-closed）。
/// 詳細な契約はモジュール doc を参照。
pub fn create_default_devices(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
) -> Result<DeviceReport, ExecError> {
    isolation.verify_caller(STAGE)?;
    create_default_devices_at(prepared.new_root())
}

/// [`create_default_devices`] の証跡検証後の本体。`root` は rootfs（新しい mount top）の fd。
/// 単体テストは証跡を偽造せず一時ディレクトリの fd を直接渡す。
fn create_default_devices_at(root: BorrowedFd<'_>) -> Result<DeviceReport, ExecError> {
    let rootfs = root_display(root);
    let dev = open_dev_dir(root, &rootfs)?;
    let mut nodes = Vec::with_capacity(DEFAULT_DEVICES.len());
    for d in &DEFAULT_DEVICES {
        let status = match mknod_syscall(dev.as_fd(), d) {
            Ok(()) => {
                finalize_node(dev.as_fd(), d)?;
                DeviceNodeStatus::Created
            }
            Err(SysError::Os(sys::EEXIST)) => {
                verify_existing_node(dev.as_fd(), d)?;
                DeviceNodeStatus::AlreadyPresent
            }
            Err(e) => {
                return Err(ExecError::from_sys(
                    e,
                    STAGE,
                    &format!("mknodat({})", d.name.to_string_lossy()),
                ));
            }
        };
        nodes.push(DeviceNodeOutcome {
            name: d.name.to_str().unwrap_or("?"),
            major: d.major,
            minor: d.minor,
            mode: d.mode,
            status,
        });
    }
    Ok(DeviceReport { nodes })
}

/// 違反記録の対象表示用に rootfs の実パスを得る（取れなければ固定文字列）。
fn root_display(root: BorrowedFd<'_>) -> PathBuf {
    std::fs::read_link(fd_magic_path(root.as_raw_fd()))
        .unwrap_or_else(|_| PathBuf::from("<rootfs>"))
}

fn fd_magic_path(fd: i32) -> PathBuf {
    PathBuf::from(format!("/proc/thread-self/fd/{fd}"))
}

/// `root` 直下の `dev` を `O_NOFOLLOW|O_DIRECTORY` で開く。無ければ rootfs 配下に作って開き直す。
/// symlink・非ディレクトリは違反記録付きで拒否する（rootfs の外へ作らない）。
fn open_dev_dir(root: BorrowedFd<'_>, rootfs: &Path) -> Result<OwnedFd, ExecError> {
    let names = [OsStr::new("dev")];
    let open = || sys::open_dir_path_nofollow(Some(root), c"dev");
    match open() {
        Ok(fd) => Ok(fd),
        Err(SysError::Os(sys::ENOENT)) => {
            // `mkdir` は最終要素の symlink を辿らない。競合で先に作られた（EEXIST）場合は
            // 開き直しで種別を検証する。
            let target = fd_magic_path(root.as_raw_fd()).join("dev");
            match std::fs::DirBuilder::new().mode(0o755).create(&target) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(ExecError::from_io(&e, STAGE, "mkdir(dev)")),
            }
            open().map_err(|e| open_error(e, true, rootfs, &names).at_stage(STAGE))
        }
        Err(e) => Err(open_error(e, true, rootfs, &names).at_stage(STAGE)),
    }
}

/// 作成に成功したノードを検証し、モードを補正する。`cfg(test)` の dry-run ではノードが実在しない
/// ため呼び出しを省く（検証ロジックは [`check_created_node`] を単体で試験する）。
fn finalize_node(dev: BorrowedFd<'_>, d: &DefaultDevice) -> Result<(), ExecError> {
    if cfg!(test) {
        return Ok(());
    }
    let fd = sys::open_path_nofollow(dev, d.name)
        .map_err(|e| ExecError::from_sys(e, STAGE, "openat(device node)"))?;
    let dup = fd
        .try_clone()
        .map_err(|e| ExecError::from_io(&e, STAGE, "dup"))?;
    let meta = std::fs::File::from(dup)
        .metadata()
        .map_err(|e| ExecError::from_io(&e, STAGE, "fstat(device node)"))?;
    check_created_node(meta.file_type().is_char_device(), meta.rdev(), d)?;
    // 検証した inode を指す fd の magic link 経由で chmod する（名前は再解決しない）。
    std::fs::set_permissions(
        fd_magic_path(fd.as_raw_fd()),
        std::fs::Permissions::from_mode(d.mode),
    )
    .map_err(|e| ExecError::from_io(&e, STAGE, "chmod(device node)"))
}

/// `EEXIST` で見つかった既存エントリを fd 起点で検証する。種別・`rdev`・モードが期待と一致しなければ
/// 拒否する（変更はしない）。symlink は `O_NOFOLLOW|O_PATH` で開いた fd が symlink 自身を指すため
/// 文字デバイスでないとして拒否される。
fn verify_existing_node(dev: BorrowedFd<'_>, d: &DefaultDevice) -> Result<(), ExecError> {
    let fd = sys::open_path_nofollow(dev, d.name)
        .map_err(|e| ExecError::from_sys(e, STAGE, "openat(existing device node)"))?;
    let meta = std::fs::File::from(
        fd.try_clone()
            .map_err(|e| ExecError::from_io(&e, STAGE, "dup"))?,
    )
    .metadata()
    .map_err(|e| ExecError::from_io(&e, STAGE, "fstat(existing device node)"))?;
    check_existing_node(
        meta.file_type().is_char_device(),
        meta.rdev(),
        meta.mode() & 0o7777,
        d,
    )
}

/// 既存ノードの検証本体（純粋関数）。文字デバイスかつ `rdev`・モードが期待と完全一致のときだけ通る。
fn check_existing_node(
    is_char: bool,
    rdev: u64,
    mode: u32,
    d: &DefaultDevice,
) -> Result<(), ExecError> {
    if is_char && rdev == sys::makedev(d.major, d.minor) && mode == d.mode {
        return Ok(());
    }
    Err(ExecError::new(
        ErrorCode::FailedPrecondition,
        STAGE,
        format!(
            "the existing entry dev/{} is not the expected character device {}:{} with mode {:o}",
            d.name.to_string_lossy(),
            d.major,
            d.minor,
            d.mode
        ),
    ))
}

/// 作成直後のノードが自分の作った文字デバイス（期待する `rdev`）であることの検証。一致しなければ
/// 作成直後に名前が差し替えられたとみなして拒否する（別 inode のモードを変えない）。
fn check_created_node(is_char: bool, rdev: u64, d: &DefaultDevice) -> Result<(), ExecError> {
    if is_char && rdev == sys::makedev(d.major, d.minor) {
        return Ok(());
    }
    Err(ExecError::new(
        ErrorCode::FailedPrecondition,
        STAGE,
        format!(
            "the device node {} was replaced right after creation",
            d.name.to_string_lossy()
        ),
    ))
}

#[cfg(not(test))]
fn mknod_syscall(dev: BorrowedFd<'_>, d: &DefaultDevice) -> Result<(), SysError> {
    sys::make_char_device(dev, d.name, d.mode, d.major, d.minor)
}

/// dry-run: 呼び出しを記録し、`MKNOD_SCRIPT` に積んだ結果を先頭から返す（空なら `Ok`）。
#[cfg(test)]
fn mknod_syscall(_dev: BorrowedFd<'_>, d: &DefaultDevice) -> Result<(), SysError> {
    tests::MKNOD_CALLS.with(|c| {
        c.borrow_mut().push((
            d.name.to_string_lossy().into_owned(),
            d.major,
            d.minor,
            d.mode,
        ))
    });
    tests::MKNOD_SCRIPT.with(|s| {
        let mut s = s.borrow_mut();
        if s.is_empty() { Ok(()) } else { s.remove(0) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    type Call = (String, u32, u32, u32);

    thread_local! {
        /// dry-run が記録した `(name, major, minor, mode)`（テストスレッドごと）。
        pub(super) static MKNOD_CALLS: RefCell<Vec<Call>> = const { RefCell::new(Vec::new()) };
        /// dry-run が次に返す結果（先頭から消費。空なら `Ok`）。
        pub(super) static MKNOD_SCRIPT: RefCell<Vec<Result<(), SysError>>> =
            const { RefCell::new(Vec::new()) };
    }

    fn take_calls() -> Vec<Call> {
        MKNOD_SCRIPT.with(|s| s.borrow_mut().clear());
        MKNOD_CALLS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    struct Tmp(PathBuf);

    impl Tmp {
        fn new(label: &str) -> Self {
            let base = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("fandhe-devices-{label}-{}", std::process::id()));
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

    fn open_root(path: &Path) -> OwnedFd {
        use std::os::unix::ffi::OsStrExt as _;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        sys::open_dir_path_nofollow(None, &c).unwrap()
    }

    /// CORE-1: 作成対象は OCI default devices の 6 種で、major/minor/モードが具体値と一致する。
    #[test]
    fn core1_default_device_table_is_exact() {
        let got: Vec<_> = DEFAULT_DEVICES
            .iter()
            .map(|d| (d.name.to_str().unwrap(), d.major, d.minor, d.mode))
            .collect();
        assert_eq!(
            got,
            vec![
                ("null", 1, 3, 0o666),
                ("zero", 1, 5, 0o666),
                ("full", 1, 7, 0o666),
                ("random", 1, 8, 0o666),
                ("urandom", 1, 9, 0o666),
                ("tty", 5, 0, 0o666),
            ]
        );
    }

    /// CORE-1: `dev` が無ければ rootfs 配下に作り、6 種すべてを `dev` fd 起点の 1 要素名で作る。
    #[test]
    fn core1_devices_create_missing_dev_dir() {
        take_calls();
        let t = Tmp::new("missing");
        let root = open_root(&t.0);
        let report = create_default_devices_at(root.as_fd()).unwrap();
        assert!(t.0.join("dev").is_dir());
        assert_eq!(report.nodes.len(), 6);
        assert!(
            report
                .nodes
                .iter()
                .all(|n| n.status == DeviceNodeStatus::Created)
        );
        let want: Vec<Call> = vec![
            ("null".into(), 1, 3, 0o666),
            ("zero".into(), 1, 5, 0o666),
            ("full".into(), 1, 7, 0o666),
            ("random".into(), 1, 8, 0o666),
            ("urandom".into(), 1, 9, 0o666),
            ("tty".into(), 5, 0, 0o666),
        ];
        assert_eq!(take_calls(), want);
    }

    /// CORE-1: `dev` がホスト側ディレクトリへの symlink なら違反記録付きで拒否し、mknod は 0 回。
    #[test]
    fn core1_devices_reject_symlinked_dev() {
        take_calls();
        let t = Tmp::new("symlink");
        let outside = t.0.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let rootfs = t.0.join("root");
        std::fs::create_dir_all(&rootfs).unwrap();
        std::os::unix::fs::symlink(&outside, rootfs.join("dev")).unwrap();
        let err = create_default_devices_at(open_root(&rootfs).as_fd()).unwrap_err();
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        let v = err.violation.as_ref().expect("violation record");
        assert_eq!(v.reason.as_str(), "path_symlink_or_not_directory");
        assert_eq!(v.behavior_id, "CORE-1");
        assert_eq!(
            v.subject.as_ref().map(|s| s.as_str().to_string()),
            Some(format!("{}/dev", rootfs.display()))
        );
        assert_eq!(take_calls(), Vec::<Call>::new());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    }

    /// CORE-1: `dev` が通常ファイルでも同様に拒否する。
    #[test]
    fn core1_devices_reject_dev_regular_file() {
        take_calls();
        let t = Tmp::new("file");
        std::fs::write(t.0.join("dev"), b"x").unwrap();
        let err = create_default_devices_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        assert_eq!(
            err.violation.as_ref().unwrap().reason.as_str(),
            "path_symlink_or_not_directory"
        );
        assert_eq!(take_calls(), Vec::<Call>::new());
    }

    /// CORE-1: `EEXIST` の既存エントリが通常ファイルなら拒否し、内容を変えない。
    #[test]
    fn core1_devices_eexist_regular_file_is_rejected() {
        take_calls();
        let t = Tmp::new("eexist");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        std::fs::write(t.0.join("dev/null"), b"keep").unwrap();
        MKNOD_SCRIPT.with(|s| *s.borrow_mut() = vec![Err(SysError::Os(sys::EEXIST))]);
        let err = create_default_devices_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        assert_eq!(std::fs::read(t.0.join("dev/null")).unwrap(), b"keep");
        assert_eq!(take_calls().len(), 1);
    }

    /// CORE-1: `EEXIST` の既存エントリが symlink でも（辿らず）拒否する。
    #[test]
    fn core1_devices_eexist_symlink_is_rejected() {
        take_calls();
        let t = Tmp::new("eexist-link");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        std::os::unix::fs::symlink("/dev/null", t.0.join("dev/null")).unwrap();
        MKNOD_SCRIPT.with(|s| *s.borrow_mut() = vec![Err(SysError::Os(sys::EEXIST))]);
        let err = create_default_devices_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        take_calls();
    }

    /// CORE-1: 既存ノード検証は、文字デバイス・`rdev`・モード 0666 がすべて一致したときだけ通る。
    #[test]
    fn core1_devices_existing_node_check_is_exact() {
        let d = &DEFAULT_DEVICES[0];
        assert!(check_existing_node(true, 0x103, 0o666, d).is_ok());
        for (is_char, rdev, mode) in [
            (false, 0x103, 0o666),
            (true, 0x105, 0o666),
            (true, 0x103, 0o600),
        ] {
            let err = check_existing_node(is_char, rdev, mode, d).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert_eq!(err.stage, IsolationStage::CreateDevices);
            assert_eq!(
                err.message,
                "the existing entry dev/null is not the expected character device 1:3 with mode 666"
            );
        }
    }

    /// CORE-1: rootless 等で `EPERM` なら `PermissionDenied`（段 `CreateDevices`）で fail-closed。
    #[test]
    fn core1_devices_eperm_fails_closed() {
        take_calls();
        let t = Tmp::new("eperm");
        MKNOD_SCRIPT.with(|s| *s.borrow_mut() = vec![Err(SysError::Os(sys::EPERM))]);
        let err = create_default_devices_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        assert!(err.violation.is_none());
        assert_eq!(take_calls().len(), 1);
    }

    /// CORE-1: 作成直後の検証は、文字デバイスかつ `rdev` 一致のときだけ通る。
    #[test]
    fn core1_devices_verify_rejects_swapped_node() {
        let d = &DEFAULT_DEVICES[0];
        assert!(check_created_node(true, 0x103, d).is_ok());
        for (is_char, rdev) in [(false, 0x103), (true, 0x105)] {
            let err = check_created_node(is_char, rdev, d).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert_eq!(err.stage, IsolationStage::CreateDevices);
            assert_eq!(
                err.message,
                "the device node null was replaced right after creation"
            );
        }
    }
}
