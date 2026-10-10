//! コンテナ起動時の `/dev` 用 tmpfs のマウントと、基本デバイスノード 6 種・default symlink 4 本の作成
//! （CORE-1・SEC-1・TASK-27.6・TASK-29 追補・#834・#1297・#1653・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! `docker export` 由来の rootfs には `/dev/null` 等が入っておらず、これらが無いとプログラムが
//! 異常終了する（PoC-15 で `iperf3 -s` が SIGSEGV する事象を確認）。OCI Runtime Spec の
//! default devices に相当する 6 種（`null`・`zero`・`full`・`random`・`urandom`・`tty`）を、
//! CDI の deviceNodes（GPU 系・TASK-127）とは独立した常設の責務として作る。
//!
//! 作成先はホスト上の rootfs ディレクトリの `dev` ではなく、本モジュールが `dev` に載せる専用の tmpfs
//! （runc 方式。設計ドラフト `docs/design/dev-default-mounts.md` 3.1・オーナー判断 2026-10-10）である。
//! これによりノードがホスト側の rootfs に残らず、イメージ同梱の `dev` 配下（偽ノード等）は tmpfs に
//! 覆い隠されてコンテナから見えない。tmpfs の作成は `sys::mount_dev_tmpfs_on`（#1652。mode 0755・
//! 64 MiB・`nosuid|strictatime`・`nodev`/`noexec` なし）を使う。
//!
//! あわせて OCI Runtime Spec の default symlink 4 本（`dev/fd` → `/proc/self/fd`、`dev/stdin`・
//! `dev/stdout`・`dev/stderr` → `/proc/self/fd/{0,1,2}`。#1297）も同じマウントのルート fd 起点で作る。これが
//! 無いと `exec` 前検査（`process.rs` の `verify_script_fd_path`）が新 root の `/dev/fd/N` を解決できず、
//! シェバン付きスクリプトを拒否する。参照先は pivot 後のコンテナ内で解決され、作成時にホスト側では辿らない。
//!
//! `crate::exec` の最小実行フロー第 3 段。呼び出し元は TASK-29 の `oci_runtime` と fork 段（#831）を
//! 想定し、次の順で通す。
//!
//! ```text
//! prepare_rootfs(&isolation, rootfs) -> PreparedRootfs
//!   -> create_default_devices(&isolation, &prepared) -> DeviceReport   // 本モジュール
//!        （dev に tmpfs → ノード 6 種 → symlink 4 本）
//!   -> [/dev/shm は `mount_tmpfs` が集合（既定 64 MiB を含む。#1654）から、/dev/pts・/dev/ptmx は #1656 が本モジュールの tmpfs の上に載せる]
//!   -> mount_tmpfs / inject_files
//!   -> pivot_root(&isolation, prepared)
//! ```
//!
//! `prepare_rootfs` の `check_no_submounts` は準備時点の検査であり、本モジュールが載せた tmpfs は
//! `pivot_root` を越えて新 root の `/dev` になる。ノード作成は「準備の後・切替の前」に置く。
//!
//! # 契約
//!
//! - **fd 起点**: [`PreparedRootfs`] の新しい mount top の fd から `dev` を `O_PATH|O_NOFOLLOW|O_DIRECTORY`
//!   で開き（無ければ作る）、その fd へ tmpfs を載せる。以後の作成（`mknodat`・`symlink`）の起点は
//!   **載せたマウントのルート fd** で、パス文字列を連結せず、マウント後に名前で `dev` を開き直した fd を
//!   作成の起点にしない（開き直しは事後検証専用）。`dev` が symlink・非ディレクトリなら
//!   `path_symlink_or_not_directory` の違反記録付きで、何もマウントせず拒否する（rootfs の外へ作らない）
//! - **ホストへ伝播させない・移動検査**: マウント直前に `dev` が shared propagation でないこと、fd 固定後に
//!   改名・移動・削除されていないことを確かめ、違反は `target_on_shared_mount`・`target_moved` の記録付きで
//!   拒否する（`mount_tmpfs` と同じ）
//! - **事後条件**: マウント後に `dev` を開き直し（作成はしない）、tmpfs であること、マウント前の fd とは別の
//!   マウントであること、自分のマウントそのものであることを確かめる（fail-closed。`mount_tmpfs` と同じ判定）
//! - **対応カーネル**: Linux 5.2 以降の新マウント API。未対応（`ENOSYS`）は `mount(2)` へ縮退せず
//!   `Unimplemented`（段 `CreateDevices`）で拒否する
//! - **tmpfs 上の `EEXIST` は検証を残す**: 新しい tmpfs は空で、マウント namespace は呼び出しスレッド専用の
//!   ため通常は起きず、結果はすべて `Created` になる。それでも `EEXIST` が起きた場合（`/proc/<pid>/root`
//!   経由で第三者が書き込んだ等）は、既存エントリが文字デバイス・`rdev`・モード（0666）まで完全一致のとき
//!   だけ [`DeviceNodeStatus::AlreadyPresent`] とし、それ以外は `FailedPrecondition`（段 `CreateDevices`）で
//!   拒否する（拒否へ一律に倒さず、従来の検証を弱めない）
//! - **モード補正**: `mknodat` のモードは umask で削られるため、作成に成功したノードだけを
//!   `O_PATH|O_NOFOLLOW` で開き直し、文字デバイス・`rdev` の一致を検証した fd に対して magic link
//!   経由で 0666 に補正する（作成直後の差し替えで別 inode の権限を変えない）
//! - **default symlink は完全一致のみ受け入れる**: ノード 6 種の作成後に symlink 4 本をマウントのルート fd
//!   の magic link 起点で `symlink(2)` する（最終要素は辿らない）。`EEXIST` は `readlink(2)` の結果が
//!   期待する参照先と 1 バイトも違わず一致するときだけ [`DeviceLinkStatus::AlreadyPresent`] とし、別の
//!   参照先・通常ファイル・ディレクトリは上書きせず `FailedPrecondition`（段 `CreateDevices`）で拒否する
//! - **rootless は fail-closed**: 非特権 user namespace では tmpfs までは載るが、文字デバイスの `mknod(2)` が
//!   `EPERM` になり `PermissionDenied`（段 `CreateDevices`）で拒否する。黙ってデバイス無しで起動させない。
//!   この場合も載せた tmpfs は外す
//! - **失敗時の後始末**: どこかで失敗したら、この呼び出しが載せたマウントを fd 経由で `umount2(MNT_DETACH)` で
//!   外し（名前から開き直した先は外さない）、この呼び出しの `mkdirat` が成功した `dev` だけを
//!   `unlinkat(AT_REMOVEDIR)` で消す（空ディレクトリしか消えないため既存の内容は壊さない）。tmpfs ごと外す
//!   のでノードは残らない。後始末は最善努力で、失敗しても元のエラーを返す。呼び出し後もプロセスは
//!   破棄する（`crate::exec` のモジュール doc の契約）
//! - **1 プロセス 1 回**: 同じ [`PreparedRootfs`] に 2 回呼ぶと tmpfs が重なる（2 回目は新しい tmpfs 上で
//!   再び `Created` になり、rootfs の外へは書かない）。重ね掛けの検出（拒否）は行わない
//! - **同一スレッド**: `MountIsolation::establish` と同じスレッドで呼ぶ
//!
//! # 未対応（REPAIR-3: 実装済みを装わない）
//!
//! - rootless 向けのホスト `/dev/*` の bind mount による供給（runc 相当。CORE-6・SEC-5。#1660）。
//!   本実装の rootless 経路は `PermissionDenied` で止まる。user namespace が載せたマウント上のデバイスが
//!   開けるか（`nodev` 相当の扱い）は本モジュールでは確かめておらず、#1660 で一次情報を確認する（未確認）
//! - `/dev/pts`・`/dev/ptmx`（#1656）。`/dev/console` は端末機能の親 issue で
//!   別途設計する（設計ドラフト 3.5）
//! - `spawn_container` の最小フローへの本関数の配線（#1314）
//!
//! # 単体テストの安全策
//!
//! `mknodat(2)`・tmpfs のマウント・解除・マウント観測は `cfg(test)` では dry-run に差し替わる
//! （`mknod_syscall`・`mount_dev_tmpfs_syscall`・`umount_dev_syscall`・`observe_dev_mount`）。root で
//! `cargo test` を実行してもホストへ実ノードやマウントを作らない。symlink は特権不要で一時ディレクトリ内
//! にしか作られないため dry-run にせず実ファイルシステムで照合する。実機での挙動は結合試験
//! `tests/default_devices.rs`（`-- --ignored`）で確認する。

use std::ffi::{CStr, CString, OsStr};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use crate::sys::{self, SysError};
use crate::traits::types::ErrorCode;

use super::tmpfs::{MountObservation, check_new_tmpfs};
use super::{
    ExecError, IsolationStage, MountIsolation, PreparedRootfs, ViolationReason, fd_still_at,
    mount_is_shared, open_error,
};

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

/// 作成する 1 本の default symlink の定義。
struct DefaultLink {
    /// `dev` 直下の名前（`/` を含まない静的な 1 要素）。
    name: &'static CStr,
    /// 期待する参照先（pivot 後のコンテナ内で解決される絶対パス）。
    target: &'static str,
}

/// OCI Runtime Spec の default symlink。任意の名前・参照先を受け付ける経路は作らない。
const DEFAULT_LINKS: [DefaultLink; 4] = [
    DefaultLink {
        name: c"fd",
        target: "/proc/self/fd",
    },
    DefaultLink {
        name: c"stdin",
        target: "/proc/self/fd/0",
    },
    DefaultLink {
        name: c"stdout",
        target: "/proc/self/fd/1",
    },
    DefaultLink {
        name: c"stderr",
        target: "/proc/self/fd/2",
    },
];

/// 1 symlink の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceLinkStatus {
    /// 今回作成した。
    Created,
    /// 既に存在し、参照先が期待と完全一致すると検証済みのため何も変更していない。
    AlreadyPresent,
}

/// [`create_default_devices`] が処理した 1 本の symlink の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceLinkOutcome {
    /// `dev` 直下の名前。
    pub name: &'static str,
    /// 期待する参照先。
    pub target: &'static str,
    /// 作成したか、既存だったか。
    pub status: DeviceLinkStatus,
}

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
    /// default symlink 4 本の結果（定義順: fd・stdin・stdout・stderr。#1297）。
    pub links: Vec<DeviceLinkOutcome>,
}

/// rootfs の `dev` に専用の tmpfs を載せ、その上へ基本デバイスノード 6 種と default symlink 4 本を作る。
///
/// [`prepare_rootfs`](super::prepare_rootfs) の後、[`pivot_root`](super::pivot_root) の前に呼ぶ。
/// [`MountIsolation`] の証跡が現在の状態と一致しなければ副作用なしに拒否する（fail-closed）。
/// 詳細な契約はモジュール doc を参照。
pub fn create_default_devices(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
) -> Result<DeviceReport, ExecError> {
    isolation.verify_caller(STAGE)?;
    create_default_devices_at(prepared.new_root(), &|dir| mount_is_shared(dir, STAGE))
}

/// この呼び出しが rootfs・mount namespace に加えた変更の記録（失敗時の [`roll_back_dev`] が使う）。
struct DevState {
    /// この呼び出しの `mkdirat` が成功して作った `dev` を指す fd（既存・競合で先に作られた `dev` は `None`）。
    /// 後始末で名前 `dev` が今も同じ inode を指すか（dev・ino）を確かめる識別情報として使う（差し替え対策）。
    created_dev: Option<OwnedFd>,
    /// 載せた「自分のマウントのルート」を指す fd（付け替え直後に保持し、事後検証に通らなくても外せる）。
    mounted: Option<OwnedFd>,
}

/// [`create_default_devices`] の証跡検証後の本体。`root` は rootfs（新しい mount top）の fd、`is_shared` は
/// `dev` が shared propagation かの判定（単体テストはホストの mountinfo に依存しないよう差し替える）。
/// 単体テストは証跡を偽造せず一時ディレクトリの fd を直接渡す。失敗時は後始末をしてから元のエラーを返す。
fn create_default_devices_at(
    root: BorrowedFd<'_>,
    is_shared: &dyn Fn(&OwnedFd) -> Result<bool, ExecError>,
) -> Result<DeviceReport, ExecError> {
    let rootfs = root_display(root);
    let mut state = DevState {
        created_dev: None,
        mounted: None,
    };
    let result = populate_dev(root, &rootfs, is_shared, &mut state);
    if result.is_err() {
        roll_back_dev(root, &state);
    }
    result
}

/// `dev` の固定・tmpfs のマウント・事後検証・ノードと symlink の作成。変更は `state` に記録する。
fn populate_dev(
    root: BorrowedFd<'_>,
    rootfs: &Path,
    is_shared: &dyn Fn(&OwnedFd) -> Result<bool, ExecError>,
    state: &mut DevState,
) -> Result<DeviceReport, ExecError> {
    let (opened, created) = open_dev_dir(root, rootfs)?;
    // 作成した `dev` の fd は複製せず所有権ごと `state` へ移す（複製の失敗で記録漏れが起きないように）。
    // 以降の処理はこの fd を借りて使い、どの失敗経路でも後始末が識別情報を参照できる。
    let local;
    let dev: &OwnedFd = if created {
        &*state.created_dev.insert(opened)
    } else {
        local = opened;
        &local
    };
    let subject = rootfs.join("dev");
    if is_shared(dev)? {
        return Err(ExecError::from_violation_at(
            ViolationReason::TargetOnSharedMount,
            Some(&subject),
            STAGE,
        ));
    }
    // fd 固定後に別プロセスが `dev`（または祖先）を改名・移動・削除していれば拒否する（`mount_tmpfs` と同じ）。
    if !fd_still_at(dev, &subject) {
        return Err(ExecError::from_violation_at(
            ViolationReason::TargetMoved,
            Some(&subject),
            STAGE,
        ));
    }
    // 付け替え直後に自分のマウントの fd を保持する（事後検証に通らなくても後始末が外せる）。
    let mount_fd = mount_dev_tmpfs_syscall(dev.as_fd(), sys::DevTmpfsCreate::new())
        .map_err(dev_mount_error)?;
    let mount_fd = &*state.mounted.insert(mount_fd);
    // 事後検証専用の開き直し（作成の起点にはしない）。
    let after = sys::open_dir_path_nofollow(Some(root), c"dev")
        .map_err(|e| open_error(e, true, rootfs, &[OsStr::new("dev")]).at_stage(STAGE))?;
    let observed = observe_dev_mount(dev, &after, mount_fd)?;
    check_new_tmpfs(observed, "/dev", STAGE)?;

    let mount = mount_fd.as_fd();
    let mut nodes = Vec::with_capacity(DEFAULT_DEVICES.len());
    for d in &DEFAULT_DEVICES {
        let status = match mknod_syscall(mount, d) {
            Ok(()) => {
                finalize_node(mount, d)?;
                DeviceNodeStatus::Created
            }
            Err(SysError::Os(sys::EEXIST)) => {
                verify_existing_node(mount, d)?;
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
    let mut links = Vec::with_capacity(DEFAULT_LINKS.len());
    for l in &DEFAULT_LINKS {
        let status = create_link(mount, l)?;
        links.push(DeviceLinkOutcome {
            name: l.name.to_str().unwrap_or("?"),
            target: l.target,
            status,
        });
    }
    Ok(DeviceReport { nodes, links })
}

/// 新マウント API の失敗をエラーにする。`Unsupported`（`ENOSYS`・対応外アーキテクチャ）は縮退せず
/// `Unimplemented` で拒否する（Linux 5.2 以降が必要）。
fn dev_mount_error(e: SysError) -> ExecError {
    if matches!(e, SysError::Unsupported) {
        return ExecError::new(
            ErrorCode::Unimplemented,
            STAGE,
            "the /dev tmpfs mount requires the new mount API (fsopen, fsconfig, fsmount, move_mount; Linux 5.2 or later)",
        );
    }
    ExecError::from_sys(e, STAGE, "mount(tmpfs on /dev)")
}

/// 失敗時の後始末（最善努力）。載せたマウントを fd 経由で外してから、この呼び出しが作った `dev` を消す。
///
/// 外すのは付け替え時に得た自分のマウントの fd が指すマウントだけで、名前から開き直した先は外さない。
/// `unlinkat(AT_REMOVEDIR)` は空ディレクトリしか消さないため、既存の `dev` の内容は壊さない。
fn roll_back_dev(root: BorrowedFd<'_>, state: &DevState) {
    if let Some(mount) = &state.mounted
        && let Ok(target) = CString::new(format!("/proc/thread-self/fd/{}", mount.as_raw_fd()))
    {
        let _ = umount_dev_syscall(&target);
    }
    // 名前 `dev` が作成時と同じ inode を指すと確認できたときだけ消す。差し替え・移動・確認不能は残す
    // （fail-closed。別プロセスが置いた別ディレクトリを消さない）。
    if let Some(created) = &state.created_dev
        && name_dev_is_same_inode(root, created)
    {
        let _ = sys::remove_dir_at(root, c"dev");
    }
}

/// `root` 直下の名前 `dev` が `created` と同じ inode（st_dev・st_ino）を指すか。開けない・取得できない場合は偽。
fn name_dev_is_same_inode(root: BorrowedFd<'_>, created: &OwnedFd) -> bool {
    let Ok(now) = sys::open_dir_path_nofollow(Some(root), c"dev") else {
        return false;
    };
    let identity = |fd: &OwnedFd| {
        let meta = std::fs::File::from(fd.try_clone().ok()?).metadata().ok()?;
        Some((meta.dev(), meta.ino()))
    };
    matches!((identity(created), identity(&now)), (Some(a), Some(b)) if a == b)
}

/// マウントのルート fd の magic link を起点に symlink 1 本を作る。`symlink(2)` は最終要素を辿らないため、
/// 既存の悪性 symlink 経由で rootfs の外へ作らない。`EEXIST` は参照先を検証する。
fn create_link(dev: BorrowedFd<'_>, l: &DefaultLink) -> Result<DeviceLinkStatus, ExecError> {
    let name = l.name.to_string_lossy();
    let path = fd_magic_path(dev.as_raw_fd()).join(&*name);
    #[cfg(test)]
    tests::EVENTS.with(|e| {
        e.borrow_mut().push(tests::Event::Symlink {
            dirfd: dev.as_raw_fd(),
            name: name.to_string(),
            target: l.target.to_owned(),
        })
    });
    match std::os::unix::fs::symlink(l.target, &path) {
        Ok(()) => Ok(DeviceLinkStatus::Created),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = match std::fs::read_link(&path) {
                Ok(t) => Some(t),
                // symlink でない（EINVAL）。
                Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => None,
                Err(e) => {
                    return Err(ExecError::from_io(
                        &e,
                        STAGE,
                        &format!("readlink(dev/{name})"),
                    ));
                }
            };
            check_existing_link(existing.as_deref(), l)?;
            Ok(DeviceLinkStatus::AlreadyPresent)
        }
        Err(e) => Err(ExecError::from_io(
            &e,
            STAGE,
            &format!("symlinkat(dev/{name})"),
        )),
    }
}

/// 既存 symlink の検証本体（純粋関数）。`existing` は `readlink` の結果（symlink でなければ `None`）。
/// 参照先が期待とバイト列で完全一致のときだけ通る（正規化しない）。
fn check_existing_link(existing: Option<&Path>, l: &DefaultLink) -> Result<(), ExecError> {
    if existing.is_some_and(|t| t.as_os_str() == OsStr::new(l.target)) {
        return Ok(());
    }
    Err(ExecError::new(
        ErrorCode::FailedPrecondition,
        STAGE,
        format!(
            "the existing entry dev/{} is not a symlink to {}",
            l.name.to_string_lossy(),
            l.target
        ),
    ))
}

/// 違反記録の対象表示用に rootfs の実パスを得る（取れなければ固定文字列）。
fn root_display(root: BorrowedFd<'_>) -> PathBuf {
    std::fs::read_link(fd_magic_path(root.as_raw_fd()))
        .unwrap_or_else(|_| PathBuf::from("<rootfs>"))
}

fn fd_magic_path(fd: i32) -> PathBuf {
    PathBuf::from(format!("/proc/thread-self/fd/{fd}"))
}

/// `root` 直下の `dev` を `O_PATH|O_NOFOLLOW|O_DIRECTORY` で開く。無ければ rootfs 配下に作って開き直し、
/// 自分で作ったときだけ戻り値の第 2 要素を真にする。symlink・非ディレクトリは違反記録付きで拒否する
/// （rootfs の外へ作らない）。
fn open_dev_dir(root: BorrowedFd<'_>, rootfs: &Path) -> Result<(OwnedFd, bool), ExecError> {
    let names = [OsStr::new("dev")];
    let open = || sys::open_dir_path_nofollow(Some(root), c"dev");
    match open() {
        Ok(fd) => Ok((fd, false)),
        Err(SysError::Os(sys::ENOENT)) => {
            // `mkdirat` は最終要素の symlink を辿らない。競合で先に作られた（EEXIST）場合は自分が作った
            // 扱いにせず、開き直しで種別を検証する。
            let created = match sys::mkdir_at(root, c"dev", 0o755) {
                Ok(()) => true,
                Err(SysError::Os(sys::EEXIST)) => false,
                Err(e) => return Err(ExecError::from_sys(e, STAGE, "mkdirat(dev)")),
            };
            match open() {
                Ok(fd) => Ok((fd, created)),
                Err(e) => {
                    // 作成直後の開き直し失敗は識別用の fd が得られないため、呼び出し元の後始末に
                    // 渡せない。ここで空ディレクトリだけを消す（`AT_REMOVEDIR` は空でない dev・symlink を
                    // 消さない）。ホスト側 rootfs に作成物を残さない。
                    if created {
                        let _ = sys::remove_dir_at(root, c"dev");
                    }
                    Err(open_error(e, true, rootfs, &names).at_stage(STAGE))
                }
            }
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
fn mknod_syscall(dir: BorrowedFd<'_>, d: &DefaultDevice) -> Result<(), SysError> {
    sys::make_char_device(dir, d.name, d.mode, d.major, d.minor)
}

/// dry-run: 呼び出しを記録し、`MKNOD_SCRIPT` に積んだ結果を先頭から返す（空なら `Ok`）。
#[cfg(test)]
fn mknod_syscall(dir: BorrowedFd<'_>, d: &DefaultDevice) -> Result<(), SysError> {
    tests::EVENTS.with(|e| {
        e.borrow_mut().push(tests::Event::Mknod {
            dirfd: dir.as_raw_fd(),
            name: d.name.to_string_lossy().into_owned(),
            major: d.major,
            minor: d.minor,
            mode: d.mode,
        })
    });
    tests::MKNOD_SCRIPT.with(|s| {
        let mut s = s.borrow_mut();
        if s.is_empty() { Ok(()) } else { s.remove(0) }
    })
}

#[cfg(not(test))]
fn mount_dev_tmpfs_syscall(
    target_dir: BorrowedFd<'_>,
    create: sys::DevTmpfsCreate,
) -> Result<OwnedFd, SysError> {
    sys::mount_dev_tmpfs_on(target_dir, create)
}

/// dry-run: 新マウント API を呼ばず、(付け替え先の実体・固定パラメータ・返す fd) を記録し、付け替え先の
/// fd の複製を「自分のマウント」として返す。`MOUNT_SCRIPT` に積んだ失敗を先に返せる。
#[cfg(test)]
fn mount_dev_tmpfs_syscall(
    target_dir: BorrowedFd<'_>,
    create: sys::DevTmpfsCreate,
) -> Result<OwnedFd, SysError> {
    let scripted = tests::MOUNT_SCRIPT.with(|s| s.borrow_mut().take());
    if let Some(e) = scripted {
        return Err(e);
    }
    let resolved = std::fs::read_link(fd_magic_path(target_dir.as_raw_fd()))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let fd = target_dir
        .try_clone_to_owned()
        .map_err(|_| SysError::Os(sys::EBADF))?;
    tests::EVENTS.with(|e| {
        e.borrow_mut().push(tests::Event::MountDev {
            target: resolved,
            attr_bits: create.attr_bits(),
            mode: create.mode(),
            size_bytes: create.size_bytes(),
            fd: fd.as_raw_fd(),
        })
    });
    Ok(fd)
}

#[cfg(not(test))]
fn umount_dev_syscall(target: &CStr) -> Result<(), SysError> {
    sys::umount_detach_at(target)
}

/// dry-run: `umount2(2)` を呼ばず、解決した対象を記録する。
#[cfg(test)]
fn umount_dev_syscall(target: &CStr) -> Result<(), SysError> {
    let resolved = std::fs::read_link(target.to_string_lossy().as_ref())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    tests::EVENTS.with(|e| e.borrow_mut().push(tests::Event::Umount(resolved)));
    Ok(())
}

#[cfg(not(test))]
fn observe_dev_mount(
    before: &OwnedFd,
    after: &OwnedFd,
    own: &OwnedFd,
) -> Result<MountObservation, ExecError> {
    Ok(MountObservation {
        magic: sys::fs_type(after.as_fd())
            .map_err(|e| ExecError::from_sys(e, STAGE, "fstatfs(/dev)"))?,
        before_mnt_id: super::fd_mount_id(before, STAGE)?,
        after_mnt_id: super::fd_mount_id(after, STAGE)?,
        own_mnt_id: super::fd_mount_id(own, STAGE)?,
    })
}

/// dry-run: 既定は「別マウントの tmpfs で自分のマウント」を観測したことにする。`OBSERVE_SCRIPT` で異常値を
/// 差し込める（実機の検証は結合試験で行う）。
#[cfg(test)]
fn observe_dev_mount(
    _before: &OwnedFd,
    _after: &OwnedFd,
    _own: &OwnedFd,
) -> Result<MountObservation, ExecError> {
    Ok(tests::OBSERVE_SCRIPT
        .with(|s| s.borrow_mut().take())
        .unwrap_or(MountObservation {
            magic: sys::TMPFS_MAGIC,
            before_mnt_id: 1,
            after_mnt_id: 2,
            own_mnt_id: 2,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    type Call = (String, u32, u32, u32);

    /// dry-run が順序つきで記録する 1 件の副作用（テストスレッドごと）。
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) enum Event {
        /// tmpfs のマウント（`target` は付け替え先の解決パス、`fd` は返したマウント fd の raw 値）。
        MountDev {
            target: String,
            attr_bits: u32,
            mode: u32,
            size_bytes: u64,
            fd: i32,
        },
        Mknod {
            dirfd: i32,
            name: String,
            major: u32,
            minor: u32,
            mode: u32,
        },
        Symlink {
            dirfd: i32,
            name: String,
            target: String,
        },
        /// `umount2(MNT_DETACH)`（解決した対象パス）。
        Umount(String),
    }

    thread_local! {
        pub(super) static EVENTS: RefCell<Vec<Event>> = const { RefCell::new(Vec::new()) };
        /// dry-run の mknod が次に返す結果（先頭から消費。空なら `Ok`）。
        pub(super) static MKNOD_SCRIPT: RefCell<Vec<Result<(), SysError>>> =
            const { RefCell::new(Vec::new()) };
        /// dry-run のマウントが次に返す失敗（消費される）。
        pub(super) static MOUNT_SCRIPT: RefCell<Option<SysError>> = const { RefCell::new(None) };
        /// dry-run の事後観測が次に返す値（消費される。無ければ正常値）。
        pub(super) static OBSERVE_SCRIPT: RefCell<Option<MountObservation>> =
            const { RefCell::new(None) };
    }

    /// 記録とスクリプトをすべて消し、記録済みの `mknodat` 呼び出しを返す。
    fn take_calls() -> Vec<Call> {
        MKNOD_SCRIPT.with(|s| s.borrow_mut().clear());
        MOUNT_SCRIPT.with(|s| *s.borrow_mut() = None);
        OBSERVE_SCRIPT.with(|s| *s.borrow_mut() = None);
        take_events()
            .into_iter()
            .filter_map(|e| match e {
                Event::Mknod {
                    name,
                    major,
                    minor,
                    mode,
                    ..
                } => Some((name, major, minor, mode)),
                _ => None,
            })
            .collect()
    }

    fn take_events() -> Vec<Event> {
        EVENTS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    fn run_at(root: BorrowedFd<'_>) -> Result<DeviceReport, ExecError> {
        create_default_devices_at(root, &|_| Ok(false))
    }

    /// `.0` は guard と同じパス（`t.0.join(..)` 用）。削除は guard の drop が行う（#1298）。
    struct Tmp(
        PathBuf,
        #[allow(dead_code)] crate::test_support::TestTempDir,
    );

    impl Tmp {
        fn new(label: &str) -> Self {
            let guard = crate::test_support::TestTempDir::new(&format!("devices-{label}"))
                .expect("create exclusive temp dir");
            Self(guard.path().to_path_buf(), guard)
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

    /// CORE-1・#1297: default symlink は OCI の 4 本で、名前は `dev` 直下の 1 要素。
    #[test]
    fn core1_default_link_table_is_exact() {
        let got: Vec<_> = DEFAULT_LINKS
            .iter()
            .map(|l| (l.name.to_str().unwrap(), l.target))
            .collect();
        assert_eq!(
            got,
            vec![
                ("fd", "/proc/self/fd"),
                ("stdin", "/proc/self/fd/0"),
                ("stdout", "/proc/self/fd/1"),
                ("stderr", "/proc/self/fd/2"),
            ]
        );
        for l in &DEFAULT_LINKS {
            let n = l.name.to_str().unwrap();
            assert!(!n.contains('/') && n != "." && n != "..", "{n}");
        }
    }

    /// CORE-1・#1297: `dev` の無い rootfs に symlink 4 本が期待する参照先で作られる。
    #[test]
    fn core1_devices_create_default_links() {
        take_calls();
        let t = Tmp::new("links");
        let report = run_at(open_root(&t.0).as_fd()).unwrap();
        assert_eq!(report.links.len(), 4);
        for (o, (n, tg)) in report.links.iter().zip([
            ("fd", "/proc/self/fd"),
            ("stdin", "/proc/self/fd/0"),
            ("stdout", "/proc/self/fd/1"),
            ("stderr", "/proc/self/fd/2"),
        ]) {
            assert_eq!(
                (o.name, o.target, o.status),
                (n, tg, DeviceLinkStatus::Created)
            );
            let p = t.0.join("dev").join(n);
            assert!(
                std::fs::symlink_metadata(&p)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(std::fs::read_link(&p).unwrap(), PathBuf::from(tg));
        }
        take_calls();
    }

    /// CORE-1・#1297: 期待どおりの既存 symlink は `AlreadyPresent` で受け入れ、変更しない。
    #[test]
    fn core1_devices_links_already_present_are_accepted() {
        take_calls();
        let t = Tmp::new("links-present");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        for l in &DEFAULT_LINKS {
            let n = l.name.to_str().unwrap();
            std::os::unix::fs::symlink(l.target, t.0.join("dev").join(n)).unwrap();
        }
        let report = run_at(open_root(&t.0).as_fd()).unwrap();
        assert!(
            report
                .links
                .iter()
                .all(|o| o.status == DeviceLinkStatus::AlreadyPresent)
        );
        assert_eq!(
            std::fs::read_link(t.0.join("dev/stdout")).unwrap(),
            PathBuf::from("/proc/self/fd/1")
        );
        take_calls();
    }

    /// CORE-1・#1297: 別の参照先・末尾 `/` 違い・外へ向かう相対参照は上書きせず拒否し、辿らない。
    #[test]
    fn core1_devices_link_with_other_target_is_rejected() {
        for (label, target) in [
            ("other", "/proc/1/fd"),
            ("slash", "/proc/self/fd/"),
            ("escape", "../../outside"),
        ] {
            take_calls();
            let t = Tmp::new(&format!("link-{label}"));
            let outside = t.0.join("outside");
            std::fs::create_dir_all(&outside).unwrap();
            let rootfs = t.0.join("root");
            std::fs::create_dir_all(rootfs.join("dev")).unwrap();
            std::os::unix::fs::symlink(target, rootfs.join("dev/fd")).unwrap();
            let err = run_at(open_root(&rootfs).as_fd()).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert_eq!(err.stage, IsolationStage::CreateDevices);
            assert_eq!(
                err.message,
                "the existing entry dev/fd is not a symlink to /proc/self/fd"
            );
            assert_eq!(
                std::fs::read_link(rootfs.join("dev/fd")).unwrap(),
                PathBuf::from(target)
            );
            assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
            take_calls();
        }
    }

    /// CORE-1・#1297: 既存エントリが通常ファイル・ディレクトリなら拒否し、内容を変えない。
    #[test]
    fn core1_devices_link_non_symlink_is_rejected() {
        take_calls();
        let t = Tmp::new("link-file");
        std::fs::create_dir_all(t.0.join("dev/fd")).unwrap();
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(t.0.join("dev/fd").is_dir());
        std::fs::remove_dir(t.0.join("dev/fd")).unwrap();
        std::fs::write(t.0.join("dev/stdin"), b"keep").unwrap();
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(
            err.message,
            "the existing entry dev/stdin is not a symlink to /proc/self/fd/0"
        );
        assert_eq!(std::fs::read(t.0.join("dev/stdin")).unwrap(), b"keep");
        take_calls();
    }

    /// CORE-1: `dev` が無ければ rootfs 配下に作り、6 種すべてを `dev` fd 起点の 1 要素名で作る。
    #[test]
    fn core1_devices_create_missing_dev_dir() {
        take_calls();
        let t = Tmp::new("missing");
        let root = open_root(&t.0);
        let report = run_at(root.as_fd()).unwrap();
        assert!(t.0.join("dev").is_dir());
        assert_eq!(report.nodes.len(), 6);
        assert_eq!(report.links.len(), 4);
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
        let err = run_at(open_root(&rootfs).as_fd()).unwrap_err();
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        let v = err.violation.as_ref().expect("violation record");
        assert_eq!(v.reason.as_str(), "path_symlink_or_not_directory");
        assert_eq!(v.behavior_id, "CORE-1");
        assert_eq!(
            v.subject.as_ref().map(|s| s.as_str().to_string()),
            Some(format!("{}/dev", rootfs.display()))
        );
        assert_eq!(take_calls(), Vec::<Call>::new());
        // dev 検証で失敗するため symlink 作成には進まず、外には 1 本も作られない。
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    }

    /// CORE-1: `dev` が通常ファイルでも同様に拒否する。
    #[test]
    fn core1_devices_reject_dev_regular_file() {
        take_calls();
        let t = Tmp::new("file");
        std::fs::write(t.0.join("dev"), b"x").unwrap();
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
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
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
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
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
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
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
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

    fn count<F: Fn(&Event) -> bool>(events: &[Event], f: F) -> usize {
        events.iter().filter(|e| f(e)).count()
    }

    /// CORE-1・SEC-1・#1653: `dev` に tmpfs を載せてからノード 6 種・symlink 4 本を、マウントのルート fd
    /// 起点で作る（`dev` を開いた fd や名前の開き直しではない）。
    #[test]
    fn core1_1653_dev_tmpfs_then_nodes_then_links_from_mount_fd() {
        take_calls();
        let t = Tmp::new("order");
        let report = run_at(open_root(&t.0).as_fd()).unwrap();
        let events = take_events();
        let Some(Event::MountDev {
            target,
            attr_bits,
            mode,
            size_bytes,
            fd,
        }) = events.first().cloned()
        else {
            panic!("first event must be the tmpfs mount: {events:?}");
        };
        assert_eq!(target, format!("{}/dev", t.0.display()));
        assert_eq!(attr_bits, 0x22);
        assert_eq!(mode, 0o755);
        assert_eq!(size_bytes, 67_108_864);
        let names: Vec<_> = events
            .iter()
            .skip(1)
            .map(|e| match e {
                Event::Mknod { dirfd, name, .. } => (*dirfd, format!("mknod {name}")),
                Event::Symlink {
                    dirfd,
                    name,
                    target,
                } => (*dirfd, format!("symlink {name} {target}")),
                other => panic!("unexpected event {other:?}"),
            })
            .collect();
        assert_eq!(
            names.iter().map(|(_, n)| n.as_str()).collect::<Vec<_>>(),
            vec![
                "mknod null",
                "mknod zero",
                "mknod full",
                "mknod random",
                "mknod urandom",
                "mknod tty",
                "symlink fd /proc/self/fd",
                "symlink stdin /proc/self/fd/0",
                "symlink stdout /proc/self/fd/1",
                "symlink stderr /proc/self/fd/2",
            ]
        );
        assert!(names.iter().all(|(d, _)| *d == fd), "dirfd must be {fd}");
        assert_eq!(count(&events, |e| matches!(e, Event::Umount(_))), 0);
        assert!(
            report
                .nodes
                .iter()
                .all(|n| n.status == DeviceNodeStatus::Created)
        );
        assert!(
            report
                .links
                .iter()
                .all(|l| l.status == DeviceLinkStatus::Created)
        );
    }

    /// CORE-1・#1653: `dev` が symlink・通常ファイルなら何もマウントせず拒否する。
    #[test]
    fn core1_1653_symlinked_or_file_dev_is_rejected_without_mount() {
        for as_symlink in [true, false] {
            take_calls();
            let t = Tmp::new("reject");
            let outside = t.0.join("outside");
            std::fs::create_dir_all(&outside).unwrap();
            let rootfs = t.0.join("root");
            std::fs::create_dir_all(&rootfs).unwrap();
            if as_symlink {
                std::os::unix::fs::symlink(&outside, rootfs.join("dev")).unwrap();
            } else {
                std::fs::write(rootfs.join("dev"), b"keep").unwrap();
            }
            let err = run_at(open_root(&rootfs).as_fd()).unwrap_err();
            assert_eq!(err.stage, IsolationStage::CreateDevices);
            let v = err.violation.as_ref().expect("violation record");
            assert_eq!(v.reason.as_str(), "path_symlink_or_not_directory");
            assert_eq!(v.behavior_id, "CORE-1");
            assert_eq!(take_events(), Vec::<Event>::new());
            assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
            if !as_symlink {
                assert_eq!(std::fs::read(rootfs.join("dev")).unwrap(), b"keep");
            }
        }
    }

    /// CORE-1・#1653: マウント後にノード作成が失敗したら自分のマウントを外し、自分で作った `dev` を消す。
    #[test]
    fn core1_1653_failure_after_mount_unmounts_and_removes_created_dev() {
        take_calls();
        let t = Tmp::new("rollback");
        MKNOD_SCRIPT.with(|s| {
            *s.borrow_mut() = vec![Ok(()), Ok(()), Err(SysError::Os(sys::EPERM))];
        });
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        let events = take_events();
        assert_eq!(
            events.last(),
            Some(&Event::Umount(format!("{}/dev", t.0.display())))
        );
        assert_eq!(count(&events, |e| matches!(e, Event::Umount(_))), 1);
        assert!(!t.0.join("dev").exists());
        take_calls();
    }

    /// CORE-1・#1653: 作成後に `dev` が別ディレクトリへ差し替えられたら、後始末は差し替え後を消さず残す。
    #[test]
    fn core1_1653_rollback_keeps_swapped_dev() {
        let t = Tmp::new("swapped");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        let root = open_root(&t.0);
        let created = sys::open_dir_path_nofollow(Some(root.as_fd()), c"dev").unwrap();
        let state = DevState {
            created_dev: Some(created),
            mounted: None,
        };
        std::fs::rename(t.0.join("dev"), t.0.join("dev-moved")).unwrap();
        std::fs::create_dir(t.0.join("dev")).unwrap();
        roll_back_dev(root.as_fd(), &state);
        assert!(t.0.join("dev").is_dir());
        assert!(t.0.join("dev-moved").is_dir());
    }

    /// CORE-1・#1653: `dev` が作成時と同じ inode のままなら後始末で消す。
    #[test]
    fn core1_1653_rollback_removes_same_dev() {
        let t = Tmp::new("same");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        let root = open_root(&t.0);
        let created = sys::open_dir_path_nofollow(Some(root.as_fd()), c"dev").unwrap();
        let state = DevState {
            created_dev: Some(created),
            mounted: None,
        };
        roll_back_dev(root.as_fd(), &state);
        assert!(!t.0.join("dev").exists());
    }

    /// CORE-1・#1653: 既存の `dev`（内容あり）は、失敗してもマウントを外すだけで消さない。
    #[test]
    fn core1_1653_failure_keeps_preexisting_dev() {
        take_calls();
        let t = Tmp::new("keep");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        std::fs::write(t.0.join("dev/keep"), b"data").unwrap();
        MKNOD_SCRIPT.with(|s| *s.borrow_mut() = vec![Err(SysError::Os(sys::EPERM))]);
        run_at(open_root(&t.0).as_fd()).unwrap_err();
        let events = take_events();
        assert_eq!(count(&events, |e| matches!(e, Event::Umount(_))), 1);
        assert_eq!(std::fs::read(t.0.join("dev/keep")).unwrap(), b"data");
        take_calls();
    }

    /// CORE-1・SEC-1・#1653: 事後検証（tmpfs でない・自分のマウントでない）に通らなければ拒否して巻き戻す。
    #[test]
    fn core1_1653_post_verification_failure_rolls_back() {
        for (obs, msg) in [
            (
                MountObservation {
                    magic: 0xEF53,
                    before_mnt_id: 1,
                    after_mnt_id: 2,
                    own_mnt_id: 2,
                },
                "the mount at /dev is not tmpfs after mount",
            ),
            (
                MountObservation {
                    magic: sys::TMPFS_MAGIC,
                    before_mnt_id: 1,
                    after_mnt_id: 2,
                    own_mnt_id: 3,
                },
                "the mount at /dev is not the mount created by this call",
            ),
        ] {
            take_calls();
            let t = Tmp::new("postverify");
            OBSERVE_SCRIPT.with(|s| *s.borrow_mut() = Some(obs));
            let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert_eq!(err.stage, IsolationStage::CreateDevices);
            assert_eq!(err.message, msg);
            let events = take_events();
            assert_eq!(count(&events, |e| matches!(e, Event::Mknod { .. })), 0);
            assert_eq!(count(&events, |e| matches!(e, Event::Umount(_))), 1);
            assert!(!t.0.join("dev").exists());
        }
    }

    /// CORE-1・#1653: 新マウント API 未対応は `Unimplemented` で拒否し、マウントしていないので外さない。
    #[test]
    fn core1_1653_mount_unsupported_is_unimplemented() {
        take_calls();
        let t = Tmp::new("unsupported");
        MOUNT_SCRIPT.with(|s| *s.borrow_mut() = Some(SysError::Unsupported));
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::Unimplemented);
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        assert_eq!(take_events(), Vec::<Event>::new());
        assert!(!t.0.join("dev").exists());
        take_calls();
    }

    /// CORE-1・#1653: shared な `dev`・固定後に改名された `dev` はマウント前に拒否する。
    #[test]
    fn core1_1653_shared_or_moved_dev_is_rejected_before_mount() {
        take_calls();
        let t = Tmp::new("shared");
        let err = create_default_devices_at(open_root(&t.0).as_fd(), &|_| Ok(true)).unwrap_err();
        assert_eq!(
            err.violation.as_ref().unwrap().reason.as_str(),
            "target_on_shared_mount"
        );
        assert_eq!(take_events(), Vec::<Event>::new());
        assert!(!t.0.join("dev").exists());

        let t = Tmp::new("moved");
        let dev = t.0.join("dev");
        let moved = t.0.join("dev-moved");
        let err = create_default_devices_at(open_root(&t.0).as_fd(), &|_| {
            std::fs::rename(&dev, &moved).unwrap();
            Ok(false)
        })
        .unwrap_err();
        assert_eq!(
            err.violation.as_ref().unwrap().reason.as_str(),
            "target_moved"
        );
        assert_eq!(take_events(), Vec::<Event>::new());
        take_calls();
    }
}
