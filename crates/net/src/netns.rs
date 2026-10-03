//! コンテナ用 network namespace の作成と pin（TASK-139.2.1・#847・NET-1・MS-8）。
//!
//! `crate::network::attach_container` が「veth の peer 側を入れる netns」を用意するための下請けで、
//! PoC-15 `netsetup` の `netns-create` に相当する。後続の runtime が名前（pin パス）でこの netns へ
//! join でき、ネットワーク削除（TASK-139.4）が同じパスから解放できるよう、netns をファイルへ
//! bind マウントして固定（pin）する。`ip netns add` と同じ方式。
//!
//! # 方式
//!
//! 呼び出しスレッドの netns は変えない。専用の使い捨て OS スレッドを 1 本起こし、そのスレッドだけが
//! `unshare(CLONE_NEWNET)` → `/proc/thread-self/ns/net` を open → pin 先ファイルへ bind マウント、を行って
//! 終了する。`CLONE_NEWNET` は `CLONE_NEWUSER` と違いマルチスレッドのプロセスでも合法で、影響は
//! 呼び出したスレッドだけに閉じる。元の netns へ戻る必要が生じないので `setns` は使わない。
//! 結果（ns ファイルの fd）は `mpsc` で返し、待ちは期限つき（REPAIR-5）。
//!
//! # 安全性の設計（P0。パストラバーサル・symlink・マウント伝播）
//!
//! - pin 先は「呼び出し側が渡す絶対パスのディレクトリ」直下の、検証済み `EndpointId`（`/` を含まず
//!   `.` 始まりでない）をファイル名にした通常ファイル。`Path::join` のみで組み立てる
//! - ディレクトリは symlink でない・group / other に書き込み不可・実効 UID の所有、のすべてを満たさない
//!   場合は拒否する（fail-closed）。ディレクトリより上位の経路の検証は呼び出し側の責務
//! - pin 先ファイルは `create_new`（`O_EXCL`）で作る。既存物（他者のファイル・symlink）は上書きも
//!   削除もしない。bind マウントの対象は、作成直後に保持した fd の `/proc/self/fd/<n>` で指定し、
//!   作成から mount までの間のパス差し替えを塞ぐ
//! - fd は `O_CLOEXEC`（std 既定）で、コンテナプロセスへ漏れない
//!
//! # 既知の制約
//!
//! `ip netns add` が行う「置き場ディレクトリを `MS_SHARED` の自己 bind にする」処理はしない。そのため
//! 後から作られた別の mount namespace がこの pin のマウントを引き継いで保持し続けると、unpin 後も
//! netns が生き残りうる。必要性の判断は後続（runtime との結線）に残す（REPAIR-3）。
//!
//! # 権限
//!
//! `unshare(CLONE_NEWNET)` と `mount` / `umount2` に `CAP_SYS_ADMIN` が必要。本 crate は権限を上げない。

#![cfg(target_os = "linux")]

use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::error::{NetError, NetErrorCode};
use crate::netlink_route::classify_errno;
use crate::network::{EndpointId, NetnsFailure, ResourceState};
use crate::sys::{self, SysError};

/// `ns` ファイルの絶対パス。`unshare` したスレッド自身の netns を指す。
const THREAD_NS_PATH: &CStr = c"/proc/thread-self/ns/net";

/// pin 済みのコンテナ用 netns。
///
/// `fd` を保持している間と pin のマウントが残っている間、netns は生き続ける。`fd` は
/// `LinkSet::move_to_netns`（`IFLA_NET_NS_FD`）の移動先指定に使う。解放は
/// `crate::network` のロールバック、または将来のネットワーク削除（TASK-139.4）が `unpin` で行う。
#[derive(Debug)]
pub struct ContainerNetns {
    fd: OwnedFd,
    pin: PathBuf,
}

impl ContainerNetns {
    /// netns を指す ns ファイルの fd（借用）。
    pub fn fd(&self) -> BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.fd.as_fd()
    }

    /// pin 先のパス（runtime が join に使う）。
    pub fn pin_path(&self) -> &Path {
        &self.pin
    }
}

fn sys_error(call: &str, e: SysError) -> NetError {
    match e {
        SysError::Os(errno) => NetError::new(
            classify_errno(errno),
            format!("{call} failed: errno {errno}"),
        ),
        SysError::Unsupported => NetError::new(
            NetErrorCode::Unimplemented,
            format!("{call}: unsupported architecture"),
        ),
        SysError::BadSenderAddress | SysError::BadLocalAddress => {
            NetError::new(NetErrorCode::Internal, format!("{call}: unexpected error"))
        }
    }
}

fn io_error(call: &str, e: &io::Error) -> NetError {
    match e.raw_os_error() {
        Some(errno) => NetError::new(
            classify_errno(errno),
            format!("{call} failed: errno {errno}"),
        ),
        None => NetError::new(NetErrorCode::Internal, format!("{call} failed")),
    }
}

/// netns 置き場ディレクトリの属性検査（OS 呼び出しを含まない純粋関数。単体テスト用に分離）。
///
/// - `is_dir`: `symlink_metadata` の結果がディレクトリ（symlink はディレクトリ扱いにならない）
/// - `mode`: `st_mode`。group / other 書き込み可なら拒否
/// - `owner` / `euid`: 所有者が実効 UID でなければ拒否
fn check_base_dir_attrs(is_dir: bool, mode: u32, owner: u32, euid: u32) -> Result<(), NetError> {
    if !is_dir {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "netns directory must be a real directory (not a symlink)",
        ));
    }
    if mode & 0o022 != 0 {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "netns directory must not be group or other writable",
        ));
    }
    if owner != euid {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "netns directory must be owned by the effective user",
        ));
    }
    Ok(())
}

fn check_base_dir(base: &Path) -> Result<(), NetError> {
    if !base.is_absolute() {
        return Err(NetError::new(
            NetErrorCode::InvalidArgument,
            "netns directory must be an absolute path",
        ));
    }
    let meta = fs::symlink_metadata(base).map_err(|e| io_error("stat netns directory", &e))?;
    check_base_dir_attrs(
        meta.file_type().is_dir(),
        meta.mode(),
        meta.uid(),
        sys::effective_uid(),
    )
}

/// 使い捨てスレッドの本体。`unshare` → ns を open → 保持中の fd 経由で pin 先へ bind マウント。
/// bind マウントが最後の副作用なので、`Err` のときは pin のマウントは作られていない。
fn unshare_and_pin(target: &CStr) -> Result<OwnedFd, NetError> {
    // 影響は当スレッドの netns だけ。このスレッドは戻り値を返したら終了する。
    sys::unshare_net().map_err(|e| sys_error("unshare", e))?;
    let ns = File::open("/proc/thread-self/ns/net").map_err(|e| io_error("open thread ns", &e))?;
    sys::bind_mount(THREAD_NS_PATH, target).map_err(|e| sys_error("mount", e))?;
    Ok(OwnedFd::from(ns))
}

/// 作った pin ファイルを消す。失敗は `Present`（残っていると分かる）で報告する。
fn remove_pin_file(pin: &Path) -> Option<ResourceState> {
    match fs::remove_file(pin) {
        Ok(()) => None,
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(_) => Some(ResourceState::Present),
    }
}

/// `base` 直下に `id` 名の pin を作り、新しい netns をそこへ固定する。
///
/// 成功時は `ContainerNetns`（fd と pin パス）を返す。失敗時は自分が作ったファイルだけを片付け、
/// 時間切れ等で mount の有無が不明なら削除せず `leftover = Some(Unknown)` で報告する。`timeout` は
/// 使い捨てスレッドの完了待ちの期限（REPAIR-5）。時間切れ後もスレッドは裏で完走しうる。
pub(crate) fn create_pinned(
    base: &Path,
    id: &EndpointId,
    timeout: Duration,
) -> Result<ContainerNetns, NetnsFailure> {
    let fail = |error: NetError, leftover: Option<ResourceState>| NetnsFailure { error, leftover };
    check_base_dir(base).map_err(|e| fail(e, None))?;
    let pin = base.join(id.as_str());
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&pin)
        .map_err(|e| fail(io_error("create netns pin file", &e), None))?;
    let target = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(|_| {
        fail(
            NetError::new(NetErrorCode::Internal, "invalid pin target"),
            remove_pin_file(&pin),
        )
    })?;

    let (tx, rx) = mpsc::channel();
    let spawned = thread::Builder::new()
        .name("fandhe-netns".to_owned())
        .spawn(move || {
            // `file` を握ったまま mount することで、`/proc/self/fd/<n>` が差し替え不能な対象を指す。
            let _hold = file;
            let _ = tx.send(unshare_and_pin(&target));
        });
    if spawned.is_err() {
        return Err(fail(
            NetError::new(
                NetErrorCode::ResourceExhausted,
                "failed to spawn netns thread",
            ),
            remove_pin_file(&pin),
        ));
    }

    match rx.recv_timeout(timeout) {
        Ok(Ok(fd)) => Ok(ContainerNetns { fd, pin }),
        Ok(Err(error)) => Err(fail(error, remove_pin_file(&pin))),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(fail(
            NetError::new(NetErrorCode::Timeout, "timed out creating netns"),
            Some(ResourceState::Unknown),
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(fail(
            NetError::new(NetErrorCode::Internal, "netns thread ended unexpectedly"),
            Some(ResourceState::Unknown),
        )),
    }
}

/// pin を外す（`umount2(MNT_DETACH)` → ファイル削除）。fd を drop し参照が尽きれば、カーネルが
/// netns と中に残った peer veth を破棄する。マウントされていない（`EINVAL`）場合はアンマウントを
/// 省略してファイルだけ消す。ロールバックと、将来のネットワーク削除（TASK-139.4）が共用する。
pub(crate) fn unpin(ns: ContainerNetns) -> Result<(), NetError> {
    let ContainerNetns { fd, pin } = ns;
    let c_path = CString::new(pin.as_os_str().as_encoded_bytes())
        .map_err(|_| NetError::new(NetErrorCode::InvalidArgument, "netns path contains NUL"))?;
    match sys::unmount_detach(&c_path) {
        Ok(()) => {}
        Err(SysError::Os(e)) if e == sys::EINVAL => {}
        Err(e) => return Err(sys_error("umount", e)),
    }
    drop(fd);
    fs::remove_file(&pin).map_err(|e| io_error("remove netns pin file", &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NET-1・TASK-139.2.1: 置き場ディレクトリ検査の具体的な合否。
    #[test]
    fn net1_base_dir_attr_checks() {
        assert!(check_base_dir_attrs(true, 0o040_755, 1000, 1000).is_ok());
        assert!(check_base_dir_attrs(true, 0o040_700, 0, 0).is_ok());
        for (is_dir, mode, owner, what) in [
            (false, 0o040_755, 1000, "not a real directory"),
            (true, 0o040_775, 1000, "group writable"),
            (true, 0o040_757, 1000, "other writable"),
            (true, 0o040_755, 1001, "other owner"),
        ] {
            let e = check_base_dir_attrs(is_dir, mode, owner, 1000).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::FailedPrecondition, "{what}");
        }
    }

    /// NET-1: 相対パスは受け付けない。
    #[test]
    fn net1_relative_base_dir_is_rejected() {
        let e = check_base_dir(Path::new("relative/dir")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fandhe-netns-test-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        fs::create_dir(&dir).unwrap();
        dir
    }

    /// NET-1: symlink の置き場ディレクトリは実体が正当でも拒否する。
    #[test]
    fn net1_symlinked_base_dir_is_rejected() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let real = scratch_dir("real");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let link = real.with_extension("link");
        symlink(&real, &link).unwrap();
        let e = check_base_dir(&link).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert!(check_base_dir(&real).is_ok());
        fs::remove_file(&link).unwrap();
        fs::remove_dir(&real).unwrap();
    }

    /// NET-1: group / other 書き込み可の実ディレクトリは拒否する。
    #[test]
    fn net1_world_writable_base_dir_is_rejected() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("ww");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        let e = check_base_dir(&dir).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        fs::remove_dir(&dir).unwrap();
    }

    /// NET-1: 既存の pin 先（他者のファイルの可能性）は上書きも削除もせず AlreadyExists で拒否する。
    /// 権限不要で検証できる経路（`create_new` の段階で失敗し、mount には進まない）。
    #[test]
    fn net1_existing_pin_file_is_kept() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("exists");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let id = EndpointId::new("web-1").unwrap();
        let pin = dir.join("web-1");
        fs::write(&pin, b"keep").unwrap();
        let f = create_pinned(&dir, &id, Duration::from_secs(1)).unwrap_err();
        assert_eq!(f.error.code(), NetErrorCode::AlreadyExists);
        assert_eq!(f.leftover, None);
        assert_eq!(fs::read(&pin).unwrap(), b"keep");
        fs::remove_file(&pin).unwrap();
        fs::remove_dir(&dir).unwrap();
    }
}
