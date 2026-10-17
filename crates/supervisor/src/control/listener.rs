//! 制御チャネルの listen ソケットの作成・検証・削除（Linux。SUP-1・SEC-1・PLUG-12 と同じ考え方・#2058）。
//!
//! 置き場所は `<state_root>/<id>/supervisor.sock`（[`CONTROL_SOCKET_NAME`]）。`<id>/` は core の `StateStore` が
//! 0700・所有者 = 実効 uid で作るディレクトリで、ソケットはその中の 0600 のファイルにする。
//!
//! # bind の手順（呼び出し元は `start_entry` の入口。`Running` を受け取った直後、`run_supervised` の前）
//!
//! 1. `<id>/` を `O_DIRECTORY | O_NOFOLLOW` で開く（symlink を辿らない）。fstat で、ディレクトリであること・
//!    所有者が実効 uid・`mode & 0o077 == 0` を確かめる。満たさなければ `PermissionDenied`（固定文言）。
//! 2. 検証した fd を `/proc/self/fd/<n>/` 経由で参照して bind・rename する（conmon と同じ方式）。`sun_path` の
//!    108 バイト上限を、255 バイトの ID でも超えない。検証した実体そのものに bind できる（パス要素のすり替えが
//!    効かない）。`/proc` が使えない環境では bind が失敗し、fail-closed で `Unavailable` を返す。
//! 3. 一時名 `supervisor.sock.tmp-<pid>` に bind → 0600 → `rename` で最終名へ置き換える（不可分。unlink と bind の間の
//!    TOCTOU が無い）。前回の supervisor が異常終了して残ったソケットはこの `rename` が置き換える。最終名にソケット
//!    以外が先にあれば `FailedPrecondition` で止める。生きている別の supervisor との衝突は、start の手順（Created の確認と
//!    起動権の予約〔`claim_start`〕）が排除済み。
//!
//! 削除は [`ControlListener`] の `Drop`（最終名の dev/ino が自分の bind した実体と一致するときだけ消す。後から来た
//! supervisor のソケットを消さない）。異常終了（SIGKILL 等）で残ったソケットは、次の start が置き換える。
//!
//! エラーメッセージは固定文言のみで、パス・uid・errno を含めない（入力値の反射禁止）。

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{
    FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};

use crate::privilege::{MAX_STATUS_BYTES, parse_proc_status};

/// 制御チャネルのソケットのファイル名（`<state_root>/<id>/` の直下）。
pub const CONTROL_SOCKET_NAME: &str = "supervisor.sock";

fn err(code: ErrorCode, message: &'static str) -> TraitError {
    TraitError::new(code, message)
}

fn unavailable() -> TraitError {
    err(
        ErrorCode::Unavailable,
        "the supervisor control channel is unavailable",
    )
}

/// 自プロセスの実効 uid を `/proc/self/status` から得る（`geteuid` の FFI を足さない。読み取りは長さ上限つき）。
pub fn effective_uid() -> Result<u32, TraitError> {
    use std::io::Read as _;
    let failed = || {
        err(
            ErrorCode::FailedPrecondition,
            "failed to read the process credentials",
        )
    };
    let mut text = String::new();
    let limit = u64::try_from(MAX_STATUS_BYTES + 1).unwrap_or(u64::MAX);
    File::open("/proc/self/status")
        .and_then(|f| f.take(limit).read_to_string(&mut text))
        .map_err(|_| failed())?;
    parse_proc_status(&text)
        .map(|s| s.uid.effective)
        .map_err(|_| failed())
}

/// `<id>/` の fstat の検証（純関数。所有者の不一致を値の注入で試験できるよう分けてある）。
pub fn check_dir_meta(
    is_dir: bool,
    owner_uid: u32,
    mode: u32,
    expected_uid: u32,
) -> Result<(), TraitError> {
    if !is_dir || owner_uid != expected_uid || mode & 0o077 != 0 {
        return Err(err(
            ErrorCode::PermissionDenied,
            "the container state directory is not private to the current user",
        ));
    }
    Ok(())
}

/// `<state_root>/<id>/` を symlink を辿らずに開き、所有者・権限を検証して fd を返す。
///
/// listen 側（bind）と接続側（client）の両方が使う。返した `File` の fd を `/proc/self/fd/<n>/` 経由で参照すれば、
/// 検証した実体そのものを指せる。
pub fn open_state_dir(
    state_root: &Path,
    id: &ContainerId,
    expected_uid: u32,
) -> Result<File, TraitError> {
    let flags = crate::sys::open_dir_nofollow_flags().map_err(|e| {
        if e.kind() == io::ErrorKind::Unsupported {
            err(
                ErrorCode::Unimplemented,
                "the supervisor control channel is not supported on this architecture",
            )
        } else {
            unavailable()
        }
    })?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(state_root.join(id.as_str()))
        .map_err(|_| unavailable())?;
    let meta = dir.metadata().map_err(|_| unavailable())?;
    check_dir_meta(meta.is_dir(), meta.uid(), meta.mode(), expected_uid)?;
    Ok(dir)
}

/// 検証済みディレクトリの fd 経由のパス（`/proc/self/fd/<n>/<name>`）。
pub fn path_via_fd(dir: &File, name: &str) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}/{name}", dir.as_raw_fd()))
}

/// ソケットの実体の識別（dev, ino）。
fn identity(path: &Path) -> io::Result<(u64, u64)> {
    let meta = std::fs::symlink_metadata(path)?;
    Ok((meta.dev(), meta.ino()))
}

/// bind 済みの listen ソケットと、その後始末（`Drop` で最終名を消す）。
#[must_use = "dropping the listener removes the control socket"]
pub struct ControlListener {
    listener: UnixListener,
    /// 検証済みの `<id>/`（`/proc/self/fd` 経由のパスの源。閉じると後始末ができない）。
    dir: File,
    /// bind した実体の識別。最終名がこれと一致するときだけ消す。
    identity: (u64, u64),
}

impl ControlListener {
    /// 実効 uid を自プロセスから得て bind する。
    pub fn bind(state_root: &Path, id: &ContainerId) -> Result<Self, TraitError> {
        Self::bind_as(state_root, id, effective_uid()?)
    }

    /// 期待する所有者 uid を指定して bind する（検証手順は module doc）。
    pub fn bind_as(
        state_root: &Path,
        id: &ContainerId,
        expected_uid: u32,
    ) -> Result<Self, TraitError> {
        let dir = open_state_dir(state_root, id, expected_uid)?;
        let tmp_name = format!("{CONTROL_SOCKET_NAME}.tmp-{}", std::process::id());
        let tmp = path_via_fd(&dir, &tmp_name);
        let final_path = path_via_fd(&dir, CONTROL_SOCKET_NAME);

        // 前回の残りの一時名はソケットのときだけ消す。それ以外（ディレクトリ等）は触らず止める。
        remove_if_socket(&tmp)?;
        // 最終名にソケット以外が居れば、置き換えずに止める（rename がディレクトリ等を壊さないように先に確かめる）。
        match std::fs::symlink_metadata(&final_path) {
            Ok(m) if !m.file_type().is_socket() => {
                return Err(err(
                    ErrorCode::FailedPrecondition,
                    "the control socket path is occupied by a non-socket",
                ));
            }
            Ok(_) | Err(_) => {}
        }

        let listener = UnixListener::bind(&tmp).map_err(|_| unavailable())?;
        let finish = (|| -> io::Result<(u64, u64)> {
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
            let id = identity(&tmp)?;
            listener.set_nonblocking(true)?;
            std::fs::rename(&tmp, &final_path)?;
            Ok(id)
        })();
        match finish {
            Ok(identity) => Ok(Self {
                listener,
                dir,
                identity,
            }),
            Err(_) => {
                let _ = std::fs::remove_file(&tmp);
                Err(unavailable())
            }
        }
    }

    /// サーバスレッドへ渡す複製（`SOCK_CLOEXEC`。コンテナへ漏れない）。
    pub fn try_clone_listener(&self) -> io::Result<UnixListener> {
        self.listener.try_clone()
    }

    /// 最終名のソケットの絶対パス相当（検証済み fd 経由）。接続側の試験が使う。
    pub fn socket_path(&self) -> PathBuf {
        path_via_fd(&self.dir, CONTROL_SOCKET_NAME)
    }
}

fn remove_if_socket(path: &Path) -> Result<(), TraitError> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path).map_err(|_| unavailable()),
        Ok(_) => Err(err(
            ErrorCode::FailedPrecondition,
            "the control socket path is occupied by a non-socket",
        )),
        Err(_) => Ok(()),
    }
}

impl Drop for ControlListener {
    fn drop(&mut self) {
        let final_path = path_via_fd(&self.dir, CONTROL_SOCKET_NAME);
        // 後から来た supervisor が置き換えたソケットは消さない。
        if identity(&final_path).is_ok_and(|i| i == self.identity) {
            let _ = std::fs::remove_file(&final_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn id(s: &str) -> ContainerId {
        ContainerId::new(s).unwrap()
    }

    /// 0700 の `<root>/<id>/` を作る。
    fn make_root(name: &str) -> (tempdir::Guard, PathBuf) {
        let guard = tempdir::Guard::new(name);
        let dir = guard.path().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        (guard, dir)
    }

    /// 一時ディレクトリ（外部クレートを足さない最小の RAII）。
    mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct Guard(PathBuf);

        impl Guard {
            pub fn new(tag: &str) -> Self {
                let n = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let p =
                    std::env::temp_dir().join(format!("fc-ctl-{tag}-{}-{n}", std::process::id()));
                std::fs::create_dir_all(&p).unwrap();
                Self(p)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn euid() -> u32 {
        effective_uid().unwrap()
    }

    /// SEC-1: 所有者・権限・種別の検証（値の注入）。
    #[test]
    fn sec1_check_dir_meta_rejections() {
        assert!(check_dir_meta(true, 1000, 0o40700, 1000).is_ok());
        for (is_dir, uid, mode) in [
            (false, 1000, 0o700),
            (true, 1001, 0o700),
            (true, 1000, 0o755),
            (true, 1000, 0o710),
            (true, 1000, 0o701),
        ] {
            let e = check_dir_meta(is_dir, uid, mode, 1000).unwrap_err();
            assert_eq!(e.code(), ErrorCode::PermissionDenied);
        }
    }

    #[test]
    fn sec1_bind_creates_private_socket_and_drop_removes_it() {
        let (guard, dir) = make_root("bind1");
        let l = ControlListener::bind_as(guard.path(), &id("bind1"), euid()).unwrap();
        let sock = dir.join(CONTROL_SOCKET_NAME);
        let meta = std::fs::symlink_metadata(&sock).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.mode() & 0o777, 0o600);
        // 一時名は残らない。
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            leftovers,
            vec![std::ffi::OsString::from(CONTROL_SOCKET_NAME)]
        );
        drop(l);
        assert!(std::fs::symlink_metadata(&sock).is_err());
    }

    #[test]
    fn sec1_bind_rejects_symlinked_and_loose_directories() {
        let guard = tempdir::Guard::new("symlink");
        let real = guard.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&real, guard.path().join("link")).unwrap();
        // symlink の <id> は O_NOFOLLOW で拒否（Unavailable）。
        let e = ControlListener::bind_as(guard.path(), &id("link"), euid())
            .err()
            .unwrap();
        assert_eq!(e.code(), ErrorCode::Unavailable);
        assert!(std::fs::read_dir(&real).unwrap().next().is_none());

        // 0755 は拒否。
        let loose = guard.path().join("loose");
        std::fs::create_dir(&loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        let e = ControlListener::bind_as(guard.path(), &id("loose"), euid())
            .err()
            .unwrap();
        assert_eq!(e.code(), ErrorCode::PermissionDenied);

        // 期待する所有者と違えば拒否。
        let (guard2, _) = make_root("owner");
        let e = ControlListener::bind_as(guard2.path(), &id("owner"), euid().wrapping_add(1))
            .err()
            .unwrap();
        assert_eq!(e.code(), ErrorCode::PermissionDenied);
    }

    #[test]
    fn sec1_bind_replaces_stale_socket_but_not_directory() {
        let (guard, dir) = make_root("stale");
        // 前回の supervisor が残したソケット。
        let stale = UnixListener::bind(dir.join(CONTROL_SOCKET_NAME)).unwrap();
        drop(stale);
        let before = identity(&dir.join(CONTROL_SOCKET_NAME)).unwrap();
        let l = ControlListener::bind_as(guard.path(), &id("stale"), euid()).unwrap();
        let after = identity(&dir.join(CONTROL_SOCKET_NAME)).unwrap();
        assert_ne!(before, after);
        drop(l);

        // 最終名がディレクトリなら止める（壊さない）。
        let (guard, dir) = make_root("occupied");
        std::fs::create_dir(dir.join(CONTROL_SOCKET_NAME)).unwrap();
        let e = ControlListener::bind_as(guard.path(), &id("occupied"), euid())
            .err()
            .unwrap();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(dir.join(CONTROL_SOCKET_NAME).is_dir());
    }

    /// 255 バイトの ID でも `sun_path` の上限に当たらない（`/proc/self/fd` 経由）。
    #[test]
    fn sec1_bind_works_with_max_length_id() {
        let name = "a".repeat(255);
        let guard = tempdir::Guard::new("longid");
        let dir = guard.path().join(&name);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let l = ControlListener::bind_as(guard.path(), &id(&name), euid()).unwrap();
        assert!(std::fs::symlink_metadata(dir.join(CONTROL_SOCKET_NAME)).is_ok());
        drop(l);
    }

    /// 置き換えられた後の Drop は、後から来たソケットを消さない。
    #[test]
    fn sec1_drop_keeps_socket_replaced_by_newer_supervisor() {
        let (guard, dir) = make_root("replaced");
        let first = ControlListener::bind_as(guard.path(), &id("replaced"), euid()).unwrap();
        let second = ControlListener::bind_as(guard.path(), &id("replaced"), euid()).unwrap();
        drop(first);
        assert!(std::fs::symlink_metadata(dir.join(CONTROL_SOCKET_NAME)).is_ok());
        drop(second);
        assert!(std::fs::symlink_metadata(dir.join(CONTROL_SOCKET_NAME)).is_err());
    }
}
