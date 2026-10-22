//! systemd の user マネージャへ届くかの検査（CORE-3・CORE-4・#2133）。
//!
//! CLI の `start`（`commands::supervisor_start`）、`doctor`、起動 p95 ベンチ（`benches` の `scope_wrap`）の
//! 3 か所が同じ判定を使うための共通実装で、判定が二重になって食い違うのを防ぐ。supervisor 自身の起動処理からは
//! 呼ばれない（`start_contract` の `USER_SCOPE_WRAPPER_ARGS` で包む呼び出し側が事前検査として使う）。
//! `start_contract` は OS 非依存の純ロジックを置く方針のため、unix 専用の本モジュールは別に置く。
//!
//! 判定は `<XDG_RUNTIME_DIR>/systemd/private`（systemd-run `--user` の直結先）が、symlink を辿らない lstat で
//! 自 euid 所有のソケットであることの確認に限る（[`user_manager_env`]。`start` とベンチはこれだけを使う）。
//! 死んだソケット（ファイルは残るが listener がいない）を見分ける実 connect は [`probe_user_manager_socket`] が
//! 担い、`doctor` だけが呼ぶ（`start` への追加と接続先の `SO_PEERCRED` 照合は未実装で、判断待ち。
//! #2448・`docs/design/user-manager-connect-precheck.md`・オーナー承認待ち）。
//! エラー値は固定文言のみで、値（パス・`XDG_RUNTIME_DIR` の内容）を載せない。

use std::ffi::{OsStr, OsString};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::{Duration, Instant};

/// user マネージャへ届かない理由（固定文言は [`UserManagerError::message`]。値〔パス〕は載せない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UserManagerError {
    /// `XDG_RUNTIME_DIR` が未設定・空・相対パス。
    RuntimeDirUnset,
    /// `<xdg>/systemd/private` が無い・ソケットでない・euid 所有でない・symlink。
    Unreachable,
}

impl UserManagerError {
    /// 利用者へ出す固定の英語文言（`start` のエラー・ベンチの不対応報告・doctor の判定の根拠に共通）。
    pub fn message(self) -> &'static str {
        match self {
            Self::RuntimeDirUnset => {
                "XDG_RUNTIME_DIR is not set to an absolute path; the systemd user manager is not reachable"
            }
            Self::Unreachable => {
                "systemd user manager is not reachable (no private socket under XDG_RUNTIME_DIR)"
            }
        }
    }
}

/// systemd の user マネージャに届くかを検査し、環境へ渡す `XDG_RUNTIME_DIR` の値を返す（CORE-3・CORE-4）。
///
/// 値は絶対パスであること、`<値>/systemd/private` が symlink でなく `euid` 所有のソケットであることを確かめる。
pub fn user_manager_env(xdg: Option<&OsStr>, euid: u32) -> Result<OsString, UserManagerError> {
    let xdg = xdg
        .filter(|v| !v.is_empty())
        .ok_or(UserManagerError::RuntimeDirUnset)?;
    let dir = Path::new(xdg);
    if !dir.is_absolute() {
        return Err(UserManagerError::RuntimeDirUnset);
    }
    let sock = dir.join("systemd").join("private");
    let meta = std::fs::symlink_metadata(&sock).map_err(|_| UserManagerError::Unreachable)?;
    if !meta.file_type().is_socket() || meta.uid() != euid {
        return Err(UserManagerError::Unreachable);
    }
    Ok(xdg.to_os_string())
}

/// connect の再試行間隔（listen backlog 満杯のときだけ待つ。REPAIR-5）。
const CONNECT_BACKLOG_INTERVAL: Duration = Duration::from_millis(5);

/// user マネージャのソケットへ実際に接続できなかった理由（固定文言は [`UserManagerConnectError::message`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UserManagerConnectError {
    /// `ECONNREFUSED`: ソケットのファイルは残っているが listener がいない（死んだソケット）。
    Refused,
    /// listen backlog が満杯のまま期限を過ぎた（生きているが応答しない）。
    TimedOut,
    /// 接続を試みられなかった（パスが `sun_path` に収まらない・NUL を含む・対象外アーキテクチャ）。
    Unsupported,
    /// 上記以外の I/O エラー（lstat と connect の間に消えた場合を含む）。
    Failed,
}

impl UserManagerConnectError {
    /// 利用者へ出す固定の英語文言（パス・errno を載せない）。
    pub fn message(self) -> &'static str {
        match self {
            Self::Refused => {
                "systemd user manager socket exists but nothing is listening on it (stale socket)"
            }
            Self::TimedOut => {
                "systemd user manager socket did not accept a connection before the deadline"
            }
            Self::Unsupported => {
                "a connection to the systemd user manager socket could not be attempted"
            }
            Self::Failed => "connecting to the systemd user manager socket failed",
        }
    }
}

/// `<runtime_dir>/systemd/private` へ実際に接続して閉じる（CORE-3・CORE-4・REPAIR-5・#2158）。
///
/// 呼び出し元は [`user_manager_env`] が成功した後の `doctor` で、その戻り値を `runtime_dir` に渡す。
/// データは送らず、接続に成功したら直ちに閉じる（副作用は相手の accept と EOF の観測だけ）。`SOCK_NONBLOCK` の
/// `connect(2)` を `deadline` まで繰り返し、`ECONNREFUSED` と `ENOENT` は再試行せず即答する（診断が目的）。
/// lstat と connect の間にソケットを差し替えられるのは同じ uid の書き手だけで、権限の境界は増えない。
pub fn probe_user_manager_socket(
    runtime_dir: &OsStr,
    deadline: Instant,
) -> Result<(), UserManagerConnectError> {
    use std::io::ErrorKind;
    let sock = Path::new(runtime_dir).join("systemd").join("private");
    loop {
        match crate::sys::connect_unix_nonblocking(&sock) {
            // 接続を保持せず、すぐ閉じる。
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(e) => match e.kind() {
                ErrorKind::ConnectionRefused => return Err(UserManagerConnectError::Refused),
                ErrorKind::InvalidInput | ErrorKind::Unsupported => {
                    return Err(UserManagerConnectError::Unsupported);
                }
                ErrorKind::WouldBlock => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(UserManagerConnectError::TimedOut);
                    }
                    std::thread::sleep(CONNECT_BACKLOG_INTERVAL.min(remaining));
                }
                _ => return Err(UserManagerConnectError::Failed),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::PathBuf;

    fn euid() -> u32 {
        std::fs::metadata("/proc/self").expect("meta").uid()
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fc-userscope-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&d)
            .expect("mkdir");
        d
    }

    /// CORE-3・CORE-4: euid 所有のソケットなら値を返し、euid 違いは拒否する（値を文言に載せない）。
    #[test]
    fn core3_core4_accepts_own_socket() {
        let d = tmp("ok");
        std::fs::create_dir(d.join("systemd")).expect("mkdir");
        let _l = std::os::unix::net::UnixListener::bind(d.join("systemd/private")).expect("bind");
        assert_eq!(
            user_manager_env(Some(d.as_os_str()), euid()),
            Ok(d.as_os_str().to_os_string())
        );
        let e = user_manager_env(Some(d.as_os_str()), euid().wrapping_add(1)).expect_err("owner");
        assert_eq!(e, UserManagerError::Unreachable);
        assert!(!e.message().contains(d.to_str().expect("utf8")));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// CORE-3・CORE-4: 未設定・空・相対は `RuntimeDirUnset`、ソケット無し・通常ファイル・symlink は `Unreachable`。
    #[test]
    fn core3_core4_rejects_bad_inputs() {
        for v in [None, Some(OsStr::new("")), Some(OsStr::new("rel/dir"))] {
            let e = user_manager_env(v, euid()).expect_err("unset");
            assert_eq!(e, UserManagerError::RuntimeDirUnset);
            assert_eq!(
                e.message(),
                "XDG_RUNTIME_DIR is not set to an absolute path; the systemd user manager is not reachable"
            );
        }
        let d = tmp("bad");
        let e = user_manager_env(Some(d.as_os_str()), euid()).expect_err("no socket");
        assert_eq!(e, UserManagerError::Unreachable);
        assert_eq!(
            e.message(),
            "systemd user manager is not reachable (no private socket under XDG_RUNTIME_DIR)"
        );
        std::fs::create_dir(d.join("systemd")).expect("mkdir");
        std::fs::write(d.join("systemd/private"), b"x").expect("file");
        assert_eq!(
            user_manager_env(Some(d.as_os_str()), euid()),
            Err(UserManagerError::Unreachable)
        );
        std::fs::remove_file(d.join("systemd/private")).expect("rm");
        let _l = std::os::unix::net::UnixListener::bind(d.join("real.sock")).expect("bind");
        std::os::unix::fs::symlink(d.join("real.sock"), d.join("systemd/private")).expect("ln");
        assert_eq!(
            user_manager_env(Some(d.as_os_str()), euid()),
            Err(UserManagerError::Unreachable)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// CORE-3・CORE-4・REPAIR-5: listen 中のソケットには接続でき、listener が消えたソケットは `Refused`。
    #[test]
    fn core3_core4_repair5_probe_live_and_stale() {
        let d = tmp("probe");
        std::fs::create_dir(d.join("systemd")).expect("mkdir");
        let l = std::os::unix::net::UnixListener::bind(d.join("systemd/private")).expect("bind");
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(probe_user_manager_socket(d.as_os_str(), deadline), Ok(()));
        drop(l);
        assert_eq!(
            probe_user_manager_socket(d.as_os_str(), deadline),
            Err(UserManagerConnectError::Refused)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// REPAIR-5: ソケットが無ければ `Failed`、108 バイト以上のパスは `Unsupported`。
    #[test]
    fn repair5_probe_missing_and_too_long() {
        let d = tmp("probe2");
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(
            probe_user_manager_socket(d.as_os_str(), deadline),
            Err(UserManagerConnectError::Failed)
        );
        let long = OsString::from("/".to_owned() + &"a".repeat(120));
        assert_eq!(
            probe_user_manager_socket(&long, deadline),
            Err(UserManagerConnectError::Unsupported)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// CORE-3: 固定文言が決まっており、パスを載せない。
    #[test]
    fn core3_connect_error_messages_are_fixed() {
        assert_eq!(
            UserManagerConnectError::Refused.message(),
            "systemd user manager socket exists but nothing is listening on it (stale socket)"
        );
        assert_eq!(
            UserManagerConnectError::TimedOut.message(),
            "systemd user manager socket did not accept a connection before the deadline"
        );
        assert_eq!(
            UserManagerConnectError::Unsupported.message(),
            "a connection to the systemd user manager socket could not be attempted"
        );
        assert_eq!(
            UserManagerConnectError::Failed.message(),
            "connecting to the systemd user manager socket failed"
        );
    }
}
