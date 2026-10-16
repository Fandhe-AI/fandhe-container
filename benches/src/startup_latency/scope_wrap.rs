//! 起動 p95 ベンチが supervisor を包む `systemd-run` のコマンドと user マネージャ検査（TASK-190 追補・#2089・CORE-10・REPAIR-8）。
//!
//! `measure` の `RealHost::spawn` から呼ばれる。CLI の `start`（`crates/cli` の `scoped_command` / `user_manager_env`）と
//! 同じ包み込み（argv は `USER_SCOPE_WRAPPER_ARGS`、環境は固定 `PATH` と検証済み `XDG_RUNTIME_DIR` のみ、cwd は `/`）を
//! 作り、scope 取得（D-Bus の往復）の費用を本番と同じ経路で測る（#2081・#2122）。ベンチだけの差異は `--unit=<名前>` で、
//! 後始末が scope の cgroup を名前で探すために付ける（名前は実行ごとの nonce を含み、残った scope と衝突しない）。
//!
//! 判定は CLI の `user_manager_env` と同じ。CLI の関数は private でベンチは CLI に依存しないため再実装している
//! （共通化の候補は `start_contract`。フォローアップ）。

use super::StartupLatencyError;
use fandhe_container_supervisor::launcher::FIXED_PATH_ENV;
use fandhe_container_supervisor::start_contract::USER_SCOPE_WRAPPER_ARGS;
use std::ffi::{OsStr, OsString};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::Path;
use std::process::Command;

fn unsupported(message: &'static str) -> StartupLatencyError {
    StartupLatencyError::new("unsupported-environment", message)
}

/// systemd の user マネージャへ直結できる `XDG_RUNTIME_DIR` を検証して返す（試行の前に fail-closed で止める）。
///
/// 空・未設定・相対パス、`<xdg>/systemd/private` が（symlink を辿らずに）自 euid 所有のソケットでない場合は拒否する。
/// エラー文は固定の英語で、値（パス）を載せない。
pub fn user_manager_env(xdg: Option<&OsStr>, euid: u32) -> Result<OsString, StartupLatencyError> {
    let unset = || {
        unsupported(
            "XDG_RUNTIME_DIR is not set to an absolute path; the systemd user manager is not reachable",
        )
    };
    let xdg = xdg.filter(|v| !v.is_empty()).ok_or_else(unset)?;
    let dir = Path::new(xdg);
    if !dir.is_absolute() {
        return Err(unset());
    }
    let unreachable = || {
        unsupported(
            "systemd user manager is not reachable (no private socket under XDG_RUNTIME_DIR)",
        )
    };
    let sock = dir.join("systemd").join("private");
    let meta = std::fs::symlink_metadata(&sock).map_err(|_| unreachable())?;
    if !meta.file_type().is_socket() || meta.uid() != euid {
        return Err(unreachable());
    }
    Ok(xdg.to_os_string())
}

/// 本番の `start` と同じ包み込みで、試行 1 回分の `systemd-run` コマンドを組む（シェルも文字列連結も使わない）。
///
/// 組み立てに失敗するのは `USER_SCOPE_WRAPPER_ARGS` の末尾が `--` でなくなった（契約が変わった）場合だけで、
/// 呼び出し側は spawn 失敗として数える（panic しない）。
pub fn scoped_command(
    systemd_run: &Path,
    unit: &str,
    supervisor: &Path,
    root: &Path,
    id: &str,
    xdg: &OsStr,
) -> Option<Command> {
    let (sep, head) = USER_SCOPE_WRAPPER_ARGS.split_last()?;
    if *sep != "--" {
        return None;
    }
    let path_value = FIXED_PATH_ENV.strip_prefix("PATH=")?;
    let mut cmd = Command::new(systemd_run);
    cmd.args(head)
        .arg(format!("--unit={unit}"))
        .arg(sep)
        .arg(supervisor)
        .arg("start")
        .arg("--root")
        .arg(root)
        .arg(id)
        .env_clear()
        .env("PATH", path_value)
        .env("XDG_RUNTIME_DIR", xdg)
        .current_dir("/");
    Some(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    fn euid() -> u32 {
        super::super::probe_env::effective_uid().expect("uid")
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fc-scopewrap-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::DirBuilder::new().mode(0o700).create(&d).unwrap();
        d
    }

    #[test]
    fn core3_core4_user_manager_env_accepts_own_socket() {
        let d = tmp("ok");
        std::fs::create_dir(d.join("systemd")).unwrap();
        let _l = UnixListener::bind(d.join("systemd/private")).unwrap();
        let got = user_manager_env(Some(d.as_os_str()), euid()).unwrap();
        assert_eq!(got, d.as_os_str());
        // euid 不一致は拒否。
        let e = user_manager_env(Some(d.as_os_str()), euid().wrapping_add(1)).unwrap_err();
        assert_eq!(e.code, "unsupported-environment");
        assert!(!e.message.contains(d.to_str().unwrap()));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn core3_core4_user_manager_env_rejects_bad_inputs() {
        for v in [None, Some(OsStr::new("")), Some(OsStr::new("relative/dir"))] {
            let e = user_manager_env(v, euid()).unwrap_err();
            assert_eq!(e.code, "unsupported-environment");
            assert_eq!(
                e.message,
                "XDG_RUNTIME_DIR is not set to an absolute path; the systemd user manager is not reachable"
            );
        }
        // ソケットが無い・通常ファイル・実ソケットへの symlink。
        let d = tmp("bad");
        let e = user_manager_env(Some(d.as_os_str()), euid()).unwrap_err();
        assert_eq!(
            e.message,
            "systemd user manager is not reachable (no private socket under XDG_RUNTIME_DIR)"
        );
        std::fs::create_dir(d.join("systemd")).unwrap();
        std::fs::write(d.join("systemd/private"), b"x").unwrap();
        assert!(user_manager_env(Some(d.as_os_str()), euid()).is_err());
        std::fs::remove_file(d.join("systemd/private")).unwrap();
        let _l = UnixListener::bind(d.join("real.sock")).unwrap();
        std::os::unix::fs::symlink(d.join("real.sock"), d.join("systemd/private")).unwrap();
        assert!(user_manager_env(Some(d.as_os_str()), euid()).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn core3_core4_scoped_command_matches_production_wrapper() {
        assert_eq!(USER_SCOPE_WRAPPER_ARGS.last(), Some(&"--"));
        let cmd = scoped_command(
            Path::new("/usr/bin/systemd-run"),
            "fcsl-scope-x",
            Path::new("/opt/sup"),
            Path::new("/r"),
            "cid",
            OsStr::new("/run/user/1000"),
        )
        .unwrap();
        assert_eq!(cmd.get_program(), "/usr/bin/systemd-run");
        let args: Vec<_> = cmd.get_args().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "--user",
                "--scope",
                "--quiet",
                "-p",
                "Delegate=yes",
                "--unit=fcsl-scope-x",
                "--",
                "/opt/sup",
                "start",
                "--root",
                "/r",
                "cid"
            ]
        );
        let mut envs: Vec<_> = cmd
            .get_envs()
            .map(|(k, v)| (k.to_str().unwrap(), v.unwrap().to_str().unwrap()))
            .collect();
        envs.sort();
        assert_eq!(
            envs,
            [
                ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
                ("XDG_RUNTIME_DIR", "/run/user/1000")
            ]
        );
        assert_eq!(cmd.get_current_dir(), Some(Path::new("/")));
    }
}
