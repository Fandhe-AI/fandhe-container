//! 起動 p95 ベンチが supervisor を包む `systemd-run` のコマンドと user マネージャ検査（TASK-190 追補・#2089・CORE-10・REPAIR-8）。
//!
//! `measure` の `RealHost::spawn` から呼ばれる。CLI の `start`（`crates/cli` の `scoped_command`）と
//! 同じ包み込み（argv は `USER_SCOPE_WRAPPER_ARGS`、環境は固定 `PATH` と検証済み `XDG_RUNTIME_DIR` のみ、cwd は `/`）を
//! 作り、scope 取得（D-Bus の往復）の費用を本番と同じ経路で測る（#2081・#2122）。ベンチだけの差異は `--unit=<名前>` で、
//! 後始末が scope の cgroup を名前で探すために付ける（名前は実行ごとの nonce を含み、残った scope と衝突しない）。
//!
//! user マネージャの判定は supervisor の `user_scope::user_manager_env` を使う（CLI の `start`・`doctor` と共通。#2133）。
//! ここで写すのは固定文言をベンチの不対応報告へ変えるだけで、判定そのものの検証は supervisor 側のテストにある。

use super::StartupLatencyError;
use fandhe_container_supervisor::launcher::FIXED_PATH_ENV;
use fandhe_container_supervisor::start_contract::USER_SCOPE_WRAPPER_ARGS;
use fandhe_container_supervisor::user_scope::user_manager_env as shared_user_manager_env;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::Command;

fn unsupported(message: &'static str) -> StartupLatencyError {
    StartupLatencyError::new("unsupported-environment", message)
}

/// systemd の user マネージャへ直結できる `XDG_RUNTIME_DIR` を検証して返す（試行の前に fail-closed で止める）。
///
/// 判定は supervisor の共通実装（空・未設定・相対パス、`<xdg>/systemd/private` が自 euid 所有のソケットでない場合は拒否）。
/// エラー文は固定の英語で、値（パス）を載せない。
pub fn user_manager_env(xdg: Option<&OsStr>, euid: u32) -> Result<OsString, StartupLatencyError> {
    shared_user_manager_env(xdg, euid).map_err(|e| unsupported(e.message()))
}

/// `systemd-run` の包み込み（`USER_SCOPE_WRAPPER_ARGS` ＋ `--unit=<unit>` ＋ `--`）と環境（固定 `PATH` と
/// `XDG_RUNTIME_DIR` のみ）・cwd（`/`）を組んだ `Command` を返す。包まれるコマンドは呼び出し側が `--` の後ろへ足す。
/// 失敗するのは `USER_SCOPE_WRAPPER_ARGS` の末尾が `--` でなくなった（契約が変わった）場合だけ。
fn wrapper_command(systemd_run: &Path, unit: &str, xdg: &OsStr) -> Option<Command> {
    let (sep, head) = USER_SCOPE_WRAPPER_ARGS.split_last()?;
    if *sep != "--" {
        return None;
    }
    let path_value = FIXED_PATH_ENV.strip_prefix("PATH=")?;
    let mut cmd = Command::new(systemd_run);
    cmd.args(head)
        .arg(format!("--unit={unit}"))
        .arg(sep)
        .env_clear()
        .env("PATH", path_value)
        .env("XDG_RUNTIME_DIR", xdg)
        .current_dir("/");
    Some(cmd)
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
    let mut cmd = wrapper_command(systemd_run, unit, xdg)?;
    cmd.arg(supervisor)
        .arg("start")
        .arg("--root")
        .arg(root)
        .arg(id);
    Some(cmd)
}

/// 後始末の `delete`（OCI-6・#2157）を委譲スコープの中で呼ぶ `Command` を組む。
/// 本番の `start` と同じ包み込み（`wrapper_command`）で `<cli> --root <root> delete <id>` を実行する。包むことで CLI 自身が
/// 委譲 cgroup の中で動き、core の `delete` が記録済みスコープを fd 起点で開く経路（`remove_recorded`）へ回れる。
/// 計測区間の外で呼ぶ後始末専用で、起動経路の計測には使わない。
pub fn scoped_cli_delete_command(
    systemd_run: &Path,
    unit: &str,
    cli: &Path,
    root: &Path,
    id: &str,
    xdg: &OsStr,
) -> Option<Command> {
    let mut cmd = wrapper_command(systemd_run, unit, xdg)?;
    cmd.arg(cli).arg("--root").arg(root).arg("delete").arg(id);
    Some(cmd)
}

/// scope 取得だけを測る診断（`--scope-only`。`scope_only` モジュール）用に、`scoped_command` と同じ包み込みで
/// 自明なコマンド（`<program> --startup-latency-noop`。すぐ終了コード 0 で終わる）を起動する `Command` を組む。
/// supervisor・create・ランチャー・Landlock を含まないので、scope 取得（D-Bus の往復）だけの費用が残る。
pub fn scoped_noop_command(
    systemd_run: &Path,
    unit: &str,
    program: &Path,
    xdg: &OsStr,
) -> Option<Command> {
    let mut cmd = wrapper_command(systemd_run, unit, xdg)?;
    cmd.arg(program).arg("--startup-latency-noop");
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

    /// CORE-3・CORE-4: 共通判定の結果をベンチの不対応報告（コード固定・文言は共通・パスを載せない）へ写す。
    /// 判定の各分岐の検証は supervisor の `user_scope` のテストにある。
    #[test]
    fn core3_core4_user_manager_env_maps_shared_errors() {
        let d = tmp("ok");
        std::fs::create_dir(d.join("systemd")).unwrap();
        let _l = UnixListener::bind(d.join("systemd/private")).unwrap();
        assert_eq!(
            user_manager_env(Some(d.as_os_str()), euid()).unwrap(),
            d.as_os_str()
        );
        let e = user_manager_env(Some(d.as_os_str()), euid().wrapping_add(1)).unwrap_err();
        assert_eq!(e.code, "unsupported-environment");
        assert_eq!(
            e.message,
            "systemd user manager is not reachable (no private socket under XDG_RUNTIME_DIR)"
        );
        assert!(!e.message.contains(d.to_str().unwrap()));
        let e = user_manager_env(None, euid()).unwrap_err();
        assert_eq!(e.code, "unsupported-environment");
        assert_eq!(
            e.message,
            "XDG_RUNTIME_DIR is not set to an absolute path; the systemd user manager is not reachable"
        );
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

    /// OCI-6: 後始末の delete は本番と同じ包み込みで `<cli> --root <root> delete <id>` を実行する。
    #[test]
    fn oci6_scoped_cli_delete_command_wraps_the_cli_delete() {
        let cmd = scoped_cli_delete_command(
            Path::new("/usr/bin/systemd-run"),
            "fcsl-del-x",
            Path::new("/opt/cli"),
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
                "--unit=fcsl-del-x",
                "--",
                "/opt/cli",
                "--root",
                "/r",
                "delete",
                "cid"
            ]
        );
        assert_eq!(cmd.get_current_dir(), Some(Path::new("/")));
    }

    /// CORE-10: 診断の包み込みは本番と同じ前半（argv・環境・cwd）で、本体だけが noop になる。
    #[test]
    fn core10_scoped_noop_command_shares_the_production_wrapper() {
        let cmd = scoped_noop_command(
            Path::new("/usr/bin/systemd-run"),
            "fcsl-scope-x",
            Path::new("/opt/bench"),
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
                "/opt/bench",
                "--startup-latency-noop"
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
