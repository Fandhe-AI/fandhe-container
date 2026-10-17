//! `doctor` の CORE-3 の前提の診断: `systemd-run` の有無と信頼、systemd の user マネージャへの到達（CORE-3・CORE-4・#2133）。
//!
//! `start` は supervisor を `systemd-run --user --scope` で包むため、`systemd-run` が信頼できる場所に無い、または
//! user マネージャに届かないと失敗する。本モジュールはその事前条件を、`start` と同じ判定
//! （`crate::user_scope` の解決器と `fandhe_container_supervisor::user_scope::user_manager_env`）で読み取り専用に調べ、
//! 具体的な対処つきの診断にする。外部コマンドは実行せず、設定も変えない。
//!
//! # 構成
//! - 事実の収集（[`collect`]。Linux のみ）と評価（[`evaluate`]。純粋関数で全 OS で単体テストできる）を分ける。
//! - 出力は NET-10 の診断（`super`）と同じ JSON Lines で、各行に `check` と `state` のトークンを付ける。
//!   パス・`XDG_RUNTIME_DIR` の値・ユーザー名などホスト固有の値は出力に載せない。
//! - 終了ステータス: Warning が 1 件でもあれば `Warning`（3）、そうでなく判定不能なら `Inconclusive`（4）、それ以外は `Ok`（0）。
//!   `systemd-run` が無い・信頼できないことは `start` の前提の不成立なので Warning に入れる。rootful で検査を省いた通知と
//!   対象外 OS は 0 に寄与する。
//!
//! # 未実装（REPAIR-3）
//! - user マネージャのソケットへ実際に connect して死んだソケットを見分ける検査（現状は lstat での存在・種別・所有者のみ）。
//! - CLI 自身の cgroup の委譲の検査（`delete` が検出に失敗する環境の診断。`commands::stop_delete` の doc 参照）。

use super::{DoctorExitStatus, DoctorSeverity};
use crate::json::json_escape;

/// 実行ユーザーの状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeState {
    /// 非 root（real / effective / saved / fs の uid がすべて 0 でない）。
    Rootless,
    /// uid のどれかが 0（rootful は `start` が未対応。SEC-5）。
    Rootful,
    /// `/proc/self/status` を解釈できない。
    Unreadable,
    /// Linux 以外では対象外。
    Unsupported,
}

/// `systemd-run` を採用できない理由のトークン。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UntrustedReason {
    /// 実体の所有者が root でも実効 UID でもない。
    FileOwner,
    /// 実体が group / other から書き込み可。
    FileMode,
    /// 通常ファイルでない（祖先がディレクトリでない場合を含む）。
    NotRegularFile,
    /// 実行ビットが無い。
    NoExecuteBit,
    /// 祖先ディレクトリの所有者が不正。
    AncestorOwner,
    /// 祖先ディレクトリが group / other から書き込み可（NixOS の `/nix/store` が該当しうる）。
    AncestorMode,
    /// メタデータを読めない。
    Unreadable,
}

impl UntrustedReason {
    fn token(self) -> &'static str {
        match self {
            Self::FileOwner => "file_owner",
            Self::FileMode => "file_mode",
            Self::NotRegularFile => "not_regular_file",
            Self::NoExecuteBit => "no_execute_bit",
            Self::AncestorOwner => "ancestor_owner",
            Self::AncestorMode => "ancestor_mode",
            Self::Unreadable => "unreadable",
        }
    }

    fn remediation(self) -> &'static str {
        match self {
            Self::FileOwner => {
                "The systemd-run executable must be owned by root or the current user; reinstall systemd from your distribution"
            }
            Self::FileMode => {
                "The systemd-run executable must not be writable by group or others; reinstall systemd from your distribution"
            }
            Self::NotRegularFile => {
                "systemd-run must resolve to a regular file; reinstall systemd from your distribution"
            }
            Self::NoExecuteBit => {
                "The systemd-run file has no execute permission; reinstall systemd from your distribution"
            }
            Self::AncestorOwner => {
                "A parent directory of systemd-run is owned by a user other than root or the current user; fix the ownership of the install location"
            }
            Self::AncestorMode => {
                "A parent directory of systemd-run is writable by group or others (a Nix store such as /nix/store with mode 1775 is a known case that is rejected; sticky bits are not treated as an exception); install systemd-run under a directory that only root or the current user can write"
            }
            Self::Unreadable => {
                "The systemd-run file or one of its parent directories could not be inspected; check its permissions"
            }
        }
    }
}

/// `systemd-run` の状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdRunState {
    /// 固定候補で見つかり、信頼の基準を満たす。
    Trusted,
    /// 固定候補に無い。`on_path` は `PATH` 上に同名のファイルがあるか（参考情報。実行も採用もしない）。
    NotFound {
        /// `PATH` 上に `systemd-run` という名のファイルがあるか。
        on_path: bool,
    },
    /// 見つかったが信頼の基準を満たさない。
    Untrusted(UntrustedReason),
    /// 検査しなかった（rootful・判定不能・対象外 OS）。
    NotChecked,
}

/// user マネージャへの到達の状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserManagerState {
    /// `<XDG_RUNTIME_DIR>/systemd/private` が自分のソケットとして存在する。
    Reachable,
    /// `XDG_RUNTIME_DIR` が未設定・空・相対パス。
    RuntimeDirUnset,
    /// `systemd/private` に届かない。
    Unreachable,
    /// 検査しなかった（rootful・判定不能・対象外 OS）。
    NotChecked,
}

/// 収集した事実。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserScopeFindings {
    /// 実行ユーザー。
    pub privilege: PrivilegeState,
    /// `systemd-run` の状態。
    pub systemd_run: SystemdRunState,
    /// user マネージャの状態。
    pub user_manager: UserManagerState,
}

/// 結論。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserScopeOutcome {
    /// 問題なし（rootful で検査を省いた場合を含む）。
    Ok,
    /// 前提が満たされない。
    Warning,
    /// 判定できなかった。
    Inconclusive,
    /// Linux 以外では対象外。
    NotApplicable,
}

/// 1 件の診断（`code` は英大文字スネーク、`message` と `remediation` は英語の固定文言）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserScopeDiagnostic {
    /// 重大度。
    pub severity: DoctorSeverity,
    /// 機械可読なコード。
    pub code: &'static str,
    /// 説明（ホスト固有の値を載せない）。
    pub message: &'static str,
    /// 対処の案内。
    pub remediation: Vec<&'static str>,
    /// どの検査か（`privilege` / `systemd_run` / `user_manager`）。
    pub check: &'static str,
    /// 状態のトークン。
    pub state: &'static str,
}

/// 評価結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserScopeReport {
    /// 結論。
    pub outcome: UserScopeOutcome,
    /// 診断。
    pub diagnostics: Vec<UserScopeDiagnostic>,
}

fn diag(
    severity: DoctorSeverity,
    code: &'static str,
    message: &'static str,
    remediation: Vec<&'static str>,
    check: &'static str,
    state: &'static str,
) -> UserScopeDiagnostic {
    UserScopeDiagnostic {
        severity,
        code,
        message,
        remediation,
        check,
        state,
    }
}

/// 事実から診断を作る純粋関数（CORE-3・CORE-4）。
///
/// `Rootless` 以外では `systemd-run` と user マネージャの検査は行わない（rootful は `start` が先に拒否するため、
/// この節の検査は意味を持たない。判定不能なら他の検査の結果も信用しない）。
pub fn evaluate(f: &UserScopeFindings) -> UserScopeReport {
    use DoctorSeverity::{Notice, Warning};
    match f.privilege {
        PrivilegeState::Unsupported => {
            return UserScopeReport {
                outcome: UserScopeOutcome::NotApplicable,
                diagnostics: Vec::new(),
            };
        }
        PrivilegeState::Rootful => {
            return UserScopeReport {
                outcome: UserScopeOutcome::Ok,
                diagnostics: vec![diag(
                    Notice,
                    "USER_SCOPE_CHECK_SKIPPED_AS_ROOT",
                    "the systemd-run and user manager checks were skipped because this process runs as root; rootful start is not supported",
                    vec![
                        "Re-run fandhe-container doctor as the unprivileged user that starts containers",
                    ],
                    "privilege",
                    "rootful",
                )],
            };
        }
        PrivilegeState::Unreadable => {
            return UserScopeReport {
                outcome: UserScopeOutcome::Inconclusive,
                diagnostics: vec![diag(
                    Notice,
                    "USER_SCOPE_INCONCLUSIVE",
                    "the process status could not be read, so the systemd-run and user manager checks were skipped",
                    vec![
                        "Check that /proc is mounted and readable, then re-run fandhe-container doctor",
                    ],
                    "privilege",
                    "unreadable",
                )],
            };
        }
        PrivilegeState::Rootless => {}
    }
    let mut diagnostics = Vec::new();
    match f.systemd_run {
        SystemdRunState::NotFound { on_path } => {
            diagnostics.push(diag(
                Warning,
                "SYSTEMD_RUN_NOT_FOUND",
                "systemd-run was not found in the fixed locations; starting a container requires it",
                vec![
                    "Install systemd so that systemd-run is placed at /usr/bin/systemd-run or another fixed location (/usr/sbin, /sbin, /bin, /run/current-system/sw/bin)",
                ],
                "systemd_run",
                "not_found",
            ));
            if on_path {
                diagnostics.push(diag(
                    Notice,
                    "SYSTEMD_RUN_OUTSIDE_FIXED_LOCATIONS",
                    "a systemd-run file exists on PATH but outside the fixed locations; PATH is never searched for it and it is not used",
                    vec![
                        "Move or link it into a fixed location owned by root or the current user and not writable by group or others",
                    ],
                    "systemd_run",
                    "outside_fixed_locations",
                ));
            }
        }
        SystemdRunState::Untrusted(reason) => diagnostics.push(diag(
            Warning,
            "SYSTEMD_RUN_UNTRUSTED",
            "systemd-run was found but is not a trusted executable (it must be a regular file owned by root or the current user, not writable by group or others, with the same condition on every parent directory)",
            vec![reason.remediation()],
            "systemd_run",
            reason.token(),
        )),
        SystemdRunState::Trusted | SystemdRunState::NotChecked => {}
    }
    match f.user_manager {
        UserManagerState::RuntimeDirUnset => diagnostics.push(diag(
            Warning,
            "XDG_RUNTIME_DIR_UNSET",
            "XDG_RUNTIME_DIR is not set to an absolute path; the systemd user manager is not reachable",
            vec![
                "Log in through a systemd login session (pam_systemd sets XDG_RUNTIME_DIR), or export XDG_RUNTIME_DIR=/run/user/$(id -u) in the shell that runs fandhe-container",
            ],
            "user_manager",
            "runtime_dir_unset",
        )),
        UserManagerState::Unreachable => diagnostics.push(diag(
            Warning,
            "USER_MANAGER_UNREACHABLE",
            "the systemd user manager private socket was not found under XDG_RUNTIME_DIR",
            vec![
                "Check the user manager with \"systemctl --user status\"",
                "To keep the user manager running without a login session (for example over SSH), enable lingering with \"loginctl enable-linger\"",
            ],
            "user_manager",
            "unreachable",
        )),
        UserManagerState::Reachable | UserManagerState::NotChecked => {}
    }
    let outcome = if diagnostics.iter().any(|d| d.severity == Warning) {
        UserScopeOutcome::Warning
    } else {
        UserScopeOutcome::Ok
    };
    UserScopeReport {
        outcome,
        diagnostics,
    }
}

impl UserScopeReport {
    /// 結論に対応する終了ステータス。
    pub fn exit_status(&self) -> DoctorExitStatus {
        match self.outcome {
            UserScopeOutcome::Ok | UserScopeOutcome::NotApplicable => DoctorExitStatus::Ok,
            UserScopeOutcome::Warning => DoctorExitStatus::Warning,
            UserScopeOutcome::Inconclusive => DoctorExitStatus::Inconclusive,
        }
    }

    /// 診断を 1 件 1 行の JSON Lines で書き出す（NET-10 の行と同じ形に `check` と `state` を付ける）。
    pub fn write_json_lines(&self, w: &mut impl std::io::Write) -> std::io::Result<()> {
        for d in &self.diagnostics {
            let rem: Vec<String> = d
                .remediation
                .iter()
                .map(|r| format!("\"{}\"", json_escape(r)))
                .collect();
            writeln!(
                w,
                "{{\"severity\":\"{}\",\"code\":\"{}\",\"message\":\"{}\",\"remediation\":[{}],\"check\":\"{}\",\"state\":\"{}\"}}",
                d.severity.as_str(),
                json_escape(d.code),
                json_escape(d.message),
                rem.join(","),
                json_escape(d.check),
                json_escape(d.state),
            )?;
        }
        Ok(())
    }
}

/// `PATH` を走査する要素数の上限（無制限の走査を避ける）。
#[cfg(target_os = "linux")]
const MAX_PATH_ENTRIES: usize = 256;

/// `PATH` の絶対パスの要素に `systemd-run` という名のファイルがあるか（存在の確認だけ。実行も採用もしない）。
#[cfg(target_os = "linux")]
fn exists_on_path(path_var: Option<&std::ffi::OsStr>) -> bool {
    let Some(p) = path_var else { return false };
    std::env::split_paths(p)
        .take(MAX_PATH_ENTRIES)
        .filter(|d| d.is_absolute())
        .any(|d| d.join(crate::user_scope::SYSTEMD_RUN_NAME).is_file())
}

/// 事実を集める（読み取りのみ）。非 Linux は対象外の値を返す。
#[cfg(target_os = "linux")]
pub fn collect() -> UserScopeFindings {
    use crate::user_scope::{
        Identity, SystemdRunRejection, identity_from_status, read_self_status, resolve_systemd_run,
        systemd_run_candidates,
    };
    let identity = read_self_status()
        .as_deref()
        .map_or(Identity::Unreadable, identity_from_status);
    let euid = match identity {
        Identity::Rootless { euid } => euid,
        Identity::Rootful => {
            return UserScopeFindings {
                privilege: PrivilegeState::Rootful,
                systemd_run: SystemdRunState::NotChecked,
                user_manager: UserManagerState::NotChecked,
            };
        }
        Identity::Unreadable => {
            return UserScopeFindings {
                privilege: PrivilegeState::Unreadable,
                systemd_run: SystemdRunState::NotChecked,
                user_manager: UserManagerState::NotChecked,
            };
        }
    };
    let candidates = systemd_run_candidates();
    let refs: Vec<&std::path::Path> = candidates.iter().map(std::path::PathBuf::as_path).collect();
    let systemd_run = match resolve_systemd_run(&refs, euid, std::path::Path::new("/")) {
        Ok(_) => SystemdRunState::Trusted,
        Err(SystemdRunRejection::NotFound) => SystemdRunState::NotFound {
            on_path: exists_on_path(std::env::var_os("PATH").as_deref()),
        },
        Err(r) => SystemdRunState::Untrusted(match r {
            SystemdRunRejection::NotRegularFile => UntrustedReason::NotRegularFile,
            SystemdRunRejection::NoExecuteBit => UntrustedReason::NoExecuteBit,
            SystemdRunRejection::UntrustedOwner { ancestor: false } => UntrustedReason::FileOwner,
            SystemdRunRejection::UntrustedOwner { ancestor: true } => {
                UntrustedReason::AncestorOwner
            }
            SystemdRunRejection::GroupOrOtherWritable { ancestor: false } => {
                UntrustedReason::FileMode
            }
            SystemdRunRejection::GroupOrOtherWritable { ancestor: true } => {
                UntrustedReason::AncestorMode
            }
            SystemdRunRejection::NotFound | SystemdRunRejection::Unreadable => {
                UntrustedReason::Unreadable
            }
        }),
    };
    use fandhe_container_supervisor::user_scope::{UserManagerError, user_manager_env};
    let user_manager = match user_manager_env(std::env::var_os("XDG_RUNTIME_DIR").as_deref(), euid)
    {
        Ok(_) => UserManagerState::Reachable,
        Err(UserManagerError::RuntimeDirUnset) => UserManagerState::RuntimeDirUnset,
        Err(_) => UserManagerState::Unreachable,
    };
    UserScopeFindings {
        privilege: PrivilegeState::Rootless,
        systemd_run,
        user_manager,
    }
}

/// 事実を集める（非 Linux は対象外）。
#[cfg(not(target_os = "linux"))]
pub fn collect() -> UserScopeFindings {
    UserScopeFindings {
        privilege: PrivilegeState::Unsupported,
        systemd_run: SystemdRunState::NotChecked,
        user_manager: UserManagerState::NotChecked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn findings(
        privilege: PrivilegeState,
        systemd_run: SystemdRunState,
        user_manager: UserManagerState,
    ) -> UserScopeFindings {
        UserScopeFindings {
            privilege,
            systemd_run,
            user_manager,
        }
    }

    fn codes(r: &UserScopeReport) -> Vec<&'static str> {
        r.diagnostics.iter().map(|d| d.code).collect()
    }

    /// CORE-3: 問題なしは診断なし・終了 0。
    #[test]
    fn core3_all_clear() {
        let r = evaluate(&findings(
            PrivilegeState::Rootless,
            SystemdRunState::Trusted,
            UserManagerState::Reachable,
        ));
        assert_eq!(r.outcome, UserScopeOutcome::Ok);
        assert!(r.diagnostics.is_empty());
        assert_eq!(r.exit_status().code(), 0);
    }

    /// CORE-3: systemd-run が無いと Warning。`PATH` にだけあるときは追加の通知が付く。
    #[test]
    fn core3_systemd_run_not_found() {
        let r = evaluate(&findings(
            PrivilegeState::Rootless,
            SystemdRunState::NotFound { on_path: false },
            UserManagerState::Reachable,
        ));
        assert_eq!(codes(&r), ["SYSTEMD_RUN_NOT_FOUND"]);
        assert_eq!(r.diagnostics[0].severity, DoctorSeverity::Warning);
        assert_eq!(r.diagnostics[0].state, "not_found");
        assert_eq!(r.diagnostics[0].remediation.len(), 1);
        assert_eq!(r.exit_status().code(), 3);

        let r = evaluate(&findings(
            PrivilegeState::Rootless,
            SystemdRunState::NotFound { on_path: true },
            UserManagerState::Reachable,
        ));
        assert_eq!(
            codes(&r),
            [
                "SYSTEMD_RUN_NOT_FOUND",
                "SYSTEMD_RUN_OUTSIDE_FIXED_LOCATIONS"
            ]
        );
        assert_eq!(r.diagnostics[1].severity, DoctorSeverity::Notice);
        assert_eq!(r.exit_status().code(), 3);
    }

    /// CORE-3・PLUG-11: 信頼できない理由ごとにトークンと対処を出し分ける。
    #[test]
    fn core3_plug11_systemd_run_untrusted_reasons() {
        let cases = [
            (UntrustedReason::FileOwner, "file_owner"),
            (UntrustedReason::FileMode, "file_mode"),
            (UntrustedReason::NotRegularFile, "not_regular_file"),
            (UntrustedReason::NoExecuteBit, "no_execute_bit"),
            (UntrustedReason::AncestorOwner, "ancestor_owner"),
            (UntrustedReason::AncestorMode, "ancestor_mode"),
            (UntrustedReason::Unreadable, "unreadable"),
        ];
        let mut seen = Vec::new();
        for (reason, token) in cases {
            let r = evaluate(&findings(
                PrivilegeState::Rootless,
                SystemdRunState::Untrusted(reason),
                UserManagerState::Reachable,
            ));
            assert_eq!(codes(&r), ["SYSTEMD_RUN_UNTRUSTED"]);
            assert_eq!(r.diagnostics[0].state, token);
            assert_eq!(r.diagnostics[0].remediation.len(), 1);
            seen.push(r.diagnostics[0].remediation[0]);
            assert_eq!(r.exit_status().code(), 3);
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 7, "each reason has its own remediation");
        let ancestor = evaluate(&findings(
            PrivilegeState::Rootless,
            SystemdRunState::Untrusted(UntrustedReason::AncestorMode),
            UserManagerState::Reachable,
        ));
        assert!(ancestor.diagnostics[0].remediation[0].contains("/nix/store"));
    }

    /// CORE-3・CORE-4: user マネージャに届かない 2 通りは Warning で、対処文の件数が決まっている。
    #[test]
    fn core3_core4_user_manager_states() {
        let r = evaluate(&findings(
            PrivilegeState::Rootless,
            SystemdRunState::Trusted,
            UserManagerState::RuntimeDirUnset,
        ));
        assert_eq!(codes(&r), ["XDG_RUNTIME_DIR_UNSET"]);
        assert_eq!(r.diagnostics[0].state, "runtime_dir_unset");
        assert_eq!(r.diagnostics[0].remediation.len(), 1);
        assert_eq!(r.exit_status().code(), 3);

        let r = evaluate(&findings(
            PrivilegeState::Rootless,
            SystemdRunState::Trusted,
            UserManagerState::Unreachable,
        ));
        assert_eq!(codes(&r), ["USER_MANAGER_UNREACHABLE"]);
        assert_eq!(r.diagnostics[0].state, "unreachable");
        assert_eq!(r.diagnostics[0].remediation.len(), 2);
        assert!(r.diagnostics[0].remediation[1].contains("loginctl enable-linger"));
        assert_eq!(r.exit_status().code(), 3);
    }

    /// CORE-3: 2 つの検査は独立で、両方失敗なら両方の診断が出る。
    #[test]
    fn core3_both_failures_reported() {
        let r = evaluate(&findings(
            PrivilegeState::Rootless,
            SystemdRunState::NotFound { on_path: false },
            UserManagerState::Unreachable,
        ));
        assert_eq!(
            codes(&r),
            ["SYSTEMD_RUN_NOT_FOUND", "USER_MANAGER_UNREACHABLE"]
        );
    }

    /// SEC-5: rootful は検査を省いた通知だけで 0、判定不能は 4、対象外 OS は診断なしで 0。
    #[test]
    fn sec5_non_rootless_privileges() {
        let r = evaluate(&findings(
            PrivilegeState::Rootful,
            SystemdRunState::NotChecked,
            UserManagerState::NotChecked,
        ));
        assert_eq!(codes(&r), ["USER_SCOPE_CHECK_SKIPPED_AS_ROOT"]);
        assert_eq!(r.diagnostics[0].severity, DoctorSeverity::Notice);
        assert_eq!(r.exit_status().code(), 0);

        let r = evaluate(&findings(
            PrivilegeState::Unreadable,
            SystemdRunState::NotChecked,
            UserManagerState::NotChecked,
        ));
        assert_eq!(codes(&r), ["USER_SCOPE_INCONCLUSIVE"]);
        assert_eq!(r.exit_status().code(), 4);

        let r = evaluate(&findings(
            PrivilegeState::Unsupported,
            SystemdRunState::NotChecked,
            UserManagerState::NotChecked,
        ));
        assert!(r.diagnostics.is_empty());
        assert_eq!(r.outcome, UserScopeOutcome::NotApplicable);
        assert_eq!(r.exit_status().code(), 0);
    }

    /// REPAIR-2・ERR-1: JSON Lines の 1 行の形が固定で、パスを載せない（テキストはすべて固定文言）。
    #[test]
    fn core3_json_lines_shape() {
        let r = evaluate(&findings(
            PrivilegeState::Rootless,
            SystemdRunState::Trusted,
            UserManagerState::RuntimeDirUnset,
        ));
        let mut buf = Vec::new();
        r.write_json_lines(&mut buf).expect("write");
        let text = String::from_utf8(buf).expect("utf8");
        assert_eq!(
            text,
            "{\"severity\":\"warning\",\"code\":\"XDG_RUNTIME_DIR_UNSET\",\"message\":\"XDG_RUNTIME_DIR is not set to an absolute path; the systemd user manager is not reachable\",\"remediation\":[\"Log in through a systemd login session (pam_systemd sets XDG_RUNTIME_DIR), or export XDG_RUNTIME_DIR=/run/user/$(id -u) in the shell that runs fandhe-container\"],\"check\":\"user_manager\",\"state\":\"runtime_dir_unset\"}\n"
        );
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::super::*;
        use std::ffi::OsString;

        /// CORE-3: `PATH` の走査は絶対パスの要素だけを対象にし、存在の確認に限る。
        #[test]
        fn core3_exists_on_path_considers_absolute_entries_only() {
            let dir = std::env::temp_dir().join(format!("fc-doc-path-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("mkdir");
            std::fs::write(dir.join("systemd-run"), b"").expect("file");
            let joined = std::env::join_paths([dir.clone()]).expect("join");
            assert!(exists_on_path(Some(joined.as_os_str())));
            assert!(!exists_on_path(None));
            assert!(!exists_on_path(Some(OsString::from("rel/dir").as_os_str())));
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// CORE-3: 実環境の収集は panic せず、非 root なら rootless、root なら rootful になる。
        #[test]
        fn core3_collect_runs_on_host() {
            let f = collect();
            assert!(matches!(
                f.privilege,
                PrivilegeState::Rootless | PrivilegeState::Rootful
            ));
        }
    }
}
