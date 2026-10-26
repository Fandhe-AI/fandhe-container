//! `doctor` の特権ランチャー経路の前提の診断: ランチャーの信頼条件と昇格手段（file capability / setuid root）
//! （#2599・SUP-14・CORE-6）。
//!
//! rootful のインストールでは `start` が CLI の実体の隣の固定名 `fandhe-container-launcher` を選び、systemd-run 経由で
//! 起動する（#2442）。ランチャーが信頼条件を満たさない、または昇格手段が無いと `start` は失敗するため、本モジュールは
//! その前提を読み取り専用で診断する。外部コマンドは実行せず、属性も変えない。
//!
//! # `start` との一致
//! ランチャーの解決と分類は `fandhe_container_supervisor::start_client::classify_launcher_beside`（`start` が呼ぶのと
//! 同じ関数）を呼ぶ。規則（実体の隣の固定名・`PATH` 探索なし・通常ファイル・実行可能・所有者が root か euid・
//! group/other 書き込み不可・symlink の解決）を doctor 側に複製しない。昇格手段は
//! `fandhe_container_supervisor::launcher_probe`（`security.capability` の復号と setuid root の代替の判定）で調べる。
//!
//! # 構成
//! - 事実の収集（[`collect`]。Linux のみ）と評価（[`evaluate`]。純粋関数で全 OS で単体テストできる）を分ける。
//! - 昇格手段の判定の後に、ランチャーの実体が `nosuid` のマウント上にあるかを調べる（[`apply_mount`]。#2661）。
//!   実体を開いた fd の mount ID（`/proc/self/fdinfo/<fd>` の `mnt_id`）で mountinfo の行を引き、その per-mount
//!   options を見る（パスの最長一致は、重ねマウント・`mount --move` で隠れた古い行を選びうるため使わない）。
//!   `nosuid` なら setuid も file capability も効かないため、昇格手段が正しくても `nosuid_mount` の警告にする。
//!   実体を開けない・fdinfo や mountinfo を読めない・該当の行が無いときは、`start` が通るはずの状態を Ok と
//!   断定せず判定不能にする（fail-closed）。
//! - 出力は `user_scope_check` と同じ JSON Lines（`severity`・`code`・`message`・`remediation`・`check`・`state`）で、
//!   `check` は常に `launcher`。パス・uid・mode・errno・capability の生の値は載せない（REPAIR-4）。
//! - 終了ステータス: Warning があれば 3、そうでなく判定不能があれば 4、それ以外は 0。rootless のインストール
//!   （ランチャー無し）と rootful での省略は通知で、0 に寄与する。
//!
//! # 未実装・範囲外（REPAIR-3。実装済みを装わない）
//! - ランチャー・supervisor の hash / 署名の照合は扱わない（`docs/design/privilege-separation.md` 12 章の未確認事項。
//!   #2599 の受け入れ条件 3）。
//! - LSM 下の挙動は検出しない。
//! - `nosuid` の検出は doctor 自身の mount namespace から見た fdinfo と `/proc/self/mountinfo` だけを根拠にする。`start` が
//!   systemd-run 経由で起動する実行環境の mount namespace とは食い違いうる。superblock の所有 user namespace が
//!   init でないために `mnt_may_suid` が偽になる場合も検出しない。
//! - 診断と `start` の実行の間の差し替え（TOCTOU）は防げない。昇格の可否は実行時にランチャーが検証する（fail-closed）。

use super::DoctorSeverity;
use super::user_scope_check::{
    PrivilegeState, UserScopeDiagnostic, UserScopeOutcome, UserScopeReport,
};

/// 診断の種別を表す `check` の値。
const CHECK: &str = "launcher";

/// ランチャーが信頼できない理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UntrustedKind {
    /// 通常ファイルではない。
    NotRegularFile,
    /// 実行ビットが無い。
    NoExecuteBit,
    /// 所有者が root でも実効 UID でもない。
    FileOwner,
    /// group / other から書き込み可。
    FileMode,
    /// 解決できない（リンク切れ・ループ・権限エラー等）。
    Unresolvable,
    /// 解決後の属性を読めない。
    Unreadable,
}

impl UntrustedKind {
    fn token(self) -> &'static str {
        match self {
            Self::NotRegularFile => "not_regular_file",
            Self::NoExecuteBit => "no_execute_bit",
            Self::FileOwner => "file_owner",
            Self::FileMode => "file_mode",
            Self::Unresolvable => "unresolvable",
            Self::Unreadable => "unreadable",
        }
    }
}

/// 信頼できるランチャーの昇格手段の状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    /// setuid root（xattr 非対応環境の代替）。
    SetuidRoot,
    /// setuid root だが併存する file capability が期待集合を満たさず、昇格できない。
    SetuidRootRestricted,
    /// file capability が期待集合ちょうど。
    FileCapabilities,
    /// 期待集合を含み超過のビットがある。
    Excess,
    /// 期待集合に足りない。
    Insufficient,
    /// effective フラグが無い。
    NotEffective,
    /// v3 の rootid が 0 以外。
    Namespaced,
    /// バイト列が壊れている。
    Malformed,
    /// 昇格手段が無い。
    NoElevation,
    /// 実体が `nosuid` マウント上にあり、setuid も file capability も効かない（#2661）。
    NosuidMount,
    /// 実体のマウント属性を確認できない（#2661）。
    MountUnknown,
    /// 読み取りに失敗した。
    Unreadable,
}

/// ランチャーの実体が載るマウントの `nosuid` 属性の確認結果（#2661）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherMount {
    /// `nosuid` ではない。
    Allowed,
    /// `nosuid` のマウント上にある。
    Nosuid,
    /// 確認できなかった（実体を開けない・fdinfo / mountinfo を読めない・上限超過・該当の行が無い・壊れた行）。
    Unknown,
}

/// 昇格手段の判定にマウント属性を重ねる純粋関数（SUP-14・CORE-6・#2661）。
///
/// `Nosuid` は常に `NosuidMount`（setuid も file capability も効かないため）。`Unknown` は `start` が通るはずの状態
/// （`FileCapabilities`・`SetuidRoot`・`Excess`）だけを `MountUnknown` に置き換え、既に不備を示す警告・読み取り失敗は
/// そのまま残す。`Allowed` は何も変えない。
pub fn apply_mount(mount: LauncherMount, e: Elevation) -> Elevation {
    match mount {
        LauncherMount::Allowed => e,
        LauncherMount::Nosuid => Elevation::NosuidMount,
        LauncherMount::Unknown => match e {
            Elevation::FileCapabilities | Elevation::SetuidRoot | Elevation::Excess => {
                Elevation::MountUnknown
            }
            other => other,
        },
    }
}

/// ランチャーの状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherState {
    /// 検査しなかった（rootful・対象外 OS・`/proc/self/status` を読めない場合）。
    NotChecked,
    /// CLI 自身の実体パスを解決できない。
    ExeUnresolvable,
    /// ランチャーが無い（rootless のインストール）。
    Absent,
    /// 在るが信頼条件を満たさない。
    Untrusted(UntrustedKind),
    /// 信頼でき、昇格手段の状態が分かっている。
    Trusted(Elevation),
}

/// 収集した事実。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LauncherFindings {
    /// 実行ユーザー。
    pub privilege: PrivilegeState,
    /// ランチャーの状態。
    pub launcher: LauncherState,
}

fn diag(
    severity: DoctorSeverity,
    code: &'static str,
    message: &'static str,
    remediation: Vec<&'static str>,
    state: &'static str,
) -> UserScopeDiagnostic {
    UserScopeDiagnostic {
        severity,
        code,
        message,
        remediation,
        check: CHECK,
        state,
    }
}

fn report(d: UserScopeDiagnostic) -> UserScopeReport {
    let outcome = match d.severity {
        DoctorSeverity::Warning => UserScopeOutcome::Warning,
        _ if d.code.ends_with("INCONCLUSIVE") => UserScopeOutcome::Inconclusive,
        _ => UserScopeOutcome::Ok,
    };
    UserScopeReport {
        outcome,
        diagnostics: vec![d],
    }
}

const REINSTALL: &str = "Reinstall with scripts/install-privileged-launcher.sh as root; it sets the file capabilities and verifies them";

/// 事実から診断を作る純粋関数（SUP-14・CORE-6）。
pub fn evaluate(f: &LauncherFindings) -> UserScopeReport {
    use DoctorSeverity::{Notice, Warning};
    match f.privilege {
        PrivilegeState::Unsupported => {
            return UserScopeReport {
                outcome: UserScopeOutcome::NotApplicable,
                diagnostics: Vec::new(),
            };
        }
        PrivilegeState::Rootful => {
            return report(diag(
                Notice,
                "LAUNCHER_CHECK_SKIPPED_AS_ROOT",
                "the privileged launcher checks were skipped because this process runs as root; rootful start is not supported",
                vec![
                    "Re-run fandhe-container doctor as the unprivileged user that starts containers",
                ],
                "rootful",
            ));
        }
        PrivilegeState::Unreadable => {
            return report(diag(
                Notice,
                "LAUNCHER_CHECK_INCONCLUSIVE",
                "the privileged launcher checks could not run because the process identity could not be read",
                vec!["Check that /proc is mounted and readable"],
                "unreadable",
            ));
        }
        PrivilegeState::Rootless => {}
    }
    match f.launcher {
        LauncherState::NotChecked => UserScopeReport {
            outcome: UserScopeOutcome::NotApplicable,
            diagnostics: Vec::new(),
        },
        LauncherState::ExeUnresolvable => report(diag(
            Notice,
            "LAUNCHER_CHECK_INCONCLUSIVE",
            "the privileged launcher checks could not run because the cli executable path could not be resolved",
            vec!["Run fandhe-container by an absolute path"],
            "exe_unresolvable",
        )),
        LauncherState::Absent => report(diag(
            Notice,
            "PRIVILEGED_LAUNCHER_ABSENT",
            "no privileged launcher is installed beside the cli executable; start uses the rootless direct path",
            vec![
                "For a rootful install, run scripts/install-privileged-launcher.sh as root so fandhe-container-launcher is placed beside the cli",
            ],
            "absent",
        )),
        LauncherState::Untrusted(kind) => report(diag(
            Warning,
            "PRIVILEGED_LAUNCHER_UNTRUSTED",
            "the privileged launcher beside the cli executable is not trusted; start refuses to run and does not fall back to the direct path",
            vec![
                "The launcher must be a regular executable file owned by root or the current user and not writable by group or others",
                REINSTALL,
                "For a rootless install, remove fandhe-container-launcher from the directory of the fandhe-container executable",
            ],
            kind.token(),
        )),
        LauncherState::Trusted(e) => evaluate_elevation(e),
    }
}

fn evaluate_elevation(e: Elevation) -> UserScopeReport {
    use DoctorSeverity::{Notice, Warning};
    let unavailable = |state: &'static str, message: &'static str| {
        report(diag(
            Warning,
            "LAUNCHER_ELEVATION_UNAVAILABLE",
            message,
            vec![REINSTALL],
            state,
        ))
    };
    match e {
        Elevation::FileCapabilities => report(diag(
            Notice,
            "PRIVILEGED_LAUNCHER_READY",
            "the privileged launcher is trusted and carries the expected file capabilities",
            Vec::new(),
            "file_capabilities",
        )),
        Elevation::SetuidRoot => report(diag(
            Notice,
            "PRIVILEGED_LAUNCHER_READY",
            "the privileged launcher is trusted and is setuid root (the alternative for filesystems without xattr support)",
            Vec::new(),
            "setuid_root",
        )),
        Elevation::SetuidRootRestricted => unavailable(
            "setuid_root_restricted",
            "the privileged launcher is setuid root but also carries file capabilities that do not cover the required set or lack CAP_SETUID; the file capabilities take precedence and start cannot elevate",
        ),
        Elevation::Excess => report(diag(
            Notice,
            "LAUNCHER_FILE_CAPABILITIES_EXCESS",
            "the privileged launcher carries file capabilities beyond the required set; the launcher reduces them at run time",
            vec![REINSTALL],
            "excess",
        )),
        Elevation::NoElevation => unavailable(
            "no_file_capabilities",
            "the privileged launcher has neither file capabilities nor the setuid root bit; start cannot elevate",
        ),
        Elevation::Insufficient => unavailable(
            "insufficient",
            "the privileged launcher file capabilities do not cover the required set",
        ),
        Elevation::NotEffective => unavailable(
            "not_effective",
            "the privileged launcher file capabilities lack the effective flag",
        ),
        Elevation::Namespaced => unavailable(
            "namespaced",
            "the privileged launcher file capabilities are bound to a non-init user namespace and do not apply",
        ),
        Elevation::Malformed => unavailable(
            "malformed",
            "the privileged launcher file capabilities are malformed",
        ),
        Elevation::NosuidMount => report(diag(
            Warning,
            "LAUNCHER_ELEVATION_UNAVAILABLE",
            "the privileged launcher is on a filesystem mounted nosuid; setuid and file capabilities have no effect there and start cannot elevate",
            vec![
                "Install the cli, supervisor and launcher into a directory on a filesystem mounted without nosuid",
                REINSTALL,
            ],
            "nosuid_mount",
        )),
        Elevation::MountUnknown => report(diag(
            Notice,
            "LAUNCHER_ELEVATION_INCONCLUSIVE",
            "the mount options of the filesystem that holds the privileged launcher could not be read",
            vec![
                "Check that /proc is mounted and /proc/self/mountinfo and /proc/self/fdinfo are readable",
            ],
            "mount_unreadable",
        )),
        Elevation::Unreadable => report(diag(
            Notice,
            "LAUNCHER_ELEVATION_INCONCLUSIVE",
            "the privileged launcher file capabilities could not be read",
            vec!["Check the filesystem that holds the launcher supports extended attributes"],
            "xattr_unreadable",
        )),
    }
}

/// mountinfo の内容と実体の mount ID から `nosuid` 属性を判定する純粋関数（Linux のみ。#2661）。
/// どちらかが得られていない（`None`）・該当の行が無い・壊れた行は `Unknown`（fail-closed）。
#[cfg(target_os = "linux")]
fn launcher_mount_state(mountinfo: Option<&[u8]>, mount_id: Option<u64>) -> LauncherMount {
    let (Some(info), Some(id)) = (mountinfo, mount_id) else {
        return LauncherMount::Unknown;
    };
    use fandhe_container_net::netns::MountOptionState;
    match fandhe_container_net::netns::mount_option_by_id(info, id, "nosuid") {
        MountOptionState::Present => LauncherMount::Nosuid,
        MountOptionState::Absent => LauncherMount::Allowed,
        // 将来の理由追加も含め、判定できないものは Unknown（fail-closed）。
        _ => LauncherMount::Unknown,
    }
}

/// ランチャーの実体を読み取り専用で開き、その fd の mount ID を得る。開けない・読めないときは `None`。
/// 実体はインストールスクリプトが 0755 / 4755 で置くため読める。開くのは mount ID を得るためだけで、
/// 中身は読まない。
#[cfg(target_os = "linux")]
fn launcher_mount_id(path: &std::path::Path) -> Option<u64> {
    let file = std::fs::File::open(path).ok()?;
    fandhe_container_net::netns::file_mount_id(&file).ok()
}

/// 事実を集める（読み取りのみ。`start` と同じ `classify_launcher_beside` を使う）。
#[cfg(target_os = "linux")]
pub fn collect() -> LauncherFindings {
    use crate::user_scope::{Identity, identity_from_status, read_self_status};
    use fandhe_container_supervisor::launcher_probe::{
        ElevationAssessment, assess_elevation, read_launcher_file_caps,
    };
    use fandhe_container_supervisor::start_client::{
        LauncherPresence, LauncherUntrustedReason, classify_launcher_beside,
    };
    let unchecked = |privilege| LauncherFindings {
        privilege,
        launcher: LauncherState::NotChecked,
    };
    let euid = match read_self_status()
        .as_deref()
        .map_or(Identity::Unreadable, identity_from_status)
    {
        Identity::Rootless { euid } => euid,
        Identity::Rootful => return unchecked(PrivilegeState::Rootful),
        Identity::Unreadable => return unchecked(PrivilegeState::Unreadable),
    };
    let found = |launcher| LauncherFindings {
        privilege: PrivilegeState::Rootless,
        launcher,
    };
    let Ok(exe) = std::env::current_exe() else {
        return found(LauncherState::ExeUnresolvable);
    };
    let presence = match classify_launcher_beside(&exe, euid) {
        Ok(p) => p,
        Err(_) => return found(LauncherState::ExeUnresolvable),
    };
    found(match presence {
        LauncherPresence::Absent => LauncherState::Absent,
        LauncherPresence::Untrusted(r) => LauncherState::Untrusted(match r {
            LauncherUntrustedReason::NotRegularFile => UntrustedKind::NotRegularFile,
            LauncherUntrustedReason::NoExecuteBit => UntrustedKind::NoExecuteBit,
            LauncherUntrustedReason::FileOwner => UntrustedKind::FileOwner,
            LauncherUntrustedReason::FileMode => UntrustedKind::FileMode,
            LauncherUntrustedReason::Unresolvable => UntrustedKind::Unresolvable,
            // 将来追加される理由も信頼しない側（fail-closed）に寄せる。
            _ => UntrustedKind::Unreadable,
        }),
        LauncherPresence::Trusted(t) => {
            let xattr = read_launcher_file_caps(&t.path);
            // mountinfo は外部入力として上限つきで生バイトのまま読む（パス欄は比べないため置換は不要）。
            let mountinfo = super::read_limited_bytes(
                std::path::Path::new("/proc/self/mountinfo"),
                super::MAX_MOUNTINFO_READ,
            )
            .ok();
            let mount = launcher_mount_state(mountinfo.as_deref(), launcher_mount_id(&t.path));
            let elevation = match assess_elevation(t.owner_uid, t.mode, &xattr) {
                ElevationAssessment::SetuidRoot => Elevation::SetuidRoot,
                ElevationAssessment::SetuidRootRestrictedByFileCaps => {
                    Elevation::SetuidRootRestricted
                }
                ElevationAssessment::FileCapabilitiesOk => Elevation::FileCapabilities,
                ElevationAssessment::FileCapabilitiesExcess => Elevation::Excess,
                ElevationAssessment::FileCapabilitiesInsufficient => Elevation::Insufficient,
                ElevationAssessment::FileCapabilitiesNotEffective => Elevation::NotEffective,
                ElevationAssessment::FileCapabilitiesNamespaced => Elevation::Namespaced,
                ElevationAssessment::FileCapabilitiesMalformed => Elevation::Malformed,
                ElevationAssessment::NoElevation => Elevation::NoElevation,
                _ => Elevation::Unreadable,
            };
            LauncherState::Trusted(apply_mount(mount, elevation))
        }
    })
}

/// 事実を集める（非 Linux は対象外）。
#[cfg(not(target_os = "linux"))]
pub fn collect() -> LauncherFindings {
    LauncherFindings {
        privilege: PrivilegeState::Unsupported,
        launcher: LauncherState::NotChecked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::DoctorExitStatus;

    fn run(privilege: PrivilegeState, launcher: LauncherState) -> (String, DoctorExitStatus) {
        let r = evaluate(&LauncherFindings {
            privilege,
            launcher,
        });
        let mut out = Vec::new();
        r.write_json_lines(&mut out).expect("write");
        (String::from_utf8(out).expect("utf8"), r.exit_status())
    }

    fn one(launcher: LauncherState) -> (String, DoctorExitStatus) {
        run(PrivilegeState::Rootless, launcher)
    }

    /// SUP-14・#2599: 不在は通知（0）で JSON 1 行の完全一致。
    #[test]
    fn sup14_absent_launcher_is_notice() {
        let (out, st) = one(LauncherState::Absent);
        assert_eq!(
            out,
            "{\"severity\":\"notice\",\"code\":\"PRIVILEGED_LAUNCHER_ABSENT\",\"message\":\"no privileged launcher is installed beside the cli executable; start uses the rootless direct path\",\"remediation\":[\"For a rootful install, run scripts/install-privileged-launcher.sh as root so fandhe-container-launcher is placed beside the cli\"],\"check\":\"launcher\",\"state\":\"absent\"}\n"
        );
        assert_eq!(st, DoctorExitStatus::Ok);
    }

    /// SUP-14・#2599: 信頼できない理由ごとに state が分かれ、終了は 3。
    #[test]
    fn sup14_untrusted_launcher_states() {
        for (kind, token) in [
            (UntrustedKind::NotRegularFile, "not_regular_file"),
            (UntrustedKind::NoExecuteBit, "no_execute_bit"),
            (UntrustedKind::FileOwner, "file_owner"),
            (UntrustedKind::FileMode, "file_mode"),
            (UntrustedKind::Unresolvable, "unresolvable"),
            (UntrustedKind::Unreadable, "unreadable"),
        ] {
            let (out, st) = one(LauncherState::Untrusted(kind));
            assert!(out.starts_with(
                "{\"severity\":\"warning\",\"code\":\"PRIVILEGED_LAUNCHER_UNTRUSTED\""
            ));
            assert!(
                out.ends_with(&format!("\"check\":\"launcher\",\"state\":\"{token}\"}}\n")),
                "{out}"
            );
            assert_eq!(st, DoctorExitStatus::Warning);
        }
    }

    /// SUP-14・#2599: 昇格手段の全状態の code / severity / state / 終了ステータス。
    #[test]
    fn sup14_elevation_states() {
        use DoctorExitStatus as S;
        for (e, sev, code, state, status) in [
            (
                Elevation::FileCapabilities,
                "notice",
                "PRIVILEGED_LAUNCHER_READY",
                "file_capabilities",
                S::Ok,
            ),
            (
                Elevation::SetuidRoot,
                "notice",
                "PRIVILEGED_LAUNCHER_READY",
                "setuid_root",
                S::Ok,
            ),
            (
                Elevation::SetuidRootRestricted,
                "warning",
                "LAUNCHER_ELEVATION_UNAVAILABLE",
                "setuid_root_restricted",
                S::Warning,
            ),
            (
                Elevation::Excess,
                "notice",
                "LAUNCHER_FILE_CAPABILITIES_EXCESS",
                "excess",
                S::Ok,
            ),
            (
                Elevation::NoElevation,
                "warning",
                "LAUNCHER_ELEVATION_UNAVAILABLE",
                "no_file_capabilities",
                S::Warning,
            ),
            (
                Elevation::Insufficient,
                "warning",
                "LAUNCHER_ELEVATION_UNAVAILABLE",
                "insufficient",
                S::Warning,
            ),
            (
                Elevation::NotEffective,
                "warning",
                "LAUNCHER_ELEVATION_UNAVAILABLE",
                "not_effective",
                S::Warning,
            ),
            (
                Elevation::Namespaced,
                "warning",
                "LAUNCHER_ELEVATION_UNAVAILABLE",
                "namespaced",
                S::Warning,
            ),
            (
                Elevation::Malformed,
                "warning",
                "LAUNCHER_ELEVATION_UNAVAILABLE",
                "malformed",
                S::Warning,
            ),
            (
                Elevation::NosuidMount,
                "warning",
                "LAUNCHER_ELEVATION_UNAVAILABLE",
                "nosuid_mount",
                S::Warning,
            ),
            (
                Elevation::MountUnknown,
                "notice",
                "LAUNCHER_ELEVATION_INCONCLUSIVE",
                "mount_unreadable",
                S::Inconclusive,
            ),
            (
                Elevation::Unreadable,
                "notice",
                "LAUNCHER_ELEVATION_INCONCLUSIVE",
                "xattr_unreadable",
                S::Inconclusive,
            ),
        ] {
            let (out, st) = one(LauncherState::Trusted(e));
            assert!(
                out.starts_with(&format!("{{\"severity\":\"{sev}\",\"code\":\"{code}\"")),
                "{e:?}: {out}"
            );
            assert!(
                out.ends_with(&format!("\"check\":\"launcher\",\"state\":\"{state}\"}}\n")),
                "{e:?}: {out}"
            );
            assert_eq!(st, status, "{e:?}");
        }
    }

    /// SUP-14・#2661: nosuid マウントは警告（3）で JSON 1 行の完全一致。
    #[test]
    fn sup14_nosuid_mount_is_warning() {
        let (out, st) = one(LauncherState::Trusted(Elevation::NosuidMount));
        assert_eq!(
            out,
            "{\"severity\":\"warning\",\"code\":\"LAUNCHER_ELEVATION_UNAVAILABLE\",\"message\":\"the privileged launcher is on a filesystem mounted nosuid; setuid and file capabilities have no effect there and start cannot elevate\",\"remediation\":[\"Install the cli, supervisor and launcher into a directory on a filesystem mounted without nosuid\",\"Reinstall with scripts/install-privileged-launcher.sh as root; it sets the file capabilities and verifies them\"],\"check\":\"launcher\",\"state\":\"nosuid_mount\"}\n"
        );
        assert_eq!(st, DoctorExitStatus::Warning);
    }

    /// SUP-14・#2661: マウント属性が読めないときは判定不能（4）で JSON 1 行の完全一致。
    #[test]
    fn sup14_mount_unknown_is_inconclusive() {
        let (out, st) = one(LauncherState::Trusted(Elevation::MountUnknown));
        assert_eq!(
            out,
            "{\"severity\":\"notice\",\"code\":\"LAUNCHER_ELEVATION_INCONCLUSIVE\",\"message\":\"the mount options of the filesystem that holds the privileged launcher could not be read\",\"remediation\":[\"Check that /proc is mounted and /proc/self/mountinfo and /proc/self/fdinfo are readable\"],\"check\":\"launcher\",\"state\":\"mount_unreadable\"}\n"
        );
        assert_eq!(st, DoctorExitStatus::Inconclusive);
    }

    /// SUP-14・#2661: `apply_mount` の全組み合わせ。
    #[test]
    fn sup14_apply_mount_table() {
        use Elevation as E;
        use LauncherMount as M;
        let all = [
            E::SetuidRoot,
            E::SetuidRootRestricted,
            E::FileCapabilities,
            E::Excess,
            E::Insufficient,
            E::NotEffective,
            E::Namespaced,
            E::Malformed,
            E::NoElevation,
            E::NosuidMount,
            E::MountUnknown,
            E::Unreadable,
        ];
        for e in all {
            assert_eq!(apply_mount(M::Allowed, e), e, "{e:?}");
            assert_eq!(apply_mount(M::Nosuid, e), E::NosuidMount, "{e:?}");
            let expected = match e {
                E::FileCapabilities | E::SetuidRoot | E::Excess => E::MountUnknown,
                other => other,
            };
            assert_eq!(apply_mount(M::Unknown, e), expected, "{e:?}");
        }
    }

    /// SUP-14・#2661: mountinfo の fixture と mount ID からの nosuid 判定（行は ID で引き、非 UTF-8 の
    /// パス欄があっても置換せずに判定する）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup14_launcher_mount_state_from_fixture() {
        let info: &[u8] = b"\
22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw
26 22 0:23 / /opt/fc rw,nosuid,relatime - tmpfs tmpfs rw
27 22 0:24 / /opt/\xff rw,nosuid - tmpfs tmpfs rw
";
        let st = launcher_mount_state;
        assert_eq!(st(Some(info), Some(26)), LauncherMount::Nosuid);
        assert_eq!(st(Some(info), Some(22)), LauncherMount::Allowed);
        assert_eq!(st(Some(info), Some(27)), LauncherMount::Nosuid);
        assert_eq!(st(Some(info), Some(99)), LauncherMount::Unknown);
        assert_eq!(st(None, Some(26)), LauncherMount::Unknown);
        assert_eq!(st(Some(info), None), LauncherMount::Unknown);
        assert_eq!(st(Some(b""), Some(22)), LauncherMount::Unknown);
    }

    /// SEC-1・CLI-1・#2909: 同じマウントポイントに重なったマウント・祖先の overmount でも ID で行を選ぶ。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_2909_launcher_mount_state_stacked_mount_point() {
        let info: &[u8] = b"\
22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw
26 22 0:23 / /opt/fc rw,nosuid,relatime - tmpfs tmpfs rw
28 26 0:25 / /opt/fc rw,relatime - ext4 /dev/sdb1 rw
30 22 0:26 / /opt rw,nosuid - tmpfs tmpfs rw
";
        let st = launcher_mount_state;
        assert_eq!(st(Some(info), Some(26)), LauncherMount::Nosuid);
        assert_eq!(st(Some(info), Some(28)), LauncherMount::Allowed);
        assert_eq!(st(Some(info), Some(30)), LauncherMount::Nosuid);
        let dup: &[u8] = b"\
26 22 0:23 / /opt/fc rw,nosuid - tmpfs tmpfs rw
26 22 0:23 / /opt/fc rw - ext4 /dev/sdb1 rw
";
        assert_eq!(st(Some(dup), Some(26)), LauncherMount::Unknown);
    }

    /// SUP-14・#2661: 実体を開けないときは mount ID を得られず判定不能（`None`）。開けるファイルでは得られる。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup14_launcher_mount_id_needs_openable_file() {
        let missing = std::env::temp_dir().join(format!("fc-mi-missing-{}", std::process::id()));
        assert_eq!(launcher_mount_id(&missing), None);
        let exe = std::env::current_exe().expect("exe");
        let id = launcher_mount_id(&exe).expect("mount id of the test binary");
        let info = std::fs::read("/proc/self/mountinfo").expect("mountinfo");
        assert_ne!(
            launcher_mount_state(Some(&info), Some(id)),
            LauncherMount::Unknown,
            "mount id {id}"
        );
    }

    /// SUP-14・#2599: rootful・読めない・対象外・exe 解決不可の扱い。
    #[test]
    fn sup14_skips_and_inconclusive() {
        let (out, st) = run(PrivilegeState::Rootful, LauncherState::NotChecked);
        assert!(out.contains("\"code\":\"LAUNCHER_CHECK_SKIPPED_AS_ROOT\""));
        assert!(out.ends_with("\"check\":\"launcher\",\"state\":\"rootful\"}\n"));
        assert_eq!(st, DoctorExitStatus::Ok);
        let (out, st) = run(PrivilegeState::Unreadable, LauncherState::NotChecked);
        assert!(out.contains("\"code\":\"LAUNCHER_CHECK_INCONCLUSIVE\""));
        assert_eq!(st, DoctorExitStatus::Inconclusive);
        let (out, st) = one(LauncherState::ExeUnresolvable);
        assert!(out.ends_with("\"state\":\"exe_unresolvable\"}\n"));
        assert_eq!(st, DoctorExitStatus::Inconclusive);
        let (out, st) = run(PrivilegeState::Unsupported, LauncherState::NotChecked);
        assert_eq!((out.as_str(), st), ("", DoctorExitStatus::Ok));
    }
}
