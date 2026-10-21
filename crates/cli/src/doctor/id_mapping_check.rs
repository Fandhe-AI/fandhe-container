//! `doctor` の rootless ID 写像の前提の診断: `/etc/subuid`・`/etc/subgid` の自分の行と `newuidmap`・`newgidmap`
//! （CORE-6・SEC-5・#2387）。
//!
//! `start` は subuid / subgid の設定を見て、両方に自分の行があれば範囲写像（`newuidmap` / `newgidmap` を使う）、
//! 両方に無ければ 1 対 1 写像を選び、それ以外は `FAILED_PRECONDITION` で止まる（#2243）。利用者が前提の欠けを
//! `start` の失敗まで知れないため、本モジュールが同じ判定を読み取り専用で 1 つずつ診断する。
//!
//! # `start` との一致
//! 判定の部品は supervisor の `id_model`（passwd の読み取り・subuid / subgid の分類・モデルの選択）と core の
//! `rootless`（所有者名の規則・範囲の写像・helper の検証）を `start` と共用し、CLI 側に規則を書き直さない。
//! 判定の順序も `start`（`resolve_launch_privilege`）に揃える: rootful の除外 → passwd → 所有者名 → subuid / subgid の
//! 分類 → モデルの選択 → 範囲の検証 → helper の検証。passwd と所有者名が Warning のときは後段を検査しない
//! （`start` もそこで止まり、後段の結果は意味を持たないため）。
//!
//! # 構成と出力
//! - 事実の収集（[`collect`]。Linux のみ）と評価（[`evaluate`]。純粋関数で全 OS で単体テストできる）を分ける。
//! - 出力は `user_scope_check` と同じ JSON Lines（`severity`・`code`・`message`・`remediation`・`check`・`state`）。
//!   ユーザー名・uid・範囲の値・ファイルの内容・errno・パスなどホスト固有の値は載せない（SEC-5・REPAIR-4）。
//! - 終了ステータス: Warning（`start` が通らない前提の不成立）が 1 件でもあれば 3、そうでなく判定不能なら 4、
//!   それ以外は 0。1 対 1 写像になる設定（`SUBORDINATE_IDS_NOT_CONFIGURED`）と rootful で省いた通知は 0 に寄与する。
//!
//! # 未実装（REPAIR-3）
//! - `newuidmap` と `newgidmap` のどちらが欠けているかの個別の切り分け（core の `HelperPaths` が組で検証するため）。
//! - `/etc/nsswitch.conf` の `subid:` で範囲を NSS（libsubid・sssd・FreeIPA）から配る構成の検出（`start` も
//!   `/etc/subuid`・`/etc/subgid` のファイルだけを読む。#2390 の対象外）。
//!
//! # 所有者名の解決（#2390）
//! 名前は `start` と同じ `user_db::resolve_owner_name` で得る（passwd を先に読み、行が無いときだけ固定パスの
//! `getent` を期限つきで実行する）。`getent` が無い・信頼できないときは `SUBID_OWNER_LOOKUP_UNAVAILABLE`（通知）、
//! NSS の参照が失敗・期限切れのときは `SUBID_OWNER_LOOKUP_FAILED`（Warning。`start` も拒否する）。

use super::user_scope_check::PrivilegeState;
use super::{DoctorExitStatus, DoctorSeverity};
use crate::json::json_escape;

/// passwd から実効 uid の名前を得られたかの状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerState {
    /// 名前を得て、`SubIdOwner` の規則に適合する。
    Resolved,
    /// passwd にも NSS（`getent`）にも実効 uid の行が無い（数値 uid の行だけで照合する）。
    Unresolved,
    /// passwd に行が無く、信頼できる `getent` も無い（NSS を引けない。数値 uid の行だけで照合する）。
    LookupUnavailable,
    /// NSS の参照が失敗・期限切れ・不正な出力（`start` は拒否する）。
    LookupFailed,
    /// passwd が読めない・壊れている・上限超過。
    PasswdUnusable,
    /// 名前が `SubIdOwner` の規則（文字種・長さ）に違反する。
    InvalidName,
    /// 検査しなかった。
    NotChecked,
}

/// subuid / subgid 1 ファイルの状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubIdState {
    /// 自分の行がある。
    Assigned,
    /// ファイルが無い、または自分の行が無い。
    Unassigned,
    /// 読めない・書式不正・上限超過。
    Unusable,
    /// 検査しなかった。
    NotChecked,
}

/// 選ばれる ID 写像モデル（`start` の `select_rootless_id_model` の結果の写像）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelState {
    /// 範囲写像（`newuidmap` / `newgidmap` を使う）。
    Subordinate,
    /// 1 対 1 写像（設定の無いホストの従来挙動）。
    Single,
    /// subuid だけに自分の行がある（`start` は拒否する）。
    IncompleteSubuidOnly,
    /// subgid だけに自分の行がある（`start` は拒否する）。
    IncompleteSubgidOnly,
    /// real uid と effective uid が違う範囲写像（`start` は拒否する）。
    UidMismatch,
    /// 検査しなかった（前段が Warning・subuid / subgid が使えない等）。
    NotChecked,
}

/// subordinate 範囲を写像にできるかの状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeState {
    /// uid・gid とも core の `rootless_mapping` が受理する。
    Valid,
    /// 受理されない（ホスト ID 0 を含む・範囲の重なり等）。
    Invalid,
    /// 検査しなかった（範囲写像でない場合を含む）。
    NotChecked,
}

/// `newuidmap` / `newgidmap` の状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperState {
    /// 固定の位置にあり、信頼の基準を満たす。
    Trusted,
    /// 固定の位置に無い。
    NotFound,
    /// 見つかったが信頼の基準を満たさない（所有者・mode・通常ファイルでない・祖先・その他の検証失敗）。
    Untrusted,
    /// 検査しなかった（範囲写像でない場合を含む）。
    NotChecked,
}

/// 収集した事実。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdMappingFindings {
    /// 実行ユーザー（`Rootless` 以外では後段を検査しない）。
    pub privilege: PrivilegeState,
    /// 所有者名の状態。
    pub owner: OwnerState,
    /// `/etc/subuid` の状態。
    pub subuid: SubIdState,
    /// `/etc/subgid` の状態。
    pub subgid: SubIdState,
    /// 選ばれるモデル。
    pub model: ModelState,
    /// 範囲の検証。
    pub range: RangeState,
    /// helper の検証。
    pub helpers: HelperState,
}

impl IdMappingFindings {
    /// 後段をすべて検査しなかった事実（`privilege` だけを与える）。
    fn unchecked(privilege: PrivilegeState) -> Self {
        Self {
            privilege,
            owner: OwnerState::NotChecked,
            subuid: SubIdState::NotChecked,
            subgid: SubIdState::NotChecked,
            model: ModelState::NotChecked,
            range: RangeState::NotChecked,
            helpers: HelperState::NotChecked,
        }
    }
}

/// 結論。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdMappingOutcome {
    /// `start` が通る前提（通知のみを含む）。
    Ok,
    /// 前提が満たされない。
    Warning,
    /// 判定できなかった。
    Inconclusive,
    /// Linux 以外では対象外。
    NotApplicable,
}

/// 1 件の診断（`message` と `remediation` は英語の固定文言）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdMappingDiagnostic {
    /// 重大度。
    pub severity: DoctorSeverity,
    /// 機械可読なコード。
    pub code: &'static str,
    /// 説明（ホスト固有の値を載せない）。
    pub message: &'static str,
    /// 対処の案内。
    pub remediation: Vec<&'static str>,
    /// どの検査か（`privilege` / `passwd` / `subuid` / `subgid` / `id_model` / `id_map_helpers`）。
    pub check: &'static str,
    /// 状態のトークン。
    pub state: &'static str,
}

/// 評価結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdMappingReport {
    /// 結論。
    pub outcome: IdMappingOutcome,
    /// 診断。
    pub diagnostics: Vec<IdMappingDiagnostic>,
}

fn diag(
    severity: DoctorSeverity,
    code: &'static str,
    message: &'static str,
    remediation: Vec<&'static str>,
    check: &'static str,
    state: &'static str,
) -> IdMappingDiagnostic {
    IdMappingDiagnostic {
        severity,
        code,
        message,
        remediation,
        check,
        state,
    }
}

const SUBID_FILE_REMEDIATION: &str = "Make /etc/subuid and /etc/subgid readable, well-formed lines of the form name:start:count (for example by running usermod --add-subuids and --add-subgids as an administrator)";

/// 事実から診断を作る純粋関数（CORE-6・SEC-5）。
pub fn evaluate(f: &IdMappingFindings) -> IdMappingReport {
    use DoctorSeverity::{Notice, Warning};
    match f.privilege {
        PrivilegeState::Unsupported => {
            return IdMappingReport {
                outcome: IdMappingOutcome::NotApplicable,
                diagnostics: Vec::new(),
            };
        }
        PrivilegeState::Rootful => {
            return IdMappingReport {
                outcome: IdMappingOutcome::Ok,
                diagnostics: vec![diag(
                    Notice,
                    "ID_MAPPING_CHECK_SKIPPED_AS_ROOT",
                    "the subordinate id checks were skipped because this process runs as root; rootful start is not supported",
                    vec![
                        "Re-run fandhe-container doctor as the unprivileged user that starts containers",
                    ],
                    "privilege",
                    "rootful",
                )],
            };
        }
        PrivilegeState::Unreadable => {
            return IdMappingReport {
                outcome: IdMappingOutcome::Inconclusive,
                diagnostics: vec![diag(
                    Notice,
                    "ID_MAPPING_INCONCLUSIVE",
                    "the process status could not be read, so the subordinate id checks were skipped",
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
    match f.owner {
        OwnerState::PasswdUnusable => diagnostics.push(diag(
            Warning,
            "PASSWD_UNUSABLE",
            "/etc/passwd could not be read or is malformed, so the owner of the subordinate id ranges cannot be determined",
            vec!["Check that /etc/passwd is a readable, well-formed file of reasonable size"],
            "passwd",
            "unusable",
        )),
        OwnerState::InvalidName => diagnostics.push(diag(
            Warning,
            "SUBID_OWNER_NAME_INVALID",
            "the user name of this account cannot be used to match subordinate id lines (it must be 1 to 256 bytes with no colon, whitespace or control characters)",
            vec![
                "Use a user name of at most 256 bytes without colons, whitespace or control characters for the account that starts containers",
            ],
            "passwd",
            "invalid_name",
        )),
        OwnerState::Unresolved => diagnostics.push(diag(
            Notice,
            "SUBID_OWNER_NAME_UNRESOLVED",
            "no user name was found in /etc/passwd or the system user database for this uid; only subordinate id lines that use the numeric uid can match",
            vec![
                "Write the numeric uid, or the account name reported by getent passwd, in the first field of /etc/subuid and /etc/subgid",
            ],
            "passwd",
            "unresolved",
        )),
        OwnerState::LookupUnavailable => diagnostics.push(diag(
            Notice,
            "SUBID_OWNER_LOOKUP_UNAVAILABLE",
            "this uid is not in /etc/passwd and no trusted getent was found, so the system user database was not consulted; only subordinate id lines that use the numeric uid can match",
            vec![
                "Install getent as a root-owned file that group and other users cannot write, or write the numeric uid in the first field of /etc/subuid and /etc/subgid",
            ],
            "passwd",
            "lookup_unavailable",
        )),
        OwnerState::LookupFailed => diagnostics.push(diag(
            Warning,
            "SUBID_OWNER_LOOKUP_FAILED",
            "this uid is not in /etc/passwd and looking it up in the system user database failed or timed out; starting a container fails closed",
            vec![
                "Check that the directory service (LDAP, sssd) is reachable and that getent passwd returns this account, then re-run fandhe-container doctor",
            ],
            "passwd",
            "lookup_failed",
        )),
        OwnerState::Resolved | OwnerState::NotChecked => {}
    }
    for (state, code, check) in [
        (f.subuid, "SUBUID_UNUSABLE", "subuid"),
        (f.subgid, "SUBGID_UNUSABLE", "subgid"),
    ] {
        if state == SubIdState::Unusable {
            diagnostics.push(diag(
                Warning,
                code,
                "the subordinate id file could not be read or its line for this user is malformed; starting a container fails closed",
                vec![SUBID_FILE_REMEDIATION],
                check,
                "unusable",
            ));
        }
    }
    match f.model {
        ModelState::IncompleteSubuidOnly | ModelState::IncompleteSubgidOnly => {
            let state = if f.model == ModelState::IncompleteSubuidOnly {
                "subuid_only"
            } else {
                "subgid_only"
            };
            diagnostics.push(diag(
                Warning,
                "SUBORDINATE_IDS_INCOMPLETE",
                "only one of /etc/subuid and /etc/subgid has a line for this user; start refuses to fall back to a single id mapping",
                vec![
                    "Add a line for this user to both /etc/subuid and /etc/subgid, or remove it from both to use the single id mapping",
                ],
                "id_model",
                state,
            ));
        }
        ModelState::UidMismatch => diagnostics.push(diag(
            Warning,
            "SUBORDINATE_IDS_UID_MISMATCH",
            "the real uid and the effective uid differ, which the subordinate id mapping refuses",
            vec![
                "Run fandhe-container without setuid or su-style credential changes so that the real and effective uid are the same",
            ],
            "id_model",
            "uid_mismatch",
        )),
        ModelState::Single => diagnostics.push(diag(
            Notice,
            "SUBORDINATE_IDS_NOT_CONFIGURED",
            "no subordinate id lines exist for this user, so containers use the single id mapping (only one uid and gid inside the container)",
            vec![
                "To map a range of ids, add a line for this user to /etc/subuid and /etc/subgid and install the uidmap package that provides newuidmap and newgidmap",
            ],
            "id_model",
            "single_id",
        )),
        ModelState::Subordinate | ModelState::NotChecked => {}
    }
    if f.range == RangeState::Invalid {
        diagnostics.push(diag(
            Warning,
            "SUBORDINATE_ID_RANGE_INVALID",
            "the subordinate id ranges for this user cannot form an id mapping (for example a range that includes host id 0 or overlaps another)",
            vec![
                "Fix the lines for this user in /etc/subuid and /etc/subgid so that each range is non-overlapping and does not include id 0",
            ],
            "id_model",
            "range_invalid",
        ));
    }
    match f.helpers {
        HelperState::NotFound => diagnostics.push(diag(
            Warning,
            "ID_MAP_HELPER_NOT_FOUND",
            "newuidmap or newgidmap was not found at /usr/bin; a subordinate id mapping requires both",
            vec![
                "Install the uidmap package (shadow-utils on some distributions) so that /usr/bin/newuidmap and /usr/bin/newgidmap exist",
            ],
            "id_map_helpers",
            "not_found",
        )),
        HelperState::Untrusted => diagnostics.push(diag(
            Warning,
            "ID_MAP_HELPER_UNTRUSTED",
            "newuidmap or newgidmap failed the trust check (each must be a regular file owned by root and not writable by group or others, with the same condition on every parent directory)",
            vec![
                "Reinstall the uidmap package and make sure /usr/bin/newuidmap, /usr/bin/newgidmap and their parent directories are owned by root and not writable by group or others",
            ],
            "id_map_helpers",
            "untrusted",
        )),
        HelperState::Trusted | HelperState::NotChecked => {}
    }
    let outcome = if diagnostics.iter().any(|d| d.severity == Warning) {
        IdMappingOutcome::Warning
    } else {
        IdMappingOutcome::Ok
    };
    IdMappingReport {
        outcome,
        diagnostics,
    }
}

impl IdMappingReport {
    /// 結論に対応する終了ステータス。
    pub fn exit_status(&self) -> DoctorExitStatus {
        match self.outcome {
            IdMappingOutcome::Ok | IdMappingOutcome::NotApplicable => DoctorExitStatus::Ok,
            IdMappingOutcome::Warning => DoctorExitStatus::Warning,
            IdMappingOutcome::Inconclusive => DoctorExitStatus::Inconclusive,
        }
    }

    /// 診断を 1 件 1 行の JSON Lines で書き出す（`user_scope_check` と同じ形）。
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

/// 収集の入力元（試験では一時ディレクトリへ差し替える。CLI 引数としては受けない）。
#[cfg(target_os = "linux")]
pub struct IdMappingSources {
    /// passwd の位置。
    pub passwd: std::path::PathBuf,
    /// subuid の位置。
    pub subuid: std::path::PathBuf,
    /// subgid の位置。
    pub subgid: std::path::PathBuf,
    /// helper の位置（`None` なら固定の既定位置）。
    pub helpers: Option<(std::path::PathBuf, std::path::PathBuf)>,
    /// NSS（`getent`）の参照設定。本番は `UserDbLookup::system()`。
    pub lookup: fandhe_container_supervisor::user_db::UserDbLookup,
}

#[cfg(target_os = "linux")]
impl IdMappingSources {
    /// 本番の固定位置（`start` と同じ定数）。
    pub fn system() -> Self {
        use fandhe_container_supervisor::id_model::{SYSTEM_PASSWD, SYSTEM_SUBGID, SYSTEM_SUBUID};
        Self {
            passwd: SYSTEM_PASSWD.into(),
            subuid: SYSTEM_SUBUID.into(),
            subgid: SYSTEM_SUBGID.into(),
            helpers: None,
            lookup: fandhe_container_supervisor::user_db::UserDbLookup::system(),
        }
    }
}

/// 事実を集める（読み取りのみ）。非 Linux は対象外の値を返す。
#[cfg(target_os = "linux")]
pub fn collect() -> IdMappingFindings {
    let status = crate::user_scope::read_self_status();
    collect_with(status.as_deref(), &IdMappingSources::system())
}

/// `/proc/self/status` の本文と入力元から事実を集める（`start` の `resolve_launch_privilege` と同じ順序・同じ部品）。
#[cfg(target_os = "linux")]
pub fn collect_with(status_text: Option<&str>, sources: &IdMappingSources) -> IdMappingFindings {
    use fandhe_container_core::rootless::{
        HelperPaths, SubIdOwner, SubordinateRange, load_subordinate_ids, rootless_mapping,
    };
    use fandhe_container_core::traits::ErrorCode;
    use fandhe_container_supervisor::id_model::{
        RootlessIdModel, SubIdFileProbe, probe_sub_id_file, select_rootless_id_model,
    };
    use fandhe_container_supervisor::privilege::parse_proc_status;
    use fandhe_container_supervisor::user_db::{OwnerNameResolution, resolve_owner_name};

    let Some(Ok(snapshot)) = status_text.map(parse_proc_status) else {
        return IdMappingFindings::unchecked(PrivilegeState::Unreadable);
    };
    let uid = snapshot.uid;
    if [uid.real, uid.effective, uid.saved, uid.fs].contains(&0) {
        return IdMappingFindings::unchecked(PrivilegeState::Rootful);
    }
    let mut f = IdMappingFindings::unchecked(PrivilegeState::Rootless);
    let (real, effective) = (uid.real, uid.effective);
    let resolution = match resolve_owner_name(&sources.passwd, effective, &sources.lookup) {
        Ok(r) => r,
        // passwd の不具合と NSS の失敗は、`start` と同じ固定文言で見分ける。
        Err(e) if e.message() == "the passwd database is unusable" => {
            f.owner = OwnerState::PasswdUnusable;
            return f;
        }
        Err(_) => {
            f.owner = OwnerState::LookupFailed;
            return f;
        }
    };
    let (name, state) = match resolution {
        OwnerNameResolution::Resolved { name, .. } => (Some(name), OwnerState::Resolved),
        OwnerNameResolution::NotFound => (None, OwnerState::Unresolved),
        OwnerNameResolution::LookupUnavailable => (None, OwnerState::LookupUnavailable),
    };
    let Ok(owner) = SubIdOwner::new(effective, name) else {
        f.owner = OwnerState::InvalidName;
        return f;
    };
    f.owner = state;
    let (pu, pg) = (
        probe_sub_id_file(&sources.subuid, &owner),
        probe_sub_id_file(&sources.subgid, &owner),
    );
    let to_state = |p: SubIdFileProbe| match p {
        SubIdFileProbe::Assigned => SubIdState::Assigned,
        SubIdFileProbe::Absent | SubIdFileProbe::NoOwnerRows => SubIdState::Unassigned,
        SubIdFileProbe::Unusable => SubIdState::Unusable,
    };
    f.subuid = to_state(pu);
    f.subgid = to_state(pg);
    if pu == SubIdFileProbe::Unusable || pg == SubIdFileProbe::Unusable {
        return f;
    }
    f.model = match select_rootless_id_model(pu, pg, real, effective) {
        Ok(RootlessIdModel::SingleId) => ModelState::Single,
        Ok(RootlessIdModel::SubordinateIds) => ModelState::Subordinate,
        Err(_) => match (pu, pg) {
            (SubIdFileProbe::Assigned, SubIdFileProbe::Assigned) => ModelState::UidMismatch,
            (SubIdFileProbe::Assigned, _) => ModelState::IncompleteSubuidOnly,
            _ => ModelState::IncompleteSubgidOnly,
        },
    };
    if f.model != ModelState::Subordinate {
        return f;
    }
    // 範囲が写像にできるか（`start` の core の `resolve_privilege` と同じ `rootless_mapping`）。
    let mappable = |path: &std::path::Path, host_id: u32| {
        load_subordinate_ids(path, &owner)
            .and_then(|ranges: Vec<SubordinateRange>| rootless_mapping(host_id, &ranges))
            .is_ok()
    };
    f.range = if mappable(&sources.subuid, effective)
        && mappable(&sources.subgid, snapshot.gid.effective)
    {
        RangeState::Valid
    } else {
        RangeState::Invalid
    };
    let helpers = match &sources.helpers {
        Some((u, g)) => HelperPaths::new(u, g),
        None => HelperPaths::system_default(),
    };
    f.helpers = match helpers {
        Ok(_) => HelperState::Trusted,
        Err(e) if e.code == ErrorCode::NotFound => HelperState::NotFound,
        Err(_) => HelperState::Untrusted,
    };
    f
}

/// 非 Linux は対象外（rootless の範囲写像は Linux の機構。`start` の Linux 限定経路と揃える）。
#[cfg(not(target_os = "linux"))]
pub fn collect() -> IdMappingFindings {
    IdMappingFindings::unchecked(PrivilegeState::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> IdMappingFindings {
        IdMappingFindings {
            privilege: PrivilegeState::Rootless,
            owner: OwnerState::Resolved,
            subuid: SubIdState::Assigned,
            subgid: SubIdState::Assigned,
            model: ModelState::Subordinate,
            range: RangeState::Valid,
            helpers: HelperState::Trusted,
        }
    }

    fn codes(r: &IdMappingReport) -> Vec<&'static str> {
        r.diagnostics.iter().map(|d| d.code).collect()
    }

    /// CORE-6: 前提がそろった範囲写像は診断なしで 0。
    #[test]
    fn core6_all_prerequisites_met_is_silent() {
        let r = evaluate(&base());
        assert!(r.diagnostics.is_empty());
        assert_eq!(r.exit_status().code(), 0);
    }

    /// CORE-6: 1 対 1 写像になる設定は通知だけで 0。
    #[test]
    fn core6_single_mapping_is_a_notice() {
        let f = IdMappingFindings {
            subuid: SubIdState::Unassigned,
            subgid: SubIdState::Unassigned,
            model: ModelState::Single,
            range: RangeState::NotChecked,
            helpers: HelperState::NotChecked,
            ..base()
        };
        let r = evaluate(&f);
        assert_eq!(codes(&r), ["SUBORDINATE_IDS_NOT_CONFIGURED"]);
        assert_eq!(r.diagnostics[0].severity, DoctorSeverity::Notice);
        assert_eq!(r.diagnostics[0].check, "id_model");
        assert_eq!(r.diagnostics[0].state, "single_id");
        assert_eq!(r.exit_status().code(), 0);
    }

    /// SEC-5: 片側だけの設定・uid の食い違いは Warning（3）。
    #[test]
    fn sec5_incomplete_and_uid_mismatch_warn() {
        for (m, st) in [
            (ModelState::IncompleteSubuidOnly, "subuid_only"),
            (ModelState::IncompleteSubgidOnly, "subgid_only"),
        ] {
            let r = evaluate(&IdMappingFindings {
                model: m,
                range: RangeState::NotChecked,
                helpers: HelperState::NotChecked,
                ..base()
            });
            assert_eq!(codes(&r), ["SUBORDINATE_IDS_INCOMPLETE"]);
            assert_eq!(r.diagnostics[0].state, st);
            assert_eq!(r.exit_status().code(), 3);
        }
        let r = evaluate(&IdMappingFindings {
            model: ModelState::UidMismatch,
            ..base()
        });
        assert_eq!(codes(&r), ["SUBORDINATE_IDS_UID_MISMATCH"]);
        assert_eq!(r.exit_status().code(), 3);
    }

    /// SEC-5: 読めない subuid / subgid・passwd・所有者名・範囲は Warning。
    #[test]
    fn sec5_unusable_inputs_warn() {
        let r = evaluate(&IdMappingFindings {
            subuid: SubIdState::Unusable,
            subgid: SubIdState::Unusable,
            model: ModelState::NotChecked,
            ..base()
        });
        assert_eq!(codes(&r), ["SUBUID_UNUSABLE", "SUBGID_UNUSABLE"]);
        assert_eq!(r.diagnostics[0].check, "subuid");
        assert_eq!(r.diagnostics[1].check, "subgid");
        assert_eq!(r.exit_status().code(), 3);
        let r = evaluate(&IdMappingFindings {
            owner: OwnerState::PasswdUnusable,
            ..IdMappingFindings::unchecked(PrivilegeState::Rootless)
        });
        assert_eq!(codes(&r), ["PASSWD_UNUSABLE"]);
        assert_eq!(r.exit_status().code(), 3);
        let r = evaluate(&IdMappingFindings {
            owner: OwnerState::InvalidName,
            ..IdMappingFindings::unchecked(PrivilegeState::Rootless)
        });
        assert_eq!(codes(&r), ["SUBID_OWNER_NAME_INVALID"]);
        let r = evaluate(&IdMappingFindings {
            range: RangeState::Invalid,
            ..base()
        });
        assert_eq!(codes(&r), ["SUBORDINATE_ID_RANGE_INVALID"]);
        assert_eq!(r.exit_status().code(), 3);
    }

    /// 名前を引けない場合・NSS を引けない場合は通知で 0、NSS の失敗は Warning で 3。
    #[test]
    fn core6_nss_lookup_states() {
        let r = evaluate(&IdMappingFindings {
            owner: OwnerState::LookupUnavailable,
            ..base()
        });
        assert_eq!(codes(&r), ["SUBID_OWNER_LOOKUP_UNAVAILABLE"]);
        assert_eq!(r.diagnostics[0].severity, DoctorSeverity::Notice);
        assert_eq!(r.diagnostics[0].state, "lookup_unavailable");
        assert_eq!(r.exit_status().code(), 0);
        let r = evaluate(&IdMappingFindings {
            owner: OwnerState::LookupFailed,
            ..IdMappingFindings::unchecked(PrivilegeState::Rootless)
        });
        assert_eq!(codes(&r), ["SUBID_OWNER_LOOKUP_FAILED"]);
        assert_eq!(r.diagnostics[0].severity, DoctorSeverity::Warning);
        assert_eq!(r.diagnostics[0].state, "lookup_failed");
        assert_eq!(r.exit_status().code(), 3);
    }

    /// 名前を引けない場合は通知で 0。
    #[test]
    fn core6_unresolved_owner_name_is_a_notice() {
        let r = evaluate(&IdMappingFindings {
            owner: OwnerState::Unresolved,
            ..base()
        });
        assert_eq!(codes(&r), ["SUBID_OWNER_NAME_UNRESOLVED"]);
        assert_eq!(r.diagnostics[0].severity, DoctorSeverity::Notice);
        assert_eq!(r.exit_status().code(), 0);
    }

    /// CORE-6: helper の欠け・信頼不成立は Warning で、他の Warning と同時に出る。
    #[test]
    fn core6_helper_failures_warn_alongside_other_warnings() {
        let r = evaluate(&IdMappingFindings {
            helpers: HelperState::NotFound,
            ..base()
        });
        assert_eq!(codes(&r), ["ID_MAP_HELPER_NOT_FOUND"]);
        assert_eq!(r.diagnostics[0].check, "id_map_helpers");
        assert_eq!(r.exit_status().code(), 3);
        let r = evaluate(&IdMappingFindings {
            helpers: HelperState::Untrusted,
            range: RangeState::Invalid,
            ..base()
        });
        assert_eq!(
            codes(&r),
            ["SUBORDINATE_ID_RANGE_INVALID", "ID_MAP_HELPER_UNTRUSTED"]
        );
    }

    /// root・判定不能・対象外 OS の扱い（0 / 4 / 0）。
    #[test]
    fn core6_privilege_states() {
        let r = evaluate(&IdMappingFindings::unchecked(PrivilegeState::Rootful));
        assert_eq!(codes(&r), ["ID_MAPPING_CHECK_SKIPPED_AS_ROOT"]);
        assert_eq!(r.exit_status().code(), 0);
        let r = evaluate(&IdMappingFindings::unchecked(PrivilegeState::Unreadable));
        assert_eq!(codes(&r), ["ID_MAPPING_INCONCLUSIVE"]);
        assert_eq!(r.exit_status().code(), 4);
        let r = evaluate(&IdMappingFindings::unchecked(PrivilegeState::Unsupported));
        assert!(r.diagnostics.is_empty());
        assert_eq!(r.exit_status().code(), 0);
    }

    /// 出力は 1 行 1 JSON で、キーの並びが固定。
    #[test]
    fn core6_json_lines_shape() {
        let r = evaluate(&IdMappingFindings {
            helpers: HelperState::NotFound,
            ..base()
        });
        let mut buf = Vec::new();
        r.write_json_lines(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.starts_with(
            "{\"severity\":\"warning\",\"code\":\"ID_MAP_HELPER_NOT_FOUND\",\"message\":\""
        ));
        assert!(
            text.trim_end()
                .ends_with("\"check\":\"id_map_helpers\",\"state\":\"not_found\"}")
        );
        assert!(text.contains("\"remediation\":[\""));
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use fandhe_container_supervisor::id_model::{SubIdFileProbe, select_rootless_id_model};
        use fandhe_container_supervisor::user_db::UserDbLookup;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        use std::path::{Path, PathBuf};
        use std::time::Duration;

        struct Dir(PathBuf);
        impl Dir {
            fn new(tag: &str) -> Self {
                let d = std::env::temp_dir().join(format!(
                    "fc-idmap-{tag}-{}-{:?}",
                    std::process::id(),
                    std::thread::current().id()
                ));
                let _ = std::fs::remove_dir_all(&d);
                std::fs::create_dir_all(&d).unwrap();
                std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
                Self(d)
            }
            fn write(&self, name: &str, body: &str) -> PathBuf {
                let p = self.0.join(name);
                std::fs::write(&p, body).unwrap();
                p
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn status(real: u32, eff: u32) -> String {
            format!(
                "Name:\tx\nUid:\t{real}\t{eff}\t{eff}\t{eff}\nGid:\t1000\t1000\t1000\t1000\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nGroups:\t1000\n"
            )
        }

        const PASSWD: &str = "alice:x:1000:1000::/h:/bin/sh\n";

        fn sources(
            d: &Dir,
            passwd: &str,
            subuid: Option<&str>,
            subgid: Option<&str>,
        ) -> IdMappingSources {
            let missing = d.0.join("missing");
            IdMappingSources {
                passwd: d.write("passwd", passwd),
                subuid: subuid.map_or(missing.clone(), |b| d.write("subuid", b)),
                subgid: subgid.map_or(missing, |b| d.write("subgid", b)),
                // 利用者所有ファイル（祖先の一時ディレクトリが g/o 書き込み可なので必ず拒否される）。
                helpers: Some((d.write("newuidmap", ""), d.write("newgidmap", ""))),
                // 既定は候補なし（実機の NSS を引かない）。
                lookup: UserDbLookup::custom(Vec::new(), Duration::from_secs(5), None, d.0.clone()),
            }
        }

        fn run(d: &Dir, st: &str, s: &IdMappingSources) -> (IdMappingFindings, IdMappingReport) {
            let _ = d;
            let f = collect_with(Some(st), s);
            let r = evaluate(&f);
            (f, r)
        }

        const GOOD: &str = "alice:100000:65536\n";

        /// SEC-5: subuid だけ行がある → INCOMPLETE（start も拒否する）。
        #[test]
        fn sec5_subuid_only_is_incomplete_and_start_agrees() {
            let d = Dir::new("incomplete");
            let s = sources(&d, PASSWD, Some(GOOD), None);
            let (f, r) = run(&d, &status(1000, 1000), &s);
            assert_eq!(f.model, ModelState::IncompleteSubuidOnly);
            assert_eq!(codes(&r), ["SUBORDINATE_IDS_INCOMPLETE"]);
            assert_eq!(r.diagnostics[0].state, "subuid_only");
            assert_eq!(r.exit_status().code(), 3);
            assert!(
                select_rootless_id_model(
                    SubIdFileProbe::Assigned,
                    SubIdFileProbe::Absent,
                    1000,
                    1000
                )
                .is_err()
            );
        }

        /// SEC-5: 書式不正・ディレクトリは UNUSABLE。
        #[test]
        fn sec5_malformed_or_directory_subid_is_unusable() {
            let d = Dir::new("unusable");
            let mut s = sources(&d, PASSWD, Some(GOOD), Some("alice:bad\n"));
            let (_, r) = run(&d, &status(1000, 1000), &s);
            assert_eq!(codes(&r), ["SUBGID_UNUSABLE"]);
            s.subuid = d.0.clone();
            let (_, r) = run(&d, &status(1000, 1000), &s);
            assert_eq!(codes(&r), ["SUBUID_UNUSABLE", "SUBGID_UNUSABLE"]);
            assert_eq!(r.exit_status().code(), 3);
        }

        /// SEC-5: passwd の上限超過・UTF-8 不正は PASSWD_UNUSABLE で後段を検査しない。
        #[test]
        fn sec5_unusable_passwd_stops_later_checks() {
            let d = Dir::new("passwd");
            let big = "a".repeat(2 * 1024 * 1024);
            let s = sources(&d, &big, Some(GOOD), Some(GOOD));
            let (f, r) = run(&d, &status(1000, 1000), &s);
            assert_eq!(f.subuid, SubIdState::NotChecked);
            assert_eq!(codes(&r), ["PASSWD_UNUSABLE"]);
            assert_eq!(r.exit_status().code(), 3);
        }

        /// CORE-6: 両方無ければ 1 対 1 写像で helper は検査しない。
        #[test]
        fn core6_nothing_configured_is_single_and_skips_helpers() {
            let d = Dir::new("single");
            let s = sources(&d, PASSWD, None, None);
            let (f, r) = run(&d, &status(1000, 1000), &s);
            assert_eq!(f.helpers, HelperState::NotChecked);
            assert_eq!(codes(&r), ["SUBORDINATE_IDS_NOT_CONFIGURED"]);
            assert_eq!(r.exit_status().code(), 0);
        }

        /// 試験用の getent を置き、それを使う設定を返す。
        fn stub_lookup(d: &Dir, body: &str) -> UserDbLookup {
            let p = d.0.join("getent");
            let _ = std::fs::remove_file(&p);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            let euid = std::fs::metadata("/proc/self").unwrap().uid();
            UserDbLookup::custom(vec![p], Duration::from_secs(5), Some(euid), d.0.clone())
        }

        /// CORE-6・SEC-5(#2390): passwd に無い名前を NSS から得て、名前で書かれた行で範囲写像になる。
        /// NSS の失敗は LOOKUP_FAILED、getent が無ければ LOOKUP_UNAVAILABLE。
        #[test]
        fn core6_nss_name_resolves_named_subid_lines() {
            let d = Dir::new("nss");
            let mut s = sources(
                &d,
                "bob:x:2000:2000::/h:/bin/sh\n",
                Some("ldapuser:100000:65536\n"),
                Some("ldapuser:100000:65536\n"),
            );
            s.lookup = stub_lookup(&d, "echo 'ldapuser:*:1000:1000::/h:/bin/sh'");
            let (f, r) = run(&d, &status(1000, 1000), &s);
            assert_eq!(f.owner, OwnerState::Resolved);
            assert_eq!(f.model, ModelState::Subordinate);
            assert!(!codes(&r).contains(&"SUBID_OWNER_NAME_UNRESOLVED"));
            s.lookup = stub_lookup(&d, "exit 1");
            let (f, r) = run(&d, &status(1000, 1000), &s);
            assert_eq!(f.owner, OwnerState::LookupFailed);
            assert_eq!(f.subuid, SubIdState::NotChecked);
            assert_eq!(codes(&r), ["SUBID_OWNER_LOOKUP_FAILED"]);
            s.lookup = UserDbLookup::custom(Vec::new(), Duration::from_secs(5), None, d.0.clone());
            let (f, r) = run(&d, &status(1000, 1000), &s);
            assert_eq!(f.owner, OwnerState::LookupUnavailable);
            assert!(codes(&r).contains(&"SUBID_OWNER_LOOKUP_UNAVAILABLE"));
        }

        /// CORE-6: 名前を引けない（passwd にも NSS にも行が無い）場合は数値 uid の行で照合し、通知を出す。
        #[test]
        fn core6_numeric_uid_line_matches_without_passwd_name() {
            let d = Dir::new("numeric");
            let mut s = sources(
                &d,
                "bob:x:2000:2000::/h:/bin/sh\n",
                Some("1000:100000:65536\n"),
                Some("1000:100000:65536\n"),
            );
            s.lookup = stub_lookup(&d, "exit 2");
            let (f, r) = run(&d, &status(1000, 1000), &s);
            assert_eq!(f.owner, OwnerState::Unresolved);
            assert_eq!(f.model, ModelState::Subordinate);
            assert!(codes(&r).contains(&"SUBID_OWNER_NAME_UNRESOLVED"));
        }

        /// CORE-6: 範囲写像で helper が無い → NOT_FOUND、利用者所有 → UNTRUSTED。
        #[test]
        fn core6_helper_not_found_and_untrusted() {
            let d = Dir::new("helpers");
            let mut s = sources(&d, PASSWD, Some(GOOD), Some(GOOD));
            let (f, r) = run(&d, &status(1000, 1000), &s);
            assert_eq!(f.helpers, HelperState::Untrusted);
            assert_eq!(codes(&r), ["ID_MAP_HELPER_UNTRUSTED"]);
            assert_eq!(r.exit_status().code(), 3);
            s.helpers = Some((d.0.join("nouid"), d.0.join("nogid")));
            let (f, r) = run(&d, &status(1000, 1000), &s);
            assert_eq!(f.helpers, HelperState::NotFound);
            assert_eq!(codes(&r), ["ID_MAP_HELPER_NOT_FOUND"]);
        }

        /// SEC-5: ホスト ID 0 を含む範囲は RANGE_INVALID。
        #[test]
        fn sec5_range_with_host_id_zero_is_invalid() {
            let d = Dir::new("range");
            let s = sources(&d, PASSWD, Some("alice:0:65536\n"), Some(GOOD));
            let (f, r) = run(&d, &status(1000, 1000), &s);
            assert_eq!(f.range, RangeState::Invalid);
            assert!(codes(&r).contains(&"SUBORDINATE_ID_RANGE_INVALID"));
        }

        /// SEC-5: real と effective の uid が違う範囲写像は UID_MISMATCH。
        #[test]
        fn sec5_real_and_effective_uid_mismatch() {
            let d = Dir::new("mismatch");
            let s = sources(&d, PASSWD, Some(GOOD), Some(GOOD));
            let (f, r) = run(&d, &status(1001, 1000), &s);
            assert_eq!(f.model, ModelState::UidMismatch);
            assert_eq!(codes(&r), ["SUBORDINATE_IDS_UID_MISMATCH"]);
        }

        /// root・解釈不能な status の扱い。
        #[test]
        fn core6_root_and_unparsable_status() {
            let d = Dir::new("priv");
            let s = sources(&d, PASSWD, Some(GOOD), Some(GOOD));
            let (_, r) = run(&d, &status(0, 0), &s);
            assert_eq!(codes(&r), ["ID_MAPPING_CHECK_SKIPPED_AS_ROOT"]);
            let (_, r) = run(&d, "garbage", &s);
            assert_eq!(codes(&r), ["ID_MAPPING_INCONCLUSIVE"]);
            assert_eq!(r.exit_status().code(), 4);
            let f = collect_with(None, &s);
            assert_eq!(f.privilege, PrivilegeState::Unreadable);
        }

        /// REPAIR-4・SEC-5: 出力にユーザー名・範囲の値・パスを載せない。
        #[test]
        fn sec5_output_has_no_host_specific_values() {
            let d = Dir::new("leak");
            let s = sources(
                &d,
                PASSWD,
                Some("alice:0:65536\n"),
                Some("alice:200000:77\n"),
            );
            let (_, r) = run(&d, &status(1000, 1000), &s);
            let mut buf = Vec::new();
            r.write_json_lines(&mut buf).unwrap();
            let text = String::from_utf8(buf).unwrap();
            assert!(!text.is_empty());
            for needle in ["alice", "65536", "200000", "fc-idmap", "1000"] {
                assert!(!text.contains(needle), "leaked {needle}");
            }
            let _ = Path::new("");
        }
    }
}
