//! 監査の記録を 100% 満たせない環境の判定と方針（SEC-4・TASK-41 追補・#2027。監査配送 6/6）。
//!
//! # 役割と呼び出し文脈
//!
//! 監査の配送は 2 層に分かれる（`docs/design/audit-delivery.md` 4 章・7 章。2026-10-15 採用・#2018）。
//!
//! - **確実な層**: seccomp の ERRNO 側の拒否を USER_NOTIF で supervisor が受けて記録する経路。記録先を作れない
//!   環境では起動を拒否する（fail-closed）。判定は supervisor の入口（`run_main`）が持ち、本モジュールの対象外
//! - **カーネル監査に頼る層**: `KILL_PROCESS` の `AUDIT_SECCOMP` と Landlock の `AUDIT_LANDLOCK_*`。記録を書くのは
//!   カーネルで、読み手は外部（auditd 等）。使えない環境では警告して起動を続け、縮退を 3 か所（inspect・構造化ログ・
//!   監査記録）に出す。厳格モード（[`AuditCoveragePolicy::Strict`]）では縮退を拒否する
//!
//! 本モジュールは後者の「縮退の判定」（[`assess`]）と「方針による拒否」（[`AuditCoverage::enforce`]）、観測値の
//! 読み取り（Linux 限定の [`KernelAuditProbe::read_host`]）を持つ。呼び出し元は core の本番 launcher
//! （`oci_runtime::launcher` の `launch_checked`。fork の前に評価・強制・記録する）と、supervisor の手順 4
//! （cgroup の追記より前の前倒し判定）。型と純関数は 3 OS で公開する（CLI-1）。
//!
//! # 契約と残余（REPAIR-3: 実装済みを装わない）
//!
//! - [`KernelAuditLayerStatus::Requested`] は「観測できる範囲に否定する証拠が無く、記録を要求した」だけを意味する。
//!   ホストの `audit_enabled` の実行時の値と、外部の読み手がいるかは**非特権では確かめられない**（`AUDIT_GET` は
//!   `CAP_AUDIT_CONTROL` / `CAP_AUDIT_READ` が要り、要求しない）ため判定に使わない。「記録された」とは書かない
//! - 観測は固定の 3 点に限る: `/proc/sys/kernel/seccomp/actions_logged`（`kill_process` を含むか）、`/proc/cmdline`
//!   の `audit=0` 系、`/proc/self/loginuid` の有無（`CONFIG_AUDIT` を持つカーネルだけが作る）。読めなかった観測は
//!   [`KernelAuditLayerStatus::Unknown`] とし、縮退と同じに扱う
//! - 出力（診断行・監査記録・inspect・`state.json`）は固定語彙と数値だけで、`/proc/cmdline` などホスト由来の
//!   文字列は転記しない（ログ注入の余地を作らない）

use std::fmt;
use std::str::FromStr;

use crate::audit_log::AuditReason;
use crate::launch_isolation::RecordedLandlockAudit;
use crate::traits::{ErrorCode, TraitError};

/// 厳格モードで縮退を理由に起動を拒否するときの固定文言（値を含めない）。
pub const AUDIT_COVERAGE_STRICT_REFUSAL: &str =
    "audit coverage is degraded and the strict audit policy refuses to start";

/// 監査の縮退への方針。既定は [`Self::BestEffort`]（警告して起動を続ける）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AuditCoveragePolicy {
    /// カーネル監査頼みの層が縮退していても警告して起動を続ける（既定）。
    #[default]
    BestEffort,
    /// 縮退（調べられなかった場合を含む）があれば起動を拒否する。opt-in。
    Strict,
}

impl AuditCoveragePolicy {
    /// 機械可読な固定語彙（argv・`state.json`・inspect で共通）。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BestEffort => "best-effort",
            Self::Strict => "strict",
        }
    }
}

impl FromStr for AuditCoveragePolicy {
    type Err = TraitError;

    /// 固定語彙だけを受ける。未知の値は `InvalidArgument`（入力値はメッセージに含めない）。
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "best-effort" => Ok(Self::BestEffort),
            "strict" => Ok(Self::Strict),
            _ => Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "the audit policy must be best-effort or strict",
            )),
        }
    }
}

/// 縮退（または調べられなかったこと）の理由。固定語彙で、ホスト由来の文字列を持たない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DegradeReason {
    /// カーネルが監査を持たない（`/proc/self/loginuid` が無い。`CONFIG_AUDIT` なし）。
    KernelAuditNotBuilt,
    /// 起動引数 `audit=0` 系で監査が無効（後から有効にできない）。
    KernelAuditDisabledAtBoot,
    /// `actions_logged` に `kill_process` が無く、`KILL_PROCESS` の `AUDIT_SECCOMP` が出ない。
    SeccompKillNotLogged,
    /// Landlock ABI が 7 未満でログ制御フラグを渡せない（#2026 の語彙）。
    LandlockAuditAbiTooOld,
    /// 観測値を読めなかった（上限超過・読み取り失敗を含む）。
    ProbeFailed,
}

impl DegradeReason {
    /// 固定トークン。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KernelAuditNotBuilt => "kernel_audit_not_built",
            Self::KernelAuditDisabledAtBoot => "kernel_audit_disabled_at_boot",
            Self::SeccompKillNotLogged => "seccomp_kill_not_logged",
            Self::LandlockAuditAbiTooOld => "landlock_audit_abi_too_old",
            Self::ProbeFailed => "probe_failed",
        }
    }

    /// 監査レコードに載せる理由トークン。
    pub(crate) const fn audit_reason(self) -> AuditReason {
        AuditReason::new(self.as_str())
    }

    /// 固定トークンから戻す（`state.json` の読み戻し用。未知は `None`）。
    pub fn from_token(token: &str) -> Option<Self> {
        [
            Self::KernelAuditNotBuilt,
            Self::KernelAuditDisabledAtBoot,
            Self::SeccompKillNotLogged,
            Self::LandlockAuditAbiTooOld,
            Self::ProbeFailed,
        ]
        .into_iter()
        .find(|r| r.as_str() == token)
    }
}

/// 縮退の判定対象の層。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageLayer {
    /// `KILL_PROCESS` の `AUDIT_SECCOMP`。
    SeccompKill,
    /// Landlock の `AUDIT_LANDLOCK_*`。
    Landlock,
}

impl CoverageLayer {
    /// その層で起こりうる縮退の理由か（`state.json` の読み戻しで矛盾する値を拒否する）。
    fn allows(self, reason: DegradeReason) -> bool {
        use DegradeReason::*;
        match self {
            Self::SeccompKill => matches!(
                reason,
                KernelAuditNotBuilt | KernelAuditDisabledAtBoot | SeccompKillNotLogged
            ),
            Self::Landlock => matches!(
                reason,
                KernelAuditNotBuilt | KernelAuditDisabledAtBoot | LandlockAuditAbiTooOld
            ),
        }
    }
}

/// カーネル監査頼みの層 1 つの状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KernelAuditLayerStatus {
    /// 観測できる範囲に否定する証拠が無く、記録を要求した（実際の記録は保証しない。モジュール doc の契約）。
    Requested,
    /// 縮退の証拠がある。
    Degraded(DegradeReason),
    /// 調べられなかった（[`DegradeReason::ProbeFailed`]）。縮退と同じに扱う。
    Unknown,
}

impl KernelAuditLayerStatus {
    /// 縮退または不明か。
    pub const fn is_degraded(self) -> bool {
        !matches!(self, Self::Requested)
    }

    /// 理由（`Requested` は `None`）。
    pub const fn reason(self) -> Option<DegradeReason> {
        match self {
            Self::Requested => None,
            Self::Degraded(r) => Some(r),
            Self::Unknown => Some(DegradeReason::ProbeFailed),
        }
    }

    /// 機械可読なモード語彙（`state.json`・inspect 共通）。
    pub const fn mode(self) -> &'static str {
        match self {
            Self::Requested => "kernel_audit_requested",
            Self::Degraded(_) => "degraded",
            Self::Unknown => "unknown",
        }
    }

    /// `state.json` の `(mode, reason)` から戻す（untrusted。未知の語彙・層と矛盾する理由は `Err`）。
    pub fn from_wire(layer: CoverageLayer, mode: &str, reason: Option<&str>) -> Option<Self> {
        match (mode, reason) {
            ("kernel_audit_requested", None) => Some(Self::Requested),
            ("unknown", Some("probe_failed")) => Some(Self::Unknown),
            ("degraded", Some(token)) => {
                let r = DegradeReason::from_token(token)?;
                layer.allows(r).then_some(Self::Degraded(r))
            }
            _ => None,
        }
    }
}

/// 監査の網羅の評価結果（カーネル監査頼みの 2 層）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditCoverage {
    seccomp_kill: KernelAuditLayerStatus,
    landlock: KernelAuditLayerStatus,
}

impl AuditCoverage {
    /// 2 層の状態から作る。
    pub const fn new(
        seccomp_kill: KernelAuditLayerStatus,
        landlock: KernelAuditLayerStatus,
    ) -> Self {
        Self {
            seccomp_kill,
            landlock,
        }
    }

    /// `KILL_PROCESS` の `AUDIT_SECCOMP` の状態。
    pub const fn seccomp_kill(&self) -> KernelAuditLayerStatus {
        self.seccomp_kill
    }

    /// Landlock の `AUDIT_LANDLOCK_*` の状態。
    pub const fn landlock(&self) -> KernelAuditLayerStatus {
        self.landlock
    }

    /// どちらかの層が縮退または不明か。
    pub const fn is_degraded(&self) -> bool {
        self.seccomp_kill.is_degraded() || self.landlock.is_degraded()
    }

    /// 縮退を示す構造化ログ 1 行（固定語彙のみ。縮退が無ければ `None`）。
    pub fn log_line(&self) -> Option<String> {
        if !self.is_degraded() {
            return None;
        }
        let token = |s: KernelAuditLayerStatus| s.reason().map_or("requested", |r| r.as_str());
        Some(format!(
            r#"{{"component":"core.audit","operation":"audit_coverage","outcome":"degraded","seccomp_kill":"{}","landlock":"{}"}}"#,
            token(self.seccomp_kill),
            token(self.landlock),
        ))
    }

    /// 方針による拒否。厳格モードで縮退があれば `FailedPrecondition`（固定文言。値を含めない）。
    pub fn enforce(&self, policy: AuditCoveragePolicy) -> Result<(), TraitError> {
        match policy {
            AuditCoveragePolicy::Strict if self.is_degraded() => Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                AUDIT_COVERAGE_STRICT_REFUSAL,
            )),
            _ => Ok(()),
        }
    }

    /// 縮退を監査記録へ載せるイベント（縮退が無ければ `None`）。
    pub fn degraded_event(&self) -> Option<crate::audit_log::AuditEvent> {
        self.is_degraded()
            .then(|| crate::audit_log::AuditEvent::AuditCoverageDegraded {
                seccomp_kill: self.seccomp_kill.reason().map(DegradeReason::audit_reason),
                landlock: self.landlock.reason().map(DegradeReason::audit_reason),
            })
    }
}

/// ホストのカーネル監査まわりの観測値(読めなかったものは `None`)。
///
/// 値を持たせるだけの素の構造体で、試験は fixture から作る。Linux では `Self::read_host` が procfs から読む。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KernelAuditProbe {
    /// `/proc/sys/kernel/seccomp/actions_logged` の内容(空白区切りの語彙)。
    pub actions_logged: Option<String>,
    /// 起動引数が監査を無効にしているか(`audit=0` 系)。
    pub audit_disabled_at_boot: Option<bool>,
    /// `/proc/self/loginuid` があるか(`CONFIG_AUDIT` を持つカーネルの印)。
    pub loginuid_present: Option<bool>,
}

impl KernelAuditProbe {
    /// 起動引数(`/proc/cmdline` の内容)が監査を無効にしているかを判定する(純関数)。
    ///
    /// カーネルの `audit=` は最後の指定が効き、数値として 0 になる値(`0`・`off` など数字で始まらない値)で無効になる。
    /// 判定が曖昧な値(`0x` 始まり)は無効とみなさない(誤って縮退と判定しない)。
    pub fn cmdline_disables_audit(cmdline: &str) -> bool {
        let Some(value) = cmdline
            .split_whitespace()
            .filter_map(|t| t.strip_prefix("audit="))
            .next_back()
        else {
            return false;
        };
        if value.starts_with("0x") || value.starts_with("0X") {
            return false;
        }
        match value.chars().next() {
            None => true,
            Some(c) if c.is_ascii_digit() => value.chars().all(|c| c == '0'),
            Some('+') | Some('-') => value[1..].chars().all(|c| c == '0'),
            Some(_) => true,
        }
    }

    /// 全項目が揃い、否定する証拠が無い観測値(試験の対照用)。
    pub fn all_clear() -> Self {
        Self {
            actions_logged: Some(
                "kill_process kill_thread trap errno user_notif trace log".to_owned(),
            ),
            audit_disabled_at_boot: Some(false),
            loginuid_present: Some(true),
        }
    }
}

/// procfs の観測値の読み取り上限(確保の上限。超えたら読めなかったものとして扱う)。
#[cfg(target_os = "linux")]
const PROBE_READ_LIMIT: u64 = 4096;

#[cfg(target_os = "linux")]
fn read_limited(path: &str) -> Option<String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    // 上限 + 1 バイトまで読み、超えたら破棄する(無制限確保の防止)。
    file.take(PROBE_READ_LIMIT + 1).read_to_end(&mut buf).ok()?;
    if buf.len() as u64 > PROBE_READ_LIMIT {
        return None;
    }
    String::from_utf8(buf).ok()
}

#[cfg(target_os = "linux")]
impl KernelAuditProbe {
    /// procfs から観測値を読む(特権も `unsafe` も要らない。各ファイルは 4 KiB まで)。Linux 限定。
    ///
    /// 呼び出し元: core の launcher(`RealOps::kernel_audit_probe`)と supervisor の手順 4 の前倒し判定。
    pub fn read_host() -> Self {
        Self {
            actions_logged: read_limited("/proc/sys/kernel/seccomp/actions_logged"),
            audit_disabled_at_boot: read_limited("/proc/cmdline")
                .map(|c| Self::cmdline_disables_audit(&c)),
            // 存在だけを見る(中身は読まない)。EACCES など存在を判断できない失敗は不明にする。
            loginuid_present: match std::fs::metadata("/proc/self/loginuid") {
                Ok(_) => Some(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
                Err(_) => None,
            },
        }
    }
}

/// 観測値と Landlock の記録から、カーネル監査頼みの 2 層の網羅を評価する(純関数)。
///
/// 判定順は、証拠のある縮退を先に、観測できなかった項目があれば `Unknown`、それ以外は `Requested`。
/// Landlock の `NotRecorded`(記録の欠落)は縮退として扱う(「監査あり」と解釈しない)。
pub fn assess(probe: &KernelAuditProbe, landlock: RecordedLandlockAudit) -> AuditCoverage {
    use DegradeReason::*;
    let host_reason = if probe.loginuid_present == Some(false) {
        Some(KernelAuditNotBuilt)
    } else if probe.audit_disabled_at_boot == Some(true) {
        Some(KernelAuditDisabledAtBoot)
    } else {
        None
    };
    let host_unknown = probe.loginuid_present.is_none() || probe.audit_disabled_at_boot.is_none();

    let seccomp_kill = if let Some(r) = host_reason {
        KernelAuditLayerStatus::Degraded(r)
    } else {
        match probe.actions_logged.as_deref() {
            Some(list) if !list.split_whitespace().any(|a| a == "kill_process") => {
                KernelAuditLayerStatus::Degraded(SeccompKillNotLogged)
            }
            Some(_) if !host_unknown => KernelAuditLayerStatus::Requested,
            _ => KernelAuditLayerStatus::Unknown,
        }
    };

    let landlock = match landlock {
        RecordedLandlockAudit::Unavailable { .. } => {
            KernelAuditLayerStatus::Degraded(LandlockAuditAbiTooOld)
        }
        // 記録が無い値は要求した証拠が無い。
        RecordedLandlockAudit::NotRecorded => KernelAuditLayerStatus::Unknown,
        _ => match host_reason {
            Some(r) => KernelAuditLayerStatus::Degraded(r),
            None if host_unknown => KernelAuditLayerStatus::Unknown,
            None => KernelAuditLayerStatus::Requested,
        },
    };
    AuditCoverage::new(seccomp_kill, landlock)
}

impl fmt::Display for AuditCoveragePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use DegradeReason::*;

    const ABI7: RecordedLandlockAudit = RecordedLandlockAudit::KernelAuditRequested;
    const ABI6: RecordedLandlockAudit = RecordedLandlockAudit::Unavailable { detected_abi: 6 };

    /// SEC-4・#2027: 全項目が揃ったプローブと ABI 7 なら 2 層とも `Requested` で、縮退の行も出ない。
    #[test]
    fn sec4_2027_assess_all_clear_is_requested() {
        let c = assess(&KernelAuditProbe::all_clear(), ABI7);
        assert_eq!(c.seccomp_kill(), KernelAuditLayerStatus::Requested);
        assert_eq!(c.landlock(), KernelAuditLayerStatus::Requested);
        assert!(!c.is_degraded());
        assert_eq!(c.log_line(), None);
        assert_eq!(c.degraded_event(), None);
    }

    /// SEC-4・#2027: 各理由への写像(表駆動)。
    #[test]
    fn sec4_2027_assess_maps_each_reason() {
        let mut p = KernelAuditProbe::all_clear();
        p.actions_logged = Some("kill_thread trap errno".to_owned());
        let c = assess(&p, ABI6);
        assert_eq!(
            c.seccomp_kill(),
            KernelAuditLayerStatus::Degraded(SeccompKillNotLogged)
        );
        assert_eq!(
            c.landlock(),
            KernelAuditLayerStatus::Degraded(LandlockAuditAbiTooOld)
        );
        // `kill_process` を `kill_process_x` と取り違えない(語単位で照合する)。
        p.actions_logged = Some("kill_process_x errno".to_owned());
        assert_eq!(
            assess(&p, ABI7).seccomp_kill(),
            KernelAuditLayerStatus::Degraded(SeccompKillNotLogged)
        );
        let mut p = KernelAuditProbe::all_clear();
        p.loginuid_present = Some(false);
        let c = assess(&p, ABI7);
        assert_eq!(
            c.seccomp_kill(),
            KernelAuditLayerStatus::Degraded(KernelAuditNotBuilt)
        );
        assert_eq!(
            c.landlock(),
            KernelAuditLayerStatus::Degraded(KernelAuditNotBuilt)
        );
        let mut p = KernelAuditProbe::all_clear();
        p.audit_disabled_at_boot = Some(true);
        let c = assess(&p, ABI7);
        assert_eq!(
            c.seccomp_kill(),
            KernelAuditLayerStatus::Degraded(KernelAuditDisabledAtBoot)
        );
        // ABI が古ければ、ホストの理由より Landlock の ABI を先に報告する。
        assert_eq!(
            assess(&p, ABI6).landlock(),
            KernelAuditLayerStatus::Degraded(LandlockAuditAbiTooOld)
        );
    }

    /// SEC-4・#2027: 観測できなかった項目は `Unknown` で、縮退と同じに扱う。証拠のある縮退は不明より優先する。
    #[test]
    fn sec4_2027_assess_unreadable_probe_is_unknown() {
        let c = assess(&KernelAuditProbe::default(), ABI7);
        assert_eq!(c.seccomp_kill(), KernelAuditLayerStatus::Unknown);
        assert_eq!(c.landlock(), KernelAuditLayerStatus::Unknown);
        assert!(c.is_degraded());
        let mut p = KernelAuditProbe::all_clear();
        p.actions_logged = None;
        let c = assess(&p, ABI7);
        assert_eq!(c.seccomp_kill(), KernelAuditLayerStatus::Unknown);
        assert_eq!(c.landlock(), KernelAuditLayerStatus::Requested);
        assert_eq!(
            assess(
                &KernelAuditProbe::all_clear(),
                RecordedLandlockAudit::NotRecorded
            )
            .landlock(),
            KernelAuditLayerStatus::Unknown
        );
        let p = KernelAuditProbe {
            actions_logged: Some("errno".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            assess(&p, ABI7).seccomp_kill(),
            KernelAuditLayerStatus::Degraded(SeccompKillNotLogged)
        );
    }

    /// SEC-4・#2027: 構造化ログの 1 行は固定語彙で完全一致する。
    #[test]
    fn sec4_2027_log_line_is_exact() {
        let mut p = KernelAuditProbe::all_clear();
        p.actions_logged = Some("kill_thread trap errno".to_owned());
        let c = assess(&p, ABI6);
        assert_eq!(
            c.log_line().unwrap(),
            r#"{"component":"core.audit","operation":"audit_coverage","outcome":"degraded","seccomp_kill":"seccomp_kill_not_logged","landlock":"landlock_audit_abi_too_old"}"#
        );
        let c = assess(&KernelAuditProbe::all_clear(), ABI6);
        assert_eq!(
            c.log_line().unwrap(),
            r#"{"component":"core.audit","operation":"audit_coverage","outcome":"degraded","seccomp_kill":"requested","landlock":"landlock_audit_abi_too_old"}"#
        );
    }

    /// SEC-4・#2027: 厳格モードだけが縮退を固定文言で拒否する。
    #[test]
    fn sec4_2027_enforce_refuses_only_in_strict() {
        let degraded = assess(&KernelAuditProbe::all_clear(), ABI6);
        assert!(degraded.enforce(AuditCoveragePolicy::BestEffort).is_ok());
        let err = degraded.enforce(AuditCoveragePolicy::Strict).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "audit coverage is degraded and the strict audit policy refuses to start"
        );
        let clear = assess(&KernelAuditProbe::all_clear(), ABI7);
        assert!(clear.enforce(AuditCoveragePolicy::Strict).is_ok());
    }

    /// 方針の語彙は往復し、未知の値は `InvalidArgument`(入力値を含めない)。
    #[test]
    fn sec4_2027_policy_roundtrip_and_unknown() {
        for p in [AuditCoveragePolicy::BestEffort, AuditCoveragePolicy::Strict] {
            assert_eq!(p.as_str().parse::<AuditCoveragePolicy>().unwrap(), p);
        }
        assert_eq!(
            AuditCoveragePolicy::default(),
            AuditCoveragePolicy::BestEffort
        );
        let err = "STRICT".parse::<AuditCoveragePolicy>().unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(!err.message().contains("STRICT"));
    }

    /// `audit=` の解釈(最後の指定が効く。数字で始まらない値は 0 とみなす)。
    #[test]
    fn sec4_2027_cmdline_audit_parsing() {
        let dis = KernelAuditProbe::cmdline_disables_audit;
        assert!(dis("quiet audit=0 ro"));
        assert!(dis("audit=off"));
        assert!(dis("audit=1 audit=0"));
        assert!(!dis("audit=0 audit=1"));
        assert!(!dis("quiet ro"));
        assert!(!dis("audit=1"));
        assert!(!dis("audit=0x1"));
        assert!(!dis("noaudit=0 xaudit=0"));
    }

    /// `state.json` の語彙の往復と、矛盾する値の拒否。
    #[test]
    fn sec4_2027_wire_roundtrip_and_rejects_contradictions() {
        use CoverageLayer::*;
        for (layer, status) in [
            (SeccompKill, KernelAuditLayerStatus::Requested),
            (SeccompKill, KernelAuditLayerStatus::Unknown),
            (
                SeccompKill,
                KernelAuditLayerStatus::Degraded(SeccompKillNotLogged),
            ),
            (
                Landlock,
                KernelAuditLayerStatus::Degraded(LandlockAuditAbiTooOld),
            ),
            (
                Landlock,
                KernelAuditLayerStatus::Degraded(KernelAuditNotBuilt),
            ),
        ] {
            let back = KernelAuditLayerStatus::from_wire(
                layer,
                status.mode(),
                status.reason().map(DegradeReason::as_str),
            );
            assert_eq!(back, Some(status));
        }
        let bad = |l, m, r| KernelAuditLayerStatus::from_wire(l, m, r).is_none();
        assert!(bad(SeccompKill, "bogus", None));
        assert!(bad(SeccompKill, "degraded", None));
        assert!(bad(SeccompKill, "degraded", Some("bogus")));
        assert!(bad(SeccompKill, "degraded", Some("probe_failed")));
        assert!(bad(
            SeccompKill,
            "degraded",
            Some("landlock_audit_abi_too_old")
        ));
        assert!(bad(Landlock, "degraded", Some("seccomp_kill_not_logged")));
        assert!(bad(
            SeccompKill,
            "kernel_audit_requested",
            Some("probe_failed")
        ));
        assert!(bad(SeccompKill, "unknown", Some("kernel_audit_not_built")));
        assert!(bad(SeccompKill, "unknown", None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_2027_read_host_does_not_panic_and_is_bounded() {
        let p = KernelAuditProbe::read_host();
        if let Some(s) = &p.actions_logged {
            assert!(s.len() <= 4096);
        }
    }
}
