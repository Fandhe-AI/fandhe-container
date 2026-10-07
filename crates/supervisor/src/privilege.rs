//! 権限昇格の必要最小集合と検証ロジック（SUP-14・TASK-171.1.2・#858・MS-9）。
//!
//! # 役割
//! `sudo` + pty に頼らない権限分離（SUP-14）で、昇格後のプロセスが保持してよい capability を
//! 「必要最小の集合」に限定できていることを機械的に検証する純ロジックを置く。
//! 方式（特権ランチャー + ambient〔[`PrivilegeMethod::LauncherAmbient`]〕／setuid〔[`PrivilegeMethod::SetuidRoot`]〕）は
//! `docs/design/privilege-separation.md` で比較したドラフトで採否は未確定のため、型は方式非依存にしてある。
//! 本モジュールは syscall を一切呼ばず `unsafe` を含まないため、3 OS の CI で具体値照合できる。
//!
//! # 呼び出し文脈・契約
//! - 呼び出し元（予定）: 特権ランチャーが supervisor を exec する直前に `/proc/self/status` を読み、
//!   [`parse_proc_status`] → [`verify_elevation`] で縮退結果を確認する（設計書 5 章 4）
//! - [`runtime_required_capabilities`] はランタイム側が一時的に保持する権限であり、コンテナへ渡す
//!   OCI 既定集合（SEC-1）とは別物
//! - カーネル応答（`/proc/<pid>/status`）は外部入力として扱い、長さ・行数を先に検証し、`unwrap`・添字アクセスを使わない
//! - 検証は fail-closed。過剰権限・不足・`no_new_privs`・uid 0・ambient 不一致のいずれも `Ok` にしない。
//!   不足時に `sudo` へ黙ってフォールバックしない（設計書 6 章）
//!
//! # 未実装（REPAIR-3。承認待ち）
//! 実際に bounding 削除・`capset`・ambient 載せ・`setresuid`・fd 検証付き exec を行う経路は未実装で、
//! [`elevate`] は [`ErrorCode::Unimplemented`] を返す。方式（設計書 9 章）・新規 `unsafe`・crate 配置（同 8 章）の
//! ユーザー承認が未取得のため着手していない。承認後に [`plan_reduction`] の計画を実行する形で実装する。

use std::fmt;

use fandhe_container_core::capabilities::{Capability, CapabilitySet};
use fandhe_container_core::traits::{ErrorCode, TraitError};

/// `/proc/<pid>/status` として受け入れる最大バイト数（無制限確保の防止）。
pub const MAX_STATUS_BYTES: usize = 64 * 1024;
/// `/proc/<pid>/status` として受け入れる最大行数。
pub const MAX_STATUS_LINES: usize = 512;

/// 権限取得の方式（設計書 3・9 章。採否未確定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrivilegeMethod {
    /// 特権ランチャー + ambient capability（設計書の推奨案 (c)）。
    LauncherAmbient,
    /// setuid root バイナリ（設計書 (a)。xattr 非対応環境向けのフォールバック案）。
    SetuidRoot,
}

/// ランタイム側が昇格後に保持する必要最小の capability（設計書 4 章の棚卸し）。
///
/// 各要素の根拠（確認済み＝コード上の呼び出しを確認／想定＝設計書で未確認）:
/// - `CAP_SYS_ADMIN`: unshare・mount・pivot_root・netns bind（確認済み。UTS 単独は想定）
/// - `CAP_MKNOD`: デバイスノード作成（確認済み）
/// - `CAP_SETPCAP`: bounding set 削除（確認済み）
/// - `CAP_NET_ADMIN`: veth・bridge・nftables（確認済み）
/// - `CAP_AUDIT_WRITE`: 監査ログのカーネル監査フォールバック（SEC-4。確認済み）
/// - `CAP_DAC_OVERRIDE`: cgroup 書き込み（所有者 root 前提。委譲方式は未確認のため想定）
/// - `CAP_KILL`: 他 UID へのシグナル送信（想定）
///
/// 設計書が未確認とする `CAP_SYS_CHROOT` は最小側に倒して含めない。必要と判明した時点で設計書とともに追加する。
pub const RUNTIME_REQUIRED_CAPABILITIES: [Capability; 7] = [
    Capability::SysAdmin,
    Capability::Mknod,
    Capability::Setpcap,
    Capability::NetAdmin,
    Capability::AuditWrite,
    Capability::DacOverride,
    Capability::Kill,
];

/// [`RUNTIME_REQUIRED_CAPABILITIES`] を集合として返す。
pub fn runtime_required_capabilities() -> CapabilitySet {
    RUNTIME_REQUIRED_CAPABILITIES
        .iter()
        .fold(CapabilitySet::empty(), |s, c| s.with(*c))
}

/// 検証失敗の理由分類（機械可読）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrivilegeErrorReason {
    /// `no_new_privs` が立っており昇格できない。
    NoNewPrivsSet,
    /// 必要最小を超える capability を保持している（未知ビット含む）。
    ExcessCapabilities,
    /// 必要な capability が不足している（昇格手段が無い）。
    MissingCapabilities,
    /// uid 0 が残っている。
    UnexpectedRootUid,
    /// ambient / inheritable が期待と一致しない。
    AmbientMismatch,
    /// `/proc/<pid>/status` の形式不正・欠落・上限超過。
    MalformedStatus,
    /// 実適用経路が未実装。
    Unimplemented,
}

/// 権限昇格の検証・計画エラー（ERR-1 の `code` と英語 `message`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PrivilegeError {
    /// 機械可読なエラーコード。
    pub code: ErrorCode,
    /// 理由分類。
    pub reason: PrivilegeErrorReason,
    /// 人間向けの説明（英語）。
    pub message: String,
}

impl PrivilegeError {
    fn new(code: ErrorCode, reason: PrivilegeErrorReason, message: impl Into<String>) -> Self {
        Self {
            code,
            reason,
            message: message.into(),
        }
    }

    fn malformed(message: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::FailedPrecondition,
            PrivilegeErrorReason::MalformedStatus,
            message,
        )
    }
}

impl fmt::Display for PrivilegeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for PrivilegeError {}

impl From<PrivilegeError> for TraitError {
    fn from(e: PrivilegeError) -> Self {
        TraitError::new(e.code, e.message)
    }
}

/// capability のビットマスク（`/proc/<pid>/status` の 16 進値）。生値は公開しない。
///
/// 本 crate の [`Capability`] が知らない番号（41 以降）のビットも保持し、過剰権限判定で fail-closed に扱う。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapMask(u64);

impl CapMask {
    /// 集合からマスクを作る。
    pub fn from_set(set: CapabilitySet) -> Self {
        Self(
            set.iter()
                .fold(0u64, |acc, c| acc | (1u64 << u32::from(c.index()))),
        )
    }

    /// 16 進文字列（`0x` なし）から作る。空・非 16 進・64 bit 超過は `None`。
    fn parse_hex(s: &str) -> Option<Self> {
        if s.is_empty() {
            return None;
        }
        u64::from_str_radix(s, 16).ok().map(Self)
    }

    /// 本 crate が知る capability だけを集合として返す。
    pub fn known(self) -> CapabilitySet {
        Capability::ALL
            .iter()
            .filter(|c| self.0 & (1u64 << u32::from(c.index())) != 0)
            .fold(CapabilitySet::empty(), |s, c| s.with(*c))
    }

    /// 本 crate が知らない番号（41 以降）のビットを含むか。
    pub fn unknown_bits_present(self) -> bool {
        self.0 >> Capability::ALL.len() != 0
    }

    fn excess_over(self, allowed: CapMask) -> bool {
        self.0 & !allowed.0 != 0
    }

    fn is_superset_of(self, other: CapMask) -> bool {
        other.0 & !self.0 == 0
    }
}

/// uid の 4 つ組（real・effective・saved・fs）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UidSet {
    /// real uid。
    pub real: u32,
    /// effective uid。
    pub effective: u32,
    /// saved set-user-ID。
    pub saved: u32,
    /// filesystem uid。
    pub fs: u32,
}

impl UidSet {
    fn any_root(self) -> bool {
        self.real == 0 || self.effective == 0 || self.saved == 0 || self.fs == 0
    }
}

/// `/proc/<pid>/status` から取り出した資格情報のスナップショット。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CredentialSnapshot {
    /// `CapInh`。
    pub inheritable: CapMask,
    /// `CapPrm`。
    pub permitted: CapMask,
    /// `CapEff`。
    pub effective: CapMask,
    /// `CapBnd`。
    pub bounding: CapMask,
    /// `CapAmb`。
    pub ambient: CapMask,
    /// `NoNewPrivs`。
    pub no_new_privs: bool,
    /// `Uid`。
    pub uid: UidSet,
}

#[derive(Default)]
struct Fields {
    inh: Option<CapMask>,
    prm: Option<CapMask>,
    eff: Option<CapMask>,
    bnd: Option<CapMask>,
    amb: Option<CapMask>,
    nnp: Option<bool>,
    uid: Option<UidSet>,
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), PrivilegeError> {
    if slot.is_some() {
        return Err(PrivilegeError::malformed(format!(
            "duplicate field {name} in process status"
        )));
    }
    *slot = Some(value);
    Ok(())
}

fn parse_mask(value: &str, name: &str) -> Result<CapMask, PrivilegeError> {
    CapMask::parse_hex(value.trim()).ok_or_else(|| {
        PrivilegeError::malformed(format!("field {name} is not a 64-bit hexadecimal mask"))
    })
}

fn parse_uids(value: &str) -> Result<UidSet, PrivilegeError> {
    let bad = || PrivilegeError::malformed("field Uid must have four decimal u32 values");
    let mut it = value.split_whitespace();
    let mut next = || -> Result<u32, PrivilegeError> {
        it.next().ok_or_else(bad)?.parse::<u32>().map_err(|_| bad())
    };
    let uid = UidSet {
        real: next()?,
        effective: next()?,
        saved: next()?,
        fs: next()?,
    };
    if it.next().is_some() {
        return Err(bad());
    }
    Ok(uid)
}

/// `/proc/<pid>/status` の内容から資格情報を取り出す（純関数）。
///
/// 入力長・行数の上限超過、必須項目（`CapInh`・`CapPrm`・`CapEff`・`CapBnd`・`CapAmb`・`NoNewPrivs`・`Uid`）の
/// 欠落・重複、形式不正・桁あふれは [`ErrorCode::FailedPrecondition`]（`MalformedStatus`）。
/// `CapAmb`・`NoNewPrivs` を持たない古いカーネルは fail-closed に拒否する。
pub fn parse_proc_status(text: &str) -> Result<CredentialSnapshot, PrivilegeError> {
    if text.len() > MAX_STATUS_BYTES {
        return Err(PrivilegeError::malformed(
            "process status exceeds the size limit",
        ));
    }
    let mut f = Fields::default();
    for (n, line) in text.lines().enumerate() {
        if n >= MAX_STATUS_LINES {
            return Err(PrivilegeError::malformed(
                "process status exceeds the line limit",
            ));
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key {
            "CapInh" => set_once(&mut f.inh, parse_mask(value, key)?, key)?,
            "CapPrm" => set_once(&mut f.prm, parse_mask(value, key)?, key)?,
            "CapEff" => set_once(&mut f.eff, parse_mask(value, key)?, key)?,
            "CapBnd" => set_once(&mut f.bnd, parse_mask(value, key)?, key)?,
            "CapAmb" => set_once(&mut f.amb, parse_mask(value, key)?, key)?,
            "NoNewPrivs" => {
                let v = match value.trim() {
                    "0" => false,
                    "1" => true,
                    _ => {
                        return Err(PrivilegeError::malformed("field NoNewPrivs must be 0 or 1"));
                    }
                };
                set_once(&mut f.nnp, v, key)?;
            }
            "Uid" => set_once(&mut f.uid, parse_uids(value)?, key)?,
            _ => {}
        }
    }
    let missing = |name: &str| PrivilegeError::malformed(format!("missing field {name}"));
    Ok(CredentialSnapshot {
        inheritable: f.inh.ok_or_else(|| missing("CapInh"))?,
        permitted: f.prm.ok_or_else(|| missing("CapPrm"))?,
        effective: f.eff.ok_or_else(|| missing("CapEff"))?,
        bounding: f.bnd.ok_or_else(|| missing("CapBnd"))?,
        ambient: f.amb.ok_or_else(|| missing("CapAmb"))?,
        no_new_privs: f.nnp.ok_or_else(|| missing("NoNewPrivs"))?,
        uid: f.uid.ok_or_else(|| missing("Uid"))?,
    })
}

/// 昇格検証に成功した結果（将来の拡張に備えた構造体）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ElevationReport {
    /// 検証に用いた方式。
    pub method: PrivilegeMethod,
    /// 保持が確認できた capability（permitted。期待集合と一致する）。
    pub held: CapabilitySet,
    /// 確認時の uid。
    pub uid: UidSet,
}

fn denied(reason: PrivilegeErrorReason, message: &str) -> PrivilegeError {
    PrivilegeError::new(ErrorCode::PermissionDenied, reason, message)
}

/// 縮退後のスナップショットが期待集合ちょうどであることを fail-closed で検証する。
///
/// 判定順: `no_new_privs` → uid 0 残存 → 過剰（permitted・effective・bounding・inheritable・ambient。未知ビット含む）
/// → 不足（permitted・effective）→ ambient 一致（ambient == 期待、inheritable ⊇ ambient）。
/// ambient 一致は方式によらず要求する（設計書 5 章 4 は (c)(a) とも ambient へ載せるため）。
pub fn verify_elevation(
    snapshot: &CredentialSnapshot,
    expected: CapabilitySet,
    method: PrivilegeMethod,
) -> Result<ElevationReport, PrivilegeError> {
    let exp = CapMask::from_set(expected);
    if snapshot.no_new_privs {
        return Err(PrivilegeError::new(
            ErrorCode::FailedPrecondition,
            PrivilegeErrorReason::NoNewPrivsSet,
            "no_new_privs is set; privilege elevation is not possible",
        ));
    }
    if snapshot.uid.any_root() {
        return Err(denied(
            PrivilegeErrorReason::UnexpectedRootUid,
            "uid 0 remains after privilege reduction",
        ));
    }
    let excess = [
        snapshot.permitted,
        snapshot.effective,
        snapshot.bounding,
        snapshot.inheritable,
        snapshot.ambient,
    ]
    .iter()
    .any(|m| m.excess_over(exp));
    if excess {
        return Err(denied(
            PrivilegeErrorReason::ExcessCapabilities,
            "capabilities exceed the required minimum set",
        ));
    }
    if !snapshot.permitted.is_superset_of(exp) || !snapshot.effective.is_superset_of(exp) {
        return Err(denied(
            PrivilegeErrorReason::MissingCapabilities,
            "required capabilities are missing; no elevation mechanism is available",
        ));
    }
    if snapshot.ambient != exp || !snapshot.inheritable.is_superset_of(snapshot.ambient) {
        return Err(denied(
            PrivilegeErrorReason::AmbientMismatch,
            "ambient set does not match the required set or is not inheritable",
        ));
    }
    Ok(ElevationReport {
        method,
        held: snapshot.permitted.known(),
        uid: snapshot.uid,
    })
}

/// 縮退の計画（適用はしない。将来の syscall 経路が実行する入力）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReductionPlan {
    /// bounding set から落とす capability 番号（現在 bounding にあり期待集合外のもの。昇順）。
    pub bounding_drop: Vec<u8>,
    /// 設定する permitted。
    pub permitted: CapabilitySet,
    /// 設定する effective。
    pub effective: CapabilitySet,
    /// 設定する inheritable。
    pub inheritable: CapabilitySet,
    /// ambient に載せる集合。
    pub ambient: CapabilitySet,
}

/// 現在の資格情報から期待集合への縮退計画を算出する（純関数。何も適用しない）。
///
/// 期待集合が現在の permitted に含まれない場合は昇格手段が無いものとして `MissingCapabilities`。
pub fn plan_reduction(
    current: &CredentialSnapshot,
    expected: CapabilitySet,
) -> Result<ReductionPlan, PrivilegeError> {
    let exp = CapMask::from_set(expected);
    if !current.permitted.is_superset_of(exp) {
        return Err(denied(
            PrivilegeErrorReason::MissingCapabilities,
            "required capabilities are not in the permitted set",
        ));
    }
    let bounding_drop = (0u8..64)
        .filter(|i| {
            let bit = 1u64 << u32::from(*i);
            current.bounding.0 & bit != 0 && exp.0 & bit == 0
        })
        .collect();
    Ok(ReductionPlan {
        bounding_drop,
        permitted: expected,
        effective: expected,
        inheritable: expected,
        ambient: expected,
    })
}

/// 権限を実際に縮退・付与する入口（スタブ。実装済みを装わない）。
///
/// 未実装（REPAIR-3）。将来仕様（設計書 5 章）: bounding 縮小 → `capset` → ambient 載せ → 読み戻し検証
/// （[`verify_elevation`]）→ fd 検証付き exec。子の待機にはタイムアウトを設ける（REPAIR-5）。
/// 方式・`unsafe`・crate 配置の承認後に実装する（SUP-14・TASK-171.1.2 の残作業）。
pub fn elevate(_method: PrivilegeMethod) -> Result<ElevationReport, PrivilegeError> {
    Err(PrivilegeError::new(
        ErrorCode::Unimplemented,
        PrivilegeErrorReason::Unimplemented,
        "privilege elevation is not implemented",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: &str = "1000\t1000\t1000\t1000";
    const FULL: &str = "000001ffffffffff";

    fn status(
        inh: &str,
        prm: &str,
        eff: &str,
        bnd: &str,
        amb: &str,
        nnp: &str,
        uid: &str,
    ) -> String {
        format!(
            "Name:\tx\nUid:\t{uid}\nCapInh:\t{inh}\nCapPrm:\t{prm}\nCapEff:\t{eff}\nCapBnd:\t{bnd}\nCapAmb:\t{amb}\nNoNewPrivs:\t{nnp}\n"
        )
    }

    fn mask_hex() -> String {
        format!(
            "{:016x}",
            CapMask::from_set(runtime_required_capabilities()).0
        )
    }

    fn verify(t: &str) -> Result<ElevationReport, PrivilegeError> {
        verify_elevation(
            &parse_proc_status(t).unwrap(),
            runtime_required_capabilities(),
            PrivilegeMethod::SetuidRoot,
        )
    }

    #[test]
    fn sup14_task171_1_2_minimum_set_is_fixed() {
        let s = runtime_required_capabilities();
        assert_eq!(s.len(), 7);
        assert_eq!(mask_hex(), "0000000028201122");
        for c in [
            Capability::SysPtrace,
            Capability::SysModule,
            Capability::SysChroot,
        ] {
            assert!(!s.contains(c));
        }
    }

    #[test]
    fn sup14_task171_1_2_parse_and_verify_ok() {
        let m = mask_hex();
        let snap = parse_proc_status(&status(&m, &m, &m, &m, &m, "0", UID)).unwrap();
        assert_eq!(snap.uid.effective, 1000);
        let r = verify_elevation(
            &snap,
            runtime_required_capabilities(),
            PrivilegeMethod::LauncherAmbient,
        )
        .unwrap();
        assert_eq!(r.held, runtime_required_capabilities());
    }

    #[test]
    fn sup14_task171_1_2_verify_rejects() {
        let m = mask_hex();
        let e = verify(&status(&m, FULL, FULL, FULL, &m, "0", UID)).unwrap_err();
        assert_eq!(
            (e.code, e.reason),
            (
                ErrorCode::PermissionDenied,
                PrivilegeErrorReason::ExcessCapabilities
            )
        );
        let e = verify(&status(&m, &m, &m, "8000000000000000", &m, "0", UID)).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::ExcessCapabilities);
        let e = verify(&status("0", "0", "0", &m, "0", "0", UID)).unwrap_err();
        assert_eq!(
            (e.code, e.reason),
            (
                ErrorCode::PermissionDenied,
                PrivilegeErrorReason::MissingCapabilities
            )
        );
        let e = verify(&status(&m, &m, &m, &m, &m, "1", UID)).unwrap_err();
        assert_eq!(
            (e.code, e.reason),
            (
                ErrorCode::FailedPrecondition,
                PrivilegeErrorReason::NoNewPrivsSet
            )
        );
        let e = verify(&status(&m, &m, &m, &m, &m, "0", "1000\t0\t1000\t1000")).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::UnexpectedRootUid);
        let e = verify(&status(&m, &m, &m, &m, "0", "0", UID)).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::AmbientMismatch);
    }

    #[test]
    fn sup14_task171_1_2_parse_rejects_malformed() {
        let m = mask_hex();
        let ok = status(&m, &m, &m, &m, &m, "0", UID);
        assert!(parse_proc_status(&ok).is_ok());
        let cases = [
            ok.replace("CapAmb:\t", "Xx:\t"),
            format!("{ok}CapEff:\t{m}\n"),
            status("zz", &m, &m, &m, &m, "0", UID),
            status("1ffffffffffffffff", &m, &m, &m, &m, "0", UID),
            status("", &m, &m, &m, &m, "0", UID),
            status(&m, &m, &m, &m, &m, "2", UID),
            status(&m, &m, &m, &m, &m, "0", "1\t2\t3"),
            "x".repeat(MAX_STATUS_BYTES + 1),
            "a\n".repeat(MAX_STATUS_LINES + 1),
        ];
        for c in cases {
            let e = parse_proc_status(&c).unwrap_err();
            assert_eq!(e.code, ErrorCode::FailedPrecondition);
            assert_eq!(e.reason, PrivilegeErrorReason::MalformedStatus);
        }
    }

    #[test]
    fn sup14_task171_1_2_plan_reduction_values() {
        let exp = runtime_required_capabilities();
        let t = status("0", FULL, FULL, FULL, "0", "0", UID);
        let plan = plan_reduction(&parse_proc_status(&t).unwrap(), exp).unwrap();
        assert_eq!(plan.bounding_drop.len(), 41 - 7);
        assert_eq!(plan.bounding_drop.first(), Some(&0));
        assert!(!plan.bounding_drop.contains(&21));
        assert_eq!(plan.ambient, exp);
        let t = status("0", "0", "0", FULL, "0", "0", UID);
        let e = plan_reduction(&parse_proc_status(&t).unwrap(), exp).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::MissingCapabilities);
    }

    #[test]
    fn sup14_task171_1_2_elevate_is_stub() {
        let e = elevate(PrivilegeMethod::LauncherAmbient).unwrap_err();
        assert_eq!(e.code, ErrorCode::Unimplemented);
        assert_eq!(TraitError::from(e).code(), ErrorCode::Unimplemented);
    }

    #[test]
    fn sup14_task171_1_2_unknown_bits_detected() {
        assert!(
            CapMask::parse_hex("20000000000")
                .unwrap()
                .unknown_bits_present()
        );
        assert!(
            !CapMask::parse_hex("1ffffffffff")
                .unwrap()
                .unknown_bits_present()
        );
    }
}
