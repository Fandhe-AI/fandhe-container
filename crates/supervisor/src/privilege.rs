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
//! - 検証は fail-closed。過剰権限・不足・`no_new_privs`・uid 0・`PR_SET_KEEPCAPS` の残存 / 未確認・ambient 不一致の
//!   いずれも `Ok` にしない。keepcaps は `/proc/<pid>/status` に現れないため、呼び出し元が `prctl(PR_GET_KEEPCAPS)` で
//!   読み戻した値を [`KeepCapsState`] として渡す（読み戻し経路は syscall のため未実装。下記）
//!   不足時に `sudo` へ黙ってフォールバックしない（設計書 6 章）
//!
//! # 未実装（REPAIR-3。承認待ち）
//! 実際に bounding 削除・`capset`・ambient 載せ・`setresuid`・`PR_SET_KEEPCAPS` の設定 / 解除 / 読み戻し・
//! fd 検証付き exec を行う経路は未実装で、
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
    /// gid 0 または補助グループが残っている。
    UnexpectedGroups,
    /// `PR_SET_KEEPCAPS` が縮退後も残っている、または解除を読み戻しで確認できていない。
    KeepCapsRetained,
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
        // from_str_radix は先頭の `+` を受理するため、全文字が 16 進桁であることを先に確認する。
        if s.is_empty() || !s.chars().all(|c| c.is_ascii_hexdigit()) {
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

/// gid の 4 つ組（real・effective・saved・fs）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GidSet {
    /// real gid。
    pub real: u32,
    /// effective gid。
    pub effective: u32,
    /// saved set-group-ID。
    pub saved: u32,
    /// filesystem gid。
    pub fs: u32,
}

impl GidSet {
    fn any_root(self) -> bool {
        self.real == 0 || self.effective == 0 || self.saved == 0 || self.fs == 0
    }
}

/// `/proc/<pid>/status` から取り出した資格情報のスナップショット。
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// `Gid`。
    pub gid: GidSet,
    /// `Groups`（補助グループ。縮退後は空であることを要求する）。
    pub groups: Vec<u32>,
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
    gid: Option<GidSet>,
    groups: Option<Vec<u32>>,
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

fn parse_gids(value: &str) -> Result<GidSet, PrivilegeError> {
    let bad = || PrivilegeError::malformed("field Gid must have four decimal u32 values");
    let mut it = value.split_whitespace();
    let mut next = || -> Result<u32, PrivilegeError> {
        it.next().ok_or_else(bad)?.parse::<u32>().map_err(|_| bad())
    };
    let gid = GidSet {
        real: next()?,
        effective: next()?,
        saved: next()?,
        fs: next()?,
    };
    if it.next().is_some() {
        return Err(bad());
    }
    Ok(gid)
}

/// `Groups` 行（空も可）を取り出す。件数は入力長上限（`MAX_STATUS_BYTES`）で自然に抑えられる。
fn parse_groups(value: &str) -> Result<Vec<u32>, PrivilegeError> {
    value
        .split_whitespace()
        .map(|g| {
            g.parse::<u32>()
                .map_err(|_| PrivilegeError::malformed("field Groups must have decimal u32 values"))
        })
        .collect()
}

/// `/proc/<pid>/status` の内容から資格情報を取り出す（純関数）。
///
/// 入力長・行数の上限超過、必須項目（`CapInh`・`CapPrm`・`CapEff`・`CapBnd`・`CapAmb`・`NoNewPrivs`・`Uid`・`Gid`・`Groups`）の
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
            "Gid" => set_once(&mut f.gid, parse_gids(value)?, key)?,
            "Groups" => set_once(&mut f.groups, parse_groups(value)?, key)?,
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
        gid: f.gid.ok_or_else(|| missing("Gid"))?,
        groups: f.groups.ok_or_else(|| missing("Groups"))?,
    })
}

/// 縮退後の `PR_SET_KEEPCAPS`（securebits の `SECBIT_KEEP_CAPS`）の読み戻し結果。
///
/// `/proc/<pid>/status` には現れないため [`CredentialSnapshot`] とは別に渡す。将来の syscall 経路が
/// `prctl(PR_GET_KEEPCAPS)` の戻り値から作る（未実装。REPAIR-3）。読み戻しに失敗した・読み戻していない場合は
/// [`KeepCapsState::Unknown`] とし、[`verify_elevation`] はこれを成功にしない（fail-closed。設計書 5 章 4・6 章）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeepCapsState {
    /// 解除済み（`PR_GET_KEEPCAPS` が 0）。
    Cleared,
    /// 有効のまま（`PR_GET_KEEPCAPS` が 1）。以後の uid 遷移で permitted が保持されてしまう。
    Set,
    /// 読み戻せていない（読み戻し失敗を含む）。
    Unknown,
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
    /// 確認時の gid。
    pub gid: GidSet,
}

fn denied(reason: PrivilegeErrorReason, message: &str) -> PrivilegeError {
    PrivilegeError::new(ErrorCode::PermissionDenied, reason, message)
}

/// 縮退後のスナップショットが期待集合ちょうどであることを fail-closed で検証する。
///
/// 判定順: `no_new_privs` → uid 0 残存 → gid 0・補助グループ残存（補助グループは空のみ許可）→ `PR_SET_KEEPCAPS` の残存・未確認
/// → 過剰（permitted・effective・bounding・inheritable・ambient。未知ビット含む）
/// → 不足（permitted・effective・bounding）→ ambient 一致（ambient == 期待、inheritable ⊇ ambient）。
/// ambient 一致は方式によらず要求する（設計書 5 章 4 は (c)(a) とも ambient へ載せるため）。
///
/// `keep_caps` は縮退の全手順（[`ReductionPlan::steps`]）を終えた後に読み戻した値を渡す。
/// [`KeepCapsState::Cleared`] 以外は方式によらず拒否する（`Set` は `PermissionDenied`、`Unknown` は
/// `FailedPrecondition`。いずれも理由は `KeepCapsRetained`）。
pub fn verify_elevation(
    snapshot: &CredentialSnapshot,
    keep_caps: KeepCapsState,
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
    if snapshot.gid.any_root() || !snapshot.groups.is_empty() {
        return Err(denied(
            PrivilegeErrorReason::UnexpectedGroups,
            "gid 0 or supplementary groups remain after privilege reduction",
        ));
    }
    match keep_caps {
        KeepCapsState::Cleared => {}
        KeepCapsState::Set => {
            return Err(denied(
                PrivilegeErrorReason::KeepCapsRetained,
                "PR_SET_KEEPCAPS remains set after privilege reduction",
            ));
        }
        KeepCapsState::Unknown => {
            return Err(PrivilegeError::new(
                ErrorCode::FailedPrecondition,
                PrivilegeErrorReason::KeepCapsRetained,
                "PR_SET_KEEPCAPS state was not read back after privilege reduction",
            ));
        }
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
    // bounding が期待集合を欠くと、後から ambient / 再取得で必要 capability を保持できない（不足も拒否）。
    if !snapshot.permitted.is_superset_of(exp)
        || !snapshot.effective.is_superset_of(exp)
        || !snapshot.bounding.is_superset_of(exp)
    {
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
        gid: snapshot.gid,
    })
}

/// 縮退の計画（適用はしない。将来の syscall 経路が実行する入力）。
///
/// 適用順は [`ReductionPlan::steps`] が返す次の列で固定する（SUP-14）:
/// `clear_supplementary_groups`（`setgroups(0)`）→ `gid`（`setresgid`）→ `bounding_drop`（昇順・`CAP_SETPCAP` は最後）
/// → `PR_SET_KEEPCAPS` を 1 → `uid`（`setresuid`）→ `capset` → ambient 載せ → `PR_SET_KEEPCAPS` を 0。
///
/// UID 0 から非 0 へ変えると effective capability は失われる（`CAP_SETPCAP` を要する bounding 削除ができなくなる）ため、
/// bounding 削除は `setresuid` より前に終える。`setresuid` 後は permitted を `keepcaps` で保持し、`capset` で
/// effective・inheritable を期待集合へ再設定してから ambient を載せる。
///
/// `PR_SET_KEEPCAPS` の設定と解除は必ず対で計画する（[`ReductionPlan::keep_capabilities`]）。解除は設計書 5 章 4 の
/// とおり ambient を載せた後の最終手順とし、縮退後のプロセスに権限保持設定を残さない。適用側の契約（未実装。REPAIR-3）:
/// 解除の失敗は縮退全体の失敗として扱い exec しない（fail-closed。設計書 6 章）。解除後は `prctl(PR_GET_KEEPCAPS)` で
/// 読み戻し、[`KeepCapsState`] として [`verify_elevation`] へ渡す。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReductionPlan {
    /// bounding set から落とす capability 番号。現在 bounding にあり期待集合外のもの。
    /// bounding の削除自体に `CAP_SETPCAP` が要るため、含まれる場合は番号 8 を末尾に置き、昇順で並べる。
    pub bounding_drop: Vec<u8>,
    /// 設定する permitted。
    pub permitted: CapabilitySet,
    /// 設定する effective。
    pub effective: CapabilitySet,
    /// 設定する inheritable。
    pub inheritable: CapabilitySet,
    /// ambient に載せる集合。
    pub ambient: CapabilitySet,
    /// 補助グループを全消去する（`setgroups(0)` 相当。縮退後の `Groups` は空が要件）。
    pub clear_supplementary_groups: bool,
    /// 設定する gid（real・effective・saved・fs すべて非 0 の対象 gid。`setresgid` 相当）。
    pub gid: GidSet,
    /// 設定する uid（real・effective・saved・fs すべて非 0 の対象 uid。`setresuid` 相当）。
    pub uid: UidSet,
    /// `setresuid` をまたいで permitted を保持するため `PR_SET_KEEPCAPS` を使うか。現在の uid が対象と異なる
    /// （uid 遷移が起きる）ときだけ真。真なら [`ReductionStep::KeepCapabilities`] と
    /// [`ReductionStep::ClearKeepCapabilities`] を必ず対で手順に含める。
    pub keep_capabilities: bool,
}

/// 縮退計画の 1 手順（[`ReductionPlan::steps`] の要素。適用順は列の順）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReductionStep {
    /// `setgroups(0)`（`CAP_SETGID` を要する）。
    ClearSupplementaryGroups,
    /// `setresgid`（`CAP_SETGID` を要する）。
    SetGid,
    /// bounding set からの削除（`CAP_SETPCAP` を要する。uid 変更前に行う）。
    DropBounding,
    /// `prctl(PR_SET_KEEPCAPS, 1)`。`setresuid` 後も permitted を保持する。
    /// 必ず [`ReductionStep::ClearKeepCapabilities`] と対で現れる。
    KeepCapabilities,
    /// `setresuid`（`CAP_SETUID` を要する）。
    SetUid,
    /// `capset`（permitted・effective・inheritable を期待集合へ）。
    Capset,
    /// ambient への載せ。
    RaiseAmbient,
    /// `prctl(PR_SET_KEEPCAPS, 0)`。権限保持設定を縮退後に残さない（設計書 5 章 4）。常に最終手順。
    /// 失敗は縮退全体の失敗として扱い、exec へ進まない（fail-closed）。
    ClearKeepCapabilities,
}

impl ReductionPlan {
    /// 実行すべき手順を適用順で返す（空の補助グループ消去・空の bounding 削除は含まない）。
    ///
    /// `KeepCapabilities` を含むときは必ず末尾が `ClearKeepCapabilities` になる（uid 遷移が無い計画はどちらも含まない）。
    pub fn steps(&self) -> Vec<ReductionStep> {
        let mut v = Vec::new();
        if self.clear_supplementary_groups {
            v.push(ReductionStep::ClearSupplementaryGroups);
        }
        v.push(ReductionStep::SetGid);
        if !self.bounding_drop.is_empty() {
            v.push(ReductionStep::DropBounding);
        }
        if self.keep_capabilities {
            v.push(ReductionStep::KeepCapabilities);
        }
        v.push(ReductionStep::SetUid);
        v.push(ReductionStep::Capset);
        v.push(ReductionStep::RaiseAmbient);
        if self.keep_capabilities {
            v.push(ReductionStep::ClearKeepCapabilities);
        }
        v
    }
}

/// 現在の資格情報から期待集合への縮退計画を算出する（純関数。何も適用しない）。
///
/// 縮退後に [`verify_elevation`] を満たせない前提は計画せず拒否する（fail-closed）:
/// - `no_new_privs` が立っている → `NoNewPrivsSet`
/// - `target_uid` / `target_gid` が 0 → `UnexpectedRootUid` / `UnexpectedGroups`（uid・gid 0 を解消できない）
/// - 期待集合が現在の permitted または bounding に含まれない → `MissingCapabilities`
/// - bounding に落とす対象があるのに現在の effective が `CAP_SETPCAP` を持たない → `MissingCapabilities`
///   （bounding 削除は `CAP_SETPCAP` を要する）
/// - 補助グループが残る・gid が対象と異なるのに effective が `CAP_SETGID` を持たない、または uid が対象と異なるのに
///   `CAP_SETUID` を持たない → `MissingCapabilities`（`setgroups`・`setresgid`・`setresuid` が実行不能）
pub fn plan_reduction(
    current: &CredentialSnapshot,
    expected: CapabilitySet,
    target_uid: u32,
    target_gid: u32,
) -> Result<ReductionPlan, PrivilegeError> {
    if current.no_new_privs {
        return Err(PrivilegeError::new(
            ErrorCode::FailedPrecondition,
            PrivilegeErrorReason::NoNewPrivsSet,
            "no_new_privs is set; privilege elevation is not possible",
        ));
    }
    if target_uid == 0 {
        return Err(denied(
            PrivilegeErrorReason::UnexpectedRootUid,
            "target uid must not be 0",
        ));
    }
    if target_gid == 0 {
        return Err(denied(
            PrivilegeErrorReason::UnexpectedGroups,
            "target gid must not be 0",
        ));
    }
    let exp = CapMask::from_set(expected);
    if !current.permitted.is_superset_of(exp) || !current.bounding.is_superset_of(exp) {
        return Err(denied(
            PrivilegeErrorReason::MissingCapabilities,
            "required capabilities are not in the permitted or bounding set",
        ));
    }
    let need_setgid = !current.groups.is_empty()
        || [
            current.gid.real,
            current.gid.effective,
            current.gid.saved,
            current.gid.fs,
        ]
        .iter()
        .any(|g| *g != target_gid);
    let need_setuid = [
        current.uid.real,
        current.uid.effective,
        current.uid.saved,
        current.uid.fs,
    ]
    .iter()
    .any(|u| *u != target_uid);
    let eff_has = |c: Capability| current.effective.0 & (1u64 << u32::from(c.index())) != 0;
    if need_setgid && !eff_has(Capability::Setgid) {
        return Err(denied(
            PrivilegeErrorReason::MissingCapabilities,
            "CAP_SETGID is required in the effective set to change gid or supplementary groups",
        ));
    }
    if need_setuid && !eff_has(Capability::Setuid) {
        return Err(denied(
            PrivilegeErrorReason::MissingCapabilities,
            "CAP_SETUID is required in the effective set to change uid",
        ));
    }
    let setpcap = Capability::Setpcap.index();
    let mut bounding_drop: Vec<u8> = (0u8..64)
        .filter(|i| {
            let bit = 1u64 << u32::from(*i);
            current.bounding.0 & bit != 0 && exp.0 & bit == 0
        })
        .collect();
    if !bounding_drop.is_empty() {
        let setpcap_bit = 1u64 << u32::from(setpcap);
        if current.effective.0 & setpcap_bit == 0 {
            return Err(denied(
                PrivilegeErrorReason::MissingCapabilities,
                "CAP_SETPCAP is required in the effective set to drop bounding capabilities",
            ));
        }
        // CAP_SETPCAP 自身を先に落とすと後続の削除ができないため最後へ回す。
        if let Some(pos) = bounding_drop.iter().position(|i| *i == setpcap) {
            bounding_drop.remove(pos);
            bounding_drop.push(setpcap);
        }
    }
    Ok(ReductionPlan {
        bounding_drop,
        permitted: expected,
        effective: expected,
        inheritable: expected,
        ambient: expected,
        clear_supplementary_groups: !current.groups.is_empty(),
        gid: GidSet {
            real: target_gid,
            effective: target_gid,
            saved: target_gid,
            fs: target_gid,
        },
        uid: UidSet {
            real: target_uid,
            effective: target_uid,
            saved: target_uid,
            fs: target_uid,
        },
        keep_capabilities: need_setuid,
    })
}

/// 権限を実際に縮退・付与する入口（スタブ。実装済みを装わない）。
///
/// 未実装（REPAIR-3）。将来仕様（設計書 5 章）: [`ReductionPlan::steps`] の順に適用（bounding 縮小 → `capset` →
/// ambient 載せ → `PR_SET_KEEPCAPS` 解除。途中の失敗は解除の失敗を含めすべて中断）→ 読み戻し検証
/// （[`verify_elevation`]。keepcaps は `PR_GET_KEEPCAPS`）→ fd 検証付き exec。子の待機にはタイムアウトを設ける（REPAIR-5）。
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
    const GID: &str = "1000\t1000\t1000\t1000";
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
            "Name:\tx\nUid:\t{uid}\nGid:\t{GID}\nGroups:\t\nCapInh:\t{inh}\nCapPrm:\t{prm}\nCapEff:\t{eff}\nCapBnd:\t{bnd}\nCapAmb:\t{amb}\nNoNewPrivs:\t{nnp}\n"
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
            KeepCapsState::Cleared,
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
            KeepCapsState::Cleared,
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
    fn sup14_task171_1_2_verify_rejects_gid_and_groups() {
        let m = mask_hex();
        let ok = status(&m, &m, &m, &m, &m, "0", UID);
        let cases = [
            ok.replace("Gid:\t1000\t1000\t1000\t1000", "Gid:\t1000\t0\t1000\t1000"),
            ok.replace("Gid:\t1000\t1000\t1000\t1000", "Gid:\t0\t1000\t1000\t1000"),
            ok.replace("Groups:\t\n", "Groups:\t0\n"),
            ok.replace("Groups:\t\n", "Groups:\t1000 4\n"),
        ];
        for c in cases {
            let e = verify(&c).unwrap_err();
            assert_eq!(
                (e.code, e.reason),
                (
                    ErrorCode::PermissionDenied,
                    PrivilegeErrorReason::UnexpectedGroups
                )
            );
        }
        let r = verify(&ok).unwrap();
        assert_eq!(r.gid.effective, 1000);
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
            status("+ff", &m, &m, &m, &m, "0", UID),
            status("1ffffffffffffffff", &m, &m, &m, &m, "0", UID),
            status("", &m, &m, &m, &m, "0", UID),
            status(&m, &m, &m, &m, &m, "2", UID),
            status(&m, &m, &m, &m, &m, "0", "1\t2\t3"),
            ok.replace("Gid:\t1000\t1000\t1000\t1000", "Gid:\t1\t2\t3"),
            ok.replace("Groups:\t\n", "Groups:\tx\n"),
            ok.replace("Groups:\t\n", ""),
            ok.replace("Gid:", "Xid:"),
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
        let plan = plan_reduction(&parse_proc_status(&t).unwrap(), exp, 1000, 1000).unwrap();
        assert_eq!(plan.bounding_drop.len(), 41 - 7);
        assert_eq!(plan.bounding_drop.first(), Some(&0));
        assert!(!plan.bounding_drop.contains(&21));
        assert_eq!(plan.ambient, exp);
        assert_eq!(plan.uid.effective, 1000);
        assert_eq!(plan.gid.saved, 1000);
        let t = status("0", "0", "0", FULL, "0", "0", UID);
        let e = plan_reduction(&parse_proc_status(&t).unwrap(), exp, 1000, 1000).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::MissingCapabilities);
        // permitted は足りても bounding が空なら計画できない。
        let t = status("0", FULL, FULL, "0", "0", "0", UID);
        let e = plan_reduction(&parse_proc_status(&t).unwrap(), exp, 1000, 1000).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::MissingCapabilities);
    }

    #[test]
    fn sup14_task171_1_2_plan_reduction_rejects_unexecutable_premises() {
        let exp = runtime_required_capabilities();
        let t = status("0", FULL, FULL, FULL, "0", "1", UID);
        let snap = parse_proc_status(&t).unwrap();
        let e = plan_reduction(&snap, exp, 1000, 1000).unwrap_err();
        assert_eq!(
            (e.code, e.reason),
            (
                ErrorCode::FailedPrecondition,
                PrivilegeErrorReason::NoNewPrivsSet
            )
        );
        let t = status("0", FULL, FULL, FULL, "0", "0", UID);
        let snap = parse_proc_status(&t).unwrap();
        let e = plan_reduction(&snap, exp, 0, 1000).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::UnexpectedRootUid);
        let e = plan_reduction(&snap, exp, 1000, 0).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::UnexpectedGroups);
        // bounding に落とす対象があるのに effective に CAP_SETPCAP が無い。
        let no_setpcap = format!("{:016x}", 0x1ffffffffffu64 & !(1u64 << 8));
        let t = status("0", FULL, &no_setpcap, FULL, "0", "0", UID);
        let snap = parse_proc_status(&t).unwrap();
        let e = plan_reduction(&snap, exp, 1000, 1000).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::MissingCapabilities);
    }

    #[test]
    fn sup14_task171_1_2_plan_reduction_requires_setuid_setgid_and_orders_steps() {
        let exp = runtime_required_capabilities();
        let root_uid = "0\t0\t0\t0";
        let t = status("0", FULL, FULL, FULL, "0", "0", root_uid);
        let plan = plan_reduction(&parse_proc_status(&t).unwrap(), exp, 1000, 1000).unwrap();
        assert_eq!(
            plan.steps(),
            vec![
                ReductionStep::SetGid,
                ReductionStep::DropBounding,
                ReductionStep::KeepCapabilities,
                ReductionStep::SetUid,
                ReductionStep::Capset,
                ReductionStep::RaiseAmbient,
                ReductionStep::ClearKeepCapabilities,
            ]
        );
        assert!(plan.keep_capabilities);
        // CAP_SETUID が無ければ uid を変えられない。
        let no_setuid = format!("{:016x}", 0x1ffffffffffu64 & !(1u64 << 7));
        let t = status("0", FULL, &no_setuid, FULL, "0", "0", root_uid);
        let e = plan_reduction(&parse_proc_status(&t).unwrap(), exp, 1000, 1000).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::MissingCapabilities);
        // CAP_SETGID が無ければ gid を変えられない。
        let no_setgid = format!("{:016x}", 0x1ffffffffffu64 & !(1u64 << 6));
        let t = status("0", FULL, &no_setgid, FULL, "0", "0", UID);
        let e = plan_reduction(&parse_proc_status(&t).unwrap(), exp, 1000, 1001).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::MissingCapabilities);
    }

    /// SUP-14・設計書 5 章 4: `PR_SET_KEEPCAPS` の設定と解除は対で計画し、解除は最終手順にする。
    #[test]
    fn sup14_task171_1_2_plan_reduction_pairs_keepcaps_set_and_clear() {
        let exp = runtime_required_capabilities();
        // uid 遷移なし（ランチャーが対象 uid で動く）: keepcaps を設定も解除もしない。
        let t = status("0", FULL, FULL, FULL, "0", "0", UID);
        let plan = plan_reduction(&parse_proc_status(&t).unwrap(), exp, 1000, 1000).unwrap();
        assert!(!plan.keep_capabilities);
        assert_eq!(
            plan.steps(),
            vec![
                ReductionStep::SetGid,
                ReductionStep::DropBounding,
                ReductionStep::SetUid,
                ReductionStep::Capset,
                ReductionStep::RaiseAmbient,
            ]
        );
        // uid 遷移あり（saved だけが 0 の場合も含む）: 設定 1 回・解除 1 回で、解除が末尾。
        for uid in ["0\t0\t0\t0", "1000\t1000\t0\t1000"] {
            let t = status("0", FULL, FULL, FULL, "0", "0", uid);
            let plan = plan_reduction(&parse_proc_status(&t).unwrap(), exp, 1000, 1000).unwrap();
            let steps = plan.steps();
            let pos = |s: ReductionStep| steps.iter().position(|x| *x == s);
            let count = |s: ReductionStep| steps.iter().filter(|x| **x == s).count();
            assert_eq!(count(ReductionStep::KeepCapabilities), 1);
            assert_eq!(count(ReductionStep::ClearKeepCapabilities), 1);
            assert_eq!(steps.last(), Some(&ReductionStep::ClearKeepCapabilities));
            assert_eq!(pos(ReductionStep::KeepCapabilities), Some(2));
            assert_eq!(pos(ReductionStep::SetUid), Some(3));
            assert_eq!(pos(ReductionStep::RaiseAmbient), Some(5));
            assert_eq!(pos(ReductionStep::ClearKeepCapabilities), Some(6));
        }
    }

    /// SUP-14: 縮退後に keepcaps が残る・読み戻せていない状態は、他がすべて期待どおりでも拒否する。
    #[test]
    fn sup14_task171_1_2_verify_rejects_keepcaps_retained_or_unknown() {
        let m = mask_hex();
        let snap = parse_proc_status(&status(&m, &m, &m, &m, &m, "0", UID)).unwrap();
        let exp = runtime_required_capabilities();
        for method in [
            PrivilegeMethod::SetuidRoot,
            PrivilegeMethod::LauncherAmbient,
        ] {
            let e = verify_elevation(&snap, KeepCapsState::Set, exp, method).unwrap_err();
            assert_eq!(
                (e.code, e.reason),
                (
                    ErrorCode::PermissionDenied,
                    PrivilegeErrorReason::KeepCapsRetained
                )
            );
            assert_eq!(
                e.message,
                "PR_SET_KEEPCAPS remains set after privilege reduction"
            );
            let e = verify_elevation(&snap, KeepCapsState::Unknown, exp, method).unwrap_err();
            assert_eq!(
                (e.code, e.reason),
                (
                    ErrorCode::FailedPrecondition,
                    PrivilegeErrorReason::KeepCapsRetained
                )
            );
            let r = verify_elevation(&snap, KeepCapsState::Cleared, exp, method).unwrap();
            assert_eq!(r.held, exp);
        }
    }

    #[test]
    fn sup14_task171_1_2_plan_reduction_drops_setpcap_last() {
        // 期待集合に CAP_SETPCAP を含めない場合、番号 8 は bounding_drop の末尾になる。
        let exp = CapabilitySet::empty().with(Capability::SysAdmin);
        let t = status("0", FULL, FULL, FULL, "0", "0", UID);
        let plan = plan_reduction(&parse_proc_status(&t).unwrap(), exp, 1000, 1000).unwrap();
        assert_eq!(plan.bounding_drop.last(), Some(&8));
        assert_eq!(plan.bounding_drop.iter().filter(|i| **i == 8).count(), 1);
        assert_eq!(plan.bounding_drop.len(), 40);
        assert_eq!(plan.bounding_drop.first(), Some(&0));
        assert_eq!(plan.bounding_drop.get(7), Some(&7));
        assert_eq!(plan.bounding_drop.get(8), Some(&9));
    }

    #[test]
    fn sup14_task171_1_2_verify_rejects_missing_bounding() {
        let m = mask_hex();
        let e = verify(&status(&m, &m, &m, "0", &m, "0", UID)).unwrap_err();
        assert_eq!(
            (e.code, e.reason),
            (
                ErrorCode::PermissionDenied,
                PrivilegeErrorReason::MissingCapabilities
            )
        );
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
