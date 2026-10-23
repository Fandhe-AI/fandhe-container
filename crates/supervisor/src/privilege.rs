//! 権限昇格の必要最小集合・検証ロジックと、縮退を実際に適用する `elevate`（SUP-14・SEC-1・TASK-171.1.2・#858／
//! TASK-171.1.3・#1475・MS-9）。
//!
//! # 役割
//! `sudo` + pty に頼らない権限分離（SUP-14）で、昇格後のプロセスが保持してよい capability を
//! 「必要最小の集合」に限定する。純ロジック（[`parse_proc_status`]・[`verify_elevation`]・[`plan_reduction`]）は
//! syscall を呼ばず `unsafe` を含まないため 3 OS の CI で具体値照合できる。実際に縮退を適用する [`elevate`] は
//! Linux 専用で、`unsafe` を `crate::sys`（Linux 版。事前承認の範囲）の薄いラッパーに閉じる。
//!
//! # 方式（承認済み。#1454 のオーナー判断 2026-10-10。`docs/design/privilege-separation.md` 9 章）
//! - 既定: [`PrivilegeMethod::LauncherAmbient`]（特権ランチャー + file capability + ambient capability）
//! - 代替: [`PrivilegeMethod::SetuidRoot`]（xattr 非対応の環境に限る）
//! - どちらも失敗したら fail-closed にし、`sudo` へ黙ってフォールバックしない（設計書 6 章）
//!
//! # 呼び出し文脈・契約
//! - 呼び出し元: 特権ランチャー（`fandhe-container-launcher`。`crate::launcher`。#1719）が起動直後に単一スレッドで [`elevate`] を呼び、
//!   `Ok` のときだけ supervisor の exec へ進む。`Err` のときプロセスは部分的に縮退した状態にあり、
//!   呼び出し元は exec も特権操作もせず非ゼロで終了する（bounding の削除は戻せないため巻き戻さない）
//! - [`runtime_required_capabilities`] はランタイム側が一時的に保持する権限であり、コンテナへ渡す
//!   OCI 既定集合（SEC-1）とは別物
//! - カーネル応答（`/proc/<pid>/status`）は外部入力として扱い、長さ・行数を先に検証し、`unwrap`・添字アクセスを使わない
//! - 検証は fail-closed。過剰権限・不足・`no_new_privs`・uid 0・`PR_SET_KEEPCAPS` の残存 / 未確認・ambient 不一致・
//!   スレッド数の増加のいずれも `Ok` にしない。keepcaps は `/proc/<pid>/status` に現れないため、
//!   `prctl(PR_GET_KEEPCAPS)` で読み戻した値を [`KeepCapsState`] として [`verify_elevation`] へ渡す
//!
//! # セッション切り離し（要素 (B)。TASK-171.2・#537）
//! 昇格の方式によらず、起動経路が pty を経由しないことも SUP-14 の要件である。[`detach_session`] が `setsid` で
//! 新しいセッションへ移り、標準入出力が端末でないこと・制御端末が無いこと・自分がセッションとプロセスグループの
//! リーダーであることを `/proc/self/stat` の読み戻しで検証する（純ロジックは [`parse_proc_stat`]・
//! [`verify_session_detached`]）。ランチャーの入口で [`elevate`] より前に呼ばれる。
//!
//! # 本モジュールの範囲外（REPAIR-3。実装済みを装わない）
//! - fd 検証付き exec（`execveat`・所有者 / 権限の検証）・引数 / 環境変数 / cwd / 継承 fd の入口検証・ランチャー bin:
//!   `crate::launcher`（#1719。実装済み）
//! - ambient は exec 後の子孫へ引き継がれる。コンテナの子は core の制限段で消すが、healthcheck の exec など
//!   supervisor が起動する子での解除は TASK-161.2（#495）の実装時（設計書 5 章 5・10 章）
//! - file capability / setuid ビットの付与（インストール）: `scripts/install-privileged-launcher.sh`（#1721。実装済み。
//!   実機での実行と検証は人間担当: #538・#539）

use std::fmt;

use fandhe_container_core::capabilities::{Capability, CapabilitySet};
use fandhe_container_core::traits::{ErrorCode, TraitError};

#[cfg(target_os = "linux")]
use crate::sys::EPERM;
/// 非 Linux では `crate::sys` が無いが、fake kernel の単体テストは 3 OS で走るため同じ値を試験用に置く
/// （値は Linux の `EPERM`）。
#[cfg(all(test, not(target_os = "linux")))]
const EPERM: i32 = 1;

/// `/proc/<pid>/status` として受け入れる最大バイト数（無制限確保の防止）。
pub const MAX_STATUS_BYTES: usize = 64 * 1024;
/// `/proc/<pid>/status` として受け入れる最大行数。
pub const MAX_STATUS_LINES: usize = 512;

/// 権限取得の方式（設計書 3・9 章。#1454 のオーナー判断 2026-10-10 で承認済み）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrivilegeMethod {
    /// 特権ランチャー + ambient capability（設計書の (c)。既定の方式。file capability で昇格した非 root のランチャー）。
    LauncherAmbient,
    /// setuid root バイナリ（設計書 (a)。xattr 非対応環境に限る代替。非 root が起動した setuid root のランチャー）。
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

/// 方式 (c)［`PrivilegeMethod::LauncherAmbient`］のランチャーに file capability として付ける集合
/// （[`RUNTIME_REQUIRED_CAPABILITIES`] に、補助グループを持つ利用者向けの `CAP_SETGID` を足したもの。[`elevate`] の契約）。
///
/// `scripts/install-privileged-launcher.sh` の `LAUNCHER_CAPS` と同期する（`launcher_probe` の単体試験が機械照合する）。
/// `doctor` の特権ランチャー診断（#2599・SUP-14）が「付いているべき集合」として使う。
pub fn launcher_file_capabilities() -> CapabilitySet {
    runtime_required_capabilities().with(Capability::Setgid)
}

/// [`launcher_file_capabilities`] のビット列（bit n が capability 番号 n。`security.capability` の permitted と同じ並び）。
pub fn launcher_file_capability_mask() -> u64 {
    launcher_file_capabilities()
        .iter()
        .fold(0u64, |m, c| m | (1u64 << c.index()))
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
    /// 実適用経路が未実装（非 Linux の [`elevate`]）。
    Unimplemented,
    /// 単一スレッドであることを確認できなかった（`Threads:` が 1 でない・読めない）。capability はスレッド単位のため、
    /// 他スレッドに強い権限が残ったまま `Ok` にしない。
    MultiThreaded,
    /// 方式と現在の資格情報の組み合わせが合わない（例: 方式 (c) なのに uid 0、方式 (a) なのに effective uid が 0 でない）。
    MethodMismatch,
    /// 縮退手順または読み戻しの syscall が失敗した（message に手順名と errno を入れる）。
    SyscallFailed,
    /// 標準入出力のいずれかが端末（pty を含む）を指している。pty 経由の起動は拒否する（SUP-14。#537）。
    StdioIsTerminal,
    /// 制御端末が残っている（`/proc/self/stat` の `tty_nr` が 0 でない。#537）。
    ControllingTerminalAttached,
    /// 自分のセッション / プロセスグループのリーダーになれていない（#537）。
    NotSessionLeader,
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
/// `/proc/<pid>/status` には現れないため [`CredentialSnapshot`] とは別に渡す。[`elevate`] が
/// `prctl(PR_GET_KEEPCAPS)` の戻り値から作る。読み戻しに失敗した・読み戻していない場合は
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

/// `Threads:` 行から現在のスレッド数を取り出す（純関数。`/proc/self/status` の外部入力検証つき）。
///
/// バイト数・行数が上限（[`MAX_STATUS_BYTES`]・[`MAX_STATUS_LINES`]）を超える、`Threads:` が無い・重複する・
/// 10 進整数でない場合は `None`（呼び出し側は fail-closed で単一スレッドと認めない）。
#[cfg(any(target_os = "linux", test))]
fn parse_thread_count(text: &str) -> Option<u64> {
    if text.len() > MAX_STATUS_BYTES {
        return None;
    }
    let mut found: Option<u64> = None;
    for (n, line) in text.lines().enumerate() {
        if n >= MAX_STATUS_LINES {
            return None;
        }
        if let Some(rest) = line.strip_prefix("Threads:") {
            if found.is_some() {
                return None;
            }
            let v = rest.trim();
            if v.is_empty() || !v.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            found = Some(v.parse::<u64>().ok()?);
        }
    }
    found
}

/// [`elevate_with`] が使うカーネル操作の抽象（テストでは偽物に差し替え、本番は Linux 版の `RealKernel`）。
///
/// 各メソッドの失敗は `io::Error`（errno 付き）で返す。capability / keepcaps は呼び出したスレッドのみに効く。
#[cfg(any(target_os = "linux", test))]
trait PrivilegeKernel {
    /// `/proc/self/status` を上限付きで読む。
    fn read_self_status(&mut self) -> std::io::Result<String>;
    fn clear_groups(&mut self) -> std::io::Result<()>;
    fn set_resgid(&mut self, gid: u32) -> std::io::Result<()>;
    fn drop_bounding(&mut self, cap: u8) -> std::io::Result<()>;
    fn set_keep_caps(&mut self, on: bool) -> std::io::Result<()>;
    fn set_resuid(&mut self, uid: u32) -> std::io::Result<()>;
    /// effective・permitted・inheritable を設定する。
    fn capset(&mut self, effective: u64, permitted: u64, inheritable: u64) -> std::io::Result<()>;
    fn ambient_clear_all(&mut self) -> std::io::Result<()>;
    fn ambient_raise(&mut self, cap: u8) -> std::io::Result<()>;
    fn get_keep_caps(&mut self) -> std::io::Result<bool>;
}

/// 手順 syscall の失敗を `SyscallFailed` にする（EPERM は `PermissionDenied`、その他は `Internal`）。
/// message は固定の英語文と errno 番号だけで、環境の情報を含めない。
#[cfg(any(target_os = "linux", test))]
fn syscall_failed(what: &str, e: &std::io::Error) -> PrivilegeError {
    let code = if e.raw_os_error() == Some(EPERM) {
        ErrorCode::PermissionDenied
    } else {
        ErrorCode::Internal
    };
    let errno = e.raw_os_error().unwrap_or(0);
    PrivilegeError::new(
        code,
        PrivilegeErrorReason::SyscallFailed,
        format!("{what} failed (errno {errno})"),
    )
}

#[cfg(any(target_os = "linux", test))]
fn multi_threaded(message: &str) -> PrivilegeError {
    PrivilegeError::new(
        ErrorCode::FailedPrecondition,
        PrivilegeErrorReason::MultiThreaded,
        message,
    )
}

/// `/proc/self/status` を読み、単一スレッドであることを確かめてから資格情報を取り出す。
#[cfg(any(target_os = "linux", test))]
fn read_single_threaded_snapshot<K: PrivilegeKernel>(
    k: &mut K,
) -> Result<CredentialSnapshot, PrivilegeError> {
    let text = k
        .read_self_status()
        .map_err(|_| multi_threaded("cannot confirm a single thread: process status unreadable"))?;
    if parse_thread_count(&text) != Some(1) {
        return Err(multi_threaded(
            "privilege elevation requires a single-threaded process",
        ));
    }
    parse_proc_status(&text)
}

/// 方式と現在の資格情報の組み合わせを確認する（何も変更しない）。
#[cfg(any(target_os = "linux", test))]
fn check_method_premise(
    snap: &CredentialSnapshot,
    method: PrivilegeMethod,
) -> Result<(), PrivilegeError> {
    let mismatch = |m: &str| {
        PrivilegeError::new(
            ErrorCode::FailedPrecondition,
            PrivilegeErrorReason::MethodMismatch,
            m,
        )
    };
    match method {
        PrivilegeMethod::LauncherAmbient if snap.uid.any_root() => Err(mismatch(
            "launcher-ambient method requires a non-root uid; uid 0 was found",
        )),
        PrivilegeMethod::SetuidRoot if snap.uid.effective != 0 || snap.uid.real == 0 => Err(
            mismatch("setuid-root method requires effective uid 0 and a non-root real uid"),
        ),
        _ => Ok(()),
    }
}

/// 縮退計画の 1 手順を適用する。
#[cfg(any(target_os = "linux", test))]
fn apply_step<K: PrivilegeKernel>(
    k: &mut K,
    step: ReductionStep,
    plan: &ReductionPlan,
) -> Result<(), PrivilegeError> {
    let fail = |what: &'static str| move |e: std::io::Error| syscall_failed(what, &e);
    match step {
        ReductionStep::ClearSupplementaryGroups => k.clear_groups().map_err(fail("setgroups")),
        ReductionStep::SetGid => k.set_resgid(plan.gid.real).map_err(fail("setresgid")),
        ReductionStep::DropBounding => {
            for cap in &plan.bounding_drop {
                k.drop_bounding(*cap).map_err(fail("bounding drop"))?;
            }
            Ok(())
        }
        ReductionStep::KeepCapabilities => k.set_keep_caps(true).map_err(fail("set keepcaps")),
        ReductionStep::SetUid => k.set_resuid(plan.uid.real).map_err(fail("setresuid")),
        ReductionStep::Capset => k
            .capset(
                CapMask::from_set(plan.effective).0,
                CapMask::from_set(plan.permitted).0,
                CapMask::from_set(plan.inheritable).0,
            )
            .map_err(fail("capset")),
        ReductionStep::RaiseAmbient => {
            k.ambient_clear_all().map_err(fail("ambient clear"))?;
            let mut caps: Vec<u8> = plan.ambient.iter().map(|c| c.index()).collect();
            caps.sort_unstable();
            for cap in caps {
                k.ambient_raise(cap).map_err(fail("ambient raise"))?;
            }
            Ok(())
        }
        ReductionStep::ClearKeepCapabilities => {
            k.set_keep_caps(false).map_err(fail("clear keepcaps"))
        }
    }
}

/// [`elevate`] の本体（カーネル操作を差し替え可能にした形。単体テストが偽物で全手順の失敗を注入する）。
///
/// 順序: 単一スレッド確認 → 資格情報の読み取り → 方式の前提確認 → [`plan_reduction`] → [`ReductionPlan::steps`] の
/// 順に適用 → `PR_GET_KEEPCAPS`・`/proc/self/status` の読み戻し → [`verify_elevation`]。前提確認と計画までは
/// 何も変更しない。最初の失敗で中断し、後続の手順は呼ばない。
#[cfg(any(target_os = "linux", test))]
fn elevate_with<K: PrivilegeKernel>(
    k: &mut K,
    method: PrivilegeMethod,
) -> Result<ElevationReport, PrivilegeError> {
    let snap = read_single_threaded_snapshot(k)?;
    check_method_premise(&snap, method)?;
    // 目標の uid / gid は呼び出し元の本来の資格情報（real）に固定し、引数では受け取らない。
    // 任意の uid への遷移を許さず、real が 0 なら計画段で拒否される。
    let expected = runtime_required_capabilities();
    let plan = plan_reduction(&snap, expected, snap.uid.real, snap.gid.real)?;
    let mut keep_set = false;
    for step in plan.steps() {
        if let Err(e) = apply_step(k, step, &plan) {
            // KeepCapabilities 後の中断では、権限保持設定を縮退後に残さないよう解除を 1 回だけ試す
            // （結果は返り値を変えない）。解除手順自体の失敗は試行済みのため繰り返さない。
            if keep_set && step != ReductionStep::ClearKeepCapabilities {
                let _ = k.set_keep_caps(false);
            }
            return Err(e);
        }
        match step {
            ReductionStep::KeepCapabilities => keep_set = true,
            ReductionStep::ClearKeepCapabilities => keep_set = false,
            _ => {}
        }
    }
    let keep = match k.get_keep_caps() {
        Ok(false) => KeepCapsState::Cleared,
        Ok(true) => KeepCapsState::Set,
        Err(_) => KeepCapsState::Unknown,
    };
    let after = read_single_threaded_snapshot(k)?;
    verify_elevation(&after, keep, expected, method)
}

/// Linux の本番実装。`crate::sys` の薄いラッパーを呼ぶ。
#[cfg(target_os = "linux")]
struct RealKernel;

#[cfg(target_os = "linux")]
impl PrivilegeKernel for RealKernel {
    fn read_self_status(&mut self) -> std::io::Result<String> {
        use std::io::Read;
        let mut text = String::new();
        let limit = u64::try_from(MAX_STATUS_BYTES + 1).unwrap_or(u64::MAX);
        std::fs::File::open("/proc/self/status")?
            .take(limit)
            .read_to_string(&mut text)?;
        if text.len() > MAX_STATUS_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "process status exceeds the size limit",
            ));
        }
        Ok(text)
    }

    fn clear_groups(&mut self) -> std::io::Result<()> {
        crate::sys::clear_supplementary_groups()
    }

    fn set_resgid(&mut self, gid: u32) -> std::io::Result<()> {
        crate::sys::set_resgid(gid, gid, gid)
    }

    fn drop_bounding(&mut self, cap: u8) -> std::io::Result<()> {
        crate::sys::cap_bounding_drop(cap)
    }

    fn set_keep_caps(&mut self, on: bool) -> std::io::Result<()> {
        crate::sys::set_keep_caps(on)
    }

    fn set_resuid(&mut self, uid: u32) -> std::io::Result<()> {
        crate::sys::set_resuid(uid, uid, uid)
    }

    fn capset(&mut self, effective: u64, permitted: u64, inheritable: u64) -> std::io::Result<()> {
        crate::sys::cap_set_thread(crate::sys::ThreadCaps {
            effective,
            permitted,
            inheritable,
        })
    }

    fn ambient_clear_all(&mut self) -> std::io::Result<()> {
        crate::sys::cap_ambient_clear_all()
    }

    fn ambient_raise(&mut self, cap: u8) -> std::io::Result<()> {
        crate::sys::cap_ambient_raise(cap)
    }

    fn get_keep_caps(&mut self) -> std::io::Result<bool> {
        crate::sys::get_keep_caps()
    }
}

/// 権限を縮退して必要最小集合だけを保持する状態にし、読み戻して検証する入口（SUP-14・SEC-1・TASK-171.1.3・#1475）。
///
/// 特権ランチャー（#1719）が起動直後に呼ぶ。呼び出し元の本来の uid / gid（real）へ遷移し、補助グループを消し、
/// bounding を必要最小集合へ縮め、`capset` と ambient で [`runtime_required_capabilities`] ちょうどを保持する。
/// どの段で失敗しても `Err` を返し、`sudo` へ戻らない（fail-closed）。
///
/// # 契約
/// - 単一スレッドのプロセスから呼ぶ（`capset`・keepcaps はスレッド単位のため、`Threads:` が 1 でなければ
///   何も変更せず `MultiThreaded` で拒否し、適用後にも再確認する）
/// - `Ok` のときだけ、呼び出し元は exec へ進んでよい。`Err` のときプロセスは部分的に縮退した状態にあり
///   （bounding の削除は戻せない）、呼び出し元は exec も特権操作もせず非ゼロで終了する
/// - 方式 (c)［`PrivilegeMethod::LauncherAmbient`］では、file capability に `RUNTIME_REQUIRED_CAPABILITIES` に加えて、
///   補助グループを持つ利用者向けに `CAP_SETGID` を effective 付きで持たせる必要がある（`plan_reduction` の前提。
///   必要最小集合は広げない。付与は `scripts/install-privileged-launcher.sh`〔#1721〕が行う）
/// - ambient は exec 後の子孫へ引き継がれる。子での解除は本関数の範囲外（コンテナの子は core の制限段、
///   supervisor が起動する子は TASK-161.2・#495）
///
/// fd 検証付き exec・入口検証は本関数の範囲外（#1719）。非 Linux では常に `Unimplemented`（SUP-14 の対象は Linux の
/// rootful 経路で、macOS / Windows は VM 内で動く）。
pub fn elevate(method: PrivilegeMethod) -> Result<ElevationReport, PrivilegeError> {
    #[cfg(target_os = "linux")]
    {
        elevate_with(&mut RealKernel, method)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = method;
        Err(PrivilegeError::new(
            ErrorCode::Unimplemented,
            PrivilegeErrorReason::Unimplemented,
            "privilege elevation is only supported on Linux",
        ))
    }
}

// ---------------------------------------------------------------------------
// セッション切り離し（SUP-14 の要素 (B)。TASK-171.2・#537）
// ---------------------------------------------------------------------------

/// `/proc/self/stat` として受け入れる最大バイト数（無制限確保の防止。実際の行は数百バイト）。
pub const MAX_STAT_BYTES: usize = 4 * 1024;

/// `/proc/<pid>/stat` から取り出したセッション関連のフィールド（`pid`・`pgrp`・`session`・`tty_nr`）。
///
/// `sudo`（`use_pty`）を `SIGKILL` したとき pty の閉鎖が supervisor 以下へシグナルとして波及する（PoC-17 の発見事項 1）。
/// その経路を断てているかの判定材料で、[`verify_session_detached`] が具体値で検証する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSnapshot {
    /// プロセス ID（呼び出し元の pid namespace から見た値）。
    pub pid: u32,
    /// プロセスグループ ID。
    pub pgrp: u32,
    /// セッション ID。
    pub session: u32,
    /// 制御端末のデバイス番号。0 は制御端末なし。
    pub tty_nr: i64,
}

/// 標準入出力（fd 0〜2）がそれぞれ端末（pty を含む）を指しているか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdioTerminals {
    /// fd 0 が端末か。
    pub stdin: bool,
    /// fd 1 が端末か。
    pub stdout: bool,
    /// fd 2 が端末か。
    pub stderr: bool,
}

impl StdioTerminals {
    fn any(self) -> bool {
        self.stdin || self.stdout || self.stderr
    }
}

fn session_error(reason: PrivilegeErrorReason, message: &str) -> PrivilegeError {
    PrivilegeError::new(ErrorCode::FailedPrecondition, reason, message)
}

/// `/proc/<pid>/stat` を解釈する。`comm` は空白や `)` を含みうるため、最後の `)` で分割してから空白区切りにする。
///
/// 長さを先に検証し、取り出しは `get()` と `parse()` だけで行う（添字・`unwrap` なし）。不正なら `MalformedStatus`。
pub fn parse_proc_stat(text: &str) -> Result<SessionSnapshot, PrivilegeError> {
    if text.len() > MAX_STAT_BYTES {
        return Err(PrivilegeError::malformed(
            "process stat exceeds the size limit",
        ));
    }
    let bad = || PrivilegeError::malformed("process stat is malformed");
    let open = text.find(" (").ok_or_else(bad)?;
    let close = text.rfind(')').ok_or_else(bad)?;
    if open >= close {
        return Err(bad());
    }
    let pid = text
        .get(..open)
        .and_then(|s| s.trim().parse::<u32>().ok())
        .ok_or_else(bad)?;
    let rest = text.get(close + 1..).ok_or_else(bad)?;
    // state ppid pgrp session tty_nr
    let mut it = rest.split_whitespace();
    let _state = it.next().ok_or_else(bad)?;
    let _ppid = it.next().ok_or_else(bad)?;
    let pgrp = it
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(bad)?;
    let session = it
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(bad)?;
    let tty_nr = it
        .next()
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(bad)?;
    Ok(SessionSnapshot {
        pid,
        pgrp,
        session,
        tty_nr,
    })
}

fn check_stdio(t: StdioTerminals) -> Result<(), PrivilegeError> {
    if t.any() {
        return Err(session_error(
            PrivilegeErrorReason::StdioIsTerminal,
            "stdin, stdout and stderr must not be terminals (a pty-backed start is refused)",
        ));
    }
    Ok(())
}

/// セッションの切り離しが済んだことを fail-closed で検証する。
///
/// 判定順: 標準入出力が端末でない → 制御端末なし（`tty_nr == 0`）→ セッションリーダー（`session == pid`）→
/// プロセスグループのリーダー（`pgrp == pid`）。最初に当たった失敗を返す。
pub fn verify_session_detached(
    snap: &SessionSnapshot,
    stdio: StdioTerminals,
) -> Result<(), PrivilegeError> {
    check_stdio(stdio)?;
    if snap.tty_nr != 0 {
        return Err(session_error(
            PrivilegeErrorReason::ControllingTerminalAttached,
            "a controlling terminal is still attached",
        ));
    }
    if snap.session != snap.pid {
        return Err(session_error(
            PrivilegeErrorReason::NotSessionLeader,
            "the process is not the leader of its own session",
        ));
    }
    if snap.pgrp != snap.pid {
        return Err(session_error(
            PrivilegeErrorReason::NotSessionLeader,
            "the process is not the leader of its own process group",
        ));
    }
    Ok(())
}

/// [`detach_session_with`] が使うカーネル操作の抽象（テストでは偽物に差し替え、本番は Linux 版の `RealSession`）。
#[cfg(any(target_os = "linux", test))]
trait SessionKernel {
    /// fd 0〜2 が端末か（副作用なし）。
    fn stdio_terminals(&mut self) -> StdioTerminals;
    /// `setsid(2)`。失敗は errno 付きの `io::Error`。
    fn setsid(&mut self) -> std::io::Result<()>;
    /// `/proc/self/stat` を上限付きで読む。
    fn read_self_stat(&mut self) -> std::io::Result<String>;
}

/// 順序: 標準入出力の端末判定（端末なら `setsid` の前に拒否）→ `setsid` → `/proc/self/stat` の読み戻し → [`verify_session_detached`]。
///
/// `setsid` が `EPERM`（呼び出し元がプロセスグループのリーダー）のときは、読み戻しで `session == pid == pgrp` かつ
/// 制御端末なしなら「既に切り離されている」として成功にする（systemd のサービスや `setsid(1)` 経由）。それ以外は拒否する。
/// fork で回避しない（ランチャーの「exec で置き換わる・待機しない」契約を保つため）。
///
/// fork しないため exec 後の supervisor は生涯セッションリーダーになる。その帰結（端末の `open` に `O_NOCTTY`
/// が必須）は `crate::launcher` の module doc を参照（#2426）。
#[cfg(any(target_os = "linux", test))]
fn detach_session_with<K: SessionKernel>(k: &mut K) -> Result<SessionSnapshot, PrivilegeError> {
    let stdio = k.stdio_terminals();
    check_stdio(stdio)?;
    match k.setsid() {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(EPERM) => {}
        Err(e) => return Err(syscall_failed("setsid", &e)),
    }
    let text = k
        .read_self_stat()
        .map_err(|e| syscall_failed("reading process stat", &e))?;
    let snap = parse_proc_stat(&text)?;
    verify_session_detached(&snap, stdio)?;
    Ok(snap)
}

/// Linux の本番実装。`crate::sys::new_session` の薄いラッパーと std の端末判定を使う。
#[cfg(target_os = "linux")]
struct RealSession;

#[cfg(target_os = "linux")]
impl SessionKernel for RealSession {
    fn stdio_terminals(&mut self) -> StdioTerminals {
        use std::io::IsTerminal;
        StdioTerminals {
            stdin: std::io::stdin().is_terminal(),
            stdout: std::io::stdout().is_terminal(),
            stderr: std::io::stderr().is_terminal(),
        }
    }

    fn setsid(&mut self) -> std::io::Result<()> {
        crate::sys::new_session()
    }

    fn read_self_stat(&mut self) -> std::io::Result<String> {
        use std::io::Read;
        let mut text = String::new();
        let limit = u64::try_from(MAX_STAT_BYTES + 1).unwrap_or(u64::MAX);
        std::fs::File::open("/proc/self/stat")?
            .take(limit)
            .read_to_string(&mut text)?;
        if text.len() > MAX_STAT_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "process stat exceeds the size limit",
            ));
        }
        Ok(text)
    }
}

/// 呼び出しプロセスを新しいセッションへ移し、制御端末と pty 経由の標準入出力が無いことを読み戻しで確認する
/// （SUP-14 の要素 (B)。TASK-171.2・#537）。
///
/// 特権ランチャー（`crate::launcher`）が入口で [`elevate`] より前に呼ぶ。`sudo`（`use_pty`）が pty 越しに子孫を
/// fork している状態で `sudo` が `SIGKILL` されても、pty の閉鎖によるシグナル配送が supervisor 以下へ波及しない
/// ことを保証する側。端末を指す標準入出力・制御端末の残存・別セッションのプロセスグループリーダーはいずれも
/// `Err`（fail-closed）で、呼び出し元は昇格も exec もせず非ゼロで終了する。
///
/// # 契約
/// - 呼び出し元は自分を `process_group(0)` 等でプロセスグループのリーダーにして起動してはならない
///   （`setsid` が `EPERM` になる。既に切り離されている場合に限り成功扱い）
/// - 標準入出力に端末（pty）を渡して起動してはならない
///
/// 非 Linux では常に `Unimplemented`（SUP-14 の対象は Linux の rootful 経路）。
pub fn detach_session() -> Result<SessionSnapshot, PrivilegeError> {
    #[cfg(target_os = "linux")]
    {
        detach_session_with(&mut RealSession)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(PrivilegeError::new(
            ErrorCode::Unimplemented,
            PrivilegeErrorReason::Unimplemented,
            "session detachment is only supported on Linux",
        ))
    }
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

    /// 非 Linux の `elevate` は常に `Unimplemented`。Linux の libtest は複数スレッドのため `MultiThreaded` で
    /// 何も変更せず拒否される（実機の縮退は `tests/privilege_elevate.rs`）。
    #[test]
    fn sup14_task171_1_3_public_elevate_reports_platform_result() {
        let e = elevate(PrivilegeMethod::LauncherAmbient).unwrap_err();
        #[cfg(target_os = "linux")]
        {
            assert_eq!(e.code, ErrorCode::FailedPrecondition);
            assert_eq!(e.reason, PrivilegeErrorReason::MultiThreaded);
            assert_eq!(TraitError::from(e).code(), ErrorCode::FailedPrecondition);
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(e.code, ErrorCode::Unimplemented);
            assert_eq!(e.reason, PrivilegeErrorReason::Unimplemented);
            assert_eq!(TraitError::from(e).code(), ErrorCode::Unimplemented);
        }
    }

    // ---- TASK-171.1.3・#1475: elevate の適用順・失敗注入（偽のカーネル操作で 3 OS 共通に照合） ----

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Op {
        ReadStatus,
        ClearGroups,
        SetGid(u32),
        DropBounding(u8),
        KeepCaps(bool),
        SetUid(u32),
        Capset(u64, u64, u64),
        AmbientClearAll,
        AmbientRaise(u8),
        GetKeepCaps,
    }

    /// 呼び出しを記録し、変更系 n 番目（0 起点。ReadStatus・GetKeepCaps は数えない）の操作に errno を注入できる偽物。
    struct FakeKernel {
        ops: Vec<Op>,
        statuses: Vec<String>,
        reads: usize,
        keep_after: Option<bool>,
        fail_nth: Option<(usize, i32)>,
        mutations: usize,
    }

    impl FakeKernel {
        fn new(statuses: Vec<String>) -> Self {
            Self {
                ops: Vec::new(),
                statuses,
                reads: 0,
                keep_after: Some(false),
                fail_nth: None,
                mutations: 0,
            }
        }

        fn mutate(&mut self, op: Op) -> std::io::Result<()> {
            self.ops.push(op);
            let n = self.mutations;
            self.mutations += 1;
            match self.fail_nth {
                Some((i, errno)) if i == n => Err(std::io::Error::from_raw_os_error(errno)),
                _ => Ok(()),
            }
        }
    }

    impl PrivilegeKernel for FakeKernel {
        fn read_self_status(&mut self) -> std::io::Result<String> {
            self.ops.push(Op::ReadStatus);
            let i = self.reads.min(self.statuses.len().saturating_sub(1));
            self.reads += 1;
            self.statuses
                .get(i)
                .cloned()
                .ok_or_else(|| std::io::Error::from_raw_os_error(5))
        }
        fn clear_groups(&mut self) -> std::io::Result<()> {
            self.mutate(Op::ClearGroups)
        }
        fn set_resgid(&mut self, gid: u32) -> std::io::Result<()> {
            self.mutate(Op::SetGid(gid))
        }
        fn drop_bounding(&mut self, cap: u8) -> std::io::Result<()> {
            self.mutate(Op::DropBounding(cap))
        }
        fn set_keep_caps(&mut self, on: bool) -> std::io::Result<()> {
            self.mutate(Op::KeepCaps(on))
        }
        fn set_resuid(&mut self, uid: u32) -> std::io::Result<()> {
            self.mutate(Op::SetUid(uid))
        }
        fn capset(&mut self, e: u64, p: u64, i: u64) -> std::io::Result<()> {
            self.mutate(Op::Capset(e, p, i))
        }
        fn ambient_clear_all(&mut self) -> std::io::Result<()> {
            self.mutate(Op::AmbientClearAll)
        }
        fn ambient_raise(&mut self, cap: u8) -> std::io::Result<()> {
            self.mutate(Op::AmbientRaise(cap))
        }
        fn get_keep_caps(&mut self) -> std::io::Result<bool> {
            self.ops.push(Op::GetKeepCaps);
            self.keep_after
                .ok_or_else(|| std::io::Error::from_raw_os_error(22))
        }
    }

    struct St<'a> {
        threads: &'a str,
        uid: &'a str,
        gid: &'a str,
        groups: &'a str,
        inh: &'a str,
        prm: &'a str,
        eff: &'a str,
        bnd: &'a str,
        amb: &'a str,
        nnp: &'a str,
    }

    impl St<'_> {
        fn render(&self) -> String {
            format!(
                "Name:\tx\nThreads:\t{}\nUid:\t{}\nGid:\t{}\nGroups:\t{}\nCapInh:\t{}\nCapPrm:\t{}\nCapEff:\t{}\nCapBnd:\t{}\nCapAmb:\t{}\nNoNewPrivs:\t{}\n",
                self.threads,
                self.uid,
                self.gid,
                self.groups,
                self.inh,
                self.prm,
                self.eff,
                self.bnd,
                self.amb,
                self.nnp
            )
        }
    }

    const MIN: &str = "0000000028201122";
    /// 最小集合 + `CAP_SETGID`（bit 6）。方式 (c) で補助グループを持つ利用者の file capability。
    const MIN_SETGID: &str = "0000000028201162";
    const NONE: &str = "0000000000000000";

    /// SUP-14・#2599: ランチャーの file capability の期待集合は最小集合 + `CAP_SETGID` ちょうど。
    #[test]
    fn sup14_launcher_file_capability_mask_is_exact() {
        assert_eq!(launcher_file_capability_mask(), 0x0000_0000_2820_1162);
        assert_eq!(launcher_file_capabilities().len(), 8);
        assert!(launcher_file_capabilities().contains(Capability::Setgid));
    }
    /// 方式 (a): real は非 root、effective / saved / fs が 0（setuid root を非 root が起動した状態）。
    const SETUID_UID: &str = "1000\t0\t0\t0";

    fn before_setuid() -> String {
        St {
            threads: "1",
            uid: SETUID_UID,
            gid: GID,
            groups: "",
            inh: NONE,
            prm: FULL,
            eff: FULL,
            bnd: FULL,
            amb: NONE,
            nnp: "0",
        }
        .render()
    }

    fn before_launcher() -> String {
        St {
            threads: "1",
            uid: UID,
            gid: GID,
            groups: "1000\t4",
            inh: NONE,
            prm: MIN_SETGID,
            eff: MIN_SETGID,
            bnd: FULL,
            amb: NONE,
            nnp: "0",
        }
        .render()
    }

    fn after_ok() -> String {
        St {
            threads: "1",
            uid: UID,
            gid: GID,
            groups: "",
            inh: MIN,
            prm: MIN,
            eff: MIN,
            bnd: MIN,
            amb: MIN,
            nnp: "0",
        }
        .render()
    }

    const MIN_MASK: u64 = 0x2820_1122;

    fn dropped_bounding() -> Vec<Op> {
        // FULL は番号 0..=40。最小集合 {1,5,8,12,21,27,29} 以外を昇順に落とす（CAP_SETPCAP=8 は残るため末尾移動なし）。
        (0u8..41)
            .filter(|i| !matches!(*i, 1 | 5 | 8 | 12 | 21 | 27 | 29))
            .map(Op::DropBounding)
            .collect()
    }

    fn ambient_ops() -> Vec<Op> {
        let mut v = vec![Op::AmbientClearAll];
        v.extend([1u8, 5, 8, 12, 21, 27, 29].map(Op::AmbientRaise));
        v
    }

    fn setuid_expected_ops() -> Vec<Op> {
        let mut v = vec![Op::ReadStatus, Op::SetGid(1000)];
        v.extend(dropped_bounding());
        v.extend([
            Op::KeepCaps(true),
            Op::SetUid(1000),
            Op::Capset(MIN_MASK, MIN_MASK, MIN_MASK),
        ]);
        v.extend(ambient_ops());
        v.extend([Op::KeepCaps(false), Op::GetKeepCaps, Op::ReadStatus]);
        v
    }

    /// SUP-14・TASK-171.1.3: 方式 (a) の適用順が `ReductionPlan::steps` どおりで、34 個の bounding 削除・7 個の ambient 載せが
    /// 具体値で一致し、結果が必要最小集合ちょうどになる。
    #[test]
    fn sup14_task171_1_3_setuid_applies_steps_in_order() {
        let mut k = FakeKernel::new(vec![before_setuid(), after_ok()]);
        let r = elevate_with(&mut k, PrivilegeMethod::SetuidRoot).unwrap();
        assert_eq!(k.ops, setuid_expected_ops());
        assert_eq!(dropped_bounding().len(), 34);
        assert_eq!(r.held, runtime_required_capabilities());
        assert_eq!(r.method, PrivilegeMethod::SetuidRoot);
        assert_eq!(r.uid.real, 1000);
    }

    /// SUP-14・TASK-171.1.3: 方式 (c) は uid 遷移が無いため keepcaps を使わず、補助グループの消去から始まる。
    #[test]
    fn sup14_task171_1_3_launcher_ambient_skips_keepcaps_and_clears_groups_first() {
        let mut k = FakeKernel::new(vec![before_launcher(), after_ok()]);
        let r = elevate_with(&mut k, PrivilegeMethod::LauncherAmbient).unwrap();
        let mut want = vec![Op::ReadStatus, Op::ClearGroups, Op::SetGid(1000)];
        want.extend(dropped_bounding());
        want.extend([Op::SetUid(1000), Op::Capset(MIN_MASK, MIN_MASK, MIN_MASK)]);
        want.extend(ambient_ops());
        want.extend([Op::GetKeepCaps, Op::ReadStatus]);
        assert_eq!(k.ops, want);
        assert_eq!(r.held, runtime_required_capabilities());
    }

    fn op_name(op: &Op) -> &'static str {
        match op {
            Op::ClearGroups => "setgroups",
            Op::SetGid(_) => "setresgid",
            Op::DropBounding(_) => "bounding drop",
            Op::KeepCaps(true) => "set keepcaps",
            Op::KeepCaps(false) => "clear keepcaps",
            Op::SetUid(_) => "setresuid",
            Op::Capset(..) => "capset",
            Op::AmbientClearAll => "ambient clear",
            Op::AmbientRaise(_) => "ambient raise",
            Op::ReadStatus | Op::GetKeepCaps => "read",
        }
    }

    /// SUP-14・TASK-171.1.3: 変更系の全手順で 1 つずつ失敗を注入すると、`Err` を返して後続の操作を一切呼ばない。
    /// keepcaps 設定後の失敗では解除を 1 回だけ試す。EPERM は `PermissionDenied`、それ以外は `Internal`。
    #[test]
    fn sup14_task171_1_3_every_step_failure_aborts_fail_closed() {
        let full: Vec<Op> = setuid_expected_ops()
            .into_iter()
            .filter(|o| !matches!(o, Op::ReadStatus | Op::GetKeepCaps))
            .collect();
        let keep_on = full.iter().position(|o| *o == Op::KeepCaps(true)).unwrap();
        let last = full.len() - 1;
        assert_eq!(full.len(), 1 + 34 + 1 + 1 + 1 + 8 + 1);
        for (i, failing) in full.iter().enumerate() {
            for (errno, code) in [(1, ErrorCode::PermissionDenied), (12, ErrorCode::Internal)] {
                let mut k = FakeKernel::new(vec![before_setuid(), after_ok()]);
                k.fail_nth = Some((i, errno));
                let e = elevate_with(&mut k, PrivilegeMethod::SetuidRoot).unwrap_err();
                assert_eq!(e.reason, PrivilegeErrorReason::SyscallFailed, "step {i}");
                assert_eq!(e.code, code, "step {i}");
                assert_eq!(
                    e.message,
                    format!("{} failed (errno {errno})", op_name(failing)),
                    "step {i}"
                );
                let mut want = vec![Op::ReadStatus];
                want.extend(full.iter().take(i + 1).cloned());
                if i > keep_on && i != last {
                    want.push(Op::KeepCaps(false));
                }
                assert_eq!(k.ops, want, "step {i}");
            }
        }
    }

    /// SUP-14・TASK-171.1.3: 事前条件で拒否するときは何も変更しない（記録されるのは ReadStatus の 1 件だけ）。
    #[test]
    fn sup14_task171_1_3_precondition_rejections_change_nothing() {
        let mk = |threads: &str, uid: &str, caps: &str, nnp: &str| {
            St {
                threads,
                uid,
                gid: GID,
                groups: "",
                inh: NONE,
                prm: caps,
                eff: caps,
                bnd: FULL,
                amb: NONE,
                nnp,
            }
            .render()
        };
        let root = "0\t0\t0\t0";
        let cases: Vec<(String, PrivilegeMethod, PrivilegeErrorReason, ErrorCode)> = vec![
            (
                mk("2", SETUID_UID, FULL, "0"),
                PrivilegeMethod::SetuidRoot,
                PrivilegeErrorReason::MultiThreaded,
                ErrorCode::FailedPrecondition,
            ),
            (
                before_setuid().replace("Threads:\t1\n", ""),
                PrivilegeMethod::SetuidRoot,
                PrivilegeErrorReason::MultiThreaded,
                ErrorCode::FailedPrecondition,
            ),
            (
                mk("1", root, FULL, "0"),
                PrivilegeMethod::LauncherAmbient,
                PrivilegeErrorReason::MethodMismatch,
                ErrorCode::FailedPrecondition,
            ),
            (
                mk("1", UID, FULL, "0"),
                PrivilegeMethod::SetuidRoot,
                PrivilegeErrorReason::MethodMismatch,
                ErrorCode::FailedPrecondition,
            ),
            (
                mk("1", root, FULL, "0"),
                PrivilegeMethod::SetuidRoot,
                PrivilegeErrorReason::MethodMismatch,
                ErrorCode::FailedPrecondition,
            ),
            (
                mk("1", UID, NONE, "0"),
                PrivilegeMethod::LauncherAmbient,
                PrivilegeErrorReason::MissingCapabilities,
                ErrorCode::PermissionDenied,
            ),
            (
                mk("1", UID, FULL, "1"),
                PrivilegeMethod::LauncherAmbient,
                PrivilegeErrorReason::NoNewPrivsSet,
                ErrorCode::FailedPrecondition,
            ),
        ];
        for (n, (text, method, reason, code)) in cases.into_iter().enumerate() {
            let mut k = FakeKernel::new(vec![text]);
            let e = elevate_with(&mut k, method).unwrap_err();
            assert_eq!(e.reason, reason, "case {n}");
            assert_eq!(e.code, code, "case {n}");
            assert_eq!(k.ops, vec![Op::ReadStatus], "case {n}");
        }
    }

    /// SUP-14・TASK-171.1.3: 状態を読めないときも単一スレッドと認めず、何も変更しない。
    #[test]
    fn sup14_task171_1_3_unreadable_status_is_rejected() {
        let mut k = FakeKernel::new(Vec::new());
        let e = elevate_with(&mut k, PrivilegeMethod::SetuidRoot).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::MultiThreaded);
        assert_eq!(k.ops, vec![Op::ReadStatus]);
    }

    /// SUP-14・TASK-171.1.3: 読み戻しの不一致（過剰 capability・keepcaps 残存 / 未確認・スレッド増加）は `Ok` にしない。
    #[test]
    fn sup14_task171_1_3_readback_rejections() {
        let excess = after_ok().replace("CapBnd:\t0000000028201122", "CapBnd:\t000001ffffffffff");
        let mut k = FakeKernel::new(vec![before_setuid(), excess]);
        let e = elevate_with(&mut k, PrivilegeMethod::SetuidRoot).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::ExcessCapabilities);
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert_eq!(k.ops.last(), Some(&Op::ReadStatus));

        let mut k = FakeKernel::new(vec![before_setuid(), after_ok()]);
        k.keep_after = Some(true);
        let e = elevate_with(&mut k, PrivilegeMethod::SetuidRoot).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::KeepCapsRetained);
        assert_eq!(e.code, ErrorCode::PermissionDenied);

        let mut k = FakeKernel::new(vec![before_setuid(), after_ok()]);
        k.keep_after = None;
        let e = elevate_with(&mut k, PrivilegeMethod::SetuidRoot).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::KeepCapsRetained);
        assert_eq!(e.code, ErrorCode::FailedPrecondition);

        let threaded = after_ok().replace("Threads:\t1\n", "Threads:\t3\n");
        let mut k = FakeKernel::new(vec![before_setuid(), threaded]);
        let e = elevate_with(&mut k, PrivilegeMethod::SetuidRoot).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::MultiThreaded);
    }

    /// SUP-14・TASK-171.1.3: `Threads:` 行の境界（欠落・非数値・重複・上限超過）は `None`。
    #[test]
    fn sup14_task171_1_3_parse_thread_count_boundaries() {
        assert_eq!(parse_thread_count("Name:\tx\nThreads:\t1\n"), Some(1));
        assert_eq!(parse_thread_count("Threads:\t12\n"), Some(12));
        assert_eq!(parse_thread_count("Name:\tx\n"), None);
        assert_eq!(parse_thread_count("Threads:\tabc\n"), None);
        assert_eq!(parse_thread_count("Threads:\t+1\n"), None);
        assert_eq!(parse_thread_count("Threads:\t\n"), None);
        assert_eq!(parse_thread_count("Threads:\t1\nThreads:\t1\n"), None);
        let long = format!("Threads:\t1\n{}", "x".repeat(MAX_STATUS_BYTES));
        assert_eq!(parse_thread_count(&long), None);
        let many = format!("{}Threads:\t1\n", "a\n".repeat(MAX_STATUS_LINES));
        assert_eq!(parse_thread_count(&many), None);
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
/// セッション切り離しの単体テスト（SUP-14・TASK-171.2・#537）。偽の kernel で手順と失敗注入を具体値で照合する。
#[cfg(test)]
mod session_tests {
    use super::*;

    const NO_TTY: StdioTerminals = StdioTerminals {
        stdin: false,
        stdout: false,
        stderr: false,
    };

    fn stat(pid: u32, pgrp: u32, sid: u32, tty: i64) -> String {
        format!(
            "{pid} (fandhe) S 1 {pgrp} {sid} {tty} -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 5 1000 50\n"
        )
    }

    fn snap(pid: u32, pgrp: u32, session: u32, tty_nr: i64) -> SessionSnapshot {
        SessionSnapshot {
            pid,
            pgrp,
            session,
            tty_nr,
        }
    }

    #[test]
    fn sup14_task171_2_parse_proc_stat_values() {
        assert_eq!(
            parse_proc_stat(&stat(4242, 4242, 4242, 0)).unwrap(),
            snap(4242, 4242, 4242, 0)
        );
        assert_eq!(
            parse_proc_stat(&stat(10, 20, 30, 34816)).unwrap(),
            snap(10, 20, 30, 34816)
        );
        // comm に空白と ')' を含んでも最後の ')' で分割する。
        let tricky = "77 (a) (b c) S 1 77 77 0 -1 0\n";
        assert_eq!(parse_proc_stat(tricky).unwrap(), snap(77, 77, 77, 0));
    }

    #[test]
    fn sup14_task171_2_parse_proc_stat_rejects_malformed() {
        let big = format!("1 (x) S 1 1 1 0 {}", "0 ".repeat(MAX_STAT_BYTES));
        let cases = [
            "",
            "1 x S 1 1 1 0",
            "1 (x S 1 1 1 0",
            "abc (x) S 1 1 1 0",
            "1 (x) S 1 1",
            "1 (x) S 1 q 1 0",
            "1 (x) S 1 1 -2 0",
            "1 (x) S 1 1 1 zz",
            ") (",
            big.as_str(),
        ];
        for c in cases {
            let e = parse_proc_stat(c).unwrap_err();
            assert_eq!(e.reason, PrivilegeErrorReason::MalformedStatus, "{c:?}");
            assert_eq!(e.code, ErrorCode::FailedPrecondition, "{c:?}");
        }
    }

    #[test]
    fn sup14_task171_2_verify_session_detached_ok_and_rejects() {
        assert!(verify_session_detached(&snap(5, 5, 5, 0), NO_TTY).is_ok());
        for (i, t) in [
            StdioTerminals {
                stdin: true,
                ..NO_TTY
            },
            StdioTerminals {
                stdout: true,
                ..NO_TTY
            },
            StdioTerminals {
                stderr: true,
                ..NO_TTY
            },
        ]
        .into_iter()
        .enumerate()
        {
            let e = verify_session_detached(&snap(5, 5, 5, 0), t).unwrap_err();
            assert_eq!(e.reason, PrivilegeErrorReason::StdioIsTerminal, "fd {i}");
            assert_eq!(e.code, ErrorCode::FailedPrecondition);
        }
        let e = verify_session_detached(&snap(5, 5, 5, 34816), NO_TTY).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::ControllingTerminalAttached);
        let e = verify_session_detached(&snap(5, 5, 4, 0), NO_TTY).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::NotSessionLeader);
        let e = verify_session_detached(&snap(5, 4, 5, 0), NO_TTY).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::NotSessionLeader);
    }

    struct Fake {
        stdio: StdioTerminals,
        setsid: Option<i32>,
        stat: Result<String, i32>,
        setsid_calls: u32,
    }

    impl SessionKernel for Fake {
        fn stdio_terminals(&mut self) -> StdioTerminals {
            self.stdio
        }
        fn setsid(&mut self) -> std::io::Result<()> {
            self.setsid_calls += 1;
            match self.setsid {
                None => Ok(()),
                Some(errno) => Err(std::io::Error::from_raw_os_error(errno)),
            }
        }
        fn read_self_stat(&mut self) -> std::io::Result<String> {
            match &self.stat {
                Ok(s) => Ok(s.clone()),
                Err(errno) => Err(std::io::Error::from_raw_os_error(*errno)),
            }
        }
    }

    fn fake(setsid: Option<i32>, stat_text: String) -> Fake {
        Fake {
            stdio: NO_TTY,
            setsid,
            stat: Ok(stat_text),
            setsid_calls: 0,
        }
    }

    #[test]
    fn sup14_task171_2_detach_with_terminal_stdio_never_calls_setsid() {
        let mut k = fake(None, stat(9, 9, 9, 0));
        k.stdio.stdout = true;
        let e = detach_session_with(&mut k).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::StdioIsTerminal);
        assert_eq!(k.setsid_calls, 0);
    }

    #[test]
    fn sup14_task171_2_detach_succeeds_after_setsid() {
        let mut k = fake(None, stat(9, 9, 9, 0));
        assert_eq!(detach_session_with(&mut k).unwrap(), snap(9, 9, 9, 0));
        assert_eq!(k.setsid_calls, 1);
    }

    #[test]
    fn sup14_task171_2_detach_eperm_is_ok_only_when_already_detached() {
        // EPERM かつ既に自分のセッションのリーダーで制御端末なし: 成功。
        let mut k = fake(Some(EPERM), stat(9, 9, 9, 0));
        assert_eq!(detach_session_with(&mut k).unwrap(), snap(9, 9, 9, 0));
        // EPERM かつ別セッション: 拒否。
        let mut k = fake(Some(EPERM), stat(9, 9, 3, 0));
        let e = detach_session_with(&mut k).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::NotSessionLeader);
        // EPERM かつ制御端末あり: 拒否。
        let mut k = fake(Some(EPERM), stat(9, 9, 9, 34816));
        let e = detach_session_with(&mut k).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::ControllingTerminalAttached);
    }

    #[test]
    fn sup14_task171_2_detach_other_errno_and_read_failures() {
        let mut k = fake(Some(22), stat(9, 9, 9, 0));
        let e = detach_session_with(&mut k).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::SyscallFailed);
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.message, "setsid failed (errno 22)");
        let mut k = fake(None, String::new());
        k.stat = Err(5);
        let e = detach_session_with(&mut k).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::SyscallFailed);
        assert_eq!(e.message, "reading process stat failed (errno 5)");
        let mut k = fake(None, "garbage".to_owned());
        let e = detach_session_with(&mut k).unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::MalformedStatus);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn sup14_task171_2_detach_is_unimplemented_off_linux() {
        let e = detach_session().unwrap_err();
        assert_eq!(e.reason, PrivilegeErrorReason::Unimplemented);
        assert_eq!(e.code, ErrorCode::Unimplemented);
    }
}
