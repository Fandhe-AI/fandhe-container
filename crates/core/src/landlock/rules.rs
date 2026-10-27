//! Landlock ファイルパスアクセス制御ルールの生成（CORE-5・TASK-39.2・#182。Linux 限定）。
//!
//! # 役割
//!
//! 検証済みの `OciConfig`（`root` と `mounts`）と検出済みの [`LandlockSupport`] から、Landlock へ渡す
//! handled access マスクとパスごとの許可ルール列を純粋関数で導出する。syscall は行わない。
//!
//! # 呼び出し文脈・契約（#183・#184 向け）
//!
//! - ルールのパスは pivot_root 後のコンテナ内パスである（Landlock 段は `exec/stages.rs` で pivot 後・exec 前）。
//!   rootfs は [`RulePath::Root`]（`/`）、mount は正規化済みの `destination` のみ。ホスト側パスは含めない
//! - #183（TASK-39.3）は各パスを `O_PATH` で開いて追加する。開いた fd がディレクトリでない場合
//!   （bind mount された単一ファイル）は、[`AccessFs::FILE_COMPATIBLE`] と積を取ってから追加すること
//!   （ディレクトリ専用の権利を付けると `landlock_add_rule` が EINVAL になる）。本モジュールは stat しない
//! - Landlock は加算的で、祖先より狭い権利を子に強制できない。書き込み系（[`AccessFs::WRITE`]）の制限が
//!   祖先ルールで無効になる構成（書き込み可能な root の下の `ro` mount・疑似 FS 等）は、最小権限を
//!   保証できないため [`LandlockRuleErrorKind::WriteRestrictionShadowed`] で拒否する（fail-closed。CORE-5）。
//!   疑似 FS の書き込み禁止は VFS の裏付けが無く Landlock だけが担うため、記録だけでは守れない。
//!   例外は**検証済みの `ro` の bind mount**（`BindMountSet` に同じ `index` の spec があり `read_only()` で、宛先が一致し、
//!   ルール自身が `WRITE` を持たないもの。#1917・#1910 の決定 B）だけで、書き込みの禁止は実際に載せた bind の VFS の
//!   読み取り専用属性が担い、ここでは [`ShadowBacking::ReadOnlyBind`] として記録する（監査用。適用時に VFS の ro を確かめる
//!   のは `apply`）。config だけを受ける入口は空の集合を渡すため、`ro` の bind はこれまでどおり拒否する
//! - 実行・`IOCTL_DEV` だけが祖先で広がる箇所（`/dev` 配下の `noexec,nodev` mount 等）は、VFS の
//!   `noexec` / `nodev` が必ず効くため許容し、[`LandlockRuleset::shadowed`] に記録する（監査は TASK-41・SEC-4）
//! - 暗黙の固定集合（`/dev`・`/dev/pts`・`/dev/shm`。オーナー判断 #1609）は `mounts[]` に関係なく常に載るため、
//!   [`crate::dev_mounts`] の定義（実マウントの属性）から導いた権利のルールを rootfs の次に足す（#1657）。
//!   `mounts[]` が同じマウント先を指す場合は拒否する（固定集合と一致する項目を供給済みとして受ける統合は、TASK-29 追補の #1910 の判断で見送り。受けるかは #2347 で判断待ち、docs/design/oci-mounts-implicit-entries.md）
//! - `/sys` の sysfs（`mounts[]`。#2020）はルールを作らない（実効の権利は root と同じ。書き込みの禁止は VFS の ro が担う。
//!   理由は `build_path_rules_with_dev` の実装コメント）
//! - `linux.readonlyPaths` / `maskedPaths` は参照しない（VFS のマウントが担うためルールは足さない。解釈は
//!   `OciConfig::readonly_paths` / `masked_paths`、適用は `exec` の pivot 前段。#1852）。暗黙の `/dev` 系と同じか
//!   祖先を指す保護パスは、ここ（予約・fork の後）ではなく start が fork 前に `InvalidArgument` で拒否する（#2015）
//!
//! # 未実装範囲（REPAIR-3）
//!
//! ステージ列への組み込み口（`with_landlock`・#184）は実装済み（`landlock_add_rule` / `landlock_restrict_self` による適用は
//! #183・`apply` 子モジュールで実装済み）。
//! GPU 向けの権利拡張は TASK-128（GPU-3）が後から追加する。

use std::fmt;

use super::{LandlockAuditMode, LandlockSupport, landlock_audit_mode_for_abi};
use crate::dev_mounts::{IMPLICIT_DEV_MOUNT_COUNT, ImplicitDevMount, ImplicitDevMounts};
use crate::oci_runtime::{
    BindMountSet, CONFIG_MAX_MOUNTS, CONFIG_MAX_PATH_BYTES, MountDestination, OciConfig, OciMount,
    OciMountKind, OciRoot,
};
use crate::tmpfs::TMPFS_MAX_MOUNTS;
use crate::traits::ErrorCode;

/// 生成するルール本数の上限（mount 上限 + rootfs 1 本 + 暗黙の `/dev` 系 3 本。DoS 防止）。
///
/// 利用者指定の tmpfs（`--tmpfs`。上限 [`TMPFS_MAX_MOUNTS`]）は `mounts[]` とは別枠で数える（SUP-12・CORE-5・#2625）。
pub const MAX_LANDLOCK_RULES: usize =
    CONFIG_MAX_MOUNTS + TMPFS_MAX_MOUNTS + 1 + IMPLICIT_DEV_MOUNT_COUNT;

/// Landlock の fs アクセス権ビット集合。既知の 16 ビット以外を表現できない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessFs(u64);

impl AccessFs {
    /// 権利なし。
    pub const EMPTY: Self = Self(0);
    /// `LANDLOCK_ACCESS_FS_EXECUTE`。
    pub const EXECUTE: Self = Self(1 << 0);
    /// `LANDLOCK_ACCESS_FS_WRITE_FILE`。
    pub const WRITE_FILE: Self = Self(1 << 1);
    /// `LANDLOCK_ACCESS_FS_READ_FILE`。
    pub const READ_FILE: Self = Self(1 << 2);
    /// `LANDLOCK_ACCESS_FS_READ_DIR`。
    pub const READ_DIR: Self = Self(1 << 3);
    /// `LANDLOCK_ACCESS_FS_REMOVE_DIR`。
    pub const REMOVE_DIR: Self = Self(1 << 4);
    /// `LANDLOCK_ACCESS_FS_REMOVE_FILE`。
    pub const REMOVE_FILE: Self = Self(1 << 5);
    /// `LANDLOCK_ACCESS_FS_MAKE_CHAR`。
    pub const MAKE_CHAR: Self = Self(1 << 6);
    /// `LANDLOCK_ACCESS_FS_MAKE_DIR`。
    pub const MAKE_DIR: Self = Self(1 << 7);
    /// `LANDLOCK_ACCESS_FS_MAKE_REG`。
    pub const MAKE_REG: Self = Self(1 << 8);
    /// `LANDLOCK_ACCESS_FS_MAKE_SOCK`。
    pub const MAKE_SOCK: Self = Self(1 << 9);
    /// `LANDLOCK_ACCESS_FS_MAKE_FIFO`。
    pub const MAKE_FIFO: Self = Self(1 << 10);
    /// `LANDLOCK_ACCESS_FS_MAKE_BLOCK`。
    pub const MAKE_BLOCK: Self = Self(1 << 11);
    /// `LANDLOCK_ACCESS_FS_MAKE_SYM`。
    pub const MAKE_SYM: Self = Self(1 << 12);
    /// `LANDLOCK_ACCESS_FS_REFER`（ABI 2+）。
    pub const REFER: Self = Self(1 << 13);
    /// `LANDLOCK_ACCESS_FS_TRUNCATE`（ABI 3+）。
    pub const TRUNCATE: Self = Self(1 << 14);
    /// `LANDLOCK_ACCESS_FS_IOCTL_DEV`（ABI 5+）。
    pub const IOCTL_DEV: Self = Self(1 << 15);

    /// 既知の全 fs 権利（ABI 5 以上）。
    pub const ALL: Self = Self(0xFFFF);
    /// 読み取り系（実行・ファイル読み取り・ディレクトリ列挙）。
    pub const READ: Self = Self(Self::EXECUTE.0 | Self::READ_FILE.0 | Self::READ_DIR.0);
    /// 書き込み系。`MAKE_CHAR` / `MAKE_BLOCK` / `IOCTL_DEV` は含めない。
    pub const WRITE: Self = Self(
        Self::WRITE_FILE.0
            | Self::REMOVE_DIR.0
            | Self::REMOVE_FILE.0
            | Self::MAKE_DIR.0
            | Self::MAKE_REG.0
            | Self::MAKE_SOCK.0
            | Self::MAKE_FIFO.0
            | Self::MAKE_SYM.0
            | Self::REFER.0
            | Self::TRUNCATE.0,
    );
    /// ディレクトリ以外の対象に付けてよい権利。
    pub const FILE_COMPATIBLE: Self = Self(
        Self::EXECUTE.0
            | Self::WRITE_FILE.0
            | Self::READ_FILE.0
            | Self::TRUNCATE.0
            | Self::IOCTL_DEV.0,
    );

    /// ビット値を返す。
    pub fn bits(self) -> u64 {
        self.0
    }

    /// ビット値から作る。既知の 16 ビットの外を含む値は `None`（`state.json` の launch 記録を untrusted として
    /// 読み戻すときの検証。TASK-163 追補・#1468）。
    pub(crate) fn from_bits(bits: u64) -> Option<Self> {
        (bits & !Self::ALL.0 == 0).then_some(Self(bits))
    }

    /// `other` のすべてのビットを含むか。
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// 和集合。
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// 積集合。
    pub fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// `other` を除いた集合。
    pub fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// `other` の部分集合か。
    pub fn is_subset_of(self, other: Self) -> bool {
        other.contains(self)
    }

    /// 空集合か。
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// ABI ごとの handled access（ルールに無い権利は既定拒否になる）。
pub(crate) fn handled_for_abi(abi: u32) -> AccessFs {
    let mut h = AccessFs(0x1FFF);
    if abi >= 2 {
        h = h.union(AccessFs::REFER);
    }
    if abi >= 3 {
        h = h.union(AccessFs::TRUNCATE);
    }
    if abi >= 5 {
        h = h.union(AccessFs::IOCTL_DEV);
    }
    h
}

/// ルール対象パス（コンテナ内パス。pivot_root 後）。生文字列を持たない。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RulePath {
    /// rootfs（`/`）。
    Root,
    /// mount の destination（正規化済み）。
    Beneath(MountDestination),
    /// ランタイムが暗黙に載せるマウントの宛先（静的なパス。#1657）。
    ImplicitDev(ImplicitDevMount),
}

impl RulePath {
    /// コンテナ内パス文字列。
    pub fn as_str(&self) -> &str {
        match self {
            Self::Root => "/",
            Self::Beneath(d) => d.as_str(),
            Self::ImplicitDev(m) => m.destination(),
        }
    }
}

/// ルールの由来（監査・将来拡張用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleOrigin {
    /// config の `root`。
    Root,
    /// config の `mounts[index]`。
    Mount {
        /// `mounts` 内の位置。
        index: usize,
    },
    /// 利用者指定の tmpfs（`--tmpfs`。tmpfs の段が載せた同じ宛先のマウントと照合する。SUP-12・CORE-5・#2625）。
    UserTmpfs,
    /// ランタイムが暗黙に載せるマウント（`/dev`・`/dev/pts`・`/dev/shm`。#1657）。
    Implicit {
        /// 対象のマウント。
        mount: ImplicitDevMount,
    },
}

/// パス 1 件分の許可ルール。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PathRule {
    /// 対象パス。
    pub path: RulePath,
    /// 許可する権利。
    pub allowed: AccessFs,
    /// 由来。
    pub origin: RuleOrigin,
}

/// Landlock では狭められない制限（祖先ルールがより広い権利を与えている）。
///
/// 書き込み系の権利が広がる場合は、検証済みの `ro` の bind（[`ShadowBacking::ReadOnlyBind`]）を除き記録せず拒否する
/// （[`LandlockRuleErrorKind::WriteRestrictionShadowed`]）。それ以外に残るのは VFS の `noexec` / `nodev` が保護する
/// 実行・`IOCTL_DEV` の差分（[`ShadowBacking::VfsExecDev`]）だけである。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ShadowedRestriction {
    /// 対象パス。
    pub path: RulePath,
    /// config が意図する権利。
    pub intended: AccessFs,
    /// 祖先ルールの和集合に対象ルール自身の許可を加えたもの（実際に効く権限）。
    pub effective: AccessFs,
    /// Landlock で狭められない分を実際に止める裏付け。
    pub backing: ShadowBacking,
}

/// [`ShadowedRestriction`] の制限を実際に担う裏付け（CORE-5・SEC-4・#1917）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShadowBacking {
    /// VFS の `noexec` / `nodev`（実行・`IOCTL_DEV` の差分）。
    VfsExecDev,
    /// 検証済みの `ro` の bind mount の VFS の読み取り専用属性（書き込みの差分。`index` は `mounts[]` の位置）。
    ReadOnlyBind {
        /// config の `mounts` 内の位置。
        index: usize,
    },
}

/// 生成結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LandlockRuleset {
    handled_access_fs: AccessFs,
    rules: Vec<PathRule>,
    shadowed: Vec<ShadowedRestriction>,
    /// カーネル監査へ拒否を残す要求の可否（SEC-4・#2026）。
    audit: LandlockAuditMode,
}

impl LandlockRuleset {
    /// 結合試験用観測関数 `observe_landlock_enforcement` と単体テストが、config を経由せず ABI から
    /// handled access を決めて組み立てる（CORE-5・TASK-39.3・#183。公開 API は増やさない）。
    pub(crate) fn for_observation(abi: u32, rules: Vec<PathRule>) -> Self {
        Self {
            handled_access_fs: handled_for_abi(abi),
            rules,
            shadowed: Vec::new(),
            audit: landlock_audit_mode_for_abi(abi),
        }
    }

    /// launch 時に記録した handled access とルールから組み直す（exec の再適用用。TASK-163 追補・#1468）。
    ///
    /// ABI の再検出も `config.json` の再解釈もしない。今のカーネルの ABI から handled を計算し直すと、launch の
    /// handled に無かった権利が無制限になり launch と意味が変わるため、**記録した `handled` をそのまま使う**。
    /// `shadowed` は適用に使わない監査用の情報なので空にする。`audit` は記録ではなく**今のカーネルの ABI**から
    /// 呼び出し側が決めて渡す（ログ制御フラグは今のカーネルが受けるかで決まる。SEC-4・#2026）。入力の検証は呼び出し側
    /// （`launch_isolation::RecordedLandlock::validate`）が済ませている前提。
    pub(crate) fn from_recorded(
        handled: AccessFs,
        rules: Vec<PathRule>,
        audit: LandlockAuditMode,
    ) -> Self {
        Self {
            handled_access_fs: handled,
            rules,
            shadowed: Vec::new(),
            audit,
        }
    }

    /// カーネル監査へ拒否を残す要求のモード（`landlock_restrict_self` の flags はこれで決まる。SEC-4・#2026）。
    pub fn audit_mode(&self) -> LandlockAuditMode {
        self.audit
    }

    /// ruleset 属性へ渡す handled access。
    pub fn handled_access_fs(&self) -> AccessFs {
        self.handled_access_fs
    }

    /// パスごとのルール（先頭が rootfs、次に暗黙の `/dev` 系、以降は config 順。後のマウントに覆い隠されたマウントは含めない）。
    pub fn rules(&self) -> &[PathRule] {
        &self.rules
    }

    /// Landlock で狭められない制限の記録。
    pub fn shadowed(&self) -> &[ShadowedRestriction] {
        &self.shadowed
    }
}

/// 生成失敗の分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LandlockRuleErrorKind {
    /// ルール本数が上限超過。
    TooManyRules {
        /// 要求本数。
        count: usize,
        /// 上限。
        max: usize,
    },
    /// パス長が上限超過。
    PathTooLong {
        /// 実長（バイト）。
        len: usize,
        /// 上限。
        max: usize,
    },
    /// 内部不変条件違反（handled 超過・MAKE_CHAR / MAKE_BLOCK 付与）。
    RightsExceedHandled,
    /// mount が拒否する書き込み系の権利を祖先ルールが許可しており、Landlock で狭められない。
    WriteRestrictionShadowed {
        /// config の `mounts` 内の位置。
        index: usize,
        /// 祖先ルールによって許可されてしまう書き込み系の権利。
        granted: AccessFs,
    },
    /// `mounts[index]` が暗黙の固定集合（`/dev`・`/dev/pts`・`/dev/shm`）と同じマウント先を指している。
    /// 後勝ちで統合すると固定集合が黙って崩れるため拒否する（統合は TASK-29 追補の #1910 の判断で見送り。受けるかは #2347 で判断待ち、docs/design/oci-mounts-implicit-entries.md）。
    ImplicitMountConflict {
        /// config の `mounts` 内の位置。
        index: usize,
    },
    /// 検証済みの bind の集合と `mounts[]` の解釈が食い違う（宛先の不一致、`ro` の spec なのにルールが `WRITE` を持つ）。
    /// 2 つの解釈の不整合は内部不変条件違反として拒否する（fail-closed。#1917）。
    VerifiedBindMismatch {
        /// config の `mounts` 内の位置。
        index: usize,
    },
    /// 許容した `ro` の bind の宛先より下に、書き込み可能なルールがある（読み取り専用が見かけだけになる）。
    WritableBeneathReadOnlyBind {
        /// 上位の `ro` の bind の `mounts` 内の位置。
        index: usize,
    },
}

impl LandlockRuleErrorKind {
    /// 機械可読な理由コード（ERR-1。`exec` 側のエラー写像の message に含める）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TooManyRules { .. } => "too_many_rules",
            Self::PathTooLong { .. } => "path_too_long",
            Self::RightsExceedHandled => "rights_exceed_handled",
            Self::WriteRestrictionShadowed { .. } => "write_restriction_shadowed",
            Self::ImplicitMountConflict { .. } => "implicit_mount_conflict",
            Self::VerifiedBindMismatch { .. } => "verified_bind_mismatch",
            Self::WritableBeneathReadOnlyBind { .. } => "writable_beneath_read_only_bind",
        }
    }
}

/// ルール生成の明示エラー。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LandlockRuleError {
    /// 構造化エラーコード（ERR 系）。
    pub code: ErrorCode,
    /// 分類。
    pub kind: LandlockRuleErrorKind,
    /// 人間向け説明（英語。入力パスは含めない）。
    pub message: String,
}

impl LandlockRuleError {
    fn new(kind: LandlockRuleErrorKind) -> Self {
        let (code, message) = match kind {
            LandlockRuleErrorKind::TooManyRules { count, max } => (
                ErrorCode::InvalidArgument,
                format!("too many Landlock rules: {count} exceeds limit {max}"),
            ),
            LandlockRuleErrorKind::PathTooLong { len, max } => (
                ErrorCode::InvalidArgument,
                format!("Landlock rule path is {len} bytes, exceeds limit {max}"),
            ),
            LandlockRuleErrorKind::RightsExceedHandled => (
                ErrorCode::Internal,
                "generated Landlock rights violate internal invariants".to_string(),
            ),
            LandlockRuleErrorKind::WriteRestrictionShadowed { index, granted } => (
                ErrorCode::InvalidArgument,
                format!(
                    "mounts[{index}] denies write access 0x{:x} that an ancestor Landlock rule \
                     grants; use a read-only root or a writable parent mount",
                    granted.bits()
                ),
            ),
            LandlockRuleErrorKind::ImplicitMountConflict { index } => (
                ErrorCode::InvalidArgument,
                format!(
                    "mounts[{index}] targets a mount point the runtime provides implicitly \
                     (/dev, /dev/pts or /dev/shm)"
                ),
            ),
            LandlockRuleErrorKind::VerifiedBindMismatch { index } => (
                ErrorCode::Internal,
                format!("mounts[{index}] disagrees with the verified bind mount set"),
            ),
            LandlockRuleErrorKind::WritableBeneathReadOnlyBind { index } => (
                ErrorCode::InvalidArgument,
                format!("a writable rule lies beneath the read-only bind mounts[{index}]"),
            ),
        };
        Self {
            code,
            kind,
            message,
        }
    }
}

impl fmt::Display for LandlockRuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for LandlockRuleError {}

/// カーネル疑似 FS（書き込み権を Landlock 側でも付けない）。
///
/// devpts は含めない。pty のスレーブへの書き込みには `WRITE_FILE` が要り、devpts に置けるのはカーネルが作る
/// pty ノードだけで `WRITE` の `MAKE_*`・`REMOVE_*` 等は VFS 側で効かない（書き込み制限に VFS の裏付けがある）。
/// 含めると将来の明示の devpts mount が読み取り専用になり、書き込み可能な祖先の下で
/// `WriteRestrictionShadowed` で拒否されてしまう（#1657）。
const PSEUDO_FS: [&str; 8] = [
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "securityfs",
    "debugfs",
    "tracefs",
    "bpf",
];

fn root_rights(readonly: bool) -> AccessFs {
    if readonly {
        AccessFs::READ
    } else {
        AccessFs::READ.union(AccessFs::WRITE)
    }
}

/// 暗黙マウントの権利。実マウントの属性（[`ImplicitDevMount::attrs`]）から導き、実マウントより広くしない。
/// `MAKE_CHAR` / `MAKE_BLOCK` は付けない。
fn implicit_rights(m: ImplicitDevMount) -> AccessFs {
    let a = m.attrs();
    let mut rights = AccessFs::READ;
    if !a.read_only {
        rights = rights.union(AccessFs::WRITE);
    }
    if a.noexec {
        rights = rights.difference(AccessFs::EXECUTE);
    }
    if !a.nodev && is_dev_path(m.destination()) {
        rights = rights.union(AccessFs::IOCTL_DEV);
    }
    rights
}

fn is_dev_path(p: &str) -> bool {
    p == "/dev" || p.starts_with("/dev/")
}

/// 相反する mount オプション 1 組（例: `ro` / `rw`）の最終値。
///
/// mount(8) は相反するオプションが並ぶと後の指定が勝つ（the last option wins）。OCI Runtime Spec の
/// Mount Options も各オプションをフラグの設定 / 解除として順に適用するため、同じ規則になる。
/// 再帰版（`rro` 等。runtime-spec 1.1）はマウント後に `mount_setattr(2)`（`AT_RECURSIVE`）で適用されるため、
/// 位置に関係なく非再帰版より後に効き、再帰版同士では後勝ちになる（runc と同じ解釈）。
#[derive(Clone, Copy, Default)]
struct MountFlagToggle {
    /// 非再帰版の最後の指定（`true` は許可側）。
    plain: Option<bool>,
    /// 再帰版の最後の指定（`true` は許可側）。
    recursive: Option<bool>,
}

impl MountFlagToggle {
    /// 指定が無ければ `default`（カーネルの既定）を返す。
    fn resolve(self, default: bool) -> bool {
        self.recursive.or(self.plain).unwrap_or(default)
    }
}

/// mount 1 件が意図する権利（config の options / fs_type / destination から導出）。
///
/// 許可側のオプション（`rw`・`exec`・`dev`）が後から来て制限を解除する場合も、実際のマウントはその権利を
/// 許すため Landlock でも許可する。これは config が明示的に開けた権利を反映するだけで、実マウントより
/// 広い権利は付けない（CORE-5 の「最小セットから明示的に開ける」と矛盾しない）。VFS より狭くする
/// 規則（疑似 FS の書き込み禁止・`/dev` 外の `IOCTL_DEV` 不許可・`MAKE_CHAR` / `MAKE_BLOCK` 不許可）は
/// オプションに関係なく維持する。
/// `nosuid` / `suid` と `defaults`（runtime-spec ではフラグ 0 の no-op）は対応する Landlock の権利が
/// 無いため権利に影響しない。
///
/// bind mount の `ro`/`rw`・`noexec`/`exec` の畳み込みは `oci_runtime::bind_mounts`（#1911）と同じ読みで、
/// 本ファイルのテスト `core5_landlock_bind_interpretation_matches` が両者を照合する。解釈を変えるときは
/// もう一方と照合試験を更新する。
fn mount_rights(m: &OciMount) -> AccessFs {
    let mut write = MountFlagToggle::default();
    let mut exec = MountFlagToggle::default();
    let mut dev = MountFlagToggle::default();
    for opt in m.options() {
        match opt.as_str() {
            "ro" => write.plain = Some(false),
            "rw" => write.plain = Some(true),
            "noexec" => exec.plain = Some(false),
            "exec" => exec.plain = Some(true),
            "nodev" => dev.plain = Some(false),
            "dev" => dev.plain = Some(true),
            "rro" => write.recursive = Some(false),
            "rrw" => write.recursive = Some(true),
            "rnoexec" => exec.recursive = Some(false),
            "rexec" => exec.recursive = Some(true),
            "rnodev" => dev.recursive = Some(false),
            "rdev" => dev.recursive = Some(true),
            _ => {}
        }
    }
    let mut rights = AccessFs::READ;
    if write.resolve(true) && !m.fs_type().is_some_and(|t| PSEUDO_FS.contains(&t)) {
        rights = rights.union(AccessFs::WRITE);
    }
    if !exec.resolve(true) {
        rights = rights.difference(AccessFs::EXECUTE);
    }
    if is_dev_path(m.mount_destination().as_str()) && dev.resolve(true) {
        rights = rights.union(AccessFs::IOCTL_DEV);
    }
    rights
}

fn is_ancestor(a: &str, b: &str) -> bool {
    a != b && (a == "/" || b.strip_prefix(a).is_some_and(|r| r.starts_with('/')))
}

/// `root` と `mounts` に、暗黙の `/dev`・`/dev/pts`・`/dev/shm`（[`ImplicitDevMounts::All`]）を加えて
/// Landlock ルールを生成する（CORE-5・TASK-39.2・#1657）。[`build_path_rules_with_dev`] の薄いラッパー。
pub fn build_path_rules(
    support: &LandlockSupport,
    root: &OciRoot,
    mounts: &[OciMount],
) -> Result<LandlockRuleset, LandlockRuleError> {
    build_path_rules_with_dev(support, root, mounts, ImplicitDevMounts::All)
}

/// [`build_path_rules`] で暗黙マウントの含め方を選べる版（CORE-5・#1657）。
///
/// 暗黙分は実マウントの属性から導いた最小の権利で `root` の次に置く（順序は root → 暗黙分 → `mounts[]`）。
/// `mounts[]` の destination が暗黙分（`All` のとき）と完全一致したら
/// [`LandlockRuleErrorKind::ImplicitMountConflict`] で拒否する。
///
/// Landlock はマウントをまたいでパス階層をさかのぼって評価するため、`/dev/pts`・`/dev/shm` に実際に効く
/// 権利は `/dev` の権利を含む。子の 2 本は意図した権利を明示し、広がった差分を [`LandlockRuleset::shadowed`]
/// に監査用の記録として残す（SEC-4）。実行・`IOCTL_DEV` の差分は VFS の `noexec` / `nodev` が効く。
///
/// `ImplicitDevMounts::WithoutShm` は `/dev/shm` を載せない構成（`--ipc=host`）向けで、
/// `ImplicitDevMounts::for_tmpfs_set` で実際に載せる tmpfs 集合から選ぶ（#1672 事後監査 P2）。どの variant でも、
/// 暗黙分のパスが実際に期待する fs の独立したマウントであることは適用時に確かめる（`apply` の `check_implicit_mount`）。
///
/// `ImplicitDevMounts::None` は rootfs にこれらのマウントが無い経路（専用の `/dev` を載せない最小入口 `spawn_container`。配線しないと #2700 で決定。本番の launcher は `All` を使う）向けで、
/// ルールが減るだけで権利は広がらない。このとき `mounts` は上限 +3 件まで通るが、`mounts[]` の件数は
/// config のパース時に [`CONFIG_MAX_MOUNTS`] で制限済みのため確保量は抑えられる。
///
/// 件数を先に検証してから確保する。検出を通過した `support` なしでは呼べない（fail-closed）。
pub fn build_path_rules_with_dev(
    support: &LandlockSupport,
    root: &OciRoot,
    mounts: &[OciMount],
    implicit: ImplicitDevMounts,
) -> Result<LandlockRuleset, LandlockRuleError> {
    // 公開の入口は検証済みの bind の集合を持たないため空を渡す（`ro` の bind は拒否のまま。#1917）。
    build_path_rules_with_user_tmpfs(
        support,
        root,
        mounts,
        &[],
        implicit,
        &BindMountSet::default(),
    )
}

/// [`build_path_rules_with_dev`] に利用者指定の tmpfs（`--tmpfs`。暗黙の `/dev/shm` を除く）を足せる版
/// （SUP-12・CORE-5・#2625）。
///
/// 利用者 tmpfs は `mounts[]` の後に重ね、ルールの由来は [`RuleOrigin::UserTmpfs`]（`mounts[]` の位置は持たない）。
/// `ro` の tmpfs はルールを作らない: 書き込み可能な祖先（root）の下では Landlock で書き込みを狭められず
/// `WriteRestrictionShadowed` になるだけで、書き込みの禁止は VFS の `ro` が担う（`/sys` の sysfs と同じ扱い）。
/// 件数は `mounts` と別枠で [`TMPFS_MAX_MOUNTS`] まで許す。
///
/// `binds` は start が検証し launcher が適用する bind の集合（`spec.bind_mounts()`）。書き込み可能な祖先の下の
/// `ro` の mount は、`binds` に同じ `index` の `read_only()` の spec があり、宛先が一致し、ルール自身が `WRITE` を
/// 持たない場合に限り許容する（#1917）。理由と残余は [`requires_read_only_mount`] の doc を参照。
pub(crate) fn build_path_rules_with_user_tmpfs(
    support: &LandlockSupport,
    root: &OciRoot,
    mounts: &[OciMount],
    user_tmpfs: &[OciMount],
    implicit: ImplicitDevMounts,
    binds: &BindMountSet,
) -> Result<LandlockRuleset, LandlockRuleError> {
    let handled = handled_for_abi(support.abi.get());
    let implicit_mounts = implicit.entries();
    let count = mounts
        .len()
        .saturating_add(user_tmpfs.len())
        .saturating_add(1)
        .saturating_add(implicit_mounts.len());
    // `mounts[]` 側（root・暗黙分を含む）と利用者 tmpfs 側は別枠で検証する（片方の余りでもう片方の超過を通さない）。
    let base = mounts
        .len()
        .saturating_add(1)
        .saturating_add(implicit_mounts.len());
    let base_max = CONFIG_MAX_MOUNTS + 1 + IMPLICIT_DEV_MOUNT_COUNT;
    if base > base_max {
        return Err(LandlockRuleError::new(
            LandlockRuleErrorKind::TooManyRules {
                count: base,
                max: base_max,
            },
        ));
    }
    if user_tmpfs.len() > TMPFS_MAX_MOUNTS {
        return Err(LandlockRuleError::new(
            LandlockRuleErrorKind::TooManyRules {
                count: user_tmpfs.len(),
                max: TMPFS_MAX_MOUNTS,
            },
        ));
    }
    let mut rules: Vec<PathRule> = Vec::with_capacity(count);
    rules.push(PathRule {
        path: RulePath::Root,
        allowed: root_rights(root.readonly()),
        origin: RuleOrigin::Root,
    });
    for &mount in implicit_mounts {
        rules.push(PathRule {
            path: RulePath::ImplicitDev(mount),
            allowed: implicit_rights(mount),
            origin: RuleOrigin::Implicit { mount },
        });
    }
    let user_start = mounts.len();
    for (index, m) in mounts.iter().chain(user_tmpfs).enumerate() {
        let is_user_tmpfs = index >= user_start;
        let dest = m.mount_destination();
        let len = dest.as_str().len();
        if len > CONFIG_MAX_PATH_BYTES {
            return Err(LandlockRuleError::new(LandlockRuleErrorKind::PathTooLong {
                len,
                max: CONFIG_MAX_PATH_BYTES,
            }));
        }
        if implicit_mounts
            .iter()
            .any(|i| i.destination() == dest.as_str())
        {
            return Err(LandlockRuleError::new(
                LandlockRuleErrorKind::ImplicitMountConflict { index },
            ));
        }
        // 後のマウントは同一 destination とその配下にある先のマウントを覆い隠す（OCI の適用順）。
        // 隠れたマウントのルールを残すと、後のマウント内の同名パスへ先の権利を与えるため除外する。
        rules.retain(|r| {
            let p = r.path.as_str();
            p != dest.as_str() && !is_ancestor(dest.as_str(), p)
        });
        // `/sys` の sysfs はルールを作らない（#2020・SEC-2・CORE-5）。Landlock は祖先の root の権利を子で狭められず、
        // 作っても `/sys` の実効の権利は root と同じになる（疑似 FS として書き込みを落としても、書き込み可能な root の
        // 下では `WriteRestrictionShadowed` で拒否されるだけで、sysfs の供給を妨げる）。書き込みの禁止は VFS の裏付け
        // （`exec::mount_sysfs` が載せる ro・事後条件の mountinfo 検証と `readonly_paths` の再帰 ro bind）が担う。
        // 先行マウントを覆うための `retain` は上で済んでいる。`/sys` 以外の sysfs は従来どおりルールを作る。
        if OciMountKind::of(m) == OciMountKind::Sysfs && dest.as_str() == "/sys" {
            continue;
        }
        if is_user_tmpfs && m.options().iter().any(|o| o == "ro") {
            continue;
        }
        rules.push(PathRule {
            path: RulePath::Beneath(dest.clone()),
            allowed: mount_rights(m),
            origin: if is_user_tmpfs {
                RuleOrigin::UserTmpfs
            } else {
                RuleOrigin::Mount { index }
            },
        });
    }

    let mut shadowed = Vec::new();
    // 許容した `ro` の bind の宛先（後段の「配下に書き込み可能なルールが無い」検査用）。
    let mut readonly_binds: Vec<(usize, String)> = Vec::new();
    for r in &rules {
        // rootfs には祖先が無い。
        if r.origin == RuleOrigin::Root {
            continue;
        }
        // 検証済みの bind の集合と `mounts[]` の解釈の照合（宛先、`ro` なのに `WRITE` を持つルール）。
        let verified = match r.origin {
            RuleOrigin::Mount { index } => binds
                .mounts()
                .iter()
                .find(|b| b.index() == index)
                .map(|b| (index, b)),
            _ => None,
        };
        if let Some((index, spec)) = verified {
            let dest_matches = mounts
                .get(index)
                .is_some_and(|m| m.mount_destination().as_str() == spec.destination().as_str());
            let write_matches =
                !spec.read_only() || r.allowed.intersection(AccessFs::WRITE).is_empty();
            if !dest_matches || !write_matches {
                return Err(LandlockRuleError::new(
                    LandlockRuleErrorKind::VerifiedBindMismatch { index },
                ));
            }
        }
        let effective = rules
            .iter()
            .filter(|a| is_ancestor(a.path.as_str(), r.path.as_str()))
            .fold(r.allowed, |acc, a| acc.union(a.allowed));
        let widened = effective.difference(r.allowed);
        let granted_writes = widened.intersection(AccessFs::WRITE);
        if !granted_writes.is_empty() {
            // 暗黙分は 3 本とも `WRITE` を持つので構造上ここへ来ない。来たら内部不変条件違反として扱う
            // （`index` は `mounts[]` の位置を表すため暗黙分には流用しない）。
            let RuleOrigin::Mount { index } = r.origin else {
                return Err(LandlockRuleError::new(
                    LandlockRuleErrorKind::RightsExceedHandled,
                ));
            };
            // 例外は検証済みの `ro` の bind だけ。書き込みの禁止は載せた bind の VFS の ro が担う（#1917）。
            if verified.is_some_and(|(_, spec)| spec.read_only()) {
                readonly_binds.push((index, r.path.as_str().to_owned()));
                shadowed.push(ShadowedRestriction {
                    path: r.path.clone(),
                    intended: r.allowed,
                    effective,
                    backing: ShadowBacking::ReadOnlyBind { index },
                });
                continue;
            }
            // Landlock は祖先の許可を子で取り消せないため、書き込み制限を黙って失わせず拒否する。
            return Err(LandlockRuleError::new(
                LandlockRuleErrorKind::WriteRestrictionShadowed {
                    index,
                    granted: granted_writes,
                },
            ));
        }
        if !widened.is_empty() {
            shadowed.push(ShadowedRestriction {
                path: r.path.clone(),
                intended: r.allowed,
                effective,
                backing: ShadowBacking::VfsExecDev,
            });
        }
    }
    // 多重防御: `ro` の bind の下に書き込み可能なルールがあると、読み取り専用が見かけだけになる。
    // bind 同士の入れ子・tmpfs・注入・保護パスとの重なりは上流が止めるが、生成器は公開 API なのでここでも閉じる。
    for (index, dest) in &readonly_binds {
        if rules.iter().any(|q| {
            is_ancestor(dest, q.path.as_str())
                && !q.allowed.intersection(AccessFs::WRITE).is_empty()
        }) {
            return Err(LandlockRuleError::new(
                LandlockRuleErrorKind::WritableBeneathReadOnlyBind { index: *index },
            ));
        }
    }

    let forbidden = AccessFs::MAKE_CHAR.union(AccessFs::MAKE_BLOCK);
    if rules
        .iter()
        .any(|r| !r.allowed.is_subset_of(handled) || !r.allowed.intersection(forbidden).is_empty())
    {
        return Err(LandlockRuleError::new(
            LandlockRuleErrorKind::RightsExceedHandled,
        ));
    }
    Ok(LandlockRuleset {
        handled_access_fs: handled,
        rules,
        shadowed,
        audit: support.audit_mode(),
    })
}

/// `rules[i]` が「祖先の書き込み権を VFS の読み取り専用属性で打ち消す」ルールか（#1917）。
///
/// 条件は、由来が `Mount` で、自身が `WRITE` を持たず、祖先ルールの和集合が `WRITE` を含むこと。この形のルールは
/// 生成器が検証済みの `ro` の bind（[`BindMountSet`] の spec と一致）を許容したときだけ作るので、launch の記録から
/// 組み直した ruleset でも同じ判定ができる（`state.json` の形式は変えない）。適用の段（`apply`）はこのルールが指す
/// マウントが実際に読み取り専用であること（`fstatfs` の `ST_RDONLY`）を `landlock_add_rule` の前に確かめる。
///
/// # 読み取り専用を外せないことの根拠（CORE-5・SEC-1・REPAIR-3）
///
/// - bind は PID 1 が `unshare(CLONE_NEWNS)` の**後**に自分の mount namespace で作るため `MNT_LOCKED` ではなく、
///   ホストから引き継いだマウントより根拠が弱い。user namespace の root は自分の namespace のマウントの ro を
///   `mount_setattr` で外せる（`exec/sysfs.rs` の実測と同じ構造）
/// - よって防御は 2 本に依存する: (1) 能力の削減の段で許可集合に `CAP_SYS_ADMIN` が無いこと、(2) 既定の seccomp が
///   `mount`・`umount2`・`open_tree`・`move_mount`・`fsopen`・`fsconfig`・`fsmount`・`fspick`・`mount_setattr` を拒否すること。
///   両段は `StagePipeline` の組み込みの固定段でフックでは差し替えられず、exec の再適用も同じ集合で掛ける
/// - rootful（user namespace なし）は bind を受けない（`exec/bind_mounts.rs` の `user_namespace_required`）
/// - 書き込みの open は VFS の読み取り専用の検査が Landlock の `file_open` より先に走り `EROFS` になる見込み
///   （実機での確認は #1916）
///
/// 残余: マウント元の別名は検出しない（同じホストのディレクトリを rw の別の bind でも公開する場合、元が書き込み可能な
/// rootfs の配下にあり rootfs 側から同じデータへ書ける場合）。これは宛先への書き込み禁止という VFS の ro の意味を
/// 超えたデータの別名の問題で、別途追跡する。
pub(crate) fn requires_read_only_mount(rules: &[PathRule], i: usize) -> bool {
    let Some(r) = rules.get(i) else {
        return false;
    };
    if !matches!(r.origin, RuleOrigin::Mount { .. })
        || !r.allowed.intersection(AccessFs::WRITE).is_empty()
    {
        return false;
    }
    rules
        .iter()
        .filter(|a| is_ancestor(a.path.as_str(), r.path.as_str()))
        .any(|a| !a.allowed.intersection(AccessFs::WRITE).is_empty())
}

/// [`build_path_rules`] の `OciConfig` 版の薄いラッパー（暗黙の `/dev` 系を含める。#1657）。
pub fn path_rules_from_config(
    support: &LandlockSupport,
    config: &OciConfig,
) -> Result<LandlockRuleset, LandlockRuleError> {
    build_path_rules(support, config.root(), config.mounts())
}

#[cfg(test)]
mod tests {
    use super::super::evaluate_abi;
    use super::*;
    use crate::oci_runtime::parse_config_bytes;
    use serde_json::{Value, json};

    fn cfg(readonly: bool, mounts: Value) -> OciConfig {
        let v = json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs", "readonly": readonly},
            "mounts": mounts,
        });
        parse_config_bytes(v.to_string().as_bytes()).expect("valid config")
    }

    /// 暗黙の `/dev` 系を含めない版（mount オプションの解釈など、`mounts[]` だけを照合するテスト用）。
    fn build(c: &OciConfig) -> LandlockRuleset {
        let s = evaluate_abi(6).expect("abi6");
        build_path_rules_with_dev(&s, c.root(), c.mounts(), ImplicitDevMounts::None).expect("rules")
    }

    /// 暗黙の `/dev` 系を含める版（本番の入口 `path_rules_from_config` と同じ）。
    fn build_all(c: &OciConfig) -> LandlockRuleset {
        let s = evaluate_abi(6).expect("abi6");
        path_rules_from_config(&s, c).expect("rules")
    }

    /// CORE-5・#1911: bind mount の `ro`/`rw`・`noexec`/`exec` の解釈が `BindMountSet` と一致する。
    /// `/dev` 配下の宛先は bind が拒否するため `IOCTL_DEV` 分岐は食い違わない。
    #[test]
    fn core5_landlock_bind_interpretation_matches() {
        use crate::oci_runtime::BindMountSet;
        let tokens = ["ro", "rw", "noexec", "exec", "nosuid", "nodev", "private"];
        let mut cases: Vec<Vec<&str>> = vec![vec![]];
        for a in tokens {
            cases.push(vec![a]);
            for b in tokens {
                cases.push(vec![a, b]);
                for c in ["ro", "rw", "noexec", "exec"] {
                    cases.push(vec![a, b, c]);
                }
            }
        }
        for extra in cases {
            let mut opts = vec!["rbind"];
            opts.extend(extra.iter().copied());
            let c = cfg(
                false,
                json!([{"destination": "/mnt/d", "type": "bind", "source": "/data", "options": opts}]),
            );
            let set = BindMountSet::from_mounts(c.mounts()).expect("bind accepted");
            let spec = &set.mounts()[0];
            let rights = mount_rights(&c.mounts()[0]);
            assert_eq!(
                rights.contains(AccessFs::WRITE),
                !spec.read_only(),
                "opts={opts:?}"
            );
            assert_eq!(
                rights.contains(AccessFs::EXECUTE),
                !spec.noexec(),
                "opts={opts:?}"
            );
        }
    }

    fn summary(rs: &LandlockRuleset) -> Vec<(&str, RuleOrigin, u64)> {
        rs.rules()
            .iter()
            .map(|r| (r.path.as_str(), r.origin, r.allowed.bits()))
            .collect()
    }

    fn shadowed_summary(rs: &LandlockRuleset) -> Vec<(&str, u64, u64)> {
        rs.shadowed()
            .iter()
            .map(|s| (s.path.as_str(), s.intended.bits(), s.effective.bits()))
            .collect()
    }

    fn rule<'a>(rs: &'a LandlockRuleset, p: &str) -> &'a PathRule {
        rs.rules()
            .iter()
            .find(|r| r.path.as_str() == p)
            .expect("rule present")
    }

    #[test]
    fn core5_uapi_constants_match_header() {
        let v = [
            (AccessFs::EXECUTE, 1u64),
            (AccessFs::WRITE_FILE, 2),
            (AccessFs::READ_FILE, 4),
            (AccessFs::READ_DIR, 8),
            (AccessFs::REMOVE_DIR, 0x10),
            (AccessFs::REMOVE_FILE, 0x20),
            (AccessFs::MAKE_CHAR, 0x40),
            (AccessFs::MAKE_DIR, 0x80),
            (AccessFs::MAKE_REG, 0x100),
            (AccessFs::MAKE_SOCK, 0x200),
            (AccessFs::MAKE_FIFO, 0x400),
            (AccessFs::MAKE_BLOCK, 0x800),
            (AccessFs::MAKE_SYM, 0x1000),
            (AccessFs::REFER, 0x2000),
            (AccessFs::TRUNCATE, 0x4000),
            (AccessFs::IOCTL_DEV, 0x8000),
            (AccessFs::ALL, 0xFFFF),
            (AccessFs::READ, 0x000D),
        ];
        for (a, b) in v {
            assert_eq!(a.bits(), b);
        }
    }

    #[test]
    fn core5_handled_for_abi_table() {
        let t = [
            (1u32, 0x1FFFu64),
            (2, 0x3FFF),
            (3, 0x7FFF),
            (4, 0x7FFF),
            (5, 0xFFFF),
            (6, 0xFFFF),
            (7, 0xFFFF),
        ];
        for (abi, bits) in t {
            assert_eq!(handled_for_abi(abi).bits(), bits, "abi {abi}");
        }
    }

    #[test]
    fn core5_readonly_root_only() {
        let rs = build(&cfg(true, json!([])));
        assert_eq!(rs.rules().len(), 1);
        assert_eq!(rs.rules()[0].path, RulePath::Root);
        assert_eq!(rs.rules()[0].path.as_str(), "/");
        assert_eq!(rs.rules()[0].allowed.bits(), 0x000D);
        assert!(rs.shadowed().is_empty());
    }

    #[test]
    fn core5_writable_root_excludes_device_rights() {
        let rs = build(&cfg(false, json!([])));
        let a = rs.rules()[0].allowed;
        assert_eq!(a.bits(), 0x000D | AccessFs::WRITE.bits());
        assert_eq!(a.bits(), 0x77BF);
        assert!(a.intersection(AccessFs::MAKE_CHAR).is_empty());
        assert!(a.intersection(AccessFs::MAKE_BLOCK).is_empty());
        assert!(a.intersection(AccessFs::IOCTL_DEV).is_empty());
    }

    /// CORE-5: 相反する mount オプションは後勝ち（ro/rw・noexec/exec・nodev/dev）。
    #[test]
    fn core5_conflicting_mount_options_last_wins() {
        let c = cfg(
            true,
            json!([
                {"destination": "/a", "options": ["ro"]},
                {"destination": "/b", "options": ["rw", "ro"]},
                {"destination": "/c", "options": ["ro", "rw"]},
                {"destination": "/d", "options": ["noexec"]},
                {"destination": "/e", "options": ["noexec", "exec"]},
                {"destination": "/f", "options": ["exec", "noexec"]},
                {"destination": "/dev", "options": ["nodev"]},
                {"destination": "/dev/a", "options": ["nodev", "dev"]},
                {"destination": "/dev/b", "options": ["dev", "nodev"]},
                {"destination": "/g", "options": ["nosuid", "suid", "defaults"]},
            ]),
        );
        let rs = build(&c);
        let rw = AccessFs::READ.union(AccessFs::WRITE);
        let rw_noexec = rw.difference(AccessFs::EXECUTE);
        let cases = [
            ("/a", AccessFs::READ),
            ("/b", AccessFs::READ),
            ("/c", rw),
            ("/d", rw_noexec),
            ("/e", rw),
            ("/f", rw_noexec),
            ("/dev", rw),
            ("/dev/a", rw.union(AccessFs::IOCTL_DEV)),
            ("/dev/b", rw),
            // nosuid / suid / defaults は対応する Landlock の権利が無く、既定（rw・exec）のまま。
            ("/g", rw),
        ];
        for (p, want) in cases {
            assert_eq!(rule(&rs, p).allowed.bits(), want.bits(), "{p}");
        }
        assert_eq!(rw.bits(), 0x77BF);
        assert_eq!(rw_noexec.bits(), 0x77BE);
    }

    /// CORE-5: 再帰版（rro 等）は位置に関係なく非再帰版より後に効き、再帰版同士は後勝ち。
    #[test]
    fn core5_recursive_mount_options_override_plain() {
        let c = cfg(
            true,
            json!([
                {"destination": "/a", "options": ["rro", "rw"]},
                {"destination": "/b", "options": ["ro", "rrw"]},
                {"destination": "/c", "options": ["rrw", "rro"]},
                {"destination": "/d", "options": ["rnoexec", "exec"]},
                {"destination": "/e", "options": ["noexec", "rexec"]},
                {"destination": "/dev", "options": ["rnodev", "dev"]},
                {"destination": "/dev/a", "options": ["nodev", "rdev"]},
            ]),
        );
        let rs = build(&c);
        let rw = AccessFs::READ.union(AccessFs::WRITE);
        let cases = [
            ("/a", AccessFs::READ),
            ("/b", rw),
            ("/c", AccessFs::READ),
            ("/d", rw.difference(AccessFs::EXECUTE)),
            ("/e", rw),
            ("/dev", rw),
            ("/dev/a", rw.union(AccessFs::IOCTL_DEV)),
        ];
        for (p, want) in cases {
            assert_eq!(rule(&rs, p).allowed.bits(), want.bits(), "{p}");
        }
    }

    /// CORE-5: 後の親マウントに覆い隠された子マウントのルールは除外する。
    #[test]
    fn core5_later_parent_mount_hides_earlier_child_rules() {
        let c = cfg(
            true,
            json!([
                {"destination": "/x/y", "options": ["rw"]},
                {"destination": "/x/y/z", "options": ["rw"]},
                {"destination": "/xy", "options": ["rw"]},
                {"destination": "/x", "options": ["ro"]},
                {"destination": "/x/w", "options": ["rw"]},
            ]),
        );
        let rs = build(&c);
        let got: Vec<(&str, RuleOrigin, u64)> = rs
            .rules()
            .iter()
            .map(|r| (r.path.as_str(), r.origin, r.allowed.bits()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("/", RuleOrigin::Root, 0x000D),
                ("/xy", RuleOrigin::Mount { index: 2 }, 0x77BF),
                ("/x", RuleOrigin::Mount { index: 3 }, 0x000D),
                ("/x/w", RuleOrigin::Mount { index: 4 }, 0x77BF),
            ]
        );
        assert!(rs.shadowed().is_empty());
    }

    #[test]
    fn core5_ioctl_dev_only_under_dev() {
        let c = cfg(
            true,
            json!([
                {"destination": "/dev"},
                {"destination": "/dev/pts"},
                {"destination": "/dev2"},
                {"destination": "/devices"},
            ]),
        );
        let rs = build(&c);
        assert!(rule(&rs, "/dev").allowed.contains(AccessFs::IOCTL_DEV));
        assert!(rule(&rs, "/dev/pts").allowed.contains(AccessFs::IOCTL_DEV));
        assert!(!rule(&rs, "/dev2").allowed.contains(AccessFs::IOCTL_DEV));
        assert!(!rule(&rs, "/devices").allowed.contains(AccessFs::IOCTL_DEV));
        assert!(!rule(&rs, "/").allowed.contains(AccessFs::IOCTL_DEV));
    }

    /// CORE-5: 疑似 FS は書き込み権を持たず、読み取り専用 root の下では何も shadowed にならない。
    #[test]
    fn core5_pseudo_fs_drops_write_under_readonly_root() {
        let rs = build(&cfg(
            true,
            json!([
                {"destination": "/proc", "type": "proc"},
                {"destination": "/mnt/sys", "type": "sysfs", "options": ["rw"]}
            ]),
        ));
        assert_eq!(rule(&rs, "/proc").allowed.bits(), 0x000D);
        assert_eq!(rule(&rs, "/mnt/sys").allowed.bits(), 0x000D);
        assert!(rs.shadowed().is_empty());
    }

    /// CORE-5: 書き込み制限が祖先ルールで無効になる構成は拒否する（fail-closed）。
    #[test]
    fn core5_write_restriction_shadowed_by_ancestor_is_rejected() {
        let s = evaluate_abi(6).expect("abi6");
        let cases = [
            // 書き込み可能な root の下の疑似 FS（VFS の裏付けが無い制限）。
            (false, json!([{"destination": "/proc", "type": "proc"}]), 0),
            // 書き込み可能な root の下の ro mount。
            (
                false,
                json!([{"destination": "/data"}, {"destination": "/etc", "options": ["ro"]}]),
                1,
            ),
            // 読み取り専用 root でも、rw mount の下の ro mount は同様に狭められない。
            (
                true,
                json!([
                    {"destination": "/data", "options": ["rw"]},
                    {"destination": "/data/sub", "options": ["ro"]}
                ]),
                1,
            ),
        ];
        assert_eq!(AccessFs::WRITE.bits(), 0x77B2);
        for (readonly, mounts, index) in cases {
            let c = cfg(readonly, mounts);
            let e = build_path_rules_with_dev(&s, c.root(), c.mounts(), ImplicitDevMounts::None)
                .expect_err("rejected");
            assert_eq!(
                e.kind,
                LandlockRuleErrorKind::WriteRestrictionShadowed {
                    index,
                    granted: AccessFs::WRITE,
                }
            );
            assert_eq!(e.code, ErrorCode::InvalidArgument);
            assert_eq!(
                e.to_string(),
                format!(
                    "INVALID_ARGUMENT: mounts[{index}] denies write access 0x77b2 that an \
                     ancestor Landlock rule grants; use a read-only root or a writable parent mount"
                )
            );
        }
        // 書き込み制限を持たない mount だけなら書き込み可能な root でも生成できる。
        let rs = build(&cfg(
            false,
            json!([{"destination": "/data", "options": ["rw"]}]),
        ));
        assert_eq!(rs.rules().len(), 2);
        assert!(rs.shadowed().is_empty());
    }

    /// CORE-5・SEC-2（#2020）: `/sys` の sysfs はルールを作らず、書き込み可能な root でも拒否されない。
    /// `/sys` 以外の sysfs は従来どおり書き込み可能な root の下で拒否される。
    #[test]
    fn core5_sec2_sysfs_at_sys_makes_no_rule() {
        let s = evaluate_abi(6).expect("abi6");
        for readonly in [true, false] {
            let c = cfg(
                readonly,
                json!([{"destination": "/sys", "type": "sysfs", "options": ["ro"]}]),
            );
            let rs = build_path_rules_with_dev(&s, c.root(), c.mounts(), ImplicitDevMounts::None)
                .expect("rules");
            assert_eq!(summary(&rs).len(), 1, "readonly={readonly}");
            assert_eq!(rs.rules()[0].path.as_str(), "/");
            assert!(rs.shadowed().is_empty());
        }
        // 先行のマウントが `/sys` の sysfs に覆われると、そのルールは外れる。
        let c = cfg(
            true,
            json!([
                {"destination": "/sys/x", "options": ["rw"]},
                {"destination": "/sys", "type": "sysfs", "options": ["ro"]},
                {"destination": "/data", "options": ["rw"]},
            ]),
        );
        let rs = build(&c);
        let paths: Vec<_> = rs.rules().iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, ["/", "/data"]);
        // `/sys` 以外の sysfs は従来どおり（書き込み可能な root の下では拒否）。
        let c = cfg(
            false,
            json!([{"destination": "/mnt/sys", "type": "sysfs", "options": ["ro"]}]),
        );
        let e = build_path_rules_with_dev(&s, c.root(), c.mounts(), ImplicitDevMounts::None)
            .expect_err("rejected");
        assert_eq!(
            e.kind,
            LandlockRuleErrorKind::WriteRestrictionShadowed {
                index: 0,
                granted: AccessFs::WRITE,
            }
        );
    }

    #[test]
    fn core5_shadowed_effective_includes_own_allowed() {
        // ro root 配下の writable noexec mount: 祖先の EXECUTE に加え自身の WRITE も実効に含まれる。
        let rs = build(&cfg(
            true,
            json!([{"destination": "/d", "options": ["noexec"]}]),
        ));
        assert_eq!(rs.shadowed().len(), 1);
        let s = &rs.shadowed()[0];
        assert_eq!(s.path.as_str(), "/d");
        assert_eq!(s.intended.bits(), 0x77BE);
        assert_eq!(s.effective.bits(), 0x77BF);
    }

    #[test]
    fn core5_duplicate_destination_last_wins() {
        let c = cfg(
            true,
            json!([
                {"destination": "/x", "options": ["ro"]},
                {"destination": "/y"},
                {"destination": "/x"},
            ]),
        );
        let rs = build(&c);
        assert_eq!(rs.rules().len(), 3);
        let x = rule(&rs, "/x");
        assert_eq!(x.origin, RuleOrigin::Mount { index: 2 });
        assert_eq!(x.allowed, AccessFs::READ.union(AccessFs::WRITE));
        assert_eq!(rs.rules()[1].path.as_str(), "/y");
    }

    #[test]
    fn core5_default_mount_set_respects_invariants() {
        let c = cfg(
            true,
            json!([
                {"destination": "/proc", "type": "proc", "source": "proc"},
                {"destination": "/dev", "type": "tmpfs", "options": ["nosuid", "strictatime", "mode=755"]},
                {"destination": "/dev/pts", "type": "devpts"},
                {"destination": "/dev/shm", "type": "tmpfs", "options": ["nosuid", "noexec", "nodev"]},
                {"destination": "/sys", "type": "sysfs", "options": ["ro"]},
                {"destination": "/sys/fs/cgroup", "type": "cgroup2", "options": ["ro"]},
            ]),
        );
        let rs = build(&c);
        assert_eq!(rs.handled_access_fs(), AccessFs::ALL);
        for r in rs.rules() {
            assert!(r.allowed.is_subset_of(rs.handled_access_fs()));
            assert!(r.allowed.intersection(AccessFs::MAKE_CHAR).is_empty());
            assert!(r.allowed.intersection(AccessFs::MAKE_BLOCK).is_empty());
        }
        // /dev の実行・IOCTL_DEV は /dev/shm（noexec,nodev）で狭められず、VFS に委ねて記録だけする。
        let shadowed: Vec<(&str, u64, u64)> = rs
            .shadowed()
            .iter()
            .map(|s| (s.path.as_str(), s.intended.bits(), s.effective.bits()))
            .collect();
        assert_eq!(shadowed, vec![("/dev/shm", 0x77BE, 0xF7BF)]);
    }

    #[test]
    fn core5_rule_count_limit() {
        let s = evaluate_abi(6).expect("abi6");
        let one = cfg(true, json!([{"destination": "/a"}]));
        let m = one.mounts()[0].clone();
        let many = vec![m.clone(); CONFIG_MAX_MOUNTS];
        let rs = build_path_rules(&s, one.root(), &many).expect("at limit");
        // 同一 destination は後勝ちで 1 本にまとまる（root・暗黙 3 本・/a）。
        assert_eq!(rs.rules().len(), 5);
        let over = vec![m; CONFIG_MAX_MOUNTS + 1];
        let e = build_path_rules(&s, one.root(), &over).expect_err("over limit");
        assert_eq!(
            e.kind,
            LandlockRuleErrorKind::TooManyRules {
                count: 1029,
                max: 1028
            }
        );
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert!(e.to_string().starts_with("INVALID_ARGUMENT: "), "{e}");
        assert_eq!(MAX_LANDLOCK_RULES, 1092);
    }

    /// 検証済みの bind の集合を渡して生成する（本番の launcher と同じ経路。#1917）。
    fn build_verified(
        c: &OciConfig,
        implicit: ImplicitDevMounts,
    ) -> Result<LandlockRuleset, LandlockRuleError> {
        let s = evaluate_abi(6).expect("abi6");
        let binds = BindMountSet::from_mounts(c.mounts()).expect("bind accepted");
        build_path_rules_with_user_tmpfs(&s, c.root(), c.mounts(), &[], implicit, &binds)
    }

    fn ro_bind(opts: Value) -> Value {
        json!([{"destination": "/data", "type": "bind", "source": "/srv/data", "options": opts}])
    }

    /// CORE-5・OCI-4・#1917: 書き込み可能な root の下の検証済みの `ro` の bind を受け、`ReadOnlyBind` で記録する
    /// （ルールは残る。`bind` / `rbind` ・`noexec` の併用、暗黙の `/dev` の有無のどちらでも同じ）。
    #[test]
    fn core5_1917_verified_readonly_bind_is_accepted_under_writable_root() {
        for implicit in [ImplicitDevMounts::None, ImplicitDevMounts::All] {
            for (opts, intended) in [
                (json!(["bind", "ro"]), 0x000Du64),
                (json!(["rbind", "ro"]), 0x000D),
                (json!(["bind", "ro", "noexec"]), 0x000C),
            ] {
                let c = cfg(false, ro_bind(opts.clone()));
                let rs = build_verified(&c, implicit).expect("accepted");
                assert_eq!(rule(&rs, "/data").allowed.bits(), intended, "{opts}");
                assert_eq!(
                    rs.shadowed()
                        .iter()
                        .filter(|s| s.path.as_str() == "/data")
                        .map(|s| (s.intended.bits(), s.effective.bits(), s.backing))
                        .collect::<Vec<_>>(),
                    vec![(intended, 0x77BF, ShadowBacking::ReadOnlyBind { index: 0 })],
                    "{opts}"
                );
                let i = rs
                    .rules()
                    .iter()
                    .position(|r| r.path.as_str() == "/data")
                    .expect("rule");
                assert!(requires_read_only_mount(rs.rules(), i));
            }
        }
    }

    /// CORE-5・#1917: 読み取り専用の root の下では記録も要らない（shadowed は空）。`requires_read_only_mount` は偽。
    #[test]
    fn core5_1917_readonly_bind_under_readonly_root_records_nothing() {
        let c = cfg(true, ro_bind(json!(["bind", "ro"])));
        let rs = build_verified(&c, ImplicitDevMounts::None).expect("accepted");
        assert!(rs.shadowed().is_empty());
        assert!(
            !(0..rs.rules().len()).any(|i| requires_read_only_mount(rs.rules(), i)),
            "{:?}",
            rs.rules()
        );
    }

    /// CORE-5・#1917: 集合に `index` が無い（空の集合）なら、従来どおり `WriteRestrictionShadowed`。
    #[test]
    fn core5_1917_readonly_bind_without_matching_spec_is_refused() {
        let s = evaluate_abi(6).expect("abi6");
        let c = cfg(false, ro_bind(json!(["bind", "ro"])));
        let e = build_path_rules_with_user_tmpfs(
            &s,
            c.root(),
            c.mounts(),
            &[],
            ImplicitDevMounts::None,
            &BindMountSet::default(),
        )
        .expect_err("empty set");
        assert_eq!(
            e.kind,
            LandlockRuleErrorKind::WriteRestrictionShadowed {
                index: 0,
                granted: AccessFs::WRITE
            }
        );
        // 公開の入口（config だけ）も同じ。
        let e = build_path_rules_with_dev(&s, c.root(), c.mounts(), ImplicitDevMounts::None)
            .expect_err("public entry");
        assert_eq!(e.code, ErrorCode::InvalidArgument);
    }

    /// CORE-5・#1917: 宛先が食い違う集合（別の config から作った集合）は `VerifiedBindMismatch`（`Internal`）。
    #[test]
    fn core5_1917_mismatched_verified_set_is_internal_error() {
        let s = evaluate_abi(6).expect("abi6");
        let c = cfg(false, ro_bind(json!(["bind", "ro"])));
        let other = cfg(
            false,
            json!([{"destination": "/other", "type": "bind", "source": "/srv/o", "options": ["bind", "ro"]}]),
        );
        let binds = BindMountSet::from_mounts(other.mounts()).expect("bind accepted");
        let e = build_path_rules_with_user_tmpfs(
            &s,
            c.root(),
            c.mounts(),
            &[],
            ImplicitDevMounts::None,
            &binds,
        )
        .expect_err("mismatch");
        assert_eq!(
            e.kind,
            LandlockRuleErrorKind::VerifiedBindMismatch { index: 0 }
        );
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.kind.as_str(), "verified_bind_mismatch");
        // spec が `ro` なのにルールが `WRITE` を持つ（`rw` の config に `ro` の集合を当てた）場合も同じ。
        let rw = cfg(false, ro_bind(json!(["bind", "rw"])));
        let ro_set = BindMountSet::from_mounts(c.mounts()).expect("bind accepted");
        let e = build_path_rules_with_user_tmpfs(
            &s,
            rw.root(),
            rw.mounts(),
            &[],
            ImplicitDevMounts::None,
            &ro_set,
        )
        .expect_err("ro spec with writable rule");
        assert_eq!(
            e.kind,
            LandlockRuleErrorKind::VerifiedBindMismatch { index: 0 }
        );
    }

    /// CORE-5・#1917: 許容した `ro` の bind の下に書き込み可能なルール（利用者 tmpfs）があれば拒否する。
    #[test]
    fn core5_1917_writable_rule_beneath_readonly_bind_is_refused() {
        let s = evaluate_abi(6).expect("abi6");
        let c = cfg(false, ro_bind(json!(["bind", "ro"])));
        let binds = BindMountSet::from_mounts(c.mounts()).expect("bind accepted");
        let tmp = cfg(
            false,
            json!([{"destination": "/data/tmp", "type": "tmpfs", "options": ["rw", "nosuid", "nodev"]}]),
        );
        let e = build_path_rules_with_user_tmpfs(
            &s,
            c.root(),
            c.mounts(),
            tmp.mounts(),
            ImplicitDevMounts::None,
            &binds,
        )
        .expect_err("writable beneath ro bind");
        assert_eq!(
            e.kind,
            LandlockRuleErrorKind::WritableBeneathReadOnlyBind { index: 0 }
        );
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert_eq!(e.kind.as_str(), "writable_beneath_read_only_bind");
    }

    /// CORE-5・#1917: `requires_read_only_mount` の真理値表（読み取り専用の root・Implicit・UserTmpfs・rw の Mount は偽）。
    #[test]
    fn core5_1917_requires_read_only_mount_truth_table() {
        let c = cfg(false, ro_bind(json!(["bind", "ro"])));
        let rs = build_verified(&c, ImplicitDevMounts::All).expect("accepted");
        let got: Vec<(String, bool)> = rs
            .rules()
            .iter()
            .enumerate()
            .map(|(i, r)| {
                (
                    r.path.as_str().to_owned(),
                    requires_read_only_mount(rs.rules(), i),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("/".to_owned(), false),
                ("/dev".to_owned(), false),
                ("/dev/pts".to_owned(), false),
                ("/dev/shm".to_owned(), false),
                ("/data".to_owned(), true),
            ]
        );
        assert!(!requires_read_only_mount(rs.rules(), 99));
    }

    /// SUP-12・CORE-5(#2625): 利用者 tmpfs は `UserTmpfs` 由来で書き込み可能に載り、`ro` は書き込み可能な root の下でも
    /// `WriteRestrictionShadowed` にならずルールを作らない。件数は `mounts[]` と別枠。
    #[test]
    fn sup12_user_tmpfs_rules_are_separate_origin_and_ro_is_skipped() {
        let s = evaluate_abi(6).expect("abi6");
        let c = cfg(
            false,
            json!([
                {"destination": "/run", "type": "tmpfs", "options": ["rw", "nosuid", "nodev"]},
                {"destination": "/ro", "type": "tmpfs", "options": ["ro", "nosuid", "nodev"]}
            ]),
        );
        let rs = build_path_rules_with_user_tmpfs(
            &s,
            c.root(),
            &[],
            c.mounts(),
            ImplicitDevMounts::None,
            &BindMountSet::default(),
        )
        .expect("rules");
        let got: Vec<(&str, RuleOrigin)> = rs
            .rules()
            .iter()
            .map(|r| (r.path.as_str(), r.origin))
            .collect();
        assert_eq!(
            got,
            vec![("/", RuleOrigin::Root), ("/run", RuleOrigin::UserTmpfs)]
        );
        let many = vec![c.mounts()[0].clone(); TMPFS_MAX_MOUNTS + 1];
        let e = build_path_rules_with_user_tmpfs(
            &s,
            c.root(),
            &[],
            &many,
            ImplicitDevMounts::None,
            &BindMountSet::default(),
        )
        .expect_err("over tmpfs limit");
        assert_eq!(
            e.kind,
            LandlockRuleErrorKind::TooManyRules {
                count: TMPFS_MAX_MOUNTS + 1,
                max: TMPFS_MAX_MOUNTS
            }
        );
        // mounts[] が上限ちょうどでも、利用者 tmpfs を足して拒否されない。
        let full = vec![c.mounts()[0].clone(); CONFIG_MAX_MOUNTS];
        build_path_rules_with_user_tmpfs(
            &s,
            c.root(),
            &full,
            &c.mounts()[..1],
            ImplicitDevMounts::All,
            &BindMountSet::default(),
        )
        .expect("mounts at limit plus tmpfs");
    }

    /// SUP-12・CORE-5・SEC-2(#2714): 読み取り専用 root では、利用者の rw tmpfs の宛先と暗黙の `/dev` 系だけが
    /// 書き込み可能になり、`/` は READ のまま。`ro` の利用者 tmpfs はルールを作らない。
    #[test]
    fn sup12_readonly_root_user_tmpfs_is_the_only_extra_writable_path() {
        let s = evaluate_abi(6).expect("abi6");
        let c = cfg(true, json!([]));
        let tmpfs = |dest: &str, opts: Value| {
            parse_config_bytes(
                json!({"ociVersion": "1.2.0", "root": {"path": "rootfs"},
                       "mounts": [{"destination": dest, "type": "tmpfs", "options": opts}]})
                .to_string()
                .as_bytes(),
            )
            .expect("valid config")
            .mounts()[0]
                .clone()
        };
        let rw = ["rw", "nosuid", "nodev", "noexec"];
        let run = tmpfs("/run", json!(rw));
        let dev = |m| RuleOrigin::Implicit { mount: m };
        let rs = build_path_rules_with_user_tmpfs(
            &s,
            c.root(),
            &[],
            std::slice::from_ref(&run),
            ImplicitDevMounts::All,
            &BindMountSet::default(),
        )
        .expect("rules");
        assert_eq!(
            summary(&rs),
            vec![
                ("/", RuleOrigin::Root, 0x000D),
                ("/dev", dev(ImplicitDevMount::Dev), 0xF7BF),
                ("/dev/pts", dev(ImplicitDevMount::DevPts), 0xF7BE),
                ("/dev/shm", dev(ImplicitDevMount::DevShm), 0x77BE),
                ("/run", RuleOrigin::UserTmpfs, 0x77BE),
            ]
        );
        assert_eq!(
            shadowed_summary(&rs),
            vec![
                ("/dev/pts", 0xF7BE, 0xF7BF),
                ("/dev/shm", 0x77BE, 0xF7BF),
                ("/run", 0x77BE, 0x77BF),
            ]
        );
        // WRITE を 1 ビットでも持つ宛先は、暗黙の /dev 系と利用者 tmpfs だけ。
        let writable: Vec<&str> = rs
            .rules()
            .iter()
            .filter(|r| !r.allowed.intersection(AccessFs::WRITE).is_empty())
            .map(|r| r.path.as_str())
            .collect();
        assert_eq!(writable, vec!["/dev", "/dev/pts", "/dev/shm", "/run"]);
        assert!(
            rule(&rs, "/")
                .allowed
                .intersection(AccessFs::WRITE)
                .is_empty()
        );

        // ro の利用者 tmpfs と、2 件目の rw tmpfs。
        let ro = tmpfs("/ro", json!(["ro", "nosuid", "nodev"]));
        let cache = tmpfs("/var/cache", json!(rw));
        let rs = build_path_rules_with_user_tmpfs(
            &s,
            c.root(),
            &[],
            &[ro, run, cache],
            ImplicitDevMounts::None,
            &BindMountSet::default(),
        )
        .expect("rules");
        assert_eq!(
            summary(&rs),
            vec![
                ("/", RuleOrigin::Root, 0x000D),
                ("/run", RuleOrigin::UserTmpfs, 0x77BE),
                ("/var/cache", RuleOrigin::UserTmpfs, 0x77BE),
            ]
        );
    }

    /// CORE-5（#1657）: 暗黙分を含めない版は root のみで、上限は暗黙分を含めた値のまま。
    #[test]
    fn core5_build_without_implicit_matches_previous_behavior() {
        let rs = build(&cfg(true, json!([])));
        assert_eq!(summary(&rs), vec![("/", RuleOrigin::Root, 0x000D)]);
        assert!(rs.shadowed().is_empty());
        assert_eq!(MAX_LANDLOCK_RULES, 1092);
    }

    /// CORE-5（#1657）: `mounts[]` が空でも暗黙の `/dev` 系のルールが具体的な権利で付く。
    /// 読み取り専用 root でも `/dev` には書き込みが付く。
    #[test]
    fn core5_implicit_dev_rules_readonly_root() {
        let rs = build_all(&cfg(true, json!([])));
        let dev = |m| RuleOrigin::Implicit { mount: m };
        assert_eq!(
            summary(&rs),
            vec![
                ("/", RuleOrigin::Root, 0x000D),
                ("/dev", dev(ImplicitDevMount::Dev), 0xF7BF),
                ("/dev/pts", dev(ImplicitDevMount::DevPts), 0xF7BE),
                ("/dev/shm", dev(ImplicitDevMount::DevShm), 0x77BE),
            ]
        );
        assert!(rule(&rs, "/dev").allowed.contains(AccessFs::WRITE_FILE));
        assert_eq!(
            shadowed_summary(&rs),
            vec![("/dev/pts", 0xF7BE, 0xF7BF), ("/dev/shm", 0x77BE, 0xF7BF)]
        );
    }

    #[test]
    fn core5_implicit_dev_rules_writable_root() {
        let rs = build_all(&cfg(false, json!([])));
        let got = summary(&rs);
        assert_eq!(got[0], ("/", RuleOrigin::Root, 0x77BF));
        assert_eq!(got[1].2, 0xF7BF);
        assert_eq!(got[2].2, 0xF7BE);
        assert_eq!(got[3].2, 0x77BE);
        assert_eq!(
            shadowed_summary(&rs),
            vec![("/dev/pts", 0xF7BE, 0xF7BF), ("/dev/shm", 0x77BE, 0xF7BF)]
        );
    }

    /// CORE-5（#1657）: `IOCTL_DEV` は `/dev`・`/dev/pts` だけ。`/dev2` 等の類似パスや `/dev/shm` には付かない。
    #[test]
    fn core5_ioctl_dev_only_on_implicit_dev_and_pts() {
        let rs = build_all(&cfg(
            true,
            json!([
                {"destination": "/dev2"},
                {"destination": "/devices"},
                {"destination": "/data"},
            ]),
        ));
        for p in ["/dev", "/dev/pts"] {
            assert!(rule(&rs, p).allowed.contains(AccessFs::IOCTL_DEV), "{p}");
        }
        for p in ["/", "/dev/shm", "/dev2", "/devices", "/data"] {
            assert!(!rule(&rs, p).allowed.contains(AccessFs::IOCTL_DEV), "{p}");
        }
    }

    /// CORE-5・SEC-1（#1657）: 暗黙分に `MAKE_CHAR` / `MAKE_BLOCK` は付かず、handled の部分集合である。
    #[test]
    fn core5_implicit_dev_rights_exclude_make_char_block() {
        let rs = build_all(&cfg(true, json!([])));
        for p in ["/dev", "/dev/pts", "/dev/shm"] {
            let a = rule(&rs, p).allowed;
            assert!(a.intersection(AccessFs::MAKE_CHAR).is_empty(), "{p}");
            assert!(a.intersection(AccessFs::MAKE_BLOCK).is_empty(), "{p}");
            assert!(a.is_subset_of(rs.handled_access_fs()), "{p}");
        }
    }

    /// CORE-5（#1657）: `mounts[]` が暗黙のマウント先と一致したら統合せず拒否する。配下（`/dev/fuse`）は受け付ける。
    #[test]
    fn core5_mount_conflicting_with_implicit_dev_is_rejected() {
        let s = evaluate_abi(6).expect("abi6");
        for dest in ["/dev", "/dev/pts", "/dev/shm", "/dev//shm/"] {
            let c = cfg(
                true,
                json!([{"destination": "/data"}, {"destination": dest}]),
            );
            let e = path_rules_from_config(&s, &c).expect_err("conflict");
            assert_eq!(
                e.kind,
                LandlockRuleErrorKind::ImplicitMountConflict { index: 1 },
                "{dest}"
            );
            assert_eq!(e.code, ErrorCode::InvalidArgument);
            assert_eq!(
                e.to_string(),
                "INVALID_ARGUMENT: mounts[1] targets a mount point the runtime provides \
                 implicitly (/dev, /dev/pts or /dev/shm)"
            );
        }
        let c = cfg(true, json!([{"destination": "/dev/fuse"}]));
        let rs = path_rules_from_config(&s, &c).expect("under implicit /dev is accepted");
        assert_eq!(
            rule(&rs, "/dev/fuse").origin,
            RuleOrigin::Mount { index: 0 }
        );
    }

    /// CORE-5（#1657）: 暗黙の `/dev` は書き込みを許すため、その配下の `ro` mount は狭められず拒否する。
    #[test]
    fn core5_mount_under_implicit_dev_write_restriction_rejected() {
        let s = evaluate_abi(6).expect("abi6");
        let c = cfg(true, json!([{"destination": "/dev/x", "options": ["ro"]}]));
        let e = path_rules_from_config(&s, &c).expect_err("rejected");
        assert_eq!(
            e.kind,
            LandlockRuleErrorKind::WriteRestrictionShadowed {
                index: 0,
                granted: AccessFs::WRITE,
            }
        );
        assert_eq!(AccessFs::WRITE.bits(), 0x77B2);
    }

    /// CORE-5（#1657）: 件数は `CONFIG_MAX_MOUNTS` 件 + 暗黙分でちょうど上限、1 件超えると拒否する。
    #[test]
    fn core5_rule_count_limit_with_implicit() {
        let s = evaluate_abi(6).expect("abi6");
        let one = cfg(true, json!([{"destination": "/a"}]));
        let m = one.mounts()[0].clone();
        let at = vec![m.clone(); CONFIG_MAX_MOUNTS];
        assert_eq!(
            build_path_rules(&s, one.root(), &at)
                .expect("at limit")
                .rules()
                .len(),
            5
        );
        let over = vec![m; CONFIG_MAX_MOUNTS + 1];
        let e = build_path_rules(&s, one.root(), &over).expect_err("over");
        assert_eq!(
            e.kind,
            LandlockRuleErrorKind::TooManyRules {
                count: 1029,
                max: 1028
            }
        );
    }

    #[test]
    fn core5_rule_error_kinds() {
        let e = LandlockRuleError::new(LandlockRuleErrorKind::RightsExceedHandled);
        assert_eq!(e.code, ErrorCode::Internal);
        let e = LandlockRuleError::new(LandlockRuleErrorKind::PathTooLong {
            len: 5000,
            max: 4096,
        });
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert!(e.message.contains("5000"));
    }

    #[test]
    fn core5_file_compatible_value() {
        assert_eq!(
            AccessFs::FILE_COMPATIBLE.bits(),
            0x8000 | 0x4000 | 4 | 2 | 1
        );
    }
}
