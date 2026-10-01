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
//!   疑似 FS の書き込み禁止は VFS の裏付けが無く Landlock だけが担うため、記録だけでは守れない
//! - 実行・`IOCTL_DEV` だけが祖先で広がる箇所（`/dev` 配下の `noexec,nodev` mount 等）は、VFS の
//!   `noexec` / `nodev` が必ず効くため許容し、[`LandlockRuleset::shadowed`] に記録する（監査は TASK-41・SEC-4）
//! - `linux.readonlyPaths` / `maskedPaths` は参照しない（`unapplied_fields` 扱いで create が拒否する）
//!
//! # 未実装範囲（REPAIR-3）
//!
//! ステージ列への組み込み（#184）は未実装（`landlock_add_rule` / `landlock_restrict_self` による適用は
//! #183・`apply` 子モジュールで実装済み）。
//! GPU 向けの権利拡張は TASK-128（GPU-3）が後から追加する。

use std::fmt;

use super::LandlockSupport;
use crate::oci_runtime::{
    CONFIG_MAX_MOUNTS, CONFIG_MAX_PATH_BYTES, MountDestination, OciConfig, OciMount, OciRoot,
};
use crate::traits::ErrorCode;

/// 生成するルール本数の上限（mount 上限 + rootfs 1 本。DoS 防止）。
pub const MAX_LANDLOCK_RULES: usize = CONFIG_MAX_MOUNTS + 1;

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
fn handled_for_abi(abi: u32) -> AccessFs {
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
}

impl RulePath {
    /// コンテナ内パス文字列。
    pub fn as_str(&self) -> &str {
        match self {
            Self::Root => "/",
            Self::Beneath(d) => d.as_str(),
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
/// 書き込み系の権利が広がる場合は記録せず拒否する（[`LandlockRuleErrorKind::WriteRestrictionShadowed`]）
/// ため、ここに残るのは VFS の `noexec` / `nodev` が保護する実行・`IOCTL_DEV` の差分だけである。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ShadowedRestriction {
    /// 対象パス。
    pub path: RulePath,
    /// config が意図する権利。
    pub intended: AccessFs,
    /// 祖先ルールの和集合に対象ルール自身の許可を加えたもの（実際に効く権限）。
    pub effective: AccessFs,
}

/// 生成結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LandlockRuleset {
    handled_access_fs: AccessFs,
    rules: Vec<PathRule>,
    shadowed: Vec<ShadowedRestriction>,
}

impl LandlockRuleset {
    /// 結合試験用観測関数 `observe_landlock_enforcement` と単体テストが、config を経由せず ABI から
    /// handled access を決めて組み立てる（CORE-5・TASK-39.3・#183。公開 API は増やさない）。
    pub(crate) fn for_observation(abi: u32, rules: Vec<PathRule>) -> Self {
        Self {
            handled_access_fs: handled_for_abi(abi),
            rules,
            shadowed: Vec::new(),
        }
    }

    /// ruleset 属性へ渡す handled access。
    pub fn handled_access_fs(&self) -> AccessFs {
        self.handled_access_fs
    }

    /// パスごとのルール（先頭が rootfs、以降は config 順。後のマウントに覆い隠されたマウントは含めない）。
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

/// `root` と `mounts` から Landlock ルールを生成する（CORE-5・TASK-39.2）。
///
/// 件数を先に検証してから確保する。検出を通過した `support` なしでは呼べない（fail-closed）。
pub fn build_path_rules(
    support: &LandlockSupport,
    root: &OciRoot,
    mounts: &[OciMount],
) -> Result<LandlockRuleset, LandlockRuleError> {
    let handled = handled_for_abi(support.abi.get());
    let count = mounts.len().saturating_add(1);
    if count > MAX_LANDLOCK_RULES {
        return Err(LandlockRuleError::new(
            LandlockRuleErrorKind::TooManyRules {
                count,
                max: MAX_LANDLOCK_RULES,
            },
        ));
    }
    let mut rules: Vec<PathRule> = Vec::with_capacity(count);
    rules.push(PathRule {
        path: RulePath::Root,
        allowed: root_rights(root.readonly()),
        origin: RuleOrigin::Root,
    });
    for (index, m) in mounts.iter().enumerate() {
        let dest = m.mount_destination();
        let len = dest.as_str().len();
        if len > CONFIG_MAX_PATH_BYTES {
            return Err(LandlockRuleError::new(LandlockRuleErrorKind::PathTooLong {
                len,
                max: CONFIG_MAX_PATH_BYTES,
            }));
        }
        // 後のマウントは同一 destination とその配下にある先のマウントを覆い隠す（OCI の適用順）。
        // 隠れたマウントのルールを残すと、後のマウント内の同名パスへ先の権利を与えるため除外する。
        rules.retain(|r| {
            let p = r.path.as_str();
            p != dest.as_str() && !is_ancestor(dest.as_str(), p)
        });
        rules.push(PathRule {
            path: RulePath::Beneath(dest.clone()),
            allowed: mount_rights(m),
            origin: RuleOrigin::Mount { index },
        });
    }

    let mut shadowed = Vec::new();
    for r in &rules {
        // rootfs には祖先が無い。
        let RuleOrigin::Mount { index } = r.origin else {
            continue;
        };
        let effective = rules
            .iter()
            .filter(|a| is_ancestor(a.path.as_str(), r.path.as_str()))
            .fold(r.allowed, |acc, a| acc.union(a.allowed));
        let widened = effective.difference(r.allowed);
        let granted_writes = widened.intersection(AccessFs::WRITE);
        if !granted_writes.is_empty() {
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
            });
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
    })
}

/// [`build_path_rules`] の `OciConfig` 版の薄いラッパー。
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

    fn build(c: &OciConfig) -> LandlockRuleset {
        let s = evaluate_abi(6).expect("abi6");
        path_rules_from_config(&s, c).expect("rules")
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
                {"destination": "/sys", "type": "sysfs", "options": ["rw"]}
            ]),
        ));
        assert_eq!(rule(&rs, "/proc").allowed.bits(), 0x000D);
        assert_eq!(rule(&rs, "/sys").allowed.bits(), 0x000D);
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
            let e = path_rules_from_config(&s, &cfg(readonly, mounts)).expect_err("rejected");
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
        // 同一 destination は後勝ちで 1 本にまとまる。
        assert_eq!(rs.rules().len(), 2);
        let over = vec![m; CONFIG_MAX_MOUNTS + 1];
        let e = build_path_rules(&s, one.root(), &over).expect_err("over limit");
        assert_eq!(
            e.kind,
            LandlockRuleErrorKind::TooManyRules {
                count: 1026,
                max: 1025
            }
        );
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert!(e.to_string().starts_with("INVALID_ARGUMENT: "), "{e}");
        assert_eq!(MAX_LANDLOCK_RULES, 1025);
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
