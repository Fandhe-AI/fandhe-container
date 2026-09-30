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
//! - Landlock は加算的で、祖先より狭い権利を子に強制できない。狭められない箇所は
//!   [`LandlockRuleset::shadowed`] に記録し、実際の保護は VFS の `ro` 等が担う（監査は TASK-41・SEC-4）
//! - `linux.readonlyPaths` / `maskedPaths` は参照しない（`unapplied_fields` 扱いで create が拒否する）
//!
//! # 未実装範囲（REPAIR-3）
//!
//! `landlock_add_rule` / `landlock_restrict_self`（#183）、ステージ列への組み込み（#184）は未実装。
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
    /// ruleset 属性へ渡す handled access。
    pub fn handled_access_fs(&self) -> AccessFs {
        self.handled_access_fs
    }

    /// パスごとのルール（先頭が rootfs、以降は config 順）。
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

/// mount 1 件が意図する権利（config の options / fs_type / destination から導出）。
fn mount_rights(m: &OciMount) -> AccessFs {
    let mut rights = AccessFs::READ.union(AccessFs::WRITE);
    let mut nodev = false;
    let mut writable = true;
    for opt in m.options() {
        match opt.as_str() {
            "ro" => writable = false,
            "rw" => writable = true,
            "noexec" => rights = rights.difference(AccessFs::EXECUTE),
            "nodev" => nodev = true,
            _ => {}
        }
    }
    if !writable {
        rights = rights.difference(AccessFs::WRITE);
    }
    if m.fs_type().is_some_and(|t| PSEUDO_FS.contains(&t)) {
        rights = rights.difference(AccessFs::WRITE);
    }
    if is_dev_path(m.mount_destination().as_str()) && !nodev {
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
        // 同一 destination は後のものが見える（OCI のマウント積み重ね）ため後勝ちにする。
        rules.retain(|r| r.path.as_str() != dest.as_str());
        rules.push(PathRule {
            path: RulePath::Beneath(dest.clone()),
            allowed: mount_rights(m),
            origin: RuleOrigin::Mount { index },
        });
    }

    let mut shadowed = Vec::new();
    for r in &rules {
        if matches!(r.origin, RuleOrigin::Root) {
            continue;
        }
        let effective = rules
            .iter()
            .filter(|a| is_ancestor(a.path.as_str(), r.path.as_str()))
            .fold(r.allowed, |acc, a| acc.union(a.allowed));
        if !effective.difference(r.allowed).is_empty() {
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

    #[test]
    fn core5_ro_rw_last_wins_and_noexec_nodev() {
        let c = cfg(
            true,
            json!([
                {"destination": "/a", "options": ["ro"]},
                {"destination": "/b", "options": ["rw", "ro"]},
                {"destination": "/c", "options": ["ro", "rw"]},
                {"destination": "/d", "options": ["noexec"]},
                {"destination": "/dev", "options": ["nodev"]},
            ]),
        );
        let rs = build(&c);
        assert_eq!(rule(&rs, "/a").allowed, AccessFs::READ);
        assert_eq!(rule(&rs, "/b").allowed, AccessFs::READ);
        assert_eq!(
            rule(&rs, "/c").allowed,
            AccessFs::READ.union(AccessFs::WRITE)
        );
        assert_eq!(
            rule(&rs, "/d").allowed,
            AccessFs::READ_FILE
                .union(AccessFs::READ_DIR)
                .union(AccessFs::WRITE)
        );
        assert!(
            rule(&rs, "/dev")
                .allowed
                .intersection(AccessFs::IOCTL_DEV)
                .is_empty()
        );
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

    #[test]
    fn core5_pseudo_fs_drops_write_and_records_shadowed() {
        let m = json!([
            {"destination": "/proc", "type": "proc"},
            {"destination": "/sys", "type": "sysfs"}
        ]);
        let rs = build(&cfg(false, m.clone()));
        assert_eq!(rule(&rs, "/proc").allowed, AccessFs::READ);
        assert_eq!(rs.shadowed().len(), 2);
        assert_eq!(rs.shadowed()[0].path.as_str(), "/proc");
        assert_eq!(rs.shadowed()[0].intended.bits(), 0x000D);
        assert_eq!(rs.shadowed()[0].effective.bits(), 0x77BF);
        let ro = build(&cfg(true, m));
        assert!(ro.shadowed().is_empty());
    }

    #[test]
    fn core5_shadowed_effective_includes_own_allowed() {
        // ro root 配下の writable noexec mount: 祖先の EXECUTE に加え自身の WRITE も実効に含まれる。
        let rs = build(&cfg(
            true,
            json!([{"destination": "/d", "options": ["noexec"]}]),
        ));
        let s = &rs.shadowed()[0];
        assert_eq!(s.path.as_str(), "/d");
        assert!(
            s.effective.is_subset_of(
                AccessFs::READ
                    .union(AccessFs::WRITE)
                    .union(AccessFs::EXECUTE)
            )
        );
        assert_eq!(
            s.effective.bits() & AccessFs::WRITE.bits(),
            AccessFs::WRITE.bits()
        );
        assert_eq!(
            s.effective.bits() & AccessFs::EXECUTE.bits(),
            AccessFs::EXECUTE.bits()
        );
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
            false,
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
