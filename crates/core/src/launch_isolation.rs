//! launch 時に確定した分離の記録（コンテナの `/` の同一性と適用した Landlock ルール。
//! SUP-6・CORE-5・SEC-1・TASK-163 追補・#1468）。
//!
//! # 役割と呼び出し文脈
//!
//! launch（本番 launcher。未結線）が pivot 後の `/` の識別子と、実際に適用する Landlock ruleset を 1 つの
//! [`LaunchIsolationRecord`] にまとめ、`CreateStateRequest::with_launch_isolation` /
//! `UpdateStateRequest::with_launch_isolation`（トレイト契約 12）で `state.json` へ残す。exec
//! （`exec/reapply.rs`。supervisor の `identify_pid1` が記録を取り出して渡す）は、この記録だけを根拠に
//! 「参加後の `/` が launch のコンテナの `/` か」を照合し、「記録と同じ Landlock ルール」を適用する。
//! `config.json` は launch の後に変わりうるため、exec の根拠にしない。
//!
//! 記録の型は `state_store`（3 OS で公開される `traits`）に載るため OS 非依存の素の型で持つ。Linux 限定の
//! ruleset との相互変換だけを `cfg(target_os = "linux")` で局所化する（CLI-1）。
//!
//! # 契約
//!
//! - 構築は検証つきの [`RecordedLandlock::new`] だけ（件数・ビット範囲・先頭が rootfs・重複なし）。
//!   `state.json` から読み戻した値も同じ関数で組み直す（untrusted。破損は呼び出し側が `Internal` にする）
//! - ルールの対象は [`RecordedTarget`] で、パスと由来が食い違う値を表現できない（REPAIR-2）
//! - [`Debug`](std::fmt::Debug) はルールの件数だけを出し、パス・識別子の値を載せない
//! - ルールの対象ごとの `(st_dev, st_ino)` は記録しない（launch の子から親へ状態 pipe が要るため。未実装）。
//!   「同じ対象」は、照合済みの `/` の fd を起点に記録したパスを `O_NOFOLLOW` で 1 要素ずつ辿ることと、
//!   対象がすべてマウントポイント（`CAP_SYS_ADMIN` が無いと動かせない）であることで担保する
//!
//! # 未実装（REPAIR-3）
//!
//! - 記録を作って状態へ書く本番 launcher の結線（`exec/landlock.rs` の `launch_isolation_from_bundle` /
//!   `LaunchIsolationRecord::new` は結線待ち。結線までは exec が記録なしで拒否する）
//! - restart の再 launch での記録の更新（`UpdateStateRequest::with_launch_isolation`。再 launch で mount namespace が
//!   作り直されるため、更新しないと restart 後の exec は `/` の照合で拒否される。fail-closed）

use std::fmt;

use crate::dev_mounts::{IMPLICIT_DEV_MOUNT_COUNT, ImplicitDevMount};
use crate::oci_runtime::{CONFIG_MAX_MOUNTS, MountDestination};

/// 記録できるルール本数の上限（`landlock::MAX_LANDLOCK_RULES` と同じ値。mount 上限 + rootfs 1 本 + 暗黙の `/dev` 系）。
pub const MAX_RECORDED_RULES: usize = CONFIG_MAX_MOUNTS + 1 + IMPLICIT_DEV_MOUNT_COUNT;

/// 既知の Landlock fs 権利ビットの全体（`landlock::AccessFs::ALL` と同じ値。Linux 以外でも検証できるよう複製し、
/// Linux では単体テストで一致を照合する）。
const ALL_FS_ACCESS_BITS: u64 = 0xFFFF;

/// 記録の検証に失敗した理由（固定の英語文言。パスや値を含めない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchIsolationError(&'static str);

impl LaunchIsolationError {
    /// 機械可読な固定文言。
    pub fn message(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for LaunchIsolationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for LaunchIsolationError {}

/// ディレクトリの同一性（`st_dev`・`st_ino`）。コンテナの `/` の識別に使う。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RootIdentity {
    dev: u64,
    ino: u64,
}

impl RootIdentity {
    /// 値から作る（`state.json` の読み戻し・試験用）。
    pub fn new(dev: u64, ino: u64) -> Self {
        Self { dev, ino }
    }

    /// `st_dev`。
    pub fn dev(&self) -> u64 {
        self.dev
    }

    /// `st_ino`。
    pub fn ino(&self) -> u64 {
        self.ino
    }

    /// ディレクトリを指す fd（`O_PATH` 可）から識別子を作る。ディレクトリでない・調べられない場合は `None`。
    ///
    /// パスを再解決せず fstat する（複製は同じ open file description を指す）。
    #[cfg(target_os = "linux")]
    pub fn of_dir_fd(fd: std::os::fd::BorrowedFd<'_>) -> Option<Self> {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::File::from(fd.try_clone_to_owned().ok()?)
            .metadata()
            .ok()?;
        meta.is_dir().then(|| Self::new(meta.dev(), meta.ino()))
    }
}

impl fmt::Debug for RootIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootIdentity(..)")
    }
}

/// Landlock ルール 1 件の対象（パスと由来を一体で持つ）。
#[derive(Clone, PartialEq, Eq)]
pub enum RecordedTarget {
    /// rootfs（`/`。config の `root`）。
    Root,
    /// config の `mounts[index]` の destination。
    Mount {
        /// 検証済みのコンテナ内マウント先。
        destination: MountDestination,
        /// `mounts` 内の位置。
        index: usize,
    },
    /// ランタイムが暗黙に載せるマウント（`/dev`・`/dev/pts`・`/dev/shm`）。
    Implicit(ImplicitDevMount),
}

impl RecordedTarget {
    /// コンテナ内パス文字列。
    pub fn as_str(&self) -> &str {
        match self {
            Self::Root => "/",
            Self::Mount { destination, .. } => destination.as_str(),
            Self::Implicit(m) => m.destination(),
        }
    }
}

/// 記録した Landlock ルール 1 件。
#[derive(Clone, PartialEq, Eq)]
pub struct RecordedRule {
    target: RecordedTarget,
    allowed: u64,
}

impl RecordedRule {
    /// 対象と許可する権利のビット値から作る（範囲の検証は [`RecordedLandlock::new`]）。
    pub fn new(target: RecordedTarget, allowed: u64) -> Self {
        Self { target, allowed }
    }

    /// 対象。
    pub fn target(&self) -> &RecordedTarget {
        &self.target
    }

    /// 許可する権利のビット値。
    pub fn allowed(&self) -> u64 {
        self.allowed
    }
}

/// launch が適用した Landlock の handled access とルール（`LandlockRuleset` の素の型での写し）。
#[derive(Clone, PartialEq, Eq)]
pub struct RecordedLandlock {
    handled: u64,
    rules: Vec<RecordedRule>,
}

impl RecordedLandlock {
    /// 検証して作る。
    ///
    /// 拒否: ルールが空・[`MAX_RECORDED_RULES`] 超過 / `handled` が空・既知のビット外 / `allowed` が `handled` の
    /// 外 / 先頭が rootfs でない・rootfs が重複 / 同じパスの重複 / マウント位置が `mounts` の上限以上。
    pub fn new(handled: u64, rules: Vec<RecordedRule>) -> Result<Self, LaunchIsolationError> {
        let err = LaunchIsolationError;
        if rules.is_empty() || rules.len() > MAX_RECORDED_RULES {
            return Err(err("landlock rule count is out of range"));
        }
        if handled == 0 || handled & !ALL_FS_ACCESS_BITS != 0 {
            return Err(err("landlock handled access is out of range"));
        }
        if rules.iter().any(|r| r.allowed & !handled != 0) {
            return Err(err("landlock rule allows access outside the handled set"));
        }
        if rules.first().map(|r| &r.target) != Some(&RecordedTarget::Root) {
            return Err(err("the first landlock rule must be the root"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for r in &rules {
            if let RecordedTarget::Mount { index, .. } = &r.target
                && *index >= CONFIG_MAX_MOUNTS
            {
                return Err(err("landlock rule mount index is out of range"));
            }
            if !seen.insert(r.target.as_str()) {
                return Err(err("landlock rules contain a duplicated path"));
            }
        }
        Ok(Self { handled, rules })
    }

    /// handled access のビット値。
    pub fn handled(&self) -> u64 {
        self.handled
    }

    /// ルール（先頭が rootfs）。
    pub fn rules(&self) -> &[RecordedRule] {
        &self.rules
    }
}

impl fmt::Debug for RecordedLandlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordedLandlock")
            .field("rules", &self.rules.len())
            .finish_non_exhaustive()
    }
}

/// launch 時の分離の記録（コンテナの `/` の同一性 + 適用した Landlock）。
///
/// 1 つの値にして「記録がある」ことを一体で判定できるようにする（片方だけの記録を表現できない）。
#[derive(Clone, PartialEq, Eq)]
pub struct LaunchIsolationRecord {
    root: RootIdentity,
    landlock: RecordedLandlock,
}

impl LaunchIsolationRecord {
    /// 検証済みの部品から作る。
    pub fn from_parts(root: RootIdentity, landlock: RecordedLandlock) -> Self {
        Self { root, landlock }
    }

    /// launch 時の pivot 後の `/` の識別子。
    pub fn root(&self) -> RootIdentity {
        self.root
    }

    /// 適用した Landlock の記録。
    pub fn landlock(&self) -> &RecordedLandlock {
        &self.landlock
    }
}

impl fmt::Debug for LaunchIsolationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaunchIsolationRecord")
            .field("landlock", &self.landlock)
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        LaunchIsolationError, LaunchIsolationRecord, RecordedLandlock, RecordedRule,
        RecordedTarget, RootIdentity,
    };
    use crate::landlock::{AccessFs, LandlockRuleset, PathRule, RuleOrigin, RulePath};

    impl LaunchIsolationRecord {
        /// launch が適用する `ruleset` と、launch 後の `/` の識別子から記録を作る。
        ///
        /// 汎用の入口: overlay のように rootfs を mount namespace の中で組み立てる launcher は、子の post-pivot の
        /// `/` から [`RootIdentity`] を得て渡す（ホスト側の bundle ディレクトリの識別子ではない）。
        pub fn new(
            root: RootIdentity,
            ruleset: &LandlockRuleset,
        ) -> Result<Self, LaunchIsolationError> {
            let rules = ruleset
                .rules()
                .iter()
                .map(recorded_rule)
                .collect::<Result<Vec<_>, _>>()?;
            let landlock = RecordedLandlock::new(ruleset.handled_access_fs().bits(), rules)?;
            Ok(Self::from_parts(root, landlock))
        }

        /// 記録から Landlock ruleset を組み直す（exec の再適用用。ABI の再検出も `config.json` の再解釈もしない）。
        pub(crate) fn landlock_ruleset(&self) -> Result<LandlockRuleset, LaunchIsolationError> {
            let bad = LaunchIsolationError("recorded landlock access is out of range");
            let handled = AccessFs::from_bits(self.landlock.handled()).ok_or(bad)?;
            let rules = self
                .landlock
                .rules()
                .iter()
                .map(|r| {
                    let allowed = AccessFs::from_bits(r.allowed()).ok_or(bad)?;
                    let (path, origin) = match r.target() {
                        RecordedTarget::Root => (RulePath::Root, RuleOrigin::Root),
                        RecordedTarget::Mount { destination, index } => (
                            RulePath::Beneath(destination.clone()),
                            RuleOrigin::Mount { index: *index },
                        ),
                        RecordedTarget::Implicit(m) => (
                            RulePath::ImplicitDev(*m),
                            RuleOrigin::Implicit { mount: *m },
                        ),
                    };
                    Ok(PathRule {
                        path,
                        allowed,
                        origin,
                    })
                })
                .collect::<Result<Vec<_>, LaunchIsolationError>>()?;
            Ok(LandlockRuleset::from_recorded(handled, rules))
        }
    }

    fn recorded_rule(rule: &PathRule) -> Result<RecordedRule, LaunchIsolationError> {
        let target = match (&rule.path, &rule.origin) {
            (RulePath::Root, RuleOrigin::Root) => RecordedTarget::Root,
            (RulePath::Beneath(d), RuleOrigin::Mount { index }) => RecordedTarget::Mount {
                destination: d.clone(),
                index: *index,
            },
            (RulePath::ImplicitDev(p), RuleOrigin::Implicit { mount }) if p == mount => {
                RecordedTarget::Implicit(*mount)
            }
            _ => {
                return Err(LaunchIsolationError(
                    "landlock rule path and origin do not match",
                ));
            }
        };
        Ok(RecordedRule::new(target, rule.allowed.bits()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(s: &str) -> MountDestination {
        MountDestination::parse(s).expect("destination")
    }

    fn root_rule(allowed: u64) -> RecordedRule {
        RecordedRule::new(RecordedTarget::Root, allowed)
    }

    fn mount_rule(path: &str, index: usize, allowed: u64) -> RecordedRule {
        RecordedRule::new(
            RecordedTarget::Mount {
                destination: dest(path),
                index,
            },
            allowed,
        )
    }

    /// SUP-6・CORE-5・#1468: 件数・ビット範囲・先頭・重複の検証を具体値で照合する。
    #[test]
    fn sup6_task163_1468_validate_rejects_malformed_records() {
        let ok = |h: u64, r: Vec<RecordedRule>| RecordedLandlock::new(h, r);
        assert!(ok(0xFFFF, vec![root_rule(0x7)]).is_ok());
        let msg = |r: Result<RecordedLandlock, LaunchIsolationError>| r.unwrap_err().message();
        assert_eq!(
            msg(ok(0xFFFF, vec![])),
            "landlock rule count is out of range"
        );
        let many = (0..MAX_RECORDED_RULES)
            .map(|i| mount_rule(&format!("/m{i}"), i % CONFIG_MAX_MOUNTS, 0))
            .collect::<Vec<_>>();
        let mut over = vec![root_rule(0)];
        over.extend(many);
        assert_eq!(over.len(), MAX_RECORDED_RULES + 1);
        assert_eq!(msg(ok(0xFFFF, over)), "landlock rule count is out of range");
        assert_eq!(
            msg(ok(0, vec![root_rule(0)])),
            "landlock handled access is out of range"
        );
        assert_eq!(
            msg(ok(0x1_0000, vec![root_rule(0)])),
            "landlock handled access is out of range"
        );
        assert_eq!(
            msg(ok(0x7, vec![root_rule(0x8)])),
            "landlock rule allows access outside the handled set"
        );
        assert_eq!(
            msg(ok(0xFFFF, vec![mount_rule("/data", 0, 1)])),
            "the first landlock rule must be the root"
        );
        assert_eq!(
            msg(ok(0xFFFF, vec![root_rule(1), root_rule(1)])),
            "landlock rules contain a duplicated path"
        );
        assert_eq!(
            msg(ok(
                0xFFFF,
                vec![root_rule(1), mount_rule("/a", 0, 1), mount_rule("/a", 1, 1)]
            )),
            "landlock rules contain a duplicated path"
        );
        assert_eq!(
            msg(ok(
                0xFFFF,
                vec![root_rule(1), mount_rule("/a", CONFIG_MAX_MOUNTS, 1)]
            )),
            "landlock rule mount index is out of range"
        );
    }

    /// `Debug` は件数だけを出し、パスや識別子の値を載せない。
    #[test]
    fn sup6_task163_1468_debug_hides_paths_and_identity() {
        let landlock =
            RecordedLandlock::new(0xFFFF, vec![root_rule(1), mount_rule("/secret-path", 0, 1)])
                .unwrap();
        let rec = LaunchIsolationRecord::from_parts(RootIdentity::new(4242, 9_999_001), landlock);
        let s = format!("{rec:?}");
        assert!(s.contains("rules: 2"), "{s}");
        assert!(!s.contains("secret-path"), "{s}");
        assert!(!s.contains("9999001") && !s.contains("4242"), "{s}");
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use crate::landlock::{AccessFs, MAX_LANDLOCK_RULES, path_rules_from_config};
        use crate::oci_runtime::parse_config_bytes;

        #[test]
        fn sup6_task163_1468_constants_match_landlock_module() {
            assert_eq!(MAX_RECORDED_RULES, MAX_LANDLOCK_RULES);
            assert_eq!(ALL_FS_ACCESS_BITS, AccessFs::ALL.bits());
        }

        /// 記録から ruleset を組み直すと、handled・ルール（パス・由来・権利）が元と一致する。
        #[test]
        fn sup6_task163_1468_record_round_trips_ruleset() {
            let cfg = parse_config_bytes(
                br#"{"ociVersion":"1.2.0","root":{"path":"rootfs","readonly":true},
                    "mounts":[{"destination":"/data","type":"bind","source":"/h","options":["rbind"]},
                              {"destination":"/tmp","type":"tmpfs","source":"tmpfs"}]}"#,
            )
            .expect("config");
            let support = crate::landlock::evaluate_abi(6).expect("abi6");
            let ruleset = path_rules_from_config(&support, &cfg).expect("rules");
            let rec = LaunchIsolationRecord::new(RootIdentity::new(1, 2), &ruleset).expect("rec");
            assert_eq!(rec.root(), RootIdentity::new(1, 2));
            assert_eq!(rec.landlock().rules().len(), ruleset.rules().len());
            let back = rec.landlock_ruleset().expect("ruleset");
            assert_eq!(back.handled_access_fs(), ruleset.handled_access_fs());
            assert_eq!(back.rules(), ruleset.rules());
        }
    }
}
