//! launch 時に確定した分離の記録（コンテナの `/` の同一性と適用した Landlock ルール。
//! SUP-6・CORE-5・SEC-1・TASK-163 追補・#1468）。
//!
//! # 役割と呼び出し文脈
//!
//! launch（本番 launcher。結線済み・#2007）が pivot 後の `/` の識別子と、実際に適用する Landlock ruleset を 1 つの
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
//! # 書き込みの経路と残る範囲（REPAIR-3）
//!
//! - 本番 launcher は `StagePipeline::with_landlock` へ渡す ruleset そのものと、pin 済みの rootfs fd の fstat から
//!   記録を作り、`LaunchedProcess::launch_isolation` で返す。start が Running の更新と同じ 1 回の `update` で書き、
//!   supervisor の restart が Running(新 pid) の更新で置き換える（#2007）。作れなければ fork 前に launch が失敗する
//! - 再 launch したハンドルが記録を持たない（偽の launcher のみ）場合は、契約 12 に従い前の記録を引き継ぐ
//! - 本番 launcher による restart の再 launch は、単一スレッドの要求で今も拒否される（#2043）

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

/// カーネル監査のログ制御フラグを渡せる最小の Landlock ABI（ABI 7。OS 非依存の定義。`crate::landlock` が再利用する。SEC-4・#2026）。
pub const MIN_LANDLOCK_AUDIT_ABI: u32 = 7;

/// launch が Landlock の拒否をカーネル監査へ残す要求をしたかの記録（OS 非依存の語彙。SEC-4・#2026）。
///
/// `crate::landlock::LandlockAuditMode` の写し。ワークロードの拒否の記録はカーネル監査（読み手は外部）で、
/// この値は「要求したか・縮退したか」を `state.json` に残すだけである。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordedLandlockAudit {
    /// ログ制御フラグで execve の後の拒否の記録を要求した（Landlock ABI 7 以上）。
    KernelAuditRequested,
    /// ABI がログ制御フラグに未対応のため要求できなかった（縮退）。
    Unavailable {
        /// launch 時に検出した ABI。
        detected_abi: u32,
    },
    /// 記録が無い（このフィールドが入る前の `state.json`）。旧記録はフラグ無しで適用されているため、
    /// 欠落を「監査あり」と解釈しない。
    NotRecorded,
}

impl RecordedLandlockAudit {
    /// 永続化して読み戻せる値かを検証する（`state.json` の読み出し側の規則と同一。SEC-4・#2026）。
    ///
    /// `Unavailable` は縮退の記録なので、`detected_abi` は 1 以上かつ [`MIN_LANDLOCK_AUDIT_ABI`] 未満に限る
    /// （0 は ABI を検出できていない値、要求 ABI 以上は縮退していない値で、どちらも矛盾する）。
    pub fn validate(self) -> Result<Self, LaunchIsolationError> {
        match self {
            Self::Unavailable { detected_abi }
                if detected_abi == 0 || detected_abi >= MIN_LANDLOCK_AUDIT_ABI =>
            {
                Err(LaunchIsolationError(
                    "landlock audit degraded ABI is out of range",
                ))
            }
            other => Ok(other),
        }
    }
}

/// launch が適用した Landlock の handled access とルール（`LandlockRuleset` の素の型での写し）。
#[derive(Clone, PartialEq, Eq)]
pub struct RecordedLandlock {
    handled: u64,
    rules: Vec<RecordedRule>,
    audit: RecordedLandlockAudit,
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
        Ok(Self {
            handled,
            rules,
            audit: RecordedLandlockAudit::NotRecorded,
        })
    }

    /// カーネル監査の要求の記録を添える（SEC-4・#2026）。
    ///
    /// [`RecordedLandlockAudit::validate`] を通らない値（`Unavailable` の ABI が 0、または要求 ABI
    /// [`MIN_LANDLOCK_AUDIT_ABI`] 以上）は拒否する。保存できても `state.json` から読み戻せない値を作らないため
    /// （永続化できる値は必ず読み戻せる）。
    pub fn with_audit(
        mut self,
        audit: RecordedLandlockAudit,
    ) -> Result<Self, LaunchIsolationError> {
        audit.validate()?;
        self.audit = audit;
        Ok(self)
    }

    /// カーネル監査の要求の記録。
    pub fn audit(&self) -> RecordedLandlockAudit {
        self.audit
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
    use super::RecordedLandlockAudit;
    use super::{
        LaunchIsolationError, LaunchIsolationRecord, RecordedLandlock, RecordedRule,
        RecordedTarget, RootIdentity,
    };
    use crate::landlock::{
        AccessFs, LandlockAuditMode, LandlockRuleset, PathRule, RuleOrigin, RulePath,
    };

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
            let audit = match ruleset.audit_mode() {
                LandlockAuditMode::KernelAuditRequested => {
                    RecordedLandlockAudit::KernelAuditRequested
                }
                LandlockAuditMode::Unavailable { detected, .. } => {
                    RecordedLandlockAudit::Unavailable {
                        detected_abi: detected,
                    }
                }
            };
            let landlock = RecordedLandlock::new(ruleset.handled_access_fs().bits(), rules)?
                .with_audit(audit)?;
            Ok(Self::from_parts(root, landlock))
        }

        /// 記録から Landlock ruleset を組み直す（exec の再適用用。ABI の再検出も `config.json` の再解釈もしない）。
        ///
        /// カーネル監査のモードは記録ではなく、呼び出し側が今のカーネルの ABI から決めて渡す（SEC-4・#2026）。
        pub(crate) fn landlock_ruleset(
            &self,
            audit: LandlockAuditMode,
        ) -> Result<LandlockRuleset, LaunchIsolationError> {
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
            Ok(LandlockRuleset::from_recorded(handled, rules, audit))
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

    /// SEC-4・#2026: `with_audit` は永続化して読み戻せる値だけを受ける。縮退の ABI は 1〜6 のみで、0 と 7 以上は拒否する
    /// （`LandlockAuditDto::into_record` と同じ規則。読み戻せない記録を保存させない）。
    #[test]
    fn sec4_2026_with_audit_rejects_unreadable_values() {
        let base = || RecordedLandlock::new(0xFFFF, vec![root_rule(0x7)]).unwrap();
        for ok in [
            RecordedLandlockAudit::NotRecorded,
            RecordedLandlockAudit::KernelAuditRequested,
            RecordedLandlockAudit::Unavailable { detected_abi: 1 },
            RecordedLandlockAudit::Unavailable { detected_abi: 6 },
        ] {
            assert_eq!(base().with_audit(ok).unwrap().audit(), ok);
        }
        for bad in [0, 7, 8, u32::MAX] {
            let err = base()
                .with_audit(RecordedLandlockAudit::Unavailable { detected_abi: bad })
                .unwrap_err();
            assert_eq!(err.message(), "landlock audit degraded ABI is out of range");
        }
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
            let back = rec.landlock_ruleset(ruleset.audit_mode()).expect("ruleset");
            assert_eq!(back.handled_access_fs(), ruleset.handled_access_fs());
            assert_eq!(back.rules(), ruleset.rules());
        }
    }
}
