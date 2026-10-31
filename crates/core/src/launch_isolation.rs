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
//! - Mount 由来のルール（暗黙の `/dev` 系・bind・利用者 tmpfs）の対象ごとの識別子（[`RecordedMountIdentity`]。
//!   `mnt_id`・`st_dev`・`st_ino`・`read_only`）は、launch の子が pivot 前段の直後に状態 pipe で親へ返し、
//!   launcher が [`RecordedLandlock::with_mount_identities`] で添える（SEC-1・SEC-4・#3201）。exec の再適用は
//!   これと適用時の観測を照合し、重ねられたマウントを検出する。識別子の無い旧記録
//!   （[`RecordedMountIdentities::Absent`]）の exec は拒否する（fail-closed）。記録は「全 Mount 由来のルールに
//!   あるか、全く無いか」のどちらかしか表現できない（REPAIR-2）
//!
//! # 書き込みの経路と残る範囲（REPAIR-3）
//!
//! - 本番 launcher は `StagePipeline::with_landlock` へ渡す ruleset そのものと、pin 済みの rootfs fd の fstat から
//!   記録を作り、`LaunchedProcess::launch_isolation` で返す。start が Running の更新と同じ 1 回の `update` で書き、
//!   supervisor の restart が Running(新 pid) の更新で置き換える（#2007）。作れなければ fork 前に launch が失敗する
//! - 再 launch したハンドルが記録を持たない（偽の launcher のみ）場合は、契約 12 に従い前の記録を引き継ぐ
//! - 本番 launcher による restart の再 launch は、supervisor が単一スレッドにしてから行う（#2043）

use std::fmt;

use crate::audit_log::{AuditCoverage, AuditCoveragePolicy};
use crate::capabilities::ContainerCapabilities;
use crate::dev_mounts::{IMPLICIT_DEV_MOUNT_COUNT, ImplicitDevMount};
use crate::oci_runtime::{CONFIG_MAX_MOUNTS, MountDestination};

/// 記録できるルール本数の上限（`landlock::MAX_LANDLOCK_RULES` と同じ値。mount 上限 + 利用者 tmpfs 上限 + rootfs 1 本 +
/// 暗黙の `/dev` 系）。
pub const MAX_RECORDED_RULES: usize =
    CONFIG_MAX_MOUNTS + crate::tmpfs::TMPFS_MAX_MOUNTS + 1 + IMPLICIT_DEV_MOUNT_COUNT;

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
    /// 利用者指定の tmpfs（`--tmpfs`。SUP-12・CORE-5・#2625）。
    Tmpfs {
        /// 検証済みのコンテナ内マウント先。
        destination: MountDestination,
    },
    /// ランタイムが暗黙に載せるマウント（`/dev`・`/dev/pts`・`/dev/shm`）。
    Implicit(ImplicitDevMount),
}

impl RecordedTarget {
    /// コンテナ内パス文字列。
    pub fn as_str(&self) -> &str {
        match self {
            Self::Root => "/",
            Self::Mount { destination, .. } | Self::Tmpfs { destination } => destination.as_str(),
            Self::Implicit(m) => m.destination(),
        }
    }
}

impl RecordedTarget {
    /// ランタイムが載せたマウント由来の対象か（`Root` 以外すべて。識別子の記録の対象）。
    pub fn is_mount_origin(&self) -> bool {
        !matches!(self, Self::Root)
    }
}

/// Mount 由来のルールの対象の launch 時の識別子（SEC-1・SEC-4・#3201）。
///
/// launch の子が各段の成功直後に採った `mnt_id`・`(st_dev, st_ino)` と、マウントが読み取り専用か。
/// exec の再適用が適用時の観測と照合する。構築は [`Self::new`] だけ（`mnt_id` 0 は無効）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RecordedMountIdentity {
    mnt_id: u64,
    dev: u64,
    ino: u64,
    read_only: bool,
}

impl RecordedMountIdentity {
    /// 値から作る。`mnt_id` は 0 を拒否する（カーネルは 0 を割り当てない）。
    pub fn new(
        mnt_id: u64,
        dev: u64,
        ino: u64,
        read_only: bool,
    ) -> Result<Self, LaunchIsolationError> {
        if mnt_id == 0 {
            return Err(LaunchIsolationError("mount identity has a zero mount id"));
        }
        Ok(Self {
            mnt_id,
            dev,
            ino,
            read_only,
        })
    }

    /// マウント ID。
    pub fn mnt_id(&self) -> u64 {
        self.mnt_id
    }

    /// ルートの `st_dev`。
    pub fn dev(&self) -> u64 {
        self.dev
    }

    /// ルートの `st_ino`。
    pub fn ino(&self) -> u64 {
        self.ino
    }

    /// 読み取り専用のマウントか。
    pub fn read_only(&self) -> bool {
        self.read_only
    }
}

impl fmt::Debug for RecordedMountIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordedMountIdentity(..)")
    }
}

/// [`RecordedLandlock`] が持つマウントの識別子の状態（全部あるか、全く無いか）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordedMountIdentities {
    /// 識別子が無い（このフィールドが入る前の `state.json`）。Mount 由来のルールがあれば exec は拒否する。
    Absent,
    /// Mount 由来の全ルールに識別子がある（Mount 由来のルールが 0 件の記録も含む）。
    Complete,
}

/// 記録した Landlock ルール 1 件。
#[derive(Clone, PartialEq, Eq)]
pub struct RecordedRule {
    target: RecordedTarget,
    allowed: u64,
    mount: Option<RecordedMountIdentity>,
}

impl RecordedRule {
    /// 対象と許可する権利のビット値から作る（範囲の検証は [`RecordedLandlock::new`]）。
    pub fn new(target: RecordedTarget, allowed: u64) -> Self {
        Self {
            target,
            allowed,
            mount: None,
        }
    }

    /// マウントの識別子を添える（`state.json` の読み戻し用。全体の整合は [`RecordedLandlock::new`] が検証する）。
    #[must_use]
    pub fn with_mount(mut self, mount: RecordedMountIdentity) -> Self {
        self.mount = Some(mount);
        self
    }

    /// launch 時のマウントの識別子（旧記録は `None`）。
    pub fn mount(&self) -> Option<&RecordedMountIdentity> {
        self.mount.as_ref()
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
    /// 外 / 先頭が rootfs でない・rootfs が重複 / 同じパスの重複 / マウント位置が `mounts` の上限以上 /
    /// rootfs に識別子がある・Mount 由来のルールの一部だけに識別子がある（全部か全く無いかのどちらか。#3201）。
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
        if rules
            .iter()
            .any(|r| !r.target.is_mount_origin() && r.mount.is_some())
        {
            return Err(err("landlock root rule must not carry a mount identity"));
        }
        let with = rules
            .iter()
            .filter(|r| r.target.is_mount_origin() && r.mount.is_some())
            .count();
        let total = rules.iter().filter(|r| r.target.is_mount_origin()).count();
        if with != 0 && with != total {
            return Err(err("landlock mount identities are partially recorded"));
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

    /// Mount 由来のルールの位置（`rules()` 内の添字）を昇順で返す（識別子の報告・期待列の共通の定義。#3201）。
    pub fn mount_rule_positions(&self) -> Vec<usize> {
        self.rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.target.is_mount_origin())
            .map(|(i, _)| i)
            .collect()
    }

    /// Mount 由来のルールへ launch 時の識別子を添える（SEC-1・SEC-4・#3201）。
    ///
    /// `entries` は `(rules() 内の位置, 識別子)` で、位置は昇順・重複なし・Mount 由来のルールだけ、かつ
    /// Mount 由来の全ルールを過不足なく覆うこと（Mount 由来が 0 件なら空）。満たさなければ拒否する。
    pub fn with_mount_identities(
        mut self,
        entries: Vec<(usize, RecordedMountIdentity)>,
    ) -> Result<Self, LaunchIsolationError> {
        let err = LaunchIsolationError;
        let expected = self.mount_rule_positions();
        if entries.len() != expected.len()
            || entries.iter().map(|(i, _)| *i).ne(expected.iter().copied())
        {
            return Err(err(
                "landlock mount identities do not cover the mount rules exactly",
            ));
        }
        for (i, id) in entries {
            if let Some(r) = self.rules.get_mut(i) {
                r.mount = Some(id);
            }
        }
        Ok(self)
    }

    /// マウントの識別子の状態（全部あるか、全く無いか）。
    pub fn mount_identities(&self) -> RecordedMountIdentities {
        let mut it = self.rules.iter().filter(|r| r.target.is_mount_origin());
        match it.next() {
            Some(first) if first.mount.is_some() => RecordedMountIdentities::Complete,
            Some(_) => RecordedMountIdentities::Absent,
            // Mount 由来のルールが無ければ照合する対象が無い（exec は拒否しない）。
            None => RecordedMountIdentities::Complete,
        }
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

/// launch が評価した監査の網羅の記録（SEC-4・#2027。OS 非依存の語彙）。
///
/// 方針と、カーネル監査頼みの 2 層の状態を残す。`inspect` の `auditCoverage` と `state.json` の
/// `launchIsolation.auditCoverage` の元になる。`Requested` は「要求した」だけで「記録された」ではない
/// （`audit_log::coverage` の契約）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordedAuditCoverage {
    /// 記録が無い（このフィールドが入る前の `state.json`）。欠落を「網羅している」と解釈しない。
    NotRecorded,
    /// launch が評価した結果。
    Evaluated {
        /// 評価時の方針。
        policy: AuditCoveragePolicy,
        /// 2 層の状態。
        coverage: AuditCoverage,
    },
}

/// 縮退の監査記録（層 `audit_coverage`）の書き込み結果の記録（SEC-4・REPAIR-4・#2468。OS 非依存の語彙）。
///
/// launcher が記録先へ書けなかった事実を起動結果に載せ、supervisor が `@supervisor-logs` へ固定の 1 行として
/// 出し直す元になる。`NotFailed` は「失敗を観測していない」だけで、「記録された」ことの保証ではない
/// （縮退が無い・記録に成功した・旧記録で不明のいずれか）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditCoverageRecordOutcome {
    /// 失敗を観測していない。
    NotFailed,
    /// 縮退の監査記録を記録先へ書けなかった。
    Failed,
}

impl AuditCoverageRecordOutcome {
    /// 失敗したときだけ、supervisor が保存する固定の診断行（改行なし）を返す。
    pub fn log_line(self) -> Option<&'static str> {
        match self {
            Self::Failed => Some(crate::audit_log::AUDIT_COVERAGE_RECORD_FAILED_LINE),
            _ => None,
        }
    }

    /// `inspect` の `auditCoverage.record` の固定語彙（SEC-4・REPAIR-4・#2601）。失敗したときだけ `Some("failed")`。
    /// `None` は「失敗を観測していない」で、「記録された」ことの保証ではない。
    pub fn as_str(self) -> Option<&'static str> {
        match self {
            Self::Failed => Some("failed"),
            Self::NotFailed => None,
        }
    }
}

/// 記録できる ID 写像の範囲（行）数の上限（uid・gid それぞれ。`rootless::MAX_EXTENTS` と同じ値。Linux では単体テストで
/// 一致を照合する。CORE-6・#2388）。
pub const MAX_RECORDED_ID_EXTENTS: usize = 340;

/// launch が選んだ ID 写像のモデル（`inspect` の `idMapping.model` の語彙。CORE-6・SEC-5・REPAIR-4・#2388）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordedIdModel {
    /// 1 対 1 写像（起動ユーザーの ID をコンテナ内 0 の 1 件だけへ写す。`RootlessSingleId`）。
    Single,
    /// 範囲写像（subuid / subgid の範囲を加える。`RootlessSubordinateIds`）。
    Subordinate,
}

impl RecordedIdModel {
    /// 機械可読な固定語彙（`state.json`・inspect・supervisor のログの `model=` と同じ）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Subordinate => "subordinate",
        }
    }

    /// [`Self::as_str`] の逆引き（未知の語彙は `None`）。
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "single" => Some(Self::Single),
            "subordinate" => Some(Self::Subordinate),
            _ => None,
        }
    }
}

/// ID 写像の 1 行（コンテナ側先頭・ホスト側先頭・個数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordedIdExtent {
    /// コンテナ側の先頭 ID。
    pub container_id: u32,
    /// ホスト側の先頭 ID（記録値。権限判断やシグナル送信先に使わない）。
    pub host_id: u32,
    /// 個数。
    pub size: u32,
}

/// launch が実際に使った ID 写像の記録（モデルと uid・gid の範囲。CORE-6・SEC-5・REPAIR-4・#2388）。
///
/// 構築は検証つきの [`Self::new`] だけ。`state.json` から読み戻した値も同じ関数で組み直す（untrusted）。
/// 観測専用で、モデルの選択や権限判断には使わない。
#[derive(Clone, PartialEq, Eq)]
pub struct RecordedIdMapping {
    model: RecordedIdModel,
    uid: Vec<RecordedIdExtent>,
    gid: Vec<RecordedIdExtent>,
}

fn validate_id_extents(
    model: RecordedIdModel,
    extents: &[RecordedIdExtent],
) -> Result<(), LaunchIsolationError> {
    let err = LaunchIsolationError;
    if extents.is_empty() || extents.len() > MAX_RECORDED_ID_EXTENTS {
        return Err(err("id mapping extent count is out of range"));
    }
    let mut container = Vec::with_capacity(extents.len());
    let mut host = Vec::with_capacity(extents.len());
    for e in extents {
        if e.size == 0 {
            return Err(err("id mapping extent size is zero"));
        }
        let c_end = u64::from(e.container_id) + u64::from(e.size);
        let h_end = u64::from(e.host_id) + u64::from(e.size);
        if c_end > u64::from(u32::MAX) + 1 || h_end > u64::from(u32::MAX) + 1 {
            return Err(err("id mapping range overflows u32"));
        }
        if e.host_id == 0 {
            return Err(err("id mapping must not map to host id 0"));
        }
        container.push((u64::from(e.container_id), c_end));
        host.push((u64::from(e.host_id), h_end));
    }
    for mut ranges in [container, host] {
        ranges.sort_unstable();
        if ranges.windows(2).any(|w| match (w.first(), w.get(1)) {
            (Some(a), Some(b)) => b.0 < a.1,
            _ => false,
        }) {
            return Err(err("id mapping ranges overlap"));
        }
    }
    if extents.first().map(|e| e.container_id) != Some(0) {
        return Err(err("container id 0 must be mapped first"));
    }
    match model {
        RecordedIdModel::Single => {
            if extents.len() != 1 || extents.first().map(|e| e.size) != Some(1) {
                return Err(err("single id mapping must be exactly one id"));
            }
        }
        RecordedIdModel::Subordinate => {
            if extents.len() < 2 || extents.first().map(|e| e.size) != Some(1) {
                return Err(err(
                    "subordinate id mapping must be one id plus at least one range",
                ));
            }
        }
    }
    Ok(())
}

impl RecordedIdMapping {
    /// 検証して作る。
    ///
    /// 拒否: uid / gid の行が空・[`MAX_RECORDED_ID_EXTENTS`] 超過 / 個数 0 / u32 を超える範囲 / ホスト ID 0 /
    /// 先頭がコンテナ内 0 でない / 範囲の重複 / モデルと形の不一致（`Single` は 0→1 件だけ、
    /// `Subordinate` は先頭が 0→1 件で合計 2 行以上）。
    pub fn new(
        model: RecordedIdModel,
        uid: Vec<RecordedIdExtent>,
        gid: Vec<RecordedIdExtent>,
    ) -> Result<Self, LaunchIsolationError> {
        validate_id_extents(model, &uid)?;
        validate_id_extents(model, &gid)?;
        Ok(Self { model, uid, gid })
    }

    /// モデル。
    pub fn model(&self) -> RecordedIdModel {
        self.model
    }

    /// uid の写像行。
    pub fn uid(&self) -> &[RecordedIdExtent] {
        &self.uid
    }

    /// gid の写像行。
    pub fn gid(&self) -> &[RecordedIdExtent] {
        &self.gid
    }
}

impl fmt::Debug for RecordedIdMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordedIdMapping")
            .field("model", &self.model)
            .field("uid_extents", &self.uid.len())
            .field("gid_extents", &self.gid.len())
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
    audit_coverage: RecordedAuditCoverage,
    audit_coverage_record: AuditCoverageRecordOutcome,
    id_mapping: Option<RecordedIdMapping>,
    capabilities: Option<ContainerCapabilities>,
    root_readonly: Option<bool>,
}

impl LaunchIsolationRecord {
    /// 検証済みの部品から作る。
    pub fn from_parts(root: RootIdentity, landlock: RecordedLandlock) -> Self {
        Self {
            root,
            landlock,
            audit_coverage: RecordedAuditCoverage::NotRecorded,
            audit_coverage_record: AuditCoverageRecordOutcome::NotFailed,
            id_mapping: None,
            capabilities: None,
            root_readonly: None,
        }
    }

    /// launch が実際に適用した `root.readonly` の実効値(config と `--read-only` の OR。mount の RDONLY・Landlock の
    /// root 規則と同じ値。CLI-1・SUP-12・CORE-5・#2828)を添える。添えなければ `None`(旧記録。推測しない)。
    #[must_use]
    pub fn with_root_readonly(mut self, root_readonly: bool) -> Self {
        self.root_readonly = Some(root_readonly);
        self
    }

    /// 添えられた `root.readonly` の実効値(無ければ `None`)。
    pub fn root_readonly(&self) -> Option<bool> {
        self.root_readonly
    }

    /// launch が適用した capability の許可集合を添える（SEC-1・CRI-2・#2666）。exec の再適用がこの集合を使い、
    /// launch より広い集合では動かさない。添えなければ `None`（導入前の launch は必ず OCI 既定集合で起動したため、
    /// exec は `None` を OCI 既定集合として扱う）。
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: ContainerCapabilities) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    /// 添えられた capability の許可集合（無ければ `None`）。
    pub fn capabilities(&self) -> Option<ContainerCapabilities> {
        self.capabilities
    }

    /// launch が使った ID 写像の記録を添える（CORE-6・#2388）。添えなければ `None`（旧記録と同じ。「single」とは推測しない）。
    #[must_use]
    pub fn with_id_mapping(mut self, mapping: RecordedIdMapping) -> Self {
        self.id_mapping = Some(mapping);
        self
    }

    /// 添えられた ID 写像の記録（無ければ `None`）。
    pub fn id_mapping(&self) -> Option<&RecordedIdMapping> {
        self.id_mapping.as_ref()
    }

    /// 監査の網羅の評価結果を添える（SEC-4・#2027）。添えなければ [`RecordedAuditCoverage::NotRecorded`]。
    #[must_use]
    pub fn with_audit_coverage(
        mut self,
        policy: AuditCoveragePolicy,
        coverage: AuditCoverage,
    ) -> Self {
        self.audit_coverage = RecordedAuditCoverage::Evaluated { policy, coverage };
        // 評価を置き換えたら記録失敗の事実は引き継がない（縮退なしの評価に Failed が残る矛盾を作らない。REPAIR-2）。
        self.audit_coverage_record = AuditCoverageRecordOutcome::NotFailed;
        self
    }

    /// 監査の網羅の記録。
    pub fn audit_coverage(&self) -> RecordedAuditCoverage {
        self.audit_coverage
    }

    /// 縮退の監査記録を書けなかった事実を添える（SEC-4・REPAIR-4・#2468）。
    ///
    /// 縮退を評価済み（`Evaluated` かつ縮退あり）の記録にだけ付けられる。縮退が無い記録に「記録の失敗」を
    /// 持たせる矛盾した値は作れない（REPAIR-2）。
    pub fn with_audit_coverage_record_failed(mut self) -> Result<Self, LaunchIsolationError> {
        match self.audit_coverage {
            RecordedAuditCoverage::Evaluated { coverage, .. } if coverage.is_degraded() => {
                self.audit_coverage_record = AuditCoverageRecordOutcome::Failed;
                Ok(self)
            }
            _ => Err(LaunchIsolationError(
                "audit coverage record failure requires a degraded evaluated coverage",
            )),
        }
    }

    /// 縮退の監査記録の書き込み結果。
    pub fn audit_coverage_record(&self) -> AuditCoverageRecordOutcome {
        self.audit_coverage_record
    }

    /// launch 時の pivot 後の `/` の識別子。
    pub fn root(&self) -> RootIdentity {
        self.root
    }

    /// 適用した Landlock の記録。
    pub fn landlock(&self) -> &RecordedLandlock {
        &self.landlock
    }

    /// launch の子が返した Mount 由来のルールの識別子を添える（SEC-1・SEC-4・#3201。検証は
    /// [`RecordedLandlock::with_mount_identities`]）。起動後（PID 1 が識別子を返した後）に launcher が呼ぶ。
    pub fn with_mount_identities(
        mut self,
        entries: Vec<(usize, RecordedMountIdentity)>,
    ) -> Result<Self, LaunchIsolationError> {
        self.landlock = self.landlock.with_mount_identities(entries)?;
        Ok(self)
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
pub(crate) use linux::id_extents_of;

#[cfg(target_os = "linux")]
mod linux {
    use super::RecordedIdExtent;
    use super::RecordedLandlockAudit;
    use super::{
        LaunchIsolationError, LaunchIsolationRecord, RecordedLandlock, RecordedRule,
        RecordedTarget, RootIdentity,
    };
    use crate::landlock::{
        AccessFs, LandlockAuditMode, LandlockRuleset, PathRule, RuleOrigin, RulePath,
    };
    use crate::rootless::IdMapSet;

    /// 検証済みの写像集合を記録用の行へ写す（CORE-6・#2388。launcher が記録を作るときに使う）。
    pub(crate) fn id_extents_of(set: &IdMapSet) -> Vec<RecordedIdExtent> {
        set.entries()
            .iter()
            .map(|e| RecordedIdExtent {
                container_id: e.container_id,
                host_id: e.host_id,
                size: e.count,
            })
            .collect()
    }

    impl From<LandlockAuditMode> for RecordedLandlockAudit {
        /// 実行時のモードを OS 非依存の記録の語彙へ写す（launcher と supervisor 手順 4 の前倒し判定が共有する。#2027）。
        fn from(mode: LandlockAuditMode) -> Self {
            match mode {
                LandlockAuditMode::KernelAuditRequested => Self::KernelAuditRequested,
                LandlockAuditMode::Unavailable { detected, .. } => Self::Unavailable {
                    detected_abi: detected,
                },
            }
        }
    }

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
            let audit = RecordedLandlockAudit::from(ruleset.audit_mode());
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
                        RecordedTarget::Tmpfs { destination } => (
                            RulePath::Beneath(destination.clone()),
                            RuleOrigin::UserTmpfs,
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
            (RulePath::Beneath(d), RuleOrigin::UserTmpfs) => RecordedTarget::Tmpfs {
                destination: d.clone(),
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

    /// inspect の `auditCoverage.record` の語彙は固定（SEC-4・#2601）。
    #[test]
    fn sec4_2601_audit_coverage_record_vocabulary() {
        assert_eq!(AuditCoverageRecordOutcome::Failed.as_str(), Some("failed"));
        assert_eq!(AuditCoverageRecordOutcome::NotFailed.as_str(), None);
    }

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

    /// SEC-1・SEC-4・#3201: 識別子は Mount 由来のルールを過不足なく覆うときだけ添えられ、添える前は `Absent`、
    /// 添えた後は `Complete` になる。位置の不足・過剰・非 Mount 由来への添付は拒否する。
    #[test]
    fn sec1_3201_with_mount_identities_requires_exact_cover() {
        let id = |n: u64| RecordedMountIdentity::new(n, 2, 3, false).unwrap();
        let base = || {
            RecordedLandlock::new(
                0xFFFF,
                vec![
                    root_rule(0x7),
                    mount_rule("/a", 0, 0x7),
                    mount_rule("/b", 1, 0x7),
                ],
            )
            .unwrap()
        };
        assert_eq!(base().mount_rule_positions(), vec![1, 2]);
        assert_eq!(base().mount_identities(), RecordedMountIdentities::Absent);
        assert!(base().with_mount_identities(vec![(1, id(10))]).is_err());
        assert!(
            base()
                .with_mount_identities(vec![(0, id(9)), (1, id(10)), (2, id(11))])
                .is_err()
        );
        assert!(
            base()
                .with_mount_identities(vec![(2, id(11)), (1, id(10))])
                .is_err()
        );
        let done = base()
            .with_mount_identities(vec![(1, id(10)), (2, id(11))])
            .unwrap();
        assert_eq!(done.mount_identities(), RecordedMountIdentities::Complete);
        // Mount 由来のルールが無い記録は、空の識別子で `Complete`(照合する対象が無い)。
        let root_only = RecordedLandlock::new(0xFFFF, vec![root_rule(0x7)]).unwrap();
        assert_eq!(
            root_only.mount_identities(),
            RecordedMountIdentities::Complete
        );
        assert!(root_only.with_mount_identities(Vec::new()).is_ok());
    }

    /// SEC-4・REPAIR-4・#2468: 記録失敗は縮退を評価済みの記録にだけ付けられる。
    #[test]
    fn sec4_2468_record_failed_requires_degraded_coverage() {
        use crate::audit_log::{DegradeReason, KernelAuditLayerStatus};
        let base = || {
            LaunchIsolationRecord::from_parts(
                RootIdentity::new(1, 2),
                RecordedLandlock::new(0xFFFF, vec![root_rule(0x7)]).unwrap(),
            )
        };
        assert_eq!(
            base().audit_coverage_record(),
            AuditCoverageRecordOutcome::NotFailed
        );
        assert!(base().with_audit_coverage_record_failed().is_err());
        let clear = AuditCoverage::new(
            KernelAuditLayerStatus::Requested,
            KernelAuditLayerStatus::Requested,
        );
        let r = base().with_audit_coverage(AuditCoveragePolicy::BestEffort, clear);
        assert!(r.with_audit_coverage_record_failed().is_err());
        let degraded = AuditCoverage::new(
            KernelAuditLayerStatus::Degraded(DegradeReason::SeccompKillNotLogged),
            KernelAuditLayerStatus::Requested,
        );
        let r = base()
            .with_audit_coverage(AuditCoveragePolicy::BestEffort, degraded)
            .with_audit_coverage_record_failed()
            .unwrap();
        assert_eq!(
            r.audit_coverage_record(),
            AuditCoverageRecordOutcome::Failed
        );
        // Failed の後に縮退なしの評価で上書きすると NotFailed に戻る（矛盾した値を残さない）。
        let overwritten = r
            .clone()
            .with_audit_coverage(AuditCoveragePolicy::BestEffort, clear);
        assert_eq!(
            overwritten.audit_coverage_record(),
            AuditCoverageRecordOutcome::NotFailed
        );
        assert_eq!(
            r.audit_coverage_record().log_line(),
            Some(
                r#"{"component":"core.audit","operation":"audit_coverage_record","outcome":"failed"}"#
            )
        );
        assert_eq!(AuditCoverageRecordOutcome::NotFailed.log_line(), None);
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

    fn ext(c: u32, h: u32, n: u32) -> RecordedIdExtent {
        RecordedIdExtent {
            container_id: c,
            host_id: h,
            size: n,
        }
    }

    /// CORE-6・SEC-5・#2388: ID 写像の記録の検証を具体値で照合する。
    #[test]
    fn core6_2388_id_mapping_validation() {
        use RecordedIdModel::{Single, Subordinate};
        let single = vec![ext(0, 1000, 1)];
        let sub = vec![ext(0, 1000, 1), ext(1, 100_000, 65_536)];
        let m = RecordedIdMapping::new(Single, single.clone(), single.clone()).unwrap();
        assert_eq!(m.model().as_str(), "single");
        assert_eq!(m.uid(), single.as_slice());
        let m = RecordedIdMapping::new(Subordinate, sub.clone(), sub.clone()).unwrap();
        assert_eq!(m.model().as_str(), "subordinate");
        assert_eq!(m.gid().len(), 2);
        assert_eq!(RecordedIdModel::parse("subordinate"), Some(Subordinate));
        assert_eq!(RecordedIdModel::parse("range"), None);

        let msg = |model, u: Vec<RecordedIdExtent>| {
            RecordedIdMapping::new(model, u, single.clone())
                .unwrap_err()
                .message()
        };
        assert_eq!(
            msg(Single, vec![]),
            "id mapping extent count is out of range"
        );
        let many = (0..=MAX_RECORDED_ID_EXTENTS as u32)
            .map(|i| ext(i, 1000 + i, 1))
            .collect();
        assert_eq!(
            msg(Subordinate, many),
            "id mapping extent count is out of range"
        );
        assert_eq!(
            msg(Single, vec![ext(0, 1000, 0)]),
            "id mapping extent size is zero"
        );
        assert_eq!(
            msg(Single, vec![ext(0, u32::MAX, 2)]),
            "id mapping range overflows u32"
        );
        assert_eq!(
            msg(Single, vec![ext(0, 0, 1)]),
            "id mapping must not map to host id 0"
        );
        assert_eq!(
            msg(Subordinate, vec![ext(0, 1000, 1), ext(1, 0, 5)]),
            "id mapping must not map to host id 0"
        );
        assert_eq!(
            msg(Subordinate, vec![ext(0, 1000, 1), ext(1, 1000, 5)]),
            "id mapping ranges overlap"
        );
        assert_eq!(
            msg(Subordinate, vec![ext(0, 1000, 1), ext(0, 5000, 5)]),
            "id mapping ranges overlap"
        );
        assert_eq!(
            msg(Single, vec![ext(1, 1000, 1)]),
            "container id 0 must be mapped first"
        );
        assert_eq!(
            msg(Single, sub.clone()),
            "single id mapping must be exactly one id"
        );
        assert_eq!(
            msg(Single, vec![ext(0, 1000, 2)]),
            "single id mapping must be exactly one id"
        );
        assert_eq!(
            msg(Subordinate, single.clone()),
            "subordinate id mapping must be one id plus at least one range"
        );
        // gid 側の不正も拒否する。
        assert!(RecordedIdMapping::new(Single, single.clone(), vec![ext(0, 0, 1)]).is_err());
    }

    /// `Debug` は値を出さず件数だけを出す。
    #[test]
    fn core6_2388_id_mapping_debug_hides_ids() {
        let sub = vec![ext(0, 1234, 1), ext(1, 777_000, 65_536)];
        let m = RecordedIdMapping::new(RecordedIdModel::Subordinate, sub.clone(), sub).unwrap();
        let s = format!("{m:?}");
        assert!(s.contains("uid_extents: 2"), "{s}");
        assert!(!s.contains("1234") && !s.contains("777000"), "{s}");
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
            assert_eq!(MAX_RECORDED_ID_EXTENTS, crate::rootless::MAX_EXTENTS);
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
