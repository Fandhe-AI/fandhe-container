//! 本番の `ProcessLauncher`(`ProductionLauncher`。TASK-29 追補・#1816。CORE-1・CORE-2・CORE-5・SEC-1・
//! SEC-4・SEC-5・OCI-6・REPAIR-2・REPAIR-3・REPAIR-5)。
//!
//! # 役割と呼び出し元
//!
//! `start` が検証して組み立てた [`LaunchSpec`] から、中間プロセス経由でコンテナの PID 1 を起動する
//! (`exec::spawn_container_via_intermediate`)。この型は **薄い**: 起動の順序の固定(拒否の判定 → Landlock の
//! ruleset → ステージ列 → 起動)と、`ExecError` から `TraitError` への固定文言への写像だけを持ち、分離・
//! 回収・監査の実体は `exec` 側にある。呼び出し元は supervisor の起動入口と restart ループ(`launch` の
//! たびに新しいステージ列を作る)。構築(`ProductionLauncherBuilder`)は supervisor が、権限モデル・監査 sink・
//! cgroup 参加の源を渡して 1 回行う。
//!
//! # 起動の順序(固定。いずれの拒否も fork より前で、副作用は無い)
//!
//! 1. 権限モデルの検査(`RootlessSingleId` 以外は `Unimplemented`)
//! 2. cgroup 要件の検査(`launch_after_cgroup_check`。要件ありで参加の源が無ければ `FailedPrecondition`。CORE-3)
//! 3. 呼び出しプロセスが単一スレッドであることの確認(`FailedPrecondition`。CORE-1)
//! 4. Landlock の ruleset(**必須**。ABI 6 未満は `FailedPrecondition` で起動を拒否し、縮退しない。CORE-5・#1314)
//! 5. ステージ列(`with_landlock` は型上 `Option` を取らず、Landlock 無しの列を作れない。参加の源があれば
//!    起動のたびに `CgroupJoin` を作って登録する)
//! 6. 既定 tmpfs(`/dev/shm`)の構築と、bind mount の宛先との重なりの検査(`InvalidArgument`。拒否は
//!    監査 sink へ記録する。SEC-4・#1915)
//! 7. 分離計画・状態 pipe・中間プロセスの起動(`exec` 側)
//!
//! exec は `StagePipeline::run_then` が作る `LaunchReady`(制限適用の証跡。Landlock を含む)が無ければ通らない。
//! この型は証跡を作る手段を増やさず、既存の `run_child` の `require_restriction_evidence` に任せる(SEC-1・CORE-5)。
//!
//! # スレッドモデルと時間上限(REPAIR-5)
//!
//! [`ProcessLauncher::launch_mode`] は `SelfBounded`。fork は呼び出しプロセスが単一スレッドであることを要求する
//! ため、start は別スレッドを作らずに呼び出しスレッドで直接 `launch` を呼ぶ。上限は `timeout` から導く単一の
//! 期限(中間プロセスの報告・pivot 前段の状態)と、失敗後の後始末の固定上限で、戻りは `timeout` ＋後始末の
//! 上限以内。複数スレッドの呼び出しは副作用なしで `FailedPrecondition` にする。
//!
//! # 起動台帳と `confirm_no_process`(CORE-2・REPAIR-5。#1817)
//!
//! launch の失敗は、起動した全プロセス(中間プロセス I と PID 1)の消滅を確かめられたかを、コンテナ ID ごとの
//! 台帳(上限 `LEDGER_MAX_ENTRIES` 件)に残す。`Clean` は消滅を確かめ済み、`Pending` は回収できなかった子の
//! ハンドルと、報告前の PID 1 の再探索が要る起動識別子を保持する状態、`Handed` は launch 成功でハンドルの所有者が
//! 呼び出し側に移った状態である(そのハンドルの `terminate` が成功すると、同じ launch の項目だけが `Clean` に進む)。`confirm_no_process` は `Clean` のときだけ `Ok` を返し、`Pending` は期限内に
//! 再回収(I → PID 1 の順。PID 1 は I の回収後でないと C の子にならない)と再探索を試みる。台帳に無い ID は
//! `confirm_no_process` では確かめられない(`FailedPrecondition`)が、記録された cgroup の配置を受け取る
//! `confirm_no_process_recorded` が別プロセスの残存を確かめる(下の「別プロセスの残存」)。回収前の `Handed`・
//! 確かめられない `Pending` は `Ok` にしない。`Pending` の ID への再 launch は(再回収を試みても確かめられなければ)
//! fork 前に拒否する。再回収の待ちの間は `Pending` を台帳から取り出し(記録は `Settling`)、台帳の Mutex を解放する
//! ため、他コンテナの launch は待たされない(REPAIR-5・CORE-1)。同じ ID への並行な確認・launch は拒否する。期限内に確かめられなかった事実は、launch の `TraitError` の固定の接尾辞
//! (`UNCONFIRMED_SUFFIX`)と [`ProcessLauncher::last_launch_may_have_left_process`] で伝える。
//!
//! # 別プロセスの残存(CORE-2・SEC-1。#2011)
//!
//! クラッシュした supervisor が起動した残存は、このプロセスの台帳に無い。`recover_interrupted_start` が渡す
//! 状態記録の cgroup の配置(`StateRecord::cgroup`)から、コンテナ cgroup `fc-<id>@<instance>` を
//! `cgroups::ensure_no_process_in_recorded` で特定する(ID だけからパスを組み立てない。照合の規則は
//! `RecordedCgroupScope::open` と同じ)。cgroup が無ければ(空でない cgroup は消えないので)居ない、空なら居ない、
//! 居れば `cgroup.kill` で止めて期限内に `populated 0` を確かめて `Ok`。配置が無い・スコープを検証できない・
//! 読めない・`cgroup.kill` が無い・期限切れは `Ok` にしない(fail-closed)。台帳にある ID は台帳で判定する。
//!
//! # 未実装・残余(REPAIR-3)
//!
//! - **権限モデル**: `RootlessSingleId` のみ。`RootfulHostRoot`(SEC-5・CORE-7・CORE-9。start が user namespace
//!   を必須とするため、start を通る構成では到達しない。整合は spec 側の判断事項)と `RootlessSubordinateIds`
//!   (CORE-6・TASK-40.2。`LaunchSpec` が uid/gid 写像を持たない)は `Unimplemented` で拒否する
//! - **`confirm_no_process`**: ID だけでは、この launcher 自身が起動した範囲だけを確証する(上の「起動台帳」)。
//!   別プロセスの残存は `confirm_no_process_recorded` が記録済みの cgroup で確かめる(上の「別プロセスの残存」。
//!   #2011)。残余は、記録が無い場合(`FailedPrecondition`)と、コンテナ内のプロセスが cgroup の外へ移った場合
//!   (検出できない。delete と同じ限界)。成功の内訳の観測記録は未実装(REPAIR-4)
//! - 起動台帳はプロセス内のメモリのみ(再起動をまたがない。別プロセスの残存は記録済みの cgroup で確かめる)
//! - **supervisor の結線**: `launch` は単一スレッドの呼び出しスレッドで直接呼ぶ必要がある。supervisor の
//!   `run_start` 手順 8 は、準備の作業スレッドを `join` してから入口スレッドが直接呼ぶ形に再構成済み(#1819)。
//!   restart の再 launch は `fandhe-relaunch` スレッド等が存在する状態で呼ばれ、この launcher が拒否する
//!   (`RelaunchFailed`・fail-closed)。呼び出しスレッドで直接行う再構成は #2043
//! - bind mount（`LaunchSpec::bind_mounts`。#1915）は載せる。fork 前に既定 tmpfs との重なりを検査して
//!   `PrePivotSetup.binds` へ渡し、restart の再 launch でも同じ集合を使う。`ro` の bind は Landlock の
//!   `WriteRestrictionShadowed` で fork 前に拒否される（#1917 で解消するまでの想定挙動）
//! - bind 以外の `mounts[]` の種類と `/dev` 以外の tmpfs の注入は `start` が拒否済みで、ここでは載せない

#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

#[cfg(target_os = "linux")]
use super::bind_mounts::{BindMountSet, audit_bind_mount_error};
#[cfg(target_os = "linux")]
use super::cgroup_requirement::{CgroupJoinMeans, launch_after_cgroup_check};
#[cfg(target_os = "linux")]
use super::config::NamespaceKind;
use super::launch::{LaunchMode, LaunchSpec, LaunchedProcess, ProcessLauncher};
use crate::audit_log::AuditSink;
#[cfg(target_os = "linux")]
use crate::audit_log::AuditedRejection;
#[cfg(target_os = "linux")]
use crate::cgroups::{CgroupError, CgroupJoin, RecordedCgroupOutcome};
#[cfg(target_os = "linux")]
use crate::exec::{
    ChildStdio, ChildSubreaper, ConfigPaths, ContainerChild, Entrypoint, ExecError, Hostname,
    IntermediateSpec, IsolationConfig, IsolationPrivilege, IsolationStage, LaunchAudit, LaunchTag,
    Namespace, NamespaceSet, PrePivotSetup, PreparedLaunchFailure, Rescan, StageKind,
    StagePipeline, plan, rescan_unreported_init, spawn_container_via_intermediate,
};
#[cfg(target_os = "linux")]
use crate::landlock::LandlockRuleset;
#[cfg(target_os = "linux")]
use crate::tmpfs::TmpfsMountSet;
use crate::traits::{CgroupPlacement, ContainerId, ErrorCode, TraitError};

/// 起動台帳の上限(異なるコンテナ ID の件数。無制限の確保を避ける。`Pending` は捨てないため、`Pending` だけで
/// 満杯なら新しい ID の launch を拒否する)。
#[cfg(target_os = "linux")]
pub(super) const LEDGER_MAX_ENTRIES: usize = 64;

/// launch が失敗し、起動したプロセスの消滅を期限内に確かめられなかったときに、失敗の文言へ足す固定の接尾辞
/// (機械可読な判定は [`ProcessLauncher::last_launch_may_have_left_process`])。
#[cfg(target_os = "linux")]
pub(super) const UNCONFIRMED_SUFFIX: &str =
    "; removal of the launched processes could not be confirmed";

/// 成功した launch の直後の検査で拒否した子(pidfd 無し)を回収する待ちの固定上限(REPAIR-5)。
#[cfg(target_os = "linux")]
const POST_SPAWN_REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// `Pending` の ID への再 launch の前に、再回収を試みる待ちの固定上限(REPAIR-5)。
#[cfg(target_os = "linux")]
const RELAUNCH_SETTLE_TIMEOUT: Duration = Duration::from_secs(5);

/// `confirm_no_process` の待ちに許す最大値(`Instant` の加算オーバーフローを避ける丸め)。
#[cfg(target_os = "linux")]
const CONFIRM_TIMEOUT_MAX: Duration = Duration::from_secs(24 * 60 * 60);

/// 本番の [`ProcessLauncher`]。構築は [`ProductionLauncher::builder`]。
///
/// Linux 以外では構築できない(`build` が `Unimplemented`)。型だけを 3 OS に置くのは、上位の crate が
/// `cfg` を持たずに型名を参照できるようにするため(CLI-1)。
pub struct ProductionLauncher {
    #[cfg(target_os = "linux")]
    inner: Inner,
    /// Linux 以外では構築できないことを型で表す(値を持たない型)。
    #[cfg(not(target_os = "linux"))]
    never: std::convert::Infallible,
}

impl std::fmt::Debug for ProductionLauncher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProductionLauncher").finish_non_exhaustive()
    }
}

/// [`ProductionLauncher`] の構築器。
///
/// 必須は `privilege` と `audit_sink`(Linux)。`cgroup_join_source` は任意で、無ければ cgroup 要件のある
/// config の起動は fork 前に拒否される。
#[derive(Default)]
pub struct ProductionLauncherBuilder {
    #[cfg(target_os = "linux")]
    privilege: Option<IsolationPrivilege>,
    #[cfg(target_os = "linux")]
    audit_sink: Option<Arc<dyn AuditSink>>,
    #[cfg(target_os = "linux")]
    cgroup_join_source: Option<JoinSource>,
}

impl std::fmt::Debug for ProductionLauncherBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProductionLauncherBuilder")
            .finish_non_exhaustive()
    }
}

/// 起動のたびに `CgroupJoin` を作る源(`CgroupJoin` は `Clone` でなく、ステージ列へ move されるため、
/// restart の再 launch で使い回せるよう「再構築できる源」で持つ)。
#[cfg(target_os = "linux")]
type JoinSource = Box<dyn Fn() -> Result<CgroupJoin, CgroupError> + Send + Sync>;

impl ProductionLauncher {
    /// 構築器を作る。
    pub fn builder() -> ProductionLauncherBuilder {
        ProductionLauncherBuilder::default()
    }
}

#[cfg(target_os = "linux")]
impl ProductionLauncherBuilder {
    /// 分離の権限モデル。`RootlessSingleId` 以外は launch が `Unimplemented` で拒否する(モジュール doc)。
    #[must_use]
    pub fn privilege(mut self, privilege: IsolationPrivilege) -> Self {
        self.privilege = Some(privilege);
        self
    }

    /// pivot 前段の違反を記録する監査 sink(SEC-4)。core は自分では作らず、呼び出し側が渡す。
    #[must_use]
    pub fn audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// 起動のたびに cgroup 参加フックを作る源(`ContainerCgroup::join_hook` を呼ぶクロージャ等。CORE-3)。
    #[must_use]
    pub fn cgroup_join_source(
        mut self,
        source: impl Fn() -> Result<CgroupJoin, CgroupError> + Send + Sync + 'static,
    ) -> Self {
        self.cgroup_join_source = Some(Box::new(source));
        self
    }
}

impl ProductionLauncherBuilder {
    /// launcher を作る。呼び出しプロセスを child subreaper にし(失敗なら `Err`)、その証跡を保持する
    /// (再親付けされた PID 1 を pid 指定で回収するため。CORE-1・#1813)。
    ///
    /// Linux 以外は常に `Unimplemented`。Linux では必須値の欠落が `InvalidArgument`。
    pub fn build(self) -> Result<ProductionLauncher, TraitError> {
        #[cfg(target_os = "linux")]
        {
            let missing = |what: &'static str| TraitError::new(ErrorCode::InvalidArgument, what);
            let privilege = self
                .privilege
                .ok_or_else(|| missing("the launcher requires an isolation privilege model"))?;
            let audit_sink = self
                .audit_sink
                .ok_or_else(|| missing("the launcher requires an audit sink"))?;
            let subreaper = ChildSubreaper::enable().map_err(|e| {
                TraitError::new(
                    e.code,
                    "failed to become a child subreaper for the launcher",
                )
            })?;
            Ok(ProductionLauncher {
                inner: Inner::new(
                    Box::new(RealOps { subreaper }),
                    privilege,
                    audit_sink,
                    self.cgroup_join_source,
                ),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(TraitError::new(
                ErrorCode::Unimplemented,
                "production launcher requires Linux",
            ))
        }
    }
}

impl ProcessLauncher for ProductionLauncher {
    /// fork は単一スレッドの呼び出しを要求するため、start は呼び出しスレッドで直接 `launch` を呼ぶ(REPAIR-5)。
    fn launch_mode(&self) -> LaunchMode {
        LaunchMode::SelfBounded
    }

    /// start が設定の検証で拒否したときの記録先として、この launcher の監査 sink を貸す(SEC-4・#1915)。
    fn rejection_audit_sink(&self) -> Option<&dyn AuditSink> {
        #[cfg(target_os = "linux")]
        {
            Some(self.inner.audit_sink.as_ref())
        }
        #[cfg(not(target_os = "linux"))]
        {
            match self.never {}
        }
    }

    /// 直近の `launch` の失敗で、回収できなかった子が残っている可能性があるか(CORE-2)。
    fn last_launch_may_have_left_process(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.inner.left_process.load(Ordering::SeqCst)
        }
        #[cfg(not(target_os = "linux"))]
        {
            match self.never {}
        }
    }

    fn launch(
        &self,
        spec: &LaunchSpec,
        timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.launch(spec, timeout)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (spec, timeout);
            match self.never {}
        }
    }

    /// この launcher が起動した範囲で、`id` の起動が生存プロセスを残していないことを確認する(CORE-2・REPAIR-5。
    /// #1817)。台帳に無い ID・ハンドルを渡し済みの ID は確証できないため `FailedPrecondition`(fail-closed)。
    fn confirm_no_process(&self, id: &ContainerId, timeout: Duration) -> Result<(), TraitError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.confirm_no_process(id, timeout)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (id, timeout);
            match self.never {}
        }
    }

    /// 台帳に無い ID(別プロセスで起動した残存)を、状態記録の cgroup の配置から確かめる(CORE-2・SEC-1。#2011)。
    /// 台帳にある ID は [`Self::confirm_no_process`] と同じ判定で、`recorded` は使わない。
    fn confirm_no_process_recorded(
        &self,
        id: &ContainerId,
        recorded: Option<&CgroupPlacement>,
        timeout: Duration,
    ) -> Result<(), TraitError> {
        #[cfg(target_os = "linux")]
        {
            self.inner
                .confirm_no_process_recorded(id, recorded, timeout)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (id, recorded, timeout);
            match self.never {}
        }
    }
}

/// 起動の実体(fork・Landlock の検出・スレッド数の観測)を差し替えられる継ぎ目(単体テストが順序と拒否を
/// フォーク無し・ABI 非依存で照合できるようにする)。本番の実装は [`RealOps`]。
#[cfg(target_os = "linux")]
trait LaunchOps: Send + Sync {
    /// 呼び出しプロセスのスレッドが 1 つか(fork の前提)。
    fn is_single_threaded(&self) -> bool;
    /// `config` から Landlock の ruleset を作る(ABI 検出を含む。6 未満は拒否)。
    fn landlock_ruleset(
        &self,
        config: &super::config::OciConfig,
    ) -> Result<LandlockRuleset, ExecError>;
    /// 中間プロセス経由で PID 1 を起動する。
    fn spawn(&self, input: SpawnInput<'_>) -> Result<Spawned, Box<PreparedLaunchFailure>>;
    /// 報告前に失われた PID 1 を、起動識別子で `/proc` から探して回収する(`confirm_no_process` が、中間プロセスの
    /// 回収後に呼ぶ。fork はしない。待ちは見つけた子ごとに `reap_timeout` まで)。
    fn rescan(&self, tag: &LaunchTag, reap_timeout: Duration) -> Rescan;
    /// 記録された cgroup の配置のコンテナ cgroup に、プロセスが居ないことを確かめる(居れば止める。`deadline`
    /// まで待つ。別プロセスの残存の確認。#2011)。本番は `cgroups::ensure_no_process_in_recorded`。失敗は code のみ。
    fn ensure_no_process_in_recorded(
        &self,
        id: &ContainerId,
        placement: &CgroupPlacement,
        deadline: Instant,
    ) -> Result<RecordedCgroupOutcome, ErrorCode>;
}

/// [`LaunchOps::spawn`] へ渡す、fork 前に launcher が確定した値。
#[cfg(target_os = "linux")]
struct SpawnInput<'a> {
    isolation: IsolationConfig,
    spec: &'a LaunchSpec,
    entry: &'a Entrypoint,
    stages: StagePipeline,
    audit: LaunchAudit<'a>,
    timeout: Duration,
    /// 暗黙の既定 tmpfs(`/dev/shm`)。launcher が fork 前に構築し、bind との重なりも検査済み。
    tmpfs: &'a TmpfsMountSet,
    /// 適用する bind mount の集合(空なら `None`。#1915)。
    binds: Option<&'a BindMountSet>,
}

/// 起動した PID 1 と、stdout / stderr の読み取り側。
#[cfg(target_os = "linux")]
struct Spawned {
    child: ContainerChild,
    stdout: std::io::PipeReader,
    stderr: std::io::PipeReader,
}

/// コンテナ ID ごとの起動結果(起動台帳の 1 件。モジュール doc「起動台帳と `confirm_no_process`」)。
#[cfg(target_os = "linux")]
#[derive(Debug)]
enum LaunchRecord {
    /// 失敗した launch で、起動した全プロセスの消滅を確かめ済み。
    Clean,
    /// 消滅を確かめられていない。
    Pending(Pending),
    /// 別スレッドが `Pending` を台帳から取り出して再回収中(台帳の Mutex は待ちの間保持しない。REPAIR-5・CORE-1)。
    /// 結果は呼び出し元が書き戻す。確かめ済みとは扱わず、捨てない。
    Settling,
    /// launch 成功。ハンドルの所有者は呼び出し側(start / supervisor)で、launcher は確証できない。
    /// 値は launch ごとの世代。そのハンドルの `terminate` が成功したら、同じ世代の項目だけを `Clean` へ進める
    /// (回収の証跡を台帳へ引き継ぐ。再 launch 後の古いハンドルが新しい項目を書き換えない。CORE-2)。
    Handed(u64),
}

/// 消滅を確かめられていない起動の残り(握りつぶさない。CORE-2)。
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct Pending {
    /// 回収できなかった子。順序は中間プロセス → PID 1(PID 1 は中間プロセスの回収後でないと C の子にならず、
    /// `waitpid` が `ECHILD` になるため、この順で再回収する)。
    children: Vec<ContainerChild>,
    /// 報告前の PID 1 の再探索が要る起動識別子。
    rescans: Vec<LaunchTag>,
}

/// 台帳への登録(`admit`)が拒否された理由。
#[cfg(target_os = "linux")]
enum AdmitError {
    /// 同じ ID に確かめられていない起動が残っている(位置)。
    Pending(usize),
    /// 同じ ID の `Pending` を別スレッドが再回収中。
    Settling,
    /// `Pending` だけで台帳が満杯。
    Full,
}

/// 起動台帳。件数に上限があり、`Pending` は捨てない(捨てると残存を見失う)。
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct Ledger {
    /// 古い順。
    entries: Vec<(ContainerId, LaunchRecord)>,
}

#[cfg(target_os = "linux")]
impl Ledger {
    fn position(&self, id: &ContainerId) -> Option<usize> {
        self.entries.iter().position(|(k, _)| k == id)
    }

    fn has_pending(&self) -> bool {
        self.entries
            .iter()
            .any(|(_, r)| matches!(r, LaunchRecord::Pending(_) | LaunchRecord::Settling))
    }

    /// 古い順に、`Pending` でない最初の項目を捨てる(捨てられたか)。
    fn evict_oldest_settled(&mut self) -> bool {
        match self
            .entries
            .iter()
            .position(|(_, r)| !matches!(r, LaunchRecord::Pending(_) | LaunchRecord::Settling))
        {
            Some(i) => {
                self.entries.remove(i);
                true
            }
            None => false,
        }
    }

    /// launch の前に、台帳へ記録できる状態かを確かめる(`Pending` が残る ID・満杯は拒否)。
    fn admit(&mut self, id: &ContainerId) -> Result<(), AdmitError> {
        match self.position(id) {
            Some(i) => match self.entries.get(i) {
                Some((_, LaunchRecord::Pending(_))) => Err(AdmitError::Pending(i)),
                Some((_, LaunchRecord::Settling)) => Err(AdmitError::Settling),
                _ => Ok(()),
            },
            None if self.entries.len() < LEDGER_MAX_ENTRIES => Ok(()),
            None if self.evict_oldest_settled() => Ok(()),
            None => Err(AdmitError::Full),
        }
    }

    /// 結果を記録する。`Pending` は必ず残し、それ以外は満杯なら古い確定済みを捨てる(捨てられなければ記録しない)。
    fn set(&mut self, id: &ContainerId, record: LaunchRecord) {
        if let Some(i) = self.position(id) {
            if let Some(slot) = self.entries.get_mut(i) {
                slot.1 = record;
            }
            return;
        }
        let is_pending = matches!(record, LaunchRecord::Pending(_));
        if self.entries.len() >= LEDGER_MAX_ENTRIES && !self.evict_oldest_settled() && !is_pending {
            return;
        }
        self.entries.push((id.clone(), record));
    }
}

/// Linux の launcher 本体(拒否の判定・順序・写像・起動台帳)。
#[cfg(target_os = "linux")]
struct Inner {
    ops: Box<dyn LaunchOps>,
    privilege: IsolationPrivilege,
    audit_sink: Arc<dyn AuditSink>,
    cgroup_join_source: Option<JoinSource>,
    /// ハンドルの回収通知（`ContainerChildProcess::with_reap_notice`）と共有するため `Arc`。
    ledger: Arc<Mutex<Ledger>>,
    /// `Handed` の世代の採番。
    next_generation: std::sync::atomic::AtomicU64,
    /// 直近の `launch` が失敗し、子が残っている可能性があるか(回収に失敗した子がある、または報告前の PID 1 の
    /// 探索ができなかった。CORE-2)。`launch` の入口で偽に戻す。
    left_process: AtomicBool,
}

#[cfg(target_os = "linux")]
impl Inner {
    fn new(
        ops: Box<dyn LaunchOps>,
        privilege: IsolationPrivilege,
        audit_sink: Arc<dyn AuditSink>,
        cgroup_join_source: Option<JoinSource>,
    ) -> Self {
        Self {
            ops,
            privilege,
            audit_sink,
            cgroup_join_source,
            ledger: Arc::new(Mutex::new(Ledger::default())),
            next_generation: std::sync::atomic::AtomicU64::new(0),
            left_process: AtomicBool::new(false),
        }
    }

    fn ledger(&self) -> std::sync::MutexGuard<'_, Ledger> {
        self.ledger.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn launch(
        &self,
        spec: &LaunchSpec,
        timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        self.left_process.store(false, Ordering::SeqCst);
        self.check_privilege()?;
        let means = if self.cgroup_join_source.is_some() {
            CgroupJoinMeans::Provided
        } else {
            CgroupJoinMeans::Absent
        };
        launch_after_cgroup_check(spec.cgroup_requirement(), means, || {
            self.launch_checked(spec, timeout)
        })
    }

    /// 権限モデルの検査。未実装のモデルは fork より前に拒否する(権限を黙って広げない。SEC-5)。
    fn check_privilege(&self) -> Result<(), TraitError> {
        match self.privilege {
            IsolationPrivilege::RootlessSingleId => Ok(()),
            IsolationPrivilege::RootfulHostRoot => Err(TraitError::new(
                ErrorCode::Unimplemented,
                "the rootful privilege model is not supported by the launcher",
            )),
            IsolationPrivilege::RootlessSubordinateIds => Err(TraitError::new(
                ErrorCode::Unimplemented,
                "the subordinate id privilege model is not supported by the launcher",
            )),
        }
    }

    fn launch_checked(
        &self,
        spec: &LaunchSpec,
        timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        let id = spec.container_id();
        self.admit(id)?;
        if !self.ops.is_single_threaded() {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "launch requires a single-threaded process",
            ));
        }
        // Landlock は必須。ABI 不足・生成失敗は起動を拒否し、Landlock 無しで続けない(CORE-5・#1314)。
        let ruleset = self
            .ops
            .landlock_ruleset(spec.config())
            .map_err(|e| to_trait_error(&e))?;
        let mut stages = StagePipeline::new()
            .with_landlock(ruleset)
            .map_err(|e| to_trait_error(&e))?;
        if let Some(source) = &self.cgroup_join_source {
            let join = source().map_err(|_| {
                TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "failed to prepare the cgroup join for the container",
                )
            })?;
            stages = stages
                .with_hook(StageKind::CgroupJoin, join)
                .map_err(|e| to_trait_error(&e))?;
        }
        let entry = entrypoint_of(spec)?;
        let isolation = isolation_config_of(spec)?;
        // 暗黙の `/dev/shm` を fork 前に構築し、bind の宛先との重なりをここで検査する(両方の集合が揃う場所。
        // 子の `run_pre_pivot` の検査は多重防御として残す。CORE-5・#1654・#1915)。
        let mut default_tmpfs = TmpfsMountSet::new();
        default_tmpfs.ensure_default_dev_shm().map_err(|e| {
            TraitError::new(e.code(), "failed to prepare the default /dev/shm mount")
        })?;
        let binds = (!spec.bind_mounts().is_empty()).then(|| spec.bind_mounts());
        if let Some(binds) = binds
            && let Err(err) = binds.check_against_tmpfs(&default_tmpfs)
        {
            let (code, message) = (err.code(), err.message());
            let _ = audit_bind_mount_error(
                err,
                spec.config().mounts(),
                Some(id),
                self.audit_sink.as_ref(),
            );
            return Err(TraitError::new(code, message));
        }
        let audit = LaunchAudit {
            sink: self.audit_sink.as_ref(),
            container: Some(id),
        };
        let spawned = self
            .ops
            .spawn(SpawnInput {
                isolation,
                spec,
                entry: &entry,
                stages,
                audit,
                timeout,
                tmpfs: &default_tmpfs,
                binds,
            })
            .map_err(|failure| self.absorb_failure(id, *failure))?;
        let Spawned {
            child,
            stdout,
            stderr,
        } = spawned;
        // pid 0 は実在する子ではない(`kill(0)` は自プロセスグループへ届くため、触らずに拒否する)。
        if child.pid() == 0 {
            return Err(TraitError::new(
                ErrorCode::Internal,
                "the launched process id is invalid",
            ));
        }
        // pidfd 無しの子は使わない(pid 再利用で別のプロセスを止めない・exec の入口が pidfd を必須にしている。
        // fail-closed)。drop では kill されないため、ここで回収する。
        if child.pidfd().is_none() {
            return Err(self.reject_unusable_child(id, child));
        }
        let generation = self.next_generation.fetch_add(1, Ordering::SeqCst);
        // ハンドルの terminate が成功した（PID 1 の消滅を回収で確かめた）ら、同じ世代の Handed を Clean へ進める。
        // 遅れて成功した状態更新の後始末が confirm_no_process で回収済みを確かめられるようにする（CORE-2）。
        let ledger = Arc::downgrade(&self.ledger);
        let owner = id.clone();
        let process = super::launch::ContainerChildProcess::new(child)?
            .with_output(stdout, stderr)
            .with_exit_audit(Arc::clone(&self.audit_sink), id.clone())
            .with_reap_notice(Box::new(move || {
                let Some(ledger) = ledger.upgrade() else {
                    return;
                };
                let mut ledger = ledger.lock().unwrap_or_else(PoisonError::into_inner);
                let slot = ledger
                    .position(&owner)
                    .and_then(|i| ledger.entries.get_mut(i));
                if let Some((_, record)) = slot
                    && matches!(record, LaunchRecord::Handed(g) if *g == generation)
                {
                    *record = LaunchRecord::Clean;
                }
            }));
        self.ledger().set(id, LaunchRecord::Handed(generation));
        Ok(Box::new(process))
    }

    /// launch の前に、同じ ID の確かめられていない起動を再回収する。確かめられなければ fork 前に拒否する
    /// (二重起動の防止。CORE-2)。台帳が `Pending` だけで満杯のときも拒否する(子は作らない)。
    fn admit(&self, id: &ContainerId) -> Result<(), TraitError> {
        let mut ledger = self.ledger();
        match ledger.admit(id) {
            Ok(()) => Ok(()),
            Err(AdmitError::Full) => Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "too many launches are awaiting confirmation that no process remains",
            )),
            Err(AdmitError::Settling) => Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "a previous launch of this container is being confirmed{UNCONFIRMED_SUFFIX}"
                ),
            )),
            Err(AdmitError::Pending(i)) => {
                // 台帳から取り出し、Mutex を解放してから再回収する(他コンテナの launch を待たせない)。
                let Some(mut pending) = Self::take_pending_at(&mut ledger, i) else {
                    return Err(TraitError::new(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "a previous launch of this container is unconfirmed{UNCONFIRMED_SUFFIX}"
                        ),
                    ));
                };
                drop(ledger);
                let deadline = Instant::now() + RELAUNCH_SETTLE_TIMEOUT;
                let settled = self.settle(&mut pending, deadline).is_ok();
                if settled {
                    self.ledger().set(id, LaunchRecord::Clean);
                    Ok(())
                } else {
                    self.ledger().set(id, LaunchRecord::Pending(pending));
                    self.left_process.store(true, Ordering::SeqCst);
                    Err(TraitError::new(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "a previous launch of this container is unconfirmed{UNCONFIRMED_SUFFIX}"
                        ),
                    ))
                }
            }
        }
    }

    /// 位置 `i` の `Pending` を取り出し、記録を `Settling` に置き換える(`Pending` でなければ `None`)。
    fn take_pending_at(ledger: &mut Ledger, i: usize) -> Option<Pending> {
        let slot = ledger.entries.get_mut(i)?;
        if !matches!(slot.1, LaunchRecord::Pending(_)) {
            return None;
        }
        match std::mem::replace(&mut slot.1, LaunchRecord::Settling) {
            LaunchRecord::Pending(p) => Some(p),
            other => {
                slot.1 = other;
                None
            }
        }
    }

    /// pidfd の無い子を回収して拒否する(回収できなければ台帳に `Pending` で残す)。
    fn reject_unusable_child(&self, id: &ContainerId, child: ContainerChild) -> TraitError {
        match child.kill_and_reap(POST_SPAWN_REAP_TIMEOUT) {
            Ok(_) => {
                self.ledger().set(id, LaunchRecord::Clean);
                TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "the launched process has no pidfd and was terminated",
                )
            }
            Err(_) => {
                self.left_process.store(true, Ordering::SeqCst);
                self.ledger().set(
                    id,
                    LaunchRecord::Pending(Pending {
                        children: vec![child],
                        rescans: Vec::new(),
                    }),
                );
                TraitError::new(
                    ErrorCode::FailedPrecondition,
                    format!("the launched process has no pidfd{UNCONFIRMED_SUFFIX}"),
                )
            }
        }
    }

    /// 起動失敗を `TraitError` へ写し、回収を確かめられなかった子と再探索は台帳へ残す(握りつぶさない。CORE-2)。
    fn absorb_failure(&self, id: &ContainerId, failure: PreparedLaunchFailure) -> TraitError {
        let PreparedLaunchFailure {
            rejection,
            unreaped,
            reap_error,
            rescans,
        } = failure;
        let AuditedRejection { error, .. } = rejection;
        // 回収できなかった子、報告前の PID 1 の探索の未完了、または探索自体の失敗は、プロセスが残る可能性を
        // 表す(CORE-2)。
        let unconfirmed = !unreaped.is_empty() || reap_error.is_some() || !rescans.is_empty();
        if unconfirmed {
            self.left_process.store(true, Ordering::SeqCst);
            self.ledger().set(
                id,
                LaunchRecord::Pending(Pending {
                    children: unreaped,
                    rescans,
                }),
            );
        } else {
            self.ledger().set(id, LaunchRecord::Clean);
        }
        launch_error(&error, unconfirmed)
    }

    /// `pending` の残りを期限内に再回収・再探索する。すべて消えたら `Ok`。確かめられなければ `Err`(`Timeout`
    /// または `Internal`)で、残りは `pending` に残る(再試行できる)。fork はしない(別スレッドから呼ばれ得る)。
    fn settle(&self, pending: &mut Pending, deadline: Instant) -> Result<(), ErrorCode> {
        let remaining = || deadline.saturating_duration_since(Instant::now());
        let mut failed = false;
        let mut kept = Vec::new();
        // 中間プロセス → PID 1 の順(積まれた順)で回収する。
        for child in std::mem::take(&mut pending.children) {
            if child.kill_and_reap(remaining()).is_err() {
                failed = true;
                kept.push(child);
            }
        }
        pending.children = kept;
        // 中間プロセスを含む全員を回収できた後でなければ、報告前の PID 1 は C へ再親付けされず見つからない。
        if !failed {
            for tag in std::mem::take(&mut pending.rescans) {
                let found = self.ops.rescan(&tag, remaining());
                if found.scan_incomplete {
                    pending.rescans.push(tag);
                }
                if found.error.is_some() {
                    failed = true;
                }
                pending.children.extend(found.unreaped);
            }
        }
        if !failed {
            return Ok(());
        }
        Err(if Instant::now() >= deadline {
            ErrorCode::Timeout
        } else {
            ErrorCode::Internal
        })
    }

    /// 台帳にある ID は台帳で判定し、台帳に無い ID だけ記録済みの cgroup で確かめる(#2011・CORE-2・SEC-1)。
    ///
    /// 台帳に無い ID は、このプロセスでは launch を始めていない(回復は `StartReservation` と `BundleLock` で
    /// launch と排他される)ので、残存は別プロセス(クラッシュした supervisor)が起動したものである。`recorded` が
    /// 無ければ従来どおり `FailedPrecondition`。cgroup の問い合わせの失敗は code だけを保った固定文言にする
    /// (パス・errno を載せない)。待ちは `timeout`(上限つき)から作る単一の期限で打ち切る(REPAIR-5)。
    /// 成功の内訳(`RecordedCgroupOutcome`)の観測記録は未実装(REPAIR-4 の将来課題)。
    fn confirm_no_process_recorded(
        &self,
        id: &ContainerId,
        recorded: Option<&CgroupPlacement>,
        timeout: Duration,
    ) -> Result<(), TraitError> {
        let in_ledger = self.ledger().position(id).is_some();
        let Some(placement) = recorded.filter(|_| !in_ledger) else {
            return self.confirm_no_process(id, timeout);
        };
        let deadline = Instant::now() + timeout.min(CONFIRM_TIMEOUT_MAX);
        match self
            .ops
            .ensure_no_process_in_recorded(id, placement, deadline)
        {
            Ok(RecordedCgroupOutcome::AlreadyAbsent)
            | Ok(RecordedCgroupOutcome::WasEmpty)
            | Ok(RecordedCgroupOutcome::Killed) => Ok(()),
            Err(ErrorCode::Timeout) => Err(TraitError::new(
                ErrorCode::Timeout,
                "timed out confirming that no process remains in the recorded cgroup",
            )),
            Err(code) => Err(TraitError::new(
                code,
                "could not confirm that no process remains in the recorded cgroup",
            )),
        }
    }

    /// `id` の起動が、この launcher が起動した範囲で生存プロセスを残していないことを確認する(CORE-2・REPAIR-5)。
    fn confirm_no_process(&self, id: &ContainerId, timeout: Duration) -> Result<(), TraitError> {
        let deadline = Instant::now() + timeout.min(CONFIRM_TIMEOUT_MAX);
        // Pending を台帳から取り出して Mutex を解放してから待つ(待ちの間、他コンテナの launch を止めない)。
        let mut pending = {
            let mut ledger = self.ledger();
            let Some(i) = ledger.position(id) else {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "the launcher has no launch record for this container; cannot confirm",
                ));
            };
            match ledger.entries.get(i) {
                Some((_, LaunchRecord::Clean)) => return Ok(()),
                Some((_, LaunchRecord::Settling)) => {
                    return Err(TraitError::new(
                        ErrorCode::FailedPrecondition,
                        "another confirmation for this container is in progress",
                    ));
                }
                Some((_, LaunchRecord::Pending(_))) => {}
                Some((_, LaunchRecord::Handed(_))) | None => {
                    return Err(TraitError::new(
                        ErrorCode::FailedPrecondition,
                        "the launched process is owned by its handle holder; cannot confirm",
                    ));
                }
            }
            match Self::take_pending_at(&mut ledger, i) {
                Some(p) => p,
                None => {
                    return Err(TraitError::new(
                        ErrorCode::Internal,
                        "could not confirm that no launched process remains",
                    ));
                }
            }
        };
        let settled = self.settle(&mut pending, deadline);
        match settled {
            Ok(()) => {
                let mut ledger = self.ledger();
                ledger.set(id, LaunchRecord::Clean);
                if !ledger.has_pending() {
                    self.left_process.store(false, Ordering::SeqCst);
                }
                Ok(())
            }
            Err(code) => {
                self.ledger().set(id, LaunchRecord::Pending(pending));
                Err(match code {
                    ErrorCode::Timeout => TraitError::new(
                        ErrorCode::Timeout,
                        "timed out confirming that no launched process remains",
                    ),
                    code => {
                        TraitError::new(code, "could not confirm that no launched process remains")
                    }
                })
            }
        }
    }
}

/// 起動失敗の `ExecError` を固定文言の `TraitError` へ写す。`unconfirmed` なら、起動したプロセスの消滅を確かめられ
/// なかった事実を固定の接尾辞で足す(パス・errno・pid は載せない)。
#[cfg(target_os = "linux")]
fn launch_error(e: &ExecError, unconfirmed: bool) -> TraitError {
    let mut error = to_trait_error(e);
    if unconfirmed {
        error = TraitError::new(e.code, format!("{}{UNCONFIRMED_SUFFIX}", error.message()));
    }
    error
}
/// `ExecError` を固定文言の `TraitError` へ写す(パス・errno・env の値を含めない。セキュリティ規約)。
#[cfg(target_os = "linux")]
fn to_trait_error(e: &ExecError) -> TraitError {
    let message = match e.code {
        ErrorCode::Timeout => "container launch did not complete within the timeout".to_owned(),
        _ => format!("container launch failed in the {:?} stage", e.stage),
    };
    TraitError::new(e.code, message)
}

/// `process.args` から exec するエントリポイントを作る(シェルを介さず配列のまま渡す。インジェクション防止)。
#[cfg(target_os = "linux")]
fn entrypoint_of(spec: &LaunchSpec) -> Result<Entrypoint, TraitError> {
    let first = spec.args().first().ok_or_else(|| {
        TraitError::new(ErrorCode::InvalidArgument, "process.args must not be empty")
    })?;
    Entrypoint::new(first, spec.args(), spec.env()).map_err(|e| to_trait_error(&e))
}

/// `LaunchSpec` の namespace・hostname から分離の設定を作る(`start` が検証済み。未対応の種別は拒否)。
#[cfg(target_os = "linux")]
fn isolation_config_of(spec: &LaunchSpec) -> Result<IsolationConfig, TraitError> {
    let mut namespaces = NamespaceSet::empty();
    for kind in spec.namespaces() {
        let ns = match kind {
            NamespaceKind::Pid => Namespace::Pid,
            NamespaceKind::Mount => Namespace::Mount,
            NamespaceKind::Uts => Namespace::Uts,
            NamespaceKind::Ipc => Namespace::Ipc,
            NamespaceKind::User => Namespace::User,
            _ => {
                return Err(TraitError::new(
                    ErrorCode::Unimplemented,
                    "the namespace kind is not supported by the launcher",
                ));
            }
        };
        namespaces = namespaces.with(ns);
    }
    let hostname = spec
        .hostname()
        .map(Hostname::new)
        .transpose()
        .map_err(|e| to_trait_error(&e))?;
    Ok(IsolationConfig {
        namespaces,
        hostname,
    })
}

/// 本番の実体(既存の `exec` の公開関数への薄い委譲)。
#[cfg(target_os = "linux")]
struct RealOps {
    /// 呼び出しプロセスが child subreaper であることの証跡(構築時に 1 回)。
    subreaper: ChildSubreaper,
}

#[cfg(target_os = "linux")]
impl LaunchOps for RealOps {
    fn is_single_threaded(&self) -> bool {
        crate::sys::self_is_single_threaded()
    }

    fn landlock_ruleset(
        &self,
        config: &super::config::OciConfig,
    ) -> Result<LandlockRuleset, ExecError> {
        crate::exec::landlock_ruleset_from_config(config)
    }

    fn spawn(&self, input: SpawnInput<'_>) -> Result<Spawned, Box<PreparedLaunchFailure>> {
        let not_started = |e: ExecError| {
            Box::new(PreparedLaunchFailure::clean(
                AuditedRejection::not_applicable(e),
            ))
        };
        // euid 0 の写像は計画の段階で拒否される(`HostRootIdentityMapping`。SEC-5)。
        let isolation_plan = plan(&input.isolation).map_err(not_started)?;
        // 計画が euid / egid 0 を拒否した後に、自 egid をコンテナ内 0 へ写す単一 ID 写像を作る(devpts の gid= の決定元)。
        let gid_map =
            crate::rootless::single_id_mapping(crate::sys::effective_gid()).map_err(|_| {
                not_started(ExecError::new(
                    ErrorCode::PermissionDenied,
                    IsolationStage::UserNamespaceMap,
                    "refusing to map the host root identity",
                ))
            })?;
        let (stdio, stdout, stderr) = ChildStdio::pipes().map_err(not_started)?;
        let setup = PrePivotSetup {
            devices: crate::exec::DevptsGidSource::Rootless(&gid_map),
            tmpfs: Some(input.tmpfs),
            inject: None,
            binds: input.binds,
            pinned_rootfs: Some(input.spec.rootfs_dir().as_fd()),
            config_paths: ConfigPaths {
                readonly: input.spec.config().readonly_paths(),
                masked: input.spec.config().masked_paths(),
            },
            status: None,
        };
        let child = spawn_container_via_intermediate(
            IntermediateSpec {
                plan: &isolation_plan,
                rootfs: input.spec.rootfs(),
                entry: input.entry,
                setup,
            },
            input.stages,
            stdio,
            &self.subreaper,
            input.audit,
            input.timeout,
        )?;
        Ok(Spawned {
            child,
            stdout,
            stderr,
        })
    }

    fn rescan(&self, tag: &LaunchTag, reap_timeout: Duration) -> Rescan {
        rescan_unreported_init(tag, &self.subreaper, reap_timeout)
    }

    fn ensure_no_process_in_recorded(
        &self,
        id: &ContainerId,
        placement: &CgroupPlacement,
        deadline: Instant,
    ) -> Result<RecordedCgroupOutcome, ErrorCode> {
        // 失敗は code だけを残す(メッセージ・パスは呼び出し側で固定文言に置き換えるため捨てる)。
        crate::cgroups::ensure_no_process_in_recorded(id, placement, deadline).map_err(|e| e.code)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::audit_log::AuditRecord;
    use crate::cgroups::CgroupJoin;
    use crate::oci_runtime::parse_config_bytes;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    struct NullSink;

    impl AuditSink for NullSink {
        fn record(&self, _record: &AuditRecord) -> Result<(), TraitError> {
            Ok(())
        }
    }

    /// 失敗した spawn が返す、回収できなかった子の種類。
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Unreaped {
        /// 無し(回収済み)。
        None,
        /// 存在しない pid(`kill_and_reap` が常に失敗する)。
        Dead,
        /// 実在する子(再回収で回収できる)。
        Live,
    }

    /// 失敗する spawn の注入(`rescans` は返す再探索の識別子の個数)。
    #[derive(Clone, Copy)]
    struct FailSpawn {
        code: ErrorCode,
        unreaped: Unreaped,
        rescans: usize,
    }

    /// 実在する子(`sleep`)のハンドル。pidfd を持ち、`kill_and_reap` で回収できる。
    // 回収は返したハンドルの `kill_and_reap` / `terminate` が行う(std の `Child` は使わない)。
    #[allow(clippy::zombie_processes)]
    fn live_child() -> ContainerChild {
        let child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        std::mem::forget(child);
        ContainerChild::from_pid_for_test(pid)
    }

    /// spawn に渡った (bind の宛先列, 既定 tmpfs の宛先列)。
    type SeenSpawn = (Option<Vec<String>>, Vec<String>);

    /// 呼び出しの記録と注入ができる偽の実体。
    struct FakeOps {
        events: Arc<Mutex<Vec<String>>>,
        single_threaded: bool,
        /// Landlock の検出を差し替える(`None` なら ABI 6 相当で成功)。
        abi: Option<u32>,
        spawn_calls: AtomicUsize,
        fail_spawn: Option<FailSpawn>,
        /// 成功する spawn が返す子を、pidfd の無い偽 pid にするか。
        child_without_pidfd: bool,
        /// 成功する spawn が返した子の pid(0 なら未起動)。
        last_pid: Arc<AtomicU32>,
        /// `rescan` が順に返す結果(尽きたら「残っていない」)。
        rescan_results: Mutex<VecDeque<Rescan>>,
        /// ステージ列を偽のカーネル上で実行して証跡を記録するか(cgroup 参加の段を含む列は実行しない)。
        run_stages: bool,
        /// spawn に渡った bind mount の宛先列と既定 tmpfs の宛先列の記録(spawn ごとに 1 件。bind 無しは `None`)。
        seen: Arc<Mutex<Vec<SeenSpawn>>>,
        /// `ensure_no_process_in_recorded` が順に返す結果(尽きたら `AlreadyAbsent`)と、受け取った配置の記録(#2011)。
        recorded_script: Mutex<VecDeque<Result<RecordedCgroupOutcome, ErrorCode>>>,
        recorded_calls: Arc<Mutex<Vec<(ContainerId, CgroupPlacement)>>>,
    }

    impl FakeOps {
        fn new(events: &Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                events: Arc::clone(events),
                single_threaded: true,
                abi: None,
                spawn_calls: AtomicUsize::new(0),
                fail_spawn: None,
                child_without_pidfd: false,
                last_pid: Arc::new(AtomicU32::new(0)),
                rescan_results: Mutex::new(VecDeque::new()),
                run_stages: true,
                seen: Arc::new(Mutex::new(Vec::new())),
                recorded_script: Mutex::new(VecDeque::new()),
                recorded_calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    fn push(events: &Arc<Mutex<Vec<String>>>, s: impl Into<String>) {
        events.lock().unwrap().push(s.into());
    }

    impl LaunchOps for FakeOps {
        fn is_single_threaded(&self) -> bool {
            push(&self.events, "threads");
            self.single_threaded
        }

        fn landlock_ruleset(
            &self,
            config: &super::super::config::OciConfig,
        ) -> Result<LandlockRuleset, ExecError> {
            push(&self.events, "landlock");
            let detected = crate::landlock::evaluate_abi(self.abi.unwrap_or(6));
            crate::exec::ruleset_from_detection(detected, config)
        }

        fn spawn(&self, input: SpawnInput<'_>) -> Result<Spawned, Box<PreparedLaunchFailure>> {
            self.spawn_calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push((
                input.binds.map(|b| {
                    b.mounts()
                        .iter()
                        .map(|m| m.destination().as_str().to_owned())
                        .collect()
                }),
                input
                    .tmpfs
                    .mounts()
                    .iter()
                    .map(|m| m.destination.as_str().to_owned())
                    .collect(),
            ));
            push(&self.events, format!("spawn {:?}", input.stages));
            // 偽のカーネル上でステージ列を実行し、制限適用の証跡(`LaunchReady`)がそろうかを記録する。
            if self.run_stages {
                let evidence = input.stages.run_then(|_, _, ev| {
                    Ok(ev
                        .map(|_| "ready".to_owned())
                        .unwrap_or_else(|e| format!("missing {:?}", e.missing())))
                });
                push(&self.events, format!("evidence {}", evidence.unwrap()));
            }
            if let Some(fail) = self.fail_spawn {
                let unreaped = match fail.unreaped {
                    Unreaped::None => Vec::new(),
                    Unreaped::Dead => vec![ContainerChild::from_pid_for_test(2_000_001)],
                    Unreaped::Live => vec![live_child()],
                };
                return Err(Box::new(PreparedLaunchFailure {
                    rejection: AuditedRejection::not_applicable(ExecError::new(
                        fail.code,
                        IsolationStage::Spawn,
                        "/secret/path errno 13",
                    )),
                    reap_error: (fail.unreaped != Unreaped::None).then(|| {
                        ExecError::new(ErrorCode::Timeout, IsolationStage::Wait, "reap failed")
                    }),
                    unreaped,
                    rescans: (0..fail.rescans).map(|_| LaunchTag::fresh()).collect(),
                }));
            }
            let (stdout, _w1) = std::io::pipe().unwrap();
            let (stderr, _w2) = std::io::pipe().unwrap();
            let child = if self.child_without_pidfd {
                ContainerChild::from_pid_for_test(2_000_002)
            } else {
                live_child()
            };
            self.last_pid.store(child.pid(), Ordering::SeqCst);
            Ok(Spawned {
                child,
                stdout,
                stderr,
            })
        }

        fn ensure_no_process_in_recorded(
            &self,
            id: &ContainerId,
            placement: &CgroupPlacement,
            _deadline: Instant,
        ) -> Result<RecordedCgroupOutcome, ErrorCode> {
            push(&self.events, "ensure-recorded");
            self.recorded_calls
                .lock()
                .unwrap()
                .push((id.clone(), placement.clone()));
            self.recorded_script
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(RecordedCgroupOutcome::AlreadyAbsent))
        }

        fn rescan(&self, _tag: &LaunchTag, _reap_timeout: Duration) -> Rescan {
            push(&self.events, "rescan");
            self.rescan_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_default()
        }
    }

    fn launcher(
        ops: FakeOps,
        privilege: IsolationPrivilege,
        join: Option<JoinSource>,
    ) -> ProductionLauncher {
        ProductionLauncher {
            inner: Inner::new(Box::new(ops), privilege, Arc::new(NullSink), join),
        }
    }

    /// bundle ディレクトリを作って `LaunchSpec` を直接組み立てる(`start` は cgroup 要件ありの config を
    /// 先に拒否するため、要件の有無を試験で選べるよう `LaunchSpec::new` を使う)。
    fn spec_for(name: &str, linux_extra: serde_json::Value) -> LaunchSpec {
        spec_with_mounts(name, linux_extra, serde_json::json!([]))
    }

    /// `spec_for` に `mounts[]` を足したもの。bind の集合は `start` と同じく `config.mounts()` から作る。
    fn spec_with_mounts(
        name: &str,
        linux_extra: serde_json::Value,
        mounts: serde_json::Value,
    ) -> LaunchSpec {
        use super::super::cgroup_requirement::CgroupRequirement;
        use super::super::launch::RootfsDir;
        use crate::traits::ContainerId;
        let dir =
            std::env::temp_dir().join(format!("fandhe-launcher-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rootfs")).unwrap();
        let mut linux = serde_json::json!({"namespaces": [
            {"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "uts"}, {"type": "ipc"}
        ]});
        if let (Some(l), Some(e)) = (linux.as_object_mut(), linux_extra.as_object()) {
            for (k, v) in e {
                l.insert(k.clone(), v.clone());
            }
        }
        let cfg = serde_json::json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "hostname": "box",
            "process": {"user": {"uid": 0, "gid": 0}, "args": ["/bin/echo", "hi"],
                        "env": ["PATH=/bin"], "cwd": "/"},
            "mounts": mounts,
            "linux": linux
        });
        let config = parse_config_bytes(&serde_json::to_vec(&cfg).unwrap()).unwrap();
        let rootfs = dir.join("rootfs");
        let rootfs_dir = RootfsDir::pin(&dir, &rootfs).expect("pin");
        let namespaces = config.namespaces().iter().map(|n| n.kind()).collect();
        let binds = super::super::bind_mounts::BindMountSet::from_mounts(config.mounts())
            .expect("valid binds");
        let spec = LaunchSpec::new(
            rootfs,
            rootfs_dir,
            vec!["/bin/echo".to_owned(), "hi".to_owned()],
            vec!["PATH=/bin".to_owned()],
            Some("box".to_owned()),
            namespaces,
            CgroupRequirement::of_config(&config),
            Arc::new(config),
            ContainerId::new(name).unwrap(),
            binds,
        );
        let _ = std::fs::remove_dir_all(&dir);
        spec
    }

    fn events() -> Arc<Mutex<Vec<String>>> {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn rootless() -> IsolationPrivilege {
        IsolationPrivilege::RootlessSingleId
    }

    /// CORE-5・SEC-1: 順序は 単一スレッド確認 → Landlock → spawn で、ステージ列に Landlock の ruleset が必ず入る。
    #[test]
    fn core5_landlock_ruleset_is_always_in_the_pipeline_and_ordered() {
        let spec = spec_for("order", serde_json::json!({}));
        let ev = events();
        let ops = FakeOps::new(&ev);
        let pid_of = Arc::clone(&ops.last_pid);
        let l = launcher(ops, rootless(), None);
        let p = l.launch(&spec, Duration::from_secs(1)).expect("launch");
        assert_eq!(p.pid().get(), pid_of.load(Ordering::SeqCst));
        p.terminate(Duration::from_secs(5)).expect("terminate");
        let log = ev.lock().unwrap().clone();
        assert_eq!(log.len(), 4, "{log:?}");
        assert_eq!(&log[..2], ["threads", "landlock"]);
        assert_eq!(log[3], "evidence ready");
        assert!(log[2].starts_with("spawn StagePipeline"), "{}", log[2]);
        assert!(log[2].contains(r#"landlock: "ruleset""#), "{}", log[2]);
        assert!(!log[2].contains("custom_hook"), "{}", log[2]);
    }

    /// SEC-1・CORE-5: Landlock を欠くステージ列では制限適用の証跡がそろわず(exec に進めない)、launcher の
    /// 列(上の試験)ではそろう。証跡は `run_then` だけが作り、launcher は作る手段を増やさない。
    #[test]
    fn sec1_pipeline_without_landlock_never_yields_launch_ready() {
        let evidence = StagePipeline::new().run_then(|_, _, ev| {
            Ok(ev
                .map(|_| "ready".to_owned())
                .unwrap_or_else(|e| format!("missing {:?}", e.missing())))
        });
        assert_eq!(evidence.unwrap(), "missing [Landlock]");
    }

    /// CORE-5: ABI 6 未満は `FailedPrecondition` で起動を拒否し、spawn を呼ばない(縮退しない)。
    #[test]
    fn core5_abi_too_old_refuses_without_spawning() {
        let spec = spec_for("abi", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.abi = Some(5);
        let l = launcher(ops, rootless(), None);
        let err = l
            .launch(&spec, Duration::from_secs(1))
            .err()
            .expect("refused");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container launch failed in the Landlock stage"
        );
        assert!(
            !ev.lock().unwrap().iter().any(|e| e.starts_with("spawn")),
            "must not spawn"
        );
    }

    /// CORE-3: cgroup 要件ありで参加の源が無ければ、スレッド確認・Landlock・fork より前に拒否する。
    #[test]
    fn core3_cgroup_requirement_without_join_source_refuses_before_anything() {
        let spec = spec_for("cgroup", serde_json::json!({"resources": {}}));
        assert!(spec.cgroup_requirement().is_required());
        let ev = events();
        let l = launcher(FakeOps::new(&ev), rootless(), None);
        let err = l
            .launch(&spec, Duration::from_secs(1))
            .err()
            .expect("refused");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "the config requires a cgroup (linux.resources) but no cgroup join was provided; refusing to launch without limits"
        );
        assert!(
            ev.lock().unwrap().is_empty(),
            "nothing must run before the refusal"
        );
    }

    /// CORE-3: 参加の源は launch のたびに 1 回呼ばれ(restart で再利用できる)、ステージ列へ登録される。
    #[test]
    fn core3_join_source_is_called_once_per_launch() {
        let spec = spec_for("join", serde_json::json!({}));
        let ev = events();
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let source: JoinSource = Box::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
            let fd = std::fs::File::open("/").unwrap();
            Ok(CgroupJoin::from_dir_for_test(
                crate::cgroups::CgroupName::new(&crate::traits::ContainerId::new("c").unwrap())
                    .unwrap(),
                std::os::fd::OwnedFd::from(fd),
            ))
        });
        let mut ops = FakeOps::new(&ev);
        ops.run_stages = false;
        let l = launcher(ops, rootless(), Some(source));
        l.launch(&spec, Duration::from_secs(1))
            .expect("first")
            .terminate(Duration::from_secs(5))
            .expect("terminate first");
        l.launch(&spec, Duration::from_secs(1))
            .expect("second")
            .terminate(Duration::from_secs(5))
            .expect("terminate second");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let log = ev.lock().unwrap().clone();
        let spawns: Vec<_> = log.iter().filter(|e| e.starts_with("spawn")).collect();
        assert_eq!(spawns.len(), 2);
        for s in spawns {
            assert!(s.contains("cgroup_join: true"), "{s}");
        }
    }

    /// CORE-1: 複数スレッドの呼び出しは副作用なしで `FailedPrecondition`(Landlock も spawn も呼ばない)。
    #[test]
    fn core1_multithreaded_caller_is_refused_without_side_effects() {
        let spec = spec_for("threads", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.single_threaded = false;
        let l = launcher(ops, rootless(), None);
        let err = l
            .launch(&spec, Duration::from_secs(1))
            .err()
            .expect("refused");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), "launch requires a single-threaded process");
        assert_eq!(ev.lock().unwrap().as_slice(), ["threads"]);
    }

    /// SEC-5: 未実装の権限モデルは `Unimplemented` で、何も呼ばずに拒否する。
    #[test]
    fn sec5_unimplemented_privilege_models_are_refused_before_fork() {
        let spec = spec_for("priv", serde_json::json!({}));
        for (privilege, message) in [
            (
                IsolationPrivilege::RootfulHostRoot,
                "the rootful privilege model is not supported by the launcher",
            ),
            (
                IsolationPrivilege::RootlessSubordinateIds,
                "the subordinate id privilege model is not supported by the launcher",
            ),
        ] {
            let ev = events();
            let l = launcher(FakeOps::new(&ev), privilege, None);
            let err = l
                .launch(&spec, Duration::from_secs(1))
                .err()
                .expect("refused");
            assert_eq!(err.code(), ErrorCode::Unimplemented);
            assert_eq!(err.message(), message);
            assert!(ev.lock().unwrap().is_empty());
        }
    }

    /// REPAIR-5: launcher は `SelfBounded` を宣言する。
    #[test]
    fn repair5_launch_mode_is_self_bounded() {
        let ev = events();
        let l = launcher(FakeOps::new(&ev), rootless(), None);
        assert_eq!(l.launch_mode(), LaunchMode::SelfBounded);
    }

    fn fail(code: ErrorCode, unreaped: Unreaped, rescans: usize) -> Option<FailSpawn> {
        Some(FailSpawn {
            code,
            unreaped,
            rescans,
        })
    }

    fn launch_err(l: &ProductionLauncher, spec: &LaunchSpec) -> TraitError {
        l.launch(spec, Duration::from_secs(1))
            .err()
            .expect("launch must fail")
    }

    const CLEAN_MESSAGE: &str = "container launch failed in the Spawn stage";

    /// セキュリティ規約・CORE-2: 失敗の文言は固定で、パス・errno を含めない。子が残らない失敗には接尾辞を付けず、
    /// 起動予約を保持させず、`confirm_no_process` が `Ok` になる(消滅を確かめ済み)。
    #[test]
    fn core2_clean_failure_has_no_suffix_and_is_confirmed() {
        let spec = spec_for("clean", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.fail_spawn = fail(ErrorCode::PermissionDenied, Unreaped::None, 0);
        let l = launcher(ops, rootless(), None);
        let err = launch_err(&l, &spec);
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(err.message(), CLEAN_MESSAGE);
        assert!(!l.last_launch_may_have_left_process());
        l.confirm_no_process(spec.container_id(), Duration::from_secs(1))
            .expect("clean");
    }

    /// CORE-2・REPAIR-5: 回収できなかった子がある失敗は、固定の接尾辞つきの文言で返り(`Timeout` はコードを保つ)、
    /// start へ「子が残り得る」と伝える。`confirm_no_process` は確かめられない間 `Ok` にせず、再試行できる。
    #[test]
    fn core2_unreaped_child_is_reported_and_not_confirmed() {
        let spec = spec_for("leave", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.fail_spawn = fail(ErrorCode::Timeout, Unreaped::Dead, 0);
        let l = launcher(ops, rootless(), None);
        assert!(!l.last_launch_may_have_left_process());
        let err = launch_err(&l, &spec);
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(
            err.message(),
            "container launch did not complete within the timeout; removal of the launched processes could not be confirmed"
        );
        assert!(l.last_launch_may_have_left_process());
        // 確かめられない間は何度呼んでも `Ok` にならない(状態は `Pending` のまま)。
        let started = Instant::now();
        for _ in 0..2 {
            let err = l
                .confirm_no_process(spec.container_id(), Duration::from_millis(200))
                .expect_err("cannot confirm");
            assert_eq!(err.code(), ErrorCode::Internal);
            assert_eq!(
                err.message(),
                "could not confirm that no launched process remains"
            );
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(l.last_launch_may_have_left_process());
    }

    /// CORE-2・REPAIR-5: 実在する子を回収できなかった失敗は、`confirm_no_process` が期限内に kill・回収して `Ok` に
    /// する。`Ok` の後は子が `/proc` に残らず、起動予約を保持させる印も戻る。
    #[test]
    fn core2_confirm_reaps_a_live_unreaped_child() {
        let spec = spec_for("reap", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.fail_spawn = fail(ErrorCode::Internal, Unreaped::Live, 0);
        let l = launcher(ops, rootless(), None);
        let err = launch_err(&l, &spec);
        assert!(err.message().ends_with(UNCONFIRMED_SUFFIX), "{err:?}");
        let pid = match &l.inner.ledger().entries[0].1 {
            LaunchRecord::Pending(p) => p.children[0].pid(),
            other => panic!("unexpected record {other:?}"),
        };
        assert!(l.last_launch_may_have_left_process());
        l.confirm_no_process(spec.container_id(), Duration::from_secs(5))
            .expect("reaped");
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "the child {pid} must be reaped"
        );
        assert!(!l.last_launch_may_have_left_process());
        // 確定済み(`Clean`)なので、もう一度呼んでも `Ok`。
        l.confirm_no_process(spec.container_id(), Duration::from_secs(1))
            .expect("still clean");
    }

    /// CORE-2: 報告前の PID 1 の再探索が要る失敗は、子を回収できても探索が済むまで `Ok` にならない。探索は子の回収が
    /// 済んでから行い(回収できない間は呼ばない)、探索が未完了を返す間は `Pending` のまま、完了すれば `Ok`。
    #[test]
    fn core2_confirm_rescans_after_children_are_reaped() {
        let spec = spec_for("rescan", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.fail_spawn = fail(ErrorCode::Timeout, Unreaped::Live, 1);
        ops.rescan_results.lock().unwrap().push_back(Rescan {
            unreaped: Vec::new(),
            error: Some(ExecError::new(
                ErrorCode::Internal,
                IsolationStage::Wait,
                "cannot scan",
            )),
            scan_incomplete: true,
        });
        let l = launcher(ops, rootless(), None);
        launch_err(&l, &spec);
        // 1 回目: 子は回収できるが、探索が未完了を返す。
        let err = l
            .confirm_no_process(spec.container_id(), Duration::from_secs(5))
            .expect_err("scan incomplete");
        assert_eq!(err.code(), ErrorCode::Internal);
        // 2 回目: 子は回収済みで、探索が完了する。
        l.confirm_no_process(spec.container_id(), Duration::from_secs(5))
            .expect("rescanned");
        assert_eq!(
            ev.lock().unwrap().iter().filter(|e| *e == "rescan").count(),
            2
        );
    }

    /// CORE-2: 回収できない子が残る間は、再探索を呼ばない(中間プロセスを回収できないと PID 1 は C の子にならない)。
    #[test]
    fn core2_confirm_does_not_rescan_while_a_child_cannot_be_reaped() {
        let spec = spec_for("norescan", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.fail_spawn = fail(ErrorCode::Timeout, Unreaped::Dead, 1);
        let l = launcher(ops, rootless(), None);
        launch_err(&l, &spec);
        l.confirm_no_process(spec.container_id(), Duration::from_millis(200))
            .expect_err("cannot reap");
        assert!(!ev.lock().unwrap().iter().any(|e| e == "rescan"));
    }

    /// CORE-2・SEC-1: 台帳に無い ID(別プロセスで起動した残存を含む)と、ハンドルを渡し済みの ID は確証できないため、
    /// `Ok` にせず `FailedPrecondition`(fail-closed)。
    #[test]
    fn core2_confirm_refuses_unknown_and_handed_ids() {
        let spec = spec_for("handed", serde_json::json!({}));
        let ev = events();
        let l = launcher(FakeOps::new(&ev), rootless(), None);
        let err = l
            .confirm_no_process(spec.container_id(), Duration::from_secs(1))
            .expect_err("unknown");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "the launcher has no launch record for this container; cannot confirm"
        );
        let p = l.launch(&spec, Duration::from_secs(1)).expect("launch");
        let err = l
            .confirm_no_process(spec.container_id(), Duration::from_secs(1))
            .expect_err("handed");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "the launched process is owned by its handle holder; cannot confirm"
        );
        p.terminate(Duration::from_secs(5)).expect("terminate");
    }

    fn placement() -> CgroupPlacement {
        CgroupPlacement::new(
            crate::traits::CgroupScope::new("/user.slice/x.scope").expect("scope"),
            crate::traits::StateRevision::from_raw(5),
        )
    }

    /// CORE-2(#2011): 台帳に無い ID は、記録された配置が無ければ従来どおり `FailedPrecondition` で、cgroup の
    /// 継ぎ目を呼ばない。ID だけからパスを組み立てない。
    #[test]
    fn core2_issue2011_unknown_id_without_record_is_refused() {
        let ev = events();
        let ops = FakeOps::new(&ev);
        let calls = Arc::clone(&ops.recorded_calls);
        let l = launcher(ops, rootless(), None);
        let id = ContainerId::new("nr").unwrap();
        let err = l
            .confirm_no_process_recorded(&id, None, Duration::from_secs(1))
            .expect_err("no record");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert!(calls.lock().unwrap().is_empty());
    }

    /// CORE-2(#2011): 台帳に無い ID は、`AlreadyAbsent`・`WasEmpty`・`Killed` のいずれでも `Ok` で、記録された配置を
    /// そのまま継ぎ目へ渡す。
    #[test]
    fn core2_issue2011_unknown_id_is_confirmed_through_recorded_cgroup() {
        for outcome in [
            RecordedCgroupOutcome::AlreadyAbsent,
            RecordedCgroupOutcome::WasEmpty,
            RecordedCgroupOutcome::Killed,
        ] {
            let ev = events();
            let ops = FakeOps::new(&ev);
            ops.recorded_script.lock().unwrap().push_back(Ok(outcome));
            let calls = Arc::clone(&ops.recorded_calls);
            let l = launcher(ops, rootless(), None);
            let id = ContainerId::new("ok").unwrap();
            let p = placement();
            l.confirm_no_process_recorded(&id, Some(&p), Duration::from_secs(1))
                .unwrap_or_else(|e| panic!("{outcome:?}: {e:?}"));
            assert_eq!(calls.lock().unwrap().clone(), vec![(id, p)]);
        }
    }

    /// CORE-2・SEC-1・REPAIR-5(#2011): cgroup を検証・読み取りできない失敗は `Ok` にならず code を保つ。
    /// 文言は固定で、期限切れは `Timeout`。
    #[test]
    fn core2_issue2011_cgroup_failures_are_not_confirmed() {
        for code in [
            ErrorCode::PermissionDenied,
            ErrorCode::FailedPrecondition,
            ErrorCode::Internal,
            ErrorCode::Unimplemented,
            ErrorCode::Timeout,
        ] {
            let ev = events();
            let ops = FakeOps::new(&ev);
            ops.recorded_script.lock().unwrap().push_back(Err(code));
            let l = launcher(ops, rootless(), None);
            let id = ContainerId::new("ng").unwrap();
            let err = l
                .confirm_no_process_recorded(&id, Some(&placement()), Duration::from_secs(1))
                .expect_err("must not confirm");
            assert_eq!(err.code(), code);
            let expected = if code == ErrorCode::Timeout {
                "timed out confirming that no process remains in the recorded cgroup"
            } else {
                "could not confirm that no process remains in the recorded cgroup"
            };
            assert_eq!(err.message(), expected);
        }
    }

    /// CORE-2(#2011): 台帳にある ID は記録された配置があっても台帳で判定する。`Handed` は拒否のまま
    /// (cgroup の継ぎ目を呼ばない)、`Clean` は継ぎ目を呼ばずに `Ok`。
    #[test]
    fn core2_issue2011_ledger_takes_precedence_over_recorded_cgroup() {
        let spec = spec_for("ledger-first", serde_json::json!({}));
        let ev = events();
        let ops = FakeOps::new(&ev);
        let calls = Arc::clone(&ops.recorded_calls);
        let l = launcher(ops, rootless(), None);
        let _handle = l.launch(&spec, Duration::from_secs(1)).expect("launch");
        let err = l
            .confirm_no_process_recorded(
                spec.container_id(),
                Some(&placement()),
                Duration::from_secs(1),
            )
            .expect_err("handed");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert!(calls.lock().unwrap().is_empty());

        let spec2 = spec_for("ledger-clean", serde_json::json!({}));
        let mut ops2 = FakeOps::new(&events());
        ops2.fail_spawn = Some(FailSpawn {
            code: ErrorCode::Internal,
            unreaped: Unreaped::None,
            rescans: 0,
        });
        let calls2 = Arc::clone(&ops2.recorded_calls);
        let l2 = launcher(ops2, rootless(), None);
        assert!(l2.launch(&spec2, Duration::from_secs(1)).is_err());
        l2.confirm_no_process_recorded(
            spec2.container_id(),
            Some(&placement()),
            Duration::from_secs(1),
        )
        .expect("clean");
        assert!(calls2.lock().unwrap().is_empty());
    }

    /// CORE-2・#1819: ハンドルの `terminate` が成功すると回収の証跡が台帳へ引き継がれ、`confirm_no_process` が
    /// `Ok` になる。再 launch 後の古いハンドルの terminate は新しい項目を `Clean` にしない(世代照合)。
    #[test]
    fn core2_terminate_of_handed_process_makes_confirm_ok() {
        let spec = spec_for("handed-reaped", serde_json::json!({}));
        let ev = events();
        let l = launcher(FakeOps::new(&ev), rootless(), None);
        let first = l.launch(&spec, Duration::from_secs(1)).expect("launch");
        assert!(
            l.confirm_no_process(spec.container_id(), Duration::from_secs(1))
                .is_err()
        );
        // 同じ ID を再 launch すると世代が進む。古いハンドルの回収は新しい項目に影響しない。
        let second = l.launch(&spec, Duration::from_secs(1)).expect("relaunch");
        first.terminate(Duration::from_secs(5)).expect("terminate");
        assert_eq!(
            l.confirm_no_process(spec.container_id(), Duration::from_secs(1))
                .expect_err("stale handle must not confirm")
                .code(),
            ErrorCode::FailedPrecondition
        );
        second.terminate(Duration::from_secs(5)).expect("terminate");
        l.confirm_no_process(spec.container_id(), Duration::from_secs(1))
            .expect("confirm after reap");
    }

    /// CORE-2: 確かめられていない起動が残る ID への再 launch は、spawn を呼ばずに拒否する(二重起動の防止)。
    /// 子を回収できるようになれば(`Live`)再回収して通る。
    #[test]
    fn core2_relaunch_is_refused_while_the_previous_launch_is_unconfirmed() {
        let spec = spec_for("relaunch", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.fail_spawn = fail(ErrorCode::Timeout, Unreaped::Dead, 0);
        let l = launcher(ops, rootless(), None);
        launch_err(&l, &spec);
        let err = launch_err(&l, &spec);
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "a previous launch of this container is unconfirmed; removal of the launched processes could not be confirmed"
        );
        assert!(l.last_launch_may_have_left_process());
        let spawns = ev
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.starts_with("spawn"))
            .count();
        assert_eq!(spawns, 1, "the second launch must not reach spawn");

        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.fail_spawn = fail(ErrorCode::Timeout, Unreaped::Live, 0);
        let l = launcher(ops, rootless(), None);
        launch_err(&l, &spec);
        // 再回収できるので、2 回目は(同じ失敗の注入で)spawn まで進む。
        launch_err(&l, &spec);
        let spawns = ev
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.starts_with("spawn"))
            .count();
        assert_eq!(spawns, 2);
        // 2 回目の失敗が積んだ子も回収する(試験が子を残さない)。
        l.confirm_no_process(spec.container_id(), Duration::from_secs(5))
            .expect("reaped");
    }

    /// SEC-1・CORE-1: pidfd の無い子は使わない。回収できなければ台帳に残して接尾辞つきで拒否し、pid 0 は
    /// 触らずに拒否する(`kill(0)` は自プロセスグループへ届くため)。
    #[test]
    fn sec1_child_without_pidfd_is_refused_and_kept() {
        let spec = spec_for("nopidfd", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.child_without_pidfd = true;
        let l = launcher(ops, rootless(), None);
        let err = launch_err(&l, &spec);
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "the launched process has no pidfd; removal of the launched processes could not be confirmed"
        );
        assert!(l.last_launch_may_have_left_process());
        l.confirm_no_process(spec.container_id(), Duration::from_millis(200))
            .expect_err("cannot confirm");
    }

    /// 台帳: 件数に上限があり、確定済みは古い順に捨て、`Pending` は捨てない。`Pending` だけで満杯なら新しい ID を
    /// 拒否する。
    #[test]
    fn ledger_is_bounded_and_never_drops_pending() {
        use crate::traits::ContainerId;
        let id = |n: usize| ContainerId::new(format!("c{n}")).unwrap();
        let mut ledger = Ledger::default();
        for n in 0..LEDGER_MAX_ENTRIES {
            ledger.set(&id(n), LaunchRecord::Clean);
        }
        assert_eq!(ledger.entries.len(), LEDGER_MAX_ENTRIES);
        assert!(ledger.admit(&id(1000)).is_ok());
        assert_eq!(ledger.entries.len(), LEDGER_MAX_ENTRIES - 1);
        assert!(ledger.position(&id(0)).is_none(), "oldest is evicted first");

        let mut ledger = Ledger::default();
        for n in 0..LEDGER_MAX_ENTRIES {
            ledger.set(&id(n), LaunchRecord::Pending(Pending::default()));
        }
        assert!(matches!(ledger.admit(&id(1000)), Err(AdmitError::Full)));
        assert!(matches!(ledger.admit(&id(3)), Err(AdmitError::Pending(3))));
        // `Pending` は満杯でも記録される(残存を見失わない)。
        ledger.set(&id(1000), LaunchRecord::Pending(Pending::default()));
        assert_eq!(ledger.entries.len(), LEDGER_MAX_ENTRIES + 1);
        // 確定済みは満杯なら記録しない。
        ledger.set(&id(2000), LaunchRecord::Clean);
        assert!(ledger.position(&id(2000)).is_none());
    }
    /// 構築: 必須値の欠落は `InvalidArgument`(固定文言)。
    #[test]
    fn builder_requires_privilege_and_audit_sink() {
        let e = ProductionLauncher::builder().build().expect_err("missing");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            e.message(),
            "the launcher requires an isolation privilege model"
        );
        let e = ProductionLauncher::builder()
            .privilege(rootless())
            .build()
            .expect_err("missing");
        assert_eq!(e.message(), "the launcher requires an audit sink");
    }

    fn bind_mounts_json() -> serde_json::Value {
        serde_json::json!([
            {"destination": "/data", "type": "bind", "source": "/srv/data", "options": ["rbind", "noexec"]},
            {"destination": "/cache", "type": "bind", "source": "/srv/cache", "options": ["bind", "rw"]}
        ])
    }

    /// OCI-4・SEC-1(#1915): bind 付きの spec は、launcher が spawn へ同じ宛先列を渡す(空なら `None`)。
    /// 既定 tmpfs は `/dev/shm` を含む。restart 相当の 2 回目の launch でも同じ集合が渡る。
    #[test]
    fn oci4_launch_passes_bind_mounts_to_spawn_on_every_launch() {
        let spec = spec_with_mounts("binds", serde_json::json!({}), bind_mounts_json());
        let ev = events();
        let ops = FakeOps::new(&ev);
        let seen = Arc::clone(&ops.seen);
        let l = launcher(ops, rootless(), None);
        for _ in 0..2 {
            let p = l.launch(&spec, Duration::from_secs(1)).expect("launch");
            p.terminate(Duration::from_secs(5)).expect("terminate");
        }
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        for (binds, tmpfs) in &seen {
            assert_eq!(
                binds.as_deref(),
                Some(["/data".to_owned(), "/cache".to_owned()].as_slice())
            );
            assert_eq!(tmpfs, &["/dev/shm".to_owned()]);
        }
    }

    /// OCI-4(#1915): bind が無い spec では `binds` は `None`。
    #[test]
    fn oci4_launch_passes_no_binds_when_mounts_are_empty() {
        let spec = spec_for("nobinds", serde_json::json!({}));
        let ev = events();
        let ops = FakeOps::new(&ev);
        let seen = Arc::clone(&ops.seen);
        let l = launcher(ops, rootless(), None);
        let p = l.launch(&spec, Duration::from_secs(1)).expect("launch");
        p.terminate(Duration::from_secs(5)).expect("terminate");
        assert_eq!(
            seen.lock().unwrap().clone(),
            vec![(None, vec!["/dev/shm".to_owned()])]
        );
    }

    /// SEC-4(#1915): `rejection_audit_sink` は構築時の sink を返す。
    #[test]
    fn sec4_rejection_audit_sink_is_the_launcher_sink() {
        let l = launcher(FakeOps::new(&events()), rootless(), None);
        assert!(l.rejection_audit_sink().is_some());
    }

    /// 全 OS 共通の型: `parse_config_bytes` を使う他の試験と同様に config が `LaunchSpec` まで載ること。
    #[test]
    fn launch_spec_carries_config_and_container_id() {
        let spec = spec_for("carry", serde_json::json!({}));
        assert_eq!(spec.container_id().as_str(), "carry");
        assert_eq!(spec.config().hostname(), Some("box"));
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod non_linux_tests {
    use super::*;

    /// CLI-1: Linux 以外では構築が常に `Unimplemented`(固定文言)で、型は 3 OS に存在する。
    #[test]
    fn cli1_build_is_unimplemented_off_linux() {
        let e = ProductionLauncher::builder()
            .build()
            .expect_err("unsupported");
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        assert_eq!(e.message(), "production launcher requires Linux");
    }
}
