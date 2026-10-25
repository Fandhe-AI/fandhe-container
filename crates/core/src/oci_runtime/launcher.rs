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
//! 1. 権限モデルの検査(`RootfulHostRoot` は `Unimplemented`。許すかはオーナー判断待ちで #2241・`docs/design/rootful-host-root.md`。`RootlessSubordinateIds` の写像の解決は構築時に済み、
//!    ホスト ID 0 を含む・helper が無い構成は構築が拒否する。CORE-6・SEC-5・#2009)
//! 2. cgroup 要件の検査(`launch_after_cgroup_check`。要件ありで参加の源が無ければ `FailedPrecondition`。CORE-3)
//! 3. 呼び出しプロセスが単一スレッドであることの確認(`FailedPrecondition`。CORE-1)
//! 4. Landlock の ruleset(**必須**。ABI 6 未満は `FailedPrecondition` で起動を拒否し、縮退しない。CORE-5・#1314)
//!    と、launch 時の分離の記録の作成(pin 済み rootfs の fstat と同じ ruleset。作れなければ `Internal` で拒否。
//!    成功時は `LaunchedProcess::launch_isolation` で返し、start / restart が `state.json` へ書く。SUP-6・#2007)
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
//! `RootlessSubordinateIds` では中間プロセス I が `newuidmap` / `newgidmap` の応答を最大 `2 × helper_timeout + 1` 秒
//! 待つため、launch の `timeout` がこれより短いと C が I を SIGKILL して起動は失敗する(fail-closed)。
//! mapper の fork は stdio を flush しない版を使う(I は C のバッファの複製で、flush は二重出力と無期限の
//! 待ちを招くため。REPAIR-5)。
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
//! - **`process.cwd` と `process.user`(OCI-1・TASK-29・SEC-5)**: cwd は子が pivot 直後に fd 起点・symlink 非追従で
//!   適用する(symlink を含む cwd は追従せず拒否。Docker/runc と異なる)。uid・gid は fork の前に `check_user_mapped` で
//!   user namespace の写像と照合し(単一 ID 写像は 0/0 のみ)、capability 削減段が既存の資格情報の切り替えで適用する。
//!   補助グループ(`additionalGids`)・名前形式の `User` の解決・exec 経路の非 root は未対応
//! - **権限モデル**: `RootlessSingleId` と `RootlessSubordinateIds`(#2009)を扱う。`RootfulHostRoot`
//!   (SEC-5・CORE-7・CORE-9。start が user namespace を必須とするため、start を通る構成では到達しない。
//!   許すかはオーナー判断待ちで #2241・`docs/design/rootful-host-root.md`)は、決まるまで `Unimplemented` で拒否する
//! - **範囲写像の入力元**: `/etc/subuid`・`/etc/subgid` と `newuidmap` / `newgidmap`(`SubordinateIdSource`)
//!   だけ。config の `linux.uidMappings` / `gidMappings` は `start` が引き続き拒否する(受理は SEC-5 に関わる
//!   オーナー判断事項で、#2240 で判断待ち。`docs/design/config-id-mappings.md`)。supervisor が `RootlessSubordinateIds` を選ぶ経路は結線済み(#2243。subuid / subgid の設定の有無で選ぶ)
//! - **mapper と helper の回収**: mapper は I が fork 前に設定した `LaunchTag` を継承するため、I が期限で殺されて
//!   C へ再親付けされても `rescan` の探索対象になる。I は範囲写像の失敗時に mapper を kill せず `R` を報告し、C が
//!   I の回収後に同じ探索で回収する。mapper が起動する `newuidmap` / `newgidmap`(helper)は exec で `comm` が
//!   識別子でなくなるため、mapper は自分のセッションを作り、`rescan` は識別子を持つプロセスを SIGSTOP で止めて
//!   (またはゾンビのまま回収せずに)錨とし、「親が錨」か「セッション ID が錨」の子孫を列挙して kill してから錨を
//!   kill・回収し、再親付けされた子孫も回収する(mapper が helper を残して終了していても帰属を失わない。CORE-2)。
//!   停止の確認・列挙に失敗した場合は錨を回収せずに `scan_incomplete` となり、台帳は Pending のまま残る
//!   (fail-closed)。残余: 契約外の回収者(`waitpid(-1)` 等)が錨を回収した場合は帰属を失う(`ContainerChild` の
//!   「唯一の回収者」の前提の外)
//! - **`confirm_no_process`**: ID だけでは、この launcher 自身が起動した範囲だけを確証する(上の「起動台帳」)。
//!   別プロセスの残存は `confirm_no_process_recorded` が記録済みの cgroup で確かめる(上の「別プロセスの残存」。
//!   #2011)。残余は、記録が無い場合(`FailedPrecondition`)と、コンテナ内のプロセスが cgroup の外へ移った場合
//!   (検出できない。delete と同じ限界)。成功の内訳の観測記録は未実装(REPAIR-4)
//! - 起動台帳はプロセス内のメモリのみ(再起動をまたがない。別プロセスの残存は記録済みの cgroup で確かめる)
//! - **supervisor の結線**: `launch` は単一スレッドの呼び出しスレッドで直接呼ぶ必要がある。supervisor の
//!   `run_start` 手順 8 は、準備の作業スレッドを `join` してから入口スレッドが直接呼ぶ形に再構成済み(#1819)。
//!   restart の再 launch は `fandhe-relaunch` スレッド等が存在する状態で呼ばれ、この launcher が拒否する
//!   (`RelaunchFailed`・fail-closed)。呼び出しスレッドで直接行う再構成は #2043
//! - bind mount（`LaunchSpec::bind_mounts`。#1915）は載せる。fork 前に tmpfs・注入ディレクトリとの重なりを検査して
//!   `PrePivotSetup.binds` へ渡し、restart の再 launch でも同じ集合を使う。`ro` の bind は Landlock の
//!   `WriteRestrictionShadowed` で fork 前に拒否される（#1917 で解消するまでの想定挙動）
//! - `/sys` の sysfs（`LaunchSpec::sysfs_mount`。#2020）は載せる。`PrePivotSetup.sysfs` へ渡し、restart の再 launch でも
//!   同じ指定を使う。方式（新しい sysfs か、ホストの `/sys` の読み取り専用 rbind か）は pivot 前段が user namespace から
//!   事前に決める。本番の `start` 経路は user namespace を必須とするため、実際には rbind になる
//! - 起動オプション(`ProductionLauncherBuilder::launch_options`。SUP-12・CORE-5・#2625)の tmpfs・注入ファイル・IPC は載せる。
//!   未指定なら既定の `/dev/shm`(64 MiB)のみ・注入なし・専用 IPC namespace。`Host` は IPC namespace を作らず `/dev/shm` を載せず、
//!   Landlock の暗黙マウントを `WithoutShm` にする(config.json からは外せない)。`reject_protected_paths_over_implicit_dev` は
//!   常に全暗黙マウントで判定するため、`WithoutShm` でも `/dev/shm` 上の保護パス指定を拒否する(厳しい側。fail-closed)。
//!   範囲写像の holder が継承するメモリから secret を外す方式(封印 memfd。#2628)は `InjectedContent` の doc を参照。
//!   CLI から supervisor への受け渡しは未結線
//! - bind・`/sys` の sysfs 以外の `mounts[]` の種類と config.json の `mounts[]` の tmpfs は `start` が拒否済みで、ここでは載せない

#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
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
#[cfg(target_os = "linux")]
use super::launch_options::{LaunchIpcMode, LaunchOptions};
#[cfg(target_os = "linux")]
use super::resources::LinuxResourceLimits;
#[cfg(target_os = "linux")]
use super::sysfs_mount::SysfsMountSpec;
use crate::audit_log::AuditSink;
#[cfg(target_os = "linux")]
use crate::audit_log::AuditedRejection;
#[cfg(target_os = "linux")]
use crate::cgroups::{CgroupError, CgroupJoin, RecordedCgroupOutcome};
#[cfg(target_os = "linux")]
use crate::dev_mounts::ImplicitDevMounts;
#[cfg(target_os = "linux")]
use crate::exec::{
    ChildStdio, ChildSubreaper, ConfigPaths, ContainerChild, Entrypoint, ExecError, Hostname,
    IntermediatePlan, IntermediateSpec, IsolationConfig, IsolationPrivilege, IsolationStage,
    LaunchAudit, LaunchTag, Namespace, NamespaceSet, PrePivotSetup, PreparedLaunchFailure, Rescan,
    StageKind, StagePipeline, plan, plan_rootless_subordinate, rescan_unreported_init,
    spawn_container_via_intermediate,
};
#[cfg(target_os = "linux")]
use crate::injected_files::InjectedFileSet;
#[cfg(target_os = "linux")]
use crate::landlock::LandlockRuleset;
#[cfg(target_os = "linux")]
use crate::launch_isolation::RootIdentity;
#[cfg(target_os = "linux")]
use crate::rootless::{
    DEFAULT_HELPER_TIMEOUT, HelperPaths, IdMapSet, IdMapWriter, SubIdOwner, load_subordinate_ids,
    rootless_mapping,
};
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
    exit_audit_sink: Option<Arc<dyn AuditSink>>,
    #[cfg(target_os = "linux")]
    rejection_audit_sink: Option<Arc<dyn AuditSink>>,
    #[cfg(target_os = "linux")]
    cgroup_join_source: Option<JoinSource>,
    #[cfg(target_os = "linux")]
    subordinate_ids: Option<SubordinateIdSource>,
    #[cfg(target_os = "linux")]
    applied_resources: Option<LinuxResourceLimits>,
    #[cfg(target_os = "linux")]
    launch_options: Option<LaunchOptions>,
    #[cfg(target_os = "linux")]
    seccomp_delivery: crate::seccomp::ErrnoDelivery,
    #[cfg(target_os = "linux")]
    audit_policy: crate::audit_log::AuditCoveragePolicy,
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
    /// 分離の権限モデル。`RootlessSingleId` と `RootlessSubordinateIds`(要 [`Self::subordinate_ids`])を扱い、
    /// `RootfulHostRoot` は launch が `Unimplemented` で拒否する(モジュール doc。許すかは #2241 で判断待ち)。
    #[must_use]
    pub fn privilege(mut self, privilege: IsolationPrivilege) -> Self {
        self.privilege = Some(privilege);
        self
    }

    /// `RootlessSubordinateIds` の写像の入力元(subuid / subgid と helper)。`RootlessSubordinateIds` では必須、
    /// それ以外の権限モデルで渡すと `build` が拒否する(取り違えを黙って無視しない。CORE-6・SEC-5・#2009)。
    #[must_use]
    pub fn subordinate_ids(mut self, source: SubordinateIdSource) -> Self {
        self.subordinate_ids = Some(source);
        self
    }

    /// pivot 前段の違反を記録する監査 sink(SEC-4)。core は自分では作らず、呼び出し側が渡す。
    #[must_use]
    pub fn audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// 回収点(`ContainerChildProcess::wait` / `terminate`)が出す補助の `exit_signal` 監査(SIGSYS 終了。#2004)だけの
    /// 記録先(任意。SEC-4・ESC-06・#2236)。未指定なら [`Self::audit_sink`] を使う。
    ///
    /// 回収点は supervisor の監視スレッドなど複数スレッドのプロセスから呼ばれ、`FileAuditSink` の fork 隔離が使えない
    /// (rootless では代替経路も失敗する)。supervisor は単一スレッドの間に作った `ControlAuditRelay` をここへ渡す。
    /// launch の時点の記録(監査網羅の縮退・pre-pivot の違反)は単一スレッドで出るため `audit_sink` のままで、
    /// relay は閉じた表の理由つきの `Mount` しか運べず（それ以外の理由つきは `InvalidArgument`）、`audit_sink` 全体の差し替えには使わない。
    /// start の検証(bind・sysfs)の拒否の記録先は [`Self::rejection_audit_sink`]。
    #[must_use]
    pub fn exit_audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.exit_audit_sink = Some(sink);
        self
    }

    /// start の設定検証(`claim_start` の bind mount の元・sysfs の拒否)が出す mount 層の拒否だけの記録先
    /// (任意。SEC-4・#2481)。未指定なら [`Self::audit_sink`] を使う。
    ///
    /// この検証は start の作業スレッド(入口スレッドが待つ間のため複数スレッド)で走り、`FileAuditSink` の fork 隔離が
    /// 使えない(rootless では代替経路も失敗して拒否が残らない)。supervisor は単一スレッドの間に作った
    /// `ControlAuditRelay`(理由なしの `Mount` と、rootfs の固定の違反の閉じた表の理由つき `Mount`〔#2623〕を運べる)をここへ渡す。launch の時点の記録(監査網羅の縮退・
    /// pre-pivot の違反)は単一スレッドで出るので `audit_sink` のまま。
    #[must_use]
    pub fn rejection_audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.rejection_audit_sink = Some(sink);
        self
    }

    /// start の cgroup 連鎖(手順 5)で制限ファイルへ書いた `linux.resources` の値(#2019・CORE-3・SEC-1)。
    ///
    /// launch は fork の前に `spec.config()` の `linux.resources` とこの値の一致を確かめ、食い違えば
    /// `FailedPrecondition` で拒否する(手順 5 と手順 8 の間に `config.json` が書き換えられても、書いた値と違う
    /// 制限のまま起動しない)。`linux.resources` が無い config では渡さない(`None` どうしが一致)。
    #[must_use]
    pub fn applied_resource_limits(mut self, applied: Option<LinuxResourceLimits>) -> Self {
        self.applied_resources = applied;
        self
    }

    /// 起動オプション(`--ipc`・`--shm-size`・`--tmpfs`・secrets / configs。SUP-12・CORE-5・#2625)。
    ///
    /// 呼び出し元は supervisor の start 経路(`ContainerOptions::launch_options` の結果)。launcher は launch のたびに
    /// (restart の再 launch を含む)同じ指定を使う。未指定なら既定の `/dev/shm`(64 MiB)1 件・注入なし・
    /// 専用の IPC namespace で、従来の動作と同じ。`LaunchIpcMode::Host` だけが IPC namespace を外す緩和で、
    /// `config.json` からは外せない(SEC-1)。
    #[must_use]
    pub fn launch_options(mut self, options: LaunchOptions) -> Self {
        self.launch_options = Some(options);
        self
    }

    /// ERRNO 側の拒否の届け方(SEC-4・#2025)。既定は [`crate::seccomp::ErrnoDelivery::Errno`](通知なし。listener を
    /// 受け取っても応答者がいなくてよい)。`UserNotif` は **launch で得た listener に応答する者がいる呼び出し元だけ**が
    /// 指定する(supervisor の start 経路が `LaunchedProcess::take_seccomp_listener` で受け取って応答する)。
    /// 応答者がいないまま指定すると、拒否対象の syscall が listener を閉じるまで止まる(閉じれば `ENOSYS`)。
    /// 既存の exec 経路(`exec/reapply.rs`)と送り手の無い経路は常に ERRNO のまま(exec の本番経路は #2544 で `UserNotif` を指定し、応答するのは exec の親)。
    #[must_use]
    pub fn seccomp_errno_delivery(mut self, delivery: crate::seccomp::ErrnoDelivery) -> Self {
        self.seccomp_delivery = delivery;
        self
    }

    /// 監査の網羅を満たせない環境(カーネル監査頼みの層の縮退)への方針(SEC-4・#2027)。既定は
    /// [`crate::audit_log::AuditCoveragePolicy::BestEffort`](警告して起動を続け、縮退を `launchIsolation` と監査記録に残す)。
    /// `Strict` は縮退(調べられなかった場合を含む)を fork の前に `FailedPrecondition` で拒否する(opt-in)。
    #[must_use]
    pub fn audit_coverage_policy(mut self, policy: crate::audit_log::AuditCoveragePolicy) -> Self {
        self.audit_policy = policy;
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
            // 写像の解決と検証・注入との併用の拒否は subreaper 化(プロセス属性の変更)より前に行い、
            // 拒否で副作用を残さない(失敗した build の後に孤児を回収し続けない)。
            if let Some(options) = &self.launch_options {
                refuse_inject_with_subordinate(privilege, options)?;
            }
            let subordinate = resolve_privilege(
                privilege,
                self.subordinate_ids,
                crate::sys::effective_uid(),
                crate::sys::effective_gid(),
            )?;
            let subreaper = ChildSubreaper::enable().map_err(|e| {
                TraitError::new(
                    e.code,
                    "failed to become a child subreaper for the launcher",
                )
            })?;
            let mut inner = Inner::new(
                Box::new(RealOps { subreaper }),
                privilege,
                subordinate,
                audit_sink,
                self.cgroup_join_source,
            );
            inner.applied_resources = self.applied_resources;
            inner.launch_options = self.launch_options;
            inner.seccomp_delivery = self.seccomp_delivery;
            inner.audit_policy = self.audit_policy;
            inner.exit_audit_sink = self.exit_audit_sink;
            inner.rejection_audit_sink = self.rejection_audit_sink;
            Ok(ProductionLauncher { inner })
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

/// 利用者指定の tmpfs と注入ディレクトリ(いずれも pivot 前段で載せる tmpfs)が、config の
/// `linux.readonlyPaths` の厳密な子孫のとき拒否する(fail-closed。SEC-2・CORE-5・#2625)。
///
/// `apply_readonly_paths` は readonlyPaths のマウント上端だけを読み取り専用にし、子マウント（`/sys` を除く）は
/// 検査しないため、`readonlyPaths=["/data"]` の配下に書き込み可能な tmpfs `/data/cache` を置くと書き込み可能のまま残る。
/// 同一の宛先は上端が読み取り専用になるため対象外。fork 前に呼び、子を作らず拒否する。
#[cfg(target_os = "linux")]
fn check_tmpfs_against_readonly_paths(
    readonly: &[crate::path_masks::ProtectedPath],
    tmpfs: &TmpfsMountSet,
    inject: Option<&InjectedFileSet>,
) -> Result<(), TraitError> {
    use crate::injected_files::within;
    let inside = |dest: &str| readonly.iter().any(|r| within(dest, r.as_str()));
    let tmpfs_hit = tmpfs
        .mounts()
        .iter()
        .any(|t| inside(t.destination.as_str()));
    let inject_hit = inject.is_some_and(|i| i.groups().iter().any(|g| inside(g.directory)));
    if tmpfs_hit || inject_hit {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "a tmpfs mount or injected file directory lies under a read-only path",
        ));
    }
    Ok(())
}

/// 範囲写像(`RootlessSubordinateIds`)と、呼び出し元のメモリにある注入内容の併用を拒否する(fail-closed)。
///
/// 範囲写像の ID 写像 holder は中間プロセスのメモリを fork で継承し、`run_userns_holder` で dumpable になるため、
/// Yama=0 では同一 UID の別プロセスから継承したメモリを読める。注入内容が封印 memfd
/// (`InjectedContent::from_file`)にあれば内容はユーザー空間のメモリに載らず holder も fd を持たないので通す。
/// `InjectedContent::from_bytes` の内容(呼び出し元のヒープに残る)だけを拒否する(#2628・SEC-1・SEC-5・CORE-6・
/// SUP-12。方式は `docs/design/rootless-id-map-holder.md`)。`build` と launch の両方で呼ぶ(builder の呼び出し順で迂回させない)。
#[cfg(target_os = "linux")]
fn refuse_inject_with_subordinate(
    privilege: IsolationPrivilege,
    options: &LaunchOptions,
) -> Result<(), TraitError> {
    if privilege == IsolationPrivilege::RootlessSubordinateIds
        && options
            .inject()
            .files()
            .iter()
            .any(|f| f.content().is_caller_memory())
    {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "injected file content held in process memory cannot be combined with the subordinate id privilege model",
        ));
    }
    Ok(())
}

/// `RootlessSubordinateIds` の写像の入力元(`/etc/subuid`・`/etc/subgid` と `newuidmap` / `newgidmap` のパス。
/// CORE-6・SEC-5・#2009)。
///
/// 呼び出し元は supervisor(結線済み。#2243。選ぶ条件と名前の取得は supervisor の start 経路)。パスはすべて絶対パスで、`PATH` は探索しない。所有者の名前は
/// 呼び出し側(supervisor の `id_model`)が `/etc/passwd`、無ければ NSS(`getent`)で解決して渡す(#2390。
/// ライブラリは `$USER` を読まず NSS も使わない)。一般的な
/// `/etc/subuid` はユーザー名で書かれるため、名前を渡さないと数値の uid の行しか一致しない。
/// 範囲の読み取りと helper の検証は [`ProductionLauncherBuilder::build`] が行う。
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct SubordinateIdSource {
    owner_name: Option<String>,
    subuid: PathBuf,
    subgid: PathBuf,
    newuidmap: PathBuf,
    newgidmap: PathBuf,
    helper_timeout: Duration,
}

#[cfg(target_os = "linux")]
impl SubordinateIdSource {
    /// 既定の位置(`/etc/subuid`・`/etc/subgid`・`/usr/bin/newuidmap`・`/usr/bin/newgidmap`・
    /// `DEFAULT_HELPER_TIMEOUT`)を使う。`owner_name` は `/etc/subuid` の第 1 フィールドと照合する起動ユーザー名。
    pub fn system(owner_name: Option<String>) -> Result<Self, TraitError> {
        Self::with_paths(
            owner_name,
            Path::new("/etc/subuid"),
            Path::new("/etc/subgid"),
            Path::new("/usr/bin/newuidmap"),
            Path::new("/usr/bin/newgidmap"),
            DEFAULT_HELPER_TIMEOUT,
        )
    }

    /// 範囲写像の解決(`resolve_id_maps`)だけに使う入力元を、subuid / subgid のパスだけ指定して作る。
    ///
    /// helper のパスとタイムアウトは既定のまま。呼び出し元は supervisor の `id_model`(start と pull の展開が同じ
    /// 解決を共有する。#2389・SEC-5・CORE-6)と試験。パスの検証は `with_paths` と同じ。
    pub fn with_id_files(
        owner_name: Option<String>,
        subuid: &Path,
        subgid: &Path,
    ) -> Result<Self, TraitError> {
        Self::with_paths(
            owner_name,
            subuid,
            subgid,
            Path::new("/usr/bin/newuidmap"),
            Path::new("/usr/bin/newgidmap"),
            DEFAULT_HELPER_TIMEOUT,
        )
    }

    /// 起動する利用者の `uid` / `gid` について、範囲写像(コンテナ 0 → 自 ID、1.. → subordinate 範囲)を組み立てる。
    ///
    /// start の本番 launcher(`resolve_privilege`)と、pull 時の展開の所有者(cli の `image_ownership`。
    /// `ChownMapped` / `ChownInUserNamespace` に渡す写像。#2389)が同じこの関数を呼ぶ。所有者の解決を
    /// 別々に持たないための唯一の入口で、副作用は無い(helper の検証は含まない)。
    ///
    /// 拒否: `uid` / `gid` が 0(`PermissionDenied`。SEC-5)、範囲が 0 件(`FailedPrecondition`。単一 ID へ
    /// 黙って縮退しない)、ホスト ID 0 を含む範囲(`PermissionDenied`)、読み取り・解析の失敗。
    /// 文言は固定の英語で、パス・errno・ユーザー名を含めない。
    pub fn resolve_id_maps(&self, uid: u32, gid: u32) -> Result<SubordinateIdMaps, TraitError> {
        let fail = |code: ErrorCode| {
            TraitError::new(
                code,
                "failed to resolve the subordinate id mapping for the launcher",
            )
        };
        if uid == 0 || gid == 0 {
            return Err(TraitError::new(
                ErrorCode::PermissionDenied,
                "refusing to map the host root identity",
            ));
        }
        let owner = SubIdOwner::new(uid, self.owner_name.clone()).map_err(|e| fail(e.code))?;
        let uid_ranges = load_subordinate_ids(&self.subuid, &owner).map_err(|e| fail(e.code))?;
        let gid_ranges = load_subordinate_ids(&self.subgid, &owner).map_err(|e| fail(e.code))?;
        if uid_ranges.is_empty() || gid_ranges.is_empty() {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "no subordinate id range is assigned to the launching user",
            ));
        }
        Ok(SubordinateIdMaps {
            uid: rootless_mapping(uid, &uid_ranges).map_err(|e| fail(e.code))?,
            gid: rootless_mapping(gid, &gid_ranges).map_err(|e| fail(e.code))?,
        })
    }

    /// 明示パスで作る(試験・別配置向け)。パスは絶対パスのみ、`helper_timeout` は 1..=60 秒、名前は
    /// `[A-Za-z0-9._-]`・32 文字以内。違反は `InvalidArgument`(副作用なし)。
    pub fn with_paths(
        owner_name: Option<String>,
        subuid: &Path,
        subgid: &Path,
        newuidmap: &Path,
        newgidmap: &Path,
        helper_timeout: Duration,
    ) -> Result<Self, TraitError> {
        let invalid = |what: &'static str| Err(TraitError::new(ErrorCode::InvalidArgument, what));
        if SubIdOwner::new(0, owner_name.clone()).is_err() {
            return invalid("the subordinate id owner name is invalid");
        }
        if ![subuid, subgid, newuidmap, newgidmap]
            .iter()
            .all(|p| p.is_absolute())
        {
            return invalid("the subordinate id source paths must be absolute");
        }
        if helper_timeout < Duration::from_secs(1) || helper_timeout > Duration::from_secs(60) {
            return invalid("the id map helper timeout must be within 1..=60 seconds");
        }
        Ok(Self {
            owner_name,
            subuid: subuid.to_path_buf(),
            subgid: subgid.to_path_buf(),
            newuidmap: newuidmap.to_path_buf(),
            newgidmap: newgidmap.to_path_buf(),
            helper_timeout,
        })
    }
}

/// `SubordinateIdSource::resolve_id_maps` の結果(uid 側と gid 側の写像)。
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct SubordinateIdMaps {
    uid: IdMapSet,
    gid: IdMapSet,
}

#[cfg(target_os = "linux")]
impl SubordinateIdMaps {
    /// uid の写像。
    pub fn uid(&self) -> &IdMapSet {
        &self.uid
    }

    /// gid の写像。
    pub fn gid(&self) -> &IdMapSet {
        &self.gid
    }
}

/// subuid 所有の rootfs の木を userns の中で消すための入力(`SubordinateIdSource::removal_inputs`。#2540)。
#[cfg(target_os = "linux")]
pub(super) struct RemovalInputs {
    /// uid の範囲写像(コンテナ 0 → 自 euid、1.. → subordinate 範囲)。
    pub(super) uid: IdMapSet,
    /// gid の範囲写像。
    pub(super) gid: IdMapSet,
    /// 写像の書き込み経路(`newuidmap` / `newgidmap`)。
    pub(super) writer: IdMapWriter,
    /// helper の応答の期限。
    pub(super) timeout: Duration,
}

#[cfg(target_os = "linux")]
impl SubordinateIdSource {
    /// image rootfs の削除(userns の中で subuid 所有の木を消す。`oci_runtime::image_rootfs`。SEC-5・#2540)に
    /// 使う写像・書き込み経路・期限を解決する。副作用は無い。start の本番 launcher と同じ解決
    /// ([`Self::resolve_id_maps`]・`HelperPaths::new`)を共有し、所有者の解決を別々に持たない。
    ///
    /// 拒否の分類と文言は [`Self::resolve_id_maps`] と同じ(パス・errno・ユーザー名を含めない)。
    pub(super) fn removal_inputs(&self, euid: u32, egid: u32) -> Result<RemovalInputs, TraitError> {
        let maps = self.resolve_id_maps(euid, egid)?;
        let helper = HelperPaths::new(&self.newuidmap, &self.newgidmap).map_err(|e| {
            TraitError::new(
                e.code,
                "failed to resolve the subordinate id mapping for the launcher",
            )
        })?;
        Ok(RemovalInputs {
            uid: maps.uid,
            gid: maps.gid,
            writer: IdMapWriter::Helper(helper),
            timeout: self.helper_timeout,
        })
    }
}

/// 構築時に解決・検証済みの範囲写像(`Inner` が保持し、起動のたびに `plan_rootless_subordinate` へ渡す)。
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct SubordinateIds {
    uid: IdMapSet,
    gid: IdMapSet,
    writer: IdMapWriter,
    timeout: Duration,
}

/// 権限モデルと写像の入力元の整合を検査し、`RootlessSubordinateIds` なら写像を解決する(副作用なし。
/// `build` が subreaper 化の前に呼ぶ。`euid` / `egid` を引数に取りテスト可能にした純関数)。
///
/// 拒否: 入力元が無い・不要な権限モデルで渡された(`InvalidArgument`)、euid / egid が 0(`PermissionDenied`。
/// SEC-5)、範囲が 0 件(`FailedPrecondition`。単一 ID へ黙って縮退しない)、ホスト ID 0 を含む範囲
/// (`PermissionDenied`。`IdMapSet::new`)、subuid / subgid の読み取り・解析の失敗、helper の検証の失敗。
/// 文言は固定の英語で、パス・errno・ユーザー名を含めない。
#[cfg(target_os = "linux")]
fn resolve_privilege(
    privilege: IsolationPrivilege,
    source: Option<SubordinateIdSource>,
    euid: u32,
    egid: u32,
) -> Result<Option<SubordinateIds>, TraitError> {
    let fail = |code: ErrorCode| {
        TraitError::new(
            code,
            "failed to resolve the subordinate id mapping for the launcher",
        )
    };
    match (privilege, source) {
        (IsolationPrivilege::RootlessSubordinateIds, Some(source)) => {
            // 範囲の読み取りと写像の組み立ては pull 時の展開と共有する(#2389)。
            let SubordinateIdMaps { uid, gid } = source.resolve_id_maps(euid, egid)?;
            let helper =
                HelperPaths::new(&source.newuidmap, &source.newgidmap).map_err(|e| fail(e.code))?;
            Ok(Some(SubordinateIds {
                uid,
                gid,
                writer: IdMapWriter::Helper(helper),
                timeout: source.helper_timeout,
            }))
        }
        (IsolationPrivilege::RootlessSubordinateIds, None) => Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "the subordinate id privilege model requires a subordinate id source",
        )),
        (_, Some(_)) => Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "a subordinate id source is only valid for the subordinate id privilege model",
        )),
        (_, None) => Ok(None),
    }
}

impl ProcessLauncher for ProductionLauncher {
    /// fork は単一スレッドの呼び出しを要求するため、start は呼び出しスレッドで直接 `launch` を呼ぶ(REPAIR-5)。
    fn launch_mode(&self) -> LaunchMode {
        LaunchMode::SelfBounded
    }

    /// start が設定の検証で拒否したときの記録先を貸す(SEC-4・#1915)。`rejection_audit_sink` の指定があればそれ、
    /// 無ければ launcher の監査 sink(#2481)。
    fn rejection_audit_sink(&self) -> Option<&dyn AuditSink> {
        #[cfg(target_os = "linux")]
        {
            Some(
                self.inner
                    .rejection_audit_sink
                    .as_ref()
                    .unwrap_or(&self.inner.audit_sink)
                    .as_ref(),
            )
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

#[cfg(target_os = "linux")]
use crate::audit_log::AUDIT_COVERAGE_RECORD_FAILED_LINE;

/// 起動の実体(fork・Landlock の検出・スレッド数の観測)を差し替えられる継ぎ目(単体テストが順序と拒否を
/// フォーク無し・ABI 非依存で照合できるようにする)。本番の実装は [`RealOps`]。
#[cfg(target_os = "linux")]
trait LaunchOps: Send + Sync {
    /// 呼び出しプロセスのスレッドが 1 つか(fork の前提)。
    fn is_single_threaded(&self) -> bool;
    /// `config` から Landlock の ruleset を作る(ABI 検出を含む。6 未満は拒否)。
    ///
    /// `user_tmpfs` は利用者指定の tmpfs(暗黙の `/dev/shm` を除く。`mounts[]` とは別枠で `RuleOrigin::UserTmpfs` になる)。
    /// `implicit` は暗黙の `/dev` 系マウントのルールの含め方(起動オプションの tmpfs 集合から導く。SUP-12・#2625)。
    fn landlock_ruleset(
        &self,
        config: &super::config::OciConfig,
        user_tmpfs: &[super::config::OciMount],
        implicit: ImplicitDevMounts,
    ) -> Result<LandlockRuleset, ExecError>;
    /// pin 済みの rootfs の `(st_dev, st_ino)`（launch 時の分離の記録の `/`。fstat できなければ `None`。
    /// SUP-6・#2007）。
    fn root_identity(&self, rootfs: &super::launch::RootfsDir) -> Option<RootIdentity>;
    /// 起動ユーザーの実効 `(uid, gid)`(単一 ID 写像のホスト側 ID。分離の記録の `idMapping` の元。CORE-6・#2388)。
    fn effective_ids(&self) -> (u32, u32);
    /// カーネル監査まわりの観測値(procfs。読めない項目は `None`。SEC-4・#2027)。
    fn kernel_audit_probe(&self) -> crate::audit_log::KernelAuditProbe;
    /// 縮退の警告 1 行(構造化ログ。固定語彙のみ)を出す。launch の単一スレッド要求のため `log_event` 系は使えない。
    fn emit_warning(&self, line: &str);
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
    /// pivot 前段で載せる tmpfs(既定の `/dev/shm` か起動オプション由来の集合)。launcher が fork 前に確定し、
    /// bind との重なりも検査済み。
    tmpfs: &'a TmpfsMountSet,
    /// 注入するファイル(secrets / configs。空なら `None`。SUP-12・#2625)。bind との重なりは検査済み。
    inject: Option<&'a InjectedFileSet>,
    /// 適用する bind mount の集合(空なら `None`。#1915)。
    binds: Option<&'a BindMountSet>,
    /// 供給する `/sys` の sysfs(無ければ `None`。#2020)。
    sysfs: Option<&'a SysfsMountSpec>,
    /// 範囲写像で起動するときの解決済み写像(`None` なら単一 ID 写像。CORE-6・#2009)。
    subordinate: Option<&'a SubordinateIds>,
}

/// 起動した PID 1 と、stdout / stderr の読み取り側。
#[cfg(target_os = "linux")]
struct Spawned {
    child: ContainerChild,
    stdout: std::io::PipeReader,
    stderr: std::io::PipeReader,
    /// PID 1 から受け取った seccomp の listener(SEC-4・#2024)。本番の入口は必ず `Some`。偽の launcher は `None`。
    listener: Option<crate::exec::SeccompListener>,
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

/// `process.user` の (uid, gid) が user namespace の写像に含まれることを fork の前に確かめる(純関数。副作用なし。
/// OCI-1・SEC-5)。
///
/// 写像の外の id で `setresuid` すると子で `EINVAL` になり構造化されないため、ここで `FailedPrecondition` の
/// 固定文言にする。`RootlessSingleId` は 0 だけが写る(0/0 以外は拒否)。`RootlessSubordinateIds` は
/// `ranges`(uid の写像, gid の写像)が対象の id を含む場合だけ許す。`RootfulHostRoot` は launcher が別途拒否する。
#[cfg(target_os = "linux")]
fn check_user_mapped(
    privilege: IsolationPrivilege,
    ranges: Option<(&IdMapSet, &IdMapSet)>,
    (uid, gid): (u32, u32),
) -> Result<(), TraitError> {
    let mapped = match (privilege, ranges) {
        (IsolationPrivilege::RootlessSubordinateIds, Some((u, g))) => {
            u.host_id_of(uid).is_some() && g.host_id_of(gid).is_some()
        }
        _ => uid == 0 && gid == 0,
    };
    if mapped {
        Ok(())
    } else {
        Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "process.user is not mapped in the user namespace (SEC-5)",
        ))
    }
}

/// launch が使う ID 写像の記録を作る(純関数。副作用なし。CORE-6・SEC-5・REPAIR-4・#2388)。
///
/// `RootlessSubordinateIds` は構築時に解決済みの uid / gid 写像、`RootlessSingleId` は起動ユーザーの実効 ID を
/// コンテナ内 0 の 1 件へ写す写像(spawn の計画と同じ内容)。ホスト ID 0 の単一 ID は spawn の計画と同じ code・
/// 文言で拒否する(fail-closed)。範囲写像で `subordinate` が無い・`RootfulHostRoot` は `check_privilege` が先に拒否する
/// ため、ここへ来たら内部不整合として拒否する。
#[cfg(target_os = "linux")]
fn recorded_id_mapping(
    privilege: IsolationPrivilege,
    subordinate: Option<&SubordinateIds>,
    euid: u32,
    egid: u32,
) -> Result<crate::launch_isolation::RecordedIdMapping, TraitError> {
    use crate::launch_isolation::{
        RecordedIdExtent, RecordedIdMapping, RecordedIdModel, id_extents_of,
    };
    let refuse = |_| {
        TraitError::new(
            ErrorCode::PermissionDenied,
            "refusing to map the host root identity",
        )
    };
    let (model, uid, gid) = match (privilege, subordinate) {
        (IsolationPrivilege::RootlessSingleId, _) => {
            let one = |host_id| {
                vec![RecordedIdExtent {
                    container_id: 0,
                    host_id,
                    size: 1,
                }]
            };
            (RecordedIdModel::Single, one(euid), one(egid))
        }
        (IsolationPrivilege::RootlessSubordinateIds, Some(ids)) => (
            RecordedIdModel::Subordinate,
            id_extents_of(&ids.uid),
            id_extents_of(&ids.gid),
        ),
        _ => {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "the id mapping cannot be recorded for the privilege model",
            ));
        }
    };
    RecordedIdMapping::new(model, uid, gid).map_err(refuse)
}

/// Linux の launcher 本体(拒否の判定・順序・写像・起動台帳)。
#[cfg(target_os = "linux")]
struct Inner {
    ops: Box<dyn LaunchOps>,
    privilege: IsolationPrivilege,
    /// `RootlessSubordinateIds` のときだけ `Some`(`resolve_privilege` が保証する)。
    subordinate: Option<SubordinateIds>,
    audit_sink: Arc<dyn AuditSink>,
    /// 回収点の `exit_signal` 監査だけの記録先(`ProductionLauncherBuilder::exit_audit_sink`。#2236)。`None` なら `audit_sink`。
    exit_audit_sink: Option<Arc<dyn AuditSink>>,
    /// start の検証(bind・sysfs)の拒否だけの記録先(`ProductionLauncherBuilder::rejection_audit_sink`。#2481)。`None` なら `audit_sink`。
    rejection_audit_sink: Option<Arc<dyn AuditSink>>,
    cgroup_join_source: Option<JoinSource>,
    /// cgroup 連鎖で書いた `linux.resources`(`ProductionLauncherBuilder::applied_resource_limits`)。
    applied_resources: Option<LinuxResourceLimits>,
    /// 起動オプション(`ProductionLauncherBuilder::launch_options`。`None` は従来どおりの既定。SUP-12・#2625)。
    launch_options: Option<LaunchOptions>,
    /// ERRNO 側の拒否の届け方(`ProductionLauncherBuilder::seccomp_errno_delivery`。既定 `Errno`。SEC-4・#2025)。
    seccomp_delivery: crate::seccomp::ErrnoDelivery,
    /// 監査の網羅を満たせない環境への方針(`ProductionLauncherBuilder::audit_coverage_policy`。既定 `BestEffort`。SEC-4・#2027)。
    audit_policy: crate::audit_log::AuditCoveragePolicy,
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
        subordinate: Option<SubordinateIds>,
        audit_sink: Arc<dyn AuditSink>,
        cgroup_join_source: Option<JoinSource>,
    ) -> Self {
        Self {
            ops,
            privilege,
            subordinate,
            audit_sink,
            exit_audit_sink: None,
            rejection_audit_sink: None,
            cgroup_join_source,
            applied_resources: None,
            launch_options: None,
            seccomp_delivery: crate::seccomp::ErrnoDelivery::Errno,
            audit_policy: crate::audit_log::AuditCoveragePolicy::BestEffort,
            ledger: Arc::new(Mutex::new(Ledger::default())),
            next_generation: std::sync::atomic::AtomicU64::new(0),
            left_process: AtomicBool::new(false),
        }
    }

    /// 回収点の `exit_signal` 監査の記録先。指定が無ければ launcher の `audit_sink`（#2236）。
    fn exit_audit_sink(&self) -> Arc<dyn AuditSink> {
        Arc::clone(self.exit_audit_sink.as_ref().unwrap_or(&self.audit_sink))
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
        check_user_mapped(
            self.privilege,
            self.subordinate.as_ref().map(|s| (&s.uid, &s.gid)),
            spec.user(),
        )?;
        let means = if self.cgroup_join_source.is_some() {
            CgroupJoinMeans::Provided
        } else {
            CgroupJoinMeans::Absent
        };
        launch_after_cgroup_check(spec.cgroup_requirement(), means, || {
            self.check_applied_resources(spec)?;
            self.launch_checked(spec, timeout)
        })
    }

    /// 制限ファイルへ書いた `linux.resources` と、これから起動する `spec` の config の値の一致を確かめる
    /// (fork の前。#2019・CORE-3・SEC-1)。片方だけ指定がある場合も不一致として拒否する。
    /// メッセージは固定文言で、値を含めない(ERR-1)。
    fn check_applied_resources(&self, spec: &LaunchSpec) -> Result<(), TraitError> {
        if spec.config().linux_resources() == self.applied_resources.as_ref() {
            return Ok(());
        }
        Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "the cgroup limits applied before start do not match config.json",
        ))
    }

    /// 権限モデルの検査。未対応のモデルは fork より前に拒否する(権限を黙って広げない。SEC-5)。
    fn check_privilege(&self) -> Result<(), TraitError> {
        match self.privilege {
            IsolationPrivilege::RootlessSingleId => Ok(()),
            // 写像は構築時に解決済み。無ければ構築の不整合として拒否する(fail-closed)。
            IsolationPrivilege::RootlessSubordinateIds if self.subordinate.is_some() => Ok(()),
            IsolationPrivilege::RootfulHostRoot => Err(TraitError::new(
                ErrorCode::Unimplemented,
                "the rootful privilege model is not supported by the launcher",
            )),
            IsolationPrivilege::RootlessSubordinateIds => Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "the subordinate id privilege model requires a subordinate id source",
            )),
        }
    }

    fn launch_checked(
        &self,
        spec: &LaunchSpec,
        timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        // 期限は入口で 1 回だけ取り、以降のすべての待ち(再回収・監査配送・spawn)をここから導く(REPAIR-5・SEC-4)。
        // 上限なしの `Instant + Duration` は `Duration::MAX` 等で panic するため、確認系と同じ上限で丸めて `checked_add` する。
        let deadline = Instant::now()
            .checked_add(timeout.min(CONFIRM_TIMEOUT_MAX))
            .ok_or_else(|| {
                TraitError::new(ErrorCode::InvalidArgument, "launch timeout is out of range")
            })?;
        let id = spec.container_id();
        self.admit(id)?;
        if !self.ops.is_single_threaded() {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "launch requires a single-threaded process",
            ));
        }
        // 起動オプション(未指定なら既定の `/dev/shm` 1 件・注入なし・専用 IPC)。暗黙の `/dev` 系の Landlock ルールは
        // 実際に載せる tmpfs 集合から導き、実マウントとの食い違いを作らない(SUP-12・CORE-5・#2625)。
        let default_options;
        let options = match &self.launch_options {
            Some(options) => options,
            None => {
                default_options = LaunchOptions::try_default()?;
                &default_options
            }
        };
        // 範囲写像の holder は fork でメモリを継承し dumpable になるため、呼び出し元のメモリにある注入内容は拒否する(#2628)。
        refuse_inject_with_subordinate(self.privilege, options)?;
        // Landlock は必須。ABI 不足・生成失敗は起動を拒否し、Landlock 無しで続けない(CORE-5・#1314)。
        // 利用者指定の tmpfs(暗黙の `/dev/shm` を除く)は `mounts[]` とは別枠で Landlock のルールにも載せる。載せないと
        // 読み取り専用 root 配下の `--tmpfs /run` が EACCES になる。`ro` の tmpfs はルール生成側が除外する
        // (SUP-12・#2625)。
        let user_tmpfs: Vec<super::config::OciMount> = options
            .tmpfs()
            .mounts()
            .iter()
            .filter(|m| m.destination.as_str() != crate::tmpfs::DEV_SHM_PATH)
            .map(super::config::OciMount::from_user_tmpfs)
            .collect();
        let ruleset = self
            .ops
            .landlock_ruleset(spec.config(), &user_tmpfs, options.implicit_dev_mounts())
            .map_err(|e| to_trait_error(&e))?;
        // 分離の記録は `with_landlock` へ渡す ruleset そのものと pin 済み rootfs の fstat から、fork の前に作る
        // (入力を 1 つに保つ。作れなければ子を作らず拒否する。fail-closed。SUP-6・CORE-5・SEC-1・#2007)。
        let isolation_record = crate::exec::launch_isolation_from_ruleset(
            &ruleset,
            self.ops.root_identity(spec.rootfs_dir()),
        )
        .map_err(|e| to_trait_error(&e))?;
        // 監査の網羅(カーネル監査頼みの層)を評価し、厳格モードの縮退は子を作る前に拒否する(SEC-4・#2027)。
        let isolation_record = self.assess_audit_coverage(id, isolation_record, deadline)?;
        // 実際に使う ID 写像のモデルと範囲を記録へ添える(inspect の `idMapping`。観測専用。作れなければ fork 前に拒否。
        // CORE-6・SEC-5・REPAIR-4・#2388)。
        let (euid, egid) = self.ops.effective_ids();
        let isolation_record = isolation_record.with_id_mapping(recorded_id_mapping(
            self.privilege,
            self.subordinate.as_ref(),
            euid,
            egid,
        )?);
        // `process.capabilities` の drop を解釈した許可集合（OCI 既定の部分集合）。launch の削減段へ渡し、同じ値を
        // 分離の記録へ添えて exec の再適用が launch より広い集合を与えないようにする(SEC-1・CRI-2・#2666)。
        let capabilities = spec.config().capabilities();
        let isolation_record = isolation_record.with_capabilities(capabilities);
        let (uid, gid) = spec.user();
        let mut stages = StagePipeline::new()
            .with_seccomp_delivery(self.seccomp_delivery)
            .with_process_ids(uid, gid)
            .with_capabilities(capabilities)
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
        let isolation = isolation_config_of(spec, options.ipc())?;
        // tmpfs と注入を fork 前に確定し、bind の宛先との重なりをここで検査する(三者の集合が揃う場所。
        // 子の `run_pre_pivot` の検査は多重防御として残す。CORE-5・SUP-12・#1654・#1915・#2625)。
        let tmpfs = options.tmpfs();
        let inject = (!options.inject().is_empty()).then(|| options.inject());
        let binds = (!spec.bind_mounts().is_empty()).then(|| spec.bind_mounts());
        check_tmpfs_against_readonly_paths(spec.config().readonly_paths(), tmpfs, inject)?;
        if let Some(binds) = binds
            && let Err(err) = binds
                .check_against_tmpfs(tmpfs)
                .and_then(|()| match inject {
                    Some(inject) => binds.check_against_injected(inject),
                    None => Ok(()),
                })
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
        // 入口の期限までの残りを spawn に渡す。尽きていれば子を作らず拒否する(fail-closed)。
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "container launch did not complete within the timeout",
            ));
        }
        let spawned = self
            .ops
            .spawn(SpawnInput {
                isolation,
                spec,
                entry: &entry,
                stages,
                audit,
                timeout,
                tmpfs,
                inject,
                binds,
                sysfs: spec.sysfs_mount(),
                subordinate: self.subordinate.as_ref(),
            })
            .map_err(|failure| self.absorb_failure(id, *failure))?;
        let Spawned {
            child,
            stdout,
            stderr,
            listener,
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
            .with_seccomp_listener(listener)
            .with_launch_isolation(isolation_record)
            .with_exit_audit(self.exit_audit_sink(), id.clone())
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

    /// 監査の網羅を評価する(fork の前。SEC-4・#2027)。
    ///
    /// 1. 観測値と Landlock の記録から [`crate::audit_log::assess`] で 2 層を評価する
    /// 2. 厳格モードで縮退(不明を含む)なら `FailedPrecondition` で拒否する(副作用なし)
    /// 3. 縮退していれば警告 1 行と監査記録(層 `audit_coverage`)を 1 件出す。記録先へ書けなくても
    ///    既定のモードでは起動の可否を変えず、固定語彙の診断行だけを出す
    /// 4. 評価結果を分離の記録に添える(`state.json` の `launchIsolation` と inspect の元)
    fn assess_audit_coverage(
        &self,
        id: &ContainerId,
        record: crate::launch_isolation::LaunchIsolationRecord,
        deadline: Instant,
    ) -> Result<crate::launch_isolation::LaunchIsolationRecord, TraitError> {
        let coverage =
            crate::audit_log::assess(&self.ops.kernel_audit_probe(), record.landlock().audit());
        coverage.enforce(self.audit_policy)?;
        if let Some(line) = coverage.log_line() {
            self.ops.emit_warning(&line);
        }
        let mut record_failed = false;
        if let Some(event) = coverage.degraded_event() {
            // 同期配送の待ちも launch の入口の期限へ絞る。尽きたときは記録できなかった扱い(警告のみ)にし、
            // 続く spawn 直前の残り時間の確認で `Timeout` として拒否する(REPAIR-5・SEC-4)。
            let delivery = crate::audit_log::mount::deliver_until(
                event,
                Some(id),
                self.audit_sink.as_ref(),
                Some(deadline),
            );
            if !matches!(delivery, crate::audit_log::AuditDelivery::Recorded) {
                // fd 2 は socket 構成向けに残す。同じ事実を評価値にも載せ、supervisor が
                // `@supervisor-logs` へ出し直す(SEC-4・REPAIR-4・#2468)。
                self.ops.emit_warning(AUDIT_COVERAGE_RECORD_FAILED_LINE);
                record_failed = true;
            }
        }
        let record = record.with_audit_coverage(self.audit_policy, coverage);
        if record_failed {
            // 縮退を評価済みなので Err にはならない。万一でも起動の可否は変えず記録をそのまま返す。
            return Ok(record
                .clone()
                .with_audit_coverage_record_failed()
                .unwrap_or(record));
        }
        Ok(record)
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
    // `/` で始まれば絶対パス。`/` を含まない名前は pivot 後に `process.env` の `PATH` で解決する(OCI-1・#2314。
    // runtime-spec は `args[0]` を `execvp` の file と同じ意味とする)。`/` を含む相対パスは `PATH` を引かず、
    // pivot と cwd の適用後に cwd 起点で解決する(OCI-1・OCI-4・#2432。`..` は `cwd_relative` が拒否)。
    let built = if first.starts_with('/') {
        Entrypoint::new(first, spec.args(), spec.env())
    } else if first.contains('/') {
        Entrypoint::cwd_relative(first, spec.args(), spec.env())
    } else {
        Entrypoint::search_path(first, spec.args(), spec.env())
    };
    built.map_err(|e| to_trait_error(&e))
}

/// `LaunchSpec` の namespace・hostname から分離の設定を作る(`start` が検証済み。未対応の種別は拒否)。
#[cfg(target_os = "linux")]
fn isolation_config_of(
    spec: &LaunchSpec,
    ipc: LaunchIpcMode,
) -> Result<IsolationConfig, TraitError> {
    let mut namespaces = NamespaceSet::empty();
    for kind in spec.namespaces() {
        let ns = match kind {
            // `--ipc=host` のときだけ IPC namespace を作らない(config.json からは外せない。SEC-1・SUP-12・#2625)。
            NamespaceKind::Ipc if ipc == LaunchIpcMode::Host => continue,
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
        user_tmpfs: &[super::config::OciMount],
        implicit: ImplicitDevMounts,
    ) -> Result<LandlockRuleset, ExecError> {
        let ruleset =
            crate::exec::landlock_ruleset_from_config_with_dev(config, user_tmpfs, implicit)?;
        // ABI 7 未満ではカーネル監査へ拒否を残せない。縮退を構造化ログに出して続行する（SEC-4・#2026）。
        // 縮退の拒否(厳格モード)と 3 か所への表示は `Inner::assess_audit_coverage`（#2027）。送れなくても起動の可否は変えない。
        if let Some(line) = ruleset.audit_mode().log_line() {
            let _ = crate::exec::emit_diagnostic_line(&line);
        }
        Ok(ruleset)
    }

    fn root_identity(&self, rootfs: &super::launch::RootfsDir) -> Option<RootIdentity> {
        RootIdentity::of_dir_fd(rootfs.as_fd())
    }

    fn effective_ids(&self) -> (u32, u32) {
        (crate::sys::effective_uid(), crate::sys::effective_gid())
    }

    fn kernel_audit_probe(&self) -> crate::audit_log::KernelAuditProbe {
        crate::audit_log::KernelAuditProbe::read_host()
    }

    fn emit_warning(&self, line: &str) {
        // 送れなくても起動の可否は変えない(警告は縮退の表示であって判定ではない)。
        let _ = crate::exec::emit_diagnostic_line(line);
    }

    fn spawn(&self, input: SpawnInput<'_>) -> Result<Spawned, Box<PreparedLaunchFailure>> {
        let not_started = |e: ExecError| {
            Box::new(PreparedLaunchFailure::clean(
                AuditedRejection::not_applicable(e),
            ))
        };
        // euid 0 の写像は計画の段階で拒否される(`HostRootIdentityMapping`。SEC-5)。
        // 単一 ID は自 egid をコンテナ内 0 へ写す写像、範囲写像は解決済みの subuid / subgid 写像(CORE-6・#2009)。
        // どちらも devpts の gid= の決定元になる gid 写像を併せて得る。
        let single_plan;
        let single_gid;
        let subordinate_plan;
        let (isolation_plan, gid_map): (IntermediatePlan<'_>, &IdMapSet) = match input.subordinate {
            None => {
                single_plan = plan(&input.isolation).map_err(not_started)?;
                // 計画が euid / egid 0 を拒否した後に作る。
                single_gid = crate::rootless::single_id_mapping(crate::sys::effective_gid())
                    .map_err(|_| {
                        not_started(ExecError::new(
                            ErrorCode::PermissionDenied,
                            IsolationStage::UserNamespaceMap,
                            "refusing to map the host root identity",
                        ))
                    })?;
                (IntermediatePlan::SingleId(&single_plan), &single_gid)
            }
            Some(ids) => {
                subordinate_plan = plan_rootless_subordinate(
                    &input.isolation,
                    ids.uid.clone(),
                    ids.gid.clone(),
                    ids.writer.clone(),
                    ids.timeout,
                )
                .map_err(not_started)?;
                (
                    IntermediatePlan::Subordinate(&subordinate_plan),
                    subordinate_plan.gid_map(),
                )
            }
        };
        let (stdio, stdout, stderr) = ChildStdio::pipes().map_err(not_started)?;
        let setup = PrePivotSetup {
            devices: crate::exec::DevptsGidSource::Rootless(gid_map),
            tmpfs: Some(input.tmpfs),
            inject: input.inject,
            binds: input.binds,
            sysfs: input.sysfs,
            pinned_rootfs: Some(input.spec.rootfs_dir().as_fd()),
            config_paths: ConfigPaths {
                readonly: input.spec.config().readonly_paths(),
                masked: input.spec.config().masked_paths(),
            },
            status: None,
            working_dir: Some(input.spec.working_dir()),
        };
        let launched = spawn_container_via_intermediate(
            IntermediateSpec {
                plan: isolation_plan,
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
            child: launched.child,
            stdout,
            stderr,
            listener: launched.listener,
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

    /// spawn に渡った (注入の宛先列, namespace に IPC があるか)。
    type SeenOptions = (Option<Vec<String>>, bool);

    /// 偽の実体が返す実効 uid / gid(試験を実行ユーザーに依存させない)。
    const FAKE_EUID: u32 = 1000;
    const FAKE_EGID: u32 = 1001;

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
        /// spawn に渡った起動オプション由来の値(注入の宛先列・namespace に IPC があるか。SUP-12・#2625)。
        seen_options: Arc<Mutex<Vec<SeenOptions>>>,
        /// `landlock_ruleset` に渡った暗黙マウントの含め方(launch ごとに 1 件)。
        seen_implicit: Arc<Mutex<Vec<ImplicitDevMounts>>>,
        /// `root_identity` が `None`(rootfs を fstat できない)を返すか。
        fail_root_identity: bool,
        /// `ensure_no_process_in_recorded` が順に返す結果(尽きたら `AlreadyAbsent`)と、受け取った配置の記録(#2011)。
        recorded_script: Mutex<VecDeque<Result<RecordedCgroupOutcome, ErrorCode>>>,
        recorded_calls: Arc<Mutex<Vec<(ContainerId, CgroupPlacement)>>>,
        /// `kernel_audit_probe` が返す観測値(既定は否定する証拠なし)。
        probe: crate::audit_log::KernelAuditProbe,
        /// `emit_warning` に渡った縮退の警告行(順序の照合に使う `events` とは分ける。#2027)。
        warnings: Arc<Mutex<Vec<String>>>,
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
                seen_options: Arc::new(Mutex::new(Vec::new())),
                seen_implicit: Arc::new(Mutex::new(Vec::new())),
                fail_root_identity: false,
                recorded_script: Mutex::new(VecDeque::new()),
                recorded_calls: Arc::new(Mutex::new(Vec::new())),
                probe: crate::audit_log::KernelAuditProbe::all_clear(),
                warnings: Arc::new(Mutex::new(Vec::new())),
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
            user_tmpfs: &[super::super::config::OciMount],
            implicit: ImplicitDevMounts,
        ) -> Result<LandlockRuleset, ExecError> {
            push(&self.events, "landlock");
            self.seen_implicit.lock().unwrap().push(implicit);
            let detected = crate::landlock::evaluate_abi(self.abi.unwrap_or(6));
            crate::exec::ruleset_from_detection_with_dev(detected, config, user_tmpfs, implicit)
        }

        fn effective_ids(&self) -> (u32, u32) {
            (FAKE_EUID, FAKE_EGID)
        }

        fn kernel_audit_probe(&self) -> crate::audit_log::KernelAuditProbe {
            self.probe.clone()
        }

        fn emit_warning(&self, line: &str) {
            self.warnings.lock().unwrap().push(line.to_owned());
        }

        fn root_identity(&self, rootfs: &super::super::launch::RootfsDir) -> Option<RootIdentity> {
            push(&self.events, "root_identity");
            if self.fail_root_identity {
                return None;
            }
            RootIdentity::of_dir_fd(rootfs.as_fd())
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
            self.seen_options.lock().unwrap().push((
                input.inject.map(|set| {
                    set.files()
                        .iter()
                        .map(|f| f.destination().as_str().to_owned())
                        .collect()
                }),
                input.isolation.namespaces.contains(Namespace::Ipc),
            ));
            // 範囲写像で起動する場合だけ、渡された写像の内容を記録する(単一 ID の起動の記録は増やさない)。
            if let Some(ids) = input.subordinate {
                push(
                    &self.events,
                    format!(
                        "ids uid=[{}] gid=[{}] timeout={}s",
                        ids.uid.to_map_content().trim_end().replace('\n', ";"),
                        ids.gid.to_map_content().trim_end().replace('\n', ";"),
                        ids.timeout.as_secs()
                    ),
                );
            }
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
                listener: None,
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
        launcher_with(ops, privilege, None, join)
    }

    fn launcher_with(
        ops: FakeOps,
        privilege: IsolationPrivilege,
        subordinate: Option<SubordinateIds>,
        join: Option<JoinSource>,
    ) -> ProductionLauncher {
        ProductionLauncher {
            inner: Inner::new(
                Box::new(ops),
                privilege,
                subordinate,
                Arc::new(NullSink),
                join,
            ),
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
        spec_with_process(
            name,
            linux_extra,
            mounts,
            &["/bin/echo", "hi"],
            &["PATH=/bin"],
        )
    }

    /// `spec_with_mounts` の `process.args` / `process.env` を選べる版。
    fn spec_with_process(
        name: &str,
        linux_extra: serde_json::Value,
        mounts: serde_json::Value,
        args: &[&str],
        env: &[&str],
    ) -> LaunchSpec {
        spec_with_process_user(name, linux_extra, mounts, args, env, (0, 0))
    }

    /// `process.user` が `user`(uid, gid)の `LaunchSpec`。権限モデルの拒否と user 写像の照合の順序を
    /// 確かめるため(#2397・SEC-5)。
    fn spec_with_user(name: &str, user: (u32, u32)) -> LaunchSpec {
        spec_with_process_user(
            name,
            serde_json::json!({}),
            serde_json::json!([]),
            &["/bin/echo", "hi"],
            &["PATH=/bin"],
            user,
        )
    }

    /// 最も内側の組み立て。config の `process.user` と `LaunchSpec` の user を同じ値にそろえる。
    fn spec_with_process_user(
        name: &str,
        linux_extra: serde_json::Value,
        mounts: serde_json::Value,
        args: &[&str],
        env: &[&str],
        user: (u32, u32),
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
            "process": {"user": {"uid": user.0, "gid": user.1}, "args": ["/bin/echo", "hi"],
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
            args.iter().map(|a| (*a).to_owned()).collect(),
            env.iter().map(|e| (*e).to_owned()).collect(),
            Some("box".to_owned()),
            namespaces,
            CgroupRequirement::of_config(&config),
            Arc::new(config),
            ContainerId::new(name).unwrap(),
            binds,
            super::super::working_dir::ContainerWorkingDir::root(),
            user,
        );
        let _ = std::fs::remove_dir_all(&dir);
        spec
    }

    /// OCI-1（#2314）: `entrypoint_of` は名前だけの `args[0]` を `PATH` 探索の対象にし、絶対パスは従来どおり、
    /// `PATH` が無い名前と `..` を含む相対パスは `InvalidArgument` で拒否し、`/` を含む相対パスは cwd 起点の
    /// 解決の対象にする(#2432)。
    #[test]
    fn oci1_entrypoint_of_bare_name_search_and_rejections() {
        let ok = |args: &[&str], env: &[&str]| {
            entrypoint_of(&spec_with_process(
                "ep",
                serde_json::json!({}),
                serde_json::json!([]),
                args,
                env,
            ))
        };
        let e = ok(
            &["docker-entrypoint.sh", "redis-server"],
            &["PATH=/usr/local/bin:/bin"],
        )
        .expect("bare name with PATH");
        assert_eq!(e.path(), std::path::Path::new("docker-entrypoint.sh"));
        let e = ok(&["/bin/sh"], &[]).expect("absolute path");
        assert_eq!(e.path(), std::path::Path::new("/bin/sh"));
        let e = ok(&["bin/app", "x"], &[]).expect("relative path with slash");
        assert_eq!(e.path(), std::path::Path::new("bin/app"));
        let e = ok(&["./entrypoint.sh"], &[]).expect("dot-relative path");
        assert_eq!(e.path(), std::path::Path::new("./entrypoint.sh"));
        for (args, env) in [
            (&["docker-entrypoint.sh"][..], &["HOME=/"][..]),
            (&["../x"][..], &["PATH=/bin"][..]),
            (&["a/../x"][..], &[][..]),
            (&["bin/"][..], &[][..]),
        ] {
            let err = ok(args, env).expect_err("rejected");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{args:?}");
        }
    }

    /// OCI-1・SEC-5: 単一 ID 写像は 0/0 だけを許し、範囲写像は uid・gid の両方が写像内の場合だけ許す(境界値を具体値で確認)。
    #[test]
    fn oci1_check_user_mapped_boundaries() {
        use crate::exec::IdMapping;
        use crate::rootless::IdMapSet;
        let map = |host| {
            IdMapSet::new(vec![
                IdMapping {
                    container_id: 0,
                    host_id: 1000,
                    count: 1,
                },
                IdMapping {
                    container_id: 1,
                    host_id: host,
                    count: 65535,
                },
            ])
            .unwrap()
        };
        let (uid_map, gid_map) = (map(100_000), map(200_000));
        let single = IsolationPrivilege::RootlessSingleId;
        let sub = IsolationPrivilege::RootlessSubordinateIds;
        let r = Some((&uid_map, &gid_map));
        assert!(check_user_mapped(single, None, (0, 0)).is_ok());
        for ids in [(1000, 1000), (0, 1), (1, 0)] {
            let e = check_user_mapped(single, None, ids).unwrap_err();
            assert_eq!(e.code(), ErrorCode::FailedPrecondition, "{ids:?}");
            assert_eq!(
                e.message(),
                "process.user is not mapped in the user namespace (SEC-5)"
            );
        }
        for ok in [(0, 0), (1, 1), (1000, 1000), (65535, 65535)] {
            assert!(check_user_mapped(sub, r, ok).is_ok(), "{ok:?}");
        }
        for bad in [(65536, 1), (1, 65536), (65536, 65536), (u32::MAX, 0)] {
            assert!(check_user_mapped(sub, r, bad).is_err(), "{bad:?}");
        }
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
        assert_eq!(log.len(), 5, "{log:?}");
        assert_eq!(&log[..3], ["threads", "landlock", "root_identity"]);
        assert_eq!(log[4], "evidence ready");
        assert!(log[3].starts_with("spawn StagePipeline"), "{}", log[3]);
        assert!(log[3].contains(r#"landlock: "ruleset""#), "{}", log[3]);
        assert!(!log[3].contains("custom_hook"), "{}", log[3]);
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

    /// SUP-6・CORE-5(#2007): 成功した launch は、適用する ruleset と同じ内容の分離の記録を返し、記録の作成は fork より前。
    #[test]
    fn sup6_launch_isolation_is_recorded_from_the_same_ruleset() {
        use crate::launch_isolation::{RecordedTarget, RootIdentity};
        let spec = spec_for("iso-record", serde_json::json!({}));
        let ev = events();
        let l = launcher(FakeOps::new(&ev), rootless(), None);
        let p = l.launch(&spec, Duration::from_secs(1)).expect("launch");
        let record = p.launch_isolation().expect("record").clone();
        let want_root = RootIdentity::of_dir_fd(spec.rootfs_dir().as_fd()).expect("fstat");
        assert_eq!(record.root(), want_root);
        let ruleset =
            crate::exec::ruleset_from_detection(crate::landlock::evaluate_abi(6), spec.config())
                .expect("ruleset");
        let expected = crate::launch_isolation::LaunchIsolationRecord::new(want_root, &ruleset)
            .expect("expected record");
        // 監査の網羅の評価結果(#2027)は同じ観測値から導かれる値を添える。
        let coverage = crate::audit_log::assess(
            &crate::audit_log::KernelAuditProbe::all_clear(),
            expected.landlock().audit(),
        );
        let expected = expected
            .with_audit_coverage(crate::audit_log::AuditCoveragePolicy::BestEffort, coverage)
            .with_id_mapping(
                recorded_id_mapping(rootless(), None, FAKE_EUID, FAKE_EGID).expect("id mapping"),
            )
            .with_capabilities(crate::capabilities::ContainerCapabilities::oci_default());
        assert!(
            record == expected,
            "record must come from the applied ruleset"
        );
        let targets: Vec<&str> = record
            .landlock()
            .rules()
            .iter()
            .map(|r| r.target().as_str())
            .collect();
        assert_eq!(targets.first().copied(), Some("/"));
        assert!(matches!(
            record.landlock().rules().first().map(|r| r.target()),
            Some(RecordedTarget::Root)
        ));
        let events = ev.lock().unwrap().clone();
        let pos = |name: &str| events.iter().position(|e| e.starts_with(name)).expect(name);
        assert!(pos("landlock") < pos("root_identity"));
        assert!(pos("root_identity") < pos("spawn"));
        p.terminate(Duration::from_secs(5)).expect("terminate");
    }

    /// SUP-6・OCI-4(#2007・#1915): bind mount の分も同じ ruleset から記録に入る。
    #[test]
    fn oci4_sup6_launch_isolation_includes_bind_mounts() {
        use crate::launch_isolation::RecordedTarget;
        let spec = spec_with_mounts("iso-binds", serde_json::json!({}), bind_mounts_json());
        let ev = events();
        let l = launcher(FakeOps::new(&ev), rootless(), None);
        let p = l.launch(&spec, Duration::from_secs(1)).expect("launch");
        let record = p.launch_isolation().expect("record");
        let mounts: Vec<(String, usize)> = record
            .landlock()
            .rules()
            .iter()
            .filter_map(|r| match r.target() {
                RecordedTarget::Mount { destination, index } => {
                    Some((destination.as_str().to_owned(), *index))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            mounts,
            vec![("/data".to_owned(), 0), ("/cache".to_owned(), 1)]
        );
        p.terminate(Duration::from_secs(5)).expect("terminate");
    }

    /// SEC-1・SUP-6(#2007): 記録を作れない(rootfs を fstat できない)なら fork せずに `Internal` で拒否する。
    #[test]
    fn sec1_launch_isolation_failure_refuses_before_fork() {
        let spec = spec_for("iso-fail", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.fail_root_identity = true;
        let l = launcher(ops, rootless(), None);
        let err = l
            .launch(&spec, Duration::from_secs(1))
            .err()
            .expect("refused");
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(
            err.message(),
            "container launch failed in the Validate stage"
        );
        assert!(
            !ev.lock().unwrap().iter().any(|e| e.starts_with("spawn")),
            "must not spawn"
        );
        assert!(!l.last_launch_may_have_left_process());
    }

    /// 縮退した環境を模す観測値(`kill_process` が `actions_logged` に無い)。ABI 6 の Landlock と合わせて 2 層とも縮退する。
    fn degraded_probe() -> crate::audit_log::KernelAuditProbe {
        let mut p = crate::audit_log::KernelAuditProbe::all_clear();
        p.actions_logged = Some("kill_thread trap errno".to_owned());
        p
    }

    fn audit_launcher(
        ops: FakeOps,
        policy: crate::audit_log::AuditCoveragePolicy,
        sink: Arc<crate::audit_log::mount::tests::VecSink>,
    ) -> ProductionLauncher {
        let mut inner = Inner::new(Box::new(ops), rootless(), None, sink, None);
        inner.audit_policy = policy;
        ProductionLauncher { inner }
    }

    const DEGRADED_LINE: &str = r#"{"component":"core.audit","operation":"audit_coverage","outcome":"degraded","seccomp_kill":"seccomp_kill_not_logged","landlock":"landlock_audit_abi_too_old"}"#;

    /// SEC-4・#2027: 既定のモード(BestEffort)では、縮退していても警告して起動を続け、縮退を分離の記録と監査記録に残す。
    #[test]
    fn sec4_2027_best_effort_degraded_launches_with_warning() {
        use crate::audit_log::{
            AuditCoveragePolicy, AuditLayer, DegradeReason, KernelAuditLayerStatus,
        };
        let spec = spec_for("cov-best", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.probe = degraded_probe();
        let warnings = Arc::clone(&ops.warnings);
        let sink = Arc::new(crate::audit_log::mount::tests::VecSink::new(false));
        let l = audit_launcher(ops, AuditCoveragePolicy::BestEffort, Arc::clone(&sink));
        let p = l.launch(&spec, Duration::from_secs(1)).expect("launched");
        let record = p.launch_isolation().expect("record").clone();
        match record.audit_coverage() {
            crate::launch_isolation::RecordedAuditCoverage::Evaluated { policy, coverage } => {
                assert_eq!(policy, AuditCoveragePolicy::BestEffort);
                assert_eq!(
                    coverage.seccomp_kill(),
                    KernelAuditLayerStatus::Degraded(DegradeReason::SeccompKillNotLogged)
                );
                assert_eq!(
                    coverage.landlock(),
                    KernelAuditLayerStatus::Degraded(DegradeReason::LandlockAuditAbiTooOld)
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        let events = ev.lock().unwrap();
        assert_eq!(events.iter().filter(|e| e.starts_with("spawn")).count(), 1);
        assert_eq!(*warnings.lock().unwrap(), vec![DEGRADED_LINE.to_owned()]);
        // 記録に成功した縮退では記録失敗を載せない(#2468)。
        assert_eq!(
            record.audit_coverage_record(),
            crate::launch_isolation::AuditCoverageRecordOutcome::NotFailed
        );
        let recs = sink.records.lock().unwrap();
        let cov: Vec<_> = recs
            .iter()
            .filter(|r| r.layer() == AuditLayer::AuditCoverage)
            .collect();
        assert_eq!(cov.len(), 1);
        let (s, ll) = cov[0].coverage_reasons().expect("reasons");
        assert_eq!(s.map(|r| r.as_str()), Some("seccomp_kill_not_logged"));
        assert_eq!(ll.map(|r| r.as_str()), Some("landlock_audit_abi_too_old"));
    }

    /// SEC-4・#2027: 厳格モードでは縮退を fork の前に `FailedPrecondition` で拒否し、記録も警告も出さない。
    /// 対照として、全項目が揃っていれば厳格モードでも起動できる。
    #[test]
    fn sec4_2027_strict_degraded_refuses_before_fork() {
        use crate::audit_log::AuditCoveragePolicy;
        let spec = spec_for("cov-strict", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.probe = degraded_probe();
        let warnings = Arc::clone(&ops.warnings);
        let sink = Arc::new(crate::audit_log::mount::tests::VecSink::new(false));
        let l = audit_launcher(ops, AuditCoveragePolicy::Strict, Arc::clone(&sink));
        let err = l
            .launch(&spec, Duration::from_secs(1))
            .err()
            .expect("refused");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "audit coverage is degraded and the strict audit policy refuses to start"
        );
        assert!(!ev.lock().unwrap().iter().any(|e| e.starts_with("spawn")));
        assert!(sink.records.lock().unwrap().is_empty());
        assert!(warnings.lock().unwrap().is_empty());
        assert!(!l.last_launch_may_have_left_process());

        // 対照: ABI 7 と否定する証拠の無い観測値なら、厳格モードでも起動し、縮退の記録は出ない。
        let spec = spec_for("cov-strict-ok", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.abi = Some(7);
        let warnings = Arc::clone(&ops.warnings);
        let sink = Arc::new(crate::audit_log::mount::tests::VecSink::new(false));
        let l = audit_launcher(ops, AuditCoveragePolicy::Strict, Arc::clone(&sink));
        l.launch(&spec, Duration::from_secs(1)).expect("launched");
        assert!(sink.records.lock().unwrap().is_empty());
        assert!(warnings.lock().unwrap().is_empty());
    }

    /// SEC-4・#2027: 既定のモードでは、縮退の監査記録を書けなくても起動の可否を変えず、固定語彙の診断行だけを出す。
    #[test]
    fn sec4_2027_best_effort_record_failure_still_launches() {
        let spec = spec_for("cov-sinkfail", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.probe = degraded_probe();
        let warnings = Arc::clone(&ops.warnings);
        let sink = Arc::new(crate::audit_log::mount::tests::VecSink::new(true));
        let l = audit_launcher(ops, crate::audit_log::AuditCoveragePolicy::BestEffort, sink);
        let p = l.launch(&spec, Duration::from_secs(1)).expect("launched");
        assert_eq!(
            *warnings.lock().unwrap(),
            vec![
                DEGRADED_LINE.to_owned(),
                AUDIT_COVERAGE_RECORD_FAILED_LINE.to_owned()
            ]
        );
        // SEC-4・REPAIR-4(#2468): 記録できなかった事実が評価値にも載る(supervisor が出し直す元)。
        assert_eq!(
            p.launch_isolation().unwrap().audit_coverage_record(),
            crate::launch_isolation::AuditCoverageRecordOutcome::Failed
        );
    }

    /// 期限まで眠ってから `Timeout` を返す遅い sink。`record`(期限を知らない経路)は期限と無関係に長く眠る。
    struct SlowSink {
        record_calls: AtomicUsize,
    }

    impl AuditSink for SlowSink {
        fn record(&self, _record: &AuditRecord) -> Result<(), TraitError> {
            self.record_calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_secs(5));
            Ok(())
        }

        fn record_until(&self, _record: &AuditRecord, deadline: Instant) -> Result<(), TraitError> {
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            Err(TraitError::new(ErrorCode::Timeout, "slow sink timed out"))
        }
    }

    /// SEC-4・REPAIR-5: 上限のない `Duration::MAX` を渡しても期限の算出で panic せず、上限で丸めた期限で起動が完了する。
    #[test]
    fn sec4_repair5_launch_with_max_timeout_does_not_panic() {
        let spec = spec_for("cov-maxtimeout", serde_json::json!({}));
        let ev = events();
        let sink = Arc::new(crate::audit_log::mount::tests::VecSink::new(false));
        let l = audit_launcher(
            FakeOps::new(&ev),
            crate::audit_log::AuditCoveragePolicy::BestEffort,
            sink,
        );
        let p = l.launch(&spec, Duration::MAX).expect("launched");
        p.terminate(Duration::from_secs(5)).expect("terminate");
        assert_eq!(
            ev.lock()
                .unwrap()
                .iter()
                .filter(|e| e.starts_with("spawn"))
                .count(),
            1
        );
    }

    /// SEC-4・REPAIR-5: 縮退の監査配送が遅くても、launch 全体が引数 timeout の近傍内に `Timeout` で返り、
    /// 配送の待ちが入口の期限の外へ出ず、子(spawn)も作られない。
    #[test]
    fn sec4_repair5_slow_audit_delivery_stays_within_launch_timeout() {
        let spec = spec_for("cov-slow", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.probe = degraded_probe();
        let sink = Arc::new(SlowSink {
            record_calls: AtomicUsize::new(0),
        });
        let mut inner = Inner::new(
            Box::new(ops),
            rootless(),
            None,
            Arc::clone(&sink) as _,
            None,
        );
        inner.audit_policy = crate::audit_log::AuditCoveragePolicy::BestEffort;
        let l = ProductionLauncher { inner };
        let started = Instant::now();
        let err = l
            .launch(&spec, Duration::from_millis(300))
            .err()
            .expect("timed out");
        let elapsed = started.elapsed();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
        assert_eq!(sink.record_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            ev.lock()
                .unwrap()
                .iter()
                .filter(|e| e.starts_with("spawn"))
                .count(),
            0
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

    fn dummy_join_source() -> JoinSource {
        Box::new(|| {
            let fd = std::fs::File::open("/").unwrap();
            Ok(CgroupJoin::from_dir_for_test(
                crate::cgroups::CgroupName::new(&crate::traits::ContainerId::new("c").unwrap())
                    .unwrap(),
                std::os::fd::OwnedFd::from(fd),
            ))
        })
    }

    /// #2019・CORE-3・SEC-1: cgroup 連鎖で書いた `linux.resources` と config の値が食い違えば(書いていない場合・
    /// 値が違う場合・config に無いのに書いた場合)、スレッド確認・Landlock・fork より前に拒否する。一致すれば進む。
    #[test]
    fn core3_applied_resource_limits_must_match_config_before_anything() {
        let resources = serde_json::json!({"resources": {"memory": {"limit": 67108864}}});
        let spec = spec_for("applied-res", resources.clone());
        let other = spec_for(
            "applied-res-other",
            serde_json::json!({"resources": {"memory": {"limit": 134217728}}}),
        );
        let plain = spec_for("applied-res-plain", serde_json::json!({}));
        let applied = |s: &LaunchSpec| s.config().linux_resources().cloned();
        for (label, spec, applied_value) in [
            ("not applied", &spec, None),
            ("different value", &spec, applied(&other)),
            ("applied but not in config", &plain, applied(&spec)),
        ] {
            let ev = events();
            let mut l = launcher(FakeOps::new(&ev), rootless(), Some(dummy_join_source()));
            l.inner.applied_resources = applied_value;
            let err = l
                .launch(spec, Duration::from_secs(1))
                .err()
                .unwrap_or_else(|| panic!("{label}: must be refused"));
            assert_eq!(err.code(), ErrorCode::FailedPrecondition, "{label}");
            assert_eq!(
                err.message(),
                "the cgroup limits applied before start do not match config.json",
                "{label}"
            );
            assert!(ev.lock().unwrap().is_empty(), "{label}: nothing may run");
        }
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.run_stages = false;
        let mut l = launcher(ops, rootless(), Some(dummy_join_source()));
        l.inner.applied_resources = applied(&spec);
        l.launch(&spec, Duration::from_secs(1))
            .expect("matching limits launch")
            .terminate(Duration::from_secs(5))
            .expect("terminate");
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

    /// SEC-5: 未実装の権限モデル(`RootfulHostRoot`)は `Unimplemented` で、何も呼ばずに拒否する。
    #[test]
    fn sec5_unimplemented_privilege_models_are_refused_before_fork() {
        let spec = spec_for("priv", serde_json::json!({}));
        let ev = events();
        let l = launcher(FakeOps::new(&ev), IsolationPrivilege::RootfulHostRoot, None);
        let err = l
            .launch(&spec, Duration::from_secs(1))
            .err()
            .expect("refused");
        assert_eq!(err.code(), ErrorCode::Unimplemented);
        assert_eq!(
            err.message(),
            "the rootful privilege model is not supported by the launcher"
        );
        assert!(ev.lock().unwrap().is_empty());
    }

    /// SEC-5・CORE-6(#2397): `RootfulHostRoot` の拒否(`Unimplemented`)は `process.user` の照合より先に返る。
    /// `RootfulHostRoot` は uid/gid が (0, 0) なら照合を通るため、写像の外の (1000, 1000) で順序を区別する。
    /// 対照として `RootlessSingleId` は同じ spec を user 照合で拒否する(選んだ uid が実際に照合で落ちる証拠)。
    #[test]
    fn sec5_core6_rootful_refusal_precedes_user_mapping_check() {
        let spec = spec_with_user("priv-user", (1000, 1000));

        let ev = events();
        let l = launcher(FakeOps::new(&ev), IsolationPrivilege::RootfulHostRoot, None);
        let err = l
            .launch(&spec, Duration::from_secs(1))
            .err()
            .expect("refused");
        assert_eq!(err.code(), ErrorCode::Unimplemented);
        assert_eq!(
            err.message(),
            "the rootful privilege model is not supported by the launcher"
        );
        assert_ne!(
            err.message(),
            "process.user is not mapped in the user namespace (SEC-5)"
        );
        assert!(ev.lock().unwrap().is_empty());

        let ev = events();
        let l = launcher(
            FakeOps::new(&ev),
            IsolationPrivilege::RootlessSingleId,
            None,
        );
        let err = l
            .launch(&spec, Duration::from_secs(1))
            .err()
            .expect("refused");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "process.user is not mapped in the user namespace (SEC-5)"
        );
        assert!(ev.lock().unwrap().is_empty());
    }

    /// CORE-6・SEC-5(#2009): 写像の無い `RootlessSubordinateIds` は(構築を迂回しても)何も呼ばずに拒否する。
    #[test]
    fn core6_subordinate_privilege_without_mapping_is_refused_before_fork() {
        let spec = spec_for("priv-sub", serde_json::json!({}));
        let ev = events();
        let l = launcher(
            FakeOps::new(&ev),
            IsolationPrivilege::RootlessSubordinateIds,
            None,
        );
        let err = l
            .launch(&spec, Duration::from_secs(1))
            .err()
            .expect("refused");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "the subordinate id privilege model requires a subordinate id source"
        );
        assert!(ev.lock().unwrap().is_empty());
    }

    /// 試験用の subuid / subgid と helper(root 所有の実在ファイルで代用)の入力元を作る。
    fn source_in(name: &str, subuid: &str, subgid: &str, helper: &str) -> SubordinateIdSource {
        let dir = std::env::temp_dir().join(format!("fandhe-subids-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("subuid"), subuid).unwrap();
        std::fs::write(dir.join("subgid"), subgid).unwrap();
        SubordinateIdSource::with_paths(
            Some("tester".to_owned()),
            &dir.join("subuid"),
            &dir.join("subgid"),
            Path::new(helper),
            Path::new(helper),
            Duration::from_secs(5),
        )
        .unwrap()
    }

    /// root 所有で祖先も root のみ書き込み可の実在の通常ファイル(`HelperPaths` の検証を通す代用)。
    /// symlink は検証が拒否するため、候補から実体のあるものを選ぶ。1 つも無ければ panic する(skip しない)。
    fn helper_stand_in() -> &'static str {
        use std::os::unix::fs::MetadataExt as _;
        [
            "/usr/bin/newuidmap",
            "/usr/bin/gnutrue",
            "/usr/bin/true",
            "/usr/bin/dash",
            "/usr/bin/bash",
            "/usr/bin/su",
            "/usr/bin/passwd",
        ]
        .into_iter()
        .find(|p| {
            std::fs::symlink_metadata(p)
                .is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0)
        })
        .expect("a root-owned regular file under /usr/bin is required by this test")
    }

    /// SEC-5(#2009): ホスト ID 0 を含む範囲は、構築(副作用なし)で `PermissionDenied` になる。
    #[test]
    fn sec5_subordinate_ids_reject_host_root_range_before_fork() {
        let src = source_in(
            "hostroot",
            "tester:0:65536\n",
            "tester:100000:65536\n",
            helper_stand_in(),
        );
        let err = resolve_privilege(
            IsolationPrivilege::RootlessSubordinateIds,
            Some(src),
            1000,
            1000,
        )
        .expect_err("host id 0 range is refused");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(
            err.message(),
            "failed to resolve the subordinate id mapping for the launcher"
        );
    }

    /// CORE-6(#2009): helper が無ければ構築が拒否し、文言にパスを含めない。
    #[test]
    fn core6_subordinate_ids_reject_missing_helper_before_fork() {
        let src = source_in(
            "nohelper",
            "tester:100000:65536\n",
            "tester:100000:65536\n",
            "/nonexistent-fandhe-dir/newuidmap",
        );
        let err = resolve_privilege(
            IsolationPrivilege::RootlessSubordinateIds,
            Some(src),
            1000,
            1000,
        )
        .expect_err("missing helper is refused");
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(
            err.message(),
            "failed to resolve the subordinate id mapping for the launcher"
        );
        assert!(!err.message().contains("nonexistent"));
    }

    /// CORE-6・SEC-5(#2009): 範囲が 0 件・euid 0・入力元の欠落と取り違えは、単一 ID へ縮退せず拒否する。
    #[test]
    fn core6_subordinate_ids_reject_empty_range_root_and_mismatched_source() {
        let sub = IsolationPrivilege::RootlessSubordinateIds;
        let src = || {
            source_in(
                "misc",
                "other:100000:65536\n",
                "tester:100000:65536\n",
                helper_stand_in(),
            )
        };
        let e = resolve_privilege(sub, Some(src()), 1000, 1000).expect_err("empty");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        let e = resolve_privilege(sub, Some(src()), 0, 1000).expect_err("root");
        assert_eq!(e.code(), ErrorCode::PermissionDenied);
        assert_eq!(e.message(), "refusing to map the host root identity");
        let e = resolve_privilege(sub, None, 1000, 1000).expect_err("missing source");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        let e = resolve_privilege(rootless(), Some(src()), 1000, 1000).expect_err("unneeded");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert!(
            resolve_privilege(rootless(), None, 1000, 1000)
                .unwrap()
                .is_none()
        );
    }

    /// CORE-6・SEC-5(#2389): `resolve_privilege` が返す写像は `resolve_id_maps` の結果と同じ行になる(具体値)。
    #[test]
    fn core6_resolve_id_maps_matches_resolve_privilege() {
        let src = source_in(
            "idmaps",
            "tester:100000:65536\n",
            "tester:200000:65536\n",
            helper_stand_in(),
        );
        let maps = src.resolve_id_maps(1000, 1001).expect("maps");
        let rows = |s: &IdMapSet| {
            s.entries()
                .iter()
                .map(|m| (m.container_id, m.host_id, m.count))
                .collect::<Vec<_>>()
        };
        assert_eq!(rows(maps.uid()), vec![(0, 1000, 1), (1, 100000, 65536)]);
        assert_eq!(rows(maps.gid()), vec![(0, 1001, 1), (1, 200000, 65536)]);
        let ids = resolve_privilege(
            IsolationPrivilege::RootlessSubordinateIds,
            Some(src),
            1000,
            1001,
        )
        .expect("resolved")
        .expect("some");
        assert_eq!(rows(&ids.uid), rows(maps.uid()));
        assert_eq!(rows(&ids.gid), rows(maps.gid()));
        let e = SubordinateIdSource::with_id_files(
            Some("tester".to_owned()),
            Path::new("/nonexistent-fandhe-dir/subuid"),
            Path::new("/nonexistent-fandhe-dir/subgid"),
        )
        .expect("source")
        .resolve_id_maps(0, 1000)
        .expect_err("root");
        assert_eq!(e.code(), ErrorCode::PermissionDenied);
    }

    /// CORE-6(#2009): 入力元の相対パス・不正な名前・範囲外の timeout は構築前に `InvalidArgument`。
    #[test]
    fn core6_subordinate_source_validates_inputs() {
        let abs = Path::new("/etc/subuid");
        let t = Duration::from_secs(5);
        let name = Some("tester".to_owned());
        for e in [
            SubordinateIdSource::with_paths(name.clone(), Path::new("subuid"), abs, abs, abs, t),
            SubordinateIdSource::with_paths(Some("a:b".to_owned()), abs, abs, abs, abs, t),
            SubordinateIdSource::with_paths(name.clone(), abs, abs, abs, abs, Duration::ZERO),
            SubordinateIdSource::with_paths(name, abs, abs, abs, abs, Duration::from_secs(61)),
        ] {
            assert_eq!(e.expect_err("invalid").code(), ErrorCode::InvalidArgument);
        }
    }

    /// CORE-6(#2009): 範囲写像の launch は `Unimplemented` にならず、spawn へコンテナ 0 → 自 ID・コンテナ 1 以上
    /// → subuid の範囲の具体的な写像が渡る(順序は 単一スレッド確認 → Landlock → spawn)。
    #[test]
    fn core6_subordinate_ids_launch_reaches_spawn_with_ranged_maps() {
        let src = source_in(
            "launch",
            "tester:100000:65536\n",
            "tester:200000:65536\n",
            helper_stand_in(),
        );
        let ids = resolve_privilege(
            IsolationPrivilege::RootlessSubordinateIds,
            Some(src),
            1000,
            1001,
        )
        .expect("resolved")
        .expect("some");
        let spec = spec_for("subordinate-launch", serde_json::json!({}));
        let ev = events();
        let l = launcher_with(
            FakeOps::new(&ev),
            IsolationPrivilege::RootlessSubordinateIds,
            Some(ids),
            None,
        );
        let p = l.launch(&spec, Duration::from_secs(1)).expect("launch");
        // CORE-6・REPAIR-4(#2388): 分離の記録へ、範囲写像のモデルと範囲が具体値で残る。
        let mapping = p
            .launch_isolation()
            .and_then(|r| r.id_mapping())
            .expect("id mapping record")
            .clone();
        assert_eq!(mapping.model().as_str(), "subordinate");
        let ext = |c, h, n| crate::launch_isolation::RecordedIdExtent {
            container_id: c,
            host_id: h,
            size: n,
        };
        assert_eq!(mapping.uid(), [ext(0, 1000, 1), ext(1, 100_000, 65_536)]);
        assert_eq!(mapping.gid(), [ext(0, 1001, 1), ext(1, 200_000, 65_536)]);
        p.terminate(Duration::from_secs(5)).expect("terminate");
        let log = ev.lock().unwrap().clone();
        assert_eq!(log.len(), 6, "{log:?}");
        assert_eq!(&log[..3], ["threads", "landlock", "root_identity"]);
        assert_eq!(
            log[3],
            "ids uid=[0 1000 1;1 100000 65536] gid=[0 1001 1;1 200000 65536] timeout=5s"
        );
        assert!(log[4].starts_with("spawn StagePipeline"), "{}", log[4]);
        assert_eq!(log[5], "evidence ready");
    }

    /// CORE-6・REPAIR-4(#2388): 単一 ID の launch は、実効 ID をコンテナ内 0 の 1 件へ写す記録を残す。
    #[test]
    fn core6_single_id_launch_records_one_to_one_mapping() {
        let spec = spec_for("single-record", serde_json::json!({}));
        let ev = events();
        let l = launcher(FakeOps::new(&ev), rootless(), None);
        let p = l.launch(&spec, Duration::from_secs(1)).expect("launch");
        let mapping = p
            .launch_isolation()
            .and_then(|r| r.id_mapping())
            .expect("id mapping record")
            .clone();
        let ext = |h| crate::launch_isolation::RecordedIdExtent {
            container_id: 0,
            host_id: h,
            size: 1,
        };
        assert_eq!(mapping.model().as_str(), "single");
        assert_eq!(mapping.uid(), [ext(FAKE_EUID)]);
        assert_eq!(mapping.gid(), [ext(FAKE_EGID)]);
        p.terminate(Duration::from_secs(5)).expect("terminate");
    }

    /// SEC-5・CORE-6(#2388): ホスト root の単一 ID は記録を作れず、spawn の計画と同じ code・文言で拒否する。
    #[test]
    fn sec5_core6_single_id_record_refuses_host_root() {
        for (u, g) in [(0, 1000), (1000, 0)] {
            let e = recorded_id_mapping(IsolationPrivilege::RootlessSingleId, None, u, g)
                .expect_err("host root");
            assert_eq!(e.code(), ErrorCode::PermissionDenied);
            assert_eq!(e.message(), "refusing to map the host root identity");
        }
        // 範囲写像なのに写像が無い・rootful は記録を作らない(fail-closed)。
        for p in [
            IsolationPrivilege::RootlessSubordinateIds,
            IsolationPrivilege::RootfulHostRoot,
        ] {
            let e = recorded_id_mapping(p, None, 1000, 1000).expect_err("no record");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
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

    fn options_with(
        tmpfs_dests: &[&str],
        shm: bool,
        inject: &[(&str, &[u8])],
        ipc: LaunchIpcMode,
    ) -> LaunchOptions {
        use crate::injected_files::{InjectedContent, InjectedFileMode, InjectedFileSpec};
        use crate::tmpfs::TmpfsMountSpec;
        let mut tmpfs = TmpfsMountSet::new();
        if shm {
            tmpfs.ensure_default_dev_shm().expect("shm");
        }
        for d in tmpfs_dests {
            tmpfs
                .push(TmpfsMountSpec::new(d, None).expect("spec"))
                .expect("push");
        }
        let mut set = InjectedFileSet::new();
        for (dest, bytes) in inject {
            set.push(
                InjectedFileSpec::new(
                    dest,
                    InjectedContent::from_bytes(bytes.to_vec()).expect("content"),
                    InjectedFileMode::new(0o444).expect("mode"),
                )
                .expect("file"),
            )
            .expect("push");
        }
        LaunchOptions::new(tmpfs, set, ipc).expect("options")
    }

    /// 封印 memfd の注入内容 1 件だけを持つ起動オプション(#2628)。
    fn options_sealed(bytes: &[u8]) -> LaunchOptions {
        use crate::injected_files::{InjectedContent, InjectedFileMode, InjectedFileSpec};
        use std::io::Write as _;
        let dir = std::env::temp_dir().join(format!("fandhe-sealed-opts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("secret");
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(bytes))
            .expect("write");
        let file = std::fs::File::open(&path).expect("open");
        let content = InjectedContent::from_file(&file).expect("sealed");
        assert!(!content.is_caller_memory());
        let _ = std::fs::remove_dir_all(&dir);
        let mut set = InjectedFileSet::new();
        set.push(
            InjectedFileSpec::new("/etc/secret-token", content, InjectedFileMode::DEFAULT)
                .expect("file"),
        )
        .expect("push");
        let mut tmpfs = TmpfsMountSet::new();
        tmpfs.ensure_default_dev_shm().expect("shm");
        LaunchOptions::new(tmpfs, set, LaunchIpcMode::Private).expect("options")
    }

    /// SUP-12・CORE-5(#2625): 起動オプション未指定は従来どおり(`/dev/shm` のみ・注入なし・IPC あり・All)。
    #[test]
    fn sup12_default_launch_keeps_current_behavior() {
        let spec = spec_for("opts-default", serde_json::json!({}));
        let ops = FakeOps::new(&events());
        let (opts, implicit) = (
            Arc::clone(&ops.seen_options),
            Arc::clone(&ops.seen_implicit),
        );
        let l = launcher(ops, rootless(), None);
        let p = l.launch(&spec, Duration::from_secs(1)).expect("launch");
        p.terminate(Duration::from_secs(5)).expect("terminate");
        assert_eq!(opts.lock().unwrap().clone(), vec![(None, true)]);
        assert_eq!(
            implicit.lock().unwrap().clone(),
            vec![ImplicitDevMounts::All]
        );
    }

    /// SUP-12・CORE-5・SEC-1(#2625): `--ipc=host` + `--tmpfs /run` + 注入。IPC namespace を外し、tmpfs は
    /// 指定どおり(`/dev/shm` なし)、Landlock は `WithoutShm`。他の namespace は保つ。再 launch でも同じ。
    #[test]
    fn sup12_host_ipc_options_reach_spawn_and_landlock_on_every_launch() {
        let spec = spec_for("opts-host", serde_json::json!({}));
        let ops = FakeOps::new(&events());
        let (seen, opts, implicit) = (
            Arc::clone(&ops.seen),
            Arc::clone(&ops.seen_options),
            Arc::clone(&ops.seen_implicit),
        );
        let mut l = launcher(ops, rootless(), None);
        l.inner.launch_options = Some(options_with(
            &["/run"],
            false,
            &[("/etc/secret-token", b"v")],
            LaunchIpcMode::Host,
        ));
        for _ in 0..2 {
            let p = l.launch(&spec, Duration::from_secs(1)).expect("launch");
            p.terminate(Duration::from_secs(5)).expect("terminate");
        }
        assert_eq!(
            seen.lock().unwrap().clone(),
            vec![(None, vec!["/run".to_owned()]); 2]
        );
        assert_eq!(
            opts.lock().unwrap().clone(),
            vec![(Some(vec!["/etc/secret-token".to_owned()]), false); 2]
        );
        assert_eq!(
            implicit.lock().unwrap().clone(),
            vec![ImplicitDevMounts::WithoutShm; 2]
        );
    }

    /// SUP-12・CORE-5(#2625): 利用者指定の tmpfs(`/run`)は Landlock のルールと分離の記録にも書き込み可能で載る。
    #[test]
    fn sup12_user_tmpfs_is_writable_in_landlock_rules_and_record() {
        use crate::launch_isolation::RecordedTarget;
        let spec = spec_for("opts-landlock-tmpfs", serde_json::json!({}));
        let mut l = launcher(FakeOps::new(&events()), rootless(), None);
        l.inner.launch_options = Some(options_with(&["/run"], true, &[], LaunchIpcMode::Private));
        let p = l.launch(&spec, Duration::from_secs(1)).expect("launch");
        let record = p.launch_isolation().expect("record");
        let rules: Vec<(String, u64)> = record
            .landlock()
            .rules()
            .iter()
            .filter_map(|r| match r.target() {
                RecordedTarget::Tmpfs { destination } => {
                    Some((destination.as_str().to_owned(), r.allowed()))
                }
                _ => None,
            })
            .collect();
        let run = rules.iter().find(|(d, _)| d == "/run").expect("/run rule");
        let write = crate::landlock::AccessFs::WRITE.bits();
        assert_eq!(run.1 & write, write);
        assert!(rules.iter().all(|(d, _)| d != "/dev/shm"));
        p.terminate(Duration::from_secs(5)).expect("terminate");
    }

    /// SUP-12・CORE-5(#2625): `ro` の利用者 tmpfs は書き込み可能な root の下でも起動でき、Landlock のルールには載らない。
    #[test]
    fn sup12_read_only_user_tmpfs_launches_without_a_landlock_rule() {
        use crate::launch_isolation::RecordedTarget;
        let spec = spec_for("opts-landlock-ro-tmpfs", serde_json::json!({}));
        let mut l = launcher(FakeOps::new(&events()), rootless(), None);
        let mut opts = options_with(&["/ro"], true, &[], LaunchIpcMode::Private);
        let mut tmpfs = TmpfsMountSet::new();
        for m in opts.tmpfs().mounts() {
            let mut m = m.clone();
            m.read_only = m.destination.as_str() == "/ro";
            tmpfs.push(m).expect("push");
        }
        opts = LaunchOptions::new(tmpfs, InjectedFileSet::new(), LaunchIpcMode::Private)
            .expect("options");
        l.inner.launch_options = Some(opts);
        let p = l.launch(&spec, Duration::from_secs(1)).expect("launch");
        let record = p.launch_isolation().expect("record");
        let tmpfs_rules = record
            .landlock()
            .rules()
            .iter()
            .filter(|r| matches!(r.target(), RecordedTarget::Tmpfs { .. }))
            .count();
        assert_eq!(tmpfs_rules, 0);
        p.terminate(Duration::from_secs(5)).expect("terminate");
    }

    /// SUP-12(#2625): `/dev/shm` と `/run` を指定順で渡し、IPC namespace は保つ。
    #[test]
    fn sup12_private_ipc_tmpfs_set_is_passed_in_order() {
        let spec = spec_for("opts-private", serde_json::json!({}));
        let ops = FakeOps::new(&events());
        let (seen, opts) = (Arc::clone(&ops.seen), Arc::clone(&ops.seen_options));
        let mut l = launcher(ops, rootless(), None);
        l.inner.launch_options = Some(options_with(&["/run"], true, &[], LaunchIpcMode::Private));
        let p = l.launch(&spec, Duration::from_secs(1)).expect("launch");
        p.terminate(Duration::from_secs(5)).expect("terminate");
        assert_eq!(
            seen.lock().unwrap().clone(),
            vec![(None, vec!["/dev/shm".to_owned(), "/run".to_owned()])]
        );
        assert_eq!(opts.lock().unwrap().clone(), vec![(None, true)]);
    }

    /// SUP-12・CORE-5(#2625): bind が利用者 tmpfs・注入ディレクトリと重なるときは spawn の前に拒否する。
    #[test]
    fn sup12_bind_overlapping_user_tmpfs_or_injected_is_rejected_before_spawn() {
        let binds = |dest: &str| {
            serde_json::json!([
                {"destination": dest, "type": "bind", "source": "/srv/data", "options": ["rbind"]}
            ])
        };
        let cases: [(&str, LaunchOptions); 2] = [
            (
                "/run/cache",
                options_with(&["/run"], true, &[], LaunchIpcMode::Private),
            ),
            (
                "/run/secrets",
                options_with(
                    &[],
                    true,
                    &[("/run/secrets/db", b"v")],
                    LaunchIpcMode::Private,
                ),
            ),
        ];
        for (i, (dest, options)) in cases.into_iter().enumerate() {
            let spec = spec_with_mounts(
                &format!("opts-overlap-{i}"),
                serde_json::json!({}),
                binds(dest),
            );
            let ops = FakeOps::new(&events());
            let mut l = launcher(ops, rootless(), None);
            l.inner.launch_options = Some(options);
            let err = l
                .launch(&spec, Duration::from_secs(1))
                .map(|_| ())
                .expect_err("rejected");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{dest}");
        }
    }

    /// SEC-2・CORE-5(#2625): readonlyPaths の厳密な子孫への tmpfs・注入ディレクトリは spawn の前に拒否する。
    /// 同一の宛先と無関係な宛先(`/datax`)は通る。
    #[test]
    fn sec2_tmpfs_under_readonly_path_is_rejected_before_spawn() {
        let linux = serde_json::json!({"readonlyPaths": ["/data"]});
        let rejected: [(&str, LaunchOptions); 2] = [
            (
                "tmpfs",
                options_with(&["/data/cache"], true, &[], LaunchIpcMode::Private),
            ),
            (
                "inject",
                options_with(&[], true, &[("/data/sec/db", b"v")], LaunchIpcMode::Private),
            ),
        ];
        for (name, options) in rejected {
            let spec = spec_for(&format!("opts-ro-{name}"), linux.clone());
            let mut l = launcher(FakeOps::new(&events()), rootless(), None);
            l.inner.launch_options = Some(options);
            let err = l
                .launch(&spec, Duration::from_secs(1))
                .map(|_| ())
                .expect_err("rejected");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{name}");
        }
        for dest in ["/data", "/datax"] {
            let spec = spec_for("opts-ro-ok", linux.clone());
            let mut l = launcher(FakeOps::new(&events()), rootless(), None);
            l.inner.launch_options = Some(options_with(&[dest], true, &[], LaunchIpcMode::Private));
            let p = l.launch(&spec, Duration::from_secs(1)).expect(dest);
            p.terminate(Duration::from_secs(5)).expect("terminate");
        }
    }

    /// SEC-1・SEC-5・CORE-6(#2628): 範囲写像と、呼び出し元のメモリにある注入内容の併用は launch で fork 前に拒否する。
    #[test]
    fn sec1_subordinate_privilege_with_inject_is_refused_before_fork() {
        let spec = spec_for("opts-sub-inject", serde_json::json!({}));
        let ev = events();
        let src = source_in(
            "inject-refused",
            "tester:100000:65536\n",
            "tester:200000:65536\n",
            helper_stand_in(),
        );
        let ids = resolve_privilege(
            IsolationPrivilege::RootlessSubordinateIds,
            Some(src),
            1000,
            1001,
        )
        .expect("resolved")
        .expect("some");
        let mut l = launcher_with(
            FakeOps::new(&ev),
            IsolationPrivilege::RootlessSubordinateIds,
            Some(ids),
            None,
        );
        l.inner.launch_options = Some(options_with(
            &["/run"],
            false,
            &[("/etc/secret-token", b"v")],
            LaunchIpcMode::Host,
        ));
        let err = l
            .launch(&spec, Duration::from_secs(1))
            .err()
            .expect("refused");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "injected file content held in process memory cannot be combined with the subordinate id privilege model"
        );
        assert!(
            !ev.lock()
                .unwrap()
                .iter()
                .any(|e| e.starts_with("spawn") || e.starts_with("landlock")),
            "{:?}",
            ev.lock().unwrap()
        );
    }

    /// SEC-1・CORE-6(#2628): 判定関数は範囲写像 + 呼び出し元のメモリの注入内容だけを拒否し、注入なしの範囲写像・
    /// 封印 memfd の注入・単一 ID + 注入は通す。
    #[test]
    fn sec1_refuse_inject_with_subordinate_only_rejects_the_combination() {
        let with = options_with(&[], true, &[("/etc/t", b"v")], LaunchIpcMode::Private);
        let without = options_with(&[], true, &[], LaunchIpcMode::Private);
        let sealed = options_sealed(b"sealed-secret-value");
        assert!(
            refuse_inject_with_subordinate(IsolationPrivilege::RootlessSubordinateIds, &sealed)
                .is_ok()
        );
        assert!(
            refuse_inject_with_subordinate(IsolationPrivilege::RootlessSubordinateIds, &with)
                .is_err()
        );
        assert!(
            refuse_inject_with_subordinate(IsolationPrivilege::RootlessSubordinateIds, &without)
                .is_ok()
        );
        assert!(
            refuse_inject_with_subordinate(IsolationPrivilege::RootlessSingleId, &with).is_ok()
        );
    }

    /// SEC-4(#1915): `rejection_audit_sink` は構築時の sink を返す。
    #[test]
    fn sec4_rejection_audit_sink_is_the_launcher_sink() {
        let l = launcher(FakeOps::new(&events()), rootless(), None);
        assert!(l.rejection_audit_sink().is_some());
    }

    /// SEC-4・ESC-06(#2236): `exit_audit_sink` 指定時は回収点の記録先だけが差し替わり、`rejection_audit_sink` は
    /// launcher の `audit_sink` のまま。未指定なら回収点も `audit_sink`。
    #[test]
    fn sec4_2236_exit_audit_sink_overrides_only_the_reap_point() {
        let mut l = launcher(FakeOps::new(&events()), rootless(), None);
        let main = Arc::clone(&l.inner.audit_sink);
        assert!(Arc::ptr_eq(&l.inner.exit_audit_sink(), &main));
        let relay: Arc<dyn AuditSink> = Arc::new(NullSink);
        l.inner.exit_audit_sink = Some(Arc::clone(&relay));
        assert!(Arc::ptr_eq(&l.inner.exit_audit_sink(), &relay));
        assert!(!Arc::ptr_eq(&l.inner.exit_audit_sink(), &main));
        let rej = l.rejection_audit_sink().expect("sink");
        assert!(std::ptr::addr_eq(rej, Arc::as_ptr(&main)));
    }

    /// SEC-4・#2481: `rejection_audit_sink` 指定時は start の検証の拒否の記録先だけが差し替わり、
    /// 回収点と launch の時点の `audit_sink` は変わらない。
    #[test]
    fn sec4_2481_rejection_audit_sink_overrides_only_the_rejection_point() {
        let mut l = launcher(FakeOps::new(&events()), rootless(), None);
        let main = Arc::clone(&l.inner.audit_sink);
        let relay: Arc<dyn AuditSink> = Arc::new(NullSink);
        l.inner.rejection_audit_sink = Some(Arc::clone(&relay));
        let rej = l.rejection_audit_sink().expect("sink");
        assert!(std::ptr::addr_eq(rej, Arc::as_ptr(&relay)));
        assert!(!std::ptr::addr_eq(rej, Arc::as_ptr(&main)));
        assert!(Arc::ptr_eq(&l.inner.audit_sink, &main));
        assert!(Arc::ptr_eq(&l.inner.exit_audit_sink(), &main));
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
