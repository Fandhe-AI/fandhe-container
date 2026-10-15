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
//! 6. 分離計画・状態 pipe・中間プロセスの起動(`exec` 側)
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
//! # 未実装・残余(REPAIR-3)
//!
//! - **権限モデル**: `RootlessSingleId` のみ。`RootfulHostRoot`(SEC-5・CORE-7・CORE-9。start が user namespace
//!   を必須とするため、start を通る構成では到達しない。整合は spec 側の判断事項)と `RootlessSubordinateIds`
//!   (CORE-6・TASK-40.2。`LaunchSpec` が uid/gid 写像を持たない)は `Unimplemented` で拒否する
//! - **`confirm_no_process`**: 既定(`Unimplemented`)のまま。中間プロセスが PID 1 を作った後に殺された場合の
//!   pid の把握とあわせて #1817 で実装する。回収できなかった子は [`ProductionLauncher::take_unreaped`] で
//!   取り出せる(握りつぶさない)
//! - **supervisor の結線**: `launch` は呼び出しスレッドで直接呼ぶ必要があり、supervisor の `run_start`
//!   手順 8 と restart の再 launch は別スレッドで呼んでいる。再構成は #1819 の範囲
//! - mounts・bind mount・`/dev` 以外の tmpfs の注入は `start` が拒否済みで、ここでは載せない

#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

#[cfg(target_os = "linux")]
use super::cgroup_requirement::{CgroupJoinMeans, launch_after_cgroup_check};
#[cfg(target_os = "linux")]
use super::config::NamespaceKind;
use super::launch::{LaunchMode, LaunchSpec, LaunchedProcess, ProcessLauncher};
#[cfg(target_os = "linux")]
use crate::audit_log::{AuditSink, AuditedRejection};
#[cfg(target_os = "linux")]
use crate::cgroups::{CgroupError, CgroupJoin};
#[cfg(target_os = "linux")]
use crate::exec::{
    ChildStdio, ChildSubreaper, ContainerChild, Entrypoint, ExecError, Hostname, IntermediateSpec,
    IsolationConfig, IsolationPrivilege, IsolationStage, LaunchAudit, Namespace, NamespaceSet,
    PrePivotSetup, PreparedLaunchFailure, StageKind, StagePipeline, plan,
    spawn_container_via_intermediate,
};
#[cfg(target_os = "linux")]
use crate::landlock::LandlockRuleset;
use crate::traits::{ErrorCode, TraitError};

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

/// 起動失敗の後始末で回収できなかった子(CORE-2・REPAIR-5)。
///
/// `ContainerChild` は drop で kill / wait をしないため、取り出した側が期限つきの `kill_and_reap` で再回収する
/// 責務を負う(孤児化させない)。回収に失敗した理由の `ErrorCode` を添える(メッセージは運ばない)。
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct UnreapedChild {
    child: ContainerChild,
    reason: ErrorCode,
}

#[cfg(target_os = "linux")]
impl UnreapedChild {
    /// 回収できなかった子のハンドル。
    pub fn child(&self) -> &ContainerChild {
        &self.child
    }

    /// ハンドルを取り出す。
    pub fn into_child(self) -> ContainerChild {
        self.child
    }

    /// 回収に失敗した理由。
    pub fn reason(&self) -> ErrorCode {
        self.reason
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

    /// 回収できなかった子(PID 1 または中間プロセス)を取り出す(取り出すと空になる)。
    ///
    /// 起動失敗の後始末で `kill_and_reap` が期限内に終わらなかった子が積まれる。呼び出し側(supervisor・
    /// `confirm_no_process`〔#1817〕)が期限つきで再回収する責務を負う(孤児化させない。CORE-2)。
    #[cfg(target_os = "linux")]
    pub fn take_unreaped(&self) -> Vec<UnreapedChild> {
        std::mem::take(
            &mut *self
                .inner
                .unreaped
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
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
}

/// 起動した PID 1 と、stdout / stderr の読み取り側。
#[cfg(target_os = "linux")]
struct Spawned {
    child: ContainerChild,
    stdout: std::io::PipeReader,
    stderr: std::io::PipeReader,
}

/// Linux の launcher 本体(拒否の判定・順序・写像)。
#[cfg(target_os = "linux")]
struct Inner {
    ops: Box<dyn LaunchOps>,
    privilege: IsolationPrivilege,
    audit_sink: Arc<dyn AuditSink>,
    cgroup_join_source: Option<JoinSource>,
    unreaped: Mutex<Vec<UnreapedChild>>,
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
            unreaped: Mutex::new(Vec::new()),
        }
    }

    fn launch(
        &self,
        spec: &LaunchSpec,
        timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
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
        let audit = LaunchAudit {
            sink: self.audit_sink.as_ref(),
            container: Some(spec.container_id()),
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
            })
            .map_err(|failure| self.absorb_failure(*failure))?;
        let process = super::launch::ContainerChildProcess::new(spawned.child)?
            .with_output(spawned.stdout, spawned.stderr);
        Ok(Box::new(process))
    }

    /// 起動失敗を `TraitError` へ写し、回収できなかった子は保持する(握りつぶさない。#1817 が読む)。
    fn absorb_failure(&self, failure: PreparedLaunchFailure) -> TraitError {
        let PreparedLaunchFailure {
            rejection,
            unreaped,
            reap_error,
        } = failure;
        let AuditedRejection { error, .. } = rejection;
        if let Some(child) = unreaped {
            self.unreaped
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(UnreapedChild {
                    child,
                    reason: reap_error.map_or(ErrorCode::Internal, |e| e.code),
                });
        }
        to_trait_error(&error)
    }
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
            Box::new(PreparedLaunchFailure {
                rejection: AuditedRejection::not_applicable(e),
                unreaped: None,
                reap_error: None,
            })
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
            tmpfs: None,
            inject: None,
            pinned_rootfs: Some(input.spec.rootfs_dir().as_fd()),
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
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::audit_log::AuditRecord;
    use crate::cgroups::CgroupJoin;
    use crate::oci_runtime::parse_config_bytes;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct NullSink;

    impl AuditSink for NullSink {
        fn record(&self, _record: &AuditRecord) -> Result<(), TraitError> {
            Ok(())
        }
    }

    /// 呼び出しの記録と注入ができる偽の実体。
    struct FakeOps {
        events: Arc<Mutex<Vec<String>>>,
        single_threaded: bool,
        /// Landlock の検出を差し替える(`None` なら ABI 6 相当で成功)。
        abi: Option<u32>,
        spawn_calls: AtomicUsize,
        fail_spawn: Option<(ErrorCode, bool)>,
        /// ステージ列を偽のカーネル上で実行して証跡を記録するか(cgroup 参加の段を含む列は実行しない)。
        run_stages: bool,
    }

    impl FakeOps {
        fn new(events: &Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                events: Arc::clone(events),
                single_threaded: true,
                abi: None,
                spawn_calls: AtomicUsize::new(0),
                fail_spawn: None,
                run_stages: true,
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
            if let Some((code, with_child)) = self.fail_spawn {
                return Err(Box::new(PreparedLaunchFailure {
                    rejection: AuditedRejection::not_applicable(ExecError::new(
                        code,
                        IsolationStage::Spawn,
                        "/secret/path errno 13",
                    )),
                    unreaped: with_child.then(|| ContainerChild::from_pid_for_test(2_000_001)),
                    reap_error: with_child.then(|| {
                        ExecError::new(ErrorCode::Timeout, IsolationStage::Wait, "reap failed")
                    }),
                }));
            }
            let (stdout, _w1) = std::io::pipe().unwrap();
            let (stderr, _w2) = std::io::pipe().unwrap();
            Ok(Spawned {
                child: ContainerChild::from_pid_for_test(2_000_002),
                stdout,
                stderr,
            })
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
            "linux": linux
        });
        let config = parse_config_bytes(&serde_json::to_vec(&cfg).unwrap()).unwrap();
        let rootfs = dir.join("rootfs");
        let rootfs_dir = RootfsDir::pin(&dir, &rootfs).expect("pin");
        let namespaces = config.namespaces().iter().map(|n| n.kind()).collect();
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
        let l = launcher(FakeOps::new(&ev), rootless(), None);
        let p = l.launch(&spec, Duration::from_secs(1)).expect("launch");
        assert_eq!(p.pid().get(), 2_000_002);
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
        l.launch(&spec, Duration::from_secs(1)).expect("first");
        l.launch(&spec, Duration::from_secs(1)).expect("second");
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

    /// セキュリティ規約: 失敗の文言は固定で、パス・errno を含めない。回収できなかった子は保持する。
    #[test]
    fn spawn_failure_message_is_fixed_and_unreaped_child_is_kept() {
        let spec = spec_for("fail", serde_json::json!({}));
        let ev = events();
        let mut ops = FakeOps::new(&ev);
        ops.fail_spawn = Some((ErrorCode::Timeout, true));
        let l = launcher(ops, rootless(), None);
        let err = l
            .launch(&spec, Duration::from_secs(1))
            .err()
            .expect("failed");
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(
            err.message(),
            "container launch did not complete within the timeout"
        );
        let kept = l.take_unreaped();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].child().pid(), 2_000_001);
        assert_eq!(kept[0].reason(), ErrorCode::Timeout);
        assert!(l.take_unreaped().is_empty());

        let mut ops = FakeOps::new(&ev);
        ops.fail_spawn = Some((ErrorCode::PermissionDenied, false));
        let l = launcher(ops, rootless(), None);
        let err = l
            .launch(&spec, Duration::from_secs(1))
            .err()
            .expect("failed");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(err.message(), "container launch failed in the Spawn stage");
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
