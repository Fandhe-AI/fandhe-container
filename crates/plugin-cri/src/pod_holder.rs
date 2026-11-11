//! plugin-cri の本番の pod namespace 保持役 provider（Linux のみ。H6・#2877・CRI-2・CORE-1・CORE-3・SEC-5・PLUG-11・REPAIR-5。
//! 設計は `docs/design/pod-namespace-holder.md`）。
//!
//! `fandhe-container-cri` の `PodNamespaceHolderProvider`（注入点。H4・#2871）の本番実装 [`ProductionPodHolder`]。
//! `CriPluginBackends::runtime_service`（`crate::adapter`）が Linux・非 root の本番構成で差し、`CriRuntimeService` の
//! `RunPodSandbox` が `spawn`、`StopPodSandbox`・`RemovePodSandbox` が `release`、Status・List・`CreateContainer` が
//! `liveness` を呼ぶ。保持役の本体は supervisor の bin の `pod-holder` モード（H2・#2874。
//! `fandhe_container_supervisor::pod_holder`）で、本 provider はそれを子プロセスとして起動し READY を受ける側。
//!
//! # 契約
//! - bin は plugin-cri の実体と同じディレクトリの固定名（[`holder_executable_beside`]）。`PATH`・環境変数・引数による
//!   上書きは作らない（PLUG-11）。bin を一度だけ開き、その fd に対して通常ファイル・所有者が root か実効 uid・group / other
//!   書き込み不可・読み取り可（保持役が `would_dump` で自分の実体を開き直すため、読めない bin では成り立たない）を確かめ、
//!   祖先ディレクトリも同じ所有者・書き込み条件で確かめる（fail-closed）。起動は検証した fd を `/proc/self/fd/N` として
//!   exec し、検証後のパス再解決による差し替え（TOCTOU）を避ける。
//! - 子は sandbox の記録が残る間 `wait`（回収）しない。pid を zombie のままでも保って再利用を防ぐ（SEC-5・#2776）。生存は
//!   [`crate::sys::child_exit_observed`]（`waitid(WNOWAIT)`）で見て、回収は `release` が終了を確かめた後に限る。
//! - 追跡する子は [`MAX_TRACKED_POD_HOLDERS`] 件まで（起動途中・回収できなかった子を含む）。起動失敗で SIGKILL 後も回収を
//!   確認できなかった子は sandbox ID 付きで保持し、`spawn` は [`CriError::with_resource_retained`] 付きの `Err` を返す
//!   （CRI は記録を残し、`release` が回収を再試行する）。1 件あたり stdin のパイプ 1 本の
//!   fd を保つ。超えたら `RESOURCE_EXHAUSTED`。
//! - 解放は stdin を閉じる → 期限つきで待つ → SIGKILL → 回収の順。READY・解放・回収の待ちはすべて期限つきで、ロックは
//!   待ちの間は保たない（ブロックしない syscall の間だけ保つ）。エラー文言は固定の英文でパス・pid・errno を含めない（REPAIR-4）。
//!
//! - READY の内容（pid・user / ipc / net の `NsId`）は表に保存する。`open_pod_namespaces`（#4483・SEC-5・SEC-1）は
//!   1 回のロック区間で死活確認・`/proc/<pid>/ns/{user,net}` の open・開いた fd の (dev, ino) と記録の照合を行い、
//!   不在・解放中・終了済み・不一致は `UNAVAILABLE` で fail-closed。区間内は非ブロッキングの syscall だけで、子は回収しない。
//! - supervisor の bin の解決・検査は `open_supervisor_beside` に共通化し、後続の netns-dial helper（#4484）が共有する。
//!
//! # 未実装・簡易実装（REPAIR-3）
//! `open_pod_namespaces` の利用側（`PodNetnsDialer`）は実装済み（#4484）で、PortForward への結線は #4486 で済み（`ProductionPortForward::pod_network`）。
//! 保持役の pid から `PodNamespacePaths` を作って bundle へ渡す配線（H5・#2876）は配線済み（user・ipc の join）。保持役の
//! netns の bundle への受け渡しは H8（#2878）で実装済み。pod ネットワークの本番 provider（rootless の pasta）は H10（#2879）で未実装。素性（pid・
//! starttime・ns）の永続化と再起動後の再採用は R11（#2940）。rootful（uid 0）は `UNIMPLEMENTED`（#2241・#2442 の判断まで）。

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
#[cfg(any(test, feature = "pod-holder-test-support"))]
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::types::{ErrorCode, TraitError};
use fandhe_container_cri::adapter::{
    PodHolder, PodHolderLiveness, PodHolderRequest, PodNamespaceHolderProvider,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_supervisor::pod_holder::{
    NsId, POD_HOLDER_SUBCOMMAND, PodHolderReady, READY_TIMEOUT, holder_executable_beside,
    read_ready,
};

use crate::sys::child_exit_observed;

/// 追跡する保持役の子の上限（`MAX_TRACKED_SUPERVISORS` に倣う。kubelet の既定 maxPods は 110）。
pub const MAX_TRACKED_POD_HOLDERS: usize = 1024;

/// SIGKILL の後に回収を待つ上限。`spawn` の READY の期限と `release` の期限は、この分を残して打ち切る。
pub const POD_HOLDER_KILL_REAP_WAIT: Duration = Duration::from_millis(500);

/// 待ちの刻み。
const POLL_STEP: Duration = Duration::from_millis(10);

const MSG_TOO_MANY: &str = "too many pod holders are tracked";
const MSG_ROOTFUL: &str = "the pod namespace holder requires a non-root plugin process";
const MSG_UNTRUSTED_EXE: &str = "pod holder executable is not trusted or not readable";
/// `sys::O_NONBLOCK` が無い組で bin の open を拒否するときの固定文言（パス・errno・アーキ名を含めない。REPAIR-4）。
const MSG_NONBLOCK_UNSUPPORTED: &str =
    "pod holder executable cannot be opened without blocking on this platform";
const MSG_DUPLICATE: &str = "a pod holder already exists for this sandbox";
const MSG_PID_MISMATCH: &str = "the pod holder reported an unexpected process";
const MSG_NS_MISMATCH: &str = "the pod holder namespaces do not match the report";
const MSG_SPAWN_FAILED: &str = "failed to start the pod holder";
const MSG_POISONED: &str = "pod holder table is unavailable";
const MSG_RELEASE_TIMEOUT: &str = "timed out releasing the pod holder";
const MSG_UNKNOWN: &str = "no pod holder is tracked for this sandbox";
const MSG_LIVENESS: &str = "failed to observe the pod holder";
/// 保持役が無い・解放中・終了済み・pid 不一致（#4483。`UNAVAILABLE` の固定文）。
const MSG_NS_HOLDER_UNAVAILABLE: &str = "the pod holder is not available for this sandbox";
/// 保持役の namespace の open・fstat の失敗（#4483）。
const MSG_NS_OPEN_FAILED: &str = "the pod holder namespaces cannot be opened";
/// 開いた namespace の (dev, ino) が READY の記録と違う（#4483）。
const MSG_NS_IDENTITY_MISMATCH: &str =
    "the pod holder namespaces do not match the recorded identity";

/// 保持役として exec する対象の決め方。
#[derive(Debug, Clone)]
enum ExeSource {
    /// 本番: spawn のたびに `current_exe()` の隣の固定名を解決する。
    Beside,
    /// 試験専用の差し替え（実行ファイルと、`pod-holder` の前に置く引数）。root の拒否と ns の照合は行わない。
    #[cfg(any(test, feature = "pod-holder-test-support"))]
    Fixed {
        program: PathBuf,
        prefix_args: Vec<String>,
        verify_namespaces: bool,
    },
}

/// 追跡中の保持役 1 件。
struct HolderEntry {
    child: Child,
    /// 閉じると保持役が EOF で終わる。`release` が `take` して drop する。
    stdin: Option<ChildStdin>,
    /// READY で受け `verify_ready` を通した内容（pid・user / ipc / net の素性）。`open_pod_namespaces` が開いた fd の
    /// 照合に使う（#4483・SEC-5・SEC-1）。
    ready: PodHolderReady,
}

/// 保持役の user・net namespace の fd と、READY 時に記録した素性（#4483・SEC-5・SEC-1）。
/// `ProductionPodHolder::open_pod_namespaces` が、開いた fd の (dev, ino) を記録と照合してから返す。
#[derive(Debug)]
pub struct PodNamespaceFds {
    user: OwnedFd,
    net: OwnedFd,
    user_id: NsId,
    net_id: NsId,
}

impl PodNamespaceFds {
    /// user namespace の fd。
    pub fn user(&self) -> BorrowedFd<'_> {
        self.user.as_fd()
    }

    /// net namespace の fd。
    pub fn net(&self) -> BorrowedFd<'_> {
        self.net.as_fd()
    }

    /// READY が記録し、fd と一致を確認済みの user namespace の素性。
    pub fn user_id(&self) -> NsId {
        self.user_id
    }

    /// READY が記録し、fd と一致を確認済みの net namespace の素性。
    pub fn net_id(&self) -> NsId {
        self.net_id
    }

    /// 試験専用: 任意の fd と素性から組む（`PodNamespaceSource` の偽実装用）。
    #[cfg(test)]
    pub(crate) fn for_test(user: OwnedFd, net: OwnedFd, user_id: NsId, net_id: NsId) -> Self {
        Self {
            user,
            net,
            user_id,
            net_id,
        }
    }

    /// (user, net) の fd を取り出す（helper へ SCM_RIGHTS で渡す側が所有する）。
    pub fn into_fds(self) -> (OwnedFd, OwnedFd) {
        (self.user, self.net)
    }
}

/// 検証済みの supervisor の bin（fd を保つガード。spawn が終わるまで保持する。PLUG-11）。
pub(crate) struct VerifiedSupervisorExe {
    file: File,
}

impl VerifiedSupervisorExe {
    /// 検証した fd を `/proc/self/fd/N` として exec する Command（検証後のパス再解決を避ける）。
    pub(crate) fn command(&self) -> Command {
        Command::new(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }
}

/// plugin-cri の実体の隣の固定名の supervisor の bin を解決・検査する。保持役の起動と、後続の netns-dial helper
/// （#4484）の起動が同じ検査を共有する（`PATH`・環境変数・引数による上書きは作らない。PLUG-11）。
pub(crate) fn open_supervisor_beside() -> Result<VerifiedSupervisorExe, TraitError> {
    let exe = std::env::current_exe().map_err(|_| {
        TraitError::new(
            ErrorCode::FailedPrecondition,
            "cannot resolve the plugin executable path",
        )
    })?;
    let euid = current_euid().map_err(|()| {
        TraitError::new(
            ErrorCode::FailedPrecondition,
            "cannot determine the plugin process credentials",
        )
    })?;
    open_supervisor_beside_at(&exe, euid)
}

/// [`open_supervisor_beside`] の本体（試験で exe と euid を注入する）。
fn open_supervisor_beside_at(exe: &Path, euid: u32) -> Result<VerifiedSupervisorExe, TraitError> {
    let program = holder_executable_beside(exe)?;
    check_ancestors_trust(&program, euid)?;
    let file = open_trusted_executable(&program, euid)?;
    Ok(VerifiedSupervisorExe { file })
}

#[derive(Default)]
struct Table {
    entries: HashMap<String, HolderEntry>,
    /// 起動途中の sandbox ID（同時の二重起動と上限の数に含める）。
    spawning: HashSet<String>,
    /// SIGKILL の後も回収を確認できなかった子（sandbox ID 付き。上限に数え、`release` と次の `spawn` で回収を試みる）。
    orphans: HashMap<String, Child>,
}

/// 本番の保持役 provider。注入口は `CriPluginBackends`（`crate::adapter`）。
pub struct ProductionPodHolder {
    exe: ExeSource,
    limit: usize,
    table: Mutex<Table>,
}

impl std::fmt::Debug for ProductionPodHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProductionPodHolder")
            .finish_non_exhaustive()
    }
}

impl ProductionPodHolder {
    /// 本番の provider（bin は plugin-cri の実体の隣の固定名。上限は [`MAX_TRACKED_POD_HOLDERS`]）。
    pub fn production() -> Self {
        Self {
            exe: ExeSource::Beside,
            limit: MAX_TRACKED_POD_HOLDERS,
            table: Mutex::new(Table::default()),
        }
    }

    /// 試験専用: 実行ファイルと上限を差し替える。`program` は `prefix_args` と `pod-holder` の順で引数を受ける。
    /// `verify_namespaces` が偽なら READY 後の `/proc/<pid>/ns/*` の照合を行わない（偽の保持役用）。
    #[cfg(any(test, feature = "pod-holder-test-support"))]
    pub fn with_fixed_program(
        program: PathBuf,
        prefix_args: Vec<String>,
        verify_namespaces: bool,
        limit: usize,
    ) -> Self {
        Self {
            exe: ExeSource::Fixed {
                program,
                prefix_args,
                verify_namespaces,
            },
            limit,
            table: Mutex::new(Table::default()),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Table>, TraitError> {
        self.table
            .lock()
            .map_err(|_| TraitError::new(ErrorCode::Internal, MSG_POISONED))
    }

    fn rootful_guard(&self) -> Result<(), TraitError> {
        if !matches!(self.exe, ExeSource::Beside) {
            return Ok(());
        }
        match current_euid() {
            Ok(0) => Err(TraitError::new(ErrorCode::Unimplemented, MSG_ROOTFUL)),
            Ok(_) => Ok(()),
            Err(()) => Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "cannot determine the plugin process credentials",
            )),
        }
    }

    /// 起動する Command を決め、bin を検査する。本番は検証済みの fd を返し、Command はその fd を
    /// `/proc/self/fd/N` として exec する（呼び出し側は spawn が終わるまで返された `File` を保つ）。
    fn resolve_command(&self) -> Result<(Command, Option<VerifiedSupervisorExe>), TraitError> {
        match &self.exe {
            ExeSource::Beside => {
                let verified = open_supervisor_beside()?;
                let cmd = verified.command();
                Ok((cmd, Some(verified)))
            }
            #[cfg(any(test, feature = "pod-holder-test-support"))]
            ExeSource::Fixed {
                program,
                prefix_args,
                ..
            } => {
                let mut c = Command::new(program);
                c.args(prefix_args);
                Ok((c, None))
            }
        }
    }

    fn verify_namespaces(&self) -> bool {
        match &self.exe {
            ExeSource::Beside => true,
            #[cfg(any(test, feature = "pod-holder-test-support"))]
            ExeSource::Fixed {
                verify_namespaces, ..
            } => *verify_namespaces,
        }
    }

    /// 子を起動して READY を検証する。失敗時は子を SIGKILL して回収を試み、回収できなかった子を返す。
    fn start_child(
        &self,
        ready_timeout: Duration,
    ) -> Result<(Child, ChildStdin, PodHolderReady), (TraitError, Option<Child>)> {
        let (mut cmd, exe_fd) = self.resolve_command().map_err(|e| (e, None))?;
        cmd.arg(POD_HOLDER_SUBCOMMAND)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let spawned = cmd.spawn();
        // 子は exec 済み（または失敗）なので、検証済み fd はここで閉じてよい。
        drop(exe_fd);
        let mut child = spawned.map_err(|_| {
            (
                TraitError::new(ErrorCode::Unavailable, MSG_SPAWN_FAILED),
                None,
            )
        })?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let left = kill_and_reap(child);
            return Err((TraitError::new(ErrorCode::Internal, MSG_SPAWN_FAILED), left));
        };
        let wait = ready_timeout
            .saturating_sub(POD_HOLDER_KILL_REAP_WAIT)
            .min(READY_TIMEOUT);
        let ready = match read_ready(stdout.as_fd(), Instant::now() + wait) {
            Ok(r) => r,
            Err(e) => {
                drop(stdin);
                return Err((e, kill_and_reap(child)));
            }
        };
        drop(stdout);
        if let Err(e) = self.verify_ready(&child, &ready) {
            drop(stdin);
            return Err((e, kill_and_reap(child)));
        }
        Ok((child, stdin, ready))
    }

    /// READY の pid が spawn した子と一致し、`/proc/<pid>/ns/{user,ipc,net}` の素性が READY と一致することを確かめる。
    /// この stat は ptrace のアクセス検査を通るため、再 exec で non-dumpable を保つ前提の直接の確認にもなる。
    fn verify_ready(&self, child: &Child, ready: &PodHolderReady) -> Result<(), TraitError> {
        if ready.pid() != child.id() {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                MSG_PID_MISMATCH,
            ));
        }
        if !self.verify_namespaces() {
            return Ok(());
        }
        for (name, want) in [
            ("user", ready.user()),
            ("ipc", ready.ipc()),
            ("net", ready.net()),
        ] {
            let path = format!("/proc/{}/ns/{name}", ready.pid());
            let got = std::fs::metadata(path)
                .map_err(|_| TraitError::new(ErrorCode::FailedPrecondition, MSG_NS_MISMATCH))?;
            if (NsId {
                dev: got.dev(),
                ino: got.ino(),
            }) != want
            {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    MSG_NS_MISMATCH,
                ));
            }
        }
        Ok(())
    }

    /// `Err` の第 2 要素は、SIGKILL の後も回収を確認できない子が `orphans` に残った（資源が残りうる）こと。
    fn spawn_inner(&self, req: &PodHolderRequest<'_>) -> Result<PodHolder, (TraitError, bool)> {
        self.rootful_guard().map_err(|e| (e, false))?;
        let id = req.sandbox_id.to_owned();
        {
            let mut t = self.lock().map_err(|e| (e, false))?;
            if t.entries.contains_key(&id) || t.spawning.contains(&id) {
                return Err((
                    TraitError::new(ErrorCode::AlreadyExists, MSG_DUPLICATE),
                    false,
                ));
            }
            if t.orphans.contains_key(&id) {
                return Err((
                    TraitError::new(ErrorCode::AlreadyExists, MSG_DUPLICATE),
                    false,
                ));
            }
            t.orphans.retain(|_, c| matches!(c.try_wait(), Ok(None)));
            if t.entries.len() + t.spawning.len() + t.orphans.len() >= self.limit {
                return Err((
                    TraitError::new(ErrorCode::ResourceExhausted, MSG_TOO_MANY),
                    false,
                ));
            }
            t.spawning.insert(id.clone());
        }
        let started = self.start_child(req.ready_timeout());
        let mut t = self.lock().map_err(|e| (e, false))?;
        t.spawning.remove(&id);
        match started {
            Ok((child, stdin, ready)) => {
                let Some(pid) = std::num::NonZeroU32::new(child.id()) else {
                    drop(stdin);
                    if let Some(left) = kill_and_reap(child) {
                        t.orphans.insert(id, left);
                        return Err((TraitError::new(ErrorCode::Internal, MSG_PID_MISMATCH), true));
                    }
                    return Err((
                        TraitError::new(ErrorCode::Internal, MSG_PID_MISMATCH),
                        false,
                    ));
                };
                t.entries.insert(
                    id,
                    HolderEntry {
                        child,
                        stdin: Some(stdin),
                        ready,
                    },
                );
                Ok(PodHolder::new(pid))
            }
            Err((e, left)) => {
                let retained = left.is_some();
                if let Some(c) = left {
                    t.orphans.insert(id, c);
                }
                Err((e, retained))
            }
        }
    }

    /// `until` まで、`id` の子の終了を回収せずに待つ。終了していれば（または追跡が無ければ）`true`。
    fn wait_exited_until(&self, id: &str, until: Instant) -> Result<bool, TraitError> {
        loop {
            {
                let t = self.lock()?;
                let Some(e) = t.entries.get(id) else {
                    return Ok(true);
                };
                let pid = std::num::NonZeroU32::new(e.child.id())
                    .ok_or_else(|| TraitError::new(ErrorCode::Internal, MSG_LIVENESS))?;
                match child_exit_observed(pid) {
                    Ok(true) => return Ok(true),
                    Ok(false) => {}
                    Err(_) => return Err(TraitError::new(ErrorCode::Internal, MSG_LIVENESS)),
                }
            }
            let now = Instant::now();
            if now >= until {
                return Ok(false);
            }
            std::thread::sleep(POLL_STEP.min(until - now));
        }
    }

    /// 起動失敗で回収できなかった子（`orphans`）を、`deadline` まで SIGKILL と回収で再試行する。回収できたか、
    /// 追跡が無ければ `Ok`。回収できなければ `Timeout`（子は `orphans` に残り、再試行できる）。
    fn reap_orphan_until(&self, sandbox_id: &str, deadline: Instant) -> Result<(), TraitError> {
        loop {
            {
                let mut t = self.lock()?;
                let Some(c) = t.orphans.get_mut(sandbox_id) else {
                    return Ok(());
                };
                let _ = c.kill();
                // 状態を取れない子（既に回収済み等）はこれ以上できないので追跡から外す。
                if !matches!(c.try_wait(), Ok(None)) {
                    t.orphans.remove(sandbox_id);
                    return Ok(());
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(TraitError::new(ErrorCode::Timeout, MSG_RELEASE_TIMEOUT));
            }
            std::thread::sleep(POLL_STEP.min(deadline - now));
        }
    }

    fn release_inner(&self, sandbox_id: &str, timeout: Duration) -> Result<(), TraitError> {
        let deadline = Instant::now() + timeout;
        {
            let mut t = self.lock()?;
            if !t.entries.contains_key(sandbox_id) {
                drop(t);
                return self.reap_orphan_until(sandbox_id, deadline);
            }
            let Some(e) = t.entries.get_mut(sandbox_id) else {
                return Ok(());
            };
            // 閉じて EOF を届ける（保持役は EOF で 0 終了する）。
            drop(e.stdin.take());
        }
        let soft = deadline - POD_HOLDER_KILL_REAP_WAIT.min(timeout / 2);
        if !self.wait_exited_until(sandbox_id, soft)? {
            if let Some(e) = self.lock()?.entries.get_mut(sandbox_id) {
                let _ = e.child.kill();
            }
            if !self.wait_exited_until(sandbox_id, deadline)? {
                return Err(TraitError::new(ErrorCode::Timeout, MSG_RELEASE_TIMEOUT));
            }
        }
        // 終了を確かめた後に限り回収する（既に終了しているので待たない）。
        let mut t = self.lock()?;
        if let Some(mut e) = t.entries.remove(sandbox_id) {
            let _ = e.child.wait();
        }
        Ok(())
    }

    fn liveness_inner(&self, sandbox_id: &str) -> Result<PodHolderLiveness, TraitError> {
        let t = self.lock()?;
        let e = t
            .entries
            .get(sandbox_id)
            .ok_or_else(|| TraitError::new(ErrorCode::NotFound, MSG_UNKNOWN))?;
        let pid = std::num::NonZeroU32::new(e.child.id())
            .ok_or_else(|| TraitError::new(ErrorCode::Internal, MSG_LIVENESS))?;
        match child_exit_observed(pid) {
            Ok(false) => Ok(PodHolderLiveness::Alive),
            Ok(true) => Ok(PodHolderLiveness::Exited),
            Err(_) => Err(TraitError::new(ErrorCode::Internal, MSG_LIVENESS)),
        }
    }

    /// sandbox の保持役の `/proc/<pid>/ns/{user,net}` を開き、READY の `NsId` と照合して返す（#4483・SEC-5・SEC-1。
    /// 呼び出し元は #4484 の `PodNetnsDialer`）。
    ///
    /// 1 回のロック区間で、非ブロッキングの syscall（`waitid(WNOHANG)`・nsfs の open・fstat）だけを使う。照合はパスでは
    /// なく開いた fd に対して行う。表に無い・解放中・終了済み・不一致・open の失敗はすべて `UNAVAILABLE` で fail-closed
    /// にし、host の namespace へは縮退しない。子は回収しない（pid の再利用を避ける。回収は同じロックの中の `release`）。
    pub fn open_pod_namespaces(&self, sandbox_id: &str) -> Result<PodNamespaceFds, TraitError> {
        self.open_pod_namespaces_at(sandbox_id, Path::new("/proc"))
    }

    /// [`Self::open_pod_namespaces`] の本体。`proc_root` を `/proc` 以外にできるのは試験だけ。
    fn open_pod_namespaces_at(
        &self,
        sandbox_id: &str,
        proc_root: &Path,
    ) -> Result<PodNamespaceFds, TraitError> {
        let unavailable = || TraitError::new(ErrorCode::Unavailable, MSG_NS_HOLDER_UNAVAILABLE);
        let t = self.lock()?;
        let e = t.entries.get(sandbox_id).ok_or_else(unavailable)?;
        if e.stdin.is_none() {
            return Err(unavailable());
        }
        let pid = std::num::NonZeroU32::new(e.child.id())
            .filter(|p| p.get() == e.ready.pid())
            .ok_or_else(unavailable)?;
        if !matches!(child_exit_observed(pid), Ok(false)) {
            return Err(unavailable());
        }
        let ns_dir = proc_root.join(pid.get().to_string()).join("ns");
        let open = |name: &str| -> Result<(File, NsId), TraitError> {
            let failed = || TraitError::new(ErrorCode::Unavailable, MSG_NS_OPEN_FAILED);
            let f = File::open(ns_dir.join(name)).map_err(|_| failed())?;
            let m = f.metadata().map_err(|_| failed())?;
            Ok((
                f,
                NsId {
                    dev: m.dev(),
                    ino: m.ino(),
                },
            ))
        };
        let (user, user_id) = open("user")?;
        let (net, net_id) = open("net")?;
        if user_id != e.ready.user() || net_id != e.ready.net() {
            return Err(TraitError::new(
                ErrorCode::Unavailable,
                MSG_NS_IDENTITY_MISMATCH,
            ));
        }
        // open と照合の間に終わった場合の多層防御。
        if !matches!(child_exit_observed(pid), Ok(false)) {
            return Err(unavailable());
        }
        Ok(PodNamespaceFds {
            user: user.into(),
            net: net.into(),
            user_id,
            net_id,
        })
    }

    /// 試験専用: 起動済みの子を表に入れる。
    #[cfg(test)]
    fn insert_for_test(
        &self,
        id: &str,
        child: Child,
        stdin: Option<ChildStdin>,
        ready: PodHolderReady,
    ) {
        self.table.lock().unwrap().entries.insert(
            id.to_owned(),
            HolderEntry {
                child,
                stdin,
                ready,
            },
        );
    }
}

impl PodNamespaceHolderProvider for ProductionPodHolder {
    fn spawn(&self, req: &PodHolderRequest<'_>) -> Result<PodHolder, CriError> {
        self.spawn_inner(req).map_err(|(e, retained)| {
            let err = CriError::from(&e);
            if retained {
                err.with_resource_retained()
            } else {
                err
            }
        })
    }

    fn release(&self, sandbox_id: &str, timeout: Duration) -> Result<(), CriError> {
        self.release_inner(sandbox_id, timeout)
            .map_err(|e| CriError::from(&e))
    }

    fn liveness(&self, sandbox_id: &str) -> Result<PodHolderLiveness, CriError> {
        self.liveness_inner(sandbox_id)
            .map_err(|e| CriError::from(&e))
    }
}

/// SIGKILL を送り、[`POD_HOLDER_KILL_REAP_WAIT`] まで回収を待つ。回収できなければ子を返す（呼び出し側が orphan として数える）。
fn kill_and_reap(mut child: Child) -> Option<Child> {
    let _ = child.kill();
    let until = Instant::now() + POD_HOLDER_KILL_REAP_WAIT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return None,
            Ok(None) => {}
            // 既に回収済み等で状態を取れない子は、これ以上できない。
            Err(_) => return None,
        }
        let now = Instant::now();
        if now >= until {
            return Some(child);
        }
        std::thread::sleep(POLL_STEP.min(until - now));
    }
}

/// bin を一度だけ開き、開いた fd に対して検査する（検査と exec の間でパスが差し替わっても、検証した実体を使う。PLUG-11）。
/// 通常ファイル・所有者が root か `euid`・group / other に書き込み不可・読み取り専用で開ける、を満たすときだけ返す。
/// `resolve_command` から呼ばれ、`O_NONBLOCK` の値は `sys` の 1 か所の宣言を使う（MVM-4・REPAIR-1・#4441）。
fn open_trusted_executable(path: &Path, euid: u32) -> Result<File, TraitError> {
    open_trusted_executable_with(path, euid, crate::sys::O_NONBLOCK)
}

/// `open_trusted_executable` の本体。`nonblock` を注入できるのは、`None` の組の拒否を x86_64 でも試験するため。
fn open_trusted_executable_with(
    path: &Path,
    euid: u32,
    nonblock: Option<i32>,
) -> Result<File, TraitError> {
    let bad = || TraitError::new(ErrorCode::FailedPrecondition, MSG_UNTRUSTED_EXE);
    // `sys::O_NONBLOCK` が `None` の組（Linux の x86_64・aarch64 以外）では、O_NONBLOCK なしで開くと書き手の居ない
    // FIFO の open が無期限に戻らないため（REPAIR-5）、open せず `FAILED_PRECONDITION` と固定文言で拒否する
    // （fail-closed）。値の宣言は `sys` の 1 か所に寄せる（MVM-4・REPAIR-1・#4441）。
    let Some(flag) = nonblock else {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            MSG_NONBLOCK_UNSUPPORTED,
        ));
    };
    // 保持役は自分の実体を開き直すため、読めない bin では成り立たない（`would_dump` の MAY_READ の代理）。
    // FIFO 等で open が無期限にブロックしないよう `sys::O_NONBLOCK` で開き、同じ fd の種別を fstat で検証する（REPAIR-5）。
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flag)
        .open(path)
        .map_err(|_| bad())?;
    let meta = file.metadata().map_err(|_| bad())?;
    if !meta.is_file() || !(meta.uid() == 0 || meta.uid() == euid) || meta.mode() & 0o022 != 0 {
        return Err(bad());
    }
    Ok(file)
}

/// bin の祖先ディレクトリの検査: すべて所有者が root か `euid`で group / other に書き込み不可（別ユーザーが
/// 祖先を書き換えて bin を差し替えられないこと。PLUG-11）。symlink は辿った先を見る。
fn check_ancestors_trust(path: &Path, euid: u32) -> Result<(), TraitError> {
    let bad = || TraitError::new(ErrorCode::FailedPrecondition, MSG_UNTRUSTED_EXE);
    let real = std::fs::canonicalize(path).map_err(|_| bad())?;
    for dir in real.ancestors().skip(1) {
        let meta = std::fs::metadata(dir).map_err(|_| bad())?;
        // sticky ビットつきで root 所有の祖先（`/tmp` 等）は、他者が自分の所有でない子を改名・削除できない
        // ため許容する。直下の子は次の反復で所有者検査を受ける。
        let sticky_root = meta.uid() == 0 && meta.mode() & 0o1000 != 0;
        if !meta.is_dir() || !(meta.uid() == 0 || meta.uid() == euid) {
            return Err(bad());
        }
        if meta.mode() & 0o022 != 0 && !sticky_root {
            return Err(bad());
        }
    }
    Ok(())
}

/// 実効 uid（`/proc/self/status`）。root（real か effective が 0）なら 0 を返す。読めなければ `Err`。
fn current_euid() -> Result<u32, ()> {
    use std::io::Read as _;
    let mut text = String::new();
    std::fs::File::open("/proc/self/status")
        .and_then(|f| f.take(64 * 1024).read_to_string(&mut text))
        .map_err(|_| ())?;
    let snap = fandhe_container_supervisor::privilege::parse_proc_status(&text).map_err(|_| ())?;
    if snap.uid.real == 0 || snap.uid.effective == 0 {
        return Ok(0);
    }
    Ok(snap.uid.effective)
}

/// 保持役 provider を注入するか（Linux の本番構成）。実効 uid が 0 と確定したときだけ注入しない（従来の rootful の挙動を
/// 保つ）。読めない場合は注入し、provider の `spawn` の検査が fail-closed で落とす。
pub fn should_inject_pod_holder<E>(euid: Result<u32, E>) -> bool {
    !matches!(euid, Ok(0))
}

/// 現在のプロセスについて [`should_inject_pod_holder`] の入力を得る。
pub(crate) fn inject_for_current_process() -> bool {
    should_inject_pod_holder(current_euid())
}

#[cfg(test)]
mod tests;
