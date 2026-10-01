//! OCI Runtime の `kill`（起動中コンテナのプロセスへシグナルを送る。TASK-30.1・CORE-2・OCI-6）。
//!
//! # 役割と呼び出し元
//!
//! `start`（TASK-29.3）が Running（pid あり）にしたコンテナへ、指定シグナルを 1 つ送る。将来の
//! plugin 側 `ContainerRuntime::kill` 実装・CLI が呼び出し元になる。`ContainerRuntime` の実装は
//! plugin 側に置く（PLUG-1）ため、create / start と同じく `StateStore` と送信境界
//! [`ProcessSignaler`] を依存注入で受ける自由関数とした。
//!
//! # 処理順（ERR-2・REPAIR-4）
//!
//! 1. 操作名 `kill` で `OpRecorder` に記録する（全終了経路）
//! 2. `StateStore::get`。未 create の ID は `NotFound`（signaler は呼ばない）
//! 3. 状態の確認。`Running`・pid あり（と将来の `Created`・pid あり）だけ送信へ進む。`Running`・pid なし
//!    （中断された start の予約）と、それ以外（`Created`・pid なし / `Creating` / `Stopped`）は
//!    `FailedPrecondition`
//! 4. [`ProcessSignaler::signal`] を `call_bounded` で上限つきに呼ぶ（REPAIR-5）。kill 全体の絶対期限を
//!    signaler 経由で `ContainerChild` まで渡し、実際の送信直前（回収状態のロック取得後）に期限を確認する。
//!    `Timeout` 後に遅れて起動・復帰した worker は、呼ぶ直前の印・期限確認と送信直前の期限確認で送信を抑止する
//!
//! # PID 再利用対策（SEC-1・CORE-1）
//!
//! `StateStore` に記録された pid へ生の `kill(2)` は送らない。記録と送信の間にプロセスが回収される
//! と、pid が無関係のプロセスへ再利用されている可能性があるためである。送信は、起動ハンドル
//! （`LaunchedProcess`。start が返す）を持つ [`ProcessSignaler`] の実装だけが行い、回収状態の排他の下で
//! 未回収の自分の子にだけ送る（`ContainerChildProcess::signal` → `ContainerChild::send_signal`）。
//!
//! # 到達範囲（REPAIR-3）
//!
//! - kill は終了を待たず、状態も更新しない（`ContainerRuntime::kill` の契約）。戻り値は照合した時点の
//!   状態。終了を検知して Stopped へ遷移させるのは起動ハンドルの所有者（supervisor。TASK-157）の責務
//! - 本番の [`ProcessSignaler`] は本 crate に無い（supervisor が提供する。launcher と同じ扱い）
//! - delete（`delete.rs`。状態ファイル・cgroup の削除は TASK-30.2・TASK-30.3）・cgroup 配下の全プロセスへの
//!   送信（TASK-32・CORE-3）・stop（SIGTERM → 猶予 → SIGKILL）は範囲外
//!
//! エラーメッセージは固定文言のみで、pid・パス・errno を含めない。

use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::LAUNCHER_REPLY_GRACE;
use super::launch::START_TIMEOUT_MAX;
use super::start::{Unbounded, call_bounded};
use crate::observability::{OpName, OpRecorder};
use crate::traits::{
    ContainerId, ContainerState, ContainerStatus, ErrorCode, GetStateRequest, KillRequest, Signal,
    StateStore, TraitError,
};

/// [`OpRecorder`] に記録する操作名（REPAIR-4）。
const KILL_OP_NAME: &str = "kill";

/// シグナル送信の境界（PID 再利用対策。SEC-1・CORE-1）。
///
/// # 契約
///
/// - 送る先は、自分が保持する `id` の起動ハンドル（start が返した [`super::LaunchedProcess`]）だけにする。
///   `pid`（状態記録の値）へ生の `kill(2)` を送ってはならない
/// - ハンドルが無い、またはハンドルの pid と `pid` が食い違う場合は、送らずに `FailedPrecondition` を返す
/// - `deadline` は [`kill`] が `Timeout` を返す時刻以前の絶対期限。実装は実際の送信の直前に確認し、
///   期限切れなら送らずに `Timeout` を返す（期限後にシグナルが届かない。REPAIR-5）。呼び出し側も別スレッドで
///   上限を強制する
/// - 別スレッドから呼ばれ得るため `Send + Sync`
///
/// 本番実装は supervisor（TASK-157）が提供する（本 crate には無い。REPAIR-3）。
pub trait ProcessSignaler: Send + Sync {
    /// `id` の起動ハンドルへ `signal` を 1 つ送る。終了は待たない。
    fn signal(
        &self,
        id: &ContainerId,
        pid: NonZeroU32,
        signal: Signal,
        deadline: Instant,
    ) -> Result<(), TraitError>;
}

/// [`kill`] が signaler を待つ上限時間（REPAIR-5）。
///
/// 0 と [`START_TIMEOUT_MAX`] 超過（無期限相当）を型で表せない。境界での打ち切りは、この値に
/// `LAUNCHER_REPLY_GRACE`（1 秒）を足した時点で行う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KillTimeout(Duration);

impl KillTimeout {
    /// 既定の上限（子プロセス応答待ちの推奨 5〜10 秒の範囲。AGENTS.md・REPAIR-5）。
    pub const DEFAULT: Duration = Duration::from_secs(5);

    /// 上限を検証して作る。0 または [`START_TIMEOUT_MAX`] 超過は `InvalidArgument`。
    pub fn new(value: Duration) -> Result<Self, TraitError> {
        if value.is_zero() || value > START_TIMEOUT_MAX {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("kill timeout must be greater than zero and at most {START_TIMEOUT_MAX:?}"),
            ));
        }
        Ok(Self(value))
    }

    /// 上限の値。
    pub fn get(&self) -> Duration {
        self.0
    }
}

impl Default for KillTimeout {
    fn default() -> Self {
        Self(Self::DEFAULT)
    }
}

/// 起動中コンテナのプロセスへ `req` のシグナルを送る。
///
/// 戻り値は照合した時点の [`ContainerStatus`]（終了を待たず、状態も更新しない）。未 create の ID は
/// [`ErrorCode::NotFound`]、送信できない状態は [`ErrorCode::FailedPrecondition`]、signaler の応答が上限
/// （`timeout`）を超えたら [`ErrorCode::Timeout`]。成功・失敗の件数と所要時間は `recorder` へ操作名
/// `kill` で記録する（全終了経路。REPAIR-4）。
pub fn kill(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    signaler: &Arc<dyn ProcessSignaler>,
    req: &KillRequest,
    timeout: &KillTimeout,
) -> Result<ContainerStatus, TraitError> {
    let name = OpName::new(KILL_OP_NAME)?;
    recorder.record_op(&name, || kill_inner(store, signaler, req, timeout))
}

fn kill_inner(
    store: &dyn StateStore,
    signaler: &Arc<dyn ProcessSignaler>,
    req: &KillRequest,
    timeout: &KillTimeout,
) -> Result<ContainerStatus, TraitError> {
    let record = store.get(&GetStateRequest::new(req.id().clone()))?;
    let status = record.status();
    let pid = match (status.state(), status.pid()) {
        // created の init へも kill できる（OCI）。現行の create は pid を持たないため将来用の分岐。
        (ContainerState::Running | ContainerState::Created, Some(pid)) => pid,
        (ContainerState::Running, None) => {
            // start と同じ文言で、中断された start の予約だと識別できるようにする。
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "container start was interrupted; recover the start reservation",
            ));
        }
        _ => {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "container is not running",
            ));
        }
    };
    let limit = timeout.get();
    let s = Arc::clone(signaler);
    let id = req.id().clone();
    let signal = req.signal();
    // 送信先まで引き継ぐ共通の絶対期限。`call_bounded` が `Timeout` を返す時刻（開始後に算出する
    // `limit` ＋ 猶予）より前に切れるよう、呼び出しの前に算出する。
    let deadline = Instant::now()
        .checked_add(limit.saturating_add(LAUNCHER_REPLY_GRACE))
        .ok_or_else(|| TraitError::new(ErrorCode::InvalidArgument, "kill timeout is too large"))?;
    // 呼び出し側が `Timeout` を返した後に、遅れて起動・復帰した worker が送信しないための印。
    let expired = Arc::new(AtomicBool::new(false));
    let worker_expired = Arc::clone(&expired);
    let call = move || {
        if worker_expired.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "the signal delivery did not complete within the timeout",
            ));
        }
        s.signal(&id, pid, signal, deadline)
    };
    let outcome = call_bounded(limit, call, drop);
    if outcome.is_err() {
        expired.store(true, Ordering::SeqCst);
    }
    match outcome {
        Ok(result) => result?,
        Err(Unbounded::TimedOut) => {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "the signal delivery did not complete within the timeout",
            ));
        }
        Err(Unbounded::SpawnFailed) => {
            return Err(TraitError::new(
                ErrorCode::Internal,
                "failed to run the process signaler",
            ));
        }
    }
    Ok(status.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{
        CreateStateRequest, DeleteStateRequest, DeleteStateResponse, ListStateRequest, StateList,
        StateRecord, StateRevision, UpdateStateRequest,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    /// テスト専用の読み取り中心のインメモリ `StateStore`（kill は get しか使わない）。
    #[derive(Default)]
    struct MemStateStore(Mutex<HashMap<ContainerId, StateRecord>>);

    impl MemStateStore {
        fn with(status: ContainerStatus) -> Self {
            let s = Self::default();
            s.create(
                &CreateStateRequest::new(status, std::env::temp_dir().join("b")).expect("req"),
            )
            .expect("create");
            s
        }
    }

    impl StateStore for MemStateStore {
        fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            let record = StateRecord::new(
                req.status().clone(),
                req.bundle().to_path_buf(),
                StateRevision::from_raw(1),
            )?;
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(req.id().clone(), record.clone());
            Ok(record)
        }
        fn update(&self, _req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(req.id())
                .cloned()
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))
        }
        fn list(&self, _req: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn delete(&self, _req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
    }

    /// 呼び出しを記録する偽の signaler（`delay` だけ眠る）。
    struct FakeSignaler {
        calls: Mutex<Vec<(ContainerId, u32, u8)>>,
        count: AtomicUsize,
        delay: Duration,
    }

    impl FakeSignaler {
        fn new(delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                count: AtomicUsize::new(0),
                delay,
            })
        }
    }

    impl ProcessSignaler for FakeSignaler {
        fn signal(
            &self,
            id: &ContainerId,
            pid: NonZeroU32,
            signal: Signal,
            _deadline: Instant,
        ) -> Result<(), TraitError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.calls.lock().unwrap_or_else(|e| e.into_inner()).push((
                id.clone(),
                pid.get(),
                signal.as_u8(),
            ));
            std::thread::sleep(self.delay);
            Ok(())
        }
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).expect("id")
    }

    fn req(id: &str, signal: Signal) -> KillRequest {
        KillRequest::new(cid(id), signal)
    }

    fn run(
        store: &MemStateStore,
        signaler: &Arc<FakeSignaler>,
        id: &str,
    ) -> Result<ContainerStatus, TraitError> {
        let dynamic: Arc<dyn ProcessSignaler> = signaler.clone();
        kill(
            store,
            &OpRecorder::new(),
            &dynamic,
            &req(id, Signal::SIGTERM),
            &KillTimeout::default(),
        )
    }

    /// OCI-6（受入基準 2）: 存在しない ID は `NotFound` で、signaler は呼ばれない。
    #[test]
    fn oci6_kill_unknown_id_returns_not_found() {
        let store = MemStateStore::default();
        let signaler = FakeSignaler::new(Duration::ZERO);
        let err = run(&store, &signaler, "missing").expect_err("not found");
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(signaler.count.load(Ordering::SeqCst), 0);
    }

    /// CORE-2: pid のない Created・Stopped・Creating は送らず `FailedPrecondition`。
    #[test]
    fn core2_kill_rejects_created_without_pid_and_stopped() {
        for status in [
            ContainerStatus::created(cid("c1"), None),
            ContainerStatus::stopped(cid("c1"), Some(0)),
            ContainerStatus::creating(cid("c1")),
        ] {
            let store = MemStateStore::with(status);
            let signaler = FakeSignaler::new(Duration::ZERO);
            let err = run(&store, &signaler, "c1").expect_err("rejected");
            assert_eq!(err.code(), ErrorCode::FailedPrecondition);
            assert_eq!(err.message(), "container is not running");
            assert_eq!(signaler.count.load(Ordering::SeqCst), 0);
        }
    }

    /// CORE-2: Running・pid なし（中断された start の予約）は送らず、識別できる文言で拒否する。
    #[test]
    fn core2_kill_rejects_interrupted_start() {
        let store = MemStateStore::with(ContainerStatus::running(cid("c1"), None));
        let signaler = FakeSignaler::new(Duration::ZERO);
        let err = run(&store, &signaler, "c1").expect_err("rejected");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container start was interrupted; recover the start reservation"
        );
        assert_eq!(signaler.count.load(Ordering::SeqCst), 0);
    }

    /// CORE-2・OCI-6: Running(pid=4242) への SIGTERM は (id, 4242, 15) が 1 回 signaler へ届き、状態は更新しない。
    #[test]
    fn core2_kill_forwards_id_pid_and_signal() {
        let pid = NonZeroU32::new(4242).expect("pid");
        let store = MemStateStore::with(ContainerStatus::running(cid("c1"), Some(pid)));
        let signaler = FakeSignaler::new(Duration::ZERO);
        let status = run(&store, &signaler, "c1").expect("kill");
        assert_eq!(
            signaler.calls.lock().unwrap().as_slice(),
            &[(cid("c1"), 4242, 15)]
        );
        assert_eq!(status.state(), ContainerState::Running);
        assert_eq!(status.pid(), Some(pid));
        let stored = store
            .get(&GetStateRequest::new(cid("c1")))
            .expect("get")
            .status()
            .clone();
        assert_eq!(stored, status);
    }

    /// REPAIR-5: signaler が上限を守らず戻らなくても、上限＋猶予で `Timeout` を返す。
    #[test]
    fn repair5_kill_times_out_when_signaler_blocks() {
        let pid = NonZeroU32::new(4242).expect("pid");
        let store = MemStateStore::with(ContainerStatus::running(cid("c1"), Some(pid)));
        let signaler = FakeSignaler::new(Duration::from_secs(5));
        let dynamic: Arc<dyn ProcessSignaler> = signaler.clone();
        let limit = Duration::from_millis(50);
        let started = Instant::now();
        let err = kill(
            &store,
            &OpRecorder::new(),
            &dynamic,
            &req("c1", Signal::SIGKILL),
            &KillTimeout::new(limit).expect("timeout"),
        )
        .expect_err("timeout");
        let elapsed = started.elapsed();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(
            err.message(),
            "the signal delivery did not complete within the timeout"
        );
        assert!(elapsed >= limit, "elapsed {elapsed:?}");
        assert!(
            elapsed < limit + LAUNCHER_REPLY_GRACE + Duration::from_secs(3),
            "elapsed {elapsed:?}"
        );
    }

    /// REPAIR-5: `KillTimeout` は 0 と無期限相当を拒否し、既定は 5 秒。
    #[test]
    fn repair5_kill_timeout_rejects_zero_and_unbounded() {
        for bad in [Duration::ZERO, START_TIMEOUT_MAX + Duration::from_nanos(1)] {
            let err = KillTimeout::new(bad).expect_err("rejected");
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert_eq!(
                err.message(),
                "kill timeout must be greater than zero and at most 600s"
            );
        }
        assert_eq!(
            KillTimeout::new(START_TIMEOUT_MAX).expect("max").get(),
            START_TIMEOUT_MAX
        );
        assert_eq!(KillTimeout::default().get(), Duration::from_secs(5));
    }

    /// REPAIR-4: 成功と失敗が 1 件ずつ操作名 `kill` で記録される。
    #[test]
    fn repair4_kill_records_success_and_failure() {
        let pid = NonZeroU32::new(7).expect("pid");
        let store = MemStateStore::with(ContainerStatus::running(cid("c1"), Some(pid)));
        let signaler = FakeSignaler::new(Duration::ZERO);
        let dynamic: Arc<dyn ProcessSignaler> = signaler.clone();
        let recorder = OpRecorder::new();
        let t = KillTimeout::default();
        kill(&store, &recorder, &dynamic, &req("c1", Signal::SIGTERM), &t).expect("ok");
        kill(
            &store,
            &recorder,
            &dynamic,
            &req("nope", Signal::SIGTERM),
            &t,
        )
        .expect_err("ng");
        let stats = recorder
            .snapshot_op(&OpName::new("kill").expect("name"))
            .expect("recorded");
        assert_eq!((stats.success(), stats.failure()), (1, 1));
    }

    /// 起動ハンドルを ID 対応で保持し、pid が一致するときだけ送る本番相当の signaler（Linux）。
    #[cfg(target_os = "linux")]
    struct HandleSignaler(Mutex<HashMap<ContainerId, crate::oci_runtime::ContainerChildProcess>>);

    #[cfg(target_os = "linux")]
    impl ProcessSignaler for HandleSignaler {
        fn signal(
            &self,
            id: &ContainerId,
            pid: NonZeroU32,
            signal: Signal,
            deadline: Instant,
        ) -> Result<(), TraitError> {
            use crate::oci_runtime::LaunchedProcess;
            let map = self.0.lock().unwrap_or_else(|e| e.into_inner());
            let process = map
                .get(id)
                .filter(|p| p.pid() == pid)
                .ok_or_else(|| TraitError::new(ErrorCode::FailedPrecondition, "no handle"))?;
            process.signal(signal, deadline)
        }
    }

    /// OCI-6（受入基準 1）: kill 後にコンテナ内プロセスがプロセステーブルから消える（実プロセス。root 不要）。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci6_kill_terminates_real_process() {
        use crate::oci_runtime::{ContainerChildProcess, LaunchedProcess, ProcessExit};
        for (signal, expected) in [(Signal::SIGKILL, 9), (Signal::SIGTERM, 15)] {
            #[allow(clippy::zombie_processes)]
            let pid = std::process::Command::new("sh")
                .args(["-c", "exec sleep 30"])
                .stdin(std::process::Stdio::null())
                .spawn()
                .expect("spawn")
                .id();
            let process =
                ContainerChildProcess::new(crate::exec::ContainerChild::from_pid_for_test(pid))
                    .expect("wrap");
            let nz = process.pid();
            let id = cid("real");
            let store = MemStateStore::with(ContainerStatus::running(id.clone(), Some(nz)));
            let handles = Arc::new(HandleSignaler(Mutex::new(HashMap::from([(
                id.clone(),
                process,
            )]))));
            let dynamic: Arc<dyn ProcessSignaler> = handles.clone();
            kill(
                &store,
                &OpRecorder::new(),
                &dynamic,
                &KillRequest::new(id.clone(), signal),
                &KillTimeout::default(),
            )
            .expect("kill");
            let exit = handles.0.lock().unwrap()[&id]
                .wait(Duration::from_secs(10))
                .expect("wait");
            assert_eq!(exit, Some(ProcessExit::Signaled(expected)));
            assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
        }
    }
}
