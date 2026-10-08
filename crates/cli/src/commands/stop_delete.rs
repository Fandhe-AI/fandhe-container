//! `stop` / `delete` コマンド本体（Linux は plugin を介さず core を直接呼ぶ。TASK-79.2.2・CLI-1・MS-6）。
//!
//! `commands::run` が argv を解析した後に [`run_stop`] / [`run_delete`] を呼ぶ。実処理は core の
//! `oci_runtime::kill` / `oci_runtime::delete`（OCI-6・CORE-2・TASK-30）へ委ね、ID の文字種検証も
//! core の型（`ContainerId`）を唯一の判定とする。状態ルートの解決・状態ストアの組み立ては
//! `create_start::production_runtime` を共用する。
//!
//! 設計判断（fail-closed）:
//! - `stop` は core の `kill` に `SIGTERM` で写像する。core に stop（猶予 → SIGKILL）は無い。
//! - 本番の [`ProcessSignaler`] はリポジトリ内に無い（supervisor が提供。TASK-157）ため、
//!   [`UnavailableSignaler`] が常に `Unimplemented` で失敗する。`state.json` の pid へ生の `kill(2)` は
//!   送らない（PID 再利用で無関係なプロセスを止めない。SEC-1・CORE-1）。
//! - `delete` の cgroup 削除は [`UnavailableCgroupRemover`] が `Unimplemented` で失敗する。cgroup 配置が
//!   記録されたレコードに出会った場合だけ呼ばれ、cgroup も状態記録も残したまま 8 で失敗する（OCI-6・CORE-3）。
//!
//! 未実装・簡易実装（REPAIR-3）:
//! - stop の失敗 JSON の `op` は `kill` になる（core に `LifecycleOp::Stop` が無いため。core 到達前の失敗も
//!   `kill` に揃える）。猶予待ち → SIGKILL・Stopped への遷移確認・本番 signaler / cgroup remover
//!   （`cgroups::DelegatedCgroup` の遅延検出）の結線は TASK-157 の範囲。
//! - macOS / Windows は plugin 発見機構経由（TASK-79.4・PLUG-4）。ここでは core を呼ぶだけで、
//!   非 Linux では状態ストアを開けず core 側が `Unimplemented` を返す（fail-closed）。

use std::sync::Arc;
use std::time::Instant;

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    CgroupRemoval, ContainerCgroupRemover, KillTimeout, LifecycleOp, OciRuntimeError,
    ProcessSignaler, delete, kill,
};
use fandhe_container_core::traits::{
    CgroupScope, ContainerId, ContainerStatus, DeleteRequest, DeleteResponse, ErrorCode,
    KillRequest, Signal, StateRevision, StateStore, TraitError,
};

use super::CliExit;
use super::args::{DeleteArgs, GlobalArgs, StopArgs};
use super::create_start::{OP_LOG_ENV, export_ops, production_runtime};

/// 本番の signaler。送信手段の本番実装がまだ無いため、常に `Unimplemented` で失敗する（REPAIR-3）。
///
/// 将来仕様: supervisor が保持する起動ハンドルへ委ねる実装（TASK-157・CORE-1）に置き換える。
struct UnavailableSignaler;

impl ProcessSignaler for UnavailableSignaler {
    fn signal(
        &self,
        _id: &ContainerId,
        _pid: std::num::NonZeroU32,
        _signal: Signal,
        _deadline: Instant,
    ) -> Result<(), TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "process signaler is not available yet",
        ))
    }
}

/// 本番の cgroup remover。委譲スコープの検出結線がまだ無いため、常に `Unimplemented` で失敗する（REPAIR-3）。
///
/// `remove` も `NotPresent` を返さない（cgroup を残したまま記録だけ消す経路を作らない）。
/// 将来仕様: 遅延 `DelegatedCgroup::detect` へ差し替える（本番 create が cgroup を記録する結線と同時。TASK-157）。
struct UnavailableCgroupRemover;

impl ContainerCgroupRemover for UnavailableCgroupRemover {
    fn scope(&self) -> Result<CgroupScope, TraitError> {
        Err(unavailable_cgroup())
    }

    fn remove(
        &self,
        _id: &ContainerId,
        _instance: StateRevision,
    ) -> Result<CgroupRemoval, TraitError> {
        Err(unavailable_cgroup())
    }
}

fn unavailable_cgroup() -> TraitError {
    TraitError::new(
        ErrorCode::Unimplemented,
        "container cgroup removal is not available yet",
    )
}

/// ID を core の型で検証し、`SIGTERM` の kill 要求を作る。
fn build_stop_request(args: &StopArgs) -> Result<KillRequest, TraitError> {
    Ok(KillRequest::new(
        ContainerId::new(args.id.as_str())?,
        Signal::SIGTERM,
    ))
}

fn build_delete_request(args: &DeleteArgs) -> Result<DeleteRequest, TraitError> {
    Ok(DeleteRequest::new(ContainerId::new(args.id.as_str())?).with_force(args.force))
}

/// 構築済みの要求で core の `kill` を呼ぶ（テストで signaler を差し替える入口）。
pub(super) fn stop_container(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    signaler: &Arc<dyn ProcessSignaler>,
    req: &KillRequest,
    timeout: &KillTimeout,
) -> Result<ContainerStatus, OciRuntimeError> {
    kill(store, recorder, signaler, req, timeout)
}

/// 構築済みの要求で core の `delete` を呼ぶ。
pub(super) fn delete_container(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    cgroups: &dyn ContainerCgroupRemover,
    req: &DeleteRequest,
) -> Result<DeleteResponse, OciRuntimeError> {
    delete(store, recorder, cgroups, req)
}

/// 本番入口の `stop`。成功時は何も出力しない（OCI の kill 互換）。
pub(super) fn run_stop(global: &GlobalArgs, args: &StopArgs) -> CliExit {
    let started = Instant::now();
    let prepared = production_runtime(global, OpRecorder::new(), "kill", started, || {
        build_stop_request(args)
    })
    .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Kill, e));
    let (rt, req) = match prepared {
        Ok(v) => v,
        Err(e) => return CliExit::Runtime(e),
    };
    let signaler: Arc<dyn ProcessSignaler> = Arc::new(UnavailableSignaler);
    let result = stop_container(
        rt.store.as_ref(),
        &rt.recorder,
        &signaler,
        &req,
        &KillTimeout::default(),
    );
    export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    match result {
        Ok(_) => CliExit::Success,
        Err(e) => CliExit::Runtime(e),
    }
}

/// 本番入口の `delete`。成功時は何も出力しない（OCI の delete 互換）。
pub(super) fn run_delete(global: &GlobalArgs, args: &DeleteArgs) -> CliExit {
    let started = Instant::now();
    let prepared = production_runtime(global, OpRecorder::new(), "delete", started, || {
        build_delete_request(args)
    })
    .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Delete, e));
    let (rt, req) = match prepared {
        Ok(v) => v,
        Err(e) => return CliExit::Runtime(e),
    };
    let result = delete_container(
        rt.store.as_ref(),
        &rt.recorder,
        &UnavailableCgroupRemover,
        &req,
    );
    export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    match result {
        Ok(_) => CliExit::Success,
        Err(e) => CliExit::Runtime(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stop_args(id: &str) -> StopArgs {
        StopArgs { id: id.into() }
    }

    fn delete_args(id: &str, force: bool) -> DeleteArgs {
        DeleteArgs {
            id: id.into(),
            force,
        }
    }

    /// ERR-2: 不正な ID 文字は INVALID_ARGUMENT（2）で、core へ到達する前に拒否される。
    #[test]
    fn err2_build_requests_reject_invalid_id() {
        for id in ["a/b", "..", "", "a b"] {
            let e = build_stop_request(&stop_args(id)).expect_err("stop");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
            let e = build_delete_request(&delete_args(id, false)).expect_err("delete");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
        }
    }

    /// CLI-1: stop は SIGTERM（15）の kill 要求、delete は force を素通しする。
    #[test]
    fn cli1_build_requests_keep_values() {
        let k = build_stop_request(&stop_args("c1")).expect("stop");
        assert_eq!(k.id().as_str(), "c1");
        assert_eq!(k.signal().as_u8(), 15);
        for force in [false, true] {
            let d = build_delete_request(&delete_args("c1", force)).expect("delete");
            assert_eq!(d.id().as_str(), "c1");
            assert_eq!(d.force(), force);
        }
    }

    /// REPAIR-3: 本番の signaler / cgroup remover は fail-closed の Unimplemented。
    #[test]
    fn repair3_unavailable_signaler_and_remover_fail_closed() {
        let id = ContainerId::new("c1").expect("id");
        let pid = std::num::NonZeroU32::new(4242).expect("pid");
        let e = UnavailableSignaler
            .signal(&id, pid, Signal::SIGTERM, Instant::now())
            .expect_err("signal");
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        let e = UnavailableCgroupRemover.scope().expect_err("scope");
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        let e = UnavailableCgroupRemover
            .remove(&id, StateRevision::from_raw(1))
            .expect_err("remove");
        assert_eq!(e.code(), ErrorCode::Unimplemented);
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::path::PathBuf;
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        use fandhe_container_core::observability::OpName;
        use fandhe_container_core::oci_runtime::{
            LaunchSpec, LaunchedProcess, ProcessExit, ProcessLauncher, StartTimeouts, create, start,
        };
        use fandhe_container_core::state_store::{FileStateStore, StateRoot};
        use fandhe_container_core::traits::{ContainerState, CreateRequest, GetStateRequest};

        /// テスト用の一意な一時ディレクトリ（Drop で削除）。
        struct TmpDir(PathBuf);

        impl TmpDir {
            fn new(tag: &str) -> Self {
                static SEQ: AtomicUsize = AtomicUsize::new(0);
                let n = SEQ.fetch_add(1, Ordering::SeqCst);
                let p = std::env::temp_dir()
                    .join(format!("fc-cli-sd-{tag}-{}-{n}", std::process::id()));
                std::fs::create_dir_all(&p).expect("mkdir");
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
                        .expect("chmod");
                }
                Self(p)
            }
        }

        impl Drop for TmpDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn make_bundle(base: &TmpDir) -> PathBuf {
            let b = base.0.join("bundle");
            std::fs::create_dir_all(b.join("rootfs")).expect("rootfs");
            std::fs::write(
                b.join("config.json"),
                r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
            )
            .expect("config");
            b
        }

        fn state_root(base: &TmpDir) -> PathBuf {
            base.0.join("state")
        }

        fn store(base: &TmpDir) -> FileStateStore {
            let root = StateRoot::from_override(state_root(base)).expect("root");
            FileStateStore::open(root).expect("open")
        }

        fn id(s: &str) -> ContainerId {
            ContainerId::new(s).expect("id")
        }

        fn do_create(base: &TmpDir, store: &FileStateStore, rec: &OpRecorder, name: &str) {
            let req = CreateRequest::new(id(name), make_bundle(base)).expect("req");
            create(store, rec, &req).expect("create");
        }

        struct FakeProcess;

        impl LaunchedProcess for FakeProcess {
            fn pid(&self) -> std::num::NonZeroU32 {
                std::num::NonZeroU32::new(4242).expect("nonzero")
            }
            fn wait(&self, _t: Duration) -> Result<Option<ProcessExit>, TraitError> {
                Ok(None)
            }
            fn terminate(&self, _t: Duration) -> Result<(), TraitError> {
                Ok(())
            }
        }

        struct FakeLauncher;

        impl ProcessLauncher for FakeLauncher {
            fn launch(
                &self,
                _spec: &LaunchSpec,
                _timeout: Duration,
            ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
                Ok(Box::new(FakeProcess))
            }
        }

        /// Running（pid 4242）まで進める。戻り値のハンドルは呼び出し元がテスト終了まで保持する。
        fn do_start(
            store: &FileStateStore,
            rec: &OpRecorder,
            name: &str,
        ) -> fandhe_container_core::oci_runtime::StartedContainer {
            let launcher: Arc<dyn ProcessLauncher> = Arc::new(FakeLauncher);
            start(
                store,
                rec,
                &launcher,
                &fandhe_container_core::traits::StartRequest::new(id(name)),
                &StartTimeouts::default(),
            )
            .expect("start")
        }

        /// 呼び出しを記録する signaler。
        #[derive(Default)]
        struct RecordingSignaler(Mutex<Vec<(String, u32, u8)>>);

        impl ProcessSignaler for RecordingSignaler {
            fn signal(
                &self,
                id: &ContainerId,
                pid: std::num::NonZeroU32,
                signal: Signal,
                _deadline: Instant,
            ) -> Result<(), TraitError> {
                self.0.lock().expect("lock").push((
                    id.as_str().to_string(),
                    pid.get(),
                    signal.as_u8(),
                ));
                Ok(())
            }
        }

        fn stop_with(
            store: &FileStateStore,
            rec: &OpRecorder,
            signaler: Arc<dyn ProcessSignaler>,
            name: &str,
        ) -> Result<ContainerStatus, OciRuntimeError> {
            let req = build_stop_request(&stop_args(name)).expect("req");
            stop_container(store, rec, &signaler, &req, &KillTimeout::default())
        }

        fn delete_with(
            store: &FileStateStore,
            rec: &OpRecorder,
            name: &str,
            force: bool,
        ) -> Result<DeleteResponse, OciRuntimeError> {
            let req = build_delete_request(&delete_args(name, force)).expect("req");
            delete_container(store, rec, &UnavailableCgroupRemover, &req)
        }

        /// ERR-2: 未 create の ID の stop は NOT_FOUND（3・op=kill）で signaler を呼ばない。
        #[test]
        fn err2_stop_unknown_id_is_not_found() {
            let base = TmpDir::new("stop-nf");
            let st = store(&base);
            let sig = Arc::new(RecordingSignaler::default());
            let e = stop_with(&st, &OpRecorder::new(), sig.clone(), "nope").expect_err("nf");
            assert_eq!(e.code(), ErrorCode::NotFound);
            assert_eq!(e.exit_code().get(), 3);
            assert_eq!(e.op(), LifecycleOp::Kill);
            assert!(sig.0.lock().expect("lock").is_empty());
        }

        /// ERR-2: Created（pid なし）の stop は FAILED_PRECONDITION（5）で signaler を呼ばない。
        #[test]
        fn err2_stop_created_is_failed_precondition() {
            let base = TmpDir::new("stop-created");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "c1");
            let sig = Arc::new(RecordingSignaler::default());
            let e = stop_with(&st, &rec, sig.clone(), "c1").expect_err("fp");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(e.exit_code().get(), 5);
            assert!(sig.0.lock().expect("lock").is_empty());
        }

        /// CLI-1・OCI-6: Running の stop は core の kill 経由で signaler に SIGTERM（15）が 1 回届く。
        #[test]
        fn cli1_stop_calls_core_and_signals_sigterm() {
            let base = TmpDir::new("stop-ok");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "sd-stop-ok");
            let _handle = do_start(&st, &rec, "sd-stop-ok");
            let sig = Arc::new(RecordingSignaler::default());
            let status = stop_with(&st, &rec, sig.clone(), "sd-stop-ok").expect("stop");
            assert_eq!(status.state(), ContainerState::Running);
            assert_eq!(
                *sig.0.lock().expect("lock"),
                vec![("sd-stop-ok".to_string(), 4242, 15)]
            );
        }

        /// REPAIR-3: 本番 signaler では stop が UNIMPLEMENTED（8・op=kill）で、状態は Running のまま。
        #[test]
        fn repair3_stop_with_unavailable_signaler_is_unimplemented() {
            let base = TmpDir::new("stop-unavail");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "sd-stop-unavail");
            let _handle = do_start(&st, &rec, "sd-stop-unavail");
            let e = stop_with(&st, &rec, Arc::new(UnavailableSignaler), "sd-stop-unavail")
                .expect_err("unimpl");
            assert_eq!(e.code(), ErrorCode::Unimplemented);
            assert_eq!(e.exit_code().get(), 8);
            assert_eq!(e.op(), LifecycleOp::Kill);
            let got = st
                .get(&GetStateRequest::new(id("sd-stop-unavail")))
                .expect("get");
            assert_eq!(got.status().state(), ContainerState::Running);
            assert_eq!(got.status().pid(), std::num::NonZeroU32::new(4242));
        }

        /// CLI-1・OCI-6: Created の delete は core を呼んで状態記録を消す。
        #[test]
        fn cli1_delete_calls_core_and_removes_state() {
            let base = TmpDir::new("del-ok");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "c1");
            assert!(state_root(&base).join("c1").join("state.json").exists());
            delete_with(&st, &rec, "c1", false).expect("delete");
            let e = st
                .get(&GetStateRequest::new(id("c1")))
                .expect_err("removed");
            assert_eq!(e.code(), ErrorCode::NotFound);
            assert!(!state_root(&base).join("c1").join("state.json").exists());
        }

        /// ERR-2: 二重 delete の 2 回目は NOT_FOUND（3・op=delete）。
        #[test]
        fn err2_delete_twice_is_not_found() {
            let base = TmpDir::new("del-twice");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "c1");
            delete_with(&st, &rec, "c1", false).expect("first");
            let e = delete_with(&st, &rec, "c1", false).expect_err("second");
            assert_eq!(e.code(), ErrorCode::NotFound);
            assert_eq!(e.exit_code().get(), 3);
            assert_eq!(e.op(), LifecycleOp::Delete);
        }

        /// ERR-2: Running の delete は 5、force でも 8 で、いずれもレコードが残る。
        #[test]
        fn err2_delete_running_is_refused_and_keeps_record() {
            let base = TmpDir::new("del-running");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "sd-del-running");
            let _handle = do_start(&st, &rec, "sd-del-running");
            let e = delete_with(&st, &rec, "sd-del-running", false).expect_err("plain");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(e.exit_code().get(), 5);
            let e = delete_with(&st, &rec, "sd-del-running", true).expect_err("force");
            assert_eq!(e.code(), ErrorCode::Unimplemented);
            assert_eq!(e.exit_code().get(), 8);
            let got = st
                .get(&GetStateRequest::new(id("sd-del-running")))
                .expect("kept");
            assert_eq!(got.status().state(), ContainerState::Running);
        }

        /// REPAIR-4: stop / delete は同じ recorder に操作名 kill / delete で成功・失敗件数が記録される。
        #[test]
        fn repair4_stop_delete_are_recorded() {
            let base = TmpDir::new("rec");
            let st = store(&base);
            let rec = OpRecorder::new();
            do_create(&base, &st, &rec, "c1");
            let sig: Arc<dyn ProcessSignaler> = Arc::new(RecordingSignaler::default());
            let _ = stop_with(&st, &rec, sig.clone(), "c1");
            let _ = stop_with(&st, &rec, sig, "nope");
            delete_with(&st, &rec, "c1", false).expect("delete");
            let _ = delete_with(&st, &rec, "c1", false);
            let kill_op = rec
                .snapshot_op(&OpName::new("kill").expect("name"))
                .expect("kill");
            assert_eq!((kill_op.success(), kill_op.failure()), (0, 2));
            let del_op = rec
                .snapshot_op(&OpName::new("delete").expect("name"))
                .expect("delete");
            assert_eq!((del_op.success(), del_op.failure()), (1, 1));
        }
    }
}
