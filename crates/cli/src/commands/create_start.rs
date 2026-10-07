//! `create` / `start` コマンド本体（Linux は plugin を介さず core を直接呼ぶ。TASK-79.2.1・CLI-1・MS-6）。
//!
//! `commands::run` が argv を解析した後に [`run_create`] / [`run_start`] を呼ぶ。実処理は core の
//! `oci_runtime::create` / `oci_runtime::start`（OCI-4・OCI-5・TASK-29）へ委ね、入力の意味検証
//! （ID の文字種・bundle の絶対パス・bundle / rootfs の symlink 検査）も core の型と関数を唯一の判定とする。
//! 依存（状態ストア・launcher・計測器）は [`Runtime`] で注入できるようにし、単体テストではフェイクを差せる。
//!
//! 未実装・簡易実装（REPAIR-3）:
//! - 本番の [`ProcessLauncher`] はリポジトリ内に存在しない。そのため本番入口の `start` は
//!   [`UnavailableLauncher`] により fail-closed で `UNIMPLEMENTED` を返す。将来は supervisor 経由の
//!   起動（TASK-157・TASK-37〜39・CORE-1）に差し替え、起動済みプロセスの監視・回収を supervisor へ引き渡す。
//! - macOS / Windows は plugin 発見機構経由（TASK-79.4・PLUG-4）。ここでは core を呼ぶだけで、
//!   非 Linux では core 側が `Unimplemented` を返す（fail-closed）。

use std::sync::Arc;
use std::time::Duration;

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    LaunchSpec, LaunchedProcess, LifecycleOp, OciRuntimeError, ProcessLauncher, StartTimeouts,
    StartedContainer, create, start,
};
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, CreateRequest, ErrorCode, StartRequest, StateRecord, StateStore, TraitError,
};

use super::CliExit;
use super::args::{CreateArgs, GlobalArgs, StartArgs};

/// core の操作へ注入する依存の束。
pub(super) struct Runtime {
    pub(super) store: Box<dyn StateStore>,
    pub(super) launcher: Arc<dyn ProcessLauncher>,
    pub(super) recorder: OpRecorder,
    pub(super) timeouts: StartTimeouts,
}

/// 本番の launcher。プロセス起動の本番実装がまだ無いため、常に `Unimplemented` で失敗する（REPAIR-3）。
///
/// core の `start` は launch 失敗時に予約を Created へ戻すため、状態は壊れない。将来仕様: supervisor 経由で
/// コンテナプロセスを起動する実装（TASK-157・TASK-37〜39・CORE-1）に置き換える。
struct UnavailableLauncher;

impl ProcessLauncher for UnavailableLauncher {
    fn launch(
        &self,
        _spec: &LaunchSpec,
        _timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "process launcher is not available yet",
        ))
    }
}

/// `create` の要求を組み立てて core の `create` を呼ぶ。
pub(super) fn create_container(
    rt: &Runtime,
    args: &CreateArgs,
) -> Result<StateRecord, OciRuntimeError> {
    let req = build_create_request(args)
        .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Create, e))?;
    create(rt.store.as_ref(), &rt.recorder, &req)
}

/// `start` の要求を組み立てて core の `start` を呼ぶ。起動済みプロセスのハンドルは呼び出し元へ返す
/// （監視・回収は呼び出し元の責務。CORE-1）。
pub(super) fn start_container(
    rt: &Runtime,
    args: &StartArgs,
) -> Result<StartedContainer, OciRuntimeError> {
    let req = build_start_request(args)
        .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Start, e))?;
    start(
        rt.store.as_ref(),
        &rt.recorder,
        &rt.launcher,
        &req,
        &rt.timeouts,
    )
}

/// ID の文字種と bundle の絶対パスを core の型で検証する（相対パスの解決・canonicalize はしない。SEC-1）。
fn build_create_request(args: &CreateArgs) -> Result<CreateRequest, TraitError> {
    let id = ContainerId::new(args.id.as_str())?;
    CreateRequest::new(id, args.bundle.clone())
}

fn build_start_request(args: &StartArgs) -> Result<StartRequest, TraitError> {
    Ok(StartRequest::new(ContainerId::new(args.id.as_str())?))
}

/// 状態ルートを解決して本番の依存を組む。失敗は `op` の `OciRuntimeError` に写す。
fn production_runtime(global: &GlobalArgs, op: LifecycleOp) -> Result<Runtime, OciRuntimeError> {
    let to_err = |e: TraitError| OciRuntimeError::from_trait_error(op, e);
    let root = StateRoot::resolve(global.root.clone()).map_err(to_err)?;
    let store = FileStateStore::open(root).map_err(to_err)?;
    Ok(Runtime {
        store: Box::new(store),
        launcher: Arc::new(UnavailableLauncher),
        recorder: OpRecorder::new(),
        timeouts: StartTimeouts::default(),
    })
}

/// 操作計測（`OpRecorder`）の JSON Lines 出力先を指す環境変数（REPAIR-4）。
///
/// OCI の stdout 契約（create / start は成功時に何も出さない）と stderr の 1 行エラー JSON を保つため、
/// 計測は stdout / stderr へ混ぜず、この環境変数が指すファイルへ追記する。未設定なら出力しない。
pub(super) const OP_LOG_ENV: &str = "FANDHE_CONTAINER_OP_LOG";

/// 計測を `path` のファイルへ追記する（best effort。失敗しても終了コード・エラー出力は変えない）。
pub(super) fn export_ops(recorder: &OpRecorder, path: Option<&std::ffi::OsStr>) {
    let Some(path) = path.filter(|p| !p.is_empty()) else {
        return;
    };
    let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    let _ = recorder.export_json_lines(Some(&mut f));
}

/// 本番入口の `create`。成功時は何も出さない（OCI の create 互換）。
pub(super) fn run_create(global: &GlobalArgs, args: &CreateArgs) -> CliExit {
    let rt = match production_runtime(global, LifecycleOp::Create) {
        Ok(rt) => rt,
        Err(e) => return CliExit::Runtime(e),
    };
    let result = create_container(&rt, args);
    export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    match result {
        Ok(_) => CliExit::Success,
        Err(e) => CliExit::Runtime(e),
    }
}

/// 本番入口の `start`。
pub(super) fn run_start(global: &GlobalArgs, args: &StartArgs) -> CliExit {
    let rt = match production_runtime(global, LifecycleOp::Start) {
        Ok(rt) => rt,
        Err(e) => return CliExit::Runtime(e),
    };
    let result = start_container(&rt, args);
    export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    match result {
        // 本番 launcher（UnavailableLauncher）では到達しない。将来 launcher が差し替わっても、
        // 監視者へ引き渡せないまま CLI が終了して孤児プロセスを残さないよう、止めてから失敗を返す
        // （fail-closed）。supervisor への引き渡しは TASK-157。
        Ok(started) => {
            let (_record, process) = started.into_parts();
            let _ = process.terminate(rt.timeouts.terminate());
            CliExit::Runtime(OciRuntimeError::new(
                LifecycleOp::Start,
                ErrorCode::Internal,
                "no supervisor is available to take over the started process",
            ))
        }
        Err(e) => CliExit::Runtime(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn create_args(bundle: &str, id: &str) -> CreateArgs {
        CreateArgs {
            bundle: PathBuf::from(bundle),
            id: id.to_string(),
        }
    }

    /// CLI-1・ERR-2: 相対 bundle は INVALID_ARGUMENT（終了コード 2・op=create）で、core へ到達する前に拒否される。
    #[test]
    fn err2_build_create_rejects_relative_bundle() {
        let e = build_create_request(&create_args("rel/b", "c1")).expect_err("relative");
        let e = OciRuntimeError::from_trait_error(LifecycleOp::Create, e);
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(e.exit_code().get(), 2);
        assert_eq!(e.op(), LifecycleOp::Create);
    }

    /// CLI-1・ERR-2: 不正な ID 文字は INVALID_ARGUMENT。
    #[test]
    fn err2_build_requests_reject_invalid_id() {
        for id in ["a/b", "..", "", "a b"] {
            let e = build_create_request(&CreateArgs {
                bundle: std::env::temp_dir(),
                id: id.to_string(),
            })
            .expect_err("id");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
            let e = build_start_request(&StartArgs { id: id.to_string() }).expect_err("id");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
        }
    }

    /// CLI-1: 正常な引数は core の要求型へ値をそのまま写す。
    #[test]
    fn cli1_build_create_request_keeps_values() {
        // OS ごとに絶対パスの形が違う（Windows は `/abs/b` を絶対と見なさない）ため temp_dir 由来にする。
        let bundle = std::env::temp_dir().join("abs-b");
        let req = build_create_request(&CreateArgs {
            bundle: bundle.clone(),
            id: "c1".to_string(),
        })
        .expect("ok");
        assert_eq!(req.id().as_str(), "c1");
        assert_eq!(req.bundle(), bundle.as_path());
    }

    /// REPAIR-4: 計測は指定ファイルへ JSON Lines で追記され、未指定なら何も書かない。
    #[test]
    fn repair4_export_ops_appends_json_lines() {
        use fandhe_container_core::observability::{OpName, OpOutcome};
        let rec = OpRecorder::new();
        rec.record(
            &OpName::new("create").expect("name"),
            OpOutcome::Success,
            Duration::from_millis(1),
        )
        .expect("record");
        let path = std::env::temp_dir().join(format!("fc-cli-oplog-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        export_ops(&rec, None);
        assert!(!path.exists());
        export_ops(&rec, Some(path.as_os_str()));
        let text = std::fs::read_to_string(&path).expect("read");
        let _ = std::fs::remove_file(&path);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"op_stats\""));
        assert!(lines[1].contains("\"op_stats_meta\""));
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use fandhe_container_core::traits::ContainerState;
        use std::num::NonZeroU32;
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// テスト用の一意な一時ディレクトリ（Drop で削除）。
        struct TmpDir(PathBuf);

        impl TmpDir {
            fn new(tag: &str) -> Self {
                static SEQ: AtomicUsize = AtomicUsize::new(0);
                let n = SEQ.fetch_add(1, Ordering::SeqCst);
                let p =
                    std::env::temp_dir().join(format!("fc-cli-{tag}-{}-{n}", std::process::id()));
                std::fs::create_dir_all(&p).expect("mkdir");
                // 状態ルートの祖先は group / other 書き込み不可でなければならない（umask に依存せず 0700 に固定）。
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

        /// 有効な bundle（config.json と rootfs/）を作る。
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

        fn runtime(base: &TmpDir, launcher: Arc<dyn ProcessLauncher>) -> Runtime {
            let root = StateRoot::from_override(base.0.join("state")).expect("root");
            Runtime {
                store: Box::new(FileStateStore::open(root).expect("open")),
                launcher,
                recorder: OpRecorder::new(),
                timeouts: StartTimeouts::default(),
            }
        }

        struct FakeProcess;

        impl LaunchedProcess for FakeProcess {
            fn pid(&self) -> NonZeroU32 {
                NonZeroU32::new(4242).expect("nonzero")
            }
            fn wait(
                &self,
                _timeout: Duration,
            ) -> Result<Option<fandhe_container_core::oci_runtime::ProcessExit>, TraitError>
            {
                Ok(None)
            }
            fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
                Ok(())
            }
        }

        struct FakeLauncher(AtomicUsize);

        impl ProcessLauncher for FakeLauncher {
            fn launch(
                &self,
                _spec: &LaunchSpec,
                _timeout: Duration,
            ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(FakeProcess))
            }
        }

        /// CLI-1・OCI-4: create は core を呼び、Created（pid なし）を記録する。同一 ID の再 create は ALREADY_EXISTS（4）。
        #[test]
        fn cli1_create_calls_core_and_rejects_duplicate() {
            let base = TmpDir::new("create");
            let bundle = make_bundle(&base);
            let rt = runtime(&base, Arc::new(UnavailableLauncher));
            let args = CreateArgs {
                bundle: bundle.clone(),
                id: "c1".into(),
            };
            let rec = create_container(&rt, &args).expect("create");
            assert_eq!(rec.status().state(), ContainerState::Created);
            assert_eq!(rec.status().pid(), None);
            let e = create_container(&rt, &args).expect_err("dup");
            assert_eq!(e.code(), ErrorCode::AlreadyExists);
            assert_eq!(e.exit_code().get(), 4);
            assert_eq!(e.op(), LifecycleOp::Create);
        }

        /// ERR-2: 未 create の ID の start は NOT_FOUND（3）で launcher を呼ばない。
        #[test]
        fn err2_start_unknown_id_is_not_found() {
            let base = TmpDir::new("notfound");
            let launcher = Arc::new(FakeLauncher(AtomicUsize::new(0)));
            let rt = runtime(&base, launcher.clone());
            let e = start_container(&rt, &StartArgs { id: "nope".into() }).expect_err("nf");
            assert_eq!(e.code(), ErrorCode::NotFound);
            assert_eq!(e.exit_code().get(), 3);
            assert_eq!(launcher.0.load(Ordering::SeqCst), 0);
        }

        /// CLI-1・CORE-1: create → start で Running・launcher の返した pid が記録され、ハンドルが呼び出し元へ渡る。
        #[test]
        fn cli1_start_calls_core_and_hands_over_process() {
            let base = TmpDir::new("start");
            let bundle = make_bundle(&base);
            let launcher = Arc::new(FakeLauncher(AtomicUsize::new(0)));
            let rt = runtime(&base, launcher.clone());
            create_container(
                &rt,
                &CreateArgs {
                    bundle,
                    id: "start-ok".into(),
                },
            )
            .expect("create");
            let started = start_container(
                &rt,
                &StartArgs {
                    id: "start-ok".into(),
                },
            )
            .expect("start");
            assert_eq!(started.record().status().state(), ContainerState::Running);
            assert_eq!(started.record().status().pid(), NonZeroU32::new(4242));
            assert_eq!(started.process().pid().get(), 4242);
            assert_eq!(launcher.0.load(Ordering::SeqCst), 1);
        }

        /// REPAIR-3: 本番 launcher では start が UNIMPLEMENTED（8）で、状態は Created に戻る。
        #[test]
        fn repair3_unavailable_launcher_keeps_created() {
            let base = TmpDir::new("unavail");
            let bundle = make_bundle(&base);
            let rt = runtime(&base, Arc::new(UnavailableLauncher));
            create_container(
                &rt,
                &CreateArgs {
                    bundle,
                    id: "unavail".into(),
                },
            )
            .expect("create");
            let e = start_container(
                &rt,
                &StartArgs {
                    id: "unavail".into(),
                },
            )
            .expect_err("unimpl");
            assert_eq!(e.code(), ErrorCode::Unimplemented);
            assert_eq!(e.exit_code().get(), 8);
            let id = ContainerId::new("unavail").expect("id");
            let got = rt
                .store
                .get(&fandhe_container_core::traits::GetStateRequest::new(id))
                .expect("get");
            assert_eq!(got.status().state(), ContainerState::Created);
        }
    }
}
