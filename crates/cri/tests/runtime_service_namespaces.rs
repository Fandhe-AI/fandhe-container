//! `StartContainer` 後に namespace 分離済みプロセスが実在することを `/proc/<pid>/ns/*` で確認する
//! 実機前提の受け入れ試験（TASK-59.2・#438・CRI-2）。
//!
//! 必要環境: Linux・`unshare`（util-linux）・非特権 user namespace の許可
//! （`kernel.apparmor_restrict_unprivileged_userns=0` 等が要る場合がある）。GitHub ホステッド runner では
//! 動かないため `#[ignore]` で既定のテスト集合から分離している。実行は
//! `cargo test -p fandhe-container-cri --test runtime_service_namespaces -- --ignored`。
//!
//! 未実装・差分（REPAIR-3）: core の本番 launcher（`ProductionLauncher`）は呼び出しプロセスが単一スレッドで
//! あることを要求する（CORE-1）一方、`spawn_blocking` は tokio のスレッドプールを作るため CRI サービスと
//! 同一プロセスでは使えない。その結線は supervisor 側（#1819）と plugin 境界化（TASK-114）で解く。本試験は
//! テスト側の `ContainerRuntime`（`unshare(1)` で起動）を注入し、CRI ハンドラが adapter 経由で実際の
//! プロセス起動まで到達することを照合する。core の分離実装そのものの照合ではない。

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use fandhe_container_core::traits::{
    ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest, DeleteResponse, ErrorCode,
    KillRequest, StartRequest, StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::{BundleProvider, RuntimeAdapter};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig, PodSandboxMetadata,
    runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use tonic::Request;

const NS: [&str; 5] = ["user", "mnt", "uts", "ipc", "net"];

/// `unshare(1)` で namespace を分離した `sleep` を起動するテスト専用の実行層。
#[derive(Default)]
struct UnshareRuntime {
    children: Mutex<HashMap<String, Child>>,
}

impl ContainerRuntime for UnshareRuntime {
    fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        Ok(ContainerStatus::created(r.id().clone(), None))
    }
    fn start(&self, r: &StartRequest) -> Result<ContainerStatus, TraitError> {
        let child = Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--mount",
                "--uts",
                "--ipc",
                "--net",
            ])
            .args(["sleep", "60"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| TraitError::new(ErrorCode::Unavailable, "failed to spawn unshare"))?;
        let pid = NonZeroU32::new(child.id());
        self.children
            .lock()
            .map_err(|_| TraitError::new(ErrorCode::Unavailable, "poisoned"))?
            .insert(r.id().as_str().to_owned(), child);
        Ok(ContainerStatus::running(r.id().clone(), pid))
    }
    fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
    fn stop(&self, _: &StopRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
    fn delete(&self, _: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
    fn state(&self, _: &StateRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
}

struct FixedBundle;

impl BundleProvider for FixedBundle {
    fn prepare(&self, id: &str, _: &str, _: &ContainerConfig) -> Result<PathBuf, CriError> {
        Ok(PathBuf::from("/tmp/unused-bundle").join(id))
    }
    fn release(&self, _: &str) -> Result<(), CriError> {
        Ok(())
    }
}

/// 起動した子を必ず kill・wait する（プロセスを残さない）。
struct Reaper(Arc<UnshareRuntime>);

impl Drop for Reaper {
    fn drop(&mut self) {
        if let Ok(mut children) = self.0.children.lock() {
            for child in children.values_mut() {
                // kill の失敗は無視せず、終了を try_wait で有限期限まで確認する（REPAIR-5）。
                let kill_result = child.kill();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                let mut reaped = false;
                while std::time::Instant::now() < deadline {
                    match child.try_wait() {
                        Ok(Some(_)) => {
                            reaped = true;
                            break;
                        }
                        Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
                        Err(_) => break,
                    }
                }
                if !reaped && !std::thread::panicking() {
                    panic!("child was not reaped within the deadline (kill: {kill_result:?})");
                }
            }
        }
    }
}

/// CRI-2: StartContainer 後のプロセスが、テスト自身とは別の user/mnt/uts/ipc/net namespace に居る。
#[tokio::test]
#[ignore = "requires Linux with unshare(1) and unprivileged user namespaces (CRI-2, TASK-59.2)"]
async fn task_59_2_started_process_is_namespace_isolated() {
    let runtime = Arc::new(UnshareRuntime::default());
    let _reaper = Reaper(runtime.clone());
    struct Shared(Arc<UnshareRuntime>);
    impl ContainerRuntime for Shared {
        fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
            self.0.create(r)
        }
        fn start(&self, r: &StartRequest) -> Result<ContainerStatus, TraitError> {
            self.0.start(r)
        }
        fn kill(&self, r: &KillRequest) -> Result<ContainerStatus, TraitError> {
            self.0.kill(r)
        }
        fn stop(&self, r: &StopRequest) -> Result<ContainerStatus, TraitError> {
            self.0.stop(r)
        }
        fn delete(&self, r: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
            self.0.delete(r)
        }
        fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
            self.0.state(r)
        }
    }
    let service = CriRuntimeService::new().with_runtime(
        RuntimeAdapter::new(Arc::new(Shared(runtime.clone()))),
        Arc::new(FixedBundle),
    );

    let sandbox = RuntimeService::run_pod_sandbox(
        &service,
        Request::new(v1::RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "pod".into(),
                    uid: "uid".into(),
                    namespace: "ns".into(),
                    attempt: 0,
                }),
                ..Default::default()
            }),
            runtime_handler: String::new(),
        }),
    )
    .await
    .expect("sandbox")
    .into_inner()
    .pod_sandbox_id;
    let id = RuntimeService::create_container(
        &service,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox,
            config: Some(ContainerConfig {
                metadata: Some(ContainerMetadata {
                    name: "c".into(),
                    attempt: 0,
                }),
                image: Some(ImageSpec {
                    image: "busybox:1.36".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            sandbox_config: None,
        }),
    )
    .await
    .expect("create")
    .into_inner()
    .container_id;
    RuntimeService::start_container(
        &service,
        Request::new(v1::StartContainerRequest {
            container_id: id.clone(),
        }),
    )
    .await
    .expect("start");

    let pid = runtime
        .children
        .lock()
        .expect("lock")
        .get(&id)
        .map(Child::id)
        .expect("child started");
    // unshare は fork 直後は親と同じ namespace で、unshare(2) の後に分離される。分離が済むまで最大 5 秒待つ。
    for ns in NS {
        let mine = std::fs::read_link(format!("/proc/self/ns/{ns}")).expect("self ns");
        let mut theirs = PathBuf::new();
        for _ in 0..500 {
            theirs = std::fs::read_link(format!("/proc/{pid}/ns/{ns}")).expect("child ns");
            if theirs != mine {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_ne!(mine, theirs, "{ns} namespace must differ from the host's");
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("status");
    assert!(
        status
            .lines()
            .any(|l| l.starts_with("State:") && !l.contains("zombie") && !l.contains("dead")),
        "process must be alive: {status}"
    );
}
