//! `StartContainer` 後に namespace 分離済みプロセスが実在することを `/proc/<pid>/ns/*` で確認する
//! 実機前提の受け入れ試験（TASK-59.2・#438・CRI-2）と、`RemoveContainer` 後にプロセスが終了し
//! namespace の資源が解放されていることの受け入れ試験（TASK-59.3・#439・CRI-2）。
//!
//! 既定のテスト集合で動くのは `task_59_3_remove_container_terminates_process`（分離なしの `sleep` を使い、
//! Linux であれば GitHub ホステッド runner でも動く）。namespace の解放を確かめる試験は実機前提で、
//! 必要環境: Linux・`unshare`（util-linux）・非特権 user namespace の許可
//! （`kernel.apparmor_restrict_unprivileged_userns=0` 等が要る場合がある）。既定では許可されていない
//! 環境があるため `#[ignore]` で既定のテスト集合から分離している。CI は `platform-ci`（ubuntu）が AppArmor を
//! 緩めた後に `--ignored --test-threads=1` で実行する（#2220）。実行は
//! `cargo test -p fandhe-container-cri --test runtime_service_namespaces -- --ignored --test-threads=1`。
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
use fandhe_container_cri::adapter::{
    BundleProvider, BundleRequest, PreparedBundle, RuntimeAdapter,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig, PodSandboxMetadata,
    runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use tonic::Request;

const NS: [&str; 5] = ["user", "mnt", "uts", "ipc", "net"];

/// 子の終了を待つ期限（REPAIR-5。超過したらテストを失敗させ、ハングさせない）。
const REAP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// 子を kill して `try_wait` で期限まで回収する。回収できなければ `None`。
fn kill_and_reap(child: &mut Child) -> Option<std::process::ExitStatus> {
    let _ = child.kill();
    let deadline = std::time::Instant::now() + REAP_DEADLINE;
    while std::time::Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
            Err(_) => return None,
        }
    }
    None
}

/// `unshare(1)` で namespace を分離した `sleep` を起動するテスト専用の実行層。
///
/// `stop`・`delete` は子へ SIGKILL を送って回収する（猶予は使わない簡易実装）。`delete` の呼び出しは
/// `deletes` に記録する。`plain` が真なら `unshare` を使わず素の `sleep` を起動する。
#[derive(Default)]
struct UnshareRuntime {
    children: Mutex<HashMap<String, Child>>,
    deletes: Mutex<Vec<(String, bool)>>,
    plain: bool,
}

impl ContainerRuntime for UnshareRuntime {
    fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        Ok(ContainerStatus::created(r.id().clone(), None))
    }
    fn start(&self, r: &StartRequest) -> Result<ContainerStatus, TraitError> {
        let mut command = if self.plain {
            Command::new("sleep")
        } else {
            let mut c = Command::new("unshare");
            c.args([
                "--user",
                "--map-root-user",
                "--mount",
                "--uts",
                "--ipc",
                "--net",
                "sleep",
            ]);
            c
        };
        let child = command
            .arg("60")
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
    fn stop(&self, r: &StopRequest) -> Result<ContainerStatus, TraitError> {
        let mut children = self
            .children
            .lock()
            .map_err(|_| TraitError::new(ErrorCode::Unavailable, "poisoned"))?;
        let child = children
            .get_mut(r.id().as_str())
            .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "no such container"))?;
        kill_and_reap(child)
            .ok_or_else(|| TraitError::new(ErrorCode::Internal, "child was not reaped"))?;
        Ok(ContainerStatus::stopped(r.id().clone(), None))
    }
    fn delete(&self, r: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        self.deletes
            .lock()
            .map_err(|_| TraitError::new(ErrorCode::Unavailable, "poisoned"))?
            .push((r.id().as_str().to_owned(), r.force()));
        let mut child = self
            .children
            .lock()
            .map_err(|_| TraitError::new(ErrorCode::Unavailable, "poisoned"))?
            .remove(r.id().as_str())
            .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "no such container"))?;
        kill_and_reap(&mut child)
            .ok_or_else(|| TraitError::new(ErrorCode::Internal, "child was not reaped"))?;
        Ok(DeleteResponse::new())
    }
    fn state(&self, _: &StateRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
}

struct FixedBundle;

impl BundleProvider for FixedBundle {
    fn prepare(&self, req: &BundleRequest<'_>) -> Result<PreparedBundle, CriError> {
        Ok(PreparedBundle::new(
            PathBuf::from("/tmp/unused-bundle").join(req.container_id),
        ))
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
                if kill_and_reap(child).is_none() && !std::thread::panicking() {
                    panic!("child was not reaped within the deadline");
                }
            }
        }
    }
}

/// `UnshareRuntime` を共有して `ContainerRuntime` として注入するためのラッパー。
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

/// sandbox を作り、コンテナを Create・Start して ID を返す。
async fn start_container(service: &CriRuntimeService) -> String {
    let sandbox = RuntimeService::run_pod_sandbox(
        service,
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
        service,
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
        service,
        Request::new(v1::StartContainerRequest {
            container_id: id.clone(),
        }),
    )
    .await
    .expect("start");
    id
}

fn child_pid(runtime: &UnshareRuntime, id: &str) -> u32 {
    runtime
        .children
        .lock()
        .expect("lock")
        .get(id)
        .map(Child::id)
        .expect("child started")
}

/// 分離が済む（`/proc/<pid>/ns/<ns>` がホストと異なる）まで最大 5 秒待ち、その参照先を返す。
fn isolated_ns(pid: u32, ns: &str) -> PathBuf {
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
    theirs
}

/// CRI-2: RemoveContainer の後、プロセスが終了して回収され、実行層へ `delete(force)` が 1 回届く。
/// 分離なしの `sleep` を使うため、非特権 user namespace を許さない runner でも動く（既定のテスト集合）。
#[tokio::test]
async fn task_59_3_remove_container_terminates_process() {
    let runtime = Arc::new(UnshareRuntime {
        plain: true,
        ..Default::default()
    });
    let _reaper = Reaper(runtime.clone());
    let service = CriRuntimeService::new().with_runtime(
        RuntimeAdapter::new(Arc::new(Shared(runtime.clone()))),
        Arc::new(FixedBundle),
    );
    let id = start_container(&service).await;
    let pid = child_pid(&runtime, &id);
    assert!(
        std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "process must be alive before remove"
    );
    RuntimeService::remove_container(
        &service,
        Request::new(v1::RemoveContainerRequest {
            container_id: id.clone(),
        }),
    )
    .await
    .expect("remove");
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "process must be gone after remove"
    );
    assert_eq!(
        runtime.deletes.lock().expect("lock").clone(),
        vec![(id, true)]
    );
    let listed = RuntimeService::list_containers(
        &service,
        Request::new(v1::ListContainersRequest { filter: None }),
    )
    .await
    .expect("list")
    .into_inner();
    assert_eq!(listed.containers.len(), 0);
}

/// CRI-2: RemoveContainer の後、プロセスが消え、その namespace を参照するプロセスが 1 つも残らない
/// （namespace の資源が解放されている）。
#[tokio::test]
#[ignore = "requires Linux with unshare(1) and unprivileged user namespaces (CRI-2, TASK-59.3)"]
async fn task_59_3_remove_container_releases_namespaces() {
    let runtime = Arc::new(UnshareRuntime::default());
    let _reaper = Reaper(runtime.clone());
    let service = CriRuntimeService::new().with_runtime(
        RuntimeAdapter::new(Arc::new(Shared(runtime.clone()))),
        Arc::new(FixedBundle),
    );
    let id = start_container(&service).await;
    let pid = child_pid(&runtime, &id);
    let before: Vec<(&str, PathBuf)> = NS.iter().map(|ns| (*ns, isolated_ns(pid, ns))).collect();
    RuntimeService::remove_container(
        &service,
        Request::new(v1::RemoveContainerRequest { container_id: id }),
    )
    .await
    .expect("remove");
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "process must be gone after remove"
    );
    // 全プロセスの ns リンクを走査し、記録した namespace を参照するものが無いことを確かめる
    // （読めないエントリは他ユーザーのプロセスなので飛ばす）。
    for (ns, link) in &before {
        let holders = std::fs::read_dir("/proc")
            .expect("proc")
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .bytes()
                    .all(|b| b.is_ascii_digit())
            })
            .filter(|e| std::fs::read_link(e.path().join("ns").join(ns)).is_ok_and(|l| l == *link))
            .count();
        assert_eq!(holders, 0, "{ns} namespace must have no remaining holder");
    }
}
/// CRI-2: StartContainer 後のプロセスが、テスト自身とは別の user/mnt/uts/ipc/net namespace に居る。
#[tokio::test]
#[ignore = "requires Linux with unshare(1) and unprivileged user namespaces (CRI-2, TASK-59.2)"]
async fn task_59_2_started_process_is_namespace_isolated() {
    let runtime = Arc::new(UnshareRuntime::default());
    let _reaper = Reaper(runtime.clone());
    let service = CriRuntimeService::new().with_runtime(
        RuntimeAdapter::new(Arc::new(Shared(runtime.clone()))),
        Arc::new(FixedBundle),
    );
    let id = start_container(&service).await;
    let pid = child_pid(&runtime, &id);
    // unshare は fork 直後は親と同じ namespace で、unshare(2) の後に分離される。
    for ns in NS {
        isolated_ns(pid, ns);
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("status");
    assert!(
        status
            .lines()
            .any(|l| l.starts_with("State:") && !l.contains("zombie") && !l.contains("dead")),
        "process must be alive: {status}"
    );
}
