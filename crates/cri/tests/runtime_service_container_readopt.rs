//! 起動時のコンテナ記録の再採用と core の状態との照合（`readopt_containers`）の結合試験
//! （CRI-1・CRI-2・OCI-7・REPAIR-4。#2936・R7）。
//!
//! `FileRecordStore` を同じ状態ルートで開き直して「plugin-cri の再起動」を模し、公開 API だけで再起動前後の
//! `ContainerStatus`・`ListContainers` の具体値を照合する。core の偽は再起動後に別のインスタンスへ差し替える
//! （記録の無い core だけのコンテナを含む）。全待機に上限を置く（REPAIR-5）。

#![cfg(unix)]

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fandhe_container_core::traits::{
    ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest, DeleteResponse, ErrorCode,
    KillRequest, StartRequest, StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::{
    BundleProvider, BundleRequest, PreparedBundle, RuntimeAdapter,
};
use fandhe_container_cri::bundle::{AppliedUser, ResolvedImage};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ContainerState, ImageSpec, KeyValue,
    PodSandboxConfig, PodSandboxMetadata, runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::{CriRuntimeService, FileRecordStore, ListBudget};
use fandhe_container_oci::reference::Digest;
use tonic::Request;

const ENV_SENTINEL: &str = "FANDHE_R7_ENV_SENTINEL_value";

fn temp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "fandhe-cri-readopt-ct-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
    p
}

fn containers_dir(root: &Path) -> PathBuf {
    root.join(".cri/records/containers")
}

/// core の偽。`known` にある ID だけ `state` に答える（他は `NOT_FOUND`）。
#[derive(Default)]
struct Core {
    known: Mutex<HashMap<String, bool>>,
    fail_state: Mutex<bool>,
}

struct Shared(Arc<Core>);

impl ContainerRuntime for Shared {
    fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        self.0
            .known
            .lock()
            .unwrap()
            .insert(r.id().to_string(), false);
        Ok(ContainerStatus::created(r.id().clone(), None))
    }
    fn start(&self, r: &StartRequest) -> Result<ContainerStatus, TraitError> {
        self.0
            .known
            .lock()
            .unwrap()
            .insert(r.id().to_string(), true);
        Ok(ContainerStatus::running(
            r.id().clone(),
            std::num::NonZeroU32::new(4242),
        ))
    }
    fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
    fn stop(&self, _: &StopRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
    fn delete(&self, _: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        Ok(DeleteResponse::new())
    }
    fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
        if *self.0.fail_state.lock().unwrap() {
            return Err(TraitError::new(ErrorCode::Unavailable, "down"));
        }
        match self.0.known.lock().unwrap().get(r.id().as_str()) {
            None => Err(TraitError::new(ErrorCode::NotFound, "gone")),
            Some(false) => Ok(ContainerStatus::created(r.id().clone(), None)),
            Some(true) => Ok(ContainerStatus::running(
                r.id().clone(),
                std::num::NonZeroU32::new(4242),
            )),
        }
    }
}

struct Bundles;

impl BundleProvider for Bundles {
    fn prepare(&self, req: &BundleRequest<'_>) -> Result<PreparedBundle, CriError> {
        let digest = Digest::parse(&format!("sha256:{}", "ab".repeat(32))).unwrap();
        Ok(
            PreparedBundle::new(PathBuf::from("/bundles").join(req.container_id))
                .with_stop_signal(v1::Signal::Sigint)
                .with_user(AppliedUser::new(1000, 1000, vec![2000, 3000]))
                .with_image(
                    ResolvedImage::new(digest, Some(format!("busybox@sha256:{}", "ab".repeat(32))))
                        .with_tag(Some("busybox:1.36".into())),
                ),
        )
    }
    fn release(&self, _: &str) -> Result<(), CriError> {
        Ok(())
    }
}

fn service(root: &Path, core: &Arc<Core>) -> CriRuntimeService {
    CriRuntimeService::new()
        .with_record_store(Arc::new(FileRecordStore::open(root).unwrap()))
        .with_runtime(
            RuntimeAdapter::new(Arc::new(Shared(Arc::clone(core)))),
            Arc::new(Bundles),
        )
}

async fn run_sandbox(svc: &CriRuntimeService) -> String {
    RuntimeService::run_pod_sandbox(
        svc,
        Request::new(v1::RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "pod".into(),
                    uid: "uid-1".into(),
                    namespace: "ns".into(),
                    attempt: 0,
                }),
                log_directory: "/var/log/pods/ns_pod_uid-1".into(),
                ..Default::default()
            }),
            runtime_handler: String::new(),
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .pod_sandbox_id
}

async fn create(svc: &CriRuntimeService, sandbox: &str, name: &str) -> String {
    RuntimeService::create_container(
        svc,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox.into(),
            config: Some(ContainerConfig {
                metadata: Some(ContainerMetadata {
                    name: name.into(),
                    attempt: 0,
                }),
                image: Some(ImageSpec {
                    image: "busybox:1.36".into(),
                    ..Default::default()
                }),
                log_path: format!("{name}/0.log"),
                envs: vec![KeyValue {
                    key: "SECRET".into(),
                    value: ENV_SENTINEL.into(),
                }],
                labels: [("k".to_owned(), "v".to_owned())].into(),
                annotations: [("a".to_owned(), "b".to_owned())].into(),
                ..Default::default()
            }),
            sandbox_config: None,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .container_id
}

async fn start(svc: &CriRuntimeService, id: &str) {
    RuntimeService::start_container(
        svc,
        Request::new(v1::StartContainerRequest {
            container_id: id.into(),
        }),
    )
    .await
    .unwrap();
}

async fn status(svc: &CriRuntimeService, id: &str) -> v1::ContainerStatus {
    RuntimeService::container_status(
        svc,
        Request::new(v1::ContainerStatusRequest {
            container_id: id.into(),
            verbose: false,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .status
    .unwrap()
}

async fn list(svc: &CriRuntimeService) -> Vec<v1::Container> {
    let mut items =
        RuntimeService::list_containers(svc, Request::new(v1::ListContainersRequest::default()))
            .await
            .unwrap()
            .into_inner()
            .containers;
    items.sort_by(|a, b| a.id.cmp(&b.id));
    items
}

fn restart(root: &Path, core: &Arc<Core>) -> CriRuntimeService {
    let svc = service(root, core);
    svc.readopt_sandboxes(ListBudget::default()).unwrap();
    svc
}

/// CRI-1・OCI-7: 再起動後、core に状態がある実行中・作成済みコンテナが、再起動前と同じ具体値で戻る。
#[tokio::test]
async fn cri1_oci7_readopt_after_restart_restores_container_values() {
    let root = temp_root("values");
    let core_a = Arc::new(Core::default());
    let a = service(&root, &core_a);
    let sb = run_sandbox(&a).await;
    let running = create(&a, &sb, "run").await;
    start(&a, &running).await;
    let created = create(&a, &sb, "cre").await;
    let before_run = status(&a, &running).await;
    let before_cre = status(&a, &created).await;
    let before_list = list(&a).await;
    assert_eq!(before_run.state, ContainerState::ContainerRunning as i32);
    assert_eq!(before_run.stop_signal, v1::Signal::Sigint as i32);
    assert_eq!(before_run.image_id, format!("sha256:{}", "ab".repeat(32)));
    drop(a);

    // 再起動後の core は同じコンテナを知っている。
    let core_b = Arc::new(Core::default());
    core_b
        .known
        .lock()
        .unwrap()
        .extend(core_a.known.lock().unwrap().clone());
    // CRI 記録の無い core だけのコンテナ。
    core_b.known.lock().unwrap().insert("e".repeat(64), true);
    let b = restart(&root, &core_b);
    let r = b.readopt_containers(ListBudget::default()).unwrap();
    assert_eq!(
        (r.adopted, r.present, r.stale_create, r.broken.total()),
        (2, 2, 0, 0)
    );

    let after_run = status(&b, &running).await;
    let after_cre = status(&b, &created).await;
    // 照合で状態は core の lifecycle になる。それ以外の項目は再起動前と一致する。
    assert_eq!(after_run, before_run);
    assert_eq!(after_cre, before_cre);
    assert_eq!(
        after_run.metadata.as_ref().map(|m| m.name.as_str()),
        Some("run")
    );
    assert_eq!(after_run.labels.get("k").map(String::as_str), Some("v"));
    assert_eq!(
        after_run.annotations.get("a").map(String::as_str),
        Some("b")
    );
    assert_eq!(after_run.log_path, "/var/log/pods/ns_pod_uid-1/run/0.log");
    assert_eq!(after_run.stop_signal, v1::Signal::Sigint as i32);
    assert_eq!(
        after_run
            .user
            .as_ref()
            .and_then(|u| u.linux.as_ref())
            .map(|l| (l.uid, l.gid, l.supplemental_groups.clone())),
        Some((1000, 1000, vec![2000, 3000]))
    );
    assert_eq!(after_run.image_ref, before_run.image_ref);
    assert_eq!(list(&b).await, before_list);
    // envs は応答にもファイルにも出ない。
    let dump = format!("{after_run:?}");
    assert!(!dump.contains(ENV_SENTINEL));
    for entry in fs::read_dir(containers_dir(&root)).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(ENV_SENTINEL));
    }
    // 記録の無い core のコンテナには触れない（一覧にも出ない）。
    assert!(list(&b).await.iter().all(|c| c.id != "e".repeat(64)));
    let _ = fs::remove_dir_all(&root);
}

/// CRI-1・OCI-7: core から消えていれば exited（記録の値）、状態を確定できなければ unknown。記録のファイルは消さない。
#[tokio::test]
async fn cri1_oci7_readopt_absent_and_undetermined_after_restart() {
    let root = temp_root("absent");
    let core_a = Arc::new(Core::default());
    let a = service(&root, &core_a);
    let sb = run_sandbox(&a).await;
    let c = create(&a, &sb, "c").await;
    start(&a, &c).await;
    drop(a);

    // core が空（状態ストアから消えた）→ exited。
    let core_b = Arc::new(Core::default());
    let b = restart(&root, &core_b);
    let r = b.readopt_containers(ListBudget::default()).unwrap();
    assert_eq!((r.adopted, r.absent_exited), (1, 1));
    let st = status(&b, &c).await;
    assert_eq!(st.state, ContainerState::ContainerExited as i32);
    drop(b);

    // 照会が失敗 → unknown。
    let core_c = Arc::new(Core::default());
    *core_c.fail_state.lock().unwrap() = true;
    let d = restart(&root, &core_c);
    let r = d.readopt_containers(ListBudget::default()).unwrap();
    assert_eq!((r.adopted, r.undetermined), (1, 1));
    assert_eq!(
        status(&d, &c).await.state,
        ContainerState::ContainerUnknown as i32
    );
    // どちらの再起動でもファイルは消えていない。
    assert_eq!(fs::read_dir(containers_dir(&root)).unwrap().count(), 1);
    let _ = fs::remove_dir_all(&root);
}

/// CRI-1・REPAIR-4: 壊れたコンテナ記録は消さずに数え、他の記録は戻る。
#[tokio::test]
async fn cri1_repair4_broken_container_record_is_kept_and_counted() {
    let root = temp_root("broken");
    let core_a = Arc::new(Core::default());
    let a = service(&root, &core_a);
    let sb = run_sandbox(&a).await;
    let c = create(&a, &sb, "c").await;
    start(&a, &c).await;
    drop(a);
    let junk = containers_dir(&root).join(format!("{}.rec", "9".repeat(64)));
    fs::write(&junk, b"garbage").unwrap();

    let core_b = Arc::new(Core::default());
    core_b
        .known
        .lock()
        .unwrap()
        .extend(core_a.known.lock().unwrap().clone());
    let b = restart(&root, &core_b);
    let r = b.readopt_containers(ListBudget::default()).unwrap();
    assert_eq!((r.adopted, r.broken.malformed, r.broken.total()), (1, 1, 1));
    assert!(junk.exists());
    let line = r.summary_line();
    assert!(line.contains("kind=container adopted=1 "));
    assert!(!line.contains(&c));
    let _ = fs::remove_dir_all(&root);
}
