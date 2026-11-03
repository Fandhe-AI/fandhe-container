//! 起動時の sandbox の再採用（`readopt_sandboxes`）の結合試験（CRI-1・CRI-2・REPAIR-4・REPAIR-5。#2935）。
//!
//! `FileRecordStore` を同じ状態ルートで開き直して「plugin-cri の再起動」を模し、公開 API だけで再採用後の
//! 状態と壊れた記録の扱いを具体値で照合する。

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fandhe_container_cri::adapter::{PodNetns, PodNetworkProvider, PodNetworkRequest};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig, PodSandboxMetadata,
    PodSandboxState, runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::{CriRuntimeService, FileRecordStore, ListBudget};
use tonic::{Code, Request};

fn temp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "fandhe-cri-readopt-it-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
    p
}

fn sandboxes_dir(root: &Path) -> PathBuf {
    root.join(".cri/records/sandboxes")
}

fn service(root: &Path) -> CriRuntimeService {
    CriRuntimeService::new().with_record_store(Arc::new(FileRecordStore::open(root).unwrap()))
}

fn run_req(name: &str) -> v1::RunPodSandboxRequest {
    v1::RunPodSandboxRequest {
        config: Some(PodSandboxConfig {
            metadata: Some(PodSandboxMetadata {
                name: name.into(),
                uid: "uid-1".into(),
                namespace: "ns".into(),
                attempt: 0,
            }),
            labels: [("app".to_owned(), "web".to_owned())].into(),
            annotations: [("note".to_owned(), "x".to_owned())].into(),
            ..Default::default()
        }),
        runtime_handler: String::new(),
    }
}

async fn run(svc: &CriRuntimeService, name: &str) -> Result<String, tonic::Status> {
    RuntimeService::run_pod_sandbox(svc, Request::new(run_req(name)))
        .await
        .map(|r| r.into_inner().pod_sandbox_id)
}

async fn status(svc: &CriRuntimeService, id: &str) -> v1::PodSandboxStatus {
    RuntimeService::pod_sandbox_status(
        svc,
        Request::new(v1::PodSandboxStatusRequest {
            pod_sandbox_id: id.into(),
            verbose: false,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .status
    .unwrap()
}

async fn stop(svc: &CriRuntimeService, id: &str) -> Result<(), tonic::Status> {
    RuntimeService::stop_pod_sandbox(
        svc,
        Request::new(v1::StopPodSandboxRequest {
            pod_sandbox_id: id.into(),
        }),
    )
    .await
    .map(|_| ())
}

async fn remove(svc: &CriRuntimeService, id: &str) -> Result<(), tonic::Status> {
    RuntimeService::remove_pod_sandbox(
        svc,
        Request::new(v1::RemovePodSandboxRequest {
            pod_sandbox_id: id.into(),
        }),
    )
    .await
    .map(|_| ())
}

async fn list_len(svc: &CriRuntimeService) -> usize {
    RuntimeService::list_pod_sandbox(svc, Request::new(v1::ListPodSandboxRequest::default()))
        .await
        .unwrap()
        .into_inner()
        .items
        .len()
}

fn rec_files(root: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(sandboxes_dir(root))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".rec"))
        .collect();
    v.sort();
    v
}

/// CRI-2: 再起動後に NotReady で戻り、metadata・labels・annotations が一致し、重複・コンテナ作成・削除が正しく扱われる。
#[tokio::test]
async fn cri2_readopt_after_restart_returns_notready_sandbox() {
    let root = temp_root("restart");
    let a = service(&root);
    let id = run(&a, "pod").await.unwrap();
    let before = status(&a, &id).await;
    drop(a);

    let b = service(&root);
    let r = b.readopt_sandboxes(ListBudget::default()).unwrap();
    assert_eq!(
        (r.adopted, r.pending_unresolved, r.broken.total()),
        (1, 0, 0)
    );
    let after = status(&b, &id).await;
    assert_eq!(after.state, PodSandboxState::SandboxNotready as i32);
    assert_eq!(after.metadata, before.metadata);
    assert_eq!(after.labels, before.labels);
    assert_eq!(after.annotations, before.annotations);
    assert_eq!(after.created_at, before.created_at);
    assert_eq!(list_len(&b).await, 1);

    // 同じ metadata の再作成は ALREADY_EXISTS。
    assert_eq!(
        run(&b, "pod").await.unwrap_err().code(),
        Code::AlreadyExists
    );

    // NotReady の sandbox へのコンテナ作成は拒否される。
    let e = RuntimeService::create_container(
        &b,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: id.clone(),
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
    .unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);

    // Remove で記録が消え、再起動しても戻らない。
    remove(&b, &id).await.unwrap();
    assert!(rec_files(&root).is_empty());
    drop(b);
    let c = service(&root);
    assert_eq!(
        c.readopt_sandboxes(ListBudget::default()).unwrap().adopted,
        0
    );
    fs::remove_dir_all(&root).unwrap();
}

#[derive(Default)]
struct Net {
    set_ups: Mutex<usize>,
    tear_downs: Mutex<usize>,
}

impl PodNetworkProvider for Net {
    fn set_up(&self, req: &PodNetworkRequest<'_>) -> Result<PodNetns, CriError> {
        *self.set_ups.lock().unwrap() += 1;
        PodNetns::new(PathBuf::from(format!("/state/.netns/{}", req.sandbox_id)))
    }
    fn tear_down(&self, _sandbox_id: &str) -> Result<(), CriError> {
        *self.tear_downs.lock().unwrap() += 1;
        Ok(())
    }
}

/// CRI-2: network_owned の記録は再採用で provider を呼ばず、Stop が tear_down を 1 回だけ呼んで返り、Remove で記録が消える。
#[tokio::test]
async fn cri2_readopt_owned_network_is_reclaimed_by_stop_not_by_readoption() {
    let root = temp_root("owned");
    let net_a = Arc::new(Net::default());
    let a = CriRuntimeService::new()
        .with_pod_network(net_a.clone())
        .with_record_store(Arc::new(FileRecordStore::open(&root).unwrap()));
    let mut req = run_req("pod");
    if let Some(c) = req.config.as_mut() {
        c.linux = Some(v1::LinuxPodSandboxConfig {
            security_context: Some(v1::LinuxSandboxSecurityContext {
                namespace_options: Some(v1::NamespaceOption {
                    network: v1::NamespaceMode::Pod as i32,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        });
    }
    let id = RuntimeService::run_pod_sandbox(&a, Request::new(req))
        .await
        .unwrap()
        .into_inner()
        .pod_sandbox_id;
    assert_eq!(*net_a.set_ups.lock().unwrap(), 1);
    drop(a);

    let net_b = Arc::new(Net::default());
    let b = CriRuntimeService::new()
        .with_pod_network(net_b.clone())
        .with_record_store(Arc::new(FileRecordStore::open(&root).unwrap()));
    let r = b.readopt_sandboxes(ListBudget::default()).unwrap();
    assert_eq!(r.adopted, 1);
    assert_eq!(*net_b.set_ups.lock().unwrap(), 0);
    assert_eq!(*net_b.tear_downs.lock().unwrap(), 0);

    stop(&b, &id).await.unwrap();
    assert_eq!(*net_b.tear_downs.lock().unwrap(), 1);
    remove(&b, &id).await.unwrap();
    assert!(rec_files(&root).is_empty());
    fs::remove_dir_all(&root).unwrap();
}

/// CRI-2・REPAIR-4: 壊れたファイルは登録せず内訳に数え、消さずに残す。正常な 1 件だけ採用する。
#[tokio::test]
async fn cri2_repair4_broken_files_are_counted_and_left_in_place() {
    let root = temp_root("broken");
    let a = service(&root);
    let good = run(&a, "pod").await.unwrap();
    drop(a);
    let dir = sandboxes_dir(&root);
    let good_bytes = fs::read(dir.join(format!("{good}.rec"))).unwrap();

    let write = |name: &str, bytes: &[u8]| {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(name))
            .unwrap();
        f.write_all(bytes).unwrap();
    };
    let garbage = format!("{}.rec", "b".repeat(64));
    let copied = format!("{}.rec", "c".repeat(64));
    let huge = format!("{}.rec", "d".repeat(64));
    let isdir = format!("{}.rec", "e".repeat(64));
    write(&garbage, b"not a record");
    write(&copied, &good_bytes);
    write(&huge, &vec![b'x'; 2 * 1024 * 1024]);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(dir.join(&isdir))
        .unwrap();
    write("short.rec", b"x");

    let b = service(&root);
    let r = b.readopt_sandboxes(ListBudget::default()).unwrap();
    assert_eq!(r.adopted, 1);
    assert_eq!(r.broken.malformed, 2);
    assert_eq!(r.broken.too_long, 1);
    assert_eq!(r.broken.not_regular_file, 1);
    assert_eq!(r.broken.unrecognized, 1);
    assert_eq!(r.broken.total(), 5);
    assert_eq!(list_len(&b).await, 1);
    assert_eq!(fs::read(dir.join(&garbage)).unwrap(), b"not a record");
    assert_eq!(fs::read(dir.join(&copied)).unwrap(), good_bytes);
    assert_eq!(
        fs::metadata(dir.join(&huge)).unwrap().len(),
        2 * 1024 * 1024
    );
    assert!(fs::metadata(dir.join(&isdir)).unwrap().is_dir());
    fs::remove_dir_all(&root).unwrap();
}
