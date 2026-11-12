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
/// 再採用試験用: `namespace_options` を持つ `linux.security_context` つきの要求を作る（CRI-2・#4413）。
fn run_req_with_ns(name: &str, opts: v1::NamespaceOption) -> v1::RunPodSandboxRequest {
    let mut req = run_req(name);
    if let Some(cfg) = req.config.as_mut() {
        cfg.linux = Some(v1::LinuxPodSandboxConfig {
            security_context: Some(v1::LinuxSandboxSecurityContext {
                namespace_options: Some(opts),
                ..Default::default()
            }),
            ..Default::default()
        });
    }
    req
}

/// CRI-1・CRI-2・#4413: 再採用の後の `PodSandboxStatus.linux.namespaces.options` が、作成時の
/// `namespace_options`（NODE・CONTAINER・POD・target_id・userns_options）と無改変で一致する。
/// kubelet の `PodSandboxChanged` が再起動後に sandbox を作り直さないための前提。
#[tokio::test]
async fn cri2_4413_readopt_status_linux_keeps_namespace_options() {
    let root = temp_root("linux-ns");
    let map = v1::IdMapping {
        host_id: 65536,
        container_id: 0,
        length: 65536,
    };
    let opts = v1::NamespaceOption {
        network: v1::NamespaceMode::Node as i32,
        pid: v1::NamespaceMode::Container as i32,
        ipc: v1::NamespaceMode::Pod as i32,
        target_id: "target-1".into(),
        userns_options: Some(v1::UserNamespace {
            mode: v1::NamespaceMode::Pod as i32,
            uids: vec![map],
            gids: vec![map],
        }),
    };
    let expected = v1::LinuxPodSandboxStatus {
        namespaces: Some(v1::Namespace {
            options: Some(opts.clone()),
        }),
    };

    let a = service(&root);
    let id =
        RuntimeService::run_pod_sandbox(&a, Request::new(run_req_with_ns("pod-ns", opts.clone())))
            .await
            .unwrap()
            .into_inner()
            .pod_sandbox_id;
    assert_eq!(status(&a, &id).await.linux, Some(expected.clone()));
    drop(a);

    let b = service(&root);
    let r = b.readopt_sandboxes(ListBudget::default()).unwrap();
    assert_eq!(
        (r.adopted, r.pending_unresolved, r.broken.total()),
        (1, 0, 0)
    );
    let got = status(&b, &id).await;
    assert_eq!(got.state, PodSandboxState::SandboxNotready as i32);
    let o = got
        .linux
        .clone()
        .unwrap()
        .namespaces
        .unwrap()
        .options
        .unwrap();
    assert_eq!(o.network, v1::NamespaceMode::Node as i32);
    assert_eq!(o.pid, v1::NamespaceMode::Container as i32);
    assert_eq!(o.ipc, v1::NamespaceMode::Pod as i32);
    assert_eq!(o.target_id, "target-1");
    let u = o.userns_options.clone().unwrap();
    assert_eq!(u.mode, v1::NamespaceMode::Pod as i32);
    assert_eq!(u.uids, vec![map]);
    assert_eq!(u.gids, vec![map]);
    assert_eq!(got.linux, Some(expected.clone()));

    stop(&b, &id).await.unwrap();
    assert_eq!(status(&b, &id).await.linux, Some(expected));

    remove(&b, &id).await.unwrap();
    assert!(rec_files(&root).is_empty());
    fs::remove_dir_all(&root).unwrap();
}

/// CRI-1・CRI-2・#4413: `namespace_options` を指定しない sandbox は、再採用の後も `linux`・`namespaces`
/// があり `options` は `None`（既定値を補わない）。
#[tokio::test]
async fn cri2_4413_readopt_status_linux_unspecified_has_no_options() {
    let root = temp_root("linux-ns-none");
    let a = service(&root);
    let mut ids = Vec::new();
    // (a) linux なし
    ids.push(run(&a, "pod-a").await.unwrap());
    // (b) linux あり・security_context なし
    let mut rb = run_req("pod-b");
    rb.config.as_mut().unwrap().linux = Some(v1::LinuxPodSandboxConfig::default());
    // (c) security_context あり・namespace_options なし
    let mut rc = run_req("pod-c");
    rc.config.as_mut().unwrap().linux = Some(v1::LinuxPodSandboxConfig {
        security_context: Some(v1::LinuxSandboxSecurityContext::default()),
        ..Default::default()
    });
    for req in [rb, rc] {
        ids.push(
            RuntimeService::run_pod_sandbox(&a, Request::new(req))
                .await
                .unwrap()
                .into_inner()
                .pod_sandbox_id,
        );
    }
    drop(a);

    let b = service(&root);
    let r = b.readopt_sandboxes(ListBudget::default()).unwrap();
    assert_eq!(
        (r.adopted, r.pending_unresolved, r.broken.total()),
        (3, 0, 0)
    );
    for id in &ids {
        assert_eq!(
            status(&b, id).await.linux,
            Some(v1::LinuxPodSandboxStatus {
                namespaces: Some(v1::Namespace { options: None }),
            })
        );
        remove(&b, id).await.unwrap();
    }
    assert!(rec_files(&root).is_empty());
    fs::remove_dir_all(&root).unwrap();
}
// ---- 保持役の素性の記録と再採用時の扱い（R11 #2940。CRI-2・SEC-5・SEC-1） ----

use std::time::Duration;

use fandhe_container_cri::adapter::{
    HolderIdentity, NamespaceIdentity, PodHolder, PodHolderLiveness, PodHolderRequest,
    PodNamespaceHolderProvider, ProcessStartObservation,
};

const HOLDER_LINE: &str = "holder=4242,123456,4:4026531837,4:4026531839,4:4026531840\n";

fn ns(ino: u64) -> NamespaceIdentity {
    NamespaceIdentity { dev: 4, ino }
}

/// 起動した保持役の素性（pid=4242・starttime=123456）を返し、解放・死活・観測の呼び出しを数える偽の provider。
struct IdentityHolder {
    with_identity: bool,
    observation: ProcessStartObservation,
    spawns: Mutex<usize>,
    releases: Mutex<usize>,
    liveness: Mutex<usize>,
    observed: Mutex<Vec<u32>>,
}

impl IdentityHolder {
    fn new(with_identity: bool, observation: ProcessStartObservation) -> Arc<Self> {
        Arc::new(Self {
            with_identity,
            observation,
            spawns: Mutex::new(0),
            releases: Mutex::new(0),
            liveness: Mutex::new(0),
            observed: Mutex::new(Vec::new()),
        })
    }
}

impl PodNamespaceHolderProvider for IdentityHolder {
    fn spawn(&self, _req: &PodHolderRequest<'_>) -> Result<PodHolder, CriError> {
        *self.spawns.lock().unwrap() += 1;
        if self.with_identity {
            let id =
                HolderIdentity::new(4242, 123456, ns(4026531837), ns(4026531839), ns(4026531840))?;
            Ok(PodHolder::from_identity(id))
        } else {
            Ok(PodHolder::new(4242.try_into().unwrap()))
        }
    }
    fn release(&self, _id: &str, _t: Duration) -> Result<(), CriError> {
        *self.releases.lock().unwrap() += 1;
        Ok(())
    }
    fn liveness(&self, _id: &str) -> Result<PodHolderLiveness, CriError> {
        *self.liveness.lock().unwrap() += 1;
        Ok(PodHolderLiveness::Alive)
    }
    fn observe_process_start(&self, pid: u32) -> Result<ProcessStartObservation, CriError> {
        self.observed.lock().unwrap().push(pid);
        Ok(self.observation)
    }
}

fn read_rec(root: &Path, id: &str) -> String {
    String::from_utf8_lossy(&fs::read(sandboxes_dir(root).join(format!("{id}.rec"))).unwrap())
        .into_owned()
}

/// #2940: spawn が返した素性が確定版の記録に `holder=` として書かれ、素性なしの保持役は `holder=-` になる。
#[tokio::test]
async fn cri2_sec5_2940_spawn_identity_is_written_to_the_record() {
    for (with_identity, expected) in [(true, HOLDER_LINE), (false, "holder=-\n")] {
        let root = temp_root("holder-write");
        let provider = IdentityHolder::new(with_identity, ProcessStartObservation::Absent);
        let svc = service(&root).with_pod_holder(provider.clone());
        let id = run(&svc, "pod").await.unwrap();
        assert_eq!(*provider.spawns.lock().unwrap(), 1);
        let text = read_rec(&root, &id);
        assert!(
            text.starts_with("fandhe-cri-sandbox-record v2\n"),
            "{text:?}"
        );
        assert!(text.contains(expected), "{text:?}");
        fs::remove_dir_all(&root).unwrap();
    }
}

/// #2940・AC2: 再起動後に pid が別のプロセスに再利用されていても（starttime の不一致）、シグナルも解放も spawn も
/// せず、記録を NotReady で戻す。観測は記録の pid に対して 1 回だけで、Stop・Remove は成功し、記録の `holder=` は
/// Stop の後も残り Remove で消える。
#[tokio::test]
async fn cri2_sec5_2940_readopt_with_reused_pid_never_signals_or_releases() {
    let root = temp_root("holder-reused");
    let first = IdentityHolder::new(true, ProcessStartObservation::Absent);
    let a = service(&root).with_pod_holder(first.clone());
    let id = run(&a, "pod").await.unwrap();
    drop(a);

    let second = IdentityHolder::new(
        true,
        ProcessStartObservation::Present {
            start_time_ticks: 987654,
        },
    );
    let b = service(&root).with_pod_holder(second.clone());
    let r = b.readopt_sandboxes(ListBudget::default()).unwrap();
    assert_eq!(
        (r.adopted, r.holder_recorded, r.holder_pid_reused),
        (1, 1, 1)
    );
    assert_eq!(
        (
            r.holder_gone,
            r.holder_start_time_match,
            r.holder_unobserved
        ),
        (0, 0, 0)
    );
    assert!(
        r.summary_line()
            .ends_with("holder_recorded=1 holder_gone=0 holder_pid_reused=1 holder_start_time_match=0 holder_unobserved=0")
    );
    assert_eq!(
        status(&b, &id).await.state,
        PodSandboxState::SandboxNotready as i32
    );

    stop(&b, &id).await.unwrap();
    assert!(read_rec(&root, &id).contains(HOLDER_LINE));
    remove(&b, &id).await.unwrap();
    assert!(rec_files(&root).is_empty());

    assert_eq!(*second.spawns.lock().unwrap(), 0);
    assert_eq!(*second.releases.lock().unwrap(), 0);
    assert_eq!(*second.liveness.lock().unwrap(), 0);
    assert_eq!(*second.observed.lock().unwrap(), vec![4242]);
    fs::remove_dir_all(&root).unwrap();
}
