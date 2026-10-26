//! 下位層の失敗が tonic トレイト境界で ERR-3 の gRPC コードとメッセージに写ることの結合試験
//! （ERR-3・CRI-3・#2218。元 PR #2187・TASK-97.2）。
//!
//! 対象は実行層 `ContainerRuntime` の `TraitError`、`BundleProvider::prepare` の `CriError`、
//! `ImagePuller` の `PullError`。これらを `RuntimeService`・`ImageService` のトレイト経由で呼び、
//! 区分とメッセージが素通しで届くことを具体値で照合する。
//!
//! 役割分担: 写像表そのものの単体照合は `src/error.rs`、状態遷移と巻き戻しは
//! `runtime_service_runtime.rs`、本物の pull 経路は `image_pull.rs`（unix 限定）が担う。
//! 本ファイルは「区分×メッセージの素通し」だけを 3 OS で見て、状態の副作用は再照合しない。
//!
//! `ErrorCode`・`OciErrorCode` は `#[non_exhaustive]` のため、下の表は現時点の区分の列挙であり網羅保証ではない。
//! 未知の区分を `Internal` へ倒す fail-closed は `src/error.rs` 側の責務である。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use fandhe_container_core::traits::{
    ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest, DeleteResponse, ErrorCode,
    KillRequest, StartRequest, StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::{
    BundleProvider, BundleRequest, PreparedBundle, RuntimeAdapter,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::image_pull::{ImagePuller, PullError, PullRequest, PulledImage};
use fandhe_container_cri::image_service::{CriImageService, InMemoryImageStore};
use fandhe_container_cri::instrument::{CriOpKind, CriOpRecorder, CriOpSample, code_name};
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig, PodSandboxMetadata,
    image_service_server::ImageService, runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use fandhe_container_oci::error::{OciError, OciErrorCode};
use tonic::{Code, Request, Status};

/// ERR-3 の区分表（`ErrorCode` と期待する gRPC コード。`Timeout` だけ名前が異なる）。
const TRAIT_CODES: [(ErrorCode, Code); 10] = [
    (ErrorCode::InvalidArgument, Code::InvalidArgument),
    (ErrorCode::NotFound, Code::NotFound),
    (ErrorCode::AlreadyExists, Code::AlreadyExists),
    (ErrorCode::FailedPrecondition, Code::FailedPrecondition),
    (ErrorCode::Unimplemented, Code::Unimplemented),
    (ErrorCode::Internal, Code::Internal),
    (ErrorCode::PermissionDenied, Code::PermissionDenied),
    (ErrorCode::Timeout, Code::DeadlineExceeded),
    (ErrorCode::Unavailable, Code::Unavailable),
    (ErrorCode::ResourceExhausted, Code::ResourceExhausted),
];

/// REPAIR-1・ERR-3: 区分表が `ErrorCode::ALL` の全 variant を過不足なく持つ（足し忘れの検出）。
#[test]
fn err3_trait_codes_table_covers_every_error_code() {
    assert_eq!(TRAIT_CODES.len(), ErrorCode::ALL.len());
    for c in ErrorCode::ALL {
        assert!(TRAIT_CODES.iter().any(|(k, _)| *k == c), "{}", c.as_str());
    }
}

/// 操作ごとに失敗コードを注入できるフェイクの実行層。
#[derive(Default)]
struct FakeRuntime {
    calls: Mutex<Vec<String>>,
    fail_create: Mutex<Option<ErrorCode>>,
    create_message: Mutex<Option<String>>,
    fail_start: Mutex<Option<ErrorCode>>,
    fail_stop: Mutex<Option<ErrorCode>>,
    fail_delete: Mutex<Option<ErrorCode>>,
}

struct Shared(Arc<FakeRuntime>);

impl ContainerRuntime for Shared {
    fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        self.0.calls.lock().unwrap().push("create".into());
        if let Some(c) = *self.0.fail_create.lock().unwrap() {
            let msg = self
                .0
                .create_message
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| "create failed".into());
            return Err(TraitError::new(c, msg));
        }
        Ok(ContainerStatus::created(r.id().clone(), None))
    }
    fn start(&self, r: &StartRequest) -> Result<ContainerStatus, TraitError> {
        if let Some(c) = *self.0.fail_start.lock().unwrap() {
            return Err(TraitError::new(c, "start failed"));
        }
        Ok(ContainerStatus::running(
            r.id().clone(),
            std::num::NonZeroU32::new(4242),
        ))
    }
    fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
    fn stop(&self, r: &StopRequest) -> Result<ContainerStatus, TraitError> {
        if let Some(c) = *self.0.fail_stop.lock().unwrap() {
            return Err(TraitError::new(c, "stop failed"));
        }
        Ok(ContainerStatus::stopped(r.id().clone(), Some(0)))
    }
    fn delete(&self, _: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        if let Some(c) = *self.0.fail_delete.lock().unwrap() {
            return Err(TraitError::new(c, "delete failed"));
        }
        Ok(DeleteResponse::new())
    }
    fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
        Ok(ContainerStatus::created(r.id().clone(), None))
    }
}

#[derive(Default)]
struct FakeBundles {
    fail_prepare: AtomicBool,
}

impl BundleProvider for FakeBundles {
    fn prepare(&self, req: &BundleRequest<'_>) -> Result<PreparedBundle, CriError> {
        let container_id = req.container_id;
        if self.fail_prepare.load(Ordering::SeqCst) {
            return Err(CriError::resource_exhausted("bundle storage is full"));
        }
        let root = if cfg!(windows) {
            PathBuf::from(r"C:\bundles")
        } else {
            PathBuf::from("/bundles")
        };
        Ok(PreparedBundle::new(root.join(container_id)))
    }
    fn release(&self, _: &str) -> Result<(), CriError> {
        Ok(())
    }
}

#[derive(Default)]
struct Collect(Mutex<Vec<CriOpSample>>);

impl CriOpRecorder for Collect {
    fn record_cri_op(&self, sample: &CriOpSample) {
        self.0.lock().unwrap().push(*sample);
    }
}

struct Harness {
    service: CriRuntimeService,
    runtime: Arc<FakeRuntime>,
    bundles: Arc<FakeBundles>,
    recorder: Arc<Collect>,
}

fn harness() -> Harness {
    let runtime = Arc::new(FakeRuntime::default());
    let bundles = Arc::new(FakeBundles::default());
    let recorder = Arc::new(Collect::default());
    let service = CriRuntimeService::with_recorder(recorder.clone()).with_runtime(
        RuntimeAdapter::new(Arc::new(Shared(runtime.clone()))),
        bundles.clone(),
    );
    Harness {
        service,
        runtime,
        bundles,
        recorder,
    }
}

async fn run_sandbox(service: &CriRuntimeService) -> String {
    let config = PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: "pod".into(),
            uid: "uid-1".into(),
            namespace: "ns".into(),
            attempt: 0,
        }),
        ..Default::default()
    };
    RuntimeService::run_pod_sandbox(
        service,
        Request::new(v1::RunPodSandboxRequest {
            config: Some(config),
            runtime_handler: String::new(),
        }),
    )
    .await
    .expect("run sandbox")
    .into_inner()
    .pod_sandbox_id
}

async fn create(service: &CriRuntimeService, sandbox: &str) -> Result<String, Status> {
    let config = ContainerConfig {
        metadata: Some(ContainerMetadata {
            name: "app".into(),
            attempt: 0,
        }),
        image: Some(ImageSpec {
            image: "busybox:1.36".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    RuntimeService::create_container(
        service,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox.into(),
            config: Some(config),
            sandbox_config: None,
        }),
    )
    .await
    .map(|r| r.into_inner().container_id)
}

async fn start(service: &CriRuntimeService, id: &str) -> Result<(), Status> {
    RuntimeService::start_container(
        service,
        Request::new(v1::StartContainerRequest {
            container_id: id.into(),
        }),
    )
    .await
    .map(|_| ())
}

async fn stop_c(service: &CriRuntimeService, id: &str) -> Result<(), Status> {
    RuntimeService::stop_container(
        service,
        Request::new(v1::StopContainerRequest {
            container_id: id.into(),
            timeout: 0,
        }),
    )
    .await
    .map(|_| ())
}

async fn remove_c(service: &CriRuntimeService, id: &str) -> Result<(), Status> {
    RuntimeService::remove_container(
        service,
        Request::new(v1::RemoveContainerRequest {
            container_id: id.into(),
        }),
    )
    .await
    .map(|_| ())
}

fn pair(e: &Status) -> (Code, String) {
    (e.code(), e.message().to_string())
}

/// ERR-3・CRI-3: `CreateContainer` で実行層の `create` が返す全 9 区分が、コードとメッセージのまま届く。
/// `Timeout` は CRI 側の期限切れ（`runtime operation timed out`）ではなく実行層の失敗として
/// `DeadlineExceeded` + `create failed` で届くことの照合も兼ねる。
#[tokio::test]
async fn err3_create_container_maps_every_trait_error_code() {
    for (code, want) in TRAIT_CODES {
        let h = harness();
        let sb = run_sandbox(&h.service).await;
        *h.runtime.fail_create.lock().unwrap() = Some(code);
        let err = create(&h.service, &sb).await.expect_err("create must fail");
        assert_eq!(pair(&err), (want, "create failed".to_string()), "{code:?}");
    }
}

/// ERR-3・CRI-3: `StartContainer` で実行層の `start` が返す全 9 区分が、コードとメッセージのまま届く。
#[tokio::test]
async fn err3_start_container_maps_every_trait_error_code() {
    for (code, want) in TRAIT_CODES {
        let h = harness();
        let sb = run_sandbox(&h.service).await;
        let id = create(&h.service, &sb).await.expect("create");
        *h.runtime.fail_start.lock().unwrap() = Some(code);
        let err = start(&h.service, &id).await.expect_err("start must fail");
        assert_eq!(pair(&err), (want, "start failed".to_string()), "{code:?}");
    }
}

/// ERR-3・CRI-3: `StopContainer` で `stop` が返す区分が届く。例外は `NotFound` で、実行層に既に無い
/// コンテナは exited に確定して成功する（CRI-2。冪等な停止）。
#[tokio::test]
async fn err3_stop_container_maps_trait_error_codes_except_not_found() {
    for (code, want) in TRAIT_CODES {
        let h = harness();
        let sb = run_sandbox(&h.service).await;
        let id = create(&h.service, &sb).await.expect("create");
        start(&h.service, &id).await.expect("start");
        *h.runtime.fail_stop.lock().unwrap() = Some(code);
        let res = stop_c(&h.service, &id).await;
        if code == ErrorCode::NotFound {
            res.expect("NotFound on stop is treated as already exited");
        } else {
            let err = res.expect_err("stop must fail");
            assert_eq!(pair(&err), (want, "stop failed".to_string()), "{code:?}");
        }
    }
}

/// ERR-3・CRI-3: `RemoveContainer` で `delete` が返す区分が届く。例外は `NotFound` で、削除済みとして成功する。
#[tokio::test]
async fn err3_remove_container_maps_trait_error_codes_except_not_found() {
    for (code, want) in TRAIT_CODES {
        let h = harness();
        let sb = run_sandbox(&h.service).await;
        let id = create(&h.service, &sb).await.expect("create");
        *h.runtime.fail_delete.lock().unwrap() = Some(code);
        let res = remove_c(&h.service, &id).await;
        if code == ErrorCode::NotFound {
            res.expect("NotFound on delete is treated as already removed");
        } else {
            let err = res.expect_err("remove must fail");
            assert_eq!(pair(&err), (want, "delete failed".to_string()), "{code:?}");
        }
    }
}

/// ERR-3・CRI-3: `BundleProvider::prepare` の `resource_exhausted` が `RESOURCE_EXHAUSTED` とメッセージのまま届く。
/// コードだけなら `runtime_service_runtime.rs` の `task_59_2_bundle_failure_skips_the_runtime` が照合済み。
/// 本試験の追加分はメッセージの素通しと記録のコード名で、実行層の `create` が呼ばれないことも確認する。
#[tokio::test]
async fn err3_bundle_prepare_resource_exhausted_reaches_status() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    h.bundles.fail_prepare.store(true, Ordering::SeqCst);
    let err = create(&h.service, &sb)
        .await
        .expect_err("prepare must fail");
    assert_eq!(
        pair(&err),
        (
            Code::ResourceExhausted,
            "bundle storage is full".to_string()
        )
    );
    assert!(h.runtime.calls.lock().unwrap().is_empty());
    let recorded: Vec<(CriOpKind, &str)> = h
        .recorder
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|s| s.kind() == CriOpKind::CreateContainer)
        .map(|s| (s.kind(), code_name(s.code())))
        .collect();
    assert_eq!(
        recorded,
        vec![(CriOpKind::CreateContainer, "RESOURCE_EXHAUSTED")]
    );
}

/// ERR-3・ERR-2: 実行層の長いメッセージ（6000 バイト）が RPC 経由でも 4095 バイト（4096 は文字の途中）に
/// 1 回だけ切り詰められ、元の接頭辞のまま UTF-8 として妥当に届く。
#[tokio::test]
async fn err3_trait_error_message_is_bounded_through_runtime_service() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let long = "あ".repeat(2000);
    *h.runtime.create_message.lock().unwrap() = Some(long.clone());
    *h.runtime.fail_create.lock().unwrap() = Some(ErrorCode::InvalidArgument);
    let err = create(&h.service, &sb).await.expect_err("create must fail");
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(err.message().len(), 4095);
    assert!(long.starts_with(err.message()));
}

/// 呼び出しを数え、常に指定の `PullError` で失敗する puller。
struct FakePuller {
    err: PullError,
    calls: AtomicUsize,
}

impl ImagePuller for FakePuller {
    fn pull(&self, _: &PullRequest) -> Result<PulledImage, PullError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(self.err)
    }
}

/// ERR-3・CRI-3・CRI-4・OCI-3: `PullImage` で puller が返す `DataLoss`・`NotFound`・`PermissionDenied`・`Timeout` が
/// コードと区分ごとの固定メッセージで届き、参照や上流の文言は漏れない。失敗した pull はストアに何も残さない。
/// `DataLoss`・`PermissionDenied` のコードは `image_pull.rs`（unix 限定・本物の puller）で照合済み。
/// 本試験は 4 区分を同一経路・3 OS でメッセージまで具体値で見る。
#[tokio::test]
async fn err3_pull_image_maps_pull_error_codes() {
    let cases = [
        (
            OciErrorCode::DataLoss,
            Code::DataLoss,
            "registry data failed validation",
            "DATA_LOSS",
        ),
        (
            OciErrorCode::NotFound,
            Code::NotFound,
            "image not found in registry",
            "NOT_FOUND",
        ),
        (
            OciErrorCode::PermissionDenied,
            Code::PermissionDenied,
            "registry access denied",
            "PERMISSION_DENIED",
        ),
        (
            OciErrorCode::Timeout,
            Code::DeadlineExceeded,
            "registry request timed out",
            "DEADLINE_EXCEEDED",
        ),
    ];
    for (oci, want, msg, name) in cases {
        let puller = Arc::new(FakePuller {
            err: PullError::from_oci(&OciError::new(
                oci,
                "upstream detail private.example.com/team/app token=dummy",
            )),
            calls: AtomicUsize::new(0),
        });
        let recorder = Arc::new(Collect::default());
        let svc = CriImageService::with_store_and_recorder(
            Arc::new(InMemoryImageStore::new()),
            recorder.clone(),
        )
        .with_puller(puller.clone());
        let req = v1::PullImageRequest {
            image: Some(ImageSpec {
                image: "private.example.com/team/app:1".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = ImageService::pull_image(&svc, Request::new(req))
            .await
            .expect_err("pull must fail");
        assert_eq!(pair(&err), (want, msg.to_string()), "{oci:?}");
        for leaked in ["private.example.com", "upstream detail", "token="] {
            assert!(!err.message().contains(leaked), "{oci:?} leaked {leaked}");
        }
        assert_eq!(puller.calls.load(Ordering::SeqCst), 1, "{oci:?}");
        let listed =
            ImageService::list_images(&svc, Request::new(v1::ListImagesRequest::default()))
                .await
                .expect("list")
                .into_inner()
                .images;
        assert!(listed.is_empty(), "{oci:?}");
        let recorded: Vec<&str> = recorder
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.kind() == CriOpKind::PullImage)
            .map(|s| code_name(s.code()))
            .collect();
        assert_eq!(recorded, vec![name], "{oci:?}");
    }
}

/// ERR-3・CRI-3・CRI-4・#2321: `PullImage` で puller が `AlreadyExists` を返すと `INTERNAL` と固定文言
/// `image pull failed` で届く。`ALREADY_EXISTS` にはしない（ERR-3 の `ALREADY_EXISTS` は Create 系専用で、
/// 冪等な `PullImage` には当たらない）。上流の文言は漏れず、ストアにも何も残らない。
#[tokio::test]
async fn err3_pull_image_already_exists_maps_to_internal() {
    let puller = Arc::new(FakePuller {
        err: PullError::from_oci(&OciError::new(
            OciErrorCode::AlreadyExists,
            "upstream detail private.example.com/team/app token=dummy",
        )),
        calls: AtomicUsize::new(0),
    });
    let recorder = Arc::new(Collect::default());
    let svc = CriImageService::with_store_and_recorder(
        Arc::new(InMemoryImageStore::new()),
        recorder.clone(),
    )
    .with_puller(puller.clone());
    let req = v1::PullImageRequest {
        image: Some(ImageSpec {
            image: "private.example.com/team/app:1".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let err = ImageService::pull_image(&svc, Request::new(req))
        .await
        .expect_err("pull must fail");
    assert_eq!(
        pair(&err),
        (Code::Internal, "image pull failed".to_string())
    );
    for leaked in ["private.example.com", "upstream detail", "token="] {
        assert!(!err.message().contains(leaked), "leaked {leaked}");
    }
    assert_eq!(puller.calls.load(Ordering::SeqCst), 1);
    let listed = ImageService::list_images(&svc, Request::new(v1::ListImagesRequest::default()))
        .await
        .expect("list")
        .into_inner()
        .images;
    assert!(listed.is_empty());
    let recorded: Vec<&str> = recorder
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|s| s.kind() == CriOpKind::PullImage)
        .map(|s| code_name(s.code()))
        .collect();
    assert_eq!(recorded, vec!["INTERNAL"]);
}
