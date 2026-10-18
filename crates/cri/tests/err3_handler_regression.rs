//! RuntimeService / ImageService ハンドラの異常系が ERR-3 の gRPC コードへ写ることの回帰試験
//! （TASK-97.2・#450・ERR-3・REPAIR-12）。
//!
//! ハンドラ内部は `CriError`（`fandhe_container_cri::error`）で失敗を組み立て、tonic トレイトの境界で
//! `Status` へ変換する。内部のリファクタで返すコードが変わらないことを、公開 API
//! （`CriRuntimeService`・`CriImageService` のトレイトメソッド）だけで具体値として照合する。
//! TASK-57（PodSandbox）・TASK-58（Container）・TASK-61（ImageService）を対象とする。

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use fandhe_container_cri::image_service::CriImageService;
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig, PodSandboxMetadata,
    image_service_server::ImageService, runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use tonic::{Code, Request, Status};

/// テスト用の最小 executor。tokio を使わず 1 回 poll し、Pending なら失敗にする。
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("future must complete without waiting"),
    }
}

fn sandbox_config(name: &str) -> PodSandboxConfig {
    PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: name.into(),
            uid: "uid".into(),
            namespace: "ns".into(),
            attempt: 0,
        }),
        ..Default::default()
    }
}

fn container_config(name: &str) -> ContainerConfig {
    ContainerConfig {
        metadata: Some(ContainerMetadata {
            name: name.into(),
            attempt: 0,
        }),
        image: Some(ImageSpec {
            image: "busybox:1.36".into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn run(
    svc: &CriRuntimeService,
    config: Option<PodSandboxConfig>,
    handler: &str,
) -> Result<String, Status> {
    block_on(svc.run_pod_sandbox(Request::new(v1::RunPodSandboxRequest {
        config,
        runtime_handler: handler.into(),
    })))
    .map(|r| r.into_inner().pod_sandbox_id)
}

fn stop_sb(svc: &CriRuntimeService, id: &str) -> Result<(), Status> {
    block_on(
        svc.stop_pod_sandbox(Request::new(v1::StopPodSandboxRequest {
            pod_sandbox_id: id.into(),
        })),
    )
    .map(|_| ())
}

fn remove_sb(svc: &CriRuntimeService, id: &str) -> Result<(), Status> {
    block_on(
        svc.remove_pod_sandbox(Request::new(v1::RemovePodSandboxRequest {
            pod_sandbox_id: id.into(),
        })),
    )
    .map(|_| ())
}

fn status_sb(svc: &CriRuntimeService, id: &str) -> Result<(), Status> {
    block_on(
        svc.pod_sandbox_status(Request::new(v1::PodSandboxStatusRequest {
            pod_sandbox_id: id.into(),
            verbose: false,
        })),
    )
    .map(|_| ())
}

fn create(
    svc: &CriRuntimeService,
    sandbox: &str,
    config: Option<ContainerConfig>,
) -> Result<String, Status> {
    block_on(
        svc.create_container(Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox.into(),
            config,
            sandbox_config: None,
        })),
    )
    .map(|r| r.into_inner().container_id)
}

fn start(svc: &CriRuntimeService, id: &str) -> Result<(), Status> {
    block_on(svc.start_container(Request::new(v1::StartContainerRequest {
        container_id: id.into(),
    })))
    .map(|_| ())
}

fn stop_c(svc: &CriRuntimeService, id: &str, timeout: i64) -> Result<(), Status> {
    block_on(svc.stop_container(Request::new(v1::StopContainerRequest {
        container_id: id.into(),
        timeout,
    })))
    .map(|_| ())
}

fn remove_c(svc: &CriRuntimeService, id: &str) -> Result<(), Status> {
    block_on(
        svc.remove_container(Request::new(v1::RemoveContainerRequest {
            container_id: id.into(),
        })),
    )
    .map(|_| ())
}

fn status_c(svc: &CriRuntimeService, id: &str) -> Result<(), Status> {
    block_on(
        svc.container_status(Request::new(v1::ContainerStatusRequest {
            container_id: id.into(),
            verbose: false,
        })),
    )
    .map(|_| ())
}

fn code_of<T>(r: Result<T, Status>) -> Code {
    match r {
        Ok(_) => Code::Ok,
        Err(s) => s.code(),
    }
}

/// ERR-3・TASK-57: PodSandbox 系の異常系が期待どおりのコードで返る。
#[test]
fn err3_task_97_2_pod_sandbox_error_codes() {
    let svc = CriRuntimeService::new();
    let cases = [
        (
            "run: no config",
            code_of(run(&svc, None, "")),
            Code::InvalidArgument,
        ),
        (
            "run: no metadata",
            code_of(run(&svc, Some(PodSandboxConfig::default()), "")),
            Code::InvalidArgument,
        ),
        (
            "run: empty name",
            code_of(run(&svc, Some(sandbox_config("")), "")),
            Code::InvalidArgument,
        ),
        (
            "run: unknown handler",
            code_of(run(&svc, Some(sandbox_config("a")), "no-such-handler")),
            Code::InvalidArgument,
        ),
        (
            "stop: empty id",
            code_of(stop_sb(&svc, "")),
            Code::InvalidArgument,
        ),
        (
            "stop: unknown id",
            code_of(stop_sb(&svc, "nope")),
            Code::NotFound,
        ),
        (
            "remove: empty id",
            code_of(remove_sb(&svc, "")),
            Code::InvalidArgument,
        ),
        (
            "remove: unknown id is idempotent",
            code_of(remove_sb(&svc, "nope")),
            Code::Ok,
        ),
        (
            "status: empty id",
            code_of(status_sb(&svc, "")),
            Code::InvalidArgument,
        ),
        (
            "status: unknown id",
            code_of(status_sb(&svc, "nope")),
            Code::NotFound,
        ),
    ];
    for (name, got, want) in cases {
        assert_eq!(got, want, "{name}");
    }
}

/// ERR-3・TASK-57: 件数上限超過は FAILED_PRECONDITION。
#[test]
fn err3_task_97_2_run_pod_sandbox_over_limit() {
    let svc = CriRuntimeService::with_max_sandboxes(1);
    run(&svc, Some(sandbox_config("a")), "").expect("first");
    assert_eq!(
        code_of(run(&svc, Some(sandbox_config("b")), "")),
        Code::FailedPrecondition
    );
}

/// ERR-3・TASK-57: ListPodSandbox の未知の state 値は INVALID_ARGUMENT。
#[test]
fn err3_task_97_2_list_pod_sandbox_invalid_filter() {
    let svc = CriRuntimeService::new();
    let r = block_on(
        svc.list_pod_sandbox(Request::new(v1::ListPodSandboxRequest {
            filter: Some(v1::PodSandboxFilter {
                state: Some(v1::PodSandboxStateValue { state: 99 }),
                ..Default::default()
            }),
        })),
    );
    assert_eq!(code_of(r), Code::InvalidArgument);
}

/// ERR-3・TASK-58: Container 系の異常系が期待どおりのコードで返る。
#[test]
fn err3_task_97_2_container_error_codes() {
    let svc = CriRuntimeService::new();
    let sb = run(&svc, Some(sandbox_config("a")), "").expect("sandbox");
    let notready = run(&svc, Some(sandbox_config("b")), "").expect("sandbox b");
    stop_sb(&svc, &notready).expect("stop b");
    let mut no_image = container_config("n");
    no_image.image = None;
    let cid = create(&svc, &sb, Some(container_config("c"))).expect("create");
    let x = || Some(container_config("x"));
    let cases = [
        (
            "create: empty sandbox id",
            code_of(create(&svc, "", x())),
            Code::InvalidArgument,
        ),
        (
            "create: no config",
            code_of(create(&svc, &sb, None)),
            Code::InvalidArgument,
        ),
        (
            "create: no image",
            code_of(create(&svc, &sb, Some(no_image))),
            Code::InvalidArgument,
        ),
        (
            "create: unknown sandbox",
            code_of(create(&svc, "nope", x())),
            Code::NotFound,
        ),
        (
            "create: notready sandbox",
            code_of(create(&svc, &notready, x())),
            Code::FailedPrecondition,
        ),
        (
            "create: duplicate",
            code_of(create(&svc, &sb, Some(container_config("c")))),
            Code::AlreadyExists,
        ),
        (
            "start: empty id",
            code_of(start(&svc, "")),
            Code::InvalidArgument,
        ),
        (
            "start: unknown id",
            code_of(start(&svc, "nope")),
            Code::NotFound,
        ),
        (
            "stop: empty id",
            code_of(stop_c(&svc, "", 0)),
            Code::InvalidArgument,
        ),
        (
            "stop: negative timeout",
            code_of(stop_c(&svc, &cid, -1)),
            Code::InvalidArgument,
        ),
        (
            "stop: unknown id",
            code_of(stop_c(&svc, "nope", 0)),
            Code::NotFound,
        ),
        (
            "remove: empty id",
            code_of(remove_c(&svc, "")),
            Code::InvalidArgument,
        ),
        (
            "remove: unknown id is idempotent",
            code_of(remove_c(&svc, "nope")),
            Code::Ok,
        ),
        (
            "status: empty id",
            code_of(status_c(&svc, "")),
            Code::InvalidArgument,
        ),
        (
            "status: unknown id",
            code_of(status_c(&svc, "nope")),
            Code::NotFound,
        ),
    ];
    for (name, got, want) in cases {
        assert_eq!(got, want, "{name}");
    }
    start(&svc, &cid).expect("start");
    assert_eq!(
        code_of(start(&svc, &cid)),
        Code::FailedPrecondition,
        "start: twice"
    );
}

/// ERR-3・TASK-58: ListContainers の未知の state 値は INVALID_ARGUMENT。
#[test]
fn err3_task_97_2_list_containers_invalid_filter() {
    let svc = CriRuntimeService::new();
    let r = block_on(svc.list_containers(Request::new(v1::ListContainersRequest {
        filter: Some(v1::ContainerFilter {
            state: Some(v1::ContainerStateValue { state: 99 }),
            ..Default::default()
        }),
    })));
    assert_eq!(code_of(r), Code::InvalidArgument);
}

/// ERR-3・TASK-61: ImageService の異常系が期待どおりのコードで返り、メッセージに参照を含まない。
#[test]
fn err3_task_97_2_image_service_error_codes() {
    let svc = CriImageService::new();
    let long = "x".repeat(1024 * 1024);
    let spec = |s: &str| {
        Some(v1::ImageSpec {
            image: s.into(),
            ..Default::default()
        })
    };
    let st = |image| {
        code_of(block_on(svc.image_status(Request::new(
            v1::ImageStatusRequest {
                image,
                verbose: false,
            },
        ))))
    };
    assert_eq!(st(None), Code::InvalidArgument);
    assert_eq!(st(spec("")), Code::InvalidArgument);
    assert_eq!(st(spec(&long)), Code::InvalidArgument);
    let ls = block_on(svc.list_images(Request::new(v1::ListImagesRequest {
        filter: Some(v1::ImageFilter { image: spec(&long) }),
    })));
    assert_eq!(code_of(ls), Code::InvalidArgument);
    let pull = block_on(svc.pull_image(Request::new(v1::PullImageRequest {
        image: spec("reg/secret:1"),
        ..Default::default()
    })));
    let err = pull.expect_err("no puller");
    assert_eq!(err.code(), Code::Unimplemented);
    assert!(!err.message().contains("reg/secret"));
    let rm = block_on(svc.remove_image(Request::new(Default::default())));
    assert_eq!(code_of(rm), Code::Unimplemented);
    let fs = block_on(svc.image_fs_info(Request::new(Default::default())));
    assert_eq!(code_of(fs), Code::Unimplemented);
}
