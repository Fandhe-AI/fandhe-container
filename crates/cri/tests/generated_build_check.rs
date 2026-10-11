//! 生成コードのビルド確認（TASK-56.4・#427・CRI-3・REPAIR-12）。
//!
//! `build.rs` が生成し `fandhe_container_cri::runtime::v1` で取り込んだ `RuntimeService` / `ImageService`
//! トレイトを、全 RPC で `Unimplemented` を返すダミーで実装し、型レベルの整合（メソッド集合・関連型・
//! メッセージ型）が `cargo build` / `cargo test` でコンパイルを通ることを機械照合する。
//! plugin-cri（TASK-108）と同じ外部利用者の立場で、公開 API だけを使う。
//!
//! メソッド一覧は意図的にハードコードしている。cri-api の更新で RPC が増減するとここがコンパイルエラーになり、
//! 取り込み側（TASK-57 以降・TASK-108）への影響を早期に検出できる。ネットワーク I/O（bind・listen）は行わない。

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use fandhe_container_cri::runtime::v1::{
    self,
    image_service_server::{self, ImageServiceServer},
    runtime_service_server::{self, RuntimeServiceServer},
};
use prost::Message;
use tonic::codegen::tokio_stream::Empty;
use tonic::server::NamedService;
use tonic::{Request, Response, Status};

/// 全 RPC が `Unimplemented` を返す最小のダミー実装。
struct Dummy;

/// テスト用の最小 executor。tokio を使わず 1 回 poll し、Pending なら失敗にする。
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("future must complete without waiting"),
    }
}
#[tonic::async_trait]
impl runtime_service_server::RuntimeService for Dummy {
    type StreamPodSandboxesStream = Empty<Result<v1::StreamPodSandboxesResponse, Status>>;
    type StreamContainersStream = Empty<Result<v1::StreamContainersResponse, Status>>;
    type StreamContainerStatsStream = Empty<Result<v1::StreamContainerStatsResponse, Status>>;
    type StreamPodSandboxStatsStream = Empty<Result<v1::StreamPodSandboxStatsResponse, Status>>;
    type GetContainerEventsStream = Empty<Result<v1::ContainerEventResponse, Status>>;
    type StreamPodSandboxMetricsStream = Empty<Result<v1::StreamPodSandboxMetricsResponse, Status>>;
    async fn version(
        &self,
        _request: Request<v1::VersionRequest>,
    ) -> Result<Response<v1::VersionResponse>, Status> {
        Err(Status::unimplemented("version"))
    }
    async fn run_pod_sandbox(
        &self,
        _request: Request<v1::RunPodSandboxRequest>,
    ) -> Result<Response<v1::RunPodSandboxResponse>, Status> {
        Err(Status::unimplemented("run_pod_sandbox"))
    }
    async fn stop_pod_sandbox(
        &self,
        _request: Request<v1::StopPodSandboxRequest>,
    ) -> Result<Response<v1::StopPodSandboxResponse>, Status> {
        Err(Status::unimplemented("stop_pod_sandbox"))
    }
    async fn remove_pod_sandbox(
        &self,
        _request: Request<v1::RemovePodSandboxRequest>,
    ) -> Result<Response<v1::RemovePodSandboxResponse>, Status> {
        Err(Status::unimplemented("remove_pod_sandbox"))
    }
    async fn pod_sandbox_status(
        &self,
        _request: Request<v1::PodSandboxStatusRequest>,
    ) -> Result<Response<v1::PodSandboxStatusResponse>, Status> {
        Err(Status::unimplemented("pod_sandbox_status"))
    }
    async fn list_pod_sandbox(
        &self,
        _request: Request<v1::ListPodSandboxRequest>,
    ) -> Result<Response<v1::ListPodSandboxResponse>, Status> {
        Err(Status::unimplemented("list_pod_sandbox"))
    }
    async fn stream_pod_sandboxes(
        &self,
        _request: Request<v1::StreamPodSandboxesRequest>,
    ) -> Result<Response<Self::StreamPodSandboxesStream>, Status> {
        Err(Status::unimplemented("stream_pod_sandboxes"))
    }
    async fn create_container(
        &self,
        _request: Request<v1::CreateContainerRequest>,
    ) -> Result<Response<v1::CreateContainerResponse>, Status> {
        Err(Status::unimplemented("create_container"))
    }
    async fn start_container(
        &self,
        _request: Request<v1::StartContainerRequest>,
    ) -> Result<Response<v1::StartContainerResponse>, Status> {
        Err(Status::unimplemented("start_container"))
    }
    async fn stop_container(
        &self,
        _request: Request<v1::StopContainerRequest>,
    ) -> Result<Response<v1::StopContainerResponse>, Status> {
        Err(Status::unimplemented("stop_container"))
    }
    async fn remove_container(
        &self,
        _request: Request<v1::RemoveContainerRequest>,
    ) -> Result<Response<v1::RemoveContainerResponse>, Status> {
        Err(Status::unimplemented("remove_container"))
    }
    async fn list_containers(
        &self,
        _request: Request<v1::ListContainersRequest>,
    ) -> Result<Response<v1::ListContainersResponse>, Status> {
        Err(Status::unimplemented("list_containers"))
    }
    async fn stream_containers(
        &self,
        _request: Request<v1::StreamContainersRequest>,
    ) -> Result<Response<Self::StreamContainersStream>, Status> {
        Err(Status::unimplemented("stream_containers"))
    }
    async fn container_status(
        &self,
        _request: Request<v1::ContainerStatusRequest>,
    ) -> Result<Response<v1::ContainerStatusResponse>, Status> {
        Err(Status::unimplemented("container_status"))
    }
    async fn update_container_resources(
        &self,
        _request: Request<v1::UpdateContainerResourcesRequest>,
    ) -> Result<Response<v1::UpdateContainerResourcesResponse>, Status> {
        Err(Status::unimplemented("update_container_resources"))
    }
    async fn reopen_container_log(
        &self,
        _request: Request<v1::ReopenContainerLogRequest>,
    ) -> Result<Response<v1::ReopenContainerLogResponse>, Status> {
        Err(Status::unimplemented("reopen_container_log"))
    }
    async fn exec_sync(
        &self,
        _request: Request<v1::ExecSyncRequest>,
    ) -> Result<Response<v1::ExecSyncResponse>, Status> {
        Err(Status::unimplemented("exec_sync"))
    }
    async fn exec(
        &self,
        _request: Request<v1::ExecRequest>,
    ) -> Result<Response<v1::ExecResponse>, Status> {
        Err(Status::unimplemented("exec"))
    }
    async fn attach(
        &self,
        _request: Request<v1::AttachRequest>,
    ) -> Result<Response<v1::AttachResponse>, Status> {
        Err(Status::unimplemented("attach"))
    }
    async fn port_forward(
        &self,
        _request: Request<v1::PortForwardRequest>,
    ) -> Result<Response<v1::PortForwardResponse>, Status> {
        Err(Status::unimplemented("port_forward"))
    }
    async fn container_stats(
        &self,
        _request: Request<v1::ContainerStatsRequest>,
    ) -> Result<Response<v1::ContainerStatsResponse>, Status> {
        Err(Status::unimplemented("container_stats"))
    }
    async fn list_container_stats(
        &self,
        _request: Request<v1::ListContainerStatsRequest>,
    ) -> Result<Response<v1::ListContainerStatsResponse>, Status> {
        Err(Status::unimplemented("list_container_stats"))
    }
    async fn stream_container_stats(
        &self,
        _request: Request<v1::StreamContainerStatsRequest>,
    ) -> Result<Response<Self::StreamContainerStatsStream>, Status> {
        Err(Status::unimplemented("stream_container_stats"))
    }
    async fn pod_sandbox_stats(
        &self,
        _request: Request<v1::PodSandboxStatsRequest>,
    ) -> Result<Response<v1::PodSandboxStatsResponse>, Status> {
        Err(Status::unimplemented("pod_sandbox_stats"))
    }
    async fn list_pod_sandbox_stats(
        &self,
        _request: Request<v1::ListPodSandboxStatsRequest>,
    ) -> Result<Response<v1::ListPodSandboxStatsResponse>, Status> {
        Err(Status::unimplemented("list_pod_sandbox_stats"))
    }
    async fn stream_pod_sandbox_stats(
        &self,
        _request: Request<v1::StreamPodSandboxStatsRequest>,
    ) -> Result<Response<Self::StreamPodSandboxStatsStream>, Status> {
        Err(Status::unimplemented("stream_pod_sandbox_stats"))
    }
    async fn update_runtime_config(
        &self,
        _request: Request<v1::UpdateRuntimeConfigRequest>,
    ) -> Result<Response<v1::UpdateRuntimeConfigResponse>, Status> {
        Err(Status::unimplemented("update_runtime_config"))
    }
    async fn status(
        &self,
        _request: Request<v1::StatusRequest>,
    ) -> Result<Response<v1::StatusResponse>, Status> {
        Err(Status::unimplemented("status"))
    }
    async fn checkpoint_container(
        &self,
        _request: Request<v1::CheckpointContainerRequest>,
    ) -> Result<Response<v1::CheckpointContainerResponse>, Status> {
        Err(Status::unimplemented("checkpoint_container"))
    }
    async fn checkpoint_pod(
        &self,
        _request: Request<v1::CheckpointPodRequest>,
    ) -> Result<Response<v1::CheckpointPodResponse>, Status> {
        Err(Status::unimplemented("checkpoint_pod"))
    }
    async fn restore_pod(
        &self,
        _request: Request<v1::RestorePodRequest>,
    ) -> Result<Response<v1::RestorePodResponse>, Status> {
        Err(Status::unimplemented("restore_pod"))
    }
    async fn get_container_events(
        &self,
        _request: Request<v1::GetEventsRequest>,
    ) -> Result<Response<Self::GetContainerEventsStream>, Status> {
        Err(Status::unimplemented("get_container_events"))
    }
    async fn list_metric_descriptors(
        &self,
        _request: Request<v1::ListMetricDescriptorsRequest>,
    ) -> Result<Response<v1::ListMetricDescriptorsResponse>, Status> {
        Err(Status::unimplemented("list_metric_descriptors"))
    }
    async fn list_pod_sandbox_metrics(
        &self,
        _request: Request<v1::ListPodSandboxMetricsRequest>,
    ) -> Result<Response<v1::ListPodSandboxMetricsResponse>, Status> {
        Err(Status::unimplemented("list_pod_sandbox_metrics"))
    }
    async fn stream_pod_sandbox_metrics(
        &self,
        _request: Request<v1::StreamPodSandboxMetricsRequest>,
    ) -> Result<Response<Self::StreamPodSandboxMetricsStream>, Status> {
        Err(Status::unimplemented("stream_pod_sandbox_metrics"))
    }
    async fn runtime_config(
        &self,
        _request: Request<v1::RuntimeConfigRequest>,
    ) -> Result<Response<v1::RuntimeConfigResponse>, Status> {
        Err(Status::unimplemented("runtime_config"))
    }
    async fn update_pod_sandbox_resources(
        &self,
        _request: Request<v1::UpdatePodSandboxResourcesRequest>,
    ) -> Result<Response<v1::UpdatePodSandboxResourcesResponse>, Status> {
        Err(Status::unimplemented("update_pod_sandbox_resources"))
    }
}

#[tonic::async_trait]
impl image_service_server::ImageService for Dummy {
    type StreamImagesStream = Empty<Result<v1::StreamImagesResponse, Status>>;
    async fn list_images(
        &self,
        _request: Request<v1::ListImagesRequest>,
    ) -> Result<Response<v1::ListImagesResponse>, Status> {
        Err(Status::unimplemented("list_images"))
    }
    async fn stream_images(
        &self,
        _request: Request<v1::StreamImagesRequest>,
    ) -> Result<Response<Self::StreamImagesStream>, Status> {
        Err(Status::unimplemented("stream_images"))
    }
    async fn image_status(
        &self,
        _request: Request<v1::ImageStatusRequest>,
    ) -> Result<Response<v1::ImageStatusResponse>, Status> {
        Err(Status::unimplemented("image_status"))
    }
    async fn pull_image(
        &self,
        _request: Request<v1::PullImageRequest>,
    ) -> Result<Response<v1::PullImageResponse>, Status> {
        Err(Status::unimplemented("pull_image"))
    }
    async fn remove_image(
        &self,
        _request: Request<v1::RemoveImageRequest>,
    ) -> Result<Response<v1::RemoveImageResponse>, Status> {
        Err(Status::unimplemented("remove_image"))
    }
    async fn image_fs_info(
        &self,
        _request: Request<v1::ImageFsInfoRequest>,
    ) -> Result<Response<v1::ImageFsInfoResponse>, Status> {
        Err(Status::unimplemented("image_fs_info"))
    }
}
/// CRI-3: `RuntimeServiceServer` がダミーを包めて、gRPC のサービス名が cri-api と一致する。
#[test]
fn task_56_4_runtime_service_server_wraps_dummy() {
    let _server = RuntimeServiceServer::new(Dummy);
    assert_eq!(
        <RuntimeServiceServer<Dummy> as NamedService>::NAME,
        "runtime.v1.RuntimeService"
    );
}

/// CRI-3: `ImageServiceServer` がダミーを包めて、gRPC のサービス名が cri-api と一致する。
#[test]
fn task_56_4_image_service_server_wraps_dummy() {
    let _server = ImageServiceServer::new(Dummy);
    assert_eq!(
        <ImageServiceServer<Dummy> as NamedService>::NAME,
        "runtime.v1.ImageService"
    );
}

/// CRI-3: ダミーの RPC は `Unimplemented` を返す（Runtime / Image の両トレイト）。
#[test]
fn task_56_4_dummy_returns_unimplemented() {
    let req = Request::new(v1::VersionRequest {
        version: "0.1.0".into(),
    });
    let err = block_on(runtime_service_server::RuntimeService::version(&Dummy, req))
        .expect_err("dummy must return an error");
    assert_eq!(err.code(), tonic::Code::Unimplemented);
    assert_eq!(err.message(), "version");

    let req = Request::new(v1::ListImagesRequest::default());
    let err = block_on(image_service_server::ImageService::list_images(&Dummy, req))
        .expect_err("dummy must return an error");
    assert_eq!(err.code(), tonic::Code::Unimplemented);
    assert_eq!(err.message(), "list_images");
}

/// CRI-3: 生成メッセージ型が `prost::Message` として encode / decode で往復できる。
#[test]
fn task_56_4_message_roundtrip() {
    let msg = v1::VersionRequest {
        version: "0.1.0".into(),
    };
    let bytes = msg.encode_to_vec();
    let decoded = v1::VersionRequest::decode(bytes.as_slice()).expect("decode");
    assert_eq!(decoded, msg);
    assert_eq!(decoded.version, "0.1.0");
}
