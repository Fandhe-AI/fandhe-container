//! `CriRuntimeService` の `RunPodSandbox`・`StopPodSandbox`・`RemovePodSandbox` を公開 API だけで検証する結合試験
//! （TASK-57.1・TASK-57.2・#429・#430・CRI-1・ERR-3・REPAIR-4・REPAIR-12）。
//!
//! plugin-cri（TASK-108）と同じ外部利用者の立場で、`fandhe_container_cri` の公開の型
//! （`CriRuntimeService`・`SandboxLimits`・`CriOpRecorder`・生成された `RuntimeService` トレイト）だけを
//! 使う。非公開のレジストリは覗かないため、「失敗時に状態を変えない」ことは、上限を 1 件に絞った
//! サービスで失敗の後に 1 件だけ登録できることから確かめる。
//!
//! 状態の読み取りは `PodSandboxStatus`・`ListPodSandbox`（TASK-57.3・#431）で公開 API 経由に照合し、
//! レジストリ内部との突き合わせは `src/runtime_service.rs` のユニットテストが担う。
//! ネットワーク I/O（bind・listen）は行わない。

use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use fandhe_container_cri::instrument::{
    CriOpKind, CriOpOutcome, CriOpRecorder, CriOpSample, code_name,
};
use fandhe_container_cri::runtime::v1::{
    self, PodSandboxConfig, PodSandboxMetadata,
    runtime_service_server::{RuntimeService, RuntimeServiceServer},
};
use fandhe_container_cri::runtime_service::{
    CriRuntimeService, MAX_CONFIG_COLLECTION_ENTRIES, MAX_CONFIG_ENCODED_BYTES,
    MAX_METADATA_FIELD_BYTES, MAX_RETAINED_CONFIG_BYTES, MAX_SANDBOXES, RETAINED_BYTES_PER_ENTRY,
    RETAINED_BYTES_PER_RECORD, SandboxLimits,
};
use prost::Message;
use tonic::server::NamedService;
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

/// 受け取ったサンプルを順に保持する記録先（公開トレイト `CriOpRecorder` の外部実装）。
#[derive(Default)]
struct Collect(Mutex<Vec<CriOpSample>>);

impl CriOpRecorder for Collect {
    fn record_cri_op(&self, sample: &CriOpSample) {
        if let Ok(mut samples) = self.0.lock() {
            samples.push(*sample);
        }
    }
}

impl Collect {
    fn samples(&self) -> Vec<CriOpSample> {
        self.0.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// (操作名, 結果, ステータスコードの正準名) の列。
    fn lines(&self) -> Vec<(&'static str, &'static str, &'static str)> {
        self.samples()
            .iter()
            .map(|s| (s.kind().as_str(), s.outcome().as_str(), code_name(s.code())))
            .collect()
    }
}

/// labels 1 件・annotations 1 件を持つ最小の config。
fn config(name: &str) -> PodSandboxConfig {
    let mut config = PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: name.into(),
            uid: "uid-1".into(),
            namespace: "ns".into(),
            attempt: 2,
        }),
        ..Default::default()
    };
    config.labels.insert("k".into(), "v".into());
    config.annotations.insert("a".into(), "b".into());
    config
}

/// 公開トレイト経由で `RunPodSandbox` を呼ぶ。成功は ID、失敗は (コード, メッセージ)。
fn run(
    service: &CriRuntimeService,
    config: Option<PodSandboxConfig>,
    runtime_handler: &str,
) -> Result<String, (Code, String)> {
    let request = Request::new(v1::RunPodSandboxRequest {
        config,
        runtime_handler: runtime_handler.into(),
    });
    block_on(RuntimeService::run_pod_sandbox(service, request))
        .map(|response| response.into_inner().pod_sandbox_id)
        .map_err(|status: Status| (status.code(), status.message().to_owned()))
}

fn invalid(message: &str) -> Result<String, (Code, String)> {
    Err((Code::InvalidArgument, message.to_owned()))
}

fn is_sandbox_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// CRI-1・TASK-57.1: 既定の構成で `RunPodSandbox` が 64 文字の小文字 16 進の ID を返し、
/// 呼び出しごとに異なる ID になる。
#[test]
fn task_57_1_run_pod_sandbox_returns_distinct_ids() {
    let service = CriRuntimeService::new();
    let first = run(&service, Some(config("pod-a")), "").expect("first sandbox");
    let second = run(&service, Some(config("pod-a")), "").expect("second sandbox");
    assert_eq!(first.len(), 64);
    assert!(is_sandbox_id(&first), "{first}");
    assert!(is_sandbox_id(&second), "{second}");
    assert_ne!(first, second);
}

/// CRI-1・TASK-57.1: `RuntimeServiceServer` が `CriRuntimeService` を包めて、gRPC のサービス名が
/// cri-api と一致する（plugin-cri〔TASK-108〕が載せる入口）。
#[test]
fn task_57_1_runtime_service_server_wraps_cri_runtime_service() {
    let _server = RuntimeServiceServer::new(CriRuntimeService::default());
    assert_eq!(
        <RuntimeServiceServer<CriRuntimeService> as NamedService>::NAME,
        "runtime.v1.RuntimeService"
    );
}

/// ERR-3・TASK-57.1: 必須フィールドの欠落と未知のハンドラは、それぞれ固有のメッセージの
/// INVALID_ARGUMENT で拒否され、状態を変えない。
#[test]
fn task_57_1_missing_or_unknown_input_is_rejected() {
    let service = CriRuntimeService::with_max_sandboxes(1);
    assert_eq!(run(&service, None, ""), invalid("config is required"));
    assert_eq!(
        run(&service, Some(PodSandboxConfig::default()), ""),
        invalid("config.metadata is required")
    );
    assert_eq!(
        run(&service, Some(config("")), ""),
        invalid("config.metadata.name is required")
    );
    assert_eq!(
        run(&service, Some(config("pod-a")), "unknown-handler"),
        invalid("unknown runtime_handler")
    );
    // 上限 1 件のサービスで、拒否の後に 1 件登録できる（拒否は枠を消費していない）。
    let id = run(&service, Some(config("pod-a")), "").expect("slot is still free");
    assert!(is_sandbox_id(&id), "{id}");
}

/// ERR-3・TASK-57.1: config の総サイズ・metadata の長さ・repeated / map の件数が上限を超える要求は
/// INVALID_ARGUMENT で拒否され、状態を変えない。上限ちょうどは受け付ける。
#[test]
fn task_57_1_oversized_config_is_rejected() {
    assert_eq!(MAX_CONFIG_ENCODED_BYTES, 524_288);
    assert_eq!(MAX_METADATA_FIELD_BYTES, 253);
    assert_eq!(MAX_CONFIG_COLLECTION_ENTRIES, 1024);
    let service = CriRuntimeService::with_max_sandboxes(1);

    let mut too_large = config("pod-a");
    too_large.annotations.insert(
        "big".into(),
        "x".repeat(MAX_CONFIG_ENCODED_BYTES - too_large.encoded_len()),
    );
    let encoded_len = too_large.encoded_len();
    assert!(encoded_len > 524_288);
    assert_eq!(
        run(&service, Some(too_large), ""),
        invalid(&format!(
            "config is too large: {encoded_len} bytes exceeds the limit of 524288 bytes"
        ))
    );

    let mut long_namespace = config("pod-a");
    if let Some(metadata) = long_namespace.metadata.as_mut() {
        metadata.namespace = "n".repeat(254);
    }
    assert_eq!(
        run(&service, Some(long_namespace), ""),
        invalid("config.metadata.namespace is too long: 254 bytes exceeds the limit of 253 bytes")
    );

    let mut too_many_labels = config("pod-a");
    too_many_labels.labels = (0..1025)
        .map(|i| (format!("k{i}"), String::new()))
        .collect();
    assert_eq!(
        run(&service, Some(too_many_labels), ""),
        invalid("config.labels has too many entries: 1025 exceeds the limit of 1024")
    );

    let mut too_many_ports = config("pod-a");
    too_many_ports.port_mappings = vec![v1::PortMapping::default(); 1025];
    assert_eq!(
        run(&service, Some(too_many_ports), ""),
        invalid("config.port_mappings has too many entries: 1025 exceeds the limit of 1024")
    );

    // 上限ちょうど（name 253 バイト・labels 1024 件）は受け付ける。拒否は枠を消費していない。
    let mut at_limit = config(&"n".repeat(253));
    at_limit.labels = (0..1024)
        .map(|i| (format!("k{i}"), String::new()))
        .collect();
    let id = run(&service, Some(at_limit), "").expect("at the limits");
    assert!(is_sandbox_id(&id), "{id}");
}

/// ERR-3・TASK-57.1: サンドボックス数の上限に達すると FAILED_PRECONDITION で、既定の上限は 1024。
#[test]
fn task_57_1_sandbox_count_limit_returns_failed_precondition() {
    assert_eq!(MAX_SANDBOXES, 1024);
    assert_eq!(SandboxLimits::default().max_sandboxes(), 1024);

    let service = CriRuntimeService::with_max_sandboxes(2);
    run(&service, Some(config("pod-a")), "").expect("first sandbox");
    run(&service, Some(config("pod-b")), "").expect("second sandbox");
    for _ in 0..2 {
        assert_eq!(
            run(&service, Some(config("pod-c")), ""),
            Err((Code::FailedPrecondition, "too many sandboxes".to_owned()))
        );
    }
}

/// ERR-3・TASK-57.1: 既定の構成で 1024 件まで登録でき、1025 件目が FAILED_PRECONDITION になる。
#[test]
fn task_57_1_default_limit_accepts_1024_sandboxes() {
    let service = CriRuntimeService::new();
    let mut ids = std::collections::HashSet::new();
    for _ in 0..1024 {
        ids.insert(run(&service, Some(config("pod-a")), "").expect("within the limit"));
    }
    assert_eq!(ids.len(), 1024);
    assert_eq!(
        run(&service, Some(config("pod-a")), ""),
        Err((Code::FailedPrecondition, "too many sandboxes".to_owned()))
    );
}

/// ERR-3・TASK-57.1: 保持する config の量の見積もり（符号化長＋要素数×256＋4096）の合計が上限に
/// 達すると FAILED_PRECONDITION で、件数の上限に達していなくても登録できない。既定の上限は 64 MiB。
#[test]
fn task_57_1_retained_config_limit_returns_failed_precondition() {
    assert_eq!(MAX_RETAINED_CONFIG_BYTES, 67_108_864);
    assert_eq!(RETAINED_BYTES_PER_ENTRY, 256);
    assert_eq!(RETAINED_BYTES_PER_RECORD, 4096);
    assert_eq!(SandboxLimits::default().max_retained_bytes(), 67_108_864);

    let pod = config("pod-a");
    // labels 1 件＋annotations 1 件 = 要素 2 件。
    let per_sandbox = pod.encoded_len() + 2 * 256 + 4096;
    let limits = SandboxLimits::new().with_max_retained_bytes(2 * per_sandbox);
    assert_eq!(limits.max_sandboxes(), 1024);
    assert_eq!(limits.max_retained_bytes(), 2 * per_sandbox);
    let service = CriRuntimeService::with_limits_and_recorder(limits, Arc::new(Collect::default()));

    run(&service, Some(pod.clone()), "").expect("first sandbox");
    run(&service, Some(pod.clone()), "").expect("second sandbox fills the budget exactly");
    assert_eq!(
        run(&service, Some(pod), ""),
        Err((
            Code::FailedPrecondition,
            "sandbox config storage is full".to_owned()
        ))
    );
}

/// REPAIR-4・ERR-3・TASK-57.1: 注入した記録先へ、成功・入力不正・件数超過のそれぞれが 1 回の呼び出しに
/// つき 1 件、操作名・結果・ステータスコードつきで渡る。サンプルは要求の中身を持たない。
#[test]
fn task_57_1_recorder_receives_every_outcome() {
    let collect = Arc::new(Collect::default());
    let service = CriRuntimeService::with_limits_and_recorder(
        SandboxLimits::new().with_max_sandboxes(1),
        collect.clone(),
    );
    let mut secret = config("pod-a");
    secret
        .annotations
        .insert("token".into(), "do-not-record".into());

    run(&service, Some(secret.clone()), "").expect("first sandbox");
    assert_eq!(run(&service, None, ""), invalid("config is required"));
    assert_eq!(
        run(&service, Some(secret), ""),
        Err((Code::FailedPrecondition, "too many sandboxes".to_owned()))
    );

    assert_eq!(
        collect.lines(),
        vec![
            ("cri.run_pod_sandbox", "success", "OK"),
            ("cri.run_pod_sandbox", "failure", "INVALID_ARGUMENT"),
            ("cri.run_pod_sandbox", "failure", "FAILED_PRECONDITION"),
        ]
    );
    let samples = collect.samples();
    assert_eq!(
        samples
            .iter()
            .map(|s| (s.kind(), s.outcome(), s.code()))
            .collect::<Vec<_>>(),
        vec![
            (CriOpKind::RunPodSandbox, CriOpOutcome::Success, Code::Ok),
            (
                CriOpKind::RunPodSandbox,
                CriOpOutcome::Failure,
                Code::InvalidArgument
            ),
            (
                CriOpKind::RunPodSandbox,
                CriOpOutcome::Failure,
                Code::FailedPrecondition
            ),
        ]
    );
    for sample in &samples {
        assert!(sample.latency() < std::time::Duration::from_secs(5));
        assert!(!format!("{sample:?}").contains("do-not-record"));
    }
    assert!(!format!("{service:?}").contains("do-not-record"));
}

/// TASK-57.1: 未実装の RPC（`UpdateContainerResources`）は `Unimplemented` のままで、記録先へ何も渡さない
/// （実装するときに計測の種別も追加する。REPAIR-3）。
#[test]
fn task_57_1_other_rpcs_remain_unimplemented() {
    let collect = Arc::new(Collect::default());
    let service = CriRuntimeService::with_recorder(collect.clone());
    let err = block_on(RuntimeService::update_container_resources(
        &service,
        Request::new(v1::UpdateContainerResourcesRequest::default()),
    ))
    .expect_err("not implemented yet");
    assert_eq!(err.code(), Code::Unimplemented);
    assert_eq!(err.message(), "update_container_resources");
    assert_eq!(collect.lines(), vec![]);
}
/// 公開トレイト経由で `StopPodSandbox` を呼ぶ。
fn stop(service: &CriRuntimeService, id: &str) -> Result<(), (Code, String)> {
    let request = Request::new(v1::StopPodSandboxRequest {
        pod_sandbox_id: id.into(),
    });
    block_on(RuntimeService::stop_pod_sandbox(service, request))
        .map(|_| ())
        .map_err(|status: Status| (status.code(), status.message().to_owned()))
}

/// 公開トレイト経由で `RemovePodSandbox` を呼ぶ。
fn remove(service: &CriRuntimeService, id: &str) -> Result<(), (Code, String)> {
    let request = Request::new(v1::RemovePodSandboxRequest {
        pod_sandbox_id: id.into(),
    });
    block_on(RuntimeService::remove_pod_sandbox(service, request))
        .map(|_| ())
        .map_err(|status: Status| (status.code(), status.message().to_owned()))
}

/// ERR-3・TASK-57.2: 存在しないサンドボックスの Stop は NOT_FOUND。
#[test]
fn task_57_2_stop_unknown_sandbox_returns_not_found() {
    let service = CriRuntimeService::new();
    assert_eq!(
        stop(&service, &"0".repeat(64)),
        Err((Code::NotFound, "sandbox not found".to_owned()))
    );
}

/// CRI-1・TASK-57.2: Remove で件数の枠が戻り、削除済みの ID は Stop が NOT_FOUND になる。
#[test]
fn task_57_2_remove_releases_capacity() {
    let service = CriRuntimeService::with_max_sandboxes(1);
    let id = run(&service, Some(config("pod-a")), "").expect("first sandbox");
    assert_eq!(
        run(&service, Some(config("pod-b")), ""),
        Err((Code::FailedPrecondition, "too many sandboxes".to_owned()))
    );
    remove(&service, &id).expect("remove");
    assert_eq!(
        stop(&service, &id),
        Err((Code::NotFound, "sandbox not found".to_owned()))
    );
    run(&service, Some(config("pod-b")), "").expect("slot is free after remove");
}

/// REPAIR-4・TASK-57.2: Stop・Remove の結果が操作名・結果・コードつきで記録先へ渡る。
#[test]
fn task_57_2_stop_remove_recorded_by_recorder() {
    let collect = Arc::new(Collect::default());
    let service = CriRuntimeService::with_recorder(collect.clone());
    let id = run(&service, Some(config("pod-a")), "").expect("sandbox");
    stop(&service, &id).expect("stop");
    stop(&service, &"0".repeat(64)).expect_err("unknown id");
    remove(&service, &id).expect("remove");
    remove(&service, &id).expect("idempotent remove");
    assert_eq!(
        collect.lines(),
        vec![
            ("cri.run_pod_sandbox", "success", "OK"),
            ("cri.stop_pod_sandbox", "success", "OK"),
            ("cri.stop_pod_sandbox", "failure", "NOT_FOUND"),
            ("cri.remove_pod_sandbox", "success", "OK"),
            ("cri.remove_pod_sandbox", "success", "OK"),
        ]
    );
}

/// 公開トレイト経由で `PodSandboxStatus` を呼ぶ。
fn status(service: &CriRuntimeService, id: &str) -> Result<v1::PodSandboxStatusResponse, Code> {
    let request = Request::new(v1::PodSandboxStatusRequest {
        pod_sandbox_id: id.into(),
        verbose: false,
    });
    block_on(RuntimeService::pod_sandbox_status(service, request))
        .map(|r| r.into_inner())
        .map_err(|s| s.code())
}

/// 公開トレイト経由で `ListPodSandbox` を呼び、(ID, state) の列を返す。
fn list_ids(service: &CriRuntimeService) -> Vec<(String, i32)> {
    let request = Request::new(v1::ListPodSandboxRequest { filter: None });
    block_on(RuntimeService::list_pod_sandbox(service, request))
        .expect("ListPodSandbox must succeed")
        .into_inner()
        .items
        .into_iter()
        .map(|i| (i.id, i.state))
        .collect()
}
/// CRI-1・TASK-57.3: Run -> List -> Stop -> Status -> Remove -> List/Status の一連が整合する。
#[test]
fn task_57_3_status_and_list_follow_lifecycle() {
    let service = CriRuntimeService::new();
    let id = run(&service, Some(config("p")), "").expect("run");
    assert_eq!(list_ids(&service), vec![(id.clone(), 0)]);

    let ready = status(&service, &id).expect("status");
    let st = ready.status.expect("status body");
    assert_eq!(st.id, id);
    assert_eq!(st.state, 0);
    assert_eq!(st.labels.get("k").map(String::as_str), Some("v"));
    assert_eq!(st.annotations.get("a").map(String::as_str), Some("b"));
    assert!(st.created_at > 0 && ready.timestamp > 0);

    stop(&service, &id).expect("stop");
    assert_eq!(
        status(&service, &id)
            .expect("status")
            .status
            .map(|s| s.state),
        Some(1)
    );
    assert_eq!(list_ids(&service), vec![(id.clone(), 1)]);

    remove(&service, &id).expect("remove");
    assert_eq!(list_ids(&service), vec![]);
    assert_eq!(status(&service, &id).unwrap_err(), Code::NotFound);
    assert_eq!(status(&service, "").unwrap_err(), Code::InvalidArgument);
}

/// CRI-1・TASK-57.3: 枠を 1 件に絞った構成でも、Remove 後に List が空になり再登録できる。
#[test]
fn task_57_3_list_is_consistent_with_limited_registry() {
    let service = CriRuntimeService::with_max_sandboxes(1);
    let id = run(&service, Some(config("p")), "").expect("run");
    assert!(run(&service, Some(config("q")), "").is_err());
    assert_eq!(list_ids(&service).len(), 1);
    remove(&service, &id).expect("remove");
    assert_eq!(list_ids(&service), vec![]);
    let again = run(&service, Some(config("q")), "").expect("run again");
    assert_eq!(list_ids(&service), vec![(again, 0)]);
}
