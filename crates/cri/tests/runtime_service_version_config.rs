//! `RuntimeService.Version` と `UpdateRuntimeConfig` の応答の試験（CRI-1・CRI-2・REPAIR-4・#2896）。
//!
//! 公開の `RuntimeService` トレイトを plugin-cri と同じ立場で呼び、具体値で照合する
//! （値の出どころは `docs/design/cri-status-rpc.md`）。

use std::sync::{Arc, Mutex};

use fandhe_container_cri::instrument::{CriOpKind, CriOpRecorder, CriOpSample};
use fandhe_container_cri::runtime::v1::{self, runtime_service_server::RuntimeService};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use tonic::{Code, Request};

#[derive(Default)]
struct Collect(Mutex<Vec<CriOpSample>>);

impl CriOpRecorder for Collect {
    fn record_cri_op(&self, sample: &CriOpSample) {
        self.0.lock().unwrap().push(*sample);
    }
}

async fn version(service: &CriRuntimeService, v: &str) -> v1::VersionResponse {
    service
        .version(Request::new(v1::VersionRequest { version: v.into() }))
        .await
        .expect("version")
        .into_inner()
}

async fn update(service: &CriRuntimeService, cidr: &str) -> Result<(), tonic::Status> {
    service
        .update_runtime_config(Request::new(v1::UpdateRuntimeConfigRequest {
            runtime_config: Some(v1::RuntimeConfig {
                network_config: Some(v1::NetworkConfig {
                    pod_cidr: cidr.into(),
                }),
            }),
        }))
        .await
        .map(|_| ())
}

/// CRI-1: kubelet が要求する `version == "0.1.0"` と、containerd と揃えた各値。
#[tokio::test]
async fn cri_1_version_returns_kubelet_compatible_values() {
    let resp = version(&CriRuntimeService::new(), "0.1.0").await;
    assert_eq!(resp.version, "0.1.0");
    assert_eq!(resp.runtime_name, "fandhe-container");
    assert_eq!(resp.runtime_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(resp.runtime_api_version, "v1");
    let parts: Vec<&str> = resp.runtime_version.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert!(parts.iter().all(|p| p.parse::<u64>().is_ok()));
}

/// CRI-1: 要求の `version` はどんな値でも応答を変えず、応答へ現れない。
#[tokio::test]
async fn cri_1_version_ignores_request_version() {
    let service = CriRuntimeService::new();
    let base = version(&service, "").await;
    let long = "x".repeat(4096);
    for v in ["v1", "0.1.0", "secret-like", long.as_str()] {
        assert_eq!(version(&service, v).await, base);
    }
}

/// CRI-1・CRI-2: 未指定・空は `OK` で何も記録しない。
#[tokio::test]
async fn cri_2_update_runtime_config_empty_is_noop() {
    let service = CriRuntimeService::new();
    service
        .update_runtime_config(Request::new(v1::UpdateRuntimeConfigRequest {
            runtime_config: None,
        }))
        .await
        .expect("none");
    service
        .update_runtime_config(Request::new(v1::UpdateRuntimeConfigRequest {
            runtime_config: Some(v1::RuntimeConfig {
                network_config: None,
            }),
        }))
        .await
        .expect("no network");
    update(&service, "").await.expect("empty");
    assert_eq!(service.pod_cidrs(), None);
}

/// CRI-2: 有効値を記録し、空では変えない。デュアルスタックは 2 件。
#[tokio::test]
async fn cri_2_update_runtime_config_records_valid_values() {
    let service = CriRuntimeService::new();
    update(&service, "10.244.0.0/24").await.expect("v4");
    let got = service.pod_cidrs().expect("recorded");
    assert_eq!(got.as_slice().len(), 1);
    assert_eq!(got.as_slice()[0].addr().to_string(), "10.244.0.0");
    assert_eq!(got.as_slice()[0].prefix_len(), 24);
    update(&service, "").await.expect("empty keeps");
    assert_eq!(service.pod_cidrs().expect("kept"), got);
    update(&service, "10.244.0.0/24,fd00:10:244::/64")
        .await
        .expect("dual");
    let dual = service.pod_cidrs().expect("dual");
    assert_eq!(dual.as_slice().len(), 2);
    assert_eq!(dual.as_slice()[1].addr().to_string(), "fd00:10:244::");
    assert_eq!(dual.as_slice()[1].prefix_len(), 64);
}

/// CRI-2: 不正値は `INVALID_ARGUMENT`。記録は直前のまま、文言に入力を含めない。
#[tokio::test]
async fn cri_2_update_runtime_config_rejects_invalid_and_keeps_previous() {
    let service = CriRuntimeService::new();
    update(&service, "10.244.0.0/24").await.expect("v4");
    let before = service.pod_cidrs();
    let too_long = format!("secret-like{}", "1".repeat(200));
    for bad in [
        too_long.as_str(),
        "10.0.0.0/24,10.1.0.0/24",
        "10.0.0.0/24,fd00::/64,fd01::/64",
        "10.0.0.0/33",
        "secret-like",
    ] {
        let err = update(&service, bad).await.expect_err(bad);
        assert_eq!(err.code(), Code::InvalidArgument, "{bad}");
        assert!(!err.message().contains("secret"), "{bad}");
        assert_eq!(service.pod_cidrs(), before, "{bad}");
    }
}

/// REPAIR-4: 各 RPC が 1 件ずつ記録される（要求の内容は記録しない）。
#[tokio::test]
async fn repair_4_version_and_update_record_samples() {
    let recorder = Arc::new(Collect::default());
    let service = CriRuntimeService::with_recorder(recorder.clone());
    version(&service, "0.1.0").await;
    update(&service, "10.244.0.0/24").await.expect("ok");
    update(&service, "bad").await.expect_err("bad");
    let samples = recorder.0.lock().unwrap();
    let got: Vec<(CriOpKind, Code)> = samples.iter().map(|s| (s.kind(), s.code())).collect();
    assert_eq!(
        got,
        vec![
            (CriOpKind::Version, Code::Ok),
            (CriOpKind::UpdateRuntimeConfig, Code::Ok),
            (CriOpKind::UpdateRuntimeConfig, Code::InvalidArgument),
        ]
    );
}
