//! `RuntimeAdapter`（TASK-59.1・CRI-2・CRI-7・ERR-3）の結合試験。フェイクの `ContainerRuntime` で検証する。

use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fandhe_container_core::traits::{
    ContainerId, ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest, DeleteResponse,
    ErrorCode, KillRequest, StartRequest, StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::{RuntimeAdapter, trait_error_to_status};
use fandhe_container_cri::runtime::v1::ContainerState as S;
use tonic::Code;

#[derive(Default)]
struct Fake {
    calls: Mutex<Vec<String>>,
    fail: Mutex<Option<ErrorCode>>,
    status: Mutex<Option<ContainerStatus>>,
    stop_signals: Mutex<Vec<u8>>,
}

impl Fake {
    fn rec(&self, s: String) -> Result<ContainerStatus, TraitError> {
        self.calls.lock().unwrap().push(s);
        if let Some(c) = *self.fail.lock().unwrap() {
            return Err(TraitError::new(c, "boom"));
        }
        Ok(self.status.lock().unwrap().clone().unwrap())
    }
}

struct Shared(Arc<Fake>);

impl ContainerRuntime for Shared {
    fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        self.0.rec(format!(
            "create {} {}",
            r.id().as_str(),
            r.bundle().display()
        ))
    }
    fn start(&self, r: &StartRequest) -> Result<ContainerStatus, TraitError> {
        self.0.rec(format!("start {}", r.id().as_str()))
    }
    fn kill(&self, r: &KillRequest) -> Result<ContainerStatus, TraitError> {
        self.0
            .rec(format!("kill {} {}", r.id().as_str(), r.signal().as_u8()))
    }
    fn stop(&self, r: &StopRequest) -> Result<ContainerStatus, TraitError> {
        self.0.stop_signals.lock().unwrap().push(r.signal().as_u8());
        self.0
            .rec(format!("stop {} {}", r.id().as_str(), r.grace().as_secs()))
    }
    fn delete(&self, r: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        self.0
            .rec(format!("delete {} {}", r.id().as_str(), r.force()))
            .map(|_| DeleteResponse::default())
    }
    fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
        self.0.rec(format!("state {}", r.id().as_str()))
    }
}

fn abs() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\bundles\b1")
    } else {
        PathBuf::from("/bundles/b1")
    }
}

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).unwrap()
}

fn fake_with(status: ContainerStatus) -> (Arc<Fake>, RuntimeAdapter) {
    let f = Arc::new(Fake::default());
    *f.status.lock().unwrap() = Some(status);
    let a = RuntimeAdapter::new(Arc::new(Shared(f.clone())));
    (f, a)
}

/// CRI-2: トレイトオブジェクト経由で create から remove までが期待どおりの要求で呼ばれる。
#[test]
fn lifecycle_via_trait_object() {
    let (f, a) = fake_with(ContainerStatus::running(cid("c1"), NonZeroU32::new(42)));
    a.create("c1", abs()).unwrap();
    a.start("c1").unwrap();
    let st = a.state("c1").unwrap();
    a.stop("c1", 10).unwrap();
    a.kill("c1", 9).unwrap();
    a.remove("c1", true).unwrap();
    assert_eq!(st.id, "c1");
    assert_eq!(st.state, S::ContainerRunning);
    assert_eq!(st.pid, Some(42));
    let calls = f.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            format!("create c1 {}", abs().display()),
            "start c1".to_string(),
            "state c1".to_string(),
            "stop c1 10".to_string(),
            "kill c1 9".to_string(),
            "delete c1 true".to_string(),
        ]
    );
}

/// CRI-7: ジェネリクス経由でも core の具象に依存せず呼べる。
#[test]
fn generic_construction() {
    let f = Arc::new(Fake::default());
    *f.status.lock().unwrap() = Some(ContainerStatus::created(cid("c2"), None));
    let a = RuntimeAdapter::from_runtime(Shared(f.clone()));
    let st = a.start("c2").unwrap();
    assert_eq!(st.state, S::ContainerCreated);
    assert_eq!(
        f.calls.lock().unwrap().clone(),
        vec!["start c2".to_string()]
    );
}

/// 状態写像: Stopped は EXITED で終了コードを保持する。
#[test]
fn state_mapping_stopped() {
    let (_f, a) = fake_with(ContainerStatus::stopped(cid("c3"), Some(137)));
    let st = a.state("c3").unwrap();
    assert_eq!(st.state, S::ContainerExited);
    assert_eq!(st.exit_code, Some(137));
    assert_eq!(st.pid, None);
}

/// ERR-3: 全エラーコードの gRPC ステータス写像。
#[test]
fn error_mapping() {
    let cases = [
        (ErrorCode::InvalidArgument, Code::InvalidArgument),
        (ErrorCode::NotFound, Code::NotFound),
        (ErrorCode::AlreadyExists, Code::AlreadyExists),
        (ErrorCode::FailedPrecondition, Code::FailedPrecondition),
        (ErrorCode::Unimplemented, Code::Unimplemented),
        (ErrorCode::Internal, Code::Internal),
        (ErrorCode::PermissionDenied, Code::PermissionDenied),
        (ErrorCode::Timeout, Code::DeadlineExceeded),
        (ErrorCode::Unavailable, Code::Unavailable),
    ];
    for (e, c) in cases {
        let s = trait_error_to_status(&TraitError::new(e, "boom"));
        assert_eq!(s.code(), c);
        assert_eq!(s.message(), "boom");
    }
    let (f, a) = fake_with(ContainerStatus::creating(cid("c")));
    *f.fail.lock().unwrap() = Some(ErrorCode::NotFound);
    assert_eq!(a.state("c").unwrap_err().code().grpc_code(), Code::NotFound);
}

/// 入力不正は実行層を呼ばずに INVALID_ARGUMENT になる。
#[test]
fn invalid_inputs_do_not_reach_runtime() {
    let (f, a) = fake_with(ContainerStatus::creating(cid("c")));
    let codes = [
        a.start("").unwrap_err().code(),
        a.start("../x").unwrap_err().code(),
        a.create("c", PathBuf::from("rel/bundle"))
            .unwrap_err()
            .code(),
        a.stop("c", 24 * 3600 + 1).unwrap_err().code(),
        a.kill("c", 0).unwrap_err().code(),
        a.kill("c", 65).unwrap_err().code(),
    ];
    assert!(codes.iter().all(|c| c.grpc_code() == Code::InvalidArgument));
    assert!(f.calls.lock().unwrap().is_empty());
}

/// 負の timeout は 0 秒へ丸める。
#[test]
fn negative_timeout_clamped() {
    let (f, a) = fake_with(ContainerStatus::stopped(cid("c"), None));
    a.stop("c", -5).unwrap();
    assert_eq!(
        f.calls.lock().unwrap().clone(),
        vec!["stop c 0".to_string()]
    );
}

/// CRI-7: アダプタは core の `traits` 以外（実行層の具象）を参照しない。
#[test]
fn adapter_depends_only_on_core_traits() {
    let src = include_str!("../src/adapter.rs");
    for line in src.lines().filter(|l| !l.trim_start().starts_with("//")) {
        let mut rest = line;
        while let Some(i) = rest.find("fandhe_container_core::") {
            let tail = &rest[i + "fandhe_container_core::".len()..];
            assert!(tail.starts_with("traits"), "non-traits core path: {line}");
            rest = tail;
        }
    }
}

/// CRI-2・PLUG-1（#2668）: `stop_with_signal` は指定の番号を `StopRequest::signal` で運び、`stop` は SIGTERM。
#[test]
fn cri2_stop_with_signal_carries_signal() {
    let (f, a) = fake_with(ContainerStatus::stopped(cid("c1"), None));
    a.stop_with_signal("c1", 10, 2).unwrap();
    a.stop("c1", 10).unwrap();
    assert_eq!(f.stop_signals.lock().unwrap().clone(), vec![2, 15]);
}

/// CRI-2（#2668）: 範囲外のシグナル番号は実行層を呼ばず `INVALID_ARGUMENT`。
#[test]
fn cri2_stop_with_signal_rejects_out_of_range() {
    let (f, a) = fake_with(ContainerStatus::stopped(cid("c1"), None));
    for sig in [0u8, 65] {
        assert_eq!(
            a.stop_with_signal("c1", 10, sig).unwrap_err().code(),
            fandhe_container_cri::error::CriErrorCode::InvalidArgument
        );
    }
    assert!(f.stop_signals.lock().unwrap().is_empty());
}
