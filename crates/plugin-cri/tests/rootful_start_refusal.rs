//! plugin-cri の本番の start 経路（`SupervisedLifecycle::start` → starter → 共有クライアントの `privilege_gate`）で、
//! uid 0 を表す `/proc/self/status` 相当を与えたときの拒否が `PermissionDenied` と固定文言のまま `TraitError` へ届くことの
//! 結合試験（SEC-5・CRI-2・CRI-5・REPAIR-12・#4709・PR #4904）。この `TraitError` が gRPC / ttrpc の境界でコード 7 になることは
//! `crates/cri/tests/err3_backend_error_mapping.rs`・`shim_v2_create_start.rs` が照合する。Linux 限定（`supervised` と `start_client` が Linux のみ）・非 root。

#![cfg(target_os = "linux")]

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::Arc;

use fandhe_container_core::oci_runtime::{OciRuntimeError, ProcessSignaler};
use fandhe_container_core::traits::{
    ContainerId, CreateStateRequest, DeleteStateRequest, DeleteStateResponse, ErrorCode,
    GetStateRequest, ListStateRequest, StateList, StateRecord, StateStore, StdinMode, TraitError,
    UpdateStateRequest,
};
use fandhe_container_plugin_cri::supervised::{
    SignalerSource, SupervisedLifecycle, SupervisorStarter,
};
use fandhe_container_supervisor::control::UnavailableSignaler;
use fandhe_container_supervisor::start_client::{StartOptions, privilege_gate};

/// 本番の starter と同じ門（`privilege_gate`）へ、注入した status を渡すだけの starter。
struct GateStarter(&'static str);

impl SupervisorStarter for GateStarter {
    fn start(
        &self,
        _root: &Path,
        _opts: &StartOptions<'_>,
        _id: &ContainerId,
    ) -> (Result<NonZeroU32, OciRuntimeError>, Option<Child>) {
        match privilege_gate(Some(self.0)) {
            Ok(_) => panic!("rootless input must not reach this test"),
            Err(e) => (Err(e), None),
        }
    }
}

struct NoSignalers;

impl SignalerSource for NoSignalers {
    fn plain(&self, _s: &dyn StateStore) -> Arc<dyn ProcessSignaler> {
        Arc::new(UnavailableSignaler)
    }
    fn for_stop(&self, _s: &dyn StateStore) -> Arc<dyn ProcessSignaler> {
        Arc::new(UnavailableSignaler)
    }
}

/// `host_state_root` だけを持つ状態ストア（拒否は状態を読む前に返るため他は使われない）。
struct RootOnly(PathBuf);

fn unused() -> TraitError {
    TraitError::new(ErrorCode::Unimplemented, "unused")
}

impl StateStore for RootOnly {
    fn create(&self, _r: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        Err(unused())
    }
    fn get(&self, _r: &GetStateRequest) -> Result<StateRecord, TraitError> {
        Err(unused())
    }
    fn update(&self, _r: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        Err(unused())
    }
    fn delete(&self, _r: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        Err(unused())
    }
    fn list(&self, _r: &ListStateRequest) -> Result<StateList, TraitError> {
        Err(unused())
    }
    fn host_state_root(&self) -> Option<&Path> {
        Some(&self.0)
    }
}

fn status(uid: &str) -> &'static str {
    Box::leak(format!("Name:\tx\nUid:\t{uid}\nGid:\t1000\t1000\t1000\t1000\nGroups:\t\nNoNewPrivs:\t0\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n").into_boxed_str())
}

/// SEC-5: uid のどの位置が 0 でも `start` は `PermissionDenied` と固定文言で失敗し、供給側（plugin-cri）で別コードへ潰れない。
#[test]
fn sec5_supervised_start_rootful_is_permission_denied() {
    let store = RootOnly(PathBuf::from("/nonexistent/root"));
    let id = ContainerId::new("c1").expect("id");
    for uid in [
        "0\t0\t0\t0",
        "1000\t0\t1000\t1000",
        "1000\t1000\t0\t1000",
        "1000\t1000\t1000\t0",
    ] {
        let lifecycle =
            SupervisedLifecycle::new(Arc::new(GateStarter(status(uid))), Arc::new(NoSignalers));
        let err = lifecycle
            .start(&store, &id, None, StdinMode::Closed)
            .expect_err(uid);
        assert_eq!(err.code(), ErrorCode::PermissionDenied, "{uid}");
        assert_eq!(
            err.message(),
            "the rootful privilege model is permanently refused by policy (SEC-5)",
            "{uid}"
        );
    }
}
