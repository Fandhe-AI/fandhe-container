//! containerd Task API の Create / Start を `ContainerRuntime` へつなぐサービス（CRI-5・TASK-62.2・MS-7）。
//!
//! [`ServiceRegistry::dispatch`](super::service::ServiceRegistry::dispatch) から呼ばれる同期ハンドラで、
//! 接続ごとのスレッド上で動く。コンテナの作成・起動は [`RuntimeAdapter`] 経由で行い、core の具象型には
//! 依存しない（CRI-7・PLUG-1）。ランタイム側の失敗は `crate::error` の表（ERR-3）で gRPC コードへ写し、
//! ttrpc の `Response.status` に載せる。
//!
//! 未対応の欄は黙って無視せず `UNIMPLEMENTED` で拒否する（fail-closed。REPAIR-3）:
//! `rootfs`・`options`・`terminal`・`stdin`/`stdout`/`stderr`・`checkpoint`/`parent_checkpoint`・`exec_id`。
//! `rootfs` と `options`（型に持たない）は repeated / 入れ子の確保を避けるため、復号前に走査して拒否する。
//!
//! 検査の順序: 復号前の走査（rootfs → options）→ 復号 → id → bundle → terminal → stdio → checkpoint。
//!
//! 期限（REPAIR-5）: `ContainerRuntime` の契約で実装側が期限を持つ。shim は追加の期限を設けず、
//! `timeout_nano` も使わない。socket の権限・peer UID の照合は #803（TASK-62.7）の範囲。

use std::path::{Component, Path, PathBuf};

use prost::Message;

use super::message::{RpcStatus, count_top_level_field};
use super::service::{TaskApiVersion, TtrpcService, unimplemented_status};
use super::task_api::{CreateTaskRequest, CreateTaskResponse, StartRequest, StartResponse};
use crate::adapter::RuntimeAdapter;
use crate::error::{CriError, CriErrorCode};

/// `bundle` の最大バイト数（PATH_MAX 相当）。
const BUNDLE_MAX_LEN: usize = 4096;
/// `CreateTaskRequest.rootfs` のフィールド番号。
const FIELD_ROOTFS: u64 = 3;
/// `CreateTaskRequest.options`（`Any`）のフィールド番号。型には持たない。
const FIELD_OPTIONS: u64 = 10;

/// Create / Start を処理する Task サービス。他のメソッドは `Unimplemented`。
pub struct TaskService {
    version: TaskApiVersion,
    adapter: RuntimeAdapter,
}

impl std::fmt::Debug for TaskService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskService")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl TaskService {
    /// 版とランタイムのアダプタから作る。
    pub fn new(version: TaskApiVersion, adapter: RuntimeAdapter) -> Self {
        Self { version, adapter }
    }

    fn create(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        reject_undecodable_fields(payload)?;
        let req = CreateTaskRequest::decode(payload).map_err(|_| decode_failure())?;
        let bundle = checked_bundle(&req.bundle)?;
        if req.terminal {
            return Err(unsupported("terminal is not supported"));
        }
        if !req.stdin.is_empty() || !req.stdout.is_empty() || !req.stderr.is_empty() {
            return Err(unsupported("stdio is not supported"));
        }
        if !req.checkpoint.is_empty() || !req.parent_checkpoint.is_empty() {
            return Err(unsupported("checkpoint is not supported"));
        }
        let status = self
            .adapter
            .create(&req.id, bundle)
            .map_err(|e| to_status(&e))?;
        Ok(CreateTaskResponse {
            pid: status.pid.unwrap_or(0),
        }
        .encode_to_vec())
    }

    fn start(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = StartRequest::decode(payload).map_err(|_| decode_failure())?;
        if !req.exec_id.is_empty() {
            return Err(unsupported("exec_id is not supported"));
        }
        let status = self.adapter.start(&req.id).map_err(|e| to_status(&e))?;
        Ok(StartResponse {
            pid: status.pid.unwrap_or(0),
        }
        .encode_to_vec())
    }
}

impl TtrpcService for TaskService {
    fn name(&self) -> &str {
        self.version.service_name()
    }

    fn handle(&self, method: &str, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        match method {
            "Create" => self.create(payload),
            "Start" => self.start(payload),
            _ => Err(unimplemented_status("method", method)),
        }
    }
}

/// `CriError` を ttrpc の status へ写す（ERR-3 の写像は `CriErrorCode::grpc_code` に一本化済み）。
fn to_status(err: &CriError) -> RpcStatus {
    RpcStatus::from_code(err.code(), err.message())
}

fn unsupported(msg: &str) -> RpcStatus {
    RpcStatus::from_code(CriErrorCode::Unimplemented, msg)
}

/// 固定の英語文だけを返す（payload の内容はエコーしない）。
fn decode_failure() -> RpcStatus {
    RpcStatus::from_code(CriErrorCode::InvalidArgument, "malformed request payload")
}

/// 復号前の走査で `rootfs`・`options` の存在を検出して拒否する（確保を避ける。不安全な設計への対策）。
fn reject_undecodable_fields(payload: &[u8]) -> Result<(), RpcStatus> {
    for (field, msg) in [
        (FIELD_ROOTFS, "rootfs mounts are not supported"),
        (FIELD_OPTIONS, "options are not supported"),
    ] {
        match count_top_level_field(payload, field, 0) {
            None => return Err(decode_failure()),
            Some(0) => {}
            Some(_) => return Err(unsupported(msg)),
        }
    }
    Ok(())
}

/// `bundle` の形式を検査する（空・NUL・`..`・長さ超過を拒否。絶対パスの確認は `CreateRequest::new`）。
fn checked_bundle(bundle: &str) -> Result<PathBuf, RpcStatus> {
    let invalid = |m: &str| RpcStatus::from_code(CriErrorCode::InvalidArgument, m);
    if bundle.is_empty() {
        return Err(invalid("bundle must not be empty"));
    }
    if bundle.len() > BUNDLE_MAX_LEN {
        return Err(invalid("bundle path is too long"));
    }
    if bundle.contains('\0') {
        return Err(invalid("bundle must not contain NUL"));
    }
    let path = Path::new(bundle);
    if path.components().any(|c| c == Component::ParentDir) {
        return Err(invalid("bundle must not contain '..'"));
    }
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::num::NonZeroU32;
    use std::sync::{Arc, Mutex};

    use fandhe_container_core::traits::{
        ContainerRuntime, ContainerState, ContainerStatus, CreateRequest, DeleteRequest,
        DeleteResponse, ErrorCode, KillRequest, StartRequest as RtStart, StateRequest, StopRequest,
        TraitError,
    };

    use super::super::task_api::Mount;
    use super::*;

    /// 呼び出しと状態を記録する偽のランタイム。
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<String>>,
        states: Mutex<HashMap<String, ContainerState>>,
        create_pid: Option<u32>,
        wrong_id: bool,
    }

    struct Shared(Arc<Fake>);

    impl ContainerRuntime for Shared {
        fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
            let id = r.id().as_str().to_owned();
            self.0
                .calls
                .lock()
                .unwrap()
                .push(format!("create {id} {}", r.bundle().display()));
            let mut st = self.0.states.lock().unwrap();
            if st.contains_key(&id) {
                return Err(TraitError::new(ErrorCode::AlreadyExists, "exists"));
            }
            st.insert(id.clone(), ContainerState::Created);
            let rid = if self.0.wrong_id {
                fandhe_container_core::traits::ContainerId::new("other").unwrap()
            } else {
                r.id().clone()
            };
            Ok(ContainerStatus::created(
                rid,
                self.0.create_pid.and_then(NonZeroU32::new),
            ))
        }
        fn start(&self, r: &RtStart) -> Result<ContainerStatus, TraitError> {
            let id = r.id().as_str().to_owned();
            self.0.calls.lock().unwrap().push(format!("start {id}"));
            let mut st = self.0.states.lock().unwrap();
            match st.get(&id) {
                None => Err(TraitError::new(ErrorCode::NotFound, "none")),
                Some(ContainerState::Created) => {
                    st.insert(id, ContainerState::Running);
                    Ok(ContainerStatus::running(
                        r.id().clone(),
                        NonZeroU32::new(4242),
                    ))
                }
                Some(_) => Err(TraitError::new(ErrorCode::FailedPrecondition, "state")),
            }
        }
        fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn stop(&self, _: &StopRequest) -> Result<ContainerStatus, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn delete(&self, _: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn state(&self, _: &StateRequest) -> Result<ContainerStatus, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
    }

    fn svc(version: TaskApiVersion, fake: Fake) -> (TaskService, Arc<Fake>) {
        let f = Arc::new(fake);
        let s = TaskService::new(version, RuntimeAdapter::from_runtime(Shared(f.clone())));
        (s, f)
    }

    fn create_req(id: &str, bundle: &str) -> Vec<u8> {
        CreateTaskRequest {
            id: id.into(),
            bundle: bundle.into(),
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn start_req(id: &str) -> Vec<u8> {
        StartRequest {
            id: id.into(),
            exec_id: String::new(),
        }
        .encode_to_vec()
    }

    fn err_code(r: Result<Vec<u8>, RpcStatus>) -> (i32, String) {
        let s = r.unwrap_err();
        (s.code, s.message)
    }

    const INVALID: i32 = 3;
    const NOT_FOUND: i32 = 5;
    const EXISTS: i32 = 6;
    const UNIMPL: i32 = 12;
    const PRECOND: i32 = 9;
    const INTERNAL: i32 = 13;

    /// CRI-5・CRI-7: V2 / V3 の両方で Create → Start が通り、pid と ID・bundle が具体値で一致する。
    #[test]
    fn cri5_create_start_both_versions() {
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let (s, f) = svc(
                v,
                Fake {
                    create_pid: Some(100),
                    ..Default::default()
                },
            );
            let out = s.handle("Create", &create_req("c1", "/run/b1")).unwrap();
            assert_eq!(CreateTaskResponse::decode(&out[..]).unwrap().pid, 100);
            let out = s.handle("Start", &start_req("c1")).unwrap();
            assert_eq!(StartResponse::decode(&out[..]).unwrap().pid, 4242);
            assert_eq!(
                *f.calls.lock().unwrap(),
                vec!["create c1 /run/b1".to_string(), "start c1".to_string()]
            );
        }
    }

    /// CRI-5: create 直後に PID が不明なら 0。
    #[test]
    fn cri5_create_pid_none_is_zero() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        let out = s.handle("Create", &create_req("c1", "/b")).unwrap();
        assert_eq!(CreateTaskResponse::decode(&out[..]).unwrap().pid, 0);
    }

    /// ERR-3: ランタイムの失敗は表のコードで返る。
    #[test]
    fn cri5_runtime_errors_map_to_err3() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        s.handle("Create", &create_req("c1", "/b")).unwrap();
        assert_eq!(
            err_code(s.handle("Create", &create_req("c1", "/b"))).0,
            EXISTS
        );
        assert_eq!(err_code(s.handle("Start", &start_req("nope"))).0, NOT_FOUND);
        s.handle("Start", &start_req("c1")).unwrap();
        assert_eq!(err_code(s.handle("Start", &start_req("c1"))).0, PRECOND);
    }

    /// 入力の検査: 不正 ID・bundle・壊れた payload は INVALID_ARGUMENT で、ランタイムは呼ばれない。
    #[test]
    fn cri5_invalid_inputs() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        for (id, b) in [
            ("", "/b"),
            ("bad id!", "/b"),
            ("c1", ""),
            ("c1", "relative/path"),
            ("c1", "/a/../b"),
            ("c1", "/a\0b"),
        ] {
            assert_eq!(
                err_code(s.handle("Create", &create_req(id, b))).0,
                INVALID,
                "{id:?} {b:?}"
            );
        }
        let long = format!("/{}", "a".repeat(BUNDLE_MAX_LEN));
        assert_eq!(
            err_code(s.handle("Create", &create_req("c1", &long))).0,
            INVALID
        );
        let (code, msg) = err_code(s.handle("Create", &[0x0a, 5, 1]));
        assert_eq!((code, msg.as_str()), (INVALID, "malformed request payload"));
        assert_eq!(err_code(s.handle("Start", &[0x0a, 5, 1])).0, INVALID);
        assert!(f.calls.lock().unwrap().is_empty());
    }

    /// 未対応の欄は UNIMPLEMENTED で、ランタイムは呼ばれない。
    #[test]
    fn cri5_unsupported_fields_rejected() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        let base = || CreateTaskRequest {
            id: "c1".into(),
            bundle: "/b".into(),
            ..Default::default()
        };
        let mut cases: Vec<(CreateTaskRequest, &str)> = Vec::new();
        let mut r = base();
        r.rootfs = vec![Mount::default()];
        cases.push((r, "rootfs mounts are not supported"));
        let mut r = base();
        r.terminal = true;
        cases.push((r, "terminal is not supported"));
        for which in 0..3 {
            let mut r = base();
            match which {
                0 => r.stdin = "/f".into(),
                1 => r.stdout = "/f".into(),
                _ => r.stderr = "/f".into(),
            }
            cases.push((r, "stdio is not supported"));
        }
        let mut r = base();
        r.checkpoint = "c".into();
        cases.push((r, "checkpoint is not supported"));
        let mut r = base();
        r.parent_checkpoint = "c".into();
        cases.push((r, "checkpoint is not supported"));
        for (r, m) in cases {
            let (code, msg) = err_code(s.handle("Create", &r.encode_to_vec()));
            assert_eq!((code, msg.as_str()), (UNIMPL, m));
        }
        // options（番号 10）は型に持たないので手で組む。
        let mut raw = create_req("c1", "/b");
        raw.extend_from_slice(&[0x52, 0x00]);
        let (code, msg) = err_code(s.handle("Create", &raw));
        assert_eq!((code, msg.as_str()), (UNIMPL, "options are not supported"));
        let exec = StartRequest {
            id: "c1".into(),
            exec_id: "e".into(),
        }
        .encode_to_vec();
        assert_eq!(err_code(s.handle("Start", &exec)).0, UNIMPL);
        assert!(f.calls.lock().unwrap().is_empty());
    }

    /// 復号前の走査: 10 万件の空 rootfs でも確保せず UNIMPLEMENTED。切れた入力は INVALID_ARGUMENT。
    #[test]
    fn cri5_rootfs_flood_rejected_before_decode() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        let flood = [0x1a, 0x00].repeat(100_000);
        assert_eq!(err_code(s.handle("Create", &flood)).0, UNIMPL);
        assert_eq!(err_code(s.handle("Create", &[0x1a])).0, INVALID);
    }

    /// 応答の ID が要求と違えば INTERNAL。
    #[test]
    fn cri5_mismatched_response_id_is_internal() {
        let (s, _) = svc(
            TaskApiVersion::V2,
            Fake {
                wrong_id: true,
                ..Default::default()
            },
        );
        assert_eq!(
            err_code(s.handle("Create", &create_req("c1", "/b"))).0,
            INTERNAL
        );
    }

    /// 他のメソッドは Unimplemented。サービス名は版に従う。
    #[test]
    fn cri5_other_methods_unimplemented() {
        let (s, _) = svc(TaskApiVersion::V3, Fake::default());
        assert_eq!(s.name(), "containerd.task.v3.Task");
        let (code, msg) = err_code(s.handle("Delete", &[]));
        assert_eq!((code, msg.as_str()), (UNIMPL, "method Delete"));
    }
}
