//! containerd Task API の Create / Start / Delete / Exec を `ContainerRuntime` へつなぐサービス（CRI-5・ERR-3・TASK-62.2・TASK-62.3.1・TASK-62.4・MS-7）。
//!
//! [`ServiceRegistry::dispatch`](super::service::ServiceRegistry::dispatch) から呼ばれる同期ハンドラで、
//! 接続ごとのスレッド上で動く。コンテナの作成・起動は [`RuntimeAdapter`] 経由で行い、core の具象型には
//! 依存しない（CRI-7・PLUG-1）。ランタイム側の失敗は `crate::error` の表（ERR-3）で gRPC コードへ写し、
//! ttrpc の `Response.status` に載せる。
//!
//! 未対応の欄は黙って無視せず `UNIMPLEMENTED` で拒否する（fail-closed。REPAIR-3）:
//! `rootfs`・`options`・`terminal`・`stdin`/`stdout`/`stderr`・`checkpoint`/`parent_checkpoint`・`exec_id`（Delete）。
//! `Exec` と `Start(exec_id)` は [`TaskExecLauncher`] が差し込まれたときだけ動き、無ければ `UNIMPLEMENTED`（TASK-62.4）。
//! `rootfs` と `options`（型に持たない）は repeated / 入れ子の確保を避けるため、復号前に走査して拒否する。
//!
//! 検査の順序（Create）: 復号前の走査（rootfs → options）→ 復号 → id → bundle → terminal → stdio → checkpoint。
//! 検査の順序（Exec）: 起動役の有無 → 復号 → id → exec_id → terminal / stdio → spec（type URL・上限・JSON・各欄）
//! → コンテナが Running か → 登録（重複・上限）。起動は `Start(exec_id)` が行う（containerd の意味論）。
//!
//! Delete の検査の順序: 復号（repeated / `Any` の欄が無いので走査は不要）→ exec_id → id（アダプタ）。
//! 手順は state（削除前の pid・終了コードを採る）→ `remove(force=false)`。containerd の Delete に force は
//! 無く、実行中のコンテナは core の `FailedPrecondition`（9）で拒否される。応答の `exit_status` は
//! 終了コード（不明は 255）、`exited_at` は core が終了時刻を持たないため常に未設定（REPAIR-3。Wait は #871）。
//! 既知の制約: state と remove の間に状態が変わりうる（その場合の `exit_status` は不正確）。pid のある
//! `Created` は core の契約で force=false では削除できない。plugin 越しでは最悪 2 回分の待ちになる。
//!
//! 期限（REPAIR-5）: `ContainerRuntime` の契約で実装側が期限を持つ。shim は追加の期限を設けず、
//! `timeout_nano` も使わない。socket の権限・peer UID の照合は #803（TASK-62.7）の範囲。

use std::num::NonZeroU32;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use prost::Message;

use super::exec::{ExecId, ExecRegistry, TaskExecLauncher, parse_process_spec};
use super::message::{RpcStatus, count_top_level_field};
use super::service::{TaskApiVersion, TtrpcService, unimplemented_status};
use super::task_api::{
    CreateTaskRequest, CreateTaskResponse, DeleteRequest, DeleteResponse, ExecProcessRequest,
    StartRequest, StartResponse,
};
use crate::adapter::{RuntimeAdapter, RuntimeContainerStatus, RuntimeLifecycle};
use crate::error::{CriError, CriErrorCode};
use fandhe_container_core::traits::ContainerId;

/// `bundle` の最大バイト数（PATH_MAX 相当）。
const BUNDLE_MAX_LEN: usize = 4096;
/// `CreateTaskRequest.rootfs` のフィールド番号。
const FIELD_ROOTFS: u64 = 3;
/// `CreateTaskRequest.options`（`Any`）のフィールド番号。型には持たない。
const FIELD_OPTIONS: u64 = 10;

/// 終了コードが不明なときの `exit_status`。containerd クライアントの `UnknownExitStatus` に倣う。
const UNKNOWN_EXIT_STATUS: u32 = 255;

/// Create / Start / Delete / Exec を処理する Task サービス。他のメソッドは `Unimplemented`。
pub struct TaskService {
    version: TaskApiVersion,
    adapter: RuntimeAdapter,
    exec_launcher: Option<Arc<dyn TaskExecLauncher>>,
    execs: ExecRegistry,
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
        Self {
            version,
            adapter,
            exec_launcher: None,
            execs: ExecRegistry::new(),
        }
    }

    /// exec プロセスの起動役を差し込む。無ければ `Exec` と `Start(exec_id)` は `UNIMPLEMENTED`（TASK-62.4）。
    pub fn with_exec_launcher(mut self, launcher: Arc<dyn TaskExecLauncher>) -> Self {
        self.exec_launcher = Some(launcher);
        self
    }

    /// `Exec`: exec プロセスを登録するだけで起動はしない（起動は `Start(exec_id)`）。
    fn exec(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        if self.exec_launcher.is_none() {
            return Err(unsupported("exec is not supported"));
        }
        let req = ExecProcessRequest::decode(payload).map_err(|_| decode_failure())?;
        let container = ContainerId::new(&req.id).map_err(|e| to_status(&CriError::from(&e)))?;
        let exec_id = ExecId::new(&req.exec_id).map_err(|e| to_status(&e))?;
        if req.terminal {
            return Err(unsupported("terminal is not supported"));
        }
        if !req.stdin.is_empty() || !req.stdout.is_empty() || !req.stderr.is_empty() {
            return Err(unsupported("stdio is not supported"));
        }
        let any = req.spec.as_ref().ok_or_else(|| {
            RpcStatus::from_code(CriErrorCode::InvalidArgument, "exec spec is required")
        })?;
        let spec = parse_process_spec(any).map_err(|e| to_status(&e))?;
        let status = self
            .adapter
            .state(container.as_str())
            .map_err(|e| to_status(&e))?;
        if status.lifecycle != RuntimeLifecycle::Running {
            return Err(to_status(&CriError::failed_precondition(
                "container is not running",
            )));
        }
        self.execs
            .register(&container, &exec_id, spec)
            .map_err(|e| to_status(&e))?;
        Ok(Vec::new())
    }

    /// `Start(exec_id)`: 登録済みの exec を起動役で起動する。ロックは起動中に保持しない。
    fn start_exec(&self, req: &StartRequest) -> Result<Vec<u8>, RpcStatus> {
        let Some(launcher) = self.exec_launcher.as_ref() else {
            return Err(unsupported("exec_id is not supported"));
        };
        let container = ContainerId::new(&req.id).map_err(|e| to_status(&CriError::from(&e)))?;
        let exec_id = ExecId::new(&req.exec_id).map_err(|e| to_status(&e))?;
        // Exec 後に停止したコンテナへ起動役を呼ばないよう、起動の直前にも Running を再確認する。
        let status = self
            .adapter
            .state(container.as_str())
            .map_err(|e| to_status(&e))?;
        if status.lifecycle != RuntimeLifecycle::Running {
            return Err(to_status(&CriError::failed_precondition(
                "container is not running",
            )));
        }
        let spec = self
            .execs
            .begin_start(&container, &exec_id)
            .map_err(|e| to_status(&e))?;
        let result = launcher.launch(&container, &exec_id, &spec);
        self.execs
            .finish_start(&container, &exec_id, result.is_ok())
            .map_err(|e| to_status(&e))?;
        let pid = result.map_err(|e| to_status(&e))?;
        Ok(StartResponse {
            pid: pid.map_or(0, NonZeroU32::get),
        }
        .encode_to_vec())
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
            return self.start_exec(&req);
        }
        let status = self.adapter.start(&req.id).map_err(|e| to_status(&e))?;
        Ok(StartResponse {
            pid: status.pid.unwrap_or(0),
        }
        .encode_to_vec())
    }

    fn delete(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = DeleteRequest::decode(payload).map_err(|_| decode_failure())?;
        if !req.exec_id.is_empty() {
            return Err(unsupported("exec_id is not supported"));
        }
        // 状態を採れなければ削除しない（fail-closed。NotFound はそのまま 5）。
        let before = self.adapter.state(&req.id).map_err(|e| to_status(&e))?;
        self.adapter
            .remove(&req.id, false)
            .map_err(|e| to_status(&e))?;
        Ok(DeleteResponse {
            pid: before.pid.unwrap_or(0),
            exit_status: exit_status_of(&before),
            exited_at: None,
        }
        .encode_to_vec())
    }
}

/// 削除前の状態から `exit_status` を決める。未起動の Created は 0、終了コード不明・負値は 255。
fn exit_status_of(status: &RuntimeContainerStatus) -> u32 {
    match (status.lifecycle, status.exit_code) {
        (RuntimeLifecycle::Stopped, Some(c)) => u32::try_from(c).unwrap_or(UNKNOWN_EXIT_STATUS),
        (RuntimeLifecycle::Created, _) if status.pid.is_none() => 0,
        _ => UNKNOWN_EXIT_STATUS,
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
            "Delete" => self.delete(payload),
            "Exec" => self.exec(payload),
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
        ContainerId as RtId, ContainerRuntime, ContainerState, ContainerStatus, CreateRequest,
        DeleteRequest as RtDelete, DeleteResponse as RtDeleteResponse, ErrorCode, KillRequest,
        StartRequest as RtStart, StateRequest, StopRequest, TraitError,
    };

    use super::super::exec::{ExecProcessSpec, PROCESS_TYPE_URL};
    use super::super::task_api::{Any, Mount};
    use super::*;

    /// 呼び出しと状態を記録する偽のランタイム。
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<String>>,
        states: Mutex<HashMap<String, ContainerState>>,
        create_pid: Option<u32>,
        wrong_id: bool,
        /// state が返す状態の上書き（終了コード等を差し込む）。
        preset: Mutex<HashMap<String, ContainerStatus>>,
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
        fn delete(&self, r: &RtDelete) -> Result<RtDeleteResponse, TraitError> {
            let id = r.id().as_str().to_owned();
            self.0
                .calls
                .lock()
                .unwrap()
                .push(format!("delete {id} force={}", r.force()));
            let mut st = self.0.states.lock().unwrap();
            match st.get(&id) {
                None => Err(TraitError::new(ErrorCode::NotFound, "none")),
                Some(ContainerState::Running) => {
                    Err(TraitError::new(ErrorCode::FailedPrecondition, "running"))
                }
                Some(_) => {
                    st.remove(&id);
                    Ok(RtDeleteResponse::new())
                }
            }
        }
        fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
            let id = r.id().as_str().to_owned();
            self.0.calls.lock().unwrap().push(format!("state {id}"));
            if let Some(p) = self.0.preset.lock().unwrap().get(&id) {
                return Ok(p.clone());
            }
            match self.0.states.lock().unwrap().get(&id) {
                None => Err(TraitError::new(ErrorCode::NotFound, "none")),
                Some(ContainerState::Running) => Ok(ContainerStatus::running(
                    r.id().clone(),
                    NonZeroU32::new(4242),
                )),
                Some(_) => Ok(ContainerStatus::created(r.id().clone(), None)),
            }
        }
    }

    /// 引数を記録する偽の起動役。
    #[derive(Default)]
    struct FakeLauncher {
        launched: Mutex<Vec<(String, String, ExecProcessSpec)>>,
        fail: Mutex<bool>,
    }

    impl TaskExecLauncher for FakeLauncher {
        fn launch(
            &self,
            c: &ContainerId,
            e: &ExecId,
            s: &ExecProcessSpec,
        ) -> Result<Option<NonZeroU32>, CriError> {
            if *self.fail.lock().unwrap() {
                return Err(CriError::unavailable("launch failed"));
            }
            self.launched
                .lock()
                .unwrap()
                .push((c.as_str().into(), e.as_str().into(), s.clone()));
            Ok(NonZeroU32::new(5151))
        }
    }

    fn svc_exec(version: TaskApiVersion) -> (TaskService, Arc<Fake>, Arc<FakeLauncher>) {
        let (s, f) = svc(version, Fake::default());
        let l = Arc::new(FakeLauncher::default());
        (s.with_exec_launcher(l.clone()), f, l)
    }

    const SPEC: &str = r#"{"cwd":"/","args":["/bin/sh","-c","id"],"env":["A=b"],"user":{"uid":1000,"gid":1001,"additionalGids":[2000,3000]}}"#;

    fn exec_req(id: &str, eid: &str, json: &str) -> Vec<u8> {
        ExecProcessRequest {
            id: id.into(),
            exec_id: eid.into(),
            spec: Some(Any {
                type_url: PROCESS_TYPE_URL.into(),
                value: json.as_bytes().to_vec(),
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn start_exec_req(id: &str, eid: &str) -> Vec<u8> {
        StartRequest {
            id: id.into(),
            exec_id: eid.into(),
        }
        .encode_to_vec()
    }

    fn running_container(s: &TaskService, id: &str) {
        s.handle("Create", &create_req(id, "/b")).unwrap();
        s.handle("Start", &start_req(id)).unwrap();
    }

    /// CRI-5: V2 / V3 の両方で Create → Start → Exec → Start(exec_id) が通り、起動役へ具体値が渡る。
    #[test]
    fn cri5_exec_then_start_launches_process() {
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let (s, _, l) = svc_exec(v);
            running_container(&s, "c1");
            let out = s.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap();
            assert!(out.is_empty());
            assert!(l.launched.lock().unwrap().is_empty());
            let out = s.handle("Start", &start_exec_req("c1", "e1")).unwrap();
            assert_eq!(StartResponse::decode(&out[..]).unwrap().pid, 5151);
            let launched = l.launched.lock().unwrap();
            assert_eq!(launched.len(), 1);
            let (c, e, spec) = &launched[0];
            assert_eq!((c.as_str(), e.as_str()), ("c1", "e1"));
            assert_eq!(spec.args(), ["/bin/sh", "-c", "id"]);
            assert_eq!(spec.env(), ["A=b"]);
            assert_eq!(spec.cwd(), "/");
            let u = spec.user().unwrap();
            assert_eq!((u.uid, u.gid), (1000, 1001));
            assert_eq!(u.additional_gids, vec![2000, 3000]);
        }
    }

    /// CRI-5: 起動役が無ければ Exec も Start(exec_id) も UNIMPLEMENTED。
    #[test]
    fn cri5_exec_without_launcher_unimplemented() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        running_container(&s, "c1");
        let (code, msg) = err_code(s.handle("Exec", &exec_req("c1", "e1", SPEC)));
        assert_eq!((code, msg.as_str()), (UNIMPL, "exec is not supported"));
        let (code, msg) = err_code(s.handle("Start", &start_exec_req("c1", "e1")));
        assert_eq!((code, msg.as_str()), (UNIMPL, "exec_id is not supported"));
    }

    /// CRI-5: 不正な入力は INVALID_ARGUMENT で、起動役は呼ばれず登録もされない。
    #[test]
    fn cri5_exec_invalid_inputs() {
        let (s, f, l) = svc_exec(TaskApiVersion::V2);
        running_container(&s, "c1");
        let before = f.calls.lock().unwrap().len();
        let long = "a".repeat(256);
        for (id, eid) in [
            ("", "e"),
            ("..", "e"),
            ("bad id!", "e"),
            ("c1", ""),
            ("c1", ".."),
            ("c1", "bad id!"),
            ("c1", long.as_str()),
        ] {
            assert_eq!(
                err_code(s.handle("Exec", &exec_req(id, eid, SPEC))).0,
                INVALID,
                "{id:?} {eid:?}"
            );
        }
        for j in [
            "",
            "not json",
            r#"{"cwd":"/"}"#,
            r#"{"cwd":"/","args":[""]}"#,
            r#"{"cwd":"rel","args":["a"]}"#,
            r#"{"cwd":"/","args":["a"],"env":["NOEQ"]}"#,
            r#"{"cwd":"/","args":["a"],"bogus":1}"#,
        ] {
            assert_eq!(
                err_code(s.handle("Exec", &exec_req("c1", "e1", j))).0,
                INVALID,
                "{j}"
            );
        }
        let no_spec = ExecProcessRequest {
            id: "c1".into(),
            exec_id: "e1".into(),
            ..Default::default()
        }
        .encode_to_vec();
        assert_eq!(err_code(s.handle("Exec", &no_spec)).0, INVALID);
        let bad_url = ExecProcessRequest {
            id: "c1".into(),
            exec_id: "e1".into(),
            spec: Some(Any {
                type_url: "x".into(),
                value: SPEC.as_bytes().to_vec(),
            }),
            ..Default::default()
        }
        .encode_to_vec();
        assert_eq!(err_code(s.handle("Exec", &bad_url)).0, INVALID);
        assert_eq!(err_code(s.handle("Exec", &[0x0a, 5, 1])).0, INVALID);
        assert_eq!(f.calls.lock().unwrap().len(), before);
        assert!(l.launched.lock().unwrap().is_empty());
        assert_eq!(
            err_code(s.handle("Start", &start_exec_req("c1", "e1"))).0,
            NOT_FOUND
        );
    }

    /// CRI-5・SEC-1: 未対応の欄は UNIMPLEMENTED で、ランタイムは呼ばれない。
    #[test]
    fn cri5_exec_unsupported_fields() {
        let (s, f, _) = svc_exec(TaskApiVersion::V2);
        running_container(&s, "c1");
        let before = f.calls.lock().unwrap().len();
        let base = || ExecProcessRequest {
            id: "c1".into(),
            exec_id: "e1".into(),
            spec: Some(Any {
                type_url: PROCESS_TYPE_URL.into(),
                value: SPEC.as_bytes().to_vec(),
            }),
            ..Default::default()
        };
        let mut r = base();
        r.terminal = true;
        let (code, msg) = err_code(s.handle("Exec", &r.encode_to_vec()));
        assert_eq!((code, msg.as_str()), (UNIMPL, "terminal is not supported"));
        for which in 0..3 {
            let mut r = base();
            match which {
                0 => r.stdin = "/f".into(),
                1 => r.stdout = "/f".into(),
                _ => r.stderr = "/f".into(),
            }
            let (code, msg) = err_code(s.handle("Exec", &r.encode_to_vec()));
            assert_eq!((code, msg.as_str()), (UNIMPL, "stdio is not supported"));
        }
        let caps = r#"{"cwd":"/","args":["a"],"capabilities":{"bounding":["CAP_SYS_ADMIN"]}}"#;
        let (code, msg) = err_code(s.handle("Exec", &exec_req("c1", "e1", caps)));
        assert_eq!(
            (code, msg.as_str()),
            (UNIMPL, "capabilities is not supported")
        );
        assert_eq!(f.calls.lock().unwrap().len(), before);
    }

    /// ERR-3・CRI-5: 状態に関する失敗と再試行。
    #[test]
    fn cri5_exec_lifecycle_errors() {
        let (s, _, l) = svc_exec(TaskApiVersion::V2);
        assert_eq!(
            err_code(s.handle("Exec", &exec_req("nope", "e1", SPEC))).0,
            NOT_FOUND
        );
        s.handle("Create", &create_req("c1", "/b")).unwrap();
        assert_eq!(
            err_code(s.handle("Exec", &exec_req("c1", "e1", SPEC))).0,
            PRECOND
        );
        s.handle("Start", &start_req("c1")).unwrap();
        s.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap();
        assert_eq!(
            err_code(s.handle("Exec", &exec_req("c1", "e1", SPEC))).0,
            EXISTS
        );
        // launch の失敗は ERR-3 のコードで返り、再試行できる。
        *l.fail.lock().unwrap() = true;
        assert_eq!(
            err_code(s.handle("Start", &start_exec_req("c1", "e1"))).0,
            UNAVAILABLE
        );
        *l.fail.lock().unwrap() = false;
        s.handle("Start", &start_exec_req("c1", "e1")).unwrap();
        assert_eq!(
            err_code(s.handle("Start", &start_exec_req("c1", "e1"))).0,
            PRECOND
        );
        assert_eq!(
            err_code(s.handle("Start", &start_exec_req("c1", "zz"))).0,
            NOT_FOUND
        );
        assert_eq!(l.launched.lock().unwrap().len(), 1);
    }

    /// CRI-5: 1 コンテナあたりの登録上限は RESOURCE_EXHAUSTED。
    #[test]
    fn cri5_exec_registry_limit() {
        let (s, _, _) = svc_exec(TaskApiVersion::V2);
        running_container(&s, "c1");
        for i in 0..super::super::exec::MAX_EXECS_PER_CONTAINER {
            s.handle("Exec", &exec_req("c1", &format!("e{i}"), SPEC))
                .unwrap();
        }
        assert_eq!(
            err_code(s.handle("Exec", &exec_req("c1", "over", SPEC))).0,
            RESOURCE_EXHAUSTED
        );
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

    fn delete_req(id: &str, exec_id: &str) -> Vec<u8> {
        DeleteRequest {
            id: id.into(),
            exec_id: exec_id.into(),
        }
        .encode_to_vec()
    }

    fn stopped(f: &Fake, id: &str, code: Option<i32>) {
        f.preset.lock().unwrap().insert(
            id.into(),
            ContainerStatus::stopped(RtId::new(id).unwrap(), code),
        );
        f.states
            .lock()
            .unwrap()
            .insert(id.into(), ContainerState::Stopped);
    }

    fn err_code(r: Result<Vec<u8>, RpcStatus>) -> (i32, String) {
        let s = r.unwrap_err();
        (s.code, s.message)
    }

    /// 試験用の絶対パス。`Path::is_absolute` は Windows では `/b` を偽とするため、
    /// Windows では `C:` を前置して区切りを `\` にし、3 OS で絶対パスにする（CRI-5）。
    fn abs(unix_style: &str) -> String {
        if cfg!(windows) {
            format!("C:{}", unix_style.replace('/', "\\"))
        } else {
            unix_style.to_string()
        }
    }

    const INVALID: i32 = 3;
    const NOT_FOUND: i32 = 5;
    const EXISTS: i32 = 6;
    const UNIMPL: i32 = 12;
    const PRECOND: i32 = 9;
    const INTERNAL: i32 = 13;
    const RESOURCE_EXHAUSTED: i32 = 8;
    const UNAVAILABLE: i32 = 14;

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
            let out = s
                .handle("Create", &create_req("c1", &abs("/run/b1")))
                .unwrap();
            assert_eq!(CreateTaskResponse::decode(&out[..]).unwrap().pid, 100);
            let out = s.handle("Start", &start_req("c1")).unwrap();
            assert_eq!(StartResponse::decode(&out[..]).unwrap().pid, 4242);
            assert_eq!(
                *f.calls.lock().unwrap(),
                vec![
                    format!("create c1 {}", abs("/run/b1")),
                    "start c1".to_string()
                ]
            );
        }
    }

    /// CRI-5: create 直後に PID が不明なら 0。
    #[test]
    fn cri5_create_pid_none_is_zero() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        let out = s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        assert_eq!(CreateTaskResponse::decode(&out[..]).unwrap().pid, 0);
    }

    /// ERR-3: ランタイムの失敗は表のコードで返る。
    #[test]
    fn cri5_runtime_errors_map_to_err3() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        assert_eq!(
            err_code(s.handle("Create", &create_req("c1", &abs("/b")))).0,
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
        let (b, dotdot, nul) = (abs("/b"), abs("/a/../b"), abs("/a\0b"));
        for (id, b) in [
            ("", b.as_str()),
            ("bad id!", b.as_str()),
            ("c1", ""),
            ("c1", "relative/path"),
            ("c1", dotdot.as_str()),
            ("c1", nul.as_str()),
        ] {
            assert_eq!(
                err_code(s.handle("Create", &create_req(id, b))).0,
                INVALID,
                "{id:?} {b:?}"
            );
        }
        let long = abs(&format!("/{}", "a".repeat(BUNDLE_MAX_LEN)));
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
            bundle: abs("/b"),
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
        let mut raw = create_req("c1", &abs("/b"));
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
            err_code(s.handle("Create", &create_req("c1", &abs("/b")))).0,
            INTERNAL
        );
    }

    /// 他のメソッドは Unimplemented。サービス名は版に従う。
    #[test]
    fn cri5_other_methods_unimplemented() {
        let (s, _) = svc(TaskApiVersion::V3, Fake::default());
        assert_eq!(s.name(), "containerd.task.v3.Task");
        let (code, msg) = err_code(s.handle("Wait", &[]));
        assert_eq!((code, msg.as_str()), (UNIMPL, "method Wait"));
    }

    /// CRI-5: V2 / V3 で Delete が通り、pid・exit_status が具体値で返る。再度の Delete は NOT_FOUND。
    #[test]
    fn cri5_delete_both_versions() {
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let (s, f) = svc(v, Fake::default());
            s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
            stopped(&f, "c1", Some(137));
            let out = s.handle("Delete", &delete_req("c1", "")).unwrap();
            let r = DeleteResponse::decode(&out[..]).unwrap();
            assert_eq!((r.pid, r.exit_status, r.exited_at), (0, 137, None));
            let calls = f.calls.lock().unwrap().clone();
            assert_eq!(
                calls[calls.len() - 2..],
                ["state c1".to_string(), "delete c1 force=false".to_string()]
            );
            assert_eq!(
                err_code(s.handle("Delete", &delete_req("c1", ""))).0,
                NOT_FOUND
            );
        }
    }

    /// CRI-5: 一度も起動していない Created の Delete は exit_status 0。
    #[test]
    fn cri5_delete_created_never_started() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        let out = s.handle("Delete", &delete_req("c1", "")).unwrap();
        let r = DeleteResponse::decode(&out[..]).unwrap();
        assert_eq!((r.pid, r.exit_status), (0, 0));
    }

    /// ERR-3: 存在しない ID は NOT_FOUND で、delete は呼ばれない。
    #[test]
    fn cri5_delete_not_found_err3() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        assert_eq!(
            err_code(s.handle("Delete", &delete_req("nope", ""))).0,
            NOT_FOUND
        );
        assert_eq!(*f.calls.lock().unwrap(), vec!["state nope".to_string()]);
    }

    /// 実行中は FAILED_PRECONDITION で、コンテナは残る。
    #[test]
    fn cri5_delete_running_is_failed_precondition() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        assert_eq!(
            err_code(s.handle("Delete", &delete_req("c1", ""))).0,
            PRECOND
        );
        assert!(s.adapter.state("c1").is_ok());
    }

    /// 不正な入力はランタイムを呼ばずに拒否する。
    #[test]
    fn cri5_delete_invalid_inputs() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        assert_eq!(err_code(s.handle("Delete", &delete_req("", ""))).0, INVALID);
        assert_eq!(
            err_code(s.handle("Delete", &delete_req("bad id!", ""))).0,
            INVALID
        );
        let (code, msg) = err_code(s.handle("Delete", &[0x0a, 5, 1]));
        assert_eq!((code, msg.as_str()), (INVALID, "malformed request payload"));
        let (code, msg) = err_code(s.handle("Delete", &delete_req("c1", "e")));
        assert_eq!((code, msg.as_str()), (UNIMPL, "exec_id is not supported"));
        assert!(f.calls.lock().unwrap().is_empty());
    }

    /// exit_status の写像。
    #[test]
    fn cri5_exit_status_mapping() {
        let id = || RtId::new("c1").unwrap();
        let m = |s: ContainerStatus| exit_status_of(&RuntimeContainerStatus::from(&s));
        assert_eq!(m(ContainerStatus::stopped(id(), Some(0))), 0);
        assert_eq!(m(ContainerStatus::stopped(id(), Some(137))), 137);
        assert_eq!(m(ContainerStatus::stopped(id(), None)), 255);
        assert_eq!(m(ContainerStatus::stopped(id(), Some(-1))), 255);
        assert_eq!(m(ContainerStatus::created(id(), None)), 0);
    }
}
