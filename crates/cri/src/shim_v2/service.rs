//! ttrpc サービスの登録口と dispatch（CRI-5・TASK-62.1・MS-7）。
//!
//! `server` が復号した [`TtrpcRequest`] を [`ServiceRegistry::dispatch`] へ渡し、
//! サービス名で [`TtrpcService`] を引いて呼ぶ。未知のサービス・メソッドは `Unimplemented`。
//! [`EmptyTaskService`] はどのメソッドにも `Unimplemented` を返す空の Task サービスで、ランタイム未注入の起動経路用。
//! Create / Start / Delete / Wait / State / Kill / Shutdown を持つ実装は `task_service::TaskService`（TASK-62.2・TASK-62.3.1・TASK-62.3.2・TASK-62.7.2）。
//! [`EmptyTaskService`] も Shutdown だけは処理する（ランタイムを持たずコンテナが無いため無条件に終了を要求する。TASK-62.7.2）。

use std::collections::BTreeMap;
use std::sync::Arc;

use prost::Message;

use super::message::{RpcStatus, TtrpcRequest, TtrpcResponse};
use super::shutdown::ShutdownSignal;
use super::task_api::ShutdownRequest;
use crate::error::CriErrorCode;

/// 応答 message に入れる名前の最大バイト数（外部入力で応答が肥大化しないよう切る）。
const NAME_ECHO_MAX: usize = 256;

/// containerd の task API の版。どちらを採るかは #669・#672 で決まる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskApiVersion {
    /// `containerd.task.v2.Task`。
    V2,
    /// `containerd.task.v3.Task`。
    V3,
}

impl TaskApiVersion {
    /// ttrpc のサービス名。
    pub fn service_name(self) -> &'static str {
        match self {
            Self::V2 => "containerd.task.v2.Task",
            Self::V3 => "containerd.task.v3.Task",
        }
    }
}

/// ttrpc の unary サービス。
pub trait TtrpcService: Send + Sync {
    /// 登録名。
    fn name(&self) -> &str;
    /// メソッドを処理する。失敗は [`RpcStatus`] で返す。
    fn handle(&self, method: &str, payload: &[u8]) -> Result<Vec<u8>, RpcStatus>;
    /// 長く待つメソッド（Wait 等）向け。`cancelled` が真になったら（サーバー停止・接続切断）待ちを
    /// 打ち切る契約（REPAIR-5）。既定は取り消しを見ない `handle`。
    fn handle_cancellable(
        &self,
        method: &str,
        payload: &[u8],
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, RpcStatus> {
        self.handle(method, payload)
    }
}

/// 空の Task サービス。`with_shutdown` で終了要求の送り先を差し込んだときの Shutdown 以外は `Unimplemented` を返す。
#[derive(Debug, Clone)]
pub struct EmptyTaskService {
    version: TaskApiVersion,
    shutdown: Option<ShutdownSignal>,
}

impl EmptyTaskService {
    /// 版を指定して作る。
    pub fn new(version: TaskApiVersion) -> Self {
        Self {
            version,
            shutdown: None,
        }
    }

    /// Shutdown RPC の終了要求の送り先を差し込む（TASK-62.7.2）。
    pub fn with_shutdown(mut self, signal: ShutdownSignal) -> Self {
        self.shutdown = Some(signal);
        self
    }
}

impl TtrpcService for EmptyTaskService {
    fn name(&self) -> &str {
        self.version.service_name()
    }

    fn handle(&self, method: &str, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        match (method, self.shutdown.as_ref()) {
            ("Shutdown", Some(signal)) => {
                ShutdownRequest::decode(payload).map_err(|_| {
                    RpcStatus::from_code(CriErrorCode::InvalidArgument, "malformed request payload")
                })?;
                signal.request();
                Ok(Vec::new())
            }
            _ => Err(unimplemented_status("method", method)),
        }
    }
}

pub(super) fn unimplemented_status(kind: &str, name: &str) -> RpcStatus {
    let mut end = name.len().min(NAME_ECHO_MAX);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    let shown = name.get(..end).unwrap_or("");
    RpcStatus::from_code(CriErrorCode::Unimplemented, format!("{kind} {shown}"))
}

/// 二重登録のエラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateService;

impl std::fmt::Display for DuplicateService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "service already registered")
    }
}

impl std::error::Error for DuplicateService {}

/// 名前でサービスを引く登録簿。
#[derive(Default, Clone)]
pub struct ServiceRegistry {
    services: BTreeMap<String, Arc<dyn TtrpcService>>,
}

impl ServiceRegistry {
    /// 空の登録簿。
    pub fn new() -> Self {
        Self::default()
    }

    /// 登録する。同名は `Err`（panic しない）。
    pub fn register(&mut self, service: Arc<dyn TtrpcService>) -> Result<(), DuplicateService> {
        let name = service.name().to_string();
        if self.services.contains_key(&name) {
            return Err(DuplicateService);
        }
        self.services.insert(name, service);
        Ok(())
    }

    /// 要求を処理して応答を作る。
    pub fn dispatch(&self, req: &TtrpcRequest) -> TtrpcResponse {
        self.dispatch_cancellable(req, &|| false)
    }

    /// 取り消し通知つきで要求を処理する（サーバーの接続ごとの並行 dispatch が使う）。
    pub fn dispatch_cancellable(
        &self,
        req: &TtrpcRequest,
        cancelled: &dyn Fn() -> bool,
    ) -> TtrpcResponse {
        let Some(svc) = self.services.get(&req.service) else {
            return status_response(unimplemented_status("service", &req.service));
        };
        match svc.handle_cancellable(&req.method, &req.payload, cancelled) {
            Ok(payload) => TtrpcResponse {
                status: None,
                payload,
            },
            Err(st) => status_response(st),
        }
    }
}

fn status_response(st: RpcStatus) -> TtrpcResponse {
    TtrpcResponse {
        status: Some(st),
        payload: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(service: &str, method: &str) -> TtrpcRequest {
        TtrpcRequest {
            service: service.into(),
            method: method.into(),
            ..Default::default()
        }
    }

    /// CRI-5: 版ごとのサービス名と Unimplemented。
    #[test]
    fn cri5_empty_task_service() {
        let mut reg = ServiceRegistry::new();
        reg.register(Arc::new(EmptyTaskService::new(TaskApiVersion::V2)))
            .unwrap();
        reg.register(Arc::new(EmptyTaskService::new(TaskApiVersion::V3)))
            .unwrap();
        let code = CriErrorCode::Unimplemented.grpc_code() as i32;
        for svc in ["containerd.task.v2.Task", "containerd.task.v3.Task"] {
            let st = reg.dispatch(&req(svc, "Create")).status.unwrap();
            assert_eq!(st.code, code);
            assert_eq!(st.message, "method Create");
        }
    }

    /// CRI-5・TASK-62.7.2: Shutdown だけは処理し、他は Unimplemented のまま。
    #[test]
    fn cri5_873_empty_service_shutdown() {
        let sig = ShutdownSignal::new();
        let mut reg = ServiceRegistry::new();
        reg.register(Arc::new(
            EmptyTaskService::new(TaskApiVersion::V2).with_shutdown(sig.clone()),
        ))
        .unwrap();
        let mut r = req("containerd.task.v2.Task", "Shutdown");
        r.payload = vec![0xff, 0xff];
        assert_eq!(reg.dispatch(&r).status.unwrap().code, 3);
        assert!(!sig.is_requested());
        r.payload = ShutdownRequest {
            id: "x".into(),
            now: false,
        }
        .encode_to_vec();
        let resp = reg.dispatch(&r);
        assert!(resp.status.is_none() && resp.payload.is_empty());
        assert!(sig.is_requested());
        let st = reg
            .dispatch(&req("containerd.task.v2.Task", "State"))
            .status
            .unwrap();
        assert_eq!(st.code, 12);
    }

    /// CRI-5: 二重登録は Err、未知サービスは Unimplemented。
    #[test]
    fn cri5_duplicate_and_unknown() {
        let mut reg = ServiceRegistry::new();
        reg.register(Arc::new(EmptyTaskService::new(TaskApiVersion::V2)))
            .unwrap();
        assert_eq!(
            reg.register(Arc::new(EmptyTaskService::new(TaskApiVersion::V2))),
            Err(DuplicateService)
        );
        let st = reg.dispatch(&req("nope.Svc", "M")).status.unwrap();
        assert_eq!(st.code, 12);
        assert_eq!(st.message, "service nope.Svc");
    }
}
