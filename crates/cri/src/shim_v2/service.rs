//! ttrpc サービスの登録口と dispatch（CRI-5・TASK-62.1・MS-7）。
//!
//! `server` が復号した [`TtrpcRequest`] を [`ServiceRegistry::dispatch`] へ渡し、
//! サービス名で [`TtrpcService`] を引いて呼ぶ。未知のサービス・メソッドは `Unimplemented`。
//! [`EmptyTaskService`] はどのメソッドにも `Unimplemented` を返す空の Task サービスで、ランタイム未注入の起動経路用。
//! Create / Start / Delete を持つ実装は `task_service::TaskService`（TASK-62.2・TASK-62.3.1）。Wait は TASK-62.3.2、State / Kill 等は後続 issue（REPAIR-3）。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::message::{RpcStatus, TtrpcRequest, TtrpcResponse};
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
    /// 長く待つメソッド（Wait 等）向け。`ctx` で取り消し（サーバー停止・接続切断）とクライアントの
    /// 期限（ttrpc の `timeout_nano`）を受け取る契約（REPAIR-5）。既定は `ctx` を見ない `handle`。
    fn handle_with_context(
        &self,
        method: &str,
        payload: &[u8],
        _ctx: &CallContext<'_>,
    ) -> Result<Vec<u8>, RpcStatus> {
        self.handle(method, payload)
    }
}

/// ttrpc の要求に付いたクライアントの期限（`Request.timeout_nano`。CRI-1・REPAIR-5）。
///
/// containerd/ttrpc の `getRequestContext` に倣い、0 は期限なし、正は相対の期限、負は期限切れ済みとして扱う。
/// 壊れた値を表現できない形にし、巨大値による `Instant` のオーバーフローは「期限なし」に倒す
/// （上限は常に呼び出し側の設定が持つ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestDeadline {
    /// クライアントの期限なし。
    None,
    /// この時刻が期限。
    At(Instant),
    /// 受け取った時点で期限切れ。
    Expired,
}

impl RequestDeadline {
    /// 要求の読み取り開始時刻 `started` と `timeout_nano` から作る。
    pub fn from_timeout_nano(started: Instant, timeout_nano: i64) -> Self {
        match timeout_nano {
            0 => Self::None,
            n if n < 0 => Self::Expired,
            n => started
                .checked_add(Duration::from_nanos(n.unsigned_abs()))
                .map_or(Self::None, Self::At),
        }
    }

    /// `now` 時点で使える待ち時間を `cap`（呼び出し側の設定の上限）で切って返す。
    /// 期限切れ（残りが 0 以下を含む）は `None`。
    pub fn limit_from(&self, now: Instant, cap: Duration) -> Option<Duration> {
        match self {
            Self::None => Some(cap),
            Self::Expired => None,
            Self::At(t) => {
                let left = t.checked_duration_since(now).filter(|d| !d.is_zero())?;
                Some(left.min(cap))
            }
        }
    }
}

/// 長く待つメソッドへ渡す呼び出しの文脈。`server` が接続ごとの dispatch で組み立てる。
#[derive(Clone, Copy)]
pub struct CallContext<'a> {
    /// 真になったら待ちを打ち切る（サーバー停止・接続切断）。
    pub cancelled: &'a (dyn Fn() -> bool + 'a),
    /// クライアントの期限。使うのは Wait だけ（他のメソッドは短く、`ContainerRuntime` の契約で有界）。
    pub deadline: RequestDeadline,
}

impl<'a> CallContext<'a> {
    /// 文脈を組む。
    pub fn new(cancelled: &'a (dyn Fn() -> bool + 'a), deadline: RequestDeadline) -> Self {
        Self {
            cancelled,
            deadline,
        }
    }

    /// 取り消しも期限もない文脈（`dispatch` 用）。
    pub fn none() -> CallContext<'static> {
        CallContext {
            cancelled: &|| false,
            deadline: RequestDeadline::None,
        }
    }
}

/// 空の Task サービス。全メソッドに `Unimplemented` を返す。
#[derive(Debug, Clone, Copy)]
pub struct EmptyTaskService {
    version: TaskApiVersion,
}

impl EmptyTaskService {
    /// 版を指定して作る。
    pub fn new(version: TaskApiVersion) -> Self {
        Self { version }
    }
}

impl TtrpcService for EmptyTaskService {
    fn name(&self) -> &str {
        self.version.service_name()
    }

    fn handle(&self, method: &str, _payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        Err(unimplemented_status("method", method))
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
        self.dispatch_with_context(req, &CallContext::none())
    }

    /// 取り消し通知とクライアントの期限つきで要求を処理する（サーバーの接続ごとの並行 dispatch が使う）。
    pub fn dispatch_with_context(
        &self,
        req: &TtrpcRequest,
        ctx: &CallContext<'_>,
    ) -> TtrpcResponse {
        let Some(svc) = self.services.get(&req.service) else {
            return status_response(unimplemented_status("service", &req.service));
        };
        match svc.handle_with_context(&req.method, &req.payload, ctx) {
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

    /// CRI-1・REPAIR-5: `timeout_nano` の境界。0 は期限なし、負は期限切れ、正は起点からの相対、巨大値は cap で切れる。
    #[test]
    fn cri1_request_deadline_from_timeout_nano() {
        let t0 = Instant::now();
        assert_eq!(
            RequestDeadline::from_timeout_nano(t0, 0),
            RequestDeadline::None
        );
        assert_eq!(
            RequestDeadline::from_timeout_nano(t0, -1),
            RequestDeadline::Expired
        );
        assert_eq!(
            RequestDeadline::from_timeout_nano(t0, i64::MIN),
            RequestDeadline::Expired
        );
        assert_eq!(
            RequestDeadline::from_timeout_nano(t0, 1),
            RequestDeadline::At(t0 + Duration::from_nanos(1))
        );
        let big = RequestDeadline::from_timeout_nano(t0, i64::MAX);
        assert_eq!(
            big.limit_from(t0, Duration::from_secs(60)),
            Some(Duration::from_secs(60))
        );
    }

    /// CRI-1・REPAIR-5: 実効の待ち時間は `min(残り, cap)`。期限切れと残り 0 は `None`。
    #[test]
    fn cri1_request_deadline_limit() {
        let t0 = Instant::now();
        let cap = Duration::from_secs(10);
        assert_eq!(RequestDeadline::None.limit_from(t0, cap), Some(cap));
        assert_eq!(RequestDeadline::Expired.limit_from(t0, cap), None);
        let at = RequestDeadline::At(t0 + Duration::from_millis(100));
        assert_eq!(at.limit_from(t0, cap), Some(Duration::from_millis(100)));
        assert_eq!(
            at.limit_from(t0 + Duration::from_millis(40), cap),
            Some(Duration::from_millis(60))
        );
        assert_eq!(at.limit_from(t0 + Duration::from_millis(100), cap), None);
        assert_eq!(at.limit_from(t0 + Duration::from_secs(1), cap), None);
        let far = RequestDeadline::At(t0 + Duration::from_secs(100));
        assert_eq!(far.limit_from(t0, cap), Some(cap));
    }
}
