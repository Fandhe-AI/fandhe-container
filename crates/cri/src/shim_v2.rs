//! containerd shim v2 の ttrpc サーバーの骨格（CRI-5・TASK-62.1・MS-7）。
//!
//! containerd の shim v2 Task API は ttrpc（unary のみ）の上で動く。#670（TASK-62.hdep1）の
//! オーナー判断で `ttrpc` クレートと `containerd-shim-protos` は導入しないと決まったため、
//! ワイヤー形式（10 バイトのヘッダと Request / Response）は本モジュールで自作し、
//! メッセージの符号化は承認済みの prost（derive）で行う。依存は足さない。
//!
//! 構成:
//! - [`frame`]: 10 バイトのヘッダ（壊れた値を表現できない型。REPAIR-2）
//! - [`message`]: ttrpc の封筒（Request / Response / Status）
//! - [`service`]: サービスの登録口と dispatch、中身の無い Task サービス
//! - [`task_api`]・[`task_service`]: Task API の Create / Start / Delete / Exec のメッセージ型と実装（TASK-62.2・TASK-62.3.1・TASK-62.4）
//! - [`exec`]: Exec の検証済み型・登録簿・起動役のトレイト（TASK-62.4）
//! - `server`（unix のみ）: UDS 上のサーバー
//!
//! 出典: containerd/ttrpc の `PROTOCOL.md`・`request.proto`・`channel.go`・`server.go`・`services.go`
//! （commit `232612d3cc492aa0c5c83aedac5d13a31a90b0cd`）。
//!
//! 範囲外（REPAIR-3。未実装を装わない）:
//! - containerd の task API の `.proto` 取り込みと v2 / v3 の決定（#669）。メッセージ型は手書きでサービス名だけで版を分ける
//! - Wait（#673・#871）、State / Kill / Shutdown（#873）。`Unimplemented`
//! - Create の rootfs mount・stdio・terminal・`options`・checkpoint、Delete の `exited_at`（core が終了時刻を持たず常に未設定）。黙って捨てず `UNIMPLEMENTED`
//! - Exec の本番の起動役（supervisor の exec 入口への橋渡しと配線は #675・#803）、`Delete(exec_id)`（登録の除去を含め未対応で `UNIMPLEMENTED`。#674）、
//!   exec の stdio・terminal（#677）。起動役が無い `TaskService` は `Exec` と `Start(exec_id)` を `UNIMPLEMENTED` で拒否する
//! - UDS の置き場所・権限・peer UID の照合（SO_PEERCRED）。呼び出し元が bind 済みの listener を渡す。#803（TASK-62.7）で扱う
//! - ストリーミング（Data フレーム・remote open）は拒否する。`metadata`・`timeout_nano` は復号するだけで使わない
//! - Windows（named pipe）。listener と転送は unix のみ。ヘッダと封筒の型は全 OS で使える
//! - 上限超過のペイロードは Go 実装と異なり読み捨てず、`ResourceExhausted` を返して接続を閉じる

pub mod exec;
pub mod frame;
pub mod message;
#[cfg(unix)]
pub mod server;
pub mod service;
pub mod task_api;
pub mod task_service;

pub use exec::{ExecId, ExecProcessSpec, ExecUser, TaskExecLauncher};
pub use frame::{FrameError, FrameHeader, HEADER_LEN, MAX_PAYLOAD_LEN, MessageType};
pub use message::{KeyValue, RpcStatus, TtrpcRequest, TtrpcResponse};
#[cfg(unix)]
pub use server::{ServerConfig, ServerHandle, ShimV2Error, TtrpcServer};
pub use service::{EmptyTaskService, ServiceRegistry, TaskApiVersion, TtrpcService};
pub use task_api::{
    Any, CreateTaskRequest, CreateTaskResponse, DeleteRequest, DeleteResponse, ExecProcessRequest,
    Mount, StartRequest, StartResponse, Timestamp,
};
pub use task_service::TaskService;
