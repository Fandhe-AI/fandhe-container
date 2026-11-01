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
//! - [`task_api`]・[`task_service`]: Task API の Create / Start / Delete / Exec / Wait のメッセージ型と実装（TASK-62.2・TASK-62.3.1・TASK-62.3.2・TASK-62.4）
//! - [`bootstrap`]: 起動バイナリの start / delete / serve と引数解釈（TASK-62.7.1・#872）
//! - [`wait`]: Wait の期限と照会間隔の設定・ポーリング本体（TASK-62.3.2）
//! - [`exec`]: Exec の検証済み型・登録簿・起動役のトレイト（TASK-62.4）
//! - `server`（unix のみ）: UDS 上のサーバー
//!
//! ContainerRuntime の別アダプタ（TASK-62.5・CRI-5・CRI-7）:
//! [`TaskService`] は `crate::adapter::RuntimeAdapter`（core の `traits` の `ContainerRuntime`）だけを通して実行層を呼び、
//! 実行層の具象型・supervisor・RuntimeService の具象には依存しない。`CriRuntimeService::with_runtime` と同じ
//! adapter を clone して渡せば同一の実装を共有する。照合は `tests/shim_v2_runtime_boundary.rs`（依存の静的照合）と
//! `tests/shim_v2_shared_runtime.rs`（共有の結合試験）。
//!
//! 出典: containerd/ttrpc の `PROTOCOL.md`・`request.proto`・`channel.go`・`server.go`・`services.go`
//! （commit `232612d3cc492aa0c5c83aedac5d13a31a90b0cd`）。
//!
//! 範囲外（REPAIR-3。未実装を装わない）:
//! - containerd の task API の `.proto` 取り込みと v2 / v3 の決定（#669）。メッセージ型は手書きでサービス名だけで版を分ける
//! - State / Kill / Shutdown（#873）。`Unimplemented`
//! - Wait の `exec_id`・`exited_at`（常に未設定）・`timeout_nano`（期限は shim 側の [`wait::WaitConfig`] だけで決める）。
//!   サーバーは接続内で要求ごとに並行 dispatch し（同時処理数に上限あり）、Wait の待ちは他の RPC を止めない。
//!   サーバーの停止・接続の切断・応答の書き込み失敗は処理中のハンドラへ通知され、Wait は期限前に取り消される
//! - Create の rootfs mount・stdio・terminal・`options`・checkpoint、Delete の `exited_at`（core が終了時刻を持たず常に未設定）。黙って捨てず `UNIMPLEMENTED`
//! - Exec の本番の起動役（supervisor の exec 入口への橋渡しと配線は #803。cri は supervisor に依存せず `ContainerRuntime` に exec も無い）、`Delete(exec_id)`（登録の除去を含め未対応で `UNIMPLEMENTED`。#674）、
//!   exec の stdio・terminal（#677）。起動役が無い `TaskService` は `Exec` と `Start(exec_id)` を `UNIMPLEMENTED` で拒否する
//! - peer UID の照合（SO_PEERCRED）。UDS の置き場所と権限は [`bootstrap`] が扱う（#872）が、接続元の照合は未対応で後続
//! - ストリーミング（Data フレーム・remote open）は拒否する。`metadata`・`timeout_nano` は復号するだけで使わない
//! - Windows（named pipe）。listener と転送は unix のみ。ヘッダと封筒の型は全 OS で使える
//! - 上限超過のペイロードは Go 実装と異なり読み捨てず、`ResourceExhausted` を返して接続を閉じる

pub mod bootstrap;
pub mod exec;
pub mod frame;
pub mod message;
#[cfg(unix)]
pub mod server;
pub mod service;
pub mod task_api;
pub mod task_service;
pub mod wait;

pub use exec::{ExecId, ExecProcessSpec, ExecUser, TaskExecLauncher};
pub use frame::{FrameError, FrameHeader, HEADER_LEN, MAX_PAYLOAD_LEN, MessageType};
pub use message::{KeyValue, RpcStatus, TtrpcRequest, TtrpcResponse};
#[cfg(unix)]
pub use server::{ServerConfig, ServerHandle, ShimV2Error, TtrpcServer};
pub use service::{EmptyTaskService, ServiceRegistry, TaskApiVersion, TtrpcService};
pub use task_api::{
    Any, CreateTaskRequest, CreateTaskResponse, DeleteRequest, DeleteResponse, ExecProcessRequest,
    Mount, StartRequest, StartResponse, Timestamp, WaitRequest, WaitResponse,
};
pub use task_service::TaskService;
pub use wait::WaitConfig;
