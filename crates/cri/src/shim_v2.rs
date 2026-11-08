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
//! - [`task_api`]・[`task_service`]: Task API の Create / Start / Delete / Exec / Wait / State / Kill / Shutdown / Connect のメッセージ型と実装（TASK-62.2・TASK-62.3.1・TASK-62.3.2・TASK-62.4・TASK-62.7.2・TASK-62.6）
//! - [`publish`]: TaskCreate・TaskStart・TaskDelete・TaskExit を期限つきの子プロセス（containerd の publish バイナリ）で送る（TASK-62.6・#4155・#4156）
//! - [`shutdown`]: Shutdown RPC からデーモンへ終了を伝えるシグナル（TASK-62.7.2）
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
//! - exec_id つきの Kill の `all`・State の `bundle`・stdio（常に空・未設定または `UNIMPLEMENTED`。TASK-62.7.2）。Pause / Resume / Pids / Stats 等の他メソッドは `Unimplemented`
//! - Connect の `version`（常に空。containerd は使わない。TASK-62.6）
//! - Wait の `exited_at` は core が記録した終了検知時刻を返す（#3682）。`timeout_nano` は Wait の期限に使い（実効の期限は `min(timeout_nano, wait::WaitConfig::timeout)`、負値は即 `DEADLINE_EXCEEDED`）、他のメソッドでは使わない。
//!   終了待ちは core の `ContainerRuntime::wait_exit`（既定は状態の照会。plugin-cri の `CoreLifecycleRuntime` は supervisor の終了通知でイベント駆動に上書きしている〔#3683〕。cri の bin は `EmptyTaskService` のみで、この上書きへの結線は bootstrap の制約に従う）。
//!   サーバーは接続内で要求ごとに並行 dispatch し（同時処理数に上限あり）、Wait の待ちは他の RPC を止めない。
//!   サーバーの停止・接続の切断・応答の書き込み失敗は処理中のハンドラへ通知され、Wait は期限前に取り消される。
//!   停止で取り消された Wait の `UNAVAILABLE`（14）は、生きている接続へ 1 刻み分だけ書き込みを試して届ける
//! - Create の rootfs mount・stdio・terminal・`options`・checkpoint。黙って捨てず `UNIMPLEMENTED`
//! - exec の stdio・terminal（#677）。Exec の本番の起動役は plugin-cri の `ShimExecLauncher`（Linux のみ。#4148）が持ち、shim バイナリが配線する（#4149。cri は supervisor に依存せず `ContainerRuntime` に exec も無い）。起動役が無い `TaskService` は `Exec`・`Start(exec_id)` と、`exec_id` つきの `State`・`Kill`・`Wait`・`Delete` を `UNIMPLEMENTED` で拒否する（起動後の照会・停止・待機・除去は #3681 で実装済み）
//! - peer UID の照合は `server::ServerConfig::allowed_peer_uids`（SO_PEERCRED / getpeereid。PLUG-12・#872）、UDS の置き場所と権限は [`bootstrap`] が扱う
//! - ストリーミング（Data フレーム・remote open）は拒否する。`metadata` は復号するだけで使わない
//! - Windows（named pipe）。listener と転送は unix のみ。ヘッダと封筒の型は全 OS で使える
//! - exec 系・Paused・Resumed・Checkpointed・OOM のイベントは送らない（対応する RPC・仕組みが無い。#4156）
//! - 上限超過のペイロードは Go 実装と異なり読み捨てず、`ResourceExhausted` を返して接続を閉じる

pub mod bootstrap;
pub mod exec;
pub mod frame;
pub mod message;
pub mod publish;
#[cfg(unix)]
pub mod server;
pub mod service;
pub mod shutdown;
pub mod task_api;
pub mod task_service;
pub mod wait;

pub use exec::{
    ExecId, ExecProcessSpec, ExecProcessStatus, ExecUser, TaskExecLauncher, TaskExecProcess,
};
pub use frame::{FrameError, FrameHeader, HEADER_LEN, MAX_PAYLOAD_LEN, MessageType};
pub use message::{KeyValue, RpcStatus, TtrpcRequest, TtrpcResponse};
#[cfg(unix)]
pub use server::{ServerConfig, ServerHandle, ShimV2Error, TtrpcServer};
pub use service::{
    CallContext, EmptyTaskService, RequestDeadline, ServiceRegistry, TaskApiVersion, TtrpcService,
};
pub use shutdown::ShutdownSignal;
pub use task_api::{
    Any, ConnectRequest, ConnectResponse, CreateTaskRequest, CreateTaskResponse, DeleteRequest,
    DeleteResponse, ExecProcessRequest, KillRequest, Mount, ShutdownRequest, StartRequest,
    StartResponse, StateRequest, StateResponse, TaskStatus, Timestamp, WaitRequest, WaitResponse,
};
pub use task_service::TaskService;
pub use wait::WaitConfig;
