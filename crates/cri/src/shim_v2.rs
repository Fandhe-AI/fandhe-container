//! containerd shim v2 の ttrpc サーバーの骨格（CRI-5・TASK-62.1）。
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
//! - `server`（unix のみ）: UDS 上のサーバー
//!
//! 出典: containerd/ttrpc の `PROTOCOL.md`・`request.proto`・`channel.go`・`server.go`・`services.go`
//! （commit `232612d3cc492aa0c5c83aedac5d13a31a90b0cd`）。
//!
//! 範囲外（REPAIR-3。未実装を装わない）:
//! - containerd の task API の `.proto` 取り込みと v2 / v3 の決定（#669・#672 以降）。本骨格はサービス名だけを持つ
//! - UDS の置き場所・権限・peer UID の照合（SO_PEERCRED）。呼び出し元が bind 済みの listener を渡す。#803（TASK-62.7）で扱う
//! - ストリーミング（Data フレーム・remote open）は拒否する。`metadata`・`timeout_nano` は復号するだけで使わない
//! - Windows（named pipe）。listener と転送は unix のみ。ヘッダと封筒の型は全 OS で使える
//! - 上限超過のペイロードは Go 実装と異なり読み捨てず、`ResourceExhausted` を返して接続を閉じる

pub mod frame;
pub mod message;
#[cfg(unix)]
pub mod server;
pub mod service;

pub use frame::{FrameError, FrameHeader, HEADER_LEN, MAX_PAYLOAD_LEN, MessageType};
pub use message::{KeyValue, RpcStatus, TtrpcRequest, TtrpcResponse};
#[cfg(unix)]
pub use server::{ServerConfig, ServerHandle, ShimV2Error, TtrpcServer};
pub use service::{EmptyTaskService, ServiceRegistry, TaskApiVersion, TtrpcService};
