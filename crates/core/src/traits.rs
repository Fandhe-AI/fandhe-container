//! オーケストレーション拡張点のトレイト群（TASK-4・CRI-7・PLUG-1・MS-0）。
//!
//! CRI-7（Must・確定）は 4 トレイト（`ContainerRuntime`・`StateStore`・`NetworkPlugin`・
//! `VolumeProvider`）を core に定義し、CRI サーバー層・I/O 層・実行層が互いの具象型を
//! 知らずにトレイトだけで呼び合う構造を求めている。境界配置（PLUG-1・D-14）は次の通り。
//!
//! | トレイト | 実装の置き場所 |
//! | -------- | -------------- |
//! | `ContainerRuntime` | plugin（別プロセス＋UDS。TASK-114） |
//! | `NetworkPlugin` | plugin（別プロセス＋UDS） |
//! | `StateStore` | core に既定実装（ファイルベース）。plugin で差し替え可能 |
//! | `VolumeProvider` | core（データパス。トレイト定義・実装とも core 側） |
//!
//! 本モジュールは索引のみを持ち、実体はサブモジュールに分ける（兄弟 issue #16〜#18・
//! TASK-4.2〜4.4 が同じファイルへ追記する際の衝突を 1 行単位に抑えるため）。
//! `ContainerRuntime` 以外の 3 トレイトは #16〜#18 で追加される予定であり、現時点では
//! 未定義である（REPAIR-3: 実装済みを装わない）。
//!
//! シグネチャは人間のアーキテクチャレビュー（#19・TASK-4.h1）前の暫定版であり、
//! 「確認済み」の確定仕様ではない。

pub mod container_runtime;
pub mod types;

pub use container_runtime::{
    ContainerRuntime, ContainerState, ContainerStatus, CreateRequest, DeleteRequest,
    DeleteResponse, KillRequest, Signal, StartRequest, StateRequest, StopRequest,
};
pub use types::{ContainerId, ErrorCode, TraitError};
