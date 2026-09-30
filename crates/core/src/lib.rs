//! fandhe-container-core: 実行層（namespace・cgroups v2・seccomp/Landlock・rootless・ログ・状態管理）。
//!
//! # 役割
//!
//! コンテナを起動・分離する実行層（CORE-1・TASK-27）と、拡張点トレイト定義
//! （`traits`。TASK-4・CRI-7・MS-0）を担う。`StateStore` トレイトとファイルベースの
//! 既定実装も本 crate に置く（TASK-31・OCI-5・決定 6）。PLUG-1 区分は core
//! （crate-naming.md）。中央の常駐デーモンは持たない（CORE-1・D-19）。
//!
//! # 責務境界・依存方向
//!
//! - `core` は `io` に依存する想定（`VolumeProvider` のデータパス）。`io` は core に依存しない
//! - `supervisor` は core に依存する（`StateStore` 既定実装を core に一本化。決定 6）
//! - `ContainerRuntime`・`NetworkPlugin` の実装は別プロセス＋UDS の plugin 側に置く（PLUG-1）。
//!   plugin の追加で core を変更しない（PLUG-4）
//! - `cri`・`platform-*`・`microvm`・`plugin-*` には依存しない
//!
//! # モジュール構成
//!
//! - `traits`: 拡張点トレイト（実装済み。TASK-4 系）
//! - `exec`: 最小実行フロー（Linux 限定。namespace 分離〔TASK-27.2〕と `pivot_root` による
//!   rootfs 切替〔TASK-27.3〕、基本デバイスノード作成〔TASK-27.6。`exec/devices.rs`。
//!   Issue 表記の `src/devices.rs` ではなく `exec` 配下に置く: 段の型 `ExecError`・`MountIsolation`
//!   の検証が `exec` の非公開項目のため〕が実装済みで、fork / exec 等は未実装。非 Linux ではビルド対象外のため本 doc からは
//!   リンクしない）
//! - `sys`: syscall・FFI の薄いラッパー（Linux 限定・非公開。`unsafe` の事前承認範囲）
//! - 予定（未作成）: `oci_runtime`（TASK-29・30）・`state_store`
//!   （TASK-31・OCI-5）・`cgroups`（TASK-32・CORE-3）・`plugin_discovery`（TASK-109）
//!
//! 実行層本体（namespace・cgroups v2・seccomp/Landlock・rootless 等）は G3（TASK-27〜50）で
//! 実装する未実装のままである（REPAIR-3: 実装済みを装わず、未実装であることも隠さない）。

#[cfg(target_os = "linux")]
pub mod exec;
#[cfg(target_os = "linux")]
mod sys;
pub mod traits;
