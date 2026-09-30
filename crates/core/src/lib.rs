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
//!   の検証が `exec` の非公開項目のため〕、fork / exec による子プロセス起動〔TASK-27.4.1。最小構成でフック無し〕、順序固定のステージ列の枠〔TASK-27.4.2。`exec/stages.rs`。`NO_NEW_PRIVS` のみ固定ステージとして TASK-27.4.3 で実装済み〕が
//!   実装済みで、他の段の実体（cgroup 参加・capability 削減・seccomp・Landlock）は未実装。非 Linux ではビルド対象外のため本 doc からは
//!   リンクしない）
//! - `observability`: メトリクス集計型 `OpStats` 等（TASK-84.1・REPAIR-4。型定義のみ実装済みで、
//!   記録・出力・計装は TASK-84.2 以降で未実装）
//! - `sys`: syscall・FFI の薄いラッパー（Linux 限定・非公開。`unsafe` の事前承認範囲）
//! - 予定（未作成）: `oci_runtime`（TASK-29・30）・`state_store`
//!   （TASK-31・OCI-5）・`cgroups`（TASK-32・CORE-3）・`plugin_discovery`（TASK-109）
//!
//! # プラットフォーム対応（TASK-27.5・CORE-1）
//!
//! - `exec`・`sys` は `lib.rs` の `#[cfg(target_os = "linux")]` でビルド対象から外れ、
//!   `sys.rs` も内側の `#![cfg]` で二重に隔離している。`traits` は OS 非依存で 3 OS に公開される
//! - `sys` の `extern "C"` 宣言と `unsafe` は glibc / musl の型幅・syscall 番号を前提とするため、
//!   前提の成り立たない macOS / Windows でコンパイル・リンクさせない（安全上の理由での隔離）
//! - 新しい Linux 専用コードは `exec` / `sys` 配下に置く。それ以外に置く場合は
//!   `cfg(target_os = "linux")` で局所化する（CLI-1）
//! - 非 Linux ビルドの保証は CI の macOS / Windows ネイティブ runner での
//!   ビルド・clippy `-D warnings` が担う（3 OS 一級対応）
//!
//! 実行層本体（namespace・cgroups v2・seccomp/Landlock・rootless 等）は G3（TASK-27〜50）で
//! 実装する未実装のままである（REPAIR-3: 実装済みを装わず、未実装であることも隠さない）。

#[cfg(target_os = "linux")]
pub mod exec;
pub mod observability;
#[cfg(target_os = "linux")]
mod sys;
pub mod traits;

/// 非 Linux ビルドの確認（CORE-1・TASK-27.5）。
///
/// 本当のガードは macOS / Windows runner でのコンパイル（clippy `-D warnings`）そのものである。
/// 本テストは OS 非依存の公開面（`traits`）が 3 OS で到達可能であることを具体値で照合した記録。
#[cfg(test)]
mod platform_tests {
    use crate::traits::{ContainerId, ErrorCode};

    #[test]
    fn core1_task27_5_traits_surface_is_os_neutral() {
        let id = ContainerId::new("abc").expect("valid container id");
        assert_eq!(id.as_str(), "abc");
        assert_eq!(ErrorCode::Unimplemented.as_str(), "UNIMPLEMENTED");
    }
}
