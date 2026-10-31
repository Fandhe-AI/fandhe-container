//! fandhe-container-cri: CRI 実装ライブラリ（Runtime/ImageService・shim v2・streaming）。
//!
//! 雛形は TASK-1.3・REPAIR-1。現状の RPC 実装は `runtime_service` の `RunPodSandbox`・`StopPodSandbox`・`RemovePodSandbox`・`PodSandboxStatus`・`ListPodSandbox`・`CreateContainer`・`StartContainer`・`StopContainer`・`RemoveContainer`（TASK-57.1〜57.3・58.1・58.2・CRI-1）と、`image_service` の `ListImages`・`ImageStatus`・`PullImage`（TASK-61.1・61.2・61.3・CRI-4。取り込み手順は `image_pull`）のみで、
//! `ContainerRuntime` 呼び出しアダプタ `adapter` は TASK-59.1（CRI-2・CRI-7）で追加済みで、`CreateContainer`・`StartContainer` への接続は TASK-59.2（#438。`CriRuntimeService::with_runtime` で注入したときだけ有効）、
//! `StopContainer`・`RemoveContainer`・`StopPodSandbox`・`RemovePodSandbox` への接続は TASK-59.3（#439。同じく注入時のみ有効）。
//! 全ライフサイクルの結合試験は TASK-59.4（#440。`tests/adapter_integration.rs`）。
//! CRI の設定から OCI bundle（`config.json` と bundle の寿命）を作る層は `bundle`（#2395。image 展開は #2433 の `ImageRootfsSource`）。
//! 統一エラー型 `error`（ERR-3・TASK-97.1）をハンドラへ適用済み（TASK-97.2・#450）。
//! shim v2 の ttrpc サーバーの骨格と空の Task サービスは `shim_v2`（TASK-62.1・CRI-5。ワイヤー形式は自作）。
//! 他の RPC は `Unimplemented`、状態管理はメモリ上のスタブ（TASK-59 で置換。REPAIR-3）。
//! RPC の結果と所要時間は `instrument` の記録先へ渡す（REPAIR-4。core の記録器への接続は plugin-cri。TASK-108）。
//! 本体は G4（TASK-56〜63）で実装する。実行時は `fandhe-container-plugin-cri`（TASK-114）が
//! 本 crate を別プロセスとして動かす。PLUG-1 区分は plugin 境界の外側（バックエンド実装ライブラリ。crate-naming.md）。
//!
//! TASK-56.1（#423・CRI-3）で雛形を確認済み。proto は TASK-56.2（#424）で `proto/api.proto` に配置済み。`build.rs`（TASK-56.3・#426）が `OUT_DIR/runtime.v1.rs` へ
//! 生成し、[`runtime::v1`] で取り込む（TASK-56.4・#427。型の整合は `tests/generated_build_check.rs` で照合）。RPC 本体は TASK-57 以降で順次実装する（未実装分はスタブ。REPAIR-3）。

pub mod adapter;
pub mod bundle;
pub mod error;
pub mod image_pull;
pub mod image_service;
pub mod instrument;
pub mod port_mapping;
pub mod runtime_service;
pub mod shim_v2;
pub mod stop_signal;

/// cri-api の proto package `runtime` に対応するモジュール階層（CRI-3・TASK-56.4）。
pub mod runtime {
    /// `runtime.v1` の生成コード（`RuntimeService` / `ImageService` のサーバー・クライアントとメッセージ型）。
    ///
    /// `build.rs` が無改変の `proto/api.proto` から生成した `OUT_DIR/runtime.v1.rs` を取り込む。
    /// proto 由来の doc コメントが rustdoc / clippy の lint に触れるため、この生成コードに限り該当 lint を許可する
    /// （crate 全体へは広げない）。後続の TASK-57 以降と `fandhe-container-plugin-cri`（TASK-108。組み立て口は `adapter`・TASK-114.2）が使う。
    #[allow(
        clippy::doc_overindented_list_items,
        clippy::doc_lazy_continuation,
        rustdoc::bare_urls,
        rustdoc::invalid_html_tags
    )]
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/runtime.v1.rs"));
    }
}

// 先に消してから作る試験補助を排他作成へ揃えるための共有部品（oci の結合試験の補助を取り込む。
// REPAIR-12・#3506）。試験専用で製品・rlib に影響しない。
#[cfg(test)]
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;
