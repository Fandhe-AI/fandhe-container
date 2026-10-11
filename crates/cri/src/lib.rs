//! fandhe-container-cri: CRI 実装ライブラリ（Runtime/ImageService・shim v2・streaming）。
//!
//! 雛形は TASK-1.3・REPAIR-1。現状の RPC 実装は `runtime_service` の `RunPodSandbox`・`StopPodSandbox`・`RemovePodSandbox`（TASK-57.1・57.2・CRI-1）と、`image_service` の `ListImages`（TASK-61.1・CRI-4）のみで、
//! 他の RPC は `Unimplemented`、状態管理はメモリ上のスタブ（TASK-59 で置換。REPAIR-3）。
//! RPC の結果と所要時間は `instrument` の記録先へ渡す（REPAIR-4。core の記録器への接続は plugin-cri。TASK-108）。
//! 本体は G4（TASK-56〜63）で実装する。実行時は `fandhe-container-plugin-cri`（TASK-114）が
//! 本 crate を別プロセスとして動かす。PLUG-1 区分は plugin 境界の外側（バックエンド実装ライブラリ。crate-naming.md）。
//!
//! TASK-56.1（#423・CRI-3）で雛形を確認済み。proto は TASK-56.2（#424）で `proto/api.proto` に配置済み。`build.rs`（TASK-56.3・#426）が `OUT_DIR/runtime.v1.rs` へ
//! 生成し、[`runtime::v1`] で取り込む（TASK-56.4・#427。型の整合は `tests/generated_build_check.rs` で照合）。RPC 本体は TASK-57 以降で順次実装する（未実装分はスタブ。REPAIR-3）。

pub mod image_service;
pub mod instrument;
pub mod runtime_service;

/// cri-api の proto package `runtime` に対応するモジュール階層（CRI-3・TASK-56.4）。
pub mod runtime {
    /// `runtime.v1` の生成コード（`RuntimeService` / `ImageService` のサーバー・クライアントとメッセージ型）。
    ///
    /// `build.rs` が無改変の `proto/api.proto` から生成した `OUT_DIR/runtime.v1.rs` を取り込む。
    /// proto 由来の doc コメントが rustdoc / clippy の lint に触れるため、この生成コードに限り該当 lint を許可する
    /// （crate 全体へは広げない）。後続の TASK-57 以降と `fandhe-container-plugin-cri`（TASK-108）が使う。
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
