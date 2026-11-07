//! `containerd-shim-fandhe-container-v2` の入口（CRI-5・CRI-7・PLUG-1・TASK-62.6・#3684）。
//!
//! containerd が exec する shim バイナリの薄い main。引数の解釈と start / delete / serve の手順、結果の出力と終了コードは
//! `fandhe_container_cri::shim_v2::bootstrap::run_cli_with_context` にあり、ここでは serve が呼ぶサービスの注入口
//! （[`fandhe_container_plugin_cri::shim::production_registry`]。本番の `TaskService`）を渡すだけにする。
//! 本番の `ContainerRuntime` は plugin-cri にしか無いため、このバイナリの置き場所は cri ではなく plugin-cri
//! （判断は `docs/design/shim-v2-production-binary.md`）。
//! 失敗時は stdout へ何も書かず、stderr へ `{"code":"<CODE>","message":"<message>"}` の 1 行（JSON）を出して終了コード 1。
//! start の成功経路では stderr へ何も書かない（containerd が stdout と stderr をまとめて読むため）。

use std::process::ExitCode;

fn main() -> ExitCode {
    fandhe_container_cri::shim_v2::bootstrap::run_cli_with_context(
        fandhe_container_plugin_cri::shim::production_registry,
    )
}
