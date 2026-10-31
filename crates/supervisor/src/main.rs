//! supervisor の bin の入口（TASK-157 追補・#1717・SUP-1・CLI-1）。
//!
//! CLI（#1718）が固定のインストール先から起動する。argv と結果チャネル（stdout の pipe）の契約は
//! [`fandhe_container_supervisor::start_contract`]、処理順は `start_entry` を参照。本ファイルは薄い入口だけを持つ。
//! Linux 以外は supervisor の本体（状態ストア・cgroup）が無いため `UNIMPLEMENTED` を stderr に出して終わる（CLI-1）。

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    // 第 1 引数が `netns-holder` なら holder 本体へ振り分ける（NET-9・CORE-1・#3198。`docs/design/rootless-network.md` 12.2）。
    // 継承 fd の整理・結果チャネルの検証・`set_dumpable(false)`（いずれも `run_main` の手順）より前に分けるのは、
    // holder が dumpable のまま pasta に `/proc/<holder>/ns/*` を開かせる前提で、結果チャネルを持たないため。
    // 特権ランチャーは `StartArgs::parse` を通った argv だけを転送するので、この分岐の入口にはならない。
    let mut args = std::env::args_os().skip(1);
    let first = args.next();
    if fandhe_container_supervisor::netns_holder::is_holder_invocation(first.as_deref()) {
        return fandhe_container_net::netns_holder::run_netns_holder_main(args);
    }
    // 第 1 引数が `healthcheck-exec` なら healthcheck の exec 専用 helper へ振り分ける（SUP-4・SUP-6・#2441）。
    // `netns-holder` と同じ位置・同じ理由（結果の返し方が違うため `run_main` の fd 検証・結果チャネルを通さない）。
    if fandhe_container_supervisor::healthcheck::exec_helper::is_health_exec_invocation(
        first.as_deref(),
    ) {
        return fandhe_container_supervisor::healthcheck::exec_helper::run_health_exec_main(args);
    }
    fandhe_container_supervisor::start_entry::run_main(first.into_iter().chain(args))
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    use fandhe_container_core::oci_runtime::{LifecycleOp, OciRuntimeError};
    use fandhe_container_core::traits::ErrorCode;

    let err = OciRuntimeError::new(
        LifecycleOp::Start,
        ErrorCode::Unimplemented,
        "the supervisor requires Linux",
    );
    // stderr の読み手が止まっていても期限で終わる（REPAIR-5）。
    let mut line = Vec::new();
    if err.write_json_line(&mut line).is_ok() {
        let _ = fandhe_container_supervisor::stderr_sink::stderr()
            .emit_and_wait(line, std::time::Duration::from_secs(1));
    }
    std::process::ExitCode::from(err.exit_code().get())
}
