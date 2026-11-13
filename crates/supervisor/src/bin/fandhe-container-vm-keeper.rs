//! macOS の VM 保持役の bin（MAC-4・CORE-1・TASK-191・#2278。feature `vm-keeper` のときだけビルドされる）。
//!
//! 本体は `fandhe_container_supervisor::vm_keeper`。macOS 以外では構造化エラー `UNIMPLEMENTED` を出して非 0 で終わる
//! （Linux の VM 共用は不要で、Windows は WSL2 側の別設計。実装済みを装わない。REPAIR-3）。

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    // 先頭の引数（実行ファイル名）を除いて渡す。
    fandhe_container_supervisor::vm_keeper::run_main(std::env::args_os().skip(1))
}

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    use fandhe_container_core::oci_runtime::{LifecycleOp, OciRuntimeError};
    use fandhe_container_core::traits::ErrorCode;

    let err = OciRuntimeError::new(
        LifecycleOp::Start,
        ErrorCode::Unimplemented,
        "the vm keeper requires macOS",
    );
    // stderr の読み手が止まっていても期限で終わる（REPAIR-5）。
    let mut line = Vec::new();
    if err.write_json_line(&mut line).is_ok() {
        let _ = fandhe_container_supervisor::stderr_sink::stderr()
            .emit_and_wait(line, std::time::Duration::from_secs(1));
    }
    std::process::ExitCode::from(err.exit_code().get())
}
