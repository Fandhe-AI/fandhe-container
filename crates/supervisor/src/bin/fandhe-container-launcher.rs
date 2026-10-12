//! 特権ランチャーの bin の入口（TASK-171 追補・#1719・SUP-14・SEC-1）。
//!
//! CLI（#1718）が固定のインストール先から起動する。file capability（方式 (c)）または setuid root（方式 (a)。
//! xattr 非対応環境に限る）が付与されている前提で、入口検証 → 権限昇格 → 検証済み fd での supervisor の exec を行う。
//! 処理の詳細と失敗時の契約は `fandhe_container_supervisor::launcher` を参照。本ファイルは薄い入口だけを持つ。
//! Linux 以外は権限分離の対象外（macOS / Windows は VM 内で動く）のため `UNIMPLEMENTED` を stderr に出して終わる（CLI-1）。

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    fandhe_container_supervisor::launcher::run_main(
        std::env::args_os().skip(1),
        std::env::vars_os(),
    )
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    use fandhe_container_core::oci_runtime::{LifecycleOp, OciRuntimeError};
    use fandhe_container_core::traits::ErrorCode;

    let err = OciRuntimeError::new(
        LifecycleOp::Start,
        ErrorCode::Unimplemented,
        "the privileged launcher requires Linux",
    );
    // stderr の読み手が止まっていても期限で終わる（REPAIR-5）。
    let mut line = Vec::new();
    if err.write_json_line(&mut line).is_ok() {
        let _ = fandhe_container_supervisor::stderr_sink::stderr()
            .emit_and_wait(line, std::time::Duration::from_secs(1));
    }
    std::process::ExitCode::from(err.exit_code().get())
}
