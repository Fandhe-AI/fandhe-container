//! supervisor の bin の入口（TASK-157 追補・#1717・SUP-1・CLI-1）。
//!
//! CLI（#1718）が固定のインストール先から起動する。argv と結果チャネル（stdout の pipe）の契約は
//! [`fandhe_container_supervisor::start_contract`]、処理順は `start_entry` を参照。本ファイルは薄い入口だけを持つ。
//! Linux 以外は supervisor の本体（状態ストア・cgroup）が無いため `UNIMPLEMENTED` を stderr に出して終わる（CLI-1）。

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    fandhe_container_supervisor::start_entry::run_main(std::env::args_os().skip(1))
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
    let _ = err.write_json_line(&mut std::io::stderr());
    std::process::ExitCode::from(err.exit_code().get())
}
