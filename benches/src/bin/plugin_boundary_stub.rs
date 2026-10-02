//! macOS cold start 上乗せ計測（TASK-113.4・PLUG-6）用の子プロセス。
//!
//! 役割: 計測側（`macos_cold_start`）が起動する plugin 役（`--plugin-serve <sock>`）の
//! 1 モードだけを持つ。それ以外の引数は拒否する。
//! 起動は `CARGO_BIN_EXE_*` の絶対パスのみ（PATH 探索なし）。模擬制御コアであり実バックエンドではない（REPAIR-3）。

use std::process::ExitCode;

#[cfg(unix)]
fn run(args: &[String]) -> Result<(), String> {
    use fandhe_container_benches::macos_cold_start::{ARG_PLUGIN_SERVE, serve_plugin_socket};
    let [flag, socket] = args else {
        return Err("expected exactly: <mode> <socket>".to_string());
    };
    let path = std::path::Path::new(socket);
    let r = match flag.as_str() {
        ARG_PLUGIN_SERVE => serve_plugin_socket(path),
        _ => return Err("unrecognized mode".to_string()),
    };
    r.map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn run(_args: &[String]) -> Result<(), String> {
    Err("unsupported-platform: UDS transport is unavailable on this platform".to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
