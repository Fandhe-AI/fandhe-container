//! `fandhe-container-plugin-macos` バイナリの入口（TASK-115.1・#385・MAC-1・PLUG-1）。
//!
//! 呼び出し元: core 側 plugin proxy（TASK-114）の `OneShotPlugin` / `ResidentPlugin` が絶対パスで spawn し、
//! `env_clear()` 後に `PLUGIN_SOCKET_ENV` のみ渡す（stdin / stdout は null、stderr は専用ソケット）。
//! 役割は起動引数の解析と socket パス解決を `startup::run` へ委ね、結果を終了コードへ写すことだけ。
//! 送受信ループは未実装（TASK-115.2）のため、パス解決後は `UNIMPLEMENTED` で非ゼロ終了する（REPAIR-3）。
//!
//! 失敗時は stderr へ 1 行 `error: <CODE>: <message>`（機械可読な code と固定文言。REPAIR-4）を出す。
//! 終了コード: `InvalidArgument` は 2、それ以外の失敗は 1。

use std::process::ExitCode;

use fandhe_container_plugin::PluginErrorCode;
use fandhe_container_plugin_macos::startup::{self, RunOutcome};

/// `InvalidArgument` の終了コード。
const EXIT_INVALID_ARGUMENT: u8 = 2;
/// その他の失敗の終了コード。
const EXIT_FAILURE: u8 = 1;

fn main() -> ExitCode {
    match startup::run(std::env::args_os().skip(1)) {
        Ok(RunOutcome::HelpPrinted) => {
            print!("{}", startup::usage());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {}: {}", e.code().as_str(), e.message());
            if e.code() == PluginErrorCode::InvalidArgument {
                ExitCode::from(EXIT_INVALID_ARGUMENT)
            } else {
                ExitCode::from(EXIT_FAILURE)
            }
        }
    }
}
