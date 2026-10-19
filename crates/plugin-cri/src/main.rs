//! `fandhe-container-plugin-cri` バイナリの入口（TASK-114.1・#457。PLUG-1・CRI-2）。
//!
//! 呼び出し元: 将来は core 側 plugin proxy（#1869 の設計。承認待ち）が検証済みの起動対象として spawn する。
//! 役割は起動引数の解析（`startup::parse_args`）を終了コードと stderr の 1 行へ写すこと。
//! 実装の組み立て口は `adapter`（TASK-114.2・#458）にあるが、サーバーの起動と境界越しの接続は未実装（TASK-114.3・#459 以降）のため、
//! 引数なしの起動は `UNIMPLEMENTED` で失敗させ、成功終了で実装済みを装わない（REPAIR-3）。
//! socket・環境変数には触れない。
//!
//! 終了コード: 0 = `--help`、2 = `InvalidArgument`（plugin-macos / plugin-mcp と同じ値）、1 = 未実装。
//! 失敗時は stderr へ 1 行 `error: <CODE>: <message>`（固定文言のみ。引数の値は含めない。REPAIR-4）。
//! stdout に書くのは `--help` の usage だけ。

use std::process::ExitCode;

use fandhe_container_plugin::PluginErrorCode;
use fandhe_container_plugin_cri::startup::{self, Invocation};

/// `InvalidArgument` の終了コード。
const EXIT_INVALID_ARGUMENT: u8 = 2;
/// 未実装・その他の起動失敗の終了コード。
const EXIT_UNIMPLEMENTED: u8 = 1;

fn main() -> ExitCode {
    match startup::parse_args(std::env::args_os().skip(1)) {
        Ok(Invocation::Help) => {
            print!("{}", startup::usage());
            ExitCode::SUCCESS
        }
        Ok(_) => {
            // `Run` と、将来足される値は成功扱いにしない。
            eprintln!(
                "error: {}: {}",
                PluginErrorCode::Unimplemented.as_str(),
                startup::MSG_NOT_IMPLEMENTED
            );
            ExitCode::from(EXIT_UNIMPLEMENTED)
        }
        Err(e) => {
            eprintln!("error: {}: {}", e.code().as_str(), e.message());
            if e.code() == PluginErrorCode::InvalidArgument {
                ExitCode::from(EXIT_INVALID_ARGUMENT)
            } else {
                ExitCode::from(EXIT_UNIMPLEMENTED)
            }
        }
    }
}
