//! fandhe-container-plugin-windows バイナリの入口（薄いラッパー。ロジックは lib 側）。
//!
//! core 側 proxy（TASK-114）が spawn する別プロセス。argv / 環境変数を lib の
//! `resolve_startup` へ渡し、結果を stderr へ 1 行 JSON（英語・機械可読）で出して終了する。
//! 終了コード: 2 = 起動設定の解決失敗、1 = 解決成功だが送受信ループ未実装（UNIMPLEMENTED）。
//! フレームループは #393 で実装予定で、現状は実装済みを装わず即終了する（REPAIR-3・TASK-116）。
//! 出力は固定文字列と列挙名のみで、socket パス・引数値・環境変数値を含めない。

use std::process::ExitCode;

use fandhe_container_plugin_windows::{PLUGIN_SOCKET_ENV, default_socket_path, resolve_startup};

fn main() -> ExitCode {
    let args = std::env::args_os().skip(1);
    let env_socket = std::env::var_os(PLUGIN_SOCKET_ENV);
    match resolve_startup(args, env_socket, default_socket_path) {
        Ok(cfg) => {
            eprintln!(
                "{{\"event\":\"plugin.startup\",\"socket_source\":\"{}\",\"code\":\"UNIMPLEMENTED\",\"message\":\"plugin frame loop is not implemented yet\"}}",
                cfg.socket_source().as_str()
            );
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!(
                "{{\"event\":\"plugin.startup\",\"code\":\"{}\",\"message\":\"{}\"}}",
                e.code().as_str(),
                e.message()
            );
            ExitCode::from(2)
        }
    }
}
