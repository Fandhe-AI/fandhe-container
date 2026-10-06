//! fandhe-container-plugin-windows バイナリの入口（薄いラッパー。ロジックは lib 側）。
//!
//! core 側 proxy（TASK-114）が spawn する別プロセス。argv / 環境変数を lib の `resolve_startup` へ渡し、
//! core が bind 済みの UDS へ `UdsStream::connect`（peer credential 検証つき。PLUG-12）で接続して
//! `frame_loop::serve` で要求を順次処理する（TASK-116.2・#393）。終了時に stderr へ 1 行 JSON
//! （英語・機械可読）を出す。
//!
//! 終了コード: 0 = 相手の正常切断でループ終了、2 = 起動設定の解決失敗、3 = 接続失敗、
//! 4 = フレームループの異常終了（転送エラー・プロトコル違反）。
//! 出力は固定文言と列挙名のみで、socket パス・引数値・環境変数値・受信データを含めない。
//! peer 認証の拒否イベントは件数のみ出す（永続的な監査ログへの配線は TASK-114 で未実装。REPAIR-3）。

use std::process::ExitCode;
use std::time::Duration;

use fandhe_container_plugin::{JsonLinesPeerAuthObserver, PluginError, UdsStream};
use fandhe_container_plugin_windows::frame_loop::{UnimplementedHandler, serve};
use fandhe_container_plugin_windows::{PLUGIN_SOCKET_ENV, default_socket_path, resolve_startup};

/// 接続期限（core の常駐起動期限 10 秒より短くする。REPAIR-5）。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn report(event: &str, source: Option<&str>, e: &PluginError, extra: &str) {
    let src = source
        .map(|s| format!("\"socket_source\":\"{s}\","))
        .unwrap_or_default();
    eprintln!(
        "{{\"event\":\"{event}\",{src}\"code\":\"{}\",\"message\":\"{}\"{extra}}}",
        e.code().as_str(),
        e.message()
    );
}

fn main() -> ExitCode {
    let args = std::env::args_os().skip(1);
    let env_socket = std::env::var_os(PLUGIN_SOCKET_ENV);
    let cfg = match resolve_startup(args, env_socket, default_socket_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            report("plugin.startup", None, &e, "");
            return ExitCode::from(2);
        }
    };
    let source = cfg.socket_source().as_str();
    let mut observer = JsonLinesPeerAuthObserver::new();
    let mut stream = match UdsStream::connect(cfg.socket_path(), CONNECT_TIMEOUT, &mut observer) {
        Ok(s) => s,
        Err(e) => {
            // 拒否イベント行は socket パスを含むため転記せず、件数のみ出す。
            let extra = format!(",\"peer_auth_rejections\":{}", observer.len());
            report("plugin.connect", Some(source), &e, &extra);
            return ExitCode::from(3);
        }
    };
    match serve(&mut stream, &mut UnimplementedHandler) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            report("plugin.frame_loop", Some(source), &e, "");
            ExitCode::from(4)
        }
    }
}
