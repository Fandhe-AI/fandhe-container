//! fandhe-container-plugin-windows バイナリの入口（薄いラッパー。ロジックは lib 側）。
//!
//! core 側 proxy（TASK-114）が spawn する別プロセス。argv / 環境変数を lib の `resolve_startup` へ渡し、
//! core が bind 済みの UDS へ `UdsStream::connect`（peer credential 検証つき。PLUG-12）で接続して
//! `frame_loop::serve` で要求を `adapter::WindowsRuntimeAdapter` へ渡して順次処理する
//! （TASK-116.2・#393、TASK-116.3・#394）。終了時に stderr へ 1 行 JSON
//! （英語・機械可読）を出す。
//!
//! serve 終了後（正常切断・異常終了とも）に `release_all` で保持中の共有マウントを解除し、件数を出す（WIN-2）。
//! 実行場所は Windows ホスト（`wsl.exe` を起動できる側）の前提。非 Windows では create が `UNIMPLEMENTED`。
//!
//! 終了コード: 0 = 相手の正常切断または SIGTERM でループ終了、1 = SIGTERM ハンドラの登録失敗（TASK-116.5・#396）、2 = 起動設定の解決失敗、3 = 接続失敗、
//! 4 = フレームループの異常終了（転送エラー・プロトコル違反）、5 = 共有マウントの解除失敗が残った
//! （serve の結果に関わらず優先。`plugin.cleanup` は `remaining` の件数のみを出す）。終了後に残った
//! マウントを本 plugin から回収する手段は未実装で、対象の特定に必要な情報も出力しない（プロセスを
//! またぐ回収は #1412。理由は `adapter` のモジュール doc「未実装範囲」を参照。WIN-2・REPAIR-3）。
//! SIGTERM（#396）: 次の受信境界（検知遅れは最大 `IDLE_POLL` 1 秒）でループを抜け、`plugin.shutdown` を出して
//! 上記の `release_all`（最大 `RELEASE_ALL_BUDGET` 4 秒）で共有マウントを解除してから終了する。SIGKILL・猶予超過では
//! マウントが残り得る（回収は #1412）。SIGINT / SIGHUP・Windows ホスト上の終了要求は対象外（未実装。REPAIR-3）。
//! ヘルスチェック（`ping`）は adapter が即応答する。
//! 接続経路は peer 認証つき `UdsStream::connect` のみ（TASK-116.4・#395・PLUG-12）。別 UID の listener は
//! `PERMISSION_DENIED`・終了コード 3 で fail-closed し、`peer_auth_rejections` に件数のみ出す。
//! 出力は固定文言と列挙名のみで、socket パス・引数値・環境変数値・受信データを含めない。
//! peer 認証の拒否イベントは件数のみ出す（永続的な監査ログへの配線は TASK-114 で未実装。REPAIR-3）。

use std::process::ExitCode;
use std::time::Duration;

use fandhe_container_plugin::{JsonLinesPeerAuthObserver, PluginError, UdsStream};
use fandhe_container_plugin_windows::adapter::{
    PlatformBackend, UnimplementedGuestStart, WindowsRuntimeAdapter, stderr_line,
};
use fandhe_container_plugin_windows::frame_loop::{LoopExit, serve_until};
use fandhe_container_plugin_windows::sys::install_sigterm_flag;
use fandhe_container_plugin_windows::{PLUGIN_SOCKET_ENV, default_socket_path, resolve_startup};

/// 接続期限（core の常駐起動期限 10 秒より短くする。REPAIR-5）。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn report(event: &str, source: Option<&str>, e: &PluginError, extra: &str) {
    let src = source
        .map(|s| format!("\"socket_source\":\"{s}\","))
        .unwrap_or_default();
    // 壊れた stderr で panic しない出力を使う（解除失敗の終了コード 5 を panic 終了で上書きしない）。
    stderr_line(&format!(
        "{{\"event\":\"{event}\",{src}\"code\":\"{}\",\"message\":\"{}\"{extra}}}",
        e.code().as_str(),
        e.message()
    ));
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
    // 接続前に登録して取りこぼしを避ける。解除できない状態では動かさない（fail-closed）。
    let stop = match install_sigterm_flag() {
        Ok(flag) => flag,
        Err(e) => {
            report("plugin.signal", Some(source), &e, "");
            return ExitCode::from(1);
        }
    };
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
    let mut adapter = WindowsRuntimeAdapter::new(PlatformBackend, UnimplementedGuestStart);
    let result = serve_until(&mut stream, &mut adapter, stop);
    if matches!(result, Ok(LoopExit::ShutdownRequested)) {
        // 固定の 1 行のみ（socket パス・引数・受信データを含めない）。
        stderr_line("{\"event\":\"plugin.shutdown\",\"reason\":\"signal\"}");
    }
    // EOF・異常終了のどちらでも、保持中の共有マウントの解除を試みる（WIN-2）。
    let cleanup = adapter.release_all();
    if cleanup.released + cleanup.remaining > 0 {
        stderr_line(&format!(
            "{{\"event\":\"plugin.cleanup\",\"released\":{},\"remaining\":{}}}",
            cleanup.released, cleanup.remaining
        ));
    }
    if let Err(e) = &result {
        report("plugin.frame_loop", Some(source), e, "");
    }
    // 解除失敗は成功扱いにしない（共有マウントが残り得る。特権操作の後始末・WIN-2）。
    // adapter 破棄後はプロセス内の所有情報が失われる。呼び出し元へは終了コード 5 と plugin.cleanup の
    // 件数だけが伝わり、残ったマウントの回収は未実装（#1412。REPAIR-3）。
    if cleanup.remaining > 0 {
        return ExitCode::from(5);
    }
    match result {
        Ok(LoopExit::PeerClosed | LoopExit::ShutdownRequested) => ExitCode::SUCCESS,
        // 将来追加される終了要因（non_exhaustive）を成功扱いにしない。
        Ok(_) | Err(_) => ExitCode::from(4),
    }
}
