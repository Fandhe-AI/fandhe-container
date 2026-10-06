//! `fandhe-container-plugin-macos` バイナリの入口（TASK-115.1・#385、TASK-115.2・#386。MAC-1・PLUG-1）。
//!
//! 呼び出し元: core 側 plugin proxy（TASK-114）の `OneShotPlugin` / `ResidentPlugin` が絶対パスで spawn し、
//! `env_clear()` 後に `PLUGIN_SOCKET_ENV` のみ渡す（stdin / stdout は null、stderr は専用ソケット）。
//! 役割は起動引数の解析と socket パス解決を `startup::run` へ委ね、core が bind 済みの UDS へ
//! `UdsStream::connect`（peer credential 検証つき。PLUG-12）で接続し、`frame_loop::serve` で要求を
//! 順次処理して結果を終了コードへ写すこと。
//!
//! 接続経路は peer 認証つき `UdsStream::connect` のみ（TASK-115.4・#388）。別 UID の listener には
//! 1 バイトも送らず `PERMISSION_DENIED`・終了コード 3 で fail-closed する（PLUG-12）。
//!
//! 失敗時は stderr へ 1 行 `error: <CODE>: <message>`（機械可読な code と固定文言。REPAIR-4）を出す。
//! 終了コード: 0 = 正常（`--help`・相手の正常切断）、2 = `InvalidArgument`（起動引数・パス）、
//! 3 = 接続失敗、4 = フレームループの異常終了（転送エラー・プロトコル違反）、1 = その他の起動失敗。
//! 5 = 終了時に停止できなかった VM が残った。3・4 は plugin-windows と同じ値（core 側 proxy が同じ規則で扱えるようにする）。
//! 出力は固定文言と列挙名のみで、socket パス・引数値・環境変数値・受信データを含めない。
//! peer 認証の拒否イベント行は socket パスを含むため転記しない（永続的な監査ログへの配線は
//! core 側 TASK-114 で未実装。REPAIR-3・SEC-4）。
//! 要求は `adapter::MacosRuntimeAdapter`（TASK-115.3・#387）が処理し、終了時に実行中 VM を `stop_all`（総予算 `SHUTDOWN_BUDGET` 4 秒。core の 5 秒の終了猶予内に収める。REPAIR-5）で停止する。
//! 停止結果は stderr へ件数のみの 1 行 JSON（`plugin.cleanup`）で出す。

use std::process::ExitCode;
use std::time::Duration;

use fandhe_container_plugin::{JsonLinesPeerAuthObserver, PluginError, PluginErrorCode, UdsStream};
use fandhe_container_plugin_macos::adapter::{MacosRuntimeAdapter, PlatformBackend};
use fandhe_container_plugin_macos::frame_loop::serve;
use fandhe_container_plugin_macos::startup::{self, RunOutcome};

/// `InvalidArgument` の終了コード。
const EXIT_INVALID_ARGUMENT: u8 = 2;
/// その他の起動失敗の終了コード。
const EXIT_FAILURE: u8 = 1;
/// 接続失敗の終了コード。
const EXIT_CONNECT_FAILED: u8 = 3;
/// フレームループ異常終了の終了コード。
const EXIT_LOOP_FAILED: u8 = 4;
/// 終了時の停止に失敗した VM が残った場合の終了コード。
const EXIT_CLEANUP_INCOMPLETE: u8 = 5;

/// 接続期限（core の常駐起動期限より短くする。REPAIR-5）。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn report(e: &PluginError) {
    eprintln!("error: {}: {}", e.code().as_str(), e.message());
}

fn main() -> ExitCode {
    let cfg = match startup::run(std::env::args_os().skip(1)) {
        Ok(RunOutcome::HelpPrinted) => {
            print!("{}", startup::usage());
            return ExitCode::SUCCESS;
        }
        Ok(RunOutcome::Ready(cfg)) => cfg,
        Err(e) => {
            report(&e);
            return if e.code() == PluginErrorCode::InvalidArgument {
                ExitCode::from(EXIT_INVALID_ARGUMENT)
            } else {
                ExitCode::from(EXIT_FAILURE)
            };
        }
    };
    let mut observer = JsonLinesPeerAuthObserver::new();
    let mut stream = match UdsStream::connect(cfg.socket_path(), CONNECT_TIMEOUT, &mut observer) {
        Ok(s) => s,
        Err(e) => {
            report(&e);
            return ExitCode::from(EXIT_CONNECT_FAILED);
        }
    };
    let mut adapter = MacosRuntimeAdapter::new(PlatformBackend);
    let outcome = serve(&mut stream, &mut adapter);
    // Vm の Drop は停止を待たないため、正常切断・異常終了のどちらでも期限つきで明示停止する。
    let summary = adapter.stop_all();
    if summary.stopped > 0 || summary.remaining > 0 {
        eprintln!(
            "{{\"event\":\"plugin.cleanup\",\"stopped\":{},\"remaining\":{}}}",
            summary.stopped, summary.remaining
        );
    }
    match outcome {
        Err(e) => {
            report(&e);
            ExitCode::from(EXIT_LOOP_FAILED)
        }
        // 停止できなかった VM が残るなら成功扱いにしない（機械可読な code を stderr へ出す）。
        Ok(_) if summary.remaining > 0 => {
            eprintln!("error: INTERNAL: failed to stop remaining VMs");
            ExitCode::from(EXIT_CLEANUP_INCOMPLETE)
        }
        Ok(_) => ExitCode::SUCCESS,
    }
}
