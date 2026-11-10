//! `fandhe-container-plugin-microvm` バイナリの入口（TASK-117.1・#710。PLUG-1・PLUG-12・MVM-1）。
//!
//! 呼び出し元: core 側 plugin proxy（#1869 の設計）が検証済みの起動対象経由で spawn し、`env_clear()` 後に
//! `PLUGIN_SOCKET_ENV` のみ渡す想定（起動経路は未結線。lib の doc 参照）。役割は argv / 環境変数を lib の
//! `resolve_startup` へ渡し、core が bind 済みの UDS へ `UdsStream::connect`（peer credential 検証つき。PLUG-12）で
//! 接続して `frame_loop::serve_until` で要求を `adapter::MicrovmRuntimeAdapter` へ渡し、結果を終了コードへ写すこと。
//! plugin 側に bind / listen は持たない。
//!
//! 失敗時は stderr へ 1 行 `error: <CODE>: <message>`（機械可読な code と固定文言。REPAIR-4）を出す。
//! 終了コード: 0 = 相手の正常切断、1 = その他の起動失敗、2 = `InvalidArgument`（起動引数・パス）、
//! 3 = 接続失敗（別 UID の listener による `PERMISSION_DENIED` を含む）、4 = フレームループの異常終了、
//! 5 = 正常終了要因（切断・SIGTERM）だったが VM の停止が回収しきれなかった（`failed`・`remaining`・`detached` のいずれかが 0 超）。
//! 出力は固定文言と列挙名のみで、socket パス・引数値・環境変数値・受信データ・peer 拒否イベント行を含めない。
//! 終了時は実行中の microVM を `stop_all` で期限つきに止める（TASK-117.2・#711）。
//!
//! # SIGTERM でのシャットダウン（#3747。PLUG-1・REPAIR-3・REPAIR-5）
//! 接続前に `sys::install_sigterm_flag` でフラグを登録する（失敗は終了コード 1 の fail-closed。VM を止められない
//! 状態で動かさない）。SIGTERM を受けると `serve_until` が次の受信境界で抜け、stderr に
//! `level=info op=plugin.microvm.shutdown reason=signal` を出し、`stop_all` で止めて結果行
//! （`stopped=` / `failed=` / `remaining=` / `detached=`。件数を持つ backend のときは末尾に ` ignored=` / ` unbind_failed=` / ` unmap_failures=` / ` vm_unmap_failures=` の合算も付く。#4438・#4455）を出して終わる。終了までの時間が最大で
//! `IDLE_POLL`（1 秒）と `STOP_ALL_BUDGET`（4 秒）の和になるのはアイドル時だけ。`serve_until` は受信途中の
//! フレームを中断せず（`FRAME_DEADLINE` 10 秒）、処理中の要求とその応答送信の待ちも加わるため、処理中に
//! SIGTERM を受けると 5 秒を超えうる。呼び出し側（core）の猶予を超えた場合は SIGKILL され VM が残りうる（残余）。
//! 通常 stop が期限切れで切り離された VM（`detached`）は回収未確認なので、結果行に出し終了コード 5 にする。
//! SIGINT・SIGHUP は対象外。core 自身の終了要求は SIGTERM ではなく接続切断（EOF）で伝わる。
//! Linux・macOS 以外（Windows 等）では `install_sigterm_flag` が何も登録せず、決して立たないフラグを `Ok` で返すので、
//! `serve_until` は `serve` と同じく EOF でだけ終わる。Windows には SIGTERM の経路が無く（コンソール制御ハンドラは
//! 未実装。REPAIR-3）、非 unix では接続そのものが `Unimplemented` で終了コード 3 の fail-closed になる。

use std::process::ExitCode;
use std::time::Duration;

use fandhe_container_plugin::{JsonLinesPeerAuthObserver, PluginError, PluginErrorCode, UdsStream};
use fandhe_container_plugin_microvm::adapter::{
    MicrovmRuntimeAdapter, STOP_ALL_BUDGET, default_backend,
};
use fandhe_container_plugin_microvm::frame_loop::{LoopExit, serve_until};
use fandhe_container_plugin_microvm::sys::install_sigterm_flag;
use fandhe_container_plugin_microvm::{PLUGIN_SOCKET_ENV, default_socket_path, resolve_startup};

/// `InvalidArgument` の終了コード。
const EXIT_INVALID_ARGUMENT: u8 = 2;
/// その他の起動失敗の終了コード。
const EXIT_FAILURE: u8 = 1;
/// 接続失敗の終了コード。
const EXIT_CONNECT_FAILED: u8 = 3;
/// フレームループ異常終了の終了コード。
const EXIT_LOOP_FAILED: u8 = 4;
/// 切断・SIGTERM で終わったが VM の停止が回収しきれなかった（`failed` / `remaining` > 0）終了コード。
const EXIT_CLEANUP_INCOMPLETE: u8 = 5;

/// 接続期限（core の常駐起動期限より短くする。REPAIR-5）。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn report(e: &PluginError) {
    eprintln!("error: {}: {}", e.code().as_str(), e.message());
}

fn main() -> ExitCode {
    let args = std::env::args_os().skip(1);
    let env_socket = std::env::var_os(PLUGIN_SOCKET_ENV);
    let cfg = match resolve_startup(args, env_socket, default_socket_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            report(&e);
            return if e.code() == PluginErrorCode::InvalidArgument {
                ExitCode::from(EXIT_INVALID_ARGUMENT)
            } else {
                ExitCode::from(EXIT_FAILURE)
            };
        }
    };
    // 接続前に登録する（登録失敗・未確認アーキテクチャは VM を止められないため fail-closed。#3747）。
    let stop = match install_sigterm_flag() {
        Ok(flag) => flag,
        Err(e) => {
            report(&e);
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    let mut observer = JsonLinesPeerAuthObserver::new();
    let mut stream = match UdsStream::connect(cfg.socket_path(), CONNECT_TIMEOUT, &mut observer) {
        Ok(s) => s,
        Err(e) => {
            // 拒否イベント行は socket パスを含むため転記しない。
            report(&e);
            return ExitCode::from(EXIT_CONNECT_FAILED);
        }
    };
    let mut adapter = MicrovmRuntimeAdapter::new(default_backend());
    let outcome = serve_until(&mut stream, &mut adapter, stop);
    let shutdown = matches!(outcome, Ok(LoopExit::ShutdownRequested));
    if shutdown {
        eprintln!("level=info op=plugin.microvm.shutdown reason=signal");
    }
    // 終了時に実行中 VM を期限つきで止める（drop 任せだと 1 台あたり最大 5 秒待つため。REPAIR-5）。
    let stop_report = adapter.stop_all(STOP_ALL_BUDGET);
    let detached = adapter.detached();
    let incomplete = stop_report.is_incomplete(detached);
    // シャットダウンでは結果を常に出す。切断・異常終了では回収しきれないときだけ出す。
    if shutdown || incomplete {
        eprintln!("{}", stop_report.result_line(detached));
    }
    match outcome {
        Ok(LoopExit::PeerClosed | LoopExit::ShutdownRequested) => {
            if incomplete {
                eprintln!("error: INTERNAL: failed to stop remaining VMs");
                ExitCode::from(EXIT_CLEANUP_INCOMPLETE)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            report(&e);
            ExitCode::from(EXIT_LOOP_FAILED)
        }
        // `LoopExit` は non_exhaustive のため将来の要因は成功扱いにせず異常終了にする。
        Ok(_) => ExitCode::from(EXIT_LOOP_FAILED),
    }
}
