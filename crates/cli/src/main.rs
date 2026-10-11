//! バイナリ `fandhe-container` の入口（薄いラッパー。ロジックは lib 側の `fandhe_container_cli::commands`。TASK-79.1・TASK-79.2.1・CLI-1・MS-6）。
//!
//! 終了コードは core の ERR-2 表に従う: 0 は成功（出力なし。`list` のみ stdout へ一覧を出す）、2 は使い方エラー・不正引数、
//! 3 は対象なし、8 は未実装など。
//! `setup`（CLI-2）は OS 固有設定の要求ステップを stdout へ出す（Linux は要求なしで 0・出力なし）。本番の launcher が未提供のため `start` は成功せず 8 を返す。
//! unix では起動時に SIGINT・SIGTERM・SIGHUP のハンドラを登録し、起動中の plugin へ転送してから終了する（#1513・PLUG-7）。
//! 失敗時は stderr へ英語 1 行 JSON（`code` / `message`。core 由来は `op` も）を出す。
//! 終了時に、plugin の後始末の失敗のうち `Drop` で即時に書けなかった記録（`fandhe_container_plugin::take_pending_child_cleanup_failures`）を
//! コマンド結果の行の後に stderr へ 1 行ずつ出す。記録であって失敗の判定ではないため終了コードは変えない（#1673・REPAIR-4・PLUG-7）。

use std::process::ExitCode;
use std::time::Duration;

/// 終了時に延期した診断を stderr へ出す待ちの上限（REPAIR-5）。
const DEFERRED_REPORT_TIMEOUT: Duration = Duration::from_secs(2);

fn main() -> ExitCode {
    // 親が受けたシグナルを起動中の plugin へ転送する（登録に失敗したら fail-closed で終了する）。
    #[cfg(unix)]
    if let Err(e) = fandhe_container_cli::signals::install_signal_forwarding() {
        let _ = e.write_stderr(&mut std::io::stderr());
        return ExitCode::from(e.exit_code().get());
    }
    let exit = fandhe_container_cli::commands::run(std::env::args_os().skip(1));
    // stderr 書き込み失敗では panic せず、終了コードは書き込みの成否に依存させない。
    let _ = exit.write_stderr(&mut std::io::stderr());
    // `ChildGuard` の `Drop` で書けなかった後始末の失敗記録を stderr へ出す。終了コードには影響させない。
    // stderr が満杯の pipe / socket だと write が永久にブロックし得るため、別スレッドで書いて有限の期限で待つ（REPAIR-5）。
    // 期限内に終わらなければスレッドを置き去りにして終了する（main の return でプロセスごと破棄される）。
    let pending = fandhe_container_plugin::take_pending_child_cleanup_failures();
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("deferred-report".to_string())
        .spawn(move || {
            let _ = pending.write_json_lines(&mut std::io::stderr());
            let _ = tx.send(());
        });
    if spawned.is_ok() {
        let _ = rx.recv_timeout(DEFERRED_REPORT_TIMEOUT);
    }
    ExitCode::from(exit.exit_code())
}
