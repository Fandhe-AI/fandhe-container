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
    let code = exit.exit_code();
    let mut pending = fandhe_container_plugin::take_pending_child_cleanup_failures();
    // `Drop` の即時書き込みが途中で切れた断片が stderr に残っていれば、結果の JSON が連結しないよう
    // 結果の前に改行で分離する（#1673）。
    let partial = pending.take_partial_write_mark();
    // 断片分離の改行・コマンド結果・延期した後始末の記録は、順序を保ったまま 1 つの別スレッドで書く。
    // stderr が満杯の pipe / socket だと write が永久にブロックし得るため、main では一切 stderr へ書かず
    // 有限の期限で待つ（REPAIR-5）。期限内に終わらなければスレッドを置き去りにして終了する
    // （main の return でプロセスごと破棄される）。終了コードは書き込みの成否に依存させない。
    report_deferred(
        Report {
            partial,
            exit,
            pending,
        },
        DEFERRED_REPORT_TIMEOUT,
        spawn_thread,
        write_stderr,
    );
    ExitCode::from(code)
}

/// スレッドを起動する関数（テストで失敗を注入するため差し替え可能にする）。
type Spawner = fn(Box<dyn FnOnce() + Send>) -> std::io::Result<()>;

fn spawn_thread(job: Box<dyn FnOnce() + Send>) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("deferred-report".to_string())
        .spawn(job)
        .map(|_| ())
}

/// 延期した記録を `write` で出す。別スレッドで書き有限の期限で待つ。スレッド起動に失敗したら
/// 呼び出し元のスレッドでは書かず記録を諦める（満杯の pipe / socket で無期限にブロックし得るため。
/// 診断は記録であり、期限内の終了を優先する。#1673・REPAIR-4・REPAIR-5）。
fn report_deferred<T: Send + 'static>(
    pending: T,
    timeout: Duration,
    spawn: Spawner,
    write: fn(&T),
) {
    let (tx, rx) = std::sync::mpsc::channel();
    let job: Box<dyn FnOnce() + Send> = Box::new(move || {
        write(&pending);
        let _ = tx.send(());
    });
    if spawn(job).is_ok() {
        let _ = rx.recv_timeout(timeout);
    }
}

/// 終了時に stderr へ出す内容一式（改行・結果・延期した記録の順）。
struct Report {
    partial: bool,
    exit: fandhe_container_cli::commands::CliExit,
    pending: fandhe_container_plugin::PendingChildCleanup,
}

fn write_stderr(r: &Report) {
    let mut err = std::io::stderr();
    if r.partial {
        let _ = std::io::Write::write_all(&mut err, b"\n");
    }
    let _ = r.exit.write_stderr(&mut err);
    let _ = r.pending.write_json_lines(&mut err);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static WRITTEN: AtomicUsize = AtomicUsize::new(0);

    fn fail_spawn(_job: Box<dyn FnOnce() + Send>) -> std::io::Result<()> {
        Err(std::io::Error::other("injected spawn failure"))
    }

    // `report_deferred` の `write: fn(&T)` に `T = Vec<u8>` で渡すため、引数型は `&Vec<u8>` でなければならず
    // `&[u8]` へ変えると関数ポインタの型が合わない。clippy::ptr_arg の提案には従えない。
    #[allow(clippy::ptr_arg)]
    fn count(s: &Vec<u8>) {
        WRITTEN.fetch_add(s.len(), Ordering::SeqCst);
    }

    /// スレッド起動失敗では呼び出し元で書かず（無期限ブロックの回避）、即座に戻る（#1673・REPAIR-5）。
    #[test]
    fn spawn_failure_skips_write_and_returns() {
        WRITTEN.store(0, Ordering::SeqCst);
        report_deferred(
            b"record".to_vec(),
            Duration::from_secs(1),
            fail_spawn,
            count,
        );
        assert_eq!(WRITTEN.load(Ordering::SeqCst), 0);
    }
}
