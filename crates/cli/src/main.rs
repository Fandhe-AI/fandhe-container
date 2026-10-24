//! バイナリ `fandhe-container` の入口（薄いラッパー。ロジックは lib 側の `fandhe_container_cli::commands`。TASK-79.1・TASK-79.2.1・CLI-1・MS-6）。
//!
//! 終了コードは core の ERR-2 表に従う: 0 は成功（出力なし。`list` と `image ls` / `system df` / `image rm` / `image tag` のみ stdout へ表を出す）、2 は使い方エラー・不正引数、
//! 3 は対象なし、8 は未実装など。
//! `setup`（CLI-2）は OS 固有設定の要求ステップを stdout へ出す（Linux は rootful のときだけ要る特権ランチャーのインストール手順を 1 行表示して 0。表示のみで実行しない。#1454・#1722）。`start` は同じディレクトリの supervisor を起動して結果を受け取る（#1718）。supervisor は core の本番 launcher で起動する（実体の隣に `fandhe-container-launcher` があれば rootful のインストールとしてランチャー経由〔#2442〕。uid 0 の起動は `UNIMPLEMENTED`（8））。
//! unix では起動時に SIGINT・SIGTERM・SIGHUP のハンドラを登録し、起動中の plugin へ転送してから終了する（#1513・PLUG-7）。
//! 失敗時は stderr へ英語 1 行 JSON（`code` / `message`。core 由来は `op` も）を出す。
//! 終了時に、plugin の後始末の失敗のうち `Drop` で即時に書けなかった記録（`fandhe_container_plugin::take_pending_child_cleanup_failures`）を
//! コマンド結果の行の後に stderr へ 1 行ずつ出す。記録であって失敗の判定ではないため終了コードは変えない（#1673・REPAIR-4・PLUG-7）。

use std::process::ExitCode;
use std::time::Duration;

/// 終了時に延期した診断を stderr へ出す待ちの上限（REPAIR-5）。
const DEFERRED_REPORT_TIMEOUT: Duration = Duration::from_secs(2);

fn main() -> ExitCode {
    // 親が受けたシグナルを起動中の plugin へ転送する。登録に失敗したらコマンドを実行せず（fail-closed）、
    // その失敗もコマンド結果と同じ期限付きの出力経路へ流す（main で無期限に書かない。REPAIR-5・#1778）。
    #[cfg(unix)]
    let exit = match fandhe_container_cli::signals::install_signal_forwarding() {
        Ok(()) => fandhe_container_cli::commands::run(std::env::args_os().skip(1)),
        Err(e) => fandhe_container_cli::commands::CliExit::Error(e),
    };
    #[cfg(not(unix))]
    let exit = fandhe_container_cli::commands::run(std::env::args_os().skip(1));
    let code = exit.exit_code();
    let mut pending = fandhe_container_plugin::take_pending_child_cleanup_failures();
    // `Drop` の即時書き込みが途中で切れた断片が stderr に残っていれば、結果の JSON が連結しないよう
    // 結果の前に改行で分離する（#1673）。
    let partial = pending.take_partial_write_mark();
    // 断片分離の改行・コマンド結果・延期した後始末の記録は、順序を保ったまま 1 つの別スレッドで書く。
    // stderr が満杯の pipe / socket だと write が永久にブロックし得るため、main ではブロックし得る書き込みを
    // 一切せず有限の期限で待つ（REPAIR-5。スレッドを起動できないときの縮退出力もブロックしない 1 回の書き込みに限る）。期限内に終わらなければスレッドを置き去りにして終了する
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
        write_stderr_fallback,
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
/// 延期した記録は諦め、`fallback` を呼び出し元のスレッドで実行する。`fallback` はブロックし得る書き込みを
/// してはならない（本番の [`write_stderr_fallback`] は、ブロックしないと保証できる場合にだけ 1 回書く。
/// #1673・REPAIR-4・REPAIR-5）。
fn report_deferred<T: Send + 'static>(
    pending: T,
    timeout: Duration,
    spawn: Spawner,
    write: fn(&T),
    fallback: fn(&T),
) {
    let (tx, rx) = std::sync::mpsc::channel();
    // 起動失敗時に呼び出し元へ値を戻せるよう、スレッドとは共有スロット経由で受け渡す。
    let slot = std::sync::Arc::new(std::sync::Mutex::new(Some(pending)));
    let job_slot = std::sync::Arc::clone(&slot);
    let job: Box<dyn FnOnce() + Send> = Box::new(move || {
        let taken = job_slot.lock().ok().and_then(|mut g| g.take());
        if let Some(p) = taken {
            write(&p);
        }
        let _ = tx.send(());
    });
    if spawn(job).is_ok() {
        let _ = rx.recv_timeout(timeout);
    } else if let Some(p) = slot.lock().ok().and_then(|mut g| g.take()) {
        fallback(&p);
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

/// スレッドを起動できなかったときの縮退出力（main スレッドで呼ばれる）。延期した記録は出さず、断片分離の改行と
/// コマンド結果（`code` / `message`）だけを、ブロックしないと保証できる場合にだけ 1 回で書く（#1673・REPAIR-5）。
///
/// 期限付きスレッドが無いため、通常の `write_all` は満杯の pipe / socket で無期限に止まり得る。そこで
/// `fandhe_container_plugin::write_stderr_nonblocking` で 1 回だけ書く。OS ごとの保証:
/// - Linux（x86_64 / aarch64）で stderr が AF_UNIX socket: `send(MSG_DONTWAIT | MSG_NOSIGNAL)` 1 回。満杯なら
///   `WouldBlock` で即座に戻る。一部だけ書けても再試行しない（この後に stderr へ書くものは無いため、切れた行が
///   後続の行と連結することはない）
/// - それ以外（pipe・端末・通常ファイル、macOS、Windows）: 待たない手段が無いため書かない。この縮退経路では
///   ERR 系の構造化エラーは失われ、終了コードだけが残る（無期限に止まらないこと〔REPAIR-5〕を優先する）
fn write_stderr_fallback(r: &Report) {
    let bytes = fallback_bytes(r.partial, &r.exit);
    if !bytes.is_empty() {
        let _ = fandhe_container_plugin::write_stderr_nonblocking(&bytes);
    }
}

/// 縮退出力の内容（断片分離の改行・コマンド結果の順）を 1 つのバッファへ組み立てる（1 回の書き込みで出すため）。
fn fallback_bytes(partial: bool, exit: &fandhe_container_cli::commands::CliExit) -> Vec<u8> {
    let mut buf = Vec::new();
    if partial {
        buf.push(b'\n');
    }
    let _ = exit.write_stderr(&mut buf);
    buf
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

    static FALLBACK: AtomicUsize = AtomicUsize::new(0);

    #[allow(clippy::ptr_arg)]
    fn count_fallback(s: &Vec<u8>) {
        FALLBACK.fetch_add(s.len(), Ordering::SeqCst);
    }

    /// スレッド起動失敗では延期した記録は書かず、コマンド結果の縮退出力を呼び出し元で実行して即座に戻る
    /// （構造化エラーを捨てない。#1673・REPAIR-5）。
    #[test]
    fn spawn_failure_runs_fallback_and_skips_deferred_write() {
        WRITTEN.store(0, Ordering::SeqCst);
        FALLBACK.store(0, Ordering::SeqCst);
        report_deferred(
            b"record".to_vec(),
            Duration::from_secs(1),
            fail_spawn,
            count,
            count_fallback,
        );
        assert_eq!(WRITTEN.load(Ordering::SeqCst), 0);
        assert_eq!(FALLBACK.load(Ordering::SeqCst), 6);
    }

    static RELEASE_BLOCKED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    static BLOCKED_ENTERED: AtomicUsize = AtomicUsize::new(0);
    static BLOCKED_FALLBACK: AtomicUsize = AtomicUsize::new(0);

    /// 読み手が読まない stderr への書き込みの模擬: 解放されるまで戻らない（試験の終わりに解放する）。
    #[allow(clippy::ptr_arg)] // `count` と同じ理由（`fn(&Vec<u8>)` の関数ポインタ型に合わせる）
    fn block_until_released(_s: &Vec<u8>) {
        BLOCKED_ENTERED.fetch_add(1, Ordering::SeqCst);
        while !RELEASE_BLOCKED.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[allow(clippy::ptr_arg)] // `count` と同じ理由
    fn count_blocked_fallback(s: &Vec<u8>) {
        BLOCKED_FALLBACK.fetch_add(s.len(), Ordering::SeqCst);
    }

    /// 起動に成功した出力スレッドが書き込みで止まっても、`recv_timeout` の期限で呼び出し元へ戻り、縮退出力も
    /// 呼ばない（スレッドは置き去りにする。#1673・REPAIR-5）。
    #[test]
    fn blocked_writer_returns_after_timeout_without_fallback() {
        let timeout = Duration::from_millis(300);
        let start = std::time::Instant::now();
        report_deferred(
            b"record".to_vec(),
            timeout,
            spawn_thread,
            block_until_released,
            count_blocked_fallback,
        );
        let elapsed = start.elapsed();
        let entered = BLOCKED_ENTERED.load(Ordering::SeqCst);
        RELEASE_BLOCKED.store(true, Ordering::SeqCst);
        assert_eq!(entered, 1);
        assert!(
            elapsed >= timeout,
            "returned before the timeout: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "did not return in time: {elapsed:?}"
        );
        assert_eq!(BLOCKED_FALLBACK.load(Ordering::SeqCst), 0);
    }

    /// 縮退出力は断片分離の改行・コマンド結果の順で 1 つのバッファにまとまる（1 回の非ブロッキング書き込みで出す。
    /// 成功かつ断片なしなら空で、何も書かない。#1673・REPAIR-5・ERR-1）。
    #[test]
    fn fallback_bytes_orders_separator_before_result_in_one_buffer() {
        use fandhe_container_cli::commands::CliExit;
        assert_eq!(fallback_bytes(false, &CliExit::Success), b"");
        assert_eq!(fallback_bytes(true, &CliExit::Success), b"\n");
        let usage = fandhe_container_cli::commands::run(Vec::<std::ffi::OsString>::new());
        let mut line = Vec::new();
        usage.write_stderr(&mut line).unwrap();
        assert_eq!(fallback_bytes(false, &usage), line);
        let mut expected = b"\n".to_vec();
        expected.extend_from_slice(&line);
        assert_eq!(fallback_bytes(true, &usage), expected);
        assert_eq!(
            String::from_utf8(line).unwrap(),
            "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"usage: fandhe-container <create|start|stop|delete|list|logs|exec|image|system|setup|doctor>\"}\n"
        );
    }
}
