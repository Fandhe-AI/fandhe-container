//! supervisor プロセスの stderr への構造化ログを、呼び出し側を止めずに出す共有の出口（REPAIR-4・REPAIR-5・#1717）。
//!
//! stderr の先が読み手の止まった満杯の pipe だと、`eprintln!` 等の同期書き込みは無期限に止まり、std の stderr の
//! ロックを持ったままになる。監視・回収・restart の経路がその書き込み（とロック待ち）で止まらないよう、supervisor
//! のコードから stderr へ書くのは本モジュールの専用スレッド 1 本だけにする。呼び出し側は上限つきのキューへ
//! `try_send` するだけで、満杯なら捨てる（ログの欠落は許し、処理の停止は許さない）。
//!
//! 終了前の報告（固定スキーマの JSON 1 行）など、書けたことを待ちたい行は [`StderrSink::emit_and_wait`] で期限つきで
//! 待つ。期限を超えても呼び出し側は先へ進む（専用スレッドが書き込みで止まっていても待ちは期限で終わる）。
//!
//! 専用スレッドは [`stderr`] の初回呼び出しで作る。`oci_runtime::start` より前の単一スレッド前提の区間の成功経路では
//! 出力しないこと（スレッドが増えて start の前提を壊す。`start_entry` の手順 2）。
//!
//! 呼び出し元: `start_entry` の `log_event` と終了前の報告・`run::StderrLogObserver`・`main.rs`（Linux 以外）。
//! core 側の stderr 出力（監査ログのフォールバック等）は本モジュールを通らない。

use std::io::Write;
use std::sync::OnceLock;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::Duration;

/// キューに溜められる行数の上限（読み手が止まっても無制限に溜めない）。
pub const QUEUE_CAPACITY: usize = 256;

/// キューの 1 要素。`ack` があれば書き込みの成功後に通知する。
struct Line {
    bytes: Vec<u8>,
    ack: Option<SyncSender<()>>,
}

/// 専用スレッド 1 本で書き手へ書く、待たない出口。
pub struct StderrSink {
    /// 専用スレッドを作れなかったときは `None`（以後の出力は捨てる）。
    tx: Option<SyncSender<Line>>,
}

impl StderrSink {
    /// `writer` へ書く専用スレッドを作り、`capacity` 行までのキューで包む（試験では任意の書き手を渡す）。
    pub fn spawn<W: Write + Send + 'static>(writer: W, capacity: usize) -> Self {
        let (tx, rx) = sync_channel(capacity);
        let spawned = std::thread::Builder::new()
            .name("supervisor-stderr".into())
            .spawn(move || drain(writer, rx));
        Self {
            tx: spawned.ok().map(|_| tx),
        }
    }

    /// 1 行を待たずにキューへ入れる。入れられたら `true`（満杯・スレッド無しなら捨てて `false`）。
    pub fn emit(&self, bytes: Vec<u8>) -> bool {
        self.enqueue(Line { bytes, ack: None })
    }

    /// 1 行をキューへ入れ、書けたことを `deadline` まで待つ。期限内に書けたら `true`。
    ///
    /// 先に入れた行はこの行より前に書かれる（キューは FIFO）。
    pub fn emit_and_wait(&self, bytes: Vec<u8>, deadline: Duration) -> bool {
        let (ack, done) = sync_channel(1);
        if !self.enqueue(Line {
            bytes,
            ack: Some(ack),
        }) {
            return false;
        }
        done.recv_timeout(deadline).is_ok()
    }

    /// それまでに入れた行が書かれるのを `deadline` まで待つ。期限内に書き終えたら `true`。
    pub fn flush(&self, deadline: Duration) -> bool {
        self.emit_and_wait(Vec::new(), deadline)
    }

    fn enqueue(&self, line: Line) -> bool {
        self.tx.as_ref().is_some_and(|tx| tx.try_send(line).is_ok())
    }
}

/// 専用スレッドの本体。全送り手が無くなるまで 1 行ずつ書く。
fn drain<W: Write>(mut writer: W, rx: Receiver<Line>) {
    for line in rx {
        let written = line.bytes.is_empty()
            || writer
                .write_all(&line.bytes)
                .and_then(|()| writer.flush())
                .is_ok();
        if written && let Some(ack) = line.ack {
            let _ = ack.try_send(());
        }
    }
}

static STDERR: OnceLock<StderrSink> = OnceLock::new();

/// プロセスの stderr へ書く共有の出口（初回呼び出しで専用スレッドを作る）。
pub fn stderr() -> &'static StderrSink {
    STDERR.get_or_init(|| StderrSink::spawn(std::io::stderr(), QUEUE_CAPACITY))
}

/// 共有の出口を使っていれば、それまでの行が書かれるのを `deadline` まで待つ（プロセス終了の直前に呼ぶ）。
///
/// 一度も使っていなければ何もせず `true`（終了のためだけにスレッドを作らない）。
pub fn flush_stderr(deadline: Duration) -> bool {
    STDERR.get().is_none_or(|sink| sink.flush(deadline))
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{Sender, channel};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use super::*;

    /// 解放の合図まで書き込みが戻らない書き手（読み手の止まった満杯の pipe の代わり）。
    struct StuckWriter(Receiver<()>);

    impl Write for StuckWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let _ = self.0.recv();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn stuck() -> (Sender<()>, StuckWriter) {
        let (release, rx) = channel();
        (release, StuckWriter(rx))
    }

    /// 書いた内容を共有のバッファへ溜める書き手。
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// 常に失敗する書き手（EPIPE 等の代わり）。
    struct BrokenWriter;

    impl Write for BrokenWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// REPAIR-5: 書き手が止まっても `emit` は待たずに戻り、キューの上限を超えた行は捨てる。
    #[test]
    fn repair5_emit_does_not_block_on_stuck_writer() {
        let (release, writer) = stuck();
        let sink = StderrSink::spawn(writer, 2);
        let started = Instant::now();
        let accepted = (0..10).filter(|_| sink.emit(b"x\n".to_vec())).count();
        assert!(started.elapsed() < Duration::from_secs(1));
        // 専用スレッドが止まった 1 行＋キューの 2 行まで。
        assert!((2..=3).contains(&accepted), "accepted = {accepted}");
        assert!(!sink.emit(b"y\n".to_vec()));
        drop(release);
    }

    /// REPAIR-5: 書き手が止まっていれば `emit_and_wait` は期限で `false` を返す。
    #[test]
    fn repair5_emit_and_wait_times_out_on_stuck_writer() {
        let (release, writer) = stuck();
        let sink = StderrSink::spawn(writer, 4);
        let started = Instant::now();
        assert!(!sink.emit_and_wait(b"x\n".to_vec(), Duration::from_millis(100)));
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(release);
    }

    /// REPAIR-4: 書き手が動いていれば、入れた順に書かれ、`flush` で書き終えたことを確かめられる。
    #[test]
    fn repair4_lines_are_written_in_order_and_flush_waits() {
        let buf = SharedBuf::default();
        let sink = StderrSink::spawn(buf.clone(), 8);
        assert!(sink.emit(b"a\n".to_vec()));
        assert!(sink.emit_and_wait(b"b\n".to_vec(), Duration::from_secs(5)));
        assert!(sink.emit(b"c\n".to_vec()));
        assert!(sink.flush(Duration::from_secs(5)));
        assert_eq!(buf.0.lock().unwrap().as_slice(), b"a\nb\nc\n");
    }

    /// 書き込みに失敗した行は `emit_and_wait` が期限を待たずに `false` を返す。
    #[test]
    fn repair5_emit_and_wait_reports_write_failure() {
        let sink = StderrSink::spawn(BrokenWriter, 4);
        let started = Instant::now();
        assert!(!sink.emit_and_wait(b"x\n".to_vec(), Duration::from_secs(30)));
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
