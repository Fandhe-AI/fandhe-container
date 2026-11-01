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
//! 書き先は既定で fd 2 だが、[`install_stderr_writer`] で最初の [`stderr`] 呼び出しより前に差し替えられる。bin の入口は
//! 状態ルート配下のローテーションログ（[`crate::supervisor_log`]。#2067・REPAIR-4）へ差し替える。差し込みはスレッドを
//! 作らない（`start_entry` の手順 2 の単一スレッド前提を保つ）。
//!
//! 呼び出し元: `start_entry` の `log_event` と終了前の報告・`run::StderrLogObserver`・`main.rs`（Linux 以外）。
//! core 側の stderr 出力（監査ログのフォールバック等）は本モジュールを通らない。

use std::collections::VecDeque;
use std::io::Write;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Duration;

use fandhe_container_core::traits::{ErrorCode, TraitError};

/// キューに溜められる行数の上限（読み手が止まっても無制限に溜めない）。
pub const QUEUE_CAPACITY: usize = 256;

/// 出口への 1 回の依頼（`emit`・`emit_and_wait`・`flush`）の結果（REPAIR-4）。
///
/// 待つ依頼（`emit_and_wait`・`flush`）は、前回の待つ依頼より後にキューへ入った行の書き込み結果をまとめて返す
/// （キュー満杯で捨てた行は呼び出し側が `emit` の [`EmitOutcome::QueueFull`] で知るため、ここには含めない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EmitOutcome {
    /// キューへ入れた（書けたかは待たない。`emit` のみ）。
    Queued,
    /// 書き手へ書けた（待つ依頼では、前回の待つ依頼以降の行がすべて書けた）。
    Written,
    /// 書き手への書き込みが失敗した。`failed_lines` は前回の待つ依頼以降に失敗した行数（この依頼の行を含む）。
    WriteFailed {
        /// 失敗した行数（1 以上）。
        failed_lines: u64,
    },
    /// キューが満杯のため捨てた。
    QueueFull,
    /// 専用スレッドが無い（作れなかった・終了した）ため捨てた。
    WorkerUnavailable,
    /// 期限内に書き終わりを確かめられなかった（専用スレッドが書き込みで止まっている等）。
    TimedOut,
    /// 共有の出口を一度も使っていないため、待つ行が無い（[`flush_stderr`] のみ）。
    NothingQueued,
    /// 専用スレッドを一時停止中（[`StderrSink::quiesce`]）のため、待たずに戻った。行は再開（[`StderrSink::resume`]）の
    /// 後に順に書かれる（restart の再 launch の区間。#2043）。
    Quiesced,
}

impl EmitOutcome {
    /// 行が書き手まで届いた（または届けるべき行が無い）か。
    pub fn is_delivered(self) -> bool {
        matches!(self, Self::Written | Self::NothingQueued)
    }
}

/// キューの 1 要素。`ack` があれば、前回の通知以降の書き込み結果を通知する。
struct Line {
    bytes: Vec<u8>,
    ack: Option<SyncSender<EmitOutcome>>,
}

/// 専用スレッドが終了時に返す受け口。書き手と、まだ待つ依頼で通知していない書き込み失敗の行数を渡す
/// （一時停止・再開をまたいでも「前回の待つ依頼以降の失敗」を失わないため。REPAIR-4）。
type WriterReturn = Receiver<(Box<dyn Write + Send>, u64)>;

/// 専用スレッドの状態。
enum Phase {
    /// 専用スレッドが動いている。
    Running(SyncSender<Line>),
    /// 一時停止中（[`StderrSink::quiesce`] 済み）。行は `Inner::buffer` へ溜める。
    Quiesced,
    /// 専用スレッドを作れなかった（以後の出力は捨てる）。
    Unavailable,
}

struct Inner {
    phase: Phase,
    /// 動いている専用スレッドが終了時に書き手を返す受け口。
    done: Option<WriterReturn>,
    /// 一時停止で取り戻した書き手（再開で専用スレッドへ戻す）。
    writer: Option<Box<dyn Write + Send>>,
    /// 取り戻した書き手に紐づく、未通知の書き込み失敗の行数（再開した専用スレッドへ引き継ぐ）。
    carried_failed: u64,
    /// 一時停止中に溜めた行（`capacity` まで。超えた分は `QueueFull` で捨てる）。
    buffer: VecDeque<Vec<u8>>,
}

/// 専用スレッド 1 本で書き手へ書く、待たない出口。
///
/// restart の再 launch は core の本番 launcher が単一スレッド（`Threads: 1`）を要求するため、専用スレッドを
/// [`Self::quiesce`] で止めて launch し、[`Self::resume`] で再開する（#2043・SUP-3・CORE-1）。止めている間の
/// `emit` はスレッドを作らず、上限つきのバッファへ溜める。
pub struct StderrSink {
    capacity: usize,
    inner: Mutex<Inner>,
}

impl StderrSink {
    /// `writer` へ書く専用スレッドを作り、`capacity` 行までのキューで包む（試験では任意の書き手を渡す）。
    pub fn spawn<W: Write + Send + 'static>(writer: W, capacity: usize) -> Self {
        let (phase, done) = match Self::start_worker(Box::new(writer), capacity, VecDeque::new(), 0)
        {
            Some((tx, done)) => (Phase::Running(tx), Some(done)),
            None => (Phase::Unavailable, None),
        };
        Self {
            capacity,
            inner: Mutex::new(Inner {
                phase,
                done,
                writer: None,
                carried_failed: 0,
                buffer: VecDeque::new(),
            }),
        }
    }

    /// 専用スレッドを作る。`backlog` の行を先頭に書く。書き手は終了時に返す受け口へ渡す。作れなければ `None`。
    fn start_worker(
        writer: Box<dyn Write + Send>,
        capacity: usize,
        backlog: VecDeque<Vec<u8>>,
        carried_failed: u64,
    ) -> Option<(SyncSender<Line>, WriterReturn)> {
        // 再開時の溜め分の分だけ余裕を足す(溜め分で満杯にしない。上限は容量の 2 倍まで)。
        let (tx, rx) = sync_channel(capacity.saturating_add(backlog.len()));
        for bytes in backlog {
            // 容量は backlog 以上にしてあるため入る。
            tx.try_send(Line { bytes, ack: None }).ok()?;
        }
        let (done_tx, done_rx) = sync_channel(1);
        std::thread::Builder::new()
            .name("supervisor-stderr".into())
            .spawn(move || {
                let returned = drain(writer, rx, carried_failed);
                let _ = done_tx.try_send(returned);
            })
            .ok()?;
        Some((tx, done_rx))
    }

    /// 1 行を待たずにキューへ入れる。入れられたら [`EmitOutcome::Queued`]。
    pub fn emit(&self, bytes: Vec<u8>) -> EmitOutcome {
        match self.enqueue(Line { bytes, ack: None }) {
            Ok(()) => EmitOutcome::Queued,
            Err(rejected) => rejected,
        }
    }

    /// 1 行をキューへ入れ、書けたことを `deadline` まで待つ。
    ///
    /// 先に入れた行はこの行より前に書かれる（キューは FIFO）。結果は前回の待つ依頼以降の行をまとめたもの。
    /// 一時停止中は行をバッファへ溜めて待たずに [`EmitOutcome::Quiesced`] を返す。
    pub fn emit_and_wait(&self, bytes: Vec<u8>, deadline: Duration) -> EmitOutcome {
        let (ack, done) = sync_channel(1);
        if let Err(rejected) = self.enqueue(Line {
            bytes,
            ack: Some(ack),
        }) {
            return rejected;
        }
        match done.recv_timeout(deadline) {
            Ok(outcome) => outcome,
            Err(RecvTimeoutError::Timeout) => EmitOutcome::TimedOut,
            // 通知の前に専用スレッドが終わった。
            Err(RecvTimeoutError::Disconnected) => EmitOutcome::WorkerUnavailable,
        }
    }

    /// それまでに入れた行が書かれるのを `deadline` まで待つ（前回の待つ依頼以降の失敗も結果に載る）。
    pub fn flush(&self, deadline: Duration) -> EmitOutcome {
        self.emit_and_wait(Vec::new(), deadline)
    }

    fn enqueue(&self, line: Line) -> Result<(), EmitOutcome> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let capacity = self.capacity;
        match &inner.phase {
            Phase::Unavailable => Err(EmitOutcome::WorkerUnavailable),
            Phase::Running(tx) => tx.try_send(line).map_err(|e| match e {
                TrySendError::Full(_) => EmitOutcome::QueueFull,
                TrySendError::Disconnected(_) => EmitOutcome::WorkerUnavailable,
            }),
            Phase::Quiesced => {
                // 空の行（`flush`）は溜めない。
                if !line.bytes.is_empty() {
                    if inner.buffer.len() >= capacity {
                        return Err(EmitOutcome::QueueFull);
                    }
                    inner.buffer.push_back(line.bytes);
                }
                // 待つ依頼は待たずに返す（専用スレッドが無いため ack は来ない）。
                if line.ack.is_some() {
                    return Err(EmitOutcome::Quiesced);
                }
                Ok(())
            }
        }
    }

    /// 専用スレッドを止めて書き手を取り戻す（restart の再 launch の直前。#2043・SUP-3・CORE-1）。
    ///
    /// 溜まっている行を書き切らせてから送り手を閉じ、専用スレッドの終了を `deadline` まで待つ。期限内に書き手が
    /// 戻らなければ `Err`（書き込みで止まっている書き手のまま fork させない。呼び出し側は launch しない）。その場合も
    /// 以後の行はバッファへ溜め、書き手が戻っていれば [`Self::resume`] で再開できる。止めた後の `emit` はスレッドを
    /// 作らない。専用スレッドの tid が `/proc/self/task` から消えるまでの待ちは呼び出し側（`thread_settle`）が行う。
    pub fn quiesce(&self, deadline: Duration) -> Result<(), TraitError> {
        let done = {
            let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
            match std::mem::replace(&mut inner.phase, Phase::Quiesced) {
                // 送り手を閉じると、専用スレッドは溜まった行を書き切って終わる。
                Phase::Running(tx) => drop(tx),
                Phase::Quiesced => {}
                Phase::Unavailable => {
                    inner.phase = Phase::Unavailable;
                    return Ok(());
                }
            }
            if inner.writer.is_some() {
                return Ok(());
            }
            inner.done.take()
        };
        let Some(done) = done else {
            return Ok(());
        };
        match done.recv_timeout(deadline) {
            Ok((writer, failed)) => {
                let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
                inner.writer = Some(writer);
                inner.carried_failed = inner.carried_failed.saturating_add(failed);
                Ok(())
            }
            Err(RecvTimeoutError::Timeout) => {
                self.inner
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .done = Some(done);
                Err(TraitError::new(
                    ErrorCode::Timeout,
                    "stderr writer thread did not stop in time",
                ))
            }
            Err(RecvTimeoutError::Disconnected) => {
                // 書き手を返さずに専用スレッドが終わった（panic 等）。以後の出力は捨てる。
                self.inner
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .phase = Phase::Unavailable;
                Err(TraitError::new(
                    ErrorCode::Unavailable,
                    "stderr writer thread ended without returning the writer",
                ))
            }
        }
    }

    /// [`Self::quiesce`] で止めた専用スレッドを、同じ書き手で作り直す。止めている間に溜めた行を先頭から書く。
    ///
    /// 動いていれば何もしない。書き手がまだ戻っていない（`quiesce` が期限切れだった）場合は、戻っていれば取り直し、
    /// 戻っていなければ止めたまま `Err`（行は上限までバッファに残る）。
    pub fn resume(&self) -> Result<(), TraitError> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if !matches!(inner.phase, Phase::Quiesced) {
            return Ok(());
        }
        if inner.writer.is_none()
            && let Some(rx) = inner.done.as_ref()
            && let Ok((w, failed)) = rx.try_recv()
        {
            inner.writer = Some(w);
            inner.carried_failed = inner.carried_failed.saturating_add(failed);
            inner.done = None;
        }
        let Some(writer) = inner.writer.take() else {
            return Err(TraitError::new(
                ErrorCode::Unavailable,
                "stderr writer is not available to resume",
            ));
        };
        let backlog = std::mem::take(&mut inner.buffer);
        let carried = std::mem::take(&mut inner.carried_failed);
        match Self::start_worker(writer, self.capacity, backlog, carried) {
            Some((tx, done)) => {
                inner.phase = Phase::Running(tx);
                inner.done = Some(done);
                Ok(())
            }
            None => {
                inner.phase = Phase::Unavailable;
                Err(TraitError::new(
                    ErrorCode::Unavailable,
                    "failed to resume the stderr writer thread",
                ))
            }
        }
    }
}

/// 専用スレッドの本体。全送り手が無くなるまで 1 行ずつ書き、待つ依頼には前回以降の結果を返す。終了時に書き手を返す。
/// 終了時は書き手と、通知しなかった失敗の行数を返す（再開した専用スレッドが `failed_lines` の初期値にする）。
fn drain(
    mut writer: Box<dyn Write + Send>,
    rx: Receiver<Line>,
    carried_failed: u64,
) -> (Box<dyn Write + Send>, u64) {
    let mut failed_lines: u64 = carried_failed;
    for line in rx {
        let written = line.bytes.is_empty()
            || writer
                .write_all(&line.bytes)
                .and_then(|()| writer.flush())
                .is_ok();
        if !written {
            failed_lines = failed_lines.saturating_add(1);
        }
        if let Some(ack) = line.ack {
            let outcome = if failed_lines == 0 {
                EmitOutcome::Written
            } else {
                EmitOutcome::WriteFailed { failed_lines }
            };
            failed_lines = 0;
            let _ = ack.try_send(outcome);
        }
    }
    (writer, failed_lines)
}
static STDERR: OnceLock<StderrSink> = OnceLock::new();

/// 差し替える書き手の置き場。`consumed` は共有の出口の初期化が置き場を見た後を表し、以後の差し込みを拒否する
/// （初期化との競合で、差し込みが黙って失われないようにする）。
struct WriterSlot {
    writer: Option<Box<dyn Write + Send>>,
    consumed: bool,
}

static STDERR_WRITER: Mutex<WriterSlot> = Mutex::new(WriterSlot {
    writer: None,
    consumed: false,
});

/// 共有の出口の書き先を `writer` に差し替える（プロセスで 1 回だけ・最初の [`stderr`] より前に限る）。
///
/// スレッドは作らない。既に共有の出口が作られている・既に差し込み済みなら `FailedPrecondition` で拒否する
/// （黙って捨てない）。呼び出し元: `start_entry` の入口（supervisor ログの保存先。#2067・REPAIR-4）。
pub fn install_stderr_writer(writer: Box<dyn Write + Send>) -> Result<(), TraitError> {
    let mut slot = STDERR_WRITER.lock().unwrap_or_else(PoisonError::into_inner);
    if slot.consumed || slot.writer.is_some() {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "stderr writer can only be installed once before first use",
        ));
    }
    slot.writer = Some(writer);
    Ok(())
}

/// プロセスの stderr（または差し込まれた書き手）へ書く共有の出口（初回呼び出しで専用スレッドを作る）。
pub fn stderr() -> &'static StderrSink {
    STDERR.get_or_init(|| {
        let installed = {
            let mut slot = STDERR_WRITER.lock().unwrap_or_else(PoisonError::into_inner);
            slot.consumed = true;
            slot.writer.take()
        };
        match installed {
            Some(w) => StderrSink::spawn(w, QUEUE_CAPACITY),
            None => StderrSink::spawn(std::io::stderr(), QUEUE_CAPACITY),
        }
    })
}

/// 共有の出口を使っていれば、それまでの行が書かれるのを `deadline` まで待つ（プロセス終了の直前に呼ぶ）。
///
/// 一度も使っていなければ何もせず [`EmitOutcome::NothingQueued`]（終了のためだけにスレッドを作らない）。
pub fn flush_stderr(deadline: Duration) -> EmitOutcome {
    STDERR
        .get()
        .map_or(EmitOutcome::NothingQueued, |sink| sink.flush(deadline))
}

/// 共有の出口の専用スレッドを止める（restart の再 launch の直前。#2043・SUP-3・CORE-1）。
///
/// 一度も使っていなければ何もしない（止めるためだけにスレッドを作らない）。期限内に止まらなければ `Err`。
pub fn quiesce_stderr(deadline: Duration) -> Result<(), TraitError> {
    STDERR.get().map_or(Ok(()), |sink| sink.quiesce(deadline))
}

/// [`quiesce_stderr`] で止めた共有の出口を再開する（launch の成否に関わらず呼ぶ）。
pub fn resume_stderr() -> Result<(), TraitError> {
    STDERR.get().map_or(Ok(()), StderrSink::resume)
}

/// 試験用の書き手の共有部品（stderr_sink と、これを使う他モジュールの試験で使う）。
/// 「専用スレッドが書き手に入った」ことを待ってから判定する競合対策（#1970・#2538）を一箇所に置く。
#[cfg(test)]
pub(crate) mod test_support {
    use std::io::Write;
    use std::sync::mpsc::{Receiver, Sender, channel};

    /// 解放の合図まで書き込みが戻らない書き手（読み手の止まった満杯の pipe の代わり）。
    /// 書き込みに入った時点で `arrived` へ通知し、専用スレッドが止まったことをテストが確認できる（#1970）。
    pub(crate) struct StuckWriter {
        release: Receiver<()>,
        arrived: Sender<()>,
    }

    impl Write for StuckWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let _ = self.arrived.send(());
            let _ = self.release.recv();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    pub(crate) fn stuck() -> (Sender<()>, Receiver<()>, StuckWriter) {
        let (release, rx) = channel();
        let (arrived_tx, arrived) = channel();
        (
            release,
            arrived,
            StuckWriter {
                release: rx,
                arrived: arrived_tx,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use super::test_support::stuck;
    use super::*;

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

    /// REPAIR-5: 書き手が止まっても `emit` は待たずに戻り、キューの上限を超えた行は `QueueFull` で捨てる。
    /// 専用スレッドが 1 行目を取り出して書き手の中で止まるまで待ってから判定する。待たないと、
    /// 取り出し前に `emit` が終わりキューに空きができて `QueueFull` にならない競合がある（#1970）。
    #[test]
    fn repair5_emit_does_not_block_on_stuck_writer() {
        let (release, arrived, writer) = stuck();
        let sink = StderrSink::spawn(writer, 2);
        assert_eq!(sink.emit(b"x\n".to_vec()), EmitOutcome::Queued);
        arrived
            .recv_timeout(Duration::from_secs(5))
            .expect("worker thread did not reach the writer");
        // ここでキューは空で、専用スレッドは 1 行を抱えて止まっている。
        let started = Instant::now();
        let outcomes: Vec<EmitOutcome> = (0..10).map(|_| sink.emit(b"x\n".to_vec())).collect();
        assert!(started.elapsed() < Duration::from_secs(1));
        let queued = outcomes
            .iter()
            .filter(|o| **o == EmitOutcome::Queued)
            .count();
        let full = outcomes
            .iter()
            .filter(|o| **o == EmitOutcome::QueueFull)
            .count();
        // キュー容量の 2 行だけ受理し、残りは捨てる。
        assert_eq!((queued, full), (2, 8));
        assert_eq!(sink.emit(b"y\n".to_vec()), EmitOutcome::QueueFull);
        drop(release);
    }

    /// REPAIR-5: 書き手が止まっていれば `emit_and_wait` は期限で `TimedOut` を返す。
    #[test]
    fn repair5_emit_and_wait_times_out_on_stuck_writer() {
        let (release, _arrived, writer) = stuck();
        let sink = StderrSink::spawn(writer, 4);
        let started = Instant::now();
        assert_eq!(
            sink.emit_and_wait(b"x\n".to_vec(), Duration::from_millis(100)),
            EmitOutcome::TimedOut
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(release);
    }

    /// REPAIR-4: 書き手が動いていれば、入れた順に書かれ、`flush` で書き終えたことを確かめられる。
    #[test]
    fn repair4_lines_are_written_in_order_and_flush_waits() {
        let buf = SharedBuf::default();
        let sink = StderrSink::spawn(buf.clone(), 8);
        assert_eq!(sink.emit(b"a\n".to_vec()), EmitOutcome::Queued);
        assert_eq!(
            sink.emit_and_wait(b"b\n".to_vec(), Duration::from_secs(5)),
            EmitOutcome::Written
        );
        assert_eq!(sink.emit(b"c\n".to_vec()), EmitOutcome::Queued);
        assert_eq!(sink.flush(Duration::from_secs(5)), EmitOutcome::Written);
        assert_eq!(buf.0.lock().unwrap().as_slice(), b"a\nb\nc\n");
    }

    /// REPAIR-4: 書き込みに失敗した行は、待つ依頼が期限を待たずに失敗した行数つきで返す。
    #[test]
    fn repair4_emit_and_wait_reports_write_failure() {
        let sink = StderrSink::spawn(BrokenWriter, 4);
        let started = Instant::now();
        assert_eq!(
            sink.emit_and_wait(b"x\n".to_vec(), Duration::from_secs(30)),
            EmitOutcome::WriteFailed { failed_lines: 1 }
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// REPAIR-4: `flush` は前回の待つ依頼以降に `emit` で入れた行の失敗を反映し、反映後は数え直す。
    #[test]
    fn repair4_flush_reports_preceding_write_failures() {
        let sink = StderrSink::spawn(BrokenWriter, 4);
        assert_eq!(sink.emit(b"x\n".to_vec()), EmitOutcome::Queued);
        assert_eq!(sink.emit(b"y\n".to_vec()), EmitOutcome::Queued);
        assert_eq!(
            sink.flush(Duration::from_secs(5)),
            EmitOutcome::WriteFailed { failed_lines: 2 }
        );
        assert_eq!(sink.flush(Duration::from_secs(5)), EmitOutcome::Written);
    }

    /// SUP-3・CORE-1（#2043）: 止めている間の `emit` はスレッドを作らず溜め、再開後に順に書かれる。
    /// 上限を超えた分は `QueueFull`、待つ依頼は待たずに `Quiesced`。
    #[test]
    fn sup3_2043_quiesce_buffers_and_resume_writes_in_order() {
        let buf = SharedBuf::default();
        let sink = StderrSink::spawn(buf.clone(), 2);
        assert_eq!(sink.emit(b"a\n".to_vec()), EmitOutcome::Queued);
        sink.quiesce(Duration::from_secs(5)).expect("quiesce");
        // 止める前の行は書き切られている。
        assert_eq!(buf.0.lock().unwrap().as_slice(), b"a\n");
        assert_eq!(sink.emit(b"b\n".to_vec()), EmitOutcome::Queued);
        assert_eq!(
            sink.emit_and_wait(b"c\n".to_vec(), Duration::from_secs(30)),
            EmitOutcome::Quiesced
        );
        assert_eq!(sink.emit(b"d\n".to_vec()), EmitOutcome::QueueFull);
        assert_eq!(sink.flush(Duration::from_secs(30)), EmitOutcome::Quiesced);
        sink.resume().expect("resume");
        assert_eq!(sink.flush(Duration::from_secs(5)), EmitOutcome::Written);
        assert_eq!(buf.0.lock().unwrap().as_slice(), b"a\nb\nc\n");
    }

    /// SUP-3・REPAIR-5（#2043）: 書き手が止まっていれば `quiesce` は期限で `Err`。書き手が戻れば `resume` で再開できる。
    #[test]
    fn sup3_2043_quiesce_times_out_on_stuck_writer_and_resumes_later() {
        let (release, arrived, writer) = stuck();
        let sink = StderrSink::spawn(writer, 4);
        assert_eq!(sink.emit(b"x\n".to_vec()), EmitOutcome::Queued);
        arrived
            .recv_timeout(Duration::from_secs(5))
            .expect("worker thread did not reach the writer");
        let started = Instant::now();
        let err = sink
            .quiesce(Duration::from_millis(100))
            .expect_err("a stuck writer must not be quiesced");
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert!(started.elapsed() < Duration::from_secs(5));
        // 書き手がまだ戻っていないので再開できない。
        assert!(sink.resume().is_err());
        drop(release);
    }

    /// REPAIR-4・SUP-3（#2043）: 一時停止の前に失敗した行は、再開後の最初の待つ依頼で `WriteFailed` として返る。
    #[test]
    fn repair4_failures_survive_quiesce_and_resume() {
        let sink = StderrSink::spawn(BrokenWriter, 4);
        assert_eq!(sink.emit(b"x\n".to_vec()), EmitOutcome::Queued);
        assert_eq!(sink.emit(b"y\n".to_vec()), EmitOutcome::Queued);
        sink.quiesce(Duration::from_secs(5)).expect("quiesce");
        sink.resume().expect("resume");
        assert_eq!(
            sink.flush(Duration::from_secs(5)),
            EmitOutcome::WriteFailed { failed_lines: 2 }
        );
        // 通知した後は数え直す。
        assert_eq!(sink.flush(Duration::from_secs(5)), EmitOutcome::Written);
    }

    /// 結果の区別: 届いた（または届ける行が無い）ものだけが `is_delivered`。
    #[test]
    fn repair4_is_delivered_distinguishes_outcomes() {
        assert!(EmitOutcome::Written.is_delivered());
        assert!(EmitOutcome::NothingQueued.is_delivered());
        for o in [
            EmitOutcome::Queued,
            EmitOutcome::WriteFailed { failed_lines: 1 },
            EmitOutcome::QueueFull,
            EmitOutcome::WorkerUnavailable,
            EmitOutcome::TimedOut,
            EmitOutcome::Quiesced,
        ] {
            assert!(!o.is_delivered(), "{o:?}");
        }
    }
}
