//! 起動・再起動をまたぐコンテナ出力の捕捉ハブ（TASK-164 追補・#1471・SUP-7・SUP-1。関連: REPAIR-5・CORE-1・D-19）。
//!
//! core の launcher が子の stdout / stderr をパイプへ接続して返す読み取り側（`LaunchedProcess::take_output`）を、
//! 行単位捕捉（[`crate::logs::LogCapture`]）へ渡して 1 つの [`LogSink`]（本番は `RotatingFileSink`）へ流す。
//! `crate::start_entry::run_supervised`（初回の起動）と `crate::restart::LauncherRelauncher`（再起動）が呼ぶ。
//! 監視ループ（`supervise_with_restart`）は書き換えず、捕捉は監視と独立したリーダースレッドで進む。
//!
//! # 契約
//! - sink と [`ReaderBudget`] は supervisor プロセスにつき 1 つずつ（ハブが保持し、再起動・再捕捉をまたいで
//!   使い回す。`logs` モジュール doc の契約）。
//! - 生きている捕捉の取っ手は高々 1 つ。[`CaptureHub::attach`] は新しい捕捉を先に開始してから、直前の捕捉を短い期限で
//!   `drain` する（旧プロセスは終了検知済みで EOF が届くはず。孫がパイプを保持して期限切れなら `drain` が自動で取り消し、
//!   リーダー数は予算が上限管理する）。新しい捕捉を先にするのは、restart のレイテンシに drain の待ちを載せないため。
//! - 読み取りスレッドを作るのは `oci_runtime::start` の完了後に限る（start は単一スレッド前提で、入口スレッドが手順 8 を
//!   直接行う。start_entry 参照）。再起動の launch の直前には [`CaptureHub::quiesce`] で直前の捕捉を畳み、捕捉スレッドを
//!   0 にしてから launch する（core の fork 経路が `Threads: 1` を要求するため）。本番 launcher
//!   （`SelfBounded`）の再 launch は `fandhe-relaunch` スレッドを作らず監視ループのスレッドで直接行い、`stderr_sink` の専用
//!   スレッドと制御チャネルの accept スレッドも別途止める（`LauncherRelauncher::with_single_thread_launch`・
//!   `ControlledRelauncher::with_pause`。#2043・SUP-3・CORE-1）。
//! - 捕捉を開始できなかったときは `Err` を返す。読み取り側を破棄するとコンテナは次の `write` で SIGPIPE を受けるため、
//!   呼び出し側は fail-closed（起動・再起動を失敗として扱いプロセスを回収する）にする。ログ喪失を黙って許さない（REPAIR-4）。
//! - 出力は非信頼バイト列として不透明に扱い、supervisor 自身のログへ行内容を出さない。

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fandhe_container_core::oci_runtime::ContainerOutput;
use fandhe_container_core::traits::TraitError;

use crate::logs::tap::{
    OutputTap, TapReporter, TapStats, TapStreams, TapSubscription, default_reporter,
};
use crate::logs::{CaptureSummary, LogCapture, LogSink, OutputStreams, ReaderBudget};

/// `drain` の結果を構造化ログへ報告する（REPAIR-4）。
///
/// `drain` は読み取り・append・flush の失敗でも `Ok(CaptureSummary)` を返し、障害は
/// `StreamSummary::error_code` と破棄行数にだけ残る。そのため `Err` だけでなく集計内の失敗も出す
/// （ディスク容量不足などでログが失われても通知されるように）。行の内容は出さない。
fn report_drain(event: &'static str, drained: &Result<CaptureSummary, TraitError>) {
    let mut failures: Vec<(&'static str, &'static str, u64)> = Vec::new();
    match drained {
        Err(e) => failures.push(("both", e.code().as_str(), 0)),
        Ok(summary) => {
            for (name, stream) in [("stdout", summary.stdout()), ("stderr", summary.stderr())] {
                if let Some(st) = stream
                    && let Some(code) = st.error_code()
                {
                    failures.push((name, code.as_str(), st.discarded_lines()));
                }
            }
        }
    }
    for (stream, code, discarded) in failures {
        let line = format!(
            "{{\"component\":\"supervisor\",\"event\":\"{event}\",\"stream\":\"{stream}\",\"code\":\"{code}\",\"discarded_lines\":{discarded}}}\n"
        );
        // 満杯・書き込み失敗でも処理は止めない（ログの欠落は許す）。
        let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
    }
}

/// 直前の捕捉を畳むときの `drain` の期限（旧プロセスは回収済みで、通常は EOF が即座に届く。REPAIR-5）。
pub const PREVIOUS_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// コンテナ出力の捕捉ハブ。1 つの sink へ、起動ごとの出力を順に流す。
pub struct CaptureHub {
    sink: Arc<dyn LogSink>,
    budget: ReaderBudget,
    /// 生きている捕捉と、その出力の tap（捕捉 1 つにつき 1 つ。差し替えと tap の閉鎖を同じロックの区間で行う）。
    live: Mutex<Option<(LogCapture, Arc<OutputTap>)>>,
    /// tap の切断の報告先（本番は構造化ログ 1 行。試験で差し替える）。
    tap_report: TapReporter,
}

impl std::fmt::Debug for CaptureHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureHub")
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl CaptureHub {
    /// `sink` へ流すハブを作る。リーダー数の予算は supervisor プロセスにつき 1 つ（ここで作る）。
    pub fn new(sink: Arc<dyn LogSink>) -> Self {
        Self {
            sink,
            budget: ReaderBudget::with_max_limit(),
            live: Mutex::new(None),
            tap_report: default_reporter(),
        }
    }

    /// tap の切断の報告先を差し替える（試験用）。
    #[cfg(all(test, unix))]
    pub(crate) fn with_tap_reporter(mut self, report: TapReporter) -> Self {
        self.tap_report = report;
        self
    }

    /// 今の捕捉の出力を購読する（#4072・SUP-7・REPAIR-5。制御チャネルの kind 9〔`control::server`。C6 #4075〕が呼び、端を SCM_RIGHTS で返す）。
    ///
    /// 購読の後に読まれた出力だけが届く（過去の出力は持たない）。sink が優先で、溢れた・閉じた購読者は切断される
    /// （契約は [`crate::logs::tap`]）。生きている捕捉が無い（初回の `attach` の前・`quiesce` から次の `attach` まで・
    /// `finish` の後）と要求したストリームを捕捉していないときは `FailedPrecondition`、どちらも要求しないと
    /// `InvalidArgument`、上限（[`crate::logs::MAX_TAP_SUBSCRIBERS`]。初期案）超過は `ResourceExhausted`。
    /// 非 unix では `Unimplemented`。
    pub fn subscribe_output(&self, streams: TapStreams) -> Result<TapSubscription, TraitError> {
        let tap = self
            .live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|(_, tap)| Arc::clone(tap));
        match tap {
            Some(tap) => tap.subscribe(streams),
            None => Err(TraitError::new(
                fandhe_container_core::traits::ErrorCode::FailedPrecondition,
                "no live output capture",
            )),
        }
    }

    /// 今の捕捉の tap の計数。捕捉が無ければ `None`。
    pub fn output_tap_stats(&self) -> Option<TapStats> {
        self.live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|(_, tap)| tap.stats())
    }

    /// 新しいプロセスの出力の捕捉を開始し、直前の捕捉があれば畳む。出力が空（どちらのストリームも無い）なら何もしない。
    ///
    /// 開始に失敗したら `Err`（`output` は破棄され、書き込み側のコンテナは SIGPIPE を受け得る。呼び出し側が
    /// プロセスを回収すること）。直前の捕捉の `drain` が期限切れ・失敗でも、新しい捕捉は成功として扱う
    /// （失敗は返さず、取り消された旧捕捉の行は sink の契約どおり flush 済み）。
    pub fn attach(&self, output: ContainerOutput) -> Result<(), TraitError> {
        let mut streams = OutputStreams::new(&self.budget, output.stdout, output.stderr);
        if streams.is_empty() {
            // 世代交代の契機なので、旧い捕捉は畳まないが購読者だけは閉じる（#4072）。
            if let Some((_, tap)) = self
                .live
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
            {
                tap.close_all();
            }
            return Ok(());
        }
        let (has_stdout, has_stderr) = streams.presence();
        let tap = Arc::new(OutputTap::new(
            has_stdout,
            has_stderr,
            Arc::clone(&self.tap_report),
        ));
        let capture = match LogCapture::start_with_tap(
            &mut streams,
            Arc::clone(&self.sink),
            Arc::clone(&tap),
        ) {
            Ok(capture) => capture,
            Err(e) => {
                tap.close_all();
                return Err(e);
            }
        };
        let previous = {
            let mut live = self.live.lock().unwrap_or_else(PoisonError::into_inner);
            let previous = live.replace((capture, tap));
            // 旧い世代の購読者は drain を待たずに閉じる（遅れて publish されても no-op）。
            if let Some((_, old_tap)) = previous.as_ref() {
                old_tap.close_all();
            }
            previous.map(|(capture, _)| capture)
        };
        if let Some(previous) = previous {
            // 期限切れでも `drain` が自動で取り消す。ここで待つのは旧プロセスの EOF だけ。
            report_drain(
                "log_capture_previous_drain_failed",
                &previous.drain(PREVIOUS_DRAIN_TIMEOUT),
            );
        }
        Ok(())
    }

    /// 直前の捕捉を `PREVIOUS_DRAIN_TIMEOUT` まで待って畳み、読み取りスレッドを残さない（SUP-7）。
    ///
    /// 再起動の launch の直前に呼ぶ。core の fork 経路は `Threads: 1`（シングルスレッド）を要求するため、
    /// 捕捉スレッドが生きたまま launch すると `MultiThreaded` で拒否される。旧プロセスは回収済みで EOF が即座に届くはず。
    /// 期限切れの場合は `drain` が自動で取り消す（孫がパイプを保持している場合のスレッド残存は予算が上限管理する）。
    pub fn quiesce(&self) {
        self.quiesce_within(PREVIOUS_DRAIN_TIMEOUT);
    }

    /// [`Self::quiesce`] の待ちを `limit`（と `PREVIOUS_DRAIN_TIMEOUT` の小さい方）に切り詰める版。
    /// 再 launch の全体期限の残りを渡すために使う（`limit` が 0 なら EOF を待たず即座に取り消す。REPAIR-5・SUP-3）。
    pub fn quiesce_within(&self, limit: Duration) {
        let previous = self
            .live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some((previous, tap)) = previous {
            tap.close_all();
            report_drain(
                "log_capture_previous_drain_failed",
                &previous.drain(limit.min(PREVIOUS_DRAIN_TIMEOUT)),
            );
        }
    }

    /// 生きている捕捉を `timeout` まで待って畳み、末尾の行を sink へ flush する。捕捉が無ければ `None`。
    ///
    /// supervisor の全終了経路で呼ぶ（末尾の行が sink 内のバッファに残らないように）。
    ///
    /// `timeout` は `LogCapture::drain` の上限（`MAX_DRAIN_TIMEOUT`）に切り詰めて渡す。`StartTimeouts` の terminate は
    /// 最大 600 秒まで許すため、そのまま渡すと drain が `InvalidArgument` で EOF を待たず捕捉を取り消し、
    /// 正常終了でも末尾行が失われる（SUP-7・REPAIR-5）。
    pub fn finish(&self, timeout: Duration) -> Option<Result<CaptureSummary, TraitError>> {
        let live = self
            .live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        live.map(|(capture, tap)| {
            tap.close_all();
            let drained = capture.drain(timeout.min(crate::logs::MAX_DRAIN_TIMEOUT));
            report_drain("log_capture_finish_failed", &drained);
            drained
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::{MemoryLogSink, StreamKind};
    use std::io::Cursor;

    fn output(out: &str, err: &str) -> ContainerOutput {
        ContainerOutput {
            stdout: Some(Box::new(Cursor::new(out.as_bytes().to_vec()))),
            stderr: Some(Box::new(Cursor::new(err.as_bytes().to_vec()))),
        }
    }

    fn lines_of(sink: &MemoryLogSink, kind: StreamKind) -> Vec<Vec<u8>> {
        sink.snapshot()
            .expect("snapshot")
            .into_iter()
            .filter(|l| l.stream == kind)
            .map(|l| l.bytes)
            .collect()
    }

    /// SUP-7・REPAIR-5（#1471）: terminate が drain の上限（60 秒）を超える 120 秒でも、finish は拒否されず
    /// LF なしの末尾行まで sink に flush する。
    #[test]
    fn sup7_1471_finish_clamps_timeout_above_drain_limit() {
        let sink = Arc::new(MemoryLogSink::default());
        let hub = CaptureHub::new(sink.clone());
        hub.attach(output(
            "a1
last-no-lf",
            "",
        ))
        .expect("attach");
        let summary = hub
            .finish(Duration::from_secs(120))
            .expect("live capture")
            .expect("drain must not reject a 120s timeout");
        assert!(summary.stdout().is_some());
        assert_eq!(
            lines_of(&sink, StreamKind::Stdout),
            vec![b"a1".to_vec(), b"last-no-lf".to_vec()]
        );
    }

    /// SUP-7・SUP-1（#1471）: 2 回 attach しても、両方のプロセスの行がストリーム別に欠落・重複なく sink に入る。
    #[test]
    fn sup7_1471_hub_captures_both_launches() {
        let sink = Arc::new(MemoryLogSink::default());
        let hub = CaptureHub::new(sink.clone());
        hub.attach(output("a1\na2\n", "e1\n")).expect("first");
        hub.attach(output("b1\n", "e2\ne3")).expect("second");
        let summary = hub
            .finish(Duration::from_secs(5))
            .expect("live capture")
            .expect("drain");
        assert_eq!(summary.stdout().map(|s| s.lines()), Some(1));
        assert_eq!(summary.stderr().map(|s| s.lines()), Some(2));
        let mut stdout = lines_of(&sink, StreamKind::Stdout);
        stdout.sort();
        assert_eq!(stdout, vec![b"a1".to_vec(), b"a2".to_vec(), b"b1".to_vec()]);
        let mut stderr = lines_of(&sink, StreamKind::Stderr);
        stderr.sort();
        assert_eq!(stderr, vec![b"e1".to_vec(), b"e2".to_vec(), b"e3".to_vec()]);
    }

    /// SUP-7（#1471）: `quiesce` の後は読み取りスレッドが 0 になり、末尾の行も sink へ入っている。
    #[test]
    fn sup7_1471_quiesce_leaves_no_reader_threads() {
        let sink = Arc::new(MemoryLogSink::default());
        let hub = CaptureHub::new(sink.clone());
        hub.attach(output("a1\n", "e1")).expect("attach");
        hub.quiesce();
        // #3507 の後、リーダーは送信の前に枠を手放すため、quiesce から戻った時点で枠は同期的に 0
        // （待ちで補償しない。#3549・REPAIR-5）。
        assert_eq!(hub.budget.live(), 0);
        assert!(hub.finish(Duration::from_secs(1)).is_none());
        assert_eq!(lines_of(&sink, StreamKind::Stdout), vec![b"a1".to_vec()]);
        assert_eq!(lines_of(&sink, StreamKind::Stderr), vec![b"e1".to_vec()]);
    }

    /// 出力の無いプロセスは捕捉を始めず、`finish` も `None`。
    #[test]
    fn sup7_1471_hub_without_streams_is_noop() {
        let hub = CaptureHub::new(Arc::new(MemoryLogSink::default()));
        hub.attach(ContainerOutput::default()).expect("noop");
        assert!(hub.finish(Duration::from_secs(1)).is_none());
    }
}
/// 捕捉から購読者への出力の tap の試験（#4072・SUP-7・REPAIR-5）。待ちはすべて期限つき。
#[cfg(all(test, unix))]
mod tap_tests {
    use super::*;
    use crate::logs::tap::DisconnectReason;
    use crate::logs::{LogCapture, StreamKind};
    use fandhe_container_core::traits::ErrorCode;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Condvar, mpsc};
    use std::time::Instant;

    type Reports = Arc<Mutex<Vec<(Option<StreamKind>, DisconnectReason)>>>;

    /// 行数・バイト数を数える sink。`gate` が閉じている間は append が戻らない。
    struct CountSink {
        lines: AtomicU64,
        bytes: AtomicU64,
        gate: (Mutex<bool>, Condvar),
    }

    impl CountSink {
        fn new(open: bool) -> Arc<Self> {
            Arc::new(Self {
                lines: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
                gate: (Mutex::new(open), Condvar::new()),
            })
        }
        fn open(&self) {
            *self.gate.0.lock().unwrap() = true;
            self.gate.1.notify_all();
        }
        fn lines(&self) -> u64 {
            self.lines.load(Ordering::SeqCst)
        }
    }

    impl LogSink for CountSink {
        fn append(&self, _stream: StreamKind, line: &[u8]) -> Result<(), TraitError> {
            let (m, cv) = &self.gate;
            let mut g = m.lock().unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            while !*g {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(TraitError::new(ErrorCode::Timeout, "gate"));
                }
                g = cv.wait_timeout(g, left).unwrap().0;
            }
            self.bytes.fetch_add(line.len() as u64, Ordering::SeqCst);
            self.lines.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn hub_with(sink: Arc<dyn LogSink>) -> (CaptureHub, Reports) {
        let reports: Reports = Arc::default();
        let r = Arc::clone(&reports);
        let hub = CaptureHub::new(sink).with_tap_reporter(Arc::new(move |s, why| {
            r.lock().unwrap().push((s, why));
        }));
        (hub, reports)
    }

    type Pipes = (
        ContainerOutput,
        Option<std::io::PipeWriter>,
        Option<std::io::PipeWriter>,
    );

    fn pipe_output(stdout: bool, stderr: bool) -> Pipes {
        let mut out = ContainerOutput::default();
        let mut w = (None, None);
        if stdout {
            let (r, wr) = std::io::pipe().unwrap();
            out.stdout = Some(Box::new(r));
            w.0 = Some(wr);
        }
        if stderr {
            let (r, wr) = std::io::pipe().unwrap();
            out.stderr = Some(Box::new(r));
            w.1 = Some(wr);
        }
        (out, w.0, w.1)
    }

    fn wait_until(what: &str, f: impl Fn() -> bool) {
        let start = Instant::now();
        while !f() {
            assert!(start.elapsed() < Duration::from_secs(10), "timeout: {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn timed(s: &UnixStream) {
        match s.set_read_timeout(Some(Duration::from_secs(10))) {
            Ok(()) => {}
            // macOS (XNU) の `sosetopt` は、送受信の両方向が閉じた socket への
            // setsockopt に EINVAL (22) を返す。その状態の read は待たずに
            // バッファのデータか EOF を返すため期限は不要で、無視してよい。
            // 他 OS と他のエラーは従来どおり panic させる (#4144)。
            Err(e) if cfg!(target_os = "macos") && e.raw_os_error() == Some(22) => {}
            Err(e) => panic!("set_read_timeout: {e}"),
        }
    }

    fn read_n(s: &mut UnixStream, n: usize) -> Vec<u8> {
        timed(s);
        let mut v = vec![0u8; n];
        s.read_exact(&mut v).expect("read_exact");
        v
    }

    fn assert_eof(s: &mut UnixStream) {
        timed(s);
        let mut b = [0u8; 16];
        assert_eq!(s.read(&mut b).expect("read"), 0, "expected EOF");
    }

    fn assert_would_block(s: &UnixStream) {
        s.set_nonblocking(true).unwrap();
        let mut b = [0u8; 16];
        let mut r = s;
        let e = r.read(&mut b).expect_err("no data expected");
        assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock);
        s.set_nonblocking(false).unwrap();
    }

    fn out_only() -> TapStreams {
        TapStreams {
            stdout: true,
            stderr: false,
        }
    }

    fn sub_stdout(hub: &CaptureHub) -> UnixStream {
        hub.subscribe_output(out_only())
            .expect("subscribe")
            .into_parts()
            .0
            .expect("stdout end")
    }

    /// 受け入れ基準: 読まない購読者がいても、コンテナ側の write も sink も詰まらない。
    #[test]
    fn sup7_4072_never_reading_subscriber_does_not_block_writer_or_sink() {
        let sink = CountSink::new(true);
        let (hub, reports) = hub_with(sink.clone());
        let (out, w, _) = pipe_output(true, false);
        hub.attach(out).unwrap();
        let mut idle = sub_stdout(&hub);
        let mut w = w.unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let h = std::thread::spawn(move || {
            let mut line = vec![b'x'; 1023];
            line.push(b'\n');
            for _ in 0..4096 {
                w.write_all(&line).unwrap();
            }
            drop(w);
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("writer blocked by tap");
        h.join().unwrap();
        wait_until("sink lines", || sink.lines() == 4096);
        let stats = hub.output_tap_stats().unwrap();
        assert_eq!(stats.disconnected_overflow, 1);
        assert_eq!(stats.live_subscribers, 0);
        hub.finish(Duration::from_secs(10)).unwrap().unwrap();
        assert_eq!(
            *reports.lock().unwrap(),
            vec![(Some(StreamKind::Stdout), DisconnectReason::Overflow)]
        );
        assert_eq!(sink.bytes.load(Ordering::SeqCst), 4096 * 1023);
        timed(&idle);
        let mut total = 0usize;
        let mut buf = [0u8; 8192];
        loop {
            match idle.read(&mut buf).unwrap() {
                0 => break,
                n => total += n,
            }
        }
        assert!(total < 4096 * 1024, "received {total}");
    }

    /// 読む購読者は全バイトを順序どおりに受け、読まない購読者だけが切断される。
    #[test]
    fn sup7_4072_reading_subscriber_survives_while_idle_one_is_dropped() {
        let sink = CountSink::new(true);
        let (hub, reports) = hub_with(sink.clone());
        let (out, w, _) = pipe_output(true, false);
        hub.attach(out).unwrap();
        let mut reader = sub_stdout(&hub);
        let _idle = sub_stdout(&hub);
        let mut w = w.unwrap();
        let mut got: Vec<u8> = Vec::new();
        let mut expect: Vec<u8> = Vec::new();
        // macOS の UNIX stream の socketpair は既定のバッファが約 8 KB
        // (`net.local.stream.sendspace` / `recvspace`)。tap は 1 チャンクを非ブロッキングで
        // 書き切れない購読者を Overflow で切る契約のため、16 KB のチャンクでは読み続ける
        // 購読者も溢れうる。macOS ではチャンクを 2 KB にし、合計 1 MB の書き込み量は保つ (#4144)。
        let chunk_len: usize = if cfg!(target_os = "macos") {
            2 * 1024
        } else {
            16 * 1024
        };
        for i in 0..(1024 * 1024 / chunk_len) {
            let mut chunk = vec![b'a' + (i % 26) as u8; chunk_len - 1];
            chunk.push(b'\n');
            w.write_all(&chunk).unwrap();
            expect.extend_from_slice(&chunk);
            got.extend(read_n(&mut reader, chunk.len()));
        }
        assert_eq!(got, expect);
        wait_until("idle dropped", || {
            hub.output_tap_stats().unwrap().live_subscribers == 1
        });
        assert_eq!(
            *reports.lock().unwrap(),
            vec![(Some(StreamKind::Stdout), DisconnectReason::Overflow)]
        );
        drop(w);
        hub.finish(Duration::from_secs(10)).unwrap().unwrap();
    }

    /// sink が常に優先: append が戻るまで購読者には 1 バイトも届かない。
    #[test]
    fn sup7_4072_tap_waits_for_sink() {
        let sink = CountSink::new(false);
        let (hub, _) = hub_with(sink.clone());
        let (out, w, _) = pipe_output(true, false);
        hub.attach(out).unwrap();
        let mut s = sub_stdout(&hub);
        let mut w = w.unwrap();
        w.write_all(b"x\n").unwrap();
        std::thread::sleep(Duration::from_millis(150));
        assert_would_block(&s);
        sink.open();
        assert_eq!(read_n(&mut s, 2), b"x\n");
        drop(w);
        hub.finish(Duration::from_secs(10)).unwrap().unwrap();
    }

    /// LF なしのプロンプトが、書き手を開いたまま届く（sink にはまだ行が無い）。
    #[test]
    fn sup7_4072_partial_line_reaches_subscriber_before_sink() {
        let sink = CountSink::new(true);
        let (hub, _) = hub_with(sink.clone());
        let (out, w, _) = pipe_output(true, false);
        hub.attach(out).unwrap();
        let mut s = sub_stdout(&hub);
        let mut w = w.unwrap();
        w.write_all(b"prompt$ ").unwrap();
        assert_eq!(read_n(&mut s, 8), b"prompt$ ");
        assert_eq!(sink.lines(), 0);
        drop(w);
        hub.finish(Duration::from_secs(10)).unwrap().unwrap();
        assert_eq!(sink.lines(), 1);
    }

    /// 購読した後の出力だけが届く。
    #[test]
    fn sup7_4072_only_output_after_subscription_is_delivered() {
        let sink = CountSink::new(true);
        let (hub, _) = hub_with(sink.clone());
        let (out, w, _) = pipe_output(true, false);
        hub.attach(out).unwrap();
        let mut barrier = sub_stdout(&hub);
        let mut w = w.unwrap();
        w.write_all(b"before\n").unwrap();
        // 先の購読者に届いた時点で、before の publish は終わっている（同じロック）。
        assert_eq!(read_n(&mut barrier, 7), b"before\n");
        let mut late = sub_stdout(&hub);
        w.write_all(b"after\n").unwrap();
        assert_eq!(read_n(&mut late, 6), b"after\n");
        drop(w);
        hub.finish(Duration::from_secs(10)).unwrap().unwrap();
        assert_eof(&mut late);
    }

    /// 上限 8 件。9 件目は拒否され、閉じた購読者は掃除されて枠が空く。
    #[test]
    fn sup7_4072_subscriber_limit_and_sweep() {
        let (hub, _) = hub_with(CountSink::new(true));
        let (out, w, _) = pipe_output(true, false);
        hub.attach(out).unwrap();
        let mut subs: Vec<UnixStream> = (0..crate::logs::MAX_TAP_SUBSCRIBERS)
            .map(|_| sub_stdout(&hub))
            .collect();
        let e = hub.subscribe_output(out_only()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::ResourceExhausted);
        assert_eq!(hub.output_tap_stats().unwrap().rejected_limit, 1);
        drop(subs.pop());
        let _ninth = sub_stdout(&hub);
        let stats = hub.output_tap_stats().unwrap();
        assert_eq!(stats.disconnected_peer_closed, 1);
        assert_eq!(stats.live_subscribers, 8);
        drop(w);
        hub.finish(Duration::from_secs(10)).unwrap().unwrap();
    }

    /// 相手が閉じた購読者への書き込みは peer_closed で切断され、プロセスは落ちない。
    #[test]
    fn sup7_4072_closed_peer_is_dropped_without_sigpipe() {
        let (hub, reports) = hub_with(CountSink::new(true));
        let (out, w, _) = pipe_output(true, false);
        hub.attach(out).unwrap();
        drop(sub_stdout(&hub));
        let mut w = w.unwrap();
        w.write_all(b"hello\n").unwrap();
        wait_until("peer closed", || {
            hub.output_tap_stats().unwrap().disconnected_peer_closed == 1
        });
        assert_eq!(
            *reports.lock().unwrap(),
            vec![(Some(StreamKind::Stdout), DisconnectReason::PeerClosed)]
        );
        drop(w);
        hub.finish(Duration::from_secs(10)).unwrap().unwrap();
    }

    /// 書き込み側が閉じると、購読した両ストリームが EOF を受け、一覧から外れる。
    #[test]
    fn sup7_4072_eof_closes_both_streams() {
        let (hub, _) = hub_with(CountSink::new(true));
        let (out, w1, w2) = pipe_output(true, true);
        hub.attach(out).unwrap();
        let (a, b) = hub
            .subscribe_output(TapStreams {
                stdout: true,
                stderr: true,
            })
            .unwrap()
            .into_parts();
        let (mut a, mut b) = (a.unwrap(), b.unwrap());
        drop(w1);
        drop(w2);
        assert_eof(&mut a);
        assert_eof(&mut b);
        wait_until("subscriber removed", || {
            hub.output_tap_stats().unwrap().live_subscribers == 0
        });
        hub.finish(Duration::from_secs(10)).unwrap().unwrap();
    }

    /// 世代交代で旧い購読者は EOF を受け、新しい購読者は新しい出力だけを受ける。
    #[test]
    fn sup7_4072_generation_change_closes_old_subscribers() {
        let (hub, _) = hub_with(CountSink::new(true));
        let (out, old_w, _) = pipe_output(true, false);
        hub.attach(out).unwrap();
        let mut old_sub = sub_stdout(&hub);
        let (out2, new_w, _) = pipe_output(true, false);
        hub.attach(out2).unwrap();
        assert_eof(&mut old_sub);
        let mut new_sub = sub_stdout(&hub);
        // 旧い書き手に遅れて書いても、新しい購読者には届かない。
        let _ = old_w.unwrap().write_all(b"old\n");
        let mut new_w = new_w.unwrap();
        new_w.write_all(b"new\n").unwrap();
        assert_eq!(read_n(&mut new_sub, 4), b"new\n");
        drop(new_w);
        hub.finish(Duration::from_secs(10)).unwrap().unwrap();
        assert_eof(&mut new_sub);
    }

    /// quiesce の後は購読者が EOF を受け（孫がパイプを保持して drain が期限切れでも）、購読は拒否される。
    /// finish の後も同じ。
    #[test]
    fn sup7_4072_quiesce_and_finish_close_subscribers() {
        let (hub, _) = hub_with(CountSink::new(true));
        let (out, w, _) = pipe_output(true, false);
        hub.attach(out).unwrap();
        let mut s = sub_stdout(&hub);
        hub.quiesce();
        assert_eof(&mut s);
        assert_eq!(
            hub.subscribe_output(out_only()).unwrap_err().code(),
            ErrorCode::FailedPrecondition
        );
        drop(w);

        let (out, w, _) = pipe_output(true, false);
        hub.attach(out).unwrap();
        let mut s = sub_stdout(&hub);
        drop(w);
        hub.finish(Duration::from_secs(10)).unwrap().unwrap();
        assert_eof(&mut s);
        assert_eq!(
            hub.subscribe_output(out_only()).unwrap_err().code(),
            ErrorCode::FailedPrecondition
        );
        assert!(hub.output_tap_stats().is_none());
    }

    /// 要求の検査: 両方偽、捕捉していないストリーム、EOF 済みのストリーム。
    #[test]
    fn sup7_4072_request_validation() {
        let (hub, _) = hub_with(CountSink::new(true));
        let (out, w, _) = pipe_output(true, false);
        hub.attach(out).unwrap();
        let none = TapStreams {
            stdout: false,
            stderr: false,
        };
        assert_eq!(
            hub.subscribe_output(none).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        let err_only = TapStreams {
            stdout: false,
            stderr: true,
        };
        assert_eq!(
            hub.subscribe_output(err_only).unwrap_err().code(),
            ErrorCode::FailedPrecondition
        );
        drop(w);
        // リーダーが EOF を見るまで待つ。EOF 済みなら購読者の端は即 EOF。
        let start = Instant::now();
        loop {
            let mut s = sub_stdout(&hub);
            s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            let mut b = [0u8; 1];
            if matches!(s.read(&mut b), Ok(0)) {
                break;
            }
            assert!(start.elapsed() < Duration::from_secs(10), "never EOF");
        }
        hub.finish(Duration::from_secs(10)).unwrap().unwrap();
    }

    /// 取り消しの後に書かれたバイトは購読者に届かない。
    #[test]
    fn sup7_4072_cancelled_capture_publishes_nothing() {
        let sink = CountSink::new(true);
        let budget = ReaderBudget::with_max_limit();
        let (r, mut w) = std::io::pipe().unwrap();
        let (r, entered) = crate::logs::notify_on_read(r);
        let tap = Arc::new(OutputTap::new(true, false, Arc::new(|_, _| {})));
        let mut streams = OutputStreams::new(&budget, Some(r), None);
        let cap = LogCapture::start_with_tap(&mut streams, sink.clone(), Arc::clone(&tap)).unwrap();
        let mut s = tap.subscribe(out_only()).unwrap().into_parts().0.unwrap();
        crate::logs::wait_read_entered(&entered);
        cap.cancel().unwrap();
        w.write_all(b"late\n").unwrap();
        wait_until("reader gone", || budget.live() == 0);
        assert_eof(&mut s);
        assert_eq!(sink.lines(), 0);
    }
}
