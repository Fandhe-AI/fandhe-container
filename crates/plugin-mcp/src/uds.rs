//! core が bind した UDS 上の JSON-RPC 2.0 処理（PLUG-12 準拠の接続。MCP-1・MCP-2。TASK-118.4・#467）。
//!
//! 呼び出し元は bin（`src/main.rs`）のみ。`FANDHE_CONTAINER_PLUGIN_SOCKET` が設定されているとき、bin が
//! `fandhe_container_plugin::UdsStream::connect`（server の peer UID 検証つき。別 UID の listener には
//! 1 バイトも送らず切断する）で得た接続をここへ渡す。プロトコル処理は stdio と同じ
//! `crate::server::process_line`（`handle_message_with`）を共有し、本モジュールは UDS 固有の
//! 入出力と期限だけを持つ。
//!
//! フレーミング（暫定契約。REPAIR-3）: stdio と同じ「改行区切りの JSON-RPC 2.0、1 行 1 メッセージ」。
//! `fandhe-container-plugin` の長さ接頭辞フレームに包むか、core 側 proxy をどう結線するかは
//! TASK-114 で確定する。確定したら本モジュールのフレーミングを差し替える。
//!
//! 期限（REPAIR-5）: アイドル待ち（次のメッセージの先頭バイトまで）は EOF まで無期限（stdio と同じ）。
//! 実装は `UdsStream::set_io_timeout` を周期（[`IDLE_POLL`]）に使うポーリングで、周期ごとの
//! `WouldBlock` / `TimedOut` は無視して再試行する。先頭バイトを受けてからは `Limits::message_timeout`、
//! 応答の書き込み・flush は `Limits::write_timeout` の合計期限で打ち切る。単一スレッドで動くため
//! `UdsStream`（`try_clone` を持たない）をそのまま使える。

use std::cell::Cell;
use std::io::{self, BufReader, Read, Write};
use std::rc::Rc;
use std::time::{Duration, Instant};

use fandhe_container_plugin::UdsStream;
use serde_json::Value;

use crate::backend::{CoreBackend, ToolBackend};
use crate::server::{
    Limits, ServeError, log_request, log_transport, process_line, read_line, with_stderr_log,
};

/// アイドル待ちのポーリング周期。切断・期限の検知がこの粒度になる。
pub const IDLE_POLL: Duration = Duration::from_secs(1);

/// 読み書きの期限を周期設定できる接続。`UdsStream` と単体試験のフェイクが実装する。
pub trait PollStream: Read + Write {
    /// 1 回の read / write が待つ最大時間を設定する。
    fn set_poll_timeout(&self, timeout: Duration) -> io::Result<()>;
}

impl PollStream for UdsStream {
    fn set_poll_timeout(&self, timeout: Duration) -> io::Result<()> {
        // PluginError の文言は環境依存でありうるため、固定の io エラーへ写す。
        self.set_io_timeout(timeout)
            .map_err(|_| io::Error::other("failed to set socket timeout"))
    }
}

fn is_retry(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// 受信側の期限状態。reader と `read_line` の `on_start` が共有する。
#[derive(Default)]
struct RecvState {
    /// 受信中メッセージの絶対期限。アイドル中は `None`（無期限）。
    deadline: Cell<Option<Instant>>,
    /// 期限超過で受信を打ち切ったか。
    expired: Cell<bool>,
}

/// 期限までの残り時間を、周期 `poll` を上限・1ms を下限にして返す。期限超過なら `None`。
fn slice_until(deadline: Instant, poll: Duration) -> Option<Duration> {
    let rest = deadline.checked_duration_since(Instant::now())?;
    if rest.is_zero() {
        return None;
    }
    Some(rest.min(poll).max(Duration::from_millis(1)))
}

/// ポーリング周期の `WouldBlock` / `TimedOut` を吸収し、期限があれば超過で打ち切る reader。
///
/// 期限（絶対時刻）は read が成功し続ける場合にも適用する（REPAIR-5）。各 read の前に残り時間を確認し、
/// socket の待機を残り時間以下に絞り、read の後にも確認する。少量ずつ送り続ける相手でも
/// `message_timeout` を超えて受信を続けない（上限超過後の読み捨てを含む）。
struct PollReader<S> {
    stream: S,
    state: Rc<RecvState>,
    poll: Duration,
}

impl<S: PollStream> PollReader<S> {
    fn expire(&self) -> io::Error {
        self.state.expired.set(true);
        io::Error::from(io::ErrorKind::TimedOut)
    }
}

impl<S: PollStream> Read for PollReader<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let deadline = self.state.deadline.get();
            if let Some(d) = deadline {
                let Some(slice) = slice_until(d, self.poll) else {
                    return Err(self.expire());
                };
                self.stream.set_poll_timeout(slice)?;
            }
            match self.stream.read(buf) {
                Err(e) if is_retry(e.kind()) => {
                    if deadline.is_some_and(|d| Instant::now() >= d) {
                        return Err(self.expire());
                    }
                }
                Ok(n) => {
                    if deadline.is_some_and(|d| Instant::now() >= d) {
                        return Err(self.expire());
                    }
                    return Ok(n);
                }
                other => return other,
            }
        }
    }
}

/// 応答 1 件（末尾に改行を付ける）を `timeout` の合計期限で書いて flush する。
///
/// 各 write・flush の前に残り時間を確認して待機を残り時間以下に絞り、成功後にも確認する。
/// 部分書き込みが進み続けても、flush が成功しても、合計期限を超えたら `WriteTimeout`（REPAIR-5）。
fn write_line<S: PollStream>(
    stream: &mut S,
    text: &str,
    timeout: Duration,
    poll: Duration,
) -> Result<(), ServeError> {
    let deadline = Instant::now() + timeout;
    let mut data = Vec::with_capacity(text.len().saturating_add(1));
    data.extend_from_slice(text.as_bytes());
    data.push(b'\n');
    let mut rest: &[u8] = &data;
    while !rest.is_empty() {
        let slice = slice_until(deadline, poll).ok_or(ServeError::WriteTimeout)?;
        stream.set_poll_timeout(slice).map_err(ServeError::Write)?;
        match stream.write(rest) {
            Ok(0) => {
                return Err(ServeError::Write(io::Error::from(io::ErrorKind::WriteZero)));
            }
            Ok(n) => rest = rest.get(n..).unwrap_or_default(),
            Err(e) if is_retry(e.kind()) => {}
            Err(e) => return Err(ServeError::Write(e)),
        }
    }
    loop {
        let slice = slice_until(deadline, poll).ok_or(ServeError::WriteTimeout)?;
        stream.set_poll_timeout(slice).map_err(ServeError::Write)?;
        match stream.flush() {
            Ok(()) => {
                return if Instant::now() >= deadline {
                    Err(ServeError::WriteTimeout)
                } else {
                    Ok(())
                };
            }
            Err(e) if is_retry(e.kind()) => {}
            Err(e) => return Err(ServeError::Write(e)),
        }
    }
}

/// 標準の上限・期限で相手の切断（EOF）まで処理する。ログは stderr へ 1 行 JSON で出す。
pub fn serve_uds(stream: UdsStream) -> Result<(), ServeError> {
    let backend = CoreBackend::production();
    with_stderr_log(|log| serve_uds_with(stream, Limits::default(), &backend, log))
}

/// 上限・期限・ログ sink を指定して EOF まで処理する。EOF で `Ok(())`。
pub fn serve_uds_with<S: PollStream>(
    stream: S,
    limits: Limits,
    backend: &dyn ToolBackend,
    log: &mut dyn FnMut(&str),
) -> Result<(), ServeError> {
    let poll = IDLE_POLL
        .min(limits.message_timeout)
        .min(limits.write_timeout)
        .max(Duration::from_millis(1));
    if let Err(e) = stream.set_poll_timeout(poll) {
        log_transport(log, "UNAVAILABLE");
        return Err(ServeError::Read(e));
    }
    let state = Rc::new(RecvState::default());
    let mut reader = BufReader::new(PollReader {
        stream,
        state: Rc::clone(&state),
        poll,
    });
    loop {
        state.deadline.set(None);
        let start_state = Rc::clone(&state);
        let message_timeout = limits.message_timeout;
        let mut on_start = move || {
            start_state
                .deadline
                .set(Some(Instant::now() + message_timeout));
        };
        let line = match read_line(&mut reader, limits.max_line_bytes, &mut on_start) {
            Ok(Some(line)) => {
                // バッファ済みの行で完結した場合も、受信の期限超過なら拒否する。
                if state.deadline.get().is_some_and(|d| Instant::now() >= d) {
                    log_transport(log, "DEADLINE_EXCEEDED");
                    return Err(ServeError::ReadTimeout);
                }
                line
            }
            Ok(None) => return Ok(()),
            Err(e) => {
                if state.expired.get() {
                    log_transport(log, "DEADLINE_EXCEEDED");
                    return Err(ServeError::ReadTimeout);
                }
                log_transport(log, "UNAVAILABLE");
                return Err(ServeError::Read(e));
            }
        };
        // 応答の書き込みでは受信期限を使わない。
        state.deadline.set(None);
        let began = Instant::now();
        let Some(outcome) = process_line(line, backend) else {
            continue;
        };
        if let Some(reply) = &outcome.reply {
            let Ok(text) = serde_json::to_string::<Value>(reply) else {
                log_transport(log, "INTERNAL");
                return Err(ServeError::Encode);
            };
            if let Err(e) = write_line(
                &mut reader.get_mut().stream,
                &text,
                limits.write_timeout,
                poll,
            ) {
                log_transport(
                    log,
                    if matches!(e, ServeError::WriteTimeout) {
                        "DEADLINE_EXCEEDED"
                    } else {
                        "UNAVAILABLE"
                    },
                );
                return Err(e);
            }
        }
        log_request(log, &outcome, began);
    }
}

#[cfg(test)]
mod tests {
    //! MCP-1・REPAIR-5・REPAIR-12: フェイク接続で UDS ループの入出力と期限を具体値で照合する。
    use super::*;
    use crate::backend::UnavailableBackend;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// 読み出しの台本の 1 手。
    enum Step {
        Data(&'static [u8]),
        Idle,
        Eof,
    }

    struct Fake {
        script: VecDeque<Step>,
        written: Arc<Mutex<Vec<u8>>>,
        /// true なら write が常に WouldBlock。
        write_blocks: bool,
        /// 1 回の write で受け取る最大バイト数（部分書き込みの再現）。
        write_chunk: usize,
        /// read / write 1 回ごとに眠る時間（成功する遅い I/O の再現）。
        slow: Duration,
        /// 台本が尽きたあとも TimedOut を返し続けるか（EOF を返さない停止相手）。
        stall_forever: bool,
    }

    impl Fake {
        fn new(script: Vec<Step>) -> (Self, Arc<Mutex<Vec<u8>>>) {
            let written = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    script: script.into(),
                    written: Arc::clone(&written),
                    write_blocks: false,
                    write_chunk: usize::MAX,
                    slow: Duration::ZERO,
                    stall_forever: false,
                },
                written,
            )
        }
    }

    impl Read for Fake {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            std::thread::sleep(self.slow);
            match self.script.pop_front() {
                Some(Step::Data(d)) => {
                    let n = d.len().min(buf.len());
                    buf[..n].copy_from_slice(&d[..n]);
                    Ok(n)
                }
                Some(Step::Idle) => {
                    std::thread::sleep(Duration::from_millis(2));
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                }
                Some(Step::Eof) => Ok(0),
                None if self.stall_forever => {
                    std::thread::sleep(Duration::from_millis(2));
                    Err(io::Error::from(io::ErrorKind::TimedOut))
                }
                None => Ok(0),
            }
        }
    }

    impl Write for Fake {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.write_blocks {
                std::thread::sleep(Duration::from_millis(2));
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            std::thread::sleep(self.slow);
            let n = buf.len().min(self.write_chunk);
            self.written
                .lock()
                .unwrap()
                .extend_from_slice(buf.get(..n).unwrap());
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl PollStream for Fake {
        fn set_poll_timeout(&self, _: Duration) -> io::Result<()> {
            Ok(())
        }
    }

    fn quick() -> Limits {
        Limits {
            max_line_bytes: 4096,
            message_timeout: Duration::from_millis(80),
            write_timeout: Duration::from_millis(80),
        }
    }

    const PING: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}\n";

    /// アイドル（WouldBlock）を挟んでも要求を処理し、部分書き込みでも応答 1 行が欠けない。
    #[test]
    fn serves_after_idle_and_partial_writes() {
        let (mut fake, written) = Fake::new(vec![
            Step::Idle,
            Step::Idle,
            Step::Data(PING),
            Step::Idle,
            Step::Eof,
        ]);
        fake.write_chunk = 3;
        let mut logs = Vec::new();
        let r = serve_uds_with(fake, quick(), &UnavailableBackend, &mut |l| {
            logs.push(l.to_owned());
        });
        assert!(r.is_ok());
        let out = String::from_utf8(written.lock().unwrap().clone()).unwrap();
        let v: Value = serde_json::from_str(out.trim_end()).unwrap();
        assert!(out.ends_with('\n'));
        assert_eq!(out.lines().count(), 1);
        assert_eq!(v.get("id"), Some(&serde_json::json!(7)));
        assert_eq!(logs.len(), 1);
        assert!(logs[0].contains("\"op\":\"ping\""), "{}", logs[0]);
    }

    /// 先頭バイトの後で止まった相手は message_timeout で ReadTimeout（REPAIR-5）。
    #[test]
    fn stalled_partial_message_times_out() {
        let (mut fake, written) = Fake::new(vec![Step::Data(b"{\"jsonrpc\"")]);
        fake.stall_forever = true;
        let mut logs = Vec::new();
        let r = serve_uds_with(fake, quick(), &UnavailableBackend, &mut |l| {
            logs.push(l.to_owned());
        });
        assert!(matches!(r, Err(ServeError::ReadTimeout)));
        assert!(written.lock().unwrap().is_empty());
        assert_eq!(logs.len(), 1);
        assert!(logs[0].contains("DEADLINE_EXCEEDED"), "{}", logs[0]);
    }

    /// 何も送らないアイドル相手は期限で切らず、EOF で正常終了する（stdio と同じ契約）。
    #[test]
    fn idle_connection_waits_until_eof() {
        // Idle 1 回あたり最低 2ms 眠るため、60 回で期限（80ms）を確実に超える。
        let mut script: Vec<Step> = (0..60).map(|_| Step::Idle).collect();
        script.push(Step::Eof);
        let (fake, written) = Fake::new(script);
        let limits = quick();
        let started = Instant::now();
        let r = serve_uds_with(fake, limits, &UnavailableBackend, &mut |_| {});
        let elapsed = started.elapsed();
        // 期限を超えて待ったうえで ReadTimeout にならず EOF で正常終了する（REPAIR-12）。
        assert!(
            elapsed > limits.message_timeout,
            "idle wait {elapsed:?} must exceed {:?}",
            limits.message_timeout
        );
        assert!(r.is_ok(), "{r:?}");
        assert!(written.lock().unwrap().is_empty());
    }

    /// 書き込みが進まない相手は write_timeout で WriteTimeout（REPAIR-5）。
    #[test]
    fn blocked_write_times_out() {
        let (mut fake, _) = Fake::new(vec![Step::Data(PING), Step::Eof]);
        fake.write_blocks = true;
        let r = serve_uds_with(fake, quick(), &UnavailableBackend, &mut |_| {});
        assert!(matches!(r, Err(ServeError::WriteTimeout)));
    }

    /// 上限超過の行は -32600 で応答し、接続は継続する。
    #[test]
    fn oversized_line_is_rejected_then_continues() {
        let (fake, written) = Fake::new(vec![
            Step::Data(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"),
            Step::Data(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n"),
            Step::Eof,
        ]);
        let limits = Limits {
            max_line_bytes: 16,
            ..quick()
        };
        // ping の行も 16 バイトを超えるため、2 行とも -32600 の応答になる。
        let r = serve_uds_with(fake, limits, &UnavailableBackend, &mut |_| {});
        assert!(r.is_ok());
        let out = String::from_utf8(written.lock().unwrap().clone()).unwrap();
        assert_eq!(out.lines().count(), 2);
        assert!(out.lines().all(|l| l.contains("-32600")));
    }

    /// 1 バイトずつ成功し続ける遅い相手でも message_timeout で ReadTimeout（REPAIR-5）。
    #[test]
    fn slow_successful_reads_hit_message_deadline() {
        let steps = (0..200).map(|_| Step::Data(b"x")).collect();
        let (mut fake, written) = Fake::new(steps);
        fake.slow = Duration::from_millis(5);
        let began = Instant::now();
        let r = serve_uds_with(fake, quick(), &UnavailableBackend, &mut |_| {});
        assert!(matches!(r, Err(ServeError::ReadTimeout)));
        assert!(began.elapsed() < Duration::from_millis(600));
        assert!(written.lock().unwrap().is_empty());
    }

    /// 少量ずつ書けるが合計期限を超える相手は WriteTimeout（REPAIR-5）。
    #[test]
    fn slow_successful_writes_hit_write_deadline() {
        let (mut fake, _) = Fake::new(vec![Step::Data(PING), Step::Eof]);
        fake.write_chunk = 1;
        fake.slow = Duration::from_millis(10);
        // 応答は 50 バイト超 x 10ms で 80ms を超える。読み側の遅延も含むため write のみ眠らせる別台本は不要。
        let limits = Limits {
            message_timeout: Duration::from_secs(5),
            ..quick()
        };
        let r = serve_uds_with(fake, limits, &UnavailableBackend, &mut |_| {});
        assert!(matches!(r, Err(ServeError::WriteTimeout)));
    }
}
