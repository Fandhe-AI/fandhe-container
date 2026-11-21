//! 期限つきの pipe 読み取り（Linux 限定。REPAIR-5・#4733）。
//!
//! `exec.rs` の `collect_worker_result`（worker の結果 1 行）と `netns_holder.rs` の `drain_stderr`
//! （回収済み holder の stderr）が使う。書き込み端の複製を持つ並行 spawn の子が残っても、読み取りが
//! 期限で戻るようにする。`poll(2)` を `timeout = 0` で見て読める（データか HUP 系）ときだけ `read` するので
//! `read` はブロックせず、`unsafe` を足さない（`sys::poll_revents_now`）。

use std::io::{self, Read};
use std::os::fd::AsFd;
use std::time::{Duration, Instant};

use crate::sys::{POLL_GONE_MASK, POLL_IN, POLL_RDHUP, poll_revents_now};

/// 読めるまでの待ちの刻み。
const POLL_STEP: Duration = Duration::from_millis(5);

/// 期限つき読み取りの中断理由。
#[derive(Debug)]
pub(crate) enum ReadStop {
    /// 期限切れ。それまでに読めた分を保持する。
    TimedOut(Vec<u8>),
    /// 読み取りまたは `poll` の失敗（`EINTR` は内部で再試行する）。それまでに読めた分も保持する（診断に使う）。
    Io(io::Error, Vec<u8>),
}

/// EOF・上限 `max` バイト・（`stop_at_newline` なら）`\n` のいずれかで止まるまで読む。
///
/// 契約: `until` は **待ちの上限** である。`poll` が読めると報告するデータ（HUP 系を含む）は、期限を過ぎていても
/// `max` まで直ちに回収する（`max` で頭打ち・`read` は `poll` の後でブロックしないので有限時間で終わる）。読めるものが
/// 無いときだけ `until` まで待ち、過ぎたら `TimedOut`（それまでに読めた分を保持）を返す。`EINTR` の再試行も期限で打ち切る。
/// `stop_at_newline = true` は塊（最大 512 バイト）で読み、`\n` までを（`\n` を含めて）返す。塊の `\n` より後ろは
/// 読み越して **捨てる**（回収済みの worker の pipe を 1 回だけ読む用途のため無害）。`false` は塊で読み、`\n` を特別扱いしない。
///
/// 契約: `r` の `Read` は、`poll` する fd（`AsFd`）そのものを読む単独の読み手であること。読み端を複製して別に
/// 読む者がいる・並行に読む者がいる・`Read` が `poll` した fd 以外の入力を待つ実装だと、`poll` が読めると
/// 報告した直後でも `read` がブロックし得て、期限を守れない。
pub(crate) fn read_capped_until(
    r: &mut (impl Read + AsFd),
    max: u64,
    until: Instant,
    stop_at_newline: bool,
) -> Result<Vec<u8>, ReadStop> {
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    while (out.len() as u64) < max {
        let now = Instant::now();
        match poll_revents_now(r.as_fd(), POLL_IN | POLL_RDHUP) {
            Ok(rev) if rev & (POLL_IN | POLL_GONE_MASK) != 0 => {}
            Ok(_) => {
                if now >= until {
                    return Err(ReadStop::TimedOut(out));
                }
                std::thread::sleep(POLL_STEP.min(until - now));
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                if now >= until {
                    return Err(ReadStop::TimedOut(out));
                }
                continue;
            }
            Err(e) => return Err(ReadStop::Io(e, out)),
        }
        let room = (max - out.len() as u64).min(buf.len() as u64) as usize;
        let Some(dst) = buf.get_mut(..room) else {
            return Err(ReadStop::Io(
                io::Error::other("read buffer out of range"),
                out,
            ));
        };
        match r.read(dst) {
            Ok(0) => break,
            Ok(n) => {
                // `Read` の実装が渡した長さを超える値を返しても、読んでいないバイトを結果に含めず panic もしない。
                let Some(chunk) = dst.get(..n) else {
                    return Err(ReadStop::Io(
                        io::Error::other("read returned more bytes than requested"),
                        out,
                    ));
                };
                if stop_at_newline && let Some(i) = chunk.iter().position(|&b| b == b'\n') {
                    out.extend_from_slice(chunk.get(..=i).unwrap_or(chunk));
                    break;
                }
                out.extend_from_slice(chunk);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                if now >= until {
                    return Err(ReadStop::TimedOut(out));
                }
            }
            Err(e) => return Err(ReadStop::Io(e, out)),
        }
    }
    Ok(out)
}

/// 試験用: `w`（pipe の書き込み端など）を、`after` の経過か戻り値の drop の早い方で閉じる。読み取りが回帰して
/// EOF 待ちに戻っても書き込み端が独立に閉じて呼び出しが戻り、各試験が経過時間の assert で失敗を報告できる
/// （試験バイナリ全体の監視に頼らない。REPAIR-5）。
#[cfg(test)]
pub(crate) fn close_after<W: Send + 'static>(w: W, after: Duration) -> CloseAfter {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        let _ = rx.recv_timeout(after);
        drop(w);
    });
    CloseAfter(Some(tx), Some(handle))
}

/// [`close_after`] の戻り値。drop で即座に閉じさせ、閉じ終わるまで待つ。
#[cfg(test)]
pub(crate) struct CloseAfter(
    Option<std::sync::mpsc::Sender<()>>,
    Option<std::thread::JoinHandle<()>>,
);

#[cfg(test)]
impl Drop for CloseAfter {
    fn drop(&mut self) {
        drop(self.0.take());
        if let Some(h) = self.1.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    const T: Duration = Duration::from_millis(200);
    /// 書き込み端を独立に閉じるまでの時間（期待する読み取りの期限より十分後）。
    const GUARD: Duration = Duration::from_secs(5);

    /// REPAIR-5・REPAIR-12: 書き込み端を閉じない子を模す。行が途中なら期限で戻り、読めた分を保持する。
    #[test]
    fn repair5_4733_partial_line_times_out_with_bytes_kept() {
        let (mut r, mut w) = std::io::pipe().unwrap();
        w.write_all(b"abc").unwrap();
        let _w = close_after(w, GUARD);
        let t0 = Instant::now();
        let got = read_capped_until(&mut r, 4096, t0 + T, true);
        let el = t0.elapsed();
        match got {
            Err(ReadStop::TimedOut(b)) => assert_eq!(b, b"abc"),
            other => panic!("{other:?}"),
        }
        assert!(el >= T && el < Duration::from_secs(2), "{el:?}");
    }

    /// REPAIR-5: 何も書かれず writer が残る場合も期限で戻る。
    #[test]
    fn repair5_4733_silent_writer_times_out_empty() {
        let (mut r, w) = std::io::pipe().unwrap();
        let _w = close_after(w, GUARD);
        let t0 = Instant::now();
        let got = read_capped_until(&mut r, 4096, t0 + T, false);
        let el = t0.elapsed();
        assert!(
            matches!(&got, Err(ReadStop::TimedOut(b)) if b.is_empty()),
            "{got:?}"
        );
        assert!(el >= T && el < Duration::from_secs(2), "{el:?}");
    }

    /// 改行まで書けば writer が残っていても即座に返り、改行より後ろは読み越して捨てる（契約）。
    #[test]
    fn repair5_4733_newline_returns_immediately_and_discards_rest() {
        let (mut r, mut w) = std::io::pipe().unwrap();
        w.write_all(b"ok\nnext").unwrap();
        let _w = close_after(w, GUARD);
        let t0 = Instant::now();
        let got = read_capped_until(&mut r, 4096, t0 + Duration::from_secs(5), true).unwrap();
        assert_eq!(got, b"ok\n");
        assert!(t0.elapsed() < Duration::from_secs(2));
        let rest = read_capped_until(&mut r, 4096, Instant::now() + T, false);
        assert!(
            matches!(&rest, Err(ReadStop::TimedOut(b)) if b.is_empty()),
            "{rest:?}"
        );
    }

    /// REPAIR-5・SEC-4: 期限が過ぎていても、すでに読める完全な行は捨てずに返す（待ちだけを期限で切る）。
    #[test]
    fn repair5_4733_expired_deadline_still_returns_readable_line() {
        let (mut r, mut w) = std::io::pipe().unwrap();
        w.write_all(b"ready\n").unwrap();
        let _w = close_after(w, GUARD);
        let past = Instant::now() - Duration::from_millis(1);
        let got = read_capped_until(&mut r, 4096, past, true).unwrap();
        assert_eq!(got, b"ready\n");
    }

    /// 期限切れで、読めるものが無ければ待たずに即座に `TimedOut` で戻る（読めた分は保持）。
    #[test]
    fn repair5_4733_expired_deadline_does_not_wait_when_nothing_readable() {
        let (mut r, mut w) = std::io::pipe().unwrap();
        w.write_all(b"abc").unwrap();
        let _w = close_after(w, GUARD);
        let t0 = Instant::now();
        let got = read_capped_until(&mut r, 4096, t0 - Duration::from_millis(1), true);
        assert!(
            matches!(&got, Err(ReadStop::TimedOut(b)) if b == b"abc"),
            "{got:?}"
        );
        assert!(t0.elapsed() < Duration::from_millis(100));
    }

    /// writer を閉じれば EOF で期限を待たずに返る。
    #[test]
    fn repair5_4733_eof_returns_before_deadline() {
        let (mut r, mut w) = std::io::pipe().unwrap();
        w.write_all(b"xy").unwrap();
        drop(w);
        let t0 = Instant::now();
        let got = read_capped_until(&mut r, 4096, t0 + Duration::from_secs(5), true).unwrap();
        assert_eq!(got, b"xy");
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    /// REPAIR-5: `Read` が渡した長さを超える値を返したら、読めた分を保持した `Io` で返す（panic しない）。
    #[test]
    fn repair5_4733_overlong_read_count_is_io_error() {
        struct Liar(std::io::PipeReader);
        impl Read for Liar {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                Ok(b.len() + 1)
            }
        }
        impl AsFd for Liar {
            fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
                self.0.as_fd()
            }
        }
        let (r, mut w) = std::io::pipe().unwrap();
        w.write_all(b"x").unwrap();
        let _w = close_after(w, GUARD);
        let got = read_capped_until(&mut Liar(r), 4096, Instant::now() + T, false);
        match got {
            Err(ReadStop::Io(e, b)) => {
                assert_eq!(e.to_string(), "read returned more bytes than requested");
                assert!(b.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    /// 上限を超えて溜めない。
    #[test]
    fn repair5_4733_cap_stops_reading() {
        let (mut r, mut w) = std::io::pipe().unwrap();
        w.write_all(&[b'a'; 100]).unwrap();
        let _w = close_after(w, GUARD);
        let got =
            read_capped_until(&mut r, 10, Instant::now() + Duration::from_secs(5), false).unwrap();
        assert_eq!(got, [b'a'; 10]);
    }
}
