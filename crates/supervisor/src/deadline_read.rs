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
    /// 読み取りまたは `poll` の失敗（`EINTR` は内部で再試行する）。
    Io(io::Error),
}

/// `until` まで、EOF・上限 `max` バイト・（`stop_at_newline` なら）`\n` のいずれかで止まるまで読む。
/// `\n` は結果に含み、それ以降は読み越さない（1 バイトずつ読む）。`stop_at_newline = false` では塊で読む。
pub(crate) fn read_capped_until(
    r: &mut (impl Read + AsFd),
    max: u64,
    until: Instant,
    stop_at_newline: bool,
) -> Result<Vec<u8>, ReadStop> {
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    while (out.len() as u64) < max {
        match poll_revents_now(r.as_fd(), POLL_IN | POLL_RDHUP) {
            Ok(rev) if rev & (POLL_IN | POLL_GONE_MASK) != 0 => {}
            Ok(_) => {
                let now = Instant::now();
                if now >= until {
                    return Err(ReadStop::TimedOut(out));
                }
                std::thread::sleep(POLL_STEP.min(until - now));
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ReadStop::Io(e)),
        }
        let room = (max - out.len() as u64).min(buf.len() as u64) as usize;
        let want = if stop_at_newline { 1 } else { room };
        match r.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if stop_at_newline && buf[0] == b'\n' {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(ReadStop::Io(e)),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    const T: Duration = Duration::from_millis(200);

    /// REPAIR-5・REPAIR-12: 書き込み端を閉じない子を模す。行が途中なら期限で戻り、読めた分を保持する。
    #[test]
    fn repair5_4733_partial_line_times_out_with_bytes_kept() {
        let (mut r, mut w) = std::io::pipe().unwrap();
        w.write_all(b"abc").unwrap();
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
        let (mut r, _w) = std::io::pipe().unwrap();
        let t0 = Instant::now();
        let got = read_capped_until(&mut r, 4096, t0 + T, false);
        let el = t0.elapsed();
        assert!(
            matches!(&got, Err(ReadStop::TimedOut(b)) if b.is_empty()),
            "{got:?}"
        );
        assert!(el >= T && el < Duration::from_secs(2), "{el:?}");
    }

    /// 改行まで書けば writer が残っていても即座に返り、改行以降は読み越さない。
    #[test]
    fn repair5_4733_newline_returns_immediately_without_overread() {
        let (mut r, mut w) = std::io::pipe().unwrap();
        w.write_all(b"ok\nnext").unwrap();
        let t0 = Instant::now();
        let got = read_capped_until(&mut r, 4096, t0 + Duration::from_secs(5), true).unwrap();
        assert_eq!(got, b"ok\n");
        assert!(t0.elapsed() < Duration::from_secs(2));
        let rest = read_capped_until(&mut r, 4096, Instant::now() + T, false);
        assert!(
            matches!(&rest, Err(ReadStop::TimedOut(b)) if b == b"next"),
            "{rest:?}"
        );
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

    /// 上限を超えて溜めない。
    #[test]
    fn repair5_4733_cap_stops_reading() {
        let (mut r, mut w) = std::io::pipe().unwrap();
        w.write_all(&[b'a'; 100]).unwrap();
        let got =
            read_capped_until(&mut r, 10, Instant::now() + Duration::from_secs(5), false).unwrap();
        assert_eq!(got, [b'a'; 10]);
    }
}
