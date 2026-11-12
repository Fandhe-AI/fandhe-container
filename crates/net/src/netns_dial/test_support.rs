//! 試験専用: `netns-dial` helper の実プロセス経路を結合試験で駆動するための入口（feature
//! `netns-dial-test-support`。CRI-6・NET-3・SEC-1・REPAIR-12・#4479）。
//!
//! 本番の親側 channel は `netns_dial::channel`（#4480）。本入口は負の場面（任意のバイト列・fd）を作るために、試験が helper の stdin になる `SOCK_SEQPACKET` 対を作り、任意の
//! バイト列と fd を送り、応答を期限つきで受けるために使う。リリースビルドでは feature ごとコンパイルを止める（`lib.rs`）。
//! `unsafe` は持たず、`crate::sys::holder` の安全なラッパーだけを使う。

use std::ffi::OsString;
use std::io::Write as _;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::process::ExitCode;
use std::time::Duration;

use super::frame::DialErrorCode;
use super::helper::{self, Joiner, NsPair, RealJoiner};
use crate::sys::holder as sysh;
use crate::sys::{self, Deadline, Readiness};

/// helper の stdin にする `SOCK_SEQPACKET` 対（`(親の端, 子の端)`。両端とも close-on-exec）。
pub fn seqpacket_pair() -> std::io::Result<(OwnedFd, OwnedFd)> {
    sysh::socketpair_seqpacket().map_err(|e| std::io::Error::other(format!("socketpair: {e:?}")))
}

/// 任意のバイト列と fd（`SCM_RIGHTS`）を 1 通で送る。
pub fn send_raw(fd: BorrowedFd<'_>, bytes: &[u8], fds: &[BorrowedFd<'_>]) -> std::io::Result<()> {
    sysh::send_with_fds(fd, bytes, fds, true)
        .map(|_| ())
        .map_err(|e| std::io::Error::other(format!("send: {e:?}")))
}

/// 応答 1 通を期限つきで受ける。`Ok(None)` は期限切れ。EOF は `Some((空, 空))`。
pub fn recv_raw(
    fd: BorrowedFd<'_>,
    within: Duration,
) -> std::io::Result<Option<(Vec<u8>, Vec<OwnedFd>)>> {
    let deadline = Deadline::after(within);
    match sys::wait_readable(fd, &deadline) {
        Ok(Readiness::TimedOut) => return Ok(None),
        Ok(_) => {}
        Err(e) => return Err(std::io::Error::other(format!("poll: {e:?}"))),
    }
    let mut buf = [0u8; 64];
    let got = sysh::recv_with_fds(fd, &mut buf, 1)
        .map_err(|e| std::io::Error::other(format!("recv: {e:?}")))?;
    Ok(Some((buf.get(..got.len).unwrap_or(&[]).to_vec(), got.fds)))
}

/// 応答側の偽 helper が要求 1 通（frame と fd 最大 `max_fds` 本）を期限つきで受ける（#4484。要求は user・net の 2 本を運ぶため
/// [`recv_raw`] の 1 本では足りない）。`max_fds` は 1..=2 に限る（`sys::holder::MAX_FDS`）。`Ok(None)` は期限切れ。EOF は `Some((空, 空))`。
pub fn recv_raw_fds(
    fd: BorrowedFd<'_>,
    within: Duration,
    max_fds: usize,
) -> std::io::Result<Option<(Vec<u8>, Vec<OwnedFd>)>> {
    if !(1..=2).contains(&max_fds) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "max_fds must be in 1..=2",
        ));
    }
    let deadline = Deadline::after(within);
    match sys::wait_readable(fd, &deadline) {
        Ok(Readiness::TimedOut) => return Ok(None),
        Ok(_) => {}
        Err(e) => return Err(std::io::Error::other(format!("poll: {e:?}"))),
    }
    let mut buf = [0u8; 64];
    let got = sysh::recv_with_fds(fd, &mut buf, max_fds)
        .map_err(|e| std::io::Error::other(format!("recv: {e:?}")))?;
    Ok(Some((buf.get(..got.len).unwrap_or(&[]).to_vec(), got.fds)))
}

/// 3 時点の `PR_GET_DUMPABLE` の観測値。`None` はその段に届かなかった、`Some(Err(()))` は prctl の失敗。
type Observed = Option<Result<i32, ()>>;

fn observe_dumpable() -> Observed {
    Some(sysh::get_dumpable().map_err(|_| ()))
}

/// 本番の [`RealJoiner`] を包み、参加の前後と特権の破棄の後の dumpable を記録する（#4558・SEC-1・CRI-6・NET-3）。
/// 動作は `RealJoiner` と同じで、観測以外の副作用を足さない。
struct TracingJoiner {
    inner: RealJoiner,
    before_join: Observed,
    after_join: Observed,
    after_harden: Observed,
}

impl Joiner for TracingJoiner {
    fn join(&mut self, user: OwnedFd, net: OwnedFd, received: NsPair) -> Result<(), DialErrorCode> {
        self.before_join = observe_dumpable();
        let r = self.inner.join(user, net, received);
        if r.is_ok() {
            self.after_join = observe_dumpable();
        }
        r
    }

    fn harden(&mut self) -> Result<(), DialErrorCode> {
        let r = self.inner.harden();
        if r.is_ok() {
            self.after_harden = observe_dumpable();
        }
        r
    }
}

fn format_one(v: Observed) -> String {
    match v {
        None => "none".to_owned(),
        Some(Err(())) => "err".to_owned(),
        Some(Ok(n)) => n.to_string(),
    }
}

/// trace 行の組み立て（純関数）。固定語彙と整数だけを含む。
fn format_dumpable_trace(before: Observed, after_join: Observed, after_harden: Observed) -> String {
    format!(
        "netns-dial-trace dumpable before_join={} after_join={} after_harden={}",
        format_one(before),
        format_one(after_join),
        format_one(after_harden)
    )
}

/// 本番と同じ `helper::run_with` を実行し、終了前に stdout（fd 1。`close_range(3..)` の対象外）へ 3 時点の dumpable を
/// 1 行で書く。起動直後の設定が参加の前後・特権の破棄の後も 0 のままであることを実プロセスで観測するための入口
/// （#4558）。本番の supervisor の bin の振り分けには加えない。
pub fn run_netns_dial_traced_main(args: impl Iterator<Item = OsString>) -> ExitCode {
    let mut joiner = TracingJoiner {
        inner: RealJoiner,
        before_join: None,
        after_join: None,
        after_harden: None,
    };
    let code = helper::run_with(args, &mut joiner);
    let line = format_dumpable_trace(joiner.before_join, joiner.after_join, joiner.after_harden);
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    /// #4558: trace 行の形（具体値）。
    #[test]
    fn format_dumpable_trace_renders_none_err_and_integers() {
        assert_eq!(
            format_dumpable_trace(Some(Ok(0)), Some(Ok(0)), Some(Ok(0))),
            "netns-dial-trace dumpable before_join=0 after_join=0 after_harden=0"
        );
        assert_eq!(
            format_dumpable_trace(Some(Ok(1)), None, Some(Err(()))),
            "netns-dial-trace dumpable before_join=1 after_join=none after_harden=err"
        );
    }

    /// #4484: 2 本の fd が順序どおり届くこと、範囲外の `max_fds` を拒否すること。
    #[test]
    fn recv_raw_fds_receives_two_fds_and_rejects_bad_max() {
        let (a, b) = seqpacket_pair().expect("pair");
        let x = std::fs::File::open("/proc/self/ns/net").expect("net");
        let y = std::fs::File::open("/proc/self/ns/user").expect("user");
        send_raw(a.as_fd(), b"hi", &[x.as_fd(), y.as_fd()]).expect("send");
        let (bytes, fds) = recv_raw_fds(b.as_fd(), Duration::from_secs(2), 2)
            .expect("recv")
            .expect("not timed out");
        assert_eq!(bytes, b"hi");
        assert_eq!(fds.len(), 2);
        assert!(
            recv_raw_fds(b.as_fd(), Duration::from_millis(10), 2)
                .expect("recv")
                .is_none()
        );
        assert!(recv_raw_fds(b.as_fd(), Duration::from_millis(10), 0).is_err());
        assert!(recv_raw_fds(b.as_fd(), Duration::from_millis(10), 3).is_err());
    }
}
