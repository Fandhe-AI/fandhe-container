//! 試験専用: `netns-dial` helper の実プロセス経路を結合試験で駆動するための入口（feature
//! `netns-dial-test-support`。CRI-6・NET-3・SEC-1・REPAIR-12・#4479）。
//!
//! 本番の親側 channel は `netns_dial::channel`（#4480）。本入口は負の場面（任意のバイト列・fd）を作るために、試験が helper の stdin になる `SOCK_SEQPACKET` 対を作り、任意の
//! バイト列と fd を送り、応答を期限つきで受けるために使う。リリースビルドでは feature ごとコンパイルを止める（`lib.rs`）。
//! `unsafe` は持たず、`crate::sys::holder` の安全なラッパーだけを使う。

use std::os::fd::{BorrowedFd, OwnedFd};
use std::time::Duration;

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
