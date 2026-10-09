//! vhost-user セッションと ctrl キューの応答ループ（GPU-6・REPAIR-5・TASK-172 F1.4・#1519）。Linux 限定。
//!
//! 治具 VMM（frontend。crosvm 等）と接続済みの `UnixStream` 1 本分を最後まで処理する上位層。
//! `vhost_user`（codec・fd 受け渡し・ゲストメモリ）、`virtqueue`（split ring）、`adapter`（ctrl 要求の応答）をつなぎ、
//! 次の流れを作る。ネゴシエーション（`negotiation`）→ kick を受ける → ctrl キューから要求を取り出す →
//! `CtrlAdapter::handle_ctrl` → 応答を used ring へ書く → call で通知する。受入基準 2（ゲストの Mesa venus の capset
//! クエリが自前デコーダへ届いたことをログで確認）の前提で、実機での実行は F3（#725。人間担当）。
//!
//! 呼び出し元: F3 の起動側（UDS を bind して `accept` した接続を渡す）と結合試験。bind・所有者 / 権限 / symlink の検証・
//! peer credential の検証（PLUG-12 相当）は本層の範囲外で、呼び出し側が行う（既知の穴。設計書 10.8）。
//!
//! 待機はすべて期限つき（REPAIR-5）。単一 fd 用の `sys::wait_fd` を socket と ctrl の kick で交互に短く待つ方式のため、
//! kick への反応には最大 [`SessionLimits::poll_slice`] の遅延が乗る（複数 fd の ppoll 化は unsafe の承認範囲外）。
//! 未実装（REPAIR-3）: cursorq（ring 1）の要求処理・`SET_CONFIG`・`VRING_NOFD`・REPLY_ACK・inflight・
//! `observe::snapshot_lines` の定期出力。

mod error;
mod negotiation;

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub use error::{Cause, SessionError, SessionErrorCode};

use crate::adapter::CtrlAdapter;
use crate::ctrl::{CtrlResponse, RESP_ERR_INVALID_PARAMETER};
use crate::log::{self, QueryResult};
use crate::sys;
use crate::vhost_user::fd_passing::{MAX_FDS, MAX_TIMEOUT, recv_with_fds, send_with_fds};
use crate::vhost_user::{
    Decoded, HEADER_LEN, Header, MAX_PAYLOAD_LEN, TransportError, TransportErrorCode,
    decode_request_payload,
};
use crate::virtqueue::VirtqueueErrorCode;
use negotiation::{State, expected_fds};

/// ctrl 要求として受け付ける readable の最大長（固定長のスタックバッファの大きさ）。`CTX_CREATE`（96 バイト）より十分大きい。
pub const MAX_CTRL_REQ_LEN: usize = 4096;

const DEFAULT_POLL_SLICE: Duration = Duration::from_millis(10);

/// セッションの時間制限。すべて 0 より大きく [`MAX_TIMEOUT`]（1 時間）以下。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimits {
    message_timeout: Duration,
    idle_timeout: Duration,
    poll_slice: Duration,
}

impl SessionLimits {
    /// `message_timeout` は 1 メッセージの受信・応答送信・call 書き込みの期限、`idle_timeout` は無通信の上限。
    /// `poll_slice` は既定 10ms（`idle_timeout` が短ければそれ以下）。範囲外は `INVALID_ARGUMENT`。
    pub fn new(message_timeout: Duration, idle_timeout: Duration) -> Result<Self, SessionError> {
        let ok = |d: Duration| !d.is_zero() && d <= MAX_TIMEOUT;
        if !ok(message_timeout) || !ok(idle_timeout) {
            return Err(SessionError::new(SessionErrorCode::InvalidArgument, None));
        }
        Ok(Self {
            message_timeout,
            idle_timeout,
            poll_slice: DEFAULT_POLL_SLICE.min(idle_timeout),
        })
    }

    /// `poll_slice` を差し替える（0 より大きく `idle_timeout` 以下）。
    pub fn with_poll_slice(mut self, poll_slice: Duration) -> Result<Self, SessionError> {
        if poll_slice.is_zero() || poll_slice > self.idle_timeout {
            return Err(SessionError::new(SessionErrorCode::InvalidArgument, None));
        }
        self.poll_slice = poll_slice;
        Ok(self)
    }

    /// 1 メッセージの期限。
    pub fn message_timeout(&self) -> Duration {
        self.message_timeout
    }
    /// 無通信の上限。
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }
    /// socket と kick を交互に待つ 1 回の長さ。
    pub fn poll_slice(&self) -> Duration {
        self.poll_slice
    }
}

/// セッションの正常終了の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// frontend がメッセージの境界で切断した。
    PeerClosed,
}

/// 接続 1 本分のセッションを最後まで処理する。ログ（1 行 1 要求）は `sink` へ流す。
///
/// エラーで終わる場合は `session_error` の行を 1 行出してから `Err` を返す。どの経路でも保持する fd と mmap は `Drop` で解放される。
/// 内部状態が `!Send` なので、この関数を呼ぶスレッドの中で完結する。
pub fn run(
    sock: &UnixStream,
    limits: &SessionLimits,
    sink: &mut dyn FnMut(&str),
) -> Result<SessionEnd, SessionError> {
    let mut session = Session {
        state: State::new(),
        adapter: CtrlAdapter::default(),
        limits: *limits,
    };
    let result = session.serve(sock, sink);
    match &result {
        Ok(_) => sink(&log::session_end_line()),
        Err(e) => sink(&log::session_error_line(e.code.as_str(), e.request)),
    }
    result
}

struct Session {
    state: State,
    adapter: CtrlAdapter,
    limits: SessionLimits,
}

/// 受信した要求と添付 fd。
struct Incoming {
    decoded: Decoded,
    fds: Vec<OwnedFd>,
}

fn wait(fd: BorrowedFd<'_>, interest: sys::Interest, d: Duration) -> Result<bool, SessionError> {
    match sys::wait_fd(fd, interest, d) {
        Ok(ready) => Ok(ready),
        Err(sys::SysError::Interrupted(_)) => Ok(false),
        Err(e) => Err(SessionError::transport(TransportError::from_sys(e), None)),
    }
}

fn remaining(deadline: Instant) -> Result<Duration, SessionError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(SessionError::new(SessionErrorCode::Timeout, None));
    }
    Ok(left)
}

/// `buf` を期限内に読み切る。fd は最初の受信でだけ受け付ける（`first_with_fds`）。`eof_ok` で先頭の 0 バイト（切断）は `Ok(false)`。
fn fill(
    sock: &UnixStream,
    buf: &mut [u8],
    fds: &mut Vec<OwnedFd>,
    first_with_fds: bool,
    deadline: Instant,
    eof_ok: bool,
) -> Result<bool, SessionError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let max_fds = if first_with_fds && filled == 0 {
            MAX_FDS
        } else {
            0
        };
        let dst = buf
            .get_mut(filled..)
            .ok_or_else(|| SessionError::new(SessionErrorCode::InvalidArgument, None))?;
        match recv_with_fds(sock, dst, max_fds, remaining(deadline)?) {
            Ok(r) => {
                filled += r.len;
                fds.extend(r.fds);
            }
            Err(e) if e.code == TransportErrorCode::PeerClosed && filled == 0 && eof_ok => {
                return Ok(false);
            }
            Err(e) => return Err(SessionError::transport(e, None)),
        }
    }
    Ok(true)
}

impl Session {
    fn serve(
        &mut self,
        sock: &UnixStream,
        sink: &mut dyn FnMut(&str),
    ) -> Result<SessionEnd, SessionError> {
        let mut last_activity = Instant::now();
        loop {
            if last_activity.elapsed() >= self.limits.idle_timeout {
                return Err(SessionError::new(SessionErrorCode::IdleTimeout, None));
            }
            if wait(
                sock.as_fd(),
                sys::Interest::Readable,
                self.limits.poll_slice,
            )? {
                let Some(incoming) = self.read_message(sock)? else {
                    return Ok(SessionEnd::PeerClosed);
                };
                self.dispatch(sock, incoming, sink)?;
                last_activity = Instant::now();
            }
            if self.service_ctrl(sink)? {
                last_activity = Instant::now();
            }
        }
    }

    /// 1 メッセージを受信して復号し、添付 fd の個数を照合する。メッセージの境界での切断は `None`。
    fn read_message(&self, sock: &UnixStream) -> Result<Option<Incoming>, SessionError> {
        let deadline = Instant::now()
            .checked_add(self.limits.message_timeout)
            .ok_or_else(|| SessionError::new(SessionErrorCode::InvalidArgument, None))?;
        let mut fds = Vec::new();
        let mut hdr = [0u8; HEADER_LEN];
        if !fill(sock, &mut hdr, &mut fds, true, deadline, true)? {
            return Ok(None);
        }
        let header = Header::decode_request(&hdr)?;
        let mut payload = [0u8; MAX_PAYLOAD_LEN];
        let n = header.payload_len();
        let body = payload
            .get_mut(..n)
            .ok_or_else(|| SessionError::new(SessionErrorCode::InvalidValue, None))?;
        fill(sock, body, &mut fds, false, deadline, false)?;
        let decoded = decode_request_payload(&header, body)?;
        let want = expected_fds(&decoded.request);
        if fds.len() != want {
            let code = if want == 0 {
                SessionErrorCode::UnexpectedFds
            } else {
                SessionErrorCode::FdCountMismatch
            };
            return Err(SessionError::new(code, Some(header.request().as_u32())));
        }
        Ok(Some(Incoming { decoded, fds }))
    }

    fn dispatch(
        &mut self,
        sock: &UnixStream,
        incoming: Incoming,
        sink: &mut dyn FnMut(&str),
    ) -> Result<(), SessionError> {
        let Incoming { decoded, fds } = incoming;
        let code = decoded.request.code();
        match self.state.handle(decoded.request, fds)? {
            Some(reply) => {
                let msg = reply.encode()?;
                let deadline = Instant::now()
                    .checked_add(self.limits.message_timeout)
                    .ok_or_else(|| SessionError::new(SessionErrorCode::InvalidArgument, None))?;
                let bytes = msg.as_bytes();
                let mut off = 0usize;
                while off < bytes.len() {
                    let rest = bytes
                        .get(off..)
                        .ok_or_else(|| SessionError::new(SessionErrorCode::InvalidValue, None))?;
                    let sent = send_with_fds(sock, rest, &[], remaining(deadline)?)
                        .map_err(|e| SessionError::transport(e, Some(code.as_u32())))?;
                    off += sent.len;
                }
            }
            // REPLY_ACK を広告していないので、`SET_*` に NEED_REPLY が付いていても応答しない。
            None if decoded.need_reply => sink(&log::need_reply_ignored_line(code.as_u32())),
            None => {}
        }
        Ok(())
    }

    /// ctrl キュー（ring 0）の kick を待ち、積まれた要求を空にして call で通知する。処理したら真。
    fn service_ctrl(&mut self, sink: &mut dyn FnMut(&str)) -> Result<bool, SessionError> {
        let Session {
            state,
            adapter,
            limits,
        } = self;
        let Some((ring, mem)) = state.ctrl_parts() else {
            return Ok(false);
        };
        if !wait(
            ring.kick.as_fd(),
            sys::Interest::Readable,
            limits.poll_slice,
        )? {
            return Ok(false);
        }
        let mut counter = [0u8; 8];
        match (&ring.kick).read(&mut counter) {
            Ok(0) => return Err(SessionError::new(SessionErrorCode::KickClosed, None)),
            Ok(8) => {}
            _ => return Err(SessionError::new(SessionErrorCode::InvalidKick, None)),
        }
        let mut done = 0usize;
        for _ in 0..ring.depth() {
            let chain = match ring.queue.pop(mem) {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => return Err(SessionError::virtqueue(e, None)),
            };
            let vq = |e| SessionError::virtqueue(e, None);
            let (response, log_line) = if chain.readable_len() > MAX_CTRL_REQ_LEN as u64 {
                (
                    CtrlResponse::new(None, RESP_ERR_INVALID_PARAMETER, &[]),
                    log::rejected_line(None, QueryResult::InvalidParameter),
                )
            } else {
                let mut buf = [0u8; MAX_CTRL_REQ_LEN];
                let n = chain.read_readable(mem, &mut buf).map_err(vq)?;
                let req = buf
                    .get(..n)
                    .ok_or_else(|| SessionError::new(SessionErrorCode::InvalidValue, None))?;
                let h = adapter.handle_ctrl(req);
                (h.response, h.log_line)
            };
            let mut dropped = false;
            let len = match chain.write_writable(mem, response.as_bytes()) {
                Ok(n) => n,
                // 書き戻し先が足りない要求は応答を捨て（len=0）、セッションは続ける。
                Err(e) if e.code == VirtqueueErrorCode::UsedLenExceedsWritable => {
                    dropped = true;
                    0
                }
                Err(e) => return Err(vq(e)),
            };
            ring.queue.add_used(mem, chain, len).map_err(vq)?;
            sink(&log_line);
            if dropped {
                sink(&log::response_dropped_line());
            }
            done += 1;
        }
        if done > 0 {
            notify(&ring.call, limits.message_timeout)?;
        }
        Ok(true)
    }
}

/// call の eventfd へ 1 を書いてゲストへ通知する（書き込み可能になるのを期限つきで待つ）。
fn notify(call: &File, timeout: Duration) -> Result<(), SessionError> {
    if !wait(call.as_fd(), sys::Interest::Writable, timeout)? {
        return Err(SessionError::new(SessionErrorCode::Timeout, None));
    }
    match (&*call).write(&1u64.to_le_bytes()) {
        Ok(8) => Ok(()),
        _ => Err(SessionError::new(SessionErrorCode::CallFailed, None)),
    }
}

#[cfg(test)]
mod tests;
