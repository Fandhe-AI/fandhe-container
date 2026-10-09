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
//! `observe::snapshot_lines` の定期出力（セッション終了時に 1 回だけ出す）。
//!
//! kick / call の fd は frontend が複製を持ち得るため、`O_NONBLOCK` を含む open file description のフラグと counter は
//! 相手と共有され、poll の後に相手が eventfd を読み書きして状態を変えたり、フラグを落としたりできる。そこでセッションの
//! スレッドは eventfd を直接 read / write せず、使い捨ての補助スレッドへ I/O を任せ、`recv_timeout` で期限を評価する
//! （共有フラグに依存しない。REPAIR-5）。期限を超えたら補助スレッドを起こす逆向きの操作（kick は 1 を書く、call は読み出して
//! counter を空ける）を別の切り離したスレッドで試み、セッションのスレッドは決して eventfd の I/O で止まらない。
//! 逆向きの操作が間に合わなければ補助スレッドが残り得るが、それはプロセス終了で回収される（セッション 1 本につき高々数本）。
//! 補助スレッドを使うぶん kick 1 回あたり数十 us の上乗せがあり、`ctrl_kick` のヒストグラムに現れる。

mod error;
mod metrics;
mod negotiation;

use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub use error::{Cause, SessionError, SessionErrorCode};

use crate::adapter::CtrlAdapter;
use crate::ctrl::{CtrlResponse, RESP_ERR_INVALID_PARAMETER};
use crate::log::{self, QueryResult};
use crate::sys;
use crate::vhost_user::fd_passing::{MAX_FDS, MAX_TIMEOUT, recv_with_fds, send_with_fds};
use crate::vhost_user::observe;
use crate::vhost_user::{
    Decoded, HEADER_LEN, Header, MAX_PAYLOAD_LEN, TransportError, TransportErrorCode,
    decode_request_payload,
};
use crate::virtqueue::VirtqueueErrorCode;
use metrics::{SessionMetrics, SessionOp};
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
        metrics: SessionMetrics::default(),
    };
    let result = session.serve(sock, sink);
    // REPAIR-4: 操作ごとの成功 / 失敗件数と所要時間、fd 受け渡し・ゲストメモリ I/O の集計を終了時に出す。
    for line in session
        .metrics
        .lines()
        .into_iter()
        .chain(observe::snapshot_lines())
    {
        sink(&line);
    }
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
    metrics: SessionMetrics,
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
                let started = Instant::now();
                let handled = match self.read_message(sock) {
                    Ok(None) => return Ok(SessionEnd::PeerClosed),
                    Ok(Some(incoming)) => self.dispatch(sock, incoming, sink),
                    Err(e) => Err(e),
                };
                self.metrics
                    .record(SessionOp::Message, handled.is_ok(), started.elapsed());
                handled?;
                last_activity = Instant::now();
            }
            let started = Instant::now();
            let serviced = self.service_ctrl(sink);
            if !matches!(serviced, Ok(false)) {
                self.metrics
                    .record(SessionOp::CtrlKick, serviced.is_ok(), started.elapsed());
            }
            if serviced? {
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
            metrics,
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
        // 相手が poll の後に counter を読み切っていれば処理するものが無い（次の kick を待つ）。
        let kick = read_kick(&ring.kick, limits.poll_slice)?;
        if kick == KickRead::Drained {
            return Ok(false);
        }
        let mut done = 0usize;
        for _ in 0..ring.depth() {
            let chain = match ring.queue.pop(mem) {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => return Err(SessionError::virtqueue(e, None)),
            };
            let vq = |e| SessionError::virtqueue(e, None);
            // 応答を書き戻せず捨てる場合に adapter の状態変更（CTX の作成・破棄）を取り消すための控え。
            let adapter_before = adapter.clone();
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
                // frontend が結果を確認できないため、この要求による adapter の状態変更も取り消す
                // （取り消さないと同じ ID の再送が重複エラーになる）。
                Err(e) if e.code == VirtqueueErrorCode::UsedLenExceedsWritable => {
                    dropped = true;
                    *adapter = adapter_before;
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
            let started = Instant::now();
            let notified = notify(&ring.call, limits.message_timeout);
            metrics.record(SessionOp::Notify, notified.is_ok(), started.elapsed());
            notified?;
        }
        // `Lost` では kick を読めたか不明なので ring は走査済み。処理が無ければ偽。
        Ok(done > 0 || kick == KickRead::Read)
    }
}

/// [`read_kick`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KickRead {
    /// counter を読めた。
    Read,
    /// 相手が先に読み切っていて counter が無かった（`O_NONBLOCK` が立っている場合）。
    Drained,
    /// 補助スレッドが期限内に終わらなかった（相手が読み切ってフラグも落としている等）。読めたか不明なので、
    /// 呼び出し側は ring を走査する（空なら何も起きない）。
    Lost,
}

/// 補助スレッドで `op` を実行し、`wait_for` 以内の結果を返す。期限切れは `Ok(None)`（補助スレッドは切り離す）。
fn run_bounded<T: Send + 'static>(
    file: &File,
    wait_for: Duration,
    op: impl FnOnce(&File) -> io::Result<T> + Send + 'static,
) -> Result<Option<io::Result<T>>, SessionError> {
    let failed = || SessionError::new(SessionErrorCode::FdSetupFailed, None);
    let dup = file.try_clone().map_err(|_| failed())?;
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("venus-jig-fd-io".into())
        .spawn(move || {
            // 受け側が期限切れで捨てていれば送信は失敗するが、結果が要らないので無視する。
            let _ = tx.send(op(&dup));
        })
        .map_err(|_| failed())?;
    match rx.recv_timeout(wait_for) {
        Ok(r) => Ok(Some(r)),
        Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(failed()),
    }
}

/// `op` を切り離したスレッドで実行する（結果は捨てる。失敗しても何もしない）。
fn detach(file: &File, op: impl FnOnce(&File) + Send + 'static) {
    if let Ok(dup) = file.try_clone() {
        let _ = std::thread::Builder::new()
            .name("venus-jig-fd-unblock".into())
            .spawn(move || op(&dup));
    }
}

/// kick の eventfd から counter（8 バイト）を読む。読み取りは補助スレッドに任せ、`wait_for` 以内に終わらなければ
/// 読み取りを起こすために 1 を書いて（別の切り離したスレッドで）`Lost` を返す。
fn read_kick(kick: &File, wait_for: Duration) -> Result<KickRead, SessionError> {
    let result = run_bounded(kick, wait_for, |f| {
        let mut counter = [0u8; 8];
        let mut r = f;
        r.read(&mut counter).map(|n| (n, counter))
    })?;
    match result {
        None => {
            // 補助スレッドは counter 0 の read で止まっている。1 を足して起こす（余分な kick は空走査で無害）。
            detach(kick, |f| {
                let mut w = f;
                let _ = w.write(&1u64.to_le_bytes());
            });
            Ok(KickRead::Lost)
        }
        Some(Ok((0, _))) => Err(SessionError::new(SessionErrorCode::KickClosed, None)),
        Some(Ok((8, _))) => Ok(KickRead::Read),
        Some(Ok(_)) => Err(SessionError::new(SessionErrorCode::InvalidKick, None)),
        Some(Err(e)) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
            Ok(KickRead::Drained)
        }
        Some(Err(_)) => Err(SessionError::new(SessionErrorCode::InvalidKick, None)),
    }
}

/// call の eventfd へ 1 を書いてゲストへ通知する。書き込みは補助スレッドに任せて `timeout` の期限まで待ち、`EAGAIN`
/// （相手が counter を満たし `O_NONBLOCK` が立っている等）は期限内で再試行する。期限切れは `TIMEOUT`
/// （書き込みを起こすため、別の切り離したスレッドで call を読み出して counter を空ける）。
fn notify(call: &File, timeout: Duration) -> Result<(), SessionError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| SessionError::new(SessionErrorCode::InvalidArgument, None))?;
    loop {
        let left = match remaining(deadline) {
            Ok(left) => left,
            Err(e) => {
                unblock_call(call);
                return Err(e);
            }
        };
        let result = run_bounded(call, left, |f| {
            let mut w = f;
            w.write(&1u64.to_le_bytes())
        })?;
        match result {
            None => {
                unblock_call(call);
                return Err(SessionError::new(SessionErrorCode::Timeout, None));
            }
            Some(Ok(8)) => return Ok(()),
            Some(Ok(_)) => return Err(SessionError::new(SessionErrorCode::CallFailed, None)),
            Some(Err(e)) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                // busy loop を避けて短く待ってから期限内で再試行する。
                std::thread::sleep(left.min(Duration::from_millis(1)));
            }
            Some(Err(_)) => return Err(SessionError::new(SessionErrorCode::CallFailed, None)),
        }
    }
}

/// 止まっている call の書き込みを起こすため、読める状態を確認してから 1 回読み出す（切り離したスレッドで実行）。
fn unblock_call(call: &File) {
    detach(call, |f| {
        if matches!(
            sys::wait_fd(f.as_fd(), sys::Interest::Readable, MAX_UNBLOCK_WAIT),
            Ok(true)
        ) {
            let mut buf = [0u8; 8];
            let mut r = f;
            let _ = r.read(&mut buf);
        }
    });
}

/// [`unblock_call`] が読み出せるようになるのを待つ上限。
const MAX_UNBLOCK_WAIT: Duration = Duration::from_millis(100);

#[cfg(test)]
mod tests;
