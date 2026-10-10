//! backend 要求（`SHMEM_MAP` / `SHMEM_UNMAP`）の期限つき送受信とエラー型（GPU-6・REPAIR-2・REPAIR-5・TASK-172 F5.2b.3・#1642）。Linux 限定。
//!
//! 役割: `negotiation::State` が保持する backend 要求用 UDS へ、`vhost_user::backend_req` で組んだ 52 バイトの要求を
//! NEED_REPLY つきで送り、frontend の u64 応答（0 = 成功、非 0 = 失敗）を検査して返す。呼び出し元は
//! `Session::shmem_map` / `shmem_unmap`（さらにその呼び出し元は ctrl `MAP_BLOB` / `UNMAP_BLOB`＝`Session::execute_shmem`。#1643）。
//!
//! 期限（REPAIR-5）は呼び出しごとの 1 つで、送信と受信の全体を覆う（セッションからは `SessionLimits::message_timeout`）。
//! fd は 52 バイトを送る最初の `sendmsg` に付ける（crosvm は先頭のヘッダ受信で添付 fd を受け、本体側の fd を
//! `InvalidMessage` にする。設計書 10.4.4）。部分送信になった残りは fd なしで送る。応答は `recv_with_fds(max_fds = 0)` で
//! ヘッダ 12 バイト → size を確かめてから u64 の 8 バイトだけを読む。応答に fd が付いていれば `TOO_MANY_FDS` で拒否し、
//! 受け取った fd は `Drop` で閉じる。
//!
//! 失敗の分類: 治具側の失敗（期限切れ・切断・トランスポート・応答の形式不正）の後はストリームの同期が崩れている
//! （遅れて届く応答が次の要求の応答に見える）ので、呼び出し側（`Session`）が channel を `Broken` にして以後送らない。
//! frontend が形式の正しい非 0 を返した `REMOTE_FAILURE` は同期が保たれているため channel を保つ。

use std::fmt;
use std::os::fd::BorrowedFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use super::negotiation::HostVisibleUnavailable;
use crate::vhost_user::backend_req::{
    BACKEND_REPLY_PAYLOAD_LEN, BackendCodecError, BackendCodecErrorCode, BackendRequest,
    BackendRequestCode, decode_backend_reply_header, decode_backend_reply_value,
};
use crate::vhost_user::fd_passing::{recv_with_fds, send_with_fds};
use crate::vhost_user::{HEADER_LEN, TransportError, TransportErrorCode};

/// backend 要求の失敗種別。`as_str` の大文字スネーク表記が外部に出す code。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendReqErrorCode {
    /// REPLY_ACK を確定していない（NEED_REPLY の応答義務を frontend が負わない）。送らない。
    ReplyAckNotNegotiated,
    /// host-visible が使えない（SHMEM・BACKEND_REQ の未確定、ソケット無し、channel の破損）。送らない。
    HostVisibleUnavailable,
    /// 期限内に送受信が終わらなかった。
    Timeout,
    /// 応答の途中で相手が閉じた、またはヘッダ前に閉じた。
    PeerClosed,
    /// その他のトランスポートエラー（応答への fd 添付を含む）。
    Transport,
    /// 応答が形式不正（REPLY なし・要求 ID 違い・size 違い）。
    MalformedReply,
    /// frontend が非 0 を返した（`status` に値をそのまま持つ）。
    RemoteFailure,
}

impl BackendReqErrorCode {
    /// 外部へ出す固定の code 文字列。
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ReplyAckNotNegotiated => "REPLY_ACK_NOT_NEGOTIATED",
            Self::HostVisibleUnavailable => "HOST_VISIBLE_UNAVAILABLE",
            Self::Timeout => "TIMEOUT",
            Self::PeerClosed => "PEER_CLOSED",
            Self::Transport => "TRANSPORT",
            Self::MalformedReply => "MALFORMED_REPLY",
            Self::RemoteFailure => "REMOTE_FAILURE",
        }
    }
}

/// 失敗の詳細。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendReqCause {
    /// 応答または要求の codec 検査の失敗。
    Codec(BackendCodecErrorCode),
    /// トランスポートの失敗（code と errno）。
    Transport(TransportErrorCode, Option<i32>),
    /// 送れなかった理由（host-visible の未成立）。
    Unavailable(HostVisibleUnavailable),
}

/// 構造化エラー。frontend / ゲスト由来のバイト列・fd 番号は含めない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BackendReqError {
    /// 機械可読な種別。
    pub(crate) code: BackendReqErrorCode,
    /// 対象の backend 要求（frontend 要求の ID とは別型）。
    pub(crate) request: BackendRequestCode,
    /// frontend が返した非 0 の値（`REMOTE_FAILURE` のみ。`-errno as u64` もそのまま持つ）。
    pub(crate) status: Option<u64>,
    /// 詳細。
    pub(crate) cause: Option<BackendReqCause>,
}

impl BackendReqError {
    pub(crate) fn new(code: BackendReqErrorCode, request: BackendRequestCode) -> Self {
        Self {
            code,
            request,
            status: None,
            cause: None,
        }
    }

    pub(crate) fn with_cause(mut self, cause: BackendReqCause) -> Self {
        self.cause = Some(cause);
        self
    }

    fn transport(request: BackendRequestCode, e: TransportError) -> Self {
        let code = match e.code {
            TransportErrorCode::Timeout => BackendReqErrorCode::Timeout,
            TransportErrorCode::PeerClosed => BackendReqErrorCode::PeerClosed,
            _ => BackendReqErrorCode::Transport,
        };
        Self::new(code, request).with_cause(BackendReqCause::Transport(e.code, e.errno))
    }

    /// 治具側の失敗で、以後ストリームの同期が信用できない（channel を `Broken` にすべき）か。
    pub(crate) fn desyncs_channel(&self) -> bool {
        matches!(
            self.code,
            BackendReqErrorCode::Timeout
                | BackendReqErrorCode::PeerClosed
                | BackendReqErrorCode::Transport
                | BackendReqErrorCode::MalformedReply
        )
    }
}

impl fmt::Display for BackendReqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (backend request={})",
            self.code.as_str(),
            self.request.as_str()
        )
    }
}

impl std::error::Error for BackendReqError {}

/// 成功（frontend が 0 を返した）。将来のフィールド追加に備えて構造体にする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BackendAck {
    /// 送った要求。
    pub(crate) request: BackendRequestCode,
    /// frontend が返した値（常に 0）。
    pub(crate) status: u64,
}

fn remaining(deadline: Instant, request: BackendRequestCode) -> Result<Duration, BackendReqError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(
            BackendReqError::new(BackendReqErrorCode::Timeout, request).with_cause(
                BackendReqCause::Transport(TransportErrorCode::Timeout, None),
            ),
        );
    }
    Ok(left)
}

/// `buf` を満たすまで期限内に読む（fd は受け付けない）。
fn read_exact(
    sock: &UnixStream,
    buf: &mut [u8],
    deadline: Instant,
    request: BackendRequestCode,
) -> Result<(), BackendReqError> {
    let mut got = 0usize;
    while got < buf.len() {
        let rest = buf
            .get_mut(got..)
            .ok_or_else(|| BackendReqError::new(BackendReqErrorCode::Transport, request))?;
        let r = recv_with_fds(sock, rest, 0, remaining(deadline, request)?)
            .map_err(|e| BackendReqError::transport(request, e))?;
        got = got.saturating_add(r.len);
    }
    Ok(())
}

/// 要求を送り、応答を検査して frontend の値（成功は 0）を返す。`timeout` は送受信全体の期限。
///
/// `fd` は MAP のときだけ `Some`（借りるだけで所有権は移さない）。失敗の分類は [`BackendReqError::desyncs_channel`]。
pub(crate) fn exchange(
    sock: &UnixStream,
    req: &BackendRequest,
    fd: Option<BorrowedFd<'_>>,
    timeout: Duration,
) -> Result<BackendAck, BackendReqError> {
    let request = req.code();
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        BackendReqError::new(BackendReqErrorCode::Transport, request).with_cause(
            BackendReqCause::Transport(TransportErrorCode::InvalidArgument, None),
        )
    })?;
    let bytes = req.encode();
    let mut off = 0usize;
    let mut fds: Vec<BorrowedFd<'_>> = fd.into_iter().collect();
    while off < bytes.len() {
        let rest = bytes
            .get(off..)
            .ok_or_else(|| BackendReqError::new(BackendReqErrorCode::Transport, request))?;
        let sent = send_with_fds(sock, rest, &fds, remaining(deadline, request)?)
            .map_err(|e| BackendReqError::transport(request, e))?;
        if sent.len == 0 {
            return Err(BackendReqError::transport(
                request,
                TransportError::new(TransportErrorCode::PeerClosed),
            ));
        }
        off = off.saturating_add(sent.len);
        // fd は最初の sendmsg にだけ付ける（再送しない）。
        fds.clear();
    }

    let malformed = |e: BackendCodecError| {
        BackendReqError::new(BackendReqErrorCode::MalformedReply, request)
            .with_cause(BackendReqCause::Codec(e.code))
    };
    let mut header = [0u8; HEADER_LEN];
    read_exact(sock, &mut header, deadline, request)?;
    decode_backend_reply_header(&header, request).map_err(malformed)?;
    let mut payload = [0u8; BACKEND_REPLY_PAYLOAD_LEN];
    read_exact(sock, &mut payload, deadline, request)?;
    let status = decode_backend_reply_value(&payload);
    if status != 0 {
        let mut e = BackendReqError::new(BackendReqErrorCode::RemoteFailure, request);
        e.status = Some(status);
        return Err(e);
    }
    Ok(BackendAck { request, status })
}
