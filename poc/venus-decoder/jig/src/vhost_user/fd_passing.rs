//! `SCM_RIGHTS` による fd の送受信（GPU-6・MVM-4・REPAIR-5・TASK-172 F1.2・#1517）。
//!
//! 役割: vhost-user の frontend が UDS の補助データで渡すゲストメモリ領域の fd と eventfd を、上限・切り詰め検出・
//! close-on-exec・タイムアウトつきで受け取る安全な入口。呼び出し元は後続の F1.4（セッション。#1519）と偽 frontend の
//! 結合テスト。syscall は `crate::sys`（unsafe の承認範囲）に閉じる。
//!
//! 範囲外（実装済みを装わない。REPAIR-3）: vhost-user の 12 バイトヘッダ単位の読み書き・セッション状態・UDS の bind と
//! peer credential の検証・eventfd の待機は F1.4（#1519）。ここは「1 回の `recvmsg` / `sendmsg`」までを担当する。
//!
//! 入力は frontend 由来の untrusted。fd は検証より前にすべて `OwnedFd` にし、どのエラー経路でも `Drop` で閉じる（fd 漏れ防止）。
//! タイムアウトは `SO_RCVTIMEO` / `SO_SNDTIMEO`（std の `set_read_timeout` / `set_write_timeout`）で実現し、`poll` は使わない。
//! ソケットは blocking 前提で、non-blocking のソケットでは即座に `TIMEOUT` になる。

use std::ffi::CStr;
use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use super::MAX_MEM_REGIONS;
use super::transport_error::{TransportError, TransportErrorCode};
use crate::sys::{self, CMSG_HDR_LEN, CmsgBuf};

/// 1 回に受け取れる fd 数の上限。`SET_MEM_TABLE` の最大領域数と同じ 32。
pub const MAX_FDS: usize = MAX_MEM_REGIONS;

const _: () = assert!(MAX_FDS == sys::MAX_SCM_FDS);

/// 受信結果。将来のフィールド追加に備えて構造体にする。
#[derive(Debug)]
pub struct Received {
    /// 受信したデータのバイト数（1 以上）。
    pub len: usize,
    /// 受け取った fd（close-on-exec 済み。個数は `max_fds` 以下）。
    pub fds: Vec<OwnedFd>,
}

fn err(code: TransportErrorCode) -> TransportError {
    TransportError::new(code)
}

/// 補助データを走査して `SCM_RIGHTS` の fd をすべて `OwnedFd` にする。
///
/// 構造の異常は `malformed`、`SCM_RIGHTS` 以外は `unexpected` として返し、fd の回収は異常があっても続ける
/// （回収できた fd は呼び出し側で `Drop` される）。`cmsg_len` が範囲外のときは以降を読めないので走査を打ち切る。
fn collect_fds(ctrl: &[u8]) -> (Vec<OwnedFd>, bool, bool) {
    let mut fds = Vec::new();
    let (mut malformed, mut unexpected) = (false, false);
    let mut off = 0usize;
    while off < ctrl.len() {
        let hdr = ctrl.get(off..).and_then(|b| b.get(..CMSG_HDR_LEN));
        let Some(hdr) = hdr else {
            malformed = true;
            break;
        };
        let cmsg_len = hdr
            .get(0..8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_ne_bytes)
            .and_then(|v| usize::try_from(v).ok());
        let level = hdr
            .get(8..12)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(i32::from_ne_bytes);
        let kind = hdr
            .get(12..16)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(i32::from_ne_bytes);
        let (Some(cmsg_len), Some(level), Some(kind)) = (cmsg_len, level, kind) else {
            malformed = true;
            break;
        };
        let data = off
            .checked_add(cmsg_len)
            .filter(|_| cmsg_len >= CMSG_HDR_LEN)
            .and_then(|end| ctrl.get(off + CMSG_HDR_LEN..end));
        let Some(data) = data else {
            malformed = true;
            break;
        };
        if level == sys::SOL_SOCKET && kind == sys::SCM_RIGHTS {
            let (chunks, rest) = data.as_chunks::<4>();
            if !rest.is_empty() {
                malformed = true;
            }
            for c in chunks {
                let owned = sys::owned_fd_from_received(i32::from_ne_bytes(*c));
                match owned {
                    Some(fd) => fds.push(fd),
                    None => malformed = true,
                }
            }
        } else {
            unexpected = true;
        }
        off = match off.checked_add(sys::cmsg_align(cmsg_len)) {
            Some(n) => n,
            None => {
                malformed = true;
                break;
            }
        };
    }
    (fds, malformed, unexpected)
}

/// データと fd を 1 回の `recvmsg` で受け取る。
///
/// 検査順（fd を漏らさない順序）: 受信 → 補助データの fd をすべて所有 → `MSG_CTRUNC`（`CONTROL_TRUNCATED`）→
/// `MSG_TRUNC`（`DATA_TRUNCATED`）→ 構造異常（`MALFORMED_CONTROL`。読めない fd は回収できないので `MSG_CTRUNC` と同様に
/// 拒否する）→ `SCM_RIGHTS` 以外（`UNEXPECTED_CONTROL`）→ fd 数が `max_fds` 超過（`TOO_MANY_FDS`）→ 0 バイト（`PEER_CLOSED`）。
/// 拒否したときに受け取っていた fd はすべて閉じられる。
///
/// `max_fds` は `0..=MAX_FDS`、`timeout` は 0 より大きく、`buf` は空でないこと（`INVALID_ARGUMENT`）。
pub fn recv_with_fds(
    sock: &UnixStream,
    buf: &mut [u8],
    max_fds: usize,
    timeout: Duration,
) -> Result<Received, TransportError> {
    recv_impl(sock, buf, max_fds, sys::CMSG_BUF_LEN, timeout)
}

/// [`recv_with_fds`] の本体。`ctrl_cap` は補助データの受付上限で、切り詰め検出の試験だけが `CMSG_BUF_LEN` 未満を渡す。
fn recv_impl(
    sock: &UnixStream,
    buf: &mut [u8],
    max_fds: usize,
    ctrl_cap: usize,
    timeout: Duration,
) -> Result<Received, TransportError> {
    if max_fds > MAX_FDS || timeout.is_zero() || buf.is_empty() {
        return Err(err(TransportErrorCode::InvalidArgument));
    }
    let deadline = Instant::now().checked_add(timeout);
    let mut remaining = timeout;
    let mut ctrl = CmsgBuf::new();
    let raw = loop {
        sock.set_read_timeout(Some(remaining))
            .map_err(|e| TransportError::from_io(&e))?;
        match sys::recvmsg_fds(sock.as_fd(), buf, &mut ctrl, ctrl_cap) {
            Ok(r) => break r,
            Err(sys::SysError::Os(n)) if n == sys::EINTR => {
                // 単調時計で残り時間を計算し直す。尽きていれば TIMEOUT。
                remaining = deadline
                    .map(|d| d.saturating_duration_since(Instant::now()))
                    .unwrap_or(timeout);
                if remaining.is_zero() {
                    return Err(err(TransportErrorCode::Timeout));
                }
            }
            Err(e) => return Err(TransportError::from_sys(e)),
        }
    };
    let ctrl_bytes = ctrl.as_bytes().get(..raw.ctrl_len).unwrap_or(&[]);
    // 先にすべての fd を所有する。以降の return では Drop で閉じられる。
    let (fds, malformed, unexpected) = collect_fds(ctrl_bytes);
    if raw.flags & sys::MSG_CTRUNC != 0 {
        return Err(err(TransportErrorCode::ControlTruncated));
    }
    if raw.flags & sys::MSG_TRUNC != 0 {
        return Err(err(TransportErrorCode::DataTruncated));
    }
    if malformed {
        return Err(err(TransportErrorCode::MalformedControl));
    }
    if unexpected {
        return Err(err(TransportErrorCode::UnexpectedControl));
    }
    if fds.len() > max_fds {
        return Err(err(TransportErrorCode::TooManyFds));
    }
    if raw.len == 0 {
        return Err(err(TransportErrorCode::PeerClosed));
    }
    Ok(Received { len: raw.len, fds })
}

/// データと fd を 1 回の `sendmsg` で送り、送れたバイト数を返す（部分送信はあり得る）。
///
/// backend から frontend への fd 送信は後送り（BACKEND_REQ・#1057）だが、F1.4 の偽 frontend とテストが使うので公開する。
/// `fds` は `MAX_FDS` 以下、`data` は空でなく、`timeout` は 0 より大きいこと（`INVALID_ARGUMENT`）。
pub fn send_with_fds(
    sock: &UnixStream,
    data: &[u8],
    fds: &[BorrowedFd<'_>],
    timeout: Duration,
) -> Result<usize, TransportError> {
    if fds.len() > MAX_FDS || data.is_empty() || timeout.is_zero() {
        return Err(err(TransportErrorCode::InvalidArgument));
    }
    let deadline = Instant::now().checked_add(timeout);
    let mut remaining = timeout;
    loop {
        sock.set_write_timeout(Some(remaining))
            .map_err(|e| TransportError::from_io(&e))?;
        match sys::sendmsg_fds(sock.as_fd(), data, fds) {
            Ok(n) => return Ok(n),
            Err(sys::SysError::Os(n)) if n == sys::EINTR => {
                remaining = deadline
                    .map(|d| d.saturating_duration_since(Instant::now()))
                    .unwrap_or(timeout);
                if remaining.is_zero() {
                    return Err(err(TransportErrorCode::Timeout));
                }
            }
            Err(e) => return Err(TransportError::from_sys(e)),
        }
    }
}

/// 長さ `len` の memfd（close-on-exec）を作り、縮小を禁じる `F_SEAL_SHRINK` を付ける。テストと F1.4 の偽 frontend が
/// ゲストメモリ領域の代わりに使う（`GuestMemoryRegion::map` は縮小が封じられた fd だけを受け付ける）。
/// `name` は `/proc/self/maps` に出る識別名で、秘密情報を入れない。
pub fn create_memfd(name: &CStr, len: u64) -> Result<File, TransportError> {
    let fd = sys::memfd_create_cloexec(name, true).map_err(TransportError::from_sys)?;
    let file = File::from(fd);
    file.set_len(len).map_err(|e| TransportError::from_io(&e))?;
    sys::fcntl_add_seals(file.as_fd(), sys::F_SEAL_SHRINK).map_err(TransportError::from_sys)?;
    Ok(file)
}

/// [`create_memfd`] の seal なし版。`GuestMemoryRegion::map` の拒否経路（`SHRINK_NOT_SEALED`）の試験専用で、
/// `MFD_ALLOW_SEALING` を付けないため後から seal を足せない。
pub fn create_memfd_unsealed(name: &CStr, len: u64) -> Result<File, TransportError> {
    let fd = sys::memfd_create_cloexec(name, false).map_err(TransportError::from_sys)?;
    let file = File::from(fd);
    file.set_len(len).map_err(|e| TransportError::from_io(&e))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    /// GPU-6: 補助データの受付上限より多い fd を送ると `CONTROL_TRUNCATED` になり、受け取れた fd も閉じられる。
    #[test]
    fn gpu6_control_truncation_is_rejected_and_fds_are_closed() {
        let (a, b) = UnixStream::pair().expect("pair");
        let f = create_memfd(c"jig-ctrunc", 8).expect("memfd");
        let fds = [f.as_fd(), f.as_fd(), f.as_fd()];
        send_with_fds(&a, b"x", &fds, Duration::from_secs(5)).expect("send");
        let mut buf = [0u8; 4];
        // 2 個分（CMSG_SPACE(8) = 24 バイト）だけ受け付ける。
        let e = recv_impl(
            &b,
            &mut buf,
            MAX_FDS,
            sys::cmsg_space(8),
            Duration::from_secs(5),
        )
        .expect_err("truncated");
        assert_eq!(e.code, TransportErrorCode::ControlTruncated);
        let needle = "/memfd:jig-ctrunc (deleted)";
        let count = || {
            std::fs::read_dir("/proc/self/fd")
                .expect("fd dir")
                .filter_map(|e| e.ok())
                .filter_map(|e| std::fs::read_link(e.path()).ok())
                .filter(|l| l.to_string_lossy() == needle)
                .count()
        };
        // 送信側の元の fd だけが残る。
        assert_eq!(count(), 1);
        assert!(f.as_raw_fd() >= 0);
    }

    /// GPU-6: `cmsg_len` が範囲外の補助データは `MALFORMED_CONTROL` として拒否する（解析の単体照合）。
    #[test]
    fn gpu6_malformed_cmsg_is_flagged() {
        // cmsg_len = 100 だが実データは 24 バイトだけ。
        let mut ctrl = [0u8; 24];
        ctrl[0..8].copy_from_slice(&100u64.to_ne_bytes());
        ctrl[8..12].copy_from_slice(&sys::SOL_SOCKET.to_ne_bytes());
        ctrl[12..16].copy_from_slice(&sys::SCM_RIGHTS.to_ne_bytes());
        let (fds, malformed, unexpected) = collect_fds(&ctrl);
        assert!(fds.is_empty());
        assert!(malformed);
        assert!(!unexpected);
        // cmsg_len が 16 未満。
        let mut short = [0u8; 16];
        short[0..8].copy_from_slice(&8u64.to_ne_bytes());
        let (_, malformed, _) = collect_fds(&short);
        assert!(malformed);
        // SCM_RIGHTS 以外（level=1・type=2）。
        let mut other = [0u8; 24];
        other[0..8].copy_from_slice(&20u64.to_ne_bytes());
        other[8..12].copy_from_slice(&sys::SOL_SOCKET.to_ne_bytes());
        other[12..16].copy_from_slice(&2i32.to_ne_bytes());
        let (_, malformed, unexpected) = collect_fds(&other);
        assert!(!malformed);
        assert!(unexpected);
    }
}
