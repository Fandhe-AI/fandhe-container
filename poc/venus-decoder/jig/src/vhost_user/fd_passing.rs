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
//! タイムアウトは呼び出しごとの期限（単調時計）で管理する。`recvmsg` / `sendmsg` は常に `MSG_DONTWAIT` で呼び、読み書きできない間は
//! `ppoll`（`sys::wait_fd`）で残り時間だけ待つ。`SO_RCVTIMEO` / `SO_SNDTIMEO` はソケット全体の設定で、`&UnixStream` を共有する
//! 別スレッドが長い値を設定すると待ち時間が伸びてしまうため使わない（REPAIR-5）。ソケットの blocking / non-blocking にも依存しない。

use std::ffi::CStr;
use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use super::MAX_MEM_REGIONS;
use super::observe::{self, Op};
use super::transport_error::{TransportError, TransportErrorCode};
use crate::sys;

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

/// 送信結果。将来のフィールド追加（fd の送信状態等）に備えて構造体にする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sent {
    /// 送れたデータのバイト数（部分送信なら `data.len()` 未満）。
    pub len: usize,
}

fn err(code: TransportErrorCode) -> TransportError {
    TransportError::new(code)
}

/// データと fd を 1 回の `recvmsg` で受け取る。
///
/// 検査順（fd を漏らさない順序）: 受信 → 補助データの fd をすべて所有 → `MSG_CTRUNC`（`CONTROL_TRUNCATED`）→
/// `MSG_TRUNC`（`DATA_TRUNCATED`）→ 構造異常（`MALFORMED_CONTROL`。読めない fd は回収できないので `MSG_CTRUNC` と同様に
/// 拒否する）→ `SCM_RIGHTS` 以外（`UNEXPECTED_CONTROL`）→ fd 数が `max_fds` 超過（`TOO_MANY_FDS`）→ 0 バイト（`PEER_CLOSED`）。
/// 拒否したときに受け取っていた fd はすべて閉じられる。
///
/// `max_fds` は `0..=MAX_FDS`、`timeout` は 0 より大きく [`MAX_TIMEOUT`] 以下、`buf` は空でないこと（`INVALID_ARGUMENT`）。
pub fn recv_with_fds(
    sock: &UnixStream,
    buf: &mut [u8],
    max_fds: usize,
    timeout: Duration,
) -> Result<Received, TransportError> {
    observe::global().observe(Op::RecvFds, || {
        recv_impl(sock, buf, max_fds, sys::MAX_SCM_FDS, timeout)
    })
}

/// 待ち時間の上限（1 時間）。巨大な値は事実上の無期限待ちになり、
/// 期限（単調時計の加算）も作れなくなるため、入口で `INVALID_ARGUMENT` として拒否する（REPAIR-5）。
pub const MAX_TIMEOUT: Duration = Duration::from_secs(3600);

/// `timeout` を検証して期限を作る。0・上限超過・期限を構築できない値は `INVALID_ARGUMENT`。
fn deadline_for(timeout: Duration) -> Result<Instant, TransportError> {
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(err(TransportErrorCode::InvalidArgument));
    }
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| err(TransportErrorCode::InvalidArgument))
}

/// 期限に達していれば `TIMEOUT`（`EINTR` で再試行する前の確認）。
fn check_deadline(deadline: Instant) -> Result<(), TransportError> {
    if deadline <= Instant::now() {
        return Err(err(TransportErrorCode::Timeout));
    }
    Ok(())
}

/// `deadline` まで `sock` が `interest` になるのを待つ。期限に達していれば `TIMEOUT`。シグナル中断（`EINTR`）は
/// 呼び出し側のループが再試行するので成功として返す。ソケットのタイムアウト設定には依存しない（REPAIR-5）。
fn wait_until(
    sock: &UnixStream,
    interest: sys::Interest,
    deadline: Instant,
) -> Result<(), TransportError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(err(TransportErrorCode::Timeout));
    }
    match sys::wait_fd(sock.as_fd(), interest, remaining) {
        Ok(true) => Ok(()),
        Ok(false) => Err(err(TransportErrorCode::Timeout)),
        Err(sys::SysError::Interrupted(_)) => Ok(()),
        Err(e) => Err(TransportError::from_sys(e)),
    }
}

/// [`recv_with_fds`] の本体。`ctrl_fds` は補助データの受付容量（fd の個数分）で、切り詰め検出の試験だけが
/// `MAX_SCM_FDS` 未満を渡す。
fn recv_impl(
    sock: &UnixStream,
    buf: &mut [u8],
    max_fds: usize,
    ctrl_fds: usize,
    timeout: Duration,
) -> Result<Received, TransportError> {
    if max_fds > MAX_FDS || buf.is_empty() {
        return Err(err(TransportErrorCode::InvalidArgument));
    }
    let deadline = deadline_for(timeout)?;
    // fd は `recvmsg_fds` が受信と同じ呼び出しの中で所有済み。以降の return では Drop で閉じられる。
    let raw = loop {
        match sys::recvmsg_fds(sock.as_fd(), buf, ctrl_fds) {
            Ok(r) => break r,
            Err(sys::SysError::Interrupted(_)) => check_deadline(deadline)?,
            Err(sys::SysError::WouldBlock) => {
                wait_until(sock, sys::Interest::Readable, deadline)?;
            }
            Err(e) => return Err(TransportError::from_sys(e)),
        }
    };
    if raw.control_truncated {
        return Err(err(TransportErrorCode::ControlTruncated));
    }
    if raw.data_truncated {
        return Err(err(TransportErrorCode::DataTruncated));
    }
    if raw.malformed {
        return Err(err(TransportErrorCode::MalformedControl));
    }
    if raw.unexpected {
        return Err(err(TransportErrorCode::UnexpectedControl));
    }
    if raw.fds.len() > max_fds {
        return Err(err(TransportErrorCode::TooManyFds));
    }
    if raw.len == 0 {
        return Err(err(TransportErrorCode::PeerClosed));
    }
    Ok(Received {
        len: raw.len,
        fds: raw.fds,
    })
}

/// データと fd を 1 回の `sendmsg` で送り、送れたバイト数を [`Sent`] で返す（部分送信はあり得る）。
///
/// backend から frontend への fd 送信は後送り（BACKEND_REQ・#1057）だが、F1.4 の偽 frontend とテストが使うので公開する。
/// `fds` は `MAX_FDS` 以下、`data` は空でなく、`timeout` は 0 より大きく [`MAX_TIMEOUT`] 以下であること（`INVALID_ARGUMENT`）。
pub fn send_with_fds(
    sock: &UnixStream,
    data: &[u8],
    fds: &[BorrowedFd<'_>],
    timeout: Duration,
) -> Result<Sent, TransportError> {
    observe::global().observe(Op::SendFds, || {
        if fds.len() > MAX_FDS || data.is_empty() {
            return Err(err(TransportErrorCode::InvalidArgument));
        }
        let deadline = deadline_for(timeout)?;
        loop {
            match sys::sendmsg_fds(sock.as_fd(), data, fds) {
                Ok(len) => return Ok(Sent { len }),
                Err(sys::SysError::Interrupted(_)) => check_deadline(deadline)?,
                Err(sys::SysError::WouldBlock) => {
                    wait_until(sock, sys::Interest::Writable, deadline)?;
                }
                Err(e) => return Err(TransportError::from_sys(e)),
            }
        }
    })
}

/// 長さ `len` の memfd（close-on-exec）を作り、縮小を禁じる `F_SEAL_SHRINK` を付ける。テストと F1.4 の偽 frontend が
/// ゲストメモリ領域の代わりに使う（`GuestMemoryRegion::map` は縮小が封じられた fd だけを受け付ける）。
/// `name` は `/proc/self/maps` に出る識別名で、秘密情報を入れない。
/// 結果と所要時間は観測カウンタに計上する（REPAIR-4）。
pub fn create_memfd(name: &CStr, len: u64) -> Result<File, TransportError> {
    observe::global().observe(Op::MemfdCreate, || {
        let fd = sys::memfd_create_cloexec(name, true).map_err(TransportError::from_sys)?;
        let file = File::from(fd);
        file.set_len(len).map_err(|e| TransportError::from_io(&e))?;
        sys::add_shrink_seal(file.as_fd()).map_err(TransportError::from_sys)?;
        Ok(file)
    })
}

/// [`create_memfd`] の seal なし版。`GuestMemoryRegion::map` の拒否経路（`SHRINK_NOT_SEALED`）の試験専用で、
/// `MFD_ALLOW_SEALING` を付けないため後から seal を足せない。
/// [`create_memfd`] と同じ `MemfdCreate` として計上する。
pub fn create_memfd_unsealed(name: &CStr, len: u64) -> Result<File, TransportError> {
    observe::global().observe(Op::MemfdCreate, || {
        let fd = sys::memfd_create_cloexec(name, false).map_err(TransportError::from_sys)?;
        let file = File::from(fd);
        file.set_len(len).map_err(|e| TransportError::from_io(&e))?;
        Ok(file)
    })
}

// 実際の syscall を使うので、定数を定義している x86_64 / aarch64 でだけ走らせる（他アーキは `UNSUPPORTED` を返す）。
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
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
        let e = recv_impl(&b, &mut buf, MAX_FDS, 2, Duration::from_secs(5)).expect_err("truncated");
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

    /// GPU-6・REPAIR-5: 上限超過・巨大な timeout は入口で `INVALID_ARGUMENT`、上限ちょうどは受理される。
    #[test]
    fn gpu6_timeout_is_capped_at_entry() {
        let (a, b) = UnixStream::pair().expect("pair");
        let mut buf = [0u8; 4];
        for t in [
            Duration::MAX,
            MAX_TIMEOUT + Duration::from_nanos(1),
            Duration::ZERO,
        ] {
            let e = recv_with_fds(&b, &mut buf, 0, t).expect_err("recv");
            assert_eq!(e.code, TransportErrorCode::InvalidArgument);
            let e = send_with_fds(&a, b"x", &[], t).expect_err("send");
            assert_eq!(e.code, TransportErrorCode::InvalidArgument);
        }
        // 上限ちょうどは受理され、データが既にあれば即座に返る。
        assert_eq!(
            send_with_fds(&a, b"x", &[], MAX_TIMEOUT).expect("send"),
            Sent { len: 1 }
        );
        let r = recv_with_fds(&b, &mut buf, 0, MAX_TIMEOUT).expect("recv");
        assert_eq!((r.len, r.fds.len()), (1, 0));
    }

    /// GPU-6・REPAIR-5: 別スレッドが共有ソケットへ長い `SO_RCVTIMEO` / `SO_SNDTIMEO` を設定しても、呼び出しごとの期限で `TIMEOUT` になる。
    #[test]
    fn gpu6_timeout_ignores_shared_socket_timeout() {
        let (a, b) = UnixStream::pair().expect("pair");
        let b2 = b.try_clone().expect("clone");
        b2.set_read_timeout(Some(Duration::from_secs(3000)))
            .expect("set");
        let mut buf = [0u8; 4];
        let t = Instant::now();
        let e = recv_with_fds(&b, &mut buf, 0, Duration::from_millis(100)).expect_err("timeout");
        assert_eq!(e.code, TransportErrorCode::Timeout);
        assert!(t.elapsed() < Duration::from_secs(10));
        // 送信側: バッファを埋めてから送ると期限で TIMEOUT になる。
        a.set_write_timeout(Some(Duration::from_secs(3000)))
            .expect("set");
        let chunk = [0u8; 65536];
        let mut last = None;
        let t = Instant::now();
        for _ in 0..4096 {
            match send_with_fds(&a, &chunk, &[], Duration::from_millis(100)) {
                Ok(_) => {}
                Err(e) => {
                    last = Some(e);
                    break;
                }
            }
        }
        assert_eq!(last.expect("full").code, TransportErrorCode::Timeout);
        assert!(t.elapsed() < Duration::from_secs(30));
    }

    /// GPU-6・REPAIR-4: 成功・失敗が全体の観測カウンタに計上される（他テストと並行するため増分で照合する）。
    #[test]
    fn gpu6_io_is_observed() {
        let m = observe::global();
        let before_send = m.snapshot(Op::SendFds);
        let before_recv = m.snapshot(Op::RecvFds);
        let (a, b) = UnixStream::pair().expect("pair");
        send_with_fds(&a, b"x", &[], Duration::from_secs(5)).expect("send");
        let mut buf = [0u8; 4];
        recv_with_fds(&b, &mut buf, 0, Duration::from_secs(5)).expect("recv");
        recv_with_fds(&b, &mut buf, 0, Duration::ZERO).expect_err("invalid");
        let (s, r) = (m.snapshot(Op::SendFds), m.snapshot(Op::RecvFds));
        assert!(s.ok > before_send.ok);
        assert!(r.ok > before_recv.ok);
        assert!(r.err > before_recv.err);
        let i = TransportErrorCode::InvalidArgument as usize;
        assert!(r.by_code[i] > before_recv.by_code[i]);
    }
}
