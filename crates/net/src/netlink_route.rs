//! `NETLINK_ROUTE` 側の入口モジュール（TASK-136・NET-11・MS-8）。
//!
//! ファミリ非依存の nlmsghdr / rtattr コーデック（`crate::netlink`。TASK-136.1・#298）を再公開し、
//! Linux では `NETLINK_ROUTE` ソケットの open / bind / send / recv（[`NetlinkRouteSocket`]。
//! TASK-136.2.1・#843）を提供する。seq 採番・ACK / `NLMSG_ERROR` 判定（#844）・link 操作
//! （#845・#846）・address / route 操作（#301）は未実装で、各 Issue でここへ追加する
//! （REPAIR-3。実装済みを装わない）。

pub use crate::netlink::*;

#[cfg(target_os = "linux")]
pub use socket::{NetlinkRouteSocket, RECV_BUFFER_LEN};

#[cfg(target_os = "linux")]
mod socket {
    use std::fmt;
    use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
    use std::time::Duration;

    use crate::error::{NetError, NetErrorCode};
    use crate::netlink::{MAX_MESSAGE_LEN, NLMSG_HEADER_LEN};
    use crate::sys::{self, SysError};

    /// 受信バッファの固定上限（バイト）。カーネルの申告長に応じた再確保はしない（無制限確保の防止）。
    pub const RECV_BUFFER_LEN: usize = 32 * 1024;

    const _: () = assert!(RECV_BUFFER_LEN <= MAX_MESSAGE_LEN as usize);

    /// bind 済みの `NETLINK_ROUTE` ソケット（NET-11）。
    ///
    /// 未 bind の状態を表現できない（[`open`](Self::open) が open と bind をまとめて行う）。
    /// `nl_pid` はカーネル採番・マルチキャスト購読なし。fd は `SOCK_CLOEXEC` で、Drop で閉じる。
    /// 呼び出し元（#844 以降の request / ACK 層）が `NlMsgBuilder` で組んだバイト列を `send` し、
    /// `recv` の戻りを `NlMsgIter` で解釈する。seq 採番・ACK 判定・採番 pid の取得は未実装（#844）。
    pub struct NetlinkRouteSocket {
        fd: OwnedFd,
    }

    impl fmt::Debug for NetlinkRouteSocket {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("NetlinkRouteSocket")
                .field("fd", &self.fd.as_raw_fd())
                .finish()
        }
    }

    impl NetlinkRouteSocket {
        /// ソケットを開いて bind する。
        pub fn open() -> Result<Self, NetError> {
            let fd = sys::open_route_socket().map_err(|e| map_sys_error("socket", e))?;
            sys::bind_kernel_assigned(fd.as_fd()).map_err(|e| map_sys_error("bind", e))?;
            Ok(Self { fd })
        }

        /// `message`（`NlMsgBuilder` で組んだ 1 メッセージ）をそのままカーネルへ送る。
        ///
        /// 空・`NLMSG_HEADER_LEN` 未満・`MAX_MESSAGE_LEN` 超は `InvalidArgument`。部分送信は `DataLoss`。
        pub fn send(&self, message: &[u8]) -> Result<(), NetError> {
            if message.len() < NLMSG_HEADER_LEN || message.len() > MAX_MESSAGE_LEN as usize {
                return Err(NetError::new(
                    NetErrorCode::InvalidArgument,
                    format!(
                        "netlink message length {} is outside {}..={}",
                        message.len(),
                        NLMSG_HEADER_LEN,
                        MAX_MESSAGE_LEN
                    ),
                ));
            }
            let sent = sys::send_to_kernel(self.fd.as_fd(), message)
                .map_err(|e| map_sys_error("sendto", e))?;
            if sent != message.len() {
                return Err(NetError::new(
                    NetErrorCode::DataLoss,
                    format!("partial netlink send: {} of {} bytes", sent, message.len()),
                ));
            }
            Ok(())
        }

        /// 最大 `timeout` 待って 1 データグラムを受信し、受信長に切り詰めたバイト列を返す。
        ///
        /// 期限内に届かなければ `Timeout`。切り詰め・カーネル以外の送信元は `DataLoss`。
        /// 返したバイト列の解釈は呼び出し側が `NlMsgIter` で行う。
        pub fn recv(&self, timeout: Duration) -> Result<Vec<u8>, NetError> {
            let readable = sys::wait_readable(self.fd.as_fd(), timeout)
                .map_err(|e| map_sys_error("poll", e))?;
            if !readable {
                return Err(NetError::new(
                    NetErrorCode::Timeout,
                    format!("no netlink message within {} ms", timeout.as_millis()),
                ));
            }
            let mut buf = vec![0u8; RECV_BUFFER_LEN];
            let meta = sys::recv_from(self.fd.as_fd(), &mut buf)
                .map_err(|e| map_sys_error("recvfrom", e))?;
            if meta.truncated {
                return Err(NetError::new(
                    NetErrorCode::DataLoss,
                    format!(
                        "netlink datagram of {} bytes exceeds receive buffer of {} bytes",
                        meta.len, RECV_BUFFER_LEN
                    ),
                ));
            }
            if meta.sender_pid != 0 {
                return Err(NetError::new(
                    NetErrorCode::DataLoss,
                    "dropped netlink datagram from a non-kernel sender",
                ));
            }
            buf.truncate(meta.len);
            Ok(buf)
        }
    }

    /// errno を `NetErrorCode` へ写す（メッセージは英語で syscall 名と errno 数値のみ）。
    fn map_sys_error(call: &str, e: SysError) -> NetError {
        match e {
            SysError::Unsupported => NetError::new(
                NetErrorCode::Unimplemented,
                format!("{call}: unsupported architecture"),
            ),
            SysError::Os(errno) => NetError::new(
                classify_errno(errno),
                format!("{call} failed: errno {errno}"),
            ),
        }
    }

    fn classify_errno(errno: i32) -> NetErrorCode {
        match errno {
            sys::EPERM | sys::EACCES => NetErrorCode::PermissionDenied,
            sys::EAFNOSUPPORT | sys::EPROTONOSUPPORT => NetErrorCode::Unimplemented,
            sys::ENOBUFS | sys::ENOMEM | sys::EMFILE | sys::ENFILE | sys::EAGAIN => {
                NetErrorCode::ResourceExhausted
            }
            _ => NetErrorCode::Internal,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// NET-11: errno 写像の具体値。
        #[test]
        fn errno_mapping() {
            assert_eq!(classify_errno(1), NetErrorCode::PermissionDenied);
            assert_eq!(classify_errno(13), NetErrorCode::PermissionDenied);
            assert_eq!(classify_errno(93), NetErrorCode::Unimplemented);
            assert_eq!(classify_errno(97), NetErrorCode::Unimplemented);
            assert_eq!(classify_errno(105), NetErrorCode::ResourceExhausted);
            assert_eq!(classify_errno(24), NetErrorCode::ResourceExhausted);
            assert_eq!(classify_errno(11), NetErrorCode::ResourceExhausted);
            assert_eq!(classify_errno(5), NetErrorCode::Internal);
            let e = map_sys_error("socket", SysError::Os(1));
            assert_eq!(e.to_string(), "PERMISSION_DENIED: socket failed: errno 1");
        }

        /// NET-11: 送信前の入力検証（カーネルへ渡さない）。
        #[test]
        fn send_rejects_bad_lengths() {
            let s = NetlinkRouteSocket::open().expect("open");
            for len in [0usize, 15, MAX_MESSAGE_LEN as usize + 1] {
                let e = s.send(&vec![0u8; len]).expect_err("must reject");
                assert_eq!(e.code(), NetErrorCode::InvalidArgument, "len {len}");
            }
        }
    }
}
