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
    use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
    use std::time::Duration;

    use crate::error::{NetError, NetErrorCode};
    use crate::netlink::{ALIGN_TO, MAX_MESSAGE_LEN, NLMSG_HEADER_LEN, NlMsgHeader};
    use crate::sys::{self, Deadline, Readiness, RecvMeta, SysError};

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
        /// 空・`NLMSG_HEADER_LEN` 未満・`MAX_MESSAGE_LEN` 超、および「アラインした `nlmsg_len` が実長と一致しない（複数メッセージ連結を含む）・末尾パディング（0〜3 バイト）が 0 でない」入力は `InvalidArgument`。部分送信は `DataLoss`。
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
            // 単一メッセージの契約を型ではなく送信前検証で保証する（REPAIR-2）。
            // 復号できない・nlmsg_len が実長と不一致（短い=複数メッセージ連結、長い=切り詰め）は渡さない。
            let header = NlMsgHeader::decode(message).map_err(|e| {
                NetError::new(NetErrorCode::InvalidArgument, e.message().to_string())
            })?;
            // NlMsgBuilder::finish は nlmsg_len に末尾パディングを含めず、バイト列は 4 バイト境界まで 0 埋めする。
            // よって実長は nlmsg_len を 4 バイトへアラインした値と一致し、nlmsg_len 以降（0〜3 バイト）は 0 でなければならない。
            let msg_len = header.len() as usize;
            let aligned_len = msg_len.saturating_add(ALIGN_TO - 1) & !(ALIGN_TO - 1);
            let padding_is_zero = message
                .get(msg_len..)
                .is_some_and(|pad| pad.iter().all(|&b| b == 0));
            if aligned_len != message.len() || !padding_is_zero {
                return Err(NetError::new(
                    NetErrorCode::InvalidArgument,
                    format!(
                        "nlmsg_len {} does not match buffer length {} (single message with zero padding required)",
                        msg_len,
                        message.len()
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
        /// `timeout` は呼び出し全体の期限（REPAIR-5）。開始時刻（単調時計）からの残り時間を毎回
        /// 計算し直すため、次のどの場合も「残り時間だけ待ち直す」動作になり、期限より早く
        /// `Timeout` を返さず、期限を超えても待たない:
        /// - 同じソケットを共有する別スレッドが、`poll` の後に先にデータグラムを読んだ（`EAGAIN`）
        /// - シグナルで `poll` / `recvfrom` が中断された（`EINTR`）
        /// - `timeout` が 1 回の `poll` に渡せる上限（`i32::MAX` ms）を超える
        ///
        /// `timeout` が 0 なら待たず、すでに届いているデータグラムだけを返す。期限内に届かなければ
        /// `Timeout`。切り詰め・カーネル以外の送信元は `DataLoss`（そのデータグラムは破棄済み）。
        /// 返したバイト列の解釈は呼び出し側が `NlMsgIter` で行う。
        pub fn recv(&self, timeout: Duration) -> Result<Vec<u8>, NetError> {
            self.recv_with(timeout, sys::recv_from)
        }

        /// [`recv`](Self::recv) の本体。`try_recv` は待たない 1 回の受信（本番は `sys::recv_from`）で、
        /// 単体試験が「`poll` の後に別の読み手が先に取った」競合を決定的に再現するための差し替え点。
        fn recv_with(
            &self,
            timeout: Duration,
            mut try_recv: impl FnMut(BorrowedFd<'_>, &mut [u8]) -> Result<RecvMeta, SysError>,
        ) -> Result<Vec<u8>, NetError> {
            let deadline = Deadline::after(timeout);
            let timed_out = || {
                NetError::new(
                    NetErrorCode::Timeout,
                    format!("no netlink message within {} ms", timeout.as_millis()),
                )
            };
            let mut buf = vec![0u8; RECV_BUFFER_LEN];
            let meta = loop {
                let readiness = sys::wait_readable(self.fd.as_fd(), &deadline)
                    .map_err(|e| map_sys_error("poll", e))?;
                if readiness == Readiness::TimedOut {
                    return Err(timed_out());
                }
                match try_recv(self.fd.as_fd(), &mut buf) {
                    Ok(meta) => break meta,
                    // 別スレッドが先に読んだ（EAGAIN）・シグナルで中断された（EINTR）。失敗にせず、
                    // 残り時間があれば待ち直す。回数ではなく全体期限で打ち切る（REPAIR-5）。
                    Err(SysError::Os(errno @ (sys::EAGAIN | sys::EINTR))) => {
                        // POLLIN なしの例外状態（POLLERR 等）で保留中の errno も取り出せなかった場合、
                        // 待ち直しても poll が即座に戻り続ける。期限までの空回りを避けてエラーにする。
                        if readiness == Readiness::Exceptional {
                            return Err(NetError::new(
                                NetErrorCode::Internal,
                                format!(
                                    "netlink socket reported an error condition without data (recvfrom errno {errno})"
                                ),
                            ));
                        }
                        if deadline.remaining().is_zero() {
                            return Err(timed_out());
                        }
                    }
                    Err(e) => return Err(map_sys_error("recvfrom", e)),
                }
            };
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
            SysError::BadSenderAddress => NetError::new(
                NetErrorCode::DataLoss,
                format!("{call}: dropped datagram whose sender is not a netlink address"),
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
            let e = map_sys_error("recvfrom", SysError::BadSenderAddress);
            assert_eq!(
                e.to_string(),
                "DATA_LOSS: recvfrom: dropped datagram whose sender is not a netlink address"
            );
            let e = map_sys_error("poll", SysError::Unsupported);
            assert_eq!(
                e.to_string(),
                "UNIMPLEMENTED: poll: unsupported architecture"
            );
        }

        const RTM_NEWLINK: u16 = 16;
        const RTM_GETLINK: u16 = 18;

        /// lo（ifindex 1）1 件だけを問い合わせる非 dump の RTM_GETLINK。非特権で成立し、カーネルは
        /// RTM_NEWLINK 1 件を 1 データグラムで返す（NLM_F_ACK なしのため ACK は返らない）。
        fn getlink_lo(seq: u32) -> Vec<u8> {
            use crate::netlink::{NLM_F_REQUEST, NlMsgBuilder};
            let mut b = NlMsgBuilder::new(RTM_GETLINK, NLM_F_REQUEST, seq, 0);
            // struct ifinfomsg: family(1) pad(1) type(2) index(i32) flags(4) change(4)。
            let mut ifi = [0u8; 16];
            ifi[4..8].copy_from_slice(&1i32.to_ne_bytes());
            b.put_fixed(&ifi).expect("ifinfomsg");
            b.finish().expect("finish")
        }

        /// 受信 1 データグラムの先頭メッセージの (type, seq)。
        fn first_type_and_seq(data: &[u8]) -> (u16, u32) {
            let h = NlMsgHeader::decode(data).expect("header");
            (h.msg_type(), h.seq())
        }

        /// NET-11・REPAIR-5: `poll` 通過後に別の読み手が先にデータグラムを読んでも（`recvfrom` が
        /// EAGAIN）、`Timeout` で失敗せず、期限内に届いた次の応答を受信する。
        ///
        /// 競合の再現: seq=1 の応答が届いて `poll` が通過した直後、1 回目の `try_recv` の中で
        /// 「別の読み手」がその応答を読み取り、続けて seq=2 の要求を送ってから EAGAIN を返す。
        #[test]
        fn recv_keeps_waiting_after_another_reader_wins_the_race() {
            let s = NetlinkRouteSocket::open().expect("open");
            s.send(&getlink_lo(1)).expect("send 1");
            let mut calls = 0u32;
            let mut stolen = None;
            let started = std::time::Instant::now();
            let data = s
                .recv_with(Duration::from_secs(5), |fd, buf| {
                    calls += 1;
                    if calls == 1 {
                        let meta = sys::recv_from(fd, buf).expect("other reader takes it");
                        stolen = Some(first_type_and_seq(buf.get(..meta.len).expect("len")));
                        s.send(&getlink_lo(2)).expect("send 2");
                        return Err(SysError::Os(sys::EAGAIN));
                    }
                    sys::recv_from(fd, buf)
                })
                .expect("recv must continue until the next datagram");
            assert_eq!(stolen, Some((RTM_NEWLINK, 1)));
            assert_eq!(first_type_and_seq(&data), (RTM_NEWLINK, 2));
            assert_eq!(calls, 2);
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        /// NET-11・REPAIR-5: `recvfrom` が EINTR で中断されても同じ扱いで、残り時間内に待ち直して
        /// 同じデータグラムを受信する（回数上限で `Internal` にしない）。
        #[test]
        fn recv_retries_after_eintr_within_the_deadline() {
            let s = NetlinkRouteSocket::open().expect("open");
            s.send(&getlink_lo(7)).expect("send");
            let mut calls = 0u32;
            let data = s
                .recv_with(Duration::from_secs(5), |fd, buf| {
                    calls += 1;
                    if calls <= 20 {
                        return Err(SysError::Os(sys::EINTR));
                    }
                    sys::recv_from(fd, buf)
                })
                .expect("recv");
            assert_eq!(first_type_and_seq(&data), (RTM_NEWLINK, 7));
            assert_eq!(calls, 21);
        }

        /// NET-11・REPAIR-5: 先に読まれたあと次の応答が来なければ、残り時間を待ち切ってから
        /// `Timeout` を返す（即座には返さず、期限を超えても待たない）。
        #[test]
        fn recv_times_out_at_the_deadline_after_losing_the_race() {
            let s = NetlinkRouteSocket::open().expect("open");
            s.send(&getlink_lo(3)).expect("send");
            let mut calls = 0u32;
            let started = std::time::Instant::now();
            let e = s
                .recv_with(Duration::from_millis(300), |fd, buf| {
                    calls += 1;
                    sys::recv_from(fd, buf).expect("other reader takes it");
                    Err(SysError::Os(sys::EAGAIN))
                })
                .expect_err("timeout");
            assert_eq!(e.code(), NetErrorCode::Timeout);
            assert_eq!(e.to_string(), "TIMEOUT: no netlink message within 300 ms");
            assert_eq!(calls, 1);
            assert!(started.elapsed() >= Duration::from_millis(300));
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        /// NET-11・REPAIR-5: 読み続けても毎回先を越される場合でも、期限を過ぎたら `Timeout` で止まる
        /// （受信競合が続いても無期限に回らない）。
        #[test]
        fn recv_stops_at_the_deadline_under_repeated_races() {
            let s = NetlinkRouteSocket::open().expect("open");
            s.send(&getlink_lo(4)).expect("send");
            let started = std::time::Instant::now();
            // データグラムを読まずに EAGAIN を返し続ける（poll は毎回 Readable で即座に戻る）。
            let e = s
                .recv_with(Duration::from_millis(200), |_, _| {
                    Err(SysError::Os(sys::EAGAIN))
                })
                .expect_err("timeout");
            assert_eq!(e.code(), NetErrorCode::Timeout);
            assert!(started.elapsed() >= Duration::from_millis(200));
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        /// NET-11・REPAIR-5: timeout 0 は待たず、届いていなければ直ちに `Timeout`。
        #[test]
        fn recv_with_zero_timeout_does_not_wait() {
            let s = NetlinkRouteSocket::open().expect("open");
            let started = std::time::Instant::now();
            let e = s.recv(Duration::ZERO).expect_err("timeout");
            assert_eq!(e.to_string(), "TIMEOUT: no netlink message within 0 ms");
            assert!(started.elapsed() < Duration::from_secs(5));
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

        /// NET-11・REPAIR-2: nlmsg_len と実長の不一致・複数メッセージ連結は送信前に拒否する。
        #[test]
        fn send_rejects_mismatched_header_len() {
            use crate::netlink::NlMsgBuilder;
            let s = NetlinkRouteSocket::open().expect("open");
            let one = NlMsgBuilder::new(18, crate::netlink::NLM_F_REQUEST, 1, 0)
                .finish()
                .expect("finish");
            assert_eq!(one.len(), NLMSG_HEADER_LEN);
            // 2 メッセージ連結（先頭の nlmsg_len は 16 のまま実長 32）。
            let mut two = one.clone();
            two.extend_from_slice(&one);
            let e = s.send(&two).expect_err("must reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            // ヘッダ長が実長より大きい。
            let mut long_hdr = one.clone();
            long_hdr[0..4].copy_from_slice(&32u32.to_ne_bytes());
            let e = s.send(&long_hdr).expect_err("must reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            // ヘッダ長が 16 未満。
            let mut short_hdr = one;
            short_hdr[0..4].copy_from_slice(&8u32.to_ne_bytes());
            let e = s.send(&short_hdr).expect_err("must reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        }

        /// NET-11・REPAIR-2: 末尾パディングを含む NlMsgBuilder の出力は受理し、非 0 パディング・過剰パディングは拒否する。
        #[test]
        fn send_accepts_padded_builder_output() {
            use crate::netlink::NlMsgBuilder;
            let s = NetlinkRouteSocket::open().expect("open");
            let mut b = NlMsgBuilder::new(18, crate::netlink::NLM_F_REQUEST, 1, 0);
            b.put_fixed(&[1]).expect("fixed");
            let msg = b.finish().expect("finish");
            assert_eq!(u32::from_ne_bytes(msg[0..4].try_into().expect("len")), 17);
            assert_eq!(msg.len(), 20);
            // 受理（カーネル応答の成否は問わず、InvalidArgument でないこと）。
            if let Err(e) = s.send(&msg) {
                assert_ne!(e.code(), NetErrorCode::InvalidArgument);
            }
            let mut dirty = msg.clone();
            dirty[19] = 1;
            let e = s.send(&dirty).expect_err("must reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            let mut over = msg.clone();
            over.extend_from_slice(&[0u8; 4]);
            let e = s.send(&over).expect_err("must reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            let e = s.send(&msg[..17]).expect_err("must reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        }
    }
}
