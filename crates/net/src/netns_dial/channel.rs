//! `netns-dial` helper の親側の端（plugin-cri 側。Linux のみ。CRI-6・NET-3・SEC-1・REPAIR-2・REPAIR-5・#4480）。
//!
//! 呼び出し元は #4484 の `PodNetnsDialer`（dial ごとに helper を spawn する側）。設計の手順 3・5 を担う。
//! socketpair を作り（[`NetnsDialChannel::pair`]）、子の端を helper の stdin にして spawn した後、要求 frame と
//! user / net namespace の fd 2 本を [`NetnsDialChannel::send_request`] で送り、[`NetnsDialChannel::wait_response`]
//! で応答を期限つきで受けて、返ってきた fd を `verify_dialed_socket` に通してから `TcpStream` にする。
//! 本モジュールはプロセスを起動も回収もしない（`netns_holder::channel` と同じ分担）。
//!
//! # 検査の順序（SEC-1。helper の応答は untrusted）
//! 1. 期限が `(0, MAX_RESPONSE_TIMEOUT]` 内であること
//! 2. 期待する netns が自プロセスの netns でないこと（host の loopback への接続を受け入れない多層防御）
//! 3. 受信は固定長 buffer・fd 最大 1 本。`data_truncated`・`ctrl_truncated` はどちらも `Protocol`
//!    （`recv_one_fd` は 0 本の応答も `Ok` で返すため、本数の検査はここで行う）
//! 4. frame の decode、`Error` に fd が添わないこと、`Connected` の fd がちょうど 1 本であること
//! 5. `verify_dialed_socket`（種別・peer・local・`SIOCGSKNS` の netns）。失敗は fd を閉じて `Rejected`
//!
//! 失敗は固定語彙（[`NetnsDialFailure`]）で返し、gRPC status への写像は呼び出し側（#4484）が決める。
//! `NetError` への変換の文は固定の英語で、port・pid・パス・errno を含めない（REPAIR-4）。

use std::fs::File;
use std::net::TcpStream;
use std::num::NonZeroU16;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::time::Duration;

use super::frame::{
    DialErrorCode, DialRequest, DialRequestFrame, DialResponse, DialResponseFrame, FRAME_LEN,
};
use super::verify::{DialExpectation, DialedSocketError, NsId, verify_dialed_socket};
use crate::error::{NetError, NetErrorCode};
use crate::sys::holder as sysh;
use crate::sys::{self, Deadline, Readiness, SysError};

/// 応答を待つ期限の上限（helper の connect 期限の上限 `MAX_CONNECT_TIMEOUT_MS` に余裕を足した値。REPAIR-5）。
pub const MAX_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// errno の分類。`netns_holder::holder::classify` と同じ写像（あちらは `pub(super)` で別モジュールのため、
/// 2 か所の写像を共有する下位モジュールを作らず複製する。差が出たら両方を直す）。
fn classify(e: SysError) -> NetErrorCode {
    match e {
        SysError::Unsupported => NetErrorCode::Unimplemented,
        SysError::Os(n) if n == sys::EPERM || n == sys::EACCES => NetErrorCode::PermissionDenied,
        SysError::Os(n) if n == sys::EINVAL || n == sysh::ENOTSOCK || n == sysh::EPIPE => {
            NetErrorCode::FailedPrecondition
        }
        SysError::Os(n) if n == sys::EMFILE || n == sys::ENFILE || n == sys::ENOMEM => {
            NetErrorCode::ResourceExhausted
        }
        _ => NetErrorCode::Internal,
    }
}

fn sys_err(e: SysError, message: &'static str) -> NetError {
    NetError::new(classify(e), message)
}

fn precondition(message: &'static str) -> NetError {
    NetError::new(NetErrorCode::FailedPrecondition, message)
}

fn stat_fd(f: &File) -> Result<NsId, NetError> {
    f.metadata()
        .map(|m| NsId::new(m.dev(), m.ino()))
        .map_err(|_| NetError::new(NetErrorCode::Internal, "cannot stat a namespace descriptor"))
}

fn stat_path(path: &str) -> Result<NsId, NetError> {
    std::fs::metadata(path)
        .map(|m| NsId::new(m.dev(), m.ino()))
        .map_err(|_| NetError::new(NetErrorCode::Internal, "cannot stat an own namespace"))
}

/// 保持役の user / net namespace の fd の組。順（user、net）を型で固定する。
#[derive(Debug)]
pub struct NetnsDialFds {
    user: File,
    net: File,
}

impl NetnsDialFds {
    /// `user`・`net` の順に fd を受け取る。2 本が同じ nsfs 上の別の namespace であること、かつ
    /// 自プロセスの user / net namespace でないことを確かめる（違えば `FailedPrecondition`）。
    pub fn new(user: OwnedFd, net: OwnedFd) -> Result<Self, NetError> {
        let fds = Self::distinct(user, net)?;
        if stat_fd(&fds.user)? == stat_path("/proc/self/ns/user")?
            || stat_fd(&fds.net)? == stat_path("/proc/self/ns/net")?
        {
            return Err(precondition(
                "the namespace descriptors refer to a namespace of this process",
            ));
        }
        Ok(fds)
    }

    /// 自プロセスの ns との照合を除いた検査（試験が自 ns の fd で送信部を確かめるために分けてある）。
    fn distinct(user: OwnedFd, net: OwnedFd) -> Result<Self, NetError> {
        let user = File::from(user);
        let net = File::from(net);
        let (u, n) = (stat_fd(&user)?, stat_fd(&net)?);
        if u.dev() != n.dev() || u.ino() == n.ino() {
            return Err(precondition(
                "the namespace descriptors are not distinct namespaces on one filesystem",
            ));
        }
        Ok(Self { user, net })
    }

    /// 送る net namespace の (dev, ino)。plugin-cri が保持役の READY で保存した識別との照合に使う。
    pub fn net_id(&self) -> NsId {
        // `new` / `distinct` が stat 済みだが、fd は保持しているため再度取る。失敗は到達しない想定で 0 を返さず
        // 呼び出し側が不一致で拒否する値（最大値）にする。
        stat_fd(&self.net).unwrap_or(NsId::new(u64::MAX, u64::MAX))
    }
}

/// 送信済みの要求。port を [`NetnsDialChannel::wait_response`] へ受け渡す（port の取り違えを型で塞ぐ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentDial {
    port: NonZeroU16,
}

impl SentDial {
    /// 要求した宛先 port。
    pub fn port(&self) -> NonZeroU16 {
        self.port
    }
}

/// `wait_response` の失敗の分類（固定語彙。`#[non_exhaustive]`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetnsDialFailure {
    /// helper が `Error{code}` を返した。
    Helper(DialErrorCode),
    /// 期限内に応答が無かった。
    TimedOut,
    /// 応答の前に helper の端が閉じた（EOF）。
    HelperExited,
    /// decode 失敗・切り詰め・fd の本数違い・`Error` に fd が添った。
    Protocol,
    /// 期待する netns が自プロセスの netns と同じ（fail-closed）。
    OwnNetns,
    /// `verify_dialed_socket` が拒否した。
    Rejected(DialedSocketError),
    /// 期限が `(0, MAX_RESPONSE_TIMEOUT]` の外（呼び出し側の誤り）。
    InvalidTimeout,
    /// poll / recv の想定外の errno。
    Io,
}

impl NetnsDialFailure {
    /// 機械可読な固定語彙。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Helper(DialErrorCode::Refused) => "helper:refused",
            Self::Helper(DialErrorCode::TimedOut) => "helper:timed_out",
            Self::Helper(DialErrorCode::Unreachable) => "helper:unreachable",
            Self::Helper(DialErrorCode::JoinFailed) => "helper:join_failed",
            Self::Helper(DialErrorCode::IdentityMismatch) => "helper:identity_mismatch",
            Self::Helper(DialErrorCode::InvalidRequest) => "helper:invalid_request",
            Self::TimedOut => "timed_out",
            Self::HelperExited => "helper_exited",
            Self::Protocol => "protocol",
            Self::OwnNetns => "own_netns",
            Self::Rejected(e) => match e.reason() {
                Some(r) => match r {
                    super::verify::DialedSocketRejection::NotSocket => "rejected:not_socket",
                    super::verify::DialedSocketRejection::NotStream => "rejected:not_stream",
                    super::verify::DialedSocketRejection::NotInet => "rejected:not_inet",
                    super::verify::DialedSocketRejection::NotTcp => "rejected:not_tcp",
                    super::verify::DialedSocketRejection::NotConnected => "rejected:not_connected",
                    super::verify::DialedSocketRejection::PeerMismatch => "rejected:peer_mismatch",
                    super::verify::DialedSocketRejection::LocalNotLoopback => {
                        "rejected:local_not_loopback"
                    }
                    super::verify::DialedSocketRejection::NetnsUnavailable => {
                        "rejected:netns_unavailable"
                    }
                    super::verify::DialedSocketRejection::NetnsMismatch => {
                        "rejected:netns_mismatch"
                    }
                },
                None => "rejected:unexpected",
            },
            Self::InvalidTimeout => "invalid_timeout",
            Self::Io => "io",
        }
    }
}

/// `wait_response` の失敗。分類と、`Io` のときの errno を構造化フィールドとして持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetnsDialError {
    failure: NetnsDialFailure,
    errno: Option<i32>,
}

impl NetnsDialError {
    fn new(failure: NetnsDialFailure) -> Self {
        Self {
            failure,
            errno: None,
        }
    }

    /// 失敗の分類。gRPC status への写像は呼び出し側（#4484）が決める。
    pub fn failure(&self) -> NetnsDialFailure {
        self.failure
    }

    /// `Io` のときの errno（文には含めない。REPAIR-4）。
    pub fn errno(&self) -> Option<i32> {
        self.errno
    }
}

impl From<NetnsDialError> for NetError {
    fn from(e: NetnsDialError) -> Self {
        let (code, msg) = match e.failure {
            NetnsDialFailure::TimedOut => (
                NetErrorCode::Timeout,
                "timed out waiting for the netns-dial helper",
            ),
            NetnsDialFailure::Helper(DialErrorCode::TimedOut) => (
                NetErrorCode::Timeout,
                "the netns-dial helper timed out connecting inside the namespace",
            ),
            NetnsDialFailure::Helper(DialErrorCode::InvalidRequest) => (
                NetErrorCode::Internal,
                "the netns-dial helper rejected the request",
            ),
            NetnsDialFailure::Helper(_) => (
                NetErrorCode::FailedPrecondition,
                "the netns-dial helper could not connect inside the namespace",
            ),
            NetnsDialFailure::HelperExited => (
                NetErrorCode::FailedPrecondition,
                "the netns-dial helper exited before responding",
            ),
            NetnsDialFailure::Protocol => (
                NetErrorCode::FailedPrecondition,
                "the netns-dial helper sent an unexpected response",
            ),
            NetnsDialFailure::OwnNetns => (
                NetErrorCode::FailedPrecondition,
                "the expected network namespace is a namespace of this process",
            ),
            NetnsDialFailure::Rejected(r) => return NetError::from(r),
            NetnsDialFailure::InvalidTimeout => (
                NetErrorCode::InvalidArgument,
                "the response timeout must be in (0, MAX_RESPONSE_TIMEOUT]",
            ),
            NetnsDialFailure::Io => (
                NetErrorCode::Internal,
                "cannot communicate with the netns-dial helper",
            ),
        };
        NetError::new(code, msg)
    }
}

/// 親側の端。drop すると端が閉じ、helper は EOF で終了する。
#[derive(Debug)]
pub struct NetnsDialChannel {
    fd: OwnedFd,
}

impl NetnsDialChannel {
    /// `SOCK_SEQPACKET` の socketpair を作り、`(親の端, helper の stdin にする端)` を返す（両端とも close-on-exec）。
    pub fn pair() -> Result<(Self, OwnedFd), NetError> {
        let (mine, child) = sysh::socketpair_seqpacket()
            .map_err(|e| sys_err(e, "cannot create the netns-dial socket pair"))?;
        Ok((Self { fd: mine }, child))
    }

    /// 要求 frame と user・net の fd を 1 通で送り（`MSG_DONTWAIT`）、送った後に fd を閉じる（pin しない）。
    pub fn send_request(&self, req: DialRequest, fds: NetnsDialFds) -> Result<SentDial, NetError> {
        let frame = DialRequestFrame::encode(req);
        sysh::send_with_fds(
            self.fd.as_fd(),
            frame.as_bytes(),
            &[fds.user.as_fd(), fds.net.as_fd()],
            true,
        )
        .map_err(|e| sys_err(e, "cannot send the request to the netns-dial helper"))?;
        Ok(SentDial { port: req.port() })
    }

    /// 応答を `timeout` 以内（0 より大きく [`MAX_RESPONSE_TIMEOUT`] 以下）に受け、検証済みの `TcpStream` を返す。
    /// `expected_netns` は plugin-cri が保持役の READY で保存した識別（送った fd から導出しない）。
    pub fn wait_response(
        &self,
        sent: &SentDial,
        expected_netns: NsId,
        timeout: Duration,
    ) -> Result<TcpStream, NetnsDialError> {
        let fail = NetnsDialError::new;
        if timeout.is_zero() || timeout > MAX_RESPONSE_TIMEOUT {
            return Err(fail(NetnsDialFailure::InvalidTimeout));
        }
        // 自プロセスの netns が期待値なら、受信の前に拒否する（取れなければ fail-closed）。
        match stat_path("/proc/self/ns/net") {
            Ok(own) if own == expected_netns => return Err(fail(NetnsDialFailure::OwnNetns)),
            Ok(_) => {}
            Err(_) => return Err(fail(NetnsDialFailure::Io)),
        }
        let deadline = Deadline::after(timeout);
        let mut buf = [0u8; FRAME_LEN];
        let got = loop {
            match sys::wait_readable(self.fd.as_fd(), &deadline) {
                Err(e) => return Err(io_err(e)),
                Ok(Readiness::TimedOut) => return Err(fail(NetnsDialFailure::TimedOut)),
                Ok(Readiness::Readable | Readiness::Exceptional) => {}
            }
            match sysh::recv_one_fd(self.fd.as_fd(), &mut buf) {
                Ok(r) => break r,
                Err(SysError::Os(n)) if n == sys::EAGAIN || n == sys::EINTR => {
                    if deadline.remaining().is_zero() {
                        return Err(fail(NetnsDialFailure::TimedOut));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => return Err(io_err(e)),
            }
        };
        let mut fds = got.fds;
        if got.len == 0 && fds.is_empty() && !got.ctrl_truncated {
            return Err(fail(NetnsDialFailure::HelperExited));
        }
        if got.ctrl_truncated || got.data_truncated {
            return Err(fail(NetnsDialFailure::Protocol));
        }
        let resp = DialResponseFrame::decode(buf.get(..got.len).unwrap_or(&[]))
            .map_err(|_| fail(NetnsDialFailure::Protocol))?;
        match resp {
            DialResponse::Error(code) if fds.is_empty() => {
                Err(fail(NetnsDialFailure::Helper(code)))
            }
            DialResponse::Error(_) => Err(fail(NetnsDialFailure::Protocol)),
            DialResponse::Connected => {
                let (Some(fd), true) = (fds.pop(), fds.is_empty()) else {
                    return Err(fail(NetnsDialFailure::Protocol));
                };
                verify_dialed_socket(fd, DialExpectation::new(sent.port, expected_netns))
                    .map_err(|e| fail(NetnsDialFailure::Rejected(e)))
            }
        }
    }

    /// 試験専用: 任意のバイト列と fd を端へ流し込めるよう、端の fd を借りる。
    #[cfg(test)]
    fn raw_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn io_err(e: SysError) -> NetnsDialError {
    NetnsDialError {
        failure: NetnsDialFailure::Io,
        errno: match e {
            SysError::Os(n) => Some(n),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netns_dial::frame::ConnectTimeout;
    use crate::netns_dial::verify::DialedSocketRejection;
    use std::net::{Ipv4Addr, TcpListener};
    use std::time::Instant;

    fn missing() -> NsId {
        NsId::new(u64::MAX, u64::MAX)
    }

    fn sent(port: u16) -> SentDial {
        SentDial {
            port: NonZeroU16::new(port).unwrap(),
        }
    }

    /// 子の端から `bytes` と `fds` を送る helper 役。
    fn feed(child: &OwnedFd, bytes: &[u8], fds: &[std::os::fd::BorrowedFd<'_>]) {
        sysh::send_with_fds(child.as_fd(), bytes, fds, true).unwrap();
    }

    fn resp(r: DialResponse) -> [u8; FRAME_LEN] {
        *DialResponseFrame::encode(r).as_bytes()
    }

    fn open(path: &str) -> OwnedFd {
        OwnedFd::from(File::open(path).unwrap())
    }

    fn failure_of(
        ch: &NetnsDialChannel,
        port: u16,
        t: Duration,
    ) -> Result<TcpStream, NetnsDialError> {
        ch.wait_response(&sent(port), missing(), t)
    }

    /// SEC-1・NET-3(#4480): fd 0 本の `Connected` は拒否する（`recv_one_fd` は 0 本でも Ok を返すため）。
    #[test]
    fn sec1_net3_4480_connected_with_zero_fds_is_protocol() {
        let (ch, child) = NetnsDialChannel::pair().unwrap();
        feed(&child, &resp(DialResponse::Connected), &[]);
        let e = failure_of(&ch, 1, Duration::from_secs(2)).unwrap_err();
        assert_eq!(e.failure(), NetnsDialFailure::Protocol);
    }

    /// SEC-1・NET-3(#4480): fd 2 本（`ctrl_truncated`）は拒否する。
    #[test]
    fn sec1_net3_4480_connected_with_two_fds_is_protocol() {
        let (ch, child) = NetnsDialChannel::pair().unwrap();
        let a = open("/proc/self/ns/net");
        let b = open("/proc/self/ns/user");
        feed(
            &child,
            &resp(DialResponse::Connected),
            &[a.as_fd(), b.as_fd()],
        );
        let e = failure_of(&ch, 1, Duration::from_secs(2)).unwrap_err();
        assert_eq!(e.failure(), NetnsDialFailure::Protocol);
    }

    /// SEC-1・NET-3(#4480): 17 バイトの応答（`data_truncated`）と壊れた magic は `Protocol`。
    #[test]
    fn sec1_net3_4480_truncated_or_corrupt_frames_are_protocol() {
        let (ch, child) = NetnsDialChannel::pair().unwrap();
        feed(&child, &[0u8; FRAME_LEN + 1], &[]);
        let e = failure_of(&ch, 1, Duration::from_secs(2)).unwrap_err();
        assert_eq!(e.failure(), NetnsDialFailure::Protocol);
        feed(&child, &[0xffu8; FRAME_LEN], &[]);
        let e = failure_of(&ch, 1, Duration::from_secs(2)).unwrap_err();
        assert_eq!(e.failure(), NetnsDialFailure::Protocol);
    }

    /// SEC-1・NET-3(#4480): `Error` に fd が添えば `Protocol`、添わなければ code のまま `Helper(code)`。
    #[test]
    fn sec1_net3_4480_error_response_maps_code_and_rejects_attached_fd() {
        let (ch, child) = NetnsDialChannel::pair().unwrap();
        let a = open("/proc/self/ns/net");
        feed(
            &child,
            &resp(DialResponse::Error(DialErrorCode::Refused)),
            &[a.as_fd()],
        );
        let e = failure_of(&ch, 1, Duration::from_secs(2)).unwrap_err();
        assert_eq!(e.failure(), NetnsDialFailure::Protocol);
        for code in DialErrorCode::ALL {
            feed(&child, &resp(DialResponse::Error(code)), &[]);
            let e = failure_of(&ch, 1, Duration::from_secs(2)).unwrap_err();
            assert_eq!(e.failure(), NetnsDialFailure::Helper(code));
        }
    }

    /// REPAIR-5(#4480): 端が閉じれば `HelperExited`、何も来なければ期限で `TimedOut`。
    #[test]
    fn repair5_4480_eof_and_timeout() {
        let (ch, child) = NetnsDialChannel::pair().unwrap();
        let started = Instant::now();
        let e = failure_of(&ch, 1, Duration::from_millis(50)).unwrap_err();
        assert_eq!(e.failure(), NetnsDialFailure::TimedOut);
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(50) && took < Duration::from_secs(5),
            "{took:?}"
        );
        drop(child);
        let e = failure_of(&ch, 1, Duration::from_secs(2)).unwrap_err();
        assert_eq!(e.failure(), NetnsDialFailure::HelperExited);
    }

    /// REPAIR-5(#4480): 期限は `(0, MAX_RESPONSE_TIMEOUT]` に限る。
    #[test]
    fn repair5_4480_timeout_range_is_enforced() {
        let (ch, _child) = NetnsDialChannel::pair().unwrap();
        for t in [
            Duration::ZERO,
            MAX_RESPONSE_TIMEOUT + Duration::from_millis(1),
        ] {
            let e = failure_of(&ch, 1, t).unwrap_err();
            assert_eq!(e.failure(), NetnsDialFailure::InvalidTimeout);
        }
    }

    /// SEC-1・NET-3(#4480): socket でない fd は `Rejected(NotSocket)`。
    #[test]
    fn sec1_net3_4480_non_socket_fd_is_rejected() {
        let (ch, child) = NetnsDialChannel::pair().unwrap();
        let f = open("/proc/self/ns/net");
        feed(&child, &resp(DialResponse::Connected), &[f.as_fd()]);
        let e = failure_of(&ch, 1, Duration::from_secs(2)).unwrap_err();
        let NetnsDialFailure::Rejected(r) = e.failure() else {
            panic!("{e:?}")
        };
        assert_eq!(r.reason(), Some(DialedSocketRejection::NotSocket));
    }

    /// SEC-1・NET-3(#4480): host の netns の loopback 接続は、期待する netns と一致しないため拒否する。
    /// 非 root は `SIOCGSKNS` が拒否されて `NetnsUnavailable`、権限があれば `NetnsMismatch`。
    #[test]
    fn sec1_net3_4480_host_netns_socket_is_rejected() {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        let s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        let (ch, child) = NetnsDialChannel::pair().unwrap();
        feed(&child, &resp(DialResponse::Connected), &[s.as_fd()]);
        let e = failure_of(&ch, port, Duration::from_secs(2)).unwrap_err();
        let NetnsDialFailure::Rejected(r) = e.failure() else {
            panic!("{e:?}")
        };
        let want = [
            Some(DialedSocketRejection::NetnsUnavailable),
            Some(DialedSocketRejection::NetnsMismatch),
        ];
        assert!(want.contains(&r.reason()), "{:?}", r.reason());
    }

    /// SEC-1(#4480): 期待する netns が自プロセスの netns なら、受信の前に `OwnNetns` で拒否する。
    #[test]
    fn sec1_4480_expected_own_netns_is_rejected_before_receiving() {
        let (ch, child) = NetnsDialChannel::pair().unwrap();
        feed(&child, &resp(DialResponse::Connected), &[]);
        let own = stat_path("/proc/self/ns/net").unwrap();
        let e = ch
            .wait_response(&sent(1), own, Duration::from_secs(2))
            .unwrap_err();
        assert_eq!(e.failure(), NetnsDialFailure::OwnNetns);
    }

    /// SEC-1(#4480): `NetnsDialFds::new` は同じ ns の 2 本と、自プロセスの ns を拒否する。
    #[test]
    fn sec1_4480_fds_new_rejects_same_and_own_namespaces() {
        let e =
            NetnsDialFds::new(open("/proc/self/ns/net"), open("/proc/self/ns/net")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        let e =
            NetnsDialFds::new(open("/proc/self/ns/user"), open("/proc/self/ns/net")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
    }

    /// NET-3(#4480): 送った 16 バイトが `DialRequestFrame` と一致し、fd が user、net の順で届く。
    #[test]
    fn net3_4480_send_request_sends_frame_and_fds_in_order() {
        let fds =
            NetnsDialFds::distinct(open("/proc/self/ns/user"), open("/proc/self/ns/net")).unwrap();
        let req = DialRequest::new(
            NonZeroU16::new(8080).unwrap(),
            ConnectTimeout::new(3000).unwrap(),
        );
        let (ch, child) = NetnsDialChannel::pair().unwrap();
        let s = ch.send_request(req, fds).unwrap();
        assert_eq!(s.port().get(), 8080);
        let mut buf = [0u8; 64];
        let got = sysh::recv_with_fds(child.as_fd(), &mut buf, 2).unwrap();
        assert_eq!(
            buf.get(..got.len),
            Some(&DialRequestFrame::encode(req).as_bytes()[..])
        );
        let ids: Vec<(u64, u64)> = got
            .fds
            .iter()
            .map(|f| {
                let m = std::fs::File::from(f.try_clone().unwrap())
                    .metadata()
                    .unwrap();
                (m.dev(), m.ino())
            })
            .collect();
        let user = stat_path("/proc/self/ns/user").unwrap();
        let net = stat_path("/proc/self/ns/net").unwrap();
        assert_eq!(ids, vec![(user.dev(), user.ino()), (net.dev(), net.ino())]);
        let _ = ch.raw_fd();
    }

    /// REPAIR-4(#4480): 固定語彙に重複が無く、`NetError` の文に port の数字が入らない。
    #[test]
    fn repair4_4480_vocabulary_is_unique_and_messages_are_fixed() {
        let mut names: Vec<&str> = DialErrorCode::ALL
            .iter()
            .map(|c| NetnsDialFailure::Helper(*c).as_str())
            .collect();
        names.extend([
            NetnsDialFailure::TimedOut.as_str(),
            NetnsDialFailure::HelperExited.as_str(),
            NetnsDialFailure::Protocol.as_str(),
            NetnsDialFailure::OwnNetns.as_str(),
            NetnsDialFailure::InvalidTimeout.as_str(),
            NetnsDialFailure::Io.as_str(),
        ]);
        let n = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), n);
        let e = NetnsDialError {
            failure: NetnsDialFailure::Io,
            errno: Some(98),
        };
        let ne = NetError::from(e);
        assert_eq!(ne.code(), NetErrorCode::Internal);
        assert!(!ne.message().chars().any(|c| c.is_ascii_digit()));
    }
}
