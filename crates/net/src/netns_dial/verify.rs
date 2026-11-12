//! `netns-dial` helper が返した接続済み fd の検証（CRI-6・NET-3・SEC-1・REPAIR-2・REPAIR-5・#4478。
//! 設計は `docs/design/cri-streaming-server.md`「POD ネットワークの PortForward の設計（#3766）」の手順 5）。
//!
//! plugin-cri は helper から `SCM_RIGHTS` で fd を 1 本受け取り、`TcpStream` にする前に
//! `verify_dialed_socket` を通す。helper の不具合で host netns の socket が返っても、ここで拒否して
//! host loopback を露出させない（多層防御）。fd は untrusted として全項目を検証する。
//!
//! # 検査（安い順。1 つでも外れたら拒否し、fd は drop で閉じる）
//! 1. socket であること（`SO_TYPE` が `ENOTSOCK` でない）かつ `SOCK_STREAM`
//! 2. `AF_INET` か `AF_INET6`（AF_UNIX 等を拒否）かつ `IPPROTO_TCP`（SCTP 等を拒否）。ファミリは以降の 3・4 の
//!    アドレスの型と結びつける（#4572: helper は `127.0.0.1` を試し、失敗したら `::1` でつなぎ直す）
//! 3. peer が `127.0.0.1:<要求した port>` か `[::1]:<要求した port>`（scope 0）と完全一致。ファミリと食い違う型、
//!    v4-mapped（`::ffff:127.0.0.1`）・IPv4 互換形・`::1` 以外の IPv6 は正規化せずに拒否する
//! 4. local が IPv4 なら loopback（127/8）、IPv6 なら `::1` だけ
//! 5. `SIOCGSKNS`（IPv6 でも必須）で得た netns の (dev, ino) が保持役の素性と一致。`SIOCGSKNS` が失敗したら照合を飛ばさず拒否する
//!    （fail-closed。#4491 の判断 1〔2026-11-12〕で必須と決定。拒否されても緩めない）。非 root の plugin-cri では host netns の socket は
//!    ioctl の `EPERM` で拒否され、これが主な拒否経路になる（`sys/dial.rs` の「カーネルの要求」）
//!
//! 判定は syscall を含まない純関数（`check_*`）に分け、具体値の試験を置く。
//! 本モジュール全体が Linux 限定（素性の型 `NsId` が `network_mode::host` の Linux 限定の型のため）。
//!
//! # 呼び出し元の責務
//! ブロッキング状態・timeout は変えない（設定は呼び出し側 #4484 が行う。REPAIR-5）。待ちは持たない。
//! 非 Linux ではモジュールごと提供しない（`netns_holder` の channel と同じ扱い）。

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;

use crate::error::{NetError, NetErrorCode};
pub use crate::network_mode::host::NsId;

/// 期待値（要求した port と保持役の netns の素性）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialExpectation {
    port: NonZeroU16,
    netns: NsId,
}

impl DialExpectation {
    /// 要求した宛先 port と、保持役 netns の (dev, ino) から作る。
    pub fn new(port: NonZeroU16, netns: NsId) -> Self {
        Self { port, netns }
    }
    /// 要求した宛先 port。
    pub fn port(&self) -> NonZeroU16 {
        self.port
    }
    /// 保持役 netns の素性。
    pub fn netns(&self) -> NsId {
        self.netns
    }
}

/// 拒否の理由（固定語彙。`#[non_exhaustive]`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DialedSocketRejection {
    /// socket ではない。
    NotSocket,
    /// `SOCK_STREAM` ではない。
    NotStream,
    /// `AF_INET` でも `AF_INET6` でもない。
    NotInet,
    /// `IPPROTO_TCP` ではない。
    NotTcp,
    /// 接続済みではない（`ENOTCONN`）。
    NotConnected,
    /// peer が `127.0.0.1:<要求した port>` でも `[::1]:<要求した port>` でもない（ファミリと型の食い違いを含む）。
    PeerMismatch,
    /// local が IPv4 loopback（127/8）でも `::1` でもない（ファミリと型の食い違いを含む）。
    LocalNotLoopback,
    /// `SIOCGSKNS` が失敗した（権限不足を含む。fail-closed）。
    NetnsUnavailable,
    /// netns の (dev, ino) が保持役と異なる。
    NetnsMismatch,
}

impl DialedSocketRejection {
    /// 全理由（語彙の重複確認用）。
    pub const ALL: [Self; 9] = [
        Self::NotSocket,
        Self::NotStream,
        Self::NotInet,
        Self::NotTcp,
        Self::NotConnected,
        Self::PeerMismatch,
        Self::LocalNotLoopback,
        Self::NetnsUnavailable,
        Self::NetnsMismatch,
    ];

    /// 機械可読な固定語彙。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotSocket => "not_socket",
            Self::NotStream => "not_stream",
            Self::NotInet => "not_inet",
            Self::NotTcp => "not_tcp",
            Self::NotConnected => "not_connected",
            Self::PeerMismatch => "peer_mismatch",
            Self::LocalNotLoopback => "local_not_loopback",
            Self::NetnsUnavailable => "netns_unavailable",
            Self::NetnsMismatch => "netns_mismatch",
        }
    }
}

/// `verify_dialed_socket` の失敗。拒否（`reason` あり）か、対応外・想定外の errno（`reason` なし）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialedSocketError {
    reason: Option<DialedSocketRejection>,
    code: NetErrorCode,
    errno: Option<i32>,
}

impl DialedSocketError {
    fn rejected(reason: DialedSocketRejection, errno: Option<i32>) -> Self {
        Self {
            reason: Some(reason),
            code: NetErrorCode::FailedPrecondition,
            errno,
        }
    }
    fn unexpected(code: NetErrorCode, errno: Option<i32>) -> Self {
        Self {
            reason: None,
            code,
            errno,
        }
    }
    /// 拒否の理由（対応外・想定外の errno なら `None`）。
    pub fn reason(&self) -> Option<DialedSocketRejection> {
        self.reason
    }
    /// 機械可読な分類。
    pub fn code(&self) -> NetErrorCode {
        self.code
    }
    /// 元の errno（構造化フィールドとしてだけ持つ。文には含めない）。
    pub fn errno(&self) -> Option<i32> {
        self.errno
    }
}

impl From<DialedSocketError> for NetError {
    /// 固定の英語の文にする（port・pid・パス・errno を含めない。REPAIR-4）。
    fn from(e: DialedSocketError) -> Self {
        let msg = match e.reason {
            Some(DialedSocketRejection::NotSocket) => "dialed fd is not a socket",
            Some(DialedSocketRejection::NotStream) => "dialed socket is not a stream socket",
            Some(DialedSocketRejection::NotInet) => "dialed socket is not an IPv4 or IPv6 socket",
            Some(DialedSocketRejection::NotTcp) => "dialed socket is not a TCP socket",
            Some(DialedSocketRejection::NotConnected) => "dialed socket is not connected",
            Some(DialedSocketRejection::PeerMismatch) => {
                "dialed socket peer is not the requested loopback address"
            }
            Some(DialedSocketRejection::LocalNotLoopback) => {
                "dialed socket local address is not loopback"
            }
            Some(DialedSocketRejection::NetnsUnavailable) => {
                "dialed socket network namespace could not be determined"
            }
            Some(DialedSocketRejection::NetnsMismatch) => {
                "dialed socket belongs to a different network namespace"
            }
            None if e.code == NetErrorCode::Unimplemented => {
                "dialed socket verification is not supported on this platform"
            }
            None => "dialed socket verification failed unexpectedly",
        };
        NetError::new(e.code, msg)
    }
}

const SOCK_STREAM: i32 = 1;
const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const IPPROTO_TCP: i32 = 6;

// 定数の `libc` 照合（coding-rust.md「unsafe・FFI・syscall」。Linux の値と比べる。他 OS の値は同じ ABI 値のため対象外）。
#[cfg(all(test, target_os = "linux"))]
const _: () = {
    assert!(SOCK_STREAM == libc::SOCK_STREAM);
    assert!(AF_INET == libc::AF_INET);
    assert!(AF_INET6 == libc::AF_INET6);
    assert!(IPPROTO_TCP == libc::IPPROTO_TCP);
};

/// 接続済み socket のアドレスファミリ（検査 2 の結果。3・4 のアドレスの型と結びつける）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialFamily {
    /// `AF_INET`。
    V4,
    /// `AF_INET6`。
    V6,
}

/// socket の種別・ファミリ・プロトコルの照合（検査 1・2）。ファミリを返す。
pub(crate) fn check_kind(
    so_type: i32,
    domain: i32,
    protocol: i32,
) -> Result<DialFamily, DialedSocketRejection> {
    if so_type != SOCK_STREAM {
        return Err(DialedSocketRejection::NotStream);
    }
    let family = match domain {
        AF_INET => DialFamily::V4,
        AF_INET6 => DialFamily::V6,
        _ => return Err(DialedSocketRejection::NotInet),
    };
    if protocol != IPPROTO_TCP {
        return Err(DialedSocketRejection::NotTcp);
    }
    Ok(family)
}

/// peer が `127.0.0.1:<port>` か `[::1]:<port>`（scope 0）と、ファミリに合う側で完全一致するかの照合（検査 3）。
///
/// 正規化（`to_canonical` 等）はしない。正規化すると v4-mapped（`::ffff:127.0.0.1`）が通ってしまうため。
/// flowinfo は見ない（宛先を固定で組む helper は 0 で接続する）。
pub(crate) fn check_peer(
    peer: SocketAddr,
    port: NonZeroU16,
    family: DialFamily,
) -> Result<(), DialedSocketRejection> {
    match (family, peer) {
        (DialFamily::V4, SocketAddr::V4(a))
            if *a.ip() == Ipv4Addr::LOCALHOST && a.port() == port.get() =>
        {
            Ok(())
        }
        (DialFamily::V6, SocketAddr::V6(a))
            if *a.ip() == Ipv6Addr::LOCALHOST && a.scope_id() == 0 && a.port() == port.get() =>
        {
            Ok(())
        }
        _ => Err(DialedSocketRejection::PeerMismatch),
    }
}

/// local が IPv4 なら loopback（127/8）、IPv6 なら `::1` だけかの照合（検査 4）。
pub(crate) fn check_local(
    local: SocketAddr,
    family: DialFamily,
) -> Result<(), DialedSocketRejection> {
    match (family, local) {
        (DialFamily::V4, SocketAddr::V4(a)) if a.ip().is_loopback() => Ok(()),
        (DialFamily::V6, SocketAddr::V6(a)) if *a.ip() == Ipv6Addr::LOCALHOST => Ok(()),
        _ => Err(DialedSocketRejection::LocalNotLoopback),
    }
}

/// netns の素性の照合（検査 5）。
pub(crate) fn check_netns(observed: NsId, expected: NsId) -> Result<(), DialedSocketRejection> {
    if observed == expected {
        Ok(())
    } else {
        Err(DialedSocketRejection::NetnsMismatch)
    }
}

/// helper から受け取った fd を検証し、全項目に合格したときだけ [`TcpStream`](std::net::TcpStream) にして返す。
///
/// fd は所有権ごと受け取り、拒否なら drop で閉じる。検査の内容と順序はモジュール doc を参照。
/// 成功経路（pod の netns の socket が `Ok`）と別 netns の socket の `NetnsMismatch` の実機での照合は
/// 実機前提試験 `netns_dial_userns`（#4480）が担う。
pub fn verify_dialed_socket(
    fd: std::os::fd::OwnedFd,
    expected: DialExpectation,
) -> Result<std::net::TcpStream, DialedSocketError> {
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::MetadataExt as _;

    use crate::sys::{SysError, dial, holder};

    let sys_fail = |e: SysError| match e {
        SysError::Unsupported => DialedSocketError::unexpected(NetErrorCode::Unimplemented, None),
        SysError::Os(errno) => DialedSocketError::unexpected(NetErrorCode::Internal, Some(errno)),
        _ => DialedSocketError::unexpected(NetErrorCode::Internal, None),
    };

    let so_type = match holder::socket_type(fd.as_fd()) {
        Ok(v) => v,
        Err(SysError::Os(errno)) if errno == holder::ENOTSOCK => {
            return Err(DialedSocketError::rejected(
                DialedSocketRejection::NotSocket,
                Some(errno),
            ));
        }
        Err(e) => return Err(sys_fail(e)),
    };
    let domain = holder::socket_domain(fd.as_fd()).map_err(sys_fail)?;
    let protocol = holder::socket_protocol(fd.as_fd()).map_err(sys_fail)?;
    let family =
        check_kind(so_type, domain, protocol).map_err(|r| DialedSocketError::rejected(r, None))?;

    let stream = std::net::TcpStream::from(fd);
    let peer = stream.peer_addr().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotConnected {
            DialedSocketError::rejected(DialedSocketRejection::NotConnected, e.raw_os_error())
        } else {
            DialedSocketError::unexpected(NetErrorCode::Internal, e.raw_os_error())
        }
    })?;
    check_peer(peer, expected.port, family).map_err(|r| DialedSocketError::rejected(r, None))?;
    let local = stream
        .local_addr()
        .map_err(|e| DialedSocketError::unexpected(NetErrorCode::Internal, e.raw_os_error()))?;
    check_local(local, family).map_err(|r| DialedSocketError::rejected(r, None))?;

    // netns の照合は必須（fail-closed）。ioctl の失敗（EPERM・ENOTTY 等）で飛ばさない。
    let nsfd = match dial::socket_netns(stream.as_fd()) {
        Ok(f) => f,
        Err(SysError::Unsupported) => {
            return Err(DialedSocketError::unexpected(
                NetErrorCode::Unimplemented,
                None,
            ));
        }
        Err(SysError::Os(errno)) => {
            return Err(DialedSocketError::rejected(
                DialedSocketRejection::NetnsUnavailable,
                Some(errno),
            ));
        }
        Err(_) => {
            return Err(DialedSocketError::rejected(
                DialedSocketRejection::NetnsUnavailable,
                None,
            ));
        }
    };
    let meta = std::fs::File::from(nsfd)
        .metadata()
        .map_err(|e| DialedSocketError::unexpected(NetErrorCode::Internal, e.raw_os_error()))?;
    check_netns(NsId::new(meta.dev(), meta.ino()), expected.netns)
        .map_err(|r| DialedSocketError::rejected(r, None))?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn port(p: u16) -> NonZeroU16 {
        NonZeroU16::new(p).expect("nonzero")
    }

    /// SEC-1・NET-3・#4478: 種別・ファミリ・プロトコルの各不一致を具体値で拒否する。
    #[test]
    fn sec1_net3_4478_check_kind_rejects_each_mismatch() {
        assert_eq!(check_kind(2, 2, 17), Err(DialedSocketRejection::NotStream));
        assert_eq!(check_kind(1, 1, 0), Err(DialedSocketRejection::NotInet));
        assert_eq!(check_kind(1, 10, 6), Ok(DialFamily::V6));
        assert_eq!(check_kind(1, 10, 132), Err(DialedSocketRejection::NotTcp));
        assert_eq!(check_kind(1, 2, 132), Err(DialedSocketRejection::NotTcp));
        assert_eq!(check_kind(1, 2, 6), Ok(DialFamily::V4));
    }

    /// peer はファミリに合う `127.0.0.1` / `[::1]` と port の完全一致だけを受ける（#4572）。
    #[test]
    fn sec1_net3_4572_check_peer_requires_exact_loopback_and_port() {
        use std::net::SocketAddrV6;
        let want = port(8080);
        for bad in [
            "127.0.0.1:8081",
            "127.0.0.2:8080",
            "10.0.0.1:8080",
            "[::1]:8080",
            "[::ffff:127.0.0.1]:8080",
        ] {
            let a: SocketAddr = bad.parse().expect("addr");
            assert_eq!(
                check_peer(a, want, DialFamily::V4),
                Err(DialedSocketRejection::PeerMismatch),
                "v4 {bad}"
            );
        }
        let ok4: SocketAddr = "127.0.0.1:8080".parse().expect("addr");
        assert_eq!(check_peer(ok4, want, DialFamily::V4), Ok(()));

        for bad in [
            "[::1]:8081",
            "[::ffff:127.0.0.1]:8080",
            "[::127.0.0.1]:8080",
            "[::2]:8080",
            "[::]:8080",
            "[fe80::1]:8080",
            "127.0.0.1:8080",
        ] {
            let a: SocketAddr = bad.parse().expect("addr");
            assert_eq!(
                check_peer(a, want, DialFamily::V6),
                Err(DialedSocketRejection::PeerMismatch),
                "v6 {bad}"
            );
        }
        let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 3));
        assert_eq!(
            check_peer(scoped, want, DialFamily::V6),
            Err(DialedSocketRejection::PeerMismatch)
        );
        let ok6: SocketAddr = "[::1]:8080".parse().expect("addr");
        assert_eq!(check_peer(ok6, want, DialFamily::V6), Ok(()));
    }

    /// local は IPv4 なら 127/8、IPv6 なら `::1` だけを受ける（#4572）。
    #[test]
    fn sec1_net3_4572_check_local_requires_family_loopback() {
        for bad in ["10.0.0.2:5000", "[::1]:5000"] {
            let a: SocketAddr = bad.parse().expect("addr");
            assert_eq!(
                check_local(a, DialFamily::V4),
                Err(DialedSocketRejection::LocalNotLoopback),
                "v4 {bad}"
            );
        }
        for ok in ["127.0.0.1:5000", "127.1.2.3:5000"] {
            let a: SocketAddr = ok.parse().expect("addr");
            assert_eq!(check_local(a, DialFamily::V4), Ok(()), "{ok}");
        }
        for bad in [
            "[::ffff:127.0.0.1]:5000",
            "[::]:5000",
            "[::2]:5000",
            "[fe80::1]:5000",
            "127.0.0.1:5000",
        ] {
            let a: SocketAddr = bad.parse().expect("addr");
            assert_eq!(
                check_local(a, DialFamily::V6),
                Err(DialedSocketRejection::LocalNotLoopback),
                "v6 {bad}"
            );
        }
        let ok: SocketAddr = "[::1]:5000".parse().expect("addr");
        assert_eq!(check_local(ok, DialFamily::V6), Ok(()));
    }

    /// dev・ino のどちらが違っても `NetnsMismatch`。
    #[test]
    fn sec1_net3_4478_check_netns_rejects_dev_or_ino_difference() {
        let want = NsId::new(4, 4_026_532_000);
        assert_eq!(
            check_netns(NsId::new(4, 4_026_532_001), want),
            Err(DialedSocketRejection::NetnsMismatch)
        );
        assert_eq!(
            check_netns(NsId::new(5, 4_026_532_000), want),
            Err(DialedSocketRejection::NetnsMismatch)
        );
        assert_eq!(check_netns(want, want), Ok(()));
    }

    /// 理由の語彙は重複しない固定の snake_case で、`NetError` の文に port や errno を含めない。
    #[test]
    fn sec1_net3_4478_vocabulary_is_unique_and_message_has_no_port() {
        let names: HashSet<&str> = DialedSocketRejection::ALL
            .iter()
            .map(|r| r.as_str())
            .collect();
        assert_eq!(names.len(), DialedSocketRejection::ALL.len());
        let e = DialedSocketError::rejected(DialedSocketRejection::PeerMismatch, Some(54321));
        assert_eq!(e.errno(), Some(54321));
        let ne = NetError::from(e);
        assert_eq!(ne.code(), NetErrorCode::FailedPrecondition);
        assert!(!ne.message().contains("54321"), "{}", ne.message());
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::net::{TcpListener, TcpStream, UdpSocket};
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;

        fn reject(fd: OwnedFd, exp: DialExpectation) -> DialedSocketError {
            verify_dialed_socket(fd, exp).expect_err("must be rejected")
        }

        fn current() -> NsId {
            crate::network_mode::host::current_thread_netns().expect("netns")
        }

        fn exp(p: u16) -> DialExpectation {
            DialExpectation::new(port(p), current())
        }

        /// ソケットでない fd。
        #[test]
        fn sec1_net3_4478_not_socket_rejected() {
            let f = std::fs::File::open("/dev/null").expect("open");
            let e = reject(OwnedFd::from(f), exp(1));
            assert_eq!(e.reason(), Some(DialedSocketRejection::NotSocket));
            assert_eq!(e.errno(), Some(88));
        }

        /// UDP は `NotStream`、AF_UNIX stream は `NotInet`、listen 中の TCP は `NotConnected`。
        #[test]
        fn sec1_net3_4478_wrong_kind_rejected() {
            let u = UdpSocket::bind("127.0.0.1:0").expect("bind");
            assert_eq!(
                reject(OwnedFd::from(u), exp(1)).reason(),
                Some(DialedSocketRejection::NotStream)
            );
            let (a, _b) = UnixStream::pair().expect("pair");
            assert_eq!(
                reject(OwnedFd::from(a), exp(1)).reason(),
                Some(DialedSocketRejection::NotInet)
            );
            let l = TcpListener::bind("127.0.0.1:0").expect("bind");
            assert_eq!(
                reject(OwnedFd::from(l), exp(1)).reason(),
                Some(DialedSocketRejection::NotConnected)
            );
        }

        /// port の不一致は `PeerMismatch`。
        #[test]
        fn sec1_net3_4478_peer_port_mismatch_rejected() {
            let l = TcpListener::bind("127.0.0.1:0").expect("bind");
            let real = l.local_addr().expect("addr").port();
            let wrong = real.checked_add(1).unwrap_or(real - 1);
            let c = TcpStream::connect(("127.0.0.1", real)).expect("connect");
            let e = reject(OwnedFd::from(c), exp(wrong));
            assert_eq!(e.reason(), Some(DialedSocketRejection::PeerMismatch));
        }

        /// IPv6 の stream は netns の段まで進む（#4572）。`Ok` か `EPERM`（`NetnsUnavailable`）、1 ずらせば
        /// `NetnsMismatch` か `EPERM`。
        #[test]
        fn sec1_net3_4572_ipv6_stream_reaches_netns_stage() {
            let l = TcpListener::bind("[::1]:0").expect("bind ::1");
            let p = l.local_addr().expect("addr").port();
            let cur = current();
            let run = |ns: NsId| {
                let c = TcpStream::connect(("::1", p)).expect("connect");
                let _accepted = l.accept().expect("accept");
                verify_dialed_socket(OwnedFd::from(c), DialExpectation::new(port(p), ns))
            };
            let same = run(cur);
            let shifted = run(NsId::new(cur.dev(), cur.ino() + 1));
            match (same, shifted) {
                (Ok(s), Err(e)) => {
                    assert_eq!(
                        s.peer_addr().expect("peer").to_string(),
                        format!("[::1]:{p}")
                    );
                    assert_eq!(e.reason(), Some(DialedSocketRejection::NetnsMismatch));
                }
                (Err(a), Err(b)) => {
                    for e in [a, b] {
                        assert_eq!(e.reason(), Some(DialedSocketRejection::NetnsUnavailable));
                        assert_eq!(e.errno(), Some(1));
                    }
                }
                (a, b) => panic!("unexpected: {:?} / {:?}", a.map(|_| ()), b.map(|_| ())),
            }
        }

        /// IPv6 で port が違えば `PeerMismatch`（#4572）。
        #[test]
        fn sec1_net3_4572_ipv6_peer_port_mismatch_rejected() {
            let l = TcpListener::bind("[::1]:0").expect("bind ::1");
            let real = l.local_addr().expect("addr").port();
            let wrong = real.checked_add(1).unwrap_or(real - 1);
            let c = TcpStream::connect(("::1", real)).expect("connect");
            let e = reject(OwnedFd::from(c), exp(wrong));
            assert_eq!(e.reason(), Some(DialedSocketRejection::PeerMismatch));
        }

        /// v4-mapped（`::ffff:127.0.0.1` への AF_INET6 の接続）は peer の段で拒否する（#4572）。
        /// v4-mapped の接続が作れない環境（`ipv6.disable` 等）では作れた場合だけ確かめる。
        #[test]
        fn sec1_net3_4572_v4_mapped_peer_rejected() {
            let l = TcpListener::bind("[::]:0").expect("bind dual-stack");
            let p = l.local_addr().expect("addr").port();
            let mapped: SocketAddr = format!("[::ffff:127.0.0.1]:{p}").parse().expect("addr");
            let Ok(c) = TcpStream::connect(mapped) else {
                return;
            };
            let e = reject(OwnedFd::from(c), exp(p));
            assert_eq!(e.reason(), Some(DialedSocketRejection::PeerMismatch));
        }

        /// netns の段: 期待が現在の netns なら `Ok` か `EPERM`、1 ずらせば `NetnsMismatch` か `EPERM`。
        /// 非 root では host netns の socket が `SIOCGSKNS` の `EPERM` で fail-closed になる本番の拒否経路を通る。
        /// euid では分岐しない（`unshare -r` 内の euid 0 でも init 所有の netns には `EPERM` になるため）。
        #[test]
        fn sec1_net3_4478_netns_stage_accepts_or_fails_closed() {
            let l = TcpListener::bind("127.0.0.1:0").expect("bind");
            let p = l.local_addr().expect("addr").port();
            let cur = current();
            let run = |ns: NsId| {
                let c = TcpStream::connect(("127.0.0.1", p)).expect("connect");
                let _accepted = l.accept().expect("accept");
                verify_dialed_socket(OwnedFd::from(c), DialExpectation::new(port(p), ns))
            };
            let same = run(cur);
            let shifted = run(NsId::new(cur.dev(), cur.ino() + 1));
            match (same, shifted) {
                (Ok(_), Err(e)) => {
                    assert_eq!(e.reason(), Some(DialedSocketRejection::NetnsMismatch));
                }
                (Err(a), Err(b)) => {
                    for e in [a, b] {
                        assert_eq!(e.reason(), Some(DialedSocketRejection::NetnsUnavailable));
                        assert_eq!(e.errno(), Some(1));
                    }
                }
                (a, b) => panic!("unexpected: {:?} / {:?}", a.map(|_| ()), b.map(|_| ())),
            }
        }
    }
}
