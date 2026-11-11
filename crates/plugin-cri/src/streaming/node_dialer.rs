//! NODE ネットワーク（hostNetwork）の pod 向け `PortForwardDialer` の本番実装（CRI-6・SEC-1・REPAIR-3・REPAIR-5・#3755）。
//!
//! 呼び出し元: cri の `PortForwardHandler`（Upgrade 後のセッション）が `spawn_blocking` 上で呼ぶ。`production_stream_dispatcher`
//! が `PortForwardHandler` へ注入する。cri はホストの loopback へつなぐ実装を持たない設計のため（URL を知る者に
//! ホストのローカルサービスを晒す経路になる）、NODE に限って plugin-cri だけがここに置く。
//!
//! # 接続先（SEC-1）
//! 可変なのはポート番号だけで、アドレスは定数 `127.0.0.1` に固定する。要求の文字列・HTTP ヘッダ・sandbox の記録から
//! アドレスを組み立てない。`::1` は試さない（fail-closed。設計記録の確認事項）。成功後に `peer_addr` が loopback で
//! あることを多層防御として確かめる。
//!
//! # POD ネットワーク（REPAIR-3）
//! 本 dialer は POD の target を `UNIMPLEMENTED` で断る（RPC 時にも cri が断る多層防御）。pod の netns 内の loopback への
//! 接続は `PodNetnsDialer`（#4484。保持役の fd と `netns-dial` helper）が担い、結線は #4486。
//!
//! # 残余
//! hostNetwork の pod の port-forward はホストの loopback 上の任意のサービスへ届く。これは hostNetwork の性質で、
//! 認可は単回トークンの URL（TTL 60 秒）と kubelet / apiserver が担う。URL 発行後に sandbox が消えても dialer は
//! 記録を照合しない（トークンの TTL とセッションの idle の期限で有界）。

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use fandhe_container_cri::error::CriError;
use fandhe_container_cri::streaming::port_forward::{
    PortForwardDialer, PortForwardNetwork, PortForwardTarget,
};

/// 接続関数。試験で差し替える（loopback の connect で期限切れを決定的に起こせないため）。
type Connector = fn(&SocketAddr, Duration) -> io::Result<TcpStream>;

/// host の loopback の指定ポートへ期限つきで接続する dialer。
#[derive(Debug, Clone)]
pub struct NodeLoopbackDialer {
    connect: Connector,
}

impl NodeLoopbackDialer {
    /// 本番の dialer（`TcpStream::connect_timeout`）。
    pub fn new() -> Self {
        Self {
            connect: TcpStream::connect_timeout,
        }
    }

    #[cfg(test)]
    fn with_connector(connect: Connector) -> Self {
        Self { connect }
    }
}

impl Default for NodeLoopbackDialer {
    fn default() -> Self {
        Self::new()
    }
}

impl PortForwardDialer for NodeLoopbackDialer {
    fn dial(
        &self,
        target: &PortForwardTarget,
        port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, CriError> {
        if target.network() != PortForwardNetwork::Node {
            return Err(CriError::unimplemented(
                "port-forward for pod network is not implemented",
            ));
        }
        // 0 は有効なポートではない（`u16` の範囲外は型で表現できない）。
        if port == 0 {
            return Err(CriError::invalid_argument(
                "port forward port is out of range",
            ));
        }
        if timeout.is_zero() {
            return Err(CriError::invalid_argument(
                "port forward dial timeout must be positive",
            ));
        }
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let stream = (self.connect)(&addr, timeout).map_err(|e| match e.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
                CriError::timeout("port forward dial timed out")
            }
            _ => CriError::unavailable("port forward dial failed"),
        })?;
        match stream.peer_addr() {
            Ok(peer) if peer.ip().is_loopback() => Ok(stream),
            _ => Err(CriError::unavailable("port forward dial failed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use fandhe_container_cri::error::CriErrorCode;

    use super::*;

    fn node() -> PortForwardTarget {
        PortForwardTarget::new("sb", PortForwardNetwork::Node)
    }

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static SEEN_PORT: AtomicUsize = AtomicUsize::new(0);
    static SEEN_MS: AtomicUsize = AtomicUsize::new(0);

    fn record(addr: &SocketAddr, timeout: Duration, kind: io::ErrorKind) -> io::Result<TcpStream> {
        CALLS.fetch_add(1, Ordering::SeqCst);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        SEEN_PORT.store(usize::from(addr.port()), Ordering::SeqCst);
        SEEN_MS.store(timeout.as_millis() as usize, Ordering::SeqCst);
        Err(io::Error::new(kind, "x"))
    }

    fn timed_out(a: &SocketAddr, t: Duration) -> io::Result<TcpStream> {
        record(a, t, io::ErrorKind::TimedOut)
    }

    fn refused(a: &SocketAddr, t: Duration) -> io::Result<TcpStream> {
        record(a, t, io::ErrorKind::ConnectionRefused)
    }

    /// 静的カウンタを使うため、差し替え接続を使う検証は 1 つの試験にまとめる。
    #[test]
    fn cri6_sec1_3755_rejects_without_dialing_and_maps_errors() {
        CALLS.store(0, Ordering::SeqCst);
        let d = NodeLoopbackDialer::with_connector(timed_out);

        // POD は接続しない。
        let e = d
            .dial(
                &PortForwardTarget::new("sb", PortForwardNetwork::Pod),
                80,
                Duration::from_secs(1),
            )
            .expect_err("pod");
        assert_eq!(e.code(), CriErrorCode::Unimplemented);
        assert_eq!(
            e.message(),
            "port-forward for pod network is not implemented"
        );
        // 不正なポートと期限は接続しない。
        let e = d
            .dial(&node(), 0, Duration::from_secs(1))
            .expect_err("port 0");
        assert_eq!(e.code(), CriErrorCode::InvalidArgument);
        assert_eq!(e.message(), "port forward port is out of range");
        let e = d
            .dial(&node(), 80, Duration::ZERO)
            .expect_err("zero timeout");
        assert_eq!(e.code(), CriErrorCode::InvalidArgument);
        assert_eq!(CALLS.load(Ordering::SeqCst), 0);

        // 期限切れ。接続先は定数の loopback で、文言にアドレスや OS の文字列が無い。
        let e = d
            .dial(&node(), 8080, Duration::from_millis(250))
            .expect_err("timeout");
        assert_eq!(e.code(), CriErrorCode::Timeout);
        assert_eq!(e.message(), "port forward dial timed out");
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(SEEN_PORT.load(Ordering::SeqCst), 8080);
        assert_eq!(SEEN_MS.load(Ordering::SeqCst), 250);

        // 拒否は Unavailable。
        let d = NodeLoopbackDialer::with_connector(refused);
        let e = d
            .dial(&node(), 8081, Duration::from_secs(1))
            .expect_err("refused");
        assert_eq!(e.code(), CriErrorCode::Unavailable);
        assert_eq!(e.message(), "port forward dial failed");
    }

    /// loopback の待ち受けへ接続でき、往復できる。
    #[test]
    fn cri6_sec1_3755_connects_to_loopback_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        // REPAIR-5: accept・read・write・join のすべてに有限の期限を持たせる。
        let io_limit = Duration::from_secs(5);
        let server = std::thread::spawn(move || {
            listener.set_nonblocking(true).expect("nonblocking");
            let deadline = std::time::Instant::now() + io_limit;
            let mut c = loop {
                match listener.accept() {
                    Ok((c, _)) => break c,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "accept deadline exceeded"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("accept failed: {e}"),
                }
            };
            c.set_nonblocking(false).expect("blocking");
            c.set_read_timeout(Some(io_limit)).expect("read timeout");
            c.set_write_timeout(Some(io_limit)).expect("write timeout");
            let mut buf = [0u8; 4];
            c.read_exact(&mut buf).expect("read");
            c.write_all(&buf).expect("write");
        });
        let mut s = NodeLoopbackDialer::new()
            .dial(&node(), port, Duration::from_secs(2))
            .expect("dial");
        s.set_read_timeout(Some(io_limit)).expect("read timeout");
        s.set_write_timeout(Some(io_limit)).expect("write timeout");
        assert_eq!(
            s.peer_addr().expect("peer"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
        );
        s.write_all(b"ping").expect("send");
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).expect("recv");
        assert_eq!(&buf, b"ping");
        server.join().expect("join");
    }

    /// 待ち受けの無いポートは `Unavailable`（実際の拒否）。
    #[test]
    fn cri6_sec1_3755_closed_port_is_unavailable() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").expect("bind");
            l.local_addr().expect("addr").port()
        };
        let e = NodeLoopbackDialer::new()
            .dial(&node(), port, Duration::from_secs(2))
            .expect_err("closed");
        assert_eq!(e.code(), CriErrorCode::Unavailable);
    }
}
