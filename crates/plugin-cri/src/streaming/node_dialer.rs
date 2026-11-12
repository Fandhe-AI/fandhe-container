//! NODE ネットワーク（hostNetwork）の pod 向け `PortForwardDialer` の本番実装（CRI-6・SEC-1・REPAIR-3・REPAIR-5・#3755）。
//!
//! 呼び出し元: cri の `PortForwardHandler`（Upgrade 後のセッション）が `spawn_blocking` 上で呼ぶ。`production_stream_dispatcher`
//! が `PortForwardHandler` へ注入する。cri はホストの loopback へつなぐ実装を持たない設計のため（URL を知る者に
//! ホストのローカルサービスを晒す経路になる）、NODE に限って plugin-cri だけがここに置く。
//!
//! # 接続先（SEC-1・#4575）
//! 可変なのはポート番号だけで、アドレスは定数 `127.0.0.1`、失敗したら `::1` の 2 つに固定する（`LOOPBACK_ADDRS`）。
//! 要求の文字列・HTTP ヘッダ・sandbox の記録からアドレスを組み立てない。期限（呼び出し側の `dial_timeout`）は 2 回の
//! 試行で 1 つを共有し延ばさない。IPv4 の失敗が期限切れ、または残りが 0 のときは IPv6 を試さない。両方失敗したときは
//! 理由を問わず `UNAVAILABLE "port forward dial failed"`、どちらかが期限切れなら `TIMEOUT "port forward dial timed out"`
//! （POD の netns-dial helper〔#4572〕と同じ写像）。成功後は `peer_addr` が接続した宛先と完全一致することを多層防御として
//! 確かめる（`::ffff:127.0.0.1` などの写像アドレスは正規化せず拒否する）。
//!
//! 承認の範囲: 「IPv4 で失敗したら `::1` でつなぎ直す・宛先は 2 つに固定・期限は延ばさない」は #4116 の項目 2 の
//! オーナー判断（2026-11-12。containerd の `tcp4` の次に `tcp6` を試す挙動に合わせる）。両方失敗したときの理由の選び方、
//! peer の完全一致への締め込み、net の内部関数を公開せず本モジュールに小さく持つことは Agent の判断で、オーナーの承認は
//! 得ていない。
//!
//! # POD ネットワーク（REPAIR-3）
//! 本 dialer は POD の target を `UNIMPLEMENTED` で断る（RPC 時にも cri が断る多層防御）。pod の netns 内の loopback への
//! 接続は `PodNetnsDialer`（#4484。保持役の fd と `netns-dial` helper）が担い、結線は #4486 で済み（`ProductionPortForward::pod_network`）、実機の通しは `tests/cri_exec_real.rs` の段 F で照合済み（#4487）。
//!
//! # 残余
//! hostNetwork の pod の port-forward はホストの loopback 上の任意のサービスへ届く。これは hostNetwork の性質で、
//! 認可は単回トークンの URL（TTL 60 秒）と kubelet / apiserver が担う。URL 発行後に sandbox が消えても dialer は
//! 記録を照合しない（トークンの TTL とセッションの idle の期限で有界）。`::1` を試すため、`::1` だけで待ち受ける
//! ホストのサービスにも届く（containerd と同じ挙動。認可は変わらない）。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use fandhe_container_cri::error::CriError;
use fandhe_container_cri::streaming::port_forward::{
    PortForwardDialer, PortForwardNetwork, PortForwardTarget,
};

/// 接続関数。試験で差し替える（loopback の connect で期限切れを決定的に起こせないため）。
type Connector = fn(&SocketAddr, Duration) -> io::Result<TcpStream>;

/// 接続先の固定の 2 宛先。順序がそのまま優先順位（SEC-1）。
const LOOPBACK_ADDRS: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::LOCALHOST),
    IpAddr::V6(Ipv6Addr::LOCALHOST),
];

const MSG_TIMED_OUT: &str = "port forward dial timed out";
const MSG_DIAL_FAILED: &str = "port forward dial failed";

/// 両方の試行をまとめた失敗の分類（アドレス・OS の文字列を持たない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeDialFailure {
    TimedOut,
    Failed,
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

/// `127.0.0.1` → `::1` の順で接続する。成功時は接続の値と使った宛先を返す。
///
/// IPv4 へ `remaining()` の期間で接続し、失敗が期限切れなら IPv6 は試さず `TimedOut` を返す。続いて `remaining()` が
/// 0 なら `TimedOut`（0 の期間を `connect_timeout` へ渡すと `InvalidInput` になり `Failed` に化けるため分ける）。
/// 残りの期間で IPv6 へ接続する。合計の待ちは期限を超えない（REPAIR-5）。
fn dial_loopback_with<T>(
    port: u16,
    mut connect: impl FnMut(SocketAddr, Duration) -> io::Result<T>,
    mut remaining: impl FnMut() -> Duration,
) -> Result<(T, SocketAddr), NodeDialFailure> {
    let [first, second] = LOOPBACK_ADDRS;
    let a1 = SocketAddr::new(first, port);
    match connect(a1, remaining()) {
        Ok(v) => return Ok((v, a1)),
        Err(e) if is_timeout(&e) => return Err(NodeDialFailure::TimedOut),
        Err(_) => {}
    }
    let left = remaining();
    if left.is_zero() {
        return Err(NodeDialFailure::TimedOut);
    }
    let a2 = SocketAddr::new(second, port);
    match connect(a2, left) {
        Ok(v) => Ok((v, a2)),
        Err(e) if is_timeout(&e) => Err(NodeDialFailure::TimedOut),
        Err(_) => Err(NodeDialFailure::Failed),
    }
}

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
        let started = Instant::now();
        let (stream, addr) = dial_loopback_with(
            port,
            |a, t| (self.connect)(&a, t),
            || timeout.saturating_sub(started.elapsed()),
        )
        .map_err(|f| match f {
            NodeDialFailure::TimedOut => CriError::timeout(MSG_TIMED_OUT),
            NodeDialFailure::Failed => CriError::unavailable(MSG_DIAL_FAILED),
        })?;
        match stream.peer_addr() {
            Ok(peer) if peer == addr => Ok(stream),
            _ => Err(CriError::unavailable(MSG_DIAL_FAILED)),
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
        assert!(LOOPBACK_ADDRS.contains(&addr.ip()));
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
        // 期間は期限から経過分を引いた残りで、延びない（250 ms 以下）。
        let seen_ms = SEEN_MS.load(Ordering::SeqCst);
        assert!((200..=250).contains(&seen_ms), "seen_ms={seen_ms}");

        // 拒否は Unavailable。
        let d = NodeLoopbackDialer::with_connector(refused);
        let e = d
            .dial(&node(), 8081, Duration::from_secs(1))
            .expect_err("refused");
        assert_eq!(e.code(), CriErrorCode::Unavailable);
        assert_eq!(e.message(), "port forward dial failed");
        // IPv4 の拒否の後に IPv6 も試すため 2 回呼ばれる（期限切れは IPv6 を試さず 1 回だった）。
        assert_eq!(CALLS.load(Ordering::SeqCst), 3);
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

    /// 待ち受けの無いポートは `Unavailable`（実際の拒否。IPv4・IPv6 の両方で閉じた番号を使う）。
    #[test]
    fn cri6_sec1_3755_closed_port_is_unavailable() {
        let port = (0..20)
            .find_map(|_| {
                let v4 = TcpListener::bind("127.0.0.1:0").ok()?;
                let p = v4.local_addr().ok()?.port();
                let _v6 = TcpListener::bind(("::1", p)).ok()?;
                Some(p)
            })
            .expect("precondition: could not reserve a port on both loopbacks");
        // 期限は広めにする（Windows は閉じた loopback の拒否が 1〜2 秒かかることがあり、2 回試すため）。
        let e = NodeLoopbackDialer::new()
            .dial(&node(), port, Duration::from_secs(10))
            .expect_err("closed");
        assert_eq!(e.code(), CriErrorCode::Unavailable);
        assert_eq!(e.message(), "port forward dial failed");
    }

    fn err(kind: io::ErrorKind) -> io::Result<()> {
        Err(io::Error::new(kind, "x"))
    }

    type RunOutcome = (
        Result<((), SocketAddr), NodeDialFailure>,
        Vec<(SocketAddr, Duration)>,
    );

    /// 偽の接続・偽の時計で手順を照合する（IPv6 の有無に依存しない）。
    fn run(results: Vec<io::Result<()>>, rem: Vec<u64>) -> RunOutcome {
        let mut calls = Vec::new();
        let mut res = results.into_iter();
        let mut rem = rem.into_iter();
        let out = dial_loopback_with(
            8080,
            |a, t| {
                calls.push((a, t));
                res.next().expect("unexpected extra connect")
            },
            || Duration::from_millis(rem.next().expect("remaining exhausted")),
        );
        (out, calls)
    }

    fn v4() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
    }
    fn v6() -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080)
    }

    /// CRI-6・NET-3・#4575: IPv4 が成功したら IPv6 は試さない。
    #[test]
    fn cri6_net3_4575_ipv4_success_does_not_try_ipv6() {
        let (out, calls) = run(vec![Ok(())], vec![1000]);
        assert_eq!(out, Ok(((), v4())));
        assert_eq!(calls, vec![(v4(), Duration::from_millis(1000))]);
    }

    /// CRI-6・NET-3・#4575: IPv4 拒否の後、残りの期間で `::1` へ接続する。
    #[test]
    fn cri6_net3_4575_ipv4_refused_then_ipv6_success_uses_remaining() {
        let (out, calls) = run(
            vec![err(io::ErrorKind::ConnectionRefused), Ok(())],
            vec![1000, 990],
        );
        assert_eq!(out, Ok(((), v6())));
        assert_eq!(
            calls,
            vec![
                (v4(), Duration::from_millis(1000)),
                (v6(), Duration::from_millis(990))
            ]
        );
    }

    /// REPAIR-5・#4575: IPv4 で期限切れなら IPv6 を試さない。
    #[test]
    fn repair5_4575_ipv4_timeout_does_not_try_ipv6() {
        let (out, calls) = run(vec![err(io::ErrorKind::TimedOut)], vec![1000]);
        assert_eq!(out, Err(NodeDialFailure::TimedOut));
        assert_eq!(calls.len(), 1);
    }

    /// REPAIR-5・#4575: 残りが 0 なら IPv6 を試さない。
    #[test]
    fn repair5_4575_zero_remaining_skips_ipv6() {
        let (out, calls) = run(vec![err(io::ErrorKind::ConnectionRefused)], vec![1000, 0]);
        assert_eq!(out, Err(NodeDialFailure::TimedOut));
        assert_eq!(calls.len(), 1);
    }

    /// CRI-6・NET-3・#4575: 両方失敗したときの分類（POD の helper と同じ写像）。
    #[test]
    fn cri6_net3_4575_both_fail_mapping() {
        use io::ErrorKind as K;
        for (first, second, want) in [
            (
                K::ConnectionRefused,
                K::ConnectionRefused,
                NodeDialFailure::Failed,
            ),
            (
                K::NetworkUnreachable,
                K::ConnectionRefused,
                NodeDialFailure::Failed,
            ),
            (
                K::ConnectionRefused,
                K::NetworkUnreachable,
                NodeDialFailure::Failed,
            ),
            (K::ConnectionRefused, K::TimedOut, NodeDialFailure::TimedOut),
        ] {
            let (out, calls) = run(vec![err(first), err(second)], vec![1000, 900]);
            assert_eq!(out, Err(want), "{first:?} / {second:?}");
            assert_eq!(calls.len(), 2);
        }
    }

    /// 前提: IPv4 を手放して `[::1]` だけ保持する listener。IPv6 の loopback が無い環境では明示的に失敗させる
    /// （黙って return すると偽陽性になる）。IPv4 を手放してからダイヤルまでの窓は std では塞げない残余。
    fn ipv6_only_listener() -> TcpListener {
        for _ in 0..20 {
            let v4l = TcpListener::bind("127.0.0.1:0").expect("bind v4");
            let p = v4l.local_addr().expect("addr").port();
            if let Ok(l) = TcpListener::bind(("::1", p)) {
                drop(v4l);
                return l;
            }
        }
        panic!("precondition: could not bind an IPv6-only loopback listener");
    }

    /// CRI-6・NET-3・#4575: `::1` だけで待ち受ける listener へ届き、往復できる（実ソケット）。
    #[test]
    fn cri6_net3_4575_falls_back_to_ipv6_loopback() {
        let l = ipv6_only_listener();
        let port = l.local_addr().expect("addr").port();
        let io_limit = Duration::from_secs(5);
        let server = std::thread::spawn(move || {
            l.set_nonblocking(true).expect("nonblocking");
            let deadline = Instant::now() + io_limit;
            let (mut c, peer) = loop {
                match l.accept() {
                    Ok(x) => break x,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "accept deadline exceeded");
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
            peer
        });
        let mut s = NodeLoopbackDialer::new()
            .dial(&node(), port, Duration::from_secs(10))
            .expect("dial");
        s.set_read_timeout(Some(io_limit)).expect("read timeout");
        s.set_write_timeout(Some(io_limit)).expect("write timeout");
        assert_eq!(
            s.peer_addr().expect("peer").to_string(),
            format!("[::1]:{port}")
        );
        s.write_all(b"ping").expect("send");
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).expect("recv");
        assert_eq!(&buf, b"ping");
        let peer = server.join().expect("join");
        assert_eq!(peer, s.local_addr().expect("local"));
    }

    /// CRI-6・#4575: 両方で待ち受けるときは IPv4 を優先する。
    #[test]
    fn cri6_net3_4575_prefers_ipv4_when_both_listen() {
        let (v4l, _v6l) = (0..20)
            .find_map(|_| {
                let v4l = TcpListener::bind("127.0.0.1:0").ok()?;
                let p = v4l.local_addr().ok()?.port();
                TcpListener::bind(("::1", p)).ok().map(|v6l| (v4l, v6l))
            })
            .expect("precondition: could not bind both loopbacks");
        let port = v4l.local_addr().expect("addr").port();
        let s = NodeLoopbackDialer::new()
            .dial(&node(), port, Duration::from_secs(10))
            .expect("dial");
        assert_eq!(
            s.peer_addr().expect("peer").to_string(),
            format!("127.0.0.1:{port}")
        );
    }

    static MISMATCH_LISTENER_PORT: AtomicUsize = AtomicUsize::new(0);

    fn to_other_port(_a: &SocketAddr, t: Duration) -> io::Result<TcpStream> {
        let other = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            MISMATCH_LISTENER_PORT.load(Ordering::SeqCst) as u16,
        );
        TcpStream::connect_timeout(&other, t)
    }

    /// SEC-1・#4575: 接続した宛先と peer が一致しなければ拒否する（完全一致の照合が効いていること）。
    #[test]
    fn sec1_4575_peer_mismatch_is_rejected() {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        MISMATCH_LISTENER_PORT.store(
            usize::from(l.local_addr().expect("addr").port()),
            Ordering::SeqCst,
        );
        let e = NodeLoopbackDialer::with_connector(to_other_port)
            .dial(&node(), 9, Duration::from_secs(10))
            .expect_err("mismatch");
        assert_eq!(e.code(), CriErrorCode::Unavailable);
        assert_eq!(e.message(), "port forward dial failed");
    }
}
