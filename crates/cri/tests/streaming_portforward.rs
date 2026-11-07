//! CRI PortForward（SPDY/3.1）の結合試験（CRI-6・TASK-63.4・#682）。
//!
//! loopback の TCP だけで完結し、root も外部ネットワークも要らない。クライアントは std のブロッキング
//! `TcpStream` に生の HTTP/1.1 の Upgrade 要求を送り、その後は本 crate の `spdy` モジュールでフレームを
//! 組み立てる（サーバー側のタスクを塞がないよう `spawn_blocking` で別スレッドに逃がす）。転送先は試験用の
//! dialer で loopback の echo サーバーへつなぐ。トークンの乱数源は unix のみのため全体を `cfg(unix)` にする。
//! crictl 相当の操作の疎通は `tests/streaming.rs`（#683・TASK-63.5）。実 kubectl / crictl との照合は本番 backend の結線後（`docs/design/cri-streaming-server.md`「残るもの」）。
#![cfg(unix)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime::v1;
use fandhe_container_cri::streaming::port_forward::{
    PortForwardConfig, PortForwardDialer, PortForwardHandler,
};
use fandhe_container_cri::streaming::spdy::{
    Frame, FrameDecoder, FrameEncoder, Headers, StreamId, goaway_status, rst_status,
};
use fandhe_container_cri::streaming::{
    StreamDispatcher, StreamRequest, StreamingConfig, StreamingServer,
};

/// 転送先ポート番号から echo サーバーのアドレスへ写す試験用 dialer。表に無いポートは接続失敗にする。
struct MapDialer(HashMap<u16, SocketAddr>);

impl PortForwardDialer for MapDialer {
    fn dial(
        &self,
        pod_sandbox_id: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, CriError> {
        assert_eq!(pod_sandbox_id, "sb-1");
        let addr = self
            .0
            .get(&port)
            .ok_or_else(|| CriError::unavailable("no route"))?;
        TcpStream::connect_timeout(addr, timeout).map_err(|_| CriError::unavailable("refused"))
    }
}

/// 受けたバイトをそのまま返し、相手の書き込み側が閉じたら自分も閉じる echo サーバー。
fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            std::thread::spawn(move || {
                // 相手が止まっても待ち続けない（REPAIR-5）。期限切れは read / write のエラーで抜ける。
                let _ = conn.set_read_timeout(Some(Duration::from_secs(30)));
                let _ = conn.set_write_timeout(Some(Duration::from_secs(10)));
                let mut buf = [0u8; 4096];
                while let Ok(n) = conn.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    if conn.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
                let _ = conn.shutdown(Shutdown::Write);
            });
        }
    });
    addr
}

struct Fixture {
    server: StreamingServer,
    path: String,
}

async fn fixture(
    pf: PortForwardConfig,
    streaming: StreamingConfig,
    ports: Vec<i32>,
    echo: Option<SocketAddr>,
) -> Fixture {
    let mut map = HashMap::new();
    if let Some(echo) = echo {
        map.insert(8080u16, echo);
    }
    fixture_with_map(pf, streaming, ports, map).await
}

async fn fixture_with_map(
    pf: PortForwardConfig,
    streaming: StreamingConfig,
    ports: Vec<i32>,
    map: HashMap<u16, SocketAddr>,
) -> Fixture {
    let handler = PortForwardHandler::new(Arc::new(MapDialer(map)), pf).expect("handler");
    let dispatcher = StreamDispatcher::new().with_port_forward(Arc::new(handler));
    let server = StreamingServer::bind_with_handler(streaming, Arc::new(dispatcher))
        .await
        .expect("bind");
    let url = server
        .issuer()
        .issue(StreamRequest::PortForward(v1::PortForwardRequest {
            pod_sandbox_id: "sb-1".to_string(),
            port: ports,
        }))
        .expect("issue");
    let rest = url.strip_prefix("http://").expect("http url");
    let path = rest[rest.find('/').expect("path")..].to_string();
    Fixture { server, path }
}

struct Client {
    tcp: TcpStream,
    enc: FrameEncoder,
    dec: FrameDecoder,
}

const UPGRADE_REQUEST: &str =
    "Connection: Upgrade\r\nUpgrade: SPDY/3.1\r\nX-Stream-Protocol-Version: portforward.k8s.io\r\n";

fn raw_connect(addr: SocketAddr) -> TcpStream {
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    tcp.set_write_timeout(Some(Duration::from_secs(5)))
        .expect("write timeout");
    tcp
}

/// ヘッダ終端までを 1 バイトずつ読む（後続の SPDY フレームを食わない）。
fn read_http_head(tcp: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tcp.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
        assert!(head.len() < 8192, "head too long");
    }
    String::from_utf8_lossy(&head).into_owned()
}

impl Client {
    fn connect(addr: SocketAddr, path: &str) -> Self {
        let mut tcp = raw_connect(addr);
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{UPGRADE_REQUEST}\r\n");
        tcp.write_all(req.as_bytes()).expect("write request");
        let head = read_http_head(&mut tcp);
        assert!(head.starts_with("HTTP/1.1 101"), "head: {head}");
        let lower = head.to_ascii_lowercase();
        assert!(lower.contains("connection: upgrade"), "head: {head}");
        assert!(lower.contains("upgrade: spdy/3.1"), "head: {head}");
        assert!(
            lower.contains("x-stream-protocol-version: portforward.k8s.io"),
            "head: {head}"
        );
        Self {
            tcp,
            enc: FrameEncoder::new(),
            dec: FrameDecoder::new(),
        }
    }

    fn send(&mut self, frame: &Frame) {
        let mut bytes = Vec::new();
        self.enc.encode(frame, &mut bytes).expect("encode");
        self.tcp.write_all(&bytes).expect("send");
    }

    fn syn(&mut self, id: u32, kind: &str, port: &str, request_id: &str) {
        self.send(&Frame::SynStream {
            stream_id: sid(id),
            associated_to: 0,
            priority: 0,
            fin: false,
            unidirectional: false,
            headers: {
                let mut h = Headers::new();
                h.push("streamtype", kind);
                h.push("port", port);
                h.push("requestid", request_id);
                h
            },
        });
    }

    /// 次のフレームを読む。EOF と接続リセット・切断は None。読み取りタイムアウトは切断漏れなので panic する。
    fn recv(&mut self) -> Option<Frame> {
        loop {
            if let Some(frame) = self.dec.next_frame().expect("decode") {
                return Some(frame);
            }
            let mut buf = [0u8; 4096];
            match self.tcp.read(&mut buf) {
                Ok(0) => return None,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::UnexpectedEof
                    ) =>
                {
                    return None;
                }
                Err(e) => panic!("read failed (disconnect not observed): {e}"),
                Ok(n) => self.dec.extend(&buf[..n]),
            }
        }
    }

    /// `want` 個の SYN_REPLY を読み飛ばさず順に確認する。
    fn expect_reply(&mut self, id: u32) {
        match self.recv() {
            Some(Frame::SynReply { stream_id, .. }) => assert_eq!(stream_id.get(), id),
            other => panic!("expected SYN_REPLY for {id}, got {other:?}"),
        }
    }

    /// 指定ストリームの DATA を FIN まで集める。他のストリームのフレームは `others` に積む。
    fn collect_until_fin(&mut self, id: u32, others: &mut Vec<Frame>) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            match self.recv().expect("frame before eof") {
                Frame::Data {
                    stream_id,
                    fin,
                    data,
                } if stream_id.get() == id => {
                    out.extend(data);
                    if fin {
                        return out;
                    }
                }
                other => others.push(other),
            }
        }
    }
}

fn sid(v: u32) -> StreamId {
    StreamId::new(v).expect("sid")
}

fn data(id: u32, fin: bool, payload: &[u8]) -> Frame {
    Frame::Data {
        stream_id: sid(id),
        fin,
        data: payload.to_vec(),
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.expect("join")
}

/// CRI-6: ホスト側のクライアントが error / data の対を張り、echo サーバーのポートへ往復できる（受け入れ条件）。
#[tokio::test]
async fn cri6_port_forward_round_trip() {
    let echo = spawn_echo();
    let fx = fixture(
        PortForwardConfig::default(),
        StreamingConfig::default(),
        vec![8080],
        Some(echo),
    )
    .await;
    let addr = fx.server.local_addr();
    let path = fx.path.clone();
    blocking(move || {
        let mut c = Client::connect(addr, &path);
        c.syn(1, "error", "8080", "0");
        c.expect_reply(1);
        c.syn(3, "data", "8080", "0");
        c.expect_reply(3);
        c.send(&data(3, false, b"hello"));
        let mut got = Vec::new();
        while got.len() < 5 {
            match c.recv().expect("echo") {
                Frame::Data {
                    stream_id, data, ..
                } if stream_id.get() == 3 => got.extend(data),
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(got, b"hello");
        // クライアントが書き込み側を閉じると、echo が閉じて両ストリームに FIN が届く。
        c.send(&data(3, true, b""));
        let mut others = Vec::new();
        assert_eq!(c.collect_until_fin(3, &mut others), b"");
        assert_eq!(c.collect_until_fin(1, &mut others), b"");
        assert!(others.is_empty(), "{others:?}");
    })
    .await;
    drop(fx);
}

/// CRI-6: 複数の requestID の対が並行して別々に転送される（大きめの本体を含む）。
#[tokio::test]
async fn cri6_port_forward_concurrent_pairs() {
    let echo = spawn_echo();
    let fx = fixture(
        PortForwardConfig::default(),
        StreamingConfig::default(),
        vec![],
        Some(echo),
    )
    .await;
    let addr = fx.server.local_addr();
    let path = fx.path.clone();
    blocking(move || {
        let mut c = Client::connect(addr, &path);
        for (err, dat, rid) in [(1, 3, "a"), (5, 7, "b")] {
            c.syn(err, "error", "8080", rid);
            c.syn(dat, "data", "8080", rid);
        }
        let big = vec![0x5au8; 200_000];
        c.send(&data(3, false, b"first"));
        for chunk in big.chunks(30_000) {
            c.send(&data(7, false, chunk));
        }
        c.send(&data(3, true, b""));
        c.send(&data(7, true, b""));
        let mut others = Vec::new();
        let mut first = Vec::new();
        let mut second = Vec::new();
        // 順不同で届くので、FIN が揃うまで全フレームを振り分ける。
        let mut fins = 0;
        while fins < 4 {
            match c.recv().expect("frame") {
                Frame::Data {
                    stream_id,
                    fin,
                    data,
                } => {
                    match stream_id.get() {
                        3 => first.extend(data),
                        7 => second.extend(data),
                        _ => assert!(data.is_empty()),
                    }
                    if fin {
                        fins += 1;
                    }
                }
                other => others.push(other),
            }
        }
        assert_eq!(first, b"first");
        assert_eq!(second, big);
        // SYN_REPLY 4 件（順序は問わない）以外は来ない。
        assert_eq!(others.len(), 4, "{others:?}");
    })
    .await;
    drop(fx);
}

/// CRI-6: 転送先へ接続できないとき、error ストリームに固定の英文が届き、両ストリームが閉じる。
#[tokio::test]
async fn cri6_port_forward_dial_failure_reports_on_error_stream() {
    let fx = fixture(
        PortForwardConfig::default(),
        StreamingConfig::default(),
        vec![],
        None,
    )
    .await;
    let addr = fx.server.local_addr();
    let path = fx.path.clone();
    blocking(move || {
        let mut c = Client::connect(addr, &path);
        c.syn(1, "error", "9", "0");
        c.syn(3, "data", "9", "0");
        let mut others = Vec::new();
        let message = c.collect_until_fin(1, &mut others);
        assert_eq!(
            String::from_utf8(message).expect("utf8"),
            "error forwarding port 9: connection failed"
        );
        assert_eq!(c.collect_until_fin(3, &mut others), b"");
    })
    .await;
    drop(fx);
}

/// CRI-6: 保存済み要求の port 一覧が非空なら、一覧外のポートのストリームは REFUSED_STREAM になる。
#[tokio::test]
async fn cri6_port_forward_port_outside_allowed_list_refused() {
    let echo = spawn_echo();
    let fx = fixture(
        PortForwardConfig::default(),
        StreamingConfig::default(),
        vec![8080],
        Some(echo),
    )
    .await;
    let addr = fx.server.local_addr();
    let path = fx.path.clone();
    blocking(move || {
        let mut c = Client::connect(addr, &path);
        c.syn(1, "error", "9090", "0");
        assert_eq!(
            c.recv(),
            Some(Frame::RstStream {
                stream_id: sid(1),
                status: rst_status::REFUSED_STREAM
            })
        );
        // 不正な streamtype・port・requestid の欠落も同様に拒否される。
        c.syn(3, "bogus", "8080", "0");
        c.syn(5, "data", "80x", "0");
        c.send(&Frame::SynStream {
            stream_id: sid(7),
            associated_to: 0,
            priority: 0,
            fin: false,
            unidirectional: false,
            headers: {
                let mut h = Headers::new();
                h.push("streamtype", "data");
                h
            },
        });
        for id in [3, 5, 7] {
            assert_eq!(
                c.recv(),
                Some(Frame::RstStream {
                    stream_id: sid(id),
                    status: rst_status::REFUSED_STREAM
                })
            );
        }
        // 一覧内のポートは通る。
        c.syn(9, "error", "8080", "1");
        c.expect_reply(9);
    })
    .await;
    drop(fx);
}

/// CRI-6: PING は同じ ID で返る。
#[tokio::test]
async fn cri6_port_forward_ping_is_echoed() {
    let fx = fixture(
        PortForwardConfig::default(),
        StreamingConfig::default(),
        vec![],
        None,
    )
    .await;
    let addr = fx.server.local_addr();
    let path = fx.path.clone();
    blocking(move || {
        let mut c = Client::connect(addr, &path);
        c.send(&Frame::Ping { id: 1 });
        assert_eq!(c.recv(), Some(Frame::Ping { id: 1 }));
    })
    .await;
    drop(fx);
}

/// CRI-6: 未知のストリームへの DATA は PROTOCOL_ERROR の RST_STREAM で返る。
#[tokio::test]
async fn cri6_port_forward_data_for_unknown_stream_is_reset() {
    let fx = fixture(
        PortForwardConfig::default(),
        StreamingConfig::default(),
        vec![],
        None,
    )
    .await;
    let addr = fx.server.local_addr();
    let path = fx.path.clone();
    blocking(move || {
        let mut c = Client::connect(addr, &path);
        c.send(&data(7, false, b"x"));
        assert_eq!(
            c.recv(),
            Some(Frame::RstStream {
                stream_id: sid(7),
                status: 1
            })
        );
    })
    .await;
    drop(fx);
}

/// CRI-6: 使用済みの（または減少する）クライアント起点ストリーム ID は PROTOCOL_ERROR で切断する。
#[tokio::test]
async fn cri6_port_forward_non_monotonic_stream_id_closes_session() {
    let fx = fixture(
        PortForwardConfig::default(),
        StreamingConfig::default(),
        vec![],
        None,
    )
    .await;
    let addr = fx.server.local_addr();
    let path = fx.path.clone();
    blocking(move || {
        let mut c = Client::connect(addr, &path);
        c.syn(5, "data", "8080", "0");
        c.expect_reply(5);
        c.syn(3, "error", "8080", "0");
        assert_eq!(
            c.recv(),
            Some(Frame::GoAway {
                last_good_stream_id: 0,
                status: goaway_status::PROTOCOL_ERROR
            })
        );
        assert_eq!(c.recv(), None);
    })
    .await;
    drop(fx);
}

/// CRI-6: Upgrade 後に送受信が無いまま idle の期限が来ると、GOAWAY を送って切断する。
#[tokio::test]
async fn cri6_port_forward_idle_timeout_closes_session() {
    let fx = fixture(
        PortForwardConfig {
            idle_timeout: Duration::from_millis(300),
            ..Default::default()
        },
        StreamingConfig::default(),
        vec![],
        None,
    )
    .await;
    let addr = fx.server.local_addr();
    let path = fx.path.clone();
    blocking(move || {
        let mut c = Client::connect(addr, &path);
        assert_eq!(
            c.recv(),
            Some(Frame::GoAway {
                last_good_stream_id: 0,
                status: 0
            })
        );
        assert_eq!(c.recv(), None);
    })
    .await;
    drop(fx);
}

/// CRI-6: 上限を超えるフレーム長は PROTOCOL_ERROR の GOAWAY で切断する。
#[tokio::test]
async fn cri6_port_forward_oversize_frame_closes_session() {
    let fx = fixture(
        PortForwardConfig {
            max_frame_bytes: 1024,
            ..Default::default()
        },
        StreamingConfig::default(),
        vec![],
        None,
    )
    .await;
    let addr = fx.server.local_addr();
    let path = fx.path.clone();
    blocking(move || {
        let mut c = Client::connect(addr, &path);
        c.syn(1, "data", "8080", "0");
        c.expect_reply(1);
        c.send(&data(1, false, &[0u8; 2000]));
        assert_eq!(
            c.recv(),
            Some(Frame::GoAway {
                last_good_stream_id: 0,
                status: goaway_status::PROTOCOL_ERROR
            })
        );
        assert_eq!(c.recv(), None);
    })
    .await;
    drop(fx);
}

/// CRI-6: 対が揃わないまま対の成立待ちの期限が来ると、既存のストリームが CANCEL で閉じられる。
#[tokio::test]
async fn cri6_port_forward_unpaired_stream_times_out() {
    let fx = fixture(
        PortForwardConfig {
            pair_timeout: Duration::from_millis(300),
            ..Default::default()
        },
        StreamingConfig::default(),
        vec![],
        None,
    )
    .await;
    let addr = fx.server.local_addr();
    let path = fx.path.clone();
    blocking(move || {
        let mut c = Client::connect(addr, &path);
        c.syn(1, "error", "8080", "0");
        c.expect_reply(1);
        assert_eq!(
            c.recv(),
            Some(Frame::RstStream {
                stream_id: sid(1),
                status: rst_status::CANCEL
            })
        );
    })
    .await;
    drop(fx);
}

/// CRI-6: Upgrade の欠落・プロトコル版の不一致は 400 になり、Upgrade しない。
#[tokio::test]
async fn cri6_port_forward_rejects_missing_upgrade_headers() {
    let fx = fixture(
        PortForwardConfig::default(),
        StreamingConfig::default(),
        vec![],
        None,
    )
    .await;
    let addr = fx.server.local_addr();
    let path = fx.path.clone();
    let head = blocking(move || {
        let mut tcp = raw_connect(addr);
        tcp.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .expect("write");
        read_http_head(&mut tcp)
    })
    .await;
    assert!(head.starts_with("HTTP/1.1 400"), "head: {head}");
    drop(fx);
}

/// CRI-6・REPAIR-3・#3753: `StreamDispatcher` に PortForward だけを登録した構成で、未登録の種別（Exec）は
/// URL を発行せず `UNIMPLEMENTED` になり、結線済みは PortForward だけと答える。
#[tokio::test]
async fn cri6_repair3_dispatcher_with_port_forward_only_refuses_exec_issue() {
    let handler = PortForwardHandler::new(
        Arc::new(MapDialer(HashMap::new())),
        PortForwardConfig::default(),
    )
    .expect("handler");
    let dispatcher = StreamDispatcher::new().with_port_forward(Arc::new(handler));
    let server =
        StreamingServer::bind_with_handler(StreamingConfig::default(), Arc::new(dispatcher))
            .await
            .expect("bind");
    let issuer = server.issuer();
    assert!(issuer.is_wired(fandhe_container_cri::streaming::StreamKind::PortForward));
    assert!(!issuer.is_wired(fandhe_container_cri::streaming::StreamKind::Exec));
    let err = issuer
        .issue(StreamRequest::Exec(v1::ExecRequest {
            container_id: "c1".to_string(),
            cmd: vec!["sh".to_string()],
            tty: false,
            stdin: false,
            stdout: true,
            stderr: false,
        }))
        .expect_err("exec is not wired");
    assert_eq!(
        err.code(),
        fandhe_container_cri::error::CriErrorCode::Unimplemented
    );
    drop(server);
}

/// CRI-6: Upgrade 後のセッションが接続数の枠（`max_connections`）を保持し続け、閉じると枠が返る。
#[tokio::test]
async fn cri6_port_forward_session_holds_connection_permit() {
    let fx = fixture(
        PortForwardConfig::default(),
        StreamingConfig::default().with_max_connections(1),
        vec![],
        None,
    )
    .await;
    let addr = fx.server.local_addr();
    let path = fx.path.clone();
    blocking(move || {
        let mut c = Client::connect(addr, &path);
        // 枠が 1 つだけなので 2 本目は応答なしで閉じられる。
        let mut second = raw_connect(addr);
        let mut buf = [0u8; 16];
        // EOF か接続リセットだけを切断とみなし、TimedOut / WouldBlock は失敗にする（REPAIR-12）。
        match second.read(&mut buf) {
            Ok(0) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) => {}
            other => panic!("second connection must be closed, got {other:?}"),
        }
        c.send(&Frame::Ping { id: 1 });
        assert_eq!(c.recv(), Some(Frame::Ping { id: 1 }));
        drop(c);
    })
    .await;
    drop(fx);
}

/// 受け付けるだけで一切読まない転送先（接続は保持して閉じない）。
fn spawn_sink() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind sink");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for conn in listener.incoming().flatten() {
            held.push(conn);
        }
    });
    addr
}

/// CRI-6・REPAIR-5・TASK-63.4: 片方の転送先が TCP を読まず滞留が上限に達しても、有限時間でその対が
/// RST_STREAM(CANCEL) で閉じられて受信が再開し、同じ接続の別の対の DATA とクライアントの RST_STREAM が処理される。
#[tokio::test]
async fn cri6_stalled_target_does_not_block_other_pairs_or_rst_stream() {
    let echo = spawn_echo();
    let sink = spawn_sink();
    let fx = fixture_with_map(
        PortForwardConfig {
            write_stall_timeout: Duration::from_millis(500),
            ..Default::default()
        },
        StreamingConfig::default(),
        vec![],
        HashMap::from([(8080u16, echo), (8081u16, sink)]),
    )
    .await;
    let addr = fx.server.local_addr();
    let path = fx.path.clone();
    blocking(move || {
        let mut c = Client::connect(addr, &path);
        // 対 B（echo）と対 A（読まない sink）を張る。
        c.syn(1, "error", "8080", "b");
        c.expect_reply(1);
        c.syn(3, "data", "8080", "b");
        c.expect_reply(3);
        c.syn(5, "error", "8081", "a");
        c.expect_reply(5);
        c.syn(7, "data", "8081", "a");
        c.expect_reply(7);
        // 対 A の data へ大量に送る。sink が読まないため、いずれサーバーは滞留の上限で受信を止める。
        let mut flood = Vec::new();
        let mut enc = FrameEncoder::new();
        for _ in 0..2048 {
            enc.encode(&data(7, false, &[0xAB; 16 * 1024]), &mut flood)
                .expect("encode flood");
        }
        let mut writer = c.tcp.try_clone().expect("clone");
        writer
            .set_write_timeout(Some(Duration::from_secs(20)))
            .expect("write timeout");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_w = Arc::clone(&stop);
        let flooder = std::thread::spawn(move || {
            // フレームの境界で止める（途中で止めると後続のフレームが壊れる）。
            for chunk in flood.chunks(8 + 16 * 1024) {
                if stop_w.load(std::sync::atomic::Ordering::Acquire)
                    || writer.write_all(chunk).is_err()
                {
                    break;
                }
            }
        });
        // 打ち切りの CANCEL が有限時間（読み取り期限 5 秒）で両ストリームに届く。
        let started = std::time::Instant::now();
        let mut cancelled = Vec::new();
        while cancelled.len() < 2 {
            match c.recv().expect("frame before eof") {
                Frame::RstStream { stream_id, status }
                    if status == rst_status::CANCEL && [5, 7].contains(&stream_id.get()) =>
                {
                    cancelled.push(stream_id.get());
                }
                _ => {}
            }
        }
        cancelled.sort_unstable();
        assert_eq!(cancelled, vec![5, 7]);
        assert!(
            started.elapsed() >= Duration::from_millis(500),
            "aborted before the stall timeout: {:?}",
            started.elapsed()
        );
        stop.store(true, std::sync::atomic::Ordering::Release);
        flooder.join().expect("flooder");

        // 対 B の DATA は echo される（A の打ち切り後の DATA に対する RST_STREAM は読み飛ばす）。
        let write_b = |c: &mut Client| c.send(&data(3, false, b"still-alive"));
        write_b(&mut c);
        let mut echoed = Vec::new();
        while echoed.len() < b"still-alive".len() {
            match c.recv().expect("frame before eof") {
                Frame::Data {
                    stream_id, data, ..
                } if stream_id.get() == 3 => echoed.extend(data),
                _ => {}
            }
        }
        assert_eq!(echoed, b"still-alive");

        // クライアントの RST_STREAM が処理される: 対 B の相手側ストリーム 3 が CANCEL で閉じられる。
        c.send(&Frame::RstStream {
            stream_id: sid(1),
            status: rst_status::CANCEL,
        });
        loop {
            match c.recv().expect("frame before eof") {
                Frame::RstStream { stream_id, status }
                    if stream_id.get() == 3 && status == rst_status::CANCEL =>
                {
                    break;
                }
                _ => {}
            }
        }
    })
    .await;
    drop(fx);
}
