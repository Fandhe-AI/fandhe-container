//! vsock トランスポート（[`fandhe_container_io::vsock`]）の結合試験
//! （IO-1・REPAIR-5・P1-3・PLUG-12 相当・SEC-4・TASK-13.4・#1119）。
//!
//! # 実機前提テストの扱い（ci.md「実機前提テスト」）
//! Linux の loopback 試験は、カーネルモジュール `vsock_loopback`（Linux 5.6 以降。通常は
//! root の `modprobe vsock_loopback` でロードする）と `/dev/vsock` への読み書き権限が要る。
//! GitHub ホステッド runner ではモジュールのロードが保証されないため、既定のテスト集合
//! から外して `#[ignore]` にしている。実行は
//! `cargo test -p fandhe-container-io --test vsock -- --ignored`（root は不要。必要環境は
//! AGENTS.md の「実機前提テスト」節）。
//!
//! 接続元は loopback では CID 1（`VMADDR_CID_LOCAL`）として見える。ホスト上の任意 uid の
//! プロセスが CID 1 経由で接続できるため、受理する CID を明示するポリシー
//! ([`VsockPeerPolicy::exact_cid`]) を各テストで CID 1 に指定している。
//!
//! 共通のストリーム処理（期限・drain・受信上限・poison）は UDS と共有する
//! `crate::stream_io` にあり、UDS の結合試験（`tests/server.rs`）が既定の集合で常時検証する。
//! ここでは vsock 固有の部分（アドレス・CID 検証・方向別のフレーム種別・向きの引き継ぎ）に
//! 加えて、同じ契約を vsock 経由でも確認する。

use fandhe_container_io::{IoErrorCode, VsockAddr, VsockPeerPolicy};

/// 全 OS: 期待 CID に `VMADDR_CID_ANY` は指定できない（「任意の相手」を作らない）。
#[test]
fn plug12_vsock_peer_policy_rejects_cid_any_and_accepts_explicit_cids() {
    let err = VsockPeerPolicy::exact_cid(VsockAddr::CID_ANY)
        .expect_err("VMADDR_CID_ANY must not be usable as an expected peer");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);

    for cid in [
        VsockAddr::CID_HYPERVISOR,
        VsockAddr::CID_LOCAL,
        VsockAddr::CID_HOST,
        3,
    ] {
        let policy = VsockPeerPolicy::exact_cid(cid).expect("explicit CID must be accepted");
        assert_eq!(policy.expected_cid(), cid);
    }
}

/// 全 OS: アドレスの値の保持と定数（`linux/vm_sockets.h` の値）。
#[test]
fn io1_vsock_addr_constants_match_kernel_header() {
    let addr = VsockAddr::new(3, 1234);
    assert_eq!(addr.cid(), 3);
    assert_eq!(addr.port(), 1234);
    assert_eq!(VsockAddr::CID_ANY, 0xFFFF_FFFF);
    assert_eq!(VsockAddr::PORT_ANY, 0xFFFF_FFFF);
    assert_eq!(VsockAddr::CID_HYPERVISOR, 0);
    assert_eq!(VsockAddr::CID_LOCAL, 1);
    assert_eq!(VsockAddr::CID_HOST, 2);
}

/// 非 Linux（macOS・Windows）: 未実装であることを fail-closed で示す（REPAIR-3）。
#[cfg(not(target_os = "linux"))]
mod unsupported {
    use std::time::Duration;

    use fandhe_container_io::{
        IoErrorCode, IoTimeout, NoopServerObserver, ReceiveLimits, VsockAddr, VsockConnection,
        VsockPeerPolicy, VsockServer,
    };

    #[test]
    fn repair3_vsock_bind_and_connect_are_unimplemented_on_this_os() {
        let policy = VsockPeerPolicy::exact_cid(VsockAddr::CID_LOCAL).expect("valid policy");
        let err = VsockServer::bind(
            VsockAddr::new(VsockAddr::CID_ANY, VsockAddr::PORT_ANY),
            policy,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect_err("bind must be unimplemented on this OS");
        assert_eq!(err.code(), IoErrorCode::Unimplemented);

        let timeout = IoTimeout::new(Duration::from_secs(1)).expect("valid timeout");
        let err = VsockConnection::connect(
            VsockAddr::new(VsockAddr::CID_HOST, 1024),
            timeout,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect_err("connect must be unimplemented on this OS");
        assert_eq!(err.code(), IoErrorCode::Unimplemented);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::time::{Duration, Instant};

    use fandhe_container_io::{
        Frame, FrameKind, FrameReceiver, FrameSender, IoErrorCode, IoTimeout,
        JsonLinesServerObserver, NoopServerObserver, ReceiveLimits, ServerObserver, SplitTransport,
        VsockAddr, VsockConnection, VsockPeerPolicy, VsockServer,
    };

    const REQUIRES_LOOPBACK: &str = "requires the vsock_loopback kernel module (Linux >= 5.6) \
                                     and /dev/vsock access; IO-1 #1119";

    fn test_timeout() -> IoTimeout {
        IoTimeout::new(Duration::from_secs(5)).expect("5s must be a valid IoTimeout")
    }

    fn short_timeout() -> IoTimeout {
        IoTimeout::new(Duration::from_millis(300)).expect("300ms must be a valid IoTimeout")
    }

    /// loopback で接続元として見える CID（`VMADDR_CID_LOCAL`）を明示指定するポリシー。
    fn local_policy() -> VsockPeerPolicy {
        VsockPeerPolicy::exact_cid(VsockAddr::CID_LOCAL).expect("valid policy")
    }

    /// カーネルに空きポートを割り当てさせて待ち受けを始める。
    fn bind_server<O: ServerObserver>(
        limits: ReceiveLimits,
        policy: VsockPeerPolicy,
        observer: O,
    ) -> (VsockServer<O>, VsockAddr) {
        let server = VsockServer::bind(
            VsockAddr::new(VsockAddr::CID_ANY, VsockAddr::PORT_ANY),
            policy,
            limits,
            observer,
        )
        .expect("bind on VMADDR_CID_ANY with a kernel-assigned port must succeed");
        let port = server.local_addr().expect("local_addr must succeed").port();
        assert_ne!(port, VsockAddr::PORT_ANY, "kernel must assign a real port");
        (server, VsockAddr::new(VsockAddr::CID_LOCAL, port))
    }

    fn connect<O: ServerObserver>(
        addr: VsockAddr,
        limits: ReceiveLimits,
        observer: O,
    ) -> VsockConnection<O> {
        VsockConnection::connect(addr, test_timeout(), limits, observer)
            .expect("loopback client must connect")
    }

    /// サーバーと、接続済みのクライアントを 1 組作る。
    fn connected(
        limits: ReceiveLimits,
    ) -> (
        VsockServer<NoopServerObserver>,
        VsockConnection<NoopServerObserver>,
        VsockConnection<NoopServerObserver>,
    ) {
        let (mut server, addr) = bind_server(limits, local_policy(), NoopServerObserver);
        let client = connect(addr, ReceiveLimits::default(), NoopServerObserver);
        let accepted = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the loopback client");
        (server, accepted, client)
    }

    /// IO-1: クライアントが `Write` を送り、サーバーが受信して `Ack` を返し、クライアントが
    /// それを受信する（UDS と同じ `Frame` がバイト一致で往復する）。
    #[test]
    #[ignore = "requires the vsock_loopback kernel module (Linux >= 5.6) and /dev/vsock access; IO-1 #1119"]
    fn io1_vsock_roundtrip_single_frame() {
        let _ = REQUIRES_LOOPBACK;
        let (_server, mut accepted, mut client) = connected(ReceiveLimits::default());

        let request = Frame::new(FrameKind::Write, vec![0xde, 0xad, 0xbe, 0xef])
            .expect("payload within MAX_PAYLOAD_LEN must construct a Frame");
        client
            .send_frame(&request, test_timeout())
            .expect("client must send the Write frame");

        let received = accepted
            .recv_frame(test_timeout())
            .expect("server must receive the client's frame");
        assert_eq!(received.kind(), FrameKind::Write);
        assert_eq!(received.payload(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(received.encode(), request.encode());

        let ack = Frame::new(FrameKind::Ack, vec![0x01]).expect("ack frame must construct");
        accepted
            .send_frame(&ack, test_timeout())
            .expect("server must send the Ack frame");
        let got = client
            .recv_frame(test_timeout())
            .expect("client must receive the Ack frame");
        assert_eq!(got.kind(), FrameKind::Ack);
        assert_eq!(got.payload(), &[0x01]);
    }

    /// REPAIR-5: クライアントが来なければ `accept` は期限内に `Timeout` で返る。
    #[test]
    #[ignore = "requires the vsock_loopback kernel module (Linux >= 5.6) and /dev/vsock access; IO-1 #1119"]
    fn repair5_vsock_accept_times_out_without_client() {
        let (mut server, _addr) =
            bind_server(ReceiveLimits::default(), local_policy(), NoopServerObserver);
        let started = Instant::now();
        let err = server
            .accept(short_timeout(), NoopServerObserver)
            .expect_err("accept without a client must time out");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "accept must return near its deadline, took {:?}",
            started.elapsed()
        );
    }

    /// REPAIR-5・P1-3: 何も送らない相手からの受信は期限内に `Timeout` になり、以後は
    /// `Unavailable`（poison）。
    #[test]
    #[ignore = "requires the vsock_loopback kernel module (Linux >= 5.6) and /dev/vsock access; IO-1 #1119"]
    fn repair5_vsock_recv_times_out_on_silent_peer_then_poisons() {
        let (_server, mut accepted, _client) = connected(ReceiveLimits::default());
        let started = Instant::now();
        let err = accepted
            .recv_frame(short_timeout())
            .expect_err("a silent peer must time out");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert!(started.elapsed() < Duration::from_secs(3));

        let err = accepted
            .recv_frame(short_timeout())
            .expect_err("the connection must be poisoned after an error");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
        let frame = Frame::new(FrameKind::Ack, vec![0x01]).expect("frame");
        let err = accepted
            .send_frame(&frame, short_timeout())
            .expect_err("send on a poisoned connection must fail");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
    }

    /// REPAIR-5: 受信側が読まない相手へ送り続けても、送信は期限内に `Timeout` で返る。
    #[test]
    #[ignore = "requires the vsock_loopback kernel module (Linux >= 5.6) and /dev/vsock access; IO-1 #1119"]
    fn repair5_vsock_send_times_out_on_unresponsive_peer() {
        let (_server, mut accepted, _client) = connected(ReceiveLimits::default());
        let payload = vec![0u8; 1024 * 1024];
        let frame = Frame::new(FrameKind::Ack, payload).expect("frame within MAX_PAYLOAD_LEN");
        let started = Instant::now();
        let mut result = Ok(());
        // クライアントは読まないため、送信バッファが埋まった時点で書き込みが詰まる。
        for _ in 0..4096 {
            result = accepted.send_frame(&frame, short_timeout());
            if result.is_err() {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "sending must not run unbounded"
            );
        }
        let err = result.expect_err("sending to a peer that never reads must eventually time out");
        assert_eq!(err.code(), IoErrorCode::Timeout);
    }

    /// REPAIR-5: 待ち受けのないポートへの接続は、期限内に失敗として返る（無期限にブロックしない）。
    #[test]
    #[ignore = "requires the vsock_loopback kernel module (Linux >= 5.6) and /dev/vsock access; IO-1 #1119"]
    fn repair5_vsock_connect_to_unused_port_fails_within_timeout() {
        let (server, addr) =
            bind_server(ReceiveLimits::default(), local_policy(), NoopServerObserver);
        // 待ち受けを閉じて、直前まで使われていたポートへ接続する。
        drop(server);
        let started = Instant::now();
        let err = VsockConnection::connect(
            addr,
            short_timeout(),
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect_err("connect to a port with no listener must fail");
        assert!(
            matches!(err.code(), IoErrorCode::Unavailable | IoErrorCode::Timeout),
            "unexpected code: {:?}",
            err.code()
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    /// 接続先に `VMADDR_CID_ANY` は使えない（fail-closed）。
    #[test]
    #[ignore = "requires the vsock_loopback kernel module (Linux >= 5.6) and /dev/vsock access; IO-1 #1119"]
    fn io1_vsock_connect_rejects_cid_any_target() {
        let err = VsockConnection::connect(
            VsockAddr::new(VsockAddr::CID_ANY, 1024),
            short_timeout(),
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect_err("VMADDR_CID_ANY is not a valid connect target");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// TASK-13.4: bind 時に渡した受信上限が確保前の受理判定に使われる。
    #[test]
    #[ignore = "requires the vsock_loopback kernel module (Linux >= 5.6) and /dev/vsock access; IO-1 #1119"]
    fn f_820_vsock_recv_honors_receive_limits_passed_to_bind() {
        let small = ReceiveLimits::new(8, 8).expect("8 bytes must be a valid limit");
        let (_server, mut accepted, mut client) = connected(small);
        let frame = Frame::new(FrameKind::Write, vec![0u8; 9]).expect("frame");
        client
            .send_frame(&frame, test_timeout())
            .expect("client must send");
        let err = accepted
            .recv_frame(test_timeout())
            .expect_err("a Write frame over the bind-time limit must be rejected");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
        assert!(err.message().contains('8'));
        let err = accepted
            .recv_frame(test_timeout())
            .expect_err("the connection must be poisoned");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
    }

    /// IO-1・REPAIR-2: サーバー側はクライアント発の `Ack` を確保前に拒否する。
    #[test]
    #[ignore = "requires the vsock_loopback kernel module (Linux >= 5.6) and /dev/vsock access; IO-1 #1119"]
    fn io1_vsock_server_rejects_client_originated_ack_frame() {
        let (_server, mut accepted, mut client) = connected(ReceiveLimits::default());
        let ack = Frame::new(FrameKind::Ack, vec![0x01]).expect("frame");
        client
            .send_frame(&ack, test_timeout())
            .expect("client must send");
        let err = accepted
            .recv_frame(test_timeout())
            .expect_err("server must reject a client-originated Ack");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        let err = accepted
            .recv_frame(test_timeout())
            .expect_err("the connection must be poisoned");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
    }

    /// IO-1・REPAIR-2: クライアント側はサーバー発の `Write` を拒否する（方向が逆）。
    #[test]
    #[ignore = "requires the vsock_loopback kernel module (Linux >= 5.6) and /dev/vsock access; IO-1 #1119"]
    fn io1_vsock_client_rejects_server_originated_write_frame() {
        let (_server, mut accepted, mut client) = connected(ReceiveLimits::default());
        let write = Frame::new(FrameKind::Write, vec![0x01]).expect("frame");
        accepted
            .send_frame(&write, test_timeout())
            .expect("server must send");
        let err = client
            .recv_frame(test_timeout())
            .expect_err("client must reject a server-originated Write");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        let err = client
            .recv_frame(test_timeout())
            .expect_err("the connection must be poisoned");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
    }

    /// 相手が切断したら、受信は `Unavailable` になる。
    #[test]
    #[ignore = "requires the vsock_loopback kernel module (Linux >= 5.6) and /dev/vsock access; IO-1 #1119"]
    fn io1_vsock_recv_reports_unavailable_on_peer_close() {
        let (_server, mut accepted, client) = connected(ReceiveLimits::default());
        drop(client);
        let err = accepted
            .recv_frame(test_timeout())
            .expect_err("a closed peer must be reported");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
    }

    /// IO-1・P1-3: 分割後の送信側・受信側が並行に使え、片側のエラーでもう片側も `Unavailable`
    /// になる。
    #[test]
    #[ignore = "requires the vsock_loopback kernel module (Linux >= 5.6) and /dev/vsock access; IO-1 #1119"]
    fn p1_3_vsock_split_halves_share_poison() {
        let (_server, accepted, mut client) = connected(ReceiveLimits::default());
        let (mut send, mut recv) = accepted.split().expect("split must succeed");

        let write = Frame::new(FrameKind::Write, vec![0xaa]).expect("frame");
        client
            .send_frame(&write, test_timeout())
            .expect("client must send");
        let got = recv
            .recv_frame(test_timeout())
            .expect("recv half must receive");
        assert_eq!(got.payload(), &[0xaa]);

        let ack = Frame::new(FrameKind::Ack, vec![0x01]).expect("frame");
        send.send_frame(&ack, test_timeout())
            .expect("send half must send");
        let got = client
            .recv_frame(test_timeout())
            .expect("client must receive the Ack");
        assert_eq!(got.kind(), FrameKind::Ack);

        // 受信側のタイムアウトで poison が立ち、送信側も `Unavailable` になる。
        let err = recv
            .recv_frame(short_timeout())
            .expect_err("a silent peer must time out");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        let err = send
            .send_frame(&ack, short_timeout())
            .expect_err("the send half must be poisoned by the recv half");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
    }

    /// 分割後の受信側も、接続の向き（サーバー側）を引き継いでクライアント発の `Ack` を拒否する。
    #[test]
    #[ignore = "requires the vsock_loopback kernel module (Linux >= 5.6) and /dev/vsock access; IO-1 #1119"]
    fn io1_vsock_split_recv_half_keeps_direction() {
        let (_server, accepted, mut client) = connected(ReceiveLimits::default());
        let (_send, mut recv) = accepted.split().expect("split must succeed");
        let ack = Frame::new(FrameKind::Ack, vec![0x01]).expect("frame");
        client
            .send_frame(&ack, test_timeout())
            .expect("client must send");
        let err = recv
            .recv_frame(test_timeout())
            .expect_err("server-side recv half must reject Ack");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// PLUG-12 相当・SEC-4: 期待 CID と異なる接続元は accept 直後に閉じて個別に通知する。
    /// loopback の接続元は CID 1 なので、期待 CID を 7 にすると必ず拒否される。
    #[test]
    #[ignore = "requires the vsock_loopback kernel module (Linux >= 5.6) and /dev/vsock access; IO-1 #1119"]
    fn plug12_vsock_accept_rejects_unexpected_cid_and_records_peer_cid() {
        let policy = VsockPeerPolicy::exact_cid(7).expect("valid policy");
        let (mut server, addr) = bind_server(
            ReceiveLimits::default(),
            policy,
            JsonLinesServerObserver::new(),
        );

        let client_thread = std::thread::spawn(move || {
            let mut client = connect(addr, ReceiveLimits::default(), NoopServerObserver);
            // サーバーが拒否して閉じるので、受信は EOF（Unavailable）になる。
            client
                .recv_frame(IoTimeout::new(Duration::from_secs(5)).expect("timeout"))
                .expect_err("the rejected connection must be closed by the server")
                .code()
        });

        let err = server
            .accept(short_timeout(), NoopServerObserver)
            .expect_err("a mismatched peer CID must never be accepted");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert_eq!(
            client_thread.join().expect("client thread must not panic"),
            IoErrorCode::Unavailable
        );

        let lines = server.observer_mut().drain_lines();
        let rejection = lines
            .iter()
            .find(|l| l.contains("\"reason\":\"rejected_peer_credential\""))
            .expect("the rejection must be recorded as an individual audit line");
        assert!(rejection.contains("\"op\":\"accept\""), "line={rejection}");
        assert!(rejection.contains("\"peer_cid\":1,"), "line={rejection}");
        assert!(
            rejection.contains("\"peer_credential_rejections\":1"),
            "line={rejection}"
        );
        let last = lines
            .last()
            .expect("the final accept event must be recorded");
        assert!(last.contains("\"op\":\"accept\""), "line={last}");
        assert!(last.contains("\"code\":\"TIMEOUT\""), "line={last}");
    }

    /// REPAIR-4: 接続の送受信イベントが観測フックへ JSON 行で記録される。
    #[test]
    #[ignore = "requires the vsock_loopback kernel module (Linux >= 5.6) and /dev/vsock access; IO-1 #1119"]
    fn a3_vsock_json_lines_server_observer_records_events() {
        let (mut server, addr) = bind_server(
            ReceiveLimits::default(),
            local_policy(),
            JsonLinesServerObserver::new(),
        );
        let mut client = connect(addr, ReceiveLimits::default(), NoopServerObserver);
        let mut accepted = server
            .accept(test_timeout(), JsonLinesServerObserver::new())
            .expect("server must accept");

        let write = Frame::new(FrameKind::Write, vec![0x01]).expect("frame");
        client
            .send_frame(&write, test_timeout())
            .expect("client must send");
        accepted
            .recv_frame(test_timeout())
            .expect("server must receive");
        let ack = Frame::new(FrameKind::Ack, vec![0x01]).expect("frame");
        accepted
            .send_frame(&ack, test_timeout())
            .expect("server must send");

        let accept_lines = server.observer_mut().drain_lines();
        assert_eq!(accept_lines.len(), 1, "lines={accept_lines:?}");
        let accept_line = accept_lines.first().expect("one accept line");
        assert!(
            accept_line
                .starts_with("{\"event\":\"io_server\",\"op\":\"accept\",\"outcome\":\"ok\","),
            "line={accept_line}"
        );

        let lines = accepted.observer_mut().drain_lines();
        assert_eq!(lines.len(), 2, "lines={lines:?}");
        assert!(
            lines
                .first()
                .is_some_and(|l| l.contains("\"op\":\"recv\"") && l.contains("\"kind\":\"WRITE\"")),
            "lines={lines:?}"
        );
        assert!(
            lines
                .get(1)
                .is_some_and(|l| l.contains("\"op\":\"send\"") && l.contains("\"kind\":\"ACK\"")),
            "lines={lines:?}"
        );
    }
}
