//! vhost-user セッションと ctrl キュー応答ループの結合試験（GPU-6・REPAIR-5・TASK-172 F1.4・#1519）。
//!
//! 偽 frontend（`UnixStream` のペアの片端）が、ネゴシエーション → ring 設定 → kick → capset クエリの応答 → call の
//! 一連を送り、used ring・応答バイト列・構造化ログを具体値で照合する。順序違反・fd 個数・タイムアウトも構造化エラーとして
//! 照合する。memfd・`SCM_RIGHTS` は Linux 固有で定数は x86_64 / aarch64 にだけあるため、それ以外では skip を明示する
//! テスト 1 本だけを走らせる（`vhost_user_transport.rs` と同じ流儀）。root・KVM・GPU は要らない。

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[test]
fn gpu6_session_is_linux_only() {
    eprintln!("skip: the vhost-user session is Linux x86_64 / aarch64 only (memfd, SCM_RIGHTS)");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::fs::FileExt;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use fandhe_container_poc_venus_jig::adapter::CtrlAdapter;
    use fandhe_container_poc_venus_jig::log::find_capset_queries;
    use fandhe_container_poc_venus_jig::session::{
        SessionEnd, SessionError, SessionErrorCode, SessionLimits, run,
    };
    use fandhe_container_poc_venus_jig::vhost_user::fd_passing::{
        create_memfd, recv_with_fds, send_with_fds,
    };
    use fandhe_container_poc_venus_jig::vhost_user::{
        ConfigPayload, MemRegion, MemTable, Reply, Request, RequestCode, TransportErrorCode,
        VringAddr, VringFd, VringState, decode_reply,
    };

    const T: Duration = Duration::from_secs(5);
    const FEATURES: u64 = 0x0000_0001_4000_0019;
    const UVA: u64 = 0x7f00_0000_0000;
    const MEM_LEN: u64 = 0x1_0000;

    type Outcome = (Result<SessionEnd, SessionError>, Vec<String>);

    fn unique_name(tag: &str) -> String {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        format!(
            "jig-sess-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn memfd(name: &str, len: u64) -> File {
        create_memfd(&CString::new(name).expect("name"), len).expect("memfd")
    }

    fn count_fds(name: &str) -> usize {
        let needle = format!("/memfd:{name} (deleted)");
        std::fs::read_dir("/proc/self/fd")
            .expect("read /proc/self/fd")
            .filter_map(|e| e.ok())
            .filter_map(|e| std::fs::read_link(e.path()).ok())
            .filter(|l| l.to_string_lossy() == needle)
            .count()
    }

    fn limits(message_ms: u64, idle_ms: u64) -> SessionLimits {
        SessionLimits::new(
            Duration::from_millis(message_ms),
            Duration::from_millis(idle_ms),
        )
        .expect("limits")
    }

    /// backend（`run`）を別スレッドで動かす。終了時に socket は閉じられ、frontend は `PEER_CLOSED` を観測できる。
    fn spawn_backend(sock: UnixStream, limits: SessionLimits) -> JoinHandle<Outcome> {
        std::thread::spawn(move || {
            let mut lines = Vec::new();
            let r = run(&sock, &limits, &mut |l| lines.push(l.to_string()));
            (r, lines)
        })
    }

    fn pair(limits: SessionLimits) -> (UnixStream, JoinHandle<Outcome>) {
        let (front, back) = UnixStream::pair().expect("pair");
        (front, spawn_backend(back, limits))
    }

    fn send(f: &UnixStream, req: &Request, fds: &[std::os::fd::BorrowedFd<'_>]) {
        let msg = req.encode(false).expect("encode");
        let sent = send_with_fds(f, msg.as_bytes(), fds, T).expect("send");
        assert_eq!(sent.len, msg.as_bytes().len());
    }

    fn read_exact(f: &UnixStream, buf: &mut [u8]) {
        let mut done = 0;
        while done < buf.len() {
            let r = recv_with_fds(f, &mut buf[done..], 0, T).expect("recv");
            done += r.len;
        }
    }

    fn recv_reply(f: &UnixStream, expected: RequestCode) -> Reply {
        let mut hdr = [0u8; 12];
        read_exact(f, &mut hdr);
        let size = u32::from_le_bytes(hdr[8..12].try_into().expect("size")) as usize;
        let mut msg = hdr.to_vec();
        msg.resize(12 + size, 0);
        read_exact(f, &mut msg[12..]);
        decode_reply(&msg, expected).expect("decode reply")
    }

    fn cfg_req(offset: u32, size: usize) -> Request {
        Request::GetConfig(
            ConfigPayload::new(RequestCode::GetConfig, offset, 0, &vec![0u8; size]).expect("cfg"),
        )
    }

    /// `SET_FEATURES` まで済ませる（広告値・protocol feature・queue 数・config も具体値で照合）。
    fn negotiate(f: &UnixStream) {
        send(f, &Request::GetFeatures, &[]);
        assert_eq!(
            recv_reply(f, RequestCode::GetFeatures),
            Reply::Features(FEATURES)
        );
        send(f, &Request::SetOwner, &[]);
        send(f, &Request::GetProtocolFeatures, &[]);
        assert_eq!(
            recv_reply(f, RequestCode::GetProtocolFeatures),
            Reply::ProtocolFeatures(0x201)
        );
        send(f, &Request::SetProtocolFeatures(0x201), &[]);
        send(f, &Request::GetQueueNum, &[]);
        assert_eq!(recv_reply(f, RequestCode::GetQueueNum), Reply::QueueNum(2));
        send(f, &cfg_req(0, 16), &[]);
        let Reply::Config(c) = recv_reply(f, RequestCode::GetConfig) else {
            panic!("config reply expected");
        };
        let mut want = [0u8; 16];
        want[12] = 1;
        assert_eq!(c.data(), &want);
        send(f, &cfg_req(12, 8), &[]);
        assert_eq!(recv_reply(f, RequestCode::GetConfig), Reply::ConfigError);
        send(f, &Request::SetFeatures(FEATURES), &[]);
    }

    struct Frontend {
        /// 保持して接続を開いたままにするための所有（読み出しはしない）。
        _sock: UnixStream,
        mem: File,
        kick: UnixStream,
        call: UnixStream,
    }

    /// ring 0 を設定して起動する。desc1（writable）の長さは `writable_len`。
    fn setup_ring0(sock: UnixStream, writable_len: u32, tag: &str) -> Frontend {
        negotiate(&sock);
        let mem = memfd(&unique_name(tag), MEM_LEN);
        let table = MemTable::new(&[MemRegion {
            guest_phys_addr: 0,
            memory_size: MEM_LEN,
            userspace_addr: UVA,
            mmap_offset: 0,
        }])
        .expect("table");
        send(&sock, &Request::SetMemTable(table), &[mem.as_fd()]);
        let st = |num| VringState { index: 0, num };
        send(&sock, &Request::SetVringNum(st(8)), &[]);
        send(&sock, &Request::SetVringBase(st(0)), &[]);
        send(
            &sock,
            &Request::SetVringAddr(VringAddr {
                index: 0,
                flags: 0,
                descriptor: UVA,
                used: UVA + 0x2000,
                available: UVA + 0x1000,
                log: 0,
            }),
            &[],
        );
        let (kick, kick_back) = UnixStream::pair().expect("kick");
        let (call, call_back) = UnixStream::pair().expect("call");
        let vf = VringFd {
            index: 0,
            no_fd: false,
        };
        send(&sock, &Request::SetVringKick(vf), &[kick_back.as_fd()]);
        send(&sock, &Request::SetVringCall(vf), &[call_back.as_fd()]);
        // 送った後は手元の複製を閉じても backend 側の fd は生きている。
        drop((kick_back, call_back));
        send(&sock, &Request::SetVringEnable(st(1)), &[]);
        call.set_read_timeout(Some(T)).expect("timeout");
        let fe = Frontend {
            _sock: sock,
            mem,
            kick,
            call,
        };
        // desc0: readable 32 バイト（NEXT -> 1）、desc1: WRITE。
        let desc = |addr: u64, len: u32, flags: u16, next: u16| {
            let mut d = Vec::new();
            d.extend_from_slice(&addr.to_le_bytes());
            d.extend_from_slice(&len.to_le_bytes());
            d.extend_from_slice(&flags.to_le_bytes());
            d.extend_from_slice(&next.to_le_bytes());
            d
        };
        fe.mem.write_at(&desc(0x4000, 32, 1, 1), 0).expect("desc0");
        fe.mem
            .write_at(&desc(0x5000, writable_len, 2, 0), 16)
            .expect("desc1");
        fe
    }

    /// GET_CAPSET（capset_id=4・version=0）の 32 バイトを ring 0 に積んで kick する。
    fn submit_get_capset(fe: &Frontend) -> Vec<u8> {
        let mut req = vec![0u8; 32];
        req[..4].copy_from_slice(&0x0109u32.to_le_bytes());
        req[24..28].copy_from_slice(&4u32.to_le_bytes());
        fe.mem.write_at(&req, 0x4000).expect("req");
        fe.mem.write_at(&[0, 0], 0x1004).expect("ring[0]");
        fe.mem.write_at(&[1, 0], 0x1002).expect("idx");
        (&fe.kick).write_all(&1u64.to_le_bytes()).expect("kick");
        req
    }

    fn wait_call(fe: &Frontend) {
        let mut b = [0u8; 8];
        (&fe.call).read_exact(&mut b).expect("call");
        assert_eq!(u64::from_le_bytes(b), 1);
    }

    fn used(fe: &Frontend) -> [u8; 12] {
        let mut u = [0u8; 12];
        fe.mem.read_at(&mut u, 0x2000).expect("used");
        u
    }

    #[test]
    fn gpu6_negotiate_kick_capset_query_call() {
        let (front, backend) = pair(limits(5000, 5000));
        let fe = setup_ring0(front, 408, "a1");
        let req = submit_get_capset(&fe);
        wait_call(&fe);

        // used: flags=0, idx=1, ring[0]={id=0, len=184(=24+160)}。
        assert_eq!(used(&fe), [0, 0, 1, 0, 0, 0, 0, 0, 184, 0, 0, 0]);
        let mut resp = vec![0u8; 184];
        fe.mem.read_at(&mut resp, 0x5000).expect("resp");
        assert_eq!(resp[..4], 0x1103u32.to_le_bytes());
        let expected = CtrlAdapter::default().handle_ctrl(&req).response;
        assert_eq!(resp, expected.as_bytes());

        drop(fe);
        let (end, lines) = backend.join().expect("join");
        assert_eq!(end, Ok(SessionEnd::PeerClosed));
        let want = "venus_jig event=capset_query cmd=GET_CAPSET capset_id=4 version=0 result=ok max_size=160";
        assert!(lines.iter().any(|l| l == want), "log: {lines:?}");
        let report = find_capset_queries(&lines.join("\n")).expect("report");
        assert_eq!(report.venus_get_capset_ok, 1);
        // REPAIR-4: 終了時に操作別の件数・時間と fd / メモリ I/O の集計が出る（壊れた行は増えない）。
        assert_eq!(report.malformed_lines, 0, "log: {lines:?}");
        for op in ["ctrl_kick", "notify"] {
            let want = format!("venus_jig event=session_op op={op} ok=1 err=0 ");
            assert!(lines.iter().any(|l| l.starts_with(&want)), "log: {lines:?}");
        }
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("venus_jig event=vhost_user_io op=recv_fds ")),
            "log: {lines:?}"
        );
    }

    #[test]
    fn gpu6_writable_too_small_returns_len_zero_and_continues() {
        let (front, backend) = pair(limits(5000, 5000));
        let fe = setup_ring0(front, 8, "small");
        submit_get_capset(&fe);
        wait_call(&fe);
        assert_eq!(used(&fe), [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        drop(fe);
        let (end, lines) = backend.join().expect("join");
        assert_eq!(end, Ok(SessionEnd::PeerClosed));
        assert!(
            lines
                .iter()
                .any(|l| { l == "venus_jig event=response_dropped reason=writable_too_small" }),
            "log: {lines:?}"
        );
    }

    #[test]
    fn gpu6_kick_before_mem_table_is_out_of_order() {
        let (front, backend) = pair(limits(5000, 5000));
        negotiate(&front);
        let (_k, kick_back) = UnixStream::pair().expect("kick");
        let vf = VringFd {
            index: 0,
            no_fd: false,
        };
        send(&front, &Request::SetVringKick(vf), &[kick_back.as_fd()]);
        let (end, lines) = backend.join().expect("join");
        let e = end.expect_err("must fail");
        assert_eq!(
            (e.code, e.request),
            (SessionErrorCode::OutOfOrder, Some(12))
        );
        assert!(
            lines.contains(
                &"venus_jig event=session_error code=OUT_OF_ORDER request=12".to_string()
            ),
            "log: {lines:?}"
        );
        let mut b = [0u8; 1];
        let r = recv_with_fds(&front, &mut b, 0, T).expect_err("closed");
        assert_eq!(r.code, TransportErrorCode::PeerClosed);
    }

    #[test]
    fn gpu6_unoffered_feature_bit_is_rejected() {
        let (front, backend) = pair(limits(5000, 5000));
        send(&front, &Request::SetOwner, &[]);
        send(&front, &Request::SetFeatures(FEATURES | (1 << 5)), &[]);
        let (end, _) = backend.join().expect("join");
        let e = end.expect_err("must fail");
        assert_eq!(
            (e.code, e.request),
            (SessionErrorCode::FeatureNotOffered, Some(2))
        );
    }

    #[test]
    fn repair5_partial_header_times_out() {
        let (front, backend) = pair(limits(200, 5000));
        let start = Instant::now();
        (&front).write_all(&[1, 0, 0, 0]).expect("partial");
        let (end, _) = backend.join().expect("join");
        let elapsed = start.elapsed();
        assert_eq!(end.expect_err("timeout").code, SessionErrorCode::Timeout);
        assert!(
            elapsed >= Duration::from_millis(150) && elapsed < Duration::from_secs(5),
            "elapsed: {elapsed:?}"
        );
    }

    #[test]
    fn repair5_silence_hits_idle_timeout() {
        let (front, backend) = pair(limits(5000, 200));
        let (end, lines) = backend.join().expect("join");
        assert_eq!(end.expect_err("idle").code, SessionErrorCode::IdleTimeout);
        assert!(
            lines.contains(
                &"venus_jig event=session_error code=IDLE_TIMEOUT request=-1".to_string()
            ),
            "log: {lines:?}"
        );
        drop(front);
    }

    #[test]
    fn gpu6_fds_on_a_fd_less_request_are_rejected_and_closed() {
        let name = unique_name("unexpected");
        let f = memfd(&name, 8);
        let (front, backend) = pair(limits(5000, 5000));
        send(&front, &Request::GetFeatures, &[f.as_fd()]);
        let (end, _) = backend.join().expect("join");
        let e = end.expect_err("must fail");
        assert_eq!(
            (e.code, e.request),
            (SessionErrorCode::UnexpectedFds, Some(1))
        );
        // frontend 手元の 1 本だけが残り、backend が受け取った複製は閉じられている。
        assert_eq!(count_fds(&name), 1);
        drop(f);
        assert_eq!(count_fds(&name), 0);
    }
}
