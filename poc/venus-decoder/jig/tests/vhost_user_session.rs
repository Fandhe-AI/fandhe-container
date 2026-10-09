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
mod common;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use super::common::*;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::fs::FileExt;
    use std::os::unix::net::UnixStream;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use fandhe_container_poc_venus_jig::adapter::CtrlAdapter;
    use fandhe_container_poc_venus_jig::log::find_capset_queries;
    use fandhe_container_poc_venus_jig::session::{
        SessionEnd, SessionError, SessionErrorCode, SessionLimits, run,
    };
    use fandhe_container_poc_venus_jig::vhost_user::fd_passing::recv_with_fds;
    use fandhe_container_poc_venus_jig::vhost_user::{Request, TransportErrorCode, VringFd};

    type Outcome = (Result<SessionEnd, SessionError>, Vec<String>);

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

    /// GPU-6・REPAIR-3: 応答を書き戻せず捨てた `CTX_CREATE` は adapter の状態を残さない。
    /// 同じ ctx_id の再送が重複エラー（`ERR_INVALID_CONTEXT_ID` 0x1203）にならず `OK_NODATA`（0x1100）になる。
    #[test]
    fn gpu6_dropped_ctx_create_response_rolls_back_adapter_state() {
        let (front, backend) = pair(limits(5000, 5000));
        let fe = setup_ring0(front, 8, "rb");
        // readable を CTX_CREATE（96 バイト）の長さへ広げる。
        let mut d0 = Vec::new();
        d0.extend_from_slice(&0x4000u64.to_le_bytes());
        d0.extend_from_slice(&96u32.to_le_bytes());
        d0.extend_from_slice(&1u16.to_le_bytes());
        d0.extend_from_slice(&1u16.to_le_bytes());
        fe.mem.write_at(&d0, 0).expect("desc0");
        let mut req = vec![0u8; 96];
        req[..4].copy_from_slice(&0x0200u32.to_le_bytes());
        req[16..20].copy_from_slice(&3u32.to_le_bytes());
        req[28..32].copy_from_slice(&4u32.to_le_bytes());
        fe.mem.write_at(&req, 0x4000).expect("req");
        fe.mem.write_at(&[0, 0], 0x1004).expect("ring[0]");
        fe.mem.write_at(&[1, 0], 0x1002).expect("idx");
        (&fe.kick).write_all(&1u64.to_le_bytes()).expect("kick");
        wait_call(&fe);
        // 8 バイトの writable には 24 バイトの応答が入らず len=0。
        assert_eq!(used(&fe), [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // writable を広げて同じ要求を再送する。
        let mut d1 = Vec::new();
        d1.extend_from_slice(&0x5000u64.to_le_bytes());
        d1.extend_from_slice(&408u32.to_le_bytes());
        d1.extend_from_slice(&2u16.to_le_bytes());
        d1.extend_from_slice(&0u16.to_le_bytes());
        fe.mem.write_at(&d1, 16).expect("desc1");
        fe.mem.write_at(&[0, 0], 0x1006).expect("ring[1]");
        fe.mem.write_at(&[2, 0], 0x1002).expect("idx");
        (&fe.kick).write_all(&1u64.to_le_bytes()).expect("kick");
        wait_call(&fe);
        let mut resp = [0u8; 4];
        fe.mem.read_at(&mut resp, 0x5000).expect("resp");
        assert_eq!(resp, 0x1100u32.to_le_bytes());
        drop(fe);
        let (end, _lines) = backend.join().expect("join");
        assert_eq!(end, Ok(SessionEnd::PeerClosed));
    }

    /// n 番目（0..4）の要求を ring 0 へ積んで kick し、call を待つ。descriptor は 2n（readable・NEXT）と 2n+1（writable）。
    fn post(fe: &Frontend, n: u16, req: &[u8], writable_len: u32) {
        let desc = |addr: u64, len: u32, flags: u16, next: u16| {
            let mut d = Vec::new();
            d.extend_from_slice(&addr.to_le_bytes());
            d.extend_from_slice(&len.to_le_bytes());
            d.extend_from_slice(&flags.to_le_bytes());
            d.extend_from_slice(&next.to_le_bytes());
            d
        };
        let req_addr = 0x4000 + u64::from(n) * 0x400;
        let resp_addr = 0x5000 + u64::from(n) * 0x400;
        let head = 2 * n;
        let readable = u32::try_from(req.len()).expect("len");
        fe.mem
            .write_at(&desc(req_addr, readable, 1, head + 1), u64::from(head) * 16)
            .expect("desc r");
        fe.mem
            .write_at(
                &desc(resp_addr, writable_len, 2, 0),
                u64::from(head + 1) * 16,
            )
            .expect("desc w");
        fe.mem.write_at(req, req_addr).expect("req");
        fe.mem
            .write_at(&head.to_le_bytes(), 0x1004 + u64::from(n) * 2)
            .expect("ring");
        fe.mem
            .write_at(&(n + 1).to_le_bytes(), 0x1002)
            .expect("idx");
        (&fe.kick).write_all(&1u64.to_le_bytes()).expect("kick");
        wait_call(fe);
    }

    fn resp_type(fe: &Frontend, n: u16) -> u32 {
        let mut b = [0u8; 4];
        fe.mem
            .read_at(&mut b, 0x5000 + u64::from(n) * 0x400)
            .expect("resp");
        u32::from_le_bytes(b)
    }

    fn used_len(fe: &Frontend, n: u16) -> u32 {
        let mut b = [0u8; 4];
        fe.mem
            .read_at(&mut b, 0x2000 + 4 + u64::from(n) * 8 + 4)
            .expect("used len");
        u32::from_le_bytes(b)
    }

    fn ctrl_req(cmd: u32, ctx: u32, total: usize, words: &[(usize, u32)]) -> Vec<u8> {
        let mut v = vec![0u8; total];
        v[..4].copy_from_slice(&cmd.to_le_bytes());
        v[16..20].copy_from_slice(&ctx.to_le_bytes());
        for (off, x) in words {
            v[*off..*off + 4].copy_from_slice(&x.to_le_bytes());
        }
        v
    }

    /// GPU-6・TASK-172.4・#1601: 応答を書き戻せず捨てた `RESOURCE_CREATE_BLOB` は資源表を残さない。
    /// 同じ resource_id の再送が `ERR_INVALID_RESOURCE_ID`（0x1203）にならず `OK_NODATA`（0x1100）になり、
    /// 続く `CTX_ATTACH_RESOURCE` も成功する。
    #[test]
    fn task1601_gpu6_dropped_blob_response_rolls_back_resource_table() {
        let (front, backend) = pair(limits(5000, 5000));
        let fe = setup_ring0(front, 408, "blobrb");
        post(&fe, 0, &ctrl_req(0x0200, 1, 96, &[(24, 3), (28, 4)]), 408);
        assert_eq!(resp_type(&fe, 0), 0x1100);
        let mut blob = ctrl_req(0x010c, 1, 56, &[(24, 7), (28, 2), (32, 1)]);
        blob[48..56].copy_from_slice(&8192u64.to_le_bytes());
        // writable が 8 バイトで 24 バイトの応答が入らない -> len=0 で捨てられる。
        post(&fe, 1, &blob, 8);
        assert_eq!(used_len(&fe, 1), 0);
        // 同じ要求の再送は成功する（巻き戻されていなければ 0x1203）。
        post(&fe, 2, &blob, 408);
        assert_eq!(resp_type(&fe, 2), 0x1100);
        assert_eq!(used_len(&fe, 2), 24);
        post(&fe, 3, &ctrl_req(0x0202, 1, 32, &[(24, 7)]), 408);
        assert_eq!(resp_type(&fe, 3), 0x1100);
        drop(fe);
        let (end, lines) = backend.join().expect("join");
        assert_eq!(end, Ok(SessionEnd::PeerClosed));
        assert!(
            lines.contains(
                &"venus_jig event=response_dropped reason=writable_too_small".to_string()
            ),
            "log: {lines:?}"
        );
    }

    /// GPU-6・TASK-172.4・#1601: session 経由の `SUBMIT_3D` は `OK_NODATA`（24 バイト）で応答し、ログ行が出る。
    #[test]
    fn task1601_gpu6_submit_3d_over_session_is_acked() {
        let (front, backend) = pair(limits(5000, 5000));
        let fe = setup_ring0(front, 408, "submit");
        post(&fe, 0, &ctrl_req(0x0200, 1, 96, &[(24, 3), (28, 4)]), 408);
        let mut req = ctrl_req(0x0207, 1, 32, &[(24, 256)]);
        req[4..8].copy_from_slice(&2u32.to_le_bytes());
        req[20] = 0;
        let mut body = vec![0u8; 256];
        body[..4].copy_from_slice(&188u32.to_le_bytes());
        req.extend_from_slice(&body);
        post(&fe, 1, &req, 408);
        assert_eq!(resp_type(&fe, 1), 0x1100);
        assert_eq!(used_len(&fe, 1), 24);
        drop(fe);
        let (end, lines) = backend.join().expect("join");
        assert_eq!(end, Ok(SessionEnd::PeerClosed));
        let want = "venus_jig event=submit_3d cmd=SUBMIT_3D ctx_id=1 ring_idx=0 size=256 venus_cmd=188 wire=ok result=ok";
        assert!(lines.iter().any(|l| l == want), "log: {lines:?}");
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
