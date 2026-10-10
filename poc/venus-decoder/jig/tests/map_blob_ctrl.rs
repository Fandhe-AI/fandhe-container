//! ctrl ring 経由の `RESOURCE_MAP_BLOB` / `UNMAP_BLOB` の結合試験（GPU-6・REPAIR-5・REPAIR-12・TASK-172 F5.2b.4a・#1643）。
//!
//! 偽 frontend が vhost-user で ring 0 を設定し、別の socketpair を backend channel（`SET_BACKEND_REQ_FD`）として渡す。
//! 要求は ring に積んで kick するので、`service_ctrl` の要求読み取り・応答書き戻し・used ring 更新・call 通知を通る。
//! 成功・frontend の失敗応答・切断（通信失敗）・短い writable に対するゲストへの応答と used len を具体値で照合する。
//! memfd と SCM_RIGHTS を使うため Linux x86_64 / aarch64 のみ（他は skip を明示）。

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[test]
fn gpu6_map_blob_ctrl_is_linux_only() {
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
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::thread::{self, JoinHandle};

    use fandhe_container_poc_venus_jig::session::{SessionEnd, SessionError, SessionLimits, run};
    use fandhe_container_poc_venus_jig::vhost_user::backend_req::{
        BackendRequestCode, decode_backend_request, encode_backend_reply,
    };
    use fandhe_container_poc_venus_jig::vhost_user::fd_passing::{recv_with_fds, send_with_fds};

    type Outcome = (Result<SessionEnd, SessionError>, Vec<String>);
    /// 偽 frontend が受けた要求（種別・shm_offset・len・添付 fd 数）。
    type Seen = (BackendRequestCode, u64, u64, usize);

    const OK_NODATA: u32 = 0x1100;
    const OK_MAP_INFO: u32 = 0x1106;
    const ERR_UNSPEC: u32 = 0x1200;

    fn spawn_backend(sock: UnixStream) -> JoinHandle<Outcome> {
        thread::spawn(move || {
            let limits = SessionLimits::new(T, T).expect("limits");
            let mut lines = Vec::new();
            let end = run(&sock, &limits, &mut |l: &str| lines.push(l.to_string()));
            (end, lines)
        })
    }

    /// backend channel の偽 frontend: `replies`（None は応答せず切断）の数だけ要求を受けて応答する。
    fn frontend_channel(b: UnixStream, replies: Vec<Option<u64>>) -> JoinHandle<Vec<Seen>> {
        thread::spawn(move || {
            let mut seen = Vec::new();
            for v in replies {
                let mut buf = [0u8; 64];
                let r = recv_with_fds(&b, &mut buf, 1, T).expect("recv");
                let d = decode_backend_request(buf.get(..r.len).expect("len")).expect("decode");
                seen.push((d.request, d.shm_offset, d.len, r.fds.len()));
                match v {
                    Some(v) => {
                        send_with_fds(&b, &encode_backend_reply(d.request, v), &[], T)
                            .expect("reply");
                    }
                    None => return seen,
                }
            }
            seen
        })
    }

    fn create_blob(res: u32, size: u64) -> Vec<u8> {
        let mut v = ctrl_req(0x010c, 1, 56, &[(24, res), (28, 2), (32, 1)]);
        v[48..56].copy_from_slice(&size.to_le_bytes());
        v
    }

    fn map_blob(res: u32, offset: u64) -> Vec<u8> {
        let mut v = ctrl_req(0x0208, 0, 40, &[(24, res)]);
        v[32..40].copy_from_slice(&offset.to_le_bytes());
        v
    }

    fn unmap_blob(res: u32) -> Vec<u8> {
        ctrl_req(0x0209, 0, 32, &[(24, res)])
    }

    /// ctx 1 と res 7（8192 バイト）を用意した状態で ring 0 を返す。要求 0・1 を消費済み（次は n=2。ring は 8 descriptor = 4 要求まで）。
    fn start(tag: &str) -> (Frontend, UnixStream, JoinHandle<Outcome>) {
        let (front, back) = UnixStream::pair().expect("pair");
        let (chan_front, chan_give) = UnixStream::pair().expect("chan");
        let backend = spawn_backend(back);
        let fe = setup_ring0_shmem(front, 408, tag, chan_give.as_fd());
        drop(chan_give);
        post(&fe, 0, &ctx_create_req(1), 408);
        post(&fe, 1, &create_blob(7, 8192), 408);
        assert_eq!(
            (resp_type(&fe, 0), resp_type(&fe, 1)),
            (OK_NODATA, OK_NODATA)
        );
        (fe, chan_front, backend)
    }

    #[test]
    fn f5_2b_4a_gpu6_ring_map_unmap_success_returns_map_info_and_nodata() {
        let (fe, chan, backend) = start("mapok");
        let h = frontend_channel(chan, vec![Some(0), Some(0)]);
        post(&fe, 2, &map_blob(7, 4096), 408);
        assert_eq!((resp_type(&fe, 2), used_len(&fe, 2)), (OK_MAP_INFO, 32));
        post(&fe, 3, &unmap_blob(7), 408);
        assert_eq!((resp_type(&fe, 3), used_len(&fe, 3)), (OK_NODATA, 24));
        let seen = h.join().expect("join");
        assert_eq!(
            seen,
            vec![
                (BackendRequestCode::ShmemMap, 4096, 8192, 1),
                (BackendRequestCode::ShmemUnmap, 4096, 8192, 0),
            ]
        );
        drop(fe);
        let (end, lines) = backend.join().expect("join");
        assert_eq!(end, Ok(SessionEnd::PeerClosed));
        let want = "venus_jig event=resource cmd=RESOURCE_MAP_BLOB res_id=7 offset=4096 size=8192 map_info=1 result=ok";
        assert_eq!(
            lines.iter().filter(|l| l.as_str() == want).count(),
            1,
            "{lines:?}"
        );
    }

    #[test]
    fn f5_2b_4a_gpu6_ring_frontend_failure_returns_err_then_retry_succeeds() {
        let (fe, chan, backend) = start("mapfail");
        let h = frontend_channel(chan, vec![Some((-22i64) as u64), Some(0)]);
        post(&fe, 2, &map_blob(7, 4096), 408);
        assert_eq!((resp_type(&fe, 2), used_len(&fe, 2)), (ERR_UNSPEC, 24));
        // 失敗した MAP は巻き戻されているので、同じ要求が再び frontend へ届いて成功する。
        post(&fe, 3, &map_blob(7, 4096), 408);
        assert_eq!((resp_type(&fe, 3), used_len(&fe, 3)), (OK_MAP_INFO, 32));
        assert_eq!(h.join().expect("join").len(), 2);
        drop(fe);
        assert_eq!(backend.join().expect("join").0, Ok(SessionEnd::PeerClosed));
    }

    #[test]
    fn f5_2b_4a_gpu6_ring_channel_disconnect_returns_err_and_session_continues() {
        let (fe, chan, backend) = start("mapgone");
        let h = frontend_channel(chan, vec![None]);
        post(&fe, 2, &map_blob(7, 4096), 408);
        assert_eq!((resp_type(&fe, 2), used_len(&fe, 2)), (ERR_UNSPEC, 24));
        assert_eq!(h.join().expect("join").len(), 1);
        // channel が壊れた後の MAP は送らずに ERR。ctrl 自体は動き続ける。
        post(&fe, 3, &map_blob(7, 4096), 408);
        assert_eq!(resp_type(&fe, 3), ERR_UNSPEC);
        drop(fe);
        assert_eq!(backend.join().expect("join").0, Ok(SessionEnd::PeerClosed));
    }

    #[test]
    fn f5_2b_4a_gpu6_ring_short_writable_drops_without_contacting_frontend() {
        let (fe, chan, backend) = start("mapshort");
        // 要求 2: writable 24 は MAP の応答（32）に満たない。frontend へは何も送らず、used len は 0。
        post(&fe, 2, &map_blob(7, 4096), 24);
        assert_eq!(used_len(&fe, 2), 0);
        // 同じ要求を十分な長さで再送すると、巻き戻されているので frontend へ届いて成功する（届いた要求は 1 件だけ）。
        let h = frontend_channel(chan, vec![Some(0)]);
        post(&fe, 3, &map_blob(7, 4096), 408);
        assert_eq!((resp_type(&fe, 3), used_len(&fe, 3)), (OK_MAP_INFO, 32));
        assert_eq!(
            h.join().expect("join"),
            vec![(BackendRequestCode::ShmemMap, 4096, 8192, 1)]
        );
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
}
