//! backend 要求 `SHMEM_MAP` / `SHMEM_UNMAP` の送信の試験（GPU-6・REPAIR-5・TASK-172 F5.2b.3・#1642）。
//!
//! `socketpair` の一端を治具の backend channel として渡し、もう一端を偽 frontend のスレッドが動かす。`State` / `Session` は
//! `!Send` なので試験スレッド側に置き、スレッドへは `UnixStream` だけを渡す。期待値は具体値で照合する。

use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

use super::backend_req::{BackendReqCause, BackendReqErrorCode};
use super::negotiation::{HostVisible, HostVisibleUnavailable, State};
use super::*;
use crate::vhost_user::backend_req::{
    BackendCodecErrorCode, BackendRequest, BackendRequestCode, DecodedBackendRequest,
    ShmemMapRequest, ShmemMapping, decode_backend_request, encode_backend_reply,
};
use crate::vhost_user::fd_passing::{create_memfd, recv_with_fds, send_with_fds};
use crate::vhost_user::{Request, ShmemConfig, ShmemRegion};

pub(super) const T: Duration = Duration::from_secs(5);

fn config() -> ShmemConfig {
    ShmemConfig::new(&[ShmemRegion {
        id: 1,
        size: device::HOST_VISIBLE_SHM_SIZE,
    }])
    .expect("config")
}

fn mapping() -> ShmemMapping {
    ShmemMapping::new(&config(), 1, 4096, 8192).expect("mapping")
}

fn map_req() -> ShmemMapRequest {
    ShmemMapRequest::new(mapping(), 0).expect("req")
}

pub(super) fn session(protocol: u64, connect: bool, timeout: Duration) -> (Session, UnixStream) {
    let mut state = State::new();
    state
        .handle(Request::GetProtocolFeatures, Vec::new())
        .expect("query");
    state
        .handle(Request::SetProtocolFeatures(protocol), Vec::new())
        .expect("set");
    state
        .handle(Request::GetShmemConfig, Vec::new())
        .expect("44");
    let (a, b) = UnixStream::pair().expect("pair");
    if connect {
        state
            .handle(Request::SetBackendReqFd, vec![OwnedFd::from(a)])
            .expect("21");
    }
    let limits = SessionLimits::new(timeout, Duration::from_secs(60)).expect("limits");
    let s = Session {
        state,
        adapter: CtrlAdapter::default(),
        limits,
        metrics: SessionMetrics::default(),
        blobs: BlobMemTable::default(),
    };
    (s, b)
}

pub(super) fn ready(timeout: Duration) -> (Session, UnixStream) {
    session(0x0040_0229, true, timeout)
}

/// 偽 frontend: 要求を 1 回受ける（添付 fd は最大 1 本）。
pub(super) fn recv_request(b: &UnixStream) -> (DecodedBackendRequest, Vec<OwnedFd>) {
    let mut buf = [0u8; 64];
    let r = recv_with_fds(b, &mut buf, 1, T).expect("recv");
    let d = decode_backend_request(buf.get(..r.len).expect("len")).expect("decode");
    (d, r.fds)
}

fn code(e: &BackendReqError) -> &'static str {
    e.code.as_str()
}

#[test]
fn f5_2b_3_gpu6_map_success_sends_exactly_one_fd_and_logs() {
    let (mut s, b) = ready(T);
    let memfd = create_memfd(c"f5-2b-3", 8192).expect("memfd");
    let want = memfd.metadata().expect("meta");
    let h = thread::spawn(move || {
        let (d, fds) = recv_request(&b);
        let fd_meta = fds.first().map(|f| {
            let m = File::from(f.try_clone().expect("dup"))
                .metadata()
                .expect("meta");
            (m.dev(), m.ino())
        });
        send_with_fds(&b, &encode_backend_reply(d.request, 0), &[], T).expect("reply");
        (d, fds.len(), fd_meta)
    });
    let mut lines = Vec::new();
    let ack = s
        .shmem_map(&map_req(), memfd.as_fd(), &mut |l| {
            lines.push(l.to_string())
        })
        .expect("ack");
    assert_eq!(ack.status, 0);
    assert_eq!(ack.request, BackendRequestCode::ShmemMap);
    let (d, nfds, fd_meta) = h.join().expect("join");
    assert_eq!(
        (
            d.request,
            d.shmid,
            d.fd_offset,
            d.shm_offset,
            d.len,
            d.flags
        ),
        (BackendRequestCode::ShmemMap, 1, 0, 4096, 8192, 1)
    );
    assert_eq!(nfds, 1);
    assert_eq!(fd_meta, Some((want.dev(), want.ino())));
    assert_eq!(
        lines,
        vec![
            "venus_jig event=backend_req cmd=SHMEM_MAP shmid=1 shm_offset=4096 len=8192 result=ok status=0"
        ]
    );
    assert_eq!(s.state.host_visible(), HostVisible::Ready);
}

#[test]
fn f5_2b_3_gpu6_remote_failure_keeps_status_and_channel() {
    let (mut s, b) = ready(T);
    let memfd = create_memfd(c"f5-2b-3", 8192).expect("memfd");
    let h = thread::spawn(move || {
        let (d, _fds) = recv_request(&b);
        let v = (-22i64) as u64;
        send_with_fds(&b, &encode_backend_reply(d.request, v), &[], T).expect("reply");
    });
    let mut lines = Vec::new();
    let e = s
        .shmem_map(&map_req(), memfd.as_fd(), &mut |l| {
            lines.push(l.to_string())
        })
        .expect_err("remote failure");
    h.join().expect("join");
    assert_eq!(code(&e), "REMOTE_FAILURE");
    assert_eq!(e.status, Some(18446744073709551594));
    assert_eq!(
        lines,
        vec![
            "venus_jig event=backend_req cmd=SHMEM_MAP shmid=1 shm_offset=4096 len=8192 result=err status=18446744073709551594"
        ]
    );
    // 形式の正しい非 0 は同期が保たれているので channel は使える。
    assert_eq!(s.state.host_visible(), HostVisible::Ready);
}

fn hdr(id: u32, flags: u32, size: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&id.to_le_bytes());
    h.extend_from_slice(&flags.to_le_bytes());
    h.extend_from_slice(&size.to_le_bytes());
    h
}

#[test]
fn f5_2b_3_gpu6_malformed_replies_break_the_channel() {
    use BackendCodecErrorCode as C;
    let mut size16 = hdr(9, 0x5, 16);
    size16.extend_from_slice(&[0u8; 16]);
    let mut no_reply = hdr(9, 0x1, 8);
    no_reply.extend_from_slice(&[0u8; 8]);
    let cases: Vec<(&str, Vec<u8>, Option<C>)> = vec![
        (
            "other_id",
            encode_backend_reply(BackendRequestCode::ShmemUnmap, 0).to_vec(),
            Some(C::ReplyRequestMismatch),
        ),
        ("no_reply_flag", no_reply, Some(C::ReplyFlagMissing)),
        ("size16", size16, Some(C::ReplySizeMismatch)),
        ("with_fd", Vec::new(), None),
    ];
    for (name, bytes, want_cause) in cases {
        let (mut s, b) = ready(T);
        let memfd = create_memfd(c"f5-2b-3", 8192).expect("memfd");
        let attach = bytes.is_empty();
        let h = thread::spawn(move || {
            let (d, _fds) = recv_request(&b);
            if attach {
                let extra = create_memfd(c"f5-2b-3-x", 4096).expect("memfd");
                let r = encode_backend_reply(d.request, 0);
                send_with_fds(&b, &r, &[extra.as_fd()], T).expect("reply");
            } else {
                send_with_fds(&b, &bytes, &[], T).expect("reply");
            }
            // 治具側が channel を閉じる（EOF になる）。
            let mut buf = [0u8; 8];
            recv_with_fds(&b, &mut buf, 0, T).expect_err("closed").code
        });
        let mut lines = Vec::new();
        let e = s
            .shmem_map(&map_req(), memfd.as_fd(), &mut |l| {
                lines.push(l.to_string())
            })
            .expect_err(name);
        match want_cause {
            Some(c) => {
                assert_eq!(code(&e), "MALFORMED_REPLY", "{name}");
                assert_eq!(e.cause, Some(BackendReqCause::Codec(c)), "{name}");
            }
            None => {
                assert_eq!(code(&e), "TRANSPORT", "{name}");
                assert_eq!(
                    e.cause,
                    Some(BackendReqCause::Transport(
                        TransportErrorCode::TooManyFds,
                        None
                    ))
                );
            }
        }
        // 未読の応答が残る場合、閉じた側には EOF ではなく ECONNRESET（OS_ERROR）が見える。どちらも「もう書かれない」。
        let seen = h.join().expect("join");
        assert!(
            matches!(
                seen,
                TransportErrorCode::PeerClosed | TransportErrorCode::OsError
            ),
            "{name}: {seen:?}"
        );
        assert_eq!(lines.len(), 1, "{name}");
        assert_eq!(
            s.state.host_visible().as_str(),
            "backend_channel_broken",
            "{name}"
        );
        // 次の呼び出しは送らずに拒否される。
        let mut more = Vec::new();
        let e2 = s
            .shmem_unmap(&mapping(), &mut |l| more.push(l.to_string()))
            .expect_err("broken");
        assert_eq!(code(&e2), "HOST_VISIBLE_UNAVAILABLE");
        assert_eq!(
            e2.cause,
            Some(BackendReqCause::Unavailable(
                HostVisibleUnavailable::BackendChannelBroken
            ))
        );
        assert!(more.is_empty());
    }
}

#[test]
fn f5_2b_3_gpu6_timeout_breaks_the_channel_within_the_deadline() {
    let (mut s, b) = ready(Duration::from_millis(100));
    let memfd = create_memfd(c"f5-2b-3", 8192).expect("memfd");
    let h = thread::spawn(move || {
        let _ = recv_request(&b);
        // 応答せず、治具側が閉じるまで待つ。
        let mut buf = [0u8; 8];
        let _ = recv_with_fds(&b, &mut buf, 0, T);
    });
    let started = Instant::now();
    let mut lines = Vec::new();
    let e = s
        .shmem_map(&map_req(), memfd.as_fd(), &mut |l| {
            lines.push(l.to_string())
        })
        .expect_err("timeout");
    assert!(started.elapsed() < Duration::from_secs(3));
    h.join().expect("join");
    assert_eq!(code(&e), "TIMEOUT");
    assert_eq!(
        lines,
        vec![
            "venus_jig event=backend_req cmd=SHMEM_MAP shmid=1 shm_offset=4096 len=8192 result=err code=TIMEOUT"
        ]
    );
    assert_eq!(s.state.host_visible().as_str(), "backend_channel_broken");
}

#[test]
fn f5_2b_3_gpu6_disconnect_is_peer_closed() {
    for partial in [false, true] {
        let (mut s, b) = ready(T);
        let memfd = create_memfd(c"f5-2b-3", 8192).expect("memfd");
        let h = thread::spawn(move || {
            let _ = recv_request(&b);
            if partial {
                send_with_fds(&b, &[9, 0, 0, 0, 5, 0, 0, 0, 8, 0], &[], T).expect("part");
            }
            drop(b);
        });
        let e = s
            .shmem_map(&map_req(), memfd.as_fd(), &mut |_| {})
            .expect_err("closed");
        h.join().expect("join");
        assert_eq!(code(&e), "PEER_CLOSED", "partial={partial}");
        assert_eq!(s.state.host_visible().as_str(), "backend_channel_broken");
    }
}

#[test]
fn f5_2b_3_gpu6_unmap_has_no_fd_and_same_range() {
    let (mut s, b) = ready(T);
    let h = thread::spawn(move || {
        let (d, fds) = recv_request(&b);
        send_with_fds(&b, &encode_backend_reply(d.request, 0), &[], T).expect("reply");
        (d, fds.len())
    });
    let mut lines = Vec::new();
    let ack = s
        .shmem_unmap(&mapping(), &mut |l| lines.push(l.to_string()))
        .expect("ack");
    assert_eq!(ack.request, BackendRequestCode::ShmemUnmap);
    let (d, nfds) = h.join().expect("join");
    assert_eq!(nfds, 0);
    assert_eq!(
        d,
        DecodedBackendRequest {
            request: BackendRequestCode::ShmemUnmap,
            shmid: 1,
            fd_offset: 0,
            shm_offset: 4096,
            len: 8192,
            flags: 0,
        }
    );
    assert_eq!(
        lines,
        vec![
            "venus_jig event=backend_req cmd=SHMEM_UNMAP shmid=1 shm_offset=4096 len=8192 result=ok status=0"
        ]
    );
    assert_eq!(BackendRequest::ShmemUnmap(mapping()).code(), d.request);
}

#[test]
fn f5_2b_3_gpu6_gates_do_not_send_or_log() {
    // (protocol, connect, 期待 code, 期待 cause)
    let cases: Vec<(u64, bool, &str, Option<HostVisibleUnavailable>)> = vec![
        (0x0040_0221, true, "REPLY_ACK_NOT_NEGOTIATED", None),
        (
            0x0040_0229,
            false,
            "HOST_VISIBLE_UNAVAILABLE",
            Some(HostVisibleUnavailable::BackendChannelMissing),
        ),
    ];
    for (protocol, connect, want, why) in cases {
        let (mut s, b) = session(protocol, connect, T);
        let memfd = create_memfd(c"f5-2b-3", 8192).expect("memfd");
        let mut lines = Vec::new();
        let e = s
            .shmem_map(&map_req(), memfd.as_fd(), &mut |l| {
                lines.push(l.to_string())
            })
            .expect_err(want);
        assert_eq!(code(&e), want, "{protocol:#x}");
        assert_eq!(e.cause, why.map(BackendReqCause::Unavailable));
        assert!(lines.is_empty());
        // 偽 frontend 側には 1 バイトも届いていない。
        let mut buf = [0u8; 8];
        let t = recv_with_fds(&b, &mut buf, 0, Duration::from_millis(100))
            .expect_err("nothing written");
        let want_t = if connect {
            TransportErrorCode::Timeout
        } else {
            // 治具側の端点（`a`）は State に渡さず drop 済みなので閉じている。
            TransportErrorCode::PeerClosed
        };
        assert_eq!(t.code, want_t, "{protocol:#x}");
    }
    assert_eq!(
        BackendReqErrorCode::RemoteFailure.as_str(),
        "REMOTE_FAILURE"
    );
}

#[test]
fn f5_2b_3_gpu6_set_backend_req_fd_is_rejected_after_break() {
    let (mut s, b) = ready(Duration::from_millis(50));
    drop(b);
    let memfd = create_memfd(c"f5-2b-3", 8192).expect("memfd");
    s.shmem_map(&map_req(), memfd.as_fd(), &mut |_| {})
        .expect_err("peer gone");
    assert_eq!(s.state.host_visible().as_str(), "backend_channel_broken");
    let (c, _d) = UnixStream::pair().expect("pair");
    let r = s
        .state
        .handle(Request::SetBackendReqFd, vec![OwnedFd::from(c)]);
    assert_eq!(r.expect_err("rejected").code, SessionErrorCode::OutOfOrder);
}
