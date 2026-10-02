//! `NetlinkRouteSocket` の結合試験（NET-11・TASK-136.2.1・#843）。
//!
//! 非特権で成立する RTM_GETLINK dump の往復で、送ったバイト列がカーネルへそのまま届くことを
//! 機械照合する（seq の一致・lo の RTM_NEWLINK・NLMSG_DONE）。root 不要のため既定の結合試験集合で
//! 実行する（ci.md「実機前提テスト」: 既定集合で動くテストは分離しない）。Linux のみ。

#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use fandhe_container_net::error::NetErrorCode;
use fandhe_container_net::netlink_route::{
    NLM_F_MATCH, NLM_F_REQUEST, NLM_F_ROOT, NLMSG_DONE, NLMSG_ERROR, NetlinkRouteSocket,
    NlMsgBuilder, NlMsgIter,
};

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const SEQ: u32 = 0x1357_9bdf;

/// RTM_GETLINK dump を送り、NLMSG_DONE まで (type, seq, payload) を集める。
fn dump_links(sock: &NetlinkRouteSocket) -> Vec<(u16, u32, Vec<u8>)> {
    let mut b = NlMsgBuilder::new(
        RTM_GETLINK,
        NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH,
        SEQ,
        0,
    );
    // struct ifinfomsg（16 バイト・全ゼロ = 全 link）。
    b.put_fixed(&[0u8; 16]).expect("ifinfomsg");
    let req = b.finish().expect("finish");
    sock.send(&req).expect("send");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut out = Vec::new();
    for _ in 0..64 {
        // 合計期限の残り時間を 1 回の recv 待機の上限にする（REPAIR-5）。
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "dump exceeded the total deadline");
        let data = sock
            .recv(remaining.min(Duration::from_secs(5)))
            .expect("recv");
        for m in NlMsgIter::new(&data) {
            let m = m.expect("valid message");
            let h = m.header();
            out.push((h.msg_type(), h.seq(), m.payload().to_vec()));
            if h.msg_type() == NLMSG_DONE {
                return out;
            }
        }
    }
    panic!("NLMSG_DONE not seen within the iteration limit");
}

/// NET-11: 送ったバイト列が届き、seq が往復し、lo の RTM_NEWLINK と NLMSG_DONE が返る。
#[test]
fn getlink_dump_roundtrip() {
    let sock = NetlinkRouteSocket::open().expect("open");
    let msgs = dump_links(&sock);
    assert!(msgs.iter().all(|(t, _, _)| *t != NLMSG_ERROR));
    assert!(msgs.iter().all(|(_, seq, _)| *seq == SEQ));
    assert_eq!(msgs.last().map(|m| m.0), Some(NLMSG_DONE));
    // ifinfomsg: family(1) pad(1) type(2) index(i32 LE @4)。lo は ifindex 1。
    let has_lo = msgs.iter().any(|(t, _, p)| {
        *t == RTM_NEWLINK
            && p.get(4..8)
                .is_some_and(|b| b == 1i32.to_le_bytes().as_slice())
    });
    assert!(has_lo, "RTM_NEWLINK for ifindex 1 (lo) not found");
}

/// NET-11・REPAIR-5: 何も送らなければ recv は Timeout を返しハングしない。
#[test]
fn recv_times_out_without_request() {
    let sock = NetlinkRouteSocket::open().expect("open");
    let t = Instant::now();
    let e = sock.recv(Duration::from_millis(200)).expect_err("timeout");
    assert_eq!(e.code(), NetErrorCode::Timeout);
    assert!(t.elapsed() < Duration::from_secs(5));
}

/// NET-11: nl_pid=0 採番のため、複数ソケットを同時に bind できる。
#[test]
fn multiple_sockets_bind_independently() {
    let a = NetlinkRouteSocket::open().expect("open a");
    let b = NetlinkRouteSocket::open().expect("open b");
    assert_eq!(dump_links(&a).last().map(|m| m.0), Some(NLMSG_DONE));
    assert_eq!(dump_links(&b).last().map(|m| m.0), Some(NLMSG_DONE));
}
