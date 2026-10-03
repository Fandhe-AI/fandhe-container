//! `LinkSet` 公開 API の結合試験（NET-11・TASK-136.3.2・#846・MS-8）。
//!
//! crate 外部から公開 API だけで `RTM_SETLINK`（netns 移動・up）のメッセージを組み立て、
//! nlmsghdr・ifinfomsg・属性を機械照合する。ソケットを使わない OS 非依存のテストのため
//! 3 OS の既定結合試験集合で実行する（ci.md）。

use fandhe_container_net::error::NetErrorCode;
use fandhe_container_net::netlink_route::{
    IFF_UP, IFINFOMSG_LEN, IFLA_IFNAME, IFLA_NET_NS_PID, IfName, LinkIndex, LinkRef, LinkSet,
    NLM_F_ACK, NLM_F_REQUEST, NetnsPid, NetnsTarget, NlMsgBuilder, NlMsgIter, RTM_SETLINK,
};

const SEQ: u32 = 0x1357_9bdf;

fn build(req: &LinkSet<'_>) -> Vec<u8> {
    let mut b = NlMsgBuilder::new(req.msg_type(), req.flags(), SEQ, 0);
    req.encode(&mut b).expect("encode");
    b.finish().expect("finish")
}

fn name(s: &str) -> LinkRef {
    LinkRef::Name(IfName::new(s).expect("valid name"))
}

/// NET-11: PID 指定の netns 移動のヘッダ・ifinfomsg・属性。
#[test]
fn net11_move_by_pid_message_structure() {
    let req = LinkSet::move_to_netns(
        name("veth0"),
        NetnsTarget::Pid(NetnsPid::new(31337).expect("pid")),
    );
    let data = build(&req);
    let mut it = NlMsgIter::new(&data);
    let msg = it.next().expect("one message").expect("decode");
    assert!(it.next().is_none());
    let h = msg.header();
    assert_eq!(h.msg_type(), RTM_SETLINK);
    assert_eq!(h.flags(), 0);
    assert_eq!(h.flags() & (NLM_F_REQUEST | NLM_F_ACK), 0);
    assert_eq!(h.seq(), SEQ);
    assert_eq!(msg.payload().get(..IFINFOMSG_LEN), Some(&[0u8; 16][..]));
    let attrs: Vec<_> = msg
        .attrs(IFINFOMSG_LEN)
        .expect("attrs")
        .map(|a| a.expect("attr"))
        .collect();
    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs[0].attr_type(), IFLA_IFNAME);
    assert_eq!(attrs[0].payload(), b"veth0\0");
    assert_eq!(attrs[1].attr_type(), IFLA_NET_NS_PID);
    assert_eq!(attrs[1].payload(), 31337u32.to_ne_bytes());
}

/// NET-11: FD 指定は実 fd 番号を IFLA_NET_NS_FD(28) に載せる。
#[cfg(unix)]
#[test]
fn net11_move_by_fd_carries_real_fd_number() {
    use fandhe_container_net::netlink_route::{IFLA_NET_NS_FD, NetnsFd};
    use std::os::fd::{AsFd as _, AsRawFd as _};

    let f = std::fs::File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).expect("open");
    let fd = NetnsFd::new(f.as_fd()).expect("fd");
    let req = LinkSet::move_to_netns(name("veth1"), NetnsTarget::Fd(fd));
    let data = build(&req);
    let mut it = NlMsgIter::new(&data);
    let msg = it.next().expect("one message").expect("decode");
    let attrs: Vec<_> = msg
        .attrs(IFINFOMSG_LEN)
        .expect("attrs")
        .map(|a| a.expect("attr"))
        .collect();
    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs[1].attr_type(), IFLA_NET_NS_FD);
    assert_eq!(attrs[1].attr_type(), 28);
    assert_eq!(attrs[1].payload(), (f.as_raw_fd() as u32).to_ne_bytes());
}

/// NET-11: up は index 指定で flags / change に IFF_UP のみを立てる。
#[test]
fn net11_up_by_index_sets_flag_and_change() {
    let req = LinkSet::up(LinkRef::Index(LinkIndex::new(9).expect("index")));
    let data = build(&req);
    let mut it = NlMsgIter::new(&data);
    let msg = it.next().expect("one message").expect("decode");
    let ifi = msg.payload().get(..IFINFOMSG_LEN).expect("ifinfomsg");
    assert_eq!(ifi.get(4..8), Some(&9i32.to_ne_bytes()[..]));
    assert_eq!(ifi.get(8..12), Some(&IFF_UP.to_ne_bytes()[..]));
    assert_eq!(ifi.get(12..16), Some(&1u32.to_ne_bytes()[..]));
    assert_eq!(msg.attrs(IFINFOMSG_LEN).expect("attrs").count(), 0);
}

/// NET-11・REPAIR-2: 範囲外の PID / ifindex は組み立て前に拒否する。
#[test]
fn net11_invalid_pid_and_index_rejected() {
    assert_eq!(
        NetnsPid::new(0).expect_err("zero").code(),
        NetErrorCode::InvalidArgument
    );
    assert_eq!(
        LinkIndex::new(0).expect_err("zero").code(),
        NetErrorCode::InvalidArgument
    );
}
