//! `LinkCreate` 公開 API の結合試験（NET-11・TASK-136.3.1・#845・MS-8）。
//!
//! crate 外部から公開 API だけで bridge / veth の `RTM_NEWLINK` メッセージを組み立て、
//! nlmsghdr・ifinfomsg・属性の入れ子・名前の境界値を機械照合する。ソケットを使わない
//! OS 非依存のテストのため 3 OS の既定結合試験集合で実行する（ci.md）。

use fandhe_container_net::error::NetErrorCode;
use fandhe_container_net::netlink_route::{
    AttrIter, IFINFOMSG_LEN, IFLA_IFNAME, IFLA_INFO_DATA, IFLA_INFO_KIND, IFLA_LINK, IFLA_LINKINFO,
    IfName, LinkCreate, NLM_F_ACK, NLM_F_CREATE, NLM_F_ECHO, NLM_F_EXCL, NLM_F_REQUEST,
    NlMsgBuilder, NlMsgIter, RTM_NEWLINK, VETH_INFO_PEER, decode_created_link, decode_created_veth,
};

const SEQ: u32 = 0x2468_ace0;

fn build(req: &LinkCreate) -> Vec<u8> {
    let mut b = NlMsgBuilder::new(req.msg_type(), req.flags(), SEQ, 0);
    req.encode(&mut b).expect("encode");
    b.finish().expect("finish")
}

fn name(s: &str) -> IfName {
    IfName::new(s).expect("valid name")
}

/// NET-11: bridge のヘッダ（type・flags・seq）と属性構造を公開 API だけで確認する。
#[test]
fn net11_bridge_message_header_and_attrs() {
    let data = build(&LinkCreate::bridge(name("br0")));
    let mut it = NlMsgIter::new(&data);
    let msg = it.next().expect("one message").expect("decode");
    assert!(it.next().is_none());
    let h = msg.header();
    assert_eq!(h.msg_type(), RTM_NEWLINK);
    assert_eq!(h.flags(), NLM_F_CREATE | NLM_F_EXCL);
    assert_eq!(h.flags() & (NLM_F_REQUEST | NLM_F_ACK), 0);
    assert_eq!(h.seq(), SEQ);
    assert_eq!(h.len() as usize, data.len());
    assert_eq!(msg.payload().get(..IFINFOMSG_LEN), Some(&[0u8; 16][..]));

    let attrs: Vec<_> = msg
        .attrs(IFINFOMSG_LEN)
        .expect("attrs")
        .map(|a| a.expect("attr"))
        .collect();
    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs[0].attr_type(), IFLA_IFNAME);
    assert_eq!(attrs[0].payload(), b"br0\0");
    assert_eq!(attrs[1].attr_type(), IFLA_LINKINFO);
    assert!(attrs[1].is_nested());
    let kids: Vec<_> = attrs[1].nested().map(|a| a.expect("kid")).collect();
    assert_eq!(kids.len(), 1);
    assert_eq!(kids[0].attr_type(), IFLA_INFO_KIND);
    assert_eq!(kids[0].payload(), b"bridge\0");
}

/// NET-11: veth は INFO_DATA > VETH_INFO_PEER に 2 つ目の ifinfomsg と peer 名を持つ。
#[test]
fn net11_veth_message_nests_peer() {
    let data = build(&LinkCreate::veth(name("veth0"), name("veth1")).expect("veth"));
    let mut it = NlMsgIter::new(&data);
    let msg = it.next().expect("one message").expect("decode");
    assert_eq!(msg.header().msg_type(), RTM_NEWLINK);
    assert_eq!(msg.header().flags(), NLM_F_CREATE | NLM_F_EXCL);

    let attrs: Vec<_> = msg
        .attrs(IFINFOMSG_LEN)
        .expect("attrs")
        .map(|a| a.expect("attr"))
        .collect();
    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs[0].attr_type(), IFLA_IFNAME);
    assert_eq!(attrs[0].payload(), b"veth0\0");

    let info: Vec<_> = attrs[1].nested().map(|a| a.expect("info")).collect();
    assert_eq!(info.len(), 2);
    assert_eq!(info[0].attr_type(), IFLA_INFO_KIND);
    assert_eq!(info[0].payload(), b"veth\0");
    assert_eq!(info[1].attr_type(), IFLA_INFO_DATA);
    let peers: Vec<_> = info[1].nested().map(|a| a.expect("peer")).collect();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].attr_type(), VETH_INFO_PEER);
    let body = peers[0].payload();
    assert_eq!(body.get(..IFINFOMSG_LEN), Some(&[0u8; 16][..]));
    let rest = body.get(IFINFOMSG_LEN..).expect("peer attrs");
    let pa: Vec<_> = AttrIter::new(rest).map(|a| a.expect("pattr")).collect();
    assert_eq!(pa.len(), 1);
    assert_eq!(pa[0].attr_type(), IFLA_IFNAME);
    assert_eq!(pa[0].payload(), b"veth1\0");
}

/// NET-11・REPAIR-2: 名前長の境界（15 バイト受理・16 バイト拒否）が組み立てまで通る。
#[test]
fn net11_name_length_boundary_roundtrip() {
    let max = "0123456789abcde";
    assert_eq!(max.len(), 15);
    let data = build(&LinkCreate::bridge(name(max)));
    let mut it = NlMsgIter::new(&data);
    let msg = it.next().expect("msg").expect("decode");
    let first = msg
        .attrs(IFINFOMSG_LEN)
        .expect("attrs")
        .next()
        .expect("ifname")
        .expect("attr");
    assert_eq!(first.payload().len(), 16);
    assert_eq!(first.payload().last(), Some(&0));

    for bad in [
        "",
        "0123456789abcdef",
        ".",
        "..",
        "a/b",
        "a:b",
        "a b",
        "a\0b",
    ] {
        let e = IfName::new(bad).expect_err(bad);
        assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{bad:?}");
    }
}

/// NET-11: 同名 veth は組み立て前に拒否され、異名なら受理される。
#[test]
fn net11_veth_same_name_rejected() {
    let e = LinkCreate::veth(name("v0"), name("v0")).expect_err("same name");
    assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    assert!(LinkCreate::veth(name("v0"), name("v1")).is_ok());
}

/// NET-1・Issue #1972: echo 付き bridge 作成要求は flags に `NLM_F_ECHO` だけを足し、属性構造は変わらない。
#[test]
fn net1_bridge_echo_message_flags_and_attrs() {
    let data = build(&LinkCreate::bridge(name("br0")).with_echo());
    let msg = NlMsgIter::new(&data).next().expect("msg").expect("decode");
    let h = msg.header();
    assert_eq!(h.msg_type(), RTM_NEWLINK);
    assert_eq!(h.flags(), NLM_F_CREATE | NLM_F_EXCL | NLM_F_ECHO);
    assert_eq!(h.flags(), 0x0608);
    assert_eq!(h.flags() & (NLM_F_REQUEST | NLM_F_ACK), 0);
    let attrs: Vec<_> = msg
        .attrs(IFINFOMSG_LEN)
        .expect("attrs")
        .map(|a| a.expect("attr"))
        .collect();
    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs[0].payload(), b"br0\0");
}

/// NET-1・Issue #1972: 合成した作成通知から ifindex を取り出し、通知なしは `None`、名前の不一致は `DataLoss`。
#[test]
fn net1_decode_created_link_from_synthetic_notification() {
    let mut b = NlMsgBuilder::new(RTM_NEWLINK, 0, 1, 0);
    let mut ifinfo = [0u8; IFINFOMSG_LEN];
    ifinfo[4..8].copy_from_slice(&42i32.to_ne_bytes());
    b.put_fixed(&ifinfo).expect("fixed");
    b.put_attr(IFLA_IFNAME, b"fcbr1\0").expect("name");
    let data = b.finish().expect("finish");
    let payload = NlMsgIter::new(&data)
        .next()
        .expect("msg")
        .expect("decode")
        .payload()
        .to_vec();
    let got = decode_created_link([(RTM_NEWLINK, payload.as_slice())], &name("fcbr1"))
        .expect("decode")
        .expect("some");
    assert_eq!(got.get(), 42);
    let none: [(u16, &[u8]); 0] = [];
    assert_eq!(decode_created_link(none, &name("fcbr1")).expect("ok"), None);
    let e = decode_created_link([(RTM_NEWLINK, payload.as_slice())], &name("fcbr2"))
        .expect_err("mismatch");
    assert_eq!(e.code(), NetErrorCode::DataLoss);
}

/// NET-1・Issue #3205: veth + echo の要求は flags 0x0608 で、属性は echo なしと同じ。
#[test]
fn net1_veth_echo_message_flags_and_attrs() {
    let plain = build(&LinkCreate::veth(name("fcvh0"), name("fcvp0")).expect("veth"));
    let echo = build(
        &LinkCreate::veth(name("fcvh0"), name("fcvp0"))
            .expect("veth")
            .with_echo(),
    );
    let msg = NlMsgIter::new(&echo).next().expect("msg").expect("decode");
    assert_eq!(msg.header().msg_type(), RTM_NEWLINK);
    assert_eq!(msg.header().flags(), 0x0608);
    let plain_msg = NlMsgIter::new(&plain).next().expect("msg").expect("decode");
    assert_eq!(plain_msg.header().flags(), NLM_F_CREATE | NLM_F_EXCL);
    assert_eq!(msg.payload(), plain_msg.payload());
}

/// NET-1・Issue #3205: 合成した veth 作成通知から host / peer の ifindex を取り出す。
/// `IFLA_LINK` が無い通知と通知なしの扱いも確認する。
#[test]
fn net1_decode_created_veth_from_synthetic_notification() {
    let make = |with_link: bool| {
        let mut b = NlMsgBuilder::new(RTM_NEWLINK, 0, 1, 0);
        let mut ifinfo = [0u8; IFINFOMSG_LEN];
        ifinfo[4..8].copy_from_slice(&42i32.to_ne_bytes());
        b.put_fixed(&ifinfo).expect("fixed");
        b.put_attr(IFLA_IFNAME, b"fcvh1\0").expect("name");
        if with_link {
            b.put_attr(IFLA_LINK, &43u32.to_ne_bytes()).expect("link");
        }
        let data = b.finish().expect("finish");
        NlMsgIter::new(&data)
            .next()
            .expect("msg")
            .expect("decode")
            .payload()
            .to_vec()
    };
    let payload = make(true);
    let got = decode_created_veth([(RTM_NEWLINK, payload.as_slice())], &name("fcvh1"))
        .expect("decode")
        .expect("some");
    assert_eq!((got.host().get(), got.peer().get()), (42, 43));
    let none: [(u16, &[u8]); 0] = [];
    assert_eq!(decode_created_veth(none, &name("fcvh1")).expect("ok"), None);
    let no_link = make(false);
    let e = decode_created_veth([(RTM_NEWLINK, no_link.as_slice())], &name("fcvh1"))
        .expect_err("no link");
    assert_eq!(e.code(), NetErrorCode::DataLoss);
}
