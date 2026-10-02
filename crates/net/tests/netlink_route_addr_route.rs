//! address / route 追加（`RTM_NEWADDR` / `RTM_NEWROUTE`）の実機前提結合試験（NET-11・TASK-136.4・#301）。
//!
//! `CAP_NET_ADMIN` が必要なため既定のテスト集合から `#[ignore]` で分離する（ci.md「実機前提テスト」）。
//! host の network namespace を変更しないよう、隔離 netns（例: `unshare -rn`）で lo のみの
//! 状態でなければ panic で拒否する（fail-closed）。実行方法は AGENTS.md「実機前提テスト」節を参照。
//! Linux のみ。

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use fandhe_container_net::error::NetErrorCode;
use fandhe_container_net::netlink_route::{
    AddrScope, AddressSpec, AttrIter, IFA_LOCAL, IfAddrMsg, IfIndex, IpPrefix, NLM_F_MATCH,
    NLM_F_ROOT, NetlinkReply, NetlinkRouteSocket, NlMsgBuilder, RTA_OIF, RTM_GETADDR, RTM_GETROUTE,
    RouteNextHop, RouteSpec, RtMsg,
};

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const IFF_UP: u32 = 1;
const T: Duration = Duration::from_secs(5);

fn dump(sock: &NetlinkRouteSocket, msg_type: u16, fixed: &[u8]) -> NetlinkReply {
    sock.request(msg_type, NLM_F_ROOT | NLM_F_MATCH, T, |b| {
        b.put_fixed(fixed)
    })
    .expect("dump")
}

/// 固定ヘッダ `fixed_len` の後ろから `attr_type` の属性ペイロードを探す。
fn attr_payload(payload: &[u8], fixed_len: usize, attr_type: u16) -> Option<Vec<u8>> {
    let rest = payload.get(fixed_len..)?;
    AttrIter::new(rest)
        .filter_map(Result::ok)
        .find(|a| a.attr_type() == attr_type)
        .map(|a| a.payload().to_vec())
}

/// NET-11・TASK-136.4: lo に address と route を追加し、dump で内容を確認する。
#[test]
#[ignore = "requires CAP_NET_ADMIN inside an isolated network namespace (e.g. unshare -rn); NET-11"]
fn add_address_and_route_in_isolated_netns() {
    let sock = NetlinkRouteSocket::open().expect("open");

    // 安全ガード: link が lo（ifindex 1）だけでなければ host netns の可能性があるため中止する。
    let links = dump(&sock, RTM_GETLINK, &[0u8; 16]);
    let idx: Vec<u32> = links
        .messages()
        .iter()
        .filter(|m| m.msg_type() == RTM_NEWLINK)
        .filter_map(|m| {
            m.payload()
                .get(4..8)?
                .try_into()
                .ok()
                .map(u32::from_ne_bytes)
        })
        .collect();
    assert_eq!(
        idx,
        vec![1],
        "refusing to run: not an isolated netns with only lo; the host network namespace must not be modified"
    );

    // lo を up にする（down だと dev 経由の route が ENETDOWN で拒否される）。
    // #846 の API が main に入ったらそちらへ置き換える。
    sock.request(RTM_NEWLINK, 0, T, |b: &mut NlMsgBuilder| {
        let mut ifi = [0u8; 16];
        ifi[4..8].copy_from_slice(&1i32.to_ne_bytes());
        ifi[8..12].copy_from_slice(&IFF_UP.to_ne_bytes());
        ifi[12..16].copy_from_slice(&IFF_UP.to_ne_bytes());
        b.put_fixed(&ifi)
    })
    .expect("lo up");

    let lo = IfIndex::new(1).expect("ifindex");
    let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));

    // address（IPv4）。
    let addr = AddressSpec::new(
        lo,
        IpPrefix::new(v4(10, 200, 0, 1), 24).expect("prefix"),
        AddrScope::Universe,
    );
    sock.add_address(&addr, T).expect("add address");
    let e = sock.add_address(&addr, T).expect_err("duplicate");
    assert_eq!(e.code(), NetErrorCode::AlreadyExists);
    let addrs = dump(&sock, RTM_GETADDR, &[0u8; 8]);
    let found = addrs.messages().iter().any(|m| {
        let Ok(h) = IfAddrMsg::decode(m.payload()) else {
            return false;
        };
        h.index() == 1
            && h.prefix_len() == 24
            && h.family() == 2
            && attr_payload(m.payload(), 8, IFA_LOCAL).as_deref() == Some(&[10, 200, 0, 1][..])
    });
    assert!(found, "added IPv4 address not found in RTM_GETADDR dump");

    // address（IPv6。lo で disable_ipv6=1 だと失敗する）。
    let v6 = AddressSpec::new(
        lo,
        IpPrefix::new(IpAddr::V6("fd00::1".parse::<Ipv6Addr>().expect("v6")), 64).expect("prefix"),
        AddrScope::Universe,
    )
    .with_nodad();
    sock.add_address(&v6, T)
        .expect("add IPv6 address (is net.ipv6.conf.lo.disable_ipv6 set to 1?)");

    // route（default と通常）。
    let default = RouteSpec::new(IpPrefix::default_v4(), RouteNextHop::Device { oif: lo })
        .expect("route spec");
    sock.add_route(&default, T).expect("add default route");
    let net = RouteSpec::new(
        IpPrefix::new(v4(10, 201, 0, 0), 24).expect("prefix"),
        RouteNextHop::Device { oif: lo },
    )
    .expect("route spec");
    sock.add_route(&net, T).expect("add route");

    let routes = dump(&sock, RTM_GETROUTE, &[0u8; 12]);
    let default_found = routes.messages().iter().any(|m| {
        RtMsg::decode(m.payload()).is_ok_and(|h| {
            h.family() == 2 && h.table() == 254 && h.dst_len() == 0 && h.protocol() == 4
        }) && attr_payload(m.payload(), 12, RTA_OIF).as_deref() == Some(&1u32.to_ne_bytes()[..])
    });
    assert!(
        default_found,
        "default route not found in RTM_GETROUTE dump"
    );
}
