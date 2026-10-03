//! address / route 追加（`RTM_NEWADDR` / `RTM_NEWROUTE`）の実機前提結合試験（NET-11・TASK-136.4・#301）。
//!
//! `CAP_NET_ADMIN` が必要なため既定のテスト集合から `#[ignore]` で分離する（ci.md「実機前提テスト」）。
//! host の network namespace を変更しないよう、自プロセスの netns が親プロセスの netns と
//! 異なる隔離 netns（例: `unshare -rn`）でなければ panic で拒否する（fail-closed）。実行方法は AGENTS.md「実機前提テスト」節を参照。
//! Linux のみ。
//!
//! root なしで `unshare -rn` だけで動かせる lo 上の版（IPv6 も検証）。root を要する一連（作成〜address / route）は
//! `link_netns_privileged`（TASK-136.5・#302）が担当する。

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use fandhe_container_net::error::NetErrorCode;
use fandhe_container_net::netlink_route::{
    AddrScope, AddressSpec, AttrIter, IFA_ADDRESS, IFA_LOCAL, IfAddrMsg, IfIndex, IpPrefix,
    LinkIndex, LinkRef, LinkSet, NLM_F_MATCH, NLM_F_ROOT, NetlinkReply, NetlinkRouteSocket,
    RTA_DST, RTA_OIF, RTM_GETADDR, RTM_GETLINK, RTM_GETROUTE, RTM_NEWLINK, RouteNextHop, RouteSpec,
    RtMsg,
};

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

/// 自プロセスと親プロセスの network namespace が別物であることを検証する（fail-closed）。
///
/// `unshare -rn <exe>` は unshare 自身が exec で置き換わるため、親は host netns のシェル等になる。
/// 同一 kuid のプロセスの `/proc/<pid>/ns/net` は読めるため、読めない場合も拒否する。
fn assert_isolated_from_parent_netns() {
    let own = std::fs::read_link("/proc/self/ns/net").expect("read own netns link");
    let parent_path = format!("/proc/{}/ns/net", std::os::unix::process::parent_id());
    let parent = std::fs::read_link(&parent_path)
        .unwrap_or_else(|e| panic!("refusing to run: cannot read parent netns {parent_path}: {e}"));
    assert_ne!(
        own, parent,
        "refusing to run: same network namespace as the parent process; run under `unshare -rn` so the host network namespace is not modified"
    );
}

/// NET-11・TASK-136.4: lo に address と route を追加し、dump で内容を確認する。
#[test]
#[ignore = "requires CAP_NET_ADMIN inside an isolated network namespace (e.g. unshare -rn); NET-11"]
fn net11_add_address_and_route_in_isolated_netns() {
    let sock = NetlinkRouteSocket::open().expect("open");

    // 安全ガード 1: 実行元（親プロセス）と netns が異なることを確認する。判別できなければ中止する。
    assert_isolated_from_parent_netns();

    // 安全ガード 2: link が lo（ifindex 1）だけでなければ想定外の構成のため中止する。
    let links = dump(&sock, RTM_GETLINK, &[0u8; 16]);
    let idx: Vec<u32> = links
        .messages()
        .iter()
        .filter(|m| m.msg_type() == RTM_NEWLINK)
        .map(|m| {
            // 不正な payload は黙って除外せず即失敗させる（fail-closed。ガードの迂回防止）
            let raw: [u8; 4] = m
                .payload()
                .get(4..8)
                .and_then(|b| b.try_into().ok())
                .expect("malformed RTM_NEWLINK payload: refusing to run");
            u32::from_ne_bytes(raw)
        })
        .collect();
    assert_eq!(
        idx,
        vec![1],
        "refusing to run: not an isolated netns with only lo; the host network namespace must not be modified"
    );

    // lo を up にする（down だと dev 経由の route が ENETDOWN で拒否される）。
    sock.set_link(
        &LinkSet::up(LinkRef::Index(LinkIndex::new(1).expect("lo index"))),
        T,
    )
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
    .with_nodad()
    .expect("IPv6 nodad");
    sock.add_address(&v6, T)
        .expect("add IPv6 address (is net.ipv6.conf.lo.disable_ipv6 set to 1?)");
    let v6_octets = "fd00::1".parse::<Ipv6Addr>().expect("v6").octets();
    let addrs = dump(&sock, RTM_GETADDR, &[0u8; 8]);
    let v6_found = addrs.messages().iter().any(|m| {
        let Ok(h) = IfAddrMsg::decode(m.payload()) else {
            return false;
        };
        h.index() == 1
            && h.prefix_len() == 64
            && h.family() == 10
            && attr_payload(m.payload(), 8, IFA_ADDRESS).as_deref() == Some(&v6_octets[..])
    });
    assert!(v6_found, "added IPv6 address not found in RTM_GETADDR dump");

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

    let net_found = routes.messages().iter().any(|m| {
        RtMsg::decode(m.payload()).is_ok_and(|h| {
            h.family() == 2 && h.table() == 254 && h.dst_len() == 24 && h.protocol() == 4
        }) && attr_payload(m.payload(), 12, RTA_DST).as_deref() == Some(&[10, 201, 0, 0][..])
            && attr_payload(m.payload(), 12, RTA_OIF).as_deref() == Some(&1u32.to_ne_bytes()[..])
    });
    assert!(
        net_found,
        "10.201.0.0/24 route (oif=lo) not found in RTM_GETROUTE dump"
    );
}
