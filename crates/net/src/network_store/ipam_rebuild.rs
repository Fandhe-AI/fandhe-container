//! 記録からの静的 IPAM の組み直し（NET-1・NET-7・REPAIR-2・REPAIR-5・#3067）。
//!
//! 役割: IPAM は独立したカウンタを持たず、ネットワークのロックの下で操作のたびに `realized`・`members/*`・
//! `members-intent/*` から [`rebuild_ipam`] で組み直す（D11）。これにより「記録は更新されたがカウンタが古い」
//! という数え違いが原理的に起きない。OS 非依存の純関数で、呼び出し元は `NetworkLockGuard::rebuild_ipam`
//! （ガードが記録を読んで本関数へ渡す）と `network::recorded` の合成関数。
//!
//! # 規則（fail-closed）
//! - 確定記録は netns pin 置き場の記録つきで戻す（`delete_network` が pin を判定できるまま）
//! - 意図記録は使用中のアドレスとして数える（カーネル側に資源が残りうるため再割り当てしない）
//! - 同じ ID の確定記録と意図記録が endpoint もアドレスも同じなら 1 回だけ数える（確定記録を書いた後、
//!   意図記録を消す前に落ちた窓）。所有トークンの世代まで一致しない場合は別の操作として `DataLoss`
//! - 食い違い（アドレス・endpoint の衝突、サブネット外、トークン不整合、dns が gateway）は `DataLoss`。
//!   組み直せないときは払い出さない

use super::member::{MemberIntent, MemberRecord};
use super::realized::RealizedRecord;
use crate::error::{NetError, NetErrorCode};
use crate::network::{StaticIpam, host_token_is_for};

fn bad(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::DataLoss, msg)
}

/// 記録から IPAM を組み直す。
pub fn rebuild_ipam(
    realized: &RealizedRecord,
    members: &[MemberRecord],
    intents: &[MemberIntent],
) -> Result<StaticIpam, NetError> {
    let mut ipam = StaticIpam::new(realized.name(), realized.gateway())
        .map_err(|_| bad("realized record cannot form an address pool"))?;
    for m in members {
        if !host_token_is_for(realized.token(), m.endpoint(), m.token()) {
            return Err(bad("member token does not belong to the network"));
        }
        if m.dns().contains(&realized.gateway().addr()) {
            return Err(bad("member dns server is the network gateway"));
        }
        ipam.reserve_pinned(m.endpoint(), m.address(), m.netns_dir_record())
            .map_err(|_| bad("member records conflict or lie outside the subnet"))?;
    }
    for i in intents {
        if !host_token_is_for(realized.token(), i.endpoint(), i.token()) {
            return Err(bad("member intent token does not belong to the network"));
        }
        if let Some(m) = members.iter().find(|m| m.id() == i.id()) {
            if m.endpoint() == i.endpoint() && m.address() == i.address() && m.token() == i.token()
            {
                continue;
            }
            return Err(bad("member intent conflicts with the member record"));
        }
        ipam.reserve(i.endpoint(), i.address())
            .map_err(|_| bad("member intents conflict or lie outside the subnet"))?;
    }
    Ok(ipam)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etc_hosts::NameResolution;
    use crate::netlink_route::{IfIndex, IpPrefix};
    use crate::network::{CreatedNetwork, EndpointId, NetworkName, NetworkResourceNames};
    use crate::network_store::member::MemberId;
    use crate::nftables_batch::NftTableHandle;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;

    const BRIDGE_TOKEN: &str = "fandhe-net:web:1:0:0";

    fn pfx(a: [u8; 4], len: u8) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(Ipv4Addr::from(a)), len).unwrap()
    }

    fn realized() -> RealizedRecord {
        let name = NetworkName::new("web").unwrap();
        let names = NetworkResourceNames::derive(&name).unwrap();
        let c = CreatedNetwork {
            bridge: names.bridge().clone(),
            bridge_index: IfIndex::new(7).unwrap(),
            bridge_token: BRIDGE_TOKEN.to_owned(),
            table: names.table().clone(),
            gateway: pfx([10, 0, 0, 1], 24),
            name_resolution: NameResolution::default(),
            name,
        };
        RealizedRecord::from_created(
            &c,
            pfx([10, 0, 0, 0], 24),
            NftTableHandle::new(42).unwrap(),
            crate::network_store::HostGeneration::current().unwrap(),
        )
        .unwrap()
    }

    fn token(ep: &str) -> String {
        format!("{BRIDGE_TOKEN}/ep/{ep}/g/00000000000000000000000000000001")
    }

    fn member(id: &str, ep: &str, last: u8) -> MemberRecord {
        MemberRecord::new(
            MemberId::new(id).unwrap(),
            EndpointId::new(ep).unwrap(),
            pfx([10, 0, 0, last], 24),
            &token(ep),
            Path::new("/run/ns"),
            (8, 9),
            &[],
        )
        .unwrap()
    }

    fn intent(id: &str, ep: &str, last: u8) -> MemberIntent {
        MemberIntent::new(
            MemberId::new(id).unwrap(),
            EndpointId::new(ep).unwrap(),
            pfx([10, 0, 0, last], 24),
            &token(ep),
        )
        .unwrap()
    }

    fn eid(s: &str) -> EndpointId {
        EndpointId::new(s).unwrap()
    }

    /// NET-1・#3067: 確定記録 3 件と意図記録 1 件から組み直すと 4 件が数えられ、次の払い出しは .6。
    #[test]
    fn net1_3067_rebuild_counts_members_and_intents() {
        let members = [
            member("a", "a", 2),
            member("b", "b", 3),
            member("c", "c", 5),
        ];
        let intents = [intent("d", "d", 4)];
        let mut ipam = rebuild_ipam(&realized(), &members, &intents).unwrap();
        assert_eq!(ipam.allocated_count(), 4);
        assert_eq!(ipam.address_of(&eid("d")), Some(pfx([10, 0, 0, 4], 24)));
        assert_eq!(
            ipam.netns_dir_of(&eid("a")).unwrap().dir_id(),
            (8, 9),
            "確定記録は pin 置き場の記録つきで戻る"
        );
        assert!(ipam.netns_dir_of(&eid("d")).is_none());
        assert_eq!(ipam.allocate(&eid("e")).unwrap(), pfx([10, 0, 0, 6], 24));
    }

    /// 意図記録だけが残ったアドレスは再割り当てされない。
    #[test]
    fn net1_3067_rebuild_intent_only_address_is_not_reused() {
        let mut ipam = rebuild_ipam(&realized(), &[], &[intent("a", "a", 2)]).unwrap();
        assert_eq!(ipam.allocate(&eid("b")).unwrap(), pfx([10, 0, 0, 3], 24));
    }

    #[test]
    fn net1_3067_rebuild_same_id_member_and_intent_counts_once() {
        let ipam =
            rebuild_ipam(&realized(), &[member("a", "a", 2)], &[intent("a", "a", 2)]).unwrap();
        assert_eq!(ipam.allocated_count(), 1);
    }

    #[test]
    fn net1_3067_rebuild_conflicts_are_data_loss() {
        let r = realized();
        let cases: Vec<(Vec<MemberRecord>, Vec<MemberIntent>)> = vec![
            // アドレスの衝突。
            (vec![member("a", "a", 2), member("b", "b", 2)], vec![]),
            // 同じ endpoint を 2 件。
            (vec![member("a", "a", 2), member("b", "a", 3)], vec![]),
            // 同じ ID で内容が違う。
            (vec![member("a", "a", 2)], vec![intent("a", "a", 3)]),
            // 別 ID の意図記録とアドレスが衝突。
            (vec![member("a", "a", 2)], vec![intent("b", "b", 2)]),
            // 同じ ID・endpoint・アドレスでも所有トークンの世代が違う。
            (
                vec![member("a", "a", 2)],
                vec![
                    MemberIntent::new(
                        MemberId::new("a").unwrap(),
                        eid("a"),
                        pfx([10, 0, 0, 2], 24),
                        &format!("{BRIDGE_TOKEN}/ep/a/g/00000000000000000000000000000002"),
                    )
                    .unwrap(),
                ],
            ),
            // gateway と同じアドレス。
            (vec![member("a", "a", 1)], vec![]),
        ];
        for (m, i) in &cases {
            assert_eq!(
                rebuild_ipam(&r, m, i).unwrap_err().code(),
                NetErrorCode::DataLoss
            );
        }
        // 別ネットワークのトークン。
        let foreign = MemberRecord::new(
            MemberId::new("a").unwrap(),
            eid("a"),
            pfx([10, 0, 0, 2], 24),
            "fandhe-net:other:1:0:0/ep/a/g/00000000000000000000000000000001",
            Path::new("/run/ns"),
            (8, 9),
            &[],
        )
        .unwrap();
        assert_eq!(
            rebuild_ipam(&r, &[foreign], &[]).unwrap_err().code(),
            NetErrorCode::DataLoss
        );
        // サブネット外。
        let outside = member("a", "a", 2);
        let mut other = realized();
        other = RealizedRecord::decode(
            &String::from_utf8(other.encode())
                .unwrap()
                .replace("10.0.0.", "10.9.0.")
                .into_bytes(),
        )
        .unwrap();
        assert_eq!(
            rebuild_ipam(&other, &[outside], &[]).unwrap_err().code(),
            NetErrorCode::DataLoss
        );
    }

    #[test]
    fn net1_3067_rebuild_rejects_dns_equal_to_gateway() {
        let m = MemberRecord::new(
            MemberId::new("a").unwrap(),
            eid("a"),
            pfx([10, 0, 0, 2], 24),
            &token("a"),
            Path::new("/run/ns"),
            (8, 9),
            &["10.0.0.1".parse().unwrap()],
        )
        .unwrap();
        assert_eq!(
            rebuild_ipam(&realized(), &[m], &[]).unwrap_err().code(),
            NetErrorCode::DataLoss
        );
    }
}
