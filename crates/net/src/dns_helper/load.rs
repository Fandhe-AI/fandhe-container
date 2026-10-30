//! メンバー記録（`members/<id>`）から DNS ヘルパーのレジストリへ登録する名前を導く（NET-5・SEC-1・#3071）。
//!
//! 役割: ヘルパー側の制御サーバー（`control::os`）が `Reload` を受けたとき、読み込んだ [`MemberRecord`] の列を
//! 「名前 → IPv4 アドレス」の組へ変換する純関数だけを持つ（OS 非依存）。読み込み（ファイル）と差し替え
//! （[`super::DnsRegistry::replace_all`]）は呼び出し側が行う。
//!
//! # 名前の規則（D11 の空白を埋める判断。`docs/design/network-wiring.md`）
//! 各メンバーは最大 2 つの名前で登録される。(1) メンバー ID（コンテナ ID）を [`DnsName::new`] に通したもの、
//! (2) 記録の `dns-name`（コンテナ名。#3531）。
//! - ID が RFC 1123 のホスト名規則に合わない（`_` を含む・63 文字を超えるラベル・先頭末尾の `-` 等）ときは ID の名前を
//!   登録せず、件数だけを数える（[`LoadedNames::skipped_invalid`]。名前そのものはログに出さない）。`dns-name` は記録の
//!   復号時に検証済みなので、ここで無効になることはない
//! - 正規化後の名前を **2 つ以上の別メンバー** が主張したら、**どのメンバーにも登録しない**（先着で名前を取らせると、
//!   後から attach したコンテナが既存の名前を乗っ取れる。fail-closed）。件数は [`LoadedNames::dropped_collisions`]。
//!   同じメンバーの ID と `dns-name` が同じ名前になる場合は 1 件として数え、衝突にしない。衝突しなかった他方の名前は登録する
//!
//! 登録時の事前検査（`network::recorded`）が衝突する attach を断るが、記録は untrusted なのでここでも落とす（多層防御）。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use super::DnsName;
use super::upstream::{UpstreamList, validated_list};
use crate::network_store::MemberRecord;

/// [`names_from_members`] の結果。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadedNames {
    /// 登録する (名前, アドレス)。名前は正規化済みで互いに異なる。
    pub entries: Vec<(DnsName, Ipv4Addr)>,
    /// メンバー ID が DNS 名として無効なため、ID の名前を登録しなかった数（`dns-name` は検証済みのため数えない）。
    pub skipped_invalid: usize,
    /// 正規化後の名前が他のメンバーと衝突したため登録しなかった (名前, メンバー) の組の数（衝突した全員を数える）。
    pub dropped_collisions: usize,
}

/// メンバー記録から登録する名前を導く（純関数）。
pub fn names_from_members(members: &[MemberRecord]) -> LoadedNames {
    let mut out = LoadedNames::default();
    // 正規化名 → (アドレス, 主張したメンバーの添字)。同じメンバーの二重の主張は 1 件に数える。
    let mut by_name: HashMap<String, (Ipv4Addr, Vec<usize>)> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for (idx, m) in members.iter().enumerate() {
        let IpAddr::V4(addr) = m.address().addr() else {
            // 記録の検証（check_ipv4_member_address）が IPv4 に限るため通常は来ない。来たら無効として数える。
            out.skipped_invalid += 1;
            continue;
        };
        let id_name = match DnsName::new(m.id().as_str()) {
            Ok(n) => Some(n),
            Err(_) => {
                out.skipped_invalid += 1;
                None
            }
        };
        for name in id_name.iter().chain(m.dns_name()) {
            let key = name.as_str().to_owned();
            match by_name.get_mut(&key) {
                Some((_, claimed)) => {
                    if !claimed.contains(&idx) {
                        claimed.push(idx);
                    }
                }
                None => {
                    order.push(key.clone());
                    by_name.insert(key, (addr, vec![idx]));
                }
            }
        }
    }
    for key in order {
        let Some((addr, claimed)) = by_name.remove(&key) else {
            continue;
        };
        if claimed.len() > 1 {
            out.dropped_collisions += claimed.len();
            continue;
        }
        if let Ok(name) = DnsName::new(&key) {
            out.entries.push((name, addr));
        }
    }
    out
}

/// [`upstreams_from_members`] の結果。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadedUpstreams {
    /// 登録する (コンテナの IPv4, 上流リスト)。アドレスは互いに異なる。
    pub entries: Vec<(Ipv4Addr, UpstreamList)>,
    /// 上流の指定が無効（IPv6 のアドレス・loopback 等の拒否・gateway 指定）で登録しなかったメンバーの数。
    pub skipped_invalid: usize,
    /// 同じ IPv4 アドレスを持つ他のメンバーと衝突したため登録しなかったメンバーの数（衝突した全員を数える）。
    pub dropped_collisions: usize,
}

/// メンバー記録の `--dns`（FCMEM1 の `dns` 項目）から、コンテナのアドレスごとの上流を導く（純関数。NET-12・D11・#3072）。
///
/// 記録は untrusted として扱い、decode 時の検証に加えて `DnsUpstreamMap::set` と同じ
/// 検証（`validated_list`）を通す。`gateway` はヘルパー自身の待ち受けアドレスで、上流に指定されたメンバーは飛ばす。
/// `dns` が空のメンバーは結果に入れない（転送しない）。同じアドレスのメンバーが複数あれば、他コンテナの上流を
/// 奪えないよう**どれも登録しない**（名前の衝突の扱いと同じ fail-closed）。衝突は `dns` の検証より先に数え、
/// 片方の `dns` が無効でも衝突に含める（無効な側だけが落ちて他方が登録される状況を作らない）。
pub fn upstreams_from_members(members: &[MemberRecord], gateway: Ipv4Addr) -> LoadedUpstreams {
    let mut out = LoadedUpstreams::default();
    // 値は (上流リスト, 上流の指定が無効だったか, 件数)。無効なメンバーもアドレスの衝突には数える。
    let mut by_addr: HashMap<Ipv4Addr, (Option<UpstreamList>, bool, usize)> = HashMap::new();
    let mut order: Vec<Ipv4Addr> = Vec::new();
    for m in members {
        let IpAddr::V4(addr) = m.address().addr() else {
            out.skipped_invalid += 1;
            continue;
        };
        let servers = m.dns();
        let (list, invalid) = if servers.is_empty() {
            (None, false)
        } else {
            match validated_list(gateway, servers) {
                Ok(l) => (Some(l), false),
                Err(_) => (None, true),
            }
        };
        match by_addr.get_mut(&addr) {
            Some((_, _, n)) => *n += 1,
            None => {
                order.push(addr);
                by_addr.insert(addr, (list, invalid, 1));
            }
        }
    }
    for addr in order {
        let Some((list, invalid, n)) = by_addr.remove(&addr) else {
            continue;
        };
        if n > 1 {
            out.dropped_collisions += n;
            continue;
        }
        if invalid {
            out.skipped_invalid += 1;
            continue;
        }
        if let Some(list) = list {
            out.entries.push((addr, list));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink_route::IpPrefix;
    use crate::network::EndpointId;
    use crate::network_store::MemberId;
    use std::path::Path;

    fn member(id: &str, last: u8) -> MemberRecord {
        member_dns(id, last, &[])
    }

    fn member_dns(id: &str, last: u8, dns: &[IpAddr]) -> MemberRecord {
        let ep = EndpointId::new("ep").expect("endpoint");
        let token = format!(
            "fandhe-net:web:1:0:0/ep/{}/g/00000000000000000000000000000001",
            ep.as_str()
        );
        MemberRecord::new(
            MemberId::new(id).expect("id"),
            ep,
            IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, last)), 24).expect("prefix"),
            &token,
            Path::new("/run/ns"),
            (8, 9),
            dns,
        )
        .expect("member")
    }

    /// NET-5・#3071: 有効な ID はアドレスつきで登録される（具体値）。
    #[test]
    fn net5_3071_names_registers_valid_id() {
        let l = names_from_members(&[member("web", 2)]);
        assert_eq!(l.skipped_invalid, 0);
        assert_eq!(l.dropped_collisions, 0);
        assert_eq!(l.entries.len(), 1);
        assert_eq!(l.entries[0].0.as_str(), "web");
        assert_eq!(l.entries[0].1, Ipv4Addr::new(10, 89, 0, 2));
    }

    /// NET-5・#3071: `_` を含む ID は登録せず、件数だけを数える。
    #[test]
    fn net5_3071_names_skips_invalid_ids() {
        let l = names_from_members(&[member("my_app", 2), member("db", 3)]);
        assert_eq!(l.skipped_invalid, 1);
        assert_eq!(l.entries.len(), 1);
        assert_eq!(l.entries[0].0.as_str(), "db");
    }

    /// NET-5・SEC-1・#3071: 大文字小文字の違いだけで衝突する ID はどちらも登録しない（名前の乗っ取りの防止）。
    #[test]
    fn net5_3071_names_drops_both_colliding_ids() {
        let l = names_from_members(&[member("Web", 2), member("web", 3), member("db", 4)]);
        assert_eq!(l.dropped_collisions, 2);
        assert_eq!(l.entries.len(), 1);
        assert_eq!(l.entries[0].0.as_str(), "db");
    }

    /// NET-5・#3071: 空の入力は空の結果。
    #[test]
    fn net5_3071_names_empty_input() {
        assert_eq!(names_from_members(&[]), LoadedNames::default());
    }

    fn member_named(id: &str, last: u8, name: &str) -> MemberRecord {
        member(id, last).with_dns_name(DnsName::new(name).expect("name"))
    }

    fn names(l: &LoadedNames) -> Vec<(&str, Ipv4Addr)> {
        l.entries.iter().map(|(n, a)| (n.as_str(), *a)).collect()
    }

    /// NET-5・#3531: ID とコンテナ名の両方が同じアドレスで登録される。
    #[test]
    fn net5_3531_names_registers_id_and_name() {
        let l = names_from_members(&[member_named("c1", 2, "web")]);
        let a = Ipv4Addr::new(10, 89, 0, 2);
        assert_eq!(names(&l), vec![("c1", a), ("web", a)]);
        assert_eq!((l.skipped_invalid, l.dropped_collisions), (0, 0));
    }

    /// NET-5・#3531: 同じメンバーの ID と名前が同じ正規化名なら 1 件で、衝突にしない。
    #[test]
    fn net5_3531_names_same_id_and_name_counts_once() {
        let l = names_from_members(&[member_named("Web", 2, "web")]);
        assert_eq!(names(&l), vec![("web", Ipv4Addr::new(10, 89, 0, 2))]);
        assert_eq!(l.dropped_collisions, 0);
    }

    /// NET-5・SEC-1・#3531: 名前が他のメンバーの ID と衝突したら、その名前はどちらにも登録しない。
    #[test]
    fn net5_3531_names_name_vs_other_id_drops_both() {
        let l = names_from_members(&[member_named("a1", 2, "db"), member("db", 3)]);
        assert_eq!(names(&l), vec![("a1", Ipv4Addr::new(10, 89, 0, 2))]);
        assert_eq!(l.dropped_collisions, 2);
    }

    /// NET-5・SEC-1・#3531: 名前どうしの衝突もどちらにも登録しない。ID は登録される。
    #[test]
    fn net5_3531_names_name_vs_name_drops_both() {
        let l = names_from_members(&[member_named("a1", 2, "web"), member_named("b1", 3, "WEB")]);
        assert_eq!(
            names(&l),
            vec![
                ("a1", Ipv4Addr::new(10, 89, 0, 2)),
                ("b1", Ipv4Addr::new(10, 89, 0, 3))
            ]
        );
        assert_eq!(l.dropped_collisions, 2);
    }

    /// NET-5・#3531: ID が無効（`_`）でも、有効な名前は登録される。無効な ID は数える。
    #[test]
    fn net5_3531_names_invalid_id_with_valid_name() {
        let l = names_from_members(&[member_named("my_app", 2, "app")]);
        assert_eq!(names(&l), vec![("app", Ipv4Addr::new(10, 89, 0, 2))]);
        assert_eq!((l.skipped_invalid, l.dropped_collisions), (1, 0));
    }

    /// NET-5・#3531: 名前なし（旧形式）のメンバーは、名前つきのメンバーと混ざっても ID だけが登録される。
    #[test]
    fn net5_3531_names_old_format_member_id_only() {
        let l = names_from_members(&[member("old", 2), member_named("c1", 3, "web")]);
        assert_eq!(
            names(&l),
            vec![
                ("old", Ipv4Addr::new(10, 89, 0, 2)),
                ("c1", Ipv4Addr::new(10, 89, 0, 3)),
                ("web", Ipv4Addr::new(10, 89, 0, 3))
            ]
        );
    }

    const GW: Ipv4Addr = Ipv4Addr::new(10, 89, 0, 1);

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// NET-12・#3072: メンバーの `--dns` が、そのコンテナのアドレスの上流として登録順どおりに組まれる。
    #[test]
    fn net12_3072_upstreams_from_member_dns() {
        let m = member_dns("web", 2, &[ip(192, 0, 2, 53), ip(198, 51, 100, 7)]);
        let l = upstreams_from_members(&[m], GW);
        assert_eq!(l.skipped_invalid, 0);
        assert_eq!(l.dropped_collisions, 0);
        assert_eq!(l.entries.len(), 1);
        assert_eq!(l.entries[0].0, Ipv4Addr::new(10, 89, 0, 2));
        let got: Vec<String> = l.entries[0].1.iter().map(|a| a.to_string()).collect();
        assert_eq!(got, vec!["192.0.2.53:53", "198.51.100.7:53"]);
    }

    /// NET-12・#3072: コンテナごとに別々の上流が割り当たる（混ざらない）。
    #[test]
    fn net12_3072_upstreams_are_per_container() {
        let a = member_dns("a", 2, &[ip(192, 0, 2, 53)]);
        let b = member_dns("b", 3, &[ip(198, 51, 100, 7)]);
        let l = upstreams_from_members(&[a, b], GW);
        assert_eq!(l.entries.len(), 2);
        let first: Vec<String> = l.entries[0].1.iter().map(|x| x.to_string()).collect();
        let second: Vec<String> = l.entries[1].1.iter().map(|x| x.to_string()).collect();
        assert_eq!(l.entries[0].0, Ipv4Addr::new(10, 89, 0, 2));
        assert_eq!(first, vec!["192.0.2.53:53"]);
        assert_eq!(l.entries[1].0, Ipv4Addr::new(10, 89, 0, 3));
        assert_eq!(second, vec!["198.51.100.7:53"]);
    }

    /// NET-12・#3072: `dns` が空のメンバーは結果に入らない（転送しない）。
    #[test]
    fn net12_3072_member_without_dns_is_absent() {
        let l = upstreams_from_members(&[member("web", 2)], GW);
        assert_eq!(l, LoadedUpstreams::default());
    }

    /// NET-12・SEC-1・#3072: gateway（ヘルパー自身）を上流にしたメンバーだけが飛ばされる。
    #[test]
    fn net12_3072_gateway_upstream_is_skipped() {
        let bad = member_dns("bad", 2, &[IpAddr::V4(GW)]);
        let good = member_dns("good", 3, &[ip(192, 0, 2, 53)]);
        let l = upstreams_from_members(&[bad, good], GW);
        assert_eq!(l.skipped_invalid, 1);
        assert_eq!(l.entries.len(), 1);
        assert_eq!(l.entries[0].0, Ipv4Addr::new(10, 89, 0, 3));
    }

    /// NET-12・SEC-1・#3072: 同じアドレスのメンバーが 2 件あればどちらも登録しない。
    #[test]
    fn net12_3072_duplicate_address_drops_both() {
        let a = member_dns("a", 2, &[ip(192, 0, 2, 53)]);
        let b = member_dns("b", 2, &[ip(198, 51, 100, 7)]);
        let c = member_dns("c", 3, &[ip(192, 0, 2, 53)]);
        let l = upstreams_from_members(&[a, b, c], GW);
        assert_eq!(l.dropped_collisions, 2);
        assert_eq!(l.entries.len(), 1);
        assert_eq!(l.entries[0].0, Ipv4Addr::new(10, 89, 0, 3));
    }

    /// NET-12・SEC-1・#3072: 同じアドレスの片方の `dns` が無効でも衝突として両方を落とす（有効な側だけが登録されない）。
    #[test]
    fn net12_3072_duplicate_address_with_invalid_dns_drops_both() {
        let bad = member_dns("bad", 2, &[IpAddr::V4(GW)]);
        let good = member_dns("good", 2, &[ip(192, 0, 2, 53)]);
        let l = upstreams_from_members(&[bad, good], GW);
        assert_eq!(l.dropped_collisions, 2);
        assert_eq!(l.skipped_invalid, 0);
        assert!(l.entries.is_empty());
    }
}
