//! メンバー記録（`members/<id>`）から DNS ヘルパーのレジストリへ登録する名前を導く（NET-5・SEC-1・#3071）。
//!
//! 役割: ヘルパー側の制御サーバー（`control::os`）が `Reload` を受けたとき、読み込んだ [`MemberRecord`] の列を
//! 「名前 → IPv4 アドレス」の組へ変換する純関数だけを持つ（OS 非依存）。読み込み（ファイル）と差し替え
//! （[`super::DnsRegistry::replace_all`]）は呼び出し側が行う。
//!
//! # 名前の規則（D11 の空白を埋める判断。`docs/design/network-wiring.md`）
//! FCMEM1 にホスト名の項目は無い。本 PR では記録の形式を広げず、メンバー ID（コンテナ ID）を
//! [`DnsName::new`] に通して登録名にする。
//! - RFC 1123 のホスト名規則に合わないもの（`_` を含む・63 文字を超えるラベル・先頭末尾の `-` 等）は登録せず、
//!   件数だけを数える（[`LoadedNames::skipped_invalid`]。名前そのものはログに出さない）
//! - 大文字小文字の正規化で同じ名前になる ID が複数あれば、**どれも登録しない**（先着で名前を取らせると、
//!   後から attach したコンテナが既存の名前を乗っ取れる。fail-closed）。件数は
//!   [`LoadedNames::dropped_collisions`]
//!
//! コンテナ名（`--name` 等）を使う拡張は記録形式の変更を伴うため、この PR の範囲外（残余）。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use super::DnsName;
use crate::network_store::MemberRecord;

/// [`names_from_members`] の結果。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadedNames {
    /// 登録する (名前, アドレス)。名前は正規化済みで互いに異なる。
    pub entries: Vec<(DnsName, Ipv4Addr)>,
    /// DNS 名として無効なため登録しなかったメンバーの数。
    pub skipped_invalid: usize,
    /// 正規化後の名前が他のメンバーと衝突したため、登録しなかったメンバーの数（衝突した全員を数える）。
    pub dropped_collisions: usize,
}

/// メンバー記録から登録する名前を導く（純関数）。
pub fn names_from_members(members: &[MemberRecord]) -> LoadedNames {
    let mut out = LoadedNames::default();
    // 正規化名 → 該当した (アドレス, 件数)。
    let mut by_name: HashMap<String, (Ipv4Addr, usize)> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for m in members {
        let IpAddr::V4(addr) = m.address().addr() else {
            // 記録の検証（check_ipv4_member_address）が IPv4 に限るため通常は来ない。来たら無効として数える。
            out.skipped_invalid += 1;
            continue;
        };
        let Ok(name) = DnsName::new(m.id().as_str()) else {
            out.skipped_invalid += 1;
            continue;
        };
        let key = name.as_str().to_owned();
        match by_name.get_mut(&key) {
            Some((_, n)) => *n += 1,
            None => {
                order.push(key.clone());
                by_name.insert(key, (addr, 1));
            }
        }
    }
    for key in order {
        let Some((addr, n)) = by_name.remove(&key) else {
            continue;
        };
        if n > 1 {
            out.dropped_collisions += n;
            continue;
        }
        if let Ok(name) = DnsName::new(&key) {
            out.entries.push((name, addr));
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
            &[],
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
}
