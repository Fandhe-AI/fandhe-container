//! ネットワーク専用 nft テーブルの `postrouting` へ投入する masquerade ルールの expr 列（NET-1・NET-11・
//! D11・#3073）。
//!
//! 呼び出し元は `crate::network` の `fill_create_batch`（`create_network` の nft バッチ。テーブル・
//! チェインと同じ all-or-nothing のバッチの末尾に 1 件積む）。値は検証済みの `NetworkCreateSpec` の gateway
//! と、ネットワーク名から導出した bridge の `IfName` だけから作り、外部の文字列は組み込まない。
//!
//! # ルールの形
//!
//! `ip saddr <subnet>/<n> oifname != "<bridge>" masquerade`（Docker の `-s <subnet> ! -o <bridge>
//! -j MASQUERADE` と同じ意味）。出口が bridge 自身の通信を除外するのは、`bridge-nf-call-iptables` が
//! 有効な環境で bridge 内（コンテナ間）の通信まで送信元を書き換えてしまうのを避けるため。
//! expr 列は payload(saddr) → bitwise(mask) → cmp eq(network) → meta(oifname) → cmp neq(bridge 名)
//! → masq の 6 個。
//!
//! # 契約・未実装範囲（REPAIR-3）
//!
//! - IPv4 のみ（静的 IPAM が IPv4 のみのため）
//! - host の `ip_forward` は変更しない（D11。NET-10 の診断で案内する）。削除はテーブル単位のため、
//!   ルール個別のハンドルは持たない

use crate::error::{NetError, NetErrorCode};
use crate::netlink_route::{IfName, IpPrefix};
use crate::nftables_rules::{
    NftBitwise, NftCmp, NftCmpOp, NftDataValue, NftMasq, NftMeta, NftMetaKey, NftPayload,
    NftRegister, NftRuleExprs,
};

/// `meta oifname` の load 長（`IFNAMSIZ`。NUL 込み）。
const IFNAME_LEN: usize = 16;

fn invalid(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

/// IPv4 のプレフィックス長（1..=32）からネットマスクを作る。0 と 33 以上は `InvalidArgument`。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn ipv4_prefix_mask(prefix_len: u8) -> Result<[u8; 4], NetError> {
    if prefix_len == 0 || prefix_len > 32 {
        return Err(invalid("ipv4 prefix length must be 1 to 32"));
    }
    let shift = 32u32
        .checked_sub(u32::from(prefix_len))
        .ok_or_else(|| invalid("ipv4 prefix length must be 1 to 32"))?;
    let mask = u32::MAX
        .checked_shl(shift)
        .ok_or_else(|| invalid("ipv4 prefix length must be 1 to 32"))?;
    Ok(mask.to_be_bytes())
}

/// インターフェース名を NUL で 16 バイトに詰める（`meta oifname` の比較値。`IfName` は 15 バイト以下）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn ifname_padded(name: &IfName) -> [u8; IFNAME_LEN] {
    let mut out = [0u8; IFNAME_LEN];
    let bytes = name.as_str().as_bytes();
    // `IfName::new` が 15 バイト以下を保証する。万一超えても切り詰めて panic しない。
    let n = bytes.len().min(IFNAME_LEN - 1);
    if let (Some(dst), Some(src)) = (out.get_mut(..n), bytes.get(..n)) {
        dst.copy_from_slice(src);
    }
    out
}

/// `ip saddr <subnet> oifname != <bridge> masquerade` の expr 列を作る。IPv4 以外は `InvalidArgument`。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn masquerade_rule_exprs(
    gateway: &IpPrefix,
    bridge: &IfName,
) -> Result<NftRuleExprs, NetError> {
    let std::net::IpAddr::V4(addr) = gateway.addr() else {
        return Err(invalid("masquerade supports ipv4 only"));
    };
    let mask = ipv4_prefix_mask(gateway.prefix_len())?;
    let network = u32::from(addr) & u32::from_be_bytes(mask);
    let r1 = NftRegister::REG_1;
    let mut exprs = NftRuleExprs::new();
    exprs.push(NftPayload::ipv4_saddr(r1)?.to_expr()?)?;
    exprs.push(NftBitwise::and_mask(r1, NftDataValue::new(&mask)?)?.to_expr()?)?;
    exprs.push(NftCmp::eq(r1, NftDataValue::new(&network.to_be_bytes())?)?.to_expr()?)?;
    exprs.push(NftMeta::load(NftMetaKey::OifName, r1)?.to_expr()?)?;
    exprs.push(
        NftCmp::new(
            r1,
            NftCmpOp::Neq,
            NftDataValue::new(&ifname_padded(bridge))?,
        )?
        .to_expr()?,
    )?;
    exprs.push(NftMasq::new().to_expr()?)?;
    Ok(exprs)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    fn ifname(s: &str) -> IfName {
        IfName::new(s).expect("ifname")
    }

    fn gw(a: [u8; 4], len: u8) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(Ipv4Addr::from(a)), len).expect("prefix")
    }

    /// NET-1・NET-11: プレフィックス長からのマスクの具体値。
    #[test]
    fn masks_for_prefix_lengths() {
        assert_eq!(ipv4_prefix_mask(24).expect("24"), [255, 255, 255, 0]);
        assert_eq!(ipv4_prefix_mask(30).expect("30"), [255, 255, 255, 252]);
        assert_eq!(ipv4_prefix_mask(1).expect("1"), [128, 0, 0, 0]);
        assert_eq!(ipv4_prefix_mask(17).expect("17"), [255, 255, 128, 0]);
        assert_eq!(ipv4_prefix_mask(32).expect("32"), [255, 255, 255, 255]);
        for bad in [0u8, 33, 255] {
            assert_eq!(
                ipv4_prefix_mask(bad).expect_err("bad").code(),
                NetErrorCode::InvalidArgument
            );
        }
    }

    /// NET-1・NET-11: 名前は NUL で 16 バイトに詰まり、meta oifname の load 長と一致する。
    #[test]
    fn ifname_padding() {
        let p = ifname_padded(&ifname("br-test"));
        assert_eq!(&p[..7], b"br-test");
        assert_eq!(&p[7..], &[0u8; 9]);
        let long = ifname_padded(&ifname("abcdefghijklmno"));
        assert_eq!(&long[..15], b"abcdefghijklmno");
        assert_eq!(long[15], 0);
        assert_eq!(
            u32::try_from(p.len()).expect("len"),
            NftMetaKey::OifName.load_len()
        );
    }

    /// NET-1・NET-11: 6 expr の順序と具体値。
    #[test]
    fn rule_exprs_concrete_values() {
        let exprs = masquerade_rule_exprs(&gw([10, 88, 0, 1], 24), &ifname("fcbr1234")).expect("e");
        let e = exprs.exprs();
        assert_eq!(e.len(), 6);
        let r1 = NftRegister::REG_1;
        assert_eq!(
            NftPayload::from_expr(&e[0]).expect("p"),
            NftPayload::ipv4_saddr(r1).expect("p")
        );
        let b = NftBitwise::from_expr(&e[1]).expect("b");
        assert_eq!(b.mask().as_bytes(), &[255, 255, 255, 0]);
        let net = NftCmp::from_expr(&e[2]).expect("c");
        assert_eq!(net.op(), NftCmpOp::Eq);
        assert_eq!(net.data().as_bytes(), &[10, 88, 0, 0]);
        let m = NftMeta::from_expr(&e[3]).expect("m");
        assert_eq!(m.key(), NftMetaKey::OifName);
        let out = NftCmp::from_expr(&e[4]).expect("c");
        assert_eq!(out.op(), NftCmpOp::Neq);
        assert_eq!(out.data().as_bytes(), &ifname_padded(&ifname("fcbr1234")));
        assert_eq!(NftMasq::from_expr(&e[5]).expect("q"), NftMasq::new());
    }

    /// NET-1・NET-11: バイト境界でない /17 でも network は addr & mask。
    #[test]
    fn rule_network_is_masked_for_non_byte_boundary() {
        let exprs = masquerade_rule_exprs(&gw([172, 20, 200, 1], 17), &ifname("br0")).expect("e");
        let net = NftCmp::from_expr(&exprs.exprs()[2]).expect("c");
        assert_eq!(net.data().as_bytes(), &[172, 20, 128, 0]);
    }

    /// NET-1: IPv6 の gateway は拒否する。
    #[test]
    fn rule_rejects_ipv6() {
        let g = IpPrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 64).expect("p");
        let e = masquerade_rule_exprs(&g, &ifname("br0")).expect_err("v6");
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    }
}
