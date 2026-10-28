//! nftables の `bitwise`・`meta` expr の公開 API 結合試験（NET-1・NET-11・#3060）。
//!
//! crate 外部から公開 API だけで masquerade の形（payload → bitwise → cmp → meta → masq）の
//! NEWRULE を組み立て、符号化した具体的なワイヤー値を照合し、復号の往復と不正入力の拒否を確かめる。
//! ソケットを使わない OS 非依存の試験のため 3 OS の既定結合試験集合で実行する（ci.md）。

use fandhe_container_net::error::NetErrorCode;
use fandhe_container_net::netlink::NlMsgIter;
use fandhe_container_net::nftables_batch::{NFGENMSG_LEN, NftFamily, NftName};
use fandhe_container_net::nftables_rules::{
    NFT_BITWISE_MASK_XOR, NFTA_BITWISE_DREG, NFTA_BITWISE_LEN, NFTA_BITWISE_MASK, NFTA_BITWISE_OP,
    NFTA_BITWISE_SREG, NFTA_BITWISE_XOR, NFTA_META_DREG, NFTA_META_KEY, NftBitwise, NftCmp,
    NftDataValue, NftExprAttr, NftExprValue, NftMasq, NftMeta, NftMetaKey, NftPayload, NftRegister,
    NftRuleExprs, RuleCreate,
};

fn be32(attr: &NftExprAttr) -> u32 {
    attr.as_u32_be().expect("be32 attr")
}

/// NET-11: bitwise の mask-xor の各属性値（sreg/dreg/len/op/mask/xor）が具体値で一致する。
#[test]
fn net11_bitwise_wire_values() {
    let reg = NftRegister::REG_1;
    let b = NftBitwise::and_mask(
        reg,
        NftDataValue::new(&[0xff, 0xff, 0xff, 0x00]).expect("mask"),
    )
    .expect("bitwise");
    let e = b.to_expr().expect("expr");
    assert_eq!(e.name().as_str(), "bitwise");
    let d = e.data();
    assert_eq!(d.len(), 6);
    let get = |t: u16| d.iter().find(|a| a.attr_type() == t).expect("attr");
    assert_eq!(be32(get(NFTA_BITWISE_SREG)), 1);
    assert_eq!(be32(get(NFTA_BITWISE_DREG)), 1);
    assert_eq!(be32(get(NFTA_BITWISE_LEN)), 4);
    assert_eq!(be32(get(NFTA_BITWISE_OP)), NFT_BITWISE_MASK_XOR);
    assert!(matches!(
        get(NFTA_BITWISE_MASK).value(),
        NftExprValue::Nested(_)
    ));
    assert!(matches!(
        get(NFTA_BITWISE_XOR).value(),
        NftExprValue::Nested(_)
    ));
    assert_eq!(NftBitwise::from_expr(&e).expect("back"), b);
}

/// NET-11: meta の load の key/dreg が具体値（oifname = 7, REG_1 = 1）で一致する。
#[test]
fn net11_meta_wire_values() {
    let m = NftMeta::load(NftMetaKey::OifName, NftRegister::REG_1).expect("meta");
    let e = m.to_expr().expect("expr");
    assert_eq!(e.name().as_str(), "meta");
    let d = e.data();
    let get = |t: u16| d.iter().find(|a| a.attr_type() == t).expect("attr");
    assert_eq!(d.len(), 2);
    assert_eq!(be32(get(NFTA_META_KEY)), 7);
    assert_eq!(be32(get(NFTA_META_DREG)), 1);
    assert_eq!(NftMeta::from_expr(&e).expect("back"), m);
}

/// NET-1・NET-11: masquerade の形の NEWRULE が符号化でき、メッセージから expr 列が往復する。
#[test]
fn net1_masquerade_rule_message_roundtrips() {
    let reg = NftRegister::REG_1;
    let payload = NftPayload::ipv4_saddr(reg).expect("payload");
    let bitwise = NftBitwise::and_mask(
        reg,
        NftDataValue::new(&[0xff, 0xff, 0xff, 0x00]).expect("mask"),
    )
    .expect("bitwise");
    let net = NftCmp::eq(reg, NftDataValue::new(&[10, 88, 0, 0]).expect("net")).expect("cmp");
    let meta = NftMeta::load(NftMetaKey::OifName, reg).expect("meta");
    let mut exprs = NftRuleExprs::new();
    for e in [
        payload.to_expr().expect("e"),
        bitwise.to_expr().expect("e"),
        net.to_expr().expect("e"),
        meta.to_expr().expect("e"),
        NftMasq::new().to_expr().expect("e"),
    ] {
        exprs.push(e).expect("push");
    }
    let rule = RuleCreate::new(
        NftFamily::Ipv4,
        NftName::new("fandhe_nat").expect("table"),
        NftName::new("postrouting").expect("chain"),
        exprs,
    );
    let bytes = rule.build(7).expect("build").finish().expect("finish");
    let msg = NlMsgIter::new(&bytes).next().expect("one").expect("msg");
    assert_eq!(msg.header().seq(), 7);
    // 属性は table・chain・expressions の順。末尾の expressions を復号する。
    let attr = msg
        .attrs(NFGENMSG_LEN)
        .expect("attrs")
        .map(|a| a.expect("attr"))
        .last()
        .expect("expressions attr");
    let back = NftRuleExprs::decode(attr).expect("decode");
    assert_eq!(back.len(), 5);
    assert_eq!(NftBitwise::from_expr(&back.exprs()[1]).expect("b"), bitwise);
    assert_eq!(NftMeta::from_expr(&back.exprs()[3]).expect("m"), meta);
}

/// NET-11・REPAIR-2: レジスタ容量超過・長さ不一致は構築時に InvalidArgument で拒否される。
#[test]
fn net11_invalid_inputs_are_rejected() {
    // reg32 の末尾は容量 4 バイトのため、5 バイトの mask は載らない。
    let last = NftRegister::reg32(15).expect("reg32");
    let five = NftDataValue::new(&[0xff; 5]).expect("five");
    let e = NftBitwise::and_mask(last, five.clone()).expect_err("capacity");
    assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    // mask と xor の長さ不一致。
    let four = NftDataValue::new(&[0; 4]).expect("four");
    let e = NftBitwise::mask_xor(NftRegister::REG_1, NftRegister::REG_1, five, four)
        .expect_err("len mismatch");
    assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    // oifname は 16 バイト load で、4 バイト容量のレジスタには載らない。
    let e = NftMeta::load(NftMetaKey::OifName, last).expect_err("meta capacity");
    assert_eq!(e.code(), NetErrorCode::InvalidArgument);
}
