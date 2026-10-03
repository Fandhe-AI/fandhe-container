//! nf_tables の `nat` expr（SNAT / DNAT。レジスタ指定の変換先）の型付きエンコード
//! （TASK-138.3・NET-11・REPAIR-2・MS-8・#311）。
//!
//! 変換先アドレス・ポートはレジスタから読むため、直前に [`super::NftImmediate`] で値を置く。
//! DNAT はポート公開（TASK-139）に使う。OS 非依存のコーデックで、ソケット・`unsafe` は持たない。
//! expr 名 `"nat"` はコンパイル時定数に固定する。
//!
//! # 呼び出し元
//!
//! [`super::RuleCreate`] に積む [`super::NftRuleExprs`] の末尾へ `to_expr` の結果を `push` する。
//!
//! # ワイヤーレイアウト
//!
//! 定数の出典は UAPI `linux/netfilter/nf_tables.h`・`linux/netfilter/nf_nat.h`。数値属性はすべて `__be32`。
//! 属性順は libnftnl（`nftnl_expr_nat_build`）に合わせる。
//!
//! ```text
//! NFTA_EXPR_DATA (nested) {
//!   NFTA_NAT_TYPE         = be32 (NFT_NAT_SNAT=0 / NFT_NAT_DNAT=1)
//!   NFTA_NAT_FAMILY       = be32 (NFPROTO_IPV4=2 / NFPROTO_IPV6=10)
//!   NFTA_NAT_REG_ADDR_MIN = be32 (レジスタ)   // 任意
//!   NFTA_NAT_REG_ADDR_MAX = be32 (レジスタ)   // 任意。MIN があるときのみ
//!   NFTA_NAT_REG_PROTO_MIN = be32 (レジスタ)  // 任意
//!   NFTA_NAT_REG_PROTO_MAX = be32 (レジスタ)  // 任意。MIN があるときのみ
//!   NFTA_NAT_FLAGS        = be32 (NF_NAT_RANGE_*。0 のときは省略)
//! }
//! ```
//!
//! # 信頼境界
//!
//! アドレス・ポートの両方が無い nat、容量不足のレジスタ（アドレス 4 / 16 バイト、ポート 2 バイト）、
//! 未知のフラグビットを構築時に `InvalidArgument` で拒否する。`NF_NAT_RANGE_MAP_IPS` /
//! `PROTO_SPECIFIED` は kernel が属性の有無から導くため受け取らず送らない。
//! kernel は DNAT を nat 型 chain の PREROUTING / OUTPUT に限って受理し（`nft_nat_validate`）、
//! ip / ip6 テーブルでは nat の family がテーブルと一致する必要がある（`nft_nat_init`）。
//! これらは kernel 側の検証で、ここでは判定しない。[`NftNat::from_expr`] は違反を `DataLoss` で拒否する。
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - `NF_NAT_RANGE_PROTO_OFFSET` / `NETMAP` と、SNAT の実機検証
//! - inet テーブルでのアドレス family 指定の実機検証

use std::ops::BitOr;

use super::{
    NftExpr, NftExprAttr, NftExprName, NftRegister, collect_u32_attrs, data_loss, invalid,
};
use crate::error::NetError;

/// 変換種別（`NFTA_NAT_TYPE`）。
pub const NFTA_NAT_TYPE: u16 = 1;
/// アドレス family（`NFTA_NAT_FAMILY`）。
pub const NFTA_NAT_FAMILY: u16 = 2;
/// アドレス範囲の下限レジスタ（`NFTA_NAT_REG_ADDR_MIN`）。
pub const NFTA_NAT_REG_ADDR_MIN: u16 = 3;
/// アドレス範囲の上限レジスタ（`NFTA_NAT_REG_ADDR_MAX`）。
pub const NFTA_NAT_REG_ADDR_MAX: u16 = 4;
/// ポート範囲の下限レジスタ（`NFTA_NAT_REG_PROTO_MIN`）。
pub const NFTA_NAT_REG_PROTO_MIN: u16 = 5;
/// ポート範囲の上限レジスタ（`NFTA_NAT_REG_PROTO_MAX`）。
pub const NFTA_NAT_REG_PROTO_MAX: u16 = 6;
/// フラグ（`NFTA_NAT_FLAGS`）。
pub const NFTA_NAT_FLAGS: u16 = 7;
/// `NFT_NAT_SNAT`。
pub const NFT_NAT_SNAT: u32 = 0;
/// `NFT_NAT_DNAT`。
pub const NFT_NAT_DNAT: u32 = 1;
/// `NFPROTO_IPV4`。
const NFPROTO_IPV4: u32 = 2;
/// `NFPROTO_IPV6`。
const NFPROTO_IPV6: u32 = 10;
/// ソースポートをランダム化する（`NF_NAT_RANGE_PROTO_RANDOM`）。
pub const NAT_RANGE_PROTO_RANDOM: u32 = 1 << 2;
/// 同一送信元に同じマッピングを使う（`NF_NAT_RANGE_PERSISTENT`）。
pub const NAT_RANGE_PERSISTENT: u32 = 1 << 3;
/// 完全にランダム化する（`NF_NAT_RANGE_PROTO_RANDOM_FULLY`）。
pub const NAT_RANGE_PROTO_RANDOM_FULLY: u32 = 1 << 4;

const NAT_EXPR_NAME: &str = "nat";
const KNOWN_FLAGS: u32 =
    NAT_RANGE_PROTO_RANDOM | NAT_RANGE_PERSISTENT | NAT_RANGE_PROTO_RANDOM_FULLY;
/// ポート（`u16`）を置くレジスタに要る最小容量。
const PORT_BYTES: u32 = 2;

/// 変換種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// 送信元の書き換え。
    Snat,
    /// 宛先の書き換え。
    Dnat,
}

impl NatType {
    const fn wire_value(self) -> u32 {
        match self {
            Self::Snat => NFT_NAT_SNAT,
            Self::Dnat => NFT_NAT_DNAT,
        }
    }

    fn from_wire(v: u32) -> Option<Self> {
        match v {
            NFT_NAT_SNAT => Some(Self::Snat),
            NFT_NAT_DNAT => Some(Self::Dnat),
            _ => None,
        }
    }
}

/// 変換先アドレスの family。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatFamily {
    /// IPv4（アドレス 4 バイト）。
    Ipv4,
    /// IPv6（アドレス 16 バイト）。
    Ipv6,
}

impl NatFamily {
    const fn wire_value(self) -> u32 {
        match self {
            Self::Ipv4 => NFPROTO_IPV4,
            Self::Ipv6 => NFPROTO_IPV6,
        }
    }

    fn from_wire(v: u32) -> Option<Self> {
        match v {
            NFPROTO_IPV4 => Some(Self::Ipv4),
            NFPROTO_IPV6 => Some(Self::Ipv6),
            _ => None,
        }
    }

    /// アドレスのバイト長。
    pub const fn addr_len(self) -> u32 {
        match self {
            Self::Ipv4 => 4,
            Self::Ipv6 => 16,
        }
    }
}

/// 既知の `NF_NAT_RANGE_*` ビットだけを持つフラグ集合。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NatFlags(u32);

impl NatFlags {
    /// フラグなし。
    pub const NONE: Self = Self(0);
    /// `NF_NAT_RANGE_PROTO_RANDOM`。
    pub const PROTO_RANDOM: Self = Self(NAT_RANGE_PROTO_RANDOM);
    /// `NF_NAT_RANGE_PERSISTENT`。
    pub const PERSISTENT: Self = Self(NAT_RANGE_PERSISTENT);
    /// `NF_NAT_RANGE_PROTO_RANDOM_FULLY`。
    pub const PROTO_RANDOM_FULLY: Self = Self(NAT_RANGE_PROTO_RANDOM_FULLY);

    /// ビット値から作る。未知ビット（`MAP_IPS` / `PROTO_SPECIFIED` を含む）は `InvalidArgument`。
    pub fn from_bits(bits: u32) -> Result<Self, NetError> {
        if bits & !KNOWN_FLAGS != 0 {
            return Err(invalid("unsupported nat flag bits"));
        }
        Ok(Self(bits))
    }

    /// ビット値。
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl BitOr for NatFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// 値の範囲を持つ変換先（下限レジスタと任意の上限レジスタ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatRange {
    /// 下限（単一値のときはこの値）。
    pub min: NftRegister,
    /// 上限。`None` なら単一値。
    pub max: Option<NftRegister>,
}

impl NatRange {
    /// 単一値。
    pub fn single(min: NftRegister) -> Self {
        Self { min, max: None }
    }

    fn check(&self, need: u32, msg: &'static str) -> Result<(), NetError> {
        let ok = self.min.capacity() >= need && self.max.is_none_or(|m| m.capacity() >= need);
        if ok { Ok(()) } else { Err(invalid(msg)) }
    }
}

/// `nat` expr。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NftNat {
    nat_type: NatType,
    family: NatFamily,
    addr: Option<NatRange>,
    proto: Option<NatRange>,
    flags: NatFlags,
}

impl NftNat {
    /// アドレス・ポートの少なくとも一方が必要。レジスタ容量不足は `InvalidArgument`。
    pub fn new(
        nat_type: NatType,
        family: NatFamily,
        addr: Option<NatRange>,
        proto: Option<NatRange>,
        flags: NatFlags,
    ) -> Result<Self, NetError> {
        if addr.is_none() && proto.is_none() {
            return Err(invalid("nat needs an address or a port register"));
        }
        if let Some(a) = &addr {
            a.check(
                family.addr_len(),
                "nat address register capacity is too small",
            )?;
        }
        if let Some(p) = &proto {
            p.check(PORT_BYTES, "nat port register capacity is too small")?;
        }
        Ok(Self {
            nat_type,
            family,
            addr,
            proto,
            flags,
        })
    }

    /// IPv4 の DNAT。`addr_reg` に宛先アドレス、`proto_reg` に宛先ポートを置いておく。
    pub fn dnat_ipv4(
        addr_reg: NftRegister,
        proto_reg: Option<NftRegister>,
    ) -> Result<Self, NetError> {
        Self::new(
            NatType::Dnat,
            NatFamily::Ipv4,
            Some(NatRange::single(addr_reg)),
            proto_reg.map(NatRange::single),
            NatFlags::NONE,
        )
    }

    /// 変換種別。
    pub fn nat_type(&self) -> NatType {
        self.nat_type
    }

    /// アドレス family。
    pub fn family(&self) -> NatFamily {
        self.family
    }

    /// アドレス範囲。
    pub fn addr(&self) -> Option<NatRange> {
        self.addr
    }

    /// ポート範囲。
    pub fn proto(&self) -> Option<NatRange> {
        self.proto
    }

    /// フラグ。
    pub fn flags(&self) -> NatFlags {
        self.flags
    }

    /// 汎用 [`NftExpr`] へ変換する。
    pub fn to_expr(&self) -> Result<NftExpr, NetError> {
        let mut data = vec![
            NftExprAttr::u32_be(NFTA_NAT_TYPE, self.nat_type.wire_value())?,
            NftExprAttr::u32_be(NFTA_NAT_FAMILY, self.family.wire_value())?,
        ];
        let ranges = [
            (self.addr, NFTA_NAT_REG_ADDR_MIN, NFTA_NAT_REG_ADDR_MAX),
            (self.proto, NFTA_NAT_REG_PROTO_MIN, NFTA_NAT_REG_PROTO_MAX),
        ];
        for (range, min_ty, max_ty) in ranges {
            if let Some(r) = range {
                data.push(NftExprAttr::u32_be(min_ty, r.min.wire_value())?);
                if let Some(max) = r.max {
                    data.push(NftExprAttr::u32_be(max_ty, max.wire_value())?);
                }
            }
        }
        if self.flags.bits() != 0 {
            data.push(NftExprAttr::u32_be(NFTA_NAT_FLAGS, self.flags.bits())?);
        }
        NftExpr::new(NftExprName::new(NAT_EXPR_NAME)?, data)
    }

    /// 汎用 [`NftExpr`] から復元する。違反はすべて `DataLoss`（fail-closed）。
    pub fn from_expr(expr: &NftExpr) -> Result<Self, NetError> {
        let attrs = collect_u32_attrs(expr, NAT_EXPR_NAME)?;
        let get = |ty: u16| attrs.iter().find(|(t, _)| *t == ty).map(|(_, v)| *v);
        let known = [
            NFTA_NAT_TYPE,
            NFTA_NAT_FAMILY,
            NFTA_NAT_REG_ADDR_MIN,
            NFTA_NAT_REG_ADDR_MAX,
            NFTA_NAT_REG_PROTO_MIN,
            NFTA_NAT_REG_PROTO_MAX,
            NFTA_NAT_FLAGS,
        ];
        if attrs.iter().any(|(t, _)| !known.contains(t)) {
            return Err(data_loss("unknown attribute in nat expr"));
        }
        let nat_type = get(NFTA_NAT_TYPE)
            .and_then(NatType::from_wire)
            .ok_or_else(|| data_loss("missing or unknown nat type"))?;
        let family = get(NFTA_NAT_FAMILY)
            .and_then(NatFamily::from_wire)
            .ok_or_else(|| data_loss("missing or unknown nat family"))?;
        let range = |min_ty: u16, max_ty: u16| -> Result<Option<NatRange>, NetError> {
            let reg =
                |v: u32| NftRegister::from_wire(v).map_err(|_| data_loss("invalid nat register"));
            match (get(min_ty), get(max_ty)) {
                (None, None) => Ok(None),
                (None, Some(_)) => Err(data_loss("nat max register without min")),
                (Some(min), max) => Ok(Some(NatRange {
                    min: reg(min)?,
                    max: max.map(reg).transpose()?,
                })),
            }
        };
        let addr = range(NFTA_NAT_REG_ADDR_MIN, NFTA_NAT_REG_ADDR_MAX)?;
        let proto = range(NFTA_NAT_REG_PROTO_MIN, NFTA_NAT_REG_PROTO_MAX)?;
        let flags = NatFlags::from_bits(get(NFTA_NAT_FLAGS).unwrap_or(0))
            .map_err(|_| data_loss("unsupported nat flag bits"))?;
        Self::new(nat_type, family, addr, proto, flags)
            .map_err(|_| data_loss("invalid nat expr contents"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NetErrorCode;
    use crate::netlink::NlMsgBuilder;
    use crate::nftables_batch::{NftBatch, NftFamily, NftName};
    use crate::nftables_rules::{
        NftCmp, NftDataValue, NftImmediate, NftPayload, NftRuleExprs, RuleCreate,
    };

    fn data_bytes(expr: &NftExpr) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(0, 0, 1, 0);
        for a in expr.data() {
            a.put_into(&mut b).expect("put attr");
        }
        let all = b.finish().expect("finish");
        all.get(16..).expect("body").to_vec()
    }

    fn expr_with(name: &str, attrs: Vec<NftExprAttr>) -> NftExpr {
        NftExpr::new(NftExprName::new(name).expect("name"), attrs).expect("expr")
    }

    fn attr_be32(ty: u16, v: u32) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(&8u16.to_ne_bytes());
        w.extend_from_slice(&ty.to_ne_bytes());
        w.extend_from_slice(&v.to_be_bytes());
        w
    }

    /// NET-11・REPAIR-2: dnat_ipv4 は TYPE/FAMILY/ADDR_MIN/PROTO_MIN の 4 属性で FLAGS を出さない。
    #[test]
    fn wire_layout_of_dnat_ipv4() {
        let e = NftNat::dnat_ipv4(NftRegister::REG_1, Some(NftRegister::REG_2))
            .expect("nat")
            .to_expr()
            .expect("expr");
        assert_eq!(e.name().as_str(), "nat");
        let mut want = Vec::new();
        want.extend(attr_be32(NFTA_NAT_TYPE, 1));
        want.extend(attr_be32(NFTA_NAT_FAMILY, 2));
        want.extend(attr_be32(NFTA_NAT_REG_ADDR_MIN, 1));
        want.extend(attr_be32(NFTA_NAT_REG_PROTO_MIN, 2));
        assert_eq!(data_bytes(&e), want);
    }

    /// NET-11: フラグ付きは FLAGS の be32 値が末尾に載る。
    #[test]
    fn flags_are_appended() {
        let n = NftNat::new(
            NatType::Dnat,
            NatFamily::Ipv4,
            Some(NatRange::single(NftRegister::REG_1)),
            None,
            NatFlags::PROTO_RANDOM | NatFlags::PERSISTENT,
        )
        .expect("nat");
        let mut want = Vec::new();
        want.extend(attr_be32(NFTA_NAT_TYPE, 1));
        want.extend(attr_be32(NFTA_NAT_FAMILY, 2));
        want.extend(attr_be32(NFTA_NAT_REG_ADDR_MIN, 1));
        want.extend(attr_be32(NFTA_NAT_FLAGS, 0x0c));
        assert_eq!(data_bytes(&n.to_expr().expect("expr")), want);
    }

    /// NET-11: 往復（addr のみ / proto のみ / min-max 両方 / IPv6 / SNAT）。
    #[test]
    fn roundtrip_variants() {
        let r = NftRegister::REG_1;
        let r2 = NftRegister::REG_2;
        let range = NatRange {
            min: r,
            max: Some(r2),
        };
        for n in [
            NftNat::new(
                NatType::Dnat,
                NatFamily::Ipv4,
                Some(NatRange::single(r)),
                None,
                NatFlags::NONE,
            ),
            NftNat::new(
                NatType::Dnat,
                NatFamily::Ipv4,
                None,
                Some(NatRange::single(r2)),
                NatFlags::NONE,
            ),
            NftNat::new(
                NatType::Snat,
                NatFamily::Ipv4,
                Some(range),
                Some(range),
                NatFlags::PERSISTENT,
            ),
            NftNat::new(
                NatType::Dnat,
                NatFamily::Ipv6,
                Some(NatRange::single(r)),
                None,
                NatFlags::PROTO_RANDOM_FULLY,
            ),
        ] {
            let n = n.expect("nat");
            let back = NftNat::from_expr(&n.to_expr().expect("expr")).expect("from_expr");
            assert_eq!(back, n);
        }
    }

    /// NET-11・REPAIR-2: 構築時の拒否と受理の境界。
    #[test]
    fn new_rejects_invalid_arguments() {
        let none =
            |addr, proto| NftNat::new(NatType::Dnat, NatFamily::Ipv4, addr, proto, NatFlags::NONE);
        assert_eq!(
            none(None, None).expect_err("reject").code(),
            NetErrorCode::InvalidArgument
        );
        let r13 = NftRegister::reg32(13).expect("reg");
        let v6 = NftNat::new(
            NatType::Dnat,
            NatFamily::Ipv6,
            Some(NatRange::single(r13)),
            None,
            NatFlags::NONE,
        );
        assert_eq!(
            v6.expect_err("reject").code(),
            NetErrorCode::InvalidArgument
        );
        let r15 = NftRegister::reg32(15).expect("reg");
        assert!(none(None, Some(NatRange::single(r15))).is_ok());
        // addr 上限レジスタの容量も検証する
        let bad_max = NatRange {
            min: NftRegister::REG_1,
            max: Some(r13),
        };
        let v6_max = NftNat::new(
            NatType::Dnat,
            NatFamily::Ipv6,
            Some(bad_max),
            None,
            NatFlags::NONE,
        );
        assert!(v6_max.is_err());
        for bits in [1, 2, 1 << 5, u32::MAX] {
            assert_eq!(
                NatFlags::from_bits(bits).expect_err("reject").code(),
                NetErrorCode::InvalidArgument,
                "{bits:#x}"
            );
        }
    }

    /// NET-11・REPAIR-2: from_expr は不正な expr を DataLoss で拒否する。
    #[test]
    fn from_expr_rejects_malformed_exprs() {
        let a = |ty: u16, v: u32| NftExprAttr::u32_be(ty, v).expect("attr");
        let ty = |v| a(NFTA_NAT_TYPE, v);
        let fam = |v| a(NFTA_NAT_FAMILY, v);
        let amin = || a(NFTA_NAT_REG_ADDR_MIN, 1);
        let cases = [
            expr_with("masq", vec![ty(1), fam(2), amin()]),
            expr_with("nat", vec![fam(2), amin()]),
            expr_with("nat", vec![ty(2), fam(2), amin()]),
            expr_with("nat", vec![ty(1), fam(3), amin()]),
            expr_with("nat", vec![ty(1), fam(2)]),
            expr_with("nat", vec![ty(1), fam(2), a(NFTA_NAT_REG_ADDR_MAX, 1)]),
            expr_with("nat", vec![ty(1), fam(2), amin(), amin()]),
            expr_with("nat", vec![ty(1), fam(2), amin(), a(9, 1)]),
            expr_with("nat", vec![ty(1), fam(2), amin(), a(NFTA_NAT_FLAGS, 3)]),
            expr_with("nat", vec![ty(1), fam(2), a(NFTA_NAT_REG_ADDR_MIN, 0)]),
        ];
        for (i, c) in cases.iter().enumerate() {
            let e = NftNat::from_expr(c).expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::DataLoss, "case {i}");
        }
    }

    /// NET-11: DNAT 一式の 7 expr を NEWRULE に積んで復号でき、バッチに載る。
    #[test]
    fn full_dnat_rule_roundtrips() {
        let r1 = NftRegister::REG_1;
        let r2 = NftRegister::REG_2;
        let exprs = [
            NftPayload::ipv4_protocol(r1)
                .expect("p")
                .to_expr()
                .expect("e"),
            NftCmp::eq(r1, NftDataValue::new(&[17]).expect("d"))
                .expect("c")
                .to_expr()
                .expect("e"),
            NftPayload::transport_dport(r1)
                .expect("p")
                .to_expr()
                .expect("e"),
            NftCmp::eq(r1, NftDataValue::new(&18080u16.to_be_bytes()).expect("d"))
                .expect("c")
                .to_expr()
                .expect("e"),
            NftImmediate::ipv4_addr(r1, std::net::Ipv4Addr::new(10, 211, 1, 2))
                .expect("i")
                .to_expr()
                .expect("e"),
            NftImmediate::port(r2, 9080)
                .expect("i")
                .to_expr()
                .expect("e"),
            NftNat::dnat_ipv4(r1, Some(r2))
                .expect("n")
                .to_expr()
                .expect("e"),
        ];
        let mut list = NftRuleExprs::new();
        for e in &exprs {
            list.push(e.clone()).expect("push");
        }
        let rule = RuleCreate::new(
            NftFamily::Ipv4,
            NftName::new("t").expect("n"),
            NftName::new("c").expect("n"),
            list.clone(),
        );
        let bytes = rule.build(1).expect("build").finish().expect("finish");
        let msg = crate::netlink::NlMsgIter::new(&bytes)
            .next()
            .expect("one")
            .expect("msg");
        let e = msg
            .attrs(crate::nftables_batch::NFGENMSG_LEN)
            .expect("attrs")
            .flatten()
            .find(|a| a.attr_type() == crate::nftables_rules::NFTA_RULE_EXPRESSIONS)
            .expect("exprs attr");
        let decoded = NftRuleExprs::decode(e).expect("decode");
        assert_eq!(decoded.exprs(), exprs.as_slice());
        let mut batch = NftBatch::new(1).expect("batch");
        batch.push_with(|seq| rule.build(seq)).expect("push");
    }
}
