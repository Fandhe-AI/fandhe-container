//! nf_tables の `immediate` expr（レジスタへ定数を書き込む）の型付きエンコード
//! （TASK-138.3・NET-11・REPAIR-2・MS-8・#311）。
//!
//! `nat` expr は変換先アドレス・ポートをレジスタからしか読めないため、DNAT ルールでは
//! 本 expr で先に定数をレジスタへ置く。OS 非依存のコーデックで、ソケット・`unsafe` は持たない。
//! expr 名 `"immediate"` はコンパイル時定数に固定する。
//!
//! # 呼び出し元
//!
//! [`super::RuleCreate`] に積む [`super::NftRuleExprs`] へ、[`super::NftNat`] の直前に
//! `to_expr` の結果を `push` する（TASK-139 のポート公開が利用する）。
//!
//! # ワイヤーレイアウト
//!
//! 属性順は libnftnl（`nftnl_expr_immediate_build`）に合わせる。
//!
//! ```text
//! NFTA_EXPR_DATA (nested) {
//!   NFTA_IMMEDIATE_DREG = be32 (データレジスタ)
//!   NFTA_IMMEDIATE_DATA (nested) { NFTA_DATA_VALUE = 1..=16 バイト }
//! }
//! ```
//!
//! # 信頼境界
//!
//! データ長が `dreg` のレジスタ容量に収まることを構築時に検証する（kernel の
//! `nft_parse_register_store` 相当）。[`NftImmediate::from_expr`] は違反を `DataLoss` で拒否する。
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - verdict の書き込み（`NFTA_DATA_VERDICT`。`NFT_REG_VERDICT` への immediate）

use std::net::Ipv4Addr;

use super::{NftDataValue, NftExpr, NftExprAttr, NftExprName, NftRegister, data_loss, invalid};
use crate::error::NetError;

/// 書き込み先レジスタ（`NFTA_IMMEDIATE_DREG`）。
pub const NFTA_IMMEDIATE_DREG: u16 = 1;
/// 書き込むデータ（ネスト。`NFTA_IMMEDIATE_DATA`）。
pub const NFTA_IMMEDIATE_DATA: u16 = 2;

const IMMEDIATE_EXPR_NAME: &str = "immediate";

/// `immediate` expr。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftImmediate {
    dreg: NftRegister,
    data: NftDataValue,
}

impl NftImmediate {
    /// データ長が `dreg` の容量を超える場合は `InvalidArgument`。
    pub fn new(dreg: NftRegister, data: NftDataValue) -> Result<Self, NetError> {
        if u32::try_from(data.len()).map_or(true, |n| n > dreg.capacity()) {
            return Err(invalid(
                "immediate data exceeds destination register capacity",
            ));
        }
        Ok(Self { dreg, data })
    }

    /// IPv4 アドレス（4 バイト・ネットワークバイトオーダー）を置く。
    pub fn ipv4_addr(dreg: NftRegister, addr: Ipv4Addr) -> Result<Self, NetError> {
        Self::new(dreg, NftDataValue::new(&addr.octets())?)
    }

    /// ポート番号（2 バイト・ネットワークバイトオーダー）を置く。
    pub fn port(dreg: NftRegister, port: u16) -> Result<Self, NetError> {
        Self::new(dreg, NftDataValue::new(&port.to_be_bytes())?)
    }

    /// 書き込み先レジスタ。
    pub fn dreg(&self) -> NftRegister {
        self.dreg
    }

    /// 書き込むデータ。
    pub fn data(&self) -> &NftDataValue {
        &self.data
    }

    /// 汎用 [`NftExpr`] へ変換する。
    pub fn to_expr(&self) -> Result<NftExpr, NetError> {
        NftExpr::new(
            NftExprName::new(IMMEDIATE_EXPR_NAME)?,
            vec![
                NftExprAttr::u32_be(NFTA_IMMEDIATE_DREG, self.dreg.wire_value())?,
                self.data.to_attr(NFTA_IMMEDIATE_DATA)?,
            ],
        )
    }

    /// 汎用 [`NftExpr`] から復元する。違反はすべて `DataLoss`（fail-closed）。
    pub fn from_expr(expr: &NftExpr) -> Result<Self, NetError> {
        if expr.name().as_str() != IMMEDIATE_EXPR_NAME {
            return Err(data_loss("unexpected expr name"));
        }
        let mut dreg = None;
        let mut data = None;
        for a in expr.data() {
            match a.attr_type() {
                NFTA_IMMEDIATE_DREG if dreg.is_none() => {
                    let v = a
                        .as_u32_be()
                        .ok_or_else(|| data_loss("immediate dreg is not a be32 value"))?;
                    dreg = Some(
                        NftRegister::from_wire(v)
                            .map_err(|_| data_loss("invalid immediate dreg"))?,
                    );
                }
                NFTA_IMMEDIATE_DATA if data.is_none() => {
                    data = Some(NftDataValue::from_attr(a)?);
                }
                NFTA_IMMEDIATE_DREG | NFTA_IMMEDIATE_DATA => {
                    return Err(data_loss("duplicate attribute in immediate expr"));
                }
                _ => return Err(data_loss("unknown attribute in immediate expr")),
            }
        }
        match (dreg, data) {
            (Some(dreg), Some(data)) => Self::new(dreg, data)
                .map_err(|_| data_loss("immediate data exceeds destination register capacity")),
            _ => Err(data_loss("missing attribute in immediate expr")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NetErrorCode;
    use crate::netlink::NlMsgBuilder;
    use crate::nftables_rules::NFTA_DATA_VALUE;

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

    fn reg(v: u32) -> NftExprAttr {
        NftExprAttr::u32_be(1, v).expect("attr")
    }

    fn val(bytes: &[u8]) -> NftExprAttr {
        NftExprAttr::bytes(NFTA_DATA_VALUE, bytes.to_vec()).expect("attr")
    }

    /// NET-11・REPAIR-2: IPv4 アドレスと port の immediate が具体値で一致する。
    #[test]
    fn wire_layout_of_addr_and_port() {
        let addr = NftImmediate::ipv4_addr(NftRegister::REG_1, Ipv4Addr::new(10, 211, 1, 2))
            .expect("imm")
            .to_expr()
            .expect("expr");
        assert_eq!(addr.name().as_str(), "immediate");
        let mut want = Vec::new();
        want.extend_from_slice(&8u16.to_ne_bytes());
        want.extend_from_slice(&NFTA_IMMEDIATE_DREG.to_ne_bytes());
        want.extend_from_slice(&[0, 0, 0, 1]);
        want.extend_from_slice(&12u16.to_ne_bytes());
        want.extend_from_slice(&(NFTA_IMMEDIATE_DATA | 0x8000).to_ne_bytes());
        want.extend_from_slice(&8u16.to_ne_bytes());
        want.extend_from_slice(&NFTA_DATA_VALUE.to_ne_bytes());
        want.extend_from_slice(&[10, 211, 1, 2]);
        assert_eq!(data_bytes(&addr), want);

        let port = NftImmediate::port(NftRegister::REG_2, 9080)
            .expect("imm")
            .to_expr()
            .expect("expr");
        let mut want = Vec::new();
        want.extend_from_slice(&8u16.to_ne_bytes());
        want.extend_from_slice(&NFTA_IMMEDIATE_DREG.to_ne_bytes());
        want.extend_from_slice(&[0, 0, 0, 2]);
        want.extend_from_slice(&12u16.to_ne_bytes());
        want.extend_from_slice(&(NFTA_IMMEDIATE_DATA | 0x8000).to_ne_bytes());
        want.extend_from_slice(&6u16.to_ne_bytes());
        want.extend_from_slice(&NFTA_DATA_VALUE.to_ne_bytes());
        want.extend_from_slice(&[0x23, 0x78, 0, 0]);
        assert_eq!(data_bytes(&port), want);
    }

    /// NET-11: 往復と容量検証。
    #[test]
    fn roundtrip_and_capacity() {
        let i = NftImmediate::port(NftRegister::REG_3, 80).expect("imm");
        let back = NftImmediate::from_expr(&i.to_expr().expect("expr")).expect("from_expr");
        assert_eq!(back, i);
        let r15 = NftRegister::reg32(15).expect("reg");
        let e = NftImmediate::new(r15, NftDataValue::new(&[0; 5]).expect("d")).expect_err("reject");
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert!(NftImmediate::port(r15, 1).is_ok());
    }

    /// NET-11・REPAIR-2: from_expr は不正な expr を DataLoss で拒否する。
    #[test]
    fn from_expr_rejects_malformed_exprs() {
        let dreg = |v: u32| NftExprAttr::u32_be(NFTA_IMMEDIATE_DREG, v).expect("attr");
        let data = |children: Vec<NftExprAttr>| {
            NftExprAttr::nested(NFTA_IMMEDIATE_DATA, children).expect("attr")
        };
        let ok = || data(vec![val(&[1, 2])]);
        let cases = [
            expr_with("cmp", vec![dreg(1), ok()]),
            expr_with("immediate", vec![dreg(1), dreg(1), ok()]),
            expr_with("immediate", vec![dreg(1)]),
            expr_with("immediate", vec![ok()]),
            expr_with("immediate", vec![dreg(0), ok()]),
            expr_with("immediate", vec![dreg(1), data(vec![])]),
            expr_with(
                "immediate",
                vec![
                    dreg(1),
                    data(vec![NftExprAttr::nested(2, vec![]).expect("attr")]),
                ],
            ),
            expr_with("immediate", vec![dreg(1), ok(), reg(9)]),
        ];
        for (i, c) in cases.iter().enumerate() {
            let e = NftImmediate::from_expr(c).expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::DataLoss, "case {i}");
        }
    }
}
