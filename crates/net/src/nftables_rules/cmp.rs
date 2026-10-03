//! nf_tables の `cmp` expr（レジスタと定数の比較）の型付きエンコード
//! （TASK-138.3・NET-11・REPAIR-2・MS-8・#311）。
//!
//! 比較が偽ならルールの評価はそこで打ち切られる。DNAT ルールではプロトコル・宛先ポートの照合に使う。
//! OS 非依存のコーデックで、ソケット・`unsafe` は持たない。expr 名 `"cmp"` はコンパイル時定数に固定する
//! （kernel の expr 名によるモジュール自動ロードを呼び出し側から誘導させない）。
//!
//! # 呼び出し元
//!
//! [`super::RuleCreate`] に積む [`super::NftRuleExprs`] へ、[`super::NftPayload`] の直後に
//! `to_expr` の結果を `push` する（TASK-139 のポート公開が利用する）。
//!
//! # ワイヤーレイアウト
//!
//! 定数の出典は UAPI `linux/netfilter/nf_tables.h`。属性順は libnftnl（`nftnl_expr_cmp_build`）に合わせる。
//!
//! ```text
//! NFTA_EXPR_DATA (nested) {
//!   NFTA_CMP_SREG = be32 (データレジスタ)
//!   NFTA_CMP_OP   = be32 (NFT_CMP_EQ=0 .. NFT_CMP_GTE=5)
//!   NFTA_CMP_DATA (nested) { NFTA_DATA_VALUE = 1..=16 バイト }
//! }
//! ```
//!
//! # 信頼境界
//!
//! データ長が `sreg` のレジスタ容量に収まることを構築時に検証する（kernel の `nft_parse_register_load` 相当）。
//! [`NftCmp::from_expr`] は名前違い・属性の欠落 / 重複 / 未知・範囲外を `DataLoss` で拒否する。
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - verdict データとの比較・バイトオーダー変換（呼び出し側が比較対象のバイトオーダーで渡す）

use super::{NftDataValue, NftExpr, NftExprAttr, NftExprName, NftRegister, data_loss, invalid};
use crate::error::NetError;

/// 比較元レジスタ（`NFTA_CMP_SREG`）。
pub const NFTA_CMP_SREG: u16 = 1;
/// 比較演算子（`NFTA_CMP_OP`）。
pub const NFTA_CMP_OP: u16 = 2;
/// 比較対象データ（ネスト。`NFTA_CMP_DATA`）。
pub const NFTA_CMP_DATA: u16 = 3;

const CMP_EXPR_NAME: &str = "cmp";

/// 比較演算子（`enum nft_cmp_ops`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftCmpOp {
    /// `NFT_CMP_EQ`。
    Eq,
    /// `NFT_CMP_NEQ`。
    Neq,
    /// `NFT_CMP_LT`。
    Lt,
    /// `NFT_CMP_LTE`。
    Lte,
    /// `NFT_CMP_GT`。
    Gt,
    /// `NFT_CMP_GTE`。
    Gte,
}

impl NftCmpOp {
    /// ワイヤー値。
    pub const fn wire_value(self) -> u32 {
        match self {
            Self::Eq => 0,
            Self::Neq => 1,
            Self::Lt => 2,
            Self::Lte => 3,
            Self::Gt => 4,
            Self::Gte => 5,
        }
    }

    /// ワイヤー値から復元する。範囲外は `InvalidArgument`。
    pub fn from_wire(value: u32) -> Result<Self, NetError> {
        Ok(match value {
            0 => Self::Eq,
            1 => Self::Neq,
            2 => Self::Lt,
            3 => Self::Lte,
            4 => Self::Gt,
            5 => Self::Gte,
            _ => return Err(invalid("unknown nft cmp op")),
        })
    }
}

/// `cmp` expr。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftCmp {
    sreg: NftRegister,
    op: NftCmpOp,
    data: NftDataValue,
}

impl NftCmp {
    /// データ長が `sreg` の容量を超える場合は `InvalidArgument`。
    pub fn new(sreg: NftRegister, op: NftCmpOp, data: NftDataValue) -> Result<Self, NetError> {
        if u32::try_from(data.len()).map_or(true, |n| n > sreg.capacity()) {
            return Err(invalid("cmp data exceeds source register capacity"));
        }
        Ok(Self { sreg, op, data })
    }

    /// `sreg == data` の比較。
    pub fn eq(sreg: NftRegister, data: NftDataValue) -> Result<Self, NetError> {
        Self::new(sreg, NftCmpOp::Eq, data)
    }

    /// 比較元レジスタ。
    pub fn sreg(&self) -> NftRegister {
        self.sreg
    }

    /// 比較演算子。
    pub fn op(&self) -> NftCmpOp {
        self.op
    }

    /// 比較対象データ。
    pub fn data(&self) -> &NftDataValue {
        &self.data
    }

    /// 汎用 [`NftExpr`] へ変換する。
    pub fn to_expr(&self) -> Result<NftExpr, NetError> {
        NftExpr::new(
            NftExprName::new(CMP_EXPR_NAME)?,
            vec![
                NftExprAttr::u32_be(NFTA_CMP_SREG, self.sreg.wire_value())?,
                NftExprAttr::u32_be(NFTA_CMP_OP, self.op.wire_value())?,
                self.data.to_attr(NFTA_CMP_DATA)?,
            ],
        )
    }

    /// 汎用 [`NftExpr`] から復元する。違反はすべて `DataLoss`（fail-closed）。
    pub fn from_expr(expr: &NftExpr) -> Result<Self, NetError> {
        if expr.name().as_str() != CMP_EXPR_NAME {
            return Err(data_loss("unexpected expr name"));
        }
        let mut sreg = None;
        let mut op = None;
        let mut data = None;
        for a in expr.data() {
            match a.attr_type() {
                NFTA_CMP_SREG if sreg.is_none() => {
                    let v = a
                        .as_u32_be()
                        .ok_or_else(|| data_loss("cmp sreg is not a be32 value"))?;
                    sreg =
                        Some(NftRegister::from_wire(v).map_err(|_| data_loss("invalid cmp sreg"))?);
                }
                NFTA_CMP_OP if op.is_none() => {
                    let v = a
                        .as_u32_be()
                        .ok_or_else(|| data_loss("cmp op is not a be32 value"))?;
                    op = Some(NftCmpOp::from_wire(v).map_err(|_| data_loss("invalid cmp op"))?);
                }
                NFTA_CMP_DATA if data.is_none() => data = Some(NftDataValue::from_attr(a)?),
                NFTA_CMP_SREG | NFTA_CMP_OP | NFTA_CMP_DATA => {
                    return Err(data_loss("duplicate attribute in cmp expr"));
                }
                _ => return Err(data_loss("unknown attribute in cmp expr")),
            }
        }
        match (sreg, op, data) {
            (Some(sreg), Some(op), Some(data)) => Self::new(sreg, op, data)
                .map_err(|_| data_loss("cmp data exceeds source register capacity")),
            _ => Err(data_loss("missing attribute in cmp expr")),
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

    fn dv(b: &[u8]) -> NftDataValue {
        NftDataValue::new(b).expect("data")
    }

    /// NET-11・REPAIR-2: cmp eq の NFTA_EXPR_DATA が具体値で一致する（SREG → OP → DATA(nested)）。
    #[test]
    fn wire_layout_of_cmp_eq() {
        let e = NftCmp::eq(NftRegister::REG_1, dv(&[0x23, 0x78]))
            .expect("cmp")
            .to_expr()
            .expect("expr");
        assert_eq!(e.name().as_str(), "cmp");
        let mut want = Vec::new();
        // NFTA_CMP_SREG = REG_1
        want.extend_from_slice(&8u16.to_ne_bytes());
        want.extend_from_slice(&NFTA_CMP_SREG.to_ne_bytes());
        want.extend_from_slice(&[0, 0, 0, 1]);
        // NFTA_CMP_OP = EQ
        want.extend_from_slice(&8u16.to_ne_bytes());
        want.extend_from_slice(&NFTA_CMP_OP.to_ne_bytes());
        want.extend_from_slice(&[0, 0, 0, 0]);
        // NFTA_CMP_DATA | NLA_F_NESTED { NFTA_DATA_VALUE = 23 78 (+pad) }
        want.extend_from_slice(&12u16.to_ne_bytes());
        want.extend_from_slice(&(NFTA_CMP_DATA | 0x8000).to_ne_bytes());
        want.extend_from_slice(&6u16.to_ne_bytes());
        want.extend_from_slice(&NFTA_DATA_VALUE.to_ne_bytes());
        want.extend_from_slice(&[0x23, 0x78, 0, 0]);
        assert_eq!(data_bytes(&e), want);
    }

    /// NET-11: 6 種の演算子が NftCmp → NftExpr → from_expr で往復する。
    #[test]
    fn roundtrip_all_ops() {
        for (op, wire) in [
            (NftCmpOp::Eq, 0),
            (NftCmpOp::Neq, 1),
            (NftCmpOp::Lt, 2),
            (NftCmpOp::Lte, 3),
            (NftCmpOp::Gt, 4),
            (NftCmpOp::Gte, 5),
        ] {
            assert_eq!(op.wire_value(), wire);
            let c = NftCmp::new(NftRegister::REG_2, op, dv(&[17])).expect("cmp");
            let back = NftCmp::from_expr(&c.to_expr().expect("expr")).expect("from_expr");
            assert_eq!(back, c);
        }
        assert_eq!(
            NftCmpOp::from_wire(6).expect_err("reject").code(),
            NetErrorCode::InvalidArgument
        );
    }

    /// NET-11・REPAIR-2: 構築時にレジスタ容量超過を拒否する。
    #[test]
    fn new_rejects_capacity_overflow() {
        let r15 = NftRegister::reg32(15).expect("reg");
        let e = NftCmp::eq(r15, dv(&[1, 2, 3, 4, 5])).expect_err("reject");
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert!(NftCmp::eq(r15, dv(&[1, 2, 3, 4])).is_ok());
    }

    /// NET-11・REPAIR-2: from_expr は不正な expr を DataLoss で拒否する（fail-closed）。
    #[test]
    fn from_expr_rejects_malformed_exprs() {
        let op = |v: u32| NftExprAttr::u32_be(NFTA_CMP_OP, v).expect("attr");
        let sreg = |v: u32| NftExprAttr::u32_be(NFTA_CMP_SREG, v).expect("attr");
        let data = |children: Vec<NftExprAttr>| {
            NftExprAttr::nested(NFTA_CMP_DATA, children).expect("attr")
        };
        let ok_data = || data(vec![val(&[1])]);
        let cases = [
            expr_with("payload", vec![sreg(1), op(0), ok_data()]),
            expr_with("cmp", vec![sreg(1), sreg(1), op(0), ok_data()]),
            expr_with("cmp", vec![sreg(1), op(0)]),
            expr_with("cmp", vec![op(0), ok_data()]),
            expr_with(
                "cmp",
                vec![
                    sreg(1),
                    op(0),
                    NftExprAttr::bytes(NFTA_CMP_DATA, vec![1]).expect("attr"),
                ],
            ),
            expr_with(
                "cmp",
                vec![
                    sreg(1),
                    op(0),
                    data(vec![NftExprAttr::bytes(2, vec![0; 4]).expect("attr")]),
                ],
            ),
            expr_with(
                "cmp",
                vec![sreg(1), op(0), data(vec![val(&[1]), val(&[2])])],
            ),
            expr_with("cmp", vec![sreg(1), op(6), ok_data()]),
            expr_with("cmp", vec![sreg(0), op(0), ok_data()]),
            expr_with("cmp", vec![sreg(1), op(0), data(vec![val(&[0; 17])])]),
            expr_with("cmp", vec![sreg(1), op(0), ok_data(), reg(9)]),
        ];
        for (i, c) in cases.iter().enumerate() {
            let e = NftCmp::from_expr(c).expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::DataLoss, "case {i}");
        }
    }
}
