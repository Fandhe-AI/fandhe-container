//! nf_tables の `masq` expr（masquerade。送信元 NAT）の型付きエンコード
//! （TASK-138.2・NET-11・REPAIR-2・MS-8・#310）。
//!
//! 汎用層（[`NftExpr`]）の上に載る OS 非依存のコーデック。ソケット・`unsafe` は持たない。
//! expr 名 `"masq"` はコンパイル時定数に固定する（kernel の expr 名によるモジュール自動ロードを
//! 呼び出し側から誘導させない）。
//!
//! # 呼び出し元
//!
//! [`super::RuleCreate`] に積む [`super::NftRuleExprs`] へ `to_expr` の結果を `push` する。
//! 送信元アドレス変換を要するコンテナの外向き通信（TASK-139 の network 統合）が利用する。
//!
//! # ワイヤーレイアウト
//!
//! 定数の出典は UAPI `linux/netfilter/nf_tables.h`・`linux/netfilter/nf_nat.h`。
//!
//! ```text
//! NFTA_EXPR_DATA (nested) {
//!   NFTA_MASQ_FLAGS = be32 (NF_NAT_RANGE_* の OR。0 のときは属性ごと省略する。libnftnl / nft と同じ)
//! }
//! ```
//!
//! # 信頼境界
//!
//! [`MasqFlags`] は本モジュールが扱う `NF_NAT_RANGE_*` だけを表現でき、未知ビットは
//! `InvalidArgument`（構築時）/ `DataLoss`（[`NftMasq::from_expr`]）で拒否する。
//! kernel は masq を nat 型 chain の POSTROUTING hook に限って受理する（`nft_masq_validate`）。
//! その検証は kernel 側が行い、ここでは chain との組み合わせを判定しない。
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - ポート範囲指定（`NFTA_MASQ_REG_PROTO_MIN` / `REG_PROTO_MAX`。2 / 3）と、それに付随する
//!   `NF_NAT_RANGE_PROTO_SPECIFIED`
//! - `NF_NAT_RANGE_MAP_IPS` / `PROTO_OFFSET` / `NETMAP`（masq では使わない）

use std::ops::BitOr;

use super::{NftExpr, NftExprAttr, NftExprName, collect_u32_attrs, data_loss, invalid};
use crate::error::NetError;

/// masq のフラグ（`NFTA_MASQ_FLAGS`）。
pub const NFTA_MASQ_FLAGS: u16 = 1;
/// ソースポートをランダム化する（`NF_NAT_RANGE_PROTO_RANDOM`）。
pub const NF_NAT_RANGE_PROTO_RANDOM: u32 = 1 << 2;
/// 同一送信元に同じマッピングを使う（`NF_NAT_RANGE_PERSISTENT`）。
pub const NF_NAT_RANGE_PERSISTENT: u32 = 1 << 3;
/// 完全にランダム化する（`NF_NAT_RANGE_PROTO_RANDOM_FULLY`）。
pub const NF_NAT_RANGE_PROTO_RANDOM_FULLY: u32 = 1 << 4;

const MASQ_EXPR_NAME: &str = "masq";
const KNOWN_FLAGS: u32 =
    NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PERSISTENT | NF_NAT_RANGE_PROTO_RANDOM_FULLY;

/// 既知の `NF_NAT_RANGE_*` ビットだけを持つフラグ集合。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MasqFlags(u32);

impl MasqFlags {
    /// フラグなし。
    pub const NONE: Self = Self(0);
    /// `NF_NAT_RANGE_PROTO_RANDOM`。
    pub const PROTO_RANDOM: Self = Self(NF_NAT_RANGE_PROTO_RANDOM);
    /// `NF_NAT_RANGE_PERSISTENT`。
    pub const PERSISTENT: Self = Self(NF_NAT_RANGE_PERSISTENT);
    /// `NF_NAT_RANGE_PROTO_RANDOM_FULLY`。
    pub const PROTO_RANDOM_FULLY: Self = Self(NF_NAT_RANGE_PROTO_RANDOM_FULLY);

    /// ビット値から作る。未知ビットを含む場合は `InvalidArgument`。
    pub fn from_bits(bits: u32) -> Result<Self, NetError> {
        if bits & !KNOWN_FLAGS != 0 {
            return Err(invalid("unsupported masq flag bits"));
        }
        Ok(Self(bits))
    }

    /// ビット値。
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// フラグが 1 つも立っていないか。
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl BitOr for MasqFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// `masq` expr。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NftMasq {
    flags: MasqFlags,
}

impl NftMasq {
    /// フラグなしの masquerade。
    pub fn new() -> Self {
        Self::default()
    }

    /// フラグ付きの masquerade。
    pub fn with_flags(flags: MasqFlags) -> Self {
        Self { flags }
    }

    /// フラグ。
    pub fn flags(&self) -> MasqFlags {
        self.flags
    }

    /// 汎用 [`NftExpr`] へ変換する。フラグなしのときデータは空（`NFTA_EXPR_DATA` は常に送出される）。
    pub fn to_expr(&self) -> Result<NftExpr, NetError> {
        let data = if self.flags.is_empty() {
            Vec::new()
        } else {
            vec![NftExprAttr::u32_be(NFTA_MASQ_FLAGS, self.flags.bits())?]
        };
        NftExpr::new(NftExprName::new(MASQ_EXPR_NAME)?, data)
    }

    /// 汎用 [`NftExpr`] から復元する。違反はすべて `DataLoss`（fail-closed）。
    pub fn from_expr(expr: &NftExpr) -> Result<Self, NetError> {
        let attrs = collect_u32_attrs(expr, MASQ_EXPR_NAME)?;
        let mut flags = MasqFlags::NONE;
        for (ty, v) in attrs {
            match ty {
                NFTA_MASQ_FLAGS => {
                    flags = MasqFlags::from_bits(v)
                        .map_err(|_| data_loss("unsupported masq flag bits"))?;
                }
                _ => return Err(data_loss("unknown attribute in masq expr")),
            }
        }
        Ok(Self { flags })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NetErrorCode;
    use crate::netlink::NlMsgBuilder;

    fn data_bytes(expr: &NftExpr) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(0, 0, 1, 0);
        for a in expr.data() {
            a.put_into(&mut b).expect("put attr");
        }
        let all = b.finish().expect("finish");
        all.get(16..).expect("body").to_vec()
    }

    /// NET-11: フラグなしの masq は NFTA_EXPR_DATA が空（NFTA_MASQ_FLAGS を出さない）。
    #[test]
    fn no_flags_has_empty_data() {
        let e = NftMasq::new().to_expr().expect("expr");
        assert_eq!(e.name().as_str(), "masq");
        assert!(e.data().is_empty());
        assert_eq!(data_bytes(&e), Vec::<u8>::new());
    }

    /// NET-11: フラグ付きは NFTA_MASQ_FLAGS が be32 の具体値になる。
    #[test]
    fn flags_are_encoded_as_be32() {
        let flags = MasqFlags::PROTO_RANDOM | MasqFlags::PERSISTENT;
        assert_eq!(flags.bits(), 0x0c);
        let e = NftMasq::with_flags(flags).to_expr().expect("expr");
        let mut want = Vec::new();
        want.extend_from_slice(&8u16.to_ne_bytes());
        want.extend_from_slice(&NFTA_MASQ_FLAGS.to_ne_bytes());
        want.extend_from_slice(&[0, 0, 0, 0x0c]);
        assert_eq!(data_bytes(&e), want);
    }

    /// NET-11・REPAIR-2: 未知ビットは構築時に拒否し、既知ビットは受理する。
    #[test]
    fn unknown_flag_bits_are_rejected() {
        for bits in [1, 2, 1 << 5, 1 << 6, 1 << 31, u32::MAX] {
            let e = MasqFlags::from_bits(bits).expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{bits:#x}");
        }
        assert_eq!(MasqFlags::from_bits(0x1c).expect("all").bits(), 0x1c);
        assert_eq!(
            (MasqFlags::PROTO_RANDOM_FULLY | MasqFlags::PERSISTENT).bits(),
            0x18
        );
    }

    /// NET-11: NftMasq → NftExpr → from_expr の往復。
    #[test]
    fn roundtrip_via_expr() {
        for m in [
            NftMasq::new(),
            NftMasq::with_flags(MasqFlags::PROTO_RANDOM_FULLY),
            NftMasq::with_flags(MasqFlags::PROTO_RANDOM | MasqFlags::PERSISTENT),
        ] {
            let back = NftMasq::from_expr(&m.to_expr().expect("expr")).expect("from_expr");
            assert_eq!(back, m);
        }
    }

    fn expr_with(name: &str, attrs: Vec<NftExprAttr>) -> NftExpr {
        NftExpr::new(NftExprName::new(name).expect("name"), attrs).expect("expr")
    }

    /// NET-11・REPAIR-2: from_expr は不正な expr を DataLoss で拒否する（fail-closed）。
    #[test]
    fn from_expr_rejects_malformed_exprs() {
        let flag = |v: u32| NftExprAttr::u32_be(NFTA_MASQ_FLAGS, v).expect("attr");
        let cases = [
            expr_with("payload", vec![]),
            expr_with("masq", vec![flag(4), flag(4)]),
            expr_with("masq", vec![NftExprAttr::u32_be(2, 1).expect("attr")]),
            expr_with("masq", vec![flag(1)]),
            expr_with(
                "masq",
                vec![NftExprAttr::bytes(NFTA_MASQ_FLAGS, vec![4]).expect("attr")],
            ),
            expr_with(
                "masq",
                vec![NftExprAttr::nested(NFTA_MASQ_FLAGS, vec![]).expect("attr")],
            ),
        ];
        for (i, c) in cases.iter().enumerate() {
            let e = NftMasq::from_expr(c).expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::DataLoss, "case {i}");
        }
    }
}
