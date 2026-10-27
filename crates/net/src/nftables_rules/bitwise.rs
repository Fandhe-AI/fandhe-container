//! nf_tables の `bitwise` expr（レジスタのビット演算）の型付きエンコード
//! （NET-1・NET-11・REPAIR-2・#3060）。
//!
//! `dreg = (sreg & mask) ^ xor`（`NFT_BITWISE_MASK_XOR`）だけを扱う。OS 非依存のコーデックで、
//! ソケット・`unsafe` は持たない。expr 名 `"bitwise"` はコンパイル時定数に固定する
//! （kernel の expr 名によるモジュール自動ロードを呼び出し側から誘導させない）。
//!
//! # 呼び出し元
//!
//! postrouting の masquerade ルール（#3073）が `ip saddr <subnet>/<n>` の照合のため、
//! [`super::NftPayload`]（saddr をレジスタへ load）→ 本 expr（プレフィックスのマスク）→
//! [`super::NftCmp`]（ネットワークアドレスとの比較）の順で [`super::NftRuleExprs`] へ積む。
//! プレフィックス長からのマスク生成などの用途別ヘルパーは呼び出し側（#3073）が持つ。
//!
//! # ワイヤーレイアウト
//!
//! 定数の出典は UAPI `linux/netfilter/nf_tables.h`。kernel は属性順に依存しない。
//!
//! ```text
//! NFTA_EXPR_DATA (nested) {
//!   NFTA_BITWISE_SREG = be32 (データレジスタ)
//!   NFTA_BITWISE_DREG = be32 (データレジスタ)
//!   NFTA_BITWISE_LEN  = be32 (1..=16)
//!   NFTA_BITWISE_OP   = be32 (NFT_BITWISE_MASK_XOR = 0)
//!   NFTA_BITWISE_MASK (nested) { NFTA_DATA_VALUE = LEN バイト }
//!   NFTA_BITWISE_XOR  (nested) { NFTA_DATA_VALUE = LEN バイト }
//! }
//! ```
//!
//! # 信頼境界
//!
//! `LEN` は 1..=16 で、`sreg`・`dreg` のレジスタ容量に収まることを構築時と復号時の両方で検証する
//! （kernel の `nft_parse_register_load` / `_store` 相当）。[`NftBitwise::from_expr`] は
//! `LEN`・レジスタ・`OP` を検証してから `MASK` / `XOR` のデータを復号し、長さが `LEN` と
//! 一致しない値・欠落・重複・未知属性を `DataLoss` で拒否する（kernel 応答も untrusted）。
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - `NFT_BITWISE_LSHIFT` / `RSHIFT` / `AND` / `OR` / `XOR` 形式（`NFTA_BITWISE_DATA`・`SREG2`）。
//!   復号で受けると `DataLoss` にする

use super::{
    NFT_REG_SIZE, NftDataValue, NftExpr, NftExprAttr, NftExprName, NftRegister, data_loss, invalid,
};
use crate::error::NetError;

/// 入力レジスタ（`NFTA_BITWISE_SREG`）。
/// （出典: `include/uapi/linux/netfilter/nf_tables.h`。Linux 7.0.14 の uapi〔linux-libc-dev 7.0.0-38.38〕で値を確認。libc 0.2.189 に無い）
pub const NFTA_BITWISE_SREG: u16 = 1;
/// 出力レジスタ（`NFTA_BITWISE_DREG`）。
/// （出典: `include/uapi/linux/netfilter/nf_tables.h`。Linux 7.0.14 の uapi〔linux-libc-dev 7.0.0-38.38〕で値を確認。libc 0.2.189 に無い）
pub const NFTA_BITWISE_DREG: u16 = 2;
/// 演算対象のバイト長（`NFTA_BITWISE_LEN`）。
/// （出典: `include/uapi/linux/netfilter/nf_tables.h`。Linux 7.0.14 の uapi〔linux-libc-dev 7.0.0-38.38〕で値を確認。libc 0.2.189 に無い）
pub const NFTA_BITWISE_LEN: u16 = 3;
/// AND マスク（ネスト。`NFTA_BITWISE_MASK`）。
/// （出典: `include/uapi/linux/netfilter/nf_tables.h`。Linux 7.0.14 の uapi〔linux-libc-dev 7.0.0-38.38〕で値を確認。libc 0.2.189 に無い）
pub const NFTA_BITWISE_MASK: u16 = 4;
/// XOR 値（ネスト。`NFTA_BITWISE_XOR`）。
/// （出典: `include/uapi/linux/netfilter/nf_tables.h`。Linux 7.0.14 の uapi〔linux-libc-dev 7.0.0-38.38〕で値を確認。libc 0.2.189 に無い）
pub const NFTA_BITWISE_XOR: u16 = 5;
/// 演算種別（`NFTA_BITWISE_OP`）。
/// （出典: `include/uapi/linux/netfilter/nf_tables.h`。Linux 7.0.14 の uapi〔linux-libc-dev 7.0.0-38.38〕で値を確認。libc 0.2.189 に無い）
pub const NFTA_BITWISE_OP: u16 = 6;
/// `(sreg & mask) ^ xor`（`NFT_BITWISE_MASK_XOR`。旧名 `NFT_BITWISE_BOOL`）。
/// （出典: `include/uapi/linux/netfilter/nf_tables.h`。Linux 7.0.14 の uapi〔linux-libc-dev 7.0.0-38.38〕で値を確認。libc 0.2.189 に無い）
pub const NFT_BITWISE_MASK_XOR: u32 = 0;

const BITWISE_EXPR_NAME: &str = "bitwise";

/// `bitwise` expr（mask-xor 形式）。長さは `mask` から導き、不整合を表現できない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftBitwise {
    sreg: NftRegister,
    dreg: NftRegister,
    mask: NftDataValue,
    xor: NftDataValue,
}

/// `len` が両レジスタの容量に収まるか。
fn fits(sreg: NftRegister, dreg: NftRegister, len: usize) -> bool {
    u32::try_from(len).is_ok_and(|n| n <= sreg.capacity() && n <= dreg.capacity())
}

impl NftBitwise {
    /// `dreg = (sreg & mask) ^ xor`。`mask` と `xor` の長さ不一致・レジスタ容量超過は `InvalidArgument`。
    pub fn mask_xor(
        sreg: NftRegister,
        dreg: NftRegister,
        mask: NftDataValue,
        xor: NftDataValue,
    ) -> Result<Self, NetError> {
        if mask.len() != xor.len() {
            return Err(invalid("bitwise mask and xor lengths differ"));
        }
        if !fits(sreg, dreg, mask.len()) {
            return Err(invalid("bitwise length exceeds register capacity"));
        }
        Ok(Self {
            sreg,
            dreg,
            mask,
            xor,
        })
    }

    /// `reg = reg & mask`（xor は同じ長さのゼロ）。
    pub fn and_mask(reg: NftRegister, mask: NftDataValue) -> Result<Self, NetError> {
        let zero = NftDataValue::new(&vec![0u8; mask.len()])?;
        Self::mask_xor(reg, reg, mask, zero)
    }

    /// 入力レジスタ。
    pub fn sreg(&self) -> NftRegister {
        self.sreg
    }

    /// 出力レジスタ。
    pub fn dreg(&self) -> NftRegister {
        self.dreg
    }

    /// AND マスク。
    pub fn mask(&self) -> &NftDataValue {
        &self.mask
    }

    /// XOR 値。
    pub fn xor(&self) -> &NftDataValue {
        &self.xor
    }

    /// 演算対象のバイト長。
    pub fn byte_len(&self) -> usize {
        self.mask.len()
    }

    /// 汎用 [`NftExpr`] へ変換する。
    pub fn to_expr(&self) -> Result<NftExpr, NetError> {
        let len =
            u32::try_from(self.byte_len()).map_err(|_| invalid("bitwise length too large"))?;
        NftExpr::new(
            NftExprName::new(BITWISE_EXPR_NAME)?,
            vec![
                NftExprAttr::u32_be(NFTA_BITWISE_SREG, self.sreg.wire_value())?,
                NftExprAttr::u32_be(NFTA_BITWISE_DREG, self.dreg.wire_value())?,
                NftExprAttr::u32_be(NFTA_BITWISE_LEN, len)?,
                NftExprAttr::u32_be(NFTA_BITWISE_OP, NFT_BITWISE_MASK_XOR)?,
                self.mask.to_attr(NFTA_BITWISE_MASK)?,
                self.xor.to_attr(NFTA_BITWISE_XOR)?,
            ],
        )
    }

    /// 汎用 [`NftExpr`] から復元する。違反はすべて `DataLoss`（fail-closed）。
    ///
    /// 先に `SREG`・`DREG`・`LEN`・`OP` を集めて検証し、データ（`MASK` / `XOR`）の復号はその後に行う。
    pub fn from_expr(expr: &NftExpr) -> Result<Self, NetError> {
        if expr.name().as_str() != BITWISE_EXPR_NAME {
            return Err(data_loss("unexpected expr name"));
        }
        let mut sreg = None;
        let mut dreg = None;
        let mut len = None;
        let mut op = None;
        let mut mask: Option<&NftExprAttr> = None;
        let mut xor: Option<&NftExprAttr> = None;
        for a in expr.data() {
            match a.attr_type() {
                NFTA_BITWISE_SREG | NFTA_BITWISE_DREG | NFTA_BITWISE_LEN | NFTA_BITWISE_OP => {
                    let v = a
                        .as_u32_be()
                        .ok_or_else(|| data_loss("bitwise attribute is not a be32 value"))?;
                    let slot = match a.attr_type() {
                        NFTA_BITWISE_SREG => &mut sreg,
                        NFTA_BITWISE_DREG => &mut dreg,
                        NFTA_BITWISE_LEN => &mut len,
                        _ => &mut op,
                    };
                    if slot.replace(v).is_some() {
                        return Err(data_loss("duplicate attribute in bitwise expr"));
                    }
                }
                NFTA_BITWISE_MASK | NFTA_BITWISE_XOR => {
                    let slot = if a.attr_type() == NFTA_BITWISE_MASK {
                        &mut mask
                    } else {
                        &mut xor
                    };
                    if slot.replace(a).is_some() {
                        return Err(data_loss("duplicate attribute in bitwise expr"));
                    }
                }
                _ => return Err(data_loss("unknown attribute in bitwise expr")),
            }
        }
        let (Some(sreg), Some(dreg), Some(len), Some(op), Some(mask), Some(xor)) =
            (sreg, dreg, len, op, mask, xor)
        else {
            return Err(data_loss("missing attribute in bitwise expr"));
        };
        if op != NFT_BITWISE_MASK_XOR {
            return Err(data_loss("unsupported bitwise op"));
        }
        let len = usize::try_from(len)
            .ok()
            .filter(|n| (1..=NFT_REG_SIZE).contains(n))
            .ok_or_else(|| data_loss("bitwise length out of range"))?;
        let sreg = NftRegister::from_wire(sreg).map_err(|_| data_loss("invalid bitwise sreg"))?;
        let dreg = NftRegister::from_wire(dreg).map_err(|_| data_loss("invalid bitwise dreg"))?;
        if !fits(sreg, dreg, len) {
            return Err(data_loss("bitwise length exceeds register capacity"));
        }
        let mask = NftDataValue::from_attr(mask)?;
        let xor = NftDataValue::from_attr(xor)?;
        if mask.len() != len || xor.len() != len {
            return Err(data_loss("bitwise mask or xor length differs from len"));
        }
        Self::mask_xor(sreg, dreg, mask, xor)
            .map_err(|_| data_loss("bitwise length exceeds register capacity"))
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

    fn dv(b: &[u8]) -> NftDataValue {
        NftDataValue::new(b).expect("data")
    }

    fn u32a(t: u16, v: u32) -> NftExprAttr {
        NftExprAttr::u32_be(t, v).expect("attr")
    }

    fn nest(t: u16, bytes: &[u8]) -> NftExprAttr {
        NftExprAttr::nested(
            t,
            vec![NftExprAttr::bytes(NFTA_DATA_VALUE, bytes.to_vec()).expect("attr")],
        )
        .expect("nested")
    }

    fn bw(name: &str, attrs: Vec<NftExprAttr>) -> NftExpr {
        NftExpr::new(NftExprName::new(name).expect("name"), attrs).expect("expr")
    }

    /// 正常な属性列（sreg=1・dreg=1・len=4・op=0・mask・xor）。
    fn good(mask: &[u8], xor: &[u8]) -> Vec<NftExprAttr> {
        vec![
            u32a(NFTA_BITWISE_SREG, 1),
            u32a(NFTA_BITWISE_DREG, 1),
            u32a(NFTA_BITWISE_LEN, 4),
            u32a(NFTA_BITWISE_OP, 0),
            nest(NFTA_BITWISE_MASK, mask),
            nest(NFTA_BITWISE_XOR, xor),
        ]
    }

    fn put_u32(want: &mut Vec<u8>, t: u16, v: u32) {
        want.extend_from_slice(&8u16.to_ne_bytes());
        want.extend_from_slice(&t.to_ne_bytes());
        want.extend_from_slice(&v.to_be_bytes());
    }

    fn put_nested4(want: &mut Vec<u8>, t: u16, v: [u8; 4]) {
        want.extend_from_slice(&12u16.to_ne_bytes());
        want.extend_from_slice(&(t | 0x8000).to_ne_bytes());
        want.extend_from_slice(&8u16.to_ne_bytes());
        want.extend_from_slice(&NFTA_DATA_VALUE.to_ne_bytes());
        want.extend_from_slice(&v);
    }

    /// NET-11・REPAIR-2: mask-xor の NFTA_EXPR_DATA が具体値で一致する。
    #[test]
    fn wire_layout_of_bitwise_mask_xor() {
        let e = NftBitwise::and_mask(NftRegister::REG_1, dv(&[0xff, 0xff, 0xff, 0x00]))
            .expect("bitwise")
            .to_expr()
            .expect("expr");
        assert_eq!(e.name().as_str(), "bitwise");
        let mut want = Vec::new();
        put_u32(&mut want, NFTA_BITWISE_SREG, 1);
        put_u32(&mut want, NFTA_BITWISE_DREG, 1);
        put_u32(&mut want, NFTA_BITWISE_LEN, 4);
        put_u32(&mut want, NFTA_BITWISE_OP, 0);
        put_nested4(&mut want, NFTA_BITWISE_MASK, [0xff, 0xff, 0xff, 0x00]);
        put_nested4(&mut want, NFTA_BITWISE_XOR, [0, 0, 0, 0]);
        assert_eq!(data_bytes(&e), want);
    }

    /// NET-11: 往復する（sreg ≠ dreg・xor ≠ 0、長さ 1・4・16）。
    #[test]
    fn roundtrip_mask_xor() {
        for len in [1usize, 4, 16] {
            let mask = vec![0xf0u8; len];
            let xor = vec![0x0fu8; len];
            let b =
                NftBitwise::mask_xor(NftRegister::REG_1, NftRegister::REG_2, dv(&mask), dv(&xor))
                    .expect("bitwise");
            assert_eq!(b.byte_len(), len);
            let back = NftBitwise::from_expr(&b.to_expr().expect("expr")).expect("from_expr");
            assert_eq!(back, b);
        }
    }

    /// NET-11・REPAIR-2: 構築時に長さ不一致・容量超過を拒否する。
    #[test]
    fn new_rejects_length_mismatch_and_capacity_overflow() {
        let r15 = NftRegister::reg32(15).expect("reg");
        let r = NftRegister::REG_1;
        let e = NftBitwise::mask_xor(r, r, dv(&[1, 2, 3, 4]), dv(&[1, 2, 3])).expect_err("reject");
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        let five = [1u8, 2, 3, 4, 5];
        for (s, d) in [(r15, r), (r, r15)] {
            let e = NftBitwise::mask_xor(s, d, dv(&five), dv(&five)).expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        }
        let four = [1u8, 2, 3, 4];
        assert!(NftBitwise::mask_xor(r15, r15, dv(&four), dv(&four)).is_ok());
    }

    /// NET-11・REPAIR-2: from_expr は不正な expr を DataLoss で拒否する（fail-closed）。
    #[test]
    fn from_expr_rejects_malformed_exprs() {
        let m = [0xffu8; 4];
        let with = |idx: usize, repl: Option<NftExprAttr>| {
            let mut v = good(&m, &[0; 4]);
            match repl {
                Some(a) => v[idx] = a,
                None => {
                    v.remove(idx);
                }
            }
            bw("bitwise", v)
        };
        let mut dup = good(&m, &[0; 4]);
        dup.push(u32a(NFTA_BITWISE_LEN, 4));
        let mut unknown7 = good(&m, &[0; 4]);
        unknown7.push(u32a(7, 0));
        let mut unknown8 = good(&m, &[0; 4]);
        unknown8.push(u32a(8, 1));
        let mut two_children = good(&m, &[0; 4]);
        two_children[4] = NftExprAttr::nested(
            NFTA_BITWISE_MASK,
            vec![
                NftExprAttr::bytes(NFTA_DATA_VALUE, m.to_vec()).expect("a"),
                NftExprAttr::bytes(NFTA_DATA_VALUE, m.to_vec()).expect("a"),
            ],
        )
        .expect("nested");
        let r13 = NftRegister::reg32(13).expect("reg").wire_value();
        let cases = [
            bw("cmp", good(&m, &[0; 4])),
            with(2, Some(u32a(NFTA_BITWISE_LEN, 0))),
            with(2, Some(u32a(NFTA_BITWISE_LEN, 17))),
            with(2, Some(u32a(NFTA_BITWISE_LEN, 3))),
            with(3, None),
            with(3, Some(u32a(NFTA_BITWISE_OP, 1))),
            with(0, Some(u32a(NFTA_BITWISE_SREG, 0))),
            with(1, Some(u32a(NFTA_BITWISE_DREG, 5))),
            // len=16 を reg32(13)（容量 12）へ書く
            bw(
                "bitwise",
                vec![
                    u32a(NFTA_BITWISE_SREG, 1),
                    u32a(NFTA_BITWISE_DREG, r13),
                    u32a(NFTA_BITWISE_LEN, 16),
                    u32a(NFTA_BITWISE_OP, 0),
                    nest(NFTA_BITWISE_MASK, &[0; 16]),
                    nest(NFTA_BITWISE_XOR, &[0; 16]),
                ],
            ),
            bw("bitwise", dup),
            bw("bitwise", unknown7),
            bw("bitwise", unknown8),
            with(
                4,
                Some(NftExprAttr::bytes(NFTA_BITWISE_MASK, vec![1; 4]).expect("a")),
            ),
            bw("bitwise", two_children),
            with(4, None),
            with(5, None),
            with(5, Some(nest(NFTA_BITWISE_XOR, &[0; 3]))),
        ];
        for (i, c) in cases.iter().enumerate() {
            let e = NftBitwise::from_expr(c).expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::DataLoss, "case {i}");
        }
    }

    /// NET-11: LEN の検証がデータ復号より先に行われる（不正な MASK があっても LEN 側のメッセージで拒否）。
    #[test]
    fn len_is_validated_before_data_decoding() {
        let e = bw(
            "bitwise",
            vec![
                u32a(NFTA_BITWISE_SREG, 1),
                u32a(NFTA_BITWISE_DREG, 1),
                u32a(NFTA_BITWISE_LEN, 17),
                u32a(NFTA_BITWISE_OP, 0),
                NftExprAttr::bytes(NFTA_BITWISE_MASK, vec![1]).expect("a"),
                nest(NFTA_BITWISE_XOR, &[0; 17]),
            ],
        );
        let err = NftBitwise::from_expr(&e).expect_err("reject");
        assert_eq!(err.code(), NetErrorCode::DataLoss);
        assert!(
            err.to_string().contains("bitwise length out of range"),
            "{err}"
        );
    }
}
