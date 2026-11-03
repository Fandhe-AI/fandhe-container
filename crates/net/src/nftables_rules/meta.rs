//! nf_tables の `meta` expr（パケットのメタ情報をレジスタへ load）の型付きエンコード
//! （NET-1・NET-11・REPAIR-2・#3060）。
//!
//! load 形式（`NFTA_META_DREG` + `NFTA_META_KEY`）だけを扱う。OS 非依存のコーデックで、
//! ソケット・`unsafe` は持たない。expr 名 `"meta"` はコンパイル時定数に固定する
//! （kernel の expr 名によるモジュール自動ロードを呼び出し側から誘導させない）。
//!
//! # 呼び出し元
//!
//! postrouting の masquerade ルール（#3073）が `oifname != <bridge>` の照合のため、
//! 本 expr（`OifName` をレジスタへ load）→ [`super::NftCmp`]（`Neq`）の順で
//! [`super::NftRuleExprs`] へ積む。
//!
//! # ワイヤーレイアウト
//!
//! 定数の出典は UAPI `linux/netfilter/nf_tables.h`。kernel は属性順に依存しない。
//!
//! ```text
//! NFTA_EXPR_DATA (nested) {
//!   NFTA_META_KEY  = be32 (NFT_META_*)
//!   NFTA_META_DREG = be32 (データレジスタ)
//! }
//! ```
//!
//! # 信頼境界
//!
//! キーは [`NftMetaKey`] の列挙に限る。キーごとの load 長（[`NftMetaKey::load_len`]）が
//! `dreg` のレジスタ容量に収まることを構築時と復号時の両方で検証する
//! （kernel の `nft_parse_register_store` 相当）。[`NftMeta::from_expr`] は名前違い・属性の
//! 欠落 / 重複 / 未知・範囲外・set 形式を `DataLoss` で拒否する（kernel 応答も untrusted）。
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - set 形式（`NFTA_META_SREG`）。復号で受けると `DataLoss` にする
//! - 上記以外の `NFT_META_*` キー

use super::{
    NftExpr, NftExprAttr, NftExprName, NftRegister, collect_u32_attrs, data_loss, invalid,
};
use crate::error::NetError;

/// 格納先レジスタ（`NFTA_META_DREG`）。
/// （出典: `include/uapi/linux/netfilter/nf_tables.h`。Linux 7.0.14 の uapi〔linux-libc-dev 7.0.0-38.38〕で値を確認。libc 0.2.189 に無い）
pub const NFTA_META_DREG: u16 = 1;
/// meta キー（`NFTA_META_KEY`）。
/// （出典: `include/uapi/linux/netfilter/nf_tables.h`。Linux 7.0.14 の uapi〔linux-libc-dev 7.0.0-38.38〕で値を確認。libc 0.2.189 に無い）
pub const NFTA_META_KEY: u16 = 2;
/// set 形式の入力レジスタ（`NFTA_META_SREG`。本実装では受けない）。
/// （出典: `include/uapi/linux/netfilter/nf_tables.h`。Linux 7.0.14 の uapi〔linux-libc-dev 7.0.0-38.38〕で値を確認。libc 0.2.189 に無い）
pub const NFTA_META_SREG: u16 = 3;

const META_EXPR_NAME: &str = "meta";

/// インターフェース名の load 長（`IFNAMSIZ`）。
const IFNAME_LOAD_LEN: u32 = 16;

/// load できる meta キー（`enum nft_meta_keys` の一部）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftMetaKey {
    /// `NFT_META_IIF`（入力 interface index。4 バイト）。
    Iif,
    /// `NFT_META_OIF`（出力 interface index。4 バイト）。
    Oif,
    /// `NFT_META_IIFNAME`（入力 interface 名。16 バイト）。
    IifName,
    /// `NFT_META_OIFNAME`（出力 interface 名。16 バイト）。
    OifName,
    /// `NFT_META_NFPROTO`（netfilter プロトコルファミリ。1 バイト）。
    NfProto,
    /// `NFT_META_L4PROTO`（L4 プロトコル番号。1 バイト）。
    L4Proto,
}

impl NftMetaKey {
    /// ワイヤー値。
    pub const fn wire_value(self) -> u32 {
        match self {
            Self::Iif => 4,
            Self::Oif => 5,
            Self::IifName => 6,
            Self::OifName => 7,
            Self::NfProto => 15,
            Self::L4Proto => 16,
        }
    }

    /// ワイヤー値から復元する。未対応・範囲外は `InvalidArgument`。
    pub fn from_wire(value: u32) -> Result<Self, NetError> {
        Ok(match value {
            4 => Self::Iif,
            5 => Self::Oif,
            6 => Self::IifName,
            7 => Self::OifName,
            15 => Self::NfProto,
            16 => Self::L4Proto,
            _ => return Err(invalid("unsupported nft meta key")),
        })
    }

    /// キーが `dreg` へ書くバイト長（kernel の `nft_meta_get_init` の `len`）。
    pub const fn load_len(self) -> u32 {
        match self {
            Self::IifName | Self::OifName => IFNAME_LOAD_LEN,
            Self::Iif | Self::Oif => 4,
            Self::NfProto | Self::L4Proto => 1,
        }
    }
}

/// `meta` expr（load 形式）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NftMeta {
    key: NftMetaKey,
    dreg: NftRegister,
}

impl NftMeta {
    /// `dreg` へ `key` を load する。load 長が `dreg` の容量を超える場合は `InvalidArgument`。
    pub fn load(key: NftMetaKey, dreg: NftRegister) -> Result<Self, NetError> {
        if key.load_len() > dreg.capacity() {
            return Err(invalid("meta load exceeds destination register capacity"));
        }
        Ok(Self { key, dreg })
    }

    /// 取得するキー。
    pub fn key(&self) -> NftMetaKey {
        self.key
    }

    /// 格納先レジスタ。
    pub fn dreg(&self) -> NftRegister {
        self.dreg
    }

    /// 汎用 [`NftExpr`] へ変換する。
    pub fn to_expr(&self) -> Result<NftExpr, NetError> {
        NftExpr::new(
            NftExprName::new(META_EXPR_NAME)?,
            vec![
                NftExprAttr::u32_be(NFTA_META_KEY, self.key.wire_value())?,
                NftExprAttr::u32_be(NFTA_META_DREG, self.dreg.wire_value())?,
            ],
        )
    }

    /// 汎用 [`NftExpr`] から復元する。違反はすべて `DataLoss`（fail-closed）。
    pub fn from_expr(expr: &NftExpr) -> Result<Self, NetError> {
        let mut key = None;
        let mut dreg = None;
        for (t, v) in collect_u32_attrs(expr, META_EXPR_NAME)? {
            match t {
                NFTA_META_KEY => key = Some(v),
                NFTA_META_DREG => dreg = Some(v),
                NFTA_META_SREG => return Err(data_loss("meta set form is not supported")),
                _ => return Err(data_loss("unknown attribute in meta expr")),
            }
        }
        let (Some(key), Some(dreg)) = (key, dreg) else {
            return Err(data_loss("missing attribute in meta expr"));
        };
        let key = NftMetaKey::from_wire(key).map_err(|_| data_loss("invalid meta key"))?;
        let dreg = NftRegister::from_wire(dreg).map_err(|_| data_loss("invalid meta dreg"))?;
        Self::load(key, dreg)
            .map_err(|_| data_loss("meta load exceeds destination register capacity"))
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

    fn u32a(t: u16, v: u32) -> NftExprAttr {
        NftExprAttr::u32_be(t, v).expect("attr")
    }

    fn me(name: &str, attrs: Vec<NftExprAttr>) -> NftExpr {
        NftExpr::new(NftExprName::new(name).expect("name"), attrs).expect("expr")
    }

    /// NET-11・REPAIR-2: OifName → REG_1 の NFTA_EXPR_DATA が具体値で一致する。
    #[test]
    fn wire_layout_of_meta_load_oifname() {
        let e = NftMeta::load(NftMetaKey::OifName, NftRegister::REG_1)
            .expect("meta")
            .to_expr()
            .expect("expr");
        assert_eq!(e.name().as_str(), "meta");
        let mut want = Vec::new();
        want.extend_from_slice(&8u16.to_ne_bytes());
        want.extend_from_slice(&NFTA_META_KEY.to_ne_bytes());
        want.extend_from_slice(&[0, 0, 0, 7]);
        want.extend_from_slice(&8u16.to_ne_bytes());
        want.extend_from_slice(&NFTA_META_DREG.to_ne_bytes());
        want.extend_from_slice(&[0, 0, 0, 1]);
        assert_eq!(data_bytes(&e), want);
    }

    /// NET-11: 全キーが往復し、ワイヤー値が具体値と一致する。
    #[test]
    fn roundtrip_all_keys() {
        for (key, wire, len) in [
            (NftMetaKey::Iif, 4, 4),
            (NftMetaKey::Oif, 5, 4),
            (NftMetaKey::IifName, 6, 16),
            (NftMetaKey::OifName, 7, 16),
            (NftMetaKey::NfProto, 15, 1),
            (NftMetaKey::L4Proto, 16, 1),
        ] {
            assert_eq!(key.wire_value(), wire);
            assert_eq!(key.load_len(), len);
            assert_eq!(NftMetaKey::from_wire(wire).expect("key"), key);
            for dreg in [NftRegister::REG_1, NftRegister::REG_4] {
                let m = NftMeta::load(key, dreg).expect("meta");
                let back = NftMeta::from_expr(&m.to_expr().expect("expr")).expect("from_expr");
                assert_eq!(back, m);
            }
        }
        for bad in [0u32, 3, 8, 14, 17] {
            assert_eq!(
                NftMetaKey::from_wire(bad).expect_err("reject").code(),
                NetErrorCode::InvalidArgument
            );
        }
    }

    /// NET-11・REPAIR-2: 構築時にレジスタ容量超過を拒否する。
    #[test]
    fn load_rejects_capacity_overflow() {
        let r13 = NftRegister::reg32(13).expect("reg");
        let r12 = NftRegister::reg32(12).expect("reg");
        let r15 = NftRegister::reg32(15).expect("reg");
        let e = NftMeta::load(NftMetaKey::OifName, r13).expect_err("reject");
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert!(NftMeta::load(NftMetaKey::OifName, r12).is_ok());
        assert!(NftMeta::load(NftMetaKey::OifName, NftRegister::REG_4).is_ok());
        assert!(NftMeta::load(NftMetaKey::NfProto, r15).is_ok());
    }

    /// NET-11・REPAIR-2: from_expr は不正な expr を DataLoss で拒否する（fail-closed）。
    #[test]
    fn from_expr_rejects_malformed_exprs() {
        let key = |v: u32| u32a(NFTA_META_KEY, v);
        let dreg = |v: u32| u32a(NFTA_META_DREG, v);
        let r13 = NftRegister::reg32(13).expect("reg").wire_value();
        let cases = [
            me("cmp", vec![key(7), dreg(1)]),
            me("meta", vec![dreg(1)]),
            me("meta", vec![key(7)]),
            me("meta", vec![key(7), dreg(1), u32a(NFTA_META_SREG, 1)]),
            me("meta", vec![u32a(NFTA_META_SREG, 1), key(7)]),
            me("meta", vec![key(3), dreg(1)]),
            me("meta", vec![key(7), dreg(0)]),
            me("meta", vec![key(7), dreg(r13)]),
            me("meta", vec![key(7), key(7), dreg(1)]),
            me("meta", vec![key(7), dreg(1), u32a(9, 0)]),
            me(
                "meta",
                vec![
                    key(7),
                    dreg(1),
                    NftExprAttr::bytes(NFTA_META_KEY + 8, vec![1]).expect("a"),
                ],
            ),
            me(
                "meta",
                vec![
                    NftExprAttr::bytes(NFTA_META_KEY, vec![1]).expect("a"),
                    dreg(1),
                ],
            ),
        ];
        for (i, c) in cases.iter().enumerate() {
            let e = NftMeta::from_expr(c).expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::DataLoss, "case {i}");
        }
    }

    /// set 形式は専用のメッセージで拒否される。
    #[test]
    fn set_form_is_rejected_with_dedicated_message() {
        let e = me(
            "meta",
            vec![u32a(NFTA_META_KEY, 7), u32a(NFTA_META_SREG, 1)],
        );
        let err = NftMeta::from_expr(&e).expect_err("reject");
        assert!(err.to_string().contains("set form"), "{err}");
    }
}

/// meta キーの `libc` 照合（NET-1・MVM-4・REPAIR-12。#3060。方式は `docs/design/ffi-libc-check.md`）。
/// 宣言と同じく Linux の試験ビルド限定。`libc` に無い `NFTA_META_*` は定義の横に出典を書いた。
#[cfg(all(test, target_os = "linux"))]
mod libc_abi {
    use super::{IFNAME_LOAD_LEN, NftMetaKey};
    use core::ffi::c_int;

    const _: () = {
        libc_const_eq!(NftMetaKey::Iif.wire_value(), u32, libc::NFT_META_IIF, c_int);
        libc_const_eq!(NftMetaKey::Oif.wire_value(), u32, libc::NFT_META_OIF, c_int);
        libc_const_eq!(
            NftMetaKey::IifName.wire_value(),
            u32,
            libc::NFT_META_IIFNAME,
            c_int
        );
        libc_const_eq!(
            NftMetaKey::OifName.wire_value(),
            u32,
            libc::NFT_META_OIFNAME,
            c_int
        );
        libc_const_eq!(
            NftMetaKey::NfProto.wire_value(),
            u32,
            libc::NFT_META_NFPROTO,
            c_int
        );
        libc_const_eq!(
            NftMetaKey::L4Proto.wire_value(),
            u32,
            libc::NFT_META_L4PROTO,
            c_int
        );
        libc_const_eq!(IFNAME_LOAD_LEN, u32, libc::IFNAMSIZ, libc::size_t);
    };

    /// 逆変換 `from_wire` が `libc` の値から全キーを復元できること。
    #[test]
    fn from_wire_accepts_every_libc_meta_key() {
        let keys = [
            (libc::NFT_META_IIF, NftMetaKey::Iif),
            (libc::NFT_META_OIF, NftMetaKey::Oif),
            (libc::NFT_META_IIFNAME, NftMetaKey::IifName),
            (libc::NFT_META_OIFNAME, NftMetaKey::OifName),
            (libc::NFT_META_NFPROTO, NftMetaKey::NfProto),
            (libc::NFT_META_L4PROTO, NftMetaKey::L4Proto),
        ];
        for (raw, expected) in keys {
            assert_eq!(NftMetaKey::from_wire(raw as u32).unwrap(), expected);
        }
    }
}
