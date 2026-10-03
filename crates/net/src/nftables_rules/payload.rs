//! nf_tables の `payload` expr（パケットフィールドのレジスタへの load）の型付きエンコード
//! （TASK-138.2・NET-11・REPAIR-2・MS-8・#310）。
//!
//! network header / transport header の `base`・`offset`・`len` を、データレジスタ `dreg` へ読み込む
//! expr を [`NftExpr`] へ変換する OS 非依存のコーデック。ソケット・`unsafe` は持たない。
//! 汎用層（[`NftExpr`]）の上に載り、expr 名 `"payload"` はコンパイル時定数に固定する
//! （kernel は expr 名からモジュールを自動ロードするため、呼び出し側から名前を渡させない）。
//!
//! # 呼び出し元
//!
//! [`super::RuleCreate`] に積む [`super::NftRuleExprs`] へ `to_expr` の結果を `push` する。
//! 後続の cmp / bitwise と組み合わせるパケット照合は #311 と TASK-139（network 統合）が担当する。
//!
//! # ワイヤーレイアウト
//!
//! 定数の出典は UAPI `linux/netfilter/nf_tables.h`。数値属性はすべて `__be32`。
//! 属性順は libnftnl（`nftnl_expr_payload_build`）に合わせる。
//!
//! ```text
//! NFTA_EXPR_DATA (nested) {
//!   NFTA_PAYLOAD_DREG   = be32 (NFT_REG_1..4 または NFT_REG32_00..15)
//!   NFTA_PAYLOAD_BASE   = be32 (NFT_PAYLOAD_NETWORK_HEADER=1 / NFT_PAYLOAD_TRANSPORT_HEADER=2)
//!   NFTA_PAYLOAD_OFFSET = be32 (0..=255)
//!   NFTA_PAYLOAD_LEN    = be32 (1..=255)
//! }
//! ```
//!
//! # 信頼境界
//!
//! 構築時に、kernel（`nft_payload_select_ops`・`nft_validate_register_store`）が拒否する値を
//! `InvalidArgument` で先に弾く: `offset`・`len` は 255 以下、`len` は 1 以上、`len` が `dreg` から見た
//! レジスタ領域（64 バイト）の残りに収まること。verdict レジスタは型で表現できない。
//! [`NftPayload::from_expr`] は kernel 応答など外部由来の expr も untrusted として扱い、
//! 名前違い・属性の欠落 / 重複 / 未知・範囲外を `DataLoss` で拒否する（fail-closed）。
//! エラーメッセージに入力値は載せない。
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - link layer / inner / tunnel header（`NFT_PAYLOAD_LL_HEADER` / `INNER_HEADER` / `TUN_HEADER`）
//! - write 形式（`NFTA_PAYLOAD_SREG`・`CSUM_TYPE` / `CSUM_OFFSET` / `CSUM_FLAGS`）

use super::{NftExpr, NftExprAttr, NftExprName, collect_u32_attrs, data_loss, invalid};
use crate::error::NetError;

/// 読み込み先レジスタ（`NFTA_PAYLOAD_DREG`）。
pub const NFTA_PAYLOAD_DREG: u16 = 1;
/// ヘッダー種別（`NFTA_PAYLOAD_BASE`）。
pub const NFTA_PAYLOAD_BASE: u16 = 2;
/// ヘッダー先頭からのオフセット（`NFTA_PAYLOAD_OFFSET`）。
pub const NFTA_PAYLOAD_OFFSET: u16 = 3;
/// 読み込み長（`NFTA_PAYLOAD_LEN`）。
pub const NFTA_PAYLOAD_LEN: u16 = 4;
/// network header（`NFT_PAYLOAD_NETWORK_HEADER`）。
pub const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
/// transport header（`NFT_PAYLOAD_TRANSPORT_HEADER`）。
pub const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
/// `offset`・`len` の上限（kernel の `nft_parse_u32_check(..., U8_MAX)`）。
pub const NFT_PAYLOAD_MAX_FIELD: u32 = 255;
/// 16 バイトレジスタ `NFT_REG_1`（`NFT_REG_4` まで連番）。
pub const NFT_REG_1: u32 = 1;
/// 32bit レジスタ `NFT_REG32_00`（`NFT_REG32_15` まで連番）。
pub const NFT_REG32_00: u32 = 8;
/// データレジスタ領域の大きさ（バイト）。`NFT_REG_1` / `NFT_REG32_00` が先頭で、
/// kernel の `regs.data`（80 バイト）から verdict 用の先頭 16 バイトを除いた分。
pub const NFT_REG_AREA_BYTES: u32 = 64;

const NFT_REG_4: u32 = 4;
const NFT_REG32_15: u32 = 23;
const PAYLOAD_EXPR_NAME: &str = "payload";

/// データレジスタ。verdict レジスタ（`NFT_REG_VERDICT`）は表現できない（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NftRegister(u32);

impl NftRegister {
    /// `NFT_REG_1`（16 バイト幅の先頭レジスタ）。
    pub const REG_1: Self = Self(1);
    /// `NFT_REG_2`。
    pub const REG_2: Self = Self(2);
    /// `NFT_REG_3`。
    pub const REG_3: Self = Self(3);
    /// `NFT_REG_4`。
    pub const REG_4: Self = Self(4);

    /// 32bit レジスタ `NFT_REG32_00 + index`（`index` は 0..=15）。
    pub fn reg32(index: u8) -> Result<Self, NetError> {
        if index > 15 {
            return Err(invalid("nft reg32 index out of range"));
        }
        Ok(Self(NFT_REG32_00 + u32::from(index)))
    }

    /// ワイヤー値から復元する。verdict（0）・欠番（5..=7）・範囲外は `InvalidArgument`。
    pub fn from_wire(value: u32) -> Result<Self, NetError> {
        if (NFT_REG_1..=NFT_REG_4).contains(&value)
            || (NFT_REG32_00..=NFT_REG32_15).contains(&value)
        {
            Ok(Self(value))
        } else {
            Err(invalid("nft register is not a data register"))
        }
    }

    /// `NFTA_PAYLOAD_DREG` に載せる値。
    pub const fn wire_value(self) -> u32 {
        self.0
    }

    /// レジスタ領域（[`NFT_REG_AREA_BYTES`]）の先頭からのバイト位置。
    const fn byte_offset(self) -> u32 {
        if self.0 <= NFT_REG_4 {
            (self.0 - NFT_REG_1) * 16
        } else {
            (self.0 - NFT_REG32_00) * 4
        }
    }

    /// このレジスタから書き込める最大バイト数。
    pub const fn capacity(self) -> u32 {
        NFT_REG_AREA_BYTES - self.byte_offset()
    }
}

/// payload の基準ヘッダー。他の種別は未実装（REPAIR-3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadBase {
    /// network header（IPv4 / IPv6 ヘッダー）。
    Network,
    /// transport header（TCP / UDP 等）。
    Transport,
}

impl PayloadBase {
    /// `NFT_PAYLOAD_*_HEADER` の値。
    pub const fn wire_value(self) -> u32 {
        match self {
            Self::Network => NFT_PAYLOAD_NETWORK_HEADER,
            Self::Transport => NFT_PAYLOAD_TRANSPORT_HEADER,
        }
    }

    fn from_wire(value: u32) -> Option<Self> {
        match value {
            NFT_PAYLOAD_NETWORK_HEADER => Some(Self::Network),
            NFT_PAYLOAD_TRANSPORT_HEADER => Some(Self::Transport),
            _ => None,
        }
    }
}

/// `payload` expr の load 形式。構築時に kernel が受理する範囲へ検証済み。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NftPayload {
    base: PayloadBase,
    offset: u32,
    len: u32,
    dreg: NftRegister,
}

impl NftPayload {
    /// `base` ヘッダーの `offset` から `len` バイトを `dreg` へ読み込む。
    /// `len` が 0、`offset` / `len` が 255 超、`len` が `dreg` の残り容量超は `InvalidArgument`。
    pub fn load(
        base: PayloadBase,
        offset: u32,
        len: u32,
        dreg: NftRegister,
    ) -> Result<Self, NetError> {
        if len == 0 || len > NFT_PAYLOAD_MAX_FIELD || offset > NFT_PAYLOAD_MAX_FIELD {
            return Err(invalid("payload offset or len out of range"));
        }
        if len > dreg.capacity() {
            return Err(invalid("payload len exceeds register capacity"));
        }
        Ok(Self {
            base,
            offset,
            len,
            dreg,
        })
    }

    /// IPv4 送信元アドレス（network, offset 12, len 4）。
    pub fn ipv4_saddr(dreg: NftRegister) -> Result<Self, NetError> {
        Self::load(PayloadBase::Network, 12, 4, dreg)
    }

    /// IPv4 宛先アドレス（network, offset 16, len 4）。
    pub fn ipv4_daddr(dreg: NftRegister) -> Result<Self, NetError> {
        Self::load(PayloadBase::Network, 16, 4, dreg)
    }

    /// IPv4 のプロトコル番号（network, offset 9, len 1）。
    pub fn ipv4_protocol(dreg: NftRegister) -> Result<Self, NetError> {
        Self::load(PayloadBase::Network, 9, 1, dreg)
    }

    /// TCP / UDP の送信元ポート（transport, offset 0, len 2）。
    pub fn transport_sport(dreg: NftRegister) -> Result<Self, NetError> {
        Self::load(PayloadBase::Transport, 0, 2, dreg)
    }

    /// TCP / UDP の宛先ポート（transport, offset 2, len 2）。
    pub fn transport_dport(dreg: NftRegister) -> Result<Self, NetError> {
        Self::load(PayloadBase::Transport, 2, 2, dreg)
    }

    /// 基準ヘッダー。
    pub fn base(&self) -> PayloadBase {
        self.base
    }

    /// ヘッダー先頭からのオフセット。
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// 読み込み長。
    pub fn byte_len(&self) -> u32 {
        self.len
    }

    /// 読み込み先レジスタ。
    pub fn dreg(&self) -> NftRegister {
        self.dreg
    }

    /// 汎用 [`NftExpr`] へ変換する（属性順は DREG → BASE → OFFSET → LEN）。
    pub fn to_expr(&self) -> Result<NftExpr, NetError> {
        NftExpr::new(
            NftExprName::new(PAYLOAD_EXPR_NAME)?,
            vec![
                NftExprAttr::u32_be(NFTA_PAYLOAD_DREG, self.dreg.wire_value())?,
                NftExprAttr::u32_be(NFTA_PAYLOAD_BASE, self.base.wire_value())?,
                NftExprAttr::u32_be(NFTA_PAYLOAD_OFFSET, self.offset)?,
                NftExprAttr::u32_be(NFTA_PAYLOAD_LEN, self.len)?,
            ],
        )
    }

    /// 汎用 [`NftExpr`] から復元する。違反はすべて `DataLoss`（fail-closed）。
    pub fn from_expr(expr: &NftExpr) -> Result<Self, NetError> {
        let attrs = collect_u32_attrs(expr, PAYLOAD_EXPR_NAME)?;
        let (mut dreg, mut base, mut offset, mut len) = (None, None, None, None);
        for (ty, v) in attrs {
            match ty {
                NFTA_PAYLOAD_DREG => dreg = Some(v),
                NFTA_PAYLOAD_BASE => base = Some(v),
                NFTA_PAYLOAD_OFFSET => offset = Some(v),
                NFTA_PAYLOAD_LEN => len = Some(v),
                _ => return Err(data_loss("unknown attribute in payload expr")),
            }
        }
        let missing = || data_loss("missing attribute in payload expr");
        let dreg = NftRegister::from_wire(dreg.ok_or_else(missing)?)
            .map_err(|_| data_loss("payload dreg is not a data register"))?;
        let base = PayloadBase::from_wire(base.ok_or_else(missing)?)
            .ok_or_else(|| data_loss("unsupported payload base"))?;
        Self::load(
            base,
            offset.ok_or_else(missing)?,
            len.ok_or_else(missing)?,
            dreg,
        )
        .map_err(|_| data_loss("payload attributes out of range"))
    }
}
#[cfg(test)]
mod tests {
    use super::super::{NftExprValue, NftRuleExprs};
    use super::*;
    use crate::error::NetErrorCode;
    use crate::netlink::{NLA_F_NESTED, NlMsgBuilder, NlMsgIter};
    use crate::nftables_batch::{NFGENMSG_LEN, NfGenMsg};

    /// 型付き expr の `NFTA_EXPR_DATA` 内側のワイヤーバイト列（属性列のみ）。
    fn data_bytes(expr: &NftExpr) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(0, 0, 1, 0);
        for a in expr.data() {
            a.put_into(&mut b).expect("put attr");
        }
        let all = b.finish().expect("finish");
        all.get(16..).expect("body").to_vec()
    }

    fn be_attr(ty: u16, v: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&8u16.to_ne_bytes());
        out.extend_from_slice(&ty.to_ne_bytes());
        out.extend_from_slice(&v.to_be_bytes());
        out
    }

    fn want(dreg: u32, base: u32, offset: u32, len: u32) -> Vec<u8> {
        [
            be_attr(NFTA_PAYLOAD_DREG, dreg),
            be_attr(NFTA_PAYLOAD_BASE, base),
            be_attr(NFTA_PAYLOAD_OFFSET, offset),
            be_attr(NFTA_PAYLOAD_LEN, len),
        ]
        .concat()
    }

    /// NET-11・AC1: network header（IPv4 saddr）の base・offset・len がワイヤー上で具体値になる。
    #[test]
    fn network_header_ipv4_saddr_wire_bytes() {
        let e = NftPayload::ipv4_saddr(NftRegister::REG_1)
            .expect("saddr")
            .to_expr()
            .expect("expr");
        assert_eq!(e.name().as_str(), "payload");
        assert_eq!(data_bytes(&e), want(1, 1, 12, 4));
    }

    /// NET-11・AC1: network header の daddr・protocol。
    #[test]
    fn network_header_ipv4_daddr_and_protocol_wire_bytes() {
        let d = NftPayload::ipv4_daddr(NftRegister::REG_1).expect("daddr");
        assert_eq!(data_bytes(&d.to_expr().expect("expr")), want(1, 1, 16, 4));
        let p = NftPayload::ipv4_protocol(NftRegister::REG_1).expect("proto");
        assert_eq!(data_bytes(&p.to_expr().expect("expr")), want(1, 1, 9, 1));
    }

    /// NET-11・AC1: transport header（sport / dport）の base・offset・len。
    #[test]
    fn transport_header_ports_wire_bytes() {
        let s = NftPayload::transport_sport(NftRegister::REG_1).expect("sport");
        assert_eq!(data_bytes(&s.to_expr().expect("expr")), want(1, 2, 0, 2));
        let d = NftPayload::transport_dport(NftRegister::REG_2).expect("dport");
        assert_eq!(data_bytes(&d.to_expr().expect("expr")), want(2, 2, 2, 2));
    }

    /// NET-11: reg32 は NFT_REG32_00(8) 起点のワイヤー値になる。
    #[test]
    fn reg32_wire_values() {
        assert_eq!(NftRegister::reg32(0).expect("r").wire_value(), 8);
        assert_eq!(NftRegister::reg32(15).expect("r").wire_value(), 23);
        assert_eq!(
            NftRegister::reg32(16).expect_err("range").code(),
            NetErrorCode::InvalidArgument
        );
    }

    /// NET-11・REPAIR-2: レジスタ容量の境界。ちょうどは受理し、1 超過は拒否する。
    #[test]
    fn register_capacity_boundaries() {
        assert_eq!(NftRegister::REG_1.capacity(), 64);
        assert_eq!(NftRegister::REG_4.capacity(), 16);
        let r15 = NftRegister::reg32(15).expect("r");
        assert_eq!(r15.capacity(), 4);
        assert!(NftPayload::load(PayloadBase::Network, 0, 4, r15).is_ok());
        assert_eq!(
            NftPayload::load(PayloadBase::Network, 0, 8, r15)
                .expect_err("over")
                .code(),
            NetErrorCode::InvalidArgument
        );
        // IPv6 アドレス（16 バイト）は REG_4 と reg32(12) にちょうど収まり、reg32(13) には収まらない。
        assert!(NftPayload::load(PayloadBase::Network, 8, 16, NftRegister::REG_4).is_ok());
        let r12 = NftRegister::reg32(12).expect("r");
        assert!(NftPayload::load(PayloadBase::Network, 8, 16, r12).is_ok());
        let r13 = NftRegister::reg32(13).expect("r");
        assert!(NftPayload::load(PayloadBase::Network, 8, 16, r13).is_err());
    }

    /// NET-11・REPAIR-2: len / offset の範囲検証。
    #[test]
    fn load_rejects_out_of_range_len_and_offset() {
        let r = NftRegister::REG_1;
        for (off, len) in [(0, 0), (0, 256), (256, 4), (u32::MAX, 1)] {
            let e = NftPayload::load(PayloadBase::Network, off, len, r).expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{off} {len}");
        }
        assert!(NftPayload::load(PayloadBase::Network, 255, 1, r).is_ok());
        assert!(NftPayload::load(PayloadBase::Network, 0, 64, r).is_ok());
        assert!(NftPayload::load(PayloadBase::Network, 0, 65, r).is_err());
    }

    /// NET-11・REPAIR-2: verdict・欠番・範囲外のレジスタは表現できない。
    #[test]
    fn register_from_wire_rejects_non_data_registers() {
        for v in [0, 5, 6, 7, 24, u32::MAX] {
            let e = NftRegister::from_wire(v).expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{v}");
        }
        for v in [1, 4, 8, 23] {
            assert_eq!(NftRegister::from_wire(v).expect("ok").wire_value(), v);
        }
    }

    /// NET-11: payload → NftExpr → NEWRULE 用エンコード → デコード → from_expr で元に戻る。
    #[test]
    fn roundtrip_through_wire() {
        let cases = [
            NftPayload::ipv4_saddr(NftRegister::REG_1).expect("p"),
            NftPayload::transport_dport(NftRegister::reg32(3).expect("r")).expect("p"),
            NftPayload::load(PayloadBase::Network, 255, 1, NftRegister::REG_4).expect("p"),
        ];
        for p in cases {
            let mut rule = NftRuleExprs::new();
            rule.push(p.to_expr().expect("expr")).expect("push");
            let mut b = NlMsgBuilder::new(0x0a06, 0, 1, 0);
            NfGenMsg::new(2, 0).put_into(&mut b).expect("nfgenmsg");
            rule.put_into(&mut b).expect("put");
            let bytes = b.finish().expect("finish");
            let msg = NlMsgIter::new(&bytes).next().expect("one").expect("msg");
            let attr = msg
                .attrs(NFGENMSG_LEN)
                .expect("attrs")
                .next()
                .expect("attr")
                .expect("attr ok");
            let decoded = NftRuleExprs::decode(attr).expect("decode");
            let back =
                NftPayload::from_expr(decoded.exprs().first().expect("expr")).expect("from_expr");
            assert_eq!(back, p);
        }
    }

    fn expr_with(name: &str, attrs: Vec<NftExprAttr>) -> NftExpr {
        NftExpr::new(NftExprName::new(name).expect("name"), attrs).expect("expr")
    }

    fn u32a(ty: u16, v: u32) -> NftExprAttr {
        NftExprAttr::u32_be(ty, v).expect("attr")
    }

    fn full() -> Vec<NftExprAttr> {
        vec![
            u32a(NFTA_PAYLOAD_DREG, 1),
            u32a(NFTA_PAYLOAD_BASE, 1),
            u32a(NFTA_PAYLOAD_OFFSET, 12),
            u32a(NFTA_PAYLOAD_LEN, 4),
        ]
    }

    /// NET-11・REPAIR-2: from_expr は不正な expr を DataLoss で拒否する（fail-closed）。
    #[test]
    fn from_expr_rejects_malformed_exprs() {
        assert!(NftPayload::from_expr(&expr_with("payload", full())).is_ok());
        let mut cases: Vec<NftExpr> = vec![expr_with("masq", full())];
        for skip in 0..4 {
            let mut a = full();
            a.remove(skip);
            cases.push(expr_with("payload", a));
        }
        let mut dup = full();
        dup.push(u32a(NFTA_PAYLOAD_LEN, 4));
        cases.push(expr_with("payload", dup));
        let mut unknown = full();
        unknown.push(u32a(5, 1));
        cases.push(expr_with("payload", unknown));
        let mut bad_len = full();
        bad_len[3] = u32a(NFTA_PAYLOAD_LEN, 0);
        cases.push(expr_with("payload", bad_len));
        let mut bad_base = full();
        bad_base[1] = u32a(NFTA_PAYLOAD_BASE, 0);
        cases.push(expr_with("payload", bad_base));
        let mut bad_reg = full();
        bad_reg[0] = u32a(NFTA_PAYLOAD_DREG, 0);
        cases.push(expr_with("payload", bad_reg));
        let mut short = full();
        short[2] = NftExprAttr::bytes(NFTA_PAYLOAD_OFFSET, vec![0, 12]).expect("attr");
        cases.push(expr_with("payload", short));
        let mut nested = full();
        nested[2] = NftExprAttr::nested(NFTA_PAYLOAD_OFFSET, vec![]).expect("attr");
        assert!(matches!(nested[2].value(), NftExprValue::Nested(_)));
        cases.push(expr_with("payload", nested));
        for (i, c) in cases.iter().enumerate() {
            let e = NftPayload::from_expr(c).expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::DataLoss, "case {i}");
        }
    }

    /// NET-11: expr データ内の u32 属性は非ネストの be32 値である。
    #[test]
    fn data_attrs_are_plain_be32() {
        let e = NftPayload::ipv4_saddr(NftRegister::REG_1)
            .expect("p")
            .to_expr()
            .expect("e");
        for a in e.data() {
            assert_eq!(a.attr_type() & NLA_F_NESTED, 0);
            assert!(a.as_u32_be().is_some());
        }
    }
}
