//! nf_tables ルールの expr 列（`NFTA_RULE_EXPRESSIONS`）のネスト属性コーデック
//! （TASK-138.1・NET-11・REPAIR-2・MS-8・#309）。
//!
//! `nft` コマンドや汎用 crate に頼らず、`NFT_MSG_NEWRULE` の `NFTA_RULE_EXPRESSIONS` 以下を
//! `NlMsgBuilder` で組み立て、`AttrIter` で復号する OS 非依存のコーデック。ソケット・`unsafe` は持たない。
//! 任意の expr 名・データを運べる汎用層であり、型付き expr（payload / cmp / masq / nat 等）は
//! この層の上に `NftExpr` へ変換する形で載せる。
//!
//! # 呼び出し元
//!
//! NEWRULE 本体（`NFTA_RULE_TABLE` / `NFTA_RULE_CHAIN` の組み立てと送信。TASK-138.2・#310）と
//! nat / ルール削除（TASK-138.3・#311）が、メッセージ組み立て中に [`NftRuleExprs::put_into`] を呼ぶ。
//! 実機結合は TASK-138.4（#312）が担当する。
//!
//! # ワイヤーレイアウト
//!
//! 定数の出典は UAPI `linux/netfilter/nf_tables.h`。文字列属性は NUL 終端付き
//! （libnftnl の `mnl_attr_put_strz` と同じ）。rtattr ヘッダはネイティブ順で、
//! nf_tables の u32 属性値は `__be32` で載せる（`NLA_F_NET_BYTEORDER` は付けない）。
//!
//! ```text
//! NFTA_RULE_EXPRESSIONS (nested) {
//!   NFTA_LIST_ELEM (nested) {
//!     NFTA_EXPR_NAME = "payload\0"
//!     NFTA_EXPR_DATA (nested) { expr 固有属性 ... }   // 空でも常に送出（libnftnl と同じ）
//!   }
//!   NFTA_LIST_ELEM ...   // 最大 NFT_RULE_MAXEXPRS 個
//! }
//! ```
//!
//! # 信頼境界
//!
//! - expr 名は [`NftExprName`] で長さと文字集合（`[a-z0-9_]`）を検証する。kernel は expr 名から
//!   モジュールを自動ロードするため、任意文字列を通さない。エラーに入力値は載せない
//! - 属性ツリーは構築時とデコード時の両方でネスト段数（[`MAX_EXPR_NEST_DEPTH`]）と
//!   expr 件数（[`NFT_RULE_MAXEXPRS`]）を上限検証し、再帰と確保を有界にする
//! - デコードは kernel 応答も untrusted として扱い、重複・欠落・未知属性・想定外フラグを
//!   `DataLoss` で拒否する（fail-closed）
//! - 1 ルールの `NFTA_RULE_EXPRESSIONS` 全体は rtattr の u16 長（65535 バイト）に収まる必要があり、
//!   超過は `InvalidArgument`（ビルダーは巻き戻され半端な属性を残さない）
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - NEWRULE メッセージ本体と型付き expr（TASK-138.2 以降）
//! - `NLA_F_NET_BYTEORDER` 付き属性のデコード（本エンコーダが出さないため現状は拒否。
//!   GETRULE dump 等で必要になった時点で受理を検討する）

use crate::error::{NetError, NetErrorCode};
use crate::netlink::{Attr, MAX_ATTR_PAYLOAD_LEN, NLA_TYPE_MASK, NlMsgBuilder};

/// ルールの expr 列（ネスト。`NFTA_RULE_EXPRESSIONS`）。
pub const NFTA_RULE_EXPRESSIONS: u16 = 4;
/// リスト要素（ネスト。`NFTA_LIST_ELEM`）。
pub const NFTA_LIST_ELEM: u16 = 1;
/// expr 名（`NFTA_EXPR_NAME`）。
pub const NFTA_EXPR_NAME: u16 = 1;
/// expr 固有データ（ネスト。`NFTA_EXPR_DATA`）。
pub const NFTA_EXPR_DATA: u16 = 2;
/// 1 ルールあたりの expr 上限（`NFT_RULE_MAXEXPRS`）。
pub const NFT_RULE_MAXEXPRS: usize = 128;
/// expr 名の最大長（NUL を除く。kernel の `NFTA_EXPR_NAME` policy の `NFT_NAME_MAXLEN - 1`）。
pub const NFT_EXPR_NAME_MAXLEN: usize = 255;
/// `NFTA_EXPR_DATA` 内に許すネスト段数。kernel の最深例（immediate の verdict）は 2 段。
pub const MAX_EXPR_NEST_DEPTH: usize = 4;

fn invalid(msg: impl Into<String>) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

fn data_loss(msg: impl Into<String>) -> NetError {
    NetError::new(NetErrorCode::DataLoss, msg)
}

/// 検証済みの expr 名（`payload`・`masq` 等）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftExprName(String);

impl NftExprName {
    /// 長さ 1..=`NFT_EXPR_NAME_MAXLEN`・文字集合 `[a-z0-9_]` で検証して作る。
    pub fn new(name: &str) -> Result<Self, NetError> {
        if name.is_empty() || name.len() > NFT_EXPR_NAME_MAXLEN {
            return Err(invalid("nft expr name length must be 1..=255 bytes"));
        }
        if !name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
        {
            return Err(invalid("nft expr name contains invalid characters"));
        }
        Ok(Self(name.to_owned()))
    }

    /// 名前の文字列表現。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// expr データ内の属性値。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NftExprValue {
    /// 生ペイロード（非ネスト属性）。
    Bytes(Vec<u8>),
    /// 子属性列（ネスト属性）。
    Nested(Vec<NftExprAttr>),
}

/// expr データ内の 1 属性。種別・長さ・ネスト段数は構築時に検証済み（REPAIR-2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftExprAttr {
    attr_type: u16,
    value: NftExprValue,
}

fn check_type(attr_type: u16) -> Result<(), NetError> {
    if attr_type > NLA_TYPE_MASK {
        return Err(invalid("attribute type out of range"));
    }
    Ok(())
}

impl NftExprAttr {
    /// 生ペイロード属性。長さは `MAX_ATTR_PAYLOAD_LEN` 以下であること。
    pub fn bytes(attr_type: u16, payload: Vec<u8>) -> Result<Self, NetError> {
        check_type(attr_type)?;
        if payload.len() > MAX_ATTR_PAYLOAD_LEN {
            return Err(invalid("attribute payload too large"));
        }
        Ok(Self {
            attr_type,
            value: NftExprValue::Bytes(payload),
        })
    }

    /// `__be32` の u32 属性（nf_tables の数値属性の標準形）。
    pub fn u32_be(attr_type: u16, value: u32) -> Result<Self, NetError> {
        Self::bytes(attr_type, value.to_be_bytes().to_vec())
    }

    /// ネスト属性。ネスト段数が `MAX_EXPR_NEST_DEPTH` を超える場合は `InvalidArgument`。
    pub fn nested(attr_type: u16, children: Vec<NftExprAttr>) -> Result<Self, NetError> {
        check_type(attr_type)?;
        let deepest = children.iter().map(Self::depth).max().unwrap_or(0);
        if deepest >= MAX_EXPR_NEST_DEPTH {
            return Err(invalid("attribute nesting too deep"));
        }
        Ok(Self {
            attr_type,
            value: NftExprValue::Nested(children),
        })
    }

    /// 属性種別（フラグを除く）。
    pub fn attr_type(&self) -> u16 {
        self.attr_type
    }

    /// 属性値。
    pub fn value(&self) -> &NftExprValue {
        &self.value
    }

    /// 4 バイトの生ペイロードを `__be32` として読む。それ以外は `None`。
    pub fn as_u32_be(&self) -> Option<u32> {
        match &self.value {
            NftExprValue::Bytes(b) => <[u8; 4]>::try_from(b.as_slice())
                .ok()
                .map(u32::from_be_bytes),
            NftExprValue::Nested(_) => None,
        }
    }

    /// この属性自身を含むネスト段数（非ネストは 0、ネストは 1 + 子の最大）。
    fn depth(&self) -> usize {
        match &self.value {
            NftExprValue::Bytes(_) => 0,
            NftExprValue::Nested(c) => 1 + c.iter().map(Self::depth).max().unwrap_or(0),
        }
    }

    fn put_into(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        match &self.value {
            NftExprValue::Bytes(p) => b.put_attr(self.attr_type, p),
            NftExprValue::Nested(children) => b.put_nested(self.attr_type, |b| {
                children.iter().try_for_each(|c| c.put_into(b))
            }),
        }
    }

    /// `depth_left` は残りに許すネスト段数。
    fn decode(attr: Attr<'_>, depth_left: usize) -> Result<Self, NetError> {
        if attr.is_net_byteorder() {
            return Err(data_loss("unexpected NLA_F_NET_BYTEORDER in expr data"));
        }
        let attr_type = attr.attr_type();
        if attr.is_nested() {
            let left = depth_left
                .checked_sub(1)
                .ok_or_else(|| data_loss("expr data nesting too deep"))?;
            let mut children = Vec::new();
            for child in attr.nested() {
                children.push(Self::decode(child?, left)?);
            }
            Ok(Self {
                attr_type,
                value: NftExprValue::Nested(children),
            })
        } else {
            Ok(Self {
                attr_type,
                value: NftExprValue::Bytes(attr.payload().to_vec()),
            })
        }
    }
}

/// 1 つの expr（名前と固有データ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftExpr {
    name: NftExprName,
    data: Vec<NftExprAttr>,
}

impl NftExpr {
    /// 名前と固有データ属性列から作る。
    pub fn new(name: NftExprName, data: Vec<NftExprAttr>) -> Self {
        Self { name, data }
    }

    /// expr 名。
    pub fn name(&self) -> &NftExprName {
        &self.name
    }

    /// 固有データ属性列。
    pub fn data(&self) -> &[NftExprAttr] {
        &self.data
    }

    /// `NFTA_LIST_ELEM` として追記する。`NFTA_EXPR_DATA` は空でも送出する。
    pub fn put_into(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        b.put_nested(NFTA_LIST_ELEM, |b| {
            let mut name = Vec::with_capacity(self.name.0.len() + 1);
            name.extend_from_slice(self.name.0.as_bytes());
            name.push(0);
            b.put_attr(NFTA_EXPR_NAME, &name)?;
            b.put_nested(NFTA_EXPR_DATA, |b| {
                self.data.iter().try_for_each(|a| a.put_into(b))
            })
        })
    }

    /// `NFTA_LIST_ELEM` 1 件を復号する。違反は `DataLoss`。
    pub fn decode(attr: Attr<'_>) -> Result<Self, NetError> {
        if attr.attr_type() != NFTA_LIST_ELEM || !attr.is_nested() || attr.is_net_byteorder() {
            return Err(data_loss("expected nested NFTA_LIST_ELEM"));
        }
        let mut name: Option<NftExprName> = None;
        let mut data: Option<Vec<NftExprAttr>> = None;
        for child in attr.nested() {
            let child = child?;
            if child.is_net_byteorder() {
                return Err(data_loss("unexpected NLA_F_NET_BYTEORDER in list elem"));
            }
            match child.attr_type() {
                NFTA_EXPR_NAME => {
                    if name.is_some() || child.is_nested() {
                        return Err(data_loss("duplicate or nested NFTA_EXPR_NAME"));
                    }
                    let raw = child.payload();
                    let s = raw.strip_suffix(&[0]).unwrap_or(raw);
                    let s = std::str::from_utf8(s)
                        .map_err(|_| data_loss("expr name is not valid text"))?;
                    name = Some(NftExprName::new(s).map_err(|_| data_loss("invalid expr name"))?);
                }
                NFTA_EXPR_DATA => {
                    if data.is_some() || !child.is_nested() {
                        return Err(data_loss("duplicate or non-nested NFTA_EXPR_DATA"));
                    }
                    let mut attrs = Vec::new();
                    for a in child.nested() {
                        attrs.push(NftExprAttr::decode(a?, MAX_EXPR_NEST_DEPTH)?);
                    }
                    data = Some(attrs);
                }
                _ => return Err(data_loss("unknown attribute in NFTA_LIST_ELEM")),
            }
        }
        let name = name.ok_or_else(|| data_loss("missing NFTA_EXPR_NAME"))?;
        Ok(Self {
            name,
            data: data.unwrap_or_default(),
        })
    }
}

/// 1 ルール分の expr 列（`NFTA_RULE_EXPRESSIONS`）。件数は `NFT_RULE_MAXEXPRS` 以下。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NftRuleExprs {
    exprs: Vec<NftExpr>,
}

impl NftRuleExprs {
    /// 空の expr 列を作る（kernel は expr なしルールも受け付ける）。
    pub fn new() -> Self {
        Self::default()
    }

    /// expr を末尾に追加する。上限超過は `InvalidArgument` で状態は変わらない。
    pub fn push(&mut self, expr: NftExpr) -> Result<(), NetError> {
        if self.exprs.len() >= NFT_RULE_MAXEXPRS {
            return Err(invalid("too many exprs in rule"));
        }
        self.exprs.push(expr);
        Ok(())
    }

    /// expr 列。
    pub fn exprs(&self) -> &[NftExpr] {
        &self.exprs
    }

    /// expr 件数。
    pub fn len(&self) -> usize {
        self.exprs.len()
    }

    /// expr が 0 件か。
    pub fn is_empty(&self) -> bool {
        self.exprs.is_empty()
    }

    /// `NFTA_RULE_EXPRESSIONS` として追記する。
    pub fn put_into(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        b.put_nested(NFTA_RULE_EXPRESSIONS, |b| {
            self.exprs.iter().try_for_each(|e| e.put_into(b))
        })
    }

    /// `NFTA_RULE_EXPRESSIONS` 属性を復号する。違反は `DataLoss`。
    pub fn decode(attr: Attr<'_>) -> Result<Self, NetError> {
        if attr.attr_type() != NFTA_RULE_EXPRESSIONS || !attr.is_nested() || attr.is_net_byteorder()
        {
            return Err(data_loss("expected nested NFTA_RULE_EXPRESSIONS"));
        }
        let mut exprs = Vec::new();
        for child in attr.nested() {
            if exprs.len() >= NFT_RULE_MAXEXPRS {
                return Err(data_loss("too many exprs in rule"));
            }
            exprs.push(NftExpr::decode(child?)?);
        }
        Ok(Self { exprs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{AttrIter, NLA_F_NESTED, NLA_F_NET_BYTEORDER, NlMsgIter};
    use crate::nftables_batch::{NFGENMSG_LEN, NfGenMsg};

    fn name(s: &str) -> NftExprName {
        NftExprName::new(s).expect("valid name")
    }

    fn expr(n: &str, data: Vec<NftExprAttr>) -> NftExpr {
        NftExpr::new(name(n), data)
    }

    fn new_builder() -> NlMsgBuilder {
        let mut b = NlMsgBuilder::new(0x0a06, 0, 1, 0);
        NfGenMsg::new(2, 0).put_into(&mut b).expect("nfgenmsg");
        b
    }

    fn encode(r: &NftRuleExprs) -> Vec<u8> {
        let mut b = new_builder();
        r.put_into(&mut b).expect("put");
        b.finish().expect("finish")
    }

    /// 組み立てたメッセージの先頭属性を復号する。
    fn decode_msg(bytes: &[u8]) -> Result<NftRuleExprs, NetError> {
        let msg = NlMsgIter::new(bytes).next().expect("one")?;
        let attr = msg.attrs(NFGENMSG_LEN)?.next().expect("attr")?;
        NftRuleExprs::decode(attr)
    }

    fn rule(exprs: Vec<NftExpr>) -> NftRuleExprs {
        let mut r = NftRuleExprs::new();
        for e in exprs {
            r.push(e).expect("push");
        }
        r
    }

    fn u16ne(v: u16) -> [u8; 2] {
        v.to_ne_bytes()
    }

    /// NET-11・REPAIR-2: 単一 expr のワイヤーバイト列が期待どおり。
    #[test]
    fn wire_layout_of_single_masq_expr() {
        let r = rule(vec![expr(
            "masq",
            vec![NftExprAttr::u32_be(1, 0x10).expect("attr")],
        )]);
        let bytes = encode(&r);
        let body = bytes.get(16 + NFGENMSG_LEN..).expect("body");
        let mut data_inner = Vec::new();
        data_inner.extend_from_slice(&u16ne(8));
        data_inner.extend_from_slice(&u16ne(1));
        data_inner.extend_from_slice(&[0, 0, 0, 0x10]);
        // NAME: len 4+5=9 を 12 バイトへパディング
        let mut elem = Vec::new();
        elem.extend_from_slice(&u16ne(9));
        elem.extend_from_slice(&u16ne(NFTA_EXPR_NAME));
        elem.extend_from_slice(b"masq\0");
        elem.extend_from_slice(&[0, 0, 0]);
        elem.extend_from_slice(&u16ne(4 + 8));
        elem.extend_from_slice(&u16ne(NFTA_EXPR_DATA | NLA_F_NESTED));
        elem.extend_from_slice(&data_inner);
        let mut outer_payload = Vec::new();
        outer_payload.extend_from_slice(&u16ne(4 + elem.len() as u16));
        outer_payload.extend_from_slice(&u16ne(NFTA_LIST_ELEM | NLA_F_NESTED));
        outer_payload.extend_from_slice(&elem);
        let mut want = Vec::new();
        want.extend_from_slice(&u16ne(4 + outer_payload.len() as u16));
        want.extend_from_slice(&u16ne(NFTA_RULE_EXPRESSIONS | NLA_F_NESTED));
        want.extend_from_slice(&outer_payload);
        assert_eq!(body, want.as_slice());
    }

    fn deep(levels: usize) -> NftExprAttr {
        let mut a = NftExprAttr::bytes(9, vec![1, 2]).expect("leaf");
        for _ in 0..levels {
            a = NftExprAttr::nested(3, vec![a]).expect("nest");
        }
        a
    }

    /// NET-11: 任意の名前・データの往復。
    #[test]
    fn roundtrip_arbitrary_exprs() {
        let long = "a".repeat(NFT_EXPR_NAME_MAXLEN);
        let cases = vec![
            expr("payload", vec![]),
            expr("x", vec![NftExprAttr::bytes(1, vec![]).expect("a")]),
            expr(
                "a_1",
                vec![
                    NftExprAttr::bytes(2, vec![1, 2, 3]).expect("a"),
                    NftExprAttr::u32_be(3, 0xdead_beef).expect("b"),
                    deep(MAX_EXPR_NEST_DEPTH),
                ],
            ),
            expr(&long, vec![deep(MAX_EXPR_NEST_DEPTH)]),
            expr("n", vec![NftExprAttr::nested(5, vec![]).expect("empty")]),
        ];
        for c in cases {
            let r = rule(vec![c]);
            assert_eq!(decode_msg(&encode(&r)).expect("decode"), r);
        }
    }

    /// 複数 expr の連結: 件数・順序保持。
    #[test]
    fn multiple_exprs_keep_order() {
        let r = rule(vec![
            expr("payload", vec![NftExprAttr::u32_be(1, 1).expect("a")]),
            expr("cmp", vec![NftExprAttr::u32_be(2, 2).expect("a")]),
            expr("masq", vec![]),
        ]);
        let bytes = encode(&r);
        let msg = NlMsgIter::new(&bytes).next().expect("one").expect("msg");
        let outer = msg
            .attrs(NFGENMSG_LEN)
            .expect("it")
            .next()
            .expect("a")
            .expect("a");
        assert_eq!(outer.nested().count(), 3);
        let back = decode_msg(&bytes).expect("decode");
        let names: Vec<&str> = back.exprs().iter().map(|e| e.name().as_str()).collect();
        assert_eq!(names, vec!["payload", "cmp", "masq"]);
        assert_eq!(back, r);
    }

    /// DATA は空でも送出され、欠落入力は空データとして復号される。
    #[test]
    fn empty_data_is_emitted_and_missing_data_is_accepted() {
        let bytes = encode(&rule(vec![expr("masq", vec![])]));
        let msg = NlMsgIter::new(&bytes).next().expect("one").expect("msg");
        let outer = msg
            .attrs(NFGENMSG_LEN)
            .expect("it")
            .next()
            .expect("a")
            .expect("a");
        let elem = outer.nested().next().expect("elem").expect("elem");
        let kids: Vec<_> = elem.nested().map(|a| a.expect("a")).collect();
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[1].attr_type(), NFTA_EXPR_DATA);
        assert!(kids[1].is_nested());
        assert!(kids[1].payload().is_empty());

        let mut b = new_builder();
        b.put_nested(NFTA_RULE_EXPRESSIONS, |b| {
            b.put_nested(NFTA_LIST_ELEM, |b| b.put_attr(NFTA_EXPR_NAME, b"masq\0"))
        })
        .expect("put");
        let r = decode_msg(&b.finish().expect("finish")).expect("decode");
        assert_eq!(r, rule(vec![expr("masq", vec![])]));
    }

    #[test]
    fn expr_name_validation() {
        let too_long = "a".repeat(NFT_EXPR_NAME_MAXLEN + 1);
        for bad in [
            "",
            too_long.as_str(),
            "Masq",
            "a-b",
            "a.b",
            "a\0b",
            "ねっと",
        ] {
            let e = NftExprName::new(bad).expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn attr_construction_validation() {
        let e = NftExprAttr::bytes(NLA_TYPE_MASK + 1, vec![]).expect_err("type");
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        let e = NftExprAttr::bytes(1, vec![0; MAX_ATTR_PAYLOAD_LEN + 1]).expect_err("len");
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        let e = NftExprAttr::nested(1, vec![deep(MAX_EXPR_NEST_DEPTH)]).expect_err("depth");
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(NftExprAttr::u32_be(1, 7).expect("ok").as_u32_be(), Some(7));
    }

    #[test]
    fn expr_count_limit_on_push_and_decode() {
        let mut r = NftRuleExprs::new();
        for _ in 0..NFT_RULE_MAXEXPRS {
            r.push(expr("x", vec![])).expect("push");
        }
        let e = r.push(expr("x", vec![])).expect_err("over");
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(r.len(), NFT_RULE_MAXEXPRS);
        assert_eq!(decode_msg(&encode(&r)).expect("decode"), r);

        let mut b = new_builder();
        b.put_nested(NFTA_RULE_EXPRESSIONS, |b| {
            for _ in 0..=NFT_RULE_MAXEXPRS {
                expr("x", vec![]).put_into(b)?;
            }
            Ok(())
        })
        .expect("put");
        let e = decode_msg(&b.finish().expect("finish")).expect_err("over");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
    }

    #[test]
    fn u16_overflow_rolls_back_builder() {
        let big = || expr("x", vec![NftExprAttr::bytes(1, vec![0; 30000]).expect("a")]);
        let r = rule(vec![big(), big(), big()]);
        let mut b = new_builder();
        let before = new_builder().finish().expect("finish").len();
        let e = r.put_into(&mut b).expect_err("overflow");
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(b.finish().expect("finish").len(), before);
    }

    fn decode_built(
        f: impl FnOnce(&mut NlMsgBuilder) -> Result<(), NetError>,
    ) -> Result<NftRuleExprs, NetError> {
        let mut b = new_builder();
        f(&mut b).expect("build");
        decode_msg(&b.finish().expect("finish"))
    }

    fn elem_of(
        f: impl FnOnce(&mut NlMsgBuilder) -> Result<(), NetError>,
    ) -> Result<NftRuleExprs, NetError> {
        decode_built(|b| b.put_nested(NFTA_RULE_EXPRESSIONS, |b| b.put_nested(NFTA_LIST_ELEM, f)))
    }

    fn assert_data_loss(r: Result<NftRuleExprs, NetError>) {
        assert_eq!(r.expect_err("reject").code(), NetErrorCode::DataLoss);
    }

    fn nest(b: &mut NlMsgBuilder, n: usize) -> Result<(), NetError> {
        if n == 0 {
            return Ok(());
        }
        b.put_nested(1, |b| nest(b, n - 1))
    }

    #[test]
    fn malformed_input_is_rejected() {
        // NAME 欠落
        assert_data_loss(elem_of(|b| b.put_nested(NFTA_EXPR_DATA, |_| Ok(()))));
        // NAME 重複
        assert_data_loss(elem_of(|b| {
            b.put_attr(NFTA_EXPR_NAME, b"a\0")?;
            b.put_attr(NFTA_EXPR_NAME, b"b\0")
        }));
        // DATA 重複
        assert_data_loss(elem_of(|b| {
            b.put_attr(NFTA_EXPR_NAME, b"a\0")?;
            b.put_nested(NFTA_EXPR_DATA, |_| Ok(()))?;
            b.put_nested(NFTA_EXPR_DATA, |_| Ok(()))
        }));
        // DATA が非ネスト
        assert_data_loss(elem_of(|b| {
            b.put_attr(NFTA_EXPR_NAME, b"a\0")?;
            b.put_attr(NFTA_EXPR_DATA, &[])
        }));
        // 未知属性
        assert_data_loss(elem_of(|b| {
            b.put_attr(NFTA_EXPR_NAME, b"a\0")?;
            b.put_attr(9, &[])
        }));
        // 不正な名前
        assert_data_loss(elem_of(|b| b.put_attr(NFTA_EXPR_NAME, b"A-b\0")));
        assert_data_loss(elem_of(|b| b.put_attr(NFTA_EXPR_NAME, b"a\0\0")));
        assert_data_loss(elem_of(|b| b.put_attr(NFTA_EXPR_NAME, &[0xff, 0])));
        // LIST_ELEM が非ネスト
        assert_data_loss(decode_built(|b| {
            b.put_nested(NFTA_RULE_EXPRESSIONS, |b| b.put_attr(NFTA_LIST_ELEM, &[]))
        }));
        // 子が LIST_ELEM 以外
        assert_data_loss(decode_built(|b| {
            b.put_nested(NFTA_RULE_EXPRESSIONS, |b| b.put_nested(7, |_| Ok(())))
        }));
        // 外側属性の種別違い
        assert_data_loss(decode_built(|b| {
            b.put_nested(NFTA_RULE_EXPRESSIONS + 1, |_| Ok(()))
        }));
        // NLA_F_NET_BYTEORDER 付き
        assert_data_loss(elem_of(|b| {
            b.put_attr(NFTA_EXPR_NAME, b"a\0")?;
            b.put_nested(NFTA_EXPR_DATA, |b| {
                b.put_attr_with_flags(1, NLA_F_NET_BYTEORDER, &[0; 4])
            })
        }));
        // 深さ超過
        assert_data_loss(elem_of(|b| {
            b.put_attr(NFTA_EXPR_NAME, b"a\0")?;
            b.put_nested(NFTA_EXPR_DATA, |b| nest(b, MAX_EXPR_NEST_DEPTH + 1))
        }));
        let ok = elem_of(|b| {
            b.put_attr(NFTA_EXPR_NAME, b"a\0")?;
            b.put_nested(NFTA_EXPR_DATA, |b| nest(b, MAX_EXPR_NEST_DEPTH))
        });
        assert_eq!(ok.expect("max depth ok").len(), 1);
    }

    /// 切り詰めた入力でも panic せず Ok / Err を返す。
    #[test]
    fn truncated_prefixes_never_panic() {
        let r = rule(vec![
            expr("payload", vec![deep(2)]),
            expr("masq", vec![NftExprAttr::u32_be(1, 1).expect("a")]),
        ]);
        let bytes = encode(&r);
        let body = bytes.get(16 + NFGENMSG_LEN..).expect("body");
        for n in 0..=body.len() {
            let prefix = body.get(..n).expect("prefix");
            if let Some(Ok(attr)) = AttrIter::new(prefix).next() {
                let _ = NftRuleExprs::decode(attr);
            }
        }
    }
}
