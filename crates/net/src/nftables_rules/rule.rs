//! nf_tables の `NFT_MSG_NEWRULE` メッセージの組み立て（TASK-138.2・NET-11・REPAIR-2・MS-8・#310）。
//!
//! テーブル・チェイン名と expr 列（[`NftRuleExprs`]）から、ルール追加メッセージを `NlMsgBuilder` で
//! 組み立てる OS 非依存のコーデック。ソケット・`unsafe` は持たない。
//!
//! # 呼び出し元
//!
//! `NftBatch::push_with(|seq| rule.build(seq))` で BEGIN / END の間へ積み、
//! `NetlinkNetfilterSocket::send_batch` で送る（`nftables_batch::table_chain` の各メッセージと同じ形）。
//! `build` は `NLM_F_REQUEST | NLM_F_ACK` を付与するためバッチ側の検証を通る。
//!
//! # ワイヤーレイアウト
//!
//! ```text
//! nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE, flags = REQUEST | ACK | CREATE | APPEND
//! nfgenmsg: family = テーブルの NFPROTO_*, version = 0, res_id = 0
//! NFTA_RULE_TABLE = "t\0" | NFTA_RULE_CHAIN = "c\0" | NFTA_RULE_EXPRESSIONS (nested)
//! ```
//!
//! `NLM_F_CREATE | NLM_F_APPEND` は `nft add rule`（チェイン末尾へ追加）と同じ。
//!
//! # 信頼境界
//!
//! テーブル名・チェイン名は [`NftName`] で検証済み。expr 列は件数・サイズを `NftRuleExprs` が
//! 上限検証済みで、rtattr の u16 長を超える場合は `build` が `InvalidArgument` を返す。
//!
//! # ルール削除（TASK-138.3・#311）
//!
//! [`RuleDelete`] は `NFT_MSG_DELRULE` をハンドル指定で組み立てる。kernel はハンドルなしの DELRULE を
//! 「チェイン内（CHAIN のみ）/ テーブル内（TABLE のみ）の全ルール削除」と解釈するため、
//! [`RuleDelete::new`] はハンドルを必須引数にし、ハンドルなしの削除を型で表現できなくする（REPAIR-2）。
//!
//! ```text
//! nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELRULE, flags = REQUEST | ACK
//! NFTA_RULE_TABLE = "t\0" | NFTA_RULE_CHAIN = "c\0" | NFTA_RULE_HANDLE = be64（非ネスト）
//! ```
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - `NFTA_RULE_POSITION`（挿入位置の指定）・`NFTA_RULE_USERDATA`・`NLM_F_REPLACE`
//! - ルールハンドルの取得経路。NEWRULE の `NLM_F_ECHO` 応答の回収と GETRULE dump は、バッチ層
//!   （`nftables_batch`）が範囲内の `NLMSG_ERROR` 以外を `DataLoss` にするため未対応。
//!   [`NftRuleHandle::from_rule_attrs`] は将来その経路から使う純デコーダ

use std::num::NonZeroU64;

use super::NftRuleExprs;
use crate::error::{NetError, NetErrorCode};
use crate::netlink::{AttrIter, NLM_F_APPEND, NLM_F_CREATE, NlMsgBuilder};
use crate::nftables_batch::{
    NFNL_SUBSYS_NFTABLES, NfGenMsg, NftFamily, NftName, nfnl_msg_type, start_nft_request,
};

/// ルール追加（`linux/netfilter/nf_tables.h` の `NFT_MSG_NEWRULE`）。
pub const NFT_MSG_NEWRULE: u8 = 6;
/// ルール削除（`NFT_MSG_DELRULE`）。
pub const NFT_MSG_DELRULE: u8 = 8;
/// ルールのハンドル属性（`NFTA_RULE_HANDLE`。`__be64`）。
pub const NFTA_RULE_HANDLE: u16 = 3;
/// ルールの所属テーブル名属性（`NFTA_RULE_TABLE`）。
pub const NFTA_RULE_TABLE: u16 = 1;
/// ルールの所属チェイン名属性（`NFTA_RULE_CHAIN`）。
pub const NFTA_RULE_CHAIN: u16 = 2;

/// `NFT_MSG_NEWRULE`。チェイン末尾へルールを追加する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCreate {
    family: NftFamily,
    table: NftName,
    chain: NftName,
    exprs: NftRuleExprs,
}

impl RuleCreate {
    /// 追加先のテーブル・チェインと expr 列を指定して作る。
    pub fn new(family: NftFamily, table: NftName, chain: NftName, exprs: NftRuleExprs) -> Self {
        Self {
            family,
            table,
            chain,
            exprs,
        }
    }

    /// `nlmsg_type`。
    pub fn msg_type(&self) -> u16 {
        nfnl_msg_type(NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWRULE)
    }

    /// 操作フラグ（REQUEST / ACK は含めない）。
    pub fn flags(&self) -> u16 {
        NLM_F_CREATE | NLM_F_APPEND
    }

    /// nfgenmsg と属性を `b` へ追記する。
    pub fn encode(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        NfGenMsg::new(self.family.nfproto(), 0).put_into(b)?;
        self.put_attrs(b)
    }

    fn put_attrs(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        self.table.put_into(b, NFTA_RULE_TABLE)?;
        self.chain.put_into(b, NFTA_RULE_CHAIN)?;
        self.exprs.put_into(b)
    }

    /// REQUEST / ACK 付きで組み立てる。`NftBatch::push_with` へそのまま渡せる。
    pub fn build(&self, seq: u32) -> Result<NlMsgBuilder, NetError> {
        let mut b = start_nft_request(NFT_MSG_NEWRULE, self.flags(), self.family, seq)?;
        self.put_attrs(&mut b)?;
        Ok(b)
    }
}
/// kernel が採番するルールのハンドル。0 は無効値で表現できない（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NftRuleHandle(NonZeroU64);

impl NftRuleHandle {
    /// 0 は `InvalidArgument`。
    pub fn new(handle: u64) -> Result<Self, NetError> {
        NonZeroU64::new(handle).map(Self).ok_or_else(|| {
            NetError::new(
                NetErrorCode::InvalidArgument,
                "nft rule handle must be non-zero",
            )
        })
    }

    /// ハンドル値。
    pub fn get(self) -> u64 {
        self.0.get()
    }

    fn put_into(self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        b.put_attr(NFTA_RULE_HANDLE, &self.get().to_be_bytes())
    }

    /// NEWRULE ペイロードの属性列から `NFTA_RULE_HANDLE` をちょうど 1 件取り出す純デコーダ。
    /// 欠落・重複・8 バイト以外・ネスト・`NLA_F_NET_BYTEORDER` 付き・0 は `DataLoss`。
    /// 他の属性（TABLE / CHAIN / EXPRESSIONS / PAD 等）は読み飛ばす。
    pub fn from_rule_attrs(attrs: AttrIter<'_>) -> Result<Self, NetError> {
        let loss = |m: &str| NetError::new(NetErrorCode::DataLoss, m);
        let mut found: Option<u64> = None;
        for a in attrs {
            let a = a?;
            if a.attr_type() != NFTA_RULE_HANDLE {
                continue;
            }
            if found.is_some() {
                return Err(loss("duplicate rule handle attribute"));
            }
            if a.is_nested() || a.is_net_byteorder() {
                return Err(loss("rule handle attribute has unexpected flags"));
            }
            let raw = <[u8; 8]>::try_from(a.payload())
                .map_err(|_| loss("rule handle attribute is not 8 bytes"))?;
            found = Some(u64::from_be_bytes(raw));
        }
        let v = found.ok_or_else(|| loss("rule handle attribute is missing"))?;
        Self::new(v).map_err(|_| loss("rule handle is zero"))
    }
}

/// `NFT_MSG_DELRULE`。ハンドルで 1 ルールだけを削除する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleDelete {
    family: NftFamily,
    table: NftName,
    chain: NftName,
    handle: NftRuleHandle,
}

impl RuleDelete {
    /// 削除対象のテーブル・チェインとハンドルを指定して作る（ハンドルは必須）。
    pub fn new(family: NftFamily, table: NftName, chain: NftName, handle: NftRuleHandle) -> Self {
        Self {
            family,
            table,
            chain,
            handle,
        }
    }

    /// `nlmsg_type`。
    pub fn msg_type(&self) -> u16 {
        nfnl_msg_type(NFNL_SUBSYS_NFTABLES, NFT_MSG_DELRULE)
    }

    /// 操作フラグ（REQUEST / ACK は含めない。削除に追加フラグは不要）。
    pub fn flags(&self) -> u16 {
        0
    }

    /// nfgenmsg と属性を `b` へ追記する。
    pub fn encode(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        NfGenMsg::new(self.family.nfproto(), 0).put_into(b)?;
        self.put_attrs(b)
    }

    fn put_attrs(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        self.table.put_into(b, NFTA_RULE_TABLE)?;
        self.chain.put_into(b, NFTA_RULE_CHAIN)?;
        self.handle.put_into(b)
    }

    /// REQUEST / ACK 付きで組み立てる。`NftBatch::push_with` へそのまま渡せる。
    pub fn build(&self, seq: u32) -> Result<NlMsgBuilder, NetError> {
        let mut b = start_nft_request(NFT_MSG_DELRULE, self.flags(), self.family, seq)?;
        self.put_attrs(&mut b)?;
        Ok(b)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{NFTA_RULE_EXPRESSIONS, NftMasq, NftPayload, NftRegister};
    use super::*;
    use crate::netlink::{NLM_F_ACK, NLM_F_REQUEST, NlMsgIter};
    use crate::nftables_batch::{NFGENMSG_LEN, NftBatch};

    fn name(s: &str) -> NftName {
        NftName::new(s).expect("name")
    }

    fn exprs() -> NftRuleExprs {
        let mut r = NftRuleExprs::new();
        r.push(
            NftPayload::ipv4_saddr(NftRegister::REG_1)
                .expect("p")
                .to_expr()
                .expect("e"),
        )
        .expect("push");
        r.push(NftMasq::new().to_expr().expect("e")).expect("push");
        r
    }

    fn rule() -> RuleCreate {
        RuleCreate::new(NftFamily::Ipv4, name("t"), name("c"), exprs())
    }

    /// NET-11・REPAIR-2: ヘッダー・nfgenmsg・属性順（TABLE → CHAIN → EXPRESSIONS）が具体値で一致する。
    #[test]
    fn wire_layout_of_newrule() {
        let r = rule();
        assert_eq!(r.msg_type(), (10 << 8) | 6);
        assert_eq!(r.flags(), NLM_F_CREATE | NLM_F_APPEND);
        let bytes = r.build(7).expect("build").finish().expect("finish");
        let msg = NlMsgIter::new(&bytes).next().expect("one").expect("msg");
        let h = msg.header();
        assert_eq!(h.msg_type(), 0x0a06);
        assert_eq!(h.seq(), 7);
        assert_eq!(
            h.flags(),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND
        );
        // nfgenmsg: family = NFPROTO_IPV4(2), version = 0, res_id = 0
        assert_eq!(msg.payload().get(..NFGENMSG_LEN), Some(&[2u8, 0, 0, 0][..]));
        let mut it = msg.attrs(NFGENMSG_LEN).expect("attrs");
        let t = it.next().expect("t").expect("ok");
        assert_eq!((t.attr_type(), t.is_nested()), (NFTA_RULE_TABLE, false));
        assert_eq!(t.payload(), b"t\0");
        let c = it.next().expect("c").expect("ok");
        assert_eq!((c.attr_type(), c.is_nested()), (NFTA_RULE_CHAIN, false));
        assert_eq!(c.payload(), b"c\0");
        let e = it.next().expect("e").expect("ok");
        assert_eq!(
            (e.attr_type(), e.is_nested()),
            (NFTA_RULE_EXPRESSIONS, true)
        );
        assert_eq!(NftRuleExprs::decode(e).expect("decode"), exprs());
        assert!(it.next().is_none());
    }

    /// NET-11: encode は build と同じ nfgenmsg・属性を追記する。
    #[test]
    fn encode_matches_build_body() {
        let r = rule();
        let built = r.build(1).expect("build").finish().expect("finish");
        let mut b = NlMsgBuilder::new(r.msg_type(), 0, 1, 0);
        r.encode(&mut b).expect("encode");
        let enc = b.finish().expect("finish");
        assert_eq!(built.get(16..), enc.get(16..));
    }

    /// NET-11: NftBatch::push_with に積めて、バッチ検証（REQUEST / ACK 必須）を通る。
    #[test]
    fn accepted_by_batch() {
        let r = rule();
        let mut batch = NftBatch::new(1).expect("batch");
        batch.push_with(|seq| r.build(seq)).expect("push");
    }

    /// NET-11: 切り詰めた入力でも復号は panic しない。
    #[test]
    fn truncated_prefixes_never_panic() {
        let bytes = rule().build(1).expect("build").finish().expect("finish");
        for n in 0..bytes.len() {
            let prefix = bytes.get(..n).expect("prefix");
            for m in NlMsgIter::new(prefix).flatten() {
                if let Ok(it) = m.attrs(NFGENMSG_LEN) {
                    for a in it.flatten() {
                        let _ = NftRuleExprs::decode(a);
                    }
                }
            }
        }
    }

    fn del() -> RuleDelete {
        RuleDelete::new(
            NftFamily::Ipv4,
            name("t"),
            name("c"),
            NftRuleHandle::new(2).expect("handle"),
        )
    }

    /// NET-11・REPAIR-2: DELRULE のヘッダー・属性順（TABLE → CHAIN → HANDLE be64）が具体値で一致する。
    #[test]
    fn wire_layout_of_delrule() {
        let r = del();
        assert_eq!(r.msg_type(), 0x0a08);
        assert_eq!(r.flags(), 0);
        let bytes = r.build(5).expect("build").finish().expect("finish");
        let msg = NlMsgIter::new(&bytes).next().expect("one").expect("msg");
        let h = msg.header();
        assert_eq!(h.msg_type(), 0x0a08);
        assert_eq!(h.seq(), 5);
        assert_eq!(h.flags(), NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(msg.payload().get(..NFGENMSG_LEN), Some(&[2u8, 0, 0, 0][..]));
        let mut it = msg.attrs(NFGENMSG_LEN).expect("attrs");
        let t = it.next().expect("t").expect("ok");
        assert_eq!((t.attr_type(), t.payload()), (NFTA_RULE_TABLE, &b"t\0"[..]));
        let c = it.next().expect("c").expect("ok");
        assert_eq!((c.attr_type(), c.payload()), (NFTA_RULE_CHAIN, &b"c\0"[..]));
        let hd = it.next().expect("h").expect("ok");
        assert_eq!(hd.attr_type(), NFTA_RULE_HANDLE);
        assert!(!hd.is_nested());
        assert_eq!(hd.payload(), &[0u8, 0, 0, 0, 0, 0, 0, 2][..]);
        assert!(it.next().is_none());
    }

    /// NET-11: encode は build と同じ本体になり、バッチに積める。
    #[test]
    fn delrule_encode_matches_build_and_batches() {
        let r = del();
        let built = r.build(1).expect("build").finish().expect("finish");
        let mut b = NlMsgBuilder::new(r.msg_type(), 0, 1, 0);
        r.encode(&mut b).expect("encode");
        let enc = b.finish().expect("finish");
        assert_eq!(built.get(16..), enc.get(16..));
        let mut batch = NftBatch::new(1).expect("batch");
        batch.push_with(|seq| r.build(seq)).expect("push");
    }

    /// REPAIR-2: ハンドル 0 は表現できず、u64::MAX は往復する。
    #[test]
    fn handle_rejects_zero() {
        assert_eq!(
            NftRuleHandle::new(0).expect_err("reject").code(),
            crate::error::NetErrorCode::InvalidArgument
        );
        assert_eq!(NftRuleHandle::new(u64::MAX).expect("max").get(), u64::MAX);
    }

    fn rule_payload(extra: impl FnOnce(&mut NlMsgBuilder)) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(0x0a06, 0, 1, 0);
        NfGenMsg::new(2, 0).put_into(&mut b).expect("nfgen");
        name("t").put_into(&mut b, NFTA_RULE_TABLE).expect("t");
        name("c").put_into(&mut b, NFTA_RULE_CHAIN).expect("c");
        exprs().put_into(&mut b).expect("exprs");
        extra(&mut b);
        b.finish().expect("finish")
    }

    fn handle_of(bytes: &[u8]) -> Result<NftRuleHandle, NetError> {
        let msg = NlMsgIter::new(bytes).next().expect("one").expect("msg");
        NftRuleHandle::from_rule_attrs(msg.attrs(NFGENMSG_LEN).expect("attrs"))
    }

    /// NET-11: NEWRULE 相当のペイロードからハンドルを取り出せる（他属性は読み飛ばす）。
    #[test]
    fn from_rule_attrs_extracts_handle() {
        let ok = rule_payload(|b| {
            b.put_attr(NFTA_RULE_HANDLE, &7u64.to_be_bytes())
                .expect("h");
            b.put_attr(8, &[0; 4]).expect("pad");
        });
        assert_eq!(handle_of(&ok).expect("handle").get(), 7);
    }

    /// NET-11・REPAIR-2: 欠落・重複・長さ違反・0・ネストは DataLoss。
    #[test]
    fn from_rule_attrs_rejects_malformed() {
        use crate::error::NetErrorCode::DataLoss;
        let missing = rule_payload(|_| {});
        assert_eq!(handle_of(&missing).expect_err("missing").code(), DataLoss);
        let dup = rule_payload(|b| {
            b.put_attr(NFTA_RULE_HANDLE, &1u64.to_be_bytes())
                .expect("h");
            b.put_attr(NFTA_RULE_HANDLE, &2u64.to_be_bytes())
                .expect("h");
        });
        assert_eq!(handle_of(&dup).expect_err("dup").code(), DataLoss);
        let short = rule_payload(|b| b.put_attr(NFTA_RULE_HANDLE, &[0, 0, 0, 1]).expect("h"));
        assert_eq!(handle_of(&short).expect_err("short").code(), DataLoss);
        let zero = rule_payload(|b| b.put_attr(NFTA_RULE_HANDLE, &[0; 8]).expect("h"));
        assert_eq!(handle_of(&zero).expect_err("zero").code(), DataLoss);
        let nested = rule_payload(|b| {
            b.put_nested(NFTA_RULE_HANDLE, |b| b.put_attr(1, &[0; 8]))
                .expect("n");
        });
        assert_eq!(handle_of(&nested).expect_err("nested").code(), DataLoss);
    }

    /// NET-11: 切り詰めた DELRULE でも復号は panic しない。
    #[test]
    fn delrule_truncated_prefixes_never_panic() {
        let bytes = del().build(1).expect("build").finish().expect("finish");
        for n in 0..bytes.len() {
            let prefix = bytes.get(..n).expect("prefix");
            for m in NlMsgIter::new(prefix).flatten() {
                if let Ok(it) = m.attrs(NFGENMSG_LEN) {
                    let _ = NftRuleHandle::from_rule_attrs(it);
                }
            }
        }
    }
}
