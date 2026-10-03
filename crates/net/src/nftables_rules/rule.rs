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
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - `NFTA_RULE_POSITION` / `NFTA_RULE_HANDLE`（挿入位置の指定）・`NFTA_RULE_USERDATA`・`NLM_F_REPLACE`
//! - `NFT_MSG_DELRULE` とハンドル指定の削除（#311）

use super::NftRuleExprs;
use crate::error::NetError;
use crate::netlink::{NLM_F_APPEND, NLM_F_CREATE, NlMsgBuilder};
use crate::nftables_batch::{
    NFNL_SUBSYS_NFTABLES, NfGenMsg, NftFamily, NftName, nfnl_msg_type, start_nft_request,
};

/// ルール追加（`linux/netfilter/nf_tables.h` の `NFT_MSG_NEWRULE`）。
pub const NFT_MSG_NEWRULE: u8 = 6;
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
}
