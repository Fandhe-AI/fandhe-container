//! nf_tables の `NEWTABLE` / `NEWCHAIN` / `DELTABLE` メッセージの組み立て
//! （TASK-137.2・NET-11・REPAIR-2・MS-8・#305）。
//!
//! 専用テーブルとチェインの作成・削除を、`nft` コマンドや汎用 crate に頼らず `NlMsgBuilder` で
//! 組み立てる OS 非依存のコーデック。ソケット・`unsafe` は持たない。
//!
//! # 呼び出し元
//!
//! 呼び出し側は `NftBatch::push_with(|seq| msg.build(seq))` で各メッセージを BEGIN / END の間へ積む。
//! `build` は `NLM_F_REQUEST | NLM_F_ACK` を付与するため、バッチ側の検証（REQUEST・ACK 必須）を通る。
//! 送信と ACK 判定は #306（TASK-137.3）、実機結合は `tests/nftables_batch_privileged.rs`（TASK-137.4・#307）が担当する。
//!
//! # ワイヤーレイアウト
//!
//! 文字列属性は NUL 終端付き（libnftnl の `mnl_attr_put_strz` と同じ）。
//! nlmsghdr と rtattr ヘッダはネイティブ順だが、nf_tables の u32 属性（HOOKNUM・PRIORITY）は
//! `__be32` で載せる（`NLA_F_NET_BYTEORDER` は付けない。libnftnl と同じ）。
//!
//! ```text
//! nfgenmsg: family = テーブルの NFPROTO_*, version = 0, res_id = 0
//! NEWTABLE: nfgenmsg | NFTA_TABLE_NAME = "name\0"
//! DELTABLE: nfgenmsg | NFTA_TABLE_NAME = "name\0"
//! NEWCHAIN (regular): nfgenmsg | NFTA_CHAIN_TABLE = "t\0" | NFTA_CHAIN_NAME = "c\0"
//! NEWCHAIN (base):    nfgenmsg | NFTA_CHAIN_TABLE | NFTA_CHAIN_NAME
//!                     | NFTA_CHAIN_HOOK (nested) { NFTA_HOOK_HOOKNUM = be32, NFTA_HOOK_PRIORITY = be32 }
//!                     | NFTA_CHAIN_TYPE = "nat\0"
//! ```
//!
//! # 信頼境界
//!
//! テーブル名・チェイン名は [`NftName`] で長さと文字集合を検証してから載せる（REPAIR-2）。
//! `NFPROTO_UNSPEC`・`NLM_F_REPLACE`（kernel が `EOPNOTSUPP`）・inet 以外の base chain・ingress hook は
//! 型で表現できないか `InvalidArgument` で拒否する（fail-closed）。エラーメッセージに入力値は載せない。
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - `NFTA_TABLE_FLAGS`（dormant / owner）、`NFTA_CHAIN_POLICY` / `FLAGS` / `HANDLE`、handle 指定の削除
//! - `DELCHAIN`・GET 系・`NFT_MSG_DESTROYTABLE`
//! - ARP / Bridge / Netdev の base chain と ingress hook（netdev は `NFTA_HOOK_DEV` が必須）
//! - ルール（TASK-138）

use super::{
    NFNL_SUBSYS_NFTABLES, NFPROTO_ARP, NFPROTO_BRIDGE, NFPROTO_INET, NFPROTO_IPV4, NFPROTO_IPV6,
    NFPROTO_NETDEV, NfGenMsg, nfnl_msg_type,
};
use crate::error::{NetError, NetErrorCode};
use crate::netlink::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NlMsgBuilder};

/// テーブル作成（`linux/netfilter/nf_tables.h` の `NFT_MSG_NEWTABLE`）。
pub const NFT_MSG_NEWTABLE: u8 = 0;
/// テーブル削除（`NFT_MSG_DELTABLE`）。
pub const NFT_MSG_DELTABLE: u8 = 2;
/// チェイン作成（`NFT_MSG_NEWCHAIN`）。
pub const NFT_MSG_NEWCHAIN: u8 = 3;
/// テーブル名属性（`NFTA_TABLE_NAME`）。
pub const NFTA_TABLE_NAME: u16 = 1;
/// チェインの所属テーブル名属性（`NFTA_CHAIN_TABLE`）。
pub const NFTA_CHAIN_TABLE: u16 = 1;
/// チェイン名属性（`NFTA_CHAIN_NAME`）。
pub const NFTA_CHAIN_NAME: u16 = 3;
/// base chain の hook 指定（ネスト。`NFTA_CHAIN_HOOK`）。
pub const NFTA_CHAIN_HOOK: u16 = 4;
/// チェイン種別属性（`NFTA_CHAIN_TYPE`）。
pub const NFTA_CHAIN_TYPE: u16 = 7;
/// hook 番号（`NFTA_HOOK_HOOKNUM`。`__be32`）。
pub const NFTA_HOOK_HOOKNUM: u16 = 1;
/// hook 優先度（`NFTA_HOOK_PRIORITY`。`__be32` 上の符号付き値）。
pub const NFTA_HOOK_PRIORITY: u16 = 2;
/// 名前の最大長（NUL を含む。`NFT_NAME_MAXLEN`）。
pub const NFT_NAME_MAXLEN: usize = 256;
/// filter の標準優先度（`NF_IP_PRI_FILTER`。`linux/netfilter_ipv4.h`）。
pub const NF_IP_PRI_FILTER: i32 = 0;
/// DNAT の標準優先度（`NF_IP_PRI_NAT_DST`）。
pub const NF_IP_PRI_NAT_DST: i32 = -100;
/// SNAT の標準優先度（`NF_IP_PRI_NAT_SRC`）。
pub const NF_IP_PRI_NAT_SRC: i32 = 100;

fn invalid(msg: impl Into<String>) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

/// テーブルの family。`NFPROTO_UNSPEC` は表現できない（fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftFamily {
    /// `NFPROTO_INET`（IPv4 / IPv6 共通）。
    Inet,
    /// `NFPROTO_IPV4`。
    Ipv4,
    /// `NFPROTO_IPV6`。
    Ipv6,
    /// `NFPROTO_ARP`。
    Arp,
    /// `NFPROTO_BRIDGE`。
    Bridge,
    /// `NFPROTO_NETDEV`。
    Netdev,
}

impl NftFamily {
    /// 対応する `NFPROTO_*` 値。
    pub const fn nfproto(self) -> u8 {
        match self {
            Self::Inet => NFPROTO_INET,
            Self::Ipv4 => NFPROTO_IPV4,
            Self::Ipv6 => NFPROTO_IPV6,
            Self::Arp => NFPROTO_ARP,
            Self::Bridge => NFPROTO_BRIDGE,
            Self::Netdev => NFPROTO_NETDEV,
        }
    }

    /// 本モジュールが base chain を組み立てられる family か（inet / ip / ip6 のみ）。
    const fn supports_base_chain(self) -> bool {
        matches!(self, Self::Inet | Self::Ipv4 | Self::Ipv6)
    }
}

/// テーブル名・チェイン名。1〜255 バイト、先頭 `[A-Za-z_]`、以降 `[A-Za-z0-9_.-]`（REPAIR-2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftName(String);

impl NftName {
    /// 検証して作る。違反は `InvalidArgument`（入力値はメッセージに載せない）。
    pub fn new(name: &str) -> Result<Self, NetError> {
        if name.is_empty() || name.len() >= NFT_NAME_MAXLEN {
            return Err(invalid("nft name length must be 1..=255 bytes"));
        }
        let mut chars = name.bytes();
        let first_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_');
        let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'));
        if !first_ok || !rest_ok {
            return Err(invalid("nft name contains invalid characters"));
        }
        Ok(Self(name.to_owned()))
    }

    /// 名前の文字列表現。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// NUL 終端付きでワイヤーに載せる。
    fn put_into(&self, b: &mut NlMsgBuilder, attr_type: u16) -> Result<(), NetError> {
        let mut bytes = Vec::with_capacity(self.0.len() + 1);
        bytes.extend_from_slice(self.0.as_bytes());
        bytes.push(0);
        b.put_attr(attr_type, &bytes)
    }
}

/// base chain の hook（inet / ip / ip6 共通。ingress は含めない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfInetHook {
    /// `NF_INET_PRE_ROUTING`。
    PreRouting,
    /// `NF_INET_LOCAL_IN`。
    LocalIn,
    /// `NF_INET_FORWARD`。
    Forward,
    /// `NF_INET_LOCAL_OUT`。
    LocalOut,
    /// `NF_INET_POST_ROUTING`。
    PostRouting,
}

impl NfInetHook {
    /// `NF_INET_*` の値（`linux/netfilter.h`）。
    pub const fn value(self) -> u32 {
        match self {
            Self::PreRouting => 0,
            Self::LocalIn => 1,
            Self::Forward => 2,
            Self::LocalOut => 3,
            Self::PostRouting => 4,
        }
    }
}

/// base chain のチェイン種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainType {
    /// `"filter"`。
    Filter,
    /// `"nat"`。
    Nat,
    /// `"route"`。
    Route,
}

impl ChainType {
    /// kernel が受け付ける種別名。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Filter => "filter",
            Self::Nat => "nat",
            Self::Route => "route",
        }
    }
}

/// base chain の指定（hook・priority・種別）。組み合わせの妥当性は kernel が判定する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseChain {
    /// チェイン種別。
    pub chain_type: ChainType,
    /// 接続先 hook。
    pub hook: NfInetHook,
    /// 優先度（小さいほど先に評価）。
    pub priority: i32,
}

/// 共通の組み立て手順。`op_flags` は操作フラグのみで、REQUEST / ACK はここで付ける。
fn start(msg: u8, op_flags: u16, family: NftFamily, seq: u32) -> Result<NlMsgBuilder, NetError> {
    let mut b = NlMsgBuilder::new(
        nfnl_msg_type(NFNL_SUBSYS_NFTABLES, msg),
        op_flags | NLM_F_REQUEST | NLM_F_ACK,
        seq,
        0,
    );
    NfGenMsg::new(family.nfproto(), 0).put_into(&mut b)?;
    Ok(b)
}

fn create_flags(exclusive: bool) -> u16 {
    if exclusive {
        NLM_F_CREATE | NLM_F_EXCL
    } else {
        NLM_F_CREATE
    }
}

/// `NFT_MSG_NEWTABLE`。既定は `nft add table` 相当（既存なら成功）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableCreate {
    family: NftFamily,
    name: NftName,
    exclusive: bool,
}

impl TableCreate {
    /// `NLM_F_CREATE` のみで作る。
    pub fn new(family: NftFamily, name: NftName) -> Self {
        Self {
            family,
            name,
            exclusive: false,
        }
    }

    /// `NLM_F_EXCL` を加える（`nft create table` 相当。既存なら `EEXIST`）。
    pub fn exclusive(mut self) -> Self {
        self.exclusive = true;
        self
    }

    /// `nlmsg_type`。
    pub fn msg_type(&self) -> u16 {
        nfnl_msg_type(NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWTABLE)
    }

    /// 操作フラグ（REQUEST / ACK は含めない）。
    pub fn flags(&self) -> u16 {
        create_flags(self.exclusive)
    }

    /// nfgenmsg と属性を `b` へ追記する。
    pub fn encode(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        NfGenMsg::new(self.family.nfproto(), 0).put_into(b)?;
        self.name.put_into(b, NFTA_TABLE_NAME)
    }

    /// REQUEST / ACK 付きで組み立てる。`NftBatch::push_with` へそのまま渡せる。
    pub fn build(&self, seq: u32) -> Result<NlMsgBuilder, NetError> {
        let mut b = start(NFT_MSG_NEWTABLE, self.flags(), self.family, seq)?;
        self.name.put_into(&mut b, NFTA_TABLE_NAME)?;
        Ok(b)
    }
}

/// `NFT_MSG_DELTABLE`。専用テーブル名を指定して削除する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDelete {
    family: NftFamily,
    name: NftName,
}

impl TableDelete {
    /// 削除対象を指定して作る。
    pub fn new(family: NftFamily, name: NftName) -> Self {
        Self { family, name }
    }

    /// `nlmsg_type`。
    pub fn msg_type(&self) -> u16 {
        nfnl_msg_type(NFNL_SUBSYS_NFTABLES, NFT_MSG_DELTABLE)
    }

    /// 操作フラグ（なし）。
    pub fn flags(&self) -> u16 {
        0
    }

    /// nfgenmsg と属性を `b` へ追記する。
    pub fn encode(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        NfGenMsg::new(self.family.nfproto(), 0).put_into(b)?;
        self.name.put_into(b, NFTA_TABLE_NAME)
    }

    /// REQUEST / ACK 付きで組み立てる。
    pub fn build(&self, seq: u32) -> Result<NlMsgBuilder, NetError> {
        let mut b = start(NFT_MSG_DELTABLE, self.flags(), self.family, seq)?;
        self.name.put_into(&mut b, NFTA_TABLE_NAME)?;
        Ok(b)
    }
}

/// `NFT_MSG_NEWCHAIN`。base chain（hook あり）と通常の chain（hook なし）を表す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainCreate {
    family: NftFamily,
    table: NftName,
    name: NftName,
    base: Option<BaseChain>,
    exclusive: bool,
}

impl ChainCreate {
    /// 通常の chain（hook なし。jump / goto 先）。
    pub fn regular(family: NftFamily, table: NftName, name: NftName) -> Self {
        Self {
            family,
            table,
            name,
            base: None,
            exclusive: false,
        }
    }

    /// base chain。family が inet / ip / ip6 以外なら `InvalidArgument`。
    pub fn base(
        family: NftFamily,
        table: NftName,
        name: NftName,
        base: BaseChain,
    ) -> Result<Self, NetError> {
        if !family.supports_base_chain() {
            return Err(invalid(
                "base chain supports only inet, ip and ip6 families",
            ));
        }
        Ok(Self {
            family,
            table,
            name,
            base: Some(base),
            exclusive: false,
        })
    }

    /// `NLM_F_EXCL` を加える。
    pub fn exclusive(mut self) -> Self {
        self.exclusive = true;
        self
    }

    /// `nlmsg_type`。
    pub fn msg_type(&self) -> u16 {
        nfnl_msg_type(NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWCHAIN)
    }

    /// 操作フラグ（REQUEST / ACK は含めない）。
    pub fn flags(&self) -> u16 {
        create_flags(self.exclusive)
    }

    /// nfgenmsg と属性を `b` へ追記する。属性順は libnftnl に倣う（TABLE → NAME → HOOK → TYPE）。
    pub fn encode(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        NfGenMsg::new(self.family.nfproto(), 0).put_into(b)?;
        self.put_attrs(b)
    }

    fn put_attrs(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        self.table.put_into(b, NFTA_CHAIN_TABLE)?;
        self.name.put_into(b, NFTA_CHAIN_NAME)?;
        if let Some(base) = &self.base {
            b.put_nested(NFTA_CHAIN_HOOK, |n| {
                n.put_attr(NFTA_HOOK_HOOKNUM, &base.hook.value().to_be_bytes())?;
                // 符号付き優先度は u32 のビット表現を BE で載せる。
                n.put_attr(NFTA_HOOK_PRIORITY, &(base.priority as u32).to_be_bytes())
            })?;
            let mut ty = Vec::from(base.chain_type.as_str().as_bytes());
            ty.push(0);
            b.put_attr(NFTA_CHAIN_TYPE, &ty)?;
        }
        Ok(())
    }

    /// REQUEST / ACK 付きで組み立てる。
    pub fn build(&self, seq: u32) -> Result<NlMsgBuilder, NetError> {
        let mut b = start(NFT_MSG_NEWCHAIN, self.flags(), self.family, seq)?;
        self.put_attrs(&mut b)?;
        Ok(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{NLM_F_REPLACE, NlMsgIter};
    use crate::nftables_batch::{NFGENMSG_LEN, NftBatch};

    fn name(s: &str) -> NftName {
        NftName::new(s).expect("valid name")
    }

    /// 復号結果: (type, flags, nfgenmsg 4B, 属性列 (type, nested, net_byteorder, payload))。
    type Decoded = (u16, u16, Vec<u8>, Vec<(u16, bool, bool, Vec<u8>)>);

    fn decode(b: NlMsgBuilder) -> Decoded {
        let bytes = b.finish().expect("finish");
        let msg = NlMsgIter::new(&bytes).next().expect("one").expect("decode");
        let h = msg.header();
        let nfg = msg
            .payload()
            .get(..NFGENMSG_LEN)
            .expect("nfgenmsg")
            .to_vec();
        let attrs = msg
            .attrs(NFGENMSG_LEN)
            .expect("attrs")
            .map(|a| {
                let a = a.expect("attr");
                (
                    a.attr_type(),
                    a.is_nested(),
                    a.is_net_byteorder(),
                    a.payload().to_vec(),
                )
            })
            .collect();
        (h.msg_type(), h.flags(), nfg, attrs)
    }

    const RA: u16 = NLM_F_REQUEST | NLM_F_ACK;

    /// NET-11: NEWTABLE は NFTA_TABLE_NAME を 1 件だけ持つ。
    #[test]
    fn net11_newtable_has_table_name() {
        let m = TableCreate::new(NftFamily::Inet, name("fandhe"));
        let (ty, fl, nfg, attrs) = decode(m.build(7).expect("build"));
        assert_eq!(ty, 0x0A00);
        assert_eq!(fl, RA | NLM_F_CREATE);
        assert_eq!(nfg, [NFPROTO_INET, 0, 0, 0]);
        assert_eq!(attrs, vec![(1, false, false, b"fandhe\0".to_vec())]);
        let (_, fl, _, _) = decode(m.exclusive().build(7).expect("build"));
        assert_eq!(fl, RA | NLM_F_CREATE | NLM_F_EXCL);
    }

    /// NET-11: 通常の chain は hook・type を持たない。
    #[test]
    fn net11_newchain_regular_has_no_hook() {
        let m = ChainCreate::regular(NftFamily::Inet, name("t"), name("c"));
        let (ty, _, _, attrs) = decode(m.build(1).expect("build"));
        assert_eq!(ty, 0x0A03);
        assert_eq!(
            attrs,
            vec![
                (1, false, false, b"t\0".to_vec()),
                (3, false, false, b"c\0".to_vec())
            ]
        );
    }

    /// NET-11・REPAIR-2: base chain は hook（BE の hooknum / priority）と type を持つ。
    #[test]
    fn net11_newchain_base_has_hook_priority_type() {
        let cases = [
            (NfInetHook::PostRouting, 100, [0, 0, 0, 4], [0, 0, 0, 0x64]),
            (
                NfInetHook::PreRouting,
                -100,
                [0, 0, 0, 0],
                [0xFF, 0xFF, 0xFF, 0x9C],
            ),
        ];
        for (hook, prio, hn, pr) in cases {
            let base = BaseChain {
                chain_type: ChainType::Nat,
                hook,
                priority: prio,
            };
            let m = ChainCreate::base(NftFamily::Inet, name("t"), name("c"), base).expect("base");
            let bytes = m.build(1).expect("build").finish().expect("finish");
            let msg = NlMsgIter::new(&bytes).next().expect("one").expect("ok");
            let attrs: Vec<_> = msg
                .attrs(NFGENMSG_LEN)
                .expect("attrs")
                .map(|a| a.expect("attr"))
                .collect();
            assert_eq!(attrs.len(), 4);
            let hook_attr = attrs.get(2).expect("hook");
            assert_eq!(hook_attr.attr_type(), 4);
            assert!(hook_attr.is_nested());
            let kids: Vec<_> = hook_attr
                .nested()
                .map(|a| {
                    let a = a.expect("child");
                    (a.attr_type(), a.is_net_byteorder(), a.payload().to_vec())
                })
                .collect();
            assert_eq!(kids, vec![(1, false, hn.to_vec()), (2, false, pr.to_vec())]);
            let ty = attrs.get(3).expect("type");
            assert_eq!((ty.attr_type(), ty.payload()), (7, &b"nat\0"[..]));
        }
    }

    /// NET-11: inet / ip / ip6 以外の family では base chain を拒否する。
    #[test]
    fn net11_base_chain_rejects_non_inet_family() {
        let base = BaseChain {
            chain_type: ChainType::Filter,
            hook: NfInetHook::LocalIn,
            priority: NF_IP_PRI_FILTER,
        };
        for f in [NftFamily::Arp, NftFamily::Bridge, NftFamily::Netdev] {
            let e = ChainCreate::base(f, name("t"), name("c"), base).expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        }
        for f in [NftFamily::Inet, NftFamily::Ipv4, NftFamily::Ipv6] {
            assert!(ChainCreate::base(f, name("t"), name("c"), base).is_ok());
        }
    }

    /// NET-11: DELTABLE は専用テーブル名のみを指定し、CREATE / EXCL / REPLACE を持たない。
    #[test]
    fn net11_deltable_targets_named_table() {
        let m = TableDelete::new(NftFamily::Inet, name("fandhe"));
        let (ty, fl, _, attrs) = decode(m.build(3).expect("build"));
        assert_eq!(ty, 0x0A02);
        assert_eq!(fl, RA);
        assert_eq!(fl & (NLM_F_CREATE | NLM_F_EXCL | NLM_F_REPLACE), 0);
        assert_eq!(attrs, vec![(1, false, false, b"fandhe\0".to_vec())]);
    }

    /// REPAIR-2: 名前の長さ・文字集合の検証。
    #[test]
    fn repair2_nft_name_validation() {
        let long = "a".repeat(256);
        for bad in ["", long.as_str(), "a\0b", "a b", "a/b", "é", "1abc", "-a"] {
            let e = NftName::new(bad).expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        }
        let ok255 = "a".repeat(255);
        assert_eq!(NftName::new(&ok255).expect("255").as_str(), ok255);
        assert_eq!(
            NftName::new("fandhe_container-1.x").expect("ok").as_str(),
            "fandhe_container-1.x"
        );
    }

    /// NET-11: 4 種をバッチへ積んで seq と type が期待どおり。
    #[test]
    fn net11_messages_fit_nft_batch() {
        let base = BaseChain {
            chain_type: ChainType::Nat,
            hook: NfInetHook::PostRouting,
            priority: NF_IP_PRI_NAT_SRC,
        };
        let t = TableCreate::new(NftFamily::Inet, name("t"));
        let c1 = ChainCreate::base(NftFamily::Inet, name("t"), name("c"), base).expect("base");
        let c2 = ChainCreate::regular(NftFamily::Inet, name("t"), name("d"));
        let d = TableDelete::new(NftFamily::Inet, name("t"));
        let mut batch = NftBatch::new(10).expect("new");
        batch.push_with(|s| t.build(s)).expect("t");
        batch.push_with(|s| c1.build(s)).expect("c1");
        batch.push_with(|s| c2.build(s)).expect("c2");
        batch.push_with(|s| d.build(s)).expect("d");
        let out = batch.finish().expect("finish");
        let got: Vec<(u16, u32)> = NlMsgIter::new(out.bytes())
            .map(|m| {
                let h = m.expect("decode").header();
                (h.msg_type(), h.seq())
            })
            .collect();
        assert_eq!(
            got,
            vec![
                (0x10, 10),
                (0x0A00, 11),
                (0x0A03, 12),
                (0x0A03, 13),
                (0x0A02, 14),
                (0x11, 15)
            ]
        );
    }

    /// NET-11: family が NFPROTO_* に写り nfgenmsg 先頭バイトへ反映される。
    #[test]
    fn net11_family_maps_to_nfproto() {
        let cases = [
            (NftFamily::Inet, 1u8),
            (NftFamily::Ipv4, 2),
            (NftFamily::Arp, 3),
            (NftFamily::Netdev, 5),
            (NftFamily::Bridge, 7),
            (NftFamily::Ipv6, 10),
        ];
        for (f, v) in cases {
            assert_eq!(f.nfproto(), v);
            let (_, _, nfg, _) = decode(TableDelete::new(f, name("t")).build(1).expect("build"));
            assert_eq!(nfg, [v, 0, 0, 0]);
        }
    }

    /// `encode` 単体でも build と同じバイト列になる。
    #[test]
    fn encode_matches_build() {
        let m = TableCreate::new(NftFamily::Ipv4, name("x"));
        let mut b = NlMsgBuilder::new(m.msg_type(), m.flags() | RA, 5, 0);
        m.encode(&mut b).expect("encode");
        assert_eq!(
            b.finish().expect("f"),
            m.build(5).expect("build").finish().expect("f")
        );
    }
}
