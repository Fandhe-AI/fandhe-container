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
//! - `NFTA_TABLE_FLAGS`（dormant / owner）、`NFTA_CHAIN_POLICY`（書き込み）/ `FLAGS` / `HANDLE`、チェインの handle 指定の削除
//! - `DELCHAIN`・GETTABLE / GETCHAIN 以外の GET 系（ダンプ要求を含む）・`NFT_MSG_DESTROYTABLE`
//!
//! 読み取りは `NFT_MSG_GETCHAIN` と応答の `NFTA_CHAIN_POLICY` の復号のみ実装済み（[`ChainGet`]・[`ChainInfo`]。
//! TASK-148.1・NET-10。cli の `doctor` がホストの `ip filter FORWARD` チェイン policy を調べるために使う）。
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
/// テーブル照会（`NFT_MSG_GETTABLE`）。
pub const NFT_MSG_GETTABLE: u8 = 1;
/// テーブル削除（`NFT_MSG_DELTABLE`）。
pub const NFT_MSG_DELTABLE: u8 = 2;
/// チェイン作成（`NFT_MSG_NEWCHAIN`）。
pub const NFT_MSG_NEWCHAIN: u8 = 3;
/// チェイン照会（`NFT_MSG_GETCHAIN`）。
pub const NFT_MSG_GETCHAIN: u8 = 4;
/// テーブル名属性（`NFTA_TABLE_NAME`）。
pub const NFTA_TABLE_NAME: u16 = 1;
/// テーブルのハンドル属性（`NFTA_TABLE_HANDLE`。`__be64`。カーネルが採番し再利用されない）。
pub const NFTA_TABLE_HANDLE: u16 = 4;
/// テーブルのユーザーデータ属性（`NFTA_TABLE_USERDATA`。最大 `NFT_USERDATA_MAXLEN` バイト）。
pub const NFTA_TABLE_USERDATA: u16 = 6;
/// ユーザーデータの最大長（`NFT_USERDATA_MAXLEN`）。
pub const NFT_USERDATA_MAXLEN: usize = 256;
/// チェインの所属テーブル名属性（`NFTA_CHAIN_TABLE`）。
pub const NFTA_CHAIN_TABLE: u16 = 1;
/// チェイン名属性（`NFTA_CHAIN_NAME`）。
pub const NFTA_CHAIN_NAME: u16 = 3;
/// base chain の policy 属性（`NFTA_CHAIN_POLICY`。`__be32` の `NF_DROP` / `NF_ACCEPT`）。
pub const NFTA_CHAIN_POLICY: u16 = 5;
/// policy 値 drop（`linux/netfilter.h` の `NF_DROP`）。
pub const NF_DROP: u32 = 0;
/// policy 値 accept（`NF_ACCEPT`）。
pub const NF_ACCEPT: u32 = 1;
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
    pub(crate) fn put_into(&self, b: &mut NlMsgBuilder, attr_type: u16) -> Result<(), NetError> {
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
pub(crate) fn start(
    msg: u8,
    op_flags: u16,
    family: NftFamily,
    seq: u32,
) -> Result<NlMsgBuilder, NetError> {
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
    userdata: Option<Vec<u8>>,
}

impl TableCreate {
    /// `NLM_F_CREATE` のみで作る。
    pub fn new(family: NftFamily, name: NftName) -> Self {
        Self {
            family,
            name,
            exclusive: false,
            userdata: None,
        }
    }

    /// 所有トークンを `NFTA_TABLE_USERDATA` として載せる（TASK-139.4・#317）。削除時に `TableGet` の応答と
    /// 照合し、同名の別者のテーブルを巻き込まないために使う。空・`NFT_USERDATA_MAXLEN` 超は `InvalidArgument`。
    pub fn with_userdata(mut self, data: &[u8]) -> Result<Self, NetError> {
        if data.is_empty() || data.len() > NFT_USERDATA_MAXLEN {
            return Err(invalid("table userdata length is out of range"));
        }
        self.userdata = Some(data.to_vec());
        Ok(self)
    }

    fn put_attrs(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        self.name.put_into(b, NFTA_TABLE_NAME)?;
        if let Some(data) = &self.userdata {
            b.put_attr(NFTA_TABLE_USERDATA, data)?;
        }
        Ok(())
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
        self.put_attrs(b)
    }

    /// REQUEST / ACK 付きで組み立てる。`NftBatch::push_with` へそのまま渡せる。
    pub fn build(&self, seq: u32) -> Result<NlMsgBuilder, NetError> {
        let mut b = start(NFT_MSG_NEWTABLE, self.flags(), self.family, seq)?;
        self.put_attrs(&mut b)?;
        Ok(b)
    }
}

/// `NFT_MSG_DELTABLE`。専用テーブル名を指定して削除する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDelete {
    family: NftFamily,
    name: NftName,
    handle: Option<u64>,
}

impl TableDelete {
    /// 名前で削除対象を指定して作る。
    pub fn new(family: NftFamily, name: NftName) -> Self {
        Self {
            family,
            name,
            handle: None,
        }
    }

    /// ハンドルで削除対象を指定して作る（TASK-139.4・#317）。ハンドルはカーネルが採番して再利用しないため、
    /// `TableGet` で所有を確認した個体だけを（確認後に同名の別テーブルへ差し替えられても）削除できる。
    /// ハンドル指定のとき名前属性は載せない（カーネルはハンドルを優先する）。
    pub fn by_handle(family: NftFamily, name: NftName, handle: u64) -> Self {
        Self {
            family,
            name,
            handle: Some(handle),
        }
    }

    fn put_attrs(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        match self.handle {
            Some(h) => b.put_attr(NFTA_TABLE_HANDLE, &h.to_be_bytes()),
            None => self.name.put_into(b, NFTA_TABLE_NAME),
        }
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
        self.put_attrs(b)
    }

    /// REQUEST / ACK 付きで組み立てる。
    pub fn build(&self, seq: u32) -> Result<NlMsgBuilder, NetError> {
        let mut b = start(NFT_MSG_DELTABLE, self.flags(), self.family, seq)?;
        self.put_attrs(&mut b)?;
        Ok(b)
    }
}

/// `NFT_MSG_GETTABLE`。テーブルの存在を読み取り専用で照会する（TASK-139.4・#317・NET-11）。
///
/// バッチ（BEGIN / END）を使わない単発の要求で、ルールセットを変更しない。存在すれば `NFT_MSG_NEWTABLE`
/// の応答と errno 0 の ACK、無ければ `-ENOENT`（`NotFound`）が返る。bridge の消失後に、専用テーブルが
/// 削除済みかを（所有の証明なしに破壊的操作をせず）確認するために使う。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableGet {
    family: NftFamily,
    name: NftName,
}

impl TableGet {
    /// 照会対象を指定して作る。
    pub fn new(family: NftFamily, name: NftName) -> Self {
        Self { family, name }
    }

    /// `nlmsg_type`。
    pub fn msg_type(&self) -> u16 {
        nfnl_msg_type(NFNL_SUBSYS_NFTABLES, NFT_MSG_GETTABLE)
    }

    /// 操作フラグ（なし。REQUEST / ACK は送信側が付ける）。
    pub fn flags(&self) -> u16 {
        0
    }

    /// nfgenmsg と属性を `b` へ追記する。
    pub fn encode(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        NfGenMsg::new(self.family.nfproto(), 0).put_into(b)?;
        self.name.put_into(b, NFTA_TABLE_NAME)
    }
}

/// `NFT_MSG_GETTABLE` 応答（`NFT_MSG_NEWTABLE`）から読み取ったテーブルの識別情報（TASK-139.4・#317）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableInfo {
    handle: Option<u64>,
    userdata: Option<Vec<u8>>,
}

impl TableInfo {
    /// カーネルが採番したハンドル（応答に無ければ `None`）。
    pub fn handle(&self) -> Option<u64> {
        self.handle
    }

    /// 作成時に載せたユーザーデータ（無ければ `None`）。
    pub fn userdata(&self) -> Option<&[u8]> {
        self.userdata.as_deref()
    }

    /// 応答ペイロード（nfgenmsg + 属性）を復号する。カーネル由来の外部入力として属性走査で検証し、
    /// 短い・不正な属性列は `DataLoss`。
    pub fn decode(payload: &[u8]) -> Result<Self, NetError> {
        let attrs = payload.get(NFGENMSG_LEN..).ok_or_else(|| {
            NetError::new(
                NetErrorCode::DataLoss,
                "table reply is shorter than nfgenmsg",
            )
        })?;
        let mut info = Self {
            handle: None,
            userdata: None,
        };
        for attr in crate::netlink::AttrIter::new(attrs) {
            let attr = attr?;
            match attr.attr_type() {
                NFTA_TABLE_HANDLE => {
                    let raw = <[u8; 8]>::try_from(attr.payload()).map_err(|_| {
                        NetError::new(
                            NetErrorCode::DataLoss,
                            "NFTA_TABLE_HANDLE has an invalid length",
                        )
                    })?;
                    info.handle = Some(u64::from_be_bytes(raw));
                }
                NFTA_TABLE_USERDATA => info.userdata = Some(attr.payload().to_vec()),
                _ => {}
            }
        }
        Ok(info)
    }
}

/// `NFT_MSG_GETCHAIN`。チェインの policy を読み取り専用で照会する（TASK-148.1・NET-10・NET-11）。
///
/// [`TableGet`] と同じ単発要求で、ルールセットを変更しない。ホストの `ip filter FORWARD` が
/// `policy drop` かを調べる cli の `doctor` から呼ばれる。無ければ `-ENOENT`（`NotFound`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainGet {
    family: NftFamily,
    table: NftName,
    chain: NftName,
}

impl ChainGet {
    /// 照会対象を指定して作る。
    pub fn new(family: NftFamily, table: NftName, chain: NftName) -> Self {
        Self {
            family,
            table,
            chain,
        }
    }

    /// `nlmsg_type`。
    pub fn msg_type(&self) -> u16 {
        nfnl_msg_type(NFNL_SUBSYS_NFTABLES, NFT_MSG_GETCHAIN)
    }

    /// 操作フラグ（なし。REQUEST / ACK は送信側が付ける）。
    pub fn flags(&self) -> u16 {
        0
    }

    /// nfgenmsg と属性を `b` へ追記する。
    pub fn encode(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        NfGenMsg::new(self.family.nfproto(), 0).put_into(b)?;
        self.table.put_into(b, NFTA_CHAIN_TABLE)?;
        self.chain.put_into(b, NFTA_CHAIN_NAME)
    }
}

/// base chain の policy（`NFTA_CHAIN_POLICY`）。未知の値を accept / drop に丸めない（fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainPolicy {
    /// `NF_ACCEPT`。
    Accept,
    /// `NF_DROP`。
    Drop,
    /// 上記以外のカーネル値。
    Other(u32),
}

impl ChainPolicy {
    /// カーネルの policy 値から変換する。
    pub fn from_raw(v: u32) -> Self {
        match v {
            NF_ACCEPT => Self::Accept,
            NF_DROP => Self::Drop,
            other => Self::Other(other),
        }
    }
}

/// `NFT_MSG_GETCHAIN` 応答（`NFT_MSG_NEWCHAIN`）から読み取ったチェインの情報（TASK-148.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainInfo {
    policy: Option<ChainPolicy>,
    hook: Option<u32>,
}

impl ChainInfo {
    /// base chain の policy。base chain でない（属性が無い）場合は `None`。
    pub fn policy(&self) -> Option<ChainPolicy> {
        self.policy
    }

    /// base chain の hook 番号（`NFTA_HOOK_HOOKNUM`。`NF_INET_*` の値）。hook 属性が無い場合は `None`。
    ///
    /// 同名のチェインでも別 hook の base chain でありうるため、policy を転送経路のものとして
    /// 扱う側（cli の `doctor`。NET-10）はこの値が `NfInetHook::Forward` と一致することを確認する。
    pub fn hook(&self) -> Option<u32> {
        self.hook
    }

    /// 応答ペイロード（nfgenmsg + 属性）を復号する。カーネル由来の外部入力として属性走査で検証し、
    /// 短い・不正な属性列は `DataLoss`。
    pub fn decode(payload: &[u8]) -> Result<Self, NetError> {
        let attrs = payload.get(NFGENMSG_LEN..).ok_or_else(|| {
            NetError::new(
                NetErrorCode::DataLoss,
                "chain reply is shorter than nfgenmsg",
            )
        })?;
        let mut info = Self {
            policy: None,
            hook: None,
        };
        for attr in crate::netlink::AttrIter::new(attrs) {
            let attr = attr?;
            if attr.attr_type() == NFTA_CHAIN_HOOK {
                for child in attr.nested() {
                    let child = child?;
                    if child.attr_type() == NFTA_HOOK_HOOKNUM {
                        let raw = <[u8; 4]>::try_from(child.payload()).map_err(|_| {
                            NetError::new(
                                NetErrorCode::DataLoss,
                                "NFTA_HOOK_HOOKNUM has an invalid length",
                            )
                        })?;
                        info.hook = Some(u32::from_be_bytes(raw));
                    }
                }
            } else if attr.attr_type() == NFTA_CHAIN_POLICY {
                let raw = <[u8; 4]>::try_from(attr.payload()).map_err(|_| {
                    NetError::new(
                        NetErrorCode::DataLoss,
                        "NFTA_CHAIN_POLICY has an invalid length",
                    )
                })?;
                info.policy = Some(ChainPolicy::from_raw(u32::from_be_bytes(raw)));
            }
        }
        Ok(info)
    }
}

/// nfgenmsg の長さ（family・version・res_id）。
const NFGENMSG_LEN: usize = 4;

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

    /// NET-11・TASK-139.4: GETTABLE は名前だけを持つ読み取り専用の照会（type 0x0A01・CREATE 等なし）。
    #[test]
    fn net11_gettable_queries_named_table() {
        let g = TableGet::new(NftFamily::Ipv4, name("fandhe"));
        let mut b = NlMsgBuilder::new(g.msg_type(), g.flags() | NLM_F_REQUEST | NLM_F_ACK, 3, 0);
        g.encode(&mut b).expect("encode");
        let (ty, fl, _, attrs) = decode(b);
        assert_eq!(ty, 0x0A01);
        assert_eq!(fl, RA);
        assert_eq!(attrs, vec![(1, false, false, b"fandhe\0".to_vec())]);
    }

    /// NET-11・TASK-139.4: 所有トークンは NFTA_TABLE_USERDATA(6) に載り、範囲外は拒否される。
    #[test]
    fn net11_newtable_carries_userdata() {
        let m = TableCreate::new(NftFamily::Ipv4, name("fandhe"))
            .exclusive()
            .with_userdata(b"tok")
            .expect("userdata");
        let (_, _, _, attrs) = decode(m.build(3).expect("build"));
        assert_eq!(
            attrs,
            vec![
                (1, false, false, b"fandhe\0".to_vec()),
                (6, false, false, b"tok".to_vec())
            ]
        );
        for bad in [Vec::new(), vec![b'a'; 257]] {
            let e = TableCreate::new(NftFamily::Ipv4, name("t"))
                .with_userdata(&bad)
                .expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        }
    }

    /// NET-11・TASK-139.4: ハンドル指定の DELTABLE は NFTA_TABLE_HANDLE(4) の __be64 だけを載せる。
    #[test]
    fn net11_deltable_by_handle_has_only_handle() {
        let m = TableDelete::by_handle(NftFamily::Ipv4, name("fandhe"), 0x0102);
        let (ty, _, _, attrs) = decode(m.build(3).expect("build"));
        assert_eq!(ty, 0x0A02);
        assert_eq!(attrs, vec![(4, false, false, vec![0, 0, 0, 0, 0, 0, 1, 2])]);
    }

    /// NET-11・TASK-139.4: GETTABLE 応答からハンドルとユーザーデータを復号し、壊れた属性は DataLoss。
    #[test]
    fn net11_table_info_decodes_reply() {
        let mut p = vec![2u8, 0, 0, 0];
        let mut put = |ty: u16, data: &[u8]| {
            p.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
            p.extend_from_slice(&ty.to_ne_bytes());
            p.extend_from_slice(data);
            while p.len() % 4 != 0 {
                p.push(0);
            }
        };
        put(1, b"fandhe\0");
        put(4, &7u64.to_be_bytes());
        put(6, b"tok");
        let info = TableInfo::decode(&p).expect("decode");
        assert_eq!(info.handle(), Some(7));
        assert_eq!(info.userdata(), Some(&b"tok"[..]));

        let bare = TableInfo::decode(&[2, 0, 0, 0]).expect("bare");
        assert_eq!((bare.handle(), bare.userdata()), (None, None));

        let mut bad = vec![2u8, 0, 0, 0, 8, 0, 4, 0, 1, 2, 3, 4];
        assert_eq!(
            TableInfo::decode(&bad).expect_err("len").code(),
            NetErrorCode::DataLoss
        );
        bad.truncate(2);
        assert_eq!(
            TableInfo::decode(&bad).expect_err("short").code(),
            NetErrorCode::DataLoss
        );
    }

    /// NET-10・TASK-148.1: GETCHAIN はテーブル名とチェイン名だけを持つ読み取り専用の照会（type 0x0A04）。
    #[test]
    fn net10_getchain_queries_named_chain() {
        let g = ChainGet::new(NftFamily::Ipv4, name("filter"), name("FORWARD"));
        let mut b = NlMsgBuilder::new(g.msg_type(), g.flags() | NLM_F_REQUEST | NLM_F_ACK, 3, 0);
        g.encode(&mut b).expect("encode");
        let (ty, fl, _, attrs) = decode(b);
        assert_eq!(ty, 0x0A04);
        assert_eq!(fl, RA);
        assert_eq!(
            attrs,
            vec![
                (1, false, false, b"filter\0".to_vec()),
                (3, false, false, b"FORWARD\0".to_vec())
            ]
        );
    }

    /// NET-10・TASK-148.1: GETCHAIN 応答から policy を復号し、未知値は Other、壊れた属性は DataLoss。
    #[test]
    fn net10_chain_info_decodes_policy() {
        let reply = |policy: Option<&[u8]>| {
            let mut p = vec![2u8, 0, 0, 0];
            let mut put = |ty: u16, data: &[u8]| {
                p.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
                p.extend_from_slice(&ty.to_ne_bytes());
                p.extend_from_slice(data);
                while p.len() % 4 != 0 {
                    p.push(0);
                }
            };
            put(3, b"FORWARD\0");
            if let Some(d) = policy {
                put(5, d);
            }
            p
        };
        let pol = |v: u32| ChainInfo::decode(&reply(Some(&v.to_be_bytes()))).expect("decode");
        assert_eq!(pol(0).policy(), Some(ChainPolicy::Drop));
        assert_eq!(pol(1).policy(), Some(ChainPolicy::Accept));
        assert_eq!(pol(7).policy(), Some(ChainPolicy::Other(7)));
        assert_eq!(
            ChainInfo::decode(&reply(None)).expect("none").policy(),
            None
        );
        assert_eq!(
            ChainInfo::decode(&reply(Some(&[0, 0, 0])))
                .expect_err("len")
                .code(),
            NetErrorCode::DataLoss
        );
        assert_eq!(
            ChainInfo::decode(&[2, 0]).expect_err("short").code(),
            NetErrorCode::DataLoss
        );
    }

    /// NET-10・TASK-148.1: GETCHAIN 応答の NFTA_CHAIN_HOOK（ネスト）から hook 番号を復号する。
    #[test]
    fn net10_chain_info_decodes_hook() {
        let reply = |hook: Option<&[u8]>| {
            let mut p = vec![2u8, 0, 0, 0];
            // NFTA_CHAIN_HOOK (nested) { NFTA_HOOK_HOOKNUM = data }
            if let Some(d) = hook {
                let inner_len = (4 + d.len()) as u16;
                p.extend_from_slice(&(4 + inner_len).to_ne_bytes());
                p.extend_from_slice(&(NFTA_CHAIN_HOOK | 0x8000).to_ne_bytes());
                p.extend_from_slice(&inner_len.to_ne_bytes());
                p.extend_from_slice(&NFTA_HOOK_HOOKNUM.to_ne_bytes());
                p.extend_from_slice(d);
            }
            p
        };
        assert_eq!(
            ChainInfo::decode(&reply(Some(&2u32.to_be_bytes())))
                .expect("forward")
                .hook(),
            Some(NfInetHook::Forward.value())
        );
        assert_eq!(
            ChainInfo::decode(&reply(Some(&0u32.to_be_bytes())))
                .expect("prerouting")
                .hook(),
            Some(NfInetHook::PreRouting.value())
        );
        assert_eq!(ChainInfo::decode(&reply(None)).expect("none").hook(), None);
        assert_eq!(
            ChainInfo::decode(&reply(Some(&[0, 0, 2])))
                .expect_err("len")
                .code(),
            NetErrorCode::DataLoss
        );
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
