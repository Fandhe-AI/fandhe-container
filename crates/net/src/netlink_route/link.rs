//! `RTM_NEWLINK` による bridge / veth ペアの作成メッセージ組み立て（TASK-136.3.1・#845・NET-11・MS-8）。
//!
//! `struct ifinfomsg` と `IFLA_*` 属性を `crate::netlink::NlMsgBuilder` で組み立てるだけの OS 非依存
//! モジュールで、ソケットも `unsafe` も持たない。呼び出し元（#846 TASK-136.3.2 の送信ラッパー）は
//! `NetlinkRouteSocket::request(req.msg_type(), req.flags(), timeout, |b| req.encode(b))` の
//! `build` クロージャから [`LinkCreate::encode`] を呼ぶ。`NLM_F_REQUEST | NLM_F_ACK` は
//! `request` が付与するため [`LinkCreate::flags`] には含めない。
//!
//! # ワイヤーレイアウト
//!
//! 文字列属性はすべて NUL 終端付き（libnl の `nla_put_string` と同じ）。
//!
//! ```text
//! bridge:
//!   nlmsghdr(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL)
//!   ifinfomsg(16B, すべて 0)
//!   IFLA_IFNAME = "br0\0"
//!   IFLA_LINKINFO (nested)
//!     IFLA_INFO_KIND = "bridge\0"
//!
//! veth:
//!   nlmsghdr / ifinfomsg / IFLA_IFNAME = "veth0\0"
//!   IFLA_LINKINFO (nested)
//!     IFLA_INFO_KIND = "veth\0"
//!     IFLA_INFO_DATA (nested)
//!       VETH_INFO_PEER (nested)
//!         ifinfomsg(16B, すべて 0)   <- peer 側は 2 つ目の ifinfomsg で始まる
//!         IFLA_IFNAME = "veth1\0"
//! ```
//!
//! # 信頼境界
//!
//! インターフェース名は [`IfName`] でカーネルの `dev_valid_name` 相当（1〜15 バイト・`.` / `..` 不可・
//! `/`・`:`・空白・NUL 不可）を満たすことを検証してからワイヤーに載せる（REPAIR-2）。
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - ソケットへの送信ラッパーと `NetOpKind` の拡張（#846・TASK-136.3.2）
//! - `RTM_SETLINK`（netns 移動 `IFLA_NET_NS_PID/FD`・up の `IFF_UP`）（#846）
//! - MTU・MAC 等の追加属性、bridge のオプション（`IFLA_BR_*`）、`RTM_DELLINK` の組み立て

use crate::error::{NetError, NetErrorCode};
use crate::netlink::{NLM_F_CREATE, NLM_F_EXCL, NlMsgBuilder};

/// リンクの新規作成（`linux/rtnetlink.h`）。
pub const RTM_NEWLINK: u16 = 16;
/// リンクの削除（`linux/rtnetlink.h`）。
pub const RTM_DELLINK: u16 = 17;
/// リンクの取得（`linux/rtnetlink.h`）。
pub const RTM_GETLINK: u16 = 18;
/// リンクの設定変更（`linux/rtnetlink.h`）。
pub const RTM_SETLINK: u16 = 19;
/// アドレスファミリ未指定（`linux/socket.h`）。
pub const AF_UNSPEC: u8 = 0;
/// `struct ifinfomsg` のバイト長（`linux/rtnetlink.h`）。
pub const IFINFOMSG_LEN: usize = 16;
/// インターフェース名属性（`linux/if_link.h`）。
pub const IFLA_IFNAME: u16 = 3;
/// リンク種別情報のネスト属性（`linux/if_link.h`）。
pub const IFLA_LINKINFO: u16 = 18;
/// リンク種別名（`bridge`・`veth` 等。`linux/if_link.h`）。
pub const IFLA_INFO_KIND: u16 = 1;
/// リンク種別固有データのネスト属性（`linux/if_link.h`）。
pub const IFLA_INFO_DATA: u16 = 2;
/// veth の peer 側を指定するネスト属性（`linux/veth.h`）。
pub const VETH_INFO_PEER: u16 = 1;
/// インターフェース名の最大長（NUL を含む。`linux/if.h`）。
pub const IFNAMSIZ: usize = 16;

fn invalid(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

/// 検証済みのインターフェース名（REPAIR-2: 不正な名前を表現できない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfName(String);

impl IfName {
    /// カーネルの `dev_valid_name` に合わせて検証する。違反は `InvalidArgument`（入力は載せない）。
    pub fn new(name: &str) -> Result<Self, NetError> {
        if name.is_empty() || name.len() >= IFNAMSIZ {
            return Err(invalid("interface name length must be 1 to 15 bytes"));
        }
        if name == "." || name == ".." {
            return Err(invalid("interface name must not be . or .."));
        }
        if name
            .chars()
            .any(|c| c == '/' || c == ':' || c == '\0' || c.is_whitespace())
        {
            return Err(invalid("interface name contains a forbidden character"));
        }
        Ok(Self(name.to_owned()))
    }

    /// 名前を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// NUL 終端付きのワイヤー表現（最大 16 バイト）。
    fn to_nul_terminated(&self) -> Vec<u8> {
        nul_terminated(self.0.as_bytes())
    }
}

fn nul_terminated(s: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s);
    v.push(0);
    v
}

/// 作成時の `ifinfomsg`（family = `AF_UNSPEC`、type・index・flags・change はすべて 0）。
///
/// レイアウトは `family:u8 | pad:u8 | type:u16 | index:i32 | flags:u32 | change:u32`。
/// 全フィールドが 0 のため、バイトオーダーの差は生じない。
fn ifinfomsg_for_create() -> [u8; IFINFOMSG_LEN] {
    [AF_UNSPEC; IFINFOMSG_LEN]
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Bridge { name: IfName },
    Veth { name: IfName, peer: IfName },
}

/// `RTM_NEWLINK` によるリンク作成要求（bridge / veth ペア）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkCreate(Kind);

impl LinkCreate {
    /// bridge を 1 本作る要求。
    pub fn bridge(name: IfName) -> Self {
        Self(Kind::Bridge { name })
    }

    /// veth ペア（`name` と `peer`）を作る要求。同名は `InvalidArgument`（fail-closed）。
    pub fn veth(name: IfName, peer: IfName) -> Result<Self, NetError> {
        if name == peer {
            return Err(invalid("veth name and peer name must differ"));
        }
        Ok(Self(Kind::Veth { name, peer }))
    }

    /// `nlmsg_type`（常に `RTM_NEWLINK`）。
    pub fn msg_type(&self) -> u16 {
        RTM_NEWLINK
    }

    /// `nlmsg_flags`（`NLM_F_CREATE | NLM_F_EXCL`。REQUEST / ACK は `request` が付与する）。
    pub fn flags(&self) -> u16 {
        NLM_F_CREATE | NLM_F_EXCL
    }

    /// nlmsghdr の後ろに続く `ifinfomsg` と属性を `b` へ書き込む。
    pub fn encode(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        let (name, kind, peer) = match &self.0 {
            Kind::Bridge { name } => (name, "bridge", None),
            Kind::Veth { name, peer } => (name, "veth", Some(peer)),
        };
        b.put_fixed(&ifinfomsg_for_create())?;
        b.put_attr(IFLA_IFNAME, &name.to_nul_terminated())?;
        b.put_nested(IFLA_LINKINFO, |b| {
            b.put_attr(IFLA_INFO_KIND, &nul_terminated(kind.as_bytes()))?;
            if let Some(peer) = peer {
                b.put_nested(IFLA_INFO_DATA, |b| {
                    b.put_nested(VETH_INFO_PEER, |b| {
                        b.put_fixed(&ifinfomsg_for_create())?;
                        b.put_attr(IFLA_IFNAME, &peer.to_nul_terminated())
                    })
                })?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{AttrIter, NLA_F_NESTED, NLM_F_ACK, NLM_F_REQUEST, NlMsgIter};

    fn build(req: &LinkCreate) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(req.msg_type(), req.flags(), 0x1234, 0);
        req.encode(&mut b).unwrap();
        b.finish().unwrap()
    }

    fn name(s: &str) -> IfName {
        IfName::new(s).unwrap()
    }

    /// NET-11: bridge 作成は IFLA_IFNAME と IFLA_LINKINFO(KIND=bridge) だけを持つ。
    #[test]
    fn net11_bridge_create_has_ifname_and_linkinfo_kind_bridge() {
        let data = build(&LinkCreate::bridge(name("br0")));
        let mut it = NlMsgIter::new(&data);
        let msg = it.next().unwrap().unwrap();
        let h = msg.header();
        assert_eq!(h.msg_type(), 16);
        assert_eq!(h.flags(), NLM_F_CREATE | NLM_F_EXCL);
        assert_eq!(msg.payload().get(..IFINFOMSG_LEN).unwrap(), &[0u8; 16]);
        let attrs: Vec<_> = msg
            .attrs(IFINFOMSG_LEN)
            .unwrap()
            .map(|a| a.unwrap())
            .collect();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].attr_type(), IFLA_IFNAME);
        assert_eq!(attrs[0].payload(), b"br0\0");
        assert_eq!(attrs[1].attr_type(), IFLA_LINKINFO);
        assert!(attrs[1].is_nested());
        let kids: Vec<_> = attrs[1].nested().map(|a| a.unwrap()).collect();
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].attr_type(), IFLA_INFO_KIND);
        assert_eq!(kids[0].payload(), b"bridge\0");
    }

    /// NET-11: メッセージ全体のバイト列を期待値と完全一致で比べる。
    #[test]
    fn net11_bridge_create_golden_bytes() {
        let data = build(&LinkCreate::bridge(name("br0")));
        let mut e = Vec::new();
        // nlmsghdr: len = 16 + 16 + 8 (IFNAME) + 16 (LINKINFO: 4 + 11 + 1 pad) = 56
        e.extend_from_slice(&56u32.to_ne_bytes());
        e.extend_from_slice(&16u16.to_ne_bytes());
        e.extend_from_slice(&0x0600u16.to_ne_bytes());
        e.extend_from_slice(&0x1234u32.to_ne_bytes());
        e.extend_from_slice(&0u32.to_ne_bytes());
        e.extend_from_slice(&[0u8; 16]);
        e.extend_from_slice(&8u16.to_ne_bytes());
        e.extend_from_slice(&3u16.to_ne_bytes());
        e.extend_from_slice(b"br0\0");
        e.extend_from_slice(&16u16.to_ne_bytes());
        e.extend_from_slice(&(18u16 | NLA_F_NESTED).to_ne_bytes());
        e.extend_from_slice(&11u16.to_ne_bytes());
        e.extend_from_slice(&1u16.to_ne_bytes());
        e.extend_from_slice(b"bridge\0");
        e.push(0);
        assert_eq!(data, e);
    }

    /// NET-11: veth は INFO_DATA の中に VETH_INFO_PEER(ifinfomsg + IFNAME) を持つ。
    #[test]
    fn net11_veth_create_has_peer_in_info_data() {
        let data = build(&LinkCreate::veth(name("veth0"), name("veth1")).unwrap());
        let mut it = NlMsgIter::new(&data);
        let msg = it.next().unwrap().unwrap();
        let attrs: Vec<_> = msg
            .attrs(IFINFOMSG_LEN)
            .unwrap()
            .map(|a| a.unwrap())
            .collect();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].attr_type(), IFLA_IFNAME);
        assert_eq!(attrs[0].payload(), b"veth0\0");
        let info: Vec<_> = attrs[1].nested().map(|a| a.unwrap()).collect();
        assert_eq!(info.len(), 2);
        assert_eq!(info[0].attr_type(), IFLA_INFO_KIND);
        assert_eq!(info[0].payload(), b"veth\0");
        assert_eq!(info[1].attr_type(), IFLA_INFO_DATA);
        assert!(info[1].is_nested());
        let data_kids: Vec<_> = info[1].nested().map(|a| a.unwrap()).collect();
        assert_eq!(data_kids.len(), 1);
        assert_eq!(data_kids[0].attr_type(), VETH_INFO_PEER);
        assert!(data_kids[0].is_nested());
        let peer = data_kids[0].payload();
        assert_eq!(peer.get(..IFINFOMSG_LEN).unwrap(), &[0u8; 16]);
        let rest = peer.get(IFINFOMSG_LEN..).unwrap();
        let a: Vec<_> = AttrIter::new(rest).map(|a| a.unwrap()).collect();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].attr_type(), IFLA_IFNAME);
        assert_eq!(a[0].payload(), b"veth1\0");
    }

    /// NET-11・REPAIR-2: 不正な名前を拒否し、境界値は受理する。
    #[test]
    fn net11_ifname_rejects_invalid() {
        for bad in [
            "",
            "0123456789abcdef",
            ".",
            "..",
            "a/b",
            "a:b",
            "a b",
            "a\0b",
            "a\u{3000}b",
            "a\tb",
        ] {
            let e = IfName::new(bad).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{bad:?}");
        }
        assert_eq!(IfName::new("0123456789abcde").unwrap().as_str().len(), 15);
        assert_eq!(IfName::new("eth0").unwrap().as_str(), "eth0");
    }

    /// NET-11・REPAIR-2: ワイヤー表現は NUL 終端付きで最大 16 バイト。
    #[test]
    fn net11_ifname_wire_bytes_nul_terminated() {
        let w = name("0123456789abcde").to_nul_terminated();
        assert_eq!(w.len(), 16);
        assert_eq!(w.last(), Some(&0));
    }

    /// NET-11: 同名 veth は送る前に拒否する。
    #[test]
    fn net11_veth_rejects_same_peer_name() {
        let e = LinkCreate::veth(name("v0"), name("v0")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    }

    /// NET-11: flags は CREATE|EXCL のみ（REQUEST / ACK は request が付与）。
    #[test]
    fn net11_link_create_flags_exclude_request_ack() {
        let f = LinkCreate::bridge(name("br0")).flags();
        assert_eq!(f, 0x0600);
        assert_eq!(f & (NLM_F_REQUEST | NLM_F_ACK), 0);
    }
}
