//! `NETLINK_ROUTE` の address / route 設定（`RTM_NEWADDR` / `RTM_NEWROUTE`）のエンコード / デコード
//! と要求送信（TASK-136.4・#301・NET-11・MS-8）。
//!
//! 上位の `NetlinkRouteSocket::request`（`netlink_route`。seq 採番・ACK 判定・期限つき往復）を呼び、
//! 静的 IPv4 / IPv6 アドレスの付与と route（default route を含む）の追加を行う。bridge / veth の
//! ネットワーク構成（TASK-137〜139）から呼ばれる想定の土台で、`ip` コマンドや汎用 netlink crate は
//! 使わない（NET-11）。ワイヤー構造の根拠は Linux の `include/uapi/linux/if_addr.h`
//! （`struct ifaddrmsg`）と `include/uapi/linux/rtnetlink.h`（`struct rtmsg`・`RTA_*`・`RTN_*`）。
//!
//! # バイトオーダー
//!
//! 固定ヘッダ内の整数と `u32` 属性（`RTA_OIF`）はホストバイトオーダー（`to_ne_bytes`）。アドレス属性
//! （`IFA_LOCAL`・`IFA_ADDRESS`・`RTA_DST`・`RTA_GATEWAY`）はネットワークバイトオーダーのバイト列
//! （`octets()`）で、`NLA_F_NET_BYTEORDER` は付けない（iproute2 と同じ）。
//!
//! # 型の方針（REPAIR-2）
//!
//! `IfIndex`・`IpPrefix`・`RouteSpec` 等はフィールドを非公開にし、検証済みの値しか作れない。
//! 送信前にホスト部つき dst・ファミリ不一致等を `InvalidArgument` で弾く（カーネルも `EINVAL` で拒否する）。
//!
//! # 未実装範囲（REPAIR-3。実装済みを装わない）
//!
//! - `RTM_DELADDR` / `RTM_DELROUTE`（削除）
//! - `IFA_BROADCAST`・`IFA_LABEL`・`IFA_FLAGS`（u32 拡張フラグ）、`RTA_PRIORITY`（metric）・
//!   `RTA_PREFSRC`・`RTA_TABLE`（main 以外のテーブル）・マルチパス
//! - 応答属性の構造体へのパース（デコードは固定ヘッダまで。属性は `NlMsg::attrs` で読む）
//! - `ENETDOWN` / `ENETUNREACH` の errno 分類（現状 `Internal`）
//! - 操作別の計装種別（現状は `NetOpKind::NetlinkRequest` として記録される。REPAIR-4）

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;

use crate::error::{NetError, NetErrorCode};
use crate::netlink::{NLM_F_CREATE, NLM_F_EXCL, NlMsgBuilder};

/// `RTM_NEWADDR`（`rtnetlink.h`）。
pub const RTM_NEWADDR: u16 = 20;
/// `RTM_GETADDR`（`rtnetlink.h`）。
pub const RTM_GETADDR: u16 = 22;
/// `RTM_NEWROUTE`（`rtnetlink.h`）。
pub const RTM_NEWROUTE: u16 = 24;
/// `RTM_GETROUTE`（`rtnetlink.h`）。
pub const RTM_GETROUTE: u16 = 26;

/// `AF_INET`（Linux）。
pub const AF_INET: u8 = 2;
/// `AF_INET6`（Linux）。
pub const AF_INET6: u8 = 10;

/// `IFA_ADDRESS`（`if_addr.h`）。
pub const IFA_ADDRESS: u16 = 1;
/// `IFA_LOCAL`（`if_addr.h`）。
pub const IFA_LOCAL: u16 = 2;
/// `IFA_F_NODAD`（`if_addr.h`。IPv6 の DAD を省く）。
pub const IFA_F_NODAD: u8 = 0x02;

/// `RT_SCOPE_UNIVERSE`（`rtnetlink.h`）。
pub const RT_SCOPE_UNIVERSE: u8 = 0;
/// `RT_SCOPE_SITE`。
pub const RT_SCOPE_SITE: u8 = 200;
/// `RT_SCOPE_LINK`。
pub const RT_SCOPE_LINK: u8 = 253;
/// `RT_SCOPE_HOST`。
pub const RT_SCOPE_HOST: u8 = 254;

/// `RTA_DST`（`rtnetlink.h`）。
pub const RTA_DST: u16 = 1;
/// `RTA_OIF`。
pub const RTA_OIF: u16 = 4;
/// `RTA_GATEWAY`。
pub const RTA_GATEWAY: u16 = 5;

/// `RT_TABLE_MAIN`。
pub const RT_TABLE_MAIN: u8 = 254;
/// `RTPROT_STATIC`。
pub const RTPROT_STATIC: u8 = 4;
/// `RTN_UNICAST`。
pub const RTN_UNICAST: u8 = 1;

/// `RTM_NEWADDR` / `RTM_NEWROUTE` に付ける作成フラグ（`NLM_F_CREATE | NLM_F_EXCL` = 0x600）。
/// 既存の対象があれば `EEXIST`（`AlreadyExists`）になり、黙って上書きしない。
pub const NEW_ADDR_ROUTE_FLAGS: u16 = NLM_F_CREATE | NLM_F_EXCL;

/// `struct ifaddrmsg` の長さ（バイト）。
pub const IFADDRMSG_LEN: usize = 8;
/// `struct rtmsg` の長さ（バイト）。
pub const RTMSG_LEN: usize = 12;

fn invalid(msg: &str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

fn data_loss(msg: &str) -> NetError {
    NetError::new(NetErrorCode::DataLoss, msg)
}

/// インターフェース番号（`ifindex`。1 以上 `i32::MAX` 以下。カーネルでは `int`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IfIndex(NonZeroU32);

impl IfIndex {
    /// 範囲外（0 または `i32::MAX` 超）は `InvalidArgument`。
    pub fn new(index: u32) -> Result<Self, NetError> {
        if index > i32::MAX as u32 {
            return Err(invalid("ifindex exceeds i32::MAX"));
        }
        NonZeroU32::new(index)
            .map(Self)
            .ok_or_else(|| invalid("ifindex must be non-zero"))
    }

    /// 数値を返す。
    pub fn get(&self) -> u32 {
        self.0.get()
    }
}

/// アドレスとプレフィックス長（IPv4 は 32 以下・IPv6 は 128 以下）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpPrefix {
    addr: IpAddr,
    prefix_len: u8,
}

impl IpPrefix {
    /// プレフィックス長がファミリの上限を超えれば `InvalidArgument`。
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, NetError> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix_len > max {
            return Err(invalid("prefix length exceeds the address family maximum"));
        }
        Ok(Self { addr, prefix_len })
    }

    /// `0.0.0.0/0`。
    pub fn default_v4() -> Self {
        Self {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_len: 0,
        }
    }

    /// `::/0`。
    pub fn default_v6() -> Self {
        Self {
            addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            prefix_len: 0,
        }
    }

    /// アドレス。
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// プレフィックス長。
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// ホスト部がすべて 0 か（route の dst に必要な条件）。
    pub fn is_network(&self) -> bool {
        let bytes = addr_bytes(&self.addr);
        let mut remaining = usize::from(self.prefix_len);
        for b in bytes {
            let keep = remaining.min(8);
            remaining -= keep;
            // 上位 keep ビットだけを残すマスク。keep=0 なら 0、8 なら 0xff。
            let mask = (0xffu16 << (8 - keep)) as u8;
            if b & !mask != 0 {
                return false;
            }
        }
        true
    }

    fn family(&self) -> u8 {
        family_of(&self.addr)
    }
}

fn family_of(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    }
}

/// ネットワークバイトオーダーのアドレスバイト列。
fn addr_bytes(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// アドレスの scope（`ifa_scope`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AddrScope {
    /// `RT_SCOPE_UNIVERSE`。
    Universe,
    /// `RT_SCOPE_SITE`。
    Site,
    /// `RT_SCOPE_LINK`。
    Link,
    /// `RT_SCOPE_HOST`。
    Host,
}

impl AddrScope {
    /// カーネルの scope 値。
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Universe => RT_SCOPE_UNIVERSE,
            Self::Site => RT_SCOPE_SITE,
            Self::Link => RT_SCOPE_LINK,
            Self::Host => RT_SCOPE_HOST,
        }
    }
}

/// `struct ifaddrmsg`（8 バイト）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfAddrMsg {
    family: u8,
    prefix_len: u8,
    flags: u8,
    scope: u8,
    index: u32,
}

impl IfAddrMsg {
    /// ヘッダを組む。
    pub fn new(family: u8, prefix_len: u8, flags: u8, scope: u8, index: u32) -> Self {
        Self {
            family,
            prefix_len,
            flags,
            scope,
            index,
        }
    }

    /// ワイヤー表現（ホストバイトオーダー）。
    pub fn to_bytes(&self) -> [u8; IFADDRMSG_LEN] {
        let mut out = [0u8; IFADDRMSG_LEN];
        out[0] = self.family;
        out[1] = self.prefix_len;
        out[2] = self.flags;
        out[3] = self.scope;
        out[4..8].copy_from_slice(&self.index.to_ne_bytes());
        out
    }

    /// メッセージペイロードの先頭から読む。8 バイト未満は `DataLoss`（外部入力として検証する）。
    pub fn decode(payload: &[u8]) -> Result<Self, NetError> {
        let head: &[u8; IFADDRMSG_LEN] = payload
            .get(..IFADDRMSG_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| data_loss("ifaddrmsg is shorter than 8 bytes"))?;
        let [family, prefix_len, flags, scope, i0, i1, i2, i3] = *head;
        Ok(Self {
            family,
            prefix_len,
            flags,
            scope,
            index: u32::from_ne_bytes([i0, i1, i2, i3]),
        })
    }

    /// `ifa_family`。
    pub fn family(&self) -> u8 {
        self.family
    }

    /// `ifa_prefixlen`。
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// `ifa_flags`。
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// `ifa_scope`。
    pub fn scope(&self) -> u8 {
        self.scope
    }

    /// `ifa_index`。
    pub fn index(&self) -> u32 {
        self.index
    }
}

/// `struct rtmsg`（12 バイト）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtMsg {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    route_type: u8,
    flags: u32,
}

impl RtMsg {
    /// `to_bytes` / `decode` の往復用に全フィールドを指定して組む。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        family: u8,
        dst_len: u8,
        src_len: u8,
        tos: u8,
        table: u8,
        protocol: u8,
        scope: u8,
        route_type: u8,
        flags: u32,
    ) -> Self {
        Self {
            family,
            dst_len,
            src_len,
            tos,
            table,
            protocol,
            scope,
            route_type,
            flags,
        }
    }

    /// ワイヤー表現（ホストバイトオーダー）。
    pub fn to_bytes(&self) -> [u8; RTMSG_LEN] {
        let mut out = [0u8; RTMSG_LEN];
        out[0] = self.family;
        out[1] = self.dst_len;
        out[2] = self.src_len;
        out[3] = self.tos;
        out[4] = self.table;
        out[5] = self.protocol;
        out[6] = self.scope;
        out[7] = self.route_type;
        out[8..12].copy_from_slice(&self.flags.to_ne_bytes());
        out
    }

    /// メッセージペイロードの先頭から読む。12 バイト未満は `DataLoss`。
    pub fn decode(payload: &[u8]) -> Result<Self, NetError> {
        let head: &[u8; RTMSG_LEN] = payload
            .get(..RTMSG_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| data_loss("rtmsg is shorter than 12 bytes"))?;
        let [
            family,
            dst_len,
            src_len,
            tos,
            table,
            protocol,
            scope,
            route_type,
            f0,
            f1,
            f2,
            f3,
        ] = *head;
        Ok(Self {
            family,
            dst_len,
            src_len,
            tos,
            table,
            protocol,
            scope,
            route_type,
            flags: u32::from_ne_bytes([f0, f1, f2, f3]),
        })
    }

    /// `rtm_family`。
    pub fn family(&self) -> u8 {
        self.family
    }

    /// `rtm_dst_len`。
    pub fn dst_len(&self) -> u8 {
        self.dst_len
    }

    /// `rtm_src_len`。
    pub fn src_len(&self) -> u8 {
        self.src_len
    }

    /// `rtm_tos`。
    pub fn tos(&self) -> u8 {
        self.tos
    }

    /// `rtm_table`。
    pub fn table(&self) -> u8 {
        self.table
    }

    /// `rtm_protocol`。
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// `rtm_scope`。
    pub fn scope(&self) -> u8 {
        self.scope
    }

    /// `rtm_type`。
    pub fn route_type(&self) -> u8 {
        self.route_type
    }

    /// `rtm_flags`。
    pub fn flags(&self) -> u32 {
        self.flags
    }
}

/// `RTM_NEWADDR` の要求内容（静的アドレスの付与）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressSpec {
    ifindex: IfIndex,
    local: IpPrefix,
    scope: AddrScope,
    nodad: bool,
}

impl AddressSpec {
    /// `local` はホスト部ありを許す（`10.0.0.2/24` は正当）。
    pub fn new(ifindex: IfIndex, local: IpPrefix, scope: AddrScope) -> Self {
        Self {
            ifindex,
            local,
            scope,
            nodad: false,
        }
    }

    /// IPv6 の DAD（重複アドレス検出）を省く（`IFA_F_NODAD`）。
    pub fn with_nodad(mut self) -> Self {
        self.nodad = true;
        self
    }

    /// `ifaddrmsg` と `IFA_LOCAL` / `IFA_ADDRESS` を `b` へ書く。
    ///
    /// 2 属性に同じアドレスを入れるのは iproute2 の `ip addr add` と同じ形で、ポイントツーポイント
    /// でない限り `IFA_ADDRESS` は自アドレスと等しい。
    pub fn encode_into(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        let flags = if self.nodad { IFA_F_NODAD } else { 0 };
        let hdr = IfAddrMsg::new(
            self.local.family(),
            self.local.prefix_len,
            flags,
            self.scope.as_u8(),
            self.ifindex.get(),
        );
        b.put_fixed(&hdr.to_bytes())?;
        let bytes = addr_bytes(&self.local.addr);
        b.put_attr(IFA_LOCAL, &bytes)?;
        b.put_attr(IFA_ADDRESS, &bytes)
    }
}

/// route の次の転送先。nexthop のない route を型で表現できないようにする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteNextHop {
    /// ゲートウェイ経由（`oif` は任意）。
    Gateway {
        /// ゲートウェイのアドレス（dst と同じファミリであること）。
        gateway: IpAddr,
        /// 出力インターフェース。
        oif: Option<IfIndex>,
    },
    /// デバイス直結（ゲートウェイなし）。
    Device {
        /// 出力インターフェース。
        oif: IfIndex,
    },
}

/// `RTM_NEWROUTE` の要求内容（main テーブル・`RTPROT_STATIC`・`RTN_UNICAST` 固定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSpec {
    dst: IpPrefix,
    nexthop: RouteNextHop,
}

impl RouteSpec {
    /// dst のホスト部が 0 でない、またはゲートウェイのファミリが dst と異なれば `InvalidArgument`。
    pub fn new(dst: IpPrefix, nexthop: RouteNextHop) -> Result<Self, NetError> {
        if !dst.is_network() {
            return Err(invalid("route destination has host bits set"));
        }
        if let RouteNextHop::Gateway { gateway, .. } = &nexthop
            && family_of(gateway) != dst.family()
        {
            return Err(invalid("gateway address family differs from destination"));
        }
        Ok(Self { dst, nexthop })
    }

    /// `rtm_scope` の導出（iproute2 の `iproute_modify` に合わせる）。IPv6 は常に universe。
    /// IPv4 はゲートウェイありなら universe、なし（デバイス直結）なら link。
    fn scope(&self) -> u8 {
        match (&self.nexthop, self.dst.addr) {
            (_, IpAddr::V6(_)) => RT_SCOPE_UNIVERSE,
            (RouteNextHop::Gateway { .. }, IpAddr::V4(_)) => RT_SCOPE_UNIVERSE,
            (RouteNextHop::Device { .. }, IpAddr::V4(_)) => RT_SCOPE_LINK,
        }
    }

    /// `rtmsg` → `RTA_DST`（default route 以外）→ `RTA_GATEWAY` → `RTA_OIF` の順で `b` へ書く。
    pub fn encode_into(&self, b: &mut NlMsgBuilder) -> Result<(), NetError> {
        let hdr = RtMsg::new(
            self.dst.family(),
            self.dst.prefix_len,
            0,
            0,
            RT_TABLE_MAIN,
            RTPROT_STATIC,
            self.scope(),
            RTN_UNICAST,
            0,
        );
        b.put_fixed(&hdr.to_bytes())?;
        if self.dst.prefix_len != 0 {
            b.put_attr(RTA_DST, &addr_bytes(&self.dst.addr))?;
        }
        let oif = match &self.nexthop {
            RouteNextHop::Gateway { gateway, oif } => {
                b.put_attr(RTA_GATEWAY, &addr_bytes(gateway))?;
                *oif
            }
            RouteNextHop::Device { oif } => Some(*oif),
        };
        if let Some(oif) = oif {
            b.put_attr(RTA_OIF, &oif.get().to_ne_bytes())?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::time::Duration;

    use super::{AddressSpec, NEW_ADDR_ROUTE_FLAGS, RTM_NEWADDR, RTM_NEWROUTE, RouteSpec};
    use crate::error::NetError;
    use crate::netlink_route::{NetlinkReply, NetlinkRouteSocket};

    impl NetlinkRouteSocket {
        /// アドレスを付与する（`RTM_NEWADDR`・`NLM_F_CREATE | NLM_F_EXCL`）。
        ///
        /// 既存なら `AlreadyExists`。`CAP_NET_ADMIN` が必要で、本 crate は権限を上げない。
        /// `Timeout` / `DataLoss` のときは適用済みか不明なので、呼び出し側が状態を再照会すること
        /// （`request` の契約を引き継ぐ。REPAIR-5）。
        pub fn add_address(
            &self,
            spec: &AddressSpec,
            timeout: Duration,
        ) -> Result<NetlinkReply, NetError> {
            self.request(RTM_NEWADDR, NEW_ADDR_ROUTE_FLAGS, timeout, |b| {
                spec.encode_into(b)
            })
        }

        /// route を追加する（`RTM_NEWROUTE`・`NLM_F_CREATE | NLM_F_EXCL`）。
        ///
        /// 既存なら `AlreadyExists`。出力デバイスが down だと `ENETDOWN` が `Internal` で返る
        /// （未分類。未実装範囲を参照）。`Timeout` / `DataLoss` の扱いは `add_address` と同じ。
        pub fn add_route(
            &self,
            spec: &RouteSpec,
            timeout: Duration,
        ) -> Result<NetlinkReply, NetError> {
            self.request(RTM_NEWROUTE, NEW_ADDR_ROUTE_FLAGS, timeout, |b| {
                spec.encode_into(b)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{NLM_F_REQUEST, NlMsgIter};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn ifx(i: u32) -> IfIndex {
        IfIndex::new(i).expect("ifindex")
    }

    /// エンコード結果を NlMsgIter で読み直し (payload, 属性 (type, payload) 一覧) を返す。
    fn build(
        msg_type: u16,
        fixed_len: usize,
        f: impl FnOnce(&mut NlMsgBuilder) -> Result<(), NetError>,
    ) -> (Vec<u8>, Vec<(u16, Vec<u8>)>) {
        let mut b = NlMsgBuilder::new(msg_type, NLM_F_REQUEST | NEW_ADDR_ROUTE_FLAGS, 1, 0);
        f(&mut b).expect("encode");
        let buf = b.finish().expect("finish");
        let m = NlMsgIter::new(&buf).next().expect("one").expect("valid");
        assert_eq!(m.header().msg_type(), msg_type);
        let attrs = m
            .attrs(fixed_len)
            .expect("attrs")
            .map(|a| {
                let a = a.expect("attr");
                (a.attr_type(), a.payload().to_vec())
            })
            .collect();
        (m.payload().to_vec(), attrs)
    }

    /// NET-11・TASK-136.4 AC1: ifaddrmsg の prefixlen・scope・IFA_ADDRESS が具体値で一致する。
    #[test]
    fn newaddr_v4_encodes_header_and_attrs() {
        let spec = AddressSpec::new(
            ifx(3),
            IpPrefix::new(v4(10, 0, 0, 2), 24).expect("prefix"),
            AddrScope::Universe,
        );
        let (payload, attrs) = build(RTM_NEWADDR, IFADDRMSG_LEN, |b| spec.encode_into(b));
        let mut expect = vec![2, 24, 0, 0];
        expect.extend_from_slice(&3u32.to_ne_bytes());
        assert_eq!(payload.get(..8), Some(expect.as_slice()));
        assert_eq!(
            attrs,
            vec![
                (IFA_LOCAL, vec![10, 0, 0, 2]),
                (IFA_ADDRESS, vec![10, 0, 0, 2])
            ]
        );
    }

    /// NET-11: IPv6 + NODAD、および host scope。
    #[test]
    fn newaddr_v6_nodad_and_host_scope() {
        let a6: Ipv6Addr = "fd00::1".parse().expect("v6");
        let spec = AddressSpec::new(
            ifx(1),
            IpPrefix::new(IpAddr::V6(a6), 64).expect("prefix"),
            AddrScope::Universe,
        )
        .with_nodad();
        let (payload, attrs) = build(RTM_NEWADDR, IFADDRMSG_LEN, |b| spec.encode_into(b));
        let h = IfAddrMsg::decode(&payload).expect("decode");
        assert_eq!(
            (h.family(), h.prefix_len(), h.flags(), h.scope(), h.index()),
            (10, 64, 0x02, 0, 1)
        );
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].1, a6.octets().to_vec());

        let lo = AddressSpec::new(
            ifx(1),
            IpPrefix::new(v4(127, 0, 0, 2), 8).expect("prefix"),
            AddrScope::Host,
        );
        let (payload, _) = build(RTM_NEWADDR, IFADDRMSG_LEN, |b| lo.encode_into(b));
        assert_eq!(IfAddrMsg::decode(&payload).expect("decode").scope(), 254);
    }

    /// NET-11・TASK-136.4 AC2: default route（0.0.0.0/0 via gateway）は RTA_DST を持たない。
    #[test]
    fn default_route_via_gateway() {
        let spec = RouteSpec::new(
            IpPrefix::default_v4(),
            RouteNextHop::Gateway {
                gateway: v4(192, 0, 2, 1),
                oif: Some(ifx(2)),
            },
        )
        .expect("spec");
        let (payload, attrs) = build(RTM_NEWROUTE, RTMSG_LEN, |b| spec.encode_into(b));
        assert_eq!(
            RtMsg::decode(&payload).expect("decode"),
            RtMsg::new(2, 0, 0, 0, 254, 4, 0, 1, 0)
        );
        assert_eq!(
            attrs,
            vec![
                (RTA_GATEWAY, vec![192, 0, 2, 1]),
                (RTA_OIF, 2u32.to_ne_bytes().to_vec())
            ]
        );
    }

    /// NET-11: デバイス直結の default（scope link・gateway なし）、IPv6 default、通常 route。
    #[test]
    fn device_v6_and_prefixed_routes() {
        let dev = RouteSpec::new(IpPrefix::default_v4(), RouteNextHop::Device { oif: ifx(1) })
            .expect("spec");
        let (payload, attrs) = build(RTM_NEWROUTE, RTMSG_LEN, |b| dev.encode_into(b));
        assert_eq!(RtMsg::decode(&payload).expect("decode").scope(), 253);
        assert_eq!(attrs, vec![(RTA_OIF, 1u32.to_ne_bytes().to_vec())]);

        let gw6: Ipv6Addr = "fe80::1".parse().expect("v6");
        let v6 = RouteSpec::new(
            IpPrefix::default_v6(),
            RouteNextHop::Gateway {
                gateway: IpAddr::V6(gw6),
                oif: Some(ifx(2)),
            },
        )
        .expect("spec");
        let (payload, attrs) = build(RTM_NEWROUTE, RTMSG_LEN, |b| v6.encode_into(b));
        let h = RtMsg::decode(&payload).expect("decode");
        assert_eq!((h.family(), h.scope(), h.dst_len()), (10, 0, 0));
        assert_eq!(attrs[0], (RTA_GATEWAY, gw6.octets().to_vec()));

        let net = RouteSpec::new(
            IpPrefix::new(v4(10, 1, 0, 0), 16).expect("prefix"),
            RouteNextHop::Device { oif: ifx(4) },
        )
        .expect("spec");
        let (payload, attrs) = build(RTM_NEWROUTE, RTMSG_LEN, |b| net.encode_into(b));
        assert_eq!(RtMsg::decode(&payload).expect("decode").dst_len(), 16);
        assert_eq!(attrs[0], (RTA_DST, vec![10, 1, 0, 0]));
    }

    /// NET-11: 固定ヘッダの to_bytes → decode が往復で一致する。
    #[test]
    fn header_roundtrip() {
        let a = IfAddrMsg::new(10, 64, 2, 200, 0x0102_0304);
        assert_eq!(IfAddrMsg::decode(&a.to_bytes()).expect("decode"), a);
        let r = RtMsg::new(2, 24, 0, 1, 254, 4, 253, 1, 0xdead_beef);
        assert_eq!(RtMsg::decode(&r.to_bytes()).expect("decode"), r);
    }

    /// NET-11: 不正入力は InvalidArgument、短い固定ヘッダは DataLoss。
    #[test]
    fn rejects_invalid_input() {
        let code = |e: NetError| e.code();
        assert_eq!(
            code(IpPrefix::new(v4(10, 0, 0, 1), 33).expect_err("v4")),
            NetErrorCode::InvalidArgument
        );
        assert_eq!(
            code(IpPrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 129).expect_err("v6")),
            NetErrorCode::InvalidArgument
        );
        assert_eq!(
            code(IfIndex::new(0).expect_err("zero")),
            NetErrorCode::InvalidArgument
        );
        assert_eq!(
            code(IfIndex::new(i32::MAX as u32 + 1).expect_err("big")),
            NetErrorCode::InvalidArgument
        );
        assert!(IfIndex::new(i32::MAX as u32).is_ok());
        let host = IpPrefix::new(v4(10, 1, 0, 1), 16).expect("prefix");
        assert_eq!(
            code(RouteSpec::new(host, RouteNextHop::Device { oif: ifx(1) }).expect_err("host")),
            NetErrorCode::InvalidArgument
        );
        let mismatch = RouteSpec::new(
            IpPrefix::default_v4(),
            RouteNextHop::Gateway {
                gateway: IpAddr::V6(Ipv6Addr::LOCALHOST),
                oif: None,
            },
        );
        assert_eq!(
            code(mismatch.expect_err("family")),
            NetErrorCode::InvalidArgument
        );
        assert_eq!(
            code(IfAddrMsg::decode(&[0; 7]).expect_err("short")),
            NetErrorCode::DataLoss
        );
        assert_eq!(
            code(RtMsg::decode(&[0; 11]).expect_err("short")),
            NetErrorCode::DataLoss
        );
    }

    /// NET-11: is_network の境界（非バイト境界のプレフィックス）。
    #[test]
    fn is_network_boundaries() {
        assert!(IpPrefix::new(v4(10, 0, 0, 0), 20).expect("p").is_network());
        assert!(!IpPrefix::new(v4(10, 0, 16, 1), 20).expect("p").is_network());
        assert!(!IpPrefix::new(v4(10, 0, 8, 0), 20).expect("p").is_network());
        assert!(IpPrefix::new(v4(10, 0, 0, 1), 32).expect("p").is_network());
        assert!(IpPrefix::default_v6().is_network());
    }

    /// NET-11: 要求フラグは NLM_F_CREATE | NLM_F_EXCL（0x600）。
    #[test]
    fn request_flags_are_create_excl() {
        assert_eq!(NEW_ADDR_ROUTE_FLAGS, 0x600);
    }
}
