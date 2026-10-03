//! コンテナのポート公開指定（検証済みの型）と DNAT ルールの expr 列（TASK-139.3・#316・NET-1・MS-8）。
//!
//! 呼び出し元は `crate::network::ContainerAttachSpec::with_port_publishes`（外部入力である CLI / TOML /
//! CRI 由来の公開指定を型へ落とす境界）と `crate::network::attach_container`（接続の最後に
//! ネットワーク専用 nft テーブルの `prerouting` / `output` へ投入）。ルールの形は PoC-15 と
//! TASK-138.3 / 138.4 の実機試験で実証済みのものを踏襲する。
//!
//! # ルールの形
//!
//! `ip daddr == host_addr && ip protocol == {6|17} && th dport == host_port` →
//! `dnat to container_addr:container_port`。dport だけでは照合しない。`prerouting` は bridge から
//! 出ていく転送通信も通るため、dport のみだとコンテナ発の外部宛て通信を横取りしてしまう。
//!
//! # 契約・未実装範囲（REPAIR-3）
//!
//! - `host_addr` は明示された非 loopback の unicast アドレスに限る。`0.0.0.0`（全アドレス公開）は
//!   意図しない外部公開につながり、loopback 宛ては `route_localnet` が必要になるため拒否する
//! - 同一 host アドレス・ポートの競合（コンテナ間・ネットワーク間）の検出は呼び出し側（状態レジストリ）
//!   の責務。nft は同一ルールの重複を拒否しない
//! - IPv4 のみ（静的 IPAM が IPv4 のみのため）。公開の個別解除はルールハンドルの取得経路が無く未対応
//!   （ネットワーク削除時にテーブルごと解放する。TASK-139.4）

use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use crate::error::{NetError, NetErrorCode};
use crate::nftables_rules::{
    NftCmp, NftDataValue, NftImmediate, NftNat, NftPayload, NftRegister, NftRuleExprs,
};

/// 1 コンテナあたりの公開指定の上限（バッチ長の上限 1 MiB に対して十分小さい値）。
pub const MAX_PORT_PUBLISHES: usize = 64;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

fn invalid(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

/// 公開するトランスポートプロトコル。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PortProtocol {
    /// TCP（IP プロトコル番号 6）。
    Tcp,
    /// UDP（IP プロトコル番号 17）。
    Udp,
}

impl PortProtocol {
    /// IP ヘッダーのプロトコル番号。
    pub(crate) fn number(self) -> u8 {
        match self {
            Self::Tcp => IPPROTO_TCP,
            Self::Udp => IPPROTO_UDP,
        }
    }
}

/// ポート公開 1 件（host の `host_addr:host_port` 宛ての通信をコンテナの `container_port` へ DNAT する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortPublish {
    protocol: PortProtocol,
    host_addr: Ipv4Addr,
    host_port: NonZeroU16,
    container_port: NonZeroU16,
}

impl PortPublish {
    /// 検証して作る。ポート 0、および `host_addr` が未指定（0.0.0.0）・loopback・broadcast・multicast
    /// なら `InvalidArgument`（入力値はメッセージに載せない）。
    pub fn new(
        protocol: PortProtocol,
        host_addr: Ipv4Addr,
        host_port: u16,
        container_port: u16,
    ) -> Result<Self, NetError> {
        if host_addr.is_unspecified()
            || host_addr.is_loopback()
            || host_addr.is_broadcast()
            || host_addr.is_multicast()
        {
            return Err(invalid(
                "host address must be an explicit unicast non-loopback address",
            ));
        }
        let host_port = NonZeroU16::new(host_port).ok_or_else(|| invalid("host port is zero"))?;
        let container_port =
            NonZeroU16::new(container_port).ok_or_else(|| invalid("container port is zero"))?;
        Ok(Self {
            protocol,
            host_addr,
            host_port,
            container_port,
        })
    }

    /// プロトコル。
    pub fn protocol(&self) -> PortProtocol {
        self.protocol
    }

    /// 公開する host 側のアドレス。
    pub fn host_addr(&self) -> Ipv4Addr {
        self.host_addr
    }

    /// 公開する host 側のポート。
    pub fn host_port(&self) -> u16 {
        self.host_port.get()
    }

    /// 転送先のコンテナ側ポート。
    pub fn container_port(&self) -> u16 {
        self.container_port.get()
    }

    /// 同じ host 側の受け口（プロトコル・アドレス・ポート）かどうか。重複検出に使う。
    pub(crate) fn same_listener(&self, other: &Self) -> bool {
        self.protocol == other.protocol
            && self.host_addr == other.host_addr
            && self.host_port == other.host_port
    }

    /// `container` 宛ての DNAT ルールの expr 列を組み立てる（モジュール doc「ルールの形」）。
    pub(crate) fn dnat_rule_exprs(&self, container: Ipv4Addr) -> Result<NftRuleExprs, NetError> {
        let r1 = NftRegister::REG_1;
        let r2 = NftRegister::REG_2;
        let mut exprs = NftRuleExprs::new();
        exprs.push(NftPayload::ipv4_daddr(r1)?.to_expr()?)?;
        exprs.push(NftCmp::eq(r1, NftDataValue::new(&self.host_addr.octets())?)?.to_expr()?)?;
        exprs.push(NftPayload::ipv4_protocol(r1)?.to_expr()?)?;
        exprs.push(NftCmp::eq(r1, NftDataValue::new(&[self.protocol.number()])?)?.to_expr()?)?;
        exprs.push(NftPayload::transport_dport(r1)?.to_expr()?)?;
        exprs.push(
            NftCmp::eq(r1, NftDataValue::new(&self.host_port.get().to_be_bytes())?)?.to_expr()?,
        )?;
        exprs.push(NftImmediate::ipv4_addr(r1, container)?.to_expr()?)?;
        exprs.push(NftImmediate::port(r2, self.container_port.get())?.to_expr()?)?;
        exprs.push(NftNat::dnat_ipv4(r1, Some(r2))?.to_expr()?)?;
        Ok(exprs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nftables_rules::NatType;

    fn a(x: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(x)
    }

    /// NET-1・TASK-139.3: 非 loopback の unicast は受理し、未指定・loopback・broadcast・multicast・
    /// ポート 0 は `InvalidArgument`。
    #[test]
    fn net1_port_publish_validation() {
        let ok = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 8080, 80).unwrap();
        assert_eq!(ok.host_addr(), a([192, 0, 2, 10]));
        assert_eq!(ok.host_port(), 8080);
        assert_eq!(ok.container_port(), 80);
        for bad in [
            a([0, 0, 0, 0]),
            a([127, 0, 0, 1]),
            a([127, 255, 255, 254]),
            a([255, 255, 255, 255]),
            a([224, 0, 0, 1]),
        ] {
            let e = PortPublish::new(PortProtocol::Udp, bad, 8080, 80).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{bad}");
        }
        for (hp, cp) in [(0, 80), (8080, 0)] {
            let e = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), hp, cp).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        }
    }

    /// NET-1・TASK-139.3: expr 列の具体値（daddr・プロトコル番号・dport の big endian・転送先・nat 種別）。
    #[test]
    fn net1_dnat_exprs_have_expected_values() {
        for (proto, num) in [(PortProtocol::Tcp, 6u8), (PortProtocol::Udp, 17u8)] {
            let p = PortPublish::new(proto, a([192, 0, 2, 10]), 0x1f90, 80).unwrap();
            let exprs = p.dnat_rule_exprs(a([10, 89, 0, 2])).unwrap();
            let e = exprs.exprs();
            assert_eq!(e.len(), 9);
            let names: Vec<&str> = e.iter().map(|x| x.name().as_str()).collect();
            assert_eq!(
                names,
                [
                    "payload",
                    "cmp",
                    "payload",
                    "cmp",
                    "payload",
                    "cmp",
                    "immediate",
                    "immediate",
                    "nat"
                ]
            );
            assert_eq!(
                NftCmp::from_expr(&e[1]).unwrap().data().as_bytes(),
                [192, 0, 2, 10]
            );
            assert_eq!(NftCmp::from_expr(&e[3]).unwrap().data().as_bytes(), [num]);
            assert_eq!(
                NftCmp::from_expr(&e[5]).unwrap().data().as_bytes(),
                [0x1f, 0x90]
            );
            let nat = NftNat::from_expr(&e[8]).unwrap();
            assert_eq!(nat.nat_type(), NatType::Dnat);
        }
    }

    /// NET-1・TASK-139.3: 受け口の同一判定はプロトコル・アドレス・ポートの 3 つ組。
    #[test]
    fn net1_same_listener_compares_triple() {
        let t = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 80, 80).unwrap();
        let u = PortPublish::new(PortProtocol::Udp, a([192, 0, 2, 10]), 80, 80).unwrap();
        let t2 = PortPublish::new(PortProtocol::Tcp, a([192, 0, 2, 10]), 80, 8080).unwrap();
        assert!(t.same_listener(&t2));
        assert!(!t.same_listener(&u));
    }
}
