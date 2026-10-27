//! attach の巻き戻しの失敗を作る故障注入（試験専用。NET-1・REPAIR-3・REPAIR-4・#2971）。
//!
//! 公開 API だけでは「前進の途中で失敗し、さらに巻き戻し（host 側 veth の削除・netns の unpin）も失敗して
//! 取り残しが出る」場面を作れない。そのため `AttachOps` を包むデコレータ `FaultyAttachOps` で、前進側の
//! 特定の段と、巻き戻しの 2 操作（`delete_link`・`unpin_netns`）を失敗させる。
//!
//! # 位置づけと境界
//! - 呼び出し元は単体試験（`network::attach_tests`・`network::delete::tests`）と、feature
//!   `attach-fault-test-support` が有効な Linux の結合試験 `network_attach_privileged` だけ。製品の既定ビルドには
//!   入らない（モジュール自体が `cfg(test)` または feature の裏。リリースビルドで feature が有効なら
//!   `lib.rs` の `compile_error!` で止める）。
//! - 注入するのは失敗だけで、`reclaim_failed_attach` の所有の照合（別名・master・pin の識別子・`.owned` 記録）には
//!   一切手を入れない。回収側の fail-closed は本番と同じ。
//! - 対象は `attach_container` の経路だけ。事前作成の netns の経路（`attach_prepared_*`）は netns を unpin
//!   しないため対象外。

use std::net::Ipv4Addr;
use std::path::Path;

use super::{
    AttachOps, AttachStep, EndpointId, NetnsFailure, NftApplyFailure, PortPublish,
    PublishedListeners, RuleHandlePair, UnpinFailure,
};
use crate::error::{NetError, NetErrorCode};
use crate::netlink_route::{IfIndex, IfName, IpPrefix};
use crate::nftables_batch::NftName;

/// 前進側で失敗させる段。1 つの `AttachOps` 操作だけに対応する段に限る（`ConfigureLoopback` と `PeerUp` は
/// どちらも `netns_set_up`、`ResolveIndex` と `ResolvePeer` はどちらも `link_index` を通り区別できないため含めない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttachFaultPoint {
    /// host 側 veth への所有トークン付与（`set_owner_token`）。
    SetOwnerToken,
    /// bridge への接続（`set_master`）。
    SetMaster,
    /// host 側の up（`set_up`）。
    SetUp,
    /// peer の netns への移動（`move_to_netns`）。
    MoveToNetns,
    /// netns 内の peer へのアドレス付与（`netns_add_address`）。IPAM 払い出し後の段。
    AddAddress,
    /// netns 内の default route 設定（`netns_add_default_route`）。IPAM 払い出し後の段。
    DefaultRoute,
}

impl AttachFaultPoint {
    /// この故障点で失敗したときに報告される `AttachStep`。
    pub fn step(self) -> AttachStep {
        match self {
            Self::SetOwnerToken => AttachStep::SetOwnerToken,
            Self::SetMaster => AttachStep::SetMaster,
            Self::SetUp => AttachStep::SetUp,
            Self::MoveToNetns => AttachStep::MoveToNetns,
            Self::AddAddress => AttachStep::AddAddress,
            Self::DefaultRoute => AttachStep::DefaultRoute,
        }
    }
}

/// 故障の指定。前進側の失敗は常に `Internal`（確定的な失敗）。巻き戻しの失敗は呼び出し側がコードを選ぶ
/// （`Internal` なら資源は `Present`、`Timeout` なら結果不明の `Unknown` として報告される）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AttachFault {
    point: AttachFaultPoint,
    veth_delete: Option<NetErrorCode>,
    unpin: Option<NetErrorCode>,
}

impl AttachFault {
    /// `point` の段で前進側を失敗させる（巻き戻しは失敗させない）。
    pub fn new(point: AttachFaultPoint) -> Self {
        Self {
            point,
            veth_delete: None,
            unpin: None,
        }
    }

    /// 巻き戻しの host 側 veth の削除（`delete_link`）を `code` で失敗させる。
    #[must_use]
    pub fn with_veth_delete_failure(mut self, code: NetErrorCode) -> Self {
        self.veth_delete = Some(code);
        self
    }

    /// 巻き戻しの netns の unpin を `code` で失敗させる（pin のマウントと所有記録は残る）。
    #[must_use]
    pub fn with_unpin_failure(mut self, code: NetErrorCode) -> Self {
        self.unpin = Some(code);
        self
    }
}

fn injected(code: NetErrorCode) -> NetError {
    NetError::new(code, "injected attach fault (test support)")
}

/// `inner` の操作をすべて委譲し、`fault` の指定した操作だけ内側を呼ばずに失敗させるデコレータ。
pub(crate) struct FaultyAttachOps<O> {
    pub(crate) inner: O,
    pub(crate) fault: AttachFault,
}

impl<O> FaultyAttachOps<O> {
    fn forward_fails(&self, point: AttachFaultPoint) -> Result<(), NetError> {
        if self.fault.point == point {
            Err(injected(NetErrorCode::Internal))
        } else {
            Ok(())
        }
    }
}

impl<O: AttachOps> AttachOps for FaultyAttachOps<O> {
    type Netns = O::Netns;

    fn create_netns(
        &self,
        dir: &Path,
        id: &EndpointId,
    ) -> Result<(Self::Netns, (u64, u64)), NetnsFailure> {
        self.inner.create_netns(dir, id)
    }
    fn unpin_netns(&self, ns: Self::Netns) -> Result<(), UnpinFailure<Self::Netns>> {
        match self.fault.unpin {
            // ハンドルはそのまま返す（呼び出し側が drop し、pin のマウントと所有記録は残る）。
            Some(code) => Err(UnpinFailure {
                error: injected(code),
                netns: ns,
            }),
            None => self.inner.unpin_netns(ns),
        }
    }
    fn create_veth(&self, host: &IfName, peer: &IfName) -> Result<(), NetError> {
        self.inner.create_veth(host, peer)
    }
    fn link_index(&self, name: &IfName) -> Result<IfIndex, NetError> {
        self.inner.link_index(name)
    }
    fn owned_bridge_index(&self, name: &IfName, token: &str) -> Result<IfIndex, NetError> {
        self.inner.owned_bridge_index(name, token)
    }
    fn set_owner_token(&self, link: IfIndex, token: &str) -> Result<(), NetError> {
        self.forward_fails(AttachFaultPoint::SetOwnerToken)?;
        self.inner.set_owner_token(link, token)
    }
    fn set_master(&self, link: IfIndex, master: IfIndex) -> Result<(), NetError> {
        self.forward_fails(AttachFaultPoint::SetMaster)?;
        self.inner.set_master(link, master)
    }
    fn set_up(&self, link: IfIndex) -> Result<(), NetError> {
        self.forward_fails(AttachFaultPoint::SetUp)?;
        self.inner.set_up(link)
    }
    fn move_to_netns(&self, link: IfIndex, ns: &Self::Netns) -> Result<(), NetError> {
        self.forward_fails(AttachFaultPoint::MoveToNetns)?;
        self.inner.move_to_netns(link, ns)
    }
    fn delete_link(&self, link: IfIndex) -> Result<(), NetError> {
        match self.fault.veth_delete {
            Some(code) => Err(injected(code)),
            None => self.inner.delete_link(link),
        }
    }
    fn netns_link_index(&self, ns: &Self::Netns, name: &IfName) -> Result<IfIndex, NetError> {
        self.inner.netns_link_index(ns, name)
    }
    fn netns_set_up(&self, ns: &Self::Netns, link: IfIndex) -> Result<(), NetError> {
        self.inner.netns_set_up(ns, link)
    }
    fn netns_add_address(
        &self,
        ns: &Self::Netns,
        link: IfIndex,
        addr: IpPrefix,
    ) -> Result<(), NetError> {
        self.forward_fails(AttachFaultPoint::AddAddress)?;
        self.inner.netns_add_address(ns, link, addr)
    }
    fn netns_add_default_route(
        &self,
        ns: &Self::Netns,
        gateway: Ipv4Addr,
        oif: IfIndex,
    ) -> Result<(), NetError> {
        self.forward_fails(AttachFaultPoint::DefaultRoute)?;
        self.inner.netns_add_default_route(ns, gateway, oif)
    }
    fn release_netns_socket(&self, ns: &mut Self::Netns) {
        self.inner.release_netns_socket(ns);
    }
    fn published_listeners(&self) -> Result<PublishedListeners, NetError> {
        self.inner.published_listeners()
    }
    fn publish_ports(
        &self,
        table: &NftName,
        container: Ipv4Addr,
        ports: &[PortPublish],
    ) -> Result<Vec<RuleHandlePair>, NftApplyFailure> {
        self.inner.publish_ports(table, container, ports)
    }
}

/// `attach_container` に故障注入を載せた版（結合試験 `network_attach_privileged` 専用。NET-1・#2971）。
/// 製品の経路ではない。`CAP_NET_ADMIN`・`CAP_SYS_ADMIN` の要件は `attach_container` と同じ。
#[cfg(all(feature = "attach-fault-test-support", target_os = "linux"))]
pub fn attach_container_with_fault_for_test(
    route: &crate::netlink_route::NetlinkRouteSocket,
    nft: &crate::nftables_batch::NetlinkNetfilterSocket,
    spec: &super::ContainerAttachSpec,
    ipam: &mut super::StaticIpam,
    ports: &mut super::PortRegistry,
    timeout: std::time::Duration,
    fault: AttachFault,
) -> Result<super::AttachedContainer<crate::netns::ContainerNetns>, super::ContainerAttachError> {
    super::attach_container_with(
        &FaultyAttachOps {
            inner: super::LinuxAttachOps {
                route,
                nft,
                timeout,
            },
            fault,
        },
        spec,
        ipam,
        ports,
    )
}

/// 単体試験が共有する、世代・トークン固定の接続（ネットワーク `web`）の請求書の記録。
/// Fake の経路では pin が実在しないため `pin=-`。attach 側が実際に作る請求書と一致することを照合し、
/// 回収側（`delete::tests`）はこの文字列を復号して `reclaim_failed_attach_with` へ渡す。
#[cfg(test)]
pub(crate) fn expected_record(endpoint: &str, veth: bool, netns: bool, quarantine: bool) -> String {
    format!(
        "fandhe-net-attach-claim v1\nnetwork=web\nendpoint={endpoint}\ntoken=fandhe-net:web:1:0:0\ngeneration=0123456789abcdef0123456789abcdef\nveth={}\nnetns={}\npin=-\nquarantine={}\n",
        u8::from(veth),
        u8::from(netns),
        u8::from(quarantine),
    )
}
