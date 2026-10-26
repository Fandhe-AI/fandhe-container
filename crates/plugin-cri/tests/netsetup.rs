//! `NetsetupNetwork`（netsetup の操作単位への写像。TASK-114.4・#460・MS-4）と `pod_network` の振る舞い試験。
//!
//! カーネルを触らない fake の `NetsetupBackend` で、`NetworkPlugin` の契約 6〜9・12 の分岐と、
//! PodSandbox 作成 → コンテナ作成 → PodSandbox 削除で net の操作が正しい順序で呼ばれることを
//! 具体値で照合する（PLUG-1・CRI-2・CRI-7・NET-1〜NET-3）。3 OS の既定集合で動く（root 不要）。

use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};

use fandhe_container_core::traits::{
    AttachRequest, ContainerId, CreateNetnsRequest, CreateNetworkRequest, DeleteNetworkRequest,
    DetachRequest, ErrorCode, IpCidr, NetworkName, NetworkPlugin, Protocol, PublishPortRequest,
    TraitError, UnpublishPortRequest,
};
use fandhe_container_net::netlink_route::IpPrefix;
use fandhe_container_net::network::{EndpointId, NetworkName as NetName, PortPublish};
use fandhe_container_plugin_cri::netsetup::{
    AttachFailure, AttachOutcome, CreateFailure, DeleteFailure, MAX_NETWORKS,
    MSG_RECOVERED_NETWORK_UNTRACKED, NetsetupBackend, NetsetupContainer, NetsetupNetwork,
    PublishFailure, RECLAIM_DIR, ReclaimStore,
};
use fandhe_container_plugin_cri::pod_network;

#[derive(Debug)]
struct FakeContainer(String);

impl NetsetupContainer for FakeContainer {
    fn endpoint_id(&self) -> &str {
        &self.0
    }
}

#[derive(Default)]
struct Script {
    calls: Vec<String>,
    fail_create: bool,
    /// create 失敗時に取り残す資源の件数。
    create_leftover: usize,
    /// encode_claim を永続化しない（None）にするか。
    no_encode: bool,
    /// 次の reclaim_failed_create を成功させるか。
    reclaim_ok: bool,
    /// create 失敗時に回収用の請求書を出さない（所有を証明できない取り残し）か。
    no_claim: bool,
    fail_attach: bool,
    /// attach 失敗時に巻き戻しで取り残す資源の件数。
    attach_leftover: usize,
    /// attach 失敗時にバックエンドが準備済み netns を保持している印を立てるか。
    attach_retained: bool,
    /// attach の取り残しに回収用の請求書を付けるか（所有を証明できる取り残し）。
    attach_claim: bool,
    /// attach の請求書を永続化しない（None）にするか。
    no_attach_encode: bool,
    /// 次の reclaim_failed_attach を成功させるか。
    reclaim_attach_ok: bool,
    /// attach の請求書に quarantine（プロセス内の保持）が含まれる模型にするか。
    attach_quarantine: bool,
    /// 次の delete_network を失敗させ、渡されたハンドルを全部 retry に返す回数。
    fail_delete: u32,
    /// netns の事前作成・解放の呼び出し列（`calls` とは別に持ち、既存の期待列を変えない）。
    netns_calls: Vec<String>,
    /// create_netns を失敗させるか。
    fail_create_netns: bool,
    /// create_netns の失敗時に取り残す pin の件数。
    create_netns_leftover: usize,
    /// create_netns の失敗でバックエンドがハンドルを保持している印を立てるか。
    create_netns_retained: bool,
    /// 次の release_netns を失敗させる回数。
    fail_release: u32,
    /// このホストポートの publish_port を失敗させる（0 は失敗させない）。
    fail_publish_port: u16,
    /// 失敗させる publish_port の結果を不明（DNAT ルールが入った可能性）にするか。
    publish_unknown: bool,
    /// このホストポートの unpublish_port を失敗させる（0 は失敗させない）。
    fail_unpublish_port: u16,
    /// 失敗させる unpublish_port の結果を不明（ルールが残った可能性）にするか。
    unpublish_unknown: bool,
}

#[derive(Clone, Default)]
struct Fake(Arc<Mutex<Script>>);

impl Fake {
    fn calls(&self) -> Vec<String> {
        self.0.lock().expect("lock").calls.clone()
    }
    fn netns_calls(&self) -> Vec<String> {
        self.0.lock().expect("lock").netns_calls.clone()
    }
}

impl NetsetupBackend for Fake {
    type Network = String;
    type Container = FakeContainer;
    type FailedCreate = String;
    /// (ネットワーク名, endpoint)。
    type FailedAttach = (String, String);

    fn create_network(
        &self,
        name: &NetName,
        gateway: IpPrefix,
    ) -> Result<String, CreateFailure<String>> {
        let mut s = self.0.lock().expect("lock");
        s.calls.push(format!(
            "create_network {} {}/{}",
            name.as_str(),
            gateway.addr(),
            gateway.prefix_len()
        ));
        if s.fail_create {
            return Err(CreateFailure {
                error: TraitError::new(ErrorCode::Internal, "create failed"),
                leftover: s.create_leftover,
                reclaim: (!s.no_claim).then(|| format!("claim-{}", name.as_str())),
            });
        }
        Ok(name.as_str().to_owned())
    }

    fn encode_claim(&self, claim: &String) -> Option<String> {
        let s = self.0.lock().expect("lock");
        (!s.no_encode).then(|| format!("rec:{claim}"))
    }

    fn decode_claim(&self, name: &NetName, record: &str) -> Result<String, TraitError> {
        let claim = record
            .strip_prefix("rec:")
            .filter(|c| *c == format!("claim-{}", name.as_str()))
            .ok_or_else(|| TraitError::new(ErrorCode::InvalidArgument, "bad record"))?;
        Ok(claim.to_owned())
    }

    fn reclaim_failed_create(&self, name: &NetName, claim: &String) -> Result<(), TraitError> {
        let mut s = self.0.lock().expect("lock");
        s.calls.push(format!("reclaim {} {claim}", name.as_str()));
        if s.reclaim_ok {
            Ok(())
        } else {
            Err(TraitError::new(ErrorCode::Internal, "reclaim failed"))
        }
    }

    fn create_netns(
        &self,
        _network: &mut String,
        endpoint: &EndpointId,
    ) -> Result<(), AttachFailure> {
        let mut s = self.0.lock().expect("lock");
        s.netns_calls
            .push(format!("create_netns {}", endpoint.as_str()));
        if s.fail_create_netns {
            return Err(AttachFailure {
                error: TraitError::new(ErrorCode::Internal, "create_netns failed"),
                leftover: s.create_netns_leftover,
                netns_retained: s.create_netns_retained,
                reclaim: None,
            });
        }
        Ok(())
    }

    fn release_netns(&self, endpoint: &EndpointId) -> Result<(), TraitError> {
        let mut s = self.0.lock().expect("lock");
        s.netns_calls
            .push(format!("release_netns {}", endpoint.as_str()));
        if s.fail_release > 0 {
            s.fail_release -= 1;
            return Err(TraitError::new(ErrorCode::Internal, "release failed"));
        }
        Ok(())
    }

    fn encode_attach_claim(&self, claim: &(String, String)) -> Option<String> {
        let s = self.0.lock().expect("lock");
        (!s.no_attach_encode).then(|| format!("arec:{}:{}", claim.0, claim.1))
    }

    fn decode_attach_claim(
        &self,
        endpoint: &EndpointId,
        record: &str,
    ) -> Result<(NetName, (String, String)), TraitError> {
        let bad = || TraitError::new(ErrorCode::InvalidArgument, "bad record");
        let (net, ep) = record
            .strip_prefix("arec:")
            .and_then(|r| r.split_once(':'))
            .filter(|(_, ep)| *ep == endpoint.as_str())
            .ok_or_else(bad)?;
        let name = NetName::new(net).map_err(|_| bad())?;
        Ok((name, (net.to_owned(), ep.to_owned())))
    }

    fn attach_claim_quarantine_remainder(
        &self,
        claim: &(String, String),
    ) -> Option<(String, String)> {
        let s = self.0.lock().expect("lock");
        s.attach_quarantine.then(|| claim.clone())
    }

    fn reclaim_failed_attach(&self, claim: &(String, String)) -> Result<(), TraitError> {
        let mut s = self.0.lock().expect("lock");
        s.calls
            .push(format!("reclaim_attach {} {}", claim.0, claim.1));
        if s.reclaim_attach_ok {
            Ok(())
        } else {
            Err(TraitError::new(
                ErrorCode::Internal,
                "reclaim attach failed",
            ))
        }
    }

    fn attach(
        &self,
        network: &mut String,
        endpoint: &EndpointId,
    ) -> Result<AttachOutcome<FakeContainer>, AttachFailure<(String, String)>> {
        let mut s = self.0.lock().expect("lock");
        s.calls
            .push(format!("attach {network} {}", endpoint.as_str()));
        if s.fail_attach {
            return Err(AttachFailure {
                error: TraitError::new(ErrorCode::Internal, "attach failed"),
                leftover: s.attach_leftover,
                netns_retained: s.attach_retained,
                reclaim: s
                    .attach_claim
                    .then(|| (network.clone(), endpoint.as_str().to_owned())),
            });
        }
        Ok(AttachOutcome {
            container: FakeContainer(endpoint.as_str().to_owned()),
            address: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 2)), 24).expect("prefix"),
        })
    }

    fn publish_port(
        &self,
        network: &mut String,
        container: &FakeContainer,
        publish: &PortPublish,
    ) -> Result<(), PublishFailure> {
        let mut s = self.0.lock().expect("lock");
        s.calls.push(format!(
            "publish_port {network} {} {}:{}->{}",
            container.0,
            publish.host_addr(),
            publish.host_port(),
            publish.container_port()
        ));
        if s.fail_publish_port == publish.host_port() {
            return Err(PublishFailure {
                error: TraitError::new(ErrorCode::Internal, "publish failed"),
                rules_unknown: s.publish_unknown,
            });
        }
        Ok(())
    }

    fn unpublish_port(
        &self,
        network: &mut String,
        container: &FakeContainer,
        publish: &PortPublish,
    ) -> Result<(), PublishFailure> {
        let mut s = self.0.lock().expect("lock");
        s.calls.push(format!(
            "unpublish_port {network} {} {}:{}->{}",
            container.0,
            publish.host_addr(),
            publish.host_port(),
            publish.container_port()
        ));
        if s.fail_unpublish_port == publish.host_port() {
            return Err(PublishFailure {
                error: TraitError::new(ErrorCode::Internal, "unpublish failed"),
                rules_unknown: s.unpublish_unknown,
            });
        }
        Ok(())
    }

    fn delete_network(
        &self,
        network: &mut String,
        containers: Vec<FakeContainer>,
    ) -> Result<(), DeleteFailure<FakeContainer>> {
        let mut s = self.0.lock().expect("lock");
        let mut ids: Vec<&str> = containers.iter().map(|c| c.0.as_str()).collect();
        ids.sort_unstable();
        s.calls
            .push(format!("delete_network {network} [{}]", ids.join(",")));
        if s.fail_delete > 0 {
            s.fail_delete -= 1;
            return Err(DeleteFailure {
                error: TraitError::new(ErrorCode::Internal, "delete failed"),
                retry: containers,
            });
        }
        Ok(())
    }
}

fn nname(s: &str) -> NetworkName {
    NetworkName::new(s).expect("network name")
}

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).expect("container id")
}

fn subnet() -> IpCidr {
    IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 0)), 24).expect("subnet")
}

fn plugin() -> (NetsetupNetwork<Fake>, Fake) {
    let fake = Fake::default();
    (NetsetupNetwork::new(fake.clone()), fake)
}

/// 受け入れ条件 1〜3（CRI-7・NET-1〜NET-3）: Pod 作成 → コンテナ作成 → Pod 削除の呼び出し順と応答値。
#[test]
fn cri7_pod_lifecycle_calls_netsetup_in_order() {
    let (net, fake) = plugin();
    let st = pod_network::set_up_pod(&net, &nname("pod1"), subnet()).expect("set_up_pod");
    assert_eq!(st.name().as_str(), "pod1");
    assert_eq!(st.subnet(), subnet());

    let resp = pod_network::set_up_container(&net, &nname("pod1"), &cid("c1")).expect("container");
    assert_eq!(
        resp.address(),
        IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 2)), 24).expect("cidr")
    );
    assert_eq!(
        resp.gateway(),
        Some(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 1)))
    );

    pod_network::tear_down_pod(&net, &nname("pod1")).expect("tear_down");
    assert_eq!(
        fake.calls(),
        vec![
            "create_network pod1 10.89.0.1/24",
            "attach pod1 c1",
            "delete_network pod1 [c1]",
        ]
    );
    // 削除後は同名を作り直せる（記録が消えている）。
    pod_network::set_up_pod(&net, &nname("pod1"), subnet()).expect("recreate");
}

/// 契約 6: バックエンドの作成失敗は状態を変えず、再試行できる。
#[test]
fn contract6_failed_create_keeps_no_state() {
    let (net, fake) = plugin();
    fake.0.lock().expect("lock").fail_create = true;
    let e = pod_network::set_up_pod(&net, &nname("pod1"), subnet()).expect_err("fail");
    assert_eq!(e.code(), ErrorCode::Internal);
    fake.0.lock().expect("lock").fail_create = false;
    pod_network::set_up_pod(&net, &nname("pod1"), subnet()).expect("retry");
}

/// 契約 6: attach 失敗後は記録を戻すので、同じコンテナの再試行が AlreadyExists で恒久失敗しない。
#[test]
fn contract6_failed_attach_allows_retry() {
    let (net, fake) = plugin();
    pod_network::set_up_pod(&net, &nname("pod1"), subnet()).expect("pod");
    fake.0.lock().expect("lock").fail_attach = true;
    let e = pod_network::set_up_container(&net, &nname("pod1"), &cid("c1")).expect_err("fail");
    assert_eq!(e.message(), "attach failed");
    fake.0.lock().expect("lock").fail_attach = false;
    pod_network::set_up_container(&net, &nname("pod1"), &cid("c1")).expect("retry");
}

/// 契約 7: 同名ネットワーク・同一コンテナの netns の二重作成は AlreadyExists。
#[test]
fn contract7_duplicates_are_rejected() {
    let (net, _) = plugin();
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("a");
    assert_eq!(
        pod_network::set_up_pod(&net, &nname("a"), subnet())
            .expect_err("dup")
            .code(),
        ErrorCode::AlreadyExists
    );
    pod_network::set_up_pod(&net, &nname("b"), subnet()).expect("b");
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
        .expect("netns");
    // 別ネットワークでも同じコンテナは AlreadyExists。
    let e = net
        .create_netns(&CreateNetnsRequest::new(nname("b"), cid("c1")))
        .expect_err("dup");
    assert_eq!(e.code(), ErrorCode::AlreadyExists);
}

/// 契約 8・12: attach の判定順（NotFound → NotFound → FailedPrecondition。attach 済みは最初に AlreadyExists）。
#[test]
fn contract8_12_attach_precondition_order() {
    let (net, _) = plugin();
    // ネットワーク未作成。
    let e = net
        .attach(&AttachRequest::new(nname("a"), cid("c1")))
        .expect_err("no net");
    assert_eq!(e.code(), ErrorCode::NotFound);
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("a");
    pod_network::set_up_pod(&net, &nname("b"), subnet()).expect("b");
    // netns 未登録。
    let e = net
        .attach(&AttachRequest::new(nname("a"), cid("c1")))
        .expect_err("no netns");
    assert_eq!(e.code(), ErrorCode::NotFound);
    // 紐付けネットワーク不一致。
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
        .expect("netns");
    let e = net
        .attach(&AttachRequest::new(nname("b"), cid("c1")))
        .expect_err("mismatch");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    // 静的アドレスは未対応。
    let req = AttachRequest::new(nname("a"), cid("c1"))
        .with_address(IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 9)), 24).expect("addr"));
    assert_eq!(
        net.attach(&req).expect_err("static").code(),
        ErrorCode::Unimplemented
    );
    net.attach(&AttachRequest::new(nname("a"), cid("c1")))
        .expect("attach");
    // 契約 12: attach 済みはネットワークが未作成でも最初に AlreadyExists。
    for n in ["a", "b", "ghost"] {
        let e = net
            .attach(&AttachRequest::new(nname(n), cid("c1")))
            .expect_err("again");
        assert_eq!(e.code(), ErrorCode::AlreadyExists, "network {n}");
    }
}

/// 契約 8: 未 attach の detach は記録を消して Ok、二重 detach は NotFound、attach 済みは Unimplemented。
#[test]
fn contract8_detach_behaviour() {
    let (net, fake) = plugin();
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("a");
    pod_network::set_up_pod(&net, &nname("b"), subnet()).expect("b");
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
        .expect("netns");
    assert_eq!(
        net.detach(&DetachRequest::new(nname("b"), cid("c1")))
            .expect_err("mismatch")
            .code(),
        ErrorCode::FailedPrecondition
    );
    net.detach(&DetachRequest::new(nname("a"), cid("c1")))
        .expect("detach");
    assert_eq!(
        net.detach(&DetachRequest::new(nname("a"), cid("c1")))
            .expect_err("twice")
            .code(),
        ErrorCode::NotFound
    );
    pod_network::set_up_container(&net, &nname("a"), &cid("c2")).expect("c2");
    assert_eq!(
        net.detach(&DetachRequest::new(nname("a"), cid("c2")))
            .expect_err("attached")
            .code(),
        ErrorCode::Unimplemented
    );
    // 状態は変わらず、削除時に c2 が渡される。
    pod_network::tear_down_pod(&net, &nname("a")).expect("delete");
    assert_eq!(
        fake.calls().last().map(String::as_str),
        Some("delete_network a [c2]")
    );
}

/// 契約 9: 削除に失敗したらハンドルを保持し、再試行で同じハンドルが渡って成功する。
#[test]
fn contract9_failed_delete_is_retryable() {
    let (net, fake) = plugin();
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("a");
    pod_network::set_up_container(&net, &nname("a"), &cid("c1")).expect("c1");
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c2")))
        .expect("c2 record only");
    fake.0.lock().expect("lock").fail_delete = 1;
    let e = pod_network::tear_down_pod(&net, &nname("a")).expect_err("fail");
    assert_eq!(e.code(), ErrorCode::Internal);
    // 契約 9: 部分削除済みのネットワークへは、完了まで新規登録・接続を許さない。
    assert_eq!(
        net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c3")))
            .expect_err("deleting")
            .code(),
        ErrorCode::FailedPrecondition
    );
    assert_eq!(
        net.attach(&AttachRequest::new(nname("a"), cid("c2")))
            .expect_err("deleting")
            .code(),
        ErrorCode::FailedPrecondition
    );
    let resp = pod_network::tear_down_pod(&net, &nname("a")).expect("retry");
    assert_eq!(
        resp,
        fandhe_container_core::traits::DeleteNetworkResponse::new()
    );
    let calls = fake.calls();
    assert_eq!(
        calls[calls.len() - 2..],
        ["delete_network a [c1]", "delete_network a [c1]"]
    );
    assert_eq!(
        pod_network::tear_down_pod(&net, &nname("a"))
            .expect_err("gone")
            .code(),
        ErrorCode::NotFound
    );
}

fn publish_req(
    network: &str,
    container: &str,
    host_port: u16,
    ip: Option<IpAddr>,
) -> PublishPortRequest {
    let req = PublishPortRequest::new(
        nname(network),
        cid(container),
        NonZeroU16::new(host_port).expect("port"),
        NonZeroU16::new(80).expect("port"),
        Protocol::Tcp,
    );
    match ip {
        Some(ip) => req.with_host_ip(ip),
        None => req,
    }
}

fn ip4() -> Option<IpAddr> {
    Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
}

/// ネットワークを作り、コンテナを 1 件 attach 済みにする。
fn attached(net: &NetsetupNetwork<Fake>, network: &str, container: &str) {
    pod_network::set_up_pod(net, &nname(network), subnet()).expect("pod");
    pod_network::set_up_container(net, &nname(network), &cid(container)).expect("container");
}

/// NET-4（#2676）: attach 済みコンテナの publish_port は host_ip つきの応答を返し、バックエンドへ具体値を渡す。
#[test]
fn net4_publish_port_publishes_and_echoes_host_ip() {
    let (net, fake) = plugin();
    attached(&net, "a", "c1");
    let m = net
        .publish_port(&publish_req("a", "c1", 8080, ip4()))
        .expect("publish");
    assert_eq!(m.host_ip(), ip4());
    assert_eq!(m.host_port().get(), 8080);
    assert_eq!(m.container_port().get(), 80);
    assert_eq!(
        fake.calls().last().unwrap(),
        "publish_port a c1 192.0.2.10:8080->80"
    );
}

/// 契約 8: ネットワーク未作成と未 attach は NotFound、別ネットワークは FailedPrecondition。
#[test]
fn net4_publish_port_requires_attached_container_in_same_network() {
    let (net, fake) = plugin();
    let e = net
        .publish_port(&publish_req("a", "c1", 8080, ip4()))
        .expect_err("no network");
    assert_eq!(e.code(), ErrorCode::NotFound);
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("pod");
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
        .expect("netns");
    let e = net
        .publish_port(&publish_req("a", "c1", 8080, ip4()))
        .expect_err("not attached");
    assert_eq!(e.code(), ErrorCode::NotFound);
    attached(&net, "b", "c2");
    let e = net
        .publish_port(&publish_req("a", "c2", 8080, ip4()))
        .expect_err("other network");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert!(!fake.calls().iter().any(|c| c.starts_with("publish_port")));
}

/// 契約 11: 別ネットワーク・別 host_ip でも同じ (host_port, protocol) は AlreadyExists。
/// delete_network の後は再公開できる。
#[test]
fn net4_publish_port_rejects_duplicate_host_port_across_networks() {
    let (net, _fake) = plugin();
    attached(&net, "a", "c1");
    attached(&net, "b", "c2");
    net.publish_port(&publish_req("a", "c1", 8080, ip4()))
        .expect("first");
    let other_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)));
    let e = net
        .publish_port(&publish_req("b", "c2", 8080, other_ip))
        .expect_err("duplicate");
    assert_eq!(e.code(), ErrorCode::AlreadyExists);
    net.delete_network(&DeleteNetworkRequest::new(nname("a")))
        .expect("delete");
    net.publish_port(&publish_req("b", "c2", 8080, other_ip))
        .expect("re-publish after delete");
}

/// host_ip なしと IPv6 は Unimplemented（全アドレス公開を作らない）で、バックエンドを呼ばない。
/// 不正な host_ip（loopback）は InvalidArgument。
#[test]
fn net4_publish_port_host_ip_validation() {
    let (net, fake) = plugin();
    attached(&net, "a", "c1");
    let v6 = Some(IpAddr::V6("2001:db8::1".parse().expect("ip")));
    for ip in [None, v6] {
        let e = net
            .publish_port(&publish_req("a", "c1", 8080, ip))
            .expect_err("unimplemented");
        assert_eq!(e.code(), ErrorCode::Unimplemented);
    }
    let lo = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let e = net
        .publish_port(&publish_req("a", "c1", 8080, lo))
        .expect_err("loopback");
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert!(!fake.calls().iter().any(|c| c.starts_with("publish_port")));
}

/// 結果不明の失敗は Internal で、同じポートは AlreadyExists のまま残り、delete_network の後に再公開できる。
/// 確定的な失敗は受け口を残さない。
#[test]
fn net4_publish_port_unknown_result_keeps_the_listener_until_network_deleted() {
    let (net, fake) = plugin();
    attached(&net, "a", "c1");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_publish_port = 8080;
        s.publish_unknown = false;
    }
    let e = net
        .publish_port(&publish_req("a", "c1", 8080, ip4()))
        .expect_err("definite failure");
    assert_eq!(e.code(), ErrorCode::Internal);
    fake.0.lock().expect("lock").fail_publish_port = 0;
    net.publish_port(&publish_req("a", "c1", 8080, ip4()))
        .expect("definite failure leaves no record");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_publish_port = 8081;
        s.publish_unknown = true;
    }
    let e = net
        .publish_port(&publish_req("a", "c1", 8081, ip4()))
        .expect_err("unknown result");
    assert_eq!(e.code(), ErrorCode::Internal);
    assert!(e.message().contains("left behind"));
    fake.0.lock().expect("lock").fail_publish_port = 0;
    let e = net
        .publish_port(&publish_req("a", "c1", 8081, ip4()))
        .expect_err("kept");
    assert_eq!(e.code(), ErrorCode::AlreadyExists);
    net.delete_network(&DeleteNetworkRequest::new(nname("a")))
        .expect("delete");
    attached(&net, "a", "c1");
    net.publish_port(&publish_req("a", "c1", 8081, ip4()))
        .expect("republish");
}

/// publish_port・unpublish_port を実装しない（既定のままの）バックエンド。
#[derive(Clone, Default)]
struct NoPublish(Fake);
impl NetsetupBackend for NoPublish {
    type Network = String;
    type Container = FakeContainer;
    type FailedCreate = String;
    type FailedAttach = (String, String);
    fn create_network(
        &self,
        name: &NetName,
        gateway: IpPrefix,
    ) -> Result<String, CreateFailure<String>> {
        self.0.create_network(name, gateway)
    }
    fn attach(
        &self,
        network: &mut String,
        endpoint: &EndpointId,
    ) -> Result<AttachOutcome<FakeContainer>, AttachFailure<(String, String)>> {
        self.0.attach(network, endpoint)
    }
    fn delete_network(
        &self,
        network: &mut String,
        containers: Vec<FakeContainer>,
    ) -> Result<(), DeleteFailure<FakeContainer>> {
        self.0.delete_network(network, containers)
    }
}

/// REPAIR-3: publish_port を実装しないバックエンドは既定で Unimplemented を返し、成功を装わない。
#[test]
fn repair3_backend_without_publish_support_is_unimplemented() {
    let net = NetsetupNetwork::new(NoPublish::default());
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("pod");
    pod_network::set_up_container(&net, &nname("a"), &cid("c1")).expect("container");
    let e = net
        .publish_port(&publish_req("a", "c1", 8080, ip4()))
        .expect_err("unimplemented");
    assert_eq!(e.code(), ErrorCode::Unimplemented);
}
/// 入力の検証: net の名前規則に合わない名前・IPv6・大文字の ID は InvalidArgument で、バックエンドを呼ばない。
#[test]
fn input_validation_precedes_backend() {
    let (net, fake) = plugin();
    let e = net
        .create_network(&CreateNetworkRequest::new(nname("Upper"), subnet()))
        .expect_err("upper");
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    let v6 = IpCidr::new("fd00::".parse().expect("v6"), 64).expect("cidr");
    let e = net
        .create_network(&CreateNetworkRequest::new(nname("v6"), v6))
        .expect_err("v6");
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("a");
    let e = net
        .create_netns(&CreateNetnsRequest::new(nname("a"), cid("UPPER")))
        .expect_err("upper id");
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(fake.calls(), vec!["create_network a 10.89.0.1/24"]);
}

/// ネットワーク数の上限を超えたら FailedPrecondition（信頼できない入力で状態が増え続けない）。
#[test]
fn network_count_is_bounded() {
    let (net, _) = plugin();
    for i in 0..MAX_NETWORKS {
        pod_network::set_up_pod(&net, &nname(&format!("n{i}")), subnet()).expect("create");
    }
    let e = pod_network::set_up_pod(&net, &nname("extra"), subnet()).expect_err("limit");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
}

/// バックエンドが panic してロックが poisoned になっても、以後は panic せず Internal を返す。
#[test]
fn poisoned_lock_returns_internal() {
    struct Panics;
    impl NetsetupBackend for Panics {
        type Network = ();
        type Container = FakeContainer;
        type FailedCreate = ();
        type FailedAttach = ();
        fn create_network(&self, _: &NetName, _: IpPrefix) -> Result<(), CreateFailure> {
            panic!("injected");
        }
        fn attach(
            &self,
            _: &mut (),
            _: &EndpointId,
        ) -> Result<AttachOutcome<FakeContainer>, AttachFailure> {
            Err(TraitError::new(ErrorCode::Internal, "unused").into())
        }
        fn delete_network(
            &self,
            _: &mut (),
            _: Vec<FakeContainer>,
        ) -> Result<(), DeleteFailure<FakeContainer>> {
            Ok(())
        }
    }
    let p = Arc::new(NetsetupNetwork::new(Panics));
    let p2 = Arc::clone(&p);
    let joined = std::thread::spawn(move || {
        p2.create_network(&CreateNetworkRequest::new(nname("a"), subnet()))
    })
    .join();
    assert!(joined.is_err(), "backend panicked");
    let e = p
        .create_network(&CreateNetworkRequest::new(nname("b"), subnet()))
        .expect_err("poisoned");
    assert_eq!(e.code(), ErrorCode::Internal);
}
/// attach も巻き戻しの detach も失敗する NetworkPlugin（契約 6・9 の握りつぶし防止の照合用）。
struct FailingRollback;

impl NetworkPlugin for FailingRollback {
    fn create_network(
        &self,
        _req: &CreateNetworkRequest,
    ) -> Result<fandhe_container_core::traits::NetworkStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, "unused"))
    }
    fn create_netns(
        &self,
        req: &CreateNetnsRequest,
    ) -> Result<fandhe_container_core::traits::NetnsStatus, TraitError> {
        let name = fandhe_container_core::traits::NetnsName::new("netns-x").expect("name");
        Ok(fandhe_container_core::traits::NetnsStatus::new(
            req.container().clone(),
            name,
        ))
    }
    fn attach(
        &self,
        _req: &AttachRequest,
    ) -> Result<fandhe_container_core::traits::AttachResponse, TraitError> {
        Err(TraitError::new(ErrorCode::Timeout, "attach timed out"))
    }
    fn publish_port(
        &self,
        _req: &PublishPortRequest,
    ) -> Result<fandhe_container_core::traits::PortMapping, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, "unused"))
    }
    fn detach(
        &self,
        _req: &DetachRequest,
    ) -> Result<fandhe_container_core::traits::DetachResponse, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, "detach broke"))
    }
    fn delete_network(
        &self,
        _req: &fandhe_container_core::traits::DeleteNetworkRequest,
    ) -> Result<fandhe_container_core::traits::DeleteNetworkResponse, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, "unused"))
    }
}

/// 契約 6・9: attach 失敗後の detach も失敗したら Internal で両方のエラーを残す。
#[test]
fn set_up_container_reports_failed_rollback() {
    let e = pod_network::set_up_container(&FailingRollback, &nname("pod1"), &cid("c1"))
        .expect_err("fail");
    assert_eq!(e.code(), ErrorCode::Internal);
    assert!(e.message().contains("attach failed (") && e.message().contains("attach timed out"));
    assert!(e.message().contains("detach broke"));
    assert!(e.message().contains("may remain"));
}

/// REPAIR-4: 入力拒否を含む公開操作の結果が共有の記録器に件数で残る。
#[test]
fn repair4_public_ops_are_recorded() {
    use fandhe_container_core::observability::OpRecorder;
    let rec = Arc::new(OpRecorder::new());
    let net = NetsetupNetwork::with_recorder(Fake::default(), Arc::clone(&rec));
    net.create_network(&CreateNetworkRequest::new(nname("pod1"), subnet()))
        .expect("create");
    // IPv6 のサブネットは入力拒否になるが失敗として記録される。
    let v6 = IpCidr::new("fd00::".parse().expect("v6"), 64).expect("cidr");
    net.create_network(&CreateNetworkRequest::new(nname("pod2"), v6))
        .expect_err("v6");
    let snap = rec.snapshot();
    let s = snap
        .iter()
        .find(|s| s.name().as_str() == "net.create_network")
        .expect("stats");
    assert_eq!((s.success(), s.failure()), (1, 1));
    // 個別解除も計測される（未 attach の解除は NotFound で失敗として記録される。NET-3・#2904）。
    net.unpublish_port(&UnpublishPortRequest::new(
        nname("pod1"),
        cid("c1"),
        NonZeroU16::new(8080).expect("port"),
        NonZeroU16::new(80).expect("port"),
        Protocol::Tcp,
    ))
    .expect_err("not attached");
    let snap = rec.snapshot();
    let s = snap
        .iter()
        .find(|s| s.name().as_str() == "net.unpublish_port")
        .expect("unpublish stats");
    assert_eq!((s.success(), s.failure()), (0, 1));
}

/// 契約 6・後始末: attach の巻き戻しで資源を取り残したら、記録を残し detach・再 attach・ネットワーク削除を拒否する。
#[test]
fn contract6_leftover_attach_keeps_record_and_blocks_cleanup() {
    let fake = Fake::default();
    let net = NetsetupNetwork::new(fake.clone());
    net.create_network(&CreateNetworkRequest::new(nname("a"), subnet()))
        .expect("net");
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
        .expect("netns");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_attach = true;
        s.attach_leftover = 1;
    }
    let req = AttachRequest::new(nname("a"), cid("c1"));
    net.attach(&req).expect_err("attach fails");
    fake.0.lock().expect("lock").fail_attach = false;
    // detach は記録を消して成功を装わない。
    let e = net
        .detach(&DetachRequest::new(nname("a"), cid("c1")))
        .expect_err("detach");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    // 再 attach は拒否する（記録は残る）。
    assert_eq!(
        net.attach(&req).expect_err("reattach").code(),
        ErrorCode::FailedPrecondition
    );
    // 取り残しのあるネットワークへは、ほかのコンテナの netns 登録も attach も拒否する（資源を増やさない）。
    assert_eq!(
        net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c2")))
            .expect_err("netns")
            .code(),
        ErrorCode::FailedPrecondition
    );
}

/// 契約 9: 取り残しのコンテナがあるネットワークは削除しない（bridge の所有証明を保つ）。
/// バックエンドを呼ばず何も解放せず、再試行しても同じ結果で、記録は残る。
#[test]
fn contract9_delete_blocked_while_unreclaimed_container_remains() {
    let fake = Fake::default();
    let net = NetsetupNetwork::new(fake.clone());
    net.create_network(&CreateNetworkRequest::new(nname("a"), subnet()))
        .expect("net");
    for c in ["c1", "c2"] {
        net.create_netns(&CreateNetnsRequest::new(nname("a"), cid(c)))
            .expect("netns");
    }
    net.attach(&AttachRequest::new(nname("a"), cid("c1")))
        .expect("attach c1");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_attach = true;
        s.attach_leftover = 1;
    }
    net.attach(&AttachRequest::new(nname("a"), cid("c2")))
        .expect_err("attach c2 fails");
    let before = fake.calls().len();
    for _ in 0..2 {
        let e = net
            .delete_network(&DeleteNetworkRequest::new(nname("a")))
            .expect_err("delete blocked");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(fake.calls().len(), before, "backend is not called");
    }
}

/// NET-1・CRI-7（契約 6・9）: 作成が取り残し付きで失敗したネットワークは回収待ちで残り MAX_NETWORKS に数えられ、
/// 上限で新規作成が拒否され、delete_network で回収が確認できると登録が消えて新規作成が通る。
#[test]
fn contract6_create_leftover_is_tracked_until_reclaimed() {
    let (net, fake) = plugin();
    fake.0.lock().expect("lock").fail_create = true;
    fake.0.lock().expect("lock").create_leftover = 2;
    for i in 0..MAX_NETWORKS {
        let e = pod_network::set_up_pod(&net, &nname(&format!("n{i}")), subnet())
            .expect_err("create fails");
        assert_eq!(e.message(), "create failed");
    }
    fake.0.lock().expect("lock").fail_create = false;
    // 回収待ちが 128 件で上限に達し、取り残しの無い作成も拒否される。
    let e = pod_network::set_up_pod(&net, &nname("extra"), subnet()).expect_err("limit");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "network limit reached");
    // 回収待ちへの接続系は拒否され、同名の再作成は AlreadyExists。
    assert_eq!(
        net.create_netns(&CreateNetnsRequest::new(nname("n0"), cid("c1")))
            .expect_err("leaked")
            .code(),
        ErrorCode::FailedPrecondition
    );
    assert_eq!(
        pod_network::set_up_pod(&net, &nname("n0"), subnet())
            .expect_err("dup")
            .code(),
        ErrorCode::AlreadyExists
    );
    // 回収に失敗する間は記録を保持する。
    assert_eq!(
        net.delete_network(&DeleteNetworkRequest::new(nname("n0")))
            .expect_err("reclaim fails")
            .message(),
        "reclaim failed"
    );
    assert_eq!(
        pod_network::set_up_pod(&net, &nname("extra"), subnet())
            .expect_err("still full")
            .message(),
        "network limit reached"
    );
    // 回収が確認できると登録が消え、新規作成が通る。
    fake.0.lock().expect("lock").reclaim_ok = true;
    net.delete_network(&DeleteNetworkRequest::new(nname("n0")))
        .expect("reclaimed");
    // 作成時に出した請求書がそのまま回収に渡る（失敗した 1 回と成功した 1 回）。
    let reclaims: Vec<String> = fake
        .calls()
        .into_iter()
        .filter(|c| c.starts_with("reclaim "))
        .collect();
    assert_eq!(reclaims, ["reclaim n0 claim-n0", "reclaim n0 claim-n0"]);
    // 回収した名前は再作成できる（空いた 1 枠を使う）。
    pod_network::set_up_pod(&net, &nname("n0"), subnet()).expect("n0 reusable after reclaim");
}

/// 請求書が無い（所有を証明できない）取り残しは、バックエンドの回収を呼ばず手動回収を求め、記録を保持する。
#[test]
fn contract6_leak_without_claim_requires_manual_reclaim() {
    let (net, fake) = plugin();
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_create = true;
        s.create_leftover = 1;
        s.no_claim = true;
        s.reclaim_ok = true;
    }
    pod_network::set_up_pod(&net, &nname("n0"), subnet()).expect_err("create fails");
    for _ in 0..2 {
        let e = net
            .delete_network(&DeleteNetworkRequest::new(nname("n0")))
            .expect_err("manual reclaim");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(e.message().contains("manual reclaim required"));
    }
    assert!(!fake.calls().iter().any(|c| c.starts_with("reclaim ")));
    // 記録は保持され、再作成は AlreadyExists のまま。
    fake.0.lock().expect("lock").fail_create = false;
    assert_eq!(
        pod_network::set_up_pod(&net, &nname("n0"), subnet())
            .expect_err("still tracked")
            .code(),
        ErrorCode::AlreadyExists
    );
}

/// 取り残しの無い作成失敗は従来どおり何も保持しない。
#[test]
fn contract6_create_failure_without_leftover_is_not_tracked() {
    let (net, fake) = plugin();
    fake.0.lock().expect("lock").fail_create = true;
    pod_network::set_up_pod(&net, &nname("p"), subnet()).expect_err("fail");
    assert_eq!(
        net.delete_network(&DeleteNetworkRequest::new(nname("p")))
            .expect_err("none")
            .code(),
        ErrorCode::NotFound
    );
}

/// 一意な一時の状態ルート（0700）を作る。
fn temp_state_root(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "fandhe-netsetup-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&p).expect("root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("mode");
    }
    p
}

fn persistent(root: &std::path::Path, fake: &Fake) -> NetsetupNetwork<Fake> {
    let store = ReclaimStore::open(root).expect("store");
    NetsetupNetwork::with_reclaim_store(fake.clone(), store, None).expect("plugin")
}

fn leak_n0(net: &NetsetupNetwork<Fake>, fake: &Fake) {
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_create = true;
        s.create_leftover = 1;
    }
    pod_network::set_up_pod(net, &nname("n0"), subnet()).expect_err("create fails");
    fake.0.lock().expect("lock").fail_create = false;
}

/// NET-1・NET-6・#2604: 作成失敗の請求書は plugin の再起動をまたいで残り、再起動後の delete_network で
/// 元と同じ請求書が回収に渡り、回収後に記録ファイルが消えて同名を再作成できる。
#[test]
fn net1_failed_create_claim_survives_plugin_restart() {
    let root = temp_state_root("restart");
    let fake = Fake::default();
    let net = persistent(&root, &fake);
    leak_n0(&net, &fake);
    let file = root.join(RECLAIM_DIR).join("n0.claim");
    assert_eq!(
        std::fs::read_to_string(&file).expect("record"),
        "rec:claim-n0"
    );
    drop(net);

    // 再起動: 同じ置き場から作り直す。
    let fake2 = Fake::default();
    let net = persistent(&root, &fake2);
    assert_eq!(
        pod_network::set_up_pod(&net, &nname("n0"), subnet())
            .expect_err("tracked")
            .code(),
        ErrorCode::AlreadyExists
    );
    assert_eq!(
        net.create_netns(&CreateNetnsRequest::new(nname("n0"), cid("c1")))
            .expect_err("leaked")
            .code(),
        ErrorCode::FailedPrecondition
    );
    // 回収に失敗する間は記録が残る。
    assert_eq!(
        net.delete_network(&DeleteNetworkRequest::new(nname("n0")))
            .expect_err("reclaim fails")
            .message(),
        "reclaim failed"
    );
    assert!(file.exists());
    fake2.0.lock().expect("lock").reclaim_ok = true;
    net.delete_network(&DeleteNetworkRequest::new(nname("n0")))
        .expect("reclaimed");
    assert!(!file.exists());
    let reclaims: Vec<String> = fake2
        .calls()
        .into_iter()
        .filter(|c| c.starts_with("reclaim "))
        .collect();
    assert_eq!(reclaims, ["reclaim n0 claim-n0", "reclaim n0 claim-n0"]);
    pod_network::set_up_pod(&net, &nname("n0"), subnet()).expect("reusable");
    std::fs::remove_dir_all(&root).expect("cleanup");
}

/// 壊れた記録（復号できない）はファイルを残し、請求書なしの手動回収として登録し、記録器の失敗件数に数える。
#[test]
fn net1_corrupt_reclaim_record_requires_manual_reclaim() {
    let root = temp_state_root("corrupt");
    let store = ReclaimStore::open(&root).expect("store");
    let file = root.join(RECLAIM_DIR).join("n0.claim");
    std::fs::write(&file, "garbage").expect("write");
    let fake = Fake::default();
    fake.0.lock().expect("lock").reclaim_ok = true;
    let recorder = Arc::new(fandhe_container_core::observability::OpRecorder::new());
    let net = NetsetupNetwork::with_reclaim_store(fake.clone(), store, Some(Arc::clone(&recorder)))
        .expect("plugin");
    let e = net
        .delete_network(&DeleteNetworkRequest::new(nname("n0")))
        .expect_err("manual");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert!(e.message().contains("manual reclaim required"));
    assert!(file.exists());
    assert!(!fake.calls().iter().any(|c| c.starts_with("reclaim ")));
    let op = fandhe_container_core::observability::OpName::new("net.reclaim_store_load")
        .expect("op name");
    assert_eq!(recorder.snapshot_op(&op).expect("stats").failure(), 1);
    std::fs::remove_dir_all(&root).expect("cleanup");
}

/// 別ネットワークの記録をファイル名だけ付け替えても、復号が名前の食い違いを拒否して手動回収になる。
#[test]
fn net1_reclaim_record_for_other_network_is_rejected() {
    let root = temp_state_root("other");
    let store = ReclaimStore::open(&root).expect("store");
    std::fs::write(root.join(RECLAIM_DIR).join("n1.claim"), "rec:claim-n0").expect("write");
    let fake = Fake::default();
    fake.0.lock().expect("lock").reclaim_ok = true;
    let net = NetsetupNetwork::with_reclaim_store(fake.clone(), store, None).expect("plugin");
    let e = net
        .delete_network(&DeleteNetworkRequest::new(nname("n1")))
        .expect_err("manual");
    assert!(e.message().contains("manual reclaim required"));
    assert!(fake.calls().is_empty());
    std::fs::remove_dir_all(&root).expect("cleanup");
}

/// 符号化しないバックエンド（請求書を記録にできない）では何も書かない。
#[test]
fn net1_no_record_when_backend_does_not_encode() {
    let root = temp_state_root("noenc");
    let fake = Fake::default();
    fake.0.lock().expect("lock").no_encode = true;
    let net = persistent(&root, &fake);
    leak_n0(&net, &fake);
    assert!(!root.join(RECLAIM_DIR).join("n0.claim").exists());
    std::fs::remove_dir_all(&root).expect("cleanup");
}

/// 記録を書けないときは成功を装わず Internal を返し、メモリの記録は保持して同じプロセスでは回収できる（unix）。
#[cfg(unix)]
#[test]
fn net1_persist_failure_is_reported_and_memory_record_kept() {
    let root = temp_state_root("rofail");
    let fake = Fake::default();
    let net = persistent(&root, &fake);
    let dir = root.join(RECLAIM_DIR);
    // 権限に依存せず（root でも効く）、置き場のディレクトリを通常ファイルに差し替えて保存を必ず失敗させる。
    std::fs::remove_dir_all(&dir).expect("rm dir");
    std::fs::write(&dir, "not a directory").expect("replace by file");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_create = true;
        s.create_leftover = 1;
    }
    let e = pod_network::set_up_pod(&net, &nname("n0"), subnet()).expect_err("fails");
    assert_eq!(e.code(), ErrorCode::Internal);
    assert!(e.message().contains("could not be persisted"));
    fake.0.lock().expect("lock").reclaim_ok = true;
    // 置き場を作り直す。記録ファイルは無いので、回収の確認後の削除は冪等に成功する。
    std::fs::remove_file(&dir).expect("rm file");
    ReclaimStore::open(&root).expect("reopen");
    net.delete_network(&DeleteNetworkRequest::new(nname("n0")))
        .expect("reclaimed from memory");
    std::fs::remove_dir_all(&root).expect("cleanup");
}
// ---- sandbox 単位の netns 作成・結線（CRI-2・NET-1・PLUG-1。#2675） ----

const SB: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// 事前作成の netns は detach で解放される。解放に失敗したら記録を残し、再試行で成功する。
#[test]
fn net1_detach_releases_the_prepared_netns() {
    let (net, fake) = plugin();
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("a");
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
        .expect("netns");
    fake.0.lock().expect("lock").fail_release = 1;
    let e = net
        .detach(&DetachRequest::new(nname("a"), cid("c1")))
        .expect_err("release fails");
    assert_eq!(e.code(), ErrorCode::Internal);
    net.detach(&DetachRequest::new(nname("a"), cid("c1")))
        .expect("retry");
    assert_eq!(
        fake.netns_calls(),
        vec!["create_netns c1", "release_netns c1", "release_netns c1"]
    );
    // 記録は消えている。
    assert_eq!(
        net.detach(&DetachRequest::new(nname("a"), cid("c1")))
            .expect_err("gone")
            .code(),
        ErrorCode::NotFound
    );
}

/// delete_network は未 attach の事前作成 netns も解放する（attach 済みはバックエンドの delete に任せる）。
#[test]
fn net1_delete_network_releases_unattached_prepared_netns() {
    let (net, fake) = plugin();
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("a");
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
        .expect("c1");
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c2")))
        .expect("c2");
    net.attach(&AttachRequest::new(nname("a"), cid("c2")))
        .expect("attach c2");
    // 解放の失敗ではネットワークを消さず、再試行で完了する。
    fake.0.lock().expect("lock").fail_release = 1;
    assert_eq!(
        pod_network::tear_down_pod(&net, &nname("a"))
            .expect_err("release fails")
            .code(),
        ErrorCode::Internal
    );
    // 契約 9: c1 の解放失敗で止まらず、attach 済みの c2 の解放は続ける。
    assert_eq!(fake.calls().last().unwrap(), "delete_network a [c2]");
    pod_network::tear_down_pod(&net, &nname("a")).expect("retry");
    assert_eq!(
        fake.netns_calls(),
        vec![
            "create_netns c1",
            "create_netns c2",
            "release_netns c1",
            "release_netns c1"
        ]
    );
    assert_eq!(fake.calls().last().unwrap(), "delete_network a [c2]");
    assert_eq!(
        fake.calls()
            .iter()
            .filter(|c| c.starts_with("delete_network"))
            .count(),
        1
    );
}

/// 保持された netns を解放できなくても、同じネットワークの attach 済みコンテナの回収は続く（契約 9。#2675）。
#[test]
fn contract9_release_failure_does_not_stop_attached_cleanup() {
    let (net, fake) = plugin();
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("a");
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
        .expect("c1");
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c2")))
        .expect("c2");
    net.attach(&AttachRequest::new(nname("a"), cid("c2")))
        .expect("attach c2");
    fake.0.lock().expect("lock").fail_release = 5;
    let e = net
        .delete_network(&DeleteNetworkRequest::new(nname("a")))
        .expect_err("release fails");
    assert_eq!(e.code(), ErrorCode::Internal);
    assert_eq!(fake.calls().last().unwrap(), "delete_network a [c2]");
    // 失敗した c1 の記録は残り、解放できるようになれば完了する。
    fake.0.lock().expect("lock").fail_release = 0;
    net.delete_network(&DeleteNetworkRequest::new(nname("a")))
        .expect("retry");
}

/// create_netns が lo の up 失敗後の unpin にも失敗し、バックエンドがハンドルを保持したら、
/// 回収待ちで固定せず `release_netns` で回収できる（#2675）。
#[test]
fn net1_create_netns_retained_handle_is_released_by_delete() {
    let (net, fake) = plugin();
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("a");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_create_netns = true;
        s.create_netns_leftover = 1;
        s.create_netns_retained = true;
    }
    assert!(
        net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
            .is_err()
    );
    fake.0.lock().expect("lock").fail_create_netns = false;
    // attach はできない。
    assert_eq!(
        net.attach(&AttachRequest::new(nname("a"), cid("c1")))
            .expect_err("pending release")
            .code(),
        ErrorCode::FailedPrecondition
    );
    net.delete_network(&DeleteNetworkRequest::new(nname("a")))
        .expect("released and deleted");
    assert!(fake.netns_calls().contains(&"release_netns c1".to_owned()));
}

/// attach 失敗で veth が残り（unreclaimed）かつ準備済み netns をバックエンドが保持していても、
/// detach は netns を `release_netns` で解放する。取り残しの回収待ち自体は残る（#2675・NET-1）。
#[test]
fn net1_attach_leftover_with_retained_netns_is_released_by_detach() {
    let (net, fake) = plugin();
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("a");
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
        .expect("netns");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_attach = true;
        s.attach_leftover = 1;
        s.attach_retained = true;
    }
    net.attach(&AttachRequest::new(nname("a"), cid("c1")))
        .expect_err("attach fails");
    let e = net
        .detach(&DetachRequest::new(nname("a"), cid("c1")))
        .expect_err("still unreclaimed");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    let releases = |f: &Fake| {
        f.netns_calls()
            .iter()
            .filter(|c| *c == "release_netns c1")
            .count()
    };
    assert_eq!(releases(&fake), 1);
    // 解放済みなので二度目の detach は release を繰り返さない。
    let _ = net.detach(&DetachRequest::new(nname("a"), cid("c1")));
    assert_eq!(releases(&fake), 1);
}

/// 同じ状況で delete_network も、取り残しの拒否の前に netns を解放する（pin と fd を残さない）。
#[test]
fn net1_attach_leftover_with_retained_netns_is_released_by_delete_network() {
    let (net, fake) = plugin();
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("a");
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
        .expect("netns");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_attach = true;
        s.attach_leftover = 1;
        s.attach_retained = true;
    }
    net.attach(&AttachRequest::new(nname("a"), cid("c1")))
        .expect_err("attach fails");
    let e = net
        .delete_network(&DeleteNetworkRequest::new(nname("a")))
        .expect_err("blocked by unreclaimed");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(
        fake.netns_calls()
            .iter()
            .filter(|c| *c == "release_netns c1")
            .count(),
        1
    );
}

/// 請求書つきの取り残し（#2681）でも、delete_network は請求書による回収（記録を外す）より前に保持中の netns を
/// 解放する。回収が先だと記録が消え、バックエンドが保持する netns（pin・fd）に届かなくなる（#2675・NET-1）。
#[test]
fn net1_attach_leftover_with_claim_releases_retained_netns_before_reclaim() {
    let (net, fake) = plugin();
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("a");
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
        .expect("netns");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_attach = true;
        s.attach_leftover = 1;
        s.attach_retained = true;
        s.attach_claim = true;
        s.reclaim_attach_ok = true;
    }
    net.attach(&AttachRequest::new(nname("a"), cid("c1")))
        .expect_err("attach fails");
    net.delete_network(&DeleteNetworkRequest::new(nname("a")))
        .expect("reclaimed and deleted");
    assert_eq!(
        fake.netns_calls(),
        vec!["create_netns c1", "release_netns c1"]
    );
    assert_eq!(
        fake.calls()
            .into_iter()
            .filter(|c| c.starts_with("reclaim_attach") || c.starts_with("delete_network"))
            .collect::<Vec<_>>(),
        vec!["reclaim_attach a c1", "delete_network a []"]
    );
}

/// 請求書による回収が成功しても、保持中の netns の解放に失敗している間はコンテナの記録を外さない。
/// delete_network は失敗を返し、再試行で解放してから記録ごと消える（pin・fd への回収経路を失わない。#2675・NET-1）。
#[test]
fn net1_reclaimed_attach_leftover_keeps_record_until_netns_released() {
    let (net, fake) = plugin();
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("a");
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
        .expect("netns");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_attach = true;
        s.attach_leftover = 1;
        s.attach_retained = true;
        s.attach_claim = true;
        s.reclaim_attach_ok = true;
        // 回収前の解放と、回収後の未 attach の解放の両方を失敗させる。
        s.fail_release = 2;
    }
    net.attach(&AttachRequest::new(nname("a"), cid("c1")))
        .expect_err("attach fails");
    let e = net
        .delete_network(&DeleteNetworkRequest::new(nname("a")))
        .expect_err("release fails");
    assert_eq!(e.message(), "release failed");
    // 記録は残り、保持中の netns があるので attach は拒否される。
    assert_eq!(
        net.attach(&AttachRequest::new(nname("a"), cid("c1")))
            .expect_err("pending release")
            .code(),
        ErrorCode::FailedPrecondition
    );
    net.delete_network(&DeleteNetworkRequest::new(nname("a")))
        .expect("released on retry");
    assert_eq!(
        fake.netns_calls(),
        vec![
            "create_netns c1",
            "release_netns c1",
            "release_netns c1",
            "release_netns c1"
        ]
    );
    // 記録ごと消えている。
    assert_eq!(
        net.delete_network(&DeleteNetworkRequest::new(nname("a")))
            .expect_err("gone")
            .code(),
        ErrorCode::NotFound
    );
}

/// create_netns の失敗では記録を作らない。
#[test]
fn net1_failed_create_netns_leaves_no_record() {
    let (net, fake) = plugin();
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("a");
    fake.0.lock().expect("lock").fail_create_netns = true;
    assert!(
        net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
            .is_err()
    );
    fake.0.lock().expect("lock").fail_create_netns = false;
    net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
        .expect("retry is not AlreadyExists");
}

/// create_netns が pin を取り残したら回収待ちとして保持し、delete_network は成功を返さない（契約 6・9。#2675）。
#[test]
fn net1_create_netns_leftover_is_tracked_and_blocks_delete() {
    let (net, fake) = plugin();
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("a");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_create_netns = true;
        s.create_netns_leftover = 1;
    }
    assert!(
        net.create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
            .is_err()
    );
    // 同じコンテナの再作成は記録が残るので AlreadyExists ではなく取り残しで拒否される。
    fake.0.lock().expect("lock").fail_create_netns = false;
    let e = net
        .create_netns(&CreateNetnsRequest::new(nname("a"), cid("c1")))
        .expect_err("tracked");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    let e = net
        .delete_network(&DeleteNetworkRequest::new(nname("a")))
        .expect_err("blocked");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
}

/// set_up_sandbox: 呼び出し列は create_network → create_netns → attach（sandbox ID が名前・コンテナ ID）。
#[test]
fn set_up_sandbox_calls_in_order() {
    let (net, fake) = plugin();
    let st = pod_network::set_up_sandbox(&net, SB, subnet(), &[]).expect("set up");
    assert_eq!(st.name().as_str(), SB);
    assert_eq!(
        fake.calls(),
        vec![
            format!("create_network {SB} 10.89.0.1/24"),
            format!("attach {SB} {SB}"),
        ]
    );
    assert_eq!(fake.netns_calls(), vec![format!("create_netns {SB}")]);
    pod_network::tear_down_pod(&net, &nname(SB)).expect("tear down");
    assert_eq!(
        fake.calls().last().unwrap(),
        &format!("delete_network {SB} [{SB}]")
    );
}

/// set_up_sandbox: create_netns の失敗は delete_network で戻す。
#[test]
fn set_up_sandbox_rolls_back_network_when_create_netns_fails() {
    let (net, fake) = plugin();
    fake.0.lock().expect("lock").fail_create_netns = true;
    let f = pod_network::set_up_sandbox(&net, SB, subnet(), &[]).expect_err("fail");
    assert!(f.rolled_back);
    assert_eq!(f.error.message(), "create_netns failed");
    assert_eq!(
        fake.calls(),
        vec![
            format!("create_network {SB} 10.89.0.1/24"),
            format!("delete_network {SB} []"),
        ]
    );
    // 記録が残らないので同じ sandbox を作り直せる。
    fake.0.lock().expect("lock").fail_create_netns = false;
    pod_network::set_up_sandbox(&net, SB, subnet(), &[]).expect("retry");
}

/// set_up_sandbox: create_network が取り残し付きで失敗したら rolled_back は偽（サブネット枠を返さない。CRI-2・NET-1）。
#[test]
fn set_up_sandbox_create_network_leftover_is_not_rolled_back() {
    let (net, fake) = plugin();
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_create = true;
        s.create_leftover = 2;
    }
    let f = pod_network::set_up_sandbox(&net, SB, subnet(), &[]).expect_err("fail");
    assert!(!f.rolled_back);
}

/// set_up_sandbox: attach の失敗は detach（netns の解放）→ delete_network の順に戻す。
#[test]
fn set_up_sandbox_rolls_back_in_reverse_when_attach_fails() {
    let (net, fake) = plugin();
    fake.0.lock().expect("lock").fail_attach = true;
    let f = pod_network::set_up_sandbox(&net, SB, subnet(), &[]).expect_err("fail");
    assert!(f.rolled_back);
    assert_eq!(f.error.message(), "attach failed");
    assert_eq!(
        fake.netns_calls(),
        vec![format!("create_netns {SB}"), format!("release_netns {SB}")]
    );
    assert_eq!(
        fake.calls().last().unwrap(),
        &format!("delete_network {SB} []")
    );
}

/// set_up_sandbox: 戻しも失敗したら両方を載せた Internal で、rolled_back は偽。
#[test]
fn set_up_sandbox_reports_failed_rollback() {
    let (net, fake) = plugin();
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_attach = true;
        s.fail_release = 1;
    }
    let f = pod_network::set_up_sandbox(&net, SB, subnet(), &[]).expect_err("fail");
    assert!(!f.rolled_back);
    assert_eq!(f.error.code(), ErrorCode::Internal);
    assert!(f.error.message().contains("attach failed"), "{}", f.error);
    assert!(
        f.error.message().contains("rollback detach failed"),
        "{}",
        f.error
    );
}

fn parent() -> IpCidr {
    IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 90, 0, 0)), 16).expect("parent")
}

/// サブネットの払い出し: 具体値・冪等・返却・枯渇。
#[test]
fn pod_subnet_pool_allocates_releases_and_exhausts() {
    use fandhe_container_plugin_cri::pod_network::PodSubnetPool;
    let pool = PodSubnetPool::new(parent(), 24).expect("pool");
    let a = pool.allocate("a").expect("a");
    assert_eq!(
        (a.network_address(), a.prefix_len()),
        (IpAddr::V4(Ipv4Addr::new(10, 90, 0, 0)), 24)
    );
    let b = pool.allocate("b").expect("b");
    assert_eq!(b.network_address(), IpAddr::V4(Ipv4Addr::new(10, 90, 1, 0)));
    // 冪等。
    assert_eq!(pool.allocate("a").expect("again"), a);
    assert_eq!(pool.in_use(), 2);
    // 返却した枠は再利用される。
    pool.release("a");
    assert_eq!(pool.allocate("c").expect("c"), a);
    // 枯渇。
    let small = PodSubnetPool::new(
        IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 91, 0, 0)), 23).expect("p"),
        24,
    )
    .expect("small");
    small.allocate("x").expect("x");
    small.allocate("y").expect("y");
    assert_eq!(
        small.allocate("z").expect_err("full").code(),
        ErrorCode::ResourceExhausted
    );
    // 不正な分割。
    for (len, pod) in [(16u8, 16u8), (24, 16), (16, 31), (8, 30)] {
        let p = IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), len).expect("p");
        assert_eq!(
            PodSubnetPool::new(p, pod).expect_err("bad").code(),
            ErrorCode::InvalidArgument,
            "{len}/{pod}"
        );
    }
}

fn provider_with(fake: &Fake) -> fandhe_container_plugin_cri::pod_network::NetsetupPodNetwork {
    use fandhe_container_plugin_cri::pod_network::{NetsetupPodNetwork, PodSubnetPool};
    let net: Arc<dyn NetworkPlugin> = Arc::new(NetsetupNetwork::new(fake.clone()));
    NetsetupPodNetwork::new(
        net,
        // Linux 側の置き場（PodNetns の契約により 3 OS とも `/` 区切り）。
        std::path::PathBuf::from("/state/.netns"),
        PodSubnetPool::new(parent(), 24).expect("pool"),
    )
}

/// provider: set_up は netns のパスを返し、tear_down は冪等で枠を返す。
#[test]
fn pod_network_provider_set_up_and_tear_down() {
    use fandhe_container_cri::adapter::{PodNetworkProvider, PodNetworkRequest};
    use fandhe_container_cri::runtime::v1::PodSandboxConfig;
    let fake = Fake::default();
    let provider = provider_with(&fake);
    let cfg = PodSandboxConfig::default();
    let netns = provider
        .set_up(&PodNetworkRequest::new(SB, &cfg))
        .expect("set up");
    let expected = std::path::PathBuf::from(format!("/state/.netns/{SB}"));
    assert_eq!(netns.path(), expected);
    assert_eq!(fake.calls()[0], format!("create_network {SB} 10.90.0.1/24"));
    provider.tear_down(SB).expect("tear down");
    // 冪等: 解放済み・未知は成功。
    provider.tear_down(SB).expect("again");
    provider.tear_down(&"f".repeat(64)).expect("unknown");
    // 不正な ID はエラー。
    assert!(provider.tear_down("bad_id").is_err());
}

/// provider: 巻き戻しが完了した失敗は枠を返し、次の set_up が同じ枠から始まる。
#[test]
fn pod_network_provider_reuses_the_subnet_after_a_clean_rollback() {
    use fandhe_container_cri::adapter::{PodNetworkProvider, PodNetworkRequest};
    use fandhe_container_cri::runtime::v1::PodSandboxConfig;
    let fake = Fake::default();
    let provider = provider_with(&fake);
    let cfg = PodSandboxConfig::default();
    fake.0.lock().expect("lock").fail_attach = true;
    assert!(provider.set_up(&PodNetworkRequest::new(SB, &cfg)).is_err());
    fake.0.lock().expect("lock").fail_attach = false;
    provider
        .set_up(&PodNetworkRequest::new(SB, &cfg))
        .expect("retry");
    let creates: Vec<String> = fake
        .calls()
        .into_iter()
        .filter(|c| c.starts_with("create_network"))
        .collect();
    assert_eq!(
        creates,
        vec![
            format!("create_network {SB} 10.90.0.1/24"),
            format!("create_network {SB} 10.90.0.1/24")
        ]
    );
}

/// set_up_sandbox: 同名の稼働中ネットワークで create_network が AlreadyExists なら、戻さず rolled_back は偽
/// （稼働中のネットワークを消さない・枠を返させない。CRI-2・NET-1）。
#[test]
fn set_up_sandbox_already_exists_is_not_rolled_back() {
    let (net, fake) = plugin();
    pod_network::set_up_sandbox(&net, SB, subnet(), &[]).expect("first");
    let f = pod_network::set_up_sandbox(&net, SB, subnet(), &[]).expect_err("dup");
    assert_eq!(f.error.code(), ErrorCode::AlreadyExists);
    assert!(!f.rolled_back);
    // 稼働中のネットワークを消す呼び出しは無い。
    assert!(
        !fake.calls().iter().any(|c| c.starts_with("delete_network")),
        "{:?}",
        fake.calls()
    );
}

/// サブネットの払い出し: lease は新規払い出しと既存予約を区別する（NET-1）。
#[test]
fn pod_subnet_pool_lease_distinguishes_new_and_existing() {
    use fandhe_container_plugin_cri::pod_network::PodSubnetPool;
    let pool = PodSubnetPool::new(parent(), 24).expect("pool");
    let first = pool.lease("a").expect("a");
    assert!(first.newly_allocated);
    assert_eq!(
        first.subnet.network_address(),
        IpAddr::V4(Ipv4Addr::new(10, 90, 0, 0))
    );
    let again = pool.lease("a").expect("again");
    assert!(!again.newly_allocated);
    assert_eq!(again.subnet, first.subnet);
    assert_eq!(pool.in_use(), 1);
}

/// provider: 同じ sandbox への set_up の再呼び出しが AlreadyExists で失敗しても、稼働中のネットワークの枠を
/// 返さない。次の sandbox には別のサブネットが渡り、tear_down の成功で初めて枠が返る（CRI-2・NET-1）。
#[test]
fn pod_network_provider_duplicate_set_up_keeps_the_subnet_in_use() {
    use fandhe_container_cri::adapter::{PodNetworkProvider, PodNetworkRequest};
    use fandhe_container_cri::runtime::v1::PodSandboxConfig;
    let fake = Fake::default();
    let provider = provider_with(&fake);
    let cfg = PodSandboxConfig::default();
    let other = "b".repeat(64);
    let third = "c".repeat(64);
    provider
        .set_up(&PodNetworkRequest::new(SB, &cfg))
        .expect("first");
    let dup = provider
        .set_up(&PodNetworkRequest::new(SB, &cfg))
        .expect_err("dup");
    assert_eq!(dup.code().as_str(), "ALREADY_EXISTS");
    provider
        .set_up(&PodNetworkRequest::new(&other, &cfg))
        .expect("other");
    provider.tear_down(SB).expect("tear down");
    provider
        .set_up(&PodNetworkRequest::new(&third, &cfg))
        .expect("third");
    let creates: Vec<String> = fake
        .calls()
        .into_iter()
        .filter(|c| c.starts_with("create_network"))
        .collect();
    assert_eq!(
        creates,
        vec![
            // 二重作成は registry が backend の前で拒否するため backend の呼び出しは 1 回だけ。
            format!("create_network {SB} 10.90.0.1/24"),
            format!("create_network {other} 10.90.1.1/24"),
            // SB の tear_down で返った枠が再利用される。
            format!("create_network {third} 10.90.0.1/24"),
        ]
    );
}

/// `create_network` で指定の名前だけ止める NetworkPlugin（他は内側へ委譲）。並行試験用。
struct GatedNetwork {
    inner: NetsetupNetwork<Fake>,
    gated: String,
    entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl NetworkPlugin for GatedNetwork {
    fn create_network(
        &self,
        req: &CreateNetworkRequest,
    ) -> Result<fandhe_container_core::traits::NetworkStatus, TraitError> {
        if req.name().as_str() == self.gated {
            if let Some(tx) = self.entered.lock().expect("lock").take() {
                tx.send(()).expect("entered");
            }
            if let Some(rx) = self.release.lock().expect("lock").take() {
                rx.recv_timeout(std::time::Duration::from_secs(20))
                    .expect("release");
            }
        }
        self.inner.create_network(req)
    }
    fn create_netns(
        &self,
        req: &CreateNetnsRequest,
    ) -> Result<fandhe_container_core::traits::NetnsStatus, TraitError> {
        self.inner.create_netns(req)
    }
    fn attach(
        &self,
        req: &AttachRequest,
    ) -> Result<fandhe_container_core::traits::AttachResponse, TraitError> {
        self.inner.attach(req)
    }
    fn publish_port(
        &self,
        req: &PublishPortRequest,
    ) -> Result<fandhe_container_core::traits::PortMapping, TraitError> {
        self.inner.publish_port(req)
    }
    fn unpublish_port(
        &self,
        req: &UnpublishPortRequest,
    ) -> Result<fandhe_container_core::traits::UnpublishPortResponse, TraitError> {
        self.inner.unpublish_port(req)
    }
    fn detach(
        &self,
        req: &DetachRequest,
    ) -> Result<fandhe_container_core::traits::DetachResponse, TraitError> {
        self.inner.detach(req)
    }
    fn delete_network(
        &self,
        req: &DeleteNetworkRequest,
    ) -> Result<fandhe_container_core::traits::DeleteNetworkResponse, TraitError> {
        self.inner.delete_network(req)
    }
}

/// provider: 同じ sandbox の set_up 実行中の tear_down・set_up は FAILED_PRECONDITION で拒否し
/// （delete_network と枠の返却の間に作り直されて稼働中の枠を返すのを防ぐ）、別の sandbox は並行できる（NET-1）。
#[test]
fn pod_network_provider_serializes_operations_on_the_same_sandbox() {
    use fandhe_container_cri::adapter::{PodNetworkProvider, PodNetworkRequest};
    use fandhe_container_cri::runtime::v1::PodSandboxConfig;
    use fandhe_container_plugin_cri::pod_network::{NetsetupPodNetwork, PodSubnetPool};
    let fake = Fake::default();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let net: Arc<dyn NetworkPlugin> = Arc::new(GatedNetwork {
        inner: NetsetupNetwork::new(fake.clone()),
        gated: SB.to_owned(),
        entered: Mutex::new(Some(entered_tx)),
        release: Mutex::new(Some(release_rx)),
    });
    let provider = Arc::new(NetsetupPodNetwork::new(
        net,
        std::path::PathBuf::from("/state/.netns"),
        PodSubnetPool::new(parent(), 24).expect("pool"),
    ));
    let worker = {
        let provider = Arc::clone(&provider);
        std::thread::spawn(move || {
            let cfg = PodSandboxConfig::default();
            provider.set_up(&PodNetworkRequest::new(SB, &cfg))
        })
    };
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("set_up entered create_network");
    let cfg = PodSandboxConfig::default();
    let busy = provider.tear_down(SB).expect_err("busy tear_down");
    assert_eq!(busy.code().as_str(), "FAILED_PRECONDITION");
    let busy = provider
        .set_up(&PodNetworkRequest::new(SB, &cfg))
        .expect_err("busy set_up");
    assert_eq!(busy.code().as_str(), "FAILED_PRECONDITION");
    // 別の sandbox は止まらない。
    let other = "d".repeat(64);
    provider
        .set_up(&PodNetworkRequest::new(&other, &cfg))
        .expect("other");
    release_tx.send(()).expect("release");
    worker.join().expect("join").expect("set up");
    // 完了後は印が外れて tear_down できる。
    provider.tear_down(SB).expect("tear down");
    assert_eq!(
        fake.calls()
            .into_iter()
            .filter(|c| c.starts_with("delete_network"))
            .collect::<Vec<_>>(),
        vec![format!("delete_network {SB} [{SB}]")]
    );
}

const ATTACH_DIR: &str = "attach";

/// attach を取り残し付き（請求書つき）で失敗させる。
fn leak_attach(net: &NetsetupNetwork<Fake>, fake: &Fake, network: &str, container: &str) {
    pod_network::set_up_pod(net, &nname(network), subnet()).expect("pod");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_attach = true;
        s.attach_leftover = 1;
        s.attach_claim = true;
    }
    pod_network::set_up_container(net, &nname(network), &cid(container)).expect_err("attach fails");
    fake.0.lock().expect("lock").fail_attach = false;
}

/// NET-1・#2681: 請求書つきの attach の取り残しは、記録ファイルへ書かれ、detach の所有確認つき回収で記録ごと消え、
/// 同じ container で netns をやり直せる。回収に失敗する間は記録とファイルが残り、再試行で収束する。
#[test]
fn net1_attach_leftover_reclaimed_by_detach() {
    let root = temp_state_root("detach");
    let fake = Fake::default();
    let net = persistent(&root, &fake);
    leak_attach(&net, &fake, "n0", "c1");
    let file = root.join(RECLAIM_DIR).join(ATTACH_DIR).join("c1.attach");
    assert_eq!(
        std::fs::read_to_string(&file).expect("record"),
        "arec:n0:c1"
    );
    // 回収に失敗する間は、記録とファイルを保持してエラーを返す。
    let e = net
        .detach(&DetachRequest::new(nname("n0"), cid("c1")))
        .expect_err("reclaim fails");
    assert_eq!(e.message(), "reclaim attach failed");
    assert!(file.exists());
    fake.0.lock().expect("lock").reclaim_attach_ok = true;
    net.detach(&DetachRequest::new(nname("n0"), cid("c1")))
        .expect("reclaimed");
    assert!(!file.exists());
    let calls: Vec<String> = fake
        .calls()
        .into_iter()
        .filter(|c| c.starts_with("reclaim_attach "))
        .collect();
    assert_eq!(
        calls,
        [
            "reclaim_attach n0 c1",
            "reclaim_attach n0 c1",
            "reclaim_attach n0 c1"
        ]
    );
    // 記録が外れているので、netns をやり直せる。
    net.create_netns(&CreateNetnsRequest::new(nname("n0"), cid("c1")))
        .expect("netns again");
    std::fs::remove_dir_all(&root).expect("cleanup");
}

/// NET-1・#2681: quarantine（アドレス・ポート予約）を含む取り残しは、detach でカーネル側を回収しても成功を
/// 装わず、登録と記録を保持する（再 attach を拒否）。delete_network がネットワークごと解放して記録も消す。
#[test]
fn net1_detach_keeps_registration_while_quarantine_held() {
    let root = temp_state_root("quarantine");
    let fake = Fake::default();
    let net = persistent(&root, &fake);
    fake.0.lock().expect("lock").attach_quarantine = true;
    leak_attach(&net, &fake, "n0", "c1");
    fake.0.lock().expect("lock").reclaim_attach_ok = true;
    let file = root.join(RECLAIM_DIR).join(ATTACH_DIR).join("c1.attach");
    for _ in 0..2 {
        let e = net
            .detach(&DetachRequest::new(nname("n0"), cid("c1")))
            .expect_err("quarantine still held");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(
            e.message()
                .contains("released only when the network is deleted")
        );
        assert!(file.exists());
        // 再 attach は IPAM の二重払い出しに進まず、バックエンドの attach を呼ばずに拒否される。
        let before = fake
            .calls()
            .iter()
            .filter(|c| c.starts_with("attach "))
            .count();
        let e = pod_network::set_up_container(&net, &nname("n0"), &cid("c1"))
            .expect_err("blocked while held");
        assert!(e.message().contains("unreclaimed"));
        let after = fake
            .calls()
            .iter()
            .filter(|c| c.starts_with("attach "))
            .count();
        assert_eq!(before, after);
    }
    // カーネル側の取り残しではないので、delete_network は回収待ちとして止まらず、ネットワークと一緒に片付ける。
    net.delete_network(&DeleteNetworkRequest::new(nname("n0")))
        .expect("delete releases the held quarantine");
    assert!(!file.exists());
    std::fs::remove_dir_all(&root).expect("cleanup");
}

/// NET-1・#2681: delete_network は bridge の解放より前に attach の取り残しを回収し、成功すれば通常の削除へ進む。
#[test]
fn net1_delete_network_reclaims_attach_leftover_first() {
    let root = temp_state_root("delfirst");
    let fake = Fake::default();
    let net = persistent(&root, &fake);
    leak_attach(&net, &fake, "n0", "c1");
    fake.0.lock().expect("lock").reclaim_attach_ok = true;
    // 回収は set_up_container のロールバックの detach でも 1 回走る（失敗して残った）ので、呼び出し列は後ろだけ見る。
    net.delete_network(&DeleteNetworkRequest::new(nname("n0")))
        .expect("delete");
    let calls = fake.calls();
    let tail: Vec<&str> = calls.iter().rev().take(2).map(String::as_str).collect();
    assert_eq!(tail, ["delete_network n0 []", "reclaim_attach n0 c1"]);
    assert!(
        !root
            .join(RECLAIM_DIR)
            .join(ATTACH_DIR)
            .join("c1.attach")
            .exists()
    );
    std::fs::remove_dir_all(&root).expect("cleanup");
}

/// NET-1・#2681: 再起動後は attach の記録だけから復元したネットワークとなり、delete_network が取り残しを回収して
/// 記録を消し、ネットワーク本体は手動回収と固定の文言で知らせる（成功を装わない）。2 回目は NotFound。
#[test]
fn net1_attach_leftover_survives_plugin_restart() {
    let root = temp_state_root("attrestart");
    let fake = Fake::default();
    let net = persistent(&root, &fake);
    leak_attach(&net, &fake, "n0", "c1");
    let file = root.join(RECLAIM_DIR).join(ATTACH_DIR).join("c1.attach");
    assert_eq!(
        std::fs::read_to_string(&file).expect("record"),
        "arec:n0:c1"
    );
    drop(net);

    let fake2 = Fake::default();
    let net = persistent(&root, &fake2);
    // 復元したネットワークへは資源を増やさない。
    assert_eq!(
        net.create_netns(&CreateNetnsRequest::new(nname("n0"), cid("c2")))
            .expect_err("recovered")
            .code(),
        ErrorCode::FailedPrecondition
    );
    // 回収に失敗する間は記録を保持する。
    assert_eq!(
        net.delete_network(&DeleteNetworkRequest::new(nname("n0")))
            .expect_err("reclaim fails")
            .message(),
        "reclaim attach failed"
    );
    assert!(file.exists());
    fake2.0.lock().expect("lock").reclaim_attach_ok = true;
    let e = net
        .delete_network(&DeleteNetworkRequest::new(nname("n0")))
        .expect_err("network itself needs manual reclaim");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(e.message(), MSG_RECOVERED_NETWORK_UNTRACKED);
    assert!(!file.exists());
    assert_eq!(
        net.delete_network(&DeleteNetworkRequest::new(nname("n0")))
            .expect_err("gone")
            .code(),
        ErrorCode::NotFound
    );
    // バックエンドの delete_network は呼ばれない（ハンドルが無い）。
    assert!(
        !fake2
            .calls()
            .iter()
            .any(|c| c.starts_with("delete_network"))
    );
    std::fs::remove_dir_all(&root).expect("cleanup");
}

/// NET-1・#2681: 復元したネットワークの detach も回収でき、コンテナが 0 件になればネットワークの記録も外れる。
#[test]
fn net1_recovered_network_is_forgotten_after_detach_reclaim() {
    let root = temp_state_root("attdetach");
    let fake = Fake::default();
    let net = persistent(&root, &fake);
    leak_attach(&net, &fake, "n0", "c1");
    drop(net);
    let fake2 = Fake::default();
    fake2.0.lock().expect("lock").reclaim_attach_ok = true;
    let net = persistent(&root, &fake2);
    net.detach(&DetachRequest::new(nname("n0"), cid("c1")))
        .expect("detach reclaims");
    assert_eq!(
        net.delete_network(&DeleteNetworkRequest::new(nname("n0")))
            .expect_err("forgotten")
            .code(),
        ErrorCode::NotFound
    );
    std::fs::remove_dir_all(&root).expect("cleanup");
}

/// NET-1・#2681: 壊れた attach の記録は消さず、登録せず、記録器の失敗件数に数える。
#[test]
fn net1_corrupt_attach_record_is_counted_and_kept() {
    let root = temp_state_root("attcorrupt");
    let store = ReclaimStore::open(&root).expect("store");
    let dir = root.join(RECLAIM_DIR).join(ATTACH_DIR);
    std::fs::write(dir.join("c1.attach"), "garbage").expect("write");
    std::fs::write(dir.join("c2.attach"), "arec:n0:other").expect("mismatch");
    let fake = Fake::default();
    let recorder = Arc::new(fandhe_container_core::observability::OpRecorder::new());
    let net = NetsetupNetwork::with_reclaim_store(fake.clone(), store, Some(Arc::clone(&recorder)))
        .expect("plugin");
    assert!(dir.join("c1.attach").exists() && dir.join("c2.attach").exists());
    assert_eq!(
        net.delete_network(&DeleteNetworkRequest::new(nname("n0")))
            .expect_err("not registered")
            .code(),
        ErrorCode::NotFound
    );
    let op = fandhe_container_core::observability::OpName::new("net.reclaim_store_load")
        .expect("op name");
    assert_eq!(recorder.snapshot_op(&op).expect("stats").failure(), 2);
    std::fs::remove_dir_all(&root).expect("cleanup");
}

/// NET-1・#2681: 記録を書けないときは成功を装わず、件を足した Internal を返し、メモリの記録は保持する。
#[cfg(unix)]
#[test]
fn net1_attach_persist_failure_is_reported() {
    let root = temp_state_root("attfail");
    let fake = Fake::default();
    let net = persistent(&root, &fake);
    let dir = root.join(RECLAIM_DIR).join(ATTACH_DIR);
    std::fs::remove_dir_all(&dir).expect("rm dir");
    std::fs::write(&dir, "not a directory").expect("replace by file");
    pod_network::set_up_pod(&net, &nname("n0"), subnet()).expect("pod");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_attach = true;
        s.attach_leftover = 1;
        s.attach_claim = true;
    }
    net.create_netns(&CreateNetnsRequest::new(nname("n0"), cid("c1")))
        .expect("netns");
    let e = net
        .attach(&AttachRequest::new(nname("n0"), cid("c1")))
        .expect_err("fails");
    assert_eq!(e.code(), ErrorCode::Internal);
    assert!(e.message().contains("could not be persisted"));
    // メモリの記録は保持されているので、再 attach は拒否される。
    assert_eq!(
        net.attach(&AttachRequest::new(nname("n0"), cid("c1")))
            .expect_err("kept")
            .code(),
        ErrorCode::FailedPrecondition
    );
    std::fs::remove_dir_all(&root).expect("cleanup");
}

/// NET-1・#2681: 請求書の無い取り残しは今までどおり手動回収のまま（detach・delete を拒否し、ファイルも書かない）。
#[test]
fn net1_attach_leftover_without_claim_stays_manual() {
    let root = temp_state_root("attnoclaim");
    let fake = Fake::default();
    let net = persistent(&root, &fake);
    pod_network::set_up_pod(&net, &nname("n0"), subnet()).expect("pod");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_attach = true;
        s.attach_leftover = 1;
    }
    pod_network::set_up_container(&net, &nname("n0"), &cid("c1")).expect_err("attach fails");
    assert!(
        !root
            .join(RECLAIM_DIR)
            .join(ATTACH_DIR)
            .join("c1.attach")
            .exists()
    );
    fake.0.lock().expect("lock").reclaim_attach_ok = true;
    assert_eq!(
        net.detach(&DetachRequest::new(nname("n0"), cid("c1")))
            .expect_err("manual")
            .code(),
        ErrorCode::FailedPrecondition
    );
    assert_eq!(
        net.delete_network(&DeleteNetworkRequest::new(nname("n0")))
            .expect_err("blocked")
            .code(),
        ErrorCode::FailedPrecondition
    );
    assert!(!fake.calls().iter().any(|c| c.starts_with("reclaim_attach")));
    std::fs::remove_dir_all(&root).expect("cleanup");
}
fn pod_publish(
    host_port: i32,
    host_ip: &str,
) -> fandhe_container_cri::port_mapping::PodPortPublish {
    use fandhe_container_cri::runtime::v1::PortMapping;
    fandhe_container_cri::port_mapping::parse_port_mappings(&[PortMapping {
        protocol: 0,
        container_port: 80,
        host_port,
        host_ip: host_ip.into(),
    }])
    .expect("valid")
    .remove(0)
}

/// CRI-2・NET-4（#2676）: 呼び出し順は create_network → create_netns → attach → publish_port（公開指定ごと）。
#[test]
fn set_up_sandbox_publishes_ports_after_attach() {
    let (net, fake) = plugin();
    let ports = [
        pod_publish(8080, "192.0.2.10"),
        pod_publish(8081, "192.0.2.10"),
    ];
    pod_network::set_up_sandbox(&net, SB, subnet(), &ports).expect("set up");
    assert_eq!(
        fake.calls(),
        vec![
            format!("create_network {SB} 10.89.0.1/24"),
            format!("attach {SB} {SB}"),
            format!("publish_port {SB} {SB} 192.0.2.10:8080->80"),
            format!("publish_port {SB} {SB} 192.0.2.10:8081->80"),
        ]
    );
}

/// 2 件目の公開が失敗したら、公開済みの 1 件を個別に解除してから delete_network で戻す
/// （attach 済みの detach は呼ばない。NET-3・CRI-2・#2904）。
#[test]
fn cri2_set_up_sandbox_unpublishes_then_deletes_network_when_publish_fails() {
    let (net, fake) = plugin();
    fake.0.lock().expect("lock").fail_publish_port = 8081;
    let ports = [
        pod_publish(8080, "192.0.2.10"),
        pod_publish(8081, "192.0.2.10"),
    ];
    let f = pod_network::set_up_sandbox(&net, SB, subnet(), &ports).expect_err("fail");
    assert!(f.rolled_back);
    assert_eq!(f.error.message(), "publish failed");
    let calls = fake.calls();
    assert_eq!(
        calls[calls.len() - 4..],
        [
            format!("publish_port {SB} {SB} 192.0.2.10:8080->80"),
            format!("publish_port {SB} {SB} 192.0.2.10:8081->80"),
            format!("unpublish_port {SB} {SB} 192.0.2.10:8080->80"),
            format!("delete_network {SB} [{SB}]"),
        ]
    );
    assert_eq!(
        calls
            .iter()
            .filter(|c| c.starts_with("delete_network"))
            .count(),
        1
    );
    // detach（netns の解放）は呼ばれていない。
    assert_eq!(fake.netns_calls(), vec![format!("create_netns {SB}")]);
    // 記録が残らないので、同じ sandbox を作り直せる。
    fake.0.lock().expect("lock").fail_publish_port = 0;
    pod_network::set_up_sandbox(&net, SB, subnet(), &ports).expect("retry");
}

/// 巻き戻しの delete_network も失敗したら rolled_back は偽で、Internal に両方の失敗を載せる。
#[test]
fn set_up_sandbox_publish_rollback_failure_is_not_rolled_back() {
    let (net, fake) = plugin();
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_publish_port = 8080;
        s.fail_delete = 1;
    }
    let ports = [pod_publish(8080, "192.0.2.10")];
    let f = pod_network::set_up_sandbox(&net, SB, subnet(), &ports).expect_err("fail");
    assert!(!f.rolled_back);
    assert_eq!(f.error.code(), ErrorCode::Internal);
    assert!(f.error.message().contains("rollback delete_network failed"));
}

/// NET-3・#2839: `unpublish_port` を実装しないバックエンドは成功を装わず `Unimplemented`（結果不明ではない）。
#[test]
fn net3_unpublish_port_defaults_to_unimplemented() {
    let fake = NoPublish::default();
    let publish = PortPublish::new(
        fandhe_container_net::network::PortProtocol::Tcp,
        "192.0.2.10".parse().expect("addr"),
        8080,
        80,
    )
    .expect("publish");
    let mut network = "web".to_owned();
    let e = fake
        .unpublish_port(&mut network, &FakeContainer("c1".to_owned()), &publish)
        .expect_err("unimplemented");
    assert_eq!(e.error.code(), ErrorCode::Unimplemented);
    assert!(!e.rules_unknown);
}
/// 個別解除で受け口が解放され、別ネットワークのコンテナが同じ受け口を公開できる（契約 11・13）。
#[test]
fn net3_unpublish_port_releases_listener_for_republish() {
    let (net, fake) = plugin();
    attached(&net, "a", "c1");
    attached(&net, "b", "c2");
    let m = net
        .publish_port(&publish_req("a", "c1", 8080, ip4()))
        .expect("publish");
    net.unpublish_port(&UnpublishPortRequest::from(&m))
        .expect("unpublish");
    assert_eq!(
        fake.calls().last().unwrap(),
        "unpublish_port a c1 192.0.2.10:8080->80"
    );
    net.publish_port(&publish_req("b", "c2", 8080, ip4()))
        .expect("republish elsewhere");
}

fn unpublish_req(network: &str, container: &str, host_port: u16) -> UnpublishPortRequest {
    UnpublishPortRequest::new(
        nname(network),
        cid(container),
        NonZeroU16::new(host_port).expect("port"),
        NonZeroU16::new(80).expect("port"),
        Protocol::Tcp,
    )
    .with_host_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
}

/// 契約 13 の判定順: ネットワーク未作成 → 未 attach → 越境 → 未公開。いずれもバックエンドを呼ばない。
#[test]
fn net3_unpublish_port_precondition_order() {
    let (net, fake) = plugin();
    let code = |net: &NetsetupNetwork<Fake>, network: &str| {
        net.unpublish_port(&unpublish_req(network, "c1", 8080))
            .expect_err("rejected")
            .code()
    };
    assert_eq!(code(&net, "a"), ErrorCode::NotFound);
    pod_network::set_up_pod(&net, &nname("a"), subnet()).expect("pod");
    assert_eq!(code(&net, "a"), ErrorCode::NotFound);
    pod_network::set_up_container(&net, &nname("a"), &cid("c1")).expect("container");
    pod_network::set_up_pod(&net, &nname("b"), subnet()).expect("pod b");
    assert_eq!(code(&net, "b"), ErrorCode::FailedPrecondition);
    assert_eq!(code(&net, "a"), ErrorCode::NotFound);
    assert!(!fake.calls().iter().any(|c| c.starts_with("unpublish_port")));
}

/// 成功後の同じ要求は NotFound（Ok を返さない）。
#[test]
fn net3_unpublish_port_twice_is_not_found() {
    let (net, _) = plugin();
    attached(&net, "a", "c1");
    net.publish_port(&publish_req("a", "c1", 8080, ip4()))
        .expect("publish");
    net.unpublish_port(&unpublish_req("a", "c1", 8080))
        .expect("first");
    let e = net
        .unpublish_port(&unpublish_req("a", "c1", 8080))
        .expect_err("second");
    assert_eq!(e.code(), ErrorCode::NotFound);
    assert_eq!(e.message(), "published port is not recorded");
}

/// 確定的な失敗は記録を保持し、同じ要求で再試行できる。
#[test]
fn net3_unpublish_port_definite_failure_keeps_record_and_retries() {
    let (net, fake) = plugin();
    attached(&net, "a", "c1");
    net.publish_port(&publish_req("a", "c1", 8080, ip4()))
        .expect("publish");
    fake.0.lock().expect("lock").fail_unpublish_port = 8080;
    let e = net
        .unpublish_port(&unpublish_req("a", "c1", 8080))
        .expect_err("definite failure");
    assert_eq!(e.code(), ErrorCode::Internal);
    assert_eq!(e.message(), "unpublish failed");
    assert_eq!(
        net.publish_port(&publish_req("a", "c1", 8080, ip4()))
            .expect_err("still published")
            .code(),
        ErrorCode::AlreadyExists
    );
    fake.0.lock().expect("lock").fail_unpublish_port = 0;
    net.unpublish_port(&unpublish_req("a", "c1", 8080))
        .expect("retry");
    net.publish_port(&publish_req("a", "c1", 8080, ip4()))
        .expect("republish");
}

/// 結果不明の解除は Internal（left behind）で記録を保持し、delete_network の後に再公開できる。
#[test]
fn net3_unpublish_port_unknown_result_quarantines_until_delete_network() {
    let (net, fake) = plugin();
    attached(&net, "a", "c1");
    net.publish_port(&publish_req("a", "c1", 8080, ip4()))
        .expect("publish");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_unpublish_port = 8080;
        s.unpublish_unknown = true;
    }
    let e = net
        .unpublish_port(&unpublish_req("a", "c1", 8080))
        .expect_err("unknown");
    assert_eq!(e.code(), ErrorCode::Internal);
    assert!(e.message().contains("left behind"), "{}", e.message());
    assert_eq!(
        net.publish_port(&publish_req("a", "c1", 8080, ip4()))
            .expect_err("quarantined")
            .code(),
        ErrorCode::AlreadyExists
    );
    net.delete_network(&DeleteNetworkRequest::new(nname("a")))
        .expect("delete");
    attached(&net, "a", "c1");
    net.publish_port(&publish_req("a", "c1", 8080, ip4()))
        .expect("republish after delete");
}

/// 結果不明で記録した公開は個別に解除できない（FailedPrecondition・固定文言）。バックエンドを呼ばない。
#[test]
fn net3_unpublish_port_of_unknown_publish_is_failed_precondition() {
    let (net, fake) = plugin();
    attached(&net, "a", "c1");
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_publish_port = 8080;
        s.publish_unknown = true;
    }
    net.publish_port(&publish_req("a", "c1", 8080, ip4()))
        .expect_err("unknown publish");
    let e = net
        .unpublish_port(&unpublish_req("a", "c1", 8080))
        .expect_err("not individually releasable");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(
        e.message(),
        "published port has an unknown result and is released only by delete_network"
    );
    assert!(!fake.calls().iter().any(|c| c.starts_with("unpublish_port")));
}

/// 個別解除が失敗しても、残りの解除と delete_network を続け、rolled_back は偽。
#[test]
fn cri2_set_up_sandbox_unpublish_failure_still_deletes_network() {
    let (net, fake) = plugin();
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_publish_port = 8082;
        s.fail_unpublish_port = 8080;
    }
    let ports = [
        pod_publish(8080, "192.0.2.10"),
        pod_publish(8081, "192.0.2.10"),
        pod_publish(8082, "192.0.2.10"),
    ];
    let f = pod_network::set_up_sandbox(&net, SB, subnet(), &ports).expect_err("fail");
    assert!(!f.rolled_back);
    assert_eq!(f.error.code(), ErrorCode::Internal);
    assert!(f.error.message().contains("publish failed"), "{}", f.error);
    assert!(
        f.error.message().contains("rollback unpublish_port failed"),
        "{}",
        f.error
    );
    let calls = fake.calls();
    assert_eq!(
        calls[calls.len() - 3..],
        [
            format!("unpublish_port {SB} {SB} 192.0.2.10:8081->80"),
            format!("unpublish_port {SB} {SB} 192.0.2.10:8080->80"),
            format!("delete_network {SB} [{SB}]"),
        ]
    );
}

/// attach の失敗では公開が無いので個別解除を呼ばず、detach → delete_network の順のまま。
#[test]
fn cri2_set_up_sandbox_attach_failure_never_unpublishes() {
    let (net, fake) = plugin();
    fake.0.lock().expect("lock").fail_attach = true;
    let ports = [pod_publish(8080, "192.0.2.10")];
    let f = pod_network::set_up_sandbox(&net, SB, subnet(), &ports).expect_err("fail");
    assert!(f.rolled_back);
    let calls = fake.calls();
    assert!(!calls.iter().any(|c| c.starts_with("unpublish_port")));
    assert!(!calls.iter().any(|c| c.starts_with("publish_port")));
    assert_eq!(
        fake.netns_calls(),
        vec![format!("create_netns {SB}"), format!("release_netns {SB}")]
    );
    assert_eq!(calls.last().unwrap(), &format!("delete_network {SB} []"));
}

/// 個別解除できた受け口は、delete_network が失敗しても記録から外れ、別ネットワークで再公開できる。
#[test]
fn cri2_set_up_sandbox_unpublished_ports_are_republishable_after_failed_delete() {
    let (net, fake) = plugin();
    {
        let mut s = fake.0.lock().expect("lock");
        s.fail_publish_port = 8081;
        s.fail_delete = 1;
    }
    let ports = [
        pod_publish(8080, "192.0.2.10"),
        pod_publish(8081, "192.0.2.10"),
    ];
    let f = pod_network::set_up_sandbox(&net, SB, subnet(), &ports).expect_err("fail");
    assert!(!f.rolled_back);
    attached(&net, "other", "c9");
    net.publish_port(&publish_req("other", "c9", 8080, ip4()))
        .expect("8080 was released individually");
}
