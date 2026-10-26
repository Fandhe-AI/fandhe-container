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
    TraitError,
};
use fandhe_container_net::netlink_route::IpPrefix;
use fandhe_container_net::network::{EndpointId, NetworkName as NetName};
use fandhe_container_plugin_cri::netsetup::{
    AttachFailure, AttachOutcome, CreateFailure, DeleteFailure, MAX_NETWORKS,
    MSG_RECOVERED_NETWORK_UNTRACKED, NetsetupBackend, NetsetupContainer, NetsetupNetwork,
    RECLAIM_DIR, ReclaimStore,
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
}

#[derive(Clone, Default)]
struct Fake(Arc<Mutex<Script>>);

impl Fake {
    fn calls(&self) -> Vec<String> {
        self.0.lock().expect("lock").calls.clone()
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

/// 未実装は固定文言の Unimplemented（REPAIR-3）。ポート公開は DNAT の経路を開かない。
#[test]
fn repair3_publish_port_is_unimplemented() {
    let (net, fake) = plugin();
    let req = PublishPortRequest::new(
        nname("a"),
        cid("c1"),
        NonZeroU16::new(8080).expect("port"),
        NonZeroU16::new(80).expect("port"),
        Protocol::Tcp,
    );
    let e = net.publish_port(&req).expect_err("unimpl");
    assert_eq!(e.code(), ErrorCode::Unimplemented);
    assert!(fake.calls().is_empty());
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
