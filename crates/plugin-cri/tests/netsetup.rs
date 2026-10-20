//! `NetsetupNetwork`（netsetup の操作単位への写像。TASK-114.4・#460・MS-4）と `pod_network` の振る舞い試験。
//!
//! カーネルを触らない fake の `NetsetupBackend` で、`NetworkPlugin` の契約 6〜9・12 の分岐と、
//! PodSandbox 作成 → コンテナ作成 → PodSandbox 削除で net の操作が正しい順序で呼ばれることを
//! 具体値で照合する（PLUG-1・CRI-2・CRI-7・NET-1〜NET-3）。3 OS の既定集合で動く（root 不要）。

use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};

use fandhe_container_core::traits::{
    AttachRequest, ContainerId, CreateNetnsRequest, CreateNetworkRequest, DetachRequest, ErrorCode,
    IpCidr, NetworkName, NetworkPlugin, Protocol, PublishPortRequest, TraitError,
};
use fandhe_container_net::netlink_route::IpPrefix;
use fandhe_container_net::network::{EndpointId, NetworkName as NetName};
use fandhe_container_plugin_cri::netsetup::{
    AttachOutcome, DeleteFailure, MAX_NETWORKS, NetsetupBackend, NetsetupContainer, NetsetupNetwork,
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
    fail_attach: bool,
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

    fn create_network(&self, name: &NetName, gateway: IpPrefix) -> Result<String, TraitError> {
        let mut s = self.0.lock().expect("lock");
        s.calls.push(format!(
            "create_network {} {}/{}",
            name.as_str(),
            gateway.addr(),
            gateway.prefix_len()
        ));
        if s.fail_create {
            return Err(TraitError::new(ErrorCode::Internal, "create failed"));
        }
        Ok(name.as_str().to_owned())
    }

    fn attach(
        &self,
        network: &mut String,
        endpoint: &EndpointId,
    ) -> Result<AttachOutcome<FakeContainer>, TraitError> {
        let mut s = self.0.lock().expect("lock");
        s.calls
            .push(format!("attach {network} {}", endpoint.as_str()));
        if s.fail_attach {
            return Err(TraitError::new(ErrorCode::Internal, "attach failed"));
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
        fn create_network(&self, _: &NetName, _: IpPrefix) -> Result<(), TraitError> {
            panic!("injected");
        }
        fn attach(
            &self,
            _: &mut (),
            _: &EndpointId,
        ) -> Result<AttachOutcome<FakeContainer>, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "unused"))
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
