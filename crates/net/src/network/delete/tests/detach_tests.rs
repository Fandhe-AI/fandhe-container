//! コンテナ単体の切り離し（`detach_container_with`）の単体試験（NET-1・NET-3・#3062）。
//!
//! 親の `delete::tests` の fake（`Fake`）と補助を再利用する。呼び出し列・件数・アドレスは具体値で照合する。

use super::*;
use crate::network::PublishedPort;

fn handle(n: u64) -> NftRuleHandle {
    NftRuleHandle::new(n).unwrap()
}

fn pub_of(host_port: u16) -> PortPublish {
    PortPublish::new(
        crate::network::PortProtocol::Tcp,
        Ipv4Addr::new(192, 0, 2, 10),
        host_port,
        80,
    )
    .unwrap()
}

/// `id` の公開 1 件を予約してハンドル（`h`・`h + 1`）を作る。
fn published(ports: &mut PortRegistry, id: &str, host_port: u16, h: u64) -> PublishedPort {
    let p = pub_of(host_port);
    ports
        .reserve(&NetworkName::new("web").unwrap(), &eid(id), &[p])
        .unwrap();
    PublishedPort::new(
        &NetworkName::new("web").unwrap(),
        TOKEN,
        &eid(id),
        p,
        (handle(h), handle(h + 1)),
    )
}

fn held(ports: &mut PortRegistry, id: &str) -> usize {
    ports
        .held_by(&NetworkName::new("web").unwrap(), &eid(id))
        .unwrap()
}

struct Two {
    net: CreatedNetwork,
    ipam: StaticIpam,
    ports: PortRegistry,
    c1: Option<AttachedContainer<()>>,
    extra: Vec<PublishedPort>,
    a1: IpPrefix,
    a2: IpPrefix,
}

/// 兄弟 c2（公開 1 件）を残して切り離す c1（attach 時 1 件 + 追加 1 件）の用意。
fn two_containers() -> Two {
    let (net, mut ipam, mut ports) = setup();
    let mut c1 = attached(&mut ipam, "c1");
    let c2 = attached(&mut ipam, "c2");
    c1.published_ports = vec![published(&mut ports, "c1", 8080, 2)];
    let extra = vec![published(&mut ports, "c1", 8081, 4)];
    // c2 の公開（ハンドルは c2 側が持つので切り離しには渡さない）。
    let _c2_handle = published(&mut ports, "c2", 9090, 6);
    let (a1, a2) = (c1.address, c2.address);
    Two {
        net,
        ipam,
        ports,
        c1: Some(c1),
        extra,
        a1,
        a2,
    }
}

fn detach(
    fake: &Fake,
    t: &mut Two,
    c1: AttachedContainer<()>,
    extra: Vec<PublishedPort>,
) -> Result<NetworkDeleteReport, Box<detach::ContainerDetachError<()>>> {
    detach::detach_container_with(fake, &t.net, c1, extra, &mut t.ipam, &mut t.ports)
}

/// NET-1・NET-3・#3062: c1 の切り離しは c1 の公開 → veth → pin → アドレスの順に解放し、c2 の公開・veth・
/// アドレス・予約と bridge・テーブルには触れない。
#[test]
fn net1_detach_releases_only_the_container() {
    let mut t = two_containers();
    let (c1, extra) = (t.c1.take().unwrap(), std::mem::take(&mut t.extra));
    let fake = Fake::default();
    let report = detach(&fake, &mut t, c1, extra).unwrap();
    let tbl = t.net.table.as_str();
    assert_eq!(
        fake.calls(),
        vec![
            format!("table_info {tbl}"),
            format!("delete_rules {tbl} 4/5"),
            format!("table_info {tbl}"),
            format!("delete_rules {tbl} 2/3"),
            format!("link_attachment {}", host_of("c1").as_str()),
            "delete_link 21".to_owned(),
            "unpin_netns".to_owned(),
        ]
    );
    assert_eq!(
        report.removed,
        vec![
            DeleteResource::PortRules(eid("c1"), pub_of(8081)),
            DeleteResource::PortRules(eid("c1"), pub_of(8080)),
            DeleteResource::Veth(host_of("c1")),
            DeleteResource::Netns(pin("c1")),
            DeleteResource::Address(eid("c1"), t.a1),
        ]
    );
    assert!(report.leftover.is_empty());
    // 兄弟は影響を受けない。
    assert_eq!(t.ipam.address_of(&eid("c1")), None);
    assert_eq!(t.ipam.address_of(&eid("c2")), Some(t.a2));
    assert_eq!(t.ports.len(), 1);
    assert_eq!(held(&mut t.ports, "c2"), 1);
    assert_eq!(held(&mut t.ports, "c1"), 0);
    let c2_host = host_of("c2");
    assert!(!fake.calls().iter().any(|c| c.contains(c2_host.as_str())
        || c.starts_with("delete_table")
        || c == "delete_link 7"));
}

/// NET-1・SEC-1・#3062: 他のコンテナの公開ハンドル・他ネットワークのハンドル・受け口の重複・
/// 食い違うアドレスは、I/O の前に拒否してコンテナとハンドルを返す。
#[test]
fn net1_detach_validate_rejects_without_io() {
    let fake = Fake::default();

    // c2 のハンドルを c1 の切り離しに混ぜる。
    let mut t = two_containers();
    let foreign = published(&mut t.ports, "c2", 9999, 8);
    let c1 = t.c1.take().unwrap();
    let e = detach(&fake, &mut t, c1, vec![foreign]).unwrap_err();
    assert_eq!(e.step, DeleteStep::Validate);
    assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
    assert!(fake.calls().is_empty());
    assert_eq!(
        e.retry.as_ref().map(|c| c.endpoint.clone()),
        Some(eid("c1"))
    );
    assert_eq!(e.published.len(), 1);
    assert!(e.reclaim_claim().is_none());
    assert_eq!(t.ipam.address_of(&eid("c1")), Some(t.a1));

    // 他ネットワークのハンドル。
    let mut t = two_containers();
    let other = PublishedPort::new(
        &NetworkName::new("db").unwrap(),
        TOKEN,
        &eid("c1"),
        pub_of(7000),
        (handle(20), handle(21)),
    );
    let c1 = t.c1.take().unwrap();
    let e = detach(&fake, &mut t, c1, vec![other]).unwrap_err();
    assert_eq!(e.step, DeleteStep::Validate);
    assert!(fake.calls().is_empty());

    // attach 時の公開と同じ受け口の重複。
    let mut t = two_containers();
    let dup = PublishedPort::new(
        &NetworkName::new("web").unwrap(),
        TOKEN,
        &eid("c1"),
        pub_of(8080),
        (handle(30), handle(31)),
    );
    let c1 = t.c1.take().unwrap();
    let e = detach(&fake, &mut t, c1, vec![dup]).unwrap_err();
    assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    assert!(fake.calls().is_empty());

    // アドレスの食い違い。
    let mut t = two_containers();
    let mut c1 = t.c1.take().unwrap();
    c1.address = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 99)), 24).unwrap();
    let extra = std::mem::take(&mut t.extra);
    let e = detach(&fake, &mut t, c1, extra).unwrap_err();
    assert_eq!(e.step, DeleteStep::Validate);
    assert!(fake.calls().is_empty());
    assert_eq!(t.ports.len(), 3);
}

/// NET-3・#3062: DELRULE が確定的に失敗（Aborted）。veth と pin は外れ、アドレスと予約は保持され、
/// 請求書は quarantine だけを持つ。
#[test]
fn net3_detach_rule_delete_failure_holds_address() {
    let mut t = two_containers();
    let c1 = t.c1.take().unwrap();
    let extra = std::mem::take(&mut t.extra);
    let fake = Fake {
        rules_err: Some((NetErrorCode::Internal, NftBatchOutcome::Aborted)),
        ..Fake::default()
    };
    let e = detach(&fake, &mut t, c1, extra).unwrap_err();
    assert_eq!(e.step, DeleteStep::UnpublishPorts);
    assert_eq!(e.code(), NetErrorCode::Internal);
    assert!(e.retry.is_none());
    assert_eq!(
        e.report.leftover,
        vec![
            (
                DeleteResource::PortRules(eid("c1"), pub_of(8081)),
                ResourceState::Present
            ),
            (
                DeleteResource::PortRules(eid("c1"), pub_of(8080)),
                ResourceState::Present
            ),
            (
                DeleteResource::Address(eid("c1"), t.a1),
                ResourceState::Present
            ),
        ]
    );
    assert!(
        e.report
            .removed
            .contains(&DeleteResource::Veth(host_of("c1")))
    );
    assert!(e.report.removed.contains(&DeleteResource::Netns(pin("c1"))));
    // アドレスと予約は保持（c1 の 2 件 + c2 の 1 件）。
    assert_eq!(t.ipam.address_of(&eid("c1")), Some(t.a1));
    assert_eq!(t.ipam.address_of(&eid("c2")), Some(t.a2));
    assert_eq!(t.ports.len(), 3);
    let claim = e.reclaim_claim().unwrap();
    let rec = claim.to_record();
    assert!(
        rec.contains("veth=0\nnetns=0\npin=-\nquarantine=1\n"),
        "{rec}"
    );
    assert_eq!(FailedAttachClaim::from_record(&rec), Ok(claim));
}

/// NET-3・#3062: DELRULE の結果不明（Unknown）は状態 Unknown で報告し、同じく保持する。
#[test]
fn net3_detach_rule_delete_unknown_is_reported() {
    let mut t = two_containers();
    let c1 = t.c1.take().unwrap();
    let extra = std::mem::take(&mut t.extra);
    let fake = Fake {
        rules_err: Some((NetErrorCode::Timeout, NftBatchOutcome::Unknown)),
        ..Fake::default()
    };
    let e = detach(&fake, &mut t, c1, extra).unwrap_err();
    assert_eq!(e.code(), NetErrorCode::Timeout);
    assert_eq!(
        e.report.leftover[0],
        (
            DeleteResource::PortRules(eid("c1"), pub_of(8081)),
            ResourceState::Unknown
        )
    );
    assert_eq!(
        e.report.leftover.last(),
        Some(&(
            DeleteResource::Address(eid("c1"), t.a1),
            ResourceState::Unknown
        ))
    );
    assert_eq!(t.ipam.address_of(&eid("c1")), Some(t.a1));
}

/// NET-3・SEC-1・#3068: 記録したテーブルハンドル（98）が生きたもの（99）と食い違う公開は DELRULE を送らず、
/// 取り残し（状態 Unknown）として報告してアドレスと予約を保持する（quarantine）。
#[test]
fn net3_3068_detach_stale_table_handle_holds_address_without_deleting() {
    let mut t = two_containers();
    let c1 = t.c1.take().unwrap();
    let extra: Vec<PublishedPort> = std::mem::take(&mut t.extra)
        .into_iter()
        .map(|p| p.with_table_handle(crate::nftables_batch::NftTableHandle::new(98).unwrap()))
        .collect();
    let fake = Fake::default();
    let e = detach(&fake, &mut t, c1, extra).unwrap_err();
    assert_eq!(e.step, DeleteStep::UnpublishPorts);
    assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
    assert!(
        !fake
            .calls()
            .iter()
            .any(|c| c.starts_with("delete_rules") && c.ends_with(" 4/5")),
        "食い違うハンドルでは DELRULE を送らない: {:?}",
        fake.calls()
    );
    assert_eq!(
        e.report.leftover[0],
        (
            DeleteResource::PortRules(eid("c1"), pub_of(8081)),
            ResourceState::Unknown
        )
    );
    assert_eq!(t.ipam.address_of(&eid("c1")), Some(t.a1));
    // 束縛の無い 8080 は解除済みで、食い違った 8081 の予約だけが残る。
    assert_eq!(
        held(&mut t.ports, "c1"),
        1,
        "食い違った公開の予約は解放しない"
    );
}

/// NET-1・NET-3・#3062: 結果不明の公開が残した予約（ハンドルなし）があれば、公開なしの切り離しでも
/// アドレスを保持し、成功を装わない。
#[test]
fn net1_detach_held_reservation_keeps_address() {
    let (net, mut ipam, mut ports) = setup();
    let c1 = attached(&mut ipam, "c1");
    let a1 = c1.address;
    reserve_port(&mut ports, "c1", 8080);
    let fake = Fake::default();
    let e = detach::detach_container_with(&fake, &net, c1, Vec::new(), &mut ipam, &mut ports)
        .unwrap_err();
    assert_eq!(e.step, DeleteStep::ReleaseReservations);
    assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
    assert!(
        e.report
            .removed
            .contains(&DeleteResource::Veth(host_of("c1")))
    );
    assert_eq!(ipam.address_of(&eid("c1")), Some(a1));
    assert_eq!(ports.len(), 1);
    let rec = e.reclaim_claim().unwrap().to_record();
    assert!(
        rec.contains("veth=0\nnetns=0\npin=-\nquarantine=1\n"),
        "{rec}"
    );
}

/// NET-1・#3062: veth の削除に失敗したら unpin せず、アドレスも保持する。請求書は veth と netns を含み、
/// 既存の `reclaim_failed_attach_with` で veth と pin を回収できる。
#[test]
fn net1_detach_veth_failure_keeps_pin_and_address() {
    let (net, mut ipam, mut ports) = setup();
    let c1 = attached(&mut ipam, "c1");
    let a1 = c1.address;
    let fake = Fake {
        veth_delete_err: Some(NetErrorCode::Internal),
        ..Fake::default()
    };
    let e = detach::detach_container_with(&fake, &net, c1, Vec::new(), &mut ipam, &mut ports)
        .unwrap_err();
    assert_eq!(e.step, DeleteStep::DeleteVeth);
    assert!(!fake.calls().iter().any(|c| c == "unpin_netns"));
    assert_eq!(ipam.address_of(&eid("c1")), Some(a1));
    let claim = e.reclaim_claim().unwrap();
    // アドレスを保持するため quarantine も含む（回収後に記録を外して再 attach が AlreadyExists になるのを防ぐ）。
    assert!(claim.includes_veth() && claim.includes_netns() && claim.includes_quarantine());
    assert!(claim.quarantine_only().is_some());
    let fake2 = Fake::default();
    let report = reclaim_failed_attach_with(&fake2, &claim, &netns_dir());
    assert!(report.is_ok(), "{:?}", fake2.calls());
    assert!(fake2.calls().iter().any(|c| c == "delete_link 21"));
}

/// NET-1・#3062: unpin に失敗したらアドレスを保持し、請求書は netns だけを含む。
#[test]
fn net1_detach_unpin_failure_keeps_address() {
    let (net, mut ipam, mut ports) = setup();
    let c1 = attached(&mut ipam, "c1");
    let a1 = c1.address;
    let fake = Fake {
        unpin_fails: true,
        ..Fake::default()
    };
    let e = detach::detach_container_with(&fake, &net, c1, Vec::new(), &mut ipam, &mut ports)
        .unwrap_err();
    assert_eq!(e.step, DeleteStep::UnpinNetns);
    assert_eq!(ipam.address_of(&eid("c1")), Some(a1));
    let claim = e.reclaim_claim().unwrap();
    assert!(!claim.includes_veth() && claim.includes_netns() && claim.includes_quarantine());
    assert_eq!(
        FailedAttachClaim::from_record(&claim.to_record()),
        Ok(claim)
    );
}

/// NET-1・#3062: 請求書の pin 識別子は接続時にハンドルへ固定した値で、現在のパスから採り直さない
/// （パス上の pin が作り直されても、古いハンドルの請求書が新世代の識別子を取り込まない）。
#[test]
fn net1_detach_claim_uses_pin_identity_fixed_at_attach() {
    use crate::network::attach_claim::TEST_PIN;
    let (net, mut ipam, mut ports) = setup();
    let mut c1 = attached(&mut ipam, "c1");
    // 接続時に控えた識別子。テストのパスには実在の pin が無く、採り直せば `None` になる。
    c1.pin_identity = Some(TEST_PIN);
    let fake = Fake {
        veth_delete_err: Some(NetErrorCode::Internal),
        ..Fake::default()
    };
    let e = detach::detach_container_with(&fake, &net, c1, Vec::new(), &mut ipam, &mut ports)
        .unwrap_err();
    assert_eq!(e.reclaim_claim().unwrap().pin(), Some(TEST_PIN));

    // 識別子を控えていない接続は、パスから採り直さず `None` のまま。
    let mut c2 = attached(&mut ipam, "c2");
    c2.pin_identity = None;
    let e = detach::detach_container_with(&fake, &net, c2, Vec::new(), &mut ipam, &mut ports)
        .unwrap_err();
    assert_eq!(e.reclaim_claim().unwrap().pin(), None);
}

/// 期限切れの切り離しの共通照合: c2 は不変で、請求書は veth・netns・quarantine を持つ。
fn assert_deadline_claim(e: &detach::ContainerDetachError<()>) {
    assert_eq!(e.code(), NetErrorCode::Timeout);
    assert_eq!(e.message(), "detach deadline exceeded");
    let rec = e.reclaim_claim().unwrap().to_record();
    assert!(
        rec.contains("veth=1\nnetns=1\n") && rec.contains("quarantine=1\n"),
        "{rec}"
    );
}

/// REPAIR-5・NET-1・#3258: 1 件解除した後に全体の期限が切れると、残りの公開と veth の要求を出さず、
/// 公開・veth・pin・アドレスを `Present` の取り残しとして報告し、アドレスと予約を保持する。
#[test]
fn repair5_detach_deadline_exceeded_stops_remaining_ports() {
    let mut t = two_containers();
    let c1 = t.c1.take().unwrap();
    let extra = std::mem::take(&mut t.extra);
    let fake = Fake {
        expire_after_calls: Some(2),
        ..Fake::default()
    };
    let e = detach(&fake, &mut t, c1, extra).unwrap_err();
    let tbl = t.net.table.as_str();
    assert_eq!(
        fake.calls(),
        vec![
            format!("table_info {tbl}"),
            format!("delete_rules {tbl} 4/5")
        ]
    );
    assert_eq!(e.step, DeleteStep::UnpublishPorts);
    assert_deadline_claim(&e);
    assert_eq!(
        e.report.removed,
        vec![DeleteResource::PortRules(eid("c1"), pub_of(8081))]
    );
    assert_eq!(
        e.report.leftover,
        vec![
            (
                DeleteResource::PortRules(eid("c1"), pub_of(8080)),
                ResourceState::Present
            ),
            (DeleteResource::Veth(host_of("c1")), ResourceState::Present),
            (DeleteResource::Netns(pin("c1")), ResourceState::Present),
            (
                DeleteResource::Address(eid("c1"), t.a1),
                ResourceState::Present
            ),
        ]
    );
    assert_eq!(t.ipam.address_of(&eid("c1")), Some(t.a1));
    assert_eq!(held(&mut t.ports, "c1"), 1);
    assert_eq!(t.ipam.address_of(&eid("c2")), Some(t.a2));
    assert_eq!(held(&mut t.ports, "c2"), 1);
}

/// REPAIR-5・NET-1・#3258: 公開の解除が済んだ後に期限が切れると、veth の要求を出さずに取り残す。
#[test]
fn repair5_detach_deadline_exceeded_before_veth() {
    let mut t = two_containers();
    let c1 = t.c1.take().unwrap();
    let extra = std::mem::take(&mut t.extra);
    let fake = Fake {
        expire_after_calls: Some(4),
        ..Fake::default()
    };
    let e = detach(&fake, &mut t, c1, extra).unwrap_err();
    assert_eq!(fake.calls().len(), 4);
    assert!(
        !fake.calls().iter().any(|c| c.starts_with("link_attachment")
            || c.starts_with("delete_link")
            || c == "unpin_netns")
    );
    assert_eq!(e.step, DeleteStep::DeleteVeth);
    assert_deadline_claim(&e);
    assert_eq!(
        e.report.removed,
        vec![
            DeleteResource::PortRules(eid("c1"), pub_of(8081)),
            DeleteResource::PortRules(eid("c1"), pub_of(8080)),
        ]
    );
    assert_eq!(
        e.report.leftover,
        vec![
            (DeleteResource::Veth(host_of("c1")), ResourceState::Present),
            (DeleteResource::Netns(pin("c1")), ResourceState::Present),
            (
                DeleteResource::Address(eid("c1"), t.a1),
                ResourceState::Present
            ),
        ]
    );
    assert_eq!(t.ipam.address_of(&eid("c1")), Some(t.a1));
    assert_eq!(held(&mut t.ports, "c1"), 0);
}

/// REPAIR-5・NET-1・#3258: 最初から期限が切れていれば、カーネル要求は 1 件も出さない。
#[test]
fn repair5_detach_deadline_exceeded_before_any_request() {
    let mut t = two_containers();
    let c1 = t.c1.take().unwrap();
    let extra = std::mem::take(&mut t.extra);
    let fake = Fake {
        expire_after_calls: Some(0),
        ..Fake::default()
    };
    let e = detach(&fake, &mut t, c1, extra).unwrap_err();
    assert!(fake.calls().is_empty());
    assert_eq!(e.step, DeleteStep::UnpublishPorts);
    assert_deadline_claim(&e);
    assert!(e.report.removed.is_empty());
    assert_eq!(
        e.report.leftover,
        vec![
            (
                DeleteResource::PortRules(eid("c1"), pub_of(8081)),
                ResourceState::Present
            ),
            (
                DeleteResource::PortRules(eid("c1"), pub_of(8080)),
                ResourceState::Present
            ),
            (DeleteResource::Veth(host_of("c1")), ResourceState::Present),
            (DeleteResource::Netns(pin("c1")), ResourceState::Present),
            (
                DeleteResource::Address(eid("c1"), t.a1),
                ResourceState::Present
            ),
        ]
    );
    assert_eq!(held(&mut t.ports, "c1"), 2);
}
