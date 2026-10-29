//! `network::reconcile` の単体試験（root 不要。カーネル操作は fake。NET-1・NET-7・REPAIR-4・#3346）。

use std::cell::{Cell, RefCell};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use super::*;
use crate::network::recorded::{RecordedError, create_recorded_with};
use crate::network::{NetworkName, PortProtocol, PortPublish, PublishedListeners};
use crate::network_store::{
    MemberIntent, MemberRecord, NetworkDefinition, NetworkStore, RecordedPublish,
};
use crate::nftables_rules::NftRuleHandle;

const TOKEN: &str = "fandhe-net:web:1:0:0";
const OTHER_TOKEN: &str = "fandhe-net:web:9:9:9";
const NETNS_DIR: &str = "/run/fc-test-ns";

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "fc-netreconcile-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        Tmp(p)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn pfx(a: [u8; 4], len: u8) -> crate::netlink_route::IpPrefix {
    crate::netlink_route::IpPrefix::new(IpAddr::V4(Ipv4Addr::from(a)), len).unwrap()
}
fn name() -> NetworkName {
    NetworkName::new("web").unwrap()
}
fn setup(t: &Tmp) -> NetworkStore {
    let store = NetworkStore::open(&t.0).unwrap();
    store
        .create(&NetworkDefinition::bridge("web", pfx([10, 0, 0, 0], 24)).unwrap())
        .unwrap();
    store
}
fn host() -> HostGeneration {
    HostGeneration::current().unwrap()
}
fn mid(s: &str) -> MemberId {
    MemberId::new(s).unwrap()
}
fn ep(s: &str) -> EndpointId {
    EndpointId::new(s).unwrap()
}
fn member_token(id: &str) -> String {
    format!("{TOKEN}/ep/{id}/g/00000000000000000000000000000001")
}
fn intent(op: RealizedOp, token: &str) -> RealizedIntent {
    RealizedIntent::new(
        op,
        name(),
        token,
        pfx([10, 0, 0, 0], 24),
        pfx([10, 0, 0, 1], 24),
    )
    .unwrap()
}
fn realized_rec() -> RealizedRecord {
    let names = NetworkResourceNames::derive(&name()).unwrap();
    let created = CreatedNetwork {
        name: name(),
        bridge: names.bridge().clone(),
        bridge_index: IfIndex::new(7).unwrap(),
        bridge_token: TOKEN.to_owned(),
        table: names.table().clone(),
        gateway: pfx([10, 0, 0, 1], 24),
        name_resolution: NameResolution::default(),
    };
    RealizedRecord::from_created(
        &created,
        pfx([10, 0, 0, 0], 24),
        NftTableHandle::new(42).unwrap(),
        host(),
    )
    .unwrap()
}
fn member_intent(id: &str, last: u8) -> MemberIntent {
    MemberIntent::new(
        mid(id),
        ep(id),
        pfx([10, 0, 0, last], 24),
        &member_token(id),
    )
    .unwrap()
}
fn member_rec(id: &str, last: u8) -> MemberRecord {
    MemberRecord::new(
        mid(id),
        ep(id),
        pfx([10, 0, 0, last], 24),
        &member_token(id),
        std::path::Path::new(NETNS_DIR),
        (8, 9),
        &[],
    )
    .unwrap()
}
fn port(host_port: u16) -> PortPublish {
    PortPublish::new(
        PortProtocol::Tcp,
        Ipv4Addr::new(192, 168, 1, 5),
        host_port,
        80,
    )
    .unwrap()
}
fn table_reply(handle: u64, userdata: Option<&str>) -> TableInfo {
    let mut p = vec![2u8, 0, 0, 0];
    let mut attrs: Vec<(u16, Vec<u8>)> = vec![(4, handle.to_be_bytes().to_vec())];
    if let Some(u) = userdata {
        attrs.push((6, u.as_bytes().to_vec()));
    }
    for (ty, data) in attrs {
        p.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        p.extend_from_slice(&ty.to_ne_bytes());
        p.extend_from_slice(&data);
        while p.len() % 4 != 0 {
            p.push(0);
        }
    }
    TableInfo::decode(&p).unwrap()
}

/// bridge の状態の代役。
#[derive(Clone)]
enum Br {
    Absent,
    Alias(Option<String>),
    Fail,
}
/// テーブルの状態の代役。
#[derive(Clone)]
enum Tb {
    Absent,
    Userdata(Option<String>),
    Fail,
}

struct Fake {
    bridge: RefCell<Br>,
    table: RefCell<Tb>,
    live_veths: RefCell<Vec<String>>,
    veth_fails: Cell<bool>,
    pin: RefCell<Result<bool, NetErrorCode>>,
    dnat: RefCell<Result<Vec<PublishedListener>, NetErrorCode>>,
    rollback_ok: Cell<bool>,
    /// 巻き戻しの請求書の (bridge, table) の組。
    rollbacks: RefCell<Vec<(bool, bool)>>,
    dnat_calls: Cell<usize>,
}

impl Fake {
    fn new(bridge: Br, table: Tb) -> Self {
        Self {
            bridge: RefCell::new(bridge),
            table: RefCell::new(table),
            live_veths: RefCell::new(Vec::new()),
            veth_fails: Cell::new(false),
            pin: RefCell::new(Ok(true)),
            dnat: RefCell::new(Ok(Vec::new())),
            rollback_ok: Cell::new(true),
            rollbacks: RefCell::new(Vec::new()),
            dnat_calls: Cell::new(0),
        }
    }
    fn owned() -> Self {
        Self::new(
            Br::Alias(Some(TOKEN.to_owned())),
            Tb::Userdata(Some(TOKEN.to_owned())),
        )
    }
    fn absent() -> Self {
        Self::new(Br::Absent, Tb::Absent)
    }
    fn rollback_count(&self) -> usize {
        self.rollbacks.borrow().len()
    }
}

fn err(code: NetErrorCode) -> NetError {
    NetError::new(code, "fake")
}

impl ReconcileOps for Fake {
    fn link_attachment(&self, link: &IfName) -> Result<LinkAttachment, NetError> {
        let bridge = NetworkResourceNames::derive(&name()).unwrap();
        if link == bridge.bridge() {
            return match &*self.bridge.borrow() {
                Br::Absent => Err(err(NetErrorCode::NotFound)),
                Br::Alias(a) => Ok(LinkAttachment {
                    index: IfIndex::new(7).unwrap(),
                    master: None,
                    alias: a.clone(),
                }),
                Br::Fail => Err(err(NetErrorCode::Timeout)),
            };
        }
        if self.veth_fails.get() {
            return Err(err(NetErrorCode::Timeout));
        }
        if self.live_veths.borrow().iter().any(|v| v == link.as_str()) {
            return Ok(LinkAttachment {
                index: IfIndex::new(10).unwrap(),
                master: Some(IfIndex::new(7).unwrap()),
                alias: Some(member_token("x")),
            });
        }
        Err(err(NetErrorCode::NotFound))
    }
    fn table_info(&self, _table: &NftName) -> Result<TableInfo, NetError> {
        match &*self.table.borrow() {
            Tb::Absent => Err(err(NetErrorCode::NotFound)),
            Tb::Userdata(u) => Ok(table_reply(42, u.as_deref())),
            Tb::Fail => Err(err(NetErrorCode::Timeout)),
        }
    }
    fn rollback(&self, claim: &FailedCreateClaim) -> Result<(), NetError> {
        self.rollbacks
            .borrow_mut()
            .push((claim.includes_bridge(), claim.includes_table()));
        if !self.rollback_ok.get() {
            return Err(err(NetErrorCode::Internal));
        }
        if claim.includes_bridge() {
            *self.bridge.borrow_mut() = Br::Absent;
        }
        if claim.includes_table() {
            *self.table.borrow_mut() = Tb::Absent;
        }
        Ok(())
    }
    fn pin_absent(&self, _dir: &Path, _endpoint: &EndpointId) -> Result<bool, NetError> {
        (*self.pin.borrow()).map_err(err)
    }
    fn dnat_listeners(&self, _table: &NftName) -> Result<Vec<PublishedListener>, NetError> {
        self.dnat_calls.set(self.dnat_calls.get() + 1);
        self.dnat.borrow().clone().map_err(err)
    }
}

fn run(
    guard: &NetworkLockGuard<'_>,
    fake: &Fake,
    dir: Option<&Path>,
) -> Result<ReconcileReport, NetError> {
    reconcile_recorded_with(&host(), guard, dir, fake)
}

fn code<T: std::fmt::Debug>(r: Result<T, NetError>) -> NetErrorCode {
    r.unwrap_err().code()
}

/// create の途中で落ちた状態（意図記録のみ）を作る。
fn crashed_create(n: &NetworkLockGuard<'_>) {
    n.write_realized_intent(&intent(RealizedOp::Create, TOKEN))
        .unwrap();
}

/// NET-1・#3346: カーネルに何も無ければ意図記録を消し、続く create が成功する。
#[test]
fn net1_3346_create_intent_absent_kernel_discards_intent() {
    let t = Tmp::new("absent");
    let store = setup(&t);
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    crashed_create(&n);
    let fake = Fake::absent();
    let report = run(&n, &fake, None).unwrap();
    assert_eq!(report.realized, RealizedReconcile::Discarded);
    assert_eq!(n.realized_intent().unwrap(), None);
    assert_eq!(n.realized().unwrap(), None);
    assert_eq!(fake.rollback_count(), 0);
}

/// NET-1・#3346: 実体が揃っていれば `realized` へ昇格する（ifindex 7・handle 42・gateway・subnet が具体値で一致）。
#[test]
fn net1_3346_create_intent_complete_promotes() {
    let t = Tmp::new("promote");
    let store = setup(&t);
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    crashed_create(&n);
    let fake = Fake::owned();
    let report = run(&n, &fake, None).unwrap();
    assert_eq!(report.realized, RealizedReconcile::Promoted);
    assert_eq!(n.realized_intent().unwrap(), None);
    assert_eq!(n.realized().unwrap(), Some(realized_rec()));
    assert_eq!(fake.rollback_count(), 0, "昇格ではカーネルを変更しない");
}

/// NET-1・#3346: 混在（bridge だけ所有）は所有する資源だけを巻き戻す。
#[test]
fn net1_3346_create_intent_partial_rolls_back_owned_only() {
    let t = Tmp::new("partial");
    let store = setup(&t);
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    crashed_create(&n);
    let fake = Fake::new(Br::Alias(Some(TOKEN.to_owned())), Tb::Absent);
    let report = run(&n, &fake, None).unwrap();
    assert_eq!(report.realized, RealizedReconcile::RolledBack);
    assert_eq!(*fake.rollbacks.borrow(), vec![(true, false)]);
    assert_eq!(n.realized_intent().unwrap(), None);
    assert_eq!(n.realized().unwrap(), None);
}

/// NET-1・#3346: 証明できない場合は何も変えず、続く操作は `FailedPrecondition` のまま。
#[test]
fn net1_3346_create_intent_unproven_is_fail_closed() {
    let cases: Vec<(&str, Fake)> = vec![
        (
            "empty-alias",
            Fake::new(Br::Alias(None), Tb::Userdata(Some(TOKEN.into()))),
        ),
        (
            "other-alias",
            Fake::new(
                Br::Alias(Some(OTHER_TOKEN.into())),
                Tb::Userdata(Some(TOKEN.into())),
            ),
        ),
        ("bridge-fail", Fake::new(Br::Fail, Tb::Absent)),
        (
            "table-timeout",
            Fake::new(Br::Alias(Some(TOKEN.into())), Tb::Fail),
        ),
        (
            "table-userdata-mismatch",
            Fake::new(
                Br::Alias(Some(TOKEN.into())),
                Tb::Userdata(Some(OTHER_TOKEN.into())),
            ),
        ),
        (
            "table-no-userdata",
            Fake::new(Br::Alias(Some(TOKEN.into())), Tb::Userdata(None)),
        ),
    ];
    for (tag, fake) in cases {
        let t = Tmp::new(tag);
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        crashed_create(&n);
        let report = run(&n, &fake, None).unwrap();
        assert_eq!(
            report.realized,
            RealizedReconcile::Unresolved(Unresolved::Unproven),
            "{tag}"
        );
        assert_eq!(fake.rollback_count(), 0, "{tag}");
        assert_eq!(
            n.realized_intent().unwrap(),
            Some(intent(RealizedOp::Create, TOKEN)),
            "{tag}"
        );
        // 続く create は未解決の操作として拒否される。
        let def = NetworkDefinition::bridge("web", pfx([10, 0, 0, 0], 24)).unwrap();
        let r = create_recorded_with(
            &host(),
            &n,
            &def,
            pfx([10, 0, 0, 1], 24),
            |_| unreachable!("create must not run"),
            |_| unreachable!(),
        );
        match r {
            Err(RecordedError::Store(e)) => {
                assert_eq!(e.code(), NetErrorCode::FailedPrecondition, "{tag}");
                assert_eq!(
                    e.message(),
                    "network has an unreconciled operation",
                    "{tag}"
                );
            }
            other => panic!("{tag}: unexpected {other:?}"),
        }
    }
}

/// REPAIR-4・#3346: 巻き戻しに失敗したら意図記録を残し、次回の照合が再試行して収束する。
#[test]
fn net1_3346_rollback_failure_keeps_intent() {
    let t = Tmp::new("rbfail");
    let store = setup(&t);
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    crashed_create(&n);
    let fake = Fake::new(Br::Alias(Some(TOKEN.into())), Tb::Absent);
    fake.rollback_ok.set(false);
    let report = run(&n, &fake, None).unwrap();
    assert_eq!(
        report.realized,
        RealizedReconcile::Unresolved(Unresolved::RollbackIncomplete)
    );
    assert!(n.realized_intent().unwrap().is_some());
    fake.rollback_ok.set(true);
    let report = run(&n, &fake, None).unwrap();
    assert_eq!(report.realized, RealizedReconcile::RolledBack);
    assert_eq!(fake.rollback_count(), 2);
    assert_eq!(n.realized_intent().unwrap(), None);
}

/// #3346: create の意図記録と `realized` が両方ある窓は、トークン一致なら意図記録だけ消す。不一致は DataLoss。
#[test]
fn net1_3346_create_intent_with_realized_removes_intent() {
    let t = Tmp::new("createreal");
    let store = setup(&t);
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    n.commit_realized(&realized_rec()).unwrap();
    n.write_realized_intent(&intent(RealizedOp::Create, TOKEN))
        .unwrap();
    let fake = Fake::owned();
    let report = run(&n, &fake, None).unwrap();
    assert_eq!(report.realized, RealizedReconcile::Completed);
    assert_eq!(n.realized_intent().unwrap(), None);
    assert_eq!(n.realized().unwrap(), Some(realized_rec()));
    // 不一致。
    n.write_realized_intent(&intent(RealizedOp::Create, OTHER_TOKEN))
        .unwrap();
    assert_eq!(code(run(&n, &fake, None)), NetErrorCode::DataLoss);
    assert!(n.realized_intent().unwrap().is_some());
}

/// NET-1・#3346: 削除の途中で落ちた状態を完了させる。
#[test]
fn net1_3346_delete_intent_completes_delete() {
    // (a) カーネルは削除済み。 (b) 資源が残っていて巻き戻す。
    for (tag, fake, rollbacks) in [
        ("gone", Fake::absent(), 0usize),
        ("owned", Fake::owned(), 1usize),
    ] {
        let t = Tmp::new(tag);
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        n.commit_realized(&realized_rec()).unwrap();
        n.write_realized_intent(&intent(RealizedOp::Delete, TOKEN))
            .unwrap();
        let report = run(&n, &fake, None).unwrap();
        assert_eq!(report.realized, RealizedReconcile::Completed, "{tag}");
        assert_eq!(n.realized().unwrap(), None, "{tag}");
        assert_eq!(n.realized_intent().unwrap(), None, "{tag}");
        assert_eq!(fake.rollback_count(), rollbacks, "{tag}");
    }
    // 意図記録の gateway が realized と違えば DataLoss。
    let t = Tmp::new("dlmismatch");
    let store = setup(&t);
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    n.commit_realized(&realized_rec()).unwrap();
    n.write_realized_intent(
        &RealizedIntent::new(
            RealizedOp::Delete,
            name(),
            TOKEN,
            pfx([10, 0, 0, 0], 24),
            pfx([10, 0, 0, 2], 24),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(code(run(&n, &Fake::absent(), None)), NetErrorCode::DataLoss);
}

/// #3346: `realized` を消した後に落ちた delete（意図記録のみ）は意図記録を消す。
#[test]
fn net1_3346_delete_intent_without_realized_removes_intent() {
    let t = Tmp::new("delnoreal");
    let store = setup(&t);
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    n.write_realized_intent(&intent(RealizedOp::Delete, TOKEN))
        .unwrap();
    let report = run(&n, &Fake::absent(), None).unwrap();
    assert_eq!(report.realized, RealizedReconcile::Completed);
    assert_eq!(n.realized_intent().unwrap(), None);
}

/// #3346: 巻き戻しの成功後に同じトークンの `pending-reclaim/create` を消し、違うトークンのものは残す。
#[test]
fn net1_3346_pending_create_claim_removed_after_rollback() {
    for (tag, saved_token, remains) in [("same", TOKEN, false), ("other", OTHER_TOKEN, true)] {
        let t = Tmp::new(tag);
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        crashed_create(&n);
        n.save_reclaim_create(
            &FailedCreateClaim::for_reconcile(name(), saved_token, true, true).unwrap(),
        )
        .unwrap();
        let fake = Fake::new(Br::Alias(Some(TOKEN.into())), Tb::Absent);
        let report = run(&n, &fake, None).unwrap();
        assert_eq!(report.realized, RealizedReconcile::RolledBack, "{tag}");
        assert_eq!(
            n.reclaim_records().unwrap().create.is_some(),
            remains,
            "{tag}"
        );
    }
}

fn ready(n: &NetworkLockGuard<'_>) {
    n.commit_realized(&realized_rec()).unwrap();
}

/// NET-7・#3346: 実体の無い意図記録を消し、アドレスが再び払い出される。
#[test]
fn net7_3346_sweep_removes_orphan_intent_and_frees_address() {
    let t = Tmp::new("sweep");
    let store = setup(&t);
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    ready(&n);
    n.write_member_intent(&member_intent("c1", 2)).unwrap();
    let mut ipam = n.rebuild_ipam().unwrap();
    assert_eq!(
        ipam.allocate(&ep("c2")).unwrap(),
        pfx([10, 0, 0, 3], 24),
        "意図記録のアドレスは使用中"
    );
    let fake = Fake::owned();
    let report = run(&n, &fake, Some(Path::new(NETNS_DIR))).unwrap();
    assert_eq!(report.realized, RealizedReconcile::None);
    assert_eq!(report.removed_intents, vec![mid("c1")]);
    assert!(report.kept_intents.is_empty());
    assert!(n.member_intents().unwrap().is_empty());
    let mut ipam = n.rebuild_ipam().unwrap();
    assert_eq!(ipam.allocate(&ep("c3")).unwrap(), pfx([10, 0, 0, 2], 24));
}

/// NET-7・#3346: 実体のある意図記録は消さず、理由を報告する。
#[test]
fn net7_3346_sweep_keeps_intents_with_substance() {
    let veth = VethNames::derive(&ep("c1")).unwrap();
    let veth_name = veth.host().as_str().to_owned();
    type Setup = Box<dyn Fn(&Fake)>;
    let cases: Vec<(&str, Setup, bool, IntentKeep)> = vec![
        (
            "veth-present",
            Box::new(move |f: &Fake| f.live_veths.borrow_mut().push(veth_name.clone())),
            true,
            IntentKeep::VethPresent,
        ),
        (
            "veth-query-fails",
            Box::new(|f: &Fake| f.veth_fails.set(true)),
            true,
            IntentKeep::VethUnproven,
        ),
        (
            "pin-present",
            Box::new(|f: &Fake| *f.pin.borrow_mut() = Ok(false)),
            true,
            IntentKeep::PinPresent,
        ),
        (
            "pin-unknown",
            Box::new(|f: &Fake| *f.pin.borrow_mut() = Err(NetErrorCode::Internal)),
            true,
            IntentKeep::PinUnknown,
        ),
        (
            "no-netns-dir",
            Box::new(|_: &Fake| {}),
            false,
            IntentKeep::PinUnknown,
        ),
        (
            "dnat-dump-fails",
            Box::new(|f: &Fake| *f.dnat.borrow_mut() = Err(NetErrorCode::Timeout)),
            true,
            IntentKeep::DnatUnaccounted,
        ),
        (
            "dnat-unaccounted",
            Box::new(|f: &Fake| {
                *f.dnat.borrow_mut() = Ok(PublishedListeners::from_ports_for_test(&[port(8080)])
                    .listeners()
                    .to_vec());
            }),
            true,
            IntentKeep::DnatUnaccounted,
        ),
    ];
    for (tag, setup_fake, with_dir, keep) in cases {
        let t = Tmp::new(tag);
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        ready(&n);
        n.write_member_intent(&member_intent("c1", 2)).unwrap();
        let fake = Fake::owned();
        setup_fake(&fake);
        let dir = with_dir.then(|| Path::new(NETNS_DIR));
        let report = run(&n, &fake, dir).unwrap();
        assert!(report.removed_intents.is_empty(), "{tag}");
        assert_eq!(report.kept_intents, vec![(mid("c1"), keep)], "{tag}");
        assert_eq!(n.member_intents().unwrap().len(), 1, "{tag}");
    }
    // attach の請求書がある意図記録は、カーネル照会の前に残す。
    let t = Tmp::new("claim");
    let store = setup(&t);
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    ready(&n);
    n.write_member_intent(&member_intent("c1", 2)).unwrap();
    let claim = crate::network::FailedAttachClaim::from_record(&format!(
        "fandhe-net-attach-claim v1\nnetwork=web\nendpoint=c1\ntoken={TOKEN}\ngeneration=00000000000000000000000000000001\nveth=1\nnetns=0\npin=-\nquarantine=1\n"
    ))
    .unwrap();
    n.save_reclaim_attach(&claim).unwrap();
    let report = run(&n, &Fake::owned(), Some(Path::new(NETNS_DIR))).unwrap();
    assert_eq!(
        report.kept_intents,
        vec![(mid("c1"), IntentKeep::AttachClaim)]
    );
}

/// NET-7・#3346: 公開の記録で説明できる DNAT（1 公開 2 ルール）があっても、候補は掃除できる。本数超過は残す。
#[test]
fn net7_3346_sweep_dnat_accounting_uses_published_records() {
    let published = port(8080);
    let h = |n: u64| NftRuleHandle::new(n).unwrap();
    let both = PublishedListeners::from_ports_for_test(&[published, published])
        .listeners()
        .to_vec();
    let three = PublishedListeners::from_ports_for_test(&[published, published, published])
        .listeners()
        .to_vec();
    for (tag, observed, removed) in [("two-rules", both, true), ("three-rules", three, false)] {
        let t = Tmp::new(tag);
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        ready(&n);
        let owner = member_rec("c9", 5)
            .with_publishes(
                NftTableHandle::new(42).unwrap(),
                vec![RecordedPublish::new(published, h(1), h(2))],
            )
            .unwrap();
        n.commit_member(&owner).unwrap();
        n.write_member_intent(&member_intent("c1", 2)).unwrap();
        let fake = Fake::owned();
        *fake.dnat.borrow_mut() = Ok(observed);
        let report = run(&n, &fake, Some(Path::new(NETNS_DIR))).unwrap();
        assert_eq!(report.removed_intents.len(), usize::from(removed), "{tag}");
        assert_eq!(fake.dnat_calls.get(), 1, "{tag}");
        assert_eq!(n.members().unwrap().len(), 1, "確定記録は残る");
    }
}

/// NET-7・#3346: 確定記録と同一の意図記録は冗長として消し、確定記録は残す。
#[test]
fn net7_3346_sweep_removes_redundant_intent_with_member() {
    let t = Tmp::new("redundant");
    let store = setup(&t);
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    ready(&n);
    n.write_member_intent(&member_intent("c1", 2)).unwrap();
    n.commit_member(&member_rec("c1", 2)).unwrap();
    // commit_member が意図記録を消す実装でも、残った場合の窓を模擬するため再度書く。
    let _ = n.write_member_intent(&member_intent("c1", 2));
    let fake = Fake::owned();
    let report = run(&n, &fake, None).unwrap();
    assert_eq!(n.member_intents().unwrap().len(), 0);
    assert_eq!(n.members().unwrap().len(), 1);
    assert!(report.kept_intents.is_empty());
    assert_eq!(
        fake.dnat_calls.get(),
        0,
        "冗長な記録の掃除ではカーネルを見ない"
    );
}

/// #3346: 共有ロックのガードでは何も変えず、カーネルにも触れない。
#[test]
fn net1_3346_shared_guard_reconcile_is_noop() {
    let t = Tmp::new("shared");
    let store = setup(&t);
    {
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        crashed_create(&n);
    }
    let g = store.lock_global_shared().unwrap();
    let n = g.lock_network_shared(&name()).unwrap();
    let fake = Fake::owned();
    let report = run(&n, &fake, None).unwrap();
    assert_eq!(report.realized, RealizedReconcile::None);
    assert_eq!(fake.rollback_count(), 0);
    assert!(n.realized_intent().unwrap().is_some());
}

/// #3346: 未解決の `realized.intent` が残る間は掃除しない。
#[test]
fn net1_3346_unresolved_realized_skips_sweep() {
    let t = Tmp::new("skipsweep");
    let store = setup(&t);
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    n.commit_realized(&realized_rec()).unwrap();
    n.write_realized_intent(&intent(RealizedOp::Delete, TOKEN))
        .unwrap();
    n.write_member_intent(&member_intent("c1", 2)).unwrap();
    let fake = Fake::new(Br::Alias(None), Tb::Userdata(Some(TOKEN.into())));
    let report = run(&n, &fake, Some(Path::new(NETNS_DIR))).unwrap();
    assert_eq!(
        report.realized,
        RealizedReconcile::Unresolved(Unresolved::Unproven)
    );
    assert_eq!(n.member_intents().unwrap().len(), 1);
    assert_eq!(fake.dnat_calls.get(), 0);
}
