//! ホストの再起動をまたぐ記録だけの detach（`detach_member_after_reboot_with`）の単体試験
//! （NET-1・NET-3・SEC-1・REPAIR-4・#3412）。
//!
//! 親の `recorded::tests` の補助（`Tmp`・`attach_two` 相当・`PortRegistry` の準備）を再利用する。
//! 前の boot の記録は、別の boot ID の世代で attach して作る。期待値は具体値で照合する。

use super::*;
use crate::instrument::NetOpOutcome;
use crate::instrument::testing::Collect;
use crate::network::FailedAttachClaim;

/// 前の boot を表す boot ID（現在の boot ID とは必ず違う固定値）。
const OLD_BOOT: &str = "00000000-0000-4000-8000-000000000000";

fn old_boot() -> HostGeneration {
    HostGeneration::new(OLD_BOOT, host().netns()).unwrap()
}

/// c1（Active の公開 1 件と墓標 1 件・pin つき）と c2（公開なし）を、前の boot の世代で attach したストアを用意する。
fn attach_two_in_old_boot(t: &Tmp) {
    let store = setup(t);
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    realize_in(&n, old_boot());
    let s1 = spec("c1");
    attach_recorded_with(
        &old_boot(),
        &n,
        &mid("c1"),
        &s1,
        &[],
        live_table(42),
        |ipam, generation| {
            let mut att = run_with_publish_and_pin(&s1)(ipam, generation)?;
            att.published_ports.push(PublishedPort::new(
                &name(),
                BRIDGE_TOKEN,
                s1.endpoint(),
                api_publish(),
                (rule(4), rule(5)),
            ));
            Ok(att)
        },
    )
    .unwrap();
    let rec = n.members().unwrap().remove(0);
    n.replace_member(&rec.with_unpublished(&api_publish()).unwrap())
        .unwrap();
    let s2 = spec("c2");
    attach_recorded_with(
        &old_boot(),
        &n,
        &mid("c2"),
        &s2,
        &[],
        live_table(42),
        ok_run(&s2),
    )
    .unwrap();
}

/// 予約表に c1 の 2 件（web・api）と c2 の 1 件を載せる。
fn reserved() -> PortRegistry {
    let mut reg = PortRegistry::new();
    reg.reserve(
        &name(),
        &EndpointId::new("c1").unwrap(),
        &[web_publish(), api_publish()],
    )
    .unwrap();
    let other =
        PortPublish::new(PortProtocol::Tcp, Ipv4Addr::new(192, 0, 2, 10), 9191, 80).unwrap();
    reg.reserve(&name(), &EndpointId::new("c2").unwrap(), &[other])
        .unwrap();
    reg
}

type RebootOut = Result<NetworkDeleteReport, RecordedError<(), NetworkDeleteReport>>;

/// 再起動をまたぐ detach を、`run` に渡った請求書を控えて実行する（現在の boot は `host()`）。
fn after_reboot(
    n: &NetworkLockGuard<'_>,
    id: &str,
    dir: &str,
    reg: &mut PortRegistry,
    run_result: Result<(), ()>,
) -> (RebootOut, Option<FailedAttachClaim>) {
    let seen = std::cell::RefCell::new(None);
    let r = detach_member_after_reboot_with(&host(), n, &mid(id), Path::new(dir), reg, |c, d| {
        assert_eq!(d.path(), Path::new(NETNS_DIR));
        assert_eq!(d.dir_id(), (8, 9));
        *seen.borrow_mut() = Some(c.clone());
        run_result.map(|()| NetworkDeleteReport::default())
    });
    (r, seen.into_inner())
}

/// NET-1・NET-3・#3412: boot ID が違う記録は、ルールを載せない請求書で回収され、c1 の Active・墓標の予約が解放される。
/// c2 の記録・アドレス・予約と `realized` は変わらない。
#[test]
fn net1_3412_after_reboot_releases_member_and_reservations() {
    let t = Tmp::new("reboot-ok");
    attach_two_in_old_boot(&t);
    let store = NetworkStore::open(&t.0).unwrap();
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    assert_eq!(n.rebuild_ipam().unwrap().allocated_count(), 2);
    let realized_before = n.realized().unwrap().unwrap();
    let mut reg = reserved();
    assert_eq!(reg.len(), 3);
    let (r, claim) = after_reboot(&n, "c1", NETNS_DIR, &mut reg, Ok(()));
    assert!(r.is_ok());
    let claim = claim.expect("run was called");
    assert_eq!(claim.network(), &name());
    assert_eq!(claim.endpoint().as_str(), "c1");
    assert_eq!(claim.token(), BRIDGE_TOKEN);
    assert!(claim.includes_veth() && claim.includes_netns());
    assert!(!claim.includes_quarantine());
    assert!(claim.port_rules().is_none());
    assert_eq!(claim.pin(), Some(PIN));
    let ids: Vec<String> = n
        .members()
        .unwrap()
        .iter()
        .map(|m| m.id().as_str().to_owned())
        .collect();
    assert_eq!(ids, vec!["c2".to_owned()]);
    assert_eq!(n.rebuild_ipam().unwrap().allocated_count(), 1);
    assert_eq!(reg.len(), 1, "c1 の 2 件だけが解放され、c2 の 1 件は残る");
    assert_eq!(n.realized().unwrap().unwrap(), realized_before);
}

/// NET-3・SEC-1・#3412: 解除の印つきの公開も（通常の入口が断るのに対し）解放される。
#[test]
fn net1_3412_after_reboot_accepts_unpublishing_mark() {
    let t = Tmp::new("reboot-mark");
    attach_two_in_old_boot(&t);
    let store = NetworkStore::open(&t.0).unwrap();
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    let rec = n
        .members()
        .unwrap()
        .into_iter()
        .find(|m| m.id().as_str() == "c1")
        .unwrap();
    n.replace_member(&rec.with_unpublishing(&web_publish()).unwrap())
        .unwrap();
    // 通常の入口は世代違いで断る（印の有無の前に）。
    let normal = detach_member_recorded_with::<(), _>(
        &host(),
        &n,
        &mid("c1"),
        Path::new(NETNS_DIR),
        &mut PortRegistry::new(),
        |_, _| Ok(NetworkDeleteReport::default()),
    );
    assert_eq!(
        normal.unwrap_err().store_code(),
        Some(NetErrorCode::FailedPrecondition)
    );
    let mut reg = reserved();
    let (r, _) = after_reboot(&n, "c1", NETNS_DIR, &mut reg, Ok(()));
    assert!(r.is_ok());
    assert_eq!(n.members().unwrap().len(), 1);
    assert_eq!(reg.len(), 1);
}

/// NET-1・SEC-1・#3412: boot ID が同じ記録は、netns も同じなら通常の入口へ誘導し、netns だけ違えば手動回収に回す。
/// どちらも `run` を呼ばず、記録・予約は変わらない。
#[test]
fn net1_3412_after_reboot_refuses_same_boot() {
    let t = Tmp::new("reboot-same-boot");
    // 現在の boot の記録。
    attach_two(&t);
    let store = NetworkStore::open(&t.0).unwrap();
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    let mut reg = reserved();
    let (r, claim) = after_reboot(&n, "c1", NETNS_DIR, &mut reg, Ok(()));
    let Err(RecordedError::Store(e)) = r else {
        panic!("expected Store error");
    };
    assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
    assert_eq!(
        e.message(),
        "member belongs to the current boot; use detach_member_recorded"
    );
    assert!(claim.is_none());
    assert_eq!(n.members().unwrap().len(), 2);
    assert_eq!(reg.len(), 3);

    // 同じ boot で netns だけ違う世代。
    let cur = host();
    let other_ns = HostGeneration::new(
        cur.boot_id(),
        crate::network_store::NetnsIdentity::new(
            cur.netns().dev().wrapping_add(1),
            cur.netns().ino(),
        ),
    )
    .unwrap();
    let ran = std::cell::Cell::new(false);
    let r = detach_member_after_reboot_with::<(), _>(
        &other_ns,
        &n,
        &mid("c1"),
        Path::new(NETNS_DIR),
        &mut reg,
        |_, _| {
            ran.set(true);
            Ok(NetworkDeleteReport::default())
        },
    );
    let Err(RecordedError::Store(e)) = r else {
        panic!("expected Store error");
    };
    assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
    assert_eq!(
        e.message(),
        "record is from another network namespace of the same boot"
    );
    assert!(!ran.get());
    assert_eq!(n.members().unwrap().len(), 2);
    assert_eq!(reg.len(), 3);
}

/// NET-1・SEC-1・REPAIR-4・#3412: 関門を満たさないときは `run` を呼ばず、決まった `code`・`message` で断り、記録も変えない。
#[test]
fn net1_3412_after_reboot_gates() {
    let t = Tmp::new("reboot-gates");
    attach_two_in_old_boot(&t);
    let store = NetworkStore::open(&t.0).unwrap();
    {
        // 共有ロックのガードでは断る。
        let g = store.lock_global_shared().unwrap();
        let n = g.lock_network_shared(&name()).unwrap();
        let (r, claim) = after_reboot(&n, "c1", NETNS_DIR, &mut PortRegistry::new(), Ok(()));
        let Err(RecordedError::Store(e)) = r else {
            panic!("expected Store error");
        };
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "network operations need the exclusive network lock"
        );
        assert!(claim.is_none());
    }
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    let refuse = |id: &str, dir: &str, code: NetErrorCode, msg: &str| {
        let (r, claim) = after_reboot(&n, id, dir, &mut PortRegistry::new(), Ok(()));
        let Err(RecordedError::Store(e)) = r else {
            panic!("expected Store error for {msg}");
        };
        assert_eq!((e.code(), e.message()), (code, msg));
        assert!(claim.is_none(), "{msg}");
        assert_eq!(n.members().unwrap().len(), 2, "{msg}");
    };
    refuse(
        "nope",
        NETNS_DIR,
        NetErrorCode::NotFound,
        "member not found",
    );
    refuse(
        "c1",
        "/run/other-ns",
        NetErrorCode::InvalidArgument,
        "netns directory does not match the member record",
    );
    // 同じ endpoint の回収待ちの請求書。
    n.save_reclaim_attach(&FailedAttachClaim::for_test(
        name(),
        EndpointId::new("c1").unwrap(),
        BRIDGE_TOKEN,
        "0123456789abcdef0123456789abcdef",
        true,
        false,
        false,
    ))
    .unwrap();
    refuse(
        "c1",
        NETNS_DIR,
        NetErrorCode::FailedPrecondition,
        "endpoint has a pending reclaim record",
    );
    // 別のメンバー（請求書の無い c2）は通る。
    let (r, _) = after_reboot(&n, "c2", NETNS_DIR, &mut PortRegistry::new(), Ok(()));
    assert!(r.is_ok());
}

/// SEC-1・#3412: 別ネットワークのトークンのメンバーは `DataLoss` で断り、未完了の操作が残るネットワークは断る。
#[test]
fn net1_3412_after_reboot_refuses_foreign_token_and_unsettled() {
    let t = Tmp::new("reboot-token");
    attach_two_in_old_boot(&t);
    let store = NetworkStore::open(&t.0).unwrap();
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    let path = t.0.join("@networks/web/members/c1");
    let alt: String = BRIDGE_TOKEN
        .chars()
        .map(|c| if c == 'a' { 'b' } else { 'a' })
        .collect();
    let good = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    std::fs::write(&path, good.replace(BRIDGE_TOKEN, &alt).as_bytes()).unwrap();
    let (r, claim) = after_reboot(&n, "c1", NETNS_DIR, &mut PortRegistry::new(), Ok(()));
    assert!(claim.is_none());
    let Err(RecordedError::Store(e)) = r else {
        panic!("expected Store error");
    };
    assert_eq!(e.code(), NetErrorCode::DataLoss);
    assert_eq!(e.message(), "member token does not belong to the network");
    std::fs::write(&path, good.as_bytes()).unwrap();
    n.write_realized_intent(
        &RealizedIntent::new(
            RealizedOp::Delete,
            name(),
            BRIDGE_TOKEN,
            pfx([10, 0, 0, 0], 24),
            pfx([10, 0, 0, 1], 24),
            old_boot(),
        )
        .unwrap(),
    )
    .unwrap();
    let (r, claim) = after_reboot(&n, "c1", NETNS_DIR, &mut PortRegistry::new(), Ok(()));
    assert!(claim.is_none());
    let Err(RecordedError::Store(e)) = r else {
        panic!("expected Store error");
    };
    assert_eq!(e.message(), "network has an unreconciled operation");
}

/// REPAIR-4・#3412: `run` が失敗したら、メンバー記録・アドレス・予約を残して `Op` を返す（再実行で収束する）。
#[test]
fn net1_3412_after_reboot_run_failure_keeps_record() {
    let t = Tmp::new("reboot-fail");
    attach_two_in_old_boot(&t);
    let store = NetworkStore::open(&t.0).unwrap();
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    let mut reg = reserved();
    let (r, claim) = after_reboot(&n, "c1", NETNS_DIR, &mut reg, Err(()));
    assert!(matches!(r, Err(RecordedError::Op(()))));
    assert!(claim.is_some());
    assert_eq!(n.members().unwrap().len(), 2);
    assert_eq!(n.rebuild_ipam().unwrap().allocated_count(), 2);
    assert_eq!(reg.len(), 3);
    // 再実行は収束する。
    let (r, _) = after_reboot(&n, "c1", NETNS_DIR, &mut reg, Ok(()));
    assert!(r.is_ok());
    assert_eq!(n.members().unwrap().len(), 1);
    assert_eq!(reg.len(), 1);
}

/// NET-1・#3412: 全メンバーを片付けた後は `delete_recorded_with` が成功し、`realized` が消える
/// （前の世代の記録が残っていても、同じ名前で作り直せる状態に収束する）。
#[test]
fn net1_3412_after_reboot_then_delete_collapses_realized() {
    let t = Tmp::new("reboot-delete");
    attach_two_in_old_boot(&t);
    let store = NetworkStore::open(&t.0).unwrap();
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    let mut reg = reserved();
    // メンバーが残る間は削除できない（通常の規則）。
    let blocked = delete_recorded_with(&n, |_, _| Ok::<(), ()>(()));
    assert_eq!(
        blocked.unwrap_err().store_code(),
        Some(NetErrorCode::FailedPrecondition)
    );
    for id in ["c1", "c2"] {
        let (r, _) = after_reboot(&n, id, NETNS_DIR, &mut reg, Ok(()));
        assert!(r.is_ok(), "{id}");
    }
    assert!(n.members().unwrap().is_empty());
    assert_eq!(reg.len(), 0);
    delete_recorded_with(&n, |_, _| Ok::<(), ()>(())).unwrap();
    assert!(n.realized().unwrap().is_none());
}

/// SEC-1・#3412: 別ネットワーク（現在の boot）のメンバー記録と予約は、他方の回収で変わらない。
#[test]
fn net1_3412_other_network_untouched() {
    let t = Tmp::new("reboot-other-net");
    attach_two_in_old_boot(&t);
    // 別名のネットワーク（現在の boot）を同じストアに作り、メンバーを 1 件持たせる。
    let store = NetworkStore::open(&t.0).unwrap();
    let other_name = NetworkName::new("db").unwrap();
    store
        .create(&NetworkDefinition::bridge("db", pfx([10, 0, 1, 0], 24)).unwrap())
        .unwrap();
    let g = store.lock_global_exclusive().unwrap();
    {
        let o = g.lock_network(&other_name).unwrap();
        let names = NetworkResourceNames::derive(&other_name).unwrap();
        let token = "fandhe-net:db:1:0:0";
        let created_db = CreatedNetwork {
            bridge: names.bridge().clone(),
            bridge_index: IfIndex::new(8).unwrap(),
            bridge_token: token.to_owned(),
            table: names.table().clone(),
            gateway: pfx([10, 0, 1, 1], 24),
            name_resolution: NameResolution::default(),
            name: other_name.clone(),
        };
        o.commit_realized(
            &RealizedRecord::from_created(
                &created_db,
                pfx([10, 0, 1, 0], 24),
                NftTableHandle::new(43).unwrap(),
                host(),
            )
            .unwrap(),
        )
        .unwrap();
        let s = ContainerAttachSpec::new(
            EndpointId::new("d1").unwrap(),
            &created_db,
            PathBuf::from(NETNS_DIR),
        )
        .unwrap();
        attach_recorded_with(
            &host(),
            &o,
            &mid("d1"),
            &s,
            &[],
            |_| table_info_reply(43, token),
            |ipam, generation| {
                let ep = s.endpoint().clone();
                let address = ipam
                    .allocate_pinned(&ep, NetnsDirRecord::new(PathBuf::from(NETNS_DIR), (8, 9)))
                    .unwrap();
                let v = VethNames::derive(&ep).unwrap();
                Ok(AttachedContainer {
                    host_veth: v.host().clone(),
                    host_index: IfIndex::new(11).unwrap(),
                    host_token: host_owner_token(token, &ep, generation),
                    peer_veth: v.peer().clone(),
                    container_ifname: IfName::new(CONTAINER_IFNAME).unwrap(),
                    netns_path: Path::new(NETNS_DIR).join(ep.as_str()),
                    address,
                    netns: (),
                    published_ports: Vec::new(),
                    pin_identity: None,
                    endpoint: ep,
                })
            },
        )
        .unwrap();
    }
    let mut reg = reserved();
    let d1 = EndpointId::new("d1").unwrap();
    let db_publish =
        PortPublish::new(PortProtocol::Tcp, Ipv4Addr::new(192, 0, 2, 20), 5432, 5432).unwrap();
    reg.reserve(&other_name, &d1, &[db_publish]).unwrap();
    let n = g.lock_network(&name()).unwrap();
    let (r, _) = after_reboot(&n, "c1", NETNS_DIR, &mut reg, Ok(()));
    assert!(r.is_ok());
    assert_eq!(reg.len(), 2, "c2 の 1 件と db の d1 の 1 件が残る");
    drop(n);
    let o = g.lock_network(&other_name).unwrap();
    let ids: Vec<String> = o
        .members()
        .unwrap()
        .iter()
        .map(|m| m.id().as_str().to_owned())
        .collect();
    assert_eq!(ids, vec!["d1".to_owned()]);
    assert_eq!(o.rebuild_ipam().unwrap().allocated_count(), 1);
}

/// REPAIR-4・#3412: 成功・関門の拒否・`run` の失敗のどれでも操作 1 件が `network.member.detach_after_reboot` に記録される。
#[test]
fn repair4_3412_after_reboot_records_every_outcome() {
    let t = Tmp::new("reboot-instr");
    attach_two_in_old_boot(&t);
    let c = std::sync::Arc::new(Collect::default());
    let store = NetworkStore::open_with_recorder(&t.0, c.clone()).unwrap();
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    let mut reg = PortRegistry::new();
    let (r, _) = after_reboot(&n, "nope", NETNS_DIR, &mut reg, Ok(()));
    assert!(r.is_err());
    let (r, _) = after_reboot(&n, "c1", NETNS_DIR, &mut reg, Err(()));
    assert!(r.is_err());
    let (r, _) = after_reboot(&n, "c1", NETNS_DIR, &mut reg, Ok(()));
    assert!(r.is_ok());
    let outcomes: Vec<NetOpOutcome> = c
        .kinds()
        .into_iter()
        .filter(|(k, _)| *k == NetOpKind::MemberDetachAfterReboot)
        .map(|(_, o)| o)
        .collect();
    assert_eq!(
        outcomes,
        vec![
            NetOpOutcome::Failure,
            NetOpOutcome::Failure,
            NetOpOutcome::Success
        ]
    );
}

/// `dir` 配下から名前が `members` のディレクトリを探す。
fn find_members_dir(dir: &Path) -> Option<PathBuf> {
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        if p.is_dir() {
            if e.file_name() == "members" {
                return Some(p);
            }
            if let Some(f) = find_members_dir(&p) {
                return Some(f);
            }
        }
    }
    None
}

/// c1 の publish 行（web が Active・api が墓標の 2 件）のうち、墓標の件数。
fn c1_tombstones(n: &NetworkLockGuard<'_>) -> usize {
    let m = n.members().unwrap();
    let c1 = m.iter().find(|r| r.id() == &mid("c1")).unwrap();
    assert_eq!(c1.publishes().len(), 2);
    c1.publishes().iter().filter(|p| p.unpublished()).count()
}

/// 関門を通った後（`run` の中）で `inject` を実行し、失敗を作る detach を行う。
fn after_reboot_injecting(
    n: &NetworkLockGuard<'_>,
    id: &str,
    reg: &mut PortRegistry,
    inject: impl FnOnce(),
) -> RebootOut {
    detach_member_after_reboot_with(&host(), n, &mid(id), Path::new(NETNS_DIR), reg, |_, _| {
        inject();
        Ok::<_, ()>(NetworkDeleteReport::default())
    })
}

fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// NET-3・REPAIR-4・#3412: 解放中の印を書けなければ、何も解放せず `Uncommitted`。c1 の web は Active のまま、
/// 予約は 3 件のまま。権限を戻した再実行で収束し、c1 の記録が消えて予約は c2 の 1 件になる。
#[test]
fn net3_repair4_3412_after_reboot_mark_write_failure_releases_nothing() {
    let t = Tmp::new("reboot-markfail");
    attach_two_in_old_boot(&t);
    let store = NetworkStore::open(&t.0).unwrap();
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    let mut reg = reserved();
    let members = find_members_dir(&t.0).expect("members dir");
    assert_eq!(c1_tombstones(&n), 1);
    let r = after_reboot_injecting(&n, "c1", &mut reg, || set_mode(&members, 0o500));
    set_mode(&members, 0o700);
    assert!(matches!(r, Err(RecordedError::Uncommitted { .. })));
    assert_eq!(c1_tombstones(&n), 1, "印は書かれていない");
    assert_eq!(reg.len(), 3);
    let r = after_reboot_injecting(&n, "c1", &mut reg, || {});
    assert!(r.is_ok());
    assert_eq!(n.members().unwrap().len(), 1);
    assert_eq!(reg.len(), 1);
}

/// NET-3・REPAIR-4・#3412: 共有ファイルの予約の解放が失敗したら、印（c1 の 2 件とも墓標）つきの記録と予約が残り、
/// ファイルを直した再実行で収束する（c1 の 2 件が解放されて c2 の 1 件が残る）。
#[test]
fn net3_repair4_3412_after_reboot_release_failure_keeps_mark_and_converges() {
    let t = Tmp::new("reboot-relfail");
    attach_two_in_old_boot(&t);
    let store = NetworkStore::open(&t.0).unwrap();
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    let shared = t.0.join("ports.reg");
    let mut reg = PortRegistry::with_shared_file(shared.clone());
    let c1 = EndpointId::new("c1").unwrap();
    reg.reserve(&name(), &c1, &[web_publish(), api_publish()])
        .unwrap();
    let other =
        PortPublish::new(PortProtocol::Tcp, Ipv4Addr::new(192, 0, 2, 10), 9191, 80).unwrap();
    reg.reserve(&name(), &EndpointId::new("c2").unwrap(), &[other])
        .unwrap();
    let good = std::fs::read(&shared).unwrap();
    let r = after_reboot_injecting(&n, "c1", &mut reg, || {
        std::fs::write(&shared, b"junk").unwrap();
        set_mode(&shared, 0o600);
    });
    assert!(matches!(r, Err(RecordedError::Uncommitted { .. })));
    assert_eq!(n.members().unwrap().len(), 2, "記録は残る");
    assert_eq!(c1_tombstones(&n), 2, "解放中の印が残る");
    std::fs::write(&shared, &good).unwrap();
    set_mode(&shared, 0o600);
    let r = after_reboot_injecting(&n, "c1", &mut reg, || {});
    assert!(r.is_ok());
    assert_eq!(n.members().unwrap().len(), 1);
    assert_eq!(reg.len(), 1);
}

/// NET-3・REPAIR-4・#3412: 記録の削除だけが失敗したら（c2 は publish 行が無く印は不要）、予約は解放済みで記録が残り
/// （c2 の予約 1 件が減って 2 件）、再実行で記録が消える。
#[test]
fn net3_repair4_3412_after_reboot_record_removal_failure_converges() {
    let t = Tmp::new("reboot-rmfail");
    attach_two_in_old_boot(&t);
    let store = NetworkStore::open(&t.0).unwrap();
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name()).unwrap();
    let mut reg = reserved();
    let members = find_members_dir(&t.0).expect("members dir");
    let r = after_reboot_injecting(&n, "c2", &mut reg, || set_mode(&members, 0o500));
    set_mode(&members, 0o700);
    assert!(matches!(r, Err(RecordedError::Uncommitted { .. })));
    assert_eq!(n.members().unwrap().len(), 2);
    assert_eq!(reg.len(), 2);
    let r = after_reboot_injecting(&n, "c2", &mut reg, || {});
    assert!(r.is_ok());
    assert_eq!(n.members().unwrap().len(), 1);
    assert_eq!(reg.len(), 2);
}
