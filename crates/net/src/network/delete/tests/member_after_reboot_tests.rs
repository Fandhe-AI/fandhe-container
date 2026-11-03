//! ホストの再起動をまたぐ記録だけの detach の回収本体（`reclaim_member_after_reboot_with`）の単体試験
//! （NET-1・NET-3・SEC-1・REPAIR-5・#3412）。
//!
//! 親の `delete::tests` の fake（`Fake`）と補助を再利用する。カーネル側の呼び出しの並びを完全一致で照合し、
//! 資源が見つかったときは変更（`delete_*`・`unpin_*`）が 0 件であることを確かめる。

use super::*;
use crate::network::attach_claim::TEST_PIN;
use crate::network::delete::member_after_reboot::reclaim_member_after_reboot_with;

fn dir() -> NetnsDirRecord {
    NetnsDirRecord::new(netns_dir(), DIR_ID)
}

/// veth と pin を含み、pin の識別子を控え、quarantine もルールも無い請求書（再起動後の合成）。
fn reboot_claim() -> FailedAttachClaim {
    attach_claim(true, true, false)
}

/// 前の boot の資源がカーネルに無い fake（テーブル・bridge・veth が `NotFound`、pin は残っている）。
fn gone_fake() -> Fake {
    Fake {
        table_absent: true,
        absent_veths: vec![
            created().bridge.as_str().to_owned(),
            host_of("c1").as_str().to_owned(),
        ],
        pins_present: vec![pin("c1")],
        ..Fake::default()
    }
}

fn table_call() -> String {
    format!("table_info {}", created().table.as_str())
}
fn bridge_call() -> String {
    format!("link_attachment {}", created().bridge.as_str())
}
fn veth_call() -> String {
    format!("link_attachment {}", host_of("c1").as_str())
}
fn pin_exists_call() -> String {
    format!("pin_exists {}", pin("c1").display())
}
fn unpin_call() -> String {
    format!("unpin_stale_path {}", pin("c1").display())
}

/// 変更を伴う呼び出しが 1 件も無いこと。
fn assert_no_mutation(fake: &Fake) {
    assert!(
        !fake.calls().iter().any(|c| {
            c.starts_with("delete_") || c.starts_with("unpin_") || c.starts_with("umount")
        }),
        "unexpected mutation: {:?}",
        fake.calls()
    );
}

/// NET-1・NET-3・#3412: 資源が全部無ければ、照会 3 件 → pin の確認 → 残った pin の除去だけを行い、
/// DELRULE・テーブル・link の削除は 1 件も呼ばない。
#[test]
fn net1_3412_reboot_reclaim_queries_then_removes_only_the_pin() {
    let fake = gone_fake();
    let report = reclaim_member_after_reboot_with(&fake, &reboot_claim(), &dir()).unwrap();
    assert_eq!(
        fake.calls(),
        vec![
            table_call(),
            bridge_call(),
            veth_call(),
            pin_exists_call(),
            unpin_call()
        ]
    );
    assert_eq!(report.removed, vec![DeleteResource::Netns(pin("c1"))]);
    assert!(report.leftover.is_empty());
}

/// NET-1・#3412: pin が既に無ければ `unpin_stale_path` は呼ばず、回収済みとして成功する（冪等）。
#[test]
fn net1_3412_reboot_reclaim_without_pin_is_idempotent() {
    let fake = Fake {
        pins_present: Vec::new(),
        ..gone_fake()
    };
    let report = reclaim_member_after_reboot_with(&fake, &reboot_claim(), &dir()).unwrap();
    assert_eq!(
        fake.calls(),
        vec![table_call(), bridge_call(), veth_call(), pin_exists_call()]
    );
    assert_eq!(report.removed, vec![DeleteResource::Netns(pin("c1"))]);
}

/// NET-1・SEC-1・#3412: 専用テーブルがある（所有トークンの一致・不一致のどちらも）なら、以降を照会せず変更 0 件で断る。
#[test]
fn net1_3412_reboot_reclaim_refuses_existing_table() {
    for userdata in [None, Some(b"someone-else".to_vec())] {
        let fake = Fake {
            table_absent: false,
            table_userdata: userdata,
            ..gone_fake()
        };
        let e = reclaim_member_after_reboot_with(&fake, &reboot_claim(), &dir()).unwrap_err();
        assert_eq!(e.step, DeleteStep::Validate);
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "resources of the recorded network exist in this boot"
        );
        assert_eq!(fake.calls(), vec![table_call()]);
        assert_no_mutation(&fake);
    }
}

/// NET-1・SEC-1・#3412: bridge がある場合は veth と pin を見ずに断る。
#[test]
fn net1_3412_reboot_reclaim_refuses_existing_bridge() {
    let fake = Fake {
        absent_veths: vec![host_of("c1").as_str().to_owned()],
        ..gone_fake()
    };
    let e = reclaim_member_after_reboot_with(&fake, &reboot_claim(), &dir()).unwrap_err();
    assert_eq!(e.step, DeleteStep::Validate);
    assert_eq!(
        e.message(),
        "resources of the recorded network exist in this boot"
    );
    assert_eq!(fake.calls(), vec![table_call(), bridge_call()]);
    assert_no_mutation(&fake);
}

/// NET-1・SEC-1・#3412: host veth がある（別名の一致・不一致のどちらも）なら pin に触れず断る。
#[test]
fn net1_3412_reboot_reclaim_refuses_existing_host_veth() {
    for alias in [None, Some(Some("someone-else".to_owned()))] {
        let fake = Fake {
            absent_veths: vec![created().bridge.as_str().to_owned()],
            veth_alias: alias,
            ..gone_fake()
        };
        let e = reclaim_member_after_reboot_with(&fake, &reboot_claim(), &dir()).unwrap_err();
        assert_eq!(e.step, DeleteStep::Validate);
        assert_eq!(e.message(), "host veth of the member exists in this boot");
        assert_eq!(fake.calls(), vec![table_call(), bridge_call(), veth_call()]);
        assert_no_mutation(&fake);
    }
}

/// REPAIR-5・SEC-1・#3412: 照会が `NotFound` 以外で失敗したら「無い」と言えないので、分類を保って断る。
#[test]
fn net1_3412_reboot_reclaim_refuses_when_a_query_fails() {
    let fake = Fake {
        table_query_err: Some(NetErrorCode::Internal),
        ..gone_fake()
    };
    let e = reclaim_member_after_reboot_with(&fake, &reboot_claim(), &dir()).unwrap_err();
    assert_eq!(e.step, DeleteStep::Validate);
    assert_eq!(e.code(), NetErrorCode::Internal);
    assert_eq!(fake.calls(), vec![table_call()]);

    let fake = Fake {
        veth_lookup_err: Some(NetErrorCode::Timeout),
        absent_veths: Vec::new(),
        ..gone_fake()
    };
    let e = reclaim_member_after_reboot_with(&fake, &reboot_claim(), &dir()).unwrap_err();
    assert_eq!(e.step, DeleteStep::Validate);
    assert_eq!(e.code(), NetErrorCode::Timeout);
    assert_eq!(fake.calls(), vec![table_call(), bridge_call()]);
    assert_no_mutation(&fake);
}

/// REPAIR-5・#3412: 全体の期限が切れていれば、要求を 1 件も出さずに `Timeout` で断る。
#[test]
fn net1_3412_reboot_reclaim_expired_deadline_sends_nothing() {
    let fake = Fake {
        expire_after_calls: Some(0),
        ..gone_fake()
    };
    let e = reclaim_member_after_reboot_with(&fake, &reboot_claim(), &dir()).unwrap_err();
    assert_eq!(e.step, DeleteStep::Validate);
    assert_eq!(e.code(), NetErrorCode::Timeout);
    assert!(fake.calls().is_empty());
}

/// NET-1・SEC-1・#3412: pin がマウントされている・識別子が別世代なら、除去は拒否され `Present` の取り残しになる。
#[test]
fn net1_3412_reboot_reclaim_keeps_mounted_or_foreign_pin() {
    let mounted = Fake {
        unpin_path_err: Some(NetErrorCode::FailedPrecondition),
        ..gone_fake()
    };
    let e = reclaim_member_after_reboot_with(&mounted, &reboot_claim(), &dir()).unwrap_err();
    assert_eq!(e.step, DeleteStep::UnpinNetns);
    assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
    assert_eq!(
        e.report.leftover,
        vec![(DeleteResource::Netns(pin("c1")), ResourceState::Present)]
    );
    assert!(e.report.removed.is_empty());

    let foreign = Fake {
        pin_now: Some(crate::network::attach_claim::PinIdentity {
            dev: 1,
            ino: 2,
            serial: 4,
        }),
        ..gone_fake()
    };
    assert_eq!(TEST_PIN.serial, 3);
    let e = reclaim_member_after_reboot_with(&foreign, &reboot_claim(), &dir()).unwrap_err();
    assert_eq!(e.step, DeleteStep::UnpinNetns);
    assert_eq!(
        e.report.leftover,
        vec![(DeleteResource::Netns(pin("c1")), ResourceState::Present)]
    );
}

/// NET-1・SEC-1・#3412: 置き場の実体が記録と違うとき、設定の置き場に同名の pin が無ければ進み、あれば断る。
#[test]
fn net1_3412_reboot_reclaim_with_replaced_dir() {
    let moved = Fake {
        dir_id_now: Some((8, 10)),
        pins_present: Vec::new(),
        ..gone_fake()
    };
    let report = reclaim_member_after_reboot_with(&moved, &reboot_claim(), &dir()).unwrap();
    assert_eq!(
        moved.calls(),
        vec![
            table_call(),
            bridge_call(),
            veth_call(),
            pin_exists_call(),
            format!("pin_absent {}", pin("c1").display()),
        ]
    );
    assert_eq!(report.removed, vec![DeleteResource::Netns(pin("c1"))]);

    let still_there = Fake {
        dir_id_now: Some((8, 10)),
        ..gone_fake()
    };
    let e = reclaim_member_after_reboot_with(&still_there, &reboot_claim(), &dir()).unwrap_err();
    assert_eq!(e.step, DeleteStep::Validate);
    assert_eq!(
        e.message(),
        "netns pin remains in a directory that differs from the record"
    );
    assert_no_mutation(&still_there);
}

/// NET-1・#3412: 識別子の無い旧形式の記録は、pin が無ければ進み、残っていれば触れずに断る。
#[test]
fn net1_3412_reboot_reclaim_legacy_record_without_pin_identity() {
    let legacy = || reboot_claim().with_pin_for_test(None);
    let present = gone_fake();
    let e = reclaim_member_after_reboot_with(&present, &legacy(), &dir()).unwrap_err();
    assert_eq!(e.step, DeleteStep::Validate);
    assert_eq!(
        e.message(),
        "claim has no pin identity; netns pin left in place"
    );
    assert_no_mutation(&present);

    let absent = Fake {
        pins_present: Vec::new(),
        ..gone_fake()
    };
    let report = reclaim_member_after_reboot_with(&absent, &legacy(), &dir()).unwrap();
    assert_eq!(report.removed, vec![DeleteResource::Netns(pin("c1"))]);
    assert_no_mutation(&absent);
}
