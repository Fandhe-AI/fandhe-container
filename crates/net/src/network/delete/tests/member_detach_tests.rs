//! 記録だけから行う detach の回収本体（`reclaim_member_with`）の単体試験（NET-1・NET-6・SEC-1・#3347）。
//!
//! 親の `delete::tests` の fake（`Fake`）と補助を再利用する。呼び出し列と取り残しは具体値で照合する。

use super::*;
use crate::network::attach_claim::TEST_PIN;
use crate::network::delete::member_detach::reclaim_member_with;

fn dir() -> NetnsDirRecord {
    NetnsDirRecord::new(netns_dir(), DIR_ID)
}

/// veth と pin を含み、pin の識別子を控えた請求書（記録から合成したもの）。
fn member_claim() -> FailedAttachClaim {
    attach_claim(true, true, false)
}

/// NET-1・NET-6・#3347: 置き場が記録と同じ実体なら、veth → pin の順に外し、期待した識別子で pin を解除する。
#[test]
fn net1_3347_member_reclaim_removes_veth_then_pin() {
    let fake = Fake {
        pins_present: vec![pin("c1")],
        ..Fake::default()
    };
    let report = reclaim_member_with(&fake, &member_claim(), &dir()).unwrap();
    let pin_path = pin("c1");
    assert_eq!(
        fake.calls(),
        vec![
            format!("pin_exists {}", pin_path.display()),
            format!("link_attachment {}", host_of("c1").as_str()),
            format!("owned_bridge_index {}", created().bridge.as_str()),
            "delete_link 21".to_owned(),
            format!("unpin_path {}", pin_path.display()),
        ]
    );
    assert_eq!(
        report.removed,
        vec![
            DeleteResource::Veth(host_of("c1")),
            DeleteResource::Netns(pin("c1"))
        ]
    );
    assert!(report.leftover.is_empty());
}

/// NET-1・SEC-1・#3347: 置き場が記録と違う実体なら `pin_exists` 以外の呼び出しを 0 件にして断る。
#[test]
fn net1_3347_member_reclaim_rejects_other_netns_dir_without_changes() {
    let fake = Fake {
        dir_id_now: Some((8, 10)),
        pins_present: vec![pin("c1")],
        ..Fake::default()
    };
    let e = reclaim_member_with(&fake, &member_claim(), &dir()).unwrap_err();
    assert_eq!(e.step, DeleteStep::Validate);
    assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
    assert_eq!(
        fake.calls(),
        vec![format!("pin_exists {}", pin("c1").display())]
    );
}

/// NET-1・SEC-1・#3347: veth の別名が請求書の世代のものでなければ veth にも pin にも触れず、`Unknown` の取り残しになる。
#[test]
fn net1_3347_member_reclaim_unproven_veth_keeps_pin() {
    let fake = Fake {
        pins_present: vec![pin("c1")],
        veth_alias: Some(Some("someone-else".to_owned())),
        ..Fake::default()
    };
    let e = reclaim_member_with(&fake, &member_claim(), &dir()).unwrap_err();
    assert_eq!(e.step, DeleteStep::DeleteVeth);
    assert!(
        e.report
            .leftover
            .contains(&(DeleteResource::Veth(host_of("c1")), ResourceState::Unknown))
    );
    assert!(
        e.report
            .leftover
            .contains(&(DeleteResource::Netns(pin("c1")), ResourceState::Unknown))
    );
    assert!(
        !fake
            .calls()
            .iter()
            .any(|c| c.starts_with("delete_link") || c.starts_with("unpin_path"))
    );
}

/// NET-1・SEC-1・#3347: 現在の pin が記録の識別子と別の世代なら解除は拒否され、pin は `Unknown` の取り残しで残る。
#[test]
fn net1_3347_member_reclaim_refuses_pin_of_other_generation() {
    let fake = Fake {
        pins_present: vec![pin("c1")],
        pin_now: Some(crate::network::attach_claim::PinIdentity {
            dev: 1,
            ino: 2,
            serial: 4,
        }),
        ..Fake::default()
    };
    let e = reclaim_member_with(&fake, &member_claim(), &dir()).unwrap_err();
    assert_eq!(e.step, DeleteStep::UnpinNetns);
    assert_eq!(TEST_PIN.serial, 3);
    assert_eq!(
        e.report.leftover,
        vec![(DeleteResource::Netns(pin("c1")), ResourceState::Present)]
    );
    assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
}

/// NET-1・REPAIR-4・#3347: 2 回目の実行（veth が無く pin も無い）は `Ok` に収束する（冪等）。
#[test]
fn net1_3347_member_reclaim_rerun_converges() {
    let fake = Fake {
        absent_veths: vec![host_of("c1").as_str().to_owned()],
        ..Fake::default()
    };
    let report = reclaim_member_with(&fake, &member_claim(), &dir()).unwrap();
    assert_eq!(
        report.removed,
        vec![
            DeleteResource::Veth(host_of("c1")),
            DeleteResource::Netns(pin("c1"))
        ]
    );
    // veth には触れない。pin の解除は「既に無ければ成功」の冪等な呼び出しで収束する。
    assert!(!fake.calls().iter().any(|c| c.starts_with("delete_link")));
}

/// NET-1・#3347: 識別子を控えていない旧形式の記録（pin なし）は、pin が残っていれば `Unknown` で触れない。
#[test]
fn net1_3347_member_reclaim_without_pin_identity_leaves_pin() {
    let fake = Fake {
        pins_present: vec![pin("c1")],
        ..Fake::default()
    };
    let claim = member_claim().with_pin_for_test(None);
    let e = reclaim_member_with(&fake, &claim, &dir()).unwrap_err();
    assert_eq!(e.step, DeleteStep::UnpinNetns);
    assert!(
        e.report
            .leftover
            .contains(&(DeleteResource::Netns(pin("c1")), ResourceState::Unknown))
    );
    assert!(!fake.calls().iter().any(|c| c.starts_with("unpin_path")));
}
