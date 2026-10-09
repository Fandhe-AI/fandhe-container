//! セッション層の単体テスト（GPU-6・REPAIR-5・TASK-172 F1.4・#1519）。
//!
//! I/O を伴わない状態機械（ゲート表・feature 照合・`GET_CONFIG` のスライス）と時間制限の境界を具体値で照合する。
//! socket を使う一連の流れは `tests/vhost_user_session.rs` が担当する。

use std::time::Duration;

use super::negotiation::{OFFERED_FEATURES, State, check_features};
use super::*;
use crate::vhost_user::{
    ConfigPayload, MemRegion, MemTable, Reply, Request, RequestCode, VringFd, VringState,
};

fn code_of(r: Result<Option<Reply>, SessionError>) -> (SessionErrorCode, Option<u32>) {
    let e = r.expect_err("must be rejected");
    (e.code, e.request)
}

#[test]
fn gpu6_offered_features_value() {
    assert_eq!(OFFERED_FEATURES, 0x0000_0001_4000_0019);
}

#[test]
fn gpu6_feature_check_distinguishes_unoffered_and_missing() {
    assert_eq!(check_features(OFFERED_FEATURES), Ok(()));
    assert_eq!(
        check_features(OFFERED_FEATURES | (1 << 5)),
        Err(SessionErrorCode::FeatureNotOffered)
    );
    assert_eq!(
        check_features(OFFERED_FEATURES & !(1 << 4)),
        Err(SessionErrorCode::RequiredFeatureMissing)
    );
    assert_eq!(
        check_features(OFFERED_FEATURES & !(1 << 30)),
        Err(SessionErrorCode::RequiredFeatureMissing)
    );
}

#[test]
fn gpu6_gate_rejects_out_of_order_requests_with_request_id() {
    let mut s = State::new();
    let table = MemTable::new(&[MemRegion {
        guest_phys_addr: 0,
        memory_size: 0x1000,
        userspace_addr: 0x1000,
        mmap_offset: 0,
    }])
    .expect("table");
    let kick = Request::SetVringKick(VringFd {
        index: 0,
        no_fd: false,
    });
    let st = |n| VringState { index: 0, num: n };
    let cases: Vec<(Request, u32)> = vec![
        (Request::SetProtocolFeatures(0x201), 16),
        (Request::GetQueueNum, 17),
        (Request::SetFeatures(OFFERED_FEATURES), 2),
        (Request::SetMemTable(table), 5),
        (Request::SetVringNum(st(8)), 8),
        (Request::SetVringBase(st(0)), 10),
        (kick, 12),
        (Request::SetVringEnable(st(1)), 18),
    ];
    for (req, id) in cases {
        assert_eq!(
            code_of(s.handle(req, Vec::new())),
            (SessionErrorCode::OutOfOrder, Some(id))
        );
    }
}

#[test]
fn gpu6_second_set_owner_is_rejected() {
    let mut s = State::new();
    assert!(s.handle(Request::SetOwner, Vec::new()).is_ok());
    assert_eq!(
        code_of(s.handle(Request::SetOwner, Vec::new())),
        (SessionErrorCode::OutOfOrder, Some(3))
    );
}

#[test]
fn gpu6_protocol_negotiation_values() {
    let mut s = State::new();
    assert_eq!(
        s.handle(Request::GetProtocolFeatures, Vec::new())
            .expect("ok"),
        Some(Reply::ProtocolFeatures(0x201))
    );
    assert_eq!(
        code_of(s.handle(Request::SetProtocolFeatures(0x203), Vec::new())),
        (SessionErrorCode::FeatureNotOffered, Some(16))
    );
    s.handle(Request::SetProtocolFeatures(0x201), Vec::new())
        .expect("set");
    assert_eq!(
        s.handle(Request::GetQueueNum, Vec::new()).expect("ok"),
        Some(Reply::QueueNum(2))
    );
}

#[test]
fn gpu6_get_config_slices_and_rejects_out_of_range() {
    let mut s = State::new();
    s.handle(Request::GetProtocolFeatures, Vec::new())
        .expect("q");
    s.handle(Request::SetProtocolFeatures(0x201), Vec::new())
        .expect("set");
    let req = |off, size| {
        Request::GetConfig(
            ConfigPayload::new(RequestCode::GetConfig, off, 0, &vec![0u8; size]).expect("cfg"),
        )
    };
    let Some(Reply::Config(c)) = s.handle(req(0, 16), Vec::new()).expect("full") else {
        panic!("config reply expected");
    };
    let mut want = [0u8; 16];
    want[12] = 1;
    assert_eq!(c.data(), &want);
    let Some(Reply::Config(c)) = s.handle(req(12, 4), Vec::new()).expect("tail") else {
        panic!("config reply expected");
    };
    assert_eq!(c.data(), &[1, 0, 0, 0]);
    assert_eq!(
        s.handle(req(12, 8), Vec::new()).expect("range"),
        Some(Reply::ConfigError)
    );
}

#[test]
fn repair5_limits_bounds() {
    let ok = Duration::from_secs(1);
    assert!(SessionLimits::new(ok, ok).is_ok());
    assert!(SessionLimits::new(Duration::from_secs(3600), Duration::from_secs(3600)).is_ok());
    for bad in [Duration::ZERO, Duration::from_secs(3601)] {
        assert_eq!(
            SessionLimits::new(bad, ok).expect_err("bad").code,
            SessionErrorCode::InvalidArgument
        );
        assert_eq!(
            SessionLimits::new(ok, bad).expect_err("bad").code,
            SessionErrorCode::InvalidArgument
        );
    }
}

#[test]
fn gpu6_error_display_is_fixed_vocabulary() {
    let e = SessionError::new(SessionErrorCode::OutOfOrder, Some(12));
    assert_eq!(
        e.to_string(),
        "OUT_OF_ORDER (request=12): request is not allowed in the current session state"
    );
}
