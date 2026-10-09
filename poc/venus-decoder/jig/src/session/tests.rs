//! セッション層の単体テスト（GPU-6・REPAIR-5・TASK-172 F1.4・#1519）。
//!
//! I/O を伴わない状態機械（ゲート表・feature 照合・`GET_CONFIG` のスライス）と時間制限の境界を具体値で照合する。
//! socket を使う一連の流れは `tests/vhost_user_session.rs` が担当する。

use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

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
/// 試験用の memfd（1 領域のメモリ表）で、メモリ表の設定まで済ませた状態を作る。
fn state_with_mem() -> State {
    use crate::vhost_user::fd_passing::create_memfd;
    use std::ffi::CString;

    const UVA: u64 = 0x7f00_0000_0000;
    const LEN: u64 = 0x1_0000;
    let mut s = State::new();
    s.handle(Request::SetOwner, Vec::new()).expect("owner");
    s.handle(Request::GetProtocolFeatures, Vec::new())
        .expect("q");
    s.handle(Request::SetProtocolFeatures(0x201), Vec::new())
        .expect("proto");
    s.handle(Request::SetFeatures(OFFERED_FEATURES), Vec::new())
        .expect("features");
    let table = MemTable::new(&[MemRegion {
        guest_phys_addr: 0,
        memory_size: LEN,
        userspace_addr: UVA,
        mmap_offset: 0,
    }])
    .expect("table");
    let file = create_memfd(&CString::new("jig-sess-unit").expect("name"), LEN).expect("memfd");
    s.handle(Request::SetMemTable(table), vec![OwnedFd::from(file)])
        .expect("mem table");
    s
}

fn vring_addr() -> crate::vhost_user::VringAddr {
    const UVA: u64 = 0x7f00_0000_0000;
    crate::vhost_user::VringAddr {
        index: 0,
        flags: 0,
        descriptor: UVA,
        used: UVA + 0x2000,
        available: UVA + 0x1000,
        log: 0,
    }
}

/// GPU-6・REPAIR-5: キューサイズは 0・2 の冪でない値・上限超を `INVALID_VALUE`（要求 ID 8）で拒否する。
#[test]
fn gpu6_set_vring_num_rejects_invalid_sizes() {
    let mut s = state_with_mem();
    let num = |n| Request::SetVringNum(VringState { index: 0, num: n });
    for bad in [0u32, 3, 12, 32769, 65536] {
        assert_eq!(
            code_of(s.handle(num(bad), Vec::new())),
            (SessionErrorCode::InvalidValue, Some(8)),
            "num={bad}"
        );
    }
    for good in [1u32, 8, 32768] {
        assert!(s.handle(num(good), Vec::new()).is_ok(), "num={good}");
    }
}

/// GPU-6: `SET_VRING_NUM` は旧 ring アドレスの検証結果を捨てる。ENABLE(0) → NUM → ENABLE(1) では
/// ADDR を送り直すまで有効化できない（旧 cfg のまま別サイズで起動しない）。
#[test]
fn gpu6_set_vring_num_invalidates_ring_address() {
    let mut s = state_with_mem();
    let st = |num| VringState { index: 0, num };
    s.handle(Request::SetVringNum(st(8)), Vec::new())
        .expect("num");
    s.handle(Request::SetVringAddr(vring_addr()), Vec::new())
        .expect("addr");
    s.handle(Request::SetVringEnable(st(0)), Vec::new())
        .expect("disable");
    s.handle(Request::SetVringNum(st(16)), Vec::new())
        .expect("renum");
    assert_eq!(
        code_of(s.handle(Request::SetVringEnable(st(1)), Vec::new())),
        (SessionErrorCode::OutOfOrder, Some(18))
    );
    // ADDR の再送で検証し直せば有効化できる。
    s.handle(Request::SetVringAddr(vring_addr()), Vec::new())
        .expect("addr again");
    assert!(s.handle(Request::SetVringEnable(st(1)), Vec::new()).is_ok());
}

fn file_pair() -> (File, UnixStream) {
    let (a, b) = UnixStream::pair().expect("pair");
    (File::from(OwnedFd::from(a)), b)
}

/// REPAIR-5: poll の後に相手が読み切っていても kick の読み取りは `wait_for` で打ち切る
/// （`O_NONBLOCK` に依存しない。blocking のままの空の fd でも期限で `Lost` になり、呼び出し元は止まらない）。
#[test]
fn repair5_read_kick_does_not_block_on_drained_counter() {
    let (kick, _peer) = file_pair();
    let started = Instant::now();
    assert_eq!(
        read_kick(&kick, Duration::from_millis(50)).expect("empty"),
        KickRead::Lost
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// REPAIR-5: kick の読み取りの具体値（読めた・切断）。
#[test]
fn repair5_read_kick_reads_counter_and_detects_close() {
    let slice = Duration::from_secs(5);
    let (kick, mut peer) = file_pair();
    peer.write_all(&1u64.to_le_bytes()).expect("kick");
    assert_eq!(read_kick(&kick, slice).expect("one"), KickRead::Read);
    drop(peer);
    assert_eq!(
        read_kick(&kick, slice).expect_err("closed").code,
        SessionErrorCode::KickClosed
    );
}

/// REPAIR-5: `O_NONBLOCK` が立っていて空なら `Drained`（相手が先に読み切った場合）。
#[test]
fn repair5_read_kick_drained_when_nonblocking() {
    let (kick, _peer) = file_pair();
    let sock = UnixStream::from(OwnedFd::from(kick.try_clone().expect("dup")));
    sock.set_nonblocking(true).expect("nb");
    assert_eq!(
        read_kick(&kick, Duration::from_secs(5)).expect("drained"),
        KickRead::Drained
    );
}

/// REPAIR-5: 相手が `O_NONBLOCK` を落としていても（blocking の fd でも）call の書き込み先が埋まっていれば
/// 期限で `TIMEOUT` になり、無期限に止まらない。
#[test]
fn repair5_notify_times_out_when_call_is_full() {
    let (call, _peer) = file_pair();
    // call 側の送信バッファを満杯にする（peer は読まないので埋まったままになる）。
    let sock = UnixStream::from(OwnedFd::from(call.try_clone().expect("dup")));
    sock.set_nonblocking(true).expect("nb");
    let mut writer = &call;
    while writer.write(&[0u8; 4096]).is_ok() {}
    sock.set_nonblocking(false).expect("blocking");
    let started = Instant::now();
    let e = notify(&call, Duration::from_millis(100)).expect_err("full");
    assert_eq!(e.code, SessionErrorCode::Timeout);
    assert!(started.elapsed() < Duration::from_secs(5));
}
