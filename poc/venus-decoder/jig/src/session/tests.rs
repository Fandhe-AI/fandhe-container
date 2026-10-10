//! セッション層の単体テスト（GPU-6・REPAIR-5・TASK-172 F1.4・#1519）。
//!
//! I/O を伴わない状態機械（ゲート表・feature 照合・`GET_CONFIG` のスライス）と時間制限の境界を具体値で照合する。
//! socket を使う一連の流れは `tests/vhost_user_session.rs` が担当する。

use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::negotiation::{
    HostVisible, HostVisibleUnavailable, OFFERED_FEATURES, OFFERED_PROTOCOL, State, check_features,
    expected_fds,
};
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
        Some(Reply::ProtocolFeatures(0x0040_0229))
    );
    // 広告外のビット（bit 1）を含む確定は拒否する。
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

/// REPAIR-5: `O_NONBLOCK` が立っていて空なら、補助スレッドは readiness を待ち切れず期限で終わり `Lost`
/// （`Drained` は poll の後に相手が読み切った競合でだけ返る）。
#[test]
fn repair5_read_kick_drained_when_nonblocking() {
    let (kick, _peer) = file_pair();
    let sock = UnixStream::from(OwnedFd::from(kick.try_clone().expect("dup")));
    sock.set_nonblocking(true).expect("nb");
    assert_eq!(
        read_kick(&kick, Duration::from_millis(50)).expect("empty"),
        KickRead::Lost
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

/// REPAIR-5: 補助スレッドの枠は上限で拒否され、解放すれば再び取れる（接続の繰り返しで残存スレッドが蓄積しない）。
#[test]
fn repair5_worker_slots_are_capped_and_released() {
    let live = AtomicUsize::new(0);
    let a = WorkerSlot::acquire(&live, 2).expect("first");
    let b = WorkerSlot::acquire(&live, 2).expect("second");
    assert!(WorkerSlot::acquire(&live, 2).is_none());
    assert_eq!(live.load(Ordering::Acquire), 2);
    drop(a);
    assert_eq!(live.load(Ordering::Acquire), 1);
    let c = WorkerSlot::acquire(&live, 2).expect("after release");
    drop((b, c));
    assert_eq!(live.load(Ordering::Acquire), 0);
}

/// REPAIR-5: 書き込めない（満杯の）fd でも補助スレッド自身が期限で終了し、結果が `TimedOut` として返る
/// （期限切れの I/O が回収されずに残らない）。繰り返しても毎回同じ。
#[test]
fn repair5_full_call_worker_ends_by_itself_on_deadline() {
    let (call, _peer) = file_pair();
    let sock = UnixStream::from(OwnedFd::from(call.try_clone().expect("dup")));
    sock.set_nonblocking(true).expect("nb");
    let mut writer = &call;
    while writer.write(&[0u8; 4096]).is_ok() {}
    sock.set_nonblocking(false).expect("blocking");
    for _ in 0..3 {
        let r = run_bounded(
            &call,
            sys::Interest::Writable,
            Duration::from_millis(50),
            |f| {
                let mut w = f;
                w.write(&1u64.to_le_bytes())
            },
        )
        .expect("spawned")
        .expect("worker reports before the grace period");
        assert_eq!(r.expect_err("not writable").kind(), ErrorKind::TimedOut);
    }
}

/// REPAIR-5: poll が成立しても `op` が `WouldBlock` を返し続ける競合（相手が counter を読み切る・満たす）では、
/// 補助スレッドは blocking I/O に入らず期限で `TimedOut` を返して自力終了する。
#[test]
fn repair5_worker_ends_on_deadline_when_op_keeps_would_block() {
    let (kick, mut peer) = file_pair();
    peer.write_all(&[1u8]).expect("readable");
    let started = Instant::now();
    let r = run_bounded(
        &kick,
        sys::Interest::Readable,
        Duration::from_millis(80),
        |_| Err::<usize, _>(io::Error::from(ErrorKind::WouldBlock)),
    )
    .expect("spawned")
    .expect("worker reports before the grace period");
    assert_eq!(r.expect_err("never completes").kind(), ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// GPU-6・TASK-172 F5.2b.1（#1639）: `reply_ack()` は REPLY_ACK を含む確定の後だけ真になり、広告外の確定失敗では変わらない。
#[test]
fn f5_2b_1_gpu6_reply_ack_follows_confirmed_protocol_features() {
    let mut s = State::new();
    assert!(!s.reply_ack());
    s.handle(Request::GetProtocolFeatures, Vec::new())
        .expect("ok");
    s.handle(Request::SetProtocolFeatures(0x201), Vec::new())
        .expect("ok");
    assert!(!s.reply_ack());
    s.handle(Request::SetProtocolFeatures(0x209), Vec::new())
        .expect("ok");
    assert!(s.reply_ack());
    assert_eq!(
        code_of(s.handle(Request::SetProtocolFeatures(0x20b), Vec::new())),
        (SessionErrorCode::FeatureNotOffered, Some(16))
    );
    assert!(s.reply_ack());
}

// ---- GPU-6・TASK-172 F5.2b.2（#1641） ----

fn uds() -> OwnedFd {
    let (a, _b) = UnixStream::pair().expect("pair");
    OwnedFd::from(a)
}

fn proto(s: &mut State, v: u64) {
    s.handle(Request::GetProtocolFeatures, Vec::new())
        .expect("query");
    s.handle(Request::SetProtocolFeatures(v), Vec::new())
        .expect("set");
}

#[test]
fn f5_2b_2_gpu6_offered_protocol_and_fd_counts() {
    assert_eq!(OFFERED_PROTOCOL, 0x0040_0229);
    assert_eq!(expected_fds(&Request::SetBackendReqFd), 1);
    assert_eq!(expected_fds(&Request::GetShmemConfig), 0);
    assert_eq!(
        SessionErrorCode::InvalidBackendReqFd.as_str(),
        "INVALID_BACKEND_REQ_FD"
    );
}

#[test]
fn f5_2b_2_gpu6_gates_reject_without_negotiation() {
    let mut s = State::new();
    // 確定前はどちらも OUT_OF_ORDER。
    assert_eq!(
        code_of(s.handle(Request::GetShmemConfig, Vec::new())),
        (SessionErrorCode::OutOfOrder, Some(44))
    );
    assert_eq!(
        code_of(s.handle(Request::SetBackendReqFd, vec![uds()])),
        (SessionErrorCode::OutOfOrder, Some(21))
    );
    // MQ・REPLY_ACK・CONFIG だけを確定した場合も同じ。
    proto(&mut s, 0x209);
    assert_eq!(
        code_of(s.handle(Request::GetShmemConfig, Vec::new())),
        (SessionErrorCode::OutOfOrder, Some(44))
    );
    assert_eq!(
        code_of(s.handle(Request::SetBackendReqFd, vec![uds()])),
        (SessionErrorCode::OutOfOrder, Some(21))
    );
}

#[test]
fn f5_2b_2_gpu6_backend_req_fd_must_be_unix_socket_and_only_once() {
    let mut s = State::new();
    proto(&mut s, 0x0040_0229);
    // memfd（socket でない）。
    let mem = crate::vhost_user::fd_passing::create_memfd(c"f5-2b-2", 4096).expect("memfd");
    assert_eq!(
        code_of(s.handle(Request::SetBackendReqFd, vec![OwnedFd::from(mem)])),
        (SessionErrorCode::InvalidBackendReqFd, Some(21))
    );
    // UDP socket（socket だが AF_UNIX でない）。
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp");
    assert_eq!(
        code_of(s.handle(Request::SetBackendReqFd, vec![OwnedFd::from(udp)])),
        (SessionErrorCode::InvalidBackendReqFd, Some(21))
    );
    // 個数違いは FD_COUNT_MISMATCH。
    assert_eq!(
        code_of(s.handle(Request::SetBackendReqFd, Vec::new())),
        (SessionErrorCode::FdCountMismatch, Some(21))
    );
    assert_eq!(
        s.handle(Request::SetBackendReqFd, vec![uds()]).expect("ok"),
        None
    );
    // 2 回目は拒否。
    assert_eq!(
        code_of(s.handle(Request::SetBackendReqFd, vec![uds()])),
        (SessionErrorCode::OutOfOrder, Some(21))
    );
}

#[test]
fn f5_2b_2_gpu6_host_visible_states() {
    use HostVisibleUnavailable::*;
    let un = HostVisible::Unavailable;
    let mut s = State::new();
    assert_eq!(s.host_visible(), un(ShmemNotNegotiated));
    proto(&mut s, 0x0040_0221);
    assert_eq!(s.host_visible(), un(ConfigNotQueried));
    s.handle(Request::GetShmemConfig, Vec::new()).expect("44");
    assert_eq!(s.host_visible(), un(BackendChannelMissing));
    s.handle(Request::SetBackendReqFd, vec![uds()]).expect("21");
    assert_eq!(s.host_visible(), HostVisible::Ready);
    assert_eq!(HostVisible::Ready.as_str(), "ready");
    // BACKEND_REQ を外して再確定すると使えない（保持した fd は閉じない）。
    proto(&mut s, 0x0040_0201);
    assert_eq!(s.host_visible(), un(BackendReqNotNegotiated));
    assert_eq!(
        un(BackendReqNotNegotiated).as_str(),
        "backend_req_not_negotiated"
    );
    // SHMEM を外した再確定。
    proto(&mut s, 0x201);
    assert_eq!(s.host_visible(), un(ShmemNotNegotiated));
    assert_eq!(un(ConfigNotQueried).as_str(), "config_not_queried");
    assert_eq!(
        un(BackendChannelMissing).as_str(),
        "backend_channel_missing"
    );
}

#[test]
fn f5_2b_2_gpu6_shmem_config_reply_is_stable() {
    let mut s = State::new();
    proto(&mut s, 0x0040_0201);
    let a = s.handle(Request::GetShmemConfig, Vec::new()).expect("a");
    let b = s.handle(Request::GetShmemConfig, Vec::new()).expect("b");
    assert_eq!(a, b);
    let Some(Reply::ShmemConfig(cfg)) = a else {
        panic!("shmem config expected");
    };
    assert_eq!((cfg.nregions(), cfg.size(1)), (1, 134_217_728));
    assert_eq!(crate::device::HOST_VISIBLE_SHM_SIZE, 134_217_728);
    assert_eq!(crate::device::SHM_ID_HOST_VISIBLE, 1);
}
