//! shim v2 の ttrpc サーバーの UDS 結合試験（CRI-5・TASK-62.1・MS-7）。
#![cfg(unix)]

#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;

use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::shim_v2::{
    EmptyTaskService, FrameHeader, HEADER_LEN, MAX_PAYLOAD_LEN, MessageType, RpcStatus,
    ServerConfig, ServerHandle, ServiceRegistry, TaskApiVersion, TtrpcRequest, TtrpcResponse,
    TtrpcServer, TtrpcService,
};
use prost::Message;

const UNIMPL: i32 = 12;
const INVALID: i32 = 3;
const EXHAUSTED: i32 = 8;

/// 設定を 1 項目だけ壊す関数（範囲外設定の試験用）。
type Mutate = fn(&mut ServerConfig);

fn start(
    tag: &str,
    version: TaskApiVersion,
    cfg: ServerConfig,
) -> (test_root::TestRoot, std::path::PathBuf, ServerHandle) {
    let root = test_root::test_root("ttrpc", tag);
    let path = root.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mut reg = ServiceRegistry::new();
    reg.register(Arc::new(EmptyTaskService::new(version)))
        .unwrap();
    let h = TtrpcServer::new(reg, cfg).serve(listener).unwrap();
    (root, path, h)
}

fn connect(path: &std::path::Path) -> UnixStream {
    let s = UnixStream::connect(path).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

fn send_req(s: &mut UnixStream, sid: u32, service: &str, method: &str) {
    let body = TtrpcRequest {
        service: service.into(),
        method: method.into(),
        ..Default::default()
    }
    .encode_to_vec();
    let h = FrameHeader::new(body.len() as u32, sid, MessageType::Request, 0).unwrap();
    s.write_all(&h.to_bytes()).unwrap();
    s.write_all(&body).unwrap();
}

/// 応答を読む。接続が閉じていれば None。
fn read_resp(s: &mut UnixStream) -> Option<(u32, TtrpcResponse)> {
    let mut hb = [0u8; HEADER_LEN];
    s.read_exact(&mut hb).ok()?;
    let h = FrameHeader::from_bytes(&hb).unwrap();
    assert_eq!(h.message_type(), MessageType::Response);
    assert_eq!(h.flags(), 0);
    let mut body = vec![0u8; h.length() as usize];
    s.read_exact(&mut body).unwrap();
    Some((h.stream_id(), TtrpcResponse::decode(&body[..]).unwrap()))
}

fn code(r: &TtrpcResponse) -> i32 {
    r.status.as_ref().unwrap().code
}

fn assert_closed(s: &mut UnixStream) {
    let mut b = [0u8; 1];
    match s.read(&mut b) {
        Ok(0) => {}
        // 相手側の close が RST として届く場合のみ切断として受理する。タイムアウトは失敗。
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ) => {}
        other => panic!("expected disconnect, got {other:?}"),
    }
}

/// CRI-5: v2 / v3 の空の Task サービスは Create に Unimplemented を返す。
#[test]
fn cri5_empty_task_service_unimplemented_v2_v3() {
    assert_eq!(CriErrorCode::Unimplemented.grpc_code() as i32, UNIMPL);
    for (tag, ver, name) in [
        ("v2", TaskApiVersion::V2, "containerd.task.v2.Task"),
        ("v3", TaskApiVersion::V3, "containerd.task.v3.Task"),
    ] {
        let (_r, path, h) = start(tag, ver, ServerConfig::default());
        let mut s = connect(&path);
        send_req(&mut s, 1, name, "Create");
        let (sid, r) = read_resp(&mut s).unwrap();
        assert_eq!(sid, 1);
        assert_eq!(code(&r), UNIMPL);
        assert_eq!(r.status.unwrap().message, "method Create");
        h.shutdown().unwrap();
    }
}

/// CRI-5: 未登録のサービスは Unimplemented。
#[test]
fn cri5_unknown_service() {
    let (_r, path, h) = start("unk", TaskApiVersion::V2, ServerConfig::default());
    let mut s = connect(&path);
    send_req(&mut s, 1, "other.Svc", "M");
    let (_, r) = read_resp(&mut s).unwrap();
    assert_eq!(code(&r), UNIMPL);
    assert_eq!(r.status.unwrap().message, "service other.Svc");
    h.shutdown().unwrap();
}

/// CRI-5: stream id の検証（奇数・増加）。
#[test]
fn cri5_stream_id_rules() {
    let (_r, path, h) = start("sid", TaskApiVersion::V2, ServerConfig::default());
    let mut s = connect(&path);
    let svc = "containerd.task.v2.Task";
    for sid in [1u32, 3] {
        send_req(&mut s, sid, svc, "State");
        let (got, r) = read_resp(&mut s).unwrap();
        assert_eq!((got, code(&r)), (sid, UNIMPL));
    }
    for sid in [4u32, 3, 1] {
        send_req(&mut s, sid, svc, "State");
        let (got, r) = read_resp(&mut s).unwrap();
        assert_eq!((got, code(&r)), (sid, INVALID));
    }
    h.shutdown().unwrap();
}

/// CRI-5: 上限超過の長さは ResourceExhausted を返して閉じる。
#[test]
fn cri5_oversize_length_closes() {
    let (_r, path, h) = start("big", TaskApiVersion::V2, ServerConfig::default());
    let mut s = connect(&path);
    let mut hb = [0u8; HEADER_LEN];
    hb[..4].copy_from_slice(&((4u32 << 20) + 1).to_be_bytes());
    hb[7] = 1;
    hb[8] = 0x01;
    s.write_all(&hb).unwrap();
    let (sid, r) = read_resp(&mut s).unwrap();
    assert_eq!((sid, code(&r)), (1, EXHAUSTED));
    assert_closed(&mut s);
    h.shutdown().unwrap();
}

/// CRI-5: Data フレームは InvalidArgument。
#[test]
fn cri5_data_frame_rejected() {
    let (_r, path, h) = start("data", TaskApiVersion::V2, ServerConfig::default());
    let mut s = connect(&path);
    let hdr = FrameHeader::new(0, 1, MessageType::Data, 0).unwrap();
    s.write_all(&hdr.to_bytes()).unwrap();
    let (sid, r) = read_resp(&mut s).unwrap();
    assert_eq!((sid, code(&r)), (1, INVALID));
    h.shutdown().unwrap();
}

/// CRI-5: ヘッダを途中で止めると frame_read_timeout 後に閉じる。
#[test]
fn cri5_partial_header_times_out() {
    let cfg = ServerConfig {
        frame_read_timeout: Duration::from_millis(200),
        ..ServerConfig::default()
    };
    let (_r, path, h) = start("slow", TaskApiVersion::V2, cfg);
    let mut s = connect(&path);
    s.write_all(&[0, 0, 0]).unwrap();
    assert_closed(&mut s);
    h.shutdown().unwrap();
}

/// CRI-5: 同時接続の上限を超えた接続は閉じる。
#[test]
fn cri5_connection_limit() {
    let cfg = ServerConfig {
        max_connections: 1,
        ..ServerConfig::default()
    };
    let (_r, path, h) = start("lim", TaskApiVersion::V2, cfg);
    let mut a = connect(&path);
    send_req(&mut a, 1, "containerd.task.v2.Task", "State");
    assert!(read_resp(&mut a).is_some());
    let mut b = connect(&path);
    assert_closed(&mut b);
    // 先の接続は生きている。
    send_req(&mut a, 3, "containerd.task.v2.Task", "State");
    assert!(read_resp(&mut a).is_some());
    h.shutdown().unwrap();
}

/// CRI-5: shutdown は期限内に戻り、アイドル接続も閉じる。
#[test]
fn cri5_shutdown_closes_idle_connections() {
    let (_r, path, h) = start("down", TaskApiVersion::V2, ServerConfig::default());
    let mut s = connect(&path);
    h.shutdown().unwrap();
    assert_closed(&mut s);
}

/// CRI-5: フレーム途中（ヘッダ 1 バイトのみ）で止まった接続があっても、
/// shutdown は frame_read_timeout を待たず shutdown_timeout 内に成功する。
#[test]
fn cri5_shutdown_with_mid_frame_stalled_connection() {
    let cfg = ServerConfig {
        frame_read_timeout: Duration::from_secs(30),
        shutdown_timeout: Duration::from_secs(3),
        ..ServerConfig::default()
    };
    let (_r, path, h) = start("stall", TaskApiVersion::V2, cfg);
    let mut s = connect(&path);
    s.write_all(&[0u8]).unwrap();
    // サーバーが 1 バイトを読んでフレーム読み取りに入るのを待つ。
    std::thread::sleep(Duration::from_millis(200));
    let t = std::time::Instant::now();
    h.shutdown().unwrap();
    assert!(t.elapsed() < Duration::from_secs(3));
    assert_closed(&mut s);
}

/// 計測の記録先（試験用）。
#[derive(Default)]
struct Rec(std::sync::Mutex<Vec<(String, i32)>>);

impl fandhe_container_cri::instrument::CriOpRecorder for Rec {
    fn record_cri_op(&self, s: &fandhe_container_cri::instrument::CriOpSample) {
        self.0
            .lock()
            .unwrap()
            .push((s.kind().as_str().to_string(), s.code() as i32));
    }
}

/// CRI-5・REPAIR-4: dispatch・不正フレーム・期限切れが固定の種別と結果コードで記録される。
#[test]
fn cri5_operations_are_recorded() {
    let rec = Arc::new(Rec::default());
    let cfg = ServerConfig {
        frame_read_timeout: Duration::from_millis(200),
        ..ServerConfig::default()
    };
    let root = test_root::test_root("ttrpc", "rec");
    let path = root.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mut reg = ServiceRegistry::new();
    reg.register(Arc::new(EmptyTaskService::new(TaskApiVersion::V2)))
        .unwrap();
    let h = TtrpcServer::with_recorder(reg, cfg, rec.clone())
        .serve(listener)
        .unwrap();
    let mut s = connect(&path);
    send_req(&mut s, 1, "containerd.task.v2.Task", "State");
    read_resp(&mut s).unwrap();
    send_req(&mut s, 1, "containerd.task.v2.Task", "State");
    read_resp(&mut s).unwrap();
    let mut t = connect(&path);
    t.write_all(&[0, 0, 0]).unwrap();
    assert_closed(&mut t);
    h.shutdown().unwrap();
    let got = rec.0.lock().unwrap().clone();
    assert!(got.contains(&("cri.shim_v2.dispatch".into(), UNIMPL)));
    assert!(got.contains(&("cri.shim_v2.frame".into(), INVALID)));
    // DeadlineExceeded = 4
    assert!(got.contains(&("cri.shim_v2.io".into(), 4)));
}
/// CRI-5・REPAIR-5: 範囲外の期限設定（`Duration::MAX`・ゼロの間隔）は
/// panic せず構造化エラーで起動を拒否する。
#[test]
fn out_of_range_config_is_rejected_without_panic() {
    let cases: [(&str, Mutate); 5] = [
        ("shutdown_timeout", |c| c.shutdown_timeout = Duration::MAX),
        ("write_timeout", |c| c.write_timeout = Duration::MAX),
        ("frame_read_timeout", |c| {
            c.frame_read_timeout = Duration::MAX
        }),
        ("poll_interval", |c| c.poll_interval = Duration::MAX),
        ("poll_interval", |c| c.poll_interval = Duration::ZERO),
    ];
    for (i, (field, mutate)) in cases.iter().enumerate() {
        let root = test_root::test_root("ttrpc", &format!("badcfg{i}"));
        let path = root.join("s.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let mut cfg = ServerConfig::default();
        mutate(&mut cfg);
        let err = match TtrpcServer::new(ServiceRegistry::new(), cfg).serve(listener) {
            Ok(_) => panic!("must reject {field}"),
            Err(e) => e,
        };
        assert_eq!(err.to_string(), format!("invalid config: {field}"));
    }
}

/// 上限超過の成功ペイロードを返すサービス（試験用）。
struct BigService;

impl TtrpcService for BigService {
    fn name(&self) -> &str {
        "test.Big"
    }
    fn handle(&self, _method: &str, _payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        Ok(vec![0u8; MAX_PAYLOAD_LEN as usize + 1])
    }
}

fn start_with_rec(
    tag: &str,
    svc: Arc<dyn TtrpcService>,
    rec: Arc<Rec>,
) -> (test_root::TestRoot, std::path::PathBuf, ServerHandle) {
    let root = test_root::test_root("ttrpc", tag);
    let path = root.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mut reg = ServiceRegistry::new();
    reg.register(svc).unwrap();
    let h = TtrpcServer::with_recorder(reg, ServerConfig::default(), rec)
        .serve(listener)
        .unwrap();
    (root, path, h)
}

/// CRI-5・REPAIR-4: 応答サイズ超過で置換された応答の結果コード（ResourceExhausted）が記録される。
#[test]
fn cri5_oversize_response_is_recorded_as_resource_exhausted() {
    let rec = Arc::new(Rec::default());
    let (_root, path, h) = start_with_rec("big", Arc::new(BigService), rec.clone());
    let mut s = connect(&path);
    send_req(&mut s, 1, "test.Big", "M");
    let (_, r) = read_resp(&mut s).unwrap();
    assert_eq!(code(&r), EXHAUSTED);
    h.shutdown().unwrap();
    let got = rec.0.lock().unwrap().clone();
    assert!(got.contains(&("cri.shim_v2.dispatch".into(), EXHAUSTED)));
    assert!(!got.contains(&("cri.shim_v2.dispatch".into(), 0)));
}

/// CRI-5・REPAIR-5: metadata が件数上限を超える要求は復号されず InvalidArgument になる。
#[test]
fn cri5_metadata_flood_is_rejected() {
    let (_root, path, h) = start("mdflood", TaskApiVersion::V2, ServerConfig::default());
    let mut s = connect(&path);
    let mut body = TtrpcRequest {
        service: "containerd.task.v2.Task".into(),
        method: "State".into(),
        ..Default::default()
    }
    .encode_to_vec();
    // 空の KeyValue（0x2a 0x00）を大量に並べる。
    for _ in 0..100_000 {
        body.extend_from_slice(&[0x2a, 0x00]);
    }
    let hd = FrameHeader::new(body.len() as u32, 1, MessageType::Request, 0).unwrap();
    s.write_all(&hd.to_bytes()).unwrap();
    s.write_all(&body).unwrap();
    let (_, r) = read_resp(&mut s).unwrap();
    assert_eq!(code(&r), INVALID);
    h.shutdown().unwrap();
}

/// CRI-5・REPAIR-4: 不正ヘッダへの応答の書き込み失敗（相手が切断済み）も io として記録される。
#[test]
fn cri5_invalid_header_write_failure_is_recorded() {
    let rec = Arc::new(Rec::default());
    let (_root, path, h) = start_with_rec(
        "badhdrwrite",
        Arc::new(EmptyTaskService::new(TaskApiVersion::V2)),
        rec.clone(),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut seen = false;
    while !seen && std::time::Instant::now() < deadline {
        let mut s = connect(&path);
        // 長さが上限超過の不正ヘッダを送って、応答を読まずに即切断する。
        let mut raw = [0u8; HEADER_LEN];
        raw[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        raw[4..8].copy_from_slice(&1u32.to_be_bytes());
        raw[8] = 1;
        s.write_all(&raw).unwrap();
        drop(s);
        std::thread::sleep(Duration::from_millis(100));
        // Unavailable = 14
        seen = rec
            .0
            .lock()
            .unwrap()
            .contains(&("cri.shim_v2.io".into(), 14));
    }
    h.shutdown().unwrap();
    assert!(
        seen,
        "write failure on invalid-header path must be recorded"
    );
}

/// "Slow" は取り消しまで待ち、"Fast" は即座に返す試験用サービス。
struct BlockingSvc {
    cancelled_seen: Arc<std::sync::atomic::AtomicBool>,
}

impl TtrpcService for BlockingSvc {
    fn name(&self) -> &str {
        "test.Blocking"
    }
    fn handle(&self, method: &str, _payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        assert_eq!(method, "Fast");
        Ok(Vec::new())
    }
    fn handle_cancellable(
        &self,
        method: &str,
        payload: &[u8],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, RpcStatus> {
        if method != "Slow" {
            return self.handle(method, payload);
        }
        let end = std::time::Instant::now() + Duration::from_secs(30);
        while std::time::Instant::now() < end {
            if cancelled() {
                self.cancelled_seen
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(RpcStatus::from_code(CriErrorCode::Unavailable, "cancelled"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(Vec::new())
    }
}

fn start_blocking(
    tag: &str,
) -> (
    test_root::TestRoot,
    std::path::PathBuf,
    ServerHandle,
    Arc<std::sync::atomic::AtomicBool>,
) {
    let root = test_root::test_root("ttrpc", tag);
    let path = root.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut reg = ServiceRegistry::new();
    reg.register(Arc::new(BlockingSvc {
        cancelled_seen: Arc::clone(&seen),
    }))
    .unwrap();
    let h = TtrpcServer::new(reg, ServerConfig::default())
        .serve(listener)
        .unwrap();
    (root, path, h, seen)
}

/// 同じ接続で待ち中の要求が後続の要求を塞がない（CRI-5・TASK-62.3.2 の Create -> Wait -> Start）。
#[test]
fn cri5_pending_request_does_not_block_later_requests_on_same_connection() {
    let (_root, path, h, _seen) = start_blocking("conc");
    let mut c = connect(&path);
    send_req(&mut c, 1, "test.Blocking", "Slow");
    send_req(&mut c, 3, "test.Blocking", "Fast");
    let (sid, r) = read_resp(&mut c).unwrap();
    assert_eq!((sid, r.status.is_none()), (3, true));
    // Slow は停止要求で取り消される。
    h.shutdown().unwrap();
}

/// 待ち中のハンドラへ停止要求が届き、shutdown が期限内に終わる（REPAIR-5）。
#[test]
fn cri5_shutdown_cancels_pending_handler() {
    let (_root, path, h, seen) = start_blocking("cancel");
    let mut c = connect(&path);
    send_req(&mut c, 1, "test.Blocking", "Slow");
    std::thread::sleep(Duration::from_millis(100));
    let t = std::time::Instant::now();
    h.shutdown().unwrap();
    assert!(t.elapsed() < Duration::from_secs(3));
    assert!(seen.load(std::sync::atomic::Ordering::SeqCst));
}

/// 接続が閉じたら待ち中のハンドラも取り消される。
#[test]
fn cri5_disconnect_cancels_pending_handler() {
    let (_root, path, h, seen) = start_blocking("disc");
    let mut c = connect(&path);
    send_req(&mut c, 1, "test.Blocking", "Slow");
    std::thread::sleep(Duration::from_millis(100));
    drop(c);
    let end = std::time::Instant::now() + Duration::from_secs(5);
    while !seen.load(std::sync::atomic::Ordering::SeqCst) && std::time::Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(seen.load(std::sync::atomic::Ordering::SeqCst));
    h.shutdown().unwrap();
}
