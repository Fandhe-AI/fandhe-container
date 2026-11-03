//! shim v2 の ttrpc サーバーの peer UID 照合の結合試験（PLUG-12・CRI-5・TASK-62.7.1・#872）。
#![cfg(unix)]

#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;

use fandhe_container_cri::shim_v2::{
    EmptyTaskService, FrameHeader, HEADER_LEN, MessageType, ServerConfig, ServiceRegistry,
    TaskApiVersion, TtrpcRequest, TtrpcServer,
};
use prost::Message;

fn serve(
    tag: &str,
    cfg: ServerConfig,
) -> (
    test_root::TestRoot,
    std::path::PathBuf,
    fandhe_container_cri::shim_v2::ServerHandle,
) {
    let root = test_root::test_root("peeruid", tag);
    let path = root.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mut reg = ServiceRegistry::new();
    reg.register(Arc::new(EmptyTaskService::new(TaskApiVersion::V2)))
        .unwrap();
    let h = TtrpcServer::new(reg, cfg).serve(listener).unwrap();
    (root, path, h)
}

fn state_request(s: &mut UnixStream) -> std::io::Result<usize> {
    let body = TtrpcRequest {
        service: "containerd.task.v2.Task".into(),
        method: "State".into(),
        ..Default::default()
    }
    .encode_to_vec();
    let h = FrameHeader::new(body.len() as u32, 1, MessageType::Request, 0).unwrap();
    s.write_all(&h.to_bytes())?;
    s.write_all(&body)?;
    let mut hb = [0u8; HEADER_LEN];
    s.read(&mut hb)
}

/// PLUG-12: 許可一覧に無い uid の接続は、応答なしで切断される。
#[test]
fn plug12_peer_uid_not_allowed_is_closed() {
    // 自分で作ったディレクトリの所有者が実効 uid。
    let probe = test_root::test_root("peeruid", "probe");
    let euid = std::fs::metadata(&probe).unwrap().uid();
    let cfg = ServerConfig {
        allowed_peer_uids: Some(vec![euid.wrapping_add(1)]),
        ..ServerConfig::default()
    };
    let (_r, path, h) = serve("deny", cfg);
    let mut s = UnixStream::connect(&path).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // 切断済みなので、書き込みの失敗か、応答 0 バイト（EOF）・RST のいずれかになる。応答は返らない。
    match state_request(&mut s) {
        Ok(n) => assert_eq!(n, 0, "no response must be sent to a denied peer"),
        Err(e) => assert!(
            !matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "{e}"
        ),
    }
    h.shutdown().unwrap();
}

/// PLUG-12: 既定の設定は実効 uid の接続を受ける。
#[test]
fn plug12_default_accepts_same_uid() {
    let (_r, path, h) = serve("allow", ServerConfig::default());
    let mut s = UnixStream::connect(&path).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(state_request(&mut s).unwrap(), HEADER_LEN);
    h.shutdown().unwrap();
}

/// 記録を溜めるだけの監査 sink。
struct CollectSink(std::sync::Mutex<Vec<fandhe_container_core::audit_log::AuditRecord>>);

impl fandhe_container_core::audit_log::AuditSink for CollectSink {
    fn record(
        &self,
        record: &fandhe_container_core::audit_log::AuditRecord,
    ) -> Result<(), fandhe_container_core::traits::TraitError> {
        self.0.lock().unwrap().push(record.clone());
        Ok(())
    }
}

/// SEC-4・PLUG-12: 許可外 uid の実接続が、層 `plugin_peer`・理由 `plugin_peer_uid_mismatch` の監査レコード 1 件になる。
/// 許可された接続は記録されない。
#[test]
fn sec4_872_denied_connection_is_audited_once() {
    use fandhe_container_core::audit_log::AuditLayer;
    let probe = test_root::test_root("peeruid", "auditprobe");
    let euid = std::fs::metadata(&probe).unwrap().uid();
    let root = test_root::test_root("peeruid", "audit");
    let path = root.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mut reg = ServiceRegistry::new();
    reg.register(Arc::new(EmptyTaskService::new(TaskApiVersion::V2)))
        .unwrap();
    let sink = Arc::new(CollectSink(std::sync::Mutex::new(Vec::new())));
    let cfg = ServerConfig {
        allowed_peer_uids: Some(vec![euid.wrapping_add(1)]),
        ..ServerConfig::default()
    };
    let h = TtrpcServer::new(reg, cfg)
        .with_audit_sink(sink.clone())
        .serve(listener)
        .unwrap();
    let _s = UnixStream::connect(&path).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while sink.0.lock().unwrap().is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    h.shutdown().unwrap();
    let got = sink.0.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].layer(), AuditLayer::PluginPeer);
    assert_eq!(
        got[0].reason().unwrap().as_str(),
        "plugin_peer_uid_mismatch"
    );
}

/// 書き込みに時間がかかる(または止まる)sink。`release` が立つまで `record` を保留する。
struct SlowSink {
    entered: std::sync::atomic::AtomicBool,
    release: std::sync::atomic::AtomicBool,
    written: std::sync::atomic::AtomicUsize,
    hold: Duration,
}

impl fandhe_container_core::audit_log::AuditSink for SlowSink {
    fn record(
        &self,
        _record: &fandhe_container_core::audit_log::AuditRecord,
    ) -> Result<(), fandhe_container_core::traits::TraitError> {
        use std::sync::atomic::Ordering;
        self.entered.store(true, Ordering::SeqCst);
        let end = std::time::Instant::now() + self.hold;
        while std::time::Instant::now() < end && !self.release.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        self.written.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// 拒否 1 件を遅い sink へ積ませてから `shutdown` した結果(経過時間・書き込み件数・shutdown の戻り)を返す。
fn shutdown_with_slow_sink(
    tag: &str,
    hold: Duration,
    drain: Duration,
) -> (
    Duration,
    usize,
    Result<(), fandhe_container_cri::shim_v2::ShimV2Error>,
) {
    use std::sync::atomic::Ordering;
    let probe = test_root::test_root("peeruid", &format!("{tag}probe"));
    let euid = std::fs::metadata(&probe).unwrap().uid();
    let root = test_root::test_root("peeruid", tag);
    let path = root.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mut reg = ServiceRegistry::new();
    reg.register(Arc::new(EmptyTaskService::new(TaskApiVersion::V2)))
        .unwrap();
    let sink = Arc::new(SlowSink {
        entered: false.into(),
        release: false.into(),
        written: 0.into(),
        hold,
    });
    let cfg = ServerConfig {
        allowed_peer_uids: Some(vec![euid.wrapping_add(1)]),
        audit_drain_timeout: drain,
        ..ServerConfig::default()
    };
    let h = TtrpcServer::new(reg, cfg)
        .with_audit_sink(sink.clone())
        .serve(listener)
        .unwrap();
    let _s = UnixStream::connect(&path).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !sink.entered.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(sink.entered.load(Ordering::SeqCst), "sink was never called");
    let started = std::time::Instant::now();
    let r = h.shutdown();
    let elapsed = started.elapsed();
    let written = sink.written.load(Ordering::SeqCst);
    sink.release.store(true, Ordering::SeqCst);
    (elapsed, written, r)
}

/// SEC-4・REPAIR-5: `shutdown` は書き込み中の拒否レコードの完了まで待つ(排出前に戻らない)。
#[test]
fn sec4_3663_shutdown_waits_for_inflight_audit_record() {
    let (elapsed, written, r) = shutdown_with_slow_sink(
        "drainwait",
        Duration::from_millis(400),
        Duration::from_secs(10),
    );
    r.unwrap();
    assert_eq!(
        written, 1,
        "the in-flight record must be written before shutdown returns"
    );
    assert!(elapsed >= Duration::from_millis(100), "elapsed={elapsed:?}");
}

/// SEC-4・REPAIR-5: 監査の書き込みが止まっていても、`audit_drain_timeout` で `shutdown` は戻る(永久に待たない)。
#[test]
fn sec4_3663_shutdown_returns_at_drain_deadline_when_sink_hangs() {
    let (elapsed, written, r) = shutdown_with_slow_sink(
        "drainhang",
        Duration::from_secs(60),
        Duration::from_millis(300),
    );
    r.unwrap();
    assert_eq!(
        written, 0,
        "the hung record must not be reported as written"
    );
    assert!(elapsed >= Duration::from_millis(250), "elapsed={elapsed:?}");
    assert!(elapsed < Duration::from_secs(10), "elapsed={elapsed:?}");
}
