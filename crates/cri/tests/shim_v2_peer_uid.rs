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
