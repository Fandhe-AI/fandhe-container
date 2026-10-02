//! フレーム単位の送受信とタイムアウトの結合試験（PLUG-2・PLUG-5・REPAIR-5。TASK-107.6・#250）。
//! root・特権不要。待ちはすべて有限の期限付き。
//!
//! 要求・応答の往復を通した ACK 待ちタイムアウトの試験は `transport_timeout.rs`（TASK-107.7・#251）。

#[cfg(not(unix))]
#[test]
fn repair5_frame_io_requires_unix_transport() {
    use fandhe_container_plugin::{PluginErrorCode, UdsStream};
    let err = UdsStream::connect(
        std::path::Path::new("s.sock"),
        std::time::Duration::from_secs(1),
    )
    .unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::Unimplemented);
}

#[cfg(unix)]
mod unix {
    use fandhe_container_plugin::{
        ControlMessage, MessageId, PluginErrorCode, RpcTimeout, UdsListener, UdsStream,
        decode_message, encode_message,
    };
    use std::io::Write;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    const WAIT: Duration = Duration::from_secs(5);

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcpf-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
        fn sock(&self) -> PathBuf {
            self.0.join("s.sock")
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    type Msg = ControlMessage<String>;

    fn rpc(ms: u64) -> RpcTimeout {
        RpcTimeout::new(Duration::from_millis(ms)).unwrap()
    }

    fn request(id: u64, body: &str) -> Msg {
        ControlMessage::Request {
            id: MessageId::new(id),
            body: body.to_string(),
        }
    }

    /// listener を bind し、client 接続と accept 済み server 側接続の組を返す。
    fn pair(dir: &TempDir) -> (UdsListener, UdsStream, UdsStream) {
        let l = UdsListener::bind(&dir.sock()).unwrap();
        let client = UdsStream::connect(l.path(), WAIT).unwrap();
        let server = l.accept(WAIT).unwrap();
        (l, client, server)
    }

    #[test]
    fn plug2_write_frame_then_read_frame_roundtrip() {
        let dir = TempDir::new();
        let (_l, mut client, mut server) = pair(&dir);
        let frame = encode_message(&request(7, "ping")).unwrap();
        client.write_frame(&frame, rpc(1000)).unwrap();
        let got = server.read_frame(rpc(1000)).unwrap();
        assert_eq!(decode_message::<String>(&got).unwrap(), request(7, "ping"));
    }

    #[test]
    fn repair5_read_frame_returns_timeout_error() {
        let dir = TempDir::new();
        let (_l, _client, mut server) = pair(&dir);
        let start = Instant::now();
        let e = server.read_frame(rpc(200)).unwrap_err();
        let elapsed = start.elapsed();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        assert_eq!(e.code().as_str(), "TIMEOUT");
        assert_eq!(e.message(), "timed out waiting for a frame");
        assert!(elapsed >= Duration::from_millis(150), "{elapsed:?}");
        assert!(elapsed < WAIT, "{elapsed:?}");
    }

    /// 1 バイトずつ間隔を空けて送り続ける相手でも、合計期限で打ち切る。
    #[test]
    fn repair5_read_frame_total_deadline_covers_slow_sender() {
        let dir = TempDir::new();
        let (_l, mut client, mut server) = pair(&dir);
        let bytes = encode_message(&request(1, "slow")).unwrap().encode();
        // 全体の送信に 100ms * len かかる。受信側の期限（300ms）はそれより十分短い。
        let h = std::thread::spawn(move || {
            for b in bytes {
                if client.write_all(&[b]).is_err() || client.flush().is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let start = Instant::now();
        let e = server.read_frame(rpc(300)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        assert!(start.elapsed() < WAIT);
        drop(server);
        h.join().unwrap();
    }

    #[test]
    fn plug2_read_frame_peer_closed_returns_unavailable() {
        let dir = TempDir::new();
        let (_l, client, mut server) = pair(&dir);
        drop(client);
        let e = server.read_frame(rpc(2000)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(e.message(), "peer closed the connection");
    }

    #[test]
    fn repair5_stream_is_unusable_after_frame_timeout() {
        let dir = TempDir::new();
        let (_l, _client, mut server) = pair(&dir);
        let e = server.read_frame(rpc(100)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        let e = server.read_frame(rpc(100)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(
            e.message(),
            "connection is unusable after a previous frame error"
        );
        let frame = encode_message(&request(1, "x")).unwrap();
        let e = server.write_frame(&frame, rpc(100)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
    }

    #[test]
    fn repair5_raw_io_is_rejected_after_frame_failure() {
        use std::io::{ErrorKind, Read};
        let dir = TempDir::new();
        let (_l, _client, mut server) = pair(&dir);
        let e = server.read_frame(rpc(100)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        let mut buf = [0u8; 1];
        assert_eq!(
            server.read(&mut buf).unwrap_err().kind(),
            ErrorKind::NotConnected
        );
        assert_eq!(
            server.write(b"x").unwrap_err().kind(),
            ErrorKind::NotConnected
        );
        assert_eq!(server.flush().unwrap_err().kind(), ErrorKind::NotConnected);
    }

    /// 送信バッファの挙動は OS 差が大きい（macOS は詰まりの閾値が異なる）ため、確実に詰まる
    /// Linux に限定する。期待値は弱めない。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_write_frame_times_out_when_peer_does_not_read() {
        let dir = TempDir::new();
        let (_l, mut client, _server) = pair(&dir);
        let frame = fandhe_container_plugin::Frame::new(vec![0xAB; 8 * 1024 * 1024]).unwrap();
        let start = Instant::now();
        let e = client.write_frame(&frame, rpc(300)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        assert_eq!(e.message(), "timed out sending a frame");
        assert!(start.elapsed() < WAIT);
    }

    #[test]
    fn plug2_read_frame_rejects_corrupted_checksum() {
        let dir = TempDir::new();
        let (_l, mut client, mut server) = pair(&dir);
        let mut bytes = encode_message(&request(1, "bad")).unwrap().encode();
        let last = bytes.last_mut().unwrap();
        *last ^= 0xFF;
        client.write_all(&bytes).unwrap();
        client.flush().unwrap();
        let e = server.read_frame(rpc(1000)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::DataLoss);
    }
}
