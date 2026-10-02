//! UDS client 接続の結合試験（PLUG-2・PLUG-12・REPAIR-5。TASK-107.5・#249）。
//! root・特権不要。待ちはすべて有限の期限付き。
//!
//! peer UID 不一致（偽 listener）の拒否は別 UID が必要で既定のテスト集合では再現できないため、
//! listener 側（accept）と同じく自動テストの対象外。

#[cfg(not(unix))]
#[test]
fn plug2_connect_is_unimplemented_on_non_unix() {
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
        ControlMessage, FRAME_HEADER_LEN, Frame, FrameHeader, MessageId, PluginErrorCode,
        UDS_CONNECT_TIMEOUT_MAX, UdsListener, UdsStream, decode_message, encode_message,
    };
    use std::io::{Read, Write};
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
                "fcpc-{}-{}",
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

    /// 公開 API だけでフレームを送る（encode_message → Frame::encode → write_all）。
    fn send(s: &mut UdsStream, msg: &Msg) {
        let frame = encode_message(msg).unwrap();
        s.write_all(&frame.encode()).unwrap();
        s.flush().unwrap();
    }

    /// 公開 API だけでフレームを受ける（ヘッダ → 検証済み body_len 分のみ確保 → デコード）。
    fn recv(s: &mut UdsStream) -> Msg {
        let mut head = [0u8; FRAME_HEADER_LEN];
        s.read_exact(&mut head).unwrap();
        let header = FrameHeader::from_bytes(head).unwrap();
        let mut body = vec![0u8; header.body_len()];
        s.read_exact(&mut body).unwrap();
        let frame = Frame::decode_body(header, &body).unwrap();
        decode_message(&frame).unwrap()
    }

    fn request(id: u64, body: &str) -> Msg {
        ControlMessage::Request {
            id: MessageId::new(id),
            body: body.to_string(),
        }
    }

    fn response(id: u64, body: &str) -> Msg {
        ControlMessage::Response {
            id: MessageId::new(id),
            body: body.to_string(),
        }
    }

    #[test]
    fn plug2_connect_then_frames_roundtrip() {
        let dir = TempDir::new();
        let l = UdsListener::bind(&dir.sock()).unwrap();
        let path = l.path().to_path_buf();
        let h = std::thread::spawn(move || {
            let mut c = UdsStream::connect(&path, WAIT).unwrap();
            send(&mut c, &request(1, "hello"));
            recv(&mut c)
        });
        let mut s = l.accept(WAIT).unwrap();
        assert_eq!(recv(&mut s), request(1, "hello"));
        send(&mut s, &response(1, "world"));
        assert_eq!(h.join().unwrap(), response(1, "world"));
    }

    #[test]
    fn plug2_connect_multiple_frames_on_one_connection() {
        let dir = TempDir::new();
        let l = UdsListener::bind(&dir.sock()).unwrap();
        let path = l.path().to_path_buf();
        let h = std::thread::spawn(move || {
            let mut c = UdsStream::connect(&path, WAIT).unwrap();
            let mut got = Vec::new();
            for i in 0..3u64 {
                send(&mut c, &request(i, &format!("req-{i}")));
                got.push(recv(&mut c));
            }
            got
        });
        let mut s = l.accept(WAIT).unwrap();
        for i in 0..3u64 {
            assert_eq!(recv(&mut s), request(i, &format!("req-{i}")));
            send(&mut s, &response(i, &format!("res-{i}")));
        }
        let got = h.join().unwrap();
        assert_eq!(
            got,
            vec![
                response(0, "res-0"),
                response(1, "res-1"),
                response(2, "res-2")
            ]
        );
    }

    #[test]
    fn plug2_connect_missing_socket_returns_not_found() {
        let dir = TempDir::new();
        let e = UdsStream::connect(&dir.sock(), WAIT).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::NotFound);
    }

    #[test]
    fn plug2_connect_stale_socket_returns_unavailable() {
        let dir = TempDir::new();
        drop(std::os::unix::net::UnixListener::bind(dir.sock()).unwrap());
        assert!(dir.sock().exists());
        let e = UdsStream::connect(&dir.sock(), WAIT).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
    }

    #[test]
    fn repair5_connect_rejects_invalid_timeout() {
        let dir = TempDir::new();
        let e = UdsStream::connect(&dir.sock(), Duration::ZERO).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        let e = UdsStream::connect(
            &dir.sock(),
            UDS_CONNECT_TIMEOUT_MAX + Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
    }

    #[test]
    fn plug2_connect_rejects_too_long_path() {
        let long = PathBuf::from(format!("/{}", "a".repeat(300)));
        let e = UdsStream::connect(&long, WAIT).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(e.message(), "socket path is too long");
    }

    #[test]
    fn repair5_connected_stream_read_times_out() {
        let dir = TempDir::new();
        let l = UdsListener::bind(&dir.sock()).unwrap();
        let path = l.path().to_path_buf();
        let h = std::thread::spawn(move || {
            let mut c = UdsStream::connect(&path, WAIT).unwrap();
            c.set_io_timeout(Duration::from_millis(200)).unwrap();
            let t = Instant::now();
            let mut b = [0u8; 1];
            let r = c.read(&mut b);
            (r, t.elapsed())
        });
        let _s = l.accept(WAIT).unwrap();
        let (r, el) = h.join().unwrap();
        let kind = r.unwrap_err().kind();
        assert!(
            matches!(
                kind,
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "{kind:?}"
        );
        assert!(el >= Duration::from_millis(150), "{el:?}");
        assert!(el < Duration::from_secs(5), "{el:?}");
    }
}
