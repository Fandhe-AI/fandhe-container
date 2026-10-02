//! UDS listener の結合試験（PLUG-2・PLUG-12・REPAIR-5。TASK-107.4・#248）。
//! root・特権不要。accept は期限付きでハングしない。

#[cfg(not(unix))]
#[test]
fn plug2_bind_is_unimplemented_on_non_unix() {
    use fandhe_container_plugin::{PluginErrorCode, UdsListener};
    let err = UdsListener::bind(std::path::Path::new("s.sock")).unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::Unimplemented);
}

#[cfg(unix)]
mod unix {
    use fandhe_container_plugin::{PluginErrorCode, UDS_ACCEPT_TIMEOUT_MAX, UdsListener};
    use std::io::{Read, Write};
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    const WAIT: Duration = Duration::from_secs(5);

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcpl-{}-{}",
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

    fn connect_and_ping(path: &Path) -> std::thread::JoinHandle<Vec<u8>> {
        let path = path.to_path_buf();
        std::thread::spawn(move || {
            let mut c = UnixStream::connect(path).unwrap();
            c.set_read_timeout(Some(WAIT)).unwrap();
            c.write_all(b"ping").unwrap();
            let mut buf = [0u8; 4];
            c.read_exact(&mut buf).unwrap();
            buf.to_vec()
        })
    }

    #[test]
    fn plug2_bind_then_accept_receives_connection() {
        let dir = TempDir::new();
        let l = UdsListener::bind(&dir.sock()).unwrap();
        let h = connect_and_ping(l.path());
        let mut s = l.accept(WAIT).unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        s.write_all(b"pong").unwrap();
        assert_eq!(h.join().unwrap(), b"pong".to_vec());
    }

    /// PLUG-12: bind 後の socket は 0600、親が他者書き込み可なら拒否し socket を残さない。
    #[test]
    fn plug12_bind_restricts_mode_and_rejects_writable_parent() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let l = UdsListener::bind(&dir.sock()).unwrap();
        let mode = std::fs::metadata(l.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        drop(l);

        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = UdsListener::bind(&dir.sock()).unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
        assert!(!dir.sock().exists());
    }

    #[test]
    fn plug2_accept_accepts_multiple_connections_sequentially() {
        let dir = TempDir::new();
        let l = UdsListener::bind(&dir.sock()).unwrap();
        for _ in 0..2 {
            let h = connect_and_ping(l.path());
            let mut s = l.accept(WAIT).unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            s.write_all(b"pong").unwrap();
            h.join().unwrap();
        }
    }

    #[test]
    fn repair5_accept_times_out_without_client() {
        let dir = TempDir::new();
        let l = UdsListener::bind(&dir.sock()).unwrap();
        let t = Instant::now();
        let err = l.accept(Duration::from_millis(200)).unwrap_err();
        let el = t.elapsed();
        assert_eq!(err.code(), PluginErrorCode::Timeout);
        assert!(el >= Duration::from_millis(200), "{el:?}");
        assert!(el < Duration::from_secs(5), "{el:?}");
    }

    #[test]
    fn repair5_accept_rejects_invalid_timeout() {
        let dir = TempDir::new();
        let l = UdsListener::bind(&dir.sock()).unwrap();
        let e = l.accept(Duration::ZERO).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        let e = l
            .accept(UDS_ACCEPT_TIMEOUT_MAX + Duration::from_secs(1))
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
    }

    #[test]
    fn plug12_bind_existing_path_is_rejected_without_unlink() {
        let dir = TempDir::new();
        std::fs::write(dir.sock(), b"keep").unwrap();
        let e = UdsListener::bind(&dir.sock()).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::AlreadyExists);
        assert_eq!(std::fs::read(dir.sock()).unwrap(), b"keep");

        let dir2 = TempDir::new();
        let l = UdsListener::bind(&dir2.sock()).unwrap();
        let e = UdsListener::bind(&dir2.sock()).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::AlreadyExists);
        let h = connect_and_ping(l.path());
        let mut s = l.accept(WAIT).unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        s.write_all(b"pong").unwrap();
        h.join().unwrap();
    }

    #[test]
    fn plug2_bind_missing_parent_dir_returns_not_found() {
        let dir = TempDir::new();
        let e = UdsListener::bind(&dir.0.join("nodir").join("s.sock")).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::NotFound);
    }

    #[test]
    fn plug2_drop_removes_own_socket_and_allows_rebind() {
        let dir = TempDir::new();
        drop(UdsListener::bind(&dir.sock()).unwrap());
        assert!(!dir.sock().exists());
        let _l = UdsListener::bind(&dir.sock()).unwrap();
    }

    #[test]
    fn plug2_drop_keeps_replaced_path() {
        let dir = TempDir::new();
        let l = UdsListener::bind(&dir.sock()).unwrap();
        std::fs::rename(dir.sock(), dir.0.join("moved")).unwrap();
        std::fs::write(dir.sock(), b"other").unwrap();
        drop(l);
        assert_eq!(std::fs::read(dir.sock()).unwrap(), b"other");
    }
}
