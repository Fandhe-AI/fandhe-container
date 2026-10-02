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

    /// PLUG-12: `..` を含む bind パスは再解決で別ディレクトリを指しうるため拒否する。
    #[test]
    fn plug12_bind_rejects_parent_dir_component() {
        let dir = TempDir::new();
        let p = dir.0.join("sub").join("..").join("s.sock");
        let e = UdsListener::bind(&p).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
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

    /// PLUG-12: group/other に権限のある親・symlink の親は拒否する（0700 相当のみ許可）。
    #[test]
    fn plug12_bind_rejects_group_accessible_and_symlink_parent() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o750)).unwrap();
        let e = UdsListener::bind(&dir.sock()).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();

        let real = dir.0.join("real");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&real)
            .unwrap();
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let e = UdsListener::bind(&link.join("s.sock")).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
        assert!(!real.join("s.sock").exists());
    }

    /// PLUG-12: 祖先要素が symlink でも、検証した配置ディレクトリ（解決後の実体）の直下に
    /// socket が作られ、接続でき、Drop で削除される（検証 fd と bind 先が一致する）。
    #[test]
    fn plug12_bind_with_symlinked_ancestor_creates_socket_in_verified_dir() {
        let dir = TempDir::new();
        let real = dir.0.join("real");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&real)
            .unwrap();
        let inner = real.join("inner");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&inner)
            .unwrap();
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let requested = link.join("inner").join("s.sock");
        let l = UdsListener::bind(&requested).unwrap();
        assert!(inner.join("s.sock").exists());
        // PLUG-12: 公開パスは symlink を解決した検証済みディレクトリ基準（渡した経路ではない）。
        // TempDir 自体が symlink 配下にある OS（macOS の /var → /private/var）があるため、
        // 期待値は実体ディレクトリの canonicalize 結果から組み立てる。
        let expected = std::fs::canonicalize(&inner).unwrap().join("s.sock");
        assert_eq!(l.path(), expected.as_path());
        assert_ne!(l.path(), requested.as_path());
        let h = connect_and_ping(&inner.join("s.sock"));
        let mut s = l.accept(WAIT).unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        s.write_all(&buf).unwrap();
        assert_eq!(h.join().unwrap(), b"ping");
        drop(l);
        assert!(!inner.join("s.sock").exists());
    }

    /// PLUG-12: bind 後に祖先の symlink を別ディレクトリへ差し替えても、`path()` は検証済みの
    /// socket を指し続け、`path()` を使う client は差し替え先（偽の listener）へ誘導されない。
    #[test]
    fn plug12_path_stays_on_verified_socket_after_ancestor_symlink_swap() {
        let dir = TempDir::new();
        let real = dir.0.join("real");
        let decoy = dir.0.join("decoy");
        // 配置ディレクトリ自体の symlink は拒否されるため、symlink は祖先（1 つ上）に置く。
        for d in [&real, &decoy] {
            std::fs::DirBuilder::new().mode(0o700).create(d).unwrap();
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(d.join("inner"))
                .unwrap();
        }
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let l = UdsListener::bind(&link.join("inner").join("s.sock")).unwrap();

        // 祖先 symlink を差し替え、差し替え先に同名の別 listener を置く。
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&decoy, &link).unwrap();
        let decoy_listener =
            std::os::unix::net::UnixListener::bind(decoy.join("inner").join("s.sock")).unwrap();
        decoy_listener.set_nonblocking(true).unwrap();

        let expected = std::fs::canonicalize(real.join("inner"))
            .unwrap()
            .join("s.sock");
        assert_eq!(l.path(), expected.as_path());
        let h = connect_and_ping(l.path());
        let mut s = l.accept(WAIT).unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        s.write_all(b"pong").unwrap();
        assert_eq!(h.join().unwrap(), b"pong".to_vec());
        // 差し替え先の listener には接続が届いていない。
        assert_eq!(
            decoy_listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    /// PLUG-2・PLUG-12: path() は配置ディレクトリを解決した絶対パス＋socket 名で保持される
    /// （相対指定でも Drop 時の cwd に依存しない）。
    #[test]
    fn plug2_path_is_absolute() {
        let dir = TempDir::new();
        let l = UdsListener::bind(&dir.sock()).unwrap();
        assert!(l.path().is_absolute());
        let expected = std::fs::canonicalize(&dir.0).unwrap().join("s.sock");
        assert_eq!(l.path(), expected.as_path());
    }

    /// REPAIR-5: 何も送らない peer でも read は期限で戻り、0 の期限は拒否される。
    #[test]
    fn repair5_accepted_stream_read_times_out() {
        let dir = TempDir::new();
        let l = UdsListener::bind(&dir.sock()).unwrap();
        let _c = UnixStream::connect(l.path()).unwrap();
        let mut s = l.accept(WAIT).unwrap();
        let e = s.set_io_timeout(Duration::ZERO).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        s.set_io_timeout(Duration::from_millis(100)).unwrap();
        let t = Instant::now();
        let mut buf = [0u8; 1];
        let err = s.read(&mut buf).unwrap_err();
        assert!(matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        assert!(t.elapsed() < Duration::from_secs(5));
    }
}
