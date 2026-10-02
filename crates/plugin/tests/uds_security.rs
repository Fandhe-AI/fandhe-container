//! runtime directory 解決・作成の結合試験（PLUG-12・TASK-123.1・#286）。root・特権不要。

#[cfg(not(unix))]
#[test]
fn plug12_runtime_dir_is_unimplemented_on_non_unix() {
    use fandhe_container_plugin::{PluginErrorCode, RuntimeDir};
    let err = RuntimeDir::ensure_under(std::path::Path::new("C:\\x")).unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::Unimplemented);
}

#[cfg(unix)]
mod unix {
    use fandhe_container_plugin::{PluginErrorCode, RUNTIME_DIR_NAME, RuntimeDir, UdsListener};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcrd-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
        fn rt(&self) -> PathBuf {
            self.0.join(RUNTIME_DIR_NAME)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn mode_of(p: &std::path::Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().mode() & 0o777
    }

    #[test]
    fn plug12_creates_runtime_dir_with_0700() {
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let expected = std::fs::canonicalize(&t.0).unwrap().join(RUNTIME_DIR_NAME);
        assert_eq!(d.path(), expected.as_path());
        assert_eq!(mode_of(d.path()), 0o700);
        assert_eq!(
            std::fs::metadata(d.path()).unwrap().uid(),
            std::fs::metadata(&t.0).unwrap().uid()
        );
    }

    #[test]
    fn plug12_reuses_existing_private_dir() {
        let t = TempDir::new();
        let a = RuntimeDir::ensure_under(&t.0).unwrap();
        std::fs::write(a.path().join("keep"), b"x").unwrap();
        let b = RuntimeDir::ensure_under(&t.0).unwrap();
        assert_eq!(a, b);
        assert!(b.path().join("keep").exists());
    }

    #[test]
    fn plug12_rejects_group_or_other_accessible_dir() {
        for m in [0o755, 0o770, 0o702] {
            let t = TempDir::new();
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(t.rt())
                .unwrap();
            std::fs::set_permissions(t.rt(), std::fs::Permissions::from_mode(m)).unwrap();
            let err = RuntimeDir::ensure_under(&t.0).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::PermissionDenied, "mode {m:o}");
            assert_eq!(mode_of(&t.rt()), m, "mode must not be repaired");
        }
    }

    #[test]
    fn plug12_rejects_symlink_runtime_dir() {
        let t = TempDir::new();
        let real = t.0.join("real");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&real)
            .unwrap();
        std::os::unix::fs::symlink(&real, t.rt()).unwrap();
        let err = RuntimeDir::ensure_under(&t.0).unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
        assert!(
            std::fs::symlink_metadata(t.rt())
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn plug12_rejects_non_directory() {
        let t = TempDir::new();
        std::fs::write(t.rt(), b"x").unwrap();
        let err = RuntimeDir::ensure_under(&t.0).unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
        assert!(t.rt().is_file());
    }

    #[test]
    fn plug12_missing_base_is_not_created() {
        let t = TempDir::new();
        let base = t.0.join("absent");
        let err = RuntimeDir::ensure_under(&base).unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::NotFound);
        assert!(!base.exists());
    }

    #[test]
    fn plug12_rejects_relative_base() {
        let err = RuntimeDir::ensure_under(std::path::Path::new("rel")).unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::FailedPrecondition);
    }

    /// transport の親ディレクトリ検証閾値と一致し、得たディレクトリで bind できる。
    #[test]
    fn plug12_runtime_dir_accepted_by_listener_bind() {
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        UdsListener::bind(&d.path().join("s.sock")).unwrap();
    }
    /// 自 UID 所有の stale socket は削除され再 bind できる（TASK-123.2・AC3）。
    #[test]
    fn plug12_rebind_over_own_stale_socket() {
        use std::time::Duration;
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let p = d.path().join("s.sock");
        drop(std::os::unix::net::UnixListener::bind(&p).unwrap()); // std は unlink しない
        let old_ino = std::fs::symlink_metadata(&p).unwrap().ino();
        let l = UdsListener::bind(&p).unwrap();
        let m = std::fs::symlink_metadata(&p).unwrap();
        assert_ne!(m.ino(), old_ino);
        assert_eq!(m.mode() & 0o777, 0o600);
        let _c = std::os::unix::net::UnixStream::connect(l.path()).unwrap();
        l.accept(Duration::from_secs(2)).unwrap();
    }

    /// symlink は削除せず PermissionDenied。リンクもリンク先も不変（TASK-123.2・AC1）。
    #[test]
    fn plug12_symlink_at_socket_path_is_rejected_untouched() {
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let target = d.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        let link = d.path().join("s.sock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let e = UdsListener::bind(&link).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");

        // リンク先が stale socket の場合も、リンクもリンク先も残る。
        let link2 = d.path().join("t.sock");
        let stale = d.path().join("stale");
        drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
        std::os::unix::fs::symlink(&stale, &link2).unwrap();
        let e = UdsListener::bind(&link2).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
        assert!(
            std::fs::symlink_metadata(&link2)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(std::fs::symlink_metadata(&stale).is_ok());
    }

    /// 生存中の listener のパスは奪わない（TASK-123.2）。
    #[test]
    fn plug12_live_listener_path_is_not_stolen() {
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let p = d.path().join("s.sock");
        let live = std::os::unix::net::UnixListener::bind(&p).unwrap();
        let e = UdsListener::bind(&p).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::AlreadyExists);
        assert!(std::fs::symlink_metadata(&p).is_ok());
        std::os::unix::net::UnixStream::connect(&p).unwrap();
        drop(live);
    }
}
