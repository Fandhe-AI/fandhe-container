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

    #[cfg(target_os = "linux")]
    const SUN_PATH_CAPACITY: usize = 108;
    #[cfg(not(target_os = "linux"))]
    const SUN_PATH_CAPACITY: usize = 104;

    /// PLUG-12・TASK-123.3: socket_path -> bind で socket が 0600 になる。
    #[test]
    fn plug12_socket_path_then_bind_yields_0600() {
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let sp = d.socket_path("s.sock").unwrap();
        assert_eq!(sp, d.path().join("s.sock"));
        let _l = UdsListener::bind(&sp).unwrap();
        assert_eq!(mode_of(&sp), 0o600);
    }

    /// PLUG-12・TASK-123.3: sun_path 境界。容量 - 1 は成功、容量ちょうどは拒否し socket を作らない。
    #[test]
    fn plug12_socket_path_sun_path_boundary() {
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let base = d.path().as_os_str().len() + 1; // 区切り 1 バイト
        if base + 1 >= SUN_PATH_CAPACITY {
            return; // 一時ディレクトリ自体が長すぎる環境では境界を作れない
        }
        let fits = "a".repeat(SUN_PATH_CAPACITY - 1 - base);
        let p = d.socket_path(&fits).unwrap();
        assert_eq!(p.as_os_str().len(), SUN_PATH_CAPACITY - 1);
        let over = "a".repeat(SUN_PATH_CAPACITY - base);
        let err = d.socket_path(&over).unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(err.message(), "socket path is too long");
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    /// PLUG-12・TASK-123.3: 単一コンポーネント以外の名前は bind 前に拒否する。
    #[test]
    fn plug12_socket_path_rejects_invalid_names() {
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        for n in ["", ".", "..", "a/b", "/abs", "a/", "a/.", "../x", "a\0b"] {
            let err = d.socket_path(n).unwrap_err();
            assert_eq!(err.code(), PluginErrorCode::InvalidArgument, "name {n:?}");
        }
    }
}
