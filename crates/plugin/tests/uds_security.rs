//! runtime directory 解決・作成の結合試験（PLUG-12・TASK-123.1・#286、フォールバックは TASK-123.4・#289）。root・特権不要。

#[cfg(not(unix))]
#[test]
fn plug12_runtime_dir_is_unimplemented_on_non_unix() {
    use fandhe_container_plugin::{PluginErrorCode, RuntimeDir};
    let err = RuntimeDir::ensure_under(std::path::Path::new("C:\\x")).unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::Unimplemented);
    let err = RuntimeDir::from_env().unwrap_err();
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
            Self::new_in(std::env::temp_dir())
        }
        /// 環境の `TMPDIR` に依らず短いパスを保証する（sun_path 境界テスト用）。
        fn new_short() -> Self {
            Self::new_in(PathBuf::from("/tmp"))
        }
        fn new_in(root: PathBuf) -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = root.join(format!(
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

    /// ロックの記録 `fcus2 <dev> <ino> <mtime 秒> <mtime ナノ秒>\n` から ino を取り出す。
    fn recorded_ino(record: &str) -> Option<u64> {
        let mut it = record.strip_suffix('\n')?.split(' ');
        if it.next()? != "fcus2" {
            return None;
        }
        it.nth(1)?.parse().ok()
    }

    /// 自 UID 所有の stale socket は削除され再 bind できる（TASK-123.2・AC3）。
    #[test]
    fn plug12_rebind_over_own_stale_socket() {
        use std::time::Duration;
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let p = d.path().join("s.sock");
        // クラッシュ後の残骸を再現する: 記録つきロックファイルと同一 inode の socket が残り、保持者は居ない。
        let first = UdsListener::bind(&p).unwrap();
        let lock = d.path().join("s.sock.lock");
        let record = std::fs::read(&lock).unwrap();
        assert!(record.starts_with(b"fcus2 "));
        let keep = d.path().join("s.keep");
        std::fs::hard_link(&p, &keep).unwrap(); // 正常終了の unlink から inode を守る
        drop(first); // socket 名を unlink し、記録の無くなったロックファイルも削除する
        assert!(std::fs::symlink_metadata(&lock).is_err());
        std::fs::rename(&keep, &p).unwrap();
        std::fs::write(&lock, &record).unwrap(); // クラッシュ時は記録が残る
        let l = UdsListener::bind(&p).unwrap();
        let m = std::fs::symlink_metadata(&p).unwrap();
        // inode は tmpfs で再利用され得るため同一性比較に使わない。新 listener への接続成功で置換を確認する。
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

    /// 生存中の listener のパスは奪わず、既存 listener に副作用（accept queue への probe 接続）も
    /// 与えない（TASK-123.2）。
    #[test]
    fn plug12_live_listener_path_is_not_stolen_and_has_no_side_effect() {
        use std::time::Duration;
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let p = d.path().join("s.sock");
        let live = UdsListener::bind(&p).unwrap();
        for _ in 0..3 {
            let e = UdsListener::bind(&p).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::AlreadyExists);
        }
        assert!(std::fs::symlink_metadata(&p).is_ok());
        // 拒否された bind が probe 接続を残していないため、accept は接続なしで Timeout になる。
        let e = live.accept(Duration::from_millis(200)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        // 実クライアントは通常どおり接続できる。
        let _c = std::os::unix::net::UnixStream::connect(&p).unwrap();
        live.accept(Duration::from_secs(2)).unwrap();
    }

    /// 記録の無い socket（他実装・旧版）は生存中か判別できないため削除しない。失敗した bind は
    /// 作ったロックファイルを残さず、再試行しても socket は削除されない（PLUG-12・TASK-123.2）。
    #[test]
    fn plug12_unmanaged_socket_is_never_removed() {
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let p = d.path().join("s.sock");
        let _other = std::os::unix::net::UnixListener::bind(&p).unwrap();
        for _ in 0..2 {
            let e = UdsListener::bind(&p).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::AlreadyExists);
            assert!(std::fs::symlink_metadata(&p).is_ok());
            assert!(std::fs::symlink_metadata(d.path().join("s.sock.lock")).is_err());
        }
        // 生存中の別 listener へ接続できる（socket が削除・置換されていない）。
        std::os::unix::net::UnixStream::connect(&p).unwrap();
    }

    /// ロックファイルは listener の生存中だけ記録つきで存在し、記録が無くなれば（bind 失敗・正常終了）
    /// 削除される。socket 名ごとのロックファイルを溜めない（PLUG-12・TASK-123.2）。
    #[test]
    fn plug12_lock_file_exists_only_while_recorded() {
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let p = d.path().join("s.sock");
        let lock = d.path().join("s.sock.lock");
        let other = std::os::unix::net::UnixListener::bind(&p).unwrap();
        let e = UdsListener::bind(&p).unwrap_err(); // ロックを新規作成して失敗する
        assert_eq!(e.code(), PluginErrorCode::AlreadyExists);
        assert!(std::fs::symlink_metadata(&lock).is_err());
        drop(other);
        std::fs::remove_file(&p).unwrap();
        let l = UdsListener::bind(&p).unwrap();
        let ino = std::fs::symlink_metadata(&p).unwrap().ino();
        assert_eq!(
            recorded_ino(&std::fs::read_to_string(&lock).unwrap()),
            Some(ino)
        );
        drop(l);
        assert!(std::fs::symlink_metadata(&lock).is_err());
        assert!(std::fs::symlink_metadata(&p).is_err());
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, Vec::<std::ffi::OsString>::new());
    }

    /// 同じパスへの bind / 解放を複数スレッドで繰り返しても、同時に成功する listener は 1 つだけで、
    /// 失敗は `AlreadyExists` のみ。ロックファイルの削除と取得が競合しても排他が保たれる
    /// （PLUG-12・TASK-123.2）。
    #[test]
    fn plug12_concurrent_bind_and_release_keeps_exclusion() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let p = d.path().join("s.sock");
        let active = Arc::new(AtomicUsize::new(0));
        let bound = Arc::new(AtomicUsize::new(0));
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let (p, active, bound) = (p.clone(), active.clone(), bound.clone());
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        match UdsListener::bind(&p) {
                            Ok(l) => {
                                assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                                // 保持中は自分の listener へ接続できる（パスを奪われていない）。
                                let _c = std::os::unix::net::UnixStream::connect(l.path()).unwrap();
                                l.accept(std::time::Duration::from_secs(5)).unwrap();
                                bound.fetch_add(1, Ordering::SeqCst);
                                assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
                                drop(l);
                            }
                            Err(e) => assert_eq!(e.code(), PluginErrorCode::AlreadyExists),
                        }
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap();
        }
        assert!(bound.load(Ordering::SeqCst) >= 1);
        // 全員が解放した後は何も残らず、再 bind できる。
        assert!(std::fs::symlink_metadata(d.path().join("s.sock.lock")).is_err());
        UdsListener::bind(&p).unwrap();
    }

    /// stale socket を削除した後の再 bind が失敗しても、削除済み socket の記録を残さない。残すと
    /// inode 番号の再利用で別経路の socket を管理下と誤認し得る（PLUG-12・TASK-123.2）。
    #[test]
    fn plug12_record_is_cleared_when_recorded_socket_is_gone() {
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let p = d.path().join("s.sock");
        let lock = d.path().join("s.sock.lock");
        // クラッシュ後の残骸（記録つきロックと同一 inode の socket）を再現する。
        let first = UdsListener::bind(&p).unwrap();
        let record = std::fs::read(&lock).unwrap();
        assert!(record.starts_with(b"fcus2 "));
        let keep = d.path().join("s.keep");
        std::fs::hard_link(&p, &keep).unwrap();
        drop(first);
        std::fs::write(&lock, &record).unwrap();
        // 1) 記録した socket が既に無く、別経路の socket がある: 削除せず、古い記録は消える。
        let other = std::os::unix::net::UnixListener::bind(&p).unwrap();
        let e = UdsListener::bind(&p).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::AlreadyExists);
        // 一致しない記録は消去され、記録の無くなったロックファイルも残らない。
        assert!(std::fs::symlink_metadata(&lock).is_err());
        std::os::unix::net::UnixStream::connect(&p).unwrap();
        drop(other);
        std::fs::remove_file(&p).unwrap();
        // 2) 記録した socket も何も無い: bind は成功し、記録は新しい socket のものへ置き換わる。
        std::fs::write(&lock, &record).unwrap();
        let l = UdsListener::bind(&p).unwrap();
        let ino = std::fs::symlink_metadata(&p).unwrap().ino();
        let now = std::fs::read_to_string(&lock).unwrap();
        assert_eq!(recorded_ino(&now), Some(ino), "{now:?}");
        drop(l);
        // stale socket を削除した直後（再 bind の前）の消去は、公開 API からは観測できないため
        // `uds_security` の単体テスト `plug12_clear_stale_socket_clears_record_after_removal` で照合する。
        std::fs::remove_file(&keep).unwrap();
    }

    /// ロック名に FIFO がある場合、open で止まらずに `PermissionDenied` で拒否し、FIFO には触れない
    /// （PLUG-12・REPAIR-5・TASK-123.2）。
    #[test]
    fn plug12_fifo_at_lock_name_is_rejected_without_blocking() {
        use std::os::unix::fs::FileTypeExt;
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let p = d.path().join("s.sock");
        let fifo = d.path().join("s.sock.lock");
        let st = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(st.success());
        let (tx, rx) = std::sync::mpsc::channel();
        let path = p.clone();
        std::thread::spawn(move || {
            let _ = tx.send(UdsListener::bind(&path).map(|_| ()));
        });
        // 止まった場合は期限で失敗させる（ハングで CI を止めない）。
        let res = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("bind must not block on a FIFO lock path");
        assert_eq!(res.unwrap_err().code(), PluginErrorCode::PermissionDenied);
        assert!(
            std::fs::symlink_metadata(&fifo)
                .unwrap()
                .file_type()
                .is_fifo()
        );
        assert!(std::fs::symlink_metadata(&p).is_err());
    }

    /// 後始末で socket を unlink できなかった場合は記録を残し、次回の bind が stale として削除して
    /// 再 bind できる（記録を先に消すと以後常に AlreadyExists になる。PLUG-12・TASK-123.2）。
    #[test]
    fn plug12_record_survives_failed_unlink_and_allows_rebind() {
        use std::os::unix::fs::PermissionsExt;
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let p = d.path().join("s.sock");
        let lock = d.path().join("s.sock.lock");
        let first = UdsListener::bind(&p).unwrap();
        let m = std::fs::symlink_metadata(&p).unwrap();
        // dev の符号化は実装依存のため、接頭辞と ino・mtime（具体値）で照合する。
        let record = std::fs::read_to_string(&lock).unwrap();
        assert_eq!(recorded_ino(&record), Some(m.ino()), "{record:?}");
        assert!(
            record.ends_with(&format!(" {} {}\n", m.mtime(), m.mtime_nsec())),
            "{record:?}"
        );
        // ディレクトリを書き込み不可にして unlink を失敗させる（root は権限検査を受けないため対象外）。
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let unlink_blocked = std::fs::remove_file(&p).is_err();
        drop(first);
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        if !unlink_blocked {
            // root 実行: 上の remove_file が socket を消しており、失敗経路を再現できない。
            return;
        }
        assert_eq!(std::fs::symlink_metadata(&p).unwrap().ino(), m.ino());
        assert_eq!(std::fs::read_to_string(&lock).unwrap(), record);
        let l = UdsListener::bind(&p).unwrap();
        let _c = std::os::unix::net::UnixStream::connect(l.path()).unwrap();
        l.accept(std::time::Duration::from_secs(2)).unwrap();
    }

    /// 記録の無いロックファイルが残っていても（旧版・外部で作られた空ファイル）管理下の証拠に
    /// ならず、別経路が bind した socket は削除しない（PLUG-12・TASK-123.2）。
    #[test]
    fn plug12_leftover_lock_does_not_authorize_removing_foreign_socket() {
        let t = TempDir::new();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let p = d.path().join("s.sock");
        drop(UdsListener::bind(&p).unwrap());
        let _other = std::os::unix::net::UnixListener::bind(&p).unwrap();
        for _ in 0..2 {
            std::fs::write(d.path().join("s.sock.lock"), b"").unwrap();
            let e = UdsListener::bind(&p).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::AlreadyExists);
            assert!(std::fs::symlink_metadata(&p).is_ok());
        }
        // 生存中の別 listener へ接続できる（socket が削除・置換されていない）。
        std::os::unix::net::UnixStream::connect(&p).unwrap();
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
        // TMPDIR が長い環境でも境界を必ず構成できるよう、短い /tmp 配下を使う。
        let t = TempDir::new_short();
        let d = RuntimeDir::ensure_under(&t.0).unwrap();
        let base = d.path().as_os_str().len() + 1; // 区切り 1 バイト
        // 構成不能なら黙って成功させず失敗させる（テストの skip で CI を通さない）。
        assert!(
            base + 1 < SUN_PATH_CAPACITY,
            "cannot construct sun_path boundary: runtime dir too long ({base} bytes)"
        );
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

    /// PLUG-12・TASK-123.4: `from_env` は環境から基底を決め、Ok なら 0700 で bind でき、
    /// 基底が無ければ FailedPrecondition で止まる。環境変数は読むだけで書き換えない。
    /// macOS の CI は XDG 未設定・TMPDIR 設定済みのため、フォールバックの Ok 側が実際に通る。
    #[test]
    fn plug12_from_env_resolves_or_fails_closed() {
        let probe = TempDir::new();
        let uid = std::fs::metadata(&probe.0).unwrap().uid();
        let xdg = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty());
        let base: Option<PathBuf> = match &xdg {
            Some(v) => Some(PathBuf::from(v)),
            None if cfg!(target_os = "macos") => std::env::var_os("TMPDIR").map(PathBuf::from),
            None if cfg!(target_os = "linux") && uid == 0 => Some(PathBuf::from("/run")),
            None if cfg!(target_os = "linux") => Some(PathBuf::from(format!("/run/user/{uid}"))),
            None => None,
        };
        let result = RuntimeDir::from_env();
        match (&base, result) {
            (Some(b), Ok(d)) => {
                assert!(d.path().starts_with(std::fs::canonicalize(b).unwrap()));
                assert_eq!(d.path().file_name().unwrap(), RUNTIME_DIR_NAME);
                assert_eq!(mode_of(d.path()), 0o700);
                UdsListener::bind(&d.path().join("fromenv.sock")).unwrap();
                let _ = std::fs::remove_file(d.path().join("fromenv.sock"));
            }
            (Some(b), Err(e)) => {
                if xdg.is_none() && !b.exists() {
                    assert_eq!(e.code(), PluginErrorCode::FailedPrecondition);
                } else {
                    // 基底が存在するのに拒否される環境は、Linux の非標準構成のみ許容する。
                    assert!(
                        !cfg!(target_os = "macos") || xdg.is_some(),
                        "macOS fallback must resolve: {e:?}"
                    );
                    assert!(matches!(
                        e.code(),
                        PluginErrorCode::PermissionDenied | PluginErrorCode::NotFound
                    ));
                }
            }
            (None, Err(e)) => assert_eq!(e.code(), PluginErrorCode::FailedPrecondition),
            (None, Ok(_)) => panic!("no base expected but from_env succeeded"),
        }
    }
}
