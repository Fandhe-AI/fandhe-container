//! 異常終了で残った都度起動の socket とロックファイルの掃除の結合試験
//! （#1310・PLUG-7・PLUG-12・REPAIR-5）。root・特権不要。待ちはすべて有限の期限付き。
//!
//! 異常終了役の子プロセスはテストバイナリ自身を `--exact unix::sweep_child_entry` で再実行して
//! 用意し、親が SIGKILL（`Child::kill`）で止めて残骸を作る。

#[cfg(not(unix))]
#[test]
fn plug7_sweep_requires_unix_transport() {
    use fandhe_container_plugin::{PluginErrorCode, RuntimeDir};
    let err = RuntimeDir::ensure_under(&std::env::temp_dir()).unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::Unimplemented);
}

#[cfg(unix)]
mod unix {
    use fandhe_container_plugin::{
        ONE_SHOT_SWEEP_MAX_ENTRIES, OneShotSweep, RuntimeDir, UdsListener,
    };
    use std::os::unix::fs::{DirBuilderExt, symlink};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    /// 子へ基底ディレクトリを渡すテスト専用の環境変数。
    const BASE_ENV: &str = "FCSW_BASE";
    /// 子が bind 後に基底直下へ書く準備完了マーカー名。
    const READY: &str = "ready";
    /// 子の準備完了を待つ上限。
    const READY_WAIT: Duration = Duration::from_secs(15);

    /// 0700 の基底ディレクトリ（`RuntimeDir::ensure_under` が要求する group / other 書き込み不可）。
    struct Base(PathBuf);
    impl Base {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcsw-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Base {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// runtime directory 内の `oneshot-` で始まるエントリ数。
    fn oneshot_entries(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("oneshot-")
            })
            .count()
    }

    /// 子プロセスの入口。通常のテスト実行（`BASE_ENV` 未設定）では何もしない。
    /// 2 つの都度起動名で bind し、準備完了を知らせて待機する（親が SIGKILL で止める）。
    #[test]
    fn sweep_child_entry() {
        let Some(base) = std::env::var_os(BASE_ENV) else {
            return;
        };
        let base = PathBuf::from(base);
        let rd = RuntimeDir::ensure_under(&base).unwrap();
        let pid = std::process::id();
        let _l0 = UdsListener::bind(&rd.path().join(format!("oneshot-{pid}-0.sock"))).unwrap();
        let _l1 = UdsListener::bind(&rd.path().join(format!("oneshot-{pid}-1.sock"))).unwrap();
        std::fs::write(base.join(READY), b"ok").unwrap();
        std::thread::sleep(Duration::from_secs(60));
    }

    /// 子を起動して bind させ、SIGKILL で止めて残骸を作る。`rd` は子の起動前に解決しておく。
    fn leave_leftovers_by_sigkill(base: &Base) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "unix::sweep_child_entry", "--test-threads=1"])
            .env(BASE_ENV, &base.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + READY_WAIT;
        while !base.0.join(READY).exists() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child did not become ready within {READY_WAIT:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // unix の `kill` は SIGKILL。listener の後始末（drop）は走らない。
        child.kill().unwrap();
        child.wait().unwrap();
    }

    /// 記録つきロックファイルを手で作る（実在しない同一性。socket とは一致しない）。
    fn write_foreign_record(path: &Path) {
        std::fs::write(path, "fcus2 1 2 3 4\n").unwrap();
    }

    /// AC1・PLUG-7: SIGKILL された子の socket とロックが、次の初期化（`ensure_under`）で消える。
    #[test]
    fn plug7_initialization_removes_leftovers_after_sigkill() {
        let base = Base::new();
        let rd = RuntimeDir::ensure_under(&base.0).unwrap();
        leave_leftovers_by_sigkill(&base);
        // socket 2 つ + ロックファイル 2 つ。
        assert_eq!(oneshot_entries(rd.path()), 4);
        let again = RuntimeDir::ensure_under(&base.0).unwrap();
        assert_eq!(oneshot_entries(again.path()), 0);
    }

    /// AC1・PLUG-7: 公開メソッドは削除件数（具体値）を返す。
    #[test]
    fn plug7_sweep_reports_removed_count_after_sigkill() {
        let base = Base::new();
        let rd = RuntimeDir::ensure_under(&base.0).unwrap();
        leave_leftovers_by_sigkill(&base);
        assert_eq!(oneshot_entries(rd.path()), 4);
        let r = rd.sweep_one_shot_leftovers().unwrap();
        assert_eq!(r.removed, 2);
        assert_eq!(r.in_use, 0);
        assert_eq!(r.skipped, 0);
        assert!(!r.truncated);
        assert_eq!(oneshot_entries(rd.path()), 0);
        // 掃除済みなら 2 回目は何も削除しない。
        assert_eq!(rd.sweep_one_shot_leftovers().unwrap().removed, 0);
    }

    /// AC2・PLUG-12: 記録の無い socket は、ロックファイルがあってもなくても削除しない。
    #[test]
    fn plug12_sweep_keeps_unmanaged_sockets() {
        let base = Base::new();
        let rd = RuntimeDir::ensure_under(&base.0).unwrap();
        let with_lock = rd.path().join("oneshot-9-0.sock");
        let without_lock = rd.path().join("oneshot-9-1.sock");
        drop(UnixListener::bind(&with_lock).unwrap());
        drop(UnixListener::bind(&without_lock).unwrap());
        std::fs::write(rd.path().join("oneshot-9-0.sock.lock"), b"").unwrap();
        let r = rd.sweep_one_shot_leftovers().unwrap();
        assert_eq!(r.removed, 0);
        assert!(with_lock.exists());
        assert!(without_lock.exists());
    }

    /// AC2・PLUG-12: symlink は、記録つきロックがあってもリンクもリンク先も触らない。
    #[test]
    fn plug12_sweep_keeps_symlink_and_target() {
        let base = Base::new();
        let rd = RuntimeDir::ensure_under(&base.0).unwrap();
        let victim = base.0.join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let link = rd.path().join("oneshot-9-2.sock");
        symlink(&victim, &link).unwrap();
        write_foreign_record(&rd.path().join("oneshot-9-2.sock.lock"));
        let r = rd.sweep_one_shot_leftovers().unwrap();
        assert_eq!(r.removed, 0);
        assert_eq!(r.skipped, 1);
        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    }

    /// AC2・PLUG-12: 別の同一性を記録したロックでは、socket を削除しない。
    #[test]
    fn plug12_sweep_keeps_socket_with_mismatched_record() {
        let base = Base::new();
        let rd = RuntimeDir::ensure_under(&base.0).unwrap();
        let sock = rd.path().join("oneshot-9-3.sock");
        drop(UnixListener::bind(&sock).unwrap());
        let lock = rd.path().join("oneshot-9-3.sock.lock");
        write_foreign_record(&lock);
        let r = rd.sweep_one_shot_leftovers().unwrap();
        assert_eq!(r.removed, 0);
        assert_eq!(r.skipped, 1);
        assert!(sock.exists());
    }

    /// AC3・PLUG-7: 使用中（生存中の listener がロックを保持）の socket は削除せず、接続も受けられる。
    #[test]
    fn plug7_sweep_keeps_socket_in_use() {
        let base = Base::new();
        let rd = RuntimeDir::ensure_under(&base.0).unwrap();
        let path = rd
            .path()
            .join(format!("oneshot-{}-7.sock", std::process::id()));
        let listener = UdsListener::bind(&path).unwrap();
        let r = rd.sweep_one_shot_leftovers().unwrap();
        assert_eq!(r.in_use, 1);
        assert_eq!(r.removed, 0);
        assert!(path.exists());
        // 掃除後も同じ listener へ接続できる。
        let _client = UnixStream::connect(&path).unwrap();
        drop(listener);
    }

    /// 対象外の名前（`resident-*`・その他）は、ロックファイルがあっても触らない。
    #[test]
    fn plug7_sweep_ignores_other_names() {
        let base = Base::new();
        let rd = RuntimeDir::ensure_under(&base.0).unwrap();
        for name in ["resident-1-0.sock", "s.sock"] {
            drop(UnixListener::bind(rd.path().join(name)).unwrap());
            write_foreign_record(&rd.path().join(format!("{name}.lock")));
        }
        let r = rd.sweep_one_shot_leftovers().unwrap();
        assert_eq!(r.removed, 0);
        assert_eq!(r.skipped, 0);
        for name in ["resident-1-0.sock", "s.sock"] {
            assert!(rd.path().join(name).exists(), "{name}");
            assert_eq!(
                std::fs::read(rd.path().join(format!("{name}.lock"))).unwrap(),
                b"fcus2 1 2 3 4\n"
            );
        }
    }

    /// REPAIR-5: 候補の件数は上限で打ち切り、対象外の名前は件数に数えない。
    #[test]
    fn repair5_sweep_stops_at_candidate_limit() {
        let base = Base::new();
        let rd = RuntimeDir::ensure_under(&base.0).unwrap();
        for i in 0..=ONE_SHOT_SWEEP_MAX_ENTRIES {
            std::fs::write(rd.path().join(format!("other-{i}")), b"").unwrap();
        }
        let r: OneShotSweep = rd.sweep_one_shot_leftovers().unwrap();
        assert_eq!(r.examined, 0);
        assert!(!r.truncated);
        for i in 0..=ONE_SHOT_SWEEP_MAX_ENTRIES {
            std::fs::write(rd.path().join(format!("oneshot-1-{i}.sock.lock")), b"").unwrap();
        }
        let r = rd.sweep_one_shot_leftovers().unwrap();
        assert_eq!(r.examined as usize, ONE_SHOT_SWEEP_MAX_ENTRIES);
        assert!(r.truncated);
        assert_eq!(r.removed, 0);
    }
}
