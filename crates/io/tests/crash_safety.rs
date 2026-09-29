//! SIGKILL 耐性テスト（IO-3・TASK-18）の結合試験の最小スケルトン（TASK-18.1.1・#825）。
//!
//! `tests/bin/crash_test_server.rs`（専用 feature `crash-test-server` でのみビルドされる
//! テスト用サーバー）を子プロセスとして起動できること、および SIGKILL で強制終了できることを
//! 確かめる。ACK の観測・無効試行の除外（#826）、フラッシュ済み / 未フラッシュの対照ケース
//! （#95）は後続 issue で追加する（現時点は未実装。REPAIR-3）。
//! Windows など UDS 未対応 OS では、未対応終了コード 5 を返すことだけを確かめる。

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use std::io::{BufRead, BufReader, Read};
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const READY_WAIT: Duration = Duration::from_secs(10);
    const EXIT_WAIT: Duration = Duration::from_secs(15);

    /// 短いパスの 0700 一時ディレクトリ（macOS の sun_path 上限 104 バイト対策。`tests/server.rs` と同方針）。
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("fcio-cs-{}-{tag}", std::process::id()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .expect("must be able to create a temp dir");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("must be able to force mode 0700 regardless of umask");
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// 失敗時も孤児を残さないよう Drop で kill + wait する。
    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn spawn_server(dir: &TempDir) -> ChildGuard {
        let child = Command::new(env!("CARGO_BIN_EXE_crash_test_server"))
            .arg("--socket")
            .arg(dir.0.join("s.sock"))
            .arg("--data-dir")
            .arg(&dir.0)
            .arg("--file")
            .arg("data.bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("crash_test_server must spawn");
        ChildGuard(child)
    }

    /// stdout の `READY` 行を期限付きで待つ。
    fn wait_ready(child: &mut ChildGuard) {
        let stdout = child.0.stdout.take().expect("stdout must be piped");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        let line = rx
            .recv_timeout(READY_WAIT)
            .expect("READY line must arrive within the deadline");
        assert_eq!(line.trim_end(), "READY");
    }

    fn wait_exit(child: &mut ChildGuard) -> ExitStatus {
        let deadline = Instant::now() + EXIT_WAIT;
        loop {
            if let Some(status) = child.0.try_wait().expect("try_wait must succeed") {
                return status;
            }
            assert!(Instant::now() < deadline, "child must exit within deadline");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// IO-3・TASK-18.1.1: 子プロセスとして起動でき、接続して切断すると終了コード 0 で終わる。
    #[test]
    fn io3_crash_test_server_spawns_and_accepts() {
        let dir = TempDir::new("ok");
        let mut child = spawn_server(&dir);
        wait_ready(&mut child);
        drop(UnixStream::connect(dir.0.join("s.sock")).expect("connect must succeed"));
        let status = wait_exit(&mut child);
        let mut stderr = String::new();
        child
            .0
            .stderr
            .take()
            .expect("stderr must be piped")
            .read_to_string(&mut stderr)
            .expect("stderr must be readable");
        assert_eq!(status.code(), Some(0), "stderr: {stderr}");
        assert!(
            stderr.contains("\"code\":\"UNAVAILABLE\""),
            "stderr: {stderr}"
        );
    }

    /// IO-3・TASK-18.1.1: READY 後に SIGKILL で強制終了できる（シグナル 9）。
    #[test]
    fn io3_crash_test_server_can_be_sigkilled() {
        let dir = TempDir::new("kill");
        let mut child = spawn_server(&dir);
        wait_ready(&mut child);
        child.0.kill().expect("kill (SIGKILL) must succeed");
        let status = wait_exit(&mut child);
        assert_eq!(status.signal(), Some(9));
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod other {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// 子プロセス終了の待機上限（REPAIR-5: 相手の応答を待つ処理には期限を設ける）。
    const EXIT_WAIT: Duration = Duration::from_secs(15);

    /// IO-3・TASK-18.1.1: UDS 未対応 OS では終了コード 5 と UNIMPLEMENTED を返す。
    #[test]
    fn io3_crash_test_server_reports_unsupported_platform() {
        let mut child = Command::new(env!("CARGO_BIN_EXE_crash_test_server"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("crash_test_server must spawn");
        // 期限付きの try_wait ループ。超過時は kill + wait して孤児とハングを防ぐ
        let deadline = Instant::now() + EXIT_WAIT;
        let status = loop {
            if let Some(status) = child.try_wait().expect("try_wait must succeed") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("crash_test_server must exit within the deadline");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .expect("stderr must be piped")
            .read_to_string(&mut stderr)
            .expect("stderr must be readable");
        assert_eq!(status.code(), Some(5), "stderr: {stderr}");
        assert!(stderr.contains("UNIMPLEMENTED"), "stderr: {stderr}");
    }
}
