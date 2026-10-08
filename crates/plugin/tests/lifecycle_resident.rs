//! 常駐モードの結合試験（PLUG-7・REPAIR-5。TASK-110.2・#259）。
//! root・特権不要。待ちはすべて有限の期限付きで、CI の既定テスト集合で実行される。
//!
//! plugin 役の子プロセスはテストバイナリ自身を `--exact unix::plugin_child_entry` で再実行して
//! 用意する（`lifecycle_one_shot.rs` と同方式）。子の環境は `env_clear()` されるため、振る舞いは
//! socket ディレクトリ内の `behavior` ファイルで子へ伝える。

#[cfg(not(unix))]
#[test]
fn plug7_resident_requires_unix_transport() {
    use fandhe_container_plugin::{
        OneShotPlugin, PluginErrorCode, ResidentPlugin, ResidentStartTimeout,
    };
    let exe = std::env::current_exe().unwrap();
    let dir = std::env::temp_dir();
    let plugin = OneShotPlugin::new(exe, vec![], dir).unwrap();
    let err = ResidentPlugin::start(
        &plugin,
        ResidentStartTimeout::default(),
        &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
    )
    .unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::Unimplemented);
}

#[cfg(unix)]
mod unix {
    use fandhe_container_plugin::{
        Frame, OneShotPlugin, OneShotTermination, PLUGIN_SOCKET_ENV, PluginErrorCode,
        ResidentCallRecord, ResidentPlugin, ResidentStartTimeout, ResidentState, RpcTimeout,
        UdsStream,
    };
    use std::ffi::OsString;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// ウォッチドッグの上限。終了猶予（5 秒）を含む最長ケースより長く、CI ステップの timeout より短い。
    const WAIT: Duration = Duration::from_secs(25);

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(behavior: &str) -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcrs-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            std::fs::write(p.join("behavior"), behavior).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn with_watchdog<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        match rx.recv_timeout(WAIT) {
            Ok(v) => v,
            Err(_) => panic!("{what} hung: no result within {WAIT:?}"),
        }
    }

    fn rpc(ms: u64) -> RpcTimeout {
        RpcTimeout::new(Duration::from_millis(ms)).unwrap()
    }

    fn write_stderr(bytes: &[u8]) {
        use std::io::Write;
        let mut err = std::io::stderr().lock();
        err.write_all(bytes).unwrap();
        err.flush().unwrap();
    }

    /// 子プロセスの入口。通常のテスト実行（`PLUGIN_SOCKET_ENV` 未設定）では何もしない。
    /// 接続後は EOF（親が接続を閉じる）まで「要求 1 件 -> `pid=<pid> seq=<n>` を返信」を繰り返す。
    #[test]
    fn plugin_child_entry() {
        let Some(sock) = std::env::var_os(PLUGIN_SOCKET_ENV) else {
            return;
        };
        let sock = PathBuf::from(sock);
        let behavior = std::fs::read_to_string(sock.parent().unwrap().join("behavior")).unwrap();
        match behavior.as_str() {
            "exit_early" => {}
            "silent_no_connect" => std::thread::sleep(Duration::from_secs(60)),
            mode => {
                if mode == "stderr_small" || mode == "stderr_exit3_after_first" {
                    write_stderr(b"plugin-diagnostic\n");
                }
                let mut s = UdsStream::connect(
                    &sock,
                    Duration::from_secs(5),
                    &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
                )
                .unwrap();
                if mode == "silent_after_connect" {
                    std::thread::sleep(Duration::from_secs(60));
                    return;
                }
                let mut seq = 0u32;
                while s.read_frame(rpc(5000)).is_ok() {
                    seq += 1;
                    if mode == "exit3_on_second" && seq == 2 {
                        std::process::exit(3);
                    }
                    if mode == "exit0_on_second" && seq == 2 {
                        std::process::exit(0);
                    }
                    let body = format!("pid={} seq={seq}", std::process::id());
                    s.write_frame(&Frame::new(body.into_bytes()).unwrap(), rpc(5000))
                        .unwrap();
                    if mode == "exit_after_first" && seq == 1 {
                        return;
                    }
                    if (mode == "exit3_after_first" || mode == "stderr_exit3_after_first")
                        && seq == 1
                    {
                        std::process::exit(3);
                    }
                }
                if mode == "linger" {
                    std::thread::sleep(Duration::from_secs(60));
                }
            }
        }
    }

    fn plugin_for(dir: &TempDir) -> OneShotPlugin {
        let args: Vec<OsString> = ["--exact", "unix::plugin_child_entry", "--test-threads=1"]
            .iter()
            .map(OsString::from)
            .collect();
        OneShotPlugin::new(std::env::current_exe().unwrap(), args, dir.0.clone()).unwrap()
    }

    fn start(
        dir: &TempDir,
        ms: u64,
    ) -> Result<ResidentPlugin, fandhe_container_plugin::PluginError> {
        let plugin = plugin_for(dir);
        // Linux では plugin が PR_SET_PDEATHSIG で start を呼んだスレッドに結び付く（#1514・PLUG-7）。
        // セッションを返す都合上、start は別スレッドではなくテストスレッド上で呼び、ハング検出だけを
        // 監視スレッドに任せる（監視スレッドは完了通知を待ち、期限超過ならプロセスごと中断する）。
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let watcher = std::thread::spawn(move || {
            if let Err(mpsc::RecvTimeoutError::Timeout) = done_rx.recv_timeout(WAIT) {
                eprintln!("ResidentPlugin::start hung: no result within {WAIT:?}");
                std::process::abort();
            }
        });
        let mut audit = fandhe_container_plugin::JsonLinesPeerAuthObserver::new();
        let r = ResidentPlugin::start(
            &plugin,
            ResidentStartTimeout::new(Duration::from_millis(ms)).unwrap(),
            &mut audit,
        );
        drop(done_tx);
        watcher.join().unwrap();
        // 接続するのは spawn した子だけなので、peer 認証の拒否イベントは 0 件（PLUG-12・SEC-4）。
        assert_eq!(audit.drain_lines(), Vec::<String>::new());
        r
    }

    fn ping() -> Frame {
        Frame::new(b"ping".to_vec()).unwrap()
    }

    /// 応答 `pid=<pid> seq=<n>` を (pid, seq) へ分解する。
    fn parse(frame: &Frame) -> (u32, u32) {
        let text = std::str::from_utf8(frame.payload()).unwrap();
        let (pid, seq) = text.split_once(' ').unwrap();
        (
            pid.strip_prefix("pid=").unwrap().parse().unwrap(),
            seq.strip_prefix("seq=").unwrap().parse().unwrap(),
        )
    }

    fn assert_process_gone(pid: u32) {
        #[cfg(target_os = "linux")]
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "pid {pid}"
        );
        #[cfg(not(target_os = "linux"))]
        let _ = pid;
    }

    fn no_socket_left(dir: &TempDir) {
        let left: Vec<_> = std::fs::read_dir(&dir.0)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().ends_with(".sock"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    /// 受入基準 1: 1 つの常駐プロセスが複数リクエストを順次処理する（同一 pid・seq が 1, 2, 3, 4）。
    #[test]
    fn plug7_resident_handles_multiple_requests_sequentially() {
        let dir = TempDir::new("respond");
        let mut session = start(&dir, 5000).unwrap();
        // 接続確立後は socket が残らない（listener は即 drop される）。
        no_socket_left(&dir);
        assert_eq!(session.state(), ResidentState::Running);
        let child_pid = session.pid().unwrap();
        for expected_seq in 1..=4u32 {
            let resp = session.call(&ping(), rpc(5000)).unwrap();
            assert_eq!(parse(&resp), (child_pid, expected_seq));
        }
        assert_ne!(child_pid, std::process::id());
        let done = session.shutdown().unwrap();
        assert_eq!(
            done.termination(),
            OneShotTermination::Exited { code: Some(0) }
        );
        assert_process_gone(child_pid);
        no_socket_left(&dir);
    }

    /// 受入基準 2: 処理中の異常終了（2 回目の要求の受信後に exit 3）を構造化エラーで伝える。
    #[test]
    fn plug7_resident_detects_abnormal_exit_as_structured_error() {
        let dir = TempDir::new("exit3_on_second");
        let mut session = start(&dir, 5000).unwrap();
        let child_pid = session.pid().unwrap();
        assert_eq!(
            parse(&session.call(&ping(), rpc(5000)).unwrap()),
            (child_pid, 1)
        );
        let e = session.call(&ping(), rpc(5000)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(e.code().as_str(), "UNAVAILABLE");
        assert_eq!(
            e.message(),
            "resident plugin process exited unexpectedly with exit code 3"
        );
        assert_eq!(session.state(), ResidentState::Exited { code: Some(3) });
        assert_process_gone(child_pid);
    }

    /// 終了後の呼び出しは I/O せず FailedPrecondition。shutdown は終了状況を返す。
    #[test]
    fn plug7_resident_rejects_calls_after_plugin_died() {
        let dir = TempDir::new("exit3_on_second");
        let mut session = start(&dir, 5000).unwrap();
        session.call(&ping(), rpc(5000)).unwrap();
        let first = session.call(&ping(), rpc(5000)).unwrap_err();
        assert_eq!(first.code(), PluginErrorCode::Unavailable);
        let again = session.call(&ping(), rpc(5000)).unwrap_err();
        assert_eq!(again.code(), PluginErrorCode::FailedPrecondition);
        let e = session.shutdown().unwrap_err().into_error();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(
            e.message(),
            "resident plugin process exited unexpectedly with exit code 3"
        );
    }

    /// 最終応答後の異常終了は、shutdown が成功として返さず Unavailable にする（PLUG-7）。
    #[test]
    fn plug7_resident_shutdown_reports_abnormal_exit_after_last_response() {
        let dir = TempDir::new("exit3_after_first");
        let mut session = start(&dir, 5000).unwrap();
        session.call(&ping(), rpc(5000)).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let e = session.shutdown().unwrap_err().into_error();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(
            e.message(),
            "resident plugin process exited unexpectedly with exit code 3"
        );
    }

    /// 異常終了の shutdown 失敗でも、セッション全期間の stderr が結果に載り、読み取りスレッドが止まる。
    #[test]
    fn plug7_resident_shutdown_failure_still_returns_stderr() {
        let dir = TempDir::new("stderr_exit3_after_first");
        let mut session = start(&dir, 5000).unwrap();
        session.call(&ping(), rpc(5000)).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let failure = session.shutdown().unwrap_err();
        assert_eq!(failure.error().code(), PluginErrorCode::Unavailable);
        assert_eq!(failure.stderr().bytes(), b"plugin-diagnostic\n");
        assert_eq!(failure.stderr().total_bytes(), 18);
        assert!(failure.stderr().reader_stopped());
    }

    /// 通信失敗の後に子が終了コード 0 で終わった場合、元の通信エラーを Unavailable へ読み替えない。
    #[test]
    fn plug7_resident_keeps_original_error_when_child_exits_cleanly() {
        let dir = TempDir::new("exit0_on_second");
        let mut session = start(&dir, 5000).unwrap();
        session.call(&ping(), rpc(5000)).unwrap();
        let e = session.call(&ping(), rpc(5000)).unwrap_err();
        assert!(
            !e.message().contains("exited unexpectedly"),
            "{}",
            e.message()
        );
        assert_eq!(session.state(), ResidentState::Exited { code: Some(0) });
    }

    /// 呼び出し間で自発終了した子を、次の呼び出しの前に検知して Unavailable にする。
    #[test]
    fn plug7_resident_detects_exit_between_calls() {
        let dir = TempDir::new("exit_after_first");
        let mut session = start(&dir, 5000).unwrap();
        session.call(&ping(), rpc(5000)).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let e = session.call(&ping(), rpc(5000)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(session.state(), ResidentState::Exited { code: Some(0) });
    }

    /// 応答しない子は呼び出しの期限で Timeout になり、子は回収されセッションは終了状態になる。
    #[test]
    fn plug7_resident_call_times_out_and_reaps_silent_plugin() {
        let dir = TempDir::new("silent_after_connect");
        let mut session = start(&dir, 5000).unwrap();
        let child_pid = session.pid().unwrap();
        let started = Instant::now();
        let e = session.call(&ping(), rpc(500)).unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        assert_eq!(session.state(), ResidentState::Killed);
        assert_process_gone(child_pid);
        let again = session.call(&ping(), rpc(500)).unwrap_err();
        assert_eq!(again.code(), PluginErrorCode::FailedPrecondition);
    }

    /// 接続前に終了した子は、期限を待たず Unavailable になる。
    #[test]
    fn plug7_resident_start_fails_fast_when_plugin_exits_early() {
        let dir = TempDir::new("exit_early");
        let started = Instant::now();
        let e = start(&dir, 8000).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert!(started.elapsed() < Duration::from_secs(6));
        no_socket_left(&dir);
    }

    /// 接続しない子は起動の合計期限で Timeout になり、socket は残らない。
    #[test]
    fn plug7_resident_start_times_out_when_plugin_never_connects() {
        let dir = TempDir::new("silent_no_connect");
        let started = Instant::now();
        let e = start(&dir, 300).unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        assert!(elapsed >= Duration::from_millis(250), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        no_socket_left(&dir);
    }

    /// EOF 後も終了しない子は shutdown で強制終了され、プロセスが残らない。
    #[test]
    fn plug7_resident_shutdown_kills_lingering_plugin() {
        let dir = TempDir::new("linger");
        let mut session = start(&dir, 5000).unwrap();
        let child_pid = session.pid().unwrap();
        session.call(&ping(), rpc(5000)).unwrap();
        let done = with_watchdog("shutdown", move || session.shutdown());
        assert_eq!(done.unwrap().termination(), OneShotTermination::Killed);
        assert_process_gone(child_pid);
    }

    /// shutdown せずに破棄しても子が残らない。
    #[test]
    fn plug7_resident_drop_reaps_plugin() {
        let dir = TempDir::new("linger");
        let session = start(&dir, 5000).unwrap();
        let child_pid = session.pid().unwrap();
        drop(session);
        assert_process_gone(child_pid);
    }

    /// stderr はセッション全期間分が shutdown の結果で返る（上限つき・untrusted）。
    #[test]
    fn plug7_resident_shutdown_returns_bounded_stderr() {
        let dir = TempDir::new("stderr_small");
        let mut session = start(&dir, 5000).unwrap();
        session.call(&ping(), rpc(5000)).unwrap();
        let done = session.shutdown().unwrap();
        assert_eq!(done.stderr().bytes(), b"plugin-diagnostic\n");
        assert_eq!(done.stderr().total_bytes(), 18);
        assert!(!done.stderr().is_truncated());
        assert!(done.stderr().is_complete());
        assert!(done.stderr().reader_stopped());
    }

    /// REPAIR-4: 成功・失敗の双方で観測記録が 1 件ずつ渡される。
    #[test]
    fn repair4_resident_call_records_success_and_failure() {
        let dir = TempDir::new("exit_after_first");
        let mut session = start(&dir, 5000).unwrap();
        let mut records: Vec<ResidentCallRecord> = Vec::new();
        session
            .call_observed(&ping(), rpc(5000), &mut |r| records.push(r.clone()))
            .unwrap();
        let e = session
            .call_observed(&ping(), rpc(5000), &mut |r| records.push(r.clone()))
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].operation, "plugin.resident_call");
        assert!(records[0].success);
        assert_eq!(records[0].error_code, None);
        assert!(!records[1].success);
        assert_eq!(records[1].error_code, Some("UNAVAILABLE"));
    }

    /// 存在しない絶対パスは NotFound で、socket は残らない。
    #[test]
    fn plug7_resident_reports_missing_program() {
        let dir = TempDir::new("respond");
        let missing = dir.0.join("no-such-plugin");
        let plugin = OneShotPlugin::new(missing, vec![], dir.0.clone()).unwrap();
        let e = ResidentPlugin::start(
            &plugin,
            ResidentStartTimeout::default(),
            &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
        )
        .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::NotFound);
        no_socket_left(&dir);
    }
}
