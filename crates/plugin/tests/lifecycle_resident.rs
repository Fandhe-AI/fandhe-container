//! 常駐モードの結合試験（PLUG-7・REPAIR-5。TASK-110.2・#259）。
//! root・特権不要。待ちはすべて有限の期限付きで、CI の既定テスト集合で実行される。
//!
//! plugin 役の子プロセスはテストバイナリ自身を `--exact unix::plugin_child_entry` で再実行して
//! 用意する（`lifecycle_one_shot.rs` と同方式）。子の環境は `env_clear()` されるため、振る舞いは
//! socket ディレクトリ内の `behavior` ファイルで子へ伝える。

#[cfg(target_os = "linux")]
#[path = "support/swap.rs"]
mod swap;

/// 試験用: 実行中のテストバイナリ自身を起動対象にする（構築口を呼んでよいのは試験コードだけ。#1856）。
fn exe_target() -> fandhe_container_plugin::PluginLaunchTarget {
    let p = std::env::current_exe().unwrap();
    fandhe_container_plugin::PluginLaunchTarget::from_verified_file(
        std::fs::File::open(&p).unwrap(),
        p.clone(),
        p,
    )
    .unwrap()
}

#[cfg(not(unix))]
#[test]
fn plug7_resident_requires_unix_transport() {
    use fandhe_container_plugin::{
        PluginErrorCode, PluginLaunchSpec, ResidentPlugin, ResidentStartTimeout,
    };
    let dir = std::env::temp_dir();
    let plugin = PluginLaunchSpec::new(exe_target(), vec![], dir).unwrap();
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
        Frame, PLUGIN_SOCKET_ENV, PluginErrorCode, PluginLaunchSpec, PluginTermination,
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
            // 孫（`/bin/sleep 60`。stderr を引き継ぐ）を起動して pid をファイルへ書き、接続後に応答しない
            // （#1311。プロセスグループ単位の回収を確かめる）。pid ファイルは接続より前に書く。
            "grandchild_silent" => {
                #[allow(clippy::zombie_processes)]
                let gc = std::process::Command::new("/bin/sleep")
                    .arg("60")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .spawn()
                    .unwrap();
                let dir = sock.parent().unwrap();
                std::fs::write(dir.join("gc.tmp"), gc.id().to_string()).unwrap();
                std::fs::rename(dir.join("gc.tmp"), dir.join("grandchild.pid")).unwrap();
                let _s = UdsStream::connect(
                    &sock,
                    Duration::from_secs(5),
                    &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
                )
                .unwrap();
                std::thread::sleep(Duration::from_secs(60));
            }
            "silent_no_connect" => std::thread::sleep(Duration::from_secs(60)),
            mode => {
                if let Some(n) = mode.strip_prefix("decoys:") {
                    // 回収の確認用に自 pid を残してから、decoy を順に起動する。
                    let dir = sock.parent().unwrap();
                    std::fs::write(dir.join("child.pid"), std::process::id().to_string()).unwrap();
                    for _ in 0..n.parse::<u32>().unwrap() {
                        spawn_decoy_and_wait(&sock);
                    }
                }
                // 同じグループの孫を残して自発終了する plugin（#1604）。pid ファイルは接続より前に書く。
                if mode == "grandchild_exit_after_first" || mode == "grandchild_exit_on_eof" {
                    spawn_grandchild_and_record_pid(&sock);
                }
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
                    let body = if mode == "argv0" {
                        // 受け取った `argv[0]` を応答に載せる（起動対象の `exec_path` との照合用。#1856）。
                        use std::os::unix::ffi::OsStrExt;
                        let a0 = std::env::args_os().next().unwrap();
                        [b"argv0=".as_slice(), a0.as_bytes()].concat()
                    } else if mode == "env_dump" {
                        // 子の環境変数の全集合を `name=value` の改行区切りで応答する（#1858）。
                        use std::os::unix::ffi::OsStrExt;
                        let mut vars: Vec<_> = std::env::vars_os().collect();
                        vars.sort();
                        let mut out = Vec::new();
                        for (k, v) in vars {
                            out.extend_from_slice(k.as_bytes());
                            out.push(b'=');
                            out.extend_from_slice(v.as_bytes());
                            out.push(b'\n');
                        }
                        out
                    } else {
                        format!("pid={} seq={seq}", std::process::id()).into_bytes()
                    };
                    s.write_frame(&Frame::new(body).unwrap(), rpc(5000))
                        .unwrap();
                    if (mode == "exit_after_first" || mode == "grandchild_exit_after_first")
                        && seq == 1
                    {
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

    /// 孫（`/bin/sleep 60`。plugin と同じプロセスグループ。stdout・stderr は閉じる）を起動し、pid を
    /// `grandchild.pid` へ原子的に書く（#1604）。孫は wait しない。
    #[allow(clippy::zombie_processes)]
    fn spawn_grandchild_and_record_pid(sock: &std::path::Path) {
        let gc = std::process::Command::new("/bin/sleep")
            .arg("60")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let dir = sock.parent().unwrap();
        std::fs::write(dir.join("gc.tmp"), gc.id().to_string()).unwrap();
        std::fs::rename(dir.join("gc.tmp"), dir.join("grandchild.pid")).unwrap();
    }

    /// 孫が有限時間内に存在しなくなることを確かめる（REPAIR-5。Linux は `/proc`、macOS は `kill -0`）。
    fn assert_grandchild_gone(dir: &TempDir) {
        let pid: u32 = std::fs::read_to_string(dir.0.join("grandchild.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let t = Instant::now();
        while crate::is_alive(pid) {
            assert!(
                t.elapsed() < Duration::from_secs(5),
                "grandchild {pid} alive"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn plugin_for(dir: &TempDir) -> PluginLaunchSpec {
        let args: Vec<OsString> = ["--exact", "unix::plugin_child_entry", "--test-threads=1"]
            .iter()
            .map(OsString::from)
            .collect();
        PluginLaunchSpec::new(super::exe_target(), args, dir.0.clone()).unwrap()
    }

    fn start(
        dir: &TempDir,
        ms: u64,
    ) -> Result<ResidentPlugin, fandhe_container_plugin::PluginError> {
        start_plugin(plugin_for(dir), ms)
    }

    fn start_plugin(
        plugin: PluginLaunchSpec,
        ms: u64,
    ) -> Result<ResidentPlugin, fandhe_container_plugin::PluginError> {
        let (r, lines) = start_audited_plugin(plugin, ms);
        // 接続するのは spawn した子だけなので、peer 認証の拒否イベントは 0 件（PLUG-12・SEC-4）。
        assert_eq!(lines, Vec::<String>::new());
        r
    }

    /// 子プロセスと同じ UID の別プロセス（このテストバイナリの `decoy_entry`）を起動し、終了まで待つ。
    fn spawn_decoy_and_wait(sock: &std::path::Path) {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "unix::decoy_entry", "--test-threads=1"])
            .env("FCOS_DECOY_SOCK", sock)
            .env_remove(PLUGIN_SOCKET_ENV)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// decoy の入口。通常のテスト実行（`FCOS_DECOY_SOCK` 未設定）では何もしない。socket へ接続して
    /// 受付に切断されるのを待ってから終了する（接続自体の成否は問わない）。
    #[test]
    fn decoy_entry() {
        let Some(sock) = std::env::var_os("FCOS_DECOY_SOCK") else {
            return;
        };
        let Ok(mut s) = UdsStream::connect(
            std::path::Path::new(&sock),
            Duration::from_secs(5),
            &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
        ) else {
            return;
        };
        // 受付が peer の pid を読み終えて切断する（EOF・エラー）まで生存し続ける。先に終了すると
        // macOS の LOCAL_PEERPID 取得が失敗して pid 不一致として数えられない（#1861）。
        let mut buf = [0u8; 64];
        while matches!(std::io::Read::read(&mut s, &mut buf), Ok(n) if n > 0) {}
    }

    fn audit_fields(lines: &[String]) -> Vec<(String, String, String, String, u64)> {
        lines
            .iter()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                let s = |k: &str| v[k].as_str().unwrap().to_string();
                (
                    s("reason"),
                    s("code"),
                    s("op"),
                    s("outcome"),
                    v["expected_uid"].as_u64().unwrap(),
                )
            })
            .collect()
    }

    fn my_uid(dir: &TempDir) -> u64 {
        use std::os::unix::fs::MetadataExt;
        u64::from(std::fs::metadata(&dir.0).unwrap().uid())
    }

    fn recorded_child_pid(dir: &TempDir) -> u32 {
        std::fs::read_to_string(dir.0.join("child.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn start_audited(
        dir: &TempDir,
        ms: u64,
    ) -> (
        Result<ResidentPlugin, fandhe_container_plugin::PluginError>,
        Vec<String>,
    ) {
        start_audited_plugin(plugin_for(dir), ms)
    }

    fn start_audited_plugin(
        plugin: PluginLaunchSpec,
        ms: u64,
    ) -> (
        Result<ResidentPlugin, fandhe_container_plugin::PluginError>,
        Vec<String>,
    ) {
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
        (r, audit.drain_lines())
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

    /// 起動経路（`ResidentPlugin::start`）の受付は、別プロセス（同一 UID・別 pid）の接続を切断して待ち受けを
    /// 続け、正しい子へ接続できる。拒否 1 件につき監査イベント 1 件（PLUG-7・PLUG-12・SEC-4・#1861）。
    /// 別 UID は root なしに作れないため pid 不一致で同じ継続・合算の経路を通す（UID 固有の分岐は crate 内
    /// ユニットテスト `transport::tests::plug12_accept_peer_pid_*` が受け持つ）。
    #[test]
    fn plug12_resident_continues_accepting_after_rejected_peers() {
        let dir = TempDir::new("decoys:3");
        let (r, lines) = start_audited(&dir, 10000);
        let mut session = r.unwrap();
        let child_pid = session.pid().unwrap();
        assert_eq!(
            parse(&session.call(&ping(), rpc(5000)).unwrap()),
            (child_pid, 1)
        );
        let expected = (
            "peer_pid_mismatch".to_string(),
            "PERMISSION_DENIED".to_string(),
            "accept".to_string(),
            "error".to_string(),
            my_uid(&dir),
        );
        assert_eq!(audit_fields(&lines), vec![expected; 3]);
        session.shutdown().unwrap();
        assert_process_gone(child_pid);
        no_socket_left(&dir);
    }

    /// 拒否が上限を超えたら `PermissionDenied`。子は回収され、監査イベントは上限 + 1 件（PLUG-12・REPAIR-5）。
    #[test]
    fn plug12_resident_stops_when_rejections_exceed_limit() {
        let over = fandhe_container_plugin::transport::UDS_ACCEPT_PEER_REJECTION_LIMIT as usize + 1;
        let dir = TempDir::new(&format!("decoys:{}", over + 3));
        let (r, lines) = start_audited(&dir, 10000);
        let err = r.expect_err("start must fail");
        assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
        assert_eq!(err.message(), "too many rejected peer connections");
        let expected = (
            "peer_pid_mismatch".to_string(),
            "PERMISSION_DENIED".to_string(),
            "accept".to_string(),
            "error".to_string(),
            my_uid(&dir),
        );
        assert_eq!(audit_fields(&lines), vec![expected; over]);
        assert!(!crate::is_alive(recorded_child_pid(&dir)));
        no_socket_left(&dir);
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
            PluginTermination::Exited { code: Some(0) }
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

    /// #1604・PLUG-7・REPAIR-5: 呼び出し間で自発終了した plugin の孫も、次の `call` の生存確認が回収の前に
    /// グループへ送る `SIGKILL` で止まる。
    #[test]
    fn plug7_resident_call_stops_grandchild_of_self_exited_plugin() {
        let dir = TempDir::new("grandchild_exit_after_first");
        let mut session = start(&dir, 5000).unwrap();
        session.call(&ping(), rpc(5000)).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let e = session.call(&ping(), rpc(5000)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(session.state(), ResidentState::Exited { code: Some(0) });
        assert_grandchild_gone(&dir);
    }

    /// #1604・PLUG-7・REPAIR-5: EOF を受けて自発終了（終了コード 0）した plugin の孫も、`shutdown` で止まる。
    #[test]
    fn plug7_resident_shutdown_stops_grandchild_of_self_exited_plugin() {
        let dir = TempDir::new("grandchild_exit_on_eof");
        let mut session = start(&dir, 5000).unwrap();
        session.call(&ping(), rpc(5000)).unwrap();
        let done = session.shutdown().unwrap();
        assert_eq!(
            done.termination(),
            PluginTermination::Exited { code: Some(0) }
        );
        assert_grandchild_gone(&dir);
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

    /// #1311・PLUG-7: 呼び出しタイムアウト後の kill はプロセスグループ全体へ届き、孫も残らない。
    #[test]
    fn plug7_resident_call_timeout_kills_grandchild_process_group() {
        let dir = TempDir::new("grandchild_silent");
        let mut session = start(&dir, 5000).unwrap();
        let e = session.call(&ping(), rpc(500)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        assert_eq!(session.state(), ResidentState::Killed);
        let pid: u32 = std::fs::read_to_string(dir.0.join("grandchild.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let t = Instant::now();
        loop {
            let alive = crate::is_alive(pid);
            if !alive {
                break;
            }
            assert!(
                t.elapsed() < Duration::from_secs(5),
                "grandchild {pid} alive"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
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
        assert_eq!(done.unwrap().termination(), PluginTermination::Killed);
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

    /// 実行権の無いファイルの起動対象は PermissionDenied で、socket は残らない（ファイルを開けない＝起動対象を
    /// 作れないため、旧「存在しないプログラムは NotFound」の試験の置き換え。#1856）。
    #[test]
    fn plug7_resident_reports_non_executable_program() {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = TempDir::new("respond");
        let program = dir.0.join("not-executable");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&program)
            .and_then(|mut f| std::io::Write::write_all(&mut f, b"not a native executable\n"))
            .unwrap();
        let target = fandhe_container_plugin::PluginLaunchTarget::from_verified_file(
            std::fs::File::open(&program).unwrap(),
            program.clone(),
            program,
        )
        .unwrap();
        let plugin = PluginLaunchSpec::new(target, vec![], dir.0.clone()).unwrap();
        let e = ResidentPlugin::start(
            &plugin,
            ResidentStartTimeout::default(),
            &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
        )
        .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
        assert_eq!(e.message(), "permission denied spawning plugin program");
        no_socket_left(&dir);
    }

    fn env_dump(vars: Vec<(String, OsString)>) -> std::collections::BTreeMap<String, String> {
        let dir = TempDir::new("env_dump");
        let plugin = plugin_for(&dir).with_env(vars).unwrap();
        let mut session = start_plugin(plugin, 5000).unwrap();
        let resp = session.call(&ping(), rpc(5000)).unwrap();
        session.shutdown().unwrap();
        let map: std::collections::BTreeMap<String, String> = std::str::from_utf8(resp.payload())
            .unwrap()
            .lines()
            .map(|l| {
                let (k, v) = l.split_once('=').unwrap();
                (k.to_string(), v.to_string())
            })
            .collect();
        let sock = map.get(PLUGIN_SOCKET_ENV).unwrap();
        assert_eq!(
            std::path::Path::new(sock).parent().unwrap(),
            // 公開パスは配置ディレクトリの canonicalize 結果のため、期待側も同じ規則で正規化する
            // （macOS の `/var` → `/private/var`。PLUG-7・PLUG-12）。
            std::fs::canonicalize(&dir.0).unwrap().as_path()
        );
        map
    }

    /// 指定なしなら常駐 plugin の環境は socket の変数だけ（#1858・PLUG-7）。
    #[test]
    fn plug7_resident_env_default_is_socket_only() {
        assert!(std::env::var_os("PATH").is_some());
        let map = env_dump(vec![]);
        let keys: Vec<&str> = map.keys().map(String::as_str).collect();
        assert_eq!(keys, vec![PLUGIN_SOCKET_ENV]);
    }

    /// 明示した 2 件だけが socket の変数に加わって常駐 plugin へ渡る（#1858・PLUG-7）。
    #[test]
    fn plug7_resident_env_passes_explicit_vars_only() {
        assert!(std::env::var_os("HOME").is_some());
        let map = env_dump(vec![
            ("HOME".to_string(), OsString::from("/nonexistent/fcos-home")),
            ("FCOS_ENV_B".to_string(), OsString::from("beta value")),
        ]);
        let keys: Vec<&str> = map.keys().map(String::as_str).collect();
        assert_eq!(keys, vec![PLUGIN_SOCKET_ENV, "FCOS_ENV_B", "HOME"]);
        assert_eq!(map["HOME"], "/nonexistent/fcos-home");
        assert_eq!(map["FCOS_ENV_B"], "beta value");
    }

    /// plugin が受け取る `argv[0]` は起動対象の `exec_path`（Linux でも `/proc/self/fd/N` ではない。#1856）。
    #[test]
    fn plug11_resident_passes_exec_path_as_argv0() {
        let dir = TempDir::new("argv0");
        let mut session = start(&dir, 5000).unwrap();
        let resp = session.call(&ping(), rpc(5000)).unwrap();
        let expected = std::env::current_exe().unwrap();
        let mut want = b"argv0=".to_vec();
        want.extend_from_slice(std::os::unix::ffi::OsStrExt::as_bytes(expected.as_os_str()));
        assert_eq!(resp.payload(), want.as_slice());
        session.shutdown().unwrap();
    }

    /// 起動対象を作った後に元のパスを別の実行ファイルへ差し替えても、起動されるのは元の実体（Linux。
    /// fd の実体を実行する。#1856・PLUG-11）。
    #[cfg(target_os = "linux")]
    #[test]
    fn plug11_resident_runs_original_after_path_replaced() {
        let dir = TempDir::new("respond");
        let fx = crate::swap::Fixture::new();
        let args: Vec<OsString> = ["--exact", "unix::plugin_child_entry", "--test-threads=1"]
            .iter()
            .map(OsString::from)
            .collect();
        let plugin = PluginLaunchSpec::new(fx.target(), args, dir.0.clone()).unwrap();
        fx.replace_with_script();
        let mut session = start_plugin(plugin, 5000).unwrap();
        let child_pid = session.pid().unwrap();
        assert_eq!(
            parse(&session.call(&ping(), rpc(5000)).unwrap()),
            (child_pid, 1)
        );
        let done = session.shutdown().unwrap();
        assert_eq!(
            done.termination(),
            PluginTermination::Exited { code: Some(0) }
        );
        // 対照: 差し替え後のパスから新しく起動対象を作るとスクリプトとして拒否される。
        let err = fx.try_target_from_path().unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::InvalidArgument);
    }
}

/// 孫の生存確認（#1311）。Linux は `/proc/<pid>/stat` を読み、ゾンビ（`Z`）を終了済みとして扱う（pid 1 が
/// 回収しない開発コンテナ対応）。外部コマンド（procps の `kill`。開発コンテナの slim イメージに無い）に
/// 依存しない。呼び出し元は `mod unix` のみ。
#[cfg(target_os = "linux")]
fn is_alive(pid: u32) -> bool {
    // `pid (comm) state ...`。comm に空白や括弧を含み得るため、最後の ')' の後ろを見る。
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.trim_start().chars().next())
            .is_some_and(|state| state != 'Z')
    })
}

/// 孫の生存確認（#1311）。`/proc` の無い unix（macOS）は OS 標準の `/bin/kill -0` で確かめ、外部コマンドの
/// 待機にも期限を設ける（REPAIR-5）。呼び出し元は `mod unix` のみ。
#[cfg(all(unix, not(target_os = "linux")))]
fn is_alive(pid: u32) -> bool {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut child = Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kill");
    let start = Instant::now();
    loop {
        match child.try_wait().expect("try_wait") {
            Some(st) => return st.success(),
            None if start.elapsed() < Duration::from_secs(10) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            None => {
                let _ = child.kill();
                let reap = Instant::now();
                while reap.elapsed() < Duration::from_secs(2) {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                panic!("kill -0 timed out for pid {pid}");
            }
        }
    }
}
