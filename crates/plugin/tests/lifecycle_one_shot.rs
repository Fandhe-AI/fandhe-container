//! 都度起動モードの結合試験（PLUG-7・REPAIR-5。TASK-110.1・#258）。
//! root・特権不要。待ちはすべて有限の期限付きで、CI の既定テスト集合で実行される。
//!
//! plugin 役の子プロセスはテストバイナリ自身を `--exact unix::plugin_child_entry` で再実行して
//! 用意する。`call_once` は子の環境を `env_clear()` するため、振る舞いは socket ディレクトリ内の
//! `behavior` ファイルで子へ伝える。

#[cfg(not(unix))]
#[test]
fn plug7_one_shot_requires_unix_transport() {
    use fandhe_container_plugin::{
        Frame, OneShotPlugin, OneShotTimeout, PluginErrorCode, call_once,
    };
    let exe = std::env::current_exe().unwrap();
    let dir = std::env::temp_dir();
    let plugin = OneShotPlugin::new(exe, vec![], dir).unwrap();
    let req = Frame::new(b"ping".to_vec()).unwrap();
    let err = call_once(&plugin, &req, OneShotTimeout::default()).unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::Unimplemented);
}

#[cfg(unix)]
mod unix {
    use fandhe_container_plugin::{
        Frame, OneShotPlugin, OneShotTermination, OneShotTimeout, PLUGIN_SOCKET_ENV, PluginError,
        PluginErrorCode, RpcTimeout, UdsStream, call_once,
    };
    use std::ffi::OsString;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// ウォッチドッグの上限。終了猶予（5 秒）を含む最長ケースより長く、CI ステップの timeout より短い。
    const WAIT: Duration = Duration::from_secs(20);

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(behavior: &str) -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcos-{}-{}",
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

    /// 子プロセスの入口。通常のテスト実行（`PLUGIN_SOCKET_ENV` 未設定）では何もしない。
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
                let mut s = UdsStream::connect(&sock, Duration::from_secs(5)).unwrap();
                if mode == "silent_after_connect" {
                    std::thread::sleep(Duration::from_secs(60));
                    return;
                }
                let _req = s.read_frame(rpc(5000)).unwrap();
                let body = format!("pid={}", std::process::id());
                s.write_frame(&Frame::new(body.into_bytes()).unwrap(), rpc(5000))
                    .unwrap();
                if mode == "linger" {
                    std::thread::sleep(Duration::from_secs(60));
                }
                if mode == "exit_nonzero" {
                    std::process::exit(3);
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

    fn run(
        behavior: &str,
        ms: u64,
    ) -> (
        Result<fandhe_container_plugin::OneShotOutcome, PluginError>,
        Duration,
        TempDir,
    ) {
        let dir = TempDir::new(behavior);
        let plugin = plugin_for(&dir);
        let (res, elapsed) = with_watchdog("call_once", move || {
            let req = Frame::new(b"ping".to_vec()).unwrap();
            let start = Instant::now();
            let r = call_once(
                &plugin,
                &req,
                OneShotTimeout::new(Duration::from_millis(ms)).unwrap(),
            );
            (r, start.elapsed())
        });
        (res, elapsed, dir)
    }

    fn pid_of(payload: &[u8]) -> u32 {
        std::str::from_utf8(payload)
            .unwrap()
            .strip_prefix("pid=")
            .unwrap()
            .parse()
            .unwrap()
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

    /// 正常系と受入基準 2（処理完了後に plugin プロセスが終了している）。
    #[test]
    fn plug7_one_shot_responds_and_process_exits() {
        let (res, _, dir) = run("respond", 5000);
        let out = res.unwrap();
        assert_eq!(
            out.termination(),
            OneShotTermination::Exited { code: Some(0) }
        );
        let pid = pid_of(out.response().payload());
        assert_ne!(pid, std::process::id());
        assert_process_gone(pid);
        no_socket_left(&dir);
    }

    /// 受入基準 1: 接続しない子は合計期限で Timeout になり、子は回収される。
    #[test]
    fn plug7_one_shot_times_out_when_plugin_never_connects() {
        let (res, elapsed, dir) = run("silent_no_connect", 300);
        assert_eq!(res.unwrap_err().code(), PluginErrorCode::Timeout);
        assert!(elapsed >= Duration::from_millis(250), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        no_socket_left(&dir);
    }

    /// 受入基準 1: 接続後に応答しない子も合計期限で Timeout になる。
    #[test]
    fn plug7_one_shot_times_out_when_plugin_never_responds() {
        let (res, elapsed, _dir) = run("silent_after_connect", 1500);
        assert_eq!(res.unwrap_err().code(), PluginErrorCode::Timeout);
        assert!(elapsed < Duration::from_secs(8), "{elapsed:?}");
    }

    /// 接続前に終了した子は、期限を待たず Unavailable になる。
    #[test]
    fn plug7_one_shot_fails_fast_when_plugin_exits_early() {
        let (res, elapsed, _dir) = run("exit_early", 8000);
        assert_eq!(res.unwrap_err().code(), PluginErrorCode::Unavailable);
        assert!(elapsed < Duration::from_secs(6), "{elapsed:?}");
    }

    /// 応答後も終了しない子は強制終了され、プロセスが残らない。
    #[test]
    fn plug7_one_shot_kills_plugin_that_lingers_after_response() {
        let (res, _, _dir) = run("linger", 5000);
        let out = res.unwrap();
        assert_eq!(out.termination(), OneShotTermination::Killed);
        assert_process_gone(pid_of(out.response().payload()));
    }

    /// 応答後に非ゼロ終了した子は成功扱いにせず Unavailable（REPAIR-5・PLUG-7）。
    #[test]
    fn plug7_one_shot_rejects_nonzero_exit_after_response() {
        let (res, _, _dir) = run("exit_nonzero", 5000);
        let e = res.unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
    }

    /// 存在しない絶対パスは NotFound。
    #[test]
    fn plug7_one_shot_reports_missing_program() {
        let dir = TempDir::new("respond");
        let missing = dir.0.join("no-such-plugin");
        let plugin = OneShotPlugin::new(missing, vec![], dir.0.clone()).unwrap();
        let req = Frame::new(b"ping".to_vec()).unwrap();
        let err = call_once(&plugin, &req, OneShotTimeout::default()).unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::NotFound);
        no_socket_left(&dir);
    }
}
