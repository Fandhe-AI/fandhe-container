//! モード選択 API の結合試験（PLUG-7・REPAIR-5。TASK-110.3・#260）。
//! root・特権不要。待ちはすべて有限の期限付きで、CI の既定テスト集合で実行される。
//!
//! 同一の起動仕様に対し、常駐モードと都度起動モードを切り替えて呼び出せることを確認する。
//! plugin 役の子プロセスはテストバイナリ自身を `--exact unix::plugin_child_entry` で再実行して
//! 用意する（`lifecycle_resident.rs` と同方式。結合試験は別 crate のため harness を複製する）。

#[cfg(not(unix))]
#[test]
fn plug7_mode_selection_requires_unix_transport() {
    use fandhe_container_plugin::{Frame, PluginModeKind};
    use fandhe_container_plugin::{OneShotPlugin, PluginErrorCode, PluginMode, PluginSession};
    let exe = std::env::current_exe().unwrap();
    let dir = std::env::temp_dir();
    let plugin = OneShotPlugin::new(exe, vec![], dir).unwrap();
    let err = PluginSession::start(
        &plugin,
        PluginMode::resident(),
        &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
    )
    .unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::Unimplemented);
    let mut session = PluginSession::start(
        &plugin,
        PluginMode::one_shot(),
        &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
    )
    .unwrap();
    assert_eq!(session.mode(), PluginModeKind::OneShot);
    let err = session
        .call(
            &Frame::new(b"ping".to_vec()).unwrap(),
            &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
        )
        .unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::Unimplemented);
}

#[cfg(unix)]
mod unix {
    use fandhe_container_plugin::{
        Frame, OneShotPlugin, OneShotTermination, PLUGIN_SOCKET_ENV, PluginErrorCode, PluginMode,
        PluginModeKind, PluginSession, PluginSessionShutdown, RpcTimeout, UdsStream,
    };
    use std::ffi::OsString;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// ウォッチドッグの上限。CI ステップの timeout より短い。
    const WAIT: Duration = Duration::from_secs(25);

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(behavior: &str) -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcmd-{}-{}",
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
    /// 接続後は EOF（親が接続を閉じる）まで「要求 1 件 -> `pid=<pid> seq=<n>` を返信」を繰り返す。
    #[test]
    fn plugin_child_entry() {
        let Some(sock) = std::env::var_os(PLUGIN_SOCKET_ENV) else {
            return;
        };
        let sock = PathBuf::from(sock);
        let mut s = UdsStream::connect(
            &sock,
            Duration::from_secs(5),
            &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
        )
        .unwrap();
        let mut seq = 0u32;
        while s.read_frame(rpc(5000)).is_ok() {
            seq += 1;
            let body = format!("pid={} seq={seq}", std::process::id());
            s.write_frame(&Frame::new(body.into_bytes()).unwrap(), rpc(5000))
                .unwrap();
        }
    }

    fn plugin_for(dir: &TempDir) -> OneShotPlugin {
        let args: Vec<OsString> = ["--exact", "unix::plugin_child_entry", "--test-threads=1"]
            .iter()
            .map(OsString::from)
            .collect();
        OneShotPlugin::new(std::env::current_exe().unwrap(), args, dir.0.clone()).unwrap()
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

    /// 受入基準: 同一の起動仕様で、都度起動 -> 常駐 -> 都度起動と切り替えて呼び出せる。
    #[test]
    fn plug7_switch_between_resident_and_ondemand() {
        let dir = TempDir::new("respond");
        let plugin = plugin_for(&dir);
        let started = Instant::now();
        with_watchdog("mode switch", move || {
            let me = std::process::id();

            // 1. 都度起動: 呼び出しごとに新しいプロセスで、seq は毎回 1。
            let mut s = PluginSession::start(
                &plugin,
                PluginMode::one_shot(),
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
            .unwrap();
            assert_eq!(s.mode(), PluginModeKind::OneShot);
            let (a1, seq) = parse(
                &s.call(
                    &ping(),
                    &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
                )
                .unwrap()
                .into_response(),
            );
            assert_eq!(seq, 1);
            assert_process_gone(a1);
            no_socket_left(&dir);
            let out = s
                .call(
                    &ping(),
                    &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
                )
                .unwrap();
            // 都度起動の終了状況と stderr は統一 API でも保持される。
            assert_eq!(
                out.termination(),
                Some(OneShotTermination::Exited { code: Some(0) })
            );
            assert!(out.stderr().is_some());
            let (a2, seq) = parse(&out.into_response());
            assert_eq!(seq, 1);
            assert_ne!(a1, a2);
            assert_process_gone(a2);
            no_socket_left(&dir);
            match s.shutdown().unwrap() {
                PluginSessionShutdown::OneShot(sum) => {
                    assert_eq!(sum.calls(), 2);
                    assert_eq!(
                        sum.last_termination(),
                        Some(OneShotTermination::Exited { code: Some(0) })
                    );
                    assert!(sum.last_stderr().is_some());
                }
                other => panic!("unexpected shutdown: {other:?}"),
            }

            // 2. 常駐へ切替: 同一 pid で seq が 1, 2, 3。
            let mut s = PluginSession::start(
                &plugin,
                PluginMode::resident(),
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
            .unwrap();
            assert_eq!(s.mode(), PluginModeKind::Resident);
            let (b, seq) = parse(
                &s.call(
                    &ping(),
                    &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
                )
                .unwrap()
                .into_response(),
            );
            assert_eq!(seq, 1);
            assert_eq!(
                parse(
                    &s.call(
                        &ping(),
                        &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new()
                    )
                    .unwrap()
                    .into_response()
                ),
                (b, 2)
            );
            assert_eq!(
                parse(
                    &s.call(
                        &ping(),
                        &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new()
                    )
                    .unwrap()
                    .into_response()
                ),
                (b, 3)
            );
            assert!(b != me && b != a1 && b != a2);
            match s.shutdown().unwrap() {
                PluginSessionShutdown::Resident(done) => assert_eq!(
                    done.termination(),
                    OneShotTermination::Exited { code: Some(0) }
                ),
                other => panic!("unexpected shutdown: {other:?}"),
            }
            assert_process_gone(b);
            no_socket_left(&dir);

            // 3. 再び都度起動へ切替。
            let mut s = PluginSession::start(
                &plugin,
                PluginMode::one_shot(),
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
            .unwrap();
            let (c, seq) = parse(
                &s.call(
                    &ping(),
                    &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
                )
                .unwrap()
                .into_response(),
            );
            assert_eq!(seq, 1);
            assert_ne!(c, b);
            assert_process_gone(c);
            no_socket_left(&dir);
            assert!(matches!(
                s.shutdown().unwrap(),
                PluginSessionShutdown::OneShot(_)
            ));
        });
        assert!(started.elapsed() < WAIT);
    }

    /// REPAIR-4: 観測記録は両モードで同じ形で受け取れる（成功件数・モード・操作名）。
    #[test]
    fn plug7_mode_session_call_observed_records_both_modes() {
        let dir = TempDir::new("respond");
        let plugin = plugin_for(&dir);
        with_watchdog("observed", move || {
            for (mode, op) in [
                (PluginMode::one_shot(), "plugin.call_once"),
                (PluginMode::resident(), "plugin.resident_call"),
            ] {
                let kind = mode.kind();
                let mut s = PluginSession::start(
                    &plugin,
                    mode,
                    &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
                )
                .unwrap();
                let mut records = Vec::new();
                s.call_observed(
                    &ping(),
                    &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
                    &mut |r| records.push(r.clone()),
                )
                .unwrap();
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].mode, kind);
                assert_eq!(records[0].operation, op);
                assert!(records[0].success);
                assert_eq!(records[0].error_code, None);
                assert_eq!(records[0].stderr.is_some(), kind == PluginModeKind::OneShot);
                s.shutdown().unwrap();
            }
        });
    }

    /// 存在しない絶対パスは両モードとも NotFound の構造化エラーで、socket は残らない。
    #[test]
    fn plug7_mode_session_propagates_structured_errors() {
        let dir = TempDir::new("respond");
        let missing = dir.0.join("no-such-plugin");
        let plugin = OneShotPlugin::new(missing, vec![], dir.0.clone()).unwrap();

        let e = PluginSession::start(
            &plugin,
            PluginMode::resident(),
            &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
        )
        .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::NotFound);
        no_socket_left(&dir);

        let mut s = PluginSession::start(
            &plugin,
            PluginMode::one_shot(),
            &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
        )
        .unwrap();
        let e = s
            .call(
                &ping(),
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::NotFound);
        no_socket_left(&dir);
    }
}
