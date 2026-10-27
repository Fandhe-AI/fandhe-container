//! 都度起動モードの結合試験（PLUG-7・REPAIR-5。TASK-110.1・#258）。
//! root・特権不要。待ちはすべて有限の期限付きで、CI の既定テスト集合で実行される。
//!
//! plugin 役の子プロセスはテストバイナリ自身を `--exact unix::plugin_child_entry` で再実行して
//! 用意する。`call_once` は子の環境を `env_clear()` するため、振る舞いは socket ディレクトリ内の
//! `behavior` ファイルで子へ伝える。

#[cfg(unix)]
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
fn plug7_one_shot_requires_unix_transport() {
    use fandhe_container_plugin::{
        Frame, OneShotTimeout, PluginErrorCode, PluginLaunchSpec, call_once,
    };
    let dir = std::env::temp_dir();
    let plugin = PluginLaunchSpec::new(exe_target(), vec![], dir).unwrap();
    let req = Frame::new(b"ping".to_vec()).unwrap();
    let err = call_once(
        &plugin,
        &req,
        OneShotTimeout::default(),
        &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
    )
    .unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::Unimplemented);
}

#[cfg(unix)]
mod unix {
    use fandhe_container_plugin::{
        Frame, OneShotRecord, OneShotTimeout, PLUGIN_SOCKET_ENV, PLUGIN_STDERR_MAX_BYTES,
        PluginError, PluginErrorCode, PluginLaunchSpec, PluginTermination, RpcTimeout, UdsStream,
        call_once, call_once_observed,
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

    /// stderr 大量出力ケースで子が書くバイト数（1 MiB。Linux・macOS のソケットバッファより大きい）。
    const FLOOD_BYTES: usize = 1024 * 1024;

    /// 子の stderr へ直接書く（`eprint!` は libtest の出力捕捉に入るため使わない）。
    fn write_stderr(bytes: &[u8]) {
        use std::io::Write;
        let mut err = std::io::stderr().lock();
        err.write_all(bytes).unwrap();
        err.flush().unwrap();
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
            "stderr_exit_early" => write_stderr(b"boom: cannot start\n"),
            // 孫（`/bin/sleep 60`。stderr を引き継ぐ）を起動し、pid をファイルへ書いてから、接続後に
            // 応答せず待つ（#1311。プロセスグループ単位の回収を確かめる）。
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
            // 孫（`/bin/sleep 60`。同じプロセスグループ）を起動して pid をファイルへ書き、接続前に自発終了する
            // （`check_child` 経路。#1604）。
            "grandchild_exit_early" => spawn_grandchild_and_record_pid(&sock),
            "silent_no_connect" => std::thread::sleep(Duration::from_secs(60)),
            mode => {
                // 同一 UID の別プロセス（decoy）に、接続して切断させてから本来の接続へ進む
                // （受付は別 pid の接続を切断して待ち受けを続ける。#1861）。
                if let Some(n) = mode.strip_prefix("decoys:") {
                    // 回収の確認用に自 pid を残してから、decoy を順に起動する。
                    let dir = sock.parent().unwrap();
                    std::fs::write(dir.join("child.pid"), std::process::id().to_string()).unwrap();
                    for _ in 0..n.parse::<u32>().unwrap() {
                        spawn_decoy_and_wait(&sock);
                    }
                }
                // 接続前に書く。親が stderr を読み続けていなければバッファが埋まって子はここで止まる。
                if mode == "stderr_flood" {
                    write_stderr(&vec![b'x'; FLOOD_BYTES]);
                }
                if mode == "stderr_small" {
                    write_stderr(b"plugin-diagnostic\n");
                }
                // stderr を引き継いだ孫プロセスを残したまま応答して終了する（孫は 5 秒で自然終了）。
                // この子はすぐ終了するため孫は wait しない（孫は init に引き取られ、終了後に回収される）。
                // 孫は `process_group(0)` で plugin のグループの外へ出す。自発終了後のグループ停止（#1604）は
                // 同じグループの孫を止めるため、stderr を保持し続ける状況（REPAIR-5 の打ち切り）を保つには
                // グループ外が要る。グループを抜けた孫は対象外（`lifecycle` のモジュール doc）。
                #[allow(clippy::zombie_processes)]
                if mode == "stderr_held_by_grandchild" {
                    use std::os::unix::process::CommandExt;
                    std::process::Command::new("/bin/sleep")
                        .arg("5")
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .process_group(0)
                        .spawn()
                        .unwrap();
                }
                // 同じグループの孫を残して応答し、自発終了する（#1604）。
                if mode == "grandchild_then_exit" {
                    spawn_grandchild_and_record_pid(&sock);
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
                let _req = s.read_frame(rpc(5000)).unwrap();
                // 要求を受け取った後、応答せずに終了する（応答前に plugin が落ちる最頻の失敗経路。#1311）。
                if mode == "exit_after_request" {
                    return;
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
                    format!("pid={}", std::process::id()).into_bytes()
                };
                s.write_frame(&Frame::new(body).unwrap(), rpc(5000))
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

    /// 孫（`/bin/sleep 60`。plugin と同じプロセスグループ。stdout・stderr は閉じる）を起動し、pid を
    /// `grandchild.pid` へ原子的に書く（#1604）。孫は wait せず、plugin の終了後は init に引き取られる。
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

    fn grandchild_pid(dir: &TempDir) -> u32 {
        std::fs::read_to_string(dir.0.join("grandchild.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn plugin_for(dir: &TempDir) -> PluginLaunchSpec {
        let args: Vec<OsString> = ["--exact", "unix::plugin_child_entry", "--test-threads=1"]
            .iter()
            .map(OsString::from)
            .collect();
        PluginLaunchSpec::new(super::exe_target(), args, dir.0.clone()).unwrap()
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
            let mut audit = fandhe_container_plugin::JsonLinesPeerAuthObserver::new();
            let r = call_once(
                &plugin,
                &req,
                OneShotTimeout::new(Duration::from_millis(ms)).unwrap(),
                &mut audit,
            );
            let elapsed = start.elapsed();
            // 接続するのは spawn した子だけなので、peer 認証の拒否イベントは 0 件（PLUG-12・SEC-4）。
            assert_eq!(audit.drain_lines(), Vec::<String>::new());
            (r, elapsed)
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

    /// 孫が有限時間内に存在しなくなる（init に引き取られ回収されるまでの猶予を見る）ことを確かめる。
    /// Linux ではゾンビ（`Z`）も消滅として扱う（pid 1 が回収しない開発コンテナ対応）。
    fn assert_process_gone_within(pid: u32, limit: Duration) {
        let start = Instant::now();
        loop {
            let alive = crate::is_alive(pid);
            if !alive {
                return;
            }
            assert!(start.elapsed() < limit, "grandchild {pid} still alive");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// #1311・PLUG-7・REPAIR-5: 接続して要求を受け取った後、応答せずに終了した plugin（子は未回収のゾンビの
    /// まま後始末に入る）では、元のエラー（`Unavailable`・`peer closed the connection`）の分類を失わない。
    /// Linux はゾンビへの `killpg` が成功するため元のエラーそのもの。macOS はゾンビだけのグループへの
    /// `killpg` が `EPERM` になり得るため、グループ停止失敗の付記つきの値も許す（どちらも code は同じ）。
    #[test]
    fn plug7_exit_after_request_keeps_original_error() {
        let (res, elapsed, _dir) = run("exit_after_request", 8000);
        let e = res.unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        let original = "peer closed the connection";
        let with_note = "peer closed the connection; additionally, the plugin process group could \
                         not be killed after a failed exchange, so descendant processes may remain";
        #[cfg(target_os = "macos")]
        assert!(
            e.message() == original || e.message() == with_note,
            "{}",
            e.message()
        );
        #[cfg(not(target_os = "macos"))]
        {
            let _ = with_note;
            assert_eq!(e.message(), original);
        }
        assert!(elapsed < Duration::from_secs(8), "{elapsed:?}");
    }

    /// #1311・PLUG-7・REPAIR-5: タイムアウト後始末の kill はプロセスグループ全体へ届き、孫も残らない。
    #[test]
    fn plug7_one_shot_timeout_kills_grandchild_process_group() {
        let (res, elapsed, dir) = run("grandchild_silent", 2000);
        assert_eq!(res.unwrap_err().code(), PluginErrorCode::Timeout);
        assert!(elapsed < Duration::from_secs(8), "{elapsed:?}");
        let pid: u32 = std::fs::read_to_string(dir.0.join("grandchild.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_process_gone_within(pid, Duration::from_secs(5));
    }

    /// #1604・PLUG-7・REPAIR-5: 応答後に自発終了（終了コード 0）した plugin の孫も、回収の前にグループへ
    /// 送る `SIGKILL` で止まる。pid の消滅を Linux は `/proc`、macOS は `kill -0` で確かめる。
    #[test]
    fn plug7_one_shot_stops_grandchild_of_self_exited_plugin() {
        let (res, _, dir) = run("grandchild_then_exit", 5000);
        let out = res.unwrap();
        assert_eq!(
            out.termination(),
            PluginTermination::Exited { code: Some(0) }
        );
        assert_process_gone_within(grandchild_pid(&dir), Duration::from_secs(5));
    }

    /// #1604・PLUG-7・REPAIR-5: 接続前に自発終了した plugin（`check_child` 経路）の孫も止まり、元の
    /// `Unavailable` が保たれる（グループ停止の付記が付かない）。
    #[test]
    fn plug7_one_shot_stops_grandchild_when_plugin_exits_before_connecting() {
        let (res, _, dir) = run("grandchild_exit_early", 8000);
        let e = res.unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(e.message(), "plugin exited before connecting");
        assert_process_gone_within(grandchild_pid(&dir), Duration::from_secs(5));
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
            PluginTermination::Exited { code: Some(0) }
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
        assert_eq!(out.termination(), PluginTermination::Killed);
        assert_process_gone(pid_of(out.response().payload()));
    }

    /// 応答後に非ゼロ終了した子は成功扱いにせず Unavailable（REPAIR-5・PLUG-7）。
    #[test]
    fn plug7_one_shot_rejects_nonzero_exit_after_response() {
        let (res, _, _dir) = run("exit_nonzero", 5000);
        let e = res.unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
    }

    /// plugin の stderr は親へ流さず、上限以内ならそのまま収集結果として返る（PLUG-7）。
    #[test]
    fn plug7_one_shot_captures_plugin_stderr() {
        let (res, _, _dir) = run("stderr_small", 5000);
        let out = res.unwrap();
        assert_eq!(out.stderr().bytes(), b"plugin-diagnostic\n");
        assert_eq!(out.stderr().total_bytes(), 18);
        assert!(!out.stderr().is_truncated());
        assert!(out.stderr().is_complete());
        assert!(out.stderr().reader_stopped());
    }

    /// stderr を出さない plugin では収集結果が空になる。
    #[test]
    fn plug7_one_shot_reports_empty_stderr_for_quiet_plugin() {
        let (res, _, _dir) = run("respond", 5000);
        let out = res.unwrap();
        assert_eq!(out.stderr().bytes(), b"");
        assert_eq!(out.stderr().total_bytes(), 0);
        assert!(!out.stderr().is_truncated());
        assert!(out.stderr().is_complete());
        assert!(out.stderr().reader_stopped());
    }

    /// ソケットバッファを超える stderr を書く plugin でも詰まらず応答でき、保持は上限までに留まる
    /// （REPAIR-5・PLUG-7。親が読み続けていなければ子は接続前に止まり、合計期限で Timeout になる）。
    #[test]
    fn plug7_one_shot_bounds_flooding_plugin_stderr() {
        let (res, elapsed, _dir) = run("stderr_flood", 8000);
        let out = res.unwrap();
        assert_eq!(
            out.termination(),
            PluginTermination::Exited { code: Some(0) }
        );
        assert_eq!(PLUGIN_STDERR_MAX_BYTES, 65_536);
        assert_eq!(out.stderr().bytes().len(), 65_536);
        assert_eq!(
            out.stderr().bytes().iter().filter(|b| **b == b'x').count(),
            65_536
        );
        assert_eq!(out.stderr().total_bytes(), 1_048_576);
        assert!(out.stderr().is_truncated());
        assert!(out.stderr().is_complete());
        assert!(elapsed < Duration::from_secs(8), "{elapsed:?}");
    }

    /// 孫プロセスが stderr の書き込み端を保持し続けても、収集は期限で打ち切られ、読み取りスレッドは
    /// 停止する（REPAIR-5・PLUG-7。呼び出しは孫の終了〔5 秒〕を待たずに戻る）。
    /// 起動経路（`call_once`）の受付は、別プロセス（同一 UID・別 pid）の接続を切断して待ち受けを続け、
    /// 正しい子へ接続できる。拒否 1 件につき監査イベント 1 件（PLUG-7・PLUG-12・SEC-4・#1861）。
    /// 別 UID の接続は root なしに作れないため、同じ継続・合算の経路を pid 不一致で通す。UID 不一致
    /// 固有の分岐は crate 内ユニットテスト `transport::tests::plug12_accept_peer_pid_*` が受け持つ。
    #[test]
    fn plug12_one_shot_continues_accepting_after_rejected_peers() {
        let dir = TempDir::new("decoys:3");
        let plugin = plugin_for(&dir);
        let (res, lines) = with_watchdog("call_once", move || {
            let req = Frame::new(b"ping".to_vec()).unwrap();
            let mut audit = fandhe_container_plugin::JsonLinesPeerAuthObserver::new();
            let r = call_once(
                &plugin,
                &req,
                OneShotTimeout::new(Duration::from_millis(10000)).unwrap(),
                &mut audit,
            );
            (r, audit.drain_lines())
        });
        let out = res.unwrap();
        assert_eq!(
            out.termination(),
            PluginTermination::Exited { code: Some(0) }
        );
        assert_process_gone(pid_of(out.response().payload()));
        let expected = (
            "peer_pid_mismatch".to_string(),
            "PERMISSION_DENIED".to_string(),
            "accept".to_string(),
            "error".to_string(),
            my_uid(&dir),
        );
        assert_eq!(audit_fields(&lines), vec![expected; 3]);
        no_socket_left(&dir);
    }

    /// 拒否が上限（`UDS_ACCEPT_PEER_REJECTION_LIMIT`）を超えたら `PermissionDenied` を返し、子は回収される。
    /// 監査イベントは上限 + 1 件（最後の 1 件も通知してから打ち切る。PLUG-12・REPAIR-5・#1861）。
    #[test]
    fn plug12_one_shot_stops_when_rejections_exceed_limit() {
        let over = fandhe_container_plugin::transport::UDS_ACCEPT_PEER_REJECTION_LIMIT as usize + 1;
        let dir = TempDir::new(&format!("decoys:{}", over + 3));
        let plugin = plugin_for(&dir);
        let (res, lines) = with_watchdog("call_once", move || {
            let req = Frame::new(b"ping".to_vec()).unwrap();
            let mut audit = fandhe_container_plugin::JsonLinesPeerAuthObserver::new();
            let r = call_once(
                &plugin,
                &req,
                OneShotTimeout::new(Duration::from_millis(10000)).unwrap(),
                &mut audit,
            );
            (r, audit.drain_lines())
        });
        let err = res.unwrap_err();
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

    #[test]
    fn repair5_one_shot_stops_stderr_reader_when_grandchild_holds_stderr() {
        let (res, elapsed, _dir) = run("stderr_held_by_grandchild", 5000);
        let out = res.unwrap();
        assert_eq!(
            out.termination(),
            PluginTermination::Exited { code: Some(0) }
        );
        assert_eq!(out.stderr().bytes(), b"");
        assert!(!out.stderr().is_complete());
        assert!(out.stderr().reader_stopped());
        assert!(elapsed >= Duration::from_millis(500), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(4), "{elapsed:?}");
    }

    /// 失敗時も stderr は観測記録で受け取れ、構造化ログの行には内容が入らない（REPAIR-4・PLUG-7）。
    #[test]
    fn repair4_one_shot_failure_record_carries_stderr_without_logging_it() {
        let dir = TempDir::new("stderr_exit_early");
        let plugin = plugin_for(&dir);
        let (res, records) = with_watchdog("call_once_observed", move || {
            let req = Frame::new(b"ping".to_vec()).unwrap();
            let mut records: Vec<OneShotRecord> = Vec::new();
            let r = call_once_observed(
                &plugin,
                &req,
                OneShotTimeout::new(Duration::from_millis(8000)).unwrap(),
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
                &mut |rec| records.push(rec.clone()),
            );
            (r, records)
        });
        assert_eq!(res.unwrap_err().code(), PluginErrorCode::Unavailable);
        assert_eq!(records.len(), 1);
        let rec = &records[0];
        assert_eq!(rec.error_code, Some("UNAVAILABLE"));
        assert_eq!(rec.stderr.bytes(), b"boom: cannot start\n");
        assert!(rec.stderr.is_complete());
        let line = rec.to_json_line();
        assert!(!line.contains("boom"), "{line}");
        assert!(
            line.ends_with(
                ",\"plugin_stderr_bytes\":19,\"plugin_stderr_truncated\":false,\
                 \"plugin_stderr_complete\":true,\"plugin_stderr_reader_stopped\":true}"
            ),
            "{line}"
        );
    }

    /// 実行権の無いファイルの起動対象は PermissionDenied（spawn 失敗の構造化エラー）で、socket は残らない
    /// （ファイルを開けない＝起動対象を作れないため、旧「存在しないプログラムは NotFound」の試験の置き換え。#1856）。
    #[test]
    fn plug7_one_shot_reports_non_executable_program() {
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
        let req = Frame::new(b"ping".to_vec()).unwrap();
        let err = call_once(
            &plugin,
            &req,
            OneShotTimeout::default(),
            &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
        assert_eq!(err.message(), "permission denied spawning plugin program");
        no_socket_left(&dir);
    }

    /// `env_dump` の応答を名前から値への写像にする。
    fn parse_env_dump(payload: &[u8]) -> std::collections::BTreeMap<String, String> {
        std::str::from_utf8(payload)
            .unwrap()
            .lines()
            .map(|l| {
                let (k, v) = l.split_once('=').unwrap();
                (k.to_string(), v.to_string())
            })
            .collect()
    }

    fn run_env_dump(vars: Vec<(String, OsString)>) -> std::collections::BTreeMap<String, String> {
        let dir = TempDir::new("env_dump");
        let plugin = plugin_for(&dir).with_env(vars).unwrap();
        let out = with_watchdog("call_once", move || {
            let req = Frame::new(b"ping".to_vec()).unwrap();
            call_once(
                &plugin,
                &req,
                OneShotTimeout::default(),
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
            .unwrap()
        });
        let map = parse_env_dump(out.response().payload());
        let sock = map.get(PLUGIN_SOCKET_ENV).unwrap();
        // 公開パスは配置ディレクトリの canonicalize 結果＋socket 名（transport.rs の契約）。
        // macOS の `/var` → `/private/var` のように一時ディレクトリが symlink 経由でも一致させるため、
        // 期待側も同じ規則（canonicalize）で正規化して比べる（PLUG-7・PLUG-12）。
        assert_eq!(
            std::path::Path::new(sock).parent().unwrap(),
            std::fs::canonicalize(&dir.0).unwrap().as_path(),
            "socket variable points into the test socket directory"
        );
        map
    }

    /// 指定なしなら子の環境は socket の変数だけ（親の環境を継承しない。#1858・PLUG-7）。
    #[test]
    fn plug7_one_shot_env_default_is_socket_only() {
        assert!(std::env::var_os("PATH").is_some());
        let map = run_env_dump(vec![]);
        let keys: Vec<&str> = map.keys().map(String::as_str).collect();
        assert_eq!(keys, vec![PLUGIN_SOCKET_ENV]);
    }

    /// 明示した 2 件だけが socket の変数に加わって子へ渡る（親の `HOME` は上書きされる。#1858・PLUG-7）。
    #[test]
    fn plug7_one_shot_env_passes_explicit_vars_only() {
        assert!(std::env::var_os("HOME").is_some());
        let map = run_env_dump(vec![
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
    fn plug11_one_shot_passes_exec_path_as_argv0() {
        let (res, _, _dir) = run("argv0", 5000);
        let out = res.unwrap();
        let expected = std::env::current_exe().unwrap();
        let mut want = b"argv0=".to_vec();
        std::os::unix::ffi::OsStrExt::as_bytes(expected.as_os_str())
            .iter()
            .for_each(|b| want.push(*b));
        assert_eq!(out.response().payload(), want.as_slice());
    }

    /// 起動対象を作った後に元のパスを別の実行ファイルへ差し替えても、起動されるのは元の実体（Linux。
    /// fd の実体を実行する。#1856・PLUG-11）。
    #[cfg(target_os = "linux")]
    #[test]
    fn plug11_one_shot_runs_original_after_path_replaced() {
        let dir = TempDir::new("respond");
        let fx = crate::swap::Fixture::new();
        let args: Vec<OsString> = ["--exact", "unix::plugin_child_entry", "--test-threads=1"]
            .iter()
            .map(OsString::from)
            .collect();
        let plugin = PluginLaunchSpec::new(fx.target(), args, dir.0.clone()).unwrap();
        fx.replace_with_script();
        let req = Frame::new(b"ping".to_vec()).unwrap();
        let out = with_watchdog("call_once", move || {
            call_once(
                &plugin,
                &req,
                OneShotTimeout::new(Duration::from_millis(5000)).unwrap(),
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
        })
        .unwrap();
        assert_eq!(
            out.termination(),
            PluginTermination::Exited { code: Some(0) }
        );
        let pid = pid_of(out.response().payload());
        assert_ne!(pid, std::process::id());
        // 対照: 差し替え後のパスから新しく起動対象を作るとスクリプトとして拒否される。
        let err = fx.try_target_from_path().unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::InvalidArgument);
    }

    /// macOS 等（Linux 以外の unix）: 構築後にパスを別ファイルへ差し替えると、spawn 直前の同一性確認で
    /// 拒否され、子は spawn されない（#1866・PLUG-11）。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn plug11_1866_one_shot_rejects_after_path_replaced() {
        let dir = TempDir::new("respond");
        let fx = crate::swap::Fixture::new();
        let plugin = PluginLaunchSpec::new(fx.target(), vec![], dir.0.clone()).unwrap();
        let marker = fx.marker_path();
        fx.replace_with_marker_script(&marker);
        let req = Frame::new(b"ping".to_vec()).unwrap();
        let err = with_watchdog("call_once", move || {
            call_once(
                &plugin,
                &req,
                OneShotTimeout::new(Duration::from_millis(5000)).unwrap(),
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
        })
        .unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "plugin launch target path does not refer to the verified file"
        );
        std::thread::sleep(Duration::from_millis(300));
        assert!(!marker.exists(), "child must not be spawned");
        // 対照: 差し替え後のパスから新しく起動対象を作るとスクリプトとして拒否される。
        assert_eq!(
            fx.try_target_from_path().unwrap_err().code(),
            PluginErrorCode::InvalidArgument
        );
    }

    /// macOS 等: 差し替えなしなら起動し、1 往復が成功する（#1866）。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn plug11_1866_one_shot_runs_when_not_replaced() {
        let dir = TempDir::new("respond");
        let fx = crate::swap::Fixture::new();
        let args: Vec<OsString> = ["--exact", "unix::plugin_child_entry", "--test-threads=1"]
            .iter()
            .map(OsString::from)
            .collect();
        let plugin = PluginLaunchSpec::new(fx.target(), args, dir.0.clone()).unwrap();
        let req = Frame::new(b"ping".to_vec()).unwrap();
        let out = with_watchdog("call_once", move || {
            call_once(
                &plugin,
                &req,
                OneShotTimeout::new(Duration::from_millis(5000)).unwrap(),
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
        })
        .unwrap();
        assert_eq!(
            out.termination(),
            PluginTermination::Exited { code: Some(0) }
        );
        assert_ne!(pid_of(out.response().payload()), std::process::id());
    }

    /// 構築後に同じ inode の内容が `#!` スクリプトへ書き換えられた場合は、解釈系が閉じた fd を開き直せず
    /// `Unavailable` で失敗する（doc の「ネイティブの実行ファイルに限る」の裏付け。Linux。#1856）。
    #[cfg(target_os = "linux")]
    #[test]
    fn plug11_one_shot_fails_when_inode_rewritten_to_script() {
        let dir = TempDir::new("respond");
        let fx = crate::swap::Fixture::new_rewritable();
        let plugin = PluginLaunchSpec::new(fx.target(), vec![], dir.0.clone()).unwrap();
        fx.rewrite_in_place_to_script();
        let req = Frame::new(b"ping".to_vec()).unwrap();
        let err = with_watchdog("call_once", move || {
            call_once(
                &plugin,
                &req,
                OneShotTimeout::new(Duration::from_millis(5000)).unwrap(),
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
        })
        .unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::Unavailable);
        assert_eq!(err.message(), "plugin exited before connecting");
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
