//! plugin-windows の E2E 結合試験（TASK-116.6・#397。PLUG-1・WIN-1。関連: WIN-2・REPAIR-3・REPAIR-5・REPAIR-12）。
//!
//! 「plugin 起動 → UDS 接続 → WSL2 起動（create / start）→ 停止（stop・切断）」を 1 本の流れで通す。
//! `fandhe-container-plugin` の UDS 実体は unix のみで、実バックエンド（`wsl.exe`）は Windows のみのため、
//! 両者を同時に満たす経路は現時点で存在しない（Windows ホスト上の接続経路は TASK-114 で確定予定）。
//! そのため試験を 2 層に分ける（実装済みを装わない。REPAIR-3）。
//!
//! - 層 A（`mock_core`・unix・既定集合 6 件）: 試験本体が core 役（`UdsListener::accept`）、別スレッドが
//!   plugin 役（peer 認証つき `UdsStream::connect` → `serve_session`。`main.rs` と同じ実行順）となり、
//!   偽バックエンドで create → start → stop → 切断を実 UDS 上で往復する。
//! - 層 B（`real_wsl2`・Windows・`#[ignore]` 1 件）: 実 `wsl.exe` と実 WSL2 に対し、アダプタをプロセス内で
//!   駆動する。UDS ホップは含まない（TASK-114 待ち）。手順は AGENTS.md「実機前提テスト」節。
//!
//! 層 A で扱わないもの（既存試験の担当）: 実バイナリ spawn・フレーム破損・実 SIGTERM（`frame_loop.rs`）、
//! 停止フラグ時の `release_all`（`shutdown_cleanup.rs`）、peer 認証（`peer_auth.rs`）。
//! 暫定ワイヤー契約（`adapter.rs` と同一）: create `["create", id, distro, policy, (name, host, "ro"|"rw")*]` →
//! `["created","",""]`、start → `["running", transport, warning]`、stop → `["stopped","",""]`。
//! 待ちはすべて期限つき（REPAIR-5）。

#[cfg(unix)]
mod mock_core {
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc::{Receiver, channel};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use fandhe_container_platform_windows::error::{WinError, WinErrorCode};
    use fandhe_container_platform_windows::instrument::WinWarningCode;
    use fandhe_container_platform_windows::wsl2::{
        DistroName, LaunchRequest, SharedTransport, TransportPolicy,
    };
    use fandhe_container_plugin::{
        ControlMessage, JsonLinesPeerAuthObserver, MessageId, PluginErrorCode, RpcTimeout,
        UdsListener, UdsStream, decode_message, encode_message,
    };
    use fandhe_container_plugin_windows::adapter::{
        BackendFailure, GuestStart, LaunchOutcome, ReleaseAllReport, SessionOutcome,
        WindowsBackend, WindowsRuntimeAdapter, serve_session,
    };
    use fandhe_container_plugin_windows::frame_loop::LoopExit;

    struct FakePrepared;

    /// 偽バックエンドが次の launch で返す結果。
    #[derive(Clone)]
    enum LaunchMode {
        Ok {
            transport: Option<SharedTransport>,
            warning: Option<WinWarningCode>,
        },
        /// 解除できていないマウントつきの失敗（`unreleased: Some`）。
        FailUnreleased { warning: Option<WinWarningCode> },
    }

    /// launch へ届いた要求の要約（distro・方針・(名前, ホスト, ro)）。
    type LaunchRecord = (String, TransportPolicy, Vec<(String, String, bool)>);

    /// 偽バックエンドの呼び出し記録と注入設定（試験本体と plugin 役スレッドで共有する）。
    struct Record {
        launches: Vec<LaunchRecord>,
        releases: usize,
        mode: LaunchMode,
    }

    type Shared = Arc<Mutex<Record>>;

    struct FakeBackend(Shared);

    impl WindowsBackend for FakeBackend {
        type Prepared = FakePrepared;

        fn check_distro(&self, _d: &DistroName, _budget: Duration) -> Result<(), WinError> {
            Ok(())
        }

        fn launch(
            &self,
            req: &LaunchRequest,
            guest: &dyn GuestStart<FakePrepared>,
            budget: Duration,
            _cancel: &dyn Fn() -> bool,
        ) -> Result<LaunchOutcome<FakePrepared>, BackendFailure<FakePrepared>> {
            let mode = {
                let mut r = self.0.lock().expect("lock");
                let mounts = req
                    .mounts()
                    .iter()
                    .map(|m| {
                        (
                            m.name.as_str().to_string(),
                            m.host.as_str().to_string(),
                            m.read_only,
                        )
                    })
                    .collect();
                r.launches.push((
                    req.distro().as_str().to_string(),
                    req.transport_policy(),
                    mounts,
                ));
                r.mode.clone()
            };
            match mode {
                LaunchMode::Ok { transport, warning } => {
                    guest.start(&FakePrepared, budget)?;
                    Ok(LaunchOutcome {
                        prepared: FakePrepared,
                        transport,
                        warning,
                    })
                }
                LaunchMode::FailUnreleased { warning } => Err(BackendFailure {
                    error: WinError::new(WinErrorCode::Timeout, "fake launch timeout"),
                    unreleased: Some(FakePrepared),
                    warning,
                }),
            }
        }

        fn release(
            &self,
            _p: &FakePrepared,
            _budget: Duration,
        ) -> Result<(), BackendFailure<FakePrepared>> {
            self.0.lock().expect("lock").releases += 1;
            Ok(())
        }
    }

    struct OkGuest;

    impl GuestStart<FakePrepared> for OkGuest {
        fn start(&self, _p: &FakePrepared, _remaining: Duration) -> Result<(), WinError> {
            Ok(())
        }
    }

    /// core 役（試験本体）のハーネス。plugin 役はスレッドで `serve_session` を回す。
    struct E2e {
        dir: PathBuf,
        stream: Option<UdsStream>,
        next_id: u64,
        record: Shared,
        outcome: Receiver<SessionOutcome>,
    }

    impl E2e {
        fn start() -> Self {
            let dir = create_unique_dir();
            let sock = dir.join("p.sock");
            let listener = UdsListener::bind(&sock).expect("bind");
            let record: Shared = Arc::new(Mutex::new(Record {
                launches: Vec::new(),
                releases: 0,
                mode: LaunchMode::Ok {
                    transport: Some(SharedTransport::Virtiofs),
                    warning: None,
                },
            }));
            let (tx, outcome) = channel();
            {
                let record = Arc::clone(&record);
                let sock = sock.clone();
                std::thread::spawn(move || {
                    let mut obs = JsonLinesPeerAuthObserver::new();
                    let mut stream = UdsStream::connect(&sock, Duration::from_secs(5), &mut obs)
                        .expect("connect");
                    let mut adapter = WindowsRuntimeAdapter::new(FakeBackend(record), OkGuest);
                    let stop = AtomicBool::new(false);
                    let _ = tx.send(serve_session(&mut stream, &mut adapter, &stop));
                });
            }
            let mut obs = JsonLinesPeerAuthObserver::new();
            let stream = listener
                .accept(Duration::from_secs(20), &mut obs)
                .expect("accept");
            Self {
                dir,
                stream: Some(stream),
                next_id: 0,
                record,
                outcome,
            }
        }

        fn set_mode(&self, mode: LaunchMode) {
            self.record.lock().expect("lock").mode = mode;
        }

        fn call(&mut self, body: &[&str]) -> ControlMessage<Vec<String>> {
            self.next_id += 1;
            let id = self.next_id;
            let stream = self.stream.as_mut().expect("connected");
            let f = encode_message(&ControlMessage::Request {
                id: MessageId::new(id),
                body: body.iter().map(|s| s.to_string()).collect::<Vec<String>>(),
            })
            .expect("encode");
            stream
                .write_frame(&f, RpcTimeout::default())
                .expect("write");
            let r = stream.read_frame(RpcTimeout::default()).expect("read");
            let msg = decode_message::<Vec<String>>(&r).expect("decode");
            // 応答は要求と同じ id で返る（相関の確認）。
            let got = match &msg {
                ControlMessage::Response { id, .. } | ControlMessage::Error { id, .. } => id.get(),
                other => panic!("unexpected {other:?}"),
            };
            assert_eq!(got, id);
            msg
        }

        fn expect_ok(&mut self, body: &[&str]) -> Vec<String> {
            match self.call(body) {
                ControlMessage::Response { body, .. } => body,
                other => panic!("expected response, got {other:?}"),
            }
        }

        /// エラーフレームの (code, message) を返す。
        fn expect_err(&mut self, body: &[&str]) -> (PluginErrorCode, String) {
            match self.call(body) {
                ControlMessage::Error { error, .. } => (error.code(), error.message().to_string()),
                other => panic!("expected error, got {other:?}"),
            }
        }

        /// 接続を閉じ、plugin 役の終了結果を期限つきで受け取る（裸の join はしない。REPAIR-5）。
        fn disconnect(mut self) -> (SessionOutcome, Shared) {
            drop(self.stream.take());
            let outcome = self
                .outcome
                .recv_timeout(Duration::from_secs(30))
                .expect("serve_session did not return within deadline");
            let _ = std::fs::remove_dir_all(&self.dir); // 排他作成した自前のディレクトリのみ
            (outcome, Arc::clone(&self.record))
        }
    }

    /// `sun_path` 上限を避けるため `/tmp` 直下の短名を 0700 で排他作成する（PLUG-12）。
    fn create_unique_dir() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        for n in 0..100u32 {
            let p =
                PathBuf::from("/tmp").join(format!("fc-pwe-{}-{nanos:x}-{n}", std::process::id()));
            match std::fs::DirBuilder::new().mode(0o700).create(&p) {
                Ok(()) => return p,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create test dir: {e}"),
            }
        }
        panic!("could not create a unique test dir");
    }

    const CREATE: &[&str] = &[
        "create",
        "c1",
        "Ubuntu",
        "prefer-virtiofs",
        "data",
        "C:\\data\\app",
        "ro",
    ];

    fn assert_cleanup(o: &SessionOutcome, released: usize, remaining: usize) {
        assert_eq!(
            (o.cleanup.released, o.cleanup.remaining),
            (released, remaining)
        );
        // 型を使うことで ReleaseAllReport の公開フィールドが変わったらここで気付く。
        let _: &ReleaseAllReport = &o.cleanup;
    }

    /// PLUG-1・WIN-1: create → start → stop → ping が同一 UDS 接続で往復し、切断で正常終了する。
    #[test]
    fn task116_6_plug1_win1_create_start_stop_roundtrip_over_uds() {
        let mut e = E2e::start();
        assert_eq!(e.expect_ok(CREATE), vec!["created", "", ""]);
        assert_eq!(
            e.expect_ok(&["start", "c1"]),
            vec!["running", "virtiofs", ""]
        );
        assert_eq!(e.expect_ok(&["stop", "c1"]), vec!["stopped", "", ""]);
        assert_eq!(e.expect_ok(&["ping"]), vec!["pong"]);
        let (outcome, record) = e.disconnect();
        assert!(
            matches!(outcome.result, Ok(LoopExit::PeerClosed)),
            "{:?}",
            outcome.result
        );
        assert_cleanup(&outcome, 0, 0);
        let r = record.lock().expect("lock");
        assert_eq!((r.launches.len(), r.releases), (1, 1));
    }

    /// WIN-1: stop せずに切断しても、保持中の共有マウントは `release_all` で解除される。
    #[test]
    fn task116_6_win1_disconnect_with_running_mount_is_released() {
        let mut e = E2e::start();
        e.expect_ok(CREATE);
        e.expect_ok(&["start", "c1"]);
        let (outcome, record) = e.disconnect();
        assert!(matches!(outcome.result, Ok(LoopExit::PeerClosed)));
        assert_cleanup(&outcome, 1, 0);
        assert_eq!(record.lock().expect("lock").releases, 1);
    }

    /// PLUG-1・WIN-1: create の引数（distro・方針・共有）が `LaunchRequest` としてバックエンドへ届く。
    #[test]
    fn task116_6_win1_create_arguments_reach_backend() {
        let mut e = E2e::start();
        e.expect_ok(&[
            "create",
            "c1",
            "Debian",
            "require-virtiofs",
            "rw-share",
            "D:\\work\\src",
            "rw",
            "ro-share",
            "C:\\data\\ro",
            "ro",
        ]);
        e.expect_ok(&["start", "c1"]);
        let (_, record) = e.disconnect();
        let r = record.lock().expect("lock");
        assert_eq!(
            r.launches,
            vec![(
                "Debian".to_string(),
                TransportPolicy::RequireVirtiofs,
                vec![
                    ("rw-share".to_string(), "D:\\work\\src".to_string(), false),
                    ("ro-share".to_string(), "C:\\data\\ro".to_string(), true),
                ]
            )]
        );
    }

    /// WIN-2: 9P 降格の警告が start 応答の第 3 要素で core へ伝わる。
    #[test]
    fn task116_6_win2_nine_p_downgrade_warning_propagates() {
        let mut e = E2e::start();
        e.set_mode(LaunchMode::Ok {
            transport: Some(SharedTransport::NineP),
            warning: Some(WinWarningCode::VirtiofsNotEnabled),
        });
        e.expect_ok(CREATE);
        assert_eq!(
            e.expect_ok(&["start", "c1"]),
            vec!["running", "9p", WinWarningCode::VirtiofsNotEnabled.as_str()]
        );
        let (outcome, _) = e.disconnect();
        assert_cleanup(&outcome, 1, 0);
    }

    /// WIN-2: 解除できないまま起動に失敗しても所有情報を保持し、続く stop が解除を再試行する。
    #[test]
    fn task116_6_win2_launch_failure_keeps_unreleased_and_stop_retries() {
        let mut e = E2e::start();
        e.set_mode(LaunchMode::FailUnreleased {
            warning: Some(WinWarningCode::VirtiofsNotApplied),
        });
        e.expect_ok(CREATE);
        let (code, msg) = e.expect_err(&["start", "c1"]);
        assert_eq!(code, PluginErrorCode::Timeout);
        assert_eq!(msg, "fake launch timeout; warning=VIRTIOFS_NOT_APPLIED");
        assert_eq!(e.expect_ok(&["stop", "c1"]), vec!["stopped", "", ""]);
        let (outcome, record) = e.disconnect();
        assert_cleanup(&outcome, 0, 0);
        assert_eq!(record.lock().expect("lock").releases, 1);
    }

    /// PLUG-1: 状態違反はエラーフレームで返り接続は維持される。message は固定文言で id・パスを反射しない。
    #[test]
    fn task116_6_plug1_error_frames_keep_connection_without_reflection() {
        let mut e = E2e::start();
        let secrets = ["ghost-1", "C:\\data\\app"];
        let not_found = (PluginErrorCode::NotFound, "container not found".to_string());
        assert_eq!(e.expect_err(&["start", "ghost-1"]), not_found);
        assert_eq!(e.expect_err(&["stop", "ghost-1"]), not_found);
        e.expect_ok(CREATE);
        let dup = e.expect_err(CREATE);
        assert_eq!(
            dup,
            (
                PluginErrorCode::AlreadyExists,
                "container already exists".to_string()
            )
        );
        e.expect_ok(&["start", "c1"]);
        let twice = e.expect_err(&["start", "c1"]);
        assert_eq!(
            twice,
            (
                PluginErrorCode::FailedPrecondition,
                "container is not in created state".to_string()
            )
        );
        for (_, m) in [&not_found, &dup, &twice] {
            for s in secrets {
                assert!(!m.contains(s), "message reflects input: {m}");
            }
        }
        assert_eq!(e.expect_ok(&["ping"]), vec!["pong"]);
        let (outcome, _) = e.disconnect();
        assert!(matches!(outcome.result, Ok(LoopExit::PeerClosed)));
        assert_cleanup(&outcome, 1, 0);
    }
}

#[cfg(target_os = "windows")]
mod real_wsl2 {
    //! 層 B。実 `wsl.exe` と実 WSL2 に対し、plugin の要求経路（`RequestHandler::handle`）を
    //! プロセス内で駆動する。UDS ホップは含まない（Windows ホスト上の UDS は TASK-114 待ち。REPAIR-3）。
    //! 環境変数は `platform-windows/tests/wsl2_virtiofs.rs` と同名（新設しない）。
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use fandhe_container_platform_windows::error::{WinError, WinErrorCode};
    use fandhe_container_platform_windows::instrument::WinWarningCode;
    use fandhe_container_platform_windows::wsl2::{
        MAX_WSL_TIMEOUT, MIN_WSL_TIMEOUT, PreparedLaunch,
    };
    use fandhe_container_plugin::PluginError;
    use fandhe_container_plugin_windows::adapter::{
        GuestStart, PlatformBackend, WindowsRuntimeAdapter,
    };
    use fandhe_container_plugin_windows::frame_loop::RequestHandler;

    const ENV_DISTRO: &str = "FANDHE_CONTAINER_WSL_DISTRO";
    const ENV_TRANSPORT: &str = "FANDHE_CONTAINER_WSL_EXPECT_TRANSPORT";
    const ENV_TIMEOUT: &str = "FANDHE_CONTAINER_TEST_TIMEOUT_SECS";

    /// 共有元の一時ディレクトリ。解除を確認できるまで保持する（fail-closed。確認後に `retain` を倒す）。
    struct TempDir {
        dir: PathBuf,
        retain: Arc<AtomicBool>,
    }

    impl TempDir {
        fn new() -> Self {
            for n in 0..100u32 {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let dir = std::env::temp_dir()
                    .join(format!("fandhe-e2e-{}-{nanos}-{n}", std::process::id()));
                match std::fs::create_dir(&dir) {
                    Ok(()) => {
                        return Self {
                            dir,
                            retain: Arc::new(AtomicBool::new(true)),
                        };
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("create temp dir: {e}"),
                }
            }
            panic!("could not create a unique temp dir");
        }

        fn path(&self) -> &Path {
            &self.dir
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            if self.retain.load(Ordering::SeqCst) {
                eprintln!(
                    "shared source directory retained because unmount was not confirmed: {}",
                    self.dir.display()
                );
            } else {
                let _ = std::fs::remove_dir_all(&self.dir);
            }
        }
    }

    fn test_timeout() -> Duration {
        let secs = match std::env::var(ENV_TIMEOUT) {
            Ok(v) => v
                .parse::<u64>()
                .unwrap_or_else(|_| panic!("{ENV_TIMEOUT} must be an integer")),
            Err(_) => 60,
        };
        let t = Duration::from_secs(secs);
        assert!(
            (MIN_WSL_TIMEOUT..=MAX_WSL_TIMEOUT).contains(&t),
            "{ENV_TIMEOUT} is out of range"
        );
        t
    }

    /// ゲスト内で `sh -c` を root で実行し成否を返す（期限超過は kill して false）。引数配列で渡す。
    fn guest_sh_ok(distro: &str, script: &str, timeout: Duration) -> bool {
        let Ok(mut child) = Command::new("wsl.exe")
            .args(["-d", distro, "--user", "root", "--", "sh", "-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            return false;
        };
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(s)) => return s.success(),
                Ok(None) if start.elapsed() > timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => return false,
            }
        }
    }

    /// ゲスト内ランタイム起動の代わりに、各共有の目印ファイルがゲストから見えることを確かめる
    /// （REPAIR-12。失敗するとアダプタがマウントをロールバックする）。
    struct MarkerGuest {
        distro: String,
        timeout: Duration,
    }

    impl GuestStart<PreparedLaunch> for MarkerGuest {
        fn start(&self, p: &PreparedLaunch, remaining: Duration) -> Result<(), WinError> {
            // REPAIR-5: 全共有の確認をアダプタから渡された残り時間内に収める。期限切れは Timeout で失敗させる。
            let began = Instant::now();
            for m in p.mounts() {
                let left = remaining.saturating_sub(began.elapsed());
                if left.is_zero() {
                    return Err(WinError::new(
                        WinErrorCode::Timeout,
                        "guest marker check exceeded the launch deadline",
                    ));
                }
                let script = format!("test -f '{}/marker.txt'", m.guest_path);
                if !guest_sh_ok(&self.distro, &script, self.timeout.min(left)) {
                    if began.elapsed() >= remaining {
                        return Err(WinError::new(
                            WinErrorCode::Timeout,
                            "guest marker check exceeded the launch deadline",
                        ));
                    }
                    return Err(WinError::new(
                        WinErrorCode::FailedPrecondition,
                        "marker file is not visible from the guest",
                    ));
                }
            }
            Ok(())
        }
    }

    fn fail(what: &str, e: PluginError) -> ! {
        panic!(
            "{what} failed: code={} message={}",
            e.code().as_str(),
            e.message()
        )
    }

    /// PLUG-1・WIN-1・WIN-2: 実 WSL2 に対し create → start → stop をアダプタ経由で通す。
    ///
    /// 既知のリスク: 要求の合計期限 `REQUEST_BUDGET` は固定で、コールドスタートでは `TIMEOUT` になり得る
    /// ため、事前に `wsl.exe` で起動を温める。それでも `TIMEOUT` なら期限設計の知見として報告する。
    #[test]
    #[ignore = "requires real Windows with WSL2 and a WSL2 distribution (and .wslconfig virtiofs=true applied for the virtiofs expectation); PLUG-1 WIN-1; see AGENTS.md"]
    fn task116_6_plug1_win1_real_wsl2_launch_and_stop_via_adapter() {
        let timeout = test_timeout();
        let distro = std::env::var(ENV_DISTRO)
            .unwrap_or_else(|_| panic!("{ENV_DISTRO} must be set to a WSL2 distribution name"));
        let expect_virtiofs = match std::env::var(ENV_TRANSPORT).as_deref() {
            Err(_) | Ok("virtiofs") => true,
            Ok("9p") => false,
            Ok(_) => panic!("{ENV_TRANSPORT} must be 'virtiofs' or '9p'"),
        };
        assert!(
            guest_sh_ok(&distro, "true", timeout),
            "warm-up of the WSL2 distribution failed"
        );

        let tmp = TempDir::new();
        let mut create: Vec<String> = ["create", "c1", distro.as_str(), "prefer-virtiofs"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        for (name, sub, mode) in [("fc-e2e-rw", "rw", "rw"), ("fc-e2e-ro", "ro", "ro")] {
            let dir = tmp.path().join(sub);
            std::fs::create_dir_all(&dir).expect("create share dir");
            std::fs::write(dir.join("marker.txt"), b"fandhe-e2e").expect("write marker");
            create.extend([
                name.to_string(),
                dir.to_str().expect("UTF-8 path").to_string(),
                mode.to_string(),
            ]);
        }

        let guest = MarkerGuest {
            distro: distro.clone(),
            timeout,
        };
        let mut adapter = WindowsRuntimeAdapter::new(PlatformBackend, guest);
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<String>>();

        assert_eq!(adapter.handle(&s(&["ping"])).expect("ping"), vec!["pong"]);
        match adapter.handle(&create) {
            Ok(b) => assert_eq!(b, vec!["created", "", ""]),
            Err(e) => fail("create", e),
        }
        let started = match adapter.handle(&s(&["start", "c1"])) {
            Ok(b) => b,
            Err(e) => fail("start", e),
        };
        let want_transport = if expect_virtiofs { "virtiofs" } else { "9p" };
        assert_eq!(started.len(), 3);
        assert_eq!(started[0], "running");
        assert_eq!(started[1], want_transport);
        if expect_virtiofs {
            assert_eq!(started[2], "");
        } else {
            assert!(
                [
                    WinWarningCode::VirtiofsNotEnabled.as_str(),
                    WinWarningCode::VirtiofsNotApplied.as_str()
                ]
                .contains(&started[2].as_str()),
                "9P fallback must carry a warning: {:?}",
                started[2]
            );
        }
        match adapter.handle(&s(&["stop", "c1"])) {
            Ok(b) => assert_eq!(b, vec!["stopped", "", ""]),
            Err(e) => fail("stop", e),
        }
        // stop が成功した時点で解除済み。残りがないことも確かめてから共有元を片付ける。
        let report = adapter.release_all();
        assert_eq!((report.released, report.remaining), (0, 0));
        tmp.retain.store(false, Ordering::SeqCst);
    }
}
