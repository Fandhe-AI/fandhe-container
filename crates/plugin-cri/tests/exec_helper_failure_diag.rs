//! 実 helper のコードで起動失敗を注入し、fd 2 の転送と秘密の非出力を照合する結合試験
//! （CRI-6・SUP-6・SEC-1・REPAIR-4・REPAIR-12・#4172。前提は #4171 の fd 2 の socketpair と読み手）。
//!
//! 役割と呼び出し文脈: supervisor の bin の `main` は第 1 引数が `stream-exec` なら
//! `run_stream_exec_main` へ振り分ける。本試験の `main`（`harness = false`）は同じ分岐を持ち、自分自身を helper として
//! 再実行する。helper として動く経路（fd の整理・fd 0 の検査・引数の解釈・状態ストア・kind 6 の取得・`Result` の送信）は
//! supervisor の bin と同一で、偽の helper ではない。supervisor の実ファイルを使わないのは、
//! `cargo test -p fandhe-container-plugin-cri` が supervisor の bin を build せず位置も得られないため
//! （実ファイルを要求すると既定の集合で動かせない）。root も実コンテナも要らないので既定の集合に置く。
//!
//! 場面（具体値で固定する）:
//!
//! - A: fd 0 が socket でない helper（`InvalidArgument` になる stdio の注入）。fd 2 の診断を本番と同じ読み手
//!   （`diagnostics::spawn_reader`）が拾い、`code` だけの 1 行が構造化ログへ出る。
//! - B: 存在しない pid のコンテナを本番の `SupervisorExecLauncher` で exec する。supervisor が不在なので
//!   `Unavailable` で失敗し、`Failed(code)` の `Result` frame だけが返る。
//!
//! 現状の観測事実（REPAIR-3）: helper が fd 2 へ書くのは「fd 0 が socket でない」「要求元の消滅で取り消した」の
//! 2 行だけで、段名と errno を出す生成側は supervisor・core に無い（状態の不一致・kind 6 の失敗・stdio の受け取りの
//! 失敗は `Result` frame の `Failed(code)` だけで返る）。よって A は `code` だけの行、B は転送行 0 件になる。
//! 生成側（段名・errno）が入ったら、この期待値を「段名と errno の行が 1 件以上」へ直す。後続 issue で扱う。
//! `require_stdio_kinds`・mask の不一致の場面は kind 6 の成功（稼働中の supervisor）が前提のため、ここでは起こせない。
//!
//! 秘密の非出力（SEC-1）: 既知のコンテナ ID・argv・トークン風の引数・状態ルートの名前が、sink の全バイト列に
//! 部分文字列として現れないことを両場面で照合する。
//!
//! 待ちはすべて上限つき（REPAIR-5）。Linux 以外は not applicable の 1 行を出して成功する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("exec_helper_failure_diag: not applicable (linux only)");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

// 残骸に強い 0700 の一時ディレクトリ作成（net の試験と共有。試験 crate 間でモジュールを共有できないため `#[path]`）。
#[cfg(target_os = "linux")]
#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Write;
    use std::num::NonZeroU32;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode, Stdio};
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerStatus, CreateStateRequest, StateStore, UpdateStateRequest,
    };
    use fandhe_container_cri::error::{CriError, CriErrorCode};
    use fandhe_container_cri::streaming::exec::{ExecLaunch, ExecStreamLauncher};
    use fandhe_container_plugin_cri::streaming::exec_launcher::diagnostics::{
        DiagTracker, spawn_reader,
    };
    use fandhe_container_plugin_cri::streaming::exec_launcher::{
        HelperCapabilities, HelperSpawner, SpawnedHelper, SupervisorExecLauncher,
        spawn_helper_command,
    };
    use fandhe_container_plugin_cri::telemetry::LineSink;
    use fandhe_container_supervisor::stream_exec::helper::{
        StreamExecArgs, is_stream_exec_invocation, run_stream_exec_main, stream_exec_command,
    };
    use fandhe_container_supervisor::stream_exec::wire::StdioMask;

    use super::exclusive_dir;

    /// 既知の秘密（ログに出てはならない値。実トークンではないダミー）。
    const SENTINEL_ID: &str = "fcc4172sentinelid";
    const SENTINEL_ARGV0: &str = "/bin/fcc4172-sentinel-argv";
    const SENTINEL_TOKEN: &str = "tok4172AbCdEf0123456789";
    const SENTINEL_DIR: &str = "fcc4172-sentinel-dir";

    /// 子の終了待ちの上限。CI の試験バイナリ用 watchdog（既定 300 秒）より先に効く。
    const CHILD_WAIT: Duration = Duration::from_secs(10);
    const LAUNCH_WAIT: Duration = Duration::from_secs(30);
    const IDLE_WAIT: Duration = Duration::from_secs(10);

    struct Collect(Arc<Mutex<Vec<u8>>>);

    impl Write for Collect {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("collect lock").extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// 0700 の一時ディレクトリ（Drop で削除）。名前に既知の秘密を含め、ログへの漏れを検出できるようにする。
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            Self(exclusive_dir::create(SENTINEL_DIR).expect("create temp dir"))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn new_sink() -> (LineSink, Arc<Mutex<Vec<u8>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        (
            LineSink::spawn(Box::new(Collect(Arc::clone(&buf))), 256),
            buf,
        )
    }

    fn text_of(buf: &Mutex<Vec<u8>>) -> String {
        String::from_utf8(buf.lock().expect("buf lock").clone()).expect("sink output is utf8")
    }

    /// sink の全バイト列に既知の秘密が現れないことを照合する（見つかった値と全文を失敗に含める）。
    fn assert_no_secrets(scene: &str, text: &str) {
        for secret in [SENTINEL_ID, SENTINEL_ARGV0, SENTINEL_TOKEN, SENTINEL_DIR] {
            assert!(
                !text.contains(secret),
                "{scene}: secret {secret:?} leaked into the log: {text:?}"
            );
        }
    }

    fn wait_child(child: &mut std::process::Child) -> std::process::ExitStatus {
        let until = Instant::now() + CHILD_WAIT;
        loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                return status;
            }
            if Instant::now() >= until {
                let _ = child.kill();
                let _ = child.wait();
                panic!("helper did not exit within {CHILD_WAIT:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// 回収済みの子の pid（存在しない pid として使う）。
    fn dead_pid() -> NonZeroU32 {
        let mut child = Command::new("/bin/true").spawn().expect("spawn /bin/true");
        let pid = child.id();
        let _ = wait_child(&mut child);
        NonZeroU32::new(pid).expect("pid is nonzero")
    }

    fn state_root(dir: &Path) -> PathBuf {
        let root = dir.join("state");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("state root");
        root
    }

    fn sentinel_argv() -> Vec<String> {
        vec![SENTINEL_ARGV0.to_string(), SENTINEL_TOKEN.to_string()]
    }

    /// 場面 A: fd 0 が socket でない helper（`InvalidArgument` になる stdio）。
    fn scene_a_fd0_not_socket() -> Result<(), String> {
        let dir = TempDir::new();
        let args = StreamExecArgs::new(
            state_root(&dir.0),
            ContainerId::new(SENTINEL_ID).expect("id"),
            dead_pid(),
            Duration::from_secs(5),
            StdioMask::from_presence(false, false, false),
            sentinel_argv(),
        )
        .map_err(|e| format!("args: {e:?}"))?;
        let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let (diag_end, helper_err) = UnixStream::pair().map_err(|e| format!("pair: {e}"))?;
        let mut command = stream_exec_command(&exe, &args);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(OwnedFd::from(helper_err)));
        let spawned = command.spawn();
        // 親に残る helper 側の端を閉じ、helper の終了で読み手が EOF を観測できるようにする。
        drop(command);
        let mut child = spawned.map_err(|e| format!("spawn: {e}"))?;

        let (sink, buf) = new_sink();
        let tracker = Arc::new(DiagTracker::default());
        spawn_reader(
            diag_end,
            Arc::new(AtomicBool::new(false)),
            Instant::now() + Duration::from_secs(30),
            sink.clone(),
            &tracker,
        )
        .map_err(|_| "reader did not start".to_string())?;

        let status = wait_child(&mut child);
        assert_eq!(status.code(), Some(1), "scene A: helper status {status:?}");
        assert_eq!(
            tracker.wait_idle(IDLE_WAIT),
            0,
            "scene A: reader must stop by EOF"
        );
        sink.wait_idle(IDLE_WAIT);
        let text = text_of(&buf);
        // 段名・errno の欄は無い（生成側が無い現状。入ったらこの期待値を直す）。message は捨てられる。
        assert_eq!(
            text, "{\"event\":\"cri_exec_helper_diagnostic\",\"code\":\"INVALID_ARGUMENT\"}\n",
            "scene A: sink output"
        );
        assert_no_secrets("scene A", &text);
        Ok(())
    }

    /// 本番の spawner と同じ結線で、自分自身を `stream-exec` helper として起動する。
    struct SelfSpawner;

    impl HelperSpawner for SelfSpawner {
        fn spawn(&self, args: &StreamExecArgs) -> Result<SpawnedHelper, CriError> {
            let exe = std::env::current_exe()
                .map_err(|_| CriError::failed_precondition("cannot resolve the test executable"))?;
            spawn_helper_command(stream_exec_command(&exe, args))
        }

        fn capabilities(&self) -> HelperCapabilities {
            HelperCapabilities { tty: false }
        }
    }

    /// 場面 B: 存在しない pid のコンテナを本番の launcher で exec する（supervisor 不在）。
    fn scene_b_dead_pid_via_launcher() -> Result<(), String> {
        let dir = TempDir::new();
        let root = state_root(&dir.0);
        let store: Arc<dyn StateStore> = Arc::new(
            FileStateStore::open(
                StateRoot::from_override(root.clone()).map_err(|e| format!("root: {e:?}"))?,
            )
            .map_err(|e| format!("open: {e:?}"))?,
        );
        let bundle = dir.0.join("bundle");
        std::fs::create_dir_all(bundle.join("rootfs")).map_err(|e| format!("bundle: {e}"))?;
        std::fs::write(bundle.join("config.json"), "{}").map_err(|e| format!("config: {e}"))?;
        let id = ContainerId::new(SENTINEL_ID).expect("id");
        let created = store
            .create(
                &CreateStateRequest::new(ContainerStatus::created(id.clone(), None), bundle)
                    .map_err(|e| format!("req: {e:?}"))?,
            )
            .map_err(|e| format!("create: {e:?}"))?;
        store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id, Some(dead_pid())),
                created.revision(),
            ))
            .map_err(|e| format!("running: {e:?}"))?;

        let (sink, buf) = new_sink();
        let launcher = SupervisorExecLauncher::new(root, Arc::clone(&store), Arc::new(SelfSpawner))
            .with_diagnostic_sink(sink.clone());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))?;
        let result = rt.block_on(async {
            tokio::time::timeout(
                LAUNCH_WAIT,
                launcher.launch(ExecLaunch {
                    container_id: SENTINEL_ID.to_string(),
                    cmd: sentinel_argv(),
                    tty: false,
                    stdin: true,
                    stdout: true,
                    stderr: true,
                }),
            )
            .await
        });
        let err = match result {
            Err(_) => return Err("scene B: launch timed out".to_string()),
            Ok(Ok(_)) => return Err("scene B: launch unexpectedly succeeded".to_string()),
            Ok(Err(e)) => e,
        };
        assert_eq!(err.code(), CriErrorCode::Unavailable, "scene B: {err:?}");
        assert_eq!(
            err.message(),
            "exec helper is unavailable",
            "scene B: message"
        );
        assert_eq!(
            launcher.wait_diagnostics_idle(IDLE_WAIT),
            0,
            "scene B: readers must stop"
        );
        assert_eq!(
            launcher.active_sessions(),
            0,
            "scene B: helper must be reclaimed"
        );
        sink.wait_idle(IDLE_WAIT);
        let text = text_of(&buf);
        let lines: Vec<&str> = text.lines().collect();
        // 生成側が無い現状: `Failed(code)` の `Result` frame だけが返り、fd 2 に転送行は出ない。
        assert_eq!(lines, Vec::<&str>::new(), "scene B: sink lines");
        assert_no_secrets("scene B", &text);
        // エラーメッセージにも秘密を含めない（CRI クライアントへ返る値）。
        assert_no_secrets("scene B error", err.message());
        Ok(())
    }

    type Scene = fn() -> Result<(), String>;

    pub fn main() -> ExitCode {
        // supervisor の bin の `main` と同じ振り分け。helper として再実行されたときはここで終わる。
        let mut args = std::env::args_os().skip(1);
        let first = args.next();
        if is_stream_exec_invocation(first.as_deref()) {
            return run_stream_exec_main(args);
        }
        let mut failed = false;
        let scenes: [(&str, Scene); 2] = [
            ("fd0_not_socket", scene_a_fd0_not_socket),
            ("dead_pid_via_launcher", scene_b_dead_pid_via_launcher),
        ];
        for (name, scene) in scenes {
            match std::panic::catch_unwind(scene) {
                Ok(Ok(())) => println!("exec_helper_failure_diag: {name} ok"),
                Ok(Err(e)) => {
                    eprintln!("exec_helper_failure_diag: {name} FAILED: {e}");
                    failed = true;
                }
                Err(_) => {
                    eprintln!("exec_helper_failure_diag: {name} FAILED: assertion panicked");
                    failed = true;
                }
            }
        }
        if failed {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
    }
}
