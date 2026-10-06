//! plugin-macos の E2E 結合試験（TASK-115.6・#390。PLUG-1・MAC-1・REPAIR-3・REPAIR-5・REPAIR-12）。
//!
//! 「plugin 起動 → UDS 接続 → VM 起動（create / start）→ 停止（stop・切断・終了要求）」を 1 本の流れで通す。
//! 既存の `frame_loop.rs`（フレーム不正・ping 単体・SIGTERM 配送・create 検証エラー）と重複させず、
//! 正常系のライフサイクル全体と終了時の VM 回収だけを扱う。UDS 実体が unix のみのため unix に限定する
//! （Windows では 0 件になる。走っているように見せない。REPAIR-3）。
//!
//! 二層構成（`platform-macos/tests/vm_boot.rs` と同じ流儀）:
//! - 層 A（既定集合）: テスト本体が core 役（`UdsListener` を bind して `accept`）、別スレッドが plugin 役
//!   （peer 認証つき `UdsStream::connect` → `serve_until` → `stop_all`。`main.rs` と同じ実行順）になり、
//!   偽バックエンドの `MacosBackend` で VM 起動・停止を記録する。実バイナリは `PlatformBackend::default()`
//!   固定のため、CI では start の正常系を UDS 越しに通せない穴を、この層が埋める。
//! - 層 B（`#[ignore]`・macOS のみ）: 実バイナリを spawn し、実 VM を plugin 経由で起動・停止する。
//!   必要環境と実行コマンドは `AGENTS.md`「実機前提テスト」節。
//!
//! 待ちはすべて期限つきで、裸の `join()` は使わない（REPAIR-5）。暫定ワイヤー契約（型つき本体は TASK-114 待ち）:
//! create `["create", id, kernel, initrd|"", cmdline, (tag, host_dir, "ro"|"rw")*]` → `["created"]`、
//! start → `["running"]`、stop → `["stopped"]`、ping → `["pong"]`。
#![cfg(unix)]

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_platform_macos::config::VmConfigSpec;
use fandhe_container_plugin::{
    ControlMessage, JsonLinesPeerAuthObserver, MessageId, PluginError, PluginErrorCode, RpcTimeout,
    UdsListener, UdsStream, decode_message, encode_message,
};
use fandhe_container_plugin_macos::adapter::{
    BackendError, MacosBackend, MacosRuntimeAdapter, StopAllSummary,
};
use fandhe_container_plugin_macos::frame_loop::{LoopExit, serve_until};

/// core 役が plugin 役の接続を待つ上限。
const ACCEPT_WAIT: Duration = Duration::from_secs(20);
/// plugin 役スレッド・子プロセスの結果を待つ上限（裸の `join()` で待たない。REPAIR-5）。
const OUTCOME_WAIT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// 共通ヘルパー（層 A・層 B）
// ---------------------------------------------------------------------------

/// 排他作成した 0700 の一時ディレクトリ。Drop で自分が作ったものだけを削除する。
struct TempDir(PathBuf);

impl TempDir {
    /// macOS の `sun_path` 104 バイト上限に収めるため `/tmp` 直下の短い名前にする。
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        for n in 0..100u32 {
            let p =
                PathBuf::from("/tmp").join(format!("fc-e2e-{}-{nanos:x}-{n}", std::process::id()));
            match std::fs::DirBuilder::new().mode(0o700).create(&p) {
                Ok(()) => return Self(p),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create test dir: {e}"),
            }
        }
        panic!("could not create a unique test dir");
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn join_str(&self, name: &str) -> String {
        self.0.join(name).to_str().expect("utf8 path").to_string()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request(id: u64, body: &[&str]) -> fandhe_container_plugin::Frame {
    encode_message(&ControlMessage::Request {
        id: MessageId::new(id),
        body: body.iter().map(|s| s.to_string()).collect::<Vec<String>>(),
    })
    .expect("encode")
}

/// 要求を 1 件送り、応答 1 件を受ける（期限つき）。
fn call(stream: &mut UdsStream, id: u64, body: &[&str]) -> ControlMessage<Vec<String>> {
    stream
        .write_frame(&request(id, body), RpcTimeout::default())
        .expect("write");
    let r = stream.read_frame(RpcTimeout::default()).expect("read");
    decode_message(&r).expect("decode")
}

/// 成功応答の本体を取り出す（`MessageId` の一致も確かめる）。
fn expect_ok(msg: ControlMessage<Vec<String>>, want_id: u64) -> Vec<String> {
    match msg {
        ControlMessage::Response { id, body } => {
            assert_eq!(id.get(), want_id);
            body
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// エラー応答の (code, message) を取り出す（`MessageId` の一致も確かめる）。
fn expect_err(msg: ControlMessage<Vec<String>>, want_id: u64) -> (PluginErrorCode, String) {
    match msg {
        ControlMessage::Error { id, error } => {
            assert_eq!(id.get(), want_id);
            (error.code(), error.message().to_string())
        }
        other => panic!("unexpected {other:?}"),
    }
}

fn one(s: &str) -> Vec<String> {
    vec![s.to_string()]
}

// ---------------------------------------------------------------------------
// 層 A: モッククライアント（core 役）＋偽バックエンド（plugin 役スレッド）
// ---------------------------------------------------------------------------

/// 偽バックエンドの呼び出し記録。
#[derive(Default)]
struct Record {
    launched: Vec<VmConfigSpec>,
    stops: u32,
    /// 真なら launch が VM 生成後の期限切れ相当（`vm_may_exist` が真になる変種）で失敗する。
    fail_launch: bool,
}

/// `MacosBackend` の偽実装。本物の VZ を呼ばず、launch / stop の呼び出しだけを共有記録へ残す。
#[derive(Clone)]
struct TestBackend(Arc<Mutex<Record>>);

impl MacosBackend for TestBackend {
    type Handle = u32;

    fn launch(&self, spec: &VmConfigSpec) -> Result<u32, BackendError> {
        let mut r = self.0.lock().expect("lock");
        if r.fail_launch {
            return Err(BackendError::LaunchTimedOut {
                after: Duration::from_secs(7),
            });
        }
        r.launched.push(spec.clone());
        Ok(u32::try_from(r.launched.len()).expect("small"))
    }

    fn stop(&self, _handle: &u32) -> Result<(), BackendError> {
        self.0.lock().expect("lock").stops += 1;
        Ok(())
    }

    fn stop_timeout(&self) -> Duration {
        Duration::from_millis(100)
    }
}

/// 計測イベントの要点 `(op, error_code, ok_total, err_total)`。
type EventRow = (&'static str, Option<&'static str>, u64, u64);

/// plugin 役の最終結果（`main.rs` の serve → stop_all と同じ順で得る）。
struct Outcome {
    exit: Result<LoopExit, PluginError>,
    summary: StopAllSummary,
    events: Vec<EventRow>,
}

/// core 役のテスト側ハーネス。plugin 役スレッドと UDS で接続済みの状態で始まる。
struct E2e {
    stream: Option<UdsStream>,
    outcome: Receiver<Outcome>,
    record: Arc<Mutex<Record>>,
    stop_flag: Arc<AtomicBool>,
    dir: TempDir,
}

impl E2e {
    fn start() -> Self {
        let dir = TempDir::new();
        let sock = dir.path().join("p.sock");
        let listener = UdsListener::bind(&sock).expect("bind");
        let record = Arc::new(Mutex::new(Record::default()));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let (tx, outcome) = channel();
        {
            let backend = TestBackend(Arc::clone(&record));
            let stop = Arc::clone(&stop_flag);
            // アダプタは `Send` でないため、plugin 役スレッドの中で生成する。
            std::thread::spawn(move || {
                let mut observer = JsonLinesPeerAuthObserver::new();
                let mut stream = UdsStream::connect(&sock, Duration::from_secs(5), &mut observer)
                    .expect("plugin role connect");
                let events: Arc<Mutex<Vec<EventRow>>> = Arc::new(Mutex::new(Vec::new()));
                let sink = Arc::clone(&events);
                let mut adapter = MacosRuntimeAdapter::new(backend).with_op_sink(move |ev| {
                    sink.lock().expect("lock").push((
                        ev.op,
                        ev.error_code,
                        ev.ok_total,
                        ev.err_total,
                    ));
                });
                let exit = serve_until(&mut stream, &mut adapter, &stop);
                let summary = adapter.stop_all();
                let events = events.lock().expect("lock").clone();
                let _ = tx.send(Outcome {
                    exit,
                    summary,
                    events,
                });
            });
        }
        let mut obs = JsonLinesPeerAuthObserver::new();
        let stream = listener.accept(ACCEPT_WAIT, &mut obs).expect("accept");
        Self {
            stream: Some(stream),
            outcome,
            record,
            stop_flag,
            dir,
        }
    }

    fn call(&mut self, id: u64, body: &[&str]) -> ControlMessage<Vec<String>> {
        call(self.stream.as_mut().expect("stream"), id, body)
    }

    /// 0600 のダミー kernel を置き、そのパスを返す。
    fn kernel(&self) -> String {
        let p = self.dir.path().join("kernel");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .and_then(|mut f| std::io::Write::write_all(&mut f, b"k"))
            .expect("write kernel");
        self.dir.join_str("kernel")
    }

    /// 接続を閉じて plugin 役の結果を期限つきで受ける。
    fn disconnect(mut self) -> (Outcome, Arc<Mutex<Record>>) {
        self.stream = None;
        self.wait_outcome()
    }

    fn wait_outcome(self) -> (Outcome, Arc<Mutex<Record>>) {
        match self.outcome.recv_timeout(OUTCOME_WAIT) {
            Ok(o) => (o, self.record),
            Err(RecvTimeoutError::Timeout) => panic!("plugin role did not finish within deadline"),
            Err(RecvTimeoutError::Disconnected) => panic!("plugin role thread panicked"),
        }
    }
}

/// PLUG-1・MAC-1: create → start → stop → ping が同一接続で往復し、切断後は回収対象が残らない。
#[test]
fn task115_6_plug1_mac1_create_start_stop_roundtrip_over_uds() {
    let mut h = E2e::start();
    let k = h.kernel();
    assert_eq!(
        expect_ok(h.call(1, &["create", "c1", &k, "", "console=hvc0"]), 1),
        one("created")
    );
    assert_eq!(expect_ok(h.call(2, &["start", "c1"]), 2), one("running"));
    assert_eq!(expect_ok(h.call(3, &["stop", "c1"]), 3), one("stopped"));
    assert_eq!(expect_ok(h.call(4, &["ping"]), 4), one("pong"));
    let (o, rec) = h.disconnect();
    assert!(matches!(o.exit, Ok(LoopExit::PeerClosed)), "{:?}", o.exit);
    assert_eq!(
        o.summary,
        StopAllSummary {
            stopped: 0,
            remaining: 0
        }
    );
    // ping は計測対象外。create / start / stop が各 1 回成功・失敗 0 回。
    assert_eq!(
        o.events,
        vec![
            ("create", None, 1, 0),
            ("start", None, 1, 0),
            ("stop", None, 1, 0)
        ]
    );
    let rec = rec.lock().expect("lock");
    assert_eq!(rec.launched.len(), 1);
    assert_eq!(rec.launched[0].kernel.as_path(), Path::new(&k));
    assert_eq!(rec.stops, 1);
}

/// MAC-1: stop しないまま切断しても、終了時の `stop_all` が実行中 VM を停止する（VM リークなし）。
#[test]
fn task115_6_mac1_disconnect_with_running_vm_is_stopped_by_stop_all() {
    let mut h = E2e::start();
    let k = h.kernel();
    expect_ok(h.call(1, &["create", "c1", &k, "", ""]), 1);
    expect_ok(h.call(2, &["start", "c1"]), 2);
    let (o, rec) = h.disconnect();
    assert!(matches!(o.exit, Ok(LoopExit::PeerClosed)), "{:?}", o.exit);
    assert_eq!(
        o.summary,
        StopAllSummary {
            stopped: 1,
            remaining: 0
        }
    );
    assert_eq!(rec.lock().expect("lock").stops, 1);
}

/// MAC-1・PLUG-1: 停止フラグ（SIGTERM 相当）は接続が開いたままでも次の受信境界でループを抜け、VM を停止する。
#[test]
fn task115_6_mac1_shutdown_flag_stops_running_vm() {
    let mut h = E2e::start();
    let k = h.kernel();
    expect_ok(h.call(1, &["create", "c1", &k, "", ""]), 1);
    expect_ok(h.call(2, &["start", "c1"]), 2);
    h.stop_flag.store(true, Ordering::SeqCst);
    // 接続は開いたまま（`IDLE_POLL` 1 秒＋余裕の期限内に抜けることを `wait_outcome` が検証する）。
    let (o, rec) = h.wait_outcome();
    assert!(
        matches!(o.exit, Ok(LoopExit::ShutdownRequested)),
        "{:?}",
        o.exit
    );
    assert_eq!(
        o.summary,
        StopAllSummary {
            stopped: 1,
            remaining: 0
        }
    );
    assert_eq!(rec.lock().expect("lock").stops, 1);
}

/// MAC-1: create の virtiofs 共有（タグ・読み取り専用）が VM 起動の仕様としてバックエンドへ届く。
#[test]
fn task115_6_mac1_virtiofs_share_reaches_backend() {
    let mut h = E2e::start();
    let k = h.kernel();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(h.dir.path().join("share"))
        .expect("mkdir share");
    let share = h.dir.join_str("share");
    expect_ok(
        h.call(1, &["create", "c1", &k, "", "", "share0", &share, "ro"]),
        1,
    );
    expect_ok(h.call(2, &["start", "c1"]), 2);
    let (o, rec) = h.disconnect();
    assert_eq!(
        o.summary,
        StopAllSummary {
            stopped: 1,
            remaining: 0
        }
    );
    let rec = rec.lock().expect("lock");
    assert_eq!(rec.launched.len(), 1);
    let shares = rec.launched[0].shares.shares();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].tag.as_str(), "share0");
    assert!(shares[0].access.is_read_only());
}

/// PLUG-1: 状態違反はエラーフレームになるが接続は維持され、固定文言に入力値（id・パス）を反射しない。
#[test]
fn task115_6_plug1_error_frames_keep_connection() {
    let mut h = E2e::start();
    let k = h.kernel();
    let secret_id = "secret-id";
    let (code, msg) = expect_err(h.call(1, &["start", secret_id]), 1);
    assert_eq!(
        (code, msg.as_str()),
        (PluginErrorCode::NotFound, "container not found")
    );
    let (code, msg) = expect_err(h.call(2, &["stop", secret_id]), 2);
    assert_eq!(
        (code, msg.as_str()),
        (PluginErrorCode::NotFound, "container not found")
    );
    expect_ok(h.call(3, &["create", secret_id, &k, "", ""]), 3);
    let (code, msg) = expect_err(h.call(4, &["create", secret_id, &k, "", ""]), 4);
    assert_eq!(
        (code, msg.as_str()),
        (PluginErrorCode::AlreadyExists, "container already exists")
    );
    assert!(!msg.contains(secret_id) && !msg.contains(&k), "{msg}");
    expect_ok(h.call(5, &["start", secret_id]), 5);
    let (code, msg) = expect_err(h.call(6, &["start", secret_id]), 6);
    assert_eq!(
        (code, msg.as_str()),
        (
            PluginErrorCode::FailedPrecondition,
            "container is not in the created state"
        )
    );
    // 失敗のあとも同じ接続で応答する。
    assert_eq!(expect_ok(h.call(7, &["ping"]), 7), one("pong"));
    let (o, _) = h.disconnect();
    assert_eq!(
        o.summary,
        StopAllSummary {
            stopped: 1,
            remaining: 0
        }
    );
}

/// MAC-1・REPAIR-3: VM が作られ得た起動失敗は `TIMEOUT` で報告し、停止を確認できない VM は成功扱いにせず remaining に数える。
#[test]
fn task115_6_mac1_launch_failure_is_reported_and_counted_remaining() {
    let mut h = E2e::start();
    let k = h.kernel();
    h.record.lock().expect("lock").fail_launch = true;
    expect_ok(h.call(1, &["create", "c1", &k, "", ""]), 1);
    let (code, msg) = expect_err(h.call(2, &["start", "c1"]), 2);
    assert_eq!(
        (code, msg.as_str()),
        (PluginErrorCode::Timeout, "VM launch did not finish in time")
    );
    let (o, rec) = h.disconnect();
    assert_eq!(
        o.summary,
        StopAllSummary {
            stopped: 0,
            remaining: 1
        }
    );
    assert_eq!(
        o.events,
        vec![("create", None, 1, 0), ("start", Some("TIMEOUT"), 0, 1)]
    );
    assert_eq!(rec.lock().expect("lock").stops, 0);
}

// ---------------------------------------------------------------------------
// 層 B: 実機前提（実バイナリ＋実 VM。macOS のみ・`#[ignore]`）
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod real_vm {
    use super::*;
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    use fandhe_container_plugin::PLUGIN_SOCKET_ENV;

    const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-macos");

    /// 絶対パスの環境変数を読む。相対パス・非 UTF-8 は panic（要求本体へ未検証で入れない）。
    fn env_abs(name: &str) -> Option<String> {
        let v = std::env::var_os(name)?;
        let s = v
            .into_string()
            .unwrap_or_else(|_| panic!("{name} must be UTF-8"));
        assert!(
            Path::new(&s).is_absolute(),
            "{name} must be an absolute path"
        );
        Some(s)
    }

    /// 子プロセスを Drop で必ず回収する。
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// PLUG-1・MAC-1: 実バイナリを spawn し、plugin 経由で実 VM を起動・停止して終了コード 0 で終わる。
    ///
    /// 実機前提のため `#[ignore]` で既定集合から分離している（CI 通過のための弱体化ではない）。
    /// 共有（virtiofs）は渡さない（ゲスト init 未実装では `guest_mount.timeout` になるため）。
    /// 署名対象は plugin バイナリ。手順は `AGENTS.md`「実機前提テスト」節。
    #[test]
    #[ignore = "requires real macOS 13+ with Virtualization.framework, the plugin binary codesigned with com.apple.security.virtualization, and guest assets; MAC-1 PLUG-1; see AGENTS.md"]
    fn task115_6_plug1_mac1_real_vm_boots_and_stops_via_plugin_binary() {
        let kernel = env_abs("FANDHE_CONTAINER_MACOS_VM_KERNEL").unwrap_or_else(|| {
            panic!(
                "FANDHE_CONTAINER_MACOS_VM_KERNEL (absolute path to a guest kernel) is required. \
                 Optional: FANDHE_CONTAINER_MACOS_VM_INITRD, FANDHE_CONTAINER_MACOS_VM_CMDLINE \
                 (default \"console=hvc0\"). The plugin binary must be codesigned. See AGENTS.md."
            )
        });
        let initrd = env_abs("FANDHE_CONTAINER_MACOS_VM_INITRD").unwrap_or_default();
        let cmdline = std::env::var("FANDHE_CONTAINER_MACOS_VM_CMDLINE")
            .unwrap_or_else(|_| "console=hvc0".to_string());

        let dir = TempDir::new();
        let sock = dir.join_str("p.sock");
        let listener = UdsListener::bind(Path::new(&sock)).expect("bind");
        let mut child = Child(
            Command::new(BIN)
                .env_clear()
                .env(PLUGIN_SOCKET_ENV, &sock)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn"),
        );
        let mut obs = JsonLinesPeerAuthObserver::new();
        let mut stream = listener.accept(ACCEPT_WAIT, &mut obs).expect("accept");

        assert_eq!(expect_ok(call(&mut stream, 1, &["ping"]), 1), one("pong"));
        let body = ["create", "real1", &kernel, &initrd, &cmdline];
        assert_eq!(expect_ok(call(&mut stream, 2, &body), 2), one("created"));
        // 起動期限は adapter 固定の 7 秒。失敗時はまず start の Error フレームのコード（TIMEOUT か）を確認する。
        assert_eq!(
            expect_ok(call(&mut stream, 3, &["start", "real1"]), 3),
            one("running")
        );
        assert_eq!(
            expect_ok(call(&mut stream, 4, &["stop", "real1"]), 4),
            one("stopped")
        );
        drop(stream);

        let start = Instant::now();
        let status = loop {
            if let Some(s) = child.0.try_wait().expect("try_wait") {
                break s;
            }
            assert!(
                start.elapsed() < OUTCOME_WAIT,
                "plugin binary did not exit within deadline"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut err = String::new();
        if let Some(mut s) = child.0.stderr.take() {
            let _ = s.read_to_string(&mut err);
        }
        assert_eq!(status.code(), Some(0), "{err}");
        assert!(err.contains("\"op\":\"start\",\"result\":\"ok\""), "{err}");
        assert!(err.contains("\"op\":\"stop\",\"result\":\"ok\""), "{err}");
        assert!(!err.contains("\"remaining\":"), "{err}");
        assert!(
            !err.contains(&sock) && !err.contains(&kernel),
            "stderr leaks a path: {err}"
        );
    }
}
