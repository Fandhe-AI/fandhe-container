//! 制御チャネルの Attach 用 fd の受け渡し（AttachRequest。kind 9）の結合試験
//! （SUP-4・SUP-7・REPAIR-2・REPAIR-5・SEC-1・CRI-6・#4075）。
//!
//! 実際の UDS の上で、`ControlAttach`（クライアント入口）→ `ControlServer` → `SignalSlot` の入出力と
//! `CaptureHub` の tap を通し、`SCM_RIGHTS` で入力の fd と出力の tap の端が届くことを具体値で照合する。
//! root・実コンテナは不要で既定のテスト集合で動く。コンテナの代わりに、stdin の pipe の読み取り側と出力の pipe の
//! 書き込み側を試験が握る模擬の起動ハンドルを使う。拒否の応答が fd を持たないことは、サーバの `respond`
//! （`write_all`。fd を添える口を持たない）による構造的な保証で、ここでは理由コードとクライアントの写像を照合する。

#![cfg(target_os = "linux")]

use std::io::{Read as _, Write as _};
use std::num::NonZeroU32;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::exec::{PtyMaster, WindowSize, open_host_pty_for_test};
use fandhe_container_core::oci_runtime::{
    ContainerOutput, ContainerStdin, LaunchedProcess, ProcessExit,
};
use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};
use fandhe_container_supervisor::control::listener::{ControlListener, effective_uid};
use fandhe_container_supervisor::control::observe::ControlObserver;
use fandhe_container_supervisor::control::protocol::{
    ATTACH_ROUND_TRIP_BUDGET, AttachMask, AttachRequestFrame, ControlReason, HEADER_LEN,
    RESPONSE_LEN, ResponseFrame, SignalDeadline, encode_hello,
};
use fandhe_container_supervisor::control::server::{ControlServer, ServeConfig};
use fandhe_container_supervisor::control::target::{ControlledProcess, SignalSlot};
use fandhe_container_supervisor::control::{
    AttachInput, AttachIo, AttachIoRequest, AttachIoSource, ControlAttach,
};
use fandhe_container_supervisor::log_pipeline::CaptureHub;
use fandhe_container_supervisor::logs::MemoryLogSink;
use fandhe_container_supervisor::start_contract::StdinOption;

const PID: u32 = 4321;

/// stdin の端と pty master を一度だけ渡す模擬の起動ハンドル。
struct Fake {
    stdin: Mutex<Option<ContainerStdin>>,
    master: Mutex<Option<PtyMaster>>,
}

impl LaunchedProcess for Fake {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(PID).unwrap()
    }
    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        std::thread::sleep(timeout.min(Duration::from_millis(5)));
        Ok(None)
    }
    fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
        Ok(())
    }
    fn take_stdin(&self) -> Option<ContainerStdin> {
        self.stdin.lock().unwrap().take()
    }
    fn take_pty_master(&self) -> Option<PtyMaster> {
        self.master.lock().unwrap().take()
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    /// 0700 で排他的に作る（SEC-1）。
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::DirBuilderExt as _;
        for attempt in 0..64u32 {
            let n = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let p = std::env::temp_dir().join(format!(
                "fc-att-it-{tag}-{}-{n}-{attempt}",
                std::process::id()
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&p) {
                Ok(()) => return Self(p),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create temp root: {e}"),
            }
        }
        panic!("could not create a unique temp root");
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 試験が握る、コンテナ側の端。
struct Container {
    /// コンテナの stdin の読み取り側（非 tty のとき）。
    stdin_r: Option<std::io::PipeReader>,
    /// コンテナの stdout / stderr の書き込み側。
    out_w: Option<std::io::PipeWriter>,
    err_w: Option<std::io::PipeWriter>,
    /// tty の slave（master が EIO にならないように保持する）。
    _slave: Option<fandhe_container_core::exec::PtySlave>,
}

struct Rig {
    root: TempRoot,
    id: ContainerId,
    container: Container,
    hub: Arc<CaptureHub>,
    _process: ControlledProcess,
    _server: ControlServer,
    _listener: ControlListener,
}

struct Setup {
    tag: &'static str,
    stdin: Option<StdinOption>,
    tty: bool,
    /// 捕捉ハブを結線するか。
    hub: bool,
    /// stdin の端を起動ハンドルに持たせるか（非 tty）。
    has_stdin: bool,
}

impl Rig {
    fn start(s: Setup) -> Self {
        let root = TempRoot::new(s.tag);
        let dir = root.0.join(s.tag);
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        }
        let id = ContainerId::new(s.tag).unwrap();
        let listener = ControlListener::bind(&root.0, &id).unwrap();

        let hub = Arc::new(CaptureHub::new(Arc::new(MemoryLogSink::default())));
        let (out_r, out_w) = std::io::pipe().unwrap();
        let (err_r, err_w) = std::io::pipe().unwrap();
        let (err_r, err_w) = if s.tty {
            drop(err_r);
            drop(err_w);
            (None, None)
        } else {
            (Some(err_r), Some(err_w))
        };
        hub.attach(ContainerOutput {
            stdout: Some(Box::new(out_r)),
            stderr: err_r.map(|r| Box::new(r) as Box<dyn std::io::Read + Send>),
        })
        .unwrap();

        let (stdin_r, stdin) = if s.has_stdin && !s.tty {
            let (r, w) = std::io::pipe().unwrap();
            (Some(r), Some(ContainerStdin::from_pipe_writer_for_test(w)))
        } else {
            (None, None)
        };
        let (master, slave) = if s.tty {
            let (m, sl) = open_host_pty_for_test(WindowSize::new(24, 80)).unwrap();
            (Some(m), Some(sl))
        } else {
            (None, None)
        };
        let slot = SignalSlot::new()
            .with_stdin_option(s.stdin)
            .with_output_capture(s.hub.then(|| Arc::clone(&hub)));
        let process = ControlledProcess::new(
            Box::new(Fake {
                stdin: Mutex::new(stdin),
                master: Mutex::new(master),
            }),
            slot.clone(),
        );
        let server = ControlServer::spawn(
            listener.try_clone_listener().unwrap(),
            slot,
            effective_uid().unwrap(),
            ServeConfig::default(),
            Arc::new(ControlObserver::new(None, None)),
        )
        .unwrap();
        Self {
            root,
            id,
            container: Container {
                stdin_r,
                out_w: Some(out_w),
                err_w,
                _slave: slave,
            },
            hub,
            _process: process,
            _server: server,
            _listener: listener,
        }
    }

    fn obtain(&self, pid: u32, req: AttachIoRequest) -> Result<AttachIo, TraitError> {
        ControlAttach::new(self.root.0.clone()).obtain(
            &self.id,
            NonZeroU32::new(pid).unwrap(),
            req,
            Instant::now() + Duration::from_secs(5),
        )
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.container.out_w.take();
        self.container.err_w.take();
        let _ = self.hub.finish(Duration::from_secs(5));
    }
}

fn req(stdin: bool, stdout: bool, stderr: bool, tty: bool) -> AttachIoRequest {
    AttachIoRequest {
        stdin,
        stdout,
        stderr,
        tty,
    }
}

fn read_exactly(stream: &mut UnixStream, len: usize) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).unwrap();
    buf
}

/// `/proc/self/fdinfo/<n>` の `flags`（8 進）に `O_CLOEXEC`（02000000）が立っているか。
fn is_cloexec(fd: &impl std::os::fd::AsRawFd) -> bool {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).unwrap();
    let flags = text
        .lines()
        .find_map(|l| l.strip_prefix("flags:"))
        .map(str::trim)
        .unwrap();
    u32::from_str_radix(flags, 8).unwrap() & 0o2000000 != 0
}

/// SUP-4・SUP-7・REPAIR-2・SEC-1・CRI-6・#4075: 非 tty の `--stdin open` で、入力・stdout・stderr の 3 本が届き、
/// 入力に書いたバイトがコンテナの stdin に、コンテナの出力が tap に具体値で届く。受け取った fd は close-on-exec。
#[test]
fn sup4_sup7_4075_open_delivers_input_and_both_taps() {
    let mut rig = Rig::start(Setup {
        tag: "open3",
        stdin: Some(StdinOption::Open),
        tty: false,
        hub: true,
        has_stdin: true,
    });
    let io = rig.obtain(PID, req(true, true, true, false)).unwrap();
    let Some(AttachInput::Pipe(input)) = io.input else {
        panic!("expected a pipe input");
    };
    assert!(is_cloexec(&input));
    let mut stdout = io.stdout.unwrap();
    let mut stderr = io.stderr.unwrap();
    assert!(is_cloexec(&stdout) && is_cloexec(&stderr));

    let mut file = std::fs::File::from(input);
    file.write_all(b"typed-by-attach").unwrap();
    let mut got = vec![0u8; 15];
    rig.container
        .stdin_r
        .as_mut()
        .unwrap()
        .read_exact(&mut got)
        .unwrap();
    assert_eq!(got, b"typed-by-attach");

    rig.container
        .out_w
        .as_mut()
        .unwrap()
        .write_all(b"out-bytes$ ")
        .unwrap();
    rig.container
        .err_w
        .as_mut()
        .unwrap()
        .write_all(b"err-bytes")
        .unwrap();
    assert_eq!(read_exactly(&mut stdout, 11), b"out-bytes$ ");
    assert_eq!(read_exactly(&mut stderr, 9), b"err-bytes");

    // `Open` は繰り返し受け取れる。
    let again = rig.obtain(PID, req(true, false, false, false)).unwrap();
    assert!(matches!(again.input, Some(AttachInput::Pipe(_))));
    assert!(again.stdout.is_none() && again.stderr.is_none());
}

/// SUP-7・SEC-1・CRI-6・#4075（D5）: `stdin_once` は 1 回目で唯一の書き込み端が移り、受け手が閉じるとコンテナの
/// stdin が EOF になる。2 回目は `StdinClosed` で fd は 0 本。
#[test]
fn sup7_cri6_4075_once_moves_sole_write_end() {
    let mut rig = Rig::start(Setup {
        tag: "once",
        stdin: Some(StdinOption::Once),
        tty: false,
        hub: true,
        has_stdin: true,
    });
    let io = rig.obtain(PID, req(true, false, false, false)).unwrap();
    let Some(AttachInput::Pipe(input)) = io.input else {
        panic!("expected a pipe input");
    };
    std::fs::File::from(input).write_all(b"once").unwrap();
    let r = rig.container.stdin_r.as_mut().unwrap();
    let mut got = [0u8; 4];
    r.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"once");
    // 受け手が（File の drop で）閉じた。サーバも送信後に自分の端を閉じているので、読み取り側は EOF になる。
    let mut rest = Vec::new();
    r.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());

    let e = rig.obtain(PID, req(true, false, false, false)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(
        e.message(),
        "the container stdin was already consumed by an attach"
    );
}

/// CRI-6・SEC-1・#4075: tty では master の複製が届き（`PtyMaster::from_received` を通る）、`stdin_once` でも
/// 消費済みにならず 2 回目も届く。tty と stderr の併用はクライアントが接続せず `InvalidArgument`。
#[test]
fn cri6_4075_tty_delivers_master_dup_every_time() {
    let rig = Rig::start(Setup {
        tag: "tty",
        stdin: Some(StdinOption::Once),
        tty: true,
        hub: true,
        has_stdin: false,
    });
    for _ in 0..2 {
        let io = rig.obtain(PID, req(true, true, false, true)).unwrap();
        let Some(AttachInput::Pty(master)) = io.input else {
            panic!("expected a pty master");
        };
        assert!(is_cloexec(&master.as_fd().try_clone_to_owned().unwrap()));
        assert!(io.stdout.is_some() && io.stderr.is_none());
        master.resize(WindowSize::new(30, 100)).unwrap();
    }
    let e = rig.obtain(PID, req(true, true, true, true)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
}

/// SUP-4・SEC-1・#4075: 拒否の理由コードとクライアントの写像（pid 不一致・`--stdin` なし・tty の不一致・
/// ハブなし・購読の上限）。
#[test]
fn sup4_sec1_4075_rejections_map_to_fixed_errors() {
    let rig = Rig::start(Setup {
        tag: "rej",
        stdin: None,
        tty: false,
        hub: true,
        has_stdin: true,
    });
    let e = rig
        .obtain(PID + 1, req(false, true, false, false))
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(
        e.message(),
        "the process id does not match the launched process"
    );
    let e = rig.obtain(PID, req(true, true, false, false)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "the container was not created with stdin open");
    let e = rig.obtain(PID, req(false, true, false, true)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(
        e.message(),
        "the requested tty mode does not match the container"
    );

    // 購読の上限（8）。保持し続けると 9 件目は Busy。
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(rig.obtain(PID, req(false, true, false, false)).unwrap());
    }
    let e = rig.obtain(PID, req(false, true, false, false)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unavailable);
    assert_eq!(e.message(), "the supervisor control channel is busy");
    drop(held);

    let no_hub = Rig::start(Setup {
        tag: "nohub",
        stdin: Some(StdinOption::Open),
        tty: false,
        hub: false,
        has_stdin: true,
    });
    let e = no_hub
        .obtain(PID, req(false, true, false, false))
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "the supervisor holds no launched process");
}

/// 生の接続で Hello を受け、`frame` を送り、Response の理由コードを読む。
fn raw_exchange(rig: &Rig, frame: &[u8]) -> ControlReason {
    let path = rig.root.0.join(rig.id.as_str()).join("supervisor.sock");
    let mut s = UnixStream::connect(path).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut hello = [0u8; HEADER_LEN];
    s.read_exact(&mut hello).unwrap();
    assert_eq!(hello, encode_hello());
    s.write_all(frame).unwrap();
    let mut resp = [0u8; RESPONSE_LEN];
    s.read_exact(&mut resp).unwrap();
    let expected_head: [u8; HEADER_LEN] = [b'F', b'C', b'S', b'C', 1, 3, 0, 1];
    assert_eq!(resp.get(..HEADER_LEN), Some(&expected_head[..]));
    ControlReason::from_u8(*resp.last().unwrap()).unwrap()
}

/// REPAIR-2・REPAIR-5・#4075（受け入れ基準 2）: 往復の上限は 5 秒。残りが 5 秒を超える期限を載せた生の要求は
/// `Malformed`（読み取りの実行前に断る）。知らない kind 10 も `Malformed`（古い supervisor が kind 9 に返すのと同じ）。
#[test]
fn repair5_4075_budget_is_five_seconds_and_unknown_kind_is_malformed() {
    assert_eq!(ATTACH_ROUND_TRIP_BUDGET, Duration::from_secs(5));
    let rig = Rig::start(Setup {
        tag: "budget",
        stdin: Some(StdinOption::Open),
        tty: false,
        hub: true,
        has_stdin: true,
    });
    let frame = |secs: u64| {
        AttachRequestFrame::new(
            NonZeroU32::new(PID).unwrap(),
            AttachMask::new(false, true, false).unwrap(),
            false,
            SignalDeadline::from_now(Duration::from_secs(secs)).unwrap(),
        )
        .unwrap()
        .encode()
    };
    assert_eq!(raw_exchange(&rig, &frame(8)), ControlReason::Malformed);
    assert_eq!(raw_exchange(&rig, &frame(3)), ControlReason::Ok);
    let mut unknown = vec![b'F', b'C', b'S', b'C', 1, 10, 0, 14];
    unknown.extend_from_slice(&[0u8; 14]);
    assert_eq!(raw_exchange(&rig, &unknown), ControlReason::Malformed);
}

/// 偽のサーバ。Hello を送り、要求を読み、`reply` 通りに応える（`None` なら応えずに待つ）。
fn fake_server(
    tag: &str,
    reply: Option<ControlReason>,
) -> (TempRoot, ContainerId, std::thread::JoinHandle<()>) {
    let root = TempRoot::new(tag);
    let dir = root.0.join(tag);
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    }
    let id = ContainerId::new(tag).unwrap();
    let listener = ControlListener::bind(&root.0, &id).unwrap();
    let l = listener.try_clone_listener().unwrap();
    l.set_nonblocking(false).unwrap();
    let handle = std::thread::spawn(move || {
        let _keep = listener;
        let Ok((mut s, _)) = l.accept() else { return };
        s.write_all(&encode_hello()).unwrap();
        let mut req = [0u8; HEADER_LEN + 14];
        s.read_exact(&mut req).unwrap();
        match reply {
            Some(reason) => s.write_all(&ResponseFrame { reason }.encode()).unwrap(),
            // 応えずに相手が閉じるまで待つ。
            None => {
                let mut b = [0u8; 1];
                let _ = s.read(&mut b);
            }
        }
    });
    (root, id, handle)
}

/// SUP-4・REPAIR-2・SEC-1・#4075（受け入れ基準 1）: 古い supervisor が kind 9 に返す `Malformed`（と `TooLarge`・
/// `UnsupportedVersion`）を、クライアントは「届かない」（`Unavailable`）として扱い、別の手段へ切り替えない。
#[test]
fn sup4_4075_old_supervisor_malformed_is_unavailable() {
    for (i, reason) in [
        ControlReason::Malformed,
        ControlReason::TooLarge,
        ControlReason::UnsupportedVersion,
    ]
    .into_iter()
    .enumerate()
    {
        let tag = format!("old{i}");
        let (root, id, handle) = fake_server(&tag, Some(reason));
        let e = ControlAttach::new(root.0.clone())
            .obtain(
                &id,
                NonZeroU32::new(PID).unwrap(),
                req(true, true, false, false),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::Unavailable, "{reason:?}");
        assert_eq!(e.message(), "the supervisor does not support attach");
        handle.join().unwrap();
    }
}

/// REPAIR-5・#4075: Hello の後に応答しない supervisor に対して、短い期限で `Timeout` が期限の近くで返る
/// （5 秒は待たない）。
#[test]
fn repair5_4075_unresponsive_supervisor_times_out_at_deadline() {
    let (root, id, handle) = fake_server("hang", None);
    let started = Instant::now();
    let e = ControlAttach::new(root.0.clone())
        .obtain(
            &id,
            NonZeroU32::new(PID).unwrap(),
            req(false, true, false, false),
            Instant::now() + Duration::from_millis(300),
        )
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Timeout);
    assert!(started.elapsed() < Duration::from_secs(3));
    handle.join().unwrap();
}

/// REPAIR-3・SEC-1・#4075: 状態ルートを公開しないストア用の取得元は `Unimplemented`（縮退しない）。
#[test]
fn repair3_4075_unavailable_source_is_unimplemented() {
    use fandhe_container_supervisor::control::UnavailableAttachIoSource;
    let id = ContainerId::new("x").unwrap();
    let e = UnavailableAttachIoSource
        .obtain(
            &id,
            NonZeroU32::new(1).unwrap(),
            req(true, true, false, false),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unimplemented);
}
