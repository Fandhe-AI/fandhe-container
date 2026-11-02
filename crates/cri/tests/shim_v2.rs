//! containerd 経由の shim v2 疎通確認（CRI-5・TASK-62.6・MS-7・#676）。
//!
//! 確認するのは shim v2 のプロトコル水準の疎通（containerd の起動規約〔start の stdout のアドレス〕、ttrpc の枠、
//! Create / Connect / Start / Wait / State / Delete / Shutdown の意味論、終了コードの伝搬）で、実コンテナの実行ではない。
//! 配布する shim バイナリ（`containerd-shim-fandhe-container-v2`）には実行層が結線されていない
//! （cri は plugin-cri に依存できない。bootstrap の doc を参照。REPAIR-3）ため、この試験バイナリ自身が shim 役を兼ね、
//! メモリ上の偽 `ContainerRuntime` を包んだ `TaskService` を `bootstrap::run` へ渡す。shim 役になるのは
//! `FANDHE_CONTAINER_SHIM_V2_E2E_ROLE=shim` があるときだけで、試験役が偶然 shim として振る舞うことはない。
//!
//! 構成（`harness = false`）:
//! - 既定（非 root・CI で走る）: containerd と同じ呼び出し順を (1) 同一プロセスの UDS サーバーと (2) 試験バイナリ自身の
//!   shim 役（start → デーモン → Shutdown）へ通す。containerd を使う前段の配線不良をここで検出する
//! - `--ignored`（Linux・root・containerd 2.0 以上と ctr が必要。人間が実行する。AGENTS.md「実機前提テスト」）:
//!   私設の containerd を起動し、`ctr run --rm --runtime <この試験バイナリ>` で Create → Start → Wait → Delete を
//!   containerd に駆動させる。前提が欠ければ 1 行目 `PRECONDITION FAILED` で非 0（skip しない）
//!
//! 期限（REPAIR-5）: 子プロセスの待ちはすべて期限つきで、全体にも watchdog（180 秒）を置く。

#[cfg(unix)]
#[path = "../../core/tests/support/reap.rs"]
mod reap;
#[cfg(unix)]
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

#[cfg(not(unix))]
fn main() {
    // listener と bootstrap は unix のみ（Windows の named pipe は範囲外。REPAIR-3）。
    println!("shim_v2: not applicable on this OS");
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    e2e::main()
}

#[cfg(unix)]
mod e2e {
    use std::collections::HashMap;
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::num::NonZeroU32;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use fandhe_container_core::traits::{
        ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest as RtDelete,
        DeleteResponse as RtDeleteResponse, ErrorCode, KillRequest as RtKill,
        StartRequest as RtStart, StateRequest as RtState, StopRequest, TraitError,
    };
    use fandhe_container_cri::adapter::RuntimeAdapter;
    use fandhe_container_cri::error::CriError;
    use fandhe_container_cri::shim_v2::bootstrap::{parse_args, run};
    use fandhe_container_cri::shim_v2::{
        CallContext, ConnectRequest, ConnectResponse, CreateTaskRequest, DeleteRequest,
        DeleteResponse, FrameHeader, HEADER_LEN, MessageType, RpcStatus, ServerConfig,
        ServiceRegistry, ShutdownRequest, ShutdownSignal, StartRequest, StartResponse,
        StateRequest, StateResponse, TaskApiVersion, TaskService, TaskStatus, TtrpcRequest,
        TtrpcResponse, TtrpcServer, TtrpcService, WaitRequest, WaitResponse,
    };
    use prost::Message;

    use super::{reap, test_root};

    /// この環境変数が `shim` のときだけ、試験バイナリが containerd から exec された shim として振る舞う。
    const ROLE_ENV: &str = "FANDHE_CONTAINER_SHIM_V2_E2E_ROLE";
    /// shim 役が RPC の記録を追記するファイルの絶対パス。
    const TRACE_ENV: &str = "FANDHE_CONTAINER_SHIM_V2_E2E_TRACE";
    /// `bootstrap` の socket 置き場所の上書き。
    const SOCKET_DIR_ENV: &str = "FANDHE_CONTAINER_SHIM_SOCKET_DIR";
    /// 偽ランタイムが Start から Stopped へ移るまでの時間。Wait が Start より前に張られることを確かめる余地になる。
    const RUN_FOR: Duration = Duration::from_millis(200);
    /// 偽ランタイムの終了コード。containerd を通って `ctr` の終了コードへ伝わることの証跡にする。
    const EXIT_CODE: i32 = 42;
    const WATCHDOG: Duration = Duration::from_secs(180);
    const SVC_V2: &str = "containerd.task.v2.Task";
    const SVC_V3: &str = "containerd.task.v3.Task";

    // ---- 偽ランタイム（shim 役のデーモンの中で動く） ----

    #[derive(Clone, Copy, PartialEq)]
    enum Life {
        Created,
        Running(Instant),
        Stopped(i32),
    }

    /// 状態だけを持つ偽ランタイム。実プロセスは作らず、シグナルも送らない。
    ///
    /// pid にはデーモン自身の pid を返す（実在する pid で、task monitor を無効にした構成の containerd は
    /// pid を使わない。Connect の `task_pid` と Start の応答が一致することの照合にも使う）。
    #[derive(Default)]
    struct Fake {
        entries: Mutex<HashMap<String, Life>>,
    }

    struct Shared(Arc<Fake>);

    fn not_found() -> TraitError {
        TraitError::new(ErrorCode::NotFound, "no such container")
    }

    impl ContainerRuntime for Shared {
        fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
            let mut m = self.0.entries.lock().unwrap();
            if m.contains_key(r.id().as_str()) {
                return Err(TraitError::new(ErrorCode::AlreadyExists, "exists"));
            }
            m.insert(r.id().as_str().to_owned(), Life::Created);
            Ok(ContainerStatus::created(r.id().clone(), None))
        }
        fn start(&self, r: &RtStart) -> Result<ContainerStatus, TraitError> {
            let mut m = self.0.entries.lock().unwrap();
            match m.get_mut(r.id().as_str()) {
                None => Err(not_found()),
                Some(l @ Life::Created) => {
                    *l = Life::Running(Instant::now());
                    Ok(ContainerStatus::running(
                        r.id().clone(),
                        NonZeroU32::new(std::process::id()),
                    ))
                }
                Some(_) => Err(TraitError::new(ErrorCode::FailedPrecondition, "state")),
            }
        }
        fn kill(&self, r: &RtKill) -> Result<ContainerStatus, TraitError> {
            if let Some(l) = self.0.entries.lock().unwrap().get_mut(r.id().as_str()) {
                *l = Life::Stopped(137);
            }
            self.state(&RtState::new(r.id().clone()))
        }
        fn stop(&self, r: &StopRequest) -> Result<ContainerStatus, TraitError> {
            if let Some(l) = self.0.entries.lock().unwrap().get_mut(r.id().as_str()) {
                *l = Life::Stopped(137);
            }
            self.state(&RtState::new(r.id().clone()))
        }
        fn delete(&self, r: &RtDelete) -> Result<RtDeleteResponse, TraitError> {
            let mut m = self.0.entries.lock().unwrap();
            match m.get(r.id().as_str()) {
                None => Err(not_found()),
                Some(Life::Running(_)) => {
                    Err(TraitError::new(ErrorCode::FailedPrecondition, "running"))
                }
                Some(_) => {
                    m.remove(r.id().as_str());
                    Ok(RtDeleteResponse::new())
                }
            }
        }
        fn state(&self, r: &RtState) -> Result<ContainerStatus, TraitError> {
            let mut m = self.0.entries.lock().unwrap();
            let l = m.get_mut(r.id().as_str()).ok_or_else(not_found)?;
            if let Life::Running(at) = *l
                && at.elapsed() >= RUN_FOR
            {
                *l = Life::Stopped(EXIT_CODE);
            }
            Ok(match *l {
                Life::Created => ContainerStatus::created(r.id().clone(), None),
                Life::Running(_) => {
                    ContainerStatus::running(r.id().clone(), NonZeroU32::new(std::process::id()))
                }
                Life::Stopped(c) => ContainerStatus::stopped(r.id().clone(), Some(c)),
            })
        }
    }

    // ---- RPC の記録 ----

    /// `TaskService` を包み、各 RPC の開始行と結果行を記録先へ追記する薄いデコレータ。
    ///
    /// 記録の失敗は RPC の結果を変えない。結果行を RPC の後に書くため、デーモンが終了する Shutdown だけは
    /// 開始行（`Shutdown begin`）で到達を判定する。
    struct Traced {
        inner: TaskService,
        trace: Option<PathBuf>,
    }

    impl Traced {
        fn line(&self, text: &str) {
            let Some(p) = &self.trace else { return };
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .custom_flags(nofollow())
                .open(p);
            if let Ok(mut f) = f {
                let _ = f.write_all(format!("{text}\n").as_bytes());
            }
        }
        fn result(&self, method: &str, r: &Result<Vec<u8>, RpcStatus>) {
            match r {
                Ok(_) => self.line(&format!("{method} ok")),
                Err(s) => self.line(&format!("{method} code={}", s.code)),
            }
        }
    }

    fn nofollow() -> i32 {
        // O_NOFOLLOW（Linux 0o400000 / macOS 0x100）。libc に依存しないため定数で持つ。
        if cfg!(target_os = "linux") {
            0o400000
        } else {
            0x100
        }
    }

    impl TtrpcService for Traced {
        fn name(&self) -> &str {
            self.inner.name()
        }
        fn handle(&self, method: &str, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
            self.line(&format!("{method} begin"));
            let r = self.inner.handle(method, payload);
            self.result(method, &r);
            r
        }
        fn handle_with_context(
            &self,
            method: &str,
            payload: &[u8],
            ctx: &CallContext<'_>,
        ) -> Result<Vec<u8>, RpcStatus> {
            self.line(&format!("{method} begin"));
            let r = self.inner.handle_with_context(method, payload, ctx);
            self.result(method, &r);
            r
        }
    }

    /// 記録先の環境変数を検証して解釈する（絶対パスで NUL を含まないものだけ）。
    fn parse_trace(v: Option<std::ffi::OsString>) -> Option<PathBuf> {
        let p = PathBuf::from(v?);
        (p.is_absolute() && !p.to_string_lossy().contains('\0')).then_some(p)
    }

    fn registry(signal: ShutdownSignal) -> Result<ServiceRegistry, CriError> {
        let adapter = RuntimeAdapter::from_runtime(Shared(Arc::new(Fake::default())));
        let trace = parse_trace(std::env::var_os(TRACE_ENV));
        let v2 =
            TaskService::new(TaskApiVersion::V2, adapter.clone()).with_shutdown(signal.clone());
        let v3 = TaskService::new(TaskApiVersion::V3, adapter)
            .with_shutdown(signal)
            .with_shared_created(&v2);
        let mut reg = ServiceRegistry::new();
        for inner in [v2, v3] {
            let svc = Traced {
                inner,
                trace: trace.clone(),
            };
            reg.register(Arc::new(svc))
                .map_err(|_| CriError::internal("cannot register task service"))?;
        }
        Ok(reg)
    }

    /// shim 役の本体。出力と終了コードの契約は `src/bin/shim_v2_main.rs` と同じ
    /// （成功は stdout へバイト列だけ、失敗は stderr へ JSON 1 行と終了コード 1）。
    /// デーモンの起動時に単一スレッドであることが要る（監査 relay の fork）ため、スレッドを作る前に呼ぶ。
    fn shim_role() -> ExitCode {
        let result = parse_args(std::env::args_os().skip(1)).and_then(|inv| run(inv, registry));
        match result {
            Ok(bytes) => {
                let mut out = std::io::stdout();
                if out.write_all(&bytes).and_then(|()| out.flush()).is_err() {
                    return ExitCode::FAILURE;
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                let line = serde_json::json!({"code": e.code().as_str(), "message": e.message()});
                eprintln!("{line}");
                ExitCode::FAILURE
            }
        }
    }

    // ---- ttrpc クライアント ----

    struct Client {
        s: UnixStream,
        sid: u32,
    }

    impl Client {
        fn connect(path: &Path) -> Self {
            let s = UnixStream::connect(path).expect("connect to shim socket");
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            Self { s, sid: 1 }
        }
        fn call(&mut self, svc: &str, method: &str, payload: Vec<u8>) -> TtrpcResponse {
            let body = TtrpcRequest {
                service: svc.into(),
                method: method.into(),
                payload,
                ..Default::default()
            }
            .encode_to_vec();
            let h = FrameHeader::new(body.len() as u32, self.sid, MessageType::Request, 0).unwrap();
            self.sid += 2;
            self.s.write_all(&h.to_bytes()).unwrap();
            self.s.write_all(&body).unwrap();
            let mut hb = [0u8; HEADER_LEN];
            self.s.read_exact(&mut hb).unwrap();
            let h = FrameHeader::from_bytes(&hb).unwrap();
            let mut rb = vec![0u8; h.length() as usize];
            self.s.read_exact(&mut rb).unwrap();
            TtrpcResponse::decode(&rb[..]).unwrap()
        }
        fn ok<M: Message + Default>(&mut self, svc: &str, method: &str, req: impl Message) -> M {
            let r = self.call(svc, method, req.encode_to_vec());
            assert!(r.status.is_none(), "{method}: {:?}", r.status);
            M::decode(&r.payload[..]).unwrap()
        }
    }

    /// containerd の `ctr run --rm` と同じ順序で Task API を通し、各応答を具体値で照合する。
    ///
    /// 順序は Create → Connect（Create 直後の PID 取得）→ Wait（別接続・Start より前）→ Start → Connect → Wait の完了
    /// → State → Delete → Shutdown（containerd v2.1.4 の `shimTask` の呼び出し順。TASK-62.6）。返り値は Connect が返した shim の pid。
    fn drive(sock: &Path, svc: &str, id: &str, trace: &Path) -> u32 {
        let mut c = Client::connect(sock);
        let bundle = std::env::temp_dir().join("shim-v2-e2e-bundle");
        let _: fandhe_container_cri::shim_v2::CreateTaskResponse = c.ok(
            svc,
            "Create",
            CreateTaskRequest {
                id: id.into(),
                bundle: bundle.to_string_lossy().into_owned(),
                ..Default::default()
            },
        );
        let conn: ConnectResponse = c.ok(svc, "Connect", ConnectRequest { id: id.into() });
        assert_eq!((conn.task_pid, conn.version.as_str()), (0, ""));
        assert_ne!(conn.shim_pid, 0);

        let sock_w = sock.to_path_buf();
        let (svc_w, id_w) = (svc.to_owned(), id.to_owned());
        let waiter = std::thread::spawn(move || {
            let mut w = Client::connect(&sock_w);
            let r: WaitResponse = w.ok(
                &svc_w,
                "Wait",
                WaitRequest {
                    id: id_w,
                    exec_id: String::new(),
                },
            );
            r.exit_status
        });
        // Wait がサーバーへ届いたこと（記録の `Wait begin`）を期限つきで確かめてから Start を送る。
        assert!(
            wait_until(Duration::from_secs(10), || {
                std::fs::read_to_string(trace).is_ok_and(|t| t.lines().any(|l| l == "Wait begin"))
            }),
            "Wait must reach the server before Start"
        );
        let started: StartResponse = c.ok(
            svc,
            "Start",
            StartRequest {
                id: id.into(),
                exec_id: String::new(),
            },
        );
        assert_eq!(
            started.pid, conn.shim_pid,
            "fake runtime reports the daemon pid"
        );
        let conn2: ConnectResponse = c.ok(svc, "Connect", ConnectRequest { id: id.into() });
        assert_eq!(
            (conn2.shim_pid, conn2.task_pid),
            (conn.shim_pid, started.pid)
        );
        assert_eq!(waiter.join().expect("wait thread"), EXIT_CODE as u32);

        let st: StateResponse = c.ok(
            svc,
            "State",
            StateRequest {
                id: id.into(),
                exec_id: String::new(),
            },
        );
        assert_eq!(
            (st.id.as_str(), st.status, st.exit_status),
            (id, TaskStatus::Stopped as i32, EXIT_CODE as u32)
        );
        let del: DeleteResponse = c.ok(
            svc,
            "Delete",
            DeleteRequest {
                id: id.into(),
                exec_id: String::new(),
            },
        );
        assert_eq!(del.exit_status, EXIT_CODE as u32);
        let gone = c.call(
            svc,
            "State",
            StateRequest {
                id: id.into(),
                exec_id: String::new(),
            }
            .encode_to_vec(),
        );
        assert_eq!(
            gone.status.map(|s| s.code),
            Some(5),
            "deleted container is NOT_FOUND"
        );
        let sd = c.call(
            svc,
            "Shutdown",
            ShutdownRequest {
                id: id.into(),
                now: false,
            }
            .encode_to_vec(),
        );
        assert!(sd.status.is_none(), "{:?}", sd.status);
        conn.shim_pid
    }

    // ---- 小さな補助 ----

    /// 子プロセスの pid。watchdog が期限切れで止める対象（REPAIR-5）。
    static CHILDREN: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    /// 今回の試験プロセスが shim として起動した ID（pid を含み一意）。watchdog とガードが停止対象を絞る根拠。
    static SHIM_IDS: Mutex<Vec<String>> = Mutex::new(Vec::new());

    /// shim デーモンの追跡ガード。panic で巻き戻っても期限つきで停止し、消滅を確認する。
    struct DaemonGuard(String);

    impl DaemonGuard {
        fn new(id: &str) -> Self {
            if let Ok(mut g) = SHIM_IDS.lock() {
                g.push(id.to_owned());
            }
            Self(id.to_owned())
        }
    }

    impl Drop for DaemonGuard {
        fn drop(&mut self) {
            #[cfg(target_os = "linux")]
            {
                let pids = leftover_shims(&self.0);
                for pid in &pids {
                    kill_pid("KILL", *pid);
                }
                let _ = wait_until(Duration::from_secs(10), || {
                    pids.iter().all(|p| !pid_alive(*p))
                });
            }
        }
    }

    fn kill_pid(sig: &str, pid: u32) {
        let mut cmd = Command::new("kill");
        cmd.arg(format!("-{sig}")).arg(pid.to_string());
        let _ = reap::run_within(&mut cmd, Duration::from_secs(5));
    }

    fn watchdog() {
        let spawned = std::thread::Builder::new()
            .name("watchdog".into())
            .spawn(|| {
                std::thread::sleep(WATCHDOG);
                for pid in CHILDREN.lock().map(|g| g.clone()).unwrap_or_default() {
                    kill_pid("KILL", pid);
                }
                // 今回の試験が起動した ID の shim だけを止める（並行実行中の別の試験は巻き込まない）。
                #[cfg(target_os = "linux")]
                for id in SHIM_IDS.lock().map(|g| g.clone()).unwrap_or_default() {
                    for pid in leftover_shims(&id) {
                        kill_pid("KILL", pid);
                    }
                }
                eprintln!("shim_v2: WATCHDOG EXPIRED after {}s", WATCHDOG.as_secs());
                std::process::exit(124);
            });
        if spawned.is_err() {
            eprintln!("shim_v2: cannot start watchdog");
            std::process::exit(1);
        }
    }

    /// 試験用ディレクトリ（sun_path の制約のため短い /tmp 直下に 0700 で排他作成する）。
    fn scratch(tag: &str) -> test_root::TestRoot {
        test_root::test_root_at(PathBuf::from(format!(
            "/tmp/fcs-{tag}-{}",
            std::process::id()
        )))
    }

    fn wait_until(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
        let end = Instant::now() + limit;
        loop {
            if f() {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// pid が生きているか。Linux は `/proc/<pid>/stat` の状態（ゾンビは死亡扱い）、他は不明として生存扱いにしない。
    fn pid_alive(pid: u32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(s) => s
                .rsplit_once(')')
                .and_then(|(_, rest)| rest.trim_start().chars().next())
                .is_some_and(|c| c != 'Z'),
            Err(_) => false,
        }
    }

    /// 自分の試験バイナリで動いている shim デーモンの pid（cmdline が `-id <id>` を含むもの）。
    #[cfg(target_os = "linux")]
    fn leftover_shims(id: &str) -> Vec<u32> {
        let Ok(me) = std::env::current_exe() else {
            return Vec::new();
        };
        let Ok(rd) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        let own = std::process::id();
        let needle = format!("-id\0{id}\0");
        rd.flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .filter(|&pid| pid != own)
            .filter(|pid| std::fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|p| p == me))
            .filter(|pid| {
                std::fs::read(format!("/proc/{pid}/cmdline"))
                    .is_ok_and(|c| String::from_utf8_lossy(&c).contains(needle.as_str()))
            })
            .collect()
    }

    // ---- 既定のケース ----

    /// (1) containerd と同じ順序を同一プロセスの UDS サーバーへ通す。
    fn case_call_order_in_process() {
        for (svc, version, tag) in [
            (SVC_V2, TaskApiVersion::V2, "ip2"),
            (SVC_V3, TaskApiVersion::V3, "ip3"),
        ] {
            let root = scratch(tag);
            let path = root.join("s.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let signal = ShutdownSignal::new();
            let mut reg = ServiceRegistry::new();
            let adapter = RuntimeAdapter::from_runtime(Shared(Arc::new(Fake::default())));
            let trace = root.join("trace");
            reg.register(Arc::new(Traced {
                inner: TaskService::new(version, adapter).with_shutdown(signal.clone()),
                trace: Some(trace.clone()),
            }))
            .unwrap();
            let handle = TtrpcServer::new(reg, ServerConfig::default())
                .serve(listener)
                .unwrap();
            let shim_pid = drive(&path, svc, "c1", &trace);
            assert_eq!(shim_pid, std::process::id());
            assert!(signal.is_requested(), "Shutdown must request daemon exit");
            assert!(handle.wait_idle(Duration::from_secs(5)));
            drop(handle);
        }
        println!("shim_v2: in-process call order ok");
    }

    /// (2) この試験バイナリ自身を shim 役として start → 順序の通し → Shutdown でデーモンが消えるまで確かめる。
    fn case_self_as_shim_bootstrap() {
        let root = scratch("bs");
        let id = format!("e2e{}", std::process::id());
        let trace = root.join("trace");
        let _guard = DaemonGuard::new(&id);
        let me = std::env::current_exe().expect("own executable");
        let mut cmd = Command::new(&me);
        cmd.args(["-namespace", "fandhe-e2e", "-address"])
            .arg(root.join("containerd.sock"))
            .arg("-publish-binary")
            .arg("/usr/bin/containerd")
            .args(["-id", &id, "start"])
            .env(ROLE_ENV, "shim")
            .env(TRACE_ENV, &trace)
            .env(SOCKET_DIR_ENV, root.join("s"))
            .env("XDG_RUNTIME_DIR", &*root)
            .current_dir(&*root)
            .stdin(Stdio::null());
        let out =
            reap::output_within(&mut cmd, Duration::from_secs(30)).expect("start exits in time");
        assert!(out.status.success(), "{out:?}");
        assert_eq!(out.stderr, b"", "start must not write to stderr");
        let addr = String::from_utf8(out.stdout).unwrap();
        let sock = PathBuf::from(addr.strip_prefix("unix://").expect("unix:// address"));
        let shim_pid = drive(&sock, SVC_V2, "c1", &trace);
        assert_ne!(shim_pid, std::process::id(), "daemon is a separate process");
        assert!(
            wait_until(Duration::from_secs(10), || !sock.exists()
                && !pid_alive(shim_pid)),
            "daemon must exit and remove its socket after Shutdown"
        );
        let log = std::fs::read_to_string(&trace).unwrap_or_default();
        let ok = |m: &str| log.lines().position(|l| l == format!("{m} ok"));
        for m in ["Create", "Connect", "Start", "Wait", "State", "Delete"] {
            assert!(ok(m).is_some(), "missing `{m} ok` in trace:\n{log}");
        }
        assert!(log.lines().any(|l| l == "Shutdown begin"), "trace:\n{log}");
        assert!(
            ok("Create") < ok("Start") && ok("Start") < ok("Delete"),
            "order:\n{log}"
        );
        println!("shim_v2: self-as-shim bootstrap ok");
    }

    /// (3) 環境変数・版文字列の解釈の単体照合。
    fn case_parsers() {
        assert_eq!(parse_trace(None), None);
        assert_eq!(parse_trace(Some("rel/trace".into())), None);
        assert_eq!(
            parse_trace(Some("/tmp/t".into())),
            Some(PathBuf::from("/tmp/t"))
        );
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                containerd_version("containerd github.com/containerd/containerd/v2 v2.1.4 abcdef"),
                Some((2, 1))
            );
            assert_eq!(
                containerd_version("containerd github.com/containerd/containerd v1.7.2 x"),
                Some((1, 7))
            );
            assert_eq!(containerd_version("garbage"), None);
            let cfg = containerd_config(Path::new("/tmp/w"));
            assert!(cfg.starts_with("version = 3\n"));
            assert!(cfg.contains("\"io.containerd.monitor.task.v1.cgroups\""));
            assert!(cfg.contains("address = \"/tmp/w/c.sock\""));
        }
        println!("shim_v2: parsers ok");
    }

    // ---- containerd シナリオ（Linux・root・--ignored） ----

    /// `containerd --version` の出力から (major, minor) を取り出す。
    #[cfg(target_os = "linux")]
    fn containerd_version(text: &str) -> Option<(u32, u32)> {
        let v = text.split_whitespace().find(|w| {
            w.strip_prefix('v')
                .is_some_and(|r| r.chars().next().is_some_and(|c| c.is_ascii_digit()))
        })?;
        let mut it = v.trim_start_matches('v').split('.');
        Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
    }

    /// 私設 containerd の設定（v3 形式）。CRI・NRI・task monitor・tracing を無効にし、システムの containerd と何も共有しない。
    ///
    /// plugin ID は containerd v2.x のもの。実機で未知の ID が警告になっても動作には影響しない
    /// （`disabled_plugins` は未知の ID を無視する）。task monitor を外すのは偽の pid から cgroup を引かせないため。
    #[cfg(target_os = "linux")]
    fn containerd_config(dir: &Path) -> String {
        let d = dir.display();
        format!(
            "version = 3\nroot = \"{d}/root\"\nstate = \"{d}/state\"\ntemp = \"{d}/tmp\"\n\
             disabled_plugins = [\"io.containerd.grpc.v1.cri\", \"io.containerd.cri.v1.runtime\", \
             \"io.containerd.cri.v1.images\", \"io.containerd.nri.v1.nri\", \
             \"io.containerd.monitor.task.v1.cgroups\", \"io.containerd.internal.v1.tracing\", \
             \"io.containerd.tracing.processor.v1.otlp\", \
             \"io.containerd.podsandbox.controller.v1.podsandbox\"]\n\
             [grpc]\n  address = \"{d}/c.sock\"\n[ttrpc]\n  address = \"{d}/t.sock\"\n[debug]\n  address = \"{d}/d.sock\"\n"
        )
    }

    #[cfg(target_os = "linux")]
    fn precondition_failed(reason: &str) -> ! {
        // 前提欠如は回帰と 1 行目で見分ける（skip にしない）。メッセージはホストのパス・ID を含めない。
        println!(
            "shim_v2: PRECONDITION FAILED (test environment, not a shim v2 regression): {reason}"
        );
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    fn tool(env: &str, name: &str) -> PathBuf {
        use std::os::unix::fs::MetadataExt;
        let cand: Vec<PathBuf> = match std::env::var_os(env) {
            Some(p) => vec![PathBuf::from(p)],
            None => ["/usr/bin", "/usr/local/bin"]
                .iter()
                .map(|d| Path::new(d).join(name))
                .collect(),
        };
        let Some(p) = cand.into_iter().find(|p| p.is_absolute() && p.is_file()) else {
            precondition_failed(&format!(
                "{name} is not installed (set {env} to an absolute path)"
            ));
        };
        // symlink を解決した実体を検査し、その実体のパスを実行まで使う。
        // 実体と全祖先が root 所有で group/other 書き込み不可であれば、検査後に差し替えられない。
        let real = std::fs::canonicalize(&p)
            .unwrap_or_else(|_| precondition_failed("cannot resolve tool path"));
        for a in real.ancestors() {
            let m = std::fs::metadata(a)
                .unwrap_or_else(|_| precondition_failed("cannot stat tool or its ancestor"));
            if m.uid() != 0 || m.mode() & 0o022 != 0 {
                precondition_failed(&format!(
                    "{name} and all its ancestor directories must be owned by root and not group/other writable"
                ));
            }
        }
        if !real.is_file() {
            precondition_failed("tool is not a regular file");
        }
        real
    }

    /// 作業ディレクトリ配下に mount が残っていないか（root で消すため、残っていれば削除しない）。
    #[cfg(target_os = "linux")]
    fn has_mounts_under(dir: &Path) -> bool {
        let text = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        let prefix = dir.to_string_lossy().into_owned();
        text.lines().any(|l| {
            l.split_whitespace()
                .nth(4)
                .is_some_and(|m| m.starts_with(&prefix))
        })
    }

    #[cfg(target_os = "linux")]
    fn case_containerd() {
        use std::os::unix::fs::MetadataExt;
        // 1. 前提確認
        let uid = std::fs::metadata("/proc/self")
            .map(|m| m.uid())
            .unwrap_or(u32::MAX);
        if uid != 0 {
            precondition_failed("must run as root");
        }
        let containerd = tool("FANDHE_CONTAINER_E2E_CONTAINERD", "containerd");
        let ctr = tool("FANDHE_CONTAINER_E2E_CTR", "ctr");
        let mut v = Command::new(&containerd);
        v.arg("--version");
        let vout = reap::output_within(&mut v, Duration::from_secs(10))
            .unwrap_or_else(|_| precondition_failed("containerd --version did not finish"));
        match containerd_version(&String::from_utf8_lossy(&vout.stdout)) {
            Some((major, _)) if major >= 2 => {}
            _ => precondition_failed("containerd 2.0 or newer is required"),
        }

        // 2. 私設 containerd
        let work = scratch("ct");
        let dir: PathBuf = (*work).to_path_buf();
        let id = format!("e2e{}", std::process::id());
        let _guard = DaemonGuard::new(&id);
        let me = std::env::current_exe().expect("own executable");
        let cfg_path = dir.join("config.toml");
        std::fs::write(&cfg_path, containerd_config(&dir)).unwrap();
        let rootfs = dir.join("rootfs");
        std::fs::create_dir(&rootfs).unwrap();
        let open_log = |n: &str| std::fs::File::create(dir.join(n)).unwrap();
        let mut d = Command::new(&containerd);
        d.arg("--config")
            .arg(&cfg_path)
            .env(ROLE_ENV, "shim")
            .env(TRACE_ENV, dir.join("trace"))
            .env(SOCKET_DIR_ENV, dir.join("s"))
            .stdin(Stdio::null())
            .stdout(open_log("containerd.out"))
            .stderr(open_log("containerd.err"));
        let mut daemon = d
            .spawn()
            .unwrap_or_else(|_| precondition_failed("cannot start containerd"));
        CHILDREN.lock().unwrap().push(daemon.id());
        let sock = dir.join("c.sock");
        let ctr_cmd = |args: &[&str]| {
            let mut c = Command::new(&ctr);
            c.arg("--address")
                .arg(&sock)
                .args(["--namespace", "fandhe-e2e"])
                .args(args)
                .stdin(Stdio::null());
            c
        };

        let outcome = (|| -> Result<(), String> {
            if !wait_until(Duration::from_secs(30), || {
                reap::output_within(&mut ctr_cmd(&["version"]), Duration::from_secs(5))
                    .is_ok_and(|o| o.status.success())
            }) {
                return Err("containerd did not become ready".into());
            }
            // 3. 本体。--rootfs は bool で、最初の位置引数が rootfs。--null-io は stdio の FIFO を作らず、
            //    Create の stdin/stdout/stderr が空になる（shim の未対応欄の拒否に当たらない）。
            //    --runtime に絶対パスを渡すと containerd は PATH を探さずこの試験バイナリを shim として exec する。
            let mut run_cmd = ctr_cmd(&[
                "run",
                "--rm",
                "--null-io",
                "--runtime",
                &me.to_string_lossy(),
                "--rootfs",
            ]);
            run_cmd.arg(&rootfs).arg(&id).arg("/bin/true");
            let out = reap::output_within(&mut run_cmd, Duration::from_secs(60))
                .map_err(|e| format!("ctr run: {e}"))?;
            // 4. 照合
            let code = out.status.code();
            if code != Some(EXIT_CODE) {
                return Err(format!(
                    "ctr exit code {code:?} (want {EXIT_CODE}); stderr: {}",
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            let log = std::fs::read_to_string(dir.join("trace")).unwrap_or_default();
            let pos = |m: &str| log.lines().position(|l| l == format!("{m} ok"));
            for m in ["Create", "Connect", "Start", "Wait", "State", "Delete"] {
                if pos(m).is_none() {
                    return Err(format!("trace lacks `{m} ok`:\n{log}"));
                }
            }
            if !log.lines().any(|l| l == "Shutdown begin") {
                return Err(format!("trace lacks Shutdown:\n{log}"));
            }
            if !(pos("Create") < pos("Start") && pos("Start") < pos("Delete")) {
                return Err(format!("unexpected order:\n{log}"));
            }
            if !wait_until(Duration::from_secs(10), || leftover_shims(&id).is_empty()) {
                return Err("shim daemon still alive after the run".into());
            }
            for what in ["tasks", "containers"] {
                let o =
                    reap::output_within(&mut ctr_cmd(&[what, "ls", "-q"]), Duration::from_secs(10))
                        .map_err(|e| format!("ctr {what} ls: {e}"))?;
                if !o.status.success() {
                    return Err(format!(
                        "ctr {what} ls failed: {:?}; stderr: {}",
                        o.status.code(),
                        String::from_utf8_lossy(&o.stderr)
                    ));
                }
                if !o.stdout.is_empty() {
                    return Err(format!(
                        "{what} remain: {}",
                        String::from_utf8_lossy(&o.stdout)
                    ));
                }
            }
            let socks = match std::fs::read_dir(dir.join("s")) {
                Ok(rd) => {
                    let mut n = 0usize;
                    for e in rd {
                        e.map_err(|e| format!("read socket dir entry: {e}"))?;
                        n += 1;
                    }
                    n
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
                Err(e) => return Err(format!("read socket dir: {e}")),
            };
            if socks != 0 {
                return Err(format!("{socks} shim socket(s) remain"));
            }
            Ok(())
        })();

        // 5. 後始末（成否に関わらず）
        let _ = reap::output_within(
            &mut ctr_cmd(&["tasks", "kill", "--signal", "SIGKILL", &id]),
            Duration::from_secs(10),
        );
        let _ = reap::output_within(
            &mut ctr_cmd(&["tasks", "delete", &id]),
            Duration::from_secs(10),
        );
        let _ = reap::output_within(
            &mut ctr_cmd(&["containers", "rm", &id]),
            Duration::from_secs(10),
        );
        kill_pid("TERM", daemon.id());
        if !wait_until(Duration::from_secs(15), || {
            daemon.try_wait().ok().flatten().is_some()
        }) {
            let _ = reap::reap(&mut daemon, Duration::from_secs(10));
        }
        for pid in leftover_shims(&id) {
            kill_pid("KILL", pid);
        }
        match outcome {
            Ok(()) => println!(
                "shim_v2: containerd drove Create -> Start -> Wait -> Delete through the shim (exit_status={EXIT_CODE})"
            ),
            Err(e) => {
                for f in ["containerd.err", "containerd.out", "s/daemon.log"] {
                    let t = std::fs::read_to_string(dir.join(f)).unwrap_or_default();
                    let tail: Vec<&str> = t.lines().rev().take(40).collect();
                    eprintln!(
                        "--- {f} (last lines) ---\n{}",
                        tail.into_iter().rev().collect::<Vec<_>>().join("\n")
                    );
                }
                eprintln!("shim_v2: FAILED: {e}");
                if has_mounts_under(&dir) {
                    std::mem::forget(work);
                }
                std::process::exit(1);
            }
        }
        if has_mounts_under(&dir) {
            eprintln!("shim_v2: mounts remain under the work dir; not removing it");
            std::mem::forget(work);
        }
    }

    pub fn main() -> ExitCode {
        // shim 役はスレッドを作る前に判定する（デーモンの監査 relay が単一スレッドの fork を要求する）。
        if std::env::var(ROLE_ENV).as_deref() == Ok("shim") {
            return shim_role();
        }
        let ignored = std::env::args().any(|a| a == "--ignored");
        watchdog();
        case_parsers();
        case_call_order_in_process();
        case_self_as_shim_bootstrap();
        if !ignored {
            println!(
                "shim_v2: containerd scenario ignored (run the test binary with --ignored as root; see AGENTS.md)"
            );
            return ExitCode::SUCCESS;
        }
        #[cfg(target_os = "linux")]
        case_containerd();
        #[cfg(not(target_os = "linux"))]
        println!("shim_v2: containerd scenario not applicable on this OS");
        ExitCode::SUCCESS
    }
}
