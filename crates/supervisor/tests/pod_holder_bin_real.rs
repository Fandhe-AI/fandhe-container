//! supervisor の bin の `pod-holder` モードを本物のバイナリで通す実機前提の結合試験（CRI-2・CORE-1・SEC-5・REPAIR-5・
//! REPAIR-12。#2874。設計は `docs/design/pod-namespace-holder.md` の H2）。
//!
//! 保持役は `unshare(CLONE_NEWUSER)` を使うため、非特権 user namespace を作れる環境（`kernel.apparmor_restrict_unprivileged_userns`
//! の緩和など）と util-linux の `nsenter`・`setpriv` が要る。CI への組み込みは H3（#2875）。`harness = false` で
//! `-- --ignored` 指定時のみ動かす（AGENTS.md）。前提が欠けていれば `PRECONDITION FAILED` で終了コード 1（成功を装わない）。
//!
//! # シナリオ（各成功行は固定の文字列。`scripts/check-success-lines.sh` が本ファイルのリテラルから導出して照合する）
//! - A: READY の内容（pid・3 つの namespace の素性を親の `stat` と照合・継承 fd の整理・`uid_map`）
//! - B: 保持役の netns に `nsenter` で入った 2 つのプロセスが `127.0.0.1` の TCP で往復できる（`lo` は H1 の API が up にする）
//! - C: stdin の EOF で終了コード 0、SIGTERM でシグナル 15 の終了
//! - D: PDEATHSIG を使わない（中間プロセスを SIGKILL しても保持役が残り、stdin の EOF で消える）
//! - E: dumpable の判別（再 exec しない陰性対照は親が `/proc/<pid>/ns/net` を開けず、案 (a) の保持役は親が開ける。pod の
//!   user namespace の中の capability を持たないプロセスは保持役の `environ` を開けない）
//! - F: 拒否（余分な argv は終了コード 2、SIGTERM が無視された起動は ERROR フレームと終了コード 1）
//!
//! 範囲外: provider の無い `POD` で pod 内の 2 コンテナが通信する試験は core の net join（H7・#2872）が要るため、
//! H7 の後に H3 か H5 で扱う。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("pod_holder_bin_real: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("pod_holder_bin_real: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod linux {
    use std::io::{BufRead as _, Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{Child, Command, ExitCode, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_supervisor::pod_holder::{PodHolderReady, READY_TIMEOUT, read_ready};

    use super::reap;

    const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-supervisor");
    const NSENTER: &str = "/usr/bin/nsenter";
    const SETPRIV: &str = "/usr/bin/setpriv";
    const KILL: &str = "/usr/bin/kill";
    /// 全シナリオの上限(超えたら `WATCHDOG EXPIRED` と終了コード 124。REPAIR-5)。
    const WATCHDOG: Duration = Duration::from_secs(240);
    const STEP: Duration = Duration::from_secs(20);

    pub fn main() -> ExitCode {
        let mut args = std::env::args().skip(1);
        match args.next().as_deref() {
            Some("--role") => role(args.collect()),
            Some("--spawner") => spawner(args.collect()),
            Some("--no-reexec-control") => return no_reexec_control(),
            Some("--probe-open") => return probe_open(args.next()),
            Some("--ignored") => return run_all(),
            _ => {
                println!(
                    "pod_holder_bin_real: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
                );
            }
        }
        ExitCode::SUCCESS
    }

    fn precondition_failed(what: &str) -> ExitCode {
        println!("pod_holder_bin_real: PRECONDITION FAILED: {what}");
        ExitCode::from(1)
    }

    fn euid() -> u32 {
        std::fs::metadata("/proc/self").map_or(u32::MAX, |m| m.uid())
    }

    fn fail(msg: &str) -> ! {
        println!("pod_holder_bin_real: FAILED: {msg}");
        std::process::exit(1)
    }

    fn start_watchdog() {
        std::thread::spawn(|| {
            std::thread::sleep(WATCHDOG);
            println!("pod_holder_bin_real: WATCHDOG EXPIRED after {WATCHDOG:?}");
            std::process::exit(124);
        });
    }

    // ---- 再入するロール ----

    /// `--role listen <dev> <ino>` / `--role connect <port> <dev> <ino>`: 保持役の netns の中の TCP 往復。
    fn role(args: Vec<String>) {
        let check_ns = |dev: &str, ino: &str| {
            let md = std::fs::metadata("/proc/self/ns/net").expect("stat own net ns");
            assert_eq!(
                (md.dev().to_string(), md.ino().to_string()),
                (dev.to_owned(), ino.to_owned())
            );
        };
        match args.first().map(String::as_str) {
            Some("listen") => {
                check_ns(&args[1], &args[2]);
                let l = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1");
                l.set_nonblocking(true).expect("nonblocking");
                println!("{}", l.local_addr().expect("addr").port());
                std::io::stdout().flush().expect("flush");
                let until = Instant::now() + STEP;
                let (mut s, _) = loop {
                    match l.accept() {
                        Ok(c) => break c,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < until, "no connection within the deadline");
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) => panic!("accept failed: {e}"),
                    }
                };
                s.set_nonblocking(false).expect("blocking");
                s.set_read_timeout(Some(STEP)).expect("timeout");
                let mut buf = [0u8; 5];
                s.read_exact(&mut buf).expect("read ping");
                assert_eq!(&buf, b"ping!");
                s.write_all(b"pong!").expect("write pong");
            }
            Some("connect") => {
                check_ns(&args[2], &args[3]);
                let port: u16 = args[1].parse().expect("port");
                let mut s = TcpStream::connect_timeout(
                    &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                    STEP,
                )
                .expect("connect 127.0.0.1");
                s.set_read_timeout(Some(STEP)).expect("timeout");
                s.write_all(b"ping!").expect("write ping");
                let mut buf = [0u8; 5];
                s.read_exact(&mut buf).expect("read pong");
                assert_eq!(&buf, b"pong!");
            }
            _ => fail("unknown role"),
        }
    }

    /// `--spawner <bin>`: 保持役を stdin / stdout を引き継いで起動し、自分は居座る(D の中間プロセス)。
    fn spawner(args: Vec<String>) {
        let bin = args.first().expect("bin path");
        let mut holder = Command::new(bin)
            .arg("pod-holder")
            .env_clear()
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn holder");
        // 居座る(保持役の終了まで待つ。SIGKILL されたら保持役だけが残る)。
        let _ = holder.wait();
    }

    /// `--no-reexec-control`: 再 exec をしない陰性対照。namespace を確立してから non-dumpable にして待つ。
    fn no_reexec_control() -> ExitCode {
        use fandhe_container_core::exec::{IsolationPrivilege, set_non_dumpable_for_test};
        use fandhe_container_core::oci_runtime::establish_pod_namespaces;
        use fandhe_container_supervisor::id_model::{
            RootlessIdResolution, SYSTEM_PASSWD, SYSTEM_SUBGID, SYSTEM_SUBUID,
            resolve_rootless_id_source,
        };
        let id = euid();
        let (privilege, source) = match resolve_rootless_id_source(
            id,
            id,
            std::path::Path::new(SYSTEM_PASSWD),
            std::path::Path::new(SYSTEM_SUBUID),
            std::path::Path::new(SYSTEM_SUBGID),
        ) {
            Ok(RootlessIdResolution::SingleId) => (IsolationPrivilege::RootlessSingleId, None),
            Ok(RootlessIdResolution::SubordinateIds(src)) => {
                (IsolationPrivilege::RootlessSubordinateIds, Some(src))
            }
            Err(_) => return ExitCode::from(5),
        };
        if let Err(e) = establish_pod_namespaces(privilege, source) {
            eprintln!("control establish failed: {:?} {}", e.code(), e.message());
            return ExitCode::from(4);
        }
        // 確立の後で non-dumpable にする(再 exec をしないので mm->user_ns は初期 user namespace のまま)。
        if set_non_dumpable_for_test().is_err() {
            return ExitCode::from(3);
        }
        println!("control-ready");
        let _ = std::io::stdout().flush();
        let mut b = [0u8; 1];
        let _ = std::io::stdin().read(&mut b);
        ExitCode::SUCCESS
    }

    /// `--probe-open <pid>`: `/proc/<pid>/environ` を開けるかを終了コードで返す(0 = 開けた、10 = 拒否)。
    fn probe_open(pid: Option<String>) -> ExitCode {
        let Some(pid) = pid.and_then(|p| p.parse::<u32>().ok()) else {
            return ExitCode::from(2);
        };
        // `environ` を使う(Linux 7.0.0-34 の実測では、capability を持たない pod 内プロセスは non-dumpable の
        // `environ`・`mem` を開けないが ns リンクは開けた。ns リンクの扱いはカーネルの版で異なり得るため
        // non-dumpable の判別には使わない)。
        match std::fs::File::open(format!("/proc/{pid}/environ")) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => ExitCode::from(10),
            Err(_) => ExitCode::from(11),
        }
    }

    // ---- 親の補助 ----

    struct Holder {
        child: Child,
        ready: PodHolderReady,
    }

    fn deadline() -> Instant {
        Instant::now() + READY_TIMEOUT.min(STEP)
    }

    fn spawn_holder(shell_prefix: Option<&str>) -> Child {
        let mut cmd = match shell_prefix {
            Some(p) => {
                let mut c = Command::new("/bin/sh");
                c.arg("-c")
                    .arg(format!("{p} exec \"$0\" pod-holder"))
                    .arg(BIN);
                c
            }
            None => {
                let mut c = Command::new(BIN);
                c.arg("pod-holder");
                c
            }
        };
        cmd.env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| fail(&format!("spawn holder: {e}")))
    }

    fn start_holder(shell_prefix: Option<&str>) -> Holder {
        let mut child = spawn_holder(shell_prefix);
        let out = child.stdout.take().expect("stdout");
        match read_ready(out.as_fd(), deadline()) {
            Ok(ready) => {
                // stdout は以後使わない。親が閉じても保持役は書かない。
                drop(out);
                Holder { child, ready }
            }
            Err(e) => {
                let mut err = String::new();
                reap::reap_or_report(&mut child, reap::reap_within());
                if let Some(mut s) = child.stderr.take() {
                    let _ = s.read_to_string(&mut err);
                }
                fail(&format!(
                    "holder did not report READY: {:?} stderr={err}",
                    e.code()
                ))
            }
        }
    }

    impl Holder {
        fn pid(&self) -> u32 {
            self.ready.pid
        }

        fn stop_by_eof(&mut self) -> std::process::ExitStatus {
            drop(self.child.stdin.take());
            self.wait()
        }

        fn wait(&mut self) -> std::process::ExitStatus {
            match reap::wait_within(&mut self.child, STEP) {
                Ok(st) => st,
                Err(e) => {
                    reap::reap_or_report(&mut self.child, reap::reap_within());
                    fail(&format!("holder did not exit: {e}"))
                }
            }
        }
    }

    impl Drop for Holder {
        fn drop(&mut self) {
            reap::reap_or_report(&mut self.child, reap::reap_within());
        }
    }

    fn ns_stat(pid: u32, which: &str) -> (u64, u64) {
        let md = std::fs::metadata(format!("/proc/{pid}/ns/{which}"))
            .unwrap_or_else(|e| fail(&format!("cannot stat /proc/<holder>/ns/{which}: {e}")));
        (md.dev(), md.ino())
    }

    fn nsenter_cmd(pid: u32) -> Command {
        let mut c = Command::new(NSENTER);
        c.arg("--preserve-credentials")
            .arg(format!("--user=/proc/{pid}/ns/user"))
            .arg(format!("--net=/proc/{pid}/ns/net"));
        c
    }

    fn exe() -> std::path::PathBuf {
        std::env::current_exe().expect("current_exe")
    }

    // ---- シナリオ ----

    fn scenario_a() {
        // 継承 fd(9)が閉じられることも同時に確かめる。
        let mut h = start_holder(Some("exec 9</dev/null;"));
        let pid = h.pid();
        assert_eq!(pid, h.child.id(), "READY pid is the spawned pid");
        for (which, got) in [
            ("user", h.ready.user),
            ("ipc", h.ready.ipc),
            ("net", h.ready.net),
        ] {
            assert_eq!(ns_stat(pid, which), (got.dev, got.ino), "{which} identity");
        }
        let mut fds: Vec<String> = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .unwrap_or_else(|e| fail(&format!("cannot list fds: {e}")))
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        fds.sort();
        assert_eq!(fds, ["0", "1", "2"], "only stdio stays open");
        let map = std::fs::read_to_string(format!("/proc/{pid}/uid_map")).expect("uid_map");
        let first: Vec<&str> = map
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        assert_eq!(first, ["0".to_owned(), euid().to_string(), "1".to_owned()]);
        if std::env::var("FANDHE_CONTAINER_TEST_ID_HELPER").as_deref() == Ok("1") {
            assert!(map.lines().count() >= 2, "range mapping is required: {map}");
        }
        assert_eq!(h.stop_by_eof().code(), Some(0));
        println!(
            "pod_holder_bin_real: scenario A ok: READY carries the pid and the namespace identities (root=false)"
        );
    }

    fn scenario_b() {
        let mut h = start_holder(None);
        let pid = h.pid();
        let net = h.ready.net;
        let mut listener = nsenter_cmd(pid)
            .arg(exe())
            .args(["--role", "listen"])
            .arg(net.dev.to_string())
            .arg(net.ino.to_string())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| fail(&format!("spawn listener: {e}")));
        let mut line = String::new();
        let mut out = std::io::BufReader::new(listener.stdout.take().expect("stdout"));
        if out.read_line(&mut line).is_err() {
            reap::reap_or_report(&mut listener, reap::reap_within());
            fail("listener did not report a port");
        }
        let port = line.trim().to_owned();
        assert!(port.parse::<u16>().is_ok(), "port line: {port:?}");
        let mut connector = nsenter_cmd(pid)
            .arg(exe())
            .args(["--role", "connect"])
            .arg(&port)
            .arg(net.dev.to_string())
            .arg(net.ino.to_string())
            .spawn()
            .unwrap_or_else(|e| fail(&format!("spawn connector: {e}")));
        for (name, child) in [("connector", &mut connector), ("listener", &mut listener)] {
            match reap::wait_within(child, STEP) {
                Ok(st) => assert_eq!(st.code(), Some(0), "{name} exit"),
                Err(e) => {
                    reap::reap_or_report(child, reap::reap_within());
                    fail(&format!("{name}: {e}"));
                }
            }
        }
        assert_eq!(h.stop_by_eof().code(), Some(0));
        println!(
            "pod_holder_bin_real: scenario B ok: two processes talk over 127.0.0.1 inside the holder netns (root=false)"
        );
    }

    fn scenario_c() {
        let mut h = start_holder(None);
        assert_eq!(h.stop_by_eof().code(), Some(0), "stdin EOF exits 0");
        let mut h = start_holder(None);
        let pid = h.pid().to_string();
        match reap::run_within(Command::new(KILL).args(["-TERM", &pid]), STEP) {
            Ok(st) => assert!(st.success(), "kill -TERM"),
            Err(e) => fail(&e),
        }
        assert_eq!(
            h.wait().signal(),
            Some(15),
            "SIGTERM ends the holder by signal 15"
        );
        println!(
            "pod_holder_bin_real: scenario C ok: stdin EOF exits 0 and SIGTERM ends it (root=false)"
        );
    }

    fn pid_gone(pid: u32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => true,
            Ok(s) => s
                .rsplit_once(')')
                .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z')),
        }
    }

    fn scenario_d() {
        let (stdin_r, stdin_w) = std::io::pipe().expect("pipe");
        let (out_r, out_w) = std::io::pipe().expect("pipe");
        let mut mid = Command::new(exe())
            .args(["--spawner", BIN])
            .env_clear()
            .stdin(Stdio::from(stdin_r))
            .stdout(Stdio::from(out_w))
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| fail(&format!("spawn spawner: {e}")));
        let ready = match read_ready(out_r.as_fd(), deadline()) {
            Ok(r) => r,
            Err(e) => {
                reap::reap_or_report(&mut mid, reap::reap_within());
                fail(&format!(
                    "spawner holder did not report READY: {:?}",
                    e.code()
                ))
            }
        };
        reap::reap_or_report(&mut mid, reap::reap_within());
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            !pid_gone(ready.pid),
            "the holder outlives its spawner (no PDEATHSIG)"
        );
        drop(stdin_w);
        let until = Instant::now() + STEP;
        while !pid_gone(ready.pid) {
            if Instant::now() >= until {
                fail("the holder did not exit after stdin EOF");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        println!(
            "pod_holder_bin_real: scenario D ok: the holder survives its spawner and exits on stdin EOF (root=false)"
        );
    }

    fn scenario_e() {
        // 陰性対照: 再 exec しない non-dumpable の保持役相当は、同 uid の親でも ns を開けない。
        let mut ctl = Command::new(exe())
            .arg("--no-reexec-control")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| fail(&format!("spawn control: {e}")));
        let mut line = String::new();
        let _ = std::io::BufReader::new(ctl.stdout.take().expect("stdout")).read_line(&mut line);
        if line.trim() != "control-ready" {
            reap::reap_or_report(&mut ctl, reap::reap_within());
            fail("the no-reexec control did not become ready");
        }
        let denied = std::fs::File::open(format!("/proc/{}/ns/net", ctl.id()));
        drop(ctl.stdin.take());
        reap::reap_or_report(&mut ctl, reap::reap_within());
        match denied {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
            other => fail(&format!("negative control must be denied, got {other:?}")),
        }
        // 陽性: 案 (a) の保持役は親が開ける(A でも stat 済み)。pod の userns の中で capability を持たない
        // プロセスは `environ` を開けない(non-dumpable の効果。ns リンクは対象にしない)。
        let mut h = start_holder(None);
        let pid = h.pid();
        for target in ["ns/net", "ns/ipc", "ns/user", "environ"] {
            std::fs::File::open(format!("/proc/{pid}/{target}")).unwrap_or_else(|e| {
                fail(&format!(
                    "the parent must open /proc/<holder>/{target}: {e}"
                ))
            });
        }
        let mut probe = Command::new(NSENTER);
        probe
            .arg("--preserve-credentials")
            .arg(format!("--user=/proc/{pid}/ns/user"))
            .args([
                SETPRIV,
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--",
            ])
            .arg(exe())
            .args(["--probe-open", &pid.to_string()])
            .stdin(Stdio::null());
        match reap::run_within(&mut probe, STEP) {
            Ok(st) => assert_eq!(
                st.code(),
                Some(10),
                "a capability-less process inside the pod userns is denied"
            ),
            Err(e) => fail(&e),
        }
        assert_eq!(h.stop_by_eof().code(), Some(0));
        println!(
            "pod_holder_bin_real: scenario E ok: the holder is non-dumpable yet its owner can open the namespaces (root=false)"
        );
    }

    fn scenario_f() {
        let mut extra = Command::new(BIN)
            .args(["pod-holder", "extra"])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| fail(&format!("spawn: {e}")));
        match reap::wait_within(&mut extra, STEP) {
            Ok(st) => assert_eq!(st.code(), Some(2), "extra argv exits 2"),
            Err(e) => {
                reap::reap_or_report(&mut extra, reap::reap_within());
                fail(&e);
            }
        }
        let mut child = spawn_holder(Some("trap '' TERM;"));
        let out = child.stdout.take().expect("stdout");
        let r = read_ready(out.as_fd(), deadline());
        match r {
            Err(e) => assert_eq!(
                e.code(),
                fandhe_container_core::traits::types::ErrorCode::FailedPrecondition
            ),
            Ok(_) => fail("a holder with SIGTERM ignored must be rejected"),
        }
        match reap::wait_within(&mut child, STEP) {
            Ok(st) => assert_eq!(st.code(), Some(1), "rejected start exits 1"),
            Err(e) => {
                reap::reap_or_report(&mut child, reap::reap_within());
                fail(&e);
            }
        }
        println!(
            "pod_holder_bin_real: scenario F ok: extra arguments and an ignored SIGTERM are rejected (root=false)"
        );
    }

    fn run_all() -> ExitCode {
        if euid() == 0 {
            println!("pod_holder_bin_real: FAILED: must run as non-root (root=true)");
            return ExitCode::from(1);
        }
        for tool in [NSENTER, SETPRIV, KILL] {
            if !std::path::Path::new(tool).exists() {
                return precondition_failed(&format!("{tool} is required"));
            }
        }
        start_watchdog();
        scenario_a();
        scenario_b();
        scenario_c();
        scenario_d();
        scenario_e();
        scenario_f();
        println!(
            "pod_holder_bin_real: the pod-holder mode works end to end in a rootless user namespace (root=false)"
        );
        ExitCode::SUCCESS
    }
}
