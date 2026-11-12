//! netns-dial helper と親側の `NetnsDialChannel` が、非特権の user + network namespace の中の listener と実際に往復し、
//! 別の namespace の socket を拒否することを照合する実機前提テスト（CRI-6・NET-3・SEC-1・REPAIR-5・REPAIR-12・#4479・#4480）。
//!
//! # 流れ
//! 親（`-- --ignored`）は同じ番号 P の TCP port を、自分の（init の）network namespace の `127.0.0.1` で listen したまま、
//! 次の場面を順に回す。対象は `unshare --user --map-root-user --net <自身> --target <P>`（試験専用の再入口。
//! `lo` を up にして `127.0.0.1:P` で 1 接続を受け、受けた内容に `target:` を前置して返す）か、`lo` が down の `sleep`。
//! - 場面 L（到達不能）: `lo` が down で listener も無い対象へは `Helper(Unreachable | Refused)`。終了コード 1、stderr は空。
//! - 場面 R（往復）: 対象 A の user / net の fd を `NetnsDialChannel` で helper へ送り、応答の fd が検証を通って
//!   `TcpStream` になり、書いた内容に `target:` を前置した内容が返る（A の中の listener に届いた証拠）。親の P の
//!   listener は接続を受けない。helper の終了コードは 0、stderr は空。
//! - 場面 M（netns の不一致）: A の fd を送り、期待する netns に別の対象 B のものを渡すと、`Rejected(NetnsMismatch)`
//!   で拒否される（非 root でも、試験の euid は A の user namespace の所有者なので `SIOCGSKNS` は成功し、識別の比較で落ちる）。
//! - 場面 D（non-dumpable）: 試験専用の入口 `netns-dial-traced`（本番と同じ本体。#4558）で `lo` が down の対象へ dial し、
//!   helper が終了前に stdout へ書く 1 行で、参加の直前・直後・特権の破棄の後の `PR_GET_DUMPABLE` がすべて 0 であることを
//!   具体値で照合する（起動直後に設定した non-dumpable が `setns` と capset の `commit_creds` で戻らない証拠）。
//!
//! # 前提
//! 非特権 user namespace（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` がない環境）と util-linux の
//! `unshare` が要る。root は不要。前提を満たさない場合は skip せず失敗する。`harness = false` で `--ignored` が
//! 渡らなくても exit 0 になるため、CI は成功行を照合して false-green を防ぐ（AGENTS.md「実機前提テスト」）。
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。Linux のみ。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("netns_dial_userns: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os();
    let _exe = args.next();
    match args.next() {
        Some(a) if a == fandhe_container_net::netns_dial::NETNS_DIAL_SUBCOMMAND => {
            fandhe_container_net::netns_dial::run_netns_dial_main(args)
        }
        Some(a) if a == "netns-dial-traced" => {
            fandhe_container_net::netns_dial::test_support::run_netns_dial_traced_main(args)
        }
        Some(a) if a == "--ignored" => linux::run(),
        Some(a) if a == "--target" => linux::target(args.next()),
        _ => {
            println!(
                "netns_dial_userns: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
            );
            std::process::ExitCode::SUCCESS
        }
    }
}

#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[cfg(target_os = "linux")]
mod linux {
    use super::reap;
    use std::fs::File;
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::num::NonZeroU16;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::MetadataExt as _;
    use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_net::netlink_route::{LinkIndex, LinkRef, LinkSet, NetlinkRouteSocket};
    use fandhe_container_net::netns_dial::{
        ConnectTimeout, DialErrorCode, DialRequest, DialedSocketRejection, NetnsDialChannel,
        NetnsDialError, NetnsDialFailure, NetnsDialFds, NsId,
    };

    const LINE_L: &str = "netns_dial_userns: helper joined the target user+net namespaces and dialed from inside them";
    const LINE_ROUND_TRIP: &str = "netns_dial_userns: helper joined the target and the channel returned a verified socket whose echo round trip matched";
    const LINE_PARENT_QUIET: &str = "netns_dial_userns: helper joined the target and the same-port listener in the parent namespace saw no connection";
    const LINE_MISMATCH: &str = "netns_dial_userns: helper joined the target and the channel rejected the socket expected in another target netns with netns_mismatch";
    const LINE_DUMPABLE: &str = "netns_dial_userns: helper joined the target with PR_GET_DUMPABLE 0 before the join, right after the join and after hardening";
    const WANT_TRACE: &str =
        "netns-dial-trace dumpable before_join=0 after_join=0 after_harden=0\n";
    const TARGET_READY: &str = "netns_dial_userns: target ready";
    const PAYLOAD: &[u8] = b"ping-4480";
    const REPLY_PREFIX: &[u8] = b"target:";

    fn limit() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn check(cond: bool, msg: impl FnOnce() -> String) -> Result<(), String> {
        if cond { Ok(()) } else { Err(msg()) }
    }

    fn ns_identity(path: &str) -> Result<(u64, u64), String> {
        let m = std::fs::metadata(path).map_err(|e| format!("stat {path}: {e}"))?;
        Ok((m.dev(), m.ino()))
    }

    fn net_id(pid: u32) -> Result<NsId, String> {
        let (dev, ino) = ns_identity(&format!("/proc/{pid}/ns/net"))?;
        Ok(NsId::new(dev, ino))
    }

    /// 対象（試験専用の再入口）: 新しい user + network namespace の中で `lo` を up にし、`127.0.0.1:port` で 1 接続を受けて
    /// `target:` + 受けた内容を返す。接続後の失敗（場面 M は相手が先に閉じる）は握りつぶして待機に入る。
    pub fn target(port: Option<std::ffi::OsString>) -> ExitCode {
        let fail = |e: String| {
            eprintln!("netns_dial_userns: FAILED: target: {e}");
            ExitCode::from(1)
        };
        let Some(port) = port.and_then(|p| p.to_str().and_then(|s| s.parse::<u16>().ok())) else {
            return fail("missing or invalid --target port".into());
        };
        let t = limit();
        let up = || -> Result<TcpListener, String> {
            let sock = NetlinkRouteSocket::open().map_err(|e| format!("netlink: {e}"))?;
            let lo = LinkIndex::new(1).map_err(|e| format!("link index: {e}"))?;
            sock.set_link(&LinkSet::up(LinkRef::Index(lo)), t)
                .map_err(|e| format!("lo up: {e}"))?;
            let l =
                TcpListener::bind((Ipv4Addr::LOCALHOST, port)).map_err(|e| format!("bind: {e}"))?;
            l.set_nonblocking(true).map_err(|e| e.to_string())?;
            Ok(l)
        };
        let listener = match up() {
            Ok(l) => l,
            Err(e) => return fail(e),
        };
        println!("{TARGET_READY}");
        let started = Instant::now();
        let stream = loop {
            match listener.accept() {
                Ok((s, _)) => break Some(s),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if started.elapsed() > t * 3 {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break None,
            }
        };
        if let Some(mut s) = stream {
            let _ = s.set_nonblocking(false);
            let _ = s.set_read_timeout(Some(t));
            let mut buf = [0u8; 64];
            if let Ok(n) = s.read(&mut buf) {
                let mut reply = REPLY_PREFIX.to_vec();
                reply.extend_from_slice(buf.get(..n).unwrap_or(&[]));
                let _ = s.write_all(&reply);
            }
        }
        // 親が kill するまで待つ（上限つき）。
        std::thread::sleep(t * 6);
        ExitCode::SUCCESS
    }

    /// `unshare --user --map-root-user --net <argv...>` を起動し、exec 後に `/proc/<pid>/ns/user` が自分と別になるまで待つ。
    fn spawn_unshared(prog_args: &[&str], stdout_piped: bool) -> Result<Child, String> {
        let own_user = ns_identity("/proc/self/ns/user")?;
        let mut cmd = Command::new("unshare");
        cmd.args(["--user", "--map-root-user", "--net"])
            .args(prog_args)
            .stdin(Stdio::null())
            .stdout(if stdout_piped {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn().map_err(|e| {
            format!("cannot spawn `unshare` (util-linux missing or not permitted): {e}")
        })?;
        let pid = child.id();
        let started = Instant::now();
        loop {
            let user = ns_identity(&format!("/proc/{pid}/ns/user"));
            let exec_done = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .map(|c| c.trim() != "unshare")
                .unwrap_or(false);
            if exec_done && user.as_ref().is_ok_and(|u| *u != own_user) {
                return Ok(child);
            }
            if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
                return Err(format!(
                    "`unshare` exited early with {st} (unprivileged user namespaces unavailable?)"
                ));
            }
            if started.elapsed() > limit() {
                reap::reap(&mut child, limit())?;
                return Err("target namespaces were not created in time".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// `lo` が down で listener も無い対象（場面 L）。
    fn spawn_sleep_target() -> Result<Child, String> {
        spawn_unshared(&["sleep", "60"], false)
    }

    /// listener を持つ対象（場面 R・M）。ready の行を待つ。早期終了は前提不足として失敗させる。
    fn spawn_listening_target(port: u16) -> Result<Child, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe = exe
            .to_str()
            .ok_or("non-UTF-8 test executable path")?
            .to_owned();
        let port_s = port.to_string();
        let mut child = spawn_unshared(&[&exe, "--target", &port_s], true)?;
        let stdout = child.stdout.take().ok_or("target stdout")?;
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        let started = Instant::now();
        loop {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(line) if line.trim_end() == TARGET_READY => return Ok(child),
                Ok(line) => {
                    reap::reap(&mut child, limit())?;
                    return Err(format!("unexpected target output {line:?}"));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    reap::reap(&mut child, limit())?;
                    return Err("target closed stdout before ready".into());
                }
            }
            if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
                return Err(format!("target exited early with {st}"));
            }
            if started.elapsed() > limit() {
                reap::reap(&mut child, limit())?;
                return Err("target was not ready in time".into());
            }
        }
    }

    struct Dialed {
        result: Result<TcpStream, NetnsDialError>,
        status: ExitStatus,
        stderr: String,
        /// helper の stdout 全体（traced の入口のときだけ pipe。本番の入口では空）。
        stdout: String,
    }

    /// `dial_pid` の user / net の fd を送り、`expect_pid` の netns を期待として helper に dial させる。
    fn dial(dial_pid: u32, expect_pid: u32, port: u16) -> Result<Dialed, String> {
        dial_with(dial_pid, expect_pid, port, false)
    }

    /// `traced` なら再入口 `netns-dial-traced`（本番と同じ本体 + dumpable の trace 行）で helper を起動する。
    fn dial_with(
        dial_pid: u32,
        expect_pid: u32,
        port: u16,
        traced: bool,
    ) -> Result<Dialed, String> {
        let open = |ns: &str| -> Result<OwnedFd, String> {
            File::open(format!("/proc/{dial_pid}/ns/{ns}"))
                .map(OwnedFd::from)
                .map_err(|e| e.to_string())
        };
        let fds = NetnsDialFds::new(open("user")?, open("net")?).map_err(|e| e.to_string())?;
        let expected = net_id(expect_pid)?;
        let (channel, child_end) = NetnsDialChannel::pair().map_err(|e| e.to_string())?;
        let mut child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .arg(if traced {
                "netns-dial-traced"
            } else {
                "netns-dial"
            })
            .env_clear()
            .stdin(Stdio::from(child_end))
            .stdout(if traced {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn helper: {e}"))?;
        let outcome = (|| -> Result<Dialed, String> {
            let mut stderr = child.stderr.take().ok_or("stderr")?;
            let mut stdout = child.stdout.take();
            let req = DialRequest::new(
                NonZeroU16::new(port).ok_or("port 0")?,
                ConnectTimeout::new(3000).map_err(|e| format!("{e:?}"))?,
            );
            let sent = channel.send_request(req, fds).map_err(|e| e.to_string())?;
            let result = channel.wait_response(&sent, expected, limit());
            let started = Instant::now();
            let status = loop {
                if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
                    break st;
                }
                if started.elapsed() > limit() {
                    return Err("helper did not exit in time".to_string());
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text);
            let mut out = String::new();
            if let Some(o) = stdout.as_mut() {
                let _ = o.read_to_string(&mut out);
            }
            Ok(Dialed {
                result,
                status,
                stderr: text,
                stdout: out,
            })
        })();
        let reaped = reap::reap(&mut child, limit());
        let dialed = outcome?;
        reaped?;
        Ok(dialed)
    }

    fn parent_quiet(listener: &TcpListener) -> Result<(), String> {
        match listener.accept() {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            other => Err(format!("parent listener saw a connection: {other:?}")),
        }
    }

    fn scenario_l(sleeper: &Child, port: u16, listener: &TcpListener) -> Result<(), String> {
        let d = dial(sleeper.id(), sleeper.id(), port)?;
        check(d.stderr.is_empty(), || {
            format!("helper stderr {:?}", d.stderr)
        })?;
        match d.result {
            Err(e)
                if matches!(
                    e.failure(),
                    NetnsDialFailure::Helper(DialErrorCode::Unreachable | DialErrorCode::Refused)
                ) => {}
            other => return Err(format!("L: {other:?}, want Helper(Unreachable or Refused)")),
        }
        check(d.status.code() == Some(1), || {
            format!("L: helper exit {}, want code 1", d.status)
        })?;
        parent_quiet(listener)
    }

    fn scenario_r(a: &Child, port: u16, listener: &TcpListener) -> Result<(), String> {
        let d = dial(a.id(), a.id(), port)?;
        check(d.stderr.is_empty(), || {
            format!("helper stderr {:?}", d.stderr)
        })?;
        check(d.status.code() == Some(0), || {
            format!("R: helper exit {}, want code 0", d.status)
        })?;
        let mut stream = d.result.map_err(|e| format!("R: dial failed: {e:?}"))?;
        stream
            .set_read_timeout(Some(limit()))
            .and_then(|()| stream.set_write_timeout(Some(limit())))
            .map_err(|e| e.to_string())?;
        stream.write_all(PAYLOAD).map_err(|e| e.to_string())?;
        let mut want = REPLY_PREFIX.to_vec();
        want.extend_from_slice(PAYLOAD);
        let mut got = vec![0u8; want.len()];
        stream
            .read_exact(&mut got)
            .map_err(|e| format!("R: read reply: {e}"))?;
        check(got == want, || format!("R: reply {got:?}, want {want:?}"))?;
        parent_quiet(listener)
    }

    fn scenario_m(a: &Child, b: &Child, port: u16, listener: &TcpListener) -> Result<(), String> {
        let d = dial(a.id(), b.id(), port)?;
        check(d.stderr.is_empty(), || {
            format!("helper stderr {:?}", d.stderr)
        })?;
        check(d.status.code() == Some(0), || {
            format!("M: helper exit {}, want code 0", d.status)
        })?;
        match d.result {
            Err(e) => match e.failure() {
                NetnsDialFailure::Rejected(r)
                    if r.reason() == Some(DialedSocketRejection::NetnsMismatch) => {}
                other => return Err(format!("M: {other:?}, want Rejected(NetnsMismatch)")),
            },
            Ok(_) => return Err("M: a socket of another netns was accepted".into()),
        }
        parent_quiet(listener)
    }

    /// 場面 D（#4558・SEC-1）: trace 入口で `lo` が down の対象へ dial し、3 時点の dumpable がすべて 0 であることを見る。
    fn scenario_d(sleeper: &Child, port: u16, listener: &TcpListener) -> Result<(), String> {
        let d = dial_with(sleeper.id(), sleeper.id(), port, true)?;
        check(d.stderr.is_empty(), || {
            format!("helper stderr {:?}", d.stderr)
        })?;
        match d.result {
            Err(e)
                if matches!(
                    e.failure(),
                    NetnsDialFailure::Helper(DialErrorCode::Unreachable | DialErrorCode::Refused)
                ) => {}
            other => return Err(format!("D: {other:?}, want Helper(Unreachable or Refused)")),
        }
        check(d.status.code() == Some(1), || {
            format!("D: helper exit {}, want code 1", d.status)
        })?;
        check(d.stdout == WANT_TRACE, || {
            format!("D: trace {:?}, want {WANT_TRACE:?}", d.stdout)
        })?;
        parent_quiet(listener)
    }

    pub fn run() -> ExitCode {
        let mut targets: Vec<Child> = Vec::new();
        let result = run_inner(&mut targets);
        let mut reaped = Ok(());
        for t in &mut targets {
            reaped = reaped.and(reap::reap(t, limit()));
        }
        match result.and_then(|lines| reaped.map(|()| lines)) {
            Ok(lines) => {
                for l in lines {
                    println!("{l}");
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("netns_dial_userns: FAILED: {e}");
                ExitCode::from(1)
            }
        }
    }

    fn run_inner(targets: &mut Vec<Child>) -> Result<[&'static str; 5], String> {
        // 親（init）の network namespace の 127.0.0.1 で待ち受ける。対象も同じ番号を自分の namespace で使う。
        // helper が対象へ参加していなければ、ここへ繋がる。
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();

        targets.push(spawn_sleep_target()?);
        targets.push(spawn_listening_target(port)?);
        targets.push(spawn_listening_target(port)?);
        let (s, a, b) = (
            targets.first().ok_or("sleep target")?,
            targets.get(1).ok_or("target A")?,
            targets.get(2).ok_or("target B")?,
        );
        scenario_l(s, port, &listener)?;
        scenario_r(a, port, &listener)?;
        scenario_m(a, b, port, &listener)?;
        scenario_d(s, port, &listener)?;
        Ok([
            LINE_L,
            LINE_ROUND_TRIP,
            LINE_PARENT_QUIET,
            LINE_MISMATCH,
            LINE_DUMPABLE,
        ])
    }
}
