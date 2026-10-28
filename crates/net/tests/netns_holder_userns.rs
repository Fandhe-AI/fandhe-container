//! netns holder が非特権の user + network namespace へ実際に参加し、capability を落として待機し、同じ uid の
//! 別プロセスが `/proc/<holder>/ns/{net,user}` を開けることを照合する実機前提テスト
//! （NET-9・CORE-6・SEC-5・REPAIR-5・#3197。`docs/design/rootless-network.md` 12.2）。
//!
//! # 流れ
//! - 親（`-- --ignored`）: `unshare --user --map-root-user --net sleep` で対象の namespace を作り、その
//!   `/proc/<pid>/ns/{user,net}` を開いて `NetnsHolderChannel` で holder（自身を `netns-holder` で再実行）へ送る。
//! - 照合（具体値）: READY の (dev, ino) が対象と一致・`/proc/<holder>/ns/{net,user}` の inode が対象と一致・
//!   試験プロセス（pasta と同じ立場。同じ uid・init の user namespace）が `/proc/<holder>/ns/*` を開ける
//!   （holder が dumpable のまま。12.2 の前提）・`CapInh` / `CapPrm` / `CapEff` / `CapAmb` が 0・`NoNewPrivs` が 1・
//!   fd が 0・1・2 だけ・STOP でも EOF でも 1 秒以内に終了コード 0 で終わる。
//!
//! # 前提
//! 非特権 user namespace（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` がない環境）と util-linux の
//! `unshare` が要る。root は不要。前提を満たさない場合は skip せず失敗する。`harness = false` で `--ignored` が
//! 渡らなくても exit 0 になるため、CI は成功行を照合して false-green を防ぐ（AGENTS.md「実機前提テスト」）。
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。Linux のみ。
//!
//! 実機で 12.2 の前提（dumpable・PDEATHSIG が参加後も保たれる、同じ uid が `/proc/<holder>/ns/*` を開ける）が
//! 崩れた場合は、回避せず失敗として表に出す（holder 自身も READY の前に dumpable と PDEATHSIG を自己確認する）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("netns_holder_userns: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os();
    let _exe = args.next();
    match args.next() {
        Some(a) if a == fandhe_container_net::netns_holder::NETNS_HOLDER_SUBCOMMAND => {
            fandhe_container_net::netns_holder::run_netns_holder_main(args)
        }
        Some(a) if a == "--ignored" => linux::run(),
        _ => {
            println!(
                "netns_holder_userns: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
            );
            std::process::ExitCode::SUCCESS
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io::Read as _;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::MetadataExt as _;
    use std::process::{Child, Command, ExitCode, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_net::netns_holder::{
        NetnsHolderChannel, NetnsHolderFds, NsIdentity, READY_TIMEOUT, STOP_GRACE,
    };

    const OK_LINE: &str =
        "netns_holder_userns: holder joined user+net namespaces, dropped capabilities and stopped";

    fn limit() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn ns_identity(path: &str) -> Result<(u64, u64), String> {
        let m = std::fs::metadata(path).map_err(|e| format!("stat {path}: {e}"))?;
        Ok((m.dev(), m.ino()))
    }

    /// 対象: 新しい user + network namespace に入った `sleep`。`unshare` が namespace の作成と uid_map の書き込みの
    /// 後に `sleep` へ exec するのを（`comm` と user namespace の inode の変化で）待つ。
    fn spawn_target() -> Result<Child, String> {
        let own_user = ns_identity("/proc/self/ns/user")?;
        let mut child = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net", "sleep", "60"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                format!("cannot spawn `unshare` (util-linux missing or not permitted): {e}")
            })?;
        let pid = child.id();
        let started = Instant::now();
        loop {
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            let user = ns_identity(&format!("/proc/{pid}/ns/user"));
            if comm.trim() == "sleep" && user.as_ref().is_ok_and(|u| *u != own_user) {
                return Ok(child);
            }
            if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
                return Err(format!(
                    "`unshare` exited early with {st} (unprivileged user namespaces unavailable?)"
                ));
            }
            if started.elapsed() > limit() {
                let _ = child.kill();
                let _ = child.wait();
                return Err("target namespaces were not created in time".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn open_target_fds(pid: u32) -> Result<(OwnedFd, OwnedFd), String> {
        let open = |name: &str| {
            File::open(format!("/proc/{pid}/ns/{name}"))
                .map(OwnedFd::from)
                .map_err(|e| format!("open target ns {name}: {e}"))
        };
        Ok((open("user")?, open("net")?))
    }

    /// `/proc/<pid>/status` の `Name:\tvalue` 行の値。
    fn status_field(pid: u32, name: &str) -> Result<String, String> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .map_err(|e| format!("read status: {e}"))?;
        s.lines()
            .find_map(|l| l.strip_prefix(&format!("{name}:")))
            .map(|v| v.trim().to_string())
            .ok_or_else(|| format!("no {name} in status"))
    }

    struct Holder {
        child: Child,
        chan: Option<NetnsHolderChannel>,
        stderr: mpsc::Receiver<String>,
        pid: u32,
    }

    /// holder を起動して target の namespace を送り、READY を検証して返す（識別は対象の fd と一致済み）。
    fn start_holder(target_pid: u32) -> Result<(Holder, NsIdentity), String> {
        let (chan, child_end) = NetnsHolderChannel::pair().map_err(|e| e.to_string())?;
        let mut child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .arg("netns-holder")
            .env_clear()
            .stdin(Stdio::from(child_end))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn holder: {e}"))?;
        let mut stderr = child.stderr.take().ok_or("stderr")?;
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s);
            let _ = tx.send(s);
        });
        let pid = child.id();
        let holder = Holder {
            child,
            chan: Some(chan),
            stderr: rx,
            pid,
        };
        let (user, net) = open_target_fds(target_pid)?;
        let fds = NetnsHolderFds::new(user, net).map_err(|e| e.to_string())?;
        let live = holder.chan.as_ref().ok_or("channel closed")?;
        let sent = live.send_namespaces(fds).map_err(|e| e.to_string())?;
        let ready = live
            .wait_ready(&sent, READY_TIMEOUT)
            .map_err(|e| format!("wait_ready: {e}"))?;
        if ready.identity != sent.identity() {
            return Err(format!(
                "READY identity {:?} != sent {:?}",
                ready.identity,
                sent.identity()
            ));
        }
        Ok((holder, ready.identity))
    }

    /// 終了を待つ（`within` 以内）。終了コードと経過時間を返し、期限切れは kill して失敗にする。
    fn wait_exit(
        h: &mut Holder,
        within: Duration,
    ) -> Result<(Option<i32>, Duration, String), String> {
        let started = Instant::now();
        loop {
            if let Some(st) = h.child.try_wait().map_err(|e| e.to_string())? {
                let text = h
                    .stderr
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap_or_default();
                return Ok((st.code(), started.elapsed(), text));
            }
            if started.elapsed() > within {
                let _ = h.child.kill();
                let _ = h.child.wait();
                return Err(format!("holder did not exit within {within:?}"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn check(cond: bool, msg: impl FnOnce() -> String) -> Result<(), String> {
        if cond { Ok(()) } else { Err(msg()) }
    }

    fn scenario(target_pid: u32) -> Result<(), String> {
        let target_net = ns_identity(&format!("/proc/{target_pid}/ns/net"))?;
        let target_user = ns_identity(&format!("/proc/{target_pid}/ns/user"))?;
        check(target_net.0 == target_user.0, || {
            "nsfs dev differs between user and net".into()
        })?;

        // ---- STOP で終わる経路 ----
        let (mut h, identity) = start_holder(target_pid)?;
        check(
            identity
                == NsIdentity {
                    dev: target_net.0,
                    net_ino: target_net.1,
                    user_ino: target_user.1,
                },
            || format!("READY identity {identity:?} does not match the target"),
        )?;
        let hp = h.pid;
        // pasta と同じ立場（同じ uid・init の user namespace）の本プロセスが holder の ns を開ける。
        check(
            ns_identity(&format!("/proc/{hp}/ns/net"))? == target_net,
            || "holder net ns inode differs from the target".into(),
        )?;
        check(
            ns_identity(&format!("/proc/{hp}/ns/user"))? == target_user,
            || "holder user ns inode differs from the target".into(),
        )?;
        for f in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
            let v = status_field(hp, f)?;
            check(v == "0000000000000000", || {
                format!("{f} = {v}, want all-zero")
            })?;
        }
        let nnp = status_field(hp, "NoNewPrivs")?;
        check(nnp == "1", || format!("NoNewPrivs = {nnp}, want 1"))?;
        let mut fds: Vec<String> = std::fs::read_dir(format!("/proc/{hp}/fd"))
            .map_err(|e| format!("read holder fd dir: {e}"))?
            .filter_map(|e| e.ok().and_then(|e| e.file_name().into_string().ok()))
            .collect();
        fds.sort();
        check(fds == ["0", "1", "2"], || {
            format!("holder fds = {fds:?}, want [0, 1, 2]")
        })?;
        h.chan
            .as_ref()
            .ok_or("channel closed")?
            .send_stop()
            .map_err(|e| e.to_string())?;
        let (code, elapsed, text) = wait_exit(&mut h, limit())?;
        check(code == Some(0), || {
            format!("STOP exit code {code:?}, stderr {text:?}")
        })?;
        check(elapsed < STOP_GRACE, || format!("STOP took {elapsed:?}"))?;
        check(text.is_empty(), || format!("unexpected stderr {text:?}"))?;

        // ---- EOF（端を閉じる）で終わる経路 ----
        let (mut h, _) = start_holder(target_pid)?;
        h.chan.take().ok_or("channel already closed")?.close();
        let (code, elapsed, text) = wait_exit(&mut h, limit())?;
        check(code == Some(0), || {
            format!("EOF exit code {code:?}, stderr {text:?}")
        })?;
        check(elapsed < STOP_GRACE, || format!("EOF took {elapsed:?}"))?;
        Ok(())
    }

    pub fn run() -> ExitCode {
        let mut target = match spawn_target() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("netns_holder_userns: FAILED: {e}");
                return ExitCode::from(1);
            }
        };
        let result = scenario(target.id());
        let _ = target.kill();
        let _ = target.wait();
        match result {
            Ok(()) => {
                println!("{OK_LINE}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("netns_holder_userns: FAILED: {e}");
                ExitCode::from(1)
            }
        }
    }
}
