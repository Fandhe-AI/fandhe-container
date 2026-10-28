//! supervisor の holder 起動（`netns_holder::spawn_netns_holder`）が、非特権の user + network namespace へ実際に
//! 参加した holder を作り、メモリを継承せず、停止・drop・supervisor の異常終了で回収されることを照合する
//! 実機前提テスト（NET-9・CORE-1・CORE-6・SUP-12・SEC-5・REPAIR-5・#3198・#2628。`docs/design/rootless-network.md` 12.2・12.10）。
//!
//! # 流れ
//! - 親（`-- --ignored`）: `unshare --user --map-root-user --net sleep` で対象の namespace を作り、本番の
//!   `spawn_netns_holder` で holder（自身を `netns-holder` で再実行）へ送る。
//! - 成功経路（具体値）: READY の識別が対象と一致・`/proc/<holder>/fd` が 0・1・2 だけ・`environ` が空・`Cap*` が 0・
//!   `NoNewPrivs` が 1・`stop()` が `Stopped`・終了コード 0・`STOP_GRACE` 未満。
//! - メモリを継承しない（#2628）: spawn の前にヒープへ置いた 64 バイトの乱数が、`/proc/<holder>/mem` に 0 件であること
//!   （同じ走査器が `/proc/self/mem` では 1 件以上見つける陽性対照つき）。
//! - drop の回収・supervisor の異常終了: `--fake-supervisor` で別プロセスを中間の supervisor にして main スレッドから
//!   holder を起動させ、その中間プロセスを SIGKILL すると holder が期限内に消える（PDEATHSIG と EOF。pid の再利用は
//!   `/proc/<pid>/stat` の starttime で除く）。
//!
//! # 前提
//! 非特権 user namespace（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` がない環境）と util-linux の
//! `unshare` が要る。root は不要。前提を満たさない場合は skip せず失敗する。`harness = false` で `--ignored` が
//! 渡らなくても exit 0 になるため、CI は成功行を照合して false-green を防ぐ（AGENTS.md「実機前提テスト」）。
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。Linux のみ。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("netns_holder_launch_userns: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os();
    let _exe = args.next();
    match args.next() {
        Some(a) if a == fandhe_container_net::netns_holder::NETNS_HOLDER_SUBCOMMAND => {
            fandhe_container_net::netns_holder::run_netns_holder_main(args)
        }
        Some(a) if a == "--fake-supervisor" => linux::fake_supervisor(args.next()),
        Some(a) if a == "--ignored" => linux::run(),
        _ => {
            println!(
                "netns_holder_launch_userns: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
            );
            std::process::ExitCode::SUCCESS
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io::{BufRead as _, Read as _};
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::{FileExt as _, MetadataExt as _};
    use std::process::{Child, Command, ExitCode, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_net::netns_holder::{NetnsHolderFds, NsIdentity, STOP_GRACE};
    use fandhe_container_supervisor::netns_holder::{StopPath, spawn_netns_holder};

    const OK_LINE: &str = "netns_holder_launch_userns: holder spawned from supervisor, joined, inherited no memory and was reaped";

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

    /// 子を kill し、期限つきで回収する。
    fn reap(child: &mut Child) -> Result<(), String> {
        let _ = child.kill();
        let until = Instant::now() + limit();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => {}
                Err(e) => return Err(format!("try_wait: {e}")),
            }
            if Instant::now() >= until {
                return Err(format!("child {} was not reaped", child.id()));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// 対象: 新しい user + network namespace に入った `sleep`（`netns_holder_userns` と同じ作り方）。
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
                reap(&mut child)?;
                return Err("target namespaces were not created in time".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn target_fds(pid: u32) -> Result<NetnsHolderFds, String> {
        let open = |name: &str| {
            File::open(format!("/proc/{pid}/ns/{name}"))
                .map(OwnedFd::from)
                .map_err(|e| format!("open target ns {name}: {e}"))
        };
        NetnsHolderFds::new(open("user")?, open("net")?).map_err(|e| e.to_string())
    }

    fn status_field(pid: u32, name: &str) -> Result<String, String> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .map_err(|e| format!("read status: {e}"))?;
        s.lines()
            .find_map(|l| l.strip_prefix(&format!("{name}:")))
            .map(|v| v.trim().to_string())
            .ok_or_else(|| format!("no {name} in status"))
    }

    /// `/proc/<pid>/stat` の (state, starttime)。comm に括弧を含み得るため最後の ')' の後ろを読む。
    fn stat_of(pid: u32) -> Option<(char, u64)> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = s.rsplit_once(')')?.1;
        let mut it = rest.split_whitespace();
        let state = it.next()?.chars().next()?;
        // 3 番目のフィールド（state）から数えて 22 番目が starttime。
        let start = it.nth(18)?.parse().ok()?;
        Some((state, start))
    }

    /// `needle` が `/proc/<pid>/mem` の読める領域に何件あるか。`(件数, 走査したバイト数)`。
    fn scan_memory(pid: u32, needle: &[u8]) -> Result<(usize, u64), String> {
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
            .map_err(|e| format!("read maps: {e}"))?;
        let mem = File::open(format!("/proc/{pid}/mem")).map_err(|e| format!("open mem: {e}"))?;
        let (mut found, mut scanned) = (0usize, 0u64);
        const CHUNK: usize = 1 << 20;
        for line in maps.lines() {
            let mut f = line.split_whitespace();
            let (Some(range), Some(perms)) = (f.next(), f.next()) else {
                continue;
            };
            let path = f.nth(3).unwrap_or("");
            if !perms.starts_with('r') || path == "[vvar]" || path == "[vsyscall]" {
                continue;
            }
            let Some((a, b)) = range.split_once('-') else {
                continue;
            };
            let (Ok(start), Ok(end)) = (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16))
            else {
                continue;
            };
            let mut pos = start;
            let mut carry: Vec<u8> = Vec::new();
            while pos < end {
                let n = ((end - pos) as usize).min(CHUNK);
                let mut buf = vec![0u8; n];
                let Ok(got) = mem.read_at(&mut buf, pos) else {
                    break;
                };
                if got == 0 {
                    break;
                }
                buf.truncate(got);
                scanned += got as u64;
                let mut window = std::mem::take(&mut carry);
                window.extend_from_slice(&buf);
                found += window
                    .windows(needle.len())
                    .filter(|w| *w == needle)
                    .count();
                let keep = needle.len().saturating_sub(1).min(window.len());
                carry = window[window.len() - keep..].to_vec();
                pos += got as u64;
            }
        }
        Ok((found, scanned))
    }

    fn read_secret() -> Result<Vec<u8>, String> {
        let mut secret = vec![0u8; 64];
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut secret))
            .map_err(|e| format!("read /dev/urandom: {e}"))?;
        Ok(secret)
    }

    fn scenario(target_pid: u32) -> Result<(), String> {
        let target_net = ns_identity(&format!("/proc/{target_pid}/ns/net"))?;
        let target_user = ns_identity(&format!("/proc/{target_pid}/ns/user"))?;
        // spawn の前にヒープへ置く（リテラルは .rodata に写るため使わない）。
        let secret = read_secret()?;
        let holder = spawn_netns_holder(target_fds(target_pid)?, Instant::now() + limit())
            .map_err(|e| format!("spawn_netns_holder: {e:?}"))?;
        let hp = holder.pid();
        let want = NsIdentity {
            dev: target_net.0,
            net_ino: target_net.1,
            user_ino: target_user.1,
        };
        check(holder.ready().identity == want, || {
            format!("READY identity {:?} != target", holder.ready().identity)
        })?;
        let mut fds: Vec<String> = std::fs::read_dir(format!("/proc/{hp}/fd"))
            .map_err(|e| format!("read holder fd dir: {e}"))?
            .filter_map(|e| e.ok().and_then(|e| e.file_name().into_string().ok()))
            .collect();
        fds.sort();
        check(fds == ["0", "1", "2"], || format!("holder fds = {fds:?}"))?;
        let environ = std::fs::read(format!("/proc/{hp}/environ"))
            .map_err(|e| format!("read holder environ: {e}"))?;
        check(environ.is_empty(), || {
            format!("holder environ has {} bytes", environ.len())
        })?;
        for f in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
            let v = status_field(hp, f)?;
            check(v == "0000000000000000", || format!("{f} = {v}"))?;
        }
        let nnp = status_field(hp, "NoNewPrivs")?;
        check(nnp == "1", || format!("NoNewPrivs = {nnp}"))?;

        // メモリを継承しない（陽性対照つき）。
        let (control, _) = scan_memory(std::process::id(), &secret)?;
        check(control >= 1, || {
            "positive control: the scanner did not find the secret in our own memory".into()
        })?;
        let (hits, scanned) = scan_memory(hp, &secret)?;
        check(scanned > 64 * 1024, || {
            format!("only {scanned} bytes of the holder were scanned")
        })?;
        check(hits == 0, || {
            format!("the holder memory contains the supervisor secret ({hits} hits)")
        })?;
        let maps = std::fs::read_to_string(format!("/proc/{hp}/maps"))
            .map_err(|e| format!("read holder maps: {e}"))?;
        check(!maps.contains("memfd:"), || {
            "the holder maps a memfd".to_string()
        })?;

        let out = holder.stop();
        check(out.path == StopPath::Stopped, || format!("{:?}", out.path))?;
        let exit = out.exit.ok_or("no exit material")?;
        check(exit.code == Some(0) && exit.signal.is_none(), || {
            format!("{exit:?}")
        })?;
        check(exit.stderr.is_empty(), || {
            format!("unexpected stderr {:?}", exit.stderr)
        })?;
        check(out.elapsed < STOP_GRACE, || {
            format!("stop took {:?}", out.elapsed)
        })?;
        check(stat_of(hp).is_none(), || {
            "the holder is still visible after stop".to_string()
        })?;

        // drop も回収する（zombie を残さない）。
        let holder = spawn_netns_holder(target_fds(target_pid)?, Instant::now() + limit())
            .map_err(|e| format!("spawn_netns_holder (drop case): {e:?}"))?;
        let dp = holder.pid();
        drop(holder);
        check(stat_of(dp).is_none(), || {
            "the holder is still visible after drop".to_string()
        })?;
        Ok(())
    }

    /// 中間の supervisor: main スレッドから本番の spawn で holder を起動し、pid を stdout に出して眠る。
    pub fn fake_supervisor(target: Option<std::ffi::OsString>) -> ExitCode {
        let Some(pid) = target.and_then(|s| s.to_str().and_then(|s| s.parse::<u32>().ok())) else {
            eprintln!("netns_holder_launch_userns: fake-supervisor needs a target pid");
            return ExitCode::from(2);
        };
        let holder = match target_fds(pid).and_then(|f| {
            spawn_netns_holder(f, Instant::now() + limit()).map_err(|e| format!("{e:?}"))
        }) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("netns_holder_launch_userns: fake-supervisor: {e}");
                return ExitCode::from(1);
            }
        };
        println!("{}", holder.pid());
        // SIGKILL されるまで holder を持ったまま眠る（正常な後始末の経路を通さない）。
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    fn supervisor_abnormal_exit(target_pid: u32) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut mid = Command::new(exe)
            .args(["--fake-supervisor", &target_pid.to_string()])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("spawn fake supervisor: {e}"))?;
        let stdout = mid.stdout.take().ok_or("stdout")?;
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        let line = match rx.recv_timeout(limit()) {
            Ok(l) => l,
            Err(_) => {
                reap(&mut mid)?;
                return Err("the fake supervisor did not report a holder pid".into());
            }
        };
        let result = (|| {
            let hp: u32 = line
                .trim()
                .parse()
                .map_err(|_| format!("bad holder pid line {line:?}"))?;
            let (_, born) = stat_of(hp).ok_or("holder not visible while its supervisor lives")?;
            // 中間の supervisor を SIGKILL する（後始末の経路を通らない）。
            mid.kill()
                .map_err(|e| format!("kill fake supervisor: {e}"))?;
            let until = Instant::now() + limit().min(Duration::from_secs(5));
            loop {
                match stat_of(hp) {
                    None => return Ok(()),
                    Some(('Z', s)) if s == born => return Ok(()),
                    Some((_, s)) if s != born => return Ok(()),
                    _ => {}
                }
                if Instant::now() >= until {
                    return Err(format!("holder {hp} outlived its killed supervisor"));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        })();
        let reaped = reap(&mut mid);
        result.and(reaped)
    }

    pub fn run() -> ExitCode {
        let mut target = match spawn_target() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("netns_holder_launch_userns: FAILED: {e}");
                return ExitCode::from(1);
            }
        };
        let tp = target.id();
        let result = scenario(tp).and_then(|()| supervisor_abnormal_exit(tp));
        let result = result.and(reap(&mut target));
        match result {
            Ok(()) => {
                println!("{OK_LINE}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("netns_holder_launch_userns: FAILED: {e}");
                ExitCode::from(1)
            }
        }
    }
}
