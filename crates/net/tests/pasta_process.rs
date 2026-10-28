//! pasta の起動・準備完了の待ち・タイムアウト・回収の非特権結合試験（NET-9・REPAIR-5・ERR-1・#1938。root 不要・pasta 不要・
//! 既定の集合。Linux 以外は `Unimplemented` と純関数だけを照合する）。
//!
//! 自身の実行ファイルを「偽の pasta」としてコピーして実行する（第 1 引数が `-f` のときだけ偽の pasta として振る舞い、
//! モードはコピー先の親ディレクトリ名で選ぶ）ため `harness = false`。偽の pasta は `--version` にも答える
//! （`verify_pasta_binary_below` が実行する）。本物の pasta での確認（AppArmor・`-P` の書き込みの時点・PDEATHSIG）は
//! #1941 の担当。待ちはすべて有限の期限で切る（REPAIR-5）。

const OK_LINE: &str = "pasta_process: spawn/ready/timeout/reap passed (NET-9)";

#[cfg(not(target_os = "linux"))]
fn main() {
    use fandhe_container_net::error::NetErrorCode;
    use fandhe_container_net::pasta::process::{MSG_PASTA_TARGET, PastaTarget};
    let e = PastaTarget::from_pid(1).unwrap_err();
    assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    assert_eq!(e.message(), MSG_PASTA_TARGET);
    println!("{OK_LINE}");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::io::{Read as _, Write as _};
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_net::error::NetErrorCode;
    use fandhe_container_net::pasta::PastaStage;
    use fandhe_container_net::pasta::binary::{PastaBinary, verify_pasta_binary_below};
    use fandhe_container_net::pasta::port_forward::PastaPortForwards;
    use fandhe_container_net::pasta::process::{
        MSG_PASTA_PID_FILE, MSG_PASTA_TARGET, MSG_PASTA_TIMEOUT_RANGE, PASTA_STDERR_CAP,
        PASTA_STOP_GRACE, PastaStopPath, PastaTarget, pasta_argv, spawn_pasta,
    };
    use fandhe_container_net::pasta::run_dir::PastaRunDir;

    const GOOD_VERSION: &str = "pasta 0.0~git20260120.386b5f5-1\nCopyright Red Hat\n";
    const NOTERM_MARKER: &str = "--noterm-marker";

    pub fn main() -> ExitCode {
        let args: Vec<OsString> = std::env::args_os().skip(1).collect();
        if args.len() == 1 && args[0] == "--version" {
            print!("{GOOD_VERSION}");
            return ExitCode::SUCCESS;
        }
        match args.first().and_then(|a| a.to_str()) {
            Some("-f") => fake_pasta(&args, false),
            Some(NOTERM_MARKER) => fake_pasta(args.get(1..).unwrap_or(&[]), true),
            Some("--intermediate") => intermediate(&args),
            _ => {}
        }
        let anchor = std::fs::canonicalize(env!("CARGO_TARGET_TMPDIR")).expect("anchor");
        let base = anchor.join(format!("pasta-process-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("base");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let result = std::panic::catch_unwind(|| run(&anchor, &base));
        let _ = std::fs::remove_dir_all(&base);
        if let Err(p) = result {
            std::panic::resume_unwind(p);
        }
        println!("{}", super::OK_LINE);
        ExitCode::SUCCESS
    }

    fn mode_of_exe() -> String {
        std::env::current_exe()
            .ok()
            .as_deref()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned()
    }

    fn sleep_long() -> ! {
        for _ in 0..30 {
            std::thread::sleep(Duration::from_secs(1));
        }
        std::process::exit(0)
    }

    fn write_pid(path: &Path, pid: u32) {
        std::fs::write(path, format!("{pid}\n")).expect("write pid");
    }

    /// 偽の pasta 本体。`args` は argv[0] を除いた引数（`-f --quiet -P <pid> … <target>`）。
    fn fake_pasta(args: &[OsString], reexeced: bool) -> ! {
        let mode = mode_of_exe();
        let pid_file = PathBuf::from(args.get(3).cloned().unwrap_or_default());
        let me = std::process::id();
        let dir = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(Path::to_path_buf))
            .unwrap_or_default();
        match mode.as_str() {
            "ready" => {
                write_pid(&pid_file, me);
                sleep_long()
            }
            "argv" => {
                let mut bytes = Vec::new();
                for a in std::env::args_os() {
                    use std::os::unix::ffi::OsStrExt as _;
                    bytes.extend_from_slice(a.as_bytes());
                    bytes.push(0);
                }
                std::fs::write(dir.join("args"), bytes).expect("args");
                let mut stdin_bytes = Vec::new();
                let _ = std::io::stdin().read_to_end(&mut stdin_bytes);
                let ok = std::env::vars_os().count() == 0
                    && stdin_bytes.is_empty()
                    && std::env::current_dir().is_ok_and(|d| d == Path::new("/"));
                std::fs::write(dir.join("self_check"), if ok { "ok" } else { "bad" }).expect("chk");
                write_pid(&pid_file, me);
                sleep_long()
            }
            "exit3" => std::process::exit(3),
            "hang" => sleep_long(),
            "wrongpid" => {
                write_pid(&pid_file, me + 1);
                sleep_long()
            }
            "garbage" => {
                std::fs::write(&pid_file, "abc").expect("garbage");
                sleep_long()
            }
            "die" => {
                write_pid(&pid_file, me);
                std::thread::sleep(Duration::from_millis(200));
                std::process::exit(7)
            }
            "noterm" => {
                // SIGTERM を無視した状態（無視の設定は exec をまたいで残る）で自分を再実行する。
                if !reexeced {
                    let exe = std::env::current_exe().expect("exe");
                    let e = Command::new("/bin/sh")
                        .arg("-c")
                        .arg("trap '' TERM; exec \"$0\" \"$@\"")
                        .arg(exe)
                        .arg(NOTERM_MARKER)
                        .args(args)
                        .exec();
                    eprintln!("exec failed: {e}");
                    std::process::exit(99);
                }
                write_pid(&pid_file, me);
                sleep_long()
            }
            "stderr" => {
                let mut noise = vec![0x01u8, b'E'];
                noise.extend(std::iter::repeat_n(b'A', 8190));
                let _ = std::io::stderr().write_all(&noise);
                write_pid(&pid_file, me);
                sleep_long()
            }
            "pdeath" => {
                write_pid(&pid_file, me);
                sleep_long()
            }
            _ => std::process::exit(98),
        }
    }

    /// PDEATHSIG の確認用の中間プロセス: pasta を起動して pid を出力し、Drop を走らせずに終了する。
    fn intermediate(args: &[OsString]) -> ! {
        let s = |i: usize| PathBuf::from(args.get(i).cloned().unwrap_or_default());
        let (anchor, pasta, root) = (s(1), s(2), s(3));
        let bin = verify_pasta_binary_below(&anchor, &pasta).expect("verify");
        let root = std::fs::File::open(root).expect("root");
        let rd = PastaRunDir::prepare(root.as_fd(), "pdeath").expect("prepare");
        let target = PastaTarget::from_pid(2).expect("target");
        let (proc, ready) = spawn_pasta(
            &bin,
            &rd,
            &PastaPortForwards::new(),
            target,
            Duration::from_secs(5),
        )
        .expect("spawn");
        println!("{}", ready.pid());
        let _ = std::io::stdout().flush();
        std::mem::forget(proc);
        std::process::exit(0)
    }

    fn mkdir(base: &Path, name: &str) -> PathBuf {
        let d = base.join(name);
        std::fs::create_dir_all(&d).expect("mkdir");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        d
    }

    fn place(base: &Path, mode: &str) -> PathBuf {
        let d = mkdir(base, mode);
        let f = d.join("pasta");
        std::fs::copy(std::env::current_exe().expect("exe"), &f).expect("copy");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        f
    }

    fn binary(anchor: &Path, base: &Path, mode: &str) -> PastaBinary {
        verify_pasta_binary_below(anchor, &place(base, mode)).expect("verify fake pasta")
    }

    fn proc_gone(pid: u32) -> bool {
        !Path::new(&format!("/proc/{pid}")).exists()
    }

    fn target() -> PastaTarget {
        PastaTarget::from_pid(2).expect("target")
    }

    fn run(anchor: &Path, base: &Path) {
        let root_dir = mkdir(base, "root");
        let root = std::fs::File::open(&root_dir).expect("root fd");
        let none = PastaPortForwards::new();
        let long = Duration::from_secs(5);
        let short = Duration::from_millis(300);
        use NetErrorCode as C;

        // ready: 起動 → 生存 → SIGTERM で停止 → zombie を残さない。
        {
            let bin = binary(anchor, base, "ready");
            let rd = PastaRunDir::prepare(root.as_fd(), "ready").expect("prepare");
            let (mut p, ready) = spawn_pasta(&bin, &rd, &none, target(), long).expect("spawn");
            let pid = p.pid();
            assert_eq!(ready.pid(), pid);
            assert_eq!(p.is_alive(), Ok(true));
            let out = p.stop().expect("stop");
            assert_eq!(out.path, PastaStopPath::Term);
            assert_eq!(out.exit.signal, Some(15));
            assert!(proc_gone(pid), "no zombie after stop");
            rd.remove().expect("remove run dir");
            assert!(!root_dir.join("@pasta/ready").exists());
        }

        // argv: 固定の並び・env 空・cwd /・stdin EOF。
        {
            let bin = binary(anchor, base, "argv");
            let rd = PastaRunDir::prepare(root.as_fd(), "argv").expect("prepare");
            let fwd = PastaPortForwards::parse_all(["127.0.0.1:8080:80", "9090:90/udp"])
                .expect("forwards");
            let (p, _) = spawn_pasta(&bin, &rd, &fwd, target(), long).expect("spawn");
            let raw = std::fs::read(base.join("argv/args")).expect("args file");
            let got: Vec<String> = raw
                .split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            let mut want = vec!["pasta".to_owned()];
            want.extend(
                pasta_argv(rd.pid_path(), &fwd, target())
                    .iter()
                    .map(|a| a.to_string_lossy().into_owned()),
            );
            assert_eq!(got, want);
            assert_eq!(
                std::fs::read_to_string(base.join("argv/self_check")).expect("chk"),
                "ok"
            );
            p.stop().expect("stop");
        }

        // exit3: 準備完了前の終了は FailedPrecondition。終了コードが材料に入り、子は回収済み。
        {
            let bin = binary(anchor, base, "exit3");
            let rd = PastaRunDir::prepare(root.as_fd(), "exit3").expect("prepare");
            let mut e = spawn_pasta(&bin, &rd, &none, target(), long).expect_err("exit3");
            assert_eq!(e.code(), C::FailedPrecondition);
            assert_eq!(e.diagnostics().stage, PastaStage::Ready);
            assert_eq!(e.diagnostics().exit.code, Some(3));
            assert!(e.take_unreaped().is_none());
        }

        // hang: 期限切れは Timeout。kill して回収する。
        {
            let bin = binary(anchor, base, "hang");
            let rd = PastaRunDir::prepare(root.as_fd(), "hang").expect("prepare");
            let t = Instant::now();
            let mut e = spawn_pasta(&bin, &rd, &none, target(), short).expect_err("hang");
            let took = t.elapsed();
            assert_eq!(e.code(), C::Timeout);
            assert!(
                took >= short && took < short + Duration::from_secs(2),
                "took {took:?}"
            );
            assert_eq!(e.diagnostics().exit.signal, Some(9));
            assert!(e.take_unreaped().is_none());
        }

        // wrongpid: 一致しない値は準備完了と誤検出しない。
        {
            let bin = binary(anchor, base, "wrongpid");
            let rd = PastaRunDir::prepare(root.as_fd(), "wrongpid").expect("prepare");
            let e = spawn_pasta(&bin, &rd, &none, target(), short).expect_err("wrongpid");
            assert_eq!(e.code(), C::Timeout);
        }

        // garbage: 10 進以外は FailedPrecondition（固定の message）。
        {
            let bin = binary(anchor, base, "garbage");
            let rd = PastaRunDir::prepare(root.as_fd(), "garbage").expect("prepare");
            let e = spawn_pasta(&bin, &rd, &none, target(), long).expect_err("garbage");
            assert_eq!(e.code(), C::FailedPrecondition);
            assert_eq!(e.message(), MSG_PASTA_PID_FILE);
        }

        // die: 準備完了の後の死を is_alive が検出し、stop は終了状態を返す。
        {
            let bin = binary(anchor, base, "die");
            let rd = PastaRunDir::prepare(root.as_fd(), "die").expect("prepare");
            let (mut p, _) = spawn_pasta(&bin, &rd, &none, target(), long).expect("spawn");
            let until = Instant::now() + Duration::from_secs(2);
            while p.is_alive() == Ok(true) {
                assert!(Instant::now() < until, "pasta did not die in time");
                std::thread::sleep(Duration::from_millis(20));
            }
            assert_eq!(p.is_alive(), Ok(false));
            let out = p.stop().expect("stop");
            assert_eq!(out.path, PastaStopPath::AlreadyExited);
            assert_eq!(out.exit.code, Some(7));
        }

        // noterm: SIGTERM を無視すると SIGKILL まで進む（猶予を待つ）。
        {
            let bin = binary(anchor, base, "noterm");
            let rd = PastaRunDir::prepare(root.as_fd(), "noterm").expect("prepare");
            let (p, _) = spawn_pasta(&bin, &rd, &none, target(), long).expect("spawn");
            let pid = p.pid();
            let t = Instant::now();
            let out = p.stop().expect("stop");
            assert_eq!(out.path, PastaStopPath::Kill);
            assert_eq!(out.exit.signal, Some(9));
            assert!(t.elapsed() >= PASTA_STOP_GRACE, "took {:?}", t.elapsed());
            assert!(proc_gone(pid));
        }

        // stderr: 大量の出力でも子は止まらず、保持は上限以下でエスケープ済み。
        {
            let bin = binary(anchor, base, "stderr");
            let rd = PastaRunDir::prepare(root.as_fd(), "stderr").expect("prepare");
            let (p, _) = spawn_pasta(&bin, &rd, &none, target(), long).expect("spawn");
            let out = p.stop().expect("stop");
            assert!(out.stderr_excerpt.len() <= PASTA_STDERR_CAP);
            assert!(
                out.stderr_excerpt.starts_with("\\x01E"),
                "{}",
                out.stderr_excerpt
            );
            assert!(out.stderr_excerpt.chars().all(|c| (' '..='~').contains(&c)));
        }

        // stale: 古い pid は prepare が消すので、残った値で誤検出しない。symlink の pid は拒否する。
        {
            let bin = binary(anchor, base, "ready");
            let rd = PastaRunDir::prepare(root.as_fd(), "stale").expect("prepare");
            write_pid(rd.pid_path(), 999_999);
            drop(rd);
            let rd = PastaRunDir::prepare(root.as_fd(), "stale").expect("prepare again");
            assert!(!rd.pid_path().exists());
            let (p, _) = spawn_pasta(&bin, &rd, &none, target(), long).expect("spawn");
            p.stop().expect("stop");
            std::fs::remove_file(rd.pid_path()).ok();
            symlink("/etc/passwd", rd.pid_path()).expect("symlink");
            drop(rd);
            let e = PastaRunDir::prepare(root.as_fd(), "stale").expect_err("symlink pid");
            assert_eq!(e.code(), C::FailedPrecondition);
        }

        // 入力の拒否（固定の英文でパスを含まない）。
        {
            let e = PastaTarget::from_pid(1).expect_err("pid 1");
            assert_eq!(
                (e.code(), e.message()),
                (C::InvalidArgument, MSG_PASTA_TARGET)
            );
            let bin = binary(anchor, base, "ready");
            let rd = PastaRunDir::prepare(root.as_fd(), "badtimeout").expect("prepare");
            for t in [Duration::ZERO, Duration::from_secs(11)] {
                let e = spawn_pasta(&bin, &rd, &none, target(), t).expect_err("timeout range");
                assert_eq!(e.code(), C::InvalidArgument);
                assert_eq!(e.message(), MSG_PASTA_TIMEOUT_RANGE);
                assert_eq!(e.diagnostics().stage, PastaStage::Prepare);
            }
        }

        pdeathsig(anchor, base, &root_dir);
    }

    /// 中間プロセスが Drop なしで終わると、PDEATHSIG で pasta が消える（12.10 の (1)）。
    fn pdeathsig(anchor: &Path, base: &Path, root_dir: &Path) {
        let pasta = place(base, "pdeath");
        let mut mid = Command::new(std::env::current_exe().expect("exe"))
            .arg("--intermediate")
            .arg(anchor)
            .arg(&pasta)
            .arg(root_dir)
            .stdout(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn intermediate");
        // 出力取得も終了確認も共通の期限（10 秒）の中で行う。超えたら強制終了して有限時間で回収する。
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut pipe = mid.stdout.take().expect("stdout");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut out = String::new();
            let r = pipe.read_to_string(&mut out).map(|_| out);
            let _ = tx.send(r);
        });
        let got = rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        let out = match got {
            Ok(r) => r.expect("read pid"),
            Err(_) => {
                let _ = mid.kill();
                wait_exit(&mut mid, Duration::from_secs(2));
                panic!("intermediate produced no pid before the deadline");
            }
        };
        let left = deadline.saturating_duration_since(Instant::now());
        let st = wait_exit(&mut mid, left);
        assert!(st, "intermediate did not exit");
        let pid: u32 = out.trim().parse().expect("pasta pid");
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            let state = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok();
            // 消えている、または kill 済みで回収待ち（zombie）。
            let dead =
                state.is_none_or(|s| s.rsplit(") ").next().is_some_and(|r| r.starts_with('Z')));
            if dead {
                break;
            }
            assert!(Instant::now() < until, "pasta {pid} survived its parent");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_exit(c: &mut std::process::Child, within: Duration) -> bool {
        let until = Instant::now() + within;
        loop {
            if let Ok(Some(_)) = c.try_wait() {
                return true;
            }
            if Instant::now() >= until {
                let _ = c.kill();
                // 強制終了後の回収も有限時間で打ち切る。
                let reap = Instant::now() + Duration::from_secs(2);
                while !matches!(c.try_wait(), Ok(Some(_))) && Instant::now() < reap {
                    std::thread::sleep(Duration::from_millis(10));
                }
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
