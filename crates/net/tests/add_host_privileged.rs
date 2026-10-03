//! none モードのコンテナで `--add-host` の `/etc/hosts` 追記が反映されることの実機結合試験
//! （NET-12・NET-6・TASK-185.2・#345・MS-8）。
//!
//! root と util-linux の `unshare` / `nsenter` / `mount` が必要な実機前提テストのため `harness = false` の
//! 独自 `main` で動かし、`-- --ignored` を付けたときだけ実行する（未指定時は「ignored」を出力して成功終了
//! する分離であり、CI 通過のための弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では対象外。
//!
//! # 流れ
//! - ランチャ（host netns・root）: 0700 の一時ディレクトリを作り、`unshare --net --mount -- <exe> --inner` で
//!   新しい netns・mount namespace の子を起動して終了コードを引き継ぐ
//! - 子（新 netns・新 mount namespace）: `/` を rprivate にして tmpfs を載せ、`create_none_netns` で none
//!   モードの netns を作る。一時 hosts ファイルへ `apply_add_hosts` で追記し、private な mount namespace 内
//!   だけで `/etc/hosts` へ bind mount して `nsenter --net=<pin> <exe> --probe ...` で none netns 内から名前解決する
//! - `--probe`（none netns 内）: `/etc/hosts` の追記行のバイト列と、名前解決結果が期待 IP を含むことを照合する。
//!   none netns は外部 DNS に到達できないため、解決成功は `/etc/hosts` 由来であることの判別材料になる
//!
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。前提（root・
//! 外部コマンド・`/etc/nsswitch.conf` の `hosts:` に `files` を含むこと・hosts キャッシュが無いこと）を満たさない
//! 場合は skip せず失敗する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("add_host_privileged: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--probe") {
        linux::probe(args.get(pos + 1..).unwrap_or_default());
    } else if args.iter().any(|a| a == "--inner") {
        linux::inner();
    } else if args.iter().any(|a| a == "--ignored") {
        linux::launcher();
    } else {
        println!(
            "add_host_privileged: ignored (requires root, `unshare`, `nsenter`; run the built executable with `--ignored` under `sudo`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::Read as _;
    use std::net::ToSocketAddrs as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use fandhe_container_net::add_host_dns::apply_add_hosts;
    use fandhe_container_net::error::{NetError, NetErrorCode};
    use fandhe_container_net::instrument::{NetOpRecorder, NoopNetOpRecorder};
    use fandhe_container_net::network::EndpointId;
    use fandhe_container_net::network_mode::none::{
        NoneModeSpec, create_none_netns, release_none_netns,
    };

    const LAUNCHER_PID_ENV: &str = "FANDHE_ADDHOST_TEST_LAUNCHER_PID";
    const DIR_ENV: &str = "FANDHE_ADDHOST_TEST_DIR";
    const OK_LINE: &str = "add_host_privileged: ok mode=none v4=resolved v6=resolved";
    const INITIAL_HOSTS: &str = "127.0.0.1\tlocalhost\n";
    const EXPECTED_HOSTS: &str =
        "127.0.0.1\tlocalhost\n192.0.2.10\tfc-addhost-v4\n2001:db8::10\tfc-addhost-v6\n";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn fail(msg: impl Into<String>) -> NetError {
        NetError::new(NetErrorCode::Internal, msg)
    }

    fn require_root_and_tools() {
        let uid_root = fs::read_to_string("/proc/self/status")
            .expect("read /proc/self/status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_owned))
            .as_deref()
            == Some("0");
        assert!(uid_root, "this test requires root (euid 0); see AGENTS.md");
        for tool in ["unshare", "nsenter", "mount"] {
            let ok = Command::new(tool)
                .arg("--help")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            assert!(ok, "util-linux `{tool}` is required; see AGENTS.md");
        }
    }

    /// ランチャ（host netns の root プロセス）。自身では何も変更せず、一時ディレクトリを作って子を起動する。
    pub fn launcher() {
        require_root_and_tools();
        let dir = std::env::temp_dir().join(format!("fandhe-addhost-test-{}", std::process::id()));
        fs::create_dir(&dir).expect("create temp dir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod temp dir");
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new("unshare")
            .args(["--net", "--mount", "--"])
            .arg(exe)
            .arg("--inner")
            .env(LAUNCHER_PID_ENV, std::process::id().to_string())
            .env(DIR_ENV, &dir)
            .spawn()
            .expect("spawn unshare --net --mount");
        let deadline = Instant::now() + timeout() * 6;
        let code = loop {
            match child.try_wait().expect("wait inner") {
                Some(st) => break st.code().unwrap_or(1),
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    println!("add_host_privileged: inner did not finish before deadline");
                    break 1;
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        // mount namespace は子の終了で消えるので、host 側には空のディレクトリだけが残る。
        let _ = fs::remove_dir(&dir);
        std::process::exit(code);
    }

    fn ensure_launched_by_launcher() -> Result<(), NetError> {
        let expected = std::env::var(LAUNCHER_PID_ENV)
            .ok()
            .and_then(|v| v.parse::<u32>().ok());
        if expected != Some(std::os::unix::process::parent_id()) {
            return Err(fail(
                "`--inner` must be started by the `--ignored` launcher; refusing to run",
            ));
        }
        Ok(())
    }

    /// 子が親（ランチャ）とは別の netns にいることを確かめる（host の `/etc/hosts` を触らない前提の確認）。
    fn ensure_isolated_mount_and_net() -> Result<(), NetError> {
        let parent = std::os::unix::process::parent_id();
        for ns in ["net", "mnt"] {
            let own = fs::read_link(format!("/proc/self/ns/{ns}"))
                .map_err(|e| fail(format!("readlink {ns}: {e}")))?;
            let par = fs::read_link(format!("/proc/{parent}/ns/{ns}"))
                .map_err(|e| fail(format!("cannot read parent {ns} ns ({e}); refusing to run")))?;
            if own == par {
                return Err(fail(format!(
                    "same {ns} namespace as the parent process; refusing to run (see AGENTS.md)"
                )));
            }
        }
        Ok(())
    }

    /// 外部コマンドを期限つきで実行する（REPAIR-5）。期限切れなら子を kill して回収する。
    fn run_cmd(program: &str, args: &[&str]) -> Result<String, NetError> {
        // 子孫がパイプを保持しても止まらないよう、子を新しいプロセスグループに入れ、期限切れ時は
        // グループごと SIGKILL する。パイプ回収も期限で打ち切る（REPAIR-5）。
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|e| fail(format!("spawn {program}: {e}")))?;
        let pgid = child.id();
        let kill_group = |child: &mut std::process::Child| {
            let _ = Command::new("kill")
                .args(["-KILL", "--", &format!("-{pgid}")])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = child.kill();
            let _ = child.wait();
        };
        let mut out_pipe = child.stdout.take();
        let mut err_pipe = child.stderr.take();
        let (out_tx, out_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let (err_tx, err_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        // 読み取りスレッドは join せず切り離す（グループ kill 後は EOF で自然に終了する）。
        std::thread::spawn(move || {
            let mut b = Vec::new();
            if let Some(p) = out_pipe.as_mut() {
                let _ = p.read_to_end(&mut b);
            }
            let _ = out_tx.send(b);
        });
        std::thread::spawn(move || {
            let mut b = Vec::new();
            if let Some(p) = err_pipe.as_mut() {
                let _ = p.read_to_end(&mut b);
            }
            let _ = err_tx.send(b);
        });
        let deadline = Instant::now() + timeout();
        let status = loop {
            match child
                .try_wait()
                .map_err(|e| fail(format!("wait {program}: {e}")))?
            {
                Some(st) => break st,
                None if Instant::now() >= deadline => {
                    kill_group(&mut child);
                    return Err(NetError::new(
                        NetErrorCode::Timeout,
                        format!("{program} did not finish before the deadline"),
                    ));
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        // 直接の子が終了しても子孫がパイプを保持し続け得るため、回収は期限内に限る。
        let remaining = deadline.saturating_duration_since(Instant::now());
        let stdout = out_rx.recv_timeout(remaining).ok();
        let remaining = deadline.saturating_duration_since(Instant::now());
        let stderr = err_rx.recv_timeout(remaining).ok();
        let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
            kill_group(&mut child);
            return Err(NetError::new(
                NetErrorCode::Timeout,
                format!("{program} output pipes did not close before the deadline"),
            ));
        };
        if !status.success() {
            return Err(fail(format!(
                "{program} failed: {}{}",
                String::from_utf8_lossy(&stderr),
                String::from_utf8_lossy(&stdout)
            )));
        }
        Ok(String::from_utf8_lossy(&stdout).into_owned())
    }

    /// `nsenter --net=<pin>` で入り直した自身の再入モード。`args` は `<name> <expected-ip>` の組の列。
    pub fn probe(args: &[String]) {
        match probe_checked(args) {
            Ok(()) => println!("probe: ok"),
            Err(m) => {
                println!("probe: failed: {m}");
                std::process::exit(1);
            }
        }
    }

    fn probe_checked(args: &[String]) -> Result<(), String> {
        let hosts = fs::read_to_string("/etc/hosts").map_err(|e| format!("read hosts: {e}"))?;
        if hosts != EXPECTED_HOSTS {
            return Err(format!("unexpected /etc/hosts content: {hosts:?}"));
        }
        if args.is_empty() || !args.len().is_multiple_of(2) {
            return Err("expected <name> <ip> pairs".to_owned());
        }
        for pair in args.chunks(2) {
            let (name, want) = (&pair[0], &pair[1]);
            let want_ip: std::net::IpAddr =
                want.parse().map_err(|e| format!("parse {want}: {e}"))?;
            let resolved: Vec<std::net::IpAddr> = (name.as_str(), 0)
                .to_socket_addrs()
                .map_err(|e| format!("resolve {name}: {e}"))?
                .map(|a| a.ip())
                .collect();
            if !resolved.contains(&want_ip) {
                return Err(format!(
                    "{name} resolved to {resolved:?}, expected {want_ip}"
                ));
            }
        }
        Ok(())
    }

    pub fn inner() {
        match inner_checked() {
            Ok(()) => println!("{OK_LINE}"),
            Err(e) => {
                println!("add_host_privileged: failed: {e}");
                std::process::exit(1);
            }
        }
    }

    fn inner_checked() -> Result<(), NetError> {
        ensure_launched_by_launcher()?;
        ensure_isolated_mount_and_net()?;
        let base = std::path::PathBuf::from(
            std::env::var(DIR_ENV).map_err(|_| fail("missing test directory env"))?,
        );
        // host へ mount と pin ファイルを漏らさない: 先に伝播を切り、tmpfs を載せる。
        run_cmd("mount", &["--make-rprivate", "/"])?;
        let base_str = base
            .to_str()
            .ok_or_else(|| fail("test directory is not UTF-8"))?;
        run_cmd(
            "mount",
            &["-t", "tmpfs", "-o", "mode=0700", "tmpfs", base_str],
        )?;
        let exe = std::env::current_exe().map_err(|e| fail(format!("current_exe: {e}")))?;
        let exe_str = exe.to_str().ok_or_else(|| fail("exe path is not UTF-8"))?;

        // none モードの netns（外部 DNS に到達できない）。
        let t = timeout();
        let recorder: Arc<dyn NetOpRecorder> = Arc::new(NoopNetOpRecorder);
        let spec = NoneModeSpec::new(EndpointId::new("addhostctr")?, base.clone())?;
        let none = create_none_netns(&spec, t, &recorder)
            .map_err(|e| fail(format!("create_none_netns failed at {:?}: {e}", e.step)))?;
        // 以降はどこで失敗しても umount と netns 解放を必ず実行し、本体と後始末の両方のエラーを保つ。
        let pin_path = none.netns_path.clone();
        let mut mounted = false;
        let body = run_body(&base, &pin_path, exe_str, &mut mounted);
        let umount_res = if mounted {
            run_cmd("umount", &["/etc/hosts"]).map(|_| ())
        } else {
            Ok(())
        };
        let release_res =
            release_none_netns(none).map_err(|e| fail(format!("release_none_netns failed: {e}")));
        combine_results(body, umount_res, release_res)
    }

    /// hosts 追記・bind mount・none netns 内での照合。`mounted` は `/etc/hosts` へ bind した後に立てる。
    fn run_body(
        base: &std::path::Path,
        pin_path: &std::path::Path,
        exe_str: &str,
        mounted: &mut bool,
    ) -> Result<(), NetError> {
        // コンテナの hosts ファイル相当へ追記し、private な mount ns 内だけで /etc/hosts に重ねる。
        let hosts = base.join("hosts");
        fs::write(&hosts, INITIAL_HOSTS).map_err(|e| fail(format!("write hosts: {e}")))?;
        apply_add_hosts(
            &hosts,
            ["fc-addhost-v4:192.0.2.10", "fc-addhost-v6:2001:db8::10"],
        )?;
        let hosts_str = hosts
            .to_str()
            .ok_or_else(|| fail("hosts path is not UTF-8"))?;
        run_cmd("mount", &["--bind", hosts_str, "/etc/hosts"])?;
        *mounted = true;

        let pin_arg = format!(
            "--net={}",
            pin_path
                .to_str()
                .ok_or_else(|| fail("pin path is not UTF-8"))?
        );
        let out = run_cmd(
            "nsenter",
            &[
                &pin_arg,
                exe_str,
                "--probe",
                "fc-addhost-v4",
                "192.0.2.10",
                "fc-addhost-v6",
                "2001:db8::10",
            ],
        )?;
        if out.trim() != "probe: ok" {
            return Err(fail(format!("unexpected probe output: {out}")));
        }
        Ok(())
    }

    /// 本体・umount・解放の結果を 1 つにまとめる。失敗が複数なら全メッセージを連結して保持する。
    fn combine_results(
        body: Result<(), NetError>,
        umount: Result<(), NetError>,
        release: Result<(), NetError>,
    ) -> Result<(), NetError> {
        let msgs: Vec<String> = [("body", body), ("umount", umount), ("release", release)]
            .into_iter()
            .filter_map(|(label, r)| r.err().map(|e| format!("{label}: {e}")))
            .collect();
        if msgs.is_empty() {
            Ok(())
        } else {
            Err(fail(msgs.join("; ")))
        }
    }
}
