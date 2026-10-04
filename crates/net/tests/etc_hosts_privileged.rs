//! 軽量運用（`NameResolution::StaticHosts`）の bridge ネットワークで、/etc/hosts 静的注入によりサービス名が
//! 解決され、DNS ヘルパーが起動しないことの実機結合試験（NET-8・NET-7・TASK-146.1・#334・MS-8）。
//!
//! root と util-linux の `unshare` / `nsenter` / `mount` が必要な実機前提テストのため `harness = false` の
//! 独自 `main` で動かし、`-- --ignored` を付けたときだけ実行する（未指定時は「ignored」を出力して成功終了
//! する分離であり、CI 通過のための弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では対象外。
//!
//! # 流れ
//! - ランチャ（host netns・root）: 0700 の一時ディレクトリを作り、`unshare --net --mount -- <exe> --inner` で子を起動する
//! - 子: `/` を rprivate にして tmpfs を載せ、軽量運用の `create_network` で c1・c2 を `attach_container` する。
//!   `join_network` が両方 `HelperDisabled` で、gateway:53 の UDP 待受が 0 件であることを確かめる。
//!   c2 用の一時 hosts へ `inject_service_hosts` で追記し、private な mount namespace 内だけで `/etc/hosts` へ
//!   bind mount して `nsenter --net=<c2 の pin> <exe> --probe ...` で `svc-a` が c1 のアドレスへ解決されることを照合する
//!
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。前提（root・外部コマンド・
//! `/etc/nsswitch.conf` の `hosts:` に `files` を含むこと・hosts キャッシュが無いこと）を満たさない場合は skip せず失敗する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("etc_hosts_privileged: Linux only, not applicable on this OS");
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
            "etc_hosts_privileged: ignored (requires root, `unshare`, `nsenter`; run the built executable with `--ignored` under `sudo`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::Read as _;
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, ToSocketAddrs as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_net::dns_helper::refcount::{
        DnsHelperRefCounts, JoinOutcome, ProcessLauncher,
    };
    use fandhe_container_net::dns_helper::{
        DnsListenAddr, READY_TIMEOUT_DEFAULT, REAP_TIMEOUT_DEFAULT,
    };
    use fandhe_container_net::error::{NetError, NetErrorCode};
    use fandhe_container_net::etc_hosts::{
        NameResolution, StaticHostsOutcome, inject_service_hosts,
    };
    use fandhe_container_net::netlink_route::{IpPrefix, NetlinkRouteSocket};
    use fandhe_container_net::netns::ContainerNetns;
    use fandhe_container_net::network::{
        AttachedContainer, ContainerAttachSpec, CreatedNetwork, EndpointId, NetworkCreateSpec,
        NetworkName, PortRegistry, StaticIpam, attach_container, create_network, delete_network,
    };
    use fandhe_container_net::nftables_batch::NetlinkNetfilterSocket;

    const LAUNCHER_PID_ENV: &str = "FANDHE_ETCHOSTS_TEST_LAUNCHER_PID";
    const DIR_ENV: &str = "FANDHE_ETCHOSTS_TEST_DIR";
    const NETWORK: &str = "ethosts";
    const OK_LINE: &str =
        "etc_hosts_privileged: ok mode=static-hosts peer=resolved helper=not-started";
    const INITIAL_HOSTS: &str = "127.0.0.1\tlocalhost\n";

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

    fn expect_eq<T: PartialEq + std::fmt::Debug>(
        what: &str,
        got: T,
        want: T,
    ) -> Result<(), NetError> {
        if got == want {
            Ok(())
        } else {
            Err(fail(format!("{what}: got {got:?}, want {want:?}")))
        }
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
        let dir = std::env::temp_dir().join(format!("fandhe-ethosts-test-{}", std::process::id()));
        fs::create_dir(&dir).expect("create temp dir");
        // 管理ルートは symlink を含まない絶対パスで渡す契約（`inject_service_hosts` は正規化しない）。
        let dir = fs::canonicalize(&dir).expect("canonicalize temp dir");
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
                    println!("etc_hosts_privileged: inner did not finish before deadline");
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

    /// `nsenter --net=<pin>` で入り直した自身の再入モード。引数は `<name> <expected-ip> <expected-hosts>`。
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
        let [name, want, expected_hosts] = args else {
            return Err("expected <name> <ip> <hosts>".to_owned());
        };
        let hosts = fs::read_to_string("/etc/hosts").map_err(|e| format!("read hosts: {e}"))?;
        if &hosts != expected_hosts {
            return Err(format!("unexpected /etc/hosts content: {hosts:?}"));
        }
        let want_ip: IpAddr = want.parse().map_err(|e| format!("parse {want}: {e}"))?;
        let resolved: Vec<IpAddr> = (name.as_str(), 0)
            .to_socket_addrs()
            .map_err(|e| format!("resolve {name}: {e}"))?
            .map(|a| a.ip())
            .collect();
        if !resolved.contains(&want_ip) {
            return Err(format!(
                "{name} resolved to {resolved:?}, expected {want_ip}"
            ));
        }
        Ok(())
    }

    /// `/proc/self/net/udp` の local address 一覧（IPv4 は 16 進のネイティブエンディアン、port は 16 進）。
    fn udp_local_addrs() -> Result<Vec<SocketAddrV4>, NetError> {
        let text = fs::read_to_string("/proc/self/net/udp")
            .map_err(|e| fail(format!("read /proc/self/net/udp: {e}")))?;
        let mut out = Vec::new();
        for line in text.lines().skip(1) {
            let Some((ip_hex, port_hex)) = line
                .split_whitespace()
                .nth(1)
                .and_then(|l| l.split_once(':'))
            else {
                continue;
            };
            let (Ok(ip), Ok(port)) = (
                u32::from_str_radix(ip_hex, 16),
                u16::from_str_radix(port_hex, 16),
            ) else {
                continue;
            };
            out.push(SocketAddrV4::new(Ipv4Addr::from(ip.to_ne_bytes()), port));
        }
        Ok(out)
    }

    pub fn inner() {
        match inner_checked() {
            Ok(()) => println!("{OK_LINE}"),
            Err(e) => {
                println!("etc_hosts_privileged: failed: {e}");
                std::process::exit(1);
            }
        }
    }

    fn inner_checked() -> Result<(), NetError> {
        ensure_launched_by_launcher()?;
        ensure_isolated_mount_and_net()?;
        let base =
            PathBuf::from(std::env::var(DIR_ENV).map_err(|_| fail("missing test directory env"))?);
        let base_str = base
            .to_str()
            .ok_or_else(|| fail("test directory is not UTF-8"))?;
        // host へ mount と pin ファイルを漏らさない: 先に伝播を切り、tmpfs を載せる。
        run_cmd("mount", &["--make-rprivate", "/"])?;
        run_cmd(
            "mount",
            &["-t", "tmpfs", "-o", "mode=0700", "tmpfs", base_str],
        )?;

        let route = NetlinkRouteSocket::open()?;
        let nft = NetlinkNetfilterSocket::open()?;
        let t = timeout();
        // IPAM は特権資源を作る前に構築する（構築失敗で delete_network に到達できない経路を作らない）。
        let gateway = IpPrefix::new("10.217.0.1".parse().map_err(|_| fail("addr"))?, 24)?;
        let name = NetworkName::new(NETWORK)?;
        let mut ipam = StaticIpam::new(&name, gateway)?;
        let spec = NetworkCreateSpec::new(NetworkName::new(NETWORK)?, gateway)?
            .with_name_resolution(NameResolution::StaticHosts);
        let net = create_network(&route, &nft, &spec, t)
            .map_err(|e| fail(format!("create_network failed at {:?}: {e}", e.step)))?;

        let mut ports = PortRegistry::new();
        let mut attached = Vec::new();
        let mut mounted = false;
        let result = run_body(
            &net,
            &route,
            &nft,
            &base,
            &mut ipam,
            &mut ports,
            &mut attached,
            &mut mounted,
        );

        // 後始末（必ず実行）: umount → ネットワーク削除。
        let umount_res = if mounted {
            run_cmd("umount", &["/etc/hosts"]).map(|_| ())
        } else {
            Ok(())
        };
        let deleted = delete_network(&route, &nft, &net, attached, &mut ipam, &mut ports, t)
            .map(|_| ())
            .map_err(|e| fail(format!("delete_network failed: {e}")));
        let msgs: Vec<String> = [
            ("body", result),
            ("umount", umount_res),
            ("delete", deleted),
        ]
        .into_iter()
        .filter_map(|(label, r)| r.err().map(|e| format!("{label}: {e}")))
        .collect();
        if msgs.is_empty() {
            Ok(())
        } else {
            Err(fail(msgs.join("; ")))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_body(
        net: &CreatedNetwork,
        route: &NetlinkRouteSocket,
        nft: &NetlinkNetfilterSocket,
        base: &Path,
        ipam: &mut StaticIpam,
        ports: &mut PortRegistry,
        attached: &mut Vec<AttachedContainer<ContainerNetns>>,
        mounted: &mut bool,
    ) -> Result<(), NetError> {
        let t = timeout();
        let exe = std::env::current_exe().map_err(|e| fail(format!("current_exe: {e}")))?;
        let exe_str = exe.to_str().ok_or_else(|| fail("exe path is not UTF-8"))?;
        let c1 = EndpointId::new("c1")?;
        let c2 = EndpointId::new("c2")?;
        let spec1 = ContainerAttachSpec::new(c1.clone(), net, base.to_path_buf())?;
        let a1 = attach_container(route, nft, &spec1, ipam, ports, t)
            .map_err(|e| fail(format!("attach c1 failed at {:?}: {e}", e.step)))?;
        let c1_ip = a1.address.addr();
        attached.push(a1);
        let spec2 = ContainerAttachSpec::new(c2.clone(), net, base.to_path_buf())?;
        let a2 = attach_container(route, nft, &spec2, ipam, ports, t)
            .map_err(|e| fail(format!("attach c2 failed at {:?}: {e}", e.step)))?;
        let c2_ip = a2.address.addr();
        let pin2 = a2
            .netns_path
            .to_str()
            .ok_or_else(|| fail("pin path is not UTF-8"))
            .map(str::to_owned);
        attached.push(a2);
        let pin2 = pin2?;

        // NET-7 の参照カウント経由でも DNS ヘルパーは起動しない。
        let rc = DnsHelperRefCounts::new(ProcessLauncher::new(
            exe.clone(),
            READY_TIMEOUT_DEFAULT,
            REAP_TIMEOUT_DEFAULT,
        )?);
        for id in [&c1, &c2] {
            expect_eq(
                "join_network",
                rc.join_network(net, id)?,
                JoinOutcome::HelperDisabled,
            )?;
        }
        expect_eq("helper running", rc.is_running(&net.name), false)?;
        let listen = DnsListenAddr::for_network(net)?.socket_addr();
        let udp53 = udp_local_addrs()?.iter().filter(|a| **a == listen).count();
        expect_eq("udp sockets on gateway:53", udp53, 0)?;

        // c2 の hosts へ参加者全員を静的注入し、/etc/hosts へ bind mount して c2 の netns から解決する。
        let hosts = base.join("hosts");
        fs::write(&hosts, INITIAL_HOSTS).map_err(|e| fail(format!("write hosts: {e}")))?;
        let (n1, n2) = ("svc-a", "svc-b");
        let out = inject_service_hosts(net, base, Path::new("hosts"), [(n1, c1_ip), (n2, c2_ip)])?;
        expect_eq(
            "inject outcome",
            out,
            StaticHostsOutcome::Injected { entries: 2 },
        )?;
        let expected = format!("{INITIAL_HOSTS}{c1_ip}\t{n1}\n{c2_ip}\t{n2}\n");
        let hosts_str = hosts
            .to_str()
            .ok_or_else(|| fail("hosts path is not UTF-8"))?;
        run_cmd("mount", &["--bind", hosts_str, "/etc/hosts"])?;
        *mounted = true;
        let pin_arg = format!("--net={pin2}");
        let c1_ip_s = c1_ip.to_string();
        let out = run_cmd(
            "nsenter",
            &[&pin_arg, exe_str, "--probe", n1, &c1_ip_s, &expected],
        )?;
        if out.trim() != "probe: ok" {
            return Err(fail(format!("unexpected probe output: {out}")));
        }
        Ok(())
    }
}
