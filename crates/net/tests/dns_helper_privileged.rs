//! DNS ヘルパーを bridge 上のネットワーク用 netns で起動し、コンテナ netns から UDP で疎通する実機結合試験
//! （NET-5・TASK-141.1・#321・MS-8）。
//!
//! root と util-linux の `unshare` / `nsenter` / `mount` が必要な実機前提テストのため `harness = false` の
//! 独自 `main` で動かし、`-- --ignored` を付けたときだけ実行する（未指定時は「ignored」を出力して成功終了
//! する分離であり、CI 通過のための弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では対象外。
//!
//! # 流れ
//! - ランチャ（host netns・root）: 0700 の一時ディレクトリを作り、`unshare --net --mount -- <exe> --inner` で
//!   子を起動して終了コードを引き継ぐ
//! - 子（新 netns・新 mount namespace。ネットワーク用 netns にあたる）: tmpfs を載せ、`create_network` と
//!   `attach_container`（c1）を実行し、`spawn_dns_helper` で自身（`--listen` モード）を gateway:53 で起動する。
//!   ヘルパーの netns が子と同一でランチャとは別であることを `/proc/<pid>/ns/net` の inode で照合し、
//!   `nsenter --net=<pin> <exe> --dns-client <gateway:53>` でコンテナ netns からクエリを送る
//!   （不正パケットは無応答・続く正常クエリには応答 = ヘルパー生存の証明）。最後に回収と `delete_network`
//!
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。前提を満たさない
//! 場合は skip せず失敗する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("dns_helper_privileged: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.get(1).is_some_and(|a| a == "--listen") {
        // ヘルパー本体（spawn_dns_helper が自身を再実行したとき）。
        return fandhe_container_net::dns_helper::run_dns_helper_main(args.into_iter().skip(1));
    }
    let has = |f: &str| args.iter().any(|a| a == f);
    if has("--dns-client") {
        return linux::client(&args);
    }
    if has("--inner") {
        linux::inner();
    } else if has("--ignored") {
        linux::launcher();
    } else {
        println!(
            "dns_helper_privileged: ignored (requires root, `unshare`, `nsenter`; run the built executable with `--ignored` under `sudo`, see AGENTS.md)"
        );
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::process::{Command, ExitCode, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_net::dns_helper::{
        DnsListenAddr, READY_TIMEOUT_DEFAULT, REAP_TIMEOUT_DEFAULT, spawn_dns_helper,
    };
    use fandhe_container_net::error::{NetError, NetErrorCode};
    use fandhe_container_net::netlink_route::{IpPrefix, NetlinkRouteSocket};
    use fandhe_container_net::network::{
        ContainerAttachSpec, EndpointId, NetworkCreateSpec, NetworkName, PortRegistry, StaticIpam,
        attach_container, create_network, delete_network,
    };
    use fandhe_container_net::nftables_batch::NetlinkNetfilterSocket;

    const LAUNCHER_PID_ENV: &str = "FANDHE_DNS_TEST_LAUNCHER_PID";
    const DIR_ENV: &str = "FANDHE_DNS_TEST_DIR";
    const OK_LINE: &str =
        "dns_helper_privileged: ok netns=dedicated reachable=yes malformed=dropped (NET-5)";

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

    fn query(id: u16, flags: u16, qd: u16) -> Vec<u8> {
        let mut v = id.to_be_bytes().to_vec();
        v.extend_from_slice(&flags.to_be_bytes());
        v.extend_from_slice(&qd.to_be_bytes());
        v.extend_from_slice(&[0; 6]);
        v
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

    /// 期限つきで外部コマンドを実行し、終了コードと標準出力を返す（REPAIR-5）。
    fn run_cmd(program: &str, args: &[&str]) -> Result<(bool, String), NetError> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| fail(format!("spawn {program}: {e}")))?;
        let mut pipe = child.stdout.take();
        let reader = std::thread::spawn(move || {
            use std::io::Read as _;
            let mut b = Vec::new();
            if let Some(p) = pipe.as_mut() {
                let _ = p.read_to_end(&mut b);
            }
            b
        });
        let deadline = Instant::now() + timeout();
        let status = loop {
            match child
                .try_wait()
                .map_err(|e| fail(format!("wait {program}: {e}")))?
            {
                Some(st) => break st,
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(NetError::new(
                        NetErrorCode::Timeout,
                        format!("{program} did not finish before the deadline"),
                    ));
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        let out = reader.join().unwrap_or_default();
        Ok((status.success(), String::from_utf8_lossy(&out).into_owned()))
    }

    /// ランチャ（host netns の root プロセス）。自身では何も変更せず、子を新しい netns・mount namespace で起動する。
    pub fn launcher() {
        require_root_and_tools();
        let dir = std::env::temp_dir().join(format!("fandhe-dns-test-{}", std::process::id()));
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
                    println!("dns_helper_privileged: inner did not finish before deadline");
                    break 1;
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        let _ = fs::remove_dir(&dir);
        std::process::exit(code);
    }

    /// コンテナ netns 側のクライアント（`nsenter --net=<pin> <exe> --dns-client <addr>`）。
    /// 不正パケットが無応答であることと、続く正常クエリへの応答（ID 一致・QR=1・RCODE=4）を確認する。
    pub fn client(args: &[OsString]) -> ExitCode {
        let target: Option<SocketAddrV4> = args
            .iter()
            .skip_while(|a| *a != "--dns-client")
            .nth(1)
            .and_then(|a| a.to_str())
            .and_then(|s| s.parse().ok());
        let Some(target) = target else {
            println!("dns client: invalid target");
            return ExitCode::from(2);
        };
        let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            println!("dns client: bind failed");
            return ExitCode::from(1);
        };
        let _ = sock.set_read_timeout(Some(Duration::from_millis(300)));
        let mut buf = [0u8; 600];
        for bad in [vec![0u8; 5], query(1, 0x8100, 1), query(1, 0x0100, 0)] {
            if sock.send_to(&bad, target).is_err() || sock.recv_from(&mut buf).is_ok() {
                println!("dns client: malformed packet was answered or send failed");
                return ExitCode::from(1);
            }
        }
        // 起動直後の取りこぼしに備え、期限内で再送する。
        let deadline = Instant::now() + timeout();
        while Instant::now() < deadline {
            if sock.send_to(&query(0x4242, 0x0100, 1), target).is_err() {
                return ExitCode::from(1);
            }
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                let ok =
                    buf.get(..n) == Some(&[0x42, 0x42, 0x81, 0x04, 0, 0, 0, 0, 0, 0, 0, 0][..]);
                println!("dns client: reply ok={ok}");
                return if ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                };
            }
        }
        println!("dns client: no reply before the deadline");
        ExitCode::from(1)
    }

    pub fn inner() {
        match inner_checked() {
            Ok(()) => println!("{OK_LINE}"),
            Err(e) => {
                println!("dns_helper_privileged: failed: {e}");
                std::process::exit(1);
            }
        }
    }

    fn inner_checked() -> Result<(), NetError> {
        let expected = std::env::var(LAUNCHER_PID_ENV)
            .ok()
            .and_then(|v| v.parse::<u32>().ok());
        if expected != Some(std::os::unix::process::parent_id()) {
            return Err(fail(
                "`--inner` must be started by the `--ignored` launcher; refusing to run",
            ));
        }
        let own = fs::read_link("/proc/self/ns/net").map_err(|e| fail(format!("readlink: {e}")))?;
        let parent = fs::read_link(format!(
            "/proc/{}/ns/net",
            std::os::unix::process::parent_id()
        ))
        .map_err(|e| fail(format!("cannot read parent netns ({e}); refusing to run")))?;
        if own == parent {
            return Err(fail(
                "same network namespace as the launcher; refusing to run (see AGENTS.md)",
            ));
        }
        let base =
            PathBuf::from(std::env::var(DIR_ENV).map_err(|_| fail("missing test directory env"))?);
        let base_str = base
            .to_str()
            .ok_or_else(|| fail("test directory is not UTF-8"))?;
        run_cmd("mount", &["--make-rprivate", "/"])?;
        run_cmd(
            "mount",
            &["-t", "tmpfs", "-o", "mode=0700", "tmpfs", base_str],
        )?;

        let route = NetlinkRouteSocket::open()?;
        let nft = NetlinkNetfilterSocket::open()?;
        let t = timeout();
        let net = create_network(
            &route,
            &nft,
            &NetworkCreateSpec::new(
                NetworkName::new("dns")?,
                IpPrefix::new("10.215.0.1".parse().map_err(|_| fail("addr"))?, 24)?,
            )?,
            t,
        )
        .map_err(|e| fail(format!("create_network failed at {:?}: {e}", e.step)))?;
        let spec = ContainerAttachSpec::new(EndpointId::new("c1")?, &net, base.clone())?;
        let mut ipam = StaticIpam::for_network(&net)?;
        let mut ports = PortRegistry::new();
        let attached = attach_container(&route, &nft, &spec, &mut ipam, &mut ports, t)
            .map_err(|e| fail(format!("attach_container failed at {:?}: {e}", e.step)))?;

        let exe = std::env::current_exe().map_err(|e| fail(format!("current_exe: {e}")))?;
        let listen = DnsListenAddr::for_network(&net)?;
        let helper = spawn_dns_helper(&exe, listen, READY_TIMEOUT_DEFAULT)?;
        let result = (|| -> Result<(), NetError> {
            let pid = helper.pid().ok_or_else(|| fail("helper has no pid"))?;
            let helper_ns = fs::read_link(format!("/proc/{pid}/ns/net"))
                .map_err(|e| fail(format!("readlink helper netns: {e}")))?;
            if helper_ns != own || helper_ns == parent {
                return Err(fail(
                    "helper is not in the network's own netns (or shares the launcher's)",
                ));
            }
            let pin = attached
                .netns_path
                .to_str()
                .ok_or_else(|| fail("pin path is not UTF-8"))?;
            let exe_str = exe.to_str().ok_or_else(|| fail("exe path is not UTF-8"))?;
            let target = listen.to_string();
            let (ok, out) = run_cmd(
                "nsenter",
                &[&format!("--net={pin}"), exe_str, "--dns-client", &target],
            )?;
            if !ok {
                return Err(fail(format!("container-side dns client failed: {out}")));
            }
            Ok(())
        })();
        let stop = helper.stop(REAP_TIMEOUT_DEFAULT);
        delete_network(&route, &nft, &net, vec![attached], &mut ipam, &mut ports, t)
            .map_err(|e| fail(format!("delete_network failed: {e}")))?;
        result?;
        stop
    }
}
