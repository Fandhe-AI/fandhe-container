//! DNS ヘルパーのオンデマンド起動・終了を実ネットワーク（bridge・gateway:53）上で確かめる実機結合試験
//! （NET-7・TASK-144.2・#330・MS-8）。
//!
//! 参照カウント本体（`dns_helper::refcount::DnsHelperRefCounts`。TASK-144.1・#329）はユニットテスト（偽ランチャ）と
//! ループバックの `dns_helper_process` で検証済みで、本テストは「コンテナ参加で実プロセスが起動し、最後の
//! コンテナ停止で終了して痕跡（子プロセス・待受ソケット・応答）が残らない」ことを 1 回の実行で通して確かめる。
//! 実機での 5 回実証とレポートは TASK-145（人間担当）が本テストで行う。
//!
//! root と util-linux の `unshare` / `nsenter` / `mount` が必要な実機前提テストのため `harness = false` の
//! 独自 `main` で動かし、`-- --ignored` を付けたときだけ実行する（未指定時は「ignored」を出力して成功終了
//! する分離であり、CI 通過のための弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では対象外。
//!
//! # ライフサイクルの対応づけ
//! net crate にコンテナのライフサイクルは無いため、次のように対応づける。
//! - 「コンテナ参加」= `attach_container` に続けて `DnsHelperRefCounts::join`
//! - 「コンテナ停止」= `DnsHelperRefCounts::leave`
//! - ネットワークの片付け = 全 leave の後に `delete_network`
//!
//! ヘルパーは `spawn_dns_helper` を直接呼ばず、必ず `DnsHelperRefCounts<ProcessLauncher>` 経由で起動・停止する。
//!
//! # 流れ
//! - ランチャ（host netns・root）: 0700 の一時ディレクトリを作り、`unshare --net --mount -- <exe> --inner` で
//!   子を起動して終了コードを引き継ぐ
//! - 子（新 netns・新 mount namespace。ネットワーク用 netns にあたる）: `create_network` の後、c1 参加で
//!   `Started`、c2 参加で `Joined`（pid 不変）、c1 離脱で `Remaining`、c2 離脱で `Stopped` を確かめる。
//!   終了後は (1) `is_running` / `members` / `bound_addr` の状態、(2) 自分の子で `--listen` を持つプロセスが 0 件、
//!   (3) `/proc/self/net/udp` に gateway:53 の待受が 0 件、(4) コンテナ netns からの正常クエリに応答が無いこと、を
//!   具体値で確認する
//!
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。前提を満たさない
//! 場合は skip せず失敗する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("dns_helper_ondemand_privileged: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.get(1).is_some_and(|a| a == "--listen") {
        // ヘルパー本体（ProcessLauncher が自身を再実行したとき）。
        return fandhe_container_net::dns_helper::run_dns_helper_main(args.into_iter().skip(1));
    }
    let has = |f: &str| args.iter().any(|a| a == f);
    if has("--dns-client") {
        return linux::client(&args);
    }
    if has("--dns-expect-silent") {
        return linux::expect_silent(&args);
    }
    if has("--inner") {
        linux::inner();
    } else if has("--ignored") {
        linux::launcher();
    } else {
        println!(
            "dns_helper_ondemand_privileged: ignored (requires root, `unshare`, `nsenter`; run the built executable with `--ignored` under `sudo`, see AGENTS.md)"
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
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use fandhe_container_net::dns_helper::refcount::{
        DnsHelperRefCounts, JoinOutcome, LeaveOutcome, ProcessLauncher,
    };
    use fandhe_container_net::dns_helper::{
        DnsListenAddr, READY_TIMEOUT_DEFAULT, REAP_TIMEOUT_DEFAULT,
    };
    use fandhe_container_net::error::{NetError, NetErrorCode};
    use fandhe_container_net::instrument::{NetOpKind, NetOpOutcome, NetOpRecorder, NetOpSample};
    use fandhe_container_net::netlink_route::{IpPrefix, NetlinkRouteSocket};
    use fandhe_container_net::network::{
        ContainerAttachSpec, EndpointId, NetworkCreateSpec, NetworkName, PortRegistry, StaticIpam,
        attach_container, create_network, delete_network,
    };
    use fandhe_container_net::nftables_batch::NetlinkNetfilterSocket;

    const LAUNCHER_PID_ENV: &str = "FANDHE_DNS_ONDEMAND_TEST_LAUNCHER_PID";
    const DIR_ENV: &str = "FANDHE_DNS_ONDEMAND_TEST_DIR";
    const NETWORK: &str = "dnsod";

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

    /// ヘッダー + 質問 1 件（`example.com` A IN）の正常クエリ。
    fn full_query(id: u16) -> Vec<u8> {
        let mut v = query(id, 0x0100, 1);
        v.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        v
    }

    /// 外部コマンドを実行し、非ゼロ終了・失敗をエラーにする（後続の特権操作を中止するため）。
    fn run_checked(program: &str, args: &[&str]) -> Result<(), NetError> {
        let (ok, _) = run_cmd(program, args)?;
        if ok {
            Ok(())
        } else {
            Err(fail(format!("{program} {args:?} exited non-zero")))
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
        let dir =
            std::env::temp_dir().join(format!("fandhe-dns-ondemand-test-{}", std::process::id()));
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
                    println!(
                        "dns_helper_ondemand_privileged: inner did not finish before deadline"
                    );
                    break 1;
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        let _ = fs::remove_dir(&dir);
        std::process::exit(code);
    }

    fn parse_target(args: &[OsString], flag: &str) -> Option<SocketAddrV4> {
        args.iter()
            .skip_while(|a| *a != flag)
            .nth(1)
            .and_then(|a| a.to_str())
            .and_then(|s| s.parse().ok())
    }

    /// 生存確認用クライアント（`nsenter --net=<pin> <exe> --dns-client <addr>`）。正常クエリに ID 一致・QR=1・
    /// RCODE=4（NOTIMP。プロセス外からの登録経路が無い間）の 12 バイトが期限内に返れば成功。
    pub fn client(args: &[OsString]) -> ExitCode {
        let Some(target) = parse_target(args, "--dns-client") else {
            println!("dns client: invalid target");
            return ExitCode::from(2);
        };
        let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            println!("dns client: bind failed");
            return ExitCode::from(1);
        };
        let _ = sock.set_read_timeout(Some(Duration::from_millis(300)));
        let mut buf = [0u8; 600];
        // 起動直後の取りこぼしに備え、期限内で再送する。
        let deadline = Instant::now() + timeout();
        while Instant::now() < deadline {
            if sock.send_to(&full_query(0x4242), target).is_err() {
                return ExitCode::from(1);
            }
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                let want = [0x42, 0x42, 0x81, 0x04, 0, 0, 0, 0, 0, 0, 0, 0];
                let ok = buf.get(..n) == Some(&want[..]);
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

    /// 終了確認用クライアント（`--dns-expect-silent <addr>`）。正常クエリを数回送り、応答が 1 件も無ければ成功
    /// （受信タイムアウトも ECONNREFUSED も「応答なし」）。応答があれば失敗、送信自体の失敗は判定不能として失敗。
    pub fn expect_silent(args: &[OsString]) -> ExitCode {
        let Some(target) = parse_target(args, "--dns-expect-silent") else {
            println!("dns silent client: invalid target");
            return ExitCode::from(2);
        };
        let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            println!("dns silent client: bind failed");
            return ExitCode::from(1);
        };
        let _ = sock.set_read_timeout(Some(Duration::from_millis(300)));
        let mut buf = [0u8; 600];
        for id in 0..3u16 {
            if sock.send_to(&full_query(0x5000 + id), target).is_err() {
                println!("dns silent client: send failed");
                return ExitCode::from(1);
            }
            if sock.recv_from(&mut buf).is_ok() {
                println!("dns silent client: unexpected reply");
                return ExitCode::from(1);
            }
        }
        println!("dns silent client: no reply");
        ExitCode::SUCCESS
    }

    /// 起動・停止の計測サンプルを集める記録先（REPAIR-4）。
    #[derive(Default)]
    struct Collector(Mutex<Vec<NetOpSample>>);

    impl NetOpRecorder for Collector {
        fn record_net_op(&self, sample: &NetOpSample) {
            if let Ok(mut v) = self.0.lock() {
                v.push(*sample);
            }
        }
    }

    impl Collector {
        fn samples(&self, kind: NetOpKind) -> Vec<NetOpSample> {
            self.0
                .lock()
                .map(|v| v.iter().filter(|s| s.kind() == kind).copied().collect())
                .unwrap_or_default()
        }
    }

    /// `/proc/<pid>/stat` から ppid を得る（comm に空白・括弧を含みうるため最後の `)` 以降を読む）。
    fn ppid_of(pid: u32) -> Option<u32> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let (_, rest) = stat.rsplit_once(')')?;
        rest.split_whitespace().nth(1)?.parse().ok()
    }

    /// 自分の子で `--listen <addr>` を引数に持つプロセスの pid 一覧。`/proc/<pid>` の有無ではなく ppid と
    /// cmdline で照合し、pid の再利用による誤判定を避ける。
    fn helper_children(listen: &str) -> Result<Vec<u32>, NetError> {
        let me = std::process::id();
        let mut out = Vec::new();
        let dir = fs::read_dir("/proc").map_err(|e| fail(format!("read /proc: {e}")))?;
        for entry in dir.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            if ppid_of(pid) != Some(me) {
                continue;
            }
            let Ok(raw) = fs::read(format!("/proc/{pid}/cmdline")) else {
                continue;
            };
            let mut argv = raw.split(|b| *b == 0);
            let _program = argv.next();
            if argv.next() == Some(b"--listen".as_slice()) && argv.next() == Some(listen.as_bytes())
            {
                out.push(pid);
            }
        }
        Ok(out)
    }

    /// `/proc/self/net/udp` の local address を `SocketAddrV4` に直す。IPv4 は 16 進のネイティブエンディアン、
    /// port は 16 進で出力される。
    fn udp_local_addrs() -> Result<Vec<SocketAddrV4>, NetError> {
        let text = fs::read_to_string("/proc/self/net/udp")
            .map_err(|e| fail(format!("read /proc/self/net/udp: {e}")))?;
        let mut out = Vec::new();
        for line in text.lines().skip(1) {
            let Some(local) = line.split_whitespace().nth(1) else {
                continue;
            };
            let Some((ip_hex, port_hex)) = local.split_once(':') else {
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

    fn count_udp(addr: SocketAddrV4) -> Result<usize, NetError> {
        Ok(udp_local_addrs()?.iter().filter(|a| **a == addr).count())
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

    pub fn inner() {
        match inner_checked() {
            Ok(line) => println!("{line}"),
            Err(e) => {
                println!("dns_helper_ondemand_privileged: failed: {e}");
                std::process::exit(1);
            }
        }
    }

    /// 成功時に計測つきの 1 行（TASK-145 が機械で読む）を返す。
    fn inner_checked() -> Result<String, NetError> {
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
        run_checked("mount", &["--make-rprivate", "/"])?;
        run_checked(
            "mount",
            &["-t", "tmpfs", "-o", "mode=0700", "tmpfs", base_str],
        )?;

        let route = NetlinkRouteSocket::open()?;
        let nft = NetlinkNetfilterSocket::open()?;
        let t = timeout();
        // IPAM は特権資源（network）を作る前に構築する。構築失敗で `delete_network` に到達できず
        // root で作った資源が残る経路を作らない（AGENTS.md「特権操作の後始末」）。
        let gateway = IpPrefix::new("10.216.0.1".parse().map_err(|_| fail("addr"))?, 24)?;
        let name = NetworkName::new(NETWORK)?;
        let mut ipam = StaticIpam::new(&name, gateway)?;
        let spec = NetworkCreateSpec::new(NetworkName::new(NETWORK)?, gateway)?;
        let net = create_network(&route, &nft, &spec, t)
            .map_err(|e| fail(format!("create_network failed at {:?}: {e}", e.step)))?;

        // 参照カウント（本番ランチャ）。構築失敗も create_network 後の後始末に乗せるため Result のまま持つ。
        let collector = Arc::new(Collector::default());
        let rc = std::env::current_exe()
            .map_err(|e| fail(format!("current_exe: {e}")))
            .and_then(|exe| ProcessLauncher::new(exe, READY_TIMEOUT_DEFAULT, REAP_TIMEOUT_DEFAULT))
            .map(|l| DnsHelperRefCounts::with_recorder(l, collector.clone()));

        // create_network 成功後は、どの失敗経路でも逆順（leave でヘルパー停止 → delete_network）で回収する。
        let mut ports = PortRegistry::new();
        let mut attached = Vec::new();
        let result = (|| -> Result<String, NetError> {
            let rc = rc
                .as_ref()
                .map_err(|e| fail(format!("setup failed: {e}")))?;
            let exe = std::env::current_exe().map_err(|e| fail(format!("current_exe: {e}")))?;
            let exe_str = exe.to_str().ok_or_else(|| fail("exe path is not UTF-8"))?;
            let listen = DnsListenAddr::for_network(&net)?;
            let addr = listen.socket_addr();
            let listen_str = listen.to_string();
            let c1 = EndpointId::new("c1")?;
            let c2 = EndpointId::new("c2")?;

            // 事前状態: ヘルパーは存在しない。
            expect_eq("running before join", rc.is_running(&name), false)?;
            expect_eq(
                "helper processes before join",
                helper_children(&listen_str)?.len(),
                0,
            )?;
            expect_eq("udp sockets before join", count_udp(addr)?, 0)?;

            // c1 参加 -> 起動。
            let spec1 = ContainerAttachSpec::new(c1.clone(), &net, base.clone())?;
            let a1 = attach_container(&route, &nft, &spec1, &mut ipam, &mut ports, t)
                .map_err(|e| fail(format!("attach_container failed at {:?}: {e}", e.step)))?;
            let pin1 = a1
                .netns_path
                .to_str()
                .ok_or_else(|| fail("pin path is not UTF-8"))
                .map(str::to_owned);
            attached.push(a1);
            let pin1 = pin1?;
            expect_eq(
                "first join",
                rc.join(&name, listen, &c1)?,
                JoinOutcome::Started,
            )?;

            // 起動確認。
            expect_eq("running after first join", rc.is_running(&name), true)?;
            expect_eq("bound address", rc.bound_addr(&name), Some(addr))?;
            let pids = helper_children(&listen_str)?;
            expect_eq("helper processes after first join", pids.len(), 1)?;
            let helper_pid = *pids.first().ok_or_else(|| fail("helper pid missing"))?;
            let helper_ns = fs::read_link(format!("/proc/{helper_pid}/ns/net"))
                .map_err(|e| fail(format!("readlink helper netns: {e}")))?;
            if helper_ns != own || helper_ns == parent {
                return Err(fail(
                    "helper is not in the network's own netns (or shares the launcher's)",
                ));
            }
            expect_eq("udp sockets after first join", count_udp(addr)?, 1)?;
            let (ok, out) = run_cmd(
                "nsenter",
                &[
                    &format!("--net={pin1}"),
                    exe_str,
                    "--dns-client",
                    &listen_str,
                ],
            )?;
            if !ok {
                return Err(fail(format!("container-side dns client failed: {out}")));
            }

            // c2 参加 -> 参照カウントのみ増える（再起動しない）。
            let spec2 = ContainerAttachSpec::new(c2.clone(), &net, base.clone())?;
            let a2 = attach_container(&route, &nft, &spec2, &mut ipam, &mut ports, t)
                .map_err(|e| fail(format!("attach_container failed at {:?}: {e}", e.step)))?;
            let pin2 = a2
                .netns_path
                .to_str()
                .ok_or_else(|| fail("pin path is not UTF-8"))
                .map(str::to_owned);
            attached.push(a2);
            let pin2 = pin2?;
            expect_eq(
                "second join",
                rc.join(&name, listen, &c2)?,
                JoinOutcome::Joined { members: 2 },
            )?;
            expect_eq(
                "helper pids after second join",
                helper_children(&listen_str)?,
                vec![helper_pid],
            )?;

            // c1 離脱 -> c2 が残るので停止しない。
            expect_eq(
                "first leave",
                rc.leave(&name, &c1)?,
                LeaveOutcome::Remaining { members: 1 },
            )?;
            expect_eq(
                "helper pids after first leave",
                helper_children(&listen_str)?,
                vec![helper_pid],
            )?;
            let (ok, out) = run_cmd(
                "nsenter",
                &[
                    &format!("--net={pin2}"),
                    exe_str,
                    "--dns-client",
                    &listen_str,
                ],
            )?;
            if !ok {
                return Err(fail(format!("dns client after first leave failed: {out}")));
            }

            // c2 離脱 -> 停止。
            expect_eq("last leave", rc.leave(&name, &c2)?, LeaveOutcome::Stopped)?;

            // 終了確認: 常駐コスト 0。
            expect_eq("running after stop", rc.is_running(&name), false)?;
            expect_eq("members after stop", rc.members(&name), 0)?;
            expect_eq("bound address after stop", rc.bound_addr(&name), None)?;
            let procs_after = helper_children(&listen_str)?.len();
            expect_eq("helper processes after stop", procs_after, 0)?;
            let udp_after = count_udp(addr)?;
            expect_eq("udp sockets after stop", udp_after, 0)?;
            let (ok, out) = run_cmd(
                "nsenter",
                &[
                    &format!("--net={pin2}"),
                    exe_str,
                    "--dns-expect-silent",
                    &listen_str,
                ],
            )?;
            if !ok {
                return Err(fail(format!("helper still answers after stop: {out}")));
            }

            // 起動・停止の計測は各ちょうど 1 回の成功。
            let starts = collector.samples(NetOpKind::DnsHelperStart);
            let stops = collector.samples(NetOpKind::DnsHelperStop);
            expect_eq("start sample count", starts.len(), 1)?;
            expect_eq("stop sample count", stops.len(), 1)?;
            expect_eq(
                "start outcome",
                starts.first().map(NetOpSample::outcome),
                Some(NetOpOutcome::Success),
            )?;
            expect_eq(
                "stop outcome",
                stops.first().map(NetOpSample::outcome),
                Some(NetOpOutcome::Success),
            )?;
            let stop_ms = stops.first().map_or(0, |s| s.latency().as_millis());
            Ok(format!(
                "dns_helper_ondemand_privileged: ok start=1 stop=1 helper_pid={helper_pid} stop_ms={stop_ms} procs_after={procs_after} udp53_after={udp_after} reply_after=none (NET-7)"
            ))
        })();

        // 後始末（必ず実行）: 残っている参加者を離脱させてヘルパーを止めてから、ネットワークを削除する。
        let left = match rc.as_ref() {
            Ok(rc) => ["c1", "c2"]
                .into_iter()
                .try_for_each(|id| rc.leave(&name, &EndpointId::new(id)?).map(|_| ())),
            Err(_) => Ok(()),
        };
        drop(rc);
        let deleted = delete_network(&route, &nft, &net, attached, &mut ipam, &mut ports, t)
            .map(|_| ())
            .map_err(|e| fail(format!("delete_network failed: {e}")));
        // 後始末の失敗も必ず報告する（先に `?` で返さず、全結果を評価してから最初の失敗を返す）。
        let cleanup = match (left, deleted) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
            (Err(e), Err(d)) => Err(fail(format!("{e}; additionally: {d}"))),
        };
        match (result, cleanup) {
            (Ok(line), Ok(())) => Ok(line),
            (Err(e), Ok(())) | (Ok(_), Err(e)) => Err(e),
            (Err(e), Err(d)) => Err(fail(format!("{e}; additionally: {d}"))),
        }
    }
}
