//! none モード（`lo` のみの netns 作成・解放）の実機結合試験（NET-6・TASK-143.2・#327・MS-8）。
//!
//! root と util-linux の `unshare` / `nsenter` / `mount` が必要な実機前提テストのため `harness = false` の
//! 独自 `main` で動かし、`-- --ignored` を付けたときだけ実行する（未指定時は「ignored」を出力して成功終了
//! する分離であり、CI 通過のための弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では
//! 対象外（skip ではなく OS 非該当）。
//!
//! # 流れ
//! - ランチャ（host netns・root）: 0700 の一時ディレクトリを作り、`unshare --net --mount -- <exe> --inner` で
//!   新しい netns・mount namespace の子を起動して終了コードを引き継ぐ
//! - 子（新 netns・新 mount namespace）: `/` を rprivate にして tmpfs を載せ（pin を host へ漏らさない）、
//!   比較対象として bridge に別コンテナ相当を 1 つ接続した後、`create_none_netns` を実行して次を照合する
//!   - (a) pin の inode が保持 fd の netns と一致し、子の netns とは別
//!   - (b) `nsenter --net=<pin>` 越しの `/proc/net/dev` に veth が現れない（lo とフォールバックトンネルのみ）
//!   - (c) `nsenter --net=<pin> <exe> --probe <addr>...`: loopback の TCP 疎通が成立し、TEST-NET-1・他コンテナ・
//!     bridge gateway への connect が `ENETUNREACH` で失敗し、`/proc/net/route` に loopback の 127.0.0.0/8 以外の経路が無いこと
//!   - (d) `release_none_netns` 後に pin ファイルが消え、`unpin_path` の再実行が `Ok` になること（冪等）
//!
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。前提（root・
//! 外部コマンド）を満たさない場合は skip せず失敗する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("none_mode_privileged: Linux only, not applicable on this OS");
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
            "none_mode_privileged: ignored (requires root, `unshare`, `nsenter`; run the built executable with `--ignored` under `sudo`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::Read as _;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use fandhe_container_net::error::{NetError, NetErrorCode};
    use fandhe_container_net::instrument::{NetOpRecorder, NoopNetOpRecorder};
    use fandhe_container_net::netlink_route::{IpPrefix, NetlinkRouteSocket};
    use fandhe_container_net::netns;
    use fandhe_container_net::network::{
        ContainerAttachSpec, EndpointId, NetworkCreateSpec, NetworkName, PortRegistry, StaticIpam,
        attach_container, create_network, delete_network,
    };
    use fandhe_container_net::network_mode::none::{
        NoneModeSpec, create_none_netns, release_none_netns,
    };
    use fandhe_container_net::nftables_batch::NetlinkNetfilterSocket;

    const LAUNCHER_PID_ENV: &str = "FANDHE_NONE_TEST_LAUNCHER_PID";
    const DIR_ENV: &str = "FANDHE_NONE_TEST_DIR";
    const OK_LINE: &str = "none_mode_privileged: ok pin=bound veth=none loopback=ok external=unreachable release=clean";
    const ENETUNREACH: i32 = 101;
    /// 新規 netns にカーネルが自動生成するフォールバックトンネルデバイス（有無は環境で変わる）。
    /// down かつアドレスなしで通信経路にならない。
    const FALLBACK_TUNNEL_DEVICES: [&str; 10] = [
        "tunl0",
        "gre0",
        "gretap0",
        "erspan0",
        "ip_vti0",
        "ip6_vti0",
        "sit0",
        "ip6tnl0",
        "ip6gre0",
        "ip6erspan0",
    ];

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
        let dir = std::env::temp_dir().join(format!("fandhe-none-test-{}", std::process::id()));
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
                    println!("none_mode_privileged: inner did not finish before deadline");
                    break 1;
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        // mount namespace は子の終了で消えるので、host 側には空のディレクトリだけが残る。
        let _ = fs::remove_dir(&dir);
        std::process::exit(code);
    }

    /// 自プロセスが「作成直後の新規 network namespace」にいることを検証する（fail-closed）。
    fn ensure_isolated_netns() -> Result<(), NetError> {
        let own = fs::read_link("/proc/self/ns/net").map_err(|e| fail(format!("readlink: {e}")))?;
        let parent_path = format!("/proc/{}/ns/net", std::os::unix::process::parent_id());
        let parent = fs::read_link(&parent_path)
            .map_err(|e| fail(format!("cannot read parent netns ({e}); refusing to run")))?;
        if own == parent {
            return Err(fail(
                "same network namespace as the parent process; refusing to run (see AGENTS.md)",
            ));
        }
        let extra = non_loopback_devices(
            &fs::read_to_string("/proc/net/dev").map_err(|e| fail(format!("read dev: {e}")))?,
        );
        if !extra.is_empty() {
            return Err(fail(format!(
                "network namespace is not freshly created (found interfaces: {}); refusing to run",
                extra.join(",")
            )));
        }
        Ok(())
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

    /// `/proc/net/dev` から lo とフォールバックトンネル以外のインターフェース名を返す。
    fn non_loopback_devices(dev: &str) -> Vec<String> {
        dev.lines()
            .skip(2)
            .filter_map(|l| l.split(':').next().map(str::trim))
            .filter(|n| !n.is_empty() && *n != "lo" && !FALLBACK_TUNNEL_DEVICES.contains(n))
            .map(str::to_owned)
            .collect()
    }

    /// 外部コマンドを期限つきで実行する（REPAIR-5）。期限切れなら子を kill して回収する。
    fn run_cmd(program: &str, args: &[&str]) -> Result<String, NetError> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| fail(format!("spawn {program}: {e}")))?;
        // パイプが詰まって子が止まらないよう、別スレッドで読み切る。
        let mut out_pipe = child.stdout.take();
        let mut err_pipe = child.stderr.take();
        let out_t = std::thread::spawn(move || {
            let mut b = Vec::new();
            if let Some(p) = out_pipe.as_mut() {
                let _ = p.read_to_end(&mut b);
            }
            b
        });
        let err_t = std::thread::spawn(move || {
            let mut b = Vec::new();
            if let Some(p) = err_pipe.as_mut() {
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
        let stdout = out_t.join().unwrap_or_default();
        let stderr = err_t.join().unwrap_or_default();
        if !status.success() {
            return Err(fail(format!(
                "{program} failed: {}{}",
                String::from_utf8_lossy(&stderr),
                String::from_utf8_lossy(&stdout)
            )));
        }
        Ok(String::from_utf8_lossy(&stdout).into_owned())
    }

    /// `nsenter --net=<pin>` で入り直した自身の再入モード。none モードの netns の中で実行される。
    /// `args` は到達不能であるべきアドレス（`ip:port`）。失敗は標準出力へ理由を出して非ゼロ終了する。
    pub fn probe(args: &[String]) {
        match probe_checked(args) {
            Ok(()) => println!("probe: ok"),
            Err(m) => {
                println!("probe: failed: {m}");
                std::process::exit(1);
            }
        }
    }

    fn probe_checked(unreachable: &[String]) -> Result<(), String> {
        // 1. loopback の疎通。
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind lo: {e}"))?;
        let addr = listener.local_addr().map_err(|e| format!("addr: {e}"))?;
        TcpStream::connect_timeout(&addr, Duration::from_secs(3))
            .map_err(|e| format!("loopback connect: {e}"))?;
        // 2. 外部・他コンテナ・gateway は経路が無く ENETUNREACH になる。
        for a in unreachable {
            let sa: SocketAddr = a.parse().map_err(|e| format!("parse {a}: {e}"))?;
            match TcpStream::connect_timeout(&sa, Duration::from_secs(3)) {
                Err(e) if e.raw_os_error() == Some(ENETUNREACH) => {}
                other => return Err(format!("connect {a} expected ENETUNREACH, got {other:?}")),
            }
        }
        // 3. ルートテーブルにはヘッダ行以外に loopback の 127.0.0.0/8 だけが許される。
        //    lo を up にするとカーネルが設置し得るため許容し、それ以外（default route 等）は拒否する。
        //    /proc/net/route は Destination・Mask を little-endian の 16 進で出す
        //    （127.0.0.0 = 0000007F、255.0.0.0 = 000000FF）。
        let route = fs::read_to_string("/proc/net/route").map_err(|e| format!("route: {e}"))?;
        let unexpected: Vec<&str> = route
            .lines()
            .skip(1)
            .filter(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                !(f.get(1) == Some(&"0000007F") && f.get(7) == Some(&"000000FF"))
            })
            .collect();
        if !unexpected.is_empty() {
            return Err(format!("unexpected routes: {unexpected:?}"));
        }
        Ok(())
    }

    pub fn inner() {
        match inner_checked() {
            Ok(()) => println!("{OK_LINE}"),
            Err(e) => {
                println!("none_mode_privileged: failed: {e}");
                std::process::exit(1);
            }
        }
    }

    fn inner_checked() -> Result<(), NetError> {
        ensure_launched_by_launcher()?;
        ensure_isolated_netns()?;
        let base =
            PathBuf::from(std::env::var(DIR_ENV).map_err(|_| fail("missing test directory env"))?);
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

        let route = NetlinkRouteSocket::open()?;
        let nft = NetlinkNetfilterSocket::open()?;
        let t = timeout();

        // --- 比較対象: bridge に別コンテナ相当を 1 つ接続し、そのアドレスへ到達できないことを後で確かめる ---
        let net = create_network(
            &route,
            &nft,
            &NetworkCreateSpec::new(
                NetworkName::new("nonecmp")?,
                IpPrefix::new("10.215.0.1".parse().map_err(|_| fail("addr"))?, 24)?,
            )?,
            t,
        )
        .map_err(|e| fail(format!("create_network failed at {:?}: {e}", e.step)))?;
        let other_spec = ContainerAttachSpec::new(EndpointId::new("other")?, &net, base.clone())?;
        let mut ipam = StaticIpam::for_network(&net)?;
        let mut ports = PortRegistry::new();
        let other = attach_container(&route, &nft, &other_spec, &mut ipam, &mut ports, t)
            .map_err(|e| fail(format!("attach_container failed at {:?}: {e}", e.step)))?;
        let other_ip = other.address.addr();

        // --- none モード ---
        let recorder: Arc<dyn NetOpRecorder> = Arc::new(NoopNetOpRecorder);
        let spec = NoneModeSpec::new(EndpointId::new("nonectr")?, base.clone())?;
        let none = create_none_netns(&spec, t, &recorder)
            .map_err(|e| fail(format!("create_none_netns failed at {:?}: {e}", e.step)))?;
        if none.netns_path != base.join("nonectr") {
            return Err(fail("unexpected pin path"));
        }

        // (a) pin と保持 fd が同じ netns で、自分の netns とは別。
        let pin_ino = fs::metadata(&none.netns_path)
            .map_err(|e| fail(format!("stat pin: {e}")))?
            .ino();
        let fd_path = format!("/proc/self/fd/{}", none.netns.fd().as_raw_fd());
        let fd_ino = fs::metadata(&fd_path)
            .map_err(|e| fail(format!("stat netns fd: {e}")))?
            .ino();
        if pin_ino != fd_ino {
            return Err(fail("pin path and netns fd refer to different namespaces"));
        }
        let own_ino = fs::metadata("/proc/self/ns/net")
            .map_err(|e| fail(format!("stat own netns: {e}")))?
            .ino();
        if own_ino == pin_ino {
            return Err(fail("none-mode netns is the same as the current netns"));
        }

        // (b) veth が無い（lo とフォールバックトンネルのみ）。
        let pin_arg = format!(
            "--net={}",
            none.netns_path
                .to_str()
                .ok_or_else(|| fail("pin path is not UTF-8"))?
        );
        let dev = run_cmd("nsenter", &[&pin_arg, "cat", "/proc/net/dev"])?;
        let extra = non_loopback_devices(&dev);
        if !extra.is_empty() || !dev.contains("lo:") {
            return Err(fail(format!(
                "unexpected interfaces in none-mode netns: {extra:?}"
            )));
        }

        // (c) loopback だけが通り、外部・他コンテナ・gateway へは経路が無い。
        let other_target = format!("{other_ip}:9");
        let out = run_cmd(
            "nsenter",
            &[
                &pin_arg,
                exe_str,
                "--probe",
                "192.0.2.1:9",
                &other_target,
                "10.215.0.1:9",
            ],
        )?;
        if out.trim() != "probe: ok" {
            return Err(fail(format!("unexpected probe output: {out}")));
        }

        // (d) 解放: pin が消え、unpin_path の再実行は冪等に Ok。
        let pin = none.netns_path.clone();
        release_none_netns(none).map_err(|e| fail(format!("release_none_netns failed: {e}")))?;
        if pin.exists() {
            return Err(fail("pin file still exists after release"));
        }
        netns::unpin_path(&pin)?;

        delete_network(&route, &nft, &net, vec![other], &mut ipam, &mut ports, t)
            .map_err(|e| fail(format!("delete_network failed at {:?}: {e}", e.step)))?;
        Ok(())
    }
}
