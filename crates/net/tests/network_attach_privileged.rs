//! コンテナ接続（netns 作成・pin、veth 作成、bridge 接続、peer の netns 移動）の実機結合試験
//! （NET-1・TASK-139.2.1・#847・MS-8）。
//!
//! root と util-linux の `unshare` / `nsenter` / `mount` が必要な実機前提テストのため `harness = false` の
//! 独自 `main` で動かし、`-- --ignored` を付けたときだけ実行する（未指定時は「ignored」を出力して成功終了
//! する分離であり、CI 通過のための弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では
//! 対象外（skip ではなく OS 非該当）。
//!
//! # 流れ
//! - ランチャ（host netns・root）: 0700 の一時ディレクトリを作り、`unshare --net --mount -- <exe> --inner` で
//!   新しい netns・mount namespace の子を起動して終了コードを引き継ぐ。終了後に一時ディレクトリを消す
//! - 子（新 netns・新 mount namespace の中）: `/` を rprivate にし、一時ディレクトリへ tmpfs を載せる
//!   （bind マウントと pin ファイルを host へ漏らさない）→ `create_network` で bridge を作る →
//!   `attach_container` を実行し、(1) host 側 veth の `IFLA_MASTER` が bridge の ifindex と一致し `IFF_UP`、
//!   (2) peer 側が子の netns から消えている、(3) pin パスの inode が保持 fd の netns と一致し子の netns と
//!   別、(4) `nsenter --net=<pin>` 越しの `/proc/net/dev` に peer 名が現れる、を具体値で照合する。
//!   続けて host 側 veth 名を事前に作っておき `AlreadyExists` で失敗させ、pin ファイルが消え、事前作成の
//!   veth が残ることでロールバック（他者のリソースを消さない）を確認する
//!
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。前提（root・
//! 外部コマンド）を満たさない場合は skip せず失敗する。
//!
//! `create_network` が `ResolveIndex` で失敗する場合は TASK-139.1 の所有トークン（作成時 `IFLA_IFALIAS`）が
//! 実カーネルで機能していない疑いであり、本タスクでは修正せず（スコープ外）その旨を出力して失敗する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("network_attach_privileged: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--inner") {
        linux::inner();
    } else if args.iter().any(|a| a == "--ignored") {
        linux::launcher();
    } else {
        println!(
            "network_attach_privileged: ignored (requires root, `unshare`, `nsenter`; run the built executable with `--ignored` under `sudo`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_net::error::{NetError, NetErrorCode};
    use fandhe_container_net::netlink::AttrIter;
    use fandhe_container_net::netlink_route::{
        IFF_UP, IFINFOMSG_LEN, IFLA_IFNAME, IFLA_MASTER, IfName, IpPrefix, LinkCreate,
        NetlinkRouteSocket, NlMsgBuilder, RTM_GETLINK, RTM_NEWLINK,
    };
    use fandhe_container_net::network::{
        AttachResource, AttachStep, ContainerAttachSpec, CreateStep, EndpointId, NetworkCreateSpec,
        NetworkName, PortProtocol, PortPublish, StaticIpam, VethNames, attach_container,
        create_network,
    };
    use fandhe_container_net::nftables_batch::NetlinkNetfilterSocket;

    const LAUNCHER_PID_ENV: &str = "FANDHE_ATTACH_TEST_LAUNCHER_PID";
    const DIR_ENV: &str = "FANDHE_ATTACH_TEST_DIR";
    const OK_LINE: &str =
        "network_attach_privileged: ok master=bridge host=up peer=moved pin=bound rollback=clean";
    /// 新規 netns にカーネルが自動生成するフォールバックトンネルデバイス（有無は環境で変わる）。
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
        let dir = std::env::temp_dir().join(format!("fandhe-attach-test-{}", std::process::id()));
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
                    println!("network_attach_privileged: inner did not finish before deadline");
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
        let dev =
            fs::read_to_string("/proc/net/dev").map_err(|e| fail(format!("read dev: {e}")))?;
        let extra: Vec<&str> = dev
            .lines()
            .skip(2)
            .filter_map(|l| l.split(':').next().map(str::trim))
            .filter(|n| !n.is_empty() && *n != "lo" && !FALLBACK_TUNNEL_DEVICES.contains(n))
            .collect();
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

    /// 外部コマンドを期限つきで実行する（REPAIR-5）。期限切れなら子を kill して回収する。
    fn run_cmd(program: &str, args: &[&str]) -> Result<String, NetError> {
        use std::io::Read as _;
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
                "{program} failed: {}",
                String::from_utf8_lossy(&stderr)
            )));
        }
        Ok(String::from_utf8_lossy(&stdout).into_owned())
    }

    /// 名前指定の `RTM_GETLINK` で応答の `RTM_NEWLINK` ペイロード（ifinfomsg + 属性）を返す。
    fn get_link_payload(sock: &NetlinkRouteSocket, name: &str) -> Result<Vec<u8>, NetError> {
        let n = IfName::new(name)?;
        let reply = sock.request(RTM_GETLINK, 0, timeout(), |b: &mut NlMsgBuilder| {
            b.put_fixed(&[0u8; IFINFOMSG_LEN])?;
            let mut v = n.as_str().as_bytes().to_vec();
            v.push(0);
            b.put_attr(IFLA_IFNAME, &v)
        })?;
        let msg = reply
            .messages()
            .iter()
            .find(|m| m.msg_type() == RTM_NEWLINK)
            .ok_or_else(|| fail("no RTM_NEWLINK in reply"))?;
        Ok(msg.payload().to_vec())
    }

    fn u32_at(payload: &[u8], range: std::ops::Range<usize>) -> Result<u32, NetError> {
        payload
            .get(range)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(u32::from_ne_bytes)
            .ok_or_else(|| fail("short ifinfomsg in reply"))
    }

    /// `(ifindex, ifi_flags, IFLA_MASTER)` を返す。
    fn link_state(
        sock: &NetlinkRouteSocket,
        name: &str,
    ) -> Result<(u32, u32, Option<u32>), NetError> {
        let payload = get_link_payload(sock, name)?;
        let index = u32_at(&payload, 4..8)?;
        let flags = u32_at(&payload, 8..12)?;
        let attrs = payload
            .get(IFINFOMSG_LEN..)
            .ok_or_else(|| fail("short ifinfomsg in reply"))?;
        for attr in AttrIter::new(attrs) {
            let attr = attr?;
            if attr.attr_type() == IFLA_MASTER {
                return Ok((index, flags, Some(u32_at(attr.payload(), 0..4)?)));
            }
        }
        Ok((index, flags, None))
    }

    pub fn inner() {
        match inner_checked() {
            Ok(()) => println!("{OK_LINE}"),
            Err(e) => {
                println!("network_attach_privileged: failed: {e}");
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

        let route = NetlinkRouteSocket::open()?;
        let nft = NetlinkNetfilterSocket::open()?;
        let t = timeout();

        let net = create_network(
            &route,
            &nft,
            &NetworkCreateSpec::new(
                NetworkName::new("att")?,
                IpPrefix::new("10.213.0.1".parse().map_err(|_| fail("addr"))?, 24)?,
            )?,
            t,
        )
        .map_err(|e| {
            if e.step == CreateStep::ResolveIndex {
                fail(format!(
                    "create_network failed at ResolveIndex ({e}); the TASK-139.1 bridge ownership token (IFLA_IFALIAS at creation) may not work on a real kernel (out of scope for TASK-139.2.1)"
                ))
            } else {
                fail(format!("create_network failed at {:?}: {e}", e.step))
            }
        })?;

        // --- 成功経路 ---
        let spec = ContainerAttachSpec::new(EndpointId::new("c1")?, &net, base.clone())?;
        let mut ipam = StaticIpam::for_network(&net)?;
        let attached = attach_container(&route, &nft, &spec, &mut ipam, t)
            .map_err(|e| fail(format!("attach_container failed at {:?}: {e}", e.step)))?;
        if attached.address != IpPrefix::new("10.213.0.2".parse().map_err(|_| fail("addr"))?, 24)? {
            return Err(fail(format!("unexpected address {:?}", attached.address)));
        }
        let host = attached.host_veth.as_str();
        let peer = attached.peer_veth.as_str();

        let (index, flags, master) = link_state(&route, host)?;
        if index != attached.host_index.get() {
            return Err(fail("host ifindex differs from the returned one"));
        }
        if master != Some(net.bridge_index.get()) {
            return Err(fail(format!(
                "host veth IFLA_MASTER is {master:?}, expected {}",
                net.bridge_index.get()
            )));
        }
        if flags & IFF_UP == 0 {
            return Err(fail("host veth is not up"));
        }
        // peer は host（子の）netns から消えている。
        match get_link_payload(&route, peer) {
            Err(e) if e.code() == NetErrorCode::NotFound => {}
            other => {
                return Err(fail(format!(
                    "peer should be gone from this netns: {other:?}"
                )));
            }
        }
        // pin と保持 fd が同じ netns（nsfs の inode が一致）で、自分の netns とは別。
        let pin_ino = fs::metadata(&attached.netns_path)
            .map_err(|e| fail(format!("stat pin: {e}")))?
            .ino();
        let fd_path = format!("/proc/self/fd/{}", attached.netns.fd().as_raw_fd());
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
            return Err(fail("container netns is the same as the current netns"));
        }
        // netns 内にプロセスがいないので pin 経由で入って確認する。
        let pin_str = attached
            .netns_path
            .to_str()
            .ok_or_else(|| fail("pin path is not UTF-8"))?;
        let dev = run_cmd(
            "nsenter",
            &[&format!("--net={pin_str}"), "cat", "/proc/net/dev"],
        )?;
        if !dev
            .lines()
            .any(|l| l.trim_start().starts_with(&format!("{peer}:")))
        {
            return Err(fail(format!(
                "peer {peer} not found in the container netns"
            )));
        }

        // netns 内の設定（TASK-139.3・#316）: default route が gateway 経由で peer から出る。
        // /proc/net/route の Destination・Gateway・Mask は 16 進のリトルエンディアン（10.213.0.1 = 0100D50A）。
        let route_table = run_cmd(
            "nsenter",
            &[&format!("--net={pin_str}"), "cat", "/proc/net/route"],
        )?;
        let default_routes: Vec<&str> = route_table
            .lines()
            .filter(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                f.first() == Some(&peer)
                    && f.get(1) == Some(&"00000000")
                    && f.get(7) == Some(&"00000000")
            })
            .collect();
        if default_routes.len() != 1
            || default_routes[0].split_whitespace().nth(2) != Some("0100D50A")
        {
            return Err(fail(format!(
                "expected exactly one default route via 10.213.0.1 on {peer}, got {default_routes:?}"
            )));
        }

        // --- ロールバック経路: host 側 veth 名を先に塞ぎ、AlreadyExists で失敗させる ---
        let c2 = EndpointId::new("c2")?;
        let names = VethNames::derive(&c2)?;
        route.create_link(
            &LinkCreate::veth(names.host().clone(), IfName::new("fxpre0")?)?,
            t,
        )?;
        let spec2 = ContainerAttachSpec::new(c2, &net, base.clone())?;
        let e = match attach_container(&route, &nft, &spec2, &mut ipam, t) {
            Err(e) => e,
            Ok(_) => return Err(fail("attach on a taken veth name unexpectedly succeeded")),
        };
        if e.step != AttachStep::CreateVeth || e.code() != NetErrorCode::AlreadyExists {
            return Err(fail(format!(
                "unexpected failure: step {:?} code {:?}",
                e.step,
                e.code()
            )));
        }
        let pin2 = spec2.netns_path();
        if e.rollback.removed != [AttachResource::Netns(pin2.clone())]
            || !e.rollback.leftover.is_empty()
        {
            return Err(fail(format!(
                "unexpected rollback report: {:?}",
                e.rollback
            )));
        }
        if Path::new(&pin2).exists() {
            return Err(fail("pin file was not removed by the rollback"));
        }
        link_state(&route, names.host().as_str())
            .map_err(|_| fail("the pre-existing veth must not be deleted by the rollback"))?;

        // --- ポート公開（TASK-139.3・#316）: DNAT ルールが専用テーブルの両チェインに入る ---
        let publish = PortPublish::new(
            PortProtocol::Tcp,
            "192.0.2.10".parse().map_err(|_| fail("addr"))?,
            8080,
            80,
        )?;
        let spec3 = ContainerAttachSpec::new(EndpointId::new("c3")?, &net, base.clone())?
            .with_port_publishes(vec![publish])?;
        let attached3 = attach_container(&route, &nft, &spec3, &mut ipam, t).map_err(|e| {
            fail(format!(
                "attach with port publish failed at {:?}: {e}",
                e.step
            ))
        })?;
        let ruleset = run_cmd("nft", &["list", "table", "ip", net.table.as_str()])?;
        let dnat_lines = ruleset
            .lines()
            .filter(|l| l.contains("dnat to") && l.contains("192.0.2.10") && l.contains("8080"))
            .filter(|l| l.contains(&attached3.address.addr().to_string()) && l.contains(":80"))
            .count();
        if dnat_lines != 2 {
            return Err(fail(format!(
                "expected 2 DNAT rules (prerouting and output), found {dnat_lines} in:\n{ruleset}"
            )));
        }
        Ok(())
    }
}
