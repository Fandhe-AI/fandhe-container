//! nftables masquerade（payload・masq expr と NEWRULE）の実機前提結合試験
//! （NET-11・TASK-138.2・#310・MS-8）。
//!
//! コンテナ相当の netns から外部相当の netns へ、router 相当の netns を経由して UDP を送り、
//! router の POSTROUTING（nat base chain）に投入した masquerade ルールで送信元アドレスが
//! 変換されることを実カーネルで照合する。転送トラフィックが POSTROUTING を通ることを確かめるため
//! 3 つの netns を使う（ローカル発信のトラフィックでは代用しない）。
//!
//! root が必要な実機前提テストのため `harness = false` の独自 `main` で動かし、`-- --ignored` を
//! 付けたときだけ実行する（未指定時は「ignored」を出力して成功終了する分離であり、CI 通過のための
//! 弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では対象外（skip ではなく OS 非該当）。
//!
//! # トポロジー
//!
//! ```text
//! container (10.210.1.2/24, default via 10.210.1.1)
//!     | veth mcn0 <-> mrc0
//! router    (10.210.1.1/24 / 10.210.2.1/24, ip_forward=1, nft: ip table / nat postrouting / masq)
//!     | veth mre0 <-> mex0
//! external  (10.210.2.2/24, 10.210.1.0/24 via 10.210.2.1)
//! ```
//!
//! router は `sudo unshare -n <exe> --ignored` で隔離 netns に入ったテストプロセス自身で、container と
//! external は router から `unshare --net -- <exe> --child <role>` で起動する子（stdin/stdout の行
//! プロトコルで操作）。ルールの投入前に container から UDP を 1 個送り external が見た送信元が
//! `10.210.1.2` であること、投入後に新しい送信元ポートで送り `10.210.2.1`（router の外側アドレス）に
//! 変換されていることを照合する（既存の conntrack エントリの再利用による偽陰性を避けるため、
//! 宛先ポートと送信元ポートを変える）。ip_forward・nft ルール・veth はすべて隔離 netns の中に閉じ、
//! host の設定は変えない。待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る
//! （REPAIR-5）。前提（root・`unshare`・カーネルモジュール）を満たさない場合は skip せず失敗する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("nftables_masq_privileged: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--child") {
        let role = args.get(pos + 1).map(String::as_str).unwrap_or("");
        linux::child(role);
    } else if args.iter().any(|a| a == "--ignored") {
        linux::router();
    } else {
        println!(
            "nftables_masq_privileged: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::mpsc::{self, Receiver};
    use std::time::{Duration, Instant};

    use fandhe_container_net::error::{NetError, NetErrorCode};
    use fandhe_container_net::netlink_route::{
        AddrScope, AddressSpec, IFINFOMSG_LEN, IFLA_IFNAME, IfIndex, IfName, IpPrefix, LinkCreate,
        LinkRef, LinkSet, NetlinkRouteSocket, NetnsPid, NetnsTarget, NlMsgBuilder, RTM_GETLINK,
        RTM_NEWLINK, RouteNextHop, RouteSpec,
    };
    use fandhe_container_net::nftables_batch::{
        BaseChain, ChainCreate, ChainType, NF_IP_PRI_NAT_SRC, NetlinkNetfilterSocket, NfInetHook,
        NftFamily, NftName, TableCreate, TableDelete,
    };
    use fandhe_container_net::nftables_rules::{
        NftMasq, NftPayload, NftRegister, NftRuleExprs, RuleCreate,
    };

    /// 投入前に container が external へ送る宛先ポート。
    const PORT_BEFORE: u16 = 9001;
    /// 投入後に container が external へ送る宛先ポート（conntrack の再利用を避けるため別にする）。
    const PORT_AFTER: u16 = 9002;
    const CONTAINER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 210, 1, 2);
    const ROUTER_INNER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 210, 1, 1);
    const ROUTER_OUTER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 210, 2, 1);
    const EXTERNAL_ADDR: Ipv4Addr = Ipv4Addr::new(10, 210, 2, 2);
    /// router 側 / 子側の veth 名（router の隔離 netns の中で作るため固定名でよい）。
    const RC: &str = "mrc0";
    const CN: &str = "mcn0";
    const RE: &str = "mre0";
    const EX: &str = "mex0";
    const OK_PREFIX: &str = "nftables_masq_privileged: masquerade verified";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn ifname(s: &str) -> IfName {
        IfName::new(s).expect("valid interface name")
    }

    fn nft_name(s: &str) -> NftName {
        NftName::new(s).expect("valid nft name")
    }

    fn fail(msg: impl Into<String>) -> NetError {
        NetError::new(NetErrorCode::FailedPrecondition, msg)
    }

    fn v4(a: Ipv4Addr) -> IpAddr {
        IpAddr::V4(a)
    }

    /// 自プロセスと親プロセスの network namespace が別物であることを検証する（fail-closed）。
    /// 親と同じ netns のまま実行すると host の ip_forward・ruleset・veth を変更してしまうため拒否する。
    fn ensure_isolated_netns() -> Result<(), NetError> {
        let io = |what: &str, e: std::io::Error| {
            NetError::new(NetErrorCode::Internal, format!("{what} failed: {e}"))
        };
        let own = std::fs::read_link("/proc/self/ns/net")
            .map_err(|e| io("readlink /proc/self/ns/net", e))?;
        let parent_path = format!("/proc/{}/ns/net", std::os::unix::process::parent_id());
        let parent = std::fs::read_link(&parent_path)
            .map_err(|e| fail(format!("cannot read parent netns ({e}); refusing to run")))?;
        if own == parent {
            return Err(fail(
                "same network namespace as the parent process; run under `unshare -n` (see AGENTS.md)",
            ));
        }
        Ok(())
    }

    /// 名前指定の `RTM_GETLINK` で ifindex を返す。
    fn get_link_index(sock: &NetlinkRouteSocket, name: &str) -> Result<IfIndex, NetError> {
        let n = ifname(name);
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
            .ok_or_else(|| NetError::new(NetErrorCode::Internal, "no RTM_NEWLINK in reply"))?;
        let raw = msg
            .payload()
            .get(4..8)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .ok_or_else(|| NetError::new(NetErrorCode::Internal, "short ifinfomsg in reply"))?;
        IfIndex::new(u32::from_ne_bytes(raw))
    }

    /// 標準入力から 1 行を読む（EOF は `None`）。
    fn read_line() -> Option<String> {
        let mut line = String::new();
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line.trim().to_owned()),
        }
    }

    fn say(line: &str) {
        println!("{line}");
        let _ = std::io::stdout().flush();
    }

    // ---- 子（container / external。新 netns の中）----

    pub fn child(role: &str) {
        if let Err(e) = child_inner(role) {
            println!("nftables_masq_privileged: child {role} failed: {e}");
            std::process::exit(1);
        }
    }

    fn child_inner(role: &str) -> Result<(), NetError> {
        // `--child` は直接起動できてしまうため、操作前に隔離を確認する（P0・fail-closed）。
        ensure_isolated_netns()?;
        let (dev, addr, route_dst, route_gw) = match role {
            "container" => (
                CN,
                CONTAINER_ADDR,
                IpPrefix::default_v4(),
                ROUTER_INNER_ADDR,
            ),
            "external" => (
                EX,
                EXTERNAL_ADDR,
                IpPrefix::new(v4(Ipv4Addr::new(10, 210, 1, 0)), 24)?,
                ROUTER_OUTER_ADDR,
            ),
            _ => {
                return Err(NetError::new(
                    NetErrorCode::InvalidArgument,
                    "unknown child role",
                ));
            }
        };
        say("ready");
        if read_line().as_deref() != Some("go") {
            return Err(fail("did not receive go"));
        }
        let sock = NetlinkRouteSocket::open()?;
        let idx = get_link_index(&sock, dev)?;
        sock.set_link(&LinkSet::up(LinkRef::Name(ifname(dev))), timeout())?;
        sock.add_address(
            &AddressSpec::new(idx, IpPrefix::new(v4(addr), 24)?, AddrScope::Universe),
            timeout(),
        )?;
        sock.add_route(
            &RouteSpec::new(
                route_dst,
                RouteNextHop::Gateway {
                    gateway: v4(route_gw),
                    oif: Some(idx),
                },
            )?,
            timeout(),
        )?;
        let listeners = if role == "external" {
            let mut v = Vec::new();
            for port in [PORT_BEFORE, PORT_AFTER] {
                let s = UdpSocket::bind(SocketAddr::new(v4(addr), port))
                    .map_err(|e| fail(format!("bind udp failed: {e}")))?;
                s.set_read_timeout(Some(timeout()))
                    .map_err(|e| fail(format!("set_read_timeout failed: {e}")))?;
                v.push((port, s));
            }
            v
        } else {
            Vec::new()
        };
        say("configured");
        while let Some(cmd) = read_line() {
            let mut parts = cmd.split_whitespace();
            match (
                parts.next(),
                parts.next().and_then(|p| p.parse::<u16>().ok()),
            ) {
                (Some("send"), Some(port)) => {
                    // 毎回新しいソケット（新しい送信元ポート）で送る。
                    let s = UdpSocket::bind(SocketAddr::new(v4(addr), 0))
                        .map_err(|e| fail(format!("bind udp failed: {e}")))?;
                    s.send_to(b"fandhe", SocketAddr::new(v4(EXTERNAL_ADDR), port))
                        .map_err(|e| fail(format!("send_to failed: {e}")))?;
                    say("sent");
                }
                (Some("recv"), Some(port)) => {
                    let (_, s) = listeners
                        .iter()
                        .find(|(p, _)| *p == port)
                        .ok_or_else(|| fail("no listener on that port"))?;
                    let mut buf = [0u8; 64];
                    let (n, peer) = s
                        .recv_from(&mut buf)
                        .map_err(|e| fail(format!("recv_from failed: {e}")))?;
                    if buf.get(..n) != Some(&b"fandhe"[..]) {
                        return Err(fail("unexpected datagram payload"));
                    }
                    say(&format!("peer {peer}"));
                }
                _ => return Err(fail("unknown command")),
            }
        }
        Ok(())
    }

    // ---- 親（router。隔離 netns の中のテストプロセス）----

    /// drop で子を kill して wait するガード（失敗経路でも子と netns を残さない）。
    struct ChildGuard {
        role: &'static str,
        child: Child,
        stdin: Option<ChildStdin>,
        lines: Receiver<String>,
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl ChildGuard {
        fn spawn(role: &'static str) -> Self {
            let exe = std::env::current_exe().expect("current_exe");
            let mut child = Command::new("unshare")
                .args(["--net", "--"])
                .arg(exe)
                .args(["--child", role])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("spawn unshare --net child");
            let stdin = child.stdin.take();
            let stdout = child.stdout.take().expect("child stdout");
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
            Self {
                role,
                child,
                stdin,
                lines: rx,
            }
        }

        fn pid(&self) -> u32 {
            self.child.id()
        }

        /// 期限内に `prefix` で始まる行が来るまで読み、その行を返す。
        fn expect_prefix(&self, prefix: &str) -> String {
            let deadline = Instant::now() + timeout();
            let mut skipped = Vec::new();
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match self.lines.recv_timeout(left) {
                    Ok(l) if l.starts_with(prefix) => return l,
                    Ok(l) => skipped.push(l),
                    Err(e) => panic!(
                        "{} did not print {prefix:?} before deadline: {e}; other lines: {skipped:?}",
                        self.role
                    ),
                }
            }
        }

        fn send(&mut self, line: &str) {
            let stdin = self.stdin.as_mut().expect("child stdin");
            stdin
                .write_all(format!("{line}\n").as_bytes())
                .expect("write to child");
            stdin.flush().expect("flush to child");
        }
    }

    /// テスト途中で失敗しても nft テーブルを消す（ベストエフォート。隔離 netns なので host には影響しない）。
    struct TableGuard {
        socket: NetlinkNetfilterSocket,
        table: NftName,
    }

    impl Drop for TableGuard {
        fn drop(&mut self) {
            let del = TableDelete::new(NftFamily::Ipv4, self.table.clone());
            let _ = self
                .socket
                .send_batch(timeout(), |b| b.push_with(|seq| del.build(seq)).map(|_| ()));
        }
    }

    fn require_root_and_unshare() {
        let uid_root = std::fs::read_to_string("/proc/self/status")
            .expect("read /proc/self/status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_owned))
            .as_deref()
            == Some("0");
        assert!(uid_root, "this test requires root (euid 0); see AGENTS.md");
        let ok = Command::new("unshare")
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "util-linux `unshare` is required; see AGENTS.md");
    }

    /// 受信側が見た `peer 10.x.y.z:port` から送信元 IP を取り出す。
    fn peer_ip(line: &str) -> String {
        line.strip_prefix("peer ")
            .and_then(|r| r.rsplit_once(':'))
            .map(|(ip, _)| ip.to_owned())
            .unwrap_or_else(|| panic!("unparsable peer line: {line:?}"))
    }

    fn configure_router_side(sock: &NetlinkRouteSocket, dev: &str, addr: Ipv4Addr) {
        let idx = get_link_index(sock, dev).expect("router link index");
        sock.set_link(&LinkSet::up(LinkRef::Name(ifname(dev))), timeout())
            .expect("router link up");
        sock.add_address(
            &AddressSpec::new(
                idx,
                IpPrefix::new(v4(addr), 24).expect("prefix"),
                AddrScope::Universe,
            ),
            timeout(),
        )
        .expect("router address");
    }

    pub fn router() {
        require_root_and_unshare();
        ensure_isolated_netns().expect("refusing to run outside an isolated netns");
        // ip_forward は netns ごとの値のため、隔離 netns の中に限り host には影響しない。
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n").expect("enable ip_forward");

        let mut container = ChildGuard::spawn("container");
        let mut external = ChildGuard::spawn("external");
        container.expect_prefix("ready");
        external.expect_prefix("ready");

        let sock = NetlinkRouteSocket::open().expect("open netlink route socket");
        sock.create_link(
            &LinkCreate::veth(ifname(RC), ifname(CN)).expect("veth"),
            timeout(),
        )
        .expect("create container veth");
        sock.create_link(
            &LinkCreate::veth(ifname(RE), ifname(EX)).expect("veth"),
            timeout(),
        )
        .expect("create external veth");
        for (dev, child) in [(CN, &container), (EX, &external)] {
            let pid = NetnsPid::new(child.pid()).expect("child pid");
            sock.set_link(
                &LinkSet::move_to_netns(LinkRef::Name(ifname(dev)), NetnsTarget::Pid(pid)),
                timeout(),
            )
            .expect("move veth by pid");
        }
        configure_router_side(&sock, RC, ROUTER_INNER_ADDR);
        configure_router_side(&sock, RE, ROUTER_OUTER_ADDR);

        container.send("go");
        external.send("go");
        container.expect_prefix("configured");
        external.expect_prefix("configured");

        // 投入前: 送信元は変換されず container のアドレスのまま。
        container.send(&format!("send {PORT_BEFORE}"));
        container.expect_prefix("sent");
        external.send(&format!("recv {PORT_BEFORE}"));
        let before = peer_ip(&external.expect_prefix("peer "));
        assert_eq!(before, CONTAINER_ADDR.to_string(), "before masquerade");

        // masquerade ルールを 1 回のバッチで投入する。payload（IPv4 saddr を REG_1 へ load）は
        // 自前エンコードの payload を kernel が受理することを確かめるためで、読み込んだ値は使わない。
        let nft = NetlinkNetfilterSocket::open().expect("open NETLINK_NETFILTER");
        let table = nft_name("fandhe_masq_it");
        let guard = TableGuard {
            socket: nft,
            table: table.clone(),
        };
        let chain = nft_name("postrouting");
        let create_table = TableCreate::new(NftFamily::Ipv4, table.clone()).exclusive();
        let create_chain = ChainCreate::base(
            NftFamily::Ipv4,
            table.clone(),
            chain.clone(),
            BaseChain {
                chain_type: ChainType::Nat,
                hook: NfInetHook::PostRouting,
                priority: NF_IP_PRI_NAT_SRC,
            },
        )
        .expect("base chain");
        let mut exprs = NftRuleExprs::new();
        exprs
            .push(
                NftPayload::ipv4_saddr(NftRegister::REG_1)
                    .expect("payload")
                    .to_expr()
                    .expect("payload expr"),
            )
            .expect("push payload");
        exprs
            .push(NftMasq::new().to_expr().expect("masq expr"))
            .expect("push masq");
        let rule = RuleCreate::new(NftFamily::Ipv4, table.clone(), chain, exprs);
        let limit = timeout();
        let started = Instant::now();
        guard
            .socket
            .send_batch(limit, |b| {
                b.push_with(|seq| create_table.build(seq))?;
                b.push_with(|seq| create_chain.build(seq))?;
                b.push_with(|seq| rule.build(seq))?;
                Ok(())
            })
            .expect("install masquerade rule (needs nf_tables, nft_chain_nat, nft_masq, nf_nat)");
        assert!(started.elapsed() < limit, "batch exceeded {limit:?}");

        // 投入後: 新しい送信元ポート・別の宛先ポートで送り、router の外側アドレスへ変換されていること。
        container.send(&format!("send {PORT_AFTER}"));
        container.expect_prefix("sent");
        external.send(&format!("recv {PORT_AFTER}"));
        let after = peer_ip(&external.expect_prefix("peer "));
        assert_eq!(after, ROUTER_OUTER_ADDR.to_string(), "after masquerade");

        drop(guard);
        println!("{OK_PREFIX} before={before} after={after} (NET-11)");
    }
}
