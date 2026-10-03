//! nftables DNAT（payload・cmp・immediate・nat expr と NEWRULE / DELRULE）の実機前提結合試験
//! （NET-11・TASK-138.3・#311・MS-8）。
//!
//! external 相当の netns から router 相当の netns の外側アドレス宛てに送った UDP が、router の
//! PREROUTING（nat base chain）に投入した DNAT ルールで container 相当の netns へ転送されること
//! （AC1）と、投入したルールをハンドル指定の DELRULE で削除でき、削除後は転送されなくなること（AC2）を
//! 実カーネルで照合する。ローカル配送のトラフィックでは代用しない。
//!
//! root が必要な実機前提テストのため `harness = false` の独自 `main` で動かし、`-- --ignored` を
//! 付けたときだけ実行する（未指定時は「ignored」を出力して成功終了する分離であり、CI 通過のための
//! 弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では対象外（skip ではなく OS 非該当）。
//!
//! # トポロジー
//!
//! ```text
//! container (10.211.1.2/24, default via 10.211.1.1, udp 9080 で待受)
//!     | veth dcn0 <-> drc0
//! router    (10.211.1.1/24 / 10.211.2.1/24, ip_forward=1, udp 18080 で待受,
//!            nft: ip table / nat prerouting / udp daddr+dport 一致 -> dnat 10.211.1.2:9080)
//!     | veth dre0 <-> dex0
//! external  (10.211.2.2/24)
//! ```
//!
//! router は `sudo unshare -n <exe> --ignored` で隔離 netns に入ったテストプロセス自身で、container と
//! external は router から `unshare --net -- <exe> --child <role>` で起動する子（stdin/stdout の行
//! プロトコルで操作）。external は毎回新しいソケット（新しい送信元ポート）で送り、conntrack の既存
//! エントリの再利用による偽陽性・偽陰性を避ける。照合の順序は次のとおり。
//!
//! 1. 投入前: router 自身の待受ソケットに届く（送信元 10.211.2.2）
//! 2. 1 バッチで table / chain / rule を投入する
//! 3. 投入後: container の待受ソケットに届く（送信元は変換されず 10.211.2.2）
//! 4. ハンドル指定の DELRULE で削除する
//! 5. 削除後: 再び router 自身の待受ソケットに届く
//! 6. 同じハンドルをもう一度削除すると ENOENT（ハンドルで個別のルールを指している証拠）
//!
//! ip_forward・nft ルール・veth はすべて隔離 netns の中に閉じ、host の設定は変えない。待ちはすべて
//! `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。前提（root・`unshare`・
//! カーネルモジュール）を満たさない場合は skip せず失敗する。
//!
//! # ルールハンドルの前提
//!
//! ハンドル取得経路（NLM_F_ECHO・GETRULE dump）は未実装（`nftables_rules::rule` の未実装範囲）のため、
//! kernel のテーブルごとの採番（`nf_tables_alloc_handle` が `++table->hgenerator`）を前提に、新規
//! テーブルへ chain → rule の順で作ったルールのハンドルを [`EXPECTED_RULE_HANDLE`] とする。
//! 前提が外れた場合は削除バッチが ENOENT で失敗するので、その旨を名指しして失敗する（fail-closed）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("nftables_dnat_privileged: Linux only, not applicable on this OS");
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
            "nftables_dnat_privileged: ignored (requires root and `unshare -n`; run the built executable with `--ignored` under `sudo unshare -n`, see AGENTS.md)"
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
        BaseChain, ChainCreate, ChainType, NF_IP_PRI_NAT_DST, NetlinkNetfilterSocket, NfInetHook,
        NftBatchOutcome, NftBatchPosition, NftFamily, NftName, TableCreate, TableDelete,
    };
    use fandhe_container_net::nftables_rules::{
        NftCmp, NftDataValue, NftImmediate, NftNat, NftPayload, NftRegister, NftRuleExprs,
        NftRuleHandle, RuleCreate, RuleDelete,
    };

    /// router の外側アドレスで公開するポート（DNAT 前の宛先ポート）。
    const HOST_PORT: u16 = 18080;
    /// container が待ち受けるポート（DNAT 後の宛先ポート。書き換え自体を検証するため別の値にする）。
    const CONT_PORT: u16 = 9080;
    const CONTAINER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 211, 1, 2);
    const ROUTER_INNER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 211, 1, 1);
    const ROUTER_OUTER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 211, 2, 1);
    const EXTERNAL_ADDR: Ipv4Addr = Ipv4Addr::new(10, 211, 2, 2);
    /// 新規テーブルへ chain → rule の順に作ったルールのハンドル（モジュール doc「ルールハンドルの前提」）。
    const EXPECTED_RULE_HANDLE: u64 = 2;
    /// router 側 / 子側の veth 名（router の隔離 netns の中で作るため固定名でよい）。
    const RC: &str = "drc0";
    const CN: &str = "dcn0";
    const RE: &str = "dre0";
    const EX: &str = "dex0";
    const OK_PREFIX: &str = "nftables_dnat_privileged: dnat verified";
    const UDP_PROTO: u8 = 17;

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
            println!("nftables_dnat_privileged: child {role} failed: {e}");
            std::process::exit(1);
        }
    }

    fn child_inner(role: &str) -> Result<(), NetError> {
        // `--child` は直接起動できてしまうため、操作前に隔離を確認する（P0・fail-closed）。
        ensure_isolated_netns()?;
        let (dev, addr, default_gw) = match role {
            "container" => (CN, CONTAINER_ADDR, Some(ROUTER_INNER_ADDR)),
            "external" => (EX, EXTERNAL_ADDR, None),
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
        if let Some(gw) = default_gw {
            sock.add_route(
                &RouteSpec::new(
                    IpPrefix::default_v4(),
                    RouteNextHop::Gateway {
                        gateway: v4(gw),
                        oif: Some(idx),
                    },
                )?,
                timeout(),
            )?;
        }
        let listener = if role == "container" {
            let s = UdpSocket::bind(SocketAddr::new(v4(addr), CONT_PORT))
                .map_err(|e| fail(format!("bind udp failed: {e}")))?;
            s.set_read_timeout(Some(timeout()))
                .map_err(|e| fail(format!("set_read_timeout failed: {e}")))?;
            Some(s)
        } else {
            None
        };
        say("configured");
        while let Some(cmd) = read_line() {
            let mut parts = cmd.split_whitespace();
            match (
                parts.next(),
                parts.next().and_then(|p| p.parse::<u16>().ok()),
            ) {
                (Some("send"), Some(port)) => {
                    // 毎回新しいソケット（新しい送信元ポート）で router の外側アドレスへ送る。
                    let s = UdpSocket::bind(SocketAddr::new(v4(addr), 0))
                        .map_err(|e| fail(format!("bind udp failed: {e}")))?;
                    s.send_to(b"fandhe", SocketAddr::new(v4(ROUTER_OUTER_ADDR), port))
                        .map_err(|e| fail(format!("send_to failed: {e}")))?;
                    say("sent");
                }
                (Some("recv"), None) => {
                    let s = listener
                        .as_ref()
                        .ok_or_else(|| fail("this role has no listener"))?;
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

    /// external から router の外側アドレス `HOST_PORT` 宛てに 1 個送る。
    fn external_sends(external: &mut ChildGuard) {
        external.send(&format!("send {HOST_PORT}"));
        external.expect_prefix("sent");
    }

    /// router 自身の待受ソケットが受けた送信元 IP を返す（期限付き）。
    fn router_receives(sock: &UdpSocket) -> String {
        let mut buf = [0u8; 64];
        let (n, peer) = sock
            .recv_from(&mut buf)
            .expect("router did not receive the datagram before deadline");
        assert_eq!(buf.get(..n), Some(&b"fandhe"[..]), "router payload");
        peer.ip().to_string()
    }

    /// DNAT ルールの expr 列。`ip daddr == router 外側 && ip protocol == udp && udp dport == HOST_PORT`
    /// を照合し、`CONTAINER_ADDR:CONT_PORT` へ書き換える。
    fn dnat_exprs() -> NftRuleExprs {
        let r1 = NftRegister::REG_1;
        let r2 = NftRegister::REG_2;
        let data = |b: &[u8]| NftDataValue::new(b).expect("data");
        let mut exprs = NftRuleExprs::new();
        let all = [
            NftPayload::ipv4_daddr(r1)
                .expect("daddr")
                .to_expr()
                .expect("expr"),
            NftCmp::eq(r1, data(&ROUTER_OUTER_ADDR.octets()))
                .expect("cmp")
                .to_expr()
                .expect("expr"),
            NftPayload::ipv4_protocol(r1)
                .expect("proto")
                .to_expr()
                .expect("expr"),
            NftCmp::eq(r1, data(&[UDP_PROTO]))
                .expect("cmp")
                .to_expr()
                .expect("expr"),
            NftPayload::transport_dport(r1)
                .expect("dport")
                .to_expr()
                .expect("expr"),
            NftCmp::eq(r1, data(&HOST_PORT.to_be_bytes()))
                .expect("cmp")
                .to_expr()
                .expect("expr"),
            NftImmediate::ipv4_addr(r1, CONTAINER_ADDR)
                .expect("imm")
                .to_expr()
                .expect("expr"),
            NftImmediate::port(r2, CONT_PORT)
                .expect("imm")
                .to_expr()
                .expect("expr"),
            NftNat::dnat_ipv4(r1, Some(r2))
                .expect("nat")
                .to_expr()
                .expect("expr"),
        ];
        for e in all {
            exprs.push(e).expect("push expr");
        }
        exprs
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

        // router 自身の待受（DNAT されないときに届く先）。
        let router_sock = UdpSocket::bind(SocketAddr::new(v4(ROUTER_OUTER_ADDR), HOST_PORT))
            .expect("bind router udp");
        router_sock
            .set_read_timeout(Some(timeout()))
            .expect("router read timeout");

        // 1. 投入前: router 自身に届く。
        external_sends(&mut external);
        let before = router_receives(&router_sock);
        assert_eq!(before, EXTERNAL_ADDR.to_string(), "before dnat (router)");

        // 2. table / nat prerouting chain / DNAT rule を 1 バッチで投入する。
        let nft = NetlinkNetfilterSocket::open().expect("open NETLINK_NETFILTER");
        let table = nft_name("fandhe_dnat_it");
        let guard = TableGuard {
            socket: nft,
            table: table.clone(),
        };
        let chain = nft_name("prerouting");
        let create_table = TableCreate::new(NftFamily::Ipv4, table.clone()).exclusive();
        let create_chain = ChainCreate::base(
            NftFamily::Ipv4,
            table.clone(),
            chain.clone(),
            BaseChain {
                chain_type: ChainType::Nat,
                hook: NfInetHook::PreRouting,
                priority: NF_IP_PRI_NAT_DST,
            },
        )
        .expect("base chain");
        let rule = RuleCreate::new(NftFamily::Ipv4, table.clone(), chain.clone(), dnat_exprs());
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
            .expect("install dnat rule (needs nf_tables, nft_chain_nat, nft_nat, nf_nat)");
        assert!(started.elapsed() < limit, "batch exceeded {limit:?}");

        // 3. 投入後: container の CONT_PORT に届く（送信元は変換されない）。AC1。
        external_sends(&mut external);
        container.send("recv");
        let after = peer_ip(&container.expect_prefix("peer "));
        assert_eq!(after, EXTERNAL_ADDR.to_string(), "after dnat (container)");

        // 4. ハンドル指定で削除する。AC2。
        let handle = NftRuleHandle::new(EXPECTED_RULE_HANDLE).expect("handle");
        let delete = RuleDelete::new(NftFamily::Ipv4, table.clone(), chain.clone(), handle);
        guard
            .socket
            .send_batch(limit, |b| {
                b.push_with(|seq| delete.build(seq))?;
                Ok(())
            })
            .unwrap_or_else(|e| {
                panic!(
                    "delete by handle {EXPECTED_RULE_HANDLE} failed: {e}; the test assumes the kernel assigns handle 1 to the chain and 2 to the first rule of a new table (nf_tables_alloc_handle)"
                )
            });

        // 5. 削除後: 再び router 自身に届く（DNAT が外れた直接の証拠）。
        external_sends(&mut external);
        let removed = router_receives(&router_sock);
        assert_eq!(removed, EXTERNAL_ADDR.to_string(), "after delete (router)");

        // 6. 同じハンドルの再削除は ENOENT（ハンドルで個別のルールを指している証拠）。
        let err = guard
            .socket
            .send_batch(limit, |b| {
                b.push_with(|seq| delete.build(seq))?;
                Ok(())
            })
            .expect_err("deleting a removed handle must fail");
        assert_eq!(err.outcome(), NftBatchOutcome::Aborted, "{err}");
        assert_eq!(err.failures().len(), 1, "{err}");
        let f = err.failures().first().copied().expect("one failure");
        assert_eq!(f.position(), NftBatchPosition::Body { index: 0 }, "{err}");
        assert_eq!(f.errno(), 2, "{err}");
        assert_eq!(f.code(), NetErrorCode::NotFound, "{err}");

        drop(guard);
        println!(
            "{OK_PREFIX} before={before} after={after} removed={removed} handle={EXPECTED_RULE_HANDLE} (NET-11)"
        );
    }
}
