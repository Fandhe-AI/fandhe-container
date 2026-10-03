//! bridge・DNAT・masquerade の 3 経路疎通の実機前提結合試験（NET-11・TASK-138.4・#312・MS-8）。
//!
//! NET-11 の期待「PoC-15 と同じ 3 経路が自前の netlink / nftables 実装で成立すること」を、実カーネルで
//! 1 本のテストにまとめて照合する。
//!
//! - (a) 同一 bridge 上のコンテナ間: c1 -> c2
//! - (b) ホスト -> コンテナ: router（ホスト役）の bridge アドレスから c1 へ
//! - (c) ポート公開（DNAT。ホストの非ループバックアドレス宛て）: 主はホスト自身が外側アドレス
//!   `10.212.2.1:18080` 宛てに送る通信を OUTPUT（`NfInetHook::LocalOut`）の nat chain で c1 へ、副は
//!   external が同じ宛先に送る通信を PREROUTING の DNAT で c1 へ（PoC-15 は OUTPUT 経路で計測している）
//! - 追加: c1 -> external の送信元が masquerade で外側アドレスへ変換されること
//!
//! root が必要な実機前提テストのため `harness = false` の独自 `main` で動かし、`-- --ignored` を付けた
//! ときだけ実行する（未指定時は「ignored」を出力して成功終了する分離であり、CI 通過のための弱体化では
//! ない。`AGENTS.md`「実機前提テスト」節）。非 Linux では対象外（skip ではなく OS 非該当）。
//!
//! # トポロジー
//!
//! ```text
//! c1 (10.212.1.2/24, gw 10.212.1.1)      c2 (10.212.1.3/24, gw 10.212.1.1)
//!    | veth fcc1 <-> fpc1                    | veth fcc2 <-> fpc2
//!    +------------ bridge fbr0 (10.212.1.1/24) ------------+
//! router/host (テストプロセス自身。ip_forward=1。fbr0 と fpe0 10.212.2.1/24 を持つ)
//!    | veth fpe0 <-> fex0
//! external (10.212.2.2/24)
//! ```
//!
//! `sudo <exe> --ignored` のランチャ（host netns の root プロセス）はネットワーク操作をせず、
//! `unshare --net -- <exe> --router` で新規 netns の router を起動する。router は c1 / c2 / external を
//! `unshare --net -- <exe> --child <role>` で起動し、stdin / stdout の行プロトコル（`listen` / `recv` /
//! `send`）で操作する。送信ごとに新しいソケットを bind して保持し、送信元ポートの重複（conntrack の
//! 既存エントリ再利用による偽陽性・偽陰性）を送信側と router 側の両方で確かめる。
//!
//! # 照合の順序
//!
//! 1. 投入前: bridge への接続（`IFLA_MASTER`）・(a)・(b)・(c) のホスト自己宛て・masq 前の送信元
//! 2. 1 バッチで table（output / prerouting / postrouting の 3 chain とルール）を投入する
//! 3. 投入後: (c) 主・(c) 副・masq の変換後送信元
//! 4. 回帰: (a)・(b) の送信元が投入前と同じであること（ルールの範囲指定が効いている証拠）
//!
//! masq は `ip daddr == external` に絞る。範囲を絞らないと、`bridge-nf-call-iptables` が有効な環境で
//! bridge 内の c1 -> c2 まで書き換えて (a) を壊す。DNAT も外側アドレス・UDP・公開ポートに絞る。
//!
//! # bridge への接続
//!
//! `IFLA_MASTER`（bridge への enslave）は `netlink_route` に未実装（REPAIR-3。TASK-139 で API 化予定）の
//! ため、本テストは公開の `NetlinkRouteSocket::request` と `NlMsgBuilder` で `RTM_SETLINK` を組んで送る。
//! 接続は `RTM_GETLINK` 応答の `IFLA_MASTER` が bridge の ifindex と一致することで具体値照合する。
//!
//! ip_forward・nft ルール・bridge・veth はすべて隔離 netns の中に閉じ、host の設定は変えない。待ちは
//! すべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。前提（root・
//! `unshare`・カーネルモジュール）を満たさない場合は skip せず失敗する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("nftables_paths_privileged: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--child") {
        let role = args.get(pos + 1).map(String::as_str).unwrap_or("");
        linux::child(role);
    } else if args.iter().any(|a| a == "--ignored") {
        linux::launcher();
    } else if args.iter().any(|a| a == "--router") {
        linux::router();
    } else {
        println!(
            "nftables_paths_privileged: ignored (requires root and `unshare`; run the built executable with `--ignored` under `sudo`, see AGENTS.md)"
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
    use fandhe_container_net::netlink::AttrIter;
    use fandhe_container_net::netlink_route::{
        AddrScope, AddressSpec, IFINFOMSG_LEN, IFLA_IFNAME, IfIndex, IfName, IpPrefix, LinkCreate,
        LinkRef, LinkSet, NetlinkRouteSocket, NetnsPid, NetnsTarget, NlMsgBuilder, RTM_GETLINK,
        RTM_NEWLINK, RTM_SETLINK, RouteNextHop, RouteSpec,
    };
    use fandhe_container_net::nftables_batch::{
        BaseChain, ChainCreate, ChainType, NF_IP_PRI_NAT_DST, NF_IP_PRI_NAT_SRC,
        NetlinkNetfilterSocket, NfInetHook, NftFamily, NftName, TableCreate, TableDelete,
    };
    use fandhe_container_net::nftables_rules::{
        NftCmp, NftDataValue, NftImmediate, NftMasq, NftNat, NftPayload, NftRegister, NftRuleExprs,
        RuleCreate,
    };

    /// router の外側アドレスで公開するポート（DNAT 前の宛先ポート）。
    const HOST_PORT: u16 = 18080;
    /// c1 が待ち受けるポート（DNAT 後の宛先ポート。書き換え自体を検証するため別の値にする）。
    const CONT_PORT: u16 = 9080;
    /// 経路 (a) の c2 の待受ポート。
    const PORT_A: u16 = 9101;
    /// 経路 (b) の c1 の待受ポート。
    const PORT_B: u16 = 9102;
    /// masq 確認の external の待受ポート。
    const PORT_M: u16 = 9103;
    const C1_ADDR: Ipv4Addr = Ipv4Addr::new(10, 212, 1, 2);
    const C2_ADDR: Ipv4Addr = Ipv4Addr::new(10, 212, 1, 3);
    /// bridge に付けるホスト側アドレス（コンテナの default gateway）。
    const HOST_INNER: Ipv4Addr = Ipv4Addr::new(10, 212, 1, 1);
    /// ホストの非ループバックな外側アドレス（ポート公開の宛先）。
    const HOST_OUTER: Ipv4Addr = Ipv4Addr::new(10, 212, 2, 1);
    const EXTERNAL_ADDR: Ipv4Addr = Ipv4Addr::new(10, 212, 2, 2);
    const BRIDGE: &str = "fbr0";
    const PC1: &str = "fpc1";
    const CC1: &str = "fcc1";
    const PC2: &str = "fpc2";
    const CC2: &str = "fcc2";
    const PE: &str = "fpe0";
    const EX: &str = "fex0";
    /// `IFLA_MASTER`（`linux/if_link.h`）。bridge への接続先 ifindex を持つ u32 属性。
    const IFLA_MASTER: u16 = 10;
    const OK_PREFIX: &str = "nftables_paths_privileged: three paths verified";
    const UDP_PROTO: u8 = 17;
    const PAYLOAD: &[u8] = b"fandhe";

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

    /// ランチャが router へ自身の pid を渡す環境変数（router が自分の親＝ランチャであることの確認に使う）。
    const LAUNCHER_PID_ENV: &str = "FANDHE_PATHS_TEST_LAUNCHER_PID";

    /// 新規 netns にカーネルが自動生成するフォールバックトンネルデバイス名。
    /// モジュールのロード状況で有無が変わるため「新規 netns 判定」では無視する
    /// （`link_netns_privileged` の同名定数と同じ一覧）。
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

    /// 自プロセスが「作成直後の新規 network namespace」にいることを検証する（fail-closed）。
    ///
    /// 親との netns 比較だけでは、親が別の共有 netns にいる場合に素通りするため、(1) 親と別 netns
    /// であること、(2) `/proc/net/dev`（読み手の netns を映す）に `lo` とフォールバックトンネル
    /// デバイス以外のインターフェースが無いこと（host・共有 netns は通常それ以外を持つ）を併せて確認する。
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
                "same network namespace as the parent process; refusing to run (see AGENTS.md)",
            ));
        }
        let dev =
            std::fs::read_to_string("/proc/net/dev").map_err(|e| io("read /proc/net/dev", e))?;
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

    /// ランチャ（host netns の root プロセス）。自身では何も変更せず、新規 netns の router を起動して
    /// 終了コードを引き継ぐ。待ちは期限付き（REPAIR-5）。
    pub fn launcher() {
        require_root_and_unshare();
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new("unshare")
            .args(["--net", "--"])
            .arg(exe)
            .arg("--router")
            .env(LAUNCHER_PID_ENV, std::process::id().to_string())
            .spawn()
            .expect("spawn unshare --net router");
        let deadline = Instant::now() + timeout() * 6;
        loop {
            match child.try_wait().expect("wait router") {
                Some(st) => std::process::exit(st.code().unwrap_or(1)),
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    println!("nftables_paths_privileged: router did not finish before deadline");
                    std::process::exit(1);
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    /// router が、環境変数で渡されたランチャの直接の子であることを確認する（手動で `--router` を
    /// 直接起動して隔離を迂回する誤用を弾く）。
    fn ensure_launched_by_launcher() -> Result<(), NetError> {
        let expected = std::env::var(LAUNCHER_PID_ENV)
            .ok()
            .and_then(|v| v.parse::<u32>().ok());
        if expected != Some(std::os::unix::process::parent_id()) {
            return Err(fail(
                "`--router` must be started by the `--ignored` launcher; refusing to run",
            ));
        }
        Ok(())
    }

    /// 名前指定の `RTM_GETLINK` で応答の `RTM_NEWLINK` ペイロード（ifinfomsg + 属性）を返す。
    fn get_link_payload(sock: &NetlinkRouteSocket, name: &str) -> Result<Vec<u8>, NetError> {
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
        Ok(msg.payload().to_vec())
    }

    /// 名前指定の `RTM_GETLINK` で ifindex を返す。
    fn get_link_index(sock: &NetlinkRouteSocket, name: &str) -> Result<IfIndex, NetError> {
        let payload = get_link_payload(sock, name)?;
        let raw = payload
            .get(4..8)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .ok_or_else(|| NetError::new(NetErrorCode::Internal, "short ifinfomsg in reply"))?;
        IfIndex::new(u32::from_ne_bytes(raw))
    }

    /// `port` を `master`（bridge）の ifindex に接続する（`RTM_SETLINK` + `IFLA_MASTER`）。
    ///
    /// `netlink_route` に未実装の操作をテスト内で組む（モジュール doc「bridge への接続」）。
    fn set_master(sock: &NetlinkRouteSocket, port: &str, master: IfIndex) -> Result<(), NetError> {
        let port_idx = get_link_index(sock, port)?;
        let mut ifi = [0u8; IFINFOMSG_LEN];
        if let Some(d) = ifi.get_mut(4..8) {
            d.copy_from_slice(&port_idx.get().to_ne_bytes());
        }
        sock.request(RTM_SETLINK, 0, timeout(), |b: &mut NlMsgBuilder| {
            b.put_fixed(&ifi)?;
            b.put_attr(IFLA_MASTER, &master.get().to_ne_bytes())
        })?;
        Ok(())
    }

    /// `RTM_GETLINK` 応答の `IFLA_MASTER`（接続先 bridge の ifindex）を返す。未接続なら `None`。
    fn link_master(sock: &NetlinkRouteSocket, name: &str) -> Result<Option<u32>, NetError> {
        let payload = get_link_payload(sock, name)?;
        let attrs = payload
            .get(IFINFOMSG_LEN..)
            .ok_or_else(|| NetError::new(NetErrorCode::Internal, "short ifinfomsg in reply"))?;
        for attr in AttrIter::new(attrs) {
            let attr = attr?;
            if attr.attr_type() == IFLA_MASTER {
                let raw = attr
                    .payload()
                    .get(..4)
                    .and_then(|s| <[u8; 4]>::try_from(s).ok())
                    .ok_or_else(|| {
                        NetError::new(NetErrorCode::Internal, "short IFLA_MASTER attribute")
                    })?;
                return Ok(Some(u32::from_ne_bytes(raw)));
            }
        }
        Ok(None)
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

    /// 新しいソケットを `src` に bind して保持リストへ入れ、`dst` へ 1 個送る。使った送信元ポートを返す。
    ///
    /// 保持したソケットは close しない。close すると次の bind(0) が同じ送信元ポートを再利用し得て、
    /// 既存 conntrack エントリが適用され配送先判定を誤らせるため。保持中のポートとの重複は送信前に
    /// 検査して fail-closed にする。
    fn send_fresh(
        held: &mut Vec<(u16, UdpSocket)>,
        src: Ipv4Addr,
        dst: SocketAddr,
    ) -> Result<u16, NetError> {
        let s = UdpSocket::bind(SocketAddr::new(v4(src), 0))
            .map_err(|e| fail(format!("bind udp failed: {e}")))?;
        let src_port = s
            .local_addr()
            .map_err(|e| fail(format!("local_addr failed: {e}")))?
            .port();
        if held.iter().any(|(p, _)| *p == src_port) {
            return Err(fail(format!(
                "source port {src_port} is already used by a held sender socket"
            )));
        }
        s.send_to(PAYLOAD, dst)
            .map_err(|e| fail(format!("send_to failed: {e}")))?;
        held.push((src_port, s));
        Ok(src_port)
    }

    /// `src` を bind した待受ソケット（受信は期限付き）。
    fn listen(addr: SocketAddr) -> Result<UdpSocket, NetError> {
        let s = UdpSocket::bind(addr).map_err(|e| fail(format!("bind udp failed: {e}")))?;
        s.set_read_timeout(Some(timeout()))
            .map_err(|e| fail(format!("set_read_timeout failed: {e}")))?;
        Ok(s)
    }

    /// 受信して payload を検証し、送信元を返す（期限付き）。
    fn recv_checked(s: &UdpSocket) -> Result<SocketAddr, NetError> {
        let mut buf = [0u8; 64];
        let (n, peer) = s
            .recv_from(&mut buf)
            .map_err(|e| fail(format!("recv_from failed: {e}")))?;
        if buf.get(..n) != Some(PAYLOAD) {
            return Err(fail("unexpected datagram payload"));
        }
        Ok(peer)
    }

    // ---- 子（c1 / c2 / external。新 netns の中）----

    pub fn child(role: &str) {
        if let Err(e) = child_inner(role) {
            println!("nftables_paths_privileged: child {role} failed: {e}");
            std::process::exit(1);
        }
    }

    fn child_inner(role: &str) -> Result<(), NetError> {
        // `--child` は直接起動できてしまうため、操作前に隔離を確認する（P0・fail-closed）。
        ensure_isolated_netns()?;
        let (dev, addr, default_gw) = match role {
            "c1" => (CC1, C1_ADDR, Some(HOST_INNER)),
            "c2" => (CC2, C2_ADDR, Some(HOST_INNER)),
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
        let mut listeners: Vec<(u16, UdpSocket)> = Vec::new();
        let mut held_senders: Vec<(u16, UdpSocket)> = Vec::new();
        say("configured");
        while let Some(cmd) = read_line() {
            let mut parts = cmd.split_whitespace();
            match (parts.next(), parts.next(), parts.next()) {
                (Some("listen"), Some(port), None) => {
                    let port = port
                        .parse::<u16>()
                        .map_err(|_| fail("invalid port in listen"))?;
                    listeners.push((port, listen(SocketAddr::new(v4(addr), port))?));
                    say("listening");
                }
                (Some("recv"), Some(port), None) => {
                    let port = port
                        .parse::<u16>()
                        .map_err(|_| fail("invalid port in recv"))?;
                    let s = listeners
                        .iter()
                        .find(|(p, _)| *p == port)
                        .map(|(_, s)| s)
                        .ok_or_else(|| fail("no listener on that port"))?;
                    let peer = recv_checked(s)?;
                    say(&format!("peer {peer}"));
                }
                (Some("send"), Some(ip), Some(port)) => {
                    let ip = ip
                        .parse::<Ipv4Addr>()
                        .map_err(|_| fail("invalid address in send"))?;
                    let port = port
                        .parse::<u16>()
                        .map_err(|_| fail("invalid port in send"))?;
                    let src_port =
                        send_fresh(&mut held_senders, addr, SocketAddr::new(v4(ip), port))?;
                    say(&format!("sent {src_port}"));
                }
                _ => return Err(fail("unknown command")),
            }
        }
        Ok(())
    }

    // ---- 親（router / host。隔離 netns の中のテストプロセス）----

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

        /// 子に `listen` させる。
        fn listen(&mut self, port: u16) {
            self.send(&format!("listen {port}"));
            self.expect_prefix("listening");
        }

        /// 子から `dst` へ新しいソケットで送り、使った送信元ポートを返す。
        /// `used` は同一子の過去の送信元ポート。子の検査に加え router 側でも重複しないことを照合する。
        fn send_to(&mut self, dst: SocketAddrV4Pair, used: &mut Vec<u16>) -> u16 {
            self.send(&format!("send {} {}", dst.0, dst.1));
            let line = self.expect_prefix("sent ");
            let port = line
                .strip_prefix("sent ")
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or_else(|| panic!("unparsable sent line: {line:?}"));
            assert!(
                !used.contains(&port),
                "source port {port} reused (previous ports: {used:?}); conntrack entry would be reused"
            );
            used.push(port);
            port
        }

        /// 子の待受が受けた送信元を返す。
        fn recv(&mut self, port: u16) -> SocketAddr {
            self.send(&format!("recv {port}"));
            peer_addr(&self.expect_prefix("peer "))
        }
    }

    /// `send_to` の宛先（アドレス, ポート）。
    type SocketAddrV4Pair = (Ipv4Addr, u16);

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

    /// 受信側が見た `peer 10.x.y.z:port` を取り出す。
    fn peer_addr(line: &str) -> SocketAddr {
        line.strip_prefix("peer ")
            .and_then(|r| r.parse::<SocketAddr>().ok())
            .unwrap_or_else(|| panic!("unparsable peer line: {line:?}"))
    }

    /// router 側のデバイスを up にし、`addr` があれば /24 を付与する。
    fn configure_router_side(sock: &NetlinkRouteSocket, dev: &str, addr: Option<Ipv4Addr>) {
        sock.set_link(&LinkSet::up(LinkRef::Name(ifname(dev))), timeout())
            .expect("router link up");
        if let Some(addr) = addr {
            let idx = get_link_index(sock, dev).expect("router link index");
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
    }

    /// router（ホスト役）自身の待受が受けた送信元を返す（期限付き）。
    fn router_receives(sock: &UdpSocket) -> SocketAddr {
        recv_checked(sock).expect("router did not receive the datagram before deadline")
    }

    /// ホスト自身から `src` を bind して `dst` へ送る。使った送信元ポートが重複しないことも照合する。
    fn host_sends(held: &mut Vec<(u16, UdpSocket)>, src: Ipv4Addr, dst: SocketAddrV4Pair) -> u16 {
        send_fresh(held, src, SocketAddr::new(v4(dst.0), dst.1)).expect("host send")
    }

    fn data(b: &[u8]) -> NftDataValue {
        NftDataValue::new(b).expect("data")
    }

    /// DNAT ルールの expr 列。`ip daddr == HOST_OUTER && ip protocol == udp && udp dport == HOST_PORT`
    /// を照合し、`C1_ADDR:CONT_PORT` へ書き換える。output / prerouting の両 chain で同じものを使う。
    fn dnat_exprs() -> NftRuleExprs {
        let r1 = NftRegister::REG_1;
        let r2 = NftRegister::REG_2;
        let mut exprs = NftRuleExprs::new();
        let all = [
            NftPayload::ipv4_daddr(r1)
                .expect("daddr")
                .to_expr()
                .expect("expr"),
            NftCmp::eq(r1, data(&HOST_OUTER.octets()))
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
            NftImmediate::ipv4_addr(r1, C1_ADDR)
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

    /// masquerade ルールの expr 列。`ip daddr == EXTERNAL_ADDR` に限定し、bridge 内の通信を巻き込まない。
    fn masq_exprs() -> NftRuleExprs {
        let r1 = NftRegister::REG_1;
        let mut exprs = NftRuleExprs::new();
        let all = [
            NftPayload::ipv4_daddr(r1)
                .expect("daddr")
                .to_expr()
                .expect("expr"),
            NftCmp::eq(r1, data(&EXTERNAL_ADDR.octets()))
                .expect("cmp")
                .to_expr()
                .expect("expr"),
            NftMasq::new().to_expr().expect("masq expr"),
        ];
        for e in all {
            exprs.push(e).expect("push expr");
        }
        exprs
    }

    pub fn router() {
        ensure_launched_by_launcher().expect("refusing to run outside the launcher");
        ensure_isolated_netns().expect("refusing to run outside an isolated netns");
        // ip_forward は netns ごとの値のため、隔離 netns の中に限り host には影響しない。
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n").expect("enable ip_forward");

        let mut c1 = ChildGuard::spawn("c1");
        let mut c2 = ChildGuard::spawn("c2");
        let mut external = ChildGuard::spawn("external");
        c1.expect_prefix("ready");
        c2.expect_prefix("ready");
        external.expect_prefix("ready");

        let sock = NetlinkRouteSocket::open().expect("open netlink route socket");
        sock.create_link(&LinkCreate::bridge(ifname(BRIDGE)), timeout())
            .expect("create bridge");
        for (host_side, child_side) in [(PC1, CC1), (PC2, CC2), (PE, EX)] {
            sock.create_link(
                &LinkCreate::veth(ifname(host_side), ifname(child_side)).expect("veth"),
                timeout(),
            )
            .expect("create veth");
        }
        for (dev, child) in [(CC1, &c1), (CC2, &c2), (EX, &external)] {
            let pid = NetnsPid::new(child.pid()).expect("child pid");
            sock.set_link(
                &LinkSet::move_to_netns(LinkRef::Name(ifname(dev)), NetnsTarget::Pid(pid)),
                timeout(),
            )
            .expect("move veth by pid");
        }
        let bridge_idx = get_link_index(&sock, BRIDGE).expect("bridge index");
        for port in [PC1, PC2] {
            set_master(&sock, port, bridge_idx).expect("enslave veth to bridge");
        }
        configure_router_side(&sock, BRIDGE, Some(HOST_INNER));
        configure_router_side(&sock, PC1, None);
        configure_router_side(&sock, PC2, None);
        configure_router_side(&sock, PE, Some(HOST_OUTER));

        // bridge への接続を具体値で照合する（(a) が通ったことだけを接続の証拠にしない）。
        for port in [PC1, PC2] {
            assert_eq!(
                link_master(&sock, port).expect("link master"),
                Some(bridge_idx.get()),
                "{port} must be enslaved to {BRIDGE}"
            );
        }

        c1.send("go");
        c2.send("go");
        external.send("go");
        c1.expect_prefix("configured");
        c2.expect_prefix("configured");
        external.expect_prefix("configured");

        // 待受: c1 は (b) と DNAT 後の宛先、c2 は (a)、external は masq 確認、host は (c) 自己宛て。
        c1.listen(PORT_B);
        c1.listen(CONT_PORT);
        c2.listen(PORT_A);
        external.listen(PORT_M);
        let host_sock =
            UdpSocket::bind(SocketAddr::new(v4(HOST_OUTER), HOST_PORT)).expect("bind host udp");
        host_sock
            .set_read_timeout(Some(timeout()))
            .expect("host read timeout");

        let mut c1_ports = Vec::new();
        let mut ext_ports = Vec::new();
        let mut host_held: Vec<(u16, UdpSocket)> = Vec::new();
        let mut host_ports = Vec::new();
        let track = |p: u16, v: &mut Vec<u16>| {
            assert!(!v.contains(&p), "host source port {p} reused: {v:?}");
            v.push(p);
        };

        // 1. 投入前。
        // (a) c1 -> c2。
        let pa = c1.send_to((C2_ADDR, PORT_A), &mut c1_ports);
        let a = c2.recv(PORT_A);
        assert_eq!(a, SocketAddr::new(v4(C1_ADDR), pa), "path (a) before rules");
        // (b) ホスト -> c1（bridge アドレスから）。
        let pb = host_sends(&mut host_held, HOST_INNER, (C1_ADDR, PORT_B));
        track(pb, &mut host_ports);
        let b = c1.recv(PORT_B);
        assert_eq!(
            b,
            SocketAddr::new(v4(HOST_INNER), pb),
            "path (b) before rules"
        );
        // (c) 投入前: 外側アドレス宛ては DNAT されずホスト自身に届く。
        let pc0 = host_sends(&mut host_held, HOST_OUTER, (HOST_OUTER, HOST_PORT));
        track(pc0, &mut host_ports);
        let c_before = router_receives(&host_sock);
        assert_eq!(
            c_before,
            SocketAddr::new(v4(HOST_OUTER), pc0),
            "path (c) before dnat (host)"
        );
        // masq 投入前: c1 の送信元のまま external に届く。
        let pm0 = c1.send_to((EXTERNAL_ADDR, PORT_M), &mut c1_ports);
        let m_before = external.recv(PORT_M);
        assert_eq!(
            m_before,
            SocketAddr::new(v4(C1_ADDR), pm0),
            "before masquerade"
        );

        // 2. 1 バッチで table / 3 chain / 3 rule を投入する。
        let nft = NetlinkNetfilterSocket::open().expect("open NETLINK_NETFILTER");
        let table = nft_name("fandhe_paths_it");
        let guard = TableGuard {
            socket: nft,
            table: table.clone(),
        };
        let create_table = TableCreate::new(NftFamily::Ipv4, table.clone()).exclusive();
        let base = |name: &str, hook: NfInetHook, priority: i32| {
            ChainCreate::base(
                NftFamily::Ipv4,
                table.clone(),
                nft_name(name),
                BaseChain {
                    chain_type: ChainType::Nat,
                    hook,
                    priority,
                },
            )
            .expect("base chain")
        };
        let out_chain = base("output", NfInetHook::LocalOut, NF_IP_PRI_NAT_DST);
        let pre_chain = base("prerouting", NfInetHook::PreRouting, NF_IP_PRI_NAT_DST);
        let post_chain = base("postrouting", NfInetHook::PostRouting, NF_IP_PRI_NAT_SRC);
        let rule = |chain: &str, exprs: NftRuleExprs| {
            RuleCreate::new(NftFamily::Ipv4, table.clone(), nft_name(chain), exprs)
        };
        let out_rule = rule("output", dnat_exprs());
        let pre_rule = rule("prerouting", dnat_exprs());
        let post_rule = rule("postrouting", masq_exprs());
        let limit = timeout();
        let started = Instant::now();
        guard
            .socket
            .send_batch(limit, |b| {
                b.push_with(|seq| create_table.build(seq))?;
                b.push_with(|seq| out_chain.build(seq))?;
                b.push_with(|seq| pre_chain.build(seq))?;
                b.push_with(|seq| post_chain.build(seq))?;
                b.push_with(|seq| out_rule.build(seq))?;
                b.push_with(|seq| pre_rule.build(seq))?;
                b.push_with(|seq| post_rule.build(seq))?;
                Ok(())
            })
            .expect("install rules (needs nf_tables, nft_chain_nat, nft_nat, nft_masq, nf_nat)");
        assert!(started.elapsed() < limit, "batch exceeded {limit:?}");

        // 3. 投入後。
        // (c) 主: ホスト自身の外側アドレス宛てが OUTPUT の DNAT で c1 の CONT_PORT に届く。
        let pc1 = host_sends(&mut host_held, HOST_OUTER, (HOST_OUTER, HOST_PORT));
        track(pc1, &mut host_ports);
        let c_host = c1.recv(CONT_PORT);
        assert_eq!(
            c_host,
            SocketAddr::new(v4(HOST_OUTER), pc1),
            "path (c) after dnat (host output -> c1)"
        );
        // (c) 副: external 発の同じ宛先が PREROUTING の DNAT で c1 に届く（送信元は変換されない）。
        let pe = external.send_to((HOST_OUTER, HOST_PORT), &mut ext_ports);
        let c_external = c1.recv(CONT_PORT);
        assert_eq!(
            c_external,
            SocketAddr::new(v4(EXTERNAL_ADDR), pe),
            "path (c) after dnat (external prerouting -> c1)"
        );
        // masq: c1 -> external の送信元が外側アドレスへ変換される（ポート保存は保証されないため IP で照合）。
        let _pm1 = c1.send_to((EXTERNAL_ADDR, PORT_M), &mut c1_ports);
        let m_after = external.recv(PORT_M);
        assert_eq!(m_after.ip(), v4(HOST_OUTER), "after masquerade");

        // 4. 回帰: (a)・(b) は投入前と同じ送信元のまま（ルールの範囲指定が効いている証拠）。
        let pa2 = c1.send_to((C2_ADDR, PORT_A), &mut c1_ports);
        let a2 = c2.recv(PORT_A);
        assert_eq!(
            a2,
            SocketAddr::new(v4(C1_ADDR), pa2),
            "path (a) after rules"
        );
        let pb2 = host_sends(&mut host_held, HOST_INNER, (C1_ADDR, PORT_B));
        track(pb2, &mut host_ports);
        let b2 = c1.recv(PORT_B);
        assert_eq!(
            b2,
            SocketAddr::new(v4(HOST_INNER), pb2),
            "path (b) after rules"
        );

        drop(guard);
        println!(
            "{OK_PREFIX} a={a} b={b} c_host={c_host} c_external={c_external} masq={} (NET-11)",
            m_after.ip()
        );
    }
}
