//! 非特権の netns で `lo` の up 前後の自己宛て UDP 配送を照合する実機前提テスト
//! （NET-2・NET-11・REPAIR-5・REPAIR-7・REPAIR-12・TASK-140 追補・#2077・MS-8）。
//!
//! #1927 では、新しい netns の `lo` が down のままだと、自分の非ループバックアドレス宛ての UDP が
//! 届かず受信が期限切れになった。PR #2056 は root 前提の `nftables_paths_privileged` で `lo` を up にして
//! 直したが、実機では未検証（root での再実行は #319）。本試験はその場面を root なしで照合する。
//!
//! # 流れ
//! - 親（`-- --ignored`）: 自分自身を `unshare -rn <exe> --child` で再実行し、子の成功行と終了コードを期限付きで待つ。
//!   子が成功行を出して exit 0 のときだけ最終の成功行を出す。
//! - 子（親が環境変数で渡した親の netns 識別子と比べる。新しい user + network namespace の中）: ガード（親と別の netns・lo とフォールバックトンネルだけ・
//!   lo が down で `IFF_LOOPBACK`）を確かめた後、down の `lo` に `10.215.0.1/24` を付け、
//!   (1) 送信は成功するのに受信が `WouldBlock`（EAGAIN）で期限切れになること、
//!   (2) `lo` を up にすると `IFF_UP` が立ち、新しい送信ソケットの同じ内容が届き peer も一致することを具体値で照合する。
//!
//! # アドレスの選び方（カーネル経路の推定）
//! `127.0.0.1` は `lo` の `NETDEV_UP` で初めて付く（`net/ipv4/devinet.c` の `inetdev_event`）ため、down の間は
//! bind が `EADDRNOTAVAIL` になり #1927 の場面を作れない。そこで down のまま `lo` に付けた `10.215.0.1` を使う。
//! `fib_add_ifaddr`（`net/ipv4/fib_frontend.c`）は `IFF_UP` の確認より前に `RTN_LOCAL` の経路を入れるため bind と
//! 経路解決は通り、`ip_route_output_key_hash_rcu`（`net/ipv4/route.c`）は `RTN_LOCAL` を `loopback_dev` から出す。
//! down の `lo` の qdisc は noop で破棄されるが、`net_xmit_errno` が `NET_XMIT_CN` を 0 に読み替えるため送信は成功する。
//! この経路は PR #2056 の推定であり、本試験を CI で走らせた結果が実測になる。外れた場合は出た具体値へ assert を直す
//! （「何かしらのエラー」へ緩めない）。
//!
//! `harness = false` の独自 `main` のため、`--ignored` が渡らなくても exit 0 で終わる。CI は成功行を
//! 完全一致で照合して false-green を防ぐ（`.github/workflows/ci.yml` の `platform-ci`）。待ちはすべて
//! `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。root は不要で、非特権 user namespace
//! （AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` がない環境）と util-linux の `unshare` が要る。
//! 前提を満たさない場合は skip せず失敗する。Linux のみ。実行方法は AGENTS.md「実機前提テスト」節を参照。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("lo_self_delivery: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--child") {
        linux::child();
    } else if args.iter().any(|a| a == "--ignored") {
        linux::parent();
    } else {
        println!(
            "lo_self_delivery: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead as _, BufReader};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_net::netlink_route::{
        AddrScope, AddressSpec, IFF_UP, IfIndex, IpPrefix, LinkIndex, LinkRef, LinkSet,
        NLM_F_MATCH, NLM_F_ROOT, NetlinkRouteSocket, RTM_GETLINK, RTM_NEWLINK,
    };

    /// 子が検証を終えたときに出す行（親が完全一致で受け取る）。
    const CHILD_OK_LINE: &str =
        "lo_self_delivery: child verified down=WouldBlock(errno=11) up=IFF_UP delivered";
    /// `linux/if.h` の `IFF_LOOPBACK`。
    const IFF_LOOPBACK: u32 = 0x8;
    /// Linux の `EAGAIN`（`EWOULDBLOCK` と同値。x86_64・aarch64 共通）。
    const EAGAIN: i32 = 11;
    /// 親が子へ自分の netns 識別子（`net:[inode]`）を渡す環境変数名。
    const PARENT_NETNS_ENV: &str = "FANDHE_LO_SELF_DELIVERY_PARENT_NETNS";
    const PAYLOAD: &[u8] = b"fandhe-lo-self-delivery";
    /// 他の試験（10.200〜10.214）と衝突しない、隔離 netns 内だけで使う試験用アドレス。
    const TEST_ADDR: Ipv4Addr = Ipv4Addr::new(10, 215, 0, 1);
    /// 新規 netns にカーネルが自動生成するフォールバックトンネルデバイス名（`link_netns_privileged` と同じ集合）。
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

    /// 親: 実効 uid が 0 かを `/proc/self/status` の `Uid:` 行から読む（libc を使わない）。
    fn is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("Uid:"))
                    .and_then(|r| r.split_whitespace().nth(1).map(str::to_owned))
            })
            .is_some_and(|euid| euid == "0")
    }

    fn fail(msg: &str) -> ! {
        eprintln!("lo_self_delivery: FAILED: {msg}");
        std::process::exit(1);
    }

    /// 親: `unshare -rn <自分> --child` を起動し、期限付きで成功行と終了コードを確かめる。
    pub fn parent() {
        let root = is_root();
        // 親の netns の識別子は親自身が読んで子へ渡す（子は新しい user namespace の中で、親の
        // `/proc/<pid>/ns/net` を ptrace 権限不足で読めないため。CI の EACCES の原因）。
        let parent_netns = std::fs::read_link("/proc/self/ns/net")
            .unwrap_or_else(|e| fail(&format!("read own netns: {e}")));
        let exe = std::env::current_exe().unwrap_or_else(|e| fail(&format!("current_exe: {e}")));
        let mut child = Command::new("unshare")
            .arg("-rn")
            .arg(&exe)
            .arg("--child")
            .env(PARENT_NETNS_ENV, &parent_netns)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| {
                fail(&format!(
                    "cannot spawn `unshare -rn` (util-linux missing or not permitted): {e}"
                ))
            });
        let stdout = child
            .stdout
            .take()
            .unwrap_or_else(|| fail("child stdout was not piped"));
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                println!("{line}");
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        // 子の全体期限。内訳は down の待ち・up 後の待ち・短い追加待ちで、各待ち以内に収まるはずの 3 倍を許す。
        let deadline = Instant::now() + timeout() * 3;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(None) => {
                    // kill の失敗は握りつぶさず、回収も別の有限期限までの try_wait で確認する（REPAIR-5）。
                    let kill_result = child.kill();
                    let reap_deadline = Instant::now() + Duration::from_secs(10);
                    let reaped = loop {
                        match child.try_wait() {
                            Ok(Some(_)) => break true,
                            Ok(None) if Instant::now() < reap_deadline => {
                                std::thread::sleep(Duration::from_millis(50));
                            }
                            Ok(None) | Err(_) => break false,
                        }
                    };
                    match (kill_result, reaped) {
                        (Ok(()), true) => fail("child did not finish within the deadline (killed)"),
                        (Ok(()), false) => fail(
                            "child did not finish within the deadline and was not reaped after kill",
                        ),
                        (Err(e), _) => fail(&format!(
                            "child did not finish within the deadline and kill failed: {e}"
                        )),
                    }
                }
                Err(e) => fail(&format!("try_wait: {e}")),
            }
        };
        if !status.success() {
            fail(&format!("child exited with {status}"));
        }
        // 子の終了後は書き込み側が閉じているため、残りの行を即座に回収できる。
        let mut ok = false;
        while let Ok(line) = rx.recv_timeout(Duration::from_secs(2)) {
            if line == CHILD_OK_LINE {
                ok = true;
            }
        }
        if !ok {
            fail("child exited 0 but did not report its success line");
        }
        println!("lo_self_delivery: lo down timed out and lo up delivered (root={root})");
    }

    /// 子: 新しい user + network namespace の中で照合する。失敗は非ゼロ終了。
    pub fn child() {
        let t = timeout();
        let sock = NetlinkRouteSocket::open().unwrap_or_else(|e| fail(&format!("netlink: {e}")));

        // ガード (a): 親と別の netns でなければ何も変えずに拒否する（host の netns を変えない）。
        let own = std::fs::read_link("/proc/self/ns/net")
            .unwrap_or_else(|e| fail(&format!("read own netns: {e}")));
        let parent = std::env::var_os(PARENT_NETNS_ENV).unwrap_or_else(|| {
            fail("refusing to run: parent netns identity was not passed (run via the parent)")
        });
        if own.as_os_str() == parent.as_os_str() {
            fail("refusing to run: same network namespace as the parent");
        }

        // ガード (b): lo とフォールバックトンネルだけの新規 netns であること。
        let dev = std::fs::read_to_string("/proc/net/dev")
            .unwrap_or_else(|e| fail(&format!("read /proc/net/dev: {e}")));
        let foreign: Vec<&str> = dev
            .lines()
            .skip(2)
            .filter_map(|l| l.split(':').next().map(str::trim))
            .filter(|n| !n.is_empty() && *n != "lo" && !FALLBACK_TUNNEL_DEVICES.contains(n))
            .collect();
        if !foreign.is_empty() {
            fail(&format!("netns is not fresh (interfaces: {foreign:?})"));
        }

        // ガード (c): lo（ifindex 1）が down で IFF_LOOPBACK であること。
        let flags_before = lo_flags(&sock, t);
        eprintln!("lo_self_delivery: lo flags before up = {flags_before:#x}");
        assert_eq!(flags_before & IFF_UP, 0, "lo must start down");
        assert_eq!(
            flags_before & IFF_LOOPBACK,
            IFF_LOOPBACK,
            "lo must be loopback"
        );

        // down のまま lo に試験用アドレスを付ける（モジュール doc の推定を参照）。
        let lo = IfIndex::new(1).unwrap_or_else(|e| fail(&format!("ifindex: {e}")));
        let spec = AddressSpec::new(
            lo,
            IpPrefix::new(IpAddr::V4(TEST_ADDR), 24).unwrap_or_else(|e| fail(&format!("{e}"))),
            AddrScope::Universe,
        );
        sock.add_address(&spec, t)
            .unwrap_or_else(|e| fail(&format!("add address on down lo: {e}")));

        let rx = UdpSocket::bind((TEST_ADDR, 0)).unwrap_or_else(|e| fail(&format!("bind rx: {e}")));
        let rx_addr = rx
            .local_addr()
            .unwrap_or_else(|e| fail(&format!("rx addr: {e}")));

        // (1) down: 送信は成功し、受信は EAGAIN（WouldBlock）で期限切れになる。
        let tx1 =
            UdpSocket::bind((TEST_ADDR, 0)).unwrap_or_else(|e| fail(&format!("bind tx1: {e}")));
        let sent = tx1
            .send_to(PAYLOAD, rx_addr)
            .unwrap_or_else(|e| fail(&format!("send on down lo must succeed (hypothesis): {e}")));
        assert_eq!(sent, PAYLOAD.len());
        let down_wait = t.min(Duration::from_secs(2));
        rx.set_read_timeout(Some(down_wait))
            .unwrap_or_else(|e| fail(&format!("set_read_timeout: {e}")));
        let mut buf = [0u8; 128];
        let err = rx
            .recv_from(&mut buf)
            .expect_err("datagram must not arrive while lo is down");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(err.raw_os_error(), Some(EAGAIN));

        // (2) up: IFF_UP が立ち、新しい送信ソケットの同じ内容が届く。
        let lo_idx = LinkIndex::new(1).unwrap_or_else(|e| fail(&format!("link index: {e}")));
        sock.set_link(&LinkSet::up(LinkRef::Index(lo_idx)), t)
            .unwrap_or_else(|e| fail(&format!("lo up: {e}")));
        let flags_after = lo_flags(&sock, t);
        eprintln!("lo_self_delivery: lo flags after up = {flags_after:#x}");
        assert_eq!(IFF_UP, 0x1);
        assert_eq!(flags_after & IFF_UP, IFF_UP);

        // 新しい送信ソケット（キャッシュされた dst を再利用しない）。
        let tx2 =
            UdpSocket::bind((TEST_ADDR, 0)).unwrap_or_else(|e| fail(&format!("bind tx2: {e}")));
        let tx2_addr = tx2
            .local_addr()
            .unwrap_or_else(|e| fail(&format!("tx2 addr: {e}")));
        let sent = tx2
            .send_to(PAYLOAD, rx_addr)
            .unwrap_or_else(|e| fail(&format!("send on up lo: {e}")));
        assert_eq!(sent, PAYLOAD.len());
        rx.set_read_timeout(Some(t))
            .unwrap_or_else(|e| fail(&format!("set_read_timeout: {e}")));
        let (n, peer) = rx
            .recv_from(&mut buf)
            .unwrap_or_else(|e| fail(&format!("datagram did not arrive after lo up: {e}")));
        assert_eq!(buf.get(..n), Some(PAYLOAD));
        assert_eq!(
            peer,
            SocketAddr::new(IpAddr::V4(TEST_ADDR), tx2_addr.port())
        );

        // (3) down の間に送った 1 通目が遅れて届いたのではなく、破棄されていたこと。
        rx.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap_or_else(|e| fail(&format!("set_read_timeout: {e}")));
        let err = rx
            .recv_from(&mut buf)
            .expect_err("the datagram sent while down must have been dropped");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);

        println!("{CHILD_OK_LINE}");
    }

    /// `RTM_GETLINK` の dump から ifindex 1（lo）の `ifi_flags` を読む。見つからなければ失敗する。
    fn lo_flags(sock: &NetlinkRouteSocket, t: Duration) -> u32 {
        let reply = sock
            .request(RTM_GETLINK, NLM_F_ROOT | NLM_F_MATCH, t, |b| {
                b.put_fixed(&[0u8; 16])
            })
            .unwrap_or_else(|e| fail(&format!("RTM_GETLINK dump: {e}")));
        for m in reply
            .messages()
            .iter()
            .filter(|m| m.msg_type() == RTM_NEWLINK)
        {
            // ifinfomsg: family(1) pad(1) type(2) index(4) flags(4) change(4)
            let index = m
                .payload()
                .get(4..8)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_ne_bytes);
            let flags = m
                .payload()
                .get(8..12)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_ne_bytes);
            if index == Some(1) {
                return flags.unwrap_or_else(|| fail("malformed RTM_NEWLINK payload"));
            }
        }
        fail("lo (ifindex 1) not found in RTM_GETLINK dump")
    }
}
