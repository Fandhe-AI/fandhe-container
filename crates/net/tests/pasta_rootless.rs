//! 実際の pasta を本番の API（`verify_pasta_binary`・`PastaRunDir::prepare`・`PastaPortForwards`・`spawn_pasta`・
//! `PastaProcess::stop`）と netns holder に通す実機前提の結合試験（NET-9・SEC-5・CORE-6・REPAIR-5・REPAIR-12・
//! NET-6・ERR-1・#1941。`docs/design/rootless-network.md` 12.11 の #1941 担当の行。TASK-147 追補）。
//!
//! 実機での実行と結果の記録は人間の担当（#341）。CI のランナーには pasta が無いため CI では実行しない。
//!
//! # 必要な環境
//! - Linux。pasta（Ubuntu / Debian は `passt` パッケージ。#340 の確認版は `0.0~git20260120.386b5f5-1`、カーネル 7.0.0-34）。
//!   既定の場所は `/usr/bin/pasta`、変えるときは `FANDHE_CONTAINER_TEST_PASTA=<絶対パス>`
//! - 非特権 user namespace（`unshare --user --map-root-user --net` が通ること）と util-linux の `unshare`。
//!   `kernel.apparmor_restrict_unprivileged_userns=1` の環境では対象を作れず、場面 S0 が理由つきで失敗する。
//!   これを「restrict=1 のままでの後付けは、この環境では確かめられない」の記録とする
//! - `$XDG_RUNTIME_DIR`（所有者が実行ユーザーのディレクトリ。状態ルートをその下に一時作成して終了時に消す）
//! - root は不要（euid 0 なら失敗する）
//!
//! # 実行
//! `cargo test -p fandhe-container-net --test pasta_rootless -- --ignored`。期限は
//! `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（1〜600、既定 10 秒。REPAIR-5）。`--ignored` が無ければ ignored の行を出して
//! exit 0 になる実機前提テストの分離であり、CI 通過のための弱体化ではない。前提が欠けても skip にせず非 0 で終わる。
//!
//! sysctl を緩めて実行する場合の手順（root のコマンド。人間が実行する。Agent は実行しない）:
//! `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` → 本試験 → 値を `1` に戻す。
//!
//! # 場面（12.11 の行との対応）
//! - S0 前提・AppArmor の制限値の観測・対象の作成可否
//! - S1 #340 の形（unshare の子を対象）: `lo` + `eth0`・IPv4 既定経路・IPv6 既定経路なし・`stop` が Term
//! - S2 本番の形（holder を対象）: ポート公開は loopback のみ・`-u none`・`-T none -U none`・
//!   `--map-host-loopback none`・DNS 転送・`argv[0]`・実行ファイル・停止と回収。`passt` 名のリンクも S1 の形で確認
//! - S3 同じプロトコルの `-t` を複数回渡したときの累積　S4 公開 0 件ではホスト側のポートが開かない
//! - S5 明示した `-t` の bind 競合（二者択一の観測。どちらになるかを決めつけない）
//! - S6 対象が消えた直後の `stop`　S7 netns-quit の観測　S8 PDEATHSIG（中間の supervisor を SIGKILL）
//! - S9 AppArmor が enforce のとき許可外の置き場所が拒否されるか（条件つき観測）
//! - S10 準備完了の前に pasta が死んだときのエラー　S11 `-P` の PID ファイルの書き込みの時点（観測）
//!
//! S6・S7 は対象（unshare の子）も SIGKILL し、netns の最後の保持者が消えた状態にする。観測は `/proc` から行い
//! （`ip`・`ss`・`nsenter` に依存しない）、手で確かめるときの同等のコマンドは `ss -ltnup`、`pgrep -P <pid> -x pasta`。
//! `/proc/<pasta>/fd` が読めなければ起動前後の差分に切り替えて `pasta_fd_visible=no` を出す。
//!
//! 実機の挙動が想定と違う場合はアサーションを緩めず、具体値つきで失敗して表に出す（修正は #341 の実測の後）。
//! pasta が x86_64 で `pasta.avx2` へ再 exec する場合に備え、comm と exe は接頭辞 `pasta` で照合する。
//! 出力にホスト名・IP アドレス・ユーザー名・パスは出さない。成功行は
//! `pasta_rootless: real pasta attached to the target and the holder, published loopback only and was reaped (NET-9)`。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("pasta_rootless: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os();
    let _exe = args.next();
    match args.next() {
        Some(a) if a == fandhe_container_net::netns_holder::NETNS_HOLDER_SUBCOMMAND => {
            fandhe_container_net::netns_holder::run_netns_holder_main(args)
        }
        Some(a) if a == "--inner" => linux::inner(args),
        Some(a) if a == "--fake-supervisor" => linux::fake_supervisor(args),
        Some(a) if a == "--ignored" => linux::run(),
        _ => {
            println!(
                "pasta_rootless: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
            );
            std::process::ExitCode::SUCCESS
        }
    }
}

#[cfg(target_os = "linux")]
#[path = "support/reap.rs"]
mod reap;

#[cfg(target_os = "linux")]
mod linux {
    use super::reap;
    use std::collections::HashSet;
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::{BufRead as _, Read as _, Write as _};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, ExitCode, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_net::error::NetErrorCode;
    use fandhe_container_net::netns_holder::{
        NetnsHolderChannel, NetnsHolderFds, NsIdentity, READY_TIMEOUT,
    };
    use fandhe_container_net::network::PortProtocol;
    use fandhe_container_net::pasta::binary::{PastaBinary, verify_pasta_binary};
    use fandhe_container_net::pasta::port_forward::{PastaPortForward, PastaPortForwards};
    use fandhe_container_net::pasta::process::{
        MSG_PASTA_EXITED_EARLY, PASTA_READY_TIMEOUT_DEFAULT, PASTA_REAP_TIMEOUT, PASTA_STOP_GRACE,
        PastaProcess, PastaSpawnError, PastaStage, PastaStopPath, PastaTarget, pasta_argv,
        spawn_pasta,
    };
    use fandhe_container_net::pasta::run_dir::{PastaRunDir, remove_pasta_run_dir};

    const OK_LINE: &str = "pasta_rootless: real pasta attached to the target and the holder, published loopback only and was reaped (NET-9)";
    const DNS_ADDR: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 1);

    fn limit() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn check(cond: bool, msg: impl FnOnce() -> String) -> Result<(), String> {
        if cond { Ok(()) } else { Err(msg()) }
    }

    fn obs(key: &str, value: &str) {
        println!("pasta_rootless: observation {key}={value}");
    }

    fn ns_identity(path: &str) -> Result<(u64, u64), String> {
        let m = std::fs::metadata(path).map_err(|e| format!("stat {path}: {e}"))?;
        Ok((m.dev(), m.ino()))
    }

    /// 期限まで 10 ms 刻みで `f` を評価し、`Ok(v)` が返ったらその値を返す。期限切れは最後の観測を添えて失敗にする。
    fn wait_for<T>(
        what: &str,
        mut f: impl FnMut() -> Result<Result<T, String>, String>,
    ) -> Result<T, String> {
        let until = Instant::now() + limit();
        loop {
            match f()? {
                Ok(v) => return Ok(v),
                Err(last) => {
                    if Instant::now() >= until {
                        return Err(format!("{what}: not satisfied in time (last: {last})"));
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    // ---------------------------------------------------------------- /proc の純関数

    fn hex_ip(ip: Ipv4Addr) -> String {
        format!("{:08X}", u32::from_le_bytes(ip.octets()))
    }

    fn parse_ip_hex(h: &str) -> Option<Ipv4Addr> {
        u32::from_str_radix(h, 16)
            .ok()
            .map(|v| Ipv4Addr::from(v.to_le_bytes()))
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Sock {
        addr: String,
        port: u16,
        state: String,
        inode: u64,
    }

    /// `/proc/net/{tcp,udp}` の表。添字アクセスは使わず、読めない行は捨てる。
    fn parse_net_table(text: &str) -> Vec<Sock> {
        text.lines()
            .skip(1)
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                let (a, p) = f.get(1)?.split_once(':')?;
                Some(Sock {
                    addr: a.to_string(),
                    port: u16::from_str_radix(p, 16).ok()?,
                    state: (*f.get(3)?).to_string(),
                    inode: f.get(9)?.parse().ok()?,
                })
            })
            .collect()
    }

    /// 新規 netns にカーネルが自動生成するフォールバックトンネルデバイス名（`lo_self_delivery` と同じ集合）。
    /// pasta の有無とは無関係に現れるため、インターフェース一覧の照合では無視する。
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

    fn parse_ifaces(dev: &str) -> Vec<String> {
        let mut v: Vec<String> = dev
            .lines()
            .skip(2)
            .filter_map(|l| l.split_once(':').map(|(n, _)| n.trim().to_string()))
            .filter(|n| !FALLBACK_TUNNEL_DEVICES.contains(&n.as_str()))
            .collect();
        v.sort();
        v
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RouteRow {
        iface: String,
        dest: String,
        gateway: String,
        flags: u32,
    }

    fn parse_route(text: &str) -> Vec<RouteRow> {
        text.lines()
            .skip(1)
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                Some(RouteRow {
                    iface: (*f.first()?).to_string(),
                    dest: (*f.get(1)?).to_string(),
                    gateway: (*f.get(2)?).to_string(),
                    flags: u32::from_str_radix(f.get(3)?, 16).ok()?,
                })
            })
            .collect()
    }

    /// `/proc/net/ipv6_route` に実効のある既定経路（`::/0`）の行があるか。
    /// カーネルが `lo` に持つ拒否用の `::/0`（flags `00200200`。`RTF_REJECT` を含む）は既定経路に数えない。
    fn has_v6_default(text: &str) -> bool {
        /// `RTF_REJECT`。
        const RTF_REJECT: u32 = 0x0200;
        text.lines().any(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let is_zero_dest = f
                .first()
                .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b == b'0'))
                && f.get(1) == Some(&"00");
            let flags = f.get(8).and_then(|v| u32::from_str_radix(v, 16).ok());
            let iface = f.get(9).copied();
            is_zero_dest && flags.is_some_and(|v| v & RTF_REJECT == 0) && iface != Some("lo")
        })
    }

    fn self_check() -> Result<(), String> {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0 100 0 0 10 0\n";
        let want = Sock {
            addr: "0100007F".into(),
            port: 8080,
            state: "0A".into(),
            inode: 4242,
        };
        check(parse_net_table(tcp) == [want], || {
            "self-check: tcp table".into()
        })?;
        check(hex_ip(Ipv4Addr::LOCALHOST) == "0100007F", || {
            "self-check: hex_ip".into()
        })?;
        check(
            parse_ip_hex("0100A8C0") == Some(Ipv4Addr::new(192, 168, 0, 1)),
            || "self-check: parse_ip_hex".into(),
        )?;
        check(
            parse_ifaces("Inter-|\n face |\n    lo: 1\n  eth0: 2\n") == ["eth0", "lo"],
            || "self-check: ifaces".into(),
        )?;
        let route = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\neth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        check(
            parse_route(route)
                .first()
                .map(|r| (r.flags, r.dest.as_str()))
                == Some((3, "00000000")),
            || "self-check: route".into(),
        )?;
        let z = "0".repeat(32);
        let v6 = format!("{z} 00 {z} 00 {z} 00000400 00000001 00000000 00000003 eth0\n");
        check(has_v6_default(&v6), || "self-check: v6 default".into())?;
        // カーネル内部の拒否用経路（実機の行形式）は既定経路ではない。
        let v6_reject = format!("{z} 00 {z} 00 {z} ffffffff 00000001 00000001 00200200 lo\n");
        check(!has_v6_default(&v6_reject), || {
            "self-check: v6 reject route".into()
        })?;
        check(
            parse_ifaces("Inter-|\n face |\n    lo: 1\n  sit0: 2\n ip6tnl0: 3\n") == ["lo"],
            || "self-check: fallback tunnels ignored".into(),
        )?;
        check(
            !has_v6_default("ff000000000000000000000000000000 08 x\n"),
            || "self-check: v6 non-default".into(),
        )
    }

    // ---------------------------------------------------------------- ホスト側の観測

    #[derive(Default, Clone)]
    struct HostSnap {
        tcp: HashSet<(String, u16)>,
        udp: HashSet<(String, u16)>,
    }

    fn read_table(path: &str) -> Result<Vec<Sock>, String> {
        let s = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        Ok(parse_net_table(&s))
    }

    fn host_snapshot() -> Result<HostSnap, String> {
        let tcp = read_table("/proc/self/net/tcp")?
            .into_iter()
            .filter(|s| s.state == "0A")
            .map(|s| (s.addr, s.port))
            .collect();
        let udp = read_table("/proc/self/net/udp")?
            .into_iter()
            .map(|s| (s.addr, s.port))
            .collect();
        Ok(HostSnap { tcp, udp })
    }

    struct PastaSocks {
        tcp: Vec<(String, u16)>,
        udp: Vec<(String, u16)>,
        fd_visible: bool,
    }

    /// pasta のホスト側ソケット。`/proc/<pasta>/fd` が読めればその inode で、読めなければ起動前の `base` との
    /// 差分（`watch` のポート番号に限る）で求める。
    fn pasta_sockets(pid: u32, base: &HostSnap, watch: &[u16]) -> Result<PastaSocks, String> {
        let inodes: Option<HashSet<u64>> =
            std::fs::read_dir(format!("/proc/{pid}/fd")).ok().map(|d| {
                d.filter_map(|e| {
                    let l = std::fs::read_link(e.ok()?.path()).ok()?;
                    let s = l.to_str()?;
                    s.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
                })
                .collect()
            });
        let tcp_all = read_table("/proc/self/net/tcp")?;
        let udp_all = read_table("/proc/self/net/udp")?;
        let (mut tcp, mut udp): (Vec<_>, Vec<_>) = match &inodes {
            Some(set) => (
                tcp_all
                    .into_iter()
                    .filter(|s| s.state == "0A" && set.contains(&s.inode))
                    .map(|s| (s.addr, s.port))
                    .collect(),
                udp_all
                    .into_iter()
                    .filter(|s| set.contains(&s.inode))
                    .map(|s| (s.addr, s.port))
                    .collect(),
            ),
            None => (
                tcp_all
                    .into_iter()
                    .filter(|s| s.state == "0A")
                    .map(|s| (s.addr, s.port))
                    .filter(|k| watch.contains(&k.1) && !base.tcp.contains(k))
                    .collect(),
                udp_all
                    .into_iter()
                    .map(|s| (s.addr, s.port))
                    .filter(|k| watch.contains(&k.1) && !base.udp.contains(k))
                    .collect(),
            ),
        };
        tcp.sort();
        udp.sort();
        Ok(PastaSocks {
            tcp,
            udp,
            fd_visible: inodes.is_some(),
        })
    }

    /// pasta の TCP LISTEN が `expected` と一致するまで待ち、少し置いて同じであることを再確認する。
    /// `/proc/<pasta>/fd` が見えたかを返す。
    fn expect_tcp_listeners(
        pid: u32,
        base: &HostSnap,
        watch: &[u16],
        mut expected: Vec<(String, u16)>,
    ) -> Result<bool, String> {
        expected.sort();
        let socks = wait_for("pasta tcp listeners", || {
            let s = pasta_sockets(pid, base, watch)?;
            if s.tcp == expected {
                Ok(Ok(s))
            } else {
                Ok(Err(format!("{:?}", s.tcp)))
            }
        })?;
        std::thread::sleep(Duration::from_millis(300));
        let again = pasta_sockets(pid, base, watch)?;
        check(again.tcp == expected, || {
            format!(
                "pasta tcp listeners changed: {:?}, want {expected:?}",
                again.tcp
            )
        })?;
        check(again.udp.iter().all(|u| !watch.contains(&u.1)), || {
            format!("pasta udp sockets on published ports: {:?}", again.udp)
        })?;
        Ok(socks.fd_visible)
    }

    fn free_ports(n: usize) -> Result<Vec<u16>, String> {
        let mut v: Vec<u16> = Vec::new();
        let until = Instant::now() + limit();
        while v.len() < n {
            let l = TcpListener::bind("0.0.0.0:0").map_err(|e| format!("bind probe: {e}"))?;
            let p = l.local_addr().map_err(|e| e.to_string())?.port();
            drop(l);
            let ok = !v.contains(&p)
                && TcpListener::bind(("127.0.0.1", p)).is_ok()
                && TcpListener::bind(("127.0.0.2", p)).is_ok()
                && UdpSocket::bind(("0.0.0.0", p)).is_ok();
            if ok {
                v.push(p);
            } else if Instant::now() >= until {
                return Err("could not find free ports in time".into());
            }
        }
        Ok(v)
    }

    fn non_loopback_addr() -> Result<Ipv4Addr, String> {
        let s = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        s.connect("192.0.2.1:9")
            .map_err(|e| format!("no route to pick a non-loopback host address: {e}"))?;
        match s.local_addr().map_err(|e| e.to_string())?.ip() {
            std::net::IpAddr::V4(a) if !a.is_loopback() && !a.is_unspecified() => Ok(a),
            _ => Err("no non-loopback IPv4 host address".into()),
        }
    }

    /// 自分の子で comm が `pasta` で始まるプロセス。
    fn pasta_children() -> Result<Vec<u32>, String> {
        let me = std::process::id();
        let mut out = Vec::new();
        for e in std::fs::read_dir("/proc").map_err(|e| format!("read /proc: {e}"))? {
            let Some(pid) = e
                .ok()
                .and_then(|e| e.file_name().into_string().ok())
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else {
                continue;
            };
            let comm = stat.get(open + 1..close).unwrap_or("");
            let mut rest = stat.get(close + 1..).unwrap_or("").split_whitespace();
            let ppid = rest.nth(1).and_then(|v| v.parse::<u32>().ok());
            if ppid == Some(me) && comm.starts_with("pasta") {
                out.push(pid);
            }
        }
        Ok(out)
    }

    fn expect_no_pasta_children() -> Result<(), String> {
        let c = pasta_children()?;
        check(c.is_empty(), || format!("pasta children remain: {c:?}"))
    }

    /// `/proc/<pid>/stat` の状態と starttime（最後の `)` の後ろを読む）。
    fn stat_fields(pid: u32) -> Option<(char, u64)> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after = stat.get(stat.rfind(')')? + 1..)?;
        let mut it = after.split_whitespace();
        let state = it.next()?.chars().next()?;
        let start = it.nth(18)?.parse().ok()?;
        Some((state, start))
    }

    // ---------------------------------------------------------------- 対象プロセス（unshare の中）

    /// `unshare` の中で動く対象。コンテナ側のポートで待ち受け、標準入力の命令に 1 行で答える（命令は試験自身が組む）。
    pub fn inner(args: impl Iterator<Item = OsString>) -> ExitCode {
        let mut listeners = Vec::new();
        for a in args {
            let port = a.to_str().and_then(|s| s.parse::<u16>().ok());
            let l = port.and_then(|p| TcpListener::bind(("0.0.0.0", p)).ok());
            match l {
                Some(l) if l.set_nonblocking(true).is_ok() => listeners.push(l),
                _ => {
                    println!("ERR bind");
                    let _ = std::io::stdout().flush();
                    return ExitCode::from(1);
                }
            }
        }
        println!("READY");
        // パイプ越しの親が行を読めるよう、行ごとに flush する（ブロックバッファのまま待たせない）。
        let _ = std::io::stdout().flush();
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            let mut it = line.split_whitespace();
            let reply = match it.next() {
                Some("ACCEPT") => {
                    let l = it
                        .next()
                        .and_then(|v| v.parse::<usize>().ok())
                        .and_then(|i| listeners.get(i));
                    inner_accept(l)
                }
                Some("CONNECT") => {
                    let ip = it.next().and_then(|v| v.parse::<Ipv4Addr>().ok());
                    let port = it.next().and_then(|v| v.parse::<u16>().ok());
                    match (ip, port) {
                        (Some(ip), Some(port)) => inner_connect(SocketAddr::from((ip, port))),
                        _ => "ERR args".into(),
                    }
                }
                Some("DNS") => inner_dns(),
                Some("EXIT") => break,
                _ => "ERR unknown".into(),
            };
            println!("{reply}");
            let _ = std::io::stdout().flush();
        }
        ExitCode::SUCCESS
    }

    fn inner_accept(l: Option<&TcpListener>) -> String {
        let Some(l) = l else {
            return "ERR index".into();
        };
        let until = Instant::now() + limit();
        loop {
            match l.accept() {
                Ok((mut s, _)) => {
                    return match s.write_all(b"K") {
                        Ok(()) => "OK".into(),
                        Err(_) => "ERR write".into(),
                    };
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return "ERR accept".into(),
            }
            if Instant::now() >= until {
                return "TIMEOUT".into();
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn inner_connect(addr: SocketAddr) -> String {
        let t = limit().min(Duration::from_secs(3));
        match TcpStream::connect_timeout(&addr, t) {
            Ok(_) => "CONNECTED".into(),
            Err(e) => match e.kind() {
                std::io::ErrorKind::ConnectionRefused => "REFUSED".into(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "TIMEOUT".into(),
                _ => "ERR".into(),
            },
        }
    }

    /// `169.254.1.1:53` への A 問い合わせ（名前は固定）。応答の ID と送信元を確かめ、rcode を返す。
    fn inner_dns() -> String {
        const ID: u16 = 0x1941;
        let mut q = Vec::new();
        q.extend_from_slice(&ID.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        q.push(9);
        q.extend_from_slice(b"localhost");
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        let Ok(s) = UdpSocket::bind("0.0.0.0:0") else {
            return "ERR bind".into();
        };
        let target = SocketAddr::from((DNS_ADDR, 53));
        if s.set_read_timeout(Some(limit())).is_err() || s.send_to(&q, target).is_err() {
            return "ERR send".into();
        }
        let mut buf = [0u8; 512];
        match s.recv_from(&mut buf) {
            Ok((n, from)) if from == target && n >= 12 => {
                let b = |i: usize| buf.get(i).copied().unwrap_or(0);
                let id = u16::from_be_bytes([b(0), b(1)]);
                let flags = u16::from_be_bytes([b(2), b(3)]);
                if id == ID && flags & 0x8000 != 0 {
                    format!("DNS {}", flags & 0xF)
                } else {
                    "DNS BAD".into()
                }
            }
            Ok(_) => "DNS BAD".into(),
            Err(_) => "DNS TIMEOUT".into(),
        }
    }

    struct Target {
        child: Child,
        stdin: Option<ChildStdin>,
        lines: mpsc::Receiver<String>,
        pid: u32,
    }

    impl Target {
        fn spawn(ctr_ports: &[u16]) -> Result<Target, String> {
            let own_user = ns_identity("/proc/self/ns/user")?;
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let mut cmd = Command::new("unshare");
            cmd.args(["--user", "--map-root-user", "--net"])
                .arg(exe)
                .arg("--inner");
            for p in ctr_ports {
                cmd.arg(p.to_string());
            }
            let mut child = cmd
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| format!("cannot spawn `unshare`: {e}"))?;
            let pid = child.id();
            let stdin = child.stdin.take();
            let out = child.stdout.take().ok_or("stdout")?;
            let (tx, rx) = mpsc::channel::<String>();
            std::thread::spawn(move || {
                for l in std::io::BufReader::new(out).lines() {
                    let Ok(l) = l else { break };
                    if tx.send(l).is_err() {
                        break;
                    }
                }
            });
            let mut t = Target {
                child,
                stdin,
                lines: rx,
                pid,
            };
            match t.lines.recv_timeout(limit()) {
                Ok(l) if l == "READY" => {}
                Ok(l) => {
                    let _ = t.kill();
                    return Err(format!("target said {l:?} instead of READY"));
                }
                Err(_) => {
                    let st = t.child.try_wait().ok().flatten();
                    let _ = t.kill();
                    return Err(format!(
                        "target did not become ready (unshare status {st:?}; unprivileged user namespaces unavailable?)"
                    ));
                }
            }
            let user = ns_identity(&format!("/proc/{pid}/ns/user"))?;
            if user == own_user {
                let _ = t.kill();
                return Err("target did not enter a new user namespace".into());
            }
            Ok(t)
        }

        fn send(&mut self, line: &str) -> Result<(), String> {
            let w = self.stdin.as_mut().ok_or("target stdin closed")?;
            w.write_all(line.as_bytes())
                .and_then(|()| w.write_all(b"\n"))
                .and_then(|()| w.flush())
                .map_err(|e| format!("write to target: {e}"))
        }

        fn recv(&mut self) -> Result<String, String> {
            self.lines
                .recv_timeout(limit() * 2)
                .map_err(|e| format!("no reply from target: {e}"))
        }

        fn cmd(&mut self, line: &str) -> Result<String, String> {
            self.send(line)?;
            self.recv()
        }

        /// 対象の netns の `/proc/<pid>/net/<file>`（同じ uid の本プロセスから読む）。
        fn net(&self, file: &str) -> Result<String, String> {
            let p = format!("/proc/{}/net/{file}", self.pid);
            std::fs::read_to_string(&p).map_err(|e| format!("read target net/{file}: {e}"))
        }

        fn kill(&mut self) -> Result<(), String> {
            self.stdin = None;
            reap::reap(&mut self.child, limit())
        }

        /// 正常終了（EXIT）を試み、期限切れなら kill して回収する。
        fn finish(&mut self) -> Result<(), String> {
            let _ = self.send("EXIT");
            self.stdin = None;
            match reap::wait_within(&mut self.child, limit()) {
                Ok(_) => Ok(()),
                Err(_) => self.kill(),
            }
        }
    }

    // ---------------------------------------------------------------- holder

    struct Holder {
        child: Child,
        chan: Option<NetnsHolderChannel>,
        stderr: mpsc::Receiver<String>,
        pid: u32,
    }

    /// holder を起動して対象の namespace を送り、READY の識別が対象と一致することまで確かめる。
    fn start_holder(target_pid: u32) -> Result<Holder, String> {
        let (chan, child_end) = NetnsHolderChannel::pair().map_err(|e| e.to_string())?;
        let mut child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .arg("netns-holder")
            .env_clear()
            .stdin(Stdio::from(child_end))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn holder: {e}"))?;
        let mut stderr = child.stderr.take().ok_or("stderr")?;
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s);
            let _ = tx.send(s);
        });
        let pid = child.id();
        let mut h = Holder {
            child,
            chan: Some(chan),
            stderr: rx,
            pid,
        };
        let verified = (|| {
            let open = |name: &str| {
                File::open(format!("/proc/{target_pid}/ns/{name}"))
                    .map(OwnedFd::from)
                    .map_err(|e| format!("open target ns {name}: {e}"))
            };
            let fds =
                NetnsHolderFds::new(open("user")?, open("net")?).map_err(|e| e.to_string())?;
            let chan = h.chan.as_ref().ok_or("channel closed")?;
            let sent = chan.send_namespaces(fds).map_err(|e| e.to_string())?;
            let r = chan
                .wait_ready(&sent, READY_TIMEOUT)
                .map_err(|e| format!("wait_ready: {e}"))?;
            let net = ns_identity(&format!("/proc/{target_pid}/ns/net"))?;
            let user = ns_identity(&format!("/proc/{target_pid}/ns/user"))?;
            let want = NsIdentity {
                dev: net.0,
                net_ino: net.1,
                user_ino: user.1,
            };
            check(r.identity == sent.identity() && r.identity == want, || {
                "READY identity does not match the target".into()
            })
        })();
        match verified {
            Ok(()) => Ok(h),
            Err(e) => {
                let _ = reap::reap(&mut h.child, limit());
                Err(e)
            }
        }
    }

    impl Holder {
        /// STOP を送り、期限内に終了コード 0 で終わることを確かめる（終わらなければ kill して失敗）。
        fn stop(&mut self) -> Result<(), String> {
            if let Some(c) = self.chan.as_ref() {
                c.send_stop().map_err(|e| e.to_string())?;
            }
            match reap::wait_within(&mut self.child, limit()) {
                Ok(st) => {
                    let text = self
                        .stderr
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap_or_default();
                    check(st.code() == Some(0), || {
                        format!("holder exit {st:?}, stderr {text:?}")
                    })
                }
                Err(e) => {
                    let _ = reap::reap(&mut self.child, limit());
                    Err(format!("holder did not stop: {e}"))
                }
            }
        }
    }

    // ---------------------------------------------------------------- 状態ルートと場面

    struct StateRoot {
        path: PathBuf,
        file: File,
    }

    #[derive(Clone, Copy)]
    struct Ctx<'a> {
        binary: &'a PastaBinary,
        root: &'a StateRoot,
    }

    struct Scene {
        name: &'static str,
        target: Option<Target>,
        holder: Option<Holder>,
        pasta: Option<PastaProcess>,
        run_dir: Option<PastaRunDir>,
        base: HostSnap,
    }

    impl Scene {
        fn target(&mut self) -> Result<&mut Target, String> {
            self.target
                .as_mut()
                .ok_or_else(|| "target already gone".into())
        }

        /// pasta が参加する対象の PID（holder があれば holder、無ければ unshare の子）。
        fn attach_pid(&self) -> Result<u32, String> {
            match (&self.holder, &self.target) {
                (Some(h), _) => Ok(h.pid),
                (None, Some(t)) => Ok(t.pid),
                _ => Err("no attach target".into()),
            }
        }

        fn prepare_dir(&mut self, root: &StateRoot) -> Result<(), String> {
            let rd = PastaRunDir::prepare(root.file.as_fd(), self.name)
                .map_err(|e| format!("PastaRunDir::prepare: {}", e.code().as_str()))?;
            self.run_dir = Some(rd);
            Ok(())
        }

        /// 起動を試み、結果（成功なら `self.pasta` に保持）をそのまま返す。呼び出しは main スレッドから。
        fn spawn(
            &mut self,
            root: &StateRoot,
            binary: &PastaBinary,
            forwards: &PastaPortForwards,
            pid: u32,
        ) -> Result<Result<(), Box<PastaSpawnError>>, String> {
            if self.run_dir.is_none() {
                self.prepare_dir(root)?;
            }
            let rd = self.run_dir.as_ref().ok_or("run dir")?;
            let target = PastaTarget::from_pid(pid).map_err(|e| e.code().as_str().to_string())?;
            match spawn_pasta(binary, rd, forwards, target, PASTA_READY_TIMEOUT_DEFAULT) {
                Ok((p, _ready)) => {
                    self.pasta = Some(p);
                    Ok(Ok(()))
                }
                Err(e) => Ok(Err(e)),
            }
        }

        fn start(&mut self, ctx: Ctx<'_>, forwards: &PastaPortForwards) -> Result<(), String> {
            let pid = self.attach_pid()?;
            match self.spawn(ctx.root, ctx.binary, forwards, pid)? {
                Ok(()) => Ok(()),
                Err(mut e) => {
                    let text = spawn_error_text(&e);
                    if let Some(p) = e.take_unreaped() {
                        let _ = p.stop();
                    }
                    Err(text)
                }
            }
        }

        fn pasta_pid(&self) -> Result<u32, String> {
            self.pasta
                .as_ref()
                .map(PastaProcess::pid)
                .ok_or_else(|| "pasta not running".into())
        }

        /// 後始末: pasta → run dir → holder → 対象の順。失敗は集めて返す。
        fn teardown(&mut self) -> Result<(), String> {
            let mut errs: Vec<String> = Vec::new();
            if let Some(p) = self.pasta.take()
                && let Err(e) = p.stop()
            {
                errs.push(format!("teardown pasta stop: {e}"));
            }
            if let Some(rd) = self.run_dir.take()
                && let Err(e) = rd.remove()
            {
                errs.push(format!("teardown run dir: {}", e.code().as_str()));
            }
            if let Some(mut h) = self.holder.take()
                && let Err(e) = h.stop()
            {
                errs.push(format!("teardown holder: {e}"));
            }
            if let Some(mut t) = self.target.take()
                && let Err(e) = t.finish()
            {
                errs.push(format!("teardown target: {e}"));
            }
            if errs.is_empty() {
                Ok(())
            } else {
                Err(errs.join("; "))
            }
        }
    }

    fn spawn_error_text(e: &PastaSpawnError) -> String {
        format!(
            "spawn_pasta failed: code={} stage={:?} message={:?} exit={:?} stderr={:?}",
            e.code().as_str(),
            e.diagnostics().stage,
            e.message(),
            e.diagnostics().exit,
            e.diagnostics().stderr_excerpt
        )
    }

    /// 場面を作って本体を実行し、成否にかかわらず後始末する。本体は main スレッドで同期的に走る（PDEATHSIG のため）。
    fn run_scene(
        name: &'static str,
        ctr_ports: &[u16],
        use_holder: bool,
        body: &mut dyn FnMut(&mut Scene) -> Result<(), String>,
    ) -> Result<(), String> {
        let base = host_snapshot()?;
        let mut scene = Scene {
            name,
            target: None,
            holder: None,
            pasta: None,
            run_dir: None,
            base,
        };
        scene.target = Some(Target::spawn(ctr_ports).map_err(|e| format!("{name}: {e}"))?);
        if use_holder {
            let pid = scene.target()?.pid;
            match start_holder(pid) {
                Ok(h) => scene.holder = Some(h),
                Err(e) => {
                    let _ = scene.teardown();
                    return Err(format!("{name}: {e}"));
                }
            }
        }
        let result = body(&mut scene).map_err(|e| format!("{name}: {e}"));
        let torn = scene.teardown().map_err(|e| format!("{name}: {e}"));
        result.and(torn)
    }

    /// 起動後の netns の状態: `lo` + `eth0`・IPv4 既定経路・IPv6 既定経路なし。
    fn expect_basic_net(t: &Target) -> Result<(), String> {
        wait_for("eth0 with a default route", || {
            let ifaces = parse_ifaces(&t.net("dev")?);
            let rows = parse_route(&t.net("route")?);
            let has_default = rows
                .iter()
                .any(|r| r.iface == "eth0" && r.dest == "00000000" && r.flags & 3 == 3);
            if ifaces == ["eth0", "lo"] && has_default {
                Ok(Ok(()))
            } else {
                Ok(Err(format!(
                    "ifaces {ifaces:?}, default route {has_default}"
                )))
            }
        })?;
        check(!has_v6_default(&t.net("ipv6_route")?), || {
            "IPv6 default route exists despite -4".into()
        })
    }

    fn expect_only_lo(t: &Target) -> Result<(), String> {
        let ifaces = parse_ifaces(&t.net("dev")?);
        check(ifaces == ["lo"], || {
            format!("interfaces before attach: {ifaces:?}, want [lo]")
        })
    }

    fn stop_and_check(scene: &mut Scene, want_term: bool) -> Result<(), String> {
        let p = scene.pasta.take().ok_or("pasta not running")?;
        let started = Instant::now();
        let out = p.stop().map_err(|e| format!("stop: {e}"))?;
        let elapsed = started.elapsed();
        if want_term {
            check(out.path == PastaStopPath::Term, || {
                format!("stop path {:?}, want Term", out.path)
            })?;
            check(elapsed < PASTA_STOP_GRACE, || {
                format!("stop took {elapsed:?}")
            })?;
        }
        expect_no_pasta_children()
    }

    fn tcp_key(ip: Ipv4Addr, port: u16) -> (String, u16) {
        (hex_ip(ip), port)
    }

    fn net_msg(e: &fandhe_container_net::error::NetError) -> String {
        format!("{} {}", e.code().as_str(), e.message())
    }

    fn forward(addr: Option<Ipv4Addr>, host: u16, ctr: u16) -> Result<PastaPortForward, String> {
        PastaPortForward::new(PortProtocol::Tcp, addr, host, ctr).map_err(|e| net_msg(&e))
    }

    fn forwards(items: Vec<PastaPortForward>) -> Result<PastaPortForwards, String> {
        PastaPortForwards::try_from_forwards(items).map_err(|e| net_msg(&e))
    }

    /// ホストから公開ポートへ接続し、対象の `ACCEPT <idx>` が 1 バイト `K` を返すことを確かめる。
    fn reach_published(t: &mut Target, idx: usize, ip: Ipv4Addr, port: u16) -> Result<(), String> {
        t.send(&format!("ACCEPT {idx}"))?;
        let mut c = TcpStream::connect_timeout(&SocketAddr::from((ip, port)), limit())
            .map_err(|e| format!("connect to forward {idx}: {e}"))?;
        c.set_read_timeout(Some(limit()))
            .map_err(|e| e.to_string())?;
        let mut b = [0u8; 1];
        c.read_exact(&mut b)
            .map_err(|e| format!("read from forward {idx}: {e}"))?;
        let r = t.recv()?;
        check(b == *b"K" && r == "OK", || {
            format!("forward {idx}: byte {b:?}, reply {r:?}")
        })
    }

    // ---------------------------------------------------------------- 場面

    /// S1: #340 の形（unshare の子を対象）。
    fn scene_basic(ctx: Ctx<'_>, name: &'static str, binary: &PastaBinary) -> Result<(), String> {
        run_scene(name, &[], false, &mut |s| {
            expect_only_lo(s.target()?)?;
            let pid = s.attach_pid()?;
            if let Err(e) = s.spawn(ctx.root, binary, &PastaPortForwards::new(), pid)? {
                return Err(spawn_error_text(&e));
            }
            expect_basic_net(s.target()?)?;
            stop_and_check(s, true)?;
            let rd = s.run_dir.take().ok_or("run dir")?;
            rd.remove()
                .map_err(|e| format!("run dir remove: {}", e.code().as_str()))?;
            check(!ctx.root.path.join("@pasta").join(name).exists(), || {
                "@pasta/<id> remains".into()
            })
        })
    }

    /// S2: 本番の形（holder を対象）。観測した AppArmor の封じ込め状態を返す。
    fn scene_holder(ctx: Ctx<'_>) -> Result<&'static str, String> {
        let ports = free_ports(3)?;
        let (p1, p2, c1) = (ports[0], ports[1], ports[2]);
        let mut confinement = "not-determined";
        run_scene("s2", &[c1], true, &mut |s| {
            expect_only_lo(s.target()?)?;
            let fw = forwards(vec![forward(None, p1, c1)?])?;
            // ホスト側に別ポートの待ち受けを置く（--map-host-loopback none の照合用）。
            let host_l = TcpListener::bind(("127.0.0.1", p2)).map_err(|e| e.to_string())?;
            host_l.set_nonblocking(true).map_err(|e| e.to_string())?;
            let watch = [p1, c1, p2];
            s.base = host_snapshot()?;
            s.start(ctx, &fw)?;
            let pasta = s.pasta_pid()?;
            expect_basic_net(s.target()?)?;
            let fd_visible = expect_tcp_listeners(
                pasta,
                &s.base,
                &watch,
                vec![tcp_key(Ipv4Addr::LOCALHOST, p1)],
            )?;
            obs("pasta_fd_visible", if fd_visible { "yes" } else { "no" });
            let t = s.target()?;
            // 届く: ホストの 127.0.0.1:P1 → 対象のコンテナ側ポート。
            reach_published(t, 0, Ipv4Addr::LOCALHOST, p1)?;
            // loopback 以外の同じポートは接続拒否。
            let nl = non_loopback_addr()?;
            let e = TcpStream::connect_timeout(&SocketAddr::from((nl, p1)), limit());
            check(
                matches!(&e, Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused),
                || {
                    format!(
                        "non-loopback connect: {:?}",
                        e.as_ref()
                            .map(|_| "connected")
                            .map_err(std::io::Error::kind)
                    )
                },
            )?;
            // -T none -U none / --map-host-loopback none。
            let r = t.cmd(&format!("CONNECT 127.0.0.1 {p2}"))?;
            check(r == "REFUSED", || {
                format!("netns -> 127.0.0.1:P2 reply {r:?}, want REFUSED")
            })?;
            let gw = parse_route(&t.net("route")?)
                .into_iter()
                .find(|r| r.dest == "00000000")
                .and_then(|r| parse_ip_hex(&r.gateway))
                .ok_or("no default gateway in target")?;
            let _ = t.cmd(&format!("CONNECT {gw} {p2}"))?;
            check(
                matches!(host_l.accept(), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock),
                || "host loopback listener received a connection from the namespace".into(),
            )?;
            let listen: Vec<u16> = parse_net_table(&t.net("tcp")?)
                .into_iter()
                .filter(|x| x.state == "0A")
                .map(|x| x.port)
                .collect();
            check(listen == [c1], || {
                format!("target tcp listeners {listen:?}, want only the test's own")
            })?;
            let udp = parse_net_table(&t.net("udp")?);
            check(udp.is_empty(), || {
                format!("target udp sockets {udp:?}, want none")
            })?;
            // DNS 転送（169.254.1.1:53 への転送が働くこと）。
            let r = t.cmd("DNS")?;
            let rcode = r.strip_prefix("DNS ").and_then(|v| v.parse::<u8>().ok());
            check(matches!(rcode, Some(0 | 3)), || {
                format!("DNS reply {r:?}, want rcode 0 or 3")
            })?;
            obs(
                "dns_rcode",
                &rcode.map_or_else(|| "?".into(), |v| v.to_string()),
            );
            // argv[0]・実行ファイル・comm・AppArmor。
            let cmdline = std::fs::read(format!("/proc/{pasta}/cmdline"))
                .map_err(|e| format!("read cmdline: {e}"))?;
            let argv0 = cmdline.split(|b| *b == 0).next().unwrap_or(&[]);
            check(argv0 == b"pasta", || {
                format!("argv[0] = {:?}, want pasta", String::from_utf8_lossy(argv0))
            })?;
            let comm = std::fs::read_to_string(format!("/proc/{pasta}/comm")).unwrap_or_default();
            check(comm.trim().starts_with("pasta"), || {
                format!("comm = {:?}", comm.trim())
            })?;
            match std::fs::read_link(format!("/proc/{pasta}/exe")) {
                Ok(exe) if exe == ctx.binary.path() => obs("exe", "exact"),
                Ok(exe)
                    if exe.parent() == ctx.binary.path().parent()
                        && exe
                            .file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.starts_with("pasta")) =>
                {
                    obs("exe", "variant");
                }
                Ok(_) => return Err("pasta executable is not the verified binary".into()),
                Err(_) => obs("exe_visible", "no"),
            }
            let attr = std::fs::read_to_string(format!("/proc/{pasta}/attr/apparmor/current"))
                .or_else(|_| std::fs::read_to_string(format!("/proc/{pasta}/attr/current")));
            confinement = match attr.as_deref().map(str::trim) {
                Ok(a) if a.ends_with("(enforce)") => "enforce",
                Ok(a) if a.ends_with("(complain)") => "complain",
                Ok("unconfined") => "unconfined",
                _ => "not-determined",
            };
            obs("pasta_confinement", confinement);
            stop_and_check(s, true)?;
            s.holder.as_mut().ok_or("holder")?.stop()?;
            s.holder = None;
            Ok(())
        })?;
        Ok(confinement)
    }

    /// `/usr/bin/passt`（リンク数 2 の別名）が同じ実体なら、その検証済みバイナリでも S1 と同じ照合をする。
    fn scene_passt_link(ctx: Ctx<'_>) -> Result<(), String> {
        match verify_pasta_binary(Path::new("/usr/bin/passt")) {
            Err(_) => {
                obs("passt_link", "absent");
                Ok(())
            }
            Ok(b)
                if b.identity().dev() == ctx.binary.identity().dev()
                    && b.identity().ino() == ctx.binary.identity().ino() =>
            {
                obs("passt_link", "same-file");
                scene_basic(ctx, "s2b", &b)
            }
            Ok(_) => {
                obs("passt_link", "different-file");
                Ok(())
            }
        }
    }

    /// S3: 同じプロトコルの `-t` を複数回渡したときの累積。
    fn scene_accumulate(ctx: Ctx<'_>) -> Result<(), String> {
        let ports = free_ports(6)?;
        let (pa, pb, pc) = (ports[0], ports[1], ports[2]);
        let (ca, cb, cc) = (ports[3], ports[4], ports[5]);
        run_scene("s3", &[ca, cb, cc], false, &mut |s| {
            let l2 = Ipv4Addr::new(127, 0, 0, 2);
            let fw = forwards(vec![
                forward(None, pa, ca)?,
                forward(Some(l2), pb, cb)?,
                forward(None, pc, cc)?,
            ])?;
            let dummy = PastaTarget::from_pid(2).map_err(|e| net_msg(&e))?;
            let argv: Vec<String> = pasta_argv(Path::new("/x"), &fw, dummy)
                .into_iter()
                .filter_map(|o| o.into_string().ok())
                .collect();
            let dash_t: Vec<&str> = argv
                .iter()
                .enumerate()
                .filter(|(_, a)| a.as_str() == "-t")
                .filter_map(|(i, _)| argv.get(i + 1).map(String::as_str))
                .collect();
            let want = [
                format!("127.0.0.1/{pa}:{ca},{pc}:{cc}"),
                format!("127.0.0.2/{pb}:{cb}"),
            ];
            check(dash_t == want, || format!("-t arguments: {dash_t:?}"))?;
            let watch = [pa, pb, pc, ca, cb, cc];
            s.base = host_snapshot()?;
            s.start(ctx, &fw)?;
            let pasta = s.pasta_pid()?;
            expect_tcp_listeners(
                pasta,
                &s.base,
                &watch,
                vec![
                    tcp_key(Ipv4Addr::LOCALHOST, pa),
                    tcp_key(l2, pb),
                    tcp_key(Ipv4Addr::LOCALHOST, pc),
                ],
            )?;
            for (i, (ip, hp)) in [
                (Ipv4Addr::LOCALHOST, pa),
                (l2, pb),
                (Ipv4Addr::LOCALHOST, pc),
            ]
            .into_iter()
            .enumerate()
            {
                reach_published(s.target()?, i, ip, hp)?;
            }
            stop_and_check(s, true)
        })
    }

    /// S4: 公開 0 件ではホスト側のポートが 1 つも開かない（`auto` が働かない）。
    fn scene_none(ctx: Ctx<'_>) -> Result<(), String> {
        let ports = free_ports(2)?;
        let (p3, cq) = (ports[0], ports[1]);
        // 対象側（netns 内）に未公開の待ち受け cq を置く。`-t none` が `auto` に誤ると cq がホストへ転送される。
        run_scene("s4", &[cq], false, &mut |s| {
            let host_l = TcpListener::bind(("127.0.0.1", p3)).map_err(|e| e.to_string())?;
            let _keep = &host_l;
            s.base = host_snapshot()?;
            s.start(ctx, &PastaPortForwards::new())?;
            let pasta = s.pasta_pid()?;
            expect_basic_net(s.target()?)?;
            expect_tcp_listeners(pasta, &s.base, &[p3, cq], vec![])?;
            // 対象側の cq は待ち受け中のまま（観測の前提）で、ホスト側には転送が生じない。
            let listen = parse_net_table(&s.target()?.net("tcp")?)
                .into_iter()
                .filter(|x| x.state == "0A" && x.port == cq)
                .count();
            check(listen == 1, || {
                format!("target has {listen} unpublished listeners on {cq}, want 1")
            })?;
            let leaked = TcpStream::connect_timeout(
                &SocketAddr::from((Ipv4Addr::LOCALHOST, cq)),
                Duration::from_millis(500),
            );
            check(leaked.is_err(), || {
                format!("host port {cq} reached the target despite no publish")
            })?;
            stop_and_check(s, true)
        })
    }

    /// S5: 明示した `-t` の bind に失敗したとき（二者択一の観測。どちらになるかを決めつけない）。
    fn scene_bind_conflict(ctx: Ctx<'_>) -> Result<(), String> {
        let ports = free_ports(2)?;
        let (px, cx) = (ports[0], ports[1]);
        run_scene("s5", &[], false, &mut |s| {
            let host_l = TcpListener::bind(("127.0.0.1", px)).map_err(|e| e.to_string())?;
            let _keep = &host_l;
            let fw = forwards(vec![forward(None, px, cx)?])?;
            s.base = host_snapshot()?;
            let pid = s.attach_pid()?;
            match s.spawn(ctx.root, ctx.binary, &fw, pid)? {
                Err(mut e) => {
                    let text = spawn_error_text(&e);
                    check(
                        e.code() == NetErrorCode::FailedPrecondition
                            && e.message() == MSG_PASTA_EXITED_EARLY
                            && e.diagnostics().stage == PastaStage::Ready,
                        || text.clone(),
                    )?;
                    if let Some(p) = e.take_unreaped() {
                        let _ = p.stop();
                        return Err(format!("unreaped pasta after early exit: {text}"));
                    }
                    expect_no_pasta_children()?;
                    obs("bind_conflict", "pasta-exited-before-ready");
                    Ok(())
                }
                Ok(()) => {
                    let pasta = s.pasta_pid()?;
                    let socks = pasta_sockets(pasta, &s.base, &[px])?;
                    check(socks.tcp.is_empty(), || {
                        format!("pasta listens despite the conflict: {:?}", socks.tcp)
                    })?;
                    obs("bind_conflict", "pasta-continued-without-listener");
                    stop_and_check(s, false)
                }
            }
        })
    }

    /// S6・S7 の共通部: holder 構成で起動し、holder と対象を SIGKILL して回収する。
    fn start_and_kill_holder(ctx: Ctx<'_>, s: &mut Scene) -> Result<(), String> {
        s.start(ctx, &PastaPortForwards::new())?;
        expect_basic_net(s.target()?)?;
        let mut h = s.holder.take().ok_or("holder")?;
        reap::reap(&mut h.child, limit())?;
        s.target()?.kill()?;
        s.target = None;
        Ok(())
    }

    /// S6: 対象が消えた直後の `stop`（netns-quit の約 1 秒周期に頼らず期限内に回収される）。
    fn scene_stop_after_kill(ctx: Ctx<'_>) -> Result<(), String> {
        run_scene("s6", &[], true, &mut |s| {
            start_and_kill_holder(ctx, s)?;
            let p = s.pasta.take().ok_or("pasta")?;
            let started = Instant::now();
            let out = p
                .stop()
                .map_err(|e| format!("stop after target kill: {e}"))?;
            let elapsed = started.elapsed();
            let bound = PASTA_STOP_GRACE + PASTA_REAP_TIMEOUT + Duration::from_secs(1);
            check(elapsed < bound, || format!("stop took {elapsed:?}"))?;
            obs(
                "stop_after_target_kill_path",
                match out.path {
                    PastaStopPath::Term => "term",
                    PastaStopPath::Kill => "kill",
                    PastaStopPath::AlreadyExited => "already-exited",
                    _ => "other",
                },
            );
            expect_no_pasta_children()
        })
    }

    /// S7: holder と対象が消えた後の netns-quit（`stop` を呼ばずに pasta が自分で終わるか。観測）。
    fn scene_netns_quit(ctx: Ctx<'_>) -> Result<(), String> {
        run_scene("s7", &[], true, &mut |s| {
            start_and_kill_holder(ctx, s)?;
            let started = Instant::now();
            let quit = {
                let p = s.pasta.as_mut().ok_or("pasta")?;
                loop {
                    if !p.is_alive().map_err(|e| e.message().to_string())? {
                        break Some(started.elapsed());
                    }
                    if started.elapsed() >= limit() {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            };
            let Some(took) = quit else {
                return Err("pasta did not quit by itself after the namespace holders were gone (12.10 step 3 does not work)".into());
            };
            obs("netns_quit_ms", &took.as_millis().to_string());
            let p = s.pasta.take().ok_or("pasta")?;
            let out = p.stop().map_err(|e| format!("stop: {e}"))?;
            check(out.path == PastaStopPath::AlreadyExited, || {
                format!("stop path {:?}, want AlreadyExited", out.path)
            })
        })
    }

    /// S8 の中間プロセス: main スレッドで pasta を起動し、pid と starttime を出して SIGKILL を待つ。
    pub fn fake_supervisor(mut args: impl Iterator<Item = OsString>) -> ExitCode {
        let (Some(pid), Some(root), Some(bin)) = (args.next(), args.next(), args.next()) else {
            return ExitCode::from(2);
        };
        let r = (|| -> Result<(u32, u64), String> {
            let pid: u32 = pid.to_str().and_then(|s| s.parse().ok()).ok_or("pid")?;
            let binary = verify_pasta_binary(Path::new(&bin)).map_err(|e| net_msg(&e))?;
            let root = File::open(root).map_err(|e| e.to_string())?;
            let rd = PastaRunDir::prepare(root.as_fd(), "s8x").map_err(|e| net_msg(&e))?;
            let target = PastaTarget::from_pid(pid).map_err(|e| net_msg(&e))?;
            let (proc, ready) = spawn_pasta(
                &binary,
                &rd,
                &PastaPortForwards::new(),
                target,
                PASTA_READY_TIMEOUT_DEFAULT,
            )
            .map_err(|e| spawn_error_text(&e))?;
            let start = stat_fields(ready.pid()).map(|f| f.1).ok_or("starttime")?;
            // Drop を走らせない（pasta を止めずに SIGKILL される側の挙動を再現する）。
            std::mem::forget(proc);
            std::mem::forget(rd);
            Ok((ready.pid(), start))
        })();
        match r {
            Ok((p, st)) => {
                println!("{p} {st}");
                let _ = std::io::stdout().flush();
                std::thread::sleep(limit() * 6);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("fake-supervisor: {e}");
                ExitCode::from(1)
            }
        }
    }

    /// S8: 中間の supervisor が SIGKILL されたら pasta も消える（PDEATHSIG）。
    fn scene_pdeathsig(ctx: Ctx<'_>) -> Result<(), String> {
        run_scene("s8", &[], false, &mut |s| {
            let target_pid = s.attach_pid()?;
            let mut sup = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
                .arg("--fake-supervisor")
                .arg(target_pid.to_string())
                .arg(&ctx.root.path)
                .arg(ctx.binary.path())
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| format!("spawn fake supervisor: {e}"))?;
            let out = sup.stdout.take().ok_or("stdout")?;
            let (tx, rx) = mpsc::channel::<String>();
            std::thread::spawn(move || {
                let mut l = String::new();
                let _ = std::io::BufReader::new(out).read_line(&mut l);
                let _ = tx.send(l);
            });
            let line = match rx.recv_timeout(limit() + PASTA_READY_TIMEOUT_DEFAULT) {
                Ok(l) => l,
                Err(_) => {
                    let _ = reap::reap(&mut sup, limit());
                    return Err("fake supervisor did not report in time".into());
                }
            };
            let mut it = line.split_whitespace();
            let parsed = (
                it.next().and_then(|v| v.parse::<u32>().ok()),
                it.next().and_then(|v| v.parse::<u64>().ok()),
            );
            let (Some(pasta), Some(start)) = parsed else {
                let _ = reap::reap(&mut sup, limit());
                return Err(format!("fake supervisor reported {line:?}"));
            };
            reap::reap(&mut sup, limit())?;
            let gone = wait_for(
                "pasta gone after the supervisor was killed",
                || match stat_fields(pasta) {
                    None => Ok(Ok(())),
                    Some((_, st)) if st != start => Ok(Ok(())),
                    Some((state, _)) => Ok(Err(format!("state {state}"))),
                },
            );
            // 残骸の掃除は成否にかかわらず行う（s8x の置き場所は中間プロセスが作った）。
            let cleaned =
                remove_pasta_run_dir(ctx.root.file.as_fd(), "s8x").map_err(|e| net_msg(&e));
            gone.and(cleaned)
        })
    }

    /// S9: AppArmor が enforce のとき許可外の置き場所が拒否されるか（条件つき観測）。
    fn scene_outside_allowed(ctx: Ctx<'_>, confinement: &str) -> Result<(), String> {
        if confinement != "enforce" {
            obs(
                "apparmor_outside_allowed",
                &format!("not-run-{confinement}"),
            );
            return Ok(());
        }
        let dir = PathBuf::from("/var/tmp").join(format!(
            "pasta-rootless-out-{}-{}",
            std::process::id(),
            nanos()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| format!("create outside dir: {e}"))?;
        let result = (|| {
            let root = StateRoot {
                file: File::open(&dir).map_err(|e| e.to_string())?,
                path: dir.clone(),
            };
            let ctx = Ctx {
                binary: ctx.binary,
                root: &root,
            };
            run_scene("s9", &[], false, &mut |s| {
                let pid = s.attach_pid()?;
                match s.spawn(ctx.root, ctx.binary, &PastaPortForwards::new(), pid)? {
                    Err(mut e) => {
                        let text = spawn_error_text(&e);
                        if let Some(p) = e.take_unreaped() {
                            let _ = p.stop();
                        }
                        check(
                            e.code() == NetErrorCode::FailedPrecondition
                                && e.message() == MSG_PASTA_EXITED_EARLY,
                            || text,
                        )?;
                        obs("apparmor_outside_allowed", "refused");
                        Ok(())
                    }
                    Ok(()) => {
                        obs("apparmor_outside_allowed", "allowed");
                        Ok(())
                    }
                }
            })
        })();
        let removed = std::fs::remove_dir_all(&dir).map_err(|e| format!("remove outside dir: {e}"));
        result.and(removed)
    }

    /// S10: 準備完了の前に pasta が死んだ（対象が終了済みで未回収）ときのエラー。
    fn scene_dead_target(ctx: Ctx<'_>) -> Result<(), String> {
        // 対象は必ず新規の user + net namespace 内のプロセスにする（ホストの netns に pasta が attach して
        // eth0・アドレス・経路を作る事故を避ける）。`unshare` は exec するので子の pid がそのまま対象になる。
        let host_ifaces_before = parse_ifaces(
            &std::fs::read_to_string("/proc/self/net/dev")
                .map_err(|e| format!("read host dev: {e}"))?,
        );
        let mut zombie = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net", "sleep", "600"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn isolated target: {e}"))?;
        let zpid = zombie.id();
        let own_net = ns_identity("/proc/self/ns/net")?;
        let isolated = wait_for("target enters a new net namespace", || {
            Ok(match ns_identity(&format!("/proc/{zpid}/ns/net")) {
                Ok(n) if n != own_net => Ok(()),
                other => Err(format!("{other:?}")),
            })
        });
        if let Err(e) = isolated {
            let _ = zombie.kill();
            let _ = reap::wait_within(&mut zombie, limit());
            return Err(e);
        }
        zombie.kill().map_err(|e| format!("kill target: {e}"))?;
        let waited = wait_for("target becomes a zombie", || {
            Ok(match stat_fields(zpid) {
                Some(('Z', _)) => Ok(()),
                other => Err(format!("{other:?}")),
            })
        });
        let result = waited.and_then(|()| {
            let mut scene = Scene {
                name: "s10",
                target: None,
                holder: None,
                pasta: None,
                run_dir: None,
                base: HostSnap::default(),
            };
            let r = (|| match scene.spawn(ctx.root, ctx.binary, &PastaPortForwards::new(), zpid)? {
                Ok(()) => Err("pasta became ready on a dead target".to_string()),
                Err(mut e) => {
                    let text = spawn_error_text(&e);
                    if let Some(p) = e.take_unreaped() {
                        let _ = p.stop();
                        return Err(format!("unreaped: {text}"));
                    }
                    let exit = e.diagnostics().exit;
                    check(
                        e.code() == NetErrorCode::FailedPrecondition
                            && e.message() == MSG_PASTA_EXITED_EARLY
                            && e.diagnostics().stage == PastaStage::Ready
                            && (exit.code.is_some_and(|c| c != 0) || exit.signal.is_some()),
                        || text,
                    )?;
                    expect_no_pasta_children()
                }
            })();
            r.and(scene.teardown())
        });
        let reaped = reap::wait_within(&mut zombie, limit()).map(|_| ());
        // ホストの netns に pasta が触れていないこと（インターフェース一覧が不変）。
        let host_untouched = std::fs::read_to_string("/proc/self/net/dev")
            .map_err(|e| format!("read host dev: {e}"))
            .and_then(|t| {
                let after = parse_ifaces(&t);
                check(after == host_ifaces_before, || {
                    format!("host interfaces changed: {host_ifaces_before:?} -> {after:?}")
                })
            });
        result.and(reaped).and(host_untouched)
    }

    /// S11: `-P` の PID ファイルが書かれる時点（空のファイルを見るか）の観測。pasta を直接起動する。
    fn scene_pid_file(ctx: Ctx<'_>) -> Result<(), String> {
        run_scene("s11", &[], false, &mut |s| {
            s.prepare_dir(ctx.root)?;
            let pid_path = s
                .run_dir
                .as_ref()
                .ok_or("run dir")?
                .pid_path()
                .to_path_buf();
            let target = PastaTarget::from_pid(s.attach_pid()?).map_err(|e| net_msg(&e))?;
            let argv = pasta_argv(&pid_path, &PastaPortForwards::new(), target);
            let mut child = Command::new(ctx.binary.path())
                .arg0("pasta")
                .args(argv)
                .env_clear()
                .current_dir("/")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("spawn pasta: {e}"))?;
            let want = child.id().to_string();
            let started = Instant::now();
            let mut seen_empty = false;
            let outcome = loop {
                match std::fs::read(&pid_path) {
                    Ok(b) if b.is_empty() => seen_empty = true,
                    Ok(b) if String::from_utf8_lossy(&b).trim() == want => break Ok(()),
                    _ => {}
                }
                if matches!(child.try_wait(), Ok(Some(_))) {
                    break Err("pasta exited before writing its pid file".to_string());
                }
                if started.elapsed() >= limit() {
                    break Err("pid file was not written in time".to_string());
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            let reaped = reap::reap(&mut child, limit());
            outcome.and(reaped)?;
            obs("pid_file_seen_empty", if seen_empty { "yes" } else { "no" });
            Ok(())
        })
    }

    fn nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    }

    fn effective_uid() -> Result<u32, String> {
        let s = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
        s.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|v| v.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| "cannot read the effective uid".to_string())
    }

    fn restrict_value() -> String {
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .map_or_else(|_| "absent".to_string(), |v| v.trim().to_string())
    }

    fn all_scenes() -> Result<(), String> {
        // ---- S0: 前提 ----
        let uid = effective_uid()?;
        check(uid != 0, || "must not run as root (rootless test)".into())?;
        self_check()?;
        let pasta_path = std::env::var_os("FANDHE_CONTAINER_TEST_PASTA")
            .map_or_else(|| PathBuf::from("/usr/bin/pasta"), PathBuf::from);
        let binary = verify_pasta_binary(&pasta_path).map_err(|e| {
            format!(
                "verify_pasta_binary failed: {} (install `passt` or set FANDHE_CONTAINER_TEST_PASTA)",
                net_msg(&e)
            )
        })?;
        let restrict = restrict_value();
        obs("apparmor_restrict_unprivileged_userns", &restrict);
        let xdg = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or("XDG_RUNTIME_DIR is not set")?;
        check(xdg.is_absolute(), || {
            "XDG_RUNTIME_DIR is not absolute".into()
        })?;
        let meta = std::fs::metadata(&xdg).map_err(|e| format!("stat XDG_RUNTIME_DIR: {e}"))?;
        check(meta.is_dir() && meta.uid() == uid, || {
            "XDG_RUNTIME_DIR is not a directory owned by the current user".into()
        })?;
        match Target::spawn(&[]) {
            Ok(mut t) => t.finish()?,
            Err(e) => {
                return Err(format!(
                    "target namespaces could not be created unprivileged (apparmor_restrict_unprivileged_userns={restrict}); attach under the default restriction cannot be verified on this host: {e}"
                ));
            }
        }
        let path = xdg.join(format!("pasta-rootless-{}-{}", std::process::id(), nanos()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| format!("create state root: {e}"))?;
        let result = (|| {
            let root = StateRoot {
                file: File::open(&path).map_err(|e| e.to_string())?,
                path: path.clone(),
            };
            let ctx = Ctx {
                binary: &binary,
                root: &root,
            };
            scene_basic(ctx, "s1", &binary)?;
            let confinement = scene_holder(ctx)?;
            scene_passt_link(ctx)?;
            scene_accumulate(ctx)?;
            scene_none(ctx)?;
            scene_bind_conflict(ctx)?;
            scene_stop_after_kill(ctx)?;
            scene_netns_quit(ctx)?;
            scene_pdeathsig(ctx)?;
            scene_outside_allowed(ctx, confinement)?;
            scene_dead_target(ctx)?;
            scene_pid_file(ctx)
        })();
        let removed = std::fs::remove_dir_all(&path).map_err(|e| format!("remove state root: {e}"));
        result.and(removed)
    }

    pub fn run() -> ExitCode {
        match all_scenes() {
            Ok(()) => {
                println!("{OK_LINE}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("pasta_rootless: FAILED: {e}");
                ExitCode::from(1)
            }
        }
    }
}
