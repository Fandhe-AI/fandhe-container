//! 軽量運用（`NameResolution::StaticHosts`）の bridge ネットワークで、`--dns` の値が `resolv.conf` の
//! `nameserver` へ直接書かれ、コンテナからの名前解決クエリが指定サーバーへ直接到達することの実機結合試験
//! （NET-8・NET-12・TASK-146.3・#337・TASK-185・MS-8。書き込み側は TASK-146.2・#336 の `apply_static_dns`）。
//!
//! root と util-linux の `unshare` / `nsenter` / `mount` が必要な実機前提テストのため `harness = false` の
//! 独自 `main` で動かし、`-- --ignored` を付けたときだけ実行する（未指定時は「ignored」を出力して成功終了
//! する分離であり、CI 通過のための弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では対象外。
//!
//! # 流れ
//! - ランチャ（host netns・root）: 0700 の一時ディレクトリを作り、`unshare --net --mount -- <exe> --inner` で子を起動する
//! - 子: `/` を rprivate にして tmpfs を載せ、軽量運用の `create_network` で c1 を `attach_container` する。
//!   `join_network` が `HelperDisabled` で gateway:53 の UDP 待受が 0 件であることを確かめる。bridge に secondary
//!   アドレス（gateway と別）を付与してそこへ偽 DNS サーバー（クエリログ付き UDP）を待ち受けさせ、`apply_static_dns` で
//!   書いた `resolv.conf` を `nsenter --net=<c1 の pin> <exe> --probe ...` で読む stub resolver にクエリを送らせる。
//!   サーバー側のクエリログ（送信元 = c1 のアドレス・QNAME・QTYPE）と、gateway:53 のデコイが受信 0 件であることで
//!   「指定サーバーへ直接届いた」ことを照合する
//!
//! probe は getaddrinfo を使わない（ホストの nsswitch が `resolve` / `mdns` 等を経由して `resolv.conf` を無視し、
//! ホストの resolver へクエリが漏れ得るため）。`resolv.conf` の先頭 `nameserver` へ手組みの A クエリを直接送る。
//!
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。前提（root・外部コマンド）を
//! 満たさない場合は skip せず失敗する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("static_dns_privileged: Linux only, not applicable on this OS");
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
            "static_dns_privileged: ignored (requires root, `unshare`, `nsenter`; run the built executable with `--ignored` under `sudo`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::Read as _;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use fandhe_container_net::add_host_dns::resolv_conf::{DnsApplyOutcome, PersistGuarantee};
    use fandhe_container_net::dns_helper::refcount::{
        DnsHelperRefCounts, JoinOutcome, ProcessLauncher,
    };
    use fandhe_container_net::dns_helper::{
        DnsListenAddr, MAX_DATAGRAM_LEN, READY_TIMEOUT_DEFAULT, REAP_TIMEOUT_DEFAULT,
        parse_question,
    };
    use fandhe_container_net::error::{NetError, NetErrorCode};
    use fandhe_container_net::etc_hosts::{NameResolution, StaticDnsOutcome, apply_static_dns};
    use fandhe_container_net::instrument::NoopNetOpRecorder;
    use fandhe_container_net::netlink_route::{
        AddrScope, AddressSpec, IpPrefix, NetlinkRouteSocket,
    };
    use fandhe_container_net::netns::ContainerNetns;
    use fandhe_container_net::network::{
        AttachedContainer, ContainerAttachSpec, CreatedNetwork, EndpointId, NetworkCreateSpec,
        NetworkName, PortRegistry, StaticIpam, attach_container, create_network, delete_network,
    };
    use fandhe_container_net::nftables_batch::NetlinkNetfilterSocket;

    const LAUNCHER_PID_ENV: &str = "FANDHE_STATICDNS_TEST_LAUNCHER_PID";
    const DIR_ENV: &str = "FANDHE_STATICDNS_TEST_DIR";
    const NETWORK: &str = "staticdns";
    const GATEWAY: &str = "10.218.0.1";
    /// 指定 `--dns` サーバー。gateway（DNS ヘルパーの待受位置）とは別アドレスにして直接性を区別する。
    const DNS_SERVER: &str = "10.218.0.53";
    /// 偽 DNS サーバーが返す A レコード（RFC 5737 TEST-NET-1）。
    const ANSWER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);
    /// クエリログの保持上限（無制限確保の防止）。
    const LOG_CAP: usize = 64;
    const OK_LINE: &str =
        "static_dns_privileged: ok mode=static-hosts dns=reached helper=not-started";

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
        let dir =
            std::env::temp_dir().join(format!("fandhe-staticdns-test-{}", std::process::id()));
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
                    println!("static_dns_privileged: inner did not finish before deadline");
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

    /// 偽 DNS サーバーが記録する 1 件のクエリ（送信元・QNAME のドット区切り文字列・QTYPE）。
    type QueryLog = Vec<(SocketAddr, String, u16)>;

    /// QNAME のラベル列（終端 0 を含む）をドット区切りへ変換する。不正なら `None`。
    fn qname_to_string(qname: &[u8]) -> Option<String> {
        let mut out = String::new();
        let mut off = 0usize;
        loop {
            let len = usize::from(*qname.get(off)?);
            off = off.checked_add(1)?;
            if len == 0 {
                break;
            }
            let end = off.checked_add(len)?;
            let label = std::str::from_utf8(qname.get(off..end)?).ok()?;
            if !out.is_empty() {
                out.push('.');
            }
            out.push_str(label);
            off = end;
        }
        Some(out)
    }

    /// A クエリ全体（ヘッダー + 質問）を組み立てる。
    fn a_query(id: u16, name: &str) -> Option<Vec<u8>> {
        let mut v = Vec::new();
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        v.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QDCOUNT=1
        for label in name.split('.') {
            let len = u8::try_from(label.len())
                .ok()
                .filter(|l| (1..=63).contains(l))?;
            v.push(len);
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A / QCLASS=IN
        Some(v)
    }

    /// 受信クエリ `q`（質問終端 `end`）に対する A 応答を組み立てる。
    fn a_answer(q: &[u8], end: usize, ip: Ipv4Addr) -> Option<Vec<u8>> {
        let mut r = Vec::new();
        r.extend_from_slice(q.get(0..2)?); // ID
        r.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1 RD RA RCODE=0
        r.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]); // QD=1 AN=1
        r.extend_from_slice(q.get(12..end)?); // 質問のエコー
        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]); // NAME ptr / A / IN / TTL=0 / RDLEN=4
        r.extend_from_slice(&ip.octets());
        Some(r)
    }

    fn be16(b: &[u8], off: usize) -> Option<u16> {
        Some(u16::from_be_bytes([
            *b.get(off)?,
            *b.get(off.checked_add(1)?)?,
        ]))
    }

    /// 応答が期待どおり（ID 一致・QR=1・RCODE=0・ANCOUNT=1・質問エコー一致・RDATA=期待アドレス）かを照合する。
    fn answer_matches(resp: &[u8], query: &[u8], id: u16, want: Ipv4Addr) -> Option<bool> {
        let flags = be16(resp, 2)?;
        if be16(resp, 0)? != id || flags & 0x8000 == 0 || flags & 0x000f != 0 || be16(resp, 6)? != 1
        {
            return Some(false);
        }
        let end = parse_question(resp)?.end;
        if resp.get(12..end)? != query.get(12..)? {
            return Some(false);
        }
        let rdata_start = resp.len().checked_sub(4)?;
        Some(resp.get(rdata_start..)? == want.octets())
    }

    /// 偽 DNS サーバー（クエリログ付き）。UDP ソケットは呼び出し側で bind 済みのものを受け取る。
    struct FakeDns {
        stop: Arc<AtomicBool>,
        rx: std::sync::mpsc::Receiver<QueryLog>,
    }

    impl FakeDns {
        /// `answer` が `Some` なら A クエリへその IP で応答する（デコイは `None` で応答しない）。
        fn spawn(sock: UdpSocket, answer: Option<Ipv4Addr>) -> Result<Self, NetError> {
            sock.set_read_timeout(Some(Duration::from_millis(100)))
                .map_err(|e| fail(format!("set_read_timeout: {e}")))?;
            let stop = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&stop);
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut log: QueryLog = Vec::new();
                let mut buf = [0u8; MAX_DATAGRAM_LEN];
                while !flag.load(Ordering::SeqCst) {
                    let Ok((n, from)) = sock.recv_from(&mut buf) else {
                        continue;
                    };
                    let Some(q) = buf.get(..n) else { continue };
                    let Some(question) = parse_question(q) else {
                        continue;
                    };
                    if let Some(name) = qname_to_string(question.qname)
                        && log.len() < LOG_CAP
                    {
                        log.push((from, name, question.qtype));
                    }
                    if let Some(ip) = answer
                        && let Some(resp) = a_answer(q, question.end, ip)
                    {
                        let _ = sock.send_to(&resp, from);
                    }
                }
                let _ = tx.send(log);
            });
            Ok(Self { stop, rx })
        }

        /// 停止してクエリログを回収する（回収は期限付き。REPAIR-5）。
        fn finish(self) -> Result<QueryLog, NetError> {
            self.stop.store(true, Ordering::SeqCst);
            self.rx
                .recv_timeout(timeout())
                .map_err(|_| fail("fake DNS server thread did not stop before the deadline"))
        }
    }

    /// `nsenter --net=<pin>` で入り直した自身の再入モード。引数は `<resolv.conf> <qname> <expected-ip>`。
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
        let [path, name, want] = args else {
            return Err("expected <resolv.conf> <qname> <ip>".to_owned());
        };
        let want_ip: Ipv4Addr = want.parse().map_err(|e| format!("parse {want}: {e}"))?;
        // resolv.conf は小さい前提のため長さを上限で切って読む。
        let mut text = String::new();
        fs::File::open(path)
            .and_then(|f| f.take(4096).read_to_string(&mut text))
            .map_err(|e| format!("read {path}: {e}"))?;
        let server: IpAddr = text
            .lines()
            .filter_map(|l| l.strip_prefix("nameserver "))
            .find_map(|v| v.trim().parse::<IpAddr>().ok())
            .ok_or_else(|| format!("no nameserver in resolv.conf: {text:?}"))?;
        let id = u16::try_from(std::process::id() & 0xffff).map_err(|e| e.to_string())?;
        let query = a_query(id, name).ok_or("invalid qname")?;
        let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
        sock.set_read_timeout(Some(timeout()))
            .map_err(|e| format!("set_read_timeout: {e}"))?;
        sock.send_to(&query, SocketAddr::new(server, 53))
            .map_err(|e| format!("send to {server}:53: {e}"))?;
        let mut buf = [0u8; MAX_DATAGRAM_LEN];
        let (n, from) = sock
            .recv_from(&mut buf)
            .map_err(|e| format!("no reply from {server}:53: {e}"))?;
        if from.ip() != server {
            return Err(format!("reply came from {from}, expected {server}"));
        }
        let resp = buf.get(..n).ok_or("short buffer")?;
        match answer_matches(resp, &query, id, want_ip) {
            Some(true) => Ok(()),
            _ => Err(format!("unexpected reply: {resp:?}")),
        }
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
                println!("static_dns_privileged: failed: {e}");
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
        let gateway = IpPrefix::new(GATEWAY.parse().map_err(|_| fail("addr"))?, 24)?;
        let name = NetworkName::new(NETWORK)?;
        let mut ipam = StaticIpam::new(&name, gateway)?;
        let spec = NetworkCreateSpec::new(NetworkName::new(NETWORK)?, gateway)?
            .with_name_resolution(NameResolution::StaticHosts);
        let net = create_network(&route, &nft, &spec, t)
            .map_err(|e| fail(format!("create_network failed at {:?}: {e}", e.step)))?;

        let mut ports = PortRegistry::new();
        let mut attached = Vec::new();
        let result = run_body(
            &net,
            &route,
            &nft,
            &base,
            &mut ipam,
            &mut ports,
            &mut attached,
        );

        // 後始末（必ず実行）: ネットワーク削除（bridge とともに secondary アドレスも消える）。
        let deleted = delete_network(&route, &nft, &net, attached, &mut ipam, &mut ports, t)
            .map(|_| ())
            .map_err(|e| fail(format!("delete_network failed: {e}")));
        let msgs: Vec<String> = [("body", result), ("delete", deleted)]
            .into_iter()
            .filter_map(|(label, r)| r.err().map(|e| format!("{label}: {e}")))
            .collect();
        if msgs.is_empty() {
            Ok(())
        } else {
            Err(fail(msgs.join("; ")))
        }
    }

    fn run_body(
        net: &CreatedNetwork,
        route: &NetlinkRouteSocket,
        nft: &NetlinkNetfilterSocket,
        base: &Path,
        ipam: &mut StaticIpam,
        ports: &mut PortRegistry,
        attached: &mut Vec<AttachedContainer<ContainerNetns>>,
    ) -> Result<(), NetError> {
        let t = timeout();
        let exe = std::env::current_exe().map_err(|e| fail(format!("current_exe: {e}")))?;
        let exe_str = exe.to_str().ok_or_else(|| fail("exe path is not UTF-8"))?;
        let c1 = EndpointId::new("c1")?;
        let spec1 = ContainerAttachSpec::new(c1.clone(), net, base.to_path_buf())?;
        let a1 = attach_container(route, nft, &spec1, ipam, ports, t)
            .map_err(|e| fail(format!("attach c1 failed at {:?}: {e}", e.step)))?;
        let c1_ip = a1.address.addr();
        let pin1 = a1
            .netns_path
            .to_str()
            .ok_or_else(|| fail("pin path is not UTF-8"))
            .map(str::to_owned);
        attached.push(a1);
        let pin1 = pin1?;

        // NET-7 の参照カウント経由でも DNS ヘルパーは起動しない。
        let rc = DnsHelperRefCounts::new(ProcessLauncher::new(
            exe.clone(),
            READY_TIMEOUT_DEFAULT,
            REAP_TIMEOUT_DEFAULT,
        )?);
        expect_eq(
            "join_network",
            rc.join_network(net, &c1)?,
            JoinOutcome::HelperDisabled,
        )?;
        expect_eq("helper running", rc.is_running(&net.name), false)?;
        let listen = DnsListenAddr::for_network(net)?.socket_addr();
        let udp53 = udp_local_addrs()?.iter().filter(|a| **a == listen).count();
        expect_eq("udp sockets on gateway:53", udp53, 0)?;

        // 指定サーバーは bridge の secondary アドレス（同一サブネット。コンテナは ARP で直接到達する）。
        let server_ip: IpAddr = DNS_SERVER.parse().map_err(|_| fail("dns addr"))?;
        route.add_address(
            &AddressSpec::new(
                net.bridge_index,
                IpPrefix::new(server_ip, 32)?,
                AddrScope::Universe,
            ),
            t,
        )?;
        // 待受は probe より前に確立する（bind 後にスレッドへ渡す）。
        let server_sock = UdpSocket::bind(SocketAddr::new(server_ip, 53))
            .map_err(|e| fail(format!("bind {DNS_SERVER}:53: {e}")))?;
        let server = FakeDns::spawn(server_sock, Some(ANSWER_IP))?;
        // 対照: DNS ヘルパーの待受位置 gateway:53 のデコイ。ここへ届いたらクエリが直接性を失っている。
        let decoy = UdpSocket::bind(listen)
            .map_err(|e| fail(format!("bind decoy {listen}: {e}")))
            .and_then(|s| FakeDns::spawn(s, None));
        let decoy = match decoy {
            Ok(d) => d,
            Err(e) => {
                let _ = server.finish();
                return Err(e);
            }
        };

        let probed = probe_through_resolv_conf(net, base, exe_str, &pin1, DNS_SERVER);
        // 成否にかかわらずスレッドを停止してログを回収する。
        let server_log = server.finish();
        let decoy_log = decoy.finish();
        probed?;
        let server_log = server_log?;
        let decoy_log = decoy_log?;

        for (from, qname, qtype) in &server_log {
            println!("static_dns_privileged: server log: from={from} qname={qname} qtype={qtype}");
        }
        if server_log.is_empty() {
            return Err(fail("the specified --dns server received no query"));
        }
        let qname = probe_qname();
        for (from, got, qtype) in &server_log {
            expect_eq("query source ip", from.ip(), c1_ip)?;
            expect_eq("query name", got.as_str(), qname.as_str())?;
            expect_eq("query type", *qtype, 1u16)?;
        }
        expect_eq("decoy (gateway:53) queries", decoy_log.len(), 0)?;
        Ok(())
    }

    /// 一意トークン入りの QNAME（`.test` は RFC 6761 の予約 TLD で実在名と衝突しない）。
    fn probe_qname() -> String {
        format!("probe-{}.fandhe.test", std::process::id())
    }

    /// `apply_static_dns` で `resolv.conf` を書き、c1 の netns から probe を実行する。
    fn probe_through_resolv_conf(
        net: &CreatedNetwork,
        base: &Path,
        exe_str: &str,
        pin: &str,
        dns: &str,
    ) -> Result<(), NetError> {
        let resolv = base.join("resolv.conf");
        let out = apply_static_dns(net, &[dns], &resolv, &NoopNetOpRecorder)?;
        expect_eq(
            "apply_static_dns outcome",
            out,
            StaticDnsOutcome::Applied(DnsApplyOutcome::Written {
                count: 1,
                persistence: PersistGuarantee::Durable,
            }),
        )?;
        let written =
            fs::read_to_string(&resolv).map_err(|e| fail(format!("read resolv.conf: {e}")))?;
        expect_eq(
            "resolv.conf content",
            written.as_str(),
            format!("# Generated by fandhe-container (NET-12)\nnameserver {dns}\n").as_str(),
        )?;
        let resolv_str = resolv
            .to_str()
            .ok_or_else(|| fail("resolv.conf path is not UTF-8"))?;
        let pin_arg = format!("--net={pin}");
        let qname = probe_qname();
        let want = ANSWER_IP.to_string();
        let out = run_cmd(
            "nsenter",
            &[&pin_arg, exe_str, "--probe", resolv_str, &qname, &want],
        )?;
        if out.trim() != "probe: ok" {
            return Err(fail(format!("unexpected probe output: {out}")));
        }
        Ok(())
    }
}
