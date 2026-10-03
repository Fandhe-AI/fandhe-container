//! ユーザー定義ネットワークの統合 API（`create_network` / `attach_container` / `delete_network`）を通しで使う
//! 3 経路疎通の実機前提結合試験と、作成・接続・削除の所要時間計測（NET-1・NET-4・TASK-139.5・#318・MS-8）。
//!
//! NET-1 の期待「同一 bridge 上のコンテナ間・ホスト⇔コンテナ間・ポート公開経由の 3 経路すべてで疎通する」を、
//! link やルールを手組みせず統合 API だけで組み上げた状態で実カーネルに照合する。ルール単位の検証は
//! `nftables_paths_privileged`（TASK-138.4）が担い、本テストは統合 API の組み合わせが成立することを確かめる。
//!
//! - (a) 同一 bridge 上のコンテナ間: c1 -> c2
//! - (b) ホスト -> コンテナ: テストプロセス（ホスト役）が bridge アドレスから c1 へ
//! - (c) ポート公開（DNAT）: ホスト自身が非ループバックの外側アドレス `10.214.1.1:18080`（UDP）へ送る通信が
//!   OUTPUT フック（`LocalOut`）の DNAT で c1 の `9080` へ届く（PoC-15 も同じ経路で計測している）
//!
//! root と util-linux の `unshare` / `nsenter` / `mount` が必要な実機前提テストのため `harness = false` の
//! 独自 `main` で動かし、`--ignored`（3 経路疎通）または `--measure`（所要時間計測）を付けたときだけ実行する
//! （未指定時は「ignored」を出力して成功終了する分離であり、CI 通過のための弱体化ではない。`AGENTS.md`
//! 「実機前提テスト」節）。非 Linux では対象外（skip ではなく OS 非該当）。
//!
//! # トポロジー
//!
//! ```text
//! c1 (10.214.0.2/24, 公開 udp 18080 -> 9080)   c2 (10.214.0.3/24)      netns は attach_container が作成・pin
//!    | veth                                       | veth
//!    +------------ bridge (10.214.0.1/24) --------+
//! host（テストプロセス自身。隔離 netns の中）
//!    | veth fcox0 (10.214.1.1/24) <-> fcox1       外側アドレス用。両端とも同じ netns に残して up
//! ```
//!
//! # 流れ
//!
//! - ランチャ（host netns・root）: 0700 の一時ディレクトリを作り、`unshare --net --mount -- <exe> --inner ...` で
//!   新しい netns・mount namespace の子を起動して終了コードを引き継ぐ。終了後に一時ディレクトリを消す
//!   （`network_attach_privileged` のランチャを踏襲）
//! - inner（新 netns・新 mount namespace の中）: `/` を rprivate にして tmpfs を載せ、`lo` と外側アドレスを用意する。
//!   `create_network` -> `attach_container` x2（c1 はポート公開つき）-> 3 経路の照合 -> `delete_network` の順
//! - コンテナ側の待受・送信は `nsenter --net=<pin> -- <exe> --child <addr>` の子プロセスが行う
//!   （`setns` を直接呼ぶと `sys` 外の unsafe になるため使わない）。stdin / stdout の行プロトコル
//!   （`listen` / `recv` / `send`）は `nftables_paths_privileged` を踏襲し、送信ごとに別ソケットを保持して
//!   送信元ポートの重複（conntrack エントリ再利用による誤判定）を検査する
//!
//! # 対象外の経路
//!
//! external netns から PREROUTING を通る DNAT と、コンテナ発の masquerade は検証しない。masquerade 本体は
//! `network.rs` で未実装（REPAIR-3）であり、PREROUTING 側のルール単位の検証は `nftables_paths_privileged` が行う。
//! `ip_forward` は変更しない。
//!
//! # 所要時間計測（`--measure --trials N --warmup W`）
//!
//! 1 試行は `create_network` -> `attach_container`（ポート公開なし）-> `delete_network` の 3 操作で、各 API 呼び出しの
//! 前後を `Instant` で計る。1 操作 1 行の JSONL を stdout へ出す。数値と固定文字列だけを出力し、エラー文言や
//! アドレスは載せない。集計と TASK-140 向けの JSON 化は `scripts/bench/net_setup_timing.sh` が行う。
//! `N` は 1..=200、`W` は 0..=20 に上限検証する（範囲外は即失敗）。
//!
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。前提（root・
//! 外部コマンド）を満たさない場合は skip せず失敗する。実機（root）での実行結果は TASK-140 で人間が記録する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("network_paths_privileged: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--child") {
        linux::child(&args);
    } else if args.iter().any(|a| a == "--inner") {
        linux::inner(&args);
    } else if args.iter().any(|a| a == "--ignored") {
        linux::launcher(Vec::new());
    } else if args.iter().any(|a| a == "--measure") {
        linux::launcher(linux::measure_args(&args));
    } else {
        println!(
            "network_paths_privileged: ignored (requires root, `unshare`, `nsenter`; run the built executable with `--ignored` or `--measure` under `sudo`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::mpsc::{self, Receiver};
    use std::time::{Duration, Instant};

    use fandhe_container_net::error::{NetError, NetErrorCode};
    use fandhe_container_net::netlink_route::{
        AddrScope, AddressSpec, IfName, IpPrefix, LinkCreate, LinkRef, LinkSet, NetlinkRouteSocket,
    };
    use fandhe_container_net::network::{
        ContainerAttachSpec, CreatedNetwork, EndpointId, NetworkCreateSpec, NetworkName,
        PortProtocol, PortPublish, PortRegistry, StaticIpam, attach_container, create_network,
        delete_network,
    };
    use fandhe_container_net::nftables_batch::NetlinkNetfilterSocket;

    const LAUNCHER_PID_ENV: &str = "FANDHE_PATHS_TEST_LAUNCHER_PID";
    const INNER_PID_ENV: &str = "FANDHE_PATHS_TEST_INNER_PID";
    const DIR_ENV: &str = "FANDHE_PATHS_TEST_DIR";
    const OK_PREFIX: &str = "network_paths_privileged: three paths verified";
    const PAYLOAD: &[u8] = b"fandhe";
    /// 公開ポート（DNAT 前の宛先ポート）。
    const HOST_PORT: u16 = 18080;
    /// c1 が待ち受けるポート（DNAT 後の宛先。書き換え自体を検証するため別の値にする）。
    const CONT_PORT: u16 = 9080;
    /// 経路 (a) の c2 の待受ポート。
    const PORT_A: u16 = 9101;
    /// 経路 (b) の c1 の待受ポート。
    const PORT_B: u16 = 9102;
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 214, 0, 1);
    const C1_ADDR: Ipv4Addr = Ipv4Addr::new(10, 214, 0, 2);
    const C2_ADDR: Ipv4Addr = Ipv4Addr::new(10, 214, 0, 3);
    /// ホストの非ループバックな外側アドレス（ポート公開の宛先）。
    const HOST_OUTER: Ipv4Addr = Ipv4Addr::new(10, 214, 1, 1);
    const OUTER0: &str = "fcox0";
    const OUTER1: &str = "fcox1";
    /// 計測の試行数・ウォームアップ数の上限と既定（PoC-15 の既定は 20 試行）。
    const TRIALS_MAX: u32 = 200;
    const TRIALS_DEFAULT: u32 = 20;
    const WARMUP_MAX: u32 = 20;
    const WARMUP_DEFAULT: u32 = 1;
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

    fn v4(a: Ipv4Addr) -> IpAddr {
        IpAddr::V4(a)
    }

    fn ifname(s: &str) -> Result<IfName, NetError> {
        IfName::new(s)
    }

    /// `--flag <u32>` を取り出す（未指定は既定値。範囲外・非数値は `None` で呼び出し側が失敗させる）。
    fn flag_value(args: &[String], flag: &str, default: u32, max: u32, min: u32) -> Option<u32> {
        match args.iter().position(|a| a == flag) {
            None => Some(default),
            Some(i) => args
                .get(i + 1)
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|v| (min..=max).contains(v)),
        }
    }

    /// 計測モードの引数を検証して inner へ渡す形にする。範囲外は即失敗（上限検証。REPAIR-5 の資源上限）。
    pub fn measure_args(args: &[String]) -> Vec<String> {
        let trials = flag_value(args, "--trials", TRIALS_DEFAULT, TRIALS_MAX, 1);
        let warmup = flag_value(args, "--warmup", WARMUP_DEFAULT, WARMUP_MAX, 0);
        match (trials, warmup) {
            (Some(t), Some(w)) => vec![
                "--measure".into(),
                "--trials".into(),
                t.to_string(),
                "--warmup".into(),
                w.to_string(),
            ],
            _ => {
                eprintln!(
                    "network_paths_privileged: invalid --trials (1..={TRIALS_MAX}) or --warmup (0..={WARMUP_MAX})"
                );
                std::process::exit(2);
            }
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

    /// プロセスグループ `pgid` の全員に SIGKILL を送り、グループが空になる（`kill -0` が失敗する）まで
    /// 期限つきで待つ。空になったことを確認できたら true（外部 `kill` コマンド経由で `sys` 外の unsafe を避ける）。
    fn kill_group(pgid: u32) -> bool {
        let target = format!("-{pgid}");
        let signal = |sig: &str| {
            Command::new("kill")
                .args([sig, "--", &target])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };
        let _ = signal("-KILL");
        let deadline = Instant::now() + timeout();
        loop {
            if !signal("-0") {
                return true;
            }
            if Instant::now() >= deadline {
                eprintln!(
                    "network_paths_privileged: process group {pgid} still alive after SIGKILL"
                );
                return false;
            }
            let _ = signal("-KILL");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// ランチャ（host netns の root プロセス）。自身では何も変更せず、一時ディレクトリを作って inner を起動する。
    pub fn launcher(extra: Vec<String>) {
        require_root_and_tools();
        let dir = std::env::temp_dir().join(format!("fandhe-paths-test-{}", std::process::id()));
        fs::create_dir(&dir).expect("create temp dir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod temp dir");
        let exe = std::env::current_exe().expect("current_exe");
        // 専用プロセスグループで起動し、期限切れ時に inner・nsenter・その配下の子孫をまとめて停止できるようにする。
        let mut child = Command::new("unshare")
            .process_group(0)
            .args(["--net", "--mount", "--"])
            .arg(exe)
            .arg("--inner")
            .args(extra)
            .env(LAUNCHER_PID_ENV, std::process::id().to_string())
            .env(DIR_ENV, &dir)
            .spawn()
            .expect("spawn unshare --net --mount");
        // 計測は最大 (200 + 20) 試行になり得るため、期限は試行数に依らず固定倍率にせず十分長く取る。
        let pgid = child.id();
        let deadline = Instant::now() + timeout() * 60;
        let code = loop {
            match child.try_wait().expect("wait inner") {
                Some(st) => break st.code().unwrap_or(1),
                None if Instant::now() >= deadline => {
                    kill_group(pgid);
                    let _ = child.wait();
                    eprintln!("network_paths_privileged: inner did not finish before deadline");
                    break 1;
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        // 正常終了でも取り残された子孫があればグループごと停止し、消えたことを確認する（特権操作の後始末）。
        // mount namespace・tmpfs・netns の pin は全プロセスの終了で解放される。
        let code = if kill_group(pgid) { code } else { 1 };
        // mount namespace は inner の終了で消えるので、host 側には空のディレクトリだけが残る。
        let _ = fs::remove_dir(&dir);
        std::process::exit(code);
    }

    /// 自プロセスが「作成直後の新規 network namespace」にいることを検証する（fail-closed）。
    /// `network_attach_privileged` の同名関数を踏襲（tests 間の共有機構は持たない）。
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
                "`--inner` must be started by the launcher; refusing to run",
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

    /// inner の共通準備: 隔離の確認 -> rprivate + tmpfs -> 一時ディレクトリのパスを返す。
    fn prepare_isolation() -> Result<PathBuf, NetError> {
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
        Ok(base)
    }

    fn create_spec(name: &str) -> Result<NetworkCreateSpec, NetError> {
        NetworkCreateSpec::new(NetworkName::new(name)?, IpPrefix::new(v4(GATEWAY), 24)?)
    }

    pub fn inner(args: &[String]) {
        let measuring = args.iter().any(|a| a == "--measure");
        let result = if measuring {
            let trials = flag_value(args, "--trials", TRIALS_DEFAULT, TRIALS_MAX, 1);
            let warmup = flag_value(args, "--warmup", WARMUP_DEFAULT, WARMUP_MAX, 0);
            match (trials, warmup) {
                (Some(t), Some(w)) => measure(t, w),
                _ => Err(fail("invalid --trials or --warmup")),
            }
        } else {
            verify_paths()
        };
        if let Err(e) = result {
            // 計測モードの stdout は JSONL 専用なので、診断は stderr へ出す。
            eprintln!("network_paths_privileged: failed: {e}");
            std::process::exit(1);
        }
    }

    // ---- 子（c1 / c2。コンテナ netns の中）----

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
    /// 保持したソケットは close しない（close すると次の bind(0) が同じポートを再利用し、既存 conntrack
    /// エントリが配送先判定を誤らせ得るため）。保持中のポートとの重複は送信前に検査して fail-closed にする。
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

    /// `--child <addr>` の入口。`nsenter` で inner の直下に起動されたときだけ動く。
    pub fn child(args: &[String]) {
        if let Err(e) = child_inner(args) {
            println!("network_paths_privileged: child failed: {e}");
            std::process::exit(1);
        }
    }

    fn child_inner(args: &[String]) -> Result<(), NetError> {
        // `--child` は直接起動できてしまうため、親が inner であることを確認する（fail-closed）。
        // `nsenter` は fork せず exec するので、親は nsenter を起動した inner のままである。
        let expected = std::env::var(INNER_PID_ENV)
            .ok()
            .and_then(|v| v.parse::<u32>().ok());
        if expected != Some(std::os::unix::process::parent_id()) {
            return Err(fail("`--child` must be started by `--inner`; refusing"));
        }
        let addr: Ipv4Addr = args
            .iter()
            .position(|a| a == "--child")
            .and_then(|i| args.get(i + 1))
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| fail("missing or invalid child address"))?;
        let mut listeners: Vec<(u16, UdpSocket)> = Vec::new();
        let mut held_senders: Vec<(u16, UdpSocket)> = Vec::new();
        say("ready");
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

    // ---- 親（inner。隔離 netns の中のテストプロセス）----

    /// drop で子を kill して wait するガード（失敗経路でも子を残さない。名前一致の `pkill` は使わない）。
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
        /// `netns_path` の netns に入って `--child <addr>` を起動する。
        fn spawn(role: &'static str, netns_path: &Path, addr: Ipv4Addr) -> Result<Self, NetError> {
            let exe = std::env::current_exe().map_err(|e| fail(format!("current_exe: {e}")))?;
            let mut netns_arg = std::ffi::OsString::from("--net=");
            netns_arg.push(netns_path);
            let mut child = Command::new("nsenter")
                .arg(netns_arg)
                .arg("--")
                .arg(exe)
                .args(["--child", &addr.to_string()])
                .env(INNER_PID_ENV, std::process::id().to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .map_err(|e| fail(format!("spawn nsenter: {e}")))?;
            let stdin = child.stdin.take();
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| fail("child stdout missing"))?;
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
            Ok(Self {
                role,
                child,
                stdin,
                lines: rx,
            })
        }

        /// 期限内に `prefix` で始まる行が来るまで読み、その行を返す。
        fn expect_prefix(&self, prefix: &str) -> Result<String, NetError> {
            let deadline = Instant::now() + timeout();
            let mut skipped = Vec::new();
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match self.lines.recv_timeout(left) {
                    Ok(l) if l.starts_with(prefix) => return Ok(l),
                    Ok(l) => skipped.push(l),
                    Err(e) => {
                        return Err(fail(format!(
                            "{} did not print {prefix:?} before deadline: {e}; other lines: {skipped:?}",
                            self.role
                        )));
                    }
                }
            }
        }

        fn send(&mut self, line: &str) -> Result<(), NetError> {
            let stdin = self
                .stdin
                .as_mut()
                .ok_or_else(|| fail("child stdin closed"))?;
            stdin
                .write_all(format!("{line}\n").as_bytes())
                .and_then(|()| stdin.flush())
                .map_err(|e| fail(format!("write to child: {e}")))
        }

        fn listen(&mut self, port: u16) -> Result<(), NetError> {
            self.send(&format!("listen {port}"))?;
            self.expect_prefix("listening").map(|_| ())
        }

        /// 子から `dst` へ新しいソケットで送り、使った送信元ポートを返す。`used` は同一子の過去の送信元
        /// ポートで、子の検査に加えて親側でも重複しないことを照合する。
        fn send_to(&mut self, dst: (Ipv4Addr, u16), used: &mut Vec<u16>) -> Result<u16, NetError> {
            self.send(&format!("send {} {}", dst.0, dst.1))?;
            let line = self.expect_prefix("sent ")?;
            let port = line
                .strip_prefix("sent ")
                .and_then(|p| p.parse::<u16>().ok())
                .ok_or_else(|| fail(format!("unparsable sent line: {line:?}")))?;
            if used.contains(&port) {
                return Err(fail(format!(
                    "source port {port} reused (previous ports: {used:?})"
                )));
            }
            used.push(port);
            Ok(port)
        }

        /// 子の待受が受けた送信元を返す。
        fn recv(&mut self, port: u16) -> Result<SocketAddr, NetError> {
            self.send(&format!("recv {port}"))?;
            let line = self.expect_prefix("peer ")?;
            line.strip_prefix("peer ")
                .and_then(|r| r.parse::<SocketAddr>().ok())
                .ok_or_else(|| fail(format!("unparsable peer line: {line:?}")))
        }

        /// stdin を閉じて子の正常終了を期限つきで待つ（期限切れは drop の kill に任せる）。
        fn finish(mut self) -> Result<(), NetError> {
            self.stdin = None;
            let deadline = Instant::now() + timeout();
            loop {
                match self
                    .child
                    .try_wait()
                    .map_err(|e| fail(format!("wait child: {e}")))?
                {
                    Some(st) if st.success() => return Ok(()),
                    Some(st) => return Err(fail(format!("{} exited with {st}", self.role))),
                    None if Instant::now() >= deadline => {
                        return Err(fail(format!("{} did not exit before deadline", self.role)));
                    }
                    None => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        }
    }

    /// ホスト（inner 自身）から `src` を bind して `dst` へ送る。
    fn host_send(
        held: &mut Vec<(u16, UdpSocket)>,
        src: Ipv4Addr,
        dst: (Ipv4Addr, u16),
    ) -> Result<u16, NetError> {
        send_fresh(held, src, SocketAddr::new(v4(dst.0), dst.1))
    }

    fn expect_eq<T: PartialEq + std::fmt::Debug>(
        got: T,
        want: T,
        what: &str,
    ) -> Result<(), NetError> {
        if got == want {
            Ok(())
        } else {
            Err(fail(format!("{what}: got {got:?}, expected {want:?}")))
        }
    }

    /// `lo` を up にし、外側アドレス用の veth ペア（両端とも inner の netns に残す）を作って up、
    /// 片端に `HOST_OUTER/24` を付ける。ローカル宛て配送には `lo` が up である必要がある。
    fn prepare_outer_address(route: &NetlinkRouteSocket) -> Result<(), NetError> {
        let t = timeout();
        route.set_link(&LinkSet::up(LinkRef::Name(ifname("lo")?)), t)?;
        route.create_link(&LinkCreate::veth(ifname(OUTER0)?, ifname(OUTER1)?)?, t)?;
        route.set_link(&LinkSet::up(LinkRef::Name(ifname(OUTER1)?)), t)?;
        route.set_link(&LinkSet::up(LinkRef::Name(ifname(OUTER0)?)), t)?;
        let idx = route.link_index(&ifname(OUTER0)?, t)?;
        route.add_address(
            &AddressSpec::new(idx, IpPrefix::new(v4(HOST_OUTER), 24)?, AddrScope::Universe),
            t,
        )?;
        Ok(())
    }

    fn gone(route: &NetlinkRouteSocket, name: &IfName, t: Duration) -> bool {
        matches!(
            route.link_index(name, t),
            Err(ref e) if e.code() == NetErrorCode::NotFound
        )
    }

    /// 3 経路疎通の照合本体（`--ignored`）。
    fn verify_paths() -> Result<(), NetError> {
        let base = prepare_isolation()?;
        let route = NetlinkRouteSocket::open()?;
        let nft = NetlinkNetfilterSocket::open()?;
        let t = timeout();
        prepare_outer_address(&route)?;

        let net = create_network(&route, &nft, &create_spec("pth")?, t)
            .map_err(|e| fail(format!("create_network failed at {:?}: {e}", e.step)))?;
        let mut ipam = StaticIpam::for_network(&net)?;
        let mut ports = PortRegistry::new();

        // c1 はポート公開つき（udp 10.214.1.1:18080 -> 9080）、c2 は公開なし。
        let publish = PortPublish::new(PortProtocol::Udp, HOST_OUTER, HOST_PORT, CONT_PORT)?;
        let spec1 = ContainerAttachSpec::new(EndpointId::new("c1")?, &net, base.clone())?
            .with_port_publishes(vec![publish])?;
        let c1_attached = attach_container(&route, &nft, &spec1, &mut ipam, &mut ports, t)
            .map_err(|e| fail(format!("attach c1 failed at {:?}: {e}", e.step)))?;
        let spec2 = ContainerAttachSpec::new(EndpointId::new("c2")?, &net, base.clone())?;
        let c2_attached = attach_container(&route, &nft, &spec2, &mut ipam, &mut ports, t)
            .map_err(|e| fail(format!("attach c2 failed at {:?}: {e}", e.step)))?;
        expect_eq(
            c1_attached.address,
            IpPrefix::new(v4(C1_ADDR), 24)?,
            "c1 address",
        )?;
        expect_eq(
            c2_attached.address,
            IpPrefix::new(v4(C2_ADDR), 24)?,
            "c2 address",
        )?;

        let mut c1 = ChildGuard::spawn("c1", &c1_attached.netns_path, C1_ADDR)?;
        let mut c2 = ChildGuard::spawn("c2", &c2_attached.netns_path, C2_ADDR)?;
        c1.expect_prefix("ready")?;
        c2.expect_prefix("ready")?;
        c1.listen(PORT_B)?;
        c1.listen(CONT_PORT)?;
        c2.listen(PORT_A)?;

        let mut c1_ports = Vec::new();
        let mut host_held: Vec<(u16, UdpSocket)> = Vec::new();
        let mut host_ports: Vec<u16> = Vec::new();
        let mut track = |p: u16| -> Result<(), NetError> {
            if host_ports.contains(&p) {
                return Err(fail(format!("host source port {p} reused: {host_ports:?}")));
            }
            host_ports.push(p);
            Ok(())
        };

        // (a) c1 -> c2。
        let pa = c1.send_to((C2_ADDR, PORT_A), &mut c1_ports)?;
        let a = c2.recv(PORT_A)?;
        expect_eq(a, SocketAddr::new(v4(C1_ADDR), pa), "path (a)")?;
        // (b) ホスト -> c1（bridge アドレスから）。
        let pb = host_send(&mut host_held, GATEWAY, (C1_ADDR, PORT_B))?;
        track(pb)?;
        let b = c1.recv(PORT_B)?;
        expect_eq(b, SocketAddr::new(v4(GATEWAY), pb), "path (b)")?;
        // (c) ホスト自身の外側アドレス宛てが OUTPUT の DNAT で c1 の CONT_PORT に届く。
        let pc = host_send(&mut host_held, HOST_OUTER, (HOST_OUTER, HOST_PORT))?;
        track(pc)?;
        let c = c1.recv(CONT_PORT)?;
        expect_eq(c, SocketAddr::new(v4(HOST_OUTER), pc), "path (c)")?;

        c1.finish()?;
        c2.finish()?;

        // 削除: c1 と c2 を渡し、取り残しが無く、bridge が消えていること。
        let bridge = net.bridge.clone();
        let hosts = [c1_attached.host_veth.clone(), c2_attached.host_veth.clone()];
        let pins = [
            c1_attached.netns_path.clone(),
            c2_attached.netns_path.clone(),
        ];
        let report = delete_network(
            &route,
            &nft,
            &net,
            vec![c1_attached, c2_attached],
            &mut ipam,
            &mut ports,
            t,
        )
        .map_err(|e| {
            fail(format!(
                "delete_network failed at {:?}: {e}; report: {:?}",
                e.step, e.report
            ))
        })?;
        if !report.leftover.is_empty() {
            return Err(fail(format!("unexpected leftover: {:?}", report.leftover)));
        }
        if !gone(&route, &bridge, t) {
            return Err(fail("bridge still exists after delete_network"));
        }
        for host in &hosts {
            if !gone(&route, host, t) {
                return Err(fail(format!("veth {} still exists", host.as_str())));
            }
        }
        for pin in &pins {
            if pin.exists() {
                return Err(fail(format!("pin {} still exists", pin.display())));
            }
        }
        println!("{OK_PREFIX} a={a} b={b} c={c} (NET-1)");
        Ok(())
    }

    /// 経過時間を 3 桁小数のミリ秒で出す JSONL 行（数値と固定文字列のみ。手組みしても注入経路が無い）。
    fn emit(trial: u32, warmup: bool, op: &str, elapsed: Duration, ok: bool) {
        let ms = elapsed.as_secs_f64() * 1000.0;
        println!(
            "{{\"trial\":{trial},\"warmup\":{warmup},\"op\":\"{op}\",\"elapsed_ms\":{ms:.3},\"ok\":{ok}}}"
        );
        let _ = std::io::stdout().flush();
    }

    /// 作成・接続・削除の所要時間計測（`--measure`）。失敗した操作は `ok:false` を出して即中断する。
    fn measure(trials: u32, warmup: u32) -> Result<(), NetError> {
        let base = prepare_isolation()?;
        let route = NetlinkRouteSocket::open()?;
        let nft = NetlinkNetfilterSocket::open()?;
        let t = timeout();
        for i in 0..(trials + warmup) {
            let is_warmup = i < warmup;
            let trial = if is_warmup { i } else { i - warmup };
            let net_name = format!("mt{i}");
            let net_spec = create_spec(&net_name)?;
            let ep = EndpointId::new(&format!("mt{i}c1"))?;

            let start = Instant::now();
            let created = create_network(&route, &nft, &net_spec, t);
            let elapsed = start.elapsed();
            emit(trial, is_warmup, "net_create", elapsed, created.is_ok());
            let net: CreatedNetwork = created.map_err(|e| fail(format!("create: {:?}", e.step)))?;

            let mut ipam = StaticIpam::for_network(&net)?;
            let mut ports = PortRegistry::new();
            let spec = ContainerAttachSpec::new(ep, &net, base.clone())?;
            let start = Instant::now();
            let attached = attach_container(&route, &nft, &spec, &mut ipam, &mut ports, t);
            let elapsed = start.elapsed();
            emit(
                trial,
                is_warmup,
                "container_attach",
                elapsed,
                attached.is_ok(),
            );
            let attached = attached.map_err(|e| fail(format!("attach: {:?}", e.step)))?;

            let start = Instant::now();
            let deleted =
                delete_network(&route, &nft, &net, vec![attached], &mut ipam, &mut ports, t);
            let elapsed = start.elapsed();
            let ok = deleted.as_ref().is_ok_and(|r| r.leftover.is_empty());
            emit(trial, is_warmup, "net_delete", elapsed, ok);
            if !ok {
                return Err(fail("delete failed or left resources behind"));
            }
        }
        Ok(())
    }
}
