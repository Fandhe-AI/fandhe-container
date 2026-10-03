//! DNS ヘルパーを bridge 上のネットワーク用 netns で起動し、コンテナ netns から UDP で疎通する実機結合試験
//! （NET-5・TASK-141.1・#321・MS-8）。
//!
//! root と util-linux の `unshare` / `nsenter` / `mount` が必要な実機前提テストのため `harness = false` の
//! 独自 `main` で動かし、`-- --ignored` を付けたときだけ実行する（未指定時は「ignored」を出力して成功終了
//! する分離であり、CI 通過のための弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では対象外。
//!
//! # 流れ
//! - ランチャ（host netns・root）: 0700 の一時ディレクトリを作り、`unshare --net --mount -- <exe> --inner` で
//!   子を起動して終了コードを引き継ぐ
//! - 子（新 netns・新 mount namespace。ネットワーク用 netns にあたる）: tmpfs を載せ、`create_network` と
//!   `attach_container`（c1）を実行し、`spawn_dns_helper` で自身（`--listen` モード）を gateway:53 で起動する。
//!   ヘルパーの netns が子と同一でランチャとは別であることを `/proc/<pid>/ns/net` の inode で照合し、
//!   `nsenter --net=<pin> <exe> --dns-client <gateway:53>` でコンテナ netns からクエリを送る
//!   （不正パケットは無応答・続く正常クエリには応答 = ヘルパー生存の証明）。最後に回収と `delete_network`
//!
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。前提を満たさない
//! 場合は skip せず失敗する。
//!
//! # 実機計測モード（`--measure`。TASK-141.3・#323・NET-5・MS-8）
//!
//! `scripts/bench/dns_helper_measure.sh` が専用 cgroup と同期ディレクトリを用意して本実行ファイルを
//! `--measure --queries N --warmup W --cgroup <path> --sync-dir <dir>` で呼ぶ。
//! - 計測対象は「本テストバイナリが組み立てた `DnsHelperServer` + `RegistryHandler`」であり、製品の入口
//!   `run_dns_helper_main`（プロセス外から名前を登録する経路が無く NOTIMP 固定。REPAIR-3）ではない。
//!   製品の入口の数値として読んではならない。入口へ登録フラグを足す設計は後続タスクの責務で、本モードは行わない
//! - 系列構成は PoC-15 と同じ: コンテナ netns 2 個（c1・c2）x 登録名 3 個（svc-a・svc-b・svc-c）x N クエリ
//! - 計測専用ヘルパー（`--dns-measure-helper`）は bind・READY より前に自身を専用 cgroup へ参加させる。
//!   スクリプトは `cgroup.procs` から PID を 1 個だけ取って PSS を読む（PoC-15 の sudo の PID 誤計測の再発防止）
//! - 全系列の後に `<sync-dir>/pss-ready` を作り、スクリプトが PSS を読み終えて `pss-done` を作るまで待つ
//! - stdout は 1 クエリ 1 行の JSONL 専用（診断は stderr）。集計はスクリプト側
//!
//! 実機（root）での実行結果は TASK-142（人間）が記録する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("dns_helper_privileged: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.get(1).is_some_and(|a| a == "--listen") {
        // ヘルパー本体（spawn_dns_helper が自身を再実行したとき）。
        return fandhe_container_net::dns_helper::run_dns_helper_main(args.into_iter().skip(1));
    }
    let has = |f: &str| args.iter().any(|a| a == f);
    if has("--dns-client") {
        return linux::client(&args);
    }
    // 計測モード（TASK-141.3・#323）の再入口。ランチャ（--measure）→ inner（--inner-measure）→
    // 計測専用ヘルパー（--dns-measure-helper）／コンテナ側クライアント（--dns-bench）。
    if has("--dns-measure-helper") {
        return linux::measure::helper(&args);
    }
    if has("--dns-bench") {
        return linux::measure::bench(&args);
    }
    if has("--inner-measure") {
        return linux::measure::inner(&args);
    }
    if has("--measure") {
        return linux::measure::launcher(&args);
    }
    if has("--inner") {
        linux::inner();
    } else if has("--ignored") {
        linux::launcher();
    } else {
        println!(
            "dns_helper_privileged: ignored (requires root, `unshare`, `nsenter`; run the built executable with `--ignored` under `sudo`, see AGENTS.md)"
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
    use std::time::{Duration, Instant};

    use fandhe_container_net::dns_helper::{
        DnsListenAddr, READY_TIMEOUT_DEFAULT, REAP_TIMEOUT_DEFAULT, spawn_dns_helper,
    };
    use fandhe_container_net::error::{NetError, NetErrorCode};
    use fandhe_container_net::netlink_route::{IpPrefix, NetlinkRouteSocket};
    use fandhe_container_net::network::{
        ContainerAttachSpec, EndpointId, NetworkCreateSpec, NetworkName, PortRegistry, StaticIpam,
        attach_container, create_network, delete_network,
    };
    use fandhe_container_net::nftables_batch::NetlinkNetfilterSocket;

    const LAUNCHER_PID_ENV: &str = "FANDHE_DNS_TEST_LAUNCHER_PID";
    const DIR_ENV: &str = "FANDHE_DNS_TEST_DIR";
    const OK_LINE: &str =
        "dns_helper_privileged: ok netns=dedicated reachable=yes malformed=dropped (NET-5)";

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
        let dir = std::env::temp_dir().join(format!("fandhe-dns-test-{}", std::process::id()));
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
                    println!("dns_helper_privileged: inner did not finish before deadline");
                    break 1;
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        let _ = fs::remove_dir(&dir);
        std::process::exit(code);
    }

    /// コンテナ netns 側のクライアント（`nsenter --net=<pin> <exe> --dns-client <addr>`）。
    /// 不正パケットが無応答であることと、続く正常クエリへの応答（ID 一致・QR=1・RCODE=4 の NOTIMP。登録経路が無い間）を確認する。
    pub fn client(args: &[OsString]) -> ExitCode {
        let target: Option<SocketAddrV4> = args
            .iter()
            .skip_while(|a| *a != "--dns-client")
            .nth(1)
            .and_then(|a| a.to_str())
            .and_then(|s| s.parse().ok());
        let Some(target) = target else {
            println!("dns client: invalid target");
            return ExitCode::from(2);
        };
        let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            println!("dns client: bind failed");
            return ExitCode::from(1);
        };
        let _ = sock.set_read_timeout(Some(Duration::from_millis(300)));
        let mut buf = [0u8; 600];
        for bad in [
            vec![0u8; 5],
            query(1, 0x8100, 1),
            query(1, 0x0100, 0),
            query(1, 0x0100, 1), // 質問セクション無し
        ] {
            if sock.send_to(&bad, target).is_err() || sock.recv_from(&mut buf).is_ok() {
                println!("dns client: malformed packet was answered or send failed");
                return ExitCode::from(1);
            }
        }
        // 起動直後の取りこぼしに備え、期限内で再送する。
        let deadline = Instant::now() + timeout();
        while Instant::now() < deadline {
            if sock.send_to(&full_query(0x4242), target).is_err() {
                return ExitCode::from(1);
            }
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                let want = vec![0x42, 0x42, 0x81, 0x04, 0, 0, 0, 0, 0, 0, 0, 0];
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

    pub fn inner() {
        match inner_checked() {
            Ok(()) => println!("{OK_LINE}"),
            Err(e) => {
                println!("dns_helper_privileged: failed: {e}");
                std::process::exit(1);
            }
        }
    }

    fn inner_checked() -> Result<(), NetError> {
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
        let net = create_network(
            &route,
            &nft,
            &NetworkCreateSpec::new(
                NetworkName::new("dns")?,
                IpPrefix::new("10.215.0.1".parse().map_err(|_| fail("addr"))?, 24)?,
            )?,
            t,
        )
        .map_err(|e| fail(format!("create_network failed at {:?}: {e}", e.step)))?;
        // create_network 成功後は、どの失敗経路でも逆順（helper 停止 → delete_network）で回収する。
        // ipam を作れない場合は delete_network を呼べないが、子は専用 netns・mount namespace のため
        // 終了時にカーネルが bridge・nft・pin を解放する。
        let mut ipam = StaticIpam::for_network(&net)?;
        let mut ports = PortRegistry::new();
        let mut attached = Vec::new();
        let mut helper = None;
        let result = (|| -> Result<(), NetError> {
            let spec = ContainerAttachSpec::new(EndpointId::new("c1")?, &net, base.clone())?;
            let a = attach_container(&route, &nft, &spec, &mut ipam, &mut ports, t)
                .map_err(|e| fail(format!("attach_container failed at {:?}: {e}", e.step)))?;
            let pin = a
                .netns_path
                .to_str()
                .ok_or_else(|| fail("pin path is not UTF-8"))
                .map(str::to_owned);
            attached.push(a);
            let pin = pin?;

            let exe = std::env::current_exe().map_err(|e| fail(format!("current_exe: {e}")))?;
            let listen = DnsListenAddr::for_network(&net)?;
            let h = spawn_dns_helper(&exe, listen, READY_TIMEOUT_DEFAULT)?;
            let pid = h.pid();
            helper = Some(h);
            let pid = pid.ok_or_else(|| fail("helper has no pid"))?;
            let helper_ns = fs::read_link(format!("/proc/{pid}/ns/net"))
                .map_err(|e| fail(format!("readlink helper netns: {e}")))?;
            if helper_ns != own || helper_ns == parent {
                return Err(fail(
                    "helper is not in the network's own netns (or shares the launcher's)",
                ));
            }
            let exe_str = exe.to_str().ok_or_else(|| fail("exe path is not UTF-8"))?;
            let target = listen.to_string();
            let (ok, out) = run_cmd(
                "nsenter",
                &[&format!("--net={pin}"), exe_str, "--dns-client", &target],
            )?;
            if !ok {
                return Err(fail(format!("container-side dns client failed: {out}")));
            }
            Ok(())
        })();
        let stop = match helper {
            Some(h) => h.stop(REAP_TIMEOUT_DEFAULT),
            None => Ok(()),
        };
        let deleted = delete_network(&route, &nft, &net, attached, &mut ipam, &mut ports, t)
            .map(|_| ())
            .map_err(|e| fail(format!("delete_network failed: {e}")));
        result?;
        stop?;
        deleted
    }

    /// 実機計測モード（`--measure`。TASK-141.3・#323・NET-5）。呼び出し元は `scripts/bench/dns_helper_measure.sh`
    /// （実行ファイルを `--measure` で起動し、stdout の JSONL を集計する）。`dns_helper_privileged` の
    /// 既定経路（`--ignored`）とは独立で、製品コードは変更しない。
    pub mod measure {
        use std::io::{BufRead as _, BufReader, Read as _};
        use std::net::IpAddr;
        use std::path::Path;
        use std::process::Child;
        use std::sync::atomic::AtomicBool;
        use std::sync::{Arc, mpsc};

        use fandhe_container_net::dns_helper::{
            DnsHelperServer, DnsName, DnsRegistry, RegistryHandler, parse_question,
        };

        use super::*;

        const QUERIES_MAX: u32 = 10_000;
        const WARMUP_MAX: u32 = 1_000;
        const RECORDS_MAX: usize = 16;
        /// クエリごとの受信期限。無応答は ok:false で記録する。
        const RECV_TIMEOUT: Duration = Duration::from_millis(500);
        /// 連続無応答がこの回数に達したらヘルパーが死んでいるとみなして打ち切る（REPAIR-5）。
        const MAX_CONSECUTIVE_MISSES: u32 = 50;
        /// svc-c の固定アドレス（レジストリはサブネット内かを検証しない。応答の中身を照合するだけ）。
        const SVC_C_ADDR: &str = "10.215.0.200";
        const CGROUP_ROOT: &str = "/sys/fs/cgroup";
        const CGROUP_PREFIX: &str = "fandhe-dns-measure-";

        /// `--flag <value>` の値を返す。
        fn opt<'a>(args: &'a [OsString], flag: &str) -> Option<&'a str> {
            let i = args.iter().position(|a| a == flag)?;
            args.get(i + 1)?.to_str()
        }

        /// 繰り返し指定された `--flag <value>` の値を全て返す。
        fn opts<'a>(args: &'a [OsString], flag: &str) -> Vec<&'a str> {
            let mut out = Vec::new();
            let mut it = args.iter();
            while let Some(a) = it.next() {
                if a == flag
                    && let Some(v) = it.next().and_then(|v| v.to_str())
                {
                    out.push(v);
                }
            }
            out
        }

        fn bounded(args: &[OsString], flag: &str, max: u32, min: u32) -> Option<u32> {
            opt(args, flag)
                .filter(|v| v.len() <= 5)
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|v| (min..=max).contains(v))
        }

        /// stderr に英語 1 行（code / message）を出す。外部由来の文字列は載せない。
        fn err_line(code: &str, message: &str) {
            eprintln!("error code={code} message={message}");
        }

        /// 専用 cgroup のパスを検証する（絶対・親が `/sys/fs/cgroup`・接頭辞つき名前・既存ディレクトリ）。
        fn validate_cgroup(path: &str) -> Result<PathBuf, NetError> {
            let p = Path::new(path);
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| fail("invalid cgroup path"))?;
            let suffix = name
                .strip_prefix(CGROUP_PREFIX)
                .ok_or_else(|| fail("cgroup name must start with the measurement prefix"))?;
            let name_ok = (1..=64).contains(&suffix.len())
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-');
            if !p.is_absolute() || p.parent() != Some(Path::new(CGROUP_ROOT)) || !name_ok {
                return Err(fail("cgroup must be a direct child of /sys/fs/cgroup"));
            }
            let meta = fs::symlink_metadata(p).map_err(|_| fail("cgroup does not exist"))?;
            if !meta.is_dir() || !p.join("cgroup.procs").exists() {
                return Err(fail("cgroup is not a cgroup v2 directory"));
            }
            Ok(p.to_path_buf())
        }

        /// 同期ディレクトリを検証する（絶対パス・実ディレクトリ・0700）。
        fn validate_sync_dir(path: &str) -> Result<PathBuf, NetError> {
            let p = Path::new(path);
            let meta = fs::symlink_metadata(p).map_err(|_| fail("sync dir does not exist"))?;
            if !p.is_absolute() || !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
                return Err(fail("sync dir must be an absolute 0700 directory"));
            }
            Ok(p.to_path_buf())
        }

        /// 子の終了を期限つきで待つ。期限切れは kill して `None`。
        fn wait_deadline(child: &mut Child, limit: Duration) -> Option<i32> {
            let deadline = Instant::now() + limit;
            loop {
                match child.try_wait() {
                    Ok(Some(st)) => return Some(st.code().unwrap_or(1)),
                    Ok(None) if Instant::now() >= deadline => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return None;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                    Err(_) => return None,
                }
            }
        }

        /// ランチャ（host netns の root プロセス）。`unshare --net --mount` で inner を起動して終了コードを引き継ぐ。
        pub fn launcher(args: &[OsString]) -> ExitCode {
            let (Some(q), Some(w), Some(cg), Some(sync)) = (
                bounded(args, "--queries", QUERIES_MAX, 1),
                bounded(args, "--warmup", WARMUP_MAX, 0),
                opt(args, "--cgroup"),
                opt(args, "--sync-dir"),
            ) else {
                err_line(
                    "INVALID_ARGUMENT",
                    "need --queries 1..=10000 --warmup 0..=1000 --cgroup --sync-dir",
                );
                return ExitCode::from(2);
            };
            if validate_cgroup(cg).is_err() || validate_sync_dir(sync).is_err() {
                err_line("INVALID_ARGUMENT", "invalid --cgroup or --sync-dir");
                return ExitCode::from(2);
            }
            require_root_and_tools();
            let dir =
                std::env::temp_dir().join(format!("fandhe-dns-measure-{}", std::process::id()));
            if fs::create_dir(&dir)
                .and_then(|()| fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)))
                .is_err()
            {
                err_line("INTERNAL", "cannot create temp dir");
                return ExitCode::from(1);
            }
            let Ok(exe) = std::env::current_exe() else {
                err_line("INTERNAL", "current_exe failed");
                return ExitCode::from(1);
            };
            let child = Command::new("unshare")
                .args(["--net", "--mount", "--"])
                .arg(exe)
                .args(["--inner-measure", "--queries"])
                .arg(q.to_string())
                .arg("--warmup")
                .arg(w.to_string())
                .arg("--cgroup")
                .arg(cg)
                .arg("--sync-dir")
                .arg(sync)
                .env(LAUNCHER_PID_ENV, std::process::id().to_string())
                .env(DIR_ENV, &dir)
                .spawn();
            let code = match child {
                Ok(mut c) => wait_deadline(&mut c, Duration::from_secs(600)).unwrap_or(1),
                Err(_) => {
                    err_line("INTERNAL", "cannot spawn unshare");
                    1
                }
            };
            let _ = fs::remove_dir(&dir);
            ExitCode::from(u8::try_from(code).unwrap_or(1))
        }

        /// 計測専用ヘルパーのハンドル。`Drop` でも kill と回収を行う（ゾンビを残さない）。
        struct HelperGuard(Option<Child>);

        impl HelperGuard {
            fn stop(&mut self) {
                if let Some(mut c) = self.0.take() {
                    let _ = c.kill();
                    let _ = wait_deadline(&mut c, REAP_TIMEOUT_DEFAULT);
                }
            }
        }

        impl Drop for HelperGuard {
            fn drop(&mut self) {
                self.stop();
            }
        }

        /// inner（新 netns・新 mount namespace）。ネットワークと 2 コンテナを用意し、計測専用ヘルパーと
        /// コンテナ側クライアントを動かして JSONL を stdout へ中継し、PSS 取得の同期後に後始末する。
        pub fn inner(args: &[OsString]) -> ExitCode {
            let (Some(q), Some(w), Some(cg), Some(sync)) = (
                bounded(args, "--queries", QUERIES_MAX, 1),
                bounded(args, "--warmup", WARMUP_MAX, 0),
                opt(args, "--cgroup"),
                opt(args, "--sync-dir"),
            ) else {
                err_line("INVALID_ARGUMENT", "invalid measurement arguments");
                return ExitCode::from(2);
            };
            match inner_checked(q, w, cg, sync) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    err_line(e.code().as_str(), e.message());
                    ExitCode::from(1)
                }
            }
        }

        fn inner_checked(q: u32, w: u32, cg: &str, sync: &str) -> Result<(), NetError> {
            validate_cgroup(cg)?;
            let sync = validate_sync_dir(sync)?;
            let expected = std::env::var(LAUNCHER_PID_ENV)
                .ok()
                .and_then(|v| v.parse::<u32>().ok());
            if expected != Some(std::os::unix::process::parent_id()) {
                return Err(fail(
                    "`--inner-measure` must be started by the `--measure` launcher; refusing to run",
                ));
            }
            let own =
                fs::read_link("/proc/self/ns/net").map_err(|e| fail(format!("readlink: {e}")))?;
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
            let base = PathBuf::from(
                std::env::var(DIR_ENV).map_err(|_| fail("missing test directory env"))?,
            );
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
            let net = create_network(
                &route,
                &nft,
                &NetworkCreateSpec::new(
                    NetworkName::new("dnsm")?,
                    IpPrefix::new("10.215.0.1".parse().map_err(|_| fail("addr"))?, 24)?,
                )?,
                t,
            )
            .map_err(|e| fail(format!("create_network failed at {:?}: {e}", e.step)))?;
            // create_network 成功後は、どの失敗経路でも逆順（helper 停止 → delete_network）で回収する。
            let mut ipam = StaticIpam::for_network(&net)?;
            let mut ports = PortRegistry::new();
            let mut attached = Vec::new();
            let mut helper = HelperGuard(None);
            let result = (|| -> Result<(), NetError> {
                let mut addrs = Vec::new();
                let mut pins = Vec::new();
                for id in ["c1", "c2"] {
                    let spec = ContainerAttachSpec::new(EndpointId::new(id)?, &net, base.clone())?;
                    let a = attach_container(&route, &nft, &spec, &mut ipam, &mut ports, t)
                        .map_err(|e| {
                            fail(format!("attach_container failed at {:?}: {e}", e.step))
                        })?;
                    let ip = match a.address.addr() {
                        IpAddr::V4(v4) => Some(v4),
                        IpAddr::V6(_) => None,
                    };
                    let pin = a.netns_path.to_str().map(str::to_owned);
                    attached.push(a);
                    addrs.push(ip.ok_or_else(|| fail("container address is not IPv4"))?);
                    pins.push(pin.ok_or_else(|| fail("pin path is not UTF-8"))?);
                }
                let a1 = addrs
                    .first()
                    .copied()
                    .ok_or_else(|| fail("no c1 address"))?;
                let a2 = addrs.get(1).copied().ok_or_else(|| fail("no c2 address"))?;
                let c_addr: Ipv4Addr = SVC_C_ADDR.parse().map_err(|_| fail("svc-c addr"))?;
                let records = [("svc-a", a1), ("svc-b", a2), ("svc-c", c_addr)];

                let exe = std::env::current_exe().map_err(|e| fail(format!("current_exe: {e}")))?;
                let listen = DnsListenAddr::for_network(&net)?;
                helper.0 = Some(spawn_measure_helper(&exe, listen, cg, &records)?);
                let pid = helper
                    .0
                    .as_ref()
                    .map(Child::id)
                    .ok_or_else(|| fail("no helper"))?;
                let helper_ns = fs::read_link(format!("/proc/{pid}/ns/net"))
                    .map_err(|e| fail(format!("readlink helper netns: {e}")))?;
                if helper_ns != own || helper_ns == parent {
                    return Err(fail(
                        "helper is not in the network's own netns (or shares the launcher's)",
                    ));
                }

                let exe_str = exe.to_str().ok_or_else(|| fail("exe path is not UTF-8"))?;
                let target = listen.socket_addr().to_string();
                for (label, pin) in ["c1", "c2"].iter().zip(pins.iter()) {
                    let mut cmd_args: Vec<String> = vec![
                        format!("--net={pin}"),
                        exe_str.to_owned(),
                        "--dns-bench".into(),
                        target.clone(),
                        "--label".into(),
                        (*label).to_owned(),
                        "--queries".into(),
                        q.to_string(),
                        "--warmup".into(),
                        w.to_string(),
                    ];
                    for (name, ip) in &records {
                        cmd_args.push("--expect".into());
                        cmd_args.push(format!("{name}={ip}"));
                    }
                    // クライアントの stdout（JSONL）はそのまま親へ中継する。
                    let mut child = Command::new("nsenter")
                        .args(&cmd_args)
                        .stdin(Stdio::null())
                        .stdout(Stdio::inherit())
                        .stderr(Stdio::inherit())
                        .spawn()
                        .map_err(|e| fail(format!("spawn nsenter: {e}")))?;
                    // 失敗時はクライアントが連続無応答で打ち切るため、期限は十分な余裕を持たせる。
                    match wait_deadline(&mut child, timeout() * 3 + Duration::from_secs(30)) {
                        Some(0) => {}
                        Some(_) => return Err(fail("container-side dns bench failed")),
                        None => {
                            return Err(NetError::new(
                                NetErrorCode::Timeout,
                                "container-side dns bench did not finish before the deadline",
                            ));
                        }
                    }
                }

                // 全クエリ後のアイドル時に PSS を読ませる。スクリプトが読み終えるまでヘルパーを生かす。
                fs::write(sync.join("pss-ready"), b"1")
                    .map_err(|e| fail(format!("write pss-ready: {e}")))?;
                let deadline = Instant::now() + timeout() * 3;
                while !sync.join("pss-done").exists() {
                    if Instant::now() >= deadline {
                        return Err(NetError::new(
                            NetErrorCode::Timeout,
                            "pss-done was not signalled before the deadline",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(())
            })();
            helper.stop();
            let deleted = delete_network(&route, &nft, &net, attached, &mut ipam, &mut ports, t)
                .map(|_| ())
                .map_err(|e| fail(format!("delete_network failed: {e}")));
            result?;
            deleted
        }

        /// 計測専用ヘルパーを起動し、READY 行を期限内に受理するまで待つ。
        fn spawn_measure_helper(
            exe: &Path,
            listen: DnsListenAddr,
            cgroup: &str,
            records: &[(&str, Ipv4Addr)],
        ) -> Result<Child, NetError> {
            let mut cmd = Command::new(exe);
            cmd.args(["--dns-measure-helper", "--listen"])
                .arg(listen.socket_addr().to_string())
                .arg("--cgroup")
                .arg(cgroup);
            for (name, ip) in records {
                cmd.arg("--record").arg(format!("{name}={ip}"));
            }
            let mut child = cmd
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| fail(format!("spawn measure helper: {e}")))?;
            let Some(stdout) = child.stdout.take() else {
                let _ = child.kill();
                let _ = child.wait();
                return Err(fail("helper stdout unavailable"));
            };
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let mut line = String::new();
                // READY 行は短い。上限つきで 1 行だけ読む。
                let _ = BufReader::new(stdout.take(256)).read_line(&mut line);
                let _ = tx.send(line);
            });
            let want = format!("READY {}", listen.socket_addr());
            match rx.recv_timeout(READY_TIMEOUT_DEFAULT) {
                Ok(line) if line.trim_end() == want => Ok(child),
                other => {
                    let _ = child.kill();
                    let _ = wait_deadline(&mut child, REAP_TIMEOUT_DEFAULT);
                    Err(NetError::new(
                        NetErrorCode::FailedPrecondition,
                        if other.is_err() {
                            "measure helper was not ready before the deadline"
                        } else {
                            "measure helper reported an unexpected ready line"
                        },
                    ))
                }
            }
        }

        /// 計測専用ヘルパー本体（`--dns-measure-helper --listen <ipv4:port> --cgroup <path> --record <name>=<ipv4>...`）。
        /// 製品の `run_dns_helper_main` ではなく、`DnsHelperServer` + `RegistryHandler`（製品コード）を本バイナリが
        /// 直接組み立てる。bind と READY より前に専用 cgroup へ参加し、READY 時点で参加済みを保証する。
        pub fn helper(args: &[OsString]) -> ExitCode {
            match helper_checked(args) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    err_line(e.code().as_str(), e.message());
                    ExitCode::from(1)
                }
            }
        }

        fn helper_checked(args: &[OsString]) -> Result<(), NetError> {
            let listen: SocketAddrV4 = opt(args, "--listen")
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| fail("invalid --listen"))?;
            let listen = DnsListenAddr::new(*listen.ip(), listen.port())?;
            let cgroup =
                validate_cgroup(opt(args, "--cgroup").ok_or_else(|| fail("missing --cgroup"))?)?;
            let recs = opts(args, "--record");
            if recs.is_empty() || recs.len() > RECORDS_MAX {
                return Err(fail("--record count out of range"));
            }
            let registry = Arc::new(DnsRegistry::new());
            for r in recs {
                let (name, ip) = r.split_once('=').ok_or_else(|| fail("invalid --record"))?;
                let ip: Ipv4Addr = ip.parse().map_err(|_| fail("invalid --record address"))?;
                registry.register(&DnsName::new(name)?, ip)?;
            }
            // "0" は書き込んだプロセス自身を指す。READY より前に参加することで PID 取得の競合を避ける。
            fs::write(cgroup.join("cgroup.procs"), b"0")
                .map_err(|e| fail(format!("join cgroup: {e}")))?;
            let mut server = DnsHelperServer::bind(listen)?;
            println!("READY {}", server.local_addr());
            std::io::Write::flush(&mut std::io::stdout())
                .map_err(|e| fail(format!("flush ready line: {e}")))?;
            // 親が kill するまで動き続ける。
            let stop = AtomicBool::new(false);
            server.serve(&RegistryHandler::new(registry), &stop)
        }

        /// A クエリ（RD=1・IN）を組む。
        fn a_query(id: u16, name: &str) -> Option<Vec<u8>> {
            let mut v = query(id, 0x0100, 1);
            for label in name.split('.') {
                let len = u8::try_from(label.len())
                    .ok()
                    .filter(|l| (1..=63).contains(l))?;
                v.push(len);
                v.extend_from_slice(label.as_bytes());
            }
            v.push(0);
            v.extend_from_slice(&[0, 1, 0, 1]);
            Some(v)
        }

        fn be16(b: &[u8], off: usize) -> Option<u16> {
            Some(u16::from_be_bytes([
                *b.get(off)?,
                *b.get(off.checked_add(1)?)?,
            ]))
        }

        /// 応答が期待どおり（ID 一致・QR=1・RCODE=0・ANCOUNT=1・TYPE=A・RDATA=期待アドレス）かを照合する。
        fn answer_matches(resp: &[u8], id: u16, want: Ipv4Addr) -> Option<bool> {
            let flags = be16(resp, 2)?;
            if be16(resp, 0)? != id || flags & 0x8000 == 0 || flags & 0x000f != 0 {
                return Some(false);
            }
            if be16(resp, 6)? != 1 {
                return Some(false);
            }
            let mut off = parse_question(resp)?.end;
            // 回答の NAME（圧縮ポインタまたはラベル列）を読み飛ばす。
            loop {
                let b = *resp.get(off)?;
                if b & 0xC0 == 0xC0 {
                    off = off.checked_add(2)?;
                    break;
                }
                off = off.checked_add(1)?;
                if b == 0 {
                    break;
                }
                off = off.checked_add(usize::from(b))?;
            }
            let rtype = be16(resp, off)?;
            let rdlen = be16(resp, off.checked_add(8)?)?;
            let rdata = resp.get(off.checked_add(10)?..off.checked_add(14)?)?;
            Some(rtype == 1 && rdlen == 4 && rdata == want.octets())
        }

        /// コンテナ netns 側のクライアント（`--dns-bench <ipv4:port> --label <c1|c2> --expect <name>=<ipv4>... --queries N --warmup W`）。
        /// 名前ごとに warmup W 回と本計測 N 回を順に送り、1 クエリ 1 行の JSONL を stdout へ出す。
        /// 連続無応答が [`MAX_CONSECUTIVE_MISSES`] 回に達したら打ち切って非ゼロで終える（REPAIR-5）。
        pub fn bench(args: &[OsString]) -> ExitCode {
            let target: Option<SocketAddrV4> = args
                .iter()
                .skip_while(|a| *a != "--dns-bench")
                .nth(1)
                .and_then(|a| a.to_str())
                .and_then(|s| s.parse().ok());
            let label = opt(args, "--label").filter(|l| matches!(*l, "c1" | "c2"));
            let (Some(target), Some(label), Some(q), Some(w)) = (
                target,
                label,
                bounded(args, "--queries", QUERIES_MAX, 1),
                bounded(args, "--warmup", WARMUP_MAX, 0),
            ) else {
                err_line("INVALID_ARGUMENT", "invalid bench arguments");
                return ExitCode::from(2);
            };
            let mut expects: Vec<(String, Ipv4Addr)> = Vec::new();
            for e in opts(args, "--expect").into_iter().take(RECORDS_MAX) {
                let parsed = e.split_once('=').and_then(|(n, ip)| {
                    let n = DnsName::new(n).ok()?;
                    Some((n.as_str().to_owned(), ip.parse::<Ipv4Addr>().ok()?))
                });
                match parsed {
                    Some(p) => expects.push(p),
                    None => {
                        err_line("INVALID_ARGUMENT", "invalid --expect");
                        return ExitCode::from(2);
                    }
                }
            }
            if expects.is_empty() {
                err_line("INVALID_ARGUMENT", "missing --expect");
                return ExitCode::from(2);
            }
            let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
                err_line("INTERNAL", "bind failed");
                return ExitCode::from(1);
            };
            let _ = sock.set_read_timeout(Some(RECV_TIMEOUT));
            let mut next_id: u16 = 1;
            let mut misses: u32 = 0;
            let mut buf = [0u8; 600];
            for (name, want) in &expects {
                for i in 0..(w + q) {
                    let is_warmup = i < w;
                    let trial = if is_warmup { i } else { i - w };
                    let id = next_id;
                    next_id = next_id.wrapping_add(1);
                    let Some(pkt) = a_query(id, name) else {
                        err_line("INVALID_ARGUMENT", "cannot build query");
                        return ExitCode::from(2);
                    };
                    let start = Instant::now();
                    let mut result: Option<(bool, Duration)> = None;
                    if sock.send_to(&pkt, target).is_ok() {
                        let deadline = start + RECV_TIMEOUT;
                        while Instant::now() < deadline {
                            let Ok((n, _)) = sock.recv_from(&mut buf) else {
                                break;
                            };
                            let at = start.elapsed();
                            let resp = buf.get(..n).unwrap_or(&[]);
                            // ID が違う遅延応答は読み捨てる。
                            if be16(resp, 0) == Some(id) {
                                result =
                                    Some((answer_matches(resp, id, *want).unwrap_or(false), at));
                                break;
                            }
                        }
                    }
                    if let Some((ok, at)) = result {
                        misses = 0;
                        let us = at.as_secs_f64() * 1e6;
                        println!(
                            "{{\"series\":\"{label}/{name}\",\"trial\":{trial},\"warmup\":{is_warmup},\"ok\":{ok},\"latency_us\":{us:.3}}}"
                        );
                    } else {
                        misses += 1;
                        println!(
                            "{{\"series\":\"{label}/{name}\",\"trial\":{trial},\"warmup\":{is_warmup},\"ok\":false,\"latency_us\":null}}"
                        );
                        if misses >= MAX_CONSECUTIVE_MISSES {
                            err_line("TIMEOUT", "too many consecutive missing replies");
                            return ExitCode::from(1);
                        }
                    }
                }
            }
            ExitCode::SUCCESS
        }
    }
}
