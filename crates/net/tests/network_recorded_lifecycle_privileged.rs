//! 記録つき合成（`network::recorded`）の create → attach → detach → delete の通しの実機結合試験
//! （NET-1・NET-7・REPAIR-12・#3348）。
//!
//! root と util-linux の `unshare --net --mount`、`ip`、`nft` が必要な実機前提テストのため `harness = false` の
//! 独自 `main` で動かし、`-- --ignored` を付けたときだけ実行する（未指定時は「ignored」を出力して成功終了する分離であり、
//! CI 通過のための弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では対象外。
//! 実機（root）での実行は未実施（人間担当。#1626 に足す）。
//!
//! `network_publish_record_privileged`（#3068）は公開ハンドルが対象で、途中でテーブルを作り直すため detach / delete まで
//! 進まない。本試験は作り直さずに最後まで通し、各段で記録（`realized`・`members`・意図記録・`pending-reclaim`）と
//! 実体（bridge・veth・pin・テーブル handle・所有トークン）が一致することを具体値で照合する。
//!
//! # 流れ（子は `unshare --net --mount` の新しい netns・mount namespace の中）
//! - create: `realized` が確定し意図記録が無い。トークン・テーブル handle・userdata・gateway・subnet が実体と一致する
//! - attach（c1 は TCP 公開つき、c2）: `members` の endpoint・address・token が結果と一致し、host 側 veth が
//!   bridge に属して up、pin が存在し、意図記録が無い。IPAM を記録から組み直すと使用中の件数が一致する
//! - detach c1: c1 の記録・veth・pin・DNAT が消え、c2 は残る（`detach_sibling=kept`）。detach c2 で `members` が空になる
//! - delete: `realized` が消え、bridge とテーブルが `NotFound`、`pending-reclaim` が空
//!
//! 各段の照合の前にストアを開き直し、記録がディスクで確定していることを確かめる。待ちは
//! `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。前提を満たさない場合は skip せず失敗する。
//! `/tmp` 配下の flock が systemd-tmpfiles の aging と競合しうる点は
//! `docs/design/measurements/production-launcher-tmpfiles-flock.md` を参照（間欠失敗したときの追跡先）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("network_recorded_lifecycle_privileged: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--child") {
        linux::child();
    } else if args.iter().any(|a| a == "--ignored") {
        linux::launcher();
    } else {
        println!(
            "network_recorded_lifecycle_privileged: ignored (requires root, `unshare --net --mount`, `nft` and `ip`; run the built executable with `--ignored` under `sudo`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_net::error::NetErrorCode;
    use fandhe_container_net::netlink_route::{IpPrefix, NetlinkRouteSocket};
    use fandhe_container_net::netns::ContainerNetns;
    use fandhe_container_net::network::recorded::{
        attach_container_recorded, create_network_recorded, delete_network_recorded,
        detach_container_recorded,
    };
    use fandhe_container_net::network::{
        AttachedContainer, ContainerAttachSpec, EndpointId, NetworkCreateSpec, NetworkName,
        PortProtocol, PortPublish, PortRegistry,
    };
    use fandhe_container_net::network_store::{
        MemberId, NetworkDefinition, NetworkStore, rebuild_ipam,
    };
    use fandhe_container_net::nftables_batch::{NetlinkNetfilterSocket, NftFamily, TableGet};

    const OK_LINE: &str = "network_recorded_lifecycle_privileged: ok create=recorded attach=recorded detach=recorded detach_sibling=kept delete=recorded";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn fail(msg: &str) -> ! {
        eprintln!("network_recorded_lifecycle_privileged: child failed: {msg}");
        std::process::exit(1);
    }

    fn e(x: impl std::fmt::Display) -> String {
        x.to_string()
    }

    fn netns_id() -> Result<String, String> {
        fs::read_link("/proc/self/ns/net")
            .map(|p| p.to_string_lossy().into_owned())
            .map_err(|x| format!("read_link /proc/self/ns/net: {x}"))
    }

    pub fn launcher() {
        let root = fs::read_to_string("/proc/self/status")
            .expect("read /proc/self/status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_owned))
            .as_deref()
            == Some("0");
        assert!(root, "this test requires root (euid 0); see AGENTS.md");
        let exe = std::env::current_exe().expect("current_exe");
        let parent_ns = netns_id().expect("launcher netns id");
        let base = std::env::temp_dir().join(format!("fc-reclife-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        for d in [&base, &base.join("store"), &base.join("ns")] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(d)
                .expect("create temp dir");
        }
        let mut c = Command::new("unshare")
            .args(["--net", "--mount", "--"])
            .arg(exe)
            .arg("--child")
            .arg(format!("--base={}", base.display()))
            .arg(format!("--parent-netns={parent_ns}"))
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn unshare child");
        let deadline = Instant::now() + timeout() * 6;
        let st = loop {
            if let Some(st) = c.try_wait().expect("try_wait") {
                break st;
            }
            if Instant::now() >= deadline {
                let _ = c.kill();
                let _ = c.wait();
                panic!("child did not exit within the timeout");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        // 子の mount namespace が消えた後なので、pin のファイルも含めて消せる。
        let _ = fs::remove_dir_all(&base);
        assert!(st.success(), "child failed: {st:?}");
    }

    /// 期限つきで外部コマンドを実行し、標準出力を返す（失敗は標準エラー）。
    fn run(program: &str, args: &[&str]) -> Result<String, String> {
        let mut c = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|x| format!("spawn {program}: {x}"))?;
        let deadline = Instant::now() + timeout();
        loop {
            if c.try_wait().map_err(e)?.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = c.kill();
                let _ = c.wait();
                return Err(format!("{program} timed out"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let out = c.wait_with_output().map_err(e)?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).into_owned())
        }
    }

    pub fn child() {
        let parent_ns = std::env::args()
            .find_map(|a| a.strip_prefix("--parent-netns=").map(str::to_owned))
            .unwrap_or_else(|| fail("missing --parent-netns (run via the launcher)"));
        if netns_id().unwrap_or_else(|x| fail(&x)) == parent_ns {
            fail("child shares the launcher netns");
        }
        let base = std::env::args()
            .find_map(|a| a.strip_prefix("--base=").map(PathBuf::from))
            .unwrap_or_else(|| fail("missing --base (run via the launcher)"));
        let route = NetlinkRouteSocket::open().unwrap_or_else(|x| fail(&x.to_string()));
        let nft = NetlinkNetfilterSocket::open().unwrap_or_else(|x| fail(&x.to_string()));
        // pin の bind mount を host へ漏らさない。
        if let Err(x) = run("mount", &["--make-rprivate", "/"]) {
            fail(&x);
        }
        if let Err(x) = scenario(&route, &nft, &base, timeout()) {
            fail(&x);
        }
        println!("{OK_LINE}");
    }

    /// `ip -o link show <name>` の 1 行。存在しなければ `None`。
    fn link_line(name: &str) -> Option<String> {
        run("ip", &["-o", "link", "show", name]).ok()
    }

    /// 行から `alias <値>` を取り出す。
    fn alias_of(line: &str) -> Option<String> {
        let mut w = line.split_whitespace();
        while let Some(x) = w.next() {
            if x == "alias" {
                return w.next().map(str::to_owned);
            }
        }
        None
    }

    fn dnat_count(table: &str, port: &str) -> Result<usize, String> {
        let rs = run("nft", &["list", "table", "ip", table])?;
        Ok(rs
            .lines()
            .filter(|l| l.contains("dnat to") && l.contains(port))
            .count())
    }

    type Attached = Vec<(MemberId, AttachedContainer<ContainerNetns>)>;

    fn scenario(
        route: &NetlinkRouteSocket,
        nft: &NetlinkNetfilterSocket,
        base: &Path,
        t: Duration,
    ) -> Result<(), String> {
        let dir = base.join("store");
        let ns_dir = base.join("ns");
        let subnet = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 232, 0, 0)), 24).map_err(e)?;
        let gateway = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 232, 0, 1)), 24).map_err(e)?;
        let name = NetworkName::new("reclife").map_err(e)?;
        let def = NetworkDefinition::bridge("reclife", subnet).map_err(e)?;
        let (m1, m2) = (
            MemberId::new("c1").map_err(e)?,
            MemberId::new("c2").map_err(e)?,
        );
        let publish = PortPublish::new(PortProtocol::Tcp, Ipv4Addr::new(192, 0, 2, 10), 8091, 80)
            .map_err(e)?;
        let mut ports = PortRegistry::new();
        NetworkStore::open(&dir)
            .map_err(e)?
            .create(&def)
            .map_err(e)?;

        // --- create ---
        let created = {
            let store = NetworkStore::open(&dir).map_err(e)?;
            let g = store.lock_global_exclusive().map_err(e)?;
            let n = g.lock_network(&name).map_err(e)?;
            let spec = NetworkCreateSpec::new(name.clone(), gateway).map_err(e)?;
            create_network_recorded(route, nft, &n, &def, &spec, t)
                .map_err(|x| format!("create_network_recorded: {x:?}"))?
        };
        let (bridge, table) = (created.bridge.as_str().to_owned(), created.table.clone());
        {
            let store = NetworkStore::open(&dir).map_err(e)?;
            let g = store.lock_global_exclusive().map_err(e)?;
            let n = g.lock_network(&name).map_err(e)?;
            let r = n.realized().map_err(e)?.ok_or("realized missing")?;
            if n.realized_intent().map_err(e)?.is_some() {
                return Err("realized intent remains after create".into());
            }
            if r.token() != created.bridge_token || r.gateway() != gateway || r.subnet() != subnet {
                return Err("realized record differs from the created network".into());
            }
            let info = nft
                .table_info(&TableGet::new(NftFamily::Ipv4, table.clone()), t)
                .map_err(e)?;
            if info.handle() != Some(r.table_handle().get())
                || info.userdata() != Some(created.bridge_token.as_bytes())
            {
                return Err("table handle or userdata differs from the record".into());
            }
            let line = link_line(&bridge).ok_or("bridge is missing")?;
            if alias_of(&line).as_deref() != Some(created.bridge_token.as_str()) {
                return Err(format!("bridge alias is not the token: {line}"));
            }
            let rc = n.reclaim_records().map_err(e)?;
            if rc.create.is_some() || !rc.attach.is_empty() {
                return Err("pending-reclaim is not empty after create".into());
            }
        }

        // --- attach c1（公開つき）・c2 ---
        let mut attached: Attached = Vec::new();
        for (mid, publishes) in [(&m1, vec![publish]), (&m2, Vec::new())] {
            let store = NetworkStore::open(&dir).map_err(e)?;
            let g = store.lock_global_exclusive().map_err(e)?;
            let n = g.lock_network(&name).map_err(e)?;
            let ep = EndpointId::new(mid.as_str()).map_err(e)?;
            let spec = ContainerAttachSpec::new(ep, &created, ns_dir.clone())
                .and_then(|s| s.with_port_publishes(publishes))
                .map_err(e)?;
            let a = attach_container_recorded(route, nft, &n, mid, &spec, &[], &mut ports, t)
                .map_err(|x| format!("attach_container_recorded({}): {x:?}", mid.as_str()))?;
            attached.push((mid.clone(), a));
        }
        {
            let store = NetworkStore::open(&dir).map_err(e)?;
            let g = store.lock_global_exclusive().map_err(e)?;
            let n = g.lock_network(&name).map_err(e)?;
            let members = n.members().map_err(e)?;
            if members.len() != 2 || !n.member_intents().map_err(e)?.is_empty() {
                return Err(format!(
                    "unexpected members after attach: {}",
                    members.len()
                ));
            }
            for (mid, a) in &attached {
                let rec = members
                    .iter()
                    .find(|m| m.id() == mid)
                    .ok_or("member record missing")?;
                if rec.endpoint() != &a.endpoint
                    || rec.address() != a.address
                    || rec.token() != a.host_token
                {
                    return Err(format!("member record differs for {}", mid.as_str()));
                }
                let line = link_line(a.host_veth.as_str()).ok_or("host veth is missing")?;
                if alias_of(&line).as_deref() != Some(a.host_token.as_str())
                    || !line.contains(&format!("master {bridge}"))
                    || !line.contains("UP")
                {
                    return Err(format!("host veth state mismatch: {line}"));
                }
                if !a.netns_path.exists() {
                    return Err("netns pin is missing".into());
                }
            }
            let realized = n.realized().map_err(e)?.ok_or("realized missing")?;
            let ipam = rebuild_ipam(&realized, &members, &[]).map_err(e)?;
            if ipam.allocated_count() != 2 {
                return Err(format!(
                    "rebuilt ipam holds {} addresses, want 2",
                    ipam.allocated_count()
                ));
            }
        }
        if dnat_count(table.as_str(), "dport 8091")? != 2 {
            return Err("c1 must publish 2 DNAT rules".into());
        }

        // --- detach c1 → c2（c1 の後も c2 は残る）---
        while !attached.is_empty() {
            let (mid, a) = attached.remove(0);
            let veth = a.host_veth.as_str().to_owned();
            let pin = a.netns_path.clone();
            let sibling = attached.first().map(|(m, s)| {
                (
                    m.clone(),
                    s.host_veth.as_str().to_owned(),
                    s.netns_path.clone(),
                )
            });
            {
                let store = NetworkStore::open(&dir).map_err(e)?;
                let g = store.lock_global_exclusive().map_err(e)?;
                let n = g.lock_network(&name).map_err(e)?;
                detach_container_recorded(route, nft, &n, &mid, a, Vec::new(), &mut ports, t)
                    .map_err(|x| format!("detach_container_recorded({}): {x:?}", mid.as_str()))?;
            }
            let store = NetworkStore::open(&dir).map_err(e)?;
            let g = store.lock_global_exclusive().map_err(e)?;
            let n = g.lock_network(&name).map_err(e)?;
            let members = n.members().map_err(e)?;
            if members.len() != attached.len() || !n.member_intents().map_err(e)?.is_empty() {
                return Err(format!("members after detach: {}", members.len()));
            }
            if members.iter().any(|m| m.id() == &mid) {
                return Err("detached member record remains".into());
            }
            if link_line(&veth).is_some() || pin.exists() {
                return Err("veth or pin remains after detach".into());
            }
            if dnat_count(table.as_str(), "dport 8091")? != 0 {
                return Err("DNAT rules remain after detaching the publishing member".into());
            }
            if let Some((sid, sveth, spin)) = sibling
                && (!members.iter().any(|m| m.id() == &sid)
                    || link_line(&sveth).is_none()
                    || !spin.exists())
            {
                return Err("sibling record, veth or pin was removed by detach".into());
            }
        }

        // --- delete ---
        {
            let store = NetworkStore::open(&dir).map_err(e)?;
            let g = store.lock_global_exclusive().map_err(e)?;
            let n = g.lock_network(&name).map_err(e)?;
            delete_network_recorded(route, nft, &n, &mut ports, t)
                .map_err(|x| format!("delete_network_recorded: {x:?}"))?;
        }
        let store = NetworkStore::open(&dir).map_err(e)?;
        let g = store.lock_global_exclusive().map_err(e)?;
        let n = g.lock_network(&name).map_err(e)?;
        if n.realized().map_err(e)?.is_some() || n.realized_intent().map_err(e)?.is_some() {
            return Err("realized record remains after delete".into());
        }
        let rc = n.reclaim_records().map_err(e)?;
        if rc.create.is_some() || !rc.attach.is_empty() {
            return Err("pending-reclaim is not empty after delete".into());
        }
        if link_line(&bridge).is_some() {
            return Err("bridge remains after delete".into());
        }
        match nft.table_info(&TableGet::new(NftFamily::Ipv4, table), t) {
            Err(x) if x.code() == NetErrorCode::NotFound => {}
            other => return Err(format!("table still readable after delete: {other:?}")),
        }
        Ok(())
    }
}
