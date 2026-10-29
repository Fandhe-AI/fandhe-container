//! 残った `realized.intent` のカーネル照合と実体の無い `members-intent` の掃除の実機結合試験
//! （NET-1・NET-7・REPAIR-4・REPAIR-12・#3346）。
//!
//! root と util-linux の `unshare --net --mount`、`nft`、`ip` が必要な実機前提テストのため `harness = false` の独自 `main` で
//! 動かし、`-- --ignored` を付けたときだけ実行する（未指定時は「ignored」を出力して成功終了する分離であり、
//! CI 通過のための弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では対象外。
//! 実機（root）での実行は未実施（人間担当）。
//!
//! # 流れ
//! 子は `unshare --net --mount` の新しい netns の中。`create_network_recorded` で実カーネルに作った後、
//! `realized` を消して create の意図記録を書き直し、「run 成功後・確定記録の前の SIGKILL」を模擬する。
//! - (1) 昇格: 実体が揃っているので `reconcile_network_recorded` が `realized` へ昇格し、元の記録と一致する
//! - (2) 巻き戻し: nft テーブルを消すと bridge だけが残る。照合が bridge を消し（`ip link` に無い）、意図記録も消える
//! - (3) 据え置き: bridge の別名を空にすると所有を証明できない。何も消さず、意図記録が残り、attach は `FailedPrecondition`
//! - (4) 削除の完了: delete の意図記録を重ね、bridge とテーブルを消すと、`realized` も意図記録も消える
//! - (5) 掃除: 実体の無いメンバー意図記録は消え、同名の host veth が生きているものは残る
//!
//! 成功行は `network_reconcile_privileged: ok promote=ok rollback=ok unproven=kept delete=completed sweep=removed sweep_live=kept`
//! の 1 行。待ちは `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。
//! 前提を満たさない場合は skip せず失敗する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("network_reconcile_privileged: Linux only, not applicable on this OS");
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
            "network_reconcile_privileged: ignored (requires root, `unshare --net --mount`, `nft` and `ip`; run the built executable with `--ignored` under `sudo`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
#[path = "support/reap.rs"]
mod reap;

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
    use fandhe_container_net::network::reconcile::{
        IntentKeep, RealizedReconcile, Unresolved, reconcile_network_recorded,
    };
    use fandhe_container_net::network::recorded::{
        RecordedError, attach_container_recorded, create_network_recorded,
    };
    use fandhe_container_net::network::{
        ContainerAttachSpec, CreatedNetwork, EndpointId, NetworkCreateSpec, NetworkName,
        PortRegistry, VethNames,
    };
    use fandhe_container_net::network_store::{
        HostGeneration, MemberId, MemberIntent, NetworkDefinition, NetworkStore, RealizedIntent,
        RealizedOp,
    };
    use fandhe_container_net::nftables_batch::NetlinkNetfilterSocket;

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn fail(msg: &str) -> ! {
        eprintln!("network_reconcile_privileged: child failed: {msg}");
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
        let base = std::env::temp_dir().join(format!("fc-reconcile-{}", std::process::id()));
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
                crate::reap::reap_or_report(&mut c, crate::reap::reap_within());
                panic!("child did not exit within the timeout");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let _ = fs::remove_dir_all(&base);
        assert!(st.success(), "child failed: {st:?}");
    }

    /// 期限つきで外部コマンドを実行し、標準出力を返す。
    fn run(program: &str, args: &[&str]) -> Result<String, String> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        // spawn・期限・出力回収を一括で期限つきにする（`wait_with_output` の無期限待ちを避ける。REPAIR-5・#3409）。
        let out = crate::reap::output_within(&mut cmd, timeout())?;
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
        let t = timeout();
        let route = NetlinkRouteSocket::open().unwrap_or_else(|x| fail(&x.to_string()));
        let nft = NetlinkNetfilterSocket::open().unwrap_or_else(|x| fail(&x.to_string()));
        let base = std::env::args()
            .find_map(|a| a.strip_prefix("--base=").map(PathBuf::from))
            .unwrap_or_else(|| fail("missing --base (run via the launcher)"));
        if let Err(x) = scenario(&route, &nft, &base, t) {
            fail(&x);
        }
        println!(
            "network_reconcile_privileged: ok promote=ok rollback=ok unproven=kept delete=completed sweep=removed sweep_live=kept"
        );
    }

    /// 実カーネルに 1 つのネットワークを作る。第三オクテットでサブネットを分ける。
    fn make(
        route: &NetlinkRouteSocket,
        nft: &NetlinkNetfilterSocket,
        store: &NetworkStore,
        name: &str,
        octet: u8,
        t: Duration,
    ) -> Result<(NetworkName, CreatedNetwork, IpPrefix, IpPrefix), String> {
        let subnet = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 232, octet, 0)), 24).map_err(e)?;
        let gateway = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 232, octet, 1)), 24).map_err(e)?;
        let nn = NetworkName::new(name).map_err(e)?;
        let def = NetworkDefinition::bridge(name, subnet).map_err(e)?;
        store.create(&def).map_err(e)?;
        let g = store.lock_global_exclusive().map_err(e)?;
        let n = g.lock_network(&nn).map_err(e)?;
        let spec = NetworkCreateSpec::new(nn.clone(), gateway).map_err(e)?;
        let created = create_network_recorded(route, nft, &n, &def, &spec, t)
            .map_err(|x| format!("create_network_recorded({name}): {x:?}"))?;
        Ok((nn, created, subnet, gateway))
    }

    fn intent_for(
        nn: &NetworkName,
        created: &CreatedNetwork,
        subnet: IpPrefix,
        gateway: IpPrefix,
        op: RealizedOp,
    ) -> Result<RealizedIntent, String> {
        let generation = HostGeneration::current().map_err(e)?;
        RealizedIntent::new(
            op,
            nn.clone(),
            &created.bridge_token,
            subnet,
            gateway,
            generation,
        )
        .map_err(e)
    }

    fn link_exists(name: &str) -> bool {
        run("ip", &["-o", "link", "show", name]).is_ok()
    }

    fn scenario(
        route: &NetlinkRouteSocket,
        nft: &NetlinkNetfilterSocket,
        base: &Path,
        t: Duration,
    ) -> Result<(), String> {
        let store = NetworkStore::open(&base.join("store")).map_err(e)?;
        let ns_dir = base.join("ns");

        // (1) 昇格。
        let (nn, created, subnet, gateway) = make(route, nft, &store, "rcpro", 1, t)?;
        {
            let g = store.lock_global_exclusive().map_err(e)?;
            let n = g.lock_network(&nn).map_err(e)?;
            let original = n.realized().map_err(e)?.ok_or("realized missing")?;
            n.remove_realized().map_err(e)?;
            n.write_realized_intent(&intent_for(
                &nn,
                &created,
                subnet,
                gateway,
                RealizedOp::Create,
            )?)
            .map_err(e)?;
            let report = reconcile_network_recorded(route, nft, &n, t).map_err(e)?;
            if report.realized != RealizedReconcile::Promoted {
                return Err(format!("promote: unexpected {:?}", report.realized));
            }
            if n.realized().map_err(e)? != Some(original)
                || n.realized_intent().map_err(e)?.is_some()
            {
                return Err("promote: realized differs from the original or intent remains".into());
            }
        }

        // (2) 巻き戻し: テーブルが無く bridge だけが残る。
        let (nn, created, subnet, gateway) = make(route, nft, &store, "rcrol", 2, t)?;
        {
            let g = store.lock_global_exclusive().map_err(e)?;
            let n = g.lock_network(&nn).map_err(e)?;
            n.remove_realized().map_err(e)?;
            n.write_realized_intent(&intent_for(
                &nn,
                &created,
                subnet,
                gateway,
                RealizedOp::Create,
            )?)
            .map_err(e)?;
            run("nft", &["delete", "table", "ip", created.table.as_str()])?;
            let report = reconcile_network_recorded(route, nft, &n, t).map_err(e)?;
            if report.realized != RealizedReconcile::RolledBack {
                return Err(format!("rollback: unexpected {:?}", report.realized));
            }
            if link_exists(created.bridge.as_str()) {
                return Err("rollback: the bridge is still present".into());
            }
            if n.realized_intent().map_err(e)?.is_some() || n.realized().map_err(e)?.is_some() {
                return Err("rollback: records remain".into());
            }
        }

        // (3) 据え置き: 別名が空で所有を証明できない。
        let (nn, created, subnet, gateway) = make(route, nft, &store, "rcunp", 3, t)?;
        {
            let g = store.lock_global_exclusive().map_err(e)?;
            let n = g.lock_network(&nn).map_err(e)?;
            n.remove_realized().map_err(e)?;
            n.write_realized_intent(&intent_for(
                &nn,
                &created,
                subnet,
                gateway,
                RealizedOp::Create,
            )?)
            .map_err(e)?;
            run(
                "ip",
                &["link", "set", "dev", created.bridge.as_str(), "alias", ""],
            )?;
            let report = reconcile_network_recorded(route, nft, &n, t).map_err(e)?;
            if report.realized != RealizedReconcile::Unresolved(Unresolved::Unproven) {
                return Err(format!("unproven: unexpected {:?}", report.realized));
            }
            if !link_exists(created.bridge.as_str()) || n.realized_intent().map_err(e)?.is_none() {
                return Err("unproven: the bridge or the intent was removed".into());
            }
            let spec = ContainerAttachSpec::new(
                EndpointId::new("c1").map_err(e)?,
                &created,
                ns_dir.clone(),
            )
            .map_err(e)?;
            let mut ports = PortRegistry::new();
            match attach_container_recorded(
                route,
                nft,
                &n,
                &MemberId::new("c1").map_err(e)?,
                &spec,
                &[],
                &mut ports,
                t,
            ) {
                Err(RecordedError::Store(x)) if x.code() == NetErrorCode::FailedPrecondition => {}
                other => return Err(format!("unproven: attach must be refused, got {other:?}")),
            }
        }

        // (4) 削除の完了: delete の意図記録が残り、カーネル側は削除済み。
        let (nn, created, subnet, gateway) = make(route, nft, &store, "rcdel", 4, t)?;
        {
            let g = store.lock_global_exclusive().map_err(e)?;
            let n = g.lock_network(&nn).map_err(e)?;
            n.write_realized_intent(&intent_for(
                &nn,
                &created,
                subnet,
                gateway,
                RealizedOp::Delete,
            )?)
            .map_err(e)?;
            run("nft", &["delete", "table", "ip", created.table.as_str()])?;
            run("ip", &["link", "del", created.bridge.as_str()])?;
            let report = reconcile_network_recorded(route, nft, &n, t).map_err(e)?;
            if report.realized != RealizedReconcile::Completed {
                return Err(format!("delete: unexpected {:?}", report.realized));
            }
            if n.realized().map_err(e)?.is_some() || n.realized_intent().map_err(e)?.is_some() {
                return Err("delete: records remain".into());
            }
        }

        // (5) 掃除: 実体の無い意図記録は消え、生きた host veth のあるものは残る。
        let (nn, created, _subnet, _gateway) = make(route, nft, &store, "rcswp", 5, t)?;
        {
            let g = store.lock_global_exclusive().map_err(e)?;
            let n = g.lock_network(&nn).map_err(e)?;
            for (id, last) in [("c1", 2u8), ("c2", 3u8)] {
                let ep = EndpointId::new(id).map_err(e)?;
                let addr =
                    IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 232, 5, last)), 24).map_err(e)?;
                let token = format!("{}/ep/{id}/g/{:032x}", created.bridge_token, 1u8);
                let dir_id = {
                    use std::os::unix::fs::MetadataExt;
                    let m = std::fs::metadata(&ns_dir).map_err(|x| x.to_string())?;
                    (m.dev(), m.ino())
                };
                n.write_member_intent(
                    &MemberIntent::new(MemberId::new(id).map_err(e)?, ep, addr, &token)
                        .and_then(|i| i.with_netns_dir(&ns_dir))
                        .and_then(|i| i.with_netns_dir_id(dir_id))
                        .map_err(e)?,
                )
                .map_err(e)?;
            }
            let live = VethNames::derive(&EndpointId::new("c2").map_err(e)?).map_err(e)?;
            run(
                "ip",
                &["link", "add", live.host().as_str(), "type", "dummy"],
            )?;
            let report = reconcile_network_recorded(route, nft, &n, t).map_err(e)?;
            let c1 = MemberId::new("c1").map_err(e)?;
            let c2 = MemberId::new("c2").map_err(e)?;
            if report.removed_intents != vec![c1] {
                return Err(format!("sweep: removed {:?}", report.removed_intents));
            }
            if report.kept_intents != vec![(c2, IntentKeep::VethPresent)] {
                return Err(format!("sweep: kept {:?}", report.kept_intents));
            }
            if n.member_intents().map_err(e)?.len() != 1 {
                return Err("sweep: one intent must remain".into());
            }
        }
        Ok(())
    }
}
