//! 公開ハンドルとテーブル handle の記録、再起動後の復元・個別解除、テーブル再作成時の拒否の実機結合試験
//! （NET-3・SEC-1・REPAIR-12・#3068）。
//!
//! root と util-linux の `unshare --net`、`nft`、`ip` が必要な実機前提テストのため `harness = false` の独自 `main` で
//! 動かし、`-- --ignored` を付けたときだけ実行する（未指定時は「ignored」を出力して成功終了する分離であり、
//! CI 通過のための弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では対象外。
//! 実機（root）での実行は未実施（人間担当。#1626 と同じ扱い）。
//!
//! # 流れ（子は `unshare --net` の新しい netns の中）
//! - (1) `create_network_recorded` が記録した `realized` のテーブル handle が、実カーネルの GETTABLE の handle と一致する
//! - (2) 公開（受け口と rule handle 2 本）つきのメンバー記録を書き、ストアを開き直して（再起動の模擬）
//!   `restore_published_ports` が記録どおりの公開を復元する
//! - (3) 同名・同 userdata でテーブルを作り直す（ルールセットの退避・復元の模擬）と handle が変わる。その新テーブルに
//!   別のルールを 1 つ置く
//! - (4) `attach_container_recorded` は veth を作る前に `FailedPrecondition` で断り、メンバー記録も意図記録も増えない
//! - (5) 復元した公開の `unpublish_port_recorded` は DELRULE を送らず `StaleHandles` で断り、新テーブルの別ルールが
//!   残り、メンバー記録は変わらない
//!
//! 成功行は `network_publish_record_privileged: ok` の 1 行。待ちは `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`
//! （既定 10 秒）で期限を切る（REPAIR-5）。前提を満たさない場合は skip せず失敗する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("network_publish_record_privileged: Linux only, not applicable on this OS");
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
            "network_publish_record_privileged: ignored (requires root, `unshare --net`, `nft` and `ip`; run the built executable with `--ignored` under `sudo`, see AGENTS.md)"
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
    use fandhe_container_net::network::recorded::{
        RecordedError, attach_container_recorded, create_network_recorded, restore_published_ports,
        unpublish_port_recorded,
    };
    use fandhe_container_net::network::{
        ContainerAttachSpec, EndpointId, NetworkCreateSpec, NetworkName, PortProtocol, PortPublish,
        PortRegistry, UnpublishRules,
    };
    use fandhe_container_net::network_store::{
        MemberId, MemberRecord, NetworkDefinition, NetworkStore, RecordedPublish,
    };
    use fandhe_container_net::nftables_batch::{
        NetlinkNetfilterSocket, NftFamily, NftName, TableCreate, TableDelete, TableGet,
    };
    use fandhe_container_net::nftables_rules::NftRuleHandle;

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn fail(msg: &str) -> ! {
        eprintln!("network_publish_record_privileged: child failed: {msg}");
        std::process::exit(1);
    }

    fn netns_id() -> Result<String, String> {
        fs::read_link("/proc/self/ns/net")
            .map(|p| p.to_string_lossy().into_owned())
            .map_err(|e| format!("read_link /proc/self/ns/net: {e}"))
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
        let mut c = Command::new("unshare")
            .args(["--net", "--"])
            .arg(exe)
            .arg("--child")
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
        assert!(st.success(), "child failed: {st:?}");
    }

    /// 期限つきで外部コマンドを実行し、標準出力を返す。
    fn run(program: &str, args: &[&str]) -> Result<String, String> {
        let mut c = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {program}: {e}"))?;
        let deadline = Instant::now() + timeout();
        loop {
            if c.try_wait().map_err(|e| e.to_string())?.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = c.kill();
                let _ = c.wait();
                return Err(format!("{program} timed out"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let out = c.wait_with_output().map_err(|e| e.to_string())?;
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
        if netns_id().unwrap_or_else(|e| fail(&e)) == parent_ns {
            fail("child shares the launcher netns");
        }
        let t = timeout();
        let route = NetlinkRouteSocket::open().unwrap_or_else(|e| fail(&e.to_string()));
        let nft = NetlinkNetfilterSocket::open().unwrap_or_else(|e| fail(&e.to_string()));
        let dir = std::env::temp_dir().join(format!("fc-pubrec-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .unwrap_or_else(|e| fail(&e.to_string()));
        let result = scenario(&route, &nft, &dir, t);
        let _ = fs::remove_dir_all(&dir);
        if let Err(e) = result {
            fail(&e);
        }
        println!("network_publish_record_privileged: ok");
    }

    fn live_handle(
        nft: &NetlinkNetfilterSocket,
        table: &NftName,
        t: Duration,
    ) -> Result<u64, String> {
        nft.table_info(&TableGet::new(NftFamily::Ipv4, table.clone()), t)
            .map_err(|e| e.to_string())?
            .handle()
            .ok_or_else(|| "no table handle".to_owned())
    }

    fn scenario(
        route: &NetlinkRouteSocket,
        nft: &NetlinkNetfilterSocket,
        dir: &Path,
        t: Duration,
    ) -> Result<(), String> {
        fn e(x: impl std::fmt::Display) -> String {
            x.to_string()
        }
        let subnet = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 231, 0, 0)), 24).map_err(e)?;
        let gateway = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 231, 0, 1)), 24).map_err(e)?;
        let name = NetworkName::new("pubrec").map_err(e)?;
        let def = NetworkDefinition::bridge("pubrec", subnet).map_err(e)?;
        let store = NetworkStore::open(dir).map_err(e)?;
        store.create(&def).map_err(e)?;
        let mid = MemberId::new("c1").map_err(e)?;
        let ep = EndpointId::new("c1").map_err(e)?;
        let publish = PortPublish::new(PortProtocol::Tcp, Ipv4Addr::new(192, 0, 2, 10), 8080, 80)
            .map_err(e)?;
        let rule = NftRuleHandle::new;
        let (token, table, created, recorded_handle);
        {
            let g = store.lock_global_exclusive().map_err(e)?;
            let n = g.lock_network(&name).map_err(e)?;
            // (1) 作成で記録したテーブル handle が、実カーネルの handle と一致する。
            let spec = NetworkCreateSpec::new(name.clone(), gateway).map_err(e)?;
            created = create_network_recorded(route, nft, &n, &def, &spec, t)
                .map_err(|x| format!("create_network_recorded: {x:?}"))?;
            table = created.table.clone();
            token = created.bridge_token.clone();
            let realized = n.realized().map_err(e)?.ok_or("realized missing")?;
            recorded_handle = live_handle(nft, &table, t)?;
            if realized.table_handle().get() != recorded_handle {
                return Err(format!(
                    "recorded table handle {} != live {recorded_handle}",
                    realized.table_handle().get()
                ));
            }
            // (2) 公開つきのメンバー記録（rule handle 2・3）を書く。
            let rec = MemberRecord::new(
                mid.clone(),
                ep.clone(),
                IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 231, 0, 2)), 24).map_err(e)?,
                "fandhe-net:pubrec:c1:token",
                Path::new("/run/fc-pubrec-ns"),
                (8, 9),
                &[],
            )
            .and_then(|r| {
                r.with_publishes(
                    realized.table_handle(),
                    vec![RecordedPublish::new(publish, rule(2)?, rule(3)?)],
                )
            })
            .map_err(e)?;
            n.commit_member(&rec).map_err(e)?;
        }
        // 再起動の模擬: ストアを開き直し、記録だけから公開を復元する。
        let store = NetworkStore::open(dir).map_err(e)?;
        let g = store.lock_global_exclusive().map_err(e)?;
        let n = g.lock_network(&name).map_err(e)?;
        let mut restored = restore_published_ports(&n, &mid).map_err(e)?;
        if restored.len() != 1
            || *restored[0].publish() != publish
            || restored[0].table_handle().map(|h| h.get()) != Some(recorded_handle)
        {
            return Err(format!("unexpected restored ports: {}", restored.len()));
        }
        let member_path: PathBuf = dir.join("@networks/pubrec/members/c1");
        let before = fs::read(&member_path).map_err(e)?;

        // (3) テーブルを同じ名前・userdata で作り直す（handle が変わる）。別のルールを 1 つ置く。
        nft.send_batch(t, |b| {
            b.push_with(|seq| {
                TableDelete::by_handle(NftFamily::Ipv4, table.clone(), recorded_handle).build(seq)
            })?;
            b.push_with(|seq| {
                TableCreate::new(NftFamily::Ipv4, table.clone())
                    .with_userdata(token.as_bytes())?
                    .build(seq)
            })?;
            Ok(())
        })
        .map_err(|x| format!("recreate table: {x}"))?;
        let new_handle = live_handle(nft, &table, t)?;
        if new_handle == recorded_handle {
            return Err("table handle did not change after recreation".to_owned());
        }
        run(
            "nft",
            &[
                "add",
                "chain",
                "ip",
                table.as_str(),
                "other",
                "{ type filter hook input priority 0; }",
            ],
        )?;
        run(
            "nft",
            &["add", "rule", "ip", table.as_str(), "other", "counter"],
        )?;

        // (4) attach は veth を作る前に断る。
        let attach_spec = ContainerAttachSpec::new(
            EndpointId::new("c2").map_err(e)?,
            &created,
            PathBuf::from("/run/fc-pubrec-ns"),
        )
        .map_err(e)?;
        let mut ports = PortRegistry::new();
        match attach_container_recorded(
            route,
            nft,
            &n,
            &MemberId::new("c2").map_err(e)?,
            &attach_spec,
            &[],
            &mut ports,
            t,
        ) {
            Err(RecordedError::Store(err)) if err.code() == NetErrorCode::FailedPrecondition => {}
            other => return Err(format!("attach must be refused (ok={})", other.is_ok())),
        }
        if !run("ip", &["-o", "link", "show", "type", "veth"])?
            .trim()
            .is_empty()
        {
            return Err("a veth was created before the refusal".to_owned());
        }
        if n.members().map_err(e)?.len() != 1 || !n.member_intents().map_err(e)?.is_empty() {
            return Err("attach left records behind".to_owned());
        }

        // (5) 解除は DELRULE を送らず StaleHandles で断る。別のルールは残り、記録は変わらない。
        let p = restored.remove(0);
        let mut reg = PortRegistry::new();
        match unpublish_port_recorded(nft, &n, &mid, p, &mut reg, t) {
            Err(RecordedError::Op(err)) if err.rules == UnpublishRules::StaleHandles => {}
            other => {
                return Err(format!(
                    "unpublish must be StaleHandles (ok={})",
                    other.is_ok()
                ));
            }
        }
        let listing = run("nft", &["-a", "list", "table", "ip", table.as_str()])?;
        if !listing.contains("counter") {
            return Err(format!("the other rule was deleted: {listing}"));
        }
        if fs::read(&member_path).map_err(e)? != before {
            return Err("member record changed after the refusal".to_owned());
        }
        Ok(())
    }
}
