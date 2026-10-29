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
//! - (2b) 実際に `attach_container_recorded` で 2 件を公開したコンテナ（実カーネルが返した rule handle を記録）を、
//!   ストアを開き直して復元し、`unpublish_port_recorded` で 1 件だけ解除する。対象の DNAT 2 本とメンバー記録の
//!   該当の公開が消え、もう 1 件の公開（DNAT 2 本）と別メンバーの記録が残ることを具体値で照合する
//! - (3) 同名・同 userdata でテーブルを作り直す（ルールセットの退避・復元の模擬）と handle が変わる。その新テーブルに
//!   別のルールを 1 つ置く
//! - (4) `attach_container_recorded` は veth を作る前に `FailedPrecondition` で断り、メンバー記録も意図記録も増えない
//! - (5) 復元した公開の `unpublish_port_recorded` は DELRULE を送らず `StaleHandles` で断り、新テーブルの別ルールが
//!   残り、メンバー記録は変わらない
//! - (6) 別ネットワークで、片方のルールだけ残した公開の切り離し失敗が、テーブル handle とルール handle つきの
//!   請求書（v2）をストアへ保存する（開き直して読み戻す）。`reclaim_failed_attach` がそのルールだけを消し、同じ
//!   コンテナの別の公開・他コンテナの DNAT は残る（NET-1・NET-6・REPAIR-4・SEC-1・#3285）
//! - (7) テーブルが作り直された後の回収は DELRULE を送らず、新テーブルの別ルールが残る
//!
//! - (8) 墓標（#3343）: 共有の予約ファイルを壊して解放を失敗させ、DELRULE 成功後の墓標を永続化する。ストアを
//!   開き直して `restore_unpublished_ports` で墓標を復元し（通常の復元には含まれない）、予約ファイルを直して
//!   `unpublish_port_recorded` を再試行すると、DELRULE を送らず予約だけが解放される。他の公開の DNAT は変わらず、
//!   解放された受け口は別コンテナが再び公開できる（NET-3・SEC-1・REPAIR-12）
//!
//! 子は `unshare --net --mount` の中（netns の pin の bind mount を mount namespace に閉じる）。
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
        RecordedError, attach_container_recorded, create_network_recorded,
        detach_container_recorded, restore_published_ports, restore_unpublished_ports,
        unpublish_port_recorded,
    };
    use fandhe_container_net::network::{
        ContainerAttachSpec, EndpointId, NetworkCreateSpec, NetworkName, PortProtocol, PortPublish,
        PortRegistry, UnpublishRules, reclaim_failed_attach,
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
        let base = std::env::temp_dir().join(format!("fc-pubrec-{}", std::process::id()));
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
        let base = std::env::args()
            .find_map(|a| a.strip_prefix("--base=").map(PathBuf::from))
            .unwrap_or_else(|| fail("missing --base (run via the launcher)"));
        let result = scenario(&route, &nft, &base, t)
            .and_then(|()| reclaim_scenario(&route, &nft, &base, t))
            .and_then(|()| tombstone_scenario(&route, &nft, &base, t));
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
        base: &Path,
        t: Duration,
    ) -> Result<(), String> {
        let dir = &base.join("store");
        let ns_dir = base.join("ns");
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
        let c0 = MemberId::new("c0").map_err(e)?;
        let pub_a = PortPublish::new(PortProtocol::Tcp, Ipv4Addr::new(192, 0, 2, 10), 8081, 81)
            .map_err(e)?;
        let pub_b = PortPublish::new(PortProtocol::Tcp, Ipv4Addr::new(192, 0, 2, 10), 8082, 82)
            .map_err(e)?;
        let (token, table, created, recorded_handle);
        let mut attach_handles = Vec::new();
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
            // (2b) 実際に 2 件を公開して attach する。実カーネルが返した rule handle が記録される。
            let spec0 =
                ContainerAttachSpec::new(EndpointId::new("c0").map_err(e)?, &created, ns_dir)
                    .and_then(|s| s.with_port_publishes(vec![pub_a, pub_b]))
                    .map_err(e)?;
            let mut ports0 = PortRegistry::new();
            let attached =
                attach_container_recorded(route, nft, &n, &c0, &spec0, &[], &mut ports0, t)
                    .map_err(|x| format!("attach_container_recorded(c0): {x:?}"))?;
            if attached.published_ports.len() != 2 {
                return Err(format!(
                    "c0 must publish 2 ports, got {}",
                    attached.published_ports.len()
                ));
            }
            for p in &attached.published_ports {
                attach_handles.push((
                    *p.publish(),
                    p.prerouting_handle().get(),
                    p.output_handle().get(),
                ));
            }
            // (2) 公開つきのメンバー記録（実カーネルに無い rule handle 9001・9002）を書く。
            let rec = MemberRecord::new(
                mid.clone(),
                ep.clone(),
                IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 231, 0, 200)), 24).map_err(e)?,
                // 所有トークンは `<bridge_token>/ep/<endpoint>/g/<世代>` の形でなければ構築段階で拒否される。
                &format!("{token}/ep/c1/g/{:032x}", 1u8),
                Path::new("/run/fc-pubrec-ns"),
                (8, 9),
                &[],
            )
            .and_then(|r| {
                r.with_publishes(
                    realized.table_handle(),
                    vec![RecordedPublish::new(publish, rule(9001)?, rule(9002)?)],
                )
            })
            .map_err(e)?;
            n.commit_member(&rec).map_err(e)?;
        }
        // 再起動の模擬: ストアを開き直し、記録だけから公開を復元する。
        let store = NetworkStore::open(dir).map_err(e)?;
        let g = store.lock_global_exclusive().map_err(e)?;
        let n = g.lock_network(&name).map_err(e)?;
        let mut restored = restore_published_ports(nft, &n, &mid).map_err(e)?;
        if restored.len() != 1
            || *restored[0].publish() != publish
            || restored[0].table_handle().map(|h| h.get()) != Some(recorded_handle)
        {
            return Err(format!("unexpected restored ports: {}", restored.len()));
        }
        let member_path: PathBuf = dir.join("@networks/pubrec/members/c1");
        let before = fs::read(&member_path).map_err(e)?;

        // (2b) 再起動後に c0 の公開を復元し、記録の rule handle が attach の結果と一致することを確かめる。
        let mut c0_ports = restore_published_ports(nft, &n, &c0).map_err(e)?;
        if c0_ports.len() != 2 {
            return Err(format!("c0 restored {} ports, expected 2", c0_ports.len()));
        }
        for p in &c0_ports {
            let got = (
                *p.publish(),
                p.prerouting_handle().get(),
                p.output_handle().get(),
            );
            if !attach_handles.contains(&got)
                || p.table_handle().map(|h| h.get()) != Some(recorded_handle)
            {
                return Err(format!(
                    "restored c0 port does not match the attach result: {got:?}"
                ));
            }
        }
        let dnat = |port: &str| -> Result<usize, String> {
            let rs = run("nft", &["list", "table", "ip", table.as_str()])?;
            Ok(rs
                .lines()
                .filter(|l| l.contains("dnat to") && l.contains(port))
                .count())
        };
        if dnat("dport 8081")? != 2 || dnat("dport 8082")? != 2 {
            return Err("c0 must have 2 DNAT rules per published port before unpublish".to_owned());
        }
        let idx = c0_ports
            .iter()
            .position(|p| *p.publish() == pub_a)
            .ok_or("restored c0 lacks 8081")?;
        let target = c0_ports.remove(idx);
        let c1_before = fs::read(dir.join("@networks/pubrec/members/c1")).map_err(e)?;
        let mut reg0 = PortRegistry::new();
        unpublish_port_recorded(nft, &n, &c0, target, &mut reg0, t)
            .map_err(|x| format!("unpublish_port_recorded(c0 8081): {x:?}"))?;
        if dnat("dport 8081")? != 0 || dnat("dport 8082")? != 2 {
            return Err("only the 8081 DNAT rules must be removed".to_owned());
        }
        let left = restore_published_ports(nft, &n, &c0).map_err(e)?;
        if left.len() != 1 || *left[0].publish() != pub_b {
            return Err(format!("c0 record must keep only 8082, has {}", left.len()));
        }
        if fs::read(dir.join("@networks/pubrec/members/c1")).map_err(e)? != c1_before {
            return Err("the c1 record changed by unpublishing c0".to_owned());
        }
        let veths_before = run("ip", &["-o", "link", "show", "type", "veth"])?;

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
        if run("ip", &["-o", "link", "show", "type", "veth"])? != veths_before {
            return Err("a veth was created before the refusal".to_owned());
        }
        if n.members().map_err(e)?.len() != 2 || !n.member_intents().map_err(e)?.is_empty() {
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

    /// DNAT ルール（`dnat to` の行）のうち、`dport <port>` を含むものの数。
    fn dnat_count(table: &NftName, port: u16) -> Result<usize, String> {
        let rs = run("nft", &["list", "table", "ip", table.as_str()])?;
        let needle = format!("dport {port}");
        Ok(rs
            .lines()
            .filter(|l| l.contains("dnat to") && l.contains(&needle))
            .count())
    }

    /// 公開の切り離し失敗の請求書（DNAT ルールのハンドルつき）の保存・読み戻し・回収（#3285）。
    fn reclaim_scenario(
        route: &NetlinkRouteSocket,
        nft: &NetlinkNetfilterSocket,
        base: &Path,
        t: Duration,
    ) -> Result<(), String> {
        fn e(x: impl std::fmt::Display) -> String {
            x.to_string()
        }
        let dir = &base.join("store");
        let ns_dir = base.join("ns");
        let subnet = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 232, 0, 0)), 24).map_err(e)?;
        let gateway = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 232, 0, 1)), 24).map_err(e)?;
        let name = NetworkName::new("dnatrc").map_err(e)?;
        let def = NetworkDefinition::bridge("dnatrc", subnet).map_err(e)?;
        let store = NetworkStore::open(dir).map_err(e)?;
        store.create(&def).map_err(e)?;
        let publish = |host_port: u16| {
            PortPublish::new(
                PortProtocol::Tcp,
                Ipv4Addr::new(192, 0, 2, 10),
                host_port,
                80,
            )
            .map_err(e)
        };
        let mut ports = PortRegistry::new();
        let (table, token, table_handle);
        let (mut r0, mut r2) = (None, None);
        let (r0_handles, r2_handles);
        {
            let g = store.lock_global_exclusive().map_err(e)?;
            let n = g.lock_network(&name).map_err(e)?;
            let spec = NetworkCreateSpec::new(name.clone(), gateway).map_err(e)?;
            let created = create_network_recorded(route, nft, &n, &def, &spec, t)
                .map_err(|x| format!("create_network_recorded(dnatrc): {x:?}"))?;
            table = created.table.clone();
            token = created.bridge_token.clone();
            table_handle = live_handle(nft, &table, t)?;
            // r0: 8091・8092、r1: 8093（他コンテナ）、r2: 8094。
            for (id, host_ports) in [
                ("r0", vec![8091u16, 8092]),
                ("r1", vec![8093]),
                ("r2", vec![8094]),
            ] {
                let pubs = host_ports
                    .into_iter()
                    .map(publish)
                    .collect::<Result<Vec<_>, _>>()?;
                let spec = ContainerAttachSpec::new(
                    EndpointId::new(id).map_err(e)?,
                    &created,
                    ns_dir.clone(),
                )
                .and_then(|s| s.with_port_publishes(pubs))
                .map_err(e)?;
                let att = attach_container_recorded(
                    route,
                    nft,
                    &n,
                    &MemberId::new(id).map_err(e)?,
                    &spec,
                    &[],
                    &mut ports,
                    t,
                )
                .map_err(|x| format!("attach_container_recorded({id}): {x:?}"))?;
                match id {
                    "r0" => r0 = Some(att),
                    "r2" => r2 = Some(att),
                    _ => {}
                }
            }
            let handles_of = |c: &Option<_>, port: u16| -> Result<(u64, u64), String> {
                let c: &fandhe_container_net::network::AttachedContainer<_> =
                    c.as_ref().ok_or("container missing")?;
                c.published_ports
                    .iter()
                    .find(|p| p.publish().host_port() == port)
                    .map(|p| (p.prerouting_handle().get(), p.output_handle().get()))
                    .ok_or_else(|| format!("port {port} not published"))
            };
            r0_handles = handles_of(&r0, 8091)?;
            r2_handles = handles_of(&r2, 8094)?;
            for port in [8091, 8092, 8093, 8094] {
                if dnat_count(&table, port)? != 2 {
                    return Err(format!("port {port} must have 2 DNAT rules"));
                }
            }
            // 片方だけ残す: 8091 と 8094 の output チェインのルールを先に消す（一括削除は ENOENT で中止される）。
            for h in [r0_handles.1, r2_handles.1] {
                run(
                    "nft",
                    &[
                        "delete",
                        "rule",
                        "ip",
                        table.as_str(),
                        "output",
                        "handle",
                        &h.to_string(),
                    ],
                )?;
            }
            // r0 の切り離しは 8092（逆順で先）を消し、8091 で失敗する。請求書がストアへ保存される。
            match detach_container_recorded(
                route,
                nft,
                &n,
                &MemberId::new("r0").map_err(e)?,
                r0.take().ok_or("r0")?,
                Vec::new(),
                &mut ports,
                t,
            ) {
                Err(RecordedError::Op(_)) => {}
                other => {
                    return Err(format!(
                        "detach(r0) must fail with a saved claim (ok={})",
                        other.is_ok()
                    ));
                }
            }
        }
        // (6) ストアを開き直して請求書を読み戻す（永続化した記録そのもの）。
        let store = NetworkStore::open(dir).map_err(e)?;
        let g = store.lock_global_exclusive().map_err(e)?;
        let n = g.lock_network(&name).map_err(e)?;
        let claims = n.reclaim_records().map_err(e)?.attach;
        let claim0 = claims
            .iter()
            .find(|c| c.endpoint().as_str() == "r0")
            .ok_or("no saved claim for r0")?;
        let rec = claim0.to_record();
        let rule_lines: Vec<&str> = rec.lines().filter(|l| l.starts_with("rule=")).collect();
        let want_rule = format!(
            "rule=tcp 192.0.2.10:8091 80 {} {}",
            r0_handles.0, r0_handles.1
        );
        if !rec.starts_with("fandhe-net-attach-claim v2\n")
            || !rec.contains(&format!("table-handle={table_handle}\n"))
            || rule_lines != vec![want_rule.as_str()]
        {
            return Err(format!("unexpected saved claim: {rec}"));
        }
        if dnat_count(&table, 8091)? != 1
            || dnat_count(&table, 8092)? != 0
            || dnat_count(&table, 8093)? != 2
        {
            return Err(
                "before the reclaim: 8091 must keep 1 rule, 8092 none, 8093 both".to_owned(),
            );
        }
        // 読み戻した請求書で回収する。残った 1 本だけが消え、他コンテナの公開は残る。
        reclaim_failed_attach(route, nft, claim0, &ns_dir, t)
            .map_err(|x| format!("reclaim_failed_attach(r0): {x}; report: {:?}", x.report))?;
        if dnat_count(&table, 8091)? != 0 || dnat_count(&table, 8093)? != 2 {
            return Err("after the reclaim: 8091 must be gone and 8093 untouched".to_owned());
        }

        // (7) r2 も請求書を保存させた後で、テーブルを作り直してから回収する。
        match detach_container_recorded(
            route,
            nft,
            &n,
            &MemberId::new("r2").map_err(e)?,
            r2.take().ok_or("r2")?,
            Vec::new(),
            &mut ports,
            t,
        ) {
            Err(RecordedError::Op(_)) => {}
            other => {
                return Err(format!(
                    "detach(r2) must fail with a saved claim (ok={})",
                    other.is_ok()
                ));
            }
        }
        let claim2 = n
            .reclaim_records()
            .map_err(e)?
            .attach
            .into_iter()
            .find(|c| c.endpoint().as_str() == "r2")
            .ok_or("no saved claim for r2")?;
        let rec2 = claim2.to_record();
        if !rec2.contains(&format!("table-handle={table_handle}\n"))
            || !rec2.contains(&format!(" {} {}\n", r2_handles.0, r2_handles.1))
        {
            return Err(format!("unexpected saved claim for r2: {rec2}"));
        }
        nft.send_batch(t, |b| {
            b.push_with(|seq| {
                TableDelete::by_handle(NftFamily::Ipv4, table.clone(), table_handle).build(seq)
            })?;
            b.push_with(|seq| {
                TableCreate::new(NftFamily::Ipv4, table.clone())
                    .with_userdata(token.as_bytes())?
                    .build(seq)
            })?;
            Ok(())
        })
        .map_err(|x| format!("recreate table: {x}"))?;
        if live_handle(nft, &table, t)? == table_handle {
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
        let before = run("nft", &["-a", "list", "table", "ip", table.as_str()])?;
        reclaim_failed_attach(route, nft, &claim2, &ns_dir, t)
            .map_err(|x| format!("reclaim_failed_attach(r2): {x}; report: {:?}", x.report))?;
        let after = run("nft", &["-a", "list", "table", "ip", table.as_str()])?;
        if after != before || !after.contains("counter") {
            return Err(format!(
                "the recreated table must be untouched: {before} -> {after}"
            ));
        }
        Ok(())
    }

    /// 墓標の保存・復元・予約だけの解放の完了（#3343）。
    fn tombstone_scenario(
        route: &NetlinkRouteSocket,
        nft: &NetlinkNetfilterSocket,
        base: &Path,
        t: Duration,
    ) -> Result<(), String> {
        fn e(x: impl std::fmt::Display) -> String {
            x.to_string()
        }
        let dir = &base.join("store");
        let ns_dir = base.join("ns");
        let reg_dir = base.join("reg");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&reg_dir)
            .map_err(e)?;
        let reg_path = reg_dir.join("ports.reg");
        let subnet = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 233, 0, 0)), 24).map_err(e)?;
        let gateway = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 233, 0, 1)), 24).map_err(e)?;
        let name = NetworkName::new("tomb").map_err(e)?;
        let def = NetworkDefinition::bridge("tomb", subnet).map_err(e)?;
        let store = NetworkStore::open(dir).map_err(e)?;
        store.create(&def).map_err(e)?;
        let publish = |host_port: u16| {
            PortPublish::new(
                PortProtocol::Tcp,
                Ipv4Addr::new(192, 0, 2, 10),
                host_port,
                80,
            )
            .map_err(e)
        };
        let (pub_a, pub_b) = (publish(8101)?, publish(8102)?);
        let t0 = MemberId::new("t0").map_err(e)?;
        let table;
        let created;
        let good;
        {
            let g = store.lock_global_exclusive().map_err(e)?;
            let n = g.lock_network(&name).map_err(e)?;
            let spec = NetworkCreateSpec::new(name.clone(), gateway).map_err(e)?;
            created = create_network_recorded(route, nft, &n, &def, &spec, t)
                .map_err(|x| format!("create_network_recorded(tomb): {x:?}"))?;
            table = created.table.clone();
            let spec0 = ContainerAttachSpec::new(
                EndpointId::new("t0").map_err(e)?,
                &created,
                ns_dir.clone(),
            )
            .and_then(|s| s.with_port_publishes(vec![pub_a, pub_b]))
            .map_err(e)?;
            let mut ports = PortRegistry::with_shared_file(reg_path.clone());
            attach_container_recorded(route, nft, &n, &t0, &spec0, &[], &mut ports, t)
                .map_err(|x| format!("attach_container_recorded(t0): {x:?}"))?;
            good = fs::read(&reg_path).map_err(e)?;
            if dnat_count(&table, 8101)? != 2 || dnat_count(&table, 8102)? != 2 {
                return Err("t0 must have 2 DNAT rules per published port".to_owned());
            }
            // 予約ファイルを壊して解放だけを失敗させる。DELRULE は成功し、墓標が書かれる。
            let mut restored = restore_published_ports(nft, &n, &t0).map_err(e)?;
            let idx = restored
                .iter()
                .position(|p| *p.publish() == pub_a)
                .ok_or("restored t0 lacks 8101")?;
            let target = restored.remove(idx);
            fs::write(&reg_path, b"garbage\n").map_err(e)?;
            match unpublish_port_recorded(nft, &n, &t0, target, &mut ports, t) {
                Err(RecordedError::Op(err))
                    if err.rules == UnpublishRules::Removed && err.reservation_held => {}
                other => {
                    return Err(format!(
                        "unpublish must fail with Removed and a held reservation (ok={})",
                        other.is_ok()
                    ));
                }
            }
        }
        if dnat_count(&table, 8101)? != 0 || dnat_count(&table, 8102)? != 2 {
            return Err("after the failed release: 8101 gone, 8102 untouched".to_owned());
        }
        // 再起動の模擬: 予約ファイルを直し、ストアを開き直して墓標を復元する。
        fs::write(&reg_path, &good).map_err(e)?;
        let store = NetworkStore::open(dir).map_err(e)?;
        let g = store.lock_global_exclusive().map_err(e)?;
        let n = g.lock_network(&name).map_err(e)?;
        let live = restore_published_ports(nft, &n, &t0).map_err(e)?;
        if live.len() != 1 || *live[0].publish() != pub_b {
            return Err(format!(
                "only 8102 may be a live publish, got {}",
                live.len()
            ));
        }
        let mut tomb = restore_unpublished_ports(nft, &n, &t0).map_err(e)?;
        if tomb.len() != 1 || *tomb[0].publish() != pub_a {
            return Err(format!(
                "expected one tombstone for 8101, got {}",
                tomb.len()
            ));
        }
        let members_before = n.members().map_err(e)?;
        if members_before.len() != 1 || !members_before[0].is_unpublished(&pub_a) {
            return Err("the member record must hold the tombstone".to_owned());
        }
        // 再試行: DELRULE を送らず予約だけを解放する。
        let mut ports = PortRegistry::with_shared_file(reg_path.clone());
        unpublish_port_recorded(nft, &n, &t0, tomb.remove(0), &mut ports, t)
            .map_err(|x| format!("tombstone retry: {x:?}"))?;
        if dnat_count(&table, 8101)? != 0 || dnat_count(&table, 8102)? != 2 {
            return Err("the retry must not change any DNAT rule".to_owned());
        }
        let after = n.members().map_err(e)?;
        if after.len() != 1
            || after[0].publishes().len() != 1
            || !after[0].has_publish(&pub_b)
            || after[0].has_publish(&pub_a)
        {
            return Err("the record must keep only 8102 after the retry".to_owned());
        }
        if !restore_unpublished_ports(nft, &n, &t0)
            .map_err(e)?
            .is_empty()
        {
            return Err("the tombstone must be gone after the retry".to_owned());
        }
        // 解放の確認: 8101 は別コンテナが再び公開でき、8102 の予約は残る。
        let spec1 = ContainerAttachSpec::new(EndpointId::new("t1").map_err(e)?, &created, ns_dir)
            .and_then(|s| s.with_port_publishes(vec![pub_a]))
            .map_err(e)?;
        attach_container_recorded(
            route,
            nft,
            &n,
            &MemberId::new("t1").map_err(e)?,
            &spec1,
            &[],
            &mut ports,
            t,
        )
        .map_err(|x| format!("8101 must be reservable again after the retry: {x:?}"))?;
        if dnat_count(&table, 8101)? != 2 || dnat_count(&table, 8102)? != 2 {
            return Err("after re-publishing 8101: both must have 2 DNAT rules".to_owned());
        }
        Ok(())
    }
}
