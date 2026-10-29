//! bridge の所有トークンが実カーネルで付き、読み戻せることの実機結合試験
//! （NET-1・NET-4・NET-11・TASK-139 追補・Issue #1925・MS-8）。
//!
//! カーネルは作成要求（`RTM_NEWLINK`）の `IFLA_IFALIAS` を反映しないため、`create_network` は作成の ACK 後に
//! ifindex 指定の `RTM_SETLINK` で所有トークンを付ける。単体テストは fake のカーネル模型でしか検証できない
//! ので、本試験で実カーネルの挙動（`ip -o link show` の `alias` 表示）と突き合わせる。
//!
//! root と util-linux の `unshare --net`、iproute2 の `ip` が必要な実機前提テストのため `harness = false` の
//! 独自 `main` で動かし、`-- --ignored` を付けたときだけ実行する（未指定時は「ignored」を出力して成功終了する
//! 分離であり、CI 通過のための弱体化ではない。この端末のように AppArmor が非特権 user namespace を制限する
//! 環境では `unshare -rn` が使えず、既定のテスト集合には置けない。`AGENTS.md`「実機前提テスト」節）。
//! 非 Linux では対象外。
//!
//! # 流れ
//! - ランチャ（root）: `unshare --net -- <自身> --child` で新しい netns の子を起動して終了を待つ
//! - 子（新 netns の中）: (0) 新しい netns であること（`lo` とフォールバックトンネルのみ）を確認して
//!   から、(1) `create_network` の成功と、`ip -o link show` の alias が `bridge_token`・ifindex が
//!   `bridge_index` と一致すること、(2) 別名の無い同名 bridge を先に作ると `AlreadyExists` で `leftover` が空
//!   かつその bridge が残ること、(3) 別名を書き換えた bridge を `delete_network` が削除せず失敗すること、
//!   (4) 別名を戻した正規の `delete_network` で bridge が消えること、(5) 作成失敗の回収（`reclaim_failed_create`。
//!   #2467）が所有トークン一致の bridge・nft テーブルを消すこと、(6) bridge の別名が書き換えられていれば
//!   bridge に触れず（テーブルは独立に消える）、別名を戻した再回収で収束すること、(7) 請求書を永続化記録（ファイル）
//!   へ書いて読み戻した請求書で回収できること（#2604）、(8) 印を刻む前に失敗した bridge（別名なし）は回収が触れず、
//!   手で消した後の再回収で収束すること（#2604）、(9) `NLM_F_ECHO` 付きの bridge 作成要求の作成通知から得た
//!   ifindex が `ip -o link show` と一致すること（Linux v6.2 以降。それより前は通知が無く、戻し経路で
//!   `create_network` が成功すること。Issue #1972）を確認する
//!
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。前提（root・
//! `unshare`・`ip`）を満たさない場合は skip せず失敗する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("bridge_owner_token_privileged: Linux only, not applicable on this OS");
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
            "bridge_owner_token_privileged: ignored (requires root, `unshare --net` and `ip`; run the built executable with `--ignored` under `sudo`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
#[path = "support/reap.rs"]
mod reap;

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_net::netlink_route::{
        IfName, IpPrefix, LinkCreate, NetlinkRouteSocket, decode_created_link,
    };
    use fandhe_container_net::network::{
        FailedCreateClaim, NetworkCreateSpec, NetworkName, NetworkResourceNames, PortRegistry,
        StaticIpam, create_network, delete_network, reclaim_failed_create,
    };
    use fandhe_container_net::nftables_batch::{NetlinkNetfilterSocket, NftFamily, TableGet};

    /// 新規 netns にカーネルが自動生成しうるデバイス（モジュールのロード状況で有無が変わる）。
    const ALLOWED_DEVICES: [&str; 11] = [
        "lo",
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

    /// SIGKILL の後に `try_wait` を有限の猶予でポーリングして回収する（期限なしの `wait` は使わない。REPAIR-5）。
    /// 猶予内に回収できなければ `false` を返し、呼び出し側が結果に含めて明示的に失敗させる。
    fn kill_and_reap(c: &mut std::process::Child) -> bool {
        let _ = c.kill();
        let grace = Instant::now() + Duration::from_secs(5);
        loop {
            if matches!(c.try_wait(), Ok(Some(_))) {
                return true;
            }
            if Instant::now() >= grace {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// 現在のプロセスの netns 識別子（`/proc/self/ns/net` のリンク先。`net:[inode]`）。
    fn netns_id() -> Result<String, String> {
        fs::read_link("/proc/self/ns/net")
            .map(|p| p.to_string_lossy().into_owned())
            .map_err(|e| format!("read_link /proc/self/ns/net: {e}"))
    }

    pub fn launcher() {
        let uid_root = fs::read_to_string("/proc/self/status")
            .expect("read /proc/self/status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_owned))
            .as_deref()
            == Some("0");
        assert!(uid_root, "this test requires root (euid 0); see AGENTS.md");
        let exe = std::env::current_exe().expect("current_exe");
        // 子が新規 netns であることを識別子の比較で確認するため、ランチャ（元の netns）の識別子を渡す。
        let parent_ns = netns_id().expect("launcher netns id");
        let mut c = Command::new("unshare")
            .args(["--net", "--"])
            .arg(exe)
            .arg("--child")
            .arg(format!("--parent-netns={parent_ns}"))
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn unshare child");
        let deadline = Instant::now() + timeout() * 3;
        let st = loop {
            if let Some(st) = c.try_wait().expect("try_wait") {
                break st;
            }
            if Instant::now() >= deadline {
                let reaped = kill_and_reap(&mut c);
                panic!("child did not exit within the timeout (reaped after SIGKILL: {reaped})");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(st.success(), "child failed: {st:?}");
    }

    /// `ip` を実行して標準出力を返す（失敗は `Err` に標準エラーを載せる）。期限つき。
    fn ip(args: &[&str]) -> Result<String, String> {
        let mut cmd = Command::new("ip");
        cmd.args(args);
        // spawn・期限・出力回収を一括で期限つきにする（`wait_with_output` の無期限待ちを避ける。REPAIR-5・#3409）。
        let out = crate::reap::output_within(&mut cmd, timeout())?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).into_owned())
        }
    }

    /// `ip -o link show <name>` の出力から (ifindex, alias) を取り出す。
    fn show(name: &str) -> Result<(u32, Option<String>), String> {
        let out = ip(&["-o", "link", "show", name])?;
        let index = out
            .split(':')
            .next()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .ok_or_else(|| format!("no ifindex in {out:?}"))?;
        let mut words = out.split_whitespace();
        let mut alias = None;
        while let Some(w) = words.next() {
            if w == "alias" {
                alias = words.next().map(str::to_owned);
            }
        }
        Ok((index, alias))
    }

    fn fail(msg: &str) -> ! {
        eprintln!("bridge_owner_token_privileged: child failed: {msg}");
        std::process::exit(1);
    }

    pub fn child() {
        // (0) 新しい netns であること。ホストの bridge を触らないための防御。
        // ランチャの netns 識別子と同一、または確認不能なら、何も変更せず拒否する。
        let parent_ns = std::env::args()
            .find_map(|a| a.strip_prefix("--parent-netns=").map(str::to_owned))
            .unwrap_or_else(|| fail("missing --parent-netns (run via the launcher)"));
        let own_ns = netns_id().unwrap_or_else(|e| fail(&e));
        if own_ns == parent_ns {
            fail(&format!("child shares the launcher netns ({own_ns})"));
        }
        // 補助: 新規 netns に出るデバイスだけであること。
        let devs = fs::read_to_string("/proc/net/dev").unwrap_or_else(|e| fail(&e.to_string()));
        for l in devs.lines().skip(2) {
            let n = l.split(':').next().map(str::trim).unwrap_or_default();
            if !ALLOWED_DEVICES.contains(&n) {
                fail(&format!("not a fresh netns (found interface {n})"));
            }
        }

        let route = NetlinkRouteSocket::open().unwrap_or_else(|e| fail(&e.to_string()));
        let nft = NetlinkNetfilterSocket::open().unwrap_or_else(|e| fail(&e.to_string()));
        let t = timeout();
        let spec = |name: &str, gw: [u8; 4]| {
            NetworkCreateSpec::new(
                NetworkName::new(name).unwrap_or_else(|e| fail(&e.to_string())),
                IpPrefix::new(std::net::IpAddr::from(gw), 24)
                    .unwrap_or_else(|e| fail(&e.to_string())),
            )
            .unwrap_or_else(|e| fail(&e.to_string()))
        };

        // (1) 作成の成功と、実カーネルでの alias・ifindex の一致。
        let net = create_network(&route, &nft, &spec("own", [10, 214, 0, 1]), t)
            .unwrap_or_else(|e| fail(&format!("create_network: {e}")));
        let (idx, alias) = show(net.bridge.as_str()).unwrap_or_else(|e| fail(&e));
        if alias.as_deref() != Some(net.bridge_token.as_str()) {
            fail(&format!("alias {alias:?} != token {:?}", net.bridge_token));
        }
        if idx != net.bridge_index.get() {
            fail(&format!("ifindex {idx} != {}", net.bridge_index.get()));
        }

        // (2) 別名の無い同名 bridge が先にあれば、他者のものとして削除せず AlreadyExists。
        let pre = NetworkResourceNames::derive(
            &NetworkName::new("pre").unwrap_or_else(|e| fail(&e.to_string())),
        )
        .unwrap_or_else(|e| fail(&e.to_string()));
        ip(&["link", "add", pre.bridge().as_str(), "type", "bridge"]).unwrap_or_else(|e| fail(&e));
        match create_network(&route, &nft, &spec("pre", [10, 215, 0, 1]), t) {
            Ok(_) => fail("create_network must fail when the bridge already exists"),
            Err(e) => {
                if e.code() != fandhe_container_net::error::NetErrorCode::AlreadyExists {
                    fail(&format!("expected AlreadyExists, got {e}"));
                }
                if !e.rollback.leftover.is_empty() || !e.rollback.removed.is_empty() {
                    fail(&format!("unexpected rollback report {:?}", e.rollback));
                }
            }
        }
        if show(pre.bridge().as_str()).is_err() {
            fail("someone else's bridge was removed");
        }

        // (3) 別名が書き換えられた bridge は delete_network が削除せず失敗する。
        let mut ipam = StaticIpam::for_network(&net).unwrap_or_else(|e| fail(&e.to_string()));
        let mut ports = PortRegistry::new();
        ip(&["link", "set", net.bridge.as_str(), "alias", "other-owner"])
            .unwrap_or_else(|e| fail(&e));
        if delete_network(&route, &nft, &net, Vec::new(), &mut ipam, &mut ports, t).is_ok() {
            fail("delete_network must refuse a bridge with a foreign alias");
        }
        if show(net.bridge.as_str()).is_err() {
            fail("bridge with a foreign alias was removed");
        }

        // (4) 別名を戻した正規の削除で bridge が消える。
        ip(&[
            "link",
            "set",
            net.bridge.as_str(),
            "alias",
            &net.bridge_token,
        ])
        .unwrap_or_else(|e| fail(&e));
        delete_network(&route, &nft, &net, Vec::new(), &mut ipam, &mut ports, t)
            .unwrap_or_else(|e| fail(&format!("delete_network: {e}")));
        if show(net.bridge.as_str()).is_ok() {
            fail("bridge still exists after delete_network");
        }

        // (5) 作成失敗の回収。所有トークン一致の bridge・テーブルが消える。
        let table_gone = |table: &fandhe_container_net::nftables_batch::NftName| {
            matches!(
                nft.table_info(&TableGet::new(NftFamily::Ipv4, table.clone()), t),
                Err(e) if e.code() == fandhe_container_net::error::NetErrorCode::NotFound
            )
        };
        let rc = create_network(&route, &nft, &spec("rc", [10, 216, 0, 1]), t)
            .unwrap_or_else(|e| fail(&format!("create_network rc: {e}")));
        reclaim_failed_create(&route, &nft, &FailedCreateClaim::from_created(&rc), t)
            .unwrap_or_else(|e| fail(&format!("reclaim_failed_create: {e}")));
        if show(rc.bridge.as_str()).is_ok() {
            fail("bridge still exists after reclaim");
        }
        if !table_gone(&rc.table) {
            fail("nft table still exists after reclaim");
        }

        // (6) bridge の別名が書き換えられていれば bridge に触れない。テーブルは独立に消える。
        let rf = create_network(&route, &nft, &spec("rf", [10, 217, 0, 1]), t)
            .unwrap_or_else(|e| fail(&format!("create_network rf: {e}")));
        let claim = FailedCreateClaim::from_created(&rf);
        ip(&["link", "set", rf.bridge.as_str(), "alias", "other-owner"])
            .unwrap_or_else(|e| fail(&e));
        match reclaim_failed_create(&route, &nft, &claim, t) {
            Ok(_) => fail("reclaim must refuse a bridge with a foreign alias"),
            Err(e) => {
                let want = vec![(
                    fandhe_container_net::network::DeleteResource::Bridge(rf.bridge.clone()),
                    fandhe_container_net::network::ResourceState::Unknown,
                )];
                if e.report.leftover != want {
                    fail(&format!("unexpected reclaim report {:?}", e.report));
                }
            }
        }
        if show(rf.bridge.as_str()).is_err() {
            fail("bridge with a foreign alias was removed by reclaim");
        }
        if !table_gone(&rf.table) {
            fail("owned nft table was not removed by reclaim");
        }
        ip(&["link", "set", rf.bridge.as_str(), "alias", &rf.bridge_token])
            .unwrap_or_else(|e| fail(&e));
        reclaim_failed_create(&route, &nft, &claim, t)
            .unwrap_or_else(|e| fail(&format!("second reclaim: {e}")));
        if show(rf.bridge.as_str()).is_ok() {
            fail("bridge still exists after the second reclaim");
        }

        // (7) 請求書を永続化記録（ファイル）へ書いて読み戻しても、実カーネルの bridge・テーブルを回収できる
        // （plugin の再起動後の回収の核。記録を読むのは復号だけで、所有はカーネル側のトークンで判定する。#2604）。
        let rr = create_network(&route, &nft, &spec("rr", [10, 218, 0, 1]), t)
            .unwrap_or_else(|e| fail(&format!("create_network rr: {e}")));
        // 共有一時ディレクトリの予測できるパスへ書かない: 0700 の専用ディレクトリを新規に作り、その中に
        // `create_new` で排他的に作る（既存ファイルの切り詰め・symlink 追従を許さない）。
        let record_dir = std::env::temp_dir().join(format!(
            "fandhe-bridge-owner-token-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        {
            use std::os::unix::fs::DirBuilderExt as _;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&record_dir)
                .unwrap_or_else(|e| fail(&e.to_string()));
        }
        let record_path = record_dir.join("rr.claim");
        {
            use std::io::Write as _;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&record_path)
                .unwrap_or_else(|e| fail(&e.to_string()));
            f.write_all(FailedCreateClaim::from_created(&rr).to_record().as_bytes())
                .unwrap_or_else(|e| fail(&e.to_string()));
        }
        let record = fs::read_to_string(&record_path).unwrap_or_else(|e| fail(&e.to_string()));
        let _ = fs::remove_dir_all(&record_dir);
        let restored =
            FailedCreateClaim::from_record(&record).unwrap_or_else(|e| fail(&e.to_string()));
        reclaim_failed_create(&route, &nft, &restored, t)
            .unwrap_or_else(|e| fail(&format!("reclaim from record: {e}")));
        if show(rr.bridge.as_str()).is_ok() || !table_gone(&rr.table) {
            fail("resources remain after reclaim from a persisted record");
        }

        // (8) 印（別名）を刻む前に失敗して残った bridge は自動回収されず Unknown のまま残る。手で消した後の
        // 再回収は収束する（`docs/setup/network-reclaim-recovery.md` の手順。REPAIR-4）。
        let un = NetworkName::new("un").unwrap_or_else(|e| fail(&e.to_string()));
        let un_names = NetworkResourceNames::derive(&un).unwrap_or_else(|e| fail(&e.to_string()));
        ip(&["link", "add", un_names.bridge().as_str(), "type", "bridge"])
            .unwrap_or_else(|e| fail(&e));
        let un_claim = FailedCreateClaim::from_record(
            "fandhe-net-claim v1\nnetwork=un\ntoken=fandhe-net:un:1:2:3\nbridge=1\ntable=0\n",
        )
        .unwrap_or_else(|e| fail(&e.to_string()));
        if reclaim_failed_create(&route, &nft, &un_claim, t).is_ok() {
            fail("reclaim must not remove a bridge without an ownership alias");
        }
        if show(un_names.bridge().as_str()).is_err() {
            fail("unstamped bridge was removed by reclaim");
        }
        ip(&["link", "delete", un_names.bridge().as_str()]).unwrap_or_else(|e| fail(&e));
        reclaim_failed_create(&route, &nft, &un_claim, t)
            .unwrap_or_else(|e| fail(&format!("reclaim after manual removal: {e}")));

        // (9) NLM_F_ECHO 付きの作成要求の作成通知から ifindex を得る（Issue #1972）。v6.2 以降は通知が届き、
        // ifindex が実カーネルと一致する。それより前は通知が無く、戻し経路で create_network が成功する。
        // 版を読めない・期待と違う場合は skip せず失敗する。
        let release = fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_else(|e| fail(&format!("read osrelease: {e}")));
        let mut nums = release
            .trim()
            .split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .map(|p| p.parse::<u32>().ok());
        let (major, minor) = match (nums.next().flatten(), nums.next().flatten()) {
            (Some(a), Some(b)) => (a, b),
            _ => fail(&format!("cannot parse kernel release {release:?}")),
        };
        let echo_supported = (major, minor) >= (6, 2);
        let eb = IfName::new("fcecho0").unwrap_or_else(|e| fail(&e.to_string()));
        let reply = route
            .create_link(&LinkCreate::bridge(eb.clone()).with_echo(), t)
            .unwrap_or_else(|e| fail(&format!("create_link with echo: {e}")));
        let echoed = decode_created_link(
            reply.messages().iter().map(|m| (m.msg_type(), m.payload())),
            &eb,
        )
        .unwrap_or_else(|e| fail(&format!("decode echo reply: {e}")));
        let (actual_index, _) = show(eb.as_str()).unwrap_or_else(|e| fail(&e));
        ip(&["link", "delete", eb.as_str()]).unwrap_or_else(|e| fail(&e));
        match (echo_supported, echoed) {
            (true, Some(i)) if i.get() == actual_index => {}
            (false, None) => {}
            (supported, got) => fail(&format!(
                "unexpected echo result on kernel {release:?}: supported={supported} echoed={:?} actual={actual_index}",
                got.map(|i| i.get())
            )),
        }
        let en = create_network(&route, &nft, &spec("ec", [10, 219, 0, 1]), t)
            .unwrap_or_else(|e| fail(&format!("create_network after echo: {e}")));
        let (en_index, en_alias) = show(en.bridge.as_str()).unwrap_or_else(|e| fail(&e));
        if en_index != en.bridge_index.get()
            || en_alias.as_deref() != Some(en.bridge_token.as_str())
        {
            fail("create_network bridge does not match the created index or token");
        }
        delete_network(&route, &nft, &en, Vec::new(), &mut ipam, &mut ports, t)
            .unwrap_or_else(|e| fail(&format!("delete_network ec: {e}")));
        if echo_supported {
            println!(
                "bridge_owner_token_privileged: ok alias=token index=match foreign=kept delete=ok reclaim=ok reclaim_foreign=kept reclaim_restart=ok reclaim_manual=converged echo=index"
            );
        } else {
            println!(
                "bridge_owner_token_privileged: ok alias=token index=match foreign=kept delete=ok reclaim=ok reclaim_foreign=kept reclaim_restart=ok reclaim_manual=converged echo=fallback"
            );
        }
    }
}
