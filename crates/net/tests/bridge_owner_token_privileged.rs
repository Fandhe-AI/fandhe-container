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
//!   (4) 別名を戻した正規の `delete_network` で bridge が消えることを確認する
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
mod linux {
    use std::fs;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_net::netlink_route::{IpPrefix, NetlinkRouteSocket};
    use fandhe_container_net::network::{
        NetworkCreateSpec, NetworkName, NetworkResourceNames, PortRegistry, StaticIpam,
        create_network, delete_network,
    };
    use fandhe_container_net::nftables_batch::NetlinkNetfilterSocket;

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
        let mut c = Command::new("unshare")
            .args(["--net", "--"])
            .arg(exe)
            .arg("--child")
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn unshare child");
        let deadline = Instant::now() + timeout() * 3;
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

    /// `ip` を実行して標準出力を返す（失敗は `Err` に標準エラーを載せる）。期限つき。
    fn ip(args: &[&str]) -> Result<String, String> {
        let mut c = Command::new("ip")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn ip: {e}"))?;
        let deadline = Instant::now() + timeout();
        loop {
            if c.try_wait().map_err(|e| e.to_string())?.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = c.kill();
                let _ = c.wait();
                return Err("ip timed out".to_owned());
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
        println!(
            "bridge_owner_token_privileged: ok alias=token index=match foreign=kept delete=ok"
        );
    }
}
