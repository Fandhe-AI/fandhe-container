//! コンテナ接続（netns 作成・pin、veth 作成、bridge 接続、peer の netns 移動）の実機結合試験
//! （NET-1・TASK-139.2.1・#847・MS-8）。
//!
//! root と util-linux の `unshare` / `nsenter` / `mount` が必要な実機前提テストのため `harness = false` の
//! 独自 `main` で動かし、`-- --ignored` を付けたときだけ実行する（未指定時は「ignored」を出力して成功終了
//! する分離であり、CI 通過のための弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では
//! 対象外（skip ではなく OS 非該当）。
//!
//! # 流れ
//! - ランチャ（host netns・root）: 0700 の一時ディレクトリを作り、`unshare --net --mount -- <exe> --inner` で
//!   新しい netns・mount namespace の子を起動して終了コードを引き継ぐ。終了後に一時ディレクトリを消す
//! - 子（新 netns・新 mount namespace の中）: `/` を rprivate にし、一時ディレクトリへ tmpfs を載せる
//!   （bind マウントと pin ファイルを host へ漏らさない）→ `create_network` で bridge を作る →
//!   `attach_container` を実行し、(1) host 側 veth の `IFLA_MASTER` が bridge の ifindex と一致し `IFF_UP`、
//!   (2) peer 側が子の netns から消えている、(3) pin パスの inode が保持 fd の netns と一致し子の netns と
//!   別、(4) `nsenter --net=<pin>` 越しの `/proc/net/dev` に `eth0` が現れ、veth 作成時の peer 名は無い（改名。#3061）、を具体値で照合する。
//!   続けて host 側 veth 名を事前に作っておき `AlreadyExists` で失敗させ、pin ファイルが消え、事前作成の
//!   veth が残ることでロールバック（他者のリソースを消さない）を確認する
//!
//! ポート公開付きの接続（c3）では、`nft list table` に DNAT が 2 件入ることに続けて、公開の個別解除
//! （`unpublish_container_port`。echo 応答のハンドル指定。NET-3・#2839）で 2 件が消え予約が空になること、
//! 同じ受け口を再び公開できる（`publish_container_ports`）ことを具体値で照合する。
//!
//! 公開の個別解除の後に、コンテナ単体の切り離し（`detach_container`。NET-1・NET-3・#3062）を確かめる。c11 と c12
//! （それぞれ TCP 公開つき）を接続して c11 だけを外し、veth が `NotFound`・pin が消え・DNAT が c12 の 2 件だけになり、
//! c12 の veth が bridge に属して up のまま・IPAM と予約に c12 だけが残ることを具体値で照合する。続けて同じ
//! 受け口で再び接続でき、両方を外すと元の状態に戻る。実機（root）での実行は #1626（人間担当）で未実行。
//!
//! `delete_network` の前に、attach の取り残しの回収（`reclaim_failed_attach`。#2681）を確かめる。c4 を接続し、
//! 請求書の記録の復号から回収して veth が `NotFound`・pin が消えること（2 回目も成功する冪等性）と、別名のない他者の veth は
//! 請求書に載っても消えないことを具体値で照合する。
//!
//! さらに、作った本人のプロセスが終わった後の回収（プロセスをまたぐ回収。NET-1・REPAIR-3・#2906）を確かめる。
//! 子プロセス（`--attach-child`）に自前のネットワーク `atx` を作らせて endpoint c8 を接続させ、請求書の記録を
//! 受けた直後に SIGKILL で終わらせる（デストラクタを走らせず、veth・pin・所有記録 `.owned/c8` が残る状態。実際の
//! 巻き戻し失敗の取り残しと残る資源は近いが、attach 成功後のプロセス終了で模すだけの場面）。別プロセス（`--reclaim-child`。メモリ上の所有記録を持たない）が請求書から
//! `reclaim_failed_attach` を呼び、veth と pin が回収されること（S1。冪等性を含む）と、同じ endpoint に作り直された
//! 新しい pin は古い請求書では外れないこと（S2）を具体値で照合する。子モードは inner が直接起動した場合しか
//! 動かない（親 pid・名前空間のガードで拒否する）。実機（root）での実行は #1626（人間担当）。
//!
//! 本物の巻き戻しの失敗による取り残しは、試験用 feature `attach-fault-test-support` の故障注入
//! （`attach_container_with_fault_for_test`。NET-1・REPAIR-3・#2971。feature が外れていると `--ignored` は名指しで失敗する）で作る。
//! S3: `SetUp` で失敗し veth 削除・unpin も失敗 → 別名つき・bridge 接続済みの veth と pin が残り、請求書
//! （pin の識別子つき）から別プロセスが `XRECLAIM ok removed=2 leftover=0` で回収する（冪等）。
//! S4: `SetOwnerToken` で失敗し veth 削除も失敗 → 別名の無い veth は所有を証明できず、回収は
//! `XRECLAIM err step=DeleteVeth removed=0 leftover=1` で拒否して veth を残す（試験が後始末する）。
//! IPAM 払い出し後の段（NET-1・REPAIR-3・#3040）も確かめる。
//! S5: ポート公開（8093）つきの c13 が `DefaultRoute` で失敗し veth 削除・unpin も失敗 → veth・pin・所有記録に加え
//! アドレスとポート予約が残り（`leftover` の末尾が `Address`・請求書は `quarantine=1`）、別プロセスの回収は
//! カーネル側の veth と pin だけを消して quarantine（アドレス・予約）は解放しない。解放は `delete_network` が行う。
//! S6: ポート公開（8094）つきの c14 が `AddAddress` で失敗し巻き戻しは成功 → veth・pin が消え、アドレスと予約は
//! 即時に解放され、DNAT は投入されない。S5 の quarantine は `delete_network` の前後で保持と解放を照合する。
//! 実機（root）での実行は #1626（人間担当）で未実行。
//!
//! 続けて netns の事前作成（`create_container_netns`。#2675・CRI-2）→ 接続（`attach_prepared_container`。c6）と、
//! 作成 → 解放（`release_container_netns`。c7。pin が消える）を確かめる。
//!
//! 最後に `delete_network`（TASK-139.4・#317）で c1・c3・c6 を渡してネットワークを削除し、bridge・host 側 veth が
//! `NotFound`、`nft list table` の失敗、pin ファイルの消滅、IPAM・ポート予約が空であることを具体値で照合する
//! （渡していない c2 の事前作成 veth は IPAM に無く、削除の対象外）。続けて空の `containers` での再実行が成功する（冪等）。
//!
//! veth の作成通知（`NLM_F_ECHO`。Issue #3205）も確かめる。専用の名前の veth を echo 付きで作り、`decode_created_veth` の
//! host / peer の ifindex が実カーネルの link と一致することを照合する（v6.2 以上。それより前は通知なしで、
//! `attach_container` は名前引きの戻し経路で成功する）。成功行は `veth_echo=index` / `veth_echo=fallback` の 2 通り。
//! 実機（root）での実行は #1626（人間担当）で未実行。
//!
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。前提（root・
//! 外部コマンド）を満たさない場合は skip せず失敗する。
//!
//! `create_network` が `ResolveIndex` で失敗する場合は所有トークンの付与・読み戻しが実カーネルで通っていない
//! 疑いとして名指しで失敗する。作成時の `IFLA_IFALIAS` はカーネルが反映しなかったため、作成後の
//! `RTM_SETLINK` で付ける方式に直した（Issue #1925。実機での再確認は `bridge_owner_token_privileged`）。

#[path = "support/reap.rs"]
mod reap;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("network_attach_privileged: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--attach-child") {
        linux::attach_child();
    } else if args.iter().any(|a| a == "--reclaim-child") {
        linux::reclaim_child();
    } else if args.iter().any(|a| a == "--inner") {
        linux::inner();
    } else if args.iter().any(|a| a == "--ignored") {
        linux::launcher();
    } else {
        println!(
            "network_attach_privileged: ignored (requires root, `unshare`, `nsenter`; run the built executable with `--ignored` under `sudo`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_net::error::{NetError, NetErrorCode};
    use fandhe_container_net::netlink::AttrIter;
    use fandhe_container_net::netlink_route::{
        IFF_UP, IFINFOMSG_LEN, IFLA_IFNAME, IFLA_MASTER, IfName, IpPrefix, LinkCreate, LinkDelete,
        LinkRef, NetlinkRouteSocket, NlMsgBuilder, RTM_GETLINK, RTM_NEWLINK, decode_created_veth,
    };
    #[cfg(feature = "attach-fault-test-support")]
    use fandhe_container_net::network::{
        AttachFault, AttachFaultPoint, attach_container_with_fault_for_test,
    };
    use fandhe_container_net::network::{
        AttachResource, AttachStep, ContainerAttachSpec, CreateStep, CreatedNetwork, DeleteStep,
        EndpointId, FailedAttachClaim, FailedCreateClaim, NetworkCreateSpec, NetworkName,
        PortProtocol, PortPublish, PortRegistry, ResourceState, StaticIpam, VethNames,
        attach_container, attach_prepared_container, create_container_netns, create_network,
        delete_network, detach_container, publish_container_ports, reclaim_failed_attach,
        reclaim_failed_create, release_container_netns, unpublish_container_port,
    };
    use fandhe_container_net::nftables_batch::NetlinkNetfilterSocket;

    const LAUNCHER_PID_ENV: &str = "FANDHE_ATTACH_TEST_LAUNCHER_PID";
    const DIR_ENV: &str = "FANDHE_ATTACH_TEST_DIR";
    /// inner が子（`--attach-child` / `--reclaim-child`）へ渡す自分の pid。子はこれが親 pid と一致しなければ拒否する。
    const INNER_PID_ENV: &str = "FANDHE_ATTACH_TEST_INNER_PID";
    /// `--reclaim-child` へ渡す請求書の記録（hex）。
    const CLAIM_HEX_ENV: &str = "FANDHE_ATTACH_TEST_CLAIM_HEX";
    /// 請求書の記録（hex）の長さ上限（外部入力として検証してから復号する）。
    const CLAIM_HEX_MAX_LEN: usize = 4096;
    /// attach 子が標準出力へ出す行の接頭辞。
    const ATTACH_CHILD_PREFIX: &str = "XATTACH_CHILD ";
    /// 成功行は veth の作成通知（`NLM_F_ECHO`。Issue #3205）が届く v6.2 以上か、届かない戻し経路かで 2 通り。
    /// `check-success-lines.sh` が試験ソースの文字列リテラルから導出するため、`format!` で組み立てず 2 つのリテラルで持つ。
    const OK_LINE_ECHO_INDEX: &str = "network_attach_privileged: ok master=bridge host=up peer=moved ifname=eth0 masq=ok pin=bound rollback=clean reclaim_attach=ok reclaim_attach_foreign=kept unpublish=ok reclaim_xproc=ok reclaim_xproc_newer=kept reclaim_fault=ok reclaim_fault_unowned=kept reclaim_fault_post_ipam=ok rollback_post_ipam=released detach=ok detach_sibling=kept veth_echo=index";
    const OK_LINE_ECHO_FALLBACK: &str = "network_attach_privileged: ok master=bridge host=up peer=moved ifname=eth0 masq=ok pin=bound rollback=clean reclaim_attach=ok reclaim_attach_foreign=kept unpublish=ok reclaim_xproc=ok reclaim_xproc_newer=kept reclaim_fault=ok reclaim_fault_unowned=kept reclaim_fault_post_ipam=ok rollback_post_ipam=released detach=ok detach_sibling=kept veth_echo=fallback";
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
        let dir = std::env::temp_dir().join(format!("fandhe-attach-test-{}", std::process::id()));
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
        // inner は、プロセスをまたぐ回収の確認（#2906）で子プロセスの起動・待ち・終了の回収を数回行うため、従来の 6 倍から広げる。
        let deadline = Instant::now() + timeout() * 10;
        let code = loop {
            match child.try_wait().expect("wait inner") {
                Some(st) => break st.code().unwrap_or(1),
                None if Instant::now() >= deadline => {
                    crate::reap::reap_or_report(&mut child, crate::reap::reap_within());
                    println!("network_attach_privileged: inner did not finish before deadline");
                    break 1;
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        // mount namespace は子の終了で消えるので、host 側には空のディレクトリだけが残る。
        let _ = fs::remove_dir(&dir);
        std::process::exit(code);
    }

    /// 自プロセスが「作成直後の新規 network namespace」にいることを検証する（fail-closed）。
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
                "`--inner` must be started by the `--ignored` launcher; refusing to run",
            ));
        }
        Ok(())
    }

    /// 外部コマンドを期限つきで実行する（REPAIR-5）。期限切れなら子を kill して回収する。
    fn run_cmd(program: &str, args: &[&str]) -> Result<String, NetError> {
        run_cmd_env(program, args, &[])
    }

    /// [`run_cmd`] に環境変数を足せる版（`--reclaim-child` の起動に使う）。
    fn run_cmd_env(
        program: &str,
        args: &[&str],
        envs: &[(&str, &str)],
    ) -> Result<String, NetError> {
        use std::io::Read as _;
        let mut child = Command::new(program)
            .args(args)
            .envs(envs.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| fail(format!("spawn {program}: {e}")))?;
        // パイプが詰まって子が止まらないよう、別スレッドで読み切る。
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
                    crate::reap::reap_or_report(&mut child, crate::reap::reap_within());
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

    /// 名前指定の `RTM_GETLINK` で応答の `RTM_NEWLINK` ペイロード（ifinfomsg + 属性）を返す。
    fn get_link_payload(sock: &NetlinkRouteSocket, name: &str) -> Result<Vec<u8>, NetError> {
        let n = IfName::new(name)?;
        let reply = sock.request(RTM_GETLINK, 0, timeout(), |b: &mut NlMsgBuilder| {
            b.put_fixed(&[0u8; IFINFOMSG_LEN])?;
            let mut v = n.as_str().as_bytes().to_vec();
            v.push(0);
            b.put_attr(IFLA_IFNAME, &v)
        })?;
        let msg = reply
            .messages()
            .iter()
            .find(|m| m.msg_type() == RTM_NEWLINK)
            .ok_or_else(|| fail("no RTM_NEWLINK in reply"))?;
        Ok(msg.payload().to_vec())
    }

    fn u32_at(payload: &[u8], range: std::ops::Range<usize>) -> Result<u32, NetError> {
        payload
            .get(range)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(u32::from_ne_bytes)
            .ok_or_else(|| fail("short ifinfomsg in reply"))
    }

    /// `(ifindex, ifi_flags, IFLA_MASTER)` を返す。
    fn link_state(
        sock: &NetlinkRouteSocket,
        name: &str,
    ) -> Result<(u32, u32, Option<u32>), NetError> {
        let payload = get_link_payload(sock, name)?;
        let index = u32_at(&payload, 4..8)?;
        let flags = u32_at(&payload, 8..12)?;
        let attrs = payload
            .get(IFINFOMSG_LEN..)
            .ok_or_else(|| fail("short ifinfomsg in reply"))?;
        for attr in AttrIter::new(attrs) {
            let attr = attr?;
            if attr.attr_type() == IFLA_MASTER {
                return Ok((index, flags, Some(u32_at(attr.payload(), 0..4)?)));
            }
        }
        Ok((index, flags, None))
    }

    /// 小文字 hex へ符号化する（請求書の記録を環境変数・標準出力で受け渡すため。依存を足さない）。
    fn hex_encode(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(char::from(DIGITS[usize::from(b >> 4)]));
            out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
        }
        out
    }

    /// [`hex_encode`] の復号。長さ上限・偶数長・文字種を検証し、違反は `Err`（外部入力として扱う）。
    fn hex_decode(text: &str) -> Result<String, NetError> {
        if text.is_empty() || text.len() > CLAIM_HEX_MAX_LEN || !text.len().is_multiple_of(2) {
            return Err(fail("claim hex has an invalid length"));
        }
        let nibble = |c: u8| -> Result<u8, NetError> {
            match c {
                b'0'..=b'9' => Ok(c - b'0'),
                b'a'..=b'f' => Ok(c - b'a' + 10),
                _ => Err(fail("claim hex has an invalid character")),
            }
        };
        let raw = text.as_bytes();
        let mut bytes = Vec::with_capacity(raw.len() / 2);
        for pair in raw.chunks(2) {
            let (Some(&hi), Some(&lo)) = (pair.first(), pair.get(1)) else {
                return Err(fail("claim hex has an odd length"));
            };
            bytes.push((nibble(hi)? << 4) | nibble(lo)?);
        }
        String::from_utf8(bytes).map_err(|_| fail("claim hex is not UTF-8"))
    }

    /// 成功した接続から、c4 と同じ形の請求書の記録（`veth=1 netns=1 quarantine=0`）を組む。
    fn attach_claim_record(
        network: &str,
        endpoint: &str,
        bridge_token: &str,
        host_token: &str,
        pin_value: &str,
    ) -> Result<String, NetError> {
        // 世代は attach の試行ごとに発行されるため、成功ハンドルの所有トークン（`<..>/g/<世代>`）から取る。
        let generation = host_token
            .rsplit_once("/g/")
            .map(|(_, g)| g)
            .ok_or_else(|| fail("host_token has no generation"))?;
        Ok(format!(
            "fandhe-net-attach-claim v1\nnetwork={network}\nendpoint={endpoint}\ntoken={bridge_token}\ngeneration={generation}\nveth=1\nnetns=1\npin={pin_value}\nquarantine=0\n"
        ))
    }

    /// 子モード（`--attach-child` / `--reclaim-child`）が inner の直接の子であることを確かめる（fail-closed）。
    /// root の子が host の netns・mount namespace で bridge を作ったりマウントを触ったりしないよう、
    /// ソケットを開く前に、(1) 親 pid が inner の通知と一致、(2) 自分が init の netns・mnt ns と別、
    /// (3) 親（inner）と同じ netns・mnt ns にいること、を検査する。
    fn ensure_child_of_inner(mode: &str) -> Result<(), NetError> {
        let ppid = std::os::unix::process::parent_id();
        let expected = std::env::var(INNER_PID_ENV)
            .ok()
            .and_then(|v| v.parse::<u32>().ok());
        if expected != Some(ppid) {
            return Err(fail(format!(
                "{mode} must be started by the `--inner` process; refusing to run"
            )));
        }
        let link = |pid: &str, ns: &str| {
            fs::read_link(format!("/proc/{pid}/ns/{ns}"))
                .map_err(|e| fail(format!("{mode}: cannot read /proc/{pid}/ns/{ns} ({e})")))
        };
        let ppid = ppid.to_string();
        for ns in ["net", "mnt"] {
            let own = link("self", ns)?;
            if own == link("1", ns)? {
                return Err(fail(format!(
                    "{mode}: same {ns} namespace as init; refusing to run"
                )));
            }
            if own != link(&ppid, ns)? {
                return Err(fail(format!(
                    "{mode}: {ns} namespace differs from the parent; refusing to run"
                )));
            }
        }
        Ok(())
    }

    /// 子モードの共通の終わり方。`Err` は 1 行で報告して非 0 終了する。
    fn child_exit_on_error(mode: &str, r: Result<(), NetError>) {
        if let Err(e) = r {
            println!("network_attach_privileged: {mode} refused or failed: {e}");
            std::process::exit(1);
        }
    }

    /// `--attach-child`: 自前のネットワーク `atx` を作って c8 を接続し、請求書の記録を 1 行で出して待つ。
    /// inner が SIGKILL で終わらせる（デストラクタを走らせず、veth・pin・所有記録を残す）。期限を過ぎたら自分で終わる。
    pub fn attach_child() {
        child_exit_on_error("--attach-child", attach_child_checked());
    }

    fn attach_child_checked() -> Result<(), NetError> {
        ensure_child_of_inner("--attach-child")?;
        let base =
            PathBuf::from(std::env::var(DIR_ENV).map_err(|_| fail("missing test directory env"))?);
        let route = NetlinkRouteSocket::open()?;
        let nft = NetlinkNetfilterSocket::open()?;
        let t = timeout();
        let net = create_network(
            &route,
            &nft,
            &NetworkCreateSpec::new(
                NetworkName::new("atx")?,
                IpPrefix::new("10.213.8.1".parse().map_err(|_| fail("addr"))?, 24)?,
            )?,
            t,
        )
        .map_err(|e| fail(format!("create_network (atx) failed at {:?}: {e}", e.step)))?;
        let spec = ContainerAttachSpec::new(EndpointId::new("c8")?, &net, base)?;
        let mut ipam = StaticIpam::for_network(&net)?;
        let mut ports = PortRegistry::new();
        let attached = attach_container(&route, &nft, &spec, &mut ipam, &mut ports, t)
            .map_err(|e| fail(format!("attach c8 failed at {:?}: {e}", e.step)))?;
        let pin_value = attached.netns_pin_record_value();
        if pin_value == "-" {
            return Err(fail(
                "the pin identity of c8 is unavailable; the cross-process reclaim cannot be exercised",
            ));
        }
        let attach_claim = attach_claim_record(
            "atx",
            "c8",
            &net.bridge_token,
            &attached.host_token,
            &pin_value,
        )?;
        let create_claim = FailedCreateClaim::from_created(&net).to_record();
        // pin のパスは空白を含みうる（TMPDIR 由来）ため hex で符号化して空白区切りの行に載せる。
        let line = format!(
            "{ATTACH_CHILD_PREFIX}attach_claim={} create_claim={} host={} bridge={} bridge_index={} table={} pin={}",
            hex_encode(attach_claim.as_bytes()),
            hex_encode(create_claim.as_bytes()),
            attached.host_veth.as_str(),
            net.bridge.as_str(),
            net.bridge_index.get(),
            net.table.as_str(),
            hex_encode(attached.netns_path.display().to_string().as_bytes()),
        );
        // SIGKILL で捨てられないよう、書いた直後に明示 flush する（バッファ挙動に依存しない）。
        {
            use std::io::Write as _;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{line}").map_err(|e| fail(format!("write claim line: {e}")))?;
            out.flush()
                .map_err(|e| fail(format!("flush claim line: {e}")))?;
        }
        // inner の SIGKILL を待つ（ハンドルは手放さない）。来なければ期限で自分から失敗終了する。
        let deadline = Instant::now() + timeout() * 3;
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        drop((attached, ipam, ports));
        Err(fail("attach child was not terminated before the deadline"))
    }

    /// `--reclaim-child`: 環境変数の請求書の記録（hex）から `reclaim_failed_attach` を呼び、結果を 1 行で出す。
    /// 作った本人ではない別プロセス（メモリ上の所有記録を持たない）として、永続の所有記録経由の照合を通す。
    pub fn reclaim_child() {
        child_exit_on_error("--reclaim-child", reclaim_child_checked());
    }

    fn reclaim_child_checked() -> Result<(), NetError> {
        ensure_child_of_inner("--reclaim-child")?;
        let base =
            PathBuf::from(std::env::var(DIR_ENV).map_err(|_| fail("missing test directory env"))?);
        let hex = std::env::var(CLAIM_HEX_ENV).map_err(|_| fail("missing claim env"))?;
        let claim = FailedAttachClaim::from_record(&hex_decode(&hex)?)?;
        let route = NetlinkRouteSocket::open()?;
        let nft = NetlinkNetfilterSocket::open()?;
        match reclaim_failed_attach(&route, &nft, &claim, &base, timeout()) {
            Ok(r) => println!(
                "XRECLAIM ok removed={} leftover={}",
                r.removed.len(),
                r.leftover.len()
            ),
            Err(e) => println!(
                "XRECLAIM err step={:?} removed={} leftover={}",
                e.step,
                e.report.removed.len(),
                e.report.leftover.len()
            ),
        }
        Ok(())
    }

    /// 子（`--attach-child`）を起動し、`prefix` で始まる標準出力の行を期限つきで受けたら SIGKILL で終わらせる。
    /// 終了が SIGKILL によるもの（自分で終わっていない）ことも確かめ、受けた行を返す（REPAIR-5）。
    fn spawn_until_line_then_kill(mode: &str, prefix: &str) -> Result<String, NetError> {
        use std::io::{BufRead as _, BufReader};
        use std::os::unix::process::ExitStatusExt as _;
        let exe = std::env::current_exe().map_err(|e| fail(format!("current_exe: {e}")))?;
        let mut child = Command::new(exe)
            .arg(mode)
            .env(INNER_PID_ENV, std::process::id().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| fail(format!("spawn {mode}: {e}")))?;
        let Some(stdout) = child.stdout.take() else {
            crate::reap::reap_or_report(&mut child, crate::reap::reap_within());
            return Err(fail("child stdout is not piped"));
        };
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let deadline = Instant::now() + timeout() * 2;
        let mut found: Option<String> = None;
        let mut seen = Vec::new();
        while found.is_none() {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(line) if line.starts_with(prefix) => found = Some(line),
                Ok(line) => seen.push(line),
                Err(_) => break,
            }
        }
        let _ = child.kill();
        let reap_deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) if Instant::now() < reap_deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => break None,
            }
        };
        // 読み取りスレッドは join しない。回収できなかった子が stdout を保持すると lines() が
        // 終わらず join が無期限に待つため（REPAIR-5）。子の終了で EOF になりスレッドは自然に終わる。
        drop(reader);
        let Some(line) = found else {
            return Err(fail(format!(
                "{mode} did not report before the deadline; output: {seen:?}"
            )));
        };
        let status = status.ok_or_else(|| fail(format!("{mode} was not reaped after SIGKILL")))?;
        if status.signal() != Some(9) {
            return Err(fail(format!("{mode} must end by SIGKILL, got {status:?}")));
        }
        Ok(line)
    }

    /// `key=value` を空白区切りで並べた行から `key` の値を返す。
    fn field<'a>(line: &'a str, key: &str) -> Result<&'a str, NetError> {
        line.split_whitespace()
            .find_map(|kv| kv.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
            .ok_or_else(|| fail(format!("field {key} missing in {line:?}")))
    }

    /// `--reclaim-child` を請求書の記録つきで起動し、`XRECLAIM` 行を返す。
    fn run_reclaim_child(claim_hex: &str) -> Result<String, NetError> {
        let exe = std::env::current_exe().map_err(|e| fail(format!("current_exe: {e}")))?;
        let exe = exe
            .to_str()
            .ok_or_else(|| fail("current_exe is not UTF-8"))?;
        let pid = std::process::id().to_string();
        let out = run_cmd_env(
            exe,
            &["--reclaim-child"],
            &[(INNER_PID_ENV, &pid), (CLAIM_HEX_ENV, claim_hex)],
        )?;
        out.lines()
            .find(|l| l.starts_with("XRECLAIM "))
            .map(str::to_owned)
            .ok_or_else(|| fail(format!("no XRECLAIM line in {out:?}")))
    }

    /// feature が外れた構成では故障注入の入口が無く、照合できない。`--ignored` で実行されたのに成功を
    /// 装わないよう、名指しで失敗させる（ci.md の fail-closed。#2971）。
    #[cfg(not(feature = "attach-fault-test-support"))]
    fn fault_scenarios(
        _route: &NetlinkRouteSocket,
        _nft: &NetlinkNetfilterSocket,
        _net: &CreatedNetwork,
        _ipam: &mut StaticIpam,
        _ports: &mut PortRegistry,
        _base: &Path,
        _t: Duration,
    ) -> Result<Vec<EndpointId>, NetError> {
        Err(fail(
            "feature `attach-fault-test-support` is required for the fault injection scenarios (S3/S4/S5/S6)",
        ))
    }

    /// 故障注入（`attach_container_with_fault_for_test`）で巻き戻しも失敗させて取り残しを作り、別プロセス
    /// （`--reclaim-child`）が請求書から回収するかを実カーネルで照合する（NET-1・REPAIR-3・#2971）。
    /// S3/S4 の故障点は IPAM 払い出し前の段。S5/S6 は払い出し後の段で、S5 が残した quarantine（アドレス・予約）は
    /// 戻り値の endpoint として返し、呼び出し側が `delete_network` の前後で保持と解放を照合する
    /// （最後の「IPAM・予約が空」の照合を崩さない順序。#3040）。
    /// - S3: `SetUp` で失敗し veth 削除・unpin も失敗 → veth（別名あり・bridge 接続済み）と pin が残り、
    ///   請求書（pin の識別子つき）から回収されて冪等に成功する
    /// - S4: `SetOwnerToken` で失敗し veth 削除も失敗 → 別名の無い veth が残り、所有を証明できないため回収は
    ///   `DeleteVeth` で拒否して veth を残す（試験が自分で後始末する）
    /// - S5: ポート公開つきで `DefaultRoute` に失敗し veth 削除・unpin も失敗 → veth・pin に加えアドレスと予約が残る。
    ///   回収はカーネル側だけで quarantine は解放しない（c13 を返す）
    /// - S6: ポート公開つきで `AddAddress` に失敗し巻き戻しは成功 → 資源・アドレス・予約がすべて解放される
    #[cfg(feature = "attach-fault-test-support")]
    fn fault_scenarios(
        route: &NetlinkRouteSocket,
        nft: &NetlinkNetfilterSocket,
        net: &CreatedNetwork,
        ipam: &mut StaticIpam,
        ports: &mut PortRegistry,
        base: &Path,
        t: Duration,
    ) -> Result<Vec<EndpointId>, NetError> {
        let gone = |name: &IfName| {
            matches!(
                route.link_index(name, t),
                Err(ref e) if e.code() == NetErrorCode::NotFound
            )
        };

        // S3
        let c9 = EndpointId::new("c9")?;
        let spec9 = ContainerAttachSpec::new(c9.clone(), net, base.to_path_buf())?;
        let fault = AttachFault::new(AttachFaultPoint::SetUp)
            .with_veth_delete_failure(NetErrorCode::Internal)
            .with_unpin_failure(NetErrorCode::Internal);
        let e =
            match attach_container_with_fault_for_test(route, nft, &spec9, ipam, ports, t, fault) {
                Err(e) => e,
                Ok(_) => return Err(fail("S3: the injected attach unexpectedly succeeded")),
            };
        let host9 = VethNames::derive(&c9)?.host().clone();
        let pin9 = base.join("c9");
        let ledger9 = base.join(".owned").join("c9");
        if e.step != AttachStep::SetUp
            || !e.rollback.removed.is_empty()
            || e.rollback.leftover
                != [
                    (AttachResource::Veth(host9.clone()), ResourceState::Present),
                    (AttachResource::Netns(pin9.clone()), ResourceState::Present),
                ]
            || ipam.address_of(&c9).is_some()
        {
            return Err(fail(format!(
                "S3: unexpected attach failure shape: step {:?}, rollback {:?}",
                e.step, e.rollback
            )));
        }
        let record9 = e
            .reclaim_claim()
            .ok_or_else(|| fail("S3: no reclaim claim for a leftover attach"))?
            .to_record();
        if !record9.contains("\nveth=1\nnetns=1\n")
            || !record9.contains("\nquarantine=0\n")
            || record9.contains("\npin=-\n")
        {
            return Err(fail(format!(
                "S3: unexpected claim record (pin identity missing?): {record9:?}"
            )));
        }
        // 取り残しの実体: 別名（所有トークン）つきで bridge に繋がった veth、pin、永続の所有記録。
        let (_, master9, alias9) = route.link_index_master_alias(&host9, t)?;
        if master9 != Some(net.bridge_index) {
            return Err(fail(format!(
                "S3: left-over veth master is {master9:?}, expected the bridge"
            )));
        }
        if !alias9
            .as_deref()
            .is_some_and(|a| a.starts_with(&format!("{}/ep/c9/g/", net.bridge_token)))
        {
            return Err(fail(format!("S3: left-over veth alias is {alias9:?}")));
        }
        if !pin9.exists() || !ledger9.exists() {
            return Err(fail(
                "S3: the pin or the ownership record .owned/c9 is missing",
            ));
        }
        let record9_hex = hex_encode(record9.as_bytes());
        for round in 0..2 {
            let r = run_reclaim_child(&record9_hex)?;
            if r != "XRECLAIM ok removed=2 leftover=0" {
                return Err(fail(format!(
                    "S3: unexpected reclaim result (round {round}): {r}"
                )));
            }
        }
        if !gone(&host9) || pin9.exists() || ledger9.exists() {
            return Err(fail(
                "S3: the reclaim left the veth, the pin or the ownership record",
            ));
        }

        // S4
        let c10 = EndpointId::new("c10")?;
        let spec10 = ContainerAttachSpec::new(c10.clone(), net, base.to_path_buf())?;
        let fault = AttachFault::new(AttachFaultPoint::SetOwnerToken)
            .with_veth_delete_failure(NetErrorCode::Internal);
        let e = match attach_container_with_fault_for_test(
            route, nft, &spec10, ipam, ports, t, fault,
        ) {
            Err(e) => e,
            Ok(_) => return Err(fail("S4: the injected attach unexpectedly succeeded")),
        };
        let host10 = VethNames::derive(&c10)?.host().clone();
        let pin10 = base.join("c10");
        if e.step != AttachStep::SetOwnerToken
            || e.rollback.removed != [AttachResource::Netns(pin10.clone())]
            || e.rollback.leftover
                != [(AttachResource::Veth(host10.clone()), ResourceState::Present)]
            || ipam.address_of(&c10).is_some()
        {
            return Err(fail(format!(
                "S4: unexpected attach failure shape: step {:?}, rollback {:?}",
                e.step, e.rollback
            )));
        }
        let record10 = e
            .reclaim_claim()
            .ok_or_else(|| fail("S4: no reclaim claim for a leftover attach"))?
            .to_record();
        if !record10.contains("\nveth=1\nnetns=0\n") || !record10.contains("\nquarantine=0\n") {
            return Err(fail(format!("S4: unexpected claim record: {record10:?}")));
        }
        // 取り残しの実体: 所有トークンも bridge 接続も無い veth（所有を証明できない）。
        let (_, master10, alias10) = route.link_index_master_alias(&host10, t)?;
        if master10.is_some() || alias10.is_some() {
            return Err(fail(format!(
                "S4: left-over veth should have no master and no alias: {master10:?} {alias10:?}"
            )));
        }
        let r = run_reclaim_child(&hex_encode(record10.as_bytes()))?;
        if r != "XRECLAIM err step=DeleteVeth removed=0 leftover=1" {
            return Err(fail(format!("S4: unexpected reclaim result: {r}")));
        }
        if gone(&host10) {
            return Err(fail(
                "S4: the reclaim deleted a veth whose ownership it could not prove",
            ));
        }
        // 後始末: 試験自身が消す（隔離した netns の中なので host には漏れない）。
        route.delete_link(&LinkDelete::new(LinkRef::Name(host10.clone())), t)?;
        if !gone(&host10) {
            return Err(fail("S4: the test cleanup could not delete the veth"));
        }

        // S5: IPAM 払い出し後の段（DefaultRoute）。取り残しがあるのでアドレスと予約を保持する。
        let base_ports = ports.len();
        let published = |port: u16| -> Result<Vec<PortPublish>, NetError> {
            Ok(vec![PortPublish::new(
                PortProtocol::Tcp,
                "192.0.2.10".parse().map_err(|_| fail("addr"))?,
                port,
                80,
            )?])
        };
        let c13 = EndpointId::new("c13")?;
        let spec13 = ContainerAttachSpec::new(c13.clone(), net, base.to_path_buf())?
            .with_port_publishes(published(8093)?)?;
        let fault = AttachFault::new(AttachFaultPoint::DefaultRoute)
            .with_veth_delete_failure(NetErrorCode::Internal)
            .with_unpin_failure(NetErrorCode::Internal);
        let e = match attach_container_with_fault_for_test(
            route, nft, &spec13, ipam, ports, t, fault,
        ) {
            Err(e) => e,
            Ok(_) => return Err(fail("S5: the injected attach unexpectedly succeeded")),
        };
        let host13 = VethNames::derive(&c13)?.host().clone();
        let pin13 = base.join("c13");
        let ledger13 = base.join(".owned").join("c13");
        let addr13 = ipam
            .address_of(&c13)
            .ok_or_else(|| fail("S5: the address was released although resources are left"))?;
        if e.step != AttachStep::DefaultRoute
            || !e.rollback.removed.is_empty()
            || e.rollback.leftover
                != [
                    (AttachResource::Veth(host13.clone()), ResourceState::Present),
                    (AttachResource::Netns(pin13.clone()), ResourceState::Present),
                    (AttachResource::Address(addr13), ResourceState::Unknown),
                ]
            || ports.len() != base_ports + 1
        {
            return Err(fail(format!(
                "S5: unexpected attach failure shape: step {:?}, rollback {:?}, ports {} (base {base_ports})",
                e.step,
                e.rollback,
                ports.len()
            )));
        }
        let record13 = e
            .reclaim_claim()
            .ok_or_else(|| fail("S5: no reclaim claim for a leftover attach"))?
            .to_record();
        if !record13.contains("\nveth=1\nnetns=1\n")
            || !record13.contains("\nquarantine=1\n")
            || record13.contains("\npin=-\n")
        {
            return Err(fail(format!("S5: unexpected claim record: {record13:?}")));
        }
        let (_, master13, alias13) = route.link_index_master_alias(&host13, t)?;
        if master13 != Some(net.bridge_index)
            || !alias13
                .as_deref()
                .is_some_and(|a| a.starts_with(&format!("{}/ep/c13/g/", net.bridge_token)))
        {
            return Err(fail(format!(
                "S5: left-over veth master/alias unexpected: {master13:?} {alias13:?}"
            )));
        }
        if !pin13.exists() || !ledger13.exists() {
            return Err(fail(
                "S5: the pin or the ownership record .owned/c13 is missing",
            ));
        }
        let record13_hex = hex_encode(record13.as_bytes());
        for round in 0..2 {
            let r = run_reclaim_child(&record13_hex)?;
            if r != "XRECLAIM ok removed=2 leftover=0" {
                return Err(fail(format!(
                    "S5: unexpected reclaim result (round {round}): {r}"
                )));
            }
        }
        if !gone(&host13) || pin13.exists() || ledger13.exists() {
            return Err(fail(
                "S5: the reclaim left the veth, the pin or the ownership record",
            ));
        }
        // 回収はカーネル側だけ。quarantine（アドレス・予約）は `delete_network` が解放するまで残る。
        if ipam.address_of(&c13) != Some(addr13) || ports.len() != base_ports + 1 {
            return Err(fail(
                "S5: the reclaim must not release the quarantined address or the port reservation",
            ));
        }

        // S6: IPAM 払い出し後の段（AddAddress）。巻き戻しが成功するのでアドレスと予約は即時に解放される。
        let dnat_count = || -> Result<usize, NetError> {
            Ok(
                run_cmd("nft", &["list", "table", "ip", net.table.as_str()])?
                    .matches("dnat to")
                    .count(),
            )
        };
        let dnat_before = dnat_count()?;
        let c14 = EndpointId::new("c14")?;
        let spec14 = ContainerAttachSpec::new(c14.clone(), net, base.to_path_buf())?
            .with_port_publishes(published(8094)?)?;
        let fault = AttachFault::new(AttachFaultPoint::AddAddress);
        let e = match attach_container_with_fault_for_test(
            route, nft, &spec14, ipam, ports, t, fault,
        ) {
            Err(e) => e,
            Ok(_) => return Err(fail("S6: the injected attach unexpectedly succeeded")),
        };
        let host14 = VethNames::derive(&c14)?.host().clone();
        let pin14 = base.join("c14");
        if e.step != AttachStep::AddAddress
            || e.rollback.removed
                != [
                    AttachResource::Veth(host14.clone()),
                    AttachResource::Netns(pin14.clone()),
                ]
            || !e.rollback.leftover.is_empty()
            || e.reclaim_claim().is_some()
        {
            return Err(fail(format!(
                "S6: unexpected attach failure shape: step {:?}, rollback {:?}",
                e.step, e.rollback
            )));
        }
        if ipam.address_of(&c14).is_some() || ports.len() != base_ports + 1 {
            return Err(fail(
                "S6: the address or the port reservation of c14 was not released by the rollback",
            ));
        }
        if !gone(&host14) || pin14.exists() || base.join(".owned").join("c14").exists() {
            return Err(fail(
                "S6: the rollback left the veth, the pin or the ownership record",
            ));
        }
        if dnat_count()? != dnat_before {
            return Err(fail(
                "S6: DNAT rules changed although the attach failed before publishing",
            ));
        }
        Ok(vec![c13])
    }

    pub fn inner() {
        match inner_checked() {
            Ok(true) => println!("{OK_LINE_ECHO_INDEX}"),
            Ok(false) => println!("{OK_LINE_ECHO_FALLBACK}"),
            Err(e) => {
                println!("network_attach_privileged: failed: {e}");
                std::process::exit(1);
            }
        }
    }

    /// 成功時は veth の作成通知が届く経路（v6.2 以上）だったかを返す。
    fn inner_checked() -> Result<bool, NetError> {
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

        let route = NetlinkRouteSocket::open()?;
        let nft = NetlinkNetfilterSocket::open()?;
        let t = timeout();

        let net = create_network(
            &route,
            &nft,
            &NetworkCreateSpec::new(
                NetworkName::new("att")?,
                IpPrefix::new("10.213.0.1".parse().map_err(|_| fail("addr"))?, 24)?,
            )?,
            t,
        )
        .map_err(|e| {
            if e.step == CreateStep::ResolveIndex {
                fail(format!(
                    "create_network failed at ResolveIndex ({e}); the bridge ownership token (IFLA_IFALIAS set by RTM_SETLINK after creation, Issue #1925) may not be readable on this kernel; see bridge_owner_token_privileged"
                ))
            } else {
                fail(format!("create_network failed at {:?}: {e}", e.step))
            }
        })?;

        // --- masquerade（#3073・NET-1・NET-11）---
        // postrouting にちょうど 1 件。カーネルが受理した形を nft の解釈で読み戻し、サブネットと
        // 出口 bridge の除外（oifname の 16 バイト比較）が意図どおりに読めることを確かめる。
        let listing = run_cmd("nft", &["list", "table", "ip", net.table.as_str()])?;
        let masq_lines: Vec<&str> = listing
            .lines()
            .filter(|l| l.contains("masquerade"))
            .collect();
        let [masq_line] = masq_lines.as_slice() else {
            return Err(fail(format!(
                "expected exactly one masquerade rule in {listing}"
            )));
        };
        let want_oif = format!("oifname != \"{}\"", net.bridge.as_str());
        if !masq_line.contains("ip saddr 10.213.0.0/24") || !masq_line.contains(&want_oif) {
            return Err(fail(format!("unexpected masquerade rule: {masq_line}")));
        }
        let post = listing
            .split("chain postrouting")
            .nth(1)
            .and_then(|r| r.split("chain ").next())
            .unwrap_or("");
        if !post.contains("masquerade") {
            return Err(fail("masquerade rule is not in the postrouting chain"));
        }

        // --- 成功経路 ---
        let spec = ContainerAttachSpec::new(EndpointId::new("c1")?, &net, base.clone())?;
        let mut ipam = StaticIpam::for_network(&net)?;
        let mut ports = PortRegistry::new();
        let attached = attach_container(&route, &nft, &spec, &mut ipam, &mut ports, t)
            .map_err(|e| fail(format!("attach_container failed at {:?}: {e}", e.step)))?;
        if attached.address != IpPrefix::new("10.213.0.2".parse().map_err(|_| fail("addr"))?, 24)? {
            return Err(fail(format!("unexpected address {:?}", attached.address)));
        }
        let host = attached.host_veth.as_str();
        let peer = attached.peer_veth.as_str();
        let ifname = attached.container_ifname.as_str();
        if ifname != "eth0" {
            return Err(fail(format!("unexpected container ifname {ifname}")));
        }

        let (index, flags, master) = link_state(&route, host)?;
        if index != attached.host_index.get() {
            return Err(fail("host ifindex differs from the returned one"));
        }
        if master != Some(net.bridge_index.get()) {
            return Err(fail(format!(
                "host veth IFLA_MASTER is {master:?}, expected {}",
                net.bridge_index.get()
            )));
        }
        if flags & IFF_UP == 0 {
            return Err(fail("host veth is not up"));
        }
        // peer は host（子の）netns から消えている。
        match get_link_payload(&route, peer) {
            Err(e) if e.code() == NetErrorCode::NotFound => {}
            other => {
                return Err(fail(format!(
                    "peer should be gone from this netns: {other:?}"
                )));
            }
        }
        // pin と保持 fd が同じ netns（nsfs の inode が一致）で、自分の netns とは別。
        let pin_ino = fs::metadata(&attached.netns_path)
            .map_err(|e| fail(format!("stat pin: {e}")))?
            .ino();
        let fd_path = format!("/proc/self/fd/{}", attached.netns.fd().as_raw_fd());
        let fd_ino = fs::metadata(&fd_path)
            .map_err(|e| fail(format!("stat netns fd: {e}")))?
            .ino();
        if pin_ino != fd_ino {
            return Err(fail("pin path and netns fd refer to different namespaces"));
        }
        let own_ino = fs::metadata("/proc/self/ns/net")
            .map_err(|e| fail(format!("stat own netns: {e}")))?
            .ino();
        if own_ino == pin_ino {
            return Err(fail("container netns is the same as the current netns"));
        }
        // netns 内にプロセスがいないので pin 経由で入って確認する。
        let pin_str = attached
            .netns_path
            .to_str()
            .ok_or_else(|| fail("pin path is not UTF-8"))?;
        let dev = run_cmd(
            "nsenter",
            &[&format!("--net={pin_str}"), "cat", "/proc/net/dev"],
        )?;
        if !dev
            .lines()
            .any(|l| l.trim_start().starts_with(&format!("{ifname}:")))
        {
            return Err(fail(format!("{ifname} not found in the container netns")));
        }
        if dev
            .lines()
            .any(|l| l.trim_start().starts_with(&format!("{peer}:")))
        {
            return Err(fail(format!(
                "peer {peer} still has its original name in the container netns"
            )));
        }

        // netns 内の設定（TASK-139.3・#316）: default route が gateway 経由で peer から出る。
        // /proc/net/route の Destination・Gateway・Mask は 16 進のリトルエンディアン（10.213.0.1 = 0100D50A）。
        let route_table = run_cmd(
            "nsenter",
            &[&format!("--net={pin_str}"), "cat", "/proc/net/route"],
        )?;
        let default_routes: Vec<&str> = route_table
            .lines()
            .filter(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                f.first() == Some(&ifname)
                    && f.get(1) == Some(&"00000000")
                    && f.get(7) == Some(&"00000000")
            })
            .collect();
        if default_routes.len() != 1
            || default_routes[0].split_whitespace().nth(2) != Some("0100D50A")
        {
            return Err(fail(format!(
                "expected exactly one default route via 10.213.0.1 on {ifname}, got {default_routes:?}"
            )));
        }

        // --- veth の作成通知（NLM_F_ECHO）の ifindex（Issue #3205）---
        // v6.2 以降は通知が届き、host / peer の ifindex が実カーネルの link と一致する。それより前は通知が無く
        // （上の attach_container は戻し経路で成功している）。版を読めない・期待と違う場合は skip せず失敗する。
        let echo_supported = kernel_supports_create_echo()?;
        let eh = IfName::new("fxech0")?;
        let ep = IfName::new("fxech1")?;
        let reply = route.create_link(&LinkCreate::veth(eh.clone(), ep.clone())?.with_echo(), t)?;
        let echoed = decode_created_veth(
            reply.messages().iter().map(|m| (m.msg_type(), m.payload())),
            &eh,
        )?;
        let actual_host = link_state(&route, eh.as_str())?.0;
        let actual_peer = link_state(&route, ep.as_str())?.0;
        route.delete_link(&LinkDelete::new(LinkRef::Name(eh.clone())), t)?;
        match (echo_supported, echoed) {
            (true, Some(c)) if c.host().get() == actual_host && c.peer().get() == actual_peer => {}
            (false, None) => {}
            (supported, got) => {
                return Err(fail(format!(
                    "unexpected veth echo result: supported={supported} echoed={:?} actual=({actual_host}, {actual_peer})",
                    got.map(|c| (c.host().get(), c.peer().get()))
                )));
            }
        }

        // --- ロールバック経路: host 側 veth 名を先に塞ぎ、AlreadyExists で失敗させる ---
        let c2 = EndpointId::new("c2")?;
        let names = VethNames::derive(&c2)?;
        route.create_link(
            &LinkCreate::veth(names.host().clone(), IfName::new("fxpre0")?)?,
            t,
        )?;
        let spec2 = ContainerAttachSpec::new(c2, &net, base.clone())?;
        let e = match attach_container(&route, &nft, &spec2, &mut ipam, &mut ports, t) {
            Err(e) => e,
            Ok(_) => return Err(fail("attach on a taken veth name unexpectedly succeeded")),
        };
        if e.step != AttachStep::CreateVeth || e.code() != NetErrorCode::AlreadyExists {
            return Err(fail(format!(
                "unexpected failure: step {:?} code {:?}",
                e.step,
                e.code()
            )));
        }
        let pin2 = spec2.netns_path();
        if e.rollback.removed != [AttachResource::Netns(pin2.clone())]
            || !e.rollback.leftover.is_empty()
        {
            return Err(fail(format!(
                "unexpected rollback report: {:?}",
                e.rollback
            )));
        }
        if Path::new(&pin2).exists() {
            return Err(fail("pin file was not removed by the rollback"));
        }
        link_state(&route, names.host().as_str())
            .map_err(|_| fail("the pre-existing veth must not be deleted by the rollback"))?;

        // --- ポート公開（TASK-139.3・#316）: DNAT ルールが専用テーブルの両チェインに入る ---
        let publish = PortPublish::new(
            PortProtocol::Tcp,
            "192.0.2.10".parse().map_err(|_| fail("addr"))?,
            8080,
            80,
        )?;
        let spec3 = ContainerAttachSpec::new(EndpointId::new("c3")?, &net, base.clone())?
            .with_port_publishes(vec![publish])?;
        let mut attached3 = attach_container(&route, &nft, &spec3, &mut ipam, &mut ports, t)
            .map_err(|e| {
                fail(format!(
                    "attach with port publish failed at {:?}: {e}",
                    e.step
                ))
            })?;
        let ruleset = run_cmd("nft", &["list", "table", "ip", net.table.as_str()])?;
        let dnat_lines = ruleset
            .lines()
            .filter(|l| l.contains("dnat to") && l.contains("192.0.2.10") && l.contains("8080"))
            .filter(|l| l.contains(&attached3.address.addr().to_string()) && l.contains(":80"))
            .count();
        if dnat_lines != 2 {
            return Err(fail(format!(
                "expected 2 DNAT rules (prerouting and output), found {dnat_lines} in:\n{ruleset}"
            )));
        }

        // --- 公開の個別解除（NET-3・NET-4・#2839）: echo で取ったハンドルで DNAT 2 件だけを消し、予約を戻す ---
        let count_dnat = || -> Result<usize, NetError> {
            let rs = run_cmd("nft", &["list", "table", "ip", net.table.as_str()])?;
            Ok(rs.lines().filter(|l| l.contains("dnat to")).count())
        };
        let mut published = std::mem::take(&mut attached3.published_ports);
        let (Some(first), None) = (published.pop(), published.pop()) else {
            return Err(fail("attach must return exactly 1 published port"));
        };
        if (first.prerouting_handle().get(), first.output_handle().get()) == (0, 0) {
            return Err(fail("echoed rule handles must be non-zero"));
        }
        if ports.len() != 1 {
            return Err(fail(format!(
                "expected 1 reservation, found {}",
                ports.len()
            )));
        }
        unpublish_container_port(&nft, &net, first, &mut ports, t)
            .map_err(|e| fail(format!("unpublish failed: {e} (rules {:?})", e.rules)))?;
        let left = count_dnat()?;
        if left != 0 || !ports.is_empty() {
            return Err(fail(format!(
                "after unpublish expected 0 DNAT rules and 0 reservations, found {left} rules and {} reservations",
                ports.len()
            )));
        }
        // 同じ受け口を再び公開できる（予約が戻っている証拠）。
        let again = publish_container_ports(&nft, &net, &attached3, &[publish], &mut ports, t)
            .map_err(|e| fail(format!("re-publish failed: {e}")))?;
        let again_rules = count_dnat()?;
        if again.len() != 1 || again_rules != 2 {
            return Err(fail(format!(
                "re-publish expected 1 port and 2 DNAT rules, found {} and {again_rules}",
                again.len()
            )));
        }

        // --- コンテナ単体の切り離し（NET-1・NET-3・#3062）: c11 だけを外し、c12 の公開・veth・アドレスは残る ---
        let attach_published = |id: &str, host_port: u16| -> Result<_, NetError> {
            let p = PortPublish::new(
                PortProtocol::Tcp,
                "192.0.2.10".parse().map_err(|_| fail("addr"))?,
                host_port,
                80,
            )?;
            ContainerAttachSpec::new(EndpointId::new(id)?, &net, base.clone())?
                .with_port_publishes(vec![p])
        };
        let (c11, c12) = (EndpointId::new("c11")?, EndpointId::new("c12")?);
        let attached11 = attach_container(
            &route,
            &nft,
            &attach_published("c11", 8091)?,
            &mut ipam,
            &mut ports,
            t,
        )
        .map_err(|e| fail(format!("attach c11 failed at {:?}: {e}", e.step)))?;
        let attached12 = attach_container(
            &route,
            &nft,
            &attach_published("c12", 8092)?,
            &mut ipam,
            &mut ports,
            t,
        )
        .map_err(|e| fail(format!("attach c12 failed at {:?}: {e}", e.step)))?;
        let (host11, pin11) = (attached11.host_veth.clone(), attached11.netns_path.clone());
        let (host12, addr12) = (attached12.host_veth.clone(), attached12.address);
        let before = count_dnat()?;
        let removed = detach_container(
            &route,
            &nft,
            &net,
            attached11,
            Vec::new(),
            &mut ipam,
            &mut ports,
            t,
        )
        .map_err(|e| {
            fail(format!(
                "detach c11 failed at {:?}: {e}; report: {:?}",
                e.step, e.report
            ))
        })?;
        if !removed.leftover.is_empty() || removed.removed.len() != 4 {
            return Err(fail(format!("unexpected detach report: {removed:?}")));
        }
        if !matches!(
            route.link_index(&host11, t),
            Err(ref e) if e.code() == NetErrorCode::NotFound
        ) {
            return Err(fail("detached veth still exists"));
        }
        if pin11.exists() {
            return Err(fail("detached pin still exists"));
        }
        let ruleset = run_cmd("nft", &["list", "table", "ip", net.table.as_str()])?;
        let (n8091, n8092) = (
            ruleset
                .lines()
                .filter(|l| l.contains("dnat to") && l.contains("8091"))
                .count(),
            ruleset
                .lines()
                .filter(|l| l.contains("dnat to") && l.contains("8092"))
                .count(),
        );
        if (n8091, n8092) != (0, 2) || count_dnat()? != before - 2 {
            return Err(fail(format!(
                "after detach expected DNAT 8091 x0 / 8092 x2 and {} in total, found {n8091} / {n8092} and {} in:\n{ruleset}",
                before - 2,
                count_dnat()?
            )));
        }
        // 兄弟の veth は bridge に属して up のまま、bridge も残る。
        let (_, flags12, master12) = link_state(&route, host12.as_str())?;
        if master12 != Some(net.bridge_index.get()) || flags12 & IFF_UP == 0 {
            return Err(fail("sibling veth must stay attached to the bridge and up"));
        }
        link_state(&route, net.bridge.as_str())?;
        if ipam.address_of(&c11).is_some() || ipam.address_of(&c12) != Some(addr12) {
            return Err(fail("detach must release only the detached address"));
        }
        if ports.len() != 2 {
            return Err(fail(format!(
                "expected 2 reservations (c3 and c12), found {}",
                ports.len()
            )));
        }
        // 同じ受け口とアドレスを再び使える（予約と払い出しが戻っている証拠）。後始末として両方を切り離す。
        let again11 = attach_container(
            &route,
            &nft,
            &attach_published("c11", 8091)?,
            &mut ipam,
            &mut ports,
            t,
        )
        .map_err(|e| fail(format!("re-attach c11 failed at {:?}: {e}", e.step)))?;
        for c in [again11, attached12] {
            let id = c.endpoint.clone();
            detach_container(&route, &nft, &net, c, Vec::new(), &mut ipam, &mut ports, t)
                .map_err(|e| fail(format!("cleanup detach {id:?} failed: {e}")))?;
        }
        if ports.len() != 1 || count_dnat()? != before - 4 || ipam.address_of(&c12).is_some() {
            return Err(fail("cleanup detach left reservations, rules or addresses"));
        }

        // --- attach の取り残しの回収（NET-1・#2681）: 請求書の記録から、所有を確かめて veth と pin を回収する ---
        let c4 = EndpointId::new("c4")?;
        let spec4 = ContainerAttachSpec::new(c4.clone(), &net, base.clone())?;
        let attached4 = attach_container(&route, &nft, &spec4, &mut ipam, &mut ports, t)
            .map_err(|e| fail(format!("attach c4 failed at {:?}: {e}", e.step)))?;
        let host4 = attached4.host_veth.clone();
        let pin4 = attached4.netns_path.clone();
        // 世代は attach の試行ごとに発行されるため、成功ハンドルの所有トークン（`<..>/g/<世代>`）から取る。
        let generation4 = attached4
            .host_token
            .rsplit_once("/g/")
            .map(|(_, g)| g.to_owned())
            .ok_or_else(|| fail("host_token has no generation"))?;
        let pin4_value = attached4.netns_pin_record_value();
        let record = format!(
            "fandhe-net-attach-claim v1\nnetwork=att\nendpoint=c4\ntoken={}\ngeneration={generation4}\nveth=1\nnetns=1\npin={}\nquarantine=0\n",
            net.bridge_token, pin4_value
        );
        let claim4 = FailedAttachClaim::from_record(&record)?;
        for round in 0..2 {
            // 2 回目は何も残っていない状態での再実行で、冪等に成功する。
            reclaim_failed_attach(&route, &nft, &claim4, &base, t).map_err(|e| {
                fail(format!(
                    "reclaim_failed_attach (round {round}) failed at {:?}: {e}; report: {:?}",
                    e.step, e.report
                ))
            })?;
        }
        if !matches!(
            route.link_index(&host4, t),
            Err(ref e) if e.code() == NetErrorCode::NotFound
        ) {
            return Err(fail("reclaimed veth still exists"));
        }
        if pin4.exists() {
            return Err(fail("reclaimed pin still exists"));
        }
        ipam.release(&c4)?;
        drop(attached4);
        // 別名のない（他者の）veth は、請求書に載っていても消さない。
        let c5 = EndpointId::new("c5")?;
        let names5 = VethNames::derive(&c5)?;
        route.create_link(
            &LinkCreate::veth(names5.host().clone(), IfName::new("fxpre1")?)?,
            t,
        )?;
        let record5 = record
            .replace("endpoint=c4", "endpoint=c5")
            .replace("netns=1", "netns=0")
            .replace(&format!("pin={pin4_value}"), "pin=-");
        let e = match reclaim_failed_attach(
            &route,
            &nft,
            &FailedAttachClaim::from_record(&record5)?,
            &base,
            t,
        ) {
            Err(e) => e,
            Ok(_) => return Err(fail("reclaim of a foreign veth unexpectedly succeeded")),
        };
        if e.step != DeleteStep::DeleteVeth {
            return Err(fail(format!("unexpected reclaim step {:?}", e.step)));
        }
        link_state(&route, names5.host().as_str())
            .map_err(|_| fail("a foreign veth must not be deleted by the reclaim"))?;

        // --- プロセスをまたぐ回収（NET-1・REPAIR-3・#2906）。実機（root）での実行は #1626（人間担当）で未実行 ---
        // S1: 別プロセスが接続して SIGKILL で終わった後に残る veth・pin・所有記録を、さらに別のプロセスが回収する。
        let line = spawn_until_line_then_kill("--attach-child", ATTACH_CHILD_PREFIX)?;
        let attach_hex = field(&line, "attach_claim")?.to_owned();
        let create_hex = field(&line, "create_claim")?.to_owned();
        let host8 = IfName::new(field(&line, "host")?)?;
        let bridge8 = IfName::new(field(&line, "bridge")?)?;
        let bridge8_index: u32 = field(&line, "bridge_index")?
            .parse()
            .map_err(|_| fail("bridge_index is not a number"))?;
        let table8 = field(&line, "table")?.to_owned();
        let pin8 = PathBuf::from(hex_decode(field(&line, "pin")?)?);
        let c8 = EndpointId::new("c8")?;
        if pin8 != base.join("c8") {
            return Err(fail(format!("unexpected pin path {}", pin8.display())));
        }
        let ledger8 = base.join(".owned").join("c8");
        // 回収前: 作った本人は居ないが、資源は残っている。
        let (_, _, master8) = link_state(&route, host8.as_str())?;
        if master8 != Some(bridge8_index) {
            return Err(fail(format!(
                "left-over host veth IFLA_MASTER is {master8:?}, expected {bridge8_index}"
            )));
        }
        let own_netns_ino = fs::metadata("/proc/self/ns/net")
            .map_err(|e| fail(format!("stat own netns: {e}")))?
            .ino();
        let pin8_ino = fs::metadata(&pin8)
            .map_err(|e| fail(format!("stat left-over pin: {e}")))?
            .ino();
        if pin8_ino == own_netns_ino {
            return Err(fail("left-over pin is not bound to a separate netns"));
        }
        if !ledger8.exists() {
            return Err(fail("the persistent ownership record .owned/c8 is missing"));
        }
        // 識別子なしでは（メモリに記録の無い pin は）外せない。
        if fandhe_container_net::netns::unpin_path(&pin8).is_ok() || !pin8.exists() {
            return Err(fail(
                "unpin_path without a claim identity must refuse a pin this process did not create",
            ));
        }
        // 別プロセスが、請求書と所有記録とカーネルの実状態の三者照合で回収する。2 回目は冪等。
        for round in 0..2 {
            let r = run_reclaim_child(&attach_hex)?;
            if r != "XRECLAIM ok removed=2 leftover=0" {
                return Err(fail(format!(
                    "unexpected reclaim result (round {round}): {r}"
                )));
            }
        }
        if !matches!(
            route.link_index(&host8, t),
            Err(ref e) if e.code() == NetErrorCode::NotFound
        ) {
            return Err(fail("cross-process reclaimed veth still exists"));
        }
        if pin8.exists() || ledger8.exists() {
            return Err(fail(
                "cross-process reclaim left the pin or the ownership record",
            ));
        }

        // S2: 同じ endpoint に作り直した新しい pin は、古い請求書では外れない（世代の保護）。
        let prepared8 = create_container_netns(&route, &base, &c8, t)
            .map_err(|e| fail(format!("re-create c8 netns failed: {e:?}")))?;
        let newer_pin = prepared8.pin_path();
        let newer_ino = fs::metadata(&newer_pin)
            .map_err(|e| fail(format!("stat newer pin: {e}")))?
            .ino();
        let r = run_reclaim_child(&attach_hex)?;
        if r != "XRECLAIM err step=UnpinNetns removed=1 leftover=1" {
            return Err(fail(format!("stale claim result was unexpected: {r}")));
        }
        let still = fs::metadata(&newer_pin)
            .map_err(|e| fail(format!("newer pin vanished after the stale claim: {e}")))?
            .ino();
        if still != newer_ino || still == own_netns_ino {
            return Err(fail("the newer pin was touched by the stale claim"));
        }
        if !ledger8.exists() {
            return Err(fail(
                "the newer ownership record was removed by the stale claim",
            ));
        }
        release_container_netns(&route, &nft, prepared8, t)
            .map_err(|e| fail(format!("release of the newer c8 netns failed: {}", e.error)))?;
        if newer_pin.exists() || ledger8.exists() {
            return Err(fail(
                "released c8 netns left the pin or the ownership record",
            ));
        }

        // 後始末: 子が作ったネットワーク atx を作成の請求書で回収する。
        let create_claim = FailedCreateClaim::from_record(&hex_decode(&create_hex)?)?;
        reclaim_failed_create(&route, &nft, &create_claim, t).map_err(|e| {
            fail(format!(
                "reclaim of network atx failed at {:?}: {e}",
                e.step
            ))
        })?;
        if !matches!(
            route.link_index(&bridge8, t),
            Err(ref e) if e.code() == NetErrorCode::NotFound
        ) || run_cmd("nft", &["list", "table", "ip", &table8]).is_ok()
        {
            return Err(fail("network atx was not reclaimed"));
        }

        // --- 故障注入で作った巻き戻しの失敗の取り残しを別プロセスが回収する（S3・S4。NET-1・REPAIR-3・#2971）---
        let quarantined = fault_scenarios(&route, &nft, &net, &mut ipam, &mut ports, &base, t)?;

        // --- 事前作成の netns（#2675・CRI-2）: 作成 → 接続 と、作成 → 解放 ---
        // 準備済みの試験で、実機（root）での実行結果は PR に記録する（未実行のまま成功とは書かない）。
        let ep6 = EndpointId::new("c6")?;
        let prepared6 = create_container_netns(&route, &base, &ep6, t)
            .map_err(|e| fail(format!("create_container_netns failed: {e:?}")))?;
        let pin6 = prepared6.pin_path();
        if !pin6.exists() {
            return Err(fail("prepared netns pin does not exist"));
        }
        let pin6_ino = fs::metadata(&pin6)
            .map_err(|e| fail(format!("stat prepared pin: {e}")))?
            .ino();
        let own_ino6 = fs::metadata("/proc/self/ns/net")
            .map_err(|e| fail(format!("stat own netns: {e}")))?
            .ino();
        if pin6_ino == own_ino6 {
            return Err(fail("prepared netns is the same as the current netns"));
        }
        let spec6 = ContainerAttachSpec::new(ep6.clone(), &net, base.clone())?;
        let attached6 =
            attach_prepared_container(&route, &nft, &spec6, prepared6, &mut ipam, &mut ports, t)
                .map_err(|e| {
                    fail(format!(
                        "attach_prepared_container failed at {:?}: {}",
                        e.error.step, e.error
                    ))
                })?;
        if attached6.netns_path != pin6 {
            return Err(fail("attached netns path differs from the prepared pin"));
        }
        let (_, flags6, master6) = link_state(&route, attached6.host_veth.as_str())?;
        if master6 != Some(net.bridge_index.get()) || flags6 & IFF_UP == 0 {
            return Err(fail(
                "host veth of the prepared netns is not up on the bridge",
            ));
        }
        let ep7 = EndpointId::new("c7")?;
        let prepared7 = create_container_netns(&route, &base, &ep7, t)
            .map_err(|e| fail(format!("create_container_netns (c7) failed: {e:?}")))?;
        let pin7 = prepared7.pin_path();
        release_container_netns(&route, &nft, prepared7, t)
            .map_err(|e| fail(format!("release_container_netns failed: {}", e.error)))?;
        if pin7.exists() {
            return Err(fail("released netns pin still exists"));
        }

        // --- ネットワーク削除（TASK-139.4・#317）: bridge・veth・netns pin・nft テーブル・予約が解放される ---
        let hosts = [
            attached.host_veth.clone(),
            attached3.host_veth.clone(),
            attached6.host_veth.clone(),
        ];
        let pins = [
            attached.netns_path.clone(),
            attached3.netns_path.clone(),
            attached6.netns_path.clone(),
        ];
        // S5 の quarantine（アドレス・予約）は、回収後も `delete_network` の直前までは残っている。
        for ep in &quarantined {
            if ipam.address_of(ep).is_none() {
                return Err(fail(format!(
                    "quarantined address of {} was released before delete_network",
                    ep.as_str()
                )));
            }
        }
        let deleted = delete_network(
            &route,
            &nft,
            &net,
            vec![attached, attached3, attached6],
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
        if !deleted.leftover.is_empty() {
            return Err(fail(format!("unexpected leftover: {:?}", deleted.leftover)));
        }
        let gone = |name: &IfName| {
            matches!(
                route.link_index(name, t),
                Err(ref e) if e.code() == NetErrorCode::NotFound
            )
        };
        if !gone(&net.bridge) {
            return Err(fail("bridge still exists after delete_network"));
        }
        for host in &hosts {
            if !gone(host) {
                return Err(fail(format!("veth {} still exists", host.as_str())));
            }
        }
        if run_cmd("nft", &["list", "table", "ip", net.table.as_str()]).is_ok() {
            return Err(fail("nft table still exists after delete_network"));
        }
        // masquerade はテーブルごと消える（ruleset 全体に残らない）。
        let ruleset = run_cmd("nft", &["list", "ruleset"])?;
        if ruleset.contains(net.table.as_str()) {
            return Err(fail(
                "nft ruleset still mentions the network table after delete_network",
            ));
        }
        for pin in &pins {
            if pin.exists() {
                return Err(fail(format!("pin {} still exists", pin.display())));
            }
        }
        for ep in &quarantined {
            if ipam.address_of(ep).is_some() {
                return Err(fail(format!(
                    "quarantined address of {} was not released by delete_network",
                    ep.as_str()
                )));
            }
        }
        if ipam.allocated_count() != 0 || !ports.is_empty() {
            return Err(fail("ipam or port reservations were not released"));
        }
        // 冪等: 何も残っていない状態での再実行も成功する。
        delete_network(&route, &nft, &net, Vec::new(), &mut ipam, &mut ports, t).map_err(|e| {
            fail(format!(
                "repeated delete_network failed at {:?}: {e}",
                e.step
            ))
        })?;
        Ok(echo_supported)
    }

    /// カーネルが `NLM_F_ECHO` 付きの link 作成に作成通知を返す版（v6.2 以上）かを `osrelease` から判定する。
    /// 版を読めなければ skip せず失敗する。
    fn kernel_supports_create_echo() -> Result<bool, NetError> {
        let release = fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|e| fail(format!("read osrelease: {e}")))?;
        let mut nums = release
            .trim()
            .split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .map(|p| p.parse::<u32>().ok());
        match (nums.next().flatten(), nums.next().flatten()) {
            (Some(major), Some(minor)) => Ok((major, minor) >= (6, 2)),
            _ => Err(fail(format!("cannot parse kernel release {release:?}"))),
        }
    }
}
