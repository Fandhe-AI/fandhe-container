//! bridge・veth の作成 → netns 移動 → up の実機結合試験（NET-11・TASK-136.3.2・#846・MS-8）。
//!
//! root が必要な実機前提テストのため `harness = false` の独自 `main` で動かし、`-- --ignored` を
//! 付けたときだけ実行する（未指定時は「ignored」を出力して成功終了する分離であり、CI 通過のための
//! 弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では対象外（skip ではなく OS 非該当）。
//!
//! # 流れ
//! - 親（host netns・root）: 外部コマンド `unshare --net` で新 netns の子を起動 → host の
//!   `NetlinkRouteSocket` で veth ペアを作成 → 片端を PID 指定、もう片端を ns fd 指定で子の netns へ移動
//!   → host から 2 端が消え、子の `/proc/<pid>/net/dev` に現れることを確認 → 子へ `go` を送る
//! - 子（新 netns の中）: bridge を作成 → bridge と veth 両端を up → `RTM_GETLINK` で `IFF_UP` を確認
//!
//! 移動したデバイスは移動先で down になり host のソケットからは見えなくなるため、up は子の netns 内の
//! ソケットから送る（`netlink_route/link.rs` のモジュール doc）。作ったものはすべて子の netns に入り、
//! 子の終了とともに消える。親の失敗経路では host に残りうる veth を、作成直後に控えた ifindex 指定（名前と ifindex の一致を再確認した場合のみ）の
//! `RTM_DELLINK` で後始末する（ベストエフォート。他者の同名リンクは消さない）。待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で
//! 期限を切る（REPAIR-5）。前提（root・`unshare`）を満たさない場合は skip せず失敗する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("link_netns_privileged: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().any(|a| a == "--ignored" || a == "--child") {
        linux::run();
    } else {
        println!(
            "link_netns_privileged: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::cell::Cell;
    use std::fs::File;
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::fd::AsFd as _;
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::mpsc::{self, Receiver};
    use std::time::{Duration, Instant};

    use fandhe_container_net::error::{NetError, NetErrorCode};
    use fandhe_container_net::netlink_route::{
        IFF_UP, IFINFOMSG_LEN, IFLA_IFNAME, IfName, LinkCreate, LinkRef, LinkSet,
        NetlinkRouteSocket, NetnsFd, NetnsPid, NetnsTarget, NlMsgBuilder, RTM_DELLINK, RTM_GETLINK,
        RTM_NEWLINK,
    };

    /// 新規 netns にカーネルが自動生成するフォールバックトンネルデバイス名。
    /// モジュールのロード状況で有無が変わるため「新規 netns 判定」では無視する。
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

    /// `IFLA_LINK`（linux/if_link.h）。veth ではペア相手の ifindex。
    const IFLA_LINK_ATTR: u16 = 5;

    const OK_LINE: &str = "link_netns_privileged: ok bridge=up veth_a=up veth_b=up";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        if let Some(pos) = args.iter().position(|a| a == "--child") {
            let names: Vec<&str> = args.iter().skip(pos + 1).map(String::as_str).collect();
            match child(&names) {
                Ok(()) => println!("{OK_LINE}"),
                Err(e) => {
                    println!("link_netns_privileged: child failed: {e}");
                    std::process::exit(1);
                }
            }
        } else {
            parent();
        }
    }

    fn name(s: &str) -> IfName {
        IfName::new(s).expect("valid interface name")
    }

    /// 名前指定の `RTM_GETLINK`（`ifinfomsg` 0 + `IFLA_IFNAME`）。応答の `RTM_NEWLINK` の
    /// `ifi_flags` を返す。
    fn get_link_flags(sock: &NetlinkRouteSocket, ifname: &str) -> Result<u32, NetError> {
        let n = name(ifname);
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
            .ok_or_else(|| NetError::new(NetErrorCode::Internal, "no RTM_NEWLINK in reply"))?;
        let raw = msg
            .payload()
            .get(8..12)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .ok_or_else(|| NetError::new(NetErrorCode::Internal, "short ifinfomsg in reply"))?;
        Ok(u32::from_ne_bytes(raw))
    }

    /// 名前指定の `RTM_GETLINK` で ifindex（`ifinfomsg.ifi_index`）を返す。
    fn get_link_index(sock: &NetlinkRouteSocket, ifname: &str) -> Result<u32, NetError> {
        let n = name(ifname);
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
            .ok_or_else(|| NetError::new(NetErrorCode::Internal, "no RTM_NEWLINK in reply"))?;
        let raw = msg
            .payload()
            .get(4..8)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .ok_or_else(|| NetError::new(NetErrorCode::Internal, "short ifinfomsg in reply"))?;
        Ok(u32::from_ne_bytes(raw))
    }

    /// 名前指定の `RTM_GETLINK` で (ifindex, `IFLA_LINK`) を返す。veth では `IFLA_LINK` が
    /// ペアの相手端の ifindex になる（作成直後の所有確認に使う）。
    fn get_link_index_and_peer(
        sock: &NetlinkRouteSocket,
        ifname: &str,
    ) -> Result<(u32, Option<u32>), NetError> {
        let n = name(ifname);
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
            .ok_or_else(|| NetError::new(NetErrorCode::Internal, "no RTM_NEWLINK in reply"))?;
        let payload = msg.payload();
        let short = || NetError::new(NetErrorCode::Internal, "short ifinfomsg in reply");
        let index = payload
            .get(4..8)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(u32::from_ne_bytes)
            .ok_or_else(short)?;
        // rtattr 列（len(2) type(2) 値、4 バイト境界）を checked で走査して IFLA_LINK を探す。
        let mut peer = None;
        let mut off = IFINFOMSG_LEN;
        let rd16 = |at: usize| {
            payload
                .get(at..at + 2)
                .and_then(|s| <[u8; 2]>::try_from(s).ok())
                .map(u16::from_ne_bytes)
        };
        while let (Some(len), Some(ty)) = (rd16(off), rd16(off + 2)) {
            let len = usize::from(len);
            let ty = ty & 0x3fff;
            if len < 4 {
                break;
            }
            if ty == IFLA_LINK_ATTR {
                peer = payload
                    .get(off + 4..off + len)
                    .and_then(|v| <[u8; 4]>::try_from(v).ok())
                    .map(u32::from_ne_bytes);
            }
            off += (len + 3) & !3;
        }
        Ok((index, peer))
    }

    /// ifindex 指定の `RTM_DELLINK`（テスト内の後始末専用。公開 API にはしない）。
    /// 名前ではなく自分が作成直後に控えた ifindex で消すため、同名の他者のリンクを巻き込まない。
    fn del_link_by_index(sock: &NetlinkRouteSocket, index: u32) -> Result<(), NetError> {
        sock.request(RTM_DELLINK, 0, timeout(), |b: &mut NlMsgBuilder| {
            let mut m = [0u8; IFINFOMSG_LEN];
            // ifinfomsg: family(1) pad(1) type(2) index(4) flags(4) change(4)
            if let Some(slot) = m.get_mut(4..8) {
                slot.copy_from_slice(&index.to_ne_bytes());
            }
            b.put_fixed(&m)
        })
        .map(|_| ())
    }

    // ---- 子（新 netns の中）----

    fn child(names: &[&str]) -> Result<(), NetError> {
        let (br, a, b) = match names {
            [br, a, b] => (*br, *a, *b),
            _ => {
                return Err(NetError::new(
                    NetErrorCode::InvalidArgument,
                    "child expects 3 interface names",
                ));
            }
        };
        // `--child` は親の `unshare --net` 経路を通らず直接起動できてしまう。root が host の netns で
        // 直接起動すると host に bridge 作成と link up が及ぶため、操作前に隔離を確認し、
        // 確認できなければ拒否する（P0・fail-closed）。
        ensure_isolated_netns()?;
        println!("ready");
        // パイプ越しでも確実に親へ届けるため明示的に flush する（go 待ちでブロックする前）。
        std::io::stdout().flush().map_err(|e| {
            NetError::new(NetErrorCode::Internal, format!("flush stdout failed: {e}"))
        })?;
        wait_for_go();
        let sock = NetlinkRouteSocket::open()?;
        sock.create_link(&LinkCreate::bridge(name(br)), timeout())?;
        for n in [br, a, b] {
            sock.set_link(&LinkSet::up(LinkRef::Name(name(n))), timeout())?;
        }
        for n in [br, a, b] {
            let flags = get_link_flags(&sock, n)?;
            if flags & IFF_UP == 0 {
                return Err(NetError::new(
                    NetErrorCode::FailedPrecondition,
                    format!("IFF_UP not set on {n}: flags={flags:#x}"),
                ));
            }
        }
        Ok(())
    }

    /// 自分が新規 netns にいることを確認する。次の 2 条件をどちらも満たさなければ拒否する。
    /// - 親プロセスの netns と inode が異なる（`unshare --net` 経由なら親は host の netns）
    /// - `/proc/self/net/dev` が `lo` とカーネルのフォールバックトンネルデバイスのみ
    ///   （新規 netns は `lo` に加え、tunnel 系モジュールのロード状況により `sit0`・`gre0` 等を自動で持つ）
    fn ensure_isolated_netns() -> Result<(), NetError> {
        let deny = |m: String| NetError::new(NetErrorCode::FailedPrecondition, m);
        let io = |what: &str, e: std::io::Error| {
            NetError::new(NetErrorCode::Internal, format!("{what} failed: {e}"))
        };
        let status = std::fs::read_to_string("/proc/self/status")
            .map_err(|e| io("read /proc/self/status", e))?;
        let ppid = status
            .lines()
            .find_map(|l| l.strip_prefix("PPid:"))
            .and_then(|v| v.trim().parse::<u32>().ok())
            .ok_or_else(|| deny("cannot determine parent pid; refusing to run".to_owned()))?;
        let own = std::fs::read_link("/proc/self/ns/net")
            .map_err(|e| io("readlink /proc/self/ns/net", e))?;
        let parent = std::fs::read_link(format!("/proc/{ppid}/ns/net"))
            .map_err(|e| deny(format!("cannot read parent netns ({e}); refusing to run")))?;
        if own == parent {
            return Err(deny(format!(
                "child shares the parent's netns ({}); run via the parent test (`-- --ignored`)",
                own.display()
            )));
        }
        let dev = std::fs::read_to_string("/proc/self/net/dev")
            .map_err(|e| io("read /proc/self/net/dev", e))?;
        let foreign: Vec<&str> = dev
            .lines()
            .skip(2)
            .filter_map(|l| l.split(':').next().map(str::trim))
            .filter(|n| !n.is_empty() && *n != "lo" && !FALLBACK_TUNNEL_DEVICES.contains(n))
            .collect();
        if !foreign.is_empty() {
            return Err(deny(format!(
                "netns is not fresh (interfaces present: {foreign:?}); refusing to run"
            )));
        }
        Ok(())
    }

    /// 標準入力の `go` 行を期限付きで待つ。期限切れ・EOF は失敗として終了する。
    fn wait_for_go() {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::stdin().lock().read_line(&mut line);
            let _ = tx.send(line);
        });
        match rx.recv_timeout(timeout()) {
            Ok(l) if l.trim() == "go" => {}
            other => {
                println!("link_netns_privileged: child did not receive go: {other:?}");
                std::process::exit(1);
            }
        }
    }

    // ---- 親（host netns）----

    /// host 上に残りうる veth の後始末用状態（親の失敗経路で参照する）。
    struct HostState {
        /// create_link の成功応答後に控えた、host 上の未移動の端の ifindex。
        owned: [Cell<Option<u32>>; 2],
        /// create_link の成功応答を得たか（ifindex 記録前の失敗経路の判定用）。
        created: Cell<bool>,
        /// 各端の移動要求が成功応答を得て host から外れたか。
        moved: [Cell<bool>; 2],
    }

    /// create_link 成功後〜ifindex 記録前に失敗した経路の所有確認。ifindex が未記録のため、今の host 上の
    /// 両端が互いを `IFLA_LINK` で指し合う veth ペアだと確認できた場合だけ ifindex を控える
    /// （他者の同名リンクを巻き込まない。確認できなければ控えず、消さずに残存を許容する）。
    fn confirm_unrecorded_pair(sock: &NetlinkRouteSocket, a: &str, b: &str, st: &HostState) {
        let unrecorded = st.created.get()
            && st.owned.iter().all(|c| c.get().is_none())
            && st.moved.iter().all(|m| !m.get());
        if !unrecorded {
            return;
        }
        let (Ok((ia, pa)), Ok((ib, pb))) = (
            get_link_index_and_peer(sock, a),
            get_link_index_and_peer(sock, b),
        ) else {
            return;
        };
        if pa == Some(ib) && pb == Some(ia) {
            st.owned[0].set(Some(ia));
            st.owned[1].set(Some(ib));
        }
    }

    /// drop で子を kill して wait するガード（失敗経路でも netns と子を残さない）。
    struct ChildGuard {
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
        /// 期限内に `expected` と一致する行が来るまで読む。`unshare` の診断など想定外の行は読み捨てる。
        fn expect_line(&self, deadline: Instant, expected: &str) {
            let mut skipped = Vec::new();
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match self.lines.recv_timeout(left) {
                    Ok(l) if l == expected => return,
                    Ok(l) => skipped.push(l),
                    Err(e) => panic!(
                        "child did not print {expected:?} before deadline: {e}; other lines: {skipped:?}"
                    ),
                }
            }
        }
    }

    fn require_root_and_unshare() {
        let uid_root = std::fs::read_to_string("/proc/self/status")
            .expect("read /proc/self/status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_owned))
            .as_deref()
            == Some("0");
        assert!(uid_root, "this test requires root (euid 0); see AGENTS.md");
        let ok = Command::new("unshare")
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "util-linux `unshare` is required; see AGENTS.md");
    }

    fn parent() {
        require_root_and_unshare();
        let deadline = Instant::now() + timeout();
        let tag = format!("{:x}", std::process::id() & 0xfffff);
        let (br, a, b) = (
            format!("fcb{tag}"),
            format!("fcv{tag}a"),
            format!("fcv{tag}b"),
        );
        let sock = NetlinkRouteSocket::open().expect("open netlink route socket");

        let exe = std::env::current_exe().expect("current_exe");
        let mut cmd = Command::new("unshare");
        cmd.args(["--net", "--"])
            .arg(exe)
            .args(["--child", &br, &a, &b])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn unshare --net child");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("child stdout");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let pid = child.id();
        let mut guard = ChildGuard {
            child,
            stdin,
            lines: rx,
        };

        // 本試験が create_link の成功応答を得て、作成直後に ifindex を控えた host 上の未移動の端だけを保持する。
        // 後始末は名前ではなく ifindex で消すため、同名の他者のリンクは消さない（P0）。
        let st = HostState {
            owned: [Cell::new(None), Cell::new(None)],
            created: Cell::new(false),
            moved: [Cell::new(false), Cell::new(false)],
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scenario(&sock, &mut guard, pid, (&a, &b), deadline, &st)
        }));
        // 移動前に失敗した場合に host へ残る veth を片付ける（本試験が作成したものに限る）。
        {
            // create_link 成功後〜ifindex 記録前に失敗した経路: ifindex が未記録のため、今の host 上の
            // 両端が「互いを IFLA_LINK で指し合う veth ペア」だと確認できた場合だけ ifindex を控える
            // （他者の同名リンクを巻き込まない。確認できなければ消さず残存を許容する）。
            confirm_unrecorded_pair(&sock, &a, &b, &st);
            // a だけ移動済みで b が host に残る経路もあるため、未移動の端ごとに試す（NotFound は想定内）。
            // 移動要求が Timeout / DataLoss 等で応答不明でもカーネル側では移動済みの可能性がある。
            // 控えた ifindex が今も host 上の同名リンクのものだと再確認できた場合だけ消す（P0。
            // ifindex を他者が再利用したリンクを巻き込まない。確認できなければ消さず残存を許容する）。
            for (ifname, idx) in [&a, &b]
                .into_iter()
                .zip(st.owned.iter())
                .filter_map(|(n, c)| c.get().map(|i| (n, i)))
            {
                if get_link_index(&sock, ifname).ok() != Some(idx) {
                    eprintln!(
                        "link_netns_privileged: {ifname} is not the link we created on host; skip cleanup"
                    );
                    continue;
                }
                match del_link_by_index(&sock, idx) {
                    Ok(()) => eprintln!("link_netns_privileged: cleaned up leftover veth on host"),
                    Err(e) if e.code() == NetErrorCode::NotFound => {}
                    Err(e) => eprintln!("link_netns_privileged: cleanup failed: {e}"),
                }
            }
        }
        drop(guard);
        if let Err(p) = result {
            std::panic::resume_unwind(p);
        }
        println!("link_netns_privileged: bridge/veth create, netns move (pid+fd), up verified");
    }

    fn scenario(
        sock: &NetlinkRouteSocket,
        guard: &mut ChildGuard,
        pid: u32,
        (a, b): (&str, &str),
        deadline: Instant,
        st: &HostState,
    ) {
        guard.expect_line(deadline, "ready");

        // 既存の host インターフェースと名前が衝突していないことを作成前に確認する。
        for n in [a, b] {
            let e = get_link_flags(sock, n)
                .expect_err("interface name already exists on host; refusing to proceed");
            assert_eq!(e.code(), NetErrorCode::NotFound, "{n}");
        }
        // 所有は create_link の成功応答を得た後にだけ宣言する。事前の不在確認だけでは、確認と作成の間に
        // 別プロセスが同名を作った場合に AlreadyExists 後の後始末で他者のリンクを消してしまう（P0）。
        // 応答不明（Timeout / DataLoss）の場合は所有を主張せず失敗する（残存の可能性は許容し、消さない側に倒す）。
        sock.create_link(
            &LinkCreate::veth(name(a), name(b)).expect("veth request"),
            timeout(),
        )
        .expect("create veth pair");
        st.created.set(true);
        // 作成直後に ifindex を控え、後始末はこの ifindex だけを対象にする。
        st.owned[0].set(Some(get_link_index(sock, a).expect("ifindex of a")));
        st.owned[1].set(Some(get_link_index(sock, b).expect("ifindex of b")));

        // a は PID 指定、b は ns fd 指定で子の netns へ移動する。
        let by_pid = NetnsTarget::Pid(NetnsPid::new(pid).expect("child pid"));
        sock.set_link(
            &LinkSet::move_to_netns(LinkRef::Name(name(a)), by_pid),
            timeout(),
        )
        .expect("move a by pid");
        // 移動の成功応答を得た端は host の ifindex と無関係になるため後始末対象から外す。
        // 失敗・応答不明の場合は外さず、後始末側が名前と ifindex の一致を再確認してから消す。
        st.owned[0].set(None);
        st.moved[0].set(true);
        let ns_file = File::open(format!("/proc/{pid}/ns/net")).expect("open child netns");
        let by_fd = NetnsTarget::Fd(NetnsFd::new(ns_file.as_fd()).expect("netns fd"));
        sock.set_link(
            &LinkSet::move_to_netns(LinkRef::Name(name(b)), by_fd),
            timeout(),
        )
        .expect("move b by fd");
        st.owned[1].set(None);
        st.moved[1].set(true);

        // host からは両端が消え、子の netns に現れる。
        for n in [a, b] {
            let e = get_link_flags(sock, n).expect_err("moved link must be gone from host");
            assert_eq!(e.code(), NetErrorCode::NotFound, "{n}");
        }
        let dev = std::fs::read_to_string(format!("/proc/{pid}/net/dev")).expect("child net/dev");
        for n in [a, b] {
            assert!(
                dev.lines()
                    .any(|l| l.trim_start().starts_with(&format!("{n}:"))),
                "{n} missing from child netns: {dev}"
            );
        }

        let stdin = guard.stdin.as_mut().expect("child stdin");
        stdin.write_all(b"go\n").expect("write go");
        stdin.flush().expect("flush go");
        guard.expect_line(deadline, OK_LINE);

        loop {
            match guard.child.try_wait().expect("try_wait") {
                Some(status) => {
                    assert_eq!(status.code(), Some(0), "child must exit with 0");
                    return;
                }
                None if Instant::now() >= deadline => panic!("child did not exit in time"),
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }
}
