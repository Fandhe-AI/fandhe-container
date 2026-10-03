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
//! 子の終了とともに消える。親の失敗経路では host に残りうる veth を名前指定の `RTM_DELLINK` で
//! 後始末する（ベストエフォート）。待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で
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

    /// 名前指定の `RTM_DELLINK`（テスト内の後始末専用。公開 API にはしない）。
    fn del_link(sock: &NetlinkRouteSocket, ifname: &str) -> Result<(), NetError> {
        let n = name(ifname);
        sock.request(RTM_DELLINK, 0, timeout(), |b: &mut NlMsgBuilder| {
            b.put_fixed(&[0u8; IFINFOMSG_LEN])?;
            let mut v = n.as_str().as_bytes().to_vec();
            v.push(0);
            b.put_attr(IFLA_IFNAME, &v)
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
        println!("ready");
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
        fn next_line(&self, deadline: Instant) -> String {
            let left = deadline.saturating_duration_since(Instant::now());
            self.lines
                .recv_timeout(left)
                .unwrap_or_else(|e| panic!("child produced no line before deadline: {e}"))
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

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scenario(&sock, &mut guard, pid, &a, &b, deadline)
        }));
        // 移動前に失敗した場合に host へ残る veth を片付ける（NotFound は想定内）。
        match del_link(&sock, &a) {
            Ok(()) => eprintln!("link_netns_privileged: cleaned up leftover veth on host"),
            Err(e) if e.code() == NetErrorCode::NotFound => {}
            Err(e) => eprintln!("link_netns_privileged: cleanup failed: {e}"),
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
        a: &str,
        b: &str,
        deadline: Instant,
    ) {
        assert_eq!(guard.next_line(deadline), "ready");

        sock.create_link(
            &LinkCreate::veth(name(a), name(b)).expect("veth request"),
            timeout(),
        )
        .expect("create veth pair");

        // a は PID 指定、b は ns fd 指定で子の netns へ移動する。
        let by_pid = NetnsTarget::Pid(NetnsPid::new(pid).expect("child pid"));
        sock.set_link(
            &LinkSet::move_to_netns(LinkRef::Name(name(a)), by_pid),
            timeout(),
        )
        .expect("move a by pid");
        let ns_file = File::open(format!("/proc/{pid}/ns/net")).expect("open child netns");
        let by_fd = NetnsTarget::Fd(NetnsFd::new(ns_file.as_fd()).expect("netns fd"));
        sock.set_link(
            &LinkSet::move_to_netns(LinkRef::Name(name(b)), by_fd),
            timeout(),
        )
        .expect("move b by fd");

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
        assert_eq!(guard.next_line(deadline), OK_LINE);

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
