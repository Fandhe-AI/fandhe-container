//! `PodNetnsDialer` の単体試験（偽の helper と偽の保持役 source を使う。実 helper を通す確認は #4487 の段 F。
//! CRI-6・NET-3・SEC-1・SEC-5・REPAIR-4・REPAIR-5・#4484）。待ちにはすべて有限の期限を付ける。

use std::collections::HashMap;
use std::fs::File;
use std::io::Read as _;
use std::net::{Ipv4Addr, TcpListener};
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_net::netns_dial::test_support::{recv_raw_fds, send_raw};
use fandhe_container_net::netns_dial::{DialRequestFrame, DialResponse, DialResponseFrame};
use fandhe_container_supervisor::pod_holder::NsId;

use super::*;

fn pod(id: &str) -> PortForwardTarget {
    PortForwardTarget::new(id, PortForwardNetwork::Pod)
}

fn nsid(f: &File) -> NsId {
    let m = f.metadata().expect("stat");
    NsId {
        dev: m.dev(),
        ino: m.ino(),
    }
}

// 期限つき回収の正本（排他作成の 0700 親＋共有 flock。#2840・#2887・REPAIR-12）を core の試験補助から取り込む。
#[path = "../../../../core/tests/support/scratch_root.rs"]
mod scratch_root;

/// 一意な一時ディレクトリ。排他作成した保護済みの親を `ScratchDir` が持ち、作成した pid でだけ drop で消す。
struct Scratch(scratch_root::ScratchDir);

impl Scratch {
    fn new(tag: &str) -> Self {
        Self(scratch_root::ScratchDir::new(
            &format!("fc-poddialer-{tag}"),
            Duration::from_secs(10),
        ))
    }

    fn path(&self) -> &Path {
        self.0.path()
    }
}

/// sandbox ID ごとに通常ファイル 2 本を ns の fd として返す偽の source。
struct FakeSource {
    dir: PathBuf,
    calls: AtomicUsize,
    /// 記録の net 素性を実体とずらす sandbox。
    skew_net: Vec<String>,
    /// 実体を自プロセスの ns にする sandbox（`user`・`net`）。
    own_user: Vec<String>,
    own_net: Vec<String>,
    known: Mutex<HashMap<String, ()>>,
}

impl FakeSource {
    fn new(dir: &Path, ids: &[&str]) -> Self {
        let mut known = HashMap::new();
        for id in ids {
            std::fs::write(dir.join(format!("{id}_user")), b"").expect("w");
            std::fs::write(dir.join(format!("{id}_net")), b"").expect("w");
            known.insert((*id).to_owned(), ());
        }
        Self {
            dir: dir.to_path_buf(),
            calls: AtomicUsize::new(0),
            skew_net: vec![],
            own_user: vec![],
            own_net: vec![],
            known: Mutex::new(known),
        }
    }

    fn ids_of(&self, id: &str) -> ((u64, u64), (u64, u64)) {
        let u = nsid(&File::open(self.dir.join(format!("{id}_user"))).expect("open"));
        let n = nsid(&File::open(self.dir.join(format!("{id}_net"))).expect("open"));
        ((u.dev, u.ino), (n.dev, n.ino))
    }
}

impl PodNamespaceSource for FakeSource {
    fn open_pod_namespaces(&self, sandbox_id: &str) -> Result<PodNamespaceFds, TraitError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.known.lock().expect("lock").contains_key(sandbox_id) {
            return Err(TraitError::new(ErrorCode::Unavailable, "no holder"));
        }
        let user = if self.own_user.iter().any(|s| s == sandbox_id) {
            File::open("/proc/self/ns/user")
        } else {
            File::open(self.dir.join(format!("{sandbox_id}_user")))
        }
        .expect("open user");
        let net = if self.own_net.iter().any(|s| s == sandbox_id) {
            File::open("/proc/self/ns/net")
        } else {
            File::open(self.dir.join(format!("{sandbox_id}_net")))
        }
        .expect("open net");
        let (uid, mut nid) = (nsid(&user), nsid(&net));
        if self.skew_net.iter().any(|s| s == sandbox_id) {
            nid.ino = nid.ino.wrapping_add(1000);
        }
        Ok(PodNamespaceFds::for_test(
            OwnedFd::from(user),
            OwnedFd::from(net),
            uid,
            nid,
        ))
    }
}

/// 偽 helper の返答。
#[derive(Clone)]
enum Reply {
    /// 何も返さず stdin も読まない（期限切れの場面）。
    Silent,
    Frame(DialResponse),
    Raw(Vec<u8>),
    Hangup,
    /// 要求の port の host の loopback へ connect した socket を `Connected` で返す。
    ConnectedHost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    port: u16,
    fds: Vec<(u64, u64)>,
}

struct FakeSpawner {
    reply: Reply,
    spawns: AtomicUsize,
    pids: Mutex<Vec<u32>>,
    seen: std::sync::Arc<Mutex<Vec<Seen>>>,
}

impl FakeSpawner {
    fn new(reply: Reply) -> Self {
        Self {
            reply,
            spawns: AtomicUsize::new(0),
            pids: Mutex::new(vec![]),
            seen: std::sync::Arc::new(Mutex::new(vec![])),
        }
    }
}

fn sleeper() -> Command {
    let mut c = Command::new("sleep");
    c.arg("30");
    c
}

impl NetnsDialSpawner for FakeSpawner {
    fn spawn(&self, channel_end: OwnedFd) -> Result<Child, CriError> {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        let mut cmd = sleeper();
        if matches!(self.reply, Reply::Silent) {
            cmd.stdin(Stdio::from(channel_end));
            let child = cmd.spawn().expect("spawn sleep");
            self.pids.lock().expect("l").push(child.id());
            return Ok(child);
        }
        cmd.stdin(Stdio::null());
        let child = cmd.spawn().expect("spawn sleep");
        self.pids.lock().expect("l").push(child.id());
        let reply = self.reply.clone();
        let seen = self.seen.clone();
        std::thread::spawn(move || {
            let Ok(Some((bytes, fds))) =
                recv_raw_fds(channel_end.as_fd(), Duration::from_secs(5), 2)
            else {
                return;
            };
            let port = DialRequestFrame::decode(&bytes)
                .map(|r| r.port().get())
                .unwrap_or(0);
            let ids = fds
                .iter()
                .map(|f| {
                    let m = File::from(f.try_clone().expect("clone"))
                        .metadata()
                        .expect("stat");
                    (m.dev(), m.ino())
                })
                .collect();
            seen.lock().expect("l").push(Seen { port, fds: ids });
            drop(fds);
            let connected = *DialResponseFrame::encode(DialResponse::Connected).as_bytes();
            match reply {
                Reply::Silent | Reply::Hangup => {}
                Reply::Frame(r) => {
                    let _ = send_raw(
                        channel_end.as_fd(),
                        DialResponseFrame::encode(r).as_bytes(),
                        &[],
                    );
                }
                Reply::Raw(b) => {
                    let _ = send_raw(channel_end.as_fd(), &b, &[]);
                }
                Reply::ConnectedHost => {
                    let s = std::net::TcpStream::connect_timeout(
                        &std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                        Duration::from_secs(5),
                    )
                    .expect("connect host");
                    send_raw(channel_end.as_fd(), &connected, &[s.as_fd()]).expect("send fd");
                }
            }
        });
        Ok(child)
    }
}

fn dialer(
    src: FakeSource,
    sp: &std::sync::Arc<FakeSpawner>,
) -> (PodNetnsDialer, std::sync::Arc<FakeSource>) {
    let src = std::sync::Arc::new(src);
    (PodNetnsDialer::with_spawner(src.clone(), sp.clone()), src)
}

const T5: Duration = Duration::from_secs(5);

fn err_of(r: Result<TcpStream, CriError>) -> (CriErrorCode, String) {
    let e = r.expect_err("must fail");
    (e.code(), e.message().to_owned())
}

/// 最大 `d` の間、`f` が真になるのを待つ。
fn wait_until(d: Duration, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + d;
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    f()
}

/// CRI-6・#4484: NODE の target は host の loopback の dialer へ委ね、helper も保持役も使わない。
#[test]
fn cri6_4484_node_target_delegates_to_loopback() {
    let s = Scratch::new("node");
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::Silent));
    let (d, src) = dialer(FakeSource::new(s.path(), &[]), &sp);
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let port = l.local_addr().expect("addr").port();
    let c = d
        .dial(
            &PortForwardTarget::new("x", PortForwardNetwork::Node),
            port,
            T5,
        )
        .expect("dial");
    assert_eq!(c.peer_addr().expect("peer").port(), port);
    assert_eq!(sp.spawns.load(Ordering::SeqCst), 0);
    assert_eq!(src.calls.load(Ordering::SeqCst), 0);
}

/// CRI-6・#4484: port 0 と timeout 0 は固定文の `INVALID_ARGUMENT` で、保持役も helper も使わない。
#[test]
fn cri6_4484_invalid_port_and_timeout_do_not_spawn() {
    let s = Scratch::new("inval");
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::Silent));
    let (d, src) = dialer(FakeSource::new(s.path(), &["a"]), &sp);
    assert_eq!(
        err_of(d.dial(&pod("a"), 0, T5)),
        (CriErrorCode::InvalidArgument, MSG_PORT_RANGE.to_owned())
    );
    assert_eq!(
        err_of(d.dial(&pod("a"), 80, Duration::ZERO)),
        (
            CriErrorCode::InvalidArgument,
            MSG_TIMEOUT_POSITIVE.to_owned()
        )
    );
    assert_eq!(
        err_of(d.dial(&pod("a"), 80, Duration::MAX)),
        (CriErrorCode::InvalidArgument, MSG_TIMEOUT_RANGE.to_owned())
    );
    assert_eq!(sp.spawns.load(Ordering::SeqCst), 0);
    assert_eq!(src.calls.load(Ordering::SeqCst), 0);
}

/// CRI-6・SEC-1・#4484: 保持役が無ければ `UNAVAILABLE` で、host の loopback へは縮退しない。
#[test]
fn cri6_sec1_4484_missing_holder_is_unavailable_without_fallback() {
    let s = Scratch::new("missing");
    let holder = std::sync::Arc::new(ProductionPodHolder::with_fixed_program(
        PathBuf::from("/nonexistent"),
        vec![],
        false,
        4,
    ));
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::Silent));
    let d = PodNetnsDialer::with_spawner(holder, sp.clone());
    // host の loopback で待ち受ける（縮退していれば接続される）。
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    l.set_nonblocking(true).expect("nb");
    let port = l.local_addr().expect("addr").port();
    assert_eq!(
        err_of(d.dial(&pod("absent"), port, T5)),
        (CriErrorCode::Unavailable, MSG_NS_UNAVAILABLE.to_owned())
    );
    assert_eq!(sp.spawns.load(Ordering::SeqCst), 0);
    assert!(
        l.accept().is_err(),
        "must not fall back to the host loopback"
    );
    drop(s);
}

/// SEC-1・NET-3・#4484: 保持役の net / user が plugin-cri 自身のものなら helper の起動前に拒否する。
#[test]
fn sec1_net3_4484_own_namespace_is_rejected_before_spawn() {
    let s = Scratch::new("own");
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::Silent));
    let mut src = FakeSource::new(s.path(), &["n", "u"]);
    src.own_net = vec!["n".into()];
    src.own_user = vec!["u".into()];
    let (d, _src) = dialer(src, &sp);
    for id in ["n", "u"] {
        assert_eq!(
            err_of(d.dial(&pod(id), 80, T5)),
            (CriErrorCode::Unavailable, MSG_NS_NOT_ISOLATED.to_owned()),
            "{id}"
        );
    }
    assert_eq!(sp.spawns.load(Ordering::SeqCst), 0);
}

/// SEC-1・#4484: 記録の net 素性と fd の実体が違えば `UNAVAILABLE` で、helper は起動しない。
#[test]
fn sec1_4484_recorded_identity_mismatch_is_rejected() {
    let s = Scratch::new("skew");
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::Silent));
    let mut src = FakeSource::new(s.path(), &["a"]);
    src.skew_net = vec!["a".into()];
    let (d, _src) = dialer(src, &sp);
    assert_eq!(
        err_of(d.dial(&pod("a"), 80, T5)),
        (CriErrorCode::Unavailable, MSG_NS_UNAVAILABLE.to_owned())
    );
    assert_eq!(sp.spawns.load(Ordering::SeqCst), 0);
}

/// REPAIR-5・#4484: 後始末の予約を引くと予算が残らない timeout は、helper を起動せず `TIMEOUT`。
#[test]
fn repair5_4484_insufficient_budget_times_out_without_spawn() {
    let s = Scratch::new("budget");
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::Silent));
    let (d, src) = dialer(FakeSource::new(s.path(), &["a"]), &sp);
    assert_eq!(
        err_of(d.dial(&pod("a"), 80, Duration::from_millis(1500))),
        (CriErrorCode::Timeout, MSG_TIMED_OUT.to_owned())
    );
    assert_eq!(sp.spawns.load(Ordering::SeqCst), 0);
    assert_eq!(src.calls.load(Ordering::SeqCst), 0);
}

/// REPAIR-5・#4484: 応答しない helper は期限内に `TIMEOUT` で返り、SIGKILL で回収される（保持一覧は空）。
#[test]
fn repair5_4484_silent_helper_times_out_and_is_reaped() {
    let s = Scratch::new("silent");
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::Silent));
    let (d, _src) = dialer(FakeSource::new(s.path(), &["a"]), &sp);
    let started = Instant::now();
    assert_eq!(
        err_of(d.dial(&pod("a"), 80, Duration::from_millis(1600))),
        (CriErrorCode::Timeout, MSG_TIMED_OUT.to_owned())
    );
    assert!(
        started.elapsed() < Duration::from_millis(2600),
        "elapsed {:?}",
        started.elapsed()
    );
    let pid = sp.pids.lock().expect("l")[0];
    assert!(!Path::new(&format!("/proc/{pid}")).exists(), "reaped");
    assert_eq!(d.retained_len_for_test(), 0);
}

/// SEC-1・NET-3・#4484: helper が host の netns の socket を返しても拒否し、fd は閉じる。
#[test]
fn sec1_net3_4484_host_netns_socket_is_rejected() {
    let s = Scratch::new("host");
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::ConnectedHost));
    let (d, _src) = dialer(FakeSource::new(s.path(), &["a"]), &sp);
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let port = l.local_addr().expect("addr").port();
    assert_eq!(
        err_of(d.dial(&pod("a"), port, T5)),
        (CriErrorCode::Unavailable, MSG_POD_DIAL_FAILED.to_owned())
    );
    // dialer が受けた fd と偽 helper の複製が閉じていれば、listener 側は EOF を読む。
    // accept に期限が無いと接続前の失敗で無期限に止まるため、nonblocking＋締切付きで待つ（REPAIR-5）。
    l.set_nonblocking(true).expect("nb");
    let deadline = std::time::Instant::now() + T5;
    let mut peer = loop {
        match l.accept() {
            Ok((p, _)) => break p,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(std::time::Instant::now() < deadline, "accept timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("accept failed: {e}"),
        }
    };
    peer.set_nonblocking(false).expect("blocking");
    peer.set_read_timeout(Some(T5)).expect("timeout");
    let mut b = [0u8; 1];
    assert_eq!(peer.read(&mut b).expect("eof"), 0);
    let pid = sp.pids.lock().expect("l")[0];
    assert!(wait_until(T5, || !Path::new(&format!("/proc/{pid}")).exists()));
}

/// SEC-1・SEC-5・#4484: pod A / B の dial は、それぞれ自分の保持役の (user, net) の順で fd を送り、取り違えない。
#[test]
fn sec1_sec5_4484_pod_a_and_b_send_their_own_namespaces() {
    let s = Scratch::new("ab");
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::Frame(DialResponse::Error(
        DialErrorCode::Refused,
    ))));
    let (d, src) = dialer(FakeSource::new(s.path(), &["a", "b"]), &sp);
    for (id, port) in [("a", 8080u16), ("b", 9090u16)] {
        assert_eq!(
            err_of(d.dial(&pod(id), port, T5)),
            (CriErrorCode::Unavailable, MSG_DIAL_FAILED.to_owned())
        );
    }
    let seen = sp.seen.lock().expect("l").clone();
    let (a, b) = (src.ids_of("a"), src.ids_of("b"));
    assert_eq!(
        seen,
        vec![
            Seen {
                port: 8080,
                fds: vec![a.0, a.1]
            },
            Seen {
                port: 9090,
                fds: vec![b.0, b.1]
            },
        ]
    );
    assert_ne!(a, b);
}

/// REPAIR-4・#4484: helper の失敗は固定の code と文に写る（EOF・壊れた frame を含む）。
#[test]
fn cri6_repair4_4484_helper_failures_map_to_fixed_errors() {
    let mut cases: Vec<(Reply, CriErrorCode, &str)> = vec![
        (
            Reply::Hangup,
            CriErrorCode::Unavailable,
            MSG_POD_DIAL_FAILED,
        ),
        (
            Reply::Raw(vec![0xff; 16]),
            CriErrorCode::Unavailable,
            MSG_POD_DIAL_FAILED,
        ),
        (
            Reply::Frame(DialResponse::Connected),
            CriErrorCode::Unavailable,
            MSG_POD_DIAL_FAILED,
        ),
    ];
    for code in DialErrorCode::ALL {
        let (c, m) = match code {
            DialErrorCode::TimedOut => (CriErrorCode::Timeout, MSG_TIMED_OUT),
            DialErrorCode::Refused | DialErrorCode::Unreachable => {
                (CriErrorCode::Unavailable, MSG_DIAL_FAILED)
            }
            DialErrorCode::JoinFailed | DialErrorCode::IdentityMismatch => {
                (CriErrorCode::Unavailable, MSG_POD_DIAL_FAILED)
            }
            _ => (CriErrorCode::Internal, MSG_POD_DIAL_INTERNAL),
        };
        cases.push((Reply::Frame(DialResponse::Error(code)), c, m));
    }
    for (reply, code, msg) in cases {
        let s = Scratch::new("map");
        let sp = std::sync::Arc::new(FakeSpawner::new(reply));
        let (d, _src) = dialer(FakeSource::new(s.path(), &["a"]), &sp);
        assert_eq!(err_of(d.dial(&pod("a"), 80, T5)), (code, msg.to_owned()));
    }
}

/// REPAIR-5・#4484: 回収できない helper が上限に達したら、保持役も helper も使わず `RESOURCE_EXHAUSTED`。
#[test]
fn repair5_4484_retained_limit_returns_resource_exhausted() {
    let s = Scratch::new("limit");
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::Frame(DialResponse::Error(
        DialErrorCode::Refused,
    ))));
    let (d, src) = dialer(FakeSource::new(s.path(), &["a"]), &sp);
    for _ in 0..MAX_RETAINED_DIAL_HELPERS {
        d.push_retained_for_test(sleeper().stdin(Stdio::null()).spawn().expect("spawn"));
    }
    assert_eq!(
        err_of(d.dial(&pod("a"), 80, T5)),
        (
            CriErrorCode::ResourceExhausted,
            MSG_RETAINED_FULL.to_owned()
        )
    );
    assert_eq!(sp.spawns.load(Ordering::SeqCst), 0);
    assert_eq!(src.calls.load(Ordering::SeqCst), 0);
    // 回収できたものは掃除され、次の dial は helper を起動する。
    for c in d.lock_retained().iter_mut() {
        let _ = c.kill();
    }
    assert!(wait_until(T5, || d.sweep_retained() == 0));
    assert_eq!(
        err_of(d.dial(&pod("a"), 80, T5)),
        (CriErrorCode::Unavailable, MSG_DIAL_FAILED.to_owned())
    );
    assert_eq!(sp.spawns.load(Ordering::SeqCst), 1);
}

/// REPAIR-4・#4484: 固定文は互いに異なり、port・pid 等の数字を含まない。
#[test]
fn repair4_4484_messages_are_fixed_and_unique() {
    let all = [
        MSG_PORT_RANGE,
        MSG_TIMEOUT_POSITIVE,
        MSG_RETAINED_FULL,
        MSG_TIMED_OUT,
        MSG_NS_LOOKUP_FAILED,
        MSG_NS_UNAVAILABLE,
        MSG_NS_NOT_ISOLATED,
        MSG_HELPER_START,
        MSG_DIAL_FAILED,
        MSG_POD_DIAL_FAILED,
        MSG_POD_DIAL_INTERNAL,
    ];
    for (i, a) in all.iter().enumerate() {
        assert!(
            a.is_ascii() && !a.bytes().any(|b| b.is_ascii_digit()),
            "{a}"
        );
        for b in &all[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

/// SEC-1・PLUG-11・#4484: helper の Command は argv が `netns-dial` の 1 個だけで cwd は `/`。
#[test]
fn cri6_4484_netns_dial_command_has_fixed_argv_and_cwd() {
    let (_ch, end) = NetnsDialChannel::pair().expect("pair");
    let mut cmd = Command::new("x");
    configure_netns_dial(&mut cmd, end);
    assert_eq!(
        cmd.get_args().collect::<Vec<_>>(),
        vec![std::ffi::OsStr::new("netns-dial")]
    );
    assert_eq!(cmd.get_current_dir(), Some(Path::new("/")));
}

/// CRI-6・#4484: 本 dialer は POD ネットワークに対応する。
#[test]
fn cri6_4484_supports_pod_network() {
    let s = Scratch::new("supports");
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::Silent));
    let (d, _src) = dialer(FakeSource::new(s.path(), &[]), &sp);
    assert!(d.supports_pod_network());
}

/// 起動した `true` が zombie（終了済み・未回収）になるまで待つ。`try_wait` を呼ばず `/proc` で観測する。
fn zombie_child() -> Child {
    let c = Command::new("true")
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn");
    let stat = format!("/proc/{}/stat", c.id());
    assert!(wait_until(T5, || {
        std::fs::read_to_string(&stat).is_ok_and(|s| s.contains(") Z"))
    }));
    c
}

/// REPAIR-5・#4525: 保持一覧へ入れる直前に掃除し、回収済みの子は数え直しで外れる。
#[test]
fn repair5_4525_retain_sweeps_reaped_helpers_before_push() {
    let s = Scratch::new("retain");
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::Silent));
    let (d, _src) = dialer(FakeSource::new(s.path(), &[]), &sp);
    let zs: Vec<Child> = (0..3).map(|_| zombie_child()).collect();
    let pids: Vec<u32> = zs.iter().map(Child::id).collect();
    for z in zs {
        d.push_retained_for_test(z);
    }
    d.retain(sleeper().stdin(Stdio::null()).spawn().expect("spawn"));
    assert_eq!(d.retained_len_for_test(), 1);
    for pid in pids {
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }
    for c in d.lock_retained().iter_mut() {
        let _ = c.kill();
    }
    assert!(wait_until(T5, || d.sweep_retained() == 0));
}

/// REPAIR-5・#4525: dial の出口（`DialHelper::finish`）でも保持一覧を掃除する。
#[test]
fn repair5_4525_dial_exit_sweeps_reaped_retained_helpers() {
    let s = Scratch::new("exit");
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::Silent));
    let (d, _src) = dialer(FakeSource::new(s.path(), &[]), &sp);
    let zs: Vec<Child> = (0..2).map(|_| zombie_child()).collect();
    let pids: Vec<u32> = zs.iter().map(Child::id).collect();
    for z in zs {
        d.push_retained_for_test(z);
    }
    assert_eq!(d.retained_len_for_test(), 2);
    let own = Command::new("true")
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn");
    let mut h = DialHelper::new(&d, own);
    h.finish();
    assert_eq!(d.retained_len_for_test(), 0);
    for pid in pids {
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }
}

/// REPAIR-5・#4525: dialer の drop は、既に終了した保持中の子を回収する。
#[test]
fn repair5_4525_drop_reaps_exited_retained_helpers() {
    let s = Scratch::new("drop");
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::Silent));
    let (d, _src) = dialer(FakeSource::new(s.path(), &[]), &sp);
    let z = zombie_child();
    let pid = z.id();
    d.push_retained_for_test(z);
    drop(d);
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
}

// ---- #4546: 回収できない helper の保持・上限超過・満杯の拒否の観測（CRI-6・REPAIR-4・REPAIR-5）----

use crate::streaming::connection_observer::tests::Collect;
use fandhe_container_core::observability::{OpName, OpRecorder};

fn tele_dialer(
    s: &Scratch,
    ids: &[&str],
) -> (
    PodNetnsDialer,
    std::sync::Arc<FakeSpawner>,
    std::sync::Arc<FakeSource>,
    std::sync::Arc<OpRecorder>,
    Collect,
) {
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::Silent));
    let (d, src) = dialer(FakeSource::new(s.path(), ids), &sp);
    let rec = std::sync::Arc::new(OpRecorder::new());
    let out = Collect::default();
    let sink = LineSink::spawn(Box::new(out.clone()), 64);
    let t = PodDialTelemetry::new(std::sync::Arc::clone(&rec), sink).expect("telemetry");
    (d.with_telemetry(t), sp, src, rec, out)
}

fn pf_line(op: &str, reason: &str, count: u64) -> String {
    format!(
        "{{\"event\":\"cri_port_forward_helper\",\"op\":\"{op}\",\"outcome\":\"error\",\"reason\":\"{reason}\",\"count\":{count}}}"
    )
}

fn counts(rec: &OpRecorder, op: &str) -> Option<(u64, u64)> {
    rec.snapshot_op(&OpName::new(op).expect("name"))
        .map(|s| (s.success(), s.failure()))
}

fn kill_all(d: &PodNetnsDialer) {
    for c in d.lock_retained().iter_mut() {
        let _ = c.kill();
    }
    assert!(wait_until(T5, || d.sweep_retained() == 0));
}

/// CRI-6・REPAIR-4・#4546: 保持 4 回で件数が 4、行は累計 1・2・4 の 3 本だけ（3 回目は出ない）で pid を含まない。
#[test]
fn cri6_repair4_4546_retain_records_and_log_scales_lines() {
    let s = Scratch::new("tele-retain");
    let (d, _sp, _src, rec, out) = tele_dialer(&s, &[]);
    let mut pids = Vec::new();
    for _ in 0..4 {
        let c = sleeper().stdin(Stdio::null()).spawn().expect("spawn");
        pids.push(c.id().to_string());
        d.retain(c);
    }
    assert_eq!(counts(&rec, OP_PF_HELPER_RETAINED), Some((0, 4)));
    assert_eq!(counts(&rec, OP_PF_RETAINED_OVER_LIMIT), None);
    assert_eq!(counts(&rec, OP_PF_RETAINED_FULL), None);
    out.wait_lines(3);
    assert_eq!(
        out.lines(),
        vec![
            pf_line(OP_PF_HELPER_RETAINED, REASON_HELPER_UNREAPED, 1),
            pf_line(OP_PF_HELPER_RETAINED, REASON_HELPER_UNREAPED, 2),
            pf_line(OP_PF_HELPER_RETAINED, REASON_HELPER_UNREAPED, 4),
        ]
    );
    for l in out.lines() {
        for pid in &pids {
            assert!(!l.contains(&format!(":{pid}")) && !l.contains(&format!("\"{pid}\"")));
        }
    }
    kill_all(&d);
}

/// REPAIR-5・#4546: 保持数が上限を超えた回は、保持と上限超過の両方に数える。
#[test]
fn repair5_4546_over_limit_counts_when_retained_exceeds_max() {
    let s = Scratch::new("tele-over");
    let (d, _sp, _src, rec, out) = tele_dialer(&s, &[]);
    for _ in 0..MAX_RETAINED_DIAL_HELPERS {
        d.push_retained_for_test(sleeper().stdin(Stdio::null()).spawn().expect("spawn"));
    }
    d.retain(sleeper().stdin(Stdio::null()).spawn().expect("spawn"));
    assert_eq!(d.retained_len_for_test(), MAX_RETAINED_DIAL_HELPERS + 1);
    assert_eq!(counts(&rec, OP_PF_HELPER_RETAINED), Some((0, 1)));
    assert_eq!(counts(&rec, OP_PF_RETAINED_OVER_LIMIT), Some((0, 1)));
    out.wait_lines(2);
    assert_eq!(
        out.lines(),
        vec![
            pf_line(OP_PF_HELPER_RETAINED, REASON_HELPER_UNREAPED, 1),
            pf_line(OP_PF_RETAINED_OVER_LIMIT, REASON_RETAINED_OVER_LIMIT, 1),
        ]
    );
    kill_all(&d);
}

/// CRI-6・REPAIR-4・#4546: 満杯の拒否 4 回で件数が 4、行は累計 1・2・4 の 3 本で port・pid を含まない。
#[test]
fn cri6_repair4_4546_full_rejection_records_and_lines_have_no_port() {
    let s = Scratch::new("tele-full");
    let (d, sp, src, rec, out) = tele_dialer(&s, &["a"]);
    for _ in 0..MAX_RETAINED_DIAL_HELPERS {
        d.push_retained_for_test(sleeper().stdin(Stdio::null()).spawn().expect("spawn"));
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    for _ in 0..4 {
        assert_eq!(
            err_of(d.dial(&pod("a"), port, T5)),
            (
                CriErrorCode::ResourceExhausted,
                MSG_RETAINED_FULL.to_owned()
            )
        );
    }
    assert_eq!(counts(&rec, OP_PF_RETAINED_FULL), Some((0, 4)));
    assert_eq!(counts(&rec, OP_PF_HELPER_RETAINED), None);
    assert_eq!(sp.spawns.load(Ordering::SeqCst), 0);
    assert_eq!(src.calls.load(Ordering::SeqCst), 0);
    out.wait_lines(3);
    assert_eq!(
        out.lines(),
        vec![
            pf_line(OP_PF_RETAINED_FULL, REASON_RETAINED_FULL, 1),
            pf_line(OP_PF_RETAINED_FULL, REASON_RETAINED_FULL, 2),
            pf_line(OP_PF_RETAINED_FULL, REASON_RETAINED_FULL, 4),
        ]
    );
    for l in out.lines() {
        assert!(!l.contains(&port.to_string()), "{l}");
    }
    kill_all(&d);
}

/// REPAIR-4・#4546: 操作名は検証を通り、観測なしの dialer でも保持は panic しない。
#[test]
fn repair4_4546_op_names_are_valid_and_no_telemetry_is_noop() {
    for n in [
        OP_PF_HELPER_RETAINED,
        OP_PF_RETAINED_OVER_LIMIT,
        OP_PF_RETAINED_FULL,
    ] {
        assert!(OpName::new(n).is_ok(), "{n}");
    }
    let s = Scratch::new("tele-none");
    let sp = std::sync::Arc::new(FakeSpawner::new(Reply::Silent));
    let (d, _src) = dialer(FakeSource::new(s.path(), &[]), &sp);
    d.retain(sleeper().stdin(Stdio::null()).spawn().expect("spawn"));
    assert_eq!(d.retained_len_for_test(), 1);
    kill_all(&d);
}
