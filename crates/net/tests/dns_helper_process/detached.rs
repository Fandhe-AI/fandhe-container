//! 切り離し起動・記録・pidfd 経由の停止の結合試験（Linux のみ。NET-5・NET-7・REPAIR-5・SEC-1・#3070）。
//!
//! `dns_helper_process` の一部。ヘルパーは試験バイナリ自身の再実行（段 1 `--dns-helper-detach`・段 2
//! `--dns-helper-stage2`）で、ループバックの `127.0.0.1:0` のみを使い root を要さない。待ちはすべて期限つき。

use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, UdpSocket};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_net::dns_helper::detach::{
    ARG_DETACH, ARG_NONCE, ARG_STAGE2, DNS_HELPER_ACK_TIMEOUT, DnsHelperStopRequest, NoStopRequest,
    RequestOutcome, StopOutcome, spawn_detached_dns_helper, stop_recorded_dns_helper,
};
use fandhe_container_net::dns_helper::identity::read_identity;
use fandhe_container_net::dns_helper::record::{DnsHelperRecord, HelperNonce};
use fandhe_container_net::dns_helper::{DnsListenAddr, READY_TIMEOUT_DEFAULT};
use fandhe_container_net::error::NetErrorCode;
use fandhe_container_net::instrument::NoopNetOpRecorder;
use fandhe_container_net::network::NetworkName;
use fandhe_container_net::network_store::{NetworkDefinition, NetworkStore};

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("fc-dnsh-detach-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&p)
            .expect("tmp");
        Tmp(p)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `/proc/<pid>/stat` の (ppid, session)。
fn ppid_sid(pid: u32) -> (u32, u32) {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat");
    let rest = raw.rsplit_once(')').expect("comm").1;
    let f: Vec<&str> = rest.split_whitespace().collect();
    (f[1].parse().expect("ppid"), f[3].parse().expect("sid"))
}

/// プロセスが消える（ゾンビ含む。回収は init か subreaper が行う）のを期限つきで待つ。
fn gone(pid: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => return true,
            Ok(s)
                if s.rsplit_once(')')
                    .is_some_and(|(_, r)| r.trim_start().starts_with('Z')) =>
            {
                return true;
            }
            Ok(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    false
}

fn notimp(target: std::net::SocketAddrV4) -> bool {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client");
    client
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let mut q = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    let mut buf = [0u8; 600];
    for _ in 0..20 {
        client.send_to(&q, target).expect("send");
        if let Ok((n, _)) = client.recv_from(&mut buf) {
            return buf.get(..n) == Some(&[0xAB, 0xCD, 0x81, 0x04, 0, 0, 0, 0, 0, 0, 0, 0][..]);
        }
    }
    false
}

/// 試験用の停止要求: SIGTERM（既定動作で終了する）を `kill` コマンドで送り、要求を送ったことにする。
struct TermRequest;
impl DnsHelperStopRequest for TermRequest {
    fn request(&self, record: &DnsHelperRecord) -> RequestOutcome {
        let ok = Command::new("kill")
            .arg(record.identity().pid.to_string())
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            RequestOutcome::Sent
        } else {
            RequestOutcome::Unavailable
        }
    }
}

fn setup(tmp: &Tmp) -> (NetworkStore, NetworkName) {
    let store = NetworkStore::open(&tmp.0).expect("open");
    store
        .create(&NetworkDefinition::pasta("dnsh").expect("def"))
        .expect("create");
    (store, NetworkName::new("dnsh").expect("name"))
}

/// 段 1・段 2 としての再実行の引数か。
pub fn is_helper_arg(a: &std::ffi::OsStr) -> bool {
    a == ARG_DETACH || a == ARG_STAGE2
}

pub fn run(exe: &Path) {
    lifecycle(exe);
    stop_on_request(exe);
    ack_timeout(exe);
}

/// 切り離し起動 → 記録 → 二重起動の拒否 → 古い記録は何も送らない → 記録で停止（SIGKILL）。
fn lifecycle(exe: &Path) {
    let tmp = Tmp::new("life");
    let (store, name) = setup(&tmp);
    let g = store.lock_global_exclusive().expect("global");
    let n = g.lock_network(&name).expect("net");
    let listen = DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("listen");
    let h = spawn_detached_dns_helper(&n, exe, listen, READY_TIMEOUT_DEFAULT, &NoopNetOpRecorder)
        .expect("spawn");
    let pid = h.identity.pid;

    // 親から切り離されている: 親は試験プロセスでなく、セッションも別。
    let (ppid, sid) = ppid_sid(pid);
    let (_, my_sid) = ppid_sid(std::process::id());
    assert_ne!(ppid, std::process::id(), "helper must not be our child");
    assert_ne!(sid, my_sid, "helper must be in a new session");

    // 記録は実際のプロセスの値と一致し、意図記録は消えている。
    let rec = n.read_dns_helper().expect("read").expect("record");
    assert_eq!(rec.identity(), &h.identity);
    assert_eq!(&read_identity(pid).expect("identity"), rec.identity());
    assert_eq!(n.read_dns_helper_intent().expect("intent"), None);
    assert!(notimp(h.listen), "detached helper must answer");

    // 二重起動はしない。
    let e = spawn_detached_dns_helper(&n, exe, listen, READY_TIMEOUT_DEFAULT, &NoopNetOpRecorder)
        .expect_err("second spawn");
    assert_eq!(e.code(), NetErrorCode::AlreadyExists);

    // 開始時刻が違う記録（pid の再利用の想定）には何も送らず、記録だけを消す。
    let mut stale_id = rec.identity().clone();
    stale_id.start_time_ticks += 1;
    let stale = DnsHelperRecord::new(stale_id, rec.nonce().clone(), rec.listen()).expect("stale");
    n.remove_dns_helper().expect("rm");
    n.write_dns_helper(&stale).expect("write stale");
    assert_eq!(
        stop_recorded_dns_helper(&n, &NoStopRequest, &NoopNetOpRecorder).expect("stop"),
        StopOutcome::StaleRecord
    );
    assert_eq!(n.read_dns_helper().expect("read"), None);
    assert!(notimp(h.listen), "a stale record must not stop the helper");

    // 正しい記録で停止（制御 UDS が無いので SIGKILL の段）。
    n.write_dns_helper(&rec).expect("write");
    let t = Instant::now();
    assert_eq!(
        stop_recorded_dns_helper(&n, &NoStopRequest, &NoopNetOpRecorder).expect("stop"),
        StopOutcome::Killed
    );
    assert!(t.elapsed() < Duration::from_secs(4));
    assert!(gone(pid), "helper must be gone");
    assert_eq!(n.read_dns_helper().expect("read"), None);
    assert_eq!(
        stop_recorded_dns_helper(&n, &NoStopRequest, &NoopNetOpRecorder).expect("stop"),
        StopOutcome::NoRecord
    );
    drop(n);
    drop(g);
}

/// 停止要求が通れば、猶予内に自分で終了し SIGKILL は不要。
fn stop_on_request(exe: &Path) {
    let tmp = Tmp::new("req");
    let (store, name) = setup(&tmp);
    let g = store.lock_global_exclusive().expect("global");
    let n = g.lock_network(&name).expect("net");
    let listen = DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("listen");
    let h = spawn_detached_dns_helper(&n, exe, listen, READY_TIMEOUT_DEFAULT, &NoopNetOpRecorder)
        .expect("spawn");
    let t = Instant::now();
    assert_eq!(
        stop_recorded_dns_helper(&n, &TermRequest, &NoopNetOpRecorder).expect("stop"),
        StopOutcome::StoppedOnRequest
    );
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "must finish within the grace"
    );
    assert!(gone(h.identity.pid));
    drop(n);
    drop(g);
}

/// ack を返さなければ、段 2 は bind せずに約 2 秒で自分から終了する（D14 (ii)）。
fn ack_timeout(exe: &Path) {
    let nonce = HelperNonce::generate().expect("nonce");
    let mut child = Command::new(exe)
        .args([
            ARG_STAGE2,
            "--listen",
            "127.0.0.1:0",
            ARG_NONCE,
            nonce.as_str(),
        ])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn stage 2");
    let _stdin = child.stdin.take().expect("stdin");
    let mut out = BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    out.read_line(&mut line).expect("ident");
    assert!(line.starts_with("IDENT "), "{line:?}");
    let t = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            break s;
        }
        assert!(
            t.elapsed() < Duration::from_secs(6),
            "helper must exit by itself"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let waited = t.elapsed();
    assert!(!status.success());
    assert!(
        waited >= DNS_HELPER_ACK_TIMEOUT - Duration::from_millis(300),
        "{waited:?}"
    );
    let mut rest = String::new();
    out.read_to_string(&mut rest).expect("rest");
    assert_eq!(rest, "", "must not print READY without ack");
}
