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
    ARG_DETACH, ARG_NONCE, ARG_STAGE2, DNS_HELPER_ACK_TIMEOUT, DnsHelperStopRequest,
    IntentRecovery, MAX_RECOVERY_CANDIDATES, NoStopRequest, RequestOutcome, StopOutcome,
    recover_dns_helper_intent, spawn_detached_dns_helper, stop_recorded_dns_helper,
};
use fandhe_container_net::dns_helper::identity::read_identity;
use fandhe_container_net::dns_helper::record::{DnsHelperIntent, DnsHelperRecord, HelperNonce};
use fandhe_container_net::dns_helper::{DnsListenAddr, READY_TIMEOUT_DEFAULT};
use fandhe_container_net::error::NetErrorCode;
use fandhe_container_net::instrument::{
    NetOpKind, NetOpOutcome, NetOpRecorder, NetOpSample, NoopNetOpRecorder,
};
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
        let mut kill = Command::new("kill");
        kill.arg(record.identity().pid.to_string());
        // 期限なしの `status()` を避ける。期限切れ・spawn 失敗は `Unavailable` として理由を残す（REPAIR-5・#3409）。
        let ok = match crate::reap::run_within(&mut kill, crate::reap::reap_within()) {
            Ok(s) => s.success(),
            Err(e) => {
                eprintln!("TermRequest: {e}");
                false
            }
        };
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
    recover_intent(exe);
    recover_intent_by_nonce(exe);
    start_failure_records(exe);
    stopped_stage2_is_reaped(exe);
    spawn_write_count(exe);
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
    // IDENT 行の読み取りにも期限を設ける（子が送らず止まっても試験が無期限に待たない。REPAIR-5）。
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let r = out.read_line(&mut line).map(|_| line);
        let _ = tx.send(r);
        out
    });
    let line = match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(r) => r.expect("ident"),
        Err(_) => {
            crate::reap::reap_or_report(&mut child, crate::reap::reap_within());
            panic!("helper did not print its identity line before the deadline");
        }
    };
    let mut out = reader.join().expect("reader");
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

/// 起動窓の意図記録の回収（D14 (iv)。NET-5・NET-7・REPAIR-5・REPAIR-12・#3070）。
/// nonce 一致だけを停止し、不一致は残し、確定記録があれば意図記録だけを消し、候補の上限超過では意図記録を保持する。
fn recover_intent(exe: &Path) {
    let tmp = Tmp::new("recover");
    let (store, name) = setup(&tmp);
    let g = store.lock_global_exclusive().expect("global");
    let n = g.lock_network(&name).expect("net");
    let listen = DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("listen");
    let h = spawn_detached_dns_helper(&n, exe, listen, READY_TIMEOUT_DEFAULT, &NoopNetOpRecorder)
        .expect("spawn");
    let pid = h.identity.pid;
    let rec = n.read_dns_helper().expect("read").expect("record");
    let intent_of = |nonce: HelperNonce| DnsHelperIntent::new(name.clone(), nonce, rec.listen());

    // 意図記録なし。
    assert_eq!(
        recover_dns_helper_intent(&n, &mut std::iter::once(pid), &NoopNetOpRecorder)
            .expect("recover"),
        IntentRecovery::NoIntent
    );

    // 確定記録があれば意図記録だけを消し、プロセスには触れない。
    n.write_dns_helper_intent(&intent_of(rec.nonce().clone()))
        .expect("intent");
    assert_eq!(
        recover_dns_helper_intent(&n, &mut std::iter::once(pid), &NoopNetOpRecorder)
            .expect("recover"),
        IntentRecovery::IntentDiscarded
    );
    assert_eq!(n.read_dns_helper_intent().expect("intent"), None);
    assert!(notimp(h.listen), "a confirmed record must keep the helper");

    // 確定記録を外す（起動窓で記録が無い状態）。
    n.remove_dns_helper().expect("rm");

    // nonce が一致しない子は残し、意図記録は消す。
    n.write_dns_helper_intent(&intent_of(HelperNonce::generate().expect("nonce")))
        .expect("intent");
    assert_eq!(
        recover_dns_helper_intent(&n, &mut std::iter::once(pid), &NoopNetOpRecorder)
            .expect("recover"),
        IntentRecovery::Recovered { stopped: 0 }
    );
    assert_eq!(n.read_dns_helper_intent().expect("intent"), None);
    assert!(notimp(h.listen), "a different nonce must not be stopped");

    // 候補の上限を超えたら走査を終えていないので意図記録を保持する。
    n.write_dns_helper_intent(&intent_of(rec.nonce().clone()))
        .expect("intent");
    let mut many = std::iter::repeat_n(0u32, MAX_RECOVERY_CANDIDATES + 1);
    let e = recover_dns_helper_intent(&n, &mut many, &NoopNetOpRecorder).expect_err("too many");
    assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
    assert!(n.read_dns_helper_intent().expect("intent").is_some());
    assert!(
        notimp(h.listen),
        "an incomplete scan must not stop anything"
    );

    // 同一性つきの意図記録は、候補なしでも同一性で帰属して止める。開始時刻が違えば何も送らない（#3344）。
    let mut reused = h.identity.clone();
    reused.start_time_ticks += 1;
    n.remove_dns_helper_intent().expect("rm intent");
    n.write_dns_helper_intent(
        &intent_of(rec.nonce().clone())
            .with_identity(reused)
            .expect("identity"),
    )
    .expect("intent");
    assert_eq!(
        recover_dns_helper_intent(&n, &mut std::iter::empty(), &NoopNetOpRecorder)
            .expect("recover"),
        IntentRecovery::Recovered { stopped: 0 }
    );
    assert!(notimp(h.listen), "a reused pid must not be stopped");
    n.write_dns_helper_intent(
        &intent_of(rec.nonce().clone())
            .with_identity(h.identity.clone())
            .expect("identity"),
    )
    .expect("intent");
    assert_eq!(
        recover_dns_helper_intent(&n, &mut std::iter::empty(), &NoopNetOpRecorder)
            .expect("recover"),
        IntentRecovery::Recovered { stopped: 1 }
    );
    assert!(gone(pid), "the recorded identity must be stopped");
    assert_eq!(n.read_dns_helper_intent().expect("intent"), None);
    drop(n);
    drop(g);
}

/// 同一性の追記が無い従来の経路（#3070）: nonce が一致する子だけを停止し、意図記録を消す。
fn recover_intent_by_nonce(exe: &Path) {
    let tmp = Tmp::new("recover-nonce");
    let (store, name) = setup(&tmp);
    let g = store.lock_global_exclusive().expect("global");
    let n = g.lock_network(&name).expect("net");
    let listen = DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("listen");
    let h = spawn_detached_dns_helper(&n, exe, listen, READY_TIMEOUT_DEFAULT, &NoopNetOpRecorder)
        .expect("spawn");
    let pid = h.identity.pid;
    let rec = n.read_dns_helper().expect("read").expect("record");
    let intent_of = |nonce: HelperNonce| DnsHelperIntent::new(name.clone(), nonce, rec.listen());
    n.remove_dns_helper().expect("rm");
    n.write_dns_helper_intent(&intent_of(rec.nonce().clone()))
        .expect("intent");
    // nonce が一致する子だけを停止し、意図記録を消す。
    assert_eq!(
        recover_dns_helper_intent(&n, &mut [0u32, pid].into_iter(), &NoopNetOpRecorder)
            .expect("recover"),
        IntentRecovery::Recovered { stopped: 1 }
    );
    assert!(gone(pid), "the matching helper must be stopped");
    assert_eq!(n.read_dns_helper_intent().expect("intent"), None);
    drop(n);
    drop(g);
}

/// 起動失敗時の意図記録（NET-5・REPAIR-5・#3070）。`spawn` 自体の失敗は子が存在しないので消し、段 1 の起動後に
/// 終了を確認できない失敗（識別行なし・段 1 の異常終了）は nonce の再試行に要るので残す。
fn start_failure_records(_exe: &Path) {
    let tmp = Tmp::new("startfail");
    let (store, name) = setup(&tmp);
    let g = store.lock_global_exclusive().expect("global");
    let n = g.lock_network(&name).expect("net");
    let listen = DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("listen");
    let ready = Duration::from_secs(2);

    // 実行できないパス: spawn が失敗する（子は無い）→ 意図記録は消える。
    let missing = tmp.0.join("no-such-program");
    let e = spawn_detached_dns_helper(&n, &missing, listen, ready, &NoopNetOpRecorder)
        .expect_err("spawn fails");
    assert_ne!(e.code(), NetErrorCode::AlreadyExists);
    assert_eq!(n.read_dns_helper_intent().expect("intent"), None);

    // 識別行を出さずに終了するプログラム: 起動後の失敗 → 意図記録を残す。
    for prog in ["/bin/true", "/bin/false"] {
        if !Path::new(prog).exists() {
            continue;
        }
        let e = spawn_detached_dns_helper(&n, Path::new(prog), listen, ready, &NoopNetOpRecorder)
            .expect_err("no identity line");
        assert!(
            e.message().contains("intent record kept"),
            "{prog}: {}",
            e.message()
        );
        let kept = n.read_dns_helper_intent().expect("intent");
        assert!(kept.is_some(), "{prog}: intent must be kept");
        assert_eq!(n.read_dns_helper().expect("record"), None);
        // 回収（候補なし）で意図記録が消え、再び起動できる状態に戻る。
        assert_eq!(
            recover_dns_helper_intent(&n, &mut std::iter::empty(), &NoopNetOpRecorder)
                .expect("recover"),
            IntentRecovery::Recovered { stopped: 0 }
        );
        assert_eq!(n.read_dns_helper_intent().expect("intent"), None);
    }
    drop(n);
    drop(g);
}

/// 開いている fd の数（`/proc/self/fd`）。
fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").expect("fd dir").count()
}

/// 識別行を出す前に SIGSTOP された段 2（NET-5・REPAIR-5・#3070）。読み取りは poll と絶対期限で終わり
/// （読み手スレッドが残らない）、段 1 が知らせた pid の pidfd で SIGKILL して回収し、意図記録を消す。
/// 試験用の偽の段 1 は `SPAWN <pid>` を出して終了し、段 2 相当の `sh` は stdout を持ったまま自分を止める。
fn stopped_stage2_is_reaped(_exe: &Path) {
    let tmp = Tmp::new("stopped");
    let (store, name) = setup(&tmp);
    let g = store.lock_global_exclusive().expect("global");
    let n = g.lock_network(&name).expect("net");
    let listen = DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("listen");
    let script = tmp.0.join("fake-stage1.sh");
    let pidfile = tmp.0.join("stage2.pid");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nsh -c 'kill -STOP $$; sleep 30' sh --nonce \"$5\" &\necho \"$!\" > '{}'\necho \"SPAWN $!\"\n",
            pidfile.display()
        ),
    )
    .expect("script");
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .expect("chmod");

    let fds_before = open_fd_count();
    let t = Instant::now();
    let e = spawn_detached_dns_helper(
        &n,
        &script,
        listen,
        Duration::from_secs(2),
        &NoopNetOpRecorder,
    )
    .expect_err("no identity line");
    let took = t.elapsed();
    assert_eq!(e.code(), NetErrorCode::Timeout, "{}", e.message());
    // 識別行の期限（2 秒）の後、停止 → 回収の猶予（高々 4 秒）で戻る。
    assert!(took < Duration::from_secs(9), "{took:?}");
    assert_eq!(
        open_fd_count(),
        fds_before,
        "no fd or reader thread may remain"
    );
    assert_eq!(n.read_dns_helper_intent().expect("intent"), None);
    let pid: u32 = std::fs::read_to_string(&pidfile)
        .expect("pid file")
        .trim()
        .parse()
        .expect("pid");
    assert!(gone(pid), "the stopped stage 2 must be killed");
    drop(n);
    drop(g);
}

/// 記録先に渡されたサンプルを溜める。
#[derive(Default)]
struct Collect(std::sync::Mutex<Vec<NetOpSample>>);
impl NetOpRecorder for Collect {
    fn record_net_op(&self, sample: &NetOpSample) {
        self.0.lock().expect("lock").push(*sample);
    }
}

/// #3414: `SPAWN` 行の時点で同一性を記録しても、成功した起動の `NetworkStoreDnsHelperWrite` は 3 回
/// （意図記録の新規・同一性つきへの置き換え 1 回・`dns-helper`）のまま。レイテンシは PR 本文用に stderr へ出す。
fn spawn_write_count(exe: &Path) {
    let tmp = Tmp::new("wcount");
    let rec = std::sync::Arc::new(Collect::default());
    let store = NetworkStore::open_with_recorder(&tmp.0, rec.clone()).expect("open");
    store
        .create(&NetworkDefinition::pasta("dnsh").expect("def"))
        .expect("create");
    let name = NetworkName::new("dnsh").expect("name");
    let g = store.lock_global_exclusive().expect("global");
    let n = g.lock_network(&name).expect("net");
    let listen = DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("listen");
    let h = spawn_detached_dns_helper(&n, exe, listen, READY_TIMEOUT_DEFAULT, &NoopNetOpRecorder)
        .expect("spawn");
    let lat: Vec<u128> = rec
        .0
        .lock()
        .expect("lock")
        .iter()
        .filter(|s| {
            s.kind() == NetOpKind::NetworkStoreDnsHelperWrite
                && s.outcome() == NetOpOutcome::Success
        })
        .map(|s| s.latency().as_micros())
        .collect();
    eprintln!(
        "dns_helper_process: dns_helper_write samples={} latencies_us={lat:?}",
        lat.len()
    );
    assert_eq!(lat.len(), 3, "intent, intent replace, dns-helper");
    assert_eq!(
        stop_recorded_dns_helper(&n, &NoStopRequest, &NoopNetOpRecorder).expect("stop"),
        StopOutcome::Killed
    );
    assert!(gone(h.identity.pid));
    drop(n);
    drop(g);
}
