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

use fandhe_container_net::dns_helper::control::frame::{
    ControlFrame, ControlMessage, ReloadGeneration,
};
use fandhe_container_net::dns_helper::control::{
    ControlStopRequest, ReloadOutcome, reload_dns_helper,
};
use fandhe_container_net::dns_helper::detach::{
    ARG_DETACH, ARG_NETWORK, ARG_NONCE, ARG_STAGE2, ARG_STATE_ROOT, DNS_HELPER_ACK_TIMEOUT,
    DnsHelperStopRequest, IntentRecovery, MAX_RECOVERY_CANDIDATES, NoStopRequest, RequestOutcome,
    StopOutcome, recover_dns_helper_intent, spawn_detached_dns_helper, stop_recorded_dns_helper,
};
use fandhe_container_net::dns_helper::identity::read_identity;
use fandhe_container_net::dns_helper::record::{DnsHelperIntent, DnsHelperRecord, HelperNonce};
use fandhe_container_net::dns_helper::{DnsListenAddr, READY_TIMEOUT_DEFAULT};
use fandhe_container_net::error::NetErrorCode;
use fandhe_container_net::instrument::{
    NetOpKind, NetOpOutcome, NetOpRecorder, NetOpSample, NoopNetOpRecorder,
};
use fandhe_container_net::netlink_route::IpPrefix;
use fandhe_container_net::network::{EndpointId, NetworkName};
use fandhe_container_net::network_store::{
    MemberId, MemberRecord, NetworkDefinition, NetworkStore,
};

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

/// 切り離し起動のヘルパーが DNS クエリに応答するか（名前の経路を持つので、未登録の名前には REFUSED を返す。#3071）。
fn answers(target: std::net::SocketAddrV4) -> bool {
    matches!(
        query_a(target, "example.com").map(|r| r.get(..4).map(<[u8]>::to_vec)),
        Some(Some(h)) if h == [0xAB, 0xCD, 0x81, 0x05]
    )
}

/// `name` の A クエリ（ID 0xABCD）を送り、最初に届いた応答のバイト列を返す（届かなければ None）。
fn query_a(target: std::net::SocketAddrV4, name: &str) -> Option<Vec<u8>> {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client");
    client
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let mut q = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        q.push(u8::try_from(label.len()).expect("label len"));
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    let mut buf = [0u8; 600];
    for _ in 0..20 {
        client.send_to(&q, target).expect("send");
        if let Ok((n, _)) = client.recv_from(&mut buf) {
            return buf.get(..n).map(<[u8]>::to_vec);
        }
    }
    None
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

/// 起動元（`spawn_detached_dns_helper` の呼び出し側）としての再実行の引数（`launcher_killed_after_spawn_line` 用）。
pub const ARG_LAUNCHER_CHILD: &str = "--launcher-child";

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
    launcher_killed_after_spawn_line(exe);
    control_reload(exe);
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
    assert!(answers(h.listen), "detached helper must answer");

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
    assert!(answers(h.listen), "a stale record must not stop the helper");

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
            ARG_STATE_ROOT,
            "/nonexistent-fandhe-state-root",
            ARG_NETWORK,
            "dnsh",
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
    assert!(answers(h.listen), "a confirmed record must keep the helper");

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
    assert!(answers(h.listen), "a different nonce must not be stopped");

    // 候補の上限を超えたら走査を終えていないので意図記録を保持する。
    n.write_dns_helper_intent(&intent_of(rec.nonce().clone()))
        .expect("intent");
    let mut many = std::iter::repeat_n(0u32, MAX_RECOVERY_CANDIDATES + 1);
    let e = recover_dns_helper_intent(&n, &mut many, &NoopNetOpRecorder).expect_err("too many");
    assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
    assert!(n.read_dns_helper_intent().expect("intent").is_some());
    assert!(
        answers(h.listen),
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
    assert!(answers(h.listen), "a reused pid must not be stopped");
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

/// 起動元の子モード（`--launcher-child <state_root> <program>`）。偽の段 1 `program` で
/// `spawn_detached_dns_helper` を呼び、識別行の待ちの途中で親に SIGKILL されることを前提にする。
/// 呼び出しが戻った時点で場面は不成立（起動元自身が期限切れで後始末して意図記録を消すため、回収の照合が
/// 緑に見える誤判定になる）なので、固有の終了コード 3 で終わる（REPAIR-4）。
pub fn launcher_child(args: Vec<std::ffi::OsString>) -> std::process::ExitCode {
    let (Some(root), Some(program)) = (args.get(2), args.get(3)) else {
        eprintln!("launcher_child: usage: --launcher-child <state_root> <program>");
        return std::process::ExitCode::from(2);
    };
    let store = NetworkStore::open(Path::new(root)).expect("open");
    let name = NetworkName::new("dnsh").expect("name");
    let g = store.lock_global_exclusive().expect("global");
    let n = g.lock_network(&name).expect("net");
    let listen = DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("listen");
    let r = spawn_detached_dns_helper(
        &n,
        Path::new(program),
        listen,
        READY_TIMEOUT_DEFAULT,
        &NoopNetOpRecorder,
    );
    match r {
        Ok(_) => eprintln!("launcher_child: spawn returned before being killed: Ok"),
        Err(e) => eprintln!(
            "launcher_child: spawn returned before being killed: {:?} {}",
            e.code(),
            e.message()
        ),
    }
    std::process::ExitCode::from(3)
}

/// 失敗時に起動元の子と段 2 相当を片付ける（プロセスを漏らさない。REPAIR-5）。
/// pid 番号への kill は後始末に限り、cmdline の `--nonce` の直後の引数が偽の段 1 の書いた nonce と
/// 完全一致したときだけ送る（pid 再利用で別の試験のプロセスを止めない。#3482）。帰属できなければ送らない。
/// 確認から kill までの再利用の窓は残るが、nonce は 128 bit の乱数で別プロセスに当たる確率は実質 0。
struct KillGuard {
    child: Option<std::process::Child>,
    stage2: PathBuf,
    nonce_file: PathBuf,
}
impl Drop for KillGuard {
    fn drop(&mut self) {
        if let Some(c) = self.child.as_mut() {
            crate::reap::reap_or_report(c, crate::reap::reap_within());
        }
        let Some(pid) = std::fs::read_to_string(&self.stage2)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
        else {
            return;
        };
        let nonce = std::fs::read_to_string(&self.nonce_file)
            .ok()
            .and_then(|s| HelperNonce::new(s.trim()).ok());
        if nonce.is_some_and(|n| cmdline_has_nonce(pid, &n)) {
            let mut kill = Command::new("kill");
            kill.args(["-KILL", &pid.to_string()]);
            let _ = crate::reap::run_within(&mut kill, crate::reap::reap_within());
        } else {
            eprintln!("kill guard: pid {pid} not attributed by nonce; not killing");
        }
    }
}

/// `/proc/<pid>/cmdline` に隣接する `--nonce`・`<nonce>` の引数対が完全一致であるか（読めなければ false）。
fn cmdline_has_nonce(pid: u32, nonce: &HelperNonce) -> bool {
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let args: Vec<&[u8]> = raw.split(|b| *b == 0).collect();
    args.windows(2)
        .any(|w| w[0] == b"--nonce" && w[1] == nonce.as_str().as_bytes())
}

/// `/proc/<pid>/stat` の状態文字。
fn proc_state(pid: u32) -> Option<char> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    raw.rsplit_once(')')?.1.trim_start().chars().next()
}

/// #3455（#3414 の残り。NET-5・NET-7・REPAIR-4・REPAIR-5・REPAIR-12）: 段 1 の `SPAWN <pid>` 行が識別行より先に
/// 届き、起動元が同一性を意図記録へ追記した後、識別行が届く前に起動元が SIGKILL されても、次の回収が
/// 記録した同一性で帰属して止める。回収は候補なしで呼び、帰属が cgroup 走査でなく記録から来たことを固定する。
fn launcher_killed_after_spawn_line(exe: &Path) {
    use std::os::unix::process::ExitStatusExt;
    let tmp = Tmp::new("killspawn");
    let (store, name) = setup(&tmp);
    let script = tmp.0.join("fake-stage1.sh");
    let pidfile = tmp.0.join("stage2.pid");
    let nonce_file = tmp.0.join("stage2.nonce");
    // 本体は複合コマンドにする（単一の `sleep` だと sh が exec して argv の nonce が消える）。
    // nonce は KillGuard の帰属用に、段 2 相当の起動前に書く（試験が早期に panic しても帰属できる）。
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$5\" > '{}'\nsh -c 'kill -STOP $$; sleep 30' sh --nonce \"$5\" &\necho \"$!\" > '{}'\necho \"SPAWN $!\"\nexit 0\n",
            nonce_file.display(),
            pidfile.display()
        ),
    )
    .expect("script");
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .expect("chmod");

    let child = Command::new(exe)
        .arg(ARG_LAUNCHER_CHILD)
        .arg(&tmp.0)
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn launcher child");
    let mut guard = KillGuard {
        child: Some(child),
        stage2: pidfile.clone(),
        nonce_file: nonce_file.clone(),
    };

    // 同一性つきの意図記録が現れるのを、起動元の ack 期限（2 秒）より短い期限で待つ。
    let intent_path = tmp.0.join("@networks/dnsh/dns-helper.intent");
    let deadline = Instant::now() + Duration::from_millis(1500);
    let recorded = loop {
        match std::fs::read(&intent_path) {
            Ok(bytes) => {
                let i = DnsHelperIntent::decode(&bytes).expect("decode intent");
                if let Some(id) = i.identity() {
                    break id.clone();
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("read intent: {e}"),
        }
        if Instant::now() >= deadline {
            let st = guard.child.as_mut().and_then(|c| c.try_wait().ok());
            panic!("intent record with identity did not appear in time; launcher status {st:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    let mut child = guard.child.take().expect("child");
    child.kill().expect("SIGKILL launcher");
    let status = match crate::reap::wait_within(&mut child, crate::reap::reap_within()) {
        Ok(s) => s,
        Err(e) => {
            guard.child = Some(child);
            panic!("launcher did not exit after SIGKILL: {e}");
        }
    };
    assert_eq!(
        status.signal(),
        Some(9),
        "launcher must die by our SIGKILL, not by itself (exit {:?}); see its stderr",
        status.code()
    );

    // 窓が本物だったこと: 同一性は段 2 相当の実値で、識別行は出ておらず（停止中）、確定記録は無い。
    let pid: u32 = std::fs::read_to_string(&pidfile)
        .expect("pid file")
        .trim()
        .parse()
        .expect("pid");
    assert_eq!(recorded.pid, pid);
    assert_eq!(read_identity(pid).expect("identity"), recorded);
    // KillGuard の帰属の自己照合: 書かれた nonce は意図記録のものと一致し、cmdline の対にだけ一致する。
    let written = HelperNonce::new(
        std::fs::read_to_string(&nonce_file)
            .expect("nonce file")
            .trim(),
    )
    .expect("written nonce");
    assert!(cmdline_has_nonce(pid, &written));
    assert!(!cmdline_has_nonce(
        pid,
        &HelperNonce::generate().expect("other nonce")
    ));
    let stop_deadline = Instant::now() + Duration::from_secs(5);
    while proc_state(pid) != Some('T') {
        assert!(
            Instant::now() < stop_deadline,
            "stage 2 stand-in must be stopped, state {:?}",
            proc_state(pid)
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // 起動元が死んだので flock はカーネルが解放済み。
    let g = store.lock_global_exclusive().expect("global");
    let n = g.lock_network(&name).expect("net");
    assert_eq!(
        n.read_dns_helper_intent()
            .expect("intent")
            .expect("kept")
            .identity(),
        Some(&recorded)
    );
    assert_eq!(n.read_dns_helper().expect("record"), None);
    assert_eq!(
        recover_dns_helper_intent(&n, &mut std::iter::empty(), &NoopNetOpRecorder)
            .expect("recover"),
        IntentRecovery::Recovered { stopped: 1 }
    );
    assert!(gone(pid), "the recorded identity must be stopped");
    assert_eq!(n.read_dns_helper_intent().expect("intent"), None);
    assert_eq!(
        recover_dns_helper_intent(&n, &mut std::iter::empty(), &NoopNetOpRecorder)
            .expect("recover"),
        IntentRecovery::NoIntent
    );
    // 起動できる状態に戻っている。
    let listen = DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("listen");
    let h = spawn_detached_dns_helper(&n, exe, listen, READY_TIMEOUT_DEFAULT, &NoopNetOpRecorder)
        .expect("respawn");
    assert_eq!(
        stop_recorded_dns_helper(&n, &NoStopRequest, &NoopNetOpRecorder).expect("stop"),
        StopOutcome::Killed
    );
    assert!(gone(h.identity.pid));
    drop(n);
    drop(g);
    drop(guard);
    eprintln!(
        "dns_helper_process: launcher_killed_after_spawn_line ok launcher_signal=9 stage2_state=T recovered_stopped=1 intent_after=none record_after=none"
    );
}

/// ネットワーク `dnsh` のメンバー記録（ID = コンテナ ID が DNS 名になる。10.89.0.`last`/24）。
fn member(id: &str, last: u8) -> MemberRecord {
    let token = format!("fandhe-net:dnsh:1:0:0/ep/{id}/g/00000000000000000000000000000001");
    MemberRecord::new(
        MemberId::new(id).expect("member id"),
        EndpointId::new(id).expect("endpoint"),
        IpPrefix::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 89, 0, last)), 24).expect("prefix"),
        &token,
        Path::new("/run/fc-test-ns"),
        (8, 9),
        &[],
    )
    .expect("member record")
}

/// A 応答の RCODE。
fn rcode(resp: &[u8]) -> Option<u8> {
    resp.get(3).map(|b| b & 0x0f)
}

/// 名前の A 応答のアドレス（NOERROR で answer 1 件のときだけ）。
fn a_record(target: std::net::SocketAddrV4, name: &str) -> Option<Ipv4Addr> {
    let r = query_a(target, name)?;
    if rcode(&r) != Some(0) || r.get(7) != Some(&1) {
        return None;
    }
    let tail: [u8; 4] = r.get(r.len().checked_sub(4)?..)?.try_into().ok()?;
    Some(Ipv4Addr::from(tail))
}

/// 制御 UDS: 起動時の読み込み・`Reload` の ack・壊れた記録でも前の状態を保つ・メンバー削除の反映・
/// `Stop` による停止と socket の後始末・残った socket の起動時の除去（NET-5・PLUG-12・REPAIR-5・#3071）。
fn control_reload(exe: &Path) {
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
    let tmp = Tmp::new("ctl");
    let (store, name) = setup(&tmp);
    let g = store.lock_global_exclusive().expect("global");
    let n = g.lock_network(&name).expect("net");
    let ctl = tmp.0.join("@networks/dnsh/dns.ctl");

    // ヘルパーが居なければ送るものがない。
    assert_eq!(
        reload_dns_helper(&n, &NoopNetOpRecorder).expect("reload"),
        ReloadOutcome::NotRunning
    );

    // 起動前に書いたメンバーは、起動時の初回読み込みで答える。`_` を含む ID は DNS 名にできず登録されない。
    n.commit_member(&member("web", 2)).expect("web");
    n.commit_member(&member("my_app", 9)).expect("my_app");
    // 前回の残りの制御 socket（listener は無い）は起動時に消される。
    drop(std::os::unix::net::UnixListener::bind(&ctl).expect("stale socket"));
    assert!(ctl.exists());
    let listen = DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("listen");
    let h = spawn_detached_dns_helper(&n, exe, listen, READY_TIMEOUT_DEFAULT, &NoopNetOpRecorder)
        .expect("spawn");
    let meta = std::fs::symlink_metadata(&ctl).expect("ctl");
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
    assert_eq!(a_record(h.listen, "web"), Some(Ipv4Addr::new(10, 89, 0, 2)));
    assert_eq!(rcode(&query_a(h.listen, "my_app").expect("resp")), Some(5));

    // Reload: 追加したメンバーが引けるようになる（ack の後に答える）。
    n.commit_member(&member("db", 3)).expect("db");
    let t = Instant::now();
    assert_eq!(
        reload_dns_helper(&n, &NoopNetOpRecorder).expect("reload"),
        ReloadOutcome::Loaded
    );
    assert!(t.elapsed() < Duration::from_secs(2));
    assert_eq!(a_record(h.listen, "db"), Some(Ipv4Addr::new(10, 89, 0, 3)));
    assert_eq!(a_record(h.listen, "web"), Some(Ipv4Addr::new(10, 89, 0, 2)));

    // 壊れた記録があれば Reload は失敗し、前のレジストリは保たれる。
    let junk = tmp.0.join("@networks/dnsh/members/zz");
    std::fs::write(&junk, b"junk").expect("junk");
    std::fs::set_permissions(&junk, std::fs::Permissions::from_mode(0o600)).expect("mode");
    let e = reload_dns_helper(&n, &NoopNetOpRecorder).expect_err("corrupt");
    assert_eq!(e.code(), NetErrorCode::DataLoss);
    assert_eq!(a_record(h.listen, "db"), Some(Ipv4Addr::new(10, 89, 0, 3)));
    std::fs::remove_file(&junk).expect("rm junk");

    // メンバーを消して Reload すると、その名前は引けなくなる（REFUSED）。
    assert!(
        n.remove_member(&MemberId::new("web").expect("id"))
            .expect("rm")
    );
    assert_eq!(
        reload_dns_helper(&n, &NoopNetOpRecorder).expect("reload"),
        ReloadOutcome::Loaded
    );
    assert_eq!(rcode(&query_a(h.listen, "web").expect("resp")), Some(5));
    assert_eq!(a_record(h.listen, "db"), Some(Ipv4Addr::new(10, 89, 0, 3)));

    // 実在しない世代の Loaded を返さない相手（生のフレームで Reload を直接送る）への応答は同じ世代。
    let raw = std::os::unix::net::UnixStream::connect(&ctl).expect("connect");
    raw.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("t");
    let gen_ = ReloadGeneration::new(0xFEED).expect("gen");
    let mut w = &raw;
    ControlFrame::encode(ControlMessage::Reload(gen_))
        .write_to(&mut w)
        .expect("write");
    let mut r = &raw;
    assert_eq!(
        ControlFrame::read_from(&mut r).expect("loaded"),
        ControlMessage::Loaded(gen_)
    );
    drop(raw);

    // Stop: 猶予内に自分で終了し、socket と記録が消える。
    let t = Instant::now();
    assert_eq!(
        stop_recorded_dns_helper(&n, &ControlStopRequest::new(&n), &NoopNetOpRecorder)
            .expect("stop"),
        StopOutcome::StoppedOnRequest
    );
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "must finish within the grace"
    );
    assert!(gone(h.identity.pid));
    assert!(!ctl.exists(), "the control socket must be removed");
    assert_eq!(n.read_dns_helper().expect("read"), None);
    assert_eq!(
        reload_dns_helper(&n, &NoopNetOpRecorder).expect("reload"),
        ReloadOutcome::NotRunning
    );
    drop(n);
    drop(g);
    println!("dns_helper_process: control_reload ok registered=db refused=web stop=on_request");
}

/// 実機前提（`--ignored`・root と util-linux の `setpriv`）: 別 uid の接続は、フレームを読まれずに切断される
/// （PLUG-12・NET-5・#3071）。
///
/// 非 root（uid 65534）の子にストアとヘルパーを作らせ、root の親が DAC を越えて `dns.ctl` へ接続して `Reload` を送る。
/// `Loaded` も `Error` も返らず切断され、その後も同じ uid からの `Reload` は成功し、`Stop` で止まる。
/// root でない・`setpriv` が無い場合は理由つきで ignored を出して成功終了する（AGENTS.md に実行方法）。
pub fn foreign_uid(exe: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let uid_line = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("Uid:")).map(str::to_owned))
        .unwrap_or_default();
    let is_root = uid_line.split_whitespace().nth(2) == Some("0");
    let have_setpriv = Command::new("setpriv")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !is_root || !have_setpriv {
        println!(
            "dns_helper_process: control_foreign_uid ignored (needs root and setpriv: root={is_root} setpriv={have_setpriv})"
        );
        return;
    }
    let tmp = Tmp::new("foreign");
    let nobody = 65534u32;
    std::os::unix::fs::chown(&tmp.0, Some(nobody), Some(nobody)).expect("chown tmp");
    // 子（uid 65534）が実行できるよう、試験バイナリを専用ディレクトリへ複製する。
    let bin = tmp.0.join("test-bin");
    std::fs::copy(exe, &bin).expect("copy exe");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    std::os::unix::fs::chown(&bin, Some(nobody), Some(nobody)).expect("chown bin");
    let mut child = Command::new("setpriv")
        .args(["--reuid=65534", "--regid=65534", "--clear-groups"])
        .arg(&bin)
        .arg(ARG_FOREIGN_UID_CHILD)
        .arg(&tmp.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn child");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut out = BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    out.read_line(&mut line).expect("child ready");
    assert_eq!(line.trim(), "CHILD-READY", "child did not start the helper");

    // root は DAC を越えて接続できるが、ヘルパーは uid 不一致として読まずに切断する。
    let ctl = tmp.0.join("@networks/dnsh/dns.ctl");
    let raw = std::os::unix::net::UnixStream::connect(&ctl).expect("root connect");
    raw.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("t");
    let mut w = &raw;
    let _ = ControlFrame::encode(ControlMessage::Reload(
        ReloadGeneration::new(1).expect("gen"),
    ))
    .write_to(&mut w);
    let mut r = &raw;
    let mut one = [0u8; 1];
    match r.read(&mut one) {
        Ok(0) | Err(_) => {}
        Ok(_) => panic!("a foreign uid must not receive any frame"),
    }
    drop(raw);

    // 同じ uid（子）からの Reload は成功し、Stop で止まる。
    std::io::Write::write_all(&mut stdin, b"go\n").expect("go");
    drop(stdin);
    for want in ["CHILD-RELOADED", "CHILD-STOPPED"] {
        line.clear();
        out.read_line(&mut line).expect("child progress");
        assert_eq!(line.trim(), want);
    }
    let status = child.wait().expect("child exit");
    assert!(status.success(), "child failed: {status:?}");
    println!("dns_helper_process: control_foreign_uid ok peer_uid=65534 foreign=dropped");
}

/// `foreign_uid` の子の引数。
pub const ARG_FOREIGN_UID_CHILD: &str = "--foreign-uid-child";

/// `foreign_uid` の子（uid 65534）。ストアとヘルパーを作り、親の合図の後に Reload と Stop を行う。
pub fn foreign_uid_child(args: Vec<std::ffi::OsString>) -> std::process::ExitCode {
    let Some(root) = args.get(2) else {
        eprintln!("foreign_uid_child: usage: --foreign-uid-child <state_root>");
        return std::process::ExitCode::from(2);
    };
    let exe = std::env::current_exe().expect("exe");
    let store = NetworkStore::open(Path::new(root)).expect("open");
    store
        .create(&NetworkDefinition::pasta("dnsh").expect("def"))
        .expect("create");
    let name = NetworkName::new("dnsh").expect("name");
    let g = store.lock_global_exclusive().expect("global");
    let n = g.lock_network(&name).expect("net");
    n.commit_member(&member("web", 2)).expect("web");
    let listen = DnsListenAddr::new(Ipv4Addr::LOCALHOST, 0).expect("listen");
    spawn_detached_dns_helper(&n, &exe, listen, READY_TIMEOUT_DEFAULT, &NoopNetOpRecorder)
        .expect("spawn");
    println!("CHILD-READY");
    let mut go = String::new();
    std::io::stdin().read_line(&mut go).expect("go");
    assert_eq!(
        reload_dns_helper(&n, &NoopNetOpRecorder).expect("reload"),
        ReloadOutcome::Loaded
    );
    println!("CHILD-RELOADED");
    assert_eq!(
        stop_recorded_dns_helper(&n, &ControlStopRequest::new(&n), &NoopNetOpRecorder)
            .expect("stop"),
        StopOutcome::StoppedOnRequest
    );
    println!("CHILD-STOPPED");
    std::process::ExitCode::SUCCESS
}
