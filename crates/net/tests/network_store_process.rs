//! ネットワーク定義ストアのプロセス間結合試験（NET-6・REPAIR-5・REPAIR-12・#3059）。
//!
//! 公開 API だけで、別プロセス間の排他ロック・共有ロック・競合時の期限（`Timeout`）・保持プロセス終了後の
//! 再取得・別ハンドルで作った定義の可視性を確かめる。子は本試験バイナリ自身を環境変数つきで再実行した
//! `helper_hold_lock` で、ロックを取って成功行を出し、親が殺すまで保持する。待ちはすべて期限つき。
//! Linux のみ（ストアが Linux 実装のため。他 OS では試験なし）。

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fandhe_container_net::error::NetErrorCode;
use std::net::{IpAddr, Ipv4Addr};

use fandhe_container_net::netlink_route::IpPrefix;
use fandhe_container_net::network::{EndpointId, NetworkName, NetworkResourceNames};
use fandhe_container_net::network_store::{
    MemberId, MemberIntent, MemberRecord, NetworkDefinition, NetworkStore, RealizedIntent,
    RealizedOp, RealizedRecord, rebuild_ipam,
};

const ENV_ROOT: &str = "FC_STORE_HELPER_ROOT";
const ENV_MODE: &str = "FC_STORE_HELPER_MODE";
const READY: &str = "FC_STORE_HELPER_LOCKED";
const REAP_DEADLINE: Duration = Duration::from_secs(10);

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("fc-netstore-it-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Tmp(p)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 子として動く入口。環境変数が無ければ何もしない（通常の試験実行では素通り）。
#[test]
fn helper_hold_lock() {
    let (Ok(root), Ok(mode)) = (std::env::var(ENV_ROOT), std::env::var(ENV_MODE)) else {
        return;
    };
    let store = NetworkStore::open(Path::new(&root)).unwrap();
    let _g = match mode.as_str() {
        "shared" => store.lock_global_shared().unwrap(),
        _ => store.lock_global_exclusive().unwrap(),
    };
    println!("{READY}");
    // 親が kill するまで保持する。親が消えた場合に備えて上限を設ける。
    std::thread::sleep(Duration::from_secs(60));
}

fn spawn_holder(root: &Path, mode: &str) -> Child {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "helper_hold_lock",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ENV_ROOT, root)
        .env(ENV_MODE, mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let out = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if line.contains(READY) {
                let _ = tx.send(());
                return;
            }
        }
    });
    if rx.recv_timeout(Duration::from_secs(20)).is_err() {
        let reaped = reap_with_deadline(&mut child);
        panic!("holder did not report the lock within 20s (reap result: {reaped:?})");
    }
    child
}

/// 子を kill して期限内に回収する（REPAIR-5）。kill 失敗・期限超過は明示的なエラーで返す。
fn reap_with_deadline(child: &mut Child) -> Result<(), String> {
    // 既に終了済みの子への kill は失敗しうるため、回収できるかを先に見る。
    if let Err(e) = child.kill() {
        if !matches!(child.try_wait(), Ok(Some(_))) {
            return Err(format!("kill failed: {e}"));
        }
        return Ok(());
    }
    let deadline = Instant::now() + REAP_DEADLINE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(e) => return Err(format!("try_wait failed: {e}")),
        }
        if Instant::now() >= deadline {
            return Err(format!("child not reaped within {REAP_DEADLINE:?}"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn stop(mut child: Child) {
    if let Err(e) = reap_with_deadline(&mut child) {
        panic!("failed to stop holder: {e}");
    }
}

fn store(root: &Path) -> NetworkStore {
    NetworkStore::open(root)
        .unwrap()
        .with_lock_timeout(Duration::from_millis(300))
}

/// NET-6・REPAIR-5: 別プロセスが排他ロックを持つ間、排他も共有も期限で `Timeout` になる。
#[test]
fn net6_exclusive_held_by_other_process_times_out() {
    let t = Tmp::new("excl");
    let s = store(&t.0);
    let holder = spawn_holder(&t.0, "exclusive");
    assert_eq!(
        s.lock_global_exclusive().unwrap_err().code(),
        NetErrorCode::Timeout
    );
    assert_eq!(
        s.lock_global_shared().unwrap_err().code(),
        NetErrorCode::Timeout
    );
    let def = NetworkDefinition::pasta("alpha").unwrap();
    assert_eq!(s.create(&def).unwrap_err().code(), NetErrorCode::Timeout);
    stop(holder);
}

/// NET-6: 別プロセスが共有ロックを持つ間、共有は取れ、排他は `Timeout` になる。
#[test]
fn net6_shared_held_by_other_process_allows_shared_blocks_exclusive() {
    let t = Tmp::new("shared");
    let s = store(&t.0);
    let holder = spawn_holder(&t.0, "shared");
    let g = s.lock_global_shared().unwrap();
    drop(g);
    assert_eq!(
        s.lock_global_exclusive().unwrap_err().code(),
        NetErrorCode::Timeout
    );
    stop(holder);
}

/// NET-6・REPAIR-5: 保持プロセスが死ぬとロックは自動で解放され、再取得できる。
#[test]
fn net6_lock_is_reacquirable_after_holder_exits() {
    let t = Tmp::new("reacq");
    let s = store(&t.0);
    let holder = spawn_holder(&t.0, "exclusive");
    assert_eq!(
        s.lock_global_exclusive().unwrap_err().code(),
        NetErrorCode::Timeout
    );
    stop(holder);
    let _g = s.lock_global_exclusive().unwrap();
}

/// NET-6: 別の `NetworkStore`（別の open）で作った定義が見え、削除も共有される。
#[test]
fn net6_definition_visible_across_store_handles() {
    let t = Tmp::new("visible");
    let a = store(&t.0);
    let b = store(&t.0);
    a.create(&NetworkDefinition::pasta("alpha").unwrap())
        .unwrap();
    let name = NetworkName::new("alpha").unwrap();
    assert_eq!(b.get(&name).unwrap().name().as_str(), "alpha");
    b.remove(&name).unwrap();
    assert_eq!(a.get(&name).unwrap_err().code(), NetErrorCode::NotFound);
}

// ---- メンバー記録・realized の別プロセス間の永続（NET-1・REPAIR-12・#3067） ----

const ENV_RECORDS_ROOT: &str = "FC_STORE_RECORDS_ROOT";
const RECORDS_DONE: &str = "FC_STORE_RECORDS_WRITTEN";
const BRIDGE_TOKEN: &str = "fandhe-net:web:1:0:0";

fn pfx(last: u8, len: u8) -> IpPrefix {
    IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)), len).unwrap()
}

fn ep_token(ep: &str) -> String {
    format!("{BRIDGE_TOKEN}/ep/{ep}/g/00000000000000000000000000000001")
}

/// `realized` を FCREA1 の正準形で組む（`CreatedNetwork` は外から作れないため復号経由）。
fn realized_record() -> RealizedRecord {
    let names = NetworkResourceNames::derive(&NetworkName::new("web").unwrap()).unwrap();
    let mut text = String::from("FCREA1\n");
    for (k, v) in [
        ("name", "web".to_owned()),
        ("bridge", names.bridge().as_str().to_owned()),
        ("ifindex", "7".to_owned()),
        ("token", BRIDGE_TOKEN.to_owned()),
        ("table", names.table().as_str().to_owned()),
        ("table-handle", "42".to_owned()),
        ("gateway", "10.0.0.1/24".to_owned()),
        ("subnet", "10.0.0.0/24".to_owned()),
    ] {
        text.push_str(&format!("{k} {}\n{v}\n", v.len()));
    }
    RealizedRecord::decode(text.as_bytes()).unwrap()
}

/// 子として動く入口。記録を書いて（意図記録 1 件を取り残して）終了する。
#[test]
fn helper_write_records() {
    let Ok(root) = std::env::var(ENV_RECORDS_ROOT) else {
        return;
    };
    let store = NetworkStore::open(Path::new(&root)).unwrap();
    let name = NetworkName::new("web").unwrap();
    let g = store.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name).unwrap();
    n.write_realized_intent(
        &RealizedIntent::new(RealizedOp::Create, name, BRIDGE_TOKEN, pfx(0, 24)).unwrap(),
    )
    .unwrap();
    n.commit_realized(&realized_record()).unwrap();
    let member_intent = |id: &str, last: u8| {
        MemberIntent::new(
            MemberId::new(id).unwrap(),
            EndpointId::new(id).unwrap(),
            pfx(last, 24),
            &ep_token(id),
        )
        .unwrap()
    };
    n.write_member_intent(&member_intent("a", 2)).unwrap();
    let member = MemberRecord::new(
        MemberId::new("a").unwrap(),
        EndpointId::new("a").unwrap(),
        pfx(2, 24),
        &ep_token("a"),
        Path::new("/run/ns"),
        (8, 9),
        &[],
    )
    .unwrap();
    n.commit_member(&member).unwrap();
    // 確定しないまま終わる attach（意図記録だけ残る）。
    n.write_member_intent(&member_intent("b", 3)).unwrap();
    println!("{RECORDS_DONE}");
}

/// NET-1・REPAIR-12・#3067: 別プロセスが書いて終了した記録を別の `NetworkStore` が読み直し、確定記録の .2 と
/// 取り残した意図記録の .3 が予約されたまま、次の払い出しが .4 になる（再払い出しされない）。
#[test]
fn net1_3067_records_persist_across_processes_and_reserve_addresses() {
    let t = Tmp::new("records");
    let writer = store(&t.0);
    writer
        .create(&NetworkDefinition::bridge("web", pfx(0, 24)).unwrap())
        .unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "helper_write_records",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ENV_RECORDS_ROOT, &t.0)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let out = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let wrote = BufReader::new(out)
            .lines()
            .map_while(Result::ok)
            .any(|l| l.contains(RECORDS_DONE));
        let _ = tx.send(wrote);
    });
    let wrote = rx.recv_timeout(Duration::from_secs(30));
    let reaped = reap_with_deadline(&mut child);
    assert_eq!(wrote, Ok(true), "writer did not finish (reap: {reaped:?})");

    let reader = store(&t.0);
    let name = NetworkName::new("web").unwrap();
    let g = reader.lock_global_exclusive().unwrap();
    let n = g.lock_network(&name).unwrap();
    let realized = n.realized().unwrap().expect("realized must persist");
    assert_eq!(realized.gateway(), pfx(1, 24));
    assert!(n.realized_intent().unwrap().is_none());
    let members = n.members().unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].address(), pfx(2, 24));
    let intents = n.member_intents().unwrap();
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].address(), pfx(3, 24));
    let mut ipam = rebuild_ipam(&realized, &members, &intents).unwrap();
    assert_eq!(
        ipam.allocate(&EndpointId::new("c").unwrap()).unwrap(),
        pfx(4, 24)
    );
}
