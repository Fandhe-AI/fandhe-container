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
use std::time::Duration;

use fandhe_container_net::error::NetErrorCode;
use fandhe_container_net::network::NetworkName;
use fandhe_container_net::network_store::{NetworkDefinition, NetworkStore};

const ENV_ROOT: &str = "FC_STORE_HELPER_ROOT";
const ENV_MODE: &str = "FC_STORE_HELPER_MODE";
const READY: &str = "FC_STORE_HELPER_LOCKED";

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
        let _ = child.kill();
        let _ = child.wait();
        panic!("holder did not report the lock within 20s");
    }
    child
}

fn stop(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
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
