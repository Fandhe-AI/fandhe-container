//! イメージストア排他の結合試験（OCI-7・TASK-183.2・#473）。
//!
//! 公開 API のみを使い、別プロセスが排他区間を保持している間は親の `lock()` が `Timeout` になり、
//! 解放後に取得できることを確かめる。子プロセスは同じ試験バイナリを `--exact` で再起動する
//! （core の state_store_integration と同じ形）。待機にはすべて期限を置く（REPAIR-5）。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::image_management::ImageStore;

#[path = "../../core/tests/support/reap.rs"]
mod reap;
#[path = "support/test_root.rs"]
mod test_root;
use test_root::{TestRoot, test_root, test_root_at};

const CHILD_TEST: &str = "oci7_child_holds_lock";
const ROOT_ENV: &str = "FC_OCI_STORE_TEST_ROOT";
const DEADLINE: Duration = Duration::from_secs(30);

fn wait_for(path: &Path) {
    let deadline = Instant::now() + DEADLINE;
    while !path.exists() {
        assert!(Instant::now() < deadline, "marker did not appear in time");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// 子側のエントリ。環境変数が無ければ何もしない（通常の試験集合で単独実行されても副作用なし）。
#[test]
fn oci7_child_holds_lock() {
    let Some(root) = std::env::var_os(ROOT_ENV).map(PathBuf::from) else {
        return;
    };
    let store = ImageStore::open(&root).expect("open");
    let _guard = store.lock().expect("child lock");
    std::fs::write(root.join("ready"), b"").expect("ready");
    wait_for(&root.join("release"));
}

/// OCI-7: 別プロセスの排他区間中は待機（Timeout）となり、解放後に取得できる。
#[test]
fn oci7_lock_excludes_other_process() {
    run_lock_excludes_other_process(test_root("fc-oci-store-it", "lock"));
}

/// OCI-7・REPAIR-12（#3298）: 前回の `ready` / `release` の残骸があっても、子の排他区間中は
/// `Timeout` になる本来の流れが通る（残骸で `wait_for` が即通って親が先に lock しない）。
#[test]
fn oci7_repair12_lock_flow_passes_over_stale_ready_release() {
    let p = std::env::temp_dir().join(format!("fc-oci-store-it-residue-{}", std::process::id()));
    std::fs::create_dir_all(&p).expect("mkdir residue");
    std::fs::write(p.join("ready"), b"").expect("stale ready");
    std::fs::write(p.join("release"), b"").expect("stale release");
    run_lock_excludes_other_process(test_root_at(p));
}

fn run_lock_excludes_other_process(root: TestRoot) {
    assert!(!root.join("ready").exists() && !root.join("release").exists());
    let mut child = Command::new(std::env::current_exe().expect("exe"))
        .args(["--exact", CHILD_TEST, "--test-threads=1", "--nocapture"])
        .env(ROOT_ENV, &*root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");

    wait_for(&root.join("ready"));
    let store = ImageStore::open(&root)
        .expect("open")
        .with_timeout(Duration::from_millis(200));
    let e = store.lock().expect_err("held by child");
    assert_eq!(e.code(), OciErrorCode::Timeout);

    std::fs::write(root.join("release"), b"").expect("release");
    let deadline = Instant::now() + DEADLINE;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => {
                assert!(status.success(), "child exited with {status}");
                break;
            }
            None if Instant::now() >= deadline => {
                reap::reap_or_report(&mut child, reap::REAP_WITHIN);
                panic!("child did not finish within the deadline");
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }

    let store = store.with_timeout(Duration::from_secs(5));
    store.lock().expect("acquire after child released");
}

/// REPAIR-5・REPAIR-12（#3305）: 期限つきの終了待ち `wait_within` は、子が終わらないとき無期限に
/// 止まらず、pid と期限を含む具体的なメッセージの `Err` で期限切れを表に出し、続く `reap` で回収できる。
#[test]
fn repair5_wait_within_reports_expiry() {
    let root = test_root("fc-oci-store-it", "reap-expiry");
    let mut child = Command::new(std::env::current_exe().expect("exe"))
        .args(["--exact", CHILD_TEST, "--test-threads=1", "--nocapture"])
        .env(ROOT_ENV, &*root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let pid = child.id();

    // 子は `release` が現れるまで排他区間を保持して終わらない。照合の失敗で子を残さないよう、
    // 結果を変数に取り、回収してから assert する。
    wait_for(&root.join("ready"));
    let expired = reap::wait_within(&mut child, Duration::from_millis(200));
    let reaped = reap::reap(&mut child, Duration::from_secs(10));

    assert_eq!(
        expired,
        Err(format!("child {pid} did not exit within 200ms"))
    );
    assert_eq!(reaped, Ok(()));
}
