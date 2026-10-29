//! 状態ルートのインスタンス排他の結合試験（CRI-2・CORE-1・REPAIR-5。#2931）。
//!
//! 1. 別プロセスが保持している間は取れず、そのプロセスが SIGKILL で消えた後は再取得できる（OS がロックを解放する）
//! 2. 実バイナリを同じ状態ルート・別 socket パスで 2 つ起動すると、2 つ目は固定文言で終了コード 1 になり bind しない
//!
//! 子の待ちはすべて期限つき（REPAIR-5）。

#![cfg(unix)]

use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::ErrorCode;
use fandhe_container_plugin_cri::instance_lock::{
    INSTANCE_LOCK_NAME, MSG_INSTANCE_LOCK_BUSY, acquire_instance_lock_in,
};

#[cfg(target_os = "linux")]
const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-cri");
const ENV_ROOT: &str = "FC_CRI_INSTLOCK_ROOT";
const ENV_READY: &str = "FC_CRI_INSTLOCK_READY";
const WAIT: Duration = Duration::from_secs(15);
const REAP_GRACE: Duration = Duration::from_secs(5);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "fcpc-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&p)
            .expect("create temp dir");
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Drop で kill し、期限つきで回収する子のガード。
struct ChildGuard(Child);

impl ChildGuard {
    fn kill_and_reap(&mut self) {
        let _ = self.0.kill();
        let start = Instant::now();
        while start.elapsed() < REAP_GRACE {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("child was not reaped within the grace period");
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let start = Instant::now();
        while start.elapsed() < REAP_GRACE {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn wait_for(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(start.elapsed() < WAIT, "timed out waiting for {path:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// 子の役。env が無い通常実行では何もしない。取得したら ready ファイルを作り、kill されるまで待つ。
#[test]
fn child_holder() {
    let (Some(root), Some(ready)) = (std::env::var_os(ENV_ROOT), std::env::var_os(ENV_READY))
    else {
        return;
    };
    let _lock = acquire_instance_lock_in(Path::new(&root), Duration::from_secs(5))
        .expect("child acquires the lock");
    std::fs::write(&ready, b"").expect("write ready");
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// CRI-2: 別プロセスが保持中は固定文言の Timeout、SIGKILL 後は再取得できる。
#[test]
fn cri2_lock_held_by_other_process_until_it_is_killed() {
    let root = TempDir::new("ilock-root");
    let ready = root.0.join("ready-marker");
    let exe = std::env::current_exe().expect("current exe");
    let child = Command::new(exe)
        .args([
            "--exact",
            "child_holder",
            "--no-capture",
            "--test-threads=1",
        ])
        .env(ENV_ROOT, &root.0)
        .env(ENV_READY, &ready)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn holder");
    let mut guard = ChildGuard(child);
    wait_for(&ready);

    let e = acquire_instance_lock_in(&root.0, Duration::from_millis(300))
        .expect_err("must be held by the child");
    assert_eq!(e.code(), ErrorCode::Timeout);
    assert_eq!(e.message(), MSG_INSTANCE_LOCK_BUSY);

    guard.kill_and_reap();
    let _l = acquire_instance_lock_in(&root.0, Duration::from_secs(5))
        .expect("reacquire after the holder died");
    assert!(root.0.join(".cri").join(INSTANCE_LOCK_NAME).exists());
}

#[cfg(target_os = "linux")]
fn spawn_server(sock: &Path, xdg: &Path) -> ChildGuard {
    let child = Command::new(BIN)
        .arg("--socket")
        .arg(sock)
        .env_clear()
        .env("XDG_RUNTIME_DIR", xdg)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn plugin binary");
    ChildGuard(child)
}

/// CRI-2・CORE-1: 同じ状態ルート・別 socket パスの 2 つ目は拒否され（bind 前）、1 つ目が消えた後は起動できる。
/// root では状態ルートが XDG を無視するため隔離できず、前提不成立として失敗させる（CI は非 root）。
#[cfg(target_os = "linux")]
#[test]
fn cri2_second_instance_on_same_state_root_is_rejected() {
    use std::io::Read as _;
    // SAFETY 不要の確認: geteuid 相当は /proc から読む（unsafe を使わない）。
    let status = std::fs::read_to_string("/proc/self/status").expect("read status");
    let euid_is_root = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|r| r.split_whitespace().nth(1).map(|s| s == "0"))
        .expect("parse euid");
    assert!(
        !euid_is_root,
        "this test requires a non-root user (state root would ignore XDG_RUNTIME_DIR)"
    );

    let xdg = TempDir::new("ilock-xdg");
    let socks = TempDir::new("ilock-socks");
    let sock_a = socks.0.join("a.sock");
    let sock_b = socks.0.join("b.sock");
    let sock_c = socks.0.join("c.sock");

    let mut a = spawn_server(&sock_a, &xdg.0);
    wait_for(&sock_a);

    let mut b = spawn_server(&sock_b, &xdg.0);
    let start = Instant::now();
    let status_b = loop {
        if let Some(s) = b.0.try_wait().expect("try_wait") {
            break s;
        }
        assert!(start.elapsed() < WAIT, "second instance did not exit");
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut err = String::new();
    b.0.stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut err)
        .expect("read stderr");
    let mut out = String::new();
    b.0.stdout
        .take()
        .expect("stdout")
        .read_to_string(&mut out)
        .expect("read stdout");
    assert_eq!(status_b.code(), Some(1));
    assert_eq!(
        err,
        "error: TIMEOUT: state root is in use by another cri plugin instance\n"
    );
    assert_eq!(out, "");
    assert!(!sock_b.exists(), "lock must be taken before bind");

    a.kill_and_reap();
    let mut c = spawn_server(&sock_c, &xdg.0);
    wait_for(&sock_c);
    c.kill_and_reap();
}
