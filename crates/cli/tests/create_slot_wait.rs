//! `create` の起動オプション I/O が、プロセス共有の作業枠の一時的な満杯を期限内で待つことの結合試験
//! （#2834・CLI-1・REPAIR-5・ERR-2）。
//!
//! 枠は static のため、枠を埋める本試験は専用の試験バイナリに置き、他の試験へ漏らさない。試験関数は 1 つだけ。
//! 以前は満杯を待たずに `TIMEOUT`（"container options file I/O did not finish within the deadline"）で失敗した。

#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use fandhe_container_cli::commands::run_to;
use fandhe_container_supervisor::supervisor_log::{BoundedFailure, run_bounded_classified};

/// 枠の上限（`MAX_INFLIGHT_LOG_REMOVALS`）と同じ値。
const SLOTS: usize = 8;

fn argv(root: &Path, rest: &[&str]) -> Vec<OsString> {
    let mut v: Vec<OsString> = vec!["--root".into(), root.into()];
    v.extend(rest.iter().map(OsString::from));
    v
}

#[test]
fn cli1_repair5_create_waits_for_a_busy_worker_slot_instead_of_timing_out() {
    let tmp = std::env::temp_dir().join(format!("fc-cli-slotwait-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = tmp.join("state");
    let bundle = tmp.join("bundle");
    std::fs::create_dir_all(bundle.join("rootfs")).unwrap();
    std::fs::write(
        bundle.join("config.json"),
        r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .unwrap();

    // 枠を SLOTS 個、止めた作業で埋める（期限切れで戻っても枠は作業の実終了まで残る）。
    let mut releases = Vec::new();
    for _ in 0..SLOTS {
        let (tx, rx) = mpsc::channel::<()>();
        releases.push(tx);
        let r = run_bounded_classified(
            move || {
                let _ = rx.recv();
            },
            Duration::from_millis(20),
        );
        assert_eq!(r, Err(BoundedFailure::Unfinished));
    }
    // 300ms 後に全枠を解放する。create はその間待ち、TIMEOUT にならず成功する。
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        drop(releases);
    });

    let mut out = Vec::new();
    let ex = run_to(
        argv(
            &root,
            &["create", "--bundle", bundle.to_str().unwrap(), "slotwait"],
        ),
        &mut out,
    );
    let mut err = Vec::new();
    ex.write_stderr(&mut err).unwrap();
    assert_eq!(
        ex.exit_code(),
        0,
        "create failed: {}",
        String::from_utf8_lossy(&err)
    );
    releaser.join().unwrap();
    let _ = std::fs::remove_dir_all(&tmp);
}
