//! 作業枠の満杯（即時 Busy）が、期限切れと別の結果になることの結合試験（#2894・CLI-1・SUP-7・REPAIR-5・ERR-1）。
//!
//! 枠（`MAX_INFLIGHT_LOG_REMOVALS`）はプロセス共有の static のため、枠を埋める本試験は専用の試験バイナリに置き、
//! 試験関数は 1 つだけにする。以前は `run_log_removal_bounded`・`remove_stale_bounded`・`sweep_stale_container_logs`
//! がいずれも枠の満杯を期限切れ（`TimedOut`・`TIMEOUT`・`timed_out`）として返していた。

#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{ContainerId, ErrorCode};

// 一意・排他作成の試験用ディレクトリ（pid だけの名前の残骸と衝突しない。#3374・REPAIR-12）。
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;
use fandhe_container_supervisor::container_options::store::{acquire_lock, remove_stale_bounded};
use fandhe_container_supervisor::logs::{SweepReport, sweep_stale_container_logs};
use fandhe_container_supervisor::supervisor_log::{
    BoundedFailure, LogRemoval, run_bounded_classified, run_log_removal_bounded,
};

/// 枠の上限（`MAX_INFLIGHT_LOG_REMOVALS`）と同じ値。
const SLOTS: usize = 8;

#[test]
fn repair5_err1_2894_slot_busy_is_distinct_from_timeout() {
    let scratch = scratch_root::ScratchDir::new("fc-sup-slotbusy", Duration::from_secs(10));
    let tmp = scratch.path().join("root");
    std::fs::create_dir(&tmp).unwrap();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700)).unwrap();
    let id = ContainerId::new("busy1").unwrap();

    // 1. 枠を止めた作業で埋める（期限切れで戻っても枠は作業の実終了まで残る）。
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

    // 2. 満杯の間は 3 関数とも即時に「枠の満杯」を返す。
    let t0 = Instant::now();
    assert_eq!(
        run_log_removal_bounded(|| {}, Duration::from_secs(5)),
        LogRemoval::Busy
    );
    let e = remove_stale_bounded(
        &tmp,
        &id,
        || true,
        Duration::from_secs(2),
        Duration::from_secs(5),
    )
    .unwrap_err();
    assert_eq!(e.code(), ErrorCode::ResourceExhausted);
    assert_eq!(
        e.message(),
        "container options file removal workers are busy"
    );
    let report = sweep_stale_container_logs(&tmp, Arc::new(|_| true), Duration::from_secs(30));
    assert_eq!(
        report,
        SweepReport {
            workers_busy: true,
            ..SweepReport::default()
        }
    );
    assert!(!report.timed_out);
    assert!(t0.elapsed() < Duration::from_secs(1), "must not wait");

    // 3. 枠を解放し、空くまで有界に待つ。
    drop(releases);
    let deadline = Instant::now() + Duration::from_secs(5);
    while run_bounded_classified(|| (), Duration::from_secs(1)).is_err() {
        assert!(Instant::now() < deadline, "slots were not released");
        std::thread::sleep(Duration::from_millis(10));
    }

    // 4. 実際の期限切れは従来どおり別の結果になる。
    let (tx, rx) = mpsc::channel::<()>();
    assert_eq!(
        run_log_removal_bounded(
            move || {
                let _ = rx.recv();
            },
            Duration::from_millis(50)
        ),
        LogRemoval::TimedOut
    );
    let lock = acquire_lock(&tmp, &id, Duration::from_secs(2)).unwrap();
    let e = remove_stale_bounded(
        &tmp,
        &id,
        || true,
        Duration::from_secs(2),
        Duration::from_millis(100),
    )
    .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Timeout);
    assert_eq!(
        e.message(),
        "container options file removal did not finish within the deadline"
    );

    drop(tx);
    drop(lock);
}
