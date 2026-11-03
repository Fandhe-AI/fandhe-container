//! `supervisor_log::run_bounded_waiting` の枠待ちの結合試験（#2834・REPAIR-5・CLI-1）。
//!
//! 同時実行枠はプロセス共有の static のため、枠を埋める試験は専用の試験バイナリ（本ファイル）へ置き、
//! 他の試験へ漏らさない。試験関数は 1 つだけにして、枠の状態を直列に組み立てる。

use std::sync::mpsc;
use std::time::{Duration, Instant};

use fandhe_container_supervisor::supervisor_log::{
    BoundedFailure, run_bounded_classified, run_bounded_waiting,
};

/// 枠の上限（`MAX_INFLIGHT_LOG_REMOVALS`）と同じ値。照合のため具体値で持つ。
const SLOTS: usize = 8;

#[test]
fn repair5_waiting_run_waits_for_a_free_slot_and_reports_busy_distinctly() {
    // 枠が空いていても、期限がゼロなら job を起動せず Busy（期限切れ後に副作用を走らせない）。
    let started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let started2 = started.clone();
    assert_eq!(
        run_bounded_waiting(
            move || started2.store(true, std::sync::atomic::Ordering::SeqCst),
            Duration::ZERO
        ),
        Err(BoundedFailure::Busy)
    );
    std::thread::sleep(Duration::from_millis(50));
    assert!(!started.load(std::sync::atomic::Ordering::SeqCst));

    // 枠を SLOTS 個、チャネル待ちで止めた作業で埋める。期限切れで戻っても枠は作業の実終了まで残る。
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

    // 満杯: 即時版は待たずに Busy。
    let t = Instant::now();
    assert_eq!(
        run_bounded_classified(|| 1, Duration::from_secs(5)),
        Err(BoundedFailure::Busy)
    );
    assert!(t.elapsed() < Duration::from_millis(500));

    // 待ち版は期限まで待ち、空かなければ job を実行せず Busy（期限切れの Unfinished とは区別する）。
    let t = Instant::now();
    let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ran2 = ran.clone();
    let r = run_bounded_waiting(
        move || ran2.store(true, std::sync::atomic::Ordering::SeqCst),
        Duration::from_millis(150),
    );
    assert_eq!(r, Err(BoundedFailure::Busy));
    assert!(t.elapsed() >= Duration::from_millis(150));
    assert!(t.elapsed() < Duration::from_secs(3));
    assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));

    // 途中で枠が空けば待ち版は成功する（2 個を 50ms 後に解放）。
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        drop(releases.split_off(SLOTS - 2));
        releases
    });
    let r = run_bounded_waiting(|| 42, Duration::from_secs(10));
    assert_eq!(r, Ok(42));
    drop(releaser.join().unwrap());
}
