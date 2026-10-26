//! 起動時の走査（[`sweep_stale_container_logs`]）と create 前の回収（[`reclaim_stale_container_logs`]）のユニットテスト
//! （#2760・SUP-7・CRI-2。root 不要・一時ディレクトリのみ）。

use super::*;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::atomic::AtomicU64;

struct Tmp(std::path::PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "fc-sweep-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&p).expect("tmp");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        Self(p)
    }

    fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(container_log_dir(&self.0))
            .map(|rd| {
                rd.filter_map(|e| e.ok()?.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn id(s: &str) -> fandhe_container_core::traits::ContainerId {
    fandhe_container_core::traits::ContainerId::new(s).expect("id")
}

fn open(t: &Tmp, name: &str) -> RotatingFileSink {
    let dir = container_log_dir(&t.0);
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    RotatingFileSink::open(&dir, &id(name), container_log_rotation_config()).expect("sink")
}

/// 閉じた sink の残りだけが消える。生きている sink・状態がある ID・帰属できない名前は残り、件数が具体値で一致する。
#[test]
fn sup7_cri2_sweep_removes_only_closed_unrecorded_logs() {
    let t = Tmp::new("mix");
    drop(open(&t, "closed1"));
    drop(open(&t, "present1"));
    let _live = open(&t, "live1");
    std::fs::write(container_log_dir(&t.0).join("Foo.log"), b"x").expect("foo");
    std::fs::write(container_log_dir(&t.0).join("README.txt"), b"x").expect("readme");
    let report = sweep_stale_container_logs(
        &t.0,
        Arc::new(|id| id.as_str() != "present1"),
        Duration::from_secs(30),
    );
    assert_eq!(
        report,
        SweepReport {
            scanned: report.scanned,
            reclaimed_ids: 1,
            removed_files: 1,
            skipped_live: 1,
            skipped_present: 1,
            skipped_undecodable: 1,
            failed: 0,
            timed_out: false,
        }
    );
    assert_eq!(
        t.names(),
        vec![
            "Foo.log",
            "README.txt",
            "live1.log",
            "live1.log.lock",
            "present1.log",
        ]
    );
}

/// 期限が 0 なら 1 件も消さず `timed_out` になる（REPAIR-5）。
#[test]
fn repair5_cri2_sweep_stops_when_budget_is_exhausted() {
    let t = Tmp::new("budget");
    drop(open(&t, "closed1"));
    let before = t.names();
    let report = sweep_stale_container_logs(&t.0, Arc::new(|_| true), Duration::ZERO);
    assert!(report.timed_out);
    assert_eq!(report.removed_files, 0);
    assert_eq!(t.names(), before);
}

/// ログのディレクトリが無ければ何もせず空の報告を返す。
#[test]
fn sup7_cri2_sweep_without_log_dir_is_empty() {
    let t = Tmp::new("nodir");
    let report = sweep_stale_container_logs(&t.0, Arc::new(|_| true), Duration::from_secs(5));
    assert_eq!(report, SweepReport::default());
}

/// 符号化が必要な ID（大文字・`_`・予約名・`.log` を含む名前）のログも、往復で ID に戻って回収される。
#[test]
fn sup7_cri2_sweep_handles_encoded_ids() {
    let t = Tmp::new("encoded");
    for name in ["Ab_C", "con", "a.log"] {
        drop(open(&t, name));
    }
    let report = sweep_stale_container_logs(&t.0, Arc::new(|_| true), Duration::from_secs(30));
    assert_eq!(report.reclaimed_ids, 3);
    assert_eq!(report.skipped_undecodable, 0);
    assert_eq!(t.names(), Vec::<String>::new());
}

/// create 前の回収: 状態が既にある ID は消さず `Nothing`、閉じた残りは `Removed(1)`、生きた sink は `Failed`。
#[test]
fn sup7_cri2_reclaim_reports_each_outcome() {
    let t = Tmp::new("reclaim");
    drop(open(&t, "a1"));
    assert_eq!(
        reclaim_stale_container_logs(&t.0, &id("a1"), || false),
        StaleLogReclaim::Nothing
    );
    assert_eq!(t.names(), vec!["a1.log"]);
    assert_eq!(
        reclaim_stale_container_logs(&t.0, &id("a1"), || true),
        StaleLogReclaim::Removed(1)
    );
    let _live = open(&t, "l1");
    assert_eq!(
        reclaim_stale_container_logs(&t.0, &id("l1"), || true),
        StaleLogReclaim::Failed(ErrorCode::FailedPrecondition)
    );
}

/// 待ち切れなかった失敗（`FailedPrecondition`）だけが `reason` を持つ。
#[test]
fn repair4_sup7_removal_reason_only_for_sink_open() {
    assert_eq!(
        container_log_removal_reason(ErrorCode::FailedPrecondition),
        Some("sink_open_after_wait")
    );
    assert_eq!(container_log_removal_reason(ErrorCode::Timeout), None);
}
/// 掃除が同じ ID のロックを短く保持している間に start の open が当たっても、有界の試し直しで開ける（#2760・SUP-7・CRI-2）。
#[test]
fn sup7_cri2_open_waiting_survives_short_lock_hold() {
    let t = Tmp::new("openwait");
    let held = open(&t, "c1");
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        drop(held);
    });
    let dir = container_log_dir(&t.0);
    let sink = open_container_log_sink_waiting(
        &dir,
        &id("c1"),
        container_log_rotation_config(),
        Duration::from_secs(10),
    );
    releaser.join().expect("join");
    assert!(sink.is_ok());
}

/// 本当に生きている sink があれば、待ちを使い切った後は `FailedPrecondition` のまま返る（待ちは有界）。
#[test]
fn sup7_cri2_open_waiting_gives_up_when_sink_stays_alive() {
    let t = Tmp::new("openwaitlive");
    let _live = open(&t, "c1");
    let dir = container_log_dir(&t.0);
    let started = Instant::now();
    let e = open_container_log_sink_waiting(
        &dir,
        &id("c1"),
        container_log_rotation_config(),
        Duration::from_millis(150),
    )
    .err()
    .expect("must fail");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert!(started.elapsed() < Duration::from_secs(5));
}
