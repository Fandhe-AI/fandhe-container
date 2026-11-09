//! 起動時の走査（[`sweep_stale_container_logs`]）と create 前の回収（[`reclaim_stale_container_logs`]）のユニットテスト
//! （#2760・SUP-7・CRI-2。root 不要・一時ディレクトリのみ）と、supervisor ログの走査（`sweep_stale_supervisor_logs`。#4339）。

use super::*;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::atomic::AtomicU64;

/// 第 2 要素は残骸を消して作った実体（Drop で後始末する。REPAIR-12・#3435）。
struct Tmp(
    std::path::PathBuf,
    #[allow(dead_code)] crate::test_root::TestRoot,
);

impl Tmp {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "fc-sweep-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        // 残骸・PID 再利用との衝突を避けるため排他作成し、既存の名前は消さず別名で作る（0700。REPAIR-12・#3475）。
        let root = crate::test_root::test_root_at(p);
        Self(root.to_path_buf(), root)
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
            workers_busy: false,
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

// ---- supervisor ログ（@supervisor-logs）の走査（#4339・SUP-7・CRI-2・REPAIR-5） ----

fn sv_names(t: &Tmp) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(crate::supervisor_log::log_dir(&t.0))
        .map(|rd| {
            rd.filter_map(|e| e.ok()?.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn sv_open(t: &Tmp, name: &str) -> crate::supervisor_log::SupervisorLogWriter {
    crate::supervisor_log::open(&t.0, &id(name)).expect("supervisor log")
}

fn sv_sweep(t: &Tmp, may: impl Fn(&str) -> bool + Send + Sync + 'static) -> SweepReport {
    crate::supervisor_log::sweep_stale_supervisor_logs(
        &t.0,
        Arc::new(move |i| may(i.as_str())),
        Duration::from_secs(30),
    )
}

/// 記録の無い閉じたログだけが消える。記録あり・生きた sink・ID に戻せない名前は残る。
#[test]
fn sup7_cri2_4339_supervisor_sweep_removes_only_unrecorded_closed_logs() {
    let t = Tmp::new("svmix");
    drop(sv_open(&t, "dead1"));
    let dir = crate::supervisor_log::log_dir(&t.0);
    std::fs::write(dir.join("dead1.log.1"), b"old\n").expect("gen");
    drop(sv_open(&t, "present1"));
    let _live = sv_open(&t, "live1");
    std::fs::write(dir.join("Foo.log"), b"x").expect("foo");
    std::fs::write(dir.join("README.txt"), b"x").expect("readme");
    let report = sv_sweep(&t, |i| i != "present1");
    assert_eq!(
        report,
        SweepReport {
            scanned: report.scanned,
            reclaimed_ids: 1,
            removed_files: 2,
            skipped_live: 1,
            skipped_present: 1,
            skipped_undecodable: 1,
            failed: 0,
            timed_out: false,
            workers_busy: false,
        }
    );
    assert_eq!(
        sv_names(&t),
        vec![
            "Foo.log",
            "README.txt",
            "live1.log",
            "live1.log.lock",
            "present1.log",
        ]
    );
}

/// 期限が 0 なら 1 件も消さず `timed_out` になる。
#[test]
fn repair5_cri2_4339_supervisor_sweep_stops_when_budget_is_exhausted() {
    let t = Tmp::new("svbudget");
    drop(sv_open(&t, "closed1"));
    let before = sv_names(&t);
    let report = crate::supervisor_log::sweep_stale_supervisor_logs(
        &t.0,
        Arc::new(|_| true),
        Duration::ZERO,
    );
    assert!(report.timed_out);
    assert_eq!(report.removed_files, 0);
    assert_eq!(sv_names(&t), before);
}

/// ID 数の上限で打ち切ると `timed_out` になり、残りは次回に回る。
#[test]
fn repair5_cri2_4339_sweep_stops_at_id_cap() {
    let t = Tmp::new("svcap");
    for n in ["a1", "b1", "c1"] {
        drop(sv_open(&t, n));
    }
    let report = sweep_stale_logs_in(
        &t.0,
        SweepTarget::SupervisorLogs,
        Arc::new(|_| true),
        Duration::from_secs(30),
        2,
    );
    assert!(report.timed_out);
    assert_eq!(report.reclaimed_ids, 2);
    assert_eq!(sv_names(&t).len(), 2); // 残る 1 ID 分（.log と .log.lock）
}

/// ディレクトリが無ければ空の報告を返す。
#[test]
fn sup7_cri2_4339_supervisor_sweep_without_dir_is_empty() {
    let t = Tmp::new("svnodir");
    assert_eq!(sv_sweep(&t, |_| true), SweepReport::default());
}

/// ディレクトリが symlink なら何も消さず `failed` になる（SEC-1）。
#[test]
fn sec1_sup7_4339_supervisor_sweep_rejects_symlinked_dir() {
    let t = Tmp::new("svlink");
    let outside = t.0.join("outside");
    std::fs::create_dir(&outside).expect("outside");
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    std::fs::write(outside.join("victim.log"), b"x").expect("victim");
    std::os::unix::fs::symlink(&outside, crate::supervisor_log::log_dir(&t.0)).expect("link");
    let report = sv_sweep(&t, |_| true);
    assert_eq!(
        report,
        SweepReport {
            failed: 1,
            ..SweepReport::default()
        }
    );
    assert!(outside.join("victim.log").exists());
}

/// コンテナログと supervisor ログを取り違えない: 走査した側のディレクトリだけが消える。
#[test]
fn sup7_cri2_4339_sweeps_do_not_cross_directories() {
    let t = Tmp::new("svcross");
    drop(open(&t, "c1"));
    drop(sv_open(&t, "s1"));
    let r = sv_sweep(&t, |_| true);
    assert_eq!(r.reclaimed_ids, 1);
    assert_eq!(sv_names(&t), Vec::<String>::new());
    assert_eq!(t.names(), vec!["c1.log", "c1.log.lock"]);
    drop(sv_open(&t, "s2"));
    let r = sweep_stale_container_logs(&t.0, Arc::new(|_| true), Duration::from_secs(30));
    assert_eq!(r.reclaimed_ids, 1);
    assert_eq!(t.names(), Vec::<String>::new());
    assert_eq!(sv_names(&t), vec!["s2.log", "s2.log.lock"]);
}
