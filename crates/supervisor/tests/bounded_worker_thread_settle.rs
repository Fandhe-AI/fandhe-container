//! 期限つき作業スレッドの実行（`run_bounded_*`）が、戻った時点で呼び出しプロセスを単一スレッドに戻すことの結合試験
//! （SEC-4・SUP-6・REPAIR-5・REPAIR-12・#2766）。
//!
//! CLI の create は core の `FileAuditSink`（fork 隔離。単一スレッド前提）の直前に `run_bounded_*` を通る。join の
//! 直後に `/proc/self/status` の `Threads:` がまだ減っていないと、監査が `isolation_unavailable` になり
//! `sec4_2480_create_rejected_destination_is_audited` が間欠失敗した。毎回の戻りで `Threads: 1` を具体値で照合する。
//! スレッド数は libtest では測れないため、`harness = false` の単一スレッド `main` で動かす。root 不要。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("bounded_worker_thread_settle: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::time::Duration;

    use fandhe_container_supervisor::supervisor_log::{
        LogRemoval, run_bounded_classified, run_bounded_waiting, run_log_removal_bounded,
    };

    const ROUNDS: usize = 500;
    const TIMEOUT: Duration = Duration::from_secs(5);

    fn threads() -> u64 {
        let s = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
        s.lines()
            .find_map(|l| l.strip_prefix("Threads:"))
            .and_then(|v| v.trim().parse().ok())
            .expect("Threads: line")
    }

    pub fn run() {
        assert_eq!(
            threads(),
            1,
            "precondition: main must start single-threaded"
        );
        for i in 0..ROUNDS {
            let r = run_bounded_classified(move || i * 2, TIMEOUT);
            assert_eq!(r, Ok(i * 2), "classified result at round {i}");
            assert_eq!(threads(), 1, "classified left extra threads at round {i}");

            let r = run_bounded_waiting(move || i + 1, TIMEOUT);
            assert_eq!(r, Ok(i + 1), "waiting result at round {i}");
            assert_eq!(threads(), 1, "waiting left extra threads at round {i}");

            let r = run_log_removal_bounded(|| {}, TIMEOUT);
            assert_eq!(r, LogRemoval::Finished, "removal result at round {i}");
            assert_eq!(threads(), 1, "removal left extra threads at round {i}");
        }
        println!(
            "bounded_worker_thread_settle: {} calls returned single-threaded",
            ROUNDS * 3
        );
    }
}
