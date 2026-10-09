//! `FileAuditSink` の主経路・失敗通知の子プロセス隔離の結合試験（REPAIR-5・SEC-4・TASK-163 追補・#1594）。Linux 専用。
//!
//! 主経路のファイル I/O（`write_all`・`sync_data`）と失敗通知（stderr への出力）は期限を付けられないため、
//! `FileAuditSink` は fork した使い捨ての子プロセスで実行し、親は期限まで待って SIGKILL する。本試験は
//! 公開の差し込み入口 `FileAuditSink::isolated_for_test`（`exec-test-support` feature）で、無期限に止まる主経路・
//! 通知先を作り、次を具体値で照合する。
//!
//! - 正常: 子が書いた結果が親から見え、`record` が `Ok`。親のスレッド数は 1 のまま
//! - 主経路が止まる: 期限内に `record` が戻り、代替経路へ `isolation_timeout` が渡る。スレッドは残らない
//! - 主経路の失敗種別が子の終了コード越しに代替経路へ届く（`relative_path`）
//! - 両経路が失敗し通知先も止まる: `record` は `INTERNAL` を期限内に返し、スレッドは残らず、続く `record` も
//!   fork できる（以後の exec の worker 生成を妨げない）
//! - 複数スレッドのプロセス: fork できないため主経路は試行せず `isolation_unavailable` で代替経路へ進む
//!
//! fork は呼び出しプロセスが単一スレッドであることを要求するため、`harness = false` の単一スレッド `main` で動かす。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("audit_sink_isolation: Linux only, not applicable on this OS");
}

/// feature なしのビルドでは差し込み入口が無い。検証せずに成功しない（fail-closed）。
#[cfg(all(target_os = "linux", not(feature = "exec-test-support")))]
fn main() {
    eprintln!("audit_sink_isolation: not verified; the exec-test-support feature is not enabled");
    std::process::exit(2);
}

#[cfg(all(target_os = "linux", feature = "exec-test-support"))]
fn main() {
    linux::run();
}

#[cfg(all(target_os = "linux", feature = "exec-test-support"))]
mod linux {
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{
        AuditEvent, AuditFallback, AuditFileWriter, AuditPid, AuditRecord, AuditSink,
        AuditSyscallArch, AuditSyscallNr, AuditTimestamp, AuditWriteError, AuditWriteErrorKind,
        FileAuditSink,
    };
    use fandhe_container_core::traits::ErrorCode;

    type Seen = Arc<Mutex<Vec<AuditWriteErrorKind>>>;
    type Primary = Arc<dyn Fn(&Path, &AuditRecord) -> Result<(), AuditWriteError> + Send + Sync>;

    fn record() -> AuditRecord {
        AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5)),
            AuditPid::new(4242).unwrap(),
            AuditEvent::Seccomp {
                syscall: AuditSyscallNr::new(272).unwrap(),
                arch: AuditSyscallArch::from_raw(0xC000_003E),
            },
        )
    }

    /// 呼ばれた時の主経路の失敗種別を記録し、`ok` ならば成功する代替経路。
    struct Rec {
        seen: Seen,
        ok: bool,
    }

    impl AuditFallback for Rec {
        fn record_fallback(
            &mut self,
            _r: &AuditRecord,
            primary: &AuditWriteError,
        ) -> Result<(), AuditWriteError> {
            self.seen.lock().unwrap().push(primary.kind());
            if self.ok {
                Ok(())
            } else {
                Err(AuditWriteError::fallback_unavailable())
            }
        }
    }

    /// 無期限に止まる（ストレージ停止・満杯パイプ相当）。
    fn hang() -> ! {
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    struct Stuck;

    impl Write for Stuck {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            hang()
        }
        fn flush(&mut self) -> std::io::Result<()> {
            hang()
        }
    }

    fn threads() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("Threads:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap()
    }

    fn sink(
        primary: Primary,
        ok: bool,
        notify_stuck: bool,
        marker: PathBuf,
    ) -> (FileAuditSink, Seen) {
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let sink = FileAuditSink::isolated_for_test(
            marker.clone(),
            primary,
            Duration::from_millis(400),
            Arc::new(move || {
                Box::new(Rec {
                    seen: s.clone(),
                    ok,
                })
            }),
            Arc::new(move || -> Box<dyn Write> {
                if notify_stuck {
                    Box::new(Stuck)
                } else {
                    Box::new(std::io::sink())
                }
            }),
            Duration::from_millis(200),
        );
        (sink, seen)
    }

    fn tmp_marker(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fandhe-audit-isolation-{tag}-{}",
            std::process::id()
        ))
    }

    pub(super) fn run() {
        assert_eq!(threads(), 1, "the test binary must start single-threaded");
        healthy_primary_is_persisted_by_the_child();
        stuck_primary_falls_back_within_the_limit();
        primary_error_kind_reaches_the_fallback();
        stuck_notifier_leaves_no_thread_and_next_record_works();
        multi_threaded_process_skips_the_primary();
        println!("audit_sink_isolation: ok");
    }

    /// REPAIR-5・TASK-163: 子の書き込み結果が親から見え、親にスレッドが残らない。
    fn healthy_primary_is_persisted_by_the_child() {
        let marker = tmp_marker("ok");
        let _ = std::fs::remove_file(&marker);
        let primary: Primary = Arc::new(|path, _| {
            std::fs::write(path, b"persisted-by-child").map_err(|_| unreachable_err())
        });
        let (sink, seen) = sink(primary, false, false, marker.clone());
        sink.record(&record()).unwrap();
        assert_eq!(std::fs::read(&marker).unwrap(), b"persisted-by-child");
        assert_eq!(*seen.lock().unwrap(), vec![]);
        assert_eq!(threads(), 1);
        let _ = std::fs::remove_file(&marker);
    }

    /// REPAIR-5・SEC-4・TASK-163: 主経路が無期限に止まっても期限内に代替経路へ進み、スレッドを残さない。
    fn stuck_primary_falls_back_within_the_limit() {
        let primary: Primary = Arc::new(|_, _| hang());
        let (sink, seen) = sink(primary, true, false, tmp_marker("stuck"));
        let start = Instant::now();
        sink.record(&record()).unwrap();
        let took = start.elapsed();
        assert!(took >= Duration::from_millis(400), "{took:?}");
        assert!(took < Duration::from_secs(5), "{took:?}");
        assert_eq!(
            *seen.lock().unwrap(),
            vec![AuditWriteErrorKind::IsolationTimeout]
        );
        assert_eq!(threads(), 1);
    }

    /// SEC-4・TASK-163: 子の失敗種別が終了コード越しに代替経路へ届く。
    fn primary_error_kind_reaches_the_fallback() {
        let primary: Primary = Arc::new(|_, _| {
            // 相対パスの open は `relative_path`（公開の入口だけで作れる失敗種別）。
            AuditFileWriter::open(Path::new("relative/audit.log")).map(|_| ())
        });
        let (sink, seen) = sink(primary, true, false, tmp_marker("kind"));
        sink.record(&record()).unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![AuditWriteErrorKind::RelativePath]
        );
        assert_eq!(threads(), 1);
    }

    /// REPAIR-5・SUP-6・TASK-163: 両経路が失敗し通知先も止まっても `record` は期限内に `INTERNAL` を返し、
    /// スレッドを残さない。続く `record` も fork できる（以後の exec の worker 生成を妨げない）。
    fn stuck_notifier_leaves_no_thread_and_next_record_works() {
        let primary: Primary =
            Arc::new(|_, _| AuditFileWriter::open(Path::new("relative/audit.log")).map(|_| ()));
        let (sink, seen) = sink(primary, false, true, tmp_marker("notify"));
        for round in 1..=3 {
            let start = Instant::now();
            let e = sink.record(&record()).unwrap_err();
            assert_eq!(e.code(), ErrorCode::Internal);
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "{:?}",
                start.elapsed()
            );
            assert_eq!(threads(), 1, "round {round}");
            assert_eq!(seen.lock().unwrap().len(), round);
        }
    }

    /// REPAIR-5・TASK-163: 複数スレッドのプロセスでは fork できず、主経路を試行せず代替経路へ進む。
    fn multi_threaded_process_skips_the_primary() {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let helper = std::thread::spawn(move || {
            let _ = release_rx.recv();
        });
        let marker = tmp_marker("mt");
        let _ = std::fs::remove_file(&marker);
        let primary: Primary = Arc::new(|path, _| {
            std::fs::write(path, b"must-not-run").map_err(|_| unreachable_err())
        });
        let (sink, seen) = sink(primary, true, false, marker.clone());
        sink.record(&record()).unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![AuditWriteErrorKind::IsolationUnavailable]
        );
        assert!(!marker.exists());
        drop(release_tx);
        helper.join().unwrap();
    }

    fn unreachable_err() -> AuditWriteError {
        AuditWriteError::fallback_unavailable()
    }
}
