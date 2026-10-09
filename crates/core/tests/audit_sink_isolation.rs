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
//! - 子は呼び出し側の fd（3 以上）を受け継がない（D 状態で残った子が `flock`・pipe の書き込み端を持ち続けない）
//! - 両経路が失敗し通知先も止まる: `record` は `INTERNAL` を期限内に返し、スレッドは残らず、続く `record` も
//!   fork できる（以後の exec の worker 生成を妨げない）
//! - 未回収の子が上限に達していても、両経路失敗の通知 1 行はスレッドでの出し直しで必ず出る。上限の子を
//!   解放すると回収されて fork が再開する
//! - 通知の子が異常終了（panic）しても、通知 1 行はスレッドでの出し直しで出る（1 行だけ）
//! - 複数スレッドのプロセス: fork できないため主経路は試行せず `isolation_unavailable` で代替経路へ進む
//! - `SIGCHLD` が `SIG_IGN`（子が自動回収され `waitpid` が `ECHILD`）: 主経路の成功を失敗と取り違えず代替経路へ
//!   二重に記録しない。失敗種別・時間切れ・通知も同じく届く（最後に実行し、終わったら `SIG_DFL` に戻す）
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

    /// 通知の出力先。
    #[derive(Clone)]
    enum Notify {
        /// 捨てる。
        Discard,
        /// 無期限に止まる。
        Stuck,
        /// ファイルへ追記する（届いた行を照合する）。
        File(PathBuf),
        /// 子プロセスの中では panic し、親（試験プロセス）ではファイルへ追記する。
        PanicInChild(PathBuf),
    }

    fn append_to(path: &Path) -> Box<dyn Write> {
        Box::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap(),
        )
    }

    fn sink(primary: Primary, ok: bool, notify: Notify, marker: PathBuf) -> (FileAuditSink, Seen) {
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let parent = std::process::id();
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
                match &notify {
                    Notify::Discard => Box::new(std::io::sink()),
                    Notify::Stuck => Box::new(Stuck),
                    Notify::File(path) => append_to(path),
                    Notify::PanicInChild(path) => {
                        if std::process::id() != parent {
                            // 子だけ異常終了させる（panic フックを通さず標準エラーを汚さない）。
                            std::panic::resume_unwind(Box::new("notify child aborts"));
                        }
                        append_to(path)
                    }
                }
            }),
            Duration::from_millis(200),
        );
        (sink, seen)
    }

    /// 両経路失敗（主経路は `isolation_unavailable`）の通知 1 行（`AuditWriteFailure::write_json_line`）。
    const UNAVAILABLE_NOTICE: &str = "{\"event\":\"audit_write_failure\",\"code\":\"INTERNAL\",\"primary\":\"isolation_unavailable\",\"primary_code\":\"UNAVAILABLE\",\"fallback\":\"fallback_unavailable\",\"fallback_code\":\"UNIMPLEMENTED\"}\n";
    /// 両経路失敗（主経路は `relative_path`）の通知 1 行。
    const RELATIVE_NOTICE: &str = "{\"event\":\"audit_write_failure\",\"code\":\"INTERNAL\",\"primary\":\"relative_path\",\"primary_code\":\"INVALID_ARGUMENT\",\"fallback\":\"fallback_unavailable\",\"fallback_code\":\"UNIMPLEMENTED\"}\n";

    fn relative_primary() -> Primary {
        Arc::new(|_, _| AuditFileWriter::open(Path::new("relative/audit.log")).map(|_| ()))
    }

    /// 出し直しのスレッドを join した後、`/proc/self/status` の `Threads:` が 1 に戻るまで待つ（join の完了
    /// からスレッドの解放までの短い間は 2 と読める）。戻らなければ失敗する。
    fn wait_single_threaded() {
        let deadline = Instant::now() + Duration::from_secs(2);
        while threads() != 1 {
            assert!(
                Instant::now() < deadline,
                "a notifier thread was left behind"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// 未回収の子が 0 件になるまで待つ（解放した子は EOF で終了する）。
    fn wait_unreaped_cleared() {
        let deadline = Instant::now() + Duration::from_secs(5);
        while FileAuditSink::unreaped_children_for_test() != 0 {
            assert!(
                Instant::now() < deadline,
                "unreaped children were not reaped"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
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
        child_does_not_inherit_caller_fds();
        stuck_notifier_leaves_no_thread_and_next_record_works();
        too_many_unreaped_still_emits_the_notice();
        panicking_notify_child_is_retried_on_a_thread();
        multi_threaded_process_skips_the_primary();
        // `SIGCHLD` の disposition を変えるため最後に実行する。
        assert!(FileAuditSink::set_child_signal_ignored_for_test(true));
        sigchld_ignored_keeps_results_and_records_once();
        assert!(FileAuditSink::set_child_signal_ignored_for_test(false));
        println!("audit_sink_isolation: ok");
    }

    /// REPAIR-5・TASK-163: 子の書き込み結果が親から見え、親にスレッドが残らない。
    fn healthy_primary_is_persisted_by_the_child() {
        let marker = tmp_marker("ok");
        let _ = std::fs::remove_file(&marker);
        let primary: Primary = Arc::new(|path, _| {
            std::fs::write(path, b"persisted-by-child").map_err(|_| unreachable_err())
        });
        let (sink, seen) = sink(primary, false, Notify::Discard, marker.clone());
        sink.record(&record()).unwrap();
        assert_eq!(std::fs::read(&marker).unwrap(), b"persisted-by-child");
        assert_eq!(*seen.lock().unwrap(), vec![]);
        assert_eq!(threads(), 1);
        let _ = std::fs::remove_file(&marker);
    }

    /// REPAIR-5・SEC-4・TASK-163: 主経路が無期限に止まっても期限内に代替経路へ進み、スレッドを残さない。
    fn stuck_primary_falls_back_within_the_limit() {
        let primary: Primary = Arc::new(|_, _| hang());
        let (sink, seen) = sink(primary, true, Notify::Discard, tmp_marker("stuck"));
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
        let (sink, seen) = sink(primary, true, Notify::Discard, tmp_marker("kind"));
        sink.record(&record()).unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![AuditWriteErrorKind::RelativePath]
        );
        assert_eq!(threads(), 1);
    }

    /// SEC-4・REPAIR-5・CORE-2・#1594: 子は `child` の前に fd 3 以上を閉じる（結果 pipe の書き込み側 1 本だけ残る）。
    /// 呼び出し側が開いている fd（`BundleLock` 等の `flock` の代わり）は子から見えない。
    fn child_does_not_inherit_caller_fds() {
        use std::os::fd::AsRawFd;
        let held_path = tmp_marker("held");
        let held = std::fs::File::create(&held_path).unwrap();
        let held_fd = held.as_raw_fd();
        assert!(held_fd >= 3);
        let marker = tmp_marker("fds");
        let _ = std::fs::remove_file(&marker);
        let primary: Primary = Arc::new(|path, _| {
            // 開いている fd（3 以上）の一覧。`/proc/self/fd/N` の有無で調べ、列挙用の fd を開かない。
            let mut before: Vec<i32> = Vec::new();
            for fd in 3..1024 {
                if Path::new(&format!("/proc/self/fd/{fd}")).exists() {
                    before.push(fd);
                }
            }
            let text = before
                .iter()
                .map(|fd| fd.to_string())
                .collect::<Vec<_>>()
                .join(",");
            std::fs::write(path, text).map_err(|_| unreachable_err())
        });
        let (sink, seen) = sink(primary, false, Notify::Discard, marker.clone());
        sink.record(&record()).unwrap();
        assert_eq!(*seen.lock().unwrap(), vec![]);
        let listed = std::fs::read_to_string(&marker).unwrap();
        let fds: Vec<i32> = listed.split(',').map(|v| v.parse().unwrap()).collect();
        // 残るのは結果 pipe の書き込み側 1 本だけで、呼び出し側の fd は含まれない。
        assert_eq!(fds.len(), 1, "{listed}");
        assert!(!fds.contains(&held_fd), "{listed}");
        drop(held);
        let _ = std::fs::remove_file(&held_path);
        let _ = std::fs::remove_file(&marker);
    }

    /// REPAIR-5・SUP-6・TASK-163: 両経路が失敗し通知先も止まっても `record` は期限内に `INTERNAL` を返し、
    /// スレッドを残さない。続く `record` も fork できる（以後の exec の worker 生成を妨げない）。
    fn stuck_notifier_leaves_no_thread_and_next_record_works() {
        let primary: Primary =
            Arc::new(|_, _| AuditFileWriter::open(Path::new("relative/audit.log")).map(|_| ()));
        let (sink, seen) = sink(primary, false, Notify::Stuck, tmp_marker("notify"));
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
        let (sink, seen) = sink(primary, true, Notify::Discard, marker.clone());
        sink.record(&record()).unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![AuditWriteErrorKind::IsolationUnavailable]
        );
        assert!(!marker.exists());
        drop(release_tx);
        helper.join().unwrap();
    }

    /// SEC-4・REPAIR-4・REPAIR-5・#1594: 未回収の子が上限（D 状態の子が溜まった状態の再現）でも、両経路失敗の
    /// 通知 1 行がちょうど 1 回出る（子を fork できないためスレッドで出し直し、完了後にスレッドは残らない）。
    /// 子を解放すると回収され、続く `record` は再び子で主経路を書く。
    fn too_many_unreaped_still_emits_the_notice() {
        let notice = tmp_marker("unreaped-notice");
        let _ = std::fs::remove_file(&notice);
        let release = FileAuditSink::hold_unreaped_children_for_test().unwrap();
        assert_eq!(FileAuditSink::unreaped_children_for_test(), 4);
        let primary: Primary = Arc::new(|path, _| {
            std::fs::write(path, b"must-not-run").map_err(|_| unreachable_err())
        });
        let marker = tmp_marker("unreaped");
        let _ = std::fs::remove_file(&marker);
        let (held, seen) = sink(primary, false, Notify::File(notice.clone()), marker.clone());
        let e = held.record(&record()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Internal);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![AuditWriteErrorKind::IsolationUnavailable]
        );
        assert!(!marker.exists());
        assert_eq!(
            std::fs::read_to_string(&notice).unwrap(),
            UNAVAILABLE_NOTICE
        );
        wait_single_threaded();
        drop(release);
        wait_unreaped_cleared();
        // fork が再開し、主経路が子で書く（代替経路へは回らない）。
        let ok_primary: Primary = Arc::new(|path, _| {
            std::fs::write(path, b"persisted-after-release").map_err(|_| unreachable_err())
        });
        let (resumed, seen) = sink(ok_primary, false, Notify::Discard, marker.clone());
        resumed.record(&record()).unwrap();
        assert_eq!(std::fs::read(&marker).unwrap(), b"persisted-after-release");
        assert_eq!(*seen.lock().unwrap(), vec![]);
        let _ = std::fs::remove_file(&marker);
        let _ = std::fs::remove_file(&notice);
    }

    /// SEC-4・REPAIR-4・#1594: 通知の子が異常終了（panic）しても、通知 1 行はスレッドでの出し直しで 1 行だけ出る。
    fn panicking_notify_child_is_retried_on_a_thread() {
        let notice = tmp_marker("panic-notice");
        let _ = std::fs::remove_file(&notice);
        let (sink, seen) = sink(
            relative_primary(),
            false,
            Notify::PanicInChild(notice.clone()),
            tmp_marker("panic"),
        );
        let e = sink.record(&record()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Internal);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![AuditWriteErrorKind::RelativePath]
        );
        assert_eq!(std::fs::read_to_string(&notice).unwrap(), RELATIVE_NOTICE);
        wait_single_threaded();
        let _ = std::fs::remove_file(&notice);
    }

    /// REPAIR-5・SEC-4・CORE-1・#1594: `SIGCHLD` が `SIG_IGN`（子が自動回収され `waitpid` が `ECHILD`）でも、
    /// 子の結果を結果 pipe で受けるため取り違えない。主経路の成功は代替経路へ回らず（二重記録なし）、失敗種別・
    /// 時間切れ・通知 1 行も届く。時間切れの子は回収済みとして追跡に残らない。
    fn sigchld_ignored_keeps_results_and_records_once() {
        // 成功: 子が書き、代替経路は呼ばれない。
        let marker = tmp_marker("ign-ok");
        let _ = std::fs::remove_file(&marker);
        let primary: Primary = Arc::new(|path, _| {
            std::fs::write(path, b"persisted-with-sigchld-ignored").map_err(|_| unreachable_err())
        });
        let (sink_ok, seen) = sink(primary, false, Notify::Discard, marker.clone());
        for _ in 0..3 {
            sink_ok.record(&record()).unwrap();
        }
        assert_eq!(
            std::fs::read(&marker).unwrap(),
            b"persisted-with-sigchld-ignored"
        );
        assert_eq!(*seen.lock().unwrap(), vec![]);
        assert_eq!(threads(), 1);
        let _ = std::fs::remove_file(&marker);

        // 失敗種別が代替経路へ届く。
        let (sink_kind, seen) = sink(
            relative_primary(),
            true,
            Notify::Discard,
            tmp_marker("ign-k"),
        );
        sink_kind.record(&record()).unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![AuditWriteErrorKind::RelativePath]
        );

        // 時間切れ: 期限内に戻り、子は追跡に残らない。
        let (sink_stuck, seen) = sink(
            Arc::new(|_, _| hang()),
            true,
            Notify::Discard,
            tmp_marker("ign-s"),
        );
        let start = Instant::now();
        sink_stuck.record(&record()).unwrap();
        let took = start.elapsed();
        assert!(took >= Duration::from_millis(400), "{took:?}");
        assert!(took < Duration::from_secs(5), "{took:?}");
        assert_eq!(
            *seen.lock().unwrap(),
            vec![AuditWriteErrorKind::IsolationTimeout]
        );
        assert_eq!(FileAuditSink::unreaped_children_for_test(), 0);

        // 両経路失敗の通知は子で 1 行だけ出る（スレッドで出し直さない）。
        let notice = tmp_marker("ign-notice");
        let _ = std::fs::remove_file(&notice);
        let (sink_fail, _) = sink(
            relative_primary(),
            false,
            Notify::File(notice.clone()),
            tmp_marker("ign-f"),
        );
        let e = sink_fail.record(&record()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Internal);
        assert_eq!(std::fs::read_to_string(&notice).unwrap(), RELATIVE_NOTICE);
        assert_eq!(threads(), 1);
        let _ = std::fs::remove_file(&notice);
    }

    fn unreachable_err() -> AuditWriteError {
        AuditWriteError::fallback_unavailable()
    }
}
