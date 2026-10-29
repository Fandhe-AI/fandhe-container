//! exec の worker が seccomp の listener を親へ渡す経路の結合試験（SEC-4・SUP-6・#2385。`docs/design/audit-delivery.md`）。
//!
//! 本番の `run_command_with_pidfd` と同じ worker・受け渡し（`ListenerPolicy::Required`）を、試験専用の入口
//! `run_in_worker_with_listener_for_test` で任意の `work` から通す。worker の中では実カーネルで `NEW_LISTENER` 付きの
//! filter を載せ、listener を `SCM_RIGHTS` で親へ送り、親は検証して ACK を返す。親は worker の終了を待つ **前** に
//! 受信すること（相互待ちにならないこと）と、受け渡しの失敗（拒否・不着・期限切れ・ACK 無しの成功）が fail-closed に
//! なることを具体値で照合する。root・実コンテナは不要で、既定のテスト集合で実行する。
//!
//! 前提: 呼び出しプロセスの外側の filter が listener を既に持たないこと（持つ環境では `EBUSY` になる）。満たさない
//! 環境は skip せず失敗させる（`AGENTS.md`「実機前提でない試験」の注意）。受け渡しの後に worker に socket が残らないことの
//! 照合は、fork の前に採った socket の基準集合との差で見る（起動元から継承した socket は数えない。実行環境で結果が変わる
//! 前提を除く。#2603）。`inherited_socket_does_not_count_as_a_leak` が stdin を socket にした再実行で回帰を守る。
//!
//! #2544 の応答者の試験: filter は `USER_NOTIF` で載り、親が通知に同期で応答する。worker が拒否される syscall（`kcmp`）を
//! 発行し、(1) 実際の記録先（`FileAuditSink` の `@audit.log`）に 1 拒否 1 行が届き `EPERM` が返ること、(2) 複数回でも 1 拒否 1 件、
//! (3) 詰まった記録先でも応答期限で `EPERM` が返ること（REPAIR-5）、(4) 応答者がいないとき `ENOSYS` で閉じ許可に倒れないこと
//! を具体値で照合する。
//!
//! fork は単一スレッドの呼び出し元を要求するため、libtest ではなく `harness = false` の単一スレッド `main` で動かす。

#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn main() {
    println!("exec_seccomp_listener: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    linux::run();
}

// KCMP の syscall 番号・AUDIT_ARCH は x86_64 / aarch64 の値だけを持つため、同じ対象に閉じる（#3202・MVM-4）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::cell::Cell;
    use std::io::BufRead as _;
    use std::io::Write as _;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{AuditRecord, AuditSink};
    use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};
    use fandhe_container_supervisor::exec::{
        ExecListenerHandover, ExecResponderState, UserNotifTestMode,
        apply_seccomp_listener_for_test, default_audit_sink, hand_over_non_listener_for_test,
        open_socket_ids_for_test, run_in_worker_with_listener_for_test,
        run_in_worker_with_user_notif_for_test,
    };
    use fandhe_container_supervisor::seccomp_notify::NotifyConfig;

    /// `kcmp` の syscall 番号（拒否される ERRNO 側の syscall。アーキ別）。
    #[cfg(target_arch = "x86_64")]
    const KCMP_NR: u32 = 312;
    #[cfg(target_arch = "aarch64")]
    const KCMP_NR: u32 = 272;

    /// 子モードを選ぶ引数（`inherited_socket_does_not_count_as_a_leak` が自分自身を再実行するときに付ける）。
    const CHILD_FLAG: &str = "--inherited-socket-child";

    pub fn run() {
        if std::env::args().any(|a| a == CHILD_FLAG) {
            // 子モード: stdin が継承した socket の状態で、受け渡しの試験だけを通す。
            real_listener_is_handed_over_and_verified();
            println!("exec_seccomp_listener: child ok");
            return;
        }
        real_listener_is_handed_over_and_verified();
        non_listener_fd_is_rejected_and_worker_reaped();
        worker_failure_before_seccomp_is_returned_as_is();
        worker_success_without_handover_is_rejected();
        silent_worker_times_out_and_is_reaped();
        denial_reaches_the_audit_file_once_and_is_denied();
        each_denial_is_one_record();
        stuck_sink_is_answered_at_the_response_deadline();
        missing_responder_fails_closed();
        inherited_socket_does_not_count_as_a_leak();
        println!("exec_seccomp_listener: all scenarios passed");
    }

    /// fork の前に採る、今開いている socket の基準集合（`apply_seccomp_listener_for_test` が差だけを漏れとして数える。#2603）。
    fn baseline_sockets() -> Vec<String> {
        open_socket_ids_for_test().expect("list the open sockets")
    }

    /// 後始末（子 cgroup の削除に相当）の呼び出し回数を数える。
    fn counted(counter: &Cell<u32>) -> impl FnOnce() -> Result<(), TraitError> + '_ {
        move || {
            counter.set(counter.get() + 1);
            Ok(())
        }
    }

    /// worker が実 listener を作って渡すと、親は検証して ACK を返し、結果は `Verified`。
    fn real_listener_is_handed_over_and_verified() {
        let cleanups = Cell::new(0);
        let baseline = baseline_sockets();
        let outcome = run_in_worker_with_listener_for_test(
            Duration::from_secs(20),
            Duration::from_secs(10),
            counted(&cleanups),
            |sender| apply_seccomp_listener_for_test(sender, &baseline),
        )
        .unwrap_or_else(|e| {
            // EBUSY（外側の filter が listener を持つ）のときだけ原因の手がかりを付ける（#2603）。
            let hint = if e.code() == ErrorCode::FailedPrecondition {
                " (the caller's outer seccomp filter must not own a listener)"
            } else {
                ""
            };
            panic!("handover failed: {:?} {}{hint}", e.code(), e.message())
        });
        assert_eq!(outcome.seccomp_listener, ExecListenerHandover::Verified);
        assert_eq!(cleanups.get(), 1);
    }

    /// listener ではない fd は親が拒否し（段 `Seccomp`）、worker は待たずに止められて回収され、後始末はちょうど 1 回。
    fn non_listener_fd_is_rejected_and_worker_reaped() {
        let cleanups = Cell::new(0);
        let started = Instant::now();
        let err = run_in_worker_with_listener_for_test(
            Duration::from_secs(20),
            Duration::from_secs(10),
            counted(&cleanups),
            |sender| match hand_over_non_listener_for_test(sender) {
                // 親が拒否して閉じると、worker の ACK 待ちは HUP で終わり `Err` になる（期待どおり）。
                Err(_) => Ok(()),
                Ok(()) => Err(TraitError::new(
                    ErrorCode::Internal,
                    "the parent acknowledged a non-listener fd",
                )),
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(
            err.message(),
            "exec stage Seccomp: the received fd is not a seccomp notification fd"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(cleanups.get(), 1);
    }

    /// worker が seccomp の前に失敗したときは、その `code` / `message` が listener 側の失敗に隠されずにそのまま届く。
    fn worker_failure_before_seccomp_is_returned_as_is() {
        let cleanups = Cell::new(0);
        let err = run_in_worker_with_listener_for_test(
            Duration::from_secs(20),
            Duration::from_secs(10),
            counted(&cleanups),
            |sender| {
                drop(sender);
                Err(TraitError::new(
                    ErrorCode::PermissionDenied,
                    "exec stage Validate: refused before seccomp",
                ))
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(err.message(), "exec stage Validate: refused before seccomp");
        assert_eq!(cleanups.get(), 1);
    }

    /// worker が何も渡さずに成功を返しても、ACK 無しで進んだものとして `Internal`（fail-closed）で拒否される。
    fn worker_success_without_handover_is_rejected() {
        let cleanups = Cell::new(0);
        let err = run_in_worker_with_listener_for_test(
            Duration::from_secs(20),
            Duration::from_secs(10),
            counted(&cleanups),
            |sender| {
                drop(sender);
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(
            err.message(),
            "exec stage Seccomp: the exec worker finished without handing over the seccomp listener"
        );
        assert_eq!(cleanups.get(), 1);
    }

    /// 何も渡さず眠る worker は、期限で `Timeout` になり、待たずに止められて回収される。
    fn silent_worker_times_out_and_is_reaped() {
        let cleanups = Cell::new(0);
        let started = Instant::now();
        let err = run_in_worker_with_listener_for_test(
            Duration::from_secs(1),
            Duration::from_secs(1),
            counted(&cleanups),
            |sender| {
                let _keep = sender;
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(
            err.message(),
            "exec stage Seccomp: the seccomp listener was not delivered in time"
        );
        assert!(started.elapsed() < Duration::from_secs(8));
        assert_eq!(cleanups.get(), 1);
    }

    /// 起動元から継承した socket（stdin が socket）があっても、受け渡しの漏れとして数えない（#2603）。
    /// 自分自身を子として再実行し、stdin に socketpair の片端を渡して受け渡しの試験を通す。子の待ちには上限を設ける（REPAIR-5）。
    fn inherited_socket_does_not_count_as_a_leak() {
        use std::io::Read as _;
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;
        use std::process::{Command, Stdio};

        let (kept, given) = UnixStream::pair().expect("socketpair");
        let exe = std::env::current_exe().expect("current exe");
        let mut child = Command::new(exe)
            .arg(CHILD_FLAG)
            .stdin(Stdio::from(OwnedFd::from(given)))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the child");
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll the child") {
                break status;
            }
            if started.elapsed() > Duration::from_secs(60) {
                crate::reap::reap_or_report(&mut child, crate::reap::REAP_WITHIN);
                panic!("the child did not finish within 60s");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut out = String::new();
        let mut err = String::new();
        if let Some(mut o) = child.stdout.take() {
            let _ = o.read_to_string(&mut out);
        }
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut err);
        }
        drop(kept);
        assert!(
            status.success(),
            "status={status:?} stdout={out} stderr={err}"
        );
        assert!(
            out.contains("exec_seccomp_listener: child ok"),
            "stdout={out} stderr={err}"
        );
    }

    /// worker が `kcmp` を `times` 回発行した結果を親へ返す口。1 行 `pid errno_1,errno_2,... elapsed_ms_max`。
    fn probe_in_worker(
        sender: fandhe_container_core::exec::ExecListenerSender,
        writer: &std::io::PipeWriter,
        times: usize,
        baseline: &[String],
    ) -> Result<(), TraitError> {
        apply_seccomp_listener_for_test(sender, baseline)?;
        let mut errnos = Vec::new();
        let mut max_ms = 0u128;
        for _ in 0..times {
            let started = Instant::now();
            let errno = fandhe_container_core::exec::kcmp_self_errno_for_test().unwrap_or(0);
            max_ms = max_ms.max(started.elapsed().as_millis());
            errnos.push(errno.to_string());
        }
        let line = format!("{} {} {}\n", std::process::id(), errnos.join(","), max_ms);
        let mut w = writer;
        w.write_all(line.as_bytes())
            .map_err(|_| TraitError::new(ErrorCode::Internal, "failed to report the probe result"))
    }

    /// 親が受けた `probe_in_worker` の報告: `(worker の pid, errno の列, 最大の所要 ms)`。
    fn read_probe(reader: std::io::PipeReader) -> (u32, Vec<i32>, u128) {
        let mut line = String::new();
        std::io::BufReader::new(reader)
            .read_line(&mut line)
            .expect("read the probe line");
        let mut it = line.split_whitespace();
        let pid = it.next().expect("pid").parse().expect("pid number");
        let errnos = it
            .next()
            .expect("errnos")
            .split(',')
            .map(|e| e.parse().expect("errno number"))
            .collect();
        let ms = it.next().expect("ms").parse().expect("ms number");
        (pid, errnos, ms)
    }

    /// 0700 の使い捨てディレクトリ（状態ルート。`FileAuditSink` の親ディレクトリ検査を満たす）。
    fn private_dir() -> std::path::PathBuf {
        use std::os::unix::fs::DirBuilderExt as _;
        let base = std::fs::canonicalize(std::env::temp_dir()).expect("canonical temp dir");
        let dir = base.join(format!(
            "fandhe-exec-notif-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("create private dir");
        dir
    }

    /// 記録を数える記録先。
    #[derive(Default)]
    struct CountingSink {
        records: Mutex<Vec<AuditRecord>>,
    }

    impl AuditSink for CountingSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            self.records.lock().unwrap().push(record.clone());
            Ok(())
        }
    }

    /// `record_until` が期限まで眠って `Timeout` を返す記録先（詰まった記録先）。
    struct StuckSink;

    impl AuditSink for StuckSink {
        fn record(&self, _record: &AuditRecord) -> Result<(), TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "unexpected record"))
        }
        fn record_until(&self, _record: &AuditRecord, deadline: Instant) -> Result<(), TraitError> {
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            Err(TraitError::new(ErrorCode::Timeout, "stuck"))
        }
    }

    /// 実際の記録先（`FileAuditSink` → `@audit.log`）に、exec で拒否された syscall が 1 拒否 1 行で届き、コマンド側は
    /// `EPERM` を受ける。集計は `recorded` が 1 で、応答者は `Served`（SEC-4・SUP-6・#2544）。
    fn denial_reaches_the_audit_file_once_and_is_denied() {
        let dir = private_dir();
        let result = std::panic::catch_unwind(|| {
            let sink = default_audit_sink(Some(dir.clone())).expect("production audit sink");
            let id = ContainerId::new("web-1").unwrap();
            let (reader, writer) = std::io::pipe().unwrap();
            let baseline = baseline_sockets();
            let outcome = run_in_worker_with_user_notif_for_test(
                Duration::from_secs(30),
                Duration::from_secs(10),
                || Ok(()),
                &sink,
                Some(&id),
                NotifyConfig::default(),
                UserNotifTestMode::Respond,
                |sender| probe_in_worker(sender, &writer, 1, &baseline),
            )
            .unwrap_or_else(|e| panic!("{:?} {}", e.code(), e.message()));
            let (worker_pid, errnos, _) = read_probe(reader);
            assert_eq!(errnos, vec![1], "EPERM");
            assert_eq!(outcome.seccomp_audit.responder, ExecResponderState::Served);
            assert_eq!(outcome.seccomp_audit.counts.recorded, 1);
            assert_eq!(outcome.seccomp_audit.counts.unrecorded, 0);
            let text = std::fs::read_to_string(dir.join("@audit.log")).expect("read audit file");
            assert_eq!(text.lines().count(), 1, "{text}");
            let line = text.lines().next().expect("one line");
            assert!(line.contains("\"layer\":\"seccomp\""), "{line}");
            assert!(line.contains(&format!("\"pid\":{worker_pid},")), "{line}");
            assert!(line.contains(&format!("\"syscall\":{KCMP_NR},")), "{line}");
            assert!(line.ends_with("\"container_id\":\"web-1\"}"), "{line}");
        });
        let _ = std::fs::remove_dir_all(&dir);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    /// 同じ syscall を 3 回拒否されると、記録はちょうど 3 件（1 拒否 1 件）で、3 回とも `EPERM`。
    fn each_denial_is_one_record() {
        let sink = CountingSink::default();
        let id = ContainerId::new("web-1").unwrap();
        let (reader, writer) = std::io::pipe().unwrap();
        let baseline = baseline_sockets();
        let outcome = run_in_worker_with_user_notif_for_test(
            Duration::from_secs(30),
            Duration::from_secs(10),
            || Ok(()),
            &sink,
            Some(&id),
            NotifyConfig::default(),
            UserNotifTestMode::Respond,
            |sender| probe_in_worker(sender, &writer, 3, &baseline),
        )
        .unwrap_or_else(|e| panic!("{:?} {}", e.code(), e.message()));
        let (worker_pid, errnos, _) = read_probe(reader);
        assert_eq!(errnos, vec![1, 1, 1]);
        assert_eq!(outcome.seccomp_audit.counts.recorded, 3);
        let recs = sink.records.lock().unwrap();
        assert_eq!(recs.len(), 3);
        for r in recs.iter() {
            assert_eq!(r.pid().get(), worker_pid);
            assert_eq!(r.syscall().map(|s| s.get()), Some(KCMP_NR));
            assert_eq!(r.container_id().map(ContainerId::as_str), Some("web-1"));
        }
    }

    /// 詰まった記録先でも、応答期限（100ms）で `EPERM` が返り、コマンドは期限どおりに進む（REPAIR-5）。
    /// 記録は打ち切られて `unrecorded` が 1。
    fn stuck_sink_is_answered_at_the_response_deadline() {
        let config = NotifyConfig::default()
            .with_response_deadline(Duration::from_millis(100))
            .unwrap();
        let (reader, writer) = std::io::pipe().unwrap();
        let baseline = baseline_sockets();
        let outcome = run_in_worker_with_user_notif_for_test(
            Duration::from_secs(30),
            Duration::from_secs(10),
            || Ok(()),
            &StuckSink,
            None,
            config,
            UserNotifTestMode::Respond,
            |sender| probe_in_worker(sender, &writer, 1, &baseline),
        )
        .unwrap_or_else(|e| panic!("{:?} {}", e.code(), e.message()));
        let (_, errnos, ms) = read_probe(reader);
        assert_eq!(errnos, vec![1], "EPERM");
        assert!(ms < 2000, "the denial took {ms} ms");
        assert_eq!(outcome.seccomp_audit.responder, ExecResponderState::Served);
        assert_eq!(outcome.seccomp_audit.counts.unrecorded, 1);
        assert_eq!(outcome.seccomp_audit.counts.recorded, 0);
    }

    /// 応答者がいない（ACK の直後に listener を閉じる）とき、拒否された syscall は `ENOSYS`（38）で戻る。許可（成功）にも
    /// 停止にも倒れない（fail-closed）。応答者の状態は `Lost` で表に出る。
    fn missing_responder_fails_closed() {
        let sink = CountingSink::default();
        let (reader, writer) = std::io::pipe().unwrap();
        let baseline = baseline_sockets();
        let started = Instant::now();
        let outcome = run_in_worker_with_user_notif_for_test(
            Duration::from_secs(30),
            Duration::from_secs(10),
            || Ok(()),
            &sink,
            None,
            NotifyConfig::default(),
            UserNotifTestMode::AckThenDrop,
            |sender| probe_in_worker(sender, &writer, 1, &baseline),
        )
        .unwrap_or_else(|e| panic!("{:?} {}", e.code(), e.message()));
        let (_, errnos, _) = read_probe(reader);
        assert_eq!(errnos, vec![38], "ENOSYS");
        assert_eq!(outcome.seccomp_audit.responder, ExecResponderState::Lost);
        assert!(sink.records.lock().unwrap().is_empty());
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
