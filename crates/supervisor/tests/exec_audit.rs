//! exec の対象の拒否が監査ログへ 1 件ずつ記録されることの結合試験（SEC-4・SUP-6・TASK-163 追補・#1465・REPAIR-12）。
//!
//! 本番の `exec::run_command` を、自プロセスの pid を「稼働中コンテナの pid」とした記録に対して呼ぶ。自プロセスは
//! 入れ子の PID namespace の PID 1 ではないため、worker 内の `identify_pid1` が違反 `exec_target_not_nested_pid1`
//! で拒否する（`setns` の前に拒否されるので root・実コンテナは不要）。この拒否が親プロセス側で層 `exec_target` の
//! レコード 1 件になること、ファイル主経路（`AuditFileWriter`）の JSON Lines 1 行まで届くこと、記録の失敗で拒否が
//! 覆らないこと、記録の対象外（稼働中でない記録）は 0 件であることを具体値で照合する。
//!
//! fork は呼び出しプロセスが単一スレッドであることを要求するため、`harness = false` の単一スレッド `main` で動かす
//! （`exec_timeout` と同じ。root・実コンテナ不要で既定のテスト集合で実行する）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("exec_audit: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::num::NonZeroU32;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::Duration;

    use fandhe_container_core::audit_log::{
        AuditDelivery, AuditFileWriter, AuditLayer, AuditRecord, AuditSink,
    };
    use fandhe_container_core::traits::{
        CgroupPlacement, CgroupScope, ContainerId, ContainerStatus, ErrorCode, StateRecord,
        StateRevision, TraitError,
    };
    use fandhe_container_supervisor::exec::{ExecRequest, run_command};

    pub fn run() {
        rejection_is_recorded_once_with_reason_and_no_path();
        rejection_reaches_the_audit_file_one_line_per_rejection();
        sink_failure_does_not_overturn_the_rejection();
        non_running_record_is_not_audited();
        println!("exec_audit: all scenarios passed");
    }

    /// メモリ上の sink。`fail` なら記録に失敗する。
    struct VecSink {
        records: Mutex<Vec<AuditRecord>>,
        fail: bool,
    }

    impl VecSink {
        fn new(fail: bool) -> Self {
            Self {
                records: Mutex::new(Vec::new()),
                fail,
            }
        }

        fn snapshot(&self) -> Vec<AuditRecord> {
            self.records.lock().expect("sink lock").clone()
        }
    }

    impl AuditSink for VecSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            if self.fail {
                return Err(TraitError::new(ErrorCode::Internal, "sink failed"));
            }
            self.records.lock().expect("sink lock").push(record.clone());
            Ok(())
        }
    }

    /// 一時ディレクトリの監査ファイルへ書く sink（`AuditFileWriter` を `Mutex` で包む本番相当のアダプタ）。
    struct FileSink(Mutex<AuditFileWriter>);

    impl AuditSink for FileSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            self.0
                .lock()
                .map_err(|_| TraitError::new(ErrorCode::Internal, "poisoned"))?
                .write_record(record)
                .map_err(|_| TraitError::new(ErrorCode::Internal, "audit write failed"))
        }
    }

    fn cid() -> ContainerId {
        ContainerId::new("c1").expect("container id")
    }

    /// 自プロセスの pid を記録 pid とする稼働中の記録（cgroup 配置あり）。
    fn running_record_of_self() -> StateRecord {
        let pid = NonZeroU32::new(std::process::id());
        StateRecord::new(
            ContainerStatus::running(cid(), pid),
            std::env::temp_dir().join("b"),
            StateRevision::from_raw(1),
        )
        .expect("state record")
        .with_cgroup(CgroupPlacement::new(
            CgroupScope::new("/user.slice/x.scope").expect("scope"),
            StateRevision::from_raw(7),
        ))
    }

    fn request() -> ExecRequest {
        ExecRequest::new("/bin/true", ["true"]).expect("request")
    }

    const REJECTION: &str = "exec stage SetNs: the exec target is not PID 1 of a directly nested PID namespace \
         (violation: exec_target/exec_target_not_nested_pid1, SUP-6)";

    /// SEC-4・SUP-6: 拒否 1 回 = レコード 1 件。層 `exec_target`・理由コード・パスなし・親（自）プロセスの PID。
    fn rejection_is_recorded_once_with_reason_and_no_path() {
        let sink = VecSink::new(false);
        let rejected = run_command(
            &running_record_of_self(),
            &request(),
            Duration::from_secs(30),
            &sink,
        )
        .expect_err("a non-nested pid must be rejected");
        assert_eq!(rejected.error.code(), ErrorCode::FailedPrecondition);
        assert_eq!(rejected.error.message(), REJECTION);
        assert_eq!(rejected.delivery, AuditDelivery::Recorded);
        let recs = sink.snapshot();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].layer(), AuditLayer::ExecTarget);
        assert_eq!(
            recs[0].reason().map(|r| r.as_str()),
            Some("exec_target_not_nested_pid1")
        );
        assert_eq!(recs[0].path(), None);
        assert_eq!(recs[0].syscall(), None);
        assert_eq!(recs[0].pid().get(), std::process::id());
    }

    /// 0700 の使い捨てディレクトリ（`AuditFileWriter::open` の親ディレクトリ検査を満たす）。
    fn private_dir() -> PathBuf {
        use std::os::unix::fs::DirBuilderExt as _;
        let base = std::fs::canonicalize(std::env::temp_dir()).expect("canonical temp dir");
        let dir = base.join(format!(
            "fandhe-exec-audit-{}-{}",
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

    /// SEC-4・SUP-6: 記録は監査ファイルの JSON Lines まで届く（1 拒否 1 行。2 回の拒否で 2 行）。
    fn rejection_reaches_the_audit_file_one_line_per_rejection() {
        let dir = private_dir();
        let result = std::panic::catch_unwind(|| audit_file_scenario(&dir));
        let _ = std::fs::remove_dir_all(&dir);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    fn audit_file_scenario(dir: &Path) {
        let path = dir.join("audit.log");
        let writer = AuditFileWriter::open(&path).expect("open audit file");
        let sink = FileSink(Mutex::new(writer));
        let record = running_record_of_self();
        let req = request();

        let first =
            run_command(&record, &req, Duration::from_secs(30), &sink).expect_err("rejected");
        assert_eq!(first.delivery, AuditDelivery::Recorded);
        let text = std::fs::read_to_string(&path).expect("read audit file");
        assert_eq!(text.lines().count(), 1, "{text}");
        let line = text.lines().next().expect("one line");
        assert!(line.contains("\"layer\":\"exec_target\""), "{line}");
        assert!(
            line.contains("\"reason\":\"exec_target_not_nested_pid1\""),
            "{line}"
        );
        assert!(line.contains("\"path\":null"), "{line}");
        assert!(
            line.contains(&format!("\"pid\":{}", std::process::id())),
            "{line}"
        );

        let second =
            run_command(&record, &req, Duration::from_secs(30), &sink).expect_err("rejected");
        assert_eq!(second.delivery, AuditDelivery::Recorded);
        let text = std::fs::read_to_string(&path).expect("read audit file");
        assert_eq!(text.lines().count(), 2, "{text}");
    }

    /// SEC-4・fail-closed: sink が失敗しても拒否は元のまま。失敗は `delivery` で返り黙殺されない。
    fn sink_failure_does_not_overturn_the_rejection() {
        let sink = VecSink::new(true);
        let rejected = run_command(
            &running_record_of_self(),
            &request(),
            Duration::from_secs(30),
            &sink,
        )
        .expect_err("rejected");
        assert_eq!(rejected.error.message(), REJECTION);
        assert_eq!(
            rejected.delivery,
            AuditDelivery::SinkFailed(TraitError::new(ErrorCode::Internal, "sink failed"))
        );
        assert_eq!(sink.snapshot().len(), 0);
    }

    /// 稼働中でない記録は fork 前の前提不成立で、監査の対象外（`NotApplicable`・0 件）。
    fn non_running_record_is_not_audited() {
        let sink = VecSink::new(false);
        let record = StateRecord::new(
            ContainerStatus::stopped(cid(), Some(0)),
            std::env::temp_dir().join("b"),
            StateRevision::from_raw(1),
        )
        .expect("state record");
        let rejected =
            run_command(&record, &request(), Duration::from_secs(30), &sink).expect_err("rejected");
        assert_eq!(rejected.delivery, AuditDelivery::NotApplicable);
        assert_eq!(
            rejected.error.message(),
            "container is not running or has no recorded pid; cannot identify pid1"
        );
        assert_eq!(sink.snapshot().len(), 0);
    }
}
