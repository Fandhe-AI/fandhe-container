//! exec の対象の拒否が監査ログへ 1 件ずつ記録されることの結合試験（SEC-4・SUP-6・TASK-163 追補・#1465・REPAIR-12）。
//!
//! 縮退経路の試験専用入口 `exec::run_command`（`exec-test-support`。記録・照合の経路は本番と共有）を、自プロセスの pid を「稼働中コンテナの pid」とした記録に対して呼ぶ。自プロセスは
//! 入れ子の PID namespace の PID 1 ではないため、worker 内の `identify_pid1` が違反 `exec_target_not_nested_pid1`
//! で拒否する（`setns` の前に拒否されるので root・実コンテナは不要）。この拒否が親プロセス側で層 `exec_target` の
//! レコード 1 件になること、本番の記録先（`default_audit_sink` の `FileAuditSink`。`<状態ルート>/@audit.log`）の JSON Lines 1 行まで届くこと、記録の失敗で拒否が
//! 覆らないこと、記録の対象外（稼働中でない記録）は 0 件であることを具体値で照合する。
//!
//! worker の制限の準備で生じる rootfs の拒否（種別 `rootfs_pivot` の `rootfs_is_host_root`。#1614 の事後監査 P2）は、
//! 本番の経路では対象の特定を通った後でしか起きないため、試験専用の入口（`exec-test-support`）で core の判定
//! `reject_own_root`（`reject_own_root_for_test`）を本番と同じ worker の中で呼び、結果行を経た親側の記録が層 `mount`・理由コードつき・
//! パスなし・1 件になること、本番の記録先の JSON Lines に同じ 1 行が届くことを照合する。
//!
//! bundle の rootfs の固定が検証後の差し替え（symlink・不在。種別 `mount_target` の `path_symlink_or_not_directory`・
//! `path_missing`。#1702）で拒否した場合も、試験専用の差し込み（`pin_exec_bundle_with_swap_for_test`）を本番と同じ
//! worker の中で走らせ、親側の記録が層 `mount`・理由コードつき・パスなし・1 件になることを照合する。
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

    use fandhe_container_core::audit_log::{AuditDelivery, AuditLayer, AuditRecord, AuditSink};
    use fandhe_container_core::exec::reject_own_root_for_test;
    use fandhe_container_core::traits::{
        CgroupPlacement, CgroupScope, ContainerId, ContainerStatus, ErrorCode, StateRecord,
        StateRevision, TraitError,
    };
    use fandhe_container_supervisor::exec::{
        ExecOutcome, ExecRequest, TestWorkerError, default_audit_sink,
        pin_exec_bundle_with_swap_for_test, run_command, run_in_worker_audited_for_test,
        run_in_worker_trait_audited_for_test,
    };

    pub fn run() {
        rejection_is_recorded_once_with_reason_and_no_path();
        rejection_reaches_the_audit_file_one_line_per_rejection();
        failing_sink_keeps_the_process_single_threaded_for_repeated_exec();
        sink_failure_does_not_overturn_the_rejection();
        non_running_record_is_not_audited();
        worker_rootfs_rejection_is_recorded_once_as_mount_without_path();
        worker_rootfs_rejection_reaches_the_audit_file_as_one_mount_line();
        pin_swap_after_validation_is_recorded_once_as_mount_without_path();
        pin_swap_after_validation_reaches_the_audit_file_as_one_mount_line();
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

    fn cid() -> ContainerId {
        ContainerId::new("c1").expect("container id")
    }

    /// launch 時の分離の記録（rootfs だけのルール。識別子は具体値。TASK-163 追補・#1468）。
    fn launch_isolation() -> fandhe_container_core::launch_isolation::LaunchIsolationRecord {
        use fandhe_container_core::launch_isolation::{
            LaunchIsolationRecord, RecordedLandlock, RecordedRule, RecordedTarget, RootIdentity,
        };
        LaunchIsolationRecord::from_parts(
            RootIdentity::new(44, 1234),
            RecordedLandlock::new(0xFFFF, vec![RecordedRule::new(RecordedTarget::Root, 0x7)])
                .expect("recorded landlock"),
        )
    }

    /// 全 16 種の launch 記録（`Nofile` は (700, 1500)、他は種別の添字から決める具体値。TASK-169 追補・#1467）。
    fn full_rlimits() -> fandhe_container_core::rlimits::Rlimits {
        use fandhe_container_core::rlimits::{Rlimit, RlimitKind, Rlimits};
        Rlimits::new(
            RlimitKind::ALL
                .into_iter()
                .enumerate()
                .map(|(i, k)| {
                    let (soft, hard) = if k == RlimitKind::Nofile {
                        (700, 1500)
                    } else {
                        (i as u64, 100 + i as u64)
                    };
                    Rlimit::new(k, soft, hard).expect("rlimit")
                })
                .collect(),
        )
        .expect("rlimits")
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
        .with_rlimits(full_rlimits())
        .with_launch_isolation(launch_isolation())
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
        // #1618: pid は記録した親プロセスのもの。対象のコンテナは検証済みの ID で示す。
        assert_eq!(recs[0].container_id().map(|c| c.as_str()), Some("c1"));
        // #3294: worker の `err` 行で届いた段（`ExecError::stage`）が記録の `stage` に載る。
        assert_eq!(recs[0].stage().map(|s| s.as_str()), Some("set_ns"));
    }

    /// 0700 の使い捨てディレクトリ（状態ルートとして使う。`FileAuditSink` の親ディレクトリ検査を満たす）。
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

    /// 現在のプロセスのスレッド数（`/proc/self/status` の `Threads:`）。
    fn thread_count() -> u32 {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find_map(|l| l.strip_prefix("Threads:"))
            .and_then(|v| v.trim().parse().ok())
            .expect("Threads line")
    }

    /// SEC-4・SUP-6・REPAIR-5: 記録が失敗する sink（主経路が symlink で拒否される）でも、sink 生成後・失敗通知後の
    /// どの時点でも通知用スレッドが残らず、同一 sink での複数回の exec が単一スレッド検証（fork 前）を通る。
    fn failing_sink_keeps_the_process_single_threaded_for_repeated_exec() {
        let dir = private_dir();
        let result = std::panic::catch_unwind(|| {
            let sink = default_audit_sink(Some(dir.clone())).expect("production audit sink");
            std::os::unix::fs::symlink(dir.join("nowhere"), dir.join("@audit.log"))
                .expect("symlink");
            assert_eq!(thread_count(), 1, "sink creation must not spawn threads");
            let record = running_record_of_self();
            let req = request();
            for _ in 0..3 {
                let rejected = run_command(&record, &req, Duration::from_secs(30), &sink)
                    .expect_err("rejected");
                assert_eq!(rejected.error.message(), REJECTION);
                assert_eq!(thread_count(), 1, "no notifier thread may remain");
            }
        });
        let _ = std::fs::remove_dir_all(&dir);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    fn audit_file_scenario(dir: &Path) {
        let sink = default_audit_sink(Some(dir.to_path_buf())).expect("production audit sink");
        let path = dir.join("@audit.log");
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
        assert!(
            line.ends_with("\"container_id\":\"c1\",\"stage\":\"set_ns\"}"),
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

    /// worker の中で `reject_own_root` を `/` に対して呼んだときの実際の拒否（種別 `rootfs_pivot`）。
    const ROOTFS_REJECTION: &str = "exec stage Validate: rootfs must not be the host root '/' \
         (violation: rootfs_pivot/rootfs_is_host_root, CORE-1)";

    /// 本番と同じ worker の中で、core の `reject_own_root` に自分の `/` を rootfs として渡す（必ず拒否される）。
    fn rootfs_is_host_root_in_worker(
        sink: &dyn AuditSink,
    ) -> fandhe_container_core::audit_log::AuditedRejection<TraitError> {
        run_in_worker_audited_for_test(
            Duration::from_secs(30),
            || -> Result<ExecOutcome, _> {
                reject_own_root_for_test(Path::new("/"))?;
                panic!("the host root must be rejected as the rootfs");
            },
            Some(&cid()),
            sink,
        )
        .expect_err("the host root must be rejected")
    }

    /// SEC-4・SEC-1・SUP-6・#1614 の事後監査 P2: worker の `rootfs_is_host_root` の拒否は結果行を経て親側で 1 件だけ
    /// 記録される（層 `mount`・理由コード `rootfs_is_host_root` つき・パスなし・親〔自〕プロセスの PID）。拒否の内容は元のまま。
    fn worker_rootfs_rejection_is_recorded_once_as_mount_without_path() {
        let sink = VecSink::new(false);
        let rejected = rootfs_is_host_root_in_worker(&sink);
        assert_eq!(rejected.error.code(), ErrorCode::InvalidArgument);
        assert_eq!(rejected.error.message(), ROOTFS_REJECTION);
        assert_eq!(rejected.delivery, AuditDelivery::Recorded);
        let recs = sink.snapshot();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].layer(), AuditLayer::Mount);
        assert_eq!(
            recs[0].reason().map(|r| r.as_str()),
            Some("rootfs_is_host_root")
        );
        assert_eq!(recs[0].path(), None);
        assert_eq!(recs[0].syscall(), None);
        assert_eq!(recs[0].pid().get(), std::process::id());
        assert_eq!(recs[0].container_id().map(|c| c.as_str()), Some("c1"));
        // #3294: `ExecError::stage` が `err` 行を経て記録の `stage` に載る。
        assert_eq!(recs[0].stage().map(|s| s.as_str()), Some("validate"));

        // 記録の失敗で拒否は覆らない（fail-closed）。
        let failing = VecSink::new(true);
        let rejected = rootfs_is_host_root_in_worker(&failing);
        assert_eq!(rejected.error.message(), ROOTFS_REJECTION);
        assert_eq!(
            rejected.delivery,
            AuditDelivery::SinkFailed(TraitError::new(ErrorCode::Internal, "sink failed"))
        );
        assert_eq!(failing.snapshot().len(), 0);
    }

    /// SEC-4・#1614 の事後監査 P2: 本番の記録先（`FileAuditSink`）の JSON Lines に層 `mount`・`path` null の 1 行が届き、
    /// exec_target・entrypoint の層の行は増えない（二重記録なし）。
    fn worker_rootfs_rejection_reaches_the_audit_file_as_one_mount_line() {
        let dir = private_dir();
        let result = std::panic::catch_unwind(|| {
            let sink = default_audit_sink(Some(dir.clone())).expect("production audit sink");
            let rejected = rootfs_is_host_root_in_worker(&sink);
            assert_eq!(rejected.error.message(), ROOTFS_REJECTION);
            assert_eq!(rejected.delivery, AuditDelivery::Recorded);
            let text = std::fs::read_to_string(dir.join("@audit.log")).expect("read audit file");
            assert_eq!(text.lines().count(), 1, "{text}");
            let line = text.lines().next().expect("one line");
            assert!(line.contains("\"layer\":\"mount\""), "{line}");
            assert!(line.contains("\"path\":null"), "{line}");
            assert!(
                line.contains(&format!("\"pid\":{}", std::process::id())),
                "{line}"
            );
            assert!(
                line.ends_with(
                    "\"path_original_len\":null,\"reason\":\"rootfs_is_host_root\",\"container_id\":\"c1\",\"stage\":\"validate\"}"
                ),
                "{line}"
            );
            assert!(!line.contains("exec_target"), "{line}");
            assert!(!line.contains("entrypoint"), "{line}");
        });
        let _ = std::fs::remove_dir_all(&dir);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    /// 使い捨ての bundle（`config.json` と `rootfs/`）。祖先に symlink を含まない実パスに作る。
    fn make_bundle(name: &str) -> PathBuf {
        let base = std::fs::canonicalize(std::env::temp_dir()).expect("temp dir");
        let dir = base.join(format!("fandhe-exec-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rootfs")).expect("bundle");
        std::fs::write(
            dir.join("config.json"),
            br#"{"ociVersion":"1.2.0","root":{"path":"rootfs"}}"#,
        )
        .expect("config");
        dir
    }

    /// 本番と同じ worker の中で、検証後に rootfs を差し替えて固定させる。`to_symlink` なら symlink、でなければ不在。
    fn pin_swap_in_worker(
        bundle: &Path,
        to_symlink: bool,
        sink: &dyn AuditSink,
    ) -> fandhe_container_core::audit_log::AuditedRejection<TraitError> {
        run_in_worker_trait_audited_for_test(
            Duration::from_secs(30),
            || -> Result<ExecOutcome, TestWorkerError> {
                pin_exec_bundle_with_swap_for_test(bundle, || {
                    std::fs::remove_dir(bundle.join("rootfs")).expect("remove rootfs");
                    if to_symlink {
                        std::os::unix::fs::symlink("/", bundle.join("rootfs")).expect("symlink");
                    }
                })?;
                panic!("the swapped rootfs must be rejected");
            },
            Some(&cid()),
            sink,
        )
        .expect_err("the swapped rootfs must be rejected")
    }

    /// SEC-4・SEC-1・SUP-6・#1702: 検証後の rootfs の差し替え（symlink / 不在）は、結果行を経て親側で層 `mount` の
    /// 1 件（理由コードつき・パスなし・親〔自〕プロセスの PID）になる。`code` と文言（`rootfs changed after validation`）は不変。
    fn pin_swap_after_validation_is_recorded_once_as_mount_without_path() {
        for (name, to_symlink, reason) in [
            ("symlink", true, "path_symlink_or_not_directory"),
            ("missing", false, "path_missing"),
        ] {
            let bundle = make_bundle(name);
            let sink = VecSink::new(false);
            let rejected = pin_swap_in_worker(&bundle, to_symlink, &sink);
            let _ = std::fs::remove_dir_all(&bundle);
            assert_eq!(rejected.error.code(), ErrorCode::PermissionDenied);
            assert_eq!(
                rejected.error.message(),
                format!(
                    "exec stage Validate: rootfs changed after validation \
                     (violation: mount_target/{reason}, CORE-1)"
                )
            );
            assert_eq!(rejected.delivery, AuditDelivery::Recorded);
            let recs = sink.snapshot();
            assert_eq!(recs.len(), 1, "{reason}");
            assert_eq!(recs[0].layer(), AuditLayer::Mount);
            assert_eq!(recs[0].reason().map(|r| r.as_str()), Some(reason));
            assert_eq!(recs[0].path(), None);
            assert_eq!(recs[0].pid().get(), std::process::id());
            assert_eq!(recs[0].container_id().map(|c| c.as_str()), Some("c1"));
            // #3294: 固定の呼び出し点の段 `Validate`。
            assert_eq!(recs[0].stage().map(|s| s.as_str()), Some("validate"));
        }
    }

    /// SEC-4・#1702: 本番の記録先（`FileAuditSink`）の JSON Lines に層 `mount`・`path` null・理由コードつきの 1 行が届き、
    /// bundle のパスは載らない。
    fn pin_swap_after_validation_reaches_the_audit_file_as_one_mount_line() {
        let dir = private_dir();
        let bundle = make_bundle("file");
        let result = std::panic::catch_unwind(|| {
            let sink = default_audit_sink(Some(dir.clone())).expect("production audit sink");
            let rejected = pin_swap_in_worker(&bundle, true, &sink);
            assert_eq!(rejected.delivery, AuditDelivery::Recorded);
            let text = std::fs::read_to_string(dir.join("@audit.log")).expect("read audit file");
            assert_eq!(text.lines().count(), 1, "{text}");
            let line = text.lines().next().expect("one line");
            assert!(line.contains("\"layer\":\"mount\""), "{line}");
            assert!(line.contains("\"path\":null"), "{line}");
            assert!(
                line.ends_with(
                    "\"path_original_len\":null,\"reason\":\"path_symlink_or_not_directory\",\"container_id\":\"c1\",\"stage\":\"validate\"}"
                ),
                "{line}"
            );
            assert!(!line.contains(bundle.to_string_lossy().as_ref()), "{line}");
        });
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&bundle);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }
}
