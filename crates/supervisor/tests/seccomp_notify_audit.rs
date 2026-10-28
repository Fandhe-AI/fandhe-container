//! seccomp の通知を受けて記録し `EPERM` で応答する経路の、実カーネルでの end-to-end 試験
//! （SEC-4・REPAIR-5・SUP-2・TASK-41 追補・#2025。監査配送 3/6）。
//!
//! 使い捨てスレッドに `UserNotif` 版の filter（`NEW_LISTENER` 付き。core の `exec-test-support` の
//! `user_notif_probe_for_test`）を載せ、その listener を supervisor の応答ハブ（`SeccompNotifyHub`）へ渡して、
//! 本番と同じ記録先（`ControlAuditRelay` → `FileAuditSink` → `<状態ルート>/@audit.log`）まで照合する。
//! `ControlAuditRelay::spawn` は単一スレッドの呼び出し元を要求するため、`harness = false` の単一スレッド `main` で、
//! relay を **最初に** fork してから probe やハブのスレッドを作る。root は不要で、既定のテスト集合で実行する。
//!
//! - シナリオ 1: ERRNO 側の禁止 syscall（`kcmp`）が `EPERM`(1) で返り、`@audit.log` に seccomp 層の JSON 行が
//!   **ちょうど 1 行**（syscall 番号・arch・pid〔probe の TID〕・コンテナ ID の具体値）届く
//! - シナリオ 2（期限）: 記録が詰まった sink でも、応答の期限（100 ms）で `EPERM` が返り（対象が止まり続けない）、
//!   `late` が 1 になり、ゲートを開けると記録が後から 1 件届く
//! - シナリオ 3: 応答者（ハブ）が終了して listener が閉じた後は、拒否が `ENOSYS`(38) のまま保たれる（許可に倒れない）
//!
//! 前提の対照: 呼び出しスレッド自身が seccomp の下にない（`Seccomp: 0`）。外側の filter があると結果を取り違えるため、
//! 満たさないときは skip せず、1 行目 `seccomp_notify_audit: PRECONDITION FAILED (test environment, ...)` の
//! panic で非ゼロ終了する（#2235・#2497・CORE-5・SEC-4・REPAIR-12）。分類は純関数で、冒頭で自己照合する。
//! 判定できないときは前提欠如とは表示せず汎用の失敗にする（fail-closed）。待ちはすべて期限つき（REPAIR-5）。

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn main() {
    println!("seccomp_notify_audit: Linux only, not applicable on this OS");
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
    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{
        AuditRecord, AuditSink, ControlAuditRelay, RECORD_WAIT_LIMIT,
    };
    use fandhe_container_core::exec::user_notif_probe_for_test;
    use fandhe_container_core::traits::{ContainerId, TraitError};
    use fandhe_container_supervisor::exec::default_audit_sink;
    use fandhe_container_supervisor::seccomp_notify::{NotifyConfig, SeccompNotifyHub};

    const CONTAINER: &str = "notify-2025";
    const EPERM: i32 = 1;
    const ENOSYS: i32 = 38;
    const POLL_MARGIN: Duration = Duration::from_secs(5);

    #[cfg(target_arch = "x86_64")]
    const KCMP_NR: u32 = 312;
    #[cfg(target_arch = "aarch64")]
    const KCMP_NR: u32 = 272;
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xC000_00B7;

    pub fn run() {
        self_check_classifier();
        check_no_outer_seccomp();
        let root = TempRoot::new();
        let id = ContainerId::new(CONTAINER).expect("container id");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(root.0.join(id.as_str()))
            .expect("create state dir");
        // スレッドを作る前に relay を fork する（本番と同じ。以降の記録は helper へ渡る）。
        let relay = default_audit_sink(Some(root.0.clone()))
            .and_then(ControlAuditRelay::spawn)
            .expect("spawn the audit relay");
        end_to_end_record_and_eperm(&root.0, &id, Arc::new(relay));
        slow_sink_is_answered_at_the_deadline(&id);
        println!("seccomp_notify_audit: all scenarios passed");
    }

    /// `/proc/self/status` の `Seccomp:` 行の分類（REPAIR-12。純関数で自己照合する）。
    #[derive(Debug, PartialEq)]
    enum Precondition {
        /// `Seccomp: 0`。前提を満たす。
        Ok,
        /// `Seccomp:` が 0 以外の数値。外側の filter の下にある（試験環境の前提欠如）。
        OuterSeccomp { mode: String },
        /// status が読めない・`Seccomp:` 行が無い・数値でない。前提欠如とは断定しない（fail-closed）。
        Unknown,
    }

    /// status の本文を「前提を満たす / 外側の seccomp / 判定不能」へ分類する。
    /// `Seccomp_filters:` 行は `Seccomp:`（コロン付き）に一致しないので取り違えない。
    fn classify_seccomp_status(status: Option<&str>) -> Precondition {
        let Some(status) = status else {
            return Precondition::Unknown;
        };
        let Some(mode) = status
            .lines()
            .find_map(|l| l.strip_prefix("Seccomp:"))
            .map(str::trim)
        else {
            return Precondition::Unknown;
        };
        match mode.parse::<u32>() {
            Ok(0) => Precondition::Ok,
            Ok(_) => Precondition::OuterSeccomp {
                mode: mode.to_owned(),
            },
            Err(_) => Precondition::Unknown,
        }
    }

    /// 前提欠如の失敗メッセージ。1 行目で試験環境の前提欠如と分かる形式（#2235・#2497。
    /// core の `seccomp_enforcement` と同形）。
    fn precondition_message(mode: &str) -> String {
        let hint = match mode {
            "2" => {
                "an outer seccomp filter is active (e.g. Docker's default seccomp profile under make docker-ci)"
            }
            "1" => "the process is in seccomp strict mode",
            _ => "the environment applies seccomp to this process",
        };
        format!(
            "seccomp_notify_audit: PRECONDITION FAILED (test environment, not a seccomp notify regression): \
             this process is already under an outer seccomp filter (Seccomp: {mode}) before the probe's filter is installed.\n\
             hint: {hint}.\n\
             By policy (#2235) the dev container keeps Docker's seccomp and this test stays failing there; \
             run it on the host (cargo test -p fandhe-container-supervisor --test seccomp_notify_audit) or rely on CI. \
             See AGENTS.md \"make docker-ci\"."
        )
    }

    /// 分類と文言の自己照合。実環境の判定より前に常に走らせ、前提欠如と回帰を取り違えないことを確かめる。
    fn self_check_classifier() {
        let outer = |m: &str| Precondition::OuterSeccomp { mode: m.to_owned() };
        assert_eq!(
            classify_seccomp_status(Some("Name:\tx\nSeccomp:\t0\nSeccomp_filters:\t0\n")),
            Precondition::Ok
        );
        assert_eq!(
            classify_seccomp_status(Some("Seccomp:\t2\nSeccomp_filters:\t1\n")),
            outer("2")
        );
        assert_eq!(classify_seccomp_status(Some("Seccomp:\t1\n")), outer("1"));
        assert_eq!(
            classify_seccomp_status(Some("Seccomp_filters:\t1\n")),
            Precondition::Unknown
        );
        assert_eq!(
            classify_seccomp_status(Some("Name:\tx\n")),
            Precondition::Unknown
        );
        assert_eq!(classify_seccomp_status(None), Precondition::Unknown);
        assert_eq!(
            classify_seccomp_status(Some("Seccomp:\tx\n")),
            Precondition::Unknown
        );
        let msg = precondition_message("2");
        assert_eq!(
            msg.lines().next(),
            Some(
                "seccomp_notify_audit: PRECONDITION FAILED (test environment, not a seccomp notify regression): this process is already under an outer seccomp filter (Seccomp: 2) before the probe's filter is installed."
            )
        );
        assert!(msg.contains("make docker-ci"), "{msg}");
        assert!(
            msg.contains("cargo test -p fandhe-container-supervisor --test seccomp_notify_audit"),
            "{msg}"
        );
    }

    /// 前提の対照: 外側の seccomp がない。満たさないときは skip せず panic（非ゼロ終了）する。
    fn check_no_outer_seccomp() {
        let status = std::fs::read_to_string("/proc/self/status");
        match classify_seccomp_status(status.as_deref().ok()) {
            Precondition::Ok => {}
            Precondition::OuterSeccomp { mode } => panic!("{}", precondition_message(&mode)),
            Precondition::Unknown => panic!(
                "seccomp_notify_audit: could not determine the Seccomp mode from /proc/self/status (read: {:?})",
                status.as_ref().map(|_| "ok").map_err(|e| e.kind())
            ),
        }
    }

    /// 0700 の排他作成で作る一時ディレクトリ（drop で削除）。
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            for attempt in 0..16u32 {
                let path = std::env::temp_dir()
                    .join(format!("fc-sna-{}-{nanos}-{attempt}", std::process::id()));
                match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self(path),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => panic!("create temp root: {e}"),
                }
            }
            panic!("could not create a unique temp root");
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `@audit.log` を期限つきでポーリングし、`want` 行以上になるか期限が来たら返す。
    fn wait_for_audit_lines(root: &Path, want: usize) -> Vec<String> {
        let log = root.join("@audit.log");
        let deadline = Instant::now() + RECORD_WAIT_LIMIT + POLL_MARGIN;
        loop {
            let lines: Vec<String> = std::fs::read_to_string(&log)
                .map(|t| t.lines().map(str::to_owned).collect())
                .unwrap_or_default();
            if lines.len() >= want || Instant::now() >= deadline {
                return lines;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// `Pss`（kB）と `Threads` を 1 行で返す（情報のみ）。
    fn memory_sample() -> String {
        let field = |path: &str, key: &str| {
            std::fs::read_to_string(path)
                .ok()
                .and_then(|t| {
                    t.lines()
                        .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_owned()))
                })
                .unwrap_or_else(|| "?".to_owned())
        };
        format!(
            "pss={} threads={}",
            field("/proc/self/smaps_rollup", "Pss:"),
            field("/proc/self/status", "Threads:")
        )
    }

    fn assert_seccomp_line(line: &str, tid: u32) {
        let expected = [
            "\"layer\":\"seccomp\"".to_owned(),
            format!("\"pid\":{tid}"),
            format!("\"syscall\":{KCMP_NR}"),
            format!("\"arch\":{AUDIT_ARCH}"),
            format!("\"container_id\":\"{CONTAINER}\""),
        ];
        for needle in &expected {
            assert!(line.contains(needle.as_str()), "{needle} missing: {line}");
        }
    }

    fn end_to_end_record_and_eperm(root: &Path, id: &ContainerId, relay: Arc<ControlAuditRelay>) {
        let hub = SeccompNotifyHub::new(relay, id.clone(), NotifyConfig::default());
        let mut probe = user_notif_probe_for_test().expect("probe");
        let tid = probe.tid();
        // SUP-2 の参考値（情報のみ。判定には使わない）: ハブの attach 前後の Pss と Threads。
        // probe のスレッド 1 本はハブ起因ではないため before に含める。
        let before = memory_sample();
        hub.attach(probe.take_listener().expect("listener"))
            .expect("attach");
        let started = Instant::now();
        assert_eq!(
            probe.call_kcmp(),
            Some(EPERM),
            "kcmp must be denied with EPERM"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        println!(
            "seccomp_notify_audit: SUP-2 sample (informational): before={before} after={}",
            memory_sample()
        );
        let lines = wait_for_audit_lines(root, 1);
        assert_eq!(lines.len(), 1, "exactly one audit line expected: {lines:?}");
        assert_seccomp_line(lines.first().expect("one line"), tid);
        // 余分な記録が遅れて届かないこと。
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(wait_for_audit_lines(root, 2).len(), 1, "no extra record");
        let snap = hub.finish(Duration::from_secs(5)).expect("live");
        assert_eq!((snap.recorded, snap.late, snap.unrecorded), (1, 0, 0));
        // 応答者が終了して listener が閉じた後は、拒否が ENOSYS のまま保たれる（許可に倒れない）。
        assert_eq!(
            probe.call_kcmp(),
            Some(ENOSYS),
            "denial must survive the responder"
        );
        println!(
            "seccomp_notify_audit: kcmp denied with EPERM and exactly 1 seccomp record reached @audit.log; ENOSYS after the responder left"
        );
    }

    /// `release` されるまで `record` が戻らない sink。
    #[derive(Default)]
    struct GatedSink {
        closed: Mutex<bool>,
        cv: Condvar,
        records: Mutex<Vec<AuditRecord>>,
    }

    impl AuditSink for GatedSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            let mut closed = self.closed.lock().expect("lock");
            while *closed {
                closed = self.cv.wait(closed).expect("wait");
            }
            drop(closed);
            self.records.lock().expect("lock").push(record.clone());
            Ok(())
        }
    }

    fn slow_sink_is_answered_at_the_deadline(id: &ContainerId) {
        let sink = Arc::new(GatedSink::default());
        *sink.closed.lock().expect("lock") = true;
        let config = NotifyConfig::default()
            .with_response_deadline(Duration::from_millis(100))
            .expect("deadline");
        let hub = SeccompNotifyHub::new(sink.clone(), id.clone(), config);
        let mut probe = user_notif_probe_for_test().expect("probe");
        hub.attach(probe.take_listener().expect("listener"))
            .expect("attach");
        let started = Instant::now();
        assert_eq!(probe.call_kcmp(), Some(EPERM), "kcmp must still be denied");
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(100) && waited < Duration::from_secs(3),
            "answered at the deadline, not before and not never: {waited:?}"
        );
        assert!(sink.records.lock().expect("lock").is_empty());
        *sink.closed.lock().expect("lock") = false;
        sink.cv.notify_all();
        let snap = hub.finish(Duration::from_secs(5)).expect("live");
        assert_eq!((snap.late, snap.recorded), (1, 1));
        assert_eq!(sink.records.lock().expect("lock").len(), 1);
        println!(
            "seccomp_notify_audit: a stuck sink was answered with EPERM at the deadline; the record arrived later (late=1)"
        );
    }
}
