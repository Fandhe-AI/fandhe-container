//! healthcheck の本番アダプタ `ExecHealthProbe` の結合試験（SUP-4・SUP-6・REPAIR-5・REPAIR-12・#2441）。
//!
//! 偽の helper を使う: `harness = false` の本テストバイナリ自身が `/proc/self/exe` として起動され、第 1 引数が
//! `healthcheck-exec` のときは偽の helper として振る舞う（`--id` でシナリオを選ぶ）。本物の `HealthExecArgs::parse` で
//! argv の契約（root・id・pid・timeout・command）を照合し、fd 0 が渡した pidfd 代わりの `/dev/null`、環境変数が空、
//! cwd が `/` であることを確かめる（外れたら `invalid` を返す）。実コンテナへの exec は行わない（root・namespace 不要で
//! 既定のテスト集合で動く）。実コンテナでの通しは別（#2953 の結線と実機前提の試験）。
//! 成功行は `healthcheck_exec_probe: <シナリオ> ok`。

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::io::Write as _;
    use std::num::NonZeroU32;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::ExecChildStep;
    use fandhe_container_core::traits::{ContainerId, ErrorCode, HealthStatus};
    use fandhe_container_supervisor::health::HealthProbe;
    use fandhe_container_supervisor::healthcheck::exec_helper::{
        HealthExecArgs, is_health_exec_invocation,
    };
    use fandhe_container_supervisor::healthcheck::exec_wire::{AuditToken, HealthExecLine};
    use fandhe_container_supervisor::healthcheck::{
        ExecHealthProbe, HealthExecOutcome, HealthExecReport, HealthExecTarget,
        HealthcheckDefinition, RawHealthcheck,
    };

    const COMMAND: [&str; 2] = ["/bin/echo", "hi"];

    /// 利用者所有の一時状態ルート（テストプロセスの pid で一意。偽 helper は親 pid から同じパスを導く）。
    /// 記録は置かない: アダプタは記録を読めなくても probe を続行する（best-effort。cgroup 後始末だけが残余扱い）。
    fn state_root_for(pid: u32) -> PathBuf {
        std::env::temp_dir().join(format!("fandhe-hc-exec-probe-{pid}"))
    }

    /// 偽の helper の本体。結果行は fd 2、コマンド出力は fd 1 へ書く。
    fn fake_helper(args: Vec<OsString>) -> ! {
        let parsed = HealthExecArgs::parse(args);
        let (stdout, stderr) = (std::io::stdout(), std::io::stderr());
        let (mut out, mut err) = (stdout.lock(), stderr.lock());
        let finish = |code: i32| -> ! { std::process::exit(code) };
        let args = match parsed {
            Ok(a) => a,
            Err(_) => {
                let _ = err.write_all(&HealthExecLine::Invalid.encode());
                finish(0)
            }
        };
        // 契約の照合: 外れたら invalid。
        let devnull = std::fs::File::open("/proc/self/fd/0").and_then(|f| f.metadata());
        let contract_ok = args.root() == state_root_for(std::os::unix::process::parent_id())
            && args.expect_pid().get() == 4242
            && args.command() == COMMAND
            && std::env::vars_os().next().is_none()
            && std::env::current_dir().ok().as_deref() == Some(std::path::Path::new("/"))
            && devnull.map(|m| m.rdev()).ok() == Some(0x103);
        if !contract_ok {
            let _ = err.write_all(&HealthExecLine::Invalid.encode());
            finish(0)
        }
        let na = AuditToken::Na;
        let write_line = |err: &mut std::io::StderrLock<'_>, line: HealthExecLine| {
            let _ = err.write_all(&line.encode());
        };
        match args.id().as_str() {
            "hc-healthy" => {
                let _ = out.write_all(b"ok\n");
                write_line(
                    &mut err,
                    HealthExecLine::Exited {
                        code: 0,
                        healthy: true,
                        audit: na,
                        exit_audit: na,
                    },
                );
            }
            "hc-unhealthy" => write_line(
                &mut err,
                HealthExecLine::Exited {
                    code: 3,
                    healthy: false,
                    audit: na,
                    exit_audit: na,
                },
            ),
            "hc-signaled" => write_line(
                &mut err,
                HealthExecLine::Signaled {
                    signal: 9,
                    audit: na,
                    exit_audit: na,
                },
            ),
            "hc-not-started" => write_line(
                &mut err,
                HealthExecLine::NotStarted {
                    step: Some(ExecChildStep::OpenEntrypoint),
                    code: ErrorCode::NotFound,
                    violation: false,
                    audit: na,
                },
            ),
            "hc-precondition" => write_line(
                &mut err,
                HealthExecLine::Failed {
                    code: ErrorCode::FailedPrecondition,
                    audit: na,
                },
            ),
            "hc-stale" => write_line(&mut err, HealthExecLine::Stale),
            "hc-budget" => {
                let _ = write!(out, "{}", args.timeout().as_millis());
                write_line(
                    &mut err,
                    HealthExecLine::Exited {
                        code: 0,
                        healthy: true,
                        audit: na,
                        exit_audit: na,
                    },
                );
            }
            "hc-timeout" | "hc-cancel" => std::thread::sleep(Duration::from_secs(30)),
            "hc-big-output" => {
                let chunk = [b'x'; 1000];
                for _ in 0..100 {
                    let _ = out.write_all(&chunk);
                }
                write_line(
                    &mut err,
                    HealthExecLine::Exited {
                        code: 0,
                        healthy: true,
                        audit: na,
                        exit_audit: na,
                    },
                );
            }
            "hc-noisy" => {
                for i in 0..20 {
                    let _ = writeln!(err, "{{\"component\":\"fake\",\"n\":{i}}}");
                }
                let _ = err.write_all(b"not json noise\n");
                write_line(
                    &mut err,
                    HealthExecLine::Exited {
                        code: 0,
                        healthy: true,
                        audit: na,
                        exit_audit: na,
                    },
                );
            }
            "hc-garbage" => {
                let _ = err.write_all(b"hello\n");
            }
            "hc-silent" => {}
            "hc-crash-after-line" => {
                // 結果行を書いた後に異常終了する helper。行は採用されない。
                write_line(
                    &mut err,
                    HealthExecLine::Exited {
                        code: 0,
                        healthy: true,
                        audit: na,
                        exit_audit: na,
                    },
                );
                let _ = err.flush();
                finish(1)
            }
            "hc-two-lines" => {
                let line = HealthExecLine::Exited {
                    code: 0,
                    healthy: true,
                    audit: na,
                    exit_audit: na,
                };
                write_line(&mut err, line);
                write_line(&mut err, line);
            }
            "hc-contradiction" => {
                let _ = err.write_all(b"FCHX1 exited 0 unhealthy na na\n");
            }
            "hc-orphan" => {
                // 出力用の端を持ったまま残る子孫（結果用の端は持たせない）。
                let _ = Command::new("/bin/sleep")
                    .arg("5")
                    .stdin(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn();
                write_line(
                    &mut err,
                    HealthExecLine::Exited {
                        code: 0,
                        healthy: true,
                        audit: na,
                        exit_audit: na,
                    },
                );
            }
            _ => write_line(&mut err, HealthExecLine::Invalid),
        }
        let _ = out.flush();
        let _ = err.flush();
        finish(0)
    }

    fn probe_for(id: &str) -> ExecHealthProbe {
        let devnull = std::fs::File::open("/dev/null").expect("open /dev/null");
        let target = HealthExecTarget::new(
            state_root_for(std::process::id()),
            ContainerId::new(id).expect("id"),
            NonZeroU32::new(4242).expect("pid"),
            OwnedFd::from(devnull),
        );
        let definition = HealthcheckDefinition::parse(&RawHealthcheck {
            command: COMMAND.iter().map(|s| (*s).to_string()).collect(),
            ..Default::default()
        })
        .expect("definition");
        ExecHealthProbe::new(&definition, target).expect("probe")
    }

    fn run(
        id: &str,
        timeout: Duration,
    ) -> (
        Result<HealthStatus, (ErrorCode, String)>,
        HealthExecReport,
        Duration,
    ) {
        let probe = probe_for(id);
        let start = Instant::now();
        let result = probe
            .probe(timeout)
            .map_err(|e| (e.code(), e.message().to_string()));
        let elapsed = start.elapsed();
        (result, probe.last_report().expect("report"), elapsed)
    }

    fn ok(name: &str) {
        println!("healthcheck_exec_probe: {name} ok");
    }

    pub fn main() {
        let mut args = std::env::args_os().skip(1);
        let first = args.next();
        if is_health_exec_invocation(first.as_deref()) {
            fake_helper(args.collect());
        }
        let secs = Duration::from_secs;
        let root = state_root_for(std::process::id());
        std::fs::create_dir_all(&root).expect("create state root");

        let (r, rep, _) = run("hc-healthy", secs(10));
        assert_eq!(r, Ok(HealthStatus::Healthy));
        assert_eq!(rep.outcome, HealthExecOutcome::Healthy);
        assert_eq!(rep.output, b"ok\n".to_vec());
        assert_eq!(rep.output_total_bytes, 3);
        assert!(!rep.output_truncated);
        assert!(rep.helper_reaped);
        assert!(matches!(
            rep.line,
            Some(HealthExecLine::Exited {
                code: 0,
                healthy: true,
                ..
            })
        ));
        ok("hc-healthy");

        let (r, rep, _) = run("hc-unhealthy", secs(10));
        assert_eq!(r, Ok(HealthStatus::Unhealthy));
        assert!(matches!(
            rep.line,
            Some(HealthExecLine::Exited {
                code: 3,
                healthy: false,
                ..
            })
        ));
        ok("hc-unhealthy");

        let (r, _, _) = run("hc-signaled", secs(10));
        assert_eq!(r, Ok(HealthStatus::Unhealthy));
        ok("hc-signaled");

        let (r, rep, _) = run("hc-not-started", secs(10));
        let (code, message) = r.unwrap_err();
        assert_eq!(code, ErrorCode::Internal);
        assert_eq!(
            message,
            format!(
                "healthcheck command did not start: {}",
                ExecChildStep::OpenEntrypoint.message()
            )
        );
        assert_eq!(rep.outcome, HealthExecOutcome::NotStarted);
        assert!(matches!(
            rep.line,
            Some(HealthExecLine::NotStarted {
                step: Some(ExecChildStep::OpenEntrypoint),
                ..
            })
        ));
        ok("hc-not-started");

        let (r, _, _) = run("hc-precondition", secs(10));
        assert_eq!(r.unwrap_err().0, ErrorCode::Internal);
        ok("hc-precondition");

        let (r, rep, _) = run("hc-stale", secs(10));
        assert_eq!(r.unwrap_err().0, ErrorCode::FailedPrecondition);
        assert_eq!(rep.outcome, HealthExecOutcome::Stale);
        ok("hc-stale");

        let (r, rep, _) = run("hc-budget", secs(10));
        assert_eq!(r, Ok(HealthStatus::Healthy));
        assert_eq!(rep.output, b"8000".to_vec());
        ok("hc-budget");

        let (r, rep, elapsed) = run("hc-timeout", Duration::from_millis(500));
        assert_eq!(r.unwrap_err().0, ErrorCode::Timeout);
        assert_eq!(rep.outcome, HealthExecOutcome::Timeout);
        assert!(rep.helper_reaped, "helper must be reaped after SIGKILL");
        assert!(elapsed >= Duration::from_millis(500), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(2_000), "{elapsed:?}");
        ok("hc-timeout");

        let probe = Arc::new(probe_for("hc-cancel"));
        let runner = {
            let probe = Arc::clone(&probe);
            std::thread::spawn(move || {
                let start = Instant::now();
                let r = probe.probe(secs(10));
                (r, start.elapsed())
            })
        };
        std::thread::sleep(Duration::from_millis(200));
        probe.cancel();
        let (r, elapsed) = runner.join().expect("join");
        assert_eq!(r.unwrap_err().code(), ErrorCode::Timeout);
        assert!(elapsed < secs(2), "{elapsed:?}");
        let rep = probe.last_report().expect("report");
        assert_eq!(rep.outcome, HealthExecOutcome::Cancelled);
        assert!(rep.helper_reaped);
        ok("hc-cancel");

        let (r, rep, _) = run("hc-big-output", secs(10));
        assert_eq!(r, Ok(HealthStatus::Healthy));
        assert_eq!(rep.output.len(), 4096);
        assert_eq!(rep.output_total_bytes, 100_000);
        assert!(rep.output_truncated);
        ok("hc-big-output");

        let (r, rep, _) = run("hc-noisy", secs(10));
        assert_eq!(r, Ok(HealthStatus::Healthy));
        assert_eq!(rep.diag_forwarded, 16);
        assert_eq!(rep.diag_dropped, 5);
        ok("hc-noisy");

        for id in [
            "hc-garbage",
            "hc-silent",
            "hc-crash-after-line",
            "hc-two-lines",
            "hc-contradiction",
        ] {
            let (r, rep, _) = run(id, secs(10));
            assert_eq!(r.unwrap_err().0, ErrorCode::Internal, "{id}");
            assert_eq!(rep.outcome, HealthExecOutcome::HelperError, "{id}");
            ok(id);
        }

        let (r, _, elapsed) = run("hc-orphan", secs(10));
        assert_eq!(r, Ok(HealthStatus::Healthy));
        assert!(elapsed < Duration::from_millis(1_500), "{elapsed:?}");
        ok("hc-orphan");
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("healthcheck_exec_probe: Linux only, not applicable on this OS");
}
