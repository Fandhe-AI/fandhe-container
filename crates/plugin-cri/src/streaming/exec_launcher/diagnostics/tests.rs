//! `diagnostics` の単体試験（CRI-6・SEC-1・REPAIR-4・REPAIR-5・#4171・#4233）。期待値は具体値で書く。

use fandhe_container_core::exec::{
    EntrypointExecMode, LaunchPidfdUnavailable, SealedCopyUnavailable,
};

use super::*;

fn run(chunks: &[&[u8]]) -> (Vec<String>, DiagStats) {
    let mut c = DiagCounter::new();
    let mut out = Vec::new();
    for ch in chunks {
        c.feed(ch, &mut |l| out.push(l));
    }
    let st = c.finish();
    (out, st)
}

fn classify_str(s: &str) -> Classified {
    classify(s.as_bytes())
}

#[test]
fn cri6_4171_text_stage_errno_is_forwarded() {
    let (out, st) = run(&[b"stage=open_entrypoint errno=13\n"]);
    assert_eq!(
        out,
        ["{\"event\":\"cri_exec_helper_diagnostic\",\"stage\":\"open_entrypoint\",\"errno\":13}"]
    );
    assert_eq!(st.forwarded, 1);
    assert_eq!(st.unparsed, 0);
}

#[test]
fn cri6_4171_json_stage_and_errno_name_is_forwarded() {
    let (out, _) = run(&[b"{\"stage\":\"cgroup_join\",\"errno\":\"EACCES\"}\n"]);
    assert_eq!(
        out,
        [
            "{\"event\":\"cri_exec_helper_diagnostic\",\"stage\":\"cgroup_join\",\"errno\":\"EACCES\"}"
        ]
    );
}

#[test]
fn cri6_4171_core_launch_pidfd_line_is_forwarded() {
    let denied = LaunchPidfdUnavailable::Denied.log_line().expect("line");
    let failed = LaunchPidfdUnavailable::Failed { errno: "EMFILE" }
        .log_line()
        .expect("line");
    let (out, _) = run(&[denied.as_bytes(), b"\n", failed.as_bytes(), b"\n"]);
    assert_eq!(
        out,
        [
            "{\"event\":\"cri_exec_helper_diagnostic\",\"component\":\"core.exec\",\"operation\":\"launch_pidfd\",\"outcome\":\"unavailable\",\"reason\":\"denied\",\"errno\":\"EPERM\"}",
            "{\"event\":\"cri_exec_helper_diagnostic\",\"component\":\"core.exec\",\"operation\":\"launch_pidfd\",\"outcome\":\"unavailable\",\"reason\":\"failed\",\"errno\":\"EMFILE\"}",
        ]
    );
}

#[test]
fn cri6_4171_entrypoint_mode_line_is_ignored() {
    let modes = [
        EntrypointExecMode::SealedCopy,
        EntrypointExecMode::PinnedInode {
            reason: SealedCopyUnavailable::KernelTooOld,
        },
    ];
    for m in modes {
        let reason = m.fallback_reason().map_or("", |r| r.as_str());
        let line = format!(
            "{{\"component\":\"supervisor.exec\",\"operation\":\"entrypoint_mode\",\"mode\":\"{}\",\"reason\":\"{}\"}}",
            m.as_str(),
            reason
        );
        assert_eq!(classify_str(&line), Classified::Ignored, "{line}");
    }
    let (out, st) = run(&[
        b"{\"component\":\"supervisor.exec\",\"operation\":\"entrypoint_mode\",\"mode\":\"sealed_copy\",\"reason\":\"\"}\n",
    ]);
    assert!(out.is_empty());
    assert_eq!((st.ignored, st.forwarded, st.unparsed), (1, 0, 0));
}

#[test]
fn sec1_4171_rejects_unknown_keys_and_values() {
    let bad = [
        "argv=/bin/marker-4171",
        "stage=open_entrypoint argv=/bin/marker-4171",
        "stage=not_a_stage_marker",
        "errno=0",
        "errno=4096",
        "errno=abc",
        "{\"stage\":\"setsid\",\"x\":\"a\\nb\"}",
        "stage=setsid stage=setsid",
        "stage=setsid errno=13 \u{3042}",
        "stage=setsid\r",
        "reason=tok_AbCdEf0123456789",
        "{\"stage\":\"setsid\",\"message\":5}",
        "{}",
        "",
    ];
    for l in bad {
        assert_eq!(classify_str(l), Classified::Unparsed, "{l:?}");
    }
    let (out, st) = run(&[b"argv=/bin/marker-4171 tok_AbCdEf0123456789\n"]);
    assert!(out.is_empty());
    assert_eq!(st.unparsed, 1);
}

#[test]
fn sec1_4171_message_value_is_dropped_from_output() {
    let (out, _) = run(&[b"{\"code\":\"INTERNAL\",\"message\":\"secret-marker-4171 /etc/x\"}\n"]);
    assert_eq!(out.len(), 1);
    assert!(!out[0].contains("secret"));
    assert!(out[0].starts_with("{\"event\":\"cri_exec_helper_diagnostic\",\"code\":\""));
}

#[test]
fn repair5_4171_limits_and_counts() {
    let valid = b"stage=setsid errno=13\n";
    let mut input = Vec::new();
    for _ in 0..40 {
        input.extend_from_slice(valid);
    }
    let mut big = vec![b'a'; 4095];
    big.push(b'\n');
    for _ in 0..1000 {
        input.extend_from_slice(&big);
    }
    for size in [1usize, 7, 64, 4096, input.len()] {
        let chunks: Vec<&[u8]> = input.chunks(size).collect();
        let (out, st) = run(&chunks);
        assert_eq!(out.len(), 32, "size {size}");
        assert_eq!(st.forwarded, 32, "size {size}");
        assert_eq!(st.dropped_lines, 8 + 1000, "size {size}");
        assert_eq!(
            st.dropped_bytes,
            8 * valid.len() as u64 + 1000 * 4096,
            "size {size}"
        );
        assert_eq!(st.unparsed, 0, "size {size}");
    }
}

#[test]
fn repair5_4171_line_length_boundary() {
    let mut ok = vec![b'x'; DIAG_MAX_LINE_BYTES - 1];
    ok.push(b'\n');
    assert_eq!(ok.len(), 512);
    let (_, st) = run(&[&ok]);
    assert_eq!((st.unparsed, st.dropped_lines), (1, 0));
    let mut over = vec![b'x'; DIAG_MAX_LINE_BYTES];
    over.push(b'\n');
    assert_eq!(over.len(), 513);
    let (_, st) = run(&[&over]);
    assert_eq!(
        (st.unparsed, st.dropped_lines, st.dropped_bytes),
        (0, 1, 513)
    );
}

#[test]
fn repair5_4171_total_bytes_boundary() {
    // 400 バイトの行を 20 本（8000 B）受け、21 本目（8400 B）は総量の上限で捨てる。
    let mut line = vec![b'y'; 399];
    line.push(b'\n');
    let mut input = Vec::new();
    for _ in 0..21 {
        input.extend_from_slice(&line);
    }
    let (_, st) = run(&[&input]);
    assert_eq!(st.unparsed, 20);
    assert_eq!((st.dropped_lines, st.dropped_bytes), (1, 400));
}

#[test]
fn repair5_4171_trailing_fragment_counts_as_unparsed() {
    let (_, st) = run(&[b"stage=setsid errno=13"]);
    assert_eq!((st.unparsed, st.forwarded), (1, 0));
}

#[test]
fn repair4_4171_summary_only_when_noteworthy() {
    let quiet = DiagStats {
        forwarded: 3,
        ignored: 5,
        ..DiagStats::default()
    };
    assert_eq!(summary_line(DiagEnd::Eof, &quiet), None);
    assert_eq!(summary_line(DiagEnd::Stopped, &quiet), None);
    let noisy = DiagStats {
        forwarded: 32,
        unparsed: 2,
        dropped_lines: 1008,
        dropped_bytes: 4_096_000,
        ..DiagStats::default()
    };
    assert_eq!(
        summary_line(DiagEnd::Eof, &noisy).as_deref(),
        Some(
            "{\"event\":\"cri_exec_helper_diagnostics\",\"outcome\":\"error\",\"end\":\"eof\",\"forwarded\":32,\"ignored\":0,\"unparsed\":2,\"dropped_lines\":1008,\"dropped_bytes\":4096000}"
        )
    );
    assert!(summary_line(DiagEnd::Deadline, &quiet).is_some());
}

/// helper の `diagnose()` が実際に出す固定語彙の行（小文字ハイフン表記）が、正規形の `code` として転送される（CRI-6・REPAIR-4・#4171）。
#[test]
fn repair4_4171_helper_diagnose_lowercase_codes_are_forwarded() {
    let (out, st) = run(&[
        b"{\"code\":\"invalid-argument\",\"message\":\"stream-exec requires a socket on fd 0\"}\n",
        b"{\"code\":\"unavailable\",\"message\":\"stream-exec requester went away; exec cancelled\"}\n",
        b"{\"code\":\"UNAVAILABLE\",\"message\":\"x\"}\n",
    ]);
    assert_eq!(st.unparsed, 0);
    assert_eq!(out.len(), 3);
    assert!(
        out[0].contains("\"code\":\"INVALID_ARGUMENT\""),
        "{}",
        out[0]
    );
    assert!(out[1].contains("\"code\":\"UNAVAILABLE\""), "{}", out[1]);
    assert!(out[2].contains("\"code\":\"UNAVAILABLE\""), "{}", out[2]);
    assert!(matches!(
        classify_str("code=Unavailable"),
        Classified::Unparsed
    ));
}

/// 生成側（supervisor）の実関数が作る seccomp の集計行は ignored に数え、要約行を出さない（#4233）。
#[test]
fn cri6_4233_seccomp_report_line_is_ignored() {
    use fandhe_container_supervisor::seccomp_notify::{CounterSnapshot, report_lines};
    let one = report_lines(CounterSnapshot {
        unrecorded: 1,
        ..CounterSnapshot::default()
    });
    assert_eq!(one.len(), 1);
    let line = format!("{}\n", one[0]);
    let (out, st) = run(&[line.as_bytes()]);
    assert!(out.is_empty());
    assert_eq!((st.ignored, st.unparsed, st.forwarded), (1, 0, 0));
    assert_eq!(summary_line(DiagEnd::Eof, &st), None);

    let all = report_lines(CounterSnapshot {
        suppressed: 1,
        late: 1,
        unrecorded: 1,
        target_gone: 1,
        pid_unresolved: 1,
        respond_failed: 1,
        wait_failed: 1,
        receive_failed: 1,
        ..CounterSnapshot::default()
    });
    assert_eq!(all.len(), 8);
    for l in &all {
        assert_eq!(classify_str(l), Classified::Ignored, "{l}");
    }
}

#[test]
fn cri6_4233_seccomp_report_line_text_form_is_ignored() {
    assert_eq!(
        classify_str("component=supervisor event=seccomp_audit_late count=3"),
        Classified::Ignored
    );
}

/// 語彙外の event・欄の欠落や混入・count の異常は、従来どおり解釈できない行にする（#4233）。
#[test]
fn sec1_4233_unknown_event_is_unparsed() {
    let bad = [
        "{\"component\":\"supervisor\",\"event\":\"seccomp_audit_bogus\",\"count\":1}",
        "{\"component\":\"supervisor\",\"event\":\"seccomp_notify_join_timeout\"}",
        "{\"component\":\"supervisor\",\"event\":\"control_channel_failed\",\"code\":\"INTERNAL\",\"message\":\"x\"}",
        "{\"component\":\"supervisor\",\"event\":\"seccomp_audit_late\"}",
        "{\"event\":\"seccomp_audit_late\",\"count\":1}",
        "{\"component\":\"core.exec\",\"event\":\"seccomp_audit_late\",\"count\":1}",
        "{\"component\":\"supervisor\",\"event\":\"seccomp_audit_late\",\"count\":1,\"stage\":\"setsid\"}",
        "{\"component\":\"supervisor\",\"event\":\"seccomp_audit_late\",\"count\":1,\"code\":\"INTERNAL\"}",
        "{\"component\":\"supervisor\",\"event\":\"seccomp_audit_late\",\"count\":1,\"message\":\"x\"}",
        "{\"component\":\"supervisor\",\"event\":\"seccomp_audit_late\",\"count\":\"abc\"}",
        "{\"component\":\"supervisor\",\"count\":1}",
        "{\"component\":\"supervisor\",\"event\":\"seccomp_audit_late\",\"count\":12345678901}",
        "{\"component\":\"supervisor\",\"event\":\"seccomp_audit_late\",\"event\":\"seccomp_audit_late\",\"count\":1}",
    ];
    for l in bad {
        assert_eq!(classify_str(l), Classified::Unparsed, "{l}");
        let line = format!("{l}\n");
        let (out, st) = run(&[line.as_bytes()]);
        assert!(out.is_empty(), "{l}");
        assert_eq!((st.unparsed, st.ignored), (1, 0), "{l}");
        assert!(summary_line(DiagEnd::Eof, &st).is_some(), "{l}");
    }
}
