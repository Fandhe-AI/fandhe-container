//! `OpStatsFileSink` / `export_cycle` / `op_stats_export_loop_with` の試験（#4337・CRI-6・REPAIR-4・REPAIR-5・SEC-4）。
//! 実 FS を使う試験は Linux のみ（`SnapshotTarget` が Linux 限定のため）。

use super::*;
use fandhe_container_core::observability::{OpName, OpOutcome};

#[derive(Clone)]
struct Buf(Arc<Mutex<Vec<u8>>>);
impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        lock(&self.0).extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn buf_sink() -> (LineSink, Buf) {
    let buf = Buf(Arc::new(Mutex::new(Vec::new())));
    (LineSink::spawn(Box::new(buf.clone()), 64), buf)
}

fn text(sink: &LineSink, buf: &Buf) -> String {
    sink.wait_idle(Duration::from_secs(5));
    String::from_utf8(lock(&buf.0).clone()).unwrap()
}

fn recorder(name: &str, ms: u64) -> Arc<OpRecorder> {
    let r = Arc::new(OpRecorder::new());
    r.record(
        &OpName::new(name).unwrap(),
        OpOutcome::Success,
        Duration::from_millis(ms),
    )
    .unwrap();
    r
}

/// gate が閉じている間は止まる fake。gate を drop すると進む。
struct Stall(std::sync::mpsc::Receiver<()>);
impl SnapshotWrite for Stall {
    fn replace(&self, _contents: &[u8]) -> Result<(), SnapshotError> {
        let _ = self.0.recv();
        Ok(())
    }
}

struct Fail(SnapshotError);
impl SnapshotWrite for Fail {
    fn replace(&self, _contents: &[u8]) -> Result<(), SnapshotError> {
        Err(self.0)
    }
}

fn spawn_fake(w: Box<dyn SnapshotWrite>, notices: LineSink) -> OpStatsFileSink {
    OpStatsFileSink::spawn_with(
        |job| {
            std::thread::Builder::new()
                .name("test-op-stats-file".into())
                .spawn(job)
                .map(drop)
        },
        w,
        notices,
    )
    .unwrap()
}

/// REPAIR-5・#4337: 仕事中の周期は飛ばして数え、固定語彙の行を残す。終われば再び受け付ける。
#[test]
fn repair5_4337_busy_cycle_is_skipped_and_counted() {
    let (gate, rx) = std::sync::mpsc::channel::<()>();
    let (notices, out) = buf_sink();
    let sink = spawn_fake(Box::new(Stall(rx)), notices.clone());
    assert_eq!(sink.submit(b"a\n".to_vec()), FileSubmit::Queued);
    assert_eq!(sink.submit(b"b\n".to_vec()), FileSubmit::SkippedBusy);
    assert_eq!(sink.submit(b"c\n".to_vec()), FileSubmit::SkippedBusy);
    let c = sink.counts();
    assert_eq!((c.skipped_busy, c.written), (2, 0));
    assert!(!sink.wait_idle(Duration::from_millis(30)));
    drop(gate);
    assert!(sink.wait_idle(Duration::from_secs(5)));
    assert_eq!(sink.counts().written, 1);
    assert_eq!(sink.submit(b"d\n".to_vec()), FileSubmit::Queued);
    assert!(sink.wait_idle(Duration::from_secs(5)));
    let t = text(&notices, &out);
    assert_eq!(
        t,
        "{\"event\":\"op_stats_file_skipped\",\"outcome\":\"error\",\"reason\":\"busy\",\"count\":1}\n\
         {\"event\":\"op_stats_file_skipped\",\"outcome\":\"error\",\"reason\":\"busy\",\"count\":2}\n"
    );
}

/// SEC-4・#4337: 書き込み失敗は数えて固定語彙の行で残し、パスや errno を含めない。
#[test]
fn sec4_4337_write_failure_is_counted_and_reported() {
    let (notices, out) = buf_sink();
    let sink = spawn_fake(Box::new(Fail(SnapshotError::WriteFailed)), notices.clone());
    assert_eq!(sink.submit(b"x\n".to_vec()), FileSubmit::Queued);
    assert!(sink.wait_idle(Duration::from_secs(5)));
    assert_eq!(sink.counts().failed, 1);
    let t = text(&notices, &out);
    assert_eq!(
        t,
        "{\"event\":\"op_stats_file_failed\",\"outcome\":\"error\",\"reason\":\"write_failed\",\"count\":1}\n"
    );
    assert!(!t.contains('/') && !t.contains("os error"), "{t}");
}

/// SEC-4・#4337: 上限超過は書かずに `too_large` として数える。
#[test]
fn sec4_4337_too_large_error_is_counted_separately() {
    let (notices, out) = buf_sink();
    let sink = spawn_fake(Box::new(Fail(SnapshotError::TooLarge)), notices.clone());
    sink.submit(b"x\n".to_vec());
    assert!(sink.wait_idle(Duration::from_secs(5)));
    let c = sink.counts();
    assert_eq!((c.too_large, c.failed, c.written), (1, 0, 0));
    assert_eq!(
        text(&notices, &out),
        "{\"event\":\"op_stats_file_failed\",\"outcome\":\"error\",\"reason\":\"too_large\",\"count\":1}\n"
    );
}

/// SEC-4・#4337: thread を作れないときは `Err` を返す（fail-closed）。
#[test]
fn sec4_4337_spawn_failure_is_returned() {
    let (notices, _out) = buf_sink();
    let r = OpStatsFileSink::spawn_with(
        |_job| Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
        Box::new(Fail(SnapshotError::WriteFailed)),
        notices,
    );
    assert_eq!(
        r.err().map(|e| e.kind()),
        Some(std::io::ErrorKind::WouldBlock)
    );
}

/// REPAIR-5・#4337: ファイル書き込みが詰まっても、周期（stderr への出力）と同じランタイム上の受付は止まらない。
#[test]
fn repair5_4337_stalled_file_does_not_stop_export_loop_or_accept() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (gate, rx) = std::sync::mpsc::channel::<()>();
    let (stderr, err_buf) = buf_sink();
    let sink = spawn_fake(Box::new(Stall(rx)), stderr.clone());
    let recorders = vec![
        recorder("cri.run_pod_sandbox", 1),
        recorder("oci.layer.extract", 1),
    ];
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || std::net::TcpStream::connect(addr).map(drop));
        let task = tokio::spawn(op_stats_export_loop_with(
            recorders,
            Duration::from_millis(20),
            stderr.clone(),
            Some(sink.clone()),
        ));
        tokio::time::sleep(Duration::from_millis(300)).await;
        let accepted = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await;
        assert!(accepted.is_ok(), "accept stalled");
        client.join().unwrap().unwrap();
        task.abort();
    });
    let t = text(&stderr, &err_buf);
    let metas = t.matches("\"event\":\"op_stats_meta\"").count();
    assert!(metas >= 6, "metas={metas}\n{t}");
    let c = sink.counts();
    assert!(c.skipped_busy >= 2, "{c:?}");
    assert_eq!(c.written, 0);
    drop(gate);
}

/// CRI-6・#4337: 無効（`None`）のときは今までどおり stderr に記録器ごとのブロックだけを出す。
#[test]
fn cri6_4337_disabled_keeps_stderr_output() {
    let recorders = vec![
        recorder("cri.run_pod_sandbox", 3),
        recorder("oci.layer.extract", 1),
    ];
    let (sink, buf) = buf_sink();
    let cycle = export_cycle(&recorders, &sink, None);
    assert_eq!(cycle.stderr_lines, 4);
    assert_eq!(cycle.file, None);
    let t = text(&sink, &buf);
    let lines: Vec<&str> = t.lines().collect();
    assert_eq!(lines.len(), 4, "{t}");
    assert!(lines[0].contains("cri.run_pod_sandbox") && lines[2].contains("oci.layer.extract"));
    assert_eq!(export_many_to(&recorders, &sink), 4);
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::snapshot_file::SnapshotLimit;
    use std::num::NonZeroUsize;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    fn root(tag: &str) -> crate::test_root::TestRoot {
        let r = crate::test_root::test_root("opstatsfile", tag);
        std::fs::set_permissions(&*r, std::fs::Permissions::from_mode(0o700)).unwrap();
        r
    }

    fn target(dir: &Path, blocks: usize) -> SnapshotTarget {
        let limit = SnapshotLimit::for_blocks(NonZeroUsize::new(blocks).unwrap()).unwrap();
        SnapshotTarget::open(&dir.join("stats.jsonl"), limit).unwrap()
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect()
    }

    /// CRI-6・#4337: 共有・oci の 2 ブロックが 1 ファイルに完全な形で出て、stderr の行と一致する。
    #[test]
    fn cri6_4337_two_blocks_in_one_file() {
        let r = root("two-blocks");
        let (stderr, err_buf) = buf_sink();
        let sink = OpStatsFileSink::spawn(target(&r, 2), stderr.clone()).unwrap();
        let recorders = vec![
            recorder("cri.run_pod_sandbox", 3),
            recorder("oci.layer.extract", 1),
        ];
        let cycle = export_cycle(&recorders, &stderr, Some(&sink));
        assert_eq!(cycle.stderr_lines, 4);
        assert_eq!(cycle.file, Some(FileSubmit::Queued));
        assert!(sink.wait_idle(Duration::from_secs(5)));
        assert_eq!(sink.counts().written, 1);
        let path = r.join("stats.jsonl");
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 4, "{body}");
        assert!(body.ends_with('\n'));
        assert!(lines[0].contains("\"cri.run_pod_sandbox\""), "{body}");
        assert!(lines[2].contains("\"oci.layer.extract\""), "{body}");
        let meta = "{\"event\":\"op_stats_meta\",\"ops\":1,\"dropped_records\":0}";
        assert_eq!((lines[1], lines[3]), (meta, meta));
        assert_eq!(body, text(&stderr, &err_buf));
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    }

    /// CRI-6・REPAIR-5・#4337: 読み手には常に前の完全な内容か新しい完全な内容だけが見える。
    #[test]
    fn cri6_4337_replace_is_atomic_for_readers() {
        let r = root("atomic");
        let (notices, _o) = buf_sink();
        let sink = OpStatsFileSink::spawn(target(&r, 1), notices).unwrap();
        let a = format!("{}\n", "a".repeat(40000)).into_bytes();
        let b = format!("{}\n", "b".repeat(1000)).into_bytes();
        let path = r.join("stats.jsonl");
        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let (stop, path, a, b) = (stop.clone(), path.clone(), a.clone(), b.clone());
            std::thread::spawn(move || {
                let mut seen = false;
                let mut bad = 0u32;
                while !stop.load(Ordering::Relaxed) {
                    match std::fs::read(&path) {
                        Ok(c) if c == a || c == b => seen = true,
                        Ok(_) => bad += 1,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !seen => {}
                        Err(_) => bad += 1,
                    }
                }
                bad
            })
        };
        for i in 0..200 {
            assert!(sink.wait_idle(Duration::from_secs(5)));
            let body = if i % 2 == 0 { a.clone() } else { b.clone() };
            assert_eq!(sink.submit(body), FileSubmit::Queued);
        }
        assert!(sink.wait_idle(Duration::from_secs(5)));
        stop.store(true, Ordering::Relaxed);
        assert_eq!(reader.join().unwrap(), 0);
        assert_eq!(sink.counts().written, 200);
        assert_eq!(std::fs::read(&path).unwrap(), b);
        assert_eq!(leftovers(&r), Vec::<String>::new());
    }

    /// SEC-4・REPAIR-5・#4337: 上限超過は書かずに数え、固定語彙の行を残す。ちょうど上限は書ける。
    #[test]
    fn cri6_4337_too_large_is_not_written_and_counted() {
        let r = root("too-large");
        let (notices, out) = buf_sink();
        let sink = OpStatsFileSink::spawn(target(&r, 1), notices.clone()).unwrap();
        assert_eq!(sink.submit(vec![b'x'; 65537]), FileSubmit::Queued);
        assert!(sink.wait_idle(Duration::from_secs(5)));
        let c = sink.counts();
        assert_eq!((c.too_large, c.written), (1, 0));
        assert!(!r.join("stats.jsonl").exists());
        assert_eq!(leftovers(&r), Vec::<String>::new());
        assert_eq!(
            text(&notices, &out),
            "{\"event\":\"op_stats_file_failed\",\"outcome\":\"error\",\"reason\":\"too_large\",\"count\":1}\n"
        );
        assert_eq!(sink.submit(vec![b'y'; 65536]), FileSubmit::Queued);
        assert!(sink.wait_idle(Duration::from_secs(5)));
        assert_eq!(sink.counts().written, 1);
        assert_eq!(
            std::fs::metadata(r.join("stats.jsonl")).unwrap().len(),
            65536
        );
    }
}
/// 書き込み内容を覚える fake。
struct Capture(Arc<Mutex<Vec<Vec<u8>>>>);
impl SnapshotWrite for Capture {
    fn replace(&self, contents: &[u8]) -> Result<(), SnapshotError> {
        lock(&self.0).push(contents.to_vec());
        Ok(())
    }
}

/// 1 回の書き込みに時間がかかる fake（完了を待つ経路の確認用）。
struct Slow(Duration);
impl SnapshotWrite for Slow {
    fn replace(&self, _contents: &[u8]) -> Result<(), SnapshotError> {
        std::thread::sleep(self.0);
        Ok(())
    }
}

/// REPAIR-4・#4340: idle のとき最後のスナップショットは 2 ブロック（共有 → oci の順）で `Written`、stderr へはブロックを出さない。
#[test]
fn repair4_4340_final_snapshot_is_written_with_both_blocks() {
    let (notices, out) = buf_sink();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = spawn_fake(Box::new(Capture(Arc::clone(&seen))), notices.clone());
    let recs = [recorder("a", 1), recorder("b", 2)];
    let r = write_final_snapshot(&recs, &sink, Duration::from_secs(5));
    assert_eq!(r, FinalSnapshot::Written);
    let got = lock(&seen).clone();
    assert_eq!(got.len(), 1);
    let body = String::from_utf8(got[0].clone()).unwrap();
    assert_eq!(
        body.matches("\"event\":\"op_stats_meta\"").count(),
        2,
        "{body}"
    );
    assert!(body.lines().last().unwrap().contains("op_stats_meta"));
    assert_eq!(sink.counts().written, 1);
    assert_eq!(text(&notices, &out), "");
}

/// REPAIR-5・#4340: 書き込み中の分は飛ばさず、期限内に終わるのを待ってから書く。
#[test]
fn repair5_4340_final_snapshot_waits_for_inflight_write() {
    let (notices, _out) = buf_sink();
    let sink = spawn_fake(Box::new(Slow(Duration::from_millis(150))), notices);
    assert_eq!(sink.submit(b"x\n".to_vec()), FileSubmit::Queued);
    let r = write_final_snapshot(&[recorder("a", 1)], &sink, Duration::from_secs(5));
    assert_eq!(r, FinalSnapshot::Written);
    let c = sink.counts();
    assert_eq!((c.written, c.skipped_busy, c.failed), (2, 0, 0));
}

/// REPAIR-5・#4340: writer が止まったままなら期限で諦め、`final_timeout` の行を残し、期限 + 余裕以内に戻る。
#[test]
fn repair5_4340_final_snapshot_times_out_on_stalled_writer() {
    let (gate, rx) = std::sync::mpsc::channel::<()>();
    let (notices, out) = buf_sink();
    let sink = spawn_fake(Box::new(Stall(rx)), notices.clone());
    assert_eq!(sink.submit(b"x\n".to_vec()), FileSubmit::Queued);
    let start = std::time::Instant::now();
    let r = write_final_snapshot(&[recorder("a", 1)], &sink, Duration::from_millis(200));
    let elapsed = start.elapsed();
    assert_eq!(r, FinalSnapshot::TimedOut);
    assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    assert_eq!(sink.counts().failed, 1);
    assert_eq!(
        text(&notices, &out),
        "{\"event\":\"op_stats_file_failed\",\"outcome\":\"error\",\"reason\":\"final_timeout\",\"count\":1}\n"
    );
    drop(gate);
}

/// REPAIR-4・#4340: 書き込みが失敗したら `Failed`（行は書き込み thread が残す）。
#[test]
fn repair4_4340_final_snapshot_reports_write_failure() {
    let (notices, out) = buf_sink();
    let sink = spawn_fake(Box::new(Fail(SnapshotError::WriteFailed)), notices.clone());
    let r = write_final_snapshot(&[recorder("a", 1)], &sink, Duration::from_secs(5));
    assert_eq!(r, FinalSnapshot::Failed);
    assert_eq!(sink.counts().failed, 1);
    assert!(text(&notices, &out).contains("\"reason\":\"write_failed\""));
}

/// SEC-4・#4340: 置き先を開けない失敗は全 variant でコードと文言が固定で、パスを含まない。
#[test]
fn sec4_4340_open_error_mapping_is_fixed_vocabulary() {
    use fandhe_container_plugin::PluginErrorCode as C;
    let cases = [
        (SnapshotError::Unsupported, C::Unimplemented, "unsupported"),
        (
            SnapshotError::RelativePath,
            C::InvalidArgument,
            "relative_path",
        ),
        (
            SnapshotError::InvalidPath,
            C::InvalidArgument,
            "invalid_path",
        ),
        (
            SnapshotError::UntrustedDirectory,
            C::PermissionDenied,
            "untrusted_directory",
        ),
        (
            SnapshotError::UntrustedProcess,
            C::PermissionDenied,
            "untrusted_process",
        ),
        (
            SnapshotError::TargetNotRegular,
            C::PermissionDenied,
            "target_not_regular",
        ),
        (
            SnapshotError::LimitOutOfRange,
            C::Internal,
            "limit_out_of_range",
        ),
        (SnapshotError::CreateFailed, C::Internal, "create_failed"),
    ];
    for (e, code, tag) in cases {
        let pe = op_stats_open_error(e);
        assert_eq!(pe.code(), code, "{tag}");
        assert_eq!(
            pe.message(),
            format!("failed to open the op-stats snapshot file: {tag}")
        );
        assert!(!pe.message().contains('/'));
    }
}

/// #4340: 試験用の周期指定は 10 進ミリ秒の 1..=60000 だけを採る。
#[test]
fn repair5_4340_interval_override_parsing() {
    assert_eq!(parse_interval_ms("300"), Some(Duration::from_millis(300)));
    assert_eq!(parse_interval_ms("1"), Some(Duration::from_millis(1)));
    assert_eq!(parse_interval_ms("60000"), Some(Duration::from_secs(60)));
    for bad in [
        "",
        "0",
        "60001",
        "-5",
        "1e3",
        "abc",
        " 5",
        "5 ",
        "+5",
        "99999999999999999999",
    ] {
        assert_eq!(parse_interval_ms(bad), None, "{bad:?}");
    }
}

/// #4340: 環境変数が無いときの周期は既定の 60 秒。
#[cfg(feature = "op-stats-test-support")]
#[test]
fn repair5_4340_interval_defaults_without_override() {
    if std::env::var_os("FANDHE_CONTAINER_TEST_OP_STATS_INTERVAL_MS").is_none() {
        assert_eq!(op_stats_export_interval(), OP_STATS_EXPORT_INTERVAL);
    }
}
