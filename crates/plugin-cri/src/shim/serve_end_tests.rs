//! shim の serve の終了時の操作統計の書き出しの試験（CRI-5・REPAIR-4・REPAIR-5・#4408）。
//!
//! 親の `serve_end` から `#[cfg(test)]` で取り込む。実の `LineSink` に行を捕まえる writer を付け、具体値で照合する。

use std::io::Write;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};

use super::*;

/// 書かれたバイト列を溜める writer。
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 行を捕まえる sink と、捕まえたバイト列の取り出し口（他の試験からも使う）。
pub(crate) fn capture_sink() -> (LineSink, Arc<Mutex<Vec<u8>>>) {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let sink = LineSink::spawn(Box::new(Capture(Arc::clone(&buf))), 64);
    (sink, buf)
}

/// 捕まえたバイト列を行に分ける。
pub(crate) fn captured_lines(buf: &Arc<Mutex<Vec<u8>>>) -> Vec<String> {
    String::from_utf8_lossy(&buf.lock().expect("lock"))
        .lines()
        .map(str::to_owned)
        .collect()
}

fn record(rec: &OpRecorder, name: &str, ok: bool, n: usize) {
    let op = OpName::new(name).expect("name");
    for _ in 0..n {
        let outcome = if ok {
            OpOutcome::Success
        } else {
            OpOutcome::Failure
        };
        rec.record(&op, outcome, Duration::from_millis(1))
            .expect("record");
    }
}

/// #4408・REPAIR-4: 終了時の書き出しは serve 開始後に増えた 2 種の計数を具体値で載せ、`op_stats_meta` 行で終わる。
#[test]
fn repair4_4408_final_export_carries_exec_counts() {
    let rec = Arc::new(OpRecorder::new());
    record(&rec, "shim_exec_pid_unreported", false, 2);
    record(&rec, "shim_exec_instance_changed", false, 1);
    let (sink, buf) = capture_sink();
    let ex = FinalOpStatsExport::new(Arc::clone(&rec), sink, Duration::from_secs(5));
    assert_eq!(
        ex.export(),
        FinalExportOutcome::Exported {
            lines: 3,
            flushed: true
        }
    );
    let lines = captured_lines(&buf);
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(
        lines[0].starts_with(
            r#"{"event":"op_stats","op":"shim_exec_instance_changed","success":0,"failure":1,"count":1,"#
        ),
        "{lines:?}"
    );
    assert!(
        lines[1].starts_with(
            r#"{"event":"op_stats","op":"shim_exec_pid_unreported","success":0,"failure":2,"count":2,"#
        ),
        "{lines:?}"
    );
    assert_eq!(
        lines[2],
        r#"{"event":"op_stats_meta","ops":2,"dropped_records":0}"#
    );
    // 2 回目は何もしない（1 回だけ）。
    assert_eq!(ex.export(), FinalExportOutcome::Empty);
    assert_eq!(captured_lines(&buf).len(), 3);
}

/// #4408: 計数が 0 件なら何も出さない。
#[test]
fn repair4_4408_final_export_silent_when_empty() {
    let rec = Arc::new(OpRecorder::new());
    let (sink, buf) = capture_sink();
    let ex = FinalOpStatsExport::new(Arc::clone(&rec), sink.clone(), Duration::from_secs(1));
    assert_eq!(ex.export(), FinalExportOutcome::Empty);
    assert!(sink.flush(Duration::from_secs(1)));
    assert!(buf.lock().expect("lock").is_empty());
}

/// REPAIR-5・#4408: 受け手が詰まっても期限で戻り、`flushed: false` になる。
#[test]
fn repair5_4408_final_export_returns_by_deadline() {
    struct Stall(Receiver<()>);
    impl Write for Stall {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            let _ = self.0.recv();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let rec = Arc::new(OpRecorder::new());
    record(&rec, "shim_exec_pid_unreported", false, 1);
    let (gate, rx) = mpsc::channel::<()>();
    let sink = LineSink::spawn(Box::new(Stall(rx)), 8);
    let ex = FinalOpStatsExport::new(rec, sink, Duration::from_millis(200));
    let t = Instant::now();
    let out = ex.export();
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(
        out,
        FinalExportOutcome::Exported {
            lines: 2,
            flushed: false
        }
    );
    drop(gate);
}
