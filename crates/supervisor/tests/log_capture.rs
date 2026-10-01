//! logs 捕捉の土台の受け入れ照合テスト（TASK-157.7・#241・SUP-1・REPAIR-3・REPAIR-12）。
//!
//! 文字列照合は構文解析ではない（tests/monitor_loop.rs と同じ手法）。

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use fandhe_container_supervisor::logs::{
    LogCapture, MemoryLogSink, OutputStreams, ReaderBudget, StreamKind,
};

/// AC1: 別スレッドが書く stdout / stderr 相当のパイプの両方を捕捉できる。
#[test]
fn sup1_task157_7_captures_both_streams_from_pipes() {
    let (out_r, mut out_w) = std::io::pipe().unwrap();
    let (err_r, mut err_w) = std::io::pipe().unwrap();
    let sink = Arc::new(MemoryLogSink::default());
    let cap = LogCapture::start(
        OutputStreams::new(
            &ReaderBudget::with_max_limit(),
            Some(Box::new(out_r)),
            Some(Box::new(err_r)),
        ),
        sink.clone(),
    )
    .unwrap();
    let w = std::thread::spawn(move || {
        out_w.write_all(b"hello\nworld\n").unwrap();
        err_w.write_all(b"oops\n").unwrap();
    });
    w.join().unwrap();
    let sum = cap.drain(Duration::from_secs(10)).unwrap();
    assert_eq!(sum.stdout().unwrap().lines(), 2);
    assert_eq!(sum.stderr().unwrap().lines(), 1);
    let lines = sink.snapshot().unwrap();
    let of = |k: StreamKind| -> Vec<Vec<u8>> {
        lines
            .iter()
            .filter(|l| l.stream == k)
            .map(|l| l.bytes.clone())
            .collect()
    };
    assert_eq!(
        of(StreamKind::Stdout),
        vec![b"hello".to_vec(), b"world".to_vec()]
    );
    assert_eq!(of(StreamKind::Stderr), vec![b"oops".to_vec()]);
}

/// AC2: 永続化・ローテーションが未実装であることと将来仕様（SUP-7・TASK-164）が明記されている。
#[test]
fn sup1_task157_7_logs_rs_documents_unimplemented_future_spec() {
    const LOGS_RS: &str = include_str!("../src/logs.rs");
    for needle in ["SUP-7", "TASK-164", "未実装", "永続化", "ローテーション"] {
        assert!(LOGS_RS.contains(needle), "logs.rs must mention {needle}");
    }
}

/// logs.rs は unsafe・OS 分岐・グローバル状態を持たない。
#[test]
fn sup1_task157_7_logs_rs_has_no_unsafe_or_global_state() {
    const LOGS_RS: &str = include_str!("../src/logs.rs");
    let body = LOGS_RS.split("#[cfg(test)]").next().unwrap_or(LOGS_RS);
    let code: String = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in [
        "\nstatic ",
        "\npub static ",
        "thread_local",
        "OnceLock",
        "LazyLock",
        "unsafe",
        "cfg(target_os",
    ] {
        assert!(!code.contains(banned), "logs.rs must not contain {banned}");
    }
}
