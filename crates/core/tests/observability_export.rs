//! `OpRecorder::export_json_lines` の結合試験（REPAIR-4・TASK-84.3）。
//!
//! 公開 API のみを外部から呼び、操作行・メタ行・出力先なし・書き込み失敗の契約を
//! 具体値で確認する。実機権限は不要で既定のテスト集合で動く。

use std::io::Write;
use std::time::Duration;

use fandhe_container_core::observability::{ExportSink, OpName, OpOutcome, OpRecorder};
use fandhe_container_core::traits::ErrorCode;

fn name(s: &str) -> OpName {
    OpName::new(s).expect("valid op name")
}

/// REPAIR-4: 操作行は名前昇順・固定キー・整数マイクロ秒、末尾にメタ行が付く。
#[test]
fn repair4_export_op_lines_and_meta_line() {
    let r = OpRecorder::new();
    let read = name("read");
    let ms = Duration::from_millis;
    r.record(&read, OpOutcome::Success, ms(1)).unwrap();
    r.record(&read, OpOutcome::Success, ms(3)).unwrap();
    r.record(&read, OpOutcome::Failure, ms(5)).unwrap();
    r.record(&name("create"), OpOutcome::Failure, ms(2))
        .unwrap();

    let mut out: Vec<u8> = Vec::new();
    let report = r.export_json_lines(Some(&mut out)).unwrap();
    let text = String::from_utf8(out).unwrap();

    let expected = concat!(
        "{\"event\":\"op_stats\",\"op\":\"create\",\"success\":0,\"failure\":1,\"count\":1,",
        "\"min_us\":2000,\"mean_us\":2000,\"p95_us\":2000,\"max_us\":2000}\n",
        "{\"event\":\"op_stats\",\"op\":\"read\",\"success\":2,\"failure\":1,\"count\":3,",
        "\"min_us\":1000,\"mean_us\":3000,\"p95_us\":5000,\"max_us\":5000}\n",
        "{\"event\":\"op_stats_meta\",\"ops\":2,\"dropped_records\":0}\n",
    );
    assert_eq!(text, expected);
    assert_eq!(report.lines_written(), 3);
    assert_eq!(report.ops(), 2);
    assert_eq!(report.sink(), ExportSink::Provided);
}

/// REPAIR-4: 空の記録器でもメタ行が 1 行だけ出る。
#[test]
fn repair4_export_empty_recorder_emits_only_meta_line() {
    let mut out: Vec<u8> = Vec::new();
    let report = OpRecorder::new().export_json_lines(Some(&mut out)).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "{\"event\":\"op_stats_meta\",\"ops\":0,\"dropped_records\":0}\n"
    );
    assert_eq!(report.lines_written(), 1);
    assert_eq!(report.ops(), 0);
}

/// REPAIR-4: 出力先なしは何も書かず成功し、集計対象数だけ返す。
#[test]
fn repair4_export_without_sink_writes_nothing() {
    let r = OpRecorder::new();
    r.record(&name("write"), OpOutcome::Success, Duration::from_millis(1))
        .unwrap();
    let report = r.export_json_lines(None).unwrap();
    assert_eq!(report.sink(), ExportSink::None);
    assert_eq!(report.lines_written(), 0);
    assert_eq!(report.ops(), 1);
}

/// 指定回数目の write または flush で失敗する出力先。
struct FailingSink {
    writes: usize,
    fail_write_at: Option<usize>,
    fail_flush: bool,
}

impl Write for FailingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writes += 1;
        if self.fail_write_at == Some(self.writes) {
            return Err(std::io::Error::other("secret /host/path"));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if self.fail_flush {
            return Err(std::io::Error::other("secret flush"));
        }
        Ok(())
    }
}

/// REPAIR-4・ERR-1: 書き込み・flush の失敗は panic せず Internal を返し、OS 詳細を漏らさない。
#[test]
fn repair4_export_write_and_flush_failures_return_internal() {
    let r = OpRecorder::new();
    r.record(&name("read"), OpOutcome::Success, Duration::from_millis(1))
        .unwrap();

    // 3 回目の write（2 行目本体）で失敗 = 1 行書けた時点。
    let mut sink = FailingSink {
        writes: 0,
        fail_write_at: Some(3),
        fail_flush: false,
    };
    let e = r.export_json_lines(Some(&mut sink)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::Internal);
    let msg = e.to_string();
    assert!(msg.contains("after 1 lines"), "unexpected message: {msg}");
    assert!(!msg.contains("secret"), "leaked OS detail: {msg}");

    let mut sink = FailingSink {
        writes: 0,
        fail_write_at: None,
        fail_flush: true,
    };
    let e = r.export_json_lines(Some(&mut sink)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::Internal);
    let msg = e.to_string();
    assert!(msg.contains("after 2 lines"), "unexpected message: {msg}");
    assert!(!msg.contains("secret"), "leaked OS detail: {msg}");
}
