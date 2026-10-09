//! 記録器の単体試験（GPU-6・REPAIR-2・REPAIR-12・TASK-172 F6・#1602。3 OS・既定集合）。

use std::io;

use fandhe_container_plugin_macos::gpu::venus::replay::{
    MAX_RECORD_COUNT, MAX_RECORD_PAYLOAD_LEN, MAX_RECORDING_LEN, validate,
};

use super::*;

fn limits(rec: u32, count: u32, total: u64) -> RecorderLimits {
    RecorderLimits::new(rec, count, total).expect("limits")
}

#[test]
fn task1602_gpu6_two_records_validate_with_exact_payloads() {
    let mut r = SubmitRecorder::new(Vec::new(), RecorderLimits::default());
    let a = vec![0xbcu8; 40];
    let b = vec![7u8; 9];
    assert_eq!(r.record(&a), RecordOutcome::Recorded);
    assert_eq!(r.record(&b), RecordOutcome::Recorded);
    let (out, summary) = r.finish();
    let bytes = out.expect("finish");
    assert_eq!(
        summary,
        RecordSummary {
            records: 2,
            skipped: 0,
            stopped: None
        }
    );
    let v = validate(&bytes).expect("validate");
    assert_eq!(v.records().len(), 2);
    assert_eq!(v.records()[0].payload, a.as_slice());
    assert_eq!(v.records()[1].payload, b.as_slice());
    assert_eq!(v.records()[0].header.seqno, 0);
    assert_eq!(v.records()[1].header.seqno, 1);
}

#[test]
fn task1602_gpu6_record_count_limit_stops_once_then_skips() {
    let mut r = SubmitRecorder::new(Vec::new(), limits(1024, 2, 1 << 20));
    assert_eq!(r.record(&[1]), RecordOutcome::Recorded);
    assert_eq!(r.record(&[2]), RecordOutcome::Recorded);
    assert_eq!(
        r.record(&[3]),
        RecordOutcome::Stopped(StopReason::TooManyRecords)
    );
    // 停止後は小さい提出も記録しない。
    assert_eq!(r.record(&[]), RecordOutcome::Skipped);
    let (out, summary) = r.finish();
    assert_eq!(
        summary,
        RecordSummary {
            records: 2,
            skipped: 1,
            stopped: Some(StopReason::TooManyRecords)
        }
    );
    let bytes = out.expect("finish");
    assert_eq!(validate(&bytes).expect("validate").records().len(), 2);
}

#[test]
fn task1602_gpu6_total_and_record_length_limits() {
    // ファイルヘッダ 20 + (12 + 4 + 10) = 46 は収まり、2 件目 (+26 = 72) は 60 を超える。
    let mut r = SubmitRecorder::new(Vec::new(), limits(1024, 10, 60));
    assert_eq!(r.record(&[0; 10]), RecordOutcome::Recorded);
    assert_eq!(
        r.record(&[0; 10]),
        RecordOutcome::Stopped(StopReason::RecordingTooLarge)
    );
    let mut r = SubmitRecorder::new(Vec::new(), limits(8, 10, 1 << 20));
    assert_eq!(r.record(&[0; 8]), RecordOutcome::Recorded);
    assert_eq!(
        r.record(&[0; 9]),
        RecordOutcome::Stopped(StopReason::PayloadTooLarge)
    );
    assert_eq!(r.finish().1.records, 1);
}

#[test]
fn task1602_gpu6_limits_new_rejects_zero_and_over_format_constants() {
    assert!(RecorderLimits::new(0, 1, 1).is_none());
    assert!(RecorderLimits::new(1, 0, 1).is_none());
    assert!(RecorderLimits::new(1, 1, 0).is_none());
    assert!(RecorderLimits::new(MAX_RECORD_PAYLOAD_LEN + 1, 1, 1).is_none());
    assert!(RecorderLimits::new(1, MAX_RECORD_COUNT + 1, 1).is_none());
    assert!(RecorderLimits::new(1, 1, MAX_RECORDING_LEN + 1).is_none());
    assert_eq!(
        RecorderLimits::new(MAX_RECORD_PAYLOAD_LEN, MAX_RECORD_COUNT, MAX_RECORDING_LEN),
        Some(RecorderLimits::default())
    );
}

#[test]
fn task1602_gpu6_empty_payload_is_one_record() {
    let mut r = SubmitRecorder::new(Vec::new(), RecorderLimits::default());
    assert_eq!(r.record(&[]), RecordOutcome::Recorded);
    let bytes = r.finish().0.expect("finish");
    let v = validate(&bytes).expect("validate");
    assert_eq!(v.records().len(), 1);
    assert_eq!(v.records()[0].payload.len(), 0);
}

struct FailingWriter;

impl io::Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::Other))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn repair2_write_failure_is_reported_and_summary_keeps_count() {
    let mut r = SubmitRecorder::new(FailingWriter, RecorderLimits::default());
    assert_eq!(r.record(&[1, 2, 3]), RecordOutcome::Recorded);
    let (out, summary) = r.finish();
    assert!(out.is_err());
    assert_eq!(summary.records, 1);
    assert_eq!(summary.stopped, None);
}

#[test]
fn task1602_gpu6_stop_reason_vocabulary_is_fixed() {
    assert_eq!(StopReason::PayloadTooLarge.as_str(), "payload_too_large");
    assert_eq!(StopReason::TooManyRecords.as_str(), "too_many_records");
    assert_eq!(
        StopReason::RecordingTooLarge.as_str(),
        "recording_too_large"
    );
    assert_eq!(StopReason::WriterRejected.as_str(), "writer_rejected");
}
