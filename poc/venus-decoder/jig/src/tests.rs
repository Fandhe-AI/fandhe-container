//! アダプタ・ログ照合器のユニットテスト（GPU-6・TASK-172.4）。期待値は具体値で書く。

use fandhe_container_plugin_macos::gpu::venus::VenusCapset;

use crate::adapter::{CtrlAdapter, Handled, MAX_CONTEXTS};
use crate::ctrl::{
    CMD_CTX_CREATE, CMD_CTX_DESTROY, CMD_GET_CAPSET, CMD_GET_CAPSET_INFO, CMD_GET_DISPLAY_INFO,
    FLAG_FENCE, HDR_LEN, RESP_ERR_INVALID_CONTEXT_ID, RESP_ERR_INVALID_PARAMETER,
    RESP_ERR_OUT_OF_MEMORY, RESP_ERR_UNSPEC, RESP_OK_CAPSET, RESP_OK_CAPSET_INFO,
    RESP_OK_DISPLAY_INFO, RESP_OK_NODATA,
};
use crate::device;
use crate::log::{
    LogError, LogFileError, LogSink, MAX_LINES, MAX_LOG_BYTES, PRIORITY_RESERVE_LINES,
    find_capset_queries, is_priority_line, read_log_file,
};

/// 状態を持たない単発要求用（ctx 表は毎回空）。
fn handle_ctrl(req: &[u8]) -> Handled {
    CtrlAdapter::default().handle_ctrl(req)
}

fn req(cmd: u32, flags: u32, fence: u64, a: u32, b: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&cmd.to_le_bytes());
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&fence.to_le_bytes());
    v.extend_from_slice(&7u32.to_le_bytes()); // ctx_id
    v.extend_from_slice(&[3, 0, 0, 0]); // ring_idx + padding
    v.extend_from_slice(&a.to_le_bytes());
    v.extend_from_slice(&b.to_le_bytes());
    v
}

fn word(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
}

#[test]
fn task172_4_gpu6_capset_info_index0() {
    let h = handle_ctrl(&req(CMD_GET_CAPSET_INFO, 0, 0, 0, 0));
    let b = h.response.as_bytes();
    assert_eq!(h.response.resp_type(), RESP_OK_CAPSET_INFO);
    assert_eq!(b.len(), HDR_LEN + 16);
    assert_eq!(word(b, HDR_LEN), 4);
    assert_eq!(word(b, HDR_LEN + 4), 0);
    assert_eq!(word(b, HDR_LEN + 8), 160);
    assert_eq!(
        h.log_line,
        "venus_jig event=capset_query cmd=GET_CAPSET_INFO capset_index=0 result=ok max_size=160"
    );
}

#[test]
fn task172_4_gpu6_capset_info_index1_rejected() {
    let h = handle_ctrl(&req(CMD_GET_CAPSET_INFO, 0, 0, 1, 0));
    assert_eq!(h.response.resp_type(), RESP_ERR_INVALID_PARAMETER);
    assert_eq!(h.response.as_bytes().len(), HDR_LEN);
}

#[test]
fn task172_4_gpu6_get_capset_venus_v0() {
    let h = handle_ctrl(&req(CMD_GET_CAPSET, 0, 0, 4, 0));
    let b = h.response.as_bytes();
    assert_eq!(h.response.resp_type(), RESP_OK_CAPSET);
    assert_eq!(b.len(), HDR_LEN + 160);
    assert_eq!(&b[HDR_LEN..], &VenusCapset::minimal().encode()[..]);
    assert_eq!(
        h.log_line,
        "venus_jig event=capset_query cmd=GET_CAPSET capset_id=4 version=0 result=ok max_size=160"
    );
}

#[test]
fn task172_4_gpu6_get_capset_bad_id_or_version() {
    for (id, ver) in [(5, 0), (4, 1)] {
        let h = handle_ctrl(&req(CMD_GET_CAPSET, 0, 0, id, ver));
        assert_eq!(h.response.resp_type(), RESP_ERR_INVALID_PARAMETER);
        assert!(h.log_line.ends_with("result=invalid_parameter max_size=0"));
    }
}

#[test]
fn task172_4_gpu6_bad_lengths_rejected() {
    let ok = req(CMD_GET_CAPSET, 0, 0, 4, 0);
    let short = &ok[..ok.len() - 1];
    let mut long = ok.clone();
    long.push(0);
    for r in [short, &long[..], &ok[..10]] {
        let h = handle_ctrl(r);
        assert_eq!(h.response.resp_type(), RESP_ERR_INVALID_PARAMETER);
    }
}

#[test]
fn task172_4_gpu6_unknown_type_is_unspec() {
    // 0x0101 = RESOURCE_CREATE_2D、0x0208 = RESOURCE_MAP_BLOB、0x0209 = RESOURCE_UNMAP_BLOB（いずれも未実装。#1601 で BLOB 作成と SUBMIT_3D は実装済み）。
    for (cmd, dec) in [(0x0101u32, 257), (0x0208, 520), (0x0209, 521)] {
        let h = handle_ctrl(&req(cmd, 0, 0, 0, 0));
        assert_eq!(h.response.resp_type(), RESP_ERR_UNSPEC);
        assert_eq!(
            h.log_line,
            format!("venus_jig event=ctrl_rejected cmd_type={dec} result=unspec")
        );
    }
}

#[test]
fn task172_4_gpu6_fence_is_carried_over() {
    let h = handle_ctrl(&req(CMD_GET_CAPSET, FLAG_FENCE, 0x1122_3344_5566, 4, 0));
    let b = h.response.as_bytes();
    assert_eq!(word(b, 4), FLAG_FENCE);
    assert_eq!(&b[8..16], &0x1122_3344_5566u64.to_le_bytes());
    assert_eq!(word(b, 16), 7);
    assert_eq!(b[20], 3);
    let nofence = handle_ctrl(&req(CMD_GET_CAPSET, 0, 99, 4, 0));
    assert_eq!(&nofence.response.as_bytes()[4..24], &[0u8; 20]);
}

#[test]
fn task172_4_gpu6_device_features_and_config() {
    assert_eq!(device::FEATURES, 0x1_0000_0019);
    let cfg = device::config_bytes();
    assert_eq!(&cfg[12..16], &1u32.to_le_bytes());
    assert_eq!(&cfg[..12], &[0u8; 12]);
}

#[test]
fn task172_4_gpu6_checker_counts_success_lines() {
    let log = "\
venus_jig event=capset_query cmd=GET_CAPSET_INFO capset_index=0 result=ok max_size=160
venus_jig event=capset_query cmd=GET_CAPSET capset_id=4 version=0 result=ok max_size=160

venus_jig event=capset_query cmd=GET_CAPSET capset_id=5 version=0 result=ok max_size=160
venus_jig event=capset_query cmd=GET_CAPSET capset_id=4 version=1 result=invalid_parameter max_size=0
garbage line
";
    let r = find_capset_queries(log).unwrap();
    assert_eq!(r.venus_get_capset_ok, 1);
    assert_eq!(r.info_ok, 1);
    assert_eq!(r.malformed_lines, 1);
}

#[test]
fn task172_4_gpu6_checker_rejects_duplicate_and_bad_success_fields() {
    let log = "\
venus_jig event=capset_query cmd=GET_CAPSET capset_id=4 version=0 result=invalid_parameter result=ok max_size=160
venus_jig event=capset_query cmd=GET_CAPSET capset_id=4 version=9 result=ok max_size=160
venus_jig event=capset_query cmd=GET_CAPSET capset_id=4 version=0 result=ok max_size=0
venus_jig event=capset_query cmd=GET_CAPSET_INFO capset_index=0 result=ok max_size=abc
";
    let r = find_capset_queries(log).unwrap();
    assert_eq!(r.venus_get_capset_ok, 0);
    assert_eq!(r.info_ok, 0);
    assert_eq!(r.malformed_lines, 4);
}

#[test]
fn task172_4_gpu6_checker_limits() {
    let long = format!("venus_jig {}", "a".repeat(600));
    assert_eq!(find_capset_queries(&long).unwrap().malformed_lines, 1);
    assert_eq!(
        find_capset_queries(&"x".repeat(MAX_LOG_BYTES + 1)),
        Err(LogError::TooLarge)
    );
    assert_eq!(
        find_capset_queries(&"\n".repeat(MAX_LINES + 1)),
        Err(LogError::TooManyLines)
    );
}

fn hdr_req(cmd: u32, flags: u32, ctx_id: u32, total: usize) -> Vec<u8> {
    let mut v = vec![0u8; total.max(HDR_LEN)];
    v[..4].copy_from_slice(&cmd.to_le_bytes());
    v[4..8].copy_from_slice(&flags.to_le_bytes());
    v[8..16].copy_from_slice(&0x55u64.to_le_bytes());
    v[16..20].copy_from_slice(&ctx_id.to_le_bytes());
    v[20] = 2;
    v.truncate(total);
    v
}

fn create_req(ctx_id: u32, nlen: u32, init: u32, total: usize) -> Vec<u8> {
    let mut v = hdr_req(CMD_CTX_CREATE, 0, ctx_id, total.max(HDR_LEN + 8));
    v[HDR_LEN..HDR_LEN + 4].copy_from_slice(&nlen.to_le_bytes());
    v[HDR_LEN + 4..HDR_LEN + 8].copy_from_slice(&init.to_le_bytes());
    v.truncate(total);
    v
}

fn destroy_req(ctx_id: u32, total: usize) -> Vec<u8> {
    hdr_req(CMD_CTX_DESTROY, 0, ctx_id, total)
}

#[test]
fn task1520_gpu6_display_info_all_scanouts_disabled() {
    let h = handle_ctrl(&hdr_req(CMD_GET_DISPLAY_INFO, 0, 0, 24));
    let b = h.response.as_bytes();
    assert_eq!(h.response.resp_type(), RESP_OK_DISPLAY_INFO);
    assert_eq!(b.len(), 408);
    assert_eq!(&b[HDR_LEN..], &[0u8; 384][..]);
    assert_eq!(
        h.log_line,
        "venus_jig event=display_info cmd=GET_DISPLAY_INFO num_scanouts=0 result=ok"
    );
}

#[test]
fn task1520_gpu6_display_info_bad_length() {
    for n in [23usize, 25, 32] {
        let h = handle_ctrl(&hdr_req(CMD_GET_DISPLAY_INFO, 0, 0, n));
        if n < HDR_LEN {
            assert_eq!(h.response.resp_type(), RESP_ERR_INVALID_PARAMETER);
            continue;
        }
        assert_eq!(h.response.resp_type(), RESP_ERR_INVALID_PARAMETER);
        assert_eq!(h.response.as_bytes().len(), HDR_LEN);
        assert_eq!(
            h.log_line,
            "venus_jig event=display_info cmd=GET_DISPLAY_INFO num_scanouts=0 result=invalid_parameter"
        );
    }
}

#[test]
fn task1520_gpu6_ctx_create_ok_and_log_has_no_name_bytes() {
    let mut a = CtrlAdapter::default();
    let mut r = create_req(1, 5, 4, 96);
    r[HDR_LEN + 8..HDR_LEN + 13].copy_from_slice(b"a\nb\xc3\xa9");
    let h = a.handle_ctrl(&r);
    assert_eq!(h.response.resp_type(), RESP_OK_NODATA);
    assert_eq!(h.response.as_bytes().len(), HDR_LEN);
    assert_eq!(
        h.log_line,
        "venus_jig event=ctx cmd=CTX_CREATE ctx_id=1 capset_id=4 nlen=5 result=ok"
    );
    assert!(!h.log_line.contains('\n'));
}

#[test]
fn task1520_gpu6_ctx_create_rejects() {
    let mut a = CtrlAdapter::default();
    for (init, cap) in [(3u32, 3), (0, 0), (0x104, 4)] {
        let h = a.handle_ctrl(&create_req(1, 5, init, 96));
        assert_eq!(h.response.resp_type(), RESP_ERR_INVALID_PARAMETER);
        assert_eq!(
            h.log_line,
            format!(
                "venus_jig event=ctx cmd=CTX_CREATE ctx_id=1 capset_id={cap} nlen=5 result=invalid_parameter"
            )
        );
    }
    let h = a.handle_ctrl(&create_req(1, 65, 4, 96));
    assert_eq!(h.response.resp_type(), RESP_ERR_INVALID_PARAMETER);
    assert_eq!(
        h.log_line,
        "venus_jig event=ctx cmd=CTX_CREATE ctx_id=1 capset_id=-1 nlen=65 result=invalid_parameter"
    );
    for n in [95usize, 97, 24] {
        let h = a.handle_ctrl(&create_req(1, 5, 4, n));
        assert_eq!(h.response.resp_type(), RESP_ERR_INVALID_PARAMETER);
        assert_eq!(
            h.log_line,
            "venus_jig event=ctx cmd=CTX_CREATE ctx_id=1 capset_id=-1 nlen=-1 result=invalid_parameter"
        );
    }
    // 拒否では表が変わらない: ctx 1 は未作成のまま。
    assert_eq!(
        a.handle_ctrl(&destroy_req(1, 24)).response.resp_type(),
        RESP_ERR_INVALID_CONTEXT_ID
    );
}

#[test]
fn task1520_gpu6_ctx_duplicate_zero_and_destroy() {
    let mut a = CtrlAdapter::default();
    assert_eq!(
        a.handle_ctrl(&create_req(1, 5, 4, 96)).response.resp_type(),
        RESP_OK_NODATA
    );
    let dup = a.handle_ctrl(&create_req(1, 5, 4, 96));
    assert_eq!(dup.response.resp_type(), RESP_ERR_INVALID_CONTEXT_ID);
    assert_eq!(
        dup.log_line,
        "venus_jig event=ctx cmd=CTX_CREATE ctx_id=1 capset_id=4 nlen=5 result=invalid_context_id"
    );
    let zero = a.handle_ctrl(&create_req(0, 5, 4, 96));
    assert_eq!(zero.response.resp_type(), RESP_ERR_INVALID_CONTEXT_ID);
    let bad_len = a.handle_ctrl(&destroy_req(1, 25));
    assert_eq!(bad_len.response.resp_type(), RESP_ERR_INVALID_PARAMETER);
    assert_eq!(
        bad_len.log_line,
        "venus_jig event=ctx cmd=CTX_DESTROY ctx_id=1 result=invalid_parameter"
    );
    let ok = a.handle_ctrl(&destroy_req(1, 24));
    assert_eq!(ok.response.resp_type(), RESP_OK_NODATA);
    assert_eq!(
        ok.log_line,
        "venus_jig event=ctx cmd=CTX_DESTROY ctx_id=1 result=ok"
    );
    for id in [1, 9] {
        let h = a.handle_ctrl(&destroy_req(id, 24));
        assert_eq!(h.response.resp_type(), RESP_ERR_INVALID_CONTEXT_ID);
        assert_eq!(
            h.log_line,
            format!("venus_jig event=ctx cmd=CTX_DESTROY ctx_id={id} result=invalid_context_id")
        );
    }
}

#[test]
fn task1520_gpu6_ctx_table_limit() {
    let mut a = CtrlAdapter::default();
    for id in 1..=MAX_CONTEXTS as u32 {
        assert_eq!(
            a.handle_ctrl(&create_req(id, 0, 4, 96))
                .response
                .resp_type(),
            RESP_OK_NODATA
        );
    }
    let over = a.handle_ctrl(&create_req(1000, 0, 4, 96));
    assert_eq!(over.response.resp_type(), RESP_ERR_OUT_OF_MEMORY);
    assert_eq!(
        over.log_line,
        "venus_jig event=ctx cmd=CTX_CREATE ctx_id=1000 capset_id=4 nlen=0 result=out_of_memory"
    );
    // 破棄で空きができれば再び作れる。
    a.handle_ctrl(&destroy_req(5, 24));
    assert_eq!(
        a.handle_ctrl(&create_req(1000, 0, 4, 96))
            .response
            .resp_type(),
        RESP_OK_NODATA
    );
}

#[test]
fn task1520_gpu6_ctx_fence_is_carried_over() {
    let mut r = create_req(7, 0, 4, 96);
    r[4..8].copy_from_slice(&FLAG_FENCE.to_le_bytes());
    r[8..16].copy_from_slice(&0xabcdu64.to_le_bytes());
    r[20] = 3;
    let h = CtrlAdapter::default().handle_ctrl(&r);
    let b = h.response.as_bytes();
    assert_eq!(word(b, 4), FLAG_FENCE);
    assert_eq!(&b[8..16], &0xabcdu64.to_le_bytes());
    assert_eq!(word(b, 16), 7);
    assert_eq!(b[20], 3);
}

#[test]
fn task1520_gpu6_new_log_lines_do_not_disturb_checker() {
    let mut a = CtrlAdapter::default();
    let mut log = String::new();
    for r in [
        hdr_req(CMD_GET_DISPLAY_INFO, 0, 0, 24),
        create_req(1, 3, 4, 96),
        destroy_req(1, 24),
        destroy_req(1, 24),
        req(0x0101, 0, 0, 0, 0),
    ] {
        log.push_str(&a.handle_ctrl(&r).log_line);
        log.push('\n');
    }
    let rep = find_capset_queries(&log).unwrap();
    assert_eq!(
        (rep.venus_get_capset_ok, rep.info_ok, rep.malformed_lines),
        (0, 0, 0)
    );
}

const OK_LINE: &str =
    "venus_jig event=capset_query cmd=GET_CAPSET capset_id=4 version=0 result=ok max_size=160";

#[test]
fn gpu6_log_sink_writes_lines_within_limits() {
    let mut sink = LogSink::new(Vec::new());
    sink.write_line(OK_LINE);
    assert!(!sink.truncated());
    let (out, err) = sink.into_inner();
    assert_eq!(err, None);
    assert_eq!(String::from_utf8(out).unwrap(), format!("{OK_LINE}\n"));
}

#[test]
fn gpu6_log_sink_truncates_once_at_line_count_limit_and_matcher_accepts() {
    let mut sink = LogSink::new(Vec::new());
    sink.write_line(OK_LINE);
    for _ in 0..(MAX_LINES + 10) {
        sink.write_line("venus_jig event=tick");
    }
    assert!(sink.truncated());
    let (out, _) = sink.into_inner();
    let text = String::from_utf8(out).unwrap();
    assert_eq!(text.lines().count(), MAX_LINES - PRIORITY_RESERVE_LINES);
    assert_eq!(text.matches("event=log_truncated").count(), 1);
    assert_eq!(
        text.lines().last(),
        Some("venus_jig event=log_truncated reason=limit")
    );
    let report = find_capset_queries(&text).expect("within limits");
    assert_eq!(report.venus_get_capset_ok, 1);
    assert_eq!(report.malformed_lines, 0);
}

#[test]
fn gpu6_log_sink_truncates_at_byte_limit_and_over_long_line() {
    let mut sink = LogSink::new(Vec::new());
    let long = "venus_jig event=need_reply_ignored request=1 ".repeat(30);
    assert!(long.len() > 512);
    sink.write_line(&long);
    sink.write_line(OK_LINE);
    let (out, _) = sink.into_inner();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "venus_jig event=log_truncated reason=limit\n"
    );

    // 総量: 1 行 500 バイト前後を詰め続けても 4 MiB を超えない。
    let mut sink = LogSink::new(Vec::new());
    let filler = format!(
        "venus_jig event=need_reply_ignored request={}",
        "9".repeat(450)
    );
    for _ in 0..9000 {
        sink.write_line(&filler);
    }
    assert!(sink.truncated());
    let (out, _) = sink.into_inner();
    assert!(out.len() <= MAX_LOG_BYTES, "len={}", out.len());
    let text = String::from_utf8(out).unwrap();
    assert_eq!(find_capset_queries(&text).unwrap().malformed_lines, 0);
}

struct FailingWriter(usize);
impl std::io::Write for FailingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.0 == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::StorageFull));
        }
        self.0 -= 1;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn repair5_log_sink_keeps_first_write_error_and_stops() {
    let mut sink = LogSink::new(FailingWriter(1));
    sink.write_line(OK_LINE);
    sink.write_line(OK_LINE);
    sink.write_line(OK_LINE);
    let (w, err) = sink.into_inner();
    assert_eq!(err, Some(std::io::ErrorKind::StorageFull));
    assert_eq!(w.0, 0);
}

fn scratch_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let p = std::env::temp_dir().join(format!(
        "venus-jig-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&p).expect("scratch dir");
    p
}

#[test]
fn d2_read_log_file_rejects_non_regular_without_opening() {
    let dir = scratch_dir("rd");
    assert_eq!(read_log_file(&dir), Err(LogFileError::NotRegularFile));
    let file = dir.join("ok.log");
    std::fs::write(&file, format!("{OK_LINE}\n")).unwrap();
    assert_eq!(read_log_file(&file).unwrap(), format!("{OK_LINE}\n"));
    assert_eq!(
        read_log_file(&dir.join("missing.log")),
        Err(LogFileError::Open)
    );
    #[cfg(unix)]
    {
        let link = dir.join("link.log");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(read_log_file(&link), Err(LogFileError::NotRegularFile));
    }
    let big = dir.join("big.log");
    std::fs::write(&big, vec![b'a'; MAX_LOG_BYTES + 1]).unwrap();
    assert_eq!(read_log_file(&big), Err(LogFileError::TooLarge));
    let bad = dir.join("bad.log");
    std::fs::write(&bad, [0xff, 0xfe]).unwrap();
    assert_eq!(read_log_file(&bad), Err(LogFileError::NotUtf8));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// GPU-6・TASK-172 F6・#1602: 記録の 2 行は固定語彙と数値だけで、照合器は壊れた行に数えない。
#[test]
fn task1602_gpu6_record_lines_are_fixed_vocabulary_and_not_malformed() {
    use crate::log::{find_capset_queries, record_stopped_line, record_summary_line};
    use crate::recording::{RecordSummary, StopReason};
    let stopped = record_stopped_line(StopReason::TooManyRecords, 3);
    assert_eq!(
        stopped,
        "venus_jig event=record_stopped reason=too_many_records records=3"
    );
    let ok = RecordSummary {
        records: 2,
        skipped: 0,
        stopped: None,
    };
    let done = record_summary_line(&ok, true);
    assert_eq!(
        done,
        "venus_jig event=record_summary records=2 skipped=0 stopped=none result=ok"
    );
    let cut = RecordSummary {
        records: 1,
        skipped: 4,
        stopped: Some(StopReason::RecordingTooLarge),
    };
    let failed = record_summary_line(&cut, false);
    assert_eq!(
        failed,
        "venus_jig event=record_summary records=1 skipped=4 stopped=recording_too_large result=write_failed"
    );
    let report = find_capset_queries(&[stopped, done, failed].join("\n")).expect("report");
    assert_eq!(report.malformed_lines, 0);
    assert_eq!(report.venus_get_capset_ok, 0);
}

/// ログが上限で打ち切られた後も、優先行（record_stopped / record_summary）は取り置き領域に書かれる（REPAIR-4）。
#[test]
fn task1602_gpu6_priority_lines_survive_log_truncation() {
    let mut sink = LogSink::new(Vec::new());
    let line = format!("venus_jig event=x pad={}", "a".repeat(400));
    for _ in 0..(MAX_LOG_BYTES / line.len() + 10) {
        sink.write_line(&line);
    }
    assert!(sink.truncated());
    sink.write_priority("venus_jig event=record_stopped reason=too_many_records records=3");
    sink.write_priority(
        "venus_jig event=record_summary records=3 skipped=1 stopped=too_many_records result=ok",
    );
    let (out, err) = sink.into_inner();
    assert!(err.is_none());
    assert!(out.len() <= MAX_LOG_BYTES, "total {}", out.len());
    let text = String::from_utf8(out).unwrap();
    assert_eq!(text.matches("event=record_stopped").count(), 1);
    assert_eq!(text.matches("event=record_summary").count(), 1);
    assert_eq!(text.matches("event=log_truncated").count(), 1);
}

/// 優先行の判定は固定語彙の接頭辞だけで行う。
#[test]
fn task1602_gpu6_is_priority_line_matches_only_known_events() {
    assert!(is_priority_line(
        "venus_jig event=record_stopped reason=x records=1"
    ));
    assert!(is_priority_line("venus_jig event=record_summary records=1"));
    assert!(is_priority_line("venus_jig event=launch_error code=X"));
    assert!(!is_priority_line("venus_jig event=submit_3d"));
    assert!(!is_priority_line("record_stopped"));
}
