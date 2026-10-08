//! アダプタ・ログ照合器のユニットテスト（GPU-6・TASK-172.4）。期待値は具体値で書く。

use fandhe_container_plugin_macos::gpu::venus::VenusCapset;

use crate::adapter::handle_ctrl;
use crate::ctrl::{
    CMD_GET_CAPSET, CMD_GET_CAPSET_INFO, FLAG_FENCE, HDR_LEN, RESP_ERR_INVALID_PARAMETER,
    RESP_ERR_UNSPEC, RESP_OK_CAPSET, RESP_OK_CAPSET_INFO,
};
use crate::device;
use crate::log::{LogError, MAX_LINES, MAX_LOG_BYTES, find_capset_queries};

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
    let h = handle_ctrl(&req(0x0100, 0, 0, 0, 0));
    assert_eq!(h.response.resp_type(), RESP_ERR_UNSPEC);
    assert_eq!(
        h.log_line,
        "venus_jig event=ctrl_rejected cmd_type=256 result=unspec"
    );
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
