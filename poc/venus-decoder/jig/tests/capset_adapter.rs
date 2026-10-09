//! 公開 API 経由の ctrl アダプタ結合試験（GPU-6・TASK-172.4・#888。3 OS・既定集合）。
//!
//! info -> query の順に ctrl 要求を流し、出力ログを照合器が受理することを確認する。
//! 実ゲストの Mesa venus からの到達は未検証（後続 F1・#725）。

use fandhe_container_poc_venus_jig::adapter::CtrlAdapter;
use fandhe_container_poc_venus_jig::log::find_capset_queries;

fn req(cmd: u32, a: u32, b: u32) -> Vec<u8> {
    let mut v = vec![0u8; 24];
    v[..4].copy_from_slice(&cmd.to_le_bytes());
    v.extend_from_slice(&a.to_le_bytes());
    v.extend_from_slice(&b.to_le_bytes());
    v
}

#[test]
fn task172_4_gpu6_info_then_query_log_is_accepted() {
    let mut log = String::new();
    let mut adapter = CtrlAdapter::default();
    // info -> query -> display_info -> ctx_create -> ctx_destroy の順（ctx_id=3）。
    let mut create = vec![0u8; 96];
    create[..4].copy_from_slice(&0x0200u32.to_le_bytes());
    create[16..20].copy_from_slice(&3u32.to_le_bytes());
    create[28..32].copy_from_slice(&4u32.to_le_bytes());
    let mut destroy = vec![0u8; 24];
    destroy[..4].copy_from_slice(&0x0201u32.to_le_bytes());
    destroy[16..20].copy_from_slice(&3u32.to_le_bytes());
    let mut display = vec![0u8; 24];
    display[..4].copy_from_slice(&0x0100u32.to_le_bytes());
    for r in [
        req(0x0108, 0, 0),
        req(0x0109, 4, 0),
        display,
        create,
        destroy,
    ] {
        log.push_str(&adapter.handle_ctrl(&r).log_line);
        log.push('\n');
    }
    let report = find_capset_queries(&log).unwrap();
    assert_eq!(report.venus_get_capset_ok, 1);
    assert_eq!(report.info_ok, 1);
    assert_eq!(report.malformed_lines, 0);
}
