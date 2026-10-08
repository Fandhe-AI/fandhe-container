//! venus capset 応答の公開 API 結合試験（GPU-6・TASK-172.3・#724）。
//!
//! 外部 crate 視点で info -> query の順に呼び、max-size が 0 でなく data 長と一致することを確認する。
//! 実ゲストの受理は未検証（#725）。

use fandhe_container_plugin_macos::gpu::venus::{capset_info, respond_capset_query};

#[test]
fn task172_3_gpu6_info_then_query() {
    let info = capset_info(0).unwrap();
    assert_eq!(info.max_size, 160);
    let resp = respond_capset_query(info.id, 0).unwrap();
    assert_eq!(resp.info.max_size as usize, resp.data.len());
    assert_eq!(resp.data[..4], 1u32.to_le_bytes());
}
