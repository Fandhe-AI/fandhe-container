//! venus 記録・再生ハーネスの公開 API 結合試験（GPU-6・TASK-172.5・REPAIR-2・REPAIR-12）。
//!
//! `fandhe_container_plugin_macos::gpu::venus::replay` の公開 API だけで、記録→検証→再生の往復と
//! 破損ファイルの再生前拒否を具体値で確認する。GPU・実 VM は不要で 3 OS 共通。

use fandhe_container_plugin_macos::gpu::venus::CommandType;
use fandhe_container_plugin_macos::gpu::venus::replay::{
    CollectingBackend, FILE_HEADER_LEN, RecordingWriter, replay, validate,
};

/// vkCreateRingMESA(188) + GENERATE_REPLY フラグ + 引数 u64。
fn stream() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&188u32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    b
}

#[test]
fn record_validate_replay_roundtrip() {
    let s = stream();
    let mut w = RecordingWriter::new(Vec::new());
    w.append(&s).expect("append");
    w.append(&s).expect("append");
    let bytes = w.finish().expect("finish");
    // ヘッダ 20 + 2 × (レコードヘッダ 12 + ペイロード 16 + CRC 4)。
    assert_eq!(bytes.len(), FILE_HEADER_LEN + 2 * 32);

    let v = validate(&bytes).expect("validate");
    let mut backend = CollectingBackend::default();
    let summary = replay(&v, &mut backend).expect("replay");
    assert_eq!(summary.records, 2);
    assert_eq!(summary.total_bytes, 32);
    assert_eq!(
        summary.first_commands,
        vec![CommandType::CreateRingMESA, CommandType::CreateRingMESA]
    );
    assert_eq!(backend.submitted, vec![(0, s.clone()), (1, s)]);
}

#[test]
fn corrupted_recording_is_rejected_before_replay() {
    let mut w = RecordingWriter::new(Vec::new());
    w.append(&stream()).expect("append");
    let mut bytes = w.finish().expect("finish");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let err = validate(&bytes).expect_err("must reject");
    assert_eq!(err.code(), "venus_replay.record_checksum");
}
