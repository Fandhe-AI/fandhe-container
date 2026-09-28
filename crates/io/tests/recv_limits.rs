//! `fandhe-container-io` 公開 API（`ReceiveLimits` / `AdmittedHeader`）の結合試験
//! （TASK-13.4・IO-1・REPAIR-12・#796）。
//!
//! `src/recv_limits.rs` のユニットテストは crate 内部（確保回数を記録する
//! スレッドローカルの記録器を含む）から検証するが、本ファイルは
//! `fandhe-container-io` の外部利用者（TASK-13.2.1・#820 の UDS 受信ループ想定）と
//! 同じ経路（`pub use` された公開 API のみ）で、受け入れ条件（設定上限未満の
//! フレームが `BatchBuffer` へ通常どおり積まれること・設定上限超過フレームが
//! `BatchBuffer::push` に届く前に拒否されること）を機械照合する
//! （AGENTS.md「新機能追加時に更新すべきテスト一覧」）。

use fandhe_container_io::{
    BatchBuffer, BatchConfig, Frame, FrameHeader, FrameKind, IoErrorCode, PushOutcome,
    ReceiveLimits,
};

fn write_header(payload_len: u32) -> FrameHeader {
    FrameHeader::new(FrameKind::Write, payload_len).expect("header must be valid")
}

/// TASK-13.4 受け入れ条件 2: 設定上限（`BatchConfig::new(8)` 由来）未満の
/// フレームは、`admit` → `allocate_body` → `decode_body` → `BatchBuffer::push`
/// の経路で通常どおりバッファリングされ、8 件目でバッチが発火する。
#[test]
fn io1_public_api_under_limit_frames_are_buffered() {
    let config = BatchConfig::new(8).expect("valid config must succeed");
    let limits = ReceiveLimits::for_batch(&config);
    let mut buffer = BatchBuffer::new(config);

    for seq in 0..7u32 {
        let frame =
            Frame::new(FrameKind::Write, seq.to_le_bytes().to_vec()).expect("frame must be valid");
        let encoded = frame.encode();
        let header = write_header(frame.payload().len() as u32);

        let admitted = limits
            .admit(header, buffer.len())
            .expect("frame under the configured limit must be admitted");
        let mut body = admitted.allocate_body();
        let payload_and_checksum = &encoded[fandhe_container_io::FRAME_HEADER_LEN..];
        body.copy_from_slice(payload_and_checksum);
        let decoded = admitted
            .decode_body(&body)
            .expect("decode must succeed for a well-formed frame");

        let outcome = buffer.push(decoded).expect("push must succeed");
        assert!(matches!(outcome, PushOutcome::Buffered { pending } if pending as u32 == seq + 1));
    }
    assert_eq!(buffer.len(), 7);

    let frame =
        Frame::new(FrameKind::Write, 7u32.to_le_bytes().to_vec()).expect("frame must be valid");
    let header = write_header(frame.payload().len() as u32);
    let admitted = limits
        .admit(header, buffer.len())
        .expect("8th frame must still be admitted (pending == max - 1)");
    let outcome = buffer
        .push(
            admitted
                .decode_body(&frame.encode()[fandhe_container_io::FRAME_HEADER_LEN..])
                .expect("decode must succeed"),
        )
        .expect("push must succeed");
    match outcome {
        PushOutcome::Ready(batch) => assert_eq!(batch.len(), 8),
        other => panic!("must fire at the configured batch size, got {other:?}"),
    }
}

/// TASK-13.4 受け入れ条件 1: 設定上限（`BatchConfig::with_max_bytes(8, 16)`）を
/// 超えるフレームは、`admit` の段階（本体バッファ確保・`BatchBuffer::push` へ
/// 届く前）で `ResourceExhausted` として拒否され、`BatchBuffer` の `len()` は
/// 変化しない。
#[test]
fn io1_public_api_over_config_max_bytes_rejected_before_batch_push() {
    let config = BatchConfig::with_max_bytes(8, 16).expect("valid config must succeed");
    let limits = ReceiveLimits::for_batch(&config);
    let buffer = BatchBuffer::new(config);
    assert_eq!(limits.max_payload_len(), 16);

    let oversized_header = write_header(17);
    let err = limits
        .admit(oversized_header, buffer.len())
        .expect_err("frame exceeding the configured max_bytes must be rejected");
    assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
    assert_eq!(
        buffer.len(),
        0,
        "BatchBuffer must never observe a frame rejected at the admit gate"
    );
}
