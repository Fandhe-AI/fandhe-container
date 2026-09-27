//! `fandhe-container-io` 公開 API（`BatchBuffer` / `BatchConfig`）の結合試験
//! （TASK-13.1・IO-1・REPAIR-12・#76）。
//!
//! `src/batch.rs` のユニットテストは crate 内部（非公開フィールドへのアクセスを
//! 含む）から検証するが、本ファイルは `fandhe-container-io` の外部利用者
//! （TASK-13.2 系のバッチ write-back サーバー想定）と同じ経路（`pub use` された
//! 公開 API のみ）で、受け入れ条件（既定 64 件発火・カスタムサイズでの発火・
//! 不正な設定値の拒否）を機械照合する（AGENTS.md「新機能追加時に更新すべき
//! テスト一覧」）。

use fandhe_container_io::{
    BatchBuffer, BatchConfig, DEFAULT_BATCH_SIZE, Frame, FrameKind, IoErrorCode, PushOutcome,
};

fn write_frame(seq: u32) -> Frame {
    Frame::new(FrameKind::Write, seq.to_le_bytes().to_vec()).expect("Frame::new must succeed")
}

/// IO-1 受け入れ条件 1: 公開 API 経由でも既定 [`DEFAULT_BATCH_SIZE`]（64 件）到達で
/// バッチが発火し、それまでは `Buffered` を返す。
#[test]
fn io1_public_api_batch_buffer_fires_at_default_size() {
    assert_eq!(DEFAULT_BATCH_SIZE, 64);
    let mut buffer = BatchBuffer::new(BatchConfig::default());

    for seq in 0..(DEFAULT_BATCH_SIZE as u32 - 1) {
        let outcome = buffer.push(write_frame(seq)).expect("push must succeed");
        assert!(matches!(outcome, PushOutcome::Buffered { .. }));
    }

    let outcome = buffer
        .push(write_frame(DEFAULT_BATCH_SIZE as u32 - 1))
        .expect("push must succeed");
    match outcome {
        PushOutcome::Ready(batch) => assert_eq!(batch.len(), DEFAULT_BATCH_SIZE),
        _ => panic!("must fire at the default batch size"),
    }
}

/// IO-1 受け入れ条件 2: `BatchConfig::new` で件数上限を設定でき、公開 API 経由でも
/// その件数で発火する。
#[test]
fn io1_public_api_batch_config_custom_size_fires() {
    let config = BatchConfig::new(8).expect("8 must be a valid batch size");
    assert_eq!(config.batch_size(), 8);
    let mut buffer = BatchBuffer::new(config);

    for seq in 0..7u32 {
        let outcome = buffer.push(write_frame(seq)).expect("push must succeed");
        assert!(matches!(outcome, PushOutcome::Buffered { .. }));
    }
    let outcome = buffer.push(write_frame(7)).expect("push must succeed");
    match outcome {
        PushOutcome::Ready(batch) => assert_eq!(batch.len(), 8),
        _ => panic!("must fire at the 8th frame"),
    }
}

/// IO-1・REPAIR-2: 公開 API 経由でも `BatchConfig::new(0)` は
/// `IoErrorCode::InvalidArgument` として拒否される。
#[test]
fn io1_public_api_batch_config_rejects_zero() {
    let err = BatchConfig::new(0).expect_err("0 must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
}
