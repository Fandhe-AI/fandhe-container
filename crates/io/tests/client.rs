//! `fandhe-container-io` の公開 API（[`PipelineClient`]・[`InFlightLimit`]）に対する
//! 結合試験（TASK-12.1・IO-1・#73）。
//!
//! crate 内部のユニットテスト（`src/client.rs`）とは別に、crate 外から公開 API だけを
//! 使って [`FrameSender`] を実装したモックトランスポートで一連の送信フローを検証する
//! （coding-rust「テスト」: ユニットテストと結合テストを併置する）。

use std::time::Duration;

use fandhe_container_io::{
    Frame, FrameKind, FrameSender, InFlightLimit, IoError, IoErrorCode, IoTimeout, PipelineClient,
};

fn test_timeout() -> IoTimeout {
    IoTimeout::new(Duration::from_millis(1)).expect("1ms must be a valid timeout")
}

fn write_frame(byte: u8) -> Frame {
    Frame::new(FrameKind::Write, vec![byte]).expect("frame must be valid")
}

/// 結合試験専用のモック sender。送信したフレームを記録し、常に成功する。
#[derive(Debug, Default)]
struct RecordingSender {
    sent: Vec<Frame>,
}

impl FrameSender for RecordingSender {
    type Frame = Frame;

    fn send_frame(&mut self, frame: &Self::Frame, _timeout: IoTimeout) -> Result<(), IoError> {
        self.sent.push(frame.clone());
        Ok(())
    }
}

/// IO-1・TASK-12.1: 未 ACK 件数が上限に達すると `send` は
/// `IoErrorCode::ResourceExhausted` を返し、それ以上未 ACK 件数は増えない
/// （`queue().len()` が上限のまま変わらないことで確認する）。
///
/// # `into_inner` が未 ACK 保持中にトランスポートを返さないことについて
/// （TASK-12.1・#73 codex レビュー指摘対応。P1）
///
/// 未 ACK の枠を解放する [`PipelineClient::remove_in_flight`] は `pub(crate)`
/// （上記 P0 指摘対応）のため、本ファイルのような crate 外の結合試験からは
/// キューを空にできない。そのため本テストでは、送信済みバイト列を
/// `into_inner` 経由で取り出す代わりに `queue().len()` で未 ACK 件数のみを
/// 確認する。未 ACK が残ったままの `into_inner` が `Unavailable` を返し
/// トランスポートを渡さないことの確認は crate 内部の `src/client.rs` の
/// `io1_pipeline_client_into_inner_rejects_unacked_requests` が担う。
#[test]
fn io1_public_api_pipeline_client_rejects_when_limit_reached() {
    let limit = InFlightLimit::new(3).expect("3 must be a valid limit");
    let mut client = PipelineClient::new(RecordingSender::default(), limit);

    for byte in 0u8..3 {
        client
            .send(&write_frame(byte), test_timeout())
            .expect("send must succeed while under the limit");
    }

    let err = client
        .send(&write_frame(3), test_timeout())
        .expect_err("send beyond the limit must be rejected");
    assert_eq!(err.code(), IoErrorCode::ResourceExhausted);

    assert_eq!(client.queue().len(), 3);
}

// IO-1・TASK-12.1（#73 codex 指摘対応。P0）: 未 ACK 枠の解放
// （`PipelineClient::remove_in_flight`）は `pub(crate)` に変更済みで、本ファイルの
// ような crate 外の結合試験からは呼び出せない（公開 API のままだと、ACK を
// 確認せずに枠を解放でき `InFlightLimit` の上限を無視して送信を続けられてしまう
// という P0 指摘に対応するため）。解放・再利用フローそのものの検証は crate 内部の
// `src/client.rs` の `io1_pipeline_client_accepts_after_slot_released` が担う。
// 以前ここにあった `io1_public_api_pipeline_client_releases_slot_and_keeps_order`
// は公開 API 経由の解放を前提にしていたため、可視性変更に伴い削除した。

/// IO-1・TASK-12.1: `InFlightLimit` は `0` と `MAX_IN_FLIGHT_LIMIT` 超過を
/// `InvalidArgument` として拒否する。
#[test]
fn io1_public_api_in_flight_limit_validation() {
    let zero_err = InFlightLimit::new(0).expect_err("zero must be rejected");
    assert_eq!(zero_err.code(), IoErrorCode::InvalidArgument);

    let over_err = InFlightLimit::new(fandhe_container_io::MAX_IN_FLIGHT_LIMIT + 1)
        .expect_err("MAX_IN_FLIGHT_LIMIT + 1 must be rejected");
    assert_eq!(over_err.code(), IoErrorCode::InvalidArgument);
}
