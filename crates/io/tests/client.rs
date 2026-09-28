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
/// `IoErrorCode::ResourceExhausted` を返し、トランスポートへの書き込み件数は
/// 上限と一致する（それ以上は書き込まれない）。
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
    assert_eq!(client.into_inner().sent.len(), 3);
}

/// IO-1・TASK-12.1: 1 枠を解放すると次の送信が成功し、id は単調増加を続ける。
/// 送信順（残っているリクエストの並び）も保たれる。
#[test]
fn io1_public_api_pipeline_client_releases_slot_and_keeps_order() {
    let limit = InFlightLimit::new(2).expect("2 must be a valid limit");
    let mut client = PipelineClient::new(RecordingSender::default(), limit);

    let first = client
        .send(&write_frame(1), test_timeout())
        .expect("1st send must succeed");
    let second = client
        .send(&write_frame(2), test_timeout())
        .expect("2nd send must succeed");
    assert_eq!(first.id().get(), 0);
    assert_eq!(second.id().get(), 1);

    client
        .send(&write_frame(3), test_timeout())
        .expect_err("3rd send must be rejected while full");

    client
        .remove_in_flight(first.id())
        .expect("removing the oldest request must succeed");

    let third = client
        .send(&write_frame(3), test_timeout())
        .expect("send must succeed after a slot is released");
    assert_eq!(third.id().get(), 2);

    let remaining_ids: Vec<u64> = client
        .queue()
        .iter()
        .map(|entry| entry.id().get())
        .collect();
    assert_eq!(remaining_ids, vec![1, 2]);
}

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
