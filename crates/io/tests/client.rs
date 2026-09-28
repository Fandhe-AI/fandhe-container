//! `fandhe-container-io` の公開 API（[`PipelineClient`]・[`InFlightLimit`]）に対する
//! 結合試験（TASK-12.1・IO-1・#73）。
//!
//! crate 内部のユニットテスト（`src/client.rs`）とは別に、crate 外から公開 API だけを
//! 使って [`FrameSender`] を実装したモックトランスポートで一連の送信フローを検証する
//! （coding-rust「テスト」: ユニットテストと結合テストを併置する）。

use std::time::Duration;

use fandhe_container_io::{
    Frame, FrameKind, FrameSender, InFlightLimit, IoError, IoErrorCode, IoTimeout,
    JsonLinesSendObserver, PipelineClient,
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
/// （`queue().len()` が上限のまま変わらないことで確認する）。上限到達後に
/// [`PipelineClient::acknowledge`]（TASK-12.1・#73 codex 再指摘対応。P1）で
/// すべての枠を解放すれば `into_inner` がトランスポートを返し、送信済み
/// バイト列を確認できる。
#[test]
fn io1_public_api_pipeline_client_rejects_when_limit_reached() {
    let limit = InFlightLimit::new(3).expect("3 must be a valid limit");
    let mut client = PipelineClient::new(RecordingSender::default(), limit);

    let mut ids = Vec::new();
    for byte in 0u8..3 {
        let request = client
            .send(&write_frame(byte), test_timeout())
            .expect("send must succeed while under the limit");
        ids.push(request.id());
    }

    let err = client
        .send(&write_frame(3), test_timeout())
        .expect_err("send beyond the limit must be rejected");
    assert_eq!(err.code(), IoErrorCode::ResourceExhausted);

    assert_eq!(client.queue().len(), 3);

    for id in ids {
        client
            .acknowledge(id)
            .expect("acknowledging a verified id must succeed");
    }

    let sent_bytes: Vec<u8> = client
        .into_inner()
        .expect("client with a drained queue must yield its transport")
        .sent
        .iter()
        .map(|frame| frame.payload()[0])
        .collect();
    assert_eq!(sent_bytes, vec![0, 1, 2]);
}

/// IO-1・TASK-12.1（#73 codex 再指摘対応。P1）: 満杯のあと
/// [`PipelineClient::acknowledge`] で検証済み ACK の request id を渡して 1 枠
/// 解放すると、公開 API だけで次の送信が成功し、id は単調増加を続ける。
#[test]
fn io1_public_api_pipeline_client_releases_slot_and_keeps_order() {
    let limit = InFlightLimit::new(2).expect("2 must be a valid limit");
    let mut client = PipelineClient::new(RecordingSender::default(), limit);

    let first = client
        .send(&write_frame(1), test_timeout())
        .expect("1st send must succeed");
    client
        .send(&write_frame(2), test_timeout())
        .expect("2nd send must succeed");
    client
        .send(&write_frame(3), test_timeout())
        .expect_err("3rd send must be rejected while full");

    client
        .acknowledge(first.id())
        .expect("acknowledging the verified id must succeed");

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

/// IO-1・TASK-12.1（#73 codex 再指摘対応。P1）: 未登録の id・二重に acknowledge
/// 済みの id は `InvalidArgument` で拒否し、キューの状態を変更しない
/// （二重解放の防止）。`RequestId` は crate 外から任意の値を作れない
/// （フィールド非公開）ため、「このクライアントに未登録の id」は、別の
/// `PipelineClient` で採番させた（値としては重複しうるが、このクライアントの
/// キューには存在しない）id を使って再現する。
#[test]
fn io1_public_api_pipeline_client_acknowledge_rejects_unknown_and_duplicate() {
    let limit = InFlightLimit::new(2).expect("2 must be a valid limit");
    let mut client = PipelineClient::new(RecordingSender::default(), limit);
    let mut other_client = PipelineClient::new(RecordingSender::default(), limit);

    let request = client
        .send(&write_frame(1), test_timeout())
        .expect("send must succeed while under the limit");
    // `other_client` 側で id `0`（`request` と同値）・`1` を採番させ、`client` の
    // キューには存在しない id `1` を「未登録の id」として使う。
    other_client
        .send(&write_frame(9), test_timeout())
        .expect("other client's 1st send must succeed");
    let unknown_to_client = other_client
        .send(&write_frame(10), test_timeout())
        .expect("other client's 2nd send must succeed");
    assert_ne!(unknown_to_client.id().get(), request.id().get());

    let unknown_id_err = client
        .acknowledge(unknown_to_client.id())
        .expect_err("id unregistered on this client's queue must be rejected");
    assert_eq!(unknown_id_err.code(), IoErrorCode::InvalidArgument);
    assert_eq!(client.queue().len(), 1);

    client
        .acknowledge(request.id())
        .expect("acknowledging the verified id must succeed");
    assert!(client.queue().is_empty());

    let duplicate_err = client
        .acknowledge(request.id())
        .expect_err("acknowledging the same id twice must be rejected");
    assert_eq!(duplicate_err.code(), IoErrorCode::InvalidArgument);
    assert!(client.queue().is_empty());
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

/// TASK-12.1（#73 codex 再指摘対応。P1・REPAIR-4・REPAIR-5）:
/// [`PipelineClient::observer_mut`] は crate 外からも観測フックへ到達でき、
/// [`JsonLinesSendObserver`] にためた送信イベントを `drain_into` で書き出せる。
/// `on_send`（送信経路）自体は I/O をせず、書き出しは呼び出し元が明示的に行う
/// 契約（REPAIR-5）が公開 API として機能することを確認する。
#[test]
fn repair5_public_api_observer_mut_drains_buffered_send_log() {
    let limit = InFlightLimit::new(1).expect("1 must be valid");
    let observer = JsonLinesSendObserver::new();
    let mut client = PipelineClient::with_observer(RecordingSender::default(), limit, observer);

    client
        .send(&write_frame(1), test_timeout())
        .expect("send must succeed while under the limit");

    let mut buf: Vec<u8> = Vec::new();
    let written = client
        .observer_mut()
        .drain_into(&mut buf)
        .expect("writing to an in-memory buffer must not fail");
    assert_eq!(written, 1, "expected one buffered JSON line");
    assert!(client.observer_mut().is_empty());

    let output = String::from_utf8(buf).expect("output must be UTF-8");
    assert!(
        output.starts_with("{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"ok\",")
            && output.ends_with("}\n"),
        "unexpected drained output: {output}"
    );
}
