//! `fandhe-container-io` の公開 API（[`PipelineClient`]・[`InFlightLimit`]）に対する
//! 結合試験（TASK-12.1・IO-1・#73）。
//!
//! crate 内部のユニットテスト（`src/client.rs`）とは別に、crate 外から公開 API だけを
//! 使って [`FrameSender`] を実装したモックトランスポートで一連の送信フローを検証する
//! （coding-rust「テスト」: ユニットテストと結合テストを併置する）。

use std::collections::VecDeque;
use std::time::Duration;

use fandhe_container_io::{
    Frame, FrameKind, FrameReceiver, FrameSender, InFlightLimit, IoError, IoErrorCode, IoTimeout,
    JsonLinesSendObserver, NoopSendObserver, PipelineClient, WireRequestId, decode_request,
    encode_ack,
};

fn test_timeout() -> IoTimeout {
    IoTimeout::new(Duration::from_millis(1)).expect("1ms must be a valid timeout")
}

/// [`JsonLinesSendObserver::drain_lines`] は `send`（`io_send`）と `recv_ack`
/// （`io_recv_ack`）のイベントを同じキューへ積む（[`SendObserver`] が両方の通知先を
/// 兼ねるため）。ACK 系の観測を検証するテストは、`send` 呼び出しが残す `io_send`
/// 行を除いた `io_recv_ack` 行だけを見る（TASK-12.2・#74 codex 指摘対応。P1・
/// REPAIR-4）。
fn drain_ack_lines(observer: &mut JsonLinesSendObserver) -> Vec<String> {
    observer
        .drain_lines()
        .into_iter()
        .filter(|line| line.contains("\"event\":\"io_recv_ack\""))
        .collect()
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
    let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

    let mut ids = Vec::new();
    for byte in 0u8..3 {
        let request = client
            .send(FrameKind::Write, &[byte], test_timeout())
            .expect("send must succeed while under the limit");
        ids.push(request.id());
    }

    let err = client
        .send(FrameKind::Write, &[3], test_timeout())
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
        .map(|frame| {
            decode_request(frame)
                .expect("frame must decode as a request")
                .body()[0]
        })
        .collect();
    assert_eq!(sent_bytes, vec![0, 1, 2]);
}

/// IO-1・TASK-12.1（#73 codex 再指摘対応。P1）: 満杯のあと
/// [`PipelineClient::acknowledge`] で検証済み ACK の request id を渡して 1 枠
/// 解放すると、公開 API だけで次の送信が成功し、id は単調増加を続ける。
#[test]
fn io1_public_api_pipeline_client_releases_slot_and_keeps_order() {
    let limit = InFlightLimit::new(2).expect("2 must be a valid limit");
    let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

    let first = client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("1st send must succeed");
    client
        .send(FrameKind::Write, &[2], test_timeout())
        .expect("2nd send must succeed");
    client
        .send(FrameKind::Write, &[3], test_timeout())
        .expect_err("3rd send must be rejected while full");

    client
        .acknowledge(first.id())
        .expect("acknowledging the verified id must succeed");

    let third = client
        .send(FrameKind::Write, &[3], test_timeout())
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
/// `PipelineClient` で採番させた（このケースでは連番の数値が異なる）id を
/// 使って再現する。連番の数値が偶然一致するケースは
/// `io1_public_api_pipeline_client_acknowledge_rejects_same_numbered_id_from_another_client`
/// が担う（codex 再指摘: 発行元キューの区別なしに数値だけで一致判定すると、
/// このテストは連番が異なる値しか試していないため本来検出すべき誤解放を
/// 見逃す）。
#[test]
fn io1_public_api_pipeline_client_acknowledge_rejects_unknown_and_duplicate() {
    let limit = InFlightLimit::new(2).expect("2 must be a valid limit");
    let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);
    let mut other_client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

    let request = client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("send must succeed while under the limit");
    // `other_client` 側で id `0`（`request` と同値）・`1` を採番させ、`client` の
    // キューには存在しない id `1` を「未登録の id」として使う。
    other_client
        .send(FrameKind::Write, &[9], test_timeout())
        .expect("other client's 1st send must succeed");
    let unknown_to_client = other_client
        .send(FrameKind::Write, &[10], test_timeout())
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

/// IO-1・TASK-12.1（#73 codex 再指摘対応。P1）: 別の `PipelineClient` が発行した
/// `RequestId` の連番部分がたまたま同値（両方とも 1 回目の送信で得た `id=0`）
/// であっても、発行元キューが異なれば `acknowledge` は `InvalidArgument` で
/// 拒否し、対応する ACK を一度も受けていない自分自身の枠を解放しない。
/// 各 `PipelineClient` は連番を独立に `0` から採番するため、この検証がなければ
/// 別クライアントの id を渡すだけで未 ACK 枠を誤って解放できてしまう
/// （codex レビュー指摘の再現テスト）。
#[test]
fn io1_public_api_pipeline_client_acknowledge_rejects_same_numbered_id_from_another_client() {
    let limit = InFlightLimit::new(2).expect("2 must be a valid limit");
    let mut client_a = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);
    let mut client_b = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

    let request_a = client_a
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("client_a's send must succeed");
    let request_b = client_b
        .send(FrameKind::Write, &[2], test_timeout())
        .expect("client_b's send must succeed");
    // 両クライアントとも 1 回目の送信のため、連番の数値は同値になる。
    assert_eq!(request_a.id().get(), 0);
    assert_eq!(request_b.id().get(), 0);

    let err = client_a
        .acknowledge(request_b.id())
        .expect_err("id issued by another client's queue must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    assert!(
        err.message().contains("another queue"),
        "unexpected message: {}",
        err.message()
    );
    assert_eq!(
        client_a.queue().len(),
        1,
        "client_a's own entry must remain untouched"
    );

    // 対称のケース（client_b が client_a の id を渡す場合）も同様に拒否される。
    let err = client_b
        .acknowledge(request_a.id())
        .expect_err("id issued by another client's queue must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    assert_eq!(client_b.queue().len(), 1);

    // 自分自身が発行した id は引き続き解放できる（不要に厳しくなっていないことの確認）。
    client_a
        .acknowledge(request_a.id())
        .expect("acknowledging the verified id issued by the same queue must succeed");
    assert!(client_a.queue().is_empty());
    client_b
        .acknowledge(request_b.id())
        .expect("acknowledging the verified id issued by the same queue must succeed");
    assert!(client_b.queue().is_empty());
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

/// TASK-12.1（#73 codex/bugbot 再指摘対応。P1・REPAIR-4・REPAIR-5）:
/// [`PipelineClient::observer_mut`] は crate 外からも観測フックへ到達でき、
/// [`JsonLinesSendObserver`] にためた送信イベントを `drain_lines` で取り出せる。
/// `on_send`（送信経路）自体は I/O をせず、取り出した行の書き出し（部分書き込み
/// 時の再試行を含む）は呼び出し元が明示的に行う契約（REPAIR-5）が公開 API として
/// 機能することを確認する。
#[test]
fn repair5_public_api_observer_mut_drains_buffered_send_log() {
    let limit = InFlightLimit::new(1).expect("1 must be valid");
    let observer = JsonLinesSendObserver::new();
    let mut client = PipelineClient::new(RecordingSender::default(), limit, observer);

    client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("send must succeed while under the limit");

    let lines = client.observer_mut().drain_lines();
    assert_eq!(lines.len(), 1, "expected one buffered JSON line");
    assert!(client.observer_mut().is_empty());

    let line = &lines[0];
    assert!(
        line.starts_with("{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"ok\",")
            && line.ends_with('}'),
        "unexpected drained line: {line}"
    );
}
/// 結合試験専用のモック sender。常に `Timeout` を返す（トランスポート失敗・
/// 失効後の拒否を観測するために使う。`crate::client` 内のユニットテストにある
/// 同名モックと同じ役割）。
#[derive(Debug, Default)]
struct AlwaysTimeoutSender;

impl FrameSender for AlwaysTimeoutSender {
    type Frame = Frame;

    fn send_frame(&mut self, _frame: &Self::Frame, _timeout: IoTimeout) -> Result<(), IoError> {
        Err(IoError::new(IoErrorCode::Timeout, "mock always times out"))
    }
}

/// REPAIR-4・REPAIR-12（#73。Codex P1 再指摘対応・`client.rs:692`）: 観測先を
/// 明示せずに済ませられない `PipelineClient::new`（項目 J。観測フックが必須引数）に
/// [`JsonLinesSendObserver`] を渡した既定の利用経路で、成功・拒否系すべての結果
/// 種別（`Success`・`RejectedInvalidFrameKind`・`RejectedResourceExhausted`・
/// `TransportFailure`・`RejectedPoisoned`）が JSON 行として観測できることを
/// 公開 API のみで機械照合する。`metrics()` を一切読み出さなくても、`send` の
/// 呼び出しごとに `observer_mut().drain_lines()` から結果が取り出せることの確認
/// （base 側 AGENTS.md の可観測性要件・REPAIR-4）。
#[test]
fn repair4_repair12_public_api_default_observer_path_covers_all_send_outcomes() {
    // Success・RejectedInvalidFrameKind・RejectedResourceExhausted は
    // 常に成功するトランスポートで再現できる。
    let limit = InFlightLimit::new(1).expect("1 must be a valid limit");
    let observer = JsonLinesSendObserver::new();
    let mut client = PipelineClient::new(RecordingSender::default(), limit, observer);

    client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("1st send must succeed under the limit");

    client
        .send(FrameKind::Ack, &[], test_timeout())
        .expect_err("Ack frames must not be trackable as in-flight requests");

    let resource_exhausted_err = client
        .send(FrameKind::Write, &[2], test_timeout())
        .expect_err("2nd Write must be rejected: in-flight limit already reached");
    assert_eq!(
        resource_exhausted_err.code(),
        IoErrorCode::ResourceExhausted
    );

    let lines = client.observer_mut().drain_lines();
    assert_eq!(lines.len(), 3, "expected one JSON line per send() call");
    assert!(
        lines[0].starts_with("{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"ok\",")
            && lines[0].ends_with('}'),
        "unexpected success line: {}",
        lines[0]
    );
    assert!(
        lines[1].contains("\"outcome\":\"error\"")
            && lines[1].contains("\"reason\":\"rejected_invalid_frame_kind\""),
        "unexpected invalid-frame-kind line: {}",
        lines[1]
    );
    assert!(
        lines[2].contains("\"outcome\":\"error\"")
            && lines[2].contains("\"reason\":\"rejected_resource_exhausted\""),
        "unexpected resource-exhausted line: {}",
        lines[2]
    );

    // TransportFailure・RejectedPoisoned は失効するトランスポートで再現する
    // （送信結果が不明なエラーの後、クライアントが失効して以降の送信を拒否する
    // 契約。`PipelineClient::send` のドキュメント参照）。
    let poisoning_observer = JsonLinesSendObserver::new();
    let mut poisoning_client = PipelineClient::new(AlwaysTimeoutSender, limit, poisoning_observer);

    poisoning_client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect_err("the mock sender always times out");
    poisoning_client
        .send(FrameKind::Write, &[2], test_timeout())
        .expect_err("poisoned client must reject further sends");

    let poisoning_lines = poisoning_client.observer_mut().drain_lines();
    assert_eq!(
        poisoning_lines.len(),
        2,
        "expected one JSON line per send() call"
    );
    assert!(
        poisoning_lines[0].contains("\"outcome\":\"error\"")
            && poisoning_lines[0].contains("\"reason\":\"transport_failure\""),
        "unexpected transport-failure line: {}",
        poisoning_lines[0]
    );
    assert!(
        poisoning_lines[1].contains("\"outcome\":\"error\"")
            && poisoning_lines[1].contains("\"reason\":\"rejected_poisoned\""),
        "unexpected rejected-poisoned line: {}",
        poisoning_lines[1]
    );
}

/// 結合試験専用のモック receiver（TASK-12.2・#74）。台本
/// （`Result<Frame, IoError>` の列）を順に返し、空になったら常に
/// [`IoErrorCode::Timeout`] を返す。`crate::client` 内のユニットテストにある
/// 同名の役割のモックと同じ発想だが、公開 API（[`FrameReceiver`]）だけで実装する。
#[derive(Debug, Default)]
struct ScriptedReceiver {
    script: VecDeque<Result<Frame, IoError>>,
    call_count: usize,
}

impl ScriptedReceiver {
    fn new(script: Vec<Result<Frame, IoError>>) -> Self {
        Self {
            script: script.into(),
            call_count: 0,
        }
    }

    fn call_count(&self) -> usize {
        self.call_count
    }
}

impl FrameReceiver for ScriptedReceiver {
    type Frame = Frame;

    fn recv_frame(&mut self, _timeout: IoTimeout) -> Result<Self::Frame, IoError> {
        self.call_count += 1;
        match self.script.pop_front() {
            Some(result) => result,
            None => Err(IoError::new(
                IoErrorCode::Timeout,
                "scripted receiver script exhausted",
            )),
        }
    }
}

/// IO-1・TASK-12.2（#74。受入基準 1・親 #72 の受信順序）: 3 件送り、id `0, 1, 2` の
/// ACK を送信順どおりに受け取ると、それぞれ対応する [`AckReceipt::request`] の
/// id が一致し、キュー長が `2 → 1 → 0` と減る。
#[test]
fn io1_recv_ack_matches_by_wire_request_id() {
    let limit = InFlightLimit::new(4).expect("4 must be valid");
    let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

    let mut requests = Vec::new();
    for byte in [1u8, 2, 3] {
        requests.push(
            client
                .send(FrameKind::Write, &[byte], test_timeout())
                .expect("send must succeed while under the limit"),
        );
    }

    let acks: Vec<Frame> = requests
        .iter()
        .map(|request| {
            encode_ack(FrameKind::Ack, WireRequestId::from(request.id()))
                .expect("encode_ack must succeed")
        })
        .collect();
    let mut receiver = ScriptedReceiver::new(acks.into_iter().map(Ok).collect());

    for (expected_len_after, request) in
        [(2usize, &requests[0]), (1, &requests[1]), (0, &requests[2])]
    {
        let receipt = client
            .recv_ack(&mut receiver, test_timeout())
            .expect("recv_ack must succeed for the oldest in-flight request");
        assert_eq!(receipt.request().id().get(), request.id().get());
        assert_eq!(client.queue().len(), expected_len_after);
    }
}

/// IO-1・TASK-12.2（#74）: 上限 2 で満杯のあと `recv_ack` を 1 回呼んで枠を
/// 解放すると、次の `send` が成功する。
#[test]
fn io1_recv_ack_releases_slot_so_send_can_continue() {
    let limit = InFlightLimit::new(2).expect("2 must be valid");
    let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

    let first = client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("1st send must succeed");
    client
        .send(FrameKind::Write, &[2], test_timeout())
        .expect("2nd send must succeed");
    client
        .send(FrameKind::Write, &[3], test_timeout())
        .expect_err("3rd send must be rejected while full");

    let ack = encode_ack(FrameKind::Ack, WireRequestId::from(first.id()))
        .expect("encode_ack must succeed");
    let mut receiver = ScriptedReceiver::new(vec![Ok(ack)]);
    client
        .recv_ack(&mut receiver, test_timeout())
        .expect("recv_ack must release the oldest slot");

    let third = client
        .send(FrameKind::Write, &[3], test_timeout())
        .expect("send must succeed after recv_ack releases a slot");
    assert_eq!(third.id().get(), 2);
}

/// IO-1・IO-2・TASK-12.2（#74）: `Write` → `Flush` の順に送り、`Ack` → `FlushAck`
/// の順に受け取ると、それぞれ [`AckReceipt::ack_kind`] が対応する種別になる。
#[test]
fn io1_recv_ack_flush_ack_matches_flush() {
    let limit = InFlightLimit::new(4).expect("4 must be valid");
    let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

    let write_request = client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("write send must succeed");
    let flush_request = client
        .send(FrameKind::Flush, &[], test_timeout())
        .expect("flush send must succeed");

    let ack = encode_ack(FrameKind::Ack, WireRequestId::from(write_request.id()))
        .expect("encode_ack must succeed");
    let flush_ack = encode_ack(FrameKind::FlushAck, WireRequestId::from(flush_request.id()))
        .expect("encode_ack must succeed");
    let mut receiver = ScriptedReceiver::new(vec![Ok(ack), Ok(flush_ack)]);

    let write_receipt = client
        .recv_ack(&mut receiver, test_timeout())
        .expect("recv_ack must accept the write ack");
    assert_eq!(write_receipt.ack_kind(), FrameKind::Ack);
    assert_eq!(write_receipt.request().id().get(), write_request.id().get());

    let flush_receipt = client
        .recv_ack(&mut receiver, test_timeout())
        .expect("recv_ack must accept the flush ack");
    assert_eq!(flush_receipt.ack_kind(), FrameKind::FlushAck);
    assert_eq!(flush_receipt.request().id().get(), flush_request.id().get());
}

/// IO-1・TASK-12.2（#74）: 送信順 id `0, 1` のうち id `1`（キュー先頭ではない）の
/// ACK を先に受け取ると `InvalidArgument`（"out-of-order ack"）で拒否され、
/// クライアントは失効する。以後の `send`・`recv_ack` は `Unavailable` になり、
/// receiver の呼び出し回数はこれ以上増えない。
#[test]
fn io1_recv_ack_rejects_out_of_order_and_poisons() {
    let limit = InFlightLimit::new(4).expect("4 must be valid");
    let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

    client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("1st send must succeed");
    let second = client
        .send(FrameKind::Write, &[2], test_timeout())
        .expect("2nd send must succeed");

    let out_of_order_ack = encode_ack(FrameKind::Ack, WireRequestId::from(second.id()))
        .expect("encode_ack must succeed");
    let mut receiver = ScriptedReceiver::new(vec![Ok(out_of_order_ack)]);

    let err = client
        .recv_ack(&mut receiver, test_timeout())
        .expect_err("ack for a non-oldest in-flight request must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    assert!(
        err.message().contains("out-of-order ack"),
        "unexpected message: {}",
        err.message()
    );
    assert!(client.is_poisoned());

    let calls_after_first = receiver.call_count();
    let send_err = client
        .send(FrameKind::Write, &[3], test_timeout())
        .expect_err("poisoned client must reject further sends");
    assert_eq!(send_err.code(), IoErrorCode::Unavailable);
    let recv_err = client
        .recv_ack(&mut receiver, test_timeout())
        .expect_err("poisoned client must reject further recv_ack calls");
    assert_eq!(recv_err.code(), IoErrorCode::Unavailable);
    assert_eq!(
        receiver.call_count(),
        calls_after_first,
        "a poisoned client must not touch the receiver again"
    );
}

/// IO-1・TASK-12.2（#74）: このクライアントが送っていない id（キューのどこにも
/// 存在しない）の ACK を受け取ると `InvalidArgument`（"unknown ack id"）で
/// 拒否され、クライアントは失効する。
#[test]
fn io1_recv_ack_rejects_unknown_id_and_poisons() {
    let limit = InFlightLimit::new(4).expect("4 must be valid");
    let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

    let kept = client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("1st send must succeed");
    let released = client
        .send(FrameKind::Write, &[2], test_timeout())
        .expect("2nd send must succeed");
    // `released` の id をキューから直接取り除き、「このクライアントの
    // どの未 ACK リクエストにも該当しない id」を作る（`kept` だけが残る）。
    client
        .acknowledge(released.id())
        .expect("removing the released id via the low-level entry point must succeed");
    assert_eq!(client.queue().len(), 1);

    let unknown_ack = encode_ack(FrameKind::Ack, WireRequestId::from(released.id()))
        .expect("encode_ack must succeed");
    let mut receiver = ScriptedReceiver::new(vec![Ok(unknown_ack)]);

    let err = client
        .recv_ack(&mut receiver, test_timeout())
        .expect_err("ack for an id absent from the queue must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    assert!(
        err.message().contains("unknown ack id"),
        "unexpected message: {}",
        err.message()
    );
    assert!(client.is_poisoned());
    // `kept` は unknown ack の対象ではなく、失効前のキューに残っていた唯一の
    // 未 ACK エントリと一致すること（released とは異なる id）を確認する。
    assert_ne!(kept.id().get(), released.id().get());
    assert_eq!(
        client.queue().oldest().map(|entry| entry.id()),
        Some(kept.id())
    );
}

/// IO-1・IO-2・TASK-12.2（#74）: `Write` に `FlushAck`、`Flush` に `Ack` を返すと
/// 種別不一致として `InvalidArgument` で拒否され、クライアントは失効する。
#[test]
fn io1_recv_ack_rejects_kind_mismatch() {
    let limit = InFlightLimit::new(4).expect("4 must be valid");
    let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

    let write_request = client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("write send must succeed");

    let mismatched_ack = encode_ack(FrameKind::FlushAck, WireRequestId::from(write_request.id()))
        .expect("encode_ack must succeed");
    let mut receiver = ScriptedReceiver::new(vec![Ok(mismatched_ack)]);

    let err = client
        .recv_ack(&mut receiver, test_timeout())
        .expect_err("FlushAck for a Write request must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    assert!(client.is_poisoned());
}

/// IO-1・TASK-12.2（#74）: `Ack`/`FlushAck` 以外のフレーム種別
/// （`decode_ack` が拒否する）を受け取ると `InvalidArgument` で拒否され、
/// クライアントは失効する。
#[test]
fn io1_recv_ack_rejects_malformed_ack_payload() {
    let limit = InFlightLimit::new(4).expect("4 must be valid");
    let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

    client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("send must succeed");

    // `Write` フレームは `decode_ack` が種別違反として拒否する
    // （`payload.rs` の `io1_decode_ack_rejects_malformed_payload_len` が
    // ペイロード長違反を、本テストは種別違反を担当する）。
    let not_an_ack = Frame::new(FrameKind::Write, vec![0u8; 8]).expect("Frame::new must succeed");
    let mut receiver = ScriptedReceiver::new(vec![Ok(not_an_ack)]);

    let err = client
        .recv_ack(&mut receiver, test_timeout())
        .expect_err("a non-ack frame kind must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    assert!(client.is_poisoned());
}

/// IO-1・TASK-12.2（#74。受入基準 2・REPAIR-5）: 受信側の台本が空なら
/// `recv_ack` は `Timeout` を返して失効し、以後は `Unavailable` を返す
/// （同じ接続でのポーリングを想定しない契約）。
#[test]
fn repair5_recv_ack_times_out_and_poisons() {
    let limit = InFlightLimit::new(2).expect("2 must be valid");
    let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

    client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("send must succeed");

    let mut receiver = ScriptedReceiver::new(Vec::new());
    let err = client
        .recv_ack(&mut receiver, test_timeout())
        .expect_err("an empty script must time out");
    assert_eq!(err.code(), IoErrorCode::Timeout);
    assert!(client.is_poisoned());

    let err = client
        .recv_ack(&mut receiver, test_timeout())
        .expect_err("a poisoned client must reject further recv_ack calls");
    assert_eq!(err.code(), IoErrorCode::Unavailable);
    assert_eq!(
        receiver.call_count(),
        1,
        "a poisoned client must not call the receiver again"
    );
}

/// IO-1・TASK-12.2（#74）: 未 ACK のリクエストが 1 件もない状態で `recv_ack` を
/// 呼ぶと `InvalidArgument` を返し、receiver は一度も呼ばれない（失効もしない）。
#[test]
fn io1_recv_ack_on_empty_queue_is_rejected_without_receiving() {
    let limit = InFlightLimit::new(2).expect("2 must be valid");
    let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

    let mut receiver = ScriptedReceiver::default();
    let err = client
        .recv_ack(&mut receiver, test_timeout())
        .expect_err("recv_ack with no in-flight requests must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    assert!(!client.is_poisoned());
    assert_eq!(receiver.call_count(), 0);
}

/// IO-1・TASK-12.2（#74）: 失効済みのクライアントで `recv_ack` を呼ぶと
/// `Unavailable` を返し、receiver には一切触れない。
#[test]
fn io1_recv_ack_on_poisoned_client_does_not_touch_receiver() {
    let limit = InFlightLimit::new(2).expect("2 must be valid");
    let mut client = PipelineClient::new(AlwaysTimeoutSender, limit, NoopSendObserver);

    client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect_err("the always-timeout sender must poison the client");
    assert!(client.is_poisoned());

    let mut receiver = ScriptedReceiver::default();
    let err = client
        .recv_ack(&mut receiver, test_timeout())
        .expect_err("a poisoned client must reject recv_ack");
    assert_eq!(err.code(), IoErrorCode::Unavailable);
    assert_eq!(receiver.call_count(), 0);
}

/// IO-1・TASK-12.2（#74）: `recv_ack` で解放済みの id へ、低水準の `acknowledge`
/// を呼ぶと二重解放として拒否される。
#[test]
fn io1_acknowledge_rejects_id_already_released_by_recv_ack() {
    let limit = InFlightLimit::new(2).expect("2 must be valid");
    let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

    let request = client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("send must succeed");

    let ack = encode_ack(FrameKind::Ack, WireRequestId::from(request.id()))
        .expect("encode_ack must succeed");
    let mut receiver = ScriptedReceiver::new(vec![Ok(ack)]);
    client
        .recv_ack(&mut receiver, test_timeout())
        .expect("recv_ack must release the request");

    let err = client
        .acknowledge(request.id())
        .expect_err("acknowledging an id already released by recv_ack must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
}

/// TASK-12.2・#74 codex 指摘対応（P1・REPAIR-4）: `recv_ack` の成功・早期拒否
/// （poisoned・no in-flight）・タイムアウト（トランスポート失敗）を
/// [`PipelineClient::ack_metrics`] が結果別に計上し、[`JsonLinesSendObserver`]
/// （`SendObserver::on_ack`）が `io_recv_ack` イベントとして通知することを
/// 確認する。プロトコル違反系（形式・送信順・種別）の分岐は
/// `repair4_public_api_ack_observer_covers_protocol_violation_outcomes` で扱う。
#[test]
fn repair4_public_api_ack_metrics_and_observer_cover_success_and_early_reject_outcomes() {
    // 早期拒否（poisoned・no in-flight）は `receiver` を呼ばず `latency_us":0`。
    let limit = InFlightLimit::new(2).expect("2 must be valid");
    let observer = JsonLinesSendObserver::new();
    let mut client = PipelineClient::new(RecordingSender::default(), limit, observer);

    let mut empty_receiver = ScriptedReceiver::default();
    client
        .recv_ack(&mut empty_receiver, test_timeout())
        .expect_err("recv_ack with no in-flight requests must be rejected");
    assert_eq!(client.ack_metrics().rejected_no_in_flight_count(), 1);

    let request = client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("send must succeed");
    let ack = encode_ack(FrameKind::Ack, WireRequestId::from(request.id()))
        .expect("encode_ack must succeed");
    let mut receiver = ScriptedReceiver::new(vec![Ok(ack)]);
    client
        .recv_ack(&mut receiver, test_timeout())
        .expect("recv_ack must succeed for the oldest in-flight request");
    assert_eq!(client.ack_metrics().success_count(), 1);
    assert_eq!(client.ack_metrics().wait_latency().count(), 1);

    let lines = drain_ack_lines(client.observer_mut());
    assert_eq!(lines.len(), 2, "expected one JSON line per recv_ack() call");
    assert!(
        lines[0].contains("\"event\":\"io_recv_ack\"")
            && lines[0].contains("\"outcome\":\"error\"")
            && lines[0].contains("\"reason\":\"rejected_no_in_flight\"")
            && lines[0].contains("\"latency_us\":0")
            // TASK-12.2・#74 codex P1 再指摘対応（IO-1・IO-2・REPAIR-4）: `decode_ack`
            // 前の早期拒否は ACK 種別が確定していないため `ack_kind` フィールド
            // 自体を持たない（`AckEvent::ack_kind` のドキュメント参照）。
            && !lines[0].contains("\"ack_kind\""),
        "unexpected no-in-flight line: {}",
        lines[0]
    );
    assert!(
        lines[1].starts_with("{\"event\":\"io_recv_ack\",\"ack_kind\":\"ACK\",\"outcome\":\"ok\",")
            && lines[1].ends_with('}'),
        "unexpected success line: {}",
        lines[1]
    );

    // poisoned は失効済みトランスポートで再現する。
    let poisoning_observer = JsonLinesSendObserver::new();
    let mut poisoning_client = PipelineClient::new(AlwaysTimeoutSender, limit, poisoning_observer);
    poisoning_client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect_err("the mock sender always times out");
    let mut receiver = ScriptedReceiver::default();
    poisoning_client
        .recv_ack(&mut receiver, test_timeout())
        .expect_err("a poisoned client must reject recv_ack");
    assert_eq!(poisoning_client.ack_metrics().rejected_poisoned_count(), 1);
    let poisoning_lines = drain_ack_lines(poisoning_client.observer_mut());
    assert_eq!(poisoning_lines.len(), 1);
    assert!(
        poisoning_lines[0].contains("\"reason\":\"rejected_poisoned\"")
            && poisoning_lines[0].contains("\"latency_us\":0"),
        "unexpected poisoned line: {}",
        poisoning_lines[0]
    );

    // タイムアウト（トランスポート失敗）は所要時間 0 ではない可能性があるため
    // `reason` のみを確認する（`repair5_recv_ack_times_out_and_poisons` が
    // 失効・エラーコードの契約を担当する）。
    let timeout_limit = InFlightLimit::new(1).expect("1 must be valid");
    let timeout_observer = JsonLinesSendObserver::new();
    let mut timeout_client =
        PipelineClient::new(RecordingSender::default(), timeout_limit, timeout_observer);
    timeout_client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("send must succeed");
    let mut empty_script = ScriptedReceiver::new(Vec::new());
    timeout_client
        .recv_ack(&mut empty_script, test_timeout())
        .expect_err("an empty script must time out");
    assert_eq!(timeout_client.ack_metrics().transport_failure_count(), 1);
    let timeout_lines = drain_ack_lines(timeout_client.observer_mut());
    assert_eq!(timeout_lines.len(), 1);
    assert!(
        timeout_lines[0].contains("\"reason\":\"transport_failure\"")
            && timeout_lines[0].contains("\"code\":\"TIMEOUT\""),
        "unexpected transport-failure line: {}",
        timeout_lines[0]
    );
}

/// TASK-12.2・#74 codex 指摘対応（P1・REPAIR-4）: `recv_ack` のプロトコル違反系
/// （ペイロード形式・送信順〔out-of-order／unknown〕・種別対応）の各分岐が
/// [`PipelineClient::ack_metrics`] へ個別に計上され、`SendObserver::on_ack` へも
/// 対応する `reason` で通知されることを確認する。
#[test]
fn repair4_public_api_ack_observer_covers_protocol_violation_outcomes() {
    let limit = InFlightLimit::new(4).expect("4 must be valid");

    // RejectedInvalidPayload: `decode_ack` が種別違反として拒否するフレーム。
    let observer = JsonLinesSendObserver::new();
    let mut client = PipelineClient::new(RecordingSender::default(), limit, observer);
    client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("send must succeed");
    let not_an_ack = Frame::new(FrameKind::Write, vec![0u8; 8]).expect("Frame::new must succeed");
    let mut receiver = ScriptedReceiver::new(vec![Ok(not_an_ack)]);
    client
        .recv_ack(&mut receiver, test_timeout())
        .expect_err("a non-ack frame kind must be rejected");
    assert_eq!(client.ack_metrics().rejected_invalid_payload_count(), 1);
    let lines = drain_ack_lines(client.observer_mut());
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("\"reason\":\"rejected_invalid_payload\""));

    // RejectedOutOfOrder: キュー先頭ではない id への ACK。
    let observer = JsonLinesSendObserver::new();
    let mut client = PipelineClient::new(RecordingSender::default(), limit, observer);
    client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("1st send must succeed");
    let second = client
        .send(FrameKind::Write, &[2], test_timeout())
        .expect("2nd send must succeed");
    let out_of_order_ack = encode_ack(FrameKind::Ack, WireRequestId::from(second.id()))
        .expect("encode_ack must succeed");
    let mut receiver = ScriptedReceiver::new(vec![Ok(out_of_order_ack)]);
    client
        .recv_ack(&mut receiver, test_timeout())
        .expect_err("out-of-order ack must be rejected");
    assert_eq!(client.ack_metrics().rejected_out_of_order_count(), 1);
    let lines = drain_ack_lines(client.observer_mut());
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("\"reason\":\"rejected_out_of_order\""));

    // RejectedUnknownAckId: キューのどこにも存在しない id への ACK。
    let observer = JsonLinesSendObserver::new();
    let mut client = PipelineClient::new(RecordingSender::default(), limit, observer);
    client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("1st send must succeed");
    let released = client
        .send(FrameKind::Write, &[2], test_timeout())
        .expect("2nd send must succeed");
    client
        .acknowledge(released.id())
        .expect("removing the released id via the low-level entry point must succeed");
    let unknown_ack = encode_ack(FrameKind::Ack, WireRequestId::from(released.id()))
        .expect("encode_ack must succeed");
    let mut receiver = ScriptedReceiver::new(vec![Ok(unknown_ack)]);
    client
        .recv_ack(&mut receiver, test_timeout())
        .expect_err("unknown ack id must be rejected");
    assert_eq!(client.ack_metrics().rejected_unknown_ack_id_count(), 1);
    let lines = drain_ack_lines(client.observer_mut());
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("\"reason\":\"rejected_unknown_ack_id\""));

    // RejectedAckKindMismatch: `Write` に `FlushAck` を返す。
    let observer = JsonLinesSendObserver::new();
    let mut client = PipelineClient::new(RecordingSender::default(), limit, observer);
    let write_request = client
        .send(FrameKind::Write, &[1], test_timeout())
        .expect("write send must succeed");
    let mismatched_ack = encode_ack(FrameKind::FlushAck, WireRequestId::from(write_request.id()))
        .expect("encode_ack must succeed");
    let mut receiver = ScriptedReceiver::new(vec![Ok(mismatched_ack)]);
    client
        .recv_ack(&mut receiver, test_timeout())
        .expect_err("kind mismatch must be rejected");
    assert_eq!(client.ack_metrics().rejected_ack_kind_mismatch_count(), 1);
    let lines = drain_ack_lines(client.observer_mut());
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("\"reason\":\"rejected_ack_kind_mismatch\""));
    // TASK-12.2・#74 codex P1 再指摘対応（IO-1・IO-2・REPAIR-4）: 種別対応違反でも
    // `decode_ack` は成功しているため、実際に受信した ACK 種別（`FLUSH_ACK`）が
    // `ack_kind` として観測イベントに残る（送信時に期待した種別ではなく、届いた
    // 種別を記録することで通常 ACK と FlushAck を区別できる）。
    assert!(lines[0].contains("\"ack_kind\":\"FLUSH_ACK\""));
}
