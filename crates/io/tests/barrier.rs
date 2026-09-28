//! `fandhe-container-io` の公開 API（[`PipelineClient::flush`]・[`AckReceipt`]・
//! [`FlushAck`]・[`FlushBarrier`]）に対する結合試験（TASK-15.1・IO-1・IO-2・#85）。
//!
//! `tests/client.rs` の `RecordingSender`/`RecvHandle` と同形の最小モックを本
//! ファイル内に複製する（既存テストファイルの構造を変えないため。両ファイルは
//! 別のテストバイナリとしてコンパイルされ、`tests/` 配下に共有モジュールを新設
//! すると both バイナリから使うための `mod` 配線が別途必要になり、本タスクの
//! スコープに対して過剰なため）。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_io::{
    AckReceipt, FlushAck, Frame, FrameKind, FrameReceiver, FrameSender, InFlightLimit, IoError,
    IoErrorCode, IoTimeout, NoopSendObserver, PipelineClient, WireRequestId, encode_ack,
};

fn test_timeout() -> IoTimeout {
    IoTimeout::new(Duration::from_millis(1)).expect("1ms must be a valid timeout")
}

/// [`RecordingSender::recv_handle`] が返す、ACK 受信用の台本の追加用ハンドル
/// （`tests/client.rs` の同名型と同じ役割。モジュールドキュメント参照）。
#[derive(Debug, Clone, Default)]
struct RecvHandle {
    script: Arc<Mutex<VecDeque<Result<Frame, IoError>>>>,
}

impl RecvHandle {
    fn push_ack(&self, result: Result<Frame, IoError>) {
        self.script
            .lock()
            .expect("test mock mutex must not be poisoned")
            .push_back(result);
    }
}

/// 結合試験専用のモック sender 兼 receiver（`tests/client.rs` の同名型と同じ役割）。
#[derive(Debug, Default)]
struct RecordingSender {
    recv_script: Arc<Mutex<VecDeque<Result<Frame, IoError>>>>,
}

impl RecordingSender {
    fn recv_handle(&self) -> RecvHandle {
        RecvHandle {
            script: Arc::clone(&self.recv_script),
        }
    }
}

impl FrameSender for RecordingSender {
    type Frame = Frame;

    fn send_frame(&mut self, _frame: &Self::Frame, _timeout: IoTimeout) -> Result<(), IoError> {
        Ok(())
    }
}

impl FrameReceiver for RecordingSender {
    type Frame = Frame;

    fn recv_frame(&mut self, _timeout: IoTimeout) -> Result<Self::Frame, IoError> {
        match self
            .recv_script
            .lock()
            .expect("test mock mutex must not be poisoned")
            .pop_front()
        {
            Some(result) => result,
            None => Err(IoError::new(
                IoErrorCode::Timeout,
                "recording sender recv script exhausted",
            )),
        }
    }
}

/// IO-1・IO-2・TASK-15.1（#85）: `send(Write)` → `flush()` → 対応する ACK を
/// 送信順どおりに受け取ると、`recv_ack` は `AckReceipt::Write` →
/// `AckReceipt::Flush` の順に返し、`FlushAck::barrier()` は `flush()` が
/// 返した `FlushBarrier` と一致する。キュー長は `2 → 1 → 0` と減る。
#[test]
fn io2_flush_then_recv_ack_returns_matching_flush_barrier() {
    let limit = InFlightLimit::new(4).expect("4 must be valid");
    let sender = RecordingSender::default();
    let recv = sender.recv_handle();
    let mut client = PipelineClient::new(sender, limit, NoopSendObserver);

    let write_request = client
        .send(FrameKind::Write, &[7], test_timeout())
        .expect("write send must succeed");
    let barrier = client.flush(test_timeout()).expect("flush must succeed");
    assert_eq!(client.queue().len(), 2);

    let write_ack = encode_ack(FrameKind::Ack, WireRequestId::from(write_request.id()))
        .expect("encode_ack must succeed");
    let flush_ack_frame = encode_ack(FrameKind::FlushAck, WireRequestId::from(barrier.id()))
        .expect("encode_ack must succeed");
    recv.push_ack(Ok(write_ack));
    recv.push_ack(Ok(flush_ack_frame));

    let write_receipt = client
        .recv_ack(test_timeout())
        .expect("recv_ack must accept the write ack");
    assert!(matches!(write_receipt, AckReceipt::Write(_)));
    assert_eq!(client.queue().len(), 1);

    let flush_receipt = client
        .recv_ack(test_timeout())
        .expect("recv_ack must accept the flush ack");
    assert_eq!(client.queue().len(), 0);
    let flush_ack =
        FlushAck::try_from(flush_receipt).expect("AckReceipt::Flush must convert to FlushAck");
    assert_eq!(flush_ack.barrier(), barrier);
}

/// IO-2・TASK-15.1（#85）: FLUSH リクエストに対して通常 `Ack`（種別取り違え）が
/// 返ると `recv_ack` は `InvalidArgument` で拒否してクライアントを失効させ、
/// `rejected_ack_kind_mismatch_count` を計上する。
#[test]
fn io2_flush_recv_ack_kind_mismatch_is_rejected() {
    let limit = InFlightLimit::new(4).expect("4 must be valid");
    let sender = RecordingSender::default();
    let recv = sender.recv_handle();
    let mut client = PipelineClient::new(sender, limit, NoopSendObserver);

    let barrier = client.flush(test_timeout()).expect("flush must succeed");

    // 期待される `FlushAck` の代わりに通常 `Ack` を返す台本（種別取り違え）。
    let mismatched_ack = encode_ack(FrameKind::Ack, WireRequestId::from(barrier.id()))
        .expect("encode_ack must succeed");
    recv.push_ack(Ok(mismatched_ack));

    let err = client
        .recv_ack(test_timeout())
        .expect_err("ack kind mismatch must be rejected");
    assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    assert!(client.is_poisoned());
    assert_eq!(client.ack_metrics().rejected_ack_kind_mismatch_count(), 1);
}
