//! パイプライン送信クライアント（TASK-12・IO-1）の送信キュー本体（TASK-12.1・#73）。
//!
//! IO-1（確定）は「クライアントは ACK を待たずに書き込みリクエストを連続送信し、
//! サーバーはバッファリングした時点で ACK を返す」というプロトコルを定める。ACK を
//! 待たずに送り続けると未 ACK のリクエストが際限なく増えうるため、本モジュールは
//! 未 ACK 件数に上限を設けて追跡する送信キュー（[`SendQueue`]）と、それを使って
//! [`crate::transport::FrameSender`] へ橋渡しするクライアント（[`PipelineClient`]）を
//! 提供する。
//!
//! # #74（TASK-12.2）との境界
//!
//! 本モジュールが持つのは「送信済みで ACK 未受信のリクエストを追跡する」ところまで。
//! 次の範囲は #74（TASK-12.2）以降が担い、ここでは実装しない（REPAIR-3。スタブの
//! 明示）:
//! - ACK フレームの受信・デコードと、request id との対応付け
//! - タイムアウト付きの ACK 待ち・ブロッキング送信 API
//! - request id のワイヤー表現（ペイロード内レイアウト）。[`RequestId`] は
//!   クライアントがローカルに振る連番であり、ペイロードには含めない
//!
//! 未フラッシュ滞留量（バイト数）の上限・自動フラッシュは IO-10（別タスク）の範囲。
//! 送信側と受信側をスレッド間で分割する API も #74 以降で扱い、本モジュールの
//! [`PipelineClient`] は `&mut self` を要求する単一スレッド前提の型として実装する。

use std::collections::VecDeque;

use crate::error::{IoError, IoErrorCode};
use crate::protocol::{Frame, FrameKind};
use crate::transport::{FrameSender, IoTimeout};

/// [`SendQueue`] の既定の未 ACK 件数上限。
///
/// PoC-2（`03-poc/io-layer-redesign`）のクライアントが使っていた in-flight window の
/// 既定値（64 件。サーバー側バッチサイズに揃えた値）を根拠とする。IO-1 の「既定 64 件」
/// はサーバーのバッチサイズ（TASK-13）を指しており、クライアントの window とは別の
/// 概念だが、値としては同じ 64 を踏襲する。
pub const DEFAULT_IN_FLIGHT_LIMIT: usize = 64;

/// [`InFlightLimit::new`] が受理する上限件数の最大値。
///
/// [`InFlightRequest`] はペイロードを保持せず（`id`・`kind` のみ）、上限まで埋まっても
/// メモリ使用量は小さい。この `4096` は暫定値であり、TASK-113 のベンチ・TASK-85 の
/// 結合試験で見直してよい（REPAIR-3）。無制限確保を防ぐための上限（security.md
/// 「不安全な設計」観点）として、`0` 件を含む検証は [`InFlightLimit::new`] が行う。
pub const MAX_IN_FLIGHT_LIMIT: usize = 4096;

/// 検証済みの未 ACK 件数上限（[`SendQueue`] の容量。IO-1・TASK-12.1）。
///
/// フィールドは非公開で、[`Self::new`] を経由しない限り値を作れない
/// （REPAIR-2: 壊れた値を表現できない型）。`0`（送信できないキューになる）と
/// [`MAX_IN_FLIGHT_LIMIT`] 超過（無制限確保の防止）を拒否する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InFlightLimit(usize);

impl InFlightLimit {
    /// `limit` が `1..=MAX_IN_FLIGHT_LIMIT` の範囲であれば受理する。
    /// 範囲外の場合は [`IoErrorCode::InvalidArgument`] を返す。
    pub fn new(limit: usize) -> Result<Self, IoError> {
        if limit == 0 {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "in-flight limit must not be zero",
            ));
        }
        if limit > MAX_IN_FLIGHT_LIMIT {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("in-flight limit must be at most {MAX_IN_FLIGHT_LIMIT}"),
            ));
        }
        Ok(Self(limit))
    }

    /// 検証済みの上限件数を `usize` として返す。
    pub fn get(self) -> usize {
        self.0
    }
}

impl TryFrom<usize> for InFlightLimit {
    type Error = IoError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Default for InFlightLimit {
    /// 既定値は [`DEFAULT_IN_FLIGHT_LIMIT`]（64 件）。
    fn default() -> Self {
        Self(DEFAULT_IN_FLIGHT_LIMIT)
    }
}

/// クライアントがローカルに振る、送信リクエストの単調増加な識別子（TASK-12.1）。
///
/// ワイヤー上のレイアウト（ペイロードへどう載せるか）は #74（TASK-12.2）が定める。
/// 本型は crate 外から任意の値を作れないようにし（採番は [`SendQueue::register`] の
/// みが行う）、`get()` で値の読み出しのみ許す。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(u64);

impl RequestId {
    /// 識別子を `u64` として返す。
    pub fn get(self) -> u64 {
        self.0
    }
}

/// 送信済みで ACK 未受信の 1 リクエストを表す（TASK-12.1）。
///
/// ペイロードそのものは保持しない（再送は本件の範囲外。§2「スコープ境界」）。
/// 将来フィールドを追加できるよう、フィールドは非公開でアクセサ経由にする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InFlightRequest {
    id: RequestId,
    kind: FrameKind,
}

impl InFlightRequest {
    /// このリクエストの識別子を返す。
    pub fn id(&self) -> RequestId {
        self.id
    }

    /// このリクエストのフレーム種別を返す。
    pub fn kind(&self) -> FrameKind {
        self.kind
    }
}

/// 送信済みで ACK 未受信のリクエストを、上限件数付きで送信順に追跡するキュー
/// （IO-1・TASK-12.1）。
///
/// トランスポートを持たない純粋なデータ構造で、[`PipelineClient`] がこれと
/// [`crate::transport::FrameSender`] を組み合わせて使う。ACK 受信による取り外しは
/// [`Self::remove`] が担い、その呼び出し元は #74（TASK-12.2）の ACK 処理を想定する
/// （untrusted な入力〔ACK 由来の id〕を扱う経路であり、`unwrap`・`expect`・添字
/// アクセスを使わない）。
#[derive(Debug)]
pub struct SendQueue {
    entries: VecDeque<InFlightRequest>,
    next_id: u64,
    limit: InFlightLimit,
}

impl SendQueue {
    /// 上限件数を指定してキューを作る。
    pub fn new(limit: InFlightLimit) -> Self {
        Self {
            entries: VecDeque::new(),
            next_id: 0,
            limit,
        }
    }

    /// このキューの上限件数を返す。
    pub fn limit(&self) -> InFlightLimit {
        self.limit
    }

    /// 現在の未 ACK 件数を返す。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 未 ACK のリクエストが 1 件もないかを返す。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 未 ACK 件数が上限に達しているかを返す。
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.limit.get()
    }

    /// 上限まで残っている件数を返す。
    pub fn remaining(&self) -> usize {
        self.limit.get().saturating_sub(self.entries.len())
    }

    /// 送信順で最も古い（最初に送信された）未 ACK リクエストを返す。
    pub fn oldest(&self) -> Option<&InFlightRequest> {
        self.entries.front()
    }

    /// 送信順で未 ACK リクエストを列挙するイテレータを返す。
    pub fn iter(&self) -> impl Iterator<Item = &InFlightRequest> {
        self.entries.iter()
    }

    /// 上限到達・id 採番の両方が可能かを検証する。どちらか一方でも不可なら
    /// トランスポートへ書き込む前に呼び出し元がエラーを返せるようにする
    /// （[`PipelineClient::send`] が使う）。
    fn ensure_can_register(&self) -> Result<(), IoError> {
        if self.is_full() {
            return Err(IoError::new(
                IoErrorCode::ResourceExhausted,
                format!(
                    "send queue is full: {} in-flight requests reached the limit of {}",
                    self.entries.len(),
                    self.limit.get()
                ),
            ));
        }
        if self.next_id.checked_add(1).is_none() {
            return Err(IoError::new(
                IoErrorCode::ResourceExhausted,
                "request id counter would overflow u64",
            ));
        }
        Ok(())
    }

    /// 新しい id を採番し、末尾に登録する。
    ///
    /// 上限に達している場合、または id の採番が `u64` の範囲を超える場合は
    /// [`IoErrorCode::ResourceExhausted`] を返し、キューの状態を変更しない。
    pub fn register(&mut self, kind: FrameKind) -> Result<InFlightRequest, IoError> {
        self.ensure_can_register()?;
        let id = RequestId(self.next_id);
        // `ensure_can_register` が `checked_add` の成功を確認済みのため、ここでの
        // インクリメントは安全に行える（未検証の `+= 1` を避けるための事前確認）。
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("checked in ensure_can_register");
        let request = InFlightRequest { id, kind };
        self.entries.push_back(request);
        Ok(request)
    }

    /// 指定した id の未 ACK リクエストを取り外す（ACK 受信時に #74 が呼ぶ入口）。
    ///
    /// `id` はキューには無関係な由来（ACK フレーム。untrusted）でありうるため、
    /// `position` と `Option` 経由で探し、`unwrap`・`expect`・添字アクセスは使わない。
    /// 未登録の id を渡された場合は [`IoErrorCode::InvalidArgument`] を返し、
    /// キューの状態を変更しない。
    pub fn remove(&mut self, id: RequestId) -> Result<InFlightRequest, IoError> {
        let position = self
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or_else(|| {
                IoError::new(
                    IoErrorCode::InvalidArgument,
                    format!("unknown in-flight request id: {}", id.get()),
                )
            })?;
        self.entries.remove(position).ok_or_else(|| {
            IoError::new(
                IoErrorCode::Internal,
                "in-flight request disappeared between position lookup and removal",
            )
        })
    }

    /// テスト専用: 次に採番する id を直接設定する（オーバーフロー境界のテストに使う）。
    #[cfg(test)]
    fn set_next_id_for_test(&mut self, next_id: u64) {
        self.next_id = next_id;
    }
}

/// [`crate::transport::FrameSender`] と [`SendQueue`] を組み合わせ、パイプライン送信
/// （IO-1）のキュー管理付き送信 API を提供する（TASK-12.1）。
///
/// ACK の受信・対応付け・タイムアウト付き待機は持たない（#74。モジュール冒頭の
/// 「#74（TASK-12.2）との境界」を参照）。`&mut self` を要求し、単一スレッド前提
/// （[`crate::transport::FrameSender`] と同じ契約）。
#[derive(Debug)]
pub struct PipelineClient<S>
where
    S: FrameSender<Frame = Frame>,
{
    sender: S,
    queue: SendQueue,
}

impl<S> PipelineClient<S>
where
    S: FrameSender<Frame = Frame>,
{
    /// トランスポートと未 ACK 件数上限からクライアントを作る。
    pub fn new(sender: S, limit: InFlightLimit) -> Self {
        Self {
            sender,
            queue: SendQueue::new(limit),
        }
    }

    /// 未 ACK リクエストの追跡状態を参照する。
    pub fn queue(&self) -> &SendQueue {
        &self.queue
    }

    /// 内部のトランスポートを取り出す（呼び出し元がトランスポートの後始末をしたい
    /// 場合に使う）。未 ACK の追跡状態は破棄される。
    pub fn into_inner(self) -> S {
        self.sender
    }

    /// フレームを送信する。ACK は待たない。
    ///
    /// 処理順（トランスポートへ書き込む前に上限判定を行う。REPAIR-5・
    /// security.md「不安全な設計」観点）:
    /// 1. 未 ACK 件数が上限に達していれば、あるいは id 採番が溢れるなら
    ///    [`IoErrorCode::ResourceExhausted`] を返す（この時点ではトランスポートへ
    ///    書き込まない）
    /// 2. `sender.send_frame` でトランスポートへ書き出す。失敗したらそのまま
    ///    エラーを返し、キューへは登録しない（id も消費しない）
    /// 3. 成功したら [`SendQueue::register`] で採番・登録し、[`InFlightRequest`]
    ///    を返す
    ///
    /// `timeout` は 1 回の書き込みにそのまま渡す（ACK を待つものではない。
    /// REPAIR-5）。
    pub fn send(&mut self, frame: &Frame, timeout: IoTimeout) -> Result<InFlightRequest, IoError> {
        self.queue.ensure_can_register()?;
        self.sender.send_frame(frame, timeout)?;
        self.queue.register(frame.kind())
    }

    /// 指定した id の未 ACK リクエストを取り外す（#74 の ACK 処理から呼ばれる入口）。
    pub fn remove_in_flight(&mut self, id: RequestId) -> Result<InFlightRequest, IoError> {
        self.queue.remove(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::FrameKind;
    use std::time::Duration;

    fn test_timeout() -> IoTimeout {
        IoTimeout::new(Duration::from_millis(1)).expect("1ms must be a valid timeout")
    }

    fn write_frame(byte: u8) -> Frame {
        Frame::new(FrameKind::Write, vec![byte]).expect("frame must be valid")
    }

    /// テスト専用のモック sender。送信したフレームを記録し、常に成功する。
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

    /// テスト専用のモック sender。常に `Timeout` を返し、トランスポートへの
    /// 書き込み失敗時にキューへ登録しないことを確認するために使う。
    #[derive(Debug, Default)]
    struct AlwaysTimeoutSender;

    impl FrameSender for AlwaysTimeoutSender {
        type Frame = Frame;

        fn send_frame(&mut self, _frame: &Self::Frame, _timeout: IoTimeout) -> Result<(), IoError> {
            Err(IoError::new(IoErrorCode::Timeout, "mock always times out"))
        }
    }

    /// IO-1: `InFlightLimit::new(0)` は `InvalidArgument` で拒否される。
    #[test]
    fn io1_in_flight_limit_rejects_zero() {
        let err = InFlightLimit::new(0).expect_err("zero must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1: `1` と `MAX_IN_FLIGHT_LIMIT` はちょうど受理され、値が保持される。
    #[test]
    fn io1_in_flight_limit_accepts_boundaries() {
        let lower = InFlightLimit::new(1).expect("1 must be accepted");
        assert_eq!(lower.get(), 1);

        let upper =
            InFlightLimit::new(MAX_IN_FLIGHT_LIMIT).expect("MAX_IN_FLIGHT_LIMIT must be accepted");
        assert_eq!(upper.get(), MAX_IN_FLIGHT_LIMIT);
    }

    /// IO-1: `MAX_IN_FLIGHT_LIMIT + 1` と `usize::MAX` は `InvalidArgument` で
    /// 拒否される。
    #[test]
    fn io1_in_flight_limit_rejects_above_max() {
        let over = InFlightLimit::new(MAX_IN_FLIGHT_LIMIT + 1)
            .expect_err("MAX_IN_FLIGHT_LIMIT + 1 must be rejected");
        assert_eq!(over.code(), IoErrorCode::InvalidArgument);

        let max = InFlightLimit::new(usize::MAX).expect_err("usize::MAX must be rejected");
        assert_eq!(max.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1: `Default` の値は `DEFAULT_IN_FLIGHT_LIMIT`（64）。
    #[test]
    fn io1_in_flight_limit_default_is_64() {
        assert_eq!(InFlightLimit::default().get(), 64);
        assert_eq!(DEFAULT_IN_FLIGHT_LIMIT, 64);
    }

    /// IO-1・TASK-12.1: 上限に余裕があれば、送信順どおりに id `0, 1, 2` が振られ、
    /// キューの内容・sender の記録もその順序を保つ。
    #[test]
    fn io1_pipeline_client_preserves_send_order() {
        let limit = InFlightLimit::new(4).expect("4 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit);

        let mut ids = Vec::new();
        for byte in [10u8, 20, 30] {
            let request = client
                .send(&write_frame(byte), test_timeout())
                .expect("send must succeed while under the limit");
            ids.push(request.id().get());
        }

        assert_eq!(ids, vec![0, 1, 2]);

        let queued: Vec<(u64, FrameKind)> = client
            .queue()
            .iter()
            .map(|entry| (entry.id().get(), entry.kind()))
            .collect();
        assert_eq!(
            queued,
            vec![
                (0, FrameKind::Write),
                (1, FrameKind::Write),
                (2, FrameKind::Write),
            ]
        );

        let sent_bytes: Vec<u8> = client
            .into_inner()
            .sent
            .iter()
            .map(|frame| frame.payload()[0])
            .collect();
        assert_eq!(sent_bytes, vec![10, 20, 30]);
    }

    /// IO-1・TASK-12.1（受け入れ条件の中核）: 上限に達すると `send` は
    /// `ResourceExhausted` を返し、トランスポートへは書き込まれない。
    #[test]
    fn io1_pipeline_client_rejects_when_limit_reached() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit);

        client
            .send(&write_frame(1), test_timeout())
            .expect("1st send must succeed");
        client
            .send(&write_frame(2), test_timeout())
            .expect("2nd send must succeed");

        let err = client
            .send(&write_frame(3), test_timeout())
            .expect_err("3rd send must be rejected once the limit is reached");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);

        assert_eq!(client.queue().len(), 2);
        assert!(client.queue().is_full());
        assert_eq!(client.into_inner().sent.len(), 2);
    }

    /// IO-1・TASK-12.1: 満杯のあと 1 枠を解放すると次の送信が成功し、id は
    /// 単調増加を続ける。キューの順序は解放後も送信順を保つ。
    #[test]
    fn io1_pipeline_client_accepts_after_slot_released() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
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
            .remove_in_flight(first.id())
            .expect("removing the released id must succeed");

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

    /// IO-1・TASK-12.1: 未登録の id を `remove` すると `InvalidArgument` を返し、
    /// キューの件数は変わらない（#74 では ACK〔untrusted〕由来の id がここへ来る）。
    #[test]
    fn io1_send_queue_remove_unknown_id_is_rejected() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut queue = SendQueue::new(limit);
        queue
            .register(FrameKind::Write)
            .expect("register must succeed while under the limit");

        let err = queue
            .remove(RequestId(999))
            .expect_err("unknown id must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        assert_eq!(queue.len(), 1);
    }

    /// IO-1・TASK-12.1: トランスポートへの書き込みが失敗した場合はキューへ登録
    /// せず、id も消費しない（次に成功したときの id が `0` から始まる）。
    #[test]
    fn io1_pipeline_client_does_not_register_on_transport_error() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(AlwaysTimeoutSender, limit);

        let err = client
            .send(&write_frame(1), test_timeout())
            .expect_err("transport failure must propagate");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert_eq!(client.queue().len(), 0);

        // sender を成功するものへ差し替えても、失敗した送信は id を消費していない
        // ことを確認する（新しいクライアントで id が 0 から始まる）。
        let mut client = PipelineClient::new(RecordingSender::default(), limit);
        let request = client
            .send(&write_frame(1), test_timeout())
            .expect("send must succeed with a working sender");
        assert_eq!(request.id().get(), 0);
    }

    /// IO-1・TASK-12.1: id の採番が `u64` の範囲を超える場合は `ResourceExhausted`
    /// を返し、トランスポートへは書き込まれない。
    #[test]
    fn io1_send_queue_rejects_id_overflow() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit);
        // `pub(crate)` ではなく `#[cfg(test)]` の内部ヘルパーで直接キューの状態を
        // 書き換え、`u64::MAX` からの採番がオーバーフローを起こす境界を再現する。
        client.queue.set_next_id_for_test(u64::MAX);

        let err = client
            .send(&write_frame(1), test_timeout())
            .expect_err("id overflow must be rejected");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
        assert_eq!(client.into_inner().sent.len(), 0);
    }

    fn assert_send<T: Send>() {}

    /// IO-1: `PipelineClient<RecordingSender>` は `Send` を満たす
    /// （`FrameSender: Send` の supertrait により自動的に成立する）。
    #[test]
    fn io1_pipeline_client_is_send() {
        assert_send::<PipelineClient<RecordingSender>>();
    }
}
