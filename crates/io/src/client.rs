//! パイプライン送信クライアント（TASK-12・IO-1）の送信キュー本体（TASK-12.1・#73）。
//!
//! IO-1（確定）は「クライアントは ACK を待たずに書き込みリクエストを連続送信し、
//! サーバーはバッファリングした時点で ACK を返す」というプロトコルを定める。ACK を
//! 待たずに送り続けると未 ACK のリクエストが際限なく増えうるため、本モジュールは
//! 未 ACK 件数に上限を設けて追跡する送信キュー（[`SendQueue`]）と、それを使って
//! [`crate::transport::FrameSender`] へ橋渡しするクライアント（[`PipelineClient`]）を
//! 提供する。[`PipelineClient::send`] の成功・失敗カウントとレイテンシ分布は
//! [`SendMetrics`]（[`PipelineClient::metrics`] で参照）として観測できるほか、
//! 送信のたびに [`crate::observe::SendObserver`] へイベント通知する。
//! [`PipelineClient::new`] は観測フックを必須引数として要求し（TASK-12.1・#73
//! codex 再指摘対応。P1・REPAIR-4）、観測しない場合は呼び出し元が
//! [`crate::observe::NoopSendObserver`] を明示的に渡す（暗黙に破棄しない）。
//! [`crate::observe::JsonLinesSendObserver`] 等へ差し替えれば送信イベントを記録
//! できる。`on_send` は送信経路から同期で呼ばれるためブロックする I/O をしては
//! ならず（REPAIR-5。[`crate::observe`] モジュールドキュメント参照）、
//! [`crate::observe::JsonLinesSendObserver`] はメモリ内にためるだけで、実際の
//! 書き出しは [`PipelineClient::observer_mut`] 経由で取り出した観測フックに対し
//! 呼び出し元が行う。base 側 AGENTS.md の可観測性要件・REPAIR-4）。
//!
//! [`PipelineClient::send`]（TASK-12.2・#74）は [`crate::payload::encode_request`]
//! で request id を埋め込んだフレームを組み立てて送る。[`PipelineClient::recv_ack`]
//! （TASK-12.2・#74）は [`crate::payload::decode_ack`] で受信 ACK を検証し、送信順
//! （[`SendQueue::oldest`]）と対応付けてから未 ACK 枠を解放する。ワイヤー上の
//! request id は連番（`u64`）のみで、[`RequestId`] が内部に持つ発行元キュー識別子
//! （[`QueueId`]）はメモリ内の区別のみに使い、ワイヤー上のバイト表現には一切
//! 影響しない（TASK-12.1・#73 codex 再指摘対応。P1）。
//!
//! # #74（TASK-12.2）以降に残る範囲
//!
//! トランスポート層の分割は [`crate::transport::SplitTransport`]（#1118）で定義済みだが、
//! 本モジュールの [`PipelineClient`] 自体の送受信分割（共有 `SendQueue` を持つ送信側・
//! ACK 受信側）は持たず、`&mut self` を要求する単一スレッド前提の型のまま実装する
//! （別タスクの範囲。要起票）。未フラッシュ滞留量（バイト数）の上限・自動フラッシュは
//! IO-10（別タスク）の範囲。ACK に status バイトを持たせるかどうか（サーバー側の
//! 失敗を伝える手段）は [`crate::payload`] モジュールドキュメントの「status バイトを
//! 持たせない理由」を参照（導入する場合は `PROTOCOL_VERSION` を上げる必要がある）。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// ACK 受信結果の型。定義は [`crate::barrier`]（TASK-15.1・IO-2）へ移したが、
/// 従来の公開パス `fandhe_container_io::client::AckReceipt` を維持するため再エクスポートする。
pub use crate::barrier::AckReceipt;
use crate::barrier::FlushBarrier;
use crate::error::{IoError, IoErrorCode};
#[cfg(test)]
use crate::observe::NoopSendObserver;
use crate::observe::{AckEvent, AckEventError, SendEvent, SendEventError, SendObserver};
use crate::payload::{self, WireRequestId};
use crate::protocol::{Frame, FrameKind};
use crate::transport::{FrameReceiver, FrameSender, IoTimeout};

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

/// `Default for InFlightLimit` は検証付きコンストラクタ（[`InFlightLimit::new`]）を
/// 経由しないため、[`DEFAULT_IN_FLIGHT_LIMIT`] 自体が `InFlightLimit::new` の検証
/// 範囲（`1..=MAX_IN_FLIGHT_LIMIT`）に収まることをコンパイル時に保証する
/// （初回レビュー Low 指摘対応。REPAIR-5）。
const _: () = assert!(
    DEFAULT_IN_FLIGHT_LIMIT > 0 && DEFAULT_IN_FLIGHT_LIMIT <= MAX_IN_FLIGHT_LIMIT,
    "DEFAULT_IN_FLIGHT_LIMIT は InFlightLimit::new の検証範囲（1..=MAX_IN_FLIGHT_LIMIT）を \
     満たさなければならない"
);

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

/// プロセス内で一意な [`SendQueue`] の発行元識別子（TASK-12.1・#73 codex 再指摘
/// 対応。P1）。
///
/// codex 指摘: [`RequestId`] の数値部分（連番）は各 [`SendQueue`] が `0` から
/// 独立に採番するため、別の [`PipelineClient`] が発行した同値の id を渡されても
/// [`SendQueue::remove`] が数値だけで一致判定すると誤って解放してしまう。本型を
/// [`RequestId`] へ埋め込み、id の発行元キューが自分自身と一致するかを検証してから
/// 解放できるようにする。
///
/// [`Self::allocate`] は `counter`（[`SendQueue::new`] からは
/// プロセス全体で共有する `static` を渡す）を `checked_add` 相当
/// （[`AtomicU64::try_update`]）で進め、`u64` の範囲を超える採番を
/// [`IoErrorCode::ResourceExhausted`] として検出する。`u64::MAX` 個の
/// [`SendQueue`] を単一プロセス内で生成することは実用上起こり得ないが、
/// 万一そこへ到達しても値を巻き戻して重複させることはない（`try_update` は
/// 失敗時にカウンタを変更しないため、以降のすべての採番も同じエラーで拒否され
/// 続ける。整数オーバーフローによる id の再利用・衝突を防ぐ。security.md
/// 「不安全な設計」観点）。
///
/// `Ordering::Relaxed` で十分な理由: この counter が保証すべき性質は
/// 「返す値がプロセス内で重複しない」ことのみで、他のメモリ操作との
/// happens-before 関係を必要としない（この値を経由して他のデータを
/// 公開・参照することはない）ため、より強い順序付けは不要。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueueId(u64);

impl QueueId {
    /// `counter` から次の値を採番する。`u64` の範囲を超える場合は
    /// [`IoErrorCode::ResourceExhausted`] を返し、`counter` の状態は変更しない
    /// （`try_update` が失敗時にカウンタを変更しない契約を利用する）。
    fn allocate(counter: &AtomicU64) -> Result<Self, IoError> {
        counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map(Self)
            .map_err(|_| {
                IoError::new(
                    IoErrorCode::ResourceExhausted,
                    "queue id counter would overflow u64",
                )
            })
    }
}

/// プロセス全体で共有する [`QueueId`] の採番カウンタ（[`SendQueue::new`] が使う）。
static NEXT_QUEUE_ID: AtomicU64 = AtomicU64::new(0);

/// クライアントがローカルに振る、送信リクエストの単調増加な識別子（TASK-12.1）。
///
/// ワイヤー上のレイアウト（ペイロードへどう載せるか）は #74（TASK-12.2）が定める。
/// 本型は crate 外から任意の値を作れないようにし（採番は [`SendQueue::register`] の
/// みが行う）、`get()` で連番部分の読み出しのみ許す。発行元キュー
/// （[`QueueId`]。TASK-12.1・#73 codex 再指摘対応。P1）はメモリ内の区別にのみ使い、
/// ワイヤー上のバイト表現には一切影響しない（本モジュール冒頭の「#74（TASK-12.2）
/// との境界」を参照）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId {
    queue_id: QueueId,
    seq: u64,
}

impl RequestId {
    /// この識別子を発行した [`SendQueue`] の連番部分を `u64` として返す。
    ///
    /// 発行元が異なれば同じ値が返りうる（各 [`SendQueue`] が独立に `0` から
    /// 採番するため）。発行元ごとの一意性は [`QueueId`] が担う（非公開。
    /// [`SendQueue::remove`] の照合にのみ使う）。
    pub fn get(self) -> u64 {
        self.seq
    }
}

/// 送信済みで ACK 未受信の 1 リクエストを表す（TASK-12.1）。
///
/// ペイロードそのものは保持しない（再送はモジュール冒頭の「#74（TASK-12.2）との
/// 境界」に記した範囲外）。将来フィールドを追加できるよう、フィールドは非公開で
/// アクセサ経由にする。
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

/// [`FrameKind::Write`] / [`FrameKind::Flush`] だけを未 ACK 追跡の対象として受理する。
///
/// [`FrameKind::Ack`] / [`FrameKind::FlushAck`] は応答フレームであり、これらに対応する
/// ACK は来ない。追跡対象に含めると未 ACK キューの枠を占有し続け、二度と解放されない
/// （[`SendQueue::register`]・[`PipelineClient::send`] の両方で共有する検証。
/// codex レビュー指摘: `register` は本検証を経ずに `Ack`/`FlushAck` を受理していた）。
fn ensure_trackable_frame_kind(kind: FrameKind) -> Result<(), IoError> {
    match kind {
        FrameKind::Write | FrameKind::Flush => Ok(()),
        FrameKind::Ack | FrameKind::FlushAck => Err(IoError::new(
            IoErrorCode::InvalidArgument,
            "only Write/Flush frames can be tracked as in-flight requests",
        )),
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
    /// このキューの発行元識別子（TASK-12.1・#73 codex 再指摘対応。P1）。
    ///
    /// [`QueueId::allocate`] がプロセス全体の `static` カウンタの枯渇
    /// （実用上起こり得ない）を検出した場合のみ `None` になる。`None` の
    /// キューは [`Self::ensure_can_register`] が常に
    /// [`IoErrorCode::ResourceExhausted`] を返すため、二度と id を発行できない
    /// （枯渇したカウンタから重複した [`QueueId`] を割り当てて衝突させるより、
    /// このキューを恒久的に使用不能にする方を選ぶ。無効な `RequestId` を
    /// 一切生成しない）。
    queue_id: Option<QueueId>,
}

impl SendQueue {
    /// 上限件数を指定してキューを作る。発行元識別子はプロセス全体で共有する
    /// `static` カウンタ（[`NEXT_QUEUE_ID`]）から採番する。
    pub fn new(limit: InFlightLimit) -> Self {
        Self::with_queue_id_counter(limit, &NEXT_QUEUE_ID)
    }

    /// [`Self::new`] の内部実装。テストでは枯渇済みのローカルカウンタを渡し、
    /// `queue_id` が `None` になる経路を再現する（`static` を汚染せずに済む）。
    fn with_queue_id_counter(limit: InFlightLimit, counter: &AtomicU64) -> Self {
        Self {
            entries: VecDeque::new(),
            next_id: 0,
            limit,
            queue_id: QueueId::allocate(counter).ok(),
        }
    }

    /// テスト専用: 枯渇済みのローカルカウンタから作ったキュー（`queue_id` が
    /// `None`）を返す（[`QueueId`] 枯渇時に `register` が恒久的に拒否することを
    /// 確認するために使う）。
    #[cfg(test)]
    fn new_exhausted_for_test(limit: InFlightLimit) -> Self {
        let exhausted_counter = AtomicU64::new(u64::MAX);
        Self::with_queue_id_counter(limit, &exhausted_counter)
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
        if self.queue_id.is_none() {
            return Err(IoError::new(
                IoErrorCode::ResourceExhausted,
                "queue id counter would overflow u64; this queue can no longer register requests",
            ));
        }
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

    /// 次に [`Self::register`] が採番するであろう id を、キューの状態を変更せずに
    /// 覗き見る（TASK-12.2・#74。[`PipelineClient::send`] が id を先に確保して
    /// フレームを組み立てるために使う）。
    ///
    /// 呼び出し元は事前に [`Self::ensure_can_register`] で登録可能であることを
    /// 確認しておくこと。本メソッド自身は上限到達・id 採番の溢れを検証せず、
    /// [`Self::queue_id`] の枯渇（実用上起こり得ない）のみを
    /// [`IoErrorCode::ResourceExhausted`] として検出する（[`Self::register`] と
    /// 同じフォールバック。`unwrap`・`expect` を使わず `Result` で扱う）。
    pub(crate) fn peek_next_id(&self) -> Result<RequestId, IoError> {
        let queue_id = self.queue_id.ok_or_else(|| {
            IoError::new(
                IoErrorCode::ResourceExhausted,
                "queue id counter would overflow u64; this queue can no longer register requests",
            )
        })?;
        Ok(RequestId {
            queue_id,
            seq: self.next_id,
        })
    }

    /// 新しい id を採番し、末尾に登録する。
    ///
    /// `kind` が [`FrameKind::Write`] / [`FrameKind::Flush`] 以外
    /// （[`FrameKind::Ack`] / [`FrameKind::FlushAck`]）の場合は
    /// [`IoErrorCode::InvalidArgument`] を返し、キューの状態を変更しない
    /// （[`ensure_trackable_frame_kind`]。codex レビュー指摘: これらは応答フレームで
    /// 対応する ACK が来ず、登録すると未 ACK キューの枠が解放されないまま残る）。
    /// 上限に達している場合、または id の採番が `u64` の範囲を超える場合は
    /// [`IoErrorCode::ResourceExhausted`] を返し、キューの状態を変更しない。
    pub fn register(&mut self, kind: FrameKind) -> Result<InFlightRequest, IoError> {
        ensure_trackable_frame_kind(kind)?;
        self.ensure_can_register()?;
        // `ensure_can_register` で `queue_id` が `Some` であることを確認済みだが、
        // ライブラリコードは panic させない方針（coding-rust）のため、ここでも
        // `expect` ではなく `Result` 経由で扱う（到達しないはずの経路も含めて
        // panic 経路を作らない）。
        let queue_id = self.queue_id.ok_or_else(|| {
            IoError::new(
                IoErrorCode::ResourceExhausted,
                "queue id counter would overflow u64; this queue can no longer register requests",
            )
        })?;
        let id = RequestId {
            queue_id,
            seq: self.next_id,
        };
        // 上記と同様、`ensure_can_register` で `checked_add` の成功を確認済みだが、
        // ここでも `Result` 経由でオーバーフローを扱う。
        self.next_id = self.next_id.checked_add(1).ok_or_else(|| {
            IoError::new(
                IoErrorCode::ResourceExhausted,
                "request id counter would overflow u64",
            )
        })?;
        let request = InFlightRequest { id, kind };
        self.entries.push_back(request);
        Ok(request)
    }

    /// 指定した id の未 ACK リクエストを取り外す（検証済み ACK に基づく解放。
    /// TASK-12.1・#73 codex 再指摘対応。P1）。
    ///
    /// `id` はキューには無関係な由来（ACK フレーム。untrusted）でありうるため、
    /// `position` と `Option` 経由で探し、`unwrap`・`expect`・添字アクセスは使わない。
    /// 未登録の id・すでに解放済みの id を渡された場合は
    /// [`IoErrorCode::InvalidArgument`] を返し、キューの状態を変更しない
    /// （二重解放の防止）。
    ///
    /// # 発行元キューの検証（TASK-12.1・#73 codex 再指摘対応。P1）
    ///
    /// `id` が自分自身（`self`）以外の [`SendQueue`] で発行された場合、キューの
    /// 内部連番（`seq`）が同値でも [`IoErrorCode::InvalidArgument`] で拒否し、
    /// キューの状態を変更しない。各 [`SendQueue`] は連番を独立に `0` から
    /// 採番するため、この検証がなければ別クライアントが受け取った ACK 未受信の
    /// id を渡すだけで、対応する ACK を一度も受けていない自分自身の枠を
    /// 誤って解放できてしまう（codex レビュー指摘）。
    ///
    /// # 公開範囲と ACK 検証の責務（TASK-12.1・#73 codex 再指摘対応。P1）
    ///
    /// 公開 API だが、「渡された `id` がすでに検証済みの ACK に対応する」ことは
    /// 呼び出し元の責務であり、本メソッド自身は ACK フレームの検証を行わない
    /// （キューに存在する id かどうかの整合性チェックのみ行う）。ACK フレームの
    /// 受信・デコード・ペイロード検証（request id が実在の未 ACK リクエストに
    /// 対応するかを含む）は #74（TASK-12.2）の範囲で、#74 が受信した検証済み ACK
    /// の request id を使ってこの入口を呼ぶことを想定する（REPAIR-3。それまでは
    /// 呼び出し元が ACK を解釈してこのメソッドを呼ぶ）。
    pub fn remove(&mut self, id: RequestId) -> Result<InFlightRequest, IoError> {
        if self.queue_id != Some(id.queue_id) {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!(
                    "in-flight request id {} was issued by another queue and cannot be \
                     released here",
                    id.get()
                ),
            ));
        }
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

/// [`PipelineClient::send`] 1 回の結果種別（[`SendMetrics`] の内訳。TASK-12.1・#73
/// codex 指摘対応。P1・REPAIR-4）。
///
/// [`PipelineClient::send`] のドキュメンテーションコメントに記した処理順の各分岐に
/// 1 対 1 で対応する。呼び出し元はこの内訳を使い、上限到達（`ResourceExhausted`）や
/// トランスポート失敗（`TransportFailure`）を成功と区別して観測できる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SendOutcome {
    /// トランスポートへの書き込みまで成功した。
    Success,
    /// すでに失効済み（[`PipelineClient::is_poisoned`]）だったため拒否した。
    RejectedPoisoned,
    /// `Ack`/`FlushAck` など追跡対象外のフレーム種別だったため拒否した。
    RejectedInvalidFrameKind,
    /// 未 ACK 件数の上限到達、id（連番）採番の溢れ、または発行元キュー識別子
    /// （[`QueueId`]）の採番カウンタ枯渇（TASK-12.1・#73 codex 再指摘対応。P1。
    /// 実用上起こり得ない）で拒否した。
    RejectedResourceExhausted,
    /// [`crate::payload::encode_request`] がペイロード形式の検証（`Write` の body
    /// 長超過・`Flush` に body がある等）で拒否した（TASK-12.2・#74）。
    ///
    /// 未 ACK キューへは登録前に検出されるため、キューの状態は変化しない。
    /// `RejectedInvalidFrameKind`（フレーム種別そのものが追跡対象外）とは別に
    /// 区別する（body 長違反を既存の種別に混ぜると誤った分類になるため。
    /// REPAIR-4）。
    RejectedInvalidPayload,
    /// トランスポートへの書き込みが失敗し、クライアントを失効させた。
    TransportFailure,
}

/// [`LatencyStats`] のヒストグラムのバケット数（TASK-12.1・#73 codex 再指摘対応。
/// P1・REPAIR-4・REPAIR-3）。
///
/// バケット `i`（`1..=LATENCY_HISTOGRAM_BUCKETS - 2`）は `[2^(i-1), 2^i)` マイクロ秒を
/// 表し、バケット `0` は `0µs` 以上 `1µs` 未満を表す。最後のバケット
/// （`LATENCY_HISTOGRAM_BUCKETS - 1`）は上限なしで
/// `2^(LATENCY_HISTOGRAM_BUCKETS - 2)` マイクロ秒以上のすべてを受け持つ
/// （[`latency_bucket_index`]）。`25` は、最後のバケットの下限
/// （`2^23 = 8_388_608µs` ≒ 8.39 秒）が [`crate::transport::MAX_IO_TIMEOUT`]
/// （10 秒）以下になるよう選んだ値で、`MAX_IO_TIMEOUT` を超える所要時間は必ず
/// 最後のバケットに入る（下記の `const` assert で保証する）。
pub const LATENCY_HISTOGRAM_BUCKETS: usize = 25;

/// [`LATENCY_HISTOGRAM_BUCKETS`] が [`crate::transport::MAX_IO_TIMEOUT`] を
/// 超える所要時間を最後のバケットで受け持てることをコンパイル時に保証する
/// （バケット数を変更した際に、この前提が壊れていないかを検出する）。
const _: () = assert!(
    (1u128 << (LATENCY_HISTOGRAM_BUCKETS - 2)) <= crate::transport::MAX_IO_TIMEOUT.as_micros(),
    "LATENCY_HISTOGRAM_BUCKETS は、最後のバケットの下限が MAX_IO_TIMEOUT 以下になる \
     大きさでなければならない（MAX_IO_TIMEOUT を超える値が最後のバケットに入らなくなる）"
);

/// `micros` が属するヒストグラムのバケット番号を返す（[`LATENCY_HISTOGRAM_BUCKETS`]
/// のドキュメント参照）。`0` はバケット `0`、それ以外は `ilog2(micros) + 1` を
/// 最後のバケット番号で飽和させた値になる（`u64::ilog2` は `0` に対して
/// panic するため、`0` は先に分岐する）。
fn latency_bucket_index(micros: u64) -> usize {
    if micros == 0 {
        return 0;
    }
    // `ilog2` は `usize` へ変換してから加算する（`u32` のまま `+1` しても桁あふれは
    // 実用上起こらないが、以降の比較・添字アクセスを `usize` へ統一するため変換する）。
    let raw = micros.ilog2() as usize + 1;
    raw.min(LATENCY_HISTOGRAM_BUCKETS - 1)
}

/// 所要時間の分布を件数・合計・最小・最大・ヒストグラムで集計する（TASK-12.1・#73
/// codex 指摘対応。P1・REPAIR-4。ヒストグラムは #73 codex 再指摘対応。REPAIR-3・
/// REPAIR-4「所要時間分布」の doc と実装を一致させる）。
///
/// 外部メトリクス基盤へのエクスポートは持たない（REPAIR-3。スタブの明示。
/// エクスポートは別タスクで拡張してよい）。[`SendMetrics`] が送信結果種別ごとに
/// 保持し、[`PipelineClient::metrics`] 経由で読み出す。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LatencyStats {
    count: u64,
    total: Duration,
    min: Option<Duration>,
    max: Option<Duration>,
    /// マイクロ秒の 2 のべき乗境界のヒストグラム（[`LATENCY_HISTOGRAM_BUCKETS`]の
    /// doc 参照）。固定長配列でアロケーションを伴わず、各バケットは
    /// `saturating_add` で増やす（オーバーフローで panic・巻き戻りをしない）。
    buckets: [u64; LATENCY_HISTOGRAM_BUCKETS],
}

impl LatencyStats {
    fn record(&mut self, elapsed: Duration) {
        self.count = self.count.saturating_add(1);
        self.total = self.total.saturating_add(elapsed);
        self.min = Some(match self.min {
            Some(current) => current.min(elapsed),
            None => elapsed,
        });
        self.max = Some(match self.max {
            Some(current) => current.max(elapsed),
            None => elapsed,
        });
        // `Duration::as_micros` は `u128` を返すため、`u64` へ縮める際は `try_from`
        // で飽和させる（`as` キャストによる無言の切り捨てをしない。coding-rust
        // 「外部入力」観点に準じ、境界値〔`Duration::MAX`〕でも panic させない）。
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let index = latency_bucket_index(micros);
        // 添字アクセス（`[]`）を使わず `get_mut` で範囲を確認してから更新する
        // （`index` は `latency_bucket_index` が必ず範囲内に収める契約だが、
        // 万一の不整合でも panic させない）。
        if let Some(bucket) = self.buckets.get_mut(index) {
            *bucket = bucket.saturating_add(1);
        }
    }

    /// 観測件数を返す。
    pub fn count(&self) -> u64 {
        self.count
    }

    /// 観測した所要時間の合計を返す。
    pub fn total(&self) -> Duration {
        self.total
    }

    /// 観測した所要時間の最小値を返す（未観測なら `None`）。
    pub fn min(&self) -> Option<Duration> {
        self.min
    }

    /// 観測した所要時間の最大値を返す（未観測なら `None`）。
    pub fn max(&self) -> Option<Duration> {
        self.max
    }

    /// 観測した所要時間の平均値を返す（未観測なら `None`）。
    ///
    /// `count` は内部カウンタであり untrusted な入力ではないが、`Duration` の
    /// 秒数換算は浮動小数点を経由するため、`total`（`saturating_add` で
    /// 積算し続けた結果 `Duration::MAX` に達している）を極端に小さい `count`
    /// で割った場合など、`Duration::from_secs_f64` なら panic しうる値
    /// （NaN・負値・表現可能な範囲の超過）になりうる。[`Duration::try_from_secs_f64`]
    /// で `Result` として扱い、変換できない場合は `None` を返す（panic 経路の
    /// 除去。coding-rust「ライブラリコードでは `Result` を返し、panic させない」）。
    pub fn mean(&self) -> Option<Duration> {
        if self.count == 0 {
            return None;
        }
        Duration::try_from_secs_f64(self.total.as_secs_f64() / self.count as f64).ok()
    }

    /// ヒストグラムの各バケットの観測件数を返す（[`LATENCY_HISTOGRAM_BUCKETS`]の
    /// doc にバケット境界の定義がある）。
    pub fn histogram(&self) -> &[u64; LATENCY_HISTOGRAM_BUCKETS] {
        &self.buckets
    }

    /// `index` 番目のバケットが表す上限（排他的。マイクロ秒）を返す。
    ///
    /// 最後のバケット（`LATENCY_HISTOGRAM_BUCKETS - 1`。上限なし）と範囲外の
    /// `index` はどちらも `None` を返す（呼び出し元が「上限なし」と「無効な
    /// index」を区別したい場合は [`LATENCY_HISTOGRAM_BUCKETS`] と比較する）。
    pub fn bucket_upper_bound_micros(index: usize) -> Option<u64> {
        if index >= LATENCY_HISTOGRAM_BUCKETS - 1 {
            return None;
        }
        Some(1u64 << index)
    }
}

/// [`PipelineClient::send`] の成功・失敗カウントとレイテンシ分布を保持する
/// 構造化メトリクス（TASK-12.1・#73 codex 指摘対応。P1・REPAIR-4）。
///
/// base 側 AGENTS.md が要求する「write 操作の成功・失敗カウントとレイテンシ分布」
/// をプロセス内で観測するための最小実装。外部のログ / メトリクス基盤への出力は
/// 持たず、[`PipelineClient::metrics`] で読み出した値を呼び出し元が任意の基盤へ
/// 変換して出す（REPAIR-3。詳細な分布・エクスポート先の選定は別タスクの範囲）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SendMetrics {
    success_count: u64,
    rejected_poisoned_count: u64,
    rejected_invalid_frame_kind_count: u64,
    rejected_resource_exhausted_count: u64,
    rejected_invalid_payload_count: u64,
    transport_failure_count: u64,
    /// トランスポートへ実際に書き込んだ呼び出し（`Success`・`TransportFailure`）
    /// の所要時間分布。早期に拒否した呼び出し（`RejectedPoisoned` 等）はここへ
    /// 含めない（トランスポートを介さないため所要時間として意味を持たない）。
    write_latency: LatencyStats,
}

impl SendMetrics {
    fn record(&mut self, outcome: SendOutcome, elapsed: Duration) {
        match outcome {
            SendOutcome::Success => {
                self.success_count = self.success_count.saturating_add(1);
                self.write_latency.record(elapsed);
            }
            SendOutcome::RejectedPoisoned => {
                self.rejected_poisoned_count = self.rejected_poisoned_count.saturating_add(1);
            }
            SendOutcome::RejectedInvalidFrameKind => {
                self.rejected_invalid_frame_kind_count =
                    self.rejected_invalid_frame_kind_count.saturating_add(1);
            }
            SendOutcome::RejectedResourceExhausted => {
                self.rejected_resource_exhausted_count =
                    self.rejected_resource_exhausted_count.saturating_add(1);
            }
            SendOutcome::RejectedInvalidPayload => {
                self.rejected_invalid_payload_count =
                    self.rejected_invalid_payload_count.saturating_add(1);
            }
            SendOutcome::TransportFailure => {
                self.transport_failure_count = self.transport_failure_count.saturating_add(1);
                self.write_latency.record(elapsed);
            }
        }
    }

    /// トランスポートへの書き込みまで成功した回数。
    pub fn success_count(&self) -> u64 {
        self.success_count
    }

    /// [`PipelineClient::is_poisoned`] により拒否した回数。
    pub fn rejected_poisoned_count(&self) -> u64 {
        self.rejected_poisoned_count
    }

    /// 追跡対象外のフレーム種別（`Ack`/`FlushAck`）により拒否した回数。
    pub fn rejected_invalid_frame_kind_count(&self) -> u64 {
        self.rejected_invalid_frame_kind_count
    }

    /// 未 ACK 件数の上限到達・id 採番の溢れ・[`QueueId`] 採番カウンタ枯渇
    /// （実用上起こり得ない）により拒否した回数（`InFlightLimit` への到達を
    /// 観測する指標。TASK-12.1）。
    pub fn rejected_resource_exhausted_count(&self) -> u64 {
        self.rejected_resource_exhausted_count
    }

    /// [`crate::payload::encode_request`] のペイロード形式検証（`Write` の body
    /// 長超過・`Flush` に body がある等）により拒否した回数（TASK-12.2・#74）。
    pub fn rejected_invalid_payload_count(&self) -> u64 {
        self.rejected_invalid_payload_count
    }

    /// トランスポートへの書き込みが失敗し、クライアントを失効させた回数。
    pub fn transport_failure_count(&self) -> u64 {
        self.transport_failure_count
    }

    /// トランスポートへ実際に書き込んだ呼び出し（成功・失敗の両方）の
    /// 所要時間分布を返す。
    pub fn write_latency(&self) -> LatencyStats {
        self.write_latency
    }
}

/// [`PipelineClient::recv_ack`] 1 回の結果種別（[`AckMetrics`] の内訳。TASK-12.2・#74
/// codex 指摘対応。P1・REPAIR-4）。
///
/// [`PipelineClient::recv_ack`] のドキュメンテーションコメントに記した処理順の各
/// 分岐に 1 対 1 で対応する。呼び出し元はこの内訳を使い、成功・タイムアウト・
/// プロトコル違反（形式・送信順・種別）を区別して観測できる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AckOutcome {
    /// 送信順・種別の対応付けまで検証し、未 ACK 枠を解放できた。
    Success,
    /// すでに失効済み（[`PipelineClient::is_poisoned`]）だったため拒否した
    /// （`receiver` は呼ばない）。
    RejectedPoisoned,
    /// 未 ACK のリクエストが 1 件もない状態で呼ばれたため拒否した
    /// （`receiver` は呼ばない。プロトコル違反ではないため失効させない）。
    RejectedNoInFlight,
    /// `receiver.recv_frame` がエラー（[`IoErrorCode::Timeout`] を含む）を返し、
    /// クライアントを失効させた。
    TransportFailure,
    /// [`crate::payload::decode_ack`] のペイロード検証（種別違反・長さ違反）で
    /// 拒否し、クライアントを失効させた。
    RejectedInvalidPayload,
    /// 受け取った request id がキュー内には存在するが最古ではなかった
    /// （out-of-order ack）ため拒否し、クライアントを失効させた。
    RejectedOutOfOrder,
    /// 受け取った request id がキューのどこにも存在しなかった（unknown ack id）
    /// ため拒否し、クライアントを失効させた。
    RejectedUnknownAckId,
    /// 送信時の [`FrameKind`] に対応する ACK 種別（`Write` → `Ack`・`Flush` →
    /// `FlushAck`）と実際の受信種別が一致しなかったため拒否し、クライアントを
    /// 失効させた。
    RejectedAckKindMismatch,
    /// 構造上起こらないはずの内部不整合（キューが空チェック後に空になった・
    /// 追跡対象外のフレーム種別が未 ACK エントリに残っていた）を検出し、安全側に
    /// 倒して拒否した。到達しない想定だが、`unwrap`・`expect` を避けるための
    /// フォールバック分岐（coding-rust「ライブラリコードでは panic させない」）。
    RejectedInternal,
}

/// [`PipelineClient::recv_ack`] の成功・失敗カウントと ACK 待機の所要時間分布を
/// 保持する構造化メトリクス（TASK-12.2・#74 codex 指摘対応。P1・REPAIR-4）。
///
/// [`SendMetrics`] と対になる ACK 受信側の観測で、base 側 AGENTS.md が要求する
/// 「I/O 操作の成功・失敗カウントとレイテンシ分布」を `recv_ack` についても満たす。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AckMetrics {
    success_count: u64,
    rejected_poisoned_count: u64,
    rejected_no_in_flight_count: u64,
    transport_failure_count: u64,
    rejected_invalid_payload_count: u64,
    rejected_out_of_order_count: u64,
    rejected_unknown_ack_id_count: u64,
    rejected_ack_kind_mismatch_count: u64,
    rejected_internal_count: u64,
    /// `receiver.recv_frame` を実際に呼び出した呼び出し（成功・失敗の両方）の
    /// 所要時間分布。`receiver` を呼ばずに早期拒否した呼び出し
    /// （`RejectedPoisoned`・`RejectedNoInFlight`）はここへ含めない（[`SendMetrics::write_latency`]
    /// と同じ扱い）。
    wait_latency: LatencyStats,
}

impl AckMetrics {
    fn record(&mut self, outcome: AckOutcome, elapsed: Duration) {
        match outcome {
            AckOutcome::Success => {
                self.success_count = self.success_count.saturating_add(1);
                self.wait_latency.record(elapsed);
            }
            AckOutcome::RejectedPoisoned => {
                self.rejected_poisoned_count = self.rejected_poisoned_count.saturating_add(1);
            }
            AckOutcome::RejectedNoInFlight => {
                self.rejected_no_in_flight_count =
                    self.rejected_no_in_flight_count.saturating_add(1);
            }
            AckOutcome::TransportFailure => {
                self.transport_failure_count = self.transport_failure_count.saturating_add(1);
                self.wait_latency.record(elapsed);
            }
            AckOutcome::RejectedInvalidPayload => {
                self.rejected_invalid_payload_count =
                    self.rejected_invalid_payload_count.saturating_add(1);
                self.wait_latency.record(elapsed);
            }
            AckOutcome::RejectedOutOfOrder => {
                self.rejected_out_of_order_count =
                    self.rejected_out_of_order_count.saturating_add(1);
                self.wait_latency.record(elapsed);
            }
            AckOutcome::RejectedUnknownAckId => {
                self.rejected_unknown_ack_id_count =
                    self.rejected_unknown_ack_id_count.saturating_add(1);
                self.wait_latency.record(elapsed);
            }
            AckOutcome::RejectedAckKindMismatch => {
                self.rejected_ack_kind_mismatch_count =
                    self.rejected_ack_kind_mismatch_count.saturating_add(1);
                self.wait_latency.record(elapsed);
            }
            AckOutcome::RejectedInternal => {
                self.rejected_internal_count = self.rejected_internal_count.saturating_add(1);
                self.wait_latency.record(elapsed);
            }
        }
    }

    /// 送信順・種別の対応付けまで検証し、未 ACK 枠を解放できた回数。
    pub fn success_count(&self) -> u64 {
        self.success_count
    }

    /// [`PipelineClient::is_poisoned`] により拒否した回数（`receiver` を呼ばない）。
    pub fn rejected_poisoned_count(&self) -> u64 {
        self.rejected_poisoned_count
    }

    /// 未 ACK のリクエストが 1 件もない状態で呼ばれ拒否した回数
    /// （`receiver` を呼ばない）。
    pub fn rejected_no_in_flight_count(&self) -> u64 {
        self.rejected_no_in_flight_count
    }

    /// `receiver.recv_frame` がエラー（タイムアウトを含む）を返し失効させた回数。
    pub fn transport_failure_count(&self) -> u64 {
        self.transport_failure_count
    }

    /// ACK ペイロードの形式検証で拒否し失効させた回数。
    pub fn rejected_invalid_payload_count(&self) -> u64 {
        self.rejected_invalid_payload_count
    }

    /// 受信 ACK の request id がキュー内には存在するが最古ではなく拒否し
    /// 失効させた回数（out-of-order ack）。
    pub fn rejected_out_of_order_count(&self) -> u64 {
        self.rejected_out_of_order_count
    }

    /// 受信 ACK の request id がキューのどこにも存在せず拒否し失効させた回数
    /// （unknown ack id）。
    pub fn rejected_unknown_ack_id_count(&self) -> u64 {
        self.rejected_unknown_ack_id_count
    }

    /// 送信時のフレーム種別に対応しない ACK 種別を受け取り拒否し失効させた回数。
    pub fn rejected_ack_kind_mismatch_count(&self) -> u64 {
        self.rejected_ack_kind_mismatch_count
    }

    /// 構造上起こらないはずの内部不整合を検出し拒否した回数（到達しない想定の
    /// フォールバック分岐。[`AckOutcome::RejectedInternal`] 参照）。
    pub fn rejected_internal_count(&self) -> u64 {
        self.rejected_internal_count
    }

    /// `receiver.recv_frame` を実際に呼び出した呼び出し（成功・失敗の両方）の
    /// 所要時間分布を返す。
    pub fn wait_latency(&self) -> LatencyStats {
        self.wait_latency
    }
}

/// [`crate::transport::FrameSender`] と [`SendQueue`] を組み合わせ、パイプライン送信
/// （IO-1）のキュー管理付き送信 API を提供する（TASK-12.1）。
///
/// ACK の受信・対応付け・タイムアウト付き待機は持たない（#74。モジュール冒頭の
/// 「#74（TASK-12.2）との境界」を参照）。`&mut self` を要求し、単一スレッド前提
/// （[`crate::transport::FrameSender`] と同じ契約）。
#[derive(Debug)]
pub struct PipelineClient<S, O>
where
    S: FrameSender<Frame = Frame>,
    O: SendObserver,
{
    sender: S,
    queue: SendQueue,
    /// `send_frame` が「相手に届いたか不明」なエラーを返した後に立てる失効フラグ
    /// （TASK-12.1・#73 codex 指摘対応）。
    ///
    /// [`FrameSender::send_frame`] の契約は「エラー時に相手へ届いていないことを
    /// 保証しない」（`transport` モジュールのドキュメント参照）。部分送信・
    /// タイムアウト後のエラーでは、実際には相手に届いている可能性が残るため、
    /// その id を再利用して次のリクエストに使うと、後から届く応答（ACK）が
    /// 別のリクエストへ誤対応付けされる危険がある。これを避けるため、送信結果が
    /// 不明なエラーが起きたら本フィールドを立てて以降の [`Self::send`] をすべて
    /// 拒否し、id 空間・トランスポートの両方をこのクライアントでは再利用しない
    /// 状態へ遷移させる。
    poisoned: bool,
    /// [`Self::send`] の成功・失敗カウントとレイテンシ分布（TASK-12.1・#73 codex
    /// 指摘対応。P1・REPAIR-4）。
    metrics: SendMetrics,
    /// [`Self::recv_ack`] の成功・失敗カウントと ACK 待機の所要時間分布
    /// （TASK-12.2・#74 codex 指摘対応。P1・REPAIR-4）。
    ack_metrics: AckMetrics,
    /// [`Self::send`] のたびに通知する送信イベントの観測フック（TASK-12.1・#73
    /// codex 指摘対応。P1・REPAIR-4）。[`Self::new`] の必須引数であり、観測しない
    /// 場合は呼び出し元が [`crate::observe::NoopSendObserver`] を明示的に渡す（codex P1 再指摘
    /// 対応。既定を暗黙に選ばず、観測先の指定を構築時の必須契約にする）。
    /// [`Self::recv_ack`] の ACK イベントも同じ観測フック（[`SendObserver::on_ack`]）
    /// へ通知する（TASK-12.2・#74 codex 指摘対応。P1・REPAIR-4）。
    observer: O,
}

impl<S, O> PipelineClient<S, O>
where
    S: FrameSender<Frame = Frame>,
    O: SendObserver,
{
    /// トランスポート・未 ACK 件数上限・送信イベントの観測フックからクライアントを
    /// 作る（TASK-12.1・#73 codex 指摘対応。P1・REPAIR-4）。
    ///
    /// `observer` は必須引数であり、観測しない場合は呼び出し元が
    /// [`crate::observe::NoopSendObserver`] を明示的に渡す（codex P1 再指摘対応: `NoopSendObserver`
    /// を暗黙の既定にすると、通常の利用経路で送信成功・失敗や上限到達のイベントが
    /// 呼び出し元に気づかれないまま破棄され、base 側 AGENTS.md の可観測性要件
    /// 〔REPAIR-4〕を満たさない。観測先の指定を構築時の必須契約にすることで、
    /// 「観測しない」ことを呼び出し元の明示的な選択にする）。
    ///
    /// `observer` には [`crate::observe::JsonLinesSendObserver`] 等、送信イベントを
    /// 記録する実装を渡せる。渡した観測フックは [`Self::observer_mut`] で
    /// 取り出せる。
    pub fn new(sender: S, limit: InFlightLimit, observer: O) -> Self {
        Self {
            sender,
            queue: SendQueue::new(limit),
            poisoned: false,
            metrics: SendMetrics::default(),
            ack_metrics: AckMetrics::default(),
            observer,
        }
    }

    /// 未 ACK リクエストの追跡状態を参照する。
    pub fn queue(&self) -> &SendQueue {
        &self.queue
    }

    /// [`Self::send`] の成功・失敗カウントとレイテンシ分布を参照する
    /// （TASK-12.1・#73 codex 指摘対応。P1・REPAIR-4）。呼び出し元はここから
    /// 読み出した値を、任意のログ・メトリクス基盤へ変換して出力する。
    ///
    /// 送信の都度リアルタイムに出力したい場合は [`Self::new`] へ渡す
    /// [`SendObserver`] を使う（本メソッドは呼び出し元が明示的に読み出す
    /// 集計値であり、送信のたびに自動で外部へ出力する経路ではない）。
    pub fn metrics(&self) -> &SendMetrics {
        &self.metrics
    }

    /// [`Self::recv_ack`] の成功・失敗カウントと ACK 待機の所要時間分布を参照する
    /// （TASK-12.2・#74 codex 指摘対応。P1・REPAIR-4）。呼び出し元はここから
    /// 読み出した値を、任意のログ・メトリクス基盤へ変換して出力する。
    ///
    /// 受信の都度リアルタイムに出力したい場合は [`Self::new`] へ渡す
    /// [`SendObserver`]（[`SendObserver::on_ack`]）を使う（本メソッドは呼び出し元が
    /// 明示的に読み出す集計値であり、`recv_ack` のたびに自動で外部へ出力する
    /// 経路ではない）。
    pub fn ack_metrics(&self) -> &AckMetrics {
        &self.ack_metrics
    }

    /// [`Self::new`] へ渡した観測フックを参照する（TASK-12.1・#73
    /// codex 再指摘対応。P1・REPAIR-4）。
    pub fn observer(&self) -> &O {
        &self.observer
    }

    /// [`Self::new`] へ渡した観測フックを可変参照で取り出す
    /// （TASK-12.1・#73 codex 再指摘対応。P1・REPAIR-4・REPAIR-5）。
    ///
    /// [`crate::observe::JsonLinesSendObserver`] のようにメモリ内へためるだけの
    /// 実装では、`send` の呼び出しごとに `on_send`（ブロックしない契約。REPAIR-5）
    /// がここへ積むだけなので、実際の書き出し（部分書き込み時の再試行を含む）は
    /// 呼び出し元がこの参照から `drain_lines` を呼んで行う。
    pub fn observer_mut(&mut self) -> &mut O {
        &mut self.observer
    }

    /// このクライアントが失効済み（[`Self::poisoned`] 参照）かどうかを返す。
    ///
    /// `true` の場合、[`Self::send`] は常に [`IoErrorCode::Unavailable`] を返す。
    /// [`Self::into_inner`] も同様に `Err` を返してトランスポートを drop するため
    /// （TASK-12.1・#73 codex 指摘対応。P1）、呼び出し元はこの状態になった
    /// トランスポートを再利用できず、新しい接続を張り直す必要がある（送信結果が
    /// 不明なリクエストが残っている可能性があるため）。
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// 内部のトランスポートを取り出す（呼び出し元がトランスポートの後始末をしたい
    /// 場合に使う）。未 ACK の追跡状態は破棄される。
    ///
    /// # 失効済みトランスポートの扱い（TASK-12.1・#73 codex 指摘対応。P1）
    ///
    /// [`Self::is_poisoned`] が `true`（送信結果が不明なエラーの後）の場合は
    /// [`IoErrorCode::Unavailable`] を返し、`self`（`sender` を含む）をその場で
    /// drop する。トランスポートを呼び出し元へ返すと、それを使って新しい
    /// [`PipelineClient::new`] を作り直せてしまい、id が `0` から再開した状態で
    /// 遅れて届く ACK が別のリクエストへ誤対応付けされる危険がある
    /// （[`FrameSender`] は明示的な close / shutdown を持たないため、`self` を
    /// consume して drop することが、この接続を再利用不可にする API 上の唯一の
    /// 保証手段になる）。
    ///
    /// # 未 ACK が残るトランスポートの扱い（TASK-12.1・#73 codex 指摘対応。P1）
    ///
    /// `poisoned` が `false` でも、[`SendQueue`] に未 ACK のリクエストが 1 件でも
    /// 残っている場合は [`IoErrorCode::Unavailable`] を返し、同様に `self` を drop
    /// する。未 ACK 追跡状態（`queue`）はこの呼び出しで破棄されるため、返した
    /// `sender` を使って呼び出し元が新しい [`PipelineClient::new`] を作ると、
    /// 未 ACK キュー・`next_id` が空・`0` に巻き戻り、（a）まだ応答が来ていない
    /// 旧リクエストの ACK が新しいクライアントの id 空間へ誤対応付けされる、
    /// （b）ACK 未受信のまま実質的に `InFlightLimit` を超えて送信を継続できる、
    /// という 2 つの問題を招く。追跡状態を保ったままトランスポートだけを
    /// 差し替えたい場合は、`queue().is_empty()` で未 ACK が無いことを確認してから
    /// 呼び出すか、すべての ACK を受信し終えてから呼び出す（#74 の範囲。IO-1）。
    pub fn into_inner(self) -> Result<S, IoError> {
        if self.poisoned {
            return Err(IoError::new(
                IoErrorCode::Unavailable,
                "pipeline client is poisoned after an ambiguous send failure; \
                 the transport is dropped instead of being returned for reuse",
            ));
        }
        if !self.queue.is_empty() {
            return Err(IoError::new(
                IoErrorCode::Unavailable,
                format!(
                    "pipeline client still has {} unacknowledged in-flight request(s); \
                     the transport is dropped instead of being returned for reuse, since \
                     recreating PipelineClient would reset the in-flight tracking state \
                     and misattribute late ACKs",
                    self.queue.len()
                ),
            ));
        }
        Ok(self.sender)
    }

    /// `kind`（[`FrameKind::Write`] / [`FrameKind::Flush`]）と `body` からフレームを
    /// 組み立てて送信する。ACK は待たない（TASK-12.2・#74。TASK-12.1 の `send(&Frame,
    /// ..)` を置き換える）。
    ///
    /// # フレームを呼び出し元が組み立てられない理由
    ///
    /// request id は [`SendQueue::register`] が初めて採番するため、呼び出し元が
    /// 送信前に完成したフレームを渡すことができない（[`crate::payload`] モジュール
    /// ドキュメント参照）。本メソッドが [`crate::payload::encode_request`] で id を
    /// 埋め込んだフレームを内部で組み立てる。
    ///
    /// 処理順（拒否したときはキューの状態を変えない。REPAIR-5・security.md
    /// 「不安全な設計」観点）:
    /// 1. すでに失効済み（[`Self::is_poisoned`]）なら [`IoErrorCode::Unavailable`]
    ///    を返す（トランスポートへは書き込まない）
    /// 2. `kind` が [`FrameKind::Write`] / [`FrameKind::Flush`] 以外
    ///    （[`FrameKind::Ack`] / [`FrameKind::FlushAck`] は応答フレームであり
    ///    対応する ACK が来ないため、未 ACK キューに載せると枠が解放されない。
    ///    IO-1 の未 ACK リクエスト追跡契約の対象外）なら
    ///    [`IoErrorCode::InvalidArgument`] を返す（[`ensure_trackable_frame_kind`]。
    ///    [`SendQueue::register`] も同じ検証を共有する）
    /// 3. [`SendQueue::ensure_can_register`] で未 ACK 件数の上限到達・id 採番の
    ///    溢れを検証する。不可なら [`IoErrorCode::ResourceExhausted`] を返す
    ///    （この時点ではトランスポートへ書き込まない）
    /// 4. [`SendQueue::peek_next_id`] で次に採番されるであろう id を覗き見て、
    ///    [`crate::payload::encode_request`] でフレームを組み立てる。この時点では
    ///    まだキューへ登録せず、トランスポートへも書き込まない。ペイロード形式の
    ///    検証（`Write` の body 長超過・`Flush` に body がある等）が失敗した場合は
    ///    [`SendOutcome::RejectedInvalidPayload`] としてそのエラーを返す
    /// 5. [`SendQueue::register`] で id を確保してキューへ登録する（送信前に
    ///    確保することで、送信結果が不明なエラーが起きても id を使い回さない）。
    ///    返った id が手順 4 で覗き見た id と一致しない場合（単一スレッド前提
    ///    〔`&mut self`〕のこの型では構造上起こらないはずの内部不整合）は、
    ///    誤ったペイロードを送らないよう登録を取り消して
    ///    [`IoErrorCode::Internal`] を返す
    /// 6. `sender.send_frame` でトランスポートへ書き出す。失敗した場合、
    ///    [`FrameSender::send_frame`] は「相手に届いていないことを保証しない」
    ///    契約であるため、届いた可能性を残したまま id を回収せず（キューの
    ///    エントリはそのまま残す）、[`Self::poisoned`] を立てて以降の送信を
    ///    すべて拒否し、エラーを返す
    ///
    /// `timeout` は 1 回の書き込みにそのまま渡す（ACK を待つものではない。
    /// REPAIR-5）。
    ///
    /// # 観測（TASK-12.1・#73 codex 指摘対応。P1・REPAIR-4）
    ///
    /// 呼び出しごとに結果種別（[`SendOutcome`]）を [`Self::metrics`] へ記録し、
    /// [`SendEvent`] として [`Self::observer`]（`observer` フィールド。[`Self::new`]
    /// の必須引数）へも通知する。上限到達
    /// （[`SendOutcome::RejectedResourceExhausted`]）・ペイロード形式違反
    /// （[`SendOutcome::RejectedInvalidPayload`]）・トランスポート失敗
    /// （[`SendOutcome::TransportFailure`]）も含め、すべての分岐を計上・通知する。
    /// 所要時間はトランスポートへ実際に書き込んだ呼び出し（成功・失敗の両方）に
    /// ついてのみ計測する（早期拒否はトランスポートを介さないため `Duration::ZERO`）。
    pub fn send(
        &mut self,
        kind: FrameKind,
        body: &[u8],
        timeout: IoTimeout,
    ) -> Result<InFlightRequest, IoError> {
        if self.poisoned {
            self.metrics
                .record(SendOutcome::RejectedPoisoned, Duration::ZERO);
            let err = IoError::new(
                IoErrorCode::Unavailable,
                "pipeline client is poisoned after an ambiguous send failure; reconnect required",
            );
            self.notify(kind, SendOutcome::RejectedPoisoned, Duration::ZERO, &err);
            return Err(err);
        }
        if let Err(err) = ensure_trackable_frame_kind(kind) {
            self.metrics
                .record(SendOutcome::RejectedInvalidFrameKind, Duration::ZERO);
            self.notify(
                kind,
                SendOutcome::RejectedInvalidFrameKind,
                Duration::ZERO,
                &err,
            );
            return Err(err);
        }
        if let Err(err) = self.queue.ensure_can_register() {
            self.metrics
                .record(SendOutcome::RejectedResourceExhausted, Duration::ZERO);
            self.notify(
                kind,
                SendOutcome::RejectedResourceExhausted,
                Duration::ZERO,
                &err,
            );
            return Err(err);
        }
        let peeked_id = match self.queue.peek_next_id() {
            Ok(id) => id,
            Err(err) => {
                self.metrics
                    .record(SendOutcome::RejectedResourceExhausted, Duration::ZERO);
                self.notify(
                    kind,
                    SendOutcome::RejectedResourceExhausted,
                    Duration::ZERO,
                    &err,
                );
                return Err(err);
            }
        };
        let frame = match payload::encode_request(kind, WireRequestId::from(peeked_id), body) {
            Ok(frame) => frame,
            Err(err) => {
                self.metrics
                    .record(SendOutcome::RejectedInvalidPayload, Duration::ZERO);
                self.notify(
                    kind,
                    SendOutcome::RejectedInvalidPayload,
                    Duration::ZERO,
                    &err,
                );
                return Err(err);
            }
        };
        let request = match self.queue.register(kind) {
            Ok(request) => request,
            Err(err) => {
                self.metrics
                    .record(SendOutcome::RejectedResourceExhausted, Duration::ZERO);
                self.notify(
                    kind,
                    SendOutcome::RejectedResourceExhausted,
                    Duration::ZERO,
                    &err,
                );
                return Err(err);
            }
        };
        if request.id() != peeked_id {
            // 単一スレッド前提（`&mut self`）のこの型では、手順 4（覗き見）と
            // 手順 5（登録）の間に他の呼び出しが割り込む余地はなく、構造上
            // 起こらないはずの内部不整合。とはいえ panic はせず（coding-rust）、
            // 誤ったペイロード（覗き見た id で組み立て済みのフレーム）を送って
            // しまう前に登録を取り消して拒否する。
            let _ = self.queue.remove(request.id());
            let err = IoError::new(
                IoErrorCode::Internal,
                "registered request id did not match the previously peeked id; \
                 refusing to send a frame built for a different id",
            );
            return Err(err);
        }
        let started_at = Instant::now();
        if let Err(err) = self.sender.send_frame(&frame, timeout) {
            // 送信結果が不明なため、request.id() をキューへ残したまま接続を
            // 失効させる（上記ドキュメンテーションコメント参照）。
            self.poisoned = true;
            let elapsed = started_at.elapsed();
            self.metrics.record(SendOutcome::TransportFailure, elapsed);
            self.notify(kind, SendOutcome::TransportFailure, elapsed, &err);
            return Err(err);
        }
        let elapsed = started_at.elapsed();
        self.metrics.record(SendOutcome::Success, elapsed);
        self.observer.on_send(&SendEvent {
            kind,
            outcome: SendOutcome::Success,
            latency: elapsed,
            error: None,
        });
        Ok(request)
    }

    /// [`Self::send`] の各失敗分岐から共通で呼び、[`SendEvent`]（失敗詳細つき）を
    /// [`Self::observer`] へ通知する（TASK-12.1・#73 codex 指摘対応。P1・REPAIR-4・
    /// REPAIR-5 P0 再指摘対応）。
    ///
    /// `err.message()` を借用のまま [`SendEventError::message`] へ渡し、複製しない
    /// （[`SendEvent`] のドキュメント参照）。呼び出し元（[`Self::send`]）はこの
    /// 呼び出しが返ったあとに `err` を返すため、借用は `on_send` の呼び出し中に
    /// 限られる契約と整合する。
    fn notify(&mut self, kind: FrameKind, outcome: SendOutcome, latency: Duration, err: &IoError) {
        self.observer.on_send(&SendEvent {
            kind,
            outcome,
            latency,
            error: Some(SendEventError {
                code: err.code(),
                message: err.message(),
            }),
        });
    }

    /// [`Self::recv_ack`] の各失敗分岐から共通で呼び、[`Self::ack_metrics`] へ記録
    /// したうえで [`AckEvent`]（失敗詳細つき）を [`Self::observer`] へ通知する
    /// （TASK-12.2・#74 codex 指摘対応。P1・REPAIR-4）。
    ///
    /// [`Self::notify`]（送信側）と対になる ACK 受信側の入口。`err.message()` を
    /// 借用のまま [`AckEventError::message`] へ渡し、複製しない
    /// （[`SendEvent`]・[`AckEvent`] のドキュメント参照）。
    ///
    /// `ack_kind` は呼び出し元が `crate::payload::decode_ack` で復号済みの種別を
    /// 渡す（未復号の早期拒否では `None`。[`AckEvent::ack_kind`] のドキュメント
    /// 参照。TASK-12.2・#74 codex P1 再指摘対応。IO-1・IO-2・REPAIR-4）。
    fn notify_ack(
        &mut self,
        outcome: AckOutcome,
        ack_kind: Option<FrameKind>,
        latency: Duration,
        err: &IoError,
    ) {
        self.ack_metrics.record(outcome, latency);
        self.observer.on_ack(&AckEvent {
            outcome,
            ack_kind,
            latency,
            error: Some(AckEventError {
                code: err.code(),
                message: err.message(),
            }),
        });
    }

    /// 検証済み ACK の request id で未 ACK 枠を解放する、メモリ内の低水準な入口
    /// （IO-1・TASK-12.1・#73 codex 再指摘対応。P1）。
    ///
    /// # 呼び出し元の責務
    ///
    /// 本メソッドは「渡された `id` が実在の未 ACK リクエストに対応するかどうか」
    /// （キューに存在するか・自分自身が発行元か）だけを検証し、ACK フレーム自体の
    /// 受信・デコード・送信順の照合は行わない。ワイヤー経路（トランスポートから
    /// 届く ACK フレーム）を扱う場合は [`Self::recv_ack`]（TASK-12.2・#74）を使う
    /// こと。本メソッドはテストや、すでに検証済みの id を直接扱いたい場合の
    /// 低水準な入口として残す。
    ///
    /// 未登録の id・すでに解放済み（二重 acknowledge）の id は
    /// [`IoErrorCode::InvalidArgument`] で拒否し、キューの状態を変更しない
    /// （二重解放の防止）。`self.poisoned` はここでは変更しない。失効済みの
    /// 接続でも、送信結果が不明なまま残っていたリクエストの遅延 ACK を
    /// 受け取ってキューを空にすることは許すが（後始末として無害）、接続自体は
    /// 引き続き失効したまま（[`Self::is_poisoned`]）で、新しい送信は拒否され続ける。
    pub fn acknowledge(&mut self, id: RequestId) -> Result<InFlightRequest, IoError> {
        self.queue.remove(id)
    }
}

impl<S, O> PipelineClient<S, O>
where
    S: FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>,
    O: SendObserver,
{
    /// トランスポートから ACK フレームを 1 つ受信し、送信順（[`SendQueue::oldest`]）
    /// で検証・対応付けしてから未 ACK 枠を解放する（IO-1・IO-2・TASK-12.2・#74）。
    ///
    /// # 送受信を同じ接続へ束ねる理由（TASK-12.2・#74 codex 再指摘対応。P0）
    ///
    /// 本メソッドは引数で任意の受信側を受け取らず、[`Self::new`] へ渡した送信用
    /// トランスポート（`self.sender`）自身から [`FrameReceiver::recv_frame`] で
    /// ACK を受信する（このため `S` は本 impl ブロックで [`FrameSender`] に加えて
    /// [`FrameReceiver`] も実装している必要がある）。以前の実装は
    /// `receiver: &mut R`（`S` とは無関係な任意のトランスポート）を引数に取って
    /// いたが、ワイヤー上の request id は各クライアントで `0` から独立に採番される
    /// （モジュール冒頭参照）ため、呼び出し元が誤って別接続（別
    /// [`PipelineClient`]）の受信側を渡すと、id と種別だけの照合を通過して
    /// 未 ACK 枠を誤って解放できてしまっていた。[`FrameKind::FlushAck`] の場合は
    /// 実際には永続化されていない書き込みを完了扱いにしてしまい、IO-2
    /// （フラッシュバリア保証）に反する。送受信を同じ接続オブジェクトへ束ねる
    /// ことで、この誤対応付けを型レベルで起こせなくする（`PipelineClient`
    /// 自体を送信側と受信側へ分ける API は引き続き範囲外〔モジュール冒頭「#74（TASK-12.2）
    /// 以降に残る範囲」参照〕で、本メソッドは単一スレッド前提〔`&mut self`〕の
    /// まま実装する）。
    ///
    /// # 処理順（拒否・失効時の分岐は fail-closed。security.md「不安全な設計」観点）
    ///
    /// 1. すでに失効済み（[`Self::is_poisoned`]）なら [`IoErrorCode::Unavailable`]
    ///    を返す（`self.sender.recv_frame` は一切呼ばない）
    /// 2. 未 ACK のリクエストが 1 件もなければ [`IoErrorCode::InvalidArgument`] を
    ///    返す（`self.sender.recv_frame` は呼ばない。待つ対象がない呼び出しの
    ///    誤りであり、プロトコル違反ではないため接続は失効させない）
    /// 3. `self.sender.recv_frame(timeout)` を呼ぶ。`Err` なら本メソッドが
    ///    [`Self::poisoned`] を立ててから、そのエラー（[`IoErrorCode::Timeout`] を
    ///    含む）をそのまま返す。[`FrameReceiver::recv_frame`] の契約
    ///    （P1-3・`crate::transport` モジュールドキュメント）により、エラーを
    ///    返した接続は以後使用不可であり、「まだ ACK が来ていないので再試行」
    ///    という意味を持たない。同じ接続でポーリングする使い方は想定しない
    /// 4. [`crate::payload::decode_ack`] でペイロードを検証する。失敗（種別違反・
    ///    長さ違反）したら失効させて [`IoErrorCode::InvalidArgument`] を返す
    ///    （プロトコル違反）
    /// 5. **送信順の照合（厳格）**: 受け取った request id が
    ///    [`SendQueue::oldest`] の id と一致しなければ失効させて
    ///    [`IoErrorCode::InvalidArgument`] を返す。id がキュー内には存在するが
    ///    最古ではない場合は "out-of-order ack"、キューのどこにも存在しない場合は
    ///    "unknown ack id" とメッセージを区別する（[`SendQueue`] は FIFO であり、
    ///    サーバー側は送信順に ACK を返す設計〔TASK-13.2〕を前提とする。順序が
    ///    入れ替わる必要が生じた場合は TASK-13 側で本方針を見直す）
    /// 6. 種別の対応を確かめる。[`FrameKind::Ack`] は [`FrameKind::Write`] に、
    ///    [`FrameKind::FlushAck`] は [`FrameKind::Flush`] に対応しなければ
    ///    ならない。ずれていれば失効させて [`IoErrorCode::InvalidArgument`] を返す
    /// 7. `crate::barrier::AckReceipt::from_matched` で種別ごとの
    ///    [`AckReceipt`]（[`AckReceipt::Write`] / [`AckReceipt::Flush`]）を
    ///    組み立ててから [`SendQueue::remove`] で自分のキューの id を使って
    ///    解放し、その [`AckReceipt`] を返す（[`crate::barrier`] モジュール
    ///    ドキュメント「構築経路」参照。TASK-15.1・#85）
    ///
    /// # IO-1・IO-2 の保証範囲の違い
    ///
    /// [`FrameKind::Ack`] は対応する書き込みがバッファリングされたことのみを
    /// 保証し（IO-1）、[`FrameKind::FlushAck`] はそのバリア以前に受理した
    /// すべての書き込みが永続化済みであることを保証する（IO-2）。本メソッドの
    /// 送信順照合はどちらの種別でも同じ規則（キュー先頭との一致）を使い、
    /// この保証範囲の違いと矛盾しない。戻り値の [`AckReceipt`] は
    /// [`AckReceipt::Write`]（[`crate::barrier::WriteAck`]）と
    /// [`AckReceipt::Flush`]（[`crate::barrier::FlushAck`]）を別バリアントとして
    /// 区別するため、呼び出し元がこの保証範囲の違いを取り違えることはできない
    /// （TASK-15.1・#85）。
    ///
    /// # 観測（TASK-12.2・#74 codex 指摘対応。P1・REPAIR-4）
    ///
    /// 呼び出しごとに結果種別（[`AckOutcome`]）を [`Self::ack_metrics`] へ記録し、
    /// [`AckEvent`] として [`Self::observer`]（`observer` フィールド。[`Self::new`]
    /// の必須引数）へも通知する。受信成功・タイムアウトを含むトランスポート失敗
    /// （[`AckOutcome::TransportFailure`]）・ペイロード形式違反
    /// （[`AckOutcome::RejectedInvalidPayload`]）・送信順照合違反
    /// （[`AckOutcome::RejectedOutOfOrder`]・[`AckOutcome::RejectedUnknownAckId`]）・
    /// 種別対応違反（[`AckOutcome::RejectedAckKindMismatch`]）も含め、すべての
    /// 分岐を計上・通知する。所要時間は `self.sender.recv_frame` を実際に呼び出した
    /// 呼び出し（成功・失敗の両方）に対して計測し、それより前の早期拒否
    /// （[`AckOutcome::RejectedPoisoned`]・[`AckOutcome::RejectedNoInFlight`]）は
    /// [`Duration::ZERO`] とする（[`Self::send`] の早期拒否と同じ扱い）。
    pub fn recv_ack(&mut self, timeout: IoTimeout) -> Result<AckReceipt, IoError> {
        if self.poisoned {
            let err = IoError::new(
                IoErrorCode::Unavailable,
                "pipeline client is poisoned after an ambiguous send failure; reconnect required",
            );
            self.notify_ack(AckOutcome::RejectedPoisoned, None, Duration::ZERO, &err);
            return Err(err);
        }
        if self.queue.is_empty() {
            let err = IoError::new(
                IoErrorCode::InvalidArgument,
                "recv_ack called with no in-flight requests to match against",
            );
            self.notify_ack(AckOutcome::RejectedNoInFlight, None, Duration::ZERO, &err);
            return Err(err);
        }

        let started_at = Instant::now();

        let frame = match self.sender.recv_frame(timeout) {
            Ok(frame) => frame,
            Err(err) => {
                // P1-3（`crate::transport` モジュールドキュメント）: エラーを
                // 返した接続はどんなエラーであれ以後使用不可。「まだ来ていない
                // だけ」という再試行の余地を残さない。
                self.poisoned = true;
                let elapsed = started_at.elapsed();
                self.notify_ack(AckOutcome::TransportFailure, None, elapsed, &err);
                return Err(err);
            }
        };

        let ack = match payload::decode_ack(&frame) {
            Ok(ack) => ack,
            Err(err) => {
                self.poisoned = true;
                let elapsed = started_at.elapsed();
                self.notify_ack(AckOutcome::RejectedInvalidPayload, None, elapsed, &err);
                return Err(err);
            }
        };

        // `is_empty` を上で確認済みだが、`oldest` は `Option` を返す契約のため
        // `unwrap`・`expect` は使わず `Result` 経由でフォールバックする
        // （coding-rust「ライブラリコードでは panic させない」）。到達しない
        // はずの経路でも `Internal` として安全側に倒す。
        let oldest = match self.queue.oldest().copied() {
            Some(oldest) => oldest,
            None => {
                self.poisoned = true;
                let elapsed = started_at.elapsed();
                let err = IoError::new(
                    IoErrorCode::Internal,
                    "in-flight queue became empty between the emptiness check and oldest() lookup",
                );
                self.notify_ack(
                    AckOutcome::RejectedInternal,
                    Some(ack.kind()),
                    elapsed,
                    &err,
                );
                return Err(err);
            }
        };

        if oldest.id().get() != ack.id().get() {
            self.poisoned = true;
            let elapsed = started_at.elapsed();
            let is_known_but_not_oldest = self
                .queue
                .iter()
                .any(|entry| entry.id().get() == ack.id().get());
            let (outcome, message) = if is_known_but_not_oldest {
                (
                    AckOutcome::RejectedOutOfOrder,
                    format!(
                        "out-of-order ack: received ack for request id {}, but the oldest \
                         unacknowledged request id is {}",
                        ack.id().get(),
                        oldest.id().get()
                    ),
                )
            } else {
                (
                    AckOutcome::RejectedUnknownAckId,
                    format!(
                        "unknown ack id: received ack for request id {}, which is not among \
                         the {} in-flight request(s) tracked by this queue",
                        ack.id().get(),
                        self.queue.len()
                    ),
                )
            };
            let err = IoError::new(IoErrorCode::InvalidArgument, message);
            self.notify_ack(outcome, Some(ack.kind()), elapsed, &err);
            return Err(err);
        }

        let expected_ack_kind = match oldest.kind() {
            FrameKind::Write => FrameKind::Ack,
            FrameKind::Flush => FrameKind::FlushAck,
            // `SendQueue::register`（`ensure_trackable_frame_kind` 経由）は
            // `Write`/`Flush` 以外を受理しないため到達しないが、`unwrap`・
            // `expect` を避け、フォールバックとして安全側（拒否）に倒す。
            FrameKind::Ack | FrameKind::FlushAck => {
                self.poisoned = true;
                let elapsed = started_at.elapsed();
                let err = IoError::new(
                    IoErrorCode::Internal,
                    "in-flight request has a non-trackable frame kind; this must not happen",
                );
                self.notify_ack(
                    AckOutcome::RejectedInternal,
                    Some(ack.kind()),
                    elapsed,
                    &err,
                );
                return Err(err);
            }
        };
        if ack.kind() != expected_ack_kind {
            self.poisoned = true;
            let elapsed = started_at.elapsed();
            let err = IoError::new(
                IoErrorCode::InvalidArgument,
                format!(
                    "ack kind mismatch: request id {} was sent as {:?} but the ack frame kind is {:?}",
                    oldest.id().get(),
                    oldest.kind(),
                    ack.kind()
                ),
            );
            self.notify_ack(
                AckOutcome::RejectedAckKindMismatch,
                Some(ack.kind()),
                elapsed,
                &err,
            );
            return Err(err);
        }

        // `AckReceipt` を `SendQueue::remove`（枠の解放）より前に組み立てる。
        // ここまでの検証（`expected_ack_kind` との一致）により
        // `AckReceipt::from_matched` が `Err` を返すことは到達しないはずだが、
        // 万一そうなった場合でもまだ枠を解放していない状態で拒否できる
        // （fail-closed。TASK-15.1・#85 セキュリティ考慮・IO-2 のデータ損失防止）。
        let receipt = match AckReceipt::from_matched(oldest, ack.kind()) {
            Ok(receipt) => receipt,
            Err(err) => {
                self.poisoned = true;
                let elapsed = started_at.elapsed();
                self.notify_ack(
                    AckOutcome::RejectedInternal,
                    Some(ack.kind()),
                    elapsed,
                    &err,
                );
                return Err(err);
            }
        };

        // 戻り値は `oldest` から組み立てた `receipt` を使うため、`remove` の
        // 戻り値そのものは枠を解放した事実の確認以上の意味を持たない
        // （`remove` は id 一致のみを検証し、`oldest` と同一エントリを返す契約）。
        if let Err(err) = self.queue.remove(oldest.id()) {
            let elapsed = started_at.elapsed();
            self.notify_ack(
                AckOutcome::RejectedInternal,
                Some(ack.kind()),
                elapsed,
                &err,
            );
            return Err(err);
        }
        let elapsed = started_at.elapsed();
        self.ack_metrics.record(AckOutcome::Success, elapsed);
        self.observer.on_ack(&AckEvent {
            outcome: AckOutcome::Success,
            ack_kind: Some(ack.kind()),
            latency: elapsed,
            error: None,
        });
        Ok(receipt)
    }

    /// [`Self::send`] の薄いラッパーで、[`FrameKind::Flush`] フレームを送信する
    /// （IO-2・TASK-15.1・#85）。
    ///
    /// body は常に空（`Flush` に body を渡すと `payload::encode_request` が
    /// 拒否する。`docs/design/io-protocol.md` のペイロード形式と整合）。観測・
    /// 計上・失効の扱いは [`Self::send`] と同一。成功時は発行済みリクエストを
    /// [`FlushBarrier`] へ包んで返し、呼び出し元は対応する
    /// [`crate::barrier::FlushAck::barrier`] と突き合わせて、待っていた
    /// バリアの ACK であることを確認できる。
    ///
    /// [`Self::send`] が返す [`InFlightRequest`] は種別 `Flush` で登録済みの
    /// ため、[`FlushBarrier::try_from`] の変換が失敗することは構造上ない。
    /// とはいえ `unwrap`・`expect` は使わず、万一失敗した場合は
    /// [`IoErrorCode::Internal`] として返す（panic させない。coding-rust）。
    pub fn flush(&mut self, timeout: IoTimeout) -> Result<FlushBarrier, IoError> {
        let request = self.send(FrameKind::Flush, &[], timeout)?;
        FlushBarrier::try_from(request).map_err(|_| {
            IoError::new(
                IoErrorCode::Internal,
                "PipelineClient::send(Flush) returned a request whose kind is not Flush; \
                 this must not happen",
            )
        })
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

    /// テスト専用のモック sender。送信したフレームを記録し、常に成功する。
    ///
    /// `recv_script`・`recv_call_count` は [`FrameReceiver`] 実装用（TASK-12.2・#74
    /// codex 再指摘対応。P0）: `recv_ack` が「送信に使うのと同じ接続オブジェクト」
    /// からしか ACK を受信できなくなった（[`PipelineClient::recv_ack`] 参照）ため、
    /// テストでも送信・受信を同じモック型に持たせる。台本が空なら常に
    /// `Timeout` を返す（[`ScriptedReceiver`] と同じ挙動）。
    #[derive(Debug, Default)]
    struct RecordingSender {
        sent: Vec<Frame>,
        recv_script: VecDeque<Result<Frame, IoError>>,
        recv_call_count: usize,
    }

    impl RecordingSender {
        fn recv_call_count(&self) -> usize {
            self.recv_call_count
        }
    }

    impl FrameSender for RecordingSender {
        type Frame = Frame;

        fn send_frame(&mut self, frame: &Self::Frame, _timeout: IoTimeout) -> Result<(), IoError> {
            self.sent.push(frame.clone());
            Ok(())
        }
    }

    impl FrameReceiver for RecordingSender {
        type Frame = Frame;

        fn recv_frame(&mut self, _timeout: IoTimeout) -> Result<Self::Frame, IoError> {
            self.recv_call_count += 1;
            match self.recv_script.pop_front() {
                Some(result) => result,
                None => Err(IoError::new(
                    IoErrorCode::Timeout,
                    "recording sender recv script exhausted",
                )),
            }
        }
    }

    /// テスト専用のモック sender。常に `Timeout` を返す。
    ///
    /// 現行仕様（TASK-12.1・#73 codex 指摘対応）: `send_frame` が失敗しても
    /// [`SendQueue::register`] はすでに送信前に id を確保済みのため、失敗した
    /// リクエストの枠はキューに残ったまま回収されず、[`PipelineClient`] は
    /// 失効（poison）して以降の送信をすべて拒否する（「登録しない」わけではなく
    /// 「登録済みの枠を回収せずクライアントごと失効させる」）。
    #[derive(Debug, Default)]
    struct AlwaysTimeoutSender;

    impl FrameSender for AlwaysTimeoutSender {
        type Frame = Frame;

        fn send_frame(&mut self, _frame: &Self::Frame, _timeout: IoTimeout) -> Result<(), IoError> {
            Err(IoError::new(IoErrorCode::Timeout, "mock always times out"))
        }
    }

    /// テスト専用のモック sender。最初の `send_frame` 呼び出しだけ `Timeout` を
    /// 返し、以降は成功する実装だが、現行仕様（TASK-12.1・#73 codex 指摘対応）では
    /// 1 回目の失敗で [`PipelineClient`] が失効（poison）するため、2 回目以降が
    /// 実際に呼ばれることはない（失効後の送信はトランスポートへ届く前に拒否される。
    /// `io1_pipeline_client_reserves_id_before_send_and_does_not_reuse_after_poison`
    /// 参照）。1 回目の失敗で確保した id が、失効した接続をまたいで使い回されない
    /// ことを確認するために使う。呼ばれない想定の 2 回目以降の送信内容は
    /// 検証対象ではないため、送信済みフレームを記録するフィールドは持たない。
    #[derive(Debug, Default)]
    struct FailOnceSender {
        failed_once: bool,
    }

    impl FrameSender for FailOnceSender {
        type Frame = Frame;

        fn send_frame(&mut self, _frame: &Self::Frame, _timeout: IoTimeout) -> Result<(), IoError> {
            if !self.failed_once {
                self.failed_once = true;
                return Err(IoError::new(IoErrorCode::Timeout, "mock times out once"));
            }
            Ok(())
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
        let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

        let mut ids = Vec::new();
        let mut requests = Vec::new();
        for byte in [10u8, 20, 30] {
            let request = client
                .send(FrameKind::Write, &[byte], test_timeout())
                .expect("send must succeed while under the limit");
            ids.push(request.id().get());
            requests.push(request);
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

        // `into_inner` は未 ACK が残る限りトランスポートを返さない（#73 codex
        // レビュー指摘対応。P1）ため、送信済みバイト列を確認する前に、すべての
        // 枠を ACK 済み相当として解放しておく。
        for request in requests {
            client
                .acknowledge(request.id())
                .expect("removing an acknowledged id must succeed");
        }

        let sent_bytes: Vec<u8> = client
            .into_inner()
            .expect("healthy client with a drained queue must yield its transport")
            .sent
            .iter()
            .map(|frame| {
                payload::decode_request(frame)
                    .expect("frame must decode as a request")
                    .body()[0]
            })
            .collect();
        assert_eq!(sent_bytes, vec![10, 20, 30]);
    }

    /// IO-1・TASK-12.1（受け入れ条件の中核）: 上限に達すると `send` は
    /// `ResourceExhausted` を返し、トランスポートへは書き込まれない。
    #[test]
    fn io1_pipeline_client_rejects_when_limit_reached() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

        let first = client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect("1st send must succeed");
        let second = client
            .send(FrameKind::Write, &[2], test_timeout())
            .expect("2nd send must succeed");

        let err = client
            .send(FrameKind::Write, &[3], test_timeout())
            .expect_err("3rd send must be rejected once the limit is reached");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);

        assert_eq!(client.queue().len(), 2);
        assert!(client.queue().is_full());

        // `into_inner` は未 ACK が残る限りトランスポートを返さない（#73 codex
        // レビュー指摘対応。P1）ため、送信件数を確認する前に両方の枠を
        // ACK 済み相当として解放しておく。
        for request in [first, second] {
            client
                .acknowledge(request.id())
                .expect("removing an acknowledged id must succeed");
        }

        assert_eq!(
            client
                .into_inner()
                .expect("healthy client with a drained queue must yield its transport")
                .sent
                .len(),
            2
        );
    }

    /// IO-1・TASK-12.1: 満杯のあと 1 枠を解放すると次の送信が成功し、id は
    /// 単調増加を続ける。キューの順序は解放後も送信順を保つ。
    #[test]
    fn io1_pipeline_client_accepts_after_slot_released() {
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

        client
            .acknowledge(first.id())
            .expect("removing the released id must succeed");

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

    /// IO-1・TASK-12.1: 未登録の id を `remove` すると `InvalidArgument` を返し、
    /// キューの件数は変わらない（#74 では ACK〔untrusted〕由来の id がここへ来る）。
    #[test]
    fn io1_send_queue_remove_unknown_id_is_rejected() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut queue = SendQueue::new(limit);
        let registered = queue
            .register(FrameKind::Write)
            .expect("register must succeed while under the limit");

        // 同じキュー（同じ `queue_id`）で採番されていない `seq` を渡し、
        // 「発行元は自分自身だが未登録の seq」を再現する（発行元自体が異なる
        // ケースは `io1_send_queue_remove_rejects_id_from_another_queue` が担う）。
        let unknown_id = RequestId {
            queue_id: registered.id().queue_id,
            seq: 999,
        };
        let err = queue
            .remove(unknown_id)
            .expect_err("unknown id must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        assert_eq!(queue.len(), 1);
    }

    /// IO-1・TASK-12.1（#73 codex 再指摘対応。P1）: 別の [`SendQueue`] が発行した
    /// [`RequestId`]（連番の数値としては自分のキューにも存在しうる値）を渡すと、
    /// `queue_id` の不一致により `InvalidArgument` で拒否され、キューの状態は
    /// 変わらない。数値だけを見て解放してしまう codex 指摘の再現テスト。
    #[test]
    fn io1_send_queue_remove_rejects_id_from_another_queue() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut queue_a = SendQueue::new(limit);
        let mut queue_b = SendQueue::new(limit);

        let a_request = queue_a
            .register(FrameKind::Write)
            .expect("queue_a register must succeed");
        let b_request = queue_b
            .register(FrameKind::Write)
            .expect("queue_b register must succeed");
        // 両キューとも `0` から独立に採番するため、連番の数値は同値になる。
        assert_eq!(a_request.id().get(), b_request.id().get());

        let err = queue_a
            .remove(b_request.id())
            .expect_err("id issued by another queue must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        assert!(
            err.message().contains("another queue"),
            "unexpected message: {}",
            err.message()
        );
        assert_eq!(queue_a.len(), 1, "queue_a's entry must remain untouched");

        queue_a
            .remove(a_request.id())
            .expect("queue_a's own id must still be removable");
        assert_eq!(queue_a.len(), 0);
    }

    /// IO-1・TASK-12.1（#73 codex 指摘対応。P2）: `SendQueue::register` は
    /// [`FrameKind::Ack`] / [`FrameKind::FlushAck`] を `InvalidArgument` で拒否し、
    /// キューの件数（採番済み id の枠）を増やさない。これらは応答フレームで対応する
    /// ACK が来ないため、登録を許すと未 ACK キューの枠が占有されたまま解放されない
    /// （[`PipelineClient::send`] の種別検証と同じ [`ensure_trackable_frame_kind`] を
    /// 共有する）。
    #[test]
    fn io1_send_queue_register_rejects_response_frame_kinds() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut queue = SendQueue::new(limit);

        let ack_err = queue
            .register(FrameKind::Ack)
            .expect_err("Ack must be rejected as a trackable frame kind");
        assert_eq!(ack_err.code(), IoErrorCode::InvalidArgument);
        assert_eq!(queue.len(), 0, "rejected Ack must not occupy a slot");

        let flush_ack_err = queue
            .register(FrameKind::FlushAck)
            .expect_err("FlushAck must be rejected as a trackable frame kind");
        assert_eq!(flush_ack_err.code(), IoErrorCode::InvalidArgument);
        assert_eq!(queue.len(), 0, "rejected FlushAck must not occupy a slot");

        // 拒否後も採番カウンタは進んでいないため、次に許可される種別を登録すると
        // id は 0 から始まる（拒否がキューの内部状態を変更していないことの確認）。
        let accepted = queue
            .register(FrameKind::Write)
            .expect("Write must still be accepted after rejected registrations");
        assert_eq!(accepted.id().get(), 0);
        assert_eq!(queue.len(), 1);
    }

    /// IO-1・TASK-12.1（#73 codex 指摘対応）: トランスポートへの書き込みが失敗した
    /// 場合、`send_frame` は「相手に届いていないことを保証しない」契約であるため、
    /// 確保済みの id はキューに残したまま回収せず、クライアントを失効
    /// （[`PipelineClient::is_poisoned`]）させる。失効後の送信はすべて
    /// `Unavailable` になり、id を再利用しない。
    #[test]
    fn io1_pipeline_client_poisons_on_transport_error() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(AlwaysTimeoutSender, limit, NoopSendObserver);

        let err = client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect_err("transport failure must propagate");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        // 送信結果が不明なため id `0` の枠はキューに残ったままになる。
        assert_eq!(client.queue().len(), 1);
        assert!(client.is_poisoned());

        // 失効後は再送を試みても id を再利用せず、常に `Unavailable` を返す。
        let err = client
            .send(FrameKind::Write, &[2], test_timeout())
            .expect_err("poisoned client must reject further sends");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
        assert_eq!(client.queue().len(), 1);
    }

    /// IO-1・TASK-12.1（#73 codex 指摘対応。P1）: 失効（[`PipelineClient::is_poisoned`]）
    /// したクライアントの [`PipelineClient::into_inner`] は `Unavailable` を返し、
    /// トランスポートを呼び出し元へ渡さずに drop する。呼び出し元がこの sender を
    /// 使って [`PipelineClient::new`] を作り直し、id を `0` から再開して遅延 ACK を
    /// 誤対応付けする経路を塞ぐ。
    #[test]
    fn io1_pipeline_client_into_inner_rejects_poisoned() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(AlwaysTimeoutSender, limit, NoopSendObserver);

        client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect_err("transport failure must propagate");
        assert!(client.is_poisoned());

        let err = client
            .into_inner()
            .expect_err("poisoned client must not yield its transport for reuse");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
    }

    /// IO-1・TASK-12.1（#73 codex レビュー指摘対応。P1）: `poisoned` が `false` でも、
    /// 未 ACK のリクエストが残ったままの [`PipelineClient::into_inner`] は
    /// `Unavailable` を返し、トランスポートを渡さない。返してしまうと、呼び出し元が
    /// その sender で新しい `PipelineClient::new` を作り直せてしまい、未 ACK キュー・
    /// `next_id` が空・`0` に巻き戻って、後から届く旧リクエストの ACK が新しい
    /// リクエストへ誤対応付けされたり、ACK 未受信のまま実質的に `InFlightLimit` を
    /// 超えて送信を継続できたりする。
    #[test]
    fn io1_pipeline_client_into_inner_rejects_unacked_requests() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

        client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect("send must succeed while under the limit");
        assert!(!client.is_poisoned());
        assert_eq!(client.queue().len(), 1);

        let err = client
            .into_inner()
            .expect_err("client with unacknowledged requests must not yield its transport");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
    }

    /// IO-1・TASK-12.1（#73 codex レビュー指摘対応。P1 の回帰確認）: 送信済みの
    /// リクエストがすべて `acknowledge`（#74 の ACK 処理が呼ぶ想定の入口）で
    /// 解放され、未 ACK 件数が `0` に戻っていれば `into_inner` は通常どおり
    /// トランスポートを返す（不要に厳しくなっていないことの確認）。
    #[test]
    fn io1_pipeline_client_into_inner_accepts_when_queue_drained() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

        let request = client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect("send must succeed while under the limit");
        client
            .acknowledge(request.id())
            .expect("removing the acknowledged id must succeed");
        assert!(client.queue().is_empty());

        client
            .into_inner()
            .expect("client with a drained queue must yield its transport");
    }

    /// IO-1・TASK-12.1（#73 codex 指摘対応）: 送信前に id を確保するため、1 回目の
    /// 失敗で確保した id（`0`）は失効した接続に残り続け、新しい接続（新しい
    /// `PipelineClient`）でのみ id `0` から採番が再開されることを確認する
    /// （失効した接続をまたいで id が使い回されないことの確認）。
    #[test]
    fn io1_pipeline_client_reserves_id_before_send_and_does_not_reuse_after_poison() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(FailOnceSender::default(), limit, NoopSendObserver);

        let first_attempt = client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect_err("1st attempt must fail via the mock sender");
        assert_eq!(first_attempt.code(), IoErrorCode::Timeout);
        assert!(client.is_poisoned());
        // 確保済みの id `0` はキューに残ったまま（送信結果が不明なため回収しない）。
        assert_eq!(client.queue().len(), 1);
        assert_eq!(
            client
                .queue()
                .oldest()
                .expect("one entry must remain")
                .id()
                .get(),
            0
        );

        // 失効した接続では id を再利用できない（Unavailable で拒否される）。
        let err = client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect_err("poisoned client must reject further sends");
        assert_eq!(err.code(), IoErrorCode::Unavailable);

        // 新しい接続（新しい `PipelineClient`）でのみ id `0` から採番が再開される。
        let mut fresh_client =
            PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);
        let request = fresh_client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect("a fresh connection must succeed");
        assert_eq!(request.id().get(), 0);
        assert_eq!(fresh_client.queue().len(), 1);
    }

    /// IO-1・TASK-12.1（#73 codex 指摘対応）: `send` は `Write`・`Flush` 以外の
    /// フレーム種別（`Ack`・`FlushAck`）を拒否する。応答フレームを未 ACK キューへ
    /// 登録すると、対応する ACK が来ないため枠が解放されないままになる。
    #[test]
    fn io1_pipeline_client_rejects_response_frame_kinds() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

        let err = client
            .send(FrameKind::Ack, &[], test_timeout())
            .expect_err("Ack frames must not be trackable as in-flight requests");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        assert_eq!(client.queue().len(), 0);

        let err = client
            .send(FrameKind::FlushAck, &[], test_timeout())
            .expect_err("FlushAck frames must not be trackable as in-flight requests");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        assert_eq!(client.queue().len(), 0);
        assert_eq!(
            client
                .into_inner()
                .expect("healthy client must yield its transport")
                .sent
                .len(),
            0
        );
    }

    /// IO-1・TASK-12.1: id の採番が `u64` の範囲を超える場合は `ResourceExhausted`
    /// を返し、トランスポートへは書き込まれない。
    #[test]
    fn io1_send_queue_rejects_id_overflow() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);
        // `pub(crate)` ではなく `#[cfg(test)]` の内部ヘルパーで直接キューの状態を
        // 書き換え、`u64::MAX` からの採番がオーバーフローを起こす境界を再現する。
        client.queue.set_next_id_for_test(u64::MAX);

        let err = client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect_err("id overflow must be rejected");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
        assert_eq!(
            client
                .into_inner()
                .expect("healthy client must yield its transport")
                .sent
                .len(),
            0
        );
    }

    /// TASK-12.1（#73 codex 再指摘対応。P1）: [`QueueId::allocate`] はカウンタが
    /// `u64::MAX` に達していると `ResourceExhausted` を返し、カウンタの値は
    /// `u64::MAX` のまま変わらない（`try_update` が失敗時に状態を変更しない
    /// 契約により、以降の呼び出しもすべて同じエラーで拒否され続けることを
    /// 確認する）。
    #[test]
    fn repair2_queue_id_allocate_rejects_counter_overflow() {
        let counter = AtomicU64::new(u64::MAX);

        let err = QueueId::allocate(&counter).expect_err("u64::MAX must reject allocation");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);

        // カウンタが変化していないため、続けて呼んでも同じエラーで拒否され続ける
        // （id を巻き戻して重複させることがないことの確認）。
        let err_again =
            QueueId::allocate(&counter).expect_err("repeated allocation must still fail");
        assert_eq!(err_again.code(), IoErrorCode::ResourceExhausted);
    }

    /// IO-1・TASK-12.1（#73 codex 再指摘対応。P1）: `queue_id` の採番カウンタが
    /// 枯渇した [`SendQueue`]（[`SendQueue::new_exhausted_for_test`]）は
    /// `register` が常に `ResourceExhausted` を返し、未 ACK キューへ何も
    /// 積まない（枯渇したカウンタから重複した `QueueId` を割り当てて別の
    /// キューと衝突させるより、このキューを恒久的に使用不能にする設計の確認）。
    #[test]
    fn io1_send_queue_register_rejects_when_queue_id_exhausted() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut queue = SendQueue::new_exhausted_for_test(limit);

        let err = queue
            .register(FrameKind::Write)
            .expect_err("register must fail when the queue id counter is exhausted");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
        assert_eq!(queue.len(), 0);
    }

    fn assert_send<T: Send>() {}

    /// IO-1: `PipelineClient<RecordingSender>` は `Send` を満たす
    /// （`FrameSender: Send` の supertrait により自動的に成立する）。
    #[test]
    fn io1_pipeline_client_is_send() {
        assert_send::<PipelineClient<RecordingSender, NoopSendObserver>>();
    }

    /// TASK-12.1（#73 codex 指摘対応。P1・REPAIR-4）: 成功した送信は
    /// `SendMetrics::success_count` を増分し、`write_latency` の観測件数も
    /// 増える（早期拒否と異なりトランスポートへ実際に書き込むため）。
    #[test]
    fn repair4_send_metrics_counts_success_and_latency() {
        let limit = InFlightLimit::new(4).expect("4 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

        client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect("send must succeed while under the limit");
        client
            .send(FrameKind::Write, &[2], test_timeout())
            .expect("send must succeed while under the limit");

        let metrics = client.metrics();
        assert_eq!(metrics.success_count(), 2);
        assert_eq!(metrics.rejected_poisoned_count(), 0);
        assert_eq!(metrics.rejected_invalid_frame_kind_count(), 0);
        assert_eq!(metrics.rejected_resource_exhausted_count(), 0);
        assert_eq!(metrics.transport_failure_count(), 0);
        assert_eq!(metrics.write_latency().count(), 2);
    }

    /// TASK-12.1（#73 codex 指摘対応。P1・REPAIR-4）: 未 ACK 件数の上限到達で
    /// 拒否された送信は `rejected_resource_exhausted_count` を増分し、
    /// `write_latency` へは計上しない（トランスポートへ書き込んでいないため）。
    #[test]
    fn repair4_send_metrics_counts_resource_exhausted() {
        let limit = InFlightLimit::new(1).expect("1 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

        client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect("1st send must succeed");
        let err = client
            .send(FrameKind::Write, &[2], test_timeout())
            .expect_err("2nd send must be rejected once the limit is reached");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);

        let metrics = client.metrics();
        assert_eq!(metrics.success_count(), 1);
        assert_eq!(metrics.rejected_resource_exhausted_count(), 1);
        assert_eq!(metrics.write_latency().count(), 1);
    }

    /// TASK-12.1（#73 codex 指摘対応。P1・REPAIR-4）: トランスポート失敗
    /// （クライアントを失効させる分岐）は `transport_failure_count` を増分し、
    /// `write_latency` にも計上する（トランスポートへ実際に書き込んだため）。
    /// 失効後の拒否は `rejected_poisoned_count` を増分し、`write_latency` には
    /// 計上しない。
    #[test]
    fn repair4_send_metrics_counts_transport_failure_and_poisoned_rejection() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(AlwaysTimeoutSender, limit, NoopSendObserver);

        client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect_err("transport failure must propagate");
        client
            .send(FrameKind::Write, &[2], test_timeout())
            .expect_err("poisoned client must reject further sends");

        let metrics = client.metrics();
        assert_eq!(metrics.success_count(), 0);
        assert_eq!(metrics.transport_failure_count(), 1);
        assert_eq!(metrics.rejected_poisoned_count(), 1);
        assert_eq!(metrics.write_latency().count(), 1);
    }

    /// TASK-12.1（#73 codex 再指摘対応。P1・REPAIR-4・REPAIR-5）:
    /// [`PipelineClient::new`] に差し込んだ
    /// [`crate::observe::JsonLinesSendObserver`] が、成功・上限到達（早期拒否）の
    /// 2 件それぞれで 1 行ずつ JSON Lines をメモリ内にためる。`on_send` 自体は
    /// I/O をせず（REPAIR-5）、`observer_mut().drain_lines()` で呼び出し元が
    /// 取り出す。`metrics()` を明示的に読み出さなくても送信結果が観測できる
    /// ことを確認する（codex レビュー指摘の解消）。
    #[test]
    fn repair4_observer_buffers_json_lines_for_each_send_outcome() {
        use crate::observe::JsonLinesSendObserver;

        let limit = InFlightLimit::new(1).expect("1 must be valid");
        let observer = JsonLinesSendObserver::new();
        let mut client = PipelineClient::new(RecordingSender::default(), limit, observer);

        client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect("1st send must succeed under the limit");
        let err = client
            .send(FrameKind::Write, &[2], test_timeout())
            .expect_err("2nd send must be rejected once the limit is reached");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
        assert_eq!(
            err.message(),
            "send queue is full: 1 in-flight requests reached the limit of 1"
        );

        let lines = client.observer_mut().drain_lines();
        assert_eq!(lines.len(), 2, "expected one JSON line per send() call");
        assert!(
            lines[0].starts_with(
                "{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"ok\",\"latency_us\":"
            ) && lines[0].ends_with('}'),
            "unexpected success line: {}",
            lines[0]
        );
        assert_eq!(
            lines[1],
            "{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"error\",\
             \"reason\":\"rejected_resource_exhausted\",\"code\":\"RESOURCE_EXHAUSTED\",\
             \"message\":\"send queue is full: 1 in-flight requests reached the limit of 1\",\
             \"latency_us\":0}"
        );
    }

    /// TASK-12.1（#73 codex 指摘対応。P1・REPAIR-4）: 追跡対象外のフレーム種別
    /// （`Ack`・`FlushAck`）による拒否は `rejected_invalid_frame_kind_count` を
    /// 増分し、`write_latency` には計上しない。
    #[test]
    fn repair4_send_metrics_counts_invalid_frame_kind() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

        client
            .send(FrameKind::Ack, &[], test_timeout())
            .expect_err("Ack frames must not be trackable as in-flight requests");

        let metrics = client.metrics();
        assert_eq!(metrics.rejected_invalid_frame_kind_count(), 1);
        assert_eq!(metrics.write_latency().count(), 0);
    }

    /// TASK-12.1（#73 codex 指摘対応。P1・REPAIR-4）: 未観測の `LatencyStats` は
    /// `count` が `0` で `min`/`max`/`mean` が `None` になり、ヒストグラムは
    /// すべて `0` になる（#73 codex 再指摘対応。REPAIR-4・REPAIR-12）。
    #[test]
    fn repair4_latency_stats_defaults_to_empty() {
        let stats = LatencyStats::default();
        assert_eq!(stats.count(), 0);
        assert_eq!(stats.total(), Duration::ZERO);
        assert_eq!(stats.min(), None);
        assert_eq!(stats.max(), None);
        assert_eq!(stats.mean(), None);
        assert_eq!(*stats.histogram(), [0u64; LATENCY_HISTOGRAM_BUCKETS]);
    }

    /// REPAIR-4・REPAIR-12（#73。項目 K・M。コミット 2）: ヒストグラムの各バケット
    /// 境界（`0µs`・各境界の直前・直後・`Duration::MAX`）が、
    /// [`LATENCY_HISTOGRAM_BUCKETS`] のドキュメントどおりの区間
    /// （バケット `i` は `[2^(i-1), 2^i)`、バケット `0` は `[0, 1)`、最後の
    /// バケットは上限なし）に入ることを機械照合する。
    #[test]
    fn repair4_repair12_latency_stats_histogram_bucket_boundaries() {
        // `0µs` はバケット `0`（`[0, 1)`）。
        let mut zero = LatencyStats::default();
        zero.record(Duration::ZERO);
        assert_eq!(zero.histogram()[0], 1);
        assert_eq!(zero.count(), 1);

        // バケット `0`/`1` の境界の直後（`1µs`）、および続く `1`/`2` の境界の
        // 直前（`1µs`）・直後（`2µs`）。
        let mut boundary_1_2_before = LatencyStats::default();
        boundary_1_2_before.record(Duration::from_micros(1));
        assert_eq!(boundary_1_2_before.histogram()[1], 1);

        let mut boundary_1_2_after = LatencyStats::default();
        boundary_1_2_after.record(Duration::from_micros(2));
        assert_eq!(boundary_1_2_after.histogram()[2], 1);

        // 最後から 2 番目のバケット（`23`。`[2^22, 2^23)`）の直前（`2^23 - 1`）は
        // バケット `23` のまま、直後（`2^23`）は上限なしの最後のバケット（`24`）
        // へ入る。この境界が「`MAX_IO_TIMEOUT`（10 秒 = 10,000,000µs）を超える
        // 値は最後のバケットに入る」という [`LATENCY_HISTOGRAM_BUCKETS`] の契約の
        // 核心（`2^23 = 8_388_608 < 10_000_000` のため、10 秒を超える値は必ず
        // このバケットより後ろ、つまり最後のバケットに入る）。
        let last_finite_upper_bound = 1u64 << (LATENCY_HISTOGRAM_BUCKETS - 2);
        let mut just_below_last = LatencyStats::default();
        just_below_last.record(Duration::from_micros(last_finite_upper_bound - 1));
        assert_eq!(
            just_below_last.histogram()[LATENCY_HISTOGRAM_BUCKETS - 2],
            1
        );

        let mut at_last_boundary = LatencyStats::default();
        at_last_boundary.record(Duration::from_micros(last_finite_upper_bound));
        assert_eq!(
            at_last_boundary.histogram()[LATENCY_HISTOGRAM_BUCKETS - 1],
            1
        );

        // `MAX_IO_TIMEOUT`（10 秒）を超える値・`Duration::MAX` も最後のバケットへ入る。
        let mut over_max_io_timeout = LatencyStats::default();
        over_max_io_timeout.record(crate::transport::MAX_IO_TIMEOUT + Duration::from_secs(1));
        assert_eq!(
            over_max_io_timeout.histogram()[LATENCY_HISTOGRAM_BUCKETS - 1],
            1
        );

        let mut duration_max = LatencyStats::default();
        duration_max.record(Duration::MAX);
        assert_eq!(duration_max.histogram()[LATENCY_HISTOGRAM_BUCKETS - 1], 1);
        assert_eq!(duration_max.count(), 1);
    }

    /// REPAIR-4・REPAIR-12（#73。項目 K・M）: `bucket_upper_bound_micros` は
    /// バケット `0` からバケット `LATENCY_HISTOGRAM_BUCKETS - 2` までは
    /// `2^index` を返し、最後のバケット（上限なし）と範囲外の `index` は
    /// どちらも `None` を返す。
    #[test]
    fn repair4_repair12_latency_stats_bucket_upper_bound_micros_boundaries() {
        assert_eq!(LatencyStats::bucket_upper_bound_micros(0), Some(1));
        assert_eq!(LatencyStats::bucket_upper_bound_micros(1), Some(2));
        assert_eq!(
            LatencyStats::bucket_upper_bound_micros(LATENCY_HISTOGRAM_BUCKETS - 2),
            Some(1u64 << (LATENCY_HISTOGRAM_BUCKETS - 2))
        );
        assert_eq!(
            LatencyStats::bucket_upper_bound_micros(LATENCY_HISTOGRAM_BUCKETS - 1),
            None,
            "the last bucket has no upper bound"
        );
        assert_eq!(
            LatencyStats::bucket_upper_bound_micros(LATENCY_HISTOGRAM_BUCKETS),
            None,
            "an out-of-range index must not panic and must be treated the same as \
             the open-ended last bucket"
        );
    }

    /// REPAIR-4・REPAIR-12（#73。項目 K・M）: ヒストグラムの各バケットは
    /// `saturating_add` で増分するため、`u64::MAX` に達したバケットへさらに
    /// 記録してもオーバーフローで `0` へ巻き戻らない（無制限リソース消費とは
    /// 別種の不変条件だが、カウンタの巻き戻りによる観測値の誤りを防ぐ）。
    #[test]
    fn repair4_repair12_latency_stats_histogram_bucket_saturates() {
        let mut stats = LatencyStats {
            buckets: [u64::MAX; LATENCY_HISTOGRAM_BUCKETS],
            ..LatencyStats::default()
        };
        stats.record(Duration::ZERO);
        assert_eq!(
            stats.histogram()[0],
            u64::MAX,
            "bucket count must saturate rather than wrap to 0"
        );
    }

    // --- コミット 2（#73・受け入れ基準の機械照合。REPAIR-12）から追加したテスト ---

    /// テスト専用のモック sender。常に `1 MiB` の巨大なメッセージを持つ `Timeout`
    /// を返す（項目 E: `notify` が巨大メッセージを複製せず借用で渡すことの確認に
    /// 使う）。
    #[derive(Debug, Default)]
    struct HugeMessageTimeoutSender;

    /// `notify`（項目 A）が複製をなくす対象とする、ヒープ確保コストが無視できない
    /// メッセージ長（1 MiB）。
    const HUGE_MESSAGE_LEN: usize = 1024 * 1024;

    impl FrameSender for HugeMessageTimeoutSender {
        type Frame = Frame;

        fn send_frame(&mut self, _frame: &Self::Frame, _timeout: IoTimeout) -> Result<(), IoError> {
            Err(IoError::new(
                IoErrorCode::Timeout,
                "x".repeat(HUGE_MESSAGE_LEN),
            ))
        }
    }

    /// テスト専用の観測フック。`on_send` が受け取った `error.message` の
    /// アドレスと長さだけを記録する（項目 E）。生ポインタは `Send` ではないため
    /// `usize` として保持し、`SendObserver: Send` の制約を満たす。
    #[derive(Debug, Default)]
    struct PtrCapturingObserver {
        captured: Option<(usize, usize)>,
    }

    impl SendObserver for PtrCapturingObserver {
        fn on_send(&mut self, event: &SendEvent<'_>) {
            if let Some(error) = &event.error {
                self.captured = Some((error.message.as_ptr() as usize, error.message.len()));
            }
        }

        fn on_ack(&mut self, _event: &AckEvent<'_>) {}
    }

    /// 項目 E（#73 P0 再指摘対応。REPAIR-5・REPAIR-12）: `PipelineClient::notify`
    /// が `SendObserver::on_send` へ渡す `SendEventError::message` は、
    /// `PipelineClient::send` が最終的に返す `IoError::message()` と同じヒープ
    /// バッファを指す借用であり、複製されていないことを `ptr::eq` とアドレス・
    /// 長さの一致で照合する。複製が起きていれば、`IoError` の上限（1024 バイト）を超える 1 MiB の入力に対して
    /// このアドレス一致は成立しない。
    #[test]
    fn repair5_repair12_notify_borrows_error_message_without_copying_huge_message() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let observer = PtrCapturingObserver::default();
        let mut client = PipelineClient::new(HugeMessageTimeoutSender, limit, observer);

        let err = client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect_err("the mock sender always fails");
        // #1116: `IoError::new` が 1 MiB を上限へ切り詰める。
        assert_eq!(err.message().len(), crate::MAX_IO_ERROR_MESSAGE_BYTES);
        assert!(err.message_truncated());

        let (captured_addr, captured_len) = client
            .observer()
            .captured
            .expect("a transport failure must notify the observer with an error");
        assert_eq!(
            captured_len,
            err.message().len(),
            "on_send must observe the same message length as the returned error"
        );
        assert!(
            std::ptr::eq(captured_addr as *const u8, err.message().as_ptr()),
            "on_send must observe the same heap buffer as the returned error, not a copy"
        );
    }

    /// 項目 G（REPAIR-12）: `SendQueue::remaining` は空のとき上限件数を、満杯の
    /// ときは `0` を返す（`is_full`・`len` と矛盾しないことの機械照合）。
    #[test]
    fn io1_repair12_send_queue_remaining_boundaries() {
        let limit = InFlightLimit::new(3).expect("3 must be valid");
        let mut queue = SendQueue::new(limit);
        assert_eq!(queue.remaining(), 3);
        assert!(!queue.is_full());

        for _ in 0..3 {
            queue
                .register(FrameKind::Write)
                .expect("register must succeed while under the limit");
        }

        assert_eq!(queue.remaining(), 0);
        assert!(queue.is_full());
    }

    /// 項目 G（REPAIR-12）: `TryFrom<usize> for InFlightLimit` は `InFlightLimit::new`
    /// と同じ境界（`0`・`1`・`MAX_IN_FLIGHT_LIMIT`・`MAX_IN_FLIGHT_LIMIT + 1`）を
    /// 検証する。
    #[test]
    fn io1_repair12_in_flight_limit_try_from_boundaries() {
        let zero = InFlightLimit::try_from(0usize).expect_err("0 must be rejected via TryFrom");
        assert_eq!(zero.code(), IoErrorCode::InvalidArgument);

        let one = InFlightLimit::try_from(1usize).expect("1 must be accepted via TryFrom");
        assert_eq!(one.get(), 1);

        let upper = InFlightLimit::try_from(MAX_IN_FLIGHT_LIMIT)
            .expect("MAX_IN_FLIGHT_LIMIT must be accepted via TryFrom");
        assert_eq!(upper.get(), MAX_IN_FLIGHT_LIMIT);

        let over = InFlightLimit::try_from(MAX_IN_FLIGHT_LIMIT + 1)
            .expect_err("MAX_IN_FLIGHT_LIMIT + 1 must be rejected via TryFrom");
        assert_eq!(over.code(), IoErrorCode::InvalidArgument);
    }

    /// 項目 H（REPAIR-12）: 3 件以上登録した状態で中間の 1 件を解放しても、残りの
    /// エントリは送信順（`oldest`・`iter`）を保つ。
    #[test]
    fn io1_repair12_send_queue_remove_middle_preserves_order() {
        let limit = InFlightLimit::new(4).expect("4 must be valid");
        let mut queue = SendQueue::new(limit);

        let first = queue
            .register(FrameKind::Write)
            .expect("register 1st must succeed");
        let second = queue
            .register(FrameKind::Write)
            .expect("register 2nd must succeed");
        let third = queue
            .register(FrameKind::Write)
            .expect("register 3rd must succeed");

        queue
            .remove(second.id())
            .expect("removing the middle entry must succeed");

        assert_eq!(
            queue
                .oldest()
                .expect("the first entry must remain")
                .id()
                .get(),
            first.id().get()
        );
        let remaining_ids: Vec<u64> = queue.iter().map(|entry| entry.id().get()).collect();
        assert_eq!(remaining_ids, vec![first.id().get(), third.id().get()]);
    }

    /// 項目 I（REPAIR-12）: 失効（poison）後に `acknowledge` でキューを空にしても
    /// `is_poisoned` は `true` のままで、`into_inner` は `Unavailable`（poison 起因の
    /// メッセージ）を返す。後始末として無害だが接続自体は再利用できないという
    /// 契約（[`PipelineClient::acknowledge`]・[`PipelineClient::into_inner`] の
    /// ドキュメント参照）を機械照合する。
    #[test]
    fn io1_repair12_poisoned_client_stays_poisoned_after_draining_queue() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(AlwaysTimeoutSender, limit, NoopSendObserver);

        client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect_err("transport failure must poison the client");
        assert!(client.is_poisoned());

        let pending_id = client
            .queue()
            .oldest()
            .expect("one entry must remain after the failed send")
            .id();
        client
            .acknowledge(pending_id)
            .expect("draining the queue via a late ack must succeed");
        assert!(client.queue().is_empty());

        assert!(
            client.is_poisoned(),
            "poison must persist even after the queue is drained"
        );

        let err = client
            .into_inner()
            .expect_err("a poisoned client must not yield its transport even with an empty queue");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
        assert!(
            err.message().contains("poisoned"),
            "error must indicate the poisoned branch was hit, not the unacked-queue branch: {}",
            err.message()
        );
    }

    // --- TASK-12.2（#74）: ペイロード形式・ACK 受信のユニットテスト ---

    /// TASK-12.2・IO-1: `SendQueue::peek_next_id` はキューの状態を変更せずに
    /// 次の id を返す。`register` を呼んだ後の実際の id と一致する。
    #[test]
    fn io1_send_queue_peek_next_id_matches_next_register() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut queue = SendQueue::new(limit);

        let peeked = queue.peek_next_id().expect("peek must succeed");
        assert_eq!(peeked.get(), 0);
        assert_eq!(queue.len(), 0, "peek must not register anything");

        let registered = queue
            .register(FrameKind::Write)
            .expect("register must succeed");
        assert_eq!(registered.id(), peeked);

        let peeked_again = queue.peek_next_id().expect("peek must succeed again");
        assert_eq!(peeked_again.get(), 1);
    }

    /// TASK-12.2・IO-1: `Flush` に空でない body を渡すと `send` は
    /// `RejectedInvalidPayload`（`InvalidArgument`）で拒否し、キューへ登録しない。
    #[test]
    fn io1_send_rejects_invalid_payload_and_does_not_register() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

        let err = client
            .send(FrameKind::Flush, b"unexpected body", test_timeout())
            .expect_err("flush with a body must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        assert_eq!(client.queue().len(), 0);
        assert_eq!(client.metrics().rejected_invalid_payload_count(), 1);

        // 拒否後も採番カウンタは進んでいないため、id は 0 から始まる。
        let request = client
            .send(FrameKind::Flush, &[], test_timeout())
            .expect("a valid flush must still succeed after a rejected payload");
        assert_eq!(request.id().get(), 0);
    }

    /// TASK-12.2・IO-1: `recv_ack` は送信順に ACK を照合し、`AckReceipt` を返して
    /// キューの枠を解放する。
    #[test]
    fn io1_recv_ack_matches_oldest_and_releases_slot() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

        let request = client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect("send must succeed");

        let ack = payload::encode_ack(FrameKind::Ack, WireRequestId::from(request.id()))
            .expect("encode_ack must succeed");
        // `client` は同じモジュール内で定義されているため、テストから private
        // フィールド `sender` へ直接アクセスできる（send/recv を同じ接続へ束ねた
        // ことの確認のため、テスト専用の別経路は用意しない）。
        client.sender.recv_script.push_back(Ok(ack));

        let receipt = client
            .recv_ack(test_timeout())
            .expect("recv_ack must succeed");
        assert_eq!(receipt.request().id().get(), request.id().get());
        assert!(matches!(receipt, AckReceipt::Write(_)));
        assert!(client.queue().is_empty());
        assert!(!client.is_poisoned());
    }

    /// TASK-12.2・IO-1（REPAIR-5）: 台本が空なら `recv_ack` は `Timeout` を返して
    /// クライアントを失効させる。
    #[test]
    fn repair5_recv_ack_timeout_poisons_client() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);
        client
            .send(FrameKind::Write, &[1], test_timeout())
            .expect("send must succeed");

        // `recv_script` は空のまま（台本切れは常に `Timeout` を返す。
        // `RecordingSender::recv_frame` 参照）。
        let err = client
            .recv_ack(test_timeout())
            .expect_err("empty script must time out");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert!(client.is_poisoned());
    }

    /// TASK-12.2・IO-1: 未 ACK が 0 件のときの `recv_ack` は受信側に触れず
    /// `InvalidArgument` を返す。
    #[test]
    fn io1_recv_ack_rejects_empty_queue_without_calling_receiver() {
        let limit = InFlightLimit::new(2).expect("2 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit, NoopSendObserver);

        let err = client
            .recv_ack(test_timeout())
            .expect_err("recv_ack with an empty queue must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        assert_eq!(client.sender.recv_call_count(), 0);
        assert!(!client.is_poisoned());
    }
}
