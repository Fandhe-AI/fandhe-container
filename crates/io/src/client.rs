//! パイプライン送信クライアント（TASK-12・IO-1）の送信キュー本体（TASK-12.1・#73）。
//!
//! IO-1（確定）は「クライアントは ACK を待たずに書き込みリクエストを連続送信し、
//! サーバーはバッファリングした時点で ACK を返す」というプロトコルを定める。ACK を
//! 待たずに送り続けると未 ACK のリクエストが際限なく増えうるため、本モジュールは
//! 未 ACK 件数に上限を設けて追跡する送信キュー（[`SendQueue`]）と、それを使って
//! [`crate::transport::FrameSender`] へ橋渡しするクライアント（[`PipelineClient`]）を
//! 提供する。[`PipelineClient::send`] の成功・失敗カウントとレイテンシ分布は
//! [`SendMetrics`]（[`PipelineClient::metrics`] で参照）として観測できるほか、
//! 送信のたびに [`crate::observe::SendObserver`] へイベント通知する（既定は
//! [`NoopSendObserver`]。[`PipelineClient::with_observer`] で
//! [`crate::observe::JsonLinesSendObserver`] 等へ差し替えられる。`on_send` は
//! 送信経路から同期で呼ばれるためブロックする I/O をしてはならず
//! （REPAIR-5。[`crate::observe`] モジュールドキュメント参照）、
//! [`crate::observe::JsonLinesSendObserver`] はメモリ内にためるだけで、実際の
//! 書き出しは [`PipelineClient::observer_mut`] 経由で取り出した観測フックに対し
//! 呼び出し元が行う。base 側 AGENTS.md の可観測性要件・REPAIR-4）。
//!
//! # #74（TASK-12.2）との境界
//!
//! 本モジュールが持つのは「送信済みで ACK 未受信のリクエストを追跡する」ところと、
//! 検証済み ACK の request id を渡されたら未 ACK 枠を解放する入口
//! （[`PipelineClient::acknowledge`]）まで。次の範囲は #74（TASK-12.2）以降が担い、
//! ここでは実装しない（REPAIR-3。スタブの明示）:
//! - ACK フレームの受信・デコードと、request id との対応付け（検証した上で
//!   [`PipelineClient::acknowledge`] を呼ぶのは #74 の責務）
//! - タイムアウト付きの ACK 待ち・ブロッキング送信 API
//! - request id のワイヤー表現（ペイロード内レイアウト）。[`RequestId`] は
//!   クライアントがローカルに振る連番であり、ペイロードには含めない。
//!   [`RequestId`] が内部に持つ発行元キュー識別子（[`QueueId`]）もメモリ内の
//!   区別のみに使い、ワイヤー上のバイト表現には一切影響しない
//!   （TASK-12.1・#73 codex 再指摘対応。P1）
//!
//! 未フラッシュ滞留量（バイト数）の上限・自動フラッシュは IO-10（別タスク）の範囲。
//! 送信側と受信側をスレッド間で分割する API も #74 以降で扱い、本モジュールの
//! [`PipelineClient`] は `&mut self` を要求する単一スレッド前提の型として実装する。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::error::{IoError, IoErrorCode};
use crate::observe::{NoopSendObserver, SendEvent, SendEventError, SendObserver};
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
/// （[`AtomicU64::fetch_update`]）で進め、`u64` の範囲を超える採番を
/// [`IoErrorCode::ResourceExhausted`] として検出する。`u64::MAX` 個の
/// [`SendQueue`] を単一プロセス内で生成することは実用上起こり得ないが、
/// 万一そこへ到達しても値を巻き戻して重複させることはない（`fetch_update` は
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
    /// （`fetch_update` が失敗時にカウンタを変更しない契約を利用する）。
    fn allocate(counter: &AtomicU64) -> Result<Self, IoError> {
        counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
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
    /// トランスポートへの書き込みが失敗し、クライアントを失効させた。
    TransportFailure,
}

/// 所要時間の分布を件数・合計・最小・最大で集計する（TASK-12.1・#73 codex 指摘
/// 対応。P1・REPAIR-4）。
///
/// ヒストグラム等の詳細な分布は持たない軽量な集計であり、外部メトリクス基盤への
/// エクスポートも持たない（REPAIR-3。スタブの明示。詳細な分布・エクスポートは
/// 別タスクで拡張してよい）。[`SendMetrics`] が送信結果種別ごとに保持し、
/// [`PipelineClient::metrics`] 経由で読み出す。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LatencyStats {
    count: u64,
    total: Duration,
    min: Option<Duration>,
    max: Option<Duration>,
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
    /// `count` は内部カウンタであり untrusted な入力ではないが、`u32` への
    /// キャストで panic させないよう浮動小数点経由で計算する。
    pub fn mean(&self) -> Option<Duration> {
        if self.count == 0 {
            return None;
        }
        Some(Duration::from_secs_f64(
            self.total.as_secs_f64() / self.count as f64,
        ))
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

/// [`crate::transport::FrameSender`] と [`SendQueue`] を組み合わせ、パイプライン送信
/// （IO-1）のキュー管理付き送信 API を提供する（TASK-12.1）。
///
/// ACK の受信・対応付け・タイムアウト付き待機は持たない（#74。モジュール冒頭の
/// 「#74（TASK-12.2）との境界」を参照）。`&mut self` を要求し、単一スレッド前提
/// （[`crate::transport::FrameSender`] と同じ契約）。
#[derive(Debug)]
pub struct PipelineClient<S, O = NoopSendObserver>
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
    /// [`Self::send`] のたびに通知する送信イベントの観測フック（TASK-12.1・#73
    /// codex 指摘対応。P1・REPAIR-4）。既定は [`NoopSendObserver`]。
    observer: O,
}

impl<S> PipelineClient<S, NoopSendObserver>
where
    S: FrameSender<Frame = Frame>,
{
    /// トランスポートと未 ACK 件数上限からクライアントを作る（観測フックは
    /// [`NoopSendObserver`]。送信イベントを記録したい場合は [`Self::with_observer`] を使う）。
    pub fn new(sender: S, limit: InFlightLimit) -> Self {
        Self::with_observer(sender, limit, NoopSendObserver)
    }
}

impl<S, O> PipelineClient<S, O>
where
    S: FrameSender<Frame = Frame>,
    O: SendObserver,
{
    /// トランスポート・未 ACK 件数上限・送信イベントの観測フックからクライアントを
    /// 作る（TASK-12.1・#73 codex 指摘対応。P1・REPAIR-4）。
    ///
    /// `observer` には [`crate::observe::JsonLinesSendObserver`] 等、送信イベントを
    /// 記録する実装を渡せる。渡した観測フックは [`Self::observer_mut`] で
    /// 取り出せる。
    pub fn with_observer(sender: S, limit: InFlightLimit, observer: O) -> Self {
        Self {
            sender,
            queue: SendQueue::new(limit),
            poisoned: false,
            metrics: SendMetrics::default(),
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
    /// 送信の都度リアルタイムに出力したい場合は [`Self::with_observer`] で
    /// [`SendObserver`] を差し込む（本メソッドは呼び出し元が明示的に読み出す
    /// 集計値であり、送信のたびに自動で外部へ出力する経路ではない）。
    pub fn metrics(&self) -> &SendMetrics {
        &self.metrics
    }

    /// [`Self::with_observer`] で差し込んだ観測フックを参照する（TASK-12.1・#73
    /// codex 再指摘対応。P1・REPAIR-4）。
    pub fn observer(&self) -> &O {
        &self.observer
    }

    /// [`Self::with_observer`] で差し込んだ観測フックを可変参照で取り出す
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

    /// フレームを送信する。ACK は待たない。
    ///
    /// 処理順（トランスポートへ書き込む前に上限判定・id 確保を行う。REPAIR-5・
    /// security.md「不安全な設計」観点）:
    /// 1. すでに失効済み（[`Self::is_poisoned`]）なら [`IoErrorCode::Unavailable`]
    ///    を返す（トランスポートへは書き込まない）
    /// 2. `frame.kind()` が [`FrameKind::Write`] / [`FrameKind::Flush`] 以外
    ///    （[`FrameKind::Ack`] / [`FrameKind::FlushAck`] は応答フレームであり
    ///    対応する ACK が来ないため、未 ACK キューに載せると枠が解放されない。
    ///    IO-1 の未 ACK リクエスト追跡契約の対象外）なら
    ///    [`IoErrorCode::InvalidArgument`] を返す（[`ensure_trackable_frame_kind`]。
    ///    [`SendQueue::register`] も同じ検証を共有する）
    /// 3. 未 ACK 件数が上限に達していれば、あるいは id 採番が溢れるなら
    ///    [`IoErrorCode::ResourceExhausted`] を返す（この時点ではトランスポートへ
    ///    書き込まない）
    /// 4. [`SendQueue::register`] で id を先に確保してキューへ登録する（送信前に
    ///    確保することで、送信結果が不明なエラーが起きても id を使い回さない）
    /// 5. `sender.send_frame` でトランスポートへ書き出す。失敗した場合、
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
    /// [`SendEvent`] として [`Self::observer`]（`observer` フィールド。既定は
    /// [`NoopSendObserver`]）へも通知する。上限到達
    /// （[`SendOutcome::RejectedResourceExhausted`]）・トランスポート失敗
    /// （[`SendOutcome::TransportFailure`]）も含め、すべての分岐を計上・通知する。
    /// 所要時間はトランスポートへ実際に書き込んだ呼び出し（成功・失敗の両方）に
    /// ついてのみ計測する（早期拒否はトランスポートを介さないため `Duration::ZERO`）。
    pub fn send(&mut self, frame: &Frame, timeout: IoTimeout) -> Result<InFlightRequest, IoError> {
        let kind = frame.kind();
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
        let started_at = Instant::now();
        if let Err(err) = self.sender.send_frame(frame, timeout) {
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
    /// [`Self::observer`] へ通知する（TASK-12.1・#73 codex 指摘対応。P1・REPAIR-4）。
    fn notify(&mut self, kind: FrameKind, outcome: SendOutcome, latency: Duration, err: &IoError) {
        self.observer.on_send(&SendEvent {
            kind,
            outcome,
            latency,
            error: Some(SendEventError {
                code: err.code(),
                message: err.message().to_string(),
            }),
        });
    }

    /// 検証済み ACK の request id で未 ACK 枠を解放する（IO-1・TASK-12.1・#73
    /// codex 再指摘対応。P1）。
    ///
    /// # ACK 検証の責務（TASK-12.2・#74 との境界）
    ///
    /// ACK フレームの受信・デコード・ペイロード検証（request id が実在の未 ACK
    /// リクエストに対応するかを含む）は #74（TASK-12.2）の範囲で、本メソッドは
    /// その検証を行わない。契約は「呼び出し元がすでに検証済みの request id を
    /// 渡す」ことであり、#74 が受信した検証済み ACK の request id でこの API を
    /// 呼ぶ想定。現時点ではまだ ACK の受信・検証経路がないため、呼び出し元が
    /// 自分で ACK を解釈してこの API を呼ぶ（REPAIR-3。スタブの明示）。
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

    /// テスト専用のモック sender。最初の `send_frame` 呼び出しだけ `Timeout` を
    /// 返し、以降は成功する。同一クライアント上で「失敗 → 成功」の連続を再現し、
    /// 失敗した送信が id を消費していないことを確認するために使う。
    #[derive(Debug, Default)]
    struct FailOnceSender {
        failed_once: bool,
        sent: Vec<Frame>,
    }

    impl FrameSender for FailOnceSender {
        type Frame = Frame;

        fn send_frame(&mut self, frame: &Self::Frame, _timeout: IoTimeout) -> Result<(), IoError> {
            if !self.failed_once {
                self.failed_once = true;
                return Err(IoError::new(IoErrorCode::Timeout, "mock times out once"));
            }
            self.sent.push(frame.clone());
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
        let mut client = PipelineClient::new(RecordingSender::default(), limit);

        let mut ids = Vec::new();
        let mut requests = Vec::new();
        for byte in [10u8, 20, 30] {
            let request = client
                .send(&write_frame(byte), test_timeout())
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

        let first = client
            .send(&write_frame(1), test_timeout())
            .expect("1st send must succeed");
        let second = client
            .send(&write_frame(2), test_timeout())
            .expect("2nd send must succeed");

        let err = client
            .send(&write_frame(3), test_timeout())
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
        let mut client = PipelineClient::new(AlwaysTimeoutSender, limit);

        let err = client
            .send(&write_frame(1), test_timeout())
            .expect_err("transport failure must propagate");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        // 送信結果が不明なため id `0` の枠はキューに残ったままになる。
        assert_eq!(client.queue().len(), 1);
        assert!(client.is_poisoned());

        // 失効後は再送を試みても id を再利用せず、常に `Unavailable` を返す。
        let err = client
            .send(&write_frame(2), test_timeout())
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
        let mut client = PipelineClient::new(AlwaysTimeoutSender, limit);

        client
            .send(&write_frame(1), test_timeout())
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
        let mut client = PipelineClient::new(RecordingSender::default(), limit);

        client
            .send(&write_frame(1), test_timeout())
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
        let mut client = PipelineClient::new(RecordingSender::default(), limit);

        let request = client
            .send(&write_frame(1), test_timeout())
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
        let mut client = PipelineClient::new(FailOnceSender::default(), limit);

        let first_attempt = client
            .send(&write_frame(1), test_timeout())
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
            .send(&write_frame(1), test_timeout())
            .expect_err("poisoned client must reject further sends");
        assert_eq!(err.code(), IoErrorCode::Unavailable);

        // 新しい接続（新しい `PipelineClient`）でのみ id `0` から採番が再開される。
        let mut fresh_client = PipelineClient::new(RecordingSender::default(), limit);
        let request = fresh_client
            .send(&write_frame(1), test_timeout())
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
        let mut client = PipelineClient::new(RecordingSender::default(), limit);

        let ack_frame = Frame::new(FrameKind::Ack, Vec::new()).expect("frame must be valid");
        let err = client
            .send(&ack_frame, test_timeout())
            .expect_err("Ack frames must not be trackable as in-flight requests");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        assert_eq!(client.queue().len(), 0);

        let flush_ack_frame =
            Frame::new(FrameKind::FlushAck, Vec::new()).expect("frame must be valid");
        let err = client
            .send(&flush_ack_frame, test_timeout())
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
        let mut client = PipelineClient::new(RecordingSender::default(), limit);
        // `pub(crate)` ではなく `#[cfg(test)]` の内部ヘルパーで直接キューの状態を
        // 書き換え、`u64::MAX` からの採番がオーバーフローを起こす境界を再現する。
        client.queue.set_next_id_for_test(u64::MAX);

        let err = client
            .send(&write_frame(1), test_timeout())
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
    /// `u64::MAX` のまま変わらない（`fetch_update` が失敗時に状態を変更しない
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
        assert_send::<PipelineClient<RecordingSender>>();
    }

    /// TASK-12.1（#73 codex 指摘対応。P1・REPAIR-4）: 成功した送信は
    /// `SendMetrics::success_count` を増分し、`write_latency` の観測件数も
    /// 増える（早期拒否と異なりトランスポートへ実際に書き込むため）。
    #[test]
    fn repair4_send_metrics_counts_success_and_latency() {
        let limit = InFlightLimit::new(4).expect("4 must be valid");
        let mut client = PipelineClient::new(RecordingSender::default(), limit);

        client
            .send(&write_frame(1), test_timeout())
            .expect("send must succeed while under the limit");
        client
            .send(&write_frame(2), test_timeout())
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
        let mut client = PipelineClient::new(RecordingSender::default(), limit);

        client
            .send(&write_frame(1), test_timeout())
            .expect("1st send must succeed");
        let err = client
            .send(&write_frame(2), test_timeout())
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
        let mut client = PipelineClient::new(AlwaysTimeoutSender, limit);

        client
            .send(&write_frame(1), test_timeout())
            .expect_err("transport failure must propagate");
        client
            .send(&write_frame(2), test_timeout())
            .expect_err("poisoned client must reject further sends");

        let metrics = client.metrics();
        assert_eq!(metrics.success_count(), 0);
        assert_eq!(metrics.transport_failure_count(), 1);
        assert_eq!(metrics.rejected_poisoned_count(), 1);
        assert_eq!(metrics.write_latency().count(), 1);
    }

    /// TASK-12.1（#73 codex 再指摘対応。P1・REPAIR-4・REPAIR-5）:
    /// [`PipelineClient::with_observer`] に差し込んだ
    /// [`crate::observe::JsonLinesSendObserver`] が、成功・上限到達（早期拒否）の
    /// 2 件それぞれで 1 行ずつ JSON Lines をメモリ内にためる。`on_send` 自体は
    /// I/O をせず（REPAIR-5）、`observer_mut().drain_lines()` で呼び出し元が
    /// 取り出す。`metrics()` を明示的に読み出さなくても送信結果が観測できる
    /// ことを確認する（codex レビュー指摘の解消）。
    #[test]
    fn repair4_with_observer_buffers_json_lines_for_each_send_outcome() {
        use crate::observe::JsonLinesSendObserver;

        let limit = InFlightLimit::new(1).expect("1 must be valid");
        let observer = JsonLinesSendObserver::new();
        let mut client = PipelineClient::with_observer(RecordingSender::default(), limit, observer);

        client
            .send(&write_frame(1), test_timeout())
            .expect("1st send must succeed under the limit");
        let err = client
            .send(&write_frame(2), test_timeout())
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
        let mut client = PipelineClient::new(RecordingSender::default(), limit);

        let ack_frame = Frame::new(FrameKind::Ack, Vec::new()).expect("frame must be valid");
        client
            .send(&ack_frame, test_timeout())
            .expect_err("Ack frames must not be trackable as in-flight requests");

        let metrics = client.metrics();
        assert_eq!(metrics.rejected_invalid_frame_kind_count(), 1);
        assert_eq!(metrics.write_latency().count(), 0);
    }

    /// TASK-12.1（#73 codex 指摘対応。P1・REPAIR-4）: 未観測の `LatencyStats` は
    /// `count` が `0` で `min`/`max`/`mean` が `None` になる。
    #[test]
    fn repair4_latency_stats_defaults_to_empty() {
        let stats = LatencyStats::default();
        assert_eq!(stats.count(), 0);
        assert_eq!(stats.total(), Duration::ZERO);
        assert_eq!(stats.min(), None);
        assert_eq!(stats.max(), None);
        assert_eq!(stats.mean(), None);
    }
}
