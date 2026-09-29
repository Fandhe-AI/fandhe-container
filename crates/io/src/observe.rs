//! [`crate::client::PipelineClient::send`] の送信イベントを観測する仕組み
//! （TASK-12.1・#73 codex 指摘対応。P1・REPAIR-4・REPAIR-5）。
//!
//! [`crate::client::SendMetrics`]（[`crate::client::PipelineClient::metrics`] で参照）は
//! プロセス内の集計値を保持するだけで、外部のログ・メトリクス基盤への出力を持たない。
//! 呼び出し元が `metrics()` を明示的に読み出さない限り、送信失敗や上限到達を観測
//! できないという codex レビュー指摘（base 側 AGENTS.md の可観測性要件・REPAIR-4）に
//! 対応するため、本モジュールは送信 1 回ごとのイベントを [`SendObserver`] へ同期的に
//! 通知する仕組みと、その既定実装として送信イベントを JSON Lines（1 イベント 1 行）へ
//! 変換して上限付きのメモリ内キューへためる [`JsonLinesSendObserver`] を提供する。
//! [`SendMetrics`](crate::client::SendMetrics) を置き換えるものではなく、その補完
//! （外部出力用のフック）として使う。
//!
//! # `on_send` はブロックしてはならない（REPAIR-5。codex 再指摘対応）
//!
//! [`SendObserver::on_send`] は [`crate::client::PipelineClient::send`] という送信経路
//! から同期で呼ばれる。旧実装の [`JsonLinesSendObserver`] は `on_send` の中で任意の
//! `Write` へ同期的に `write_all`・`flush` していたが、満杯の pipe など書き込み先が
//! ブロックする状況では `send` そのものが無期限に停止しかねず、
//! [`crate::transport::IoTimeout`] でも打ち切れない（REPAIR-5 違反）。本モジュールの
//! [`JsonLinesSendObserver`] は `on_send` の中では `VecDeque` へ積むだけにとどめ、
//! 実際の書き出しは呼び出し元が任意のタイミング・スレッドで
//! [`JsonLinesSendObserver::drain_lines`] を呼んで取り出した行を自前の `Write` 先へ
//! 書く（送信経路の外に I/O を分離する）。
//!
//! # `drain_lines` は I/O をしない（codex/bugbot 再指摘対応）
//!
//! 旧実装が持っていた `drain_into`（`Write` へ直接書き出す API）は、途中の
//! `write_all` が部分書き込みで失敗した場合に呼び出し元が同じ行を再送すると
//! 行が重複し、失敗した行を諦めると欠落するという再試行不能な状態を生んでいた。
//! 本モジュールは書き出し・部分書き込み時の再試行を本型の責務から外し、
//! [`JsonLinesSendObserver::drain_lines`] がキューを空にして完全な行（改行を含まない
//! JSON 文字列）の `Vec` を返すところまでに留める。書き出し・再試行の実装は
//! 呼び出し元が自分の `Write` 先の性質（ファイル・ソケット等）に応じて行う。

use std::collections::VecDeque;
use std::fmt;
use std::time::Duration;

use crate::client::{AckOutcome, SendOutcome};
use crate::error::{IoError, IoErrorCode};
use crate::protocol::FrameKind;

/// [`crate::client::PipelineClient::send`] 1 回分の送信イベント（TASK-12.1・#73
/// codex 指摘対応。P1・REPAIR-4・REPAIR-5 P0 再指摘対応）。
///
/// [`crate::client::SendMetrics`] が集計している事象（結果種別・所要時間）と対応させ、
/// 送信対象のフレーム種別・失敗時のエラー詳細も併せて持つ。将来フィールドを
/// 追加できるよう `#[non_exhaustive]` にする（REPAIR-3）。
///
/// # 借用型である理由（#73 P0 再指摘対応。REPAIR-5「不安全な設計」観点）
///
/// `error` の `message`（[`SendEventError::message`]）は呼び出し元
/// （[`crate::client::PipelineClient::notify`]）がすでに保持している
/// [`crate::error::IoError`] の内部文字列を借用するだけで、複製しない。
/// [`SendObserver::on_send`] は `&SendEvent<'_>` を受け取る間だけ有効な借用で、
/// 呼び出しが終われば無効になる（`'static` としてどこかへ保持できない）。
/// 上限確認前に複製すると、untrusted なトランスポート由来の巨大なメッセージが
/// 送信のたびにヒープ確保を発生させ、送信経路自体の性能に無制限リソース
/// 消費（DoS）の余地を生む。借用のままにすることで、実際にメモリへためる
/// 判断（[`JsonLinesSendObserver`] の容量・バイト数上限）が下されるまで
/// 複製を遅延できる。
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SendEvent<'a> {
    /// この送信呼び出しが対象とした（呼び出し元が渡した）フレーム種別。
    /// `Ack`/`FlushAck` を拒否した場合もその種別をそのまま記録する。
    pub kind: FrameKind,
    /// [`SendOutcome`]（成功・各拒否理由・トランスポート失敗）。
    pub outcome: SendOutcome,
    /// トランスポートへの書き込みに要した時間。早期拒否（トランスポートを介さない
    /// 分岐）の場合は `Duration::ZERO`（[`crate::client::SendMetrics`] と同じ扱い）。
    pub latency: Duration,
    /// `outcome` が失敗系だった場合の詳細（エラーコード・メッセージ）。
    /// 成功時は `None`。
    pub error: Option<SendEventError<'a>>,
}

/// 件数・破棄数等の要約のみを出す手書きの `Debug`。`message` は
/// [`fmt::Debug`] for [`SendEventError`] へ委譲し、全量をダンプしない
/// （#73 P0 再指摘対応）。
impl fmt::Debug for SendEvent<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendEvent")
            .field("kind", &self.kind)
            .field("outcome", &self.outcome)
            .field("latency", &self.latency)
            .field("error", &self.error)
            .finish()
    }
}

/// [`SendEvent::error`] が保持する失敗詳細（TASK-12.1・#73 codex 指摘対応。P1）。
///
/// # 借用は呼び出し中のみ有効（#73 P0 再指摘対応。REPAIR-5）
///
/// `message` は [`crate::error::IoError::message`] を複製せず借用する。
/// untrusted な相手側（トランスポートの先）由来の文字列で、長さの上限はこの型
/// 自体では設けていない。[`SendObserver::on_send`] の呼び出しが終わると
/// この借用は無効になるため、`on_send` の実装が `message` を保持したい場合は、
/// 呼び出し中に上限（[`MAX_SEND_LOG_MESSAGE_BYTES`] 等）を適用してからコピーする
/// こと（[`JsonLinesSendObserver`] の実装を参照）。
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SendEventError<'a> {
    /// 機械可読なエラーコード（ERR-1）。
    pub code: IoErrorCode,
    /// 人間可読なエラーメッセージ。トランスポート実装（untrusted な相手側）由来の
    /// 文字列を含みうるため、[`JsonLinesSendObserver`] は出力時にエスケープする。
    /// 借用の契約は本型のドキュメントを参照。
    pub message: &'a str,
}

/// ためた `message` を無制限に出さないよう、長さと切り詰め済みの先頭のみを出す
/// 手書きの `Debug`（#73 P0 再指摘対応。`{:?}` 経由で全量が出力される経路を防ぐ。
/// [`truncate_message_bytes`] を再利用する）。
impl fmt::Debug for SendEventError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (prefix, truncated) = truncate_message_bytes(self.message);
        f.debug_struct("SendEventError")
            .field("code", &self.code)
            .field("message_len", &self.message.len())
            .field("message_prefix", &prefix)
            .field("message_truncated", &truncated)
            .finish()
    }
}

/// [`crate::client::PipelineClient::recv_ack`] 1 回分の ACK 受信イベント
/// （TASK-12.2・#74 codex 指摘対応。P1・REPAIR-4）。
///
/// [`SendEvent`] の ACK 受信版で、[`crate::client::AckMetrics`] が集計している
/// 事象（結果種別・所要時間）と対応させる。[`SendEvent`] と同様に将来フィールドを
/// 追加できるよう `#[non_exhaustive]` にする（REPAIR-3）。
///
/// # 借用型である理由
///
/// [`SendEvent`] のドキュメント参照。`error`（[`AckEventError::message`]）は
/// 呼び出し元（[`crate::client::PipelineClient::notify_ack`]）が保持する
/// [`crate::error::IoError`] の内部文字列を借用するだけで、複製しない。
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AckEvent<'a> {
    /// [`AckOutcome`]（成功・各拒否理由・トランスポート失敗）。
    pub outcome: AckOutcome,
    /// 受信・デコード済みの ACK フレーム種別（[`FrameKind::Ack`] は IO-1 の
    /// バッファリング保証、[`FrameKind::FlushAck`] は IO-2 の永続化保証に対応する。
    /// `PipelineClient::recv_ack` のドキュメント「IO-1・IO-2 の保証範囲の違い」
    /// 参照）。`crate::payload::decode_ack` がフレームを検証する前の早期拒否
    /// （[`AckOutcome::RejectedPoisoned`]・[`AckOutcome::RejectedNoInFlight`]・
    /// [`AckOutcome::TransportFailure`]・[`AckOutcome::RejectedInvalidPayload`]）
    /// では種別が確定していないため `None` になる。それ以外（送信順照合以降の
    /// 分岐・成功）は必ず `Some` になる（TASK-12.2・#74 codex P1 再指摘対応。
    /// IO-1・IO-2・REPAIR-4:
    /// 通常のバッファリング ACK と永続化保証の FlushAck を構造化ログ／観測
    /// イベントから区別できるようにする）。
    pub ack_kind: Option<FrameKind>,
    /// `receiver.recv_frame` を実際に呼び出した呼び出しの所要時間。早期拒否
    /// （`receiver` を呼ばない分岐）の場合は `Duration::ZERO`
    /// （[`crate::client::AckMetrics`] と同じ扱い）。
    pub latency: Duration,
    /// `outcome` が失敗系だった場合の詳細（エラーコード・メッセージ）。
    /// 成功時は `None`。
    pub error: Option<AckEventError<'a>>,
}

/// 件数・破棄数等の要約のみを出す手書きの `Debug`（[`SendEvent`] と同じ理由）。
impl fmt::Debug for AckEvent<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AckEvent")
            .field("outcome", &self.outcome)
            .field("ack_kind", &self.ack_kind)
            .field("latency", &self.latency)
            .field("error", &self.error)
            .finish()
    }
}

/// [`AckEvent::error`] が保持する失敗詳細（TASK-12.2・#74 codex 指摘対応。P1）。
///
/// 借用の契約は [`SendEventError`] と同じ（呼び出し中のみ有効。REPAIR-5）。
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AckEventError<'a> {
    /// 機械可読なエラーコード（ERR-1）。
    pub code: IoErrorCode,
    /// 人間可読なエラーメッセージ。トランスポート実装（untrusted な相手側）由来の
    /// 文字列を含みうるため、[`JsonLinesSendObserver`] は出力時にエスケープする。
    pub message: &'a str,
}

/// [`SendEventError`] と同じ理由の手書き `Debug`。
impl fmt::Debug for AckEventError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (prefix, truncated) = truncate_message_bytes(self.message);
        f.debug_struct("AckEventError")
            .field("code", &self.code)
            .field("message_len", &self.message.len())
            .field("message_prefix", &prefix)
            .field("message_truncated", &truncated)
            .finish()
    }
}

/// [`crate::client::PipelineClient::send`] の送信イベントと
/// [`crate::client::PipelineClient::recv_ack`] の ACK 受信イベントを受け取る
/// 観測フック（TASK-12.1・#73／TASK-12.2・#74 codex 指摘対応。P1・REPAIR-4・
/// REPAIR-5）。
///
/// 呼び出しは送信・ACK 受信のたびに同期的・単一スレッドで行われる
/// （[`crate::client::PipelineClient`] 自体が `&mut self` を要求し単一スレッド
/// 前提であることと同じ契約）。
///
/// # 契約: ブロックする I/O をしてはならない（REPAIR-5）
///
/// `on_send`・`on_ack` は送信・受信経路（[`crate::client::PipelineClient::send`]・
/// [`crate::client::PipelineClient::recv_ack`]）から同期で呼ばれる。ここで
/// ブロックする I/O（ソケット・pipe への書き込み・ロック待ち等）を行うと、
/// 相手の応答を待たない送信・ACK 待ちであるはずの呼び出し自体が無期限に
/// 停止しかねず、[`crate::transport::IoTimeout`] でも打ち切れない。実装は
/// メモリ内へ積む・非ブロッキング操作のみに留め、実際の I/O は別経路
/// （呼び出し元が明示的に呼ぶ drain API 等）へ分離すること
/// （[`JsonLinesSendObserver`] を参照）。
///
/// `Debug` は要求しない。`Box<dyn Write + Send>` のような非 `Debug` な書き込み先を
/// 保持する観測フックも実装できるようにするため（[`crate::client::PipelineClient`]
/// の `#[derive(Debug)]` は `S: FrameSender` にも `Debug` を要求していないのと同じ
/// 扱いで、`O: Debug` を実装した具象型のみが `PipelineClient` の `Debug` を使える）。
pub trait SendObserver: Send {
    /// 1 回の送信イベントを通知する。`event` は呼び出し中のみ有効な借用
    /// （[`SendEvent`] のドキュメント参照。#73 P0 再指摘対応）。
    fn on_send(&mut self, event: &SendEvent<'_>);

    /// 1 回の ACK 受信イベントを通知する（TASK-12.2・#74 codex 指摘対応。P1・
    /// REPAIR-4）。`event` は呼び出し中のみ有効な借用（[`AckEvent`] のドキュメント
    /// 参照）。
    ///
    /// # 既定実装を持たない理由（#74 P1 再指摘対応）
    ///
    /// 過去のリビジョンは本メソッドに no-op の既定実装を用意していたが、
    /// `on_send` のみを実装した既存の観測フックへ暗黙に `PipelineClient` を
    /// 渡すと `recv_ack` の成功・失敗イベントが無言で失われ、AGENTS.md の
    /// 可観測性要件（REPAIR-4）を満たせなくなる（ACK 観測の欠落を呼び出し元が
    /// 検知する手段がなかった）。本 crate 内の実装（[`NoopSendObserver`]・
    /// [`JsonLinesSendObserver`]）はいずれも本メソッドを明示的に実装しており、
    /// コンパイル時にオーバーライド漏れを検出できる本方式のほうが安全側
    /// （fail-closed）である。観測を意図的に不要とする実装は
    /// [`NoopSendObserver`] のように本体を空にして明示する。
    fn on_ack(&mut self, event: &AckEvent<'_>);
}

/// 何もしない実装（観測しない場合に呼び出し元が
/// [`crate::client::PipelineClient::new`] へ明示的に渡す。`PipelineClient::new`
/// は観測フックを必須引数として要求するため、暗黙の既定として選ばれることはない。
/// TASK-12.1・#73 codex 再指摘対応。P1・REPAIR-4）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoopSendObserver;

impl SendObserver for NoopSendObserver {
    fn on_send(&mut self, _event: &SendEvent<'_>) {}

    fn on_ack(&mut self, _event: &AckEvent<'_>) {}
}

/// [`JsonLinesSendObserver::new`]（既定容量）が使う、ためられる JSON 行数の既定値
/// （TASK-12.1・#73 codex 再指摘対応。P1・REPAIR-5）。
pub const DEFAULT_SEND_LOG_CAPACITY: usize = 1024;

/// [`JsonLinesSendObserver::with_capacity`] が受理する容量の最大値。無制限確保を
/// 防ぐための上限（security.md「不安全な設計」観点）。
pub const MAX_SEND_LOG_CAPACITY: usize = 65536;

/// [`JsonLinesSendObserver::new`] は検証付きコンストラクタ（[`JsonLinesSendObserver::with_capacity`]）
/// を経由しないため、[`DEFAULT_SEND_LOG_CAPACITY`] 自体が
/// [`JsonLinesSendObserver::with_capacity`] の検証範囲（`1..=MAX_SEND_LOG_CAPACITY`）に
/// 収まることをコンパイル時に保証する（初回レビュー Low 指摘対応。REPAIR-5）。
const _: () = assert!(
    DEFAULT_SEND_LOG_CAPACITY > 0 && DEFAULT_SEND_LOG_CAPACITY <= MAX_SEND_LOG_CAPACITY,
    "DEFAULT_SEND_LOG_CAPACITY は with_capacity の検証範囲（1..=MAX_SEND_LOG_CAPACITY）を \
     満たさなければならない"
);

/// [`SendEventError::message`] をエンコードする際に許容する最大バイト数
/// （codex P0 再指摘対応。security.md「不安全な設計」観点）。
///
/// `capacity`（行数上限）だけでは、1 行あたりのメッセージが巨大な場合に
/// キュー全体のメモリ使用量が無制限に膨らみうる。エンコード前にこの長さで
/// 切り詰め、UTF-8 の文字境界を跨がないよう調整する（[`truncate_message_bytes`]）。
pub const MAX_SEND_LOG_MESSAGE_BYTES: usize = 512;

/// [`JsonLinesSendObserver`] がためる JSON 行の合計バイト数の上限
/// （codex P0 再指摘対応。security.md「不安全な設計」観点）。
///
/// 行数上限（`capacity`）とは独立に、エンコード後の合計バイト数がこの値を
/// 超える新規イベントは破棄する（drop-newest。[`JsonLinesSendObserver::dropped_count`]
/// に計上）。
pub const MAX_SEND_LOG_BUFFER_BYTES: usize = 1024 * 1024;

/// JSON エンコード時に固定で書き込む部分（`event`・`kind`・`outcome`・`reason`・
/// `code`・`message_truncated`・`latency_us` のキー名・区切り文字・想定される値の
/// 最大長）に見込む上限バイト数。[`MAX_SEND_LOG_LINE_BYTES`] の計算にのみ使う
/// 保守的な見積もりであり、実際のエンコード処理はこの値を直接参照しない。
const SEND_LOG_LINE_FIXED_OVERHEAD_BYTES: usize = 256;

/// エスケープ後の `message` フィールドが取りうる最大バイト数の見積もり。
/// [`escape_json_string`] は 1 文字を最大でも `\u00xx` の 6 バイトへ展開するため、
/// 切り詰め後のメッサージ長（バイト単位。[`MAX_SEND_LOG_MESSAGE_BYTES`]）に対して
/// 6 倍を上限とみなす（実際に 6 倍へ達するのは制御文字が連続する病的な入力のみ）。
const MAX_ESCAPED_MESSAGE_BYTES: usize = MAX_SEND_LOG_MESSAGE_BYTES * 6;

/// [`JsonLinesSendObserver`] がためる 1 行の JSON がとりうる最大バイト数の見積もり。
/// [`MAX_SEND_LOG_BUFFER_BYTES`] を超えないことを下記の `const` assert で保証し、
/// 「1 行だけで総バイト上限に達し以降すべて破棄され続ける」設定ミスを防ぐ。
const MAX_SEND_LOG_LINE_BYTES: usize =
    SEND_LOG_LINE_FIXED_OVERHEAD_BYTES + MAX_ESCAPED_MESSAGE_BYTES;

const _: () = assert!(
    MAX_SEND_LOG_LINE_BYTES <= MAX_SEND_LOG_BUFFER_BYTES,
    "MAX_SEND_LOG_MESSAGE_BYTES と MAX_SEND_LOG_BUFFER_BYTES の組み合わせでは \
     1 行の最大サイズが総バイト上限を超えてしまう"
);

/// 上限付きの JSON Lines バッファ（TASK-12.1・#73／TASK-13.2.1・#820 レビュー
/// 指摘対応。P1・REPAIR-4・REPAIR-5）。
///
/// [`JsonLinesSendObserver`] と [`JsonLinesServerObserver`] が共通で使う
/// 「行数上限・合計バイト数上限に達したら新規イベント側を破棄する」ロジックを
/// 1 か所へ集約する（コード重複の防止。REPAIR-1）。非公開のため公開 API には
/// 影響しない（各観測フックがこの型をラップし、同じメソッド名・戻り値で
/// 公開する）。
///
/// # 確保量の上限
/// 各行の `String` は積む前に余剰容量を返すため、行の確保量の合計は
/// `total_bytes`（[`MAX_SEND_LOG_BUFFER_BYTES`] 以下）に一致する。行を指す
/// `VecDeque` の枠は遅延確保の償却つき成長だが、行数上限（`capacity`。最大
/// [`MAX_SEND_LOG_CAPACITY`]）で頭打ちになるため、枠の確保量は
/// `2 × capacity × size_of::<(u64, String)>()` 程度に収まる（事前に `capacity`
/// ぶん確保すると、使わない観測フックにも最大容量の枠を持たせることになるため
/// 遅延確保のままにする）。
///
/// # 順序番号
/// 各行は呼び出し元が付けた順序番号（`u64`）と組で保持する。
/// [`JsonLinesServerObserver`] が通常枠と監査枠の 2 本の本型を到着順に
/// マージするために使う（SEC-4・#820 codex P0 指摘対応）。
/// [`JsonLinesSendObserver`] は 1 本しか持たないため常に `0` を渡し、
/// 順序番号を使わない。
struct BoundedJsonLines {
    lines: VecDeque<(u64, String)>,
    capacity: usize,
    /// 合計バイト数の上限。[`JsonLinesSendObserver`]・[`JsonLinesServerObserver`]
    /// の通常枠は [`MAX_SEND_LOG_BUFFER_BYTES`]、監査枠は
    /// [`MAX_SERVER_AUDIT_LOG_BUFFER_BYTES`]。
    max_bytes: usize,
    dropped: u64,
    /// `lines` にためている JSON 行のエンコード後バイト数の合計（改行を含まない）。
    /// `max_bytes` との比較にのみ使う内部カウンタで、[`Self::drain`] ・
    /// [`Self::drain_sequenced`] で `0` へ戻す。
    total_bytes: usize,
}

impl BoundedJsonLines {
    /// 既定容量（[`DEFAULT_SEND_LOG_CAPACITY`]）で作る。
    fn new() -> Self {
        Self::with_limits(DEFAULT_SEND_LOG_CAPACITY, MAX_SEND_LOG_BUFFER_BYTES)
    }

    /// 行数上限・合計バイト数上限を直接指定して作る（検証しない）。呼び出し元は
    /// `const` assert で検証済みの定数（または [`Self::try_with_capacity`] で
    /// 検証した値）だけを渡す。
    fn with_limits(capacity: usize, max_bytes: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            capacity,
            max_bytes,
            dropped: 0,
            total_bytes: 0,
        }
    }

    /// 容量を指定して作る。`capacity` が `0` または [`MAX_SEND_LOG_CAPACITY`] を
    /// 超える場合は [`IoErrorCode::InvalidArgument`] を返す（無制限確保の防止）。
    /// `label` はエラーメッセージに埋め込む呼び出し元の種別名
    /// （`"send log"` / `"server log"` 等）。
    fn try_with_capacity(capacity: usize, label: &str) -> Result<Self, IoError> {
        if capacity == 0 {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("{label} capacity must not be zero"),
            ));
        }
        if capacity > MAX_SEND_LOG_CAPACITY {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("{label} capacity must be at most {MAX_SEND_LOG_CAPACITY}"),
            ));
        }
        Ok(Self::with_limits(capacity, MAX_SEND_LOG_BUFFER_BYTES))
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn len(&self) -> usize {
        self.lines.len()
    }

    fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    fn dropped_count(&self) -> u64 {
        self.dropped
    }

    fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// ためている JSON 行をすべて取り出してキューを空にする（各行は改行を含まない
    /// 完全な JSON 文字列）。本型は I/O をしない契約（呼び出し元の `on_send` /
    /// `on_event` 実装の doc 参照）のため、取り出した行をどこへどう書き出すか
    /// （ファイル・ソケット・部分書き込み時の再試行を含む）は呼び出し元の責務。
    fn drain(&mut self) -> Vec<String> {
        self.total_bytes = 0;
        self.lines.drain(..).map(|(_, line)| line).collect()
    }

    /// [`Self::drain`] の順序番号つき版（[`JsonLinesServerObserver::drain_lines`]
    /// が 2 本のキューを到着順にマージするために使う）。
    fn drain_sequenced(&mut self) -> VecDeque<(u64, String)> {
        self.total_bytes = 0;
        std::mem::take(&mut self.lines)
    }

    /// 行数上限に達していないか確認し、達していなければ `encode` を呼んで
    /// エンコードしたうえで、合計バイト数の上限チェックのうえキューへ積む
    /// （[`JsonLinesSendObserver`]・[`JsonLinesServerObserver`] の各 `on_*` 実装が
    /// 共有する。TASK-12.2・#74／TASK-13.2.1・#820 codex・reviewer 指摘対応。
    /// P1・REPAIR-4・REPAIR-5）。
    ///
    /// `encode` を遅延評価にするのは、行数上限に達している場合はエンコード
    /// 自体を省くため。満杯・合計バイト数超過時は新規イベントを破棄し（最古の
    /// イベントを保持する。すでにためた分の消失より、直近の詳細を失うほうが
    /// 実害が小さいと判断）、[`Self::dropped_count`] を増分する。破棄そのものが
    /// 呼び出し元（送信・受信経路）へ伝播することはない（観測が主処理を妨げて
    /// はならないため）。ここでは I/O を行わない（REPAIR-5）。
    ///
    /// 戻り値は積めた場合 `true`、破棄した場合（行数上限・合計バイト数上限の
    /// いずれでも）`false`。[`JsonLinesServerObserver`] の監査枠は `false` の
    /// ときに行を捨てず集約レコードへ合算する（SEC-4・#820 codex P0 指摘対応）。
    /// `seq` は行と組で保持する順序番号（本型の doc「順序番号」節参照）。
    fn push_encoded_line(&mut self, seq: u64, encode: impl FnOnce() -> String) -> bool {
        if self.lines.len() >= self.capacity {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        let mut encoded = encode();
        // 行数上限とは独立に、合計バイト数の上限も守る（codex P0 再指摘対応）。
        // 巨大な `message` が連続しても、キューの総メモリ使用量を有界に保つ。
        if self.total_bytes.saturating_add(encoded.len()) > self.max_bytes {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        // `format!` は償却つきで伸ばすため容量が長さを上回りうる。`total_bytes` が
        // 数える長さと実際の確保量を一致させるため、積む前に余剰容量を返す
        // （#820 codex P0 指摘〔確保容量が検証済みの長さを超える〕と同じ観点）。
        encoded.shrink_to_fit();
        self.total_bytes += encoded.len();
        self.lines.push_back((seq, encoded));
        true
    }
}

/// [`SendEvent`] を JSON Lines（1 イベント 1 行）へ変換し、上限付きのメモリ内
/// バッファ（`BoundedJsonLines`）へためる既定実装（TASK-12.1・#73 codex
/// 再指摘対応。P1・REPAIR-4・REPAIR-5・ERR-1 の構造化 `code` / `message` 形式）。
///
/// 出力キーは英語 snake_case 固定（`event`・`kind`・`outcome`・`reason`・`code`・
/// `message`・`message_truncated`・`latency_us`）。`event` は常に `"io_send"`、
/// `kind` は `WRITE`/`ACK`/`FLUSH`/`FLUSH_ACK`、`outcome` は成功なら `"ok"`、
/// 失敗系なら `"error"` で、失敗系の場合のみ `reason`（[`SendOutcome`] の
/// snake_case 名）・`code`（ERR-1 文字列）・`message`（[`MAX_SEND_LOG_MESSAGE_BYTES`]
/// で切り詰め済み・エスケープ済みの文字列）を付与する。`message_truncated` は
/// 切り詰めが発生した場合のみ `true` を付与し、発生しない場合はキー自体を省く。
/// この形式は [`JsonLinesServerObserver`]（TASK-13.2.1・#820）の `io_server`
/// イベントと共通の語彙を使う（両者のドキュメント参照）。
///
/// # 依存を追加しない制約
/// 本 crate は `serde_json` 等へ依存しない（dependency-policy）。JSON は手書きで
/// 組み立てるため、固定語彙のフィールド（`event`・`kind`・`outcome`・`reason`・
/// `code`）はエスケープ不要な既知の値のみを書き込み、`message` のような任意文字列
/// （untrusted なトランスポート由来を含みうる）だけを [`escape_json_string`] で
/// エスケープする。
///
/// # `on_send` は I/O をしない（REPAIR-5。codex 再指摘対応）
/// 旧実装は `on_send` の中で任意の `Write` へ同期的に書き込んでいたが、満杯の
/// pipe 等で送信経路（[`crate::client::PipelineClient::send`]）自体が無期限に
/// ブロックしかねず、[`crate::transport::IoTimeout`] でも打ち切れなかった
/// （REPAIR-5 違反）。本実装は `on_send` の中では `BoundedJsonLines` へ積むだけに
/// とどめ、実際の書き出しは呼び出し元が [`Self::drain_lines`] を呼んで取り出した
/// 行を自分のタイミング・スレッドで書き出す（部分書き込み時の再試行も呼び出し元の
/// 責務。codex/bugbot 再指摘対応）。
///
/// # 満杯時の扱い
/// `BoundedJsonLines::push_encoded_line` のドキュメント参照（行数上限
/// [`Self::capacity`]・合計バイト数上限 [`MAX_SEND_LOG_BUFFER_BYTES`] のいずれかに
/// 達した新規イベントは破棄し [`Self::dropped_count`] を増分する）。
///
/// また、`message`（[`SendEventError::message`]）はエンコード前に
/// [`MAX_SEND_LOG_MESSAGE_BYTES`] へ切り詰める（UTF-8 の文字境界を跨がない）。
/// 切り詰めた場合は JSON に `"message_truncated":true` を付与する。
pub struct JsonLinesSendObserver {
    buf: BoundedJsonLines,
}

impl JsonLinesSendObserver {
    /// 既定容量（[`DEFAULT_SEND_LOG_CAPACITY`]）で観測フックを作る。
    pub fn new() -> Self {
        Self {
            buf: BoundedJsonLines::new(),
        }
    }

    /// 容量を指定して観測フックを作る。`capacity` が `0` または
    /// [`MAX_SEND_LOG_CAPACITY`] を超える場合は [`IoErrorCode::InvalidArgument`]
    /// を返す（無制限確保の防止）。
    pub fn with_capacity(capacity: usize) -> Result<Self, IoError> {
        Ok(Self {
            buf: BoundedJsonLines::try_with_capacity(capacity, "send log")?,
        })
    }

    /// このバッファの容量を返す。
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// 現在ためている JSON 行数を返す。
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// ためている JSON 行が 1 件もないかを返す。
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// 容量超過により破棄した（新規イベント側を破棄した）件数を返す。
    pub fn dropped_count(&self) -> u64 {
        self.buf.dropped_count()
    }

    /// 現在ためている JSON 行の合計バイト数（改行を含まない）を返す。
    pub fn total_bytes(&self) -> usize {
        self.buf.total_bytes()
    }

    /// ためている JSON 行をすべて取り出してキューを空にする（各行は改行を含まない
    /// 完全な JSON 文字列）。
    ///
    /// 本型は I/O をしない契約（[`Self::on_send`]・上記モジュール doc 参照）のため、
    /// 取り出した行をどこへどう書き出すか（ファイル・ソケット・部分書き込み時の
    /// 再試行を含む）は呼び出し元の責務とする。
    pub fn drain_lines(&mut self) -> Vec<String> {
        self.buf.drain()
    }
}

impl Default for JsonLinesSendObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl SendObserver for JsonLinesSendObserver {
    fn on_send(&mut self, event: &SendEvent<'_>) {
        self.buf.push_encoded_line(0, || encode_send_event(event));
    }

    fn on_ack(&mut self, event: &AckEvent<'_>) {
        self.buf.push_encoded_line(0, || encode_ack_event(event));
    }
}

/// ためた JSON 行の中身を誤ってダンプしないよう、件数・破棄数・合計バイト数のみを
/// 出す手書きの `Debug` 実装。
impl fmt::Debug for JsonLinesSendObserver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonLinesSendObserver")
            .field("len", &self.buf.len())
            .field("capacity", &self.buf.capacity())
            .field("dropped", &self.buf.dropped_count())
            .field("total_bytes", &self.buf.total_bytes())
            .finish()
    }
}

fn frame_kind_str(kind: FrameKind) -> &'static str {
    match kind {
        FrameKind::Write => "WRITE",
        FrameKind::Ack => "ACK",
        FrameKind::Flush => "FLUSH",
        FrameKind::FlushAck => "FLUSH_ACK",
    }
}

fn outcome_reason_str(outcome: SendOutcome) -> &'static str {
    match outcome {
        SendOutcome::Success => "success",
        SendOutcome::RejectedPoisoned => "rejected_poisoned",
        SendOutcome::RejectedInvalidFrameKind => "rejected_invalid_frame_kind",
        SendOutcome::RejectedResourceExhausted => "rejected_resource_exhausted",
        SendOutcome::RejectedInvalidPayload => "rejected_invalid_payload",
        SendOutcome::TransportFailure => "transport_failure",
    }
}

/// 制御文字・`"`・`\` を JSON 文字列リテラルとして安全な形へエスケープする。
///
/// 依存を追加せず手書きで JSON を組み立てるための最小実装（serde_json 相当の
/// 完全な仕様準拠は目指さない。ERR-1 の `message` を出力する用途に限る）。
/// 呼び出し元は [`truncate_message_bytes`] で切り詰めた入力だけを渡すため、
/// 伸長後の長さも [`MAX_ESCAPED_MESSAGE_BYTES`] 以下に収まる。
fn escape_json_string(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                escaped.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => escaped.push(c),
        }
    }
    escaped
}

/// `message` を [`MAX_SEND_LOG_MESSAGE_BYTES`] バイト以内へ切り詰める
/// （codex P0 再指摘対応）。
///
/// UTF-8 の文字境界を跨がないよう、上限に収まる最後の文字境界で切る（`str` の
/// 添字アクセスで不正境界を指すと panic するため、`char_indices` で安全に判定
/// する）。戻り値は `(切り詰め後の文字列, 切り詰めが発生したか)`。
pub(crate) fn truncate_message_bytes(message: &str) -> (&str, bool) {
    if message.len() <= MAX_SEND_LOG_MESSAGE_BYTES {
        return (message, false);
    }
    let mut end = 0;
    for (idx, ch) in message.char_indices() {
        let next = idx + ch.len_utf8();
        if next > MAX_SEND_LOG_MESSAGE_BYTES {
            break;
        }
        end = next;
    }
    // `get` で境界を確認してから切り出す（外部入力起点の文字列を添字アクセス
    // しない。coding-rust.md「外部入力」観点）。`end` は上のループで確定した
    // 文字境界のため必ず `Some` になるが、フォールバックとして空文字列にする。
    (message.get(..end).unwrap_or(""), true)
}

/// [`SendEvent`] を 1 行の JSON Lines 文字列へエンコードする（改行は含まない）。
fn encode_send_event(event: &SendEvent<'_>) -> String {
    let latency_us = event.latency.as_micros();
    let kind = frame_kind_str(event.kind);
    match (&event.outcome, &event.error) {
        (SendOutcome::Success, _) => {
            format!(
                "{{\"event\":\"io_send\",\"kind\":\"{kind}\",\"outcome\":\"ok\",\"latency_us\":{latency_us}}}"
            )
        }
        (outcome, Some(error)) => {
            let reason = outcome_reason_str(*outcome);
            let code = error.code.as_str();
            let (truncated_message, truncated) = truncate_message_bytes(error.message);
            let message = escape_json_string(truncated_message);
            if truncated {
                format!(
                    "{{\"event\":\"io_send\",\"kind\":\"{kind}\",\"outcome\":\"error\",\
                     \"reason\":\"{reason}\",\"code\":\"{code}\",\"message\":\"{message}\",\
                     \"message_truncated\":true,\"latency_us\":{latency_us}}}"
                )
            } else {
                format!(
                    "{{\"event\":\"io_send\",\"kind\":\"{kind}\",\"outcome\":\"error\",\
                     \"reason\":\"{reason}\",\"code\":\"{code}\",\"message\":\"{message}\",\
                     \"latency_us\":{latency_us}}}"
                )
            }
        }
        (outcome, None) => {
            // 契約上 `Success` 以外は必ず `error` を伴う（`PipelineClient::send` が
            // 組み立てる）が、型としては `Option` のため、万一 `None` が来ても
            // panic せず `code`/`message` を省いた行を出す（外部入力ではないため
            // 到達しない想定だが、フォールバックとして安全側に倒す）。
            let reason = outcome_reason_str(*outcome);
            format!(
                "{{\"event\":\"io_send\",\"kind\":\"{kind}\",\"outcome\":\"error\",\
                 \"reason\":\"{reason}\",\"latency_us\":{latency_us}}}"
            )
        }
    }
}

/// [`AckOutcome`] の snake_case 名を返す（[`outcome_reason_str`] の ACK 版。
/// TASK-12.2・#74 codex 指摘対応。P1・REPAIR-4）。
fn ack_outcome_reason_str(outcome: AckOutcome) -> &'static str {
    match outcome {
        AckOutcome::Success => "success",
        AckOutcome::RejectedPoisoned => "rejected_poisoned",
        AckOutcome::RejectedNoInFlight => "rejected_no_in_flight",
        AckOutcome::TransportFailure => "transport_failure",
        AckOutcome::RejectedInvalidPayload => "rejected_invalid_payload",
        AckOutcome::RejectedOutOfOrder => "rejected_out_of_order",
        AckOutcome::RejectedUnknownAckId => "rejected_unknown_ack_id",
        AckOutcome::RejectedAckKindMismatch => "rejected_ack_kind_mismatch",
        AckOutcome::RejectedInternal => "rejected_internal",
    }
}

/// [`AckEvent`] を 1 行の JSON Lines 文字列へエンコードする（改行は含まない。
/// [`encode_send_event`] の ACK 版。TASK-12.2・#74 codex 指摘対応。P1・REPAIR-4）。
///
/// `event` フィールドは `io_send` と区別するため `"io_recv_ack"` を使う。
/// フレーム種別（`kind`）は持たない（`recv_ack` はキューの先頭と対応付けるまで
/// 送信時の種別が確定しないため。[`AckEvent`] のドキュメント参照）。
/// `event.ack_kind` から `"ack_kind":"ACK",`／`"ack_kind":"FLUSH_ACK",` の
/// 先頭カンマなし・末尾カンマありの断片を組み立てる（[`encode_ack_event`] 用の
/// 共通処理。TASK-12.2・#74 codex P1 再指摘対応。IO-1・IO-2・REPAIR-4）。
///
/// `decode_ack` 前の早期拒否では種別が確定しない（[`AckEvent::ack_kind`] の
/// ドキュメント参照）ため `None` の場合はフィールド自体を省く（空文字列を返す）。
fn ack_kind_json_fragment(ack_kind: Option<FrameKind>) -> String {
    match ack_kind {
        Some(kind) => format!("\"ack_kind\":\"{}\",", frame_kind_str(kind)),
        None => String::new(),
    }
}

/// [`AckEvent`] を 1 行の JSON Lines 文字列へエンコードする（改行は含まない。
/// [`encode_send_event`] の ACK 版。TASK-12.2・#74 codex 指摘対応。P1・REPAIR-4）。
fn encode_ack_event(event: &AckEvent<'_>) -> String {
    let latency_us = event.latency.as_micros();
    let ack_kind = ack_kind_json_fragment(event.ack_kind);
    match (&event.outcome, &event.error) {
        (AckOutcome::Success, _) => {
            format!(
                "{{\"event\":\"io_recv_ack\",{ack_kind}\"outcome\":\"ok\",\"latency_us\":{latency_us}}}"
            )
        }
        (outcome, Some(error)) => {
            let reason = ack_outcome_reason_str(*outcome);
            let code = error.code.as_str();
            let (truncated_message, truncated) = truncate_message_bytes(error.message);
            let message = escape_json_string(truncated_message);
            if truncated {
                format!(
                    "{{\"event\":\"io_recv_ack\",{ack_kind}\"outcome\":\"error\",\
                     \"reason\":\"{reason}\",\"code\":\"{code}\",\"message\":\"{message}\",\
                     \"message_truncated\":true,\"latency_us\":{latency_us}}}"
                )
            } else {
                format!(
                    "{{\"event\":\"io_recv_ack\",{ack_kind}\"outcome\":\"error\",\
                     \"reason\":\"{reason}\",\"code\":\"{code}\",\"message\":\"{message}\",\
                     \"latency_us\":{latency_us}}}"
                )
            }
        }
        (outcome, None) => {
            // `Success` 以外は必ず `error` を伴う契約だが（`PipelineClient::notify_ack`
            // が組み立てる）、型としては `Option` のため、万一 `None` が来ても
            // panic せず `code`/`message` を省いた行を出す（`encode_send_event` と
            // 同じフォールバック方針）。
            let reason = ack_outcome_reason_str(*outcome);
            format!(
                "{{\"event\":\"io_recv_ack\",{ack_kind}\"outcome\":\"error\",\
                 \"reason\":\"{reason}\",\"latency_us\":{latency_us}}}"
            )
        }
    }
}

/// [`crate::server::UdsServer`]・[`crate::server::UdsConnection`]
/// （TASK-13.2.1・#820）が扱う 1 回の操作種別。
///
/// [`ServerEvent::op`] が示す操作で、将来 `Bind` 等を追加できるよう
/// `#[non_exhaustive]` にする（REPAIR-3。現時点では bind は観測イベントを
/// 持たない。[`ServerObserver`] のドキュメント「bind は観測対象外」参照）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServerOp {
    /// [`crate::server::UdsServer::accept`]。
    Accept,
    /// [`crate::server::UdsConnection`] の [`crate::transport::FrameReceiver::recv_frame`]。
    Recv,
    /// [`crate::server::UdsConnection`] の [`crate::transport::FrameSender::send_frame`]。
    Send,
}

/// [`ServerEvent::outcome`]（TASK-13.2.1・#820。P1-3 の poison 契約を
/// [`SendOutcome`] と同じ語彙で区別できるようにする）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServerOutcome {
    /// 操作が成功した。
    Success,
    /// [`crate::server::UdsConnection`] が P1-3 により失効済み（poison 済み）で
    /// あるために拒否した（送受信自体をトランスポートへ渡さなかった早期拒否）。
    RejectedPoisoned,
    /// [`ServerOp::Accept`] が、接続元の peer credential 検証
    /// （PLUG-12・security.md）に失敗した接続を拒否した（H1・#820
    /// security-auditor 指摘対応。SEC-4「分離違反の試行は監査ログに記録する」）。
    /// この拒否 1 件ごとに個別のイベントとして通知される（`crate::server`
    /// モジュール doc「peer credential の検証」節参照）ため、正常な接続が
    /// 最終的に成立しても、それまでの拒否の通知は取り消されない。通知を受けた
    /// 観測フックがそれをどう保持するかは実装による（既定実装の
    /// [`JsonLinesServerObserver`] は専用の監査枠に積み、あふれた分は集約行として
    /// 残す。SEC-4・#820 codex P0 指摘対応）。
    RejectedPeerCredential,
    /// 上記以外の失敗（タイムアウト・プロトコル違反・`ReceiveLimits::admit` の
    /// 拒否・トランスポート層のエラー等）。
    Failure,
}

/// [`crate::server::UdsServer`]・[`crate::server::UdsConnection`] の 1 回の
/// 操作イベント（TASK-13.2.1・#820・reviewer/security-auditor 指摘対応。P1・
/// REPAIR-4・REPAIR-5）。
///
/// [`SendEvent`]（TASK-12.1・#73）と同じ設計方針を UDS サーバー側へ適用した型で、
/// 借用・`Debug`・エラー詳細の扱いは [`SendEvent`] のドキュメントを参照
/// （`error` は既存の [`SendEventError`] をそのまま再利用し、専用の型を新設
/// しない）。将来フィールドを追加できるよう `#[non_exhaustive]` にする
/// （REPAIR-3）。
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerEvent<'a> {
    /// この呼び出しが対象とした操作種別。
    pub op: ServerOp,
    /// フレーム種別。[`ServerOp::Send`] は呼び出し元が渡した送信対象の種別、
    /// [`ServerOp::Recv`] はヘッダ検証（`FrameHeader::from_bytes` と
    /// `crate::server` のプロトコル違反判定）を通過した場合に確定する種別
    /// （通過前に失敗した場合は `None`）、[`ServerOp::Accept`] は常に `None`
    /// （フレームを介さない操作のため）。
    pub kind: Option<FrameKind>,
    /// [`ServerOutcome`]（成功・poison による拒否・その他の失敗）。
    pub outcome: ServerOutcome,
    /// 実際にトランスポートを介した呼び出しに要した時間。poison による早期
    /// 拒否（トランスポートを介さない分岐）の場合は `Duration::ZERO`
    /// （[`SendEvent::latency`] と同じ扱い）。
    pub latency: Duration,
    /// [`ServerOp::Accept`] が `ConnectionAborted`（相手が accept 完了前に
    /// 切断した）を再試行した回数。[`crate::server`] モジュール doc の
    /// 「受付ループの組み方」参照。[`ServerOp::Recv`]・[`ServerOp::Send`] では
    /// 常に `0`。
    ///
    /// peer credential の検証失敗による再試行（[`ServerOutcome::RejectedPeerCredential`]）
    /// はこの件数には含めない。件数は [`Self::peer_credential_rejections`] で
    /// 別に数える（H1・#820 security-auditor 指摘対応。`ConnectionAborted` は
    /// 相手の都合による一時的な切断であり、peer credential の不一致は
    /// SEC-4 の監査対象となる分離違反の試行であるため、混ぜずに区別する）。
    pub accept_aborted_retries: u32,
    /// [`ServerOp::Accept`] が peer credential の検証失敗
    /// （[`ServerOutcome::RejectedPeerCredential`]）により再試行した回数（H1・
    /// #820 security-auditor 指摘対応）。個々の拒否は
    /// [`ServerOutcome::RejectedPeerCredential`] のイベントとして 1 件ずつ
    /// 通知され、この累積件数は最終的な Accept の成功・失敗イベントにも載る。
    /// [`ServerOp::Recv`]・[`ServerOp::Send`] では常に `0`。
    pub peer_credential_rejections: u32,
    /// [`ServerOutcome::RejectedPeerCredential`] の拒否で、接続元の uid が
    /// 取得できた場合の値（`crate::sys::peer_uid` が成功したが
    /// bind 時点で取得・保存した自プロセスの実効 uid〔`crate::sys::effective_uid`〕と
    /// 不一致だった場合）。数値のみで秘密情報や
    /// untrusted な文字列を含まないため、message とは独立してそのまま観測
    /// イベントへ載せてよい（H1・#820 security-auditor 指摘対応）。取得自体に
    /// 失敗した場合・他の `op`/`outcome` では `None`。
    pub peer_uid: Option<u32>,
    /// 複数の操作を 1 件にまとめた集約イベントであれば、その集約値（件数・所要時間の
    /// 合計。[`CoalescedServerEvents`] 参照。REPAIR-4・#1118）。通常の 1 操作 1 イベント
    /// では `None`。
    ///
    /// `Some` のとき、他のフィールドの意味は次のとおり変わる。
    /// - `op`・`kind`・`outcome`・`error.code` は集約したすべての操作で同じ値（集約の
    ///   キー）
    /// - `latency` は集約した操作の所要時間の **最大値**（合計は
    ///   [`CoalescedServerEvents::latency_sum`]）
    /// - `error.message` は最後に集約した操作のメッセージ（切り詰め済み）
    ///
    /// 操作別・結果別の件数を数える観測フックは、このイベントを
    /// [`CoalescedServerEvents::count`] 件として数える。
    pub coalesced: Option<CoalescedServerEvents>,
    /// `outcome` が失敗系だった場合の詳細（エラーコード・メッセージ）。
    /// 成功時は `None`。[`SendEventError`] のドキュメント参照（借用は
    /// `on_event` の呼び出し中のみ有効）。
    pub error: Option<SendEventError<'a>>,
}

/// [`ServerEvent::coalesced`] の集約値（REPAIR-4・#1118）。
///
/// 分割後の送信側・受信側（[`crate::server::UdsSendHalf`]・
/// [`crate::server::UdsRecvHalf`]）が共有する観測フックの保留キューがあふれた
/// とき、あふれた操作を `(op, kind, outcome, error code)` ごとに 1 件へまとめた
/// 集約イベントに付く。個々の操作のイベントを捨てる代わりに、操作別・結果別の
/// 件数と所要時間（最大値は [`ServerEvent::latency`]、合計はここ）を失わずに
/// 残す（`JsonLinesServerObserver` の peer credential 拒否の集約行
/// 〔`CoalescedRejections`〕と同じ考え方）。将来フィールドを追加できるよう
/// `#[non_exhaustive]` にする（REPAIR-3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CoalescedServerEvents {
    /// 集約した操作の件数（1 以上。saturating で数える）。
    pub count: u64,
    /// 集約した操作の所要時間の合計（saturating で足す）。平均は
    /// `latency_sum / count` で求められる。
    pub latency_sum: Duration,
}

impl CoalescedServerEvents {
    /// 集約値を作る（`crate::server` の保留キューの集約が組み立てる）。
    pub(crate) fn new(count: u64, latency_sum: Duration) -> Self {
        Self { count, latency_sum }
    }
}

/// 件数・破棄数等の要約のみを出す手書きの `Debug`（[`SendEvent`] と同じ理由。
/// `error` は [`SendEventError`] の truncate 済み `Debug` へ委譲する）。
impl fmt::Debug for ServerEvent<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerEvent")
            .field("op", &self.op)
            .field("kind", &self.kind)
            .field("outcome", &self.outcome)
            .field("latency", &self.latency)
            .field("accept_aborted_retries", &self.accept_aborted_retries)
            .field(
                "peer_credential_rejections",
                &self.peer_credential_rejections,
            )
            .field("peer_uid", &self.peer_uid)
            .field("coalesced", &self.coalesced)
            .field("error", &self.error)
            .finish()
    }
}

/// [`crate::server::UdsServer`]・[`crate::server::UdsConnection`] の accept・
/// 送受信イベントを受け取る観測フック（TASK-13.2.1・#820。P1・REPAIR-4・
/// REPAIR-5）。[`SendObserver`] の UDS サーバー版で、契約は同じ
/// （[`SendObserver`] のドキュメント参照）。
///
/// # 契約: ブロックする I/O をしてはならない（REPAIR-5）
///
/// `on_event` は accept・送信・受信経路（[`crate::server::UdsServer::accept`]・
/// [`crate::transport::FrameSender::send_frame`]・
/// [`crate::transport::FrameReceiver::recv_frame`] の [`crate::server::UdsConnection`]
/// 実装）から同期で呼ばれる。ここでブロックする I/O を行うと、受付ループ・
/// 送受信そのものが無期限に停止しかねず、[`crate::transport::IoTimeout`] でも
/// 打ち切れない。実装はメモリ内へ積む・非ブロッキング操作のみに留め、実際の
/// I/O は別経路（呼び出し元が明示的に呼ぶ drain API 等）へ分離すること
/// （[`JsonLinesServerObserver`] を参照）。
///
/// # SEC-4（peer credential 拒否の監査記録）
///
/// [`ServerOutcome::RejectedPeerCredential`] のイベントは SEC-4「分離違反の
/// 試行は監査ログに記録する」の対象である。本フックの実装は、このイベントを
/// 黙って捨ててはならない（保持しきれない場合は、欠けたことが後から分かる
/// 形で残す）。既定実装の [`JsonLinesServerObserver`] は専用の監査枠と集約行で
/// これを満たす。永続的な監査ログへの配線は後続 sub-issue（要起票）で行う。
///
/// # `bind` は観測対象外
///
/// [`ServerOp`] は `Accept`・`Recv`・`Send` のみを持つ。
/// [`crate::server::UdsServer::bind`] は本フックへ引き渡す前段階（構築時の
/// 引数）であり、bind 自体の成功・失敗は観測イベントとして通知されない
/// （bind 失敗時は観測フックの値ごと破棄される）。将来 bind を観測対象に
/// 含める場合は `ServerOp` へバリアントを追加する（`#[non_exhaustive]`）。
///
/// # 全分岐で最終結果を 1 回通知する
///
/// [`crate::server::UdsServer::accept`]・[`crate::server::UdsConnection`] の
/// 送受信は、成功・各種拒否（プロトコル違反・`ReceiveLimits::admit` の拒否・
/// poison 済みでの拒否）・タイムアウトのすべての分岐で、最終結果のイベントを
/// 1 回通知する（`crates/io/tests/server.rs` の結合試験で確認する）。送受信の
/// 通知は 1 回の呼び出しにつき 1 回だけだが、accept は最終結果の前に peer
/// credential 拒否 1 件ごとのイベント（[`ServerOutcome::RejectedPeerCredential`]）
/// も通知するため、1 回の呼び出しで `1 + 拒否件数` 回呼ばれうる。
///
/// 例外として、分割後の送信側・受信側（[`crate::server::UdsSendHalf`]・
/// [`crate::server::UdsRecvHalf`]）が共有する保留キューがあふれた場合は、あふれた
/// 複数回の呼び出しの結果が `(op, kind, outcome, code)` ごとに 1 件の集約イベント
/// （[`ServerEvent::coalesced`] が `Some`）にまとまる（#1118・REPAIR-4）。件数を
/// 数える実装は [`CoalescedServerEvents::count`] を使う。
pub trait ServerObserver: Send {
    /// 1 回の操作イベントを通知する。`event` は呼び出し中のみ有効な借用
    /// （[`ServerEvent`] のドキュメント参照）。
    fn on_event(&mut self, event: &ServerEvent<'_>);
}

/// 何もしない実装（観測しない場合に呼び出し元が [`crate::server::UdsServer::bind`]・
/// [`crate::server::UdsServer::accept`] へ明示的に渡す。暗黙の既定として選ばれる
/// ことはない。TASK-13.2.1・#820。[`NoopSendObserver`] の UDS サーバー版）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoopServerObserver;

impl ServerObserver for NoopServerObserver {
    fn on_event(&mut self, _event: &ServerEvent<'_>) {}
}

/// [`ServerEvent`] の JSON エンコード時に固定で書き込む部分（`event`・`op`・
/// `kind`・`outcome`・`reason`・`code`・`message_truncated`・
/// `accept_aborted_retries`・`peer_credential_rejections`・`peer_uid`・
/// `latency_us` のキー名・区切り文字・想定される値の最大長）に見込む上限
/// バイト数。[`SEND_LOG_LINE_FIXED_OVERHEAD_BYTES`] より、`op`（最大
/// `"\"op\":\"accept\","` 相当）・`accept_aborted_retries`・
/// `peer_credential_rejections`・`peer_uid`（いずれも `u32` の最大桁数
/// `4294967295`。H1・#820 security-auditor 指摘対応で追加）ぶん余分に見積もり、
/// さらに集約イベントの `coalesced`・`count`（`u64`）・`latency_sum_us`
/// （`Duration::MAX` のマイクロ秒）ぶん（#1118）を 128 バイト足す。
/// [`MAX_SERVER_LOG_LINE_BYTES`] の計算にのみ使う保守的な見積もりであり、
/// 実際のエンコード処理はこの値を直接参照しない。
const SERVER_LOG_LINE_FIXED_OVERHEAD_BYTES: usize = SEND_LOG_LINE_FIXED_OVERHEAD_BYTES + 384;

/// [`JsonLinesServerObserver`] がためる 1 行の JSON がとりうる最大バイト数の
/// 見積もり（[`MAX_SEND_LOG_LINE_BYTES`] のサーバー版）。
const MAX_SERVER_LOG_LINE_BYTES: usize =
    SERVER_LOG_LINE_FIXED_OVERHEAD_BYTES + MAX_ESCAPED_MESSAGE_BYTES;

const _: () = assert!(
    MAX_SERVER_LOG_LINE_BYTES <= MAX_SEND_LOG_BUFFER_BYTES,
    "SERVER_LOG_LINE_FIXED_OVERHEAD_BYTES と MAX_SEND_LOG_MESSAGE_BYTES の組み合わせでは \
     1 行の最大サイズが総バイト上限を超えてしまう"
);

/// [`JsonLinesServerObserver`] の監査枠（[`ServerOutcome::RejectedPeerCredential`]
/// 専用のキュー）がためられる行数の上限（SEC-4・PLUG-12。#820 codex P0 指摘
/// 対応）。通常イベントの行数上限（[`JsonLinesServerObserver::capacity`]）とは
/// 別枠で、利用者は変更できない。
pub const SERVER_AUDIT_LOG_CAPACITY: usize = 256;

/// [`JsonLinesServerObserver`] の監査枠がためられる JSON 行の合計バイト数の上限
/// （SEC-4・#820 codex P0 指摘対応。通常枠の [`MAX_SEND_LOG_BUFFER_BYTES`] とは
/// 別枠）。1 行の最悪長の見積もり（`MAX_SERVER_LOG_LINE_BYTES` = 3712 バイト）
/// に近い行ばかりなら、行数上限より先にこちらに達する（約 35 行）。どちらの
/// 上限に先に達しても、以降の拒否は集約行へ回る。
pub const MAX_SERVER_AUDIT_LOG_BUFFER_BYTES: usize = 128 * 1024;

/// 監査枠が満杯のときに合算する集約行（[`encode_coalesced_rejections`]）が
/// とりうる最大バイト数の見積もり（固定語彙のキーと `u64`・`u32` の最大桁数
/// だけで組み立てるため 256 バイトに収まる。最悪ケースはテストで照合する）。
const MAX_SERVER_AUDIT_GAP_LINE_BYTES: usize = 256;

const _: () = assert!(
    SERVER_AUDIT_LOG_CAPACITY > 0 && SERVER_AUDIT_LOG_CAPACITY <= MAX_SEND_LOG_CAPACITY,
    "SERVER_AUDIT_LOG_CAPACITY は 1..=MAX_SEND_LOG_CAPACITY に収まらなければならない"
);
const _: () = assert!(
    MAX_SERVER_LOG_LINE_BYTES <= MAX_SERVER_AUDIT_LOG_BUFFER_BYTES,
    "監査枠の合計バイト数上限は、最悪長の拒否イベント 1 行を必ず収められなければならない"
);
const _: () = assert!(
    MAX_SERVER_AUDIT_GAP_LINE_BYTES <= MAX_SERVER_LOG_LINE_BYTES,
    "集約行の最悪長は、通常の 1 行の最悪長以下でなければならない"
);

/// 監査枠が満杯のときに、以降の [`ServerOutcome::RejectedPeerCredential`] を
/// 1 件にまとめて保持する集約レコード（SEC-4・#820 codex P0 指摘対応）。
///
/// 文字列ではなく数値だけを保持し、[`JsonLinesServerObserver::drain_lines`] の
/// 時点で [`encode_coalesced_rejections`] により 1 行へエンコードする（件数が
/// 増えても確保量は変わらない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CoalescedRejections {
    /// 最初に集約した拒否の順序番号。drain 時に集約行をこの位置へ置く
    /// （欠けた区間がどこから始まったかを他のイベントとの前後で示すため）。
    first_seq: u64,
    /// 集約した拒否の件数（saturating で数える）。
    count: u64,
    /// 最後に集約した拒否の [`ServerEvent::peer_uid`]（取得できなかった場合は
    /// `None`。そのときは集約行から `last_peer_uid` キー自体を省く）。
    last_peer_uid: Option<u32>,
}

/// [`ServerEvent`] を JSON Lines（1 イベント 1 行）へ変換し、上限付きのメモリ内
/// バッファ（`BoundedJsonLines`）へためる既定実装（TASK-13.2.1・#820。P1・
/// REPAIR-4・REPAIR-5・SEC-4。[`JsonLinesSendObserver`] の UDS サーバー版）。
///
/// 本型は有界の一時バッファであり、永続的な監査ログではない。SEC-4
/// 「分離違反の試行は監査ログに記録する」の永続的な監査ログへの配線
/// （[`Self::drain_lines`] で取り出した行の書き出し先）は後続 sub-issue
/// （要起票）で行う。本型が保証するのは「peer credential 拒否は黙って失われない（drain
/// するまで保持し、個別の行または欠けた区間を明示する集約行として
/// [`Self::drain_lines`] に現れる）」までである（drain せずに本型を破棄した
/// 場合にためた行が消えるのは、他のイベントと同じく呼び出し元の責務）。
///
/// # 2 つの枠（SEC-4・#820 codex P0 指摘対応）
/// - 通常枠: [`ServerOutcome::RejectedPeerCredential`] 以外のイベント。行数上限
///   （[`Self::capacity`]。既定 [`DEFAULT_SEND_LOG_CAPACITY`]・最大
///   [`MAX_SEND_LOG_CAPACITY`]）・合計バイト数上限（[`MAX_SEND_LOG_BUFFER_BYTES`]）・
///   満杯時に新規イベント側を破棄して [`Self::dropped_count`] を増分する方針は
///   [`JsonLinesSendObserver`] と共有する
/// - 監査枠: [`ServerOutcome::RejectedPeerCredential`] のイベントだけを積む別枠
///   （行数上限 [`SERVER_AUDIT_LOG_CAPACITY`]・合計バイト数上限
///   [`MAX_SERVER_AUDIT_LOG_BUFFER_BYTES`]）。満杯になっても拒否を捨てず、
///   以降の拒否を 1 件の集約レコードに合算する（件数・最後の接続元 uid）。
///   集約が始まった後は、drain するまで以降の拒否をすべて集約する（欠けた区間を
///   1 か所の連続した区間にするため）
///
/// 2 つの枠は互いに追い出し合わない（通常イベントが大量に来ても拒否イベントは
/// 積め、拒否イベントが大量に来ても通常イベントは積める）。ためる量の上限は
/// 通常枠 [`MAX_SEND_LOG_BUFFER_BYTES`] + 監査枠
/// [`MAX_SERVER_AUDIT_LOG_BUFFER_BYTES`] + 集約行 1 行（数値のみ）である。
/// `message` の切り詰め長（[`MAX_SEND_LOG_MESSAGE_BYTES`]）は両枠で共通。
///
/// 集約が 1 度でも起きると [`Self::audit_degraded`] が `true` になり、drain
/// 後も `false` に戻らない（監査記録の個別行が欠けたことを後から判別できる
/// ようにする）。集約した拒否の累計は [`Self::coalesced_peer_credential_rejections`]
/// で得られる。
///
/// # 出力キー
/// 通常の行のキーは [`JsonLinesSendObserver`] と共通の語彙に `op`・
/// `accept_aborted_retries`・`peer_credential_rejections`・`peer_uid` を
/// 加えたもの: `event`（常に `"io_server"`）・
/// `op`（`"accept"`/`"recv"`/`"send"`）・`kind`（`WRITE`/`ACK`/`FLUSH`/
/// `FLUSH_ACK`。[`ServerEvent::kind`] が `None` の場合はキー自体を省く）・
/// `outcome`（`"ok"`/`"error"`）・`reason`（失敗系のみ。[`ServerOutcome`] の
/// snake_case 名。`rejected_poisoned` で P1-3 の poison 拒否・
/// `rejected_peer_credential` で peer credential 拒否〔H1・#820
/// security-auditor 指摘対応〕を区別できる。下記の集約行だけは
/// `peer_credential_rejections_coalesced` を使う）・
/// `code`（失敗系のみ・ERR-1 文字列）・`message`（失敗系のみ・切り詰め済み・
/// エスケープ済み）・`message_truncated`（切り詰め発生時のみ `true`）・
/// `accept_aborted_retries`（`u32`）・`peer_credential_rejections`（`u32`。H1・
/// #820）・`peer_uid`（`u32`。[`ServerEvent::peer_uid`] が `Some` の場合のみ
/// キーを出す。H1・#820）・`coalesced`・`count`・`latency_sum_us`（下記の集約
/// イベントのみ）・`latency_us`。フィールドの出力順はこの記載順に固定する。
///
/// [`ServerEvent::coalesced`] が `Some` の集約イベント（分割後の両半分が共有する
/// 保留キューがあふれた分を `(op, kind, outcome, code)` ごとにまとめたもの。
/// #1118・REPAIR-4）は、通常の行と同じキーに `"coalesced":true`・`count`
/// （集約した操作の件数。`u64`）・`latency_sum_us`（所要時間の合計）を
/// `latency_us` の直前へ加え、`latency_us` は **最大値** を表す。`reason`・`code`
/// は集約した操作の値そのもので、`message` は最後に集約した操作のもの。
/// これらのキーがない行は 1 行 1 操作である（件数を数える側は、`count` があれば
/// その値、なければ 1 として数える）。
///
/// 集約行は `event`（`"io_server"`）・`op`（`"accept"`）・`outcome`
/// （`"error"`）・`reason`（`"peer_credential_rejections_coalesced"`）・
/// `count`（集約した件数。`u64`）・`last_peer_uid`（最後に集約した拒否の
/// 接続元 uid。取得できなかった場合はキー自体を省く）の順で出す
/// （`encode_coalesced_rejections`）。
///
/// # `on_event` は I/O をしない（REPAIR-5）
/// [`JsonLinesSendObserver`] と同じ理由（そのドキュメント参照）で、
/// [`ServerObserver::on_event`] はメモリ内の枠へ積む（または集約レコードの
/// 数値を更新する）だけにとどめ、実際の書き出しは呼び出し元が
/// [`Self::drain_lines`] で取り出して行う。
pub struct JsonLinesServerObserver {
    /// 通常枠（peer credential 拒否以外）。
    buf: BoundedJsonLines,
    /// 監査枠（[`ServerOutcome::RejectedPeerCredential`] 専用）。この枠の
    /// `dropped_count` は使わない（あふれた拒否は `pending_gap` へ合算する）。
    audit: BoundedJsonLines,
    /// 監査枠があふれてから drain するまでの拒否の集約レコード。
    pending_gap: Option<CoalescedRejections>,
    /// 次のイベントに付ける順序番号（`on_event` の呼び出しごとに 1 増やす。
    /// saturating のため `u64::MAX` 回を超えると同じ番号が続くが、その場合も
    /// マージは通常枠を先に出すだけで行は失われない）。
    next_seq: u64,
    /// 集約した拒否の累計（saturating。drain では戻さない）。
    coalesced_total: u64,
    /// 集約が 1 度でも起きたか（sticky。drain では戻さない）。
    audit_degraded: bool,
}

impl JsonLinesServerObserver {
    /// 既定容量（通常枠 [`DEFAULT_SEND_LOG_CAPACITY`]）で観測フックを作る。
    pub fn new() -> Self {
        Self::from_normal(BoundedJsonLines::new())
    }

    /// 通常枠の容量を指定して観測フックを作る。`capacity` が `0` または
    /// [`MAX_SEND_LOG_CAPACITY`] を超える場合は [`IoErrorCode::InvalidArgument`]
    /// を返す（無制限確保の防止）。監査枠の上限（[`SERVER_AUDIT_LOG_CAPACITY`]・
    /// [`MAX_SERVER_AUDIT_LOG_BUFFER_BYTES`]）は固定で、この引数の影響を受けない。
    pub fn with_capacity(capacity: usize) -> Result<Self, IoError> {
        Ok(Self::from_normal(BoundedJsonLines::try_with_capacity(
            capacity,
            "server log",
        )?))
    }

    fn from_normal(buf: BoundedJsonLines) -> Self {
        Self {
            buf,
            audit: BoundedJsonLines::with_limits(
                SERVER_AUDIT_LOG_CAPACITY,
                MAX_SERVER_AUDIT_LOG_BUFFER_BYTES,
            ),
            pending_gap: None,
            next_seq: 0,
            coalesced_total: 0,
            audit_degraded: false,
        }
    }

    /// 通常枠の容量（行数上限）を返す（監査枠の上限は
    /// [`SERVER_AUDIT_LOG_CAPACITY`]）。
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// 次の [`Self::drain_lines`] が返す行数（通常枠 + 監査枠 + 集約行があれば
    /// 1）を返す。
    pub fn len(&self) -> usize {
        self.buf
            .len()
            .saturating_add(self.audit.len())
            .saturating_add(usize::from(self.pending_gap.is_some()))
    }

    /// 次の [`Self::drain_lines`] が返す行が 1 件もないかを返す
    /// （集約行だけが残っている場合も `false`）。
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty() && self.audit.is_empty() && self.pending_gap.is_none()
    }

    /// 通常枠で容量超過により破棄した（新規イベント側を破棄した）件数を返す。
    /// peer credential 拒否は破棄せず集約するため、この件数には含まれない
    /// （集約した件数は [`Self::coalesced_peer_credential_rejections`]）。
    pub fn dropped_count(&self) -> u64 {
        self.buf.dropped_count()
    }

    /// 監査枠があふれたために個別の行ではなく集約行へ合算した
    /// [`ServerOutcome::RejectedPeerCredential`] の件数の累計を返す（saturating。
    /// drain しても戻らない。SEC-4・#820 codex P0 指摘対応）。
    ///
    /// 合算した拒否は失われず、[`Self::drain_lines`] の集約行（`count`）として
    /// 現れる。`0` でなければ、その件数ぶんの拒否は個別の行（`message`・
    /// `latency_us` 等の詳細）を持たないことを示す。
    pub fn coalesced_peer_credential_rejections(&self) -> u64 {
        self.coalesced_total
    }

    /// 監査枠があふれて拒否の集約が 1 度でも起きたかを返す（sticky。drain
    /// しても `false` に戻らない。SEC-4・#820 codex P0 指摘対応）。
    ///
    /// `true` は「監査記録の一部が個別の行ではなく集約行でしか残っていない」
    /// 監査上の劣化を示す。呼び出し元（永続的な監査ログ配線。後続
    /// sub-issue・要起票）はこれを監査障害として扱い、drain の頻度を上げる等の
    /// 対応をとる。
    pub fn audit_degraded(&self) -> bool {
        self.audit_degraded
    }

    /// 通常枠と監査枠にためている JSON 行の合計バイト数（改行を含まない）を
    /// 返す（集約行は drain 時に組み立てるため含まない。集約行の長さは
    /// 256 バイト以下）。
    pub fn total_bytes(&self) -> usize {
        self.buf
            .total_bytes()
            .saturating_add(self.audit.total_bytes())
    }

    /// ためている JSON 行をすべて取り出して空にする（各行は改行を含まない完全な
    /// JSON 文字列）。書き出し・再試行は呼び出し元の責務
    /// （[`JsonLinesSendObserver::drain_lines`] と同じ契約）。
    ///
    /// # 1 本の API で両枠を到着順に返す理由（SEC-4・#820 codex P0 指摘対応）
    /// 通常枠・監査枠・集約行を、イベントが `on_event` に届いた順（順序番号順）に
    /// マージして 1 本の `Vec` で返す。集約行は最初に集約した拒否が届いた位置に
    /// 置き、欠けた区間が他のイベントとの前後関係のどこから始まったかを示す。
    /// 監査枠専用の drain API を別に設けると、既存の呼び出し元
    /// （`drain_lines` だけを呼ぶ）が監査枠を取り出さず、監査枠が満杯のまま
    /// 集約し続ける（実質的に個別の記録が黙って失われる）ため採らない。
    ///
    /// 集約行を出した後は集約レコードを空に戻す（次に監査枠があふれたときは
    /// 新しい集約行を始める）。[`Self::audit_degraded`] と
    /// [`Self::coalesced_peer_credential_rejections`] は戻さない。
    pub fn drain_lines(&mut self) -> Vec<String> {
        let mut normal = self.buf.drain_sequenced();
        let mut audit = self.audit.drain_sequenced();
        if let Some(gap) = self.pending_gap.take() {
            // 集約レコードの `first_seq` は監査枠に積めた行のどれよりも後
            // （集約が始まった後は drain まで個別に積まない）のため、監査枠の
            // 末尾へ足しても順序番号順が保たれる。
            audit.push_back((gap.first_seq, encode_coalesced_rejections(&gap)));
        }
        let mut lines = Vec::with_capacity(normal.len().saturating_add(audit.len()));
        loop {
            let take_normal = match (normal.front(), audit.front()) {
                (Some((normal_seq, _)), Some((audit_seq, _))) => normal_seq <= audit_seq,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => break,
            };
            let next = if take_normal {
                normal.pop_front()
            } else {
                audit.pop_front()
            };
            if let Some((_, line)) = next {
                lines.push(line);
            }
        }
        lines
    }

    /// peer credential 拒否を監査枠へ積む。監査枠が満杯（または集約中）なら
    /// 集約レコードへ合算する（捨てない）。
    fn record_rejection(&mut self, seq: u64, event: &ServerEvent<'_>) {
        if let Some(gap) = self.pending_gap.as_mut() {
            gap.count = gap.count.saturating_add(1);
            gap.last_peer_uid = event.peer_uid;
        } else if self
            .audit
            .push_encoded_line(seq, || encode_server_event(event))
        {
            // 個別の行として積めた（集約は起きていない）。
            return;
        } else {
            self.pending_gap = Some(CoalescedRejections {
                first_seq: seq,
                count: 1,
                last_peer_uid: event.peer_uid,
            });
        }
        self.coalesced_total = self.coalesced_total.saturating_add(1);
        self.audit_degraded = true;
    }
}

impl Default for JsonLinesServerObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerObserver for JsonLinesServerObserver {
    fn on_event(&mut self, event: &ServerEvent<'_>) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        if event.outcome == ServerOutcome::RejectedPeerCredential {
            self.record_rejection(seq, event);
        } else {
            self.buf
                .push_encoded_line(seq, || encode_server_event(event));
        }
    }
}

/// ためた JSON 行の中身を誤ってダンプしないよう、件数・破棄数・合計バイト数のみを
/// 出す手書きの `Debug` 実装（[`JsonLinesSendObserver`] と同じ理由）。
impl fmt::Debug for JsonLinesServerObserver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonLinesServerObserver")
            .field("len", &self.buf.len())
            .field("capacity", &self.buf.capacity())
            .field("dropped", &self.buf.dropped_count())
            .field("audit_len", &self.audit.len())
            .field("pending_gap", &self.pending_gap)
            .field(
                "coalesced_peer_credential_rejections",
                &self.coalesced_total,
            )
            .field("audit_degraded", &self.audit_degraded)
            .field("total_bytes", &self.total_bytes())
            .finish()
    }
}

/// 監査枠があふれた区間の集約レコードを 1 行の JSON Lines 文字列へエンコード
/// する（改行は含まない。SEC-4・#820 codex P0 指摘対応）。数値と固定語彙だけで
/// 組み立て、untrusted な文字列を含めない。出力長は
/// [`MAX_SERVER_AUDIT_GAP_LINE_BYTES`] 以下（最悪ケースはテストで照合する）。
fn encode_coalesced_rejections(gap: &CoalescedRejections) -> String {
    let count = gap.count;
    let last_peer_uid = match gap.last_peer_uid {
        Some(uid) => format!(",\"last_peer_uid\":{uid}"),
        None => String::new(),
    };
    format!(
        "{{\"event\":\"io_server\",\"op\":\"accept\",\"outcome\":\"error\",\
         \"reason\":\"peer_credential_rejections_coalesced\",\"count\":{count}{last_peer_uid}}}"
    )
}

fn server_op_str(op: ServerOp) -> &'static str {
    match op {
        ServerOp::Accept => "accept",
        ServerOp::Recv => "recv",
        ServerOp::Send => "send",
    }
}

/// [`ServerOutcome`] の snake_case 名を返す（[`outcome_reason_str`] の UDS
/// サーバー版。TASK-13.2.1・#820）。
fn server_outcome_reason_str(outcome: ServerOutcome) -> &'static str {
    match outcome {
        ServerOutcome::Success => "success",
        ServerOutcome::RejectedPoisoned => "rejected_poisoned",
        ServerOutcome::RejectedPeerCredential => "rejected_peer_credential",
        ServerOutcome::Failure => "failure",
    }
}

/// `event.kind` から `"kind":"WRITE",` の先頭カンマなし・末尾カンマありの
/// 断片を組み立てる（[`ack_kind_json_fragment`] の `kind` 版。`None` の場合は
/// フィールド自体を省く）。
fn server_kind_json_fragment(kind: Option<FrameKind>) -> String {
    match kind {
        Some(kind) => format!("\"kind\":\"{}\",", frame_kind_str(kind)),
        None => String::new(),
    }
}

/// `event.peer_uid` から `"peer_uid":123,` の先頭カンマなし・末尾カンマありの
/// 断片を組み立てる（[`server_kind_json_fragment`] と同じパターン。`None` の
/// 場合はフィールド自体を省く。H1・#820 security-auditor 指摘対応）。
fn peer_uid_json_fragment(peer_uid: Option<u32>) -> String {
    match peer_uid {
        Some(uid) => format!("\"peer_uid\":{uid},"),
        None => String::new(),
    }
}

/// `event.coalesced` から `"coalesced":true,"count":N,"latency_sum_us":S,` の
/// 末尾カンマありの断片を組み立てる（`None` の場合は何も出さない。#1118）。
fn coalesced_json_fragment(coalesced: Option<CoalescedServerEvents>) -> String {
    match coalesced {
        Some(c) => format!(
            "\"coalesced\":true,\"count\":{},\"latency_sum_us\":{},",
            c.count,
            c.latency_sum.as_micros()
        ),
        None => String::new(),
    }
}

/// [`ServerEvent`] を 1 行の JSON Lines 文字列へエンコードする（改行は含まない。
/// [`encode_send_event`] の UDS サーバー版。TASK-13.2.1・#820）。出力長は
/// [`MAX_SERVER_LOG_LINE_BYTES`] 以下（固定語彙・数値と切り詰め済みの `message`
/// だけで組み立てるため。最悪ケースはテストで照合する）。
fn encode_server_event(event: &ServerEvent<'_>) -> String {
    let latency_us = event.latency.as_micros();
    let op = server_op_str(event.op);
    let kind = server_kind_json_fragment(event.kind);
    let retries = event.accept_aborted_retries;
    let cred_rejections = event.peer_credential_rejections;
    let peer_uid = peer_uid_json_fragment(event.peer_uid);
    let coalesced = coalesced_json_fragment(event.coalesced);
    match (&event.outcome, &event.error) {
        (ServerOutcome::Success, _) => {
            format!(
                "{{\"event\":\"io_server\",\"op\":\"{op}\",{kind}\"outcome\":\"ok\",\
                 \"accept_aborted_retries\":{retries},\
                 \"peer_credential_rejections\":{cred_rejections},{peer_uid}\
                 {coalesced}\"latency_us\":{latency_us}}}"
            )
        }
        (outcome, Some(error)) => {
            let reason = server_outcome_reason_str(*outcome);
            let code = error.code.as_str();
            let (truncated_message, truncated) = truncate_message_bytes(error.message);
            let message = escape_json_string(truncated_message);
            if truncated {
                format!(
                    "{{\"event\":\"io_server\",\"op\":\"{op}\",{kind}\"outcome\":\"error\",\
                     \"reason\":\"{reason}\",\"code\":\"{code}\",\"message\":\"{message}\",\
                     \"message_truncated\":true,\"accept_aborted_retries\":{retries},\
                     \"peer_credential_rejections\":{cred_rejections},{peer_uid}\
                     {coalesced}\"latency_us\":{latency_us}}}"
                )
            } else {
                format!(
                    "{{\"event\":\"io_server\",\"op\":\"{op}\",{kind}\"outcome\":\"error\",\
                     \"reason\":\"{reason}\",\"code\":\"{code}\",\"message\":\"{message}\",\
                     \"accept_aborted_retries\":{retries},\
                     \"peer_credential_rejections\":{cred_rejections},{peer_uid}\
                     {coalesced}\"latency_us\":{latency_us}}}"
                )
            }
        }
        (outcome, None) => {
            // 契約上 `Success` 以外は必ず `error` を伴う（`crate::server` が
            // 組み立てる）が、型としては `Option` のため、万一 `None` が来ても
            // panic せず `code`/`message` を省いた行を出す（`encode_send_event`
            // と同じフォールバック方針）。
            let reason = server_outcome_reason_str(*outcome);
            format!(
                "{{\"event\":\"io_server\",\"op\":\"{op}\",{kind}\"outcome\":\"error\",\
                 \"reason\":\"{reason}\",\"accept_aborted_retries\":{retries},\
                 \"peer_credential_rejections\":{cred_rejections},{peer_uid}\
                 {coalesced}\"latency_us\":{latency_us}}}"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn success_event(latency_us: u64) -> SendEvent<'static> {
        SendEvent {
            kind: FrameKind::Write,
            outcome: SendOutcome::Success,
            latency: Duration::from_micros(latency_us),
            error: None,
        }
    }

    // `message` の借用をそのまま `SendEvent` へ渡す（#73 P0 再指摘対応の借用型化
    // 以降、テストヘルパーは所有型の値を返せない。呼び出し元が所有する文字列
    // から借用する形にする）。
    fn failure_event(
        kind: FrameKind,
        outcome: SendOutcome,
        code: IoErrorCode,
        message: &str,
        latency_us: u64,
    ) -> SendEvent<'_> {
        SendEvent {
            kind,
            outcome,
            latency: Duration::from_micros(latency_us),
            error: Some(SendEventError { code, message }),
        }
    }

    /// REPAIR-4: 成功イベントが `outcome":"ok"` の 1 行 JSON として `drain_lines`
    /// から取り出せる（改行は含まない）。
    #[test]
    fn repair4_json_lines_observer_encodes_success_event() {
        let mut observer = JsonLinesSendObserver::new();
        observer.on_send(&success_event(123));

        let lines = observer.drain_lines();
        assert_eq!(
            lines,
            vec![
                "{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"ok\",\"latency_us\":123}"
            ]
        );
        assert!(observer.is_empty());
    }

    /// REPAIR-4: トランスポート失敗イベントが `outcome":"error"` と `code` を含む
    /// 1 行 JSON になる。
    #[test]
    fn repair4_json_lines_observer_encodes_transport_failure_event() {
        let mut observer = JsonLinesSendObserver::new();
        observer.on_send(&failure_event(
            FrameKind::Write,
            SendOutcome::TransportFailure,
            IoErrorCode::Timeout,
            "ack not received within timeout",
            456,
        ));

        let lines = observer.drain_lines();
        assert_eq!(
            lines,
            vec![
                "{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"error\",\
                 \"reason\":\"transport_failure\",\"code\":\"TIMEOUT\",\
                 \"message\":\"ack not received within timeout\",\"latency_us\":456}"
            ]
        );
    }

    /// REPAIR-4: 未 ACK 上限到達（早期拒否・`latency` は `ZERO`）イベントが
    /// `latency_us":0` を含む 1 行 JSON になる。
    #[test]
    fn repair4_json_lines_observer_encodes_resource_exhausted_event() {
        let mut observer = JsonLinesSendObserver::new();
        observer.on_send(&failure_event(
            FrameKind::Write,
            SendOutcome::RejectedResourceExhausted,
            IoErrorCode::ResourceExhausted,
            "in-flight limit reached",
            0,
        ));

        let lines = observer.drain_lines();
        assert_eq!(
            lines,
            vec![
                "{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"error\",\
                 \"reason\":\"rejected_resource_exhausted\",\"code\":\"RESOURCE_EXHAUSTED\",\
                 \"message\":\"in-flight limit reached\",\"latency_us\":0}"
            ]
        );
    }

    /// REPAIR-4・security.md「インジェクション」観点: `message` 内の `"`・`\`・
    /// 改行が JSON 文字列として正しくエスケープされる（untrusted なトランスポート
    /// エラーメッセージが JSON 構造を壊すのを防ぐ）。
    #[test]
    fn repair4_json_lines_observer_escapes_message_special_characters() {
        let mut observer = JsonLinesSendObserver::new();
        observer.on_send(&failure_event(
            FrameKind::Flush,
            SendOutcome::RejectedInvalidFrameKind,
            IoErrorCode::InvalidArgument,
            "bad \"frame\"\\payload\nwith control chars",
            0,
        ));

        let lines = observer.drain_lines();
        assert_eq!(
            lines,
            vec![
                "{\"event\":\"io_send\",\"kind\":\"FLUSH\",\"outcome\":\"error\",\
                 \"reason\":\"rejected_invalid_frame_kind\",\"code\":\"INVALID_ARGUMENT\",\
                 \"message\":\"bad \\\"frame\\\"\\\\payload\\nwith control chars\",\
                 \"latency_us\":0}"
            ]
        );
    }

    /// REPAIR-5: `with_capacity(0)` と `MAX_SEND_LOG_CAPACITY + 1` は
    /// `InvalidArgument` で拒否される（無制限確保の防止）。
    #[test]
    fn repair5_json_lines_observer_with_capacity_rejects_out_of_range() {
        let zero_err = JsonLinesSendObserver::with_capacity(0).expect_err("zero must be rejected");
        assert_eq!(zero_err.code(), IoErrorCode::InvalidArgument);

        let over_err = JsonLinesSendObserver::with_capacity(MAX_SEND_LOG_CAPACITY + 1)
            .expect_err("MAX_SEND_LOG_CAPACITY + 1 must be rejected");
        assert_eq!(over_err.code(), IoErrorCode::InvalidArgument);
    }

    /// REPAIR-5（codex 再指摘対応）: 容量に達すると新規イベントを破棄し
    /// `dropped_count` を増分する。ためた行は最古（先に来た）2 件のまま変わらず、
    /// 3 件目（新規側）が破棄されたことを確認する。
    #[test]
    fn repair5_json_lines_observer_drops_newest_when_full() {
        let mut observer =
            JsonLinesSendObserver::with_capacity(2).expect("2 must be a valid capacity");

        observer.on_send(&success_event(1));
        observer.on_send(&success_event(2));
        observer.on_send(&success_event(3));

        assert_eq!(observer.len(), 2);
        assert_eq!(observer.dropped_count(), 1);

        let lines = observer.drain_lines();
        assert_eq!(
            lines,
            vec![
                "{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"ok\",\"latency_us\":1}",
                "{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"ok\",\"latency_us\":2}",
            ]
        );
        assert!(observer.is_empty());
    }

    /// REPAIR-4・REPAIR-5（codex P0 再指摘対応）: `MAX_SEND_LOG_MESSAGE_BYTES` を
    /// 超える `message` は上限まで切り詰められ、`message_truncated":true` が
    /// 付与された 1 行の JSON が具体値どおりに出力される。
    #[test]
    fn repair4_repair5_json_lines_observer_truncates_oversized_message() {
        let mut observer = JsonLinesSendObserver::new();
        let huge_message = "a".repeat(MAX_SEND_LOG_MESSAGE_BYTES + 100);
        observer.on_send(&failure_event(
            FrameKind::Write,
            SendOutcome::TransportFailure,
            IoErrorCode::Timeout,
            &huge_message,
            0,
        ));

        let lines = observer.drain_lines();
        let expected_message = "a".repeat(MAX_SEND_LOG_MESSAGE_BYTES);
        assert_eq!(
            lines,
            vec![format!(
                "{{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"error\",\
                 \"reason\":\"transport_failure\",\"code\":\"TIMEOUT\",\
                 \"message\":\"{expected_message}\",\"message_truncated\":true,\
                 \"latency_us\":0}}"
            )]
        );
    }

    /// REPAIR-4・REPAIR-5（codex P0 再指摘対応）: マルチバイト文字（3 バイトの
    /// 日本語）が上限バイト数ちょうどで割れる場合でも、文字境界を跨がず不正な
    /// UTF-8 を生成せず、切り詰め後の具体値どおりの JSON になる。
    #[test]
    fn repair4_repair5_json_lines_observer_truncates_multibyte_message_on_char_boundary() {
        let mut observer = JsonLinesSendObserver::new();
        // 3 バイト文字（"あ"）を大量に連結し、`MAX_SEND_LOG_MESSAGE_BYTES` が
        // 3 の倍数でない場合に境界を跨ぐ入力になることを確認する。
        let repeat_count = MAX_SEND_LOG_MESSAGE_BYTES; // 3 バイト * MAX 個で確実に超過させる
        let huge_message = "あ".repeat(repeat_count);
        assert!(huge_message.len() > MAX_SEND_LOG_MESSAGE_BYTES);

        observer.on_send(&failure_event(
            FrameKind::Write,
            SendOutcome::TransportFailure,
            IoErrorCode::Timeout,
            &huge_message,
            0,
        ));

        let lines = observer.drain_lines();
        let max_chars = MAX_SEND_LOG_MESSAGE_BYTES / "あ".len();
        let expected_message = "あ".repeat(max_chars);
        assert_eq!(
            lines,
            vec![format!(
                "{{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"error\",\
                 \"reason\":\"transport_failure\",\"code\":\"TIMEOUT\",\
                 \"message\":\"{expected_message}\",\"message_truncated\":true,\
                 \"latency_us\":0}}"
            )]
        );
    }

    /// REPAIR-5（codex P0 再指摘対応）: 行数上限とは独立に、合計バイト数が
    /// `MAX_SEND_LOG_BUFFER_BYTES` を超える新規イベントは破棄され
    /// `dropped_count` が増分する。`drain_lines` 後は合計バイト数がリセットされ、
    /// 再び積めるようになる。
    #[test]
    fn repair5_json_lines_observer_drops_when_total_bytes_exceeds_limit() {
        // 容量（行数）は十分大きく取り、バイト数上限のみで破棄させる。
        let mut observer =
            JsonLinesSendObserver::with_capacity(MAX_SEND_LOG_CAPACITY).expect("valid capacity");

        // 1 行あたり最大サイズに近いメッセージを積み、総バイト数上限へ到達させる。
        let near_max_message = "b".repeat(MAX_SEND_LOG_MESSAGE_BYTES);
        let mut pushed = 0usize;
        loop {
            let before = observer.total_bytes();
            observer.on_send(&failure_event(
                FrameKind::Write,
                SendOutcome::TransportFailure,
                IoErrorCode::Timeout,
                &near_max_message,
                0,
            ));
            if observer.total_bytes() == before {
                // 増えなかった = このイベントは破棄された（上限到達）。
                break;
            }
            pushed += 1;
        }

        assert!(pushed > 0, "at least one line must fit before the limit");
        assert_eq!(observer.dropped_count(), 1);
        assert!(observer.total_bytes() <= MAX_SEND_LOG_BUFFER_BYTES);

        let lines = observer.drain_lines();
        assert_eq!(lines.len(), pushed);
        assert_eq!(observer.total_bytes(), 0);
        assert!(observer.is_empty());

        // drain 後は再び積める。
        observer.on_send(&success_event(1));
        assert_eq!(observer.len(), 1);
        assert!(observer.total_bytes() > 0);
    }

    /// NoopSendObserver は何もしない（既定実装が送信経路の動作へ影響しないことの
    /// 確認。TASK-12.1・#73 codex 指摘対応）。
    #[test]
    fn repair4_noop_send_observer_does_nothing() {
        let mut observer = NoopSendObserver;
        observer.on_send(&success_event(1));
        // panic せず戻ることのみを確認する（副作用を持たない契約）。
    }

    /// REPAIR-5 P0 再指摘対応・#73（コミット 2・受け入れ基準の機械照合。REPAIR-12）:
    /// `SendEventError` の手書き `Debug` は `message` を全量出力せず、長さと
    /// `MAX_SEND_LOG_MESSAGE_BYTES` 以内に切り詰めた先頭のみを出す（`{:?}` 経由で
    /// untrusted なメッセージが無制限に出力される経路をふさいだことの確認）。
    #[test]
    fn repair5_send_event_error_debug_truncates_message() {
        let huge_message = "a".repeat(MAX_SEND_LOG_MESSAGE_BYTES * 4);
        let error = SendEventError {
            code: IoErrorCode::Timeout,
            message: &huge_message,
        };

        let debug_output = format!("{error:?}");

        assert!(
            debug_output.contains(&format!("message_len: {}", huge_message.len())),
            "debug output must report the true (untruncated) message length: {debug_output}"
        );
        assert!(
            debug_output.contains(&"a".repeat(MAX_SEND_LOG_MESSAGE_BYTES)),
            "debug output must contain the truncated prefix: {debug_output}"
        );
        assert!(
            !debug_output.contains(&"a".repeat(MAX_SEND_LOG_MESSAGE_BYTES + 1)),
            "debug output must not contain more than MAX_SEND_LOG_MESSAGE_BYTES \
             consecutive characters of the message: {debug_output}"
        );
        assert!(
            debug_output.len() < huge_message.len(),
            "debug output ({} bytes) must be far shorter than the full message ({} bytes); \
             a regression to dumping the whole message would fail this bound",
            debug_output.len(),
            huge_message.len()
        );
    }

    /// REPAIR-5 P0 再指摘対応・#73（コミット 2・REPAIR-12）: `SendEvent` の手書き
    /// `Debug` も `error` フィールド経由で `SendEventError` の `Debug` へ委譲し、
    /// 同様に全量を出さない。
    #[test]
    fn repair5_send_event_debug_delegates_to_error_debug() {
        let huge_message = "b".repeat(MAX_SEND_LOG_MESSAGE_BYTES * 4);
        let event = SendEvent {
            kind: FrameKind::Write,
            outcome: SendOutcome::TransportFailure,
            latency: Duration::from_millis(1),
            error: Some(SendEventError {
                code: IoErrorCode::Timeout,
                message: &huge_message,
            }),
        };

        let debug_output = format!("{event:?}");

        assert!(
            !debug_output.contains(&"b".repeat(MAX_SEND_LOG_MESSAGE_BYTES + 1)),
            "SendEvent's Debug must not leak the full untruncated message: {debug_output}"
        );
        assert!(debug_output.len() < huge_message.len());
    }

    /// REPAIR-4・REPAIR-12（#73。コミット 2）: 1 行の最悪ケース（`encode_send_event`
    /// の出力が最も長くなる組み合わせ）でも `MAX_SEND_LOG_LINE_BYTES` を超えない
    /// ことを機械照合する。
    ///
    /// 最悪ケースの根拠（`encode_send_event` の実装を確認して選定）:
    /// - `kind`: [`FrameKind::FlushAck`]（`"FLUSH_ACK"`。9 バイトで 4 種別中最長。
    ///   [`frame_kind_str`] 参照）
    /// - `outcome`/`reason`: [`SendOutcome::RejectedResourceExhausted`]
    ///   （`"rejected_resource_exhausted"`。27 バイトで `"rejected_invalid_frame_kind"`
    ///   〔同じく 27 バイト〕と並ぶ最長タイ。[`outcome_reason_str`] 参照）だが、
    ///   対応する `code` が [`IoErrorCode::ResourceExhausted`]
    ///   （`"RESOURCE_EXHAUSTED"`。18 バイトで全 `IoErrorCode` バリアント中最長。
    ///   `InvalidArgument` の `"INVALID_ARGUMENT"` は 16 バイト）であるため、
    ///   `reason` と `code` の合計ではこちらの組み合わせがより悪い
    /// - `message`: [`MAX_SEND_LOG_MESSAGE_BYTES`] を超える長さの `\u{0001}`
    ///   （1 バイトの制御文字）。1 バイト文字なので文字境界の調整なしに正確に
    ///   `MAX_SEND_LOG_MESSAGE_BYTES` 文字ちょうどまで切り詰められ、
    ///   [`escape_json_string`] がその全文字を `\u0001`（6 バイト）へ展開する
    ///   最悪のエスケープ後サイズになる（`\n`/`\r`/`\t` は 2 バイトにしか
    ///   展開されないため選ばない）
    /// - `latency`: `Duration::MAX`（`as_micros()` の桁数が最大になる）
    #[test]
    fn repair4_repair12_encode_send_event_worst_case_line_fits_within_max_line_bytes() {
        let oversized_control_chars = "\u{0001}".repeat(MAX_SEND_LOG_MESSAGE_BYTES + 1);
        let event = SendEvent {
            kind: FrameKind::FlushAck,
            outcome: SendOutcome::RejectedResourceExhausted,
            latency: Duration::MAX,
            error: Some(SendEventError {
                code: IoErrorCode::ResourceExhausted,
                message: &oversized_control_chars,
            }),
        };

        let encoded = encode_send_event(&event);

        assert!(
            encoded.contains("\"message_truncated\":true"),
            "the oversized message must trigger truncation: {encoded}"
        );
        // 実際に 512 文字すべてが `\u0001`（6 バイト）へ展開されたことを数えて
        // 確認する。長さの比較だけでは、6 倍のエスケープが起きていなくても
        // たまたま緩い上限を満たしてしまう可能性がある（誤って弱いテストに
        // ならないための直接照合）。
        let escaped_control_char_count = encoded.matches("\\u0001").count();
        assert_eq!(
            escaped_control_char_count, MAX_SEND_LOG_MESSAGE_BYTES,
            "expected exactly MAX_SEND_LOG_MESSAGE_BYTES escaped control characters: {encoded}"
        );
        assert!(
            encoded.len() <= MAX_SEND_LOG_LINE_BYTES,
            "encoded line ({} bytes) must fit within MAX_SEND_LOG_LINE_BYTES ({} bytes)",
            encoded.len(),
            MAX_SEND_LOG_LINE_BYTES
        );
    }

    /// TASK-12.2・#74 codex P1 再指摘対応（IO-1・IO-2・REPAIR-4）: 成功した
    /// [`FrameKind::Ack`] の受信は `ack_kind":"ACK"` を含み、通常のバッファリング
    /// ACK であることが構造化ログから判別できる。
    #[test]
    fn repair4_encode_ack_event_success_includes_ack_kind() {
        let event = AckEvent {
            outcome: AckOutcome::Success,
            ack_kind: Some(FrameKind::Ack),
            latency: Duration::from_micros(42),
            error: None,
        };

        assert_eq!(
            encode_ack_event(&event),
            "{\"event\":\"io_recv_ack\",\"ack_kind\":\"ACK\",\"outcome\":\"ok\",\"latency_us\":42}"
        );
    }

    /// TASK-12.2・#74 codex P1 再指摘対応（IO-1・IO-2・REPAIR-4）: 成功した
    /// [`FrameKind::FlushAck`] の受信は `ack_kind":"FLUSH_ACK"` を含み、通常の
    /// ACK（IO-1）と永続化保証の FlushAck（IO-2）が構造化ログ上で区別できる。
    #[test]
    fn repair4_encode_ack_event_success_distinguishes_flush_ack() {
        let event = AckEvent {
            outcome: AckOutcome::Success,
            ack_kind: Some(FrameKind::FlushAck),
            latency: Duration::from_micros(7),
            error: None,
        };

        assert_eq!(
            encode_ack_event(&event),
            "{\"event\":\"io_recv_ack\",\"ack_kind\":\"FLUSH_ACK\",\"outcome\":\"ok\",\"latency_us\":7}"
        );
    }

    /// TASK-12.2・#74 codex P1 再指摘対応（IO-1・IO-2・REPAIR-4）: `decode_ack`
    /// 前の早期拒否（`ack_kind: None`）は種別が確定していないため `ack_kind`
    /// フィールド自体を出力しない（[`AckEvent::ack_kind`] のドキュメント参照）。
    #[test]
    fn repair4_encode_ack_event_early_reject_omits_ack_kind() {
        let message = "recv_ack called with no in-flight requests to match against";
        let event = AckEvent {
            outcome: AckOutcome::RejectedNoInFlight,
            ack_kind: None,
            latency: Duration::ZERO,
            error: Some(AckEventError {
                code: IoErrorCode::InvalidArgument,
                message,
            }),
        };

        let encoded = encode_ack_event(&event);
        assert!(
            !encoded.contains("\"ack_kind\""),
            "early-reject events must omit ack_kind entirely: {encoded}"
        );
        assert_eq!(
            encoded,
            "{\"event\":\"io_recv_ack\",\"outcome\":\"error\",\"reason\":\"rejected_no_in_flight\",\
             \"code\":\"INVALID_ARGUMENT\",\"message\":\"recv_ack called with no in-flight \
             requests to match against\",\"latency_us\":0}"
        );
    }

    /// TASK-13.2.1・#820（REPAIR-4）: `Accept` 成功イベントは `kind` を持たず、
    /// `accept_aborted_retries` を含む。
    #[test]
    fn repair4_encode_server_event_accept_success_omits_kind() {
        let event = ServerEvent {
            op: ServerOp::Accept,
            kind: None,
            outcome: ServerOutcome::Success,
            latency: Duration::from_micros(10),
            accept_aborted_retries: 2,
            peer_credential_rejections: 0,
            peer_uid: None,
            coalesced: None,
            error: None,
        };

        let encoded = encode_server_event(&event);
        assert!(!encoded.contains("\"kind\""), "encoded={encoded}");
        assert_eq!(
            encoded,
            "{\"event\":\"io_server\",\"op\":\"accept\",\"outcome\":\"ok\",\
             \"accept_aborted_retries\":2,\"peer_credential_rejections\":0,\
             \"latency_us\":10}"
        );
    }

    /// TASK-13.2.1・#820（IO-1・REPAIR-4）: `Recv` の拒否（`Ack` 受信）イベントは
    /// ヘッダ検証を通過しているため `kind` を持ち、`reason` が
    /// `rejected_invalid_frame_kind` 等ではなく `failure` になる（P1-3 の poison
    /// 拒否〔`rejected_poisoned`〕とは区別される）。
    #[test]
    fn repair4_encode_server_event_recv_rejects_client_originated_ack() {
        let message = "server does not accept client-originated response frames: Ack";
        let event = ServerEvent {
            op: ServerOp::Recv,
            kind: Some(FrameKind::Ack),
            outcome: ServerOutcome::Failure,
            latency: Duration::from_micros(5),
            accept_aborted_retries: 0,
            peer_credential_rejections: 0,
            peer_uid: None,
            coalesced: None,
            error: Some(SendEventError {
                code: IoErrorCode::InvalidArgument,
                message,
            }),
        };

        let encoded = encode_server_event(&event);
        assert_eq!(
            encoded,
            "{\"event\":\"io_server\",\"op\":\"recv\",\"kind\":\"ACK\",\"outcome\":\"error\",\
             \"reason\":\"failure\",\"code\":\"INVALID_ARGUMENT\",\
             \"message\":\"server does not accept client-originated response frames: Ack\",\
             \"accept_aborted_retries\":0,\"peer_credential_rejections\":0,\
             \"latency_us\":5}"
        );
    }

    /// TASK-13.2.1・#820（P1-3・REPAIR-4）: poison 済み接続での `Send` 拒否は
    /// `reason":"rejected_poisoned"` になり、他の失敗（`failure`）と区別できる。
    #[test]
    fn repair4_encode_server_event_send_rejects_poisoned_connection() {
        let message = "connection is poisoned by a previous error and must be reconnected";
        let event = ServerEvent {
            op: ServerOp::Send,
            kind: Some(FrameKind::Ack),
            outcome: ServerOutcome::RejectedPoisoned,
            latency: Duration::ZERO,
            accept_aborted_retries: 0,
            peer_credential_rejections: 0,
            peer_uid: None,
            coalesced: None,
            error: Some(SendEventError {
                code: IoErrorCode::Unavailable,
                message,
            }),
        };

        let encoded = encode_server_event(&event);
        assert_eq!(
            encoded,
            "{\"event\":\"io_server\",\"op\":\"send\",\"kind\":\"ACK\",\"outcome\":\"error\",\
             \"reason\":\"rejected_poisoned\",\"code\":\"UNAVAILABLE\",\
             \"message\":\"connection is poisoned by a previous error and must be reconnected\",\
             \"accept_aborted_retries\":0,\"peer_credential_rejections\":0,\
             \"latency_us\":0}"
        );
    }

    /// H1・#820（PLUG-12・security.md・SEC-4）: peer credential 拒否イベントは
    /// `reason":"rejected_peer_credential"` になり、取得できた接続元の uid を
    /// `peer_uid` として数値のまま JSON へ含める。
    #[test]
    fn h1_encode_server_event_rejects_peer_credential_includes_peer_uid() {
        let message = "connecting peer uid (1000) does not match the server's effective uid (0)";
        let event = ServerEvent {
            op: ServerOp::Accept,
            kind: None,
            outcome: ServerOutcome::RejectedPeerCredential,
            latency: Duration::ZERO,
            accept_aborted_retries: 0,
            peer_credential_rejections: 1,
            peer_uid: Some(1000),
            coalesced: None,
            error: Some(SendEventError {
                code: IoErrorCode::InvalidArgument,
                message,
            }),
        };

        let encoded = encode_server_event(&event);
        assert_eq!(
            encoded,
            "{\"event\":\"io_server\",\"op\":\"accept\",\"outcome\":\"error\",\
             \"reason\":\"rejected_peer_credential\",\"code\":\"INVALID_ARGUMENT\",\
             \"message\":\"connecting peer uid (1000) does not match the server's effective \
             uid (0)\",\"accept_aborted_retries\":0,\"peer_credential_rejections\":1,\
             \"peer_uid\":1000,\"latency_us\":0}"
        );
    }

    /// H1・#820: 接続元の uid の取得自体に失敗した場合（`peer_uid` は
    /// `None`）は、`peer_uid` キー自体を省く。
    #[test]
    fn h1_encode_server_event_rejects_peer_credential_omits_peer_uid_when_unavailable() {
        let message = "getsockopt(SO_PEERCRED) failed: some os error";
        let event = ServerEvent {
            op: ServerOp::Accept,
            kind: None,
            outcome: ServerOutcome::RejectedPeerCredential,
            latency: Duration::ZERO,
            accept_aborted_retries: 0,
            peer_credential_rejections: 1,
            peer_uid: None,
            coalesced: None,
            error: Some(SendEventError {
                code: IoErrorCode::Internal,
                message,
            }),
        };

        let encoded = encode_server_event(&event);
        assert!(!encoded.contains("\"peer_uid\""), "encoded={encoded}");
    }

    /// REPAIR-5（#820 レビュー指摘）: `JsonLinesServerObserver` は容量に達すると
    /// 新規イベントを破棄し `dropped_count` を増分する（`JsonLinesSendObserver`
    /// と同じ挙動を `BoundedJsonLines` 経由で共有していることの確認）。
    #[test]
    fn repair5_json_lines_server_observer_drops_newest_when_full() {
        let mut observer =
            JsonLinesServerObserver::with_capacity(1).expect("1 must be a valid capacity");
        let accept_ok = |retries: u32| ServerEvent {
            op: ServerOp::Accept,
            kind: None,
            outcome: ServerOutcome::Success,
            latency: Duration::ZERO,
            accept_aborted_retries: retries,
            peer_credential_rejections: 0,
            peer_uid: None,
            coalesced: None,
            error: None,
        };

        observer.on_event(&accept_ok(0));
        observer.on_event(&accept_ok(1));

        assert_eq!(observer.len(), 1);
        assert_eq!(observer.dropped_count(), 1);
        let lines = observer.drain_lines();
        assert_eq!(
            lines,
            vec![
                "{\"event\":\"io_server\",\"op\":\"accept\",\"outcome\":\"ok\",\
                 \"accept_aborted_retries\":0,\"peer_credential_rejections\":0,\
                 \"latency_us\":0}"
            ]
        );
        assert!(observer.is_empty());
    }

    /// peer credential 拒否イベント（テスト用。`peer_uid` と `message` を指定する）。
    fn rejection_event(peer_uid: Option<u32>, message: &str) -> ServerEvent<'_> {
        ServerEvent {
            op: ServerOp::Accept,
            kind: None,
            outcome: ServerOutcome::RejectedPeerCredential,
            latency: Duration::ZERO,
            accept_aborted_retries: 0,
            peer_credential_rejections: 1,
            peer_uid,
            coalesced: None,
            error: Some(SendEventError {
                code: IoErrorCode::InvalidArgument,
                message,
            }),
        }
    }

    /// Accept 成功イベント（テスト用。`accept_aborted_retries` で行を区別する）。
    fn accept_ok_event(retries: u32) -> ServerEvent<'static> {
        ServerEvent {
            op: ServerOp::Accept,
            kind: None,
            outcome: ServerOutcome::Success,
            latency: Duration::ZERO,
            accept_aborted_retries: retries,
            peer_credential_rejections: 0,
            peer_uid: None,
            coalesced: None,
            error: None,
        }
    }

    fn accept_ok_line(retries: u32) -> String {
        format!(
            "{{\"event\":\"io_server\",\"op\":\"accept\",\"outcome\":\"ok\",\
             \"accept_aborted_retries\":{retries},\"peer_credential_rejections\":0,\
             \"latency_us\":0}}"
        )
    }

    fn rejection_line(peer_uid: u32) -> String {
        format!(
            "{{\"event\":\"io_server\",\"op\":\"accept\",\"outcome\":\"error\",\
             \"reason\":\"rejected_peer_credential\",\"code\":\"INVALID_ARGUMENT\",\
             \"message\":\"uid mismatch\",\"accept_aborted_retries\":0,\
             \"peer_credential_rejections\":1,\"peer_uid\":{peer_uid},\"latency_us\":0}}"
        )
    }

    /// 監査枠を行数上限（[`SERVER_AUDIT_LOG_CAPACITY`]）ちょうどまで埋める
    /// （`peer_uid` は `1000 + i`）。
    fn fill_audit_queue(observer: &mut JsonLinesServerObserver) {
        for i in 0..SERVER_AUDIT_LOG_CAPACITY {
            let uid = 1000 + u32::try_from(i).expect("fits in u32");
            observer.on_event(&rejection_event(Some(uid), "uid mismatch"));
        }
        assert_eq!(observer.coalesced_peer_credential_rejections(), 0);
        assert!(!observer.audit_degraded());
    }

    /// SEC-4・#820（codex P0 指摘対応。(a)）: 監査枠を満杯にした後の拒否 N 件は
    /// 捨てられず、drain で集約行 1 行（`count` == N・`last_peer_uid` は最後の
    /// 値）として現れる。`audit_degraded` は drain 後も `true` のままで、
    /// drain 後の次の拒否は再び個別の行として積まれる。
    #[test]
    fn sec4_820_json_lines_server_observer_coalesces_rejections_after_audit_queue_is_full() {
        let mut observer = JsonLinesServerObserver::new();
        fill_audit_queue(&mut observer);

        for uid in [2000, 2001, 2002, 2003, 2004] {
            observer.on_event(&rejection_event(Some(uid), "uid mismatch"));
        }

        assert_eq!(observer.len(), SERVER_AUDIT_LOG_CAPACITY + 1);
        assert_eq!(observer.dropped_count(), 0);
        assert_eq!(observer.coalesced_peer_credential_rejections(), 5);
        assert!(observer.audit_degraded());

        let lines = observer.drain_lines();
        assert_eq!(lines.len(), SERVER_AUDIT_LOG_CAPACITY + 1);
        assert_eq!(lines.first(), Some(&rejection_line(1000)));
        assert_eq!(
            lines.get(SERVER_AUDIT_LOG_CAPACITY - 1),
            Some(&rejection_line(1255))
        );
        assert_eq!(
            lines.last().map(String::as_str),
            Some(
                "{\"event\":\"io_server\",\"op\":\"accept\",\"outcome\":\"error\",\
                 \"reason\":\"peer_credential_rejections_coalesced\",\"count\":5,\
                 \"last_peer_uid\":2004}"
            )
        );

        // drain 後も劣化フラグと累計は戻らない。
        assert!(observer.is_empty());
        assert!(observer.audit_degraded());
        assert_eq!(observer.coalesced_peer_credential_rejections(), 5);

        // 集約レコードは drain で空に戻り、次の拒否は個別の行として積まれる。
        observer.on_event(&rejection_event(Some(3000), "uid mismatch"));
        assert_eq!(observer.drain_lines(), vec![rejection_line(3000)]);
        assert!(observer.audit_degraded());
        assert_eq!(observer.coalesced_peer_credential_rejections(), 5);
    }

    /// SEC-4・#820（codex P0 指摘対応）: 最後に集約した拒否で接続元 uid が
    /// 取得できなかった場合は、集約行から `last_peer_uid` キー自体を省く
    /// （個別の行の `peer_uid` と同じ表現）。
    #[test]
    fn sec4_820_json_lines_server_observer_coalesced_line_omits_unknown_last_peer_uid() {
        let mut observer = JsonLinesServerObserver::new();
        fill_audit_queue(&mut observer);
        observer.on_event(&rejection_event(Some(2000), "uid mismatch"));
        observer.on_event(&rejection_event(None, "getsockopt failed"));

        let lines = observer.drain_lines();
        assert_eq!(
            lines.last().map(String::as_str),
            Some(
                "{\"event\":\"io_server\",\"op\":\"accept\",\"outcome\":\"error\",\
                 \"reason\":\"peer_credential_rejections_coalesced\",\"count\":2}"
            )
        );
    }

    /// SEC-4・#820（codex P0 指摘対応。(b)）: 通常イベントで通常枠を満杯に
    /// しても、peer credential 拒否は追い出されず個別の行として残る。
    /// `dropped_count` は通常枠の破棄だけを数え、集約は起きない。
    #[test]
    fn sec4_820_json_lines_server_observer_keeps_rejections_when_normal_queue_is_full() {
        let mut observer =
            JsonLinesServerObserver::with_capacity(1).expect("1 must be a valid capacity");

        observer.on_event(&accept_ok_event(0));
        observer.on_event(&accept_ok_event(1));
        observer.on_event(&accept_ok_event(2));
        assert_eq!(observer.dropped_count(), 2);

        observer.on_event(&rejection_event(Some(1000), "uid mismatch"));
        observer.on_event(&rejection_event(Some(1001), "uid mismatch"));

        assert_eq!(observer.len(), 3);
        assert_eq!(observer.dropped_count(), 2);
        assert_eq!(observer.coalesced_peer_credential_rejections(), 0);
        assert!(!observer.audit_degraded());
        assert_eq!(
            observer.drain_lines(),
            vec![
                accept_ok_line(0),
                rejection_line(1000),
                rejection_line(1001)
            ]
        );
    }

    /// SEC-4・#820（codex P0 指摘対応。(c)）: 拒否イベントで監査枠を満杯に
    /// しても（集約中でも）、通常イベントは通常枠へ積める。drain は到着順で、
    /// 集約行は最初に集約した拒否が届いた位置に置かれる（欠けた区間の始点が
    /// 前後の通常イベントとの関係で分かる）。
    #[test]
    fn sec4_820_json_lines_server_observer_keeps_normal_events_and_order_when_audit_is_full() {
        let mut observer = JsonLinesServerObserver::new();
        fill_audit_queue(&mut observer);

        observer.on_event(&accept_ok_event(1));
        observer.on_event(&rejection_event(Some(2000), "uid mismatch"));
        observer.on_event(&accept_ok_event(2));
        observer.on_event(&rejection_event(Some(2001), "uid mismatch"));
        observer.on_event(&accept_ok_event(3));

        assert_eq!(observer.dropped_count(), 0);
        assert_eq!(observer.coalesced_peer_credential_rejections(), 2);
        assert_eq!(observer.len(), SERVER_AUDIT_LOG_CAPACITY + 4);

        let lines = observer.drain_lines();
        let tail: Vec<&str> = lines
            .iter()
            .skip(SERVER_AUDIT_LOG_CAPACITY)
            .map(String::as_str)
            .collect();
        assert_eq!(
            tail,
            vec![
                accept_ok_line(1).as_str(),
                "{\"event\":\"io_server\",\"op\":\"accept\",\"outcome\":\"error\",\
                 \"reason\":\"peer_credential_rejections_coalesced\",\"count\":2,\
                 \"last_peer_uid\":2001}",
                accept_ok_line(2).as_str(),
                accept_ok_line(3).as_str(),
            ]
        );
    }

    /// SEC-4・#820（codex P0 指摘対応。I5 の合計バイト数版を新しい契約へ
    /// 書き換えたもの）: 行数上限ではなく監査枠の合計バイト数上限
    /// （[`MAX_SERVER_AUDIT_LOG_BUFFER_BYTES`]）に先に達した場合も、以降の拒否は
    /// 捨てられず集約される。個別に積めた行数は 1 行の長さから決まる具体値に
    /// 一致する。
    #[test]
    fn sec4_820_json_lines_server_observer_coalesces_rejections_at_audit_byte_limit() {
        let mut observer = JsonLinesServerObserver::new();
        let near_max_message = "c".repeat(MAX_SEND_LOG_MESSAGE_BYTES);
        let event = rejection_event(Some(1000), &near_max_message);
        let line_len = encode_server_event(&event).len();
        let expected_individual = MAX_SERVER_AUDIT_LOG_BUFFER_BYTES / line_len;
        assert!(
            expected_individual < SERVER_AUDIT_LOG_CAPACITY,
            "the byte limit must be reached before the line limit in this test"
        );

        for _ in 0..expected_individual + 3 {
            observer.on_event(&event);
        }

        assert_eq!(observer.total_bytes(), expected_individual * line_len);
        assert_eq!(observer.dropped_count(), 0);
        assert_eq!(observer.coalesced_peer_credential_rejections(), 3);
        assert!(observer.audit_degraded());
        let lines = observer.drain_lines();
        assert_eq!(lines.len(), expected_individual + 1);
        assert_eq!(
            lines.last().map(String::as_str),
            Some(
                "{\"event\":\"io_server\",\"op\":\"accept\",\"outcome\":\"error\",\
                 \"reason\":\"peer_credential_rejections_coalesced\",\"count\":3,\
                 \"last_peer_uid\":1000}"
            )
        );
    }

    /// SEC-4・REPAIR-12・#820（codex P0 指摘対応。(d)）: 集約行の最悪長
    /// （`count` が `u64::MAX`・`last_peer_uid` が `u32::MAX`）は
    /// [`MAX_SERVER_AUDIT_GAP_LINE_BYTES`] 以下で、通常の 1 行の最悪長
    /// [`MAX_SERVER_LOG_LINE_BYTES`] 以下に収まる。
    #[test]
    fn sec4_repair12_820_coalesced_line_worst_case_fits_within_max_line_bytes() {
        let worst = CoalescedRejections {
            first_seq: u64::MAX,
            count: u64::MAX,
            last_peer_uid: Some(u32::MAX),
        };
        let encoded = encode_coalesced_rejections(&worst);
        assert_eq!(
            encoded,
            "{\"event\":\"io_server\",\"op\":\"accept\",\"outcome\":\"error\",\
             \"reason\":\"peer_credential_rejections_coalesced\",\
             \"count\":18446744073709551615,\"last_peer_uid\":4294967295}"
        );
        assert_eq!(encoded.len(), 157);
        // `MAX_SERVER_AUDIT_GAP_LINE_BYTES <= MAX_SERVER_LOG_LINE_BYTES` は
        // `const` assert で保証済み。
        assert!(encoded.len() <= MAX_SERVER_AUDIT_GAP_LINE_BYTES);
    }

    /// REPAIR-5（#820 レビュー指摘）: `with_capacity(0)` と
    /// `MAX_SEND_LOG_CAPACITY + 1` は `InvalidArgument` で拒否される
    /// （`JsonLinesSendObserver::with_capacity` と同じ検証を共有していることの
    /// 確認）。
    #[test]
    fn repair5_json_lines_server_observer_with_capacity_rejects_out_of_range() {
        let zero_err =
            JsonLinesServerObserver::with_capacity(0).expect_err("zero must be rejected");
        assert_eq!(zero_err.code(), IoErrorCode::InvalidArgument);

        let over_err = JsonLinesServerObserver::with_capacity(MAX_SEND_LOG_CAPACITY + 1)
            .expect_err("MAX_SEND_LOG_CAPACITY + 1 must be rejected");
        assert_eq!(over_err.code(), IoErrorCode::InvalidArgument);
    }

    /// REPAIR-5（#820 レビュー指摘）: `ServerEvent` の手書き `Debug` は `error`
    /// フィールド経由で `SendEventError` の `Debug` へ委譲し、`message` の全量を
    /// 出さない（`SendEvent` と同じ確認）。
    #[test]
    fn repair5_server_event_debug_delegates_to_error_debug() {
        let huge_message = "c".repeat(MAX_SEND_LOG_MESSAGE_BYTES * 4);
        let event = ServerEvent {
            op: ServerOp::Recv,
            kind: Some(FrameKind::Write),
            outcome: ServerOutcome::Failure,
            latency: Duration::from_millis(1),
            accept_aborted_retries: 0,
            peer_credential_rejections: 0,
            peer_uid: None,
            coalesced: None,
            error: Some(SendEventError {
                code: IoErrorCode::Timeout,
                message: &huge_message,
            }),
        };

        let debug_output = format!("{event:?}");

        assert!(
            !debug_output.contains(&"c".repeat(MAX_SEND_LOG_MESSAGE_BYTES + 1)),
            "ServerEvent's Debug must not leak the full untruncated message: {debug_output}"
        );
        assert!(debug_output.len() < huge_message.len());
    }

    /// TASK-13.2.1・#820（REPAIR-4・REPAIR-12）: 1 行の最悪ケース
    /// （`encode_server_event` の出力が最も長くなる組み合わせ。`accept_aborted_retries`・
    /// `peer_credential_rejections`・`peer_uid`〔H1・#820 security-auditor
    /// 指摘対応で追加〕がいずれも `u32::MAX` の場合を含む）でも
    /// [`MAX_SERVER_LOG_LINE_BYTES`] を超えないことを機械照合する
    /// （[`repair4_repair12_encode_send_event_worst_case_line_fits_within_max_line_bytes`]
    /// のサーバー版。最悪ケースの根拠は同テストと同じ: `kind` は `FLUSH_ACK`
    /// 〔9 バイトで最長〕、`outcome`/`code` は `RejectedResourceExhausted`
    /// 相当ではなく `ServerOutcome::Failure`〔`"failure"`。`reason` の候補が
    /// 少ないため固定〕、`code` は [`IoErrorCode::ResourceExhausted`]
    /// 〔`"RESOURCE_EXHAUSTED"`。全 `IoErrorCode` 中最長〕、`message` は上限超過の
    /// 1 バイト制御文字の連続〔エスケープ後 6 倍で最悪〕、`latency` は
    /// `Duration::MAX`、`accept_aborted_retries`・`peer_credential_rejections`・
    /// `peer_uid` は `u32::MAX`
    /// 〔実行時は `MAX_ACCEPT_ABORT_RETRIES` で頭打ちだが、フィールドの型としての
    /// 上限を正直に見積もる〕、集約イベントの `count` は `u64::MAX`・`latency_sum` は
    /// `Duration::MAX`〔#1118〕）。
    #[test]
    fn repair4_repair12_encode_server_event_worst_case_line_fits_within_max_line_bytes() {
        let oversized_control_chars = "\u{0001}".repeat(MAX_SEND_LOG_MESSAGE_BYTES + 1);
        let event = ServerEvent {
            op: ServerOp::Recv,
            kind: Some(FrameKind::FlushAck),
            outcome: ServerOutcome::Failure,
            latency: Duration::MAX,
            accept_aborted_retries: u32::MAX,
            peer_credential_rejections: u32::MAX,
            peer_uid: Some(u32::MAX),
            coalesced: Some(CoalescedServerEvents::new(u64::MAX, Duration::MAX)),
            error: Some(SendEventError {
                code: IoErrorCode::ResourceExhausted,
                message: &oversized_control_chars,
            }),
        };

        let encoded = encode_server_event(&event);

        assert!(
            encoded.contains(&format!(
                "\"coalesced\":true,\"count\":{},\"latency_sum_us\":{},",
                u64::MAX,
                Duration::MAX.as_micros()
            )),
            "the worst case must include the coalesced fragment: {encoded}"
        );
        assert!(
            encoded.contains("\"message_truncated\":true"),
            "the oversized message must trigger truncation: {encoded}"
        );
        let escaped_control_char_count = encoded.matches("\\u0001").count();
        assert_eq!(
            escaped_control_char_count, MAX_SEND_LOG_MESSAGE_BYTES,
            "expected exactly MAX_SEND_LOG_MESSAGE_BYTES escaped control characters: {encoded}"
        );
        assert!(
            encoded.len() <= MAX_SERVER_LOG_LINE_BYTES,
            "encoded line ({} bytes) must fit within MAX_SERVER_LOG_LINE_BYTES ({} bytes)",
            encoded.len(),
            MAX_SERVER_LOG_LINE_BYTES
        );
    }

    /// REPAIR-4・#1118: 集約イベント（`coalesced` が `Some`）の成功行は `coalesced`・
    /// `count`・`latency_sum_us` を `latency_us`（最大値）の直前に持つ。
    #[test]
    fn repair4_1118_encode_server_event_coalesced_success() {
        let event = ServerEvent {
            op: ServerOp::Send,
            kind: Some(FrameKind::Ack),
            outcome: ServerOutcome::Success,
            latency: Duration::from_micros(900),
            accept_aborted_retries: 0,
            peer_credential_rejections: 0,
            peer_uid: None,
            coalesced: Some(CoalescedServerEvents::new(3, Duration::from_micros(1500))),
            error: None,
        };
        assert_eq!(
            encode_server_event(&event),
            "{\"event\":\"io_server\",\"op\":\"send\",\"kind\":\"ACK\",\"outcome\":\"ok\",\
             \"accept_aborted_retries\":0,\"peer_credential_rejections\":0,\
             \"coalesced\":true,\"count\":3,\"latency_sum_us\":1500,\"latency_us\":900}"
        );
    }

    /// REPAIR-4・#1118: 集約イベントの失敗行は `reason`・`code`・`message` を通常の行と
    /// 同じ位置に持ち、集約の欄を `latency_us` の直前に加える（`kind` がない場合は省く）。
    #[test]
    fn repair4_1118_encode_server_event_coalesced_failure() {
        let event = ServerEvent {
            op: ServerOp::Recv,
            kind: None,
            outcome: ServerOutcome::RejectedPoisoned,
            latency: Duration::ZERO,
            accept_aborted_retries: 0,
            peer_credential_rejections: 0,
            peer_uid: None,
            coalesced: Some(CoalescedServerEvents::new(2, Duration::ZERO)),
            error: Some(SendEventError {
                code: IoErrorCode::Unavailable,
                message: "poisoned",
            }),
        };
        assert_eq!(
            encode_server_event(&event),
            "{\"event\":\"io_server\",\"op\":\"recv\",\"outcome\":\"error\",\
             \"reason\":\"rejected_poisoned\",\"code\":\"UNAVAILABLE\",\"message\":\"poisoned\",\
             \"accept_aborted_retries\":0,\"peer_credential_rejections\":0,\
             \"coalesced\":true,\"count\":2,\"latency_sum_us\":0,\"latency_us\":0}"
        );
    }

    /// TASK-13.2.1・#820: `NoopServerObserver` は何もしない（既定実装が accept・
    /// 送受信経路の動作へ影響しないことの確認）。
    #[test]
    fn repair4_noop_server_observer_does_nothing() {
        let mut observer = NoopServerObserver;
        observer.on_event(&ServerEvent {
            op: ServerOp::Accept,
            kind: None,
            outcome: ServerOutcome::Success,
            latency: Duration::ZERO,
            accept_aborted_retries: 0,
            peer_credential_rejections: 0,
            peer_uid: None,
            coalesced: None,
            error: None,
        });
        // panic せず戻ることのみを確認する（副作用を持たない契約）。
    }
}
