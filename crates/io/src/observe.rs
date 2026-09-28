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

use crate::client::SendOutcome;
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

/// [`crate::client::PipelineClient::send`] の送信イベントを受け取る観測フック
/// （TASK-12.1・#73 codex 指摘対応。P1・REPAIR-4・REPAIR-5）。
///
/// 呼び出しは送信のたびに同期的・単一スレッドで行われる（[`crate::client::PipelineClient`]
/// 自体が `&mut self` を要求し単一スレッド前提であることと同じ契約）。
///
/// # 契約: ブロックする I/O をしてはならない（REPAIR-5）
///
/// `on_send` は送信経路（[`crate::client::PipelineClient::send`]）から同期で呼ばれる。
/// ここでブロックする I/O（ソケット・pipe への書き込み・ロック待ち等）を行うと、
/// 相手の応答を待たない送信であるはずの `send` 自体が無期限に停止しかねず、
/// [`crate::transport::IoTimeout`] でも打ち切れない。実装はメモリ内へ積む・
/// 非ブロッキング操作のみに留め、実際の I/O は別経路（呼び出し元が明示的に呼ぶ
/// drain API 等）へ分離すること（[`JsonLinesSendObserver`] を参照）。
///
/// `Debug` は要求しない。`Box<dyn Write + Send>` のような非 `Debug` な書き込み先を
/// 保持する観測フックも実装できるようにするため（[`crate::client::PipelineClient`]
/// の `#[derive(Debug)]` は `S: FrameSender` にも `Debug` を要求していないのと同じ
/// 扱いで、`O: Debug` を実装した具象型のみが `PipelineClient` の `Debug` を使える）。
pub trait SendObserver: Send {
    /// 1 回の送信イベントを通知する。`event` は呼び出し中のみ有効な借用
    /// （[`SendEvent`] のドキュメント参照。#73 P0 再指摘対応）。
    fn on_send(&mut self, event: &SendEvent<'_>);
}

/// 何もしない既定実装（観測フック未指定時に [`crate::client::PipelineClient::new`] が
/// 使う。TASK-12.1・#73 codex 指摘対応。P1）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoopSendObserver;

impl SendObserver for NoopSendObserver {
    fn on_send(&mut self, _event: &SendEvent<'_>) {}
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

/// [`SendEvent`] を JSON Lines（1 イベント 1 行）へ変換し、上限付きのメモリ内
/// `VecDeque` へためる既定実装（TASK-12.1・#73 codex 再指摘対応。P1・REPAIR-4・
/// REPAIR-5・ERR-1 の構造化 `code` / `message` 形式）。
///
/// 出力キーは英語 snake_case 固定（`event`・`kind`・`outcome`・`reason`・`code`・
/// `message`・`message_truncated`・`latency_us`）。`event` は常に `"io_send"`、
/// `kind` は `WRITE`/`ACK`/`FLUSH`/`FLUSH_ACK`、`outcome` は成功なら `"ok"`、
/// 失敗系なら `"error"` で、失敗系の場合のみ `reason`（[`SendOutcome`] の
/// snake_case 名）・`code`（ERR-1 文字列）・`message`（[`MAX_SEND_LOG_MESSAGE_BYTES`]
/// で切り詰め済み・エスケープ済みの文字列）を付与する。`message_truncated` は
/// 切り詰めが発生した場合のみ `true` を付与し、発生しない場合はキー自体を省く。
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
/// （REPAIR-5 違反）。本実装は `on_send` の中では `VecDeque` へ積むだけにとどめ、
/// 実際の書き出しは呼び出し元が [`Self::drain_lines`] を呼んで取り出した行を
/// 自分のタイミング・スレッドで書き出す（部分書き込み時の再試行も呼び出し元の
/// 責務。codex/bugbot 再指摘対応）。
///
/// # 満杯時の扱い
/// 次のいずれかに達した状態で新しいイベントが来た場合、新規イベントを破棄し
/// （最古のイベントを保持する。すでにためた分の消失より、直近の詳細を失うほうが
/// 実害が小さいと判断）、[`Self::dropped_count`] を増分する。破棄そのものが
/// `send` へ伝播することはない（観測が主処理を妨げてはならないため）。
///
/// - 行数が `capacity` に達している（[`Self::capacity`]）
/// - ためている JSON 行の合計バイト数が [`MAX_SEND_LOG_BUFFER_BYTES`] を超える
///   （codex P0 再指摘対応。1 行あたりのメッセージが巨大でも総メモリ使用量を
///   有界に保つ）
///
/// また、`message`（[`SendEventError::message`]）はエンコード前に
/// [`MAX_SEND_LOG_MESSAGE_BYTES`] へ切り詰める（UTF-8 の文字境界を跨がない）。
/// 切り詰めた場合は JSON に `"message_truncated":true` を付与する。
pub struct JsonLinesSendObserver {
    lines: VecDeque<String>,
    capacity: usize,
    dropped: u64,
    /// `lines` にためている JSON 行のエンコード後バイト数の合計（改行を含まない）。
    /// [`MAX_SEND_LOG_BUFFER_BYTES`] との比較にのみ使う内部カウンタで、
    /// [`Self::drain_lines`] で `0` へ戻す。
    total_bytes: usize,
}

impl JsonLinesSendObserver {
    /// 既定容量（[`DEFAULT_SEND_LOG_CAPACITY`]）で観測フックを作る。
    pub fn new() -> Self {
        Self {
            lines: VecDeque::new(),
            capacity: DEFAULT_SEND_LOG_CAPACITY,
            dropped: 0,
            total_bytes: 0,
        }
    }

    /// 容量を指定して観測フックを作る。`capacity` が `0` または
    /// [`MAX_SEND_LOG_CAPACITY`] を超える場合は [`IoErrorCode::InvalidArgument`]
    /// を返す（無制限確保の防止）。
    pub fn with_capacity(capacity: usize) -> Result<Self, IoError> {
        if capacity == 0 {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "send log capacity must not be zero",
            ));
        }
        if capacity > MAX_SEND_LOG_CAPACITY {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("send log capacity must be at most {MAX_SEND_LOG_CAPACITY}"),
            ));
        }
        Ok(Self {
            lines: VecDeque::new(),
            capacity,
            dropped: 0,
            total_bytes: 0,
        })
    }

    /// このバッファの容量を返す。
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 現在ためている JSON 行数を返す。
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// ためている JSON 行が 1 件もないかを返す。
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// 容量超過により破棄した（新規イベント側を破棄した）件数を返す。
    pub fn dropped_count(&self) -> u64 {
        self.dropped
    }

    /// 現在ためている JSON 行の合計バイト数（改行を含まない）を返す。
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// ためている JSON 行をすべて取り出してキューを空にする（各行は改行を含まない
    /// 完全な JSON 文字列）。
    ///
    /// 本型は I/O をしない契約（[`Self::on_send`]・上記モジュール doc 参照）のため、
    /// 取り出した行をどこへどう書き出すか（ファイル・ソケット・部分書き込み時の
    /// 再試行を含む）は呼び出し元の責務とする。
    pub fn drain_lines(&mut self) -> Vec<String> {
        self.total_bytes = 0;
        self.lines.drain(..).collect()
    }
}

impl Default for JsonLinesSendObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl SendObserver for JsonLinesSendObserver {
    fn on_send(&mut self, event: &SendEvent<'_>) {
        if self.lines.len() >= self.capacity {
            // 満杯時は新規イベントを破棄する（上記ドキュメント参照）。ここで
            // I/O は行わない（REPAIR-5）。
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let encoded = encode_send_event(event);
        // 行数上限とは独立に、合計バイト数の上限も守る（codex P0 再指摘対応）。
        // 巨大な `message` が連続しても、キューの総メモリ使用量を有界に保つ。
        if self.total_bytes.saturating_add(encoded.len()) > MAX_SEND_LOG_BUFFER_BYTES {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.total_bytes += encoded.len();
        self.lines.push_back(encoded);
    }
}

/// ためた JSON 行の中身を誤ってダンプしないよう、件数・破棄数・合計バイト数のみを
/// 出す手書きの `Debug` 実装。
impl fmt::Debug for JsonLinesSendObserver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonLinesSendObserver")
            .field("len", &self.lines.len())
            .field("capacity", &self.capacity)
            .field("dropped", &self.dropped)
            .field("total_bytes", &self.total_bytes)
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
        SendOutcome::TransportFailure => "transport_failure",
    }
}

/// 制御文字・`"`・`\` を JSON 文字列リテラルとして安全な形へエスケープする。
///
/// 依存を追加せず手書きで JSON を組み立てるための最小実装（serde_json 相当の
/// 完全な仕様準拠は目指さない。ERR-1 の `message` を出力する用途に限る）。
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
fn truncate_message_bytes(message: &str) -> (&str, bool) {
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
}
