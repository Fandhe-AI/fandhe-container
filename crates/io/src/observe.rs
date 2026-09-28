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
//! [`JsonLinesSendObserver::drain_lines`] / [`JsonLinesSendObserver::drain_into`] を
//! 呼んで行う（送信経路の外に I/O を分離する）。

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Write};
use std::time::Duration;

use crate::client::SendOutcome;
use crate::error::{IoError, IoErrorCode};
use crate::protocol::FrameKind;

/// [`crate::client::PipelineClient::send`] 1 回分の送信イベント（TASK-12.1・#73
/// codex 指摘対応。P1・REPAIR-4）。
///
/// [`crate::client::SendMetrics`] が集計している事象（結果種別・所要時間）と対応させ、
/// 送信対象のフレーム種別・失敗時のエラー詳細も併せて持つ。将来フィールドを
/// 追加できるよう `#[non_exhaustive]` にする（REPAIR-3）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SendEvent {
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
    pub error: Option<SendEventError>,
}

/// [`SendEvent::error`] が保持する失敗詳細（TASK-12.1・#73 codex 指摘対応。P1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendEventError {
    /// 機械可読なエラーコード（ERR-1）。
    pub code: IoErrorCode,
    /// 人間可読なエラーメッセージ。トランスポート実装（untrusted な相手側）由来の
    /// 文字列を含みうるため、[`JsonLinesSendObserver`] は出力時にエスケープする。
    pub message: String,
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
    /// 1 回の送信イベントを通知する。
    fn on_send(&mut self, event: &SendEvent);
}

/// 何もしない既定実装（観測フック未指定時に [`crate::client::PipelineClient::new`] が
/// 使う。TASK-12.1・#73 codex 指摘対応。P1）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoopSendObserver;

impl SendObserver for NoopSendObserver {
    fn on_send(&mut self, _event: &SendEvent) {}
}

/// [`JsonLinesSendObserver::new`]（既定容量）が使う、ためられる JSON 行数の既定値
/// （TASK-12.1・#73 codex 再指摘対応。P1・REPAIR-5）。
pub const DEFAULT_SEND_LOG_CAPACITY: usize = 1024;

/// [`JsonLinesSendObserver::with_capacity`] が受理する容量の最大値。無制限確保を
/// 防ぐための上限（security.md「不安全な設計」観点）。
pub const MAX_SEND_LOG_CAPACITY: usize = 65536;

/// [`SendEvent`] を JSON Lines（1 イベント 1 行）へ変換し、上限付きのメモリ内
/// `VecDeque` へためる既定実装（TASK-12.1・#73 codex 再指摘対応。P1・REPAIR-4・
/// REPAIR-5・ERR-1 の構造化 `code` / `message` 形式）。
///
/// 出力キーは英語 snake_case 固定（`event`・`kind`・`outcome`・`reason`・`code`・
/// `message`・`latency_us`）。`event` は常に `"io_send"`、`kind` は `WRITE`/`ACK`/
/// `FLUSH`/`FLUSH_ACK`、`outcome` は成功なら `"ok"`、失敗系なら `"error"` で、
/// 失敗系の場合のみ `reason`（[`SendOutcome`] の snake_case 名）・`code`（ERR-1
/// 文字列）・`message`（エスケープ済み文字列）を付与する。
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
/// 実際の書き出しは呼び出し元が [`Self::drain_lines`] / [`Self::drain_into`] を
/// 呼んで自分のタイミング・スレッドで行う。
///
/// # 満杯時の扱い
/// 容量に達した状態で新しいイベントが来た場合、新規イベントを破棄し
/// （最古のイベントを保持する。すでにためた分の消失より、直近の詳細を失うほうが
/// 実害が小さいと判断）、[`Self::dropped_count`] を増分する。破棄そのものが
/// `send` へ伝播することはない（観測が主処理を妨げてはならないため）。
pub struct JsonLinesSendObserver {
    lines: VecDeque<String>,
    capacity: usize,
    dropped: u64,
}

impl JsonLinesSendObserver {
    /// 既定容量（[`DEFAULT_SEND_LOG_CAPACITY`]）で観測フックを作る。
    pub fn new() -> Self {
        Self {
            lines: VecDeque::new(),
            capacity: DEFAULT_SEND_LOG_CAPACITY,
            dropped: 0,
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

    /// ためている JSON 行をすべて取り出す（呼び出し元が任意の書き出し先へ渡す
    /// 想定。改行は含まない）。
    pub fn drain_lines(&mut self) -> Vec<String> {
        self.lines.drain(..).collect()
    }

    /// ためている JSON 行を `writer` へ 1 行ずつ書き出す（改行付き）。
    ///
    /// [`Self::on_send`]（[`SendObserver`]）と異なり、こちらは呼び出し元が明示的に
    /// 呼ぶ経路であり、ブロックする I/O を行ってよい（REPAIR-5 の制約は送信経路
    /// から呼ばれる `on_send` のみが対象）。書き込みが失敗した行は `VecDeque`
    /// から取り除かず、以降の行も試みずに即座にエラーを返す（失われた行を
    /// 再現できるようにするため）。
    pub fn drain_into<W: Write>(&mut self, writer: &mut W) -> io::Result<usize> {
        let mut written = 0usize;
        while let Some(line) = self.lines.front() {
            writer.write_all(line.as_bytes())?;
            writer.write_all(b"\n")?;
            self.lines.pop_front();
            written += 1;
        }
        writer.flush()?;
        Ok(written)
    }
}

impl Default for JsonLinesSendObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl SendObserver for JsonLinesSendObserver {
    fn on_send(&mut self, event: &SendEvent) {
        if self.lines.len() >= self.capacity {
            // 満杯時は新規イベントを破棄する（上記ドキュメント参照）。ここで
            // I/O は行わない（REPAIR-5）。
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.lines.push_back(encode_send_event(event));
    }
}

/// ためた JSON 行の中身を誤ってダンプしないよう、件数・破棄数のみを出す手書きの
/// `Debug` 実装。
impl fmt::Debug for JsonLinesSendObserver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonLinesSendObserver")
            .field("len", &self.lines.len())
            .field("capacity", &self.capacity)
            .field("dropped", &self.dropped)
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

/// [`SendEvent`] を 1 行の JSON Lines 文字列へエンコードする（改行は含まない）。
fn encode_send_event(event: &SendEvent) -> String {
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
            let message = escape_json_string(&error.message);
            format!(
                "{{\"event\":\"io_send\",\"kind\":\"{kind}\",\"outcome\":\"error\",\
                 \"reason\":\"{reason}\",\"code\":\"{code}\",\"message\":\"{message}\",\
                 \"latency_us\":{latency_us}}}"
            )
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

    fn success_event(latency_us: u64) -> SendEvent {
        SendEvent {
            kind: FrameKind::Write,
            outcome: SendOutcome::Success,
            latency: Duration::from_micros(latency_us),
            error: None,
        }
    }

    fn failure_event(
        kind: FrameKind,
        outcome: SendOutcome,
        code: IoErrorCode,
        message: &str,
        latency_us: u64,
    ) -> SendEvent {
        SendEvent {
            kind,
            outcome,
            latency: Duration::from_micros(latency_us),
            error: Some(SendEventError {
                code,
                message: message.to_string(),
            }),
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

    /// REPAIR-5: `on_send` は I/O をしない契約だが、`drain_into` は呼び出し元が
    /// 明示的に呼ぶ経路として実際の書き出しを行う（改行付き）。
    #[test]
    fn repair5_json_lines_observer_drain_into_writes_lines_with_newline() {
        let mut observer = JsonLinesSendObserver::new();
        observer.on_send(&success_event(1));
        observer.on_send(&success_event(2));

        let mut buf: Vec<u8> = Vec::new();
        let written = observer
            .drain_into(&mut buf)
            .expect("writing to an in-memory buffer must not fail");
        assert_eq!(written, 2);
        assert!(observer.is_empty());

        let output = String::from_utf8(buf).expect("output must be UTF-8");
        assert_eq!(
            output,
            "{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"ok\",\"latency_us\":1}\n\
             {\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"ok\",\"latency_us\":2}\n"
        );
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
