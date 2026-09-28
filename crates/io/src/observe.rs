//! [`crate::client::PipelineClient::send`] の送信イベントを外部へ出力する観測フック
//! （TASK-12.1・#73 codex 指摘対応。P1・REPAIR-4）。
//!
//! [`crate::client::SendMetrics`]（[`crate::client::PipelineClient::metrics`] で参照）は
//! プロセス内の集計値を保持するだけで、外部のログ・メトリクス基盤への出力を持たない。
//! 呼び出し元が `metrics()` を明示的に読み出さない限り、送信失敗や上限到達を観測
//! できないという codex レビュー指摘（base 側 AGENTS.md の可観測性要件・REPAIR-4）に
//! 対応するため、本モジュールは送信 1 回ごとのイベントを [`SendObserver`] へ同期的に
//! 通知する仕組みと、その既定実装として JSON Lines（1 イベント 1 行）で出力する
//! [`JsonLinesSendObserver`] を提供する。[`SendMetrics`](crate::client::SendMetrics) を
//! 置き換えるものではなく、その補完（外部出力用のフック）として使う。

use std::fmt;
use std::io::Write;
use std::time::Duration;

use crate::client::SendOutcome;
use crate::error::IoErrorCode;
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
/// （TASK-12.1・#73 codex 指摘対応。P1・REPAIR-4）。
///
/// 呼び出しは送信のたびに同期的・単一スレッドで行われる（[`crate::client::PipelineClient`]
/// 自体が `&mut self` を要求し単一スレッド前提であることと同じ契約）。実装は送信経路を
/// ブロックしないよう軽量に保つこと（重い I/O・ロック待ちを行わない）。
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

/// [`SendEvent`] を JSON Lines（1 イベント 1 行）として `W` へ書き出す既定実装
/// （TASK-12.1・#73 codex 指摘対応。P1・REPAIR-4・ERR-1 の構造化 `code` / `message` 形式）。
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
/// # 書き込み失敗の扱い
/// `W` への書き込み・flush が失敗しても [`SendObserver::on_send`] はそれを送信処理
/// （[`crate::client::PipelineClient::send`]）へ伝播させず黙って握りつぶす（観測が
/// 主処理を妨げてはならないため）。書き込み失敗自体を計測する指標は持たない
/// （REPAIR-3。必要になれば別タスクで拡張する）。
pub struct JsonLinesSendObserver<W>
where
    W: Write + Send,
{
    writer: W,
}

impl<W> JsonLinesSendObserver<W>
where
    W: Write + Send,
{
    /// 書き込み先から観測フックを作る。
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// 内部の書き込み先を取り出す。
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W> SendObserver for JsonLinesSendObserver<W>
where
    W: Write + Send,
{
    fn on_send(&mut self, event: &SendEvent) {
        let line = encode_send_event(event);
        // 書き込み失敗は送信処理を妨げないよう握りつぶす（上記ドキュメント参照）。
        let _ = self.writer.write_all(line.as_bytes());
        let _ = self.writer.write_all(b"\n");
        let _ = self.writer.flush();
    }
}

/// `writer`（バッファリングした送信ログを含みうる）の中身を誤ってダンプしないよう、
/// フィールドを省略した手書きの `Debug` 実装（[`W`] に `Debug` を要求しないための
/// 措置。`Box<dyn Write + Send>` のような非 `Debug` な書き込み先も保持できる）。
impl<W> fmt::Debug for JsonLinesSendObserver<W>
where
    W: Write + Send,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonLinesSendObserver")
            .finish_non_exhaustive()
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

    /// REPAIR-4: 成功イベントが `outcome":"ok"` の 1 行 JSON になる。
    #[test]
    fn repair4_json_lines_observer_encodes_success_event() {
        let mut buf: Vec<u8> = Vec::new();
        let mut observer = JsonLinesSendObserver::new(&mut buf);
        observer.on_send(&success_event(123));

        let output = String::from_utf8(buf).expect("output must be UTF-8");
        assert_eq!(
            output,
            "{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"ok\",\"latency_us\":123}\n"
        );
    }

    /// REPAIR-4: トランスポート失敗イベントが `outcome":"error"` と `code` を含む
    /// 1 行 JSON になる。
    #[test]
    fn repair4_json_lines_observer_encodes_transport_failure_event() {
        let mut buf: Vec<u8> = Vec::new();
        let mut observer = JsonLinesSendObserver::new(&mut buf);
        observer.on_send(&failure_event(
            FrameKind::Write,
            SendOutcome::TransportFailure,
            IoErrorCode::Timeout,
            "ack not received within timeout",
            456,
        ));

        let output = String::from_utf8(buf).expect("output must be UTF-8");
        assert_eq!(
            output,
            "{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"error\",\
             \"reason\":\"transport_failure\",\"code\":\"TIMEOUT\",\
             \"message\":\"ack not received within timeout\",\"latency_us\":456}\n"
        );
    }

    /// REPAIR-4: 未 ACK 上限到達（早期拒否・`latency` は `ZERO`）イベントが
    /// `latency_us":0` を含む 1 行 JSON になる。
    #[test]
    fn repair4_json_lines_observer_encodes_resource_exhausted_event() {
        let mut buf: Vec<u8> = Vec::new();
        let mut observer = JsonLinesSendObserver::new(&mut buf);
        observer.on_send(&failure_event(
            FrameKind::Write,
            SendOutcome::RejectedResourceExhausted,
            IoErrorCode::ResourceExhausted,
            "in-flight limit reached",
            0,
        ));

        let output = String::from_utf8(buf).expect("output must be UTF-8");
        assert_eq!(
            output,
            "{\"event\":\"io_send\",\"kind\":\"WRITE\",\"outcome\":\"error\",\
             \"reason\":\"rejected_resource_exhausted\",\"code\":\"RESOURCE_EXHAUSTED\",\
             \"message\":\"in-flight limit reached\",\"latency_us\":0}\n"
        );
    }

    /// REPAIR-4・security.md「インジェクション」観点: `message` 内の `"`・`\`・
    /// 改行が JSON 文字列として正しくエスケープされる（untrusted なトランスポート
    /// エラーメッセージが JSON 構造を壊すのを防ぐ）。
    #[test]
    fn repair4_json_lines_observer_escapes_message_special_characters() {
        let mut buf: Vec<u8> = Vec::new();
        let mut observer = JsonLinesSendObserver::new(&mut buf);
        observer.on_send(&failure_event(
            FrameKind::Flush,
            SendOutcome::RejectedInvalidFrameKind,
            IoErrorCode::InvalidArgument,
            "bad \"frame\"\\payload\nwith control chars",
            0,
        ));

        let output = String::from_utf8(buf).expect("output must be UTF-8");
        assert_eq!(
            output,
            "{\"event\":\"io_send\",\"kind\":\"FLUSH\",\"outcome\":\"error\",\
             \"reason\":\"rejected_invalid_frame_kind\",\"code\":\"INVALID_ARGUMENT\",\
             \"message\":\"bad \\\"frame\\\"\\\\payload\\nwith control chars\",\
             \"latency_us\":0}\n"
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
