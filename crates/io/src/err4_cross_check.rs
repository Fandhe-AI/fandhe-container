//! io の観測ログ行を「1 行 1 JSON」の共有検査器で横断照合する（ERR-4・#3122）。
//!
//! TASK-98 の受け入れ条件 2（#653）の照合先のうち io 分。io は core より下の層で core の共通ログ型
//! `LogLine` を使えない（#3114 の判断 (f)）ため、core・cli・plugin と同じ検査器
//! （`crates/plugin/tests/support/json_lines_contract.rs`）を `#[path]` で取り込み、形式を保つ。
//! `drain_lines()` は LF を含まない本体を返す（書き出し先で LF を足す契約）ため `check_body` で見る。
//!
//! 対象外: 切り詰めの印のキー名（io は `message_truncated`、core は `truncated`）の統一。(f) により
//! io の形式は変えない。サーバー側のイベントは代表として Recv の失敗・Accept の peer 拒否を見る。

#[path = "../../plugin/tests/support/json_lines_contract.rs"]
mod json_lines_contract;

use json_lines_contract::{HOSTILE_TEXT, SHARED_MAX_LOG_LINE_BYTES, check_body};

use crate::client::{AckOutcome, SendOutcome};
use crate::error::IoErrorCode;
use crate::observe::{
    AckEvent, AckEventError, JsonLinesSendObserver, JsonLinesServerObserver, SendEvent,
    SendEventError, SendObserver, ServerEvent, ServerObserver, ServerOp, ServerOutcome,
};
use crate::protocol::FrameKind;
use std::time::Duration;

/// io は DEL・C1・Cf・Zl・Zp を空白へ置換し、LF / CR / NUL / BEL / ESC などの C0 は JSON のエスケープで残す。
const HOSTILE_DECODED: &str = "a\nb\rc\0d\u{7}e\u{1b}[31mf g h i j k l m\"n\\oあ";

fn send_failure(message: &str) -> SendEvent<'_> {
    let mut e = SendEvent {
        kind: FrameKind::Write,
        outcome: SendOutcome::TransportFailure,
        latency: Duration::from_micros(5),
        error: None,
    };
    e.error = Some(SendEventError {
        code: IoErrorCode::Internal,
        message,
    });
    e
}

/// ERR-4・#3122: 送信イベント。成功・敵対的な失敗・上限超過の失敗が 1 行 1 JSON になる。
#[test]
fn err4_3122_send_events_are_one_json_object() {
    let mut o = JsonLinesSendObserver::new();
    o.on_send(&SendEvent {
        kind: FrameKind::Write,
        outcome: SendOutcome::Success,
        latency: Duration::from_micros(3),
        error: None,
    });
    o.on_send(&send_failure(HOSTILE_TEXT));
    let long = format!("{HOSTILE_TEXT}{}", "z".repeat(1000));
    o.on_send(&send_failure(&long));
    let lines = o.drain_lines();
    assert_eq!(lines.len(), 3);
    for l in &lines {
        let f = check_body(l, SHARED_MAX_LOG_LINE_BYTES).expect(l);
        assert_eq!(f.event, "io_send");
    }
    let f = check_body(&lines[1], SHARED_MAX_LOG_LINE_BYTES).unwrap();
    assert_eq!(f.str_of("message"), Some(HOSTILE_DECODED));
    assert_eq!(f.bool_of("message_truncated"), None);
    let f = check_body(&lines[2], SHARED_MAX_LOG_LINE_BYTES).unwrap();
    assert_eq!(f.bool_of("message_truncated"), Some(true));
    assert!(f.str_of("message").unwrap().len() <= 512);
    for l in &lines {
        assert!(!l.contains('\n') && !l.contains('\r'));
    }
}

/// ERR-4・#3122: ACK 受信イベント。
#[test]
fn err4_3122_ack_events_are_one_json_object() {
    let mut o = JsonLinesSendObserver::new();
    o.on_ack(&AckEvent {
        outcome: AckOutcome::TransportFailure,
        ack_kind: None,
        latency: Duration::from_micros(9),
        error: Some(AckEventError {
            code: IoErrorCode::Timeout,
            message: HOSTILE_TEXT,
        }),
        rejected: None,
    });
    let lines = o.drain_lines();
    assert_eq!(lines.len(), 1);
    let f = check_body(&lines[0], SHARED_MAX_LOG_LINE_BYTES).unwrap();
    assert_eq!(f.event, "io_recv_ack");
    assert_eq!(f.str_of("message"), Some(HOSTILE_DECODED));
}

/// ERR-4・#3122: サーバー側イベント（Recv の失敗と Accept の peer 拒否）。
#[test]
fn err4_3122_server_events_are_one_json_object() {
    let mut o = JsonLinesServerObserver::new();
    o.on_event(&ServerEvent {
        op: ServerOp::Recv,
        kind: Some(FrameKind::Write),
        outcome: ServerOutcome::Failure,
        latency: Duration::from_micros(5),
        accept_aborted_retries: 0,
        peer_credential_rejections: 0,
        peer_uid: None,
        peer_cid: None,
        coalesced: None,
        error: Some(SendEventError {
            code: IoErrorCode::Internal,
            message: HOSTILE_TEXT,
        }),
    });
    o.on_event(&ServerEvent {
        op: ServerOp::Accept,
        kind: None,
        outcome: ServerOutcome::RejectedPeerCredential,
        latency: Duration::ZERO,
        accept_aborted_retries: 0,
        peer_credential_rejections: 1,
        peer_uid: Some(1000),
        peer_cid: None,
        coalesced: None,
        error: None,
    });
    let lines = o.drain_lines();
    assert_eq!(lines.len(), 2);
    for l in &lines {
        let f = check_body(l, SHARED_MAX_LOG_LINE_BYTES).expect(l);
        assert_eq!(f.event, "io_server");
    }
}
