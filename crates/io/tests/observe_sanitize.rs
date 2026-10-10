//! 観測ログ（`JsonLinesSendObserver`）の表示サニタイズの結合試験（ERR-1・REPAIR-4・REPAIR-12）。
//!
//! 公開 API（`PipelineClient::send` → `observer_mut().drain_lines()`）だけを使い、トランスポート
//! （untrusted な相手側）由来のエラーメッセージに含まれる制御文字・書式文字・行区切りが、
//! 観測ログの 1 行 JSON で具体的にどう出力されるかを照合する。

use std::time::Duration;

use fandhe_container_io::{
    Frame, FrameKind, FrameSender, InFlightLimit, IoError, IoErrorCode, IoTimeout,
    JsonLinesSendObserver, PipelineClient,
};

/// 常に固定のエラーメッセージで送信に失敗するモック sender。
struct FailingSender(&'static str);

impl FrameSender for FailingSender {
    type Frame = Frame;

    fn send_frame(&mut self, _frame: &Self::Frame, _timeout: IoTimeout) -> Result<(), IoError> {
        Err(IoError::new(IoErrorCode::Timeout, self.0))
    }
}

/// ERR-1: DEL・C1・Cf・Zl・Zp・U+2065 は空白へ置換され、C0 は `\u00xx`・改行は `\n` に
/// エスケープされ、結合文字は素通しになる。出力は改行を含まない 1 行に収まる。
#[test]
fn err1_public_api_observer_log_replaces_display_unsafe_chars() {
    let limit = InFlightLimit::new(1).expect("1 must be a valid limit");
    let sender = FailingSender(
        "a\u{7f}b\u{85}c\u{200b}d\u{202e}e\u{2028}f\u{2029}g\u{feff}h\u{2065}i\u{1}j\nk\u{301}",
    );
    let mut client = PipelineClient::new(sender, limit, JsonLinesSendObserver::new());
    let timeout = IoTimeout::new(Duration::from_millis(1)).expect("1ms must be valid");

    client
        .send(FrameKind::Write, &[1], timeout)
        .expect_err("send must fail with the mock transport error");

    let lines = client.observer_mut().drain_lines();
    assert_eq!(lines.len(), 1, "expected one JSON line");
    let line = &lines[0];
    assert!(!line.contains('\n'), "line must not contain a raw newline");
    assert!(
        line.contains("\"message\":\"a b c d e f g h i\\u0001j\\nk\u{301}\""),
        "unexpected sanitized message: {line}"
    );
    assert!(line.contains("\"outcome\":\"error\""), "{line}");
    assert!(line.contains("\"reason\":\"transport_failure\""), "{line}");
}
