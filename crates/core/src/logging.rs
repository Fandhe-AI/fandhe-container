//! JSON Lines 共通ログ型（ERR-4・TASK-98.1・MS-6）。
//!
//! 監査ログ（SEC-4）・可観測性出力（REPAIR-4）・エラー出力（ERR-1〜3）・警告行を、
//! 「1 行 1 JSON オブジェクト（LF 区切り）」の共通形式で書き出すための型と書き出し口を定義する。
//! journald / syslog へ行単位で転送できることが目的である。
//!
//! # 位置づけと呼び出し元
//!
//! 本モジュールは型と書き出しの仕組みだけを持つ。`audit_log` の `AuditLineDto` は移行済み（#3115）。残りの既存の出力（
//! `observability` の手組み行・`oci_runtime::error`・`legacy_tiocsti`・`plugin_discovery`）は
//! まだ本型を使っておらず、移行は TASK-98.2（#653）で行う（REPAIR-3: 実装済みを装わない）。
//!
//! # 確定した設計判断
//!
//! - **既存の行をバイト単位で再現できる**: 封筒 [`LogLine`] のキー順は
//!   `level`（任意）→ `event` → 本体のフィールド。level なしの行
//!   `{"event":...,<本体>}`（監査・op_stats）と level ありの行
//!   `{"level":...,"event":...,<本体>}`（legacy_tiocsti）の両方を同じバイト列で出せる。
//! - **タイムスタンプは封筒に入れない**: 監査は本体に `ts_sec` / `ts_nsec` を持ち、op_stats は
//!   持たない。共通の ts を持たせるかは TASK-98.2 で決める。
//! - **行長の上限**: [`MAX_LOG_LINE_BYTES`]。超えた行は何も書かずにエラーにする（REPAIR-5）。
//! - **1 行の保証**: serde_json の compact 出力は 0x20 未満の文字をすべてエスケープする。
//!   そのうえで LF / CR のバイトが無いことを防御として確かめ、末尾に LF をちょうど 1 つ付け、
//!   `write_all` 1 回で書く。オブジェクトでない本体は flatten が失敗し `Encode` になる。
//! - **予約キー**: 本体は `level` / `event` を持たない契約とする。持つと重複キーになる
//!   （検出は各 DTO の試験の責務。監査は file_writer の試験で検出済み〔#3115〕、残りは TASK-98.2）。
//! - **表示を乱す文字**（Cf・Zl・Zp 等）の置換は封筒の責務ではなく、各本体が前処理する。
//! - 資格情報・ホストの機密値をフィールドに入れない。出力先の権限は呼び出し元が決める。
//!
//! # 依存方向の制約
//!
//! `io`（観測ログ）と `plugin` は core より下の層にあるため本型を使えない。core への辺を足す
//! ことはオーナーの承認事項である。cli が本型を採用するかも TASK-98.2 で決める。

use std::fmt;
use std::io::Write;

use serde::{Serialize, Serializer};

use crate::traits::{ErrorCode, TraitError};

/// 1 行（LF を含まない JSON 本体）の最大バイト数。
///
/// 下限側の根拠: 監査の `path` は最大 4096 バイトで、制御文字が `\u00XX`（6 バイト）に
/// エスケープされると約 24 KiB になる。これと他のキーが収まる必要がある。
/// 上限側の根拠: journald の `LineMax` 既定値は 48 KiB で、超えた行は分割され
/// 「1 行 1 JSON」が壊れる。それより小さくする。
pub const MAX_LOG_LINE_BYTES: usize = 32 * 1024;

/// [`LogEvent`] の最大バイト数。
pub const LOG_EVENT_MAX_LEN: usize = 64;

/// ログ行の重大度。`syslog_severity` で journald の `PRIORITY` へ写せる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogLevel {
    /// エラー。
    Error,
    /// 警告。
    Warn,
    /// 情報。
    Info,
    /// デバッグ。
    Debug,
}

impl LogLevel {
    /// 出力に使う小文字の名前を返す（既存の警告行の `"warn"` と一致する）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    /// RFC 5424 の severity 値（err=3・warning=4・info=6・debug=7）を返す。
    pub fn syslog_severity(self) -> u8 {
        match self {
            Self::Error => 3,
            Self::Warn => 4,
            Self::Info => 6,
            Self::Debug => 7,
        }
    }
}

impl Serialize for LogLevel {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// イベント名。許す文字は `[a-z0-9._]`、長さは 1〜[`LOG_EVENT_MAX_LEN`] バイト。
///
/// 閉じた enum にしない: 名前は出力する各モジュールが持つ（REPAIR-1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogEvent(&'static str);

/// 名前が条件を満たすかを const 文脈でも判定する。
const fn event_name_is_valid(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > LOG_EVENT_MAX_LEN {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'_';
        if !ok {
            return false;
        }
        i += 1;
    }
    true
}

impl LogEvent {
    /// 静的な名前から const 文脈でも作る。不正な名前は `None`（panic しない）。
    ///
    /// `const` 項目では `match` で `None` を拒否すれば、不正な名前をコンパイル時に弾ける。
    pub const fn from_static(name: &'static str) -> Option<Self> {
        if event_name_is_valid(name) {
            Some(Self(name))
        } else {
            None
        }
    }

    /// 実行時に検証して作る。不正な名前は [`ErrorCode::InvalidArgument`]。
    ///
    /// 名前は `'static` を要求する（出力する各モジュールが定数として持つ）。
    pub fn new(name: &'static str) -> Result<Self, TraitError> {
        if event_name_is_valid(name) {
            Ok(Self(name))
        } else {
            Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "log event name must match [a-z0-9._]{1,64}",
            ))
        }
    }

    /// 名前を返す。
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

impl Serialize for LogEvent {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.0)
    }
}

/// 1 行分の封筒。`level`（任意）→ `event` → 本体 `fields`（flatten）の順に出す。
#[derive(Debug, Serialize)]
pub struct LogLine<'a, F: Serialize> {
    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<LogLevel>,
    event: LogEvent,
    #[serde(flatten)]
    fields: &'a F,
}

impl<'a, F: Serialize> LogLine<'a, F> {
    /// level なしの行を作る。`fields` は JSON オブジェクトになる型でなければならない。
    pub fn new(event: LogEvent, fields: &'a F) -> Self {
        Self {
            level: None,
            event,
            fields,
        }
    }

    /// level を付ける。
    pub fn with_level(mut self, level: LogLevel) -> Self {
        self.level = Some(level);
        self
    }
}

/// [`LogLineError`] の分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogLineErrorKind {
    /// JSON にできなかった（オブジェクトでない本体を含む）。
    Encode,
    /// 行が [`MAX_LOG_LINE_BYTES`] を超えた。
    TooLong,
    /// 書き込み先の I/O が失敗した。
    Io,
}

/// ログ行の組み立て・書き込みの失敗。Io 以外では何も書かれない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogLineError {
    kind: LogLineErrorKind,
}

impl LogLineError {
    const fn of(kind: LogLineErrorKind) -> Self {
        Self { kind }
    }

    /// 失敗の分類を返す。
    pub fn kind(&self) -> LogLineErrorKind {
        self.kind
    }

    /// ERR-1 の体系での分類。Io は `Internal`、それ以外は `InvalidArgument`。
    pub fn error_code(&self) -> ErrorCode {
        match self.kind {
            LogLineErrorKind::Io => ErrorCode::Internal,
            LogLineErrorKind::Encode | LogLineErrorKind::TooLong => ErrorCode::InvalidArgument,
        }
    }

    /// 英語の固定メッセージ。
    pub fn message(&self) -> &'static str {
        match self.kind {
            LogLineErrorKind::Encode => "log line could not be encoded as a JSON object",
            LogLineErrorKind::TooLong => "log line exceeds the maximum length",
            LogLineErrorKind::Io => "failed to write log line",
        }
    }
}

impl fmt::Display for LogLineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for LogLineError {}

/// 上限（[`MAX_LOG_LINE_BYTES`]）を超える書き込みを確保前に拒否するバッファ。
///
/// 巨大な本体で無制限に確保してから長さを検査する DoS を防ぐ（REPAIR-5）。
struct LimitedBuf {
    buf: Vec<u8>,
    over: bool,
}

impl Write for LimitedBuf {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.buf.len().saturating_add(data.len()) > MAX_LOG_LINE_BYTES {
            self.over = true;
            return Err(std::io::Error::other("log line too long"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 末尾 LF つきの 1 行分のバイト列を作る。ロックの中でバッファを書く呼び出し元向け。
pub fn encode_json_line<F: Serialize>(line: &LogLine<'_, F>) -> Result<Vec<u8>, LogLineError> {
    let mut w = LimitedBuf {
        buf: Vec::new(),
        over: false,
    };
    if serde_json::to_writer(&mut w, line).is_err() {
        let kind = if w.over {
            LogLineErrorKind::TooLong
        } else {
            LogLineErrorKind::Encode
        };
        return Err(LogLineError::of(kind));
    }
    let mut buf = w.buf;
    if buf.first() != Some(&b'{') || buf.iter().any(|&b| b == b'\n' || b == b'\r') {
        return Err(LogLineError::of(LogLineErrorKind::Encode));
    }
    if buf.len() > MAX_LOG_LINE_BYTES {
        return Err(LogLineError::of(LogLineErrorKind::TooLong));
    }
    buf.push(b'\n');
    Ok(buf)
}

/// 1 行を組み立て、成功したときだけ `write_all` 1 回で書く。
pub fn write_json_line<F: Serialize>(
    out: &mut dyn Write,
    line: &LogLine<'_, F>,
) -> Result<(), LogLineError> {
    let bytes = encode_json_line(line)?;
    out.write_all(&bytes)
        .map_err(|_| LogLineError::of(LogLineErrorKind::Io))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Kv {
        k: u32,
    }

    #[derive(Serialize)]
    struct Tiocsti {
        sysctl: &'static str,
        value: u32,
    }

    #[derive(Serialize)]
    struct Meta {
        ops: u32,
        dropped_records: u32,
    }

    #[derive(Serialize)]
    struct Audit<'a> {
        layer: &'a str,
        ts_sec: u64,
        ts_nsec: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<&'a str>,
        container_id: &'a str,
    }

    #[derive(Serialize)]
    struct Hostile<'a> {
        s: &'a str,
    }

    fn ev(n: &'static str) -> LogEvent {
        LogEvent::new(n).expect("valid event")
    }

    fn enc<F: Serialize>(line: &LogLine<'_, F>) -> String {
        String::from_utf8(encode_json_line(line).expect("encode")).expect("utf8")
    }

    #[test]
    fn err4_exact_bytes_without_level() {
        let b = Kv { k: 1 };
        assert_eq!(
            enc(&LogLine::new(ev("audit"), &b)),
            "{\"event\":\"audit\",\"k\":1}\n"
        );
    }

    #[test]
    fn err4_exact_bytes_with_level_first() {
        let b = Kv { k: 1 };
        let l = LogLine::new(ev("x"), &b).with_level(LogLevel::Warn);
        assert_eq!(enc(&l), "{\"level\":\"warn\",\"event\":\"x\",\"k\":1}\n");
    }

    #[test]
    fn err4_reproduces_legacy_tiocsti_line() {
        // 出典: legacy_tiocsti.rs の既存の警告行。
        let b = Tiocsti {
            sysctl: "dev.tty.legacy_tiocsti",
            value: 1,
        };
        let l = LogLine::new(ev("legacy_tiocsti_enabled"), &b).with_level(LogLevel::Warn);
        assert_eq!(
            enc(&l),
            "{\"level\":\"warn\",\"event\":\"legacy_tiocsti_enabled\",\"sysctl\":\"dev.tty.legacy_tiocsti\",\"value\":1}\n"
        );
    }

    #[test]
    fn err4_reproduces_op_stats_meta_line() {
        let b = Meta {
            ops: 3,
            dropped_records: 7,
        };
        assert_eq!(
            enc(&LogLine::new(ev("op_stats_meta"), &b)),
            "{\"event\":\"op_stats_meta\",\"ops\":3,\"dropped_records\":7}\n"
        );
    }

    #[test]
    fn err4_reproduces_audit_line_shape() {
        let a = Audit {
            layer: "seccomp",
            ts_sec: 10,
            ts_nsec: 5,
            reason: None,
            container_id: "c1",
        };
        assert_eq!(
            enc(&LogLine::new(ev("audit"), &a)),
            "{\"event\":\"audit\",\"layer\":\"seccomp\",\"ts_sec\":10,\"ts_nsec\":5,\"container_id\":\"c1\"}\n"
        );
        let a = Audit {
            reason: Some("denied"),
            ..a
        };
        assert_eq!(
            enc(&LogLine::new(ev("audit"), &a)),
            "{\"event\":\"audit\",\"layer\":\"seccomp\",\"ts_sec\":10,\"ts_nsec\":5,\"reason\":\"denied\",\"container_id\":\"c1\"}\n"
        );
    }

    #[test]
    fn err4_single_line_with_hostile_strings() {
        let nasty = "a\nb\rc\0d\u{2028}e\u{0085}f\"g\\h";
        let h = Hostile { s: nasty };
        let bytes = encode_json_line(&LogLine::new(ev("x"), &h)).expect("encode");
        assert_eq!(bytes.iter().filter(|&&b| b == b'\n').count(), 1);
        assert_eq!(bytes.last(), Some(&b'\n'));
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["s"], nasty);
    }

    #[test]
    fn err4_stream_of_lines_is_json_lines() {
        let mut out: Vec<u8> = Vec::new();
        for k in 0..3 {
            write_json_line(&mut out, &LogLine::new(ev("x"), &Kv { k })).expect("write");
        }
        let text = String::from_utf8(out).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        for (i, l) in lines.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(l).expect("json");
            assert!(v.is_object());
            assert_eq!(v["k"], i as u64);
        }
    }

    #[test]
    fn err4_non_object_payload_is_rejected_and_writes_nothing() {
        let mut out: Vec<u8> = Vec::new();
        let n = 42u32;
        let e = write_json_line(&mut out, &LogLine::new(ev("x"), &n)).expect_err("reject");
        assert_eq!(e.kind(), LogLineErrorKind::Encode);
        assert!(out.is_empty());
        let s = "s";
        assert!(write_json_line(&mut out, &LogLine::new(ev("x"), &s)).is_err());
        assert!(out.is_empty());
    }

    #[test]
    fn err4_too_long_is_rejected_and_writes_nothing() {
        let fixed = "{\"event\":\"x\",\"s\":\"\"}".len();
        let ok = "a".repeat(MAX_LOG_LINE_BYTES - fixed);
        let mut out: Vec<u8> = Vec::new();
        write_json_line(&mut out, &LogLine::new(ev("x"), &Hostile { s: &ok })).expect("exact fit");
        assert_eq!(out.len(), MAX_LOG_LINE_BYTES + 1);
        let mut out: Vec<u8> = Vec::new();
        let over = "a".repeat(MAX_LOG_LINE_BYTES - fixed + 1);
        let e = write_json_line(&mut out, &LogLine::new(ev("x"), &Hostile { s: &over }))
            .expect_err("too long");
        assert_eq!(e.kind(), LogLineErrorKind::TooLong);
        assert_eq!(e.error_code(), ErrorCode::InvalidArgument);
        assert!(out.is_empty());
    }

    #[test]
    fn err4_audit_path_worst_case_fits() {
        let path = "\u{1}".repeat(4096);
        let h = Hostile { s: &path };
        let bytes = encode_json_line(&LogLine::new(ev("audit"), &h)).expect("fits");
        assert_eq!(
            bytes.len(),
            "{\"event\":\"audit\",\"s\":\"\"}\n".len() + 4096 * 6
        );
        assert!(bytes.len() <= MAX_LOG_LINE_BYTES);
    }

    struct FailWriter;
    impl Write for FailWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("boom"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn err4_io_failure_is_internal() {
        let e =
            write_json_line(&mut FailWriter, &LogLine::new(ev("x"), &Kv { k: 1 })).expect_err("io");
        assert_eq!(e.kind(), LogLineErrorKind::Io);
        assert_eq!(e.error_code(), ErrorCode::Internal);
        assert_eq!(e.to_string(), "failed to write log line");
    }

    #[test]
    fn err4_event_name_validation() {
        for ok in [
            "audit",
            "op_stats",
            "op_stats_meta",
            "legacy_tiocsti_enabled",
            "win.warning",
        ] {
            assert_eq!(LogEvent::new(ok).expect("ok").as_str(), ok);
        }
        let long: &'static str = Box::leak("a".repeat(65).into_boxed_str());
        for bad in ["", "Audit", "a b", "a\"b", "a\nb", "日本語", long] {
            let e = LogEvent::new(bad).expect_err("bad");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn err4_event_from_static_in_const() {
        const E: LogEvent = match LogEvent::from_static("audit") {
            Some(e) => e,
            None => panic!("invalid event"),
        };
        assert_eq!(E.as_str(), "audit");
        assert!(LogEvent::from_static("").is_none());
        assert!(LogEvent::from_static("Bad").is_none());
    }

    #[test]
    fn err4_level_strings_and_syslog_severity() {
        let all = [
            (LogLevel::Error, "error", 3),
            (LogLevel::Warn, "warn", 4),
            (LogLevel::Info, "info", 6),
            (LogLevel::Debug, "debug", 7),
        ];
        for (l, s, n) in all {
            assert_eq!(l.as_str(), s);
            assert_eq!(l.syslog_severity(), n);
        }
    }

    #[derive(Serialize)]
    struct Colliding {
        event: &'static str,
    }

    #[test]
    fn err4_reserved_key_collision_is_documented_failure_mode() {
        // 契約違反の形を固定するだけで、挙動の保証ではない（重複キーの出力、または Encode）。
        if let Ok(b) = encode_json_line(&LogLine::new(ev("x"), &Colliding { event: "y" })) {
            let s = String::from_utf8(b).expect("utf8");
            assert_eq!(s.matches("\"event\"").count(), 2);
        }
    }
}
