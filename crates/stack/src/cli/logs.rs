//! `logs <service>` の注入式オーケストレーション（STACK-8・TASK-155.5・#622）。
//!
//! CLI の `logs` サブコマンド（結線は #3639）から呼ばれ、サービス名の検証、定義への存在照合、
//! ログの読み出しポート [`ServiceLogSource`] の呼び出しと出力先への中継だけを担う。
//! バイト列は加工しない（`--escape` / `--tail` / `--follow` / `--stream` は CLI 層の責務）。
//! ログはメモリに溜めずストリームのまま流す。
//!
//! # 終了コード
//!
//! | エラー | code | 終了コード |
//! | ------ | ---- | ---------- |
//! | 名前が不正 | `INVALID_ARGUMENT` | 2 |
//! | 未定義のサービス | `NOT_FOUND` | 3 |
//! | 読み出し元の失敗 | ソースの値 | ソースの値 |
//! | 出力先への書き込み失敗 | `INTERNAL` | 1 |
//!
//! # 未実装（実装済みを装わない。REPAIR-3）
//!
//! - 本番の `ServiceLogSource`（サービス名からコンテナ ID への対応づけと supervisor のログ読み出し）
//!   と CLI への結線、依存辺の追加（ユーザー承認事項）: #3639
//! - `--follow` / `--tail` / `--stream` / `--escape` の受け渡し、複数サービス・全サービスの表示

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};
use std::num::NonZeroU8;
use std::time::{Duration, Instant};

use crate::schema::Service;

/// サービス名の最大バイト数。
const MAX_SERVICE_NAME_LEN: usize = 255;

/// [`ServiceLogSource`] の失敗。固定文字列の code / message と終了コードを運ぶ。
///
/// 本番アダプタが CLI の `logs` の終了コードを潰さずに運べるよう、終了コードも持つ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSourceError {
    code: &'static str,
    message: &'static str,
    exit_code: NonZeroU8,
}

impl LogSourceError {
    /// 失敗を作る。`exit_code` が 0 のときは 1 に丸める（失敗を成功に見せない）。
    pub fn new(code: &'static str, message: &'static str, exit_code: u8) -> Self {
        Self {
            code,
            message,
            exit_code: NonZeroU8::new(exit_code).unwrap_or(NonZeroU8::MIN),
        }
    }

    /// 機械可読な code。
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// 固定の message。
    pub fn message(&self) -> &'static str {
        self.message
    }

    /// 終了コード。
    pub fn exit_code(&self) -> NonZeroU8 {
        self.exit_code
    }
}

impl fmt::Display for LogSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for LogSourceError {}

/// サービスのログを読み出すポート。`logs` から呼ばれ、本番実装は #3639 で追う。
///
/// 実装側の契約:
/// - (a) `service` は利用者入力由来。stack は文字種と定義への存在だけを検証して渡す。
///   ID・パス要素に使う前に実装側でも検証する。
/// - (b) 今回のプロジェクトのサービスに対応するコンテナのログだけを書く
///   （別プロジェクト・前回の記録を混ぜない）。
/// - (c) ブロックする実装は上限を持つ（REPAIR-5）。
/// - (d) `spec` は資格情報（`env`）を含みうる。ログ・エラーへ `{:?}` で出さない。
/// - (e) バイト列は加工せずに `out` へ書く。`out` への書き込み失敗はそのまま `Err` を返してよい
///   （`logs` は出力失敗として区別する）。
pub trait ServiceLogSource {
    /// `service` のログを `out` へ書く。
    fn write_logs(
        &mut self,
        service: &str,
        spec: &Service,
        out: &mut dyn Write,
    ) -> Result<(), LogSourceError>;
}

/// `logs` の成功報告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogsReport {
    service: String,
    bytes_written: u64,
}

impl LogsReport {
    /// ログを表示したサービス名。
    pub fn service(&self) -> &str {
        &self.service
    }

    /// 出力先へ書いたバイト数。
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

/// `logs` の失敗。`Display` に `Service` の中身を出さない。
#[derive(Debug)]
#[non_exhaustive]
pub enum LogsError {
    /// サービス名が不正。argv 由来で制御文字を含みうるため名前は保持しない。
    InvalidServiceName,
    /// 定義に無いサービス。文字種検証を通った名前だけが来るので表示してよい。
    UnknownService {
        /// 指定されたサービス名。
        service: String,
    },
    /// 読み出し元の失敗。
    Source {
        /// 対象のサービス名。
        service: String,
        /// 元の失敗。
        source: LogSourceError,
    },
    /// 出力先への書き込み・flush の失敗。
    Output,
}

impl LogsError {
    /// 機械可読な code。
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidServiceName => "INVALID_ARGUMENT",
            Self::UnknownService { .. } => "NOT_FOUND",
            Self::Source { source, .. } => source.code(),
            Self::Output => "INTERNAL",
        }
    }

    /// 固定の message。
    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidServiceName => "invalid service name",
            Self::UnknownService { .. } => "service not found",
            Self::Source { .. } => "failed to read service logs",
            Self::Output => "failed to write service logs",
        }
    }

    /// 終了コード（0 は取らない）。
    pub fn exit_code(&self) -> NonZeroU8 {
        match self {
            Self::InvalidServiceName => NonZeroU8::new(2).unwrap_or(NonZeroU8::MIN),
            Self::UnknownService { .. } => NonZeroU8::new(3).unwrap_or(NonZeroU8::MIN),
            Self::Source { source, .. } => source.exit_code(),
            Self::Output => NonZeroU8::MIN,
        }
    }
}

impl fmt::Display for LogsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidServiceName | Self::Output => {
                write!(f, "{}: {}", self.code(), self.message())
            }
            Self::UnknownService { service } => {
                write!(f, "{}: {}: {service}", self.code(), self.message())
            }
            Self::Source { service, source } => {
                write!(
                    f,
                    "{}: {}: {service}: {source}",
                    self.code(),
                    self.message()
                )
            }
        }
    }
}

impl std::error::Error for LogsError {}

/// 1〜255 バイトの `[A-Za-z0-9._-]` だけを許す（compose-spec のサービス名規則に合わせる）。
fn is_valid_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SERVICE_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `logs` 1 回の結果の分類（REPAIR-4）。失敗は `code` だけを持ち、サービスの中身を運ばない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogsOutcome {
    /// 成功。
    Success {
        /// 出力先へ書いたバイト数。
        bytes_written: u64,
    },
    /// 名前の検証失敗（`INVALID_ARGUMENT`）。
    InvalidServiceName,
    /// 定義に無いサービス（`NOT_FOUND`）。
    UnknownService,
    /// 読み出し元の失敗。`code` はソースの値。
    SourceFailed {
        /// ソースの code。
        code: &'static str,
    },
    /// 出力先への書き込み失敗（`INTERNAL`）。
    OutputFailed,
}

/// `logs` 1 回の観測記録。結果の種別と所要時間だけを持つ（ログ本文・env は含めない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogsEvent {
    /// 結果の分類。
    pub outcome: LogsOutcome,
    /// 呼び出しの開始から結果確定までの所要時間。
    pub elapsed: Duration,
}

/// `logs` の結果と所要時間を受けるポート（REPAIR-4）。
///
/// 本番では構造化ログ / メトリクスへ流すアダプタを #3639 の結線で注入する。
/// 実装は `logs` の戻り値を変えず、ブロックしてはならない。
pub trait LogsObserver {
    /// 1 回の `logs` の終了ごとに 1 度だけ呼ばれる（成功・失敗を問わない）。
    fn record(&mut self, event: &LogsEvent);
}

/// 何も記録しない観測ポート。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopLogsObserver;

impl LogsObserver for NoopLogsObserver {
    fn record(&mut self, _event: &LogsEvent) {}
}

/// 時刻の取得元。試験で決定的な時刻を注入するために分ける。
pub trait LogsClock {
    /// 現在時刻。
    fn now(&mut self) -> Instant;
}

/// 実時刻（[`Instant::now`]）。
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemLogsClock;

impl LogsClock for SystemLogsClock {
    fn now(&mut self) -> Instant {
        Instant::now()
    }
}

/// 書いたバイト数を数え、書き込み失敗を記録する出力先ラッパー。
struct CountingWriter<'a, W: Write> {
    inner: &'a mut W,
    written: u64,
    failed: bool,
}

impl<W: Write> Write for CountingWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.inner.write(buf) {
            Ok(0) if !buf.is_empty() => {
                // write_all は WriteZero を返す。出力側の失敗として記録する。
                self.failed = true;
                Ok(0)
            }
            Ok(n) => {
                self.written = self.written.saturating_add(n as u64);
                Ok(n)
            }
            // Interrupted は write_all が再試行するため永続失敗にしない。
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Err(e),
            Err(e) => {
                self.failed = true;
                Err(e)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        loop {
            match self.inner.flush() {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.failed = true;
                    return Err(e);
                }
                Ok(()) => return Ok(()),
            }
        }
    }
}

/// `service` のログを `out` へ流す（STACK-8）。観測は行わない（[`logs_observed`] の薄い包み）。
pub fn logs<S: ServiceLogSource, W: Write>(
    services: &BTreeMap<String, Service>,
    service: &str,
    source: &mut S,
    out: &mut W,
) -> Result<LogsReport, LogsError> {
    logs_observed(
        services,
        service,
        source,
        out,
        &mut NoopLogsObserver,
        &mut SystemLogsClock,
    )
}

/// `service` のログを `out` へ流し、結果と所要時間を `observer` へ 1 件記録する（STACK-8・REPAIR-4）。
///
/// 名前の検証と定義への存在照合を通ったときだけ `source` を呼ぶ。`services` は profiles で
/// 絞り込み済みの map を受ける（`up` と同じ前提。絞られて消えたサービスも `NOT_FOUND`）。
/// 検証失敗・読み出し失敗・出力失敗・成功のいずれでも `observer` は 1 度だけ呼ばれる。
pub fn logs_observed<S, W, O, C>(
    services: &BTreeMap<String, Service>,
    service: &str,
    source: &mut S,
    out: &mut W,
    observer: &mut O,
    clock: &mut C,
) -> Result<LogsReport, LogsError>
where
    S: ServiceLogSource,
    W: Write,
    O: LogsObserver,
    C: LogsClock,
{
    let start = clock.now();
    let result = run_logs(services, service, source, out);
    let outcome = match &result {
        Ok(r) => LogsOutcome::Success {
            bytes_written: r.bytes_written,
        },
        Err(LogsError::InvalidServiceName) => LogsOutcome::InvalidServiceName,
        Err(LogsError::UnknownService { .. }) => LogsOutcome::UnknownService,
        Err(LogsError::Source { source, .. }) => LogsOutcome::SourceFailed {
            code: source.code(),
        },
        Err(LogsError::Output) => LogsOutcome::OutputFailed,
    };
    let elapsed = clock.now().saturating_duration_since(start);
    observer.record(&LogsEvent { outcome, elapsed });
    result
}

fn run_logs<S: ServiceLogSource, W: Write>(
    services: &BTreeMap<String, Service>,
    service: &str,
    source: &mut S,
    out: &mut W,
) -> Result<LogsReport, LogsError> {
    if !is_valid_service_name(service) {
        return Err(LogsError::InvalidServiceName);
    }
    let spec = services
        .get(service)
        .ok_or_else(|| LogsError::UnknownService {
            service: service.to_string(),
        })?;
    let mut counting = CountingWriter {
        inner: out,
        written: 0,
        failed: false,
    };
    if let Err(e) = source.write_logs(service, spec, &mut counting) {
        return Err(if counting.failed {
            LogsError::Output
        } else {
            LogsError::Source {
                service: service.to_string(),
                source: e,
            }
        });
    }
    // ソースが書き込み失敗を握りつぶして Ok を返しても、ログ欠落を成功にしない。
    if counting.flush().is_err() || counting.failed {
        return Err(LogsError::Output);
    }
    Ok(LogsReport {
        service: service.to_string(),
        bytes_written: counting.written,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STACK-8: 名前検証の境界値。
    #[test]
    fn stack_8_service_name_validation() {
        assert!(!is_valid_service_name(""));
        assert!(is_valid_service_name(&"a".repeat(255)));
        assert!(!is_valid_service_name(&"a".repeat(256)));
        assert!(is_valid_service_name("a..b"));
        assert!(is_valid_service_name("web_1-x.y"));
        for bad in ["a/b", "a b", "\x1b[2J", "日本語", "a\n"] {
            assert!(!is_valid_service_name(bad), "{bad:?}");
        }
    }

    /// STACK-8: エラーの code / 終了コード表。
    #[test]
    fn stack_8_error_codes() {
        let src = LogSourceError::new("UNAVAILABLE", "x", 9);
        let cases = [
            (LogsError::InvalidServiceName, "INVALID_ARGUMENT", 2),
            (
                LogsError::UnknownService {
                    service: "a".into(),
                },
                "NOT_FOUND",
                3,
            ),
            (
                LogsError::Source {
                    service: "a".into(),
                    source: src,
                },
                "UNAVAILABLE",
                9,
            ),
            (LogsError::Output, "INTERNAL", 1),
        ];
        for (e, code, exit) in cases {
            assert_eq!(e.code(), code);
            assert_eq!(e.exit_code().get(), exit);
        }
        assert_eq!(LogSourceError::new("X", "y", 0).exit_code().get(), 1);
    }

    struct FakeClock {
        base: Instant,
        calls: u32,
    }

    impl LogsClock for FakeClock {
        fn now(&mut self) -> Instant {
            self.calls += 1;
            self.base + Duration::from_millis(u64::from(self.calls - 1) * 250)
        }
    }

    #[derive(Default)]
    struct Recorder(Vec<LogsEvent>);

    impl LogsObserver for Recorder {
        fn record(&mut self, event: &LogsEvent) {
            self.0.push(event.clone());
        }
    }

    struct FakeSource(Result<&'static [u8], LogSourceError>);

    impl ServiceLogSource for FakeSource {
        fn write_logs(
            &mut self,
            _service: &str,
            _spec: &Service,
            out: &mut dyn Write,
        ) -> Result<(), LogSourceError> {
            match &self.0 {
                Ok(b) => out
                    .write_all(b)
                    .map_err(|_| LogSourceError::new("INTERNAL", "w", 1)),
                Err(e) => Err(e.clone()),
            }
        }
    }

    struct FailWriter;

    impl Write for FailWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("x"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn observe<W: Write>(
        services: &BTreeMap<String, Service>,
        name: &str,
        mut src: FakeSource,
        out: &mut W,
    ) -> (bool, Vec<LogsEvent>) {
        let mut rec = Recorder::default();
        let mut clock = FakeClock {
            base: Instant::now(),
            calls: 0,
        };
        let ok = logs_observed(services, name, &mut src, out, &mut rec, &mut clock).is_ok();
        (ok, rec.0)
    }

    /// REPAIR-4・STACK-8: 成功と各失敗で結果と所要時間が 1 件ずつ記録される。
    #[test]
    fn repair_4_logs_observer_records_each_outcome() {
        let mut services = BTreeMap::new();
        services.insert("web".to_string(), Service::default());
        let ms = Duration::from_millis(250);
        let one = |outcome| {
            vec![LogsEvent {
                outcome,
                elapsed: ms,
            }]
        };

        let (ok, ev) = observe(&services, "web", FakeSource(Ok(b"hello")), &mut Vec::new());
        assert!(ok);
        assert_eq!(ev, one(LogsOutcome::Success { bytes_written: 5 }));

        let (ok, ev) = observe(&services, "a/b", FakeSource(Ok(b"")), &mut Vec::new());
        assert!(!ok);
        assert_eq!(ev, one(LogsOutcome::InvalidServiceName));

        let (_, ev) = observe(&services, "db", FakeSource(Ok(b"")), &mut Vec::new());
        assert_eq!(ev, one(LogsOutcome::UnknownService));

        let err = LogSourceError::new("UNAVAILABLE", "x", 9);
        let (_, ev) = observe(&services, "web", FakeSource(Err(err)), &mut Vec::new());
        assert_eq!(
            ev,
            one(LogsOutcome::SourceFailed {
                code: "UNAVAILABLE"
            })
        );

        let (_, ev) = observe(&services, "web", FakeSource(Ok(b"x")), &mut FailWriter);
        assert_eq!(ev, one(LogsOutcome::OutputFailed));
    }
}
