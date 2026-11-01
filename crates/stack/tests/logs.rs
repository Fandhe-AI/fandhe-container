//! `logs` の結合試験（STACK-8・TASK-155.5・#622・REPAIR-12）。
//!
//! 公開 API と偽ソースだけで、指定サービスのログだけが加工されずに出力されること（受け入れ条件）、
//! 事前検査でのソース未呼び出し、失敗の区別、秘密値の非露出を具体値で照合する。
//! 実プロセスを起動しないため既定のテスト集合で走る。範囲外: 本番アダプタ・CLI 結線（#3639）。

use std::collections::BTreeMap;
use std::io::{self, Write};

use fandhe_container_stack::cli::{LogSourceError, LogsError, ServiceLogSource, logs};
use fandhe_container_stack::schema::{ComposeToml, Service};

const SRC: &str = r#"
[project]
name = "p"

[services.web]
image = "example/web:1"
[services.web.env]
SECRET_TOKEN = "dummy-secret-value"

[services.db]
image = "example/db:1"
"#;

fn services() -> BTreeMap<String, Service> {
    toml::from_str::<ComposeToml>(SRC).unwrap().services
}

#[derive(Default)]
struct Fake {
    data: BTreeMap<&'static str, Vec<u8>>,
    fail: Option<LogSourceError>,
    calls: Vec<String>,
}

impl ServiceLogSource for Fake {
    fn write_logs(
        &mut self,
        service: &str,
        _spec: &Service,
        out: &mut dyn Write,
    ) -> Result<(), LogSourceError> {
        self.calls.push(service.to_string());
        if let Some(e) = &self.fail {
            return Err(e.clone());
        }
        let bytes = self.data.get(service).cloned().unwrap_or_default();
        out.write_all(&bytes)
            .map_err(|_| LogSourceError::new("INTERNAL", "write failed", 1))
    }
}

fn fake() -> Fake {
    let mut f = Fake::default();
    f.data
        .insert("web", b"stdout hello\nstderr warn\n".to_vec());
    f.data.insert("db", b"db line\n".to_vec());
    f
}

struct FailWriter {
    fail_write: bool,
}
impl Write for FailWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.fail_write {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        } else {
            Ok(buf.len())
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

#[test]
fn stack_8_logs_writes_only_requested_service() {
    let mut src = fake();
    let mut out = Vec::new();
    let r = logs(&services(), "web", &mut src, &mut out).unwrap();
    assert_eq!(out, b"stdout hello\nstderr warn\n");
    assert_eq!(r.service(), "web");
    assert_eq!(r.bytes_written(), 25);
    assert_eq!(src.calls, vec!["web".to_string()]);
}

#[test]
fn stack_8_logs_passes_bytes_unmodified() {
    let mut src = fake();
    let raw = b"\x1b[2J\xff\xfe\x00end".to_vec();
    src.data.insert("web", raw.clone());
    let mut out = Vec::new();
    logs(&services(), "web", &mut src, &mut out).unwrap();
    assert_eq!(out, raw);
}

#[test]
fn stack_8_logs_empty_log_is_ok() {
    let mut src = fake();
    src.data.insert("db", Vec::new());
    let mut out = Vec::new();
    let r = logs(&services(), "db", &mut src, &mut out).unwrap();
    assert!(out.is_empty());
    assert_eq!(r.bytes_written(), 0);
}

#[test]
fn stack_8_logs_unknown_service() {
    let mut src = fake();
    let mut out = Vec::new();
    let e = logs(&services(), "nope", &mut src, &mut out).unwrap_err();
    assert_eq!(e.code(), "NOT_FOUND");
    assert_eq!(e.exit_code().get(), 3);
    assert!(src.calls.is_empty());
    assert!(out.is_empty());
}

#[test]
fn stack_8_logs_invalid_name_not_echoed() {
    for bad in ["../db", "we\x1bb"] {
        let mut src = fake();
        let mut out = Vec::new();
        let e = logs(&services(), bad, &mut src, &mut out).unwrap_err();
        assert_eq!(e.code(), "INVALID_ARGUMENT");
        assert_eq!(e.exit_code().get(), 2);
        assert!(src.calls.is_empty());
        assert!(!e.to_string().contains(bad));
    }
}

#[test]
fn stack_8_logs_source_error_carries_code_and_exit() {
    let mut src = fake();
    src.fail = Some(LogSourceError::new("UNAVAILABLE", "supervisor down", 9));
    let mut out = Vec::new();
    let e = logs(&services(), "web", &mut src, &mut out).unwrap_err();
    assert!(matches!(e, LogsError::Source { .. }));
    assert_eq!(e.code(), "UNAVAILABLE");
    assert_eq!(e.exit_code().get(), 9);
    assert_eq!(e.message(), "failed to read service logs");
}

#[test]
fn stack_8_logs_output_failures_are_distinguished() {
    let mut src = fake();
    let mut w = FailWriter { fail_write: true };
    let e = logs(&services(), "web", &mut src, &mut w).unwrap_err();
    assert!(matches!(e, LogsError::Output));
    assert_eq!((e.code(), e.exit_code().get()), ("INTERNAL", 1));

    let mut src = fake();
    let mut w = FailWriter { fail_write: false };
    let e = logs(&services(), "web", &mut src, &mut w).unwrap_err();
    assert!(matches!(e, LogsError::Output));
}

#[test]
fn stack_8_logs_errors_do_not_leak_env() {
    let mut src = fake();
    src.fail = Some(LogSourceError::new("UNAVAILABLE", "x", 9));
    let mut out = Vec::new();
    let errs = [
        logs(&services(), "web", &mut src, &mut out).unwrap_err(),
        logs(&services(), "zzz", &mut src, &mut out).unwrap_err(),
        logs(&services(), "a/b", &mut src, &mut out).unwrap_err(),
    ];
    for e in errs {
        assert!(!format!("{e} {e:?}").contains("dummy-secret-value"));
    }
}

/// 書き込み失敗を握りつぶして `Ok` を返す偽ソース。
struct Swallow;
impl ServiceLogSource for Swallow {
    fn write_logs(
        &mut self,
        _service: &str,
        _spec: &Service,
        out: &mut dyn Write,
    ) -> Result<(), LogSourceError> {
        let _ = out.write_all(b"lost");
        Ok(())
    }
}

#[test]
fn stack_8_logs_swallowed_write_failure_is_output_error() {
    let mut w = FailWriter { fail_write: true };
    let e = logs(&services(), "web", &mut Swallow, &mut w).unwrap_err();
    assert!(matches!(e, LogsError::Output));
    assert_eq!((e.code(), e.exit_code().get()), ("INTERNAL", 1));
}

/// 最初の書き込みと flush が `Interrupted` で失敗し、その後は成功する出力先。
struct InterruptOnce {
    write_interrupted: bool,
    flush_interrupted: bool,
    buf: Vec<u8>,
}
impl Write for InterruptOnce {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.write_interrupted {
            self.write_interrupted = true;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if !self.flush_interrupted {
            self.flush_interrupted = true;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        Ok(())
    }
}

/// STACK-8: Interrupted は再試行で成功すれば出力失敗にしない。
#[test]
fn stack_8_logs_interrupted_write_is_retried() {
    let mut w = InterruptOnce {
        write_interrupted: false,
        flush_interrupted: false,
        buf: Vec::new(),
    };
    let r = logs(&services(), "db", &mut fake(), &mut w).unwrap();
    assert_eq!(r.bytes_written(), 8);
    assert_eq!(w.buf, b"db line\n");
}

/// 非空バッファに `Ok(0)` を返す出力先。
struct ZeroWriter;
impl Write for ZeroWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Ok(0)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// STACK-8: `Ok(0)`（WriteZero）は Source ではなく Output。握りつぶすソースでも成功にしない。
#[test]
fn stack_8_logs_write_zero_is_output_error() {
    let e = logs(&services(), "web", &mut fake(), &mut ZeroWriter).unwrap_err();
    assert!(matches!(e, LogsError::Output));
    let e = logs(&services(), "web", &mut Swallow, &mut ZeroWriter).unwrap_err();
    assert!(matches!(e, LogsError::Output));
}
