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
