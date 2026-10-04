//! タイムアウトと出力量上限つきの外部プロセス実行器（TASK-67.3・REPAIR-5）。
//!
//! `Command::output()` は待ち時間の上限を持たないため使わない。呼び出し元は `wsl2` モジュールで、
//! プログラムのパスを引数で受け取るので、テストでは本物の `wsl.exe` を起動せずに済む。
//! 期限切れでは子を kill して回収する。読み取りスレッドは孫プロセスがパイプを握り続けても
//! 戻れるよう、無期限に join しない。

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use super::{Wsl2Error, Wsl2ErrorCode};

/// 実行結果（stdout・stderr は `max_bytes` 以下のバイト列）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Captured {
    pub(super) success: bool,
    pub(super) code: Option<i32>,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

/// kill 後に子の終了を待つ上限（REPAIR-5）。超えたら回収不能として `INTERNAL` で返す。
const REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// 1 本のパイプの読み取り結果。
struct Pipe {
    /// 読み取れたバイト列（上限超過時は途中まで）。
    buf: Vec<u8>,
    /// `max_bytes` を超えたか。
    overflow: bool,
    /// `read()` が EOF 以外のエラーで終わったか（途中出力を成功として返さないための印）。
    io_error: bool,
}

/// パイプを `max_bytes` を超えるまで読み、上限超過かどうかと一緒に送る。
fn spawn_reader<R: Read + Send + 'static>(mut r: R, max_bytes: usize) -> Receiver<Pipe> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut overflow = false;
        let mut io_error = false;
        loop {
            match r.read(&mut chunk) {
                Ok(0) => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    io_error = true;
                    break;
                }
                Ok(n) => {
                    let Some(part) = chunk.get(..n) else {
                        io_error = true;
                        break;
                    };
                    buf.extend_from_slice(part);
                    if buf.len() > max_bytes {
                        overflow = true;
                        break;
                    }
                }
            }
        }
        let _ = tx.send(Pipe {
            buf,
            overflow,
            io_error,
        });
    });
    rx
}

/// 子を kill して `REAP_TIMEOUT` 以内に回収する。kill の失敗は無視せず、回収できるまで待つ
/// （既に終了していれば kill は失敗しうるが、その場合は回収に成功する）。
/// 回収できなければ `INTERNAL`（無期限に `wait()` しない。REPAIR-5）。
fn kill_and_reap(child: &mut Child) -> Result<(), Wsl2Error> {
    let kill_result = child.kill();
    let deadline = Instant::now() + REAP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(_) => {
                return Err(Wsl2Error::new(
                    Wsl2ErrorCode::Internal,
                    "failed to reap wsl.exe after kill",
                ));
            }
        }
        if Instant::now() >= deadline {
            let msg = if kill_result.is_err() {
                "failed to kill wsl.exe; the process was not reaped"
            } else {
                "wsl.exe was not reaped before the reap deadline"
            };
            return Err(Wsl2Error::new(Wsl2ErrorCode::Internal, msg));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// 子を kill・回収したうえで `err` を返す。回収に失敗したときはそのエラーを優先する。
fn abort_with(child: &mut Child, err: Wsl2Error) -> Wsl2Error {
    match kill_and_reap(child) {
        Ok(()) => err,
        Err(reap_err) => reap_err,
    }
}

fn spawn_error(e: &std::io::Error) -> Wsl2Error {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::NotFound => Wsl2Error::new(
            Wsl2ErrorCode::NotFound,
            format!(
                "wsl.exe was not found. WSL is not installed. {}",
                super::ENABLE_GUIDE
            ),
        ),
        ErrorKind::PermissionDenied => Wsl2Error::new(
            Wsl2ErrorCode::PermissionDenied,
            "permission denied while starting wsl.exe",
        ),
        _ => Wsl2Error::new(Wsl2ErrorCode::Internal, "failed to start wsl.exe"),
    }
}

/// `program` を固定の `args`・追加環境変数 `envs` で起動し、`timeout` 以内の出力を回収する。
///
/// stdin は null、stdout / stderr はパイプ。期限切れは `TIMEOUT`、出力が `max_bytes` を超えたら
/// `RESOURCE_EXHAUSTED`（どちらも子を kill して回収済み）。
pub(super) fn run_capture(
    program: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
    timeout: Duration,
    max_bytes: usize,
) -> Result<Captured, Wsl2Error> {
    let deadline = Instant::now() + timeout;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().map_err(|e| spawn_error(&e))?;
    let (Some(out_pipe), Some(err_pipe)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(abort_with(
            &mut child,
            Wsl2Error::new(Wsl2ErrorCode::Internal, "failed to capture output pipes"),
        ));
    };
    let out_rx = spawn_reader(out_pipe, max_bytes);
    let err_rx = spawn_reader(err_pipe, max_bytes);

    let mut out: Option<Pipe> = None;
    let mut err: Option<Pipe> = None;
    let mut status = None;
    loop {
        if out.is_none() {
            out = out_rx.try_recv().ok();
        }
        if err.is_none() {
            err = err_rx.try_recv().ok();
        }
        if out.as_ref().is_some_and(|o| o.io_error) || err.as_ref().is_some_and(|e| e.io_error) {
            return Err(abort_with(
                &mut child,
                Wsl2Error::new(Wsl2ErrorCode::Internal, "failed to read wsl.exe output"),
            ));
        }
        if out.as_ref().is_some_and(|o| o.overflow) || err.as_ref().is_some_and(|e| e.overflow) {
            return Err(abort_with(
                &mut child,
                Wsl2Error::new(
                    Wsl2ErrorCode::ResourceExhausted,
                    "wsl.exe output exceeded the size limit",
                ),
            ));
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(s) => status = s,
                Err(_) => {
                    return Err(abort_with(
                        &mut child,
                        Wsl2Error::new(Wsl2ErrorCode::Internal, "failed to wait for wsl.exe"),
                    ));
                }
            }
        }
        if let (Some(s), Some(o), Some(e)) = (status, out.as_ref(), err.as_ref()) {
            return Ok(Captured {
                success: s.success(),
                code: s.code(),
                stdout: o.buf.clone(),
                stderr: e.buf.clone(),
            });
        }
        if Instant::now() >= deadline {
            return Err(abort_with(
                &mut child,
                Wsl2Error::new(
                    Wsl2ErrorCode::Timeout,
                    "wsl.exe did not finish before the deadline",
                ),
            ));
        }
        // 短い間隔のポーリング。期限は上のチェックで保証される。
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENV_MODE: &str = "FANDHE_WSL2_TEST_HELPER";
    const HELPER: &str = "wsl2::run::tests::helper";

    /// 自己再実行される子側。環境変数がなければ即座に成功する（通常のテスト実行では何もしない）。
    #[test]
    fn helper() {
        match std::env::var(ENV_MODE).as_deref() {
            Ok("sleep") => thread::sleep(Duration::from_secs(60)),
            Ok("flood") => {
                use std::io::Write;
                let _ = std::io::stdout().write_all(&vec![b'x'; 100_000]);
            }
            _ => {}
        }
    }

    fn run_helper(mode: &str, timeout: Duration, max: usize) -> Result<Captured, Wsl2Error> {
        let exe = std::env::current_exe().unwrap();
        run_capture(
            &exe,
            &["--exact", HELPER, "--nocapture", "--test-threads=1"],
            &[(ENV_MODE, mode)],
            timeout,
            max,
        )
    }

    /// REPAIR-5: 期限を過ぎたら TIMEOUT で戻り、子は kill・回収される。
    #[test]
    fn timeout_kills_child() {
        let start = Instant::now();
        let e = run_helper("sleep", Duration::from_millis(500), 65536).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
        assert!(start.elapsed() < Duration::from_secs(30));
    }

    /// REPAIR-5: 出力が上限を超えたら RESOURCE_EXHAUSTED。
    #[test]
    fn output_limit_enforced() {
        let e = run_helper("flood", Duration::from_secs(30), 1024).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::ResourceExhausted);
    }

    /// 正常終了では終了コードと stdout を回収する。
    #[test]
    fn captures_success() {
        let o = run_helper("none", Duration::from_secs(30), 65536).unwrap();
        assert!(o.success);
        assert_eq!(o.code, Some(0));
        assert!(!o.stdout.is_empty());
    }

    /// 読み取りエラーは EOF と区別され、途中出力と一緒に io_error として報告される。
    #[test]
    fn reader_reports_io_error() {
        struct Failing(bool);
        impl Read for Failing {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0 {
                    return Err(std::io::Error::other("boom"));
                }
                self.0 = true;
                buf[..3].copy_from_slice(b"abc");
                Ok(3)
            }
        }
        let p = spawn_reader(Failing(false), 1024)
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        assert!(p.io_error);
        assert!(!p.overflow);
        assert_eq!(p.buf, b"abc");
    }

    /// 正常な EOF は io_error にならない。
    #[test]
    fn reader_eof_is_not_error() {
        let p = spawn_reader(&b"hello"[..], 1024)
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        assert!(!p.io_error);
        assert_eq!(p.buf, b"hello");
    }

    /// WIN-1: 存在しないパスは NOT_FOUND。
    #[test]
    fn missing_program() {
        let e = run_capture(
            Path::new("/nonexistent/fandhe/none"),
            &[],
            &[],
            Duration::from_secs(1),
            10,
        )
        .unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::NotFound);
    }
}
