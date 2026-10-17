//! `stderr_sink` の書き先の差し込み口（`install_stderr_writer`）の結合試験（#2067・REPAIR-4）。
//!
//! 差し込み先は共有の出口でプロセス単位のグローバル状態のため、この試験バイナリには `#[test]` を 1 本だけ置き、
//! 順に照合する。

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_core::traits::ErrorCode;
use fandhe_container_supervisor::stderr_sink::{
    EmitOutcome, flush_stderr, install_stderr_writer, stderr,
};

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// REPAIR-4: 差し込んだ書き手へ共有の出口の行が届き、使い始めた後や 2 回目の差し込みは拒否される。
#[test]
fn repair4_installed_writer_receives_shared_sink_lines() {
    let buf = SharedBuf::default();
    // 共有の出口を使う前は、何も待つものが無い。
    assert_eq!(
        flush_stderr(Duration::from_secs(1)),
        EmitOutcome::NothingQueued
    );
    install_stderr_writer(Box::new(buf.clone())).expect("first install");
    // 2 回目は拒否（黙って捨てない）。
    let e = install_stderr_writer(Box::new(SharedBuf::default())).expect_err("second install");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);

    assert_eq!(
        stderr().emit_and_wait(b"hello\n".to_vec(), Duration::from_secs(5)),
        EmitOutcome::Written
    );
    assert_eq!(buf.0.lock().unwrap().as_slice(), b"hello\n");

    // 共有の出口を使い始めた後の差し込みも拒否される。
    let e = install_stderr_writer(Box::new(SharedBuf::default())).expect_err("late install");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
}
