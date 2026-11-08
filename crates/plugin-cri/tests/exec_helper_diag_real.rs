//! stream-exec helper の fd 2 の結線の結合試験（CRI-6・SUP-6・REPAIR-4・REPAIR-5・#4171）。
//!
//! 本番の spawner が使う `spawn_helper_command` で実際の子プロセスを起動し、子の stderr（fd 2）へ書いた診断が
//! 構造化ログへ転送されること、子の終了後に読み手が EOF で停止すること（親に書き込み端が残っていないこと）を
//! 具体値で照合する。root も実コンテナも不要（子は `/bin/sh`）。単体試験は偽の socket を使うため、この結線は検出できない。

#![cfg(target_os = "linux")]

use std::io::Write;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_plugin_cri::streaming::exec_launcher::diagnostics::{
    DiagTracker, spawn_reader,
};
use fandhe_container_plugin_cri::streaming::exec_launcher::spawn_helper_command;
use fandhe_container_plugin_cri::telemetry::LineSink;

struct Collect(Arc<Mutex<Vec<u8>>>);

impl Write for Collect {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn cri6_4171_real_child_fd2_reaches_log_and_reader_stops_after_exit() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf 'stage=open_entrypoint errno=13\\n' >&2"]);
    let mut helper = spawn_helper_command(command).expect("spawn");
    let diag = helper.diagnostics.take().expect("diagnostics end");

    let buf = Arc::new(Mutex::new(Vec::new()));
    let sink = LineSink::spawn(Box::new(Collect(Arc::clone(&buf))), 256);
    let tracker = Arc::new(DiagTracker::default());
    let stop = Arc::new(AtomicBool::new(false));
    spawn_reader(
        diag,
        stop,
        Instant::now() + Duration::from_secs(30),
        sink.clone(),
        &tracker,
    )
    .expect("reader");

    let status = helper.child.wait().expect("wait");
    assert!(status.success(), "child status: {status:?}");
    // 子の終了で EOF となり、読み手が（stop も期限も使わず）自力で止まる = 親に書き込み端が残っていない。
    let t0 = Instant::now();
    assert_eq!(tracker.wait_idle(Duration::from_secs(10)), 0);
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "reader must stop by EOF: {:?}",
        t0.elapsed()
    );
    sink.wait_idle(Duration::from_secs(5));
    let text = String::from_utf8(buf.lock().expect("lock").clone()).expect("utf8");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.first().copied(),
        Some(
            "{\"event\":\"cri_exec_helper_diagnostic\",\"stage\":\"open_entrypoint\",\"errno\":13}"
        ),
        "lines: {lines:?}"
    );
}
