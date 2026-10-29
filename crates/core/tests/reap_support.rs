//! 試験共有補助 `support/reap.rs` の期限切れ経路の照合（REPAIR-5・REPAIR-12・#3302）。
//! core・supervisor の試験が使う期限つき回収が、止まった子に対して無期限に待たず、具体的な
//! メッセージの `Err` で失敗を表に出すことを固定する（`run_within`・`output_within` は #3409）。
//! libtest ハーネス・全 OS で動く。

#[path = "support/reap.rs"]
mod reap;

use std::process::{Child, Command};
use std::time::Duration;

const CHILD_ENV: &str = "FANDHE_CONTAINER_REAP_SUPPORT_CHILD";

/// 子の役。環境変数があるときだけ上限つきで眠る（通常実行では即座に返る no-op）。
#[test]
fn reap_support_child_blocks() {
    match std::env::var(CHILD_ENV).as_deref() {
        Ok("1") => std::thread::sleep(Duration::from_secs(30)),
        // 出力先を保持した孫の役。数秒眠り、試験プロセスの終了を待たずに自分で終わる。
        Ok("short") => std::thread::sleep(Duration::from_secs(10)),
        _ => {}
    }
}

/// 子の役。標準出力に固定の印を出して終わる。
#[test]
fn reap_support_child_prints() {
    if std::env::var(CHILD_ENV).as_deref() == Ok("print") {
        println!("REAP_MARK_STDOUT");
        eprintln!("REAP_MARK_STDERR");
    }
}

/// 子の役。出力先を継承した孫を起こして、自身は待たずに終了する。
#[test]
fn reap_support_child_leaves_holder() {
    if std::env::var(CHILD_ENV).as_deref() == Ok("holder") {
        let exe = std::env::current_exe().expect("current_exe");
        // 孫は待たずに残すのが目的（子が終了した後も出力先を保持させる）。
        #[allow(clippy::zombie_processes, reason = "孫を意図して待たずに残す")]
        Command::new(exe)
            .args(["--exact", "reap_support_child_blocks", "--test-threads=1"])
            .env(CHILD_ENV, "short")
            .spawn()
            .expect("spawn holder grandchild");
    }
}

fn self_cmd(test: &str, role: &str) -> Command {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = Command::new(exe);
    cmd.args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, role);
    cmd
}

/// 試験が途中で panic しても子を残さないためのガード。
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        reap::reap_on_drop(&mut self.0);
    }
}

fn spawn_self(blocks: bool) -> Guard {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = Command::new(exe);
    cmd.args(["--exact", "reap_support_child_blocks", "--test-threads=1"]);
    if blocks {
        cmd.env(CHILD_ENV, "1");
    }
    Guard(cmd.spawn().expect("spawn self as child"))
}

#[test]
fn repair5_wait_within_reports_expiry() {
    let mut g = spawn_self(true);
    let pid = g.0.id();
    let err = reap::wait_within(&mut g.0, Duration::from_millis(200)).expect_err("must expire");
    assert_eq!(err, format!("child {pid} did not exit within 200ms"));
    reap::reap(&mut g.0, Duration::from_secs(10)).expect("reap after kill");
    assert!(g.0.try_wait().expect("try_wait").is_some());
}

#[test]
fn repair5_reap_is_ok_for_already_reaped_child() {
    let mut g = spawn_self(false);
    reap::wait_within(&mut g.0, Duration::from_secs(10)).expect("child exits by itself");
    reap::reap(&mut g.0, Duration::from_secs(10)).expect("reaping a reaped child is Ok");
}

#[test]
fn repair5_run_within_reports_expiry_and_reaps() {
    let mut cmd = self_cmd("reap_support_child_blocks", "1");
    let program = cmd.get_program().to_string_lossy().into_owned();
    let err = reap::run_within(&mut cmd, Duration::from_millis(200)).expect_err("must expire");
    assert_eq!(err, format!("{program} did not finish within 200ms"));
}

#[test]
fn repair5_run_within_returns_success_status() {
    let mut cmd = self_cmd("reap_support_child_blocks", "none");
    let st = reap::run_within(&mut cmd, Duration::from_secs(30)).expect("child exits by itself");
    assert!(st.success(), "status: {st}");
}

#[test]
fn repair5_output_within_returns_stdout_and_stderr() {
    let mut cmd = self_cmd("reap_support_child_prints", "print");
    let out = reap::output_within(&mut cmd, Duration::from_secs(30)).expect("output");
    assert!(out.status.success(), "status: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("REAP_MARK_STDOUT"), "stdout: {stdout}");
    assert!(stderr.contains("REAP_MARK_STDERR"), "stderr: {stderr}");
}

#[test]
fn repair5_output_within_reports_expiry() {
    let mut cmd = self_cmd("reap_support_child_blocks", "1");
    let program = cmd.get_program().to_string_lossy().into_owned();
    let err = reap::output_within(&mut cmd, Duration::from_millis(300)).expect_err("must expire");
    assert_eq!(err, format!("{program} did not finish within 300ms"));
}

/// 受け入れ条件 2: 子の終了後に孫が出力先を持ち続けても、pipe の EOF を待たずに戻る
/// （`wait_with_output()` ならこの孫が眠る間ずっと戻らない）。
#[test]
fn repair5_output_within_returns_when_descendant_holds_output() {
    let mut cmd = self_cmd("reap_support_child_leaves_holder", "holder");
    let start = std::time::Instant::now();
    let out = reap::output_within(&mut cmd, Duration::from_secs(30)).expect("output");
    assert!(out.status.success(), "status: {}", out.status);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "returned late: {:?}",
        start.elapsed()
    );
}
