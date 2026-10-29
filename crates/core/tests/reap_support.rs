//! 試験共有補助 `support/reap.rs`（全 crate の正本。#3410）の期限切れ経路の照合（REPAIR-5・REPAIR-12・#3302）。
//! 全 crate の試験が使う期限つき回収・期限つき実行（`run_within`）が、止まった子に対して無期限に待たず、具体的な
//! メッセージの `Err` で失敗を表に出すことを固定する。libtest ハーネス・全 OS で動く。

#[path = "support/reap.rs"]
mod reap;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt as _;
use std::process::{Child, Command};
use std::time::Duration;

const CHILD_ENV: &str = "FANDHE_CONTAINER_REAP_SUPPORT_CHILD";

/// 子の役。環境変数があるときだけ上限つきで眠る（通常実行では即座に返る no-op）。
#[test]
fn reap_support_child_blocks() {
    if std::env::var(CHILD_ENV).as_deref() == Ok("1") {
        std::thread::sleep(Duration::from_secs(30));
    }
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
    #[cfg(unix)]
    assert_eq!(
        g.0.try_wait().expect("try_wait").expect("reaped").signal(),
        Some(9)
    );
}

#[test]
fn repair5_reap_is_ok_for_already_reaped_child() {
    let mut g = spawn_self(false);
    reap::wait_within(&mut g.0, Duration::from_secs(10)).expect("child exits by itself");
    reap::reap(&mut g.0, Duration::from_secs(10)).expect("reaping a reaped child is Ok");
}

/// 自己再実行の待ち役コマンド（`blocks` なら眠り続ける）。
fn self_cmd(blocks: bool) -> Command {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = Command::new(exe);
    cmd.args(["--exact", "reap_support_child_blocks", "--test-threads=1"]);
    if blocks {
        cmd.env(CHILD_ENV, "1");
    }
    cmd
}

#[test]
fn repair5_run_within_reports_expiry_and_reaps() {
    let mut cmd = self_cmd(true);
    let program = cmd.get_program().to_string_lossy().into_owned();
    let err = reap::run_within(&mut cmd, Duration::from_millis(200)).expect_err("must expire");
    assert_eq!(err, format!("{program} did not finish within 200ms"));
}

#[test]
fn repair5_run_within_reports_spawn_failure() {
    let missing = std::env::temp_dir().join("fandhe-container-reap-support-no-such-program");
    let program = missing.to_string_lossy().into_owned();
    let mut cmd = Command::new(&missing);
    let err = reap::run_within(&mut cmd, Duration::from_secs(10)).expect_err("spawn must fail");
    assert!(
        err.starts_with(&format!("spawn {program} failed: ")),
        "unexpected message: {err}"
    );
}

#[test]
fn repair5_run_within_returns_status_on_normal_exit() {
    let mut cmd = self_cmd(false);
    let st = reap::run_within(&mut cmd, Duration::from_secs(10)).expect("exits by itself");
    assert!(st.success(), "unexpected status: {st:?}");
}
