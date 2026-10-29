//! 試験共有補助 `support/reap.rs` の期限切れ経路の照合（REPAIR-5・REPAIR-12・#3302）。
//! core・supervisor の試験が使う期限つき回収が、止まった子に対して無期限に待たず、具体的な
//! メッセージの `Err` で失敗を表に出すことを固定する。libtest ハーネス・全 OS で動く。

#[path = "support/reap.rs"]
mod reap;

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
}

#[test]
fn repair5_reap_is_ok_for_already_reaped_child() {
    let mut g = spawn_self(false);
    reap::wait_within(&mut g.0, Duration::from_secs(10)).expect("child exits by itself");
    reap::reap(&mut g.0, Duration::from_secs(10)).expect("reaping a reaped child is Ok");
}
