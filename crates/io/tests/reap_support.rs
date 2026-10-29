//! 試験用の期限つき回収補助 `support/reap.rs` の期限切れの経路の照合（REPAIR-5・REPAIR-12・#3303）。
//!
//! `reap` 自体の期限切れは SIGKILL が無視できず決定的に起こせないため、同じ形の `wait_within` の
//! 期限切れ（終了しない子）を具体的なメッセージで照合し、そのあと `reap` で孤児を残さず回収できることを確かめる。
#![cfg(unix)]

use std::os::unix::process::ExitStatusExt as _;
use std::process::Command;
use std::time::Duration;

#[path = "support/reap.rs"]
mod reap;

#[test]
fn repair5_reap_support_wait_within_expiry_is_reported() {
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    let pid = child.id();
    let within = Duration::from_millis(200);
    assert_eq!(
        reap::wait_within(&mut child, within),
        Err(format!("child {pid} did not exit within {within:?}"))
    );
    assert_eq!(reap::reap(&mut child, reap::REAP_WITHIN), Ok(()));
    let st = child.try_wait().unwrap().expect("reaped");
    assert_eq!(st.signal(), Some(9));
}
