//! virtiofs 実機試験の補助関数（`support/virtiofs_harness.rs`）の単体試験（MAC-1・REPAIR-1・#3099）。
//!
//! `virtiofs_io.rs`・`virtiofs_link.rs` は macOS 限定のため、補助関数の試験を別 target に集め、
//! Linux（ubuntu）でも実行できるようにする。Windows は `std::os::unix` が無いため `#![cfg(unix)]` で 0 件になる。
#![cfg(unix)]

#[path = "support/common.rs"]
mod common;
#[path = "support/virtiofs_harness.rs"]
mod harness;

use std::time::Duration;

use common::{Scratch, env_path, tail_lossy};
use fandhe_container_platform_macos::console_log::TRUNCATION_MARKER;
use harness::{
    CONSOLE_LOG_SETTLE_TIMEOUT, log_truncated, resolve_probe_timeout, wait_console_log_settled,
};

/// MAC-1・IO-5・SEC-4・TASK-65.4・#1877: 上限到達で打ち切られたログは末尾の区切り文で判別できる。
#[test]
fn mac1_repair1_log_truncation_is_detected_by_marker() {
    let mut cut = b"noise".to_vec();
    cut.extend_from_slice(TRUNCATION_MARKER);
    assert!(log_truncated(&cut));
    assert!(!log_truncated(b"noise"));
}

/// MAC-1・IO-5・SEC-4・REPAIR-5: 実機テストの期限は 1..=600 秒（既定 60）。
#[test]
fn mac1_repair1_probe_timeout_bounds() {
    assert_eq!(resolve_probe_timeout(None), Ok(Duration::from_secs(60)));
    assert_eq!(
        resolve_probe_timeout(Some("1".into())),
        Ok(Duration::from_secs(1))
    );
    assert_eq!(
        resolve_probe_timeout(Some("600".into())),
        Ok(Duration::from_secs(600))
    );
    for bad in ["0", "601", "abc", ""] {
        assert!(resolve_probe_timeout(Some(bad.into())).is_err(), "{bad}");
    }
}

/// MAC-1・IO-5・TASK-65.4・REPAIR-5: ログの確定待ちは書き出し側の lock 解放で完了し、
/// 解放されなければ期限で失敗する。
#[test]
fn mac1_repair1_wait_console_log_settled_follows_writer_lock() {
    let s = Scratch::new("settle", false);
    let log = s.file("console.log", b"boot\n");
    // 書き出しスレッドの代役: 別の open で排他 lock を保持し、200ms 後に閉じる。
    let writer = std::fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .expect("open writer");
    writer.lock().expect("writer lock");
    assert_eq!(
        wait_console_log_settled(&log, Duration::from_millis(100)),
        Err("console log writer did not finish within 100ms".to_string())
    );
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        drop(writer);
    });
    assert_eq!(
        wait_console_log_settled(&log, Duration::from_secs(10)),
        Ok(())
    );
    release.join().expect("release thread");
    // ログが無ければ待たずに失敗する。
    let missing = s.dir.join("missing.log");
    assert!(
        wait_console_log_settled(&missing, Duration::from_secs(1))
            .is_err_and(|e| e.starts_with("open console log: "))
    );
}

/// MAC-1・REPAIR-1: `tail_lossy` は末尾 max バイトを返し、不正な UTF-8 は置換する。
#[test]
fn mac1_repair1_tail_lossy_keeps_tail_and_replaces_invalid_utf8() {
    assert_eq!(tail_lossy(b"abc", 10), "abc");
    assert_eq!(tail_lossy(b"abcdef", 3), "def");
    assert_eq!(tail_lossy(b"", 3), "");
    assert_eq!(tail_lossy(&[b'a', 0xff, b'b'], 3), "a\u{fffd}b");
}

/// MAC-1・REPAIR-1: 未設定の環境変数は `None`（環境は書き換えない）。
#[test]
fn mac1_repair1_env_path_unset_is_none() {
    assert_eq!(env_path("FANDHE_CONTAINER_TEST_SURELY_UNSET_3099"), None);
}

/// MAC-1・REPAIR-5: 確定待ちの上限は 30 秒（共通化で変えていないことの固定）。
#[test]
fn mac1_repair1_settle_timeout_is_30s() {
    assert_eq!(CONSOLE_LOG_SETTLE_TIMEOUT, Duration::from_secs(30));
}
