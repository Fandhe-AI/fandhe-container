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
    CONSOLE_LOG_SETTLE_TIMEOUT, CONSOLE_TAIL_BYTES, DONE_POLL_INTERVAL, DoneWait,
    done_wait_failure_message, log_truncated, read_settled_log, resolve_probe_timeout,
    wait_console_log_settled, wait_done_line,
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

fn has_done(b: &[u8]) -> bool {
    b.windows(4).any(|w| w == b"DONE")
}

fn cut(body: &[u8]) -> Vec<u8> {
    let mut v = body.to_vec();
    v.extend_from_slice(TRUNCATION_MARKER);
    v
}

/// MAC-1・REPAIR-1・#3416: done 判定に合うログは `Done` で bytes をそのまま返す。
#[test]
fn mac1_repair1_wait_done_line_returns_done_bytes() {
    let s = Scratch::new("wait-done", false);
    let log = s.file("console.log", b"boot\nDONE\n");
    assert_eq!(
        wait_done_line(&log, Duration::from_secs(5), has_done),
        DoneWait::Done(b"boot\nDONE\n".to_vec())
    );
}

/// MAC-1・REPAIR-1・#3416: done と打ち切りが同時なら done が勝つ（判定順の固定）。
#[test]
fn mac1_repair1_wait_done_line_done_wins_over_truncation() {
    let s = Scratch::new("wait-done-wins", false);
    let body = cut(b"DONE\n");
    let log = s.file("console.log", &body);
    assert_eq!(
        wait_done_line(&log, Duration::from_secs(5), has_done),
        DoneWait::Done(body)
    );
}

/// MAC-1・REPAIR-1・#3416: done 前の打ち切りの message は寄せる前と同一。
#[test]
fn mac1_repair1_wait_done_line_truncated_message_is_unchanged() {
    let s = Scratch::new("wait-trunc", false);
    let body = cut(b"boot\n");
    let log = s.file("console.log", &body);
    let w = wait_done_line(&log, Duration::from_secs(5), has_done);
    assert_eq!(w, DoneWait::Truncated(body.clone()));
    assert_eq!(
        done_wait_failure_message(&w, "probe", Duration::from_secs(5)),
        Some(format!(
            "console log hit the size limit before the probe done line; console tail:\n{}",
            tail_lossy(&body, 4096)
        ))
    );
}

/// MAC-1・REPAIR-1・REPAIR-5・#3416: 期限切れの message は寄せる前と同一（label 差し替えも）。
#[test]
fn mac1_repair1_wait_done_line_timeout_message_is_unchanged() {
    let s = Scratch::new("wait-timeout", false);
    let log = s.file("console.log", b"boot\n");
    let t = Duration::from_millis(200);
    let w = wait_done_line(&log, t, has_done);
    assert_eq!(w, DoneWait::TimedOut(b"boot\n".to_vec()));
    assert_eq!(
        done_wait_failure_message(&w, "probe", t),
        Some("probe done line not observed within 200ms; console tail:\nboot\n".to_string())
    );
    assert_eq!(
        done_wait_failure_message(&w, "link", t),
        Some("link done line not observed within 200ms; console tail:\nboot\n".to_string())
    );
    assert_eq!(
        done_wait_failure_message(&DoneWait::Done(vec![]), "probe", t),
        None
    );
}

/// MAC-1・REPAIR-1・#3416: ログが無くても期限で `TimedOut`（tail は空）。
#[test]
fn mac1_repair1_wait_done_line_missing_log_times_out_with_empty_tail() {
    let s = Scratch::new("wait-missing", false);
    let t = Duration::from_millis(150);
    let w = wait_done_line(&s.dir.join("missing.log"), t, has_done);
    assert_eq!(w, DoneWait::TimedOut(Vec::new()));
    assert_eq!(
        done_wait_failure_message(&w, "probe", t),
        Some("probe done line not observed within 150ms; console tail:\n".to_string())
    );
}

/// MAC-1・REPAIR-1・#3416: 後から書かれた done 行も観測する。
#[test]
fn mac1_repair1_wait_done_line_sees_late_done() {
    let s = Scratch::new("wait-late", false);
    let log = s.file("console.log", b"boot\n");
    let p = log.clone();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        std::fs::write(&p, b"boot\nDONE\n").expect("write");
    });
    assert_eq!(
        wait_done_line(&log, Duration::from_secs(10), has_done),
        DoneWait::Done(b"boot\nDONE\n".to_vec())
    );
    writer.join().expect("writer");
}

/// MAC-1・REPAIR-1・REPAIR-5・#3416: 確定したログを返し、失敗の message は寄せる前と同一。
#[test]
fn mac1_repair1_read_settled_log_outcomes() {
    let s = Scratch::new("settled", false);
    let log = s.file("console.log", b"boot\nDONE\n");
    assert_eq!(
        read_settled_log(&log, b"x", "link", Duration::from_secs(5)),
        Ok(b"boot\nDONE\n".to_vec())
    );
    // 書き出し側の代役が lock を保持している間は、settle 前の last の末尾つきで失敗する。
    let writer = std::fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .expect("open writer");
    writer.lock().expect("writer lock");
    assert_eq!(
        read_settled_log(&log, b"before", "link", Duration::from_millis(100)),
        Err("console log writer did not finish within 100ms; console tail:\nbefore".to_string())
    );
    drop(writer);
    // 確定後のログが打ち切られていれば失敗する。
    let body = cut(b"DONE\n");
    let cutlog = s.file("cut.log", &body);
    assert_eq!(
        read_settled_log(&cutlog, b"", "link", Duration::from_secs(5)),
        Err(format!(
            "console log hit the size limit after the link done line; later guest output was lost; console tail:\n{}",
            tail_lossy(&body, 4096)
        ))
    );
}

/// MAC-1・REPAIR-5・#3416: ポーリング間隔 100ms と tail 長 4096 の固定。
#[test]
fn mac1_repair1_done_wait_constants_are_unchanged() {
    assert_eq!(DONE_POLL_INTERVAL, Duration::from_millis(100));
    assert_eq!(CONSOLE_TAIL_BYTES, 4096);
}
