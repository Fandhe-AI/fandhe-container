//! 試験が起こした子プロセスを期限つきで回収する共有補助（net の結合試験〔`netns_holder_*`・実機前提の
//! `*_privileged`・`tcp_rtt_probe`〕から `#[path]` で取り込む。REPAIR-5・NET-9）。kill の後も無期限の
//! `Child::wait()` を呼ばず、`try_wait()` を有限の期限でポーリングする。`wait_within` は kill しない
//! 正常終了待ちの期限つき版で、期限切れの扱い（reap して失敗させる）は呼び出し側が決める。
//! 取り込み元によって使う関数が異なるため dead_code を許す。
#![allow(dead_code)]

use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

/// 子を kill し、`within` 以内に `try_wait()` で回収する。回収できない（期限切れ・`try_wait` の失敗）なら
/// 具体的なメッセージの `Err` を返す。すでに終了していた子の kill の失敗は無視する。
pub fn reap(child: &mut Child, within: Duration) -> Result<(), String> {
    let _ = child.kill();
    let pid = child.id();
    let until = Instant::now() + within;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(e) => return Err(format!("try_wait on child {pid} failed: {e}")),
        }
        if Instant::now() >= until {
            return Err(format!(
                "child {pid} was not reaped within {within:?} after kill"
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// 既定の回収期限。各試験の期限切れ後の後始末で使う（SIGKILL 後の回収は通常即時）。
pub const REAP_WITHIN: Duration = Duration::from_secs(30);

/// kill しない正常終了待ちの期限つき版。期限切れ・`try_wait` の失敗は具体的なメッセージの `Err`。
pub fn wait_within(child: &mut Child, within: Duration) -> Result<ExitStatus, String> {
    let pid = child.id();
    let until = Instant::now() + within;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Ok(st),
            Ok(None) => {}
            Err(e) => return Err(format!("try_wait on child {pid} failed: {e}")),
        }
        if Instant::now() >= until {
            return Err(format!("child {pid} did not exit within {within:?}"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// 期限切れ後の後始末用。回収失敗を握り潰さず stderr に出す（呼び出し側は既に失敗を返す経路）。
pub fn reap_or_report(child: &mut Child, within: Duration) {
    if let Err(e) = reap(child, within) {
        eprintln!("reap failure: {e}");
    }
}

/// `Drop` 用。回収失敗は通常時は panic で表に出し、巻き戻し中は abort を避けて stderr に出す。
pub fn reap_on_drop(child: &mut Child) {
    if let Err(e) = reap(child, REAP_WITHIN) {
        if std::thread::panicking() {
            eprintln!("reap failure: {e}");
        } else {
            panic!("reap failure: {e}");
        }
    }
}
