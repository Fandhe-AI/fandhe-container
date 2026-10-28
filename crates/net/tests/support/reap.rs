//! 試験が起こした子プロセスを期限つきで回収する共有補助（`netns_holder_*` の結合試験から `#[path]` で取り込む。
//! REPAIR-5・NET-9）。kill の後も無期限の `Child::wait()` を呼ばず、`try_wait()` を有限の期限でポーリングする。

use std::process::Child;
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
