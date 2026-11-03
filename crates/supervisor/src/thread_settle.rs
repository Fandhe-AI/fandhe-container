//! 自プロセスのスレッドが「呼び出しスレッドだけ」に落ち着くのを待つ補助（Linux。SUP-3・CORE-1・REPAIR-5・#2043）。
//!
//! 本番の `ProcessLauncher`（`LaunchMode::SelfBounded`）は fork の前に `/proc/self/status` の `Threads:` が 1 であることを
//! 要求する（fork 時点で他スレッドがロックや fd を握っていない前提。CORE-5・SEC-1）。`pthread_join` はカーネルが
//! スレッド ID を消した時点で返り、スレッド数の減算はそれより少し後になり得るため、restart の再 launch の直前に
//! `LauncherRelauncher` が止めた常駐スレッド（捕捉・seccomp 通知・stderr の専用スレッド・制御チャネル）の消滅を
//! 有界に待つ。呼び出し元: `restart::LauncherRelauncher::relaunch`（`with_single_thread_launch` のとき）。
//! 待ちの中ではログを出さない（`stderr_sink` の専用スレッドを作ると前提を壊すため）。
//!
//! 拒否の判断そのものは launcher が行う。本補助は「落ち着かなかった」ことを返すだけで、呼び出し側は launch せずに
//! 失敗にする（fail-closed）。

use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

/// 1 回の待ちの既定の上限（止めたスレッドは通常ミリ秒で消える。REPAIR-5）。
pub(crate) const SETTLE_LIMIT: Duration = Duration::from_secs(1);

/// `/proc/self/status` の `Threads:` の値（読めない・解釈できないときは `None`）。
#[cfg(target_os = "linux")]
fn thread_count() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// 自プロセスのスレッドが 1 本（呼び出しスレッドだけ）になるのを `limit` まで待つ。なれば `true`。
///
/// Linux 以外では常に `true`（単一スレッドの要求は Linux の本番 launcher のもの）。
#[cfg(target_os = "linux")]
pub(crate) fn wait_single_threaded(limit: Duration) -> bool {
    let until = Instant::now().checked_add(limit);
    loop {
        if thread_count() == Some(1) {
            return true;
        }
        if until.is_some_and(|u| Instant::now() >= u) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn wait_single_threaded(_limit: Duration) -> bool {
    true
}
