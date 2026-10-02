//! OS 別 RSS サンプラーの結合試験（PLUG-8・PLUG-9。TASK-112.1・#265）。
//! root・特権不要で、CI の既定テスト集合（3 OS）で実行される。
//!
//! 本ファイルは TASK-112 の最小のシード。2 条件の比較・0.5MB 閾値の判定（TASK-112.2・#266）と
//! 常駐 plugin の RSS 計測（TASK-112.3・#267）は未実装で、後続がこのファイルへ追記する。
//! ここでは増加方向の下限だけを検査し、絶対値の比較は行わない（並列テストによる揺れを避ける）。
//! RSS を読むテストは `RSS_LOCK` で直列化する。

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod supported {
    use fandhe_container_plugin::{RssSource, rss};
    use std::sync::{Mutex, MutexGuard};

    /// RSS を比較するテスト同士を直列化するロック。libtest は既定でテストを並列実行するため、
    /// 32 MiB を確保するテストが他テストの 2 回の RSS 読み取りの間に入ると差分の上限を超えて
    /// flaky になる。RSS を読むテストはすべて取得してから計測する（PLUG-8）。
    static RSS_LOCK: Mutex<()> = Mutex::new(());

    /// 他テストの panic による poison は無視してロックを取得する。
    fn rss_guard() -> MutexGuard<'static, ()> {
        RSS_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[cfg(target_os = "linux")]
    const EXPECTED_SOURCE: RssSource = RssSource::ProcStatusVmRss;
    #[cfg(target_os = "macos")]
    const EXPECTED_SOURCE: RssSource = RssSource::ProcPidTaskInfo;

    /// PLUG-8: 自プロセスの RSS が取得でき、OS ごとの取得元が期待どおり。
    #[test]
    fn plug8_current_rss_is_positive_and_page_plausible() {
        let _guard = rss_guard();
        let s = rss::current().unwrap();
        assert!(s.bytes() >= 4096, "rss too small: {}", s.bytes());
        assert_eq!(s.source(), EXPECTED_SOURCE);
    }

    /// PLUG-8: メモリに触れると RSS が増える（32 MiB 確保に対し 16 MiB 以上の増加）。
    #[test]
    fn plug8_rss_grows_after_touching_memory() {
        let _guard = rss_guard();
        let before = rss::current().unwrap().bytes();
        let mut buf = vec![0u8; 32 * 1024 * 1024];
        for i in (0..buf.len()).step_by(4096) {
            buf[i] = 1;
        }
        let buf = std::hint::black_box(buf);
        let after = rss::current().unwrap().bytes();
        drop(buf);
        assert!(
            after >= before + 16 * 1024 * 1024,
            "before={before} after={after}"
        );
    }

    /// PLUG-9: 自 pid 指定でも取得でき、取得元は `current` と同じ。
    #[test]
    fn plug9_of_pid_matches_current_source() {
        let _guard = rss_guard();
        let s = rss::of_pid(std::process::id()).unwrap();
        assert!(s.bytes() > 0);
        assert_eq!(s.source(), EXPECTED_SOURCE);
    }

    /// PLUG-8: Linux では `/proc/self/status` を直接読んだ値と近い（差 8 MiB 以内）。
    #[cfg(target_os = "linux")]
    #[test]
    fn plug8_current_matches_proc_self_status() {
        let _guard = rss_guard();
        let text = std::fs::read_to_string("/proc/self/status").unwrap();
        let kb: u64 = text
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))
            .and_then(|r| r.split_whitespace().next())
            .and_then(|v| v.parse().ok())
            .unwrap();
        let got = rss::current().unwrap().bytes();
        assert!(
            got.abs_diff(kb * 1024) <= 8 * 1024 * 1024,
            "got={got} kb={kb}"
        );
    }
}

/// PLUG-8・PLUG-9: 未対応 OS（Windows 等）は偽の値を返さず `Unimplemented`（fail-closed）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn plug8_rss_is_unimplemented_on_unsupported_os() {
    use fandhe_container_plugin::{PluginErrorCode, rss};
    assert_eq!(
        rss::current().unwrap_err().code(),
        PluginErrorCode::Unimplemented
    );
}
