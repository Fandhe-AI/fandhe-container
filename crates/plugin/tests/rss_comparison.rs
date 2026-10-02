//! OS 別 RSS サンプラーの結合試験（PLUG-8・PLUG-9。TASK-112.1・#265）。
//! root・特権不要で、CI の既定テスト集合（3 OS）で実行される。
//!
//! 本ファイルは TASK-112 の最小のシード。2 条件の比較・0.5MB 閾値の判定（TASK-112.2・#266）は
//! 未実装で、後続がこのファイルへ追記する。常駐 plugin の RSS 計測（TASK-112.3・#267）は
//! `supported::resident` にあり、環境依存のため `#[ignore]` の実機前提テストとして既定集合から分離している
//! （実行: `cargo test --release -p fandhe-container-plugin --test rss_comparison -- --ignored
//! plug9_resident_plugin_rss_is_measured --nocapture`。Linux / macOS のみ）。
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

    /// 別プロセス plugin（常駐モード）の RSS 計測（PLUG-9。TASK-112.3・#267）。実機前提テスト集合。
    ///
    /// 常駐 RSS の絶対値は OS・ビルドプロファイル・アロケータ・ページサイズに依存し、妥当性は人間が
    /// 判断する（#268）ため、計測テストは `#[ignore]` で既定集合から分離する（AGENTS.md「実機前提テスト」）。
    /// 子プロセスの入口 `plugin_child_entry` は `#[ignore]` を付けない（子は `--ignored` を受け取らず、
    /// ignore すると何もせず終了して `start` が失敗するため）。通常実行では即 return する。
    ///
    /// 比較可能性の制約（実装済みを装わない。REPAIR-3）:
    /// - plugin 役はテストバイナリ自身の再実行で、libtest と同ファイルの全テストがリンクされる。
    ///   計測値は PLUG-9 の参考値（1.938MB / 2.371MB）に対する上限寄りの値で、直接は比較できない
    /// - gRPC 方式 plugin の RSS は gRPC 境界（TASK-108）が未実装のため計測しない
    mod resident {
        use super::{EXPECTED_SOURCE, rss_guard};
        use fandhe_container_plugin::{
            Frame, OneShotPlugin, OneShotTermination, PLUGIN_SOCKET_ENV, ResidentPlugin,
            ResidentStartTimeout, ResidentState, RpcTimeout, UdsStream, rss,
        };
        use std::ffi::OsString;
        use std::os::unix::fs::DirBuilderExt;
        use std::path::PathBuf;
        use std::sync::mpsc;
        use std::time::Duration;

        /// 計測時の RPC 往復回数（PLUG-7 / PoC-13 の「4 RPC」に合わせて定常状態にする）。
        const RPC_COUNT: usize = 4;
        /// RSS のサンプル回数。
        const SAMPLES: usize = 5;
        /// 壊れた値の検出用の上限。PLUG-9 の値との比較は #268 の人間判断でここでは合否にしない。
        const SANITY_MAX_BYTES: u64 = 256 * 1024 * 1024;
        /// ウォッチドッグの上限（REPAIR-5）。
        const WAIT: Duration = Duration::from_secs(25);

        fn rpc() -> RpcTimeout {
            RpcTimeout::new(Duration::from_secs(5)).unwrap()
        }

        /// 0700 の一時ディレクトリ（socket の配置先）。Drop で削除する。
        struct TempDir(PathBuf);
        impl TempDir {
            fn new() -> Self {
                let p = std::env::temp_dir().join(format!("fcrs-rss-{}", std::process::id()));
                std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
                Self(p)
            }
        }
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        /// 子プロセスの入口。`PLUGIN_SOCKET_ENV` 未設定（通常のテスト実行）では何もしない。
        /// 接続後は EOF まで「要求 1 件 -> 固定の小さい応答」を繰り返すだけの最小の plugin 役。
        #[test]
        fn plugin_child_entry() {
            let Some(sock) = std::env::var_os(PLUGIN_SOCKET_ENV) else {
                return;
            };
            let mut s = UdsStream::connect(&PathBuf::from(sock), Duration::from_secs(5)).unwrap();
            while s.read_frame(rpc()).is_ok() {
                s.write_frame(&Frame::new(b"pong".to_vec()).unwrap(), rpc())
                    .unwrap();
            }
        }

        fn with_watchdog<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(WAIT)
                .unwrap_or_else(|_| panic!("rss measurement hung: no result within {WAIT:?}"))
        }

        fn measure() -> Vec<u64> {
            let dir = TempDir::new();
            let args: Vec<OsString> = [
                "--exact",
                "supported::resident::plugin_child_entry",
                "--test-threads=1",
            ]
            .iter()
            .map(OsString::from)
            .collect();
            let plugin =
                OneShotPlugin::new(std::env::current_exe().unwrap(), args, dir.0.clone()).unwrap();
            let mut session = ResidentPlugin::start(
                &plugin,
                ResidentStartTimeout::new(Duration::from_secs(5)).unwrap(),
            )
            .unwrap();
            assert_eq!(session.state(), ResidentState::Running);
            let pid = session.pid().unwrap();
            assert_ne!(pid, std::process::id());
            for _ in 0..RPC_COUNT {
                let resp = session
                    .call(&Frame::new(b"ping".to_vec()).unwrap(), rpc())
                    .unwrap();
                assert_eq!(resp.payload(), b"pong");
            }
            let mut bytes = Vec::new();
            for _ in 0..SAMPLES {
                let s = rss::of_pid(pid).unwrap();
                assert_eq!(s.source(), EXPECTED_SOURCE);
                bytes.push(s.bytes());
                std::thread::sleep(Duration::from_millis(50));
            }
            assert_eq!(session.state(), ResidentState::Running);
            let done = session.shutdown().unwrap();
            assert_eq!(
                done.termination(),
                OneShotTermination::Exited { code: Some(0) }
            );
            #[cfg(target_os = "linux")]
            assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
            let left = std::fs::read_dir(&dir.0)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().ends_with(".sock"))
                .count();
            assert_eq!(left, 0);
            bytes
        }

        /// PLUG-9: 常駐 plugin プロセスの RSS を計測し、1 行 JSON を stdout へ出す（REPAIR-4）。
        /// 値は健全性（4096 バイト以上・256 MiB 未満）のみ検査し、PLUG-9 との比較は #268 で人間が判断する。
        #[test]
        #[ignore = "real-machine measurement: resident plugin RSS is environment-dependent and judged by a human (PLUG-9, TASK-112.3)"]
        fn plug9_resident_plugin_rss_is_measured() {
            let _guard = rss_guard();
            let samples = with_watchdog(measure);
            for b in &samples {
                assert!(
                    (4096..SANITY_MAX_BYTES).contains(b),
                    "rss out of sane range: {b}"
                );
            }
            let mut sorted = samples.clone();
            sorted.sort_unstable();
            let median = sorted[sorted.len() / 2];
            let source = format!("{EXPECTED_SOURCE:?}");
            let list: Vec<String> = samples.iter().map(u64::to_string).collect();
            println!(
                "{{\"benchmark\":\"plugin_resident_rss\",\"behavior\":\"PLUG-9\",\"transport\":\"length_prefixed_frame\",\"mode\":\"resident\",\"child\":\"libtest_reexec\",\"os\":\"{}\",\"arch\":\"{}\",\"profile\":\"{}\",\"source\":\"{}\",\"rpc_count\":{},\"samples_bytes\":[{}],\"median_bytes\":{}}}",
                std::env::consts::OS,
                std::env::consts::ARCH,
                if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                },
                source,
                RPC_COUNT,
                list.join(","),
                median
            );
        }
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
