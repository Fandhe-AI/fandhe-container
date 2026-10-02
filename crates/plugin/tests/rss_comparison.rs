//! OS 別 RSS サンプラーの結合試験（PLUG-8・PLUG-9。TASK-112.1・#265）。
//! root・特権不要で、CI の既定テスト集合（3 OS）で実行される。
//!
//! 本ファイルは TASK-112 の結合試験。core 側 RSS の 2 条件比較ハーネス（TASK-112.2・#266。代役による
//! 近似で、閾値は assert せず差分を JSON 1 行で出力する）を含む。0.5MB 閾値の判定と
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
    // ---------------------------------------------------------------------------------------
    // TASK-112.2（#266）: core 側 RSS の 2 条件比較ハーネス（PLUG-8）
    //
    // 条件 (1): plugin 相当機能を同一プロセス内でライブラリとして呼ぶ構成。
    // 条件 (2): core 単体。plugin は別プロセスで常駐中。
    // spec の条件 (3)（動的ライブラリロード）は D-14・PoC-13 で不採用、gRPC も対象外のため比較しない。
    //
    // 【代役であること（REPAIR-3）】core 実行バイナリ（TASK-79）も参照 plugin 実装（TASK-118）も未実装で、
    // 依存方向（core -> plugin）上、本 crate のテストから core はリンクできない。このためテストバイナリ
    // 自身を再実行し、「core 役」の計測対象プロセスと「plugin 役」の常駐プロセスを用意して近似する。
    // 実ビルド変種での再計測は別途必要。値は debug ビルド・libtest 込みで、PoC-13 の絶対値とは比較できない。
    // 既定集合では閾値を assert せず記録に留める（閾値判定と実機集合への分離は TASK-112.3・#267）。
    // ---------------------------------------------------------------------------------------

    use fandhe_container_plugin::{
        Frame, OneShotPlugin, PLUGIN_SOCKET_ENV, ResidentPlugin, ResidentStartTimeout, RpcTimeout,
        UdsStream,
    };
    use std::ffi::OsString;
    use std::io::Read;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// PLUG-8 目標: 2 条件の差が 0.5 MiB 未満。PoC-13 の 3.375 は 3456 KiB ちょうどのため
    /// spec の「MB」は MiB と解釈する（524,288 バイト）。
    const PLUG8_TARGET_DIFF_BYTES: u64 = 524_288;
    /// 代表操作の往復数（PoC-13 / PLUG-5: 操作 A 相当 3 往復 + 操作 B 相当 1 往復）。
    const ROUND_TRIPS: u32 = 4;
    /// 条件ごとの試行数（PoC-13 と同じ 5 試行の中央値）。
    const TRIALS: usize = 5;
    /// 計測対象プロセスの終了待ち上限（REPAIR-5）。
    const SUBJECT_WAIT: Duration = Duration::from_secs(60);
    /// テスト全体のウォッチドッグ上限。
    const OVERALL_WAIT: Duration = Duration::from_secs(300);
    /// 計測対象プロセスへ作業ディレクトリを渡す環境変数。
    const SUBJECT_DIR_ENV: &str = "FC_RSS_SUBJECT_DIR";

    /// 2 条件の RSS 比較結果。
    #[derive(Debug, PartialEq, Eq)]
    struct RssComparison {
        diff_bytes: i128,
        abs_diff_bytes: u64,
        within_target: bool,
    }

    /// 条件 (2) - 条件 (1) の差分と PLUG-8 目標との比較を求める純関数。
    fn compare(cond1_bytes: u64, cond2_bytes: u64) -> RssComparison {
        let abs = cond1_bytes.abs_diff(cond2_bytes);
        RssComparison {
            diff_bytes: i128::from(cond2_bytes) - i128::from(cond1_bytes),
            abs_diff_bytes: abs,
            within_target: abs < PLUG8_TARGET_DIFF_BYTES,
        }
    }

    /// レポートの JSON 1 行を組み立てる（キー・値は英語。パスや環境値は含めない）。
    fn report_line(cond1: u64, cond2: u64) -> String {
        let c = compare(cond1, cond2);
        serde_json::json!({
            "behavior": "PLUG-8",
            "task": "TASK-112.2",
            "condition1_in_process_bytes": cond1,
            "condition2_core_with_resident_plugin_bytes": cond2,
            "diff_bytes": i64::try_from(c.diff_bytes).unwrap_or(i64::MAX),
            "abs_diff_bytes": c.abs_diff_bytes,
            "target_diff_bytes": PLUG8_TARGET_DIFF_BYTES,
            "within_target": c.within_target,
            "conditions_compared": 2,
            "trials": TRIALS,
            "source": format!("{:?}", EXPECTED_SOURCE),
            "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
            "stand_in": true,
        })
        .to_string()
    }

    /// 参照 plugin 機能の代役。要求 `req:<n>` に `ok:<n>:<len>` を返す。条件 (1) は直接呼び、
    /// 条件 (2) の plugin 役プロセスは受信フレームごとに同じ関数を呼んで仕事量を揃える。
    fn reference_handle(req: &Frame) -> Frame {
        let len = req.payload().len();
        let n = std::str::from_utf8(req.payload())
            .ok()
            .and_then(|t| t.strip_prefix("req:"))
            .unwrap_or("?");
        // 本文は短い ASCII のみで上限内のため Frame::new は失敗しない。
        Frame::new(format!("ok:{n}:{len}").into_bytes()).unwrap_or_else(|_| std::process::exit(2))
    }

    fn request(n: u32) -> Frame {
        Frame::new(format!("req:{n}").into_bytes()).unwrap_or_else(|_| std::process::exit(2))
    }

    fn rpc5() -> RpcTimeout {
        RpcTimeout::new(Duration::from_secs(5)).unwrap_or_else(|_| std::process::exit(2))
    }

    /// 作業ディレクトリ（0700）。計測対象への入力 `condition` と出力 `result` を置く。
    struct WorkDir(PathBuf);
    impl WorkDir {
        fn new(condition: &str) -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcrc-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            std::fs::write(p.join("condition"), condition).unwrap();
            Self(p)
        }
    }
    impl Drop for WorkDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn median(mut v: Vec<u64>) -> u64 {
        v.sort_unstable();
        v.get(v.len() / 2).copied().unwrap_or(0)
    }

    /// 往復完了後に RSS を数回採取し中央値を返す。
    fn sample_rss() -> u64 {
        let mut v = Vec::new();
        for _ in 0..5 {
            v.push(rss::current().unwrap().bytes());
            std::thread::sleep(Duration::from_millis(10));
        }
        median(v)
    }

    /// 計測対象プロセス（core 役）の入口。`FC_RSS_SUBJECT_DIR` 未設定の通常実行では何もしない。
    /// `condition` に従い 4 往復した後、plugin が常駐したままの状態で自 RSS を `result` へ書く。
    /// 失敗は非ゼロ終了で親へ伝える。
    #[test]
    fn rss_subject_entry() {
        let Some(dir) = std::env::var_os(SUBJECT_DIR_ENV) else {
            return;
        };
        let dir = PathBuf::from(dir);
        let condition = std::fs::read_to_string(dir.join("condition")).unwrap();
        let expected: Vec<Frame> = (1..=ROUND_TRIPS)
            .map(|n| reference_handle(&request(n)))
            .collect();
        let bytes = match condition.as_str() {
            "in_process" => {
                for n in 1..=ROUND_TRIPS {
                    let resp = reference_handle(&request(n));
                    assert_eq!(resp.payload(), expected[(n - 1) as usize].payload());
                }
                sample_rss()
            }
            "resident" => {
                let args: Vec<OsString> = [
                    "--exact",
                    "supported::rss_plugin_child_entry",
                    "--test-threads=1",
                ]
                .iter()
                .map(OsString::from)
                .collect();
                let plugin =
                    OneShotPlugin::new(std::env::current_exe().unwrap(), args, dir.clone())
                        .unwrap();
                let mut session =
                    ResidentPlugin::start(&plugin, ResidentStartTimeout::default()).unwrap();
                let child = session.pid().unwrap();
                assert_ne!(
                    child,
                    std::process::id(),
                    "plugin must be a separate process"
                );
                for n in 1..=ROUND_TRIPS {
                    let resp = session.call(&request(n), rpc5()).unwrap();
                    assert_eq!(resp.payload(), expected[(n - 1) as usize].payload());
                }
                // plugin が常駐したままの状態で採取する（shutdown の前）。
                let b = sample_rss();
                session.shutdown().unwrap();
                b
            }
            other => panic!("unknown condition: {other}"),
        };
        std::fs::write(dir.join("result"), format!("{bytes}\n")).unwrap();
    }

    /// plugin 役プロセスの入口。`PLUGIN_SOCKET_ENV` 未設定の通常実行では何もしない。
    /// EOF（親が接続を閉じる）まで、要求 1 件ごとに `reference_handle` で応答する。
    #[test]
    fn rss_plugin_child_entry() {
        let Some(sock) = std::env::var_os(PLUGIN_SOCKET_ENV) else {
            return;
        };
        let mut s = UdsStream::connect(Path::new(&sock), Duration::from_secs(5)).unwrap();
        while let Ok(req) = s.read_frame(rpc5()) {
            s.write_frame(&reference_handle(&req), rpc5()).unwrap();
        }
    }

    /// 自テストバイナリを計測対象として起動し、`result` の RSS（バイト）を返す。
    /// 環境は空にし、期限超過時は kill して回収する（REPAIR-5）。
    fn run_subject(condition: &str) -> u64 {
        let dir = WorkDir::new(condition);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "supported::rss_subject_entry",
                "--test-threads=1",
            ])
            .env_clear()
            .env(SUBJECT_DIR_ENV, &dir.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + SUBJECT_WAIT;
        let status = loop {
            if let Some(st) = child.try_wait().unwrap() {
                break st;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("subject ({condition}) did not finish within {SUBJECT_WAIT:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success(), "subject ({condition}) failed: {status}");
        parse_result(&dir.0.join("result"))
    }

    /// `result` を読み取り上限つきで厳密にパースする（10 進数 + 改行のみ）。
    fn parse_result(path: &Path) -> u64 {
        let mut buf = String::new();
        std::fs::File::open(path)
            .unwrap()
            .take(32)
            .read_to_string(&mut buf)
            .unwrap();
        let digits = buf.strip_suffix('\n').unwrap();
        assert!(
            !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()),
            "malformed result: {digits:?}"
        );
        digits.parse().unwrap()
    }

    /// PLUG-8: 差分の符号と絶対値が具体値で求まる。
    #[test]
    fn plug8_compare_reports_diff_and_target() {
        let c = compare(3_538_944, 3_998_208);
        assert_eq!(c.diff_bytes, 459_264);
        assert_eq!(c.abs_diff_bytes, 459_264);
        assert!(c.within_target);
        assert_eq!(compare(3_998_208, 3_538_944).diff_bytes, -459_264);
    }

    /// PLUG-8: 差が 524,288 ちょうどは目標未達、524,287 は達成。
    #[test]
    fn plug8_compare_flags_diff_at_or_over_target() {
        assert!(!compare(1_000_000, 1_524_288).within_target);
        assert!(compare(1_000_000, 1_524_287).within_target);
        assert!(!compare(1_524_288, 1_000_000).within_target);
    }

    /// レポート 1 行が期待するキーと値を持つ。
    #[test]
    fn plug8_report_json_line_has_expected_fields() {
        let line = report_line(3_538_944, 3_998_208);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["behavior"], "PLUG-8");
        assert_eq!(v["task"], "TASK-112.2");
        assert_eq!(v["condition1_in_process_bytes"], 3_538_944);
        assert_eq!(v["condition2_core_with_resident_plugin_bytes"], 3_998_208);
        assert_eq!(v["diff_bytes"], 459_264);
        assert_eq!(v["abs_diff_bytes"], 459_264);
        assert_eq!(v["target_diff_bytes"], 524_288);
        assert_eq!(v["within_target"], true);
        assert_eq!(v["conditions_compared"], 2);
        assert_eq!(v["trials"], 5);
        assert_eq!(v["stand_in"], true);
    }

    /// PLUG-8・TASK-112.2: 2 条件を各 5 試行（交互）で計測し、差分を JSON 1 行で出力する。
    /// 閾値は assert しない（TASK-112.3 の担当）。構造的な事実のみ検査する。
    #[test]
    fn plug8_two_condition_rss_comparison_is_recorded() {
        let _guard = rss_guard();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut c1 = Vec::new();
            let mut c2 = Vec::new();
            for _ in 0..TRIALS {
                c1.push(run_subject("in_process"));
                c2.push(run_subject("resident"));
            }
            let _ = tx.send((c1, c2));
        });
        let (c1, c2) = rx
            .recv_timeout(OVERALL_WAIT)
            .expect("two-condition measurement hung");
        assert_eq!(c1.len(), TRIALS);
        assert_eq!(c2.len(), TRIALS);
        assert!(
            c1.iter().chain(c2.iter()).all(|b| *b >= 4096),
            "{c1:?} {c2:?}"
        );
        println!("{}", report_line(median(c1), median(c2)));
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
