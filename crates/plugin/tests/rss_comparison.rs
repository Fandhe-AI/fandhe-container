//! OS 別 RSS サンプラーの結合試験（PLUG-8・PLUG-9。TASK-112.1・#265・MS-3）。
//! root・特権不要で、CI の既定テスト集合（3 OS）で実行される。
//!
//! 本ファイルは TASK-112（MS-3）の結合試験。core 側 RSS の 2 条件比較ハーネス（TASK-112.2・#266。代役による
//! 近似で、閾値は assert せず差分を JSON 1 行で出力する）を含む。0.5MB 閾値の判定は未実装で、
//! 後続がこのファイルへ追記する。常駐 plugin の RSS 計測（TASK-112.3・#267）は
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
    // ---------------------------------------------------------------------------------------
    // TASK-112.2（#266）: core 側 RSS の 2 条件比較ハーネス（PLUG-8・MS-3）
    //
    // 条件 (1): plugin 相当機能を同一プロセス内でライブラリとして呼ぶ構成。
    // 条件 (2): core 単体。plugin は別プロセスで常駐中。
    // PLUG-8 の条件 (3)（動的ライブラリロード）は D-14・PoC-13 で不採用、gRPC も対象外のため比較しない
    // （TASK-112・MS-3）。
    //
    // 【代役であること（REPAIR-3）】core 実行バイナリ（TASK-79）も参照 plugin 実装（TASK-118）も未実装で、
    // 依存方向（core -> plugin）上、本 crate のテストから core はリンクできない。このためテストバイナリ
    // 自身を再実行し、「core 役」の計測対象プロセスと「plugin 役」の常駐プロセスを用意して近似する。
    // 実ビルド変種での再計測は別途必要。値は debug ビルド・libtest 込みで、PoC-13 の絶対値とは比較できない。
    // 条件 (2) の計測対象も plugin をリンクした同じバイナリであり、リンク構成の差（PLUG-8 が求める
    // plugin 分離による core 側 RSS の差）は表現できない。このため代役の差分を PLUG-8 の目標判定
    // としては報告せず（`target_judged: false`）、差分の記録に留める。閾値判定は実ビルド変種を
    // 用意できる TASK-112.3・#267 以降の担当。
    // ---------------------------------------------------------------------------------------

    use fandhe_container_plugin::{
        Frame, OneShotPlugin, PLUGIN_SOCKET_ENV, ResidentPlugin, ResidentStartTimeout, RpcTimeout,
        UdsStream,
    };
    use std::ffi::OsString;
    use std::io::Read;
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    /// PLUG-8 目標（TASK-112・MS-3）: 2 条件の差が 0.5 MiB 未満。PoC-13 の 3.375 は 3456 KiB ちょうどのため
    /// PLUG-8 の「MB」は MiB と解釈する（524,288 バイト）。
    const PLUG8_TARGET_DIFF_BYTES: u64 = 524_288;
    /// 代表操作の往復数（PoC-13 / PLUG-5・TASK-112・MS-3: 操作 A 相当 3 往復 + 操作 B 相当 1 往復）。
    const ROUND_TRIPS: u32 = 4;
    /// 条件ごとの試行数（PoC-13 と同じ 5 試行の中央値。PLUG-8・TASK-112・MS-3）。
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
            // 代役はリンク構成が条件間で同一のため、PLUG-8 目標の判定結果としては出さない。
            "target_judged": false,
            "stand_in_within_reference_diff": c.within_target,
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
        // 期待応答は参照処理を呼ばず固定の書式から組み立てる（`reference_handle` の契約
        // `req:<n>` -> `ok:<n>:<len>` と同じ）。resident 条件の計測対象プロセスが plugin 相当処理を
        // 実行すると両条件の処理量がずれ RSS 差分へ混入するため（PLUG-8）。
        let expected: Vec<Vec<u8>> = (1..=ROUND_TRIPS)
            .map(|n| format!("ok:{n}:{}", format!("req:{n}").len()).into_bytes())
            .collect();
        let bytes = match condition.as_str() {
            "in_process" => {
                for n in 1..=ROUND_TRIPS {
                    let resp = reference_handle(&request(n));
                    assert_eq!(resp.payload(), expected[(n - 1) as usize].as_slice());
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
                let mut session = ResidentPlugin::start(
                    &plugin,
                    ResidentStartTimeout::default(),
                    &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
                )
                .unwrap();
                let child = session.pid().unwrap();
                assert_ne!(
                    child,
                    std::process::id(),
                    "plugin must be a separate process"
                );
                for n in 1..=ROUND_TRIPS {
                    let resp = session.call(&request(n), rpc5()).unwrap();
                    assert_eq!(resp.payload(), expected[(n - 1) as usize].as_slice());
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
        let mut s = UdsStream::connect(
            Path::new(&sock),
            Duration::from_secs(5),
            &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
        )
        .unwrap();
        while let Ok(req) = s.read_frame(rpc5()) {
            s.write_frame(&reference_handle(&req), rpc5()).unwrap();
        }
    }

    /// 自テストバイナリを計測対象として起動し、`result` の RSS（バイト）を返す。
    /// 環境は空にし、期限超過時は計測対象と子孫の常駐 plugin をプロセスグループ単位で kill し
    /// 計測対象を回収する（REPAIR-5）。
    /// `overall_deadline` は全体期限で、これを超える待機・新規起動は行わない（REPAIR-5）。
    fn run_subject(condition: &str, overall_deadline: Instant) -> u64 {
        assert!(
            Instant::now() < overall_deadline,
            "overall deadline reached before starting subject ({condition})"
        );
        let dir = WorkDir::new(condition);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "supported::rss_subject_entry",
                "--test-threads=1",
            ])
            .env_clear()
            .env(SUBJECT_DIR_ENV, &dir.0)
            // 計測対象を新しいプロセスグループの先頭にする。常駐 plugin はその子孫として同じ
            // グループに属し、期限超過時にグループ単位で終了・回収できる（REPAIR-5）。
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = (Instant::now() + SUBJECT_WAIT).min(overall_deadline);
        let status = loop {
            if let Some(st) = child.try_wait().unwrap() {
                break st;
            }
            if Instant::now() >= deadline {
                kill_process_group(&child);
                let _ = child.kill();
                let _ = child.wait();
                panic!("subject ({condition}) did not finish before its deadline");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success(), "subject ({condition}) failed: {status}");
        parse_result(&dir.0.join("result"))
    }

    /// 計測対象のプロセスグループ（計測対象と、その子孫である常駐 plugin）へ SIGKILL を送る。
    /// 計測対象は未回収（pid 保持中）の状態で呼ぶこと。pgid の再利用による誤殺を避けるため。
    /// 本 crate は libc に依存せず unsafe も使えないため、OS 同梱の `kill` コマンドを環境空・
    /// 絶対パスで起動する。失敗は無視し、呼び出し側が続けて計測対象本体を kill する。
    fn kill_process_group(child: &std::process::Child) {
        let target = format!("-{}", child.id());
        // GNU（Linux）は `--` つき、BSD（macOS）の kill は `--` を pid として拒否するため
        // `--` なしの形式も順に試す。どちらかが成功した時点で戻る。
        let arg_forms: [&[&str]; 2] = [&["-s", "KILL", "--", &target], &["-s", "KILL", &target]];
        for bin in ["/bin/kill", "/usr/bin/kill"] {
            for args in arg_forms {
                let status = Command::new(bin)
                    .args(args)
                    .env_clear()
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                if status.is_ok_and(|s| s.success()) {
                    return;
                }
            }
        }
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
        assert_eq!(v["target_judged"], false);
        assert!(v.get("within_target").is_none());
        assert_eq!(v["conditions_compared"], 2);
        assert_eq!(v["trials"], 5);
        assert_eq!(v["stand_in"], true);
    }

    /// PLUG-8・TASK-112.2・MS-3: 2 条件を各 5 試行（交互）で計測し、差分を JSON 1 行で出力する。
    /// 閾値は assert しない（TASK-112.3 の担当）。構造的な事実のみ検査する。
    #[test]
    fn plug8_two_condition_rss_comparison_is_recorded() {
        let _guard = rss_guard();
        // 全体期限を各試行へ伝える。期限到達時は稼働中の子を kill・回収して計測スレッドが
        // 自ら終了するため、join は期限後ほぼ即座に返り、スレッド・子プロセスは残らない。
        let overall_deadline = Instant::now() + OVERALL_WAIT;
        let worker = std::thread::spawn(move || {
            let mut c1 = Vec::new();
            let mut c2 = Vec::new();
            for _ in 0..TRIALS {
                c1.push(run_subject("in_process", overall_deadline));
                c2.push(run_subject("resident", overall_deadline));
            }
            (c1, c2)
        });
        let (c1, c2) = worker
            .join()
            .expect("two-condition measurement failed or hit the overall deadline");
        assert_eq!(c1.len(), TRIALS);
        assert_eq!(c2.len(), TRIALS);
        assert!(
            c1.iter().chain(c2.iter()).all(|b| *b >= 4096),
            "{c1:?} {c2:?}"
        );
        // PLUG-8: println!/eprintln! は libtest に捕捉され、成功時の既定実行
        // （`make test`・CI は --nocapture を付けない）では表示されない。
        // 捕捉対象外の stderr ハンドル直書きと、成果物ファイルの両方へ出す。
        let line = report_line(median(c1), median(c2));
        {
            use std::io::Write;
            let _ = writeln!(std::io::stderr().lock(), "{line}");
        }
        let report = Path::new(env!("CARGO_TARGET_TMPDIR")).join("rss_comparison_report.json");
        std::fs::write(&report, format!("{line}\n")).expect("write rss comparison report");
    }

    /// 別プロセス plugin（常駐モード）の RSS 計測（PLUG-9。TASK-112.3・#267・MS-3）。実機前提テスト集合。
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

        /// 計測時の RPC 往復回数（PLUG-7 / PoC-13 の「4 RPC」に合わせて定常状態にする。TASK-112.3・MS-3）。
        const RPC_COUNT: usize = 4;
        /// RSS のサンプル回数。
        const SAMPLES: usize = 5;
        /// 壊れた値の検出用の上限。PLUG-9 の値との比較は #268 の人間判断でここでは合否にしない。
        const SANITY_MAX_BYTES: u64 = 256 * 1024 * 1024;
        /// 各操作の個別期限（起動待ち 5 秒・RPC 1 回 5 秒・終了待ち 5 秒）。
        const OP_TIMEOUT: Duration = Duration::from_secs(5);
        /// ウォッチドッグの上限（REPAIR-5）。個別期限の最悪合計（起動 + RPC_COUNT 回 + 終了待ち）に
        /// 余裕 2 倍を掛け、各操作が期限内に成功した場合に全体期限で誤失敗しないようにする。
        const WAIT: Duration =
            Duration::from_secs(OP_TIMEOUT.as_secs() * (RPC_COUNT as u64 + 2) * 2);

        fn rpc() -> RpcTimeout {
            RpcTimeout::new(OP_TIMEOUT).unwrap()
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
            let mut s = UdsStream::connect(
                &PathBuf::from(sock),
                OP_TIMEOUT,
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
            .unwrap();
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
                ResidentStartTimeout::new(OP_TIMEOUT).unwrap(),
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
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

        /// PLUG-9・TASK-112.3・MS-3: 常駐 plugin プロセスの RSS を計測し、1 行 JSON を stdout へ出す（REPAIR-4）。
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
