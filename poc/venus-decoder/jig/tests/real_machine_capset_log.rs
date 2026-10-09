//! 実機前提テスト: 治具 VMM のログに Mesa venus 由来の capset クエリが届いた記録があること（GPU-6・TASK-172.4・#888）。
//!
//! 既定のテスト集合から分離している（`#[ignore]`）。必要環境: GPU 付き Linux ホスト・治具の起動 bin `venus-jig`
//! （`--log` で出力したログ。#1598）・治具に vhost-user で接続する VMM・Mesa venus を載せたゲスト。環境変数
//! `FANDHE_VENUS_JIG_LOG` に治具の出力ログのパスを渡して
//! `cargo test --manifest-path poc/venus-decoder/jig/Cargo.toml --test real_machine_capset_log -- --ignored` で実行する。
//! 実機での疎通は #725（人間担当）。
//!
//! 読み取りは `log::read_log_file`（通常ファイル以外を open 前に拒否。事後監査 #1528 D2）を補助スレッドで動かし、
//! `recv_timeout` で待つ。検査後の差し替えで読み取りが止まってもテストはハングせず失敗する（REPAIR-5）。

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use fandhe_container_poc_venus_jig::log::{find_capset_queries, read_log_file};

const READ_TIMEOUT: Duration = Duration::from_secs(30);

#[test]
#[ignore = "GPU-6: requires Linux host with GPU + jig VMM + Mesa venus guest (#725)"]
fn task172_4_gpu6_guest_capset_query_reached_decoder() {
    let path = PathBuf::from(
        std::env::var_os("FANDHE_VENUS_JIG_LOG")
            .expect("FANDHE_VENUS_JIG_LOG must point to the jig VMM log file"),
    );
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(read_log_file(&path));
    });
    let log = rx
        .recv_timeout(READ_TIMEOUT)
        .expect("reading the log timed out (is it a FIFO?)")
        .expect("log must be a readable regular file within the size limit");
    let report = find_capset_queries(&log).expect("log within limits");
    assert!(
        report.venus_get_capset_ok >= 1,
        "no successful GET_CAPSET for capset_id=4 found: {report:?}"
    );
}
