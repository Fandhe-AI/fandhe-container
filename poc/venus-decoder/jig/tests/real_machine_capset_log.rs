//! 実機前提テスト: 治具 VMM のログに Mesa venus 由来の capset クエリが届いた記録があること（GPU-6・TASK-172.4・#888）。
//!
//! 既定のテスト集合から分離している（`#[ignore]`）。必要環境: GPU 付き Linux ホスト・治具 VMM・Mesa venus を載せた
//! ゲスト。環境変数 `FANDHE_VENUS_JIG_LOG` に治具の出力ログのパスを渡して
//! `cargo test --manifest-path poc/venus-decoder/jig/Cargo.toml --test real_machine_capset_log -- --ignored` で実行する。
//! 現時点ではトランスポート（後続 F1）が未実装のため、実行しても成功するログは得られない。

use std::fs;
use std::io::Read;

use fandhe_container_poc_venus_jig::log::{MAX_LOG_BYTES, find_capset_queries};

#[test]
#[ignore = "GPU-6: requires Linux host with GPU + jig VMM + Mesa venus guest (#725)"]
fn task172_4_gpu6_guest_capset_query_reached_decoder() {
    let path = std::env::var("FANDHE_VENUS_JIG_LOG")
        .expect("FANDHE_VENUS_JIG_LOG must point to the jig VMM log file");
    // 開いたファイル自体の metadata を検証し、読み取りも上限 + 1 バイトで打ち切る（検査後の増大による メモリ枯渇を防ぐ）。
    let file = fs::File::open(&path).expect("log file must exist");
    let meta = file.metadata().expect("log metadata must be readable");
    assert!(meta.file_type().is_file(), "log must be a regular file");
    assert!(
        meta.len() <= MAX_LOG_BYTES as u64,
        "log exceeds the size limit"
    );
    let mut bytes = Vec::new();
    file.take(MAX_LOG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .expect("log must be readable");
    assert!(bytes.len() <= MAX_LOG_BYTES, "log exceeds the size limit");
    let log = String::from_utf8(bytes).expect("log must be valid UTF-8");
    let report = find_capset_queries(&log).expect("log within limits");
    assert!(
        report.venus_get_capset_ok >= 1,
        "no successful GET_CAPSET for capset_id=4 found: {report:?}"
    );
}
