//! `fandhe-container-benches` の `regression_placeholder` ベンチ（`harness = false`）。
//!
//! TASK-86.3（REPAIR-7 第 4 段階・REPAIR-8）で CI のベンチ回帰ゲートを暫定的に
//! 稼働させるための stub。**実測は行わない**（スタブの明示は REPAIR-3）。
//! ホステッド runner での時間計測はノイズが大きくフレーキーになるため、
//! `benches/baseline.json` の暫定値と対になる決定的な固定値だけを結果 JSON として
//! 書き出す。実測を伴う本物のベンチ（`plugin_boundary` 等）への置き換えは
//! TASK-113 で行う（配置方式 `benches/benches/*.rs` の是非も TASK-113 で決める）。
//!
//! 呼び出し元: `Makefile` の `bench-check` ターゲットと
//! `.github/workflows/ci.yml` の `bench-regression` ジョブが
//! `cargo bench -p fandhe-container-benches --bench regression_placeholder -- --output <path>`
//! の形式で呼び出し、書き出した結果 JSON を
//! `scripts/check-bench-regression.sh` へ渡す。
//!
//! 引数:
//! - `--output <path>`: 結果 JSON の書き出し先。指定時はそのパスへ書き出して終了する
//! - 引数なし: `cargo test --all-targets` 等のテストモードで実行されたとみなし、
//!   標準出力へ結果 JSON を出して正常終了する
//! - 上記以外（未知の引数）: エラーとして非ゼロ終了する
//!
//! `cargo bench` が自動付与する `--bench` フラグは無視する（cargo の既知の呼び出し規約）。

use std::env;
use std::fs;
use std::process::ExitCode;

/// 結果 JSON のスキーマ（`schema_version: 1`）。`benches/baseline.json` と対になる
/// 2 つの決定的な固定値を持つ。値は REPAIR-8 の判定ロジックの動作確認用であり、
/// 実測値ではない（TASK-88 が実測から確定させるまでの暫定値）。
const RESULTS_JSON: &str = r#"{
  "schema_version": 1,
  "metrics": {
    "placeholder_throughput": {
      "value": 1000,
      "unit": "ops/s"
    },
    "placeholder_latency_p95": {
      "value": 100,
      "unit": "ms"
    }
  }
}
"#;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    // `cargo bench` が自動付与する `--bench` は無視する。
    let filtered: Vec<&String> = args.iter().filter(|a| a.as_str() != "--bench").collect();

    if filtered.is_empty() {
        // テストモード（`cargo test --all-targets` 等）。標準出力へ出して正常終了する。
        print!("{RESULTS_JSON}");
        return ExitCode::SUCCESS;
    }

    if filtered.len() == 2 && filtered[0].as_str() == "--output" {
        let output_path = filtered[1];
        return match fs::write(output_path, RESULTS_JSON) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: write-failed: failed to write {output_path}: {e}");
                ExitCode::FAILURE
            }
        };
    }

    eprintln!(
        "error: invalid-args: usage: regression_placeholder [--output <path>] (got: {args:?})"
    );
    ExitCode::FAILURE
}
