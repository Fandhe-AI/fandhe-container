//! `fandhe-container-benches` の `small_files` ベンチ（`harness = false`。TASK-189・IO-6・IO-7・REPAIR-8）。
//!
//! 小ファイル多数ワークロードの files/s を計測する。経路は `--route wire`（UDS 越しのフレーム。
//! 回帰ゲートはこちら）か `--route server-api`（サーバー側 API の直接呼び出し。既定。#2074）。計測ロジックと計測定義は
//! `fandhe_container_benches::small_files` と `docs/design/small-files-bench.md` にあり、
//! ここは引数の振り分けと出力だけの薄い層。metrics.json・BENCH_NAMES へ登録済み（#1899）で、baseline 未登録の間は bench-check の比較対象外（基準値は #230）。
//!
//! 呼び出し例: `cargo bench -p fandhe-container-benches --bench small_files -- --count 50000
//! --config bind --root <dir> --output <path>`。引数なし（`--bench` は無視）は小さい固定件数の
//! スモークで、結果を標準出力へ出して終了コード 0 で終わる。エラーは標準エラーへ 1 行の JSON
//! （`code` / `message`）で出し、非ゼロで終わる。

use fandhe_container_benches::small_files::{Execution, SmallFilesError, execute, parse_args};
use std::process::ExitCode;

fn run() -> Result<(), SmallFilesError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match execute(parse_args(&args)?)? {
        Execution::Skipped => {
            println!("small_files: skipped; persist is not supported on this host");
        }
        Execution::Done { json, output } => {
            if let Some(path) = output {
                std::fs::write(&path, &json).map_err(|e| {
                    SmallFilesError::new(
                        "io-error",
                        format!("write output failed ({:?})", e.kind()),
                    )
                })?;
            }
            print!("{json}");
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
