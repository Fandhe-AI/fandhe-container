//! `fandhe-container-benches` の `startup_latency` ベンチ（`harness = false`。TASK-190・#1900・REPAIR-8・CORE-10）。
//!
//! コンテナ起動レイテンシの p95 を、core の `create` から supervisor の bin（本番 launcher）の `FCSUP1 OK` 報告までの
//! 区間で計測する。計測ロジックと計測定義は `fandhe_container_benches::startup_latency` と
//! `docs/design/startup-latency-bench.md` にあり、ここは引数の振り分けと出力だけの薄い層。
//!
//! 実機前提（Linux 6.12 以上・非 root・非特権 user namespace・`systemd-run --user`）で、CI では実行しない
//! （`docs/design/bench-calibration.md`「CI の扱いの決定（TASK-190）」）。回帰ゲートへは未登録（#1901）。
//!
//! 呼び出し例: `cargo bench -p fandhe-container-benches --bench startup_latency -- --supervisor-bin <絶対パス>
//! --cli-bin <絶対パス> --output <path>`（`--cli-bin` は区間の外の後始末の `delete` 用。OCI-6）。引数なし（`--bench` は無視）は何も起動しないスモークで、終了コード 0。
//! `--startup-latency-probe <nonce>` はコンテナ内のワークロード（同じ実行ファイルの再実行）。
//! エラーは標準エラーへ 1 行の JSON（`code` / `message`）で出し、非ゼロで終わる。

use fandhe_container_benches::startup_latency::args::{Command, parse_args};
use fandhe_container_benches::startup_latency::output::write_new;
use fandhe_container_benches::startup_latency::{
    Execution, StartupLatencyError, execute, run_workload,
};
use std::process::ExitCode;

fn run() -> Result<ExitCode, StartupLatencyError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = parse_args(&args)?;
    if matches!(command, Command::Probe(_)) {
        run_workload();
    }
    if matches!(command, Command::Noop) {
        // 診断（`--scope-only`）が scope の中で起動する自明なコマンド。何もせず終了コード 0。
        std::process::exit(0);
    }
    match execute(command)? {
        Execution::Smoke(line) => {
            println!("{line}");
            Ok(ExitCode::SUCCESS)
        }
        Execution::Unsupported => {
            println!("startup_latency: not measured; unsupported on this OS");
            Ok(ExitCode::SUCCESS)
        }
        Execution::Done {
            json,
            output,
            clean,
        } => {
            if let Some(path) = output {
                write_new(&path, &json)?;
            }
            print!("{json}");
            Ok(if clean {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
