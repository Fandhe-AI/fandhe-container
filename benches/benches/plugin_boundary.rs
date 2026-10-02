//! `fandhe-container-benches` の `plugin_boundary` ベンチ（`harness = false`。TASK-113.2・#271）。
//!
//! 代表操作 B（イメージ一覧）の plugin 境界往復コストと同一プロセス呼び出しコストを計測する
//! （PLUG-5・PLUG-6）。計測ロジックは `fandhe_container_benches::plugin_boundary` にあり、
//! ここは引数解釈・子プロセスモード分岐・結果出力だけの薄い層。
//!
//! 引数:
//! - `--output <path>`: 本計測（1,000 回 × 5 試行）。結果 JSON を `<path>` へ書き標準出力にも出す
//! - 引数なし: スモーク（少回数。`cargo test --all-targets` 等からの実行想定）。境界経路を
//!   計測できない環境（非 unix）では `unimplemented` で非ゼロ終了する（fail-closed）
//! - `--plugin-serve <path>`: 子プロセス（plugin 役）モード。本ベンチが自分自身を起動する内部用
//! - `--bench`: cargo が自動付与するため無視
//!
//! 結果 JSON を CI のベンチ回帰ゲートへ接続するのは #272（TASK-113.4）。本ベンチ単体では
//! 合否判定をしない。

use fandhe_container_benches::plugin_boundary::{
    BenchError, MockImageStore, Mode, Results, SAMPLES_PER_TRIAL, SMOKE_SAMPLES, SMOKE_TRIALS,
    TRIALS, measure_inproc, parse_args, run_framed_with_child,
};
use std::process::ExitCode;

fn run(mode: Mode) -> Result<(), BenchError> {
    match mode {
        Mode::PluginServe { socket } => serve(&socket),
        Mode::Measure { output } => {
            let framed = run_framed_with_child(TRIALS, SAMPLES_PER_TRIAL)?;
            let inproc = measure_inproc(&MockImageStore, TRIALS, SAMPLES_PER_TRIAL)?;
            let json = Results {
                inproc,
                framed: Some(framed),
            }
            .to_json()?;
            std::fs::write(&output, &json)
                .map_err(|e| BenchError::new("io", format!("write output failed: {e}")))?;
            print!("{json}");
            Ok(())
        }
        Mode::Smoke => {
            let inproc = measure_inproc(&MockImageStore, SMOKE_TRIALS, SMOKE_SAMPLES)?;
            // 境界越し経路が計測できない環境（Windows 等。WIN-1）では `unimplemented` を
            // そのまま返して非ゼロ終了する。PLUG-5 の境界経路を検証せず成功扱いにしない（fail-closed）
            let framed = Some(run_framed_with_child(SMOKE_TRIALS, SMOKE_SAMPLES)?);
            print!("{}", Results { inproc, framed }.to_json()?);
            Ok(())
        }
    }
}

#[cfg(unix)]
fn serve(socket: &str) -> Result<(), BenchError> {
    fandhe_container_benches::plugin_boundary::serve_socket(std::path::Path::new(socket))
}

#[cfg(not(unix))]
fn serve(_socket: &str) -> Result<(), BenchError> {
    Err(BenchError::new(
        "unimplemented",
        "plugin role is unavailable on this platform",
    ))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args).and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
