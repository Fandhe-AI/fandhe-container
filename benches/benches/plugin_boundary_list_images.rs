//! `fandhe-container-benches` の `plugin_boundary_list_images` ベンチ（`harness = false`。TASK-113.2・#271）。
//!
//! 代表操作 B（イメージ一覧）の plugin 境界往復コストと同一プロセス呼び出しコストを計測する
//! （PLUG-5・PLUG-6）。計測ロジックは `fandhe_container_benches::plugin_boundary_list_images` にあり、
//! ここは引数解釈・子プロセスモード分岐・結果出力だけの薄い層。
//!
//! 引数:
//! - `--output <path>`: 本計測（1,000 回 × 5 試行）。結果 JSON を `<path>` へ書き標準出力にも出す
//! - 引数なし: スモーク（少回数。`cargo test --all-targets` 等からの実行想定）。境界経路を
//!   計測できない環境（非 unix）では同一プロセス経路のみ検証し、境界経路は未計測と警告する
//!   （本計測 `--output` は同環境で非ゼロ終了。fail-closed）
//! - `--plugin-serve <path>`: 子プロセス（plugin 役）モード。本ベンチが自分自身を起動する内部用
//! - `--bench`: cargo が自動付与するため無視
//!
//! 結果 JSON を CI のベンチ回帰ゲートへ接続するのは #272（TASK-113.4）。本ベンチ単体では
//! 合否判定をしない。

use fandhe_container_benches::plugin_boundary_list_images::{
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
            // スモークは配線確認のみで合否ゲートではない。境界越し経路が未実装の環境（Windows 等。
            // WIN-1）に限り、同一プロセス経路だけ検証して `framed: null` と stderr の警告で
            // 「境界経路は未計測」を明示する（成功扱いの沈黙にしない）。それ以外の失敗、および
            // 本計測（`--output`）の未実装は非ゼロ終了のまま（fail-closed。PLUG-5）。
            let framed = match run_framed_with_child(SMOKE_TRIALS, SMOKE_SAMPLES) {
                Ok(v) => Some(v),
                Err(e) if e.code == "unimplemented" => {
                    eprintln!("warning: boundary path NOT measured in smoke ({e})");
                    None
                }
                Err(e) => return Err(e),
            };
            print!("{}", Results { inproc, framed }.to_json()?);
            Ok(())
        }
    }
}

#[cfg(unix)]
fn serve(socket: &str) -> Result<(), BenchError> {
    fandhe_container_benches::plugin_boundary_list_images::serve_socket(std::path::Path::new(
        socket,
    ))
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
