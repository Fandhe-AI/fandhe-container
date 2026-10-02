//! `plugin_boundary_macos_cold_start` ベンチ（`harness = false`。TASK-113.4・PLUG-6・MAC-2）。
//!
//! macOS のみ計測する（`cfg(target_os = "macos")`）。他 OS は引数なしなら skip を明示して成功、
//! `--output` 指定は片側だけの結果を成功にしないため `unsupported-platform` で非ゼロ終了する。
//! 計測ロジックは `fandhe_container_benches::macos_cold_start`。上乗せが 20 ms 以上なら非ゼロ終了。
//! 引数: `--output <path>`（結果 JSON を書く）。`--bench` は cargo が付与するため無視。
//! 回帰ゲート（baseline.json）には未接続（TASK-88.h1・TASK-113.h1）。

use std::process::ExitCode;

#[cfg(target_os = "macos")]
fn run(output: Option<&str>) -> Result<(), String> {
    use fandhe_container_benches::macos_cold_start::{TRIALS, measure_all, results_json};
    let exe = std::path::Path::new(env!("CARGO_BIN_EXE_plugin-boundary-stub"));
    let (s, r) = measure_all(exe, TRIALS).map_err(|e| e.to_string())?;
    if let Some(path) = output {
        std::fs::write(path, results_json(&s, &r)).map_err(|e| format!("io: write failed: {e}"))?;
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn run(output: Option<&str>) -> Result<(), String> {
    if output.is_some() {
        return Err("unsupported-platform: macOS cold start is measured on macOS only".to_string());
    }
    eprintln!("skip: macos_cold_start is enabled on macOS only (TASK-113.4)");
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "--bench")
        .collect();
    let output = match args.as_slice() {
        [] => None,
        [flag, path] if flag == "--output" => Some(path.as_str()),
        _ => {
            eprintln!("error: invalid-args: unrecognized arguments");
            return ExitCode::FAILURE;
        }
    };
    match run(output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
