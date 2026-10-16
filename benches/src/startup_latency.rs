//! コンテナ起動レイテンシ p95 の回帰ベンチの計測ロジック（TASK-190・#1900・REPAIR-8・CORE-10）。
//!
//! `benches/benches/startup_latency.rs`（`harness = false` の薄い入口）から呼ばれる。計測定義の詳細は
//! `docs/design/startup-latency-bench.md`、CI での扱いの決定は `docs/design/bench-calibration.md` にある。
//!
//! # 計測区間（CORE-10 と同じ「create からプロセス実行開始まで」の本番経路版）
//! - 始点: core の `oci_runtime::create` を呼ぶ直前
//! - 終点: supervisor の bin（本番 launcher まで到達する。#1819）が結果チャネルへ書く
//!   `FCSUP1 OK <pid>` の 1 行を読み終えた時刻
//! - CLI と `state` の往復は含まない（`scripts/bench/startup_latency.sh`〔TASK-46.1〕は CLI 経由・中央値で、
//!   区間も統計量も別。取り違えないよう metric 名を `startup_create_to_supervisor_ok_p95_ms` にする）
//!
//! # 構成
//! - OS 非依存: [`args`]（引数）・[`stats`]（nearest-rank の p95）・[`report`]（結果 1 行の分類）・[`output`]（JSON）
//! - Linux（x86_64 / aarch64）限定: 計測本体（bin 検証・rootfs 構築・試行・後始末）
//!
//! # REPAIR-3（実装済みを装わない）
//! 分離を弱めた起動（Landlock なし・フェイクの launcher・supervisor の迂回）は実装しない。本番経路が失敗したら
//! 失敗として数え、metric を出さない（fail-closed）。CI では実行できず、実測は人間担当（実機前提。AGENTS.md）。
//! 回帰ゲートへの登録（`BENCH_NAMES`・`metrics.json`・`baseline.json`）は #1901 の範囲で、本モジュールは行わない。

pub mod args;
pub mod output;
pub mod report;
pub mod stats;

#[cfg(all(
    target_os = "linux",
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod bin_check;
#[cfg(all(
    target_os = "linux",
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod bundle;
#[cfg(all(
    target_os = "linux",
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod measure;
#[cfg(target_os = "linux")]
mod probe_env;
#[cfg(all(
    target_os = "linux",
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod scope_wrap;

use args::Command;
use std::path::PathBuf;
use std::time::Duration;

/// コンテナ内のワークロードが眠る時間。OK の報告まで PID 1 を確実に生かすためで、計測区間の外にある。
const WORKLOAD_SLEEP: Duration = Duration::from_millis(300);

/// 構造化エラー（`code` / `message`）。message は固定の英語文言で、パス・ホスト名・OS 由来の文字列を載せない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupLatencyError {
    pub code: &'static str,
    pub message: String,
}

impl StartupLatencyError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for StartupLatencyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // code・message は固定文字列に由来し、引用符・バックスラッシュを含まない。
        write!(
            f,
            "{{\"error\":{{\"code\":\"{}\",\"message\":\"{}\"}}}}",
            self.code, self.message
        )
    }
}

impl std::error::Error for StartupLatencyError {}

/// 実行結果。入口（`benches/benches/startup_latency.rs`）が出力と終了コードへ写す。
#[derive(Debug)]
pub enum Execution {
    /// スモーク（何も起動しない）。標準出力へ出す 1 行。終了コード 0。
    Smoke(String),
    /// この OS では計測しない（計測したように見せない）。終了コード 0。
    Unsupported,
    /// 計測を行った。`clean` が false（失敗・後始末の残りあり）なら終了コード 1。
    Done {
        json: String,
        output: Option<PathBuf>,
        clean: bool,
    },
}

/// コンテナ内のワークロード（`--startup-latency-probe <nonce>`）。固定時間眠って終了コード 0 で終わる。
/// nonce は後始末が `/proc` を走査して自分のプローブだけを数えるための目印で、ここでは使わない。
pub fn run_workload() -> ! {
    std::thread::sleep(WORKLOAD_SLEEP);
    std::process::exit(0)
}

/// 解析済みコマンドを実行する。`Probe` は入口が `run_workload` で処理するため、ここへは来ない。
pub fn execute(command: Command) -> Result<Execution, StartupLatencyError> {
    match command {
        Command::Probe(_) => Err(StartupLatencyError::new(
            "invalid-args",
            "probe mode must be handled by the entry point",
        )),
        Command::Smoke => Ok(Execution::Smoke(smoke_line())),
        Command::Measure(plan) => measure_on_this_os(plan),
    }
}

#[cfg(target_os = "linux")]
fn smoke_line() -> String {
    probe_env::host_probe_line()
}

#[cfg(not(target_os = "linux"))]
fn smoke_line() -> String {
    "startup_latency: smoke; not applicable on this OS".to_string()
}

#[cfg(all(
    target_os = "linux",
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn measure_on_this_os(plan: args::Plan) -> Result<Execution, StartupLatencyError> {
    measure::run(plan)
}

#[cfg(not(all(
    target_os = "linux",
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn measure_on_this_os(_plan: args::Plan) -> Result<Execution, StartupLatencyError> {
    Ok(Execution::Unsupported)
}
