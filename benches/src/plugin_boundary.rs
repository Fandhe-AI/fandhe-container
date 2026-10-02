//! 代表操作 A（RunPodSandbox → CreateContainer → StartContainer 相当の 3 往復）の
//! plugin 境界ベンチの計測ロジック（TASK-113.1・PLUG-5・PLUG-6・MS-3）。
//!
//! 役割: 同一プロセス呼び出しと、plugin 境界越し（別プロセス＋UDS＋長さ接頭辞フレーム。
//! `fandhe-container-plugin`）呼び出しの p50 レイテンシを同じ状態遷移モデルで測り、
//! 比較スクリプト（`scripts/check-bench-regression.sh`）の results スキーマ
//! （`schema_version: 1`）の JSON として出力する。
//!
//! 呼び出し元: `benches/plugin_boundary.rs`（`harness = false` の薄い `main`。子プロセスの起動・
//! 後始末・ファイル書き出しを担う）と `benches/tests/plugin_boundary.rs`（スレッドのサーバーでの結合試験）。
//! `make test` はベンチバイナリを実行しないため、ロジックはこのモジュールに置いてテストする。
//!
//! 計測区間: 1 サンプル = 代表操作 A の 3 呼び出しの合計。接続確立・子プロセス起動は含めない
//! （起動コストは PLUG-6・TASK-113.4 側）。試行ごとの p50 の中央値を結果とする（PoC-13 と同じ集計）。
//!
//! Δp50（`delta_p50` モジュール。TASK-113.3）は metric `plugin_boundary_op_a_delta_p50` として出力する。
//! macOS cold start 上乗せは `macos_cold_start` モジュール（TASK-113.4）。未対応: gRPC 経路（TASK-108。未実装）。
//! 本モジュールの出力は `benches/baseline.json` に未登録のため `make bench-check` には接続していない
//! （実測基準値の確定は TASK-88.h1・TASK-113.h1。比較ロジックは fixture で検証済み）。

use std::fmt;
use std::time::{Duration, Instant};

use crate::delta_p50::{self, DeltaError};
use fandhe_container_plugin::{
    ControlMessage, MessageId, PluginError, PluginErrorCode, RpcTimeout, UdsStream, decode_message,
    encode_message,
};

/// 1 試行あたりの反復数の既定値（PLUG-5 の計測条件）。
pub const DEFAULT_ITERATIONS: usize = 1_000;
/// 試行数の既定値（PLUG-5 の計測条件）。
pub const DEFAULT_TRIALS: usize = 5;
/// 各試行前のウォームアップ回数（記録しない）。
pub const WARMUP_ITERATIONS: usize = 100;
/// 引数なし（スモーク）実行の反復数。
pub const SMOKE_ITERATIONS: usize = 20;
/// 引数なし（スモーク）実行の試行数。
pub const SMOKE_TRIALS: usize = 2;
/// 無制限な長時間占有を避けるための反復数の上限。
pub const MAX_ITERATIONS: usize = 1_000_000;
/// 試行数の上限。
pub const MAX_TRIALS: usize = 100;
/// フレーム 1 つの送受信に許す期限（REPAIR-5。`RpcTimeout` の上限と同じ 10 秒）。
pub const FRAME_TIMEOUT: Duration = Duration::from_secs(10);
/// accept・connect の期限。
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 結果 JSON の metric 名（同一プロセス経路）。
pub const METRIC_INPROC: &str = "plugin_boundary_op_a_inproc_p50";
/// 結果 JSON の metric 名（境界越し経路）。
pub const METRIC_FRAMED: &str = "plugin_boundary_op_a_framed_p50";
/// Δp50（framed − inproc。3 呼び出し合計。TASK-113.3）の metric 名。
pub const METRIC_DELTA: &str = "plugin_boundary_op_a_delta_p50";
/// 代表操作 A の往復回数 N（PLUG-5）。
pub const OP_A_ROUND_TRIPS: u32 = 3;

const OP_RUN_POD_SANDBOX: &str = "run_pod_sandbox";
const OP_CREATE_CONTAINER: &str = "create_container";
const OP_START_CONTAINER: &str = "start_container";
const PREFIX_SANDBOX: &str = "sandbox-";
const PREFIX_CONTAINER: &str = "container-";
const STATE_RUNNING: &str = "running";

/// ベンチハーネスの構造化エラー（`code` は機械可読、`message` は英語。ERR-1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchError {
    /// 機械可読なコード。
    pub code: &'static str,
    /// 英語の説明。受信データの断片は載せない。
    pub message: String,
}

impl BenchError {
    /// 構造化エラーを作る。
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for BenchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl From<PluginError> for BenchError {
    fn from(e: PluginError) -> Self {
        // 相手由来の文字列は載せず、code のみを写す。
        let code = match e.code() {
            PluginErrorCode::Timeout => "timeout",
            PluginErrorCode::Unavailable => "unavailable",
            PluginErrorCode::PermissionDenied => "permission-denied",
            PluginErrorCode::Unimplemented => "unsupported-platform",
            _ => "plugin-error",
        };
        Self::new(code, format!("plugin boundary error ({})", e.code()))
    }
}

/// 代表操作 A の状態遷移モデル（ID 採番と状態更新のみ。プロセス起動なし）。
///
/// 同一プロセス経路は直接、境界越し経路は子プロセス側のサーバーループから呼ばれ、
/// 両経路が同じ処理量になるようにする。
#[derive(Debug, Default)]
pub struct Model {
    next_id: u64,
    sandbox: Option<String>,
    container: Option<(String, bool)>,
}

impl Model {
    /// 空のモデルを作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// 1 操作を処理する。`args` は `[op, 引数...]`。未知の操作・前提状態違反は構造化エラー。
    pub fn handle(&mut self, args: &[String]) -> Result<Vec<String>, PluginError> {
        let op = args.first().map(String::as_str).unwrap_or("");
        match op {
            OP_RUN_POD_SANDBOX => {
                self.next_id += 1;
                let id = format!("sandbox-{}", self.next_id);
                self.sandbox = Some(id.clone());
                self.container = None;
                Ok(vec![id])
            }
            OP_CREATE_CONTAINER => {
                let sandbox = args.get(1);
                if sandbox.is_none() || sandbox != self.sandbox.as_ref() {
                    return Err(PluginError::new(
                        PluginErrorCode::FailedPrecondition,
                        "unknown sandbox",
                    ));
                }
                self.next_id += 1;
                let id = format!("container-{}", self.next_id);
                self.container = Some((id.clone(), false));
                Ok(vec![id])
            }
            OP_START_CONTAINER => match (&mut self.container, args.get(1)) {
                (Some((id, started)), Some(want)) if id == want && !*started => {
                    *started = true;
                    Ok(vec![STATE_RUNNING.to_string()])
                }
                _ => Err(PluginError::new(
                    PluginErrorCode::FailedPrecondition,
                    "unknown or already started container",
                )),
            },
            _ => Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "unknown operation",
            )),
        }
    }
}

/// 代表操作 A 1 回分の結果（検証用。両経路で一致すること）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpAOutcome {
    /// RunPodSandbox 相当の結果 ID。
    pub sandbox_id: String,
    /// CreateContainer 相当の結果 ID。
    pub container_id: String,
    /// StartContainer 相当の結果状態。
    pub state: String,
}

/// 応答本体がちょうど 1 要素であることを検証して取り出す（plugin 応答は untrusted。PLUG-5）。
fn single(v: Vec<String>) -> Result<String, BenchError> {
    let mut it = v.into_iter();
    match (it.next(), it.next()) {
        (Some(one), None) => Ok(one),
        _ => Err(BenchError::new(
            "bad-response",
            "response body must contain exactly one element",
        )),
    }
}

/// `<prefix><10 進数>` 形式の ID であることを検証する（`Model` が採番する形式）。
fn expect_id(v: Vec<String>, prefix: &str) -> Result<String, BenchError> {
    let id = single(v)?;
    let ok = id
        .strip_prefix(prefix)
        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()));
    if ok {
        Ok(id)
    } else {
        Err(BenchError::new("bad-response", "unexpected id format"))
    }
}

/// StartContainer 相当の応答が `running` であることを検証する。
fn expect_running(v: Vec<String>) -> Result<String, BenchError> {
    let state = single(v)?;
    if state == STATE_RUNNING {
        Ok(state)
    } else {
        Err(BenchError::new(
            "bad-response",
            "unexpected container state",
        ))
    }
}

/// 同一プロセスで代表操作 A（3 呼び出し）を実行する。
pub fn run_op_a_inproc(model: &mut Model) -> Result<OpAOutcome, BenchError> {
    let sandbox_id = expect_id(
        model.handle(&[OP_RUN_POD_SANDBOX.to_string()])?,
        PREFIX_SANDBOX,
    )?;
    let container_id = expect_id(
        model.handle(&[OP_CREATE_CONTAINER.to_string(), sandbox_id.clone()])?,
        PREFIX_CONTAINER,
    )?;
    let state =
        expect_running(model.handle(&[OP_START_CONTAINER.to_string(), container_id.clone()])?)?;
    Ok(OpAOutcome {
        sandbox_id,
        container_id,
        state,
    })
}

type Msg = ControlMessage<Vec<String>>;

fn rpc_timeout() -> Result<RpcTimeout, BenchError> {
    Ok(RpcTimeout::new(FRAME_TIMEOUT)?)
}

/// 境界越しに 1 往復する（`write_frame` → `read_frame` → 復号）。応答は untrusted として検証する。
pub fn round_trip(
    stream: &mut UdsStream,
    id: u64,
    args: Vec<String>,
) -> Result<Vec<String>, BenchError> {
    let timeout = rpc_timeout()?;
    let req: Msg = ControlMessage::Request {
        id: MessageId::new(id),
        body: args,
    };
    stream.write_frame(&encode_message(&req)?, timeout)?;
    let frame = stream.read_frame(timeout)?;
    match decode_message::<Vec<String>>(&frame)? {
        ControlMessage::Response { id: rid, body } if rid == MessageId::new(id) => Ok(body),
        ControlMessage::Error { .. } => {
            Err(BenchError::new("remote-error", "peer returned an error"))
        }
        _ => Err(BenchError::new(
            "bad-response",
            "unexpected response message",
        )),
    }
}

/// 接続済みの `UdsStream` 越しに代表操作 A（3 往復）を実行する。`next_id` はメッセージ ID の採番元。
pub fn run_op_a_framed(
    stream: &mut UdsStream,
    next_id: &mut u64,
) -> Result<OpAOutcome, BenchError> {
    let mut call = |args: Vec<String>| -> Result<Vec<String>, BenchError> {
        *next_id += 1;
        round_trip(stream, *next_id, args)
    };
    let sandbox_id = expect_id(call(vec![OP_RUN_POD_SANDBOX.to_string()])?, PREFIX_SANDBOX)?;
    let container_id = expect_id(
        call(vec![OP_CREATE_CONTAINER.to_string(), sandbox_id.clone()])?,
        PREFIX_CONTAINER,
    )?;
    let state = expect_running(call(vec![
        OP_START_CONTAINER.to_string(),
        container_id.clone(),
    ])?)?;
    Ok(OpAOutcome {
        sandbox_id,
        container_id,
        state,
    })
}

/// plugin 役のサーバーループ。切断（`Unavailable`）で正常終了し、それ以外の受信失敗はエラーで返す。
///
/// 未知の操作・前提状態違反は `ControlMessage::Error` を返して継続する。
pub fn serve(stream: &mut UdsStream) -> Result<(), BenchError> {
    let timeout = rpc_timeout()?;
    let mut model = Model::new();
    loop {
        let frame = match stream.read_frame(timeout) {
            Ok(f) => f,
            Err(e) if e.code() == PluginErrorCode::Unavailable => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let reply: Msg = match decode_message::<Vec<String>>(&frame)? {
            ControlMessage::Request { id, body } => match model.handle(&body) {
                Ok(body) => ControlMessage::Response { id, body },
                Err(error) => ControlMessage::Error { id, error },
            },
            _ => {
                return Err(BenchError::new("bad-request", "expected a request message"));
            }
        };
        stream.write_frame(&encode_message(&reply)?, timeout)?;
    }
}

/// 偶数個なら中央 2 値の平均（切り捨て）、奇数個なら中央値。空は `None`。入力は並べ替える。
pub fn percentile_p50(samples: &mut [u64]) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    let n = samples.len();
    let hi = *samples.get(n / 2)?;
    if n % 2 == 1 {
        return Some(hi);
    }
    let lo = *samples.get(n / 2 - 1)?;
    Some(lo / 2 + hi / 2 + (lo % 2 + hi % 2) / 2)
}

/// 計測条件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    /// 1 試行あたりの反復数。
    pub iterations: usize,
    /// 試行数。
    pub trials: usize,
    /// 試行前のウォームアップ回数。
    pub warmup: usize,
}

fn measure<F>(plan: Plan, mut op: F) -> Result<u64, BenchError>
where
    F: FnMut() -> Result<(), BenchError>,
{
    let mut trial_p50s = Vec::with_capacity(plan.trials);
    for _ in 0..plan.trials {
        for _ in 0..plan.warmup {
            op()?;
        }
        let mut samples = Vec::with_capacity(plan.iterations);
        for _ in 0..plan.iterations {
            let t = Instant::now();
            op()?;
            samples.push(u64::try_from(t.elapsed().as_nanos()).unwrap_or(u64::MAX));
        }
        let p50 = percentile_p50(&mut samples)
            .ok_or_else(|| BenchError::new("no-samples", "no samples were collected"))?;
        trial_p50s.push(p50);
    }
    let p50 = percentile_p50(&mut trial_p50s)
        .ok_or_else(|| BenchError::new("no-samples", "no trials were run"))?;
    if p50 == 0 {
        return Err(BenchError::new(
            "clock-resolution",
            "measured p50 is 0 ns; the clock resolution is too coarse",
        ));
    }
    Ok(p50)
}

/// 同一プロセス経路の p50（ns）を測る。
pub fn measure_inproc(plan: Plan) -> Result<u64, BenchError> {
    let mut model = Model::new();
    measure(plan, || run_op_a_inproc(&mut model).map(|_| ()))
}

/// 境界越し経路の p50（ns）を測る。`stream` は接続確立済みであること。
pub fn measure_framed(plan: Plan, stream: &mut UdsStream) -> Result<u64, BenchError> {
    let mut next_id = 0u64;
    measure(plan, || run_op_a_framed(stream, &mut next_id).map(|_| ()))
}

/// Δp50（ns）。`framed <= inproc` は計測異常として `Err`（fail-closed。0 へ丸めない）。
pub fn delta_ns(inproc_p50_ns: u64, framed_p50_ns: u64) -> Result<u64, BenchError> {
    framed_p50_ns
        .checked_sub(inproc_p50_ns)
        .filter(|d| *d > 0)
        .ok_or_else(|| {
            BenchError::new(
                DeltaError::NonPositiveDelta.code(),
                "framed p50 must exceed in-process p50",
            )
        })
}

/// Δp50 と CORE-10 比の構造化ログ行（stderr 用。`delta_p50::log_line`）を返す。
pub fn delta_log_line(inproc_p50_ns: u64, framed_p50_ns: u64) -> Result<String, BenchError> {
    // p50 の ns 値は 2^53 未満で f64 に正確に載る。
    let d = delta_p50::compute(inproc_p50_ns as f64, framed_p50_ns as f64, OP_A_ROUND_TRIPS)
        .map_err(|e| BenchError::new(e.code(), e.to_string()))?;
    Ok(delta_p50::log_line("a", &d))
}

/// 結果 JSON（比較スクリプトの results スキーマ。単位は ns）を組み立てる。
/// Δp50 が正でなければ `Err`。
pub fn results_json(inproc_p50_ns: u64, framed_p50_ns: u64) -> Result<String, BenchError> {
    let delta = delta_ns(inproc_p50_ns, framed_p50_ns)?;
    Ok(format!(
        "{{\n  \"schema_version\": 1,\n  \"metrics\": {{\n    \"{METRIC_INPROC}\": {{\n      \"value\": {inproc_p50_ns},\n      \"unit\": \"ns\"\n    }},\n    \"{METRIC_FRAMED}\": {{\n      \"value\": {framed_p50_ns},\n      \"unit\": \"ns\"\n    }},\n    \"{METRIC_DELTA}\": {{\n      \"value\": {delta},\n      \"unit\": \"ns\"\n    }}\n  }}\n}}\n"
    ))
}

/// 解釈済みのコマンドライン。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// 少数回の計測を行い、結果 JSON を標準出力へ出す。
    Smoke,
    /// 計測し、結果 JSON を `output` へ書く。
    Run {
        /// 計測条件。
        plan: Plan,
        /// 結果 JSON の書き出し先。
        output: String,
    },
    /// 子プロセス側（plugin 役）。`socket` へ接続してサーバーループを回す。
    PluginServe {
        /// 接続先の socket パス。
        socket: String,
    },
}

/// 引数（プログラム名を除く）を解釈する。`cargo bench` が付ける `--bench` は無視する。
pub fn parse_args(args: &[String]) -> Result<Command, BenchError> {
    let invalid = |m: &str| BenchError::new("invalid-args", m.to_string());
    let mut output = None;
    let mut socket = None;
    let mut iterations = None;
    let mut trials = None;
    let mut it = args.iter().filter(|a| a.as_str() != "--bench");
    while let Some(a) = it.next() {
        match a.as_str() {
            "--output" | "--plugin-serve" | "--iterations" | "--trials" => {}
            _ => {
                return Err(invalid(
                    "usage: plugin_boundary [--output <path>] [--iterations <n>] [--trials <n>]",
                ));
            }
        }
        let value = it
            .next()
            .ok_or_else(|| invalid("missing value for option"))?;
        match a.as_str() {
            "--output" => output = Some(value.clone()),
            "--plugin-serve" => socket = Some(value.clone()),
            "--iterations" => iterations = Some(parse_count(value, MAX_ITERATIONS)?),
            _ => trials = Some(parse_count(value, MAX_TRIALS)?),
        }
    }
    if let Some(socket) = socket {
        return Ok(Command::PluginServe { socket });
    }
    match output {
        Some(output) => Ok(Command::Run {
            plan: Plan {
                iterations: iterations.unwrap_or(DEFAULT_ITERATIONS),
                trials: trials.unwrap_or(DEFAULT_TRIALS),
                warmup: WARMUP_ITERATIONS,
            },
            output,
        }),
        None if iterations.is_none() && trials.is_none() => Ok(Command::Smoke),
        None => Err(invalid("--iterations and --trials require --output")),
    }
}

fn parse_count(s: &str, max: usize) -> Result<usize, BenchError> {
    match s.parse::<usize>() {
        Ok(n) if (1..=max).contains(&n) => Ok(n),
        _ => Err(BenchError::new(
            "invalid-args",
            format!("count must be an integer in 1..={max}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// PLUG-5: p50 の具体値（奇数・偶数・1 個・空）。
    #[test]
    fn plug5_percentile_p50_concrete_values() {
        assert_eq!(percentile_p50(&mut [5, 1, 3]), Some(3));
        assert_eq!(percentile_p50(&mut [4, 1, 3, 2]), Some(2));
        assert_eq!(percentile_p50(&mut [7]), Some(7));
        assert_eq!(percentile_p50(&mut []), None);
        assert_eq!(percentile_p50(&mut [u64::MAX, u64::MAX]), Some(u64::MAX));
    }

    /// PLUG-5: 代表操作 A が 3 段階を踏んで期待 ID・状態になる。
    #[test]
    fn plug5_op_a_inproc_walks_three_stages() {
        let mut m = Model::new();
        let out = run_op_a_inproc(&mut m).unwrap();
        assert_eq!(out.sandbox_id, "sandbox-1");
        assert_eq!(out.container_id, "container-2");
        assert_eq!(out.state, "running");
    }

    /// PLUG-5: 不正な応答（件数・ID 形式・状態）は計測失敗になる。
    #[test]
    fn plug5_response_validation_rejects_bad_bodies() {
        assert_eq!(single(s(&["a"])).unwrap(), "a");
        assert_eq!(single(vec![]).unwrap_err().code, "bad-response");
        assert_eq!(single(s(&["a", "b"])).unwrap_err().code, "bad-response");
        assert_eq!(
            expect_id(s(&["sandbox-12"]), PREFIX_SANDBOX).unwrap(),
            "sandbox-12"
        );
        for bad in ["container-1", "sandbox-", "sandbox-1x", "evil", ""] {
            assert_eq!(
                expect_id(s(&[bad]), PREFIX_SANDBOX).unwrap_err().code,
                "bad-response",
                "{bad}"
            );
        }
        assert_eq!(expect_running(s(&["running"])).unwrap(), "running");
        assert_eq!(
            expect_running(s(&["stopped"])).unwrap_err().code,
            "bad-response"
        );
    }

    #[test]
    fn model_rejects_unknown_op_and_bad_state() {
        let mut m = Model::new();
        assert_eq!(
            m.handle(&s(&["nope"])).unwrap_err().code(),
            PluginErrorCode::InvalidArgument
        );
        assert_eq!(
            m.handle(&s(&["create_container", "sandbox-9"]))
                .unwrap_err()
                .code(),
            PluginErrorCode::FailedPrecondition
        );
        assert_eq!(
            m.handle(&[]).unwrap_err().code(),
            PluginErrorCode::InvalidArgument
        );
    }

    #[test]
    fn plug5_results_json_has_both_metrics() {
        let j = results_json(120, 45_000).unwrap();
        assert!(j.contains("\"plugin_boundary_op_a_inproc_p50\": {\n      \"value\": 120,"));
        assert!(j.contains("\"plugin_boundary_op_a_framed_p50\": {\n      \"value\": 45000,"));
        assert!(j.contains("\"schema_version\": 1"));
        assert!(j.contains("\"plugin_boundary_op_a_delta_p50\": {\n      \"value\": 44880,"));
        assert_eq!(j.matches("\"unit\": \"ns\"").count(), 3);
    }

    /// REPAIR-8: framed が inproc 以下なら Err（fail-closed）。
    #[test]
    fn plug5_results_json_rejects_non_positive_delta() {
        assert_eq!(
            results_json(100, 100).unwrap_err().code,
            "non-positive-delta"
        );
        assert_eq!(
            results_json(200, 100).unwrap_err().code,
            "non-positive-delta"
        );
    }

    #[test]
    fn parse_args_cases() {
        assert_eq!(parse_args(&s(&[])).unwrap(), Command::Smoke);
        assert_eq!(parse_args(&s(&["--bench"])).unwrap(), Command::Smoke);
        assert_eq!(
            parse_args(&s(&["--bench", "--output", "r.json"])).unwrap(),
            Command::Run {
                plan: Plan {
                    iterations: 1000,
                    trials: 5,
                    warmup: 100
                },
                output: "r.json".into()
            }
        );
        assert_eq!(
            parse_args(&s(&["--output", "r", "--iterations", "7", "--trials", "2"])).unwrap(),
            Command::Run {
                plan: Plan {
                    iterations: 7,
                    trials: 2,
                    warmup: 100
                },
                output: "r".into()
            }
        );
        assert_eq!(
            parse_args(&s(&["--plugin-serve", "/x/s.sock"])).unwrap(),
            Command::PluginServe {
                socket: "/x/s.sock".into()
            }
        );
        for bad in [
            s(&["--wat"]),
            s(&["--output"]),
            s(&["--output", "r", "--iterations", "0"]),
            s(&["--output", "r", "--iterations", "1000001"]),
            s(&["--output", "r", "--trials", "101"]),
            s(&["--output", "r", "--trials", "x"]),
            s(&["--iterations", "5"]),
        ] {
            assert_eq!(
                parse_args(&bad).unwrap_err().code,
                "invalid-args",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn measure_inproc_returns_positive_p50() {
        let p = measure_inproc(Plan {
            iterations: 50,
            trials: 2,
            warmup: 5,
        })
        .unwrap();
        assert!(p > 0);
    }
}
