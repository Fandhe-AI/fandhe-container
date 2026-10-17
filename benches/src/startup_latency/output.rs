//! 起動レイテンシベンチの結果 JSON（results スキーマ互換。TASK-190・REPAIR-8・REPAIR-3）。
//!
//! `schema_version: 1`・`metrics.<名前>.{value, unit}` の形で、キー順は固定。失敗が 1 件でもある、または後始末の
//! 残りがある実行では `metrics` を空 `{}` にする（部分的な標本の p95 を回帰ゲートへ流さない。fail-closed）。
//! 絶対パス・ホスト名・ユーザー名は載せない（ID はベンチが生成した英数字だけ）。

use super::StartupLatencyError;
use super::stats::summarize;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

/// metric 名。区間が違う `startup_latency_p50_ms`（TASK-46.1・CLI 経由の中央値）と取り違えない。
pub const METRIC_NAME: &str = "startup_create_to_supervisor_ok_p95_ms";
/// metric の単位。`benches/metrics.json` の unit と一致させる（自己テストが機械照合する。REPAIR-12）。
pub const METRIC_UNIT: &str = "ms";
/// 計測方法の識別子（区間と経路。`docs/design/startup-latency-bench.md`）。
pub const METHOD: &str = "core-create-to-supervisor-ok/systemd-run-user-scope/production-launcher";

/// 出力に載せる実行パラメータ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    pub trials: u32,
    pub warmup: u32,
    pub timeout_secs: u64,
    pub report_timeout_ms: u64,
    pub exit_timeout_ms: u64,
    pub cleanup_timeout_ms: u64,
}

/// 1 試行の標本。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// create 開始から OK 行を読み終えるまで。
    pub total: Duration,
    /// create 単体（診断用。metric にはしない）。
    pub create: Duration,
}

/// 失敗の種別ごとの件数（ウォームアップの失敗も数える）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Failures {
    pub create: u32,
    pub spawn: u32,
    pub report_err: u32,
    pub report_err_codes: BTreeMap<&'static str, u32>,
    pub report_timeout: u32,
    pub report_eof: u32,
    pub report_invalid: u32,
    pub supervisor_exit: u32,
    pub cleanup: u32,
}

impl Failures {
    pub fn total(&self) -> u32 {
        [
            self.create,
            self.spawn,
            self.report_err,
            self.report_timeout,
            self.report_eof,
            self.report_invalid,
            self.supervisor_exit,
            self.cleanup,
        ]
        .iter()
        .fold(0u32, |acc, v| acc.saturating_add(*v))
    }
}

/// 実行全体の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    pub params: Params,
    pub samples: Vec<Sample>,
    pub failures: Failures,
    pub leftover_ids: Vec<String>,
    pub arch: &'static str,
    /// ホストの種類（`bare-metal` / `vm` / `wsl2` / `unknown`。`probe_env::detect_host_kind`）。固定の語彙だけを出す。
    /// キーを足すだけの変更なので `schema_version` は 1 のまま（読み手は未知のキーを無視する）。
    pub host_kind: &'static str,
}

impl RunResult {
    /// 失敗も残りも無い（metric を出してよい）か。
    pub fn is_clean(&self) -> bool {
        self.failures.total() == 0 && self.leftover_ids.is_empty()
    }
}

fn ms(d: Duration) -> String {
    format!("{:.3}", d.as_secs_f64() * 1000.0)
}

/// 結果を `path` へ新規作成で書く。`create_new`（O_CREAT|O_EXCL）で開くため、既存の FIFO・symlink・ファイルは
/// 開かずに失敗する（FIFO で無期限に止まらず、symlink の参照先を上書きしない。REPAIR-5）。
/// 親ディレクトリと既存の有無は計測の開始前に `bin_check::verify_output_target` が検証する。
pub fn write_new(path: &std::path::Path, json: &str) -> Result<(), StartupLatencyError> {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            StartupLatencyError::new("io-error", format!("write output failed ({:?})", e.kind()))
        })?;
    f.write_all(json.as_bytes()).map_err(|e| {
        StartupLatencyError::new("io-error", format!("write output failed ({:?})", e.kind()))
    })
}

/// JSON を組み立てる。metric の値が 0 以下になる場合は `invalid-measurement`。
pub fn render_json(result: &RunResult) -> Result<String, StartupLatencyError> {
    let totals: Vec<Duration> = result.samples.iter().map(|s| s.total).collect();
    let summary = summarize(&totals);
    let metrics = if result.is_clean() {
        let p95 = summary.map(|s| s.p95).ok_or_else(|| {
            StartupLatencyError::new("invalid-measurement", "no samples were collected")
        })?;
        if p95.is_zero() {
            return Err(StartupLatencyError::new(
                "invalid-measurement",
                "the p95 value must be positive",
            ));
        }
        format!(
            "{{\"{METRIC_NAME}\":{{\"value\":{},\"unit\":\"{METRIC_UNIT}\"}}}}",
            ms(p95)
        )
    } else {
        "{}".to_string()
    };
    let p = &result.params;
    let mut out = String::new();
    let _ = write!(
        out,
        "{{\"schema_version\":1,\"metrics\":{metrics},\"method\":\"{METHOD}\",\"aggregate\":\"p95-nearest-rank\",\
\"params\":{{\"trials\":{},\"warmup\":{},\"timeout_secs\":{},\"report_timeout_ms\":{},\"exit_timeout_ms\":{},\"cleanup_timeout_ms\":{}}},",
        p.trials,
        p.warmup,
        p.timeout_secs,
        p.report_timeout_ms,
        p.exit_timeout_ms,
        p.cleanup_timeout_ms
    );
    match summary {
        Some(s) => {
            let _ = write!(
                out,
                "\"summary\":{{\"samples\":{},\"p50_ms\":{},\"p95_ms\":{},\"max_ms\":{}}},",
                s.samples,
                ms(s.p50),
                ms(s.p95),
                ms(s.max)
            );
        }
        None => out.push_str("\"summary\":null,"),
    }
    out.push_str("\"trials\":[");
    for (i, s) in result.samples.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"total_ms\":{},\"create_ms\":{}}}",
            ms(s.total),
            ms(s.create)
        );
    }
    let f = &result.failures;
    let _ = write!(
        out,
        "],\"failures\":{{\"total\":{},\"create\":{},\"spawn\":{},\"report_err\":{},\"report_err_codes\":{{",
        f.total(),
        f.create,
        f.spawn,
        f.report_err
    );
    for (i, (code, n)) in f.report_err_codes.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{code}\":{n}");
    }
    let _ = write!(
        out,
        "}},\"report_timeout\":{},\"report_eof\":{},\"report_invalid\":{},\"supervisor_exit\":{},\"cleanup\":{}}},\"leftover_ids\":[",
        f.report_timeout, f.report_eof, f.report_invalid, f.supervisor_exit, f.cleanup
    );
    for (i, id) in result.leftover_ids.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{id}\"");
    }
    let _ = writeln!(
        out,
        "],\"arch\":\"{}\",\"host_kind\":\"{}\"}}",
        result.arch, result.host_kind
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn write_new_creates_once_and_never_follows_a_symlink() {
        let dir = std::env::temp_dir().join(format!("fc-out-wn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("mkdir");
        let out = dir.join("r.json");
        write_new(&out, "{}").expect("first write");
        assert_eq!(std::fs::read_to_string(&out).expect("read"), "{}");
        assert_eq!(write_new(&out, "x").unwrap_err().code, "io-error");
        assert_eq!(std::fs::read_to_string(&out).expect("read"), "{}");
        let victim = dir.join("victim");
        std::fs::write(&victim, "keep").expect("write");
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&victim, &link).expect("symlink");
        assert_eq!(write_new(&link, "x").unwrap_err().code, "io-error");
        assert_eq!(std::fs::read_to_string(&victim).expect("read"), "keep");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    fn params() -> Params {
        Params {
            trials: 20,
            warmup: 3,
            timeout_secs: 1800,
            report_timeout_ms: 36000,
            exit_timeout_ms: 30000,
            cleanup_timeout_ms: 10000,
        }
    }

    fn samples() -> Vec<Sample> {
        (1..=20u64)
            .map(|v| Sample {
                total: Duration::from_millis(v),
                create: Duration::from_micros(500),
            })
            .collect()
    }

    fn clean() -> RunResult {
        RunResult {
            params: params(),
            samples: samples(),
            failures: Failures::default(),
            leftover_ids: Vec::new(),
            arch: "x86_64",
            host_kind: "vm",
        }
    }

    /// 成功時は固定の期待文字列と完全一致する（キー順・小数 3 桁）。
    #[test]
    fn clean_run_matches_the_expected_document() {
        let mut r = clean();
        r.samples.truncate(2);
        let expected = concat!(
            "{\"schema_version\":1,",
            "\"metrics\":{\"startup_create_to_supervisor_ok_p95_ms\":{\"value\":2.000,\"unit\":\"ms\"}},",
            "\"method\":\"core-create-to-supervisor-ok/systemd-run-user-scope/production-launcher\",",
            "\"aggregate\":\"p95-nearest-rank\",",
            "\"params\":{\"trials\":20,\"warmup\":3,\"timeout_secs\":1800,\"report_timeout_ms\":36000,\"exit_timeout_ms\":30000,\"cleanup_timeout_ms\":10000},",
            "\"summary\":{\"samples\":2,\"p50_ms\":1.000,\"p95_ms\":2.000,\"max_ms\":2.000},",
            "\"trials\":[{\"total_ms\":1.000,\"create_ms\":0.500},{\"total_ms\":2.000,\"create_ms\":0.500}],",
            "\"failures\":{\"total\":0,\"create\":0,\"spawn\":0,\"report_err\":0,\"report_err_codes\":{},\"report_timeout\":0,\"report_eof\":0,\"report_invalid\":0,\"supervisor_exit\":0,\"cleanup\":0},",
            "\"leftover_ids\":[],\"arch\":\"x86_64\",\"host_kind\":\"vm\"}\n"
        );
        assert_eq!(render_json(&r).expect("render"), expected);
    }

    /// REPAIR-3: 失敗が 1 件でもあれば metric を出さず、件数を載せる。
    #[test]
    fn any_failure_empties_metrics_and_reports_counts() {
        let mut r = clean();
        r.failures.report_err = 2;
        r.failures.report_err_codes.insert("FAILED_PRECONDITION", 2);
        r.failures.report_timeout = 1;
        let json = render_json(&r).expect("render");
        assert!(json.contains("\"metrics\":{},"), "{json}");
        assert!(
            json.contains("\"failures\":{\"total\":3,\"create\":0,\"spawn\":0,\"report_err\":2,\"report_err_codes\":{\"FAILED_PRECONDITION\":2},\"report_timeout\":1,"),
            "{json}"
        );
    }

    #[test]
    fn leftover_ids_are_reported_and_empty_metrics() {
        let mut r = clean();
        r.leftover_ids.push("fcsl1t3".to_string());
        let json = render_json(&r).expect("render");
        assert!(json.contains("\"metrics\":{},"), "{json}");
        assert!(json.contains("\"leftover_ids\":[\"fcsl1t3\"]"), "{json}");
    }

    #[test]
    fn zero_p95_is_an_error() {
        let mut r = clean();
        for s in &mut r.samples {
            s.total = Duration::ZERO;
        }
        assert_eq!(
            render_json(&r).expect_err("must fail").code,
            "invalid-measurement"
        );
    }

    /// 絶対パス・ホスト名を出さない（`/` で始まる文字列値が無い）。
    #[test]
    fn output_has_no_absolute_path_values() {
        let json = render_json(&clean()).expect("render");
        assert!(!json.contains(":\"/"), "{json}");
        assert!(!json.contains("[\"/"), "{json}");
    }
}
