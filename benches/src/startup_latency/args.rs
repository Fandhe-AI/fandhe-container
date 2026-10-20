//! 起動レイテンシベンチの引数解析（TASK-190・REPAIR-5・REPAIR-8）。
//!
//! 引数なし（`--bench` は cargo が付けるので無視）は何も起動しないスモーク。計測には `--supervisor-bin` と
//! `--cli-bin`（どちらも絶対パス）が必須で、`PATH` からは探さない（信頼できない実行ファイルを起動しないため）。
//! `--cli-bin` は後始末の `delete`（OCI-6・#2157）だけに使い、計測区間の起動経路には入らない。

use super::StartupLatencyError;
use std::path::{Path, PathBuf};

/// 試行回数の既定と範囲。20 未満だと nearest-rank の p95 が最大値と同じ順位になるため 20 を下限にする。
pub const DEFAULT_TRIALS: u32 = 30;
pub const MIN_TRIALS: u32 = 20;
pub const MAX_TRIALS: u32 = 200;
/// ウォームアップの既定と上限。標本には入れない（失敗は数える）。
pub const DEFAULT_WARMUP: u32 = 3;
pub const MAX_WARMUP: u32 = 20;
/// 全体の期限（秒）の既定と範囲。
pub const DEFAULT_TIMEOUT_SECS: u64 = 1800;
pub const MIN_TIMEOUT_SECS: u64 = 60;
pub const MAX_TIMEOUT_SECS: u64 = 7200;
/// `systemd-run` の既定の場所。
pub const DEFAULT_SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const MAX_NONCE_LEN: usize = 64;

/// 計測の計画。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub trials: u32,
    pub warmup: u32,
    pub timeout_secs: u64,
    pub supervisor_bin: PathBuf,
    /// 後始末の `delete` を呼ぶ CLI の実バイナリ（`fandhe-container`。計測区間の外でだけ使う。OCI-6）。
    pub cli_bin: PathBuf,
    pub systemd_run: PathBuf,
    pub work_dir: Option<PathBuf>,
    pub output: Option<PathBuf>,
}

/// scope 取得だけを測る診断の計画（`--scope-only`。supervisor・作業ディレクトリは使わない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopePlan {
    pub trials: u32,
    pub warmup: u32,
    pub timeout_secs: u64,
    pub systemd_run: PathBuf,
    pub output: Option<PathBuf>,
}

/// 解析結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// 何も起動しない確認。
    Smoke,
    /// コンテナ内のワークロード（nonce は後始末の目印）。
    Probe(String),
    /// 計測。
    Measure(Plan),
    /// scope 取得だけを測る診断（`--scope-only`。metric は出さない。CORE-10・REPAIR-8）。
    ScopeOnly(ScopePlan),
    /// 診断が scope の中で起動する自明なコマンド（`--startup-latency-noop`）。すぐ終了コード 0 で終わる。
    Noop,
}

fn bad(message: impl Into<String>) -> StartupLatencyError {
    StartupLatencyError::new("invalid-args", message)
}

fn number<T: std::str::FromStr + PartialOrd + Copy>(
    name: &str,
    raw: &str,
    min: T,
    max: T,
) -> Result<T, StartupLatencyError> {
    let v: T = raw
        .parse()
        .map_err(|_| bad(format!("{name} must be an integer")))?;
    if v < min || v > max {
        return Err(bad(format!("{name} is out of range")));
    }
    Ok(v)
}

fn absolute(name: &str, raw: &str) -> Result<PathBuf, StartupLatencyError> {
    let p = Path::new(raw);
    if !p.is_absolute() {
        return Err(bad(format!("{name} must be an absolute path")));
    }
    Ok(p.to_path_buf())
}

/// 引数（プログラム名を除く）を解析する。未知・重複・値の欠落・範囲外・相対パスは `invalid-args`。
pub fn parse_args(args: &[String]) -> Result<Command, StartupLatencyError> {
    if args.first().map(String::as_str) == Some("--startup-latency-probe") {
        let nonce = args.get(1).ok_or_else(|| bad("probe nonce is missing"))?;
        if args.len() != 2
            || nonce.is_empty()
            || nonce.len() > MAX_NONCE_LEN
            || !nonce.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err(bad("probe nonce is invalid"));
        }
        return Ok(Command::Probe(nonce.clone()));
    }
    if args.first().map(String::as_str) == Some("--startup-latency-noop") {
        // cargo bench 経由の起動では `--bench` が末尾に付くため、それだけは許す。
        if args.iter().skip(1).any(|x| x != "--bench") {
            return Err(bad("noop mode takes no other arguments"));
        }
        return Ok(Command::Noop);
    }
    let mut scope_only = false;
    let mut trials = None;
    let mut warmup = None;
    let mut timeout_secs = None;
    let mut supervisor_bin = None;
    let mut cli_bin = None;
    let mut systemd_run = None;
    let mut work_dir = None;
    let mut output = None;
    let mut any = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg == "--bench" {
            continue;
        }
        any = true;
        let dup = || bad("duplicate option");
        let mut value = || {
            it.next()
                .map(String::as_str)
                .ok_or_else(|| bad("option value is missing"))
        };
        match arg.as_str() {
            "--scope-only" => {
                if std::mem::replace(&mut scope_only, true) {
                    return Err(dup());
                }
            }
            "--trials" => {
                let v = number("--trials", value()?, MIN_TRIALS, MAX_TRIALS)?;
                if trials.replace(v).is_some() {
                    return Err(dup());
                }
            }
            "--warmup" => {
                let v = number("--warmup", value()?, 0, MAX_WARMUP)?;
                if warmup.replace(v).is_some() {
                    return Err(dup());
                }
            }
            "--timeout-secs" => {
                let v = number(
                    "--timeout-secs",
                    value()?,
                    MIN_TIMEOUT_SECS,
                    MAX_TIMEOUT_SECS,
                )?;
                if timeout_secs.replace(v).is_some() {
                    return Err(dup());
                }
            }
            "--supervisor-bin" => {
                let v = absolute("--supervisor-bin", value()?)?;
                if supervisor_bin.replace(v).is_some() {
                    return Err(dup());
                }
            }
            "--cli-bin" => {
                let v = absolute("--cli-bin", value()?)?;
                if cli_bin.replace(v).is_some() {
                    return Err(dup());
                }
            }
            "--systemd-run" => {
                let v = absolute("--systemd-run", value()?)?;
                if systemd_run.replace(v).is_some() {
                    return Err(dup());
                }
            }
            "--work-dir" => {
                let v = absolute("--work-dir", value()?)?;
                if work_dir.replace(v).is_some() {
                    return Err(dup());
                }
            }
            "--output" => {
                let v = absolute("--output", value()?)?;
                if output.replace(v).is_some() {
                    return Err(dup());
                }
            }
            _ => return Err(bad("unknown option")),
        }
    }
    if !any {
        return Ok(Command::Smoke);
    }
    if scope_only {
        // 診断は supervisor も作業ディレクトリも使わない。指定は取り違えなので拒否する。
        if supervisor_bin.is_some() || cli_bin.is_some() || work_dir.is_some() {
            return Err(bad(
                "--scope-only does not accept --supervisor-bin, --cli-bin or --work-dir",
            ));
        }
        return Ok(Command::ScopeOnly(ScopePlan {
            trials: trials.unwrap_or(DEFAULT_TRIALS),
            warmup: warmup.unwrap_or(DEFAULT_WARMUP),
            timeout_secs: timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS),
            systemd_run: systemd_run.unwrap_or_else(|| PathBuf::from(DEFAULT_SYSTEMD_RUN)),
            output,
        }));
    }
    let supervisor_bin = supervisor_bin.ok_or_else(|| bad("--supervisor-bin is required"))?;
    let cli_bin = cli_bin.ok_or_else(|| bad("--cli-bin is required"))?;
    Ok(Command::Measure(Plan {
        trials: trials.unwrap_or(DEFAULT_TRIALS),
        warmup: warmup.unwrap_or(DEFAULT_WARMUP),
        timeout_secs: timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS),
        supervisor_bin,
        cli_bin,
        systemd_run: systemd_run.unwrap_or_else(|| PathBuf::from(DEFAULT_SYSTEMD_RUN)),
        work_dir,
        output,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    fn code(v: &[&str]) -> &'static str {
        parse_args(&a(v)).expect_err("must be rejected").code
    }

    #[test]
    fn no_args_and_bench_only_are_smoke() {
        assert_eq!(parse_args(&[]), Ok(Command::Smoke));
        assert_eq!(parse_args(&a(&["--bench"])), Ok(Command::Smoke));
    }

    #[test]
    fn probe_mode_requires_a_valid_nonce() {
        assert_eq!(
            parse_args(&a(&["--startup-latency-probe", "ab12"])),
            Ok(Command::Probe("ab12".to_string()))
        );
        assert_eq!(code(&["--startup-latency-probe"]), "invalid-args");
        assert_eq!(code(&["--startup-latency-probe", "a/b"]), "invalid-args");
    }

    /// CORE-10: noop は単独のときだけ受け付ける。
    #[test]
    fn noop_mode_takes_no_other_arguments() {
        assert_eq!(
            parse_args(&a(&["--startup-latency-noop"])),
            Ok(Command::Noop)
        );
        assert_eq!(
            parse_args(&a(&["--startup-latency-noop", "--bench"])),
            Ok(Command::Noop)
        );
        assert_eq!(
            code(&["--startup-latency-noop", "--trials", "20"]),
            "invalid-args"
        );
    }

    /// REPAIR-8: 診断は supervisor を要らず、指定されたら拒否する。
    #[cfg(unix)]
    #[test]
    fn scope_only_mode_is_parsed_and_rejects_measure_only_options() {
        let got = parse_args(&a(&["--bench", "--scope-only", "--trials", "25"])).expect("plan");
        assert_eq!(
            got,
            Command::ScopeOnly(ScopePlan {
                trials: 25,
                warmup: 3,
                timeout_secs: 1800,
                systemd_run: PathBuf::from("/usr/bin/systemd-run"),
                output: None,
            })
        );
        assert_eq!(
            code(&["--scope-only", "--supervisor-bin", "/opt/sup"]),
            "invalid-args"
        );
        assert_eq!(
            code(&["--scope-only", "--cli-bin", "/opt/cli"]),
            "invalid-args"
        );
        assert_eq!(code(&["--scope-only", "--work-dir", "/w"]), "invalid-args");
        assert_eq!(code(&["--scope-only", "--scope-only"]), "invalid-args");
    }

    #[cfg(unix)]
    #[test]
    fn defaults_are_applied() {
        let got = parse_args(&a(&[
            "--bench",
            "--supervisor-bin",
            "/opt/sup",
            "--cli-bin",
            "/opt/cli",
        ]))
        .expect("plan");
        assert_eq!(
            got,
            Command::Measure(Plan {
                trials: 30,
                warmup: 3,
                timeout_secs: 1800,
                supervisor_bin: PathBuf::from("/opt/sup"),
                cli_bin: PathBuf::from("/opt/cli"),
                systemd_run: PathBuf::from("/usr/bin/systemd-run"),
                work_dir: None,
                output: None,
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn explicit_values_are_parsed() {
        let got = parse_args(&a(&[
            "--supervisor-bin",
            "/opt/sup",
            "--cli-bin",
            "/opt/cli",
            "--trials",
            "20",
            "--warmup",
            "0",
            "--timeout-secs",
            "60",
            "--output",
            "/o/r.json",
        ]))
        .expect("plan");
        let Command::Measure(p) = got else {
            panic!("expected Measure");
        };
        assert_eq!((p.trials, p.warmup, p.timeout_secs), (20, 0, 60));
        assert_eq!(p.output, Some(PathBuf::from("/o/r.json")));
    }

    #[test]
    fn out_of_range_values_are_rejected() {
        for bad_args in [
            &["--trials", "19"][..],
            &["--trials", "201"],
            &["--warmup", "21"],
            &["--timeout-secs", "59"],
            &["--timeout-secs", "7201"],
            &["--trials", "x"],
        ] {
            assert_eq!(code(bad_args), "invalid-args", "{bad_args:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn malformed_options_are_rejected() {
        assert_eq!(code(&["--unknown"]), "invalid-args");
        assert_eq!(code(&["--supervisor-bin"]), "invalid-args");
        assert_eq!(code(&["--supervisor-bin", "rel/sup"]), "invalid-args");
        assert_eq!(
            code(&["--supervisor-bin", "/a", "--supervisor-bin", "/b"]),
            "invalid-args"
        );
        // 計測には --supervisor-bin と --cli-bin が必須（PATH からは探さない。OCI-6）。
        assert_eq!(code(&["--trials", "20"]), "invalid-args");
        assert_eq!(code(&["--supervisor-bin", "/opt/sup"]), "invalid-args");
        assert_eq!(code(&["--cli-bin", "rel/cli"]), "invalid-args");
        assert_eq!(
            code(&["--cli-bin", "/a", "--cli-bin", "/b"]),
            "invalid-args"
        );
    }
}
