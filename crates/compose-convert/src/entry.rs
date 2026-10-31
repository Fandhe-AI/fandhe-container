//! bin の本体: 引数解析・ファイルごとの処理・終了コードの決定（TASK-151.7・#602・STACK-3・MS-12）。
//!
//! 役割: `main.rs` → [`crate::run`] から呼ばれ、入力ディレクトリの全ファイルを
//! [`crate::input_scan::load_input_dir`] → [`crate::compose_convert::parse_compose_yaml`] →
//! [`crate::key_scan::collect_key_occurrences`] ＋ [`crate::convert::convert_top_level`] →
//! [`crate::report::FileConversionReport`] の順に処理し、[`crate::report_json`] で 1 行 JSON にして
//! stderr 用の文字列として返す。純粋に文字列を組み立てるだけで、書き込みは [`crate::run`] が期限つきで行う。
//!
//! # 引数
//!
//! `fandhe-container-compose-convert [--] <input_dir>`。`-h` / `--help` は usage を出して終了コード 0。
//! `--downgrade[=...]` は TASK-182（#627）で実装するまで `UNIMPLEMENTED`（8）で拒否し、黙って受け入れない（REPAIR-3）。
//! 位置引数が 1 個でない・未知のフラグは `INVALID_ARGUMENT`（2）。引数の値は出力に入れない。
//!
//! # 終了コード
//!
//! レポートを出し終えたら 0。`error_free` でないファイルがあっても 0 とする（PoC-16 と同じ）。分類の結果は
//! レポートの `error_free` で判断する。spec（STACK-3）は走査エラーの非 0 と `--downgrade` の不可キーでの 2 以外を
//! 定めていないため、この判断を試験で固定する。入力の走査エラーは [`crate::input_scan::ComposeInputErrorCode::exit_code`]、
//! 同じ `file_id`（`compose.yml` と `compose.yaml` の共存）は変換せず 2。
//!
//! # 未実装（REPAIR-3）
//!
//! TOML の書き出し（stdout は空けたまま。集計行に `toml_output:"unimplemented"`）、`--downgrade`。

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::compose_convert::parse_compose_yaml;
use crate::convert::{ValueDrops, convert_top_level};
use crate::input_scan::load_input_dir;
use crate::key_scan::collect_key_occurrences;
use crate::report::FileConversionReport;
use crate::report_json::{error_line, file_line, summary_line};

/// 引数の誤りの usage（値は含めない）。
const USAGE: &str = "usage: fandhe-container-compose-convert [--] <input_dir>";

/// 未実装の終了コード（ERR-2 の慣行で 8）。
pub const UNIMPLEMENTED_EXIT_CODE: u8 = 8;

/// 実行結果。`stderr` は書き出す全文（末尾改行つき）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// 終了コード。
    pub exit_code: u8,
    /// stderr に出す文字列。
    pub stderr: String,
}

#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    Help,
    Invalid,
    Downgrade,
    Run(PathBuf),
}

fn parse_args(args: &[OsString]) -> Parsed {
    let (mut help, mut unknown, mut downgrade, mut after_dd) = (false, false, false, false);
    let mut positional: Vec<&OsString> = Vec::new();
    for arg in args {
        let bytes = arg.as_encoded_bytes();
        if after_dd || bytes.first() != Some(&b'-') {
            positional.push(arg);
        } else if bytes == b"--" {
            after_dd = true;
        } else if bytes == b"-h" || bytes == b"--help" {
            help = true;
        } else if bytes == b"--downgrade" || bytes.starts_with(b"--downgrade=") {
            downgrade = true;
        } else {
            unknown = true;
        }
    }
    if help {
        return Parsed::Help;
    }
    if unknown || positional.len() != 1 {
        return Parsed::Invalid;
    }
    if downgrade {
        return Parsed::Downgrade;
    }
    match positional.first() {
        Some(p) => Parsed::Run(PathBuf::from(p)),
        None => Parsed::Invalid,
    }
}

/// `file_id` を導出する（`file_stem` → `file_name` → 固定値）。
fn file_id_of(path: &Path) -> String {
    path.file_stem()
        .or_else(|| path.file_name())
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string())
}

/// 引数列（プログラム名を除く）を処理して結果を返す。
pub fn run_args(args: &[OsString]) -> Outcome {
    match parse_args(args) {
        Parsed::Help => Outcome {
            exit_code: 0,
            stderr: format!("{USAGE}\n"),
        },
        Parsed::Invalid => Outcome {
            exit_code: 2,
            stderr: error_line("INVALID_ARGUMENT", USAGE, &[]),
        },
        Parsed::Downgrade => Outcome {
            exit_code: UNIMPLEMENTED_EXIT_CODE,
            stderr: error_line("UNIMPLEMENTED", "--downgrade is not implemented yet", &[]),
        },
        Parsed::Run(dir) => run_dir(&dir),
    }
}

fn run_dir(dir: &Path) -> Outcome {
    let inputs = match load_input_dir(dir) {
        Ok(v) => v,
        Err(e) => {
            let path = e.path.as_deref().map(|p| p.to_string_lossy().into_owned());
            let extra: Vec<(&str, &str)> =
                path.as_deref().map(|p| ("path", p)).into_iter().collect();
            return Outcome {
                exit_code: e.exit_code().get(),
                stderr: error_line(e.code.as_str(), e.message, &extra),
            };
        }
    };

    // 同じ file_id が複数あれば出力名が衝突するため、変換せず止める（fail-closed）。
    let ids: Vec<String> = inputs.iter().map(|i| file_id_of(i.path())).collect();
    let mut seen = BTreeSet::new();
    for id in &ids {
        if !seen.insert(id.as_str()) {
            return Outcome {
                exit_code: 2,
                stderr: error_line(
                    "INVALID_ARGUMENT",
                    "duplicate file_id in input directory",
                    &[("file_id", id)],
                ),
            };
        }
    }

    let mut out = String::new();
    let (mut error_free_files, mut parse_failed_files) = (0u64, 0u64);
    for (input, id) in inputs.iter().zip(&ids) {
        let report = match parse_compose_yaml(input.text()) {
            Err(e) => FileConversionReport::parse_failed(e.code),
            Ok(doc) => {
                let occ = collect_key_occurrences(&doc);
                let mut drops = ValueDrops::new();
                // TOML の書き出しは未実装（REPAIR-3）。value_drops を集めるために変換だけ行う。
                let _toml = convert_top_level(&doc, &mut drops);
                FileConversionReport::from_parsed(occ, drops)
            }
        };
        let verdict = report.error_free();
        if report.parse_error.is_some() {
            parse_failed_files += 1;
        }
        if verdict.is_error_free() {
            error_free_files += 1;
        }
        out.push_str(&file_line(id, &report, &verdict));
    }
    out.push_str(&summary_line(
        inputs.len() as u64,
        error_free_files,
        parse_failed_files,
    ));
    Outcome {
        exit_code: 0,
        stderr: out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    /// STACK-3・REPAIR-12: 引数解析の各分岐。
    #[test]
    fn parse_args_branches() {
        assert_eq!(parse_args(&os(&[])), Parsed::Invalid);
        assert_eq!(parse_args(&os(&["a", "b"])), Parsed::Invalid);
        assert_eq!(parse_args(&os(&["--bogus", "a"])), Parsed::Invalid);
        assert_eq!(parse_args(&os(&["-"])), Parsed::Invalid);
        assert_eq!(parse_args(&os(&["--help"])), Parsed::Help);
        assert_eq!(parse_args(&os(&["-h", "--bogus"])), Parsed::Help);
        assert_eq!(
            parse_args(&os(&["--", "-h"])),
            Parsed::Run(PathBuf::from("-h"))
        );
        assert_eq!(parse_args(&os(&["d"])), Parsed::Run(PathBuf::from("d")));
        assert_eq!(
            parse_args(&os(&["--", "d"])),
            Parsed::Run(PathBuf::from("d"))
        );
        assert_eq!(parse_args(&os(&["--downgrade", "d"])), Parsed::Downgrade);
        assert_eq!(parse_args(&os(&["--downgrade=x", "d"])), Parsed::Downgrade);
        assert_eq!(parse_args(&os(&["--downgrade"])), Parsed::Invalid);
        assert_eq!(parse_args(&os(&["--downgradex", "d"])), Parsed::Invalid);
    }

    /// STACK-3: 誤り時の出力に引数の値を入れない。
    #[test]
    fn invalid_args_do_not_echo_values() {
        let o = run_args(&os(&["--bogus=secret-marker"]));
        assert_eq!(o.exit_code, 2);
        assert!(!o.stderr.contains("secret-marker"));
        assert_eq!(
            o.stderr,
            format!("{{\"code\":\"INVALID_ARGUMENT\",\"message\":\"{USAGE}\"}}\n")
        );
    }

    /// STACK-3・REPAIR-3: --downgrade は未実装として 8 で拒否する。
    #[test]
    fn downgrade_is_unimplemented() {
        let o = run_args(&os(&["--downgrade=services.*.tty", "d"]));
        assert_eq!(o.exit_code, 8);
        assert_eq!(
            o.stderr,
            "{\"code\":\"UNIMPLEMENTED\",\"message\":\"--downgrade is not implemented yet\"}\n"
        );
    }

    /// STACK-3: file_id の導出とフォールバック。
    #[test]
    fn file_id_derivation() {
        assert_eq!(file_id_of(Path::new("/d/compose.yaml")), "compose");
        assert_eq!(file_id_of(Path::new("/d/a.b.yml")), "a.b");
        assert_eq!(file_id_of(Path::new("/d/.yml")), ".yml");
        assert_eq!(file_id_of(Path::new("/")), "unknown");
    }
}
