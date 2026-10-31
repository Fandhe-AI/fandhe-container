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
//! `fandhe-container-compose-convert [--downgrade=<key>[,...]] [--] <input_dir>`。`-h` / `--help` は usage を出して終了コード 0。
//! `--downgrade=` の値は [`crate::downgrade::parse_downgrade_value`] で解析し、`error-unsupported-yet` 以外のキー・
//! 空の要素・上限超過は、ディレクトリへ触れる前に `INVALID_ARGUMENT`（2）で止める（TASK-182.1・#627・STACK-3）。
//! `=` のない `--downgrade`・繰り返し・UTF-8 でない値も 2。位置引数が 1 個でない・未知のフラグも 2。
//! 引数の値は出力に入れない（拒否の詳細は分類名・表の固定のキーパス・番号だけ）。
//!
//! 拒否時の出力（TASK-182.2・#628・STACK-3。実バイナリの試験 `tests/bin_entry.rs` で全文一致を固定）は
//! 1 行の JSON で、順に `code`（`INVALID_ARGUMENT`）・`message`（`--downgrade key is not error-unsupported-yet`）・
//! `class`（`convert` / `warning` / `error-incompatible` / `unrecognized`）・`key_path`（表の行と完全一致したときだけ。
//! `x-*` の warning と unrecognized では出さない）・`index`（0 起算の要素番号。文字列）。拒否が複数あるときは
//! 最初の 1 件だけを出す。優先順位は `-h` / `--help`（0）、未知のフラグ・位置引数の誤り（2）、`--downgrade` の値の検査（2）、
//! ディレクトリの走査（3・6・10 など）の順。空の値・空の要素・上限超過も 2 で `class` / `key_path` は持たない。
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
//! TOML の書き出し（stdout は空けたまま。集計行に `toml_output:"unimplemented"`）。

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::compose_convert::parse_compose_yaml;
use crate::convert::{ValueDrops, convert_top_level};
use crate::downgrade::{DowngradeArgError, DowngradeSet, parse_downgrade_value};
use crate::input_scan::load_input_dir;
use crate::key_scan::collect_key_occurrences;
use crate::report::FileConversionReport;
use crate::report_json::{error_line, file_line, summary_line};

/// 引数の誤りの usage（値は含めない）。
const USAGE: &str =
    "usage: fandhe-container-compose-convert [--downgrade=<key>[,...]] [--] <input_dir>";

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
    DowngradeRejected(DowngradeArgError),
    Run {
        dir: PathBuf,
        downgrade: Option<DowngradeSet>,
    },
}

fn parse_args(args: &[OsString]) -> Parsed {
    let (mut help, mut unknown, mut after_dd) = (false, false, false);
    let mut downgrade_value: Option<&str> = None;
    let mut positional: Vec<&OsString> = Vec::new();
    for arg in args {
        let bytes = arg.as_encoded_bytes();
        if after_dd || bytes.first() != Some(&b'-') {
            positional.push(arg);
        } else if bytes == b"--" {
            after_dd = true;
        } else if bytes == b"-h" || bytes == b"--help" {
            help = true;
        } else if let Some(v) = bytes.strip_prefix(b"--downgrade=") {
            // 値は UTF-8 のみ。繰り返しは後勝ちにせず拒否する（fail-closed）。
            match std::str::from_utf8(v) {
                Ok(v) if downgrade_value.is_none() => downgrade_value = Some(v),
                _ => unknown = true,
            }
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
    let downgrade = match downgrade_value.map(parse_downgrade_value) {
        Some(Ok(set)) => Some(set),
        Some(Err(e)) => return Parsed::DowngradeRejected(e),
        None => None,
    };
    match positional.first() {
        Some(p) => Parsed::Run {
            dir: PathBuf::from(p),
            downgrade,
        },
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
        Parsed::DowngradeRejected(e) => {
            let index = match e {
                DowngradeArgError::EmptyItem { index }
                | DowngradeArgError::KeyTooLong { index }
                | DowngradeArgError::NotDowngradable { index, .. } => Some(index.to_string()),
                _ => None,
            };
            let mut extra: Vec<(&str, &str)> = Vec::new();
            if let DowngradeArgError::NotDowngradable {
                class, key_path, ..
            } = &e
            {
                extra.push(("class", class.as_str()));
                if let Some(p) = key_path {
                    extra.push(("key_path", p));
                }
            }
            if let Some(i) = index.as_deref() {
                extra.push(("index", i));
            }
            Outcome {
                exit_code: 2,
                stderr: error_line(e.code(), e.message(), &extra),
            }
        }
        Parsed::Run { dir, downgrade } => run_dir(&dir, downgrade.as_ref()),
    }
}

fn run_dir(dir: &Path, downgrade: Option<&DowngradeSet>) -> Outcome {
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
    let (mut error_free_files, mut parse_failed_files, mut downgrade_free_files) =
        (0u64, 0u64, 0u64);
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
        let dg = downgrade.map(|set| {
            (
                report.downgraded(set),
                report.error_free_with_downgrade(set),
            )
        });
        if dg.as_ref().is_some_and(|(_, v)| v.is_error_free()) {
            downgrade_free_files += 1;
        }
        out.push_str(&file_line(
            id,
            &report,
            &verdict,
            dg.as_ref().map(|(d, v)| (d.as_slice(), v)),
        ));
    }
    out.push_str(&summary_line(
        inputs.len() as u64,
        error_free_files,
        downgrade.map(|_| downgrade_free_files),
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

    fn run_plain(dir: &str) -> Parsed {
        Parsed::Run {
            dir: PathBuf::from(dir),
            downgrade: None,
        }
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
        assert_eq!(parse_args(&os(&["--", "-h"])), run_plain("-h"));
        assert_eq!(parse_args(&os(&["d"])), run_plain("d"));
        assert_eq!(parse_args(&os(&["--", "d"])), run_plain("d"));
        assert_eq!(parse_args(&os(&["--downgrade"])), Parsed::Invalid);
        assert_eq!(parse_args(&os(&["--downgrade", "d"])), Parsed::Invalid);
        assert_eq!(parse_args(&os(&["--downgradex", "d"])), Parsed::Invalid);
    }

    /// STACK-3・TASK-182.1: --downgrade の受理・拒否・繰り返しの拒否。
    #[test]
    fn parse_args_downgrade() {
        match parse_args(&os(&["--downgrade=services.*.tty, services.*.user", "d"])) {
            Parsed::Run { dir, downgrade } => {
                assert_eq!(dir, PathBuf::from("d"));
                let set = downgrade.expect("set");
                assert_eq!(
                    set.iter().collect::<Vec<_>>(),
                    vec!["services.*.tty", "services.*.user"]
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse_args(&os(&["--downgrade=services.*.privileged", "d"])),
            Parsed::DowngradeRejected(DowngradeArgError::NotDowngradable { .. })
        ));
        assert_eq!(
            parse_args(&os(&["--downgrade=", "d"])),
            Parsed::DowngradeRejected(DowngradeArgError::Empty)
        );
        let twice = [
            "--downgrade=services.*.tty",
            "--downgrade=services.*.user",
            "d",
        ];
        assert_eq!(parse_args(&os(&twice)), Parsed::Invalid);
        // 位置引数の誤りは downgrade の解析より先に Invalid。
        assert_eq!(
            parse_args(&os(&["--downgrade=services.*.privileged"])),
            Parsed::Invalid
        );
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

    /// STACK-3・TASK-182.1: 不可のキーは 2 で止め、詳細は分類名・表のキーパス・番号だけ。
    #[test]
    fn downgrade_rejection_output() {
        let o = run_args(&os(&[
            "--downgrade=services.*.tty,services.*.privileged",
            "/nonexistent-dir-secret-marker",
        ]));
        assert_eq!(o.exit_code, 2);
        assert_eq!(
            o.stderr,
            "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"--downgrade key is not error-unsupported-yet\",\"class\":\"error-incompatible\",\"key_path\":\"services.*.privileged\",\"index\":\"1\"}\n"
        );
        let o = run_args(&os(&["--downgrade=secret-marker", "d"]));
        assert_eq!(o.exit_code, 2);
        assert!(!o.stderr.contains("secret-marker"));
        assert!(o.stderr.contains("\"class\":\"unrecognized\""));
        assert!(!o.stderr.contains("key_path"));
    }

    /// STACK-3・TASK-182.2: 4 分類すべてが 2 で、`key_path` は表の行と完全一致のときだけ出る。`--help` が優先。
    #[test]
    fn downgrade_rejection_all_classes() {
        let head = "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"--downgrade key is not error-unsupported-yet\"";
        for (key, tail) in [
            (
                "services.*.image",
                ",\"class\":\"convert\",\"key_path\":\"services.*.image\",\"index\":\"0\"}\n",
            ),
            (
                "version",
                ",\"class\":\"warning\",\"key_path\":\"version\",\"index\":\"0\"}\n",
            ),
            ("x-common", ",\"class\":\"warning\",\"index\":\"0\"}\n"),
        ] {
            let o = run_args(&os(&[&format!("--downgrade={key}"), "d"]));
            assert_eq!(o.exit_code, 2, "{key}");
            assert_eq!(o.stderr, format!("{head}{tail}"), "{key}");
        }
        // -h / --help は不可キーの検査より先（usage で 0）。
        let o = run_args(&os(&["--downgrade=services.*.privileged", "--help"]));
        assert_eq!(o.exit_code, 0);
        assert_eq!(o.stderr, format!("{USAGE}\n"));
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
