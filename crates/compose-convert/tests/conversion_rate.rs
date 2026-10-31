//! 出現数ベースの変換可率の結合試験（TASK-152.2・#606・STACK-4・REPAIR-12）。
//!
//! 合成フィクスチャ `tests/fixtures/conversion_rate.yaml` を、ライブラリ経路と実バイナリの両方で処理し、
//! 分子・分母・率・判定を具体値で照合する。実コーパスでの実測と 80% の判断は #607（人間担当）。
//!
//! フィクスチャのキーパス別の記録（手で数えた内訳）:
//! `services`(convert 1)・`services.*`(convert 2)・`services.*.image`(convert 2)・`services.*.ports`(convert 1)・
//! `services.*.hostname`(error-unsupported-yet 1)・`services.*.privileged`(error-incompatible 1)・`version`(warning 1)。
//! convert 6 / 全体 9 = 66.66%（warning は分母に入り分子に入らない）。
//! 子プロセスの待ちには期限を付ける（REPAIR-5）。

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use fandhe_container_compose_convert::classify::KeyClass;
use fandhe_container_compose_convert::compose_convert::parse_compose_yaml;
use fandhe_container_compose_convert::conversion_rate::{ConversionRateTally, ThresholdVerdict};
use fandhe_container_compose_convert::convert::{ValueDrops, convert_top_level};
use fandhe_container_compose_convert::key_scan::collect_key_occurrences;
use fandhe_container_compose_convert::report::FileConversionReport;

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-compose-convert");
const FIXTURE: &str = include_str!("fixtures/conversion_rate.yaml");

static SEQ: AtomicU32 = AtomicU32::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("fc-conv-rate-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).expect("create scratch");
        Self(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn report_of(text: &str) -> FileConversionReport {
    let doc = parse_compose_yaml(text).expect("parse");
    let occ = collect_key_occurrences(&doc);
    let mut drops = ValueDrops::new();
    let _toml = convert_top_level(&doc, &mut drops);
    FileConversionReport::from_parsed(occ, drops)
}

/// STACK-4: ライブラリ経路。記録の内訳と分子・分母・率を具体値で照合する。
#[test]
fn library_path_counts_fixture() {
    let r = report_of(FIXTURE);
    let occ = |p: &str| r.key_occurrences.get(p).map(|e| (e.class, e.occurrences));
    assert_eq!(occ("services"), Some((KeyClass::Convert, 1)));
    assert_eq!(occ("services.*"), Some((KeyClass::Convert, 2)));
    assert_eq!(occ("services.*.image"), Some((KeyClass::Convert, 2)));
    assert_eq!(occ("services.*.ports"), Some((KeyClass::Convert, 1)));
    assert_eq!(
        occ("services.*.hostname"),
        Some((KeyClass::ErrorUnsupportedYet, 1))
    );
    assert_eq!(
        occ("services.*.privileged"),
        Some((KeyClass::ErrorIncompatible, 1))
    );
    assert_eq!(occ("version"), Some((KeyClass::Warning, 1)));

    let mut t = ConversionRateTally::new();
    t.add(&r);
    let out = t.finish();
    assert_eq!((out.convert, out.warning, out.total), (6, 1, 9));
    assert_eq!(out.rate_basis_points, Some(6666));
    assert_eq!(out.verdict, ThresholdVerdict::Below);
    assert!(out.indeterminate_reasons.is_empty());
}

/// STACK-4: 実バイナリの `summary` 行の `conversion_rate` を全文一致で照合する。終了コードは 0。
#[test]
fn binary_summary_reports_conversion_rate() {
    let s = Scratch::new();
    std::fs::write(s.0.join("conversion_rate.yaml"), FIXTURE).expect("write fixture");
    let mut child = Command::new(BIN)
        .arg(&s.0)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut stderr = child.stderr.take().expect("stderr");
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        buf
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            break st;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("binary did not exit within 30s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let err = reader.join().expect("reader");
    assert_eq!(status.code(), Some(0), "{err}");
    let summary = err.lines().last().expect("summary line");
    let tail = summary
        .split("\"toml_output\":\"unimplemented\",")
        .nth(1)
        .expect("conversion_rate tail");
    assert_eq!(
        tail,
        "\"conversion_rate\":{\"basis\":\"occurrences-excluding-warning\",\"convert_occurrences\":6,\"warning_occurrences\":1,\"error_incompatible_occurrences\":1,\"error_unsupported_yet_occurrences\":1,\"unrecognized_occurrences\":0,\"total_occurrences\":9,\"rate_percent\":\"66.66\",\"threshold_percent\":80,\"verdict\":\"below\",\"lower_bound_convert_occurrences\":6,\"lower_bound_rate_percent\":\"66.66\",\"lower_bound_verdict\":\"below\",\"indeterminate_reasons\":[]}}"
    );
    for marker in ["example/web", "host-a", "web", "worker"] {
        assert!(!summary.contains(marker), "{marker} leaked: {summary}");
    }
}
