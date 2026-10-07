//! TASK-164.2（#506）・SUP-7: 実パイプ経由の捕捉をローテーション sink へ流し、世代切り替え後も
//! 全ファイルが上限以内であることを公開 API だけで照合する結合試験（root 不要・3 OS で実行）。
//!
//! TASK-164.4（#508）・SUP-7: 100 万行を流してローテーションさせ、読み戻して欠落 0・重複 0 を
//! 連番照合する試験を追加した（stdout 単独。stdout / stderr 混在の大規模検証は対象外）。

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fandhe_container_core::traits::ContainerId;
use fandhe_container_supervisor::logs::rotating::MIN_LOG_FILE_BYTES;
use fandhe_container_supervisor::logs::{
    LogCapture, MAX_DRAIN_TIMEOUT, OutputStreams, ReaderBudget, RotatingFileSink, RotationConfig,
};

struct TmpDir(PathBuf);

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// SUP-7: 複数回ローテーションしても全ファイルが上限以内で、捕捉側にエラーが出ない。
#[test]
fn sup7_task164_2_pipe_capture_rotates_within_limit() {
    let dir = std::env::temp_dir().join(format!("fc-sup7-it-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let _guard = TmpDir(dir.clone());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let cfg = RotationConfig::new(MIN_LOG_FILE_BYTES, 3).unwrap();
    let sink =
        Arc::new(RotatingFileSink::open(&dir, &ContainerId::new("it1").unwrap(), cfg).unwrap());

    let (out_r, mut out_w) = std::io::pipe().unwrap();
    let cap = LogCapture::start(
        OutputStreams::new(&ReaderBudget::with_max_limit(), Some(Box::new(out_r)), None),
        sink.clone(),
    )
    .unwrap();
    let line = format!("{}\n", "a".repeat(999));
    for _ in 0..500 {
        out_w.write_all(line.as_bytes()).unwrap();
    }
    drop(out_w);
    let summary = cap.drain(Duration::from_secs(10)).unwrap();
    assert_eq!(summary.stdout().and_then(|s| s.error_code()), None);

    assert_eq!(sink.rotations().unwrap(), 7);
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    // ログ 3 世代と、同一 ID の排他に使う空のロックファイルだけがある。
    assert_eq!(names, ["it1.log", "it1.log.1", "it1.log.2", "it1.log.lock"]);
    assert_eq!(fs::metadata(dir.join("it1.log.lock")).unwrap().len(), 0);
    // 500 行 × 1007 バイト（"stdout " 7 + 999 + LF 1）。1 ファイルは 65 行（65,455 バイト）で、
    // 7 回のローテーション後は現在ログに 45 行が残る。保持中の合計は上限 × 世代数以内。
    let lens: Vec<u64> = ["it1.log", "it1.log.1", "it1.log.2"]
        .iter()
        .map(|n| fs::metadata(dir.join(n)).unwrap().len())
        .collect();
    assert_eq!(lens, [45 * 1007, 65 * 1007, 65 * 1007]);
    assert!(lens.iter().all(|l| *l <= cfg.max_file_bytes()));
    assert!(lens.iter().sum::<u64>() <= cfg.max_file_bytes() * u64::from(cfg.generations()));
}

// ---- TASK-164.4（#508）・SUP-7: 100 万行規模の欠落 0・重複 0 照合 ----

const TOTAL_LINES: u64 = 1_000_000;
/// レコードは "stdout " 7 + 7 桁連番 + LF 1 = 15 バイト固定。
const RECORD_BYTES: u64 = 15;
/// 上限 1MiB に入る最大レコード数（1,048,576 / 15 = 69,905 余り 1）。
const LINES_PER_FILE: u64 = 69_905;
/// 100 万行の書き込みで起きるローテーション回数（floor(1,000,000 / 69,905) = 14）。
const EXPECTED_ROTATIONS: u64 = 14;
/// 現在ログに残る行数（1,000,000 - 14 * 69,905 = 21,330）。
const CURRENT_LINES: u64 = TOTAL_LINES - EXPECTED_ROTATIONS * LINES_PER_FILE;

/// 連番検査器: 期待値より大きければ欠落、小さければ重複として数える。
#[derive(Default)]
struct SeqCheck {
    next: Option<u64>,
    lines: u64,
    missing: u64,
    duplicates: u64,
    first_anomaly: Option<String>,
}

impl SeqCheck {
    fn push(&mut self, v: u64) {
        let expect = *self.next.get_or_insert(v);
        if v > expect {
            self.missing += v - expect;
            self.first_anomaly
                .get_or_insert_with(|| format!("gap: expected {expect} got {v}"));
        } else if v < expect {
            self.duplicates += 1;
            self.first_anomaly
                .get_or_insert_with(|| format!("duplicate: expected {expect} got {v}"));
        }
        if v >= expect {
            self.next = Some(v + 1);
        }
        self.lines += 1;
    }

    /// ファイル 1 つぶんのバイト列を検査する。LF 終端・15 バイト固定形式を要求する。
    fn push_file(&mut self, bytes: &[u8]) {
        assert_eq!(bytes.last(), Some(&b'\n'), "file must end with LF");
        for rec in bytes.split_inclusive(|b| *b == b'\n') {
            assert_eq!(rec.len() as u64, RECORD_BYTES, "bad record length");
            let text = std::str::from_utf8(rec).unwrap();
            let digits = text
                .strip_prefix("stdout ")
                .and_then(|r| r.strip_suffix('\n'))
                .unwrap_or_else(|| panic!("bad record: {text:?}"));
            assert!(
                digits.bytes().all(|b| b.is_ascii_digit()),
                "bad record: {text:?}"
            );
            self.push(digits.parse().unwrap());
        }
    }
}

#[test]
fn sup7_task164_4_sequence_checker_detects_gap_and_duplicate() {
    let mut gap = SeqCheck::default();
    for v in [0, 1, 3] {
        gap.push(v);
    }
    assert_eq!((gap.lines, gap.missing, gap.duplicates), (3, 1, 0));
    let mut dup = SeqCheck::default();
    for v in [0, 1, 1, 2] {
        dup.push(v);
    }
    assert_eq!((dup.lines, dup.missing, dup.duplicates), (4, 0, 1));
}

/// 100 万行を実パイプ → LogCapture → RotatingFileSink へ流し、世代を古い順に読み戻して照合する。
/// `names_oldest_first` は古い順の世代ファイル名、`start` は保持範囲の先頭の連番。
fn run_million(tag: &str, cfg: RotationConfig, names_oldest_first: &[&str], start: u64) {
    let dir = std::env::temp_dir().join(format!("fc-sup7-1m-{tag}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let _guard = TmpDir(dir.clone());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let sink =
        Arc::new(RotatingFileSink::open(&dir, &ContainerId::new("m1").unwrap(), cfg).unwrap());
    let (out_r, mut out_w) = std::io::pipe().unwrap();
    let cap = LogCapture::start(
        OutputStreams::new(&ReaderBudget::with_max_limit(), Some(Box::new(out_r)), None),
        sink.clone(),
    )
    .unwrap();
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        let mut buf = String::with_capacity(70_000);
        for i in 0..TOTAL_LINES {
            buf.push_str(&format!("{i:07}\n"));
            if buf.len() >= 64 * 1024 {
                out_w.write_all(buf.as_bytes())?;
                buf.clear();
            }
        }
        out_w.write_all(buf.as_bytes())
    });
    let summary = cap.drain(MAX_DRAIN_TIMEOUT).unwrap();
    writer.join().unwrap().unwrap();
    let out = summary.stdout().unwrap();
    assert_eq!(out.lines(), TOTAL_LINES);
    assert_eq!(out.bytes(), TOTAL_LINES * 8);
    assert_eq!(out.truncated_lines(), 0);
    assert_eq!(out.discarded_lines(), 0);
    assert_eq!(out.error_code(), None);
    assert_eq!(sink.rotations().unwrap(), EXPECTED_ROTATIONS);
    drop(sink);

    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let mut want: Vec<String> = names_oldest_first.iter().map(|n| n.to_string()).collect();
    want.push("m1.log.lock".to_string());
    want.sort();
    assert_eq!(names, want);
    assert_eq!(fs::metadata(dir.join("m1.log.lock")).unwrap().len(), 0);

    let mut chk = SeqCheck::default();
    for (i, n) in names_oldest_first.iter().enumerate() {
        let bytes = fs::read(dir.join(n)).unwrap();
        let is_current = i + 1 == names_oldest_first.len();
        let lines = if is_current {
            CURRENT_LINES
        } else {
            LINES_PER_FILE
        };
        assert_eq!(bytes.len() as u64, lines * RECORD_BYTES, "{n}");
        assert!(bytes.len() as u64 <= cfg.max_file_bytes());
        chk.push_file(&bytes);
    }
    let retained = (names_oldest_first.len() as u64 - 1) * LINES_PER_FILE + CURRENT_LINES;
    assert_eq!(chk.first_anomaly, None);
    assert_eq!(chk.missing, 0);
    assert_eq!(chk.duplicates, 0);
    assert_eq!(chk.lines, retained);
    assert_eq!(TOTAL_LINES - retained, start);
    assert_eq!(chk.next, Some(TOTAL_LINES));
}

/// SUP-7: 1MiB × 16 世代なら 100 万行すべてが保持され、欠落 0・重複 0 で 0..=999999 が連続する。
#[test]
fn sup7_task164_4_million_lines_all_retained_no_loss_no_duplicate() {
    let cfg = RotationConfig::new(1024 * 1024, 16).unwrap();
    let mut names: Vec<String> = (1..=EXPECTED_ROTATIONS)
        .rev()
        .map(|g| format!("m1.log.{g}"))
        .collect();
    names.push("m1.log".to_string());
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    run_million("all", cfg, &refs, 0);
}

/// SUP-7（PoC-17 と同形）: 既定の 1MiB × 3 世代では古い世代が押し出され、保持範囲
/// 838,860..=999,999（161,140 行）が欠落・重複なく連続し、末尾が最終行である。
#[test]
fn sup7_task164_4_million_lines_default_rotation_retained_range_is_contiguous() {
    let cfg = RotationConfig::default();
    run_million("def", cfg, &["m1.log.2", "m1.log.1", "m1.log"], 838_860);
}
