//! 実バイナリの結合試験（TASK-151.7・#602・STACK-3・REPAIR-12）。
//! 子プロセスの待ちには期限を付ける（REPAIR-5）。一時ディレクトリは pid と連番で作り、成否にかかわらず消す。

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-compose-convert");

static SEQ: AtomicU32 = AtomicU32::new(0);

/// drop で消える一時ディレクトリ。
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("fc-compose-convert-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).expect("create scratch");
        Self(p)
    }

    fn write(&self, name: &str, text: &str) {
        std::fs::write(self.0.join(name), text).expect("write fixture");
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&std::ffi::OsStr]) -> (Option<i32>, String, String) {
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("compose-convert did not exit within 30s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let (mut out, mut err) = (String::new(), String::new());
    child
        .stdout
        .take()
        .expect("stdout")
        .read_to_string(&mut out)
        .expect("read stdout");
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut err)
        .expect("read stderr");
    (status.code(), out, err)
}

fn run_strs(args: &[&str]) -> (Option<i32>, String, String) {
    let os: Vec<&std::ffi::OsStr> = args.iter().map(std::ffi::OsStr::new).collect();
    run(&os)
}

fn run_dir(dir: &Path) -> (Option<i32>, String, String) {
    run(&[dir.as_os_str()])
}

/// STACK-3: 正常系。file 2 行 + 集計 1 行、stdout は空、値・名前は出力に出ない。
#[test]
fn report_lines_for_mixed_directory() {
    let s = Scratch::new();
    s.write(
        "a.yaml",
        "services:\n  web:\n    image: busybox\n    privileged: true\n    environment:\n      SECRET: value-marker-9c1d\n",
    );
    s.write("b.yml", "services: [unclosed\n");
    let (code, out, err) = run_dir(s.path());
    assert_eq!(code, Some(0));
    assert_eq!(out, "");
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(lines.len(), 3, "{err}");
    assert!(lines[0].starts_with("{\"kind\":\"file\",\"file_id\":\"a\","));
    assert!(lines[0].contains("\"error-incompatible\":{\"keys\":1,\"occurrences\":1}"));
    assert!(lines[0].contains("\"error_free\":false"));
    assert!(
        lines[1].starts_with(
            "{\"kind\":\"file\",\"file_id\":\"b\",\"parse_error\":\"INVALID_ARGUMENT\""
        )
    );
    assert_eq!(
        lines[2],
        "{\"kind\":\"summary\",\"files\":2,\"error_free_files\":0,\"error_free_with_downgrade_files\":null,\"parse_failed_files\":1,\"toml_output\":\"unimplemented\",\"conversion_rate\":{\"basis\":\"occurrences-excluding-warning\",\"convert_occurrences\":4,\"warning_occurrences\":0,\"error_incompatible_occurrences\":1,\"error_unsupported_yet_occurrences\":0,\"unrecognized_occurrences\":0,\"total_occurrences\":5,\"rate_percent\":\"80.00\",\"threshold_percent\":80,\"verdict\":\"indeterminate\",\"lower_bound_convert_occurrences\":4,\"lower_bound_rate_percent\":\"80.00\",\"lower_bound_verdict\":\"indeterminate\",\"indeterminate_reasons\":[\"parse-failed-files\"]}}"
    );
    for marker in ["value-marker-9c1d", "SECRET", "web"] {
        assert!(!err.contains(marker), "{marker} leaked: {err}");
    }
    assert!(err.is_ascii());
}

/// STACK-7: build: を含むファイルは終了コード 0 のまま、案内つきの blocker が出る。値は漏れない。
#[test]
fn build_key_reports_guidance() {
    let s = Scratch::new();
    s.write(
        "a.yaml",
        "services:\n  svcmarker:\n    build: ./ctx-marker\n",
    );
    let (code, out, err) = run_dir(s.path());
    assert_eq!(code, Some(0));
    assert_eq!(out, "");
    assert!(err.contains("\"error_free\":false"), "{err}");
    assert!(
        err.contains("\"guidance\":{\"code\":\"external-build\",\"message\":\""),
        "{err}"
    );
    for marker in ["ctx-marker", "svcmarker"] {
        assert!(!err.contains(marker), "{marker} leaked: {err}");
    }
    assert!(err.is_ascii());
}

/// STACK-3: 問題のないファイルは error_free: true で blocker が空。
#[test]
fn clean_file_is_error_free() {
    let s = Scratch::new();
    s.write("compose.yaml", "services:\n  web:\n    image: busybox\n");
    let (code, out, err) = run_dir(s.path());
    assert_eq!(code, Some(0));
    assert_eq!(out, "");
    let first = err.lines().next().expect("file line");
    assert!(
        first.contains(
            "\"error_free\":true,\"error_free_blockers\":[],\"error_free_with_downgrade\":null"
        ),
        "{first}"
    );
    assert!(first.contains("\"value_drops\":{},\"value_drops_total\":0,\"downgraded\":{}"));
    assert!(err.contains("\"error_free_files\":1"));
}

/// STACK-3: 引数の誤りは 2。引数の値は出力に入らない。
#[test]
fn invalid_arguments_exit_2() {
    let (code, out, err) = run_strs(&[]);
    assert_eq!(code, Some(2));
    assert_eq!(out, "");
    assert!(err.contains("\"code\":\"INVALID_ARGUMENT\""));
    let (code, _, err) = run_strs(&["--bogus=secret-marker"]);
    assert_eq!(code, Some(2));
    assert!(!err.contains("secret-marker"));
}

/// STACK-3・TASK-182.1: 不可のキーの指定は変換せず 2。ディレクトリが存在しなくても 2（走査の 3 にならない）。
#[test]
fn downgrade_of_non_unsupported_key_is_rejected() {
    let s = Scratch::new();
    s.write("a.yaml", "services: {}\n");
    let dir = s.path().to_string_lossy().into_owned();
    let (code, out, err) = run_strs(&["--downgrade=services.*.privileged", &dir]);
    assert_eq!(code, Some(2));
    assert_eq!(out, "");
    assert!(err.contains("\"code\":\"INVALID_ARGUMENT\""));
    assert!(err.contains("\"class\":\"error-incompatible\""));
    assert!(!err.contains("\"kind\":\"file\""));
    let (code, _, err) = run_strs(&["--downgrade=services.*.privileged", "/nonexistent-dir-9c1d"]);
    assert_eq!(code, Some(2), "{err}");
}

const REJECT_HEAD: &str =
    "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"--downgrade key is not error-unsupported-yet\"";

/// STACK-3・TASK-182.2: 拒否 4 分類（convert・warning〔表と `x-*`〕・error-incompatible・unrecognized）は
/// 変換せず 2。stdout は空、stderr はエラー 1 行だけで、走査より前（存在しないディレクトリでも 3 にならない）に止まる。
#[test]
fn downgrade_rejected_classes_exit_2_without_conversion() {
    let cases: [(&str, &str); 5] = [
        (
            "services.*.image",
            ",\"class\":\"convert\",\"key_path\":\"services.*.image\",\"index\":\"0\"}\n",
        ),
        (
            "version",
            ",\"class\":\"warning\",\"key_path\":\"version\",\"index\":\"0\"}\n",
        ),
        ("x-common", ",\"class\":\"warning\",\"index\":\"0\"}\n"),
        (
            "services.*.privileged",
            ",\"class\":\"error-incompatible\",\"key_path\":\"services.*.privileged\",\"index\":\"0\"}\n",
        ),
        (
            "services.*.secret-marker-628",
            ",\"class\":\"unrecognized\",\"index\":\"0\"}\n",
        ),
    ];
    let s = Scratch::new();
    s.write("a.yaml", "services:\n  web:\n    image: busybox\n");
    let dir = s.path().to_string_lossy().into_owned();
    let absent = s.path().join("absent").to_string_lossy().into_owned();
    for (key, tail) in cases {
        let expected = format!("{REJECT_HEAD}{tail}");
        for d in [&dir, &absent] {
            let (code, out, err) = run_strs(&[&format!("--downgrade={key}"), d]);
            assert_eq!(code, Some(2), "{key}: {err}");
            assert_eq!(out, "", "{key}");
            assert_eq!(err, expected, "{key}");
            assert!(!err.contains("\"kind\":\"file\""));
            assert!(!err.contains("\"kind\":\"summary\""));
        }
    }
}

/// STACK-3・TASK-182.2: 受理されるキーが混ざっていても拒否が 1 つでもあれば 2。最初の拒否だけを出し、入力は出さない。
#[test]
fn downgrade_mixed_accepted_and_rejected_exit_2() {
    let s = Scratch::new();
    s.write("a.yaml", "services:\n  web:\n    image: busybox\n");
    let dir = s.path().to_string_lossy().into_owned();
    let image_tail = ",\"class\":\"convert\",\"key_path\":\"services.*.image\"";
    let (code, out, err) = run_strs(&["--downgrade=services.*.tty,services.*.image", &dir]);
    assert_eq!(code, Some(2), "{err}");
    assert_eq!(out, "");
    assert_eq!(
        err,
        format!("{REJECT_HEAD}{image_tail},\"index\":\"1\"}}\n")
    );
    let (code, _, err) = run_strs(&["--downgrade=services.*.image,services.*.tty", &dir]);
    assert_eq!(code, Some(2));
    assert_eq!(
        err,
        format!("{REJECT_HEAD}{image_tail},\"index\":\"0\"}}\n")
    );
    // 拒否が複数: 最初のものだけ。
    let (code, _, err) = run_strs(&[
        "--downgrade=services.*.tty,services.*.image,services.*.privileged",
        &dir,
    ]);
    assert_eq!(code, Some(2));
    assert_eq!(
        err,
        format!("{REJECT_HEAD}{image_tail},\"index\":\"1\"}}\n")
    );
    assert!(!err.contains("privileged"));
    // unrecognized が混ざっても入力の目印は出ない。
    let (code, _, err) = run_strs(&[
        "--downgrade=services.*.tty,services.*.secret-marker-628",
        &dir,
    ]);
    assert_eq!(code, Some(2));
    assert!(err.contains("\"class\":\"unrecognized\""));
    assert!(err.contains("\"index\":\"1\""));
    assert!(!err.contains("secret-marker-628"));
}

/// STACK-3・TASK-182.1: 指定したキーが unsupported-yet のファイルは格下げされ、既定の error_free とは別に集計される。
#[test]
fn downgrade_of_unsupported_key_is_reported() {
    let s = Scratch::new();
    s.write(
        "a.yaml",
        "services:\n  web:\n    image: busybox\n    hostname: c\n",
    );
    s.write(
        "b.yaml",
        "services:\n  web:\n    image: busybox\n    hostname: c\n    privileged: true\n",
    );
    let dir = s.path().to_string_lossy().into_owned();
    let (code, out, err) = run_strs(&["--downgrade=services.*.hostname", &dir]);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, "");
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(lines.len(), 3, "{err}");
    assert!(lines[0].contains("\"downgraded\":{\"services.*.hostname\":1}"));
    assert!(lines[0].contains("\"error_free\":false"));
    assert!(
        lines[0].contains(
            "\"error_free_with_downgrade\":true,\"error_free_with_downgrade_blockers\":[]}"
        )
    );
    assert!(lines[1].contains("\"error_free_with_downgrade\":false"));
    assert!(lines[1].contains("\"downgraded\":{\"services.*.hostname\":1}"));
    assert_eq!(
        lines[2],
        "{\"kind\":\"summary\",\"files\":2,\"error_free_files\":0,\"error_free_with_downgrade_files\":1,\"parse_failed_files\":0,\"toml_output\":\"unimplemented\",\"conversion_rate\":{\"basis\":\"occurrences-excluding-warning\",\"convert_occurrences\":6,\"warning_occurrences\":0,\"error_incompatible_occurrences\":1,\"error_unsupported_yet_occurrences\":2,\"unrecognized_occurrences\":0,\"total_occurrences\":9,\"rate_percent\":\"66.66\",\"threshold_percent\":80,\"verdict\":\"below\",\"lower_bound_convert_occurrences\":6,\"lower_bound_rate_percent\":\"66.66\",\"lower_bound_verdict\":\"below\",\"indeterminate_reasons\":[]}}"
    );
}

/// STACK-3: 存在しないディレクトリは 3 と NOT_FOUND。
#[test]
fn missing_directory_exits_3() {
    let s = Scratch::new();
    let missing = s.path().join("absent");
    let (code, out, err) = run_dir(&missing);
    assert_eq!(code, Some(3));
    assert_eq!(out, "");
    assert!(err.contains("\"code\":\"NOT_FOUND\""));
}

/// STACK-3: compose.yml と compose.yaml の共存は変換せず 2。
#[test]
fn duplicate_file_id_exits_2() {
    let s = Scratch::new();
    s.write("compose.yml", "services: {}\n");
    s.write("compose.yaml", "services: {}\n");
    let (code, out, err) = run_dir(s.path());
    assert_eq!(code, Some(2));
    assert_eq!(out, "");
    assert!(err.contains("duplicate file_id"));
    assert!(!err.contains("\"kind\":\"file\""));
}
