//! 実バイナリの stdout への TOML 書き出しの結合試験（#3613・STACK-3・STACK-5・SEC-1・REPAIR-12）。
//!
//! 入力が 1 件で対象のときだけ stdout に往復検証済みの TOML が出ること、書き出した TOML を stack のスキーマで
//! 読み戻すと変換直後の値と等しいこと、値（env・格下げしたキー）が stderr に出ないことを照合する。
//! 子プロセスの待ちには期限を付け（REPAIR-5）、stdout / stderr は別スレッドで読む。

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use fandhe_container_compose_convert::classify::{KeyClass, classify_key_path};
use fandhe_container_compose_convert::compose_convert::parse_compose_yaml;
use fandhe_container_compose_convert::convert::{ValueDrops, convert_top_level};
use fandhe_container_stack::schema::ComposeToml;

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-compose-convert");

static SEQ: AtomicU32 = AtomicU32::new(0);

/// drop で消える一時ディレクトリ。
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("fc-toml-stdout-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).expect("create scratch");
        Self(p)
    }

    fn write(&self, name: &str, text: &str) {
        std::fs::write(self.0.join(name), text).expect("write fixture");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture(parts: &[&str]) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for part in ["tests", "fixtures", "roundtrip"].iter().chain(parts) {
        p = p.join(part);
    }
    std::fs::read_to_string(p).expect("read fixture")
}

fn run(args: &[&str], dir: &Scratch) -> (Option<i32>, String, String) {
    let mut child = Command::new(BIN)
        .args(args)
        .arg(&dir.0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut so = child.stdout.take().expect("stdout");
    let mut se = child.stderr.take().expect("stderr");
    let t_out = std::thread::spawn(move || {
        let mut b = String::new();
        let _ = so.read_to_string(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = String::new();
        let _ = se.read_to_string(&mut b);
        b
    });
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
    (
        status.code(),
        t_out.join().expect("out"),
        t_err.join().expect("err"),
    )
}

fn converted(yaml: &str) -> ComposeToml {
    let doc = parse_compose_yaml(yaml).expect("parse");
    convert_top_level(&doc, &mut ValueDrops::new())
}

/// 既定モード: 往復で変換直後の値と等しい TOML が出る。
#[test]
fn stack5_3613_default_mode_writes_roundtrippable_toml() {
    let yaml = fixture(&["default", "synthetic-full-coverage.yaml"]);
    let s = Scratch::new();
    s.write("compose.yaml", &yaml);
    let (code, out, err) = run(&[], &s);
    assert_eq!(code, Some(0), "{err}");
    assert!(!out.is_empty());
    assert!(err.contains("\"toml_output\":\"stdout\""), "{err}");
    let rt: ComposeToml = toml::from_str(&out).expect("stdout must reparse");
    assert_eq!(rt, converted(&yaml));
}

/// 格下げモード: 対象になり、格下げしたキーの名前と値は出ない。--downgrade なしでは書かない。
#[test]
fn stack3_3613_downgrade_mode_omits_downgraded_keys() {
    for k in ["services.*.hostname", "services.*.user"] {
        assert_eq!(classify_key_path(k), KeyClass::ErrorUnsupportedYet, "{k}");
    }
    let yaml = fixture(&["downgrade", "hostname-user.yaml"]);
    let s = Scratch::new();
    s.write("compose.yaml", &yaml);
    let (code, out, err) = run(&["--downgrade=services.*.hostname,services.*.user"], &s);
    assert_eq!(code, Some(0), "{err}");
    assert!(err.contains("\"toml_output\":\"stdout\""), "{err}");
    let rt: ComposeToml = toml::from_str(&out).expect("stdout must reparse");
    assert_eq!(rt, converted(&yaml));
    for marker in ["hostname", "app-host", "1000:1000"] {
        assert!(!out.contains(marker), "{marker} leaked into stdout: {out}");
    }
    // stderr のレポートはキーパスを持つが、値は持たない（SEC-1）。
    for marker in ["app-host", "1000:1000"] {
        assert!(!err.contains(marker), "{marker} leaked into stderr: {err}");
    }

    let (code, out, err) = run(&[], &s);
    assert_eq!(code, Some(0));
    assert_eq!(out, "");
    assert!(
        err.contains("\"toml_output\":\"skipped-not-error-free\""),
        "{err}"
    );
}

/// 入力が 2 件のときは書かない。
#[test]
fn stack3_3613_multiple_files_write_nothing() {
    let s = Scratch::new();
    s.write("a.yaml", "services:\n  web:\n    image: busybox\n");
    s.write("b.yaml", "services:\n  db:\n    image: busybox\n");
    let (code, out, err) = run(&[], &s);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, "");
    assert!(
        err.contains("\"toml_output\":\"skipped-multiple-files\""),
        "{err}"
    );
}

/// 入力が 0 件（yml / yaml が無いディレクトリ）のときは `skipped-no-inputs`（複数件ではない）。
#[test]
fn stack3_3613_empty_directory_reports_no_inputs() {
    let s = Scratch::new();
    s.write("readme.txt", "not compose\n");
    let (code, out, err) = run(&[], &s);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, "");
    assert!(err.contains("\"files\":0"), "{err}");
    assert!(
        err.contains("\"toml_output\":\"skipped-no-inputs\""),
        "{err}"
    );
    assert!(!err.contains("skipped-multiple-files"), "{err}");
}

/// 対象外（build: とマーカー値つき env）は書かず、値は stderr に出ない（SEC-1）。
#[test]
fn stack3_3613_not_eligible_writes_nothing_and_leaks_nothing() {
    let s = Scratch::new();
    s.write(
        "a.yaml",
        "services:\n  web:\n    build: ./ctx\n    environment:\n      TOKEN: secret-marker-3613\n",
    );
    let (code, out, err) = run(&[], &s);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, "");
    assert!(
        err.contains("\"toml_output\":\"skipped-not-error-free\""),
        "{err}"
    );
    assert!(!err.contains("secret-marker-3613"), "{err}");
}

/// 出力は決定的（2 回の実行でバイト一致）で、改行は LF だけ。
#[test]
fn stack5_3613_output_is_deterministic_lf() {
    let yaml = fixture(&["default", "synthetic-full-coverage.yaml"]);
    let s = Scratch::new();
    s.write("compose.yaml", &yaml);
    let (_, first, _) = run(&[], &s);
    let (_, second, _) = run(&[], &s);
    assert!(!first.is_empty());
    assert_eq!(first, second);
    assert!(!first.contains('\r'));
}

/// STACK-5: 3 MiB の値をアンカーで 2 サービスから参照し、TOML が stack の入力上限（4 MiB）を超える場合は
/// 書き出さず `too-large` で終了コード 1 にする（読み込み側の契約と往復検証の一致。値は stderr に出ない）。
#[test]
fn stack5_3613_output_over_stack_limit_is_rejected() {
    let big = "x".repeat(3 * 1024 * 1024);
    let yaml = format!(
        "x-v: &v \"{big}\"\nservices:\n  a:\n    image: busybox\n    environment:\n      K: *v\n  b:\n    image: busybox\n    environment:\n      K: *v\n"
    );
    assert!(yaml.len() < fandhe_container_stack::toml_input::MAX_STACK_TOML_BYTES);
    let s = Scratch::new();
    s.write("compose.yaml", &yaml);
    let (code, out, err) = run(&[], &s);
    assert_eq!(code, Some(1), "{}", &err[..err.len().min(500)]);
    assert!(out.is_empty());
    assert!(err.contains("\"toml_output\":\"too-large\""));
    assert!(!err.contains("xxxxxxxx"));
}
