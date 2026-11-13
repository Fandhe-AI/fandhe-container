//! `up` の CLI 結線の結合試験（STACK-8・STACK-10・SEC-1・ERR-1・CLI-1・TASK-155・REPAIR-12・#4638）。
//!
//! 実バイナリ `fandhe-container up` を起動し、**副作用より前の拒否**を具体値で照合する。イメージ・root・ネットワークは使わない
//! ため既定のテスト集合で走る（Linux のみ。非 Linux は `UNIMPLEMENTED` の固定値だけ照合する）。照合する不変条件は
//! 「拒否されたら子プロセスの起動もネットワークの作成も bundle の作成もゼロ」で、状態ルートに `.stack` が現れないことで確かめる。
//! 子プロセスを偽物に差し替えて create → start の argv の列・期限・終了コードを照合する試験は、cli crate の
//! `commands::up::launcher` の単体試験にある。実イメージでの通し確認は実機前提試験（後続 issue）。

#![cfg(unix)]

#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
use std::process::Command;

/// 子の上限（実行が止まっても試験が無期限に待たない。REPAIR-5）。
const RUN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// 子を起動し、期限までに終わらなければ kill して回収し、出力を集めて返す（`Command::output` の期限つき版）。
/// stdout・stderr は別スレッドで読み、満杯の pipe で子が止まらないようにする。
fn output_bounded(cmd: &mut Command) -> std::process::Output {
    use std::io::Read as _;
    use std::process::Stdio;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut so = child.stdout.take().expect("stdout");
    let mut se = child.stderr.take().expect("stderr");
    let ho = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = so.read_to_end(&mut v);
        v
    });
    let he = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = se.read_to_end(&mut v);
        v
    });
    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(st) => break st,
            None if start.elapsed() >= RUN_DEADLINE => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("up did not finish within {RUN_DEADLINE:?}");
            }
            None => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    };
    std::process::Output {
        status,
        stdout: ho.join().expect("stdout reader"),
        stderr: he.join().expect("stderr reader"),
    }
}

#[cfg(target_os = "linux")]
struct Dirs {
    base: PathBuf,
    state: PathBuf,
    images: PathBuf,
    project: PathBuf,
}

#[cfg(target_os = "linux")]
impl Dirs {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!("fc-up-wiring-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("base");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let images = base.join("images");
        std::fs::create_dir_all(images.join("blobs").join("sha256")).expect("images");
        std::fs::set_permissions(&images, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let project = base.join("project");
        std::fs::create_dir_all(&project).expect("project");
        Self {
            state: base.join("state"),
            images,
            project,
            base,
        }
    }

    fn write_toml(&self, body: &str) -> PathBuf {
        let p = self.project.join("stack.toml");
        std::fs::write(&p, body).expect("toml");
        p
    }

    /// `up` を実行し (終了コード, stdout, stderr) を返す。
    fn up(&self, file: &Path, extra: &[&str]) -> (i32, String, String) {
        let out = output_bounded(
            Command::new(env!("CARGO_BIN_EXE_fandhe-container"))
                .arg("--root")
                .arg(&self.state)
                .arg("up")
                .arg("--file")
                .arg(file)
                .arg("--image-root")
                .arg(&self.images)
                .args(extra),
        );
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// 拒否の後も、bundle・ネットワーク定義・コンテナの記録が一切作られていない。
    fn assert_no_side_effects(&self) {
        assert!(
            !self.state.join(".stack").exists(),
            "bundle directory must not exist"
        );
        let entries: Vec<String> = std::fs::read_dir(&self.state)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            entries.iter().all(|n| n.starts_with('@')),
            "no container record or network definition: {entries:?}"
        );
    }
}

#[cfg(target_os = "linux")]
impl Drop for Dirs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[cfg(target_os = "linux")]
fn code_line(code: &str, message: &str) -> String {
    format!(
        "{{\"level\":\"error\",\"event\":\"cli_error\",\"code\":\"{code}\",\"message\":\"{message}\"}}\n"
    )
}

/// SEC-1・STACK-8・#4638: `env_files` の最後の要素が範囲外を指す symlink なら、イメージにも子プロセスにも触れずに
/// `INVALID_ARGUMENT`（2）で拒否する。
#[cfg(target_os = "linux")]
#[test]
fn sec1_4638_env_file_symlink_to_outside_is_rejected_before_any_side_effect() {
    let d = Dirs::new("envlink");
    let secret = d.base.join("outside-secret.env");
    std::fs::write(&secret, "TOKEN=do-not-read\n").expect("secret");
    std::os::unix::fs::symlink(&secret, d.project.join("leak.env")).expect("symlink");
    let toml =
        d.write_toml("[services.web]\nimage = \"example/none:1\"\nenv_files = [\"leak.env\"]\n");
    let (exit, stdout, stderr) = d.up(&toml, &["--project-name", "shop"]);
    assert_eq!(exit, 2, "{stderr}");
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        code_line(
            "INVALID_ARGUMENT",
            "env_files entry must be a plain file under the project directory (env_files)"
        )
    );
    assert!(!stderr.contains("do-not-read"));
    d.assert_no_side_effects();
}

/// SEC-1・#4638: 途中のディレクトリが範囲外へ向く symlink でも同様に拒否する。
#[cfg(target_os = "linux")]
#[test]
fn sec1_4638_env_file_through_symlinked_directory_is_rejected() {
    let d = Dirs::new("envdir");
    let outside = d.base.join("outside");
    std::fs::create_dir_all(&outside).expect("outside");
    std::fs::write(outside.join("a.env"), "X=1\n").expect("a.env");
    std::os::unix::fs::symlink(&outside, d.project.join("sub")).expect("symlink");
    let toml =
        d.write_toml("[services.web]\nimage = \"example/none:1\"\nenv_files = [\"sub/a.env\"]\n");
    let (exit, _, stderr) = d.up(&toml, &["--project-name", "shop"]);
    assert_eq!(exit, 2, "{stderr}");
    assert!(stderr.contains("\"code\":\"INVALID_ARGUMENT\""), "{stderr}");
    d.assert_no_side_effects();
}

/// SEC-1・#4638: 字句で範囲外（`..`・絶対パス）の `env_files` は argv の組み立ての段で `INVALID_ARGUMENT`。
#[cfg(target_os = "linux")]
#[test]
fn sec1_4638_lexically_escaping_env_file_is_rejected() {
    for bad in ["../x.env", "/etc/hostname"] {
        let d = Dirs::new("envlex");
        let toml = d.write_toml(&format!(
            "[services.web]\nimage = \"example/none:1\"\nenv_files = [\"{bad}\"]\n"
        ));
        let (exit, _, stderr) = d.up(&toml, &["--project-name", "shop"]);
        assert_eq!(exit, 2, "{bad}: {stderr}");
        assert_eq!(
            stderr,
            code_line("INVALID_ARGUMENT", "service field is invalid (env_files)"),
            "{bad}"
        );
        d.assert_no_side_effects();
    }
}

/// OCI-7・STACK-8・#4638: 在庫に無いイメージは起動ゼロで `NOT_FOUND`（3）。`up` は pull しない。
#[cfg(target_os = "linux")]
#[test]
fn oci7_4638_missing_image_is_not_found_without_side_effects() {
    let d = Dirs::new("noimage");
    let toml = d.write_toml("[services.web]\nimage = \"example/none:1\"\n");
    let (exit, stdout, stderr) = d.up(&toml, &["--project-name", "shop"]);
    assert_eq!(exit, 3, "{stderr}");
    assert_eq!(stdout, "");
    assert!(stderr.contains("\"code\":\"NOT_FOUND\""), "{stderr}");
    d.assert_no_side_effects();
}

/// STACK-8・#4630・#4638: プロジェクト名は flag ＞ TOML ＞ ディレクトリ名で決まり、不正な値は正規化せずに拒否する。
/// ディレクトリ名が規則に反し他の段が無ければ `INVALID_ARGUMENT`。flag があればディレクトリ名は見ない。
#[cfg(target_os = "linux")]
#[test]
fn stack8_4630_4638_project_name_resolution_from_the_cli() {
    let d = Dirs::new("projname");
    let bad_dir = d.base.join("My App");
    std::fs::create_dir_all(&bad_dir).expect("dir");
    let toml = bad_dir.join("stack.toml");
    std::fs::write(&toml, "[services.web]\nimage = \"example/none:1\"\n").expect("toml");
    // ディレクトリ名 `My App` は不正で、他の段が無い。
    let (exit, _, stderr) = d.up(&toml, &[]);
    assert_eq!(exit, 2, "{stderr}");
    assert_eq!(
        stderr,
        code_line("INVALID_ARGUMENT", "project name is invalid")
    );
    // flag が上位: ディレクトリ名は見ず、次の段（イメージの解決）へ進んで NOT_FOUND になる。
    let (exit, _, stderr) = d.up(&toml, &["--project-name", "shop"]);
    assert_eq!(exit, 3, "{stderr}");
    // TOML の [project].name が dir 名より上位。
    std::fs::write(
        &toml,
        "[project]\nname = \"toml-x\"\n[services.web]\nimage = \"example/none:1\"\n",
    )
    .expect("toml");
    let (exit, _, stderr) = d.up(&toml, &[]);
    assert_eq!(exit, 3, "{stderr}");
    // flag の不正は TOML の正しい値へ落とさず拒否する。
    let (exit, _, stderr) = d.up(&toml, &["--project-name", "Bad Name"]);
    assert_eq!(exit, 2, "{stderr}");
    d.assert_no_side_effects();
}

/// STACK-10・#4638: 存在しないサービスの明示対象・不正な TOML・存在しないファイルを起動ゼロで拒否する。
#[cfg(target_os = "linux")]
#[test]
fn stack10_4638_unknown_target_bad_toml_and_missing_file_are_rejected() {
    let d = Dirs::new("inputs");
    let toml = d.write_toml("[services.web]\nimage = \"example/none:1\"\n");
    let (exit, _, stderr) = d.up(&toml, &["--project-name", "shop", "ghost"]);
    assert_eq!(exit, 2, "{stderr}");
    let bad = d.project.join("bad.toml");
    std::fs::write(&bad, "[services.web]\nunknown_key = 1\n").expect("bad");
    let (exit, _, stderr) = d.up(&bad, &["--project-name", "shop"]);
    assert_eq!(exit, 2, "{stderr}");
    let (exit, _, stderr) = d.up(&d.project.join("none.toml"), &[]);
    assert_eq!(exit, 3, "{stderr}");
    assert_eq!(stderr, code_line("NOT_FOUND", "project file was not found"));
    d.assert_no_side_effects();
}

/// STACK-8・SEC-1・#4638: pasta のフラグはユーザー定義ネットワークに付くサービスが無ければ拒否する。
#[cfg(target_os = "linux")]
#[test]
fn stack8_4638_pasta_flag_without_user_network_is_rejected() {
    let d = Dirs::new("pasta");
    let toml = d.write_toml("[services.web]\nimage = \"example/none:1\"\n");
    let out = output_bounded(
        Command::new(env!("CARGO_BIN_EXE_fandhe-container"))
            .arg("--root")
            .arg(&d.state)
            .arg("--pasta-path-search")
            .arg("up")
            .arg("--file")
            .arg(&toml)
            .arg("--image-root")
            .arg(&d.images)
            .args(["--project-name", "shop"]),
    );
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        code_line(
            "INVALID_ARGUMENT",
            "pasta flags require a service on a user-defined network"
        )
    );
    d.assert_no_side_effects();
}

/// CLI-1・ERR-1・#4638: 使い方エラー（必須オプションの欠落・重複・相対の `--image-root`・未知のオプション）は 2。
#[test]
fn cli1_4638_usage_errors_exit_2() {
    let bin = env!("CARGO_BIN_EXE_fandhe-container");
    for argv in [
        vec!["up"],
        vec!["up", "--file", "a.toml"],
        vec!["up", "--image-root", "/abs"],
        vec!["up", "--file", "a", "--file", "b", "--image-root", "/abs"],
        vec!["up", "--file", "a", "--image-root", "rel"],
        vec!["up", "--file", "a", "--image-root", "/abs", "--bogus"],
    ] {
        let out = output_bounded(Command::new(bin).args(&argv));
        assert_eq!(out.status.code(), Some(2), "{argv:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("\"code\":\"INVALID_ARGUMENT\""),
            "{argv:?}"
        );
    }
}
