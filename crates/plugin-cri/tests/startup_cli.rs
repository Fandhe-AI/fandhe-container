//! ビルドされた `fandhe-container-plugin-cri` を起動する結合試験（TASK-114.1・#457・PLUG-1）。
//!
//! 絶対パスで起動し（PATH 探索なし）、環境は `env_clear()`。子の待機は期限つき（REPAIR-5）。

#[path = "../../core/tests/support/reap.rs"]
mod reap;

use std::process::Command;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-cri");
const DEADLINE: Duration = Duration::from_secs(10);

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Out {
    run_inner(args, None)
}

/// `production()` が状態ルートを解決できるよう `XDG_RUNTIME_DIR` を与えて起動する。
#[cfg(target_os = "linux")]
fn run_with_env(args: &[&str], xdg: &std::path::Path) -> Out {
    run_inner(args, Some(xdg.to_path_buf()))
}

fn run_inner(args: &[&str], xdg: Option<std::path::PathBuf>) -> Out {
    let mut cmd = Command::new(BIN);
    cmd.args(args).env_clear();
    if let Some(x) = xdg {
        cmd.env("XDG_RUNTIME_DIR", x);
    }
    // spawn・期限・出力回収を一括で期限つきにする。孫が pipe を持ち続けても戻る（REPAIR-5・#3409）。
    let o =
        reap::output_within(&mut cmd, DEADLINE).unwrap_or_else(|e| panic!("plugin binary: {e}"));
    Out {
        code: o.status.code(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

#[test]
fn help_exits_zero_with_usage() {
    let o = run(&["--help"]);
    assert_eq!(o.code, Some(0));
    assert_eq!(
        o.stdout,
        "usage: fandhe-container-plugin-cri [--help] | --socket <PATH>\n"
    );
    assert_eq!(o.stderr, "");
}

#[test]
fn no_args_exits_one_unimplemented() {
    let o = run(&[]);
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.stderr,
        "error: UNIMPLEMENTED: default socket path is not defined yet; pass --socket <PATH>\n"
    );
    assert_eq!(o.stdout, "");
}

#[test]
fn unknown_flag_exits_two_without_echoing_value() {
    let o = run(&["--bogus"]);
    assert_eq!(o.code, Some(2));
    assert_eq!(o.stderr, "error: INVALID_ARGUMENT: unexpected argument\n");
    assert!(!o.stderr.contains("bogus"));
    assert_eq!(o.stdout, "");
}

/// 相対パスの `--socket` は InvalidArgument（終了コード 2）で、パスを echo しない。
#[test]
fn relative_socket_exits_two_without_echoing_path() {
    let o = run(&["--socket", "rel/secret.sock"]);
    assert_eq!(o.code, Some(2));
    assert_eq!(
        o.stderr,
        "error: INVALID_ARGUMENT: invalid --socket argument\n"
    );
    assert!(!o.stderr.contains("secret"));
    assert_eq!(o.stdout, "");
}

/// 配置ディレクトリが 0700 でない socket パスは bind が失敗して終了コード 1（fail-closed）。パスを echo しない。
#[cfg(target_os = "linux")]
#[test]
fn insecure_socket_dir_exits_one_without_echoing_path() {
    use std::os::unix::fs::DirBuilderExt;
    let dir = std::env::temp_dir().join(format!("fcpc-insecure-{}", std::process::id()));
    // 前回の残骸があると排他作成が AlreadyExists になるため、先に消す（REPAIR-12・#3375）。
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new()
        .mode(0o755)
        .create(&dir)
        .expect("mkdir");
    // umask に依らず 0755 にする。
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("chmod");
    let xdg = std::env::temp_dir().join(format!("fcpc-xdg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&xdg);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&xdg)
        .expect("mkdir xdg");
    let sock = dir.join("s.sock");
    let o = run_with_env(&["--socket", sock.to_str().expect("utf8")], &xdg);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);
    assert_eq!(o.code, Some(1));
    assert!(o.stderr.starts_with("error: "), "stderr: {}", o.stderr);
    assert!(!o.stderr.contains("fcpc-insecure"));
    assert_eq!(o.stdout, "");
}
