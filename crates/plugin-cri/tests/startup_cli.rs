//! ビルドされた `fandhe-container-plugin-cri` を起動する結合試験（TASK-114.1・#457・PLUG-1）。
//!
//! 絶対パスで起動し（PATH 探索なし）、環境は `env_clear()`。子の待機は期限つき（REPAIR-5）。

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// 予測できる名前を消さずに排他作成する補助（REPAIR-12・#3479）。
#[cfg(target_os = "linux")]
#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-cri");
const DEADLINE: Duration = Duration::from_secs(10);
/// kill 後の回収の猶予。
const REAP_GRACE: Duration = Duration::from_secs(5);

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
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn plugin binary");
    let start = Instant::now();
    loop {
        if child.try_wait().expect("try_wait").is_some() {
            break;
        }
        if start.elapsed() > DEADLINE {
            let kill_result = child.kill();
            // 回収も有限の猶予で行う（期限なしの wait は割り込み不能な待ちで無期限に止まる。REPAIR-5）。
            let reap_start = Instant::now();
            let mut reaped = false;
            while reap_start.elapsed() < REAP_GRACE {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    reaped = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!(
                "plugin binary did not exit within deadline (kill: {kill_result:?}, reaped: {reaped})"
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let o = child.wait_with_output().expect("collect output");
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
    use std::os::unix::fs::PermissionsExt as _;
    // 予測できる名前を消さずに排他作成し、drop で自分の分だけ消す（REPAIR-12・#3479）。
    struct Guard(std::path::PathBuf);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let dir = Guard(exclusive_dir::create("fcpc-insecure").expect("mkdir"));
    // 排他作成は 0700。umask に依らず 0755 にする（安全でない配置ディレクトリの再現）。
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let xdg = Guard(exclusive_dir::create("fcpc-xdg").expect("mkdir xdg"));
    let sock = dir.0.join("s.sock");
    let o = run_with_env(&["--socket", sock.to_str().expect("utf8")], &xdg.0);
    assert_eq!(o.code, Some(1));
    assert!(o.stderr.starts_with("error: "), "stderr: {}", o.stderr);
    assert!(!o.stderr.contains("fcpc-insecure"));
    assert_eq!(o.stdout, "");
}
