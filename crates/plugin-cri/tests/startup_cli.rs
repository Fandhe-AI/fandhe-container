//! ビルドされた `fandhe-container-plugin-cri` を起動する結合試験（TASK-114.1・#457・PLUG-1）。
//!
//! 絶対パスで起動し（PATH 探索なし）、環境は `env_clear()`。子の待機は期限つき（REPAIR-5）。

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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
    let mut child = Command::new(BIN)
        .args(args)
        .env_clear()
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
    assert_eq!(o.stdout, "usage: fandhe-container-plugin-cri [--help]\n");
    assert_eq!(o.stderr, "");
}

#[test]
fn no_args_exits_one_unimplemented() {
    let o = run(&[]);
    assert_eq!(o.code, Some(1));
    assert_eq!(
        o.stderr,
        "error: UNIMPLEMENTED: cri plugin server is not implemented yet\n"
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
