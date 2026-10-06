//! ビルドされた `fandhe-container-plugin-macos` を起動する結合試験（TASK-115.1・#385・PLUG-1・MAC-1）。
//!
//! 絶対パスで起動し（PATH 探索なし）、環境は `env_clear()` 後に必要分のみ渡す。
//! 子の待機は期限つき（REPAIR-5）。期限超過は kill して失敗にする。

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_plugin::PluginErrorCode;

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-macos");
const DEADLINE: Duration = Duration::from_secs(10);

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], envs: &[(&str, &std::ffi::OsStr)]) -> Out {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn plugin binary");
    let start = Instant::now();
    loop {
        if child.try_wait().expect("try_wait").is_some() {
            break;
        }
        if start.elapsed() > DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            panic!("plugin binary did not exit within deadline");
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

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        // macOS の TMPDIR（/var/folders/...）は長く、既定 socket パスが UDS の `sun_path`
        // 上限（104 バイト）を超えるため、unix では短い /tmp 配下を使う。
        #[cfg(unix)]
        let base = PathBuf::from("/tmp");
        #[cfg(not(unix))]
        let base = std::env::temp_dir();
        // 既存パスは削除せず、排他的な `create_dir` が衝突したら連番を進めて別名で作り直す
        // （予測可能なパスの先取り・symlink 差し替えに対して fail-closed。短さも維持する）。
        for n in 0..1000u32 {
            let p = base.join(format!("fc-pm-{tag}-{}-{n}", std::process::id()));
            match std::fs::create_dir(&p) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
                            .expect("chmod tmp dir");
                    }
                    return Tmp(p);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create tmp dir: {e}"),
            }
        }
        panic!("no free tmp dir name for tag {tag}");
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn help_exits_zero_with_usage() {
    let o = run(&["--help"], &[]);
    assert_eq!(o.code, Some(0));
    assert!(o.stdout.contains("--socket"), "stdout: {}", o.stdout);
}

#[test]
fn unknown_flag_exits_two_with_invalid_argument() {
    let o = run(&["--bogus"], &[]);
    assert_eq!(o.code, Some(2));
    assert_eq!(
        o.stderr.trim(),
        format!(
            "error: {}: unknown argument",
            PluginErrorCode::InvalidArgument.as_str()
        )
    );
}

/// 存在しない socket への接続失敗は終了コード 3（TASK-115.2）。socket は作られず、パスも出力しない。
#[test]
fn explicit_socket_connect_failure_exits_three_and_creates_nothing() {
    let t = Tmp::new("arg");
    let sock = t.0.join("a.sock");
    let sock_str = sock.to_str().expect("utf8 path");
    let o = run(&["--socket", sock_str], &[]);
    assert_eq!(o.code, Some(3), "stderr: {}", o.stderr);
    #[cfg(unix)]
    let want = PluginErrorCode::NotFound.as_str();
    #[cfg(not(unix))]
    let want = PluginErrorCode::Unimplemented.as_str();
    assert!(
        o.stderr.starts_with(&format!("error: {want}: ")),
        "stderr: {}",
        o.stderr
    );
    assert!(!o.stderr.contains(sock_str), "stderr: {}", o.stderr);
    assert!(!sock.exists());
}

#[cfg(unix)]
#[test]
fn default_path_resolves_runtime_dir_without_creating_socket() {
    let t = Tmp::new("def");
    let o = run(&[], &[("XDG_RUNTIME_DIR", t.0.as_os_str())]);
    assert_eq!(o.code, Some(3), "stderr: {}", o.stderr);
    assert!(o.stderr.contains(PluginErrorCode::NotFound.as_str()));
    assert!(t.0.join("fandhe-container").is_dir());
    assert!(
        !t.0.join("fandhe-container")
            .join("plugin-macos.sock")
            .exists()
    );
}

#[cfg(not(unix))]
#[test]
fn default_path_fails_closed_on_non_unix() {
    let o = run(&[], &[]);
    assert_eq!(o.code, Some(1));
    assert!(o.stderr.contains(PluginErrorCode::Unimplemented.as_str()));
}
