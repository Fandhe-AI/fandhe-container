//! 起動 bin `venus-jig` の結合試験（GPU-6・REPAIR-5・TASK-172 F4・#1598）。
//!
//! bin を子プロセスとして起動し、偽 frontend が UDS へ接続して capset クエリを送ると、ログファイルに
//! `GET_CAPSET`（capset_id=4・result=ok）の行が出て照合器が受理することを確かめる。拒否系は終了コードと stderr の
//! JSON 1 行を具体値で照合する。Linux x86_64 / aarch64 以外では skip を明示するテスト 1 本だけを走らせる。

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[test]
fn gpu6_venus_jig_bin_is_linux_only() {
    eprintln!("skip: venus-jig is Linux x86_64 / aarch64 only");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod common;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use super::common::*;
    use fandhe_container_poc_venus_jig::log::{find_capset_queries, read_log_file};

    const BIN: &str = env!("CARGO_BIN_EXE_venus-jig");

    /// `/tmp` 配下の一意な 0700 ディレクトリ（`sun_path` の上限に収めるため `temp_dir()` は使わない）。
    fn scratch() -> PathBuf {
        let p = PathBuf::from(format!("/tmp/vjb-{}", unique_name("d")));
        fs::DirBuilder::new().mode(0o700).create(&p).expect("dir");
        p
    }

    fn spawn(args: &[&str]) -> Child {
        Command::new(BIN)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn venus-jig")
    }

    /// 子プロセスの終了を期限つきで待つ。期限を過ぎたら kill して失敗とする（REPAIR-5）。
    fn wait_exit(child: &mut Child) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(st) = child.try_wait().expect("try_wait") {
                return st;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("venus-jig did not exit in time");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn stderr_of(mut child: Child) -> String {
        use std::io::Read;
        let mut s = String::new();
        child
            .stderr
            .take()
            .expect("stderr")
            .read_to_string(&mut s)
            .expect("read stderr");
        s
    }

    fn connect_when_ready(sock: &Path) -> UnixStream {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match UnixStream::connect(sock) {
                Ok(s) => return s,
                Err(e) if Instant::now() >= deadline => panic!("connect: {e}"),
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }

    #[test]
    fn gpu6_bin_accepts_one_connection_and_logs_get_capset() {
        let dir = scratch();
        let sock = dir.join("s.sock");
        let log = dir.join("jig.log");
        let mut child = spawn(&[
            "--socket",
            sock.to_str().unwrap(),
            "--log",
            log.to_str().unwrap(),
            "--accept-timeout-ms",
            "20000",
            "--idle-timeout-ms",
            "20000",
        ]);
        let front = connect_when_ready(&sock);
        let fe = setup_ring0(front, 408, "bin");
        submit_get_capset(&fe);
        wait_call(&fe);
        assert_eq!(used(&fe), [0, 0, 1, 0, 0, 0, 0, 0, 184, 0, 0, 0]);
        drop(fe);

        let status = wait_exit(&mut child);
        assert_eq!(status.code(), Some(0), "stderr: {}", stderr_of(child));
        assert!(fs::symlink_metadata(&sock).is_err(), "socket cleaned up");
        assert_eq!(fs::metadata(&log).unwrap().mode() & 0o777, 0o600);

        let text = read_log_file(&log).expect("log readable");
        let want = "venus_jig event=capset_query cmd=GET_CAPSET capset_id=4 version=0 result=ok max_size=160";
        assert!(text.lines().any(|l| l == want), "log: {text}");
        assert!(text.lines().any(|l| l == "venus_jig event=accepted"));
        let report = find_capset_queries(&text).expect("report");
        assert_eq!(report.venus_get_capset_ok, 1);
        assert_eq!(report.malformed_lines, 0, "log: {text}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn gpu6_bin_rejects_relative_path_with_json_and_exit_2() {
        let dir = scratch();
        let log = dir.join("jig.log");
        let mut child = spawn(&["--socket", "rel.sock", "--log", log.to_str().unwrap()]);
        let status = wait_exit(&mut child);
        assert_eq!(status.code(), Some(2));
        let err = stderr_of(child);
        assert!(
            err.starts_with("{\"code\":\"PATH_NOT_ABSOLUTE\","),
            "stderr: {err}"
        );
        assert_eq!(err.lines().count(), 1);
        assert!(fs::symlink_metadata(&log).is_err(), "no log on rejection");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn gpu6_bin_never_overwrites_an_existing_log() {
        let dir = scratch();
        let log = dir.join("jig.log");
        fs::write(&log, b"keep me").unwrap();
        let sock = dir.join("s.sock");
        let mut child = spawn(&[
            "--socket",
            sock.to_str().unwrap(),
            "--log",
            log.to_str().unwrap(),
        ]);
        let status = wait_exit(&mut child);
        assert_eq!(status.code(), Some(2));
        let err = stderr_of(child);
        assert!(
            err.starts_with("{\"code\":\"LOG_PATH_EXISTS\","),
            "stderr: {err}"
        );
        assert_eq!(fs::read(&log).unwrap(), b"keep me");
        assert!(fs::symlink_metadata(&sock).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn repair5_bin_exits_with_accept_timeout_when_nobody_connects() {
        let dir = scratch();
        let sock = dir.join("s.sock");
        let log = dir.join("jig.log");
        let mut child = spawn(&[
            "--socket",
            sock.to_str().unwrap(),
            "--log",
            log.to_str().unwrap(),
            "--accept-timeout-ms",
            "100",
        ]);
        let status = wait_exit(&mut child);
        assert_eq!(status.code(), Some(1));
        let err = stderr_of(child);
        assert!(
            err.starts_with("{\"code\":\"ACCEPT_TIMEOUT\","),
            "stderr: {err}"
        );
        assert!(fs::symlink_metadata(&sock).is_err(), "socket cleaned up");
        fs::remove_dir_all(&dir).unwrap();
    }
}
