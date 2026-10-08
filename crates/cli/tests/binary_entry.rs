//! バイナリ `fandhe-container` の入口の結合試験（CLI-1・REPAIR-12。TASK-79.1・MS-6）。
//!
//! 実バイナリを起動し、終了コード・stderr の 1 行 JSON・stdout が空であることを具体値で照合する。

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const USAGE_JSON: &str = "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"usage: fandhe-container <create|start|stop|delete|list|logs>\"}\n";
const UNIMPLEMENTED_JSON: &str =
    "{\"code\":\"UNIMPLEMENTED\",\"message\":\"command is not implemented yet\"}\n";

/// 子プロセスの終了を待つ上限（REPAIR-5）。超過時は kill して失敗させる。
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

/// kill 後の回収と、終了後の出力収集を待つ上限（REPAIR-5）。
const REAP_TIMEOUT: Duration = Duration::from_secs(10);

/// パイプを別スレッドで読み、結果をチャネルで返す（待つ側は `recv_timeout` で期限を設ける）。
fn spawn_reader<R: Read + Send + 'static>(mut pipe: R) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    rx
}

/// 実バイナリを起動し、有限期限内に終了と出力収集を完了させる（REPAIR-5）。
///
/// stdout / stderr は別スレッドで読み、パイプ詰まりによるデッドロックを避ける。
/// 回収・出力収集のいずれも期限付きで、期限超過時は読み取りを打ち切って panic で失敗させる
/// （stdout を継承した子孫が残って EOF が来ない場合も無期限に待たない）。
fn run(args: &[&str]) -> Output {
    run_env(args, &[])
}

/// [`run`] と同じ手順で、環境変数 `envs` を追加して起動する。
fn run_env(args: &[&str], envs: &[(&str, &std::ffi::OsStr)]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fandhe-container"))
        .args(args)
        .envs(envs.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn fandhe-container");
    let out_rx = spawn_reader(child.stdout.take().expect("stdout is piped"));
    let err_rx = spawn_reader(child.stderr.take().expect("stderr is piped"));

    let deadline = Instant::now() + CHILD_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("failed to poll child") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                // kill 後の回収も期限付きでポーリングする。
                let reap_deadline = Instant::now() + REAP_TIMEOUT;
                while Instant::now() < reap_deadline {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                panic!("fandhe-container did not exit within {CHILD_TIMEOUT:?}");
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    };
    let collect_deadline = Instant::now() + REAP_TIMEOUT;
    let remaining = || collect_deadline.saturating_duration_since(Instant::now());
    let stdout = out_rx
        .recv_timeout(remaining())
        .expect("stdout was not collected within the deadline");
    let stderr = err_rx
        .recv_timeout(remaining())
        .expect("stderr was not collected within the deadline");
    Output {
        status,
        stdout,
        stderr,
    }
}

fn assert_failure(out: &Output, code: i32, stderr: &str) {
    assert_eq!(out.status.code(), Some(code));
    assert_eq!(String::from_utf8_lossy(&out.stderr), stderr);
    assert!(out.stdout.is_empty(), "stdout must be empty");
}

/// CLI-1: 引数なしは使い方エラー（終了コード 2）。
#[test]
fn cli1_no_args_is_usage_error() {
    assert_failure(&run(&[]), 2, USAGE_JSON);
}

/// CLI-1: 未知コマンドは使い方エラー。引数値は出力へ埋め込まれない。
#[test]
fn cli1_unknown_command_is_usage_error() {
    for a in ["run", "Create", "", "--help", "a\"b\\c"] {
        assert_failure(&run(&[a]), 2, USAGE_JSON);
    }
}

/// CLI-1: create / start 以外の既知コマンドは未実装として終了コード 8（core の ERR-2 表）。余分な引数があっても同じ。
#[test]
fn cli1_other_commands_are_unimplemented() {
    for c in ["stop", "delete", "list", "logs"] {
        assert_failure(&run(&[c]), 8, UNIMPLEMENTED_JSON);
        assert_failure(&run(&[c, "extra"]), 8, UNIMPLEMENTED_JSON);
    }
}

/// CLI-1: create / start は引数不足・未知オプションで使い方エラー（2）。
#[test]
fn cli1_create_start_usage_errors() {
    for a in [
        &["create"][..],
        &["create", "c1"],
        &["create", "--bundle", "/b"],
        &["create", "--bundle", "/b", "--x", "c1"],
        &["start"],
        &["start", "a", "b"],
        &["--root"],
    ] {
        assert_failure(&run(a), 2, USAGE_JSON);
    }
}

/// 一意な一時ディレクトリ（Drop で削除）。
struct TmpDir(std::path::PathBuf);

impl TmpDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("fc-cli-bin-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("mkdir");
        // 状態ルートの祖先は group / other 書き込み不可でなければならない（umask に依存せず 0700 に固定）。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        Self(p)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(target_os = "linux")]
fn code_json(op: &str, code: &str, message: &str) -> String {
    format!("{{\"op\":\"{op}\",\"code\":\"{code}\",\"message\":\"{message}\"}}\n")
}

/// stderr の 1 行 JSON の `op` / `code` を取り出す（message は core の文言に依存するため照合しない）。
fn op_and_code(out: &Output) -> (String, String) {
    let s = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(s.ends_with('\n') && s.matches('\n').count() == 1, "{s:?}");
    let field = |key: &str| {
        let pat = format!("\"{key}\":\"");
        let start = s.find(&pat).expect("field") + pat.len();
        let end = s[start..].find('"').expect("end") + start;
        s[start..end].to_string()
    };
    (field("op"), field("code"))
}

/// CLI-1・OCI-4・ERR-2: Linux で create → 状態ファイル作成（0）、重複は 4、未作成 start は 3、
/// 作成済み start は本番 launcher 未提供のため 8（REPAIR-3）。
#[cfg(target_os = "linux")]
#[test]
fn cli1_create_start_flow_on_linux() {
    let tmp = TmpDir::new("flow");
    let bundle = tmp.0.join("bundle");
    std::fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
    std::fs::write(
        bundle.join("config.json"),
        r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .expect("config");
    let root = tmp.0.join("state");
    let root_s = root.to_str().expect("utf8");
    let bundle_s = bundle.to_str().expect("utf8");

    let out = run(&["--root", root_s, "create", "--bundle", bundle_s, "c1"]);
    assert_failure_free(&out);
    assert!(root.join("c1").join("state.json").exists());

    let out = run(&["--root", root_s, "create", "--bundle", bundle_s, "c1"]);
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(
        op_and_code(&out),
        ("create".into(), "ALREADY_EXISTS".into())
    );

    let out = run(&["--root", root_s, "start", "nope"]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(op_and_code(&out), ("start".into(), "NOT_FOUND".into()));

    let out = run(&["--root", root_s, "start", "c1"]);
    assert_eq!(out.status.code(), Some(8));
    assert_eq!(op_and_code(&out), ("start".into(), "UNIMPLEMENTED".into()));
    assert!(out.stdout.is_empty());
}

/// REPAIR-4: 複数の CLI プロセスが同じ `FANDHE_CONTAINER_OP_LOG` へ並行に追記しても JSON 行が混ざらない。
///
/// 相対 bundle の create は core へ到達する前に失敗し（終了コード 2）、失敗 1 件の計測を追記する。
/// 16 スレッド × 4 回 = 64 プロセスを同時に走らせ、ログが「op_stats 行 + メタ行」の 64 組だけで
/// 構成されること（1 行に JSON が 2 つ並ばない・行が途切れない・未存在からの同時作成で落とさない）を照合する。
#[cfg(target_os = "linux")]
#[test]
fn repair4_concurrent_processes_keep_op_log_lines_intact() {
    const WORKERS: usize = 16;
    const ROUNDS: usize = 4;
    const STATS_HEAD: &str = "{\"event\":\"op_stats\",\"op\":\"create\",\"success\":0,\"failure\":1,\"count\":1,\"min_us\":";
    const META: &str = "{\"event\":\"op_stats_meta\",\"ops\":1,\"dropped_records\":0}";

    let tmp = TmpDir::new("oplog");
    let log = tmp.0.join("ops.jsonl");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WORKERS));
    let handles: Vec<_> = (0..WORKERS)
        .map(|_| {
            let log = log.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                (0..ROUNDS)
                    .map(|_| {
                        run_env(
                            &["create", "--bundle", "rel/b", "c1"],
                            &[("FANDHE_CONTAINER_OP_LOG", log.as_os_str())],
                        )
                    })
                    .collect::<Vec<Output>>()
            })
        })
        .collect();
    for h in handles {
        for out in h.join().expect("join") {
            assert_eq!(out.status.code(), Some(2));
            assert_eq!(
                op_and_code(&out),
                ("create".into(), "INVALID_ARGUMENT".into())
            );
            assert!(out.stdout.is_empty(), "stdout must be empty");
        }
    }

    let text = std::fs::read_to_string(&log).expect("read op log");
    assert!(text.ends_with('\n'), "{text:?}");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), WORKERS * ROUNDS * 2, "{text}");
    for pair in lines.chunks(2) {
        let stats = pair.first().copied().unwrap_or_default();
        assert!(stats.starts_with(STATS_HEAD), "mixed line: {stats:?}");
        assert!(stats.ends_with('}'), "truncated line: {stats:?}");
        assert_eq!(stats.matches('{').count(), 1, "mixed line: {stats:?}");
        assert_eq!(stats.matches('}').count(), 1, "mixed line: {stats:?}");
        for key in ["\"mean_us\":", "\"p95_us\":", "\"max_us\":"] {
            assert_eq!(stats.matches(key).count(), 1, "mixed line: {stats:?}");
        }
        assert_eq!(pair.get(1).copied(), Some(META), "{pair:?}");
    }
}

/// 終了コード 0・stdout / stderr とも空。
#[cfg(target_os = "linux")]
fn assert_failure_free(out: &Output) {
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty(), "stdout must be empty");
    assert!(out.stderr.is_empty(), "stderr must be empty");
}

/// ERR-2: 相対 bundle は INVALID_ARGUMENT（2）。状態ルートは作られる前でも拒否の形式は同じ。
#[cfg(target_os = "linux")]
#[test]
fn err2_create_rejects_relative_bundle() {
    let tmp = TmpDir::new("relative");
    let root = tmp.0.join("state");
    let out = run(&[
        "--root",
        root.to_str().expect("utf8"),
        "create",
        "--bundle",
        "rel/b",
        "c1",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        code_json("create", "INVALID_ARGUMENT", "bundle path must be absolute")
    );
}

/// SEC-1: Linux 以外では状態ストアを開けず fail-closed の UNIMPLEMENTED（8）。
#[cfg(not(target_os = "linux"))]
#[test]
fn sec1_create_fails_closed_off_linux() {
    let tmp = TmpDir::new("offlinux");
    let root = tmp.0.join("state");
    let abs_bundle = tmp.0.join("bundle");
    let out = run(&[
        "--root",
        root.to_str().expect("utf8"),
        "create",
        "--bundle",
        abs_bundle.to_str().expect("utf8"),
        "c1",
    ]);
    assert_eq!(out.status.code(), Some(8));
    assert_eq!(op_and_code(&out), ("create".into(), "UNIMPLEMENTED".into()));
    assert!(out.stdout.is_empty());
}
