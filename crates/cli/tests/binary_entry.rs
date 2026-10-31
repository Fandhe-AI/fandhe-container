//! バイナリ `fandhe-container` の入口の結合試験（CLI-1・REPAIR-12。TASK-79.1・MS-6）。
//!
//! 実バイナリを起動し、終了コード・stderr の 1 行 JSON・stdout が空であることを具体値で照合する。

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const USAGE_JSON: &str = "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"usage: fandhe-container <create|start|stop|kill|delete|list|logs|inspect|state|image|system|network|setup|doctor>\"}\n";

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
    run_exe_env(
        std::path::Path::new(env!("CARGO_BIN_EXE_fandhe-container")),
        args,
        envs,
    )
}

/// [`run_env`] の実体。起動する実行ファイルを `exe` で指定する。
fn run_exe_env(exe: &std::path::Path, args: &[&str], envs: &[(&str, &std::ffi::OsStr)]) -> Output {
    let mut child = Command::new(exe)
        .args(args)
        // PATH 探索の opt-in を環境から持ち込まず、結果を決定的にする（PLUG-11）。
        .env_remove("FANDHE_CONTAINER_PLUGIN_PATH_SEARCH")
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

/// REPAIR-5・#1673: stderr が読み手の読まない満杯の socket でも、終了時の出力は期限（2 秒）で打ち切られ、
/// 終了コード（使い方エラーの 2）は保たれる。出力スレッドは書き込みで止まるため、終了までに期限ぶんかかる。
/// `UnixStream` を使うため unix のみ（Windows には満杯にできる同等の stderr を std で作る手段が無い）。
#[cfg(unix)]
#[test]
fn repair5_exit_is_bounded_when_stderr_reader_stalls() {
    use std::os::unix::net::UnixStream;
    let (a, b) = UnixStream::pair().expect("socketpair");
    // 送信バッファを満たす間だけ非ブロッキングにし、子へ渡す前にブロッキングへ戻す（子の書き込みは止まる）。
    a.set_nonblocking(true).expect("set_nonblocking");
    let chunk = [b'x'; 4096];
    let mut filled = false;
    for _ in 0..1_000_000 {
        match std::io::Write::write(&mut &a, &chunk) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                filled = true;
                break;
            }
            Err(e) => panic!("fill failed: {e}"),
        }
    }
    assert!(filled, "socket buffer was not filled");
    a.set_nonblocking(false).expect("set_nonblocking");

    let start = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_fandhe-container"))
        .env_remove("FANDHE_CONTAINER_PLUGIN_PATH_SEARCH")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::os::fd::OwnedFd::from(a)))
        .spawn()
        .expect("failed to spawn fandhe-container");
    let deadline = start + CHILD_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            other => {
                let _ = child.kill();
                let reap_deadline = Instant::now() + REAP_TIMEOUT;
                while Instant::now() < reap_deadline {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                panic!("fandhe-container did not exit within {CHILD_TIMEOUT:?}: {other:?}");
            }
        }
    };
    let elapsed = start.elapsed();
    drop(b);
    assert_eq!(status.code(), Some(2));
    // 書き込みが止まったまま期限で打ち切られたこと（即座に終わったなら出力が止まっていない）。
    assert!(
        elapsed >= Duration::from_millis(1500),
        "exited before the report timeout: {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(15), "exit took {elapsed:?}");
}

/// 試験専用の登録失敗の注入（feature `signal-test-support`。`signals.rs` の `TEST_INSTALL_FAILURE_ENV`）。
#[cfg(unix)]
const SIGNAL_INSTALL_FAILURE_ENV: &str = "FANDHE_CONTAINER_TEST_SIGNAL_INSTALL_FAILURE";

/// REPAIR-5・ERR-1・#1778: シグナル転送の登録に失敗したら、コマンドを実行せず終了コード 1（`INTERNAL`）と
/// 構造化エラーの 1 行を、期限付きの出力経路経由で stderr へ出す（行が失われない）。
#[cfg(unix)]
#[test]
fn repair5_signal_install_failure_reports_via_deferred_path() {
    let out = run_env(
        &[],
        &[(SIGNAL_INSTALL_FAILURE_ENV, std::ffi::OsStr::new("1"))],
    );
    assert_failure(
        &out,
        1,
        "{\"code\":\"INTERNAL\",\"message\":\"failed to install the signal handler for plugin forwarding\"}\n",
    );
}

/// REPAIR-5・#1778: 登録失敗の出力も、stderr が読み手の読まない満杯の socket なら期限（2 秒）で打ち切られ、
/// 終了コード 1 を保って終了する（main スレッドで無期限に書かない）。
#[cfg(unix)]
#[test]
fn repair5_signal_install_failure_exit_is_bounded_when_stderr_reader_stalls() {
    use std::os::unix::net::UnixStream;
    let (a, b) = UnixStream::pair().expect("socketpair");
    a.set_nonblocking(true).expect("set_nonblocking");
    let chunk = [b'x'; 4096];
    let mut filled = false;
    for _ in 0..1_000_000 {
        match std::io::Write::write(&mut &a, &chunk) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                filled = true;
                break;
            }
            Err(e) => panic!("fill failed: {e}"),
        }
    }
    assert!(filled, "socket buffer was not filled");
    a.set_nonblocking(false).expect("set_nonblocking");

    let start = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_fandhe-container"))
        .env_remove("FANDHE_CONTAINER_PLUGIN_PATH_SEARCH")
        .env(SIGNAL_INSTALL_FAILURE_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::os::fd::OwnedFd::from(a)))
        .spawn()
        .expect("failed to spawn fandhe-container");
    let deadline = start + CHILD_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            other => {
                let _ = child.kill();
                let reap_deadline = Instant::now() + REAP_TIMEOUT;
                while Instant::now() < reap_deadline {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                panic!("fandhe-container did not exit within {CHILD_TIMEOUT:?}: {other:?}");
            }
        }
    };
    let elapsed = start.elapsed();
    drop(b);
    assert_eq!(status.code(), Some(1));
    assert!(
        elapsed >= Duration::from_millis(1500),
        "exited before the report timeout: {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(15), "exit took {elapsed:?}");
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

/// CLI-1: list / logs は引数の過不足・未知オプションで使い方エラー（2）。stdout は空。
#[test]
fn cli1_list_logs_usage_errors() {
    for a in [
        &["list", "extra"][..],
        &["list", "--all"],
        &["logs"],
        &["logs", "a", "b"],
        &["logs", "--x", "a"],
        &["logs", "-f", "a"],
        &["logs", "-n", "1", "a"],
        &["logs", "--tail"],
        &["logs", "--tail", "x", "a"],
        &["logs", "--tail", "1000001", "a"],
        &["logs", "--stream", "bogus", "a"],
        &["logs", "--follow", "--follow", "a"],
    ] {
        assert_failure(&run(a), 2, USAGE_JSON);
    }
}

/// CLI-1・SUP-11(#1903): state は ID をちょうど 1 つ受け、過不足・未知オプションは使い方エラー（2）。stdout は空。
#[test]
fn cli1_state_usage_errors() {
    for a in [
        &["state"][..],
        &["state", "a", "b"],
        &["state", "--bogus", "a"],
        &["state", "--json", "a"],
    ] {
        assert_failure(&run(a), 2, USAGE_JSON);
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
        // `--read-only` は値を取らず 1 回まで(CLI-1・SUP-12・#2828)。
        &[
            "create",
            "--read-only",
            "--read-only",
            "--bundle",
            "/b",
            "c1",
        ],
        &["create", "--read-only=true", "--bundle", "/b", "c1"],
        &["create", "--read-only", "true", "--bundle", "/b", "c1"],
        &["start"],
        &["start", "a", "b"],
        &["--root"],
    ] {
        assert_failure(&run(a), 2, USAGE_JSON);
    }
}

/// CLI-1: stop / kill / delete は引数の過不足・未知オプション・`--force` 重複で使い方エラー（2）。
#[test]
fn cli1_stop_delete_usage_errors() {
    for a in [
        &["stop"][..],
        &["stop", "a", "b"],
        &["stop", "--force", "c1"],
        &["kill"],
        &["kill", "a", "b", "c"],
        &["kill", "--x", "c1"],
        &["kill", "-9", "c1"],
        &["delete"],
        &["delete", "--x", "c1"],
        &["delete", "--force", "--force", "c1"],
        &["delete", "a", "b"],
    ] {
        assert_failure(&run(a), 2, USAGE_JSON);
    }
}

/// CLI-1・NET-6（#3066）: network は引数の過不足・未知のサブコマンド・未知オプションで使い方エラー（2）。
/// グローバルの `--pasta-path` は create 以外では使い方エラーのまま。
#[test]
fn cli1_net6_network_usage_errors() {
    for a in [
        &["network"][..],
        &["network", "bogus"],
        &["network", "create"],
        &["network", "create", "a", "b"],
        &["network", "create", "--x", "a"],
        &["network", "rm"],
        &["network", "ls", "x"],
    ] {
        assert_failure(&run(a), 2, USAGE_JSON);
    }
    // create 以外へのグローバル `--pasta-path` は別の固定文言で使い方エラー（既存の規則）。
    assert_eq!(
        run(&["--pasta-path", "/x", "network", "ls"]).status.code(),
        Some(2)
    );
}

/// `parent` 配下に一意名のディレクトリを排他的に作る（既存パスは削除も採用もしない）。
///
/// 共有 /tmp 上の推測可能な固定名を削除・再利用すると、競合で置かれた symlink を root が辿りうる。
/// PID・時刻・試行番号の一意名を `create_dir` で作り、衝突時だけ名前を変える（#2324・SEC-2）。
fn exclusive_dir(parent: &std::path::Path, prefix: &str) -> std::path::PathBuf {
    for attempt in 0..16u32 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let p = parent.join(format!("{prefix}-{}-{nanos}-{attempt}", std::process::id()));
        #[cfg(unix)]
        let created = {
            use std::os::unix::fs::DirBuilderExt as _;
            // 作成時から 0700 にし、chmod までの隙間で他ユーザーが書き込めないようにする。
            std::fs::DirBuilder::new().mode(0o700).create(&p)
        };
        #[cfg(not(unix))]
        let created = std::fs::create_dir(&p);
        match created {
            Ok(()) => return p,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => panic!("exclusively create {}: {e}", p.display()),
        }
    }
    panic!("could not exclusively create a dir for {prefix}");
}

// 一時領域の親を tmpfiles の flock 走査から守る共有部品（#3026・CORE-5・REPAIR-12）。
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

// kill 後の回収を期限つきにする共有補助（#3303・REPAIR-5）。
#[path = "../../core/tests/support/reap.rs"]
mod reap;

/// 一意な一時ディレクトリ（Drop で削除）。第 2 フィールドは tmpfiles の flock 走査から守る親で、
/// 最後のフィールドのため `Drop` の削除の後に消える（#3026）。
struct TmpDir(
    std::path::PathBuf,
    #[allow(dead_code)] scratch_root::ScratchDir, // 保持が目的（drop で親を消す）
);

impl TmpDir {
    fn new(tag: &str) -> Self {
        let scratch =
            scratch_root::ScratchDir::new("fc-cli-bin", std::time::Duration::from_secs(10));
        let tmp = scratch.path().to_path_buf();
        let p = exclusive_dir(&tmp, &format!("fc-cli-bin-{tag}"));
        // 状態ルートの祖先は group / other 書き込み不可でなければならない（umask に依存せず 0700 に固定）。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        Self(p, scratch)
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

/// 実バイナリを `CARGO_TARGET_TMPDIR` 配下の一意なディレクトリへ置き直す（hard link、失敗したらコピー）。
///
/// `start` は CLI 自身の実体パスの隣の固定名 `fandhe-container-supervisor` を起動するため、`target/debug/` に
/// 兄弟の supervisor bin があるかどうかに結果が左右されないようにする（#1718）。
#[cfg(target_os = "linux")]
fn isolated_cli_dir(tag: &str) -> std::path::PathBuf {
    let dir = exclusive_dir(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        &format!("fc-cli-iso-{tag}"),
    );
    let dst = dir.join("fandhe-container");
    let src = env!("CARGO_BIN_EXE_fandhe-container");
    if std::fs::hard_link(src, &dst).is_err() {
        std::fs::copy(src, &dst).expect("copy cli");
    }
    dir
}

/// 置き直した CLI を起動する（[`run_exe_env`] の薄い別名）。
#[cfg(target_os = "linux")]
fn run_isolated(exe: &std::path::Path, args: &[&str]) -> Output {
    run_exe_env(exe, args, &[])
}

/// 状態ルートに bundle と Created のコンテナ `c1` を作る。bundle の絶対パスを返す。
#[cfg(target_os = "linux")]
fn prepare_c1(tmp: &TmpDir, cli: &std::path::Path) -> (std::path::PathBuf, String) {
    let bundle = tmp.0.join("bundle");
    std::fs::create_dir(&bundle).expect("bundle");
    std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
    std::fs::write(
        bundle.join("config.json"),
        r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .expect("config");
    let root = tmp.0.join("state");
    let root_s = root.to_str().expect("utf8").to_string();
    let out = run_isolated(
        cli,
        &[
            "--root",
            &root_s,
            "create",
            "--bundle",
            bundle.to_str().expect("utf8"),
            "c1",
        ],
    );
    assert_failure_free(&out);
    (root, root_s)
}

/// 固定名のフェイクの supervisor（シェルスクリプト）を `dir` に置く。作成と chmod は子プロセスで行い、
/// テストのプロセスが書き込み用の fd を持たないようにする（ETXTBSY の回避）。
#[cfg(target_os = "linux")]
fn install_fake_supervisor(dir: &std::path::Path, body: &str) {
    install_fake_exe(dir, "fandhe-container-supervisor", body);
}

/// 固定名 `name` のフェイクの実行ファイル（シェルスクリプト）を `dir` に置く。
#[cfg(target_os = "linux")]
fn install_fake_exe(dir: &std::path::Path, name: &str, body: &str) {
    let path = dir.join(name);
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg("cat > \"$1\" && chmod 755 \"$1\"")
        .arg("install-fake")
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin
                .take()
                .expect("stdin")
                .write_all(format!("#!/bin/sh\n{body}\n").as_bytes())?;
            // REPAIR-5: 無期限の wait を避け、期限付きで回収する（超過時は kill して None）。
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Some(st) = c.try_wait()? {
                    return Ok(Some(st));
                }
                if Instant::now() >= deadline {
                    let _ = c.kill();
                    // kill 後の回収にも有限の猶予（5 秒）を設ける。
                    let grace = Instant::now() + Duration::from_secs(5);
                    while Instant::now() < grace {
                        if c.try_wait()?.is_some() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })
        .expect("install fake supervisor")
        .expect("install fake supervisor timed out (REPAIR-5)");
    assert!(status.success());
}

/// 偽の systemd-run の本体。先頭 6 引数が `USER_SCOPE_WRAPPER_ARGS` と一致しなければ ERR を報告し、一致すれば
/// argv と環境を記録して、本物と同じく残りのコマンドを同じプロセスで exec する（#2081）。
#[cfg(target_os = "linux")]
const FAKE_SYSTEMD_RUN_BODY: &str = r#"d=$(dirname "$0")
[ "$1 $2 $3 $4 $5 $6" = "--user --scope --quiet -p Delegate=yes --" ] || { printf 'FCSUP1 ERR INTERNAL 1 badwrapper\n'; exit 0; }
printf '%s\n' "$@" > "$d/wrapper.argv"
env > "$d/wrapper.env"
shift 6
exec "$@""#;

/// 偽の systemd-run と偽の user マネージャのソケット（`<xdg>/systemd/private`）。GitHub ホステッド runner や
/// `make docker-ci` には user マネージャが無いため、既定集合の start の結合試験はこれで包み込みを通す（#2081）。
#[cfg(target_os = "linux")]
struct FakeScope {
    systemd_run: std::path::PathBuf,
    xdg: std::path::PathBuf,
    _listener: std::os::unix::net::UnixListener,
}

#[cfg(target_os = "linux")]
impl FakeScope {
    fn new(dir: &std::path::Path, tmp: &TmpDir) -> Self {
        install_fake_exe(dir, "fake-systemd-run", FAKE_SYSTEMD_RUN_BODY);
        let xdg = tmp.0.join("xdg");
        std::fs::create_dir(&xdg).expect("mkdir xdg");
        std::fs::create_dir(xdg.join("systemd")).expect("mkdir xdg/systemd");
        let listener = std::os::unix::net::UnixListener::bind(xdg.join("systemd").join("private"))
            .expect("bind fake user manager socket");
        Self {
            systemd_run: dir.join("fake-systemd-run"),
            xdg,
            _listener: listener,
        }
    }

    /// 差し替え口と `XDG_RUNTIME_DIR` を渡して CLI を起動する。
    fn run(
        &self,
        exe: &std::path::Path,
        args: &[&str],
        extra: &[(&str, &std::ffi::OsStr)],
    ) -> Output {
        let mut envs: Vec<(&str, &std::ffi::OsStr)> = vec![
            (
                "FANDHE_CONTAINER_TEST_SYSTEMD_RUN",
                self.systemd_run.as_os_str(),
            ),
            ("XDG_RUNTIME_DIR", self.xdg.as_os_str()),
        ];
        envs.extend_from_slice(extra);
        run_exe_env(exe, args, &envs)
    }
}

/// CLI-1・OCI-4・ERR-2: Linux で create → 状態ファイル作成（0）、重複は 4、未作成 start は 3。
/// 作成済み start は、CLI の隣に supervisor が無ければ FAILED_PRECONDITION（5。#1718）で、
/// 状態は Created のまま一覧に出る（Running を残さない。#1541）。
#[cfg(target_os = "linux")]
#[test]
fn cli1_create_start_flow_on_linux() {
    let tmp = TmpDir::new("flow");
    let dir = isolated_cli_dir("flow");
    let cli = dir.join("fandhe-container");
    let (root, root_s) = prepare_c1(&tmp, &cli);
    assert!(root.join("c1").join("state.json").exists());
    let bundle_s = tmp.0.join("bundle");
    let bundle_s = bundle_s.to_str().expect("utf8");

    let out = run_isolated(
        &cli,
        &["--root", &root_s, "create", "--bundle", bundle_s, "c1"],
    );
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(
        op_and_code(&out),
        ("create".into(), "ALREADY_EXISTS".into())
    );

    let out = run_isolated(&cli, &["--root", &root_s, "start", "nope"]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(op_and_code(&out), ("start".into(), "NOT_FOUND".into()));

    let out = run_isolated(&cli, &["--root", &root_s, "start", "c1"]);
    assert_eq!(out.status.code(), Some(5));
    assert_eq!(
        op_and_code(&out),
        ("start".into(), "FAILED_PRECONDITION".into())
    );
    assert!(out.stdout.is_empty());

    let out = run_isolated(&cli, &["--root", &root_s, "list"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "ID\tSTATUS\tPID\nc1\tcreated\t-\n"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// SEC-4・OCI-4・CLI-1（#2480）: 実バイナリの create が `mounts[].destination`（遡り・rootfs 全体・相対 `..`）を
/// INVALID_ARGUMENT（2）で拒否し、状態ルートの `@audit.log` に mount 層の記録が 1 件ずつ残る。
/// 正常な create は `@audit.log` を作らない。
#[cfg(target_os = "linux")]
#[test]
fn sec4_2480_create_rejected_destination_is_audited() {
    let tmp = TmpDir::new("audit-dest");
    let dir = isolated_cli_dir("audit-dest");
    let cli = dir.join("fandhe-container");
    let root = tmp.0.join("state");
    let root_s = root.to_str().expect("utf8").to_string();
    let dests = ["/../..", "/", "run/../../.."];
    for (n, dest) in dests.iter().enumerate() {
        let bundle = tmp.0.join(format!("bundle{n}"));
        std::fs::create_dir(&bundle).expect("bundle");
        std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
        let config = format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs"}},"process":{{"user":{{"uid":0,"gid":0}},"args":["/bin/echo","it"],"cwd":"/"}},"mounts":[{{"destination":"{dest}","type":"bind","source":"/tmp"}}]}}"#
        );
        std::fs::write(bundle.join("config.json"), config).expect("config");
        let id = format!("c{n}");
        let out = run_isolated(
            &cli,
            &[
                "--root",
                &root_s,
                "create",
                "--bundle",
                bundle.to_str().expect("utf8"),
                &id,
            ],
        );
        assert_eq!(out.status.code(), Some(2), "dest={dest}");
        assert_eq!(
            op_and_code(&out),
            ("create".into(), "INVALID_ARGUMENT".into()),
            "dest={dest}"
        );
        assert!(out.stdout.is_empty());
    }
    let log = std::fs::read_to_string(root.join("@audit.log")).expect("audit log");
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), dests.len(), "{log}");
    for (n, line) in lines.iter().enumerate() {
        assert!(line.contains("\"layer\":\"mount\""), "{line}");
        assert!(line.contains("\"path\":null"), "{line}");
        assert!(
            line.contains(&format!("\"container_id\":\"c{n}\"")),
            "{line}"
        );
    }

    // 正常な create は記録を増やさない。
    let ok_tmp = TmpDir::new("audit-ok");
    let (ok_root, _) = prepare_c1(&ok_tmp, &cli);
    assert!(!ok_root.join("@audit.log").exists());
    let _ = std::fs::remove_dir_all(dir);
}

/// SUP-1・CLI-1・ERR-2: 同じディレクトリのフェイクの supervisor が OK を報告すれば start は 0 で何も出さず、
/// ERR（UNIMPLEMENTED）を報告すれば 8 と構造化エラーになる。どちらも CLI は状態を書かず、一覧は created のまま。
#[cfg(target_os = "linux")]
#[test]
fn sup1_start_delegates_to_sibling_supervisor_on_linux() {
    let tmp = TmpDir::new("sup");
    let dir = isolated_cli_dir("sup");
    let cli = dir.join("fandhe-container");
    let (_root, root_s) = prepare_c1(&tmp, &cli);
    let scope = FakeScope::new(&dir, &tmp);

    install_fake_supervisor(&dir, "printf 'FCSUP1 OK 4242\\n'; exec sleep 1");
    let out = scope.run(&cli, &["--root", &root_s, "start", "c1"], &[]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    assert!(
        out.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    install_fake_supervisor(
        &dir,
        "printf 'FCSUP1 ERR UNIMPLEMENTED 8 production process launcher is not available yet\\n'",
    );
    let out = scope.run(&cli, &["--root", &root_s, "start", "c1"], &[]);
    assert_eq!(out.status.code(), Some(8));
    assert_eq!(op_and_code(&out), ("start".into(), "UNIMPLEMENTED".into()));
    assert!(out.stdout.is_empty());

    let out = run_isolated(&cli, &["--root", &root_s, "list"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "ID\tSTATUS\tPID\nc1\tcreated\t-\n"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// SEC-4・CORE-5・ERR-1・SUP-1・CLI-1（#2716）: launch の `R` の後の `execveat` の失敗は、supervisor が errno の分類
/// （NOT_FOUND / PERMISSION_DENIED / INVALID_ARGUMENT）つきの固定文言の `ERR` として報告し、CLI はその終了コード
/// （3 / 6 / 2）と構造化エラーの `op`・`code`・`message` で表示する。stdout は空で、状態は書かず created のまま。
#[cfg(target_os = "linux")]
#[test]
fn sec4_2716_start_exec_stage_failure_is_shown_with_code_and_fixed_message() {
    let tmp = TmpDir::new("sup2716");
    let dir = isolated_cli_dir("sup2716");
    let cli = dir.join("fandhe-container");
    let (_root, root_s) = prepare_c1(&tmp, &cli);
    let scope = FakeScope::new(&dir, &tmp);

    for (code, exit) in [
        ("NOT_FOUND", 3),
        ("PERMISSION_DENIED", 6),
        ("INVALID_ARGUMENT", 2),
    ] {
        install_fake_supervisor(
            &dir,
            &format!(
                "printf 'FCSUP1 ERR {code} {exit} container launch failed in the Exec stage\\n'"
            ),
        );
        let out = scope.run(&cli, &["--root", &root_s, "start", "c1"], &[]);
        assert_eq!(out.status.code(), Some(exit), "{code}");
        assert_eq!(op_and_code(&out), ("start".into(), code.into()));
        assert!(out.stdout.is_empty(), "{code}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("\"message\":\"container launch failed in the Exec stage\""),
            "{stderr}"
        );
    }

    let out = run_isolated(&cli, &["--root", &root_s, "list"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "ID\tSTATUS\tPID\nc1\tcreated\t-\n"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// `PATH` 上の symlink（例: `/usr/local/bin/fandhe-container` -> 配置先の CLI）を作る。
/// symlink の置き場所 `bin_dir` は呼び出し側が用意する。
#[cfg(target_os = "linux")]
fn link_cli_into(bin_dir: &std::path::Path, real_cli: &std::path::Path) -> std::path::PathBuf {
    let link = bin_dir.join("fandhe-container");
    std::os::unix::fs::symlink(real_cli, &link).expect("symlink");
    link
}

/// SUP-14・CLI-1・CORE-6: `PATH` 上の symlink から起動しても、CLI は実体のディレクトリの supervisor を起動する
/// （#2068）。Linux の `current_exe()` は `/proc/self/exe` の解決結果（実体のパス）で、argv[0] や symlink の置き場所には
/// 依らない。symlink 側のディレクトリに置いたおとりの supervisor（ERR を返す）は使われない。
/// 絶対パスでの起動と、`PATH` を symlink のディレクトリだけにした名前での起動の両方で確かめる。
#[cfg(target_os = "linux")]
#[test]
fn sup14_start_via_path_symlink_uses_supervisor_beside_real_exe() {
    let tmp = TmpDir::new("sup14a");
    let dir = isolated_cli_dir("sup14a");
    let cli = dir.join("fandhe-container");
    let (_root, root_s) = prepare_c1(&tmp, &cli);
    install_fake_supervisor(&dir, "printf 'FCSUP1 OK 4242\\n'; exec sleep 1");
    let scope = FakeScope::new(&dir, &tmp);

    let bin = tmp.0.join("bin");
    std::fs::create_dir(&bin).expect("mkdir bin");
    let link = link_cli_into(&bin, &cli);
    install_fake_supervisor(
        &bin,
        "printf 'FCSUP1 ERR UNIMPLEMENTED 8 decoy beside the symlink must not be used\\n'",
    );

    // (a) symlink の絶対パスで起動する。
    let out = scope.run(&link, &["--root", &root_s, "start", "c1"], &[]);
    assert_eq!(out.status.code(), Some(0), "{:?}", out.stderr);
    assert!(out.stdout.is_empty());
    assert!(
        out.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // (b) `PATH` を symlink のディレクトリだけにして、名前 `fandhe-container` で起動する。
    let out = scope.run(
        std::path::Path::new("fandhe-container"),
        &["--root", &root_s, "start", "c1"],
        &[("PATH", bin.as_os_str())],
    );
    assert_eq!(out.status.code(), Some(0), "{:?}", out.stderr);
    assert!(out.stdout.is_empty());
    assert!(
        out.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // CLI は start で状態を書かない（#1541）。
    let out = run_isolated(&cli, &["--root", &root_s, "list"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "ID\tSTATUS\tPID\nc1\tcreated\t-\n"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// 起動された偽の実行ファイル（ランチャーまたは supervisor）が自分の pgrp・stdio を `<dir>/<tag>.obs` へ記録して OK を報告する本体。
/// 記録は具体値（`pgrp_is_self`・`pgrp_eq_parent`・fd 0〜2 の行き先・tty かどうか）で照合する（SUP-14・#2442）。
#[cfg(target_os = "linux")]
fn observing_body(tag: &str) -> String {
    format!(
        r#"d=$(dirname "$0")
pg=$(sed 's/.*) //' /proc/$$/stat | cut -d' ' -f3)
ppg=$(sed 's/.*) //' /proc/$PPID/stat | cut -d' ' -f3)
s0=$(readlink /proc/$$/fd/0); s1=$(readlink /proc/$$/fd/1); s2=$(readlink /proc/$$/fd/2)
case "$s1" in pipe:*) s1=pipe;; esac
t0=0; t1=0; t2=0
[ -t 0 ] && t0=1; [ -t 1 ] && t1=1; [ -t 2 ] && t2=1
pis=0; [ "$pg" = "$$" ] && pis=1
peq=0; [ "$pg" = "$ppg" ] && peq=1
printf 'pgrp_is_self=%s pgrp_eq_parent=%s stdin=%s stdout=%s stderr=%s tty=%s%s%s\n' "$pis" "$peq" "$s0" "$s1" "$s2" "$t0" "$t1" "$t2" > "$d/{tag}.obs"
printf 'FCSUP1 OK 4242\n'; exec sleep 1"#
    )
}

/// SUP-14・CLI-1・CORE-6・SEC-1: 実体の隣に（信頼できる）ランチャーがあれば rootful のインストールとみなし、
/// systemd-run の後ろにランチャーを包んで起動する（#2442）。ランチャーは `process_group(0)` なし（CLI のグループに残り
/// リーダーでない）で、stdio は null / pipe / null（pty ではない）。隣のおとりの supervisor は使われない。
#[cfg(target_os = "linux")]
#[test]
fn sup14_start_selects_launcher_beside_real_exe() {
    let tmp = TmpDir::new("sup14l");
    let dir = isolated_cli_dir("sup14l");
    let cli = dir.join("fandhe-container");
    let (_root, root_s) = prepare_c1(&tmp, &cli);
    install_fake_supervisor(&dir, &observing_body("supervisor"));
    install_fake_exe(
        &dir,
        "fandhe-container-launcher",
        &observing_body("launcher"),
    );
    let scope = FakeScope::new(&dir, &tmp);

    let out = scope.run(&cli, &["--root", &root_s, "start", "c1"], &[]);
    assert_eq!(out.status.code(), Some(0), "{:?}", out.stderr);
    assert!(out.stdout.is_empty());
    assert!(
        out.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    let argv = std::fs::read_to_string(dir.join("wrapper.argv")).expect("wrapper.argv");
    let lines: Vec<&str> = argv.lines().collect();
    assert_eq!(
        lines.get(6).copied(),
        dir.join("fandhe-container-launcher").to_str(),
        "{argv}"
    );
    assert_eq!(lines.get(7).copied(), Some("start"));
    let obs = std::fs::read_to_string(dir.join("launcher.obs")).expect("launcher.obs");
    assert_eq!(
        obs,
        "pgrp_is_self=0 pgrp_eq_parent=1 stdin=/dev/null stdout=pipe stderr=/dev/null tty=000\n"
    );
    assert!(!dir.join("supervisor.obs").exists());
    let _ = std::fs::remove_dir_all(dir);
}

/// SUP-14・CLI-1: 隣にランチャーが無い（rootless のインストール）なら従来の直接経路のまま。supervisor は
/// `process_group(0)` でグループのリーダーになる（端末の SIGINT / SIGHUP が届かない性質の維持）。#2442
#[cfg(target_os = "linux")]
#[test]
fn sup14_start_without_launcher_keeps_direct_route() {
    let tmp = TmpDir::new("sup14d");
    let dir = isolated_cli_dir("sup14d");
    let cli = dir.join("fandhe-container");
    let (_root, root_s) = prepare_c1(&tmp, &cli);
    install_fake_supervisor(&dir, &observing_body("supervisor"));
    let scope = FakeScope::new(&dir, &tmp);

    let out = scope.run(&cli, &["--root", &root_s, "start", "c1"], &[]);
    assert_eq!(out.status.code(), Some(0), "{:?}", out.stderr);
    let argv = std::fs::read_to_string(dir.join("wrapper.argv")).expect("wrapper.argv");
    assert_eq!(
        argv.lines().nth(6),
        dir.join("fandhe-container-supervisor").to_str(),
        "{argv}"
    );
    let obs = std::fs::read_to_string(dir.join("supervisor.obs")).expect("supervisor.obs");
    assert_eq!(
        obs,
        "pgrp_is_self=1 pgrp_eq_parent=0 stdin=/dev/null stdout=pipe stderr=/dev/null tty=000\n"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// SUP-14・SEC-1・ERR-2: 隣のランチャーが信頼条件を満たさない（group 書き込み可）なら、直接経路へ落とさず
/// FAILED_PRECONDITION（5）で spawn の前に止まる。systemd-run もおとりの supervisor も呼ばれず、状態は Created のまま。#2442
#[cfg(target_os = "linux")]
#[test]
fn sup14_start_rejects_untrusted_launcher_without_fallback() {
    let tmp = TmpDir::new("sup14u");
    let dir = isolated_cli_dir("sup14u");
    let cli = dir.join("fandhe-container");
    let (_root, root_s) = prepare_c1(&tmp, &cli);
    install_fake_supervisor(&dir, &observing_body("supervisor"));
    install_fake_exe(
        &dir,
        "fandhe-container-launcher",
        &observing_body("launcher"),
    );
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.join("fandhe-container-launcher"),
            std::fs::Permissions::from_mode(0o775),
        )
        .expect("chmod");
    }
    let scope = FakeScope::new(&dir, &tmp);

    let out = scope.run(&cli, &["--root", &root_s, "start", "c1"], &[]);
    assert_eq!(out.status.code(), Some(5));
    assert_eq!(
        op_and_code(&out),
        ("start".into(), "FAILED_PRECONDITION".into())
    );
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("privileged launcher is not a trusted executable"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!dir.join("wrapper.argv").exists());
    assert!(!dir.join("supervisor.obs").exists());
    assert!(!dir.join("launcher.obs").exists());
    let out = run_isolated(&cli, &["--root", &root_s, "list"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "ID\tSTATUS\tPID\nc1\tcreated\t-\n"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// SUP-14・ERR-2: 実体のディレクトリに supervisor が無ければ、symlink の隣に supervisor があっても使わず
/// FAILED_PRECONDITION（5）で止まる（symlink の置き場所を見ていないことの判別。#2068）。
#[cfg(target_os = "linux")]
#[test]
fn sup14_start_via_symlink_ignores_supervisor_beside_link() {
    let tmp = TmpDir::new("sup14b");
    let dir = isolated_cli_dir("sup14b");
    let cli = dir.join("fandhe-container");
    let (_root, root_s) = prepare_c1(&tmp, &cli);

    let bin = tmp.0.join("bin");
    std::fs::create_dir(&bin).expect("mkdir bin");
    let link = link_cli_into(&bin, &cli);
    // 実体側には supervisor を置かない。symlink 側にだけ、使われれば成功してしまう supervisor を置く。
    install_fake_supervisor(&bin, "printf 'FCSUP1 OK 4242\\n'; exec sleep 1");

    let out = run_exe_env(&link, &["--root", &root_s, "start", "c1"], &[]);
    assert_eq!(out.status.code(), Some(5));
    assert_eq!(
        op_and_code(&out),
        ("start".into(), "FAILED_PRECONDITION".into())
    );
    assert!(out.stdout.is_empty());

    let out = run_isolated(&cli, &["--root", &root_s, "list"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "ID\tSTATUS\tPID\nc1\tcreated\t-\n"
    );
    let _ = std::fs::remove_dir_all(dir);
}
/// CLI-1・OCI-6・ERR-2: Linux で stop / delete が core を呼ぶ。未 create は 3、Created の stop は 5、
/// delete は 0 で状態ファイルを消し、2 回目は 3。不正 ID は core 到達前に 2（op は kill / delete）。
#[cfg(target_os = "linux")]
#[test]
fn cli1_stop_delete_flow_on_linux() {
    let tmp = TmpDir::new("stopdel");
    let bundle = tmp.0.join("bundle");
    std::fs::create_dir(&bundle).expect("bundle");
    std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
    std::fs::write(
        bundle.join("config.json"),
        r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .expect("config");
    let root = tmp.0.join("state");
    let root_s = root.to_str().expect("utf8");
    let bundle_s = bundle.to_str().expect("utf8");

    let out = run(&["--root", root_s, "stop", "nope"]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(op_and_code(&out), ("kill".into(), "NOT_FOUND".into()));
    let out = run(&["--root", root_s, "delete", "nope"]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(op_and_code(&out), ("delete".into(), "NOT_FOUND".into()));

    let out = run(&["--root", root_s, "kill", "nope"]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(op_and_code(&out), ("kill".into(), "NOT_FOUND".into()));

    for (cmd, op) in [("stop", "kill"), ("kill", "kill"), ("delete", "delete")] {
        let out = run(&["--root", root_s, cmd, "a/b"]);
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(op_and_code(&out), (op.into(), "INVALID_ARGUMENT".into()));
    }

    assert_failure_free(&run(&[
        "--root", root_s, "create", "--bundle", bundle_s, "c1",
    ]));
    let out = run(&["--root", root_s, "stop", "c1"]);
    assert_eq!(out.status.code(), Some(5));
    assert_eq!(
        op_and_code(&out),
        ("kill".into(), "FAILED_PRECONDITION".into())
    );
    assert!(root.join("c1").join("state.json").exists());

    // kill: Created（pid なし）は 5。不正なシグナルは状態を触る前に 2（固定文言）。
    for argv in [
        &["--root", root_s, "kill", "c1"][..],
        &["--root", root_s, "kill", "c1", "KILL"],
    ] {
        let out = run(argv);
        assert_eq!(out.status.code(), Some(5), "{argv:?}");
        assert_eq!(
            op_and_code(&out),
            ("kill".into(), "FAILED_PRECONDITION".into())
        );
    }
    let out = run(&["--root", root_s, "kill", "c1", "BOGUS"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "{\"op\":\"kill\",\"code\":\"INVALID_ARGUMENT\",\"message\":\"signal is invalid\"}\n"
    );
    assert!(root.join("c1").join("state.json").exists());

    assert_failure_free(&run(&["--root", root_s, "delete", "c1"]));
    assert!(!root.join("c1").join("state.json").exists());
    let out = run(&["--root", root_s, "delete", "c1"]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(op_and_code(&out), ("delete".into(), "NOT_FOUND".into()));

    // pid なしの Created は force でも削除できる。
    assert_failure_free(&run(&[
        "--root", root_s, "create", "--bundle", bundle_s, "c1",
    ]));
    assert_failure_free(&run(&["--root", root_s, "delete", "--force", "c1"]));
    assert!(!root.join("c1").join("state.json").exists());
}

/// REPAIR-4・ERR-2・#2067: delete は core の delete の成功後に supervisor ログを消し、成功時の stderr は空のまま。
/// `@supervisor-logs` があっても list はコンテナ ID として扱わない。delete が失敗（未 create）ならログに触れない。
#[cfg(target_os = "linux")]
#[test]
fn repair4_delete_removes_supervisor_log() {
    let tmp = TmpDir::new("suplog");
    let bundle = tmp.0.join("bundle");
    std::fs::create_dir(&bundle).expect("bundle");
    std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
    std::fs::write(
        bundle.join("config.json"),
        r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .expect("config");
    let root = tmp.0.join("state");
    let root_s = root.to_str().expect("utf8");
    let bundle_s = bundle.to_str().expect("utf8");
    let id = fandhe_container_core::traits::ContainerId::new("c1").expect("id");
    let logs = root.join("@supervisor-logs");

    assert_failure_free(&run(&[
        "--root", root_s, "create", "--bundle", bundle_s, "c1",
    ]));
    // supervisor が書いたログの代わりに、同じ入口でログ（現在ログと世代 1）を用意する。
    {
        use std::io::Write as _;
        let mut w = fandhe_container_supervisor::supervisor_log::open(&root, &id).expect("open");
        w.write_all(b"{}\n").expect("write");
        w.flush().expect("flush");
    }
    // 並行する他の試験の子プロセス起動（fork から exec まで）が、直前に閉じた書き手の flock の記述子を
    // 一瞬だけ継承して保持し得る。その間の open は FailedPrecondition になるため、期限つきで再試行する（REPAIR-5）。
    let reopen_deadline = std::time::Instant::now() + Duration::from_secs(10);
    let reopened = loop {
        match fandhe_container_supervisor::supervisor_log::open(&root, &id) {
            Ok(w) => break w,
            Err(e)
                if e.code() == fandhe_container_core::traits::ErrorCode::FailedPrecondition
                    && std::time::Instant::now() < reopen_deadline =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("reopen: {e:?}"),
        }
    };
    drop(reopened);
    assert!(logs.join("c1.log").exists());
    assert!(logs.join("c1.log.1").exists());

    let out = run(&["--root", root_s, "list"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "ID\tSTATUS\tPID\nc1\tcreated\t-\n"
    );

    // 未 create の ID の delete は失敗し、c1 のログには触れない。
    assert_eq!(
        run(&["--root", root_s, "delete", "nope"]).status.code(),
        Some(3)
    );
    assert!(logs.join("c1.log").exists());

    let out = run(&["--root", root_s, "delete", "c1"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty(), "stderr: {:?}", out.stderr);
    assert!(out.stdout.is_empty());
    let left: Vec<_> = std::fs::read_dir(&logs).expect("dir").collect();
    assert!(left.is_empty(), "left: {left:?}");
}

/// bundle を作り、`--root` 配下に c1 / c2 を create する（#2446 の試験用）。root の絶対パスを返す。
#[cfg(target_os = "linux")]
fn create_two_containers(tmp: &TmpDir) -> std::path::PathBuf {
    let bundle = tmp.0.join("bundle");
    std::fs::create_dir(&bundle).expect("bundle");
    std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
    std::fs::write(
        bundle.join("config.json"),
        r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .expect("config");
    let root = tmp.0.join("state");
    let root_s = root.to_str().expect("utf8");
    let bundle_s = bundle.to_str().expect("utf8");
    for id in ["c1", "c2"] {
        assert_failure_free(&run(&[
            "--root", root_s, "create", "--bundle", bundle_s, id,
        ]));
    }
    root
}

/// コンテナログの書き手（sink）を開いて 1 行書き、flush する。再 open の競合は期限つきで再試行する（REPAIR-5）。
#[cfg(target_os = "linux")]
fn open_container_log_sink(
    root: &std::path::Path,
    name: &str,
) -> fandhe_container_supervisor::logs::RotatingFileSink {
    use fandhe_container_supervisor::logs::{
        LogSink as _, RotatingFileSink, StreamKind, container_log_dir,
        container_log_rotation_config,
    };
    use std::os::unix::fs::PermissionsExt as _;
    let dir = container_log_dir(root);
    std::fs::create_dir_all(&dir).expect("logdir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let id = fandhe_container_core::traits::ContainerId::new(name).expect("id");
    let deadline = Instant::now() + Duration::from_secs(10);
    let sink = loop {
        match RotatingFileSink::open(&dir, &id, container_log_rotation_config()) {
            Ok(s) => break s,
            Err(e)
                if e.code() == fandhe_container_core::traits::ErrorCode::FailedPrecondition
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("open sink: {e:?}"),
        }
    };
    sink.append(StreamKind::Stdout, format!("hello {name}").as_bytes())
        .expect("append");
    sink.flush().expect("flush");
    sink
}

#[cfg(target_os = "linux")]
fn sorted_dir_names(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// SUP-7・CLI-1・#2446: `delete` は対象 ID のコンテナログ（現在ログ・世代・ロック）だけを消し、他のコンテナのログは残す。
#[cfg(target_os = "linux")]
#[test]
fn sup7_delete_removes_container_logs_only_for_target() {
    let tmp = TmpDir::new("ctrlog");
    let root = create_two_containers(&tmp);
    let root_s = root.to_str().expect("utf8");
    let logs = fandhe_container_supervisor::logs::container_log_dir(&root);
    // c1 は世代 1 まで作る（2 回目の open で現在ログが世代へ退避される）。
    drop(open_container_log_sink(&root, "c1"));
    drop(open_container_log_sink(&root, "c1"));
    drop(open_container_log_sink(&root, "c2"));
    assert_eq!(
        sorted_dir_names(&logs),
        ["c1.log", "c1.log.1", "c1.log.lock", "c2.log", "c2.log.lock"]
    );

    // 未 create の ID の delete は失敗し、c1 のログには触れない。
    assert_eq!(
        run(&["--root", root_s, "delete", "nope"]).status.code(),
        Some(3)
    );
    assert_eq!(sorted_dir_names(&logs).len(), 5);

    let out = run(&["--root", root_s, "delete", "c1"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    assert!(out.stderr.is_empty(), "stderr: {:?}", out.stderr);
    assert_eq!(sorted_dir_names(&logs), ["c2.log", "c2.log.lock"]);

    let out = run(&["--root", root_s, "logs", "c2"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, b"stdout hello c2\n");
}

/// SUP-7・CLI-1・ERR-1・#2446: sink が生きていてコンテナログを消せないとき、delete は成功のまま
/// （状態は削除済み）で、構造化された警告 1 行を stderr に出し、ログは残す。
#[cfg(target_os = "linux")]
#[test]
fn sup7_delete_warns_when_container_log_is_locked() {
    let tmp = TmpDir::new("ctrlock");
    let root = create_two_containers(&tmp);
    let root_s = root.to_str().expect("utf8");
    let logs = fandhe_container_supervisor::logs::container_log_dir(&root);
    let sink = open_container_log_sink(&root, "c1");

    let out = run(&["--root", root_s, "delete", "c1"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "{\"level\":\"warn\",\"code\":\"FAILED_PRECONDITION\",\"reason\":\"sink_open_after_wait\",\"message\":\"container log removal failed; leftover logs may remain\"}\n"
    );
    assert_eq!(sorted_dir_names(&logs), ["c1.log", "c1.log.lock"]);
    let listed = run(&["--root", root_s, "list"]);
    assert_eq!(
        String::from_utf8_lossy(&listed.stdout),
        "ID\tSTATUS\tPID\nc2\tcreated\t-\n"
    );
    drop(sink);
}

/// REPAIR-4: 複数の CLI プロセスが同じ `FANDHE_CONTAINER_OP_LOG` へ並行に追記しても JSON 行が混ざらない。
///
/// 相対 bundle の create は core へ到達する前に失敗し（終了コード 2）、失敗 1 件の計測を追記する。
/// 16 スレッド × 4 回 = 64 プロセスを同時に走らせ、ログが「op_stats 行 + メタ行」の 64 組だけで
/// 構成されること（1 行に JSON が 2 つ並ばない・行が途切れない・未存在からの同時作成で落とさない）を照合する。
/// 計測のファイル出力は Linux の x86_64 / aarch64 のみ（他は出力しない。SEC-1）。
#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
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
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                barrier.wait();
                let outs = (0..ROUNDS)
                    .map(|_| {
                        run_env(
                            &["create", "--bundle", "rel/b", "c1"],
                            &[("FANDHE_CONTAINER_OP_LOG", log.as_os_str())],
                        )
                    })
                    .collect::<Vec<Output>>();
                let _ = tx.send(outs);
            });
            rx
        })
        .collect();
    // 各 worker の完了は有限期限で待つ（REPAIR-5）。1 回の起動は `run_env` が CHILD_TIMEOUT + REAP_TIMEOUT で
    // 打ち切るため、ROUNDS 回ぶんを上限とする。
    let worker_limit = (CHILD_TIMEOUT + 2 * REAP_TIMEOUT) * ROUNDS as u32;
    for rx in handles {
        let outs = rx
            .recv_timeout(worker_limit)
            .expect("workers must finish within the deadline");
        for out in outs {
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

/// OCI-5・SEC-4・CLI-1: Linux 以外の日常コマンドが fail-closed で終わった後の状態ルートの期待。
/// plugin 拒否の監査記録先（`@audit.log`）を作る際に、`FileStateStore::open` が macOS では状態ルートを
/// 0700 で作り、Windows（`Unimplemented`）では何も作らない。
#[cfg(not(target_os = "linux"))]
fn assert_state_root_after_fail_closed(root: &std::path::Path) {
    if cfg!(target_os = "macos") {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(root).expect("state root must be created on macOS");
            assert!(meta.is_dir());
            assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        }
    } else {
        assert!(!root.exists(), "state root must not be created on Windows");
    }
}

/// SEC-1・PLUG-4: Linux 以外では plugin 発見機構経由になり、候補なし（既定探索先が空）の fail-closed で
/// FAILED_PRECONDITION（5）。状態ルートは macOS では 0700 で作られ、Windows では作らない。
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
    assert_eq!(out.status.code(), Some(5));
    assert_eq!(
        op_and_code(&out),
        ("create".into(), "FAILED_PRECONDITION".into())
    );
    assert!(out.stdout.is_empty());
    assert_state_root_after_fail_closed(&root);
    // 引数不正は plugin 解決より先に 2 で弾く（3 OS 同一）。
    let out = run(&["create", "--bundle", "relative", "c1"]);
    assert_eq!(out.status.code(), Some(2));
}

/// SEC-1・PLUG-4: Linux 以外では stop / delete も plugin 候補なしの fail-closed で FAILED_PRECONDITION（5）。
#[cfg(not(target_os = "linux"))]
#[test]
fn sec1_stop_delete_fail_closed_off_linux() {
    let tmp = TmpDir::new("offlinux-sd");
    let root = tmp.0.join("state");
    for (cmd, op) in [("stop", "kill"), ("kill", "kill"), ("delete", "delete")] {
        let out = run(&["--root", root.to_str().expect("utf8"), cmd, "c1"]);
        assert_eq!(out.status.code(), Some(5));
        assert_eq!(op_and_code(&out), (op.into(), "FAILED_PRECONDITION".into()));
        assert!(out.stdout.is_empty());
    }
    assert_state_root_after_fail_closed(&root);
}

/// CLI-1・#1902: 不正なシグナルは OS を問わず状態ルートを開く前に INVALID_ARGUMENT（2）で拒否される。
#[test]
fn cli1_kill_invalid_signal_is_rejected_on_every_os() {
    let tmp = TmpDir::new("killbadsig");
    let root = tmp.0.join("state");
    let out = run(&[
        "--root",
        root.to_str().expect("utf8"),
        "kill",
        "c1",
        "BOGUS",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        op_and_code(&out),
        ("kill".into(), "INVALID_ARGUMENT".into())
    );
    assert!(!root.exists(), "the state root must not be created");
}

/// CLI-1・ERR-2: Linux で list は stdout にタブ区切りの一覧を出し（0 件はヘッダのみ・ID 昇順）、
/// logs は不正 ID が 2、未作成が 3、ログの無い対象は空の成功（0）、世代をまたぐログは古い順にバイト単位で出る（#1543）。
#[cfg(target_os = "linux")]
#[test]
fn cli1_list_logs_flow_on_linux() {
    let tmp = TmpDir::new("listlogs");
    let bundle = tmp.0.join("bundle");
    std::fs::create_dir(&bundle).expect("bundle");
    std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
    std::fs::write(
        bundle.join("config.json"),
        r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .expect("config");
    let root = tmp.0.join("state");
    let root_s = root.to_str().expect("utf8");
    let bundle_s = bundle.to_str().expect("utf8");

    let out = run(&["--root", root_s, "list"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ID\tSTATUS\tPID\n");
    assert!(out.stderr.is_empty());

    for id in ["b2", "a1"] {
        assert_failure_free(&run(&[
            "--root", root_s, "create", "--bundle", bundle_s, id,
        ]));
    }
    let out = run(&["--root", root_s, "list"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "ID\tSTATUS\tPID\na1\tcreated\t-\nb2\tcreated\t-\n"
    );
    assert!(out.stderr.is_empty());

    assert_failure(
        &run(&["--root", root_s, "logs", "missing"]),
        3,
        "{\"code\":\"NOT_FOUND\",\"message\":\"container not found\"}\n",
    );
    let out = run(&["--root", root_s, "logs", "a1"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    assert!(out.stderr.is_empty());
    // 世代をまたぐログ（supervisor が書く `@container-logs` と同じ配置）は古い順に連結される。
    let dir = fandhe_container_supervisor::logs::container_log_dir(&root);
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(&dir).expect("logdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    std::fs::write(dir.join("a1.log.1"), b"stdout one\n").expect("g1");
    std::fs::write(dir.join("a1.log"), b"stderr two\nstdout three\n").expect("cur");
    let out = run(&["--root", root_s, "logs", "a1"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, b"stdout one\nstderr two\nstdout three\n");
    assert!(out.stderr.is_empty());
    assert_failure(
        &run(&["--root", root_s, "logs", "a/b"]),
        2,
        "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"invalid argument\"}\n",
    );
}

/// コンテナログの書き手に 1 レコード足して flush する（logs のオプション試験用）。
#[cfg(target_os = "linux")]
fn append_record(
    sink: &fandhe_container_supervisor::logs::RotatingFileSink,
    stream: fandhe_container_supervisor::logs::StreamKind,
    line: &[u8],
) {
    use fandhe_container_supervisor::logs::LogSink as _;
    sink.append(stream, line).expect("append");
    sink.flush().expect("flush");
}

/// CLI-1・SUP-7・#2447: `--tail` / `--stream` / `--escape` の出力を具体値で照合する（終了コード 0・stderr は空）。
/// 追従は存在しないコンテナで NOT_FOUND（3）になり、待たずに終わる。
#[cfg(target_os = "linux")]
#[test]
fn cli1_logs_tail_stream_escape_outputs() {
    use fandhe_container_supervisor::logs::StreamKind;
    let tmp = TmpDir::new("logsopts");
    let root = create_two_containers(&tmp);
    let root_s = root.to_str().expect("utf8");
    let sink = open_container_log_sink(&root, "c1");
    append_record(&sink, StreamKind::Stderr, b"b\x1b[1m");
    append_record(&sink, StreamKind::Stdout, b"c");

    let cases: [(&[&str], &[u8]); 6] = [
        (
            &["logs", "c1"],
            b"stdout hello c1\nstderr b\x1b[1m\nstdout c\n",
        ),
        (
            &["logs", "--tail", "2", "c1"],
            b"stderr b\x1b[1m\nstdout c\n",
        ),
        (&["logs", "--tail", "0", "c1"], b""),
        (&["logs", "--stream", "stderr", "c1"], b"stderr b\x1b[1m\n"),
        (
            &["logs", "--escape", "--stream", "stderr", "c1"],
            b"stderr b^[[1m\n",
        ),
        (
            &["logs", "--tail", "1", "--stream", "stdout", "c1"],
            b"stdout c\n",
        ),
    ];
    for (args, expect) in cases {
        let mut full = vec!["--root", root_s];
        full.extend_from_slice(args);
        let out = run(&full);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert_eq!(out.stdout, expect, "{args:?}");
        assert!(out.stderr.is_empty(), "{args:?}");
    }
    drop(sink);

    let out = run(&["--root", root_s, "logs", "--follow", "nonexist"]);
    assert_failure(
        &out,
        3,
        "{\"code\":\"NOT_FOUND\",\"message\":\"container not found\"}\n",
    );
}

/// `logs --follow` の子プロセス。Drop で kill して回収する（試験の失敗で孤児を残さない。REPAIR-5）。
#[cfg(target_os = "linux")]
struct FollowChild {
    child: std::process::Child,
    rx: mpsc::Receiver<Vec<u8>>,
    got: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl FollowChild {
    /// `logs --follow c1` を起動する。`deadline_ms` は試験専用の期限の上書き。
    fn spawn(root: &std::path::Path, deadline_ms: u64) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fandhe-container"))
            .args([
                "--root",
                root.to_str().expect("utf8"),
                "logs",
                "--follow",
                "c1",
            ])
            .env_remove("FANDHE_CONTAINER_PLUGIN_PATH_SEARCH")
            .env(
                "FANDHE_CONTAINER_TEST_LOGS_FOLLOW_DEADLINE_MS",
                deadline_ms.to_string(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn logs --follow");
        let mut pipe = child.stdout.take().expect("stdout piped");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(n) = pipe.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            rx,
            got: Vec::new(),
        }
    }

    /// 出力が `len` バイトに届くまで待つ（期限つき。超えたら panic。REPAIR-5）。
    fn wait_len(&mut self, len: usize, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while self.got.len() < len {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "timed out: got {} of {len} bytes",
                self.got.len()
            );
            if let Ok(chunk) = self.rx.recv_timeout(left) {
                self.got.extend_from_slice(&chunk);
            }
        }
    }

    /// 追加の出力が来ないことを `quiet` の間確かめる（重複の検出）。
    fn assert_quiet(&mut self, quiet: Duration) {
        let until = Instant::now() + quiet;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            if let Ok(chunk) = self.rx.recv_timeout(left) {
                self.got.extend_from_slice(&chunk);
                panic!("unexpected extra output: {} bytes", chunk.len());
            }
        }
    }

    /// 終了を期限つきで待つ。
    fn wait_exit(&mut self, timeout: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(s) = self.child.try_wait().expect("try_wait") {
                return s;
            }
            assert!(Instant::now() < deadline, "logs --follow did not exit");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn stderr_text(&mut self) -> String {
        let mut s = String::new();
        if let Some(mut e) = self.child.stderr.take() {
            let _ = e.read_to_string(&mut s);
        }
        s
    }
}

#[cfg(target_os = "linux")]
impl Drop for FollowChild {
    fn drop(&mut self) {
        reap::reap_on_drop(&mut self.child);
    }
}

/// REPAIR-5・#2447: `--follow` は期限で終わり（0）、期限までに出した分は stdout に届く。
#[cfg(target_os = "linux")]
#[test]
fn repair5_logs_follow_ends_at_deadline() {
    let tmp = TmpDir::new("followdl");
    let root = create_two_containers(&tmp);
    let sink = open_container_log_sink(&root, "c1");
    let mut f = FollowChild::spawn(&root, 600);
    let status = f.wait_exit(Duration::from_secs(20));
    assert_eq!(status.code(), Some(0));
    while let Ok(chunk) = f.rx.recv_timeout(Duration::from_secs(5)) {
        f.got.extend_from_slice(&chunk);
    }
    assert_eq!(f.got, b"stdout hello c1\n");
    assert_eq!(f.stderr_text(), "");
    drop(sink);
}

/// SUP-7・#2447: `--follow` は追記を出し、ローテーション（世代の退避）をまたいでも欠落・重複なく連結した出力になる。
#[cfg(target_os = "linux")]
#[test]
fn sup7_logs_follow_spans_rotation() {
    use fandhe_container_supervisor::logs::StreamKind;
    let tmp = TmpDir::new("followrot");
    let root = create_two_containers(&tmp);
    let sink = open_container_log_sink(&root, "c1");
    let mut f = FollowChild::spawn(&root, 120_000);
    let mut expect: Vec<u8> = b"stdout hello c1\n".to_vec();
    f.wait_len(expect.len(), Duration::from_secs(30));
    assert_eq!(f.got, expect);

    append_record(&sink, StreamKind::Stdout, b"first");
    expect.extend_from_slice(b"stdout first\n");
    f.wait_len(expect.len(), Duration::from_secs(30));
    assert_eq!(f.got, expect);

    // 1 MiB の上限を超えるまで 60000 バイトの行を足す（現在ログが世代へ退避される）。
    for i in 0..20u32 {
        let mut line = format!("{i:03}-").into_bytes();
        line.resize(60_000, b'x');
        append_record(&sink, StreamKind::Stdout, &line);
        expect.extend_from_slice(b"stdout ");
        expect.extend_from_slice(&line);
        expect.push(b'\n');
        // 追従側が世代 2 本ぶん以上遅れて世代を取りこぼさないよう、数行ごとに到達を待つ。
        if i % 4 == 3 {
            f.wait_len(expect.len(), Duration::from_secs(30));
        }
    }
    assert!(
        fandhe_container_supervisor::logs::container_log_dir(&root)
            .join("c1.log.1")
            .exists(),
        "rotation must have happened"
    );
    append_record(&sink, StreamKind::Stdout, b"last");
    expect.extend_from_slice(b"stdout last\n");
    f.wait_len(expect.len(), Duration::from_secs(30));
    f.assert_quiet(Duration::from_millis(800));
    assert!(f.got == expect, "output differs from the written records");
    drop(sink);
}

/// CLI-1・SUP-7・#2605: `--follow` は、書き手（sink）が生きている間は状態が `Running` でなくても終わらず、
/// sink の終了（最終 flush とロックの解放）後に、未 flush だった行も含めて出し切って 0 で終わる（期限より前）。
#[cfg(target_os = "linux")]
#[test]
fn sup7_logs_follow_ends_when_container_stopped() {
    use fandhe_container_supervisor::logs::{LogSink as _, StreamKind};
    let tmp = TmpDir::new("followstop");
    let root = create_two_containers(&tmp);
    let sink = open_container_log_sink(&root, "c1");
    let started = Instant::now();
    let mut f = FollowChild::spawn(&root, 20_000);
    let mut expect: Vec<u8> = b"stdout hello c1\n".to_vec();
    f.wait_len(expect.len(), Duration::from_secs(30));
    // 記録は Created（Running ではない）だが、書き手が生きているので終わらない。
    f.assert_quiet(Duration::from_millis(1000));
    assert!(f.child.try_wait().expect("try_wait").is_none());
    // flush しない追記。sink の drop（最終 flush）の後に出し切られる。
    sink.append(StreamKind::Stdout, b"tail").expect("append");
    expect.extend_from_slice(b"stdout tail\n");
    drop(sink);
    let status = f.wait_exit(Duration::from_secs(10));
    assert_eq!(status.code(), Some(0));
    while let Ok(chunk) = f.rx.recv_timeout(Duration::from_secs(5)) {
        f.got.extend_from_slice(&chunk);
    }
    assert_eq!(f.got, expect);
    assert_eq!(f.stderr_text(), "");
    assert!(started.elapsed() < Duration::from_secs(19));
}

/// REPAIR-5・#2447: `--follow` は SIGINT で終わる（シグナル終了・stderr は空で、それまでの行は stdout に届いている）。
#[cfg(target_os = "linux")]
#[test]
fn repair5_logs_follow_terminates_on_sigint() {
    use std::os::unix::process::ExitStatusExt as _;
    let tmp = TmpDir::new("followint");
    let root = create_two_containers(&tmp);
    let sink = open_container_log_sink(&root, "c1");
    let mut f = FollowChild::spawn(&root, 120_000);
    f.wait_len(b"stdout hello c1\n".len(), Duration::from_secs(30));
    let kill = Command::new("kill")
        .args(["-INT", &f.child.id().to_string()])
        .status()
        .expect("kill");
    assert!(kill.success());
    let status = f.wait_exit(Duration::from_secs(10));
    assert_eq!(status.signal(), Some(2));
    while let Ok(chunk) = f.rx.recv_timeout(Duration::from_secs(5)) {
        f.got.extend_from_slice(&chunk);
    }
    assert_eq!(f.got, b"stdout hello c1\n");
    assert_eq!(f.stderr_text(), "");
    drop(sink);
}
/// SEC-1・PLUG-4・C1: Linux 以外では list / logs も plugin 候補なしの fail-closed で FAILED_PRECONDITION（5）。
/// 文言は「未導入」の識別子（信頼性検証の拒否とは別。TASK-79.4 追補）。
/// logs の ID 不正は plugin 解決より先に 2 で弾く。
#[cfg(not(target_os = "linux"))]
#[test]
fn sec1_list_logs_fail_closed_off_linux() {
    let tmp = TmpDir::new("offlinux-ll");
    let root = tmp.0.join("state");
    let root_s = root.to_str().expect("utf8");
    for args in [
        &["--root", root_s, "list"][..],
        &["--root", root_s, "logs", "c1"],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(5));
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            "{\"code\":\"FAILED_PRECONDITION\",\"message\":\"platform backend plugin is not installed\"}\n"
        );
        assert!(out.stdout.is_empty());
    }
    assert_state_root_after_fail_closed(&root);
    let out = run(&["--root", root_s, "logs", "bad/id"]);
    assert_eq!(out.status.code(), Some(2));
}

/// `PATH` 探索の結合試験用に、ホスト OS が必要とする plugin 名のスタブ実行ファイルを置いた一時ディレクトリを作る。
/// 内容は検証を通らないダミーで、実行されることはない。
#[cfg(not(target_os = "linux"))]
fn path_candidate_dir(tag: &str) -> TmpDir {
    let tmp = TmpDir::new(tag);
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    for name in ["macos", "windows"] {
        std::fs::write(
            tmp.0
                .join(format!("fandhe-container-plugin-{name}{suffix}")),
            b"stub",
        )
        .expect("write stub");
    }
    tmp
}

/// stderr の JSON 行のうち `PLUGIN_PATH_CANDIDATE` 警告行の数を数える。
#[cfg(not(target_os = "linux"))]
fn path_warning_lines(out: &Output) -> usize {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|l| l.contains("\"code\":\"PLUGIN_PATH_CANDIDATE\""))
        .count()
}

/// PLUG-11・CLI-1・REPAIR-12: 既定（opt-in なし）では `PATH` 上の候補を探索せず、警告も出ない。
/// 候補なしの FAILED_PRECONDITION（5）で、stderr は 1 行 JSON のみ。
#[cfg(not(target_os = "linux"))]
#[test]
fn plug11_path_search_is_off_by_default_off_linux() {
    let tmp = path_candidate_dir("pathdef");
    let state = tmp.0.join("state");
    let out = run_env(
        &["--root", state.to_str().expect("utf8"), "list"],
        &[("PATH", tmp.0.as_os_str())],
    );
    assert_eq!(out.status.code(), Some(5));
    assert_eq!(path_warning_lines(&out), 0);
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "{\"code\":\"FAILED_PRECONDITION\",\"message\":\"platform backend plugin is not installed\"}\n"
    );
    assert!(out.stdout.is_empty());
}

/// 非 Linux で PATH 由来の候補が採用されないときの終了コードと最終行（#1867）。macOS は信頼性検証の拒否
/// （PERMISSION_DENIED = 6）、Windows はホストが検証しない（UNIMPLEMENTED = 8）。拒否の理由は照合しない。
#[cfg(not(target_os = "linux"))]
fn path_search_rejection() -> (i32, &'static str) {
    if cfg!(target_os = "macos") {
        (
            6,
            "{\"code\":\"PERMISSION_DENIED\",\"message\":\"platform backend plugin failed trust verification\"}",
        )
    } else {
        (
            8,
            "{\"code\":\"UNIMPLEMENTED\",\"message\":\"plugin trust verification is not performed on this host\"}",
        )
    }
}

/// PLUG-11・CLI-1・REPAIR-12: `--plugin-path-search` で opt-in すると候補ごとに警告が stderr へ出る
/// （macOS / Windows の 2 候補で 2 行）。名前一致だけでは採用されず、macOS は信頼性検証の拒否（6）、
/// Windows はホストが検証しないため 8 で拒否される。
#[cfg(not(target_os = "linux"))]
#[test]
fn plug11_path_search_flag_warns_and_rejects_off_linux() {
    let tmp = path_candidate_dir("pathflag");
    let state = tmp.0.join("state");
    let out = run_env(
        &[
            "--plugin-path-search",
            "--root",
            state.to_str().expect("utf8"),
            "list",
        ],
        &[("PATH", tmp.0.as_os_str())],
    );
    let (want_exit, want_line) = path_search_rejection();
    assert_eq!(out.status.code(), Some(want_exit));
    assert_eq!(path_warning_lines(&out), 2);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let last = stderr.lines().last().expect("last line");
    // 「未導入」（FAILED_PRECONDITION）とは別の識別子で、パス・plugin 名を含まない（C1）。
    assert_eq!(last, want_line);
    assert!(out.stdout.is_empty());
}

/// PLUG-11・CLI-1・REPAIR-12: 環境変数 `FANDHE_CONTAINER_PLUGIN_PATH_SEARCH=1` でもフラグと同じ結果になる。
#[cfg(not(target_os = "linux"))]
#[test]
fn plug11_path_search_env_warns_and_rejects_off_linux() {
    let tmp = path_candidate_dir("pathenv");
    let state = tmp.0.join("state");
    let out = run_env(
        &["--root", state.to_str().expect("utf8"), "list"],
        &[
            ("PATH", tmp.0.as_os_str()),
            (
                "FANDHE_CONTAINER_PLUGIN_PATH_SEARCH",
                std::ffi::OsStr::new("1"),
            ),
        ],
    );
    let (want_exit, want_line) = path_search_rejection();
    assert_eq!(out.status.code(), Some(want_exit));
    assert_eq!(path_warning_lines(&out), 2);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(stderr.lines().last().expect("last line"), want_line);
    assert!(out.stdout.is_empty());
}

/// CLI-2: setup は引数を受け付けない（使い方エラー 2）。
#[test]
fn cli2_setup_usage_errors() {
    for a in [&["setup", "extra"][..], &["setup", "--x"][..]] {
        assert_failure(&run(a), 2, USAGE_JSON);
    }
}

/// CLI-2・SUP-14・CORE-6: Linux の setup は rootful のインストール手順を 1 行表示して 0 で終わる（実行はしない）。
#[cfg(target_os = "linux")]
#[test]
fn cli2_sup14_setup_on_linux_lists_launcher_install_step() {
    let out = run(&["setup"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(out.stdout).expect("utf8"),
        "{\"step\":\"privileged-launcher-install\",\"requires_admin\":true,\"status\":\"manual\",\"condition\":\"rootful\",\"instructions\":\"rootful only; rootless (default) needs no install. As root, run scripts/install-privileged-launcher.sh --launcher <file> --launcher-sha256 <hex> --supervisor <file> --supervisor-sha256 <hex> --cli <file> --cli-sha256 <hex> [--dest-dir <absolute path>] (default dest-dir /usr/local/libexec/fandhe-container). fandhe-container does not run it. See docs/setup/linux.md\"}\n"
    );
    assert_eq!(String::from_utf8(out.stderr).expect("utf8"), "");
}

/// CLI-1・CLI-2・REPAIR-3（#2452）: macOS の setup は 2 ステップを手順の文言つきで stdout へ出し、自動適用未実装のため 8 で失敗する。
#[cfg(target_os = "macos")]
#[test]
fn cli1_cli2_setup_on_macos_prints_steps_with_instructions() {
    let out = run(&["setup"]);
    assert_eq!(out.status.code(), Some(8));
    assert_eq!(
        String::from_utf8(out.stdout).expect("utf8"),
        concat!(
            "{\"step\":\"virtualization-entitlement\",\"requires_admin\":false,\"status\":\"manual\",\"instructions\":\"The macOS backend plugin fandhe-container-plugin-macos must be code-signed with the com.apple.security.virtualization entitlement (ad-hoc signing is accepted), e.g. codesign --sign - --force --entitlements <plist granting com.apple.security.virtualization> <path to fandhe-container-plugin-macos>. fandhe-container does not sign binaries. See docs/setup/macos.md\"}\n",
            "{\"step\":\"macos-min-version\",\"requires_admin\":false,\"status\":\"manual\",\"instructions\":\"Requires macOS 13 or later (provisional minimum for Virtualization.framework). Check with sw_vers -productVersion. fandhe-container does not check or upgrade macOS. See docs/setup/macos.md\"}\n"
        )
    );
    assert_eq!(
        String::from_utf8(out.stderr).expect("utf8"),
        "{\"code\":\"UNIMPLEMENTED\",\"message\":\"not implemented on this platform\"}\n"
    );
}

/// CLI-1・CLI-2・REPAIR-3（#2452）: Windows の setup は 3 ステップを手順の文言つきで stdout へ出し、自動適用未実装のため 8 で失敗する。
#[cfg(target_os = "windows")]
#[test]
fn cli1_cli2_setup_on_windows_prints_steps_with_instructions() {
    let out = run(&["setup"]);
    assert_eq!(out.status.code(), Some(8));
    assert_eq!(
        String::from_utf8(out.stdout).expect("utf8"),
        concat!(
            "{\"step\":\"wsl2-enable\",\"requires_admin\":true,\"status\":\"manual\",\"instructions\":\"Requires administrator. In an elevated PowerShell, run wsl --install and reboot (or enable the Virtual Machine Platform and Windows Subsystem for Linux features, reboot, and run wsl --set-default-version 2). Then install a WSL2 distribution and confirm that wsl -l -v shows VERSION 2 and that wsl --version succeeds. fandhe-container does not run these. See docs/setup/windows.md\"}\n",
            "{\"step\":\"developer-mode\",\"requires_admin\":true,\"status\":\"manual\",\"instructions\":\"Requires administrator. Turn on Developer Mode in Settings > System > For developers (Windows 11) or Settings > Update & Security > For developers (Windows 10); it is needed to create symbolic links and widens the local attack surface. fandhe-container does not change it. See docs/setup/windows.md\"}\n",
            "{\"step\":\"wslconfig-virtiofs\",\"requires_admin\":false,\"status\":\"manual\",\"instructions\":\"No administrator needed. In %UserProfile%\\\\.wslconfig, add virtiofs=true under [wsl2] (put comments on their own lines), then run wsl --shutdown so the setting takes effect. fandhe-container does not edit .wslconfig. See docs/setup/windows.md\"}\n"
        )
    );
    assert_eq!(
        String::from_utf8(out.stderr).expect("utf8"),
        "{\"code\":\"UNIMPLEMENTED\",\"message\":\"not implemented on this platform\"}\n"
    );
}

/// CORE-3・CLI-1・SUP-1（#2081）: start は supervisor を `systemd-run --user --scope --quiet -p Delegate=yes --` で包んで
/// 起動する。包み込みの argv（supervisor の絶対パスと契約の argv が続く）と、systemd-run が受けた環境
/// （許可リストの `PATH` と `XDG_RUNTIME_DIR` だけ。`DBUS_SESSION_BUS_ADDRESS` 等は持ち込まない）を具体値で照合する。
#[cfg(target_os = "linux")]
#[test]
fn core3_cli1_start_wraps_supervisor_in_delegated_user_scope() {
    let tmp = TmpDir::new("wrap");
    let dir = isolated_cli_dir("wrap");
    let cli = dir.join("fandhe-container");
    let (_root, root_s) = prepare_c1(&tmp, &cli);
    install_fake_supervisor(&dir, "printf 'FCSUP1 OK 4242\\n'; exec sleep 1");
    let scope = FakeScope::new(&dir, &tmp);

    let out = scope.run(
        &cli,
        &["--root", &root_s, "start", "c1"],
        &[(
            "DBUS_SESSION_BUS_ADDRESS",
            std::ffi::OsStr::new("unix:path=/nonexistent"),
        )],
    );
    assert_eq!(out.status.code(), Some(0), "{:?}", out.stderr);

    let argv = std::fs::read_to_string(dir.join("wrapper.argv")).expect("argv record");
    let supervisor = dir.join("fandhe-container-supervisor");
    let expected = format!(
        "--user\n--scope\n--quiet\n-p\nDelegate=yes\n--\n{}\nstart\n--root\n{root_s}\nc1\n",
        std::fs::canonicalize(&supervisor).expect("canon").display()
    );
    assert_eq!(argv, expected);

    let env = std::fs::read_to_string(dir.join("wrapper.env")).expect("env record");
    let mut kept: Vec<&str> = env
        .lines()
        .filter(|l| {
            l.starts_with("PATH=") || l.starts_with("XDG_RUNTIME_DIR=") || l.starts_with("DBUS_")
        })
        .collect();
    kept.sort_unstable();
    let xdg_line = format!("XDG_RUNTIME_DIR={}", tmp.0.join("xdg").display());
    assert_eq!(
        kept,
        ["PATH=/usr/sbin:/usr/bin:/sbin:/bin", xdg_line.as_str()]
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// CLI-1・ERR-2・SEC-5（#2081）: user マネージャに届かない環境（`XDG_RUNTIME_DIR` 無し・ソケット無し）では、
/// spawn の前に FAILED_PRECONDITION（5）で止まり（案 B へは落とさない）、状態は Created のまま。
#[cfg(target_os = "linux")]
#[test]
fn cli1_start_fails_closed_without_user_manager() {
    let tmp = TmpDir::new("noxdg");
    let dir = isolated_cli_dir("noxdg");
    let cli = dir.join("fandhe-container");
    let (_root, root_s) = prepare_c1(&tmp, &cli);
    install_fake_supervisor(&dir, "printf 'FCSUP1 OK 4242\\n'; exec sleep 1");
    let scope = FakeScope::new(&dir, &tmp);

    // (a) XDG_RUNTIME_DIR を外す。
    let out = Command::new(&cli)
        .args(["--root", &root_s, "start", "c1"])
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("FANDHE_CONTAINER_PLUGIN_PATH_SEARCH")
        .env("FANDHE_CONTAINER_TEST_SYSTEMD_RUN", &scope.systemd_run)
        .stdin(Stdio::null())
        .output()
        .expect("run cli");
    assert_eq!(out.status.code(), Some(5));
    assert_eq!(
        op_and_code(&out),
        ("start".into(), "FAILED_PRECONDITION".into())
    );
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("XDG_RUNTIME_DIR is not set to an absolute path"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // (b) ソケットの無い XDG_RUNTIME_DIR。
    let empty = tmp.0.join("empty-xdg");
    std::fs::create_dir(&empty).expect("mkdir");
    let out = run_exe_env(
        &cli,
        &["--root", &root_s, "start", "c1"],
        &[
            (
                "FANDHE_CONTAINER_TEST_SYSTEMD_RUN",
                scope.systemd_run.as_os_str(),
            ),
            ("XDG_RUNTIME_DIR", empty.as_os_str()),
        ],
    );
    assert_eq!(out.status.code(), Some(5));
    assert_eq!(
        op_and_code(&out),
        ("start".into(), "FAILED_PRECONDITION".into())
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("systemd user manager is not reachable"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        !dir.join("wrapper.argv").exists(),
        "must fail before spawning"
    );
    let out = run_isolated(&cli, &["--root", &root_s, "list"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "ID\tSTATUS\tPID\nc1\tcreated\t-\n"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// 実バイナリの `doctor` の stdout から、`code` が `code` の行（JSON Lines の 1 行）を探す。
#[cfg(target_os = "linux")]
fn doctor_line_with_code(stdout: &str, code: &str) -> Option<String> {
    let needle = format!("\"code\":\"{code}\"");
    stdout
        .lines()
        .find(|l| l.contains(&needle))
        .map(str::to_owned)
}

/// CORE-3・CORE-4・CLI-1（#2133）: `XDG_RUNTIME_DIR` が空だと user マネージャ未到達の診断が出て終了コード 3、
/// stderr は空。root の環境では検査を省いた通知が出て、その行が出ることを期待する（skip しない）。
#[cfg(target_os = "linux")]
#[test]
fn doctor_reports_unset_xdg_runtime_dir() {
    use std::os::unix::fs::MetadataExt;
    let out = run_env(
        &["doctor"],
        &[("XDG_RUNTIME_DIR", std::ffi::OsStr::new(""))],
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(out.stderr.is_empty(), "{:?}", out.stderr);
    let euid = std::fs::metadata("/proc/self").expect("meta").uid();
    if euid == 0 {
        let line = doctor_line_with_code(&stdout, "USER_SCOPE_CHECK_SKIPPED_AS_ROOT")
            .expect("root skip notice");
        assert!(line.contains("\"check\":\"privilege\",\"state\":\"rootful\""));
        assert!([0, 3, 4].contains(&out.status.code().expect("code")));
    } else {
        let line = doctor_line_with_code(&stdout, "XDG_RUNTIME_DIR_UNSET").expect("unset line");
        assert!(line.starts_with("{\"severity\":\"warning\","), "{line}");
        assert!(line.ends_with("\"check\":\"user_manager\",\"state\":\"runtime_dir_unset\"}"));
        assert_eq!(out.status.code(), Some(3));
    }
}

/// CORE-4（#2133）: 絶対パスでも `systemd/private` が無ければ到達不能の診断を出す。パスは出力に載せない。
#[cfg(target_os = "linux")]
#[test]
fn doctor_reports_unreachable_user_manager_without_leaking_the_path() {
    use std::os::unix::fs::MetadataExt;
    if std::fs::metadata("/proc/self").expect("meta").uid() == 0 {
        return; // root では検査を省く（上のテストが通知を照合する）。
    }
    let marker = "/nonexistent-doctor-marker-2133";
    let out = run_env(
        &["doctor"],
        &[("XDG_RUNTIME_DIR", std::ffi::OsStr::new(marker))],
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(out.stderr.is_empty());
    assert!(doctor_line_with_code(&stdout, "USER_MANAGER_UNREACHABLE").is_some());
    assert!(!stdout.contains("doctor-marker"), "{stdout}");
    assert_eq!(out.status.code(), Some(3));
}

/// 一時ディレクトリに `systemd/private` の UNIX ソケットを `listen` 状態で作り、`XDG_RUNTIME_DIR` にできる
/// ディレクトリ（`TmpDir` 直下の `xdg`）とリスナーを返す。ディレクトリは 0700 で所有者は自分。
#[cfg(target_os = "linux")]
fn user_manager_socket_dir(tmp: &TmpDir) -> (std::path::PathBuf, std::os::unix::net::UnixListener) {
    use std::os::unix::fs::DirBuilderExt;
    let xdg = tmp.0.join("xdg");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&xdg)
        .expect("mkdir xdg");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(xdg.join("systemd"))
        .expect("mkdir systemd");
    let l =
        std::os::unix::net::UnixListener::bind(xdg.join("systemd").join("private")).expect("bind");
    (xdg, l)
}

/// stdout の JSON Lines に重大度 `warning` の行があるか（あれば終了コードは 3）。
#[cfg(target_os = "linux")]
fn doctor_has_warning(stdout: &str) -> bool {
    stdout
        .lines()
        .any(|l| l.starts_with("{\"severity\":\"warning\","))
}

/// root では検査を省くため、結合試験は何もしない（`doctor_reports_unset_xdg_runtime_dir` が通知を照合する）。
#[cfg(target_os = "linux")]
fn is_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").expect("meta").uid() == 0
}

/// CORE-3・CORE-4・REPAIR-5（#2158）: 生きているソケットには実 connect が成功し、user マネージャ系の診断は出ない。
/// listener を落としてファイルだけ残すと `USER_MANAGER_SOCKET_REFUSED`（warning・`socket_refused`）で終了コード 3。
#[cfg(target_os = "linux")]
#[test]
fn core3_repair5_doctor_connects_live_and_dead_socket() {
    if is_root() {
        return;
    }
    let tmp = TmpDir::new("doctor-live-dead");
    let (xdg, listener) = user_manager_socket_dir(&tmp);

    // 生存ソケット。
    let out = run_env(&["doctor"], &[("XDG_RUNTIME_DIR", xdg.as_os_str())]);
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(out.stderr.is_empty(), "{:?}", out.stderr);
    assert!(!stdout.contains("\"check\":\"user_manager\""), "{stdout}");
    let code = out.status.code().expect("code");
    if doctor_has_warning(&stdout) {
        assert_eq!(code, 3, "{stdout}");
    } else {
        assert!([0, 4].contains(&code), "{stdout}");
    }

    // 死んだソケット（listener を落としてもファイルは残る）。
    drop(listener);
    let out = run_env(&["doctor"], &[("XDG_RUNTIME_DIR", xdg.as_os_str())]);
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(out.stderr.is_empty(), "{:?}", out.stderr);
    let line = doctor_line_with_code(&stdout, "USER_MANAGER_SOCKET_REFUSED").expect("refused line");
    assert!(line.starts_with("{\"severity\":\"warning\","), "{line}");
    assert!(line.ends_with("\"check\":\"user_manager\",\"state\":\"socket_refused\"}"));
    assert_eq!(out.status.code(), Some(3));
    assert!(!stdout.contains(&xdg.display().to_string()), "{stdout}");
}

/// REPAIR-5・CORE-3（#2158）: listen backlog が満杯で accept されないソケットでも、`doctor` は期限（1 秒）の後に
/// 終了し、`USER_MANAGER_CONNECT_TIMED_OUT`（notice・`connect_timed_out`）を出す。他に warning が無ければ
/// 終了コードは 4（判定不能）、あれば 3。ハングしないことを経過時間（10 秒未満）で照合する。
#[cfg(target_os = "linux")]
#[test]
fn repair5_core3_doctor_times_out_on_full_backlog() {
    use fandhe_container_supervisor::user_scope::{
        UserManagerConnectError, probe_user_manager_socket,
    };
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    if is_root() {
        return;
    }
    let tmp = TmpDir::new("doctor-backlog");
    let (xdg, listener) = user_manager_socket_dir(&tmp);
    let sock = xdg.join("systemd").join("private");

    // accept しないまま接続を積み、backlog が満杯になるまで続ける。満杯の判定は「接続スレッドの数」ではなく、
    // doctor と同じ非ブロッキング connect（`probe_user_manager_socket`）が期限内に `TimedOut`（= `EAGAIN` が続く）に
    // なったことで行う。スレッドの未スケジュール・connect の失敗に左右されず、観測した時点のカーネルの状態だけに依る。
    let (tx, rx) = mpsc::channel::<UnixStream>();
    let mut held = Vec::new();
    let mut spawned = 0usize;
    let mut full = false;
    while spawned < 20_000 && !full {
        for _ in 0..64 {
            let tx = tx.clone();
            let sock = sock.clone();
            std::thread::Builder::new()
                .stack_size(64 * 1024)
                .spawn(move || {
                    if let Ok(s) = UnixStream::connect(&sock) {
                        let _ = tx.send(s);
                    }
                })
                .expect("spawn");
            spawned += 1;
        }
        while let Ok(s) = rx.try_recv() {
            held.push(s);
        }
        full =
            probe_user_manager_socket(xdg.as_os_str(), Instant::now() + Duration::from_millis(100))
                == Err(UserManagerConnectError::TimedOut);
    }
    assert!(full, "backlog did not fill within the connection cap");

    let start = Instant::now();
    let out = run_env(&["doctor"], &[("XDG_RUNTIME_DIR", xdg.as_os_str())]);
    let elapsed = start.elapsed();
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    drop(listener);
    drop(held);

    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    assert!(out.stderr.is_empty(), "{:?}", out.stderr);
    let line =
        doctor_line_with_code(&stdout, "USER_MANAGER_CONNECT_TIMED_OUT").expect("timed out line");
    assert!(line.starts_with("{\"severity\":\"notice\","), "{line}");
    assert!(line.ends_with("\"check\":\"user_manager\",\"state\":\"connect_timed_out\"}"));
    let expected = if doctor_has_warning(&stdout) { 3 } else { 4 };
    assert_eq!(out.status.code(), Some(expected), "{stdout}");
}

/// CLI-1（#2133）: `doctor` に余計な引数を渡すと使い方エラー（2）。stdout は空。
#[test]
fn doctor_rejects_extra_arguments() {
    let out = run(&["doctor", "extra"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert_eq!(String::from_utf8(out.stderr).expect("utf8"), USAGE_JSON);
}

/// `image` 系の stderr 1 行 JSON（op なし）を組み立てる。
#[cfg(target_os = "linux")]
fn image_err(code: &str, message: &str) -> String {
    format!("{{\"code\":\"{code}\",\"message\":\"{message}\"}}\n")
}

/// CLI-1・OCI-7・SEC-1（#2547）: Linux の `image ls` は、`--image-root` が group / other に書き込めれば
/// PERMISSION_DENIED（終了コード 6・固定文言）、0700 と 0755 は受理する。判定はビットで行うため root で
/// 走らせても 0757 は拒否される。0755 の受理は祖先（一時ディレクトリ）が 0700 の `TmpDir` 配下であることに依る。
#[cfg(target_os = "linux")]
#[test]
fn cli1_oci7_image_ls_root_mode_on_linux() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TmpDir::new("ls-mode");
    let root = tmp.0.join("images");
    std::fs::create_dir_all(root.join("blobs").join("sha256")).expect("mkdir image root");
    let ls = |root: &std::path::Path| {
        run(&["image", "ls", "--image-root", root.to_str().expect("utf8")])
    };
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o757)).expect("chmod");
    let out = ls(&root);
    assert_eq!(out.status.code(), Some(6));
    assert!(out.stdout.is_empty(), "stdout must be empty");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        image_err("PERMISSION_DENIED", "permission denied")
    );
    for mode in [0o700, 0o755] {
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(mode)).expect("chmod");
        let out = ls(&root);
        assert_eq!(out.status.code(), Some(0), "mode {mode:o}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "REPOSITORY\tTAG\tDIGEST\tSIZE\tMISSING\n"
        );
        assert!(out.stderr.is_empty(), "stderr must be empty");
    }
}

/// CLI-1・OCI-7（#2316）: `image tag` の実入口で、引数不足は INVALID_ARGUMENT（終了コード 2）。
/// 引数の解析は OS 分岐より先なので 3 OS 共通。stdout は空。
#[test]
fn cli1_image_tag_too_few_args_is_invalid_argument() {
    let tmp = TmpDir::new("tag-args");
    let root = tmp.0.join("images");
    let out = run(&[
        "image",
        "tag",
        "--image-root",
        root.to_str().expect("utf8"),
        "busybox",
    ]);
    assert_failure(&out, 2, USAGE_JSON);
}

/// CLI-1・OCI-7（#2316）: Linux で空のストアに対する `image tag` は付け元が無く NOT_FOUND（終了コード 3）。
#[cfg(target_os = "linux")]
#[test]
fn cli1_image_tag_missing_source_is_not_found_on_linux() {
    let tmp = TmpDir::new("tag-nf");
    let root = tmp.0.join("images");
    std::fs::create_dir(&root).expect("mkdir image root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let out = run(&[
        "image",
        "tag",
        "--image-root",
        root.to_str().expect("utf8"),
        "busybox:latest",
        "busybox:v2",
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty(), "stdout must be empty");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        image_err("NOT_FOUND", "image not found")
    );
}

/// CLI-1・OCI-7（#2316）: Linux で付け先が digest 指定なら INVALID_ARGUMENT（終了コード 2）。
#[cfg(target_os = "linux")]
#[test]
fn cli1_image_tag_digest_target_is_invalid_argument_on_linux() {
    let tmp = TmpDir::new("tag-digest");
    let root = tmp.0.join("images");
    std::fs::create_dir(&root).expect("mkdir image root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let target = format!("busybox@sha256:{}", "a".repeat(64));
    let out = run(&[
        "image",
        "tag",
        "--image-root",
        root.to_str().expect("utf8"),
        "busybox:latest",
        &target,
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "stdout must be empty");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        image_err("INVALID_ARGUMENT", "target must be a tag reference")
    );
}

/// CLI-1・OCI-7（#2600）: Linux の `image rm` / `image tag` は、digest に見えて正しい digest でない入力
/// （大文字 hex の sha256・sha512）をタグと誤読せず 2 / INVALID_ARGUMENT（固定文言）で拒否する。
#[cfg(target_os = "linux")]
#[test]
fn cli1_oci7_image_rm_and_tag_reject_malformed_digest_on_linux() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TmpDir::new("malformed-digest");
    let root = tmp.0.join("images");
    std::fs::create_dir(&root).expect("mkdir image root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let root = root.to_str().expect("utf8").to_string();
    let upper = format!("sha256:{}", "A".repeat(64));
    let sha512 = format!("sha512:{}", "a".repeat(128));
    let expected = image_err(
        "INVALID_ARGUMENT",
        "manifest digest must be sha256:<64 lowercase hex>",
    );
    let cases: [Vec<&str>; 4] = [
        vec!["image", "rm", "--image-root", &root, &upper],
        vec!["image", "rm", "--image-root", &root, &sha512],
        vec![
            "image",
            "tag",
            "--image-root",
            &root,
            "busybox:latest",
            &upper,
        ],
        vec!["image", "tag", "--image-root", &root, &sha512, "busybox:v2"],
    ];
    for args in &cases {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert_eq!(String::from_utf8_lossy(&out.stderr), expected, "{args:?}");
    }
    let out = run(&["image", "rm", "--image-root", &root, "busybox:latest"]);
    assert_eq!(out.status.code(), Some(3));
}

/// CLI-1・OCI-7・SEC-1（#2316）: Linux 以外の `image tag` は plugin 候補なしの fail-closed で
/// FAILED_PRECONDITION（終了コード 5）。ストアのルートは作らない。
#[cfg(not(target_os = "linux"))]
#[test]
fn cli1_image_tag_fails_closed_off_linux() {
    let tmp = TmpDir::new("tag-offlinux");
    let root = tmp.0.join("images");
    let out = run(&[
        "image",
        "tag",
        "--image-root",
        root.to_str().expect("utf8"),
        "busybox:latest",
        "busybox:v2",
    ]);
    assert_eq!(out.status.code(), Some(5));
    assert!(out.stdout.is_empty(), "stdout must be empty");
    assert!(
        String::from_utf8_lossy(&out.stderr).starts_with("{\"code\":\"FAILED_PRECONDITION\""),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!root.exists());
}
/// OCI-7・CLI-1・#2315: create / delete の `--image-root` / `--image` の使い方の誤りは、
/// 3 OS 同一に core 到達前の使用法エラー（終了コード 2）になる。
#[test]
fn oci7_image_option_usage_errors() {
    let tmp = TmpDir::new("oci7-usage");
    let root_s = tmp.0.to_str().expect("utf8").to_string();
    let digest = format!("sha256:{}", "a".repeat(64));
    for args in [
        // --image-root だけ・--image だけ。
        vec!["create", "--bundle", "/b", "--image-root", &root_s, "c1"],
        vec!["create", "--bundle", "/b", "--image", &digest, "c1"],
        // 相対パスの --image-root。
        vec![
            "create",
            "--bundle",
            "/b",
            "--image-root",
            "rel",
            "--image",
            &digest,
            "c1",
        ],
        // 重複指定。
        vec![
            "create",
            "--bundle",
            "/b",
            "--image-root",
            &root_s,
            "--image-root",
            &root_s,
            "--image",
            &digest,
            "c1",
        ],
        vec!["delete", "--image-root", "rel", "c1"],
        vec![
            "delete",
            "--image-root",
            &root_s,
            "--image-root",
            &root_s,
            "c1",
        ],
        vec!["delete", "--image-root"],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert_eq!(String::from_utf8_lossy(&out.stderr), USAGE_JSON, "{args:?}");
    }
}

/// CORE-6・SEC-5・REPAIR-12（#2387）: 実バイナリの `doctor` が rootless ID 写像の前提の診断を本番入口から出し、
/// JSON Lines の形と終了コードの合成が具体値で一致する。入力元は固定位置のため、実行環境ごとに該当する枝を照合する
/// （root は通知 1 行、非 root は診断なし〔pass〕か Notice〔pass〕か Warning〔終了コード 3〕のいずれか）。
#[cfg(target_os = "linux")]
#[test]
fn doctor_reports_id_mapping_diagnostics_through_the_real_entry() {
    // 診断コードと severity・check・state の対応（`id_mapping_check::evaluate` の全件）。
    const KNOWN: &[(&str, &str, &str, &str)] = &[
        (
            "notice",
            "ID_MAPPING_CHECK_SKIPPED_AS_ROOT",
            "privilege",
            "rootful",
        ),
        (
            "notice",
            "ID_MAPPING_INCONCLUSIVE",
            "privilege",
            "unreadable",
        ),
        ("warning", "PASSWD_UNUSABLE", "passwd", "unusable"),
        (
            "warning",
            "SUBID_OWNER_NAME_INVALID",
            "passwd",
            "invalid_name",
        ),
        (
            "notice",
            "SUBID_OWNER_NAME_UNRESOLVED",
            "passwd",
            "unresolved",
        ),
        (
            "notice",
            "SUBID_OWNER_LOOKUP_UNAVAILABLE",
            "passwd",
            "lookup_unavailable",
        ),
        (
            "warning",
            "SUBID_OWNER_LOOKUP_FAILED",
            "passwd",
            "lookup_failed",
        ),
        ("warning", "SUBUID_UNUSABLE", "subuid", "unusable"),
        ("warning", "SUBGID_UNUSABLE", "subgid", "unusable"),
        (
            "warning",
            "SUBORDINATE_IDS_INCOMPLETE",
            "id_model",
            "subuid_only",
        ),
        (
            "warning",
            "SUBORDINATE_IDS_INCOMPLETE",
            "id_model",
            "subgid_only",
        ),
        (
            "warning",
            "SUBORDINATE_IDS_UID_MISMATCH",
            "id_model",
            "uid_mismatch",
        ),
        (
            "notice",
            "SUBORDINATE_IDS_NOT_CONFIGURED",
            "id_model",
            "single_id",
        ),
        (
            "warning",
            "SUBORDINATE_ID_RANGE_INVALID",
            "id_model",
            "range_invalid",
        ),
        (
            "warning",
            "SUBID_OWNER_UNDETERMINED",
            "passwd",
            "owner_undetermined",
        ),
        (
            "warning",
            "SUBID_NAME_SERVICE_UNSUPPORTED",
            "nsswitch",
            "subid_name_service",
        ),
        ("warning", "NSSWITCH_UNUSABLE", "nsswitch", "unusable"),
        (
            "warning",
            "ID_MAP_HELPER_NOT_FOUND",
            "id_map_helpers",
            "newuidmap_not_found",
        ),
        (
            "warning",
            "ID_MAP_HELPER_NOT_FOUND",
            "id_map_helpers",
            "newgidmap_not_found",
        ),
        (
            "warning",
            "ID_MAP_HELPER_UNTRUSTED",
            "id_map_helpers",
            "newuidmap_untrusted",
        ),
        (
            "warning",
            "ID_MAP_HELPER_UNTRUSTED",
            "id_map_helpers",
            "newgidmap_untrusted",
        ),
    ];
    let out = run(&["doctor"]);
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(out.stderr.is_empty(), "{:?}", out.stderr);
    let code = out.status.code().expect("exit code");
    assert!([0, 3, 4].contains(&code), "{code}");
    let is_idmap = |l: &str| {
        KNOWN
            .iter()
            .any(|(_, c, _, _)| l.contains(&format!("\"code\":\"{c}\"")))
    };
    let idmap_lines: Vec<&str> = stdout.lines().filter(|l| is_idmap(l)).collect();
    let mut idmap_warning = false;
    for l in &idmap_lines {
        let hit = KNOWN.iter().any(|(sev, c, chk, st)| {
            l.starts_with(&format!("{{\"severity\":\"{sev}\",\"code\":\"{c}\","))
                && l.ends_with(&format!("\"check\":\"{chk}\",\"state\":\"{st}\"}}"))
        });
        assert!(hit, "unexpected id mapping line: {l}");
        assert!(
            l.contains("\"message\":\"") && l.contains("\"remediation\":["),
            "{l}"
        );
        idmap_warning |= l.starts_with("{\"severity\":\"warning\",");
    }
    if is_root() {
        assert_eq!(idmap_lines.len(), 1, "{stdout}");
        assert!(idmap_lines[0].contains("\"code\":\"ID_MAPPING_CHECK_SKIPPED_AS_ROOT\""));
    }
    // 終了コードへの合成: ID 写像の Warning があれば全体は 3。
    if idmap_warning {
        assert_eq!(code, 3, "{stdout}");
    }
    // 全体に Warning が無ければ 3 にならない。
    if !doctor_has_warning(&stdout) {
        assert_ne!(code, 3, "{stdout}");
    }
    // 出力順: ID 写像の行は他の診断の行の後ろに並ぶ。
    let all_lines: Vec<&str> = stdout.lines().collect();
    let first_idmap = all_lines.iter().position(|l| is_idmap(l));
    let last_other = all_lines
        .iter()
        .rposition(|l| !is_idmap(l) && l.starts_with("{\"severity\""));
    if let (Some(f), Some(o)) = (first_idmap, last_other) {
        assert!(o < f, "{stdout}");
    }
}

/// OCI-7・ERR-1・ERR-2・#2315: Linux で、不正な在庫・ストアルート・digest での create は core に入る前に
/// 構造化エラーと非ゼロ終了コードで終わり、状態ルートにコンテナを作らない。delete は失敗しても状態を保持する。
#[cfg(target_os = "linux")]
#[test]
fn oci7_image_failures_keep_state_on_linux() {
    let tmp = TmpDir::new("oci7-flow");
    let bundle = tmp.0.join("bundle");
    std::fs::create_dir(&bundle).expect("bundle");
    std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
    std::fs::write(
        bundle.join("config.json"),
        r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .expect("config");
    let root = tmp.0.join("state");
    let root_s = root.to_str().expect("utf8");
    let bundle_s = bundle.to_str().expect("utf8");
    let missing = tmp.0.join("no-such-image-root");
    let missing_s = missing.to_str().expect("utf8");
    let digest = format!("sha256:{}", "a".repeat(64));

    // 不正な digest: INVALID_ARGUMENT（2）。
    let out = run(&[
        "--root",
        root_s,
        "create",
        "--bundle",
        bundle_s,
        "--image-root",
        missing_s,
        "--image",
        "sha256:xyz",
        "c1",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        op_and_code(&out),
        ("create".into(), "INVALID_ARGUMENT".into())
    );
    assert!(out.stdout.is_empty());

    // 存在しないストアルート: NOT_FOUND（3）・固定文言でパスを含まない。
    let out = run(&[
        "--root",
        root_s,
        "create",
        "--bundle",
        bundle_s,
        "--image-root",
        missing_s,
        "--image",
        &digest,
        "c1",
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(op_and_code(&out), ("create".into(), "NOT_FOUND".into()));
    assert!(!String::from_utf8_lossy(&out.stderr).contains(missing_s));
    assert!(
        !root.join("c1").exists(),
        "no container state must be created"
    );

    // 在庫に無い digest（空のストア）: 構造化エラーで失敗し、状態は作られない。
    let store = tmp.0.join("images");
    std::fs::create_dir(&store).expect("images");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let store_s = store.to_str().expect("utf8");
    let out = run(&[
        "--root",
        root_s,
        "create",
        "--bundle",
        bundle_s,
        "--image-root",
        store_s,
        "--image",
        &digest,
        "c1",
    ]);
    assert_ne!(out.status.code(), Some(0));
    let (op, code) = op_and_code(&out);
    assert_eq!(op, "create");
    assert_eq!(code, "NOT_FOUND");
    assert!(!root.join("c1").join("state.json").exists());

    // delete: 存在しないストアルートでは状態を消さずに NOT_FOUND（3）。
    assert_failure_free(&run(&[
        "--root", root_s, "create", "--bundle", bundle_s, "c1",
    ]));
    let out = run(&["--root", root_s, "delete", "--image-root", missing_s, "c1"]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(op_and_code(&out), ("delete".into(), "NOT_FOUND".into()));
    assert!(root.join("c1").join("state.json").exists());

    // --force との組み合わせでも、開けないストアでは状態を保持する。
    let out = run(&[
        "--root",
        root_s,
        "delete",
        "--force",
        "--image-root",
        missing_s,
        "c1",
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert!(root.join("c1").join("state.json").exists());

    // 開ける（空の）ストアでの delete は成功し、状態が消える（登録の無い参照の解除は成功扱い）。
    assert_failure_free(&run(&[
        "--root",
        root_s,
        "delete",
        "--image-root",
        store_s,
        "c1",
    ]));
    assert!(!root.join("c1").join("state.json").exists());
}

/// OCI-7・CLI-1・#2496: Linux で、永続化済みの在庫のタグ参照（name:tag）を CLI バイナリへ渡した create は、
/// タグの指す digest で参照を登録して成功する。存在しないタグは NOT_FOUND（3）で、状態を作らない。
#[cfg(target_os = "linux")]
#[test]
fn oci7_create_with_tag_ref_resolves_persisted_tag_on_linux() {
    use fandhe_container_oci::image_management::{
        ImageStore, ImageTagSource, ManifestComposition, TagKey,
    };
    use fandhe_container_oci::reference::{Digest, ImageReference, Reference};

    let tmp = TmpDir::new("oci7-tag-ref");
    let bundle = tmp.0.join("bundle");
    std::fs::create_dir(&bundle).expect("bundle");
    std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
    std::fs::write(
        bundle.join("config.json"),
        r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .expect("config");
    let root = tmp.0.join("state");
    let root_s = root.to_str().expect("utf8");
    let bundle_s = bundle.to_str().expect("utf8");

    // 在庫: manifest 1 件とタグ 1 件を永続化する。
    let store_dir = tmp.0.join("images");
    std::fs::create_dir(&store_dir).expect("images");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
    }
    let store_s = store_dir.to_str().expect("utf8");
    let manifest = format!("sha256:{}", "a1".repeat(32));
    let cfg = Digest::parse(&format!("sha256:{}", "c".repeat(64))).expect("cfg");
    let tag = "registry.example/lib/app:v1";
    {
        let store = ImageStore::open(&store_dir).expect("store");
        store
            .lock()
            .expect("lock")
            .register_manifest(
                Digest::parse(&manifest).expect("d"),
                ManifestComposition::new(cfg, vec![]).expect("comp"),
            )
            .expect("register");
        let r = ImageReference::parse(tag).expect("ref");
        let Reference::Tag(t) = r.reference() else {
            panic!("tag expected")
        };
        store
            .tag_image(
                &ImageTagSource::Manifest(Digest::parse(&manifest).expect("d")),
                TagKey::new(r.registry().clone(), r.repository().clone(), t.clone()),
            )
            .expect("tag");
    }

    // 存在しないタグ: NOT_FOUND（3）・状態は作られない。
    let out = run(&[
        "--root",
        root_s,
        "create",
        "--bundle",
        bundle_s,
        "--image-root",
        store_s,
        "--image",
        "registry.example/lib/app:v2",
        "c1",
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(op_and_code(&out), ("create".into(), "NOT_FOUND".into()));
    assert!(!root.join("c1").join("state.json").exists());

    // 永続化済みのタグ: 成功し、参照先 manifest にコンテナの参照が 1 件登録される。
    assert_failure_free(&run(&[
        "--root",
        root_s,
        "create",
        "--bundle",
        bundle_s,
        "--image-root",
        store_s,
        "--image",
        tag,
        "c1",
    ]));
    assert!(root.join("c1").join("state.json").exists());
    let store = ImageStore::open(&store_dir).expect("reopen");
    let refs = store
        .lock()
        .expect("lock")
        .manifest_references(&Digest::parse(&manifest).expect("d"));
    assert_eq!(refs.containers.len(), 1);
    assert!(refs.containers[0].as_str().ends_with(".c1"));
}
/// 隣に置いた偽ランチャーで `doctor` を実行し、`check":"launcher"` の行・終了コード・配置先ディレクトリ
/// （正規化済み。マウント属性から期待値を選ぶ試験が使う）を返す。
/// 一意のディレクトリ名（タグ）が出力に載らないことも照合する（REPAIR-4）。root では検査を省くため `None`。
#[cfg(target_os = "linux")]
fn doctor_launcher_line(
    tag: &str,
    launcher_mode: Option<&str>,
) -> Option<(Option<String>, i32, std::path::PathBuf)> {
    use std::os::unix::fs::PermissionsExt;
    if is_root() {
        return None;
    }
    let dir = isolated_cli_dir(tag);
    if let Some(mode) = launcher_mode {
        install_fake_exe(&dir, "fandhe-container-launcher", "exit 0");
        let mode = u32::from_str_radix(mode, 8).expect("octal");
        std::fs::set_permissions(
            dir.join("fandhe-container-launcher"),
            std::fs::Permissions::from_mode(mode),
        )
        .expect("chmod");
    }
    let out = run_isolated(&dir.join("fandhe-container"), &["doctor"]);
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(out.stderr.is_empty(), "{:?}", out.stderr);
    let unique = dir.file_name().and_then(|n| n.to_str()).expect("name");
    assert!(!stdout.contains(unique), "{stdout}");
    let line = stdout
        .lines()
        .find(|l| l.contains("\"check\":\"launcher\""))
        .map(str::to_owned);
    let real = dir.canonicalize().expect("canonicalize");
    Some((line, out.status.code().expect("code"), real))
}

/// SUP-14・CORE-6・CLI-1（#2599）: 隣にランチャーが無い rootless のインストールは通知の 1 行。
#[cfg(target_os = "linux")]
#[test]
fn sup14_doctor_reports_absent_launcher() {
    let Some((line, _, _)) = doctor_launcher_line("doctor-launcher-absent", None) else {
        return;
    };
    assert_eq!(
        line.expect("launcher line"),
        "{\"severity\":\"notice\",\"code\":\"PRIVILEGED_LAUNCHER_ABSENT\",\"message\":\"no privileged launcher is installed beside the cli executable; start uses the rootless direct path\",\"remediation\":[\"For a rootful install, run scripts/install-privileged-launcher.sh as root so fandhe-container-launcher is placed beside the cli\"],\"check\":\"launcher\",\"state\":\"absent\"}"
    );
}

/// SUP-14・CORE-6・CLI-1（#2599）: group 書き込み可のランチャーは信頼せず warning・終了コード 3。
#[cfg(target_os = "linux")]
#[test]
fn sup14_doctor_reports_untrusted_launcher() {
    let Some((line, code, _)) = doctor_launcher_line("doctor-launcher-untrusted", Some("775"))
    else {
        return;
    };
    let line = line.expect("launcher line");
    assert!(
        line.starts_with(
            "{\"severity\":\"warning\",\"code\":\"PRIVILEGED_LAUNCHER_UNTRUSTED\",\"message\":\"the privileged launcher beside the cli executable is not trusted;"
        ),
        "{line}"
    );
    assert!(
        line.ends_with("\"check\":\"launcher\",\"state\":\"file_mode\"}"),
        "{line}"
    );
    assert_eq!(code, 3);
}

/// SUP-14・CORE-6・CLI-1（#2599・#2661）: 信頼できるが file capability も setuid root も無いランチャーは warning・終了コード 3
/// （非 root では file capability を付けられないため、昇格手段なしの経路を実ファイルで照合する）。
/// 配置先が `nosuid` のマウント上なら、昇格手段の判定より先に効かない理由として `nosuid_mount` になる（#2661）。
/// 期待する message と state は、配置先のマウント属性を試験側で独立に求めて選ぶ（`test_side_is_nosuid`）。
#[cfg(target_os = "linux")]
#[test]
fn sup14_doctor_reports_launcher_without_elevation() {
    let Some((line, code, real)) = doctor_launcher_line("doctor-launcher-noelev", Some("755"))
    else {
        return;
    };
    let line = line.expect("launcher line");
    let (message, state) = if test_side_is_nosuid(&real) {
        (
            "the privileged launcher is on a filesystem mounted nosuid; setuid and file capabilities have no effect there and start cannot elevate",
            "nosuid_mount",
        )
    } else {
        (
            "the privileged launcher has neither file capabilities nor the setuid root bit; start cannot elevate",
            "no_file_capabilities",
        )
    };
    assert!(
        line.starts_with(&format!(
            "{{\"severity\":\"warning\",\"code\":\"LAUNCHER_ELEVATION_UNAVAILABLE\",\"message\":\"{message}\","
        )),
        "expected {state}: {line}"
    );
    assert!(
        line.ends_with(&format!("\"check\":\"launcher\",\"state\":\"{state}\"}}")),
        "expected {state}: {line}"
    );
    assert_eq!(code, 3);
}

/// `/proc/self/mountinfo` を試験側で独立に解析し、`path` を含む最長一致のマウント（同長は後の行）が
/// `nosuid` かを返す。製品側（実体の fd の mount ID で mountinfo の行を引く `mount_option_by_id`）と別の方法で
/// 期待値を決める。ここはパスの最長一致で選ぶため、試験の一時ディレクトリの祖先に後から重ねたマウント
/// （古い子マウントを隠すもの）が無い前提で両者は一致する（ID で引くこと自体は net の単体試験
/// `sup14_mount_option_by_id` が照合する）。
#[cfg(target_os = "linux")]
fn test_side_is_nosuid(path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let info = std::fs::read("/proc/self/mountinfo").expect("mountinfo");
    let target = path.as_os_str().as_bytes();
    let mut best: Option<(usize, bool)> = None;
    for line in info.split(|b| *b == b'\n') {
        let f: Vec<&[u8]> = line
            .split(|b| *b == b' ')
            .filter(|x| !x.is_empty())
            .collect();
        let (Some(mp), Some(opts)) = (f.get(4), f.get(5)) else {
            continue;
        };
        // 8 進エスケープは空白（\040）だけ戻せば試験の一時パスには足りる。
        let mp: Vec<u8> = String::from_utf8_lossy(mp)
            .replace("\\040", " ")
            .into_bytes();
        let covers = target == mp.as_slice()
            || mp == b"/"
            || (target.starts_with(&mp) && target.get(mp.len()) == Some(&b'/'));
        if covers && best.is_none_or(|(l, _)| mp.len() >= l) {
            best = Some((mp.len(), opts.split(|b| *b == b',').any(|t| t == b"nosuid")));
        }
    }
    best.expect("covering mount").1
}

/// SUP-14・CORE-6（#2661）: 実バイナリの `doctor` が、兄弟のランチャー（file capability も setuid も持たない
/// 信頼できる実行ファイル）の載るマウントの `nosuid` 属性を診断に反映する。`collect` の実体パス解決・実体の fd の
/// mount ID の取得・mountinfo 読み取り・評価・JSON 出力・終了コードをつなぐ経路を観測する。期待値は試験側で独立に求める。nosuid ならば `nosuid_mount`、
/// そうでなければ `no_file_capabilities`（どちらも warning・終了コード 3）。mountinfo を読めない場合の
/// `mount_unreadable` は、実バイナリから /proc を差し替えられないため `launcher_check` の単体試験で照合する。
/// nosuid マウントの人工的な構築（root・mount 権限が要る）はこの試験では行わない。
#[cfg(target_os = "linux")]
#[test]
fn sup14_doctor_reports_launcher_mount_state() {
    if is_root() {
        return; // root では検査を省く（`doctor_reports_unset_xdg_runtime_dir` が通知を照合する）。
    }
    let dir = isolated_cli_dir("doctor-mount");
    install_fake_exe(&dir, "fandhe-container-launcher", "#!/bin/sh\nexit 0\n");
    let real = dir.canonicalize().expect("canonicalize");
    let expect_nosuid = test_side_is_nosuid(&real);
    let out = run_isolated(&dir.join("fandhe-container"), &["doctor"]);
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(out.stderr.is_empty(), "{:?}", out.stderr);
    let line = stdout
        .lines()
        .find(|l| l.contains("\"check\":\"launcher\""))
        .unwrap_or_else(|| panic!("no launcher line: {stdout}"));
    assert!(
        line.starts_with("{\"severity\":\"warning\",\"code\":\"LAUNCHER_ELEVATION_UNAVAILABLE\""),
        "{line}"
    );
    let state = if expect_nosuid {
        "nosuid_mount"
    } else {
        "no_file_capabilities"
    };
    assert!(
        line.ends_with(&format!("\"check\":\"launcher\",\"state\":\"{state}\"}}")),
        "expected {state}: {line}"
    );
    assert_eq!(out.status.code(), Some(3), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `c1` の状態記録へ、create が残すイメージストア root の記録（予約 annotations）を足す。
/// イメージつきの create は取得済みイメージを要するため、記録だけを状態に直接書いて delete 側を実バイナリで確かめる。
#[cfg(target_os = "linux")]
fn record_image_root(state_root: &std::path::Path, image_root: &std::path::Path) {
    let path = state_root.join("c1").join("state.json");
    let text = std::fs::read_to_string(&path).expect("read state");
    let entry = format!(
        "\"io.fandhe.container.image-root\":\"{}\"",
        image_root.to_str().expect("utf8")
    );
    // Linux の create は既定の `network none` の文書に伴う作成世代の注釈を残す(#1873)ため、
    // `annotations` が既にあれば先頭へ足し、無ければ新設する(キーの重複は状態ファイルの破損になる)。
    let patched = if let Some(at) = text.find("\"annotations\":{") {
        let open = at + "\"annotations\":{".len();
        let sep = if text[open..].starts_with('}') {
            ""
        } else {
            ","
        };
        format!("{}{entry}{sep}{}", &text[..open], &text[open..])
    } else {
        let body = text.strip_prefix('{').expect("json object");
        format!("{{\"annotations\":{{{entry}}},{body}")
    };
    std::fs::write(&path, patched).expect("write state");
}

/// 0700 の空のイメージストア root を作り、正規パスを返す。
#[cfg(target_os = "linux")]
fn empty_image_root(tmp: &TmpDir, name: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let root = tmp.0.join(name);
    std::fs::create_dir(&root).expect("mkdir image root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    std::fs::canonicalize(&root).expect("canonical")
}

/// OCI-7・OCI-5・CLI-1（#2499）: 状態記録のストア root が開ければ、`--image-root` を省いた delete は成功して状態を消す。
#[cfg(target_os = "linux")]
#[test]
fn oci7_2499_delete_uses_recorded_image_root_on_linux() {
    let tmp = TmpDir::new("del-rec");
    let dir = isolated_cli_dir("del-rec");
    let cli = dir.join("fandhe-container");
    let (root, root_s) = prepare_c1(&tmp, &cli);
    let images = empty_image_root(&tmp, "images");
    record_image_root(&root, &images);

    let out = run_isolated(&cli, &["--root", &root_s, "delete", "c1"]);
    assert_eq!(out.status.code(), Some(0), "{:?}", out.stderr);
    assert!(out.stderr.is_empty(), "stderr must be empty");
    assert!(!root.join("c1").join("state.json").exists());
    let _ = std::fs::remove_dir_all(dir);
}

/// OCI-7・CLI-1（#2499）: 記録の root と同じ `--image-root` を渡した delete も成功する。
#[cfg(target_os = "linux")]
#[test]
fn oci7_2499_delete_with_matching_image_root_succeeds_on_linux() {
    let tmp = TmpDir::new("del-same");
    let dir = isolated_cli_dir("del-same");
    let cli = dir.join("fandhe-container");
    let (root, root_s) = prepare_c1(&tmp, &cli);
    let images = empty_image_root(&tmp, "images");
    record_image_root(&root, &images);

    let out = run_isolated(
        &cli,
        &[
            "--root",
            &root_s,
            "delete",
            "--image-root",
            images.to_str().expect("utf8"),
            "c1",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{:?}", out.stderr);
    assert!(!root.join("c1").join("state.json").exists());
    let _ = std::fs::remove_dir_all(dir);
}

/// OCI-7・CLI-1（#2499）: 記録と異なる `--image-root` は FAILED_PRECONDITION（5）で拒否し、状態を消さない。
/// 記録の root を開けない delete も状態を消さずに失敗する。
#[cfg(target_os = "linux")]
#[test]
fn oci7_2499_delete_rejects_mismatched_or_unopenable_image_root_on_linux() {
    let tmp = TmpDir::new("del-mis");
    let dir = isolated_cli_dir("del-mis");
    let cli = dir.join("fandhe-container");
    let (root, root_s) = prepare_c1(&tmp, &cli);
    let images = empty_image_root(&tmp, "images");
    let other = empty_image_root(&tmp, "other");
    record_image_root(&root, &images);

    let out = run_isolated(
        &cli,
        &[
            "--root",
            &root_s,
            "delete",
            "--image-root",
            other.to_str().expect("utf8"),
            "c1",
        ],
    );
    assert_eq!(out.status.code(), Some(5), "{:?}", out.stderr);
    assert_eq!(
        op_and_code(&out),
        ("delete".into(), "FAILED_PRECONDITION".into())
    );
    assert!(out.stdout.is_empty());
    assert!(root.join("c1").join("state.json").exists());

    // 記録の root が消えている場合も、状態を残して失敗する。
    std::fs::remove_dir(&images).expect("rm image root");
    let out = run_isolated(&cli, &["--root", &root_s, "delete", "c1"]);
    assert_ne!(out.status.code(), Some(0), "{:?}", out.stderr);
    assert!(out.stdout.is_empty());
    assert!(root.join("c1").join("state.json").exists());
    let _ = std::fs::remove_dir_all(dir);
}
/// SEC-4・CLI-1・ERR-1（#2761）: `start --audit-policy` の不正な値は INVALID_ARGUMENT（2）で拒否され、入力値は文言に入らず、
/// 状態ルートは作られない。値の欠落は使い方エラー。正しい値で存在しない ID を渡せば従来どおり NOT_FOUND（3）。
#[cfg(target_os = "linux")]
#[test]
fn sec4_cli1_start_rejects_invalid_audit_policy() {
    let tmp = TmpDir::new("auditpol");
    let dir = isolated_cli_dir("auditpol");
    let cli = dir.join("fandhe-container");
    let root = tmp.0.join("state");
    let root_s = root.to_str().expect("utf8");

    let out = run_isolated(
        &cli,
        &["--root", root_s, "start", "--audit-policy", "Strict", "c1"],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        code_json(
            "start",
            "INVALID_ARGUMENT",
            "the audit policy must be best-effort or strict"
        )
    );
    assert!(!root.exists(), "state root must not be created");

    assert_failure(
        &run_isolated(&cli, &["--root", root_s, "start", "--audit-policy"]),
        2,
        USAGE_JSON,
    );

    let (_root, root_s) = prepare_c1(&tmp, &cli);
    let out = run_isolated(
        &cli,
        &[
            "--root",
            &root_s,
            "start",
            "--audit-policy",
            "best-effort",
            "nope",
        ],
    );
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(op_and_code(&out), ("start".into(), "NOT_FOUND".into()));
    let _ = std::fs::remove_dir_all(dir);
}

/// SEC-4・SUP-1・CLI-1（#2761）: `start --audit-policy strict` は supervisor の argv に `--root <root>` の直後、ID の前として
/// 渡る。未指定のときは載らない（supervisor の既定が効く）。
#[cfg(target_os = "linux")]
#[test]
fn sec4_start_passes_audit_policy_to_supervisor_argv() {
    let tmp = TmpDir::new("auditargv");
    let dir = isolated_cli_dir("auditargv");
    let cli = dir.join("fandhe-container");
    let (_root, root_s) = prepare_c1(&tmp, &cli);
    install_fake_supervisor(&dir, &observing_body("supervisor"));
    let scope = FakeScope::new(&dir, &tmp);
    let sup = dir.join("fandhe-container-supervisor");
    let sup = sup.to_str().expect("utf8");

    let out = scope.run(
        &cli,
        &["--root", &root_s, "start", "--audit-policy", "strict", "c1"],
        &[],
    );
    assert_eq!(out.status.code(), Some(0), "{:?}", out.stderr);
    let argv = std::fs::read_to_string(dir.join("wrapper.argv")).expect("wrapper.argv");
    let lines: Vec<&str> = argv.lines().collect();
    assert_eq!(
        lines[6..],
        [
            sup,
            "start",
            "--root",
            &root_s,
            "--audit-policy",
            "strict",
            "c1"
        ],
        "{argv}"
    );

    let out = scope.run(&cli, &["--root", &root_s, "start", "c1"], &[]);
    assert_eq!(out.status.code(), Some(0), "{:?}", out.stderr);
    let argv = std::fs::read_to_string(dir.join("wrapper.argv")).expect("wrapper.argv");
    let lines: Vec<&str> = argv.lines().collect();
    assert_eq!(
        lines[6..],
        [sup, "start", "--root", &root_s, "c1"],
        "{argv}"
    );
    let _ = std::fs::remove_dir_all(dir);
}
/// CORE-5・SEC-4・CLI-1（#2761）: 実バイナリの `doctor` は Landlock ABI の行をちょうど 1 行出し、`start` に要る下限（6）と
/// 監査の下限（7）を数値で示す。`state` は固定語彙のどれか（実カーネルの結果は環境で変わるため語彙で照合する）。
#[cfg(target_os = "linux")]
#[test]
fn core5_doctor_reports_landlock_line() {
    let out = run_env(&["doctor"], &[]);
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(out.stderr.is_empty(), "{:?}", out.stderr);
    let lines: Vec<&str> = stdout
        .lines()
        .filter(|l| l.contains("\"check\":\"landlock\""))
        .collect();
    assert_eq!(lines.len(), 1, "{stdout}");
    let line = lines[0];
    assert!(
        line.ends_with(",\"required\":6,\"audit_required\":7}"),
        "{line}"
    );
    let states = [
        "supported",
        "audit_abi_too_old",
        "abi_too_old",
        "kernel_lacks_landlock",
        "disabled_at_boot",
        "unsupported_architecture",
        "invalid_kernel_response",
        "probe_failed",
    ];
    assert!(
        states
            .iter()
            .any(|s| line.contains(&format!("\"state\":\"{s}\",\"abi\":"))),
        "{line}"
    );
}
/// `--pasta-path` / `--pasta-path-search` の拒否の分類を実バイナリで照合する（NET-9・CLI-1・PLUG-11・#3199）。
///
/// 結果の stderr の 1 行 JSON から `code` と `message` を取り出し、状態ルートが作られていないことも確かめる。
mod pasta_flags {
    use super::*;

    const NOT_CREATE: &str =
        "--pasta-path and --pasta-path-search apply only to the create command";
    const NOT_APPLICABLE: &str = "--pasta-path and --pasta-path-search apply only to a user-defined network on a rootless install";

    fn assert_rejected(out: &Output, code: &str, message: &str) {
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            err.contains(&format!("\"code\":\"{code}\"")),
            "unexpected stderr: {err}"
        );
        assert!(
            err.contains(&format!("\"message\":\"{message}\"")),
            "unexpected stderr: {err}"
        );
        assert!(out.stdout.is_empty(), "stdout must be empty");
    }

    /// create 以外のサブコマンドに pasta のフラグがあれば、専用の文言で `INVALID_ARGUMENT`（終了コード 2）。
    #[test]
    fn net9_cli1_pasta_flags_rejected_outside_create() {
        for args in [
            &["--pasta-path", "/usr/bin/pasta", "list"][..],
            &["--pasta-path-search", "setup"],
            &["--pasta-path-search", "doctor"],
            &[
                "--root",
                "/x",
                "--pasta-path",
                "/usr/bin/pasta",
                "start",
                "c1",
            ],
        ] {
            let out = run(args);
            assert_eq!(out.status.code(), Some(2), "{args:?}");
            assert_rejected(&out, "INVALID_ARGUMENT", NOT_CREATE);
        }
    }

    /// 重複・併用・値の欠落は使い方エラー。
    #[test]
    fn net9_cli1_pasta_flags_usage_errors() {
        for args in [
            &["--pasta-path", "/a", "--pasta-path-search", "list"][..],
            &["--pasta-path-search", "--pasta-path-search", "list"],
            &["--pasta-path", "/a", "--pasta-path", "/b", "list"],
            &["--pasta-path"],
        ] {
            let out = run(args);
            assert_failure(&out, 2, USAGE_JSON);
        }
    }

    /// ユーザー定義名でない create に pasta のフラグがあれば `INVALID_ARGUMENT`。状態ルートは作らない。
    #[test]
    fn net9_cli1_pasta_flag_with_non_user_defined_network_is_rejected() {
        let tmp = TmpDir::new("pasta-none");
        let root = tmp.0.join("never-created");
        let root_s = root.to_str().expect("utf8");
        for network in [&["--network", "none"][..], &["--network", "host"], &[]] {
            let mut args = vec![
                "--root",
                root_s,
                "--pasta-path",
                "/usr/bin/pasta",
                "create",
                "--bundle",
                "/nonexistent-bundle",
            ];
            args.extend_from_slice(network);
            args.push("c1");
            let out = run(&args);
            assert_eq!(out.status.code(), Some(2), "{network:?}");
            assert_rejected(&out, "INVALID_ARGUMENT", NOT_APPLICABLE);
            assert!(!root.exists(), "state root must not be created");
        }
    }

    /// rootless（隣にランチャーが無い）のユーザー定義名で定義が無い場合: フラグなしは `FAILED_PRECONDITION`
    /// （判定が先）、フラグがあれば pasta の解決より前に `NOT_FOUND`（存在しないネットワークのために子を起動しない）。
    /// いずれも状態ルートを作らない（D2・#3329）。
    #[cfg(target_os = "linux")]
    #[test]
    fn net9_cli1_pasta_rootless_named_network_without_definition() {
        let tmp = TmpDir::new("pasta-named");
        let cli = isolated_cli_dir("pasta-named").join("fandhe-container");
        let root = tmp.0.join("never-created");
        let root_s = root.to_str().expect("utf8");
        let create = |extra: &[&str]| {
            let mut args = vec!["--root", root_s];
            args.extend_from_slice(extra);
            args.extend_from_slice(&[
                "create",
                "--bundle",
                "/nonexistent-bundle",
                "--network",
                "web",
                "c1",
            ]);
            run_isolated(&cli, &args)
        };
        let out = create(&[]);
        assert_rejected(&out, "FAILED_PRECONDITION", "pasta path is not configured");
        for path in ["relative/pasta", "/nonexistent-dir/pasta"] {
            let out = create(&["--pasta-path", path]);
            assert_rejected(&out, "NOT_FOUND", "network not found");
            assert!(!root.exists(), "state root must not be created");
        }
        assert!(!root.exists(), "state root must not be created");
    }

    /// 定義がある場合: 不正・不在のパスは net の分類のまま。いずれも `@container-options` と状態記録を作らない（#3329）。
    #[cfg(target_os = "linux")]
    #[test]
    fn net9_cli1_pasta_rootless_named_network_with_definition() {
        let tmp = TmpDir::new("pasta-defined");
        let cli = isolated_cli_dir("pasta-defined").join("fandhe-container");
        let root = tmp.0.join("state");
        let root_s = root.to_str().expect("utf8");
        let out = run_isolated(&cli, &["--root", root_s, "network", "create", "web"]);
        assert_eq!(out.status.code(), Some(0), "{:?}", out);
        let create = |extra: &[&str]| {
            let mut args = vec!["--root", root_s];
            args.extend_from_slice(extra);
            args.extend_from_slice(&[
                "create",
                "--bundle",
                "/nonexistent-bundle",
                "--network",
                "web",
                "c1",
            ]);
            run_isolated(&cli, &args)
        };
        let out = create(&["--pasta-path", "relative/pasta"]);
        assert_rejected(
            &out,
            "INVALID_ARGUMENT",
            "pasta path must be an absolute UTF-8 path without control characters or dot components",
        );
        let out = create(&["--pasta-path", "/nonexistent-dir/pasta"]);
        assert_rejected(&out, "NOT_FOUND", "pasta binary was not found");
        // 別名のネットワーク（定義が無い）は pasta の解決より前に NOT_FOUND。
        let out = run_isolated(
            &cli,
            &[
                "--root",
                root_s,
                "--pasta-path",
                "/nonexistent-dir/pasta",
                "create",
                "--bundle",
                "/nonexistent-bundle",
                "--network",
                "other",
                "c1",
            ],
        );
        assert_rejected(&out, "NOT_FOUND", "network not found");
        assert!(
            !root.join("@container-options").exists(),
            "options dir must not be created"
        );
    }

    /// 隣に信頼できないランチャーがあれば、直接経路へ落とさず `FAILED_PRECONDITION`。
    #[cfg(target_os = "linux")]
    #[test]
    fn net9_sup14_pasta_untrusted_launcher_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TmpDir::new("pasta-untrusted");
        let dir = isolated_cli_dir("pasta-untrusted");
        let launcher = dir.join("fandhe-container-launcher");
        std::fs::write(&launcher, b"#!/bin/sh\nexit 0\n").expect("launcher");
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o775)).expect("chmod");
        let root = tmp.0.join("never-created");
        let root_s = root.to_str().expect("utf8");
        let out = run_isolated(
            &dir.join("fandhe-container"),
            &[
                "--root",
                root_s,
                "--pasta-path",
                "/usr/bin/pasta",
                "create",
                "--bundle",
                "/nonexistent-bundle",
                "--network",
                "web",
                "c1",
            ],
        );
        assert_rejected(
            &out,
            "FAILED_PRECONDITION",
            "privileged launcher is not a trusted executable (must be a regular file owned by root or the current user, not writable by group or others)",
        );
        assert!(!root.exists(), "state root must not be created");
    }

    /// Linux 以外ではユーザー定義名 + フラグは net の固定文言で `UNIMPLEMENTED`。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn net9_cli1_pasta_flag_is_unimplemented_off_linux() {
        let out = run(&[
            "--pasta-path",
            "/usr/bin/pasta",
            "create",
            "--bundle",
            "/nonexistent-bundle",
            "--network",
            "web",
            "c1",
        ]);
        assert_rejected(&out, "UNIMPLEMENTED", "pasta is only supported on Linux");
    }
}

/// NET-6・CLI-1・ERR-1（#3066）: 実バイナリで network create → ls → 重複 create → rm → ls を通す。
/// 権限モデルは CLI の隣に特権ランチャーが無い rootless（uid 0 の実行は rootful 扱いで create が UNIMPLEMENTED）。
#[cfg(target_os = "linux")]
#[test]
fn net6_network_create_ls_rm_flow_on_linux() {
    use std::os::unix::fs::MetadataExt as _;
    let tmp = TmpDir::new("net6");
    let dir = isolated_cli_dir("net6");
    let cli = dir.join("fandhe-container");
    let root = tmp.0.join("state");
    let root_s = root.to_str().expect("utf8");

    let out = run_isolated(&cli, &["--root", root_s, "network", "ls"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "NAME\tMODE\tSUBNET\n");

    let is_root = std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0);
    if is_root {
        let out = run_isolated(&cli, &["--root", root_s, "network", "create", "n1"]);
        assert_failure(
            &out,
            8,
            "{\"code\":\"UNIMPLEMENTED\",\"message\":\"user-defined networks on rootful installations are not supported yet\"}\n",
        );
        let _ = std::fs::remove_dir_all(dir);
        return;
    }

    for n in ["n2", "n1"] {
        let out = run_isolated(&cli, &["--root", root_s, "network", "create", n]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stdout.is_empty());
    }
    let out = run_isolated(&cli, &["--root", root_s, "network", "create", "n1"]);
    assert_failure(
        &out,
        4,
        "{\"code\":\"ALREADY_EXISTS\",\"message\":\"network already exists\"}\n",
    );
    let out = run_isolated(&cli, &["--root", root_s, "network", "ls"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "NAME\tMODE\tSUBNET\nn1\tpasta\t-\nn2\tpasta\t-\n"
    );
    let out = run_isolated(&cli, &["--root", root_s, "network", "rm", "n1"]);
    assert_eq!(out.status.code(), Some(0));
    let out = run_isolated(&cli, &["--root", root_s, "network", "rm", "n1"]);
    assert_failure(
        &out,
        3,
        "{\"code\":\"NOT_FOUND\",\"message\":\"network not found\"}\n",
    );
    let out = run_isolated(&cli, &["--root", root_s, "network", "ls"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "NAME\tMODE\tSUBNET\nn2\tpasta\t-\n"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// NET-6・NET-9・CLI-1・ERR-1（#3529・D10）: 実バイナリで、pasta 構成のコンテナ（状態記録と起動オプション文書）が参照する
/// ネットワークの `network rm` が `FAILED_PRECONDITION`（終了コード 5・構造化エラー）で拒否され、定義が残ること。
/// 参照するコンテナの記録と文書を消せば `rm` は成功する。pasta の実起動は要らないため、記録は core・supervisor の
/// 公開 API で直接作る（`create` の実起動は別の試験が担う）。
#[cfg(target_os = "linux")]
#[test]
fn net6_net9_cli1_3529_network_rm_refused_while_referenced_then_succeeds() {
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        Annotations, ContainerId, ContainerStatus, CreateStateRequest, DeleteStateRequest,
        GetStateRequest, StateStore,
    };
    use fandhe_container_supervisor::container_options::document::ContainerOptionsDocument;
    use fandhe_container_supervisor::container_options::store::{
        self as options_store, GENERATION_ANNOTATION,
    };
    use std::os::unix::fs::MetadataExt as _;

    let is_root = std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0);
    if is_root {
        // root の実行は rootful 扱いで user-defined network の create が UNIMPLEMENTED（net6 の試験と同じ前提）。
        return;
    }
    let tmp = TmpDir::new("net6-3529");
    let dir = isolated_cli_dir("net6-3529");
    let cli = dir.join("fandhe-container");
    let root = tmp.0.join("state");
    let root_s = root.to_str().expect("utf8");

    let out = run_isolated(&cli, &["--root", root_s, "network", "create", "n1"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 参照するコンテナ c1（世代 g1・文書の network は n1）の記録を作る。
    let store = FileStateStore::open(StateRoot::from_override(root.clone()).expect("root"))
        .expect("open store");
    let bundle = tmp.0.join("bundle");
    std::fs::create_dir_all(&bundle).expect("bundle");
    let id = ContainerId::new("c1").expect("id");
    let req = CreateStateRequest::new(ContainerStatus::created(id.clone(), None), bundle)
        .expect("req")
        .with_annotations(
            Annotations::new([(GENERATION_ANNOTATION.to_owned(), "g1".to_owned())]).expect("ann"),
        );
    let rev = store.create(&req).expect("create record").revision();
    let state_root = store.host_state_root().expect("root").to_path_buf();
    let doc = ContainerOptionsDocument::default()
        .with_network(Some("n1".to_owned()), vec![], vec![])
        .expect("net")
        .with_pasta(Some(
            "20260120 2049 131074 1234567 1760000000 123456789 -5 0 0 755\n/usr/bin/pasta"
                .to_owned(),
        ))
        .expect("pasta")
        .with_generation("g1".to_owned())
        .expect("gen");
    options_store::write_new(&state_root, &id, &doc).expect("write doc");

    // 参照中は拒否される。入力値とコンテナ ID は出力に出ず、定義は残る。
    let out = run_isolated(&cli, &["--root", root_s, "network", "rm", "n1"]);
    assert_failure(
        &out,
        5,
        "{\"code\":\"FAILED_PRECONDITION\",\"message\":\"network is in use by a container; delete the containers that use it first\"}\n",
    );
    let out = run_isolated(&cli, &["--root", root_s, "network", "ls"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "NAME\tMODE\tSUBNET\nn1\tpasta\t-\n"
    );

    // 参照するコンテナを消せば rm は成功する。
    let rev = store
        .get(&GetStateRequest::new(id.clone()))
        .map(|r| r.revision())
        .unwrap_or(rev);
    store
        .delete(&DeleteStateRequest::new(id.clone(), rev))
        .expect("delete record");
    options_store::remove(&state_root, &id).expect("remove doc");
    let out = run_isolated(&cli, &["--root", root_s, "network", "rm", "n1"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run_isolated(&cli, &["--root", root_s, "network", "ls"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "NAME\tMODE\tSUBNET\n");
    let _ = std::fs::remove_dir_all(dir);
}
/// op ログを読み、行を `(op, success, failure)` の `op_stats` 行とメタ行（`ops=N`）の列として照合する。
///
/// `expected` の各要素は 1 組（`op_stats` 行の列 + 対応するメタ行）。組内は操作名の昇順で、行の形式
/// （接頭辞・末尾 `}`・`{` が 1 つだけ）は壊れた行を見逃さないよう完全一致で見る（#3558）。
#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn assert_op_log_groups(log: &std::path::Path, expected: &[&[(&str, u32, u32)]]) {
    let text = std::fs::read_to_string(log).expect("read op log");
    assert!(text.ends_with('\n'), "{text:?}");
    let mut lines = text.lines();
    for group in expected {
        for (op, ok, ng) in *group {
            let line = lines.next().unwrap_or_default();
            let head = format!(
                "{{\"event\":\"op_stats\",\"op\":\"{op}\",\"success\":{ok},\"failure\":{ng},\"count\":{},\"min_us\":",
                ok + ng
            );
            assert!(line.starts_with(&head), "{line:?} vs {head:?}\n{text}");
            assert!(line.ends_with('}'), "{line:?}");
            assert_eq!(line.matches('{').count(), 1, "{line:?}");
        }
        let meta = format!(
            "{{\"event\":\"op_stats_meta\",\"ops\":{},\"dropped_records\":0}}",
            group.len()
        );
        assert_eq!(lines.next(), Some(meta.as_str()), "{text}");
    }
    assert_eq!(lines.next(), None, "unexpected extra lines:\n{text}");
}

/// REPAIR-4・NET-6・CLI-1（#3558）: 実バイナリで `FANDHE_CONTAINER_OP_LOG` を設定した `create --network <名前>` が、
/// 本体の記録器の組（`create`）と定義照合の記録器の組（`network.store.open` / `network.store.get`）をこの順で
/// 別々の組（メタ行つき）として追記し、定義照合が走らない失敗では 2 組目を出さないこと。
/// 記録器を統合しない判断は `docs/design/network-wiring.md`。成功経路（core の create まで到達）は
/// `repair4_net6_cli1_3577_create_named_network_success_records_two_groups` が照合する。
/// root の実行は rootful 扱いで名前つきネットワークが `UNIMPLEMENTED` のため、4 場面は照合せず明示の拒否を照合する。
#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[test]
fn repair4_net6_cli1_3558_create_named_network_records_store_ops_in_second_group() {
    use std::os::unix::fs::MetadataExt as _;
    let tmp = TmpDir::new("net6-3558");
    let dir = isolated_cli_dir("net6-3558");
    let cli = dir.join("fandhe-container");
    if std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0) {
        // root は rootful 扱いで名前つきネットワークの create が UNIMPLEMENTED になる。何も照合せず成功させず、
        // 明示的な拒否（net6 の試験と同じ固定値）を照合して終える。4 場面は非 root の実行で照合する。
        let state = tmp.0.join("state");
        let out = run_isolated(
            &cli,
            &[
                "--root",
                state.to_str().expect("utf8"),
                "network",
                "create",
                "web",
            ],
        );
        assert_failure(
            &out,
            8,
            "{\"code\":\"UNIMPLEMENTED\",\"message\":\"user-defined networks on rootful installations are not supported yet\"}\n",
        );
        let _ = std::fs::remove_dir_all(dir);
        return;
    }
    let state = tmp.0.join("state");
    let state_s = state.to_str().expect("utf8");
    let missing_pasta = "/nonexistent-dir/pasta";
    let create = |log: &std::path::Path, root: &str, net: &str, pasta: bool| {
        let mut args = vec!["--root", root];
        if pasta {
            args.extend(["--pasta-path", missing_pasta]);
        }
        args.extend([
            "create",
            "--bundle",
            "/nonexistent-bundle",
            "--network",
            net,
            "c1",
        ]);
        run_exe_env(&cli, &args, &[("FANDHE_CONTAINER_OP_LOG", log.as_os_str())])
    };

    // (a) 状態ルート未作成: 定義が無く NOT_FOUND。open は Ok(None) でも成功として数える。
    let never = tmp.0.join("never-created");
    let log = tmp.0.join("a.jsonl");
    let out = create(&log, never.to_str().expect("utf8"), "web", true);
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("network not found"));
    assert!(!never.exists(), "state root must not be created");
    assert_op_log_groups(
        &log,
        &[&[("create", 0, 1)], &[("network.store.open", 1, 0)]],
    );

    // 定義 web を作る（op ログなし）。
    let out = run_isolated(&cli, &["--root", state_s, "network", "create", "web"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");

    // (b) 別の名前: open 成功・get 失敗。
    let log = tmp.0.join("b.jsonl");
    let out = create(&log, state_s, "other", true);
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("network not found"));
    assert_op_log_groups(
        &log,
        &[
            &[("create", 0, 1)],
            &[("network.store.get", 0, 1), ("network.store.open", 1, 0)],
        ],
    );

    // (c) 定義はあるが pasta が無い: 照合は成功し、その後の pasta の検証で失敗する。
    let log = tmp.0.join("c.jsonl");
    let out = create(&log, state_s, "web", true);
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("pasta binary was not found"));
    assert_op_log_groups(
        &log,
        &[
            &[("create", 0, 1)],
            &[("network.store.get", 1, 0), ("network.store.open", 1, 0)],
        ],
    );

    // (d) pasta の指定なし: decide の段で失敗し、定義照合は走らないので 2 組目は出ない。
    let log = tmp.0.join("d.jsonl");
    let out = create(&log, state_s, "web", false);
    assert_eq!(out.status.code(), Some(5), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("pasta path is not configured"));
    assert_op_log_groups(&log, &[&[("create", 0, 1)]]);
    let _ = std::fs::remove_dir_all(dir);
}
/// `$XDG_RUNTIME_DIR` 配下に排他作成した 0700 のディレクトリへ置く偽の pasta（`--version` にだけ答える）。
///
/// 製品の `verify_pasta_binary`（anchor なし）は `/` から全祖先までの所有者・権限を検査するため、`/tmp` や
/// umask 002 で作られる `CARGO_TARGET_TMPDIR` では通らない。非 root の試験が自前で用意できる信頼できる経路は
/// `$XDG_RUNTIME_DIR`（`/run/user/<uid>`）だけで、検証器は差し替えずに本物を通す（#3577・NET-9）。Drop で削除する。
#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
struct FakePasta {
    dir: std::path::PathBuf,
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
impl FakePasta {
    /// 信頼できる `$XDG_RUNTIME_DIR` が無ければ、skip せず名前つきの前提エラーで失敗する（fail-closed）。
    fn install() -> Self {
        use std::os::unix::fs::MetadataExt as _;
        let xdg = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from);
        let base = xdg
            .filter(|p| p.is_absolute())
            .and_then(|p| p.canonicalize().ok().filter(|c| *c == p).map(|_| p))
            .unwrap_or_else(|| {
                panic!(
                    "PRECONDITION FAILED: XDG_RUNTIME_DIR must be an absolute directory without symlinked ancestors for the fake pasta (NET-9, #3577)"
                )
            });
        // 製品の検証が後で MSG_UNTRUSTED を返したときの原因切り分けのため、試験側でも全祖先を確かめる。
        let euid = std::fs::metadata("/proc/self").expect("proc self").uid();
        let mut cur = std::path::PathBuf::new();
        for comp in base.components() {
            cur.push(comp);
            let m = std::fs::symlink_metadata(&cur).expect("stat ancestor");
            assert!(
                m.is_dir() && (m.uid() == 0 || m.uid() == euid) && m.mode() & 0o022 == 0,
                "PRECONDITION FAILED: XDG_RUNTIME_DIR ancestor {} must be a root/euid-owned directory not writable by group/other (NET-9, #3577)",
                cur.display()
            );
        }
        let dir = exclusive_dir(&base, "fc-cli-pasta-3577");
        let this = Self { dir };
        install_fake_exe(
            &this.dir,
            "pasta",
            "printf 'pasta 0.0~git20260120.386b5f5-1\\nCopyright Red Hat\\n'",
        );
        let m = std::fs::symlink_metadata(this.path()).expect("stat fake pasta");
        assert!(m.is_file() && m.mode() & 0o7777 == 0o755, "{:o}", m.mode());
        this
    }

    fn path(&self) -> std::path::PathBuf {
        self.dir.join("pasta")
    }
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
impl Drop for FakePasta {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// REPAIR-4・NET-6・CLI-1（#3577）: 実バイナリの `create --network <名前>` の成功経路と、保持区間（core の create）の
/// 中での失敗で、op ログの 2 組目が `network.store.open` 2 回・`network.store.get` 2 回（早い段の
/// `require_named_definition` と保持区間の `with_named_definition_held` の各 1 回）になること。
/// pasta は create では起動されず信頼検証（`--version` のみ）を通ればよいため、本物の検証器を通す偽の pasta
/// （[`FakePasta`]）で足りる。1 組目は本体の記録器の組。root は rootful 扱いで名前つきネットワークが
/// `UNIMPLEMENTED` のため、照合せず明示の拒否を照合する。
#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[test]
fn repair4_net6_cli1_3577_create_named_network_success_records_two_groups() {
    use std::os::unix::fs::MetadataExt as _;
    let tmp = TmpDir::new("net6-3577");
    let dir = isolated_cli_dir("net6-3577");
    let cli = dir.join("fandhe-container");
    let state = tmp.0.join("state");
    let state_s = state.to_str().expect("utf8");
    if std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0) {
        let out = run_isolated(&cli, &["--root", state_s, "network", "create", "web"]);
        assert_failure(
            &out,
            8,
            "{\"code\":\"UNIMPLEMENTED\",\"message\":\"user-defined networks on rootful installations are not supported yet\"}\n",
        );
        let _ = std::fs::remove_dir_all(dir);
        return;
    }
    let pasta = FakePasta::install();
    let pasta_path = pasta.path();
    let pasta_s = pasta_path.to_str().expect("utf8");

    let out = run_isolated(&cli, &["--root", state_s, "network", "create", "web"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");

    let config = r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#;
    let ok_bundle = tmp.0.join("bundle-ok");
    std::fs::create_dir(&ok_bundle).expect("bundle");
    std::fs::create_dir(ok_bundle.join("rootfs")).expect("rootfs");
    std::fs::write(ok_bundle.join("config.json"), config).expect("config");
    // rootfs の無い bundle: core の create が失敗する（保持区間の中での失敗）。
    let ng_bundle = tmp.0.join("bundle-norootfs");
    std::fs::create_dir(&ng_bundle).expect("bundle");
    std::fs::write(ng_bundle.join("config.json"), config).expect("config");

    let create = |log: &std::path::Path, bundle: &std::path::Path, id: &str| {
        run_exe_env(
            &cli,
            &[
                "--root",
                state_s,
                "--pasta-path",
                pasta_s,
                "create",
                "--bundle",
                bundle.to_str().expect("utf8"),
                "--network",
                "web",
                id,
            ],
            &[("FANDHE_CONTAINER_OP_LOG", log.as_os_str())],
        )
    };
    let store_group: &[(&str, u32, u32)] =
        &[("network.store.get", 2, 0), ("network.store.open", 2, 0)];

    // (e) 成功: 終了コード 0・出力なし。1 組目は本体の create、2 組目は照合 2 回ぶん。
    let log = tmp.0.join("e.jsonl");
    let out = create(&log, &ok_bundle, "c1");
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(out.stdout.is_empty() && out.stderr.is_empty(), "{out:?}");
    assert_op_log_groups(&log, &[&[("create", 1, 0)], store_group]);
    // 保持区間が状態記録まで届いた証拠: 参照中の定義は削除できない。
    let out = run_isolated(&cli, &["--root", state_s, "network", "rm", "web"]);
    assert_failure(
        &out,
        5,
        "{\"code\":\"FAILED_PRECONDITION\",\"message\":\"network is in use by a container; delete the containers that use it first\"}\n",
    );

    // (f) 保持区間の中での失敗: core の create が失敗しても 2 回目の照合は走り、2 組目に入る。
    let log = tmp.0.join("f.jsonl");
    let out = create(&log, &ng_bundle, "c2");
    assert_failure(
        &out,
        3,
        "{\"op\":\"create\",\"code\":\"NOT_FOUND\",\"message\":\"rootfs directory not found\"}\n",
    );
    assert_op_log_groups(&log, &[&[("create", 0, 1)], store_group]);
    let _ = std::fs::remove_dir_all(dir);
}
