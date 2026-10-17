//! バイナリ `fandhe-container` の入口の結合試験（CLI-1・REPAIR-12。TASK-79.1・MS-6）。
//!
//! 実バイナリを起動し、終了コード・stderr の 1 行 JSON・stdout が空であることを具体値で照合する。

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const USAGE_JSON: &str = "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"usage: fandhe-container <create|start|stop|delete|list|logs|setup|doctor>\"}\n";
#[cfg(target_os = "linux")]
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
        &["start"],
        &["start", "a", "b"],
        &["--root"],
    ] {
        assert_failure(&run(a), 2, USAGE_JSON);
    }
}

/// CLI-1: stop / delete は引数の過不足・未知オプション・`--force` 重複で使い方エラー（2）。
#[test]
fn cli1_stop_delete_usage_errors() {
    for a in [
        &["stop"][..],
        &["stop", "a", "b"],
        &["stop", "--force", "c1"],
        &["delete"],
        &["delete", "--x", "c1"],
        &["delete", "--force", "--force", "c1"],
        &["delete", "a", "b"],
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

/// 実バイナリを `CARGO_TARGET_TMPDIR` 配下の一意なディレクトリへ置き直す（hard link、失敗したらコピー）。
///
/// `start` は CLI 自身の実体パスの隣の固定名 `fandhe-container-supervisor` を起動するため、`target/debug/` に
/// 兄弟の supervisor bin があるかどうかに結果が左右されないようにする（#1718）。
#[cfg(target_os = "linux")]
fn isolated_cli_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("fc-cli-iso-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
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
    std::fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
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
        std::fs::create_dir_all(xdg.join("systemd")).expect("mkdir xdg");
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
    std::fs::create_dir_all(&bin).expect("mkdir bin");
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
    std::fs::create_dir_all(&bin).expect("mkdir bin");
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
    std::fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
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

    for (cmd, op) in [("stop", "kill"), ("delete", "delete")] {
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
    std::fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
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

/// SEC-1・PLUG-4: Linux 以外では plugin 発見機構経由になり、候補なし（既定探索先が空）の fail-closed で
/// FAILED_PRECONDITION（5）。状態ルートは作らない。
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
    assert!(!root.exists());
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
    for (cmd, op) in [("stop", "kill"), ("delete", "delete")] {
        let out = run(&["--root", root.to_str().expect("utf8"), cmd, "c1"]);
        assert_eq!(out.status.code(), Some(5));
        assert_eq!(op_and_code(&out), (op.into(), "FAILED_PRECONDITION".into()));
        assert!(out.stdout.is_empty());
    }
}

/// CLI-1・ERR-2: Linux で list は stdout にタブ区切りの一覧を出し（0 件はヘッダのみ・ID 昇順）、
/// logs は不正 ID が 2、未作成が 3、存在する対象は内容未実装のため 8（stdout は空）。
#[cfg(target_os = "linux")]
#[test]
fn cli1_list_logs_flow_on_linux() {
    let tmp = TmpDir::new("listlogs");
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
    assert_failure(
        &run(&["--root", root_s, "logs", "a1"]),
        8,
        UNIMPLEMENTED_JSON,
    );
    assert_failure(
        &run(&["--root", root_s, "logs", "a/b"]),
        2,
        "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"invalid argument\"}\n",
    );
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

/// PLUG-11・CLI-1・REPAIR-12: `--plugin-path-search` で opt-in すると候補ごとに警告が stderr へ出る
/// （macOS / Windows の 2 候補で 2 行）。名前一致だけでは採用されず、信頼性検証の未実装で拒否される
/// （UNIMPLEMENTED = 8）。
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
    assert_eq!(out.status.code(), Some(8));
    assert_eq!(path_warning_lines(&out), 2);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let last = stderr.lines().last().expect("last line");
    // 「未導入」（FAILED_PRECONDITION）とは別の識別子で、パス・plugin 名を含まない（C1）。
    assert_eq!(
        last,
        "{\"code\":\"UNIMPLEMENTED\",\"message\":\"plugin trust verification is not implemented on this platform\"}"
    );
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
    assert_eq!(out.status.code(), Some(8));
    assert_eq!(path_warning_lines(&out), 2);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        stderr.lines().last().expect("last line"),
        "{\"code\":\"UNIMPLEMENTED\",\"message\":\"plugin trust verification is not implemented on this platform\"}"
    );
    assert!(out.stdout.is_empty());
}

/// CLI-2: setup は引数を受け付けない（使い方エラー 2）。
#[test]
fn cli2_setup_usage_errors() {
    for a in [&["setup", "extra"][..], &["setup", "--x"][..]] {
        assert_failure(&run(a), 2, USAGE_JSON);
    }
}

/// CLI-2: Linux の setup は要求ステップがなく、終了コード 0・出力なし。
#[cfg(target_os = "linux")]
#[test]
fn cli2_setup_on_linux_is_noop() {
    assert_failure_free(&run(&["setup"]));
}

/// CLI-2・REPAIR-3: macOS / Windows の setup は要求ステップを stdout へ出し、自動適用未実装のため 8 で失敗する。
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn cli2_setup_on_non_linux_lists_steps_and_fails() {
    let out = run(&["setup"]);
    assert_eq!(out.status.code(), Some(8));
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.lines().count() >= 2, "{stdout:?}");
    assert!(stdout.lines().all(|l| l.starts_with("{\"step\":\"")));
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
    std::fs::create_dir_all(&empty).expect("mkdir");
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

/// CLI-1（#2133）: `doctor` に余計な引数を渡すと使い方エラー（2）。stdout は空。
#[test]
fn doctor_rejects_extra_arguments() {
    let out = run(&["doctor", "extra"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert_eq!(String::from_utf8(out.stderr).expect("utf8"), USAGE_JSON);
}
