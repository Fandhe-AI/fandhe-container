//! `start` の結果待ちの間にシグナルを受けたときの扱いの結合試験（#2069・CLI-1・ERR-2・REPAIR-5・PLUG-7・MS-6）。
//!
//! 契約は `crates/cli/src/commands/supervisor_start.rs` の module doc「待機中のシグナル」にある。ここでは
//! 結果の 1 行を返さないスタブ supervisor を CLI の隣に置き、待機中の CLI へ SIGINT・SIGTERM・SIGHUP を送って、
//! 終了の仕方（受けたシグナルでのシグナル終了）・stderr / stdout が空であること・スタブが生き続けること・
//! 状態が Created のままであることを具体値で照合する。
//!
//! root 不要・Linux のみ。待ちはすべて有限期限（REPAIR-5）。ヘルパーは `binary_entry.rs` の最小の複製
//! （同ファイルとの衝突を避けるため `tests/common/` へは切り出さない）。
//! 注意: 実行環境が SIGINT / SIGHUP を `SIG_IGN` で継承していると CLI はハンドラを入れず無視するため、
//! 試験は期限で失敗する（`signal_forward.rs` と同じ前提。CI のランナーでは成立する）。
#![cfg(target_os = "linux")]

use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// スタブの pid ファイルが現れるまで・CLI の終了を待つ上限（REPAIR-5。CLI の受信期限 58.9 秒より十分短い）。
const STUB_READY_TIMEOUT: Duration = Duration::from_secs(20);
const CLI_EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(10);

// 一時領域の親を tmpfiles の flock 走査から守る共有部品（#3026・CORE-5・REPAIR-12）。
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

// kill 後の回収を期限つきにする共有補助（#3303・REPAIR-5）。
#[path = "../../core/tests/support/reap.rs"]
mod reap;

/// 状態ルートの祖先を 0700 にした一時ディレクトリ（Drop で削除）。第 2 フィールドは tmpfiles の flock 走査から守る
/// 親（最後のため `Drop` の削除の後に消える。#3026）。
struct TmpDir(
    PathBuf,
    #[allow(dead_code)] scratch_root::ScratchDir, // 保持が目的（drop で親を消す）
);

impl TmpDir {
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        // 状態ルートの祖先は group / other 書き込み不可でなければならないため、target 配下ではなく OS の一時領域に置く。
        let scratch =
            scratch_root::ScratchDir::new("fc-cli-sigint", std::time::Duration::from_secs(10));
        let p = scratch.path().join(tag);
        std::fs::create_dir_all(&p).expect("mkdir");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        Self(p, scratch)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 失敗時にも CLI とスタブを残さない。
struct Guard {
    cli: Child,
    stub_pid: Option<u32>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        // 回収の失敗でスタブの KILL が抜けないよう、先にスタブを片付けてから失敗を表に出す。
        let reaped = reap::reap(&mut self.cli, reap::reap_within());
        if let Some(pid) = self.stub_pid {
            send("KILL", pid, false);
        }
        if let Err(e) = reaped {
            if thread::panicking() {
                eprintln!("reap failure: {e}");
            } else {
                panic!("reap failure: {e}");
            }
        }
    }
}

fn is_alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.trim_start().chars().next())
            .is_some_and(|state| state != 'Z')
    })
}

/// `kill -<sig>` を送る。`group` のときはプロセスグループ宛て。
fn send(sig: &str, pid: u32, group: bool) {
    let target = if group {
        format!("-{pid}")
    } else {
        pid.to_string()
    };
    let mut c = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg("--")
        .arg(target)
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kill");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if matches!(c.try_wait(), Ok(Some(_))) {
            return;
        }
        thread::sleep(POLL);
    }
    reap::reap_or_report(&mut c, reap::reap_within());
    panic!("kill command did not finish (REPAIR-5)");
}

fn spawn_reader<R: Read + Send + 'static>(mut pipe: R) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    rx
}

/// 子プロセスを期限付きで回収して成功を確かめる。
fn wait_ok(mut c: Child, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(st) = c.try_wait().expect("poll") {
            assert!(st.success(), "{what} failed");
            return;
        }
        if Instant::now() >= deadline {
            reap::reap_or_report(&mut c, reap::reap_within());
            panic!("{what} timed out (REPAIR-5)");
        }
        thread::sleep(POLL);
    }
}

/// 実バイナリを `CARGO_TARGET_TMPDIR` 配下へ置き直す（CLI は自分の隣の supervisor を起動するため）。
fn isolated_cli_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("fc-cli-sigint-bin-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let dst = dir.join("fandhe-container");
    let src = env!("CARGO_BIN_EXE_fandhe-container");
    if std::fs::hard_link(src, &dst).is_err() {
        std::fs::copy(src, &dst).expect("copy cli");
    }
    dir
}

/// スタブ supervisor を書く。作成と chmod は子プロセスで行う（ETXTBSY の回避）。
fn install_stub_supervisor(dir: &Path, body: &str) {
    install_stub_exe(dir, "fandhe-container-supervisor", body);
}

/// 固定名 `name` のスタブ（シェルスクリプト）を `dir` に置く。
fn install_stub_exe(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    let mut c = Command::new("/bin/sh")
        .arg("-c")
        .arg("cat > \"$1\" && chmod 755 \"$1\"")
        .arg("install-stub")
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn install");
    {
        use std::io::Write;
        c.stdin
            .take()
            .expect("stdin")
            .write_all(format!("#!/bin/sh\n{body}\n").as_bytes())
            .expect("write stub");
    }
    wait_ok(c, "install stub");
}

/// 偽の systemd-run（本物と同じく包み込みの引数を検査して残りを exec する）と偽の user マネージャのソケット。
/// 返す `UnixListener` は試験の間保持する（#2081）。
fn install_fake_scope(
    dir: &Path,
    tmp: &TmpDir,
) -> (PathBuf, PathBuf, std::os::unix::net::UnixListener) {
    install_stub_exe(
        dir,
        "fake-systemd-run",
        r#"[ "$1 $2 $3 $4 $5 $6" = "--user --scope --quiet -p Delegate=yes --" ] || { printf 'FCSUP1 ERR INTERNAL 1 badwrapper
'; exit 0; }
shift 6
exec "$@""#,
    );
    let xdg = tmp.0.join("xdg");
    std::fs::create_dir_all(xdg.join("systemd")).expect("mkdir xdg");
    let listener = std::os::unix::net::UnixListener::bind(xdg.join("systemd").join("private"))
        .expect("bind fake user manager socket");
    (dir.join("fake-systemd-run"), xdg, listener)
}

fn cli_command(cli: &Path) -> Command {
    let mut c = Command::new(cli);
    c.env_remove("FANDHE_CONTAINER_PLUGIN_PATH_SEARCH")
        .stdin(Stdio::null());
    c
}

/// 状態ルートに Created のコンテナ `c1` を作り、状態ルートの文字列を返す。
fn prepare_c1(tmp: &TmpDir, cli: &Path) -> String {
    let bundle = tmp.0.join("bundle");
    std::fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
    std::fs::write(
        bundle.join("config.json"),
        r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .expect("config");
    let root_s = tmp.0.join("state").to_str().expect("utf8").to_string();
    let c = cli_command(cli)
        .args(["--root", &root_s, "create", "--bundle"])
        .arg(&bundle)
        .arg("c1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn create");
    wait_ok(c, "create");
    root_s
}

/// `list` の stdout を期限付きで取る。
fn list_stdout(cli: &Path, root_s: &str) -> String {
    let mut c = cli_command(cli)
        .args(["--root", root_s, "list"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn list");
    let rx = spawn_reader(c.stdout.take().expect("stdout"));
    let out = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("list output (REPAIR-5)");
    wait_ok(c, "list");
    String::from_utf8_lossy(&out).into_owned()
}

/// 結果の行を書かず、pid を記録して 40 秒眠るスタブ（自前の期限で終わる）。
const STUB_BODY: &str = "d=$(dirname \"$0\"); echo $$ > \"$d/stub.pid.tmp\" && mv \"$d/stub.pid.tmp\" \"$d/stub.pid\"; exec sleep 40";

struct Started {
    guard: Guard,
    out_rx: mpsc::Receiver<Vec<u8>>,
    err_rx: mpsc::Receiver<Vec<u8>>,
    stub_pid: u32,
    started: Instant,
}

/// CLI の `start c1` を spawn し、スタブが待機に入る（pid ファイルが現れる）まで待つ。
fn start_waiting(dir: &Path, root_s: &str, own_group: bool, scope: &(PathBuf, PathBuf)) -> Started {
    let cli = dir.join("fandhe-container");
    let mut cmd = cli_command(&cli);
    cmd.args(["--root", root_s, "start", "c1"])
        .env("FANDHE_CONTAINER_TEST_SYSTEMD_RUN", &scope.0)
        .env("XDG_RUNTIME_DIR", &scope.1)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if own_group {
        cmd.process_group(0);
    }
    let started = Instant::now();
    let mut child = cmd.spawn().expect("spawn cli");
    let out_rx = spawn_reader(child.stdout.take().expect("stdout"));
    let err_rx = spawn_reader(child.stderr.take().expect("stderr"));
    let mut guard = Guard {
        cli: child,
        stub_pid: None,
    };
    let deadline = Instant::now() + STUB_READY_TIMEOUT;
    let stub_pid = loop {
        if let Ok(s) = std::fs::read_to_string(dir.join("stub.pid"))
            && let Ok(pid) = s.trim().parse::<u32>()
        {
            break pid;
        }
        assert!(
            Instant::now() < deadline,
            "stub supervisor did not start (REPAIR-5)"
        );
        thread::sleep(POLL);
    };
    guard.stub_pid = Some(stub_pid);
    Started {
        guard,
        out_rx,
        err_rx,
        stub_pid,
        started,
    }
}

/// CLI の終了を期限付きで待ち、(status, stdout, stderr) を返す。
fn wait_cli(s: &mut Started) -> (std::process::ExitStatus, Vec<u8>, Vec<u8>) {
    let deadline = Instant::now() + CLI_EXIT_TIMEOUT;
    let status = loop {
        if let Some(st) = s.guard.cli.try_wait().expect("poll") {
            break st;
        }
        assert!(
            Instant::now() < deadline,
            "cli did not exit after the signal (REPAIR-5)"
        );
        thread::sleep(POLL);
    };
    let out = s.out_rx.recv_timeout(CLI_EXIT_TIMEOUT).expect("stdout");
    let err = s.err_rx.recv_timeout(CLI_EXIT_TIMEOUT).expect("stderr");
    (status, out, err)
}

fn kill_stub_and_wait(pid: u32) {
    send("KILL", pid, false);
    let deadline = Instant::now() + Duration::from_secs(10);
    while is_alive(pid) {
        assert!(Instant::now() < deadline, "stub did not exit (REPAIR-5)");
        thread::sleep(POLL);
    }
}

/// CLI-1・ERR-2・REPAIR-5・PLUG-7（#2069）: 結果待ちの間の SIGINT・SIGTERM・SIGHUP で CLI は受けた
/// シグナルで終了し（コード無し・stderr / stdout 空）、supervisor は生き続け、状態は Created のまま。
#[test]
fn cli1_repair5_signal_while_waiting_ends_cli_by_signal_and_keeps_supervisor() {
    for (name, num) in [("INT", 2), ("TERM", 15), ("HUP", 1)] {
        let tmp = TmpDir::new(&format!("a-{name}"));
        let dir = isolated_cli_dir(&format!("a-{name}"));
        let cli = dir.join("fandhe-container");
        let root_s = prepare_c1(&tmp, &cli);
        install_stub_supervisor(&dir, STUB_BODY);
        let (sd, xdg, _listener) = install_fake_scope(&dir, &tmp);

        let mut s = start_waiting(&dir, &root_s, false, &(sd, xdg));
        let cli_pid = s.guard.cli.id();
        send(name, cli_pid, false);
        let (status, out, err) = wait_cli(&mut s);

        assert_eq!(status.signal(), Some(num), "{name}");
        assert_eq!(status.code(), None, "{name}");
        assert_eq!(err, b"".to_vec(), "{name}: stderr");
        assert_eq!(out, b"".to_vec(), "{name}: stdout");
        assert!(s.started.elapsed() < Duration::from_secs(30), "{name}");
        assert!(is_alive(s.stub_pid), "{name}: stub must survive");
        assert_eq!(
            list_stdout(&cli, &root_s),
            "ID\tSTATUS\tPID\nc1\tcreated\t-\n",
            "{name}"
        );

        kill_stub_and_wait(s.stub_pid);
        s.guard.stub_pid = None;
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// CLI-1・REPAIR-5（#2069）: 端末の Ctrl-C の模擬。CLI を自前のプロセスグループで起動し、グループ宛てに
/// SIGINT を送る。supervisor は `process_group(0)` で別グループのため届かず、生き続ける。
#[test]
fn cli1_terminal_sigint_to_foreground_group_does_not_reach_supervisor() {
    let tmp = TmpDir::new("b");
    let dir = isolated_cli_dir("b");
    let cli = dir.join("fandhe-container");
    let root_s = prepare_c1(&tmp, &cli);
    install_stub_supervisor(&dir, STUB_BODY);
    let (sd, xdg, _listener) = install_fake_scope(&dir, &tmp);

    let mut s = start_waiting(&dir, &root_s, true, &(sd, xdg));
    send("INT", s.guard.cli.id(), true);
    let (status, out, err) = wait_cli(&mut s);

    assert_eq!(status.signal(), Some(2));
    assert_eq!(status.code(), None);
    assert_eq!(err, b"".to_vec());
    assert_eq!(out, b"".to_vec());
    assert!(is_alive(s.stub_pid), "stub must survive the group SIGINT");
    assert_eq!(
        list_stdout(&cli, &root_s),
        "ID\tSTATUS\tPID\nc1\tcreated\t-\n"
    );

    kill_stub_and_wait(s.stub_pid);
    s.guard.stub_pid = None;
    let _ = std::fs::remove_dir_all(dir);
}
