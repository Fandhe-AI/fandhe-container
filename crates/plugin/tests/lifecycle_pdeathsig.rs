//! 親の強制終了時に plugin 本体が止まることの結合試験（PLUG-7・REPAIR-5・CORE-1。#1514・#1403 の方式 B）。
//!
//! Linux 限定の機構（`PR_SET_PDEATHSIG`）の検証のため `cfg(target_os = "linux")` で限定する（他 OS は
//! 設定自体を行わず、従来どおり起動できることを既存の lifecycle 試験が確認する）。root・特権不要。
//!
//! 3 段構成: 外側のテスト -> 中間プロセス（テストバイナリ自身の再実行。plugin を起動する core 側の役）
//! -> plugin 本体（同じくテストバイナリの再実行）。外側が中間プロセスを SIGKILL し、plugin 本体が
//! 止まる（消滅・ゾンビ・pid 再利用のいずれか）ことを pid で確かめる。待ちはすべて有限の期限付き。
//! 中間プロセスの役割と一時ディレクトリは環境変数で渡す（plugin 本体は `env_clear()` されるため見えない）。
//!
//! fork から prctl までの窓そのものは、親を決定的に割り込ませる手段がなく再現できない。親 pid の照合
//! 分岐は `sys` の単体テスト（`plug7_pdeathsig_mismatched_parent_pid_aborts_exec`）で代替検証している。

#![cfg(target_os = "linux")]

use fandhe_container_plugin::{
    Frame, JsonLinesPeerAuthObserver, OneShotPlugin, OneShotTimeout, PLUGIN_SOCKET_ENV,
    ResidentPlugin, ResidentStartTimeout, UdsStream, call_once,
};
use std::ffi::OsString;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ROLE_ENV: &str = "FC_PDEATH_ROLE";
const DIR_ENV: &str = "FC_PDEATH_DIR";
/// 中間プロセス・plugin 本体が自力で終了するまでの上限（テストが失敗しても残留を有限にする）。
const SELF_EXIT: Duration = Duration::from_secs(20);
const WAIT: Duration = Duration::from_secs(8);

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("fcpd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 子の回収を `try_wait` のポーリングと期限で行う（REPAIR-5。無期限の `wait` を避ける）。
/// 期限内に回収できなければ `false`（呼び出し側が kill 済みであることを前提に、ここでは待たない）。
fn reap_bounded(child: &mut Child, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return true,
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// 失敗経路でも中間プロセスを残さない（Drop の回収にも `WAIT` の上限を適用する）。
struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = reap_bounded(&mut self.0, WAIT);
    }
}

/// plugin 本体の入口。通常のテスト実行（`PLUGIN_SOCKET_ENV` 未設定）では何もしない。
/// 自 pid を書き出して接続し、応答せずに待つ。
#[test]
fn plugin_child_entry() {
    let Some(sock) = std::env::var_os(PLUGIN_SOCKET_ENV) else {
        return;
    };
    let sock = PathBuf::from(sock);
    let dir = sock.parent().unwrap();
    let tmp = dir.join("plugin.pid.tmp");
    std::fs::write(&tmp, std::process::id().to_string()).unwrap();
    std::fs::rename(&tmp, dir.join("plugin.pid")).unwrap();
    let _stream = UdsStream::connect(
        &sock,
        Duration::from_secs(5),
        &mut JsonLinesPeerAuthObserver::new(),
    )
    .unwrap();
    std::thread::sleep(SELF_EXIT);
}

/// 中間プロセスの入口（core 側の役）。役割の環境変数が無ければ何もしない。
/// 起動した同じスレッドで待ち続け、外側から SIGKILL される。
#[test]
fn intermediate_entry() {
    let (Some(role), Some(dir)) = (std::env::var_os(ROLE_ENV), std::env::var_os(DIR_ENV)) else {
        return;
    };
    let args: Vec<OsString> = ["--exact", "plugin_child_entry", "--test-threads=1"]
        .iter()
        .map(OsString::from)
        .collect();
    let plugin =
        OneShotPlugin::new(std::env::current_exe().unwrap(), args, PathBuf::from(dir)).unwrap();
    let mut audit = JsonLinesPeerAuthObserver::new();
    if role == "oneshot" {
        // plugin は応答しないので、外側に kill されるまでここで待つ。
        let _ = call_once(
            &plugin,
            &Frame::new(b"ping".to_vec()).unwrap(),
            OneShotTimeout::new(Duration::from_secs(10)).unwrap(),
            &mut audit,
        );
    } else {
        let _session =
            ResidentPlugin::start(&plugin, ResidentStartTimeout::default(), &mut audit).unwrap();
        std::thread::sleep(SELF_EXIT);
    }
}

/// `/proc/<pid>/stat` の (状態, ppid, starttime)。プロセスが無ければ `None`。
fn stat(pid: u32) -> Option<(char, u32, u64)> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm は括弧内に空白・括弧を含み得るため、最後の `)` の後ろから読む。
    let rest = text.get(text.rfind(')')? + 1..)?;
    let f: Vec<&str> = rest.split_whitespace().collect();
    Some((
        f.first()?.chars().next()?,
        f.get(1)?.parse().ok()?,
        f.get(19)?.parse().ok()?,
    ))
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn read_pid(dir: &Path) -> Option<u32> {
    std::fs::read_to_string(dir.join("plugin.pid"))
        .ok()?
        .parse()
        .ok()
}

fn run(role: &str) {
    let dir = TempDir::new(role);
    let intermediate = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "intermediate_entry", "--test-threads=1"])
        .env(ROLE_ENV, role)
        .env(DIR_ENV, &dir.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mid_pid = intermediate.id();
    let mut intermediate = KillOnDrop(intermediate);

    wait_until("plugin.pid", || read_pid(&dir.0).is_some());
    let plugin_pid = read_pid(&dir.0).unwrap();
    let (state, ppid, start_time) = stat(plugin_pid).expect("plugin must be running");
    assert_ne!(state, 'Z', "plugin pid {plugin_pid} must be alive");
    // plugin 本体は中間プロセスの直接の子である（PR_SET_PDEATHSIG が効く関係）。
    assert_eq!(ppid, mid_pid);

    intermediate.0.kill().unwrap();
    assert!(
        reap_bounded(&mut intermediate.0, WAIT),
        "timed out reaping the SIGKILLed intermediate process"
    );

    wait_until("plugin to stop after parent SIGKILL", || {
        match stat(plugin_pid) {
            None => true,
            // PID 1 が回収しない環境ではゾンビで残る。止まってはいる。
            Some(('Z', _, _)) => true,
            // pid が別プロセスに再利用された。
            Some((_, _, t)) => t != start_time,
        }
    });
}

/// PLUG-7・REPAIR-5・CORE-1・#1514: 都度起動の親が SIGKILL されると plugin 本体も止まる。
#[test]
fn plug7_pdeathsig_kills_oneshot_plugin_when_parent_is_sigkilled() {
    run("oneshot");
}

/// PLUG-7・REPAIR-5・CORE-1・#1514: 常駐の親が SIGKILL されると plugin 本体も止まる。
#[test]
fn plug7_pdeathsig_kills_resident_plugin_when_parent_is_sigkilled() {
    run("resident");
}
