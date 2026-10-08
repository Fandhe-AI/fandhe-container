//! 親が受けた SIGINT・SIGTERM・SIGHUP が起動中の plugin（都度起動・常駐の両方）へ転送され、親が
//! シグナル終了することの結合試験（#1513・PLUG-7・REPAIR-5）。unix のみ。root・特権不要。
//!
//! 3 つの役割を同じテストバイナリで演じる（`plugin` crate の結合試験と同方式）:
//! - ランナー（通常の `#[test]`）: 親役を起動し、親役の pid だけへシグナルを送る。plugin の停止は
//!   端末のグループ配送ではなく転送の結果であることの証拠になる
//! - 親役（`parent_entry`。`FCSF_ROLE=parent`）: ハンドラを登録し、常駐 plugin と都度起動 plugin を起動する
//! - plugin 役（`plugin_entry`。`PLUGIN_SOCKET_ENV` 設定時）: 接続後に pid をファイルへ書き、応答せず待つ
//!   （EOF を読まないので、停止は転送されたシグナルによる）
//!
//! 待ちはすべて有限の期限付き（REPAIR-5）。

#![cfg(unix)]

use fandhe_container_plugin::{
    Frame, JsonLinesPeerAuthObserver, OneShotPlugin, OneShotTimeout, PLUGIN_SOCKET_ENV,
    ResidentPlugin, ResidentStartTimeout, UdsStream, call_once,
};
use std::ffi::OsString;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(20);
const ROLE_ENV: &str = "FCSF_ROLE";
const DIR_ENV: &str = "FCSF_DIR";

/// 親役の入口。通常のテスト実行（`FCSF_ROLE` 未設定）では何もしない。
#[test]
fn parent_entry() {
    if std::env::var_os(ROLE_ENV).is_none() {
        return;
    }
    let dir = PathBuf::from(std::env::var_os(DIR_ENV).unwrap());
    fandhe_container_cli::signals::install_signal_forwarding().unwrap();
    let plugin = plugin_spec(&dir);
    let _resident = ResidentPlugin::start(
        &plugin,
        ResidentStartTimeout::default(),
        &mut JsonLinesPeerAuthObserver::new(),
    )
    .unwrap();
    // 応答しない都度起動 plugin との往復の途中にいる状態を作る。
    let one_shot = plugin_spec(&dir);
    std::thread::spawn(move || {
        let request = Frame::new(b"ping".to_vec()).unwrap();
        let _ = call_once(
            &one_shot,
            &request,
            OneShotTimeout::default(),
            &mut JsonLinesPeerAuthObserver::new(),
        );
    });
    // シグナルで終了するまで待つ（上限つき。期限を過ぎたら異常終了させる）。
    std::thread::sleep(Duration::from_secs(40));
    std::process::exit(99);
}

/// plugin 役の入口。通常のテスト実行（`PLUGIN_SOCKET_ENV` 未設定）では何もしない。
#[test]
fn plugin_entry() {
    let Some(sock) = std::env::var_os(PLUGIN_SOCKET_ENV) else {
        return;
    };
    let sock = PathBuf::from(sock);
    let _stream = UdsStream::connect(
        &sock,
        Duration::from_secs(5),
        &mut JsonLinesPeerAuthObserver::new(),
    )
    .unwrap();
    let name = sock.file_name().unwrap().to_string_lossy().into_owned();
    std::fs::write(
        sock.with_file_name(format!("{name}.pid")),
        std::process::id().to_string(),
    )
    .unwrap();
    // 応答も読み取りもしない。転送されたシグナルで終了する。
    std::thread::sleep(Duration::from_secs(40));
}

fn plugin_spec(dir: &Path) -> OneShotPlugin {
    let args: Vec<OsString> = ["--exact", "plugin_entry", "--test-threads=1"]
        .iter()
        .map(OsString::from)
        .collect();
    OneShotPlugin::new(std::env::current_exe().unwrap(), args, dir.to_path_buf()).unwrap()
}

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "fcsf-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn send(sig: &str, pid: u32) {
    let _ = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .stderr(Stdio::null())
        .status();
}

/// 生存確認。Linux ではゾンビ（回収待ち）を終了済みとして扱う（init が回収しない環境でも判定できる）。
#[cfg(target_os = "linux")]
fn is_alive(pid: u32) -> bool {
    // `pid (comm) S ...`。comm に空白や括弧を含み得るため、最後の ')' の後ろを見る。
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.trim_start().chars().next())
            .is_some_and(|state| state != 'Z')
    })
}

/// 生存確認（`kill -0`）。
#[cfg(not(target_os = "linux"))]
fn is_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// 失敗時にも親役と plugin 役を残さない。
struct Cleanup {
    parent: Child,
    plugins: Vec<u32>,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.parent.kill();
        let _ = self.parent.wait();
        for pid in &self.plugins {
            send("KILL", *pid);
        }
    }
}

/// `dir` に `resident-*.pid` と `oneshot-*.pid` が揃うのを待ち、(resident, one_shot) の pid を返す。
fn wait_plugin_pids(dir: &Path) -> (u32, u32) {
    let start = Instant::now();
    loop {
        let mut resident = None;
        let mut one_shot = None;
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".sock.pid") {
                continue;
            }
            let pid = std::fs::read_to_string(entry.path())
                .ok()
                .and_then(|t| t.trim().parse::<u32>().ok());
            if name.starts_with("resident-") {
                resident = pid.or(resident);
            } else if name.starts_with("oneshot-") {
                one_shot = pid.or(one_shot);
            }
        }
        if let (Some(r), Some(o)) = (resident, one_shot) {
            return (r, o);
        }
        assert!(start.elapsed() < WAIT, "plugins did not become ready");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn run_case(sig_name: &str, sig_num: i32) {
    let dir = TempDir::new();
    let parent = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "parent_entry", "--test-threads=1", "--nocapture"])
        .env(ROLE_ENV, "parent")
        .env(DIR_ENV, &dir.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let parent_pid = parent.id();
    let mut cleanup = Cleanup {
        parent,
        plugins: Vec::new(),
    };
    let (resident, one_shot) = wait_plugin_pids(&dir.0);
    cleanup.plugins = vec![resident, one_shot];
    assert!(is_alive(resident) && is_alive(one_shot));

    // 親だけへ送る。plugin の停止は転送の結果になる。
    send(sig_name, parent_pid);

    // A4: 親は転送後にそのシグナルで終了する。
    let start = Instant::now();
    let status = loop {
        if let Some(st) = cleanup.parent.try_wait().unwrap() {
            break st;
        }
        assert!(
            start.elapsed() < WAIT,
            "parent did not exit on SIG{sig_name}"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.signal(), Some(sig_num), "SIG{sig_name}: {status:?}");

    // A1: 都度起動・常駐の両 plugin が停止する。
    for pid in [resident, one_shot] {
        let start = Instant::now();
        while is_alive(pid) {
            assert!(
                start.elapsed() < WAIT,
                "plugin pid {pid} survived SIG{sig_name}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// PLUG-7・#1513: SIGINT を転送し、親は SIGINT で終了する。
#[test]
fn plug7_sigint_is_forwarded_and_parent_exits_by_signal() {
    run_case("INT", 2);
}

/// PLUG-7・#1513: SIGTERM を転送し、親は SIGTERM で終了する。
#[test]
fn plug7_sigterm_is_forwarded_and_parent_exits_by_signal() {
    run_case("TERM", 15);
}

/// PLUG-7・#1513: SIGHUP を転送し、親は SIGHUP で終了する。
#[test]
fn plug7_sighup_is_forwarded_and_parent_exits_by_signal() {
    run_case("HUP", 1);
}
