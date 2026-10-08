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
//! 親が受けたシグナルでの終了検証（`run_case`）では、Linux の plugin が `PR_SET_PDEATHSIG(SIGKILL)` で
//! 親の死に追従するため、plugin の停止だけでは転送の有無を区別できない。そこで転送の受信は、親を
//! 生かしたまま `forward_to_running_plugins` を直接呼ぶ `run_direct_case` で、plugin 役が記録した
//! シグナル番号の具体値として検証する。
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
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(20);
const ROLE_ENV: &str = "FCSF_ROLE";
const DIR_ENV: &str = "FCSF_DIR";
/// 設定時、親役はシグナルを受けず、トリガーファイルの指示で転送関数を直接呼ぶ（親は生存し続ける）。
const DIRECT_ENV: &str = "FCSF_DIRECT";
const TRIGGER_FILE: &str = "trigger";

/// plugin 役のハンドラが受信シグナル番号を残す先（async-signal-safe な原子変数）。
static RECEIVED: AtomicI32 = AtomicI32::new(0);

extern "C" fn record_signal(sig: i32) {
    RECEIVED.store(sig, Ordering::SeqCst);
}

/// 親役の入口。通常のテスト実行（`FCSF_ROLE` 未設定）では何もしない。
#[test]
fn parent_entry() {
    if std::env::var_os(ROLE_ENV).is_none() {
        return;
    }
    let dir = PathBuf::from(std::env::var_os(DIR_ENV).unwrap());
    let direct = std::env::var_os(DIRECT_ENV).is_some();
    if !direct {
        fandhe_container_cli::signals::install_signal_forwarding().unwrap();
    }
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
    if direct {
        // トリガーが書かれたら、その番号のシグナルを登録済み plugin へ転送する。親は終了しない。
        let start = Instant::now();
        let sig = loop {
            if let Some(n) = std::fs::read_to_string(dir.join(TRIGGER_FILE))
                .ok()
                .and_then(|t| t.trim().parse::<i32>().ok())
            {
                break n;
            }
            assert!(start.elapsed() < WAIT, "trigger did not arrive");
            std::thread::sleep(Duration::from_millis(10));
        };
        let forward = fandhe_container_plugin::ForwardSignal::from_raw(sig).unwrap();
        let _ = fandhe_container_plugin::forward_to_running_plugins(forward);
        std::thread::sleep(Duration::from_secs(40));
        std::process::exit(98);
    }
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
    // 応答も読み取りもしない。受信したシグナル番号を記録して終了する（記録はハンドラ外で行う）。
    for sig in [1, 2, 15] {
        fandhe_container_cli::signals::install_recording_handler_for_test(sig, record_signal)
            .unwrap();
    }
    // 全ハンドラの登録後に PID ファイル（準備完了の合図）を公開する。先に公開すると、転送が先に届いて
    // 既定動作で終了し得る。
    std::fs::write(
        sock.with_file_name(format!("{name}.pid")),
        std::process::id().to_string(),
    )
    .unwrap();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(40) {
        let sig = RECEIVED.load(Ordering::SeqCst);
        if sig != 0 {
            let tmp = sock.with_file_name(format!("{name}.sig.tmp"));
            std::fs::write(&tmp, sig.to_string()).unwrap();
            std::fs::rename(&tmp, sock.with_file_name(format!("{name}.sig"))).unwrap();
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
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

/// 補助コマンド（`kill`）の待ち上限（REPAIR-5）。
const HELPER_TIMEOUT: Duration = Duration::from_secs(10);

/// 子の終了を `limit` まで `try_wait` で待つ。上限超過なら kill して回収を再試行し、None を返す。
fn wait_bounded(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Some(st),
            Ok(None) => {}
            Err(_) => return None,
        }
        if start.elapsed() >= limit {
            let _ = child.kill();
            return child.try_wait().ok().flatten();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// 期限付きでコマンドを実行し、成功終了なら true（期限超過・起動失敗は false）。
fn run_bounded(cmd: &mut Command) -> bool {
    match cmd.spawn() {
        Ok(mut c) => wait_bounded(&mut c, HELPER_TIMEOUT).is_some_and(|s| s.success()),
        Err(_) => false,
    }
}

fn send(sig: &str, pid: u32) {
    let _ = run_bounded(
        Command::new("kill")
            .arg(format!("-{sig}"))
            .arg(pid.to_string())
            .stderr(Stdio::null()),
    );
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
    run_bounded(
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null()),
    )
}

/// 失敗時にも親役を残さない。
///
/// plugin 役へは SIGKILL を送らない。plugin 役は終了済みで pid が再利用され得るうえ、Linux では親役の
/// kill で `PR_SET_PDEATHSIG` により停止し、その他でも自前の期限（40 秒）で終了するため。
struct Cleanup {
    parent: Child,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.parent.kill();
        // kill が失敗しても有限時間で戻る（REPAIR-5）。
        let _ = wait_bounded(&mut self.parent, HELPER_TIMEOUT);
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
    let mut cleanup = Cleanup { parent };
    let (resident, one_shot) = wait_plugin_pids(&dir.0);
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

/// 転送の受信検証。親を生かしたまま転送関数を直接呼び、各 plugin 役が記録した番号が `sig_num` と
/// 一致することを具体値で確認する（PDEATHSIG による停止とは区別される。REPAIR-12）。
fn run_direct_case(sig_num: i32) {
    let dir = TempDir::new();
    let parent = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "parent_entry", "--test-threads=1", "--nocapture"])
        .env(ROLE_ENV, "parent")
        .env(DIRECT_ENV, "1")
        .env(DIR_ENV, &dir.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut cleanup = Cleanup { parent };
    let _ = wait_plugin_pids(&dir.0);
    std::fs::write(dir.0.join(TRIGGER_FILE), sig_num.to_string()).unwrap();

    let start = Instant::now();
    let records = loop {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(&dir.0).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".sock.sig") {
                found.push((name, std::fs::read_to_string(entry.path()).unwrap()));
            }
        }
        if found.len() == 2 {
            break found;
        }
        assert!(
            start.elapsed() < WAIT,
            "plugins did not record the signal: {found:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    for (name, content) in &records {
        assert_eq!(content.trim(), sig_num.to_string(), "{name}");
    }
    // 親は生存したまま（停止は親の死ではなく転送によるもの）。
    assert!(cleanup.parent.try_wait().unwrap().is_none());
}

/// PLUG-7・#1513: 転送された SIGINT・SIGTERM・SIGHUP の番号が、都度起動・常駐の両 plugin に届く。
#[test]
fn plug7_forwarded_signal_number_reaches_both_plugins() {
    run_direct_case(2);
    run_direct_case(15);
    run_direct_case(1);
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

/// PLUG-7・#1513: 起動時に SIGHUP が無視されていた（nohup 相当）場合はハンドラを上書きせず、
/// SIGHUP を受けても親も plugin も終了しない（転送もしない）。
#[test]
fn plug7_sighup_ignored_at_startup_is_kept_and_not_forwarded() {
    let dir = TempDir::new();
    // `sh` で SIGHUP を無視してから exec することで、親役は SIG_IGN を継承した状態で起動する。
    let parent = Command::new("sh")
        .args(["-c", "trap '' HUP; exec \"$0\" \"$@\""])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "parent_entry", "--test-threads=1", "--nocapture"])
        .env(ROLE_ENV, "parent")
        .env(DIR_ENV, &dir.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let parent_pid = parent.id();
    let mut cleanup = Cleanup { parent };
    let (resident, one_shot) = wait_plugin_pids(&dir.0);

    send("HUP", parent_pid);

    // 取りこぼしを検出できる程度の有限の猶予の間、親も plugin も生存し続ける。
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(1) {
        assert!(
            cleanup.parent.try_wait().unwrap().is_none(),
            "parent exited although SIGHUP was ignored at startup"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(is_alive(resident) && is_alive(one_shot));
}
