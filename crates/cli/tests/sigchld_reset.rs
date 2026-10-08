//! 継承した SIGCHLD の `SIG_IGN`（カーネルによる子の自動回収）の下での plugin の公開 API の終了契約と、
//! `install_signal_forwarding` が `SIG_DFL` へ戻して正常な回収に戻すことの結合試験（#1513・PLUG-7・
//! REPAIR-5・REPAIR-12。PR #1572 事後監査の P2）。unix のみ。root・特権不要。
//!
//! 3 つの役割を同じテストバイナリで演じる（`signal_forward.rs` と同方式）:
//! - ランナー（通常の `#[test]`）: 役のプロセスを起動し、役が書いた結果ファイルを期待値と全文照合する
//!   （役の試験が実行されずに成功する経路を作らない）
//! - 役（`role_entry`。`FCSC_ROLE` 設定時）: SIGCHLD を `SIG_IGN` にして（隔離したプロセスなので他の試験の
//!   子に影響しない）、都度起動・常駐の plugin を公開 API で起動し、結果を記録する。その後
//!   `install_signal_forwarding` を呼び、同じ操作の結果を記録する
//! - plugin 役（`plugin_entry`。`PLUGIN_SOCKET_ENV` 設定時）: 要求を 1 件読み、都度起動なら応答して、
//!   常駐なら応答せずに終了コード 0 で終わる（要求を読んでから終わるため、接続の受付前に終わらない）
//!
//! `SIG_IGN` の下では plugin はカーネルに自動回収され、`waitpid` が `ECHILD` を返す。plugin crate は
//! これを終端（終了状態不明）として扱い、成功扱いにしない（都度起動は `UNAVAILABLE`、常駐は状態
//! `Exited { code: None }` と `UNAVAILABLE`）。`SIG_DFL` へ戻した後は終了コード 0 を回収できる。
//!
//! 試験専用の入口（`signals::ignore_child_signal_for_test`）は feature `signal-test-support` の下にあり、
//! `Cargo.toml` の自己参照 dev-dependency で常に有効（feature が無ければコンパイルが失敗する）。
//! 待ちはすべて有限の期限付き（REPAIR-5）。

#![cfg(unix)]

use fandhe_container_plugin::{
    Frame, JsonLinesPeerAuthObserver, OneShotPlugin, OneShotTimeout, PLUGIN_SOCKET_ENV,
    ResidentPlugin, ResidentStartTimeout, RpcTimeout, UdsStream, call_once,
};
use std::ffi::OsString;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const ROLE_ENV: &str = "FCSC_ROLE";
const DIR_ENV: &str = "FCSC_DIR";
const RESULT_FILE: &str = "result";
/// 役のプロセス全体の待ち上限（REPAIR-5）。
const ROLE_TIMEOUT: Duration = Duration::from_secs(60);

/// 役が書く結果の期待値（各操作の公開 API の結果を具体値で 1 行ずつ）。
const EXPECTED: &str = "\
ignored.one_shot=Err(UNAVAILABLE)
ignored.resident.call=Err(UNAVAILABLE)
ignored.resident.state=Exited { code: None }
ignored.resident.shutdown=Err(UNAVAILABLE)
reset.one_shot=Ok(Exited { code: Some(0) })
reset.resident.call=Err(UNAVAILABLE)
reset.resident.state=Exited { code: Some(0) }
reset.resident.shutdown=Ok(Exited { code: Some(0) })
";

fn rpc(ms: u64) -> RpcTimeout {
    RpcTimeout::new(Duration::from_millis(ms)).unwrap()
}

fn plugin_spec(dir: &Path) -> OneShotPlugin {
    let args: Vec<OsString> = ["--exact", "plugin_entry", "--test-threads=1"]
        .iter()
        .map(OsString::from)
        .collect();
    OneShotPlugin::new(std::env::current_exe().unwrap(), args, dir.to_path_buf()).unwrap()
}

/// plugin 役の入口。通常のテスト実行（`PLUGIN_SOCKET_ENV` 未設定）では何もしない。
#[test]
fn plugin_entry() {
    let Some(sock) = std::env::var_os(PLUGIN_SOCKET_ENV) else {
        return;
    };
    let sock = PathBuf::from(sock);
    let mut stream = UdsStream::connect(
        &sock,
        Duration::from_secs(5),
        &mut JsonLinesPeerAuthObserver::new(),
    )
    .unwrap();
    let request = stream.read_frame(rpc(10_000)).unwrap();
    let name = sock.file_name().unwrap().to_string_lossy().into_owned();
    // 都度起動は応答してから、常駐は応答せずに終了コード 0 で終わる。
    if name.starts_with("oneshot-") {
        stream.write_frame(&request, rpc(10_000)).unwrap();
    }
}

/// 都度起動 plugin と 1 往復した結果（成功なら終了状況、失敗なら code）。
fn one_shot(dir: &Path) -> String {
    let request = Frame::new(b"ping".to_vec()).unwrap();
    match call_once(
        &plugin_spec(dir),
        &request,
        OneShotTimeout::default(),
        &mut JsonLinesPeerAuthObserver::new(),
    ) {
        Ok(outcome) => format!("Ok({:?})", outcome.termination()),
        Err(e) => format!("Err({})", e.code().as_str()),
    }
}

/// 常駐 plugin を起動し、応答せずに終わる plugin との往復・その後の状態・終了の結果を返す。
fn resident(dir: &Path) -> (String, String, String) {
    let mut session = ResidentPlugin::start(
        &plugin_spec(dir),
        ResidentStartTimeout::default(),
        &mut JsonLinesPeerAuthObserver::new(),
    )
    .unwrap();
    let request = Frame::new(b"ping".to_vec()).unwrap();
    let call = match session.call(&request, rpc(10_000)) {
        Ok(_) => "Ok".to_string(),
        Err(e) => format!("Err({})", e.code().as_str()),
    };
    let state = format!("{:?}", session.state());
    let shutdown = match session.shutdown() {
        Ok(done) => format!("Ok({:?})", done.termination()),
        Err(e) => format!("Err({})", e.error().code().as_str()),
    };
    (call, state, shutdown)
}

/// 役の入口。通常のテスト実行（`FCSC_ROLE` 未設定）では何もしない。
#[test]
fn role_entry() {
    if std::env::var_os(ROLE_ENV).is_none() {
        return;
    }
    let dir = PathBuf::from(std::env::var_os(DIR_ENV).unwrap());
    let mut out = String::new();

    // 起動元から SIGCHLD の SIG_IGN を継承した状態を再現する（plugin は自動回収される）。
    fandhe_container_cli::signals::ignore_child_signal_for_test().unwrap();
    out.push_str(&format!("ignored.one_shot={}\n", one_shot(&dir)));
    let (call, state, shutdown) = resident(&dir);
    out.push_str(&format!("ignored.resident.call={call}\n"));
    out.push_str(&format!("ignored.resident.state={state}\n"));
    out.push_str(&format!("ignored.resident.shutdown={shutdown}\n"));

    // 公開入口で SIGCHLD を SIG_DFL へ戻すと、終了コードを回収できる。
    fandhe_container_cli::signals::install_signal_forwarding().unwrap();
    out.push_str(&format!("reset.one_shot={}\n", one_shot(&dir)));
    let (call, state, shutdown) = resident(&dir);
    out.push_str(&format!("reset.resident.call={call}\n"));
    out.push_str(&format!("reset.resident.state={state}\n"));
    out.push_str(&format!("reset.resident.shutdown={shutdown}\n"));

    let tmp = dir.join(format!("{RESULT_FILE}.tmp"));
    std::fs::write(&tmp, out).unwrap();
    std::fs::rename(&tmp, dir.join(RESULT_FILE)).unwrap();
}

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "fcsc-{}-{}",
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

/// PLUG-7・#1513: SIGCHLD の `SIG_IGN` の下では、都度起動・常駐とも他所で回収された plugin を成功扱いに
/// せず（`UNAVAILABLE`・`Exited { code: None }`）、`install_signal_forwarding` が `SIG_DFL` へ戻した後は
/// 終了コード 0 を回収できる。
#[test]
fn plug7_inherited_sigchld_ignore_is_reset_and_lost_children_fail_closed() {
    let dir = TempDir::new();
    let mut role = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "role_entry", "--test-threads=1"])
        .env(ROLE_ENV, "1")
        .env(DIR_ENV, &dir.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(st) = role.try_wait().unwrap() {
            break st;
        }
        if start.elapsed() >= ROLE_TIMEOUT {
            let _ = role.kill();
            // kill 後の回収にも有限の期限を設ける（無期限の `wait` を残さない。REPAIR-5）。
            let reap_start = Instant::now();
            while reap_start.elapsed() < Duration::from_secs(5) {
                if !matches!(role.try_wait(), Ok(None)) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("role did not finish within {ROLE_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "role failed: {status:?}");
    let result = std::fs::read_to_string(dir.0.join(RESULT_FILE)).unwrap();
    assert_eq!(result, EXPECTED);
}
