//! supervisor の bin（`fandhe-container-supervisor`）の外形の結合試験（TASK-157 追補・#1717・SUP-1・REPAIR-2・REPAIR-3・CLI-1）。
//!
//! 実バイナリを CLI と同じ契約（argv・stdout の pipe の結果チャネル）で起動し、報告 1 行・終了コード・状態を具体値で
//! 照合する。root 不要で既定のテスト集合で動く。core の本番 `ProcessLauncher`（#1715 の Phase B）が無い間、
//! 起動は `UNIMPLEMENTED` で止まる。この挙動を固定するのが `repair3_bin_fails_closed_until_core_launcher_exists` で、
//! Phase B の PR で Running を照合する試験に置き換える。`FileStateStore` は Linux 限定のため全体を Linux に限る。

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{create, exit_code_for};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, CreateRequest, ErrorCode, GetStateRequest, StateStore,
};
use fandhe_container_supervisor::start_contract::StartReport;
use fandhe_container_supervisor::state::open_default_store;

struct Env {
    base: PathBuf,
    root: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let base =
            std::env::temp_dir().join(format!("fandhe-sup-bin-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("bundle/rootfs")).unwrap();
        std::fs::write(
            base.join("bundle/config.json"),
            br#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},
"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},
"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
        )
        .unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = base.join("state");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self { base, root }
    }

    fn store(&self) -> std::sync::Arc<dyn StateStore> {
        open_default_store(Some(self.root.clone())).unwrap()
    }

    fn create(&self, id: &str) {
        let req =
            CreateRequest::new(ContainerId::new(id).unwrap(), self.base.join("bundle")).unwrap();
        create(self.store().as_ref(), &OpRecorder::new(), &req).unwrap();
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_fandhe-container-supervisor"));
    c.env_clear().stdin(Stdio::null());
    c
}

/// 子の終了待ちの上限（超過したら kill して有限時間で回収する。REPAIR-5）。
const CHILD_DEADLINE: Duration = Duration::from_secs(60);

/// kill 後の回収確認の猶予。
const REAP_GRACE: Duration = Duration::from_secs(5);

/// 期限つきで子の終了を待つ。超過時は kill して回収し panic する（無期限のハングを作らない）。
fn wait_bounded(child: &mut Child) -> ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if start.elapsed() > CHILD_DEADLINE {
            let killed = child.kill();
            // 回収も有限の猶予で確かめる（割り込み不能な待ちの子で無期限に塞がらない。REPAIR-5）。
            let reap_start = Instant::now();
            let reaped = loop {
                match child.try_wait() {
                    Ok(Some(_)) => break true,
                    Ok(None) if reap_start.elapsed() < REAP_GRACE => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    _ => break false,
                }
            };
            panic!("child did not exit within the deadline (kill: {killed:?}, reaped: {reaped})");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// 読み取りを別スレッドで行い、期限までに EOF にならなければ失敗させる。
fn read_bounded<R: std::io::Read + Send + 'static>(mut r: R) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = r.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    rx
}

fn run_with_pipe(cmd: &mut Command) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out_rx = read_bounded(child.stdout.take().unwrap());
    let err_rx = read_bounded(child.stderr.take().unwrap());
    let status = wait_bounded(&mut child);
    let stdout = out_rx.recv_timeout(CHILD_DEADLINE).unwrap();
    let stderr = err_rx.recv_timeout(CHILD_DEADLINE).unwrap();
    (status.code(), stdout, stderr)
}

fn args(root: &Path, id: &str) -> Vec<String> {
    vec![
        "start".into(),
        "--root".into(),
        root.to_string_lossy().into_owned(),
        id.into(),
    ]
}

/// REPAIR-3・SUP-1: core の本番 launcher が無い間、bin は副作用の前に UNIMPLEMENTED で止まり、状態は Created のまま。
#[test]
fn repair3_bin_fails_closed_until_core_launcher_exists() {
    let env = Env::new("failclosed");
    env.create("c1");
    let id = ContainerId::new("c1").unwrap();
    let before = env.store().get(&GetStateRequest::new(id.clone())).unwrap();
    let (code, stdout, _stderr) = run_with_pipe(bin().args(args(&env.root, "c1")));
    let n = exit_code_for(ErrorCode::Unimplemented);
    assert_eq!(code, Some(i32::from(n.get())));
    assert_eq!(
        String::from_utf8(stdout.clone()).unwrap(),
        format!("FCSUP1 ERR UNIMPLEMENTED {n} production process launcher is not available yet\n")
    );
    assert!(matches!(
        StartReport::decode(&stdout).unwrap(),
        StartReport::Failed {
            code: ErrorCode::Unimplemented,
            ..
        }
    ));
    let after = env.store().get(&GetStateRequest::new(id)).unwrap();
    assert_eq!(after.status().state(), ContainerState::Created);
    assert_eq!(after.revision(), before.revision());
    assert!(after.cgroup().is_none());
}

/// SUP-1: 引数の誤りは INVALID_ARGUMENT を報告し、状態に触れない。
#[test]
fn sup1_bin_reports_invalid_arguments() {
    let (code, stdout, _) = run_with_pipe(bin().args(["start", "--root", "relative", "c1"]));
    let n = exit_code_for(ErrorCode::InvalidArgument);
    assert_eq!(code, Some(i32::from(n.get())));
    assert_eq!(
        String::from_utf8(stdout).unwrap(),
        format!("FCSUP1 ERR INVALID_ARGUMENT {n} --root must be an absolute path\n")
    );
}

/// SUP-1: stdout が pipe でなければ報告できないので、stderr に固定スキーマの JSON を 1 行出して非 0 で終わる。
#[test]
fn sup1_bin_rejects_non_pipe_result_channel() {
    let env = Env::new("nonpipe");
    env.create("c1");
    let file = std::fs::File::create(env.base.join("out.txt")).unwrap();
    let mut child = bin()
        .args(args(&env.root, "c1"))
        .stdout(Stdio::from(file))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let err_rx = read_bounded(child.stderr.take().unwrap());
    let status = wait_bounded(&mut child);
    let stderr = String::from_utf8(err_rx.recv_timeout(CHILD_DEADLINE).unwrap()).unwrap();
    let n = exit_code_for(ErrorCode::InvalidArgument);
    assert_eq!(status.code(), Some(i32::from(n.get())));
    assert_eq!(
        stderr,
        "{\"op\":\"start\",\"code\":\"INVALID_ARGUMENT\",\"message\":\"stdout must be a pipe for the result channel\"}\n"
    );
    assert_eq!(std::fs::read(env.base.join("out.txt")).unwrap(), b"");
    let rec = env
        .store()
        .get(&GetStateRequest::new(ContainerId::new("c1").unwrap()))
        .unwrap();
    assert_eq!(rec.status().state(), ContainerState::Created);
}

/// SUP-1・REPAIR-5: 結果チャネルの読み端が先に閉じていても（CLI が期限切れで終了した場合）、supervisor は
/// SIGPIPE で死なず、書き込み失敗（EPIPE）を握って通常の終了コードで終わる。Rust の実行時は起動時に SIGPIPE を
/// 無視にするため `unsafe` の sigaction は不要で、この性質を回帰検出する。
#[test]
fn sup1_bin_survives_closed_result_channel() {
    use std::os::unix::process::ExitStatusExt;
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let mut child = bin()
        .args(["start", "--root", "relative", "c1"])
        .stdout(Stdio::from(writer))
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = wait_bounded(&mut child);
    assert_eq!(status.signal(), None, "must not be killed by SIGPIPE");
    let n = exit_code_for(ErrorCode::InvalidArgument);
    assert_eq!(status.code(), Some(i32::from(n.get())));
}
