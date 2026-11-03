//! supervisor の bin（`fandhe-container-supervisor`）の外形の結合試験（TASK-157 追補・#1717・#1819・SUP-1・REPAIR-2・
//! REPAIR-3・CLI-1）。
//!
//! 実バイナリを CLI と同じ契約（argv・stdout の pipe の結果チャネル）で起動し、報告 1 行・終了コード・状態を具体値で
//! 照合する。root 不要で既定のテスト集合で動く。起動は core の本番 launcher（`ProductionLauncher`）まで結線済みで、
//! 到達する分岐は実行環境（実効 uid・Landlock ABI・cgroup の委譲・user namespace）で変わる。そのため
//! `sup1_bin_reaches_production_launcher_and_fails_closed` は、環境から試験側で決められる分岐（rootful・Landlock ABI 6
//! 未満）は報告のコードと文言まで完全一致で照合し、それ以外の分岐は fail-closed の不変条件（報告が 1 行・終了コードが
//! 報告と整合・子と pid つきの Running を残さない）を照合する。実プロセスでの起動と `monitor` の通しは実機前提の
//! `supervisor_bin_real`（`--ignored`・人間担当）が照合する。`FileStateStore` は Linux 限定のため全体を Linux に限る。

#![cfg(target_os = "linux")]

// 一時領域の親を tmpfiles の flock 走査から守る共有部品（#3026・CORE-5・REPAIR-12）。
#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

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
    /// tmpfiles の flock 走査から守る親（#3026）。`base` はその子。最後のフィールドで、`Drop` の後に親が消える。
    _scratch: scratch_root::ScratchDir,
}

impl Env {
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::DirBuilderExt as _;
        use std::os::unix::fs::PermissionsExt;
        // 共有 /tmp 上の推測可能なパスの削除・再利用は、競合で置かれた symlink を root が辿りうる。
        // 一意名を 0700 で排他作成し（既存は採用しない）、配下も 1 階層ずつ `create_dir` で作る（#2324・SEC-2）。
        let scratch =
            scratch_root::ScratchDir::new("fandhe-sup-bin", std::time::Duration::from_secs(10));
        let tmp = scratch.path().to_path_buf();
        let mut attempt = 0u32;
        let base = loop {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let candidate = tmp.join(format!("{tag}-{nanos}-{attempt}"));
            match std::fs::DirBuilder::new().mode(0o700).create(&candidate) {
                Ok(()) => break candidate,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < 16 => {
                    attempt += 1;
                }
                Err(e) => panic!("exclusively create {}: {e}", candidate.display()),
            }
        };
        std::fs::create_dir(base.join("bundle")).unwrap();
        std::fs::create_dir(base.join("bundle/rootfs")).unwrap();
        std::fs::write(
            base.join("bundle/config.json"),
            br#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},
"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},
"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
        )
        .unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = base.join("state");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            base,
            root,
            _scratch: scratch,
        }
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

/// 手順 4（副作用なしの事前確認）で止まるはずの環境なら、その報告のコードと固定文言。試験側で環境から決められる分岐
/// だけを返す（rootful は実効 uid、Landlock は `detect_landlock_abi`）。判定の順は bin と同じ（権限モデル → Landlock）。
fn expected_check_failure() -> Option<(ErrorCode, &'static str)> {
    use std::os::unix::fs::MetadataExt as _;
    let euid_is_root = std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0);
    if euid_is_root {
        return Some((
            ErrorCode::Unimplemented,
            "rootful start is not supported by the production launcher",
        ));
    }
    fandhe_container_core::landlock::detect_landlock_abi()
        .err()
        .map(|e| {
            (
                e.code,
                "Landlock ABI 6 or newer is required to start a container",
            )
        })
}

/// SUP-1・CORE-1・CORE-2・CORE-5・SEC-5・REPAIR-3・#1819: bin は本番 launcher まで到達し、旧「未提供」の報告で止まらない。
/// 環境から決められる事前確認の失敗は固定のコードと文言で照合し（副作用なし: 状態は Created・revision 不変・cgroup なし）、
/// それ以外は fail-closed の不変条件を照合する（報告 1 行・終了コードの整合・pid つきの Running を残さない）。
#[test]
fn sup1_bin_reaches_production_launcher_and_fails_closed() {
    let env = Env::new("production");
    env.create("c1");
    let id = ContainerId::new("c1").unwrap();
    let before = env.store().get(&GetStateRequest::new(id.clone())).unwrap();
    let (code, stdout, _stderr) = run_with_pipe(bin().args(args(&env.root, "c1")));
    // 報告は改行で終わる 1 行だけ。
    assert_eq!(stdout.iter().filter(|&&b| b == b'\n').count(), 1);
    let report = StartReport::decode(&stdout).unwrap();
    let after = env.store().get(&GetStateRequest::new(id)).unwrap();
    match report {
        StartReport::Failed {
            code: c,
            exit_code,
            message,
        } => {
            // 旧「本番 launcher は未提供」の報告ではない。
            assert_ne!(
                message.as_str(),
                "production process launcher is not available yet"
            );
            // 終了コードは報告のコード、または後始末を確かめられなかった INTERNAL。
            let internal = exit_code_for(ErrorCode::Internal);
            assert!(
                code == Some(i32::from(exit_code.get())) || code == Some(i32::from(internal.get())),
                "exit code {code:?} for report {c:?}"
            );
            if let Some((expected_code, expected_message)) = expected_check_failure() {
                assert_eq!(c, expected_code);
                assert_eq!(message.as_str(), expected_message);
                assert_eq!(code, Some(i32::from(exit_code_for(expected_code).get())));
                assert_eq!(after.status().state(), ContainerState::Created);
                assert_eq!(after.revision(), before.revision());
                assert!(after.cgroup().is_none());
            }
            // pid つきの Running を残さない（子を残さない。予約だけが残る場合の pid は無い）。
            assert!(after.status().pid().is_none());
        }
        StartReport::Started { pid } => {
            // 全前提が揃った環境で起動できた場合: bin の終了後は Stopped で、子は残っていない。
            assert_eq!(after.status().state(), ContainerState::Stopped);
            assert!(!Path::new(&format!("/proc/{pid}")).exists());
        }
        other => panic!("unexpected report: {other:?}"),
    }
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

/// SUP-1・REPAIR-4・#2067: CLI と同じく stderr を null にして起動しても、supervisor の構造化ログは
/// `<root>/@supervisor-logs/<id>.log`（0600）に残る。レコードの無い ID ではログを作らない。
#[test]
fn sup1_repair4_bin_saves_structured_log_under_state_root() {
    use std::os::unix::fs::PermissionsExt as _;
    let env = Env::new("suplog");
    env.create("c1");
    let (code, stdout, _) = run_with_pipe(bin().args(args(&env.root, "c1")).stderr(Stdio::null()));
    assert!(code.is_some());
    assert_eq!(stdout.iter().filter(|&&b| b == b'\n').count(), 1);
    let dir = env.root.join("@supervisor-logs");
    let log = dir.join("c1.log");
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&log).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let body = std::fs::read_to_string(&log).unwrap();
    assert!(
        body.lines().any(|l| l.starts_with(
            "stderr {\"component\":\"supervisor\",\"event\":\"start_metrics\",\"ops\":["
        )),
        "log body: {body}"
    );

    // レコードの無い ID（打ち間違い）ではログを作らない。
    let _ = run_with_pipe(bin().args(args(&env.root, "nope")).stderr(Stdio::null()));
    assert!(!dir.join("nope.log").exists());
}
