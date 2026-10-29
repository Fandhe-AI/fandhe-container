//! pasta の改ざんの疑いが、実バイナリの start を通して `<状態ルート>/@audit.log` へ 1 件だけ届くことの結合試験
//! (SEC-4・NET-9・PLUG-11・#3330・REPAIR-12)。
//!
//! 起動オプション文書(`pasta` の記録つき)を実ストアの状態記録と組で用意し、supervisor の bin に `start` を渡す。
//! 手順 2c の再検証が拒否し(cgroup にも launch にも触れない)、`options_with_verified_pasta` → 改ざんスロット →
//! `record_pasta_tamper` → `@audit.log` の配送を通す。権限・Landlock・cgroup の委譲に依らず到達する手順だけを使うので、
//! root 不要で既定のテスト集合で動く。`FileStateStore` は Linux 限定のため全体を Linux に限る。

#![cfg(target_os = "linux")]

#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{
    Annotations, ContainerId, ContainerState, ContainerStatus, CreateStateRequest, GetStateRequest,
};
use fandhe_container_supervisor::container_options::document::ContainerOptionsDocument;
use fandhe_container_supervisor::container_options::store::{GENERATION_ANNOTATION, write_new};
use fandhe_container_supervisor::state::open_default_store;

const CHILD_DEADLINE: Duration = Duration::from_secs(60);
const GENERATION: &str = "g-3330";
const CONTAINER: &str = "tamper1";

struct Env {
    base: PathBuf,
    root: PathBuf,
    _scratch: scratch_root::ScratchDir,
}

impl Env {
    fn new() -> Self {
        let scratch =
            scratch_root::ScratchDir::new("fandhe-sup-tamper", std::time::Duration::from_secs(10));
        let base = scratch.path().join(format!("t-{}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&base)
            .unwrap();
        let root = base.join("state");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        Self {
            base,
            root,
            _scratch: scratch,
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// 識別が合わない(`dev` が 0)記録。`path` は実在する実行ファイルの正規パス。
fn record_body(path: &Path) -> String {
    format!(
        "20260120 0 1 1 1 0 1 0 0 755\n{}",
        path.to_str().expect("utf-8 path")
    )
}

/// 状態記録(世代つき)と、`pasta` の記録つきの起動オプション文書を作る。
fn prepare(env: &Env, id: &ContainerId, pasta_path: &Path) {
    let store = open_default_store(Some(env.root.clone())).unwrap();
    let ann =
        Annotations::new([(GENERATION_ANNOTATION.to_owned(), GENERATION.to_owned())]).unwrap();
    let req = CreateStateRequest::new(
        ContainerStatus::created(id.clone(), None),
        env.base.join("bundle"),
    )
    .unwrap()
    .with_annotations(ann);
    store.create(&req).unwrap();
    let doc = ContainerOptionsDocument::new(vec![], vec![], None, None, vec![])
        .unwrap()
        .with_network(Some("tamper-net".into()), vec![], vec![])
        .unwrap()
        .with_pasta(Some(record_body(pasta_path)))
        .unwrap()
        .with_generation(GENERATION.into())
        .unwrap();
    write_new(&env.root, id, &doc).unwrap();
}

/// bin の `start` を期限つきで実行する(終了コード・stdout)。
fn run_start(env: &Env, id: &str) -> (Option<i32>, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_fandhe-container-supervisor"));
    let mut child = c
        .env_clear()
        .args(["start", "--root"])
        .arg(&env.root)
        .arg(id)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::Read::read_to_string(&mut { out }, &mut s);
        let _ = tx.send(s);
    });
    // 失敗時の診断のため stderr(構造化ログ)も集める。
    let (etx, erx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::Read::read_to_string(&mut err, &mut s);
        let _ = etx.send(s);
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > CHILD_DEADLINE {
            crate::reap::reap_or_report(&mut child, crate::reap::REAP_WITHIN);
            panic!("supervisor did not exit within the deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = rx.recv_timeout(CHILD_DEADLINE).unwrap();
    let stderr = erx.recv_timeout(CHILD_DEADLINE).unwrap_or_default();
    (status.code(), stdout, stderr)
}

fn audit_lines(env: &Env) -> Vec<String> {
    std::fs::read_to_string(env.root.join("@audit.log"))
        .expect("read @audit.log")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn assert_rejected_once(env: &Env, id: &ContainerId, reason: &str) {
    let (code, stdout, stderr) = run_start(env, id.as_str());
    assert_ne!(code, Some(0), "start must be refused: {stdout}");
    assert_eq!(stdout.lines().count(), 1, "one report line: {stdout}");
    // 起動は拒否され、状態は Created のまま(cgroup にも launch にも進まない)。
    let store = open_default_store(Some(env.root.clone())).unwrap();
    let st = store.get(&GetStateRequest::new(id.clone())).unwrap();
    assert_eq!(st.status().state(), ContainerState::Created);
    let lines = audit_lines(env);
    let pasta: Vec<&String> = lines
        .iter()
        .filter(|l| l.contains(r#""layer":"pasta_verify""#))
        .collect();
    assert_eq!(
        pasta.len(),
        1,
        "exactly one pasta_verify record: {lines:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
    let line = pasta[0];
    assert!(line.contains(&format!(r#""reason":"{reason}""#)), "{line}");
    assert!(
        line.contains(&format!(r#""container_id":"{CONTAINER}""#)),
        "{line}"
    );
}

/// SEC-4・NET-9・PLUG-11・#3330: 記録と識別が合わないバイナリ(RecordChanged)は、start の拒否と同時に
/// コンテナ ID つきの `pasta_verify` を 1 件配送する。
#[test]
fn sec4_start_delivers_record_changed_to_audit_log() {
    let env = Env::new();
    let id = ContainerId::new(CONTAINER).unwrap();
    let sh = std::fs::canonicalize("/bin/sh").expect("canonical /bin/sh");
    prepare(&env, &id, &sh);
    assert_rejected_once(&env, &id, "pasta_record_changed");
}

/// SEC-4・NET-9・PLUG-11・#3330: 他者が書き込める実体(PermissionDenied)も同様に 1 件配送する。
#[test]
fn sec4_start_delivers_permission_denied_to_audit_log() {
    let env = Env::new();
    let id = ContainerId::new(CONTAINER).unwrap();
    let fake = env.base.join("pasta");
    std::fs::copy("/bin/sh", &fake).expect("copy a binary");
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o777)).unwrap();
    prepare(&env, &id, &fake);
    assert_rejected_once(&env, &id, "pasta_permission_denied");
}

/// SEC-4・REPAIR-4: 記録先(`@audit.log`)がディレクトリで開けないときも start は拒否され(fail-closed)、
/// 状態は Created のまま報告は 1 行になる(記録先の失敗で起動を通さない)。
#[test]
fn sec4_start_with_unwritable_audit_log_is_still_refused() {
    let env = Env::new();
    let id = ContainerId::new(CONTAINER).unwrap();
    let sh = std::fs::canonicalize("/bin/sh").expect("canonical /bin/sh");
    prepare(&env, &id, &sh);
    std::fs::create_dir(env.root.join("@audit.log")).unwrap();
    let (code, stdout, _stderr) = run_start(&env, id.as_str());
    assert_ne!(code, Some(0), "{stdout}");
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    let store = open_default_store(Some(env.root.clone())).unwrap();
    let st = store.get(&GetStateRequest::new(id)).unwrap();
    assert_eq!(st.status().state(), ContainerState::Created);
}
