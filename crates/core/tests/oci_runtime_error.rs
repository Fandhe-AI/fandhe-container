//! OCI Runtime 4 操作（create / start / kill / delete）の失敗応答の結合試験（ERR-2・TASK-96.3）。
//!
//! 公開 API だけを crate の外から呼び、各操作の失敗が操作種別 `op`・機械可読な `code`・非ゼロの終了コード・
//! stderr 向け 1 行 JSON（`write_json_line`）として得られることを具体値で機械照合する（REPAIR-12）。
//! 各操作の契約の詳細は `oci_create.rs`・`oci_start.rs`・`oci_kill.rs`・`oci_delete.rs` が扱う。
//!
//! 実際の stderr への書き出しとプロセス終了は CLI 側（TASK-79・TASK-95）で未結線（REPAIR-3）。本ファイルは
//! 任意の `Write` へ書いた 1 行と `exit_code()` で代替照合する。実プロセス・root は不要で 3 OS で動く。

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::observability::{OpName, OpRecorder};
use fandhe_container_core::oci_runtime::{
    CgroupRemoval, ContainerCgroupRemover, KillTimeout, LaunchSpec, LaunchedProcess, LifecycleOp,
    OciRuntimeError, ProcessLauncher, ProcessSignaler, StartTimeouts, create, delete, kill, start,
};
use fandhe_container_core::traits::{
    CgroupScope, ContainerId, ContainerStatus, CreateRequest, CreateStateRequest, DeleteRequest,
    DeleteResponse, DeleteStateRequest, DeleteStateResponse, ErrorCode, GetStateRequest,
    KillRequest, ListStateRequest, Signal, StartRequest, StateList, StateRecord, StateRevision,
    StateStore, TraitError, UpdateStateRequest,
};
use serde_json::{Value, json};

/// テスト専用のインメモリ `StateStore`（失敗経路の検証用。update / list / delete は使われない）。
#[derive(Default)]
struct MemStateStore {
    records: Mutex<HashMap<ContainerId, StateRecord>>,
    next: Mutex<u64>,
}

impl StateStore for MemStateStore {
    fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        if records.contains_key(req.id()) {
            return Err(TraitError::new(ErrorCode::AlreadyExists, "exists"));
        }
        let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
        *next += 1;
        let record = StateRecord::new(
            req.status().clone(),
            req.bundle().to_path_buf(),
            StateRevision::from_raw(*next),
        )?;
        records.insert(req.id().clone(), record.clone());
        Ok(record)
    }
    fn update(&self, _req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
    fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(req.id())
            .cloned()
            .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))
    }
    fn list(&self, _req: &ListStateRequest) -> Result<StateList, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
    fn delete(&self, _req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
}

impl MemStateStore {
    fn put(&self, status: ContainerStatus) {
        self.create(
            &CreateStateRequest::new(status, std::env::temp_dir().join("bundle")).expect("req"),
        )
        .expect("put");
    }
    fn len(&self) -> usize {
        self.records.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// 呼び出し回数を数え、`reply` が `Some` ならそのエラーを返す模擬 signaler。
struct FakeSignaler {
    calls: AtomicUsize,
    reply: Option<TraitError>,
}

impl FakeSignaler {
    fn new(reply: Option<TraitError>) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            reply,
        })
    }
}

impl ProcessSignaler for FakeSignaler {
    fn signal(
        &self,
        _id: &ContainerId,
        _pid: NonZeroU32,
        _signal: Signal,
        _deadline: Instant,
    ) -> Result<(), TraitError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.reply {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
}

/// 呼ばれたら回数を数えて失敗する模擬 launcher（失敗経路では呼ばれないことの確認用）。
struct CountingLauncher(AtomicUsize);

impl ProcessLauncher for CountingLauncher {
    fn launch(
        &self,
        _spec: &LaunchSpec,
        _timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(TraitError::new(ErrorCode::Internal, "must not launch"))
    }
    fn confirm_no_process(&self, _id: &ContainerId, _timeout: Duration) -> Result<(), TraitError> {
        Ok(())
    }
}

/// cgroup を持たない `ContainerCgroupRemover`（スコープ未記録のレコードでは呼ばれない）。
struct NoCgroup;

impl ContainerCgroupRemover for NoCgroup {
    fn scope(&self) -> Result<CgroupScope, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, "no cgroup"))
    }
    fn remove(&self, _id: &ContainerId, _i: StateRevision) -> Result<CgroupRemoval, TraitError> {
        Ok(CgroupRemoval::NotPresent)
    }
}

/// テストごとに一意な bundle（`rootfs/` と任意の `config.json`。終了時に削除）。
struct Bundle(PathBuf);

impl Bundle {
    fn new(name: &str, with_config: bool) -> Self {
        let dir =
            std::env::temp_dir().join(format!("fandhe-core-err2-it-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rootfs")).expect("bundle dir");
        if with_config {
            let config = json!({
                "ociVersion": "1.2.0",
                "root": {"path": "rootfs"},
                "process": {"user": {"uid": 0, "gid": 0}, "args": ["/bin/true"], "cwd": "/"}
            });
            std::fs::write(
                dir.join("config.json"),
                serde_json::to_vec(&config).expect("json"),
            )
            .expect("config");
        }
        Self(dir)
    }
    fn req(&self, id: &str) -> CreateRequest {
        CreateRequest::new(cid(id), self.0.clone()).expect("absolute bundle")
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).expect("id")
}

fn pid() -> NonZeroU32 {
    NonZeroU32::new(4242).expect("pid")
}

fn do_kill(
    store: &dyn StateStore,
    rec: &OpRecorder,
    sig: &Arc<dyn ProcessSignaler>,
    id: &str,
) -> Result<ContainerStatus, OciRuntimeError> {
    kill(
        store,
        rec,
        sig,
        &KillRequest::new(cid(id), Signal::SIGTERM),
        &KillTimeout::default(),
    )
}

fn do_delete(
    store: &dyn StateStore,
    rec: &OpRecorder,
    id: &str,
    force: bool,
) -> Result<DeleteResponse, OciRuntimeError> {
    delete(
        store,
        rec,
        &NoCgroup,
        &DeleteRequest::new(cid(id)).with_force(force),
    )
}

fn stats(rec: &OpRecorder, name: &str) -> (u64, u64) {
    let s = rec
        .snapshot_op(&OpName::new(name).expect("name"))
        .expect("recorded");
    (s.success(), s.failure())
}

/// 失敗 1 件を op / code / 終了コード / stderr 向け 1 行 JSON の全項目で照合し、行を返す。
fn assert_structured(
    err: &OciRuntimeError,
    op: LifecycleOp,
    op_str: &str,
    code: ErrorCode,
    code_str: &str,
    exit: u8,
) -> String {
    assert_eq!(err.op(), op);
    assert_eq!(err.code(), code);
    assert_eq!(err.exit_code().get(), exit);
    let mut out = Vec::new();
    err.write_json_line(&mut out).expect("write");
    let line = String::from_utf8(out).expect("utf8");
    assert_eq!(line.matches('\n').count(), 1);
    assert!(line.ends_with('\n'));
    let v: Value = serde_json::from_str(&line).expect("json");
    let obj = v.as_object().expect("object");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["code", "message", "op"]);
    assert_eq!(v["op"], op_str);
    assert_eq!(v["code"], code_str);
    assert_eq!(v["message"], err.message());
    line
}

/// ERR-2・TASK-96.3: create の重複 ID は create / ALREADY_EXISTS / 4。
#[test]
fn err2_create_duplicate_id() {
    let b = Bundle::new("dup", true);
    let store = MemStateStore::default();
    let rec = OpRecorder::new();
    create(&store, &rec, &b.req("a")).expect("first create");
    let err = create(&store, &rec, &b.req("a")).expect_err("dup");
    assert_structured(
        &err,
        LifecycleOp::Create,
        "create",
        ErrorCode::AlreadyExists,
        "ALREADY_EXISTS",
        4,
    );
    assert_eq!(stats(&rec, "create"), (1, 1));
}

/// ERR-2・TASK-96.3: config.json の無い bundle は create / NOT_FOUND / 3 で、ストアに残さない。
#[test]
fn err2_create_missing_config() {
    let b = Bundle::new("noconf", false);
    let store = MemStateStore::default();
    let err = create(&store, &OpRecorder::new(), &b.req("a")).expect_err("no config");
    assert_structured(
        &err,
        LifecycleOp::Create,
        "create",
        ErrorCode::NotFound,
        "NOT_FOUND",
        3,
    );
    assert_eq!(store.len(), 0);
}

/// ERR-2・TASK-96.3: 未 create ID の start は start / NOT_FOUND / 3 で、launcher は呼ばれない。
#[test]
fn err2_start_unknown_id() {
    let store = MemStateStore::default();
    let launcher = Arc::new(CountingLauncher(AtomicUsize::new(0)));
    let dynl: Arc<dyn ProcessLauncher> = launcher.clone();
    let err = start(
        &store,
        &OpRecorder::new(),
        &dynl,
        &StartRequest::new(cid("x")),
        &StartTimeouts::default(),
    )
    .expect_err("missing");
    assert_structured(
        &err,
        LifecycleOp::Start,
        "start",
        ErrorCode::NotFound,
        "NOT_FOUND",
        3,
    );
    assert_eq!(launcher.0.load(Ordering::SeqCst), 0);
}

/// ERR-2・TASK-96.3: 未 create ID の kill は kill / NOT_FOUND / 3 で、signaler は呼ばれない。
#[test]
fn err2_kill_unknown_id() {
    let store = MemStateStore::default();
    let sig = FakeSignaler::new(None);
    let dynsig: Arc<dyn ProcessSignaler> = sig.clone();
    let err = do_kill(&store, &OpRecorder::new(), &dynsig, "x").expect_err("missing");
    assert_structured(
        &err,
        LifecycleOp::Kill,
        "kill",
        ErrorCode::NotFound,
        "NOT_FOUND",
        3,
    );
    assert_eq!(sig.calls.load(Ordering::SeqCst), 0);
}

/// ERR-2・TASK-96.3: 非実行状態の kill は kill / FAILED_PRECONDITION / 5 で、signaler は呼ばれない。
#[test]
fn err2_kill_not_running() {
    let store = MemStateStore::default();
    store.put(ContainerStatus::stopped(cid("s"), Some(0)));
    let sig = FakeSignaler::new(None);
    let dynsig: Arc<dyn ProcessSignaler> = sig.clone();
    let err = do_kill(&store, &OpRecorder::new(), &dynsig, "s").expect_err("stopped");
    assert_structured(
        &err,
        LifecycleOp::Kill,
        "kill",
        ErrorCode::FailedPrecondition,
        "FAILED_PRECONDITION",
        5,
    );
    assert_eq!(sig.calls.load(Ordering::SeqCst), 0);
}

/// ERR-2・TASK-96.3: signaler の失敗 code（Unavailable）は kill / UNAVAILABLE / 9 として透過する。
#[test]
fn err2_kill_signaler_failure_code_is_preserved() {
    let store = MemStateStore::default();
    store.put(ContainerStatus::running(cid("r"), Some(pid())));
    let sig: Arc<dyn ProcessSignaler> = FakeSignaler::new(Some(TraitError::new(
        ErrorCode::Unavailable,
        "signaler down",
    )));
    let err = do_kill(&store, &OpRecorder::new(), &sig, "r").expect_err("unavailable");
    let line = assert_structured(
        &err,
        LifecycleOp::Kill,
        "kill",
        ErrorCode::Unavailable,
        "UNAVAILABLE",
        9,
    );
    assert!(line.contains("signaler down"));
}

/// ERR-2・TASK-96.3: 未 create ID の delete は delete / NOT_FOUND / 3。
#[test]
fn err2_delete_unknown_id() {
    let store = MemStateStore::default();
    let err = do_delete(&store, &OpRecorder::new(), "x", false).expect_err("missing");
    assert_structured(
        &err,
        LifecycleOp::Delete,
        "delete",
        ErrorCode::NotFound,
        "NOT_FOUND",
        3,
    );
}

/// ERR-2・TASK-96.3: 実行中の delete は FAILED_PRECONDITION / 5、force は UNIMPLEMENTED / 8。
/// どちらもレコードは残る。
#[test]
fn err2_delete_running_and_force() {
    let store = MemStateStore::default();
    store.put(ContainerStatus::running(cid("r"), Some(pid())));
    let err = do_delete(&store, &OpRecorder::new(), "r", false).expect_err("running");
    assert_structured(
        &err,
        LifecycleOp::Delete,
        "delete",
        ErrorCode::FailedPrecondition,
        "FAILED_PRECONDITION",
        5,
    );
    assert_eq!(store.len(), 1);
    let err = do_delete(&store, &OpRecorder::new(), "r", true).expect_err("force");
    assert_structured(
        &err,
        LifecycleOp::Delete,
        "delete",
        ErrorCode::Unimplemented,
        "UNIMPLEMENTED",
        8,
    );
    assert_eq!(store.len(), 1);
}

/// ERR-2・REPAIR-4・TASK-96.3: 1 つのストア・recorder で 4 操作を各 1 回失敗させ、操作別に計数され、
/// 終了コードがすべて非ゼロで、各 1 行 JSON の op が操作名と一致する。
#[test]
fn err2_four_operations_fail_and_are_counted_per_operation() {
    let b = Bundle::new("four", true);
    let store = MemStateStore::default();
    let rec = OpRecorder::new();
    let launcher: Arc<dyn ProcessLauncher> = Arc::new(CountingLauncher(AtomicUsize::new(0)));
    let sig: Arc<dyn ProcessSignaler> = FakeSignaler::new(None);

    create(&store, &rec, &b.req("a")).expect("create");
    let errs = [
        create(&store, &rec, &b.req("a"))
            .map(|_| ())
            .expect_err("create"),
        start(
            &store,
            &rec,
            &launcher,
            &StartRequest::new(cid("nope")),
            &StartTimeouts::default(),
        )
        .map(|_| ())
        .expect_err("start"),
        do_kill(&store, &rec, &sig, "nope")
            .map(|_| ())
            .expect_err("kill"),
        do_delete(&store, &rec, "nope", false)
            .map(|_| ())
            .expect_err("delete"),
    ];
    for (err, op) in errs.iter().zip(["create", "start", "kill", "delete"]) {
        assert_ne!(err.exit_code().get(), 0);
        let mut out = Vec::new();
        err.write_json_line(&mut out).expect("write");
        let v: Value = serde_json::from_slice(&out).expect("json");
        assert_eq!(v["op"], op);
    }
    assert_eq!(stats(&rec, "create"), (1, 1));
    assert_eq!(stats(&rec, "start"), (0, 1));
    assert_eq!(stats(&rec, "kill"), (0, 1));
    assert_eq!(stats(&rec, "delete"), (0, 1));
}

/// 常に同じメッセージの Internal で失敗する `StateStore`（下位の untrusted message の模擬）。
struct BadStore(String);

impl StateStore for BadStore {
    fn create(&self, _r: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, self.0.clone()))
    }
    fn update(&self, _r: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, self.0.clone()))
    }
    fn get(&self, _r: &GetStateRequest) -> Result<StateRecord, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, self.0.clone()))
    }
    fn list(&self, _r: &ListStateRequest) -> Result<StateList, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, self.0.clone()))
    }
    fn delete(&self, _r: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, self.0.clone()))
    }
}

/// ERR-2・TASK-96.3: 下位（signaler・StateStore）由来の改行・制御文字・過大な message も、kill / delete の
/// 失敗行では 1 行・4096 バイト以下・制御文字なしにサニタイズされる。
#[test]
fn err2_untrusted_message_is_sanitized_for_kill_and_delete() {
    let nasty = format!("line1\nline2\u{1b}[31m\u{202e}{}", "x".repeat(10_000));
    let store = MemStateStore::default();
    store.put(ContainerStatus::running(cid("r"), Some(pid())));
    let sig: Arc<dyn ProcessSignaler> =
        FakeSignaler::new(Some(TraitError::new(ErrorCode::Unavailable, nasty.clone())));
    let kill_err = do_kill(&store, &OpRecorder::new(), &sig, "r").expect_err("kill");
    let delete_err =
        do_delete(&BadStore(nasty), &OpRecorder::new(), "r", false).expect_err("delete");

    for err in [kill_err, delete_err] {
        assert!(err.message().len() <= 4096);
        assert!(!err.message().chars().any(char::is_control));
        assert!(!err.message().contains('\u{202e}'));
        let mut out = Vec::new();
        err.write_json_line(&mut out).expect("write");
        let line = String::from_utf8(out).expect("utf8");
        assert_eq!(line.matches('\n').count(), 1);
        assert!(line.ends_with('\n'));
    }
}
