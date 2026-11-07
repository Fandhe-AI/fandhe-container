//! shim v2 の State・Wait・Delete が返す `exited_at` を、本番の部品（`FileStateStore`・supervisor の `monitor`・
//! `CoreLifecycleRuntime`・`TaskService`）を通して範囲で照合する結合試験（CRI-5・OCI-5・SUP-1・TASK-62.7.2・#3682）。
//!
//! 偽なのは終了を返す `LaunchedProcess` だけで、終了検知時刻が `state.json` へ永続化され、shim の 3 つの RPC が同じ値を
//! 返すことを `before <= exited_at <= after` の範囲で確かめる（壁時計のため具体値は固定できない）。Linux 限定・root 不要
//! で既定のテスト集合に入る。要求・応答は prost を plugin-cri の依存に足さないため、ワイヤー形式を最小限で手組みする。

#![cfg(target_os = "linux")]

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, ContainerRuntime, ContainerStatus, CreateStateRequest, ErrorCode, GetStateRequest,
    StateStore, TraitError, UpdateStateRequest,
};
use fandhe_container_cri::adapter::RuntimeAdapter;
use fandhe_container_cri::shim_v2::{TaskApiVersion, TaskService, TtrpcService};
use fandhe_container_plugin_cri::adapter::CoreLifecycleRuntime;
use fandhe_container_supervisor::run::{MonitorConfig, MonitorOutcome, StopToken, monitor};
use fandhe_container_supervisor::state::SupervisedState;

#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;

/// 試験用の一時ディレクトリ。drop で自分の分だけ消す（REPAIR-12・#3479）。
struct TmpDir(PathBuf);
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp_dir() -> TmpDir {
    let d = exclusive_dir::create_in(&std::env::temp_dir(), "fc-cri-exited-at").expect("tmp dir");
    TmpDir(std::fs::canonicalize(&d).expect("canonicalize"))
}

fn make_bundle(dir: &Path) -> PathBuf {
    let bundle = dir.join("bundle");
    std::fs::create_dir(&bundle).expect("bundle");
    std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
    std::fs::write(
        bundle.join("config.json"),
        r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .expect("config");
    bundle
}

/// 最初の `wait` で `Exited(7)` を返す偽のプロセス。
struct ExitingProc;

impl LaunchedProcess for ExitingProc {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(4242).expect("nonzero")
    }
    fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
        Ok(Some(ProcessExit::Exited(7)))
    }
    fn terminate(&self, _: Duration) -> Result<(), TraitError> {
        Ok(())
    }
}

/// `id`（フィールド 1・文字列）だけを持つ要求（State・Wait・Delete 共通。`exec_id` は空で省略）。
fn id_request(id: &str) -> Vec<u8> {
    let mut v = vec![0x0a, u8::try_from(id.len()).expect("short id")];
    v.extend_from_slice(id.as_bytes());
    v
}

/// 応答のトップレベルのフィールド値。
enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

fn read_varint(buf: &[u8], pos: &mut usize) -> u64 {
    let mut value = 0_u64;
    let mut shift = 0;
    loop {
        let b = *buf.get(*pos).expect("truncated varint");
        *pos += 1;
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

fn fields(buf: &[u8]) -> Vec<(u64, Field<'_>)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let tag = read_varint(buf, &mut pos);
        match tag & 7 {
            0 => {
                let v = read_varint(buf, &mut pos);
                out.push((tag >> 3, Field::Varint(v)));
            }
            2 => {
                let len = usize::try_from(read_varint(buf, &mut pos)).expect("len");
                let body = buf.get(pos..pos + len).expect("truncated field");
                pos += len;
                out.push((tag >> 3, Field::Bytes(body)));
            }
            other => panic!("unexpected wire type {other}"),
        }
    }
    out
}

fn varint_field(buf: &[u8], no: u64) -> Option<u64> {
    fields(buf).into_iter().find_map(|(n, f)| match f {
        Field::Varint(v) if n == no => Some(v),
        _ => None,
    })
}

/// `exited_at`（Timestamp）フィールドをナノ秒にして返す。無ければ `None`。
fn timestamp_nanos(buf: &[u8], no: u64) -> Option<i64> {
    let inner = fields(buf).into_iter().find_map(|(n, f)| match f {
        Field::Bytes(b) if n == no => Some(b),
        _ => None,
    })?;
    let seconds = i64::try_from(varint_field(inner, 1).unwrap_or(0)).expect("seconds");
    let nanos = i64::try_from(varint_field(inner, 2).unwrap_or(0)).expect("nanos");
    Some(seconds * 1_000_000_000 + nanos)
}

// StateResponse: status=4・exit_status=9・exited_at=10。WaitResponse: exit_status=1・exited_at=2。
// DeleteResponse: exit_status=2・exited_at=3。TaskStatus: RUNNING=2・STOPPED=3。
const STATE_STATUS: u64 = 4;
const TASK_STATUS_RUNNING: u64 = 2;
const TASK_STATUS_STOPPED: u64 = 3;

fn nanos_now() -> i64 {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock");
    i64::try_from(d.as_nanos()).expect("i64 nanos")
}

/// CRI-5・OCI-5・SUP-1（#3682）: 実行中は未設定、supervisor が終了を記録した後は State・Wait・Delete が
/// 同じ値を範囲内で返し、`exit_status` は 7。
#[test]
fn cri5_3682_exited_at_flows_from_supervisor_to_shim_rpcs() {
    let tmp = tmp_dir();
    let root = StateRoot::resolve(Some(tmp.0.join("state"))).expect("root");
    let store: Arc<dyn StateStore> = Arc::new(FileStateStore::open(root).expect("open"));
    let id = ContainerId::new("c1").expect("id");
    let bundle = make_bundle(&tmp.0);

    let created = store
        .create(
            &CreateStateRequest::new(ContainerStatus::created(id.clone(), None), bundle)
                .expect("req"),
        )
        .expect("create");
    store
        .update(&UpdateStateRequest::new(
            ContainerStatus::running(id.clone(), NonZeroU32::new(4242)),
            created.revision(),
        ))
        .expect("running");

    let runtime: Arc<dyn ContainerRuntime> =
        Arc::new(CoreLifecycleRuntime::new(Arc::clone(&store)));
    let svc = TaskService::new(TaskApiVersion::V3, RuntimeAdapter::new(runtime));
    let state_of = || svc.handle("State", &id_request("c1")).expect("state");

    // 実行中は未設定。
    let running = state_of();
    assert_eq!(
        varint_field(&running, STATE_STATUS),
        Some(TASK_STATUS_RUNNING)
    );
    assert_eq!(timestamp_nanos(&running, 10), None);

    // supervisor の監視が終了を検知して記録する。
    let mut supervised = SupervisedState::attach(Arc::clone(&store), id.clone()).expect("attach");
    let before = nanos_now();
    let outcome = monitor(
        &mut supervised,
        &ExitingProc,
        &MonitorConfig::default(),
        &StopToken::new(),
    )
    .expect("monitor");
    let after = nanos_now();
    assert!(matches!(outcome, MonitorOutcome::Exited { .. }));

    // state.json に永続化され、再読込でも同じ値。
    let recorded = store
        .get(&GetStateRequest::new(id.clone()))
        .expect("get")
        .status()
        .exited_at()
        .expect("recorded")
        .as_unix_nanos();
    assert!(
        before <= recorded && recorded <= after,
        "{before} <= {recorded} <= {after}"
    );

    let stopped = state_of();
    assert_eq!(
        varint_field(&stopped, STATE_STATUS),
        Some(TASK_STATUS_STOPPED)
    );
    assert_eq!(varint_field(&stopped, 9), Some(7));
    assert_eq!(timestamp_nanos(&stopped, 10), Some(recorded));

    let waited = svc.handle("Wait", &id_request("c1")).expect("wait");
    assert_eq!(varint_field(&waited, 1), Some(7));
    assert_eq!(timestamp_nanos(&waited, 2), Some(recorded));

    let deleted = svc.handle("Delete", &id_request("c1")).expect("delete");
    assert_eq!(varint_field(&deleted, 2), Some(7));
    assert_eq!(timestamp_nanos(&deleted, 3), Some(recorded));

    let err = store.get(&GetStateRequest::new(id)).expect_err("deleted");
    assert_eq!(err.code(), ErrorCode::NotFound);
}
