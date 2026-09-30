//! OCI Runtime の `delete`（停止済みコンテナの基本リソース解放。TASK-30.2・CORE-2・OCI-6）。
//!
//! # 役割と呼び出し元
//!
//! 停止済み（または未起動）のコンテナの状態記録を `StateStore` から削除する。将来の plugin 側
//! `ContainerRuntime::delete` 実装・CLI が呼び出し元になる。`ContainerRuntime` の実装は plugin 側に置く
//! （PLUG-1）ため、create / kill と同じく `StateStore` と `OpRecorder` を依存注入で受ける自由関数とした。
//!
//! # 処理順（ERR-2・REPAIR-4）
//!
//! 1. 操作名 `delete` で `OpRecorder` に記録する（全終了経路）
//! 2. `StateStore::get`。未 create または削除済みの ID は `NotFound`（二重 delete の 2 回目も同じ）
//! 3. 状態の確認（下表）。生きている可能性がある状態は fail-closed で拒否する
//! 4. `StateStore::delete` を get で得た revision つきで呼ぶ（楽観的排他）。revision 不一致
//!    （`FailedPrecondition`）なら get を 1 回だけやり直し、`NotFound` なら並行する delete が先に削除
//!    したとみなして `NotFound`、レコードが残っていれば再試行を促す `FailedPrecondition` を返す
//!
//! | state | pid | force=false | force=true |
//! | ----- | --- | ----------- | ---------- |
//! | `Stopped` | - | 削除 | 削除 |
//! | `Created` | なし | 削除 | 削除 |
//! | `Created` | あり | `FailedPrecondition` | `Unimplemented` |
//! | `Running` | あり | `FailedPrecondition` | `Unimplemented` |
//! | `Running` | なし（中断された start の予約） | `FailedPrecondition` | 同左 |
//! | `Creating` | - | `FailedPrecondition` | 同左 |
//!
//! # 安全性（SEC-1・CORE-1）
//!
//! - 記録された pid の生存確認（`kill(pid, 0)`・`/proc`）はしない。PID 再利用の恐れがあるため、判定の
//!   正は `StateStore` の状態とする。kill は状態を更新しないので、kill 直後は supervisor（TASK-157）が
//!   Stopped へ遷移させるまで Running のままで、その間の delete は `FailedPrecondition` になる（意図した挙動）
//! - start との排他は revision 照合だけで足りる。start は launch の前に Created → Running へ予約更新するため、
//!   競合する delete は revision 不一致で失敗する
//!
//! # 到達範囲（REPAIR-3）
//!
//! - 本関数が解放するのは `StateStore` のレコードだけ。状態ファイル（ファイルベース実装）の削除確認と
//!   cgroup の削除は TASK-30.3・TASK-32（CORE-3）、OCI-7 の参照テーブルからの参照解除は TASK-183
//!   （`StateStore` 削除の後に組み込む予定）で、いずれも未実装
//! - `force`（停止してから削除。`ContainerRuntime::delete` の契約）は stop が未実装のため、生きている
//!   可能性のある状態では `Unimplemented` で拒否する
//!
//! エラーメッセージは固定文言のみで、pid・パス・errno を含めない。

use crate::observability::{OpName, OpRecorder};
use crate::traits::{
    ContainerState, DeleteRequest, DeleteResponse, DeleteStateRequest, ErrorCode, GetStateRequest,
    StateRecord, StateStore, TraitError,
};

/// [`OpRecorder`] に記録する操作名（REPAIR-4）。
const DELETE_OP_NAME: &str = "delete";

/// 停止済みまたは未起動のコンテナの状態記録を削除する。
///
/// 未 create・削除済みの ID は [`ErrorCode::NotFound`]（二重 delete は 2 回目が `NotFound`）、
/// 生きている可能性のある状態は [`ErrorCode::FailedPrecondition`]、`force` で生きているコンテナを
/// 削除する要求は [`ErrorCode::Unimplemented`]。成功・失敗の件数と所要時間は `recorder` へ操作名
/// `delete` で記録する（全終了経路。REPAIR-4）。
pub fn delete(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    req: &DeleteRequest,
) -> Result<DeleteResponse, TraitError> {
    let name = OpName::new(DELETE_OP_NAME)?;
    recorder.record_op(&name, || delete_inner(store, req))
}

fn delete_inner(store: &dyn StateStore, req: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
    let record = store.get(&GetStateRequest::new(req.id().clone()))?;
    check_deletable(&record, req.force())?;
    let delete_req = DeleteStateRequest::new(req.id().clone(), record.revision());
    match store.delete(&delete_req) {
        Ok(_) => Ok(DeleteResponse::new()),
        Err(e) if e.code() == ErrorCode::FailedPrecondition => {
            // get の後に状態が進んだか、並行する delete が先に削除した。1 回だけ確認する。
            match store.get(&GetStateRequest::new(req.id().clone())) {
                Err(g) => Err(g),
                Ok(_) => Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "container state changed during delete; retry",
                )),
            }
        }
        Err(e) => Err(e),
    }
}

/// 状態の判定表（モジュール doc）。`ContainerState` の追加をコンパイルエラーで検出するため網羅で書く。
fn check_deletable(record: &StateRecord, force: bool) -> Result<(), TraitError> {
    let status = record.status();
    match (status.state(), status.pid()) {
        (ContainerState::Stopped, _) | (ContainerState::Created, None) => Ok(()),
        (ContainerState::Created | ContainerState::Running, Some(_)) => {
            if force {
                Err(TraitError::new(
                    ErrorCode::Unimplemented,
                    "force delete of a live container is not implemented",
                ))
            } else {
                Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "container is still running",
                ))
            }
        }
        (ContainerState::Running, None) => Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container start was interrupted; recover the start reservation",
        )),
        (ContainerState::Creating, _) => Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container creation is in progress",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{
        ContainerId, ContainerStatus, CreateStateRequest, DeleteStateResponse, ListStateRequest,
        StateList, StateRevision, UpdateStateRequest,
    };
    use std::collections::HashMap;
    use std::num::NonZeroU32;
    use std::sync::Mutex;

    /// テスト専用のインメモリ `StateStore`（delete は revision 照合つき）。
    #[derive(Default)]
    struct MemStateStore {
        records: Mutex<HashMap<ContainerId, StateRecord>>,
        /// true なら delete で常に revision 不一致を返す。
        stale_delete: bool,
        /// stale_delete 時に delete の中でレコードを消す（並行する delete の再現）。
        remove_on_stale: bool,
    }

    impl MemStateStore {
        fn with(status: ContainerStatus) -> Self {
            let s = Self::default();
            s.create(
                &CreateStateRequest::new(status, std::env::temp_dir().join("b")).expect("req"),
            )
            .expect("create");
            s
        }
        fn has(&self, id: &str) -> bool {
            self.records
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&cid(id))
        }
    }

    impl StateStore for MemStateStore {
        fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            let record = StateRecord::new(
                req.status().clone(),
                req.bundle().to_path_buf(),
                StateRevision::from_raw(1),
            )?;
            self.records
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(req.id().clone(), record.clone());
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
        fn delete(&self, req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            if self.stale_delete {
                if self.remove_on_stale {
                    records.remove(req.id());
                }
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "revision mismatch",
                ));
            }
            let cur = records
                .get(req.id())
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))?;
            if cur.revision() != req.expected_revision() {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "revision mismatch",
                ));
            }
            records.remove(req.id());
            Ok(DeleteStateResponse::new())
        }
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).expect("id")
    }

    fn pid(n: u32) -> Option<NonZeroU32> {
        Some(NonZeroU32::new(n).expect("pid"))
    }

    fn run(store: &MemStateStore, id: &str, force: bool) -> Result<DeleteResponse, TraitError> {
        delete(
            store,
            &OpRecorder::new(),
            &DeleteRequest::new(cid(id)).with_force(force),
        )
    }

    /// OCI-6: Stopped は削除され、以後の get は `NotFound`。
    #[test]
    fn oci6_delete_stopped_removes_record() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        assert_eq!(
            run(&store, "c1", false).expect("delete"),
            DeleteResponse::new()
        );
        let err = store
            .get(&GetStateRequest::new(cid("c1")))
            .expect_err("gone");
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    /// OCI-6: pid のない Created（未起動）は削除される。
    #[test]
    fn oci6_delete_created_without_pid_removes_record() {
        let store = MemStateStore::with(ContainerStatus::created(cid("c1"), None));
        run(&store, "c1", false).expect("delete");
        assert!(!store.has("c1"));
    }

    /// CORE-2（受入基準 1）: Running・pid ありは拒否され、状態と revision は変わらない。
    #[test]
    fn core2_delete_rejects_running_with_pid() {
        let status = ContainerStatus::running(cid("c1"), pid(4242));
        let store = MemStateStore::with(status.clone());
        let err = run(&store, "c1", false).expect_err("rejected");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), "container is still running");
        let rec = store.get(&GetStateRequest::new(cid("c1"))).expect("kept");
        assert_eq!(rec.status(), &status);
        assert_eq!(rec.revision(), StateRevision::from_raw(1));
    }

    /// CORE-2: pid のある Created（init 生存）も同じ文言で拒否される。
    #[test]
    fn core2_delete_rejects_created_with_pid() {
        let store = MemStateStore::with(ContainerStatus::created(cid("c1"), pid(11)));
        let err = run(&store, "c1", false).expect_err("rejected");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), "container is still running");
        assert!(store.has("c1"));
    }

    /// CORE-2: 中断された start の予約は force でも回復が先。
    #[test]
    fn core2_delete_rejects_interrupted_start() {
        for force in [false, true] {
            let store = MemStateStore::with(ContainerStatus::running(cid("c1"), None));
            let err = run(&store, "c1", force).expect_err("rejected");
            assert_eq!(err.code(), ErrorCode::FailedPrecondition);
            assert_eq!(
                err.message(),
                "container start was interrupted; recover the start reservation"
            );
            assert!(store.has("c1"));
        }
    }

    /// CORE-2: Creating は拒否される。
    #[test]
    fn core2_delete_rejects_creating() {
        let store = MemStateStore::with(ContainerStatus::creating(cid("c1")));
        let err = run(&store, "c1", false).expect_err("rejected");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), "container creation is in progress");
        assert!(store.has("c1"));
    }

    /// CORE-2・REPAIR-3: 生きているコンテナへの force は stop 未実装のため `Unimplemented`。
    #[test]
    fn core2_delete_force_on_live_is_unimplemented() {
        let store = MemStateStore::with(ContainerStatus::running(cid("c1"), pid(4242)));
        let err = run(&store, "c1", true).expect_err("unimplemented");
        assert_eq!(err.code(), ErrorCode::Unimplemented);
        assert_eq!(
            err.message(),
            "force delete of a live container is not implemented"
        );
        assert!(store.has("c1"));
    }

    /// CORE-2: Stopped への force は通常どおり削除される。
    #[test]
    fn core2_delete_force_on_stopped_deletes() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), None));
        run(&store, "c1", true).expect("delete");
        assert!(!store.has("c1"));
    }

    /// OCI-6（受入基準 2）: 二重 delete は 1 回目 Ok・2 回目 `NotFound`。
    #[test]
    fn oci6_delete_twice_returns_not_found() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        run(&store, "c1", false).expect("first");
        let err = run(&store, "c1", false).expect_err("second");
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    /// OCI-6: 未 create の ID は `NotFound`。
    #[test]
    fn oci6_delete_unknown_id_returns_not_found() {
        let store = MemStateStore::default();
        let err = run(&store, "missing", false).expect_err("not found");
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    /// CORE-2: 並行する delete に負けた側（削除中にレコードが消えた）は `NotFound`。
    #[test]
    fn core2_delete_concurrent_loser_returns_not_found() {
        let mut store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        store.stale_delete = true;
        store.remove_on_stale = true;
        let err = run(&store, "c1", false).expect_err("loser");
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    /// CORE-2: revision が変わってレコードが残る場合は再試行を促す `FailedPrecondition`。
    #[test]
    fn core2_delete_revision_changed_returns_retry_error() {
        let mut store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        store.stale_delete = true;
        let err = run(&store, "c1", false).expect_err("retry");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container state changed during delete; retry"
        );
        assert!(store.has("c1"));
    }

    /// REPAIR-4: 成功と失敗が 1 件ずつ操作名 `delete` で記録される。
    #[test]
    fn repair4_delete_records_success_and_failure() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        let recorder = OpRecorder::new();
        let req = DeleteRequest::new(cid("c1"));
        delete(&store, &recorder, &req).expect("ok");
        delete(&store, &recorder, &req).expect_err("ng");
        let stats = recorder
            .snapshot_op(&OpName::new("delete").expect("name"))
            .expect("recorded");
        assert_eq!((stats.success(), stats.failure()), (1, 1));
    }
}
