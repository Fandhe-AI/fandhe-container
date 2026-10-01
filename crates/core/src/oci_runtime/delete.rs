//! OCI Runtime の `delete`（停止済みコンテナの基本リソース解放。TASK-30.2・CORE-2・OCI-6）。
//!
//! # 役割と呼び出し元
//!
//! 停止済み（または未起動）のコンテナの cgroup（CORE-3）と状態記録を削除する（TASK-30.2・TASK-30.3）。
//! 状態記録の削除は `StateStore`（ファイルベース実装では `<id>/state.json` と空の `<id>/`。OCI-5）が担い、
//! cgroup の削除は依存注入された [`ContainerCgroupRemover`] が担う。将来の plugin 側
//! `ContainerRuntime::delete` 実装・CLI が呼び出し元になる。`ContainerRuntime` の実装は plugin 側に置く
//! （PLUG-1）ため、create / kill と同じく `StateStore`・`OpRecorder`・cgroup 削除を依存注入で受ける自由関数とした。
//! cgroup 削除の本番実装は Linux 限定の `cgroups::DelegatedCgroup`（`ContainerCgroupRemover` を実装）で、
//! 本モジュールは Linux 固有の型に依存しない（3 OS でビルドする。CLI-1）。
//!
//! # 処理順（ERR-2・REPAIR-4）
//!
//! 1. 操作名 `delete` で `OpRecorder` に記録する（全終了経路）
//! 2. `StateStore::get`。未 create または削除済みの ID は `NotFound`（二重 delete の 2 回目も同じ）
//! 3. 状態の確認（下表）。生きている可能性がある状態は fail-closed で拒否する（拒否した状態では cgroup に触れない）
//! 4. cgroup の削除（TASK-30.3・OCI-6）。レコードに cgroup スコープ（[`StateRecord::cgroup_scope`]）が
//!    記録されていなければ cgroup を作っていないので触れずに手順 5 へ進む。記録されていれば、
//!    `ContainerCgroupRemover::scope` が記録と一致することを確かめ（不一致は `FailedPrecondition` で、
//!    cgroup にもレコードにも触れない）、revision を再確認してから `ContainerCgroupRemover::remove` を呼ぶ。
//!    `Removed` / `NotPresent` は成功として次へ進み、エラーはそのまま返してレコードを削除しない
//! 5. `StateStore::delete` を get で得た revision つきで呼ぶ（楽観的排他）。revision 不一致
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
//! # cgroup を先に消す理由（OCI-6・CORE-3）
//!
//! cgroup を先に消すので、削除に失敗したとき（孤児プロセスが残って空でない場合は `FailedPrecondition`）も
//! レコードが残り、再実行できる（fail-closed）。逆順にすると、cgroup の削除に失敗した時点で再試行の
//! 手掛かりが消え、cgroup がリークする。cgroup を消した後で手順 5 が revision 不一致になっても、再実行時の
//! remover は `NotPresent` を返すため冪等である。
//!
//! # 委譲スコープの照合（OCI-6・CORE-3）
//!
//! remover は自分の委譲スコープの下で `fc-<id>` を探すため、create と別の委譲スコープから呼ばれると
//! 実在する cgroup を見つけられず `NotPresent` を返す。照合なしにそれを成功扱いにすると、cgroup を
//! 残したまま再試行の手掛かりである状態記録だけを消してしまう。そこで作成時のスコープを状態に記録し
//! （`CreateStateRequest::with_cgroup_scope`）、削除側のスコープが一致したときだけ `NotPresent` を
//! 「cgroup 無し」の確認として扱う。一致しなければ正しいスコープでの再実行を促す
//! `FailedPrecondition` を返し、状態記録は残す（fail-closed）。
//!
//! # 安全性（SEC-1・CORE-1）
//!
//! - start との競合: 削除できる状態は `Stopped` と pid のない `Created` だけである。並行する start が予約した
//!   あとで子 cgroup にプロセスが参加済みなら cgroup は空でないため削除できず（`FailedPrecondition`）、
//!   空の段階で消された場合は子の参加（fd 経由の `cgroup.procs` 書き込み）が失敗して start は fail-closed で
//!   終わる。生きているプロセスの cgroup を消す経路は無い
//! - 記録された pid の生存確認（`kill(pid, 0)`・`/proc`）はしない。PID 再利用の恐れがあるため、判定の
//!   正は `StateStore` の状態とする。kill は状態を更新しないので、kill 直後は supervisor（TASK-157）が
//!   Stopped へ遷移させるまで Running のままで、その間の delete は `FailedPrecondition` になる（意図した挙動）
//! - start との排他は revision 照合だけで足りる。start は launch の前に Created → Running へ予約更新するため、
//!   競合する delete は revision 不一致で失敗する
//! - start の所有ロック（`BundleLock`）は取らない。launch の進行中・上限超過（`Timeout`）・後始末で回収を
//!   確認できずハンドルを未回収レジストリ（`take_unreaped_processes`）へ残した経路では、start は予約
//!   （Running・pid なし）を Created へ戻さないため、delete は上表どおり拒否し、生きている可能性のある
//!   プロセスの記録を消さない。予約を Created へ戻すのは、launch がプロセスを返さなかった場合・起動済み
//!   プロセスの回収を確認できた場合・`recover_interrupted_start` が生存プロセス無しを確かめた場合だけで
//!   ある（CORE-2・SEC-1）
//!
//! # 到達範囲（REPAIR-3）
//!
//! - 本関数が解放するのは cgroup（[`ContainerCgroupRemover`]）と `StateStore` のレコード（ファイルベース実装では
//!   状態ファイル）である。OCI-7 の参照テーブルからの参照解除は TASK-183（`StateStore` 削除の後に組み込む
//!   予定）で未実装
//! - 本番の呼び出し元（CLI / plugin / supervisor）が `DelegatedCgroup::detect` で得たスコープを渡す結線と、
//!   本番の create がスコープを記録する結線（`oci_runtime::create` は記録しない）は未実装（create / start が
//!   本番ではまだ cgroup を作らないため。TASK-29 / TASK-157 系）
//! - `force`（停止してから削除。`ContainerRuntime::delete` の契約）は stop が未実装のため、生きている
//!   可能性のある状態では `Unimplemented` で拒否する
//!
//! エラーメッセージは固定文言のみで、pid・パス・errno を含めない。

use crate::observability::{OpName, OpRecorder};
use crate::traits::{
    CgroupScope, ContainerId, ContainerState, DeleteRequest, DeleteResponse, DeleteStateRequest,
    ErrorCode, GetStateRequest, StateRecord, StateStore, TraitError,
};

/// [`OpRecorder`] に記録する操作名（REPAIR-4）。
const DELETE_OP_NAME: &str = "delete";

/// [`ContainerCgroupRemover::remove`] の結果（将来の拡張に備え非網羅）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CgroupRemoval {
    /// 対応する cgroup を削除した。
    Removed,
    /// 対応する cgroup が存在しなかった（削除済み・未作成。成功扱い）。
    NotPresent,
}

/// コンテナ用 cgroup の削除（CORE-3・OCI-6・TASK-30.3）。[`delete`] が状態記録の削除の前に呼ぶ。
///
/// 本番実装は Linux 限定の `cgroups::DelegatedCgroup`。呼び出し元（CLI / plugin / supervisor）が検出した
/// 委譲スコープを渡す。契約:
///
/// - 対象は `id` に対応する、このランタイムが CORE-3 で作ったコンテナ用子 cgroup だけである
/// - [`Self::scope`] は `remove` が探索する委譲スコープを、[`CgroupScope`] の正規形で返す。[`delete`] は
///   これを状態に記録されたスコープと照合し、一致したときだけ `remove` を呼ぶ
/// - 存在しなければ [`CgroupRemoval::NotPresent`] を返す（成功扱い。再実行の冪等性のため）。`NotPresent` は
///   [`Self::scope`] の配下に無いことだけを意味する
/// - プロセスが残っていて空でない場合は [`ErrorCode::FailedPrecondition`] を返す
/// - 待機を伴わないファイル I/O（`openat` / `unlinkat` / `fstat`）だけで完結する。そのため
///   タイムアウトは持たない（REPAIR-5 の対象外）
/// - エラーのメッセージにパス・errno を含めない（`code` だけを機械可読な判定に使う）
pub trait ContainerCgroupRemover: Send + Sync {
    /// `remove` が対象とする委譲スコープ（コンテナ用子 cgroup の親）を返す。
    ///
    /// 正規形にできない場合はエラーを返す（[`delete`] は照合できないため状態記録を削除しない）。
    fn scope(&self) -> Result<CgroupScope, TraitError>;

    /// `id` に対応する cgroup を削除する。
    fn remove(&self, id: &ContainerId) -> Result<CgroupRemoval, TraitError>;
}

/// 停止済みまたは未起動のコンテナの cgroup と状態記録を削除する。
///
/// 状態の確認後、`cgroups` で cgroup を削除してから状態記録を削除する（順序の根拠はモジュール doc）。
/// cgroup の削除に失敗した場合はそのエラーを返し、状態記録は残す。レコードに cgroup スコープが
/// 記録されていなければ cgroup には触れず、記録されたスコープと `cgroups.scope()` が一致しなければ
/// [`ErrorCode::FailedPrecondition`] を返して cgroup にも状態記録にも触れない。
///
/// 未 create・削除済みの ID は [`ErrorCode::NotFound`]（二重 delete は 2 回目が `NotFound`）、
/// 生きている可能性のある状態は [`ErrorCode::FailedPrecondition`]、`force` で生きているコンテナを
/// 削除する要求は [`ErrorCode::Unimplemented`]。成功・失敗の件数と所要時間は `recorder` へ操作名
/// `delete` で記録する（全終了経路。REPAIR-4）。
pub fn delete(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    cgroups: &dyn ContainerCgroupRemover,
    req: &DeleteRequest,
) -> Result<DeleteResponse, TraitError> {
    let name = OpName::new(DELETE_OP_NAME)?;
    recorder.record_op(&name, || delete_inner(store, cgroups, req))
}

fn delete_inner(
    store: &dyn StateStore,
    cgroups: &dyn ContainerCgroupRemover,
    req: &DeleteRequest,
) -> Result<DeleteResponse, TraitError> {
    let record = store.get(&GetStateRequest::new(req.id().clone()))?;
    check_deletable(&record, req.force())?;
    // スコープの記録が無いレコードは cgroup を作っていない（`StateRecord::cgroup_scope`）ので触れない。
    if let Some(recorded) = record.cgroup_scope() {
        // 別の委譲スコープでの `NotPresent` は「cgroup 無し」の確認にならない（モジュール doc
        // 「委譲スコープの照合」）。一致しなければ cgroup にもレコードにも触れずに返す。
        if cgroups.scope()? != *recorded {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "delegated cgroup scope does not match the recorded scope",
            ));
        }
        // cgroup 削除の直前に revision を再確認し、並行 delete + 再 create で作られた新しい `fc-<id>` を
        // 古い get の結果に基づいて破棄する窓を狭める。revision が変わっていれば cgroup に触れず再試行を促す。
        // 確認と削除の間の窓は `StateStore` に cgroup 削除を含む原子的操作が無いため残る（OCI-6・CORE-2）。
        let current = store.get(&GetStateRequest::new(req.id().clone()))?;
        if current.revision() != record.revision() {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "container state changed during delete; retry",
            ));
        }
        // Removed / NotPresent はどちらも記録されたスコープで「cgroup が無い」状態に到達したので次へ進む。
        // 失敗はレコードを残して返す。
        match cgroups.remove(req.id())? {
            CgroupRemoval::Removed | CgroupRemoval::NotPresent => {}
        }
    }
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
    ///
    /// revision は `StateStore::create` の再利用禁止契約どおりストア全体で 1 から単調に採番し、同じ ID の
    /// 削除・再作成でも過去の値を再発行しない（`next_revision` は最後に払い出した値）。
    #[derive(Default)]
    struct MemStateStore {
        records: Mutex<HashMap<ContainerId, StateRecord>>,
        next_revision: Mutex<u64>,
        /// Some なら最初の delete の照合前に、同じ ID を別クライアントが削除してこの状態で再作成した
        /// ことを再現する（get と delete の間の削除・再作成の競合）。
        recreate_before_delete: Mutex<Option<ContainerStatus>>,
        /// Some なら 2 回目の get の前に、同じ ID を別クライアントが削除してこの状態で再作成した
        /// ことを再現する（最初の get と cgroup 削除前の revision 再確認の間の削除・再作成の競合）。
        recreate_before_second_get: Mutex<Option<ContainerStatus>>,
        /// get の呼び出し回数。
        gets: Mutex<u32>,
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
        /// cgroup スコープ `scope` を記録したレコードを 1 件持つストア（TASK-30.3）。
        fn with_scope(status: ContainerStatus, scope: &str) -> Self {
            let s = Self::default();
            s.create(
                &CreateStateRequest::new(status, std::env::temp_dir().join("b"))
                    .expect("req")
                    .with_cgroup_scope(CgroupScope::new(scope).expect("scope")),
            )
            .expect("create");
            s
        }
        /// ストア全体で一意な revision を 1 つ払い出す。
        fn allocate_revision(&self) -> StateRevision {
            let mut last = self.next_revision.lock().unwrap_or_else(|e| e.into_inner());
            *last = last.checked_add(1).expect("revision overflow");
            StateRevision::from_raw(*last)
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
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            if records.contains_key(req.id()) {
                return Err(TraitError::new(ErrorCode::AlreadyExists, "exists"));
            }
            let mut record = StateRecord::new(
                req.status().clone(),
                req.bundle().to_path_buf(),
                self.allocate_revision(),
            )?;
            if let Some(scope) = req.cgroup_scope() {
                record = record.with_cgroup_scope(scope.clone());
            }
            records.insert(req.id().clone(), record.clone());
            Ok(record)
        }
        fn update(&self, _req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
            let nth = {
                let mut gets = self.gets.lock().unwrap_or_else(|e| e.into_inner());
                *gets += 1;
                *gets
            };
            if nth == 2 {
                let recreate = self
                    .recreate_before_second_get
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                if let Some(status) = recreate {
                    self.records
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(req.id());
                    self.create(
                        &CreateStateRequest::new(status, std::env::temp_dir().join("b2"))
                            .expect("req")
                            .with_cgroup_scope(CgroupScope::new(SCOPE).expect("scope")),
                    )?;
                }
            }
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
            let recreate = self
                .recreate_before_delete
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(status) = recreate {
                self.records
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(req.id());
                self.create(
                    &CreateStateRequest::new(status, std::env::temp_dir().join("b2")).expect("req"),
                )?;
            }
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

    /// テストで記録する委譲スコープ（`RecordingRemover` の既定スコープと同じ）。
    const SCOPE: &str = "/user.slice/user-1000.slice/a.scope";

    /// テスト専用の記録用 `ContainerCgroupRemover`。呼ばれた ID と `scope` の呼び出し回数を記録し、
    /// 決まった結果を返す。
    struct RecordingRemover {
        calls: Mutex<Vec<ContainerId>>,
        scope_calls: Mutex<u32>,
        scope: Result<CgroupScope, TraitError>,
        result: Mutex<Result<CgroupRemoval, TraitError>>,
    }

    impl RecordingRemover {
        fn returning(result: Result<CgroupRemoval, TraitError>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                scope_calls: Mutex::new(0),
                scope: CgroupScope::new(SCOPE),
                result: Mutex::new(result),
            }
        }
        fn scope_calls(&self) -> u32 {
            *self.scope_calls.lock().unwrap_or_else(|e| e.into_inner())
        }
        fn removed() -> Self {
            Self::returning(Ok(CgroupRemoval::Removed))
        }
        fn calls(&self) -> Vec<ContainerId> {
            self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    impl ContainerCgroupRemover for RecordingRemover {
        fn scope(&self) -> Result<CgroupScope, TraitError> {
            *self.scope_calls.lock().unwrap_or_else(|e| e.into_inner()) += 1;
            self.scope.clone()
        }
        fn remove(&self, id: &ContainerId) -> Result<CgroupRemoval, TraitError> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(id.clone());
            self.result
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    fn run_with(
        store: &MemStateStore,
        remover: &RecordingRemover,
        id: &str,
        force: bool,
    ) -> Result<DeleteResponse, TraitError> {
        delete(
            store,
            &OpRecorder::new(),
            remover,
            &DeleteRequest::new(cid(id)).with_force(force),
        )
    }

    fn run(store: &MemStateStore, id: &str, force: bool) -> Result<DeleteResponse, TraitError> {
        run_with(
            store,
            &RecordingRemover::returning(Ok(CgroupRemoval::NotPresent)),
            id,
            force,
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

    /// CORE-2・OCI-5: get の後に同じ ID が削除・再作成されても、新しいレコードは消さない。再作成された
    /// レコードの revision はストア全体の単調採番で旧 revision と異なるため、delete は revision 不一致になり、
    /// レコードが残っていることを確かめて再試行を促す `FailedPrecondition` を返す。
    #[test]
    fn core2_delete_does_not_remove_recreated_record() {
        let store = MemStateStore::with(ContainerStatus::stopped(cid("c1"), Some(0)));
        let recreated = ContainerStatus::created(cid("c1"), None);
        *store
            .recreate_before_delete
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(recreated.clone());
        let err = run(&store, "c1", false).expect_err("stale");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container state changed during delete; retry"
        );
        let rec = store.get(&GetStateRequest::new(cid("c1"))).expect("kept");
        assert_eq!(rec.status(), &recreated);
        assert_eq!(rec.revision(), StateRevision::from_raw(2));
    }

    /// OCI-6・CORE-3（AC2）: Stopped は cgroup 削除がちょうど 1 回、正しい ID で呼ばれ、レコードも消える。
    #[test]
    fn oci6_delete_stopped_removes_cgroup_then_record() {
        let store = MemStateStore::with_scope(ContainerStatus::stopped(cid("c1"), Some(0)), SCOPE);
        let remover = RecordingRemover::removed();
        run_with(&store, &remover, "c1", false).expect("delete");
        assert_eq!(remover.calls(), vec![cid("c1")]);
        assert!(!store.has("c1"));
    }

    /// OCI-6: pid のない Created でも呼ばれ、記録と同じスコープでの `NotPresent` なら成功する。
    #[test]
    fn oci6_delete_created_without_pid_calls_remover() {
        let store = MemStateStore::with_scope(ContainerStatus::created(cid("c1"), None), SCOPE);
        let remover = RecordingRemover::returning(Ok(CgroupRemoval::NotPresent));
        run_with(&store, &remover, "c1", false).expect("delete");
        assert_eq!(remover.calls(), vec![cid("c1")]);
        assert!(!store.has("c1"));
    }

    /// CORE-2: 拒否される状態では cgroup に触れない。
    #[test]
    fn core2_delete_rejected_states_do_not_touch_cgroup() {
        let cases = [
            (ContainerStatus::running(cid("c1"), pid(4242)), false),
            (ContainerStatus::running(cid("c1"), None), false),
            (ContainerStatus::created(cid("c1"), pid(11)), false),
            (ContainerStatus::creating(cid("c1")), false),
            (ContainerStatus::running(cid("c1"), pid(4242)), true),
        ];
        for (status, force) in cases {
            let store = MemStateStore::with_scope(status, SCOPE);
            let remover = RecordingRemover::removed();
            run_with(&store, &remover, "c1", force).expect_err("rejected");
            assert_eq!(remover.calls(), Vec::<ContainerId>::new());
            assert_eq!(remover.scope_calls(), 0);
            assert!(store.has("c1"));
        }
    }

    /// OCI-6: 未 create の ID は `NotFound` で、cgroup には触れない。
    #[test]
    fn oci6_delete_not_found_does_not_call_remover() {
        let store = MemStateStore::default();
        let remover = RecordingRemover::removed();
        let err = run_with(&store, &remover, "missing", false).expect_err("not found");
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(remover.calls(), Vec::<ContainerId>::new());
    }

    /// CORE-2・OCI-6: cgroup の削除に失敗したら code をそのまま返し、レコードと revision は変わらない。
    #[test]
    fn core2_delete_cgroup_failure_keeps_record() {
        let status = ContainerStatus::stopped(cid("c1"), Some(0));
        let store = MemStateStore::with_scope(status.clone(), SCOPE);
        let remover = RecordingRemover::returning(Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container cgroup is not empty or changed; retry",
        )));
        let recorder = OpRecorder::new();
        let err = delete(&store, &recorder, &remover, &DeleteRequest::new(cid("c1")))
            .expect_err("cgroup busy");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container cgroup is not empty or changed; retry"
        );
        let rec = store.get(&GetStateRequest::new(cid("c1"))).expect("kept");
        assert_eq!(rec.status(), &status);
        assert_eq!(rec.revision(), StateRevision::from_raw(1));
        let stats = recorder
            .snapshot_op(&OpName::new("delete").expect("name"))
            .expect("recorded");
        assert_eq!((stats.success(), stats.failure()), (0, 1));
    }

    /// CORE-2・OCI-6: revision 不一致で失敗した後の再実行は、remover が `NotPresent` を返すので冪等に成功する。
    #[test]
    fn core2_delete_retry_after_record_race_is_idempotent() {
        let mut store =
            MemStateStore::with_scope(ContainerStatus::stopped(cid("c1"), Some(0)), SCOPE);
        store.stale_delete = true;
        let remover = RecordingRemover::returning(Ok(CgroupRemoval::Removed));
        run_with(&store, &remover, "c1", false).expect_err("stale");
        store.stale_delete = false;
        *remover.result.lock().unwrap_or_else(|e| e.into_inner()) = Ok(CgroupRemoval::NotPresent);
        run_with(&store, &remover, "c1", false).expect("retry");
        assert_eq!(remover.calls(), vec![cid("c1"), cid("c1")]);
        assert!(!store.has("c1"));
    }

    /// REPAIR-4: 成功と失敗が 1 件ずつ操作名 `delete` で記録される。
    #[test]
    fn repair4_delete_records_success_and_failure() {
        let store = MemStateStore::with_scope(ContainerStatus::stopped(cid("c1"), Some(0)), SCOPE);
        let recorder = OpRecorder::new();
        let req = DeleteRequest::new(cid("c1"));
        let remover = RecordingRemover::removed();
        delete(&store, &recorder, &remover, &req).expect("ok");
        delete(&store, &recorder, &remover, &req).expect_err("ng");
        let stats = recorder
            .snapshot_op(&OpName::new("delete").expect("name"))
            .expect("recorded");
        assert_eq!((stats.success(), stats.failure()), (1, 1));
    }
}
