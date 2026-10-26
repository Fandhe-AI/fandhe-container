//! supervisor から core の `StateStore` 既定実装（`FileStateStore`）を呼び出す薄い配線（TASK-157.3・#237・SUP-1・OCI-5）。
//!
//! supervisor は `state.json` を CLI（`oci_runtime::create` 等）と共有する。状態のファイルベース実装は
//! core に一本化されており（TASK-31・crate-naming.md 決定 6）、本モジュールは 2 つ目の実装・独自の状態型・
//! シリアライズ処理を持たない。型は core の [`StateRecord`]・[`SupervisionState`]・[`HealthStatus`](fandhe_container_core::traits::HealthStatus)・
//! [`TraitError`] をそのまま使う（ファイル名 `state.rs` は spec の成果物名を維持したもので、中身は配線のみ）。
//!
//! 呼び出し元: 監視ループ（`run.rs`。TASK-157.4・#238）が起動時に [`open_default_store`] と
//! [`SupervisedState::attach`] を呼び、以後 [`SupervisedState::write`] 等で status と監視 3 項目
//! （`supervisor_pid`・`health`・`restart_count`）を書く。
//!
//! 契約（`StateStore` トレイト契約）:
//! - 状態ルートのパスは自前で組み立てず、core の `StateRoot::resolve` に委ねる（契約 5）。
//!   所有者・権限・symlink・祖先の検査、ファイルサイズ上限、ロック待ちの上限
//!   （`STATE_LOCK_TIMEOUT`。REPAIR-5）も core 側の実装であり、ここで緩めない・迂回しない。
//! - 書き込みは楽観的排他（revision）。不一致は `FailedPrecondition` をそのまま返し、
//!   再読込（[`SupervisedState::refresh`]）して再試行するかは呼び出し側（#238・#1069）が決める。
//!   本モジュールはリトライを実装しない（無限リトライによるハングを避ける）。
//! - レコードの作成は CLI 側の責務で、supervisor は作らない（無ければ `NotFound`）。
//! - `supervisor_pid` は記録値であり、シグナル送信先・権限判断にそのまま使わない（SUP-5・SUP-8）。
//! - 破損した `state.json` は untrusted として core がエラーで返す。panic せず `Result` で伝播する。

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use fandhe_container_core::launch_isolation::LaunchIsolationRecord;
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ContainerStatus, ErrorCode, ExplicitStop, GetStateRequest,
    StateRecord, StateStore, SupervisionState, TraitError, UpdateStateRequest,
};

use crate::run::MAX_WRITE_ATTEMPTS;

/// core の既定ストア（`FileStateStore`）を開く。
///
/// `root_override` が `None` なら core の既定ルート解決に従う。Linux 以外では core が `Unimplemented` を
/// 返すので、そのまま伝播する（fail-closed。CLI-1）。
pub fn open_default_store(
    root_override: Option<PathBuf>,
) -> Result<Arc<dyn StateStore>, TraitError> {
    let root = StateRoot::resolve(root_override)?;
    let store = FileStateStore::open(root)?;
    Ok(Arc::new(store))
}

/// 1 コンテナ分の状態を `StateStore` 経由で読み書きする監視ループ用ハンドル。
///
/// 直近に読んだ・書いた [`StateRecord`] を保持し、その revision を楽観的排他の期待値に使う。
pub struct SupervisedState {
    store: Arc<dyn StateStore>,
    id: ContainerId,
    last: StateRecord,
}

impl fmt::Debug for SupervisedState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `dyn StateStore` は Debug を要求しないため store は出さない。
        f.debug_struct("SupervisedState")
            .field("id", &self.id)
            .field("last", &self.last)
            .finish_non_exhaustive()
    }
}

impl SupervisedState {
    /// 既存レコードを読んでハンドルを作る。レコードが無ければ `NotFound`（作成は CLI の責務）。
    pub fn attach(store: Arc<dyn StateStore>, id: ContainerId) -> Result<Self, TraitError> {
        let last = store.get(&GetStateRequest::new(id.clone()))?;
        Ok(Self { store, id, last })
    }

    /// 対象コンテナの ID。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// 直近に読んだ・書いたレコード（status・supervisor_pid・health・restart_count を持つ）。
    pub fn record(&self) -> &StateRecord {
        &self.last
    }

    /// ストアから読み直して保持レコードを更新する。
    pub fn refresh(&mut self) -> Result<&StateRecord, TraitError> {
        self.last = self.store.get(&GetStateRequest::new(self.id.clone()))?;
        Ok(&self.last)
    }

    /// status と監視 3 項目を書く。別コンテナの status は `InvalidArgument` で拒否する。
    ///
    /// revision 不一致は `FailedPrecondition` をそのまま返す（保持レコードは更新しない）。
    pub fn write(
        &mut self,
        status: ContainerStatus,
        supervision: SupervisionState,
    ) -> Result<&StateRecord, TraitError> {
        self.write_with_isolation(status, supervision, None, None)
    }

    /// restart の再 launch の記録用。`write` に加えて、再 launch が確定した分離の記録を渡されれば置き換える
    /// （再 launch で mount namespace が作り直されるため。`None` は前の記録を引き継ぐ。トレイト契約 12。
    /// SUP-6・SUP-3・#2007）。`rlimits` も同様に、再 launch が適用した全 16 種を渡されれば置き換える
    /// （`None` は前の記録を引き継ぐ。SUP-12・#2713）。
    pub fn write_relaunched(
        &mut self,
        status: ContainerStatus,
        supervision: SupervisionState,
        launch_isolation: Option<LaunchIsolationRecord>,
        rlimits: Option<fandhe_container_core::rlimits::Rlimits>,
    ) -> Result<&StateRecord, TraitError> {
        self.write_with_isolation(status, supervision, launch_isolation, rlimits)
    }

    fn write_with_isolation(
        &mut self,
        status: ContainerStatus,
        supervision: SupervisionState,
        launch_isolation: Option<LaunchIsolationRecord>,
        rlimits: Option<fandhe_container_core::rlimits::Rlimits>,
    ) -> Result<&StateRecord, TraitError> {
        if status.id() != &self.id {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "status id does not match the supervised container",
            ));
        }
        let mut req =
            UpdateStateRequest::new(status, self.last.revision()).with_supervision(supervision);
        if let Some(record) = launch_isolation {
            req = req.with_launch_isolation(record);
        }
        if let Some(set) = rlimits {
            req = req.with_rlimits(set);
        }
        self.last = self.store.update(&req)?;
        Ok(&self.last)
    }

    /// 保持レコード（`monitor` が書いた `Stopped` の終了記録）へ「明示 stop 済み」を書き足す（トレイト契約 14。
    /// SUP-9・SUP-3・SUP-8・#2440）。status と監視 3 項目は変えない。
    ///
    /// 保持レコードが `Stopped` でなければ `FailedPrecondition`。revision 不一致のとき、cgroup の記録（作成時に決まる
    /// 世代の識別子）がある場合だけ `refresh` して再試行する（記録が無ければ世代を識別できないため再試行せず中止する）
    /// （上限 [`MAX_WRITE_ATTEMPTS`]）が、再読込したレコードの status・`restart_count` が変わったり監視権が付いたり
    /// していれば、また bundle・cgroup の記録が変わっていれば（同じ ID の再作成・別処理の再起動）書かずに `FailedPrecondition` で中止する。
    /// 呼び出し元は [`crate::restart::supervise_with_restart`] の監視スレッドだけ（`SupervisedState` を持つのは
    /// 監視スレッドだけのため、書き手は他に増えない）。
    pub fn write_explicit_stop(&mut self) -> Result<&StateRecord, TraitError> {
        let expected_status = self.last.status().clone();
        let expected_count = self.last.restart_count();
        // 世代の識別子。revision が食い違って再読込した後は、同じ ID の削除・再作成で status・終了コード・
        // `restart_count` が偶然一致しても取り違えないよう、作成時に決まる bundle と cgroup の記録も照合する。
        let expected_bundle = self.last.bundle().to_path_buf();
        let expected_cgroup = self.last.cgroup().cloned();
        let mut last_err = TraitError::new(
            ErrorCode::FailedPrecondition,
            "explicit stop write attempts exhausted",
        );
        for attempt in 0..MAX_WRITE_ATTEMPTS {
            if attempt > 0 {
                // 再読込して照合できる世代の識別子は cgroup の instance（作成時の revision。契約 8）だけ。
                // 記録が無ければ別世代と区別できないため、内容比較に頼らず書かずに中止する。
                if expected_cgroup.is_none() {
                    return Err(last_err);
                }
                self.refresh()?;
            }
            let rec = &self.last;
            if rec.status().state() != ContainerState::Stopped
                || rec.status() != &expected_status
                || rec.restart_count() != expected_count
                || rec.bundle() != expected_bundle.as_path()
                || rec.cgroup() != expected_cgroup.as_ref()
                || rec.supervisor_pid().is_some()
            {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "container state changed while recording explicit stop",
                ));
            }
            let req = UpdateStateRequest::new(rec.status().clone(), rec.revision())
                .with_supervision(rec.supervision())
                .with_explicit_stop(ExplicitStop::Recorded);
            match self.store.update(&req) {
                Ok(updated) => {
                    self.last = updated;
                    return Ok(&self.last);
                }
                Err(e) if e.code() == ErrorCode::FailedPrecondition => last_err = e,
                Err(e) => return Err(e),
            }
        }
        Err(last_err)
    }

    /// status は保持レコードのまま、監視 3 項目だけを書く。
    pub fn write_supervision(
        &mut self,
        supervision: SupervisionState,
    ) -> Result<&StateRecord, TraitError> {
        let status = self.last.status().clone();
        self.write(status, supervision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU32;
    use std::sync::Mutex;

    use fandhe_container_core::traits::{
        CreateStateRequest, DeleteStateRequest, DeleteStateResponse, HealthStatus,
        ListStateRequest, StateList, StateRevision,
    };

    /// 1 レコードだけを持つメモリ上のフェイク。revision は update ごとに +1 する。
    struct FakeStore(Mutex<Option<StateRecord>>);

    fn err(code: ErrorCode, msg: &str) -> TraitError {
        TraitError::new(code, msg)
    }

    impl StateStore for FakeStore {
        fn create(&self, _: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            Err(err(ErrorCode::Unimplemented, "fake"))
        }
        fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            let mut g = self.0.lock().unwrap();
            let cur = g.as_ref().ok_or_else(|| err(ErrorCode::NotFound, "none"))?;
            if cur.revision() != req.expected_revision() {
                return Err(err(ErrorCode::FailedPrecondition, "stale"));
            }
            let next = StateRecord::new(
                req.status().clone(),
                cur.bundle().to_path_buf(),
                StateRevision::from_raw(cur.revision().value() + 1),
            )
            .unwrap()
            .with_supervision(req.supervision().unwrap_or_else(|| cur.supervision()));
            *g = Some(next.clone());
            Ok(next)
        }
        fn get(&self, _: &GetStateRequest) -> Result<StateRecord, TraitError> {
            let g = self.0.lock().unwrap();
            g.clone().ok_or_else(|| err(ErrorCode::NotFound, "none"))
        }
        fn list(&self, _: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(err(ErrorCode::Unimplemented, "fake"))
        }
        fn delete(&self, _: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(err(ErrorCode::Unimplemented, "fake"))
        }
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).unwrap()
    }

    fn fake(id: &str) -> Arc<FakeStore> {
        let rec = StateRecord::new(
            ContainerStatus::created(cid(id), None),
            std::env::temp_dir().join("b"),
            StateRevision::from_raw(1),
        )
        .unwrap();
        Arc::new(FakeStore(Mutex::new(Some(rec))))
    }

    fn sup(pid: u32, n: u32) -> SupervisionState {
        SupervisionState::new(NonZeroU32::new(pid), Some(HealthStatus::Healthy), n)
    }

    /// SUP-1・TASK-157.3: write の結果が保持レコードに反映され、具体値で読める。
    #[test]
    fn sup1_task157_3_write_updates_cached_record() {
        let store = fake("c1");
        let mut s = SupervisedState::attach(store, cid("c1")).unwrap();
        let rec = s
            .write(
                ContainerStatus::running(cid("c1"), NonZeroU32::new(42)),
                sup(7, 2),
            )
            .unwrap();
        assert_eq!(rec.revision().value(), 2);
        assert_eq!(rec.supervisor_pid(), NonZeroU32::new(7));
        assert_eq!(rec.health(), Some(HealthStatus::Healthy));
        assert_eq!(rec.restart_count(), 2);
        assert_eq!(s.record().status().pid(), NonZeroU32::new(42));
    }

    /// TASK-157.3: 古い revision の write は FailedPrecondition で、refresh 後は成功する。
    #[test]
    fn sup1_task157_3_stale_write_is_failed_precondition_until_refresh() {
        let store = fake("c1");
        let mut a = SupervisedState::attach(store.clone(), cid("c1")).unwrap();
        let mut b = SupervisedState::attach(store, cid("c1")).unwrap();
        a.write_supervision(sup(1, 1)).unwrap();
        let e = b.write_supervision(sup(2, 2)).unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        b.refresh().unwrap();
        assert_eq!(b.write_supervision(sup(2, 2)).unwrap().restart_count(), 2);
    }

    fn placement(instance: u64) -> fandhe_container_core::traits::CgroupPlacement {
        fandhe_container_core::traits::CgroupPlacement::new(
            fandhe_container_core::traits::CgroupScope::new("/user.slice/x.scope").unwrap(),
            StateRevision::from_raw(instance),
        )
    }

    /// SUP-9・#2440: cgroup の記録が無い（世代を識別できない）レコードは、revision 競合で再試行せず書かずに中止する。
    #[test]
    fn sup9_explicit_stop_aborts_on_conflict_without_cgroup_record() {
        let rec = |rev: u64| {
            StateRecord::new(
                ContainerStatus::stopped(cid("c1"), Some(1)),
                std::env::temp_dir().join("b"),
                StateRevision::from_raw(rev),
            )
            .unwrap()
        };
        let store = Arc::new(FakeStore(Mutex::new(Some(rec(1)))));
        let mut s = SupervisedState::attach(store.clone(), cid("c1")).unwrap();
        *store.0.lock().unwrap() = Some(rec(2));
        let e = s.write_explicit_stop().unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            store.0.lock().unwrap().as_ref().unwrap().revision().value(),
            2
        );
    }

    /// SUP-9・#2440: revision 競合後の再読込で bundle が違う（同じ ID の再作成）記録なら、status・終了コード・
    /// `restart_count` が同じでも明示 stop を書かず `FailedPrecondition` で中止する。
    #[test]
    fn sup9_explicit_stop_aborts_on_recreated_generation() {
        let stopped = |bundle: &str, rev: u64| {
            StateRecord::new(
                ContainerStatus::stopped(cid("c1"), Some(1)),
                std::env::temp_dir().join(bundle),
                StateRevision::from_raw(rev),
            )
            .unwrap()
            .with_cgroup(placement(rev))
        };
        let store = Arc::new(FakeStore(Mutex::new(Some(stopped("old", 1)))));
        let mut s = SupervisedState::attach(store.clone(), cid("c1")).unwrap();
        // 削除・再作成された新世代（revision は進み、内容は同じ Stopped）。
        *store.0.lock().unwrap() = Some(stopped("new", 5));
        let e = s.write_explicit_stop().unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            store.0.lock().unwrap().as_ref().unwrap().revision().value(),
            5
        );
    }

    /// SUP-9・#2440: 同じ世代で revision だけ進んだ（health 更新など）記録なら再読込して書ける。
    #[test]
    fn sup9_explicit_stop_retries_on_same_generation() {
        let rec = |rev: u64| {
            StateRecord::new(
                ContainerStatus::stopped(cid("c1"), Some(1)),
                std::env::temp_dir().join("b"),
                StateRevision::from_raw(rev),
            )
            .unwrap()
            .with_cgroup(placement(1))
        };
        let store = Arc::new(FakeStore(Mutex::new(Some(rec(1)))));
        let mut s = SupervisedState::attach(store.clone(), cid("c1")).unwrap();
        *store.0.lock().unwrap() = Some(rec(2));
        assert_eq!(s.write_explicit_stop().unwrap().revision().value(), 3);
    }

    /// TASK-157.3: 別コンテナの status は InvalidArgument、レコードなしは NotFound。
    #[test]
    fn sup1_task157_3_rejects_other_id_and_missing_record() {
        let store = fake("c1");
        let mut s = SupervisedState::attach(store, cid("c1")).unwrap();
        let e = s
            .write(ContainerStatus::created(cid("c2"), None), sup(1, 0))
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        let empty = Arc::new(FakeStore(Mutex::new(None)));
        let e = SupervisedState::attach(empty, cid("c1")).unwrap_err();
        assert_eq!(e.code(), ErrorCode::NotFound);
    }
}
