//! supervisor から core の `StateStore` 既定実装（`FileStateStore`）を呼び出す薄い配線（TASK-157.3・#237・SUP-1・OCI-5）。
//!
//! supervisor は `state.json` を CLI（`oci_runtime::create` 等）と共有する。状態のファイルベース実装は
//! core に一本化されており（TASK-31・crate-naming.md 決定 6）、本モジュールは 2 つ目の実装・独自の状態型・
//! シリアライズ処理を持たない。型は core の [`StateRecord`]・[`SupervisionState`]・[`HealthStatus`]・
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

use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, ContainerStatus, ErrorCode, GetStateRequest, StateRecord, StateStore,
    SupervisionState, TraitError, UpdateStateRequest,
};

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
        if status.id() != &self.id {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "status id does not match the supervised container",
            ));
        }
        let req =
            UpdateStateRequest::new(status, self.last.revision()).with_supervision(supervision);
        self.last = self.store.update(&req)?;
        Ok(&self.last)
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
