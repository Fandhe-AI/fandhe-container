//! start 時の cgroup 手順（委譲スコープの記録 → mkdir → 制限の設定 → 参加フックの取得）を型で固定する
//! （TASK-32 追補・#1716・MS-2。関連: CORE-1・CORE-3・CORE-4・OCI-6・SEC-1・REPAIR-3）。
//!
//! # 役割
//! #1314 の決定（案 3-ii）では、create（CLI）は委譲スコープを記録せず、start の時点で supervisor が
//! `detect` → スコープを状態記録へ追記 → `prepare`（`fc-<id>@<n>` を mkdir）→ 制限の設定 → `join_hook` を行う。
//! 本モジュールはこの順序を、前段のトークンを値で消費する型の連鎖にして固定する。順序を入れ替えた呼び出しは
//! コンパイルできない。特に「記録の前に mkdir する」と cgroup が delete に回収されずリークするため、
//! 記録を最初の段にしている。
//!
//! ```text
//! DelegatedCgroup::record_scope(store, observed)   -> CgroupScopeRecorded   （状態記録へ追記）
//!   .create_cgroup()                               -> CgroupPrepared        （prepare = mkdir・退避・検証）
//!   .apply_limits(recorder, plan)                  -> CgroupLimited         （デバイス許可プログラム）
//!   .into_join()                                   -> StartCgroup           （CgroupJoin の取得）
//! ```
//!
//! # 呼び出し文脈・契約
//! - 呼び出し元: start 経路の supervisor（結線は #1717、本番 launcher は #1715）。fork の前に親で呼ぶ
//!   （デバイス許可プログラムは cgroup にプロセスが入る前に付ける必要がある）
//! - 既存の低レベル API（`prepare`・`join_hook`・`apply_default_device_policy`）は実機試験や exec 経路のために
//!   `pub` のままだが、start の経路ではこの連鎖だけを使う
//! - 失敗時の回収: 記録の後に落ちた場合、スコープは記録済みなので、作った cgroup は delete が記録の instance の
//!   名前で回収する。記録の後・mkdir の前に落ちても delete は `NotPresent` で冪等に閉じる。`apply_limits`
//!   以降の失敗では巻き戻さない（`prepare` の失敗時の巻き戻しは `prepare` 自身が行う）
//! - 追記の後 `oci_runtime::start` の予約の前に、並行する delete が Created のレコードを消す競合がある。
//!   このとき作った cgroup は記録が無くなるため、呼び出し元が [`StartCgroup::cgroup`] で `remove_child`
//!   する（#1717 の責務）
//! - 待機はストアの I/O とファイル I/O のみ。ストア側のタイムアウトは `StateStore` の契約 2 による
//! - エラーは [`CgroupError`]。ストア由来のメッセージ（plugin が返しうる）は外へ流さず固定文言にする
//!
//! # 未実装（REPAIR-3）
//! - OCI `linux.resources` の資源制限（memory・cpu・pids・io）の写像。[`CgroupLimitPlan`] に項目を足す形で
//!   拡張する（`#[non_exhaustive]`。TASK-170.3 ほか）。`enable_controllers` の呼び出しもそのときに足す

use super::{
    CgroupError, CgroupJoin, CgroupName, CgroupStep, ContainerCgroup, DelegatedCgroup,
    DevicePolicyMode, DevicePolicyOutcome, Evacuated,
};
use crate::exec::IsolationPrivilege;
use crate::observability::OpRecorder;
use crate::oci_runtime::ContainerCgroupRemover;
use crate::traits::{
    CgroupPlacement, ContainerId, ContainerState, ErrorCode, StateRecord, StateStore, TraitError,
    UpdateStateRequest,
};

/// ストアのエラーを `CgroupError` へ写す。`code` だけを保ち、メッセージは固定文言にする。
fn store_error(e: &TraitError) -> CgroupError {
    let message = match e.code() {
        ErrorCode::FailedPrecondition => "state revision changed or cgroup scope already recorded",
        ErrorCode::NotFound => "container state not found",
        _ => "failed to record the cgroup scope",
    };
    CgroupError::new(e.code(), CgroupStep::RecordScope, message)
}

impl DelegatedCgroup {
    /// 検出した委譲スコープを、`observed`（supervisor が `get` したレコード）の状態記録へ追記する（段 1）。
    ///
    /// 事前の確認（満たさなければストアへ書かず `FailedPrecondition`）: レコードが Created で pid が無いこと、
    /// 配置が未記録であること。追記は `observed.revision()` で排他する（合わなければ `FailedPrecondition`）。
    /// 追記後は返ったレコードの配置が `(このスコープ, observed.revision())` であることを照合し、合わなければ
    /// `Internal`（`cgroup_scope` を落とす plugin 実装の検出。この時点では mkdir していない）。
    /// instance は `observed.revision()` になり、標準の流れ（create の後の最初の書き込みで追記）では create の
    /// revision と一致する（トレイト契約 8）。
    pub fn record_scope<'a>(
        &'a self,
        store: &dyn StateStore,
        observed: &StateRecord,
    ) -> Result<CgroupScopeRecorded<'a>, CgroupError> {
        let step = CgroupStep::RecordScope;
        let status = observed.status();
        if status.state() != ContainerState::Created || status.pid().is_some() {
            return Err(CgroupError::precondition(
                step,
                "container is not in created state",
            ));
        }
        if observed.cgroup().is_some() {
            return Err(CgroupError::precondition(
                step,
                "cgroup scope is already recorded",
            ));
        }
        let scope = ContainerCgroupRemover::scope(self).map_err(|e| store_error(&e))?;
        let req = UpdateStateRequest::new(status.clone(), observed.revision())
            .with_cgroup_scope(scope.clone());
        let updated = store.update(&req).map_err(|e| store_error(&e))?;
        let expected = CgroupPlacement::new(scope, observed.revision());
        if updated.id() != observed.id() || updated.cgroup() != Some(&expected) {
            return Err(CgroupError::new(
                ErrorCode::Internal,
                step,
                "state store did not record the cgroup scope",
            ));
        }
        Ok(CgroupScopeRecorded {
            delegated: self,
            id: observed.id().clone(),
            placement: expected,
            record: updated,
        })
    }
}

/// 段 1 の結果: 委譲スコープを状態記録へ追記済み。`record_scope` の中でしか作れない。
#[derive(Debug)]
pub struct CgroupScopeRecorded<'a> {
    delegated: &'a DelegatedCgroup,
    id: ContainerId,
    placement: CgroupPlacement,
    record: StateRecord,
}

impl<'a> CgroupScopeRecorded<'a> {
    /// 記録した配置（スコープと instance）。
    pub fn placement(&self) -> &CgroupPlacement {
        &self.placement
    }

    /// 追記後のレコード。`oci_runtime::start` に渡す revision はこれの `revision()` である（#1717）。
    pub fn record(&self) -> &StateRecord {
        &self.record
    }

    /// 記録した instance から `fc-<id>@<n>` を作り、`prepare` で mkdir・退避・検証する（段 2）。
    ///
    /// 失敗時の巻き戻しは `prepare` に任せる。スコープは記録済みなので、残った cgroup は delete が回収する。
    pub fn create_cgroup(self) -> Result<CgroupPrepared<'a>, CgroupError> {
        let name = CgroupName::for_instance(&self.id, self.placement.instance())?;
        let (cgroup, evacuated) = self.delegated.prepare(&name)?;
        Ok(CgroupPrepared {
            delegated: self.delegated,
            cgroup,
            evacuated,
            record: self.record,
        })
    }
}

/// 段 2 の結果: コンテナ用 cgroup を作成済み（自プロセスは退避リーフへ移動済み）。
#[derive(Debug)]
pub struct CgroupPrepared<'a> {
    delegated: &'a DelegatedCgroup,
    cgroup: ContainerCgroup,
    evacuated: Evacuated,
    record: StateRecord,
}

impl CgroupPrepared<'_> {
    /// 作成した cgroup。
    pub fn cgroup(&self) -> &ContainerCgroup {
        &self.cgroup
    }

    /// 退避済みの証明。将来 `enable_controllers` を呼ぶ段（資源制限の写像。TASK-170.3）が使う。
    pub fn evacuation_proof(&self) -> &Evacuated {
        &self.evacuated
    }

    /// 作成元の委譲スコープ。
    pub fn delegated(&self) -> &DelegatedCgroup {
        self.delegated
    }

    /// `plan` に従って制限を設定する（段 3）。今はデバイス許可プログラムだけ（rootful では適用、rootless では
    /// `NotApplied(Rootless)` を結果として返す。SEC-1）。失敗しても巻き戻さない（delete が回収する）。
    pub fn apply_limits(
        self,
        recorder: &OpRecorder,
        plan: &CgroupLimitPlan,
    ) -> Result<CgroupLimited, CgroupError> {
        let device_policy = self
            .cgroup
            .apply_default_device_policy(recorder, plan.device_policy)?;
        Ok(CgroupLimited {
            cgroup: self.cgroup,
            record: self.record,
            report: CgroupLimitReport { device_policy },
        })
    }
}

/// 設定する制限の計画。今はデバイス許可の経路だけを持つ（REPAIR-3: 資源制限は未実装でフィールドを足して拡張する）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CgroupLimitPlan {
    /// デバイス許可プログラムの適用経路。
    pub device_policy: DevicePolicyMode,
}

impl CgroupLimitPlan {
    /// 適用経路を直接指定して作る。
    pub fn new(device_policy: DevicePolicyMode) -> Self {
        Self { device_policy }
    }

    /// launcher がこれから使う権限モデルから作る（子の `isolate` の結果ではなく、fork 前に決めた値を渡す）。
    pub fn for_privilege(privilege: IsolationPrivilege) -> Self {
        Self::new(DevicePolicyMode::from(privilege))
    }
}

/// 制限の設定結果（将来拡張できる構造。`#[non_exhaustive]`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CgroupLimitReport {
    /// デバイス許可プログラムの結果（適用した、または適用しなかった理由）。
    pub device_policy: DevicePolicyOutcome,
}

/// 段 3 の結果: 制限の設定済み。
#[derive(Debug)]
pub struct CgroupLimited {
    cgroup: ContainerCgroup,
    record: StateRecord,
    report: CgroupLimitReport,
}

impl CgroupLimited {
    /// 制限の設定結果。
    pub fn limits(&self) -> &CgroupLimitReport {
        &self.report
    }

    /// 子プロセスの参加フックを取得する（段 4）。
    pub fn into_join(self) -> Result<StartCgroup, CgroupError> {
        let join = self.cgroup.join_hook()?;
        Ok(StartCgroup {
            cgroup: self.cgroup,
            join,
            record: self.record,
            report: self.report,
        })
    }
}

/// 連鎖の最終結果: 起動に必要なものが揃った cgroup。
#[derive(Debug)]
pub struct StartCgroup {
    cgroup: ContainerCgroup,
    join: CgroupJoin,
    record: StateRecord,
    report: CgroupLimitReport,
}

impl StartCgroup {
    /// 追記後のレコード。
    pub fn record(&self) -> &StateRecord {
        &self.record
    }

    /// 制限の設定結果。
    pub fn limits(&self) -> &CgroupLimitReport {
        &self.report
    }

    /// 作成した cgroup。起動に失敗したときの `remove_child` に使う。
    pub fn cgroup(&self) -> &ContainerCgroup {
        &self.cgroup
    }

    /// `(cgroup, 参加フック, 追記後のレコード, 制限の結果)` に分解する。フックは launcher の `CgroupJoin` 段へ渡す。
    pub fn into_parts(self) -> (ContainerCgroup, CgroupJoin, StateRecord, CgroupLimitReport) {
        (self.cgroup, self.join, self.record, self.report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroups::{CgroupPath, ControllerSet};
    use crate::oci_runtime::CgroupRemoval;
    use crate::state_store::{FileStateStore, StateRoot};
    use crate::traits::{
        ContainerStatus, CreateStateRequest, DeleteRequest, GetStateRequest, StateRevision,
    };
    use std::os::fd::OwnedFd;
    use std::path::{Path, PathBuf};

    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let p = std::env::temp_dir().join(format!(
                "fandhe-start-chain-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&p).unwrap();
            // 状態ルートの祖先は group / others 書き込み不可でなければならない。
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(p)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).unwrap()
    }

    /// 一時ディレクトリを委譲スコープ（`/test.slice/x.scope`）の代わりにする。
    fn delegated_for_test(dir: &Path) -> DelegatedCgroup {
        let fd = OwnedFd::from(std::fs::File::open(dir).unwrap());
        DelegatedCgroup {
            path: CgroupPath {
                components: vec!["test.slice".to_owned(), "x.scope".to_owned()],
            },
            fd,
            controllers: ControllerSet::of(&[]),
        }
    }

    fn open_store(root: &Path) -> FileStateStore {
        use std::os::unix::fs::PermissionsExt as _;
        let state = root.join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        FileStateStore::open(StateRoot::from_override(state).unwrap()).unwrap()
    }

    fn create(store: &dyn StateStore, id: &str) -> StateRecord {
        let bundle = std::env::temp_dir().join("fandhe-bundle");
        store
            .create(
                &CreateStateRequest::new(ContainerStatus::created(cid(id), None), bundle).unwrap(),
            )
            .unwrap()
    }

    /// CORE-3・OCI-6・TASK-32: Created のレコードに追記すると、配置は (スコープ, create の revision) で、
    /// ストアから読んだ値と一致する。
    #[test]
    fn core3_oci6_task32_record_scope_appends_create_revision() {
        let t = TmpDir::new("rec");
        let delegated = delegated_for_test(&t.0);
        let store = open_store(&t.0);
        let created = create(&store, "web");
        let recorded = delegated.record_scope(&store, &created).unwrap();
        assert_eq!(recorded.placement().scope().as_str(), "/test.slice/x.scope");
        assert_eq!(recorded.placement().instance(), created.revision());
        assert_eq!(recorded.placement().instance(), StateRevision::from_raw(0));
        let got = store.get(&GetStateRequest::new(cid("web"))).unwrap();
        assert_eq!(got, *recorded.record());
        assert_eq!(got.cgroup(), Some(recorded.placement()));
        assert_eq!(got.status().state(), ContainerState::Created);
    }

    /// CORE-3・TASK-32: Created 以外・配置が既にある・observed が古い、はいずれも `FailedPrecondition`
    /// （段は `RecordScope`）で、ストアの revision を変えない。
    #[test]
    fn core3_task32_record_scope_rejects_non_created_and_recorded() {
        let t = TmpDir::new("rej");
        let delegated = delegated_for_test(&t.0);
        let store = open_store(&t.0);
        let created = create(&store, "web");
        // 古い observed（間に別の update が入った）。
        let running = store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(cid("web"), std::num::NonZeroU32::new(7)),
                created.revision(),
            ))
            .unwrap();
        let e = delegated.record_scope(&store, &running).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.step, CgroupStep::RecordScope);
        assert_eq!(e.message, "container is not in created state");
        let e = delegated.record_scope(&store, &created).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message,
            "state revision changed or cgroup scope already recorded"
        );
        let after = store.get(&GetStateRequest::new(cid("web"))).unwrap();
        assert_eq!(after.revision(), running.revision());
        assert_eq!(after.cgroup(), None);

        // 配置が既にあるレコード。
        let c2 = create(&store, "api");
        let recorded = delegated.record_scope(&store, &c2).unwrap();
        let e = delegated
            .record_scope(&store, recorded.record())
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.message, "cgroup scope is already recorded");
    }

    /// `cgroup_scope` を黙って落とすストア（plugin 実装の不具合の模擬）。
    struct DroppingStore(FileStateStore);

    impl StateStore for DroppingStore {
        fn create(&self, r: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            self.0.create(r)
        }
        fn update(&self, r: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            let plain = UpdateStateRequest::new(r.status().clone(), r.expected_revision());
            self.0.update(&plain)
        }
        fn get(&self, r: &GetStateRequest) -> Result<StateRecord, TraitError> {
            self.0.get(r)
        }
        fn list(
            &self,
            r: &crate::traits::ListStateRequest,
        ) -> Result<crate::traits::StateList, TraitError> {
            self.0.list(r)
        }
        fn delete(
            &self,
            r: &crate::traits::DeleteStateRequest,
        ) -> Result<crate::traits::DeleteStateResponse, TraitError> {
            self.0.delete(r)
        }
    }

    /// CORE-3・TASK-32: 追記を落とすストアは `Internal` で検出し、mkdir しない。
    #[test]
    fn core3_task32_record_scope_detects_store_dropping_scope() {
        let t = TmpDir::new("drop");
        let delegated = delegated_for_test(&t.0);
        let store = DroppingStore(open_store(&t.0));
        let created = create(&store, "web");
        let e = delegated.record_scope(&store, &created).unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.step, CgroupStep::RecordScope);
        assert_eq!(e.message, "state store did not record the cgroup scope");
        let entries: Vec<_> = std::fs::read_dir(&t.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(entries, vec!["state".to_owned()]);
    }

    /// OCI-6・CORE-3・TASK-32（受け入れ条件 4）: スコープを記録したが mkdir していない（トークンを捨てた）
    /// コンテナの delete は、`NotPresent` を経て冪等に成功する。
    #[test]
    fn oci6_core3_task32_delete_after_scope_recorded_without_mkdir_is_idempotent() {
        let t = TmpDir::new("idem");
        let delegated = delegated_for_test(&t.0);
        let store = open_store(&t.0);
        let created = create(&store, "web");
        let instance = {
            let recorded = delegated.record_scope(&store, &created).unwrap();
            recorded.placement().instance()
        };
        assert_eq!(
            ContainerCgroupRemover::remove(&delegated, &cid("web"), instance).unwrap(),
            CgroupRemoval::NotPresent
        );
        let recorder = OpRecorder::new();
        crate::oci_runtime::delete(
            &store,
            &recorder,
            &delegated,
            &DeleteRequest::new(cid("web")),
        )
        .unwrap();
        let e = store.get(&GetStateRequest::new(cid("web"))).unwrap_err();
        assert_eq!(e.code(), ErrorCode::NotFound);
        assert!(!t.0.join("state").join("web").exists());
        assert!(!t.0.join("fc-web@0").exists());
        let again = crate::oci_runtime::delete(
            &store,
            &recorder,
            &delegated,
            &DeleteRequest::new(cid("web")),
        );
        assert!(again.is_err());
    }
}
