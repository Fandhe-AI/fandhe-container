//! 本番の cgroup remover（`delete` が cgroup の配置を記録したコンテナを消すための `ContainerCgroupRemover`。
//! OCI-6・CORE-3・SEC-1・#1314 の 3-ii・#2096・#2434）。
//!
//! CLI の `stop_delete`（`delete` コマンド）と plugin-cri の `CoreLifecycleRuntime::delete` の 2 か所が、同じ
//! 実装を共有するために supervisor crate に置く（元は CLI の private 実装。移設は #2434・REPAIR-1）。core に置かないのは、
//! 本番の検出（呼び出しプロセス自身の cgroup）は呼び出し側の組み立ての責務で、PLUG-4 で監視される core を触らないため。
//! Linux では呼び出しプロセス自身の cgroup から委譲スコープを遅延検出する。検出に失敗したら cgroup も状態記録も
//! 残したまま構造化エラーで失敗する（fail-closed）。非 Linux では常に `Unimplemented` で失敗する（REPAIR-3）。

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{CgroupRemoval, ContainerCgroupRemover};
use fandhe_container_core::traits::{
    CgroupPlacement, CgroupScope, ContainerId, ErrorCode, StateRevision, TraitError,
};

/// 委譲スコープを初回の利用時に 1 回だけ検出し、結果をキャッシュする cgroup remover（Linux。OCI-6・CORE-3）。
///
/// CLI の `run_delete` と plugin-cri の `delete` が core の `delete` へ渡す。core は cgroup 配置の記録が無いレコードでは remover に触れないため、
/// 検出（`DelegatedCgroup::detect`）は配置のあるレコードの delete だけで走る。`scope()` と
/// `remove_with_recorder()` が同じ検出結果を共有するので、2 回の検出の間に所属が変わって食い違うことは無い。
/// 検出の失敗もキャッシュして同じエラーで返し、状態記録を残す（fail-closed）。
#[cfg(target_os = "linux")]
pub struct DetectedCgroupRemover<R, F> {
    detect: F,
    detected: std::sync::OnceLock<Result<R, TraitError>>,
}

#[cfg(target_os = "linux")]
impl<R, F> DetectedCgroupRemover<R, F>
where
    R: ContainerCgroupRemover,
    F: Fn() -> Result<R, TraitError> + Send + Sync,
{
    /// 検出関数を受けて remover を作る（検出は初回の利用時まで走らない）。
    pub fn new(detect: F) -> Self {
        Self {
            detect,
            detected: std::sync::OnceLock::new(),
        }
    }

    fn get(&self) -> Result<&R, TraitError> {
        self.detected
            .get_or_init(|| (self.detect)())
            .as_ref()
            .map_err(Clone::clone)
    }
}

#[cfg(target_os = "linux")]
impl<R, F> ContainerCgroupRemover for DetectedCgroupRemover<R, F>
where
    R: ContainerCgroupRemover,
    F: Fn() -> Result<R, TraitError> + Send + Sync,
{
    fn scope(&self) -> Result<CgroupScope, TraitError> {
        self.get()?.scope()
    }

    fn remove(
        &self,
        id: &ContainerId,
        instance: StateRevision,
    ) -> Result<CgroupRemoval, TraitError> {
        self.get()?.remove(id, instance)
    }

    /// 既定実装に任せると残留 `exec-*` の掃除の観測値が記録されないため、内側へ明示的に転送する（REPAIR-4）。
    fn remove_with_recorder(
        &self,
        id: &ContainerId,
        instance: StateRevision,
        recorder: &OpRecorder,
    ) -> Result<CgroupRemoval, TraitError> {
        self.get()?.remove_with_recorder(id, instance, recorder)
    }

    /// 記録のスコープが検出したスコープと食い違うときの経路を内側へ転送する（#2096・#2060 案 B）。
    /// 検出の失敗はキャッシュしたエラーのまま返し、記録の経路へ回さない（fail-closed。#2133 で再検討し維持。
    /// 理由と回避策は CLI の `stop_delete` の module doc「未実装・簡易実装」）。
    fn remove_recorded(
        &self,
        id: &ContainerId,
        placement: &CgroupPlacement,
        recorder: &OpRecorder,
    ) -> Result<CgroupRemoval, TraitError> {
        self.get()?.remove_recorded(id, placement, recorder)
    }
}

/// 検出失敗のエラーを `code` だけ保って固定文言にする（パス・errno を出さない。ERR-2）。
#[cfg(target_os = "linux")]
pub fn detect_error(code: ErrorCode) -> TraitError {
    TraitError::new(code, "failed to detect the delegated cgroup")
}

/// 自プロセスの委譲 cgroup を検出する（所有者・`cgroup.type` の検証は core の `detect` が行う）。
#[cfg(target_os = "linux")]
pub fn detect_delegated_cgroup()
-> Result<fandhe_container_core::cgroups::DelegatedCgroup, TraitError> {
    fandhe_container_core::cgroups::DelegatedCgroup::detect().map_err(|e| detect_error(e.code))
}

/// 本番の cgroup remover。cfg の分岐をここに閉じ込める。
#[cfg(target_os = "linux")]
pub fn production_cgroup_remover() -> impl ContainerCgroupRemover {
    DetectedCgroupRemover::new(detect_delegated_cgroup)
}

/// 非 Linux では委譲 cgroup が無い（`production_runtime` が先に fail-closed になり通常は到達しない）。
#[cfg(not(target_os = "linux"))]
pub fn production_cgroup_remover() -> impl ContainerCgroupRemover {
    UnavailableCgroupRemover
}

/// 非 Linux の cgroup remover。委譲 cgroup が無いため常に `Unimplemented` で失敗する（REPAIR-3）。
///
/// `remove` も `NotPresent` を返さない（cgroup を残したまま記録だけ消す経路を作らない）。
#[cfg(not(target_os = "linux"))]
pub struct UnavailableCgroupRemover;

#[cfg(not(target_os = "linux"))]
impl ContainerCgroupRemover for UnavailableCgroupRemover {
    fn scope(&self) -> Result<CgroupScope, TraitError> {
        Err(unavailable_cgroup())
    }

    fn remove(
        &self,
        _id: &ContainerId,
        _instance: StateRevision,
    ) -> Result<CgroupRemoval, TraitError> {
        Err(unavailable_cgroup())
    }

    fn remove_recorded(
        &self,
        _id: &ContainerId,
        _placement: &CgroupPlacement,
        _recorder: &OpRecorder,
    ) -> Result<CgroupRemoval, TraitError> {
        Err(unavailable_cgroup())
    }
}

#[cfg(not(target_os = "linux"))]
fn unavailable_cgroup() -> TraitError {
    TraitError::new(
        ErrorCode::Unimplemented,
        "container cgroup removal is not available yet",
    )
}
