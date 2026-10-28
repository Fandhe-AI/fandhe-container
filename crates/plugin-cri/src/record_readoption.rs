//! 起動時の記録の再採用の手順（R9 #2938。CRI-1・CRI-2・CORE-1・REPAIR-4・REPAIR-5。設計は
//! `docs/design/cri-record-readoption.md`）。
//!
//! 役割: `main.rs` の `serve` が受付の開始前に 1 回だけ呼ぶ 4 段（sandbox の再採用 → コンテナの再採用と core との照合 →
//! 作成途中の取り残しの解放 → 孤児 bundle の回収）をまとめ、結果を固定語彙の 1 行にする。手順を bin ではなく lib に置くのは、
//! インスタンスロックの型（`pub(crate)`）を bin から使えないことと、試験から呼べるようにするため。
//!
//! 排他: ロックを持たない backends（注入で組んだもの）は [`CriPluginBackends::readopt_records`] が
//! `FAILED_PRECONDITION` で拒否する。常駐ループは作らない（CORE-1）。
//!
//! 失敗の写し方（fail-closed）: sandbox・コンテナの再採用の `Err`（列挙の失敗・件数または保持量の上限超過・期限切れ）は
//! そのまま返し、呼び出し側が起動を止める（registry は空のまま）。壊れた記録は消さず登録もせず件数に数えるだけで、
//! 起動は止めない。孤児 bundle の回収は件数のみを返し、起動を止めない。
//!
//! 予算（REPAIR-5）: 4 段で全体の残りを分け合い、各段に渡す 1 件の期限は残りを超えない。

use std::sync::Arc;
use std::time::Instant;

use fandhe_container_cri::adapter::RuntimeAdapter;
use fandhe_container_cri::bundle::SpecBundleProvider;
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime_service::{
    ContainerReadoption, CriRuntimeService, ListBudget, RecordStore, SandboxReadoption,
    StaleCreateRelease,
};

use crate::adapter::CriPluginBackends;
use crate::instance_lock::InstanceLock;
use crate::orphan_bundles::{OrphanBundleReclamation, OrphanScan, reclaim_orphan_bundles};

/// 4 段の結果（件数のみ。ID・パス・config は持たない。REPAIR-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StartupReadoption {
    /// sandbox の再採用。
    pub sandboxes: SandboxReadoption,
    /// コンテナの再採用と core の状態との照合。
    pub containers: ContainerReadoption,
    /// 作成途中の取り残しの解放。
    pub stale: StaleCreateRelease,
    /// 孤児 bundle の回収。
    pub orphans: OrphanBundleReclamation,
}

impl StartupReadoption {
    /// 4 段とも何も無かった（初回起動・空の置き場）か。真なら要約行は出さない（起動の stderr を静かに保つ）。
    pub fn is_empty(&self) -> bool {
        let o = &self.orphans;
        self.sandboxes == SandboxReadoption::default()
            && self.containers == ContainerReadoption::default()
            && self.stale == StaleCreateRelease::default()
            && o.scan == OrphanScan::Completed
            && o.scanned == 0
            && o.reclaimed == 0
            && o.kept_has_record == 0
            && o.kept_present == 0
            && o.kept_undetermined == 0
            && o.release_failed == 0
            && o.release_timed_out == 0
            && o.skipped_unrecognized == 0
            && o.skipped_not_dir == 0
            && o.not_attempted == 0
    }

    /// 固定語彙の 1 行要約（4 段の要約を ` | ` でつなぐ。ID・パス・config を含めない）。
    pub fn summary_line(&self) -> String {
        format!(
            "{} | {} | {} | {}",
            self.sandboxes.summary_line(),
            self.containers.summary_line(),
            self.stale.summary_line(),
            self.orphans.summary_line(),
        )
    }
}

/// 全体の期限から残りを引き、各段に渡す予算を作る。
fn stage_budget(budget: ListBudget, start: Instant) -> ListBudget {
    let remaining = budget.total.saturating_sub(start.elapsed());
    ListBudget {
        per_record: budget.per_record.min(remaining),
        total: remaining,
    }
}

/// 4 段を順に実行する。`lock` はインスタンスロックの保持の証明。
///
/// 順序は固定: 解放に失敗した `stale_create` の記録が残る間はその bundle が孤児扱いにならないため、孤児回収を最後に置く。
/// `svc` には記録ストアと実行層が注入済みであること（未注入の段は件数 0 を返す）。
pub fn run_startup_readoption(
    svc: &CriRuntimeService,
    lock: &Arc<InstanceLock>,
    bundles: &Arc<SpecBundleProvider>,
    records: &dyn RecordStore,
    runtime: &RuntimeAdapter,
    budget: ListBudget,
) -> Result<StartupReadoption, CriError> {
    let start = Instant::now();
    let sandboxes = svc.readopt_sandboxes(stage_budget(budget, start))?;
    let containers = svc.readopt_containers(stage_budget(budget, start))?;
    let stale = svc.release_stale_creates(&containers, stage_budget(budget, start))?;
    let orphans =
        reclaim_orphan_bundles(lock, bundles, records, runtime, stage_budget(budget, start));
    Ok(StartupReadoption {
        sandboxes,
        containers,
        stale,
        orphans,
    })
}

impl CriPluginBackends {
    /// 起動時の記録の再採用を行う（R9 #2938。`production()` で組んだときだけ）。
    ///
    /// インスタンスロックを持たない backends（注入で組んだもの）は何も触らず `FAILED_PRECONDITION`（固定文言）。
    /// `serve` が受付の開始前に 1 回だけ呼ぶ。`Err` のときは起動を止める。
    pub fn readopt_records(
        &self,
        svc: &CriRuntimeService,
        bundles: &Arc<SpecBundleProvider>,
        records: &dyn RecordStore,
        budget: ListBudget,
    ) -> Result<StartupReadoption, CriError> {
        let Some(lock) = self.instance_lock() else {
            return Err(CriError::failed_precondition("instance lock is not held"));
        };
        let runtime = RuntimeAdapter::new(Arc::clone(self.runtime()));
        run_startup_readoption(svc, lock, bundles, records, &runtime, budget)
    }
}
