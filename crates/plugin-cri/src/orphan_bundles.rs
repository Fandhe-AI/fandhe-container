//! 孤児 bundle の回収（R8 #2937。OCI-7・CRI-1・SEC-1・REPAIR-3/4/5。設計は `docs/design/cri-record-readoption.md`）。
//!
//! 役割: plugin-cri の再起動をまたいで `<状態ルート>/.cri/bundles/<id>` だけが残ったもの（CRI の記録ファイルが無く、
//! core にもコンテナが無い）を消す（containerd の `cleanupOrphanedIDDirs` に相当）。`CreateContainer` の write-ahead
//! 記録より前に bundle を作る経路や、記録の削除後・bundle の解放前のクラッシュで生じる。
//!
//! 呼び出し元: 本番の `serve` が受付の開始前に 1 回だけ呼ぶ（配線は R9 #2938。常駐ループは作らない。CORE-1）。
//! 順序は `readopt_sandboxes` → `readopt_containers` → `release_stale_creates` → 本関数。解放に失敗した `stale_create`
//! の記録が残っている間は、その bundle が「記録あり」として孤児扱いにならないため、この順が要る。
//!
//! 排他: `Arc<InstanceLock>` を引数に取り、期限切れの解放 worker にも複製を持たせる。値は取得関数以外から作れないため、ロックを持たない経路では型として呼べない。
//! `CriPluginBackends::reclaim_orphan_bundles` はロックを持たない backends（注入で組んだもの）に
//! `FAILED_PRECONDITION` を返す。残余: 照会から解放までの窓は、受付の開始前・インスタンスロックの下・状態ルートを共有する
//! CLI は `.cri/bundles` を使わない、の 3 点で許容する。
//!
//! 回収の条件（すべて満たしたものだけ。fail-closed）:
//! 1. 名前がサービス採番の形（64 文字の小文字 16 進）のディレクトリ（symlink・通常ファイルは辿らず触らない）。
//! 2. 同じ ID のコンテナ記録ファイルが無い。読めない・壊れた記録も「所有の証明」として残す（手動回収は R10 #2939）。
//!    記録の列挙に失敗したら何も回収しない。
//! 3. core の照会が `NOT_FOUND` だけ。Present と Undetermined は残す。
//!
//! 期限（REPAIR-5）: bundle の列挙・1 件の照会・1 件の解放は期限つきで、全体の期限を超えたら残りを試みない。
//! 期限切れの解放以降は打ち切る。結果は件数のみ（REPAIR-4。ID・パスを含まない）。

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fandhe_container_cri::adapter::{BundleProvider as _, RuntimeAdapter};
use fandhe_container_cri::bundle::{BundleListing, SpecBundleProvider};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime_service::{
    CorePresence, ListBudget, ListLimits, MAX_CONTAINERS, RecordKind, RecordStore,
    probe_core_presence,
};

use crate::adapter::CriPluginBackends;
use crate::instance_lock::InstanceLock;

/// 走査するエントリ数の上限（記録ストアと同じ式。無制限確保の防止）。
const MAX_SCANNED_ENTRIES: usize = MAX_CONTAINERS * 2 + 64;

/// 列挙の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OrphanScan {
    /// 候補の作成まで完了した。
    Completed,
    /// bundle または記録の列挙に失敗した（何も回収していない）。
    ListFailed(&'static str),
    /// bundle の列挙が期限を超えた（何も回収していない）。
    TimedOut,
}

/// [`reclaim_orphan_bundles`] の結果（件数のみ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OrphanBundleReclamation {
    /// 採番の形のディレクトリの数。
    pub scanned: usize,
    /// 解放（削除）した数。
    pub reclaimed: usize,
    /// 記録ファイルがあるため残した数（壊れた記録を含む）。
    pub kept_has_record: usize,
    /// core にコンテナがあるため残した数。
    pub kept_present: usize,
    /// core の状態を確定できず残した数。
    pub kept_undetermined: usize,
    /// 解放に失敗した数。
    pub release_failed: usize,
    /// 解放が期限を超えた数（以後は打ち切る）。
    pub release_timed_out: usize,
    /// 採番の形でない名前の数（触らない）。
    pub skipped_unrecognized: usize,
    /// 採番の形だがディレクトリでないものの数（触らない）。
    pub skipped_not_dir: usize,
    /// 全体の期限・打ち切りで試みなかった数。
    pub not_attempted: usize,
    /// 列挙の結果。
    pub scan: OrphanScan,
}

impl OrphanBundleReclamation {
    fn empty(scan: OrphanScan) -> Self {
        Self {
            scanned: 0,
            reclaimed: 0,
            kept_has_record: 0,
            kept_present: 0,
            kept_undetermined: 0,
            release_failed: 0,
            release_timed_out: 0,
            skipped_unrecognized: 0,
            skipped_not_dir: 0,
            not_attempted: 0,
            scan,
        }
    }

    /// 固定語彙の 1 行要約（ID・パスを含めない）。stderr への出力は R9 #2938 が行う。
    pub fn summary_line(&self) -> String {
        let scan = match self.scan {
            OrphanScan::Completed => "completed".to_owned(),
            OrphanScan::ListFailed(code) => format!("list_failed:{code}"),
            OrphanScan::TimedOut => "timed_out".to_owned(),
        };
        format!(
            "cri orphan bundle reclamation: scan={} scanned={} reclaimed={} kept_has_record={} kept_present={} kept_undetermined={} release_failed={} release_timed_out={} skipped_unrecognized={} skipped_not_dir={} not_attempted={}",
            scan,
            self.scanned,
            self.reclaimed,
            self.kept_has_record,
            self.kept_present,
            self.kept_undetermined,
            self.release_failed,
            self.release_timed_out,
            self.skipped_unrecognized,
            self.skipped_not_dir,
            self.not_attempted,
        )
    }
}

/// 同期呼び出しを切り離したスレッドで走らせ、期限までに終わらなければ `None`（REPAIR-5）。
fn with_deadline<T, F>(timeout: Duration, f: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("cri-orphan-bundle".into())
        .spawn(move || {
            let _ = tx.send(f());
        })
        .ok()?;
    rx.recv_timeout(timeout).ok()
}

/// 孤児 bundle を回収する。`lock` はインスタンスロックの保持の証明（呼び出し側が持っている間だけ呼べる）。
///
/// 期限切れで切り離した解放 worker は `lock` の複製を持ち、解放が終わるまでロックを手放さない
/// （復帰後に呼び出し側が先にロックを落としても、別インスタンスは削除中の bundle と競合しない。REPAIR-1・SEC-1）。
///
/// 起動を止めない（失敗・期限切れは件数に数えて余分に残す側へ倒す）。モジュール doc の条件を参照。
pub fn reclaim_orphan_bundles(
    lock: &Arc<InstanceLock>,
    bundles: &Arc<SpecBundleProvider>,
    records: &dyn RecordStore,
    runtime: &RuntimeAdapter,
    budget: ListBudget,
) -> OrphanBundleReclamation {
    let start = Instant::now();
    // 1. 候補（採番の形のディレクトリ）。
    let listing = {
        let b = Arc::clone(bundles);
        match with_deadline(budget.per_record.min(budget.total), move || {
            b.list_bundle_ids(MAX_SCANNED_ENTRIES)
        }) {
            Some(Ok(l)) => l,
            Some(Err(e)) => {
                return OrphanBundleReclamation::empty(OrphanScan::ListFailed(e.code().as_str()));
            }
            None => return OrphanBundleReclamation::empty(OrphanScan::TimedOut),
        }
    };
    let BundleListing {
        ids,
        skipped_unrecognized,
        skipped_not_dir,
        ..
    } = listing;
    let mut result = OrphanBundleReclamation::empty(OrphanScan::Completed);
    result.scanned = ids.len();
    result.skipped_unrecognized = skipped_unrecognized;
    result.skipped_not_dir = skipped_not_dir;
    if ids.is_empty() {
        return result;
    }

    // 2. 記録ファイルのある ID（読めたかどうかを問わず所有の証明として扱う）。列挙の失敗は何も回収しない。
    // 候補の列挙に使った時間を引いた残りだけを渡す。尽きていれば何も始めない（REPAIR-5）。
    let list_remaining = budget.total.saturating_sub(start.elapsed());
    if list_remaining.is_zero() {
        result.scan = OrphanScan::TimedOut;
        result.not_attempted = ids.len();
        return result;
    }
    let list_budget = ListBudget {
        per_record: budget.per_record.min(list_remaining),
        total: list_remaining,
    };
    let limits = ListLimits::for_kind(RecordKind::Container)
        .with_max_records(RecordKind::Container, MAX_CONTAINERS);
    let with_record: HashSet<String> =
        match records.list(RecordKind::Container, list_budget, limits) {
            Ok(l) => l
                .records
                .into_iter()
                .map(|r| r.id.as_str().to_owned())
                .collect(),
            Err(e) => {
                result.scan = OrphanScan::ListFailed(e.code().as_str());
                return result;
            }
        };

    // 3. 記録の無い ID だけ core を照会し、`NOT_FOUND` のときだけ解放する。
    for (index, id) in ids.iter().enumerate() {
        if with_record.contains(id) {
            result.kept_has_record += 1;
            continue;
        }
        let remaining = budget.total.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            result.not_attempted = count_without_record(&ids[index..], &with_record);
            result.kept_has_record += ids.len() - index - result.not_attempted;
            break;
        }
        match probe_core_presence(runtime, id, budget.per_record.min(remaining)) {
            CorePresence::Absent => {}
            CorePresence::Present(_) => {
                result.kept_present += 1;
                continue;
            }
            _ => {
                result.kept_undetermined += 1;
                continue;
            }
        }
        let remaining = budget.total.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            result.not_attempted = count_without_record(&ids[index..], &with_record);
            result.kept_has_record += ids.len() - index - result.not_attempted;
            break;
        }
        let per = budget.per_record.min(remaining);
        let b = Arc::clone(bundles);
        let release_id = id.clone();
        let held = Arc::clone(lock);
        match with_deadline(per, move || {
            let r = b.release(&release_id);
            // 解放が終わるまでインスタンスロックを保持する。
            drop(held);
            r
        }) {
            Some(Ok(())) => result.reclaimed += 1,
            Some(Err(_)) => result.release_failed += 1,
            None => {
                // 切り離したスレッドは lock を持ったまま解放を続ける（消えるか残るかのどちらか）。以後は打ち切る。
                result.release_timed_out += 1;
                result.not_attempted = count_without_record(&ids[index + 1..], &with_record);
                result.kept_has_record += ids.len() - index - 1 - result.not_attempted;
                break;
            }
        }
    }
    result
}

/// 打ち切りで試みなかった数（記録ありとして既に数える分は除く）。
fn count_without_record(rest: &[String], with_record: &HashSet<String>) -> usize {
    rest.iter().filter(|id| !with_record.contains(*id)).count()
}

impl CriPluginBackends {
    /// 孤児 bundle を回収する（R8 #2937。`production()` で組んだときだけ）。
    ///
    /// インスタンスロックを持たない backends（注入で組んだもの）は何も触らず `FAILED_PRECONDITION`（固定文言）。
    /// 受付の開始前に 1 回だけ呼ぶ。条件と順序はモジュール doc。
    pub fn reclaim_orphan_bundles(
        &self,
        bundles: &Arc<SpecBundleProvider>,
        records: &dyn RecordStore,
        budget: ListBudget,
    ) -> Result<OrphanBundleReclamation, CriError> {
        let Some(lock) = self.instance_lock() else {
            return Err(CriError::failed_precondition("instance lock is not held"));
        };
        let runtime = RuntimeAdapter::new(Arc::clone(self.runtime()));
        Ok(reclaim_orphan_bundles(
            lock, bundles, records, &runtime, budget,
        ))
    }
}
