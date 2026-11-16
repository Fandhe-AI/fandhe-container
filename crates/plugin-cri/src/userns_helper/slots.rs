//! helper の同時実行の枠と、回収できなかった子の保持（`remover`・`extractor` の共通部。SEC-5・REPAIR-5。#4800・#4848）。
//!
//! 呼び出し元は削除器 `UsernsTreeRemover` と展開器 `UsernsLayerExtractor`。両者は別インスタンスで枠を持ち、長い展開が
//! 削除を詰まらせない。稼働中 + 回収できていない子の合計が上限に達したら待たずに断る（kubelet が再試行する）。
//! 回収できなかった子は保持し、次の枠取りの先頭で `try_wait` で掃く（`Child` を落として追えない zombie を作らない）。

use std::process::Child;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::launcher::{JOIN_BUDGET, WorkBudget};

/// 呼び出し側に期限が無いときの作業予算。
pub const DEFAULT_WORK_BUDGET: Duration = Duration::from_secs(120);

/// 呼び出し側の期限から helper の作業予算を作る（期限が無ければ既定。1〜600 秒に丸める）。
pub(super) fn work_budget_for(deadline: Option<Instant>) -> Option<WorkBudget> {
    let want = match deadline {
        Some(dl) => dl
            .saturating_duration_since(Instant::now())
            .saturating_sub(JOIN_BUDGET),
        None => DEFAULT_WORK_BUDGET,
    };
    WorkBudget::new(want.clamp(WorkBudget::MIN, WorkBudget::MAX)).ok()
}

/// 同時実行の枠。
pub(super) struct HelperSlots {
    pub(super) max: usize,
    pub(super) active: AtomicUsize,
    /// kill したが回収できなかった子（次の呼び出しで掃く）。
    pub(super) unreaped: Mutex<Vec<Child>>,
}

/// 稼働中の枠。drop で返す。
pub(super) struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl HelperSlots {
    pub(super) fn new(max: usize) -> Self {
        Self {
            max,
            active: AtomicUsize::new(0),
            unreaped: Mutex::new(Vec::new()),
        }
    }

    /// 回収できていなかった子のうち、終わったものを掃く。
    ///
    /// 回収できていない子は取得済みの枠を保持し続ける（`active` に含める）ため、掃けた分だけ枠を返す。
    fn sweep(&self) {
        let Ok(mut held) = self.unreaped.lock() else {
            return;
        };
        let before = held.len();
        held.retain_mut(|c| !matches!(c.try_wait(), Ok(Some(_)) | Err(_)));
        let freed = before - held.len();
        if freed > 0 {
            self.active.fetch_sub(freed, Ordering::AcqRel);
        }
    }

    /// 枠を取る。稼働中 + 回収できていない子が上限に達していれば `None`（待たない）。
    pub(super) fn acquire(&self) -> Option<Slot<'_>> {
        self.sweep();
        let mut cur = self.active.load(Ordering::Acquire);
        loop {
            if cur >= self.max {
                return None;
            }
            match self.active.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Slot(&self.active)),
                Err(seen) => cur = seen,
            }
        }
    }

    /// 回収できなかった子を保持する。枠は返さず子の回収まで持たせる（`sweep` が返す）。
    pub(super) fn keep(&self, child: Child, slot: Slot<'_>) {
        if let Ok(mut held) = self.unreaped.lock() {
            held.push(child);
            std::mem::forget(slot);
        }
    }
}
