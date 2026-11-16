//! 範囲写像で展開した subuid 所有の木を、再 exec helper の削除モードで消す本番の削除器（Linux x86_64 / aarch64。
//! SEC-5・OCI-7・CORE-6・REPAIR-4・REPAIR-5。#4800。親 issue #4777 の H3）。
//!
//! `fandhe-container-cri` の注入点 [`SubordinateTreeRemover`] の本番実装 [`UsernsTreeRemover`]。呼び出し元は cri の
//! `ImageRootfsSource`（`release_bounded`・展開失敗時の後始末）と `OciImagePuller`（pull の `unpack/` の後始末）で、
//! 展開設定が `ChownInUserNamespace` のときだけ呼ばれる（対応表の切り替えは H6・#4801。それまで本番では通らない）。
//! CRI の worker スレッド・pull の blocking 区間から同期で呼ばれ、helper（[`UsernsHelperLauncher`]）を 1 回起動して
//! [`Mode::Remove`] を実行させる。親ディレクトリは fd で渡し（パスは渡さない）、消す子の名前は [`RemovalTarget`] から
//! 固定の 2 種に限る。
//!
//! # 契約
//! - 縮退しない: 失敗・期限切れはホスト側の削除へ落とさず、固定文言の [`CriError`]（パス・errno・uid を含めない。REPAIR-4）
//! - 期限（REPAIR-5）: [`ReleaseBudget`] の期限があれば残り時間から [`JOIN_BUDGET`] を引いて作業予算にする（1〜600 秒に丸める）。
//!   期限が無ければ [`DEFAULT_WORK_BUDGET`]。開始前に期限切れ・取り消しなら起動しない。取り消しの旗は helper の実行中には
//!   見られず、全体の待ちは呼び出し側の期限を最大 [`JOIN_BUDGET`] 超えうる（残余）
//! - 同時実行の上限: 稼働中 + 回収できていない子の合計が [`MAX_CONCURRENT_REMOVALS`] 以上なら待たずに `UNAVAILABLE`
//!   （kubelet が再試行する。launcher の「上限は呼び出し側」の契約）
//! - 回収できなかった子は保持し、次の呼び出しの先頭で `try_wait` で掃く（`Child` を落として追えない zombie を作らない）
//! - 冪等: 削除は不在を成功とし、途中で kill されても再実行が続きから消す

use std::os::fd::BorrowedFd;
use std::process::Child;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::ErrorCode;
use fandhe_container_cri::adapter::ReleaseBudget;
use fandhe_container_cri::bundle::{RemovalTarget, SubordinateTreeRemover};
use fandhe_container_cri::error::CriError;

use super::launcher::{JOIN_BUDGET, UsernsHelperError, UsernsHelperLauncher, WorkBudget};
use super::wire::{Mode, RemoveTarget, Report};

/// 同時に動かす削除の上限（稼働中の helper + 回収できていない子の合計）。
pub const MAX_CONCURRENT_REMOVALS: usize = 4;
/// 呼び出し側に期限が無いときの作業予算。
pub const DEFAULT_WORK_BUDGET: Duration = Duration::from_secs(120);

/// 本番の削除器。プロセスで 1 つ（[`UsernsTreeRemover::shared`]）を pull 側と create 側が共有し、上限を 1 つにする。
pub struct UsernsTreeRemover {
    launcher: UsernsHelperLauncher,
    max: usize,
    active: AtomicUsize,
    /// kill したが回収できなかった子（次の呼び出しで掃く）。
    unreaped: Mutex<Vec<Child>>,
}

impl std::fmt::Debug for UsernsTreeRemover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsernsTreeRemover")
            .field("max", &self.max)
            .field("active", &self.active.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// 稼働中の枠。drop で返す。
struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl UsernsTreeRemover {
    /// plugin-cri 自身を helper として再 exec する削除器。
    pub fn new() -> Self {
        Self::with_launcher_and_limit(UsernsHelperLauncher::new(), MAX_CONCURRENT_REMOVALS)
    }

    /// プロセス共有の削除器（pull 側・create 側で同じ上限を使う）。
    pub fn shared() -> Arc<Self> {
        static SHARED: OnceLock<Arc<UsernsTreeRemover>> = OnceLock::new();
        Arc::clone(SHARED.get_or_init(|| Arc::new(Self::new())))
    }

    /// 起動役と上限を差し替える（試験専用の偽 helper・上限の試験）。
    #[cfg(any(test, feature = "userns-helper-test-support"))]
    pub fn with_launcher_and_limit(launcher: UsernsHelperLauncher, max: usize) -> Self {
        Self::build(launcher, max)
    }

    #[cfg(not(any(test, feature = "userns-helper-test-support")))]
    fn with_launcher_and_limit(launcher: UsernsHelperLauncher, max: usize) -> Self {
        Self::build(launcher, max)
    }

    fn build(launcher: UsernsHelperLauncher, max: usize) -> Self {
        Self {
            launcher,
            max,
            active: AtomicUsize::new(0),
            unreaped: Mutex::new(Vec::new()),
        }
    }

    /// 回収できていなかった子のうち、終わったものを掃く。残りの数を返す。
    fn sweep(&self) -> usize {
        let Ok(mut held) = self.unreaped.lock() else {
            return self.max;
        };
        held.retain_mut(|c| !matches!(c.try_wait(), Ok(Some(_)) | Err(_)));
        held.len()
    }

    /// 枠を取る。稼働中 + 回収できていない子が上限に達していれば `None`（待たない）。
    fn acquire(&self) -> Option<Slot<'_>> {
        let stuck = self.sweep();
        let mut cur = self.active.load(Ordering::Acquire);
        loop {
            if cur.saturating_add(stuck) >= self.max {
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

    fn keep(&self, child: Child) {
        if let Ok(mut held) = self.unreaped.lock() {
            held.push(child);
        }
    }
}

impl Default for UsernsTreeRemover {
    fn default() -> Self {
        Self::new()
    }
}

/// 呼び出し側の期限から helper の作業予算を作る（期限が無ければ既定。1〜600 秒に丸める）。
fn work_budget(budget: &ReleaseBudget<'_>) -> Result<WorkBudget, CriError> {
    let want = match budget.deadline {
        Some(dl) => dl
            .saturating_duration_since(Instant::now())
            .saturating_sub(JOIN_BUDGET),
        None => DEFAULT_WORK_BUDGET,
    };
    WorkBudget::new(want.clamp(WorkBudget::MIN, WorkBudget::MAX))
        .map_err(|_| CriError::internal("failed to compute the removal budget"))
}

fn wire_target(t: RemovalTarget) -> Result<RemoveTarget, CriError> {
    match t {
        RemovalTarget::BundleRootfs => Ok(RemoveTarget::BundleRootfs),
        RemovalTarget::PullUnpack => Ok(RemoveTarget::PullUnpack),
        // `RemovalTarget` は non_exhaustive。足した対象を黙って別の木へ写さず、helper を起動せず拒否する。
        _ => Err(CriError::failed_precondition(
            "subordinate-owned tree removal target is not supported",
        )),
    }
}

/// helper の失敗を固定文言の `CriError` へ写す（code は保つ。パス・errno・uid を含めない）。
fn map_error(e: &UsernsHelperError) -> CriError {
    match e.code() {
        ErrorCode::Timeout => {
            CriError::timeout("subordinate-owned tree removal exceeded its deadline")
        }
        ErrorCode::FailedPrecondition => {
            CriError::failed_precondition("subordinate-owned tree removal was refused")
        }
        ErrorCode::Unavailable => CriError::unavailable("userns helper is unavailable"),
        _ => CriError::internal("subordinate-owned tree removal failed"),
    }
}

impl SubordinateTreeRemover for UsernsTreeRemover {
    fn remove_child_tree(
        &self,
        parent: BorrowedFd<'_>,
        target: RemovalTarget,
        budget: &ReleaseBudget<'_>,
    ) -> Result<(), CriError> {
        // 期限切れ・取り消しなら起動しない（副作用なし）。
        budget.check()?;
        let wire = wire_target(target)?;
        let work = work_budget(budget)?;
        let _slot = self.acquire().ok_or_else(|| {
            CriError::unavailable("too many subordinate-owned tree removals in progress")
        })?;
        match self.launcher.run(Mode::Remove(wire), parent, work) {
            Ok(Report::Removed) => Ok(()),
            Ok(_) => Err(CriError::internal(
                "userns helper returned an unexpected report",
            )),
            Err(mut e) => {
                if let Some(child) = e.take_unreaped() {
                    self.keep(child);
                }
                Err(map_error(&e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::AsFd as _;

    use fandhe_container_cri::error::CriErrorCode;

    use super::*;

    fn sleeper(max: usize) -> UsernsTreeRemover {
        UsernsTreeRemover::with_launcher_and_limit(
            UsernsHelperLauncher::with_fixed_command("/bin/sleep", vec!["60".into()])
                .with_join_budget(Duration::ZERO),
            max,
        )
    }

    /// REPAIR-5・SEC-5・#4800: 応答しない helper は期限で `Timeout` になり、子は回収されて保持一覧が空・枠が戻る。
    #[test]
    fn sec5_4800_remover_timeout_reaps_the_child_and_releases_the_slot() {
        let rm = sleeper(MAX_CONCURRENT_REMOVALS);
        let dir = File::open("/").expect("open /");
        let started = Instant::now();
        let e = rm
            .remove_child_tree(
                dir.as_fd(),
                RemovalTarget::BundleRootfs,
                &ReleaseBudget::new()
                    .with_deadline(Instant::now() + JOIN_BUDGET + Duration::from_secs(1)),
            )
            .expect_err("must time out");
        assert_eq!(e.code(), CriErrorCode::Timeout);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "took {:?}",
            started.elapsed()
        );
        assert_eq!(rm.unreaped.lock().unwrap().len(), 0, "child must be reaped");
        assert_eq!(rm.active.load(Ordering::Acquire), 0);
    }

    /// REPAIR-5・#4800: 上限（稼働中 + 回収できていない子）に達していれば待たずに `UNAVAILABLE`。
    #[test]
    fn sec5_4800_remover_over_the_limit_is_unavailable() {
        let rm = sleeper(2);
        rm.active.fetch_add(2, Ordering::AcqRel);
        let dir = File::open("/").expect("open /");
        let started = Instant::now();
        let e = rm
            .remove_child_tree(
                dir.as_fd(),
                RemovalTarget::PullUnpack,
                &ReleaseBudget::new(),
            )
            .expect_err("over the limit");
        assert_eq!(e.code(), CriErrorCode::Unavailable);
        assert!(started.elapsed() < Duration::from_secs(1));
        // 上限で拒否しても、取っていない枠を返さない。
        assert_eq!(rm.active.load(Ordering::Acquire), 2);
    }

    /// REPAIR-5・#4800: 期限切れの予算では helper を起動せず `Timeout`（副作用なし）。
    #[test]
    fn sec5_4800_remover_expired_budget_does_not_spawn() {
        let rm = UsernsTreeRemover::with_launcher_and_limit(
            UsernsHelperLauncher::with_fixed_command("/nonexistent/helper", vec![]),
            MAX_CONCURRENT_REMOVALS,
        );
        let dir = File::open("/").expect("open /");
        let past = Instant::now();
        let e = rm
            .remove_child_tree(
                dir.as_fd(),
                RemovalTarget::BundleRootfs,
                &ReleaseBudget::new().with_deadline(past),
            )
            .expect_err("expired");
        assert_eq!(e.code(), CriErrorCode::Timeout);
    }

    /// REPAIR-5・#4800: 作業予算は呼び出し側の残り時間から参加の見込みを引き、1〜600 秒に丸める。
    #[test]
    fn sec5_4800_work_budget_is_derived_from_the_deadline() {
        let none = work_budget(&ReleaseBudget::new()).expect("default");
        assert_eq!(none.get(), DEFAULT_WORK_BUDGET);
        let soon = work_budget(&ReleaseBudget::new().with_deadline(Instant::now())).expect("floor");
        assert_eq!(soon.get(), WorkBudget::MIN);
        let far = work_budget(
            &ReleaseBudget::new().with_deadline(Instant::now() + Duration::from_secs(10_000)),
        )
        .expect("cap");
        assert_eq!(far.get(), WorkBudget::MAX);
    }
}
