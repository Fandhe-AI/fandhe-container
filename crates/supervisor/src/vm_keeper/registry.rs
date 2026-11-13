//! VM 保持役の登録簿（コンテナの参照数）と、参照数 0 の猶予タイマの状態機械（MAC-4・CORE-1）。
//!
//! 純粋なデータ構造で、時刻は呼び出し側が `Instant` で渡す（時計を注入して試験できる）。`vm_keeper::server` が
//! 要求ごとに [`Registry::register`] / [`Registry::unregister`] を呼び、受付ループの各周回で
//! [`Registry::should_exit`] を確かめる。
//!
//! 猶予は「参照数が 0 になった時点（起動直後を含む）から `grace` 経過」で、その間に登録が来れば取り消す。
//! 終了を決めた後（[`Registry::should_exit`] が真を返した後）は新規の登録を受けない（`ShuttingDown`）。
//! 上限 [`MAX_CONTAINERS`] は長さ・件数の上限検証（無制限確保の防止）のための防御値で、超過時の正式な応答と
//! 試験は #2279 が担う。

use std::collections::HashSet;
use std::time::{Duration, Instant};

use fandhe_container_core::traits::ContainerId;

/// 1 VM あたりのコンテナ数の上限（#1906 で承認済みの 64）。
pub const MAX_CONTAINERS: usize = 64;

/// 要求を適用できなかった理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// 同じ ID が登録済み。
    AlreadyRegistered,
    /// 未登録の ID の解除。
    NotRegistered,
    /// 上限に達している。
    CapacityExceeded,
    /// 終了を決定済み。
    ShuttingDown,
}

/// コンテナ ID の登録簿と猶予タイマ。
#[derive(Debug)]
pub struct Registry {
    ids: HashSet<ContainerId>,
    grace: Duration,
    /// 参照数が 0 になった時刻。参照数が 1 以上なら `None`。
    idle_since: Option<Instant>,
    shutting_down: bool,
}

impl Registry {
    /// 空の登録簿を作る。`start` から猶予が数え始まる（誰も登録しない保持役は猶予後に終わる）。
    pub fn new(grace: Duration, start: Instant) -> Self {
        Self {
            ids: HashSet::new(),
            grace,
            idle_since: Some(start),
            shutting_down: false,
        }
    }

    /// 現在の参照数。
    pub fn refcount(&self) -> usize {
        self.ids.len()
    }

    /// 登録する。成功すると猶予を取り消す。
    pub fn register(&mut self, id: ContainerId) -> Result<(), Reject> {
        if self.shutting_down {
            return Err(Reject::ShuttingDown);
        }
        if self.ids.contains(&id) {
            return Err(Reject::AlreadyRegistered);
        }
        if self.ids.len() >= MAX_CONTAINERS {
            return Err(Reject::CapacityExceeded);
        }
        self.ids.insert(id);
        self.idle_since = None;
        Ok(())
    }

    /// 登録を外す。参照数が 0 になったら `now` から猶予を数える。
    pub fn unregister(&mut self, id: &ContainerId, now: Instant) -> Result<(), Reject> {
        if !self.ids.remove(id) {
            return Err(Reject::NotRegistered);
        }
        if self.ids.is_empty() {
            self.idle_since = Some(now);
        }
        Ok(())
    }

    /// 参照数 0 のまま猶予を過ぎていれば終了を決定して真を返す（以後の登録は `ShuttingDown`）。
    pub fn should_exit(&mut self, now: Instant) -> bool {
        if self.shutting_down {
            return true;
        }
        if let Some(since) = self.idle_since
            && now.saturating_duration_since(since) >= self.grace
        {
            self.shutting_down = true;
        }
        self.shutting_down
    }

    /// 猶予の残り。参照数が 1 以上なら `None`、猶予を過ぎていれば `Some(ZERO)`。
    pub fn remaining_grace(&self, now: Instant) -> Option<Duration> {
        self.idle_since.map(|since| {
            self.grace
                .saturating_sub(now.saturating_duration_since(since))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> ContainerId {
        ContainerId::new(s).expect("valid id")
    }

    const GRACE: Duration = Duration::from_secs(30);

    #[test]
    fn mac4_register_cancels_grace_and_counts() {
        let t0 = Instant::now();
        let mut r = Registry::new(GRACE, t0);
        assert_eq!(r.refcount(), 0);
        assert_eq!(r.remaining_grace(t0), Some(GRACE));
        r.register(id("a")).expect("register");
        assert_eq!(r.refcount(), 1);
        assert_eq!(r.remaining_grace(t0), None);
        // 参照数 1 の間は何秒経っても終了しない。
        assert!(!r.should_exit(t0 + Duration::from_secs(3600)));
    }

    #[test]
    fn mac4_unregister_to_zero_starts_grace_and_expires() {
        let t0 = Instant::now();
        let mut r = Registry::new(GRACE, t0);
        r.register(id("a")).expect("register");
        let t1 = t0 + Duration::from_secs(100);
        r.unregister(&id("a"), t1).expect("unregister");
        assert_eq!(r.refcount(), 0);
        assert_eq!(r.remaining_grace(t1), Some(GRACE));
        assert!(!r.should_exit(t1 + Duration::from_secs(29)));
        assert_eq!(
            r.remaining_grace(t1 + Duration::from_secs(29)),
            Some(Duration::from_secs(1))
        );
        assert!(r.should_exit(t1 + GRACE));
    }

    #[test]
    fn mac4_register_within_grace_prevents_exit() {
        let t0 = Instant::now();
        let mut r = Registry::new(GRACE, t0);
        r.register(id("a")).expect("register");
        let t1 = t0 + Duration::from_secs(1);
        r.unregister(&id("a"), t1).expect("unregister");
        r.register(id("b")).expect("re-register within grace");
        assert!(!r.should_exit(t1 + Duration::from_secs(60)));
    }

    #[test]
    fn mac4_initial_idle_keeper_exits_after_grace() {
        let t0 = Instant::now();
        let mut r = Registry::new(GRACE, t0);
        assert!(!r.should_exit(t0 + Duration::from_secs(29)));
        assert!(r.should_exit(t0 + GRACE));
    }

    #[test]
    fn mac4_rejects_duplicate_unknown_and_after_shutdown() {
        let t0 = Instant::now();
        let mut r = Registry::new(GRACE, t0);
        r.register(id("a")).expect("register");
        assert_eq!(r.register(id("a")), Err(Reject::AlreadyRegistered));
        assert_eq!(r.unregister(&id("zzz"), t0), Err(Reject::NotRegistered));
        r.unregister(&id("a"), t0).expect("unregister");
        assert!(r.should_exit(t0 + GRACE));
        assert_eq!(r.register(id("b")), Err(Reject::ShuttingDown));
        assert!(r.should_exit(t0));
    }

    #[test]
    fn mac4_capacity_is_bounded_at_64() {
        let t0 = Instant::now();
        let mut r = Registry::new(GRACE, t0);
        for i in 0..MAX_CONTAINERS {
            r.register(id(&format!("c{i}"))).expect("within capacity");
        }
        assert_eq!(r.refcount(), 64);
        assert_eq!(r.register(id("over")), Err(Reject::CapacityExceeded));
        assert_eq!(r.refcount(), 64);
    }
}
