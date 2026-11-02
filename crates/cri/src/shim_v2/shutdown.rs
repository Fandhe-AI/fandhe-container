//! Shutdown RPC からデーモンの寿命管理へ終了要求を渡すシグナル（CRI-5・TASK-62.7.2・REPAIR-5・MS-7）。
//!
//! [`TaskService`](super::task_service::TaskService) / [`EmptyTaskService`](super::service::EmptyTaskService) の
//! `Shutdown` ハンドラが [`ShutdownSignal::request`] を呼び、`bootstrap` のデーモン（`run_serve`）が
//! [`ShutdownSignal::wait_timeout`] で待って `ServerHandle::shutdown` へ進む。ハンドラからサーバーを直接
//! 止めないのは、停止フラグが Shutdown 自身の応答の書き込みを打ち切るため。
//! 要求は冪等で、一度立てたら下ろさない。待ちは必ず期限つき（無期限には待たない）。

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// 終了要求の共有フラグ。`Clone` は同じ要求を共有する。
#[derive(Clone, Debug, Default)]
pub struct ShutdownSignal {
    inner: Arc<(Mutex<bool>, Condvar)>,
}

impl ShutdownSignal {
    /// 未要求の状態で作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// 終了を要求する（冪等）。待っているスレッドを起こす。
    pub fn request(&self) {
        let (lock, cv) = &*self.inner;
        *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
        cv.notify_all();
    }

    /// 要求済みか。
    pub fn is_requested(&self) -> bool {
        *self.inner.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// 要求されるか `timeout` が過ぎるまで待ち、要求済みかを返す。
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let (lock, cv) = &*self.inner;
        let guard = lock.lock().unwrap_or_else(|p| p.into_inner());
        let (guard, _) = cv
            .wait_timeout_while(guard, timeout, |requested| !*requested)
            .unwrap_or_else(|p| p.into_inner());
        *guard
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// CRI-5・TASK-62.7.2: 要求は冪等で、clone 間で共有される。
    #[test]
    fn cri5_873_signal_is_shared_and_idempotent() {
        let a = ShutdownSignal::new();
        let b = a.clone();
        assert!(!a.is_requested());
        b.request();
        b.request();
        assert!(a.is_requested());
    }

    /// CRI-5・TASK-62.7.2: 未要求なら期限で戻り、要求されれば即座に起きる。
    #[test]
    fn cri5_873_wait_timeout_expires_and_wakes() {
        let s = ShutdownSignal::new();
        let t = Instant::now();
        assert!(!s.wait_timeout(Duration::from_millis(30)));
        assert!(t.elapsed() >= Duration::from_millis(25));
        let s2 = s.clone();
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            s2.request();
        });
        let t = Instant::now();
        assert!(s.wait_timeout(Duration::from_secs(5)));
        assert!(t.elapsed() < Duration::from_secs(4));
        h.join().unwrap();
        assert!(s.wait_timeout(Duration::from_millis(1)));
    }
}
