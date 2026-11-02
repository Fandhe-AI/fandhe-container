//! Shutdown RPC からデーモンの寿命管理へ終了要求を渡すシグナル（CRI-5・TASK-62.7.2・REPAIR-5・MS-7）。
//!
//! [`TaskService`](super::task_service::TaskService) / [`EmptyTaskService`](super::service::EmptyTaskService) の
//! `Shutdown` ハンドラが [`ShutdownSignal::request`] を呼び、`bootstrap` のデーモン（`run_serve`）が
//! [`ShutdownSignal::wait_timeout`] で待って `ServerHandle::shutdown` へ進む。ハンドラからサーバーを直接
//! 止めないのは、停止フラグが Shutdown 自身の応答の書き込みを打ち切るため。
//! 要求は冪等で、一度立てたら下ろさない。待ちは必ず期限つき（無期限には待たない）。

use std::any::Any;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// 終了要求の前に取る排他（例: 同一 id の `start` との排他ロック）。取れなければ `Err`。
/// 返した保持物は [`ShutdownSignal::take_held`] で取り出すまで、シグナルが保持し続ける。
pub type ShutdownGate = Arc<dyn Fn() -> Result<Box<dyn Any + Send>, ()> + Send + Sync>;

/// [`ShutdownSignal::request`] が排他を取れず、終了を要求できなかったことを表す。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateFailed;

/// 終了要求の共有フラグ。`Clone` は同じ要求を共有する。
#[derive(Clone, Default)]
pub struct ShutdownSignal {
    inner: Arc<(Mutex<bool>, Condvar)>,
    gate: Option<ShutdownGate>,
    held: Arc<Mutex<Option<Box<dyn Any + Send>>>>,
}

impl std::fmt::Debug for ShutdownSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownSignal")
            .field("requested", &self.is_requested())
            .field("gated", &self.gate.is_some())
            .finish()
    }
}

impl ShutdownSignal {
    /// 未要求の状態で作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// 要求を立てる前に `gate` で排他を取るシグナルを作る。
    ///
    /// 要求した瞬間から片付けの終わりまで、並行する `start` を締め出すために使う（取った排他は
    /// [`take_held`](Self::take_held) で受け取って片付けの最後まで持つ。PLUG-12・REPAIR-5）。
    pub fn with_gate(gate: ShutdownGate) -> Self {
        Self {
            gate: Some(gate),
            ..Self::default()
        }
    }

    /// 終了を要求する（冪等）。待っているスレッドを起こす。
    ///
    /// ゲートがあれば先に取り、取れなければ要求を立てずに `Err`（呼び出し側は失敗を応答する）。
    pub fn request(&self) -> Result<(), GateFailed> {
        // 並行する要求を直列化し、ゲートの二重取得（自己デッドロック）を防ぐ。
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        if self.is_requested() {
            return Ok(());
        }
        if let Some(gate) = &self.gate {
            *held = Some(gate().map_err(|()| GateFailed)?);
        }
        let (lock, cv) = &*self.inner;
        *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
        cv.notify_all();
        Ok(())
    }

    /// ゲートが取った保持物を取り出す（所有を移す。無ければ `None`）。
    pub fn take_held(&self) -> Option<Box<dyn Any + Send>> {
        self.held.lock().unwrap_or_else(|p| p.into_inner()).take()
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
        b.request().unwrap();
        b.request().unwrap();
        assert!(a.is_requested());
    }

    /// CRI-5・PLUG-12・TASK-62.7.2: ゲートは要求の前に取り、失敗なら要求を立てず、成功時の保持物は取り出せる。
    #[test]
    fn plug12_873_gate_runs_before_request() {
        let failing = ShutdownSignal::with_gate(Arc::new(|| Err(())));
        assert_eq!(failing.request(), Err(GateFailed));
        assert!(!failing.is_requested());

        let ok = ShutdownSignal::with_gate(Arc::new(|| Ok(Box::new(7u32) as Box<dyn Any + Send>)));
        ok.request().unwrap();
        // 2 回目はゲートを取り直さない（冪等）。
        ok.request().unwrap();
        assert!(ok.is_requested());
        let held = ok.take_held().unwrap();
        assert_eq!(*held.downcast::<u32>().unwrap(), 7);
        assert!(ok.take_held().is_none());
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
            s2.request().unwrap();
        });
        let t = Instant::now();
        assert!(s.wait_timeout(Duration::from_secs(5)));
        assert!(t.elapsed() < Duration::from_secs(4));
        h.join().unwrap();
        assert!(s.wait_timeout(Duration::from_millis(1)));
    }
}
