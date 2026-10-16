//! 手順 8 の `launch_claimed` が行う状態 I/O（Running の記録・失敗時の予約の解放）を期限で打ち切る
//! `StateStore` のラッパー（`start_entry` の入口スレッド専用。TASK-157 追補・#1819・REPAIR-5・CORE-1・CORE-2）。
//!
//! 本番 launcher は単一スレッドの呼び出しを要求するため、手順 8 は入口スレッドが直接行う。その間の
//! `StateStore` 呼び出し（FUSE・ストレージ上の `FileStateStore` の fsync 等）が止まると、入口は期限内に結果を
//! 報告できない。そこで launch の後に起きる呼び出しを、期限つきで待てる別スレッドで実行する。
//!
//! - スレッドは呼び出しのたびに作る。launch（fork）より前の呼び出しは無い（予約は作業スレッドで済ませてある）ため、
//!   fork 前に入口プロセスのスレッドを増やさない。
//! - 期限（`until`）までに戻らなければ [`ErrorCode::Timeout`] を返し、スレッドは放置する（戻った結果は捨てる）。
//!   core は Running の記録の失敗を受けて子を terminate し、予約の解放も同じ期限切れで失敗するため、予約
//!   （Running・pid なし）が残る。その回復は報告の後の後始末（`recover_interrupted_start`）が担う。
//! - `until` が無い（期限が巨大でオーバーフローする）場合は直接呼ぶ。

use std::sync::Arc;
use std::sync::mpsc;
use std::time::Instant;

use fandhe_container_core::traits::{
    CreateStateRequest, DeleteStateRequest, DeleteStateResponse, ErrorCode, GetStateRequest,
    ListStateRequest, StateList, StateRecord, StateStore, TraitError, UpdateStateRequest,
};

/// 期限つきで内側の `StateStore` を呼ぶラッパー。
pub(crate) struct DeadlineStore {
    inner: Arc<dyn StateStore>,
    until: Option<Instant>,
}

impl DeadlineStore {
    /// `until` までに戻らない呼び出しを `Timeout` で打ち切る。`None` は打ち切らない。
    pub(crate) fn new(inner: Arc<dyn StateStore>, until: Option<Instant>) -> Self {
        Self { inner, until }
    }

    fn call<T, F>(&self, f: F) -> Result<T, TraitError>
    where
        T: Send + 'static,
        F: FnOnce(&dyn StateStore) -> Result<T, TraitError> + Send + 'static,
    {
        let timeout = || {
            TraitError::new(
                ErrorCode::Timeout,
                "the state store call exceeded the start deadline",
            )
        };
        let Some(until) = self.until else {
            return f(self.inner.as_ref());
        };
        let remaining = match until.checked_duration_since(Instant::now()) {
            Some(r) if !r.is_zero() => r,
            _ => return Err(timeout()),
        };
        let (tx, rx) = mpsc::channel();
        let inner = Arc::clone(&self.inner);
        std::thread::Builder::new()
            .name("supervisor-store".into())
            .spawn(move || {
                // 受け手が待ちをやめていれば送信は失敗する（結果は捨てる）。
                let _ = tx.send(f(inner.as_ref()));
            })
            .map_err(|_| TraitError::new(ErrorCode::Internal, "failed to spawn a store thread"))?;
        rx.recv_timeout(remaining).map_err(|_| timeout())?
    }
}

impl StateStore for DeadlineStore {
    fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        let req = req.clone();
        self.call(move |s| s.create(&req))
    }

    fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        let req = req.clone();
        self.call(move |s| s.update(&req))
    }

    fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
        let req = req.clone();
        self.call(move |s| s.get(&req))
    }

    fn list(&self, req: &ListStateRequest) -> Result<StateList, TraitError> {
        let req = req.clone();
        self.call(move |s| s.list(&req))
    }

    fn delete(&self, req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        let req = req.clone();
        self.call(move |s| s.delete(&req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::ContainerId;
    use std::time::Duration;

    /// `get` が長く止まるストア（他は到達しない）。
    struct Stuck;
    impl StateStore for Stuck {
        fn create(&self, _: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "unused"))
        }
        fn update(&self, _: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "unused"))
        }
        fn get(&self, _: &GetStateRequest) -> Result<StateRecord, TraitError> {
            std::thread::sleep(Duration::from_secs(5));
            Err(TraitError::new(ErrorCode::Internal, "late"))
        }
        fn list(&self, _: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "unused"))
        }
        fn delete(&self, _: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "unused"))
        }
    }

    fn get_req() -> GetStateRequest {
        GetStateRequest::new(ContainerId::new("c1").expect("valid id"))
    }

    /// REPAIR-5: 止まった呼び出しは期限で打ち切られ、`Timeout` を返す。
    #[test]
    fn repair5_stuck_call_times_out_at_the_deadline() {
        let store = DeadlineStore::new(
            Arc::new(Stuck),
            Instant::now().checked_add(Duration::from_millis(100)),
        );
        let started = Instant::now();
        let err = store.get(&get_req()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// REPAIR-5: 期限が過ぎていれば内側を呼ばずに `Timeout` を返す。
    #[test]
    fn repair5_expired_deadline_does_not_call_the_store() {
        let store = DeadlineStore::new(Arc::new(Stuck), Some(Instant::now()));
        let started = Instant::now();
        let err = store.get(&get_req()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}
