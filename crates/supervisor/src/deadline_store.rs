//! 手順 8 の `launch_claimed` が行う状態 I/O（Running の記録・失敗時の予約の解放）を期限で打ち切る
//! `StateStore` のラッパー（`start_entry` の入口スレッド専用。TASK-157 追補・#1819・REPAIR-5・CORE-1・CORE-2）。
//!
//! 本番 launcher は単一スレッドの呼び出しを要求するため、手順 8 は入口スレッドが直接行う。その間の
//! `StateStore` 呼び出し（FUSE・ストレージ上の `FileStateStore` の fsync 等）が止まると、入口は期限内に結果を
//! 報告できない。そこで launch の後に起きる呼び出しを、期限つきで待てる別スレッドで実行する。
//!
//! - スレッドは呼び出しのたびに作る。launch（fork）より前の呼び出しは無い（予約は作業スレッドで済ませてある）ため、
//!   fork 前に入口プロセスのスレッドを増やさない。
//! - 期限（`until`）までに戻らなければ [`ErrorCode::Timeout`] を返し、スレッドは放置する。放置した `update` が
//!   後から成功し得る（結果チャネルを捨てても副作用は取り消せない）ため、その完了と成功した記録を
//!   `LateWrites` に残し、報告の後の後始末が完了を待って照合・修復する（Running・pid ありが回収済みの pid のまま
//!   残らないようにする。CORE-2）。
//! - core は Running の記録の失敗を受けて子を terminate し、予約の解放も同じ期限切れで失敗するため、予約
//!   （Running・pid なし）が残る。その回復は報告の後の後始末（`recover_interrupted_start`）が担う。
//! - `until` が無い（期限が巨大でオーバーフローする）場合は直接呼ぶ。

use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{
    CreateStateRequest, DeleteStateRequest, DeleteStateResponse, ErrorCode, GetStateRequest,
    ListStateRequest, StateList, StateRecord, StateStore, TraitError, UpdateStateRequest,
};

/// `LateWrites` の状態。
#[derive(Default)]
struct LateState {
    /// 実行中のスレッド数（放置した呼び出しを含む）。
    in_flight: usize,
    /// 呼び出し側が待ちをやめた後に成功した `update` の記録（古い順）。
    commits: Vec<StateRecord>,
}

/// 放置した呼び出しの完了と、遅れて成功した `update` の記録の受け渡し（同じ Mutex で守る）。
#[derive(Default)]
pub(crate) struct LateWrites {
    state: Mutex<LateState>,
    cv: Condvar,
}

impl LateWrites {
    fn lock(&self) -> MutexGuard<'_, LateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 実行中の呼び出しがすべて戻るまで `limit` を上限に待つ。戻ったら `true`（REPAIR-5）。
    pub(crate) fn wait_settled(&self, limit: Duration) -> bool {
        let end = Instant::now().checked_add(limit);
        let mut guard = self.lock();
        while guard.in_flight > 0 {
            let Some(end) = end else {
                return false;
            };
            let Some(left) = end.checked_duration_since(Instant::now()) else {
                return false;
            };
            let (g, _) = self
                .cv
                .wait_timeout(guard, left)
                .unwrap_or_else(PoisonError::into_inner);
            guard = g;
        }
        true
    }

    /// 遅れて成功した `update` の記録を取り出す（古い順）。
    pub(crate) fn take_commits(&self) -> Vec<StateRecord> {
        std::mem::take(&mut self.lock().commits)
    }
}

/// 期限つきで内側の `StateStore` を呼ぶラッパー。
pub(crate) struct DeadlineStore {
    inner: Arc<dyn StateStore>,
    until: Option<Instant>,
    late: Arc<LateWrites>,
}

impl DeadlineStore {
    /// `until` までに戻らない呼び出しを `Timeout` で打ち切る。`None` は打ち切らない。
    pub(crate) fn new(inner: Arc<dyn StateStore>, until: Option<Instant>) -> Self {
        Self {
            inner,
            until,
            late: Arc::new(LateWrites::default()),
        }
    }

    /// 放置した呼び出しの完了待ちと遅れた記録の受け渡し口。
    pub(crate) fn late_writes(&self) -> Arc<LateWrites> {
        Arc::clone(&self.late)
    }

    /// `late_record` は成功値から、呼び出し側が諦めた後に残すべき記録（`update` の結果）を取り出す。
    fn call<T, F>(&self, f: F, late_record: fn(&T) -> Option<StateRecord>) -> Result<T, TraitError>
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
        let late = Arc::clone(&self.late);
        let abandoned = Arc::new(Mutex::new(false));
        let thread_abandoned = Arc::clone(&abandoned);
        self.late.lock().in_flight += 1;
        let spawned = std::thread::Builder::new()
            .name("supervisor-store".into())
            .spawn(move || {
                let result = f(inner.as_ref());
                // 送信と「諦められたか」の判定は同じロック下で行い、呼び出し側の諦めとの競合で記録が漏れないようにする。
                let mut guard = late.lock();
                let gave_up = *thread_abandoned
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if gave_up {
                    if let Some(record) = result.as_ref().ok().and_then(late_record) {
                        guard.commits.push(record);
                    }
                } else {
                    let _ = tx.send(result);
                }
                guard.in_flight = guard.in_flight.saturating_sub(1);
                drop(guard);
                late.cv.notify_all();
            });
        if spawned.is_err() {
            let mut guard = self.late.lock();
            guard.in_flight = guard.in_flight.saturating_sub(1);
            return Err(TraitError::new(
                ErrorCode::Internal,
                "failed to spawn a store thread",
            ));
        }
        match rx.recv_timeout(remaining) {
            Ok(r) => r,
            Err(_) => {
                // 諦める前に結果が届いていればそれを使う。届いていなければ以後の結果は LateWrites へ回す。
                let _guard = self.late.lock();
                if let Ok(r) = rx.try_recv() {
                    return r;
                }
                *abandoned.lock().unwrap_or_else(PoisonError::into_inner) = true;
                Err(timeout())
            }
        }
    }
}

impl StateStore for DeadlineStore {
    fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        let req = req.clone();
        self.call(move |s| s.create(&req), |_| None)
    }

    fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        let req = req.clone();
        self.call(move |s| s.update(&req), |r| Some(r.clone()))
    }

    fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
        let req = req.clone();
        self.call(move |s| s.get(&req), |_| None)
    }

    fn list(&self, req: &ListStateRequest) -> Result<StateList, TraitError> {
        let req = req.clone();
        self.call(move |s| s.list(&req), |_| None)
    }

    fn delete(&self, req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        let req = req.clone();
        self.call(move |s| s.delete(&req), |_| None)
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

    /// `update` だけを遅らせて内側へ委ねるストア（使う試験が Linux 限定のため同じ cfg を付ける）。
    #[cfg(target_os = "linux")]
    struct SlowUpdate(Arc<dyn StateStore>, Duration);
    #[cfg(target_os = "linux")]
    impl StateStore for SlowUpdate {
        fn create(&self, r: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            self.0.create(r)
        }
        fn update(&self, r: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            std::thread::sleep(self.1);
            self.0.update(r)
        }
        fn get(&self, r: &GetStateRequest) -> Result<StateRecord, TraitError> {
            self.0.get(r)
        }
        fn list(&self, r: &ListStateRequest) -> Result<StateList, TraitError> {
            self.0.list(r)
        }
        fn delete(&self, r: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            self.0.delete(r)
        }
    }

    /// CORE-2・REPAIR-5: 期限で打ち切った `update` が後から成功したら、完了を待てて、成功した記録を受け取れる。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_late_update_commit_is_reported_to_the_cleanup() {
        use fandhe_container_core::state_store::{FileStateStore, StateRoot};
        use fandhe_container_core::traits::ContainerStatus;
        // 一意・排他作成の親の子を使う（pid だけの名前の残骸と衝突しない。#3374・REPAIR-12）。
        let scratch =
            crate::scratch_root::ScratchDir::new("fandhe-sup-deadline", Duration::from_secs(10));
        let dir = scratch.path().join("root");
        std::fs::create_dir(&dir).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let root = StateRoot::resolve(Some(dir.clone())).unwrap();
        let file: Arc<dyn StateStore> = Arc::new(FileStateStore::open(root).unwrap());
        let id = ContainerId::new("c1").expect("valid id");
        let created = file
            .create(
                &CreateStateRequest::new(ContainerStatus::created(id.clone(), None), dir.clone())
                    .unwrap(),
            )
            .unwrap();
        let slow: Arc<dyn StateStore> = Arc::new(SlowUpdate(file, Duration::from_millis(300)));
        let store = DeadlineStore::new(slow, Instant::now().checked_add(Duration::from_millis(50)));
        let late = store.late_writes();
        let running = ContainerStatus::running(id, std::num::NonZeroU32::new(4242));
        let err = store
            .update(&UpdateStateRequest::new(running, created.revision()))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert!(late.wait_settled(Duration::from_secs(5)));
        let commits = late.take_commits();
        assert_eq!(commits.len(), 1);
        assert_eq!(
            commits[0].status().pid().map(std::num::NonZeroU32::get),
            Some(4242)
        );
    }
}
