//! 取り消せない OS 呼び出しを含む処理を作業スレッドへ隔離し、期限つきで結果を待つ（REPAIR-5・TASK-115.3）。
//!
//! 呼び出し元: [`crate::adapter`] の create（要求由来パスの検証・共有走査）と、macOS の
//! `PlatformBackend::launch`（`Vm::launch` の構成構築・起動）。どちらもファイルシステム操作を含み、
//! 応答しない NFS・autofs 等の上では 1 回の呼び出しが戻らないことがある。ブロック中の呼び出しは
//! 取り消せないため、要求処理スレッド（フレームループ）では実行せず、ここで期限を過ぎたら結果を待たずに
//! 構造化エラーを返す。
//!
//! 期限を過ぎた作業スレッドは止められず、処理が戻るまで残る。無制限に増やさないため、生存中の作業
//! スレッド数を [`Workers`] で数え、上限 [`MAX_WORKERS`] に達していれば新しい処理を開始せず
//! [`IsolateError::Busy`] で拒否する（fail-closed）。残ったスレッドは plugin プロセスの終了で消える。
//! 期限後に作業スレッドが返した値は受け手が無いため drop される（`Vm` なら drop の停止要求が走る）。

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::time::Duration;

/// 同時に生存できる作業スレッド数の上限（期限超過で残ったスレッドを含む。無制限確保の防止）。
pub const MAX_WORKERS: usize = 4;

/// 生存中の作業スレッド数。複製は同じ計数を共有する。
#[derive(Debug, Clone, Default)]
pub struct Workers(Arc<AtomicUsize>);

impl Workers {
    /// 生存中の作業スレッド数（計測・テスト用）。
    pub fn live(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }

    /// 上限未満なら 1 枠確保する。確保できなければ `None`。
    fn acquire(&self) -> Option<Slot> {
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < MAX_WORKERS).then_some(n + 1)
            })
            .ok()
            .map(|_| Slot(self.clone()))
    }
}

/// 確保した 1 枠。作業スレッドの終了（panic を含む）で返す。
struct Slot(Workers);

impl Drop for Slot {
    fn drop(&mut self) {
        // 確保時に加算済みのため 0 を下回らない。
        (self.0).0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// [`run`] が結果を得られなかった理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolateError {
    /// 期限内に終わらなかった（作業スレッドは残る。`after` は指定した期限）。
    Timeout { after: Duration },
    /// 生存中の作業スレッドが上限に達しており、開始しなかった。
    Busy,
    /// 作業スレッドを起動できなかった、または結果を返さずに終了した（panic 等）。
    Failed,
}

/// `f` を作業スレッドで実行し、`timeout` まで結果を待つ。
///
/// `f` は開始されないか（[`IsolateError::Busy`]・起動失敗の [`IsolateError::Failed`]）、ちょうど 1 回
/// 実行される。期限超過後も `f` は走り続け得るため、`f` の副作用は「期限超過でも完了し得る」前提で
/// 呼び出し側が扱う（VM 起動なら停止未確認として記録する等）。
pub fn run<T, F>(workers: &Workers, timeout: Duration, f: F) -> Result<T, IsolateError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let slot = workers.acquire().ok_or(IsolateError::Busy)?;
    let (tx, rx) = sync_channel::<T>(1);
    let spawned = std::thread::Builder::new()
        .name("fc-plugin-macos-isolated".to_string())
        .spawn(move || {
            // 枠は処理の終了時（panic の巻き戻しを含む）に返す。
            let _slot = slot;
            // 受け手が期限超過で去っていれば値はここで drop される。
            let _ = tx.send(f());
        });
    if spawned.is_err() {
        return Err(IsolateError::Failed);
    }
    match rx.recv_timeout(timeout) {
        Ok(v) => Ok(v),
        Err(RecvTimeoutError::Timeout) => Err(IsolateError::Timeout { after: timeout }),
        Err(RecvTimeoutError::Disconnected) => Err(IsolateError::Failed),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::channel;

    use super::*;

    /// 計数が期待値になるまで有限時間だけ待つ（作業スレッドの終了は非同期のため）。
    fn wait_live(w: &Workers, want: usize) -> usize {
        for _ in 0..500 {
            if w.live() == want {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        w.live()
    }

    /// TASK-115.3・REPAIR-5: 期限内の結果はそのまま返り、作業スレッドの枠は終了後に戻る。
    #[test]
    fn task115_3_repair5_isolated_result_is_returned() {
        let w = Workers::default();
        assert_eq!(run(&w, Duration::from_secs(30), || 41 + 1), Ok(42));
        assert_eq!(wait_live(&w, 0), 0);
    }

    /// TASK-115.3・REPAIR-5: 戻らない処理は期限で打ち切って `Timeout` を返し、残ったスレッドが上限に
    /// 達したら新しい処理を開始せず `Busy` で拒否する。処理が戻れば枠が空いて再び実行できる。
    #[test]
    fn task115_3_repair5_blocked_work_times_out_and_is_bounded() {
        let w = Workers::default();
        let mut releases = Vec::new();
        for _ in 0..MAX_WORKERS {
            let (release, blocked) = channel::<()>();
            releases.push(release);
            let after = Duration::from_millis(20);
            assert_eq!(
                run(&w, after, move || {
                    // 応答しない OS 呼び出しの代役（解放されるまで戻らない）。
                    let _ = blocked.recv();
                }),
                Err(IsolateError::Timeout { after })
            );
        }
        assert_eq!(w.live(), MAX_WORKERS);
        let ran = Arc::new(AtomicUsize::new(0));
        let ran2 = Arc::clone(&ran);
        assert_eq!(
            run(&w, Duration::from_secs(30), move || {
                ran2.fetch_add(1, Ordering::SeqCst);
            }),
            Err(IsolateError::Busy)
        );
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        drop(releases);
        assert_eq!(wait_live(&w, 0), 0);
        assert_eq!(run(&w, Duration::from_secs(30), || 7), Ok(7));
    }

    /// TASK-115.3・REPAIR-5: 作業スレッドが panic しても呼び出し側は panic せず `Failed` を受け取り、枠は戻る。
    #[test]
    fn task115_3_repair5_worker_panic_is_reported() {
        let w = Workers::default();
        let r: Result<(), IsolateError> = run(&w, Duration::from_secs(30), || {
            std::panic::resume_unwind(Box::new("worker failure"));
        });
        assert_eq!(r, Err(IsolateError::Failed));
        assert_eq!(wait_live(&w, 0), 0);
    }
}
