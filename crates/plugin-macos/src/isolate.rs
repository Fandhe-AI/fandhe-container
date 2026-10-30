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
//! 計数は [`Workers`] の実体ごとで、create の検証用（アダプタ）と launch 用（`PlatformBackend`）は別の実体を
//! 持つ。プロセス全体で残り得る作業スレッドは最大 `2 * MAX_WORKERS`（8）。
//! 期限後に作業スレッドが返した値は受け手が無いため drop される（`Vm` なら drop の停止要求が走る）。
//! 枠は結果と一緒に送り、受け手が受け取った直後に返す。[`run`] が `Ok` で戻った時点で、その作業の枠は
//! 返却済みである（スレッド自体の終了は保証しない。#3453・#3507 と同じ「send の後の資源保持」の是正。
//! #3549・PLUG-2・REPAIR-5）。

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::time::Duration;

/// 1 つの [`Workers`] で同時に生存できる作業スレッド数の上限（期限超過で残ったスレッドを含む。無制限確保の防止）。
pub const MAX_WORKERS: usize = 4;

/// 生存中の作業スレッド数。複製は同じ計数を共有する。
#[derive(Debug, Clone, Default)]
pub struct Workers(Arc<AtomicUsize>);

impl Workers {
    /// 結果を受け取られていない作業の枠の数（期限超過で残ったものを含む。計測・テスト用）。
    pub fn live(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }

    /// 上限未満なら 1 枠確保する。確保できなければ `None`。
    fn acquire(&self) -> Option<Slot> {
        let mut current = self.0.load(Ordering::SeqCst);
        // 競合で値が変わっていたら読み直して再判定する（上限未満の間だけ加算を試みる）。
        while current < MAX_WORKERS {
            match self
                .0
                .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Some(Slot(self.clone())),
                Err(seen) => current = seen,
            }
        }
        None
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
    /// 作業スレッドを起動できず、処理を開始しなかった。
    SpawnFailed,
    /// 作業スレッドが処理を開始した後、結果を返さずに終了した（panic 等）。処理の副作用は起き得る。
    Died,
}

/// `f` を作業スレッドで実行し、`timeout` まで結果を待つ。
///
/// `f` は開始されないか（[`IsolateError::Busy`]・[`IsolateError::SpawnFailed`]）、ちょうど 1 回
/// 実行される（[`IsolateError::Timeout`]・[`IsolateError::Died`] は開始後の失敗）。期限超過後も `f` は走り続け得るため、`f` の副作用は「期限超過でも完了し得る」前提で
/// 呼び出し側が扱う（VM 起動なら停止未確認として記録する等）。
pub fn run<T, F>(workers: &Workers, timeout: Duration, f: F) -> Result<T, IsolateError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let slot = workers.acquire().ok_or(IsolateError::Busy)?;
    let (tx, rx) = sync_channel::<(T, Slot)>(1);
    let spawned = std::thread::Builder::new()
        .name("fc-plugin-macos-isolated".to_string())
        .spawn(move || {
            // 宣言順に注意: panic の巻き戻しは逆順で drop するため、`slot` が `tx` より先に返り、
            // 呼び出し側が `Died` を観測した時点で枠は戻っている。
            let tx = tx;
            let slot = slot;
            let v = f();
            // 枠は結果と一緒に送り、受け手が受け取った直後に返す（send の後に枠を持ち続けない）。
            // 受け手が期限超過で去っていれば (値, 枠) の順にここで drop される。値（`Vm` なら停止要求）の
            // 片づけの間も枠を数え続け、残り得る作業スレッドの上限を保つ。
            let _ = tx.send((v, slot));
        });
    if spawned.is_err() {
        return Err(IsolateError::SpawnFailed);
    }
    match rx.recv_timeout(timeout) {
        Ok((v, slot)) => {
            drop(slot);
            Ok(v)
        }
        Err(RecvTimeoutError::Timeout) => Err(IsolateError::Timeout { after: timeout }),
        Err(RecvTimeoutError::Disconnected) => Err(IsolateError::Died),
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
        // 待たずに直接照合する（#3549: Ok で戻った時点で枠は返却済み）。
        assert_eq!(w.live(), 0);
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
        assert_eq!(w.live(), 0);
    }

    /// PLUG-2・REPAIR-5・#3549: 結果を受け取って戻った時点で枠は返却済みで、待たずに照合できる。
    /// 上限ぎりぎりまで期限切れの作業を残しても、直後の `run` が誤って `Busy` にならない。
    #[test]
    fn plug2_3549_repair5_slot_is_returned_before_result_is_received() {
        let w = Workers::default();
        let mut releases = Vec::new();
        for _ in 0..MAX_WORKERS - 1 {
            let (release, blocked) = channel::<()>();
            releases.push(release);
            let after = Duration::from_millis(20);
            assert_eq!(
                run(&w, after, move || {
                    let _ = blocked.recv();
                }),
                Err(IsolateError::Timeout { after })
            );
        }
        for i in 0..300usize {
            assert_eq!(
                run(&w, Duration::from_secs(30), move || i),
                Ok(i),
                "round {i}"
            );
            assert_eq!(w.live(), MAX_WORKERS - 1, "round {i}");
        }
        drop(releases);
        assert_eq!(wait_live(&w, 0), 0);
    }

    /// TASK-115.3・REPAIR-5: 作業スレッドが panic しても呼び出し側は panic せず `Died` を受け取り、枠は戻る。
    #[test]
    fn task115_3_repair5_worker_panic_is_reported() {
        let w = Workers::default();
        let r: Result<(), IsolateError> = run(&w, Duration::from_secs(30), || {
            std::panic::resume_unwind(Box::new("worker failure"));
        });
        assert_eq!(r, Err(IsolateError::Died));
        // 巻き戻りで枠が tx より先に返るため、Died の観測時点で 0（#3549）。
        assert_eq!(w.live(), 0);
    }
}
