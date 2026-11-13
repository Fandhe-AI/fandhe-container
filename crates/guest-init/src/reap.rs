//! PID 1 の子の回収ループ（`waitpid` による直接の子と孤児の回収）。OS 非依存の判断部分（MAC-4・CORE-1・
//! TASK-191・#2269。設計は docs/design/macos-shared-vm.md の G2）。
//!
//! `init` の `run` が ready の後に [`reap_forever`] へ入る。PID 1 は孤児（親が先に終わった子孫）の再親付け先
//! になるため、回収しないとゾンビが溜まって pid 空間を食い潰す。実際の `waitpid(2)` は `init` の
//! `LinuxWaiter`（`sys` の安全なラッパー経由）が [`ChildWaiter`] として担い、本モジュールは単体試験で
//! fake を差し込めるよう OS 非依存に保つ（`process::GuestOps` と同じ方式）。
//!
//! # 契約
//!
//! - **戻らない**: [`reap_forever`] の戻り値は `!`。どの errno でも抜けない（PID 1 が終了するとカーネルが
//!   panic する）。`ECHILD`（子がいない）と想定外の errno は [`NO_CHILD_PAUSE`] だけ待って待ち直し、
//!   busy loop にしない。`EINTR` はすぐ待ち直す。
//! - **唯一の waiter**: `waitpid(-1)` はプロセスの全ての子を回収する。ループが動き出した後に子を作る
//!   呼び出し元は `Child::wait`・`try_wait` を使ってはならない（`ECHILD` を受け終了コードを取りこぼす）。
//!   終了は `on_reaped` で受け取る（ゲスト内 CLI の終了コードの中継は G6・#2273 で配線する。現状の
//!   本番の呼び出しでは何もしない）。
//! - **観測を出さない**: hvc0 の報告行はホストとの契約（`platform-macos::guest_mount`）なので、回収の記録は
//!   出力しない。

use std::time::Duration;

use crate::report::Errno;

/// 子がいない・想定外の errno のときに待ち直す前の待ち時間。別スレッドが後から子を作った場合に
/// ゾンビが残る時間の上限になる（SIGCHLD・pidfd 駆動は G6 で再評価する。起床は 1 秒に 1 回でアイドル時の
/// 負荷は無視できる。CORE-7）。
pub const NO_CHILD_PAUSE: Duration = Duration::from_secs(1);

/// 回収した子の終了状態（`waitpid` の status の復号結果）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildStatus {
    /// `exit` による終了（終了コード）。
    Exited(u8),
    /// シグナルによる終了（シグナル番号。core dump bit は落とす）。
    Signaled(u8),
    /// 上記以外（停止・継続など。生の status を保持する）。`WUNTRACED` を渡さないので通常は起きない。
    Other(i32),
}

/// Linux の wait status を復号する（x86_64・aarch64 で同一の符号化）。
pub fn decode_wait_status(raw: i32) -> ChildStatus {
    let low = raw & 0x7f;
    if low == 0 {
        // WIFEXITED: 下位 7 bit が 0、次の 8 bit が終了コード。
        return ChildStatus::Exited(u8::try_from((raw >> 8) & 0xff).unwrap_or(0));
    }
    if low != 0x7f {
        // WIFSIGNALED: 下位 7 bit がシグナル番号（0x7f は停止の印）。
        return ChildStatus::Signaled(u8::try_from(low).unwrap_or(0));
    }
    ChildStatus::Other(raw)
}

/// `waitpid` 1 回の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    /// 子を 1 つ回収した。
    Reaped { pid: i32, status: ChildStatus },
    /// 子がいない（`ECHILD`）。
    NoChildren,
    /// シグナルで中断された（`EINTR`）。
    Interrupted,
    /// `WNOHANG` で、回収できる子が今は無い。
    NothingReady,
    /// 想定外の失敗。
    Failed(Errno),
}

/// 子の回収の差し替え口。本番は `init` の `LinuxWaiter`、試験は fake。
pub trait ChildWaiter {
    /// 任意の子を 1 つ回収する。`nohang` が真なら待たない。
    fn wait_any(&mut self, nohang: bool) -> WaitResult;
    /// 次の試行の前に待つ。
    fn pause(&mut self, d: Duration);
}

/// ブロッキングの回収を 1 回行う。回収できたら `on_reaped` を呼ぶ。
pub fn step<W: ChildWaiter>(w: &mut W, on_reaped: &mut dyn FnMut(i32, ChildStatus)) {
    match w.wait_any(false) {
        WaitResult::Reaped { pid, status } => on_reaped(pid, status),
        WaitResult::Interrupted => {}
        // NothingReady はブロッキング待ちでは起きない想定だが、来ても busy loop にしない。
        WaitResult::NoChildren | WaitResult::NothingReady | WaitResult::Failed(_) => {
            w.pause(NO_CHILD_PAUSE);
        }
    }
}

/// 子と孤児を回収し続ける。戻らない（MAC-4・CORE-1）。
pub fn reap_forever<W: ChildWaiter>(w: &mut W, mut on_reaped: impl FnMut(i32, ChildStatus)) -> ! {
    loop {
        step(w, &mut on_reaped);
    }
}

/// `WNOHANG` で回収できる子を最大 `max` 件まで回収して返す（試験と将来の用途向け）。回収できる子が
/// 無くなる・失敗するか、`EINTR` が続いて試行の上限に達すると止まる（件数・回数とも有限）。
pub fn drain<W: ChildWaiter>(w: &mut W, max: usize) -> Vec<(i32, ChildStatus)> {
    let mut out = Vec::new();
    let mut attempts = max.saturating_add(16);
    while out.len() < max && attempts > 0 {
        attempts -= 1;
        match w.wait_any(true) {
            WaitResult::Reaped { pid, status } => out.push((pid, status)),
            WaitResult::Interrupted => {}
            WaitResult::NothingReady | WaitResult::NoChildren | WaitResult::Failed(_) => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Fake {
        script: VecDeque<WaitResult>,
        /// 台本が尽きたときに返す値。
        fallback: WaitResult,
        pauses: Vec<Duration>,
        calls: Vec<bool>,
    }

    impl Fake {
        fn new(script: &[WaitResult], fallback: WaitResult) -> Self {
            Self {
                script: script.iter().copied().collect(),
                fallback,
                pauses: Vec::new(),
                calls: Vec::new(),
            }
        }
    }

    impl ChildWaiter for Fake {
        fn wait_any(&mut self, nohang: bool) -> WaitResult {
            self.calls.push(nohang);
            self.script.pop_front().unwrap_or(self.fallback)
        }
        fn pause(&mut self, d: Duration) {
            self.pauses.push(d);
        }
    }

    #[test]
    fn mac4_2269_decode_wait_status() {
        assert_eq!(decode_wait_status(0x0300), ChildStatus::Exited(3));
        assert_eq!(decode_wait_status(0x0000), ChildStatus::Exited(0));
        assert_eq!(decode_wait_status(0x0009), ChildStatus::Signaled(9));
        // core dump bit（0x80）つきでもシグナル番号だけを取る。
        assert_eq!(decode_wait_status(0x0089), ChildStatus::Signaled(9));
        assert_eq!(decode_wait_status(0x137f), ChildStatus::Other(0x137f));
    }

    #[test]
    fn mac4_2269_step_pauses_only_when_nothing_to_reap() {
        let reaped = WaitResult::Reaped {
            pid: 42,
            status: ChildStatus::Exited(7),
        };
        let mut seen = Vec::new();
        let mut w = Fake::new(&[reaped], WaitResult::NoChildren);
        step(&mut w, &mut |p, s| seen.push((p, s)));
        assert_eq!(seen, vec![(42, ChildStatus::Exited(7))]);
        assert!(w.pauses.is_empty());
        assert_eq!(w.calls, vec![false]);

        let mut w = Fake::new(&[WaitResult::Interrupted], WaitResult::NoChildren);
        step(&mut w, &mut |_, _| panic!("no child was reaped"));
        assert!(w.pauses.is_empty());

        for r in [
            WaitResult::NoChildren,
            WaitResult::NothingReady,
            WaitResult::Failed(Errno::EINVAL),
        ] {
            let mut w = Fake::new(&[r], r);
            step(&mut w, &mut |_, _| panic!("no child was reaped"));
            assert_eq!(w.pauses, vec![Duration::from_secs(1)], "{r:?}");
        }
    }

    /// 終了しない契約: 子がいない状態が続いても、ステップは毎回戻って次に進める（pause を挟む）。
    #[test]
    fn mac4_2269_echild_forever_keeps_pausing_without_exit() {
        let mut w = Fake::new(&[], WaitResult::NoChildren);
        for _ in 0..1000 {
            step(&mut w, &mut |_, _| panic!("no child was reaped"));
        }
        assert_eq!(w.pauses.len(), 1000);
        assert!(w.pauses.iter().all(|d| *d == NO_CHILD_PAUSE));
    }

    #[test]
    fn mac4_2269_drain_stops_at_max_and_at_empty() {
        let r = |pid, code| WaitResult::Reaped {
            pid,
            status: ChildStatus::Exited(code),
        };
        let mut w = Fake::new(&[r(1, 0), r(2, 1), r(3, 2)], WaitResult::NoChildren);
        assert_eq!(
            drain(&mut w, 2),
            vec![(1, ChildStatus::Exited(0)), (2, ChildStatus::Exited(1))]
        );

        let mut w = Fake::new(
            &[r(1, 0), WaitResult::Interrupted, r(2, 1)],
            WaitResult::NoChildren,
        );
        assert_eq!(
            drain(&mut w, 8),
            vec![(1, ChildStatus::Exited(0)), (2, ChildStatus::Exited(1))]
        );
        assert!(w.calls.iter().all(|nohang| *nohang));

        let mut w = Fake::new(&[r(1, 0)], WaitResult::NothingReady);
        assert_eq!(drain(&mut w, 8).len(), 1);

        // EINTR が続いても有限回で止まる。
        let mut w = Fake::new(&[], WaitResult::Interrupted);
        assert!(drain(&mut w, 4).is_empty());
        assert_eq!(w.calls.len(), 20);
    }
}
