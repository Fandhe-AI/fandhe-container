//! PID 1 の子の回収ループ（`waitpid` による直接の子と孤児の回収）。OS 非依存の判断部分（MAC-4・CORE-1・
//! TASK-191・#2269。設計は docs/design/macos-shared-vm.md の G2）。
//!
//! `init` の `run` が ready の後に [`reap_until_stop`] へ入り、停止要求（`SIGTERM`・`SIGPWR`）で戻って
//! `shutdown` の手順へ進む（#2270）。電源断に失敗したときだけ [`reap_forever`] へ落ちる。PID 1 は孤児（親が先に終わった子孫）の再親付け先
//! になるため、回収しないとゾンビが溜まって pid 空間を食い潰す。実際の `waitpid(2)` は `init` の
//! `LinuxWaiter`（`sys` の安全なラッパー経由）が [`ChildWaiter`] として担い、本モジュールは単体試験で
//! fake を差し込めるよう OS 非依存に保つ（`process::GuestOps` と同じ方式）。
//!
//! # 契約
//!
//! - **戻らない**: [`reap_forever`] の戻り値は `!`。どの errno でも抜けない（PID 1 が終了するとカーネルが
//!   panic する）。[`reap_until_stop`] が戻るのは停止要求を受けたときだけ。`ECHILD`（子がいない）と想定外の
//!   errno は [`NO_CHILD_PAUSE`] を上限に待って待ち直し、busy loop にしない。`EINTR` はすぐ待ち直す。
//! - **イベント駆動**: 待ちは `wait_event`（本番は `sigtimedwait`）。`SIGCHLD` で子の終了に即応し、
//!   停止要求（`SIGTERM`・`SIGPWR`）でも起きる。これらは `init` が `run` の冒頭でブロックしておく前提で、
//!   将来子を作る呼び出し元（G6・#2273）は exec の前にマスクを戻すこと（戻さないと子が `SIGTERM` を受け取れない）。
//! - **唯一の waiter**: `waitpid(-1)` はプロセスの全ての子を回収する。ループが動き出した後に子を作る
//!   呼び出し元は `Child::wait`・`try_wait` を使ってはならない（`ECHILD` を受け終了コードを取りこぼす）。
//!   終了は `on_reaped` で受け取る（ゲスト内 CLI の終了コードの中継は G6・#2273 で配線する。現状の
//!   本番の呼び出しでは何もしない）。
//! - **観測を出さない**: hvc0 の報告行はホストとの契約（`platform-macos::guest_mount`）なので、回収の記録は
//!   出力しない。

use std::time::Duration;

use crate::report::Errno;

/// 待ちの上限（子の終了・停止要求が来なくても起きる間隔）。`SIGCHLD` 駆動のため取りこぼしの保険であり、
/// 起床は 1 秒に 1 回でアイドル時の負荷は無視できる（CORE-7）。失敗の後の待ち直しの間隔も兼ねる。
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

/// 待ちが何で終わったか（[`ChildWaiter::wait_event`] の結果）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// 子が状態を変えた（`SIGCHLD`）。
    Child,
    /// 停止要求（`SIGTERM`・`SIGPWR`。MAC-4・#2270）。
    Stop,
    /// 期限切れ。
    Timeout,
    /// シグナルのハンドラ等で中断された。
    Interrupted,
    /// 想定外の失敗（待ち直す前に [`ChildWaiter::pause`] で間を置く）。
    Failed(Errno),
}

/// 子の回収の差し替え口。本番は `init` の `LinuxWaiter`、試験は fake。
pub trait ChildWaiter {
    /// 任意の子を 1 つ回収する。`nohang` が真なら待たない。
    fn wait_any(&mut self, nohang: bool) -> WaitResult;
    /// 子の終了か停止要求のどちらかが来るまで最大 `timeout` 待つ。本番は `sigtimedwait`（ブロック済みの
    /// `SIGCHLD`・`SIGTERM`・`SIGPWR`）で、起床は子の終了・停止要求・期限のいずれか。
    fn wait_event(&mut self, timeout: Duration) -> Event;
    /// 失敗の後に次の試行の前に待つ（busy loop を避ける）。
    fn pause(&mut self, d: Duration);
}

/// 1 ステップの結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// 続ける。
    Continue,
    /// 停止要求を受けた（[`reap_until_stop`] が戻る）。
    StopRequested,
}

/// 1 ステップで続けて回収する子の最大数。回収できる子が続く間も他の処理（停止要求）へ戻れるようにする。
pub const MAX_REAP_BATCH: usize = 256;

/// 回収できる子を（上限つきで）回収し、いなければ [`NO_CHILD_PAUSE`] を上限に子の終了か停止要求を待つ。
/// 回収できたら `on_reaped` を呼ぶ。
///
/// 待ちの前に `WNOHANG` で回収するので、`SIGCHLD` が合流・先行しても取りこぼさない（シグナルはブロック済みで
/// 保留される）。
pub fn step<W: ChildWaiter>(w: &mut W, on_reaped: &mut dyn FnMut(i32, ChildStatus)) -> Flow {
    let mut reaped = 0usize;
    let mut attempts = MAX_REAP_BATCH.saturating_add(16);
    while reaped < MAX_REAP_BATCH && attempts > 0 {
        attempts -= 1;
        match w.wait_any(true) {
            WaitResult::Reaped { pid, status } => {
                reaped += 1;
                on_reaped(pid, status);
            }
            WaitResult::Interrupted => {}
            WaitResult::NothingReady | WaitResult::NoChildren | WaitResult::Failed(_) => break,
        }
    }
    if reaped >= MAX_REAP_BATCH {
        // まだ回収できる子が残っているかもしれない。待たずに次のステップで続ける。
        return Flow::Continue;
    }
    match w.wait_event(NO_CHILD_PAUSE) {
        Event::Stop => Flow::StopRequested,
        Event::Child | Event::Timeout | Event::Interrupted => Flow::Continue,
        Event::Failed(_) => {
            w.pause(NO_CHILD_PAUSE);
            Flow::Continue
        }
    }
}

/// 子と孤児を回収し続け、停止要求を受けたら戻る（MAC-4・CORE-1・#2270）。呼び出し元（`init`）が戻りの後に
/// 停止の手順（`shutdown`）へ進む。
pub fn reap_until_stop<W: ChildWaiter>(w: &mut W, mut on_reaped: impl FnMut(i32, ChildStatus)) {
    while step(w, &mut on_reaped) != Flow::StopRequested {}
}

/// 子と孤児を回収し続ける。戻らない（MAC-4・CORE-1）。停止要求は無視する。電源断に失敗した後の
/// 行き先（PID 1 は終了できない）として使う。
pub fn reap_forever<W: ChildWaiter>(w: &mut W, mut on_reaped: impl FnMut(i32, ChildStatus)) -> ! {
    loop {
        let _ = step(w, &mut on_reaped);
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
        events: VecDeque<Event>,
        event_fallback: Event,
        pauses: Vec<Duration>,
        calls: Vec<bool>,
        waits: Vec<Duration>,
    }

    impl Fake {
        fn new(script: &[WaitResult], fallback: WaitResult) -> Self {
            Self {
                script: script.iter().copied().collect(),
                fallback,
                events: VecDeque::new(),
                event_fallback: Event::Timeout,
                pauses: Vec::new(),
                calls: Vec::new(),
                waits: Vec::new(),
            }
        }
        fn with_events(mut self, events: &[Event], fallback: Event) -> Self {
            self.events = events.iter().copied().collect();
            self.event_fallback = fallback;
            self
        }
    }

    impl ChildWaiter for Fake {
        fn wait_any(&mut self, nohang: bool) -> WaitResult {
            self.calls.push(nohang);
            self.script.pop_front().unwrap_or(self.fallback)
        }
        fn wait_event(&mut self, timeout: Duration) -> Event {
            self.waits.push(timeout);
            self.events.pop_front().unwrap_or(self.event_fallback)
        }
        fn pause(&mut self, d: Duration) {
            self.pauses.push(d);
        }
    }

    fn r(pid: i32, code: u8) -> WaitResult {
        WaitResult::Reaped {
            pid,
            status: ChildStatus::Exited(code),
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

    /// 回収できる子を全て回収してから待つ。待ちは非ブロッキングの回収だけで、最後に 1 回 `wait_event`。
    #[test]
    fn mac4_2269_step_reaps_everything_then_waits_once() {
        let mut seen = Vec::new();
        let mut w = Fake::new(&[r(42, 7), r(43, 0)], WaitResult::NothingReady);
        let flow = step(&mut w, &mut |p, s| seen.push((p, s)));
        assert_eq!(flow, Flow::Continue);
        assert_eq!(
            seen,
            vec![(42, ChildStatus::Exited(7)), (43, ChildStatus::Exited(0))]
        );
        assert!(w.calls.iter().all(|nohang| *nohang));
        assert_eq!(w.calls.len(), 3);
        assert_eq!(w.waits, vec![NO_CHILD_PAUSE]);
        assert!(w.pauses.is_empty());
    }

    /// 子がいない（ECHILD）・EINTR・Timeout でも戻って続ける。busy loop にしない（毎回 wait_event を挟む）。
    #[test]
    fn mac4_2269_echild_forever_keeps_waiting_without_exit() {
        let mut w = Fake::new(&[], WaitResult::NoChildren);
        for _ in 0..1000 {
            let f = step(&mut w, &mut |_, _| panic!("no child was reaped"));
            assert_eq!(f, Flow::Continue);
        }
        assert_eq!(w.waits.len(), 1000);
        assert!(w.waits.iter().all(|d| *d == NO_CHILD_PAUSE));
        assert!(w.pauses.is_empty());

        let mut w = Fake::new(&[WaitResult::Interrupted], WaitResult::NothingReady);
        step(&mut w, &mut |_, _| panic!("no child was reaped"));
        assert_eq!(w.waits.len(), 1);
    }

    /// 待ちの失敗は pause を挟んで続ける（busy loop にしない）。
    #[test]
    fn mac4_2269_event_failure_pauses() {
        let mut w = Fake::new(&[], WaitResult::NoChildren)
            .with_events(&[Event::Failed(Errno::EINVAL)], Event::Timeout);
        assert_eq!(step(&mut w, &mut |_, _| {}), Flow::Continue);
        assert_eq!(w.pauses, vec![NO_CHILD_PAUSE]);
        for ev in [Event::Child, Event::Timeout, Event::Interrupted] {
            let mut w = Fake::new(&[], WaitResult::NoChildren).with_events(&[ev], ev);
            assert_eq!(step(&mut w, &mut |_, _| {}), Flow::Continue, "{ev:?}");
            assert!(w.pauses.is_empty());
        }
    }

    /// 回収できる子が上限を超えて続くときは待たずに次のステップへ（停止要求への戻りを遅らせない）。
    #[test]
    fn mac4_2270_step_batch_is_bounded() {
        let mut w = Fake::new(&[], r(1, 0));
        let mut n = 0usize;
        let f = step(&mut w, &mut |_, _| n += 1);
        assert_eq!(f, Flow::Continue);
        assert_eq!(n, MAX_REAP_BATCH);
        assert!(w.waits.is_empty());
    }

    /// 停止要求で `reap_until_stop` が戻る。それまでの子の回収は続ける。
    #[test]
    fn mac4_2270_reap_until_stop_returns_on_stop() {
        let mut w = Fake::new(&[r(5, 1)], WaitResult::NothingReady)
            .with_events(&[Event::Child, Event::Timeout, Event::Stop], Event::Stop);
        let mut seen = Vec::new();
        reap_until_stop(&mut w, |p, s| seen.push((p, s)));
        assert_eq!(seen, vec![(5, ChildStatus::Exited(1))]);
        assert_eq!(w.waits.len(), 3);
    }

    #[test]
    fn mac4_2270_stop_is_seen_even_with_children_pending() {
        // 子の回収の直後でも、その回の wait_event が Stop を返せば戻る。
        let mut w = Fake::new(&[r(5, 1)], WaitResult::NothingReady)
            .with_events(&[Event::Stop], Event::Stop);
        assert_eq!(step(&mut w, &mut |_, _| {}), Flow::StopRequested);
    }

    #[test]
    fn mac4_2269_drain_stops_at_max_and_at_empty() {
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
