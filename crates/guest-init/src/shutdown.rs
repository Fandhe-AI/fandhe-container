//! ゲスト PID 1 の協調停止の手順（OS 非依存。MAC-4・MAC-1・CORE-1・REPAIR-5・TASK-191・#2270。設計は
//! docs/design/macos-shared-vm.md の G3）。
//!
//! 停止要求（ホストの VZ `requestStop` → 仮想 power button → `init` の監視スレッド → `SIGPWR`、または
//! `SIGTERM`）を `reap::reap_until_stop` が受けて戻ると、`init` が [`run`] を呼ぶ。手順は次の順で、
//! すべての待ちに上限がある。
//!
//! 1. 開始の診断行を 1 行だけ出す（[`crate::report::ReportLine::shutdown_begin`]）。
//! 2. PID 1 以外の全プロセスへ `SIGTERM`（[`GUEST_TERM_GRACE`] まで 50 ms 刻みで回収しながら待つ）。
//! 3. 残っていれば `SIGKILL`（[`GUEST_KILL_WAIT`] まで同様に待つ）。
//! 4. `sync`、`reboot(RB_POWER_OFF)`。電源断が成功すれば戻らない。失敗したら診断行
//!    （`stage=poweroff`）を出して戻り、呼び出し元は回収ループへ落ちる（PID 1 は終了しない）。
//!
//! 実際の syscall は `init` の `LinuxShutdownOps`（`sys` の安全なラッパー。PID 1 以外では何もしない）が
//! [`ShutdownOps`] として担い、本モジュールは fake で単体試験できる。
//!
//! # 範囲と残余（REPAIR-3）
//!
//! - ゲスト内のコンテナの停止は、今は `kill(-1)` の一般手順で行う。ゲスト内 CLI 経由で supervisor を順に
//!   止める手順は G6（#2273）以降。
//! - 合計の最悪値（3 + 1 秒 + 回収の刻み）は、ホスト側の最短の猶予（`plugin-macos` の 5 秒）より短い。
//!   `sync` は期限をかけられないため、最後の歯止めはホストの期限つきの強制停止（REPAIR-5）。
//! - 実 VM での `requestStop` からの到達（PL061 GPIO と gpio-keys → `KEY_POWER`）は未確認で #1628・#2282。

use std::time::Duration;

use crate::report::{Errno, InitStage, ReportLine};

/// `SIGTERM` の後にゲスト内のプロセスの終了を待つ上限。
pub const GUEST_TERM_GRACE: Duration = Duration::from_secs(3);
/// `SIGKILL` の後に待つ上限。
pub const GUEST_KILL_WAIT: Duration = Duration::from_secs(1);
/// 待ちの刻み（回収と存在確認の間隔）。
pub const SHUTDOWN_POLL: Duration = Duration::from_millis(50);

/// 終了要求の強さ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// `SIGTERM`。
    Term,
    /// `SIGKILL`。
    Kill,
}

/// 全プロセスへの終了要求の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalOutcome {
    /// 送った。
    Sent,
    /// 他にプロセスが無い（`ESRCH`）。
    NoOthers,
    /// 送れなかった（errno）。待ちに進み、残っていれば次の段へ進める。
    Failed(Errno),
}

/// 停止の手順の差し替え口。本番は `init` の `LinuxShutdownOps`、試験は fake。
pub trait ShutdownOps {
    /// PID 1 以外の全プロセスへ終了要求を送る。
    fn signal_others(&mut self, sig: Signal) -> SignalOutcome;
    /// 回収できる子を（待たずに）回収する。
    fn reap(&mut self);
    /// PID 1 以外のプロセスがまだ残っているか（回収の後に見る）。
    fn others_alive(&mut self) -> bool;
    /// 刻みの間の待ち。
    fn sleep(&mut self, d: Duration);
    /// 書き込みを流す。
    fn sync(&mut self);
    /// 電源を落とす。成功すれば戻らない。戻った値は失敗の errno。
    fn power_off(&mut self) -> Errno;
    /// 診断行を出す。
    fn write_line(&mut self, line: &ReportLine);
}

/// 全プロセスが消えるのを `limit` まで待つ。消えれば真。回数は `limit / SHUTDOWN_POLL` で有限。
fn wait_for_exit<O: ShutdownOps>(ops: &mut O, limit: Duration) -> bool {
    let polls = limit.as_millis() / SHUTDOWN_POLL.as_millis().max(1);
    let mut i = 0u128;
    loop {
        ops.reap();
        if !ops.others_alive() {
            return true;
        }
        if i >= polls {
            return false;
        }
        i += 1;
        ops.sleep(SHUTDOWN_POLL);
    }
}

/// 停止の手順を実行する。電源断が成功すれば戻らない。戻るのは電源断が失敗したときだけで、その errno を返す。
pub fn run<O: ShutdownOps>(ops: &mut O) -> Errno {
    ops.write_line(&ReportLine::shutdown_begin());
    if ops.signal_others(Signal::Term) != SignalOutcome::NoOthers
        && !wait_for_exit(ops, GUEST_TERM_GRACE)
    {
        let _ = ops.signal_others(Signal::Kill);
        let _ = wait_for_exit(ops, GUEST_KILL_WAIT);
    }
    ops.sync();
    let errno = ops.power_off();
    ops.write_line(&ReportLine::init_error(InitStage::PowerOff, errno));
    errno
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Clone)]
    enum Call {
        Signal(Signal),
        Reap,
        Alive,
        Sleep(Duration),
        Sync,
        PowerOff,
        Line(String),
    }

    struct Fake {
        calls: Vec<Call>,
        term: SignalOutcome,
        /// `others_alive` が偽になるまでの問い合わせ回数（None なら永久に真）。
        alive_until: Option<usize>,
        /// `Kill` の後にだけ偽になる（Term では消えない）。
        dies_on_kill: bool,
        killed: bool,
        alive_queries: usize,
        poweroff_errno: Errno,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                calls: Vec::new(),
                term: SignalOutcome::Sent,
                alive_until: Some(0),
                dies_on_kill: false,
                killed: false,
                alive_queries: 0,
                poweroff_errno: Errno::EINVAL,
            }
        }
    }

    impl ShutdownOps for Fake {
        fn signal_others(&mut self, sig: Signal) -> SignalOutcome {
            self.calls.push(Call::Signal(sig));
            if sig == Signal::Kill {
                self.killed = true;
                return SignalOutcome::Sent;
            }
            self.term
        }
        fn reap(&mut self) {
            self.calls.push(Call::Reap);
        }
        fn others_alive(&mut self) -> bool {
            self.calls.push(Call::Alive);
            if self.dies_on_kill {
                return !self.killed;
            }
            self.alive_queries += 1;
            self.alive_until.is_none_or(|n| self.alive_queries <= n)
        }
        fn sleep(&mut self, d: Duration) {
            self.calls.push(Call::Sleep(d));
        }
        fn sync(&mut self) {
            self.calls.push(Call::Sync);
        }
        fn power_off(&mut self) -> Errno {
            self.calls.push(Call::PowerOff);
            self.poweroff_errno
        }
        fn write_line(&mut self, line: &ReportLine) {
            self.calls.push(Call::Line(line.as_str().to_string()));
        }
    }

    fn begin() -> Call {
        Call::Line("fandhe-guest: init shutdown begin".to_string())
    }

    fn poweroff_line(n: u16) -> Call {
        Call::Line(format!("fandhe-guest: init error stage=poweroff errno={n}"))
    }

    /// 他にプロセスが無ければ待たずに sync → 電源断。
    #[test]
    fn mac4_2270_no_others_skips_waiting() {
        let mut f = Fake::new();
        f.term = SignalOutcome::NoOthers;
        let e = run(&mut f);
        assert_eq!(e, Errno::EINVAL);
        assert_eq!(
            f.calls,
            vec![
                begin(),
                Call::Signal(Signal::Term),
                Call::Sync,
                Call::PowerOff,
                poweroff_line(22),
            ]
        );
    }

    /// TERM で全員が終われば KILL は送らない。順序は TERM → 回収・確認 → sync → 電源断。
    #[test]
    fn mac4_2270_term_then_exit_does_not_kill() {
        let mut f = Fake::new();
        f.alive_until = Some(2); // 3 回目の確認で消える
        run(&mut f);
        assert_eq!(
            f.calls,
            vec![
                begin(),
                Call::Signal(Signal::Term),
                Call::Reap,
                Call::Alive,
                Call::Sleep(SHUTDOWN_POLL),
                Call::Reap,
                Call::Alive,
                Call::Sleep(SHUTDOWN_POLL),
                Call::Reap,
                Call::Alive,
                Call::Sync,
                Call::PowerOff,
                poweroff_line(22),
            ]
        );
    }

    /// TERM で消えなければ猶予の上限（3 秒 = 60 刻み）の後に KILL を送る。KILL の後は最初の確認で消える。
    #[test]
    fn mac4_2270_stubborn_process_is_killed_after_grace() {
        let mut f = Fake::new();
        f.alive_until = None;
        f.dies_on_kill = true;
        run(&mut f);
        let sleeps_before_kill = f
            .calls
            .iter()
            .take_while(|c| **c != Call::Signal(Signal::Kill))
            .filter(|c| matches!(c, Call::Sleep(_)))
            .count();
        assert_eq!(sleeps_before_kill, 60);
        let kill_at = f
            .calls
            .iter()
            .position(|c| *c == Call::Signal(Signal::Kill));
        let sync_at = f.calls.iter().position(|c| *c == Call::Sync);
        let off_at = f.calls.iter().position(|c| *c == Call::PowerOff);
        assert!(kill_at.is_some() && kill_at < sync_at && sync_at < off_at);
        let sleeps_total = f
            .calls
            .iter()
            .filter(|c| matches!(c, Call::Sleep(_)))
            .count();
        assert_eq!(sleeps_total, 60);
        let kills = f
            .calls
            .iter()
            .filter(|c| **c == Call::Signal(Signal::Kill))
            .count();
        assert_eq!(kills, 1);
    }

    /// KILL の後も消えなければ 1 秒（20 刻み）で諦めて sync・電源断へ進む（上限つき）。
    #[test]
    fn mac4_2270_waits_are_bounded() {
        let mut f = Fake::new();
        f.alive_until = None;
        run(&mut f);
        let sleeps = f
            .calls
            .iter()
            .filter(|c| matches!(c, Call::Sleep(_)))
            .count();
        assert_eq!(sleeps, 60 + 20);
        assert_eq!(f.calls.last(), Some(&poweroff_line(22)));
        assert!(f.calls.contains(&Call::Sync));
        assert!(f.calls.contains(&Call::PowerOff));
    }

    /// TERM の送信失敗でも待ちに進み、残っていれば KILL まで進む（失敗で手順を止めない）。
    #[test]
    fn mac4_2270_term_failure_still_waits() {
        let mut f = Fake::new();
        f.term = SignalOutcome::Failed(Errno::new(1));
        f.alive_until = None;
        f.dies_on_kill = true;
        run(&mut f);
        assert!(f.calls.contains(&Call::Signal(Signal::Kill)));
    }

    /// 電源断の失敗は固定語彙の診断行を出して戻る（呼び出し元が回収ループへ落ちる）。
    #[test]
    fn mac4_2270_power_off_failure_is_reported_and_returns() {
        let mut f = Fake::new();
        f.poweroff_errno = Errno::new(1);
        f.alive_until = Some(0);
        assert_eq!(run(&mut f), Errno::new(1));
        assert_eq!(f.calls.last(), Some(&poweroff_line(1)));
    }

    /// ゲストの最悪の合計はホストの既定の猶予と、plugin の猶予（5 秒）より短い。
    #[test]
    fn mac4_2270_guest_budget_fits_host_grace() {
        let total = GUEST_TERM_GRACE + GUEST_KILL_WAIT;
        assert_eq!(total, Duration::from_secs(4));
        assert!(total < Duration::from_secs(5));
    }
}
