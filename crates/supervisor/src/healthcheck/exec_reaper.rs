//! healthcheck の exec 専用 helper の親になる中間 subreaper（SUP-4・SUP-6・REPAIR-5・#2441）。
//!
//! # 役割
//! supervisor → reaper（本モジュール。`/proc/self/exe healthcheck-reaper`）→ helper（`exec_helper`）の 3 段にする。
//! helper の子孫（exec の worker、`FileAuditSink` が fork する使い捨ての子など）は、helper が先に終わる・殺されると
//! 再親付けされる。supervisor は child subreaper でコンテナの PID 1 などを直下に持つため、そこへ再親付けされると
//! 回収の責任と特定の手段が子孫の種類ごとに増える。そこで、再親付けの受け皿を **この reaper だけ** にする。
//!
//! # reaper がやること（これだけ。ファイル I/O・監査・状態ストアには触れない = 固まらない）
//! 1. `PR_SET_CHILD_SUBREAPER` を立てて（core の `ChildSubreaper::enable`）helper を fork/exec する。
//! 2. 自分の子（helper と再親付けされた孤児）を、pid 指定の `waitpid(WNOHANG)` で、子が無くなる（`ECHILD` 相当）まで
//!    回収する。`waitpid(-1)` で他人の子を奪うことはない: reaper の子は helper と、その子孫の孤児だけで、コンテナの
//!    PID 1 は supervisor の直下にあり、reaper の子ではない。
//! 3. 止める合図を受けたら helper に SIGKILL を送る（自分の子で、回収前の `Child` に対してだけ送るので pid の再利用で
//!    他人へ送らない）。その後も、孤児をすべて回収するまで終わらない。
//!
//! # 止める合図と親の死亡
//! 合図は fd 2（結果チャネルの socketpair の子側。helper へはそのまま継承させる）に **supervisor が書く 1 バイト**、
//! または **supervisor 側の端が閉じたこと（EOF）**。受け口は reaper 内の専用スレッドが fd 2 の複製を **ブロッキングで**
//! 読み、合図・EOF・読み取りエラーのどれでも `AtomicBool` を立てる（`O_NONBLOCK` はファイル記述に付き helper の fd 2 と
//! 共有されるため、non-blocking にはしない。helper の blocking `write_all` が `WouldBlock` を返さないように）。EOF なので、supervisor が異常終了しても reaper は helper を
//! SIGKILL して終わる（`PR_SET_PDEATHSIG` は生成元のスレッドに束縛されるため使わない）。端を別プロセス（supervisor が
//! fork した子）が持ち続けて EOF が来ない場合に備え、reaper 自身にも期限がある: helper の exec 期限 +
//! [`REAPER_HARD_MARGIN`]。超えたら合図なしで helper を SIGKILL する。reaper が終わるまでの待ちは supervisor が
//! 有界にし、終わらなければ `Child` を保持して新しい helper の生成を止める（`exec_probe`）。
//!
//! # 終了コード
//! helper が成功（0）で終わり、孤児もすべて回収できたら 0。それ以外は 1。結果は helper が fd 2 に書いた行が正で、
//! reaper の終了コードは「異常終了していないか」の判定にだけ使う。

use std::ffi::{OsStr, OsString};
use std::io::Read as _;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::process::{Child, ExitCode, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use fandhe_container_core::exec::{ChildSubreaper, ContainerChild};

use super::exec_helper::{HealthExecArgs, self_exe_command};

/// reaper を起動するサブコマンド名（bin の第 1 引数）。
pub const HEALTH_REAPER_SUBCOMMAND: &str = "healthcheck-reaper";

/// reaper の `argv[0]`（固定）。
pub const HEALTH_REAPER_ARG0: &str = "fandhe-container-supervisor";

/// 止める合図を受けられなかった場合の備え: helper の exec 期限に足す、reaper 自身の期限の余裕。
pub const REAPER_HARD_MARGIN: Duration = Duration::from_secs(10);

/// 子の確認・回収の刻み（`/proc` の子の一覧の読み取りと `waitpid(WNOHANG)` だけで軽い）。
const REAPER_STEP: Duration = Duration::from_millis(20);

/// bin の main が reaper へ振り分ける呼び出しか（第 1 引数が `healthcheck-reaper`）。
pub fn is_health_reaper_invocation(first: Option<&OsStr>) -> bool {
    first == Some(OsStr::new(HEALTH_REAPER_SUBCOMMAND))
}

/// 回収ループが使う操作（実体は [`RealOps`]。単体試験は偽物を注入する）。
trait ReaperOps {
    /// 止める合図が来たか、reaper 自身の期限を過ぎたか（一度 `true` になったら `true` のまま）。
    fn should_stop(&mut self) -> bool;
    /// helper に SIGKILL を送る（回収前の `Child` に対してだけ。ループは 1 回しか呼ばない）。
    fn kill_helper(&mut self);
    /// helper が終わっていれば回収して `Some(成功したか)`。
    fn poll_helper(&mut self) -> Option<bool>;
    /// helper 以外の現在の子（再親付けされた孤児）の pid。
    fn orphans(&mut self) -> Vec<u32>;
    /// 孤児 `pid` を 1 回だけ回収する（待たない）。
    fn reap(&mut self, pid: u32);
    /// 刻みの待ち。
    fn pause(&mut self);
}

/// helper を fork した後の回収ループ。戻り値は「helper が成功で終わったか」。孤児がすべて回収されるまで戻らない。
fn reap_loop(ops: &mut dyn ReaperOps) -> bool {
    let mut killed = false;
    let mut helper: Option<bool> = None;
    loop {
        if !killed && ops.should_stop() {
            ops.kill_helper();
            killed = true;
        }
        if helper.is_none() {
            helper = ops.poll_helper();
        }
        let orphans = ops.orphans();
        for pid in &orphans {
            ops.reap(*pid);
        }
        // 子が残っていなければ（`ECHILD` 相当）終わる。回収した直後の再確認で、同じ刻みの間に再親付けされた孤児も拾う。
        if let Some(success) = helper
            && ops.orphans().is_empty()
        {
            return success;
        }
        ops.pause();
    }
}

/// 本番の操作。
struct RealOps {
    helper: Child,
    helper_pid: u32,
    helper_done: bool,
    /// 止める合図の監視スレッド（[`spawn_stop_watcher`]）が立てるフラグ。
    stop_flag: Arc<AtomicBool>,
    stopped: bool,
    hard_deadline: Instant,
    proof: ChildSubreaper,
}

impl ReaperOps for RealOps {
    fn should_stop(&mut self) -> bool {
        if self.stopped {
            return true;
        }
        if Instant::now() >= self.hard_deadline {
            self.stopped = true;
            return true;
        }
        if self.stop_flag.load(Ordering::Acquire) {
            self.stopped = true;
        }
        self.stopped
    }

    fn kill_helper(&mut self) {
        // 回収前の `Child` に対してだけ送る（std は回収済みなら何もしない）。
        let _ = self.helper.kill();
    }

    fn poll_helper(&mut self) -> Option<bool> {
        match self.helper.try_wait() {
            Ok(Some(status)) => {
                self.helper_done = true;
                Some(status.success())
            }
            Ok(None) => None,
            // 待ちの失敗は異常終了として扱う（子が無くなった = 回収済みの可能性もあるため、終了を確定する）。
            Err(_) => {
                self.helper_done = true;
                Some(false)
            }
        }
    }

    fn orphans(&mut self) -> Vec<u32> {
        let me = std::process::id();
        let mut pids = list_children(me);
        // helper 自身は `poll_helper` が回収する。
        if !self.helper_done {
            pids.retain(|p| *p != self.helper_pid);
        }
        pids
    }

    fn reap(&mut self, pid: u32) {
        // 孤児は subreaper である自分の子。pid 指定の `waitpid(WNOHANG)`（`wait_for_exit(0)`）で回収し、`waitpid(-1)` は
        // 使わない。pidfd は回収前に開くので、pid が再利用されても元の子を指す。
        if let Some(nz) = std::num::NonZeroU32::new(pid) {
            let child = ContainerChild::adopt_reparented(nz, &self.proof);
            let _ = child.wait_for_exit(Duration::ZERO);
        }
    }

    fn pause(&mut self) {
        std::thread::sleep(REAPER_STEP);
    }
}

/// 止める合図の監視スレッドを起こす。`stop` を **ブロッキングのまま** 読み、1 バイト以上・EOF・読み取りエラー
/// （制御を失ったので止める側へ倒す）のいずれでも戻り値のフラグを立てて終わる。`stop` は fd 2 の複製で、同じファイル
/// 記述を helper も継承しているため、ここでフラグ（`O_NONBLOCK`）を変えない（SUP-4・REPAIR-5・#2441）。スレッドは
/// join せず、reaper のプロセス終了で消える。
fn spawn_stop_watcher(mut stop: UnixStream) -> std::io::Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    let setter = Arc::clone(&flag);
    std::thread::Builder::new()
        .name("reaper-stop".to_owned())
        .spawn(move || {
            let mut buf = [0u8; 16];
            loop {
                match stop.read(&mut buf) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    _ => break,
                }
            }
            setter.store(true, Ordering::Release);
        })?;
    Ok(flag)
}

/// `pid` の現在の子の pid 一覧。`/proc/<pid>/task/<tid>/children`（`CONFIG_PROC_CHILDREN`）が無ければ `/proc` を走査する。
fn list_children(pid: u32) -> Vec<u32> {
    if let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")) {
        return text
            .split_whitespace()
            .filter_map(|t| t.parse().ok())
            .collect();
    }
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in dir.flatten() {
        let Some(child) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{child}/stat")) else {
            continue;
        };
        if super::exec_helper::parse_stat_ppid(&stat) == Some(pid) {
            out.push(child);
        }
    }
    out
}

/// reaper の入口。`args` はサブコマンド名を除いた引数列（helper の引数と同じ。そのまま helper へ渡す）。
/// helper が成功で終わり孤児もすべて回収できたら 0、それ以外は 1。
pub fn run_health_reaper_main<I>(args: I) -> ExitCode
where
    I: IntoIterator<Item = OsString>,
{
    // 継承 fd の整理が最初。fd 0〜2 は supervisor の `Command` が置いたものだけを使う。
    let _ = crate::sys::close_fds_from(3);
    let _ = crate::sys::set_dumpable(false);
    let helper_args: Vec<OsString> = args.into_iter().collect();
    // 引数は helper が検証し直す。ここでは期限を知るためと、不正な引数で helper を起動しないために解釈する。
    let Ok(parsed) = HealthExecArgs::parse(helper_args.clone()) else {
        return ExitCode::FAILURE;
    };
    // 孤児の受け皿になる。立てられなければ helper を起動しない（fail-closed。子孫の再親付けを閉じられないため）。
    let Ok(proof) = ChildSubreaper::enable() else {
        return ExitCode::FAILURE;
    };
    // 止める合図の受け口は fd 2 の複製（結果チャネルの子側。helper は同じ fd をそのまま継承する）。
    let Ok(stop) = std::io::stderr()
        .as_fd()
        .try_clone_to_owned()
        .map(UnixStream::from)
    else {
        return ExitCode::FAILURE;
    };
    // 監視スレッドは helper の起動前に起こす（起こせなければ helper を作らず失敗にする）。早く合図が立てば、
    // 最初のループで helper を SIGKILL するだけで、起動後に立てた場合と同じ。
    let Ok(stop_flag) = spawn_stop_watcher(stop) else {
        return ExitCode::FAILURE;
    };
    let mut command = self_exe_command(super::exec_helper::HEALTH_EXEC_SUBCOMMAND, &helper_args);
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let Ok(helper) = command.spawn() else {
        return ExitCode::FAILURE;
    };
    let helper_pid = helper.id();
    let mut ops = RealOps {
        helper,
        helper_pid,
        helper_done: false,
        stop_flag,
        stopped: false,
        hard_deadline: Instant::now() + parsed.timeout() + REAPER_HARD_MARGIN,
        proof,
    };
    if reap_loop(&mut ops) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// 偽の操作。`orphan_script` は `orphans()` の呼び出しごとの戻り（尽きたら空）。
    struct Fake {
        stop_after_ticks: Option<u32>,
        hard: bool,
        ticks: u32,
        helper_exit_at_tick: Option<(u32, bool)>,
        killed: u32,
        kill_makes_helper_exit: bool,
        helper_status: Option<bool>,
        orphan_script: VecDeque<Vec<u32>>,
        reaped: Vec<u32>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                stop_after_ticks: None,
                hard: false,
                ticks: 0,
                helper_exit_at_tick: None,
                killed: 0,
                kill_makes_helper_exit: false,
                helper_status: None,
                orphan_script: VecDeque::new(),
                reaped: Vec::new(),
            }
        }
    }

    impl ReaperOps for Fake {
        fn should_stop(&mut self) -> bool {
            self.hard || self.stop_after_ticks.is_some_and(|t| self.ticks >= t)
        }
        fn kill_helper(&mut self) {
            self.killed += 1;
            if self.kill_makes_helper_exit {
                self.helper_exit_at_tick = Some((self.ticks, false));
            }
        }
        fn poll_helper(&mut self) -> Option<bool> {
            if let Some((t, ok)) = self.helper_exit_at_tick
                && self.ticks >= t
            {
                self.helper_status = Some(ok);
            }
            self.helper_status
        }
        fn orphans(&mut self) -> Vec<u32> {
            self.orphan_script.pop_front().unwrap_or_default()
        }
        fn reap(&mut self, pid: u32) {
            self.reaped.push(pid);
        }
        fn pause(&mut self) {
            self.ticks += 1;
            assert!(self.ticks < 1000, "the reap loop did not terminate");
        }
    }

    /// SUP-4・REPAIR-5（#2441）: helper が先に終わっても、再親付けされた孤児を回収してから終わる。
    #[test]
    fn repair5_2441_reaper_reaps_reparented_orphans_before_exiting() {
        let mut f = Fake::new();
        f.helper_exit_at_tick = Some((1, true));
        // 毎ループ 2 回呼ばれる `orphans()`（回収用・終了確認用）の戻り。孤児 77 が数刻み残ってから消える。
        f.orphan_script = VecDeque::from(vec![
            vec![],
            vec![],
            vec![77],
            vec![77],
            vec![77, 78],
            vec![78],
            vec![],
            vec![],
        ]);
        assert!(reap_loop(&mut f));
        assert_eq!(f.killed, 0);
        assert!(f.reaped.contains(&77), "{:?}", f.reaped);
        assert!(f.reaped.contains(&78), "{:?}", f.reaped);
    }

    /// SUP-4・REPAIR-5（#2441）: 止める合図で helper を SIGKILL（1 回だけ）し、孤児を回収し切ってから終わる。
    /// helper が殺されて失敗扱いになるので戻り値は `false`。
    #[test]
    fn repair5_2441_reaper_stop_signal_kills_helper_once_then_reaps_everything() {
        let mut f = Fake::new();
        f.stop_after_ticks = Some(2);
        f.kill_makes_helper_exit = true;
        f.orphan_script = VecDeque::from(vec![
            vec![5],
            vec![5],
            vec![5],
            vec![5],
            vec![5, 6],
            vec![5, 6],
            vec![6],
            vec![6],
            vec![],
            vec![],
        ]);
        assert!(!reap_loop(&mut f));
        assert_eq!(f.killed, 1);
        assert!(
            f.reaped.contains(&5) && f.reaped.contains(&6),
            "{:?}",
            f.reaped
        );
    }

    /// REPAIR-5（#2441）: reaper 自身の期限（合図が来ない場合）でも helper を SIGKILL して終わる。
    #[test]
    fn repair5_2441_reaper_hard_deadline_kills_helper_without_a_signal() {
        let mut f = Fake::new();
        f.hard = true;
        f.kill_makes_helper_exit = true;
        assert!(!reap_loop(&mut f));
        assert_eq!(f.killed, 1);
    }

    /// 孤児が無く helper が成功で終われば、そのまま `true`。
    #[test]
    fn sup4_2441_reaper_returns_helper_success_when_nothing_is_left() {
        let mut f = Fake::new();
        f.helper_exit_at_tick = Some((0, true));
        assert!(reap_loop(&mut f));
        assert_eq!(f.killed, 0);
        assert!(f.reaped.is_empty());
    }

    /// SUP-4・REPAIR-5（#2441）: 監視スレッドは fd の記述に `O_NONBLOCK` を立てない（helper と共有されるため）。
    /// 合図の 1 バイトでも、相手の端が閉じる（EOF）でも、フラグが立つ。
    #[test]
    fn repair5_2441_stop_watcher_keeps_description_blocking_and_flags_on_byte_or_eof() {
        use std::io::Write as _;
        use std::os::fd::AsRawFd as _;
        const O_NONBLOCK: u32 = 0o4000;
        let wait_for = |flag: &Arc<AtomicBool>| {
            let until = Instant::now() + Duration::from_secs(10);
            while !flag.load(Ordering::Acquire) && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
            flag.load(Ordering::Acquire)
        };
        let flags_of = |fd: i32| -> u32 {
            let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).expect("fdinfo");
            let line = text
                .lines()
                .find_map(|l| l.strip_prefix("flags:"))
                .expect("flags line");
            u32::from_str_radix(line.trim(), 8).expect("octal flags")
        };
        // 1 バイトの合図。
        let (mut sup, child_side) = UnixStream::pair().expect("pair");
        let raw = child_side.as_raw_fd();
        let flag = spawn_stop_watcher(child_side.try_clone().expect("clone")).expect("spawn");
        assert_eq!(
            flags_of(raw) & O_NONBLOCK,
            0,
            "O_NONBLOCK leaked to the shared description"
        );
        assert!(!flag.load(Ordering::Acquire));
        sup.write_all(b"x").expect("write");
        assert!(wait_for(&flag));
        // 端が閉じる（EOF）。
        let (sup2, child_side2) = UnixStream::pair().expect("pair");
        let flag2 = spawn_stop_watcher(child_side2.try_clone().expect("clone")).expect("spawn");
        assert_eq!(flags_of(child_side2.as_raw_fd()) & O_NONBLOCK, 0);
        assert!(!flag2.load(Ordering::Acquire));
        drop(sup2);
        assert!(wait_for(&flag2));
    }

    #[test]
    fn sup4_2441_reaper_invocation_detection() {
        assert!(is_health_reaper_invocation(Some(OsStr::new(
            "healthcheck-reaper"
        ))));
        assert!(!is_health_reaper_invocation(Some(OsStr::new(
            "healthcheck-exec"
        ))));
        assert!(!is_health_reaper_invocation(None));
    }
}
