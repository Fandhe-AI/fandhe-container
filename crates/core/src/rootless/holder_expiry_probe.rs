//! holder の期限切れ後始末を、本番と同じ namespace 構成で観測する試験専用の入口
//! (CORE-6・SEC-5・REPAIR-5・#2551)。`exec-test-support` feature を付けたビルドにだけ存在する。
//!
//! 単体試験の `sec5_holder_expiry_real_kill_ends_stopped_session` は同じ user namespace の子を止めるだけで、
//! `unshare(CLONE_NEWUSER)` 済みの本番 holder([`super::run_userns_holder`])を通らない。本入口は次を実プロセスで通す。
//!
//! - holder: 本番の `run_userns_holder`。別 user namespace に居るまま、外側の mapper のセッションへ SIGKILL を送る
//! - mapper: `setsid` 済みのセッションリーダー(`MapperPid` で錨にされる)。helper(同じセッションの子)と socket の複製を持つ
//! - 中間プロセス I: 呼び出し元。READY を受け、`MapperPid` を送り、錨の応答を受けた後に SIGKILL で消える
//! - helper: SIGSTOP で止められ、holder が kill しない限り socket の複製を握り続ける
//!
//! 呼び出し側は単一スレッドの `main`(`harness = false`)でなければならない(fork の健全性条件)。
//! 実機前提(非特権 user namespace を許可するホスト)。入口は `tests/rootless_holder_expiry.rs` だけが使う。

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::{
    HolderControl, MAPPER_REPLY_LEN, MapperPid, MapperReply, ProcHandle, SessionProbe, TargetPid,
    run_userns_holder,
};
use crate::sys;

/// 観測結果(値はすべて生の観測値。判定は呼び出し側の試験が具体値で行う)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolderExpiryObservation {
    /// holder の pid。
    pub holder_pid: u32,
    /// mapper(セッションリーダー)の pid。
    pub mapper_pid: u32,
    /// helper の pid。
    pub helper_pid: u32,
    /// 呼び出し元(I)を SIGKILL で消してから、期限前の確認までに経過した時間。
    pub midpoint_after_caller_exit: Duration,
    /// その時点で holder が生きていたか。
    pub holder_alive_at_midpoint: bool,
    /// その時点の helper の `/proc/<pid>/stat` の state(止められていれば `T`)。読めなければ `None`。
    pub helper_state_at_midpoint: Option<char>,
    /// 呼び出し元の終了から holder の終了までに掛かった時間。
    pub holder_exit_after_caller_exit: Duration,
    /// holder の wait status(生の値)。
    pub holder_status: i32,
    /// holder の終了を観測した直後に回収できた mapper の wait status(生の値)。
    pub mapper_status: Option<i32>,
    /// holder の終了を観測した直後に回収できた helper の wait status(生の値)。
    pub helper_status: Option<i32>,
}

fn fail(m: &str) -> String {
    format!("holder expiry probe: {m}")
}

/// 中間プロセス I の本体。成功なら 3 つの pid を `report` へ書いて待ち続ける(呼び出し元の SIGKILL で終わる)。
fn caller_process(
    ctl: UnixStream,
    holder_end: UnixStream,
    mut report: UnixStream,
    release_wait: Duration,
    drain_wait: Duration,
) -> Result<(), String> {
    let me = std::process::id();
    let timeout = Duration::from_secs(10);
    let holder_pid = sys::fork_single_threaded(
        move || {
            run_userns_holder(
                me,
                holder_end,
                timeout,
                release_wait,
                drain_wait,
                &mut std::io::sink(),
            )
        },
        70,
    )
    .map_err(|e| fail(&format!("fork holder: {e:?}")))?;
    // 後始末のため、起動した子の pid を判明した順に親へ報告する(失敗しても親が未回収の子を漏れなく回収できる)。
    report
        .write_all(&holder_pid.to_be_bytes())
        .map_err(|e| fail(&e.to_string()))?;
    let mut ctl = ctl;
    ctl.set_read_timeout(Some(timeout))
        .map_err(|e| fail(&e.to_string()))?;
    let mut buf = [0u8; MAPPER_REPLY_LEN];
    ctl.read_exact(&mut buf)
        .map_err(|e| fail(&format!("holder ready: {e}")))?;
    if MapperReply::decode(&buf) != Ok(MapperReply::Ok) {
        return Err(fail("holder did not report ready"));
    }
    // mapper: `setsid` 済みで、socket の複製を fd 3 に持つ。helper は同じセッションに居て同じ複製を持つ。
    let dup = ctl.try_clone().map_err(|e| fail(&e.to_string()))?;
    let mut mapper = Command::new("setsid")
        .args(["sh", "-c", "exec 3<&0; sleep 120 & echo $!; exec sleep 120"])
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(dup)))
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| fail(&format!("spawn mapper: {e}")))?;
    let mapper_pid = mapper.id();
    let mut line = String::new();
    BufReader::new(
        mapper
            .stdout
            .take()
            .ok_or_else(|| fail("no mapper stdout"))?,
    )
    .read_line(&mut line)
    .map_err(|e| fail(&format!("helper pid: {e}")))?;
    let helper_pid: u32 = line
        .trim()
        .parse()
        .map_err(|_| fail("helper pid not a number"))?;
    report
        .write_all(&[mapper_pid.to_be_bytes(), helper_pid.to_be_bytes()].concat())
        .map_err(|e| fail(&e.to_string()))?;
    let handle = ProcHandle::open(TargetPid::new(mapper_pid).map_err(|e| fail(&e.to_string()))?)
        .map_err(|e| fail(&e.to_string()))?;
    let t = Instant::now();
    while handle.session_probe() != SessionProbe::Session(mapper_pid) {
        if t.elapsed() > Duration::from_secs(5) {
            return Err(fail("mapper did not become a session leader"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let frame =
        HolderControl::MapperPid(MapperPid::new(mapper_pid).map_err(|e| fail(&e.to_string()))?);
    ctl.write_all(&frame.encode())
        .map_err(|e| fail(&e.to_string()))?;
    ctl.read_exact(&mut buf)
        .map_err(|e| fail(&format!("anchor reply: {e}")))?;
    if MapperReply::decode(&buf) != Ok(MapperReply::Ok) {
        return Err(fail("holder did not anchor the mapper"));
    }
    // 準備完了の合図(1 バイト)。
    report.write_all(&[1]).map_err(|e| fail(&e.to_string()))?;
    // 呼び出し元の SIGKILL を待つ(上限つき)。
    std::thread::sleep(Duration::from_secs(60));
    Ok(())
}

fn proc_state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.get(stat.rfind(')')? + 1..)?
        .split_whitespace()
        .next()?
        .chars()
        .next()
}

/// 子 `pid` の終了を `limit` まで待って wait status を返す(上限つき。REPAIR-5)。
fn wait_until(pid: u32, limit: Duration) -> Option<i32> {
    let t = Instant::now();
    while t.elapsed() < limit {
        if let Ok(Some(s)) = sys::wait_pid_nohang(pid) {
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    None
}

/// まだ回収していない自分の子の pid の集合(#2551)。回収済みの pid は番号が再利用され得るため、cleanup が
/// シグナルを送る対象から外す(無関係な同一 UID のプロセスを終了させない)。
struct LiveChildren(std::cell::RefCell<Vec<u32>>);

impl LiveChildren {
    fn new(pids: &[u32]) -> Self {
        Self(std::cell::RefCell::new(pids.to_vec()))
    }

    /// 起動した未回収の子 `pid` を集合へ加える。
    fn add(&self, pid: u32) {
        self.0.borrow_mut().push(pid);
    }

    /// 回収した `pid` を集合から外す。
    fn reaped(&self, pid: u32) {
        self.0.borrow_mut().retain(|p| *p != pid);
    }

    /// `pid` の終了を `limit` まで待ち、回収できたら集合から外して wait status を返す。
    fn wait(&self, pid: u32, limit: Duration) -> Option<i32> {
        let status = wait_until(pid, limit);
        if status.is_some() {
            self.reaped(pid);
        }
        status
    }

    /// 未回収の子だけに SIGKILL を送り、回収する(回収済みの pid へは送らない)。
    fn kill_and_reap(&self) {
        let pids = std::mem::take(&mut *self.0.borrow_mut());
        for p in pids {
            let _ = sys::kill_pid(p, sys::Signal::Kill);
            let _ = wait_until(p, Duration::from_secs(2));
        }
    }
}

/// 期限切れの再現を実行して観測する。呼び出しプロセスを child subreaper にする(孤児になった holder・mapper・
/// helper を `waitpid` で回収するため)。`release_wait` は 3 秒以上を推奨する(準備の時間が食い込むと期限前の確認が崩れる)。
pub fn observe_holder_expiry(
    release_wait: Duration,
    drain_wait: Duration,
) -> Result<HolderExpiryObservation, String> {
    sys::set_child_subreaper(true).map_err(|e| fail(&format!("subreaper: {e:?}")))?;
    let (ctl, holder_end) = UnixStream::pair().map_err(|e| fail(&e.to_string()))?;
    let (mut report_rd, report_wr) = UnixStream::pair().map_err(|e| fail(&e.to_string()))?;
    let caller = sys::fork_single_threaded(
        move || match caller_process(ctl, holder_end, report_wr, release_wait, drain_wait) {
            Ok(()) => 0,
            Err(m) => {
                let _ = writeln!(std::io::stderr(), "{m}");
                71
            }
        },
        72,
    )
    .map_err(|e| fail(&format!("fork caller: {e:?}")))?;
    report_rd
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| fail(&e.to_string()))?;
    // 子の pid は判明した順に届く。未回収の自分の子の集合は caller の fork 直後から持ち、どの段階で失敗しても
    // 期限つきで停止・回収する(caller を先に消して回収し、孤児になった holder・mapper・helper を subreaper の
    // 自分の子として回収する)。
    let live = LiveChildren::new(&[caller]);
    let cleanup = || live.kill_and_reap();
    let mut pids = [0u8; 12];
    if let Err(e) = report_rd.read_exact(&mut pids[..4]) {
        cleanup();
        return Err(fail(&format!("caller did not report the holder: {e}")));
    }
    let pid_at = |b: &[u8; 12], i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    let holder_pid = pid_at(&pids, 0);
    live.add(holder_pid);
    if let Err(e) = report_rd.read_exact(&mut pids[4..]) {
        cleanup();
        return Err(fail(&format!("caller did not report the mapper: {e}")));
    }
    let (mapper_pid, helper_pid) = (pid_at(&pids, 4), pid_at(&pids, 8));
    live.add(mapper_pid);
    live.add(helper_pid);
    let mut ready = [0u8; 1];
    if let Err(e) = report_rd.read_exact(&mut ready) {
        cleanup();
        return Err(fail(&format!("caller did not report ready: {e}")));
    }
    // helper と mapper を止め、呼び出し元を消す。以降、holder が止めない限り helper は socket を握り続ける。
    let stop = std::num::NonZeroU8::new(19).ok_or_else(|| fail("signal"))?;
    for p in [helper_pid, mapper_pid] {
        if let Err(e) = sys::kill_pid(p, sys::Signal::Number(stop)) {
            cleanup();
            return Err(fail(&format!("SIGSTOP: {e:?}")));
        }
    }
    let t0 = Instant::now();
    if let Err(e) = sys::kill_pid(caller, sys::Signal::Kill) {
        cleanup();
        return Err(fail(&format!("kill caller: {e:?}")));
    }
    if live.wait(caller, Duration::from_secs(5)).is_none() {
        cleanup();
        return Err(fail("caller was not reaped"));
    }
    // 期限(release_wait)が来る前に、holder は生きていて helper は止まったままのはず。
    std::thread::sleep(Duration::from_millis(500));
    let midpoint = t0.elapsed();
    let holder_alive_at_midpoint = match sys::wait_pid_nohang(holder_pid) {
        Ok(None) => true,
        // 回収できてしまった場合は集合から外し、cleanup が回収済みの pid へ送らないようにする。
        Ok(Some(_)) => {
            live.reaped(holder_pid);
            false
        }
        Err(_) => false,
    };
    let helper_state_at_midpoint = proc_state(helper_pid);
    // holder の終了を待つ(期限 + 待ち切り + 余裕)。
    let limit = release_wait + drain_wait + Duration::from_secs(10);
    let Some(holder_status) = live.wait(holder_pid, limit) else {
        cleanup();
        return Err(fail("holder did not exit within the bounded wait"));
    };
    let holder_exit_after_caller_exit = t0.elapsed();
    // holder が終わった時点で、止められていた mapper と helper は既に SIGKILL で終わっているはず。
    let mapper_status = live.wait(mapper_pid, Duration::from_millis(500));
    let helper_status = live.wait(helper_pid, Duration::from_millis(500));
    cleanup();
    Ok(HolderExpiryObservation {
        holder_pid,
        mapper_pid,
        helper_pid,
        midpoint_after_caller_exit: midpoint,
        holder_alive_at_midpoint,
        helper_state_at_midpoint,
        holder_exit_after_caller_exit,
        holder_status,
        mapper_status,
        helper_status,
    })
}
