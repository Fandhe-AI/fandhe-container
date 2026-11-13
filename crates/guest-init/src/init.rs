//! Linux ゲストの PID 1 としての起動シーケンスと [`GuestOps`] の実装（MAC-1・MAC-2・TASK-64 追補）。
//!
//! bin の入口（`main.rs`）から [`run`] だけが呼ばれる。mount は `sys` の安全なラッパー経由で（virtiofs の
//! mount 先は fd で固定する。#2268）、
//! 指示の復号・報告は OS 非依存の `directive`・`process`・`report` が、試験用プローブは `probe` が担う。
//!
//! どの経路でも終了しない（PID 1 が終了するとカーネルが panic する）。panic も [`install_panic_hook`] の
//! hook が待機へ落とす（#2139）。唯一の例外は PID 1 でないとき（ホストでの誤実行）で、何も mount せずに終了する。
//!
//! 協調停止（MAC-4・#2270）: `run` の冒頭でスレッドを作る前に `SIGCHLD`・`SIGTERM`・`SIGPWR` をブロックし、
//! ready の後の回収ループが `sigtimedwait` で子の終了と停止要求を受ける。停止要求で回収ループが戻ると
//! `shutdown::run`（全プロセスの停止 → `sync` → `reboot(RB_POWER_OFF)`）へ進む。power button の監視
//! スレッド（[`start_power_button_watchers`]）は VZ の `requestStop` が届けるキー入力を `SIGPWR` に変える。

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

use crate::cmdline::{MAX_CMDLINE_BYTES, read_bounded};
use crate::directive::{Access, Directive, GUEST_MOUNT_BASE, MountPoint};
use crate::link_probe::{RO_MOUNT, RW_MOUNT, link_plan, run_virtiofs_link};
use crate::mountinfo::{MAX_MOUNTINFO_BYTES, check_dev_hardened};
use crate::power_button::{self, MAX_INPUT_DEVICES};
use crate::probe::{GUEST_MOUNT, decode_test_mode, probe_plan, run_virtiofs_io};
use crate::process::{GuestOps, emit_ready, process_directives};
use crate::reap::{
    ChildWaiter, Event, MAX_REAP_BATCH, WaitResult, decode_wait_status, drain, reap_forever,
    reap_until_stop,
};
use crate::report::{Errno, InitStage, ReportLine};
use crate::shutdown::{self, ShutdownOps, Signal, SignalOutcome};
use crate::sys;

struct LinuxOps {
    console: Box<dyn Write>,
}

impl GuestOps for LinuxOps {
    type MountTarget = OwnedFd;

    fn ensure_mount_point(&mut self, mount_point: &MountPoint) -> Result<OwnedFd, Errno> {
        let root = sys::open_root_dir().map_err(|e| Errno::from_io(&e))?;
        open_mount_target(
            root.as_fd(),
            GUEST_MOUNT_BASE.split('/').filter(|s| !s.is_empty()),
            mount_point.elements(),
        )
    }

    fn mount_virtiofs(&mut self, target: OwnedFd, d: &Directive) -> Result<(), Errno> {
        // nosuid・nodev・`ro` なら MS_RDONLY は sys 側の固定値（呼び出し元は外せない）。
        // mount 先は ensure_mount_point が開いた fd で、文字列パスは引き直さない（#2268・#2080 P2-4）。
        // `target` は mount の後に drop して閉じる。
        sys::mount_virtiofs_at(d.tag.as_str(), target.as_fd(), d.access == Access::ReadOnly)
            .map_err(|e| Errno::from_io(&e))
    }

    fn write_line(&mut self, line: &ReportLine) {
        write_console_line(&mut self.console, line);
    }
}

/// 1 行ずつ書いて flush する。失敗は無視する（報告先が無く、ホストはタイムアウトで fail-closed になる）。
fn write_console_line(console: &mut dyn Write, line: &ReportLine) {
    let _ = writeln!(console, "{}", line.as_str());
    let _ = console.flush();
}

/// mount 先を `root` から要素ごとに `openat(O_NOFOLLOW)` で辿って fd で固定する（MAC-1・SEC-1・#2268）。
///
/// `base`（`/mnt/fandhe` の要素）は `init_filesystems` が作成済みなので作らず開くだけにし、`elements`
/// （指示の mount point の要素）は欠けていれば `mkdirat` で作る。symlink・通常ファイルの要素は
/// `ENOTDIR` で失敗し、symlink の先には何も作らない。呼び出し元は `LinuxOps::ensure_mount_point`。
/// 途中の fd はループで置き換わるたびに閉じ、最後の 1 本だけを返す。
fn open_mount_target<'a>(
    root: BorrowedFd<'_>,
    base: impl Iterator<Item = &'a str>,
    elements: impl Iterator<Item = &'a str>,
) -> Result<OwnedFd, Errno> {
    let mut cur: Option<OwnedFd> = None;
    for name in base {
        let parent = cur.as_ref().map_or(root, |f| f.as_fd());
        let next = sys::open_child_dir(parent, name).map_err(|e| Errno::from_io(&e))?;
        cur = Some(next);
    }
    for name in elements {
        let parent = cur.as_ref().map_or(root, |f| f.as_fd());
        match sys::mkdir_child(parent, name) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(Errno::from_io(&e)),
        }
        let next = sys::open_child_dir(parent, name).map_err(|e| Errno::from_io(&e))?;
        cur = Some(next);
    }
    match cur {
        Some(f) => Ok(f),
        // 要素が 0 件（MountPoint の検証上は起きない）。root 自身を mount 先にしない。
        None => Err(Errno::EINVAL),
    }
}

/// hvc0（契約の報告先）→ /dev/console → 継承した stdout の順に開く。
fn open_console() -> Box<dyn Write> {
    for path in ["/dev/hvc0", "/dev/console"] {
        if let Ok(f) = OpenOptions::new()
            .write(true)
            .custom_flags(sys::O_NOCTTY)
            .open(path)
        {
            return Box::new(f);
        }
    }
    Box::new(std::io::stdout())
}

/// `/dev` への devtmpfs の mount 結果の分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DevMount {
    /// 新しく mount でき、init が flags を付けた。
    Fresh,
    /// `EBUSY`。既存の mount があり flags は未確認（`/proc` の後に `verify_existing_dev` で確かめる）。
    AlreadyMounted,
}

/// devtmpfs の mount 結果を分類する。EBUSY を成功扱いにはせず、検査が必要な状態として返す（#2139）。
fn classify_dev_mount(r: std::io::Result<()>) -> Result<DevMount, Errno> {
    match r {
        Ok(()) => Ok(DevMount::Fresh),
        Err(e) if e.raw_os_error() == Some(i32::from(Errno::EBUSY.get())) => {
            Ok(DevMount::AlreadyMounted)
        }
        Err(e) => Err(Errno::from_io(&e)),
    }
}

/// 既存の `/dev` が `devtmpfs`＋`nosuid`＋`noexec` であることを mountinfo で確かめる。`/proc` の mount 後に呼ぶ。
fn verify_existing_dev() -> Result<(), Errno> {
    let text = File::open("/proc/self/mountinfo")
        .map_err(crate::cmdline::CmdlineError::Io)
        .and_then(|f| read_bounded(f, MAX_MOUNTINFO_BYTES))
        .map_err(|e| e.errno())?;
    check_dev_hardened(&text, "/dev").map_err(|_| Errno::EBUSY)
}

/// panic を待機へ落とす hook を入れる。PID 1 の終了（カーネルの panic）を避け、固定の 1 行だけを出す。
///
/// payload・位置は untrusted な値を含みうるため出さない（REPAIR-2）。hook 自身は panic しない形に保つ。
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|_| {
        let mut console = open_console();
        write_console_line(
            &mut console,
            &ReportLine::init_error(InitStage::Panic, Errno::EIO),
        );
        idle()
    }));
}

fn init_filesystems() -> Result<(), (InitStage, Errno)> {
    for dir in ["/proc", "/sys", "/dev", GUEST_MOUNT_BASE] {
        fs::create_dir_all(dir).map_err(|e| (InitStage::Dev, Errno::from_io(&e)))?;
    }
    Ok(())
}

/// [`ChildWaiter`] の本番実装。`waitpid(-1)` と `sigtimedwait` は `sys` の安全なラッパー、失敗後の間は
/// `std::thread::sleep`。
struct LinuxWaiter;

impl ChildWaiter for LinuxWaiter {
    fn wait_any(&mut self, nohang: bool) -> WaitResult {
        match sys::wait_any_child(nohang) {
            Ok(Some((pid, raw))) => WaitResult::Reaped {
                pid,
                status: decode_wait_status(raw),
            },
            Ok(None) => WaitResult::NothingReady,
            Err(e) => match e.raw_os_error() {
                Some(sys::ECHILD) => WaitResult::NoChildren,
                Some(sys::EINTR) => WaitResult::Interrupted,
                _ => WaitResult::Failed(Errno::from_io(&e)),
            },
        }
    }

    fn wait_event(&mut self, timeout: Duration) -> Event {
        match sys::wait_signal(timeout) {
            sys::SignalWait::Child => Event::Child,
            sys::SignalWait::Stop => Event::Stop,
            sys::SignalWait::Timeout => Event::Timeout,
            sys::SignalWait::Interrupted => Event::Interrupted,
            sys::SignalWait::Other(n) => Event::Failed(Errno::new(n)),
        }
    }

    fn pause(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// [`ShutdownOps`] の本番実装。`sys` の安全なラッパー（PID 1 以外では syscall を呼ばない）と hvc0 の診断行。
struct LinuxShutdownOps<'a> {
    ops: &'a mut LinuxOps,
}

impl ShutdownOps for LinuxShutdownOps<'_> {
    fn signal_others(&mut self, sig: Signal) -> SignalOutcome {
        let how = match sig {
            Signal::Term => sys::Escalation::Term,
            Signal::Kill => sys::Escalation::Kill,
        };
        match sys::signal_all_others(how) {
            Ok(()) => SignalOutcome::Sent,
            Err(e) if e.raw_os_error() == Some(sys::ESRCH) => SignalOutcome::NoOthers,
            Err(e) => SignalOutcome::Failed(Errno::from_io(&e)),
        }
    }

    fn reap(&mut self) {
        let _ = drain(&mut LinuxWaiter, MAX_REAP_BATCH);
    }

    fn others_alive(&mut self) -> bool {
        sys::others_alive()
    }

    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }

    fn sync(&mut self) {
        sys::sync_all();
    }

    fn power_off(&mut self) -> Errno {
        Errno::from_io(&sys::power_off())
    }

    fn write_line(&mut self, line: &ReportLine) {
        self.ops.write_line(line);
    }
}

/// power button（`gpio-keys` が出す evdev の `KEY_POWER`）の監視スレッドを、開けた入力デバイスごとに
/// 1 本起動する（MAC-4・#2270）。VZ の `requestStop` は仮想 PL061 GPIO を介して届く想定で、実 VM での
/// 到達は未確認（#1628・#2282）。デバイスが無い・開けない場合は何もせず、停止はホストの期限つきの強制停止に
/// 任せる。デバイス数・スレッド数は [`MAX_INPUT_DEVICES`] まで。
fn start_power_button_watchers() {
    let mut opened = [false; MAX_INPUT_DEVICES];
    scan_power_buttons(&mut opened);
    // ドライバの遅延 probe でノードが後から現れることがある。開けたデバイスが電源ボタン対応かは
    // ここで判別できない（別の入力デバイスが先にあると gpio-keys を取りこぼす）ため、見つかった数に
    // 関わらず既定の探索期間中は未オープンのノードを上限つきで探索し続ける（REPAIR-5・MAC-4）。
    let _ = std::thread::Builder::new()
        .name("power-button-rescan".into())
        .spawn(move || {
            for _ in 0..POWER_BUTTON_RESCAN_TRIES {
                std::thread::sleep(POWER_BUTTON_RESCAN_INTERVAL);
                scan_power_buttons(&mut opened);
            }
        });
}

/// 再探索の間隔と回数の上限（合計 30 秒）。
const POWER_BUTTON_RESCAN_INTERVAL: Duration = Duration::from_millis(500);
const POWER_BUTTON_RESCAN_TRIES: u32 = 60;

/// 未オープンの入力ノードを開いて監視スレッドを立てる。立てた本数を返す。
fn scan_power_buttons(opened: &mut [bool]) -> usize {
    let mut started = 0;
    for (i, slot) in opened.iter_mut().enumerate() {
        if *slot {
            continue;
        }
        let path = power_button::device_path(i);
        let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(sys::O_CLOEXEC)
            .open(&path)
        else {
            continue;
        };
        *slot = true;
        let spawned = std::thread::Builder::new()
            .name(format!("power-button-{i}"))
            .spawn(move || {
                power_button::watch(file, || sys::request_stop().is_ok());
            });
        if spawned.is_ok() {
            started += 1;
        }
    }
    started
}

/// 待機（回収しない）。致命的な初期化失敗（子を作る前）と panic hook（中での二重 panic を避ける）の
/// 行き先で、回収ループには入らない。
fn idle() -> ! {
    // PID 1 は終了しない。停止要求（SIGTERM・SIGPWR）はブロック中で保留されるだけで応じず、停止はホストの
    // 期限つきの強制停止に任せる（fail-safe。MAC-4・#2270・REPAIR-3）。
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// ゲストの PID 1 として動作する。終了しない。
pub fn run() -> ! {
    if std::process::id() != 1 {
        eprintln!("fandhe-container-guest-init: must run as PID 1");
        std::process::exit(2);
    }
    // 停止要求と SIGCHLD をブロックする。スレッド（power button の監視など）を作る前に行い、以後の
    // スレッドへマスクを継承させる。失敗は致命にせず、console が開いてから診断を出す（回収は 1 秒刻みの
    // 待ちで続き、停止要求だけがホストの強制停止になる）。
    let signals = sys::block_lifecycle_signals();
    install_panic_hook();
    // /dev を先に用意して console を開けるようにする（以降の診断・報告を hvc0 へ出すため）。
    let dev = init_filesystems().and_then(|()| {
        classify_dev_mount(sys::mount_devtmpfs(Path::new("/dev"))).map_err(|e| (InitStage::Dev, e))
    });
    let mut ops = LinuxOps {
        console: open_console(),
    };
    let fatal = |ops: &mut LinuxOps, stage, errno| -> ! {
        ops.write_line(&ReportLine::init_error(stage, errno));
        idle()
    };
    if let Err(e) = signals {
        ops.write_line(&ReportLine::init_error(
            InitStage::Signals,
            Errno::from_io(&e),
        ));
    }
    let dev_mount = match dev {
        Ok(m) => m,
        Err((stage, errno)) => fatal(&mut ops, stage, errno),
    };
    if let Err(e) = sys::mount_proc(Path::new("/proc")) {
        fatal(&mut ops, InitStage::Proc, Errno::from_io(&e));
    }
    // EBUSY の /dev は init の flags を持つとは限らない。/proc が使えるようになってから確かめる。
    if dev_mount == DevMount::AlreadyMounted
        && let Err(e) = verify_existing_dev()
    {
        fatal(&mut ops, InitStage::Dev, e);
    }
    if let Err(e) = sys::mount_sysfs(Path::new("/sys")) {
        fatal(&mut ops, InitStage::Sys, Errno::from_io(&e));
    }
    let cmdline = match File::open("/proc/cmdline")
        .map_err(super::cmdline::CmdlineError::Io)
        .and_then(|f| read_bounded(f, MAX_CMDLINE_BYTES))
    {
        Ok(s) => s,
        Err(e) => fatal(&mut ops, InitStage::Cmdline, e.errno()),
    };
    let outcome = process_directives(&cmdline, &mut ops);
    // ホストは ready 直後に requestStop を出しうるため、入力デバイスを開いて監視を始めてから ready を出す
    // （取りこぼすと協調停止せず強制停止になる。MAC-4・#2270）。
    start_power_button_watchers();
    emit_ready(&mut ops);
    // 試験用プローブは ready の後（init 自身の責務の完了を遅らせない）。起動条件を満たさない本番の起動では何もしない。
    let mode = decode_test_mode(&cmdline);
    if let Some(plan) = probe_plan(mode, &outcome) {
        run_virtiofs_io(plan, Path::new(GUEST_MOUNT), &mut |l| ops.write_line(&l));
    }
    // symlink・ハードリンクの観測（#1877）。モードは排他のため上の io のプローブとは同時に走らない。
    if let Some(plan) = link_plan(mode, &outcome) {
        run_virtiofs_link(plan, Path::new(RO_MOUNT), Path::new(RW_MOUNT), &mut |l| {
            ops.write_line(&ReportLine::from_link(l));
        });
    }
    // ready の後の通常経路だけが回収ループに入る。以後の子の終了は `Child::wait` ではなくここで受ける
    // （唯一の waiter。契約は `reap` のモジュール doc）。終了コードの中継は G6（#2273）で配線する。
    // 停止要求で戻り、停止の手順へ進む。電源断が成功すれば戻らない。
    reap_until_stop(&mut LinuxWaiter, |_pid, _status| {});
    let _ = shutdown::run(&mut LinuxShutdownOps { ops: &mut ops });
    // 電源断に失敗した（診断行は出した）。PID 1 は終了できないので、以後の停止要求は無視して回収を続ける。
    reap_forever(&mut LinuxWaiter, |_pid, _status| {})
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MAC-1・#2139: EBUSY は成功ではなく検査が必要な状態に分類し、他の errno は失敗のまま。
    #[test]
    fn mac1_classify_dev_mount() {
        assert_eq!(classify_dev_mount(Ok(())), Ok(DevMount::Fresh));
        assert_eq!(
            classify_dev_mount(Err(std::io::Error::from_raw_os_error(16))),
            Ok(DevMount::AlreadyMounted)
        );
        assert_eq!(
            classify_dev_mount(Err(std::io::Error::from_raw_os_error(1))),
            Err(Errno::new(1))
        );
    }

    use std::os::unix::fs::{MetadataExt, symlink};
    use std::process::{Command, Stdio};

    use crate::reap::{ChildStatus, drain};
    use crate::test_reap::{output_within, reap_within};

    const REEXEC_ENV: &str = "FANDHE_GUEST_INIT_REAP_REEXEC";
    const REEXEC_OK_LINE: &str = "guest-init reap: ok direct=3 signaled=9 orphan=5 echild";

    /// `/proc/<pid>/stat` の (状態, ppid)。`comm` に `)` を含みうるので最後の `)` の後ろを見る。
    fn proc_state(pid: i32) -> Option<(char, i32)> {
        let s = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = s.get(s.rfind(')')? + 2..)?;
        let mut it = rest.split(' ');
        let state = it.next()?.chars().next()?;
        let ppid = it.next()?.parse().ok()?;
        Some((state, ppid))
    }

    fn wait_zombie(pid: i32, ppid: i32, until: std::time::Instant) {
        loop {
            if proc_state(pid) == Some(('Z', ppid)) {
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "pid {pid} did not become a zombie of {ppid}: {:?}",
                proc_state(pid)
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// MAC-4・CORE-1・REPAIR-5・#2269: 直接の子・シグナルで終わる子・孤児（subreaper で再親付け）の
    /// ゾンビが回収ループで残らず回収される。subreaper と `waitpid(-1)` はプロセス全体に効くため、
    /// 共有の libtest プロセスではなく試験バイナリの再起動した子（`mac4_2269_reexec_entry`）で実行する。
    #[test]
    fn mac4_2269_reaper_collects_zombies_and_orphans() {
        let exe = std::env::current_exe().unwrap();
        let mut cmd = Command::new(exe);
        cmd.args([
            "--exact",
            "init::tests::mac4_2269_reexec_entry",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(REEXEC_ENV, "1")
        .stdin(Stdio::null());
        let out = output_within(&mut cmd, reap_within() * 2).unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{:?}\n{stdout}", out.status);
        assert!(stdout.contains(REEXEC_OK_LINE), "{stdout}");
        assert!(stdout.contains("1 passed"), "{stdout}");
    }

    /// 上の試験の再起動先。環境変数が無ければ何もしない（共有プロセスで subreaper を立てない）。
    #[test]
    #[ignore = "re-exec entry for mac4_2269_reaper_collects_zombies_and_orphans"]
    #[allow(
        clippy::zombie_processes,
        reason = "回収ループ（drain）が唯一の waiter であることの検証のため、Child は意図して wait しない"
    )]
    fn mac4_2269_reexec_entry() {
        if std::env::var_os(REEXEC_ENV).is_none() {
            return;
        }
        sys::set_child_subreaper().unwrap();
        let me = i32::try_from(std::process::id()).unwrap();
        let until = std::time::Instant::now() + reap_within();
        let spawn = |script: &str| {
            Command::new("sh")
                .args(["-c", script])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let direct = spawn("exit 3");
        let signaled = spawn("kill -9 $$");
        let mut mid =
            spawn("sh -c 'sleep 0.2; exit 5' </dev/null >/dev/null 2>&1 & echo $!; exit 0");
        let mut line = String::new();
        std::io::Read::read_to_string(mid.stdout.as_mut().unwrap(), &mut line).unwrap();
        let orphan: i32 = line.trim().parse().unwrap();
        let ids = [
            i32::try_from(direct.id()).unwrap(),
            i32::try_from(signaled.id()).unwrap(),
            i32::try_from(mid.id()).unwrap(),
        ];
        // どの Child にも wait は呼ばない。ゾンビが実在することを前提として確かめる。
        for pid in ids.into_iter().chain([orphan]) {
            wait_zombie(pid, me, until);
        }
        let mut got = drain(&mut LinuxWaiter, 16);
        got.sort_by_key(|(pid, _)| *pid);
        let mut want = vec![
            (ids[0], ChildStatus::Exited(3)),
            (ids[1], ChildStatus::Signaled(9)),
            (ids[2], ChildStatus::Exited(0)),
            (orphan, ChildStatus::Exited(5)),
        ];
        want.sort_by_key(|(pid, _)| *pid);
        assert_eq!(got, want);
        let e = sys::wait_any_child(true).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(sys::ECHILD));
        for (pid, _) in want {
            assert!(
                proc_state(pid).is_none_or(|(_, ppid)| ppid != me),
                "pid {pid} still a child"
            );
        }
        println!("{REEXEC_OK_LINE}");
    }

    fn tmp_root(tag: &str) -> crate::test_root::TestRoot {
        crate::test_root::test_root("fandhe-guest-init", tag)
    }

    fn open_dir(p: &Path) -> File {
        File::open(p).unwrap()
    }

    fn fd_ino(fd: &OwnedFd) -> (u64, u64) {
        let md = fs::metadata(format!(
            "/proc/self/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(fd)
        ))
        .unwrap();
        (md.dev(), md.ino())
    }

    /// MAC-1・SEC-1・#2268: 欠けた要素を作り、返った fd が作った実ディレクトリを指す。2 回目も成功する。
    #[test]
    fn mac1_2268_open_mount_target_creates_and_is_idempotent() {
        let t = tmp_root("create");
        let root = t.to_path_buf();
        fs::create_dir_all(root.join("mnt/fandhe")).unwrap();
        let rfd = open_dir(&root);
        let run = || {
            open_mount_target(
                rfd.as_fd(),
                ["mnt", "fandhe"].into_iter(),
                ["a", "b"].into_iter(),
            )
        };
        let fd = run().unwrap();
        let md = fs::metadata(root.join("mnt/fandhe/a/b")).unwrap();
        assert_eq!(fd_ino(&fd), (md.dev(), md.ino()));
        let fd2 = run().unwrap();
        assert_eq!(fd_ino(&fd2), (md.dev(), md.ino()));
    }

    /// MAC-1・SEC-1・#2268: base が symlink なら ENOTDIR で、先には何も作られない。
    #[test]
    fn mac1_2268_symlinked_base_is_rejected() {
        let t = tmp_root("base-link");
        let root = t.to_path_buf();
        fs::create_dir_all(root.join("elsewhere/fandhe")).unwrap();
        symlink("elsewhere", root.join("mnt")).unwrap();
        let rfd = open_dir(&root);
        let r = open_mount_target(
            rfd.as_fd(),
            ["mnt", "fandhe"].into_iter(),
            ["a"].into_iter(),
        );
        assert_eq!(r.err(), Some(Errno::ENOTDIR));
        assert!(!root.join("elsewhere/fandhe/a").exists());
    }

    /// MAC-1・SEC-1・#2268: 指示の要素が symlink・通常ファイルなら ENOTDIR で、symlink の先は作られない。
    #[test]
    fn mac1_2268_symlink_or_file_element_is_rejected() {
        let t = tmp_root("elem-link");
        let root = t.to_path_buf();
        fs::create_dir_all(root.join("mnt/fandhe")).unwrap();
        fs::create_dir_all(root.join("outside")).unwrap();
        symlink("../../outside", root.join("mnt/fandhe/a")).unwrap();
        fs::write(root.join("mnt/fandhe/f"), "x").unwrap();
        let rfd = open_dir(&root);
        let go = |els: &[&'static str]| {
            open_mount_target(
                rfd.as_fd(),
                ["mnt", "fandhe"].into_iter(),
                els.iter().copied(),
            )
            .err()
        };
        assert_eq!(go(&["a", "b"]), Some(Errno::ENOTDIR));
        assert!(!root.join("outside/b").exists());
        assert_eq!(go(&["f"]), Some(Errno::ENOTDIR));
    }
}
