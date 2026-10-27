//! Linux ゲストの PID 1 としての起動シーケンスと [`GuestOps`] の実装（MAC-1・MAC-2・TASK-64 追補）。
//!
//! bin の入口（`main.rs`）から [`run`] だけが呼ばれる。mount は `sys` の安全なラッパー経由で、
//! 指示の復号・報告は OS 非依存の `directive`・`process`・`report` が、試験用プローブは `probe` が担う。
//!
//! どの経路でも終了しない（PID 1 が終了するとカーネルが panic する）。panic も [`install_panic_hook`] の
//! hook が待機へ落とす（#2139）。唯一の例外は PID 1 でないとき（ホストでの誤実行）で、何も mount せずに終了する。

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cmdline::{MAX_CMDLINE_BYTES, read_bounded};
use crate::directive::{Access, Directive, GUEST_MOUNT_BASE, MountPoint};
use crate::link_probe::{RO_MOUNT, RW_MOUNT, link_plan, run_virtiofs_link};
use crate::mountinfo::{MAX_MOUNTINFO_BYTES, check_dev_hardened};
use crate::probe::{GUEST_MOUNT, decode_test_mode, probe_plan, run_virtiofs_io};
use crate::process::{GuestOps, emit_ready, process_directives};
use crate::report::{Errno, InitStage, ReportLine};
use crate::sys;

struct LinuxOps {
    console: Box<dyn Write>,
}

impl GuestOps for LinuxOps {
    fn ensure_mount_point(&mut self, mount_point: &MountPoint) -> Result<(), Errno> {
        ensure_real_dir(Path::new(GUEST_MOUNT_BASE))?;
        let mut path = PathBuf::from(GUEST_MOUNT_BASE);
        for element in mount_point.elements() {
            path.push(element);
            match fs::create_dir(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(Errno::from_io(&e)),
            }
            ensure_real_dir(&path)?;
        }
        Ok(())
    }

    fn mount_virtiofs(&mut self, d: &Directive) -> Result<(), Errno> {
        // nosuid・nodev・`ro` なら MS_RDONLY は sys 側の固定値（呼び出し元は外せない）。
        // 検査から mount までの TOCTOU は PID 1 のみが動く前提で許容（lib.rs「未実装」・#2080・#1905）。
        sys::mount_virtiofs(
            d.tag.as_str(),
            Path::new(d.mount_point.as_str()),
            d.access == Access::ReadOnly,
        )
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

/// symlink でない実ディレクトリであることを要求する（symlink 経由の mount 先すり替えを防ぐ）。
///
/// 検査後に文字列パスで mount するため TOCTOU の余地がある。mount 時にゲスト内で動くのは PID 1 だけという
/// 前提で許容しており、子プロセスを動かす前に fd 起点の mount へ移す（lib.rs「未実装」・#2080・#1905）。
fn ensure_real_dir(path: &Path) -> Result<(), Errno> {
    let md = fs::symlink_metadata(path).map_err(|e| Errno::from_io(&e))?;
    if md.is_dir() {
        Ok(())
    } else {
        Err(Errno::ENOTDIR)
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

fn idle() -> ! {
    // PID 1 は終了しない。停止はホストの VZ の強制停止に任せる（協調停止は TASK-115 で未実装。REPAIR-3）。
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
    idle()
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
}
