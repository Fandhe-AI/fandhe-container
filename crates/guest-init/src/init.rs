//! Linux ゲストの PID 1 としての起動シーケンスと [`GuestOps`] の実装（MAC-1・MAC-2・TASK-64 追補）。
//!
//! bin の入口（`main.rs`）から [`run`] だけが呼ばれる。mount は `sys` の安全なラッパー経由で、
//! 指示の復号・報告は OS 非依存の `directive`・`process`・`report` が、試験用プローブは `probe` が担う。
//!
//! どの経路でも終了しない（PID 1 が終了するとカーネルが panic する）。唯一の例外は PID 1 でないとき
//! （ホストでの誤実行）で、何も mount せずに終了する。

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cmdline::{MAX_CMDLINE_BYTES, read_bounded};
use crate::directive::{Access, Directive, GUEST_MOUNT_BASE, MountPoint};
use crate::probe::{GUEST_MOUNT, decode_test_mode, probe_plan, run_virtiofs_io};
use crate::process::{GuestOps, emit_ready, process_directives};
use crate::report::{Errno, InitStage, ReportLine};
use crate::sys;

/// `EBUSY`（既に mount 済み）。
const EBUSY: i32 = 16;

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
        // nosuid・nodev は fail-closed の既定。`ro` は必ず MS_RDONLY。
        let mut flags = sys::MS_NOSUID | sys::MS_NODEV;
        if d.access == Access::ReadOnly {
            flags |= sys::MS_RDONLY;
        }
        sys::mount_fs(
            d.tag.as_str(),
            Path::new(d.mount_point.as_str()),
            "virtiofs",
            flags,
            None,
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

/// `/dev` は devtmpfs が既に mount 済み（EBUSY）でも成功として扱う。
fn mount_pseudo(
    fstype: &str,
    target: &str,
    flags: u64,
    data: Option<&str>,
    tolerate_busy: bool,
) -> Result<(), Errno> {
    match sys::mount_fs(fstype, Path::new(target), fstype, flags, data) {
        Ok(()) => Ok(()),
        Err(e) if tolerate_busy && e.raw_os_error() == Some(EBUSY) => Ok(()),
        Err(e) => Err(Errno::from_io(&e)),
    }
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
    // /dev を先に用意して console を開けるようにする（以降の診断・報告を hvc0 へ出すため）。
    let dev = init_filesystems().and_then(|()| {
        mount_pseudo(
            "devtmpfs",
            "/dev",
            sys::MS_NOSUID | sys::MS_NOEXEC,
            Some("mode=0755"),
            true,
        )
        .map_err(|e| (InitStage::Dev, e))
    });
    let mut ops = LinuxOps {
        console: open_console(),
    };
    let fatal = |ops: &mut LinuxOps, stage, errno| -> ! {
        ops.write_line(&ReportLine::init_error(stage, errno));
        idle()
    };
    if let Err((stage, errno)) = dev {
        fatal(&mut ops, stage, errno);
    }
    let strict = sys::MS_NOSUID | sys::MS_NODEV | sys::MS_NOEXEC;
    if let Err(e) = mount_pseudo("proc", "/proc", strict, None, false) {
        fatal(&mut ops, InitStage::Proc, e);
    }
    if let Err(e) = mount_pseudo("sysfs", "/sys", strict, None, false) {
        fatal(&mut ops, InitStage::Sys, e);
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
    if let Some(plan) = probe_plan(decode_test_mode(&cmdline), &outcome) {
        run_virtiofs_io(plan, Path::new(GUEST_MOUNT), &mut |l| ops.write_line(&l));
    }
    idle()
}
