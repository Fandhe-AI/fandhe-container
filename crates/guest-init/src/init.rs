//! Linux ゲストの PID 1 としての起動シーケンスと [`GuestOps`] の実装（MAC-1・MAC-2・TASK-64 追補）。
//!
//! bin の入口（`main.rs`）から [`run`] だけが呼ばれる。mount は `sys` の安全なラッパー経由で（virtiofs の
//! mount 先は fd で固定する。#2268）、
//! 指示の復号・報告は OS 非依存の `directive`・`process`・`report` が、試験用プローブは `probe` が担う。
//!
//! どの経路でも終了しない（PID 1 が終了するとカーネルが panic する）。panic も [`install_panic_hook`] の
//! hook が待機へ落とす（#2139）。唯一の例外は PID 1 でないとき（ホストでの誤実行）で、何も mount せずに終了する。

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
use crate::probe::{GUEST_MOUNT, decode_test_mode, probe_plan, run_virtiofs_io};
use crate::process::{GuestOps, emit_ready, process_directives};
use crate::report::{Errno, InitStage, ReportLine};
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

    use std::os::unix::fs::{MetadataExt, symlink};

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
