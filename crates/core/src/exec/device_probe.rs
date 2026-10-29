//! デバイスノードの作成・pty の slave の open を errno つきで観測する入口（SEC-1・CORE-4・TASK-32 追補・MS-2・#1681）。
//!
//! # 役割・呼び出し文脈
//! 結合試験 `tests/device_cgroup_layers.rs` が、デバイス cgroup（`EPERM`）と rootfs の `nodev`（`EACCES`）を
//! errno で区別して実機照合するための観測専用の入口。`unsafe` は持たず（`sys` の安全なラッパーと std だけを使う）、
//! 判定は行わない（成否と errno を返すだけ）。呼び出し元が期待値を具体値で照合する。
//!
//! - `make_char_device_errno`: 親ディレクトリを `O_PATH|O_NOFOLLOW|O_DIRECTORY` で開き、その fd 起点で最終要素に
//!   文字デバイスを作る。Landlock の観測（`exec/landlock.rs` の `MakeCharDevice`。1:3 固定）と共有する本体。
//! - `make_char_device_for_test`・`open_pty_slave_for_test`: 任意の major/minor の `mknodat(2)` と pty の slave の
//!   open。本番の公開 API にしないため `exec-test-support` feature と `#[doc(hidden)]` の下に置く。
//!
//! 外部入力は受けない（試験が固定で渡すパスだけ）。名前に NUL を含む・親が取れない・範囲外の番号は `-1` で拒否する。

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use crate::sys;

/// `mknodat(2)` の `dev_t` に載せる major の上限（試験で使う番号は 12 bit に収まる）。
#[cfg(feature = "exec-test-support")]
const MAX_MAJOR: u32 = 4095;
/// minor の上限（20 bit）。
#[cfg(feature = "exec-test-support")]
const MAX_MINOR: u32 = 0xF_FFFF;

/// `path` の最終要素に文字デバイス（モード 0666）`major:minor` を作る。成功は `None`、失敗は `Some(errno)`
/// （親・名前が取れない・NUL を含む・対応外アーキテクチャは `-1`）。
///
/// `O_NOFOLLOW` が効くのは親の最終要素だけで、親までの中間要素の symlink は辿る（試験が固定のパスで渡す専用で、
/// 外部入力は受けない）。`exec/landlock.rs` の `MakeCharDevice`（1:3）と `make_char_device_for_test` の本体。
pub(crate) fn make_char_device_errno(path: &Path, major: u32, minor: u32) -> Option<i32> {
    let errno = |e: sys::SysError| match e {
        sys::SysError::Os(e) => e,
        _ => -1,
    };
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Some(-1);
    };
    let (Ok(parent), Ok(name)) = (
        CString::new(parent.as_os_str().as_bytes()),
        CString::new(name.as_bytes()),
    ) else {
        return Some(-1);
    };
    let dir = match sys::open_dir_path_nofollow(None, &parent) {
        Ok(fd) => fd,
        Err(e) => return Some(errno(e)),
    };
    sys::make_char_device(std::os::fd::AsFd::as_fd(&dir), &name, 0o666, major, minor)
        .err()
        .map(errno)
}

/// `path`（絶対パス）に文字デバイス `major:minor` を作る。成功は `None`、失敗は `Some(errno)`。
///
/// 範囲外の major（4095 超）・minor（0xFFFFF 超）・相対パスは `Some(-1)` で拒否する。結合試験
/// `tests/device_cgroup_layers.rs` 専用で、デバイス cgroup の `mknod` 拒否（`EPERM`）と、許可された 1:3 の成功を
/// 対にして照合する（SEC-1）。`exec-test-support` feature を付けたビルドにだけ存在する。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn make_char_device_for_test(path: &Path, major: u32, minor: u32) -> Option<i32> {
    if !path.is_absolute() || major > MAX_MAJOR || minor > MAX_MINOR {
        return Some(-1);
    }
    make_char_device_errno(path, major, minor)
}

/// 開いた pty の slave の観測結果。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PtySlaveProbe {
    /// slave の番号（`<ptmx の親>/pts/<index>`）。
    pub index: u32,
    /// 開いた slave の `st_rdev`（major は `(rdev >> 8) & 0xfff` で取り出せる）。
    pub rdev: u64,
}

/// `ptmx` を `O_RDWR|O_NOCTTY` で開き、slave をロック解除して `<ptmx の親>/pts/<N>` を `O_RDWR|O_NOCTTY` で開く。
///
/// 失敗は各段の errno（取れなければ `-1`）。slave を開けた時点で、そのノード（devpts の c 136:N）の open が
/// デバイス cgroup の許可リストを通ったことになる（許可リストの `c 136:*` の照合。SEC-1・TASK-32 追補・#1681）。
/// `exec-test-support` feature を付けたビルドにだけ存在する。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn open_pty_slave_for_test(ptmx: &Path) -> Result<PtySlaveProbe, i32> {
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(-1);
    let noctty = sys::noctty_open_flag().ok_or(-1)?;
    let master = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(noctty)
        .open(ptmx)
        .map_err(errno)?;
    let index = sys::pty_unlock_and_index(master.as_fd()).map_err(|e| match e {
        sys::SysError::Os(e) => e,
        _ => -1,
    })?;
    let parent = ptmx.parent().ok_or(-1)?;
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(noctty)
        .open(parent.join("pts").join(index.to_string()))
        .map_err(errno)?;
    let rdev = slave.metadata().map_err(errno)?.rdev();
    Ok(PtySlaveProbe { index, rdev })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-1・TASK-32 追補（#1681）: 存在しない親は `ENOENT`（2）、NUL を含む名前・親の無いパスは `-1`。
    #[test]
    fn sec1_task32_make_char_device_errno_reports_lookup_failures() {
        assert_eq!(
            make_char_device_errno(Path::new("/nonexistent-fandhe-dir/x"), 1, 3),
            Some(2)
        );
        assert_eq!(make_char_device_errno(Path::new("/"), 1, 3), Some(-1));
        let nul = std::ffi::OsStr::from_bytes(b"/tmp/a\0b");
        assert_eq!(make_char_device_errno(Path::new(nul), 1, 3), Some(-1));
    }

    /// 非 root では `mknodat(2)` が `EPERM`（1）になりノードが残らない。root では前提が崩れるため理由を出して
    /// 抜ける（root の経路は `tests/device_cgroup_layers.rs` が実機で照合する）。
    #[test]
    fn sec1_task32_make_char_device_errno_eperm_without_cap_mknod() {
        if sys::effective_uid() == 0 {
            eprintln!("skipped: running as root (CAP_MKNOD present)");
            return;
        }
        let scratch = crate::scratch_root::ScratchDir::new(
            "fandhe-devprobe",
            std::time::Duration::from_secs(10),
        );
        let node = scratch.path().join("n");
        assert_eq!(make_char_device_errno(&node, 1, 3), Some(1));
        assert!(std::fs::symlink_metadata(&node).is_err());
    }

    /// 範囲外の番号・相対パスは `-1` で拒否する（試験用の入口）。
    #[cfg(feature = "exec-test-support")]
    #[test]
    fn sec1_task32_make_char_device_for_test_rejects_out_of_range() {
        let p = Path::new("/tmp/fandhe-devprobe-never");
        assert_eq!(make_char_device_for_test(p, 4096, 0), Some(-1));
        assert_eq!(make_char_device_for_test(p, 1, 0x10_0000), Some(-1));
        assert_eq!(
            make_char_device_for_test(Path::new("rel/n"), 1, 3),
            Some(-1)
        );
    }

    /// ホストの `/dev/ptmx` から slave を開け、rdev の major が 136（devpts）になる。特権を要さない。
    #[cfg(feature = "exec-test-support")]
    #[test]
    fn sec1_task32_open_pty_slave_for_test_reaches_major_136() {
        let probe = open_pty_slave_for_test(Path::new("/dev/ptmx")).expect("open slave");
        let major = ((probe.rdev >> 8) & 0xfff) as u32;
        assert_eq!(major, 136);
    }

    /// ptmx でないファイルは unlock の `ENOTTY`（25）で失敗する。
    #[cfg(feature = "exec-test-support")]
    #[test]
    fn sec1_task32_open_pty_slave_for_test_rejects_regular_file() {
        assert_eq!(open_pty_slave_for_test(Path::new("/dev/null")), Err(25));
    }
}
