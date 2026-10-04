//! macOS の `statfs(2)` の薄いラッパー（`sys` モジュールの macOS 部。`unsafe` 事前承認の範囲。
//! coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! 呼び出し文脈: `config` の ReadWrite 共有の走査が、配下のディレクトリが共有ルートと同じマウントに
//! 属するかを [`mount_identity`] で照合する（MAC-1・TASK-65.1）。`st_dev` だけでは同一デバイス上の
//! 別マウント（nullfs 等）を見分けられないため、カーネルが返すマウント先（`f_mntonname`）と
//! `f_fsid` を比較する。`libc` / `nix` は依存追加が禁止（dependency-policy）のため、`posix.rs` と同じ流儀で
//! 必要最小限の `extern "C"` 宣言と構造体を自前で持つ。
//!
//! 不変条件: `unsafe fn` を公開しない。公開するのは安全な [`mount_identity`]（`pub(crate)`）のみ。

use std::ffi::{CString, c_char, c_int};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// `<sys/mount.h>` の `MFSTYPENAMELEN`。
const MFSTYPENAMELEN: usize = 16;
/// `<sys/param.h>` の `MAXPATHLEN`（`f_mntonname` / `f_mntfromname` の長さ）。
const MAXPATHLEN: usize = 1024;

/// `struct statfs`（64 bit inode 版。`_DARWIN_FEATURE_64_BIT_INODE` 定義時の `<sys/mount.h>`）。
///
/// フィールドの順序と幅は `libc` クレート（apple）の `statfs` 定義と同じ。aarch64 は `statfs` が、
/// x86_64 は `statfs$INODE64` がこの配置を使う。
#[repr(C)]
// FFI の配置を写すため、読まないフィールドも持つ。
#[allow(dead_code)]
struct Statfs {
    f_bsize: u32,
    f_iosize: i32,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [i32; 2],
    f_owner: u32,
    f_type: u32,
    f_flags: u32,
    f_fssubtype: u32,
    f_fstypename: [c_char; MFSTYPENAMELEN],
    f_mntonname: [c_char; MAXPATHLEN],
    f_mntfromname: [c_char; MAXPATHLEN],
    f_flags_ext: u32,
    f_reserved: [u32; 7],
}

// 構造体の写し間違いをコンパイル時に止める（4+4+5×8+8+4×4+16+1024+1024+4+7×4 = 2168、8 バイト整列）。
const _: () = assert!(std::mem::size_of::<Statfs>() == 2168);
const _: () = assert!(std::mem::align_of::<Statfs>() == 8);

// 64 bit inode 版のシンボル名は x86_64 と aarch64 でしか確認していないため、それ以外の macOS では止める。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("statfs symbol for this macOS target_arch is not verified (x86_64 / aarch64 only)");

// SAFETY: （宣言そのものの妥当性）`int statfs(const char *path, struct statfs *buf)` と同じ引数・戻り値の
// 型。x86_64 は 64 bit inode 版のシンボル `statfs$INODE64`、aarch64 は既定の `statfs` が上記 `Statfs` の
// 配置を使う（アーキ差は `cfg_attr(target_arch)` で明示する）。
unsafe extern "C" {
    #[cfg_attr(target_arch = "x86_64", link_name = "statfs$INODE64")]
    fn statfs(path: *const c_char, buf: *mut Statfs) -> c_int;
}

/// パスが属するマウントの識別子（`f_fsid`・マウント先 `f_mntonname`・ファイルシステム種別 `f_fstypename`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountIdentity {
    fsid: [i32; 2],
    mount_on: Vec<u8>,
    fs_type: Vec<u8>,
}

impl MountIdentity {
    /// ファイルシステム種別（`f_fstypename`。例: `apfs`・`hfs`）。
    pub(crate) fn fs_type(&self) -> &[u8] {
        &self.fs_type
    }
}

/// NUL 終端の固定長 `c_char` 配列を、配列の範囲内だけ読んでバイト列にする（NUL が無ければ全長）。
fn bytes_until_nul(chars: &[c_char]) -> Vec<u8> {
    chars
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect()
}

/// `path` が属するマウントの識別子を返す（`statfs(2)`。symlink は辿る）。
///
/// `path` に NUL を含む場合は `InvalidInput`、`statfs` 失敗は `errno` 由来の `io::Error` を返す。
pub(crate) fn mount_identity(path: &Path) -> io::Result<MountIdentity> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut buf = MaybeUninit::<Statfs>::uninit();
    // SAFETY: `c_path` は NUL 終端の有効な C 文字列で、呼び出し中は生存する。`buf` は `Statfs` の
    // 大きさ・整列を持つ書き込み可能な領域で、カーネルが成功時に全体を書き込む。グローバル状態は変えない。
    let rc = unsafe { statfs(c_path.as_ptr(), buf.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `statfs` が 0 を返したため、`buf` はカーネルにより初期化済み。
    let st = unsafe { buf.assume_init() };
    // 文字列欄は NUL 終端を探し、配列の範囲内だけを読む。
    Ok(MountIdentity {
        fsid: st.f_fsid,
        mount_on: bytes_until_nul(&st.f_mntonname),
        fs_type: bytes_until_nul(&st.f_fstypename),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MAC-1・TASK-65.1: 同じディレクトリ配下は同じマウント、`/` と `/dev`（devfs）は別マウントになる。
    #[test]
    fn mount_identity_distinguishes_mounts() {
        let dir = std::env::temp_dir().join(format!("fandhe-macos-sys-mnt-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).expect("create fixture");
        let a = mount_identity(&dir).expect("statfs dir");
        let b = mount_identity(&dir.join("sub")).expect("statfs sub");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(a, b);
        let root = mount_identity(Path::new("/")).expect("statfs root");
        assert_eq!(root.mount_on, b"/".to_vec());
        let dev = mount_identity(Path::new("/dev")).expect("statfs dev");
        assert_eq!(dev.mount_on, b"/dev".to_vec());
        assert_eq!(dev.fs_type(), b"devfs");
        assert_eq!(
            bytes_until_nul(&[b'h' as c_char, b's' as c_char, 0, b'x' as c_char]),
            b"hs"
        );
        assert_eq!(bytes_until_nul(&[b'a' as c_char; 3]), b"aaa");
        assert_ne!(root, dev);
        let err = mount_identity(Path::new("/nonexistent-fandhe-mount-test")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
