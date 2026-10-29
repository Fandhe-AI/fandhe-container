//! macOS の `statfs(2)` の薄いラッパー（`sys` モジュールの macOS 部。`unsafe` 事前承認の範囲。
//! coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! 呼び出し文脈: `config` の ReadWrite 共有の走査が、配下のディレクトリが共有ルートと同じマウントに
//! 属するかを [`mount_identity`] で照合する（MAC-1・TASK-65.1）。`st_dev` だけでは同一デバイス上の
//! 別マウント（nullfs 等）を見分けられないため、カーネルが返すマウント先（`f_mntonname`）と
//! `f_fsid` を比較する。`libc` / `nix` は製品の依存に入れない（dependency-policy。`libc` は dev-dependencies で照合にだけ使う。#1318）ため、
//! `posix.rs` と同じ流儀で必要最小限の `extern "C"` 宣言と構造体を自前で持つ。`libc` との機械照合は子 `libc_abi` で行う（#1844）。
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
        // 前回の残骸があれば消してから作る（REPAIR-12・#3375）。
        let _ = std::fs::remove_dir_all(&dir);
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

#[cfg(test)]
mod libc_abi {
    //! 自前の宣言を `libc` 0.2.189 と `const` 評価で照合する（#1844・MAC-1・MVM-4・REPAIR-12）。関数は呼ばない。
    //! 親モジュールと同じ cfg（macOS の x86_64 / aarch64）の下にあり、ターゲットごとの `libc` の値と比べる。
    //!
    //! 対象外（理由つき）:
    //! - `MFSTYPENAMELEN`: `libc` に対応物が無い（一次情報は macOS SDK の `<sys/mount.h>` の
    //!   `#define MFSTYPENAMELEN 16`）。代わりに `libc::statfs` の `f_fstypename` と `f_mntonname` の
    //!   オフセット差（配列の幅）で間接的に照合する
    //! - `statfs` の `link_name`: 型では照合できない。自前は `target_arch = "x86_64"` で `statfs$INODE64`、
    //!   `libc` は `not(target_arch = "aarch64")` で同じ名前。親の `compile_error!` で x86_64 / aarch64 に限るため、
    //!   対応する 2 アーキでは同じシンボルになる
    //! - `MountIdentity`・`mount_identity`・`bytes_until_nul`: FFI ではない安全なラッパー
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    /// `libc` の `c_int` を `usize` へ広げる。負値は拒否する（切り詰めを隠さない）。
    const fn widen(v: libc::c_int) -> usize {
        assert!(v >= 0);
        v as usize
    }

    const _: () = {
        assert!(MAXPATHLEN == widen(libc::MAXPATHLEN));
        // `MFSTYPENAMELEN` の間接照合（上記の対象外を参照）。
        assert!(
            offset_of!(libc::statfs, f_mntonname) - offset_of!(libc::statfs, f_fstypename)
                == MFSTYPENAMELEN * size_of::<libc::c_char>()
        );

        assert!(size_of::<Statfs>() == size_of::<libc::statfs>());
        assert!(align_of::<Statfs>() == align_of::<libc::statfs>());
        assert!(offset_of!(Statfs, f_bsize) == offset_of!(libc::statfs, f_bsize));
        assert!(offset_of!(Statfs, f_iosize) == offset_of!(libc::statfs, f_iosize));
        assert!(offset_of!(Statfs, f_blocks) == offset_of!(libc::statfs, f_blocks));
        assert!(offset_of!(Statfs, f_bfree) == offset_of!(libc::statfs, f_bfree));
        assert!(offset_of!(Statfs, f_bavail) == offset_of!(libc::statfs, f_bavail));
        assert!(offset_of!(Statfs, f_files) == offset_of!(libc::statfs, f_files));
        assert!(offset_of!(Statfs, f_ffree) == offset_of!(libc::statfs, f_ffree));
        assert!(offset_of!(Statfs, f_fsid) == offset_of!(libc::statfs, f_fsid));
        assert!(offset_of!(Statfs, f_owner) == offset_of!(libc::statfs, f_owner));
        assert!(offset_of!(Statfs, f_type) == offset_of!(libc::statfs, f_type));
        assert!(offset_of!(Statfs, f_flags) == offset_of!(libc::statfs, f_flags));
        assert!(offset_of!(Statfs, f_fssubtype) == offset_of!(libc::statfs, f_fssubtype));
        assert!(offset_of!(Statfs, f_fstypename) == offset_of!(libc::statfs, f_fstypename));
        assert!(offset_of!(Statfs, f_mntonname) == offset_of!(libc::statfs, f_mntonname));
        assert!(offset_of!(Statfs, f_mntfromname) == offset_of!(libc::statfs, f_mntfromname));
        assert!(offset_of!(Statfs, f_flags_ext) == offset_of!(libc::statfs, f_flags_ext));
        assert!(offset_of!(Statfs, f_reserved) == offset_of!(libc::statfs, f_reserved));

        // 型の書き方が違う 2 フィールド。`fsid_t` の中身は非公開（`__fsid_val: [i32; 2]`）のため、
        // サイズとアラインメントだけを照合する。
        assert!(size_of::<[i32; 2]>() == size_of::<libc::fsid_t>());
        assert!(align_of::<[i32; 2]>() == align_of::<libc::fsid_t>());
        assert!(size_of::<u32>() == size_of::<libc::uid_t>());
    };

    // 関数の型（引数・戻り値）。構造体の同一性は上の `Statfs` の照合が保証する。
    const _: unsafe extern "C" fn(*const libc::c_char, *mut Statfs) -> libc::c_int = statfs;
    const _: unsafe extern "C" fn(*const libc::c_char, *mut libc::statfs) -> libc::c_int =
        libc::statfs;
}
