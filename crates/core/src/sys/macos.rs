//! macOS 向けの `sys`（`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節）。
//!
//! # 役割と呼び出し元
//! Linux 向けの `sys.rs` とは別ファイルで、`lib.rs` が `#[cfg(target_os = "macos")]` と
//! `#[path = "sys/macos.rs"]` で排他的に `mod sys` として取り込む。Linux の宣言（glibc / musl の
//! 型幅・syscall 番号）は macOS に漏らさない。呼び出し元は `crate::state_store`（OCI-5・SEC-4・CLI-1。
//! #2247）だけで、状態ルートの信頼境界の検査に必要な次の 3 点を安全な API で提供する。
//! - 実効 UID（`geteuid(2)`）
//! - `O_NOFOLLOW | O_NONBLOCK` の値（`open_nowait` が使う）
//! - 拡張 ACL の有無（`acl_get_link_np(3)`。symlink を辿らない）
//! - `fsync(2)`（ディレクトリ fd への `F_FULLFSYNC` が `EINVAL` / `ENOTSUP` になる場合の代替。`sync_dir` 用）
//! - 追補（#1864・TASK-122 追補・PLUG-11）: plugin の信頼性検証の macOS 実装（#1865）向けに、
//!   サブモジュール `plugin_fs`（呼び出し元は `plugin_trust`〔#1865〕）が symlink 非追従の fd 相対 open・fd の実体パス取得・fd の拡張 ACL 検出を提供する
//! - 追補（#3096・PLUG-11・SEC-1）: `plugin_fs` に `fstatat(2)` の安全なラッパーを足し、open の前に種別を確かめる
//!
//! # 契約
//! - `unsafe fn` は外へ公開しない。すべての `unsafe` に `// SAFETY:` を付ける
//! - 値・型幅は Apple の `sys/fcntl.h`（`O_NONBLOCK` = 0x0004・`O_NOFOLLOW` = 0x0100）、`sys/acl.h`
//!   （`ACL_TYPE_EXTENDED` = 0x100・`acl_t` はポインタ・`acl_type_t` は `unsigned int`）、`geteuid(2)`
//!   （`uid_t` = `u32`）に合わせる。Linux の値は流用しない。対応外アーキテクチャ（x86_64・aarch64 以外）
//!   では値を持たず `None` を返す（fail-closed）
//! - 拡張 ACL は mode bits を迂回して他者に書き込みを許せるため、中身を解釈せず「付いている」だけで
//!   呼び出し側が拒否する（#1539 のオーナー判断と同じ方針）
//! - `SysError::Os` は errno を保持する（Linux の `sys` と同形。#1865 が `ENOTDIR` / `ELOOP` を判別するため）

#![cfg(target_os = "macos")]

use std::ffi::{CString, c_char, c_int, c_void};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// `sys` の失敗（errno の値や文言は呼び出し側へ漏らさない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysError {
    /// 引数が不正（パスに NUL を含む等）。
    InvalidInput,
    /// OS が失敗を返した（errno を保持する。ACL の読み出しに失敗・権限不足・非対応ファイルシステム等）。
    Os(i32),
    /// 対応外アーキテクチャ（x86_64・aarch64 以外）。定数の確認が済んでいないため拒否する（fail-closed）。
    // 対応アーキテクチャでは構築されないため dead_code になる。
    #[allow(dead_code)]
    Unsupported,
}

/// 直前の失敗の errno（取れなければ `EINVAL` に写し、成功側へは倒さない）。
fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(EINVAL)
}

/// `O_NONBLOCK`（`sys/fcntl.h`）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const O_NONBLOCK: i32 = 0x0004;
/// `O_NOFOLLOW`（`sys/fcntl.h`）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const O_NOFOLLOW: i32 = 0x0100;

/// `ACL_TYPE_EXTENDED`（`sys/acl.h`）。
const ACL_TYPE_EXTENDED: u32 = 0x0000_0100;
/// `ACL_FIRST_ENTRY`（`sys/acl.h`。`acl_get_entry` の `entry_id`）。
const ACL_FIRST_ENTRY: c_int = 0;
/// `EINVAL`（`sys/errno.h`。`acl_get_entry` が「エントリなし」で返す）。
const EINVAL: i32 = 22;
/// `ENOTSUP`（`sys/errno.h`）。
const ENOTSUP: i32 = 45;

/// `File::sync_all`（macOS では `fcntl(F_FULLFSYNC)`）が失敗したとき `fsync(2)` へ切り替えてよい errno。
/// ディレクトリ fd や一部のファイルシステムで `F_FULLFSYNC` が非対応を返すため。これ以外は fail-closed。
pub(crate) const FULLFSYNC_FALLBACK_ERRNOS: [i32; 2] = [EINVAL, ENOTSUP];

/// 自前の定数と `libc` の定数を `const` 評価で 1 件照合する試験専用マクロ（#1848・#1837・#1318・MVM-4・
/// REPAIR-7・REPAIR-12）。Linux の `sys.rs` の同名マクロと同じ方式（macOS 側は別ファイルのため複製）。
/// 両辺の型を引数で明記し、比較は `as i128`（64 bit 以下の整数では値を切り詰めない）で行う。
/// 食い違いは宣言を直す別 issue とし、試験側を合わせない。関数は呼ばず `unsafe` を使わない。
#[cfg(test)]
macro_rules! libc_const_eq {
    ($own:path, $own_ty:ty, $lib:path, $lib_ty:ty) => {{
        const OWN: $own_ty = $own;
        const LIB: $lib_ty = $lib;
        assert!(
            OWN as i128 == LIB as i128,
            concat!("libc mismatch: ", stringify!($own))
        );
    }};
    ($name:ident, $own_ty:ty, $lib_ty:ty) => {
        libc_const_eq!(super::$name, $own_ty, libc::$name, $lib_ty)
    };
}

/// 最上位の定数を `libc` の apple ターゲットと `const` 評価で照合する（#1848・MAC-1・PLUG-11）。
/// 対象外: `ACL_TYPE_EXTENDED`・`ACL_FIRST_ENTRY` は `libc` の apple に ACL の定数が無い（出典は Apple SDK の
/// `sys/acl.h`。SDK との照合は #2369 から未了で、この照合では確認していない）。
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod libc_abi {
    use libc::c_int;

    const _: () = {
        libc_const_eq!(O_NONBLOCK, i32, c_int);
        libc_const_eq!(O_NOFOLLOW, i32, c_int);
        libc_const_eq!(EINVAL, i32, c_int);
        libc_const_eq!(ENOTSUP, i32, c_int);
        // `FULLFSYNC_FALLBACK_ERRNOS` の要素が上の errno と同じであること（配列の添字は const 評価で確定する）。
        assert!(super::FULLFSYNC_FALLBACK_ERRNOS[0] == libc::EINVAL);
        assert!(super::FULLFSYNC_FALLBACK_ERRNOS[1] == libc::ENOTSUP);
    };

    // 最上位の `extern "C"` 関数の型の照合（#1849・#1837）。同じ関数ポインタ型へ自前と `libc` の両方を代入する。
    // 関数は呼ばず `unsafe` を使わない。`geteuid` の `uid_t` は apple で `u32`（自前の宣言と同じ）。
    // 対象外: `acl_get_link_np`・`acl_get_entry`・`acl_free`。`libc` 0.2.189 の apple に `acl_*` の宣言が無い
    // （一次情報は Apple SDK の `sys/acl.h` と `acl_get_file(3)`・`acl_get_entry(3)`・`acl_free(3)`）。
    // SDK との照合は #2369 から未了で、この照合では確認していない。
    const _: unsafe extern "C" fn() -> libc::uid_t = super::geteuid;
    const _: unsafe extern "C" fn() -> libc::uid_t = libc::geteuid;
    const _: unsafe extern "C" fn(c_int) -> c_int = super::fsync;
    const _: unsafe extern "C" fn(c_int) -> c_int = libc::fsync;
}

// SAFETY（宣言そのものの妥当性）: いずれも libSystem の関数。`uid_t geteuid(void)`、
// `acl_t acl_get_link_np(const char *, acl_type_t)`（`acl_t` は不透明ポインタ・`acl_type_t` は
// `unsigned int`）、`int acl_free(void *)`、`int fsync(int)` と同じ型幅。
unsafe extern "C" {
    fn geteuid() -> u32;
    fn acl_get_link_np(path: *const c_char, acl_type: u32) -> *mut c_void;
    fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry_p: *mut *mut c_void) -> c_int;
    fn acl_free(obj: *mut c_void) -> c_int;
    fn fsync(fd: c_int) -> c_int;
}

/// 自プロセスの実効 uid。
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: 引数なし・常に成功する副作用のない syscall。
    unsafe { geteuid() }
}

/// `std::fs::OpenOptions` の `custom_flags` へ渡す `O_NOFOLLOW | O_NONBLOCK`。
///
/// 状態ストアが、最終要素の symlink を辿らず FIFO 等でも `open(2)` が止まらないように開くために使う。
/// 対応外アーキテクチャでは `None`（呼び出し側が fail-closed にする）。`unsafe` を含まない。
pub(crate) fn nofollow_nonblock_open_flags() -> Option<i32> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        Some(O_NOFOLLOW | O_NONBLOCK)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        None
    }
}

/// `path` に拡張 ACL が付いているかを返す（最終要素が symlink でも辿らない）。
///
/// 付いていなければ `Ok(false)`（`acl_get_link_np` は ACL 無しを `NULL` + `ENOENT` で返す）。
/// それ以外の失敗は `Err(Os)`（呼び出し側は拒否する。fail-closed）。
pub(crate) fn has_extended_acl(path: &Path) -> Result<bool, SysError> {
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| SysError::InvalidInput)?;
    // SAFETY: `c_path` は NUL 終端で、この呼び出しの間生存する。第 2 引数は定義済みの定数。
    let acl = unsafe { acl_get_link_np(c_path.as_ptr(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let errno = last_errno();
        return if errno == plugin_fs::ENOENT {
            Ok(false)
        } else {
            Err(SysError::Os(errno))
        };
    }
    // 成功しても空の ACL（エントリ 0 件）は「ACL なし」の結果なので、エントリの有無を確かめる。
    let mut entry: *mut c_void = std::ptr::null_mut();
    // SAFETY: `acl` は直前に得た非 NULL の `acl_t`（まだ解放していない）、`entry` は有効な書き込み先。
    let rc = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) };
    let errno = last_errno();
    // SAFETY: `acl` は `acl_get_link_np` が返した非 NULL の `acl_t` で、他に所有者がいない。
    // ここで 1 回だけ解放し、以後は使わない（リーク防止）。`entry` は `acl` の内部を指すため解放後は使わない。
    let _ = unsafe { acl_free(acl) };
    if rc == 0 {
        Ok(!entry.is_null())
    } else if errno == EINVAL {
        // 先頭エントリが無い（空の ACL）。
        Ok(false)
    } else {
        Err(SysError::Os(errno))
    }
}

/// `file` に対して `fsync(2)` を呼ぶ（`F_FULLFSYNC` ではないため、ドライブのキャッシュまでは保証しない）。
///
/// `sync_dir` が `sync_all` の `EINVAL` / `ENOTSUP` に対する代替としてだけ使う。失敗は `io::Error` で返す。
pub(crate) fn fsync_file(file: &std::fs::File) -> std::io::Result<()> {
    // SAFETY: fd は呼び出しの間生きている `file` から借りた有効な descriptor で、`fsync` はそれを閉じも
    // 保持もしない。ポインタ引数は無い。
    let rc = unsafe { fsync(file.as_raw_fd()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
/// plugin の信頼性検証（PLUG-11・TASK-122 追補・#1864）向けの fd 相対 open・実体パス・fd の ACL 検出。
///
/// 呼び出し元は #1865（`plugin_trust` の macOS 実装）。`EBADF`・`EACCES` は試験でのみ参照するため
/// その項目だけ `dead_code` を許す。Linux の `O_PATH` が macOS に無いため構造が違う。
/// - 非追従 open は `O_NOFOLLOW` 付きで開き、最終要素が symlink なら `ELOOP` で失敗する。呼び出し側は
///   それを合図に `open_read_nonblock_follow_at`（カーネルが 1 回だけ辿る）へ切り替え、その戻り fd を保持 fd とする
/// - 所有者・モード・dev/ino・種別は開いた fd への `File::metadata`（std）で取る（unsafe を足さない）
/// - パス要素は `&CStr`（NUL を含まない）で受ける。単一要素であることの検証は呼び出し側の責務
/// - 種別のプローブは `fstatat(2)`（`lstat_at`・`stat_follow_at`）で open の前に行う（#3096）。呼び出し側は
///   通常ファイル以外を open せずに拒否し、open 後の fd の種別と dev/ino を probe と照合して差し替えを検出する。
///   FIFO は `O_NONBLOCK`・端末は `O_NOCTTY` で、差し替えられた場合にも止めない
pub(crate) mod plugin_fs {
    use super::{EINVAL, SysError, last_errno};
    use std::ffi::{CStr, c_char, c_int, c_void};
    use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
    use std::path::PathBuf;

    /// `ENOENT`（`sys/errno.h`）。
    pub(crate) const ENOENT: i32 = 2;
    /// `EBADF`（`sys/errno.h`）。
    #[cfg_attr(not(test), allow(dead_code))] // 試験でのみ参照する（本番は errno の既定アームで扱う）
    pub(crate) const EBADF: i32 = 9;
    /// `EACCES`（`sys/errno.h`）。
    #[cfg_attr(not(test), allow(dead_code))] // 試験でのみ参照する（本番は errno の既定アームで扱う）
    pub(crate) const EACCES: i32 = 13;
    /// `ENOTDIR`（`sys/errno.h`）。
    pub(crate) const ENOTDIR: i32 = 20;
    /// `ERANGE`（`sys/errno.h`）。`F_GETPATH` の結果が整形できないときの取り決めにも使う。
    pub(crate) const ERANGE: i32 = 34;
    /// `ELOOP`（`sys/errno.h`。Linux の 40 とは異なる）。
    pub(crate) const ELOOP: i32 = 62;

    // 以下は Apple の SDK ヘッダ（x86_64・aarch64 で同値）。Linux の値は流用しない。
    /// `O_RDONLY`（`sys/fcntl.h`）。
    const O_RDONLY: c_int = 0x0000;
    /// `O_NONBLOCK`（`sys/fcntl.h`）。
    const O_NONBLOCK: c_int = 0x0004;
    /// `O_NOFOLLOW`（`sys/fcntl.h`）。
    const O_NOFOLLOW: c_int = 0x0100;
    /// `O_NOCTTY`（`sys/fcntl.h`）。
    const O_NOCTTY: c_int = 0x0002_0000;
    /// `O_DIRECTORY`（`sys/fcntl.h`）。
    const O_DIRECTORY: c_int = 0x0010_0000;
    /// `O_CLOEXEC`（`sys/fcntl.h`）。
    const O_CLOEXEC: c_int = 0x0100_0000;
    /// `AT_FDCWD`（`sys/fcntl.h`。Linux の -100 とは異なる）。
    const AT_FDCWD: c_int = -2;
    /// `F_GETPATH`（`sys/fcntl.h`。ファームリンクは利用者視点のパスで返す。`F_GETPATH_NOFIRMLINK` は使わない）。
    const F_GETPATH: c_int = 50;
    /// `MAXPATHLEN`（`sys/param.h`）。`F_GETPATH` のバッファ長の要件。
    const MAXPATHLEN: usize = 1024;
    /// `ACL_TYPE_EXTENDED`（`sys/acl.h`）。
    const ACL_TYPE_EXTENDED: u32 = 0x0000_0100;
    /// `ACL_FIRST_ENTRY`（`sys/acl.h`）。
    const ACL_FIRST_ENTRY: c_int = 0;

    /// `AT_SYMLINK_NOFOLLOW`（`sys/fcntl.h`）。
    const AT_SYMLINK_NOFOLLOW: c_int = 0x0020;
    /// `S_IFMT`（`sys/stat.h`）。`st_mode` の種別ビットのマスク。
    const S_IFMT: u16 = 0o170000;
    /// `S_IFREG`（`sys/stat.h`）。
    const S_IFREG: u16 = 0o100000;
    /// `S_IFDIR`（`sys/stat.h`）。
    const S_IFDIR: u16 = 0o040000;
    /// `S_IFLNK`（`sys/stat.h`）。
    const S_IFLNK: u16 = 0o120000;

    /// 定数を確認済みのアーキテクチャか。それ以外の関数は `Unsupported` で拒否する。
    const SUPPORTED_ARCH: bool = cfg!(any(target_arch = "x86_64", target_arch = "aarch64"));

    /// `struct stat`（64 bit inode 版。`sys/stat.h` の `__DARWIN_STRUCT_STAT64`）。aarch64 は `fstatat`、
    /// x86_64 は `fstatat$INODE64` がこの配置を使う。読まないフィールドも配置のために宣言する
    /// （サイズ・オフセットは `libc_abi` で `libc::stat` と照合する）。
    #[repr(C)]
    #[allow(dead_code)]
    struct Stat {
        st_dev: i32,
        st_mode: u16,
        st_nlink: u16,
        st_ino: u64,
        st_uid: u32,
        st_gid: u32,
        st_rdev: i32,
        st_atime: i64,
        st_atime_nsec: i64,
        st_mtime: i64,
        st_mtime_nsec: i64,
        st_ctime: i64,
        st_ctime_nsec: i64,
        st_birthtime: i64,
        st_birthtime_nsec: i64,
        st_size: i64,
        st_blocks: i64,
        st_blksize: i32,
        st_flags: u32,
        st_gen: u32,
        st_lspare: i32,
        st_qspare: [i64; 2],
    }

    /// 開く前に `fstatat` で得た種別。通常ファイル・ディレクトリ・symlink 以外（デバイス・FIFO・ソケット等）は
    /// `Other` に束ね、呼び出し側は open せずに拒否する（#3096・PLUG-11・SEC-1）。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum EntryKind {
        Regular,
        Directory,
        Symlink,
        Other,
    }

    /// `fstatat` の結果のうち検証に使う部分（種別と、open 後の fd と照合する dev/ino）。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct EntryStat {
        kind: EntryKind,
        dev: u64,
        ino: u64,
    }

    impl EntryStat {
        pub(crate) fn kind(&self) -> EntryKind {
            self.kind
        }
        /// std の `MetadataExt::dev()` と同じ変換（`st_dev as u64`）。
        pub(crate) fn dev(&self) -> u64 {
            self.dev
        }
        pub(crate) fn ino(&self) -> u64 {
            self.ino
        }
    }

    // SAFETY（宣言そのものの妥当性）: いずれも libSystem の関数。`int openat(int, const char *, int, ...)` と
    // `int fcntl(int, int, ...)` は可変長引数で、Apple arm64 ABI は可変長部をスタックに積むため、
    // 必ず `...` 付きで宣言する。`acl_t acl_get_fd_np(int, acl_type_t)`・`int acl_get_entry(acl_t, int, acl_entry_t *)`・
    // `int acl_free(void *)` と同じ型幅（`acl_t` は不透明ポインタ・`acl_type_t` は `unsigned int`）。
    unsafe extern "C" {
        fn openat(dirfd: c_int, path: *const c_char, oflag: c_int, ...) -> c_int;
        fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
        // `int fstatat(int, const char *, struct stat *, int)`。Apple の `sys/stat.h` は `__DARWIN_INODE64(fstatat)`
        // で宣言し、x86_64 は `fstatat$INODE64`（64 bit inode の `struct stat`）に解決される。aarch64 は接尾辞なし
        // （64 bit inode のみ）。`libc` も `not(aarch64)` で同じ `link_name` を使う。型照合では検査できない。
        #[cfg_attr(target_arch = "x86_64", link_name = "fstatat$INODE64")]
        fn fstatat(dirfd: c_int, path: *const c_char, buf: *mut Stat, flags: c_int) -> c_int;
        fn acl_get_fd_np(fd: c_int, acl_type: u32) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry_p: *mut *mut c_void) -> c_int;
        fn acl_free(obj: *mut c_void) -> c_int;
    }

    /// `openat` の薄い包み。`O_CREAT` を含まないフラグだけを渡す（mode 引数は渡さない）。
    pub(super) fn openat_raw(dirfd: c_int, name: &CStr, flags: c_int) -> Result<OwnedFd, SysError> {
        if !SUPPORTED_ARCH {
            return Err(SysError::Unsupported);
        }
        // SAFETY: `name` は NUL 終端で呼び出しの間生存する。`flags` は本モジュールの定数の組で `O_CREAT` を
        // 含まないため mode は不要。`dirfd` が無効でも `EBADF` が返るだけでメモリ安全性に影響しない。
        let fd = unsafe { openat(dirfd, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(SysError::Os(last_errno()));
        }
        // SAFETY: `openat` が返した新しい fd で、他に所有者がいない。`OwnedFd` が唯一の所有者になる。
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// `fstatat` の薄い包み。成功時のみ `Stat` を初期化済みとして読み、種別へ分類する。
    pub(super) fn fstatat_raw(
        dirfd: c_int,
        name: &CStr,
        flags: c_int,
    ) -> Result<EntryStat, SysError> {
        if !SUPPORTED_ARCH {
            return Err(SysError::Unsupported);
        }
        let mut buf = std::mem::MaybeUninit::<Stat>::uninit();
        // SAFETY: `name` は NUL 終端で呼び出しの間生存する。`buf` は `Stat` 1 個分の有効な書き込み先で、
        // カーネルは `sizeof(struct stat)` を超えて書かない（`libc_abi` でサイズ・配置を照合）。`dirfd` が
        // 無効でも `EBADF` が返るだけでメモリ安全性に影響しない。
        let rc = unsafe { fstatat(dirfd, name.as_ptr(), buf.as_mut_ptr(), flags) };
        if rc != 0 {
            return Err(SysError::Os(last_errno()));
        }
        // SAFETY: `fstatat` が 0 を返した場合に限りカーネルが `buf` 全体を書き込んでいる。
        let st = unsafe { buf.assume_init() };
        let kind = match st.st_mode & S_IFMT {
            S_IFREG => EntryKind::Regular,
            S_IFDIR => EntryKind::Directory,
            S_IFLNK => EntryKind::Symlink,
            _ => EntryKind::Other,
        };
        Ok(EntryStat {
            kind,
            dev: i64::from(st.st_dev) as u64,
            ino: st.st_ino,
        })
    }

    /// `parent` の下の `name` を open せずに種別を得る（`AT_SYMLINK_NOFOLLOW`。最終要素の symlink は辿らず
    /// `Symlink`）。デバイス・FIFO・ソケットを開く副作用が無い。呼び出し側は probe と open の間の差し替えに
    /// 備え、open 後の fd の種別と dev/ino を本結果と照合すること（#3096・PLUG-11・SEC-1）。
    pub(crate) fn lstat_at(parent: BorrowedFd<'_>, name: &CStr) -> Result<EntryStat, SysError> {
        fstatat_raw(parent.as_raw_fd(), name, AT_SYMLINK_NOFOLLOW)
    }

    /// `lstat_at` の追従版。最終要素の symlink をカーネルが辿った先の種別を返す（ループ・ホップ超過は
    /// `Os(ELOOP)`）。open しないため副作用が無い。照合の責務は `lstat_at` と同じ。
    pub(crate) fn stat_follow_at(
        parent: BorrowedFd<'_>,
        name: &CStr,
    ) -> Result<EntryStat, SysError> {
        fstatat_raw(parent.as_raw_fd(), name, 0)
    }

    /// `parent`（`None` なら `AT_FDCWD`）の下の `name` を symlink を辿らずディレクトリとして開く。
    ///
    /// symlink・非ディレクトリはどちらも `Os(ENOTDIR)`、不在は `Os(ENOENT)`（Linux と同じ）。XNU の
    /// `vn_authorize_open_existing`（bsd/vfs/vfs_subr.c）は非ディレクトリへ `O_DIRECTORY` の `ENOTDIR` を
    /// `O_NOFOLLOW` の `ELOOP` より先に返すため、symlink で `ELOOP` にはならない（#3126）。呼び出し元
    /// （`plugin_trust` の `map_sys`）はどちらも `NotDirectory` に写して拒否する（fail-closed）。
    /// `O_SEARCH` は一次資料で確認できないため `O_RDONLY` で開き、読み取り権限の無いディレクトリは
    /// `Os(EACCES)` で返す（呼び出し側が拒否する。fail-closed）。
    pub(crate) fn open_dir_nofollow_at(
        parent: Option<BorrowedFd<'_>>,
        name: &CStr,
    ) -> Result<OwnedFd, SysError> {
        let dirfd = parent.map_or(AT_FDCWD, |p| p.as_raw_fd());
        openat_raw(
            dirfd,
            name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
        )
    }

    /// `parent` の下の `name` を symlink を辿らず読み取り専用で開く（FIFO で止まらない）。symlink は `Os(ELOOP)`。
    pub(crate) fn open_read_nonblock_nofollow_at(
        parent: BorrowedFd<'_>,
        name: &CStr,
    ) -> Result<OwnedFd, SysError> {
        openat_raw(
            parent.as_raw_fd(),
            name,
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC,
        )
    }

    /// `parent` の下の `name` を、最終要素の symlink をカーネルに辿らせて読み取り専用で開く。
    /// ループ・ホップ超過は `Os(ELOOP)`。戻り fd がそのまま保持 fd になる（開き直さない）。
    pub(crate) fn open_read_nonblock_follow_at(
        parent: BorrowedFd<'_>,
        name: &CStr,
    ) -> Result<OwnedFd, SysError> {
        openat_raw(
            parent.as_raw_fd(),
            name,
            O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC,
        )
    }

    /// `F_GETPATH` の薄い包み。NUL が無い・空・相対パスの結果は `Os(ERANGE)` とする。
    pub(super) fn real_path_of_raw(fd: c_int) -> Result<PathBuf, SysError> {
        use std::os::unix::ffi::OsStrExt;
        if !SUPPORTED_ARCH {
            return Err(SysError::Unsupported);
        }
        let mut buf = [0u8; MAXPATHLEN];
        // SAFETY: `buf` は `MAXPATHLEN` バイトでカーネルは超えて書かない。可変長部へポインタを 1 つだけ渡す。
        // `fd` が無効でも `EBADF` が返るだけでメモリ安全性に影響しない。
        let rc = unsafe { fcntl(fd, F_GETPATH, buf.as_mut_ptr()) };
        if rc < 0 {
            return Err(SysError::Os(last_errno()));
        }
        let c = CStr::from_bytes_until_nul(&buf).map_err(|_| SysError::Os(ERANGE))?;
        let bytes = c.to_bytes();
        if bytes.first() != Some(&b'/') {
            return Err(SysError::Os(ERANGE));
        }
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
    }

    /// 開いた `fd` の実体の正規パス（`F_GETPATH`。`/var` は `/private/var` で返る等）。失敗は `Err`。
    pub(crate) fn fd_real_path(fd: BorrowedFd<'_>) -> Result<PathBuf, SysError> {
        real_path_of_raw(fd.as_raw_fd())
    }

    /// `acl_get_fd_np` の薄い包み。判定は `has_extended_acl(path)` と同じ（空 ACL は「無し」）。
    pub(super) fn extended_acl_of_raw(fd: c_int) -> Result<bool, SysError> {
        if !SUPPORTED_ARCH {
            return Err(SysError::Unsupported);
        }
        // SAFETY: 引数は整数と定義済みの定数だけ。`fd` が無効でも `EBADF` が返るだけで安全。
        let acl = unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let errno = last_errno();
            return if errno == ENOENT {
                Ok(false)
            } else {
                Err(SysError::Os(errno))
            };
        }
        let mut entry: *mut c_void = std::ptr::null_mut();
        // SAFETY: `acl` は直前に得た非 NULL の `acl_t`（未解放）、`entry` は有効な書き込み先。
        let rc = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) };
        let errno = last_errno();
        // SAFETY: `acl` は `acl_get_fd_np` が返した非 NULL の `acl_t` で他に所有者がいない。ここで 1 回だけ
        // 解放し以後使わない。`entry` は `acl` の内部を指すため解放後は参照しない。
        let _ = unsafe { acl_free(acl) };
        if rc == 0 {
            Ok(!entry.is_null())
        } else if errno == EINVAL {
            Ok(false)
        } else {
            Err(SysError::Os(errno))
        }
    }

    /// 開いた `fd` に拡張 ACL が付いているか。無し=`Ok(false)`・有り=`Ok(true)`・判定不能=`Err`（呼び出し側が拒否）。
    pub(crate) fn has_extended_acl_fd(fd: BorrowedFd<'_>) -> Result<bool, SysError> {
        extended_acl_of_raw(fd.as_raw_fd())
    }

    /// `plugin_fs` の private な定数を `libc` の apple ターゲットと `const` 評価で照合する（#1848・PLUG-11・MAC-1）。
    /// `MAXPATHLEN` は `libc` が `c_int`（= `PATH_MAX`）、自前は `usize` で、`as i128` の比較で値を比べる。
    /// 対象外: `ACL_TYPE_EXTENDED`・`ACL_FIRST_ENTRY`（`libc` の apple に定義が無い。出典は Apple SDK の `sys/acl.h`
    /// で、SDK との照合は #2369 から未了）、`SUPPORTED_ARCH`（FFI の値でない）。
    #[cfg(test)]
    mod libc_abi {
        use libc::c_int;

        const _: () = {
            libc_const_eq!(ENOENT, i32, c_int);
            libc_const_eq!(EBADF, i32, c_int);
            libc_const_eq!(EACCES, i32, c_int);
            libc_const_eq!(ENOTDIR, i32, c_int);
            libc_const_eq!(ERANGE, i32, c_int);
            libc_const_eq!(ELOOP, i32, c_int);
            libc_const_eq!(O_RDONLY, c_int, c_int);
            libc_const_eq!(O_NONBLOCK, c_int, c_int);
            libc_const_eq!(O_NOFOLLOW, c_int, c_int);
            libc_const_eq!(O_NOCTTY, c_int, c_int);
            libc_const_eq!(O_DIRECTORY, c_int, c_int);
            libc_const_eq!(O_CLOEXEC, c_int, c_int);
            libc_const_eq!(AT_FDCWD, c_int, c_int);
            libc_const_eq!(F_GETPATH, c_int, c_int);
            libc_const_eq!(MAXPATHLEN, usize, c_int);
            libc_const_eq!(AT_SYMLINK_NOFOLLOW, c_int, c_int);
            libc_const_eq!(S_IFMT, u16, libc::mode_t);
            libc_const_eq!(S_IFREG, u16, libc::mode_t);
            libc_const_eq!(S_IFDIR, u16, libc::mode_t);
            libc_const_eq!(S_IFLNK, u16, libc::mode_t);
        };

        // `struct stat`（64 bit inode 版）のサイズ・配置を `libc::stat` と照合する（#3096）。
        const _: () = {
            use core::mem::{align_of, offset_of, size_of};
            assert!(size_of::<super::Stat>() == size_of::<libc::stat>());
            assert!(align_of::<super::Stat>() == align_of::<libc::stat>());
            assert!(offset_of!(super::Stat, st_dev) == offset_of!(libc::stat, st_dev));
            assert!(offset_of!(super::Stat, st_mode) == offset_of!(libc::stat, st_mode));
            assert!(offset_of!(super::Stat, st_nlink) == offset_of!(libc::stat, st_nlink));
            assert!(offset_of!(super::Stat, st_ino) == offset_of!(libc::stat, st_ino));
            assert!(offset_of!(super::Stat, st_uid) == offset_of!(libc::stat, st_uid));
            assert!(offset_of!(super::Stat, st_gid) == offset_of!(libc::stat, st_gid));
            assert!(offset_of!(super::Stat, st_rdev) == offset_of!(libc::stat, st_rdev));
            assert!(offset_of!(super::Stat, st_atime) == offset_of!(libc::stat, st_atime));
            assert!(
                offset_of!(super::Stat, st_atime_nsec) == offset_of!(libc::stat, st_atime_nsec)
            );
            assert!(offset_of!(super::Stat, st_mtime) == offset_of!(libc::stat, st_mtime));
            assert!(
                offset_of!(super::Stat, st_mtime_nsec) == offset_of!(libc::stat, st_mtime_nsec)
            );
            assert!(offset_of!(super::Stat, st_ctime) == offset_of!(libc::stat, st_ctime));
            assert!(
                offset_of!(super::Stat, st_ctime_nsec) == offset_of!(libc::stat, st_ctime_nsec)
            );
            assert!(offset_of!(super::Stat, st_birthtime) == offset_of!(libc::stat, st_birthtime));
            assert!(
                offset_of!(super::Stat, st_birthtime_nsec)
                    == offset_of!(libc::stat, st_birthtime_nsec)
            );
            assert!(offset_of!(super::Stat, st_size) == offset_of!(libc::stat, st_size));
            assert!(offset_of!(super::Stat, st_blocks) == offset_of!(libc::stat, st_blocks));
            assert!(offset_of!(super::Stat, st_blksize) == offset_of!(libc::stat, st_blksize));
            assert!(offset_of!(super::Stat, st_flags) == offset_of!(libc::stat, st_flags));
            assert!(offset_of!(super::Stat, st_gen) == offset_of!(libc::stat, st_gen));
            assert!(offset_of!(super::Stat, st_lspare) == offset_of!(libc::stat, st_lspare));
            assert!(offset_of!(super::Stat, st_qspare) == offset_of!(libc::stat, st_qspare));
        };

        // `extern "C"` 関数の型の照合（#1849・#1837）。`openat`・`fcntl` はどちらも可変長で、`libc` も可変長
        // （Apple arm64 ABI は可変長部をスタックに積むため、可変長の食い違いは ABI の不一致になる）。
        // `fcntl$UNIX2003` 等の `link_name` の違いは 32 bit の macOS x86 だけで、本 crate の対応（64 bit の
        // x86_64・aarch64）には該当しない。対象外: `acl_get_fd_np`・`acl_get_entry`・`acl_free`
        // （`libc` の apple に宣言が無い。理由と出典は最上位の `libc_abi` と同じで、SDK との照合は #2369 から未了）。
        const _: unsafe extern "C" fn(c_int, *const libc::c_char, c_int, ...) -> c_int =
            super::openat;
        const _: unsafe extern "C" fn(c_int, *const libc::c_char, c_int, ...) -> c_int =
            libc::openat;
        const _: unsafe extern "C" fn(c_int, c_int, ...) -> c_int = super::fcntl;
        const _: unsafe extern "C" fn(c_int, c_int, ...) -> c_int = libc::fcntl;
        // `fstatat`（#3096）。ポインタ先は別名で、配置は上の `offset_of!` が担う。x86_64 の `fstatat$INODE64` の
        // `link_name` は型照合で検査できない（`libc` も `not(aarch64)` で同じ名前。本 crate は 2 アーキに限る）。
        const _: unsafe extern "C" fn(
            c_int,
            *const libc::c_char,
            *mut super::Stat,
            c_int,
        ) -> c_int = super::fstatat;
        const _: unsafe extern "C" fn(c_int, *const libc::c_char, *mut libc::stat, c_int) -> c_int =
            libc::fstatat;
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::fd::AsFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        use std::path::Path;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        /// 試験ごとに一意な一時ディレクトリ（canonicalize 済み）。Drop で削除する。
        struct Tmp(PathBuf);
        impl Tmp {
            fn new(tag: &str) -> Self {
                let p = std::env::temp_dir().join(format!("fc-1864-{tag}-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&p);
                std::fs::create_dir_all(&p).expect("mkdir");
                Tmp(std::fs::canonicalize(&p).expect("canonicalize"))
            }
        }
        impl Drop for Tmp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn c(s: &str) -> std::ffi::CString {
            std::ffi::CString::new(s).expect("cstring")
        }

        fn open_dir(p: &Path) -> OwnedFd {
            use std::os::unix::ffi::OsStrExt;
            let n = std::ffi::CString::new(p.as_os_str().as_bytes()).expect("cstring");
            open_dir_nofollow_at(None, &n).expect("open dir")
        }

        /// 期限つきで `chmod +a` を実行する（REPAIR-5。超過時は kill して回収し失敗させる）。
        /// 子プロセスを 10 秒の期限つきで待つ。超過時は kill し、回収も 5 秒で打ち切って panic する（REPAIR-5）。
        fn wait_child_limited(child: &mut std::process::Child, what: &str) {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(st) = child.try_wait().expect("try_wait") {
                    assert!(st.success(), "{what} failed: {st}");
                    return;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let reap = Instant::now() + Duration::from_secs(5);
                    while Instant::now() < reap && matches!(child.try_wait(), Ok(None)) {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    panic!("{what} timed out");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn add_acl(path: &Path) {
            let mut child = Command::new("chmod")
                .arg("+a")
                .arg("everyone allow write")
                .arg(path)
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn chmod");
            wait_child_limited(&mut child, "chmod +a");
        }

        #[test]
        fn plug11_1864_nofollow_rejects_symlink_and_reports_std_metadata() {
            let t = Tmp::new("nofollow");
            let dir = open_dir(&t.0);
            std::fs::write(t.0.join("f"), b"x").expect("write");
            std::fs::set_permissions(t.0.join("f"), std::fs::Permissions::from_mode(0o640))
                .expect("chmod");
            symlink("f", t.0.join("l")).expect("symlink");
            assert_eq!(
                open_read_nonblock_nofollow_at(dir.as_fd(), &c("l")).err(),
                Some(SysError::Os(ELOOP))
            );
            let fd = open_read_nonblock_nofollow_at(dir.as_fd(), &c("f")).expect("open f");
            let md = std::fs::File::from(fd).metadata().expect("metadata");
            assert!(md.is_file());
            assert_eq!(md.uid(), super::super::effective_uid());
            assert_eq!(md.mode() & 0o777, 0o640);
        }

        #[test]
        fn plug11_1864_open_dir_nofollow_errors_and_root_walk() {
            let t = Tmp::new("dir");
            let dir = open_dir(&t.0);
            std::fs::create_dir(t.0.join("d")).expect("mkdir");
            std::fs::write(t.0.join("f"), b"x").expect("write");
            symlink("d", t.0.join("l")).expect("symlink");
            let go = |n: &str| open_dir_nofollow_at(Some(dir.as_fd()), &c(n)).err();
            // XNU は O_DIRECTORY の ENOTDIR を O_NOFOLLOW の ELOOP より先に返すため、symlink も ENOTDIR
            // （Linux と同じ。#3126）。拒否されること自体が契約で、エラー種別は区別しない。
            assert_eq!(go("l"), Some(SysError::Os(ENOTDIR)));
            assert_eq!(go("f"), Some(SysError::Os(ENOTDIR)));
            assert_eq!(go("nope"), Some(SysError::Os(ENOENT)));
            assert!(go("d").is_none());
            // `/` から 1 要素ずつ辿れる。
            let root = open_dir_nofollow_at(None, &c("/")).expect("root");
            let root_md = std::fs::File::from(root).metadata().expect("md");
            assert_eq!(root_md.ino(), std::fs::metadata("/").expect("md").ino());
            let mut cur = open_dir_nofollow_at(None, &c("/")).expect("root");
            for comp in t.0.components().skip(1) {
                use std::os::unix::ffi::OsStrExt;
                let n = std::ffi::CString::new(comp.as_os_str().as_bytes()).expect("cstring");
                cur = open_dir_nofollow_at(Some(cur.as_fd()), &n).expect("walk");
            }
            assert_eq!(fd_real_path(cur.as_fd()).expect("path"), t.0);
        }

        #[test]
        fn plug11_1864_search_only_dir_is_eacces() {
            let t = Tmp::new("search");
            std::fs::create_dir(t.0.join("s")).expect("mkdir");
            std::fs::set_permissions(t.0.join("s"), std::fs::Permissions::from_mode(0o311))
                .expect("chmod");
            let dir = open_dir(&t.0);
            // O_RDONLY で開くため、読み取り権限の無いディレクトリは EACCES で拒否される。
            assert_eq!(
                open_dir_nofollow_at(Some(dir.as_fd()), &c("s")).err(),
                Some(SysError::Os(EACCES))
            );
            std::fs::set_permissions(t.0.join("s"), std::fs::Permissions::from_mode(0o700))
                .expect("chmod");
        }

        #[test]
        fn plug11_1864_follow_open_real_path_and_loops() {
            let t = Tmp::new("follow");
            let dir = open_dir(&t.0);
            std::fs::write(t.0.join("real"), b"x").expect("write");
            symlink("real", t.0.join("l")).expect("symlink");
            symlink("a", t.0.join("a")).expect("symlink");
            symlink("y", t.0.join("x")).expect("symlink");
            symlink("x", t.0.join("y")).expect("symlink");
            let fd = open_read_nonblock_follow_at(dir.as_fd(), &c("l")).expect("follow");
            assert_eq!(fd_real_path(fd.as_fd()).expect("path"), t.0.join("real"));
            let md = std::fs::File::from(fd).metadata().expect("md");
            let real = std::fs::metadata(t.0.join("real")).expect("md");
            assert_eq!((md.dev(), md.ino()), (real.dev(), real.ino()));
            for n in ["a", "x", "y"] {
                assert_eq!(
                    open_read_nonblock_follow_at(dir.as_fd(), &c(n)).err(),
                    Some(SysError::Os(ELOOP)),
                    "{n}"
                );
            }
        }

        #[test]
        fn plug11_1864_extended_acl_detected_on_file_and_dir() {
            let t = Tmp::new("acl");
            let dir = open_dir(&t.0);
            std::fs::write(t.0.join("f"), b"x").expect("write");
            std::fs::create_dir(t.0.join("d")).expect("mkdir");
            let f = || open_read_nonblock_nofollow_at(dir.as_fd(), &c("f")).expect("f");
            let d = || open_dir_nofollow_at(Some(dir.as_fd()), &c("d")).expect("d");
            assert_eq!(has_extended_acl_fd(f().as_fd()), Ok(false));
            assert_eq!(has_extended_acl_fd(d().as_fd()), Ok(false));
            assert_eq!(super::super::has_extended_acl(&t.0.join("f")), Ok(false));
            add_acl(&t.0.join("f"));
            add_acl(&t.0.join("d"));
            assert_eq!(has_extended_acl_fd(f().as_fd()), Ok(true));
            assert_eq!(has_extended_acl_fd(d().as_fd()), Ok(true));
            assert_eq!(super::super::has_extended_acl(&t.0.join("f")), Ok(true));
        }

        /// 期限つきで `mkfifo` を実行する（REPAIR-5）。
        fn mkfifo(path: &Path) {
            let mut child = Command::new("mkfifo")
                .arg(path)
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn mkfifo");
            wait_child_limited(&mut child, "mkfifo");
        }

        #[test]
        fn plug11_3096_lstat_at_classifies_entries() {
            let t = Tmp::new("lstat");
            let dir = open_dir(&t.0);
            std::fs::write(t.0.join("f"), b"x").expect("write");
            std::fs::create_dir(t.0.join("d")).expect("mkdir");
            symlink("f", t.0.join("l")).expect("symlink");
            mkfifo(&t.0.join("p"));
            let _sock = std::os::unix::net::UnixListener::bind(t.0.join("s")).expect("bind");
            let kind = |n: &str| lstat_at(dir.as_fd(), &c(n)).expect(n).kind();
            assert_eq!(kind("f"), EntryKind::Regular);
            assert_eq!(kind("d"), EntryKind::Directory);
            assert_eq!(kind("l"), EntryKind::Symlink);
            assert_eq!(kind("p"), EntryKind::Other);
            assert_eq!(kind("s"), EntryKind::Other);
            let devdir = open_dir_nofollow_at(None, &c("/dev")).expect("/dev");
            assert_eq!(
                lstat_at(devdir.as_fd(), &c("null")).expect("null").kind(),
                EntryKind::Other
            );
            assert_eq!(
                lstat_at(dir.as_fd(), &c("nope")).err(),
                Some(SysError::Os(ENOENT))
            );
            let md = std::fs::symlink_metadata(t.0.join("f")).expect("md");
            let st = lstat_at(dir.as_fd(), &c("f")).expect("f");
            assert_eq!((st.dev(), st.ino()), (md.dev(), md.ino()));
        }

        #[test]
        fn plug11_3096_stat_follow_at_resolves_symlink() {
            let t = Tmp::new("sfollow");
            let dir = open_dir(&t.0);
            std::fs::write(t.0.join("real"), b"x").expect("write");
            symlink("real", t.0.join("l")).expect("symlink");
            symlink("a", t.0.join("a")).expect("symlink");
            let st = stat_follow_at(dir.as_fd(), &c("l")).expect("l");
            let real = std::fs::metadata(t.0.join("real")).expect("md");
            assert_eq!(st.kind(), EntryKind::Regular);
            assert_eq!((st.dev(), st.ino()), (real.dev(), real.ino()));
            assert_eq!(
                stat_follow_at(dir.as_fd(), &c("a")).err(),
                Some(SysError::Os(ELOOP))
            );
        }

        #[test]
        fn plug11_1864_invalid_fd_is_ebadf() {
            let bad = c_int::MAX;
            assert_eq!(
                fstatat_raw(bad, &c("x"), 0).err(),
                Some(SysError::Os(EBADF))
            );
            assert_eq!(real_path_of_raw(bad), Err(SysError::Os(EBADF)));
            assert_eq!(extended_acl_of_raw(bad), Err(SysError::Os(EBADF)));
            assert_eq!(
                openat_raw(bad, &c("x"), O_RDONLY).err(),
                Some(SysError::Os(EBADF))
            );
        }
    }
}
