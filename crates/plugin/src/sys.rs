//! syscall・FFI の薄いラッパー（`crates/plugin` の `sys` モジュール。`unsafe` 事前承認の範囲。
//! coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::transport` の UDS listener が、bind 時に自プロセスの実効 uid を取得して配置ディレクトリ
//! 所有者と照合し、accept ごとに接続元の接続時点の実効 uid を取得して照合する（PLUG-12・
//! security.md「別 UID からの接続は peer credential 検証で切断する」）。`libc` / `nix` は依存追加が
//! 禁止（dependency-policy）で `UnixStream::peer_cred` は unstable のため、`crates/io/src/sys.rs` と
//! 同じ流儀で必要最小限の `extern "C"` 宣言を自前で持つ。
//!
//! - Linux（x86_64 / aarch64）: `getsockopt(SOL_SOCKET, SO_PEERCRED)` の `struct ucred`
//! - macOS: `getpeereid(2)`（TASK-124.2・#293。`LOCAL_PEERCRED` の `struct xucred` を自前で写さず libSystem の
//!   安定 ABI に乗り、arch 依存定数を持たないため `target_arch` 分岐は不要。Linux の `SO_PEERCRED` と同じ
//!   「接続時点の実効 uid」を返す共通インターフェース）
//! - Linux・macOS: `fchmodat(2)`（`AT_SYMLINK_NOFOLLOW`。Linux の `fchmodat2` 非対応環境は `O_PATH` fd 経由へ縮退）を
//!   検証済みディレクトリ fd 基準で呼ぶ（パス再解決による TOCTOU を避ける。PLUG-12）。それ以外の unix は
//!   `mode_t` の幅・`AT_SYMLINK_NOFOLLOW` の値を持たないため `fchmodat` を呼ばず `Unsupported`（fail-closed。#1308）
//! - いずれの unix（対応 OS・アーキテクチャ）: `mkdirat(2)` を検証済みディレクトリ fd 基準で呼ぶ（runtime directory の作成。PLUG-12・#1309）
//! - いずれの unix: `unlinkat(2)` を検証済みディレクトリ fd 基準で呼ぶ（OS 依存の型・定数を使わず flags は 0 固定。PLUG-12）
//! - いずれの unix（対応 OS・アーキテクチャ）: `openat(O_NOFOLLOW | O_DIRECTORY)` で配置ディレクトリを
//!   ルートから 1 要素ずつ辿る（祖先要素の symlink を拒否。PLUG-12）
//! - いずれの unix（対応 OS・アーキテクチャ）: `openat(O_CREAT | O_NOFOLLOW)` で bind ロックファイルを開く
//!   （排他ロック自体は std の `File::try_lock`。fork 用のコールバック登録は行わない。PLUG-12・TASK-123.2）
//! - client connect（#249）: `socket(2)` / `connect(2)`（macOS は `fcntl(F_SETFD)` も）で非ブロッキング接続を期限までリトライする（REPAIR-5）。
//!   対応外の OS・アーキテクチャは `Unsupported`
//! - macOS の RSS 取得（TASK-112.1・#265）: `proc_pidinfo(PROC_PIDTASKINFO)`（`resident_size_bytes`。`crate::rss` から呼ばれる）
//! - それ以外の OS・アーキテクチャ: peer credential を取得できないため `Unimplemented`（fail-closed）
//!
//! # 契約
//! - `unsafe fn` は公開しない。公開するのは安全な [`peer_uid`]・[`effective_uid`]・[`fchmodat_nofollow`]・
//!   [`unlinkat`]・[`mkdirat`]・[`lstat_at`]・[`open_dir_nofollow`]・[`lock_file_at`]・[`names_open_file`]・[`connect_unix`]・（macOS のみ）`resident_size_bytes`（いずれも `pub(crate)`）のみ
//! - fd は `&UnixStream` の借用中のみ渡す（呼び出し中にクローズされない）
//! - SOL_SOCKET / SO_PEERCRED の定数は `cfg(target_arch)` ごとに個別定義し、流用しない
//! - OS ごとに値・幅が異なる定数・型（`ModeT`・`AT_SYMLINK_NOFOLLOW`・`O_*` 等）は対応 OS ごとに個別定義し、
//!   対応外 OS 向けの仮置き（他 OS の値の流用）を置かない。値を持たない OS の経路は `Unsupported` で fail-closed
//!   （誤った flags で symlink を追従する経路を作らない。PLUG-12・#1308）

#![cfg(unix)]

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;

use crate::error::{PluginError, PluginErrorCode};

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `uid_t geteuid(void)` と同じ戻り値の型・幅
    // （`uid_t` は `u32`）。引数を取らず、エラー条件を持たない。
    fn geteuid() -> u32;
}

/// 自プロセスの実効 uid を返す（`geteuid(2)`。エラーを返さない）。
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: 引数を取らず、POSIX の規定上エラー条件を持たない。
    unsafe { geteuid() }
}

#[cfg(target_os = "linux")]
type ModeT = u32;
#[cfg(target_os = "macos")]
type ModeT = u16;
// 対応外 OS（Linux・macOS 以外）向けの定義は置かない。値・幅が OS ごとに違い、流用すると
// symlink 追従の flags になり得るため、その経路は `fchmodat_nofollow` が `Unsupported` を返す（PLUG-12・#1308）。

#[cfg(target_os = "linux")]
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
#[cfg(target_os = "macos")]
const AT_SYMLINK_NOFOLLOW: i32 = 0x20;

#[cfg(any(target_os = "linux", target_os = "macos"))]
unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `int fchmodat(int, const char *, mode_t, int)` と
    // 同じ型・幅（`mode_t` は Linux で `u32`、macOS で `u16`。上の `ModeT`）。
    #[link_name = "fchmodat"]
    fn c_fchmodat(dirfd: i32, path: *const core::ffi::c_char, mode: ModeT, flags: i32) -> i32;
}

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `int unlinkat(int, const char *, int)` と同じ型・幅。
    #[link_name = "unlinkat"]
    fn c_unlinkat(dirfd: i32, path: *const core::ffi::c_char, flags: i32) -> i32;
}

/// `dir`（開いたディレクトリ fd）基準で `name` の mode を設定する。最終要素が symlink なら
/// 辿らない（PLUG-12）。
///
/// まず `fchmodat(AT_SYMLINK_NOFOLLOW)` を試す。この flags は Linux 6.6 の `fchmodat2` に依存し、
/// 古いカーネル・libc（musl 等）では `ENOSYS` / `EOPNOTSUPP` / `EINVAL` で失敗するため、Linux では
/// その場合に限り [`fchmodat_via_opath`] へ縮退する（symlink 防御は保ったまま古い環境でも bind 可能にする）。
/// 縮退できない環境はそのままエラー（fail-closed）。Linux・macOS 以外の unix は `mode_t` の幅・
/// `AT_SYMLINK_NOFOLLOW` の値を持たないため `fchmodat` を呼ばず `Unsupported` を返す（fail-closed。#1308）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn fchmodat_nofollow(dir: &File, name: &CStr, mode: u32) -> io::Result<()> {
    let mode = ModeT::try_from(mode).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: fd は `&File` の借用中のため有効。`name` は NUL 終端の有効な C 文字列。
    let rc = unsafe { c_fchmodat(dir.as_raw_fd(), name.as_ptr(), mode, AT_SYMLINK_NOFOLLOW) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        // ENOSYS=38・EINVAL=22・EOPNOTSUPP=95（Linux の errno は x86_64 / aarch64 で共通）。
        if matches!(err.raw_os_error(), Some(38 | 22 | 95)) {
            return fchmodat_via_opath(dir, name, mode);
        }
    }
    Err(err)
}

/// Linux・macOS 以外の unix 向け。`fchmodat` を呼ばず `Unsupported` を返す（fail-closed。#1308）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn fchmodat_nofollow(dir: &File, name: &CStr, mode: u32) -> io::Result<()> {
    let _ = (dir, name, mode);
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// `fchmodat2` 非対応環境向けの縮退実装（Linux のみ）。`name` を `O_PATH | O_NOFOLLOW` で開き、
/// fd 自体が socket であること（symlink・通常ファイルでない）を `statx(AT_EMPTY_PATH)` で確認してから、
/// `/proc/self/fd/<fd>` 経由で chmod する（fd が指す inode に対して作用し、パスは再解決しない）。
/// `/proc` が使えない場合は失敗する（fail-closed）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn fchmodat_via_opath(dir: &File, name: &CStr, mode: ModeT) -> io::Result<()> {
    // O_PATH は x86_64 / aarch64 とも 0o10000000。
    const O_PATH: i32 = 0o10000000;
    // SAFETY: `name` は NUL 終端の有効な C 文字列。`dir` は `&File` の借用中のため有効。
    let fd = unsafe {
        c_openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            O_PATH | O_NOFOLLOW | O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` は直前の openat が返した、他に所有者のいない有効な fd（非負を確認済み）。
    let opened = unsafe { File::from_raw_fd(fd) };
    let ident = statx_ident(opened.as_raw_fd(), c"", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)?;
    if !ident.is_socket {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let proc_path = std::ffi::CString::new(format!("/proc/self/fd/{}", opened.as_raw_fd()))
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `proc_path` は NUL 終端の有効な C 文字列。AT_FDCWD + 絶対パスで、flags=0 は
    // /proc の magic link を辿って検証済み socket inode に作用する（`opened` が生存中は有効）。
    let rc = unsafe { c_fchmodat(AT_FDCWD, proc_path.as_ptr(), mode, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `lstat` 相当の識別情報（同一性照合・所有者・種別の確認用。PLUG-12）。
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct FileIdent {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub is_socket: bool,
    /// symlink 本体か（`lstat` 相当で取得するため、リンク先ではなくリンク自体の種別。PLUG-12）。
    pub is_symlink: bool,
    /// 最終更新時刻（秒・ナノ秒）。socket では作成（bind）時に決まり、chmod・rename・hard link では
    /// 変わらない。inode 番号が再利用された別の socket を dev / ino の一致だけで同一と見なさないための
    /// 同一性の一部（PLUG-12・TASK-123.2）。
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
}

#[cfg(target_os = "linux")]
mod statx_abi {
    /// `struct statx` と同じレイアウト（アーキテクチャ非依存の安定 ABI。256 バイト）。
    #[repr(C)]
    pub(super) struct Statx {
        pub mask: u32,
        pub blksize: u32,
        pub attributes: u64,
        pub nlink: u32,
        pub uid: u32,
        pub gid: u32,
        pub mode: u16,
        pub pad0: u16,
        pub ino: u64,
        pub size: u64,
        pub blocks: u64,
        pub attributes_mask: u64,
        /// `stx_atime`・`stx_btime`・`stx_ctime`・`stx_mtime` の順（各 16 バイト）。
        pub timestamps: [StatxTimestamp; 4],
        pub rdev_major: u32,
        pub rdev_minor: u32,
        pub dev_major: u32,
        pub dev_minor: u32,
        pub tail: [u64; 14],
    }
    const _: () = assert!(core::mem::size_of::<Statx>() == 256);

    /// `struct statx_timestamp` と同じレイアウト（16 バイト）。
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct StatxTimestamp {
        pub sec: i64,
        pub nsec: u32,
        pub reserved: i32,
    }
    const _: () = assert!(core::mem::size_of::<StatxTimestamp>() == 16);
    const _: () = assert!(core::mem::offset_of!(Statx, timestamps) == 64);

    /// `timestamps` 内の `stx_mtime` の位置。
    pub(super) const MTIME_INDEX: usize = 3;

    /// `STATX_TYPE | STATX_MODE | STATX_UID | STATX_MTIME | STATX_INO`。
    pub(super) const REQUIRED_MASK: u32 = 0x1 | 0x2 | 0x8 | 0x40 | 0x100;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: glibc（2.28 以降）/ musl の
        // `int statx(int, const char *, int, unsigned int, struct statx *)` と同じ型・幅。
        pub(super) fn statx(
            dirfd: i32,
            path: *const core::ffi::c_char,
            flags: i32,
            mask: u32,
            buf: *mut Statx,
        ) -> i32;
    }
}

/// `statx(dirfd, name, flags)` を呼び、識別情報へ変換する（Linux のみ。symlink を辿るか否かは
/// `flags` で決まる）。`lstat_at` と、O_PATH fd の同一性確認（`AT_EMPTY_PATH`）から使う。
#[cfg(target_os = "linux")]
fn statx_ident(dirfd: i32, name: &CStr, flags: i32) -> io::Result<FileIdent> {
    let mut st = statx_abi::Statx {
        mask: 0,
        blksize: 0,
        attributes: 0,
        nlink: 0,
        uid: 0,
        gid: 0,
        mode: 0,
        pad0: 0,
        ino: 0,
        size: 0,
        blocks: 0,
        attributes_mask: 0,
        timestamps: [statx_abi::StatxTimestamp {
            sec: 0,
            nsec: 0,
            reserved: 0,
        }; 4],
        rdev_major: 0,
        rdev_minor: 0,
        dev_major: 0,
        dev_minor: 0,
        tail: [0; 14],
    };
    // SAFETY: `dirfd` は呼び出し側が保持する開いた fd。`name` は NUL 終端の有効な C 文字列。
    // `st` はスタック上の 256 バイトの `#[repr(C)]` 領域で、カーネルが書き込む最大サイズと一致。
    let rc = unsafe {
        statx_abi::statx(
            dirfd,
            name.as_ptr(),
            flags,
            statx_abi::REQUIRED_MASK,
            &raw mut st,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if st.mask & statx_abi::REQUIRED_MASK != statx_abi::REQUIRED_MASK {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    let mtime = st
        .timestamps
        .get(statx_abi::MTIME_INDEX)
        .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
    Ok(FileIdent {
        dev: (u64::from(st.dev_major) << 32) | u64::from(st.dev_minor),
        ino: st.ino,
        uid: st.uid,
        is_socket: u32::from(st.mode) & 0o170000 == 0o140000,
        is_symlink: u32::from(st.mode) & 0o170000 == 0o120000,
        mtime_sec: mtime.sec,
        mtime_nsec: mtime.nsec,
    })
}

/// `statx` の `AT_EMPTY_PATH`（fd 自体を対象にする。Linux の全アーキテクチャで共通値）。
#[cfg(target_os = "linux")]
const AT_EMPTY_PATH: i32 = 0x1000;

/// `dir` 基準の `name`（symlink を辿らない）が、開いている `file` と同じ inode（dev / ino）を指すか。
/// `name` が存在しなければ `false`。
///
/// bind ロックの取得後・解放時に、ロックファイル名が「いま flock を持っている inode」をまだ指して
/// いるかを確かめるために使う（保持者が解放時に unlink した古い inode を掴んだ取得者を弾く。
/// PLUG-12・TASK-123.2）。Linux は両方を `statx` で取得しパスを再解決しない。Linux 以外は
/// [`lstat_at`] と同じく `fallback_path` の `symlink_metadata` へ縮退する。
pub(crate) fn names_open_file(
    dir: &File,
    name: &CStr,
    fallback_path: &std::path::Path,
    file: &File,
) -> io::Result<bool> {
    let named = match lstat_at(dir, name, fallback_path) {
        Ok(i) => i,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    #[cfg(target_os = "linux")]
    let (dev, ino) = {
        let i = statx_ident(file.as_raw_fd(), c"", AT_EMPTY_PATH)?;
        (i.dev, i.ino)
    };
    #[cfg(not(target_os = "linux"))]
    let (dev, ino) = {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata()?;
        (m.dev(), m.ino())
    };
    Ok(!named.is_symlink && named.dev == dev && named.ino == ino)
}

/// `dir` 基準で `name`（symlink を辿らない）の識別情報を返す。
///
/// Linux は `statx(dirfd, name, AT_SYMLINK_NOFOLLOW)` でパスを再解決しない。Linux 以外の unix は
/// アーキテクチャ別の `struct stat` を自前で持たないため `fallback_path` の `symlink_metadata` に
/// 縮退する（残余: macOS ではパス再解決の競合窓が残る。ディレクトリ自体は 0700 の自 UID 所有で
/// 同一 UID のみが差し替えられる。TASK-123・TASK-124 で fstatat 化を検討）。
pub(crate) fn lstat_at(
    dir: &File,
    name: &CStr,
    fallback_path: &std::path::Path,
) -> io::Result<FileIdent> {
    #[cfg(target_os = "linux")]
    {
        let _ = fallback_path;
        statx_ident(dir.as_raw_fd(), name, AT_SYMLINK_NOFOLLOW)
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let _ = (dir, name);
        let m = std::fs::symlink_metadata(fallback_path)?;
        Ok(FileIdent {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            is_socket: m.file_type().is_socket(),
            is_symlink: m.file_type().is_symlink(),
            mtime_sec: m.mtime(),
            mtime_nsec: u32::try_from(m.mtime_nsec())
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
        })
    }
}

// openat 用の open(2) フラグ・AT_FDCWD。値は OS・アーキテクチャごとに異なるため個別定義し流用しない。
//
// Linux の `O_DIRECTORY` / `O_NOFOLLOW` は x86_64 が asm-generic の既定値（0o200000 / 0o400000）、
// aarch64 は `arch/arm64/include/uapi/asm/fcntl.h` が既定値を上書きした 0o40000 / 0o100000 を使う
// （aarch64 では 0o200000 は `O_DIRECT`、0o400000 は `O_LARGEFILE`。x86_64 の値を aarch64 へ
// 流用すると symlink を辿るうえに `O_DIRECT` 付きで開いてしまうため、揃えてはならない）。
// `O_CLOEXEC`・`O_PATH`・`AT_FDCWD` は両アーキテクチャで共通。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_DIRECTORY: i32 = 0o200000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_DIRECTORY: i32 = 0o40000;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_NOFOLLOW: i32 = 0o100000;
#[cfg(target_os = "linux")]
const O_CLOEXEC: i32 = 0o2000000;
#[cfg(target_os = "linux")]
const AT_FDCWD: i32 = -100;
#[cfg(target_os = "macos")]
const O_DIRECTORY: i32 = 0x0010_0000;
#[cfg(target_os = "macos")]
const O_NOFOLLOW: i32 = 0x0100;
#[cfg(target_os = "macos")]
const O_CLOEXEC: i32 = 0x0100_0000;
#[cfg(target_os = "macos")]
const AT_FDCWD: i32 = -2;

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `int openat(int, const char *, int, ...)` と同じ型・幅。
    // 可変長引数（mode）は O_CREAT を使う `lock_file_at` だけが渡す（他は渡さない）。
    #[link_name = "openat"]
    fn c_openat(dirfd: i32, path: *const core::ffi::c_char, flags: i32, ...) -> i32;
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `int mkdirat(int, const char *, mode_t)` と同じ型・幅
    // （`mode_t` は Linux で `u32`、macOS で `u16`。上の `ModeT`。確認元: Linux の `man 2 mkdirat`・
    // macOS SDK の `sys/stat.h`）。可変長引数・flags 引数は無い。
    #[link_name = "mkdirat"]
    fn c_mkdirat(dirfd: i32, path: *const core::ffi::c_char, mode: ModeT) -> i32;
}

/// `dirfd` 基準で `name` を `O_DIRECTORY | O_NOFOLLOW` で開く（1 要素）。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn openat_dir_nofollow(dirfd: i32, name: &CStr) -> io::Result<File> {
    // SAFETY: `name` は NUL 終端の有効な C 文字列。`dirfd` は呼び出し側が保持する開いた fd
    // （または AT_FDCWD + 絶対パス）。
    let fd = unsafe { c_openat(dirfd, name.as_ptr(), O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` は直前の openat が返した、他に所有者のいない有効な fd（非負を確認済み）。
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// 絶対パス `abs`（`canonicalize` 済み）をルートから 1 要素ずつ `openat(O_NOFOLLOW | O_DIRECTORY)`
/// で辿り、ディレクトリ fd を返す（PLUG-12）。いずれかの要素が symlink（検証後の差し替えを含む）なら
/// `ELOOP` 等で失敗する（fail-closed）。以降はこの fd を基準に bind・chmod・unlink を行い、
/// パスを再解決しない。未対応の OS・アーキテクチャは `Unsupported`（fail-closed）。
pub(crate) fn open_dir_nofollow(abs: &std::path::Path) -> io::Result<File> {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::path::Component;
        let invalid = || io::Error::from(io::ErrorKind::InvalidInput);
        let mut comps = abs.components();
        if comps.next() != Some(Component::RootDir) {
            return Err(invalid());
        }
        let mut cur = openat_dir_nofollow(AT_FDCWD, c"/")?;
        for c in comps {
            let Component::Normal(n) = c else {
                return Err(invalid());
            };
            let name = CString::new(n.as_bytes()).map_err(|_| invalid())?;
            cur = openat_dir_nofollow(cur.as_raw_fd(), &name)?;
        }
        Ok(cur)
    }
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = abs;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

// ロックファイル作成用の open(2) フラグ。値は OS ごとに異なる。Linux の 4 値は asm-generic の既定値で、
// x86_64・aarch64 とも上書きしないため同値だが、流用せず対応アーキテクチャごとに定義する。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_RDWR: i32 = 0o2;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_CREAT: i32 = 0o100;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_EXCL: i32 = 0o200;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_RDWR: i32 = 0o2;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_CREAT: i32 = 0o100;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_EXCL: i32 = 0o200;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(target_os = "macos")]
const O_RDWR: i32 = 0x2;
#[cfg(target_os = "macos")]
const O_CREAT: i32 = 0x200;
#[cfg(target_os = "macos")]
const O_EXCL: i32 = 0x800;
#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x4;

/// ロックファイルの取得結果（PLUG-12・TASK-123.2）。
#[derive(Debug)]
pub(crate) struct LockHandle {
    /// 排他ロック（`flock`）を保持する fd。close（プロセス終了・クラッシュ含む）で kernel が解放する。
    pub file: File,
    /// 今回の呼び出しで新規作成したか（false なら以前の保持者が作ったロックファイルが残っていた）。
    pub created: bool,
}

/// `dir` 基準で `name` のロックファイルを `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`・0600 で開き
/// （無ければ作成）、非ブロッキングで排他ロックを取る。`O_NONBLOCK` は、既存の名前が FIFO・デバイス
/// 等だった場合に open が相手を待って止まらないようにするため（通常ファイルの読み書きには影響しない。
/// REPAIR-5）。開いた fd が通常ファイルでなければロックせず `PermissionDenied`。他者が保持中なら `WouldBlock`。listener の生存判定に接続 probe を
/// 使わず、「ロックを取れる＝以前の保持者は消えた」で stale を判定するための基盤（既存 listener の
/// accept queue に副作用を与えない。PLUG-12）。未対応の OS・アーキテクチャは `Unsupported`。
///
/// ロックは std の [`File::try_lock`]（Linux・macOS は `flock(2)`）で取り、FFI は `openat` だけに
/// 留める。`flock` は open file description に紐付くため、fork した子は listener の socket fd と
/// 同じくロック fd も継承する（どちらも `O_CLOEXEC` で exec 時に閉じる）。子が両方を持ち続ける間は
/// socket も実際に接続可能なので、ロック保持＝listener 生存という対応は fork をまたいでも崩れない。
/// そのため fork 時に子側のロックだけを外す仕組み（`pthread_atfork` 等）は持たない。
pub(crate) fn lock_file_at(dir: &File, name: &CStr) -> io::Result<LockHandle> {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        let open = |flags: i32| -> io::Result<File> {
            // SAFETY: `dir` は `&File` の借用中のため fd は有効。`name` は NUL 終端の有効な C 文字列。
            // O_CREAT を含むため、可変長引数として mode（C の既定引数昇格後の `unsigned int` 幅）を
            // 1 つ渡す。openat は渡したポインタを呼び出し中しか参照しない。
            let fd = unsafe {
                c_openat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                    0o600u32,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `fd` は直前の openat が返した、他に所有者のいない有効な fd（非負を確認済み）。
            Ok(unsafe { File::from_raw_fd(fd) })
        };
        // 新規作成（O_EXCL）を試し、既にあれば O_CREAT なしで既存を開く。その間に保持者が解放時の
        // unlink をした場合は ENOENT になるため、上限つきで最初からやり直す（`created` を正確に保つ。
        // 上限まで競合し続けた場合は使用中＝`WouldBlock` として返し、待ち続けない。REPAIR-5）。
        const OPEN_ATTEMPTS: usize = 8;
        let mut opened = None;
        for _ in 0..OPEN_ATTEMPTS {
            match open(O_RDWR | O_CREAT | O_EXCL) {
                Ok(f) => {
                    opened = Some((f, true));
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => match open(O_RDWR) {
                    Ok(f) => {
                        opened = Some((f, false));
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                },
                Err(e) => return Err(e),
            }
        }
        let Some((file, created)) = opened else {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        };
        // 通常ファイル以外（FIFO・デバイス等）はロックを試みる前に拒否する（flock 自体が失敗して
        // 理由が分からなくなる OS があるため。内容にも触れない）。
        if !file.metadata()?.is_file() {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        match file.try_lock() {
            Ok(()) => Ok(LockHandle { file, created }),
            Err(std::fs::TryLockError::WouldBlock) => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    }
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = (dir, name);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
/// `dir`（検証済みの開いたディレクトリ fd）基準で、単一要素 `name` のディレクトリを作成する
/// （`mkdirat(2)`。PLUG-12・#1309）。`crate::uds_security` の runtime directory 作成が呼び、
/// パスを再解決しないため、検証後に祖先を差し替えられても検証済みの `dir` の外には作られない。
///
/// 呼び出し元は `name` を `/` を含まない単一要素にする。`mode` は umask 適用前の値。最終要素が
/// symlink でも辿らず `EEXIST`（`ErrorKind::AlreadyExists`）になる。Linux・macOS の対応アーキテクチャ以外は
/// `Unsupported`（fail-closed）。
pub(crate) fn mkdirat(dir: &File, name: &CStr, mode: u32) -> io::Result<()> {
    let mode = ModeT::try_from(mode).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: fd は `&File` の借用中のため有効。`name` は NUL 終端の C 文字列で呼び出しの間生きている。
    // `mkdirat` は fd を返さず、最終要素の symlink は辿らない（存在すれば `EEXIST`）。
    let rc = unsafe { c_mkdirat(dir.as_raw_fd(), name.as_ptr(), mode) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
pub(crate) fn mkdirat(dir: &File, name: &CStr, mode: u32) -> io::Result<()> {
    let _ = (dir, name, mode);
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// `dir`（開いたディレクトリ fd）基準で `name` を unlink する（ディレクトリは対象外: flags=0）。
pub(crate) fn unlinkat(dir: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: fd は `&File` の借用中のため有効。`name` は NUL 終端の有効な C 文字列。
    let rc = unsafe { c_unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    /// `struct ucred` と同じレイアウト。
    #[repr(C)]
    pub(super) struct Ucred {
        pub pid: i32,
        pub uid: u32,
        pub gid: u32,
    }

    pub(super) const UCRED_SIZE: usize = core::mem::size_of::<Ucred>();
    const _: () = assert!(UCRED_SIZE <= u32::MAX as usize);
    pub(super) const UCRED_LEN: u32 = UCRED_SIZE as u32;

    #[cfg(target_arch = "x86_64")]
    pub(super) const SOL_SOCKET: i32 = 1;
    #[cfg(target_arch = "x86_64")]
    pub(super) const SO_PEERCRED: i32 = 17;

    #[cfg(target_arch = "aarch64")]
    pub(super) const SOL_SOCKET: i32 = 1;
    #[cfg(target_arch = "aarch64")]
    pub(super) const SO_PEERCRED: i32 = 17;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: glibc / musl の
        // `int getsockopt(int, int, int, void *, socklen_t *)` と同じ型・幅（`socklen_t` は `u32`）。
        pub(super) fn getsockopt(
            sockfd: i32,
            level: i32,
            optname: i32,
            optval: *mut core::ffi::c_void,
            optlen: *mut u32,
        ) -> i32;
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: libSystem の `int getpeereid(int, uid_t *, gid_t *)` と同じ型・幅。
    fn getpeereid(socket: i32, euid: *mut u32, egid: *mut u32) -> i32;
}

/// 接続元の接続時点の資格情報（SO_PEERCRED）を取得する（Linux）。取得できなければ fail-closed でエラー。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn peer_ucred(stream: &UnixStream) -> Result<linux::Ucred, PluginError> {
    use std::os::unix::io::AsRawFd;
    let mut ucred = linux::Ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = linux::UCRED_LEN;
    // SAFETY: fd は `&UnixStream` の借用中のため有効。`optval` はスタック上の `#[repr(C)]` な
    // `ucred` を指し、`optlen` はそのサイズを指す有効なポインタ。
    let rc = unsafe {
        linux::getsockopt(
            stream.as_raw_fd(),
            linux::SOL_SOCKET,
            linux::SO_PEERCRED,
            (&raw mut ucred).cast(),
            &raw mut len,
        )
    };
    if rc != 0 || len as usize != linux::UCRED_SIZE {
        return Err(PluginError::new(
            PluginErrorCode::Internal,
            "failed to obtain peer credential",
        ));
    }
    Ok(ucred)
}

/// 接続元の接続時点の実効 uid を返す（Linux。SO_PEERCRED。TASK-124.1・#292）。取得できなければ fail-closed でエラー。
/// user namespace 外の uid は overflowuid として観測されうる（照合側で不一致となり拒否される）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32, PluginError> {
    Ok(peer_ucred(stream)?.uid)
}

/// 接続元の pid を返す（Linux。都度起動モードで応答者を spawn した子に限定するため。PLUG-7・PLUG-12）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) fn peer_pid(stream: &UnixStream) -> Result<u32, PluginError> {
    u32::try_from(peer_ucred(stream)?.pid).map_err(|_| {
        PluginError::new(
            PluginErrorCode::Internal,
            "failed to obtain peer credential",
        )
    })
}

/// 接続元の接続時点の実効 uid を返す（macOS。PLUG-12・TASK-124.2）。
///
/// Linux 版と同シグネチャ・同じ意味の値を返す。取得失敗は `Internal` で、呼び出し側（`transport` の
/// accept / connect）は `?` で返して stream を drop し、フレームを読まずに切断する（fail-closed）。
#[cfg(target_os = "macos")]
pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32, PluginError> {
    use std::os::unix::io::AsRawFd;
    let mut euid: u32 = 0;
    let mut egid: u32 = 0;
    // SAFETY: fd は `&UnixStream` の借用中のため有効。2 つのポインタはスタック上の有効な変数を指す。
    let rc = unsafe { getpeereid(stream.as_raw_fd(), &raw mut euid, &raw mut egid) };
    if rc != 0 {
        return Err(PluginError::new(
            PluginErrorCode::Internal,
            "failed to obtain peer credential",
        ));
    }
    Ok(euid)
}

/// 接続元の pid を返す（macOS。`LOCAL_PEERPID`）。
#[cfg(target_os = "macos")]
pub(crate) fn peer_pid(stream: &UnixStream) -> Result<u32, PluginError> {
    use std::os::unix::io::AsRawFd;
    /// `<sys/un.h>` の `SOL_LOCAL`。
    const SOL_LOCAL: i32 = 0;
    /// `<sys/un.h>` の `LOCAL_PEERPID`。
    const LOCAL_PEERPID: i32 = 0x002;
    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: libSystem の
        // `int getsockopt(int, int, int, void *, socklen_t *)` と同じ型・幅（`socklen_t` は `u32`）。
        fn getsockopt(
            sockfd: i32,
            level: i32,
            optname: i32,
            optval: *mut core::ffi::c_void,
            optlen: *mut u32,
        ) -> i32;
    }
    let mut pid: i32 = 0;
    let mut len: u32 = core::mem::size_of::<i32>() as u32;
    // SAFETY: fd は `&UnixStream` の借用中のため有効。`optval` はスタック上の `pid_t`（i32）を指し、
    // `optlen` はそのサイズを指す有効なポインタ。
    let rc = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &raw mut len,
        )
    };
    if rc != 0 || len as usize != core::mem::size_of::<i32>() {
        return Err(PluginError::new(
            PluginErrorCode::Internal,
            "failed to obtain peer credential",
        ));
    }
    u32::try_from(pid).map_err(|_| {
        PluginError::new(
            PluginErrorCode::Internal,
            "failed to obtain peer credential",
        )
    })
}

// ---- 期限付き client connect（PLUG-2・REPAIR-5。TASK-107.5・#249） ----
//
// `UnixStream::connect` は期限を指定できず、Linux では backlog が埋まった listener への blocking
// connect が無期限に待つ。そのため socket を自前で作り、非ブロッキング connect を期限までリトライする。
// 定数・構造体レイアウトは OS ごとに個別定義し流用しない（Linux x86_64 / aarch64 は共通値。
// 対応外の unix は `Unsupported`）。

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod connect_abi {
    pub(super) const AF_UNIX: i32 = 1;

    #[cfg(target_os = "linux")]
    pub(super) const SOCK_STREAM: i32 = 1;
    #[cfg(target_os = "linux")]
    pub(super) const SOCK_CLOEXEC: i32 = 0o2000000;
    #[cfg(target_os = "linux")]
    pub(super) const EISCONN: i32 = 106;
    #[cfg(target_os = "linux")]
    pub(super) const EINPROGRESS: i32 = 115;
    #[cfg(target_os = "linux")]
    pub(super) const EALREADY: i32 = 114;
    #[cfg(target_os = "linux")]
    pub(super) const EAGAIN: i32 = 11;

    #[cfg(target_os = "macos")]
    pub(super) const SOCK_STREAM: i32 = 1;
    #[cfg(target_os = "macos")]
    pub(super) const F_SETFD: i32 = 2;
    #[cfg(target_os = "macos")]
    pub(super) const FD_CLOEXEC: i32 = 1;
    #[cfg(target_os = "macos")]
    pub(super) const EISCONN: i32 = 56;
    #[cfg(target_os = "macos")]
    pub(super) const EINPROGRESS: i32 = 36;
    #[cfg(target_os = "macos")]
    pub(super) const EALREADY: i32 = 37;
    #[cfg(target_os = "macos")]
    pub(super) const EAGAIN: i32 = 35;

    pub(super) const EINTR: i32 = 4;

    #[cfg(target_os = "linux")]
    pub(super) const SUN_PATH_LEN: usize = 108;
    #[cfg(target_os = "macos")]
    pub(super) const SUN_PATH_LEN: usize = 104;

    /// Linux の `struct sockaddr_un`（110 バイト）。
    #[cfg(target_os = "linux")]
    #[repr(C)]
    pub(super) struct SockaddrUn {
        pub sun_family: u16,
        pub sun_path: [u8; SUN_PATH_LEN],
    }
    #[cfg(target_os = "linux")]
    const _: () = assert!(core::mem::size_of::<SockaddrUn>() == 110);

    /// macOS の `struct sockaddr_un`（106 バイト）。
    #[cfg(target_os = "macos")]
    #[repr(C)]
    pub(super) struct SockaddrUn {
        pub sun_len: u8,
        pub sun_family: u8,
        pub sun_path: [u8; SUN_PATH_LEN],
    }
    #[cfg(target_os = "macos")]
    const _: () = assert!(core::mem::size_of::<SockaddrUn>() == 106);

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX の `int socket(int, int, int)` と同じ型・幅。
        pub(super) fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
        // SAFETY（宣言そのものの妥当性）: POSIX の `int connect(int, const struct sockaddr *, socklen_t)`
        // と同じ型・幅（`socklen_t` は `u32`）。
        pub(super) fn connect(sockfd: i32, addr: *const SockaddrUn, addrlen: u32) -> i32;
        // SAFETY（宣言そのものの妥当性）: POSIX の `int fcntl(int, int, ...)` と同じ型・幅。
        #[cfg(target_os = "macos")]
        pub(super) fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }
}

/// `sockaddr_un` の `sun_path` 先頭オフセット（Linux: 2、macOS: 2）。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
const SUN_PATH_OFFSET: usize = 2;

/// connect 成功時にも期限を確認する（REPAIR-5）。期限超過なら成功扱いにせず `TimedOut` を返し、
/// `stream` は Drop で close される。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn connected_within_deadline(
    stream: UnixStream,
    deadline: std::time::Instant,
) -> io::Result<UnixStream> {
    if std::time::Instant::now() > deadline {
        return Err(io::Error::from(io::ErrorKind::TimedOut));
    }
    Ok(stream)
}

/// `path` の UDS へ `deadline` までに非ブロッキング connect し、接続済みの `UnixStream` を返す
/// （非ブロッキングのまま。呼び出し側が blocking へ戻す）。
///
/// `transport` の client 接続（`UdsStream::connect`）から呼ばれる。空・内部 NUL・`sun_path` 超過は
/// `InvalidInput`、期限超過は `TimedOut`、listener の backlog 満杯（Linux の `EAGAIN`）・`EINTR`・
/// `EINPROGRESS` は期限までリトライする。connect 成功時も期限超過なら `TimedOut`。未対応の OS・アーキテクチャは `Unsupported`（fail-closed）。
/// fd は socket 作成直後に `UnixStream` へ所有させ、どの失敗経路でも close される。
pub(crate) fn connect_unix(
    path: &std::path::Path,
    deadline: std::time::Instant,
) -> io::Result<UnixStream> {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        use connect_abi as abi;
        use std::os::unix::ffi::OsStrExt;
        use std::time::{Duration, Instant};

        let bytes = path.as_os_str().as_bytes();
        let invalid = || io::Error::from(io::ErrorKind::InvalidInput);
        // sun_path は終端 NUL を 1 バイト残す（`addr` はゼロ初期化済み）。
        let mut addr: abi::SockaddrUn = abi::SockaddrUn {
            #[cfg(target_os = "macos")]
            sun_len: 0,
            #[cfg(target_os = "macos")]
            sun_family: abi::AF_UNIX as u8,
            #[cfg(target_os = "linux")]
            sun_family: abi::AF_UNIX as u16,
            sun_path: [0; abi::SUN_PATH_LEN],
        };
        if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= addr.sun_path.len() {
            return Err(invalid());
        }
        addr.sun_path
            .get_mut(..bytes.len())
            .ok_or_else(invalid)?
            .copy_from_slice(bytes);
        let addr_len = u32::try_from(SUN_PATH_OFFSET + bytes.len() + 1).map_err(|_| invalid())?;
        #[cfg(target_os = "macos")]
        {
            addr.sun_len = u8::try_from(addr_len).map_err(|_| invalid())?;
        }

        #[cfg(target_os = "linux")]
        let ty = abi::SOCK_STREAM | abi::SOCK_CLOEXEC;
        #[cfg(target_os = "macos")]
        let ty = abi::SOCK_STREAM;
        // SAFETY: 引数は整数のみ。成否は戻り値で確認する。
        let fd = unsafe { abi::socket(abi::AF_UNIX, ty, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` は直前の socket が返した、他に所有者のいない有効な fd（非負を確認済み）。
        // 以降の失敗経路でも `UnixStream` の Drop で close される。
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        #[cfg(target_os = "macos")]
        {
            // SAFETY: `fd` は `stream` が所有する有効な fd。F_SETFD は int 引数 1 つを取る。
            let rc = unsafe { abi::fcntl(fd, abi::F_SETFD, abi::FD_CLOEXEC) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        stream.set_nonblocking(true)?;

        const RETRY_INTERVAL: Duration = Duration::from_millis(5);
        loop {
            // SAFETY: `fd` は `stream` が所有し生存中。`addr` はスタック上の `#[repr(C)]` な
            // `sockaddr_un` で、`addr_len` はその先頭から有効な（NUL 終端込みの）バイト数
            // （構造体サイズ以下であることは上の長さ検査で保証）。
            let rc = unsafe { abi::connect(fd, &raw const addr, addr_len) };
            if rc == 0 {
                return connected_within_deadline(stream, deadline);
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(abi::EISCONN) => return connected_within_deadline(stream, deadline),
                Some(abi::EAGAIN | abi::EINTR | abi::EINPROGRESS | abi::EALREADY) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(io::Error::from(io::ErrorKind::TimedOut));
                    }
                    std::thread::sleep((deadline - now).min(RETRY_INTERVAL));
                }
                _ => return Err(err),
            }
        }
    }
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = (path, deadline);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// 未対応の OS・アーキテクチャでは peer を検証できないため常に拒否する（fail-closed）。
#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
pub(crate) fn peer_uid(_stream: &UnixStream) -> Result<u32, PluginError> {
    Err(PluginError::new(
        PluginErrorCode::Unimplemented,
        "peer credential verification is not implemented for this platform",
    ))
}

/// 未対応の OS・アーキテクチャでは peer pid を検証できないため常に拒否する（fail-closed）。
#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
pub(crate) fn peer_pid(_stream: &UnixStream) -> Result<u32, PluginError> {
    Err(PluginError::new(
        PluginErrorCode::Unimplemented,
        "peer credential verification is not implemented for this platform",
    ))
}
#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::os::unix::net::UnixListener;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("fc-sys-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// PLUG-12: `fchmodat2` 非対応環境向けの縮退経路が socket の mode を設定できる。
    #[test]
    fn opath_fallback_sets_socket_mode_0600() {
        let d = tmpdir("sock");
        let _l = UnixListener::bind(d.join("s.sock")).unwrap();
        let dir = File::open(&d).unwrap();
        fchmodat_via_opath(&dir, c"s.sock", 0o600).unwrap();
        let mode = std::fs::symlink_metadata(d.join("s.sock")).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PLUG-12: 縮退経路でも最終要素が symlink なら辿らず拒否し、リンク先の mode は変えない。
    #[test]
    fn opath_fallback_rejects_symlink_and_leaves_target() {
        let d = tmpdir("link");
        std::fs::write(d.join("target"), b"x").unwrap();
        std::fs::set_permissions(
            d.join("target"),
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .unwrap();
        symlink(d.join("target"), d.join("lnk")).unwrap();
        let dir = File::open(&d).unwrap();
        assert!(fchmodat_via_opath(&dir, c"lnk", 0o600).is_err());
        let mode = std::fs::metadata(d.join("target")).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o644);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// REPAIR-5: 接続自体は成功する状況でも、期限が過ぎていれば成功扱いにせず `TimedOut` を返す。
    #[test]
    fn repair5_connect_unix_expired_deadline_times_out_even_if_connectable() {
        let d = tmpdir("expired");
        let sock = d.join("s.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let past = std::time::Instant::now() - std::time::Duration::from_millis(1);
        let e = connect_unix(&sock, past).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PLUG-2: 期限付き connect の入力検証と未存在パス（OS 依存の errno は NotFound）。
    #[test]
    fn plug2_connect_unix_rejects_bad_paths_and_missing_socket() {
        use std::time::{Duration, Instant};
        let dl = Instant::now() + Duration::from_secs(5);
        let long = std::path::PathBuf::from(format!("/{}", "a".repeat(200)));
        let e = connect_unix(&long, dl).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let e = connect_unix(std::path::Path::new(""), dl).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let e = connect_unix(std::path::Path::new("/tmp/a\0b"), dl).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let d = tmpdir("conn");
        let e = connect_unix(&d.join("none.sock"), dl).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(target_os = "linux")]
    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX の `int listen(int, int)` と同じ型・幅。
        fn listen(sockfd: i32, backlog: i32) -> i32;
    }

    /// REPAIR-5: accept しない listener の backlog が埋まると blocking connect は無期限に待つが、
    /// 期限付き connect は `TimedOut` で戻る（Linux の満杯時 `EAGAIN` 経路。macOS は即
    /// `ECONNREFUSED` のため対象外）。backlog は std の既定が大きく埋めにくいため、テスト内で
    /// `listen(fd, 0)` を再発行して縮める。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_connect_unix_times_out_when_backlog_is_full() {
        use std::time::{Duration, Instant};
        let d = tmpdir("backlog");
        let l = UnixListener::bind(d.join("s.sock")).unwrap();
        // SAFETY: fd は `l` の借用中は有効な listening socket。再 listen は backlog を更新するだけ。
        assert_eq!(unsafe { listen(l.as_raw_fd(), 0) }, 0);
        let mut held = Vec::new();
        let mut timed_out = None;
        for _ in 0..64 {
            let t = Instant::now();
            let dl = t + Duration::from_millis(200);
            match connect_unix(&d.join("s.sock"), dl) {
                Ok(s) => held.push(s),
                Err(e) => {
                    timed_out = Some((e.kind(), t.elapsed()));
                    break;
                }
            }
        }
        let (kind, el) = timed_out.expect("backlog did not fill");
        assert_eq!(kind, io::ErrorKind::TimedOut);
        assert!(el >= Duration::from_millis(200), "{el:?}");
        assert!(el < Duration::from_secs(5), "{el:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PLUG-12・TASK-124.1: 自己接続の peer uid / pid は自プロセスの値と一致する。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn plug12_linux_peer_uid_of_socketpair_equals_effective_uid() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), effective_uid());
        assert_eq!(peer_pid(&a).unwrap(), std::process::id());
    }
}

/// macOS の peer 認証ラッパーの検証（PLUG-12・TASK-124.2・#293）。実 UDS 接続で行う。
#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::net::UnixListener;

    /// 一時ディレクトリ（0700）に listener を bind し、実接続した (client, server) を返す。
    fn connected_pair(tag: &str) -> (UnixStream, UnixStream) {
        let dir = std::env::temp_dir().join(format!("fc-peer-{}-{tag}", std::process::id()));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .expect("create tmp dir");
        let path = dir.join("s");
        let listener = UnixListener::bind(&path).expect("bind");
        let client = UnixStream::connect(&path).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        let _ = std::fs::remove_dir_all(&dir);
        (client, server)
    }

    /// PLUG-12: 両端とも自プロセスの実効 uid を返す。
    #[test]
    fn plug12_macos_peer_uid_matches_effective_uid() {
        let (client, server) = connected_pair("uid");
        let euid = effective_uid();
        assert_eq!(peer_uid(&server).expect("server side"), euid);
        assert_eq!(peer_uid(&client).expect("client side"), euid);
    }

    /// PLUG-12: `LOCAL_PEERPID` は同一プロセス内の接続では自 pid を返す。
    #[test]
    fn plug12_macos_peer_pid_matches_own_pid() {
        let (client, server) = connected_pair("pid");
        assert_eq!(peer_pid(&server).expect("server side"), std::process::id());
        assert_eq!(peer_pid(&client).expect("client side"), std::process::id());
    }
}
// ---- macOS の常駐メモリ（RSS）取得（PLUG-8・PLUG-9。TASK-112.1・#265） ----

/// 指定 pid の常駐メモリ量（バイト）を返す（macOS。libproc の `proc_pidinfo(PROC_PIDTASKINFO)`）。
///
/// `crate::rss` の macOS 実装から呼ばれる。Linux は `/proc` を std で読むためここには FFI を持たない。
/// 戻り値が構造体サイズと一致しない場合は失敗として扱い、構造体を初期化済みとして使わない。
#[cfg(target_os = "macos")]
pub(crate) fn resident_size_bytes(pid: u32) -> io::Result<u64> {
    use core::mem::{MaybeUninit, size_of};

    /// `<sys/proc_info.h>` の `PROC_PIDTASKINFO`。
    const PROC_PIDTASKINFO: i32 = 4;

    /// `<sys/proc_info.h>` の `struct proc_taskinfo`（u64 × 6 ＋ i32 × 12 = 96 バイト。
    /// x86_64 / aarch64 でレイアウトは同一）。
    #[repr(C)]
    struct ProcTaskInfo {
        pti_virtual_size: u64,
        pti_resident_size: u64,
        pti_total_user: u64,
        pti_total_system: u64,
        pti_threads_user: u64,
        pti_threads_system: u64,
        pti_policy: i32,
        pti_faults: i32,
        pti_pageins: i32,
        pti_cow_faults: i32,
        pti_messages_sent: i32,
        pti_messages_received: i32,
        pti_syscalls_mach: i32,
        pti_syscalls_unix: i32,
        pti_csw: i32,
        pti_threadnum: i32,
        pti_numrunning: i32,
        pti_priority: i32,
    }
    // レイアウト誤りをコンパイル時に検出する。
    const _: () = assert!(size_of::<ProcTaskInfo>() == 96);

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: libSystem（libproc）の
        // `int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize)` と同じ型・幅。
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut core::ffi::c_void,
            buffersize: i32,
        ) -> i32;
    }

    let pid = i32::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
    let size = i32::try_from(size_of::<ProcTaskInfo>())
        .map_err(|_| io::Error::other("proc_taskinfo size out of range"))?;
    let mut info = MaybeUninit::<ProcTaskInfo>::uninit();
    // SAFETY: `buffer` は `size` バイト書き込み可能な `MaybeUninit<ProcTaskInfo>` を指し、`buffersize` は
    // その `size_of` と一致する。`arg` は PROC_PIDTASKINFO では未使用（0）。
    let rc = unsafe { proc_pidinfo(pid, PROC_PIDTASKINFO, 0, info.as_mut_ptr().cast(), size) };
    if rc != size {
        // 0 以下は失敗（errno 参照）。それ以外のサイズ不一致も初期化済みとして扱わない。
        return Err(if rc > 0 {
            io::Error::other("proc_pidinfo returned an unexpected size")
        } else {
            io::Error::last_os_error()
        });
    }
    // SAFETY: 戻り値が構造体サイズと一致したため、カーネルが全フィールドを書き込み済み。
    let info = unsafe { info.assume_init() };
    Ok(info.pti_resident_size)
}

/// PLUG-12・#1308: Linux・macOS 以外の OS 向けに他 OS の値を流用した仮置きの `const` / `type` を
/// 置かないことをソース照合で保証する（対応外 OS は CI で実行できないための機械照合。REPAIR-12）。
#[cfg(test)]
mod placeholder_tests {
    #[test]
    fn plug12_no_placeholder_constants_for_unsupported_os() {
        let src = include_str!("sys.rs");
        let lines: Vec<&str> = src.lines().map(str::trim_start).collect();
        let neg = concat!("#[cfg(", "not(any(target_os");
        let mut found = Vec::new();
        for (i, l) in lines.iter().enumerate() {
            if !l.starts_with(neg) {
                continue;
            }
            // 属性行（複数行の場合あり）を飛ばして直後の item を調べる。
            let item = lines[i + 1..].iter().find(|n| {
                !n.starts_with(')')
                    && !n.starts_with("target_os")
                    && !n.starts_with("any(")
                    && !n.starts_with("#[")
            });
            if let Some(n) = item
                && (n.starts_with("const ") || n.starts_with("type ") || n.starts_with("static "))
            {
                found.push(i + 1);
            }
        }
        assert_eq!(found, Vec::<usize>::new());
    }
}
