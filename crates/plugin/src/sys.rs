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
//! - macOS: `getpeereid(2)`
//! - いずれの unix: `fchmodat(2)`（`AT_SYMLINK_NOFOLLOW`。Linux の `fchmodat2` 非対応環境は `O_PATH` fd 経由へ縮退）・`unlinkat(2)` を検証済みディレクトリ fd
//!   基準で呼ぶ（パス再解決による TOCTOU を避ける。PLUG-12）
//! - いずれの unix（対応 OS・アーキテクチャ）: `openat(O_NOFOLLOW | O_DIRECTORY)` で配置ディレクトリを
//!   ルートから 1 要素ずつ辿る（祖先要素の symlink を拒否。PLUG-12）
//! - いずれの unix（対応 OS・アーキテクチャ）: `openat(O_CREAT | O_NOFOLLOW)` で bind ロックファイルを開く
//!   （排他ロック自体は std の `File::try_lock`。fork 用のコールバック登録は行わない。PLUG-12・TASK-123.2）
//! - client connect（#249）: `socket(2)` / `connect(2)`（macOS は `fcntl(F_SETFD)` も）で非ブロッキング接続を期限までリトライする（REPAIR-5）。
//!   対応外の OS・アーキテクチャは `Unsupported`
//! - それ以外の OS・アーキテクチャ: peer credential を取得できないため `Unimplemented`（fail-closed）
//!
//! # 契約
//! - `unsafe fn` は公開しない。公開するのは安全な [`peer_uid`]・[`effective_uid`]・[`fchmodat_nofollow`]・
//!   [`unlinkat`]・[`lstat_at`]・[`open_dir_nofollow`]・[`lock_file_at`]・[`connect_unix`]（いずれも `pub(crate)`）のみ
//! - fd は `&UnixStream` の借用中のみ渡す（呼び出し中にクローズされない）
//! - SOL_SOCKET / SO_PEERCRED の定数は `cfg(target_arch)` ごとに個別定義し、流用しない

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
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
type ModeT = u32;

#[cfg(target_os = "linux")]
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
#[cfg(target_os = "macos")]
const AT_SYMLINK_NOFOLLOW: i32 = 0x20;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `int fchmodat(int, const char *, mode_t, int)` と
    // 同じ型・幅（`mode_t` は Linux で `u32`、macOS で `u16`。上の `ModeT`）。
    #[link_name = "fchmodat"]
    fn c_fchmodat(dirfd: i32, path: *const core::ffi::c_char, mode: ModeT, flags: i32) -> i32;
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
/// 縮退できない環境・OS はそのままエラー（fail-closed）。
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
    const AT_EMPTY_PATH: i32 = 0x1000;
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
        pub timestamps: [u64; 8],
        pub rdev_major: u32,
        pub rdev_minor: u32,
        pub dev_major: u32,
        pub dev_minor: u32,
        pub tail: [u64; 14],
    }
    const _: () = assert!(core::mem::size_of::<Statx>() == 256);

    /// `STATX_TYPE | STATX_MODE | STATX_UID | STATX_INO`。
    pub(super) const REQUIRED_MASK: u32 = 0x1 | 0x2 | 0x8 | 0x100;

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
        timestamps: [0; 8],
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
    Ok(FileIdent {
        dev: (u64::from(st.dev_major) << 32) | u64::from(st.dev_minor),
        ino: st.ino,
        uid: st.uid,
        is_socket: u32::from(st.mode) & 0o170000 == 0o140000,
        is_symlink: u32::from(st.mode) & 0o170000 == 0o120000,
    })
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

// ロックファイル作成用の open(2) フラグ。値は OS ごとに異なる。Linux の 3 値は asm-generic の既定値で、
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
#[cfg(target_os = "macos")]
const O_RDWR: i32 = 0x2;
#[cfg(target_os = "macos")]
const O_CREAT: i32 = 0x200;
#[cfg(target_os = "macos")]
const O_EXCL: i32 = 0x800;

/// ロックファイルの取得結果（PLUG-12・TASK-123.2）。
#[derive(Debug)]
pub(crate) struct LockHandle {
    /// 排他ロック（`flock`）を保持する fd。close（プロセス終了・クラッシュ含む）で kernel が解放する。
    pub file: File,
    /// 今回の呼び出しで新規作成したか（false なら以前の保持者が作ったロックファイルが残っていた）。
    pub created: bool,
}

/// `dir` 基準で `name` のロックファイルを `O_NOFOLLOW | O_CLOEXEC`・0600 で開き（無ければ作成）、
/// 非ブロッキングで排他ロックを取る。他者が保持中なら `WouldBlock`。listener の生存判定に接続 probe を
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
                    flags | O_NOFOLLOW | O_CLOEXEC,
                    0o600u32,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `fd` は直前の openat が返した、他に所有者のいない有効な fd（非負を確認済み）。
            Ok(unsafe { File::from_raw_fd(fd) })
        };
        let (file, created) = match open(O_RDWR | O_CREAT | O_EXCL) {
            Ok(f) => (f, true),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (open(O_RDWR | O_CREAT)?, false),
            Err(e) => return Err(e),
        };
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

/// 接続元の接続時点の実効 uid を返す（Linux）。取得できなければ fail-closed でエラー。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32, PluginError> {
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
    Ok(ucred.uid)
}

/// 接続元の接続時点の実効 uid を返す（macOS）。
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
}
