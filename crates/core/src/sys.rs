//! namespace 分離に使う syscall・FFI の薄いラッパー（`crates/core` の `sys` モジュール。
//! `unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・オーナー決定
//! 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::exec::isolate`・`crate::exec::mount_proc`（CORE-1・TASK-27.2・#134）が、
//! `unshare(2)`・`sethostname(2)`・`mount(2)`・`openat(2)`・`geteuid(2)`・`getegid(2)` を
//! 呼ぶために使う。std だけでは提供されない
//! syscall のみを持ち、検証（hostname の文字種・パス形式等）は呼び出し側の型
//! （`Hostname` 等）が済ませた値だけを受け取る。
//!
//! # 契約（事前承認の条件を満たす設計）
//! - `unsafe fn` はこのモジュールの外へ公開しない。公開するのは安全な関数のみ
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` で理由と
//!   維持すべき不変条件を明記する
//! - syscall の定数は `cfg(target_arch = ...)` ごとに個別に定義し、値が同じでも
//!   他アーキテクチャの定義を流用しない。対応外アーキテクチャでは各ラッパーが
//!   [`SysError::Unsupported`] を返す（fail-closed。`ErrorCode::Unimplemented` に写す）
//! - `extern "C"` の型幅は glibc / musl の宣言に合わせる（`c_int` = `i32`・
//!   `c_ulong` = `u64`・`uid_t`/`gid_t` = `u32`）。戻り値が `-1` のときは直後に
//!   `std::io::Error::last_os_error()` で errno を確保する
//!
//! # `libc` / `nix` について
//! `libc` は #86 で採用承認済みだが、自動運転下では「追加時点で新しい版があれば PR で
//! 確認する」運用条件を満たせないため、`crates/io/src/sys.rs` と同じ流儀で `Cargo.toml`
//! を変更せず必要最小限の `extern "C"` 宣言を自前で持つ（dependency-policy）。

#![cfg(target_os = "linux")]

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};

/// syscall 失敗の分類。`crate::exec` が `ErrorCode` へ写す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysError {
    /// 対応外のアーキテクチャ（定数が未定義）。
    Unsupported,
    /// カーネルが返した errno。
    Os(i32),
}

/// errno の値（アーキテクチャごとに `consts` で個別定義。alpha / mips / sparc 等は値が違う）。
pub(crate) use consts::{EACCES, EINVAL, ELOOP, ENOENT, ENOTDIR, EPERM};

// # `open(2)` フラグのアーキテクチャ差（Codex P0 指摘〔aarch64 の値が誤り〕への確認記録）
//
// `O_DIRECTORY`・`O_NOFOLLOW` は Linux でもアーキテクチャごとに値が違う。x86_64 は
// `arch/x86/include/uapi/asm/` に `fcntl.h` を持たず（`include/uapi/asm-generic/Kbuild` の
// `mandatory-y += fcntl.h` で生成される汎用版）、`include/uapi/asm-generic/fcntl.h` の
// `O_DIRECTORY = 0o200000`・`O_NOFOLLOW = 0o400000` を使う。一方 arm64 は AArch32 互換
// のため `arch/arm64/include/uapi/asm/fcntl.h` で `O_DIRECTORY = 0o40000`・
// `O_NOFOLLOW = 0o100000`・`O_DIRECT = 0o200000`・`O_LARGEFILE = 0o400000` を定義し直して
// いる（Rust `libc` 0.2.189 の `src/unix/linux_like/linux/gnu/b64/aarch64/mod.rs` の
// `O_DIRECTORY = 0x4000`・`O_NOFOLLOW = 0x8000` も同値）。asm-generic の値を arm64 へ流用すると、`O_DIRECTORY` のつもりで `O_DIRECT`、
// `O_NOFOLLOW` のつもりで `O_LARGEFILE` を渡すことになり、ディレクトリ限定と symlink
// 非追従の保証が黙って失われる。そのため下の `consts` はアーキテクチャごとに個別定義し、
// 値は固定値テストで照合する（`crates/io/src/sys.rs` の `beneath_consts` と同じ判断）。
// `O_CLOEXEC`（`0o2000000`）は arm64 も上書きしない asm-generic の値。

/// アーキテクチャごとの clone / mount / open 定数。値が同一でも arch ごとに個別定義する。
#[cfg(target_arch = "x86_64")]
mod consts {
    pub const SUPPORTED: bool = true;
    pub const CLONE_NEWNS: i32 = 0x0002_0000;
    pub const CLONE_NEWUTS: i32 = 0x0400_0000;
    pub const CLONE_NEWIPC: i32 = 0x0800_0000;
    pub const CLONE_NEWUSER: i32 = 0x1000_0000;
    pub const CLONE_NEWPID: i32 = 0x2000_0000;
    pub const MS_NOSUID: u64 = 2;
    pub const MS_NODEV: u64 = 4;
    pub const MS_NOEXEC: u64 = 8;
    pub const MS_REC: u64 = 0x4000;
    pub const MS_PRIVATE: u64 = 0x4_0000;
    // include/uapi/asm-generic/fcntl.h（x86_64 は上書きしない）。
    pub const O_DIRECTORY: i32 = 0o200_000;
    pub const O_NOFOLLOW: i32 = 0o400_000;
    pub const O_CLOEXEC: i32 = 0o2_000_000;
    pub const O_PATH: i32 = 0o10_000_000;
    // include/uapi/asm-generic/errno-base.h・errno.h（x86_64 は上書きしない）。
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EACCES: i32 = 13;
    pub const ENOTDIR: i32 = 20;
    pub const EINVAL: i32 = 22;
    pub const ELOOP: i32 = 40;
}

#[cfg(target_arch = "aarch64")]
mod consts {
    pub const SUPPORTED: bool = true;
    pub const CLONE_NEWNS: i32 = 0x0002_0000;
    pub const CLONE_NEWUTS: i32 = 0x0400_0000;
    pub const CLONE_NEWIPC: i32 = 0x0800_0000;
    pub const CLONE_NEWUSER: i32 = 0x1000_0000;
    pub const CLONE_NEWPID: i32 = 0x2000_0000;
    pub const MS_NOSUID: u64 = 2;
    pub const MS_NODEV: u64 = 4;
    pub const MS_NOEXEC: u64 = 8;
    pub const MS_REC: u64 = 0x4000;
    pub const MS_PRIVATE: u64 = 0x4_0000;
    // arch/arm64/include/uapi/asm/fcntl.h（asm-generic と異なる。x86_64 の値を流用しない。
    // 流用すると O_DIRECT / O_LARGEFILE に化ける）。
    pub const O_DIRECTORY: i32 = 0o40_000;
    pub const O_NOFOLLOW: i32 = 0o100_000;
    // include/uapi/asm-generic/fcntl.h（arm64 も上書きしない）。
    pub const O_CLOEXEC: i32 = 0o2_000_000;
    pub const O_PATH: i32 = 0o10_000_000;
    // include/uapi/asm-generic/errno-base.h・errno.h（arm64 は上書きしない）。
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EACCES: i32 = 13;
    pub const ENOTDIR: i32 = 20;
    pub const EINVAL: i32 = 22;
    pub const ELOOP: i32 = 40;
}

/// 対応外アーキテクチャ: 定数は 0 で、ラッパーは `Unsupported` を返す。errno は実在しない
/// 負の値にして、`std::io::Error` 由来の実 errno と誤って一致させない（分類は `Internal`）。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod consts {
    pub const SUPPORTED: bool = false;
    pub const CLONE_NEWNS: i32 = 0;
    pub const CLONE_NEWUTS: i32 = 0;
    pub const CLONE_NEWIPC: i32 = 0;
    pub const CLONE_NEWUSER: i32 = 0;
    pub const CLONE_NEWPID: i32 = 0;
    pub const MS_NOSUID: u64 = 0;
    pub const MS_NODEV: u64 = 0;
    pub const MS_NOEXEC: u64 = 0;
    pub const MS_REC: u64 = 0;
    pub const MS_PRIVATE: u64 = 0;
    pub const O_DIRECTORY: i32 = 0;
    pub const O_NOFOLLOW: i32 = 0;
    pub const O_CLOEXEC: i32 = 0;
    pub const O_PATH: i32 = 0;
    pub const EPERM: i32 = -1;
    pub const ENOENT: i32 = -2;
    pub const EACCES: i32 = -3;
    pub const ENOTDIR: i32 = -4;
    pub const EINVAL: i32 = -5;
    pub const ELOOP: i32 = -6;
}

/// `openat(2)` の `AT_FDCWD`（絶対パス指定時は dirfd が無視される）。値は
/// `include/uapi/linux/fcntl.h` の全アーキテクチャ共通定義（arch 別の上書きなし）。
const AT_FDCWD: i32 = -100;

/// `unshare(2)` に渡す namespace フラグ 1 種（生のビット値を crate 外へ出さない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NsFlag {
    Mount,
    Uts,
    Ipc,
    User,
    Pid,
}

impl NsFlag {
    /// 対応する `CLONE_NEW*` のビット値。
    pub(crate) fn bits(self) -> i32 {
        match self {
            Self::Mount => consts::CLONE_NEWNS,
            Self::Uts => consts::CLONE_NEWUTS,
            Self::Ipc => consts::CLONE_NEWIPC,
            Self::User => consts::CLONE_NEWUSER,
            Self::Pid => consts::CLONE_NEWPID,
        }
    }
}

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: glibc / musl の `int unshare(int flags)` と同じ型幅。
    fn unshare(flags: i32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int sethostname(const char *name, size_t len)`。
    fn sethostname(name: *const core::ffi::c_char, len: usize) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int mount(const char *source, const char *target,
    // const char *fstype, unsigned long flags, const void *data)`（`c_ulong` は LP64 で u64）。
    fn mount(
        source: *const core::ffi::c_char,
        target: *const core::ffi::c_char,
        fstype: *const core::ffi::c_char,
        flags: u64,
        data: *const core::ffi::c_void,
    ) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int openat(int dirfd, const char *path, int flags, ...)`
    // と同じく可変長引数として宣言する（非可変長で宣言して呼ぶと、可変長引数の渡し方が
    // 異なる ABI で未定義動作になる）。可変長部は mode で、O_CREAT / O_TMPFILE 不使用の
    // ため渡さない（カーネル・libc は読まない）。
    fn openat(dirfd: i32, path: *const core::ffi::c_char, flags: i32, ...) -> i32;
    // SAFETY（宣言そのものの妥当性）: `uid_t geteuid(void)`（Linux の `uid_t` は u32）。
    fn geteuid() -> u32;
    // SAFETY（宣言そのものの妥当性）: `gid_t getegid(void)`（Linux の `gid_t` は u32）。
    fn getegid() -> u32;
}

/// 直前の失敗した syscall の errno を `SysError` にする（失敗直後に呼ぶこと）。
fn last_error() -> SysError {
    SysError::Os(io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

/// 指定 namespace 群を 1 回の `unshare(2)` で分離する。
///
/// `CLONE_NEWUSER` を同時指定すると他 namespace が新 user namespace の所有になり、
/// 非特権でも作成できる。空のフラグは呼び出し側で拒否済みの前提。
pub(crate) fn unshare_namespaces(flags: &[NsFlag]) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let bits = flags.iter().fold(0i32, |acc, f| acc | f.bits());
    // SAFETY: 引数は値渡しの整数のみでポインタを取らない。呼び出し元プロセスの
    // namespace を変更する副作用は `crate::exec::isolate` の契約として文書化済み。
    let rc = unsafe { unshare(bits) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// UTS namespace 内の hostname を設定する。`name` は `Hostname` newtype で検証済みの値。
pub(crate) fn set_hostname(name: &[u8]) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `name.as_ptr()` は `name.len()` バイト有効な借用スライスで、呼び出しの間
    // 生存する。sethostname は NUL 終端を要求せず、長さぶんだけを読む。
    let rc = unsafe { sethostname(name.as_ptr().cast(), name.len()) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `/` を再帰的に private へ変更し、以後のマウントをホストへ伝播させない。
pub(crate) fn mount_root_private_recursive() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `c"/"` は NUL 終端の静的文字列。source / fstype / data は NULL で、
    // MS_REC|MS_PRIVATE の propagation 変更ではカーネルが参照しない。
    let rc = unsafe {
        mount(
            core::ptr::null(),
            c"/".as_ptr(),
            core::ptr::null(),
            consts::MS_REC | consts::MS_PRIVATE,
            core::ptr::null(),
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// [`open_dir_path_nofollow`] が渡す `openat(2)` のフラグ。
///
/// - `O_PATH`: 読み取り権限を要求せず、経路上の search（実行）権限だけで辿れる fd を得る。
///   `CLONE_NEWUSER` 後はホスト所有で実行権限のみ（読み取り不可）の祖先ディレクトリが
///   あり得るため、読み取り可能な fd を要求すると正当なパスでも失敗する（Cursor Bugbot 指摘）。
///   O_PATH fd は `openat` の dirfd と `/proc/self/fd/N` の magic link（`mount(2)` の
///   マウント先）に使え、本モジュールの用途はこの 2 つに限る
/// - `O_DIRECTORY`: **symlink 拒否の要**。`O_PATH|O_NOFOLLOW` だけでは最終要素の symlink
///   そのものを指す fd が返る（`open(2)` の O_PATH 節）。`O_DIRECTORY` を併用することで
///   symlink・非ディレクトリはいずれも `ENOTDIR` で拒否される（実測でも symlink は `ELOOP`
///   ではなく `ENOTDIR`）。このフラグを外すと symlink を固定してしまうため外さない
/// - `O_NOFOLLOW`・`O_CLOEXEC`: 最終要素の symlink を辿らない・exec で fd を漏らさない
fn open_dir_path_flags() -> i32 {
    consts::O_PATH | consts::O_DIRECTORY | consts::O_NOFOLLOW | consts::O_CLOEXEC
}

/// `parent` 配下（`None` なら絶対パス `name` を CWD 非依存で）の `name` を
/// [`open_dir_path_flags`]（`O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`）で開き、fd を返す。
/// 最終要素が symlink・非ディレクトリなら `ENOTDIR`、不在なら `ENOENT`、search 権限が
/// 無ければ `EACCES`。
///
/// 呼び出し側が 1 要素ずつ辿ることで、検証した実体を fd で固定できる（TOCTOU 対策）。
/// 返る fd は O_PATH のため読み書きには使えない（dirfd・`/proc/self/fd/N`・fdinfo 専用）。
pub(crate) fn open_dir_path_nofollow(
    parent: Option<BorrowedFd<'_>>,
    name: &CStr,
) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let dirfd = parent.map_or(AT_FDCWD, |p| p.as_raw_fd());
    let flags = open_dir_path_flags();
    // SAFETY: `name` は借用した NUL 終端文字列で呼び出しの間生存する。`dirfd` は
    // 生存中の `BorrowedFd`（O_PATH fd も dirfd として有効）か `AT_FDCWD`。flags に
    // O_CREAT / O_TMPFILE を含まないため可変長引数（mode）は渡さず、カーネルも読まない。
    // 成功時の戻り値は新規 fd で、直後に `OwnedFd` が唯一の所有者となる（二重 close なし）。
    let fd = unsafe { openat(dirfd, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(last_error());
    }
    // SAFETY: `fd` は上で成功した openat が返した、他に所有者のいない有効な fd。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `target` に procfs を `nosuid,nodev,noexec` でマウントする。
///
/// `crate::exec::mount_proc` は検証済みの O_PATH fd を指す `/proc/self/fd/N` を渡す
/// （magic link は fd の実体へ解決されるため、パス文字列を再解決しない）。
pub(crate) fn mount_proc_at(target: &CStr) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `target` は `&CStr` の借用で NUL 終端かつ呼び出しの間生存する。
    // source / fstype は静的な NUL 終端文字列、data は NULL。
    let rc = unsafe {
        mount(
            c"proc".as_ptr(),
            target.as_ptr(),
            c"proc".as_ptr(),
            consts::MS_NOSUID | consts::MS_NODEV | consts::MS_NOEXEC,
            core::ptr::null(),
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// 自プロセスの実効 uid。
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: 引数なし・常に成功する副作用のない syscall。
    unsafe { geteuid() }
}

/// 自プロセスの実効 gid。
pub(crate) fn effective_gid() -> u32 {
    // SAFETY: 引数なし・常に成功する副作用のない syscall。
    unsafe { getegid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    /// CORE-1: フラグの具体値（Linux の CLONE_NEW* 定義）。
    #[test]
    fn core1_ns_flag_bits_are_exact() {
        assert_eq!(NsFlag::Mount.bits(), 0x0002_0000);
        assert_eq!(NsFlag::Uts.bits(), 0x0400_0000);
        assert_eq!(NsFlag::Ipc.bits(), 0x0800_0000);
        assert_eq!(NsFlag::User.bits(), 0x1000_0000);
        assert_eq!(NsFlag::Pid.bits(), 0x2000_0000);
    }

    /// x86_64: open フラグ・errno は asm-generic の値（include/uapi/asm-generic/fcntl.h・
    /// errno-base.h・errno.h）。
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn core1_open_flags_and_errno_are_exact_x86_64() {
        assert_eq!(consts::O_DIRECTORY, 0o200_000);
        assert_eq!(consts::O_NOFOLLOW, 0o400_000);
        assert_eq!(consts::O_CLOEXEC, 0o2_000_000);
        assert_eq!(consts::O_PATH, 0o10_000_000);
        assert_eq!(open_dir_path_flags(), 0o12_600_000);
        assert_eq!(
            (EPERM, ENOENT, EACCES, ENOTDIR, EINVAL, ELOOP),
            (1, 2, 13, 20, 22, 40)
        );
    }

    /// aarch64: O_DIRECTORY / O_NOFOLLOW は arch/arm64/include/uapi/asm/fcntl.h の上書き値
    /// （asm-generic の 0o200000 / 0o400000 は arm64 では O_DIRECT / O_LARGEFILE）。
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn core1_open_flags_and_errno_are_exact_aarch64() {
        assert_eq!(consts::O_DIRECTORY, 0o40_000);
        assert_eq!(consts::O_NOFOLLOW, 0o100_000);
        assert_eq!(consts::O_CLOEXEC, 0o2_000_000);
        assert_eq!(consts::O_PATH, 0o10_000_000);
        assert_eq!(open_dir_path_flags(), 0o12_140_000);
        assert_eq!(
            (EPERM, ENOENT, EACCES, ENOTDIR, EINVAL, ELOOP),
            (1, 2, 13, 20, 22, 40)
        );
    }

    /// テスト用の一時ディレクトリ（`chmod` で絞ったディレクトリを戻してから削除する）。
    struct TempTree {
        base: std::path::PathBuf,
        restore: Vec<std::path::PathBuf>,
    }

    impl TempTree {
        fn new(label: &str) -> Self {
            let base = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("fandhe-sys-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).unwrap();
            Self {
                base,
                restore: Vec::new(),
            }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;
            for p in &self.restore {
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
            }
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    fn c(path: &std::path::Path) -> std::ffi::CString {
        use std::os::unix::ffi::OsStrExt as _;
        std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap()
    }

    /// fdinfo の `flags:`（八進）。
    fn fd_flags(fd: &OwnedFd) -> i32 {
        let info =
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).unwrap();
        let v = info.lines().find_map(|l| l.strip_prefix("flags:")).unwrap();
        i32::from_str_radix(v.trim(), 8).unwrap()
    }

    /// CORE-1: symlink（ディレクトリを指すもの・宙吊りのもの）と非ディレクトリは `ENOTDIR`、
    /// 不在は `ENOENT` で拒否し、ディレクトリは O_PATH fd として開く。
    #[test]
    fn core1_open_dir_path_nofollow_rejects_symlink_and_non_dir() {
        let t = TempTree::new("nofollow");
        std::fs::create_dir(t.base.join("dir")).unwrap();
        std::fs::write(t.base.join("file"), b"").unwrap();
        std::os::unix::fs::symlink(t.base.join("dir"), t.base.join("link")).unwrap();
        std::os::unix::fs::symlink("/nonexistent", t.base.join("dangling")).unwrap();
        let parent = open_dir_path_nofollow(None, &c(&t.base)).unwrap();
        for (name, want) in [
            (c"link", ENOTDIR),
            (c"dangling", ENOTDIR),
            (c"file", ENOTDIR),
            (c"missing", ENOENT),
        ] {
            let err = open_dir_path_nofollow(Some(parent.as_fd()), name).unwrap_err();
            assert_eq!(err, SysError::Os(want), "{name:?}");
        }
        let dir = open_dir_path_nofollow(Some(parent.as_fd()), c"dir").unwrap();
        assert_eq!(
            std::fs::read_link(format!("/proc/self/fd/{}", dir.as_raw_fd())).unwrap(),
            t.base.join("dir")
        );
        assert_eq!(fd_flags(&dir) & consts::O_PATH, consts::O_PATH);
    }

    /// CORE-1（Cursor Bugbot 指摘の回帰）: 実行権限のみ（読み取り不可）のディレクトリを
    /// 起点・経由として辿れる。root では DAC を迂回するため判別力はないが失敗もしない。
    #[test]
    fn core1_open_dir_path_nofollow_traverses_execute_only_dir() {
        use std::os::unix::fs::PermissionsExt as _;
        let mut t = TempTree::new("xonly");
        let xonly = t.base.join("xonly");
        std::fs::create_dir_all(xonly.join("inner")).unwrap();
        std::fs::set_permissions(&xonly, std::fs::Permissions::from_mode(0o100)).unwrap();
        t.restore.push(xonly.clone());
        if effective_uid() != 0 {
            // 前提の確認: 読み取りで開く従来の方式ではこのディレクトリを開けない。
            let err = std::fs::read_dir(&xonly).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(EACCES));
        }
        let fd = open_dir_path_nofollow(None, &c(&xonly)).unwrap();
        let inner = open_dir_path_nofollow(Some(fd.as_fd()), c"inner").unwrap();
        assert_eq!(
            std::fs::read_link(format!("/proc/self/fd/{}", inner.as_raw_fd())).unwrap(),
            xonly.join("inner")
        );
    }

    /// geteuid は `/proc/self/status` の実効 uid と一致する。
    #[test]
    fn effective_uid_matches_proc_status() {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let line = status.lines().find(|l| l.starts_with("Uid:")).unwrap();
        let euid: u32 = line.split_whitespace().nth(2).unwrap().parse().unwrap();
        assert_eq!(effective_uid(), euid);
    }
}
