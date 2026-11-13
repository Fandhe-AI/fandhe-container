//! `mount(2)` の薄いラッパー（`unsafe` はこのモジュールに閉じる。#1823 の事前承認の範囲・MAC-1）。
//!
//! ゲスト init が `/proc`・`/sys`・`/dev` と virtiofs の mount に使う。公開するのは用途別の安全な関数
//! （virtiofs・proc・sysfs・devtmpfs）だけで、任意の flags / data は型の上で渡せない（`MS_BIND`・
//! `MS_MOVE`・`MS_REMOUNT` を呼び出し側が組めない。REPAIR-2）。`unsafe fn` は外へ出さない。`extern "C"` 宣言は自前（外部クレートを使わない）。`libc` との機械照合
//! （#1318・#2076）は試験専用モジュール `libc_abi` が const 評価で行い、固定値テストも併用する。
//!
//! virtiofs の mount 先は文字列パスではなく fd で固定する（#2268・#2080 P2-4・MAC-1・SEC-1）。`/` から
//! 要素ごとに `openat(O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)` で辿り（欠けた要素は `mkdirat`）、最後の fd を
//! `/proc/self/fd/<n>` として `mount(2)` の target に渡す。検査（open）と mount が同じ fd を指すので、
//! 途中の symlink への差し替えで mount 先がずれない。
//!
//! 定数は `O_DIRECTORY`・`O_NOFOLLOW` を除き x86_64 / aarch64 の Linux で同値（この 2 つはアーキごとに cfg で
//! 分ける）。他アーキテクチャへ流用しない（`SUPPORTED` が偽なら
//! `ENOSYS` を返して何も呼ばない）。`c_ulong` が u64 になる LP64 だけを対象にし、x32・ILP32 は `ENOSYS`
//! とする。

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// 対応アーキテクチャ（定数を検証済みのもの）。
/// `c_ulong` が u64 になる LP64 に限る（x32・ILP32 は除外）。
const SUPPORTED: bool = cfg!(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_pointer_width = "64"
));

/// 読み取り専用。
const MS_RDONLY: u64 = 1;
/// setuid / setgid を無効にする。
const MS_NOSUID: u64 = 2;
/// デバイスファイルを無効にする。
const MS_NODEV: u64 = 4;
/// 実行を禁止する。
const MS_NOEXEC: u64 = 8;
/// `open(2)` で制御端末にしない。値は asm-generic（x86_64・aarch64）のもので、`SUPPORTED` と同じ
/// 対象に cfg で閉じる（他 arch の値を流用しない。#3202・MVM-4）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub const O_NOCTTY: i32 = 0o400;
/// 対象外 arch では値を確かめていないため flag を付けない（0）。この arch では mount 系が `ENOSYS` を返し
/// init は先へ進まないので、コンソールの開き方の差は実害を生まない。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const O_NOCTTY: i32 = 0;

/// パス解決だけに使う fd を開く（読み書きはできない）。
const O_PATH: i32 = 0o10000000;
/// exec で子へ引き継がない（将来の子プロセスへ fd を漏らさない）。
const O_CLOEXEC: i32 = 0o2000000;
/// ディレクトリでなければ失敗する。値はアーキごとに違う（asm-generic と arm64 の uapi）。
#[cfg(target_arch = "x86_64")]
const O_DIRECTORY: i32 = 0o200000;
#[cfg(target_arch = "aarch64")]
const O_DIRECTORY: i32 = 0o40000;
/// 末尾要素が symlink なら辿らず失敗する。値はアーキごとに違う。
#[cfg(target_arch = "x86_64")]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(target_arch = "aarch64")]
const O_NOFOLLOW: i32 = 0o100000;
/// 対象外 arch では `SUPPORTED` が偽で syscall を呼ばないため、値は使われない（0）。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const O_DIRECTORY: i32 = 0;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const O_NOFOLLOW: i32 = 0;
/// `openat` の dirfd に渡す「カレントディレクトリ」（絶対パスでは無視される）。
const AT_FDCWD: i32 = -100;
/// 要素を開くときのフラグ。呼び出し側からは組めない（REPAIR-2）。
const OPEN_DIR_FLAGS: i32 = O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
/// 欠けた要素を作るときの mode（umask 前）。
const MKDIR_MODE: u32 = 0o755;

/// `ENOSYS`（Linux 共通）。
const ENOSYS: i32 = 38;
/// `EINVAL`（Linux 共通）。
const EINVAL: i32 = 22;

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: `int mount(const char *source, const char *target,
    // const char *fstype, unsigned long flags, const void *data)`。`c_ulong` は LP64（x86_64・aarch64 の
    // Linux。glibc / musl）で u64。
    fn mount(
        source: *const core::ffi::c_char,
        target: *const core::ffi::c_char,
        fstype: *const core::ffi::c_char,
        flags: u64,
        data: *const core::ffi::c_void,
    ) -> i32;

    // SAFETY（宣言そのものの妥当性）: `int openat(int dirfd, const char *path, int flags, ...)`。
    // 可変長引数は `O_CREAT`・`O_TMPFILE` のときだけ読まれ、本モジュールは常に渡さない。
    fn openat(dirfd: i32, path: *const core::ffi::c_char, flags: i32, ...) -> i32;

    // SAFETY（宣言そのものの妥当性）: `int mkdirat(int dirfd, const char *path, mode_t mode)`。
    // `mode_t` は Linux で u32。
    fn mkdirat(dirfd: i32, path: *const core::ffi::c_char, mode: u32) -> i32;
}

fn cstring(bytes: &[u8]) -> io::Result<CString> {
    // NUL を含む入力は EINVAL にする（カーネルへ切り詰めた文字列を渡さない）。
    CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(EINVAL))
}

/// 1 要素の名前だけを許す（空・`.`・`..`・`/` を含む・NUL を含むものは EINVAL）。
/// `MountPoint` の検証に加えた多重防御で、親 fd の外へ出る解決を作らない。
fn single_element(name: &str) -> io::Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::from_raw_os_error(EINVAL));
    }
    cstring(name.as_bytes())
}

fn wrap_fd(rc: i32) -> io::Result<OwnedFd> {
    if rc >= 0 {
        // SAFETY: `rc` は直前の成功した `openat` が返した fd で、他に所有者がいない。
        Ok(unsafe { OwnedFd::from_raw_fd(rc) })
    } else {
        // 直後に errno を取る（間に libc 呼び出しを挟まない）。
        Err(io::Error::last_os_error())
    }
}

fn open_dir_at(dirfd: i32, path: &CString) -> io::Result<OwnedFd> {
    if !SUPPORTED {
        return Err(io::Error::from_raw_os_error(ENOSYS));
    }
    // SAFETY: `path` は NUL 終端の `CString` でこの呼び出しが戻るまで生存する。`dirfd` は呼び出し元の
    // `BorrowedFd`（借用中は有効）か `AT_FDCWD`。`O_CREAT` を含まないので可変長引数は読まれない。
    // errno は `wrap_fd` が直後に取る。
    let rc = unsafe { openat(dirfd, path.as_ptr(), OPEN_DIR_FLAGS) };
    wrap_fd(rc)
}

/// `/` を symlink を辿らずに開く（fd 起点の辿りの出発点。MAC-1）。
pub fn open_root_dir() -> io::Result<OwnedFd> {
    open_dir_at(AT_FDCWD, &cstring(b"/")?)
}

/// `parent` 直下の実ディレクトリ `name` を開く。symlink・非ディレクトリは `ENOTDIR` で失敗する。
pub fn open_child_dir(parent: BorrowedFd<'_>, name: &str) -> io::Result<OwnedFd> {
    let name = single_element(name)?;
    open_dir_at(parent.as_raw_fd(), &name)
}

/// `parent` 直下にディレクトリ `name` を作る（mode 0o755）。既存なら `EEXIST`。
pub fn mkdir_child(parent: BorrowedFd<'_>, name: &str) -> io::Result<()> {
    let name = single_element(name)?;
    if !SUPPORTED {
        return Err(io::Error::from_raw_os_error(ENOSYS));
    }
    // SAFETY: `name` は NUL 終端の `CString` でこの呼び出しが戻るまで生存し、`parent` は借用中有効な fd。
    // mkdirat(2) はポインタ先を読むだけで保持しない。errno は直後に取る。
    let rc = unsafe { mkdirat(parent.as_raw_fd(), name.as_ptr(), MKDIR_MODE) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// fd を指す `/proc/self/fd/<n>`（`mount(2)` の target に渡す。先に mount 済みの proc が前提）。
fn proc_fd_path(fd: RawFd) -> String {
    format!("/proc/self/fd/{fd}")
}

/// virtiofs の mount flags（nosuid・nodev は fail-closed の既定。`ro` は必ず `MS_RDONLY`）。
fn virtiofs_flags(read_only: bool) -> u64 {
    let flags = MS_NOSUID | MS_NODEV;
    if read_only { flags | MS_RDONLY } else { flags }
}

/// proc・sysfs の flags（nosuid・nodev・noexec）。
const PSEUDO_STRICT: u64 = MS_NOSUID | MS_NODEV | MS_NOEXEC;
/// devtmpfs の flags（デバイスノードを置くため nodev は付けない）。
const DEVTMPFS_FLAGS: u64 = MS_NOSUID | MS_NOEXEC;

/// `mount(source, target, fstype, flags, data)` を呼ぶ。本モジュール内の用途別関数だけが呼ぶ。
/// 失敗は直後の errno を `io::Error` で返す。
fn mount_raw(
    source: &str,
    target: &Path,
    fstype: &str,
    flags: u64,
    data: Option<&str>,
) -> io::Result<()> {
    if !SUPPORTED {
        return Err(io::Error::from_raw_os_error(ENOSYS));
    }
    let source = cstring(source.as_bytes())?;
    let target = cstring(target.as_os_str().as_bytes())?;
    let fstype = cstring(fstype.as_bytes())?;
    let data = data.map(|d| cstring(d.as_bytes())).transpose()?;
    let data_ptr = data.as_ref().map_or(core::ptr::null(), |d| {
        d.as_ptr().cast::<core::ffi::c_void>()
    });
    // SAFETY: `source`・`target`・`fstype` は NUL 終端の `CString` で、この呼び出しが戻るまで生存する。
    // `data` は null か、同様に生存する NUL 終端文字列（呼び出し元は本モジュールの用途別関数だけで、
    // devtmpfs の `mode=0755` 固定か null）。`flags` は `c_ulong`（u64、LP64 のみ `SUPPORTED`）と同幅。
    // mount(2) はポインタ先を読むだけで保持しない。errno は直後に取る。
    let rc = unsafe {
        mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            data_ptr,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        // 直後に errno を取る（間に libc 呼び出しを挟まない）。
        Err(io::Error::last_os_error())
    }
}

/// virtiofs（`tag`）を、開いた fd が指すディレクトリへ mount する。`init` の `GuestOps::mount_virtiofs` から
/// 呼ばれる（MAC-1・#2268）。`target` は呼び出しが戻るまで借用で生きている。
pub fn mount_virtiofs_at(tag: &str, target: BorrowedFd<'_>, read_only: bool) -> io::Result<()> {
    let path = proc_fd_path(target.as_raw_fd());
    mount_raw(
        tag,
        Path::new(&path),
        "virtiofs",
        virtiofs_flags(read_only),
        None,
    )
}

/// proc を `target` へ mount する（nosuid・nodev・noexec）。
pub fn mount_proc(target: &Path) -> io::Result<()> {
    mount_raw("proc", target, "proc", PSEUDO_STRICT, None)
}

/// sysfs を `target` へ mount する（nosuid・nodev・noexec）。
pub fn mount_sysfs(target: &Path) -> io::Result<()> {
    mount_raw("sysfs", target, "sysfs", PSEUDO_STRICT, None)
}

/// devtmpfs を `target` へ mount する（nosuid・noexec、`mode=0755` 固定）。
pub fn mount_devtmpfs(target: &Path) -> io::Result<()> {
    mount_raw(
        "devtmpfs",
        target,
        "devtmpfs",
        DEVTMPFS_FLAGS,
        Some("mode=0755"),
    )
}

/// 自前の FFI 宣言・定数と `libc`（dev-dependencies のみ）のコンパイル時照合（#2076・#1318・MVM-4・REPAIR-12。
/// 方式は docs/design/ffi-libc-check.md）。食い違えば const 評価（E0080）か型不一致（E0308）で
/// ビルドが落ちる。評価されるターゲット: x86_64-unknown-linux-gnu（ネイティブ）、
/// aarch64-unknown-linux-gnu と製品のターゲット aarch64-unknown-linux-musl（cross-target-check の型検査。
/// const は評価される）。libc 0.2.189 では下記の値も `mount` の宣言も x86_64・aarch64 の gnu と musl で
/// 同一なので `target_env` では分けない（一次情報: libc の `unix/linux_like/mod.rs`・`linux_l4re_shared.rs`、
/// Linux uapi の `linux/mount.h`・`asm-generic/fcntl.h`・`asm-generic/errno-base.h`・`errno.h`）。
/// `SUPPORTED` と同じ LP64（x86_64・aarch64）に限る。他は `SUPPORTED` が偽で呼ばないため評価しない。
/// 対象外: `SUPPORTED`（cfg の判定で FFI でない）、`PSEUDO_STRICT`・`DEVTMPFS_FLAGS`・`virtiofs_flags`
/// （方針値で `libc` に無い。構成要素は照合済みで組み合わせは固定値テストが見る）、安全なラッパー群。
#[cfg(all(
    test,
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_pointer_width = "64"
))]
mod libc_abi {
    use super::*;

    // 型合わせに `as` は使わない。LP64 では u64 == c_ulong、i32 == c_int なので型が変われば E0308 になる。
    const _: () = {
        let _: libc::c_ulong = MS_RDONLY;
        assert!(MS_RDONLY == libc::MS_RDONLY);
        assert!(MS_NOSUID == libc::MS_NOSUID);
        assert!(MS_NODEV == libc::MS_NODEV);
        assert!(MS_NOEXEC == libc::MS_NOEXEC);
        assert!(O_NOCTTY == libc::O_NOCTTY);
        assert!(ENOSYS == libc::ENOSYS);
        assert!(EINVAL == libc::EINVAL);
        let _: libc::c_int = O_PATH;
        assert!(O_PATH == libc::O_PATH);
        assert!(O_DIRECTORY == libc::O_DIRECTORY);
        assert!(O_NOFOLLOW == libc::O_NOFOLLOW);
        assert!(O_CLOEXEC == libc::O_CLOEXEC);
        assert!(AT_FDCWD == libc::AT_FDCWD);
        let _: libc::mode_t = MKDIR_MODE;
    };

    // `mount` の型を自前の宣言と `libc` の宣言で同じ関数ポインタ型へ代入して照合する。
    type MountFn = unsafe extern "C" fn(
        *const libc::c_char,
        *const libc::c_char,
        *const libc::c_char,
        libc::c_ulong,
        *const libc::c_void,
    ) -> libc::c_int;
    const _: MountFn = mount;
    const _: MountFn = libc::mount;

    // `openat` は可変長。関数ポインタ型へそのまま代入して照合する（引数・戻り値・可変長の有無が一致すること）。
    type OpenatFn =
        unsafe extern "C" fn(libc::c_int, *const libc::c_char, libc::c_int, ...) -> libc::c_int;
    const _: OpenatFn = openat;
    const _: OpenatFn = libc::openat;
    type MkdiratFn =
        unsafe extern "C" fn(libc::c_int, *const libc::c_char, libc::mode_t) -> libc::c_int;
    const _: MkdiratFn = mkdirat;
    const _: MkdiratFn = libc::mkdirat;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn mac1_flag_constants_match_linux_abi() {
        assert_eq!(MS_RDONLY, 1);
        assert_eq!(MS_NOSUID, 2);
        assert_eq!(MS_NODEV, 4);
        assert_eq!(MS_NOEXEC, 8);
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        assert_eq!(O_NOCTTY, 0o400);
    }

    #[test]
    fn mac1_virtiofs_flags_compose() {
        assert_eq!(virtiofs_flags(true), 7);
        assert_eq!(virtiofs_flags(false), 6);
    }

    #[test]
    fn mac1_pseudo_flags_compose() {
        assert_eq!(PSEUDO_STRICT, 14);
        assert_eq!(DEVTMPFS_FLAGS, 10);
    }

    #[test]
    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_pointer_width = "64"
    ))]
    fn mac1_supported_on_lp64_targets() {
        const { assert!(SUPPORTED) };
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn mac1_2268_dir_flags_x86_64() {
        assert_eq!(O_DIRECTORY, 0o200000);
        assert_eq!(O_NOFOLLOW, 0o400000);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn mac1_2268_dir_flags_aarch64() {
        assert_eq!(O_DIRECTORY, 0o40000);
        assert_eq!(O_NOFOLLOW, 0o100000);
    }

    #[test]
    fn mac1_2268_common_constants_and_proc_path() {
        assert_eq!(O_PATH, 0o10000000);
        assert_eq!(O_CLOEXEC, 0o2000000);
        assert_eq!(AT_FDCWD, -100);
        assert_eq!(proc_fd_path(7), "/proc/self/fd/7");
    }

    #[test]
    fn mac1_2268_child_rejects_non_single_element() {
        let root = open_root_dir().unwrap();
        for bad in ["", ".", "..", "a/b", "a\0b"] {
            let e = open_child_dir(root.as_fd(), bad).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(22), "{bad:?}");
            let e = mkdir_child(root.as_fd(), bad).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(22), "{bad:?}");
        }
    }

    #[test]
    fn mac1_mount_rejects_nul_with_einval() {
        let root = open_root_dir().unwrap();
        let e = mount_virtiofs_at("a\0b", root.as_fd(), false).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(22));
    }

    #[test]
    fn mac1_2268_mount_at_fails_without_effect_when_unprivileged() {
        // 一時ディレクトリの fd への virtiofs mount は、非特権なら失敗し何も mount されない
        // （root の環境では tag が存在せず ENODEV 等で失敗する）。
        let dir = std::env::temp_dir();
        let f = std::fs::File::open(&dir).unwrap();
        let e = mount_virtiofs_at("fandhe-no-such-tag", f.as_fd(), true).unwrap_err();
        assert!(e.raw_os_error().is_some_and(|n| n > 0));
    }

    #[test]
    fn mac1_mount_of_unknown_fs_fails_without_effect() {
        // 存在しない fstype・target への mount は権限の有無に関わらず失敗し、何も mount されない。
        let e = mount_raw(
            "x",
            Path::new("/nonexistent-fandhe-guest-init"),
            "nosuchfs",
            0,
            None,
        )
        .unwrap_err();
        assert!(e.raw_os_error().is_some_and(|n| n > 0));
    }

    #[test]
    fn mac1_mount_proc_to_missing_target_fails() {
        let e = mount_proc(Path::new("/nonexistent-fandhe-guest-init")).unwrap_err();
        assert!(e.raw_os_error().is_some_and(|n| n > 0));
    }
}
