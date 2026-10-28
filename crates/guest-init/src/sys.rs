//! `mount(2)` の薄いラッパー（`unsafe` はこのモジュールに閉じる。#1823 の事前承認の範囲・MAC-1）。
//!
//! ゲスト init が `/proc`・`/sys`・`/dev` と virtiofs の mount に使う。公開するのは用途別の安全な関数
//! （virtiofs・proc・sysfs・devtmpfs）だけで、任意の flags / data は型の上で渡せない（`MS_BIND`・
//! `MS_MOVE`・`MS_REMOUNT` を呼び出し側が組めない。REPAIR-2）。`unsafe fn` は外へ出さない。`extern "C"` 宣言は自前（外部クレートを使わない）。`libc` との機械照合
//! （#1318・#2076）は試験専用モジュール `libc_abi` が const 評価で行い、固定値テストも併用する。
//!
//! 定数は x86_64 / aarch64 の Linux で同値だが、他アーキテクチャへ流用しない（`SUPPORTED` が偽なら
//! `ENOSYS` を返して何も呼ばない）。`c_ulong` が u64 になる LP64 だけを対象にし、x32・ILP32 は `ENOSYS`
//! とする。

use std::ffi::CString;
use std::io;
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

/// `ENOSYS`（Linux 共通）。
const ENOSYS: i32 = 38;

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
}

fn cstring(bytes: &[u8]) -> io::Result<CString> {
    // NUL を含む入力は EINVAL にする（カーネルへ切り詰めた文字列を渡さない）。
    CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(22))
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

/// virtiofs（`tag`）を `target` へ mount する。`init` の `GuestOps::mount_virtiofs` から呼ばれる（MAC-1）。
pub fn mount_virtiofs(tag: &str, target: &Path, read_only: bool) -> io::Result<()> {
    mount_raw(tag, target, "virtiofs", virtiofs_flags(read_only), None)
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
        // `cstring` の中のリテラル 22（EINVAL）。関数内で項目として参照できないため値だけを照合する
        // （`cstring` と試験 `mac1_mount_rejects_nul_with_einval` が使う）。
        assert!(libc::EINVAL == 22);
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn mac1_mount_rejects_nul_with_einval() {
        let e = mount_virtiofs("a\0b", Path::new("/nonexistent"), false).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(22));
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
