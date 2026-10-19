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
//!
//! # 契約
//! - `unsafe fn` は外へ公開しない。すべての `unsafe` に `// SAFETY:` を付ける
//! - 値・型幅は Apple の `sys/fcntl.h`（`O_NONBLOCK` = 0x0004・`O_NOFOLLOW` = 0x0100）、`sys/acl.h`
//!   （`ACL_TYPE_EXTENDED` = 0x100・`acl_t` はポインタ・`acl_type_t` は `unsigned int`）、`geteuid(2)`
//!   （`uid_t` = `u32`）に合わせる。Linux の値は流用しない。対応外アーキテクチャ（x86_64・aarch64 以外）
//!   では値を持たず `None` を返す（fail-closed）
//! - 拡張 ACL は mode bits を迂回して他者に書き込みを許せるため、中身を解釈せず「付いている」だけで
//!   呼び出し側が拒否する（#1539 のオーナー判断と同じ方針）
//! - 追補: macOS 向けの fd 相対 open 等（#1864）は、このファイルへ追記する

#![cfg(target_os = "macos")]

use std::ffi::{CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// `sys` の失敗（errno の値や文言は呼び出し側へ漏らさない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysError {
    /// 引数が不正（パスに NUL を含む等）。
    InvalidInput,
    /// OS が失敗を返した（ACL の読み出しに失敗。権限不足・非対応ファイルシステム等）。
    Os,
}

/// `O_NONBLOCK`（`sys/fcntl.h`）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const O_NONBLOCK: i32 = 0x0004;
/// `O_NOFOLLOW`（`sys/fcntl.h`）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const O_NOFOLLOW: i32 = 0x0100;

/// `ACL_TYPE_EXTENDED`（`sys/acl.h`）。
const ACL_TYPE_EXTENDED: u32 = 0x0000_0100;

// SAFETY（宣言そのものの妥当性）: いずれも libSystem の関数。`uid_t geteuid(void)`、
// `acl_t acl_get_link_np(const char *, acl_type_t)`（`acl_t` は不透明ポインタ・`acl_type_t` は
// `unsigned int`）、`int acl_free(void *)` と同じ型幅。
unsafe extern "C" {
    fn geteuid() -> u32;
    fn acl_get_link_np(path: *const c_char, acl_type: u32) -> *mut c_void;
    fn acl_free(obj: *mut c_void) -> c_int;
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
        return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(SysError::Os)
        };
    }
    // SAFETY: `acl` は `acl_get_link_np` が返した非 NULL の `acl_t` で、他に所有者がいない。
    // ここで 1 回だけ解放し、以後は使わない（リーク防止）。
    let _ = unsafe { acl_free(acl) };
    Ok(true)
}
