//! Windows 向け FFI の薄いラッパー（`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・
//! オーナー決定 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! 提供機能は [`system_directory`] のみ。`wsl2` の `wsl.exe` パス解決（TASK-67.3・WIN-1）が、
//! 環境変数 `SystemRoot`（プロセス起動元が自由に書き換えられる）に頼らず、`GetSystemDirectoryW` で
//! OS が保証するシステムディレクトリを得るために使う。
//!
//! # 不変条件
//! - `unsafe` は本モジュール内に閉じ、公開するのは安全な関数のみ。
//! - 依存（`windows-sys` 等）を増やさず、必要最小限の `extern "system"` 宣言だけを持つ
//!   （dependency-policy「ユーザー承認制」。`crates/io` の `sys` と同方針）。

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

#[link(name = "kernel32")]
unsafe extern "system" {
    // SAFETY（宣言）: `UINT GetSystemDirectoryW(LPWSTR lpBuffer, UINT uSize)`（sysinfoapi.h）。
    // 成功時は終端 NUL を含まない文字数、バッファ不足時は必要サイズ（NUL 込み）、失敗時は 0 を返す。
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
}

/// `GetSystemDirectoryW` で Windows のシステムディレクトリ（通常 `C:\Windows\System32`）を返す。
///
/// 失敗・バッファ不足・空・相対パスの結果は `None`（呼び出し側が fail-closed にする）。
pub(crate) fn system_directory() -> Option<PathBuf> {
    const CAP: usize = 1024;
    let mut buf = [0u16; CAP];
    // SAFETY: `buf` は `CAP` 要素の有効な書き込み可能領域で、`size` に同じ `CAP` を渡す。
    // 関数はこの範囲を超えて書かない。戻り値の `len` は書き込み済みの文字数（NUL 除く）で、
    // `len < CAP` を確認してから `buf.get(..len)` で読む。
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), CAP as u32) } as usize;
    if len == 0 || len >= CAP {
        return None;
    }
    let slice = buf.get(..len)?;
    let path = PathBuf::from(OsString::from_wide(slice));
    path.is_absolute().then_some(path)
}
