//! Windows 向け FFI の薄いラッパー（`crates/io` の `sys` 系モジュール。`unsafe`
//! 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節）。
//!
//! 現状の提供機能は [`file_identity`] のみ。`AppendFileSink::new_at`（IO-2・IO-3・
//! TASK-15.3・#88）が「同期対象の親ディレクトリハンドルとファイルが、パスの指す実体と
//! 同一か」を判定するために、ボリューム シリアル番号とファイル インデックスを取得する。
//! 作成時刻・属性・サイズでの比較は同一タイマー刻みの空ファイル同士や作成時刻を持たない
//! ファイルシステムで衝突するため使わない。
//!
//! # 不変条件
//! - `unsafe` は本モジュール内に閉じ、公開するのは安全な関数のみ。
//! - `windows-sys` 等の依存を増やさず、必要最小限の `extern "system"` 宣言を自前で持つ
//!   （dependency-policy「ユーザー承認制」）。

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;

/// Win32 `FILETIME`（`dwLowDateTime` / `dwHighDateTime`）。
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)] // FFI レイアウト用。読み出さないフィールドを含む。
struct FileTime {
    low: u32,
    high: u32,
}

/// Win32 `BY_HANDLE_FILE_INFORMATION` のレイアウト（全フィールド 4 バイト境界）。
#[repr(C)]
#[allow(dead_code)] // FFI レイアウト用。読み出さないフィールドを含む。
struct ByHandleFileInformation {
    file_attributes: u32,
    creation_time: FileTime,
    last_access_time: FileTime,
    last_write_time: FileTime,
    volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    // SAFETY（宣言）: シグネチャは Win32 の `GetFileInformationByHandle` に一致する。
    // `HANDLE` はポインタ幅（`*mut c_void`）、戻り値は `BOOL`（i32。0 で失敗）。
    fn GetFileInformationByHandle(
        handle: *mut core::ffi::c_void,
        info: *mut ByHandleFileInformation,
    ) -> i32;
}

/// ファイル・ディレクトリの実体識別子（ボリューム シリアル番号と 64 bit ファイル
/// インデックス）を返す。同一ボリューム内で同時に存在する実体は一意に区別できる。
/// 取得できなければ `Err`（呼び出し側は fail-closed で扱う）。
pub(crate) fn file_identity(file: &File) -> io::Result<(u32, u64)> {
    let mut info = core::mem::MaybeUninit::<ByHandleFileInformation>::zeroed();
    // SAFETY: `file` は呼び出し中有効な開いたハンドルを保持している。`info` は
    // `BY_HANDLE_FILE_INFORMATION` と同レイアウトの書き込み可能な領域で、API はこれ以外の
    // メモリへ書かない。ゼロ初期化済みのため、失敗時に読んでも未初期化にならない。
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), info.as_mut_ptr()) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: 上記のとおりゼロ初期化済みで、API 成功時に値が書き込まれている。
    let info = unsafe { info.assume_init() };
    Ok((
        info.volume_serial_number,
        (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low),
    ))
}
