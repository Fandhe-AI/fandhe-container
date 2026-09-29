//! Windows 向け FFI の薄いラッパー（`crates/io` の `sys` 系モジュール。`src/sys/` 配下。
//! `unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・オーナー決定
//! 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! 提供機能は [`open_file_beneath`] と [`flush_file_buffers`]。後者は `crate::barrier` の
//! Windows の代替フラッシュ（IO-2・IO-3・TASK-15.3・#88）が、ファイル・ディレクトリの
//! ハンドルに `FlushFileBuffers` を明示的に発行するために使う（std の `File::sync_all` の
//! 実装に依存しない）。前者は`crate::writeback::AppendFileSink::open_in`
//! （IO-2・IO-3・TASK-15.3・#88）が、書き込み先のファイルを「先に開いたディレクトリ
//! ハンドル相対」で開くために `NtCreateFile`（`OBJECT_ATTRIBUTES.RootDirectory`）を呼ぶ。
//! パスを再解決しないため、sink が同期する親ディレクトリハンドルがファイルを開いた
//! ディレクトリそのものであることを、識別子の比較（ファイル ID が 0 や非一意になる FS で
//! 誤判定しうる。Cursor #1146 指摘）ではなく構造で保証する。std の安定 API には
//! ディレクトリハンドル相対のオープンがないため FFI で持つ。
//!
//! # 不変条件
//! - `unsafe` は本モジュール内に閉じ、公開するのは安全な関数のみ（`unsafe fn` を外へ
//!   出さない）。
//! - `windows-sys` 等の依存を増やさず、必要最小限の `extern "system"` 宣言と構造体
//!   レイアウトを自前で持つ（dependency-policy「ユーザー承認制」）。レイアウトは
//!   Windows SDK（`winternl.h`・`ntdef.h`・`wdm.h`）の定義に合わせ、ポインタ幅に依存する
//!   フィールドは Rust のポインタ型・`usize` で表す（x86 / x86_64 / aarch64 共通）。
//! - 返すハンドルは `FILE_SYNCHRONOUS_IO_NONALERT` で開いた同期ハンドル（std の `File`
//!   が前提とする形）。

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle};

use crate::writeback::LeafOpen;

/// `UNICODE_STRING`（`Length`・`MaximumLength` はバイト数。NUL 終端を要求しない）。
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

/// `OBJECT_ATTRIBUTES`。
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *const c_void,
    security_quality_of_service: *const c_void,
}

/// `IO_STATUS_BLOCK`（先頭は `NTSTATUS` と `PVOID` の共用体のためポインタ幅で持つ）。
#[repr(C)]
struct IoStatusBlock {
    status_or_pointer: *mut c_void,
    information: usize,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    // SAFETY（宣言）: `BOOL FlushFileBuffers(HANDLE hFile)`（fileapi.h）。`HANDLE` は
    // ポインタ幅、`BOOL` は i32（0 で失敗）。
    fn FlushFileBuffers(handle: *mut c_void) -> i32;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    // SAFETY（宣言）: シグネチャは `NtCreateFile`（wdm.h / winternl.h）に一致する。
    // `HANDLE`・`PVOID` はポインタ幅、`ACCESS_MASK`・`ULONG` は u32、`PLARGE_INTEGER` は
    // `*const i64`、戻り値の `NTSTATUS` は i32（負で失敗）。
    fn NtCreateFile(
        file_handle: *mut *mut c_void,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const c_void,
        ea_length: u32,
    ) -> i32;
    // SAFETY（宣言）: `ULONG RtlNtStatusToDosError(NTSTATUS)`。メモリへ触れない。
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

// アクセス権（winnt.h）。
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
/// `FILE_GENERIC_WRITE`（`STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES |
/// FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE`。`SYNCHRONIZE` は同期 I/O に必須）。
const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
// 共有モード: std の `OpenOptions` の既定と同じ（READ | WRITE | DELETE）。
const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
// 作成方法（wdm.h）。
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
// 作成オプション（wdm.h）。
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `OBJ_CASE_INSENSITIVE`（Win32 の `CreateFileW` と同じ名前解決にそろえる）。
const OBJ_CASE_INSENSITIVE: u32 = 0x40;

/// `dir`（開いたディレクトリハンドル）直下のファイル `name` を、パスを再解決せずに
/// 書き込み用に開く（`NtCreateFile` の `RootDirectory`。IO-2・IO-3・TASK-15.3）。
///
/// 末端の reparse point は辿らない（`FILE_OPEN_REPARSE_POINT`。辿らずに reparse point
/// 自体を開くため、通常ファイルかどうかは呼び出し側が属性で確かめる）。ディレクトリは
/// 開かない（`FILE_NON_DIRECTORY_FILE`）。`name` は単一の名前であること（区切り文字・
/// `:`・NUL を含む名前や、末尾が `.` / 空白の名前〔Win32 からは同じ名前で開けない〕は
/// `InvalidInput`）。`mode` の対応: `CreateNew` は `FILE_CREATE`（既存なら
/// `AlreadyExists`）、`CreateOrOpen` は `FILE_OPEN_IF`、`Existing` は `FILE_OPEN`、
/// `CreateOrAppend` は `FILE_OPEN_IF` かつ `FILE_WRITE_DATA` を外した追記専用アクセス
/// （std の `append(true)` と同じ）。既存の中身を変える作成方法（`FILE_OVERWRITE_IF` 等）は
/// 使わない（reparse point 自体を開いた場合も、呼び出し側の種別確認の前に変更しない）。どのアクセスも `FlushFileBuffers` に必要な
/// 書き込み系の権限（`FILE_WRITE_DATA` または `FILE_APPEND_DATA`）を含む。
pub(crate) fn open_file_beneath(dir: &File, name: &str, mode: LeafOpen) -> io::Result<File> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['\\', '/', ':', '\0'])
        || name.ends_with(['.', ' '])
    {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    let bytes = wide
        .len()
        .checked_mul(2)
        .and_then(|len| u16::try_from(len).ok())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let (disposition, access) = match mode {
        LeafOpen::CreateNew => (FILE_CREATE, FILE_GENERIC_WRITE),
        LeafOpen::CreateOrOpen => (FILE_OPEN_IF, FILE_GENERIC_WRITE),
        LeafOpen::Existing => (FILE_OPEN, FILE_GENERIC_WRITE),
        LeafOpen::CreateOrAppend => (FILE_OPEN_IF, FILE_GENERIC_WRITE & !FILE_WRITE_DATA),
    };
    let object_name = UnicodeString {
        length: bytes,
        maximum_length: bytes,
        buffer: wide.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: u32::try_from(core::mem::size_of::<ObjectAttributes>())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?,
        root_directory: dir.as_raw_handle().cast(),
        object_name: &raw const object_name,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: core::ptr::null(),
        security_quality_of_service: core::ptr::null(),
    };
    let mut io_status = IoStatusBlock {
        status_or_pointer: core::ptr::null_mut(),
        information: 0,
    };
    let mut handle: *mut c_void = core::ptr::null_mut();
    // SAFETY: `handle`・`io_status` は書き込み可能なローカル変数で、API はそれ以外の
    // 呼び出し側メモリへ書かない。`attributes` は正しい `Length` を持ち、指す
    // `object_name`・`wide`（UTF-16 のバイト長を `Length` に持つ。NUL 終端は不要）は
    // 呼び出しの間生きている。`RootDirectory` は `dir` が借用中の有効なディレクトリ
    // ハンドルで、呼び出しの間閉じられない。`AllocationSize`・`EaBuffer` は NULL
    // （`EaLength` 0）で読まれない。
    let status = unsafe {
        NtCreateFile(
            &raw mut handle,
            access | FILE_READ_ATTRIBUTES,
            &raw const attributes,
            &raw mut io_status,
            core::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_ALL,
            disposition,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            core::ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: 引数は値渡しの NTSTATUS のみで、メモリに触れない。
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(
            // ERROR_MR_MID_NOT_FOUND（対応する Win32 エラーがない）。
            317,
        )));
    }
    if handle.is_null() {
        return Err(io::Error::from(io::ErrorKind::Other));
    }
    // SAFETY: 成功した `NtCreateFile` が返した新規ハンドル（非 NULL）で、他に所有者が
    // いない。ここで `File` へ渡し、以降は drop で閉じる。
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

/// `FlushFileBuffers` を明示的に発行し、ハンドルが指すファイル（またはディレクトリ）の
/// バッファをデバイスまで書き出す（IO-2・IO-3・TASK-15.3・#88）。
///
/// ハンドルには書き込み系のアクセス（`FILE_WRITE_DATA` または `FILE_APPEND_DATA`）が
/// 必要で、読み取り専用のハンドルは失敗する（成功を偽装しない。呼び出し側は FlushAck を
/// 返さない）。失敗は `GetLastError` の値をそのまま返す。
pub(crate) fn flush_file_buffers(file: &File) -> io::Result<()> {
    // SAFETY: `file` は呼び出しの間借用され続けるためハンドルは有効で閉じられない。
    // `FlushFileBuffers` はハンドル以外の引数を取らず、呼び出し側のメモリへ書かない。
    let ok = unsafe { FlushFileBuffers(file.as_raw_handle().cast()) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::windows::fs::OpenOptionsExt;

    struct TmpDir(std::path::PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcio-win-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&p).expect("temp dir");
            Self(p)
        }
        fn open(&self) -> File {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(0x0200_0000)
                .open(&self.0)
                .expect("open dir")
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// IO-2・IO-3・TASK-15.3: `open_file_beneath` は mode ごとに作成・切り詰め・追記・
    /// 既存のみを使い分け、ディレクトリハンドル直下にだけ作る。
    #[test]
    fn io2_open_file_beneath_modes() {
        let t = TmpDir::new("modes");
        let dir = t.open();
        let mut f = open_file_beneath(&dir, "a", LeafOpen::CreateNew).expect("create");
        f.write_all(b"abc").expect("write");
        drop(f);
        assert_eq!(std::fs::read(t.0.join("a")).expect("a"), b"abc");
        assert_eq!(
            open_file_beneath(&dir, "a", LeafOpen::CreateNew)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::AlreadyExists)
        );
        let mut f = open_file_beneath(&dir, "a", LeafOpen::CreateOrAppend).expect("append");
        f.write_all(b"de").expect("write");
        flush_file_buffers(&f).expect("append-only handle must be flushable");
        drop(f);
        assert_eq!(std::fs::read(t.0.join("a")).expect("a"), b"abcde");
        let f = open_file_beneath(&dir, "a", LeafOpen::CreateOrOpen).expect("open");
        flush_file_buffers(&f).expect("write handle must be flushable");
        f.set_len(0).expect("write handle must be truncatable");
        drop(f);
        assert_eq!(std::fs::read(t.0.join("a")).expect("a"), b"");
        drop(open_file_beneath(&dir, "b", LeafOpen::CreateOrOpen).expect("create b"));
        assert_eq!(std::fs::read(t.0.join("b")).expect("b"), b"");
        assert!(open_file_beneath(&dir, "a", LeafOpen::Existing).is_ok());
        assert_eq!(
            open_file_beneath(&dir, "missing", LeafOpen::Existing)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::NotFound)
        );
        assert!(!t.0.join("missing").exists());
    }

    /// IO-2・TASK-15.3: 区切り文字・`..`・ADS（`:`）・末尾の `.` / 空白を含む名前は、
    /// ディレクトリハンドルの外や別名を開かないよう `InvalidInput` で拒否し、何も作らない。
    #[test]
    fn io2_open_file_beneath_rejects_non_single_names() {
        let t = TmpDir::new("names");
        let dir = t.open();
        for name in [
            "", ".", "..", "a\\b", "a/b", "..\\x", "a:s", "a.", "a ", "a\0",
        ] {
            assert_eq!(
                open_file_beneath(&dir, name, LeafOpen::CreateOrOpen)
                    .err()
                    .map(|e| e.kind()),
                Some(io::ErrorKind::InvalidInput),
                "{name:?}"
            );
        }
        assert_eq!(std::fs::read_dir(&t.0).expect("list").count(), 0);
    }

    /// IO-2・TASK-15.3: `flush_file_buffers` は書き込み可能なディレクトリハンドルでは
    /// 成功し、読み取り専用のハンドルでは失敗する（成功を偽装しない）。
    #[test]
    fn io2_flush_file_buffers_requires_write_access() {
        let t = TmpDir::new("flush");
        let writable = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(0x0200_0000)
            .open(&t.0)
            .expect("open dir for write");
        flush_file_buffers(&writable).expect("writable directory handle must be flushable");
        std::fs::write(t.0.join("f"), b"x").expect("f");
        let read_only = File::open(t.0.join("f")).expect("open read-only");
        assert!(flush_file_buffers(&read_only).is_err());
        assert!(flush_file_buffers(&t.open()).is_err());
    }

    /// IO-2・TASK-15.3: ディレクトリは開かない（`FILE_NON_DIRECTORY_FILE`）。
    #[test]
    fn io2_open_file_beneath_rejects_directory() {
        let t = TmpDir::new("dir");
        std::fs::create_dir(t.0.join("sub")).expect("sub");
        let dir = t.open();
        assert!(open_file_beneath(&dir, "sub", LeafOpen::Existing).is_err());
    }
}
