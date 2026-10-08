//! Windows 向け FFI の薄いラッパー（`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・
//! オーナー決定 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! 提供機能は [`file_identity`] だけ。ローテーション sink のロックファイル検査
//! （`logs::rotating`。SUP-7・IO-5・WIN-4・TASK-164 追補・#1470）が、同じパスを 2 回開いたハンドルが同一の
//! 実体を指すこと（unix の dev / inode 照合に相当）を確かめるために使う。std の同等 API
//! （`volume_serial_number` / `file_index`）は unstable のため FFI で持つ。
//!
//! # 不変条件
//! - `unsafe` は本モジュール内に閉じ、公開するのは安全な関数のみ（`unsafe fn` を外へ出さない）。
//! - `windows-sys` 等の依存を増やさず、必要最小限の `extern "system"` 宣言と構造体レイアウトを自前で持つ
//!   （dependency-policy「ユーザー承認制」。`crates/io/src/sys/windows.rs` と同じ方式）。レイアウトは
//!   Windows SDK（`winbase.h` の `FILE_ID_INFO`）の定義に合わせ、ポインタ幅に依存するフィールドを持たない
//!   （x86_64 / aarch64 共通）。
//! - `FileIdInfo` を扱えない FS（FAT 等）では取得に失敗する。呼び出し側は fail-closed で拒否する。

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;

/// `FILE_INFO_BY_HANDLE_CLASS::FileIdInfo`。
const FILE_ID_INFO_CLASS: i32 = 18;

/// `FILE_ID_INFO`（`VolumeSerialNumber` は 64 ビット、`FileId` は 128 ビットの `FILE_ID_128`）。
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawFileIdInfo {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[link(name = "kernel32")]
unsafe extern "system" {
    // SAFETY（宣言）: `BOOL GetFileInformationByHandleEx(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD)`
    // （fileapi.h / winbase.h）。`HANDLE` はポインタ幅、クラスは列挙体（i32）、サイズは u32、`BOOL` は i32（0 で失敗）。
    fn GetFileInformationByHandleEx(
        handle: *mut c_void,
        class: i32,
        info: *mut c_void,
        buffer_size: u32,
    ) -> i32;
}

/// ファイルの同一性（ボリューム・ファイル ID）。同じ値なら同一の実体を指す。中身は不透明で、比較だけを提供する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

/// 開いているハンドルの同一性を返す。`FileIdInfo` を扱えないボリュームではエラー（呼び出し側は拒否する）。
pub(crate) fn file_identity(file: &File) -> io::Result<FileIdentity> {
    let mut raw = RawFileIdInfo::default();
    let size = u32::try_from(std::mem::size_of::<RawFileIdInfo>())
        .map_err(|_| io::Error::other("file id buffer size overflow"))?;
    // SAFETY: `file` は借用中で、ハンドルは呼び出しの間有効（クローズされない）。`raw` は `FILE_ID_INFO` と
    // 同じレイアウト（`repr(C)`・合計 24 バイト・アラインメント 8）の書き込み可能な領域で、`size` はその
    // バイト数と一致する。API は成功時にこの領域だけを書き、失敗時は何も保持しない。
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FILE_ID_INFO_CLASS,
            std::ptr::from_mut(&mut raw).cast::<c_void>(),
            size,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity {
        volume_serial_number: raw.volume_serial_number,
        file_id: raw.file_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("fc-sup7-sys-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// SUP-7・IO-5・WIN-4: 同じファイルを 2 回開いた ID は一致し、別ファイル・コピーは一致しない。
    /// ハードリンクは同一の実体なので一致する。
    #[test]
    fn sup7_task164_followup_file_identity_matches_same_entity_only() {
        let d = tmp("identity");
        let a = d.join("a");
        let b = d.join("b");
        fs::write(&a, b"x").unwrap();
        fs::write(&b, b"x").unwrap();
        let link = d.join("a-link");
        fs::hard_link(&a, &link).unwrap();
        let id_a1 = file_identity(&File::open(&a).unwrap()).unwrap();
        let id_a2 = file_identity(&File::open(&a).unwrap()).unwrap();
        let id_b = file_identity(&File::open(&b).unwrap()).unwrap();
        let id_link = file_identity(&File::open(&link).unwrap()).unwrap();
        assert_eq!(id_a1, id_a2);
        assert_ne!(id_a1, id_b);
        assert_eq!(id_a1, id_link);
        let _ = fs::remove_dir_all(&d);
    }
}
