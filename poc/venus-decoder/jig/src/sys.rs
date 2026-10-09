#![cfg(target_os = "linux")]
//! vhost-user のトランスポートが使う syscall の薄いラッパー（GPU-6・MVM-4・TASK-172 F1.2・#1517）。
//!
//! 役割: `SCM_RIGHTS` による fd の送受信（`recvmsg(2)` / `sendmsg(2)`）・`memfd_create(2)`・`mmap(2)` / `munmap(2)` と、
//! マッピング領域へのコピー入出力を、安全な `pub(crate)` 関数と型だけで包む。呼び出し元は
//! `vhost_user::fd_passing` と `vhost_user::guest_memory` で、`unsafe` はこのモジュールの外へ出さない。
//!
//! # unsafe の承認範囲（U1〜U8）
//! 個別承認の記録: <https://github.com/Fandhe-AI/fandhe-container/issues/1517#issuecomment-6074351741>。
//! 承認範囲は U1 `syscall(2)` の `extern` 宣言・U2 `recvmsg`・U3 受信 fd の `OwnedFd::from_raw_fd`・U4 `sendmsg`・
//! U5 `memfd_create` と `from_raw_fd`・U6 `mmap`・U7 `Drop` での `munmap`・U8 境界検査後の `copy_nonoverlapping`。
//! これを超える `unsafe`（`extern` 宣言の追加を含む）は書かない。`recvmsg` 等を直接 `extern` で宣言せず、すべて
//! `syscall(2)` 経由にする。
//!
//! # 契約（`crates/core/src/sys.rs` と同じ流儀）
//! - `unsafe fn` を公開しない。各 `unsafe` に `// SAFETY:` で理由と不変条件を書く
//! - 定数は `cfg(target_arch)` ごとに個別に定義し、値が同じでも他アーキの定義を流用しない。対応外アーキは
//!   `SysError::Unsupported` を返す（fail-closed）。aarch64 の定義はこの CI では型検査されない（治具はルート workspace 外）
//! - 構造体はカーネル ABI（`struct user_msghdr`・`struct cmsghdr`・`struct iovec`）に合わせる。syscall を直接呼ぶので
//!   glibc / musl の `msghdr` のパディング差に依存しない
//! - 戻り値が -1 のときは直後に `io::Error::last_os_error()` で errno を確保する
//! - 補助データの解析は呼び出し側の safe コードで行い、ここでは増やさない
//!
//! 出典（確認日 2026-10-09）: Linux UAPI ヘッダ（ローカルの `linux-libc-dev`）の `asm-generic/socket.h`
//! （SHA-256 `e833d32d3d8d03732021da6968665431d693ab4effdd4d39965ff05115a4ed21`）・`linux/socket.h`
//! （`f4331fd201269894f63242a2521b3d5b3290ca556969011d7858908d5fe658c4`）・`asm-generic/mman-common.h`・`linux/memfd.h`、
//! syscall 番号は x86_64 の `asm/unistd_64.h` と asm-generic の `unistd.h`、man `recvmsg(2)`・`unix(7)`・`cmsg(3)`・`mmap(2)`・
//! `memfd_create(2)`。値だけを転記し、コードは流用していない。

use std::ffi::CStr;
use std::io;
use std::num::NonZeroUsize;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;

/// 1 回の受信・送信で扱う fd 数の上限。補助データバッファの固定長を決める（`MAX_MEM_REGIONS` と同じ 32）。
pub(crate) const MAX_SCM_FDS: usize = 32;

/// syscall ラッパーの失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysError {
    /// 対応外のアーキテクチャ（定数が未定義。fail-closed）。
    Unsupported,
    /// カーネルが返した errno。
    Os(i32),
}

#[cfg(target_arch = "x86_64")]
mod consts {
    pub(crate) const SUPPORTED: bool = true;
    // asm/unistd_64.h（x86_64）。
    pub(crate) const NR_SENDMSG: i64 = 46;
    pub(crate) const NR_RECVMSG: i64 = 47;
    pub(crate) const NR_MMAP: i64 = 9;
    pub(crate) const NR_MUNMAP: i64 = 11;
    pub(crate) const NR_MEMFD_CREATE: i64 = 319;
    // asm-generic/socket.h・linux/socket.h・bits/socket.h の MSG_*。
    pub(crate) const SOL_SOCKET: i32 = 1;
    pub(crate) const SCM_RIGHTS: i32 = 1;
    pub(crate) const MSG_TRUNC: u32 = 0x20;
    pub(crate) const MSG_CTRUNC: u32 = 0x8;
    pub(crate) const MSG_NOSIGNAL: u32 = 0x4000;
    pub(crate) const MSG_CMSG_CLOEXEC: u32 = 0x4000_0000;
    // asm-generic/mman-common.h・mman.h。
    pub(crate) const PROT_READ: usize = 0x1;
    pub(crate) const PROT_WRITE: usize = 0x2;
    pub(crate) const MAP_SHARED: usize = 0x1;
    // linux/memfd.h。
    pub(crate) const MFD_CLOEXEC: usize = 0x1;
    // asm-generic/errno-base.h。
    pub(crate) const EINTR: i32 = 4;
    pub(crate) const EAGAIN: i32 = 11;
    pub(crate) const EINVAL: i32 = 22;
}

#[cfg(target_arch = "aarch64")]
mod consts {
    pub(crate) const SUPPORTED: bool = true;
    // asm-generic/unistd.h（aarch64）。mmap は `__NR3264_mmap`（222）。
    pub(crate) const NR_SENDMSG: i64 = 211;
    pub(crate) const NR_RECVMSG: i64 = 212;
    pub(crate) const NR_MMAP: i64 = 222;
    pub(crate) const NR_MUNMAP: i64 = 215;
    pub(crate) const NR_MEMFD_CREATE: i64 = 279;
    pub(crate) const SOL_SOCKET: i32 = 1;
    pub(crate) const SCM_RIGHTS: i32 = 1;
    pub(crate) const MSG_TRUNC: u32 = 0x20;
    pub(crate) const MSG_CTRUNC: u32 = 0x8;
    pub(crate) const MSG_NOSIGNAL: u32 = 0x4000;
    pub(crate) const MSG_CMSG_CLOEXEC: u32 = 0x4000_0000;
    pub(crate) const PROT_READ: usize = 0x1;
    pub(crate) const PROT_WRITE: usize = 0x2;
    pub(crate) const MAP_SHARED: usize = 0x1;
    pub(crate) const MFD_CLOEXEC: usize = 0x1;
    pub(crate) const EINTR: i32 = 4;
    pub(crate) const EAGAIN: i32 = 11;
    pub(crate) const EINVAL: i32 = 22;
}

/// 対応外アーキテクチャ。定数は使われない（全ラッパーが `Unsupported` を返す）。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod consts {
    pub(crate) const SUPPORTED: bool = false;
    pub(crate) const NR_SENDMSG: i64 = 0;
    pub(crate) const NR_RECVMSG: i64 = 0;
    pub(crate) const NR_MMAP: i64 = 0;
    pub(crate) const NR_MUNMAP: i64 = 0;
    pub(crate) const NR_MEMFD_CREATE: i64 = 0;
    pub(crate) const SOL_SOCKET: i32 = 0;
    pub(crate) const SCM_RIGHTS: i32 = 0;
    pub(crate) const MSG_TRUNC: u32 = 0;
    pub(crate) const MSG_CTRUNC: u32 = 0;
    pub(crate) const MSG_NOSIGNAL: u32 = 0;
    pub(crate) const MSG_CMSG_CLOEXEC: u32 = 0;
    pub(crate) const PROT_READ: usize = 0;
    pub(crate) const PROT_WRITE: usize = 0;
    pub(crate) const MAP_SHARED: usize = 0;
    pub(crate) const MFD_CLOEXEC: usize = 0;
    pub(crate) const EINTR: i32 = 0;
    pub(crate) const EAGAIN: i32 = 0;
    pub(crate) const EINVAL: i32 = 0;
}

pub(crate) use consts::{EAGAIN, EINTR, MSG_CTRUNC, MSG_TRUNC, SCM_RIGHTS, SOL_SOCKET};
use consts::{
    EINVAL, MAP_SHARED, MFD_CLOEXEC, MSG_CMSG_CLOEXEC, MSG_NOSIGNAL, NR_MEMFD_CREATE, NR_MMAP,
    NR_MUNMAP, NR_RECVMSG, NR_SENDMSG, PROT_READ, PROT_WRITE, SUPPORTED,
};

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: glibc / musl の `long syscall(long number, ...)` と同じ型幅（U1）。LP64 の
    // Linux（x86_64 / aarch64）だけを対象にし、可変長引数にはすべて `usize` 幅の値を渡す。
    fn syscall(number: i64, ...) -> i64;
}

/// `struct iovec`（`include/uapi/linux/uio.h`）。16 バイト。
#[repr(C)]
struct Iovec {
    base: *mut u8,
    len: usize,
}

/// カーネルの `struct user_msghdr`（`include/linux/socket.h`）。56 バイト。glibc / musl の `msghdr` ではない。
#[repr(C)]
struct UserMsghdr {
    name: *mut u8,
    namelen: i32,
    iov: *mut Iovec,
    iovlen: usize,
    control: *mut u8,
    controllen: usize,
    flags: u32,
}

/// `struct cmsghdr` のヘッダ長（`cmsg_len: size_t`・`cmsg_level: int`・`cmsg_type: int`）。
pub(crate) const CMSG_HDR_LEN: usize = 16;

/// `CMSG_ALIGN`（`size_t` 境界 = 8 バイト）に切り上げる。
pub(crate) const fn cmsg_align(n: usize) -> usize {
    (n + 7) & !7
}

/// `CMSG_SPACE(data_len)`。
pub(crate) const fn cmsg_space(data_len: usize) -> usize {
    CMSG_HDR_LEN + cmsg_align(data_len)
}

/// 補助データバッファの長さ（`MAX_SCM_FDS` 個の fd を載せられる固定長）。
pub(crate) const CMSG_BUF_LEN: usize = cmsg_space(MAX_SCM_FDS * 4);

/// 補助データ用の固定長バッファ。`cmsghdr` の整列（8 バイト）を満たす。
#[repr(C, align(8))]
pub(crate) struct CmsgBuf {
    buf: [u8; CMSG_BUF_LEN],
}

impl CmsgBuf {
    pub(crate) fn new() -> Self {
        Self {
            buf: [0u8; CMSG_BUF_LEN],
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

/// `recvmsg` の生の結果。
#[derive(Debug, Clone, Copy)]
pub(crate) struct RecvRaw {
    /// 受信したデータ長。
    pub(crate) len: usize,
    /// カーネルが書き戻した `msg_flags`（`MSG_CTRUNC` 等）。
    pub(crate) flags: u32,
    /// 補助データの有効長（`CmsgBuf` の先頭からの長さ）。
    pub(crate) ctrl_len: usize,
}

fn check(ret: i64) -> Result<i64, SysError> {
    if ret < 0 {
        // 直後に errno を確保する（間に他の libc 呼び出しを挟まない）。
        Err(SysError::Os(
            io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ))
    } else {
        Ok(ret)
    }
}

/// 補助データ付きで受信する（U2）。`MSG_CMSG_CLOEXEC` を必ず付け、受け取った fd を原子的に close-on-exec にする。
/// 受け取った fd は `ctrl` の中に生の番号で入っているので、呼び出し側は直ちに [`owned_fd_from_received`] で所有する。
///
/// `ctrl_cap` は補助データとして受け付ける最大長で、`CMSG_BUF_LEN` 以下に丸める。通常は `CMSG_BUF_LEN` を渡し、
/// 切り詰め（`MSG_CTRUNC`）の検出試験だけが小さい値を渡す。
pub(crate) fn recvmsg_fds(
    sock: BorrowedFd<'_>,
    data: &mut [u8],
    ctrl: &mut CmsgBuf,
    ctrl_cap: usize,
) -> Result<RecvRaw, SysError> {
    if !SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut iov = Iovec {
        base: data.as_mut_ptr(),
        len: data.len(),
    };
    let mut hdr = UserMsghdr {
        name: std::ptr::null_mut(),
        namelen: 0,
        iov: &raw mut iov,
        iovlen: 1,
        control: ctrl.buf.as_mut_ptr(),
        controllen: ctrl_cap.min(CMSG_BUF_LEN),
        flags: 0,
    };
    // SAFETY: `hdr` はカーネル ABI の `user_msghdr` と同じレイアウト（固定値テストで照合）で、`iov` は `data`
    // （長さ `data.len()` の可変借用）、`control` は `ctrl.buf`（`controllen` は `CMSG_BUF_LEN` 以下）を指す。どちらも呼び出し中は
    // 生きており他から参照されない。fd は `BorrowedFd` で有効性が保証される。カーネルは `data` と `ctrl` の範囲内にだけ
    // 書き、`hdr.controllen` / `hdr.flags` を更新する。
    let ret = unsafe {
        syscall(
            NR_RECVMSG,
            sock.as_raw_fd() as usize,
            &raw mut hdr as usize,
            MSG_CMSG_CLOEXEC as usize,
        )
    };
    let n = check(ret)?;
    Ok(RecvRaw {
        len: usize::try_from(n).map_err(|_| SysError::Os(EINVAL))?,
        flags: hdr.flags,
        // カーネルは controllen を渡した値以下に更新する。念のためバッファ長で頭打ちにする。
        ctrl_len: hdr.controllen.min(CMSG_BUF_LEN),
    })
}

/// 受信した生の fd 番号を所有する（U3）。負の値は `None`。
///
/// 前提: `raw` はカーネルが `SCM_RIGHTS` でこのプロセスに導入したばかりの fd で、他に所有者がいない。
/// 呼び出し側は補助データを解析した直後、検証より前に全 fd をこの関数で `OwnedFd` にする（エラー経路での fd 漏れ防止）。
pub(crate) fn owned_fd_from_received(raw: i32) -> Option<OwnedFd> {
    if raw < 0 {
        return None;
    }
    // SAFETY: `raw` は非負で、直前の `recvmsg` がこのプロセスの fd テーブルに新規に導入した fd。呼び出し側が
    // 同じ番号を二重に所有しない（補助データの各 fd を 1 回だけ渡す）限り、この `OwnedFd` が唯一の所有者になる。
    Some(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// データと fd を `SCM_RIGHTS` で送る（U4）。`MSG_NOSIGNAL` で SIGPIPE を避ける。fd 数は `MAX_SCM_FDS` 以下に限る。
pub(crate) fn sendmsg_fds(
    sock: BorrowedFd<'_>,
    data: &[u8],
    fds: &[BorrowedFd<'_>],
) -> Result<usize, SysError> {
    if !SUPPORTED {
        return Err(SysError::Unsupported);
    }
    if fds.len() > MAX_SCM_FDS {
        return Err(SysError::Os(EINVAL));
    }
    let mut ctrl = CmsgBuf::new();
    let ctrl_len = if fds.is_empty() {
        0
    } else {
        write_scm_rights(&mut ctrl.buf, fds)?;
        cmsg_space(fds.len() * 4)
    };
    let mut iov = Iovec {
        base: data.as_ptr().cast_mut(),
        len: data.len(),
    };
    let hdr = UserMsghdr {
        name: std::ptr::null_mut(),
        namelen: 0,
        iov: &raw mut iov,
        iovlen: 1,
        control: if fds.is_empty() {
            std::ptr::null_mut()
        } else {
            ctrl.buf.as_mut_ptr()
        },
        controllen: ctrl_len,
        flags: 0,
    };
    // SAFETY: `hdr` はカーネル ABI の `user_msghdr` と同じレイアウト。`iov` は `data`（読み取り専用の借用。送信では
    // カーネルは書かない）、`control` は `ctrl.buf` のうち `ctrl_len` バイトを指し、いずれも呼び出し中は生きている。
    // 送る fd は `BorrowedFd` で有効性が保証され、番号は `ctrl` へコピー済み。
    let ret = unsafe {
        syscall(
            NR_SENDMSG,
            sock.as_raw_fd() as usize,
            &raw const hdr as usize,
            MSG_NOSIGNAL as usize,
        )
    };
    let n = check(ret)?;
    usize::try_from(n).map_err(|_| SysError::Os(EINVAL))
}

/// `SCM_RIGHTS` の cmsg（ヘッダ + fd 配列）を `buf` へ書く。safe コードで境界検査する。
fn write_scm_rights(buf: &mut [u8], fds: &[BorrowedFd<'_>]) -> Result<(), SysError> {
    let bad = || SysError::Os(EINVAL);
    let total = CMSG_HDR_LEN + fds.len() * 4;
    buf.get_mut(0..8)
        .ok_or_else(bad)?
        .copy_from_slice(&(total as u64).to_ne_bytes());
    buf.get_mut(8..12)
        .ok_or_else(bad)?
        .copy_from_slice(&SOL_SOCKET.to_ne_bytes());
    buf.get_mut(12..16)
        .ok_or_else(bad)?
        .copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
    for (i, fd) in fds.iter().enumerate() {
        let start = CMSG_HDR_LEN + i * 4;
        buf.get_mut(start..start + 4)
            .ok_or_else(bad)?
            .copy_from_slice(&fd.as_raw_fd().to_ne_bytes());
    }
    Ok(())
}

/// close-on-exec の memfd を作る（U5）。
pub(crate) fn memfd_create_cloexec(name: &CStr) -> Result<OwnedFd, SysError> {
    if !SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `name` は NUL 終端の C 文字列で、呼び出し中は生きている。`memfd_create(name, flags)` は引数の
    // ポインタを読むだけで保持しない。
    let ret = unsafe { syscall(NR_MEMFD_CREATE, name.as_ptr() as usize, MFD_CLOEXEC) };
    let fd = i32::try_from(check(ret)?).map_err(|_| SysError::Os(EINVAL))?;
    // SAFETY: 成功した `memfd_create` が新規に返した fd で、他に所有者がいない。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `mmap` した共有マッピング。`Drop` で `munmap` する。生ポインタを持つので `!Send` / `!Sync`（そのままにする）。
///
/// マッピングへの `&[u8]` / `&mut [u8]` は作らない。frontend / ゲストが同時に書き換える共有メモリへの参照は
/// エイリアシング規則に反するため、境界検査したコピー（[`Self::copy_out`] / [`Self::copy_in`]）だけで出し入れする。
#[derive(Debug)]
pub(crate) struct MmapRegion {
    ptr: NonNull<u8>,
    len: usize,
}

impl MmapRegion {
    /// `fd` の先頭 `len` バイトを `PROT_READ | PROT_WRITE`・`MAP_SHARED` で map する（U6）。
    ///
    /// `len` が fd の実長以下かは呼び出し側が検証する（超えた範囲へのアクセスは SIGBUS になる）。
    pub(crate) fn map_shared(fd: BorrowedFd<'_>, len: NonZeroUsize) -> Result<Self, SysError> {
        if !SUPPORTED {
            return Err(SysError::Unsupported);
        }
        // SAFETY: addr = NULL（カーネルが配置を決める）・offset = 0 の新規マッピングで、既存のメモリを上書きしない
        // （`MAP_FIXED` なし）。`fd` は `BorrowedFd` で有効。`len` は非 0。失敗は -1 で返る。
        let ret = unsafe {
            syscall(
                NR_MMAP,
                0usize,
                len.get(),
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                fd.as_raw_fd() as usize,
                0usize,
            )
        };
        let addr = usize::try_from(check(ret)?).map_err(|_| SysError::Os(EINVAL))?;
        let ptr = NonNull::new(std::ptr::with_exposed_provenance_mut::<u8>(addr))
            .ok_or(SysError::Os(EINVAL))?;
        Ok(Self {
            ptr,
            len: len.get(),
        })
    }

    /// map した長さ。
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// `off` から `dst.len()` バイトを `dst` へコピーする（U8）。範囲外は `Err`。
    pub(crate) fn copy_out(&self, off: usize, dst: &mut [u8]) -> Result<(), SysError> {
        let end = off.checked_add(dst.len()).ok_or(SysError::Os(EINVAL))?;
        if end > self.len {
            return Err(SysError::Os(EINVAL));
        }
        // SAFETY: 上で `off + dst.len() <= self.len` を検査済みで、読み取り元 `ptr + off` は生きているマッピングの
        // 範囲内。`dst` は排他的な Rust の借用でマッピングと重ならない（マッピングへの参照は作らない）。他プロセスが
        // 同時に書き換え得るが、バイト列のコピーに限り値が不定になるだけでメモリ安全性は損なわない。
        unsafe {
            std::ptr::copy_nonoverlapping(self.ptr.as_ptr().add(off), dst.as_mut_ptr(), dst.len())
        };
        Ok(())
    }

    /// `src` を `off` へコピーする（U8）。範囲外は `Err`。
    pub(crate) fn copy_in(&self, off: usize, src: &[u8]) -> Result<(), SysError> {
        let end = off.checked_add(src.len()).ok_or(SysError::Os(EINVAL))?;
        if end > self.len {
            return Err(SysError::Os(EINVAL));
        }
        // SAFETY: 上で `off + src.len() <= self.len` を検査済みで、書き込み先 `ptr + off` は `PROT_WRITE` で map した
        // 生きているマッピングの範囲内。`src` は Rust の借用でマッピングと重ならない。
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr.as_ptr().add(off), src.len())
        };
        Ok(())
    }
}

impl Drop for MmapRegion {
    fn drop(&mut self) {
        // SAFETY: `ptr` / `len` は `map_shared` が成功した `mmap` の戻り値と長さそのもので、まだ unmap されていない
        // （`Drop` は 1 回だけ）。以降このマッピングへの参照は残らない（コピー API しか公開していない）。
        // 失敗しても Drop では回復できず panic も避けたいので結果は無視する（引数が不正になる経路は無い）。
        let _ = unsafe { syscall(NR_MUNMAP, self.ptr.as_ptr() as usize, self.len) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    /// GPU-6: カーネル ABI の構造体レイアウト（LP64）。
    #[test]
    fn gpu6_struct_layout_matches_kernel_abi() {
        assert_eq!(size_of::<Iovec>(), 16);
        assert_eq!(size_of::<UserMsghdr>(), 56);
        assert_eq!(offset_of!(UserMsghdr, namelen), 8);
        assert_eq!(offset_of!(UserMsghdr, iov), 16);
        assert_eq!(offset_of!(UserMsghdr, iovlen), 24);
        assert_eq!(offset_of!(UserMsghdr, control), 32);
        assert_eq!(offset_of!(UserMsghdr, controllen), 40);
        assert_eq!(offset_of!(UserMsghdr, flags), 48);
        assert_eq!(CMSG_HDR_LEN, 16);
    }

    /// GPU-6: `CMSG_SPACE` と補助データバッファの長さ。
    #[test]
    fn gpu6_cmsg_space_values() {
        assert_eq!(cmsg_space(4), 24);
        assert_eq!(cmsg_space(8), 24);
        assert_eq!(cmsg_space(12), 32);
        assert_eq!(CMSG_BUF_LEN, 144);
        assert_eq!(align_of::<CmsgBuf>(), 8);
    }

    /// GPU-6: 実行中アーキの定数の固定値（一次情報との照合結果）。
    #[test]
    fn gpu6_constants_fixed_values() {
        const { assert!(SUPPORTED) };
        assert_eq!(SOL_SOCKET, 1);
        assert_eq!(SCM_RIGHTS, 1);
        assert_eq!(MSG_CTRUNC, 0x8);
        assert_eq!(MSG_TRUNC, 0x20);
        assert_eq!(MSG_NOSIGNAL, 0x4000);
        assert_eq!(MSG_CMSG_CLOEXEC, 0x4000_0000);
        assert_eq!(
            (PROT_READ, PROT_WRITE, MAP_SHARED, MFD_CLOEXEC),
            (1, 2, 1, 1)
        );
        assert_eq!((EINTR, EAGAIN, EINVAL), (4, 11, 22));
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            (NR_SENDMSG, NR_RECVMSG, NR_MMAP, NR_MUNMAP, NR_MEMFD_CREATE),
            (46, 47, 9, 11, 319)
        );
        #[cfg(target_arch = "aarch64")]
        assert_eq!(
            (NR_SENDMSG, NR_RECVMSG, NR_MMAP, NR_MUNMAP, NR_MEMFD_CREATE),
            (211, 212, 222, 215, 279)
        );
    }
}
