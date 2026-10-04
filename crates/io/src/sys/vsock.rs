//! Linux `AF_VSOCK` の syscall 薄いラッパー（`crates/io` の `sys` モジュール配下。`unsafe`
//! 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::vsock`（IO-1 の vsock トランスポート。#1119）が、listen / accept / connect と
//! 接続元・自ソケットのアドレス取得のために呼ぶ。read / write / shutdown / タイムアウト設定は
//! 取得した fd を std の `TcpStream`（`From<OwnedFd>`）に包んで行うため、ここには含めない
//! （`crate::stream_io::TimedStream` 参照）。ここが担うのは std が持たない `AF_VSOCK` 固有の
//! 部分（アドレス構造体・socket / bind / accept4 / connect）だけである。
//!
//! # 契約（事前承認の条件を満たす設計）
//! - `unsafe fn` はこのモジュールの外へ公開しない。公開するのは安全な関数のみ
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` を付ける
//! - 戻り値が `-1` の場合は、直後（他の処理を挟まずに）`io::Error::last_os_error()` で errno を確保する
//! - fd は `socket(2)` / `accept4(2)` の成功直後の新規 fd だけを `OwnedFd::from_raw_fd` に渡す
//!   （所有者は `OwnedFd` ただ 1 つ）。作成時に `SOCK_CLOEXEC` を付け、exec 先へ漏らさない
//! - カーネルが返す `sockaddr_vm` は、長さ（`addrlen`）と `svm_family` を検証してから読む
//! - 定数・構造体レイアウトは `cfg(target_arch = ...)` ごとに個別定義し、他アーキの定義を流用しない。
//!   対応外アーキテクチャでは各ラッパーが [`IoErrorCode::Unimplemented`] を返す（fail-closed）
//! - 待機はすべて期限（`Instant`）つきの `poll(2)`。無期限にブロックしない（REPAIR-5）
//!
//! # 定数の出典（一次確認済み）
//! `include/uapi/linux/vm_sockets.h`（`struct sockaddr_vm`・`VMADDR_*`）、
//! `bits/socket.h` の `PF_VSOCK = 40`、`bits/socket_type.h` の `SOCK_STREAM = 1`・
//! `SOCK_NONBLOCK = 0o4000`・`SOCK_CLOEXEC = 0o2000000`、`asm-generic/socket.h` の
//! `SOL_SOCKET = 1`・`SO_ERROR = 4`、`poll.h` の `POLLIN = 1`・`POLLOUT = 4`。
//! x86_64 / aarch64 とも同値だが、方針どおりアーキごとに個別定義する。
//!
//! # 信頼の限界
//! vsock には `SO_PEERCRED` 相当がない。ここが返す接続元アドレス（CID・ポート）の信頼性の
//! 根拠と限界は `crate::vsock` のモジュール doc「接続元の検証」節を参照。

#![cfg(target_os = "linux")]

use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::time::{Duration, Instant};

use crate::error::{IoError, IoErrorCode};

/// vsock のアドレス（CID とポート）。カーネルの `sockaddr_vm` から読み取った値の写し。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RawAddr {
    pub(crate) cid: u32,
    pub(crate) port: u32,
}

/// [`accept_step`] の 1 回分の結果。
pub(crate) enum AcceptStep {
    /// 接続を受け付けた（fd は blocking・`SOCK_CLOEXEC`）。アドレスはカーネルが返した接続元。
    Connected(OwnedFd, RawAddr),
    /// 相手が accept 完了前に切断した（`ECONNABORTED`）。呼び出し元が有界に再試行する。
    Aborted,
    /// 待機後に接続が取り消された・他者が先に取った（`EAGAIN` / `EINTR`）。再試行件数には
    /// 数えず、呼び出し元が期限内で待ち直す。
    Spurious,
    /// 期限までに接続が来なかった。
    TimedOut,
}

#[cfg(target_arch = "x86_64")]
mod consts {
    pub(super) const SUPPORTED: bool = true;
    pub(super) const AF_VSOCK: i32 = 40;
    pub(super) const SOCK_STREAM: i32 = 1;
    pub(super) const SOCK_NONBLOCK: i32 = 0o4000;
    pub(super) const SOCK_CLOEXEC: i32 = 0o2_000_000;
    pub(super) const SOL_SOCKET: i32 = 1;
    pub(super) const SO_ERROR: i32 = 4;
    pub(super) const POLLIN: i16 = 0x0001;
    pub(super) const POLLOUT: i16 = 0x0004;
}

#[cfg(target_arch = "aarch64")]
mod consts {
    pub(super) const SUPPORTED: bool = true;
    pub(super) const AF_VSOCK: i32 = 40;
    pub(super) const SOCK_STREAM: i32 = 1;
    pub(super) const SOCK_NONBLOCK: i32 = 0o4000;
    pub(super) const SOCK_CLOEXEC: i32 = 0o2_000_000;
    pub(super) const SOL_SOCKET: i32 = 1;
    pub(super) const SO_ERROR: i32 = 4;
    pub(super) const POLLIN: i16 = 0x0001;
    pub(super) const POLLOUT: i16 = 0x0004;
}

/// 対応外アーキテクチャ。値は使われない（先頭の `SUPPORTED` 判定で `Unimplemented` を返す）。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod consts {
    pub(super) const SUPPORTED: bool = false;
    pub(super) const AF_VSOCK: i32 = 0;
    pub(super) const SOCK_STREAM: i32 = 0;
    pub(super) const SOCK_NONBLOCK: i32 = 0;
    pub(super) const SOCK_CLOEXEC: i32 = 0;
    pub(super) const SOL_SOCKET: i32 = 0;
    pub(super) const SO_ERROR: i32 = 0;
    pub(super) const POLLIN: i16 = 0;
    pub(super) const POLLOUT: i16 = 0;
}

/// `struct sockaddr_vm`（`linux/vm_sockets.h`）と同じレイアウト。
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_flags: u8,
    svm_zero: [u8; 3],
}

// カーネルの `struct sockaddr` と同じ 16 バイト（`sockaddr_vm` はこれと同サイズに揃える規約）。
const _: () = assert!(core::mem::size_of::<SockaddrVm>() == 16);
/// `socklen_t` に渡す `sockaddr_vm` の長さ（上の const assert により 16 で `u32` に収まる）。
const SOCKADDR_VM_LEN: u32 = core::mem::size_of::<SockaddrVm>() as u32;

/// `struct pollfd`。
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: 以下は glibc / musl の同名関数と同じ引数の型・幅
    // （`socklen_t` は `u32`、`nfds_t` は `unsigned long`）で宣言している。呼び出し側の
    // 不変条件は各呼び出し箇所の SAFETY コメントを参照。
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn bind(fd: i32, addr: *const SockaddrVm, addrlen: u32) -> i32;
    fn listen(fd: i32, backlog: i32) -> i32;
    fn accept4(fd: i32, addr: *mut SockaddrVm, addrlen: *mut u32, flags: i32) -> i32;
    fn connect(fd: i32, addr: *const SockaddrVm, addrlen: u32) -> i32;
    fn getsockname(fd: i32, addr: *mut SockaddrVm, addrlen: *mut u32) -> i32;
    fn getpeername(fd: i32, addr: *mut SockaddrVm, addrlen: *mut u32) -> i32;
    fn poll(fds: *mut PollFd, nfds: core::ffi::c_ulong, timeout: i32) -> i32;
}

// Linux の errno（asm-generic/errno-base.h・errno.h。x86_64 / aarch64 共通の汎用表）。
const EINTR: i32 = 4;
const EAGAIN: i32 = 11;
const EINPROGRESS: i32 = 115;
const ECONNABORTED: i32 = 103;

fn unimplemented_arch() -> IoError {
    IoError::new(
        IoErrorCode::Unimplemented,
        "vsock is not supported on this CPU architecture",
    )
}

/// `errno` を `IoError` へ変換する。`op` は失敗した操作名（相手由来の文字列は含めない）。
fn map_errno(op: &str, e: &io::Error) -> IoError {
    match e.raw_os_error() {
        // 97 EAFNOSUPPORT / 19 ENODEV / 93 EPROTONOSUPPORT: カーネルが vsock を持たない・
        // トランスポートドライバ未ロード。環境の状態であり実装バグではない。
        Some(97 | 19 | 93) => IoError::new(
            IoErrorCode::Unavailable,
            format!("vsock is not available on this host ({op}): {e}"),
        ),
        // 98 EADDRINUSE
        Some(98) => IoError::new(
            IoErrorCode::AlreadyExists,
            format!("vsock address is already in use ({op}): {e}"),
        ),
        // 99 EADDRNOTAVAIL / 13 EACCES / 1 EPERM / 22 EINVAL: 呼び出し側が渡したアドレスの問題
        // （自 CID でない・特権ポート〔1023 以下は CAP_NET_BIND_SERVICE が要る〕等）。
        Some(99 | 13 | 1 | 22) => IoError::new(
            IoErrorCode::InvalidArgument,
            format!("vsock address was rejected ({op}): {e}"),
        ),
        // 111 ECONNREFUSED / 104 ECONNRESET / 110 ETIMEDOUT / 101 ENETUNREACH / 107 ENOTCONN:
        // 相手側の事情。
        Some(111 | 104 | 110 | 101 | 107) => IoError::new(
            IoErrorCode::Unavailable,
            format!("vsock peer is unavailable ({op}): {e}"),
        ),
        // 24 EMFILE / 23 ENFILE / 12 ENOMEM / 105 ENOBUFS
        Some(24 | 23 | 12 | 105) => IoError::new(
            IoErrorCode::ResourceExhausted,
            format!("vsock resources are exhausted ({op}): {e}"),
        ),
        _ => IoError::new(IoErrorCode::Internal, format!("vsock {op} failed: {e}")),
    }
}

/// `poll(2)` のタイムアウト引数（ミリ秒）へ変換する。切り上げ（短い残りを 0 にして busy
/// loop にならないようにする）、`i32::MAX` を上限とする。
fn poll_timeout_ms(remaining: Duration) -> i32 {
    let ms = remaining.as_nanos().div_ceil(1_000_000);
    i32::try_from(ms).unwrap_or(i32::MAX)
}

/// `fd` が `events` になるまで `deadline` を上限に待つ。`true` は `events`（または
/// エラー・切断の `revents`）が立った、`false` は期限切れ。`EINTR` は残り時間を
/// 計算し直して再試行する。
fn poll_until(fd: BorrowedFd<'_>, events: i16, deadline: Instant) -> Result<bool, IoError> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut pfd = PollFd {
            fd: fd.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: `pfd` はこのスタックフレーム上の有効な `struct pollfd` 1 個で、`nfds` は 1。
        // `fd` は `BorrowedFd` として借用中のため、呼び出しの間クローズされない。
        let rc = unsafe { poll(&raw mut pfd, 1, poll_timeout_ms(remaining)) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(EINTR) {
                if Instant::now() >= deadline {
                    return Ok(false);
                }
                continue;
            }
            return Err(map_errno("poll", &err));
        }
        return Ok(rc > 0 && pfd.revents != 0);
    }
}

fn new_addr(addr: RawAddr) -> SockaddrVm {
    SockaddrVm {
        // AF_VSOCK（40）は u16 に収まる。
        svm_family: u16::try_from(consts::AF_VSOCK).unwrap_or(0),
        svm_reserved1: 0,
        svm_port: addr.port,
        svm_cid: addr.cid,
        svm_flags: 0,
        svm_zero: [0; 3],
    }
}

/// `socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC | extra_flags)` を開く。
fn open_socket(extra_flags: i32) -> Result<OwnedFd, IoError> {
    if !consts::SUPPORTED {
        return Err(unimplemented_arch());
    }
    // SAFETY: 整数引数のみの syscall で、ポインタを渡さない。
    let fd = unsafe {
        socket(
            consts::AF_VSOCK,
            consts::SOCK_STREAM | consts::SOCK_CLOEXEC | extra_flags,
            0,
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return Err(map_errno("socket", &err));
    }
    // SAFETY: `fd` は `socket(2)` が成功直後に返した、他に所有者のいない新規 fd。
    // ここで `OwnedFd` に所有を移し、以後の close は `OwnedFd` の Drop だけが行う。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `addr` に bind して listen する nonblocking の listener fd を返す。
///
/// listener を nonblocking にするのは、[`accept_step`] が `poll(2)` で期限つきに待ってから
/// `accept4` するため（待機後に接続が取り消されても `accept4` がブロックしない）。
/// accept された fd は Linux では listener の `O_NONBLOCK` を引き継がない。
pub(crate) fn listen_nonblocking(addr: RawAddr, backlog: i32) -> Result<OwnedFd, IoError> {
    let fd = open_socket(consts::SOCK_NONBLOCK)?;
    let sa = new_addr(addr);
    // SAFETY: `sa` は有効な `sockaddr_vm`（16 バイト）で、長さに `SOCKADDR_VM_LEN` を渡す。
    // `fd` は `OwnedFd` が所有し、呼び出しの間有効。
    let rc = unsafe { bind(fd.as_raw_fd(), &raw const sa, SOCKADDR_VM_LEN) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(map_errno("bind", &err));
    }
    // SAFETY: 整数引数のみの syscall。`fd` は有効。
    let rc = unsafe { listen(fd.as_raw_fd(), backlog) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(map_errno("listen", &err));
    }
    Ok(fd)
}

/// カーネルが返した `sockaddr_vm` を、長さと `svm_family` を検証してから読む。
fn read_addr(sa: &SockaddrVm, len: u32) -> Result<RawAddr, IoError> {
    if len < SOCKADDR_VM_LEN || i32::from(sa.svm_family) != consts::AF_VSOCK {
        return Err(IoError::new(
            IoErrorCode::Internal,
            "kernel returned a malformed vsock socket address",
        ));
    }
    Ok(RawAddr {
        cid: sa.svm_cid,
        port: sa.svm_port,
    })
}

fn empty_addr() -> SockaddrVm {
    SockaddrVm {
        svm_family: 0,
        svm_reserved1: 0,
        svm_port: 0,
        svm_cid: 0,
        svm_flags: 0,
        svm_zero: [0; 3],
    }
}

/// 自ソケットのアドレス（`VMADDR_PORT_ANY` で bind した場合の実ポート取得に使う）。
pub(crate) fn local_addr(fd: BorrowedFd<'_>) -> Result<RawAddr, IoError> {
    let mut sa = empty_addr();
    let mut len = SOCKADDR_VM_LEN;
    // SAFETY: `sa` は書き込み可能な `sockaddr_vm`、`len` はその長さで初期化済み。カーネルは
    // `len` を超えて書かず、実際の長さを `len` に返す。`fd` は借用中で有効。
    let rc = unsafe { getsockname(fd.as_raw_fd(), &raw mut sa, &raw mut len) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(map_errno("getsockname", &err));
    }
    read_addr(&sa, len)
}

/// 接続相手のアドレス（クライアント側の接続後 CID 照合に使う）。
pub(crate) fn peer_addr(fd: BorrowedFd<'_>) -> Result<RawAddr, IoError> {
    let mut sa = empty_addr();
    let mut len = SOCKADDR_VM_LEN;
    // SAFETY: [`local_addr`] と同じ。
    let rc = unsafe { getpeername(fd.as_raw_fd(), &raw mut sa, &raw mut len) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(map_errno("getpeername", &err));
    }
    read_addr(&sa, len)
}

/// 接続を 1 件、`deadline` を上限に待って受け付ける（1 回分。再試行・拒否判定は呼び出し元）。
pub(crate) fn accept_step(
    listener: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<AcceptStep, IoError> {
    if !consts::SUPPORTED {
        return Err(unimplemented_arch());
    }
    if !poll_until(listener, consts::POLLIN, deadline)? {
        return Ok(AcceptStep::TimedOut);
    }
    let mut sa = empty_addr();
    let mut len = SOCKADDR_VM_LEN;
    // SAFETY: `sa`・`len` は [`local_addr`] と同じ条件で有効。`listener` は借用中で有効。
    // flags は `SOCK_CLOEXEC` のみ（blocking の接続 fd を得る）。
    let fd = unsafe {
        accept4(
            listener.as_raw_fd(),
            &raw mut sa,
            &raw mut len,
            consts::SOCK_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return match err.raw_os_error() {
            // 他スレッドが先に取った・待機後に取り消された。期限内なら呼び出し元が待ち直す。
            Some(EAGAIN | EINTR) => Ok(AcceptStep::Spurious),
            Some(ECONNABORTED) => Ok(AcceptStep::Aborted),
            _ => Err(map_errno("accept4", &err)),
        };
    }
    // SAFETY: `fd` は `accept4(2)` が成功直後に返した、他に所有者のいない新規 fd。
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let peer = read_addr(&sa, len)?;
    Ok(AcceptStep::Connected(owned, peer))
}

/// `addr` へ期限つきで接続する。戻り値の fd は nonblocking のままで、呼び出し元が
/// `TcpStream::from(fd)` に包んで `set_nonblocking(false)` する。
///
/// nonblocking `connect` → `poll(POLLOUT)` → `getsockopt(SO_ERROR)` で確定する
/// （応答しない CID への `connect` が無期限にブロックしうるため。REPAIR-5）。
/// 期限切れは `Ok(None)`、接続失敗は `Err`（fd は drop で閉じ、接続試行を取り消す）。
pub(crate) fn connect_nonblocking_until(
    addr: RawAddr,
    deadline: Instant,
) -> Result<Option<OwnedFd>, IoError> {
    let fd = open_socket(consts::SOCK_NONBLOCK)?;
    let sa = new_addr(addr);
    // SAFETY: `sa` は有効な `sockaddr_vm`（16 バイト）で長さは `SOCKADDR_VM_LEN`。`fd` は有効。
    let rc = unsafe { connect(fd.as_raw_fd(), &raw const sa, SOCKADDR_VM_LEN) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(EINPROGRESS | EINTR) => {}
            _ => return Err(map_errno("connect", &err)),
        }
        if !poll_until(fd.as_fd(), consts::POLLOUT, deadline)? {
            return Ok(None);
        }
        let mut so_error: i32 = 0;
        let mut len = core::mem::size_of::<i32>() as u32;
        // SAFETY: `so_error` は書き込み可能な `i32`、`len` はその長さ（4）。`fd` は有効。
        let rc = unsafe {
            super::linux::getsockopt(
                fd.as_raw_fd(),
                consts::SOL_SOCKET,
                consts::SO_ERROR,
                (&raw mut so_error).cast::<core::ffi::c_void>(),
                &raw mut len,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            return Err(map_errno("getsockopt", &err));
        }
        if so_error != 0 {
            let err = io::Error::from_raw_os_error(so_error);
            return Err(map_errno("connect", &err));
        }
    }
    Ok(Some(fd))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `sockaddr_vm` は 16 バイトで、フィールドオフセットが `vm_sockets.h` と一致する。
    #[test]
    fn io1_vsock_sockaddr_layout_matches_kernel_header() {
        assert_eq!(core::mem::size_of::<SockaddrVm>(), 16);
        let sa = new_addr(RawAddr { cid: 3, port: 1234 });
        let bytes: [u8; 16] = to_bytes(&sa);
        assert_eq!(&bytes[0..2], &40u16.to_ne_bytes());
        assert_eq!(&bytes[2..4], &[0, 0]);
        assert_eq!(&bytes[4..8], &1234u32.to_ne_bytes());
        assert_eq!(&bytes[8..12], &3u32.to_ne_bytes());
        assert_eq!(&bytes[12..16], &[0, 0, 0, 0]);
    }

    fn to_bytes(sa: &SockaddrVm) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..2].copy_from_slice(&sa.svm_family.to_ne_bytes());
        out[2..4].copy_from_slice(&sa.svm_reserved1.to_ne_bytes());
        out[4..8].copy_from_slice(&sa.svm_port.to_ne_bytes());
        out[8..12].copy_from_slice(&sa.svm_cid.to_ne_bytes());
        out[12] = sa.svm_flags;
        out[13..16].copy_from_slice(&sa.svm_zero);
        out
    }

    /// カーネルが返したアドレスは、長さ不足・family 不一致なら読まずに拒否する（fail-closed）。
    #[test]
    fn io1_vsock_read_addr_rejects_short_length_and_wrong_family() {
        let good = new_addr(RawAddr { cid: 7, port: 9 });
        assert_eq!(
            read_addr(&good, SOCKADDR_VM_LEN).expect("valid address"),
            RawAddr { cid: 7, port: 9 }
        );
        let short = read_addr(&good, SOCKADDR_VM_LEN - 1).expect_err("short length");
        assert_eq!(short.code(), IoErrorCode::Internal);
        let mut wrong = good;
        wrong.svm_family = 1;
        let err = read_addr(&wrong, SOCKADDR_VM_LEN).expect_err("wrong family");
        assert_eq!(err.code(), IoErrorCode::Internal);
    }

    /// errno と `IoErrorCode` の対応（具体値）。
    #[test]
    fn io1_vsock_map_errno_maps_known_errnos() {
        let code = |n: i32| map_errno("x", &io::Error::from_raw_os_error(n)).code();
        assert_eq!(code(97), IoErrorCode::Unavailable); // EAFNOSUPPORT
        assert_eq!(code(98), IoErrorCode::AlreadyExists); // EADDRINUSE
        assert_eq!(code(99), IoErrorCode::InvalidArgument); // EADDRNOTAVAIL
        assert_eq!(code(13), IoErrorCode::InvalidArgument); // EACCES
        assert_eq!(code(111), IoErrorCode::Unavailable); // ECONNREFUSED
        assert_eq!(code(24), IoErrorCode::ResourceExhausted); // EMFILE
        assert_eq!(code(5), IoErrorCode::Internal); // EIO
    }

    /// `poll` のタイムアウトは切り上げ・上限つきの変換になる。
    #[test]
    fn repair5_vsock_poll_timeout_rounds_up_and_saturates() {
        assert_eq!(poll_timeout_ms(Duration::ZERO), 0);
        assert_eq!(poll_timeout_ms(Duration::from_micros(10)), 1);
        assert_eq!(poll_timeout_ms(Duration::from_millis(250)), 250);
        assert_eq!(poll_timeout_ms(Duration::from_secs(u64::MAX / 4)), i32::MAX);
    }
}
