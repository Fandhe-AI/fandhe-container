//! `NETLINK_ROUTE` ソケットに使う syscall・FFI の薄いラッパー（`crates/net` の `sys` モジュール。
//! `unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・オーナー決定
//! 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::netlink_route::NetlinkRouteSocket`（NET-11・TASK-136.2.1・#843）の `open` / `send` / `recv` が、
//! `socket(2)`・`bind(2)`・`sendto(2)`・`recvfrom(2)`・`poll(2)` を呼ぶために使う。
//! メッセージの組み立て・解釈は `crate::netlink` のコーデックが担い、ここはバイト列を
//! 運ぶだけで中身を解釈しない。
//!
//! # 契約（事前承認の条件を満たす設計）
//! - `unsafe fn` はこのモジュールの外へ公開しない。公開するのは安全な関数のみ
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` で理由と
//!   維持すべき不変条件を明記する
//! - 定数は `cfg(target_arch = ...)` ごとに個別に定義し、値が同じでも他アーキテクチャの定義を
//!   流用しない。対応外アーキテクチャでは各ラッパーが [`SysError::Unsupported`] を返す（fail-closed）
//! - 戻り値が `-1` のときは直後に `std::io::Error::last_os_error()` で errno を確保する
//! - 送信は `MSG_DONTWAIT`、受信は `poll(2)` の期限つきで、無期限に待つ経路を持たない（REPAIR-5）
//!
//! # `libc` / `nix` について
//! `libc` は #86 で採用承認済みだが、自動運転下では「追加時点で新しい版があれば PR で確認する」
//! 運用条件を満たせないため、`crates/core/src/sys.rs` と同じ流儀で `Cargo.toml` を変更せず
//! 必要最小限の `extern "C"` 宣言を自前で持つ（dependency-policy）。
//!
//! # 実装メモ
//! 受信切り詰め検出は `recvfrom(2)` に `MSG_TRUNC` を渡し、戻り値（データグラムの実長）が
//! バッファ長を超えたことで判定する。これにより `msghdr` のレイアウト（glibc / musl 差）に
//! 依存しない（`sendmsg` / `recvmsg` と同じ netlink データグラム意味論）。

#![cfg(target_os = "linux")]

use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::time::{Duration, Instant};

/// syscall 失敗の分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysError {
    /// 対応外のアーキテクチャ（定数が未定義）。
    Unsupported,
    /// カーネルが返した errno（0 は「送信元が netlink アドレスでない」等の内部検証失敗）。
    Os(i32),
}

/// EINTR 再試行の上限回数（シグナル嵐で無限ループにしない）。
const EINTR_RETRY_MAX: u32 = 16;

pub(crate) use consts::{
    EACCES, EAFNOSUPPORT, EAGAIN, EMFILE, ENFILE, ENOBUFS, ENOMEM, EPERM, EPROTONOSUPPORT,
};

// include/linux/socket.h・uapi/linux/netlink.h・uapi/asm-generic/socket.h・poll.h・errno.h の値。
// `SOCK_CLOEXEC` は `O_CLOEXEC` と同値。
#[cfg(target_arch = "x86_64")]
mod consts {
    pub const SUPPORTED: bool = true;
    pub const AF_NETLINK: u16 = 16;
    pub const SOCK_RAW: i32 = 3;
    pub const SOCK_CLOEXEC: i32 = 0o2_000_000;
    pub const NETLINK_ROUTE: i32 = 0;
    pub const MSG_TRUNC: i32 = 0x20;
    pub const MSG_DONTWAIT: i32 = 0x40;
    pub const POLLIN: i16 = 1;
    pub const EPERM: i32 = 1;
    pub const EINTR: i32 = 4;
    pub const ENOMEM: i32 = 12;
    pub const EAGAIN: i32 = 11;
    pub const EACCES: i32 = 13;
    pub const ENFILE: i32 = 23;
    pub const EMFILE: i32 = 24;
    pub const EPROTONOSUPPORT: i32 = 93;
    pub const EAFNOSUPPORT: i32 = 97;
    pub const ENOBUFS: i32 = 105;
}

#[cfg(target_arch = "aarch64")]
mod consts {
    pub const SUPPORTED: bool = true;
    pub const AF_NETLINK: u16 = 16;
    pub const SOCK_RAW: i32 = 3;
    pub const SOCK_CLOEXEC: i32 = 0o2_000_000;
    pub const NETLINK_ROUTE: i32 = 0;
    pub const MSG_TRUNC: i32 = 0x20;
    pub const MSG_DONTWAIT: i32 = 0x40;
    pub const POLLIN: i16 = 1;
    pub const EPERM: i32 = 1;
    pub const EINTR: i32 = 4;
    pub const ENOMEM: i32 = 12;
    pub const EAGAIN: i32 = 11;
    pub const EACCES: i32 = 13;
    pub const ENFILE: i32 = 23;
    pub const EMFILE: i32 = 24;
    pub const EPROTONOSUPPORT: i32 = 93;
    pub const EAFNOSUPPORT: i32 = 97;
    pub const ENOBUFS: i32 = 105;
}

/// 対応外アーキテクチャ: 値を確認していないためラッパーは `Unsupported` を返し、カーネルへ渡さない。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[allow(dead_code)]
mod consts {
    pub const SUPPORTED: bool = false;
    pub const AF_NETLINK: u16 = 0;
    pub const SOCK_RAW: i32 = 0;
    pub const SOCK_CLOEXEC: i32 = 0;
    pub const NETLINK_ROUTE: i32 = 0;
    pub const MSG_TRUNC: i32 = 0;
    pub const MSG_DONTWAIT: i32 = 0;
    pub const POLLIN: i16 = 0;
    pub const EPERM: i32 = -1;
    pub const EINTR: i32 = -1;
    pub const ENOMEM: i32 = -1;
    pub const EAGAIN: i32 = -1;
    pub const EACCES: i32 = -1;
    pub const ENFILE: i32 = -1;
    pub const EMFILE: i32 = -1;
    pub const EPROTONOSUPPORT: i32 = -1;
    pub const EAFNOSUPPORT: i32 = -1;
    pub const ENOBUFS: i32 = -1;
}

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: `int socket(int domain, int type, int protocol)`。
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int bind(int fd, const struct sockaddr *addr, socklen_t addrlen)`
    // （`socklen_t` は u32）。
    fn bind(fd: i32, addr: *const SockaddrNl, addrlen: u32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `ssize_t sendto(int fd, const void *buf, size_t len, int flags,
    // const struct sockaddr *addr, socklen_t addrlen)`（LP64 で `ssize_t` は i64）。
    fn sendto(
        fd: i32,
        buf: *const core::ffi::c_void,
        len: usize,
        flags: i32,
        addr: *const SockaddrNl,
        addrlen: u32,
    ) -> isize;
    // SAFETY（宣言そのものの妥当性）: `ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
    // struct sockaddr *addr, socklen_t *addrlen)`。
    fn recvfrom(
        fd: i32,
        buf: *mut core::ffi::c_void,
        len: usize,
        flags: i32,
        addr: *mut SockaddrNl,
        addrlen: *mut u32,
    ) -> isize;
    // SAFETY（宣言そのものの妥当性）: `int poll(struct pollfd *fds, nfds_t nfds, int timeout)`
    // （`nfds_t` は `unsigned long`＝LP64 で u64）。
    fn poll(fds: *mut PollFd, nfds: u64, timeout: i32) -> i32;
}

/// `struct sockaddr_nl`（include/uapi/linux/netlink.h。全アーキテクチャ共通の 12 バイト）。
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrNl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

/// `struct pollfd`（include/uapi/asm-generic/poll.h。全アーキテクチャ共通の 8 バイト）。
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

const _: () = assert!(core::mem::size_of::<SockaddrNl>() == 12);
const _: () = assert!(core::mem::size_of::<PollFd>() == 8);

/// 受信 1 回分の結果（解釈前のメタ情報）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecvMeta {
    /// データグラムの実長（切り詰め時はバッファ長を超えうる）。
    pub len: usize,
    /// バッファに収まらず切り詰められたか。
    pub truncated: bool,
    /// 送信元の `nl_pid`（カーネルは 0）。
    pub sender_pid: u32,
}

fn kernel_addr() -> SockaddrNl {
    SockaddrNl {
        nl_family: consts::AF_NETLINK,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    }
}

/// 直前の失敗した syscall の errno を `SysError` にする（失敗直後に呼ぶこと）。
fn last_error() -> SysError {
    SysError::Os(io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

/// `NETLINK_ROUTE` の `SOCK_RAW|SOCK_CLOEXEC` ソケットを開く（未 bind）。
///
/// `SOCK_CLOEXEC` により exec 先（コンテナプロセス）へ fd を漏らさない。
pub(crate) fn open_route_socket() -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数はすべて値渡しの整数でポインタを取らない。成功時の戻り値は新規 fd で、直後に
    // `OwnedFd` が唯一の所有者となる（二重 close なし）。
    let fd = unsafe {
        socket(
            i32::from(consts::AF_NETLINK),
            consts::SOCK_RAW | consts::SOCK_CLOEXEC,
            consts::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(last_error());
    }
    // SAFETY: `fd` は上で成功した socket が返した、他に所有者のいない有効な fd。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `nl_pid = 0`（カーネルが採番）・`nl_groups = 0`（マルチキャスト購読なし）で bind する。
pub(crate) fn bind_kernel_assigned(fd: BorrowedFd<'_>) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let addr = kernel_addr();
    // SAFETY: `addr` はスタック上の初期化済み `SockaddrNl` で、`addrlen` はその `size_of`（12）と一致する。
    // `fd` は生存中の `BorrowedFd`。カーネルは呼び出しの間だけ `addr` を読む。
    let rc = unsafe {
        bind(
            fd.as_raw_fd(),
            &raw const addr,
            core::mem::size_of::<SockaddrNl>() as u32,
        )
    };
    if rc < 0 { Err(last_error()) } else { Ok(()) }
}

/// `buf` 全体を 1 データグラムとしてカーネル（`nl_pid = 0`）へ送り、送れたバイト数を返す。
///
/// `MSG_DONTWAIT` で送信キュー詰まりでも待たず `EAGAIN` で失敗する。EINTR は上限回数まで再試行する。
pub(crate) fn send_to_kernel(fd: BorrowedFd<'_>, buf: &[u8]) -> Result<usize, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let addr = kernel_addr();
    let mut attempts = 0;
    loop {
        // SAFETY: `buf` は借用したスライスで、`buf.len()` バイトが呼び出しの間読み出し可能。`addr` は
        // スタック上の初期化済み `SockaddrNl` で、`addrlen` はその `size_of`（12）と一致する。`fd` は
        // 生存中の `BorrowedFd`。カーネルは両バッファを呼び出しの間だけ読む。
        let n = unsafe {
            sendto(
                fd.as_raw_fd(),
                buf.as_ptr().cast(),
                buf.len(),
                consts::MSG_DONTWAIT,
                &raw const addr,
                core::mem::size_of::<SockaddrNl>() as u32,
            )
        };
        match usize::try_from(n) {
            Ok(sent) => return Ok(sent),
            Err(_) => {
                let e = last_error();
                attempts += 1;
                if e == SysError::Os(consts::EINTR) && attempts < EINTR_RETRY_MAX {
                    continue;
                }
                return Err(e);
            }
        }
    }
}

/// `fd` が読み取り可能になるまで最大 `timeout` 待つ。可能なら `true`、時間切れなら `false`。
///
/// EINTR は残り時間を再計算して再試行する（全体で `timeout` を超えて待たない）。
pub(crate) fn wait_readable(fd: BorrowedFd<'_>, timeout: Duration) -> Result<bool, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let deadline = Instant::now().checked_add(timeout);
    let mut remaining = timeout;
    loop {
        // ミリ秒へ切り上げ（端数で 0 ms 待ちにならないため）。i32 に収まらなければ飽和させる。
        let ms = remaining
            .as_millis()
            .saturating_add(u128::from(
                !remaining.subsec_nanos().is_multiple_of(1_000_000),
            ))
            .min(i32::MAX as u128) as i32;
        let mut pfd = PollFd {
            fd: fd.as_raw_fd(),
            events: consts::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` はスタック上の初期化済み 1 要素で、`nfds` = 1 と一致する。カーネルは呼び出しの間だけ
        // `revents` を書く。
        let poll_started = Instant::now();
        let r = unsafe { poll(&raw mut pfd, 1, ms) };
        if r > 0 {
            return Ok(true);
        }
        if r < 0 {
            let e = last_error();
            if e != SysError::Os(consts::EINTR) {
                return Err(e);
            }
        }
        // 時間切れ（r == 0）でも、1 回の poll に渡せる上限（i32::MAX ms）で飽和していた場合は
        // 残り時間を消化するため再試行する。EINTR も同様に残り時間を再計算する。
        if let Some(d) = deadline {
            remaining = d.saturating_duration_since(Instant::now());
        } else {
            // 期限を表せない巨大 timeout では、EINTR で即戻りしても i32::MAX ms を差し引かず、
            // 実際に経過した時間だけを残り時間から引く。
            remaining = remaining.saturating_sub(poll_started.elapsed());
        }
        if remaining.is_zero() {
            return Ok(false);
        }
    }
}

/// 1 データグラムを受信する。`MSG_DONTWAIT` で呼ぶため待たずに返り、読み取り可能でなければ
/// （他スレッドが先に取った場合を含む）`Os(EAGAIN)` で失敗する。通常は [`wait_readable`] の後に呼ぶ。
/// 送信元が netlink アドレスでなければ `Os(0)` で拒否する。
///
/// `MSG_TRUNC` を渡すため、`buf` に収まらない場合も戻り値は実長になり `truncated` が立つ。
pub(crate) fn recv_from(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Result<RecvMeta, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut attempts = 0;
    loop {
        let mut addr = SockaddrNl {
            nl_family: 0,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };
        let mut addrlen = core::mem::size_of::<SockaddrNl>() as u32;
        // SAFETY: `buf` は排他借用したスライスで `buf.len()` バイトが書き込み可能（カーネルは `len` を
        // 超えて書かない。`MSG_TRUNC` でも書き込み量は `len` まで）。`addr`・`addrlen` はスタック上の
        // 初期化済みローカルで、`addrlen` は `addr` の確保サイズ（12）を入力として渡す。
        let n = unsafe {
            recvfrom(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                consts::MSG_TRUNC | consts::MSG_DONTWAIT,
                &raw mut addr,
                &raw mut addrlen,
            )
        };
        let Ok(n) = usize::try_from(n) else {
            let e = last_error();
            attempts += 1;
            if e == SysError::Os(consts::EINTR) && attempts < EINTR_RETRY_MAX {
                continue;
            }
            return Err(e);
        };
        if addrlen < core::mem::size_of::<SockaddrNl>() as u32
            || addr.nl_family != consts::AF_NETLINK
        {
            return Err(SysError::Os(0));
        }
        return Ok(RecvMeta {
            len: n,
            truncated: n > buf.len(),
            sender_pid: addr.nl_pid,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    /// NET-11: arch 別定数の具体値とレイアウト。
    #[test]
    fn constants_and_layout() {
        assert_eq!(consts::AF_NETLINK, 16);
        assert_eq!(consts::SOCK_RAW, 3);
        assert_eq!(consts::SOCK_CLOEXEC, 0x80000);
        assert_eq!(consts::NETLINK_ROUTE, 0);
        assert_eq!(consts::MSG_TRUNC, 0x20);
        assert_eq!(consts::EINTR, 4);
        assert_eq!(core::mem::size_of::<SockaddrNl>(), 12);
        assert_eq!(core::mem::size_of::<PollFd>(), 8);
    }

    /// NET-11・REPAIR-5: 何も届いていない socket の `wait_readable` は期限で false を返す。
    #[test]
    fn wait_readable_times_out() {
        let fd = open_route_socket().expect("open");
        bind_kernel_assigned(fd.as_fd()).expect("bind");
        let t = Instant::now();
        assert_eq!(
            wait_readable(fd.as_fd(), Duration::from_millis(50)),
            Ok(false)
        );
        assert!(t.elapsed() < Duration::from_secs(5));
    }
}
