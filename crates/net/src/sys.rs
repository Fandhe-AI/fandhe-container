//! `NETLINK_ROUTE` / `NETLINK_NETFILTER` ソケットと、netns の作成・pin（`unshare` / bind `mount` / `umount2`。
//! `crate::netns`。TASK-139.2.1・NET-1）に使う syscall・FFI の薄いラッパー（`crates/net` の `sys` モジュール。
//! `unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・オーナー決定
//! 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::netlink_route::NetlinkRouteSocket`（NET-11・TASK-136.2.1・#843。nf_tables のバッチ送信 TASK-137.3・#306
//! では protocol だけ `NETLINK_NETFILTER` に差し替えて再利用する）の `open` / `send` / `recv` が、
//! `socket(2)`・`bind(2)`・`getsockname(2)`・`setsockopt(2)`・`sendto(2)`・`recvfrom(2)`・`poll(2)` を呼ぶために使う。
//! メッセージの組み立て・解釈は `crate::netlink` のコーデックが担い、ここはバイト列を
//! 運ぶだけで中身を解釈しない。
//!
//! `crate::add_host_dns` の hosts ファイル追記（NET-12・TASK-185.2・#345）は、管理ルートから
//! 1 要素ずつ `openat(2)`（`O_NOFOLLOW`）で辿って開くために [`open_dir_nofollow`]・
//! [`open_dir_nofollow_at`]・[`open_append_nofollow_at`] を使う（パス再解決による TOCTOU を避ける）。
//!
//! # 契約（事前承認の条件を満たす設計）
//! - `unsafe fn` はこのモジュールの外へ公開しない。公開するのは安全な関数のみ
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` で理由と
//!   維持すべき不変条件を明記する
//! - 定数は `cfg(target_arch = ...)` ごとに個別に定義し、値が同じでも他アーキテクチャの定義を
//!   流用しない。対応外アーキテクチャでは各ラッパーが [`SysError::Unsupported`] を返す（fail-closed）
//! - 戻り値が `-1` のときは直後に `std::io::Error::last_os_error()` で errno を確保する
//! - 送信・受信とも `MSG_DONTWAIT` で、待つのは期限つきの `poll(2)` だけ。残り時間は [`Deadline`]
//!   （単調時計の開始時刻＋全体 timeout）から毎回計算し直し、無期限に待つ経路を持たない（REPAIR-5）
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
//! 受信前の長さ確認（[`peek_datagram_len`]）も同じ仕組みで、`MSG_PEEK | MSG_TRUNC` と長さ 0 の
//! バッファにより、キューから取り除かずに先頭データグラムの実長だけを得る。

#![cfg(target_os = "linux")]

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::time::{Duration, Instant};

/// syscall 失敗の分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysError {
    /// 対応外のアーキテクチャ（定数が未定義）。
    Unsupported,
    /// カーネルが返した errno。
    Os(i32),
    /// 受信した送信元アドレスが `sockaddr_nl` でない（長さ不足・`nl_family` 不一致）。
    /// カーネル応答の境界検査で検出し、アドレスの中身は読まない。
    BadSenderAddress,
    /// `getsockname(2)` が返した自ソケットのアドレスが `sockaddr_nl` でない（長さ不足・`nl_family` 不一致）。
    /// アドレスの中身は読まない。
    BadLocalAddress,
}

/// 送信（`sendto`）の EINTR 再試行の上限回数（シグナル嵐で無限ループにしない）。
/// 受信側は回数ではなく [`Deadline`] の残り時間で打ち切る。
const EINTR_RETRY_MAX: u32 = 16;

pub(crate) use consts::{
    EACCES, EAFNOSUPPORT, EAGAIN, EBUSY, EEXIST, EINTR, EINVAL, EISDIR, ELOOP, EMFILE, EMSGSIZE,
    ENFILE, ENOBUFS, ENODEV, ENOENT, ENOMEM, ENOTDIR, EOPNOTSUPP, EPERM, EPROTONOSUPPORT,
};

/// 受信待ち全体の期限（REPAIR-5）。単調時計（`Instant`）の開始時刻と全体 timeout を持ち、
/// 残り時間を毎回 `timeout - 経過時間` で計算し直す。
///
/// `Instant + timeout` を作らないため、`Duration::MAX` のような「期限を `Instant` で表せない」
/// timeout でも同じ式で扱える（EINTR・受信競合で早く戻っても、実際に経過した時間しか減らない）。
/// `NetlinkRouteSocket::recv` が 1 回の呼び出しにつき 1 つ作り、[`wait_readable`] と
/// 受信再試行の両方がこれを基準にする。
#[derive(Debug, Clone, Copy)]
pub(crate) struct Deadline {
    started: Instant,
    timeout: Duration,
}

impl Deadline {
    /// 現在時刻を起点に、全体で `timeout` 待つ期限を作る。
    pub(crate) fn after(timeout: Duration) -> Self {
        Self {
            started: Instant::now(),
            timeout,
        }
    }

    /// 残り時間（期限を過ぎていれば 0）。
    pub(crate) fn remaining(&self) -> Duration {
        remaining_after(self.timeout, self.started.elapsed())
    }
}

/// 全体 `timeout` から経過時間 `elapsed` を引いた残り時間（負にならず 0 で飽和）。
fn remaining_after(timeout: Duration, elapsed: Duration) -> Duration {
    timeout.saturating_sub(elapsed)
}

/// `poll(2)` に渡す待ち時間（ms）。端数は切り上げ（残り 1 ns を 0 ms 待ち＝ビジーループに
/// しない）、`i32::MAX` ms を超える分は飽和させる（呼び出し側が残り時間を再計算して再度待つ）。
fn poll_timeout_ms(remaining: Duration) -> i32 {
    let round_up = u128::from(!remaining.subsec_nanos().is_multiple_of(1_000_000));
    let ms = remaining.as_millis().saturating_add(round_up);
    i32::try_from(ms).unwrap_or(i32::MAX)
}

/// [`wait_readable`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Readiness {
    /// `POLLIN` が立った（データグラムが届いている。他スレッドが先に読む可能性は残る）。
    Readable,
    /// `POLLIN` なしで `POLLERR` / `POLLHUP` / `POLLNVAL` 等だけが立った。`recvfrom` で保留中の
    /// errno を取り出せる。取り出せなかった場合に再度待つと即座に戻り続けるため、呼び出し側は
    /// 待機を続けずエラーにする。
    Exceptional,
    /// 期限までに何も起きなかった。
    TimedOut,
}

// include/linux/socket.h・uapi/linux/netlink.h・uapi/asm-generic/socket.h・poll.h・errno.h の値。
// `SOCK_CLOEXEC` は `O_CLOEXEC` と同値。
#[cfg(target_arch = "x86_64")]
mod consts {
    pub const SUPPORTED: bool = true;
    pub const AF_NETLINK: u16 = 16;
    pub const SOCK_RAW: i32 = 3;
    pub const SOCK_CLOEXEC: i32 = 0o2_000_000;
    pub const NETLINK_ROUTE: i32 = 0;
    pub const NETLINK_NETFILTER: i32 = 12;
    pub const SOL_NETLINK: i32 = 270;
    pub const NETLINK_CAP_ACK: i32 = 10;
    pub const NETLINK_EXT_ACK: i32 = 11;
    pub const MSG_PEEK: i32 = 0x02;
    pub const MSG_TRUNC: i32 = 0x20;
    pub const MSG_DONTWAIT: i32 = 0x40;
    pub const POLLIN: i16 = 0x0001;
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EINTR: i32 = 4;
    pub const ENOMEM: i32 = 12;
    pub const EAGAIN: i32 = 11;
    pub const EACCES: i32 = 13;
    pub const EBUSY: i32 = 16;
    pub const EEXIST: i32 = 17;
    pub const ENODEV: i32 = 19;
    pub const EINVAL: i32 = 22;
    pub const ENFILE: i32 = 23;
    pub const EMFILE: i32 = 24;
    pub const EPROTONOSUPPORT: i32 = 93;
    pub const EOPNOTSUPP: i32 = 95;
    pub const EAFNOSUPPORT: i32 = 97;
    pub const ENOBUFS: i32 = 105;
    pub const EMSGSIZE: i32 = 90;
    /// `unshare(2)` の network namespace フラグ（`linux/sched.h` の `CLONE_NEWNET`）。
    pub const CLONE_NEWNET: i32 = 0x4000_0000;
    /// `mount(2)` の bind マウント（`linux/mount.h` の `MS_BIND`）。
    pub const MS_BIND: core::ffi::c_ulong = 4096;
    /// `umount2(2)` の遅延アンマウント（`linux/fs.h` の `MNT_DETACH`）。
    pub const MNT_DETACH: i32 = 2;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const ELOOP: i32 = 40;
    // open(2) フラグ（x86_64 は uapi/asm-generic/fcntl.h の既定値をそのまま使う）。
    pub const O_RDONLY: i32 = 0;
    pub const O_RDWR: i32 = 0o2;
    pub const O_NOCTTY: i32 = 0o400;
    pub const O_APPEND: i32 = 0o2000;
    pub const O_NONBLOCK: i32 = 0o4000;
    pub const O_DIRECTORY: i32 = 0o200_000;
    pub const O_NOFOLLOW: i32 = 0o400_000;
    pub const O_CLOEXEC: i32 = 0o2_000_000;
    /// `openat(2)` のカレントディレクトリ基準（`linux/fcntl.h` の `AT_FDCWD`）。
    pub const AT_FDCWD: i32 = -100;
}

#[cfg(target_arch = "aarch64")]
mod consts {
    pub const SUPPORTED: bool = true;
    pub const AF_NETLINK: u16 = 16;
    pub const SOCK_RAW: i32 = 3;
    pub const SOCK_CLOEXEC: i32 = 0o2_000_000;
    pub const NETLINK_ROUTE: i32 = 0;
    pub const NETLINK_NETFILTER: i32 = 12;
    pub const SOL_NETLINK: i32 = 270;
    pub const NETLINK_CAP_ACK: i32 = 10;
    pub const NETLINK_EXT_ACK: i32 = 11;
    pub const MSG_PEEK: i32 = 0x02;
    pub const MSG_TRUNC: i32 = 0x20;
    pub const MSG_DONTWAIT: i32 = 0x40;
    pub const POLLIN: i16 = 0x0001;
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EINTR: i32 = 4;
    pub const ENOMEM: i32 = 12;
    pub const EAGAIN: i32 = 11;
    pub const EACCES: i32 = 13;
    pub const EBUSY: i32 = 16;
    pub const EEXIST: i32 = 17;
    pub const ENODEV: i32 = 19;
    pub const EINVAL: i32 = 22;
    pub const ENFILE: i32 = 23;
    pub const EMFILE: i32 = 24;
    pub const EPROTONOSUPPORT: i32 = 93;
    pub const EOPNOTSUPP: i32 = 95;
    pub const EAFNOSUPPORT: i32 = 97;
    pub const ENOBUFS: i32 = 105;
    pub const EMSGSIZE: i32 = 90;
    /// `unshare(2)` の network namespace フラグ（`linux/sched.h` の `CLONE_NEWNET`）。
    pub const CLONE_NEWNET: i32 = 0x4000_0000;
    /// `mount(2)` の bind マウント（`linux/mount.h` の `MS_BIND`）。
    pub const MS_BIND: core::ffi::c_ulong = 4096;
    /// `umount2(2)` の遅延アンマウント（`linux/fs.h` の `MNT_DETACH`）。
    pub const MNT_DETACH: i32 = 2;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const ELOOP: i32 = 40;
    // open(2) フラグ。arm64 は uapi/asm/fcntl.h で O_DIRECTORY / O_NOFOLLOW / O_DIRECT / O_LARGEFILE を
    // 上書きする（0o40000 / 0o100000）。x86_64 の値（0o200000 / 0o400000）は aarch64 では O_DIRECT /
    // O_LARGEFILE になり symlink を辿ってしまうため流用しない。その他は asm-generic の既定値。
    pub const O_RDONLY: i32 = 0;
    pub const O_RDWR: i32 = 0o2;
    pub const O_NOCTTY: i32 = 0o400;
    pub const O_APPEND: i32 = 0o2000;
    pub const O_NONBLOCK: i32 = 0o4000;
    pub const O_DIRECTORY: i32 = 0o40_000;
    pub const O_NOFOLLOW: i32 = 0o100_000;
    pub const O_CLOEXEC: i32 = 0o2_000_000;
    /// `openat(2)` のカレントディレクトリ基準（`linux/fcntl.h` の `AT_FDCWD`）。
    pub const AT_FDCWD: i32 = -100;
}

/// 対応外アーキテクチャ: 値を確認していないためラッパーは `Unsupported` を返し、カーネルへ渡さない。
///
/// errno は実在しない負値を 1 つずつ割り当てる（カーネルの errno は正なので何にも一致せず、
/// 上位の `match` で互いに重複もしない）。それ以外は使われないプレースホルダの 0。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[allow(dead_code)]
mod consts {
    pub const SUPPORTED: bool = false;
    pub const AF_NETLINK: u16 = 0;
    pub const SOCK_RAW: i32 = 0;
    pub const SOCK_CLOEXEC: i32 = 0;
    pub const NETLINK_ROUTE: i32 = 0;
    pub const NETLINK_NETFILTER: i32 = 0;
    pub const SOL_NETLINK: i32 = 0;
    pub const NETLINK_CAP_ACK: i32 = 0;
    pub const NETLINK_EXT_ACK: i32 = 0;
    pub const MSG_PEEK: i32 = 0;
    pub const MSG_TRUNC: i32 = 0;
    pub const MSG_DONTWAIT: i32 = 0;
    pub const POLLIN: i16 = 0;
    pub const EPERM: i32 = -1;
    pub const ENOENT: i32 = -11;
    pub const EINTR: i32 = -2;
    pub const ENOMEM: i32 = -3;
    pub const EAGAIN: i32 = -4;
    pub const EACCES: i32 = -5;
    pub const EBUSY: i32 = -12;
    pub const EEXIST: i32 = -13;
    pub const ENODEV: i32 = -14;
    pub const EINVAL: i32 = -15;
    pub const ENFILE: i32 = -6;
    pub const EMFILE: i32 = -7;
    pub const EPROTONOSUPPORT: i32 = -8;
    pub const EOPNOTSUPP: i32 = -16;
    pub const EAFNOSUPPORT: i32 = -9;
    pub const ENOBUFS: i32 = -10;
    pub const EMSGSIZE: i32 = -17;
    pub const CLONE_NEWNET: i32 = 0;
    pub const MS_BIND: core::ffi::c_ulong = 0;
    pub const MNT_DETACH: i32 = 0;
    pub const ENOTDIR: i32 = -18;
    pub const EISDIR: i32 = -19;
    pub const ELOOP: i32 = -20;
    pub const O_RDONLY: i32 = 0;
    pub const O_RDWR: i32 = 0;
    pub const O_NOCTTY: i32 = 0;
    pub const O_APPEND: i32 = 0;
    pub const O_NONBLOCK: i32 = 0;
    pub const O_DIRECTORY: i32 = 0;
    pub const O_NOFOLLOW: i32 = 0;
    pub const O_CLOEXEC: i32 = 0;
    pub const AT_FDCWD: i32 = 0;
}

// SAFETY: 以下は Linux の libc（glibc / musl 共通）が公開する C 関数の宣言で、引数・戻り値の型を
// C の原型（各項目のコメントに記載）と一致させている。`ssize_t` / `size_t` はポインタ幅なので
// `isize` / `usize`、`nfds_t` は `unsigned long` なので `c_ulong`、`socklen_t` は u32、
// ポインタ引数は `#[repr(C)]` でサイズを const assert した `SockaddrNl`（12 バイト）・
// `PollFd`（8 バイト）を指す。呼び出し側の不変条件は各 `unsafe` ブロックの SAFETY に記す。
unsafe extern "C" {
    // 原型: `int socket(int domain, int type, int protocol)`。
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    // 原型: `int bind(int fd, const struct sockaddr *addr, socklen_t addrlen)`
    // （`socklen_t` は u32）。
    fn bind(fd: i32, addr: *const SockaddrNl, addrlen: u32) -> i32;
    // 原型: `int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)`。
    // `addrlen` は入力で `addr` の確保サイズ、出力でカーネルが返したアドレスの実長。
    fn getsockname(fd: i32, addr: *mut SockaddrNl, addrlen: *mut u32) -> i32;
    // 原型: `ssize_t sendto(int fd, const void *buf, size_t len, int flags,
    // const struct sockaddr *addr, socklen_t addrlen)`（LP64 で `ssize_t` は i64）。
    fn sendto(
        fd: i32,
        buf: *const core::ffi::c_void,
        len: usize,
        flags: i32,
        addr: *const SockaddrNl,
        addrlen: u32,
    ) -> isize;
    // 原型: `ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
    // struct sockaddr *addr, socklen_t *addrlen)`。
    fn recvfrom(
        fd: i32,
        buf: *mut core::ffi::c_void,
        len: usize,
        flags: i32,
        addr: *mut SockaddrNl,
        addrlen: *mut u32,
    ) -> isize;
    // 原型: `int poll(struct pollfd *fds, nfds_t nfds, int timeout)`
    // （`nfds_t` は `unsigned long`）。
    fn poll(fds: *mut PollFd, nfds: core::ffi::c_ulong, timeout: i32) -> i32;
    // 原型: `int setsockopt(int fd, int level, int optname, const void *optval,
    // socklen_t optlen)`（`socklen_t` は u32）。
    fn setsockopt(
        fd: i32,
        level: i32,
        optname: i32,
        optval: *const core::ffi::c_void,
        optlen: u32,
    ) -> i32;
    // 原型: `int unshare(int flags)`。
    fn unshare(flags: i32) -> i32;
    // 原型: `int mount(const char *source, const char *target, const char *filesystemtype,
    // unsigned long mountflags, const void *data)`（`unsigned long` は `c_ulong`）。
    fn mount(
        source: *const core::ffi::c_char,
        target: *const core::ffi::c_char,
        fstype: *const core::ffi::c_char,
        flags: core::ffi::c_ulong,
        data: *const core::ffi::c_void,
    ) -> i32;
    // 原型: `int umount2(const char *target, int flags)`。
    fn umount2(target: *const core::ffi::c_char, flags: i32) -> i32;
    // 原型: `uid_t geteuid(void)`（`uid_t` は u32。失敗しない）。
    fn geteuid() -> u32;
    // 原型: `int openat(int dirfd, const char *pathname, int flags, ...)`。可変長引数（mode）は
    // `O_CREAT` / `O_TMPFILE` のときだけ読まれる。本モジュールはどちらも渡さないため mode を渡さない。
    fn openat(dirfd: i32, path: *const core::ffi::c_char, flags: i32, ...) -> i32;
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

/// bind 済みソケットのカーネル採番 `nl_pid`（port ID）を `getsockname(2)` で取得する
/// （NET-11・#1313）。
///
/// `NetlinkRouteSocket::open_protocol` が bind 直後に呼び、応答の `nlmsg_pid` 照合に使う。
/// 返った値が 0 かの判定は呼び出し側（socket 層）で行い、ここは値を運ぶだけ。アドレス長が
/// `sockaddr_nl` に満たない、または `nl_family` が `AF_NETLINK` でなければ `BadLocalAddress`。
pub(crate) fn local_nl_pid(fd: BorrowedFd<'_>) -> Result<u32, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let addr_size = core::mem::size_of::<SockaddrNl>() as u32;
    let mut addr = SockaddrNl {
        nl_family: 0,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };
    let mut addrlen = addr_size;
    // SAFETY: `addr`・`addrlen` はスタック上の初期化済みローカルで、入力の `addrlen` は `addr` の
    // 確保サイズ（12）なので、カーネルは `addr` へ 12 バイトを超えて書かない。`fd` は生存中の
    // `BorrowedFd`。出力の `addrlen` と `nl_family` を検証してから `nl_pid` を使う。
    let rc = unsafe { getsockname(fd.as_raw_fd(), &raw mut addr, &raw mut addrlen) };
    if rc < 0 {
        return Err(last_error());
    }
    if addrlen < addr_size || addr.nl_family != consts::AF_NETLINK {
        return Err(SysError::BadLocalAddress);
    }
    Ok(addr.nl_pid)
}

/// 直前の失敗した syscall の errno を `SysError` にする（失敗直後に呼ぶこと）。
fn last_error() -> SysError {
    SysError::Os(io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

/// `NETLINK_ROUTE` の `SOCK_RAW|SOCK_CLOEXEC` ソケットを開く（未 bind）。
///
/// `SOCK_CLOEXEC` により exec 先（コンテナプロセス）へ fd を漏らさない。
pub(crate) fn open_route_socket() -> Result<OwnedFd, SysError> {
    open_socket(consts::NETLINK_ROUTE)
}

/// `NETLINK_NETFILTER`（nf_tables のバッチ送信用。TASK-137.3・#306）の `SOCK_RAW|SOCK_CLOEXEC`
/// ソケットを開く（未 bind）。`SOCK_CLOEXEC` の理由は [`open_route_socket`] と同じ。
pub(crate) fn open_netfilter_socket() -> Result<OwnedFd, SysError> {
    open_socket(consts::NETLINK_NETFILTER)
}

/// netlink の `SOCK_RAW|SOCK_CLOEXEC` ソケットを `protocol`（`NETLINK_*`）で開く。`protocol` は
/// このモジュールの定数だけが渡される（外部入力を渡す経路を公開しない）。
fn open_socket(protocol: i32) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数はすべて値渡しの整数でポインタを取らない。`protocol` は上の 2 つの公開関数が渡す
    // 定義済み定数のみ。成功時の戻り値は新規 fd で、直後に `OwnedFd` が唯一の所有者となる
    // （二重 close なし）。
    let fd = unsafe {
        socket(
            i32::from(consts::AF_NETLINK),
            consts::SOCK_RAW | consts::SOCK_CLOEXEC,
            protocol,
        )
    };
    if fd < 0 {
        return Err(last_error());
    }
    // SAFETY: `fd` は上で成功した socket が返した、他に所有者のいない有効な fd。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `NETLINK_EXT_ACK` を有効にする（拡張 ACK の `NLMSGERR_ATTR_MSG` / `OFFS` を受け取る。Linux 4.12 以降）。
/// 失敗（古いカーネルの `ENOPROTOOPT` 等）は呼び出し側が無視して拡張 ACK なしで続ける（NET-11）。
pub(crate) fn enable_ext_ack(fd: BorrowedFd<'_>) -> Result<(), SysError> {
    set_netlink_flag(fd, consts::NETLINK_EXT_ACK)
}

/// `NETLINK_CAP_ACK` を有効にする（エラー応答が元要求の本体を写さずヘッダのみになる。Linux 4.3 以降）。
pub(crate) fn enable_cap_ack(fd: BorrowedFd<'_>) -> Result<(), SysError> {
    set_netlink_flag(fd, consts::NETLINK_CAP_ACK)
}

/// `SOL_NETLINK` の真偽値オプション `optname` を 1 にする。`optname` はこのモジュールの定数だけが
/// 渡される（任意の optname・optval を渡す経路を公開しない）。
fn set_netlink_flag(fd: BorrowedFd<'_>, optname: i32) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let on: i32 = 1;
    // SAFETY: `on` はスタック上の初期化済み `i32` で、`optlen` はその `size_of`（4）と一致する。
    // カーネルは呼び出しの間だけ `optval` を読む。`fd` は生存中の `BorrowedFd`。`level` / `optname` は
    // 値渡しの整数で、このモジュールの定義済み定数のみ。
    let rc = unsafe {
        setsockopt(
            fd.as_raw_fd(),
            consts::SOL_NETLINK,
            optname,
            (&raw const on).cast(),
            core::mem::size_of::<i32>() as u32,
        )
    };
    if rc < 0 { Err(last_error()) } else { Ok(()) }
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

/// `fd` が読み取り可能になるまで、`deadline` の残り時間だけ待つ。
///
/// 期限を過ぎていても `poll` を 1 回は（0 ms で）呼ぶため、timeout 0 は「届いていれば読む」の
/// 非ブロック確認になる。EINTR・`i32::MAX` ms で飽和した 1 回分の時間切れは、`deadline` から
/// 残り時間を計算し直して待ち直す（全体で `deadline` を超えて待たず、早くも切り上げない）。
// 対応外アーキテクチャでは `POLLIN` がプレースホルダの 0 で、先頭の `SUPPORTED` 判定により
// マスク演算へ到達しない。その構成でだけ出る lint を、その構成に限って許可する。
#[cfg_attr(
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
    allow(clippy::bad_bit_mask)
)]
pub(crate) fn wait_readable(
    fd: BorrowedFd<'_>,
    deadline: &Deadline,
) -> Result<Readiness, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    loop {
        let ms = poll_timeout_ms(deadline.remaining());
        let mut pfd = PollFd {
            fd: fd.as_raw_fd(),
            events: consts::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` はスタック上の初期化済み 1 要素で、`nfds` = 1 と一致する。カーネルは呼び出しの間だけ
        // `revents` を書く。`fd` は生存中の `BorrowedFd`。`ms` は 0 以上で、負値（無期限待ち）を渡さない。
        let r = unsafe { poll(&raw mut pfd, 1, ms) };
        if r > 0 {
            return Ok(if pfd.revents & consts::POLLIN != 0 {
                Readiness::Readable
            } else {
                Readiness::Exceptional
            });
        }
        if r < 0 {
            let e = last_error();
            if e != SysError::Os(consts::EINTR) {
                return Err(e);
            }
        }
        if deadline.remaining().is_zero() {
            return Ok(Readiness::TimedOut);
        }
    }
}

/// 受信キュー先頭のデータグラムの実長を、キューから取り除かずに待たずに返す
/// （`MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT`）。
///
/// 呼び出し側（`NetlinkRouteSocket::recv`）が、上限検証のうえ必要な長さのバッファを確保してから
/// [`recv_from`] で取り出すために使う。届いていなければ `Os(EAGAIN)`、中断は `Os(EINTR)`。
/// 送信元アドレスは取得しない（検証は取り出す [`recv_from`] 側で行う）。
pub(crate) fn peek_datagram_len(fd: BorrowedFd<'_>) -> Result<usize, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut empty = [0u8; 0];
    // SAFETY: `len` に 0 を渡すため、カーネルは `buf` へ 1 バイトも書かない（`empty` の非 null・
    // 整列済みポインタを渡すが参照されない）。`addr`・`addrlen` は両方 null で、`recvfrom(2)` は
    // この組を「送信元アドレスを返さない」指定として扱い、どちらにも書かない。`fd` は生存中の
    // `BorrowedFd`。`MSG_PEEK` のためキューの状態を変えない。
    let n = unsafe {
        recvfrom(
            fd.as_raw_fd(),
            empty.as_mut_ptr().cast(),
            0,
            consts::MSG_PEEK | consts::MSG_TRUNC | consts::MSG_DONTWAIT,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    usize::try_from(n).map_err(|_| last_error())
}

/// 1 データグラムを待たずに受信する（`MSG_DONTWAIT`）。通常は [`wait_readable`] の後に呼ぶ。
///
/// 読み取り可能でなければ（`poll` の後に他スレッドが先に取った場合を含む）`Os(EAGAIN)`、シグナルで
/// 中断されれば `Os(EINTR)` を返す。ここでは再試行せず、呼び出し側が [`Deadline`] の残り時間で
/// 待ち直すかを決める。送信元が netlink アドレスでなければ `BadSenderAddress` で拒否する。
///
/// `MSG_TRUNC` を渡すため、`buf` に収まらない場合も戻り値は実長になり `truncated` が立つ。
pub(crate) fn recv_from(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Result<RecvMeta, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let addr_size = core::mem::size_of::<SockaddrNl>() as u32;
    let mut addr = SockaddrNl {
        nl_family: 0,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };
    let mut addrlen = addr_size;
    // SAFETY: `buf` は排他借用したスライスで `buf.len()` バイトが書き込み可能（カーネルは `len` を
    // 超えて書かない。`MSG_TRUNC` でも書き込み量は `len` まで）。`addr`・`addrlen` はスタック上の
    // 初期化済みローカルで、`addrlen` は `addr` の確保サイズ（12）を入力として渡すため、カーネルは
    // `addr` へ 12 バイトを超えて書かない。`fd` は生存中の `BorrowedFd`。
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
        return Err(last_error());
    };
    // カーネルが書いたアドレス長を検証してから `addr` の中身を使う（短ければ `nl_pid` は未設定）。
    if addrlen < addr_size || addr.nl_family != consts::AF_NETLINK {
        return Err(SysError::BadSenderAddress);
    }
    Ok(RecvMeta {
        len: n,
        truncated: n > buf.len(),
        sender_pid: addr.nl_pid,
    })
}

/// 呼び出しスレッドだけを新しい network namespace へ移す（`unshare(CLONE_NEWNET)`。TASK-139.2.1・NET-1）。
///
/// `crate::netns` の使い捨てスレッド内でのみ呼ぶ。`CLONE_NEWUSER` と違いマルチスレッドの
/// プロセスでも合法で、影響は呼び出しスレッド（Linux ではタスク）だけに閉じる。元の namespace へ
/// 戻る手段は持たないので、呼び出したスレッドは用が済んだら終了させること。`CAP_SYS_ADMIN` が必要。
pub(crate) fn unshare_net() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数は値渡しの整数 1 つでポインタを取らない。`CLONE_NEWNET` は定義済み定数。
    // カーネル側の副作用は呼び出しスレッドの netns の差し替えのみで、メモリには触れない。
    let rc = unsafe { unshare(consts::CLONE_NEWNET) };
    if rc < 0 { Err(last_error()) } else { Ok(()) }
}

/// `source` を `target` へ bind マウントする（`mount(source, target, NULL, MS_BIND, NULL)`）。
///
/// netns の pin（`/proc/thread-self/ns/net` を通常ファイルへ重ねる）にだけ使う。fstype・data は
/// 常に NULL で、他のマウント種別・フラグは公開しない。`CAP_SYS_ADMIN` が必要。
pub(crate) fn bind_mount(source: &CStr, target: &CStr) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `source` / `target` は `CStr` なので NUL 終端済みで、この呼び出しの間は借用により
    // 有効。カーネルは文字列を読むだけで保持しない。fstype と data は NULL（`MS_BIND` では無視される
    // 組み合わせ）。フラグは定義済み定数 `MS_BIND` のみ。
    let rc = unsafe {
        mount(
            source.as_ptr(),
            target.as_ptr(),
            core::ptr::null(),
            consts::MS_BIND,
            core::ptr::null(),
        )
    };
    if rc < 0 { Err(last_error()) } else { Ok(()) }
}

/// `target` のマウントを遅延アンマウントする（`umount2(target, MNT_DETACH)`）。
/// 使用中でも名前空間から切り離すだけで、参照が尽きたときにカーネルが片付ける。
/// マウントポイントでない場合は `EINVAL`。`CAP_SYS_ADMIN` が必要。
pub(crate) fn unmount_detach(target: &CStr) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `target` は NUL 終端済みの `CStr` で、呼び出しの間は借用により有効。カーネルは文字列を
    // 読むだけで保持しない。フラグは定義済み定数 `MNT_DETACH` のみ。
    let rc = unsafe { umount2(target.as_ptr(), consts::MNT_DETACH) };
    if rc < 0 { Err(last_error()) } else { Ok(()) }
}

/// 実効 UID を返す（`geteuid(2)`。失敗しない）。netns 置き場ディレクトリの所有者確認に使う。
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: 引数なしで失敗せず、メモリにも触れない（POSIX の geteuid は常に成功する）。
    unsafe { geteuid() }
}

/// 絶対パス `path` のディレクトリを `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` で開く。
///
/// 最終要素が symlink なら `ELOOP`（ディレクトリへの symlink は `O_DIRECTORY` により `ENOTDIR`）、
/// ディレクトリでなければ `ENOTDIR`。相対パスはカレントディレクトリに
/// 依存するため `EINVAL` で拒否する。`crate::add_host_dns` が管理ルート（`canonicalize` 済み）を開く起点に使う。
pub(crate) fn open_dir_nofollow(path: &CStr) -> Result<OwnedFd, SysError> {
    if path.to_bytes().first() != Some(&b'/') {
        return Err(SysError::Os(consts::EINVAL));
    }
    open_at_raw(
        consts::AT_FDCWD,
        path,
        consts::O_RDONLY | consts::O_DIRECTORY | consts::O_NOFOLLOW | consts::O_CLOEXEC,
    )
}

/// `dir` 直下の 1 要素 `name` のディレクトリを `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` で開く。
///
/// `name` は `/` を含まない通常の名前（`.`・`..`・空は `EINVAL`）。symlink なら `ELOOP`
/// または `ENOTDIR`（ディレクトリへの symlink）、ディレクトリでなければ `ENOTDIR`。
pub(crate) fn open_dir_nofollow_at(dir: BorrowedFd<'_>, name: &CStr) -> Result<OwnedFd, SysError> {
    check_single_component(name)?;
    open_at_raw(
        dir.as_raw_fd(),
        name,
        consts::O_RDONLY | consts::O_DIRECTORY | consts::O_NOFOLLOW | consts::O_CLOEXEC,
    )
}

/// `dir` 直下の 1 要素 `name` の既存ファイルを
/// `O_RDWR | O_APPEND | O_NOFOLLOW | O_NOCTTY | O_NONBLOCK | O_CLOEXEC` で開く（作成しない）。
///
/// `O_CREAT` を渡さないため、無ければ `ENOENT`。symlink なら `ELOOP`、ディレクトリなら `EISDIR`。
/// `O_NONBLOCK` / `O_NOCTTY` は通常ファイル以外（FIFO・端末）を開いた際に待たない・制御端末にしない
/// ための保険で、通常ファイルかどうかの判定は呼び出し側が開いた fd で行う。
pub(crate) fn open_append_nofollow_at(
    dir: BorrowedFd<'_>,
    name: &CStr,
) -> Result<OwnedFd, SysError> {
    check_single_component(name)?;
    open_at_raw(
        dir.as_raw_fd(),
        name,
        consts::O_RDWR
            | consts::O_APPEND
            | consts::O_NOFOLLOW
            | consts::O_NOCTTY
            | consts::O_NONBLOCK
            | consts::O_CLOEXEC,
    )
}

/// `openat` に渡す名前が 1 要素（`/` を含まない・空 / `.` / `..` でない）であることを確認する。
/// 複数要素を渡すと途中要素の symlink を辿ってしまうため、ラッパーの入口で拒否する。
fn check_single_component(name: &CStr) -> Result<(), SysError> {
    let b = name.to_bytes();
    if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') {
        return Err(SysError::Os(consts::EINVAL));
    }
    Ok(())
}

/// `openat(dirfd, path, flags)` を呼び、成功時の fd を `OwnedFd` にする。`flags` はこのモジュールの
/// 定数の組み合わせだけが渡される（`O_CREAT` / `O_TMPFILE` を含まないので mode は渡さない）。
fn open_at_raw(dirfd: i32, path: &CStr, flags: i32) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `path` は NUL 終端済みの `CStr` で、呼び出しの間は借用により有効（カーネルは読むだけで
    // 保持しない）。`dirfd` は呼び出し側が借用している生存中の fd（`BorrowedFd`）か `AT_FDCWD`
    // （このとき `path` は絶対パスに限定済み）。`flags` に `O_CREAT` / `O_TMPFILE` を含まないため
    // 可変長引数 mode は読まれない。
    let fd = unsafe { openat(dirfd, path.as_ptr(), flags) };
    if fd < 0 {
        return Err(last_error());
    }
    // SAFETY: `fd` は直前の openat が返した非負の新規 fd で他に所有者がおらず、ここで `OwnedFd` が
    // 唯一の所有者になる（二重 close なし）。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
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
        assert_eq!(consts::SOL_NETLINK, 270);
        assert_eq!(consts::NETLINK_CAP_ACK, 10);
        assert_eq!(consts::NETLINK_EXT_ACK, 11);
        assert_eq!(consts::MSG_PEEK, 0x02);
        assert_eq!(consts::MSG_TRUNC, 0x20);
        assert_eq!(consts::MSG_DONTWAIT, 0x40);
        assert_eq!(consts::POLLIN, 1);
        assert_eq!(consts::EINTR, 4);
        assert_eq!(consts::EAGAIN, 11);
        assert_eq!(consts::ENOENT, 2);
        assert_eq!(consts::EBUSY, 16);
        assert_eq!(consts::EEXIST, 17);
        assert_eq!(consts::ENODEV, 19);
        assert_eq!(consts::EINVAL, 22);
        assert_eq!(consts::EOPNOTSUPP, 95);
        assert_eq!(consts::CLONE_NEWNET, 0x4000_0000);
        assert_eq!(consts::MS_BIND, 4096);
        assert_eq!(consts::MNT_DETACH, 2);
        assert_eq!(consts::ENOTDIR, 20);
        assert_eq!(consts::EISDIR, 21);
        assert_eq!(consts::ELOOP, 40);
        assert_eq!(consts::O_RDWR, 2);
        assert_eq!(consts::O_APPEND, 0o2000);
        assert_eq!(consts::O_CLOEXEC, 0o2_000_000);
        assert_eq!(consts::AT_FDCWD, -100);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            (consts::O_DIRECTORY, consts::O_NOFOLLOW),
            (0o200_000, 0o400_000)
        );
        #[cfg(target_arch = "aarch64")]
        assert_eq!(
            (consts::O_DIRECTORY, consts::O_NOFOLLOW),
            (0o40_000, 0o100_000)
        );
        assert_eq!(core::mem::size_of::<SockaddrNl>(), 12);
        assert_eq!(core::mem::size_of::<PollFd>(), 8);
    }

    /// NET-11: 実カーネルで route ソケットに EXT_ACK / CAP_ACK を設定できる（4.12 以降のカーネル前提）。
    #[test]
    fn enable_ack_options_on_route_socket() {
        let fd = open_route_socket().expect("open");
        enable_ext_ack(fd.as_fd()).expect("ext ack");
        enable_cap_ack(fd.as_fd()).expect("cap ack");
    }

    /// NET-11・#1313: bind 後に `getsockname` で得た `nl_pid` は 0 でなく、ソケットごとに異なる。
    #[test]
    fn local_nl_pid_after_bind_is_nonzero_and_distinct() {
        let a = open_route_socket().expect("open a");
        bind_kernel_assigned(a.as_fd()).expect("bind a");
        let b = open_route_socket().expect("open b");
        bind_kernel_assigned(b.as_fd()).expect("bind b");
        let pa = local_nl_pid(a.as_fd()).expect("pid a");
        let pb = local_nl_pid(b.as_fd()).expect("pid b");
        assert_ne!(pa, 0);
        assert_ne!(pb, 0);
        assert_ne!(pa, pb);
    }

    /// NET-11・REPAIR-5: 何も届いていない socket の `wait_readable` は期限まで待って `TimedOut` を返す
    /// （早く切り上げず、無期限にも待たない）。
    #[test]
    fn wait_readable_times_out() {
        let fd = open_route_socket().expect("open");
        bind_kernel_assigned(fd.as_fd()).expect("bind");
        let t = Instant::now();
        let deadline = Deadline::after(Duration::from_millis(50));
        assert_eq!(
            wait_readable(fd.as_fd(), &deadline),
            Ok(Readiness::TimedOut)
        );
        assert!(t.elapsed() >= Duration::from_millis(50));
        assert!(t.elapsed() < Duration::from_secs(5));
        assert_eq!(deadline.remaining(), Duration::ZERO);
    }

    /// NET-11・REPAIR-5: timeout 0 は待たずに `TimedOut`、届いていない socket の `recv_from` は
    /// 待たずに `EAGAIN`（`MSG_DONTWAIT`）。
    #[test]
    fn zero_timeout_and_empty_recv_do_not_block() {
        let fd = open_route_socket().expect("open");
        bind_kernel_assigned(fd.as_fd()).expect("bind");
        let t = Instant::now();
        let deadline = Deadline::after(Duration::ZERO);
        assert_eq!(
            wait_readable(fd.as_fd(), &deadline),
            Ok(Readiness::TimedOut)
        );
        let mut buf = [0u8; 64];
        assert_eq!(
            recv_from(fd.as_fd(), &mut buf),
            Err(SysError::Os(consts::EAGAIN))
        );
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    /// NET-11: 何も届いていない socket の `peek_datagram_len` は待たずに `EAGAIN`。
    #[test]
    fn peek_on_empty_socket_does_not_block() {
        let fd = open_route_socket().expect("open");
        bind_kernel_assigned(fd.as_fd()).expect("bind");
        let t = Instant::now();
        assert_eq!(
            peek_datagram_len(fd.as_fd()),
            Err(SysError::Os(consts::EAGAIN))
        );
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    /// NET-11: `peek_datagram_len` はデータグラムを取り除かずに実長を返し、続く `recv_from` が
    /// 同じ長さのデータグラムを取り出す。小さいバッファでは `truncated` が立ち実長が返る。
    #[test]
    fn peek_reports_full_length_without_consuming() {
        // NLM_F_REQUEST|NLM_F_ACK だけの RTM_GETLINK（ifinfomsg なし）。カーネルは NLMSG_ERROR
        // 1 件（ヘッダ 16 + errno 4 + 元ヘッダ 16 = 36 バイト）を返す。
        let mut req = Vec::new();
        req.extend_from_slice(&16u32.to_ne_bytes());
        req.extend_from_slice(&18u16.to_ne_bytes());
        req.extend_from_slice(&(0x01u16 | 0x04u16).to_ne_bytes());
        req.extend_from_slice(&9u32.to_ne_bytes());
        req.extend_from_slice(&0u32.to_ne_bytes());
        let fd = open_route_socket().expect("open");
        bind_kernel_assigned(fd.as_fd()).expect("bind");
        assert_eq!(send_to_kernel(fd.as_fd(), &req), Ok(16));
        let deadline = Deadline::after(Duration::from_secs(5));
        assert_eq!(
            wait_readable(fd.as_fd(), &deadline),
            Ok(Readiness::Readable)
        );
        assert_eq!(peek_datagram_len(fd.as_fd()), Ok(36));
        let mut small = [0u8; 8];
        assert_eq!(
            recv_from(fd.as_fd(), &mut small),
            Ok(RecvMeta {
                len: 36,
                truncated: true,
                sender_pid: 0
            })
        );
        assert_eq!(
            peek_datagram_len(fd.as_fd()),
            Err(SysError::Os(consts::EAGAIN))
        );
    }

    /// REPAIR-5: 残り時間は `timeout - 経過時間` で、0 未満にならない。`Instant` で期限を表せない
    /// `Duration::MAX` でも、経過した分だけが減る（EINTR・受信競合で早戻りしても短縮されない）。
    #[test]
    fn remaining_after_subtracts_only_elapsed_time() {
        let s = Duration::from_secs;
        assert_eq!(remaining_after(s(10), s(3)), s(7));
        assert_eq!(remaining_after(s(10), s(10)), Duration::ZERO);
        assert_eq!(remaining_after(s(10), s(11)), Duration::ZERO);
        assert_eq!(
            remaining_after(Duration::MAX, s(1)),
            Duration::MAX - Duration::from_secs(1)
        );
        assert!(Deadline::after(Duration::MAX).remaining() > s(u64::MAX / 2));
        assert_eq!(Deadline::after(Duration::ZERO).remaining(), Duration::ZERO);
    }

    /// REPAIR-5: `poll` へ渡す ms は端数切り上げ・`i32::MAX` 飽和で、負値（無期限待ち）にならない。
    #[test]
    fn poll_timeout_ms_rounds_up_and_saturates() {
        assert_eq!(poll_timeout_ms(Duration::ZERO), 0);
        assert_eq!(poll_timeout_ms(Duration::from_nanos(1)), 1);
        assert_eq!(poll_timeout_ms(Duration::from_millis(50)), 50);
        assert_eq!(poll_timeout_ms(Duration::from_micros(50_001)), 51);
        assert_eq!(
            poll_timeout_ms(Duration::from_millis(i32::MAX as u64)),
            i32::MAX
        );
        assert_eq!(
            poll_timeout_ms(Duration::from_millis(i32::MAX as u64 + 1)),
            i32::MAX
        );
        assert_eq!(poll_timeout_ms(Duration::MAX), i32::MAX);
    }
}
