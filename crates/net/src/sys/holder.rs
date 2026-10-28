//! netns holder（`crate::netns_holder`。NET-9・CORE-6・SEC-5・REPAIR-5・#3197）が使う syscall・FFI の薄いラッパー
//! （`crates/net` の `sys` モジュールの子。`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節）。
//!
//! # 呼び出し文脈
//! - supervisor 側の `NetnsHolderChannel`（`socketpair`・`SCM_RIGHTS` つき `sendmsg`・`recvmsg`）
//! - holder プロセス側の `run_netns_holder_main`（stdin のソケット種別・`SO_PEERCRED`・`recvmsg`・`setns(2)`・
//!   `prctl(2)`・`capset(2)`）
//!
//! # 契約
//! - 親 `sys` と同じ（`unsafe fn` を公開しない・`SAFETY:` の明記・arch ごとの定数・戻り値 -1 は直後に errno を確保）
//! - 受け取った fd はすべて `OwnedFd` で所有する（拒否時は drop で閉じる）。制御バッファはちょうど 2 本分
//!   （`MAX_FDS`）で、3 本目以降はカーネルが閉じて `MSG_CTRUNC` を立てる
//! - 待ちは持たない（`MSG_DONTWAIT`）。期限つきの待ちは親の `wait_readable` と `Deadline` が担う（REPAIR-5）
//!
//! # `libc` 照合について
//! 定数・構造体・関数型は `libc_abi`（本ファイル末尾）で `libc` と `const` 評価で照合する。`libc` に対応物が
//! 無い `capset(2)` の `__user_cap_header_struct`・`__user_cap_data_struct`・`_LINUX_CAPABILITY_VERSION_3` は
//! カーネル uapi（`include/uapi/linux/capability.h`）の定義を直接使い、大きさだけを `const` で固定する。
//! `msghdr` 系は core の `seccomp_notify` と同じ方針で gnu に限ってオフセットまで照合する。

use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};

use super::{SysError, last_error};

/// 1 通で受けられる fd の最大本数（user・net の 2 本。12.2）。
pub(crate) const MAX_FDS: usize = 2;

pub(crate) use consts::{CLONE_NEWNET, CLONE_NEWUSER, ENOTSOCK, EPIPE, PR_SIGKILL, SOCK_SEQPACKET};

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
mod consts {
    pub const SUPPORTED: bool = true;
    pub const AF_UNIX: i32 = 1;
    pub const SOCK_SEQPACKET: i32 = 5;
    pub const SOL_SOCKET: i32 = 1;
    pub const SO_TYPE: i32 = 3;
    pub const SO_PEERCRED: i32 = 17;
    pub const SCM_RIGHTS: i32 = 1;
    pub const MSG_CTRUNC: i32 = 0x8;
    pub const MSG_NOSIGNAL: i32 = 0x4000;
    pub const MSG_CMSG_CLOEXEC: i32 = 0x4000_0000;
    pub const CLONE_NEWUSER: i32 = 0x1000_0000;
    pub const CLONE_NEWNET: i32 = 0x4000_0000;
    pub const PR_SET_PDEATHSIG: i32 = 1;
    pub const PR_GET_PDEATHSIG: i32 = 2;
    pub const PR_GET_DUMPABLE: i32 = 3;
    pub const PR_SET_NO_NEW_PRIVS: i32 = 38;
    pub const PR_SIGKILL: i32 = 9;
    pub const ENOTSOCK: i32 = 88;
    pub const EPIPE: i32 = 32;
    /// `capset(2)` のシステムコール番号（arch/x86/entry/syscalls/syscall_64.tbl）。
    pub const SYS_CAPSET: core::ffi::c_long = 126;
    /// `close_range(2)` のシステムコール番号（syscall_64.tbl。Linux 5.9 以上）。
    pub const SYS_CLOSE_RANGE: core::ffi::c_long = 436;
    pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
}

#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
mod consts {
    pub const SUPPORTED: bool = true;
    pub const AF_UNIX: i32 = 1;
    pub const SOCK_SEQPACKET: i32 = 5;
    pub const SOL_SOCKET: i32 = 1;
    pub const SO_TYPE: i32 = 3;
    pub const SO_PEERCRED: i32 = 17;
    pub const SCM_RIGHTS: i32 = 1;
    pub const MSG_CTRUNC: i32 = 0x8;
    pub const MSG_NOSIGNAL: i32 = 0x4000;
    pub const MSG_CMSG_CLOEXEC: i32 = 0x4000_0000;
    pub const CLONE_NEWUSER: i32 = 0x1000_0000;
    pub const CLONE_NEWNET: i32 = 0x4000_0000;
    pub const PR_SET_PDEATHSIG: i32 = 1;
    pub const PR_GET_PDEATHSIG: i32 = 2;
    pub const PR_GET_DUMPABLE: i32 = 3;
    pub const PR_SET_NO_NEW_PRIVS: i32 = 38;
    pub const PR_SIGKILL: i32 = 9;
    pub const ENOTSOCK: i32 = 88;
    pub const EPIPE: i32 = 32;
    /// `capset(2)` のシステムコール番号（include/uapi/asm-generic/unistd.h）。
    pub const SYS_CAPSET: core::ffi::c_long = 91;
    /// `close_range(2)` のシステムコール番号（asm-generic/unistd.h。Linux 5.9 以上）。
    pub const SYS_CLOSE_RANGE: core::ffi::c_long = 436;
    pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
}

#[cfg(not(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod consts {
    pub const SUPPORTED: bool = false;
    pub const AF_UNIX: i32 = 0;
    pub const SOCK_SEQPACKET: i32 = 0;
    pub const SOL_SOCKET: i32 = 0;
    pub const SO_TYPE: i32 = 0;
    pub const SO_PEERCRED: i32 = 0;
    pub const SCM_RIGHTS: i32 = 0;
    pub const MSG_CTRUNC: i32 = 0;
    pub const MSG_NOSIGNAL: i32 = 0;
    pub const MSG_CMSG_CLOEXEC: i32 = 0;
    pub const CLONE_NEWUSER: i32 = 0;
    pub const CLONE_NEWNET: i32 = 0;
    pub const PR_SET_PDEATHSIG: i32 = 0;
    pub const PR_GET_PDEATHSIG: i32 = 0;
    pub const PR_GET_DUMPABLE: i32 = 0;
    pub const PR_SET_NO_NEW_PRIVS: i32 = 0;
    pub const PR_SIGKILL: i32 = 0;
    pub const ENOTSOCK: i32 = -1;
    pub const EPIPE: i32 = -2;
    pub const SYS_CAPSET: core::ffi::c_long = 0;
    pub const SYS_CLOSE_RANGE: core::ffi::c_long = 0;
    pub const LINUX_CAPABILITY_VERSION_3: u32 = 0;
}

/// `struct iovec`（LP64 で 16 バイト）。
#[repr(C)]
struct IoVec {
    base: *mut core::ffi::c_void,
    len: usize,
}

/// `struct msghdr`（LP64 で 56 バイト。カーネルの `user_msghdr` に合わせる）。
#[repr(C)]
struct MsgHdr {
    name: *mut core::ffi::c_void,
    namelen: u32,
    iov: *mut IoVec,
    iovlen: usize,
    control: *mut core::ffi::c_void,
    controllen: usize,
    flags: i32,
}

/// `struct ucred`（12 バイト）。`SO_PEERCRED` の結果。
#[repr(C)]
struct Ucred {
    pid: i32,
    uid: u32,
    gid: u32,
}

/// `struct __user_cap_header_struct`（8 バイト）。
#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

/// `struct __user_cap_data_struct`（12 バイト。`_LINUX_CAPABILITY_VERSION_3` では 2 要素を渡す）。
#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const _: () = assert!(core::mem::size_of::<IoVec>() == 16);
const _: () = assert!(core::mem::size_of::<MsgHdr>() == 56);
const _: () = assert!(core::mem::size_of::<Ucred>() == 12);
const _: () = assert!(core::mem::size_of::<CapUserHeader>() == 8);
const _: () = assert!(core::mem::size_of::<CapUserData>() == 12);

const CMSG_HDR_LEN: usize = 16;

/// `CMSG_ALIGN`（`size_t` の境界へ切り上げ）。
const fn cmsg_align(len: usize) -> usize {
    (len + 7) & !7
}

/// `CMSG_SPACE(data_len)`。
const fn cmsg_space(data_len: usize) -> usize {
    CMSG_HDR_LEN + cmsg_align(data_len)
}

/// 制御バッファの容量（`MAX_FDS` 本ちょうど。余裕を持たせると 3 本目以降が入ってしまう）。
const CONTROL_CAP: usize = cmsg_space(MAX_FDS * 4);

/// `cmsghdr` の整列を満たす固定長の制御バッファ。
#[repr(C, align(8))]
struct ControlBuf([u8; CONTROL_CAP]);

/// 送信できる fd の最大本数。本番の送信は 2 本（`MAX_FDS`）だが、受信側の「3 本目以降は拒否」を試験で
/// 作るため（feature `netns-holder-test-support`）それより多く載せられる。
pub(crate) const MAX_SEND_FDS: usize = 4;

/// 送信用の制御バッファ（`MAX_SEND_FDS` 本分。整列は [`ControlBuf`] と同じ）。
#[repr(C, align(8))]
struct SendControlBuf([u8; cmsg_space(MAX_SEND_FDS * 4)]);

// SAFETY（宣言そのものの妥当性）: Linux の libc（glibc / musl 共通）が公開する C 関数の宣言で、引数・戻り値の型を
// 各項目の原型と一致させている。`ssize_t` / `size_t` はポインタ幅なので `isize` / `usize`、`socklen_t` は u32。
// 呼び出し側の不変条件は各 `unsafe` ブロックの SAFETY に記す。
unsafe extern "C" {
    // 原型: `int socketpair(int domain, int type, int protocol, int sv[2])`。
    fn socketpair(domain: i32, ty: i32, protocol: i32, sv: *mut i32) -> i32;
    // 原型: `ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)`。
    fn sendmsg(fd: i32, msg: *const MsgHdr, flags: i32) -> isize;
    // 原型: `ssize_t recvmsg(int fd, struct msghdr *msg, int flags)`。
    fn recvmsg(fd: i32, msg: *mut MsgHdr, flags: i32) -> isize;
    // 原型: `int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)`。
    fn getsockopt(
        fd: i32,
        level: i32,
        optname: i32,
        optval: *mut core::ffi::c_void,
        optlen: *mut u32,
    ) -> i32;
    // 原型: `int setns(int fd, int nstype)`。
    fn setns(fd: i32, nstype: i32) -> i32;
    // 原型: `int prctl(int option, ...)`（可変長。本モジュールは常に `unsigned long` 4 個を渡す）。
    fn prctl(option: i32, ...) -> i32;
    // 原型: `long syscall(long number, ...)`。`capset(2)` は glibc に関数が無いため経由する。
    fn syscall(number: core::ffi::c_long, ...) -> core::ffi::c_long;
}

/// `AF_UNIX` / `SOCK_SEQPACKET`（`SOCK_CLOEXEC`）のソケット対を作る。supervisor が holder の stdin にする端と
/// 自分の端を作るために使う。両端とも close-on-exec（stdin への dup2 は `Command` が行い、そこで外れる）。
pub(crate) fn socketpair_seqpacket() -> Result<(OwnedFd, OwnedFd), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut sv = [0i32; 2];
    // SAFETY: `sv` はスタック上の 2 要素の書き込み可能な配列で、`socketpair(2)` は成功時だけ 2 つの新しい fd を書く。
    let rc = unsafe {
        socketpair(
            consts::AF_UNIX,
            consts::SOCK_SEQPACKET | super::consts::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    };
    if rc < 0 {
        return Err(last_error());
    }
    // SAFETY: 成功した `socketpair(2)` が新規に割り当てた fd で、他に所有者がいない。
    let (a, b) = unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };
    Ok((a, b))
}

/// ソケットの種別（`SO_TYPE`）。ソケットでなければ `Os(ENOTSOCK)`。
pub(crate) fn socket_type(fd: BorrowedFd<'_>) -> Result<i32, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut val: i32 = 0;
    let mut len = core::mem::size_of::<i32>() as u32;
    // SAFETY: `val`・`len` はスタック上の初期化済みローカルで、入力の `len` は `val` の確保サイズ（4）。カーネルは
    // それを超えて書かない。`fd` は生存中の `BorrowedFd`。
    let rc = unsafe {
        getsockopt(
            fd.as_raw_fd(),
            consts::SOL_SOCKET,
            consts::SO_TYPE,
            (&raw mut val).cast(),
            &raw mut len,
        )
    };
    if rc < 0 {
        return Err(last_error());
    }
    if len as usize != core::mem::size_of::<i32>() {
        return Err(SysError::Os(super::EINVAL));
    }
    Ok(val)
}

/// 接続時の相手（`socketpair` では作成者自身）の pid（`SO_PEERCRED`）。pid は読み手の PID namespace へ
/// 変換された値。holder が「親 = ソケット対の作成者」を確かめるために使う（12.2・REPAIR-5）。
pub(crate) fn peer_pid(fd: BorrowedFd<'_>) -> Result<u32, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut cred = Ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = core::mem::size_of::<Ucred>() as u32;
    // SAFETY: `cred`・`len` はスタック上の初期化済みローカルで、入力の `len` は `cred` の確保サイズ（12）。
    // カーネルはそれを超えて書かない。`fd` は生存中の `BorrowedFd`。
    let rc = unsafe {
        getsockopt(
            fd.as_raw_fd(),
            consts::SOL_SOCKET,
            consts::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut len,
        )
    };
    if rc < 0 {
        return Err(last_error());
    }
    if len as usize != core::mem::size_of::<Ucred>() {
        return Err(SysError::Os(super::EINVAL));
    }
    u32::try_from(cred.pid).map_err(|_| SysError::Os(super::EINVAL))
}

/// 1 通の受信結果。
#[derive(Debug)]
pub(crate) struct Received {
    /// 受け取ったデータの長さ（0 は相手が閉じた EOF か長さ 0 のメッセージ）。
    pub len: usize,
    /// データが `buf` に収まらず切り詰められた（`MSG_TRUNC`）。
    pub data_truncated: bool,
    /// 制御データが収まらず fd が捨てられた（`MSG_CTRUNC`。3 本目以降・許可していない fd）。
    pub ctrl_truncated: bool,
    /// 受け取った fd（`SCM_RIGHTS`。`MAX_FDS` 以下）。drop で閉じる。
    pub fds: Vec<OwnedFd>,
}

/// 制御データのバイト列から `SCM_RIGHTS` の fd 番号を取り出す（純関数。境界はすべて checked）。
/// 形式違反（長さの矛盾）は `None`。他の level / type の cmsg は読み飛ばす。
fn parse_scm_rights(ctrl: &[u8]) -> Option<Vec<RawFd>> {
    let mut fds = Vec::new();
    let mut off = 0usize;
    while off < ctrl.len() {
        let hdr = ctrl.get(off..off.checked_add(CMSG_HDR_LEN)?)?;
        let len = usize::from_ne_bytes(hdr.get(0..8)?.try_into().ok()?);
        let level = i32::from_ne_bytes(hdr.get(8..12)?.try_into().ok()?);
        let kind = i32::from_ne_bytes(hdr.get(12..16)?.try_into().ok()?);
        if len < CMSG_HDR_LEN {
            return None;
        }
        let end = off.checked_add(len)?;
        let data = ctrl.get(off.checked_add(CMSG_HDR_LEN)?..end)?;
        if level == consts::SOL_SOCKET && kind == consts::SCM_RIGHTS {
            if data.len() % 4 != 0 {
                return None;
            }
            for c in data.as_chunks::<4>().0 {
                fds.push(i32::from_ne_bytes(*c));
            }
        }
        off = off.checked_add(cmsg_align(len))?;
    }
    Some(fds)
}

/// 1 通を待たずに受信する（`MSG_CMSG_CLOEXEC | MSG_DONTWAIT`）。通常は `wait_readable` の後に呼ぶ。
///
/// `max_fds` は受け取る fd の上限（0 から `MAX_FDS`）。制御バッファはその本数ちょうどで、超過分はカーネルが
/// 閉じて `ctrl_truncated` が立つ。待機中のメッセージが無ければ `Os(EAGAIN)`。
pub(crate) fn recv_with_fds(
    fd: BorrowedFd<'_>,
    buf: &mut [u8],
    max_fds: usize,
) -> Result<Received, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    if max_fds > MAX_FDS {
        return Err(SysError::Os(super::EINVAL));
    }
    let mut iov = IoVec {
        base: buf.as_mut_ptr().cast(),
        len: buf.len(),
    };
    let mut control = ControlBuf([0; CONTROL_CAP]);
    let ctl_len = if max_fds == 0 {
        0
    } else {
        cmsg_space(max_fds * 4)
    };
    let mut msg = MsgHdr {
        name: core::ptr::null_mut(),
        namelen: 0,
        iov: &raw mut iov,
        iovlen: 1,
        control: if ctl_len == 0 {
            core::ptr::null_mut()
        } else {
            control.0.as_mut_ptr().cast()
        },
        controllen: ctl_len,
        flags: 0,
    };
    // SAFETY: `msg` が指す `iov`（`buf` の `buf.len()` バイト・排他借用）と `control`（`ctl_len` ≤ `CONTROL_CAP`
    // バイト・8 バイト整列、0 のときは null）は書き込み可能で呼び出しの間生存する。カーネルは確保サイズを超えて
    // 書かず、受け取った fd 番号を制御バッファへ書く。`fd` は生存中の `BorrowedFd`。
    let n = unsafe {
        recvmsg(
            fd.as_raw_fd(),
            &raw mut msg,
            consts::MSG_CMSG_CLOEXEC | super::consts::MSG_DONTWAIT,
        )
    };
    let n = usize::try_from(n).map_err(|_| last_error())?;
    let ctl_used = msg.controllen.min(ctl_len);
    let parsed = control.0.get(..ctl_used).and_then(parse_scm_rights);
    let Some(raw_fds) = parsed else {
        // 形式違反は起こりえない（カーネルの出力）。拾えない fd 番号は所有できないため、エラーにするだけ。
        return Err(SysError::Os(super::EINVAL));
    };
    let fds = raw_fds
        .into_iter()
        // SAFETY: `SCM_RIGHTS` の fd は `recvmsg` がこの呼び出しで受信側に新規に割り当てたもので、他に所有者がいない。
        .map(|raw| unsafe { OwnedFd::from_raw_fd(raw) })
        .collect();
    Ok(Received {
        len: n.min(buf.len()),
        data_truncated: msg.flags & super::consts::MSG_TRUNC != 0,
        ctrl_truncated: msg.flags & consts::MSG_CTRUNC != 0,
        fds,
    })
}

/// 1 通を `SCM_RIGHTS` つきで送る（`MSG_NOSIGNAL`。`dontwait` なら `MSG_DONTWAIT` も）。fd は複製されて相手へ
/// 渡るだけで、呼び出し側の `fds` は閉じない（送った後に閉じるのは呼び出し側）。`fds` は `MAX_SEND_FDS` 本まで。
/// 相手が閉じていれば `Os(EPIPE)`（`SIGPIPE` は `MSG_NOSIGNAL` で抑止）。
pub(crate) fn send_with_fds(
    fd: BorrowedFd<'_>,
    data: &[u8],
    fds: &[BorrowedFd<'_>],
    dontwait: bool,
) -> Result<usize, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    if fds.len() > MAX_SEND_FDS {
        return Err(SysError::Os(super::EINVAL));
    }
    let mut control = SendControlBuf([0; cmsg_space(MAX_SEND_FDS * 4)]);
    let ctl_len = if fds.is_empty() {
        0
    } else {
        cmsg_space(fds.len() * 4)
    };
    if ctl_len > 0 {
        let invalid = SysError::Os(super::EINVAL);
        let mut bytes: Vec<u8> = Vec::with_capacity(ctl_len);
        bytes.extend_from_slice(&(CMSG_HDR_LEN + fds.len() * 4).to_ne_bytes());
        bytes.extend_from_slice(&consts::SOL_SOCKET.to_ne_bytes());
        bytes.extend_from_slice(&consts::SCM_RIGHTS.to_ne_bytes());
        for f in fds {
            bytes.extend_from_slice(&f.as_raw_fd().to_ne_bytes());
        }
        let dst = control.0.get_mut(..bytes.len()).ok_or(invalid)?;
        dst.copy_from_slice(&bytes);
    }
    let mut iov = IoVec {
        base: data.as_ptr().cast_mut().cast(),
        len: data.len(),
    };
    let msg = MsgHdr {
        name: core::ptr::null_mut(),
        namelen: 0,
        iov: &raw mut iov,
        iovlen: 1,
        control: if ctl_len == 0 {
            core::ptr::null_mut()
        } else {
            control.0.as_mut_ptr().cast()
        },
        controllen: ctl_len,
        flags: 0,
    };
    let mut flags = consts::MSG_NOSIGNAL;
    if dontwait {
        flags |= super::consts::MSG_DONTWAIT;
    }
    // SAFETY: `msg` が指す `iov`（`data` の `data.len()` バイト。`sendmsg(2)` は読むだけで書かない。`cast_mut` は
    // C の `void *` 型に合わせるためだけ）と `control`（`ctl_len` バイト・8 バイト整列、0 のときは null）は
    // 初期化済みで呼び出しの間生存する。制御データは上で組んだ `SCM_RIGHTS` 1 件で、`fds` は生存中の
    // `BorrowedFd` のため fd 番号は開いている。`fd` も生存中の `BorrowedFd`。
    let n = unsafe { sendmsg(fd.as_raw_fd(), &raw const msg, flags) };
    usize::try_from(n).map_err(|_| last_error())
}

/// 呼び出しスレッドを `fd` の namespace へ参加させる（`setns(2)`）。`nstype` は `CLONE_NEWUSER` / `CLONE_NEWNET`。
///
/// `CLONE_NEWUSER` は多スレッドのプロセスでは `EINVAL` になるため、holder は単一スレッドで呼ぶ。型違いの fd は
/// `EINVAL`、権限不足は `EPERM`。
pub(crate) fn join_namespace(fd: BorrowedFd<'_>, nstype: i32) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `fd` は生存中の `BorrowedFd`。`setns(2)` は呼び出しスレッドの namespace を変えるだけで、メモリを書かない。
    let rc = unsafe { setns(fd.as_raw_fd(), nstype) };
    if rc < 0 { Err(last_error()) } else { Ok(()) }
}

/// ポインタを取らない `prctl(option, arg2, 0, 0, 0)` の薄い入口（失敗は errno、成功は戻り値）。
fn prctl_value(option: i32, arg2: core::ffi::c_ulong) -> Result<i32, SysError> {
    // SAFETY: 可変長引数に `unsigned long` を 4 個渡す（`prctl(2)` は使わない引数を無視する）。呼び出し元の option は
    // `PR_SET_PDEATHSIG`・`PR_GET_DUMPABLE`・`PR_SET_NO_NEW_PRIVS` に限り、いずれもユーザーメモリを読み書きしない。
    let rc = unsafe {
        prctl(
            option,
            arg2,
            0 as core::ffi::c_ulong,
            0 as core::ffi::c_ulong,
            0 as core::ffi::c_ulong,
        )
    };
    if rc < 0 { Err(last_error()) } else { Ok(rc) }
}

/// 親の死亡時に `SIGKILL` を受ける設定（`PR_SET_PDEATHSIG`）。孤児化した holder を残さない（12.10・SUP-5）。
/// 注意: 「親」は fork / exec を呼んだ**スレッド**で、そのスレッドの終了でも届く。
pub(crate) fn set_pdeathsig_sigkill() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    prctl_value(
        consts::PR_SET_PDEATHSIG,
        consts::PR_SIGKILL as core::ffi::c_ulong,
    )
    .map(|_| ())
}

/// 現在の parent-death signal（`PR_GET_PDEATHSIG`。0 は未設定）。
pub(crate) fn get_pdeathsig() -> Result<i32, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut sig: i32 = 0;
    // SAFETY: `PR_GET_PDEATHSIG` は arg2 の `int *` へ 1 つだけ書く。`sig` はスタック上の書き込み可能な `int` で、
    // 呼び出しの間生存する。残りの引数は使われない。
    let rc = unsafe {
        prctl(
            consts::PR_GET_PDEATHSIG,
            (&raw mut sig) as core::ffi::c_ulong,
            0 as core::ffi::c_ulong,
            0 as core::ffi::c_ulong,
            0 as core::ffi::c_ulong,
        )
    };
    if rc < 0 { Err(last_error()) } else { Ok(sig) }
}

/// dumpable の現在値（`PR_GET_DUMPABLE`。1 が dumpable）。pasta が `/proc/<holder>/ns/*` を開ける前提
/// （12.2）を READY の前に自己確認するために使う。
pub(crate) fn get_dumpable() -> Result<i32, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    prctl_value(consts::PR_GET_DUMPABLE, 0)
}

/// 継承した fd 3 以上をすべて閉じる（`close_range(3, u32::MAX, 0)`）。dumpable な holder に親から継承した
/// fd が残ると、同じ uid が `/proc/<holder>/fd` 経由で触れてしまうため（SEC-1・NET-9）。失敗（`ENOSYS` を含む）は
/// 呼び出し側が起動拒否にする。stdin / stdout / stderr（0〜2）は閉じない。
pub(crate) fn close_inherited_fds() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `close_range(first, last, flags)` は整数引数のみを取りメモリを参照しない。fd 3 以上を閉じるだけで、
    // この関数の呼び出し時点で holder は他の fd を所有していない（呼び出しは起動直後の run の先頭）。
    let rc = unsafe {
        syscall(
            consts::SYS_CLOSE_RANGE,
            3 as core::ffi::c_ulong,
            u32::MAX as core::ffi::c_ulong,
            0 as core::ffi::c_ulong,
        )
    };
    if rc < 0 { Err(last_error()) } else { Ok(()) }
}

/// `PR_SET_NO_NEW_PRIVS` を 1 にする（不可逆）。
pub(crate) fn set_no_new_privs() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    prctl_value(consts::PR_SET_NO_NEW_PRIVS, 1).map(|_| ())
}

/// effective・permitted・inheritable をすべて空にする（`capset(2)`・`_LINUX_CAPABILITY_VERSION_3`・pid 0）。
/// ambient は permitted の部分集合のため同時に空になる。呼び出しスレッド（単一スレッドの holder）の資格情報だけに効く。
pub(crate) fn drop_all_capabilities() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut header = CapUserHeader {
        version: consts::LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapUserData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: `header`（8 バイト）と `data`（`_LINUX_CAPABILITY_VERSION_3` が要求する 2 要素・計 24 バイト）は
    // スタック上の初期化済みローカルで呼び出しの間生存する。`capset(2)` は `header` を（バージョン不一致時に
    // だけ）書き換えうるため `*mut` で渡し、`data` は読むだけ。pid 0 は呼び出しスレッド自身。
    let rc = unsafe {
        syscall(
            consts::SYS_CAPSET,
            (&raw mut header) as core::ffi::c_ulong,
            data.as_ptr() as core::ffi::c_ulong,
        )
    };
    if rc < 0 { Err(last_error()) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    fn cmsg_bytes(level: i32, kind: i32, payload: &[u8], len_override: Option<usize>) -> Vec<u8> {
        let len = len_override.unwrap_or(CMSG_HDR_LEN + payload.len());
        let mut v = Vec::new();
        v.extend_from_slice(&len.to_ne_bytes());
        v.extend_from_slice(&level.to_ne_bytes());
        v.extend_from_slice(&kind.to_ne_bytes());
        v.extend_from_slice(payload);
        while v.len() % 8 != 0 {
            v.push(0);
        }
        v
    }

    /// NET-9・REPAIR-2: `SCM_RIGHTS` 2 本を具体値で取り出す。
    #[test]
    fn parse_scm_rights_two_fds() {
        let mut p = 7i32.to_ne_bytes().to_vec();
        p.extend_from_slice(&9i32.to_ne_bytes());
        let ctrl = cmsg_bytes(1, 1, &p, None);
        assert_eq!(parse_scm_rights(&ctrl), Some(vec![7, 9]));
    }

    /// 他の level / type の cmsg は読み飛ばす。
    #[test]
    fn parse_scm_rights_skips_other_cmsg() {
        let mut ctrl = cmsg_bytes(1, 2, &[0; 12], None);
        ctrl.extend(cmsg_bytes(1, 1, &5i32.to_ne_bytes(), None));
        assert_eq!(parse_scm_rights(&ctrl), Some(vec![5]));
    }

    /// 長さの矛盾・fd 幅に満たないデータ・ヘッダー切れは拒否する（外部入力の境界。REPAIR-2）。
    #[test]
    fn parse_scm_rights_rejects_malformed() {
        assert_eq!(parse_scm_rights(&cmsg_bytes(1, 1, &[0; 8], Some(8))), None);
        assert_eq!(
            parse_scm_rights(&cmsg_bytes(1, 1, &[0; 8], Some(1000))),
            None
        );
        assert_eq!(parse_scm_rights(&cmsg_bytes(1, 1, &[0; 6], None)), None);
        assert_eq!(parse_scm_rights(&[0u8; 5]), None);
        assert_eq!(parse_scm_rights(&[]), Some(vec![]));
    }

    /// 制御バッファはちょうど 2 本分（24 バイト）。
    #[test]
    fn control_capacity_is_exactly_two_fds() {
        assert_eq!(CONTROL_CAP, 24);
        assert_eq!(cmsg_space(4), 24);
        assert_eq!(cmsg_space(8), 24);
    }

    /// socketpair の往復と fd 受け渡し（具体値）。範囲外の fd 本数は拒否し、上限 0 で受けると fd は閉じられる。
    #[test]
    fn socketpair_passes_two_fds_and_rejects_third() {
        let (a, b) = socketpair_seqpacket().expect("pair");
        assert_eq!(
            socket_type(a.as_fd()).expect("type"),
            consts::SOCK_SEQPACKET
        );
        let x = std::fs::File::open("/dev/null").expect("open");
        let y = std::fs::File::open("/dev/null").expect("open");
        let z = std::fs::File::open("/dev/null").expect("open");
        send_with_fds(a.as_fd(), b"hello", &[x.as_fd(), y.as_fd()], true).expect("send");
        let mut buf = [0u8; 16];
        let got = recv_with_fds(b.as_fd(), &mut buf, MAX_FDS).expect("recv");
        assert_eq!(got.len, 5);
        assert_eq!(buf.get(..5), Some(&b"hello"[..]));
        assert_eq!(got.fds.len(), 2);
        assert!(!got.ctrl_truncated);
        assert_eq!(
            send_with_fds(a.as_fd(), b"x", &[x.as_fd(); 5], true).unwrap_err(),
            SysError::Os(super::super::EINVAL)
        );
        // 3 本送ると 2 本だけ受かり、3 本目はカーネルが閉じて MSG_CTRUNC になる。
        send_with_fds(a.as_fd(), b"x", &[x.as_fd(), y.as_fd(), z.as_fd()], true).expect("send");
        let got = recv_with_fds(b.as_fd(), &mut buf, MAX_FDS).expect("recv");
        assert_eq!(got.fds.len(), 2);
        assert!(got.ctrl_truncated);
        drop(got);
        send_with_fds(a.as_fd(), b"hi", &[x.as_fd()], true).expect("send");
        let got = recv_with_fds(b.as_fd(), &mut buf, 0).expect("recv");
        assert_eq!(got.len, 2);
        assert!(got.ctrl_truncated);
        assert!(got.fds.is_empty());
        assert_eq!(
            recv_with_fds(b.as_fd(), &mut buf, 0).unwrap_err(),
            SysError::Os(super::super::EAGAIN)
        );
        assert_eq!(peer_pid(b.as_fd()).expect("peer"), std::process::id());
    }
}

/// 自前の宣言・定数・構造体の `libc` との機械照合（#1841・#1837・REPAIR-12。方式は `docs/design/ffi-libc-check.md`）。
///
/// 照合しないもの（`libc` に対応物が無い）: `CapUserHeader`・`CapUserData`・`LINUX_CAPABILITY_VERSION_3`
/// （大きさだけ上で固定）。`capset` は `syscall(SYS_CAPSET, ...)` 経由のため `SYS_CAPSET` を `libc::SYS_capset` と照合する。
#[cfg(all(
    test,
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod libc_abi {
    use super::{
        IoVec, MsgHdr, Ucred, consts, getsockopt, prctl, recvmsg, sendmsg, setns, socketpair,
        syscall,
    };
    use core::mem::{align_of, offset_of, size_of};

    const _: () = {
        assert!(consts::AF_UNIX == libc::AF_UNIX);
        assert!(consts::SOCK_SEQPACKET == libc::SOCK_SEQPACKET);
        assert!(consts::SOL_SOCKET == libc::SOL_SOCKET);
        assert!(consts::SO_TYPE == libc::SO_TYPE);
        assert!(consts::SO_PEERCRED == libc::SO_PEERCRED);
        assert!(consts::SCM_RIGHTS == libc::SCM_RIGHTS);
        assert!(consts::MSG_CTRUNC == libc::MSG_CTRUNC);
        assert!(consts::MSG_NOSIGNAL == libc::MSG_NOSIGNAL);
        assert!(consts::MSG_CMSG_CLOEXEC == libc::MSG_CMSG_CLOEXEC);
        assert!(consts::CLONE_NEWUSER == libc::CLONE_NEWUSER);
        assert!(consts::CLONE_NEWNET == libc::CLONE_NEWNET);
        assert!(consts::PR_SET_PDEATHSIG == libc::PR_SET_PDEATHSIG);
        assert!(consts::PR_GET_PDEATHSIG == libc::PR_GET_PDEATHSIG);
        assert!(consts::PR_GET_DUMPABLE == libc::PR_GET_DUMPABLE);
        assert!(consts::PR_SET_NO_NEW_PRIVS == libc::PR_SET_NO_NEW_PRIVS);
        assert!(consts::PR_SIGKILL == libc::SIGKILL);
        assert!(consts::ENOTSOCK == libc::ENOTSOCK);
        assert!(consts::EPIPE == libc::EPIPE);
        assert!(consts::SYS_CAPSET == libc::SYS_capset);
        assert!(consts::SYS_CLOSE_RANGE == libc::SYS_close_range);
    };

    const _: () = {
        assert!(size_of::<IoVec>() == size_of::<libc::iovec>());
        assert!(align_of::<IoVec>() == align_of::<libc::iovec>());
        assert!(offset_of!(IoVec, base) == offset_of!(libc::iovec, iov_base));
        assert!(offset_of!(IoVec, len) == offset_of!(libc::iovec, iov_len));

        assert!(size_of::<Ucred>() == size_of::<libc::ucred>());
        assert!(align_of::<Ucred>() == align_of::<libc::ucred>());
        assert!(offset_of!(Ucred, pid) == offset_of!(libc::ucred, pid));
        assert!(offset_of!(Ucred, uid) == offset_of!(libc::ucred, uid));
        assert!(offset_of!(Ucred, gid) == offset_of!(libc::ucred, gid));
    };

    // `MsgHdr`: gnu に限る（musl は `msg_iovlen`・`msg_controllen` を `int` / `socklen_t` と非公開パディングで持つ一方、
    // 自前はカーネルの `user_msghdr` に合わせた `size_t`。core の `seccomp_notify` と同じ扱い）。
    #[cfg(target_env = "gnu")]
    const _: () = {
        assert!(size_of::<MsgHdr>() == size_of::<libc::msghdr>());
        assert!(align_of::<MsgHdr>() == align_of::<libc::msghdr>());
        assert!(offset_of!(MsgHdr, name) == offset_of!(libc::msghdr, msg_name));
        assert!(offset_of!(MsgHdr, namelen) == offset_of!(libc::msghdr, msg_namelen));
        assert!(offset_of!(MsgHdr, iov) == offset_of!(libc::msghdr, msg_iov));
        assert!(offset_of!(MsgHdr, iovlen) == offset_of!(libc::msghdr, msg_iovlen));
        assert!(offset_of!(MsgHdr, control) == offset_of!(libc::msghdr, msg_control));
        assert!(offset_of!(MsgHdr, controllen) == offset_of!(libc::msghdr, msg_controllen));
        assert!(offset_of!(MsgHdr, flags) == offset_of!(libc::msghdr, msg_flags));
    };

    const _: unsafe extern "C" fn(
        libc::c_int,
        libc::c_int,
        libc::c_int,
        *mut libc::c_int,
    ) -> libc::c_int = socketpair;
    const _: unsafe extern "C" fn(
        libc::c_int,
        libc::c_int,
        libc::c_int,
        *mut libc::c_int,
    ) -> libc::c_int = libc::socketpair;
    // `sendmsg` / `recvmsg` の `msghdr` 引数は自前の `MsgHdr` と `libc::msghdr` で型が違うため、戻り値・他引数だけを
    // 揃えた関数型で照合する（`msghdr` の同一性は上の構造体照合が保証する）。
    const _: unsafe extern "C" fn(libc::c_int, *const MsgHdr, libc::c_int) -> libc::ssize_t =
        sendmsg;
    const _: unsafe extern "C" fn(libc::c_int, *const libc::msghdr, libc::c_int) -> libc::ssize_t =
        libc::sendmsg;
    const _: unsafe extern "C" fn(libc::c_int, *mut MsgHdr, libc::c_int) -> libc::ssize_t = recvmsg;
    const _: unsafe extern "C" fn(libc::c_int, *mut libc::msghdr, libc::c_int) -> libc::ssize_t =
        libc::recvmsg;
    const _: unsafe extern "C" fn(
        libc::c_int,
        libc::c_int,
        libc::c_int,
        *mut libc::c_void,
        *mut libc::socklen_t,
    ) -> libc::c_int = getsockopt;
    const _: unsafe extern "C" fn(
        libc::c_int,
        libc::c_int,
        libc::c_int,
        *mut libc::c_void,
        *mut libc::socklen_t,
    ) -> libc::c_int = libc::getsockopt;
    const _: unsafe extern "C" fn(libc::c_int, libc::c_int) -> libc::c_int = setns;
    const _: unsafe extern "C" fn(libc::c_int, libc::c_int) -> libc::c_int = libc::setns;
    const _: unsafe extern "C" fn(libc::c_int, ...) -> libc::c_int = prctl;
    const _: unsafe extern "C" fn(libc::c_int, ...) -> libc::c_int = libc::prctl;
    const _: unsafe extern "C" fn(libc::c_long, ...) -> libc::c_long = syscall;
    const _: unsafe extern "C" fn(libc::c_long, ...) -> libc::c_long = libc::syscall;
}
