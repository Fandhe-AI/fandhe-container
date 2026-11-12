//! netns holder（`crate::netns_holder`。NET-9・CORE-6・SEC-5・REPAIR-5・#3197）が使う syscall・FFI の薄いラッパー
//! （`crates/net` の `sys` モジュールの子。`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節）。
//!
//! # 呼び出し文脈
//! - supervisor 側の `NetnsHolderChannel`（`socketpair`・`SCM_RIGHTS` つき `sendmsg`・`recvmsg`）
//! - holder プロセス側の `run_netns_holder_main`（stdin のソケット種別・`SO_PEERCRED`・`recvmsg`・`setns(2)`・
//!   `prctl(2)`・`capset(2)`）。`SO_PEERCRED`・`recvmsg` は共通部品 `crate::netns_helper` 経由で
//!   netns-dial helper（`run_netns_dial_main`）からも呼ばれる（#4510）
//!
//! # 契約
//! - 親 `sys` と同じ（`unsafe fn` を公開しない・`SAFETY:` の明記・arch ごとの定数・戻り値 -1 は直後に errno を確保）
//! - 受け取った fd はすべて `OwnedFd` で所有する（拒否時は drop で閉じる）。制御メッセージの形式違反・負値の fd でも、
//!   読めた fd は閉じてから `EINVAL` を返す（#4498。位置を特定できない fd は閉じられない。`recv_with_fds` の「残余」）。受信上限は `CMSG_LEN` で切り（`cmsg_len`）、2 本分
//!   （`MAX_FDS`）なら 3 本目以降、1 本（`recv_one_fd`）なら 2 本目以降をカーネルが閉じて `MSG_CTRUNC` を立てる
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
    pub const SO_PROTOCOL: i32 = 38;
    pub const SO_DOMAIN: i32 = 39;
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
    pub const PR_SET_DUMPABLE: i32 = 4;
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
    pub const SO_PROTOCOL: i32 = 38;
    pub const SO_DOMAIN: i32 = 39;
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
    pub const PR_SET_DUMPABLE: i32 = 4;
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
    pub const SO_PROTOCOL: i32 = 0;
    pub const SO_DOMAIN: i32 = 0;
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
    pub const PR_SET_DUMPABLE: i32 = 0;
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
///
/// `len + 7` は検査しない。定数（小さい固定長）か、`len <= ctrl.len() <= CONTROL_CAP` を確認済みの値だけを渡す
/// （桁あふれしない）。カーネル由来の `cmsg_len` の解析では [`checked_cmsg_align`] を使う（#4521・SEC-1）。
const fn cmsg_align(len: usize) -> usize {
    (len + 7) & !7
}

/// `cmsg_align` の checked 版。外部入力（カーネルの `cmsg_len`）の次オフセット計算用（#4521・SEC-1・REPAIR-5）。
const fn checked_cmsg_align(len: usize) -> Option<usize> {
    match len.checked_add(7) {
        Some(v) => Some(v & !7),
        None => None,
    }
}

/// `CMSG_SPACE(data_len)`。
const fn cmsg_space(data_len: usize) -> usize {
    CMSG_HDR_LEN + cmsg_align(data_len)
}

/// `CMSG_LEN(data_len)`（整列の詰め物を含まない長さ）。
///
/// 受信側の制御バッファ長に `CMSG_SPACE` を渡すと、カーネルの `scm_max_fds`
/// （`(controllen - sizeof(cmsghdr)) / sizeof(int)`。v6.12 `net/core/scm.c:313`）は fd 1 本分の 24 バイトで 2 本と数え、
/// 2 本目を `MSG_CTRUNC` なしで受け取ってしまう。受信上限は `CMSG_LEN` で切る（0 本・2 本では値が変わらない）。
const fn cmsg_len(data_len: usize) -> usize {
    CMSG_HDR_LEN + data_len
}

/// 制御バッファの容量（`MAX_FDS` 本ちょうど。余裕を持たせると 3 本目以降が入ってしまう）。
const CONTROL_CAP: usize = cmsg_space(MAX_FDS * 4);

// 受信の `ctl_len`（`cmsg_len(max_fds * 4)`、`max_fds <= MAX_FDS`）が制御バッファに収まることを固定する。
// `recv_with_fds` の `control.0.get(..ctl_used)` が `None` にならない根拠（#4521）。
const _: () = assert!(cmsg_len(MAX_FDS * 4) <= CONTROL_CAP);

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
    getsockopt_int(fd, consts::SOL_SOCKET, consts::SO_TYPE)
}

/// ソケットのアドレスファミリ（`SO_DOMAIN`。`AF_INET` 等）。`netns_dial::verify` が IPv4 であることの照合に使う
/// （SEC-1・NET-3・#4478）。ソケットでなければ `Os(ENOTSOCK)`。
pub(crate) fn socket_domain(fd: BorrowedFd<'_>) -> Result<i32, SysError> {
    getsockopt_int(fd, consts::SOL_SOCKET, consts::SO_DOMAIN)
}

/// ソケットのプロトコル（`SO_PROTOCOL`。`IPPROTO_TCP` 等）。`SOCK_STREAM` でも SCTP 等がありうるため、
/// `netns_dial::verify` が TCP であることの照合に使う（SEC-1・NET-3・#4478）。ソケットでなければ `Os(ENOTSOCK)`。
pub(crate) fn socket_protocol(fd: BorrowedFd<'_>) -> Result<i32, SysError> {
    getsockopt_int(fd, consts::SOL_SOCKET, consts::SO_PROTOCOL)
}

/// `int` 値の `getsockopt(2)`（`SO_TYPE`・`SO_DOMAIN`・`SO_PROTOCOL` の共通部）。
fn getsockopt_int(fd: BorrowedFd<'_>, level: i32, opt: i32) -> Result<i32, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut val: i32 = 0;
    let mut len = core::mem::size_of::<i32>() as u32;
    // SAFETY: `val`・`len` はスタック上の初期化済みローカルで、入力の `len` は `val` の確保サイズ（4）。カーネルは
    // それを超えて書かない。`fd` は生存中の `BorrowedFd`。`level`・`opt` は本モジュールの定数で、いずれも
    // `int` を返すオプション。
    let rc = unsafe {
        getsockopt(
            fd.as_raw_fd(),
            level,
            opt,
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
    peer_cred(fd).map(|(pid, _)| pid)
}

/// 接続時の相手の (pid, uid)（`SO_PEERCRED`）。pid は読み手の PID namespace へ変換された値。
/// DNS ヘルパーの制御 UDS が、接続してきた相手の uid を照合する（PLUG-12・#3071）のにも使う。
pub(crate) fn peer_cred(fd: BorrowedFd<'_>) -> Result<(u32, u32), SysError> {
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
    let pid = u32::try_from(cred.pid).map_err(|_| SysError::Os(super::EINVAL))?;
    Ok((pid, cred.uid))
}

/// 1 通の受信結果。
#[derive(Debug)]
pub(crate) struct Received {
    /// 受け取ったデータの長さ（0 は相手が閉じた EOF か長さ 0 のメッセージ）。
    pub len: usize,
    /// データが `buf` に収まらず切り詰められた（`MSG_TRUNC`）。
    pub data_truncated: bool,
    /// 制御データが収まらず fd が捨てられた（`MSG_CTRUNC`。上限を超える本数・許可していない fd）。
    pub ctrl_truncated: bool,
    /// 受け取った fd（`SCM_RIGHTS`。`MAX_FDS` 以下）。drop で閉じる。
    pub fds: Vec<OwnedFd>,
}

/// 制御データの解析結果。形式違反があっても、そこまでに読めた fd 番号を失わない（#4498・SEC-1・REPAIR-5）。
#[derive(Debug, PartialEq, Eq)]
struct ScmRights {
    /// 形式違反を見つけた時点までに読めた `SCM_RIGHTS` の fd 番号（負値も含めてそのまま）。
    fds: Vec<RawFd>,
    /// 最初に見つけた形式違反（無ければ `None`）。
    malformed: Option<ScmMalformed>,
}

/// 制御データの形式違反の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScmMalformed {
    /// 残りが `cmsghdr`（16 バイト）に満たない。以降の位置を特定できない。
    HeaderTruncated,
    /// `cmsg_len` が 16 未満、またはバッファの終端を越える（桁あふれを含む）。以降の位置を特定できない。
    LengthMismatch,
    /// `SCM_RIGHTS` のデータ長が 4 の倍数でない（先頭の完全な 4 バイトは fd として読む）。
    DataNotFdAligned,
}

/// 制御データのバイト列から `SCM_RIGHTS` の fd 番号を取り出す（純関数。境界はすべて checked）。
/// 形式違反は `malformed` に記録して止まり、それまでに読めた fd 番号は `fds` に残す。他の level / type の cmsg は読み飛ばす。
fn parse_scm_rights(ctrl: &[u8]) -> ScmRights {
    let mut fds = Vec::new();
    let mut off = 0usize;
    let malformed = loop {
        if off >= ctrl.len() {
            break None;
        }
        let Some(hdr) = off.checked_add(CMSG_HDR_LEN).and_then(|e| ctrl.get(off..e)) else {
            break Some(ScmMalformed::HeaderTruncated);
        };
        let fields = (
            hdr.get(0..8).and_then(|b| <[u8; 8]>::try_from(b).ok()),
            hdr.get(8..12).and_then(|b| <[u8; 4]>::try_from(b).ok()),
            hdr.get(12..16).and_then(|b| <[u8; 4]>::try_from(b).ok()),
        );
        let (Some(len_b), Some(lvl_b), Some(kind_b)) = fields else {
            break Some(ScmMalformed::HeaderTruncated);
        };
        let len = usize::from_ne_bytes(len_b);
        let level = i32::from_ne_bytes(lvl_b);
        let kind = i32::from_ne_bytes(kind_b);
        if len < CMSG_HDR_LEN {
            break Some(ScmMalformed::LengthMismatch);
        }
        let Some(data) = off
            .checked_add(len)
            .and_then(|end| ctrl.get(off.checked_add(CMSG_HDR_LEN)?..end))
        else {
            break Some(ScmMalformed::LengthMismatch);
        };
        let mut bad = None;
        if level == consts::SOL_SOCKET && kind == consts::SCM_RIGHTS {
            // データ長が 4 の倍数でなくても、ヘッダーの範囲は収まっているので完全な 4 バイトの塊は読む。
            for c in data.as_chunks::<4>().0 {
                fds.push(i32::from_ne_bytes(*c));
            }
            if data.len() % 4 != 0 {
                bad = Some(ScmMalformed::DataNotFdAligned);
            }
        }
        if bad.is_some() {
            break bad;
        }
        // `len` は直前に `off + len <= ctrl.len()` を確かめ済みで桁あふれしないが、外部入力のため checked で進める（#4521）。
        match checked_cmsg_align(len).and_then(|a| off.checked_add(a)) {
            Some(next) => off = next,
            None => break Some(ScmMalformed::LengthMismatch),
        }
    };
    ScmRights { fds, malformed }
}

/// `fd` 番号の分類結果。`OwnedFd` にできる値（0 以上）と、捨てた不正値の件数。
#[derive(Debug, PartialEq, Eq)]
struct ValidFds {
    fds: Vec<RawFd>,
    invalid_count: usize,
}

/// fd 番号を、`OwnedFd` にできる値（0 以上）と不正値（負値）に分ける（純関数）。負値は `from_raw_fd` へ渡さない。
fn split_valid_fds(raw: &[RawFd]) -> ValidFds {
    let fds: Vec<RawFd> = raw.iter().copied().filter(|fd| *fd >= 0).collect();
    ValidFds {
        invalid_count: raw.len() - fds.len(),
        fds,
    }
}

/// 解析結果の fd を所有し、形式違反・不正値があれば閉じてから `Os(EINVAL)` を返す（#4498・SEC-1・REPAIR-5）。
/// `SCM_RIGHTS` の受信経路で `OwnedFd::from_raw_fd` を呼ぶ唯一の箇所。`recv_with_fds` から呼ばれる。
///
/// # Safety
/// - `parsed.fds` の 0 以上の番号は、呼び出し時点で開いている fd で、他に所有者がおらず、呼び出し側が所有をこの関数へ
///   譲ったもの。呼び出し後にその番号を使わない・閉じない。
/// - 0 以上の番号は互いに重複しない（重複すると 2 重 close になる）。
/// - 成功時も、形式違反で閉じて `EINVAL` を返す失敗時も、契約は同じ。
/// - 負値は契約の対象外（本関数が除いて数えるだけで `from_raw_fd` へ渡さない）。
///
/// private のまま置き、`unsafe fn` を `sys` の外へ公開しない（#4521・SEC-1・REPAIR-5）。
unsafe fn adopt_scm_rights(parsed: ScmRights) -> Result<Vec<OwnedFd>, SysError> {
    let valid = split_valid_fds(&parsed.fds);
    let owned: Vec<OwnedFd> = valid
        .fds
        .into_iter()
        // SAFETY: 0 以上であることは `split_valid_fds` で検査済み。開いている・所有者が他にいない・重複しないことは
        // 本関数の `# Safety` の契約で呼び出し側が保証する。
        .map(|raw| unsafe { OwnedFd::from_raw_fd(raw) })
        .collect();
    if parsed.malformed.is_some() || valid.invalid_count > 0 {
        drop(owned);
        return Err(SysError::Os(super::EINVAL));
    }
    Ok(owned)
}

/// 1 通を待たずに受信する（`MSG_CMSG_CLOEXEC | MSG_DONTWAIT`）。通常は `wait_readable` の後に呼ぶ。
///
/// `max_fds` は受け取る fd の上限（0 から `MAX_FDS`）。制御バッファ長は `CMSG_LEN` で切るため（[`cmsg_len`]）
/// その本数ちょうどで、超過分はカーネルが閉じて `ctrl_truncated` が立つ。待機中のメッセージが無ければ `Os(EAGAIN)`。
///
/// 制御メッセージの形式違反・負値の fd は `Os(EINVAL)` だが、読めた fd は閉じてから返す（#4498・SEC-1・REPAIR-5）。
///
/// # 前提（受信ソケット）
/// 受信ソケットで `SCM_RIGHTS` 以外に fd を運ぶ cmsg（例: `SO_PASSPIDFD` で届く `SCM_PIDFD`）を有効にしない。
/// `parse_scm_rights` は `SCM_RIGHTS` 以外を読み飛ばすため、その fd は所有されず閉じられないまま漏れる。
/// 有効にする場合は `parse_scm_rights`（解析）と `adopt_scm_rights`（所有と回収）も同じ変更で直し、その fd も閉じる。
/// `SO_PASSCRED` の `SCM_CREDENTIALS` は fd を運ばないので対象外だが、制御バッファは `cmsg_len` で切るため
/// cmsg を足すと寸法の前提も変わる。現状 net crate はこれらのオプションを有効にしていない（SEC-1・REPAIR-5・#4531）。
/// `SO_PASSPIDFD`・`SO_PASSRIGHTS`・`SO_PASSSEC` が `src/` に現れないことは `tests/recv_cmsg_options_absent.rs` が確かめる（#4544）。
///
/// # 残余
/// `cmsg_len` が壊れている（16 未満・終端越え・ヘッダー切れ）と、以降の cmsg の位置と fd 番号を特定できない。
/// 無関係な fd を誤って閉じないよう推測では閉じないため、その分の fd は漏れうる。制御データの切り出しに失敗した
/// 場合も同じ。カーネルの出力では通常起こらない。同型の supervisor 側は #2717 で追う。
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
        cmsg_len(max_fds * 4)
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
    debug_assert!(ctl_used <= CONTROL_CAP);
    let Some(ctrl) = control.0.get(..ctl_used) else {
        // 切り出せないと fd 番号を読めない（「残余」）。`max_fds <= MAX_FDS` を検査済みで
        // `ctl_used <= ctl_len <= cmsg_len(MAX_FDS * 4) <= CONTROL_CAP`（上の const assert）のため通常は起こらない。
        return Err(SysError::Os(super::EINVAL));
    };
    // 形式違反・負値でも、読めた fd は `adopt_scm_rights` が所有して閉じてから `EINVAL` を返す（#4498）。
    let parsed = parse_scm_rights(ctrl);
    // SAFETY: `recvmsg` は成功済み。`MSG_CMSG_CLOEXEC` つきで受けた `SCM_RIGHTS` の fd は、カーネルがこの呼び出しで受信
    // プロセスに新規に割り当てたもので、他に所有者がおらず互いに重複しない。`control` は 0 初期化済みで `ctrl` は
    // カーネルが書いた範囲（`controllen` と `ctl_len` の小さい方）に切ってあるため、`parse_scm_rights` が読む番号は
    // カーネルが書いた値だけ。以降 `ctrl` 由来の番号は他で使わず、所有は戻り値か失敗時の drop へ移る。
    let fds = unsafe { adopt_scm_rights(parsed) }?;
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

/// 接続済みソケットの fd を 1 本だけ送る入口（`netns-dial` helper の応答。SEC-1・NET-3・#4478）。
/// 契約は [`send_with_fds`] と同じ。
pub(crate) fn send_one_fd(
    fd: BorrowedFd<'_>,
    data: &[u8],
    one: BorrowedFd<'_>,
    dontwait: bool,
) -> Result<usize, SysError> {
    send_with_fds(fd, data, &[one], dontwait)
}

/// fd を最大 1 本だけ受ける入口（`netns-dial` の親側。SEC-1・NET-3・#4478）。制御バッファは `CMSG_LEN(4)` で、
/// 2 本目以降はカーネルが閉じて `ctrl_truncated` が立つ。本数が 1 本ちょうどか・`ctrl_truncated` が偽かの検査は
/// `netns_dial::channel`（#4480）が行う（0 本の応答もここでは `Ok` で返る）。
pub(crate) fn recv_one_fd(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Result<Received, SysError> {
    recv_with_fds(fd, buf, 1)
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
    // `PR_SET_PDEATHSIG`・`PR_GET_DUMPABLE`・`PR_SET_DUMPABLE`・`PR_SET_NO_NEW_PRIVS` に限り、いずれもユーザーメモリを読み書きしない。
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

/// dumpable を 0（non-dumpable）にする（`PR_SET_DUMPABLE`）。`netns-dial` helper が起動直後と参加後に同じ uid からの
/// `/proc/<pid>/{mem,fd,ns}` 経由の観測・ptrace を塞ぐために使う（SEC-1・CRI-6・#4479）。値は整数のみ渡す。
pub(crate) fn set_non_dumpable() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    prctl_value(consts::PR_SET_DUMPABLE, 0).map(|_| ())
}

/// 継承した fd 3 以上をすべて閉じる（`close_range(3, u32::MAX, 0)`）。dumpable な間に親から継承した fd が
/// 残ると、同じ uid が `/proc/<pid>/fd` 経由で触れてしまうため（SEC-1・NET-9・CRI-6）。呼び出し元は
/// `netns_holder::holder::run`（先頭）と `netns_dial::helper::run`（要求の受信前）の 2 つ。失敗（`ENOSYS` を含む）は
/// 呼び出し側が起動拒否にする。stdin / stdout / stderr（0〜2）は閉じない。
pub(crate) fn close_inherited_fds() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `close_range(first, last, flags)` は整数引数のみを取りメモリを参照しない。fd 3 以上を閉じるだけで、
    // 呼び出し元は `netns_holder::holder::run` の先頭と、`netns_dial::helper::run` の stdin・peer の確認の後かつ
    // 要求（SCM_RIGHTS の fd）の受信より前の 2 か所で、どちらも閉じる範囲（fd 3 以上）に自分が所有する fd を持たない
    // （fd 0〜2 は範囲外）。新しい呼び出し元を足すときは、同じ不変条件が成り立つ時点で呼ぶこと。
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

    fn fd_bytes(fds: &[i32]) -> Vec<u8> {
        fds.iter().flat_map(|f| f.to_ne_bytes()).collect()
    }

    fn rights(fds: &[i32], malformed: Option<ScmMalformed>) -> ScmRights {
        ScmRights {
            fds: fds.to_vec(),
            malformed,
        }
    }

    /// NET-9・REPAIR-2: `SCM_RIGHTS` 2 本を具体値で取り出す。
    #[test]
    fn parse_scm_rights_two_fds() {
        let ctrl = cmsg_bytes(1, 1, &fd_bytes(&[7, 9]), None);
        assert_eq!(parse_scm_rights(&ctrl), rights(&[7, 9], None));
    }

    /// 他の level / type の cmsg は読み飛ばす。
    #[test]
    fn parse_scm_rights_skips_other_cmsg() {
        let mut ctrl = cmsg_bytes(1, 2, &[0; 12], None);
        ctrl.extend(cmsg_bytes(1, 1, &5i32.to_ne_bytes(), None));
        assert_eq!(parse_scm_rights(&ctrl), rights(&[5], None));
    }

    /// SEC-1・REPAIR-5・#4498: 形式違反でも、そこまでに読めた fd 番号と違反の種別を具体値で返す。
    #[test]
    fn sec1_repair5_4498_parse_reports_fds_read_before_malformed() {
        use ScmMalformed::*;
        assert_eq!(parse_scm_rights(&[]), rights(&[], None));
        assert_eq!(
            parse_scm_rights(&[0u8; 5]),
            rights(&[], Some(HeaderTruncated))
        );
        let ok7 = cmsg_bytes(1, 1, &fd_bytes(&[7]), None);
        let mut tail = ok7.clone();
        tail.extend_from_slice(&[0u8; 5]);
        assert_eq!(parse_scm_rights(&tail), rights(&[7], Some(HeaderTruncated)));
        assert_eq!(
            parse_scm_rights(&cmsg_bytes(1, 1, &[0; 8], Some(8))),
            rights(&[], Some(LengthMismatch))
        );
        assert_eq!(
            parse_scm_rights(&cmsg_bytes(1, 1, &[0; 8], Some(1000))),
            rights(&[], Some(LengthMismatch))
        );
        let mut tail = ok7.clone();
        tail.extend(cmsg_bytes(1, 1, &[0; 8], Some(1000)));
        assert_eq!(parse_scm_rights(&tail), rights(&[7], Some(LengthMismatch)));
        let mut six = fd_bytes(&[7]);
        six.extend_from_slice(&[0, 0]);
        assert_eq!(
            parse_scm_rights(&cmsg_bytes(1, 1, &six, None)),
            rights(&[7], Some(DataNotFdAligned))
        );
        assert_eq!(
            parse_scm_rights(&cmsg_bytes(1, 1, &[0; 3], None)),
            rights(&[], Some(DataNotFdAligned))
        );
        assert_eq!(
            parse_scm_rights(&cmsg_bytes(1, 1, &fd_bytes(&[-1, 7]), None)),
            rights(&[-1, 7], None)
        );
    }

    /// SEC-1・#4498: 負値は `OwnedFd` にできる値から除かれる（`from_raw_fd` へ渡らない）。
    #[test]
    fn sec1_repair5_4498_split_valid_fds_drops_negative() {
        assert_eq!(
            split_valid_fds(&[3, -1, 4, i32::MIN]),
            ValidFds {
                fds: vec![3, 4],
                invalid_count: 2
            }
        );
        assert_eq!(
            split_valid_fds(&[0, 5]),
            ValidFds {
                fds: vec![0, 5],
                invalid_count: 0
            }
        );
        assert_eq!(
            split_valid_fds(&[]),
            ValidFds {
                fds: vec![],
                invalid_count: 0
            }
        );
    }

    /// 試験自身の socketpair の片端の所有を放棄した番号と、その相手端を返す。相手端の EOF が閉鎖の観測になる。
    fn abandoned_end() -> (OwnedFd, RawFd) {
        use std::os::fd::IntoRawFd as _;
        let (a, b) = socketpair_seqpacket().expect("pair");
        (a, b.into_raw_fd())
    }

    fn peer_state(a: &OwnedFd) -> Result<usize, SysError> {
        let mut buf = [0u8; 4];
        recv_with_fds(a.as_fd(), &mut buf, 0).map(|r| r.len)
    }

    /// SEC-1・REPAIR-5・#4498: 形式違反・不正値・非整列でも読めた fd は閉じて `EINVAL`。正常なら所有が移る。
    #[test]
    fn sec1_repair5_4498_adopt_closes_fds_on_malformed_or_invalid() {
        let einval = Err(SysError::Os(super::super::EINVAL));
        let eagain = Err(SysError::Os(super::super::EAGAIN));

        // 形式違反（後続の cmsg_len が壊れている）。
        let (a, raw) = abandoned_end();
        assert_eq!(peer_state(&a), eagain);
        let mut ctrl = cmsg_bytes(1, 1, &fd_bytes(&[raw]), None);
        ctrl.extend(cmsg_bytes(1, 1, &[0; 8], Some(1000)));
        // SAFETY: `abandoned_end` が `into_raw_fd` で所有を放棄した、この試験の番号 `raw` だけを渡す（重複なし・以後未使用）。
        let r = unsafe { adopt_scm_rights(parse_scm_rights(&ctrl)) };
        assert!(matches!(r, Err(e) if Err::<usize, _>(e) == einval));
        assert_eq!(peer_state(&a), Ok(0));

        // データ長が 4 の倍数でない。
        let (a, raw) = abandoned_end();
        let mut p = fd_bytes(&[raw]);
        p.extend_from_slice(&[0, 0]);
        let ctrl = cmsg_bytes(1, 1, &p, None);
        // SAFETY: 所有を放棄した `raw` だけを渡す（重複なし・以後未使用）。
        let r = unsafe { adopt_scm_rights(parse_scm_rights(&ctrl)) };
        assert!(r.is_err());
        assert_eq!(peer_state(&a), Ok(0));

        // 負値の混入（構造は正常）。panic せず、有効な方は閉じる。
        let (a, raw) = abandoned_end();
        let ctrl = cmsg_bytes(1, 1, &fd_bytes(&[-1, raw]), None);
        // SAFETY: 0 以上は所有を放棄した `raw` だけ（負値は関数が除く）。重複なし・以後未使用。
        let r = unsafe { adopt_scm_rights(parse_scm_rights(&ctrl)) };
        assert!(r.is_err());
        assert_eq!(peer_state(&a), Ok(0));

        // 正常: 所有が移り、drop するまで閉じない。
        let (a, raw) = abandoned_end();
        let ctrl = cmsg_bytes(1, 1, &fd_bytes(&[raw]), None);
        // SAFETY: 所有を放棄した `raw` だけを渡す（重複なし・以後未使用）。
        let owned = unsafe { adopt_scm_rights(parse_scm_rights(&ctrl)) }.expect("adopt");
        assert_eq!(owned.len(), 1);
        assert_eq!(peer_state(&a), eagain);
        drop(owned);
        assert_eq!(peer_state(&a), Ok(0));
    }

    /// 制御バッファはちょうど 2 本分（24 バイト）。
    #[test]
    fn control_capacity_is_exactly_two_fds() {
        assert_eq!(CONTROL_CAP, 24);
        assert_eq!(cmsg_space(4), 24);
        assert_eq!(cmsg_space(8), 24);
        // 受信上限の制御長は `CMSG_LEN`（0 本・2 本は `CMSG_SPACE` と同値、1 本は 20）。
        assert_eq!(cmsg_len(0), 16);
        assert_eq!(cmsg_len(4), 20);
        assert_eq!(cmsg_len(8), 24);
        // 受信の制御長は常にバッファに収まる（`get(..ctl_used)` が `None` にならない前提。#4521）。
        for n in 0..=MAX_FDS {
            assert!(cmsg_len(n * 4) <= CONTROL_CAP, "n={n}");
        }
    }

    /// SEC-1・REPAIR-5・#4521: checked 版の整列は桁あふれで `None`、通常値は `cmsg_align` と同じ。
    #[test]
    fn sec1_repair5_4521_checked_cmsg_align_and_huge_len() {
        assert_eq!(checked_cmsg_align(usize::MAX), None);
        assert_eq!(checked_cmsg_align(usize::MAX - 7), Some(usize::MAX - 7));
        assert_eq!(checked_cmsg_align(20), Some(24));
        assert_eq!(checked_cmsg_align(20), Some(cmsg_align(20)));
        // 巨大な `cmsg_len` は panic せず形式違反（`LengthMismatch`）になる。
        assert_eq!(
            parse_scm_rights(&cmsg_bytes(1, 1, &[0; 8], Some(usize::MAX))),
            rights(&[], Some(ScmMalformed::LengthMismatch))
        );
    }

    /// SEC-1・REPAIR-5・#4521: 3 本送って 2 本受けると、3 本目は受信側に残らずカーネルが閉じる（相手端の EOF で観測）。
    #[test]
    fn sec1_repair5_4521_recv_with_fds_closes_third_fd_on_ctrunc() {
        let (a, b) = socketpair_seqpacket().expect("pair");
        let x = std::fs::File::open("/dev/null").expect("open");
        let (obs2, sent2) = socketpair_seqpacket().expect("pair");
        let (obs3, sent3) = socketpair_seqpacket().expect("pair");
        send_with_fds(
            a.as_fd(),
            b"x",
            &[x.as_fd(), sent2.as_fd(), sent3.as_fd()],
            true,
        )
        .expect("send");
        drop(sent2);
        drop(sent3);
        // 対照: 送信中の参照が端を開いたままにしている。
        let eagain = Err(SysError::Os(super::super::EAGAIN));
        assert_eq!(peer_state(&obs2), eagain);
        assert_eq!(peer_state(&obs3), eagain);
        let mut buf = [0u8; 4];
        let got = recv_with_fds(b.as_fd(), &mut buf, MAX_FDS).expect("recv");
        assert_eq!((got.len, got.ctrl_truncated, got.fds.len()), (1, true, 2));
        // 3 本目はカーネルが閉じた。2 本目は `got` が所有しているので開いたまま。
        assert_eq!(peer_state(&obs3), Ok(0));
        assert_eq!(peer_state(&obs2), eagain);
        drop(got);
        assert_eq!(peer_state(&obs2), Ok(0));
    }

    /// SEC-1・NET-3・#4478: fd 1 本の送受信。1 本はそのまま受け、2 本送られたら 2 本目は閉じられて `MSG_CTRUNC`。
    #[test]
    fn sec1_net3_4478_recv_one_fd_accepts_one_and_truncates_second() {
        let (a, b) = socketpair_seqpacket().expect("pair");
        let x = std::fs::File::open("/dev/null").expect("open");
        let y = std::fs::File::open("/dev/null").expect("open");
        send_one_fd(a.as_fd(), b"one", x.as_fd(), true).expect("send");
        let mut buf = [0u8; 16];
        let got = recv_one_fd(b.as_fd(), &mut buf).expect("recv");
        assert_eq!((got.len, got.ctrl_truncated, got.fds.len()), (3, false, 1));
        send_with_fds(a.as_fd(), b"two", &[x.as_fd(), y.as_fd()], true).expect("send");
        let got = recv_one_fd(b.as_fd(), &mut buf).expect("recv");
        assert_eq!((got.len, got.ctrl_truncated, got.fds.len()), (3, true, 1));
    }

    /// SEC-1・NET-3・#4478: ドメインとプロトコル（TCP は (2, 6)、UDP は (2, 17)、AF_UNIX は (1, 0)）。
    #[test]
    fn sec1_net3_4478_socket_domain_and_protocol_values() {
        let t = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        assert_eq!(socket_domain(t.as_fd()), Ok(2));
        assert_eq!(socket_protocol(t.as_fd()), Ok(6));
        let u = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        assert_eq!(socket_domain(u.as_fd()), Ok(2));
        assert_eq!(socket_protocol(u.as_fd()), Ok(17));
        let (a, _b) = socketpair_seqpacket().expect("pair");
        assert_eq!(socket_domain(a.as_fd()), Ok(1));
        assert_eq!(socket_protocol(a.as_fd()), Ok(0));
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
        assert_eq!(
            peer_cred(b.as_fd()).expect("peer cred"),
            (std::process::id(), super::super::effective_uid())
        );
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
        assert!(consts::SO_PROTOCOL == libc::SO_PROTOCOL);
        assert!(consts::SO_DOMAIN == libc::SO_DOMAIN);
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
        assert!(consts::PR_SET_DUMPABLE == libc::PR_SET_DUMPABLE);
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
