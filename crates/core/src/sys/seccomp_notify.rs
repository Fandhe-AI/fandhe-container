//! seccomp の listener fd の取得と、UDS（`SOCK_SEQPACKET`）の `SCM_RIGHTS` での受け渡しの薄いラッパー
//! （SEC-4・TASK-41 追補・#2024。`unsafe` 事前承認の範囲の `sys` 子モジュール）。
//!
//! # 役割と呼び出し文脈
//!
//! `crate::exec::seccomp_listener` が、コンテナの PID 1（または exec の worker）で
//! `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER)` を呼んで listener fd を得て
//! （[`seccomp_set_filter_new_listener`]）、起動側（supervisor 側のプロセス C）へ socketpair で渡す
//! （[`send_fd_with_token`] / [`recv_fd_with_creds`]）ために使う。検証の方針（資格情報・fd の種別・
//! fail-closed）は呼び出し側の `exec/seccomp_listener.rs` が持ち、本モジュールは syscall の薄い安全 API だけを公開する。
//!
//! # 一次情報（Linux v6.12 `kernel/seccomp.c`。2026-10-19 に確認）
//!
//! - `NEW_LISTENER` は BPF の内容（`SECCOMP_RET_USER_NOTIF` を返すか）を調べない。`init_listener` が無条件に
//!   通知用の状態を作る。通知が生じるのは filter が `USER_NOTIF` を返したときだけ
//! - listener fd は `get_unused_fd_flags(O_CLOEXEC)` で確保され、syscall の戻り値がその fd 番号
//! - 祖先の filter が既に listener を持つ場合は `EBUSY`（`has_duplicate_listener`）
//! - `SO_PASSCRED` が受信側にあると、送信側が `SCM_CREDENTIALS` を付けなくても、カーネルが送信側の
//!   資格情報（pid は受信側の PID namespace へ変換される）を付ける
//!
//! `SO_PEERCRED` は socketpair では作成者（呼び出し元自身）を両端で返し検証の意味が無いため使わない。

use super::{ArchSysNo, EINVAL, SockFprog, SysError, consts, fcntl, last_error, syscall};
use crate::seccomp::SeccompProgram;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};

// include/uapi/linux/seccomp.h の `SECCOMP_SET_MODE_FILTER`（1）と `SECCOMP_FILTER_FLAG_NEW_LISTENER`（1UL << 3）。
const SECCOMP_SET_MODE_FILTER: u64 = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: u64 = 1 << 3;

// `seccomp(2)` の番号。arch/x86/entry/syscalls/syscall_64.tbl の 317、include/uapi/asm-generic/unistd.h の 277（aarch64）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const SYS_SECCOMP: ArchSysNo = ArchSysNo::new(317);
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
const SYS_SECCOMP: ArchSysNo = ArchSysNo::new(277);
#[cfg(not(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
const SYS_SECCOMP: ArchSysNo = ArchSysNo::UNSUPPORTED;

// include/linux/net.h の `SOCK_SEQPACKET`（5）、include/uapi/asm-generic/socket.h の `SO_PASSCRED`（16）、
// include/linux/socket.h の `SCM_RIGHTS`（1）・`SCM_CREDENTIALS`（2）・`MSG_*`。x86_64 / aarch64 は asm-generic の値を
// 上書きしない（mips・sparc・alpha・parisc は異なるが対応外 arch。ラッパーは `SUPPORTED` で拒否する）。
const SOCK_SEQPACKET: i32 = 5;
const SO_PASSCRED: i32 = 16;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;
const MSG_CTRUNC: i32 = 0x08;
const MSG_TRUNC: i32 = 0x20;
const MSG_DONTWAIT: i32 = 0x40;
const MSG_NOSIGNAL: i32 = 0x4000;
const MSG_CMSG_CLOEXEC: i32 = 0x4000_0000;

/// 受信で受け取る fd の上限（これを超える分はカーネルが `MSG_CTRUNC` で切り詰める）。
pub(crate) const MAX_RECV_FDS: usize = 4;
/// 受信する本文の最大バイト数。
const MAX_PAYLOAD: usize = 8;

/// `struct iovec`（16 バイト）。
#[repr(C)]
struct IoVec {
    base: *mut core::ffi::c_void,
    len: usize,
}

/// `struct msghdr`（LP64 で 56 バイト）。
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

/// `struct cmsghdr`（LP64 で 16 バイト）。
#[repr(C)]
struct CmsgHdr {
    len: usize,
    level: i32,
    kind: i32,
}

/// `struct ucred`（12 バイト）。`SCM_CREDENTIALS` の本体。pid は受信側の PID namespace で見た値。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct Ucred {
    pub(crate) pid: i32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

const CMSG_HDR_LEN: usize = core::mem::size_of::<CmsgHdr>();
const UCRED_LEN: usize = core::mem::size_of::<Ucred>();

/// `CMSG_ALIGN`（`size_t` の境界へ切り上げ）。
const fn cmsg_align(len: usize) -> usize {
    (len + 7) & !7
}
/// `CMSG_SPACE(data_len)`。
const fn cmsg_space(data_len: usize) -> usize {
    CMSG_HDR_LEN + cmsg_align(data_len)
}

/// 制御バッファの容量。`SCM_RIGHTS`（`MAX_RECV_FDS` 本）＋ `SCM_CREDENTIALS` に余裕を足した固定長。
const CONTROL_CAP: usize = 128;
const _: () = assert!(cmsg_space(MAX_RECV_FDS * 4) + cmsg_space(UCRED_LEN) <= CONTROL_CAP);

/// `cmsghdr` の整列を満たす固定長の制御バッファ。
#[repr(C, align(8))]
struct ControlBuf([u8; CONTROL_CAP]);

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: `int socketpair(int domain, int type, int protocol, int sv[2])`。
    fn socketpair(domain: i32, ty: i32, protocol: i32, sv: *mut i32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)`。
    fn sendmsg(fd: i32, msg: *const MsgHdr, flags: i32) -> isize;
    // SAFETY（宣言そのものの妥当性）: `ssize_t recvmsg(int fd, struct msghdr *msg, int flags)`。
    fn recvmsg(fd: i32, msg: *mut MsgHdr, flags: i32) -> isize;
    // SAFETY（宣言そのものの妥当性）: `int setsockopt(int fd, int level, int optname, const void *optval,
    // socklen_t optlen)`（`socklen_t` は u32）。
    fn setsockopt(fd: i32, level: i32, name: i32, val: *const core::ffi::c_void, len: u32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `ssize_t recv(int fd, void *buf, size_t len, int flags)`。
    fn recv(fd: i32, buf: *mut core::ffi::c_void, len: usize, flags: i32) -> isize;
}

/// 呼び出しスレッドへ filter を追加し、同時に listener fd を得る（`seccomp(2)` の
/// `SECCOMP_SET_MODE_FILTER` + `SECCOMP_FILTER_FLAG_NEW_LISTENER`。Linux 5.0 以降）。
///
/// `prctl` はフラグを渡せないため `syscall(2)` 経由。適用は不可逆で呼び出しスレッドにのみ効く。
/// `NO_NEW_PRIVS` の事前確認・単一スレッドの確認は呼び出し側の契約。戻り値の fd は `O_CLOEXEC`。
/// 祖先が既に listener を持てば `Os(EBUSY)`。
pub(crate) fn seccomp_set_filter_new_listener(
    program: &SeccompProgram,
) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let nr = SYS_SECCOMP.get()?;
    let insns = program.instructions();
    let Ok(len) = u16::try_from(insns.len()) else {
        return Err(SysError::Os(EINVAL));
    };
    let fprog = SockFprog {
        len,
        filter: insns.as_ptr(),
    };
    // SAFETY: `fprog` と `insns`（`program` が所有）は呼び出し中生存する。カーネルは命令列をコピーし、
    // 呼び出し後にポインタを保持しない。`len` は実際の命令数と一致する（`SeccompProgram` の型保証）。
    // 成功時の戻り値はカーネルが新規に確保した listener fd で、他に所有者がいない。
    let rc = unsafe {
        syscall(
            nr,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const SockFprog as usize as u64,
        )
    };
    if rc < 0 {
        return Err(last_error());
    }
    let Ok(fd) = RawFd::try_from(rc) else {
        return Err(SysError::Os(EINVAL));
    };
    // SAFETY: 成功時の戻り値は新規の fd で、ここで初めて所有者（`OwnedFd`）が付く。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `AF_UNIX` / `SOCK_SEQPACKET | SOCK_CLOEXEC` の socketpair を作る。
pub(crate) fn unix_seqpacket_pair() -> Result<(OwnedFd, OwnedFd), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut sv = [-1i32; 2];
    // SAFETY: `sv` は 2 要素の書き込み可能な配列で、カーネルは成功時に 2 要素だけを書く。
    let rc = unsafe {
        socketpair(
            consts::AF_UNIX,
            SOCK_SEQPACKET | consts::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    };
    if rc == -1 {
        return Err(last_error());
    }
    // SAFETY: 成功時の 2 要素はカーネルが新規に確保した fd で、他に所有者がいない。
    Ok(unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) })
}

/// `SO_PASSCRED` を有効にする（受信側が、送信側の資格情報を `SCM_CREDENTIALS` で受け取るため。送信の前に設定する）。
pub(crate) fn set_passcred(fd: BorrowedFd<'_>) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let on: i32 = 1;
    // SAFETY: `on` はスタック上の有効な `int` で、渡す長さ（4）と一致する。`fd` は生存中の `BorrowedFd`。
    let rc = unsafe {
        setsockopt(
            fd.as_raw_fd(),
            consts::SOL_SOCKET,
            SO_PASSCRED,
            (&raw const on).cast(),
            4,
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `fd` が close-on-exec か（`fcntl(F_GETFD)`）。
pub(crate) fn fd_is_cloexec(fd: BorrowedFd<'_>) -> Result<bool, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数は整数のみ。`fd` は生存中の `BorrowedFd`。読み取りだけで状態を変えない。
    let rc = unsafe { fcntl(fd.as_raw_fd(), consts::F_GETFD) };
    if rc == -1 {
        return Err(last_error());
    }
    Ok(rc & consts::FD_CLOEXEC != 0)
}

/// 1 バイトの `token` と `fd` 1 本を `SCM_RIGHTS` で送る（`MSG_NOSIGNAL`。待たない保証は無く、socketpair の
/// 送信バッファが空の直後に 1 回だけ使う前提）。fd は複製されて相手側に入り、手元の `fd` は閉じない。
pub(crate) fn send_fd_with_token(
    sock: BorrowedFd<'_>,
    token: u8,
    fd: BorrowedFd<'_>,
) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut payload = [token];
    let mut iov = IoVec {
        base: payload.as_mut_ptr().cast(),
        len: 1,
    };
    let mut control = ControlBuf([0; CONTROL_CAP]);
    let space = cmsg_space(4);
    // 先頭に cmsghdr、直後（`CMSG_DATA`）に fd。`ControlBuf` は 8 バイト整列。
    let hdr = CmsgHdr {
        len: CMSG_HDR_LEN + 4,
        level: consts::SOL_SOCKET,
        kind: SCM_RIGHTS,
    };
    let mut bytes = Vec::with_capacity(CMSG_HDR_LEN + 4);
    bytes.extend_from_slice(&hdr.len.to_ne_bytes());
    bytes.extend_from_slice(&hdr.level.to_ne_bytes());
    bytes.extend_from_slice(&hdr.kind.to_ne_bytes());
    bytes.extend_from_slice(&fd.as_raw_fd().to_ne_bytes());
    let Some(dst) = control.0.get_mut(..bytes.len()) else {
        return Err(SysError::Os(EINVAL));
    };
    dst.copy_from_slice(&bytes);
    let msg = MsgHdr {
        name: core::ptr::null_mut(),
        namelen: 0,
        iov: &raw mut iov,
        iovlen: 1,
        control: control.0.as_mut_ptr().cast(),
        controllen: space,
        flags: 0,
    };
    // SAFETY: `msg` が指す `iov`（1 要素・`payload` 1 バイトを指す）と `control`（`space` バイトは確保済みで初期化済み、
    // 先頭に整列した cmsghdr と fd 1 本）は呼び出しの間生存する。`name` は null・`namelen` は 0。カーネルは
    // 呼び出し中だけこれらを読み、ポインタを保持しない。`sock`・`fd` は生存中の `BorrowedFd`。
    let n = unsafe { sendmsg(sock.as_raw_fd(), &raw const msg, MSG_NOSIGNAL) };
    if n == 1 {
        Ok(())
    } else if n < 0 {
        Err(last_error())
    } else {
        Err(SysError::Os(EINVAL))
    }
}

/// [`recv_fd_with_creds`] の結果。検証は呼び出し側が行う。受け取った fd は `fds` に所有され、検証に落ちて
/// この値を捨てれば閉じられる（漏れない）。
#[derive(Debug)]
pub(crate) struct ReceivedFd {
    /// 受信した本文（空は相手が閉じた EOF）。
    pub(crate) payload: Vec<u8>,
    /// `SCM_RIGHTS` で受け取った fd（`MSG_CMSG_CLOEXEC` で close-on-exec）。
    pub(crate) fds: Vec<OwnedFd>,
    /// `SCM_CREDENTIALS`（pid は受信側の PID namespace で見た値）。無ければ `None`。
    pub(crate) creds: Option<Ucred>,
    /// `MSG_TRUNC` / `MSG_CTRUNC` が立った（本文または制御データが切り詰められた）。
    pub(crate) truncated: bool,
}

/// [`parse_control`] の結果。形式違反でも、それまでに見つけた fd 番号は `fds` に残す（呼び出し側が閉じるため）。
#[derive(Debug, PartialEq, Eq)]
struct ParsedControl {
    fds: Vec<RawFd>,
    creds: Option<Ucred>,
    well_formed: bool,
}

/// 制御バッファ（有効長 `len`）から `SCM_RIGHTS` の fd 番号と `SCM_CREDENTIALS` を取り出す純関数。
/// 添字アクセスをせず、`get()` と checked 演算だけで走査する。
fn parse_control(buf: &[u8], len: usize) -> ParsedControl {
    let mut out = ParsedControl {
        fds: Vec::new(),
        creds: None,
        well_formed: false,
    };
    out.well_formed = parse_control_into(buf, len, &mut out.fds, &mut out.creds).is_some();
    out
}

fn parse_control_into(
    buf: &[u8],
    len: usize,
    fds: &mut Vec<RawFd>,
    creds: &mut Option<Ucred>,
) -> Option<()> {
    let buf = buf.get(..len)?;
    let mut off = 0usize;
    while off < buf.len() {
        let hdr = buf.get(off..off.checked_add(CMSG_HDR_LEN)?)?;
        let clen = usize::from_ne_bytes(hdr.get(0..8)?.try_into().ok()?);
        let level = i32::from_ne_bytes(hdr.get(8..12)?.try_into().ok()?);
        let kind = i32::from_ne_bytes(hdr.get(12..16)?.try_into().ok()?);
        let data_len = clen.checked_sub(CMSG_HDR_LEN)?;
        let data_start = off.checked_add(CMSG_HDR_LEN)?;
        let data = buf.get(data_start..data_start.checked_add(data_len)?)?;
        if level == consts::SOL_SOCKET {
            if kind == SCM_RIGHTS {
                for c in data.as_chunks::<4>().0 {
                    fds.push(i32::from_ne_bytes(*c));
                }
                if data_len % 4 != 0 {
                    return None;
                }
            } else if kind == SCM_CREDENTIALS {
                if data_len != UCRED_LEN {
                    return None;
                }
                *creds = Some(Ucred {
                    pid: i32::from_ne_bytes(data.get(0..4)?.try_into().ok()?),
                    uid: u32::from_ne_bytes(data.get(4..8)?.try_into().ok()?),
                    gid: u32::from_ne_bytes(data.get(8..12)?.try_into().ok()?),
                });
            }
        }
        off = off.checked_add(cmsg_align(clen))?;
    }
    Some(())
}

/// 1 通を受信する（`MSG_CMSG_CLOEXEC`）。呼び出し前に `poll_readable` で読み取り可能を確認する（なければブロックする）。
/// 受け取った fd はすべて `OwnedFd` で所有するため、呼び出し側が拒否して値を捨てれば確実に閉じる。
/// 制御データの形式違反は、拾えた fd を閉じてから `EINVAL` を返す。
pub(crate) fn recv_fd_with_creds(sock: BorrowedFd<'_>) -> Result<ReceivedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut payload = [0u8; MAX_PAYLOAD];
    let mut iov = IoVec {
        base: payload.as_mut_ptr().cast(),
        len: MAX_PAYLOAD,
    };
    let mut control = ControlBuf([0; CONTROL_CAP]);
    let mut msg = MsgHdr {
        name: core::ptr::null_mut(),
        namelen: 0,
        iov: &raw mut iov,
        iovlen: 1,
        control: control.0.as_mut_ptr().cast(),
        controllen: CONTROL_CAP,
        flags: 0,
    };
    // SAFETY: `msg` が指す `iov`（`payload` の 8 バイト）と `control`（128 バイト・8 バイト整列）は書き込み可能で
    // 呼び出しの間生存する。カーネルは確保サイズを超えて書かず、受け取った fd 番号を制御バッファへ書く。
    // `sock` は生存中の `BorrowedFd`。
    let n = unsafe { recvmsg(sock.as_raw_fd(), &raw mut msg, MSG_CMSG_CLOEXEC) };
    let n = usize::try_from(n).map_err(|_| last_error())?;
    let controllen = msg.controllen.min(CONTROL_CAP);
    let truncated = msg.flags & (MSG_CTRUNC | MSG_TRUNC) != 0;
    // カーネルがこの呼び出しで新規に割り当てた fd だけを所有する。形式違反でも拾えた分は閉じる。
    let parsed = parse_control(&control.0, controllen);
    let fds: Vec<OwnedFd> = parsed
        .fds
        .into_iter()
        // SAFETY: `SCM_RIGHTS` の fd は `recvmsg` がこの呼び出しで受信側に新規に割り当てたもので、
        // 他に所有者がいない。形式違反の場合も、見つけた分を所有して drop で閉じる。
        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
        .collect();
    if !parsed.well_formed {
        return Err(SysError::Os(EINVAL));
    }
    let creds = parsed.creds;
    Ok(ReceivedFd {
        payload: payload.get(..n.min(MAX_PAYLOAD)).unwrap_or(&[]).to_vec(),
        fds,
        creds,
        truncated,
    })
}

/// `sock` から最大 `buf.len()` バイトを待たずに読む（`poll_readable` の後に 1 回だけ使う。ACK 用）。
/// 0 は相手が閉じた EOF。
pub(crate) fn recv_nowait(sock: BorrowedFd<'_>, buf: &mut [u8]) -> Result<usize, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `buf` は排他借用したスライスで、渡す長さは `buf.len()`。`MSG_DONTWAIT` でブロックしない。
    let n = unsafe {
        recv(
            sock.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            MSG_DONTWAIT,
        )
    };
    usize::try_from(n).map_err(|_| last_error())
}

#[cfg(all(
    test,
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    /// 構造体のサイズ・オフセットは LP64 の ABI と一致する（REPAIR-2）。
    #[test]
    fn sec4_layouts_match_lp64_abi() {
        assert_eq!(core::mem::size_of::<MsgHdr>(), 56);
        assert_eq!(core::mem::size_of::<CmsgHdr>(), 16);
        assert_eq!(core::mem::size_of::<IoVec>(), 16);
        assert_eq!(core::mem::size_of::<Ucred>(), 12);
        assert_eq!(core::mem::offset_of!(MsgHdr, iov), 16);
        assert_eq!(core::mem::offset_of!(MsgHdr, control), 32);
        assert_eq!(core::mem::offset_of!(MsgHdr, flags), 48);
        assert_eq!(core::mem::offset_of!(CmsgHdr, level), 8);
        assert_eq!(core::mem::offset_of!(CmsgHdr, kind), 12);
        assert_eq!(cmsg_space(4), 24);
        assert_eq!(cmsg_space(12), 32);
    }

    /// uapi の値（出典: include/uapi/linux/seccomp.h・asm-generic/socket.h・linux/socket.h・syscall 表）。
    #[test]
    fn sec4_constants_match_uapi() {
        assert_eq!(SECCOMP_SET_MODE_FILTER, 1);
        assert_eq!(SECCOMP_FILTER_FLAG_NEW_LISTENER, 8);
        #[cfg(target_arch = "x86_64")]
        let expected = 317;
        #[cfg(target_arch = "aarch64")]
        let expected = 277;
        assert_eq!(
            SYS_SECCOMP.get().map(super::super::SyscallNumber::raw),
            Ok(expected)
        );
        assert_eq!(
            (SOCK_SEQPACKET, SO_PASSCRED, SCM_RIGHTS, SCM_CREDENTIALS),
            (5, 16, 1, 2)
        );
        assert_eq!(
            (MSG_CTRUNC, MSG_TRUNC, MSG_DONTWAIT, MSG_CMSG_CLOEXEC),
            (0x08, 0x20, 0x40, 0x4000_0000)
        );
    }

    /// 手組みの制御バッファの走査: fd 2 本と資格情報。
    #[test]
    fn sec4_parse_control_extracts_fds_and_creds() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(CMSG_HDR_LEN + 8).to_ne_bytes());
        buf.extend_from_slice(&consts::SOL_SOCKET.to_ne_bytes());
        buf.extend_from_slice(&SCM_RIGHTS.to_ne_bytes());
        buf.extend_from_slice(&7i32.to_ne_bytes());
        buf.extend_from_slice(&9i32.to_ne_bytes());
        buf.extend_from_slice(&(CMSG_HDR_LEN + UCRED_LEN).to_ne_bytes());
        buf.extend_from_slice(&consts::SOL_SOCKET.to_ne_bytes());
        buf.extend_from_slice(&SCM_CREDENTIALS.to_ne_bytes());
        buf.extend_from_slice(&100i32.to_ne_bytes());
        buf.extend_from_slice(&1000u32.to_ne_bytes());
        buf.extend_from_slice(&1001u32.to_ne_bytes());
        let len = buf.len();
        assert_eq!(
            parse_control(&buf, len),
            ParsedControl {
                fds: vec![7, 9],
                creds: Some(Ucred {
                    pid: 100,
                    uid: 1000,
                    gid: 1001
                }),
                well_formed: true,
            }
        );
    }

    /// 壊れた長さ（ヘッダ未満・範囲外）は拒否する。
    #[test]
    fn sec4_parse_control_rejects_malformed() {
        assert!(!parse_control(&[0u8; 8], 8).well_formed);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1000usize.to_ne_bytes());
        buf.extend_from_slice(&consts::SOL_SOCKET.to_ne_bytes());
        buf.extend_from_slice(&SCM_RIGHTS.to_ne_bytes());
        assert!(!parse_control(&buf, 16).well_formed);
        let mut short = Vec::new();
        short.extend_from_slice(&8usize.to_ne_bytes());
        short.extend_from_slice(&consts::SOL_SOCKET.to_ne_bytes());
        short.extend_from_slice(&SCM_RIGHTS.to_ne_bytes());
        assert!(!parse_control(&short, 16).well_formed);
    }

    /// 実 socketpair で fd と資格情報が往復する（pid・uid は自分のもの）。余分な fd は受け取り側で閉じられる。
    #[test]
    fn sec4_roundtrip_fd_token_and_credentials() {
        let (a, b) = unix_seqpacket_pair().unwrap();
        set_passcred(b.as_fd()).unwrap();
        let (r, _w) = std::io::pipe().unwrap();
        let r = OwnedFd::from(r);
        send_fd_with_token(a.as_fd(), b'L', r.as_fd()).unwrap();
        let got = recv_fd_with_creds(b.as_fd()).unwrap();
        assert_eq!(got.payload, b"L");
        assert!(!got.truncated);
        assert_eq!(got.fds.len(), 1);
        assert!(fd_is_cloexec(got.fds[0].as_fd()).unwrap());
        let creds = got.creds.unwrap();
        assert_eq!(creds.pid, i32::try_from(std::process::id()).unwrap());
    }

    /// 相手が閉じた socket の受信は空の本文（EOF）になる。
    #[test]
    fn sec4_recv_after_peer_close_is_eof() {
        let (a, b) = unix_seqpacket_pair().unwrap();
        drop(a);
        let got = recv_fd_with_creds(b.as_fd()).unwrap();
        assert!(got.payload.is_empty());
        assert!(got.fds.is_empty());
    }
}
