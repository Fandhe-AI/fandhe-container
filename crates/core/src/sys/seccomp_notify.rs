//! seccomp の listener fd の取得と、UDS（`SOCK_SEQPACKET`）の `SCM_RIGHTS` での受け渡しの薄いラッパー
//! （SEC-4・TASK-41 追補・#2024。`unsafe` 事前承認の範囲の `sys` 子モジュール）。
//!
//! # 役割と呼び出し文脈
//!
//! `crate::exec::seccomp_listener` が、コンテナの PID 1（または exec の worker）で
//! `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER)` を呼んで listener fd を得て
//! （[`seccomp_set_filter_new_listener`]）、起動側（supervisor 側のプロセス C）へ socketpair で渡す
//! （[`send_fd_with_token`] / [`recv_fd_with_creds`]）ために使う。検証の方針（資格情報・fd の種別・
//! fail-closed）と送信元の照合（pid のみ・信頼の前提・uid を照合しない根拠。#2372）は呼び出し側の
//! `exec/seccomp_listener.rs`（モジュール doc の「信頼の前提」）が持ち、本モジュールは syscall の薄い安全 API だけを公開する。
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
//! # 受信の fd 数の制限（SEC-4・REPAIR-5・#2372・#2498。Linux v6.12 `include/net/scm.h`・`net/core/scm.c`・`net/unix/af_unix.c`）
//!
//! 版はタグ v6.12（commit `adc218676eef25575469234709c2d87185ca223a`）、行は 2026-10-26 に原文で確認したもの。
//!
//! - `SO_PASSCRED` の受信では `SCM_CREDENTIALS` が先、`SCM_RIGHTS` が後に制御バッファへ書かれる
//!   （`scm.h` の `__scm_recv_common` L172–200: `put_cmsg` → `scm_passec` → `scm_detach_fds`）。
//!   送信元の pid は送信時に `scm_set_cred`（`scm.h` L69–74）が `pid_vnr` で変換して持ち、uid / gid は受信時に
//!   `from_kuid_munged` / `from_kgid_munged` で受信側の user namespace へ写される
//! - `scm_detach_fds`（`scm.c` L320–370）は `fdmax = min(scm_max_fds, fd 数)`（`scm_max_fds` は L313 で
//!   `(msg_controllen - sizeof(cmsghdr)) / sizeof(int)`）本だけ受信側に割り当て、入らない fd は割り当てずに解放して
//!   `MSG_CTRUNC` を立てる（L361–362）
//! - `SO_PASSSEC`・`SO_PASSPIDFD` は設定しないため他の cmsg は付かない。制御バッファ（`CONTROL_CAP`）は
//!   `MAX_RECV_FDS` 本＋資格情報ちょうどの容量にし、超過は実際に `MSG_CTRUNC` になる（試験で固定する）
//! - 受信は `MSG_DONTWAIT`。`unix_seqpacket_recvmsg` は `__unix_dgram_recvmsg`（`af_unix.c` L2414）へ進み、
//!   `sock_rcvtimeo(sk, flags & MSG_DONTWAIT)` が待ち時間 0（L2429）になって、待機中メッセージ無しは `EAGAIN` のまま
//!   戻る。poll を省いても無期限に待たない。`SOCK_SEQPACKET` で `EAGAIN` かつ `RCV_SHUTDOWN`（相手が閉じた）の
//!   ときだけ `err = 0`（EOF。受信長 0）になる（L2453–2457）。`ReceiveFailure::SenderClosed` の根拠
//!
//! `SO_PEERCRED` は socketpair では作成者（呼び出し元自身）を両端で返し検証の意味が無いため使わない。

use super::{ArchSysNo, EINVAL, PollFd, SockFprog, SysError, consts, fcntl, last_error, poll};
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

/// `SYS_SECCOMP` を `libc` 0.2.189 の `SYS_seccomp` と `const` 評価で照合する（#1847・#1837・#1318・
/// MVM-4・REPAIR-7・REPAIR-12）。`sys.rs` の `consts` の照合と同じ方式（`get` + `raw` のみ使用、`unsafe` なし）。
/// 対応外 arch は `ArchSysNo::UNSUPPORTED` で番号が無く対象外。食い違いは試験側を合わせない。
#[cfg(all(
    test,
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod libc_abi {
    use super::{ArchSysNo, SYS_SECCOMP};

    const fn nr(n: ArchSysNo) -> i64 {
        match n.get() {
            Ok(v) => v.raw(),
            // 対応 arch の cfg の下でだけ定義するため到達しない（到達すればコンパイルエラー）。
            Err(_) => panic!("unsupported arch"),
        }
    }

    const _: () = assert!(nr(SYS_SECCOMP) == libc::SYS_seccomp);

    // 番号以外の定数の照合（#1848）。型は `libc_const_eq!` の引数で明記する（`sys.rs` の同名マクロ）。
    // 名前が `libc` と違う対応: `ENOENT_ERRNO` = `ENOENT`、`EPERM_ERRNO` = `EPERM`。
    // `SECCOMP_IOCTL_NOTIF_*` は `libc` が `_IOWR::<seccomp_notif>` 等で組み立てるため、一致すれば構造体の大きさ
    // （80・24・8）も間接的に一致する。構造体のレイアウトは下の「構造体と関数の型」（#1849）が個別に照合する。
    // 対象外: `SECCOMP_IOC_MAGIC`・`IOC_READ`・`IOC_WRITE`（`libc` で非公開。ioctl の値の照合に含まれる）、
    // `MAX_RECV_FDS`・`MAX_PAYLOAD`・`CMSG_HDR_LEN`・`UCRED_LEN`・`CONTROL_CAP`・`SEND_MAX_FDS`・
    // `SEND_EINTR_ATTEMPTS`（本実装の内部の上限・派生値で、カーネル ABI の値でない）。
    const _: () = {
        use libc::{c_int, c_short, c_uint, c_ulong};
        libc_const_eq!(SECCOMP_SET_MODE_FILTER, u64, c_uint);
        libc_const_eq!(SECCOMP_FILTER_FLAG_NEW_LISTENER, u64, c_ulong);
        libc_const_eq!(SOCK_SEQPACKET, i32, c_int);
        libc_const_eq!(SO_PASSCRED, i32, c_int);
        libc_const_eq!(SCM_RIGHTS, i32, c_int);
        libc_const_eq!(SCM_CREDENTIALS, i32, c_int);
        libc_const_eq!(MSG_CTRUNC, i32, c_int);
        libc_const_eq!(MSG_TRUNC, i32, c_int);
        libc_const_eq!(MSG_DONTWAIT, i32, c_int);
        libc_const_eq!(MSG_NOSIGNAL, i32, c_int);
        libc_const_eq!(MSG_CMSG_CLOEXEC, i32, c_int);
        libc_const_eq!(super::ENOENT_ERRNO, i32, libc::ENOENT, c_int);
        libc_const_eq!(super::EPERM_ERRNO, i32, libc::EPERM, c_int);
        libc_const_eq!(POLLERR, i16, c_short);
        libc_const_eq!(POLLHUP, i16, c_short);
    };
    // `Ioctl` 型は環境で変わる（gnu は `c_ulong`、musl は `c_int` で負になり得る）ため gnu に限る。
    #[cfg(target_env = "gnu")]
    const _: () = {
        use libc::c_ulong;
        libc_const_eq!(SECCOMP_IOCTL_NOTIF_RECV, u64, c_ulong);
        libc_const_eq!(SECCOMP_IOCTL_NOTIF_SEND, u64, c_ulong);
        libc_const_eq!(SECCOMP_IOCTL_NOTIF_ID_VALID, u64, c_ulong);
    };

    // ---- 構造体と `extern "C"` 関数の型（#1849・#1837） ----
    // 構造体は `size_of`・`align_of`・フィールドのオフセット（`libc` のフィールドが pub のもの）を、関数は同じ
    // 関数ポインタ型への代入で照合する。関数は呼ばず `unsafe` を使わない。食い違いは宣言を直す別 issue とし、
    // 試験側を合わせない。
    use core::mem::{align_of, offset_of, size_of};
    use libc::{c_int, c_void};

    // `SeccompData`・`SeccompNotif`・`SeccompNotifResp`: `libc` の uapi 版（`seccomp_data`・`seccomp_notif`・
    // `seccomp_notif_resp`。全フィールドが pub。Linux の x86_64・aarch64 で共通の 64・80・24 バイト）。
    const _: () = {
        use super::{SeccompData, SeccompNotif, SeccompNotifResp};
        assert!(size_of::<SeccompData>() == size_of::<libc::seccomp_data>());
        assert!(align_of::<SeccompData>() == align_of::<libc::seccomp_data>());
        assert!(offset_of!(SeccompData, nr) == offset_of!(libc::seccomp_data, nr));
        assert!(offset_of!(SeccompData, arch) == offset_of!(libc::seccomp_data, arch));
        assert!(
            offset_of!(SeccompData, instruction_pointer)
                == offset_of!(libc::seccomp_data, instruction_pointer)
        );
        assert!(offset_of!(SeccompData, args) == offset_of!(libc::seccomp_data, args));

        assert!(size_of::<SeccompNotif>() == size_of::<libc::seccomp_notif>());
        assert!(align_of::<SeccompNotif>() == align_of::<libc::seccomp_notif>());
        assert!(offset_of!(SeccompNotif, id) == offset_of!(libc::seccomp_notif, id));
        assert!(offset_of!(SeccompNotif, pid) == offset_of!(libc::seccomp_notif, pid));
        assert!(offset_of!(SeccompNotif, flags) == offset_of!(libc::seccomp_notif, flags));
        assert!(offset_of!(SeccompNotif, data) == offset_of!(libc::seccomp_notif, data));

        assert!(size_of::<SeccompNotifResp>() == size_of::<libc::seccomp_notif_resp>());
        assert!(align_of::<SeccompNotifResp>() == align_of::<libc::seccomp_notif_resp>());
        assert!(offset_of!(SeccompNotifResp, id) == offset_of!(libc::seccomp_notif_resp, id));
        assert!(offset_of!(SeccompNotifResp, val) == offset_of!(libc::seccomp_notif_resp, val));
        assert!(offset_of!(SeccompNotifResp, error) == offset_of!(libc::seccomp_notif_resp, error));
        assert!(offset_of!(SeccompNotifResp, flags) == offset_of!(libc::seccomp_notif_resp, flags));
    };

    // `IoVec`・`Ucred`: `libc::iovec`・`libc::ucred`（全ターゲット共通。フィールド名の対応は
    // `base` = `iov_base`・`len` = `iov_len`）。
    const _: () = {
        use super::{IoVec, Ucred};
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

    // `MsgHdr`・`CmsgHdr`: `libc::msghdr`・`libc::cmsghdr`。gnu に限る。musl は `msg_iovlen`・`msg_controllen`・
    // `cmsg_len` を `int` / `socklen_t` と非公開のパディングで持つ一方、自前はカーネルの `user_msghdr` に合わせた
    // `size_t` のため、フィールドが公開されている gnu でだけオフセットまで照合する（core は musl 向けに CI で
    // ビルドしないため musl は未照合）。名前の対応は `name` = `msg_name`・`namelen` = `msg_namelen`・
    // `iov` = `msg_iov`・`iovlen` = `msg_iovlen`・`control` = `msg_control`・`controllen` = `msg_controllen`・
    // `flags` = `msg_flags`、`len` = `cmsg_len`・`level` = `cmsg_level`・`kind` = `cmsg_type`。
    #[cfg(target_env = "gnu")]
    const _: () = {
        use super::{CmsgHdr, MsgHdr};
        assert!(size_of::<MsgHdr>() == size_of::<libc::msghdr>());
        assert!(align_of::<MsgHdr>() == align_of::<libc::msghdr>());
        assert!(offset_of!(MsgHdr, name) == offset_of!(libc::msghdr, msg_name));
        assert!(offset_of!(MsgHdr, namelen) == offset_of!(libc::msghdr, msg_namelen));
        assert!(offset_of!(MsgHdr, iov) == offset_of!(libc::msghdr, msg_iov));
        assert!(offset_of!(MsgHdr, iovlen) == offset_of!(libc::msghdr, msg_iovlen));
        assert!(offset_of!(MsgHdr, control) == offset_of!(libc::msghdr, msg_control));
        assert!(offset_of!(MsgHdr, controllen) == offset_of!(libc::msghdr, msg_controllen));
        assert!(offset_of!(MsgHdr, flags) == offset_of!(libc::msghdr, msg_flags));

        assert!(size_of::<CmsgHdr>() == size_of::<libc::cmsghdr>());
        assert!(align_of::<CmsgHdr>() == align_of::<libc::cmsghdr>());
        assert!(offset_of!(CmsgHdr, len) == offset_of!(libc::cmsghdr, cmsg_len));
        assert!(offset_of!(CmsgHdr, level) == offset_of!(libc::cmsghdr, cmsg_level));
        assert!(offset_of!(CmsgHdr, kind) == offset_of!(libc::cmsghdr, cmsg_type));
    };

    // 対象外: `ControlBuf`・`SendControlBuf` は `cmsghdr` の整列を満たすバイトの入れ物で、`libc` に対応物が無い。
    // 整列だけを `cmsghdr` に対して確かめる。
    const _: () = {
        assert!(align_of::<super::ControlBuf>() >= align_of::<libc::cmsghdr>());
        assert!(align_of::<super::SendControlBuf>() >= align_of::<libc::cmsghdr>());
    };

    // `extern "C"` 関数。`sendmsg`・`recvmsg` は自前が `MsgHdr` を指すため、ポインタ先の型を別々に書く
    // （`MsgHdr` の同一性は上の構造体の照合が保証する）。
    const _: unsafe extern "C" fn(c_int, c_int, c_int, *mut c_int) -> c_int = super::socketpair;
    const _: unsafe extern "C" fn(c_int, c_int, c_int, *mut c_int) -> c_int = libc::socketpair;
    const _: unsafe extern "C" fn(c_int, *const super::MsgHdr, c_int) -> libc::ssize_t =
        super::sendmsg;
    const _: unsafe extern "C" fn(c_int, *const libc::msghdr, c_int) -> libc::ssize_t =
        libc::sendmsg;
    const _: unsafe extern "C" fn(c_int, *mut super::MsgHdr, c_int) -> libc::ssize_t =
        super::recvmsg;
    const _: unsafe extern "C" fn(c_int, *mut libc::msghdr, c_int) -> libc::ssize_t = libc::recvmsg;
    const _: unsafe extern "C" fn(c_int, c_int, c_int, *const c_void, libc::socklen_t) -> c_int =
        super::setsockopt;
    const _: unsafe extern "C" fn(c_int, c_int, c_int, *const c_void, libc::socklen_t) -> c_int =
        libc::setsockopt;
    const _: unsafe extern "C" fn(c_int, *mut c_void, libc::size_t, c_int) -> libc::ssize_t =
        super::recv;
    const _: unsafe extern "C" fn(c_int, *mut c_void, libc::size_t, c_int) -> libc::ssize_t =
        libc::recv;
}

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

/// 受信で受け取る fd の上限。これを超える分はカーネルが受信側に割り当てずに閉じ、`MSG_CTRUNC` を立てる
/// （制御バッファの容量 `CONTROL_CAP` がこの本数ちょうどを保証する。SEC-4・#2372）。
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

/// 制御バッファの容量。`SCM_RIGHTS`（`MAX_RECV_FDS` 本）＋ `SCM_CREDENTIALS` ちょうど（余裕を持たせない。
/// 余裕があると `MAX_RECV_FDS` を超える fd が入ってしまう）。
const CONTROL_CAP: usize = cmsg_space(MAX_RECV_FDS * 4) + cmsg_space(UCRED_LEN);
/// 試験用の複数 fd 送信の本数の上限（`MAX_RECV_FDS` 超過を送れれば足りる）。
const SEND_MAX_FDS: usize = MAX_RECV_FDS + 1;
const _: () = assert!(cmsg_space(SEND_MAX_FDS * 4) <= CONTROL_CAP);

/// `cmsghdr` の整列を満たす固定長の制御バッファ。
#[repr(C, align(8))]
struct ControlBuf([u8; CONTROL_CAP]);

/// 送信用（試験の複数 fd 送信を含む）の制御バッファ。整列は [`ControlBuf`] と同じ。
#[repr(C, align(8))]
struct SendControlBuf([u8; cmsg_space(SEND_MAX_FDS * 4)]);

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
        ffi_syscall!(
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
    // 配列をパターンで分解して取り出す(カーネル応答の添字アクセスを避ける)。
    let [first, second] = sv;
    // SAFETY: 成功時の 2 要素はカーネルが新規に確保した fd で、他に所有者がいない。
    Ok(unsafe { (OwnedFd::from_raw_fd(first), OwnedFd::from_raw_fd(second)) })
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

/// `fd` を `O_NONBLOCK` にする（`fcntl(F_GETFL)` + `F_SETFL`）。`SECCOMP_IOCTL_NOTIF_RECV` は `O_NONBLOCK` を見ないため
/// これでは RECV のブロックは防げない（RECV のブロック防止は listener の単独の読み手と、受信直前の `poll(0)` の
/// 再確認で行う。REPAIR-5）。ここでの `O_NONBLOCK` は、他の読み出し系（`read` 等）が将来使われたときの保険。
/// open file description の状態なので複製した fd にも効く。
pub(crate) fn set_nonblocking(fd: BorrowedFd<'_>) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数は整数のみ。`fd` は生存中の `BorrowedFd`。
    let flags = unsafe { fcntl(fd.as_raw_fd(), consts::F_GETFL) };
    if flags == -1 {
        return Err(last_error());
    }
    // SAFETY: 引数は整数のみ（`F_SETFL` の第 3 引数は `int`）。`fd` は生存中の `BorrowedFd`。
    let rc = unsafe { fcntl(fd.as_raw_fd(), consts::F_SETFL, flags | consts::O_NONBLOCK) };
    if rc == -1 {
        return Err(last_error());
    }
    Ok(())
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
    send_fds_with_token(sock, token, &[fd])
}

/// [`send_fd_with_token`] の本体。`1..=SEND_MAX_FDS` 本を 1 つの `SCM_RIGHTS` で送る（範囲外は `EINVAL`）。
/// 本番の入口は 1 本送りの [`send_fd_with_token`] と、netns 同期点の 2 本送り（pasta 構成の netns と user namespace を
/// この順で渡す。NET-9・CORE-6・#1939）。複数本は受信側の上限の試験（#2372）にも使う。
pub(crate) fn send_fds_with_token(
    sock: BorrowedFd<'_>,
    token: u8,
    fds: &[BorrowedFd<'_>],
) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    if fds.is_empty() || fds.len() > SEND_MAX_FDS {
        return Err(SysError::Os(EINVAL));
    }
    let data_len = fds.len() * 4;
    let mut payload = [token];
    let mut iov = IoVec {
        base: payload.as_mut_ptr().cast(),
        len: 1,
    };
    // 送信側は資格情報を付けないので `SEND_MAX_FDS` 本分の容量を別に確保する。
    let mut control = SendControlBuf([0; cmsg_space(SEND_MAX_FDS * 4)]);
    let space = cmsg_space(data_len);
    // 先頭に cmsghdr、直後（`CMSG_DATA`）に fd。`SendControlBuf` は 8 バイト整列。
    let hdr = CmsgHdr {
        len: CMSG_HDR_LEN + data_len,
        level: consts::SOL_SOCKET,
        kind: SCM_RIGHTS,
    };
    let mut bytes = Vec::with_capacity(CMSG_HDR_LEN + data_len);
    bytes.extend_from_slice(&hdr.len.to_ne_bytes());
    bytes.extend_from_slice(&hdr.level.to_ne_bytes());
    bytes.extend_from_slice(&hdr.kind.to_ne_bytes());
    for fd in fds {
        bytes.extend_from_slice(&fd.as_raw_fd().to_ne_bytes());
    }
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
    // 先頭に整列した cmsghdr と fd `fds.len()` 本。`space` <= バッファ長は本数の検証と const assert で保証）は呼び出しの間生存する。`name` は null・`namelen` は 0。カーネルは
    // 呼び出し中だけこれらを読み、ポインタを保持しない。`sock`・`fds` は生存中の `BorrowedFd`。
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

/// 1 通を受信する（`MSG_CMSG_CLOEXEC | MSG_DONTWAIT`）。呼び出し前に poll で読み取り可能を確認する前提だが、
/// 待機中のメッセージが無ければ待たずに `Os(EAGAIN)` を返す（多重防御。REPAIR-5・#2372）。
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
    // SAFETY: `msg` が指す `iov`（`payload` の 8 バイト）と `control`（`CONTROL_CAP` バイト・8 バイト整列）は書き込み可能で
    // 呼び出しの間生存する。カーネルは確保サイズを超えて書かず、受け取った fd 番号を制御バッファへ書く。
    // `sock` は生存中の `BorrowedFd`。
    let n = unsafe {
        recvmsg(
            sock.as_raw_fd(),
            &raw mut msg,
            MSG_CMSG_CLOEXEC | MSG_DONTWAIT,
        )
    };
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

// ---- 通知の受信・応答（SEC-4・#2025）----
//
// 一次情報（Linux v6.12 `include/uapi/linux/seccomp.h`・`kernel/seccomp.c`。2026-10-19 に確認）:
// - 構造体: `seccomp_data`（64 B）・`seccomp_notif`（80 B: id u64・pid u32・flags u32・data）・
//   `seccomp_notif_resp`（24 B: id u64・val s64・error s32・flags u32）
// - ioctl: `RECV = _IOWR('!', 0, seccomp_notif)`・`SEND = _IOWR('!', 1, seccomp_notif_resp)`・
//   `ID_VALID = _IOW('!', 2, __u64)`（5.0〜5.6 の `_IOR` 版はカーネルが互換で受けるが、ここでは現行値だけを使う）
// - `RECV` は `notif` が 0 初期化でないと `EINVAL`。`notif.pid` は `task_pid_vnr(task)`（RECV を呼んだ側の PID namespace の
//   TID）。待機中の通知が無ければ、filter の利用者が 0 のときは待たずに、そうでなければ到着まで待つ。見つからなければ `ENOENT`
// - `SEND` は `ENOENT`（対象が既に消えた）・`EINPROGRESS`（応答済み）を返す。`ID_VALID` は `RECV` 済み（SENT 状態）の
//   通知が存在するとき 0、無ければ `ENOENT`
// - poll: 未処理の通知があれば `EPOLLIN`、filter の利用者が 0 なら `EPOLLHUP`
// 本節の定数のうち `libc` に対応物があるものは `libc_abi`（#1847・#1848）で `libc` と `const` 評価で照合し、`tests` でも上記 uapi 値を照合する。
// `SECCOMP_USER_NOTIF_FLAG_CONTINUE` は引数を許可判断に使うと TOCTOU になるため、定数も宣言しない。

const SECCOMP_IOC_MAGIC: u64 = b'!' as u64;
/// `_IOC(dir, type, nr, size)`（asm-generic/ioctl.h。x86_64・aarch64 共通: nr 8 bit・type 8 bit・size 14 bit・dir 2 bit）。
const fn ioc(dir: u64, nr: u64, size: u64) -> u64 {
    (dir << 30) | (size << 16) | (SECCOMP_IOC_MAGIC << 8) | nr
}
const IOC_WRITE: u64 = 1;
const IOC_READ: u64 = 2;
const SECCOMP_IOCTL_NOTIF_RECV: u64 = ioc(IOC_READ | IOC_WRITE, 0, 80);
const SECCOMP_IOCTL_NOTIF_SEND: u64 = ioc(IOC_READ | IOC_WRITE, 1, 24);
const SECCOMP_IOCTL_NOTIF_ID_VALID: u64 = ioc(IOC_WRITE, 2, 8);

const ENOENT_ERRNO: i32 = 2;
const EPERM_ERRNO: i32 = 1;
const POLLERR: i16 = 0x08;
const POLLHUP: i16 = 0x10;

/// `struct seccomp_data`（64 バイト）。引数と命令ポインタは `SeccompNotification` に公開しない（TOCTOU）。
#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

/// `struct seccomp_notif`（80 バイト）。
#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

/// `struct seccomp_notif_resp`（24 バイト）。
#[repr(C)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

/// 受信した通知のうち、記録に使う値だけ（引数・命令ポインタは持たない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RawNotification {
    pub(crate) id: u64,
    /// 受信側（listener）の PID namespace での対象 TID。
    pub(crate) pid: u32,
    pub(crate) nr: i32,
    pub(crate) arch: u32,
}

/// [`poll_listener`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerPoll {
    /// 時間切れ（通知なし）。
    Idle,
    /// 未処理の通知がある。
    Readable,
    /// filter の利用者がいない（`POLLHUP`）か fd の異常。通知は来ない。
    Closed,
}

/// listener fd を最大 `timeout_ms` 待つ。`POLLIN` と `POLLHUP` / `POLLERR` を区別する（HUP を読み取り可能と取り違えない）。
/// `EINTR` は `Idle` として返す（呼び出し側のループが停止フラグを見て再試行する）。
pub(crate) fn poll_listener(fd: BorrowedFd<'_>, timeout_ms: i32) -> Result<ListenerPoll, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut pfd = PollFd {
        fd: fd.as_raw_fd(),
        events: consts::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` はスタック上の初期化済み 1 要素で、`nfds` = 1 と一致する。カーネルは呼び出しの間だけ `revents` を書く。
    let r = unsafe { poll(&raw mut pfd, 1, timeout_ms) };
    if r < 0 {
        return match last_error() {
            SysError::Os(e) if e == super::EINTR => Ok(ListenerPoll::Idle),
            other => Err(other),
        };
    }
    if r == 0 {
        return Ok(ListenerPoll::Idle);
    }
    // 未処理の通知が残っていれば HUP と同時でも先に読む（取りこぼさない）。
    if pfd.revents & consts::POLLIN != 0 {
        Ok(ListenerPoll::Readable)
    } else if pfd.revents & (POLLHUP | POLLERR) != 0 {
        Ok(ListenerPoll::Closed)
    } else {
        Ok(ListenerPoll::Idle)
    }
}

/// 通知を 1 件受信する。対象が既に消えていた(`ENOENT`)か、待機中の通知が無かった(`O_NONBLOCK` の `EAGAIN`)、
/// または `EINTR` で割り込まれたときは `Ok(None)`(`EINTR` は再試行せず、呼び出し側が停止要求を確かめてから再び poll する。REPAIR-5)。
/// 呼び出し前に [`poll_listener`] で `Readable` を確認し、同時の読み手を 1 本に保つこと。`RECV` は `O_NONBLOCK` を
/// 見ず、通知が無いまま呼ぶと到着まで待つ。単独の読み手が `Readable` の直後に呼ぶ限り、取り消された通知は
/// `ENOENT` で戻る(`exec::SeccompListener::receive` が同時受信を 1 本に限る)。
pub(crate) fn notif_recv(fd: BorrowedFd<'_>) -> Result<Option<RawNotification>, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // カーネルは全体が 0 であることを要求する（0 以外は EINVAL）。
    let mut notif = SeccompNotif {
        id: 0,
        pid: 0,
        flags: 0,
        data: SeccompData {
            nr: 0,
            arch: 0,
            instruction_pointer: 0,
            args: [0; 6],
        },
    };
    // SAFETY: `notif` は 80 バイトの `#[repr(C)]` で初期化済み・書き込み可能。`RECV` の要求サイズ(80)と一致し、
    // カーネルは呼び出しの間だけそれへ書く。`fd` は生存中の `BorrowedFd`。
    let rc = unsafe {
        ffi_ioctl!(
            fd.as_raw_fd(),
            SECCOMP_IOCTL_NOTIF_RECV,
            &raw mut notif as usize as u64,
        )
    };
    if rc == -1 {
        return match last_error() {
            SysError::Os(e) if e == ENOENT_ERRNO || e == super::EAGAIN || e == super::EINTR => {
                Ok(None)
            }
            other => Err(other),
        };
    }
    Ok(Some(RawNotification {
        id: notif.id,
        pid: notif.pid,
        nr: notif.data.nr,
        arch: notif.data.arch,
    }))
}

/// `id` の通知が受信済みで応答待ちか（`ID_VALID`）。pid の再利用・対象の終了を見分ける cookie 検証。
pub(crate) fn notif_id_valid(fd: BorrowedFd<'_>, id: u64) -> Result<bool, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut id = id;
    // SAFETY: `id` はスタック上の `u64` で、`ID_VALID` が読む 8 バイトと一致する。読み取りのみで状態を変えない。
    let rc = unsafe {
        ffi_ioctl!(
            fd.as_raw_fd(),
            SECCOMP_IOCTL_NOTIF_ID_VALID,
            &raw mut id as usize as u64,
        )
    };
    if rc == 0 {
        return Ok(true);
    }
    match last_error() {
        SysError::Os(e) if e == ENOENT_ERRNO => Ok(false),
        other => Err(other),
    }
}

/// `id` の通知へ `-EPERM`（`val` = 0・`flags` = 0）で応答する。応答の種類はこの 1 つだけ（許可に倒す応答は持たない）。
/// 対象が既に消えていた（`ENOENT`）ときは `Ok(false)`、送れたら `Ok(true)`。
pub(crate) fn notif_send_eperm(fd: BorrowedFd<'_>, id: u64) -> Result<bool, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut resp = SeccompNotifResp {
        id,
        val: 0,
        error: -EPERM_ERRNO,
        flags: 0,
    };
    // `EINTR` は応答が届いていないだけなので、上限つきで同じ応答を再送する(受信済みの通知は再受信できず、
    // 応答を落とすと対象が待ち続けるため。REPAIR-5)。
    let mut attempts = 0;
    loop {
        attempts += 1;
        // SAFETY: `resp` はスタック上の 24 バイトの `#[repr(C)]` で、`SEND` が読むサイズ（24）と一致する。
        // カーネルは呼び出しの間だけ読み、ポインタを保持しない。
        let rc = unsafe {
            ffi_ioctl!(
                fd.as_raw_fd(),
                SECCOMP_IOCTL_NOTIF_SEND,
                &raw mut resp as usize as u64,
            )
        };
        if rc == 0 {
            return Ok(true);
        }
        match last_error() {
            SysError::Os(e) if e == ENOENT_ERRNO => return Ok(false),
            SysError::Os(e) if e == super::EINTR && attempts < SEND_EINTR_ATTEMPTS => {}
            other => return Err(other),
        }
    }
}

/// `SEND` が `EINTR` で戻ったときの再送の上限。
const SEND_EINTR_ATTEMPTS: u32 = 8;

#[cfg(all(
    test,
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

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
        assert_eq!(CONTROL_CAP, 64);
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

    /// 同じ pipe の書き端の複製を `n` 本作る（受信側が漏らさず閉じたかを読み端の EOF で見るため）。
    fn dup_writers(n: usize) -> (std::io::PipeReader, Vec<OwnedFd>) {
        let (r, w) = std::io::pipe().unwrap();
        let w = OwnedFd::from(w);
        let mut v = vec![w.try_clone().unwrap()];
        for _ in 1..n {
            v.push(w.try_clone().unwrap());
        }
        drop(w);
        (r, v)
    }

    /// 読み端が EOF（書き端がすべて閉じた）まで 5 秒以内に達するか。
    fn reader_hits_eof(r: &std::io::PipeReader) -> bool {
        use std::io::Read as _;
        let mut pfd = PollFd {
            fd: r.as_raw_fd(),
            events: consts::POLLIN,
            revents: 0,
        };
        // SAFETY: 試験用。`pfd` は初期化済みの 1 要素で nfds = 1。
        let rc = unsafe { poll(&raw mut pfd, 1, 5000) };
        let mut b = [0u8; 1];
        rc == 1 && (&*r).read(&mut b).unwrap() == 0
    }

    /// SEC-4・REPAIR-5（#2372）: `MAX_RECV_FDS` 本ちょうどと資格情報は切り詰められずに届く。
    #[test]
    fn sec4_2372_control_buffer_holds_exactly_max_fds_and_creds() {
        let (a, b) = unix_seqpacket_pair().unwrap();
        set_passcred(b.as_fd()).unwrap();
        let (_r, ws) = dup_writers(MAX_RECV_FDS);
        let bs: Vec<BorrowedFd<'_>> = ws.iter().map(AsFd::as_fd).collect();
        send_fds_with_token(a.as_fd(), b'L', &bs).unwrap();
        let got = recv_fd_with_creds(b.as_fd()).unwrap();
        assert!(!got.truncated);
        assert_eq!(got.fds.len(), MAX_RECV_FDS);
        assert_eq!(
            got.creds.unwrap().pid,
            i32::try_from(std::process::id()).unwrap()
        );
    }

    /// SEC-4・REPAIR-5（#2372）: 上限超過の fd は切り詰められ、超過分は受信側に漏れず閉じられる。
    #[test]
    fn sec4_2372_excess_fds_are_truncated_and_released() {
        let (a, b) = unix_seqpacket_pair().unwrap();
        set_passcred(b.as_fd()).unwrap();
        let (r, ws) = dup_writers(MAX_RECV_FDS + 1);
        let bs: Vec<BorrowedFd<'_>> = ws.iter().map(AsFd::as_fd).collect();
        send_fds_with_token(a.as_fd(), b'L', &bs).unwrap();
        drop(bs);
        drop(ws);
        let got = recv_fd_with_creds(b.as_fd()).unwrap();
        assert!(got.truncated);
        assert_eq!(got.fds.len(), MAX_RECV_FDS);
        assert!(got.creds.is_some());
        drop(got);
        assert!(reader_hits_eof(&r), "an excess fd leaked to the receiver");
    }

    /// SEC-4・REPAIR-5（#2372）: 空の socket でも `recv_fd_with_creds` は待たずに `EAGAIN` を返す。
    #[test]
    fn sec4_2372_recv_does_not_block_on_empty_socket() {
        let (a, b) = unix_seqpacket_pair().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let h = std::thread::spawn(move || {
            let r = recv_fd_with_creds(b.as_fd()).map(|_| ());
            let _ = tx.send(r);
        });
        let r = rx.recv_timeout(std::time::Duration::from_secs(5));
        assert!(matches!(r, Ok(Err(SysError::Os(e))) if e == super::super::EAGAIN));
        h.join().unwrap();
        drop(a);
    }

    /// 送信本数は `1..=SEND_MAX_FDS`。範囲外は `EINVAL`。
    #[test]
    fn sec4_2372_send_rejects_out_of_range_fd_counts() {
        let (a, _b) = unix_seqpacket_pair().unwrap();
        assert_eq!(
            send_fds_with_token(a.as_fd(), b'L', &[]),
            Err(SysError::Os(EINVAL))
        );
        let (_r, ws) = dup_writers(SEND_MAX_FDS + 1);
        let bs: Vec<BorrowedFd<'_>> = ws.iter().map(AsFd::as_fd).collect();
        assert_eq!(
            send_fds_with_token(a.as_fd(), b'L', &bs),
            Err(SysError::Os(EINVAL))
        );
    }

    /// SEC-4（#2025）: 通知まわりの構造体と ioctl 番号は uapi と一致する（出典: include/uapi/linux/seccomp.h v6.12）。
    #[test]
    fn sec4_2025_notif_layouts_and_ioctl_numbers_match_uapi() {
        assert_eq!(core::mem::size_of::<SeccompData>(), 64);
        assert_eq!(core::mem::size_of::<SeccompNotif>(), 80);
        assert_eq!(core::mem::size_of::<SeccompNotifResp>(), 24);
        assert_eq!(core::mem::offset_of!(SeccompNotif, data), 16);
        assert_eq!(core::mem::offset_of!(SeccompData, args), 16);
        assert_eq!(core::mem::offset_of!(SeccompNotifResp, error), 16);
        assert_eq!(SECCOMP_IOCTL_NOTIF_RECV, 0xC050_2100);
        assert_eq!(SECCOMP_IOCTL_NOTIF_SEND, 0xC018_2101);
        assert_eq!(SECCOMP_IOCTL_NOTIF_ID_VALID, 0x4008_2102);
        assert_eq!((POLLERR, POLLHUP), (0x08, 0x10));
    }

    /// `fcntl` の固定値は x86_64・aarch64 とも asm-generic の値（`F_GETFL`=3・`F_SETFL`=4）と一致する。
    #[test]
    fn sec4_2025_fcntl_flag_constants_match_uapi() {
        assert_eq!((consts::F_GETFL, consts::F_SETFL), (3, 4));
    }
}
