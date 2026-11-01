//! cri crate の唯一の `unsafe` 境界（unix 限定）。shim v2 の UDS の所有者・peer UID の照合に使う
//! syscall の薄いラッパー（PLUG-12・SEC-1・CRI-5・#872）。
//!
//! # 呼び出し文脈
//! - `shim_v2::bootstrap`: ディレクトリ・socket の所有者を実効 uid と照合する（[`effective_uid`]）
//! - `shim_v2::server`: accept 直後、要求を読む前に接続元の uid を照合する（[`peer_uid`]）
//!
//! # 契約
//! - 安全な API だけを公開し、`unsafe fn` を外へ出さない
//! - 対応外の OS では [`peer_uid`] が `Err` を返す。呼び出し側は fail-closed（切断）にする
//! - 宣言は x86_64 / aarch64 の Linux と macOS で共通の値（`SOL_SOCKET = 1`・`SO_PEERCRED = 17` は Linux 側）
//!
//! # `libc` 照合について
//! 本 crate には `libc` の dev-dependency が無く（#1837 の子の issue で導入する）、機械照合は未導入。
//! 導入されるまで、定数と構造体の値は Linux uapi（`include/uapi/asm-generic/socket.h`・`struct ucred`）で確認した。

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

unsafe extern "C" {
    /// 実効 uid（失敗しない）。
    safe fn geteuid() -> u32;
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn getsockopt(
        fd: i32,
        level: i32,
        name: i32,
        value: *mut std::ffi::c_void,
        len: *mut u32,
    ) -> i32;
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn getpeereid(fd: i32, euid: *mut u32, egid: *mut u32) -> i32;
}

/// 呼び出しプロセスの実効 uid。
pub(crate) fn effective_uid() -> u32 {
    geteuid()
}

/// `struct ucred`（12 バイト）。`SO_PEERCRED` の結果。
#[cfg(target_os = "linux")]
#[repr(C)]
struct Ucred {
    pid: i32,
    uid: u32,
    gid: u32,
}

/// 接続元の実効 uid（Linux は `SO_PEERCRED`）。
#[cfg(target_os = "linux")]
pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32, ()> {
    const SOL_SOCKET: i32 = 1;
    const SO_PEERCRED: i32 = 17;
    let mut cred = Ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<Ucred>() as u32;
    // SAFETY: `cred`・`len` はスタック上の初期化済みローカルで、入力の `len` は `cred` の確保サイズ（12）。
    // カーネルはそれを超えて書かない。`stream` は生存中で、fd は呼び出しの間有効。
    let rc = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut len,
        )
    };
    if rc < 0 || len as usize != std::mem::size_of::<Ucred>() {
        return Err(());
    }
    Ok(cred.uid)
}

/// 接続元の実効 uid（macOS は `getpeereid`）。
#[cfg(target_os = "macos")]
pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32, ()> {
    let (mut uid, mut gid) = (0u32, 0u32);
    // SAFETY: `uid`・`gid` はスタック上のローカルで、有効な書き込み先。`stream` は生存中で fd は有効。
    let rc = unsafe { getpeereid(stream.as_raw_fd(), &raw mut uid, &raw mut gid) };
    if rc < 0 { Err(()) } else { Ok(uid) }
}

/// 対応外の unix では取得できない（呼び出し側は fail-closed にする）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn peer_uid(_stream: &UnixStream) -> Result<u32, ()> {
    Err(())
}
