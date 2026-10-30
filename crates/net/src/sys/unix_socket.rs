//! DNS ヘルパーの制御 UDS（`crate::dns_helper::control`。NET-5・PLUG-12・REPAIR-5・#3071）の送り手が使う、
//! 非ブロッキングの `AF_UNIX` / `SOCK_STREAM` connect の薄いラッパー（`crates/net` の `sys` モジュールの子。
//! `unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節）。
//!
//! # 役割と呼び出し文脈
//! 標準ライブラリの `UnixStream::connect` はブロッキングで、相手の `listen` backlog が埋まっていると無期限に止まりうる
//! （REPAIR-5）。そこで `SOCK_NONBLOCK` で `connect(2)` を 1 回だけ呼び、backlog が埋まっていれば `EAGAIN` を
//! 返す形にする（呼び出し側が `Timeout` に写す）。接続できたら呼び出し側が `UnixStream` へ変換し、
//! ブロッキングに戻して read / write の timeout を設定する。bind と accept は標準ライブラリで足りるため
//! ここには置かない。
//!
//! # 契約
//! - 親 `sys` と同じ（`unsafe fn` を公開しない・`SAFETY:` の明記・arch ごとの定数・戻り値 -1 は直後に errno）
//! - 経路は `sun_path` に収まる長さ（NUL を含めて 108 バイト以下）で、NUL を含まないものに限る。超えたら
//!   `Os(EINVAL)`（切り詰めて別のパスへ接続しない）。経路は呼び出し側が検査済みディレクトリの fd 起点
//!   （`/proc/self/fd/<fd>/dns.ctl`）で組む
//! - 作る fd は `SOCK_CLOEXEC`（exec 先へ漏らさない）
//!
//! # `libc` 照合
//! 定数・構造体・関数型は `libc_abi`（末尾）で `libc` と `const` 評価で照合する（#1837）。

use std::os::fd::{FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use super::{SysError, last_error};

/// `sockaddr_un.sun_path` の長さ（NUL を含む）。
pub(crate) const SUN_PATH_LEN: usize = 108;

// include/linux/socket.h・uapi/asm-generic/socket.h・fcntl.h の値（x86_64 / aarch64 とも同じ）。
#[cfg(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod consts {
    pub const SUPPORTED: bool = true;
    pub const AF_UNIX: u16 = 1;
    pub const SOCK_STREAM: i32 = 1;
    pub const SOCK_CLOEXEC: i32 = 0o2_000_000;
    pub const SOCK_NONBLOCK: i32 = 0o4_000;
}

#[cfg(not(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod consts {
    pub const SUPPORTED: bool = false;
    pub const AF_UNIX: u16 = 0;
    pub const SOCK_STREAM: i32 = 0;
    pub const SOCK_CLOEXEC: i32 = 0;
    pub const SOCK_NONBLOCK: i32 = 0;
}

/// `struct sockaddr_un`（include/uapi/linux/un.h。110 バイト）。
#[repr(C)]
struct SockaddrUn {
    sun_family: u16,
    sun_path: [u8; SUN_PATH_LEN],
}

const _: () = assert!(core::mem::size_of::<SockaddrUn>() == 110);

// SAFETY（宣言そのものの妥当性）: Linux の libc（glibc / musl 共通）が公開する C 関数の宣言で、引数・戻り値の型を
// 各項目の原型と一致させている。`socklen_t` は u32。ポインタ引数は `#[repr(C)]` でサイズを const assert した
// `SockaddrUn`（110 バイト）を指す。呼び出し側の不変条件は各 `unsafe` ブロックの SAFETY に記す。
unsafe extern "C" {
    // 原型: `int socket(int domain, int type, int protocol)`。
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    // 原型: `int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)`。
    fn connect(fd: i32, addr: *const SockaddrUn, addrlen: u32) -> i32;
}

/// `path` の UDS へ非ブロッキングで `connect(2)` する。接続済みの fd（非ブロッキング・close-on-exec）を返す。
///
/// 相手の backlog が埋まっていれば `Os(EAGAIN)`、listener が無ければ `Os(ECONNREFUSED)` / `Os(ENOENT)`。
/// `AF_UNIX` の `connect` は接続するか即座に失敗するかのどちらかで、`EINPROGRESS` で返ることはない。
pub(crate) fn connect_unix_nonblocking(path: &Path) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let bytes = path.as_os_str().as_bytes();
    // NUL を含めて `sun_path` に収める。内部の NUL は C 文字列として別のパスに切れるため拒否する。
    if bytes.is_empty() || bytes.len() >= SUN_PATH_LEN || bytes.contains(&0) {
        return Err(SysError::Os(super::EINVAL));
    }
    let mut addr = SockaddrUn {
        sun_family: consts::AF_UNIX,
        sun_path: [0u8; SUN_PATH_LEN],
    };
    if let Some(dst) = addr.sun_path.get_mut(..bytes.len()) {
        dst.copy_from_slice(bytes);
    }
    // SAFETY: 引数はスタック上の整数定数のみで、ポインタを渡さない。成功時は新しい fd を返す。
    let raw = unsafe {
        socket(
            i32::from(consts::AF_UNIX),
            consts::SOCK_STREAM | consts::SOCK_CLOEXEC | consts::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(last_error());
    }
    // SAFETY: 成功した `socket(2)` が新規に割り当てた fd で、他に所有者がいない。以降の失敗でも drop で閉じる。
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // 先頭 2 バイト（family）+ 経路 + NUL の長さ。`sun_path` は 0 で初期化済みなので NUL は含まれている。
    let addrlen = (core::mem::size_of::<u16>() + bytes.len() + 1) as u32;
    // SAFETY: `addr` はスタック上の初期化済み `SockaddrUn`（110 バイト）で、`addrlen` は 110 以下（経路は 108 未満）。
    // カーネルは `addrlen` バイトだけ読む。`fd` は上で所有する生存中の fd。
    let rc = unsafe {
        connect(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            &raw const addr,
            addrlen,
        )
    };
    if rc < 0 {
        return Err(last_error());
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("fcdns-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// NET-5・#3071: listener があれば接続でき、無ければ ECONNREFUSED / ENOENT。
    #[test]
    fn net5_3071_connect_succeeds_and_fails_without_listener() {
        let p = scratch("ok");
        assert!(matches!(
            connect_unix_nonblocking(&p),
            Err(SysError::Os(e)) if e == super::super::ENOENT
        ));
        let l = UnixListener::bind(&p).expect("bind");
        let fd = connect_unix_nonblocking(&p).expect("connect");
        drop(fd);
        drop(l);
        // ソケットファイルは残るが listener は無い。
        assert!(matches!(connect_unix_nonblocking(&p), Err(SysError::Os(_))));
        let _ = std::fs::remove_file(&p);
    }

    /// NET-5・REPAIR-5・#3071: backlog が埋まった listener への接続は止まらず EAGAIN で返る。
    #[test]
    fn net5_3071_connect_returns_eagain_when_backlog_is_full() {
        let p = scratch("full");
        let l = UnixListener::bind(&p).expect("bind");
        let mut connects = 0usize;
        let mut got_eagain = false;
        // accept しないまま接続を重ねる。クライアント側の fd はすぐ閉じても、接続は accept 待ちの列に残って
        // backlog を使う（fd の上限に当たらない）。標準ライブラリの backlog は最大 somaxconn（通常 4096）。
        for _ in 0..20_000 {
            match connect_unix_nonblocking(&p) {
                Ok(fd) => {
                    connects += 1;
                    drop(fd);
                }
                Err(SysError::Os(e)) if e == super::super::EAGAIN => {
                    got_eagain = true;
                    break;
                }
                Err(e) => panic!("unexpected: {e:?}"),
            }
        }
        assert!(got_eagain, "never saw EAGAIN after {connects} connects");
        drop(l);
        let _ = std::fs::remove_file(&p);
    }

    /// NET-5・#3071: 長すぎる経路・NUL を含む経路・空は EINVAL（切り詰めて別の経路へ接続しない）。
    #[test]
    fn net5_3071_connect_rejects_bad_paths() {
        let long = std::path::PathBuf::from(format!("/{}", "a".repeat(SUN_PATH_LEN)));
        assert!(matches!(
            connect_unix_nonblocking(&long),
            Err(SysError::Os(e)) if e == super::super::EINVAL
        ));
        assert!(matches!(
            connect_unix_nonblocking(Path::new("")),
            Err(SysError::Os(e)) if e == super::super::EINVAL
        ));
        let nul = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/a\0b"));
        assert!(matches!(
            connect_unix_nonblocking(&nul),
            Err(SysError::Os(e)) if e == super::super::EINVAL
        ));
    }
}

/// 自前の宣言・定数・構造体の `libc` との機械照合（#1837・REPAIR-12。方式は `docs/design/ffi-libc-check.md`）。
#[cfg(all(
    test,
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod libc_abi {
    use super::{SUN_PATH_LEN, SockaddrUn, connect, consts, socket};
    use core::mem::{align_of, offset_of, size_of};

    // `AF_UNIX` は自前が `u16`（`sun_family` と同幅）、`libc` は `c_int`。範囲外なら評価エラーにして `u16` で比べる。
    const fn family(v: libc::c_int) -> u16 {
        assert!(v >= 0 && v <= 0xffff);
        v as u16
    }

    const _: () = {
        assert!(consts::AF_UNIX == family(libc::AF_UNIX));
        assert!(consts::SOCK_STREAM == libc::SOCK_STREAM);
        assert!(consts::SOCK_CLOEXEC == libc::SOCK_CLOEXEC);
        assert!(consts::SOCK_NONBLOCK == libc::SOCK_NONBLOCK);
        assert!(size_of::<u16>() == size_of::<libc::sa_family_t>());
        assert!(size_of::<SockaddrUn>() == size_of::<libc::sockaddr_un>());
        assert!(align_of::<SockaddrUn>() == align_of::<libc::sockaddr_un>());
        assert!(offset_of!(SockaddrUn, sun_family) == offset_of!(libc::sockaddr_un, sun_family));
        assert!(offset_of!(SockaddrUn, sun_path) == offset_of!(libc::sockaddr_un, sun_path));
        assert!(SUN_PATH_LEN == size_of::<[libc::c_char; 108]>());
    };

    const _: unsafe extern "C" fn(libc::c_int, libc::c_int, libc::c_int) -> libc::c_int = socket;
    const _: unsafe extern "C" fn(libc::c_int, libc::c_int, libc::c_int) -> libc::c_int =
        libc::socket;
    // `connect` の `sockaddr` 引数は自前の `SockaddrUn` と `libc::sockaddr` で型が違うため、他の引数だけを揃えた
    // 関数型で照合する（`sockaddr_un` の同一性は上の構造体照合が保証する）。
    const _: unsafe extern "C" fn(libc::c_int, *const SockaddrUn, libc::socklen_t) -> libc::c_int =
        connect;
    const _: unsafe extern "C" fn(
        libc::c_int,
        *const libc::sockaddr,
        libc::socklen_t,
    ) -> libc::c_int = libc::connect;
}
