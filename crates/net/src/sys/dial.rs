//! `netns_dial::verify`（`crate::netns_dial::verify`。CRI-6・NET-3・SEC-1・#4478）が使う `SIOCGSKNS` の薄いラッパー
//! （`crates/net` の `sys` モジュールの子。`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節）。
//!
//! # 呼び出し文脈
//! plugin-cri が `netns-dial` helper から受け取った接続済み fd が、保持役の netns に属することを
//! `verify_dialed_socket` が確かめるときの 1 回の `ioctl(SIOCGSKNS)` だけ。
//!
//! # カーネルの要求（v6.12 の一次情報。`gh api repos/torvalds/linux/contents/<path>?ref=v6.12` で確認）
//! - `net/socket.c:1313-1318` の `case SIOCGSKNS:` は `ns_capable(net->user_ns, CAP_NET_ADMIN)` を要求し、
//!   満たさなければ `EPERM`。`net` は socket が属する netns で、対象は「その netns を所有する user namespace」での
//!   `CAP_NET_ADMIN`（呼び出しプロセスの現在の cred で判定。`kernel/capability.c:381`・LSM の `security_capable` も通る）
//! - 親 user namespace にいる、所有者と同じ euid は全 capability を持つ（`security/commoncap.c:92`）。pod の user
//!   namespace は plugin-cri と同じ euid が作るため、本番の成功経路はこの規則で成り立つ
//! - host netns の socket の所有 userns は init_user_ns で、非 root は `CAP_NET_ADMIN` を持たず `EPERM` になる。
//!   これは verify にとって fail-closed の拒否経路で、`SIOCGSKNS` の失敗では照合を飛ばさない
//! - 返る fd は `open_namespace`（`fs/nsfs.c:95`・`:106`）が新規に割り当てた `O_CLOEXEC` の nsfs fd
//!
//! # `libc` 照合
//! 定数と関数型は `libc_abi` で `libc` と `const` 評価で照合する。`ioctl` の第 2 引数は gnu では `c_ulong`、musl では
//! `c_int` で自前宣言（`u64`）と一致しないため、関数型の照合は gnu に限る（core の `sys.rs` と同じ扱い）。

use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};

use super::{SysError, last_error};

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
mod consts {
    pub const SUPPORTED: bool = true;
    /// `SIOCGSKNS`（`include/uapi/linux/sockios.h:111`）。
    pub const SIOCGSKNS: u64 = 0x894C;
}

#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
mod consts {
    pub const SUPPORTED: bool = true;
    /// `SIOCGSKNS`（`include/uapi/linux/sockios.h:111`）。
    pub const SIOCGSKNS: u64 = 0x894C;
}

#[cfg(not(any(
    all(target_arch = "x86_64", target_pointer_width = "64"),
    all(target_arch = "aarch64", target_pointer_width = "64")
)))]
mod consts {
    pub const SUPPORTED: bool = false;
    pub const SIOCGSKNS: u64 = 0;
}

// SAFETY（宣言そのものの妥当性）: Linux の libc が公開する C 関数の宣言。原型は
// `int ioctl(int fd, unsigned long request, ...)`（musl は第 2 引数が `int`。LP64 の x86_64・aarch64 では
// レジスタ渡しが同じで、値は 0x894C と小さい）。呼び出し側の不変条件は `unsafe` ブロックの SAFETY に記す。
unsafe extern "C" {
    fn ioctl(fd: i32, request: u64, ...) -> i32;
}

/// socket が属する netns の nsfs fd を得る（`ioctl(SIOCGSKNS)`）。
///
/// `fd` はソケットでなければ `Os(ENOTTY)`、権限不足（上記の `CAP_NET_ADMIN`）なら `Os(EPERM)`。成功時の fd は
/// 呼び出し側が所有し（drop で閉じる）、`fstat` の (dev, ino) が netns の素性になる。
pub(crate) fn socket_netns(fd: BorrowedFd<'_>) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `fd` は生存中の `BorrowedFd`。`SIOCGSKNS` は第 3 引数を取らず、ユーザーメモリを読み書きしない
    // （戻り値として新しい fd を返すだけ）。
    let rc = unsafe { ioctl(fd.as_raw_fd(), consts::SIOCGSKNS) };
    if rc < 0 {
        return Err(last_error());
    }
    // SAFETY: 成功した `ioctl(SIOCGSKNS)` が `open_namespace` でこの呼び出しのために新規に割り当てた fd で、
    // 他に所有者がいない。
    Ok(unsafe { OwnedFd::from_raw_fd(rc) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::MetadataExt as _;

    /// SEC-1・NET-3・#4478: ソケットでない fd は `ENOTTY`（25）。
    #[test]
    fn sec1_net3_4478_socket_netns_rejects_non_socket_with_enotty() {
        let f = std::fs::File::open("/dev/null").expect("open");
        assert_eq!(
            socket_netns(f.as_fd()).map(|_| ()).unwrap_err(),
            SysError::Os(25)
        );
    }

    /// 自プロセスの netns の socket では、成功すれば `/proc/thread-self/ns/net` と同じ (dev, ino)。
    /// 権限不足なら `EPERM` だけを許す（非 root の init netns の socket は常にこちら）。
    #[test]
    fn sec1_net3_4478_socket_netns_matches_current_or_eperm() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        match socket_netns(l.as_fd()) {
            Ok(nsfd) => {
                let got = std::fs::File::from(nsfd).metadata().expect("stat");
                let me = std::fs::metadata("/proc/thread-self/ns/net").expect("stat");
                assert_eq!((got.dev(), got.ino()), (me.dev(), me.ino()));
            }
            Err(e) => assert_eq!(e, SysError::Os(1)),
        }
    }
}

/// 自前 FFI 宣言と `libc`（dev-dependencies のみ）の `const` 評価による機械照合（#1837・REPAIR-12。
/// `docs/design/ffi-libc-check.md`）。`ioctl` の関数型は gnu に限る（上記）。
#[cfg(all(
    test,
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod libc_abi {
    use super::{consts, ioctl};

    // gnu の `libc::SIOCGSKNS` は `c_ulong`（x86_64・aarch64 では u64）。
    #[cfg(target_env = "gnu")]
    const _: () = assert!(consts::SIOCGSKNS == libc::SIOCGSKNS);
    // musl の `libc::Ioctl` は `c_int` のため、符号なし 64 bit へ広げて比べる。
    #[cfg(not(target_env = "gnu"))]
    #[allow(clippy::unnecessary_cast)]
    const _: () = assert!(consts::SIOCGSKNS == libc::SIOCGSKNS as u32 as u64);

    #[cfg(target_env = "gnu")]
    const _: unsafe extern "C" fn(libc::c_int, libc::c_ulong, ...) -> libc::c_int = ioctl;
    #[cfg(target_env = "gnu")]
    const _: unsafe extern "C" fn(libc::c_int, libc::c_ulong, ...) -> libc::c_int = libc::ioctl;
    // musl では関数型の照合を行わない（第 2 引数が `c_int` で自前の `u64` と一致しないため）。
    #[cfg(not(target_env = "gnu"))]
    const _: unsafe extern "C" fn(i32, u64, ...) -> i32 = ioctl;
}
