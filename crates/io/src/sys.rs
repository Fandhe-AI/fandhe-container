//! syscall・FFI の薄いラッパー（`crates/io` の `sys` モジュール。`unsafe`
//! 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・オーナー決定
//! 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crates/io/src/server.rs`（TASK-13.2.1・#820）が accept した UDS 接続の
//! peer credential を検証する（PLUG-12・security.md「UDS は所有者・権限・
//! symlink を検証してから bind し、別 UID からの接続は peer credential 検証で
//! 切断する」）ために、std だけでは取得できない次の値を FFI で直接取得する。
//! `libc` / `nix` は依存追加が禁止されている
//! （dependency-policy。`std::os::unix::net::UnixStream::peer_cred` は
//! unstable のため使えない）ため、本モジュールが必要最小限のラッパーを持つ。
//!
//! - Linux: `getsockopt(2)` の `SOL_SOCKET`/`SO_PEERCRED` で接続元の
//!   `struct ucred`（pid・接続時点の実効 uid・gid）を取得する
//! - macOS: `getpeereid(2)` で接続元の接続時点の実効 uid・gid を取得する
//! - 両 OS 共通: `geteuid(2)` で自プロセスの実効 uid を取得する
//!   （bind したプロセス自身の実効 uid。`crate::server::imp::check_socket_owner`
//!   が親ディレクトリ所有者との照合に使う）
//!
//! # 「実 uid」ではなく「接続時点の実効 uid（euid）」（H2・#820
//! security-auditor 指摘対応）
//! `SO_PEERCRED` が返す `struct ucred.uid` も `getpeereid(2)` が返す値も、
//! 接続元プロセスの実 uid（real uid）ではなく、接続を確立した時点の実効 uid
//! （effective uid・euid）である（setuid されたプロセスが接続した場合、
//! 実 uid とは異なりうる）。また、接続元が本プロセスとは別の user namespace
//! に属する場合、その uid が本プロセス側の namespace にマッピングされて
//! いなければ `overflowuid`（Linux の既定値 `65534`）として観測されることが
//! あり、この場合も本プロセスの実効 uid とは一致せず拒否される
//! （`crate::server` モジュール doc「peer credential の検証」節参照）。
//!
//! # 契約（事前承認の条件を満たす設計）
//! - `unsafe fn` はこのモジュールの外へ公開しない。公開するのは安全な関数
//!   （[`peer_uid`]・[`effective_uid`]）のみで、`unsafe` はこのモジュール内に
//!   閉じる
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` で
//!   理由と維持すべき不変条件を明記する
//! - `fd` は呼び出し元が `&UnixStream` を借用し続けている間だけ渡される
//!   （[`peer_uid`] のシグネチャが `&UnixStream` を要求するため、呼び出しの間
//!   fd がクローズされないことを型で保証する）
//! - syscall の定数（`SOL_SOCKET`・`SO_PEERCRED`）はアーキテクチャごとに
//!   `cfg(target_arch = ...)` で個別に定義し、値が同じであっても他アーキ
//!   テクチャの定義を流用しない（coding-rust.md）。対応していない
//!   アーキテクチャでは [`IoErrorCode::Unimplemented`] を返す（fail-closed）
//! - `extern "C"` の引数の型・幅は Linux の glibc/musl・macOS の libSystem の
//!   宣言に合わせる（`socklen_t` は `u32`、`uid_t`/`gid_t` は `u32`、`c_int` は
//!   `i32`）
//! - 戻り値が `-1` の場合は `std::io::Error::last_os_error()` で errno を
//!   拾う

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

use crate::error::{IoError, IoErrorCode};

/// [`io::Error::last_os_error`] を [`IoError`] へ変換する（本モジュール限定の
/// ヘルパー。相手側〔untrusted〕由来の文字列は含まないため、そのまま
/// `Display` した errno の説明文を使ってよい）。
fn last_os_error_to_ioerror(context: &str) -> IoError {
    IoError::new(
        IoErrorCode::Internal,
        format!("{context}: {}", io::Error::last_os_error()),
    )
}

#[cfg(target_os = "linux")]
mod linux {
    //! Linux の `getsockopt(SOL_SOCKET, SO_PEERCRED)` 用の FFI 宣言・定数。

    /// `linux/socket.h` の `struct ucred` と同じレイアウト（`#[repr(C)]` で
    /// 固定）。フィールド名・型は glibc/musl と一致させる。
    #[repr(C)]
    pub(super) struct Ucred {
        pub pid: i32,
        pub uid: u32,
        pub gid: u32,
    }

    /// `struct ucred` のバイト長（コンパイル時定数）。
    pub(super) const UCRED_SIZE: usize = core::mem::size_of::<Ucred>();

    // UCRED_SIZE は u32 に収まらなければならない不変条件をコンパイル時に
    // 保証する（H5・#820 security-auditor 指摘対応。`struct ucred` は
    // pid/uid/gid の 3 フィールドのみで実際には 12 バイトだが、将来
    // フィールドが増えても `optlen` に渡す `u32` の範囲を超えないことを
    // 明示し、`peer_uid` 側で実行時に panic しうる
    // `u32::try_from(...).expect(...)` を使わずに済むようにする）。
    const _: () = assert!(UCRED_SIZE <= u32::MAX as usize);

    /// `getsockopt` の `optlen` に渡す `struct ucred` のバイト長（`u32`）。
    /// 上記の `const assert` により `as u32` での切り捨ては発生しない
    /// （コンパイル時に不変条件を保証済みのキャストであり、実行時に
    /// panic する経路を持たない。H5・#820 security-auditor 指摘対応）。
    pub(super) const UCRED_LEN: u32 = UCRED_SIZE as u32;

    // SOL_SOCKET・SO_PEERCRED の値は asm-generic の socket.h 由来で x86_64・
    // aarch64 双方とも同じ値（1・17）だが、coding-rust.md の「定数を流用
    // しない」方針に従い、アーキテクチャごとに個別の定数として定義する
    // （どちらかの値を将来アーキ固有に変更した場合、もう一方の cfg 分岐は
    // 影響を受けない）。
    #[cfg(target_arch = "x86_64")]
    pub(super) const SOL_SOCKET: i32 = 1;
    #[cfg(target_arch = "x86_64")]
    pub(super) const SO_PEERCRED: i32 = 17;

    #[cfg(target_arch = "aarch64")]
    pub(super) const SOL_SOCKET: i32 = 1;
    #[cfg(target_arch = "aarch64")]
    pub(super) const SO_PEERCRED: i32 = 17;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX / glibc / musl の
        // `int getsockopt(int sockfd, int level, int optname, void *optval,
        // socklen_t *optlen)` と同じ引数の型・幅（`socklen_t` は `u32`）で
        // 宣言している。呼び出し側の不変条件は呼び出し箇所（`peer_uid`）の
        // SAFETY コメントを参照。
        pub(super) fn getsockopt(
            sockfd: i32,
            level: i32,
            optname: i32,
            optval: *mut core::ffi::c_void,
            optlen: *mut u32,
        ) -> i32;
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: macOS libSystem の
    // `int getpeereid(int socket, uid_t *euid, gid_t *egid)` と同じ引数の
    // 型・幅（`uid_t`/`gid_t` は `u32`）で宣言している。呼び出し側の不変条件は
    // 呼び出し箇所（`peer_uid`）の SAFETY コメントを参照。
    fn getpeereid(socket: i32, euid: *mut u32, egid: *mut u32) -> i32;
}

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `uid_t geteuid(void)` と同じ
    // 戻り値の型・幅（`uid_t` は `u32`）で宣言している。引数を取らず、
    // POSIX 上エラーを返さない（呼び出し自体が失敗する経路はない）。
    fn geteuid() -> u32;
}

/// 接続済みの `stream` の相手側（接続元）の、接続時点の実効 uid（euid）を
/// 取得する（PLUG-12・security.md。実 uid ではない点・user namespace の外の
/// uid が `overflowuid` として見える点はモジュール doc 参照。H2・#820
/// security-auditor 指摘対応）。
///
/// `stream` を借用し続けている間だけ有効な fd を渡すため、呼び出し中に
/// fd がクローズされることはない。取得できない場合（syscall 失敗・
/// 対応していないアーキテクチャ）は [`IoError`] を返す（呼び出し元
/// （`crate::server::imp::verify_peer_credential`）が fail-closed に扱う）。
#[cfg(target_os = "linux")]
pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32, IoError> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let fd = stream.as_raw_fd();
        let mut ucred = linux::Ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        // H5・#820 security-auditor 指摘対応: 実行時に panic しうる
        // `u32::try_from(...).expect(...)` を使わず、コンパイル時に不変条件を
        // 保証済みの定数（`linux::UCRED_LEN`）を使う。
        let mut len = linux::UCRED_LEN;

        // SAFETY: fd は呼び出し元が `&UnixStream` を借用し続けている間だけ
        // 有効（呼び出しが終わるまでクローズされない）。`optval` は
        // スタック上の `ucred`（`#[repr(C)]` で `struct ucred` と同じ
        // レイアウト）を指す有効なポインタで、`optlen` はその構造体サイズを
        // 指す有効なポインタ。戻り値 `-1` は呼び出し直後に
        // `io::Error::last_os_error()` で拾う。
        let rc = unsafe {
            linux::getsockopt(
                fd,
                linux::SOL_SOCKET,
                linux::SO_PEERCRED,
                (&raw mut ucred).cast(),
                &raw mut len,
            )
        };
        if rc == -1 {
            return Err(last_os_error_to_ioerror("getsockopt(SO_PEERCRED) failed"));
        }
        if len as usize != linux::UCRED_SIZE {
            return Err(IoError::new(
                IoErrorCode::Internal,
                "getsockopt(SO_PEERCRED) returned an unexpected ucred size",
            ));
        }
        Ok(ucred.uid)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        // このアーキテクチャ向けの SOL_SOCKET/SO_PEERCRED 定数を持たないため、
        // 検証できない接続は fail-closed で拒否する（モジュール doc参照）。
        let _ = stream;
        Err(IoError::new(
            IoErrorCode::Unimplemented,
            "peer credential verification is not implemented for this architecture",
        ))
    }
}

/// macOS 版 [`peer_uid`]（`getpeereid(2)`）。
#[cfg(target_os = "macos")]
pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32, IoError> {
    let fd = stream.as_raw_fd();
    let mut euid: u32 = 0;
    let mut egid: u32 = 0;

    // SAFETY: fd は呼び出し元が `&UnixStream` を借用し続けている間だけ有効。
    // `euid`/`egid` へのポインタはどちらもスタック上のローカル変数を指す
    // 有効なポインタ。戻り値 `-1` は呼び出し直後に
    // `io::Error::last_os_error()` で拾う。
    let rc = unsafe { getpeereid(fd, &raw mut euid, &raw mut egid) };
    if rc == -1 {
        return Err(last_os_error_to_ioerror("getpeereid failed"));
    }
    Ok(euid)
}

/// 自プロセスの実効 uid を取得する（`geteuid(2)`）。
///
/// POSIX 上 `geteuid` はエラーを返さないため、本関数は `Result` を返さない。
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: 引数を取らず、POSIX の規定上エラー条件を持たない
    // （常に呼び出し元プロセスの実効 uid を返す）。
    unsafe { geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// E・#820（PLUG-12）: `effective_uid` はプロセスの実行ユーザーの uid を
    /// 返し、成功する（呼び出しが panic しないことと、`libc` の `geteuid(2)`
    /// と同じ意味論で非負の `u32` を返すことの確認。テスト実行ユーザーの
    /// 実際の uid は環境依存のため具体値までは固定しない）。
    #[test]
    fn e_820_effective_uid_returns_without_panicking() {
        let uid = effective_uid();
        // `geteuid()` の戻り値そのものであり、追加の意味論的な検証はできない
        // （負値を表現できない u32 のため、これ自体が範囲検証を兼ねる）。
        let _ = uid;
    }

    /// E・#820（PLUG-12）: 自分自身に接続した UDS ソケットの相手側 uid は、
    /// 自プロセスの実効 uid と一致する（同一プロセス内の自己接続のため）。
    #[test]
    fn e_820_peer_uid_of_self_connected_socket_matches_effective_uid() {
        let (a, _b) = UnixStream::pair().expect("must be able to create a socket pair");
        let expected = effective_uid();

        match peer_uid(&a) {
            Ok(uid) => assert_eq!(uid, expected),
            Err(err) => {
                // 対応していないアーキテクチャ（Unimplemented）のみ許容する。
                assert_eq!(err.code(), IoErrorCode::Unimplemented, "err={err:?}");
            }
        }
    }
}
