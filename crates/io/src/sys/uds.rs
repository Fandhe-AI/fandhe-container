//! UDS クライアントの期限つき非ブロッキング `connect(2)`（`crates/io` の `sys` モジュール配下。
//! `unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::uds_client::UdsClientConnection::connect`（IO-1・PLUG-12・REPAIR-5。#3165）が、
//! パス検査の後・peer uid の照合の前に呼ぶ。std の `UnixStream::connect` は期限を持てず、
//! listener の backlog が満杯だと無期限にブロックしうるため、非ブロッキングの `connect` を
//! 5 ms 刻みで再試行して期限（`Instant`）で打ち切る（REPAIR-5）。`crates/plugin` の
//! `connect_unix` と同じ手順を io 側に持つ（io は plugin に依存できない）。
//!
//! # 契約（事前承認の条件を満たす設計）
//! - `unsafe fn` はこのモジュールの外へ公開しない。公開するのは安全な関数のみ
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` を付ける
//! - fd は `socket(2)` の成功直後に `UnixStream::from_raw_fd` で所有させ、どの失敗経路でも
//!   close される。作成時に close-on-exec を付ける（Linux は `SOCK_CLOEXEC`、macOS は
//!   `fcntl(F_SETFD)` で非原子。socket との間の窓は `crates/plugin` の #3262 と同じ残余）
//! - `sun_path` は空・NUL（抽象ソケットの先頭 NUL を含む）・上限超過を FFI に渡す前に拒否し、
//!   コピーは境界検査つき（`get_mut`）で行う
//! - 定数・構造体レイアウトは OS ごとに個別定義し、他 OS の定義を流用しない。Linux は
//!   LP64 の x86_64・aarch64 だけが対象で、それ以外は [`IoErrorCode::Unimplemented`]（fail-closed）

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Instant;

use crate::error::{IoError, IoErrorCode};

/// 対応する OS・アーキテクチャでの実装。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod imp {
    use std::os::fd::AsRawFd as _;
    use std::os::fd::FromRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::time::Duration;

    use super::*;

    pub(super) const AF_UNIX: i32 = 1;
    pub(super) const SOCK_STREAM: i32 = 1;
    /// `sun_path` の配列長（終端 NUL を含む）。
    #[cfg(target_os = "linux")]
    pub(super) const SUN_PATH_LEN: usize = 108;
    #[cfg(target_os = "macos")]
    pub(super) const SUN_PATH_LEN: usize = 104;
    /// `sun_path` の構造体先頭からのオフセット（Linux・macOS とも 2）。
    pub(super) const SUN_PATH_OFFSET: usize = 2;

    #[cfg(target_os = "linux")]
    pub(super) const SOCK_CLOEXEC: i32 = 0o2_000_000;
    #[cfg(target_os = "linux")]
    pub(super) const SOCK_NONBLOCK: i32 = 0o4000;
    #[cfg(target_os = "macos")]
    pub(super) const F_SETFD: i32 = 2;
    #[cfg(target_os = "macos")]
    pub(super) const FD_CLOEXEC: i32 = 1;

    // errno。Linux と macOS で値が違う。
    pub(super) const EPERM: i32 = 1;
    pub(super) const ENOENT: i32 = 2;
    pub(super) const EINTR: i32 = 4;
    pub(super) const ENOMEM: i32 = 12;
    pub(super) const EACCES: i32 = 13;
    pub(super) const ENOTDIR: i32 = 20;
    pub(super) const ENFILE: i32 = 23;
    pub(super) const EMFILE: i32 = 24;
    #[cfg(target_os = "linux")]
    pub(super) const EAGAIN: i32 = 11;
    #[cfg(target_os = "linux")]
    pub(super) const ENOTSOCK: i32 = 88;
    #[cfg(target_os = "linux")]
    pub(super) const EPROTOTYPE: i32 = 91;
    #[cfg(target_os = "linux")]
    pub(super) const ENOBUFS: i32 = 105;
    #[cfg(target_os = "linux")]
    pub(super) const EISCONN: i32 = 106;
    #[cfg(target_os = "linux")]
    pub(super) const ECONNREFUSED: i32 = 111;
    #[cfg(target_os = "linux")]
    pub(super) const EALREADY: i32 = 114;
    #[cfg(target_os = "linux")]
    pub(super) const EINPROGRESS: i32 = 115;
    #[cfg(target_os = "macos")]
    pub(super) const EAGAIN: i32 = 35;
    #[cfg(target_os = "macos")]
    pub(super) const EINPROGRESS: i32 = 36;
    #[cfg(target_os = "macos")]
    pub(super) const EALREADY: i32 = 37;
    #[cfg(target_os = "macos")]
    pub(super) const ENOTSOCK: i32 = 38;
    #[cfg(target_os = "macos")]
    pub(super) const EPROTOTYPE: i32 = 41;
    #[cfg(target_os = "macos")]
    pub(super) const ENOBUFS: i32 = 55;
    #[cfg(target_os = "macos")]
    pub(super) const EISCONN: i32 = 56;
    #[cfg(target_os = "macos")]
    pub(super) const ECONNREFUSED: i32 = 61;

    /// Linux の `struct sockaddr_un`（110 バイト）。
    #[cfg(target_os = "linux")]
    #[repr(C)]
    pub(super) struct SockaddrUn {
        pub(super) sun_family: u16,
        pub(super) sun_path: [u8; SUN_PATH_LEN],
    }
    #[cfg(target_os = "linux")]
    const _: () = assert!(core::mem::size_of::<SockaddrUn>() == 110);

    /// macOS の `struct sockaddr_un`（106 バイト）。
    #[cfg(target_os = "macos")]
    #[repr(C)]
    pub(super) struct SockaddrUn {
        pub(super) sun_len: u8,
        pub(super) sun_family: u8,
        pub(super) sun_path: [u8; SUN_PATH_LEN],
    }
    #[cfg(target_os = "macos")]
    const _: () = assert!(core::mem::size_of::<SockaddrUn>() == 106);

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX の `int socket(int, int, int)` と同じ型・幅。
        // `connect` は `sys::sock_raw` の共通宣言を使う。
        pub(super) fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    }

    /// `errno` を `IoError` へ写す。呼び出し側が渡した path に起因するものは `InvalidArgument`、
    /// 相手がいない・受け付けないものは `Unavailable`、資源不足は `ResourceExhausted`。
    /// 文言は固定の英語で、パスや相手由来の文字列を含めない。
    pub(super) fn map_connect_errno(errno: Option<i32>, err: &io::Error) -> IoError {
        match errno {
            Some(ENOENT | ECONNREFUSED) => IoError::new(
                IoErrorCode::Unavailable,
                "unix domain socket server is not available",
            ),
            Some(EACCES | EPERM | ENOTSOCK | EPROTOTYPE | ENOTDIR) => IoError::new(
                IoErrorCode::InvalidArgument,
                "unix domain socket path cannot be connected to",
            ),
            Some(EMFILE | ENFILE | ENOMEM | ENOBUFS) => IoError::new(
                IoErrorCode::ResourceExhausted,
                "out of resources while connecting to the unix domain socket",
            ),
            _ => IoError::new(
                IoErrorCode::Internal,
                format!("failed to connect to unix domain socket: {err}"),
            ),
        }
    }

    pub(super) fn connect_unix_until(
        path: &Path,
        deadline: Instant,
    ) -> Result<Option<UnixStream>, IoError> {
        let invalid = |msg: &'static str| IoError::new(IoErrorCode::InvalidArgument, msg);
        let bytes = path.as_os_str().as_bytes();
        // sun_path は終端 NUL を 1 バイト残す。先頭 NUL（抽象ソケット）もここで拒否する。
        if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= SUN_PATH_LEN {
            return Err(invalid(
                "socket path must be non-empty, free of NUL, and shorter than sun_path",
            ));
        }
        let mut addr = SockaddrUn {
            #[cfg(target_os = "macos")]
            sun_len: 0,
            #[cfg(target_os = "macos")]
            sun_family: AF_UNIX as u8,
            #[cfg(target_os = "linux")]
            sun_family: AF_UNIX as u16,
            sun_path: [0; SUN_PATH_LEN],
        };
        addr.sun_path
            .get_mut(..bytes.len())
            .ok_or_else(|| invalid("socket path does not fit in sun_path"))?
            .copy_from_slice(bytes);
        let addr_len = u32::try_from(SUN_PATH_OFFSET + bytes.len() + 1)
            .map_err(|_| invalid("socket path does not fit in sun_path"))?;
        #[cfg(target_os = "macos")]
        {
            addr.sun_len = u8::try_from(addr_len)
                .map_err(|_| invalid("socket path does not fit in sun_path"))?;
        }

        #[cfg(target_os = "linux")]
        let ty = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
        #[cfg(target_os = "macos")]
        let ty = SOCK_STREAM;
        // SAFETY: 引数は整数のみ。成否は戻り値で確認し、-1 は直後に errno を拾う。
        let fd = unsafe { socket(AF_UNIX, ty, 0) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            return Err(map_connect_errno(err.raw_os_error(), &err));
        }
        // SAFETY: `fd` は直前の socket が返した、他に所有者のいない有効な fd（非負を確認済み）。
        // 以降の失敗経路でも `UnixStream` の Drop で close される。
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        #[cfg(target_os = "macos")]
        {
            // 非原子（socket との間に窓がある。crates/plugin の #3262 と同じ残余）。
            // SAFETY: `fd` は `stream` が所有する有効な fd。F_SETFD は int 引数 1 つを取る。
            let rc = unsafe { super::super::full_fsync_raw::fcntl(fd, F_SETFD, FD_CLOEXEC) };
            if rc != 0 {
                let err = io::Error::last_os_error();
                return Err(map_connect_errno(err.raw_os_error(), &err));
            }
            stream
                .set_nonblocking(true)
                .map_err(|e| map_connect_errno(e.raw_os_error(), &e))?;
        }

        const RETRY_INTERVAL: Duration = Duration::from_millis(5);
        loop {
            // SAFETY: `fd` は `stream` が所有し生存中。`addr` はスタック上の `#[repr(C)]` な
            // `sockaddr_un` で、`addr_len` は先頭から有効な（NUL 終端込みの）バイト数
            // （構造体サイズ以下であることは上の長さ検査で保証）。
            let rc = unsafe {
                super::super::sock_raw::connect(
                    stream.as_raw_fd(),
                    (&raw const addr).cast(),
                    addr_len,
                )
            };
            if rc == 0 {
                return Ok(Some(stream));
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(EISCONN) => return Ok(Some(stream)),
                Some(EAGAIN | EINTR | EINPROGRESS | EALREADY) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Ok(None);
                    }
                    std::thread::sleep((deadline - now).min(RETRY_INTERVAL));
                }
                errno => return Err(map_connect_errno(errno, &err)),
            }
        }
    }
}

/// `path` の UDS へ `deadline` までに非ブロッキング connect する（IO-1・PLUG-12・REPAIR-5）。
///
/// 戻り値は `Ok(Some(stream))`（接続済み。**非ブロッキングのまま**で、呼び出し元が blocking へ
/// 戻す）、期限切れは `Ok(None)`。空・NUL（抽象ソケットを含む）・`sun_path` 超過は
/// `InvalidArgument`、サーバー不在（`ENOENT`・`ECONNREFUSED`）は `Unavailable`。
/// 未対応の OS・アーキテクチャは `Unimplemented`（fail-closed）。
pub(crate) fn connect_unix_until(
    path: &Path,
    deadline: Instant,
) -> Result<Option<UnixStream>, IoError> {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        imp::connect_unix_until(path, deadline)
    }
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = (path, deadline);
        Err(IoError::new(
            IoErrorCode::Unimplemented,
            "unix domain socket connect is not implemented for this architecture",
        ))
    }
}

/// 自前の FFI 宣言を `libc` と `const` 評価で照合する（#1837・IO-1・REPAIR-12）。関数は呼ばない。
#[cfg(test)]
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod libc_abi {
    use super::imp::*;
    use core::mem::{align_of, offset_of, size_of};

    const _: () = {
        assert!(AF_UNIX == libc::AF_UNIX);
        assert!(SOCK_STREAM == libc::SOCK_STREAM);
        assert!(EPERM == libc::EPERM);
        assert!(ENOENT == libc::ENOENT);
        assert!(EINTR == libc::EINTR);
        assert!(ENOMEM == libc::ENOMEM);
        assert!(EACCES == libc::EACCES);
        assert!(ENOTDIR == libc::ENOTDIR);
        assert!(ENFILE == libc::ENFILE);
        assert!(EMFILE == libc::EMFILE);
        assert!(EAGAIN == libc::EAGAIN);
        assert!(ENOTSOCK == libc::ENOTSOCK);
        assert!(EPROTOTYPE == libc::EPROTOTYPE);
        assert!(ENOBUFS == libc::ENOBUFS);
        assert!(EISCONN == libc::EISCONN);
        assert!(ECONNREFUSED == libc::ECONNREFUSED);
        assert!(EALREADY == libc::EALREADY);
        assert!(EINPROGRESS == libc::EINPROGRESS);

        assert!(size_of::<SockaddrUn>() == size_of::<libc::sockaddr_un>());
        assert!(align_of::<SockaddrUn>() == align_of::<libc::sockaddr_un>());
        assert!(offset_of!(SockaddrUn, sun_family) == offset_of!(libc::sockaddr_un, sun_family));
        assert!(offset_of!(SockaddrUn, sun_path) == offset_of!(libc::sockaddr_un, sun_path));
        assert!(SUN_PATH_OFFSET == offset_of!(libc::sockaddr_un, sun_path));
        assert!(
            SUN_PATH_LEN
                == size_of::<libc::sockaddr_un>() - offset_of!(libc::sockaddr_un, sun_path)
        );
    };

    #[cfg(target_os = "linux")]
    const _: () = {
        assert!(SOCK_CLOEXEC == libc::SOCK_CLOEXEC);
        assert!(SOCK_NONBLOCK == libc::SOCK_NONBLOCK);
    };
    #[cfg(target_os = "macos")]
    const _: () = {
        assert!(F_SETFD == libc::F_SETFD);
        assert!(FD_CLOEXEC == libc::FD_CLOEXEC);
    };

    const _: unsafe extern "C" fn(libc::c_int, libc::c_int, libc::c_int) -> libc::c_int = socket;
    const _: unsafe extern "C" fn(libc::c_int, libc::c_int, libc::c_int) -> libc::c_int =
        libc::socket;
    // `connect` は `sys::sock_raw` の共通宣言（アドレスは `*const c_void`）。
    const _: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_void,
        libc::socklen_t,
    ) -> libc::c_int = super::super::sock_raw::connect;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    /// 排他作成の専用ディレクトリ（drop で自分の分だけ消す。REPAIR-12）。
    fn scratch() -> crate::test_temp_file::TempDir {
        crate::test_temp_file::TempDir::new("fc-io-uds")
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    fn code(r: Result<Option<UnixStream>, IoError>) -> IoErrorCode {
        r.expect_err("must fail").code()
    }

    /// IO-1・PLUG-12: `sun_path` の上限ちょうど（NUL 込みで収まらない）と超過は `InvalidArgument`。
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn io1_uds_connect_rejects_overlong_path() {
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                target_pointer_width = "64",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            for n in [imp::SUN_PATH_LEN, imp::SUN_PATH_LEN + 20] {
                let p = format!("/{}", "a".repeat(n - 1));
                assert_eq!(p.len(), n);
                assert_eq!(
                    code(connect_unix_until(Path::new(&p), soon())),
                    IoErrorCode::InvalidArgument,
                    "len={n}"
                );
            }
        }
    }

    /// IO-1・PLUG-12: 空・NUL を含むパス・先頭 NUL の抽象ソケットは `InvalidArgument`。
    #[test]
    fn io1_uds_connect_rejects_empty_and_nul_path() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;
        for raw in [&b""[..], b"/tmp/a\0b", b"\0abstract"] {
            let p = Path::new(OsStr::from_bytes(raw));
            assert_eq!(
                code(connect_unix_until(p, soon())),
                IoErrorCode::InvalidArgument,
                "path={raw:?}"
            );
        }
    }

    /// IO-1・PLUG-12: 存在しないパス（ENOENT）は `Unavailable`。
    #[test]
    fn io1_uds_connect_missing_path_is_unavailable() {
        let guard = scratch();
        let dir = guard.path().to_path_buf();
        let r = connect_unix_until(&dir.join("none.sock"), soon());
        assert_eq!(code(r), IoErrorCode::Unavailable);
    }

    /// IO-1・PLUG-12: listener が閉じてパスだけ残る（ECONNREFUSED）場合は `Unavailable`。
    #[test]
    fn io1_uds_connect_refused_is_unavailable() {
        let guard = scratch();
        let dir = guard.path().to_path_buf();
        let path = dir.join("stale.sock");
        drop(UnixListener::bind(&path).expect("bind"));
        assert_eq!(
            code(connect_unix_until(&path, soon())),
            IoErrorCode::Unavailable
        );
    }

    /// IO-1・PLUG-12: 接続できる listener には `Some(stream)` を返す。
    #[test]
    fn io1_uds_connect_succeeds_against_listener() {
        let guard = scratch();
        let dir = guard.path().to_path_buf();
        let path = dir.join("ok.sock");
        let _l = UnixListener::bind(&path).expect("bind");
        let s = connect_unix_until(&path, soon())
            .expect("connect")
            .expect("not timed out");
        drop(s);
    }

    /// REPAIR-5: backlog 満杯の listener への connect は、期限を過ぎたら `Ok(None)` で戻る。
    /// Linux 限定: macOS は接続が待ち行列に入って成功するため再現しない。
    #[cfg(all(
        target_os = "linux",
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn repair5_uds_connect_times_out_on_full_backlog() {
        let guard = scratch();
        let dir = guard.path().to_path_buf();
        let path = dir.join("full.sock");
        let l = UnixListener::bind(&path).expect("bind");
        // std の bind の backlog は大きいため、listen(2) を再発行して backlog を 0 に絞る
        // （Linux は backlog + 1 件で満杯になる）。
        // SAFETY: `l` は有効な listening ソケットで、この呼び出しの間生存する。
        let rc = unsafe { libc::listen(std::os::fd::AsRawFd::as_raw_fd(&l), 0) };
        assert_eq!(rc, 0, "relisten must succeed");
        let mut held = Vec::new();
        let started = Instant::now();
        let mut timed_out = false;
        for _ in 0..16 {
            let deadline = Instant::now() + Duration::from_millis(100);
            match connect_unix_until(&path, deadline).expect("connect") {
                Some(s) => held.push(s),
                None => {
                    timed_out = true;
                    break;
                }
            }
        }
        assert!(timed_out, "backlog never filled");
        assert!(started.elapsed() < Duration::from_secs(30));
        drop(held);
    }

    /// IO-1・PLUG-12: errno の写像（資源不足・パス起因・権限）が固定どおりであること。
    #[test]
    fn io1_uds_connect_errno_mapping_is_fixed() {
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                target_pointer_width = "64",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            let e = io::Error::from_raw_os_error(imp::EMFILE);
            assert_eq!(
                imp::map_connect_errno(Some(imp::EMFILE), &e).code(),
                IoErrorCode::ResourceExhausted
            );
            let e = io::Error::from_raw_os_error(imp::ENOTSOCK);
            assert_eq!(
                imp::map_connect_errno(Some(imp::ENOTSOCK), &e).code(),
                IoErrorCode::InvalidArgument
            );
            let e = io::Error::from_raw_os_error(imp::EACCES);
            assert_eq!(
                imp::map_connect_errno(Some(imp::EACCES), &e).code(),
                IoErrorCode::InvalidArgument
            );
        }
    }
}
