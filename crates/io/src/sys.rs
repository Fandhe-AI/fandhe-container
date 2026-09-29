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
//!   （`crate::server::imp::ServerInner::bind` が bind 前に 1 回だけ取得し、
//!   `crate::server::imp::check_socket_owner` による親ディレクトリ所有者との
//!   照合に使ったうえで保存し、accept ごとの peer credential 照合
//!   〔`crate::server::imp::verify_peer_credential`〕の基準にする）
//! - Linux 専用: `syncfs(2)` で fd が属するファイルシステム全体を永続化する
//!   （IO-2・TASK-15.2.1・#823）。FLUSH バリア（[`crate::barrier::FlushBarrier`]）
//!   以前の書き込みを実際に永続化してから FlushAck を返す処理
//!   （`crate::writeback` の `Flush` 受信ハンドラ）から、TASK-15.2.2・#824 で
//!   `crate::writeback::AppendFileSink::get_ref()` が返す `&File` の fd を渡して
//!   呼ぶ想定（本 issue の時点ではまだ呼び出し元がない。REPAIR-3）。
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
//!   （[`peer_uid`]・[`effective_uid`]・[`syncfs`]）のみで、`unsafe` はこの
//!   モジュール内に閉じる
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` で
//!   理由と維持すべき不変条件を明記する
//! - `fd` は呼び出し元が `&UnixStream`（または [`syncfs`] の場合 `AsFd`）を
//!   借用し続けている間だけ渡される（シグネチャが借用を要求するため、
//!   呼び出しの間 fd がクローズされないことを型で保証する）
//! - syscall の定数（`SOL_SOCKET`・`SO_PEERCRED`）はアーキテクチャごとに
//!   `cfg(target_arch = ...)` で個別に定義し、値が同じであっても他アーキ
//!   テクチャの定義を流用しない（coding-rust.md）。対応していない
//!   アーキテクチャでは [`IoErrorCode::Unimplemented`] を返す（fail-closed）。
//!   `syncfs` はこの分岐が不要（下記「`syncfs` の定数について」参照）
//! - `extern "C"` の引数の型・幅は Linux の glibc/musl・macOS の libSystem の
//!   宣言に合わせる（`socklen_t` は `u32`、`uid_t`/`gid_t` は `u32`、`c_int` は
//!   `i32`）
//! - 戻り値が `-1` の場合は `std::io::Error::last_os_error()` で errno を
//!   拾う
//!
//! # `libc` / `nix` について
//! `libc`（#86・[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4)
//! 系列で採用は承認済み）は自動運転下では「追加時点で新しい版があれば PR で
//! 確認する」という運用条件を満たせないため、本モジュールは `Cargo.toml` を
//! 変更せず、既存の `getsockopt`・`getpeereid`・`geteuid` と同じ流儀で
//! 必要最小限の `extern "C"` 宣言を自前で持つ（dependency-policy「ユーザー
//! 承認制」）。
//!
//! # `syncfs` の定数について
//! `syncfs(2)` はアーキテクチャ非依存の libc シンボル名で呼び出す（生の
//! syscall 番号を直接発行しない）ため、`SOL_SOCKET`/`SO_PEERCRED` のような
//! `cfg(target_arch = ...)` ごとの定数定義は不要（coding-rust.md の対象は
//! 「syscall 番号・構造体レイアウトのアーキテクチャ差」であり、libc の
//! シンボル解決はこれに当たらない）。

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

#[cfg(target_os = "linux")]
use std::os::fd::AsFd;

use crate::error::{IoError, IoErrorCode};

/// [`io::Error::last_os_error`] を [`IoError`] へ変換する（本モジュール限定の
/// ヘルパー。相手側〔untrusted〕由来の文字列は含まないため、そのまま
/// `Display` した errno の説明文を使ってよい）。
///
/// errno はスレッドローカルで、後続の libc 呼び出し（`format!` のメモリ確保等）
/// で上書きされうるため、関数の先頭で [`io::Error::last_os_error`] を確保して
/// から使う（I3・#820 security-auditor 再監査指摘対応）。呼び出し元は syscall
/// の戻り値を判定した直後、他の処理を挟まずにこの関数を呼ぶ。
fn last_os_error_to_ioerror(context: &str) -> IoError {
    let err = io::Error::last_os_error();
    IoError::new(IoErrorCode::Internal, format!("{context}: {err}"))
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

#[cfg(target_os = "linux")]
mod syncfs_raw {
    //! `syncfs(2)` の生の FFI 宣言（安全なラッパー [`super::syncfs`] と名前が
    //! 衝突しないよう、専用のサブモジュールに分離する）。

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: glibc / musl の
        // `int syncfs(int fd)`（man 2 syncfs）と同じ引数・戻り値の型・幅
        // （`c_int` は `i32`）で宣言している。ポインタ引数を取らないため、
        // メモリレイアウトの誤りによる不変条件違反の余地がない。呼び出し側の
        // 不変条件は呼び出し箇所（[`super::syncfs`]）の SAFETY コメントを
        // 参照。
        pub(super) fn syncfs(fd: i32) -> i32;
    }
}

/// `syncfs(2)` の戻り値を [`IoError`] へ解釈する（`syncfs` 本体から分離し、
/// 単体テストで判定ロジックだけを検証できるようにするための private
/// ヘルパー）。
///
/// - `0` → 永続化に成功した（`Ok(())`）
/// - `-1` → syscall が失敗した。呼び出し元が syscall 直後・他の処理を挟まず
///   本関数を呼ぶことを前提に、ここで `last_os_error_to_ioerror` を呼んで
///   errno を拾う（I3 対応と同じく、errno はスレッドローカルで後続の処理に
///   よって上書きされうるため）
/// - それ以外 → `syncfs(2)` の仕様（0 または -1 のみを返す）にない値であり、
///   fail-closed で [`IoErrorCode::Internal`] にする（0 以外を成功として
///   扱わない）
#[cfg(target_os = "linux")]
fn syncfs_rc_to_result(rc: i32) -> Result<(), IoError> {
    match rc {
        0 => Ok(()),
        -1 => Err(last_os_error_to_ioerror("syncfs failed")),
        _ => Err(IoError::new(
            IoErrorCode::Internal,
            "syncfs returned an unexpected value",
        )),
    }
}

/// `fd` が属するファイルシステム全体を永続化する（`syncfs(2)`。Linux 専用・
/// IO-2・TASK-15.2.1・#823）。
///
/// 同期される範囲は `fd` が指すファイルだけではなく、`fd` が属する
/// **ファイルシステム全体**である（man 2 syncfs）。FLUSH バリア
/// （[`crate::barrier::FlushBarrier`]）以前の書き込みが永続化済みであることを
/// 保証する FlushAck（IO-2）は、この意味論を前提に組み立てる
/// （呼び出し元は TASK-15.2.2・#824 で追加する `crate::writeback` の `Flush`
/// 受信ハンドラで、`crate::writeback::AppendFileSink::get_ref()` が返す
/// `&File` を渡す想定。本 issue の時点ではまだ呼び出し元がない）。
///
/// # カーネル版数の要件（IO-2 の保証範囲）
/// `syncfs(2)` は Linux 2.6.39・glibc 2.14 で追加された（man 2 syncfs の
/// STANDARDS: Linux。他 OS には存在しない）。Linux 5.8 未満では不正な fd
/// （`EBADF`）以外の失敗を報告せず、書き戻しに失敗した inode があっても
/// `0` を返しうる。Linux 5.8 以降は、前回の `syncfs()` 呼び出し以降に
/// 書き戻しに失敗した inode があればエラーを返す。FLUSH ACK の永続化保証は
/// 実行環境のカーネル版数に依存し、5.8 未満のカーネルを検出・拒否するかは
/// TASK-15.2.2・#824 以降の判断事項（REPAIR-3）。
///
/// `fd` は呼び出し元が借用し続けている間だけ有効な値を渡すため、呼び出しの
/// 間にクローズ・再利用されることはない。EINTR による再試行は行わない
/// （man 2 syncfs の ERRORS は `EBADF`・`EIO`・`ENOSPC`・`EDQUOT` のみで、
/// シグナル割り込みによる失敗は定義されていない）。エラー時は
/// [`IoErrorCode::Internal`] を返し、panic しない。
#[cfg(target_os = "linux")]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TASK-15.2.2・#824 で writeback の Flush 処理から呼ぶまで未使用"
    )
)]
pub(crate) fn syncfs(fd: impl AsFd) -> Result<(), IoError> {
    let raw_fd = fd.as_fd().as_raw_fd();

    // SAFETY: `raw_fd` は呼び出し元が `fd`（`AsFd` の借用）を保持し続けている
    // 間だけ有効で、この呼び出しが終わるまでクローズされない。`syncfs` は
    // ポインタ引数を取らず、メモリへ書き込まない。戻り値 `-1` は
    // `syncfs_rc_to_result` の呼び出しで直後に errno を拾う。
    let rc = unsafe { syncfs_raw::syncfs(raw_fd) };
    syncfs_rc_to_result(rc)
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

    /// IO-2・TASK-15.2.1・#823: `syncfs_rc_to_result(0)` は永続化成功として
    /// `Ok(())` になる。
    #[cfg(target_os = "linux")]
    #[test]
    fn io2_syncfs_rc_zero_is_ok() {
        assert_eq!(syncfs_rc_to_result(0), Ok(()));
    }

    /// IO-2・TASK-15.2.1・#823: `syncfs(2)` の仕様にない戻り値（`0`・`-1` 以外）
    /// は、それを成功として扱わず `Internal` で拒否する（fail-closed）。
    #[cfg(target_os = "linux")]
    #[test]
    fn io2_syncfs_rc_unexpected_value_is_internal() {
        for rc in [1, -2] {
            let err = syncfs_rc_to_result(rc).expect_err("non 0/-1 rc must be rejected");
            assert_eq!(err.code(), IoErrorCode::Internal, "rc={rc}");
            assert!(
                err.message().contains("unexpected"),
                "message must mention 'unexpected': {err:?}"
            );
        }
    }

    /// IO-2・TASK-15.2.1・#823: `syncfs_rc_to_result(-1)` は
    /// `last_os_error_to_ioerror` 経由で `Internal` になり、メッセージが
    /// 呼び出しの文脈（`"syncfs failed"`）から始まる（errno の説明文自体は
    /// 環境依存のため固定しない）。
    #[cfg(target_os = "linux")]
    #[test]
    fn io2_syncfs_rc_minus_one_is_internal_error() {
        let err = syncfs_rc_to_result(-1).expect_err("-1 must be rejected");
        assert_eq!(err.code(), IoErrorCode::Internal);
        assert!(
            err.message().starts_with("syncfs failed"),
            "message must start with 'syncfs failed': {err:?}"
        );
    }

    /// IO-2・TASK-15.2.1・#823: 一時ディレクトリを開いた fd に対する
    /// `syncfs` は成功する（ファイルは作らない。tempfile 系 crate は使わず
    /// `std::env::temp_dir()` を直接開く）。
    #[cfg(target_os = "linux")]
    #[test]
    fn io2_syncfs_on_temp_dir_succeeds() {
        let dir = std::fs::File::open(std::env::temp_dir())
            .expect("must be able to open the temp dir for reading");
        syncfs(&dir).expect("syncfs on the temp dir's filesystem must succeed");
    }

    /// IO-2・TASK-15.2.1・#823: `O_PATH` で開いた fd（データ操作 syscall を
    /// 拒否する）に対する `syncfs` は `EBADF` で失敗し、`Internal` になる。
    /// `O_PATH` の値はアーキテクチャごとに個別定義する（coding-rust.md
    /// 「定数を流用しない」。値自体はどちらも `0o10000000`）。
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const TEST_O_PATH: i32 = 0o10_000_000;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const TEST_O_PATH: i32 = 0o10_000_000;

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn io2_syncfs_on_o_path_fd_returns_ebadf() {
        use std::os::unix::fs::OpenOptionsExt;

        let fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(TEST_O_PATH)
            .open(std::env::temp_dir())
            .expect("must be able to open the temp dir with O_PATH");
        let err = syncfs(&fd).expect_err("syncfs on an O_PATH fd must fail with EBADF");
        assert_eq!(err.code(), IoErrorCode::Internal);
        assert!(
            err.message().contains("Bad file descriptor") || err.message().contains("os error 9"),
            "message must describe EBADF: {err:?}"
        );
    }
}
