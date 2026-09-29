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
//! - Linux（x86_64 / aarch64）・macOS: `openat(2)`・`mkdirat(2)`・`unlinkat(2)`・
//!   `renameat(2)`・`fdopendir(3)`/`readdir(3)` でディレクトリハンドル相対に
//!   ファイル・ディレクトリを作る・開く・消す・改名する・列挙する（TASK-19.2・IO-5・#100。
//!   `crate::guest_files` が共有ルート配下への作成で使う。下記「ハンドル相対の
//!   ファイル操作」節）。
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
//!   （[`peer_uid`]・[`effective_uid`]・[`syncfs`]・[`mkdir_beneath`]・
//!   [`open_dir_beneath`]・[`create_leaf_beneath`]・[`unlink_beneath`]・
//!   [`rename_beneath`]・[`for_each_dir_entry`]・[`read_dir_entries`]）のみで、`unsafe` はこのモジュール内に閉じる
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

// ---------------------------------------------------------------------------
// ハンドル相対のファイル操作（TASK-19.2・IO-5・#100。`crate::guest_files` 専用）
// ---------------------------------------------------------------------------
//
// `crate::guest_files::GuestFileCreator` が共有ルートのディレクトリハンドルを
// 起点に、パス文字列を再解決せずに祖先を 1 個ずつ辿る・作る・消すための薄い
// ラッパー群。祖先の走査（どの名前をどの順で辿るか）・衝突の再検証・取り消しの
// 判断は安全なコード（`guest_files`）が持ち、本節は 1 回の syscall / libc 呼び出し
// ごとの安全な入口だけを提供する（unsafe の範囲を最小にするため）。
//
// # アーキテクチャ差（Codex P0 指摘への確認記録を含む）
// `open(2)` のフラグは Linux でもアーキテクチャごとに値が違う。x86_64 は
// `include/uapi/asm-generic/fcntl.h` の値（`O_DIRECTORY = 0o200000`・
// `O_NOFOLLOW = 0o400000`）を使うが、arm64 は
// `arch/arm64/include/uapi/asm/fcntl.h` が AArch32 互換のため独自に
// `O_DIRECTORY = 0o40000`・`O_NOFOLLOW = 0o100000`（`O_DIRECT = 0o200000`・
// `O_LARGEFILE = 0o400000`）を定義し直している。asm-generic の値を arm64 へ
// 流用すると、`O_DIRECTORY` のつもりで `O_DIRECT`、`O_NOFOLLOW` のつもりで
// `O_LARGEFILE` を渡すことになり、symlink 非追従の保証が失われる。そのため
// 定数は `beneath_consts` で OS・アーキテクチャごとに個別定義し、値を固定値の
// テストで照合する（coding-rust.md「定数を流用しない」）。対応外のアーキ
// テクチャ（Linux の x86_64 / aarch64 以外）では実装を丸ごとビルドから除外し、
// 同じシグネチャの関数が常に `Unsupported` を返す（fail-closed。`guest_files`
// は作成も走査も行えずエラーを返す）。
//
// # 構造体レイアウトの前提
// `struct dirent` は全体を宣言せず、先頭からの固定オフセットで `d_ino`（u64）と
// `d_name`（NUL 終端）だけを読む。Linux（glibc・musl の 64 ビット版）は
// `d_ino(8) d_off(8) d_reclen(2) d_type(1) d_name`、macOS（64 ビット inode 版。
// arm64 は常にこの版、x86_64 は `$INODE64` シンボルで明示）は
// `d_ino(8) d_seekoff(8) d_reclen(2) d_namlen(2) d_type(1) d_name`。

/// ハンドル相対の操作（[`mkdir_beneath`]・[`open_dir_beneath`]・
/// [`create_leaf_beneath`]・[`unlink_beneath`]・[`rename_beneath`]）の失敗種別
/// （`crate::guest_files` が `IoError` へ写す。ホストのパスや errno の説明文は
/// 載せない）。
#[cfg_attr(
    not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )),
    allow(
        dead_code,
        reason = "対応外アーキテクチャでは常に Unsupported を返すため未構築の variant がある"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BeneathError {
    /// 辿ろうとした要素が symlink または非ディレクトリだった（symlink は辿らない）。
    AncestorNotDirectory,
    /// 作ろうとした末端が既に存在した（symlink を含む。辿らない）。
    AlreadyExists,
    /// 上記以外の OS エラー（`io::ErrorKind` だけを持つ）。
    Io(io::ErrorKind),
}

/// [`unlink_beneath`] で消す対象の種類（`unlinkat(2)` の `AT_REMOVEDIR` の有無）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnlinkTarget {
    /// 通常ファイル（`flags = 0`）。
    File,
    /// 空のディレクトリ（`AT_REMOVEDIR`。空でなければ失敗する）。
    EmptyDirectory,
}

/// [`mkdir_beneath`] で作るディレクトリの mode（umask 適用前）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirMode {
    /// 共有ルート配下の通常の祖先（`0o777`）。
    Shared,
    /// 所有者だけが読み書き・探索できる作業用ディレクトリ（`0o700`。
    /// `crate::guest_files` の取り消しの退避先）。
    Private,
}

/// [`read_dir_entries`] の失敗種別。
#[cfg_attr(
    not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )),
    allow(
        dead_code,
        reason = "対応外アーキテクチャでは常に Unsupported を返すため未構築の variant がある"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadDirError {
    /// エントリ数が上限を超えた（無制限確保による DoS の防止）。
    TooMany,
    /// OS エラー（種別のみ。パスや説明文は載せない）。
    Io(io::ErrorKind),
}

/// [`read_dir_entries`] が返す 1 エントリ（名前は生のバイト列、`ino` は
/// `dirent.d_ino`。取り消し前の同一性確認〔`crate::guest_files`〕に使う）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirEntryName {
    /// エントリ名（`.`・`..` は含まない）。
    pub(crate) name: std::ffi::OsString,
    /// エントリの inode 番号（`d_ino`）。
    pub(crate) ino: u64,
}

/// `open(2)` フラグ・`unlinkat(2)` フラグ・errno・`mode_t`・`dirent` の
/// オフセット（Linux はアーキテクチャごと、macOS は共通。上記「アーキテクチャ差」
/// 参照）。値は `sys::tests::io5_beneath_consts_*` で固定値として照合する。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod beneath_consts {
    // include/uapi/asm-generic/fcntl.h（x86_64 は上書きしない）。
    pub(super) const O_WRONLY: i32 = 0o1;
    pub(super) const O_CREAT: i32 = 0o100;
    pub(super) const O_EXCL: i32 = 0o200;
    pub(super) const O_DIRECTORY: i32 = 0o200_000;
    pub(super) const O_NOFOLLOW: i32 = 0o400_000;
    pub(super) const O_CLOEXEC: i32 = 0o2_000_000;
    // include/uapi/linux/fcntl.h。
    pub(super) const AT_REMOVEDIR: i32 = 0x200;
    // include/uapi/asm-generic/errno-base.h・errno.h。
    pub(super) const EEXIST: i32 = 17;
    pub(super) const ENOTDIR: i32 = 20;
    pub(super) const ELOOP: i32 = 40;
    pub(super) type ModeT = u32;
    pub(super) const DIRENT_INO_OFFSET: usize = 0;
    pub(super) const DIRENT_NAME_OFFSET: usize = 19;
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod beneath_consts {
    // include/uapi/asm-generic/fcntl.h（arm64 が上書きしない値）。
    pub(super) const O_WRONLY: i32 = 0o1;
    pub(super) const O_CREAT: i32 = 0o100;
    pub(super) const O_EXCL: i32 = 0o200;
    // arch/arm64/include/uapi/asm/fcntl.h（asm-generic と異なる。流用しない）。
    pub(super) const O_DIRECTORY: i32 = 0o40_000;
    pub(super) const O_NOFOLLOW: i32 = 0o100_000;
    // include/uapi/asm-generic/fcntl.h。
    pub(super) const O_CLOEXEC: i32 = 0o2_000_000;
    // include/uapi/linux/fcntl.h。
    pub(super) const AT_REMOVEDIR: i32 = 0x200;
    // include/uapi/asm-generic/errno-base.h・errno.h。
    pub(super) const EEXIST: i32 = 17;
    pub(super) const ENOTDIR: i32 = 20;
    pub(super) const ELOOP: i32 = 40;
    pub(super) type ModeT = u32;
    pub(super) const DIRENT_INO_OFFSET: usize = 0;
    pub(super) const DIRENT_NAME_OFFSET: usize = 19;
}

#[cfg(target_os = "macos")]
mod beneath_consts {
    // <sys/fcntl.h>・<sys/errno.h>・<sys/dirent.h>（x86_64 / arm64 共通）。
    pub(super) const O_WRONLY: i32 = 0x1;
    pub(super) const O_CREAT: i32 = 0x200;
    pub(super) const O_EXCL: i32 = 0x800;
    pub(super) const O_DIRECTORY: i32 = 0x0010_0000;
    pub(super) const O_NOFOLLOW: i32 = 0x100;
    pub(super) const O_CLOEXEC: i32 = 0x0100_0000;
    pub(super) const AT_REMOVEDIR: i32 = 0x80;
    pub(super) const EEXIST: i32 = 17;
    pub(super) const ENOTDIR: i32 = 20;
    pub(super) const ELOOP: i32 = 62;
    pub(super) type ModeT = u16;
    pub(super) const DIRENT_INO_OFFSET: usize = 0;
    pub(super) const DIRENT_NAME_OFFSET: usize = 21;
}

pub(crate) use beneath::{
    create_leaf_beneath, for_each_dir_entry, mkdir_beneath, open_dir_beneath, read_dir_entries,
    rename_beneath, unlink_beneath,
};

/// 対応アーキテクチャ（macOS・Linux の x86_64 / aarch64）向けの実装。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod beneath {
    use super::beneath_consts as c;
    use super::{BeneathError, DirEntryName, DirMode, ReadDirError, UnlinkTarget};
    use std::ffi::{CStr, CString, OsStr};
    use std::fs::File;
    use std::io;
    use std::ops::ControlFlow;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    mod raw {
        use core::ffi::{c_char, c_void};

        unsafe extern "C" {
            // SAFETY（宣言そのものの妥当性）: POSIX の
            // `int openat(int dirfd, const char *path, int flags, ...)`
            // （可変長引数は mode。`O_CREAT` のときだけ読まれる）と同じ型・幅。
            // 呼び出し側の不変条件は各呼び出し箇所の SAFETY 参照。
            pub(super) fn openat(dirfd: i32, path: *const c_char, flags: i32, ...) -> i32;
            // SAFETY（宣言そのものの妥当性）: POSIX の
            // `int mkdirat(int dirfd, const char *path, mode_t mode)`
            // （`mode_t` は Linux が u32、macOS が u16。`beneath_consts::ModeT`）。
            pub(super) fn mkdirat(dirfd: i32, path: *const c_char, mode: super::c::ModeT) -> i32;
            // SAFETY（宣言そのものの妥当性）: POSIX の
            // `int unlinkat(int dirfd, const char *path, int flags)`。
            pub(super) fn unlinkat(dirfd: i32, path: *const c_char, flags: i32) -> i32;
            // SAFETY（宣言そのものの妥当性）: POSIX の
            // `int renameat(int olddirfd, const char *old, int newdirfd, const char *new)`
            // （Linux・macOS とも接尾辞なしの同名シンボル）。
            pub(super) fn renameat(
                olddirfd: i32,
                old: *const c_char,
                newdirfd: i32,
                new: *const c_char,
            ) -> i32;

            // SAFETY（宣言そのものの妥当性）: POSIX の `DIR *fdopendir(int fd)`・
            // `struct dirent *readdir(DIR *)`・`void rewinddir(DIR *)`・
            // `int closedir(DIR *)`。DIR は不透明ポインタ（`*mut c_void`）、dirent は
            // 先頭バイトへのポインタとして扱い、`d_ino`・`d_name` だけを固定
            // オフセットで読む（`beneath_consts::DIRENT_*`）。macOS の x86_64 は
            // 64 ビット inode 版の DIR / dirent を扱うシンボル（`$INODE64`）を
            // fdopendir・readdir・rewinddir で揃えて明示する（混在させると DIR の
            // レイアウトが食い違う。closedir は版を持たない）。arm64 の macOS は
            // 64 ビット inode 版のみのため接尾辞を付けない。
            #[cfg_attr(
                all(target_os = "macos", target_arch = "x86_64"),
                link_name = "fdopendir$INODE64"
            )]
            pub(super) fn fdopendir(fd: i32) -> *mut c_void;
            #[cfg_attr(
                all(target_os = "macos", target_arch = "x86_64"),
                link_name = "readdir$INODE64"
            )]
            pub(super) fn readdir(dir: *mut c_void) -> *mut u8;
            #[cfg_attr(
                all(target_os = "macos", target_arch = "x86_64"),
                link_name = "rewinddir$INODE64"
            )]
            pub(super) fn rewinddir(dir: *mut c_void);
            pub(super) fn closedir(dir: *mut c_void) -> i32;
            // SAFETY（宣言そのものの妥当性）: スレッドローカルな errno への
            // ポインタを返す（glibc・musl は `__errno_location`、macOS は `__error`）。
            #[cfg(target_os = "linux")]
            pub(super) fn __errno_location() -> *mut i32;
            #[cfg(target_os = "macos")]
            pub(super) fn __error() -> *mut i32;
        }
    }

    fn cstr(name: &str) -> Result<CString, BeneathError> {
        CString::new(name).map_err(|_| BeneathError::Io(io::ErrorKind::InvalidInput))
    }

    /// 直前の libc 呼び出しの errno を（他の処理を挟まずに）取り出す。
    fn last_errno() -> (i32, io::ErrorKind) {
        let err = io::Error::last_os_error();
        (err.raw_os_error().unwrap_or(0), err.kind())
    }

    /// `openat` の戻り値を所有 fd へ変換する（`-1` は errno を `map` で写す）。
    fn own_fd(
        fd: i32,
        map: impl FnOnce(i32, io::ErrorKind) -> BeneathError,
    ) -> Result<File, BeneathError> {
        if fd < 0 {
            let (errno, kind) = last_errno();
            return Err(map(errno, kind));
        }
        // SAFETY: `fd` は直前の openat が返した有効な新規 fd（非負）で、他に
        // 所有者がいない。ここで `OwnedFd` へ渡し、以降は drop で閉じる。
        Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// `dir` 直下にディレクトリ `name` を `mode`（umask 適用前）で作る
    /// （`mkdirat`）。作ったら `Ok(true)`、既に何か（symlink を含む）があれば
    /// `Ok(false)`（その実体が辿れるディレクトリかは [`open_dir_beneath`] が
    /// `O_NOFOLLOW` で確かめる）。
    pub(crate) fn mkdir_beneath(
        dir: &File,
        name: &str,
        mode: DirMode,
    ) -> Result<bool, BeneathError> {
        let cname = cstr(name)?;
        let mode: c::ModeT = match mode {
            DirMode::Shared => 0o777,
            DirMode::Private => 0o700,
        };
        // SAFETY: `dir` は呼び出し元が借用中の有効なディレクトリ fd で、呼び出しの
        // 間閉じられない。`cname` は NUL 終端の有効な C 文字列で呼び出しの間生きて
        // いる。mkdirat は fd を返さず、失敗時は errno を直後に拾う。
        let rc = unsafe { raw::mkdirat(dir.as_raw_fd(), cname.as_ptr(), mode) };
        if rc == 0 {
            return Ok(true);
        }
        let (errno, kind) = last_errno();
        if errno == c::EEXIST {
            Ok(false)
        } else {
            Err(BeneathError::Io(kind))
        }
    }

    /// `dir` 直下のサブディレクトリ `name` を、ハンドル相対・symlink 非追従
    /// （`openat` + `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`）で開く。symlink・
    /// 非ディレクトリは `AncestorNotDirectory`、無ければ `Io(NotFound)`。
    pub(crate) fn open_dir_beneath(dir: &File, name: &str) -> Result<File, BeneathError> {
        let cname = cstr(name)?;
        // SAFETY: `dir`・`cname` は mkdir_beneath と同じ。O_CREAT を指定しない
        // ため可変長引数は読まれない。戻り値は `own_fd` が唯一の所有者になる。
        let fd = unsafe {
            raw::openat(
                dir.as_raw_fd(),
                cname.as_ptr(),
                c::O_DIRECTORY | c::O_NOFOLLOW | c::O_CLOEXEC,
            )
        };
        own_fd(fd, |errno, kind| {
            if errno == c::ELOOP || errno == c::ENOTDIR {
                BeneathError::AncestorNotDirectory
            } else {
                BeneathError::Io(kind)
            }
        })
    }

    /// `dir` 直下に通常ファイル `name` を `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|
    /// O_CLOEXEC`（mode 0o666。umask 適用前）で新規作成する。既存（symlink を
    /// 含む。辿らない）は `AlreadyExists`。
    pub(crate) fn create_leaf_beneath(dir: &File, name: &str) -> Result<File, BeneathError> {
        let cname = cstr(name)?;
        let mode: u32 = 0o666;
        // SAFETY: `dir`・`cname` は上記と同じ。O_CREAT を指定するため可変長引数の
        // mode を `c_uint` 幅（`mode_t` の既定の引数昇格後の幅）で渡す。戻り値は
        // `own_fd` が唯一の所有者になる。
        let fd = unsafe {
            raw::openat(
                dir.as_raw_fd(),
                cname.as_ptr(),
                c::O_WRONLY | c::O_CREAT | c::O_EXCL | c::O_NOFOLLOW | c::O_CLOEXEC,
                mode,
            )
        };
        own_fd(fd, |errno, kind| {
            if errno == c::EEXIST {
                BeneathError::AlreadyExists
            } else {
                BeneathError::Io(kind)
            }
        })
    }

    /// `dir` 直下のエントリ `name` を `unlinkat` で消す（symlink は辿らない。
    /// `EmptyDirectory` は空でなければ `Io(DirectoryNotEmpty)` 等で失敗する）。
    /// 消す対象が呼び出し元の意図した実体かどうかは確かめない（同一性の確認は
    /// 呼び出し元〔`crate::guest_files` の取り消し〕の責務）。
    pub(crate) fn unlink_beneath(
        dir: &File,
        name: &str,
        target: UnlinkTarget,
    ) -> Result<(), BeneathError> {
        let cname = cstr(name)?;
        let flags = match target {
            UnlinkTarget::File => 0,
            UnlinkTarget::EmptyDirectory => c::AT_REMOVEDIR,
        };
        // SAFETY: `dir`・`cname` は上記と同じ。unlinkat は fd を返さず、失敗時は
        // errno を直後に拾う。
        let rc = unsafe { raw::unlinkat(dir.as_raw_fd(), cname.as_ptr(), flags) };
        if rc == 0 {
            Ok(())
        } else {
            Err(BeneathError::Io(last_errno().1))
        }
    }

    /// `from_dir` 直下のエントリ `from` を `to_dir` 直下の `to` へ改名する
    /// （`renameat`。symlink は辿らず、名前の付け替えは原子的）。`to` が既にあれば
    /// 置き換える POSIX の意味論のため、呼び出し元は `to` に他者が触れない場所を渡す
    /// （`crate::guest_files` の取り消し用の私有ディレクトリ）。
    pub(crate) fn rename_beneath(
        from_dir: &File,
        from: &str,
        to_dir: &File,
        to: &str,
    ) -> Result<(), BeneathError> {
        let cfrom = cstr(from)?;
        let cto = cstr(to)?;
        // SAFETY: `from_dir`・`to_dir` は呼び出し元が借用中の有効なディレクトリ fd で、
        // 呼び出しの間閉じられない。`cfrom`・`cto` は NUL 終端の有効な C 文字列で
        // 呼び出しの間生きている。renameat は fd を返さず、失敗時は errno を直後に拾う。
        let rc = unsafe {
            raw::renameat(
                from_dir.as_raw_fd(),
                cfrom.as_ptr(),
                to_dir.as_raw_fd(),
                cto.as_ptr(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(BeneathError::Io(last_errno().1))
        }
    }

    fn set_errno_zero() {
        // SAFETY: スレッドローカルな errno へのポインタ（常に有効・整列済み）を
        // 得て 0 を書くだけ。
        #[cfg(target_os = "linux")]
        unsafe {
            *raw::__errno_location() = 0;
        }
        // SAFETY: 同上（macOS）。
        #[cfg(target_os = "macos")]
        unsafe {
            *raw::__error() = 0;
        }
    }

    /// `dir` 直下のエントリ（`.`・`..` を除く）を、パスを再解決せずに
    /// `fdopendir`/`readdir` で 1 件ずつ `visit`（名前と `d_ino`）へ渡す。名前は
    /// 次の `readdir` までしか有効でない借用のため、`visit` の外へは持ち出せない
    /// （複製が必要なら `visit` 内でコピーする）。`visit` が `Break` を返したら
    /// 打ち切る。一覧を確保しないため、エントリ数に比例したメモリを使わない。
    ///
    /// `dir` は dup して使い（元の fd は閉じない）、dup 先は元の fd と読み取り
    /// 位置を共有するため `rewinddir` で先頭へ戻す（`rewinddir` 以前から存在し
    /// 削除されていないエントリはすべて返る。POSIX readdir）。
    pub(crate) fn for_each_dir_entry(
        dir: &File,
        mut visit: impl FnMut(&OsStr, u64) -> ControlFlow<()>,
    ) -> Result<(), ReadDirError> {
        let raw_fd = dir
            .try_clone()
            .map_err(|err| ReadDirError::Io(err.kind()))?
            .into_raw_fd();
        // SAFETY: `raw_fd` は直前に dup した有効な fd で、他に所有者がいない。
        // 成功すれば所有権は DIR へ移り closedir で閉じられる。
        let handle = unsafe { raw::fdopendir(raw_fd) };
        if handle.is_null() {
            let err = io::Error::last_os_error();
            // SAFETY: fdopendir が失敗したとき fd の所有権は移らないため、まだ
            // 唯一の所有者である本関数がここで閉じる。
            drop(unsafe { OwnedFd::from_raw_fd(raw_fd) });
            return Err(ReadDirError::Io(err.kind()));
        }
        // SAFETY: `handle` は fdopendir が返した有効な DIR*。読み取り位置を先頭へ戻す。
        unsafe { raw::rewinddir(handle) };

        let result = loop {
            set_errno_zero();
            // SAFETY: `handle` は closedir 前の有効な DIR*。返る dirent は次の
            // readdir / closedir まで有効で、`visit` へ渡す借用もその間に限る。
            let entry = unsafe { raw::readdir(handle) };
            if entry.is_null() {
                let err = io::Error::last_os_error();
                break match err.raw_os_error() {
                    Some(0) | None => Ok(()),
                    Some(_) => Err(ReadDirError::Io(err.kind())),
                };
            }
            // SAFETY: dirent の `d_name` は `DIRENT_NAME_OFFSET` から始まり、
            // カーネル / libc が NUL 終端を保証する（構造体の範囲内に収まる）。
            let name =
                unsafe { CStr::from_ptr(entry.add(c::DIRENT_NAME_OFFSET).cast()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            // SAFETY: `d_ino` は `DIRENT_INO_OFFSET` にある u64 で、dirent の範囲内。
            // 整列を仮定しないよう read_unaligned で読む。
            let ino = unsafe {
                entry
                    .add(c::DIRENT_INO_OFFSET)
                    .cast::<u64>()
                    .read_unaligned()
            };
            if visit(OsStr::from_bytes(name), ino).is_break() {
                break Ok(());
            }
        };
        // SAFETY: `handle` は有効な DIR* で以降使わない。dup した fd もここで閉じられる。
        unsafe { raw::closedir(handle) };
        result
    }

    /// `dir` 直下のエントリ（`.`・`..` を除く）を集めて返す（[`for_each_dir_entry`]）。
    /// 件数が `max_entries` を超えたら `TooMany`（無制限確保の防止）。
    pub(crate) fn read_dir_entries(
        dir: &File,
        max_entries: usize,
    ) -> Result<Vec<DirEntryName>, ReadDirError> {
        let mut entries = Vec::new();
        let mut too_many = false;
        for_each_dir_entry(dir, |name, ino| {
            if entries.len() >= max_entries {
                too_many = true;
                return ControlFlow::Break(());
            }
            entries.push(DirEntryName {
                name: name.to_os_string(),
                ino,
            });
            ControlFlow::Continue(())
        })?;
        if too_many {
            Err(ReadDirError::TooMany)
        } else {
            Ok(entries)
        }
    }
}

/// 対応外アーキテクチャ向け（fail-closed）。実装（unsafe を含む）はビルドから
/// 除外し、同じシグネチャで常に `Unsupported` を返す。
#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
mod beneath {
    use super::{BeneathError, DirEntryName, DirMode, ReadDirError, UnlinkTarget};
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io;
    use std::ops::ControlFlow;

    pub(crate) fn mkdir_beneath(
        _dir: &File,
        _name: &str,
        _mode: DirMode,
    ) -> Result<bool, BeneathError> {
        Err(BeneathError::Io(io::ErrorKind::Unsupported))
    }

    pub(crate) fn open_dir_beneath(_dir: &File, _name: &str) -> Result<File, BeneathError> {
        Err(BeneathError::Io(io::ErrorKind::Unsupported))
    }

    pub(crate) fn create_leaf_beneath(_dir: &File, _name: &str) -> Result<File, BeneathError> {
        Err(BeneathError::Io(io::ErrorKind::Unsupported))
    }

    pub(crate) fn unlink_beneath(
        _dir: &File,
        _name: &str,
        _target: UnlinkTarget,
    ) -> Result<(), BeneathError> {
        Err(BeneathError::Io(io::ErrorKind::Unsupported))
    }

    pub(crate) fn rename_beneath(
        _from_dir: &File,
        _from: &str,
        _to_dir: &File,
        _to: &str,
    ) -> Result<(), BeneathError> {
        Err(BeneathError::Io(io::ErrorKind::Unsupported))
    }

    pub(crate) fn for_each_dir_entry(
        _dir: &File,
        _visit: impl FnMut(&OsStr, u64) -> ControlFlow<()>,
    ) -> Result<(), ReadDirError> {
        Err(ReadDirError::Io(io::ErrorKind::Unsupported))
    }

    pub(crate) fn read_dir_entries(
        _dir: &File,
        _max_entries: usize,
    ) -> Result<Vec<DirEntryName>, ReadDirError> {
        Err(ReadDirError::Io(io::ErrorKind::Unsupported))
    }
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

    /// IO-5・TASK-19.2（Codex P0 指摘の照合）: Linux x86_64 の `open(2)` 等の
    /// 定数は asm-generic の値（`include/uapi/asm-generic/fcntl.h`）。
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn io5_beneath_consts_linux_x86_64() {
        use super::beneath_consts as c;
        assert_eq!(c::O_WRONLY, 0o1);
        assert_eq!(c::O_CREAT, 0o100);
        assert_eq!(c::O_EXCL, 0o200);
        assert_eq!(c::O_DIRECTORY, 0o200_000);
        assert_eq!(c::O_NOFOLLOW, 0o400_000);
        assert_eq!(c::O_CLOEXEC, 0o2_000_000);
        assert_eq!(c::AT_REMOVEDIR, 0x200);
        assert_eq!(c::EEXIST, 17);
        assert_eq!(c::ENOTDIR, 20);
        assert_eq!(c::ELOOP, 40);
        assert_eq!(core::mem::size_of::<c::ModeT>(), 4);
        assert_eq!(c::DIRENT_INO_OFFSET, 0);
        assert_eq!(c::DIRENT_NAME_OFFSET, 19);
    }

    /// IO-5・TASK-19.2（Codex P0 指摘の照合）: Linux aarch64 は
    /// `arch/arm64/include/uapi/asm/fcntl.h` が `O_DIRECTORY`・`O_NOFOLLOW` を
    /// asm-generic と異なる値（0o40000・0o100000）で定義し直す。asm-generic の
    /// 0o200000・0o400000 は arm64 では `O_DIRECT`・`O_LARGEFILE` にあたる。
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    #[test]
    fn io5_beneath_consts_linux_aarch64() {
        use super::beneath_consts as c;
        assert_eq!(c::O_WRONLY, 0o1);
        assert_eq!(c::O_CREAT, 0o100);
        assert_eq!(c::O_EXCL, 0o200);
        assert_eq!(c::O_DIRECTORY, 0o40_000);
        assert_eq!(c::O_NOFOLLOW, 0o100_000);
        assert_ne!(c::O_DIRECTORY, 0o200_000);
        assert_ne!(c::O_NOFOLLOW, 0o400_000);
        assert_eq!(c::O_CLOEXEC, 0o2_000_000);
        assert_eq!(c::AT_REMOVEDIR, 0x200);
        assert_eq!(c::EEXIST, 17);
        assert_eq!(c::ENOTDIR, 20);
        assert_eq!(c::ELOOP, 40);
        assert_eq!(core::mem::size_of::<c::ModeT>(), 4);
        assert_eq!(c::DIRENT_INO_OFFSET, 0);
        assert_eq!(c::DIRENT_NAME_OFFSET, 19);
    }

    /// IO-5・TASK-19.2: macOS（x86_64 / arm64 共通）の定数。
    #[cfg(target_os = "macos")]
    #[test]
    fn io5_beneath_consts_macos() {
        use super::beneath_consts as c;
        assert_eq!(c::O_WRONLY, 0x1);
        assert_eq!(c::O_CREAT, 0x200);
        assert_eq!(c::O_EXCL, 0x800);
        assert_eq!(c::O_DIRECTORY, 0x0010_0000);
        assert_eq!(c::O_NOFOLLOW, 0x100);
        assert_eq!(c::O_CLOEXEC, 0x0100_0000);
        assert_eq!(c::AT_REMOVEDIR, 0x80);
        assert_eq!(c::EEXIST, 17);
        assert_eq!(c::ENOTDIR, 20);
        assert_eq!(c::ELOOP, 62);
        assert_eq!(core::mem::size_of::<c::ModeT>(), 2);
        assert_eq!(c::DIRENT_INO_OFFSET, 0);
        assert_eq!(c::DIRENT_NAME_OFFSET, 21);
    }

    /// ハンドル相対の操作の実行時の照合（対応アーキテクチャのみ。対応外では実装が
    /// ビルドから除外され常に `Unsupported` になる）。
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    mod beneath_runtime {
        use super::*;

        /// テスト用の一時ディレクトリ（drop で削除する）。
        struct TmpDir(std::path::PathBuf);
        impl TmpDir {
            fn new(tag: &str) -> Self {
                use std::sync::atomic::{AtomicU32, Ordering};
                static N: AtomicU32 = AtomicU32::new(0);
                let p = std::env::temp_dir().join(format!(
                    "fcio-sys-{tag}-{}-{}",
                    std::process::id(),
                    N.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&p).expect("temp dir");
                Self(p)
            }
            fn open(&self) -> std::fs::File {
                std::fs::File::open(&self.0).expect("open dir")
            }
        }
        impl Drop for TmpDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        /// IO-5・TASK-19.2: 実行中のアーキテクチャで `O_DIRECTORY`・`O_NOFOLLOW` が
        /// 実際に効く（symlink も通常ファイルも開けず、ディレクトリだけが開ける）。
        #[test]
        fn io5_open_dir_beneath_rejects_symlink_and_file() {
            let t = TmpDir::new("open");
            std::fs::create_dir(t.0.join("d")).expect("d");
            std::fs::write(t.0.join("f"), b"x").expect("f");
            std::os::unix::fs::symlink(t.0.join("d"), t.0.join("l")).expect("symlink");
            let root = t.open();
            assert!(
                open_dir_beneath(&root, "d")
                    .expect("dir")
                    .metadata()
                    .expect("meta")
                    .is_dir()
            );
            assert_eq!(
                open_dir_beneath(&root, "l").err(),
                Some(BeneathError::AncestorNotDirectory)
            );
            assert_eq!(
                open_dir_beneath(&root, "f").err(),
                Some(BeneathError::AncestorNotDirectory)
            );
            assert_eq!(
                open_dir_beneath(&root, "missing").err(),
                Some(BeneathError::Io(io::ErrorKind::NotFound))
            );
        }

        /// IO-5・TASK-19.2: `mkdir_beneath` は新設で `true`・既存で `false`、
        /// `create_leaf_beneath` は既存（symlink を含む。辿らない）で `AlreadyExists`。
        #[test]
        fn io5_mkdir_and_create_leaf_beneath() {
            let t = TmpDir::new("mk");
            let outside = TmpDir::new("mk-out");
            let root = t.open();
            assert_eq!(mkdir_beneath(&root, "d", DirMode::Shared), Ok(true));
            assert_eq!(mkdir_beneath(&root, "d", DirMode::Shared), Ok(false));
            let dir = open_dir_beneath(&root, "d").expect("open d");
            create_leaf_beneath(&dir, "f").expect("create f");
            assert!(t.0.join("d").join("f").is_file());
            assert_eq!(
                create_leaf_beneath(&dir, "f").err(),
                Some(BeneathError::AlreadyExists)
            );
            let victim = outside.0.join("victim");
            std::os::unix::fs::symlink(&victim, t.0.join("d").join("l")).expect("symlink");
            assert_eq!(
                create_leaf_beneath(&dir, "l").err(),
                Some(BeneathError::AlreadyExists)
            );
            assert!(!victim.exists());
        }

        /// IO-5・TASK-19.2: `read_dir_entries` は `.`・`..` を除く名前と、std の
        /// `ino()` と一致する `d_ino` を返す（`dirent` の固定オフセットの実行時照合）。
        /// 件数上限を超えたら `TooMany`。
        #[test]
        fn io5_read_dir_entries_returns_names_and_inodes() {
            use std::os::unix::fs::MetadataExt;
            let t = TmpDir::new("rd");
            std::fs::write(t.0.join("alpha"), b"x").expect("alpha");
            std::fs::create_dir(t.0.join("Beta")).expect("Beta");
            let root = t.open();
            let mut entries = read_dir_entries(&root, 10).expect("read");
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            let names: Vec<_> = entries
                .iter()
                .map(|e| e.name.to_str().expect("utf-8").to_string())
                .collect();
            assert_eq!(names, vec!["Beta".to_string(), "alpha".to_string()]);
            for entry in &entries {
                let meta = std::fs::symlink_metadata(t.0.join(&entry.name)).expect("meta");
                assert_eq!(entry.ino, meta.ino(), "entry {:?}", entry.name);
            }
            // 2 回目も先頭から読み直す（dup した fd の読み取り位置を共有しても rewind）。
            assert_eq!(read_dir_entries(&root, 10).expect("again").len(), 2);
            assert_eq!(read_dir_entries(&root, 1), Err(ReadDirError::TooMany));
        }

        /// IO-5・TASK-19.2: `rename_beneath` は同じディレクトリ内で改名し（symlink は
        /// 辿らず symlink 自体を移す）、元が無ければ `Io(NotFound)`。
        #[test]
        fn io5_rename_beneath_moves_entry_within_dir() {
            let t = TmpDir::new("mv");
            let outside = TmpDir::new("mv-out");
            std::fs::write(t.0.join("a"), b"payload").expect("a");
            std::os::unix::fs::symlink(outside.0.join("victim"), t.0.join("l")).expect("symlink");
            let root = t.open();
            assert_eq!(rename_beneath(&root, "a", &root, "b"), Ok(()));
            assert!(!t.0.join("a").exists());
            assert_eq!(std::fs::read(t.0.join("b")).expect("b"), b"payload");
            assert_eq!(rename_beneath(&root, "l", &root, "m"), Ok(()));
            assert!(
                std::fs::symlink_metadata(t.0.join("m"))
                    .expect("m")
                    .file_type()
                    .is_symlink()
            );
            assert!(!outside.0.join("victim").exists());
            assert_eq!(
                rename_beneath(&root, "missing", &root, "x"),
                Err(BeneathError::Io(io::ErrorKind::NotFound))
            );
        }

        /// IO-5・TASK-19.2: `unlink_beneath` は通常ファイル・空ディレクトリを消し、
        /// 空でないディレクトリは消さない。
        #[test]
        fn io5_unlink_beneath_file_and_empty_dir() {
            let t = TmpDir::new("rm");
            std::fs::write(t.0.join("f"), b"x").expect("f");
            std::fs::create_dir(t.0.join("e")).expect("e");
            std::fs::create_dir(t.0.join("n")).expect("n");
            std::fs::write(t.0.join("n").join("inner"), b"x").expect("inner");
            let root = t.open();
            assert_eq!(unlink_beneath(&root, "f", UnlinkTarget::File), Ok(()));
            assert!(!t.0.join("f").exists());
            assert_eq!(
                unlink_beneath(&root, "e", UnlinkTarget::EmptyDirectory),
                Ok(())
            );
            assert!(!t.0.join("e").exists());
            let err = unlink_beneath(&root, "n", UnlinkTarget::EmptyDirectory).err();
            assert!(
                matches!(
                    err,
                    Some(BeneathError::Io(
                        io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::AlreadyExists
                    ))
                ),
                "{err:?}"
            );
            assert!(t.0.join("n").join("inner").exists());
            assert_eq!(
                unlink_beneath(&root, "missing", UnlinkTarget::File),
                Err(BeneathError::Io(io::ErrorKind::NotFound))
            );
        }
    }
}
