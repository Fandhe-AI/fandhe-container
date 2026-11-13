//! SIGTERM 受信フラグの登録と、イメージパスの symlink 非追従での要素ごとの open
//! （`unsafe` 事前承認の範囲。#3746・#3748。PLUG-1・REPAIR-3・REPAIR-5。
//! coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//! 方式は `fandhe-container-plugin-macos` の `sys.rs`（TASK-115.5・#389）を写したもの。
//!
//! # 呼び出し文脈
//! `main.rs` が接続前に [`install_sigterm_flag`] を 1 回呼び、得たフラグを `frame_loop::serve_until` へ渡す
//! （#3747）。フラグが立つと受付をやめ、`stop_all` で起動中の VM を止めてから終了する。
//! `open_regular_nofollow` は `adapter::read_image_blocking`（`start` のイメージ読み込み）から呼ばれ、
//! 祖先の symlink を `openat(O_NOFOLLOW)` の要素ごとの解決で拒否する（SEC-1。#3748）。
//! core 自身の終了要求は SIGTERM ではなく接続切断（EOF）で伝わる。
//!
//! 製品の依存に `libc` は入れず（dev-dependencies で照合にだけ使う。#4726）、`nix` は不採用（dependency-policy）で、std にシグナル API が無いため、
//! 最小限の `extern "C"` 宣言を自前で持つ。`struct sigaction` は OS・アーキテクチャでレイアウトが異なるため
//! 使わず、番号とハンドラのアドレスだけを取る `signal(3)`（glibc・musl・macOS とも BSD セマンティクスで、
//! ハンドラは解除されず再設定も不要）を使う。
//!
//! # SIGUSR2 との非衝突
//! SIGTERM（15）と、`fandhe-container-microvm` の vCPU 実行が使う SIGUSR2（12）は、プロセス全体の別々の
//! disposition の枠である。ここの `signal(15, ..)` は SIGUSR2 の disposition もスレッドのマスクも変えない。
//! microvm の `install_kick_handler` は SIGUSR2 の枠だけを照会・導入し SIGTERM の枠には触れないため、
//! 登録の順序に関わらず互いの導入が `EBUSY` 等で失敗することはない。
//! SIGTERM は process-directed なので、vCPU スレッドが `KVM_RUN` 中に受けることもある。その場合 `KVM_RUN` は
//! EINTR で戻り、microvm の `device.rs` が `VcpuExit::Interrupted` に分類して再実行する（`stats.interrupted` が
//! 増えるだけ）。ハンドラは atomic store のみなので、どのスレッドで走っても安全である。
//! 呼び出し側の規約として、本 crate を組み込むプロセスは SIGUSR2 を他の用途に使わない（`lib.rs` の注意と同じ）。
//!
//! # 契約
//! - `unsafe fn` は公開しない。公開する安全な API は [`install_sigterm_flag`] と `open_regular_nofollow`
//!   （`pub(crate)`）のみ。
//! - ハンドラは `static AtomicBool` への `store` だけを行う（async-signal-safe。確保・ロック・I/O をしない）。
//! - 登録するのは `SIGTERM` の番号を確認済みの組（Linux の x86_64 / aarch64・macOS）だけ。
//! - Linux の他アーキテクチャは番号が未確認のため登録を試みず、`UNIMPLEMENTED` を返す（fail-closed）。
//! - Linux・macOS 以外（Windows・他の unix）は何も登録せず、決して立たないフラグを `Ok` で返す
//!   （実装済みを装わない。REPAIR-3）。Windows には SIGTERM 経路が無く（コンソール制御ハンドラ等は未実装）、
//!   他の unix では SIGTERM が既定動作のまま届き、後始末を経ずに即終了して VM は止まらない。
//! - 返したフラグを立てるのはハンドラだけ、というのは呼び出し側の規約である。戻り値は
//!   `&'static AtomicBool` で `store` を呼べるため、型では強制していない。
//! - 現状の本 crate と microvm には fork / exec の呼び出しが無く、捕捉中のハンドラの子への継承は問題にならない
//!   （exec した子では SIG_DFL に戻る）。fork を足すときは plugin-cri の検討（#3300）を参照する。
//!
//! # 限界（残存リスク）
//! SIGKILL は捕捉できない。`stop_all` が送信側の猶予内に終わらず SIGKILL された場合、VM は残留しうる
//! （#3722 の範囲）。SIGINT / SIGHUP は対象外。
//!
//! # 共有ではなく写した理由（#3748）
//! 要素ごとの `openat` の辿り方は `fandhe-container-plugin` の `open_dir_nofollow`（#1309）と同じ方式を写した。
//! plugin 側は `pub(crate)` で、外部 plugin 作者もリンクする境界 crate（`MIT OR Apache-2.0`）にファイルシステムの
//! 補助を公開 API として足すと面が広がる。io の `guest_files`（#3352）は共有ルートの意味づけと結びつき、
//! core は本 crate の依存ではない（足すと PLUG-1・PLUG-4 の層構造に反する）。再評価条件: 同じ辿り方の写しが
//! 3 つ目になったら共有の下位 crate を検討する（`docs/design/fdinfo-mnt-id-parsing.md` と同じ形）。
//! 対象は macOS と Linux の x86_64 / aarch64 で、他の unix は `Unsupported`、Windows は対象外（未検査）。
//!
//! # libc との機械照合
//! dev-dependencies の `libc`（#3290 の承認・#4726）と、`imp::libc_abi`・`nofollow::libc_abi` で `const` 評価により
//! 照合する（方式は `docs/design/ffi-libc-check.md`。MVM-4・REPAIR-12）。あわせて番号（`SIGTERM`・`O_*`・`AT_FDCWD`・
//! `ELOOP`・`ENOTDIR`）を具体値で固定する試験も併置して残す。出典は
//! `O_*` / `AT_FDCWD` が Linux の `include/uapi/asm-generic/fcntl.h`・`arch/arm64/include/uapi/asm/fcntl.h`・
//! macOS の `sys/fcntl.h`。`ELOOP` / `ENOTDIR` は Linux の `include/uapi/asm-generic/errno.h`・`errno-base.h` と macOS の `sys/errno.h`（#3841）。`SIGTERM` の出典は Linux `include/uapi/asm-generic/signal.h`
//! （SIGTERM=15。x86_64・aarch64 とも同じ）と macOS `sys/signal.h`（同値）、`SIG_ERR` は `(sighandler_t)-1`
//! で、手作業で突き合わせた値である。

use std::sync::atomic::AtomicBool;

use fandhe_container_plugin::PluginError;

/// SIGTERM 受信で立つフラグ。本モジュール内で立てるのはハンドラだけ。[`install_sigterm_flag`] が
/// `&'static AtomicBool` として外へ渡すため、呼び出し側が立てないことは規約であり型では強制していない。
static SIGTERM_RECEIVED: AtomicBool = AtomicBool::new(false);

// `SIGTERM` の番号を確認済みの組だけで有効にする。Linux の他アーキテクチャは実行時に `UNIMPLEMENTED` で
// 拒否する（ビルドは通すが起動は拒否。plugin-macos と同じ判断）。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod imp {
    use std::sync::atomic::Ordering;

    use super::SIGTERM_RECEIVED;

    // SIGTERM は Linux（x86_64 / aarch64）・macOS とも 15 だが、アーキテクチャ差の流用を避けるため個別に定義する。
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) const SIGTERM: i32 = 15;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub(super) const SIGTERM: i32 = 15;
    #[cfg(target_os = "macos")]
    pub(super) const SIGTERM: i32 = 15;

    /// `signal(3)` の失敗値 `SIG_ERR`（`(sighandler_t)-1`）。
    const SIG_ERR: usize = usize::MAX;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX の `sighandler_t signal(int, sighandler_t)`。
        // 前提は、本モジュールが有効になる組で `sighandler_t`（関数ポインタ）と `usize` が同じ幅で、
        // 整数レジスタで同じように受け渡されること。幅は直下の const assert がコンパイル時に確かめる。
        fn signal(signum: i32, handler: usize) -> usize;
    }

    // 上の宣言の前提（関数ポインタと `usize` が同幅）をコンパイル時に確かめる。
    const _: () = assert!(size_of::<extern "C" fn(i32)>() == size_of::<usize>());

    /// SIGTERM ハンドラ。atomic store のみ（async-signal-safe）。
    extern "C" fn on_sigterm(_signum: i32) {
        SIGTERM_RECEIVED.store(true, Ordering::SeqCst);
    }

    /// ハンドラを登録する。成功なら `true`。
    pub(super) fn install() -> bool {
        let handler: extern "C" fn(i32) = on_sigterm;
        // SAFETY: ハンドラは `'static` な関数で、単一の `static AtomicBool` 以外に触れない。
        // シグナルはどのスレッドにも配送され得るが、atomic store のみのため安全。BSD セマンティクスで
        // ハンドラは解除されないため、2 回目以降の SIGTERM もフラグを再度立てるだけでプロセスを殺さない。
        let prev = unsafe { signal(SIGTERM, handler as usize) };
        prev != SIG_ERR
    }
    /// 自前の FFI 宣言を dev-dependencies の `libc` とコンパイル時に照合する（#4726・MVM-4・REPAIR-12。
    /// 方式は `docs/design/ffi-libc-check.md`）。`const` の評価なので食い違えばビルドが落ちる。
    /// 関数は呼ばず型だけを比べる（`unsafe` は足さない）。
    ///
    /// 対象外: 構造体は無い（`struct sigaction` は使わない）。`install` は FFI でない安全なラッパー。
    /// 宣言側に gnu / musl の分岐は無く、`target_env` では分けない。
    #[cfg(test)]
    mod libc_abi {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        const _: () = assert!(super::SIGTERM == libc::SIGTERM);
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        const _: () = assert!(super::SIGTERM == libc::SIGTERM);
        #[cfg(target_os = "macos")]
        const _: () = assert!(super::SIGTERM == libc::SIGTERM);

        // `sighandler_t` は `libc` で整数。自前は `usize`（`as` で合わせず値と幅を直接比べる）。
        const _: () = assert!(super::SIG_ERR == libc::SIG_ERR);
        const _: () = assert!(size_of::<usize>() == size_of::<libc::sighandler_t>());

        const _: unsafe extern "C" fn(libc::c_int, libc::sighandler_t) -> libc::sighandler_t =
            super::signal;
        const _: unsafe extern "C" fn(libc::c_int, libc::sighandler_t) -> libc::sighandler_t =
            libc::signal;

        // `libc` に型付きのハンドラ型は無い（`sighandler_t` は整数）ため、引数型だけを確かめる。
        const _: extern "C" fn(libc::c_int) = super::on_sigterm;
    }
}

/// SIGTERM 受信フラグを登録して返す。接続前に 1 回だけ呼ぶ。
///
/// 登録失敗は `INTERNAL`、Linux の未確認アーキテクチャは `UNIMPLEMENTED`（どちらも固定文言）。
/// VM を安全に止められない状態で動かさないため、呼び出し側は fail-closed で終了する。
/// Linux・macOS 以外（Windows・他の unix）では登録せず、決して立たないフラグを `Ok` で返す
/// （SIGTERM での後始末は効かない。モジュール doc「契約」参照。REPAIR-3）。
pub fn install_sigterm_flag() -> Result<&'static AtomicBool, PluginError> {
    register()?;
    Ok(&SIGTERM_RECEIVED)
}

/// 対応済みの組: ハンドラを登録する。失敗は `INTERNAL`。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn register() -> Result<(), PluginError> {
    if imp::install() {
        Ok(())
    } else {
        Err(PluginError::new(
            fandhe_container_plugin::PluginErrorCode::Internal,
            "failed to install SIGTERM handler",
        ))
    }
}

/// Linux の未確認アーキテクチャ: `SIGTERM` の番号を持たないため登録を試みず拒否する（fail-closed）。
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn register() -> Result<(), PluginError> {
    Err(PluginError::new(
        fandhe_container_plugin::PluginErrorCode::Unimplemented,
        "SIGTERM handler is not supported on this architecture",
    ))
}

/// Linux・macOS 以外: 何も登録しない（決して立たないフラグを返す側。REPAIR-3）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn register() -> Result<(), PluginError> {
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// イメージパスの symlink 非追従 open（SEC-1・PLUG-1・REPAIR-3。#3748）
// ---------------------------------------------------------------------------------------------

/// [`open_regular_nofollow`] の失敗。`io::Error` を保持し、分類は呼び出し側が [`is_not_real_entry`]
/// （ELOOP / ENOTDIR）と `io::ErrorKind`（NotFound / PermissionDenied）で行う（ERR-1・#3841）。
/// 呼び出し側（`adapter::read_image_blocking`）が固定文言へ写し、パスも OS のエラー文言も応答に載せない。
#[cfg(unix)]
#[derive(Debug)]
pub(crate) enum NoFollowOpenError {
    /// 絶対パスの `RootDir` + `Normal` 要素だけの形ではない（相対・最終要素なし・NUL を含む）。
    InvalidPath,
    /// 祖先の 1 要素を `O_DIRECTORY | O_NOFOLLOW` で開けなかった。祖先が symlink のとき Linux・macOS とも
    /// `ENOTDIR` を返す（macOS は run 41746560647 で実測。#3870）。祖先が通常ファイルのときも同じ `ENOTDIR` のため、
    /// errno だけでは「祖先が symlink」と「祖先がディレクトリでない」を区別できず、どちらも「祖先が実ディレクトリでは
    /// ない」（`MSG_BAD_ANCESTOR`）として拒否する。区別する分類は未実装（REPAIR-3）。それ以外の errno は内部エラー。
    Ancestor(std::io::Error),
    /// 最終要素を `O_NOFOLLOW` で開けなかった（lstat の後に symlink へ差し替えられた場合の `ELOOP` を含む。
    /// `ELOOP` / `ENOTDIR` は「実体ではない」、それ以外の errno は内部エラー）。
    Leaf(std::io::Error),
    /// 定数を確認済みの組（macOS・Linux の x86_64 / aarch64）ではない。検査を省いて読まず拒否する（fail-closed）。
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    Unsupported,
}

#[cfg(all(
    unix,
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
mod nofollow {
    use std::ffi::{CString, c_char};
    use std::fs::File;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::path::{Component, Path};

    use super::NoFollowOpenError;

    // アーキテクチャ差の流用を避けるため、組ごとに個別に定義する（aarch64 に x86_64 の値を使うと
    // `O_DIRECT` / `O_LARGEFILE` になる）。
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) const O_DIRECTORY: i32 = 0o200000;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) const O_NOFOLLOW: i32 = 0o400000;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub(super) const O_DIRECTORY: i32 = 0o40000;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub(super) const O_NOFOLLOW: i32 = 0o100000;
    #[cfg(target_os = "linux")]
    pub(super) const O_CLOEXEC: i32 = 0o2000000;
    #[cfg(target_os = "linux")]
    pub(super) const O_NONBLOCK: i32 = 0o4000;
    /// 最終要素が lstat の後に tty 等の文字デバイスへ差し替えられても、制御端末を持たないセッションリーダーの
    /// plugin が制御端末を取得しないようにする（SEC-1・#3841）。x86_64 / aarch64 とも同値。
    #[cfg(target_os = "linux")]
    pub(super) const O_NOCTTY: i32 = 0o400;
    #[cfg(target_os = "linux")]
    pub(super) const AT_FDCWD: i32 = -100;
    /// `ELOOP`（symlink の追従拒否）。Linux は 40、macOS は 62（`errno.h` / `sys/errno.h`）。
    #[cfg(target_os = "linux")]
    pub(super) const ELOOP: i32 = 40;
    /// `ENOTDIR`（祖先が実ディレクトリではない）。Linux・macOS とも 20。
    pub(super) const ENOTDIR: i32 = 20;
    /// 祖先の走査は検索（x）権限だけで通す（読み取り権限は要らない。symlink の拒否に一覧の読み取りは不要）。
    /// `O_PATH` は x86_64 / aarch64 とも同値（`0o10000000`）。macOS には `O_PATH` が無く `O_RDONLY` のまま。
    #[cfg(target_os = "linux")]
    pub(super) const O_PATH: i32 = 0o10000000;
    #[cfg(target_os = "macos")]
    pub(super) const O_PATH: i32 = 0;
    #[cfg(target_os = "macos")]
    pub(super) const O_DIRECTORY: i32 = 0x0010_0000;
    #[cfg(target_os = "macos")]
    pub(super) const O_NOFOLLOW: i32 = 0x0100;
    #[cfg(target_os = "macos")]
    pub(super) const O_CLOEXEC: i32 = 0x0100_0000;
    #[cfg(target_os = "macos")]
    pub(super) const O_NONBLOCK: i32 = 0x4;
    #[cfg(target_os = "macos")]
    pub(super) const O_NOCTTY: i32 = 0x0002_0000;
    #[cfg(target_os = "macos")]
    pub(super) const ELOOP: i32 = 62;
    #[cfg(target_os = "macos")]
    pub(super) const AT_FDCWD: i32 = -2;

    /// 祖先の open フラグ。macOS は `O_PATH` が無く実際に開くため `O_NOCTTY` が効く（Linux では `O_PATH` が無視する）。
    pub(super) const DIR_FLAGS: i32 = O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY;
    /// 最終要素の open フラグ。`O_NONBLOCK` は FIFO で止まらないため、`O_NOCTTY` は制御端末の取得を避けるため。
    pub(super) const LEAF_FLAGS: i32 = O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | O_NOCTTY;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX の `int openat(int, const char *, int, ...)`。
        // `O_CREAT` / `O_TMPFILE` を使わないため mode（可変長引数）は渡さない。
        #[link_name = "openat"]
        fn c_openat(dirfd: i32, path: *const c_char, flags: i32, ...) -> i32;
    }

    /// `dirfd` 基準で `name`（1 要素）を `flags` で開く。
    fn openat_raw(dirfd: i32, name: &CString, flags: i32) -> io::Result<File> {
        // SAFETY: `name` は NUL 終端の `CString` で、呼び出しの間生きている。`dirfd` は呼び出し側が保持する
        // 開いた fd（または `AT_FDCWD`）で、本関数は閉じない。mode を取らないフラグだけを渡す（`O_NOCTTY` も mode を取らない）。
        let fd = unsafe { c_openat(dirfd, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `openat` が返した非負の新しい fd で、他に所有者がいない。`File` が唯一の所有者になる。
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub(super) fn open(abs: &Path) -> Result<File, NoFollowOpenError> {
        let mut comps = abs.components();
        if comps.next() != Some(Component::RootDir) {
            return Err(NoFollowOpenError::InvalidPath);
        }
        let mut names = Vec::new();
        for c in comps {
            match c {
                Component::Normal(n) => names
                    .push(CString::new(n.as_bytes()).map_err(|_| NoFollowOpenError::InvalidPath)?),
                _ => return Err(NoFollowOpenError::InvalidPath),
            }
        }
        let Some((leaf, ancestors)) = names.split_last() else {
            return Err(NoFollowOpenError::InvalidPath);
        };
        let dir_flags = DIR_FLAGS;
        // `/` は信頼する起点。以降は検証済みの親 fd を基準に 1 要素ずつ辿る（前の fd は代入で閉じる）。
        let root = CString::new("/").map_err(|_| NoFollowOpenError::InvalidPath)?;
        let mut cur =
            openat_raw(AT_FDCWD, &root, dir_flags).map_err(NoFollowOpenError::Ancestor)?;
        for name in ancestors {
            cur = openat_raw(cur.as_raw_fd(), name, dir_flags)
                .map_err(NoFollowOpenError::Ancestor)?;
        }
        openat_raw(cur.as_raw_fd(), leaf, LEAF_FLAGS).map_err(NoFollowOpenError::Leaf)
    }

    /// 自前の FFI 宣言を dev-dependencies の `libc` とコンパイル時に照合する（#4726・MVM-4・REPAIR-12。
    /// 方式は `docs/design/ffi-libc-check.md`）。評価されるのは x86_64 Linux のネイティブと、
    /// cross-target-check の `aarch64-unknown-linux-gnu`・`aarch64-apple-darwin`。
    ///
    /// 対象外: macOS の `O_PATH = 0`（macOS に `O_PATH` は無く、0 は本 crate で決めた値。出典は macOS `sys/fcntl.h`）、
    /// `DIR_FLAGS`・`LEAF_FLAGS`（方針で組み合わせた値で、構成要素は照合済み。組み合わせは `sec1_3748_constants_*` が見る）、
    /// `openat_raw`・`open`・`is_not_real_entry` 等の安全なラッパー。
    #[cfg(test)]
    mod libc_abi {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        const _: () = assert!(super::O_DIRECTORY == libc::O_DIRECTORY);
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        const _: () = assert!(super::O_NOFOLLOW == libc::O_NOFOLLOW);
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        const _: () = assert!(super::O_DIRECTORY == libc::O_DIRECTORY);
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        const _: () = assert!(super::O_NOFOLLOW == libc::O_NOFOLLOW);
        #[cfg(target_os = "linux")]
        const _: () = assert!(super::O_CLOEXEC == libc::O_CLOEXEC);
        #[cfg(target_os = "linux")]
        const _: () = assert!(super::O_NONBLOCK == libc::O_NONBLOCK);
        #[cfg(target_os = "linux")]
        const _: () = assert!(super::O_NOCTTY == libc::O_NOCTTY);
        #[cfg(target_os = "linux")]
        const _: () = assert!(super::AT_FDCWD == libc::AT_FDCWD);
        #[cfg(target_os = "linux")]
        const _: () = assert!(super::ELOOP == libc::ELOOP);
        #[cfg(target_os = "linux")]
        const _: () = assert!(super::O_PATH == libc::O_PATH);

        #[cfg(target_os = "macos")]
        const _: () = assert!(super::O_DIRECTORY == libc::O_DIRECTORY);
        #[cfg(target_os = "macos")]
        const _: () = assert!(super::O_NOFOLLOW == libc::O_NOFOLLOW);
        #[cfg(target_os = "macos")]
        const _: () = assert!(super::O_CLOEXEC == libc::O_CLOEXEC);
        #[cfg(target_os = "macos")]
        const _: () = assert!(super::O_NONBLOCK == libc::O_NONBLOCK);
        #[cfg(target_os = "macos")]
        const _: () = assert!(super::O_NOCTTY == libc::O_NOCTTY);
        #[cfg(target_os = "macos")]
        const _: () = assert!(super::ELOOP == libc::ELOOP);
        #[cfg(target_os = "macos")]
        const _: () = assert!(super::AT_FDCWD == libc::AT_FDCWD);

        const _: () = assert!(super::ENOTDIR == libc::ENOTDIR);

        // `openat` は可変長。`libc` も可変長のため、同じ関数ポインタ型へ両方を代入して照合する
        // （可変長の有無が食い違うと Apple arm64 で ABI が不一致になる）。自前名 `c_openat` は
        // `link_name = "openat"` で同じシンボルを指す。
        type OpenatFn =
            unsafe extern "C" fn(libc::c_int, *const libc::c_char, libc::c_int, ...) -> libc::c_int;
        const _: OpenatFn = super::c_openat;
        const _: OpenatFn = libc::openat;
    }
}

/// open の失敗が「実体ではない」（`ELOOP` / `ENOTDIR`）か。`adapter::map_nofollow_error` が入力不正
/// （`INVALID_ARGUMENT`）と内部エラー（`INTERNAL`）の分けに使う（ERR-1・SEC-1・#3841）。
/// 定数を確認済みでない unix の組は常に `false`（fail-closed。そもそも `Unsupported` で読まない）。
#[cfg(unix)]
pub(crate) fn is_not_real_entry(e: &std::io::Error) -> bool {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        matches!(e.raw_os_error(), Some(n) if n == nofollow::ELOOP || n == nofollow::ENOTDIR)
    }
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = e;
        false
    }
}

/// 絶対パスを `/` から要素ごとに `openat(O_NOFOLLOW)` で辿り、最終要素を読み取りで開く。
/// 祖先に symlink があれば [`NoFollowOpenError::Ancestor`]、最終要素が symlink なら `Leaf` で拒否する。
/// 最終要素は `O_NONBLOCK` 付きで開くため FIFO 等で止まらず、`O_NOCTTY` 付きで制御端末も取得しない（通常ファイルの読み取りには影響しない）。
/// ディレクトリや FIFO は開いて返す（種別の拒否は呼び出し側の fstat。#3842）。
/// 区切りの重複・末尾 `/`・途中の `.` は `Path::components` の正規化で受理される（安全性は `O_NOFOLLOW` が担う）。
/// 末尾 `/` の受理が経路全体で観測されないのは、呼び出し元 `adapter::read_image_blocking` が先に生のパスを
/// `symlink_metadata` するため、通常ファイル + 末尾 `/` はそこで `ENOTDIR` で失敗するから（#3866・SEC-1）。
/// その失敗は adapter の `map_lstat_error` が `INVALID_ARGUMENT` / `MSG_NOT_REGULAR` に分類する（#3890）。
/// 呼び出し元は `adapter::read_image_blocking`（`start` のイメージ読み込み）。
#[cfg(unix)]
pub(crate) fn open_regular_nofollow(
    abs: &std::path::Path,
) -> Result<std::fs::File, NoFollowOpenError> {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        nofollow::open(abs)
    }
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = abs;
        Err(NoFollowOpenError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 対応済みの組の番号を具体値で固定する（libc 照合と併置する具体値の固定。PLUG-1）。
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn plug1_sigterm_number_is_15() {
        assert_eq!(imp::SIGTERM, 15);
    }

    /// 子プロセス（自己再実行）の役を示す環境変数。値 `1` のときだけ、下の試験が登録と送信を行う。
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    const SIGTERM_CHILD_ENV: &str = "FANDHE_CONTAINER_PLUGIN_MICROVM_SIGTERM_CHILD";

    /// 子プロセスへ SIGTERM を送るとフラグが立ち、子は落ちず、2 回目でも立ったままである
    /// （PLUG-1・REPAIR-5・#3842）。送信は `kill` コマンドで行い、unsafe の面を `signal` 1 箇所に保つ。
    ///
    /// `install_sigterm_flag` はプロセス全体の SIGTERM の disposition を変えるため、試験バイナリ自身で
    /// 呼ぶと外からの SIGTERM による停止が効かなくなる。そこで自己再実行した子プロセスの中でだけ登録と
    /// 送信を行い、親（試験バイナリ本体）の SIGTERM の挙動は変えない。親は子の固定行と `1 passed` を
    /// 期限つきで照合する（子のハングは kill して失敗にする。REPAIR-5）。
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn task117_plug1_repair5_sigterm_to_self_sets_flag() {
        use std::sync::atomic::Ordering;
        use std::time::{Duration, Instant};

        if std::env::var(SIGTERM_CHILD_ENV).as_deref() == Ok("1") {
            fn send_term() {
                let status = std::process::Command::new("kill")
                    .args(["-TERM", &std::process::id().to_string()])
                    .status()
                    .expect("spawn kill");
                assert!(status.success(), "kill -TERM failed: {status:?}");
            }

            assert!(!SIGTERM_RECEIVED.load(Ordering::SeqCst));
            let flag = install_sigterm_flag().expect("install");
            assert!(std::ptr::eq(flag, &SIGTERM_RECEIVED));
            assert!(!flag.load(Ordering::SeqCst));

            send_term();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !flag.load(Ordering::SeqCst) {
                assert!(
                    Instant::now() < deadline,
                    "SIGTERM flag not set within 5s of kill -TERM"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            println!("sigterm-child: flag_set=1");

            // BSD セマンティクスでハンドラが残ること: 2 回目でもプロセスが生きていて、フラグは立ったまま。
            send_term();
            std::thread::sleep(Duration::from_millis(50));
            assert!(flag.load(Ordering::SeqCst));
            println!("sigterm-child: survived_second=1");
            return;
        }

        // 親: 試験バイナリ本体は登録しない（SIGTERM の disposition を変えない）。
        assert!(!SIGTERM_RECEIVED.load(Ordering::SeqCst));
        // `module_path!()` は `<crate>::sys::tests`。libtest の試験名は crate 名を含まない。
        let module = module_path!();
        let name = format!(
            "{}::task117_plug1_repair5_sigterm_to_self_sets_flag",
            module.split_once("::").map_or(module, |(_, rest)| rest)
        );
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = std::process::Command::new(exe)
            .args(["--exact", &name, "--test-threads=1", "--nocapture"])
            .env(SIGTERM_CHILD_ENV, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn child");
        // 出力は別スレッドで読み切る（パイプ詰まりで子が止まるのを避ける）。
        let mut out = child.stdout.take().expect("stdout");
        let mut err = child.stderr.take().expect("stderr");
        let t_out = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = std::io::Read::read_to_string(&mut out, &mut s);
            s
        });
        let t_err = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = std::io::Read::read_to_string(&mut err, &mut s);
            s
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(st) = child.try_wait().expect("try_wait") {
                break st;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("sigterm child did not finish within 30s");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout = t_out.join().expect("join stdout");
        let stderr = t_err.join().expect("join stderr");
        assert!(
            status.success(),
            "child failed: {status:?}\n{stdout}\n{stderr}"
        );
        for want in [
            "sigterm-child: flag_set=1",
            "sigterm-child: survived_second=1",
        ] {
            let n = stdout.lines().filter(|l| l.contains(want)).count();
            assert_eq!(n, 1, "expected exactly one `{want}`:\n{stdout}");
        }
        // 名前の誤りで 0 件実行になった場合は固定行が欠けて上で失敗する。要約行も具体値で確認する。
        assert!(
            stdout.lines().any(|l| l.contains("1 passed")),
            "libtest summary missing:\n{stdout}"
        );
    }

    /// Linux の未確認アーキテクチャは `UNIMPLEMENTED` で拒否し、フラグは立たない。
    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    #[test]
    fn plug1_unknown_linux_arch_is_unimplemented() {
        use std::sync::atomic::Ordering;
        let e = install_sigterm_flag().expect_err("must be rejected");
        assert_eq!(
            e.code(),
            fandhe_container_plugin::PluginErrorCode::Unimplemented
        );
        assert_eq!(
            e.message(),
            "SIGTERM handler is not supported on this architecture"
        );
        assert!(!SIGTERM_RECEIVED.load(Ordering::SeqCst));
    }

    /// Windows・他の unix は何も登録せず、決して立たないフラグを `Ok` で返す（REPAIR-3）。
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn repair3_unsupported_os_returns_never_set_flag() {
        use std::sync::atomic::Ordering;
        let flag = install_sigterm_flag().expect("ok");
        assert!(!flag.load(Ordering::SeqCst));
    }

    /// 定数を具体値で固定する（libc 照合と併置する具体値の固定。SEC-1）。
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn sec1_3748_constants_linux_x86_64() {
        use super::nofollow::*;
        assert_eq!(
            (O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC, O_NONBLOCK, AT_FDCWD),
            (0o200000, 0o400000, 0o2000000, 0o4000, -100)
        );
        assert_eq!(O_NOCTTY, 0o400);
        assert_eq!(LEAF_FLAGS, 0o400000 | 0o2000000 | 0o4000 | 0o400);
        assert_eq!(
            DIR_FLAGS,
            0o10000000 | 0o200000 | 0o400000 | 0o2000000 | 0o400
        );
        assert_eq!((ELOOP, ENOTDIR), (40, 20));
        assert_eq!(O_PATH, 0o10000000);
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    #[test]
    fn sec1_3748_constants_linux_aarch64() {
        use super::nofollow::*;
        assert_eq!(
            (O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC, O_NONBLOCK, AT_FDCWD),
            (0o40000, 0o100000, 0o2000000, 0o4000, -100)
        );
        assert_eq!(O_NOCTTY, 0o400);
        assert_eq!(LEAF_FLAGS, 0o100000 | 0o2000000 | 0o4000 | 0o400);
        assert_eq!(
            DIR_FLAGS,
            0o10000000 | 0o40000 | 0o100000 | 0o2000000 | 0o400
        );
        assert_eq!((ELOOP, ENOTDIR), (40, 20));
        assert_eq!(O_PATH, 0o10000000);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sec1_3748_constants_macos() {
        use super::nofollow::*;
        assert_eq!(
            (O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC, O_NONBLOCK, AT_FDCWD),
            (0x0010_0000, 0x0100, 0x0100_0000, 0x4, -2)
        );
        assert_eq!(O_NOCTTY, 0x0002_0000);
        assert_eq!(LEAF_FLAGS, 0x0100 | 0x0100_0000 | 0x4 | 0x0002_0000);
        assert_eq!(DIR_FLAGS, 0x0010_0000 | 0x0100 | 0x0100_0000 | 0x0002_0000);
        assert_eq!((ELOOP, ENOTDIR), (62, 20));
    }

    // `sec1_3841_is_not_real_entry_by_errno` の errno リテラルを `libc` と照合する（#4726）。
    #[cfg(target_os = "linux")]
    const _: () = {
        assert!(libc::ELOOP == 40 && libc::ENAMETOOLONG == 36 && libc::ETIMEDOUT == 110);
        assert!(libc::ENOTDIR == 20 && libc::EMFILE == 24 && libc::EIO == 5);
        assert!(libc::ENOENT == 2 && libc::EACCES == 13 && libc::EPERM == 1);
    };
    #[cfg(target_os = "macos")]
    const _: () = {
        assert!(libc::ELOOP == 62 && libc::ENAMETOOLONG == 63 && libc::ETIMEDOUT == 60);
        assert!(libc::ENOTDIR == 20 && libc::EMFILE == 24 && libc::EIO == 5);
        assert!(libc::ENOENT == 2 && libc::EACCES == 13 && libc::EPERM == 1);
    };

    /// errno の分類（ERR-1・SEC-1・#3841）。ELOOP / ENOTDIR だけが「実体ではない」。
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn sec1_3841_is_not_real_entry_by_errno() {
        use std::io::Error;
        #[cfg(target_os = "linux")]
        let (eloop, enametoolong, etimedout) = (40, 36, 110);
        #[cfg(target_os = "macos")]
        let (eloop, enametoolong, etimedout) = (62, 63, 60);
        for n in [eloop, 20] {
            assert!(is_not_real_entry(&Error::from_raw_os_error(n)), "{n}");
        }
        for n in [24, 5, 2, 13, 1, enametoolong, etimedout] {
            assert!(!is_not_real_entry(&Error::from_raw_os_error(n)), "{n}");
        }
        assert!(!is_not_real_entry(&Error::other("no errno")));
    }

    #[cfg(all(
        unix,
        any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )
    ))]
    mod nofollow_cases {
        use super::super::{NoFollowOpenError, open_regular_nofollow};
        use std::io::Read;
        use std::path::PathBuf;

        /// 正規化済みの一時ディレクトリ（macOS の `/var` → `/private/var` を避ける）。
        struct Dir(PathBuf);
        impl Dir {
            fn new(tag: &str) -> Self {
                let p = std::env::temp_dir().join(format!("fc-pmsys-{tag}-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&p);
                std::fs::create_dir_all(&p).expect("mkdir");
                Self(std::fs::canonicalize(&p).expect("canonicalize"))
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        /// errno の期待値（#3842。`io::ErrorKind::FilesystemLoop` は unstable のため `raw_os_error` で照合する）。
        /// 出典: Linux `include/uapi/asm-generic/errno-base.h`・`errno.h`、macOS `sys/errno.h`。
        /// macOS の値は CI（PR は ubuntu のみ）では実行されない。
        const EXP_ENOENT: i32 = 2;
        const EXP_ENOTDIR: i32 = 20;
        /// 最終要素が symlink（`O_NOFOLLOW`）のときの errno。Linux 40（ELOOP）、macOS 62（ELOOP）。
        #[cfg(target_os = "linux")]
        const EXP_ELOOP: i32 = 40;
        #[cfg(target_os = "macos")]
        const EXP_ELOOP: i32 = 62;
        /// 祖先が symlink（`O_PATH | O_DIRECTORY | O_NOFOLLOW`）のときの errno。Linux・macOS とも ENOTDIR。
        /// macOS の値は dispatch の run 41746560647（`platform-ci (macos-latest)`）で実測した（ELOOP ではない。#3870）。
        /// 祖先が通常ファイルのときと同じ errno のため、両者は errno では区別できない（REPAIR-3）。
        const EXP_ANCESTOR_SYMLINK: i32 = EXP_ENOTDIR;

        // 上の期待値を `libc` の errno と照合する（#4726。`sec1_3842_*` 系の試験が使う）。
        const _: () = assert!(EXP_ENOENT == libc::ENOENT);
        const _: () = assert!(EXP_ENOTDIR == libc::ENOTDIR);
        const _: () = assert!(EXP_ELOOP == libc::ELOOP);
        // `EXP_ANCESTOR_SYMLINK` は `EXP_ENOTDIR` の別名なので対象外。

        fn assert_raw(e: &std::io::Error, want: i32, ctx: &str) {
            assert_eq!(e.raw_os_error(), Some(want), "{ctx}: {e:?}");
        }

        /// `/proc/self/status` の `Uid:` 行の 2 番目（euid）。読めなければ panic（fail-closed）。
        #[cfg(target_os = "linux")]
        fn euid_from_proc() -> u32 {
            let s = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
            let line = s
                .lines()
                .find(|l| l.starts_with("Uid:"))
                .expect("Uid: line");
            line.split_whitespace()
                .nth(2)
                .expect("euid field")
                .parse()
                .expect("euid number")
        }

        /// 陽性対照: 実ディレクトリ配下の通常ファイルは開けて読める。
        #[test]
        fn sec1_3748_opens_real_file() {
            let d = Dir::new("pos");
            std::fs::create_dir(d.0.join("real")).expect("mkdir");
            std::fs::write(d.0.join("real/k"), b"abc").expect("write");
            let mut f = open_regular_nofollow(&d.0.join("real/k")).expect("open");
            let mut v = Vec::new();
            f.read_to_end(&mut v).expect("read");
            assert_eq!(v, b"abc");
        }

        /// 祖先が mode 0111（検索のみ）・最終要素が 0400 でも開ける（Linux）。
        /// root（euid 0）は権限ビットを無視して確認の意味を持たないため、成功扱いで抜けず明示的に失敗させる（#3842）。
        /// 非 root では `read_dir` が `PermissionDenied` になることを陰性対照に、O_PATH なら検索権限だけで辿れることを示す。
        #[cfg(target_os = "linux")]
        #[test]
        fn sec1_3748_opens_under_search_only_ancestor() {
            use std::os::unix::fs::PermissionsExt;
            assert_ne!(
                euid_from_proc(),
                0,
                "this test needs a non-root euid (mode bits are not enforced for root); run as a non-root user"
            );
            let d = Dir::new("x-only");
            let sub = d.0.join("xonly");
            std::fs::create_dir(&sub).expect("mkdir");
            std::fs::write(sub.join("k"), b"abc").expect("write");
            std::fs::set_permissions(sub.join("k"), std::fs::Permissions::from_mode(0o400))
                .expect("chmod file");
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o111))
                .expect("chmod dir");
            let neg = std::fs::read_dir(&sub).map(|_| ());
            let r = open_regular_nofollow(&sub.join("k"));
            // 後始末のため先に権限を戻す。
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755))
                .expect("restore");
            assert_eq!(
                neg.expect_err("read_dir must be denied").kind(),
                std::io::ErrorKind::PermissionDenied
            );
            let mut f = r.expect("open under mode 0111 ancestor");
            let mut v = Vec::new();
            f.read_to_end(&mut v).expect("read");
            assert_eq!(v, b"abc");
        }

        /// 祖先が symlink なら `Ancestor`。
        #[test]
        fn sec1_3748_rejects_symlinked_ancestor() {
            let d = Dir::new("anc");
            std::fs::create_dir(d.0.join("real")).expect("mkdir");
            std::fs::write(d.0.join("real/k"), b"abc").expect("write");
            std::os::unix::fs::symlink(d.0.join("real"), d.0.join("link")).expect("symlink");
            match open_regular_nofollow(&d.0.join("link/k")).unwrap_err() {
                NoFollowOpenError::Ancestor(e) => {
                    assert_raw(&e, EXP_ANCESTOR_SYMLINK, "ancestor symlink")
                }
                e => panic!("unexpected {e:?}"),
            }
        }

        /// 最終要素が symlink なら `Leaf`。
        #[test]
        fn sec1_3748_rejects_symlinked_leaf() {
            let d = Dir::new("leaf");
            std::fs::write(d.0.join("k"), b"abc").expect("write");
            std::os::unix::fs::symlink(d.0.join("k"), d.0.join("l")).expect("symlink");
            match open_regular_nofollow(&d.0.join("l")).unwrap_err() {
                NoFollowOpenError::Leaf(e) => assert_raw(&e, EXP_ELOOP, "leaf symlink"),
                e => panic!("unexpected {e:?}"),
            }
        }

        /// 祖先が無ければ `Ancestor` の `NotFound`、最終要素が無ければ `Leaf` の `NotFound`。
        #[test]
        fn sec1_3748_missing_components() {
            let d = Dir::new("miss");
            match open_regular_nofollow(&d.0.join("nodir/k")).unwrap_err() {
                NoFollowOpenError::Ancestor(e) => {
                    assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
                    assert_raw(&e, EXP_ENOENT, "missing ancestor");
                }
                e => panic!("unexpected {e:?}"),
            }
            match open_regular_nofollow(&d.0.join("k")).unwrap_err() {
                NoFollowOpenError::Leaf(e) => {
                    assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
                    assert_raw(&e, EXP_ENOENT, "missing leaf");
                }
                e => panic!("unexpected {e:?}"),
            }
        }

        /// 祖先を mode 0o000 にすると、祖先自体は `O_PATH` で開けるが、その下の最終要素の open が検索権限なしで
        /// `Leaf` の `PermissionDenied`（EACCES=13）になる。root では成功扱いにせず失敗させる（#3842・SEC-1）。
        #[cfg(target_os = "linux")]
        #[test]
        fn sec1_3842_unsearchable_ancestor_denies_leaf() {
            use std::os::unix::fs::PermissionsExt;
            assert_ne!(
                euid_from_proc(),
                0,
                "this test needs a non-root euid (mode bits are not enforced for root); run as a non-root user"
            );
            let d = Dir::new("anc000");
            let sub = d.0.join("noperm");
            std::fs::create_dir(&sub).expect("mkdir");
            std::fs::write(sub.join("k"), b"abc").expect("write");
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000))
                .expect("chmod dir");
            let r = open_regular_nofollow(&sub.join("k"));
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755))
                .expect("restore");
            match r.unwrap_err() {
                NoFollowOpenError::Leaf(e) => {
                    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
                    assert_raw(&e, 13, "search-denied ancestor");
                }
                e => panic!("unexpected {e:?}"),
            }
        }

        /// NUL を含むパスは open より前に `InvalidPath`（C 文字列が途中で切れて別パスを開かない。#3842・SEC-1）。
        #[test]
        fn sec1_3842_nul_is_invalid_path() {
            use std::os::unix::ffi::OsStrExt;
            let d = Dir::new("nul");
            std::fs::write(d.0.join("a"), b"abc").expect("write");
            let mut leaf = d.0.as_os_str().as_bytes().to_vec();
            leaf.extend_from_slice(b"/a\0b");
            let mut anc = d.0.as_os_str().as_bytes().to_vec();
            anc.extend_from_slice(b"\0x/a");
            for p in [leaf, anc, b"/tmp/a\0b".to_vec(), b"/tmp\0x/k".to_vec()] {
                let path = std::path::Path::new(std::ffi::OsStr::from_bytes(&p));
                let e = open_regular_nofollow(path).unwrap_err();
                assert!(matches!(e, NoFollowOpenError::InvalidPath), "{p:?}: {e:?}");
            }
        }

        /// `//`・途中の `//`・末尾 `/`・途中の `.` は `Path::components` が落とすため受理され、実ファイルが開く。
        /// 末尾 `/` は POSIX では ENOTDIR だが、adapter の `symlink_metadata` が先に失敗させ（分類は `INVALID_ARGUMENT` / `MSG_NOT_REGULAR`。#3890）、
        /// 安全性は `O_NOFOLLOW` で保たれる（#3842・SEC-1）。
        #[test]
        fn sec1_3842_redundant_separators_are_normalized() {
            let d = Dir::new("slashes");
            std::fs::create_dir(d.0.join("real")).expect("mkdir");
            std::fs::write(d.0.join("real/k"), b"abc").expect("write");
            let base = d.0.to_str().expect("utf8").to_string();
            for p in [
                format!("/{base}/real/k"),
                format!("{base}//real//k"),
                format!("{base}/real/k/"),
                format!("{base}/real/./k"),
            ] {
                let mut f = open_regular_nofollow(std::path::Path::new(&p))
                    .unwrap_or_else(|e| panic!("{p}: {e:?}"));
                let mut v = Vec::new();
                f.read_to_end(&mut v).expect("read");
                assert_eq!(v, b"abc", "{p}");
            }
        }

        /// 末尾 `/` 付きでもディレクトリへの symlink は追従しない（`Leaf` の ELOOP。#3842・SEC-1）。
        #[test]
        fn sec1_3842_trailing_slash_does_not_follow_leaf_symlink() {
            let d = Dir::new("tslink");
            std::fs::create_dir(d.0.join("real")).expect("mkdir");
            std::os::unix::fs::symlink(d.0.join("real"), d.0.join("dl")).expect("symlink");
            let p = format!("{}/dl/", d.0.to_str().expect("utf8"));
            match open_regular_nofollow(std::path::Path::new(&p)).unwrap_err() {
                NoFollowOpenError::Leaf(e) => assert_raw(&e, EXP_ELOOP, "trailing slash symlink"),
                e => panic!("unexpected {e:?}"),
            }
        }

        /// 最終要素がディレクトリなら sys は開く（種別の拒否は `adapter::read_image_blocking` の `is_file` 検査。
        /// 関数名の regular は呼び出し側との組で成り立つ。#3842・SEC-1）。
        #[test]
        fn sec1_3842_leaf_directory_opens_as_dir() {
            let d = Dir::new("leafdir");
            std::fs::create_dir(d.0.join("real")).expect("mkdir");
            let f = open_regular_nofollow(&d.0.join("real")).expect("open dir");
            let ft = f.metadata().expect("fstat").file_type();
            assert!(ft.is_dir());
            assert!(!ft.is_file());
        }

        /// 最終要素がディレクトリへの symlink は `Leaf` の ELOOP（#3842・SEC-1）。
        #[test]
        fn sec1_3842_leaf_symlink_to_dir_is_rejected() {
            let d = Dir::new("leafdirlink");
            std::fs::create_dir(d.0.join("real")).expect("mkdir");
            std::os::unix::fs::symlink(d.0.join("real"), d.0.join("dl")).expect("symlink");
            match open_regular_nofollow(&d.0.join("dl")).unwrap_err() {
                NoFollowOpenError::Leaf(e) => assert_raw(&e, EXP_ELOOP, "leaf symlink to dir"),
                e => panic!("unexpected {e:?}"),
            }
        }

        /// 最終要素が FIFO（書き手なし）でも `O_NONBLOCK` で止まらず開く（#3842・SEC-1・REPAIR-5）。
        /// 止まった場合は O_NONBLOCK の書き手で open を解放し、期限つきで待ってから失敗にする。
        #[test]
        fn sec1_3842_leaf_fifo_does_not_block() {
            use std::os::unix::fs::FileTypeExt;
            use std::time::Duration;
            let d = Dir::new("fifo");
            let fifo = d.0.join("ff");
            // mkfifo の待ちにも期限を付ける（REPAIR-5）。超えたら kill して回収し、有限時間で失敗にする。
            let mut child = std::process::Command::new("mkfifo")
                .arg(&fifo)
                .spawn()
                .expect("spawn mkfifo");
            let mk_deadline = std::time::Instant::now() + Duration::from_secs(10);
            let st = loop {
                if let Some(st) = child.try_wait().expect("try_wait mkfifo") {
                    break st;
                }
                if std::time::Instant::now() >= mk_deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("mkfifo did not exit within 10s (REPAIR-5)");
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            assert!(st.success(), "mkfifo failed: {st:?}");
            let (tx, rx) = std::sync::mpsc::channel();
            let p = fifo.clone();
            let h = std::thread::spawn(move || {
                let _ =
                    tx.send(open_regular_nofollow(&p).map(|f| f.metadata().map(|m| m.file_type())));
            });
            match rx.recv_timeout(Duration::from_secs(5)) {
                Ok(r) => {
                    h.join().expect("join");
                    let ft = r.expect("open fifo").expect("fstat");
                    assert!(ft.is_fifo());
                }
                Err(_) => {
                    // 救出: O_NONBLOCK の書き手で開いて、ブロック中の読み手の open を戻す（自身はブロックしない）。
                    // 読み手が既に閉じていれば ENXIO で失敗するだけで止まらない。join も期限つきで、超えたらスレッドを放置して失敗にする。
                    use std::os::unix::fs::OpenOptionsExt;
                    let _w = std::fs::OpenOptions::new()
                        .write(true)
                        .custom_flags(super::super::nofollow::O_NONBLOCK)
                        .open(&fifo);
                    let deadline = std::time::Instant::now() + Duration::from_secs(5);
                    while !h.is_finished() && std::time::Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    panic!("open on FIFO blocked >5s; O_NONBLOCK missing?");
                }
            }
        }

        /// 祖先が通常ファイルなら `Ancestor` の ENOTDIR（#3842・SEC-1）。
        #[test]
        fn sec1_3842_regular_file_ancestor_is_rejected() {
            let d = Dir::new("ancfile");
            std::fs::create_dir(d.0.join("real")).expect("mkdir");
            std::fs::write(d.0.join("real/k"), b"abc").expect("write");
            match open_regular_nofollow(&d.0.join("real/k/x")).unwrap_err() {
                NoFollowOpenError::Ancestor(e) => assert_raw(&e, EXP_ENOTDIR, "file ancestor"),
                e => panic!("unexpected {e:?}"),
            }
        }

        /// 相対パス・`/` だけ・`..` を含むパスは `InvalidPath`。
        #[test]
        fn sec1_3748_invalid_paths() {
            for p in ["rel/k", "/", "/a/../b"] {
                let e = open_regular_nofollow(std::path::Path::new(p)).unwrap_err();
                assert!(matches!(e, NoFollowOpenError::InvalidPath), "{p}: {e:?}");
            }
        }
    }
}
