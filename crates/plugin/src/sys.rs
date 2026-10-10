//! syscall・FFI の薄いラッパー（`crates/plugin` の `sys` モジュール。`unsafe` 事前承認の範囲。
//! coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::transport` の UDS listener が、bind 時に自プロセスの実効 uid を取得して配置ディレクトリ
//! 所有者と照合し、accept ごとに接続元の接続時点の実効 uid を取得して照合する（PLUG-12・
//! security.md「別 UID からの接続は peer credential 検証で切断する」）。`libc` / `nix` は依存追加が
//! 禁止（dependency-policy）で `UnixStream::peer_cred` は unstable のため、`crates/io/src/sys.rs` と
//! 同じ流儀で必要最小限の `extern "C"` 宣言を自前で持つ。
//!
//! - Linux（x86_64 / aarch64）: `getsockopt(SOL_SOCKET, SO_PEERCRED)` の `struct ucred`
//! - macOS: `getpeereid(2)`（TASK-124.2・#293。`LOCAL_PEERCRED` の `struct xucred` を自前で写さず libSystem の
//!   安定 ABI に乗り、arch 依存定数を持たないため `target_arch` 分岐は不要。Linux の `SO_PEERCRED` と同じ
//!   「接続時点の実効 uid」を返す共通インターフェース）
//! - macOS: `fstatat(2)`（`AT_SYMLINK_NOFOLLOW`）で、検証済みディレクトリ fd 基準の socket・ロックファイルの識別情報
//!   （dev・ino・uid・種別・mtime）を取得する（パスを再解決しない。#1307・PLUG-12。`lstat_at` の macOS 経路）
//! - Linux・macOS: `fchmodat(2)`（`AT_SYMLINK_NOFOLLOW`。Linux の `fchmodat2` 非対応環境は `O_PATH` fd 経由へ縮退）を
//!   検証済みディレクトリ fd 基準で呼ぶ（パス再解決による TOCTOU を避ける。PLUG-12）。それ以外の unix は
//!   `mode_t` の幅・`AT_SYMLINK_NOFOLLOW` の値を持たないため `fchmodat` を呼ばず `Unsupported`（fail-closed。#1308）
//! - いずれの unix（対応 OS・アーキテクチャ）: `mkdirat(2)` を検証済みディレクトリ fd 基準で呼ぶ（runtime directory の作成。PLUG-12・#1309）
//! - いずれの unix: `unlinkat(2)` を検証済みディレクトリ fd 基準で呼ぶ（OS 依存の型・定数を使わず flags は 0 固定。PLUG-12）
//! - いずれの unix（対応 OS・アーキテクチャ）: `fdopendir(3)`・`readdir(3)`・`closedir(3)` で、検証済みディレクトリ fd 基準
//!   （`openat(dir, ".")`）にカーネルのディレクトリ位置（`lseek(2)`。std の `Seek`）から名前を列挙する
//!   （都度起動の残骸掃除の再開可能な列挙。#1310・PLUG-7・REPAIR-5。[`DirStream`]）
//! - いずれの unix（対応 OS・アーキテクチャ）: `openat(O_NOFOLLOW | O_DIRECTORY)` で配置ディレクトリを
//!   ルートから 1 要素ずつ辿る（祖先要素の symlink を拒否。PLUG-12）
//! - いずれの unix（対応 OS・アーキテクチャ）: `openat(O_CREAT | O_NOFOLLOW)` で bind ロックファイルを開く
//!   （排他ロック自体は std の `File::try_lock`。fork 用のコールバック登録は行わない。PLUG-12・TASK-123.2）
//! - client connect（#249）: `socket(2)` / `connect(2)`（macOS は `fcntl(F_SETFD)` も）で非ブロッキング接続を期限までリトライする（REPAIR-5）。
//!   対応外の OS・アーキテクチャは `Unsupported`
//! - macOS の RSS 取得（TASK-112.1・#265）: `proc_pidinfo(PROC_PIDTASKINFO)`（`resident_size_bytes`。`crate::rss` から呼ばれる）
//! - Linux・macOS: `killpg(2)`（`kill_process_group`。plugin の子のプロセスグループへ `SIGKILL`。#1311。それ以外の unix は `Unsupported`）
//! - Linux（x86_64 / aarch64）: ブロックしないことを保証できる経路（ソケットは `send(MSG_DONTWAIT)`、無名 pipe は
//!   `/proc/self/fd` の `O_NONBLOCK` 開き直し。種別判定は `getsockopt` / `fcntl` / procfs の readlink で `fstat` は
//!   使わず、fd も複製しない）でだけ fd へ書く（`write_nonblocking`。`ChildGuard::drop` の診断出力がブロックしない。
//!   #1605。保証できなければ捨てる）。macOS を含むそれ以外は保証できる経路が無いため常に捨てる（`Unsupported`）
//! - Linux（x86_64 / aarch64）・macOS: `waitid(2)`（`WEXITED | WNOHANG | WNOWAIT`。`probe_child_exit`。自発終了した plugin を回収せずに
//!   観測し、グループへ送ってから回収するため。#1604・PLUG-7・REPAIR-5。それ以外は `Unsupported`）
//! - いずれの unix: `kill(2)` で起動中の plugin へ SIGINT・SIGTERM・SIGHUP を転送する（`send_signal`。
//!   `crate::signal_forward` が CLI バイナリのシグナルハンドラ上から呼ぶため async-signal-safe であること。#1513・PLUG-7）
//! - Linux: `prctl(PR_SET_PDEATHSIG, SIGKILL)` と `getppid(2)` を `pre_exec` で呼び、親の強制終了時に plugin 本体を
//!   止める（#1514・PLUG-7・REPAIR-5・CORE-1。x86_64 / aarch64 のみ。他アーキテクチャは設定しない）
//! - それ以外の OS・アーキテクチャ: peer credential を取得できないため `Unimplemented`（fail-closed）
//!
//! # 限界（残存リスク。対策は未実装。PLUG-12・#1390）
//! - 資格情報の時点: Linux の `SO_PEERCRED` は、接続を受け付ける側（server）が `listen(2)` を呼んだ時点の
//!   プロセスの資格情報を、client 側から見た peer 資格情報として返す（`man 7 unix`）。client が検証する
//!   のは accept 時点のプロセスではなく listen 時点のものである。macOS の `getpeereid(2)` も接続確立時点
//!   の値と想定するが、同じ文言での挙動は未検証。
//! - fd の受け渡し: 接続済み fd を `SCM_RIGHTS`・fork 継承で別プロセスへ渡しても、資格情報は接続確立時点の
//!   まま変わらないため検出できない。
//! - PID 再利用: `peer_pid` の照合は数値比較で、対象プロセス終了後に同じ pid が再利用される窓が残る
//!   （pidfd 等による緩和は将来課題）。
//!
//! # 契約
//! - `unsafe fn` は公開しない。公開するのは安全な [`send_signal`]・[`peer_uid`]・[`effective_uid`]・[`fchmodat_nofollow`]・
//!   [`unlinkat`]・[`mkdirat`]・[`lstat_at`]・[`open_dir_nofollow`]・[`lock_file_at`]・[`names_open_file`]・[`connect_unix`]・[`kill_process_group`]・[`probe_child_exit`]・[`write_nonblocking`]・（Linux のみ）`set_parent_death_sigkill`・[`DirStream`]（`open_at`・`next_entry`・`position`）・（macOS のみ）`resident_size_bytes`（いずれも `pub(crate)`）のみ
//! - fd は `&UnixStream` の借用中のみ渡す（呼び出し中にクローズされない）
//! - SOL_SOCKET / SO_PEERCRED の定数は `cfg(target_arch)` ごとに個別定義し、流用しない
//! - OS ごとに値・幅が異なる定数・型（`ModeT`・`AT_SYMLINK_NOFOLLOW`・`O_*` 等）は対応 OS ごとに個別定義し、
//!   対応外 OS 向けの仮置き（他 OS の値の流用）を置かない。値を持たない OS の経路は `Unsupported` で fail-closed
//!   （誤った flags で symlink を追従する経路を作らない。PLUG-12・#1308）

#![cfg(unix)]

use std::ffi::CStr;
use std::fs::File;
use std::io;
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
use std::os::unix::io::FromRawFd;
use std::os::unix::io::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;

use crate::error::{PluginError, PluginErrorCode};

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `uid_t geteuid(void)` と同じ戻り値の型・幅
    // （`uid_t` は `u32`）。引数を取らず、エラー条件を持たない。
    fn geteuid() -> u32;
}

/// 自プロセスの実効 uid を返す（`geteuid(2)`。エラーを返さない）。
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: 引数を取らず、POSIX の規定上エラー条件を持たない。
    unsafe { geteuid() }
}

/// `SIGKILL` のシグナル番号。Linux（`asm-generic/signal.h`）・macOS（`sys/signal.h`）で 9 で、
/// std の `Child::kill` が unix で送る番号と同じ（`crate::lifecycle` の終了状態分類も参照する）。
pub(crate) const SIGKILL: i32 = 9;

#[cfg(any(target_os = "linux", target_os = "macos"))]
unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `int killpg(int pgrp, int sig)`（Linux: killpg(3)、
    // macOS: killpg(2)）と同じ型・幅。`int` は対応ターゲット（Linux x86_64・aarch64、macOS）で
    // 32 bit 符号付きのため `target_arch` 分岐は不要。ポインタ引数を取らない。
    #[link_name = "killpg"]
    fn c_killpg(pgrp: i32, sig: i32) -> i32;
}

/// プロセスグループ `pgid` の全プロセスへ `SIGKILL` を 1 回送る（`killpg(2)`。PLUG-7・REPAIR-5・#1311）。
///
/// `crate::lifecycle` の `ChildGuard::kill_and_reap` が、`process_group(0)` で起動した plugin の子の
/// pid（= pgid）を渡して孫プロセスごと止めるために呼ぶ。シグナルは `SIGKILL` 固定で、番号を
/// 呼び出し側へ出さない。`pgid` が 2 未満または `i32` に収まらない場合は送信せず `InvalidInput` を返す
/// （`killpg(0, ..)` は呼び出し側自身のグループ宛て、`killpg(1, ..)` は `kill(-1)` 相当の全プロセス宛てになり
/// 得るため fail-closed）。
///
/// 呼び出し側の不変条件: 送信先は自プロセスが spawn し、まだ wait していない子の pgid に限る
/// （wait 済みなら pid が再利用され得るため送らない）。自発終了した子は [`probe_child_exit`] で終了を
/// 観測し（回収はまだ）、未回収のリーダーとして本関数で送ってから回収する（#1604）。グループが空の `ESRCH` もエラーとして返すので、
/// 呼び出し側が無視するか判断する。
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn kill_process_group(pgid: u32) -> io::Result<()> {
    let pgrp = i32::try_from(pgid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if pgrp < 2 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    // SAFETY: 引数はポインタを含まない整数 2 つでメモリ安全性の前提がない。上の 2 以上の検査で、0（呼び出し側
    // 自身のグループ宛て）と 1（glibc 等で `kill(-1)` 相当の権限の及ぶ全プロセス宛て）を排除する。宛先が
    // 呼び出し側自身のグループと一致しないこと・未回収の子のグループに限ることは、ここでは検査できない
    // 呼び出し側の不変条件で、`spawn_registered` の `process_group(0)`（子が自分の pid を pgid にする）と
    // `Child::id()` だけを渡す `ChildGuard`（回収済み・終端後は送らない）が維持する。
    let rc = unsafe { c_killpg(pgrp, SIGKILL) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Linux・macOS 以外の unix 向け。`SIGKILL` の値を持たないため送信せず `Unsupported` を返す（fail-closed）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn kill_process_group(pgid: u32) -> io::Result<()> {
    let _ = pgid;
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `ssize_t send(int socket, const void *buffer, size_t length, int flags)`。
    // `ssize_t` / `size_t` は対応ターゲットでポインタ幅、`int` は 32 bit 符号付き。
    #[link_name = "send"]
    fn c_send(fd: i32, buf: *const u8, len: usize, flags: i32) -> isize;
    // SAFETY（宣言そのものの妥当性）: POSIX の `int getsockopt(int, int, int, void *, socklen_t *)`
    // （`socklen_t` は対応ターゲットで 32 bit 符号なし）。
    #[link_name = "getsockopt"]
    fn c_getsockopt(
        fd: i32,
        level: i32,
        name: i32,
        val: *mut core::ffi::c_void,
        len: *mut u32,
    ) -> i32;
}

/// `SOL_SOCKET` / `SO_TYPE`（Linux の x86_64・aarch64 とも 1 / 3。`asm-generic/socket.h`。値の異なるアーキテクチャ
/// 〔mips 等〕へ流用しない）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const SOL_SOCKET: i32 = 1;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const SO_TYPE: i32 = 3;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: `int fcntl(int fd, int cmd, ...)`。`F_GETPIPE_SZ` は追加引数を取らない。
    #[link_name = "fcntl"]
    fn c_fcntl(fd: i32, cmd: i32, ...) -> i32;
}

/// Linux の `F_GETPIPE_SZ`（`F_LINUX_SPECIFIC_BASE` 1024 + 8。x86_64・aarch64 共通）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const F_GETPIPE_SZ: i32 = 1032;

/// `MSG_DONTWAIT`（呼び出し 1 回限りの非ブロッキング送信。Linux の x86_64・aarch64 とも 0x40）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const MSG_DONTWAIT: i32 = 0x40;

/// `MSG_NOSIGNAL`（相手が閉じた socket への送信で `SIGPIPE` を出さず `EPIPE` だけを返す。呼び出し 1 回限り）。
/// Linux x86_64 は `asm-generic` 由来の 0x4000（`include/linux/socket.h`）。アーキテクチャごとに個別定義する。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const MSG_NOSIGNAL: i32 = 0x4000;
/// Linux aarch64 の `MSG_NOSIGNAL`（x86_64 と同じ 0x4000。値が同じでも流用せず個別に定義する）。
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const MSG_NOSIGNAL: i32 = 0x4000;

/// `O_NONBLOCK | O_NOCTTY`（Linux の x86_64・aarch64 とも `O_NONBLOCK` は 0o4000、`O_NOCTTY` は 0o400）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const O_NONBLOCK_NOCTTY: i32 = 0o4000 | 0o400;

/// fd が socket か（`getsockopt(SO_TYPE)`）。fd 単位のカーネル内判定で、ファイルシステムへ問い合わせない
/// （`fstat` は FUSE / NFS で無期限に止まり得るため使わない。#1605・REPAIR-5）。socket 以外は `ENOTSOCK` で `false`。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn is_socket_fd(fd: i32) -> bool {
    let mut val: i32 = 0;
    let mut len: u32 = 4;
    // SAFETY: `val`・`len` はこの関数のスタック上の有効な書き込み先で、`len` は `val` の大きさ（4）と一致する。
    // fd は呼び出し側の借用（`BorrowedFd`）が呼び出し中開いていることを保証する。fd 単位の問い合わせで副作用は無い。
    let rc = unsafe {
        c_getsockopt(
            fd,
            SOL_SOCKET,
            SO_TYPE,
            (&raw mut val).cast::<core::ffi::c_void>(),
            &raw mut len,
        )
    };
    rc == 0
}

/// fd が pipe / FIFO か（Linux の `fcntl(F_GETPIPE_SZ)`。pipe 以外は `EBADF` / `EINVAL`）。`fstat` を使わない。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn is_pipe_fd(fd: i32) -> bool {
    // SAFETY: 引数は整数のみで、fd 単位のカーネル内問い合わせ（読み取りのみ）。メモリ安全性の前提は無い。
    unsafe { c_fcntl(fd, F_GETPIPE_SZ) >= 0 }
}

/// `/proc/thread-self/fd/<fd>` のリンク先が無名 pipe（pipefs の `pipe:[<ino>]`）か。名前付き FIFO は絶対パスになり
/// `false`（#1605・REPAIR-5）。
///
/// procfs の fd リンクの readlink はメモリ上の dentry から名前を組み立てるだけで（`d_path`）、リンク先の
/// ファイルシステムへ問い合わせない。名前付き FIFO を開き直すと、その FIFO が置かれた NFS / FUSE の
/// 権限確認・属性再検証で止まり得るため、この判定を通った無名 pipe だけを開き直す。
///
/// 残存リスク（未対策・実機未確認）: パス解決ではルート FS 上の `/proc` 要素を辿るため、ルートが FUSE / NFS
/// （chroot・rootless の rootfs 等）だと `proc` の dentry の再検証で問い合わせが起き得る。対策案は起動時に
/// `/proc/thread-self/fd` の dirfd を保持して `openat` 基準で解決すること。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn is_anonymous_pipe_link(proc_fd_path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    std::fs::read_link(proc_fd_path)
        .map(|target| target.as_os_str().as_bytes().starts_with(b"pipe:["))
        .unwrap_or(false)
}

/// ブロックしないことを保証できる経路でだけ `fd` へ `buf` を 1 回書く。保証できなければ書かない（#1605・REPAIR-5・PLUG-7）。
///
/// `crate::lifecycle` の `ChildGuard::drop` が診断 1 行を stderr へ出すために呼ぶ。共有 fd の
/// open file description（親・他プロセスと共有される）の状態は変えない。`poll(POLLOUT)` は空き容量を
/// 予約せず poll と write の間に他者が満たし得るため使わない。種別判定は `fstat` / `metadata()` を使わず
/// fd 単位のカーネル内問い合わせ（`getsockopt` / `fcntl`）と procfs の readlink だけで行い、応答しない
/// FUSE / NFS 上の fd でも判定自体が止まらない。
///
/// `fd` は複製しない。複製を閉じると NFS（未書き出しページの書き戻し）・FUSE（`FUSE_FLUSH`）では close の
/// たびにファイルシステムの flush が走り、捨てる経路でも止まり得るため。閉じるのは無名 pipe を開き直した
/// fd（pipefs。flush を持たない）だけである。
/// - ソケット（journald 等への stderr）: `send(MSG_DONTWAIT)`。この呼び出しだけ非ブロッキング
/// - ソケットへは `MSG_NOSIGNAL` も付け、相手が閉じていても `SIGPIPE` を出さず `EPIPE` を返す
/// - Linux の無名 pipe: `/proc/thread-self/fd/N` を `O_NONBLOCK` で開き直した別 description へ書く
///   （共有側のフラグは変わらない。満杯なら `WouldBlock`、読み手が無ければ open が `ENXIO`）。`/proc/self` は
///   スレッドグループのリーダーの fd 表を指し、`unshare(CLONE_FILES)` したスレッドでは別の fd になるため
///   呼び出しスレッド自身の fd 表を指す `thread-self` を使う。開いた fd が pipe でなければ書かない
/// - 上記以外（通常ファイル・キャラクタデバイス・名前付き FIFO 等）: 通常ファイルは
///   FUSE / NFS・FS freeze で、キャラクタデバイスは CUSE 等の open / write で、名前付き FIFO は置き場所の
///   NFS / FUSE での開き直し時の権限確認で無期限に止まり得て `O_NONBLOCK` でも防げず、保証できないため
///   書かず `Unsupported`（診断は捨てる）
///
/// Linux（x86_64 / aarch64）以外は常に書かず `Unsupported`（下の別定義）。macOS では満杯のブロッキング socket への
/// `send(MSG_DONTWAIT)` が戻らないことを CI で観測した（#1605）ため、socket も含めて保証できる経路が無い。
///
/// 満杯なら `WouldBlock`。部分書き込みも有り得るため書けたバイト数を返す。std の stderr ロックは取らない。
/// 前提:
/// - 呼び出し中に別スレッドが同じ fd 番号を `dup2` 等で差し替えない。崩れた場合、判定と開き直しの間に
///   差し替わった対象を辿り、対象が NFS / FUSE 上なら open で止まり得る（開いた fd が pipe でなければ書かない
///   ため、通常ファイルを上書きすることはない）
/// - pipe 経路は open と write の間に読み手が閉じると `EPIPE` と `SIGPIPE` になり得る。write 1 回だけに効く
///   `MSG_NOSIGNAL` 相当の手段が無いため、ホストが `SIGPIPE` を無視している（Rust の実行時の既定）ことを前提にする
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) fn write_nonblocking(fd: &impl AsFd, buf: &[u8]) -> io::Result<usize> {
    let raw = fd.as_fd().as_raw_fd();
    if is_socket_fd(raw) {
        // SAFETY: `buf` は有効な読み取り専用スライスで、渡す長さは `buf.len()`。fd は呼び出し側の借用が
        // 呼び出し中開いていることを保証する。`MSG_DONTWAIT` で待たず、`MSG_NOSIGNAL` で相手が閉じた socket でも
        // `SIGPIPE` を出さない（library としてホストのシグナル設定に依存しない）。
        let w = unsafe { c_send(raw, buf.as_ptr(), buf.len(), MSG_DONTWAIT | MSG_NOSIGNAL) };
        return usize::try_from(w).map_err(|_| io::Error::last_os_error());
    }
    if is_pipe_fd(raw) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = std::path::PathBuf::from(format!("/proc/thread-self/fd/{raw}"));
        if is_anonymous_pipe_link(&path) {
            let mut private = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(O_NONBLOCK_NOCTTY)
                .open(path)?;
            // 判定と open の間に fd が差し替わった場合に、pipe 以外（通常ファイル等）へ書かない。
            if is_pipe_fd(private.as_raw_fd()) {
                return private.write(buf);
            }
        }
    }
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Linux（x86_64 / aarch64）以外の unix 向け。ブロックしない保証がないため書かず `Unsupported`（fail-closed）。
///
/// macOS は socket の `send(MSG_DONTWAIT)` でも満杯のブロッキング socket で戻らないことを CI で観測した
/// （#1605。xnu の送信経路が `MSG_DONTWAIT` を非ブロッキング指定として扱わないためとみられる）。共有 fd の
/// 状態（`O_NONBLOCK`・`SO_SNDTIMEO`）を変えずに待たない手段が無く、`/proc/self/fd` の開き直しも無いため捨てる。
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub(crate) fn write_nonblocking(fd: &impl AsFd, buf: &[u8]) -> io::Result<usize> {
    let _ = (fd, buf);
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// [`probe_child_exit`] の結果。真偽値にせず、将来の状態（停止・継続等）を足せる形にする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildExitProbe {
    /// まだ終了していない。
    Running,
    /// 終了済みで、親（自プロセス）がまだ回収していない（ゾンビとして残っている）。
    Exited,
}

/// `waitid(2)` の ABI。OS・アーキテクチャごとに個別定義し、他の定義を流用しない（値が同じでも他の
/// OS・アーキテクチャの定義を借りない。REPAIR-2）。値の出典は各定義の注記。
/// 定義を持たない OS・アーキテクチャは [`probe_child_exit`] が `Unsupported` を返す（fail-closed）。
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
))]
mod waitid_abi {
    /// Linux x86_64 の定数と `siginfo_t`。
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod imp {
        /// `idtype_t` の `P_PID`（pid 指定）。`linux/wait.h`・`bits/types/idtype_t.h` の 1。
        pub(in super::super) const P_PID: i32 = 1;
        /// `WNOHANG`（待機せず戻る）。`linux/wait.h`・`bits/waitflags.h` の 1。
        pub(in super::super) const WNOHANG: i32 = 1;
        /// `WEXITED`（終了した子を対象にする）。`linux/wait.h`・`bits/waitflags.h` の 4。
        pub(in super::super) const WEXITED: i32 = 4;
        /// `WNOWAIT`（子を回収せず状態を残す）。`linux/wait.h` の `0x0100_0000`。
        pub(in super::super) const WNOWAIT: i32 = 0x0100_0000;

        /// Linux x86_64 の `siginfo_t`（`bits/types/siginfo_t.h`。`__SI_MAX_SIZE` = 128 バイト）。
        /// 先頭が `si_signo`・`si_errno`・`si_code`、64 bit では union が 8 バイト境界に置かれ、
        /// `_sigchld.si_pid` はオフセット 16。C の `siginfo_t` は union に 8 バイト整列の要素を含むため
        /// `align(8)` を明示する（`waitid` に渡す領域の整列保証）。フィールドは整数のみでパディングを持たない
        /// （4 × 6 + 104 = 128）ため、どのバイト列も有効な値である。
        #[repr(C, align(8))]
        #[allow(dead_code)] // カーネルが書く領域を写すだけで、読むのは `si_pid` のみ
        pub(in super::super) struct SigInfo {
            pub(in super::super) si_signo: i32,
            pub(in super::super) si_errno: i32,
            pub(in super::super) si_code: i32,
            pub(in super::super) pad0: i32,
            pub(in super::super) si_pid: i32,
            pub(in super::super) si_uid: u32,
            pub(in super::super) rest: [u8; 128 - 24],
        }
        const _: () = {
            assert!(size_of::<SigInfo>() == 128);
            assert!(std::mem::offset_of!(SigInfo, si_pid) == 16);
            assert!(align_of::<SigInfo>() == 8);
        };

        impl SigInfo {
            /// 全フィールド 0 の値（`unsafe` なしで組み立てる。`si_pid == 0` を「未終了」と読むための初期値）。
            pub(in super::super) const fn zeroed() -> Self {
                Self {
                    si_signo: 0,
                    si_errno: 0,
                    si_code: 0,
                    pad0: 0,
                    si_pid: 0,
                    si_uid: 0,
                    rest: [0; 128 - 24],
                }
            }
        }
    }

    /// Linux aarch64 の定数と `siginfo_t`（x86_64 と同じ値・asm-generic レイアウトだが個別に定義する）。
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    mod imp {
        /// `idtype_t` の `P_PID`（pid 指定）。`linux/wait.h`・`bits/types/idtype_t.h` の 1。
        pub(in super::super) const P_PID: i32 = 1;
        /// `WNOHANG`（待機せず戻る）。`linux/wait.h`・`bits/waitflags.h` の 1。
        pub(in super::super) const WNOHANG: i32 = 1;
        /// `WEXITED`（終了した子を対象にする）。`linux/wait.h`・`bits/waitflags.h` の 4。
        pub(in super::super) const WEXITED: i32 = 4;
        /// `WNOWAIT`（子を回収せず状態を残す）。`linux/wait.h` の `0x0100_0000`。
        pub(in super::super) const WNOWAIT: i32 = 0x0100_0000;

        /// Linux aarch64 の `siginfo_t`（128 バイト・`si_pid` はオフセット 16・整列 8。整数のみでパディングなし）。
        #[repr(C, align(8))]
        #[allow(dead_code)] // カーネルが書く領域を写すだけで、読むのは `si_pid` のみ
        pub(in super::super) struct SigInfo {
            pub(in super::super) si_signo: i32,
            pub(in super::super) si_errno: i32,
            pub(in super::super) si_code: i32,
            pub(in super::super) pad0: i32,
            pub(in super::super) si_pid: i32,
            pub(in super::super) si_uid: u32,
            pub(in super::super) rest: [u8; 128 - 24],
        }
        const _: () = {
            assert!(size_of::<SigInfo>() == 128);
            assert!(std::mem::offset_of!(SigInfo, si_pid) == 16);
            assert!(align_of::<SigInfo>() == 8);
        };

        impl SigInfo {
            /// 全フィールド 0 の値（`unsafe` なしで組み立てる。`si_pid == 0` を「未終了」と読むための初期値）。
            pub(in super::super) const fn zeroed() -> Self {
                Self {
                    si_signo: 0,
                    si_errno: 0,
                    si_code: 0,
                    pad0: 0,
                    si_pid: 0,
                    si_uid: 0,
                    rest: [0; 128 - 24],
                }
            }
        }
    }

    /// macOS の定数と `siginfo_t`（x86_64・arm64 で同じ ABI のため `target_arch` 分岐は持たない）。
    #[cfg(target_os = "macos")]
    mod imp {
        /// `idtype_t` の `P_PID`（pid 指定）。`sys/wait.h` の 1。
        pub(in super::super) const P_PID: i32 = 1;
        /// `WNOHANG`（待機せず戻る）。`sys/wait.h` の 1。
        pub(in super::super) const WNOHANG: i32 = 1;
        /// `WEXITED`（終了した子を対象にする）。`sys/wait.h` の 4。
        pub(in super::super) const WEXITED: i32 = 4;
        /// `WNOWAIT`（子を回収せず状態を残す）。`sys/wait.h` の `0x20`（Linux と値が異なる）。
        pub(in super::super) const WNOWAIT: i32 = 0x20;

        /// macOS の `siginfo_t`（`sys/signal.h` の `struct __siginfo`。LP64 で 104 バイト）。
        /// `si_signo`・`si_errno`・`si_code`・`si_pid`・`si_uid`・`si_status` の順で、`si_pid` はオフセット 12。
        /// 以降（`si_addr`・`si_value`・`si_band`・`__pad[7]`）は 80 バイトを不透明に写す。整数のみで
        /// パディングを持たない（4 × 6 + 80 = 104。`rest` はオフセット 24 で 8 バイト境界）。
        #[repr(C)]
        #[allow(dead_code)] // カーネルが書く領域を写すだけで、読むのは `si_pid` のみ
        pub(in super::super) struct SigInfo {
            pub(in super::super) si_signo: i32,
            pub(in super::super) si_errno: i32,
            pub(in super::super) si_code: i32,
            pub(in super::super) si_pid: i32,
            pub(in super::super) si_uid: u32,
            pub(in super::super) si_status: i32,
            pub(in super::super) rest: [u64; 10],
        }
        const _: () = {
            assert!(size_of::<SigInfo>() == 104);
            assert!(std::mem::offset_of!(SigInfo, si_pid) == 12);
            assert!(align_of::<SigInfo>() == 8);
        };

        impl SigInfo {
            /// 全フィールド 0 の値（`unsafe` なしで組み立てる。`si_pid == 0` を「未終了」と読むための初期値）。
            pub(in super::super) const fn zeroed() -> Self {
                Self {
                    si_signo: 0,
                    si_errno: 0,
                    si_code: 0,
                    si_pid: 0,
                    si_uid: 0,
                    si_status: 0,
                    rest: [0; 10],
                }
            }
        }
    }

    pub(super) use imp::{P_PID, SigInfo, WEXITED, WNOHANG, WNOWAIT};

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX の `int waitid(idtype_t idtype, id_t id, siginfo_t *infop,
        // int options)`。`idtype_t` は C の列挙型（int 幅）、`id_t` は `u32`、戻り値は `int`（対応ターゲットで
        // 32 bit 符号付き）。`infop` は上の `SigInfo`（`siginfo_t` 全体と同じ大きさ）を指す。
        pub(super) fn waitid(idtype: i32, id: u32, infop: *mut SigInfo, options: i32) -> i32;
    }
}

/// `EINTR` で再試行する上限（無制限に回さない。REPAIR-5）。
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
))]
const PROBE_EINTR_RETRIES: usize = 3;

/// 子 `pid` が終了済みかを、回収せず非ブロックで確かめる（`waitid(P_PID, pid, WEXITED | WNOHANG | WNOWAIT)`。
/// #1604・PLUG-7・REPAIR-5）。
///
/// `crate::lifecycle` の `ChildGuard` が、自発終了した plugin のプロセスグループへ `SIGKILL` を送る前に呼ぶ。
/// `WNOWAIT` のため子はゾンビのまま残り、pid（= pgid）は再利用されない。観測できたら呼び出し側がグループへ
/// 送信してから `waitpid` で回収する。契約外の回収（`ECHILD`）は `Err` で返し、呼び出し側は送らない。
///
/// - `pid` が 1 以下、または `i32` に収まらない場合は `InvalidInput`（`P_PID` で 0 や init を対象にしない）
/// - カーネルが返した `si_pid` が `pid` と食い違う場合は `io::Error::other`（fail-closed）
/// - 対応外の OS・アーキテクチャは `Unsupported`
///
/// 呼び出し側の不変条件: 自プロセスが spawn した子の pid だけを渡す。
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
))]
pub(crate) fn probe_child_exit(pid: u32) -> io::Result<ChildExitProbe> {
    let checked = i32::try_from(pid)
        .ok()
        .filter(|p| *p > 1)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut attempts = 0;
    loop {
        // 待機可能な子がいないときの `infop` の中身は実装依存のため、全フィールド 0 の値から始めて
        // `si_pid == 0` を「未終了」と読む（`MaybeUninit` と `assume_init` を使わない。PLUG-7）。
        let mut info = waitid_abi::SigInfo::zeroed();
        // SAFETY: `&raw mut info` は呼び出し中有効で整列済み（`SigInfo` は `siginfo_t` と同じ整列）の、
        // 初期化済みの `SigInfo` を指す。大きさは `siginfo_t` 全体と同じ（コンパイル時に検査）で、
        // カーネルが書くのは `siginfo_t` の範囲内だけ。`SigInfo` は整数フィールドのみでパディングを持たない
        // ため、カーネルがどのバイトを書いても（書かなくても）有効な値のままで、呼び出し後に safe に読める。
        // `pid` は 1 より大きい値に限定済みで `P_PID` により 1 プロセスだけを対象にする。`WNOWAIT` により
        // 子の状態を消費しないので、std の `Child` が前提にする「未回収の子だけを `waitpid` する」不変条件を
        // 崩さない。呼び出し側が自プロセスの子の pid だけを渡すことが前提。
        let rc = unsafe {
            waitid_abi::waitid(
                waitid_abi::P_PID,
                pid,
                &raw mut info,
                waitid_abi::WEXITED | waitid_abi::WNOHANG | waitid_abi::WNOWAIT,
            )
        };
        if rc != 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted && attempts < PROBE_EINTR_RETRIES {
                attempts += 1;
                continue;
            }
            return Err(e);
        }
        return match info.si_pid {
            0 => Ok(ChildExitProbe::Running),
            p if p == checked => Ok(ChildExitProbe::Exited),
            _ => Err(io::Error::other("waitid reported an unexpected pid")),
        };
    }
}

/// `waitid` の ABI を持たない OS・アーキテクチャ向け。判定せず `Unsupported`（fail-closed。他 OS の値を流用しない）。
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
)))]
pub(crate) fn probe_child_exit(pid: u32) -> io::Result<ChildExitProbe> {
    let _ = pid;
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Linux（x86_64 / aarch64）の親死亡シグナル設定用の定数。アーキテクチャごとに個別定義し流用しない
/// （値が同じでも他アーキテクチャの定義を借りない）。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod pdeathsig_abi {
    // include/uapi/linux/prctl.h の `PR_SET_PDEATHSIG`（1）。
    pub const PR_SET_PDEATHSIG: i32 = 1;
    // include/uapi/asm-generic/signal.h の `SIGKILL`（x86_64 は上書きしない）。
    pub const SIGKILL: u64 = 9;
    // include/uapi/asm-generic/errno-base.h の `ESRCH`（3）。
    pub const ESRCH: i32 = 3;
}
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod pdeathsig_abi {
    // include/uapi/linux/prctl.h の `PR_SET_PDEATHSIG`（1）。
    pub const PR_SET_PDEATHSIG: i32 = 1;
    // include/uapi/asm-generic/signal.h の `SIGKILL`（arm64 は上書きしない）。
    pub const SIGKILL: u64 = 9;
    // include/uapi/asm-generic/errno-base.h の `ESRCH`（3）。
    pub const ESRCH: i32 = 3;
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: `int prctl(int option, ...)`（glibc / musl）。可変長部は
    // `unsigned long` に合わせて `u64` で渡す（`crates/core/src/sys.rs` と同じ流儀）。
    fn prctl(option: i32, ...) -> i32;
    // SAFETY（宣言そのものの妥当性）: POSIX の `pid_t getppid(void)`（`pid_t` は `i32`）。
    // 引数を取らず、エラー条件を持たない。
    fn getppid() -> i32;
}

/// `cmd` で起動する子に「親（fork したスレッド）が終了したら SIGKILL を受ける」設定を足す
/// （`prctl(PR_SET_PDEATHSIG, SIGKILL)`。#1514・#1403 の方式 B・PLUG-7・REPAIR-5・CORE-1）。
///
/// `crate::lifecycle` の都度起動 / 常駐の spawn 直前に、`bind_to_parent_lifetime` 経由で呼ばれる。
/// 親が SIGKILL・abort で落ちるとシグナル転送（方式 A）が動かないため、直接の子である plugin 本体が
/// 孤児として残ることをカーネル側の仕掛けで防ぐ。
///
/// - fork から `prctl` までの間に親が先に終了した競合は、`prctl` の後に `getppid()` が
///   `expected_parent` と一致するか照合し、不一致なら exec せず `ESRCH` で spawn を失敗させる。
/// - 制限（残存リスク）: 発火条件は「子を fork したスレッド」の終了である（プロセス全体ではない）。
///   効くのは直接の子だけで、孫には届かない。setuid・ファイル capability つき実行ファイルの exec で
///   設定は解除され、plugin 自身が `prctl` で解除することもできる。`getppid` の照合で拾えるのは
///   親プロセスの終了だけで、fork したスレッドだけが `prctl` より前に終わった場合は拾えない。
/// - `crates/core` の同種処理は pidfd で親を確かめるが、本 crate の `Command` は PID namespace を
///   変えないため `getppid` で足りる。pidfd の継承や std の fd 管理との干渉を避けて採らない。
/// - `pre_exec` を登録すると std は `posix_spawn` の高速経路から fork + exec の経路へ移る。境界
///   レイテンシ（PLUG-5・CORE-10）への影響があり得る。
///
/// `expected_parent` が `i32` に収まらない場合は `InvalidInput`（spawn 前に親側で返す）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) fn set_parent_death_sigkill(
    cmd: &mut std::process::Command,
    expected_parent: u32,
) -> io::Result<()> {
    use std::os::unix::process::CommandExt;

    let expected =
        i32::try_from(expected_parent).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: クロージャは fork 後・exec 前の子（親のシングルスレッドの複製）で実行される。呼ぶのは
    // async-signal-safe な `prctl(2)` と `getppid(2)` だけで、割り当て・ロック・panic をしない。
    // 失敗は `io::Error`（`Repr::Os`。割り当てなし）で返し、std が errno を親へ渡して exec を行わない。
    // 捕捉するのは `i32` の Copy 値のみで `Send + Sync + 'static` を満たす。
    unsafe {
        cmd.pre_exec(move || {
            // SAFETY: 上記のとおり。引数は定数のみで、ポインタを渡さない。
            if prctl(
                pdeathsig_abi::PR_SET_PDEATHSIG,
                pdeathsig_abi::SIGKILL,
                0u64,
                0u64,
                0u64,
            ) == -1
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: 引数なし・エラーなしの `getppid(2)`。
            if getppid() != expected {
                return Err(io::Error::from_raw_os_error(pdeathsig_abi::ESRCH));
            }
            Ok(())
        });
    }
    Ok(())
}

/// 未対応アーキテクチャ（Linux で x86_64 / aarch64 以外）では親死亡シグナルを設定しない。
///
/// 定数を他アーキテクチャから流用しないための縮退。親死亡シグナルは分離の境界ではなく後始末の補助で、
/// spawn を失敗させると plugin が使えなくなるため、設定の省略を選ぶ（#1514）。
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub(crate) fn set_parent_death_sigkill(
    _cmd: &mut std::process::Command,
    _expected_parent: u32,
) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
type ModeT = u32;
#[cfg(target_os = "macos")]
type ModeT = u16;
// 対応外 OS（Linux・macOS 以外）向けの定義は置かない。値・幅が OS ごとに違い、流用すると
// symlink 追従の flags になり得るため、その経路は `fchmodat_nofollow` が `Unsupported` を返す（PLUG-12・#1308）。

#[cfg(target_os = "linux")]
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
#[cfg(target_os = "macos")]
const AT_SYMLINK_NOFOLLOW: i32 = 0x20;

#[cfg(any(target_os = "linux", target_os = "macos"))]
unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `int fchmodat(int, const char *, mode_t, int)` と
    // 同じ型・幅（`mode_t` は Linux で `u32`、macOS で `u16`。上の `ModeT`）。
    #[link_name = "fchmodat"]
    fn c_fchmodat(dirfd: i32, path: *const core::ffi::c_char, mode: ModeT, flags: i32) -> i32;
}

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `int unlinkat(int, const char *, int)` と同じ型・幅。
    #[link_name = "unlinkat"]
    fn c_unlinkat(dirfd: i32, path: *const core::ffi::c_char, flags: i32) -> i32;
}

/// `dir`（開いたディレクトリ fd）基準で `name` の mode を設定する。最終要素が symlink なら
/// 辿らない（PLUG-12）。
///
/// まず `fchmodat(AT_SYMLINK_NOFOLLOW)` を試す。この flags は Linux 6.6 の `fchmodat2` に依存し、
/// 古いカーネル・libc（musl 等）では `ENOSYS` / `EOPNOTSUPP` / `EINVAL` で失敗するため、Linux では
/// その場合に限り [`fchmodat_via_opath`] へ縮退する（symlink 防御は保ったまま古い環境でも bind 可能にする）。
/// 縮退できない環境はそのままエラー（fail-closed）。Linux・macOS 以外の unix は `mode_t` の幅・
/// `AT_SYMLINK_NOFOLLOW` の値を持たないため `fchmodat` を呼ばず `Unsupported` を返す（fail-closed。#1308）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn fchmodat_nofollow(dir: &File, name: &CStr, mode: u32) -> io::Result<()> {
    let mode = ModeT::try_from(mode).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: fd は `&File` の借用中のため有効。`name` は NUL 終端の有効な C 文字列。
    let rc = unsafe { c_fchmodat(dir.as_raw_fd(), name.as_ptr(), mode, AT_SYMLINK_NOFOLLOW) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        // ENOSYS=38・EINVAL=22・EOPNOTSUPP=95（Linux の errno は x86_64 / aarch64 で共通）。
        if matches!(err.raw_os_error(), Some(38 | 22 | 95)) {
            return fchmodat_via_opath(dir, name, mode);
        }
    }
    Err(err)
}

/// Linux・macOS 以外の unix 向け。`fchmodat` を呼ばず `Unsupported` を返す（fail-closed。#1308）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn fchmodat_nofollow(dir: &File, name: &CStr, mode: u32) -> io::Result<()> {
    let _ = (dir, name, mode);
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// `fchmodat2` 非対応環境向けの縮退実装（Linux のみ）。`name` を `O_PATH | O_NOFOLLOW` で開き、
/// fd 自体が socket であること（symlink・通常ファイルでない）を `statx(AT_EMPTY_PATH)` で確認してから、
/// `/proc/self/fd/<fd>` 経由で chmod する（fd が指す inode に対して作用し、パスは再解決しない）。
/// `/proc` が使えない場合は失敗する（fail-closed）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn fchmodat_via_opath(dir: &File, name: &CStr, mode: ModeT) -> io::Result<()> {
    // O_PATH は x86_64 / aarch64 とも 0o10000000。
    const O_PATH: i32 = 0o10000000;
    // SAFETY: `name` は NUL 終端の有効な C 文字列。`dir` は `&File` の借用中のため有効。
    let fd = unsafe {
        c_openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            O_PATH | O_NOFOLLOW | O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` は直前の openat が返した、他に所有者のいない有効な fd（非負を確認済み）。
    let opened = unsafe { File::from_raw_fd(fd) };
    let ident = statx_ident(opened.as_raw_fd(), c"", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)?;
    if !ident.is_socket {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let proc_path = std::ffi::CString::new(format!("/proc/self/fd/{}", opened.as_raw_fd()))
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `proc_path` は NUL 終端の有効な C 文字列。AT_FDCWD + 絶対パスで、flags=0 は
    // /proc の magic link を辿って検証済み socket inode に作用する（`opened` が生存中は有効）。
    let rc = unsafe { c_fchmodat(AT_FDCWD, proc_path.as_ptr(), mode, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `lstat` 相当の識別情報（同一性照合・所有者・種別の確認用。PLUG-12）。
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct FileIdent {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub is_socket: bool,
    /// symlink 本体か（`lstat` 相当で取得するため、リンク先ではなくリンク自体の種別。PLUG-12）。
    pub is_symlink: bool,
    /// 最終更新時刻（秒・ナノ秒）。socket では作成（bind）時に決まり、chmod・rename・hard link では
    /// 変わらない。inode 番号が再利用された別の socket を dev / ino の一致だけで同一と見なさないための
    /// 同一性の一部（PLUG-12・TASK-123.2）。
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
}

#[cfg(target_os = "linux")]
mod statx_abi {
    /// `struct statx` と同じレイアウト（アーキテクチャ非依存の安定 ABI。256 バイト）。
    #[repr(C)]
    pub(super) struct Statx {
        pub mask: u32,
        pub blksize: u32,
        pub attributes: u64,
        pub nlink: u32,
        pub uid: u32,
        pub gid: u32,
        pub mode: u16,
        pub pad0: u16,
        pub ino: u64,
        pub size: u64,
        pub blocks: u64,
        pub attributes_mask: u64,
        /// `stx_atime`・`stx_btime`・`stx_ctime`・`stx_mtime` の順（各 16 バイト）。
        pub timestamps: [StatxTimestamp; 4],
        pub rdev_major: u32,
        pub rdev_minor: u32,
        pub dev_major: u32,
        pub dev_minor: u32,
        pub tail: [u64; 14],
    }
    const _: () = assert!(core::mem::size_of::<Statx>() == 256);

    /// `struct statx_timestamp` と同じレイアウト（16 バイト）。
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct StatxTimestamp {
        pub sec: i64,
        pub nsec: u32,
        pub reserved: i32,
    }
    const _: () = assert!(core::mem::size_of::<StatxTimestamp>() == 16);
    const _: () = assert!(core::mem::offset_of!(Statx, timestamps) == 64);

    /// `timestamps` 内の `stx_mtime` の位置。
    pub(super) const MTIME_INDEX: usize = 3;

    /// `STATX_TYPE | STATX_MODE | STATX_UID | STATX_MTIME | STATX_INO`。
    pub(super) const REQUIRED_MASK: u32 = 0x1 | 0x2 | 0x8 | 0x40 | 0x100;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: glibc（2.28 以降）/ musl の
        // `int statx(int, const char *, int, unsigned int, struct statx *)` と同じ型・幅。
        pub(super) fn statx(
            dirfd: i32,
            path: *const core::ffi::c_char,
            flags: i32,
            mask: u32,
            buf: *mut Statx,
        ) -> i32;
    }
}

/// `statx(dirfd, name, flags)` を呼び、識別情報へ変換する（Linux のみ。symlink を辿るか否かは
/// `flags` で決まる）。`lstat_at` と、O_PATH fd の同一性確認（`AT_EMPTY_PATH`）から使う。
#[cfg(target_os = "linux")]
fn statx_ident(dirfd: i32, name: &CStr, flags: i32) -> io::Result<FileIdent> {
    let mut st = statx_abi::Statx {
        mask: 0,
        blksize: 0,
        attributes: 0,
        nlink: 0,
        uid: 0,
        gid: 0,
        mode: 0,
        pad0: 0,
        ino: 0,
        size: 0,
        blocks: 0,
        attributes_mask: 0,
        timestamps: [statx_abi::StatxTimestamp {
            sec: 0,
            nsec: 0,
            reserved: 0,
        }; 4],
        rdev_major: 0,
        rdev_minor: 0,
        dev_major: 0,
        dev_minor: 0,
        tail: [0; 14],
    };
    // SAFETY: `dirfd` は呼び出し側が保持する開いた fd。`name` は NUL 終端の有効な C 文字列。
    // `st` はスタック上の 256 バイトの `#[repr(C)]` 領域で、カーネルが書き込む最大サイズと一致。
    let rc = unsafe {
        statx_abi::statx(
            dirfd,
            name.as_ptr(),
            flags,
            statx_abi::REQUIRED_MASK,
            &raw mut st,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if st.mask & statx_abi::REQUIRED_MASK != statx_abi::REQUIRED_MASK {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    let mtime = st
        .timestamps
        .get(statx_abi::MTIME_INDEX)
        .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
    Ok(FileIdent {
        dev: (u64::from(st.dev_major) << 32) | u64::from(st.dev_minor),
        ino: st.ino,
        uid: st.uid,
        is_socket: u32::from(st.mode) & 0o170000 == 0o140000,
        is_symlink: u32::from(st.mode) & 0o170000 == 0o120000,
        mtime_sec: mtime.sec,
        mtime_nsec: mtime.nsec,
    })
}

/// macOS の `struct stat`（64 bit inode 版。`<sys/stat.h>` の `__DARWIN_STRUCT_STAT64`）と `fstatat(2)` の宣言。
///
/// レイアウトは x86_64・aarch64 とも LP64 で同一。差はシンボル名のみで、x86_64 は 32 bit inode 版との
/// 互換のため `fstatat$INODE64`、aarch64 は `fstatat`（`crates/platform-macos/src/sys/mount.rs` の
/// `statfs` と同じ流儀）。参照元: apple-oss-distributions/xnu `bsd/sys/stat.h`。
#[cfg(target_os = "macos")]
mod stat_abi {
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("macOS の struct stat レイアウトは x86_64 / aarch64 のみ確認済み（#1307）");

    /// `struct timespec`（`time_t` = `long` と `long`。16 バイト）。
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct Timespec {
        pub tv_sec: i64,
        pub tv_nsec: i64,
    }

    // 未参照のフィールドは、カーネルが書き込む `struct stat` の配置（サイズ・offset）を写すために残す。
    #[repr(C)]
    #[allow(dead_code)]
    pub(super) struct Stat {
        pub st_dev: i32,
        pub st_mode: u16,
        pub st_nlink: u16,
        pub st_ino: u64,
        pub st_uid: u32,
        pub st_gid: u32,
        pub st_rdev: i32,
        pub st_atimespec: Timespec,
        pub st_mtimespec: Timespec,
        pub st_ctimespec: Timespec,
        pub st_birthtimespec: Timespec,
        pub st_size: i64,
        pub st_blocks: i64,
        pub st_blksize: i32,
        pub st_flags: u32,
        pub st_gen: u32,
        pub st_lspare: i32,
        pub st_qspare: [i64; 2],
    }
    const _: () = assert!(core::mem::size_of::<Stat>() == 144);
    const _: () = assert!(core::mem::align_of::<Stat>() == 8);
    const _: () = assert!(core::mem::offset_of!(Stat, st_ino) == 8);
    const _: () = assert!(core::mem::offset_of!(Stat, st_atimespec) == 32);
    const _: () = assert!(core::mem::offset_of!(Stat, st_mtimespec) == 48);

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: `int fstatat(int, const char *, struct stat *, int)` と同じ
        // 型・幅。`Stat` は 64 bit inode 版の `struct stat`（上の assert でサイズを固定）で、x86_64 は
        // `$INODE64` 版のシンボルを選ぶ（32 bit inode 版を呼ぶとレイアウトが食い違うため必須）。
        #[cfg_attr(target_arch = "x86_64", link_name = "fstatat$INODE64")]
        pub(super) fn fstatat(
            dirfd: i32,
            path: *const core::ffi::c_char,
            buf: *mut Stat,
            flags: i32,
        ) -> i32;
    }
}

/// `fstatat(dirfd, name, flags)` を呼び、識別情報へ変換する（macOS のみ。`lstat_at` から呼ばれる）。
///
/// `flags` に `AT_SYMLINK_NOFOLLOW` を渡すと symlink 自体の情報を返す。
#[cfg(target_os = "macos")]
fn fstatat_ident(dirfd: i32, name: &CStr, flags: i32) -> io::Result<FileIdent> {
    let zero = stat_abi::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut st = stat_abi::Stat {
        st_dev: 0,
        st_mode: 0,
        st_nlink: 0,
        st_ino: 0,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        st_atimespec: zero,
        st_mtimespec: zero,
        st_ctimespec: zero,
        st_birthtimespec: zero,
        st_size: 0,
        st_blocks: 0,
        st_blksize: 0,
        st_flags: 0,
        st_gen: 0,
        st_lspare: 0,
        st_qspare: [0; 2],
    };
    // SAFETY: `dirfd` は呼び出し側が借用中の開いた fd。`name` は NUL 終端の有効な C 文字列。
    // `st` はスタック上の 144 バイトの `#[repr(C)]` 領域で、カーネルが書き込むサイズと一致（assert で固定）。
    // ポインタは呼び出しの間だけ有効で、保持しない。
    let rc = unsafe { stat_abi::fstatat(dirfd, name.as_ptr(), &raw mut st, flags) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdent {
        // std の `MetadataExt::dev()`（`st_dev as u64`＝`i32` からの符号拡張）と同じ変換。
        // `names_open_file` が fd 側の `file.metadata().dev()` と比較するため、ゼロ拡張だと
        // 高位ビットが立つ `dev_t` で常に不一致になる。
        dev: i64::from(st.st_dev) as u64,
        ino: st.st_ino,
        uid: st.st_uid,
        is_socket: u32::from(st.st_mode) & 0o170000 == 0o140000,
        is_symlink: u32::from(st.st_mode) & 0o170000 == 0o120000,
        mtime_sec: st.st_mtimespec.tv_sec,
        mtime_nsec: u32::try_from(st.st_mtimespec.tv_nsec)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
    })
}

/// `statx` の `AT_EMPTY_PATH`（fd 自体を対象にする。Linux の全アーキテクチャで共通値）。
#[cfg(target_os = "linux")]
const AT_EMPTY_PATH: i32 = 0x1000;

/// `dir` 基準の `name`（symlink を辿らない）が、開いている `file` と同じ inode（dev / ino）を指すか。
/// `name` が存在しなければ `false`。
///
/// bind ロックの取得後・解放時に、ロックファイル名が「いま flock を持っている inode」をまだ指して
/// いるかを確かめるために使う（保持者が解放時に unlink した古い inode を掴んだ取得者を弾く。
/// PLUG-12・TASK-123.2）。名前側は [`lstat_at`]（Linux は `statx`・macOS は `fstatat`）、fd 側は
/// `statx(AT_EMPTY_PATH)` / `fstat` で取得し、どちらもパスを再解決しない（#1307）。
/// Linux・macOS 以外の unix は [`lstat_at`] が `Unsupported` を返すため `Err`（fail-closed）。
pub(crate) fn names_open_file(dir: &File, name: &CStr, file: &File) -> io::Result<bool> {
    let named = match lstat_at(dir, name) {
        Ok(i) => i,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    #[cfg(target_os = "linux")]
    let (dev, ino) = {
        let i = statx_ident(file.as_raw_fd(), c"", AT_EMPTY_PATH)?;
        (i.dev, i.ino)
    };
    #[cfg(not(target_os = "linux"))]
    let (dev, ino) = {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata()?;
        (m.dev(), m.ino())
    };
    Ok(!named.is_symlink && named.dev == dev && named.ino == ino)
}

/// `dir` 基準で `name`（symlink を辿らない）の識別情報を返す。
///
/// 検証済みディレクトリ fd を基準にし、パスを再解決しない（PLUG-12・#1307）。`crate::uds_security`
/// （既存エントリの検査・bind ロック）と `crate::transport`（bind 後の同一性確認・Drop の後始末）から呼ばれる。
/// - Linux: `statx(dirfd, name, AT_SYMLINK_NOFOLLOW)`
/// - macOS: `fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)`（[`fstatat_ident`]）
/// - それ以外の unix: `Unsupported`（fail-closed。パス指定の `lstat` へ縮退しない。
///   `open_dir_nofollow` も `Unsupported` を返すため、実運用ではここへ到達しない）
pub(crate) fn lstat_at(dir: &File, name: &CStr) -> io::Result<FileIdent> {
    #[cfg(target_os = "linux")]
    {
        statx_ident(dir.as_raw_fd(), name, AT_SYMLINK_NOFOLLOW)
    }
    #[cfg(target_os = "macos")]
    {
        fstatat_ident(dir.as_raw_fd(), name, AT_SYMLINK_NOFOLLOW)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (dir, name);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

// openat 用の open(2) フラグ・AT_FDCWD。値は OS・アーキテクチャごとに異なるため個別定義し流用しない。
//
// Linux の `O_DIRECTORY` / `O_NOFOLLOW` は x86_64 が asm-generic の既定値（0o200000 / 0o400000）、
// aarch64 は `arch/arm64/include/uapi/asm/fcntl.h` が既定値を上書きした 0o40000 / 0o100000 を使う
// （aarch64 では 0o200000 は `O_DIRECT`、0o400000 は `O_LARGEFILE`。x86_64 の値を aarch64 へ
// 流用すると symlink を辿るうえに `O_DIRECT` 付きで開いてしまうため、揃えてはならない）。
// `O_CLOEXEC`・`O_PATH`・`AT_FDCWD` は両アーキテクチャで共通。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_DIRECTORY: i32 = 0o200000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_DIRECTORY: i32 = 0o40000;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_NOFOLLOW: i32 = 0o100000;
// 対応アーキテクチャ（x86_64 / aarch64）以外の Linux では、使う側が fail-closed のため定義しない（#1538）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const O_CLOEXEC: i32 = 0o2000000;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const AT_FDCWD: i32 = -100;
#[cfg(target_os = "macos")]
const O_DIRECTORY: i32 = 0x0010_0000;
#[cfg(target_os = "macos")]
const O_NOFOLLOW: i32 = 0x0100;
#[cfg(target_os = "macos")]
const O_CLOEXEC: i32 = 0x0100_0000;
#[cfg(target_os = "macos")]
const AT_FDCWD: i32 = -2;

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `int openat(int, const char *, int, ...)` と同じ型・幅。
    // 可変長引数（mode）は O_CREAT を使う `lock_file_at` だけが渡す（他は渡さない）。
    #[link_name = "openat"]
    fn c_openat(dirfd: i32, path: *const core::ffi::c_char, flags: i32, ...) -> i32;
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `int mkdirat(int, const char *, mode_t)` と同じ型・幅
    // （`mode_t` は Linux で `u32`、macOS で `u16`。上の `ModeT`。確認元: Linux の `man 2 mkdirat`・
    // macOS SDK の `sys/stat.h`）。可変長引数・flags 引数は無い。
    #[link_name = "mkdirat"]
    fn c_mkdirat(dirfd: i32, path: *const core::ffi::c_char, mode: ModeT) -> i32;
}

/// `dirfd` 基準で `name` を `O_DIRECTORY | O_NOFOLLOW` で開く（1 要素）。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn openat_dir_nofollow(dirfd: i32, name: &CStr) -> io::Result<File> {
    // SAFETY: `name` は NUL 終端の有効な C 文字列。`dirfd` は呼び出し側が保持する開いた fd
    // （または AT_FDCWD + 絶対パス）。
    let fd = unsafe { c_openat(dirfd, name.as_ptr(), O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` は直前の openat が返した、他に所有者のいない有効な fd（非負を確認済み）。
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// 絶対パス `abs`（`canonicalize` 済み）をルートから 1 要素ずつ `openat(O_NOFOLLOW | O_DIRECTORY)`
/// で辿り、ディレクトリ fd を返す（PLUG-12）。いずれかの要素が symlink（検証後の差し替えを含む）なら
/// `ELOOP` 等で失敗する（fail-closed）。以降はこの fd を基準に bind・chmod・unlink を行い、
/// パスを再解決しない。未対応の OS・アーキテクチャは `Unsupported`（fail-closed）。
pub(crate) fn open_dir_nofollow(abs: &std::path::Path) -> io::Result<File> {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::path::Component;
        let invalid = || io::Error::from(io::ErrorKind::InvalidInput);
        let mut comps = abs.components();
        if comps.next() != Some(Component::RootDir) {
            return Err(invalid());
        }
        let mut cur = openat_dir_nofollow(AT_FDCWD, c"/")?;
        for c in comps {
            let Component::Normal(n) = c else {
                return Err(invalid());
            };
            let name = CString::new(n.as_bytes()).map_err(|_| invalid())?;
            cur = openat_dir_nofollow(cur.as_raw_fd(), &name)?;
        }
        Ok(cur)
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
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

// ロックファイル作成用の open(2) フラグ。値は OS ごとに異なる。Linux の 4 値は asm-generic の既定値で、
// x86_64・aarch64 とも上書きしないため同値だが、流用せず対応アーキテクチャごとに定義する。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_RDWR: i32 = 0o2;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_CREAT: i32 = 0o100;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_EXCL: i32 = 0o200;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_RDWR: i32 = 0o2;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_CREAT: i32 = 0o100;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_EXCL: i32 = 0o200;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(target_os = "macos")]
const O_RDWR: i32 = 0x2;
#[cfg(target_os = "macos")]
const O_CREAT: i32 = 0x200;
#[cfg(target_os = "macos")]
const O_EXCL: i32 = 0x800;
#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x4;

/// ロックファイルの取得結果（PLUG-12・TASK-123.2）。
#[derive(Debug)]
pub(crate) struct LockHandle {
    /// 排他ロック（`flock`）を保持する fd。close（プロセス終了・クラッシュ含む）で kernel が解放する。
    pub file: File,
    /// 今回の呼び出しで新規作成したか（false なら以前の保持者が作ったロックファイルが残っていた）。
    pub created: bool,
}

/// ロックファイルの開き方（PLUG-12・#1310）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockOpen {
    /// bind 用。無ければ作成する。自分が作成した直後に他者が先にロックを取っていた場合は、期限つきで
    /// 解放を待つ（[`lock_file_at`] の「作成直後の競合」参照）。
    Bind,
    /// 無ければ作成する。他者が保持中なら待たずに `WouldBlock`（掃除の走査位置ヒント用）。
    Create,
    /// 既存のファイルだけを開く（作成しない）。無ければ `NotFound`（掃除用。掃除が、消えた残骸の
    /// 名前でロックファイルを作り直して bind と競合しないようにする）。
    Existing,
}

/// [`lock_file_at`] の失敗（PLUG-12・#1310）。「`flock` を試みて他者が保持中だった」と「`flock` を
/// 試みる前に open の競合が続いた」を型で区別する。前者だけが「この配置先で `flock` の衝突を検出
/// できた」証拠になる（`uds_security` の排他の確認が使う）。bind にとってはどちらも「使用中」。
#[derive(Debug)]
pub(crate) enum LockError {
    /// `flock` を試み、他者が保持中だった（`try_lock` が `WouldBlock`）。
    Held,
    /// 作成（`O_EXCL`）が `EEXIST`、既存を開くと `ENOENT` という競合が上限まで続いた。`flock` は
    /// 一度も試していない。待ち続けないための打ち切りで、使用中として扱う（REPAIR-5）。
    OpenContended,
    /// それ以外の失敗（開けない・通常ファイルでない・ロック非対応・未対応 OS 等）。
    Io(io::Error),
}

impl From<io::Error> for LockError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// 自分が作成した直後のロックファイルを他者が先にロックしていた場合に、解放を待つ回数と間隔
/// （[`lock_file_at`] の呼び出し 1 回につき合計 100 ms。REPAIR-5 の有限な待ち）。相手になるのは作成と
/// `flock` の間に割り込んだ掃除で、保持は 1 候補の判定の間だけなので通常は 1 回目の待ちで解放される。
/// 呼び出し側（`uds_security::acquire_bind_lock`）は、名前から外れた inode を掴むたびに作り直して
/// 本関数を呼び直す（上限 8 回）ため、bind 1 回の待ちは最悪で 8 回 × 100 ms（約 0.8 秒）になる。
/// 呼び出し側の期限（`call_once` の合計期限等）とは連動しない。
const CREATED_LOCK_WAIT_ATTEMPTS: u32 = 100;
const CREATED_LOCK_WAIT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(1);

/// テスト専用。[`lock_file_at`] が新規作成（`O_EXCL`）してから `flock` を取るまでの間に処理を差し込み、
/// 別プロセスの割り込み（掃除が先にロックを取る）を決定的に再現する（PLUG-12・#1310）。
#[cfg(test)]
pub(crate) mod lock_test_hook {
    use std::cell::RefCell;
    use std::ffi::CStr;
    use std::fs::File;

    type Hook = Box<dyn FnOnce(&File, &CStr)>;

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
        static CONTENDED_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// 呼び出しスレッドの以降 `n` 回の「作成 → 既存を開く」の試行を、競合（作成は `EEXIST`、既存を
    /// 開くと `ENOENT`）で失敗したものとして扱わせる（実際には開かない）。
    pub(crate) fn contend_opens(n: usize) {
        CONTENDED_OPENS.with(|c| c.set(n));
    }

    pub(super) fn take_contended_open() -> bool {
        CONTENDED_OPENS.with(|c| {
            let left = c.get();
            c.set(left.saturating_sub(1));
            left > 0
        })
    }

    /// 呼び出しスレッドの次の新規作成 1 回だけに `hook` を差し込む。
    pub(crate) fn set(hook: impl FnOnce(&File, &CStr) + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn run(dir: &File, name: &CStr) {
        let hook = HOOK.with(|h| h.borrow_mut().take());
        if let Some(hook) = hook {
            hook(dir, name);
        }
    }
}

/// [`open_lock_file`] の開き方（bool ではなく型で区別する）。
#[derive(Clone, Copy)]
enum LockFileOpen {
    /// `O_CREAT | O_EXCL` で新規作成する。既にあれば `AlreadyExists`。
    CreateNew,
    /// `O_CREAT` なしで既存だけを開く。無ければ `NotFound`。
    Existing,
}

/// [`lock_file_at`] の open(2) 呼び出し 1 回分。ロックファイルを開く FFI（`openat`）への依存を
/// ここ 1 か所に閉じ込め、対応アーキテクチャ以外では呼び出し側の分岐を cfg で分けずに済ませる
/// （未使用宣言の clippy 失敗を避ける。#1538）。`O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`・0600 で開く。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn open_lock_file(dir: &File, name: &CStr, how: LockFileOpen) -> io::Result<File> {
    let flags = match how {
        LockFileOpen::CreateNew => O_RDWR | O_CREAT | O_EXCL,
        LockFileOpen::Existing => O_RDWR,
    };
    // SAFETY: `dir` は `&File` の借用中のため fd は有効。`name` は NUL 終端の有効な C 文字列。
    // O_CREAT を含むため、可変長引数として mode（C の既定引数昇格後の `unsigned int` 幅）を
    // 1 つ渡す。openat は渡したポインタを呼び出し中しか参照しない。
    let fd = unsafe {
        c_openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
            0o600u32,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` は直前の openat が返した、他に所有者のいない有効な fd（非負を確認済み）。
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// 対応アーキテクチャ以外では開けない（`Unsupported`。fail-closed）。
#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
fn open_lock_file(dir: &File, name: &CStr, how: LockFileOpen) -> io::Result<File> {
    let _ = (dir, name, how);
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// `dir` 基準で `name` のロックファイルを `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`・0600 で開き
/// （`mode` に応じて無ければ作成）、非ブロッキングで排他ロックを取る。`O_NONBLOCK` は、既存の名前が FIFO・デバイス
/// 等だった場合に open が相手を待って止まらないようにするため（通常ファイルの読み書きには影響しない。
/// REPAIR-5）。開いた fd が通常ファイルでなければロックせず `PermissionDenied`。他者が保持中なら
/// [`LockError::Held`]、ロックを試みる前の open の競合が続いた場合は [`LockError::OpenContended`]。listener の生存判定に接続 probe を
/// 使わず、「ロックを取れる＝以前の保持者は消えた」で stale を判定するための基盤（既存 listener の
/// accept queue に副作用を与えない。PLUG-12）。未対応の OS・アーキテクチャは `Unsupported`。
///
/// ロックは std の [`File::try_lock`]（Linux・macOS は `flock(2)`）で取り、FFI は `openat` だけに
/// 留める。`flock` は open file description に紐付くため、fork した子は listener の socket fd と
/// 同じくロック fd も継承する（どちらも `O_CLOEXEC` で exec 時に閉じる）。子が両方を持ち続ける間は
/// socket も実際に接続可能なので、ロック保持＝listener 生存という対応は fork をまたいでも崩れない。
/// そのため fork 時に子側のロックだけを外す仕組み（`pthread_atfork` 等）は持たない。
///
/// # 作成直後の競合（#1310）
/// 作成（`O_EXCL`）と `flock` は別の操作で、その間に別プロセスの掃除（`uds_security` の都度起動の残骸
/// 掃除）が同じ名前を開いて先にロックを取りうる。[`LockOpen::Bind`] では、自分が作成したファイルで
/// `WouldBlock` になった場合に限り、[`CREATED_LOCK_WAIT_ATTEMPTS`] 回まで待って取り直す。待たないと、
/// 正当な bind が掃除との競合だけで「使用中」として失敗する。掃除は判定後に空のロックファイルを
/// unlink するので、待って取れたロックは名前から外れた inode のものでありうる。その確認と作り直しは
/// 呼び出し側（`acquire_bind_lock` の `names_open_file`）が行う。既存ファイルを開いた場合は待たない
/// （保持者は生存中の listener でありうる）。
pub(crate) fn lock_file_at(
    dir: &File,
    name: &CStr,
    mode: LockOpen,
) -> Result<LockHandle, LockError> {
    // 新規作成（O_EXCL）を試し、既にあれば O_CREAT なしで既存を開く。その間に保持者が解放時の
    // unlink をした場合は ENOENT になるため、上限つきで最初からやり直す（`created` を正確に保つ。
    // 上限まで競合し続けた場合は `OpenContended` を返し、待ち続けない。REPAIR-5）。
    const OPEN_ATTEMPTS: usize = 8;
    let mut opened = None;
    if mode == LockOpen::Existing {
        opened = Some((open_lock_file(dir, name, LockFileOpen::Existing)?, false));
    }
    for _ in 0..OPEN_ATTEMPTS {
        if opened.is_some() {
            break;
        }
        #[cfg(test)]
        if lock_test_hook::take_contended_open() {
            continue;
        }
        match open_lock_file(dir, name, LockFileOpen::CreateNew) {
            Ok(f) => {
                opened = Some((f, true));
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                match open_lock_file(dir, name, LockFileOpen::Existing) {
                    Ok(f) => {
                        opened = Some((f, false));
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    let Some((file, created)) = opened else {
        return Err(LockError::OpenContended);
    };
    // 通常ファイル以外（FIFO・デバイス等）はロックを試みる前に拒否する（flock 自体が失敗して
    // 理由が分からなくなる OS があるため。内容にも触れない）。
    if !file.metadata()?.is_file() {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
    }
    #[cfg(test)]
    if created {
        lock_test_hook::run(dir, name);
    }
    // 自分が作成した直後に他者（掃除）が先にロックを取っていた場合だけ、期限つきで待つ。
    let mut waits_left = if created && mode == LockOpen::Bind {
        CREATED_LOCK_WAIT_ATTEMPTS
    } else {
        0
    };
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(LockHandle { file, created }),
            Err(std::fs::TryLockError::WouldBlock) if waits_left > 0 => {
                waits_left -= 1;
                std::thread::sleep(CREATED_LOCK_WAIT_INTERVAL);
            }
            Err(std::fs::TryLockError::WouldBlock) => return Err(LockError::Held),
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
    }
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
/// `dir`（検証済みの開いたディレクトリ fd）基準で、単一要素 `name` のディレクトリを作成する
/// （`mkdirat(2)`。PLUG-12・#1309）。`crate::uds_security` の runtime directory 作成が呼び、
/// パスを再解決しないため、検証後に祖先を差し替えられても検証済みの `dir` の外には作られない。
///
/// 呼び出し元は `name` を `/` を含まない単一要素にする。`mode` は umask 適用前の値。最終要素が
/// symlink でも辿らず `EEXIST`（`ErrorKind::AlreadyExists`）になる。Linux・macOS の対応アーキテクチャ以外は
/// `Unsupported`（fail-closed）。
pub(crate) fn mkdirat(dir: &File, name: &CStr, mode: u32) -> io::Result<()> {
    let mode = ModeT::try_from(mode).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: fd は `&File` の借用中のため有効。`name` は NUL 終端の C 文字列で呼び出しの間生きている。
    // `mkdirat` は fd を返さず、最終要素の symlink は辿らない（存在すれば `EEXIST`）。
    let rc = unsafe { c_mkdirat(dir.as_raw_fd(), name.as_ptr(), mode) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
pub(crate) fn mkdirat(dir: &File, name: &CStr, mode: u32) -> io::Result<()> {
    let _ = (dir, name, mode);
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// `dir`（開いたディレクトリ fd）基準で `name` を unlink する（ディレクトリは対象外: flags=0）。
pub(crate) fn unlinkat(dir: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: fd は `&File` の借用中のため有効。`name` は NUL 終端の有効な C 文字列。
    let rc = unsafe { c_unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `fdopendir(3)`・`readdir(3)`・`closedir(3)` と errno 取得の宣言、`struct dirent` の `d_name` の位置
/// （#1310。`crates/io/src/sys.rs` の `for_each_dir_entry` と同じ流儀。本 crate は io crate に依存しない
/// ため宣言を個別に持つ）。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod dir_abi {
    use core::ffi::c_void;

    /// Linux（LP64。glibc・musl）の `struct dirent`: `d_ino`(8)・`d_off`(8)・`d_reclen`(2)・`d_type`(1) の
    /// 直後が `d_name`。x86_64・aarch64 で同一（`man 3 readdir`）。
    #[cfg(target_os = "linux")]
    pub(super) const DIRENT_NAME_OFFSET: usize = 19;
    /// macOS（64 bit inode 版）の `struct dirent`: `d_ino`(8)・`d_seekoff`(8)・`d_reclen`(2)・
    /// `d_namlen`(2)・`d_type`(1) の直後が `d_name`（macOS SDK の `sys/dirent.h`）。
    #[cfg(target_os = "macos")]
    pub(super) const DIRENT_NAME_OFFSET: usize = 21;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX の `DIR *fdopendir(int fd)`・
        // `struct dirent *readdir(DIR *)`・`int closedir(DIR *)`。DIR は不透明ポインタ（`*mut c_void`）、
        // dirent は先頭バイトへのポインタとして扱い、`d_name` だけを固定オフセットで読む。macOS の
        // x86_64 は 64 bit inode 版の DIR / dirent を扱うシンボル（`$INODE64`）を fdopendir・readdir で
        // 揃える（混在させると DIR のレイアウトが食い違う。closedir は版を持たない）。arm64 の macOS は
        // 64 bit inode 版のみのため接尾辞を付けない。
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
        pub(super) fn closedir(dir: *mut c_void) -> i32;
        // SAFETY（宣言そのものの妥当性）: スレッドローカルな errno へのポインタを返す
        // （glibc・musl は `__errno_location`、macOS は `__error`。引数なし）。
        #[cfg(target_os = "linux")]
        pub(super) fn __errno_location() -> *mut i32;
        #[cfg(target_os = "macos")]
        pub(super) fn __error() -> *mut i32;
    }
}

/// 検証済みディレクトリ fd 基準で、指定したカーネルのディレクトリ位置から名前を順に読むストリーム
/// （#1310・PLUG-7・PLUG-12・REPAIR-5）。
///
/// `uds_security` の都度起動の残骸掃除が、1 回の読み取り数を上限内に保ったまま前回の続きから列挙する
/// ために使う。パスを再解決せず `openat(dir, ".")` で開き直すため、列挙対象は検証済みディレクトリそのもの
/// である（`dir` の fd とは別の open file description なので、`dir` の読み取り位置は変えない）。
///
/// 位置は `lseek(2)` で設定・取得するカーネルのディレクトリ offset（不透明な値）で、件数ではない。
/// POSIX は `fdopendir` が「呼び出し時点の fd の file offset から」エントリを返すと定める。`telldir(3)` の
/// 値は使わない（macOS では `DIR` ごとの表の添字で、プロセスをまたいで使えない）。libc は複数エントリを
/// まとめて読むため、[`DirStream::position`] が返すのは「libc が最後にまとめ読みした直後」の位置である
/// （消費済みエントリの直後とは限らない）。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
pub(crate) struct DirStream {
    /// `fdopendir` が返した `DIR *`（drop の `closedir` まで有効。読み取り用 fd の所有権を持つ）。
    handle: *mut core::ffi::c_void,
    /// `handle` の fd を dup したもの（同じ open file description。位置の取得だけに使う）。
    position: File,
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
impl DirStream {
    /// `dir` を開き直し、カーネルのディレクトリ位置 `offset`（0 は先頭）から読むストリームを返す。
    /// `offset` が不正で `lseek` が失敗した場合は `Err`（呼び出し側が先頭からやり直す）。
    pub(crate) fn open_at(dir: &File, offset: u64) -> io::Result<Self> {
        use std::io::{Seek, SeekFrom};
        use std::os::unix::io::IntoRawFd;
        let file = openat_dir_nofollow(dir.as_raw_fd(), c".")?;
        (&file).seek(SeekFrom::Start(offset))?;
        let position = file.try_clone()?;
        let fd = file.into_raw_fd();
        // SAFETY: `fd` は直前に `into_raw_fd` で取り出した有効なディレクトリ fd で、他に所有者がいない。
        // 成功すれば所有権は DIR へ移り、drop の closedir で閉じられる。
        let handle = unsafe { dir_abi::fdopendir(fd) };
        if handle.is_null() {
            let err = io::Error::last_os_error();
            // SAFETY: fdopendir が失敗したとき fd の所有権は移らないため、唯一の所有者である
            // 本関数がここで閉じる（`fd` は上で取り出した有効な fd）。
            drop(unsafe { File::from_raw_fd(fd) });
            return Err(err);
        }
        Ok(Self { handle, position })
    }

    /// 次のエントリ（`.`・`..` を除く）の名前を `visit` へ渡し、その戻り値を返す。末尾なら `Ok(None)`。
    /// 名前は次の読み取りまでしか有効でない借用のため、`visit` の外へ持ち出すなら複製する。
    pub(crate) fn next_entry<R>(
        &mut self,
        visit: impl FnOnce(&[u8]) -> R,
    ) -> io::Result<Option<R>> {
        loop {
            // 末尾（NULL・errno 変化なし）とエラー（NULL・errno 設定）を区別するため errno を 0 にする。
            // SAFETY: errno へのポインタは呼び出しスレッドのスレッドローカル領域を指し、常に有効。
            #[cfg(target_os = "linux")]
            unsafe {
                *dir_abi::__errno_location() = 0;
            }
            // SAFETY: 同上（macOS の errno アクセサ）。
            #[cfg(target_os = "macos")]
            unsafe {
                *dir_abi::__error() = 0;
            }
            // SAFETY: `self.handle` は `open_at` で得た closedir 前の有効な DIR*。`&mut self` により
            // 同じ DIR* への並行した readdir は起きない。
            let entry = unsafe { dir_abi::readdir(self.handle) };
            if entry.is_null() {
                let err = io::Error::last_os_error();
                return match err.raw_os_error() {
                    Some(0) | None => Ok(None),
                    Some(_) => Err(err),
                };
            }
            // SAFETY: 返った dirent は次の readdir / closedir まで有効。`d_name` は
            // `DIRENT_NAME_OFFSET` から始まり、libc が構造体の範囲内での NUL 終端を保証する。
            // 得た借用は本ループ内（次の readdir より前）でしか使わない。
            let name =
                unsafe { CStr::from_ptr(entry.add(dir_abi::DIRENT_NAME_OFFSET).cast()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            return Ok(Some(visit(name)));
        }
    }

    /// カーネルのディレクトリ位置（libc が最後にまとめ読みした直後の位置）を返す。この値を
    /// [`DirStream::open_at`] へ渡すと、まだ libc が読んでいない続きから読める。
    /// libc はまとめ読みを先に済ませることがあるため（macOS の `fdopendir` は開いた時点で最初の分を読む）、
    /// 開いた直後の値が `open_at` に渡した位置と同じとは限らない。まとめ読みの大きさも一定ではない
    /// （macOS は開いた直後の 1 回が小さい）。
    pub(crate) fn position(&self) -> io::Result<u64> {
        use std::io::Seek;
        let mut file = &self.position;
        file.stream_position()
    }
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: `self.handle` は `open_at` で得た有効な DIR* で、drop 以降は使わない。DIR が所有する
        // fd もここで閉じられる（`position` は別の fd で、フィールドの drop が閉じる）。
        unsafe { dir_abi::closedir(self.handle) };
    }
}

/// 対応外の OS・アーキテクチャ向け（fail-closed）。dirent の配置を持たないため列挙せず、
/// 常に `Unsupported` を返す。
#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
pub(crate) struct DirStream(());

#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
impl DirStream {
    pub(crate) fn open_at(dir: &File, offset: u64) -> io::Result<Self> {
        let _ = (dir, offset);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub(crate) fn next_entry<R>(
        &mut self,
        visit: impl FnOnce(&[u8]) -> R,
    ) -> io::Result<Option<R>> {
        let _ = visit;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub(crate) fn position(&self) -> io::Result<u64> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

// 使うのは `peer_ucred`（対応アーキテクチャのみ実装）だけのため、同じ cfg に揃える（#1538）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    /// `struct ucred` と同じレイアウト。
    #[repr(C)]
    pub(super) struct Ucred {
        pub pid: i32,
        pub uid: u32,
        pub gid: u32,
    }

    pub(super) const UCRED_SIZE: usize = core::mem::size_of::<Ucred>();
    const _: () = assert!(UCRED_SIZE <= u32::MAX as usize);
    // ABI 固定: `struct ucred` は pid_t・uid_t・gid_t の 4 バイト 3 つ（x86_64 / aarch64 共通で 12 バイト）。
    const _: () = assert!(UCRED_SIZE == 12);
    pub(super) const UCRED_LEN: u32 = UCRED_SIZE as u32;

    #[cfg(target_arch = "x86_64")]
    pub(super) const SOL_SOCKET: i32 = 1;
    #[cfg(target_arch = "x86_64")]
    pub(super) const SO_PEERCRED: i32 = 17;

    #[cfg(target_arch = "aarch64")]
    pub(super) const SOL_SOCKET: i32 = 1;
    #[cfg(target_arch = "aarch64")]
    pub(super) const SO_PEERCRED: i32 = 17;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: glibc / musl の
        // `int getsockopt(int, int, int, void *, socklen_t *)` と同じ型・幅（`socklen_t` は `u32`）。
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
    // SAFETY（宣言そのものの妥当性）: libSystem の `int getpeereid(int, uid_t *, gid_t *)` と同じ型・幅。
    fn getpeereid(socket: i32, euid: *mut u32, egid: *mut u32) -> i32;
}

/// 取得バッファの初期値に使う番兵値（`(uid_t)-1`）。有効な uid として割り当てられない値で、syscall が
/// 成功を返しつつ書き込まなかった場合に、core が root（uid 0）でも peer と一致させないために使う（PLUG-12・#1390）。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
const PEER_ID_SENTINEL: u32 = u32::MAX;

/// 取得した peer uid が番兵値のままなら（＝書き込まれていない）エラー、そうでなければ値を返す（fail-closed）。
/// `peer_uid`（Linux・macOS）から呼ばれる、unsafe を含まないテスト可能な継ぎ目。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn peer_uid_from_raw(raw: u32) -> Result<u32, PluginError> {
    if raw == PEER_ID_SENTINEL {
        return Err(PluginError::new(
            PluginErrorCode::Internal,
            "failed to obtain peer credential",
        ));
    }
    Ok(raw)
}

/// 接続元の接続時点の資格情報（SO_PEERCRED）を取得する（Linux）。取得できなければ fail-closed でエラー。
/// バッファは番兵値（pid は -1、uid・gid は `u32::MAX`）で初期化する。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn peer_ucred(stream: &UnixStream) -> Result<linux::Ucred, PluginError> {
    use std::os::unix::io::AsRawFd;
    let mut ucred = linux::Ucred {
        pid: -1,
        uid: PEER_ID_SENTINEL,
        gid: PEER_ID_SENTINEL,
    };
    let mut len = linux::UCRED_LEN;
    // SAFETY: fd は `&UnixStream` の借用中のため有効。`optval` はスタック上の `#[repr(C)]` な
    // `ucred` を指し、`optlen` はそのサイズを指す有効なポインタ。バッファは番兵値で初期化済みで、
    // 書き込まれたとは仮定せず、成功は戻り値・`len`・呼び出し側の番兵検査で確認する。
    let rc = unsafe {
        linux::getsockopt(
            stream.as_raw_fd(),
            linux::SOL_SOCKET,
            linux::SO_PEERCRED,
            (&raw mut ucred).cast(),
            &raw mut len,
        )
    };
    if rc != 0 || len as usize != linux::UCRED_SIZE {
        return Err(PluginError::new(
            PluginErrorCode::Internal,
            "failed to obtain peer credential",
        ));
    }
    Ok(ucred)
}

/// 接続元の接続時点の実効 uid を返す（Linux。SO_PEERCRED。TASK-124.1・#292）。取得できなければ fail-closed でエラー。
/// 接続元が別の user namespace にあり uid がマッピングされていない場合、overflowuid（Linux 既定 65534）として
/// 観測される。照合側で拒否されるのは core 自身の euid が overflowuid として観測されない場合に限り、core の
/// euid 自体が 65534 として観測される構成（未マッピングの user namespace 内・nobody 実行等）では数値が
/// 一致して受理される（overflowuid を特別扱いしない。現状挙動）。取得値が番兵値のままなら `Internal`。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32, PluginError> {
    peer_uid_from_raw(peer_ucred(stream)?.uid)
}

/// 接続元の pid を返す（Linux。都度起動モードで応答者を spawn した子に限定するため。PLUG-7・PLUG-12）。
/// 呼び出し側の pid 照合は数値比較で、対象終了後の PID 再利用の窓が残る（モジュール doc「限界」）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) fn peer_pid(stream: &UnixStream) -> Result<u32, PluginError> {
    u32::try_from(peer_ucred(stream)?.pid).map_err(|_| {
        PluginError::new(
            PluginErrorCode::Internal,
            "failed to obtain peer credential",
        )
    })
}

/// 接続元の接続時点の実効 uid を返す（macOS。PLUG-12・TASK-124.2）。
///
/// Linux 版と同シグネチャ・同じ意味の値を返す。取得失敗は `Internal` で、呼び出し側（`transport` の
/// accept / connect）は `?` で返して stream を drop し、フレームを読まずに切断する（fail-closed）。
#[cfg(target_os = "macos")]
pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32, PluginError> {
    use std::os::unix::io::AsRawFd;
    let mut euid: u32 = PEER_ID_SENTINEL;
    let mut egid: u32 = PEER_ID_SENTINEL;
    // SAFETY: fd は `&UnixStream` の借用中のため有効。2 つのポインタはスタック上の有効な変数を指す。
    // 変数は番兵値で初期化済みで、書き込まれたとは仮定せず戻り値と番兵検査で確認する（`getpeereid` は
    // 成功時に必ず書くため防御的措置）。
    let rc = unsafe { getpeereid(stream.as_raw_fd(), &raw mut euid, &raw mut egid) };
    if rc != 0 {
        return Err(PluginError::new(
            PluginErrorCode::Internal,
            "failed to obtain peer credential",
        ));
    }
    peer_uid_from_raw(euid)
}

/// 接続元の pid を返す（macOS。`LOCAL_PEERPID`）。初期値は -1 で、書き込まれなければ `try_from` で失敗する。
/// 呼び出し側の pid 照合は数値比較で、PID 再利用の窓が残る（モジュール doc「限界」）。
#[cfg(target_os = "macos")]
pub(crate) fn peer_pid(stream: &UnixStream) -> Result<u32, PluginError> {
    use std::os::unix::io::AsRawFd;
    /// `<sys/un.h>` の `SOL_LOCAL`。
    const SOL_LOCAL: i32 = 0;
    /// `<sys/un.h>` の `LOCAL_PEERPID`。
    const LOCAL_PEERPID: i32 = 0x002;
    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: libSystem の
        // `int getsockopt(int, int, int, void *, socklen_t *)` と同じ型・幅（`socklen_t` は `u32`）。
        fn getsockopt(
            sockfd: i32,
            level: i32,
            optname: i32,
            optval: *mut core::ffi::c_void,
            optlen: *mut u32,
        ) -> i32;
    }
    let mut pid: i32 = -1;
    let mut len: u32 = core::mem::size_of::<i32>() as u32;
    // SAFETY: fd は `&UnixStream` の借用中のため有効。`optval` はスタック上の `pid_t`（i32）を指し、
    // `optlen` はそのサイズを指す有効なポインタ。
    let rc = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &raw mut len,
        )
    };
    if rc != 0 || len as usize != core::mem::size_of::<i32>() {
        return Err(PluginError::new(
            PluginErrorCode::Internal,
            "failed to obtain peer credential",
        ));
    }
    u32::try_from(pid).map_err(|_| {
        PluginError::new(
            PluginErrorCode::Internal,
            "failed to obtain peer credential",
        )
    })
}

// ---- 期限付き client connect（PLUG-2・REPAIR-5。TASK-107.5・#249） ----
//
// `UnixStream::connect` は期限を指定できず、Linux では backlog が埋まった listener への blocking
// connect が無期限に待つ。そのため socket を自前で作り、非ブロッキング connect を期限までリトライする。
// 定数・構造体レイアウトは OS ごとに個別定義し流用しない（Linux x86_64 / aarch64 は共通値。
// 対応外の unix は `Unsupported`）。

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod connect_abi {
    pub(super) const AF_UNIX: i32 = 1;

    #[cfg(target_os = "linux")]
    pub(super) const SOCK_STREAM: i32 = 1;
    #[cfg(target_os = "linux")]
    pub(super) const SOCK_CLOEXEC: i32 = 0o2000000;
    #[cfg(target_os = "linux")]
    pub(super) const EISCONN: i32 = 106;
    #[cfg(target_os = "linux")]
    pub(super) const EINPROGRESS: i32 = 115;
    #[cfg(target_os = "linux")]
    pub(super) const EALREADY: i32 = 114;
    #[cfg(target_os = "linux")]
    pub(super) const EAGAIN: i32 = 11;

    #[cfg(target_os = "macos")]
    pub(super) const SOCK_STREAM: i32 = 1;
    #[cfg(target_os = "macos")]
    pub(super) const F_SETFD: i32 = 2;
    #[cfg(target_os = "macos")]
    pub(super) const FD_CLOEXEC: i32 = 1;
    #[cfg(target_os = "macos")]
    pub(super) const EISCONN: i32 = 56;
    #[cfg(target_os = "macos")]
    pub(super) const EINPROGRESS: i32 = 36;
    #[cfg(target_os = "macos")]
    pub(super) const EALREADY: i32 = 37;
    #[cfg(target_os = "macos")]
    pub(super) const EAGAIN: i32 = 35;

    pub(super) const EINTR: i32 = 4;

    #[cfg(target_os = "linux")]
    pub(super) const SUN_PATH_LEN: usize = 108;
    #[cfg(target_os = "macos")]
    pub(super) const SUN_PATH_LEN: usize = 104;

    /// Linux の `struct sockaddr_un`（110 バイト）。
    #[cfg(target_os = "linux")]
    #[repr(C)]
    pub(super) struct SockaddrUn {
        pub sun_family: u16,
        pub sun_path: [u8; SUN_PATH_LEN],
    }
    #[cfg(target_os = "linux")]
    const _: () = assert!(core::mem::size_of::<SockaddrUn>() == 110);

    /// macOS の `struct sockaddr_un`（106 バイト）。
    #[cfg(target_os = "macos")]
    #[repr(C)]
    pub(super) struct SockaddrUn {
        pub sun_len: u8,
        pub sun_family: u8,
        pub sun_path: [u8; SUN_PATH_LEN],
    }
    #[cfg(target_os = "macos")]
    const _: () = assert!(core::mem::size_of::<SockaddrUn>() == 106);

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX の `int socket(int, int, int)` と同じ型・幅。
        pub(super) fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
        // SAFETY（宣言そのものの妥当性）: POSIX の `int connect(int, const struct sockaddr *, socklen_t)`
        // と同じ型・幅（`socklen_t` は `u32`）。
        pub(super) fn connect(sockfd: i32, addr: *const SockaddrUn, addrlen: u32) -> i32;
        // SAFETY（宣言そのものの妥当性）: POSIX の `int fcntl(int, int, ...)` と同じ型・幅。
        #[cfg(target_os = "macos")]
        pub(super) fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }
}

/// `sockaddr_un` の `sun_path` 先頭オフセット（Linux: 2、macOS: 2）。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
const SUN_PATH_OFFSET: usize = 2;

/// connect 成功時にも期限を確認する（REPAIR-5）。期限超過なら成功扱いにせず `TimedOut` を返し、
/// `stream` は Drop で close される。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn connected_within_deadline(
    stream: UnixStream,
    deadline: std::time::Instant,
) -> io::Result<UnixStream> {
    if std::time::Instant::now() > deadline {
        return Err(io::Error::from(io::ErrorKind::TimedOut));
    }
    Ok(stream)
}

/// `path` の UDS へ `deadline` までに非ブロッキング connect し、接続済みの `UnixStream` を返す
/// （非ブロッキングのまま。呼び出し側が blocking へ戻す）。
///
/// `transport` の client 接続（`UdsStream::connect`）から呼ばれる。空・内部 NUL・`sun_path` 超過は
/// `InvalidInput`、期限超過は `TimedOut`、listener の backlog 満杯（Linux の `EAGAIN`）・`EINTR`・
/// `EINPROGRESS` は期限までリトライする。connect 成功時も期限超過なら `TimedOut`。未対応の OS・アーキテクチャは `Unsupported`（fail-closed）。
/// fd は socket 作成直後に `UnixStream` へ所有させ、どの失敗経路でも close される。
pub(crate) fn connect_unix(
    path: &std::path::Path,
    deadline: std::time::Instant,
) -> io::Result<UnixStream> {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        use connect_abi as abi;
        use std::os::unix::ffi::OsStrExt;
        use std::time::{Duration, Instant};

        let bytes = path.as_os_str().as_bytes();
        let invalid = || io::Error::from(io::ErrorKind::InvalidInput);
        // sun_path は終端 NUL を 1 バイト残す（`addr` はゼロ初期化済み）。
        let mut addr: abi::SockaddrUn = abi::SockaddrUn {
            #[cfg(target_os = "macos")]
            sun_len: 0,
            #[cfg(target_os = "macos")]
            sun_family: abi::AF_UNIX as u8,
            #[cfg(target_os = "linux")]
            sun_family: abi::AF_UNIX as u16,
            sun_path: [0; abi::SUN_PATH_LEN],
        };
        if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= addr.sun_path.len() {
            return Err(invalid());
        }
        addr.sun_path
            .get_mut(..bytes.len())
            .ok_or_else(invalid)?
            .copy_from_slice(bytes);
        let addr_len = u32::try_from(SUN_PATH_OFFSET + bytes.len() + 1).map_err(|_| invalid())?;
        #[cfg(target_os = "macos")]
        {
            addr.sun_len = u8::try_from(addr_len).map_err(|_| invalid())?;
        }

        #[cfg(target_os = "linux")]
        let ty = abi::SOCK_STREAM | abi::SOCK_CLOEXEC;
        #[cfg(target_os = "macos")]
        let ty = abi::SOCK_STREAM;
        // SAFETY: 引数は整数のみ。成否は戻り値で確認する。
        let fd = unsafe { abi::socket(abi::AF_UNIX, ty, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` は直前の socket が返した、他に所有者のいない有効な fd（非負を確認済み）。
        // 以降の失敗経路でも `UnixStream` の Drop で close される。
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        #[cfg(target_os = "macos")]
        {
            // SAFETY: `fd` は `stream` が所有する有効な fd。F_SETFD は int 引数 1 つを取る。
            let rc = unsafe { abi::fcntl(fd, abi::F_SETFD, abi::FD_CLOEXEC) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        stream.set_nonblocking(true)?;

        const RETRY_INTERVAL: Duration = Duration::from_millis(5);
        loop {
            // SAFETY: `fd` は `stream` が所有し生存中。`addr` はスタック上の `#[repr(C)]` な
            // `sockaddr_un` で、`addr_len` はその先頭から有効な（NUL 終端込みの）バイト数
            // （構造体サイズ以下であることは上の長さ検査で保証）。
            let rc = unsafe { abi::connect(fd, &raw const addr, addr_len) };
            if rc == 0 {
                return connected_within_deadline(stream, deadline);
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(abi::EISCONN) => return connected_within_deadline(stream, deadline),
                Some(abi::EAGAIN | abi::EINTR | abi::EINPROGRESS | abi::EALREADY) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(io::Error::from(io::ErrorKind::TimedOut));
                    }
                    std::thread::sleep((deadline - now).min(RETRY_INTERVAL));
                }
                _ => return Err(err),
            }
        }
    }
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = (path, deadline);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// 未対応の OS・アーキテクチャでは peer を検証できないため常に拒否する（fail-closed）。
#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
pub(crate) fn peer_uid(_stream: &UnixStream) -> Result<u32, PluginError> {
    Err(PluginError::new(
        PluginErrorCode::Unimplemented,
        "peer credential verification is not implemented for this platform",
    ))
}

/// 未対応の OS・アーキテクチャでは peer pid を検証できないため常に拒否する（fail-closed）。
#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
pub(crate) fn peer_pid(_stream: &UnixStream) -> Result<u32, PluginError> {
    Err(PluginError::new(
        PluginErrorCode::Unimplemented,
        "peer credential verification is not implemented for this platform",
    ))
}
#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::os::unix::net::UnixListener;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("fc-sys-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// PLUG-12: `fchmodat2` 非対応環境向けの縮退経路が socket の mode を設定できる。
    #[test]
    fn opath_fallback_sets_socket_mode_0600() {
        let d = tmpdir("sock");
        let _l = UnixListener::bind(d.join("s.sock")).unwrap();
        let dir = File::open(&d).unwrap();
        fchmodat_via_opath(&dir, c"s.sock", 0o600).unwrap();
        let mode = std::fs::symlink_metadata(d.join("s.sock")).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PLUG-12: 縮退経路でも最終要素が symlink なら辿らず拒否し、リンク先の mode は変えない。
    #[test]
    fn opath_fallback_rejects_symlink_and_leaves_target() {
        let d = tmpdir("link");
        std::fs::write(d.join("target"), b"x").unwrap();
        std::fs::set_permissions(
            d.join("target"),
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .unwrap();
        symlink(d.join("target"), d.join("lnk")).unwrap();
        let dir = File::open(&d).unwrap();
        assert!(fchmodat_via_opath(&dir, c"lnk", 0o600).is_err());
        let mode = std::fs::metadata(d.join("target")).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o644);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// REPAIR-5: 接続自体は成功する状況でも、期限が過ぎていれば成功扱いにせず `TimedOut` を返す。
    #[test]
    fn repair5_connect_unix_expired_deadline_times_out_even_if_connectable() {
        let d = tmpdir("expired");
        let sock = d.join("s.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let past = std::time::Instant::now() - std::time::Duration::from_millis(1);
        let e = connect_unix(&sock, past).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PLUG-2: 期限付き connect の入力検証と未存在パス（OS 依存の errno は NotFound）。
    #[test]
    fn plug2_connect_unix_rejects_bad_paths_and_missing_socket() {
        use std::time::{Duration, Instant};
        let dl = Instant::now() + Duration::from_secs(5);
        let long = std::path::PathBuf::from(format!("/{}", "a".repeat(200)));
        let e = connect_unix(&long, dl).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let e = connect_unix(std::path::Path::new(""), dl).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let e = connect_unix(std::path::Path::new("/tmp/a\0b"), dl).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let d = tmpdir("conn");
        let e = connect_unix(&d.join("none.sock"), dl).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(target_os = "linux")]
    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX の `int listen(int, int)` と同じ型・幅。
        fn listen(sockfd: i32, backlog: i32) -> i32;
    }

    /// REPAIR-5: accept しない listener の backlog が埋まると blocking connect は無期限に待つが、
    /// 期限付き connect は `TimedOut` で戻る（Linux の満杯時 `EAGAIN` 経路。macOS は即
    /// `ECONNREFUSED` のため対象外）。backlog は std の既定が大きく埋めにくいため、テスト内で
    /// `listen(fd, 0)` を再発行して縮める。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_connect_unix_times_out_when_backlog_is_full() {
        use std::time::{Duration, Instant};
        let d = tmpdir("backlog");
        let l = UnixListener::bind(d.join("s.sock")).unwrap();
        // SAFETY: fd は `l` の借用中は有効な listening socket。再 listen は backlog を更新するだけ。
        assert_eq!(unsafe { listen(l.as_raw_fd(), 0) }, 0);
        let mut held = Vec::new();
        let mut timed_out = None;
        for _ in 0..64 {
            let t = Instant::now();
            let dl = t + Duration::from_millis(200);
            match connect_unix(&d.join("s.sock"), dl) {
                Ok(s) => held.push(s),
                Err(e) => {
                    timed_out = Some((e.kind(), t.elapsed()));
                    break;
                }
            }
        }
        let (kind, el) = timed_out.expect("backlog did not fill");
        assert_eq!(kind, io::ErrorKind::TimedOut);
        assert!(el >= Duration::from_millis(200), "{el:?}");
        assert!(el < Duration::from_secs(5), "{el:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PLUG-12・TASK-124.1: 自己接続の peer uid / pid は自プロセスの値と一致する。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn plug12_linux_peer_uid_of_socketpair_equals_effective_uid() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), effective_uid());
        assert_eq!(peer_pid(&a).unwrap(), std::process::id());
    }
}

/// 番兵値検査の検証（PLUG-12・#1390）。Linux・macOS 共通のヘルパを照合する。
#[cfg(all(
    test,
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
mod peer_sentinel_tests {
    use super::*;

    /// PLUG-12: 番兵値のままの uid は `Internal`・固定メッセージで拒否される（fail-closed）。
    #[test]
    fn plug12_peer_uid_from_raw_rejects_sentinel() {
        let err = peer_uid_from_raw(u32::MAX).unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::Internal);
        assert!(err.to_string().contains("failed to obtain peer credential"));
    }

    /// PLUG-12: root（0）・overflowuid（65534）・通常 uid は誤って拒否しない。
    #[test]
    fn plug12_peer_uid_from_raw_passes_valid_uids() {
        for uid in [0u32, 1000, 65534] {
            assert_eq!(peer_uid_from_raw(uid).unwrap(), uid);
        }
    }
}

/// macOS の peer 認証ラッパーの検証（PLUG-12・TASK-124.2・#293）。実 UDS 接続で行う。
#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::net::UnixListener;

    /// 一時ディレクトリ（0700）に listener を bind し、実接続した (client, server) を返す。
    fn connected_pair(tag: &str) -> (UnixStream, UnixStream) {
        let dir = std::env::temp_dir().join(format!("fc-peer-{}-{tag}", std::process::id()));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .expect("create tmp dir");
        let path = dir.join("s");
        let listener = UnixListener::bind(&path).expect("bind");
        let client = UnixStream::connect(&path).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        let _ = std::fs::remove_dir_all(&dir);
        (client, server)
    }

    /// PLUG-12: 両端とも自プロセスの実効 uid を返す。
    #[test]
    fn plug12_macos_peer_uid_matches_effective_uid() {
        let (client, server) = connected_pair("uid");
        let euid = effective_uid();
        assert_eq!(peer_uid(&server).expect("server side"), euid);
        assert_eq!(peer_uid(&client).expect("client side"), euid);
    }

    /// PLUG-12: `LOCAL_PEERPID` は同一プロセス内の接続では自 pid を返す。
    #[test]
    fn plug12_macos_peer_pid_matches_own_pid() {
        let (client, server) = connected_pair("pid");
        assert_eq!(peer_pid(&server).expect("server side"), std::process::id());
        assert_eq!(peer_pid(&client).expect("client side"), std::process::id());
    }
}
/// macOS の `lstat_at` / `names_open_file`（`fstatat` 経路）の検証（PLUG-12・#1307）。
#[cfg(all(test, target_os = "macos"))]
mod macos_stat_tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, symlink};
    use std::os::unix::net::UnixListener;

    /// 0700 の一時ディレクトリ（終了時に削除）。
    struct Tmp(std::path::PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("fc-fstatat-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// PLUG-12: socket の dev・ino・uid・種別・mtime を、dir fd 基準で `symlink_metadata` と同じ値で返す。
    #[test]
    fn plug12_macos_lstat_at_returns_socket_identity_from_dir_fd() {
        let t = Tmp::new("ident");
        let _l = UnixListener::bind(t.0.join("s")).unwrap();
        let dir = File::open(&t.0).unwrap();
        let ident = lstat_at(&dir, c"s").unwrap();
        let m = std::fs::symlink_metadata(t.0.join("s")).unwrap();
        assert_eq!(ident.dev, m.dev());
        assert_eq!(ident.ino, m.ino());
        assert_eq!(ident.uid, m.uid());
        assert_eq!(ident.uid, effective_uid());
        assert_eq!(ident.mtime_sec, m.mtime());
        assert_eq!(i64::from(ident.mtime_nsec), m.mtime_nsec());
        assert!(ident.is_socket);
        assert!(!ident.is_symlink);
    }

    /// PLUG-12: symlink は辿らず、リンク自身の情報を返す。
    #[test]
    fn plug12_macos_lstat_at_does_not_follow_symlink() {
        let t = Tmp::new("link");
        let _l = UnixListener::bind(t.0.join("s")).unwrap();
        symlink("s", t.0.join("l")).unwrap();
        let dir = File::open(&t.0).unwrap();
        let ident = lstat_at(&dir, c"l").unwrap();
        let target = std::fs::symlink_metadata(t.0.join("s")).unwrap();
        assert!(ident.is_symlink);
        assert!(!ident.is_socket);
        assert_eq!(
            ident.ino,
            std::fs::symlink_metadata(t.0.join("l")).unwrap().ino()
        );
        assert_ne!(ident.ino, target.ino());
    }

    /// PLUG-12: dir fd を開いた後にディレクトリが rename されても、fd の指すディレクトリ内の
    /// エントリを返す（元のパスに別の同名エントリがあっても再解決しない）。
    #[test]
    fn plug12_macos_lstat_at_is_relative_to_dir_fd_after_rename() {
        let t = Tmp::new("rename");
        let orig = t.0.join("d");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&orig)
            .unwrap();
        let _l = UnixListener::bind(orig.join("s")).unwrap();
        let want = std::fs::symlink_metadata(orig.join("s")).unwrap().ino();
        let dir = File::open(&orig).unwrap();
        std::fs::rename(&orig, t.0.join("moved")).unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&orig)
            .unwrap();
        std::fs::write(orig.join("s"), b"x").unwrap();
        let ident = lstat_at(&dir, c"s").unwrap();
        assert_eq!(ident.ino, want);
        assert!(ident.is_socket);
    }

    /// PLUG-12: 存在しない名前は `NotFound`。
    #[test]
    fn plug12_macos_lstat_at_missing_name_is_not_found() {
        let t = Tmp::new("missing");
        let dir = File::open(&t.0).unwrap();
        let e = lstat_at(&dir, c"nope").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    /// PLUG-12: 名前が開いているファイルと同じ inode を指す場合だけ `true`。
    #[test]
    fn plug12_macos_names_open_file_matches_only_same_inode() {
        let t = Tmp::new("names");
        let dir = File::open(&t.0).unwrap();
        let p = t.0.join("f");
        std::fs::write(&p, b"a").unwrap();
        let f = File::open(&p).unwrap();
        assert!(names_open_file(&dir, c"f", &f).unwrap());
        std::fs::remove_file(&p).unwrap();
        assert!(!names_open_file(&dir, c"f", &f).unwrap());
        std::fs::write(&p, b"b").unwrap();
        assert!(!names_open_file(&dir, c"f", &f).unwrap());
    }
}

// ---- macOS の常駐メモリ（RSS）取得（PLUG-8・PLUG-9。TASK-112.1・#265） ----

/// 指定 pid の常駐メモリ量（バイト）を返す（macOS。libproc の `proc_pidinfo(PROC_PIDTASKINFO)`）。
///
/// `crate::rss` の macOS 実装から呼ばれる。Linux は `/proc` を std で読むためここには FFI を持たない。
/// 戻り値が構造体サイズと一致しない場合は失敗として扱い、構造体を初期化済みとして使わない。
#[cfg(target_os = "macos")]
pub(crate) fn resident_size_bytes(pid: u32) -> io::Result<u64> {
    use core::mem::{MaybeUninit, size_of};

    /// `<sys/proc_info.h>` の `PROC_PIDTASKINFO`。
    const PROC_PIDTASKINFO: i32 = 4;

    /// `<sys/proc_info.h>` の `struct proc_taskinfo`（u64 × 6 ＋ i32 × 12 = 96 バイト。
    /// x86_64 / aarch64 でレイアウトは同一）。
    #[repr(C)]
    struct ProcTaskInfo {
        pti_virtual_size: u64,
        pti_resident_size: u64,
        pti_total_user: u64,
        pti_total_system: u64,
        pti_threads_user: u64,
        pti_threads_system: u64,
        pti_policy: i32,
        pti_faults: i32,
        pti_pageins: i32,
        pti_cow_faults: i32,
        pti_messages_sent: i32,
        pti_messages_received: i32,
        pti_syscalls_mach: i32,
        pti_syscalls_unix: i32,
        pti_csw: i32,
        pti_threadnum: i32,
        pti_numrunning: i32,
        pti_priority: i32,
    }
    // レイアウト誤りをコンパイル時に検出する。
    const _: () = assert!(size_of::<ProcTaskInfo>() == 96);

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: libSystem（libproc）の
        // `int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize)` と同じ型・幅。
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut core::ffi::c_void,
            buffersize: i32,
        ) -> i32;
    }

    let pid = i32::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
    let size = i32::try_from(size_of::<ProcTaskInfo>())
        .map_err(|_| io::Error::other("proc_taskinfo size out of range"))?;
    let mut info = MaybeUninit::<ProcTaskInfo>::uninit();
    // SAFETY: `buffer` は `size` バイト書き込み可能な `MaybeUninit<ProcTaskInfo>` を指し、`buffersize` は
    // その `size_of` と一致する。`arg` は PROC_PIDTASKINFO では未使用（0）。
    let rc = unsafe { proc_pidinfo(pid, PROC_PIDTASKINFO, 0, info.as_mut_ptr().cast(), size) };
    if rc != size {
        // 0 以下は失敗（errno 参照）。それ以外のサイズ不一致も初期化済みとして扱わない。
        return Err(if rc > 0 {
            io::Error::other("proc_pidinfo returned an unexpected size")
        } else {
            io::Error::last_os_error()
        });
    }
    // SAFETY: 戻り値が構造体サイズと一致したため、カーネルが全フィールドを書き込み済み。
    let info = unsafe { info.assume_init() };
    Ok(info.pti_resident_size)
}

/// `DirStream` の照合（対応 OS・アーキテクチャ共通。macOS の経路は macOS の CI が実行する）。
#[cfg(all(
    test,
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
mod dir_stream_tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("fc-dirs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// PLUG-7・PLUG-12（#1310）: `DirStream` は検証済みディレクトリ fd 基準で `.`・`..` を除く名前を
    /// すべて返し、末尾まで読んだ後のカーネル位置から開き直すと何も返さない（続きから読める）。
    #[test]
    fn plug7_dir_stream_lists_names_and_resumes_at_kernel_position() {
        let d = tmpdir("list");
        for n in ["a", "b", "c"] {
            std::fs::write(d.join(n), b"").unwrap();
        }
        let dir = open_dir_nofollow(&d.canonicalize().unwrap()).unwrap();
        let mut stream = DirStream::open_at(&dir, 0).unwrap();
        let mut names = Vec::new();
        while let Some(n) = stream.next_entry(<[u8]>::to_vec).unwrap() {
            names.push(String::from_utf8(n).unwrap());
        }
        names.sort();
        assert_eq!(names, ["a", "b", "c"]);
        let end = stream.position().unwrap();
        assert_ne!(end, 0);
        let mut rest = DirStream::open_at(&dir, end).unwrap();
        assert_eq!(rest.next_entry(<[u8]>::to_vec).unwrap(), None);
        // 開き直しは別の open file description なので、`dir` 自身の読み取り位置は変わらない。
        let mut again = DirStream::open_at(&dir, 0).unwrap();
        let mut count = 0;
        while again.next_entry(|_| ()).unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 3);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// PLUG-7・REPAIR-5（#1310）: libc のまとめ読みの境界で得たカーネル位置から開き直すと、その境界より
    /// 後ろのエントリだけが返る（手前を読み直さずに続きから読める）。3,000 件のディレクトリで、2 つ目の
    /// まとめ読みの境界から読んだ件数が「全件 - 境界より手前の件数」に一致することを確かめる。
    #[test]
    fn plug7_dir_stream_resumes_from_batch_boundary() {
        const TOTAL: usize = 3_000;
        let d = tmpdir("resume");
        for i in 0..TOTAL {
            std::fs::write(d.join(format!("entry-{i:04}")), b"").unwrap();
        }
        let dir = open_dir_nofollow(&d.canonicalize().unwrap()).unwrap();
        let mut stream = DirStream::open_at(&dir, 0).unwrap();
        // (まとめ読みを始めた位置, その先頭エントリの通し番号)
        let mut batches: Vec<(u64, usize)> = Vec::new();
        let mut pos = 0u64;
        let mut total = 0usize;
        while stream.next_entry(|_| ()).unwrap().is_some() {
            let now = stream.position().unwrap();
            if now != pos {
                batches.push((pos, total));
                pos = now;
            }
            total += 1;
        }
        assert_eq!(total, TOTAL);
        assert!(batches.len() >= 2, "batches={batches:?}");
        let (offset, before) = batches[1];
        let mut rest = DirStream::open_at(&dir, offset).unwrap();
        let mut remaining = 0usize;
        while rest.next_entry(|_| ()).unwrap().is_some() {
            remaining += 1;
        }
        assert_eq!(
            remaining,
            TOTAL - before,
            "offset={offset} before={before} batches={:?}",
            &batches[..batches.len().min(6)]
        );
        std::fs::remove_dir_all(&d).unwrap();
    }
}

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `int kill(pid_t pid, int sig)` と同じ引数・戻り値の幅
    // （`pid_t` は Linux・macOS とも `i32`）。出典: `man 2 kill`・`man 7 signal-safety`。
    fn kill(pid: i32, sig: i32) -> i32;
}

/// `pid`（負値はプロセスグループ宛て）へ `sig` を送る。送れたら true、失敗（`ESRCH` 等）は false。
///
/// `crate::signal_forward` のシグナルハンドラ（CLI バイナリ。#1513）から呼ばれるため、割り当て・ロック・
/// errno の取得をしない（`kill` は POSIX の async-signal-safe 関数）。`0`（自プロセスグループ）と
/// `-1`（権限の及ぶ全プロセス）は事故を防ぐため送らず false を返す（防御。登録表は 1 より大きい pid
/// だけを保持する）。
pub(crate) fn send_signal(pid: i32, sig: i32) -> bool {
    if pid == 0 || pid == -1 {
        return false;
    }
    // SAFETY: 引数は値渡しの整数のみでメモリ安全上の前提を持たない。`kill` は async-signal-safe。
    // 送り先の妥当性（直接の子の pid またはそのグループ）は呼び出し側の登録表が保証する。
    unsafe { kill(pid, sig) == 0 }
}

#[cfg(test)]
unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `pid_t waitpid(pid_t pid, int *status, int options)`
    // （`pid_t`・`int` は Linux・macOS とも `i32`）。出典: `man 2 waitpid`。テスト専用。
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
}

/// テスト専用: `pid` の子を `waitpid(pid, WNOHANG)` で 1 回だけ回収する。回収したら `Ok(true)`、まだ
/// 動いていれば `Ok(false)`。`ChildGuard` の外の回収者（ライブラリ利用側の `waitpid` 等）を模し、
/// `ECHILD` の経路（#1513・PLUG-7）を決定的に作るために `crate::lifecycle` のテストから呼ぶ。
/// `pid` に負値・0 を渡さない（任意の子を回収しない）ため、呼び出し側は自分が起動した子の pid だけを渡す。
#[cfg(test)]
pub(crate) fn reap_child_for_test(pid: u32) -> std::io::Result<bool> {
    // WNOHANG は Linux（`bits/waitflags.h`）・macOS（`sys/wait.h`）とも 1。
    const WNOHANG: i32 = 1;
    let pid = i32::try_from(pid)
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut status = 0i32;
    // SAFETY: `status` は呼び出し中有効なスタック上の書き込み可能な `i32`。`pid` は正の値に限定済みで、
    // 特定の 1 プロセスだけを対象にする（`-1`・`0` のグループ指定にならない）。
    let r = unsafe { waitpid(pid, &mut status, WNOHANG) };
    match r {
        0 => Ok(false),
        r if r == pid => Ok(true),
        _ => Err(std::io::Error::last_os_error()),
    }
}

/// #1514・PLUG-7: `set_parent_death_sigkill` の親 pid 照合（fork から prctl までの窓そのものは、親を決定的に
/// 割り込ませる手段がなく再現できないため、照合の分岐を不一致の pid で代替検証する）。
#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod pdeathsig_tests {
    use super::*;
    use std::process::{Child, Command, ExitStatus};
    use std::time::{Duration, Instant};

    /// 子の回収を `try_wait` のポーリングと期限で行う（REPAIR-5。期限超過時は kill 後も有限期限で回収を試み失敗にする）。
    fn wait_bounded(mut child: Child) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                // kill 後の回収にも有限の期限を設ける（無期限の `wait` は残さない）。
                let reap_deadline = Instant::now() + Duration::from_secs(5);
                while Instant::now() < reap_deadline {
                    if !matches!(child.try_wait(), Ok(None)) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                panic!("child did not exit within the deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn plug7_pdeathsig_mismatched_parent_pid_aborts_exec() {
        let wrong = std::process::id().checked_add(1).unwrap();
        let mut cmd = Command::new("/bin/true");
        set_parent_death_sigkill(&mut cmd, wrong).unwrap();
        let err = cmd.spawn().unwrap_err();
        assert_eq!(err.raw_os_error(), Some(3));
    }

    #[test]
    fn plug7_pdeathsig_matching_parent_pid_spawns_normally() {
        let mut cmd = Command::new("/bin/true");
        set_parent_death_sigkill(&mut cmd, std::process::id()).unwrap();
        let status = wait_bounded(cmd.spawn().unwrap());
        assert_eq!(status.code(), Some(0));
    }

    #[test]
    fn plug7_pdeathsig_rejects_pid_beyond_i32() {
        let mut cmd = Command::new("/bin/true");
        let err = set_parent_death_sigkill(&mut cmd, u32::MAX).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}

/// PLUG-12・#1308: Linux・macOS 以外の OS 向けに他 OS の値を流用した仮置きの `const` / `type` を
/// 置かないことをソース照合で保証する（対応外 OS は CI で実行できないための機械照合。REPAIR-12）。
#[cfg(test)]
mod placeholder_tests {
    #[test]
    fn plug12_no_placeholder_constants_for_unsupported_os() {
        let src = include_str!("sys.rs");
        let lines: Vec<&str> = src.lines().map(str::trim_start).collect();
        let neg = concat!("#[cfg(", "not(any(target_os");
        let mut found = Vec::new();
        for (i, l) in lines.iter().enumerate() {
            if !l.starts_with(neg) {
                continue;
            }
            // 属性行（複数行の場合あり）を飛ばして直後の item を調べる。
            let item = lines[i + 1..].iter().find(|n| {
                !n.starts_with(')')
                    && !n.starts_with("target_os")
                    && !n.starts_with("any(")
                    && !n.starts_with("#[")
            });
            if let Some(n) = item
                && (n.starts_with("const ") || n.starts_with("type ") || n.starts_with("static "))
            {
                found.push(i + 1);
            }
        }
        assert_eq!(found, Vec::<usize>::new());
    }
}

/// #1311・PLUG-7: `kill_process_group` の入力検証と送信。
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod killpg_tests {
    use super::*;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::Command;

    #[test]
    fn rejects_pgid_below_two_or_out_of_range() {
        for bad in [0u32, 1, u32::MAX, i32::MAX as u32 + 1] {
            let err = kill_process_group(bad).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "pgid={bad}");
        }
    }

    #[test]
    fn kills_new_process_group_with_sigkill() {
        let mut child = Command::new("/bin/sleep")
            .arg("60")
            .process_group(0)
            .spawn()
            .unwrap();
        kill_process_group(child.id()).unwrap();
        // 無期限の `wait` を避け、`try_wait` のポーリングと有限の期限で回収する（REPAIR-5）。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let status = loop {
            if let Some(st) = child.try_wait().unwrap() {
                break st;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.try_wait();
                panic!("child was not reaped within the deadline after SIGKILL");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(status.signal(), Some(9));
    }
}
/// #1604・PLUG-7・REPAIR-5: `probe_child_exit` は回収せずに終了を観測し、他所で回収された後は `ECHILD`。
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod probe_child_exit_tests {
    use super::*;
    use std::process::Command;
    use std::time::{Duration, Instant};

    /// 終了済みと観測できるまで期限つきでポーリングする（REPAIR-5）。
    fn wait_exited(pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if probe_child_exit(pid).unwrap() == ChildExitProbe::Exited {
                return;
            }
            assert!(Instant::now() < deadline, "child did not exit in time");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn plug7_probe_reports_running_for_live_child() {
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        assert_eq!(
            probe_child_exit(child.id()).unwrap(),
            ChildExitProbe::Running
        );
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn plug7_probe_reports_exited_without_reaping() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 7"])
            .spawn()
            .unwrap();
        let pid = child.id();
        wait_exited(pid);
        // 2 回目も同じ結果（回収していない）で、その後 std の `try_wait` が終了コードを回収できる。
        assert_eq!(probe_child_exit(pid).unwrap(), ChildExitProbe::Exited);
        let status = child.try_wait().unwrap().expect("must still be reapable");
        assert_eq!(status.code(), Some(7));
    }

    #[test]
    // 回収は `reap_child_for_test`（`waitpid` を pid で呼ぶ）が行うため、`Child::wait` は呼ばない。
    #[allow(clippy::zombie_processes)]
    fn plug7_probe_fails_with_echild_after_reaped_elsewhere() {
        let child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        let pid = child.id();
        wait_exited(pid);
        assert!(reap_child_for_test(pid).unwrap());
        let e = probe_child_exit(pid).unwrap_err();
        // ECHILD は Linux・macOS とも 10。
        assert_eq!(e.raw_os_error(), Some(10));
    }

    #[test]
    fn plug7_probe_rejects_pid_zero_and_one() {
        for bad in [0u32, 1, u32::MAX] {
            let e = probe_child_exit(bad).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "pid={bad}");
        }
    }
}

/// #1605・REPAIR-5・PLUG-7: Drop 診断の送信フラグの固定値（Linux x86_64 / aarch64）。
#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod write_nonblocking_flag_tests {
    use super::*;

    #[test]
    fn repair5_send_flags_are_fixed_values() {
        assert_eq!(MSG_DONTWAIT, 0x40);
        assert_eq!(MSG_NOSIGNAL, 0x4000);
        assert_eq!(MSG_DONTWAIT | MSG_NOSIGNAL, 0x4040);
        assert_eq!(SOL_SOCKET, 1);
        assert_eq!(SO_TYPE, 3);
        assert_eq!(F_GETPIPE_SZ, 1032);
        assert_eq!(O_NONBLOCK_NOCTTY, 0o4400);
    }

    /// 相手が閉じた socket への送信は `EPIPE`（`BrokenPipe`）で戻る。`SIGPIPE` が出ないことそのものは、試験の実行時が
    /// `SIGPIPE` を無視しているため本試験では照合できない（フラグの付与は上の固定値試験と呼び出し箇所で担保する）。
    #[test]
    fn repair5_send_to_closed_peer_returns_epipe() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(b);
        let e = write_nonblocking(&a, b"x\n").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
    }
}

/// REPAIR-2・#1604: `waitid_abi` の定数は OS・アーキテクチャごとの個別定義で、ヘッダの値と一致する
/// （Linux: `linux/wait.h`・`bits/waitflags.h`・`bits/types/idtype_t.h`、macOS: `sys/wait.h`）。
/// 誤った `WNOWAIT` は子を回収してしまい、pgid の再利用を許すため具体値で固定する（PLUG-7）。
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod waitid_abi_linux_x86_64_tests {
    use super::waitid_abi;

    #[test]
    fn repair2_waitid_constants_match_linux_x86_64_headers() {
        assert_eq!(waitid_abi::P_PID, 1);
        assert_eq!(waitid_abi::WNOHANG, 1);
        assert_eq!(waitid_abi::WEXITED, 4);
        assert_eq!(waitid_abi::WNOWAIT, 0x0100_0000);
    }

    /// PLUG-7: `zeroed` は `si_pid == 0`（「未終了」の読み）を含む全フィールド 0 の値を返す。
    #[test]
    fn plug7_siginfo_zeroed_has_all_fields_zero() {
        let info = waitid_abi::SigInfo::zeroed();
        assert_eq!(
            (info.si_signo, info.si_errno, info.si_code, info.pad0),
            (0, 0, 0, 0)
        );
        assert_eq!((info.si_pid, info.si_uid), (0, 0));
        assert_eq!(info.rest, [0u8; 104]);
    }
}

/// REPAIR-2・#1604: Linux aarch64 の `waitid_abi` 定数（x86_64 と同じ値だが個別に定義・検査する）。
#[cfg(all(test, target_os = "linux", target_arch = "aarch64"))]
mod waitid_abi_linux_aarch64_tests {
    use super::waitid_abi;

    #[test]
    fn repair2_waitid_constants_match_linux_aarch64_headers() {
        assert_eq!(waitid_abi::P_PID, 1);
        assert_eq!(waitid_abi::WNOHANG, 1);
        assert_eq!(waitid_abi::WEXITED, 4);
        assert_eq!(waitid_abi::WNOWAIT, 0x0100_0000);
    }

    /// PLUG-7: `zeroed` は `si_pid == 0`（「未終了」の読み）を含む全フィールド 0 の値を返す。
    #[test]
    fn plug7_siginfo_zeroed_has_all_fields_zero() {
        let info = waitid_abi::SigInfo::zeroed();
        assert_eq!(
            (info.si_signo, info.si_errno, info.si_code, info.pad0),
            (0, 0, 0, 0)
        );
        assert_eq!((info.si_pid, info.si_uid), (0, 0));
        assert_eq!(info.rest, [0u8; 104]);
    }
}

/// REPAIR-2・#1604: macOS の `waitid_abi` 定数（`WNOWAIT` は Linux と異なる 0x20）。
#[cfg(all(test, target_os = "macos"))]
mod waitid_abi_macos_tests {
    use super::waitid_abi;

    #[test]
    fn repair2_waitid_constants_match_macos_headers() {
        assert_eq!(waitid_abi::P_PID, 1);
        assert_eq!(waitid_abi::WNOHANG, 1);
        assert_eq!(waitid_abi::WEXITED, 4);
        assert_eq!(waitid_abi::WNOWAIT, 0x20);
    }

    /// PLUG-7: `zeroed` は `si_pid == 0`（「未終了」の読み）を含む全フィールド 0 の値を返す。
    #[test]
    fn plug7_siginfo_zeroed_has_all_fields_zero() {
        let info = waitid_abi::SigInfo::zeroed();
        assert_eq!((info.si_signo, info.si_errno, info.si_code), (0, 0, 0));
        assert_eq!((info.si_pid, info.si_uid, info.si_status), (0, 0, 0));
        assert_eq!(info.rest, [0u64; 10]);
    }
}
