//! `mount(2)` の薄いラッパー（`unsafe` はこのモジュールに閉じる。#1823 の事前承認の範囲・MAC-1）。
//!
//! ゲスト init が `/proc`・`/sys`・`/dev` と virtiofs の mount、および子の回収（`waitpid(-1)`。
//! pid は -1 固定・flags は 0 か `WNOHANG` の 2 値だけ。MAC-4・#2269）に使う。協調停止（MAC-4・#2270）の
//! ためのシグナル受信（`sigprocmask`・`sigtimedwait`）・全プロセスへの終了要求（`kill(-1)`）・`sync`・
//! `reboot(RB_POWER_OFF)` も持つ。ホストを巻き込む `kill(-1)`・`reboot` は PID 1 以外では syscall を呼ばない。公開するのは用途別の安全な関数
//! （virtiofs・proc・sysfs・devtmpfs）だけで、任意の flags / data は型の上で渡せない（`MS_BIND`・
//! `MS_MOVE`・`MS_REMOUNT` を呼び出し側が組めない。REPAIR-2）。`unsafe fn` は外へ出さない。`extern "C"` 宣言は自前（外部クレートを使わない）。`libc` との機械照合
//! （#1318・#2076）は試験専用モジュール `libc_abi` が const 評価で行い、固定値テストも併用する。
//!
//! virtiofs の mount 先は文字列パスではなく fd で固定する（#2268・#2080 P2-4・MAC-1・SEC-1）。`/` から
//! 要素ごとに `openat(O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)` で辿り（欠けた要素は `mkdirat`）、最後の fd を
//! `/proc/self/fd/<n>` として `mount(2)` の target に渡す。検査（open）と mount が同じ fd を指すので、
//! 途中の symlink への差し替えで mount 先がずれない。
//!
//! 定数は `O_DIRECTORY`・`O_NOFOLLOW` を除き x86_64 / aarch64 の Linux で同値（この 2 つはアーキごとに cfg で
//! 分ける）。他アーキテクチャへ流用しない（`SUPPORTED` が偽なら
//! `ENOSYS` を返して何も呼ばない）。`c_ulong` が u64 になる LP64 だけを対象にし、x32・ILP32 は `ENOSYS`
//! とする。

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// 対応アーキテクチャ（定数を検証済みのもの）。
/// `c_ulong` が u64 になる LP64 に限る（x32・ILP32 は除外）。
const SUPPORTED: bool = cfg!(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_pointer_width = "64"
));

/// 読み取り専用。
const MS_RDONLY: u64 = 1;
/// setuid / setgid を無効にする。
const MS_NOSUID: u64 = 2;
/// デバイスファイルを無効にする。
const MS_NODEV: u64 = 4;
/// 実行を禁止する。
const MS_NOEXEC: u64 = 8;
/// `open(2)` で制御端末にしない。値は asm-generic（x86_64・aarch64）のもので、`SUPPORTED` と同じ
/// 対象に cfg で閉じる（他 arch の値を流用しない。#3202・MVM-4）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub const O_NOCTTY: i32 = 0o400;
/// 対象外 arch では値を確かめていないため flag を付けない（0）。この arch では mount 系が `ENOSYS` を返し
/// init は先へ進まないので、コンソールの開き方の差は実害を生まない。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const O_NOCTTY: i32 = 0;

/// パス解決だけに使う fd を開く（読み書きはできない）。
const O_PATH: i32 = 0o10000000;
/// exec で子へ引き継がない（将来の子プロセスへ fd を漏らさない）。
pub const O_CLOEXEC: i32 = 0o2000000;
/// ディレクトリでなければ失敗する。値はアーキごとに違う（asm-generic と arm64 の uapi）。
#[cfg(target_arch = "x86_64")]
const O_DIRECTORY: i32 = 0o200000;
#[cfg(target_arch = "aarch64")]
const O_DIRECTORY: i32 = 0o40000;
/// 末尾要素が symlink なら辿らず失敗する。値はアーキごとに違う。
#[cfg(target_arch = "x86_64")]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(target_arch = "aarch64")]
const O_NOFOLLOW: i32 = 0o100000;
/// 対象外 arch では `SUPPORTED` が偽で syscall を呼ばないため、値は使われない（0）。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const O_DIRECTORY: i32 = 0;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const O_NOFOLLOW: i32 = 0;
/// `openat` の dirfd に渡す「カレントディレクトリ」（絶対パスでは無視される）。
const AT_FDCWD: i32 = -100;
/// 要素を開くときのフラグ。呼び出し側からは組めない（REPAIR-2）。
const OPEN_DIR_FLAGS: i32 = O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
/// 欠けた要素を作るときの mode（umask 前）。
const MKDIR_MODE: u32 = 0o755;

/// `ENOSYS`（Linux 共通）。
const ENOSYS: i32 = 38;
/// `EINVAL`（Linux 共通）。
const EINVAL: i32 = 22;
/// `ECHILD`（Linux 共通。回収できる子がいない）。
pub const ECHILD: i32 = 10;
/// `EINTR`（Linux 共通。シグナルで中断された）。
pub const EINTR: i32 = 4;
/// `waitpid` の flags。待たずに戻る。
const WNOHANG: i32 = 1;
/// `EAGAIN`（Linux 共通。`sigtimedwait` の期限切れ）。
pub const EAGAIN: i32 = 11;
/// `ESRCH`（Linux 共通。シグナルの送り先のプロセスが無い）。
pub const ESRCH: i32 = 3;
/// `EPERM`（Linux 共通。PID 1 でないときの停止系 syscall の拒否に使う）。
const EPERM: i32 = 1;
/// `SIGKILL`（x86_64・aarch64 で同値）。
const SIGKILL: i32 = 9;
/// `SIGTERM`（同上）。
const SIGTERM: i32 = 15;
/// `SIGCHLD`（x86_64・aarch64 の Linux で 17）。
const SIGCHLD: i32 = 17;
/// `SIGPWR`（x86_64・aarch64 の Linux で 30。停止要求として使う。mips・alpha 等では値が違うため流用しない）。
const SIGPWR: i32 = 30;
/// `sigprocmask` の how。ブロック集合に加える。
const SIG_BLOCK: i32 = 0;
/// `reboot(2)` の cmd。電源断（`LINUX_REBOOT_CMD_POWER_OFF`）。
const RB_POWER_OFF: u32 = 0x4321_fedc;
/// `prctl` の option（試験専用）。子孫の孤児の再親付け先を自分にする。
#[cfg(test)]
const PR_SET_CHILD_SUBREAPER: i32 = 36;
/// `prctl` の option（試験専用）。subreaper の設定を読み戻す。
#[cfg(test)]
const PR_GET_CHILD_SUBREAPER: i32 = 37;

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: `int mount(const char *source, const char *target,
    // const char *fstype, unsigned long flags, const void *data)`。`c_ulong` は LP64（x86_64・aarch64 の
    // Linux。glibc / musl）で u64。
    fn mount(
        source: *const core::ffi::c_char,
        target: *const core::ffi::c_char,
        fstype: *const core::ffi::c_char,
        flags: u64,
        data: *const core::ffi::c_void,
    ) -> i32;

    // SAFETY（宣言そのものの妥当性）: `int openat(int dirfd, const char *path, int flags, ...)`。
    // 可変長引数は `O_CREAT`・`O_TMPFILE` のときだけ読まれ、本モジュールは常に渡さない。
    fn openat(dirfd: i32, path: *const core::ffi::c_char, flags: i32, ...) -> i32;

    // SAFETY（宣言そのものの妥当性）: `int mkdirat(int dirfd, const char *path, mode_t mode)`。
    // `mode_t` は Linux で u32。
    fn mkdirat(dirfd: i32, path: *const core::ffi::c_char, mode: u32) -> i32;

    // SAFETY（宣言そのものの妥当性）: `pid_t waitpid(pid_t pid, int *wstatus, int options)`。
    // `pid_t` は Linux で i32。
    fn waitpid(pid: i32, wstatus: *mut i32, options: i32) -> i32;

    // SAFETY（宣言そのものの妥当性）: `int kill(pid_t pid, int sig)`。`pid_t` は Linux で i32。
    fn kill(pid: i32, sig: i32) -> i32;

    // SAFETY（宣言そのものの妥当性）: `int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)`。
    // `sigset_t` は glibc・musl とも 128 バイト（`SigSet` と同じ配置）。単一スレッド（スレッドを作る前）から
    // だけ呼ぶ（マルチスレッドの挙動は未規定のため）。
    fn sigprocmask(how: i32, set: *const SigSet, oldset: *mut SigSet) -> i32;

    // SAFETY（宣言そのものの妥当性）: `int sigtimedwait(const sigset_t *set, siginfo_t *info,
    // const struct timespec *timeout)`。info は常に null を渡す（情報を受け取らない）ため型は `c_void`。
    fn sigtimedwait(
        set: *const SigSet,
        info: *mut core::ffi::c_void,
        timeout: *const Timespec,
    ) -> i32;

    // SAFETY（宣言そのものの妥当性）: `void sync(void)`。
    fn sync();

    // SAFETY（宣言そのものの妥当性）: glibc / musl の `int reboot(int cmd)`（magic はライブラリが補う）。
    fn reboot(cmd: i32) -> i32;

    // SAFETY（宣言そのものの妥当性）: `int prctl(int option, ...)`。試験専用で、本モジュールは
    // `PR_SET_CHILD_SUBREAPER`・`PR_GET_CHILD_SUBREAPER` だけを、残りの引数を 4 つの u64 / ポインタで渡す。
    #[cfg(test)]
    fn prctl(option: i32, ...) -> i32;
}

/// カーネルの `sigset_t` を包む glibc・musl の 1024 bit の集合（128 バイト）。
#[repr(C)]
struct SigSet([u64; 16]);

impl SigSet {
    /// 空集合。
    const fn empty() -> Self {
        Self([0; 16])
    }

    /// シグナル番号（1..=64）を加える。範囲外は何もしない。
    fn add(&mut self, sig: i32) {
        if (1..=64).contains(&sig) {
            let idx = usize::try_from((sig - 1) / 64).unwrap_or(0);
            let bit = u32::try_from((sig - 1) % 64).unwrap_or(0);
            if let Some(w) = self.0.get_mut(idx) {
                *w |= 1u64 << bit;
            }
        }
    }
}

/// `struct timespec`（LP64 の Linux。x86_64・aarch64 の glibc・musl で `{ i64, i64 }`）。
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

fn cstring(bytes: &[u8]) -> io::Result<CString> {
    // NUL を含む入力は EINVAL にする（カーネルへ切り詰めた文字列を渡さない）。
    CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(EINVAL))
}

/// 1 要素の名前だけを許す（空・`.`・`..`・`/` を含む・NUL を含むものは EINVAL）。
/// `MountPoint` の検証に加えた多重防御で、親 fd の外へ出る解決を作らない。
fn single_element(name: &str) -> io::Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::from_raw_os_error(EINVAL));
    }
    cstring(name.as_bytes())
}

fn wrap_fd(rc: i32) -> io::Result<OwnedFd> {
    if rc >= 0 {
        // SAFETY: `rc` は直前の成功した `openat` が返した fd で、他に所有者がいない。
        Ok(unsafe { OwnedFd::from_raw_fd(rc) })
    } else {
        // 直後に errno を取る（間に libc 呼び出しを挟まない）。
        Err(io::Error::last_os_error())
    }
}

fn open_dir_at(dirfd: i32, path: &CString) -> io::Result<OwnedFd> {
    if !SUPPORTED {
        return Err(io::Error::from_raw_os_error(ENOSYS));
    }
    // SAFETY: `path` は NUL 終端の `CString` でこの呼び出しが戻るまで生存する。`dirfd` は呼び出し元の
    // `BorrowedFd`（借用中は有効）か `AT_FDCWD`。`O_CREAT` を含まないので可変長引数は読まれない。
    // errno は `wrap_fd` が直後に取る。
    let rc = unsafe { openat(dirfd, path.as_ptr(), OPEN_DIR_FLAGS) };
    wrap_fd(rc)
}

/// `/` を symlink を辿らずに開く（fd 起点の辿りの出発点。MAC-1）。
pub fn open_root_dir() -> io::Result<OwnedFd> {
    open_dir_at(AT_FDCWD, &cstring(b"/")?)
}

/// `parent` 直下の実ディレクトリ `name` を開く。symlink・非ディレクトリは `ENOTDIR` で失敗する。
pub fn open_child_dir(parent: BorrowedFd<'_>, name: &str) -> io::Result<OwnedFd> {
    let name = single_element(name)?;
    open_dir_at(parent.as_raw_fd(), &name)
}

/// `parent` 直下にディレクトリ `name` を作る（mode 0o755）。既存なら `EEXIST`。
pub fn mkdir_child(parent: BorrowedFd<'_>, name: &str) -> io::Result<()> {
    let name = single_element(name)?;
    if !SUPPORTED {
        return Err(io::Error::from_raw_os_error(ENOSYS));
    }
    // SAFETY: `name` は NUL 終端の `CString` でこの呼び出しが戻るまで生存し、`parent` は借用中有効な fd。
    // mkdirat(2) はポインタ先を読むだけで保持しない。errno は直後に取る。
    let rc = unsafe { mkdirat(parent.as_raw_fd(), name.as_ptr(), MKDIR_MODE) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// 任意の子（pid -1）を 1 つ回収する（MAC-4・#2269）。PID 1 の回収ループ（`reap`）が `init` の
/// `LinuxWaiter` 経由で呼ぶ。`nohang` が真なら `WNOHANG` で、回収できる子が今は無ければ `Ok(None)`。
/// 成功は (pid, 生の wait status)。子がいなければ `ECHILD`、中断なら `EINTR` を `io::Error` で返す。
/// pid と flags は型の上で固定され、特定の子の指定や `WUNTRACED` 等は渡せない（REPAIR-2）。
pub fn wait_any_child(nohang: bool) -> io::Result<Option<(i32, i32)>> {
    if !SUPPORTED {
        return Err(io::Error::from_raw_os_error(ENOSYS));
    }
    let flags = if nohang { WNOHANG } else { 0 };
    let mut status: i32 = 0;
    // SAFETY: `&mut status` は有効な `int` で、この呼び出しが戻るまで生存し、waitpid(2) は戻るまでの間だけ
    // 書き込む。pid は -1 固定、flags は 0 か `WNOHANG` の 2 値だけで、他のプロセスの状態を変える値は
    // 渡さない。errno は直後に取る。
    let rc = unsafe { waitpid(-1, &mut status, flags) };
    match rc {
        0 => Ok(None),
        n if n > 0 => Ok(Some((n, status))),
        _ => Err(io::Error::last_os_error()),
    }
}

/// 停止要求として扱うシグナルと `SIGCHLD` を、以後に作るスレッドを含めてブロックする（MAC-4・#2270）。
///
/// PID 1 は SIG_DFL のシグナルをカーネルが捨てるが、blocked なら捨てずに保留する。ブロックして
/// [`wait_signal`] で受けることで、ハンドラ（非同期シグナルの制約）を置かずに停止要求と子の終了で
/// 起きる。スレッドを作る前の 1 回だけ呼ぶ（スレッドはマスクを継承する）。
pub fn block_lifecycle_signals() -> io::Result<()> {
    if !SUPPORTED {
        return Err(io::Error::from_raw_os_error(ENOSYS));
    }
    let mut set = SigSet::empty();
    for s in [SIGCHLD, SIGTERM, SIGPWR] {
        set.add(s);
    }
    // SAFETY: `&set` は有効な 128 バイトの集合でこの呼び出しが戻るまで生存する。oldset は null（読み出さない）。
    // how は `SIG_BLOCK` 固定で、呼び出し元は単一スレッドの段階（スレッドを作る前）。errno は直後に取る。
    let rc = unsafe { sigprocmask(SIG_BLOCK, &raw const set, core::ptr::null_mut()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// [`wait_signal`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalWait {
    /// `SIGCHLD`（子が状態を変えた）。
    Child,
    /// 停止要求（`SIGTERM` または `SIGPWR`）。
    Stop,
    /// 期限切れ（`EAGAIN`）。
    Timeout,
    /// シグナルのハンドラに割り込まれた（`EINTR`）。
    Interrupted,
    /// 想定外のシグナル番号・失敗（errno。取れなければ 0）。
    Other(i32),
}

/// ブロック済みの `SIGCHLD`・`SIGTERM`・`SIGPWR` のいずれかを最大 `timeout` 待つ（MAC-4・#2270）。
/// 呼び出し元のスレッドは [`block_lifecycle_signals`] の後のスレッドでなければならない。
pub fn wait_signal(timeout: std::time::Duration) -> SignalWait {
    if !SUPPORTED {
        return SignalWait::Other(ENOSYS);
    }
    let mut set = SigSet::empty();
    for s in [SIGCHLD, SIGTERM, SIGPWR] {
        set.add(s);
    }
    let ts = Timespec {
        tv_sec: i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(timeout.subsec_nanos()),
    };
    // SAFETY: `&set`・`&ts` は有効でこの呼び出しが戻るまで生存し、sigtimedwait(2) は読むだけ。info は null
    // （受け取らない）。errno は直後に取る。
    let rc = unsafe { sigtimedwait(&raw const set, core::ptr::null_mut(), &raw const ts) };
    if rc > 0 {
        return classify_signal(rc);
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(EAGAIN) => SignalWait::Timeout,
        Some(EINTR) => SignalWait::Interrupted,
        Some(n) => SignalWait::Other(n),
        None => SignalWait::Other(0),
    }
}

/// 受け取ったシグナル番号の分類（OS 非依存の判断なので単体で試験する）。
fn classify_signal(sig: i32) -> SignalWait {
    match sig {
        SIGCHLD => SignalWait::Child,
        SIGTERM | SIGPWR => SignalWait::Stop,
        other => SignalWait::Other(other),
    }
}

/// 自プロセスへ停止要求（`SIGPWR`）を送る。power button の監視スレッドが使う（MAC-4・#2270）。
/// `SIGPWR` はブロック済みで、メインスレッドの [`wait_signal`] が受ける。
pub fn request_stop() -> io::Result<()> {
    if !SUPPORTED {
        return Err(io::Error::from_raw_os_error(ENOSYS));
    }
    let me = i32::try_from(std::process::id()).unwrap_or(-1);
    if me <= 0 {
        return Err(io::Error::from_raw_os_error(EINVAL));
    }
    // SAFETY: 送り先は自プロセス固定（正の pid）、sig は `SIGPWR` 固定。ポインタを渡さない。
    let rc = unsafe { kill(me, SIGPWR) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// 終了要求の強さ。型の上で `SIGTERM` と `SIGKILL` の 2 値に限る（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escalation {
    /// `SIGTERM`（猶予あり）。
    Term,
    /// `SIGKILL`。
    Kill,
}

/// PID 1 自身と呼び出し元を除く全プロセスへ終了要求を送る（`kill(-1, sig)`。MAC-4・#2270）。
/// 他にプロセスがなければ `ESRCH`。ホストの全プロセスを殺しうるため、PID 1 でなければ syscall を呼ばず
/// `EPERM` を返す（開発機・試験での誤実行の防止）。
pub fn signal_all_others(how: Escalation) -> io::Result<()> {
    if !SUPPORTED {
        return Err(io::Error::from_raw_os_error(ENOSYS));
    }
    if std::process::id() != 1 {
        return Err(io::Error::from_raw_os_error(EPERM));
    }
    let sig = match how {
        Escalation::Term => SIGTERM,
        Escalation::Kill => SIGKILL,
    };
    // SAFETY: pid は -1 固定（呼び出し元の PID 1 は対象外）、sig は上の 2 値だけ。PID 1 でなければ上で返っている。
    // ポインタを渡さない。errno は直後に取る。
    let rc = unsafe { kill(-1, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// PID 1 以外にまだプロセスが残っているか（`kill(-1, 0)` の存在確認。シグナルは送らない）。
/// 回収前のゾンビも「残っている」に数えるので、呼び出し側は先に回収する。PID 1 でなければ偽。
pub fn others_alive() -> bool {
    if !SUPPORTED || std::process::id() != 1 {
        return false;
    }
    // SAFETY: sig 0 は存在確認だけでシグナルを送らない。pid は -1 固定。ポインタを渡さない。errno は直後に取る。
    let rc = unsafe { kill(-1, 0) };
    if rc == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() != Some(ESRCH)
}

/// 書き込みをバッファからデバイスへ流す（`sync(2)`。失敗しない）。
pub fn sync_all() {
    // SAFETY: 引数なしで失敗を返さない syscall。
    unsafe { sync() }
}

/// `reboot(RB_POWER_OFF)` で電源を落とす（MAC-4・#2270）。成功すると戻らない。戻ったときは失敗の errno。
/// ホストを落としうるため、PID 1 でなければ syscall を呼ばず `EPERM` を返す。
pub fn power_off() -> io::Error {
    if !SUPPORTED {
        return io::Error::from_raw_os_error(ENOSYS);
    }
    if std::process::id() != 1 {
        return io::Error::from_raw_os_error(EPERM);
    }
    // SAFETY: cmd は `RB_POWER_OFF` 固定（`cast_signed` で i32 に写す。値は定義上 0x4321fedc）。PID 1 でなければ
    // 上で返っている。成功すれば戻らず、失敗なら -1 と errno。ポインタを渡さない。errno は直後に取る。
    let rc = unsafe { reboot(RB_POWER_OFF.cast_signed()) };
    let _ = rc;
    io::Error::last_os_error()
}

/// 自プロセスを子孫の孤児の再親付け先（subreaper）にし、読み戻して確かめる。試験専用（本物の PID 1 でない
/// 試験プロセスで孤児の再親付けを起こすため。MAC-4・#2269）。プロセス全体に効くので、再起動した子プロセス
/// の中でだけ呼ぶ。
#[cfg(test)]
pub fn set_child_subreaper() -> io::Result<()> {
    if !SUPPORTED {
        return Err(io::Error::from_raw_os_error(ENOSYS));
    }
    // SAFETY: 可変長引数は 4 つの u64 で、`PR_SET_CHILD_SUBREAPER` は arg2 の値だけを読む。ポインタを
    // 受け取らず、戻り値だけを見る。errno は直後に取る。
    let rc = unsafe { prctl(PR_SET_CHILD_SUBREAPER, 1u64, 0u64, 0u64, 0u64) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut v: i32 = 0;
    // SAFETY: `PR_GET_CHILD_SUBREAPER` は arg2 を `int *` として書き込む。`&mut v` は有効でこの呼び出しが
    // 戻るまで生存する。残りの引数は無視される 0。errno は直後に取る。
    let rc = unsafe { prctl(PR_GET_CHILD_SUBREAPER, &raw mut v, 0u64, 0u64, 0u64) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if v == 1 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(EINVAL))
    }
}

/// fd を指す `/proc/self/fd/<n>`（`mount(2)` の target に渡す。先に mount 済みの proc が前提）。
fn proc_fd_path(fd: RawFd) -> String {
    format!("/proc/self/fd/{fd}")
}

/// virtiofs の mount flags（nosuid・nodev は fail-closed の既定。`ro` は必ず `MS_RDONLY`）。
fn virtiofs_flags(read_only: bool) -> u64 {
    let flags = MS_NOSUID | MS_NODEV;
    if read_only { flags | MS_RDONLY } else { flags }
}

/// proc・sysfs の flags（nosuid・nodev・noexec）。
const PSEUDO_STRICT: u64 = MS_NOSUID | MS_NODEV | MS_NOEXEC;
/// devtmpfs の flags（デバイスノードを置くため nodev は付けない）。
const DEVTMPFS_FLAGS: u64 = MS_NOSUID | MS_NOEXEC;

/// `mount(source, target, fstype, flags, data)` を呼ぶ。本モジュール内の用途別関数だけが呼ぶ。
/// 失敗は直後の errno を `io::Error` で返す。
fn mount_raw(
    source: &str,
    target: &Path,
    fstype: &str,
    flags: u64,
    data: Option<&str>,
) -> io::Result<()> {
    if !SUPPORTED {
        return Err(io::Error::from_raw_os_error(ENOSYS));
    }
    let source = cstring(source.as_bytes())?;
    let target = cstring(target.as_os_str().as_bytes())?;
    let fstype = cstring(fstype.as_bytes())?;
    let data = data.map(|d| cstring(d.as_bytes())).transpose()?;
    let data_ptr = data.as_ref().map_or(core::ptr::null(), |d| {
        d.as_ptr().cast::<core::ffi::c_void>()
    });
    // SAFETY: `source`・`target`・`fstype` は NUL 終端の `CString` で、この呼び出しが戻るまで生存する。
    // `data` は null か、同様に生存する NUL 終端文字列（呼び出し元は本モジュールの用途別関数だけで、
    // devtmpfs の `mode=0755` 固定か null）。`flags` は `c_ulong`（u64、LP64 のみ `SUPPORTED`）と同幅。
    // mount(2) はポインタ先を読むだけで保持しない。errno は直後に取る。
    let rc = unsafe {
        mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            data_ptr,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        // 直後に errno を取る（間に libc 呼び出しを挟まない）。
        Err(io::Error::last_os_error())
    }
}

/// virtiofs（`tag`）を、開いた fd が指すディレクトリへ mount する。`init` の `GuestOps::mount_virtiofs` から
/// 呼ばれる（MAC-1・#2268）。`target` は呼び出しが戻るまで借用で生きている。
pub fn mount_virtiofs_at(tag: &str, target: BorrowedFd<'_>, read_only: bool) -> io::Result<()> {
    let path = proc_fd_path(target.as_raw_fd());
    mount_raw(
        tag,
        Path::new(&path),
        "virtiofs",
        virtiofs_flags(read_only),
        None,
    )
}

/// proc を `target` へ mount する（nosuid・nodev・noexec）。
pub fn mount_proc(target: &Path) -> io::Result<()> {
    mount_raw("proc", target, "proc", PSEUDO_STRICT, None)
}

/// sysfs を `target` へ mount する（nosuid・nodev・noexec）。
pub fn mount_sysfs(target: &Path) -> io::Result<()> {
    mount_raw("sysfs", target, "sysfs", PSEUDO_STRICT, None)
}

/// devtmpfs を `target` へ mount する（nosuid・noexec、`mode=0755` 固定）。
pub fn mount_devtmpfs(target: &Path) -> io::Result<()> {
    mount_raw(
        "devtmpfs",
        target,
        "devtmpfs",
        DEVTMPFS_FLAGS,
        Some("mode=0755"),
    )
}

/// 自前の FFI 宣言・定数と `libc`（dev-dependencies のみ）のコンパイル時照合（#2076・#1318・MVM-4・REPAIR-12。
/// 方式は docs/design/ffi-libc-check.md）。食い違えば const 評価（E0080）か型不一致（E0308）で
/// ビルドが落ちる。評価されるターゲット: x86_64-unknown-linux-gnu（ネイティブ）、
/// aarch64-unknown-linux-gnu と製品のターゲット aarch64-unknown-linux-musl（cross-target-check の型検査。
/// const は評価される）。libc 0.2.189 では下記の値も `mount` の宣言も x86_64・aarch64 の gnu と musl で
/// 同一なので `target_env` では分けない（一次情報: libc の `unix/linux_like/mod.rs`・`linux_l4re_shared.rs`、
/// Linux uapi の `linux/mount.h`・`asm-generic/fcntl.h`・`asm-generic/errno-base.h`・`errno.h`）。
/// `SUPPORTED` と同じ LP64（x86_64・aarch64）に限る。他は `SUPPORTED` が偽で呼ばないため評価しない。
/// 対象外: `SUPPORTED`（cfg の判定で FFI でない）、`PSEUDO_STRICT`・`DEVTMPFS_FLAGS`・`virtiofs_flags`
/// （方針値で `libc` に無い。構成要素は照合済みで組み合わせは固定値テストが見る）、安全なラッパー群。
#[cfg(all(
    test,
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_pointer_width = "64"
))]
mod libc_abi {
    use super::*;

    // 型合わせに `as` は使わない。LP64 では u64 == c_ulong、i32 == c_int なので型が変われば E0308 になる。
    const _: () = {
        let _: libc::c_ulong = MS_RDONLY;
        assert!(MS_RDONLY == libc::MS_RDONLY);
        assert!(MS_NOSUID == libc::MS_NOSUID);
        assert!(MS_NODEV == libc::MS_NODEV);
        assert!(MS_NOEXEC == libc::MS_NOEXEC);
        assert!(O_NOCTTY == libc::O_NOCTTY);
        assert!(ENOSYS == libc::ENOSYS);
        assert!(EINVAL == libc::EINVAL);
        let _: libc::c_int = O_PATH;
        assert!(O_PATH == libc::O_PATH);
        assert!(O_DIRECTORY == libc::O_DIRECTORY);
        assert!(O_NOFOLLOW == libc::O_NOFOLLOW);
        assert!(O_CLOEXEC == libc::O_CLOEXEC);
        assert!(AT_FDCWD == libc::AT_FDCWD);
        let _: libc::mode_t = MKDIR_MODE;
        assert!(ECHILD == libc::ECHILD);
        assert!(EINTR == libc::EINTR);
        assert!(WNOHANG == libc::WNOHANG);
        assert!(EAGAIN == libc::EAGAIN);
        assert!(ESRCH == libc::ESRCH);
        assert!(EPERM == libc::EPERM);
        assert!(SIGKILL == libc::SIGKILL);
        assert!(SIGTERM == libc::SIGTERM);
        assert!(SIGCHLD == libc::SIGCHLD);
        assert!(SIGPWR == libc::SIGPWR);
        assert!(SIG_BLOCK == libc::SIG_BLOCK);
        // libc の RB_POWER_OFF は c_int。自前は u32 で持ち、cast_signed で渡す値と一致を見る。
        assert!(RB_POWER_OFF.cast_signed() == libc::RB_POWER_OFF);
        // sigset_t・timespec は配置（大きさ・アラインメント）で照合する。
        assert!(core::mem::size_of::<SigSet>() == core::mem::size_of::<libc::sigset_t>());
        assert!(core::mem::align_of::<SigSet>() == core::mem::align_of::<libc::sigset_t>());
        assert!(core::mem::size_of::<Timespec>() == core::mem::size_of::<libc::timespec>());
        assert!(core::mem::align_of::<Timespec>() == core::mem::align_of::<libc::timespec>());
        assert!(PR_SET_CHILD_SUBREAPER == libc::PR_SET_CHILD_SUBREAPER);
        assert!(PR_GET_CHILD_SUBREAPER == libc::PR_GET_CHILD_SUBREAPER);
    };

    // `mount` の型を自前の宣言と `libc` の宣言で同じ関数ポインタ型へ代入して照合する。
    type MountFn = unsafe extern "C" fn(
        *const libc::c_char,
        *const libc::c_char,
        *const libc::c_char,
        libc::c_ulong,
        *const libc::c_void,
    ) -> libc::c_int;
    const _: MountFn = mount;
    const _: MountFn = libc::mount;

    // `openat` は可変長。関数ポインタ型へそのまま代入して照合する（引数・戻り値・可変長の有無が一致すること）。
    type OpenatFn =
        unsafe extern "C" fn(libc::c_int, *const libc::c_char, libc::c_int, ...) -> libc::c_int;
    const _: OpenatFn = openat;
    const _: OpenatFn = libc::openat;
    type MkdiratFn =
        unsafe extern "C" fn(libc::c_int, *const libc::c_char, libc::mode_t) -> libc::c_int;
    const _: MkdiratFn = mkdirat;
    const _: MkdiratFn = libc::mkdirat;
    type WaitpidFn =
        unsafe extern "C" fn(libc::pid_t, *mut libc::c_int, libc::c_int) -> libc::pid_t;
    const _: WaitpidFn = waitpid;
    const _: WaitpidFn = libc::waitpid;
    // `kill`・`sync`・`reboot` は引数がポインタを含まないので関数型をそのまま照合する。
    type KillFn = unsafe extern "C" fn(libc::pid_t, libc::c_int) -> libc::c_int;
    const _: KillFn = kill;
    const _: KillFn = libc::kill;
    type SyncFn = unsafe extern "C" fn();
    const _: SyncFn = sync;
    const _: SyncFn = libc::sync;
    type RebootFn = unsafe extern "C" fn(libc::c_int) -> libc::c_int;
    const _: RebootFn = reboot;
    const _: RebootFn = libc::reboot;
    // `sigprocmask`・`sigtimedwait` の集合・時刻のポインタ型は自前の型（`SigSet`・`Timespec`）で、`libc` の型と
    // 別の名前になるため関数ポインタ型の代入では照合できない。引数の個数・幅は下の型で、型の配置は上の
    // size / align の const assert で見る（`siginfo_t` は null しか渡さないので `c_void` で宣言している）。
    type SigprocmaskFn =
        unsafe extern "C" fn(libc::c_int, *const SigSet, *mut SigSet) -> libc::c_int;
    const _: SigprocmaskFn = sigprocmask;
    type SigtimedwaitFn =
        unsafe extern "C" fn(*const SigSet, *mut core::ffi::c_void, *const Timespec) -> libc::c_int;
    const _: SigtimedwaitFn = sigtimedwait;
    // `prctl` は可変長（試験専用）。
    type PrctlFn = unsafe extern "C" fn(libc::c_int, ...) -> libc::c_int;
    const _: PrctlFn = prctl;
    const _: PrctlFn = libc::prctl;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn mac1_flag_constants_match_linux_abi() {
        assert_eq!(MS_RDONLY, 1);
        assert_eq!(MS_NOSUID, 2);
        assert_eq!(MS_NODEV, 4);
        assert_eq!(MS_NOEXEC, 8);
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        assert_eq!(O_NOCTTY, 0o400);
    }

    #[test]
    fn mac1_virtiofs_flags_compose() {
        assert_eq!(virtiofs_flags(true), 7);
        assert_eq!(virtiofs_flags(false), 6);
    }

    #[test]
    fn mac1_pseudo_flags_compose() {
        assert_eq!(PSEUDO_STRICT, 14);
        assert_eq!(DEVTMPFS_FLAGS, 10);
    }

    #[test]
    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_pointer_width = "64"
    ))]
    fn mac1_supported_on_lp64_targets() {
        const { assert!(SUPPORTED) };
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn mac1_2268_dir_flags_x86_64() {
        assert_eq!(O_DIRECTORY, 0o200000);
        assert_eq!(O_NOFOLLOW, 0o400000);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn mac1_2268_dir_flags_aarch64() {
        assert_eq!(O_DIRECTORY, 0o40000);
        assert_eq!(O_NOFOLLOW, 0o100000);
    }

    #[test]
    fn mac1_2268_common_constants_and_proc_path() {
        assert_eq!(O_PATH, 0o10000000);
        assert_eq!(O_CLOEXEC, 0o2000000);
        assert_eq!(AT_FDCWD, -100);
        assert_eq!(proc_fd_path(7), "/proc/self/fd/7");
    }

    #[test]
    fn mac1_2268_child_rejects_non_single_element() {
        let root = open_root_dir().unwrap();
        for bad in ["", ".", "..", "a/b", "a\0b"] {
            let e = open_child_dir(root.as_fd(), bad).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(22), "{bad:?}");
            let e = mkdir_child(root.as_fd(), bad).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(22), "{bad:?}");
        }
    }

    #[test]
    fn mac4_2269_wait_constants() {
        assert_eq!(WNOHANG, 1);
        assert_eq!(ECHILD, 10);
        assert_eq!(EINTR, 4);
        assert_eq!(PR_SET_CHILD_SUBREAPER, 36);
        assert_eq!(PR_GET_CHILD_SUBREAPER, 37);
    }

    /// MAC-4・#2270: 停止系の定数は Linux の ABI の値（x86_64・aarch64）。
    #[test]
    fn mac4_2270_shutdown_constants() {
        assert_eq!(SIGKILL, 9);
        assert_eq!(SIGTERM, 15);
        assert_eq!(SIGCHLD, 17);
        assert_eq!(SIGPWR, 30);
        assert_eq!(SIG_BLOCK, 0);
        assert_eq!(RB_POWER_OFF, 0x4321_fedc);
        assert_eq!(EAGAIN, 11);
        assert_eq!(ESRCH, 3);
        assert_eq!(core::mem::size_of::<SigSet>(), 128);
        assert_eq!(core::mem::size_of::<Timespec>(), 16);
    }

    #[test]
    fn mac4_2270_sigset_add_sets_the_right_bits() {
        let mut s = SigSet::empty();
        s.add(SIGCHLD);
        s.add(SIGTERM);
        s.add(SIGPWR);
        // シグナル n はビット (n - 1)。
        assert_eq!(s.0[0], (1u64 << 16) | (1u64 << 14) | (1u64 << 29));
        assert!(s.0[1..].iter().all(|w| *w == 0));
        // 範囲外は無視する。
        s.add(0);
        s.add(65);
        s.add(-3);
        assert_eq!(s.0[0].count_ones(), 3);
    }

    #[test]
    fn mac4_2270_classify_signal() {
        assert_eq!(classify_signal(SIGCHLD), SignalWait::Child);
        assert_eq!(classify_signal(SIGTERM), SignalWait::Stop);
        assert_eq!(classify_signal(SIGPWR), SignalWait::Stop);
        assert_eq!(classify_signal(10), SignalWait::Other(10));
    }

    /// MAC-4・SEC-1・#2270: PID 1 でなければホストを巻き込む syscall を呼ばない（試験プロセスは PID 1 でない）。
    #[test]
    fn mac4_2270_destructive_calls_refuse_when_not_pid1() {
        assert_ne!(std::process::id(), 1);
        for how in [Escalation::Term, Escalation::Kill] {
            let e = signal_all_others(how).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(EPERM), "{how:?}");
        }
        assert_eq!(power_off().raw_os_error(), Some(EPERM));
        assert!(!others_alive());
    }

    /// MAC-4・#2270: ブロック済みのシグナルを `sigtimedwait` で受ける。マスクは呼び出したスレッドだけに効き
    /// （libtest は試験ごとにスレッドを作る）、`raise` はそのスレッド宛てなので、他のスレッドや試験へ届かない。
    /// 本物の PID 1 でなくても、ブロックして受ける経路そのものは同じ。
    #[test]
    fn mac4_2270_wait_signal_receives_blocked_signals_and_times_out() {
        use std::time::Duration;
        block_lifecycle_signals().unwrap();
        let short = Duration::from_millis(30);
        assert_eq!(wait_signal(short), SignalWait::Timeout);
        for (sig, want) in [
            (libc::SIGPWR, SignalWait::Stop),
            (libc::SIGTERM, SignalWait::Stop),
            (libc::SIGCHLD, SignalWait::Child),
        ] {
            // SAFETY: `raise` は呼び出したスレッド自身へシグナルを送る。当該シグナルは直前にこのスレッドで
            // ブロック済みなので、既定動作（終了）は起きず保留される。
            assert_eq!(unsafe { libc::raise(sig) }, 0);
            assert_eq!(wait_signal(Duration::from_secs(5)), want, "signal {sig}");
        }
        // 受け取った後は保留が残らない。
        assert_eq!(wait_signal(short), SignalWait::Timeout);
    }

    #[test]
    fn mac1_mount_rejects_nul_with_einval() {
        let root = open_root_dir().unwrap();
        let e = mount_virtiofs_at("a\0b", root.as_fd(), false).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(22));
    }

    #[test]
    fn mac1_2268_mount_at_fails_without_effect_when_unprivileged() {
        // 一時ディレクトリの fd への virtiofs mount は、非特権なら失敗し何も mount されない
        // （root の環境では tag が存在せず ENODEV 等で失敗する）。
        let dir = std::env::temp_dir();
        let f = std::fs::File::open(&dir).unwrap();
        let e = mount_virtiofs_at("fandhe-no-such-tag", f.as_fd(), true).unwrap_err();
        assert!(e.raw_os_error().is_some_and(|n| n > 0));
    }

    #[test]
    fn mac1_mount_of_unknown_fs_fails_without_effect() {
        // 存在しない fstype・target への mount は権限の有無に関わらず失敗し、何も mount されない。
        let e = mount_raw(
            "x",
            Path::new("/nonexistent-fandhe-guest-init"),
            "nosuchfs",
            0,
            None,
        )
        .unwrap_err();
        assert!(e.raw_os_error().is_some_and(|n| n > 0));
    }

    #[test]
    fn mac1_mount_proc_to_missing_target_fails() {
        let e = mount_proc(Path::new("/nonexistent-fandhe-guest-init")).unwrap_err();
        assert!(e.raw_os_error().is_some_and(|n| n > 0));
    }
}
