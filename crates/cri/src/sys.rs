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
//! crates/cri には `libc` の dev-dependency が無く、自前宣言の機械照合は未導入である（crates/cri への
//! `libc` の追加はオーナー承認待ち。追跡は #3669・判断は #3290。方式は `docs/design/ffi-libc-check.md`）。
//! 承認後に同じ PR 方針で照合を足す。Linux の `peer_uid` は LP64 の x86_64 / aarch64 に限り、
//! それ以外は `Err`（fail-closed）にする。

#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
))]
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

unsafe extern "C" {
    /// 実効 uid（失敗しない）。
    safe fn geteuid() -> u32;
    /// `int dup2(int oldfd, int newfd)`。`newfd` を `oldfd` の複製に置き換える（POSIX。Linux・macOS 共通）。
    fn dup2(oldfd: i32, newfd: i32) -> i32;
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
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
// SAFETY（宣言そのものの妥当性）: libSystem の関数。`acl_t acl_get_link_np(const char *, acl_type_t)`
// （`acl_t` は不透明ポインタ・`acl_type_t` は `unsigned int`）、`int acl_get_entry(acl_t, int, acl_entry_t *)`、
// `int acl_free(void *)` と同じ型幅。`libc` 0.2.189 の apple に `acl_*` の宣言が無いため libc 照合の対象外（一次情報は Apple SDK の `sys/acl.h`。core の sys/macos.rs と同じ扱い）。
unsafe extern "C" {
    fn getpeereid(fd: i32, euid: *mut u32, egid: *mut u32) -> i32;
    fn acl_get_link_np(path: *const std::ffi::c_char, acl_type: u32) -> *mut std::ffi::c_void;
    fn acl_get_entry(
        acl: *mut std::ffi::c_void,
        entry_id: i32,
        entry_p: *mut *mut std::ffi::c_void,
    ) -> i32;
    fn acl_free(obj: *mut std::ffi::c_void) -> i32;
    #[cfg(test)]
    fn acl_from_text(text: *const std::ffi::c_char) -> *mut std::ffi::c_void;
    #[cfg(test)]
    fn acl_set_file(
        path: *const std::ffi::c_char,
        acl_type: u32,
        acl: *mut std::ffi::c_void,
    ) -> i32;
}

/// `ACL_TYPE_EXTENDED`（`sys/acl.h`）。
#[cfg(target_os = "macos")]
const ACL_TYPE_EXTENDED: u32 = 0x0000_0100;
/// `ACL_FIRST_ENTRY`（`sys/acl.h`）。
#[cfg(target_os = "macos")]
const ACL_FIRST_ENTRY: i32 = 0;
/// `ENOENT`（`sys/errno.h`。`acl_get_link_np` が「ACL 無し」で返す）。
#[cfg(target_os = "macos")]
const ENOENT: i32 = 2;
/// `EINVAL`（`sys/errno.h`。`acl_get_entry` が「エントリ無し」で返す）。
#[cfg(target_os = "macos")]
const EINVAL: i32 = 22;

/// 標準入出力のうち差し替えを許す番号（stdin・stderr）。任意の fd 番号を渡せないようにする。
#[derive(Clone, Copy)]
pub(crate) enum StdSlot {
    Stdin = 0,
    Stderr = 2,
}

/// 標準入力または標準エラーを `src` の複製に置き換える（`dup2`。shim v2 のデーモンが listen socket を fork する
/// 子に持たせない・stderr を検証済みのログへ向けるために使う。SEC-4・PLUG-12・#3663）。
/// 置き換え後の fd は close-on-exec ではない。`EINTR` は数回やり直し、失敗は `Err`。
pub(crate) fn replace_std(slot: StdSlot, src: std::os::fd::BorrowedFd<'_>) -> Result<(), ()> {
    use std::os::fd::AsRawFd;
    for _ in 0..8 {
        // SAFETY: `src` は呼び出しの間生きている有効な fd で、`slot` は 0 か 2 に限られる。ポインタを渡さず、
        // 戻り値を検査する。`dup2` はプロセス全体の fd 表を書き換えるため、呼び出し元は fd 0/2 を別スレッドが使って
        // いない単一スレッドの起動段で呼ぶ（維持すべき不変条件）。
        let r = unsafe { dup2(src.as_raw_fd(), slot as i32) };
        if r >= 0 {
            return Ok(());
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(());
        }
    }
    Err(())
}

/// 呼び出しプロセスの実効 uid。
pub(crate) fn effective_uid() -> u32 {
    geteuid()
}

/// `struct ucred`（12 バイト）。`SO_PEERCRED` の結果。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[repr(C)]
struct Ucred {
    pid: i32,
    uid: u32,
    gid: u32,
}

/// 接続元の実効 uid（Linux は `SO_PEERCRED`）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
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

/// `path` に拡張 ACL が付いているかを返す（最終要素が symlink でも辿らない。macOS 限定）。
///
/// 付いていなければ `Ok(false)`。mode bits を迂回して他ユーザーへ変更権限を与えうる ACL の検出に使う
/// （PLUG-12・SEC-1。core の `state_store` の `reject_extended_acl` と同じ方式。core 側は非公開のため複製）。
/// 判定不能（NUL を含む・errno が ENOENT / EINVAL 以外）は `Err(())`で、呼び出し側は拒否する（fail-closed）。
/// Linux・Windows は mode bits と所有者で判定するため対象外（このシンボル自体を持たない）。
#[cfg(target_os = "macos")]
pub(crate) fn has_extended_acl(path: &std::path::Path) -> Result<bool, ()> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| ())?;
    // SAFETY: `c_path` は NUL 終端で、この呼び出しの間生存する。第 2 引数は定義済みの定数。
    let acl = unsafe { acl_get_link_np(c_path.as_ptr(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(ENOENT) => Ok(false),
            _ => Err(()),
        };
    }
    let mut entry: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: `acl` は直前に得た非 NULL の `acl_t`（未解放）、`entry` は有効な書き込み先。
    let rc = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &raw mut entry) };
    let errno = std::io::Error::last_os_error().raw_os_error();
    // SAFETY: `acl` は `acl_get_link_np` が返した非 NULL の `acl_t` で他に所有者がいない。ここで 1 回だけ
    // 解放し以後使わない（リーク防止）。`entry` は `acl` の内部を指すため解放後は参照しない。
    let _ = unsafe { acl_free(acl) };
    if rc == 0 {
        Ok(!entry.is_null())
    } else if errno == Some(EINVAL) {
        // 先頭エントリが無い（空の ACL）。
        Ok(false)
    } else {
        Err(())
    }
}

/// 試験専用: `path` へ「everyone に write(= ディレクトリでは add_file)・delete_child を許可」の拡張 ACL を付ける
/// （macOS 限定。`has_extended_acl` の陽性対照。CRI 層は子プロセスを起動しないため `chmod +a` を使わない。
/// PLUG-12・SEC-1・#872）。失敗は原因の errno を返す(`acl_from_text` / `acl_set_file` のどちらで失敗したかは区別しない)。
///
/// テキスト形式は Apple Libc の `posix1e/acl_translate.c`(`acl_from_text`)の解析に合わせる:
/// 1 行目 `!#acl 1`、以降 `<user|group>:<uuid>:<name>:<id>:<allow|deny>[,<flags>]:<perms>` を `:` 区切りで読む。
/// 権限は最後の `:` の後にカンマ区切りで置く(`allow` の直後に `,` で続けると flags 扱いで `EINVAL`)。
/// 権限名はディレクトリ用の `add_file` が解析表でコメントアウトされており(`write` と同じビット)、`write` と書く。
/// `libc` に `acl_*` の宣言が無いため、ここでは自前宣言の `acl_from_text` / `acl_set_file` を使う。
#[cfg(all(test, target_os = "macos"))]
pub(crate) fn set_everyone_acl_for_test(path: &std::path::Path) -> Result<(), i32> {
    use std::os::unix::ffi::OsStrExt;
    let errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| EINVAL)?;
    let text = c"!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:allow:write,delete_child\n";
    // SAFETY: `text` は NUL 終端の定数文字列で、呼び出しの間生存する。
    let acl = unsafe { acl_from_text(text.as_ptr()) };
    if acl.is_null() {
        return Err(errno());
    }
    // SAFETY: `c_path` は NUL 終端で生存中、`acl` は直前に得た非 NULL の `acl_t`。
    let rc = unsafe { acl_set_file(c_path.as_ptr(), ACL_TYPE_EXTENDED, acl) };
    // errno は `acl_free` で上書きされうるので、解放の前に控える。
    let set_errno = errno();
    // SAFETY: `acl` は `acl_from_text` が返した非 NULL の `acl_t` で他に所有者がいない。1 回だけ解放し以後使わない。
    let _ = unsafe { acl_free(acl) };
    if rc == 0 { Ok(()) } else { Err(set_errno) }
}

/// 対応外の unix では取得できない（呼び出し側は fail-closed にする）。
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
)))]
pub(crate) fn peer_uid(_stream: &UnixStream) -> Result<u32, ()> {
    Err(())
}
