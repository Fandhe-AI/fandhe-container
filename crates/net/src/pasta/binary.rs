//! pasta のバイナリの探索と検証（絶対パス・所有者・権限・版数。NET-9・PLUG-11・ERR-1・REPAIR-5・SEC-1）。
//!
//! rootless のユーザー定義ネットワークは pasta を別プロセスとして exec する（`docs/design/rootless-network.md`
//! 12.4・12.5・12.9・12.12）。実行するバイナリを信頼できるものに限るため、検証を通った値だけを表す型
//! [`PastaBinary`] を作る。フィールドは非公開で、検証関数を通さずに作る経路は無い（REPAIR-2）。
//!
//! - 呼び出し元: cli（作成時に検証し、識別と版の日付を FCOPT1 へ記録。12.14）、supervisor（起動時に同じ関数で
//!   再検証。#1940）、#1938（起動。[`PastaBinary::path`] を exec に使う）。
//! - 検証の基準は plugin の信頼検証（PLUG-11。`crates/core/src/plugin_trust.rs`）と同じ: `/` から全要素を fd 相対
//!   （`O_PATH | O_NOFOLLOW`）で辿り、バイナリと全祖先の所有者を root か実効 UID に、`mode & 0o022 == 0`
//!   （sticky でも例外にしない）に限る。判定は開いた fd への `fstat` で行い、パスを再 stat しない。net は core に
//!   依存しないため同じ基準をここに持つ。祖先に symlink があれば拒否する（merged-usr の `/bin/pasta` は拒否され、
//!   利用者は `/usr/bin/pasta` を指定する）。最終要素の symlink は実体まで検証し、exec には実体の正規パスを使う。
//! - 版は `--version` を子として実行して確かめる（環境を引き継がない・stdin null・stdout 4 KiB 上限・期限 2 秒）。
//!   版を確かめた後に識別を取り直して一致を確認し、確かめた実体と記録する識別を結びつける。
//! - エラーは固定の英文だけ（`MSG_*`）で、パス・子の出力・入力値を含めない。`PermissionDenied` は改ざんの可能性で、
//!   SEC-4 の監査への記録は呼び出し側（cli・supervisor）の責務（net に記録先は無い）。
//! - 残余: 検証から起動時の再検証までの間に root か実効 UID 本人が差し替えることは防がない（信頼の範囲内）。
//!   最終要素の symlink の中間ホップが置かれたディレクトリは検証しない（exec は実体のパスで行う）。
//!   グループ経由でだけ実行できるバイナリは拒否する（fail-closed）。
//! - Linux 以外では型を作れない（`Unimplemented`。CLI-1）。

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::version::PastaVersionDate;
use crate::error::{NetError, NetErrorCode};

/// pasta を起動するときの `argv[0]`（常にこの値。12.4）。
pub const PASTA_ARGV0: &str = "pasta";
/// `--version` の期限（REPAIR-5）。
pub const PASTA_VERSION_TIMEOUT: Duration = Duration::from_secs(2);
/// `--version` の stdout の上限バイト数。
pub const PASTA_VERSION_OUTPUT_MAX: usize = 4096;
/// 指定・探索で得るパスの上限バイト数（FCOPT1 の記録の上限に合わせる。12.4）。
pub const PASTA_PATH_MAX_BYTES: usize = 3072;

/// Linux 以外では使えない。
pub const MSG_UNSUPPORTED_OS: &str = "pasta is only supported on Linux";
/// パスの形が不正（相対・`.` / `..`・非 UTF-8・制御文字）。
pub const MSG_PATH_INVALID: &str =
    "pasta path must be an absolute UTF-8 path without control characters or dot components";
/// パスが長すぎる。
pub const MSG_PATH_TOO_LONG: &str = "pasta path is too long";
/// パスの要素が無い。
pub const MSG_NOT_FOUND: &str = "pasta binary was not found";
/// `PATH` に候補が無い。
pub const MSG_NOT_IN_PATH: &str = "pasta was not found in PATH";
/// アクセス権限で辿れない。
pub const MSG_ACCESS_DENIED: &str = "pasta path could not be traversed: permission denied";
/// 所有者または書き込み権限が基準外（バイナリ・祖先）。
pub const MSG_UNTRUSTED: &str =
    "pasta binary or one of its directories has an untrusted owner or is writable by others";
/// 祖先が symlink。
pub const MSG_SYMLINK_DIR: &str = "pasta path must not traverse a symlinked directory";
/// 祖先がディレクトリでない。
pub const MSG_NOT_DIR: &str = "pasta path has a component that is not a directory";
/// 通常ファイルでない。
pub const MSG_NOT_REGULAR: &str = "pasta binary must be a regular file";
/// 実行できない。
pub const MSG_NOT_EXECUTABLE: &str = "pasta binary is not executable";
/// setuid / setgid。
pub const MSG_SETID: &str = "pasta binary must not be setuid or setgid";
/// symlink のループ・連鎖。
pub const MSG_SYMLINK_LOOP: &str = "pasta path symlink could not be resolved to a single file";
/// 検証中の差し替え。
pub const MSG_CHANGED: &str = "pasta binary changed during verification";
/// `--version` が期限内に終わらない。
pub const MSG_VERSION_TIMEOUT: &str = "pasta --version did not finish before the deadline";
/// `--version` の出力が上限を超えた。
pub const MSG_VERSION_TOO_LONG: &str = "pasta --version output exceeded the size limit";
/// 資源枯渇。
pub const MSG_RESOURCE: &str = "resource exhausted while verifying pasta";
/// 分類できない失敗。
pub const MSG_INTERNAL: &str = "internal error while verifying pasta";

fn err(code: NetErrorCode, msg: &'static str) -> NetError {
    NetError::new(code, msg)
}

/// バイナリの識別（FCOPT1 への記録と起動時の再検証での照合に使う。12.4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PastaBinaryIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
    uid: u32,
    mode: u32,
}

impl PastaBinaryIdentity {
    /// デバイス番号。
    pub fn dev(&self) -> u64 {
        self.dev
    }
    /// inode 番号。
    pub fn ino(&self) -> u64 {
        self.ino
    }
    /// サイズ（バイト）。
    pub fn size(&self) -> u64 {
        self.size
    }
    /// 更新時刻（秒, ナノ秒）。
    pub fn mtime(&self) -> (i64, i64) {
        (self.mtime_sec, self.mtime_nsec)
    }
    /// 状態変更時刻（秒, ナノ秒）。
    pub fn ctime(&self) -> (i64, i64) {
        (self.ctime_sec, self.ctime_nsec)
    }
    /// 所有者 UID。
    pub fn uid(&self) -> u32 {
        self.uid
    }
    /// 権限ビット（種別ビットを除く `0o7777`）。
    pub fn mode(&self) -> u32 {
        self.mode
    }
}

/// 検証を通った pasta のバイナリ（NET-9・PLUG-11）。
///
/// フィールドは非公開で、[`verify_pasta_binary`]・[`search_pasta_in_path`] を通さずに作れない。
/// fd は保持しない（起動時に同じ規則で再検証する。12.4）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PastaBinary {
    path: PathBuf,
    requested: PathBuf,
    identity: PastaBinaryIdentity,
    version: PastaVersionDate,
}

impl PastaBinary {
    /// 実体の正規パス（symlink・`..` を含まない）。exec にはこれを使い、FCOPT1 にもこれを記録する。
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// 指定・探索で得たパス（表示用。exec に使わない）。
    pub fn requested_path(&self) -> &Path {
        &self.requested
    }
    /// 検証時点の識別。
    pub fn identity(&self) -> &PastaBinaryIdentity {
        &self.identity
    }
    /// `--version` から得た版の日付。
    pub fn version(&self) -> PastaVersionDate {
        self.version
    }
}

/// opt-in の `PATH` 探索で採ったパスの警告（暗黙の探索結果を利用者に見せる。12.5）。
///
/// stderr への 1 行の出力と JSON 化は呼び出し側（cli）の責務。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PastaPathSearchWarning {
    path: PathBuf,
}

impl PastaPathSearchWarning {
    /// 採ったパス。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(target_os = "linux")]
/// 所有者・権限ビットの判定（ディレクトリ用）。所有者は root か `euid`、`mode & 0o022 == 0`。
fn check_dir_owner_mode(uid: u32, mode: u32, euid: u32) -> Result<(), NetError> {
    if mode & 0o022 != 0 || (uid != 0 && uid != euid) {
        return Err(err(NetErrorCode::PermissionDenied, MSG_UNTRUSTED));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
/// 所有者・権限ビットの判定（バイナリ用。PLUG-11 と同じ基準に実行可能性と setuid / setgid の拒否を加える）。
///
/// 実行可能性は fstat だけで見る: 所有者の x ビットがあり、所有者が `euid` でないときは other の x ビットも要る。
fn check_owner_mode_exec(uid: u32, mode: u32, euid: u32) -> Result<(), NetError> {
    let mode = mode & 0o7777;
    check_dir_owner_mode(uid, mode, euid)?;
    if mode & 0o6000 != 0 {
        return Err(err(NetErrorCode::FailedPrecondition, MSG_SETID));
    }
    let exec_ok = mode & 0o100 != 0 && (uid == euid || mode & 0o001 != 0);
    if !exec_ok {
        return Err(err(NetErrorCode::FailedPrecondition, MSG_NOT_EXECUTABLE));
    }
    Ok(())
}

/// pasta のバイナリを検証する（NET-9・PLUG-11）。
///
/// `path` は絶対パスのみ。検証を通ったときだけ [`PastaBinary`] を返す。副作用は `--version` の子の実行だけ。
/// Linux 以外では `Unimplemented`。
pub fn verify_pasta_binary(path: &Path) -> Result<PastaBinary, NetError> {
    imp::verify(path, None)
}

/// opt-in の `PATH` 探索（12.5）。`path_env` は `PATH` の値（呼び出し側が `std::env::var_os("PATH")` を渡す）。
///
/// 空の要素と相対の要素は飛ばし、最初の候補に [`verify_pasta_binary`] と同じ検証を課す。検証に落ちたら
/// 後ろの候補へ進まずその失敗を返す。採ったパスは警告として返す。
pub fn search_pasta_in_path(
    path_env: Option<&std::ffi::OsStr>,
) -> Result<(PastaBinary, PastaPathSearchWarning), NetError> {
    imp::search(path_env, None)
}

/// 試験専用: `anchor` より上は種別と symlink の確認だけにし、`anchor` より下を厳密に検証する。
///
/// `/tmp` が 1777 のため、一時ディレクトリの下の正の試験は祖先の検査で必ず落ちる。本番の入口ではない
/// （feature `pasta-test-support` はリリースビルドで有効にできない。lib.rs）。
#[cfg(any(test, feature = "pasta-test-support"))]
pub fn verify_pasta_binary_below(anchor: &Path, path: &Path) -> Result<PastaBinary, NetError> {
    imp::verify(path, Some(anchor))
}

/// 試験専用: [`search_pasta_in_path`] の `anchor` 版（[`verify_pasta_binary_below`] と同じ緩和）。
#[cfg(any(test, feature = "pasta-test-support"))]
pub fn search_pasta_in_path_below(
    anchor: &Path,
    path_env: Option<&std::ffi::OsStr>,
) -> Result<(PastaBinary, PastaPathSearchWarning), NetError> {
    imp::search(path_env, Some(anchor))
}

/// パスの形の検査（相対・`.` / `..`・非 UTF-8・制御文字・長さ）。入口と readlink の結果の両方に課す。
///
/// OS 非依存（FCOPT1 の記録 [`super::record`] の復号も同じ規則を課す。二重に書かない）。
pub(super) fn check_shape(path: &Path) -> Result<(), NetError> {
    if path.as_os_str().len() > PASTA_PATH_MAX_BYTES {
        return Err(err(NetErrorCode::InvalidArgument, MSG_PATH_TOO_LONG));
    }
    let s = path
        .to_str()
        .ok_or_else(|| err(NetErrorCode::InvalidArgument, MSG_PATH_INVALID))?;
    let dot = s.split('/').skip(1).any(|c| c == "." || c == "..");
    if !s.starts_with('/') || s.chars().any(char::is_control) || dot {
        return Err(err(NetErrorCode::InvalidArgument, MSG_PATH_INVALID));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub(super) fn verify(_path: &Path, _anchor: Option<&Path>) -> Result<PastaBinary, NetError> {
        Err(err(NetErrorCode::Unimplemented, MSG_UNSUPPORTED_OS))
    }

    pub(super) fn search(
        _path_env: Option<&std::ffi::OsStr>,
        _anchor: Option<&Path>,
    ) -> Result<(PastaBinary, PastaPathSearchWarning), NetError> {
        Err(err(NetErrorCode::Unimplemented, MSG_UNSUPPORTED_OS))
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use crate::pasta::version::parse_version_output;
    use crate::sys::{self, Deadline, Readiness, SysError};
    use std::ffi::{CString, OsStr};
    use std::fs::{File, Metadata};
    use std::io::Read as _;
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::process::CommandExt as _;
    use std::path::Component;
    use std::process::{Child, Command, Stdio};

    fn map_sys(e: SysError) -> NetError {
        match e {
            SysError::Os(x) if x == sys::ENOENT => err(NetErrorCode::NotFound, MSG_NOT_FOUND),
            SysError::Os(x) if x == sys::EACCES || x == sys::EPERM => {
                err(NetErrorCode::PermissionDenied, MSG_ACCESS_DENIED)
            }
            SysError::Os(x) if x == sys::EMFILE || x == sys::ENFILE || x == sys::ENOMEM => {
                err(NetErrorCode::ResourceExhausted, MSG_RESOURCE)
            }
            SysError::Os(x) if x == sys::ELOOP => {
                err(NetErrorCode::FailedPrecondition, MSG_SYMLINK_LOOP)
            }
            _ => err(NetErrorCode::Internal, MSG_INTERNAL),
        }
    }

    fn fstat(fd: &OwnedFd) -> Result<Metadata, NetError> {
        fd.try_clone()
            .and_then(|c| File::from(c).metadata())
            .map_err(|_| err(NetErrorCode::Internal, MSG_INTERNAL))
    }

    struct Verified {
        meta: Metadata,
        canonical: PathBuf,
    }

    fn identity_of(m: &Metadata) -> PastaBinaryIdentity {
        PastaBinaryIdentity {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mtime_sec: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
            ctime_sec: m.ctime(),
            ctime_nsec: m.ctime_nsec(),
            uid: m.uid(),
            mode: m.mode() & 0o7777,
        }
    }

    /// `allow_symlink` が真のとき、最終要素が symlink なら実体を固定して実体のパスを再検証する（1 回だけ）。
    fn verify_path(
        path: &Path,
        anchor: Option<&Path>,
        euid: u32,
        allow_symlink: bool,
    ) -> Result<Verified, NetError> {
        check_shape(path)?;
        let comps: Vec<&OsStr> = path
            .components()
            .skip(1)
            .map(|c| match c {
                Component::Normal(s) => Ok(s),
                _ => Err(err(NetErrorCode::InvalidArgument, MSG_PATH_INVALID)),
            })
            .collect::<Result<_, _>>()?;
        let Some((last, dirs)) = comps.split_last() else {
            return Err(err(NetErrorCode::InvalidArgument, MSG_PATH_INVALID));
        };
        // anchor より上（anchor 自身を含む）は種別と symlink の確認だけにする（試験専用）。
        let anchor_len = anchor.map(|a| a.components().count().saturating_sub(1));
        let relaxed = |traversed: usize| anchor_len.is_some_and(|n| traversed <= n);

        let mut cur = sys::open_root_dir().map_err(map_sys)?;
        let meta = fstat(&cur)?;
        if !meta.is_dir() {
            return Err(err(NetErrorCode::FailedPrecondition, MSG_NOT_DIR));
        }
        if !relaxed(0) {
            check_dir_owner_mode(meta.uid(), meta.mode(), euid)?;
        }
        for (i, name) in dirs.iter().enumerate() {
            let c = CString::new(name.as_bytes())
                .map_err(|_| err(NetErrorCode::InvalidArgument, MSG_PATH_INVALID))?;
            let next = match sys::open_dir_path_nofollow_at(cur.as_fd(), &c) {
                Ok(fd) => fd,
                Err(SysError::Os(x)) if x == sys::ELOOP || x == sys::ENOTDIR => {
                    // 祖先が symlink か、ディレクトリでないかを区別する。
                    let probe = sys::open_path_nofollow_at(cur.as_fd(), &c).map_err(map_sys)?;
                    let kind = fstat(&probe)?;
                    return Err(if kind.file_type().is_symlink() {
                        err(NetErrorCode::FailedPrecondition, MSG_SYMLINK_DIR)
                    } else {
                        err(NetErrorCode::FailedPrecondition, MSG_NOT_DIR)
                    });
                }
                Err(e) => return Err(map_sys(e)),
            };
            let m = fstat(&next)?;
            if !m.is_dir() {
                return Err(err(NetErrorCode::FailedPrecondition, MSG_NOT_DIR));
            }
            if !relaxed(i + 1) {
                check_dir_owner_mode(m.uid(), m.mode(), euid)?;
            }
            cur = next;
        }

        let lc = CString::new(last.as_bytes())
            .map_err(|_| err(NetErrorCode::InvalidArgument, MSG_PATH_INVALID))?;
        let fd = sys::open_path_nofollow_at(cur.as_fd(), &lc).map_err(map_sys)?;
        let meta = fstat(&fd)?;
        if meta.file_type().is_symlink() {
            if !allow_symlink {
                return Err(err(NetErrorCode::FailedPrecondition, MSG_SYMLINK_LOOP));
            }
            let followed = sys::open_path_follow_at(cur.as_fd(), &lc).map_err(map_sys)?;
            let fm = fstat(&followed)?;
            let link = format!(
                "/proc/thread-self/fd/{}",
                std::os::fd::AsRawFd::as_raw_fd(&followed)
            );
            let canonical =
                std::fs::read_link(link).map_err(|_| err(NetErrorCode::Internal, MSG_INTERNAL))?;
            let sub_anchor = anchor.filter(|a| canonical.starts_with(a));
            let v = verify_path(&canonical, sub_anchor, euid, false)?;
            if (v.meta.dev(), v.meta.ino()) != (fm.dev(), fm.ino()) {
                return Err(err(NetErrorCode::FailedPrecondition, MSG_CHANGED));
            }
            return Ok(v);
        }
        if !meta.is_file() {
            return Err(err(NetErrorCode::FailedPrecondition, MSG_NOT_REGULAR));
        }
        check_owner_mode_exec(meta.uid(), meta.mode(), euid)?;
        Ok(Verified {
            meta,
            canonical: path.to_path_buf(),
        })
    }

    pub(super) fn verify(path: &Path, anchor: Option<&Path>) -> Result<PastaBinary, NetError> {
        check_shape(path)?;
        if let Some(a) = anchor
            && !path.starts_with(a)
        {
            return Err(err(NetErrorCode::InvalidArgument, MSG_PATH_INVALID));
        }
        let euid = sys::effective_uid();
        let first = verify_path(path, anchor, euid, true)?;
        let version = run_version(&first.canonical)?;
        // 版を確かめた実体と記録する識別を結びつける: 取り直して一致しなければ差し替えとみなす。
        let again = verify_path(
            &first.canonical,
            anchor.filter(|a| first.canonical.starts_with(a)),
            euid,
            false,
        )?;
        let id = identity_of(&first.meta);
        if identity_of(&again.meta) != id {
            return Err(err(NetErrorCode::FailedPrecondition, MSG_CHANGED));
        }
        Ok(PastaBinary {
            path: first.canonical,
            requested: path.to_path_buf(),
            identity: id,
            version,
        })
    }

    pub(super) fn search(
        path_env: Option<&OsStr>,
        anchor: Option<&Path>,
    ) -> Result<(PastaBinary, PastaPathSearchWarning), NetError> {
        let not_in_path = || err(NetErrorCode::NotFound, MSG_NOT_IN_PATH);
        let env = path_env.filter(|e| !e.is_empty()).ok_or_else(not_in_path)?;
        for dir in std::env::split_paths(env) {
            if dir.as_os_str().is_empty() || !dir.is_absolute() {
                continue;
            }
            let cand = dir.join(PASTA_ARGV0);
            // 候補の選定だけに使う。判定は verify の fd 相対の検証で行う。
            match std::fs::symlink_metadata(&cand) {
                Ok(_) => {
                    let bin = verify(&cand, anchor)?;
                    return Ok((bin, PastaPathSearchWarning { path: cand }));
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) => {}
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    return Err(err(NetErrorCode::PermissionDenied, MSG_ACCESS_DENIED));
                }
                Err(_) => return Err(err(NetErrorCode::Internal, MSG_INTERNAL)),
            }
        }
        Err(not_in_path())
    }

    fn spawn_error(e: &std::io::Error) -> NetError {
        match e.kind() {
            std::io::ErrorKind::NotFound => err(NetErrorCode::NotFound, MSG_NOT_FOUND),
            _ => match e.raw_os_error() {
                Some(x) if x == sys::EMFILE || x == sys::ENFILE || x == sys::ENOMEM => {
                    err(NetErrorCode::ResourceExhausted, MSG_RESOURCE)
                }
                _ => err(NetErrorCode::FailedPrecondition, MSG_NOT_EXECUTABLE),
            },
        }
    }

    /// `--version` の stdout を上限と期限つきで集め、終了を期限内に待つ。
    fn collect(
        child: &mut Child,
        file: &mut File,
        deadline: &Deadline,
    ) -> Result<(bool, Vec<u8>), NetError> {
        let timeout = || err(NetErrorCode::Timeout, MSG_VERSION_TIMEOUT);
        let internal = || err(NetErrorCode::Internal, MSG_INTERNAL);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            match sys::wait_readable(file.as_fd(), deadline) {
                Ok(Readiness::Readable | Readiness::Exceptional) => {}
                Ok(Readiness::TimedOut) => return Err(timeout()),
                Err(_) => return Err(internal()),
            }
            match file.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
                    if buf.len() > PASTA_VERSION_OUTPUT_MAX {
                        return Err(err(NetErrorCode::FailedPrecondition, MSG_VERSION_TOO_LONG));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(internal()),
            }
        }
        loop {
            match child.try_wait() {
                Ok(Some(st)) => return Ok((st.success(), buf)),
                Ok(None) if deadline.remaining().is_zero() => return Err(timeout()),
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => return Err(internal()),
            }
        }
    }

    /// `pasta --version` を子として実行して版の日付を得る。失敗・期限切れでは子を kill して回収する。
    fn run_version(exe: &Path) -> Result<PastaVersionDate, NetError> {
        let mut child = Command::new(exe)
            .arg0(PASTA_ARGV0)
            .arg("--version")
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| spawn_error(&e))?;
        let Some(stdout) = child.stdout.take() else {
            crate::dns_helper::kill_reap_or_detach(child, Duration::from_secs(1));
            return Err(err(NetErrorCode::Internal, MSG_INTERNAL));
        };
        let mut file = File::from(OwnedFd::from(stdout));
        let deadline = Deadline::after(PASTA_VERSION_TIMEOUT);
        match collect(&mut child, &mut file, &deadline) {
            Ok((ok, out)) => parse_version_output(ok, &out),
            Err(e) => {
                crate::dns_helper::kill_reap_or_detach(child, Duration::from_secs(1));
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PLUG-11・NET-9: バイナリの所有者・権限・実行可能性の判定表（他者所有は root なしでは作れないため純関数で照合）。
    #[cfg(target_os = "linux")]
    #[test]
    fn plug11_owner_mode_exec_table() {
        let euid = 1000;
        let ok = [(0, 0o755), (euid, 0o700), (euid, 0o755), (0, 0o555)];
        for (uid, mode) in ok {
            assert!(
                check_owner_mode_exec(uid, mode, euid).is_ok(),
                "{uid} {mode:o}"
            );
        }
        let denied = [
            (euid + 1, 0o755),
            (0, 0o775),
            (0, 0o757),
            (0, 0o1777),
            (euid, 0o770),
        ];
        for (uid, mode) in denied {
            let e = check_owner_mode_exec(uid, mode, euid).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::PermissionDenied, "{uid} {mode:o}");
            assert_eq!(e.message(), MSG_UNTRUSTED);
        }
        let setid = [(0, 0o4755), (0, 0o2755), (euid, 0o6755)];
        for (uid, mode) in setid {
            let e = check_owner_mode_exec(uid, mode, euid).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::FailedPrecondition, "{uid} {mode:o}");
            assert_eq!(e.message(), MSG_SETID);
        }
        let noexec = [(0, 0o750), (0, 0o644), (euid, 0o600), (0, 0o655)];
        for (uid, mode) in noexec {
            let e = check_owner_mode_exec(uid, mode, euid).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::FailedPrecondition, "{uid} {mode:o}");
            assert_eq!(e.message(), MSG_NOT_EXECUTABLE);
        }
    }

    #[cfg(target_os = "linux")]
    /// PLUG-11: ディレクトリは sticky でも例外にしない。
    #[test]
    fn plug11_dir_owner_mode_table() {
        assert!(check_dir_owner_mode(0, 0o755, 1000).is_ok());
        assert!(check_dir_owner_mode(1000, 0o700, 1000).is_ok());
        for (uid, mode) in [(0, 0o1777), (0, 0o775), (0, 0o757), (1001, 0o755)] {
            let e = check_dir_owner_mode(uid, mode, 1000).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::PermissionDenied);
        }
    }

    /// NET-9: パスの形の拒否（InvalidArgument）。
    #[cfg(target_os = "linux")]
    #[test]
    fn net9_path_shape_rejected() {
        let long = format!("/{}", "a".repeat(PASTA_PATH_MAX_BYTES));
        let cases = [
            ("pasta", MSG_PATH_INVALID),
            ("usr/bin/pasta", MSG_PATH_INVALID),
            ("/a/./b", MSG_PATH_INVALID),
            ("/a/../b", MSG_PATH_INVALID),
            ("/a/\u{7}b", MSG_PATH_INVALID),
            ("/a/b\n", MSG_PATH_INVALID),
            (long.as_str(), MSG_PATH_TOO_LONG),
        ];
        for (p, msg) in cases {
            let e = verify_pasta_binary(Path::new(p)).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{p:?}");
            assert_eq!(e.message(), msg, "{p:?}");
        }
        use std::os::unix::ffi::OsStrExt as _;
        let e =
            verify_pasta_binary(Path::new(std::ffi::OsStr::from_bytes(b"/a/\xff"))).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    }

    /// CLI-1: Linux 以外では型を作れない。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_is_unimplemented() {
        let e = verify_pasta_binary(Path::new("/usr/bin/pasta")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::Unimplemented);
        assert_eq!(e.message(), MSG_UNSUPPORTED_OS);
    }
}
