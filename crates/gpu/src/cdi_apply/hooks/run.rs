//! `createContainer` フックの前提状態ゲートと実行（Linux 限定。TASK-127.3・GPU-2）。
//!
//! 呼び出し元は core の pre-pivot 段（配線は #2774）。検証済みフック（`validate_create_container_hooks`）と
//! `verify_hook_stage` の証跡を受け、各フックを直列に host 側プロセスとして起動する。
//! `unsafe` は `crate::sys` の fcntl ラッパー（pipe の
//! non-blocking 化）に限る。stdin / stderr はスレッド無しで回し（REPAIR-5）、実行ファイルは所有者と祖先経路を
//! 検査して fd で固定し exec する。

use super::{CDI_HOOK_MAX_MOUNTINFO_BYTES, CdiCreateContainerHook, check_hook_stage_mountinfo};
use crate::cdi_apply::{CdiApplyError, CdiApplyErrorCode as Code};
use crate::sys;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::OwnedFd;
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// 報告に載せる stderr の先頭最大バイト数。
pub const CDI_HOOK_STDERR_CAP: usize = 8 * 1024;
/// stdin へ渡す state JSON の最大バイト数（pipe 容量内に収め書き込みで塞がらないため）。
const MAX_STATE_BYTES: usize = 16 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const OCI_VERSION: &str = "1.2.0";

const fn e(code: Code, message: &'static str) -> CdiApplyError {
    CdiApplyError::new(code, message)
}

/// 実行順序の前提を満たしたことの証跡。[`verify_hook_stage`] だけが発行する（構築子は非公開）。
#[derive(Debug)]
pub struct CdiHookStage {
    rootfs: PathBuf,
    /// 発行時のプロセス ID（`CLONE_NEWPID` 内の値）。別プロセスへ持ち出した証跡を拒否する（GPU-2・REPAIR-2）。
    pid: u32,
    /// 発行時の mount namespace の識別子（`/proc/thread-self/ns/mnt` のリンク先）。
    mnt_ns: String,
    /// 実行直前に実 mountinfo で再検証するか（試験用の証跡だけ false）。
    recheck_mounts: bool,
    /// 試験用: 立てると再検証が mount namespace の不一致で失敗する（先行フックが前提を壊した場面の模擬）。
    #[cfg(test)]
    poisoned: std::sync::atomic::AtomicBool,
}

impl CdiHookStage {
    /// 検証した rootfs。
    pub fn rootfs(&self) -> &Path {
        &self.rootfs
    }

    #[cfg(test)]
    pub(crate) fn for_test(rootfs: &Path) -> Self {
        Self {
            rootfs: rootfs.to_path_buf(),
            pid: std::process::id(),
            mnt_ns: current_mnt_ns().unwrap_or_default(),
            recheck_mounts: false,
            poisoned: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// 実行直前の再検証。作成元のプロセス・mount namespace に結び付き、前提状態が今も成り立つことを確かめる。
    fn recheck(&self) -> Result<(), CdiApplyError> {
        if self.pid != std::process::id() {
            return Err(e(
                Code::FailedPrecondition,
                "hook stage was issued by another process",
            ));
        }
        #[cfg(test)]
        if self.poisoned.load(Ordering::SeqCst) {
            return Err(e(
                Code::FailedPrecondition,
                "hook stage was issued in another mount namespace",
            ));
        }
        if current_mnt_ns()? != self.mnt_ns {
            return Err(e(
                Code::FailedPrecondition,
                "hook stage was issued in another mount namespace",
            ));
        }
        if self.recheck_mounts {
            let again = verify_hook_stage(&self.rootfs)?;
            if again.mnt_ns != self.mnt_ns {
                return Err(e(
                    Code::FailedPrecondition,
                    "mount namespace changed during hook stage check",
                ));
            }
        }
        Ok(())
    }
}

fn current_mnt_ns() -> Result<String, CdiApplyError> {
    // `unshare(CLONE_NEWNS)` は呼び出しスレッドだけを移すため、スレッドグループ代表の `/proc/self` ではなく
    // 呼び出しスレッドの `/proc/thread-self` を読む（core の thread_ns_link と同じ方式。GPU-2・SEC-1）。
    fs::read_link("/proc/thread-self/ns/mnt")
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .ok_or_else(|| e(Code::Internal, "failed to read mount namespace id"))
}

/// 実際の `/proc/thread-self/mountinfo` と `/` で前提（自己 bind 済み・proc 済み・pivot 前）を検証し、証跡を返す。
/// 逸脱時は `FailedPrecondition`（GPU-2）。
pub fn verify_hook_stage(rootfs: &Path) -> Result<CdiHookStage, CdiApplyError> {
    let canon = fs::canonicalize(rootfs).map_err(|_| {
        e(
            Code::InvalidArgument,
            "rootfs must be an existing absolute path",
        )
    })?;
    if !rootfs.is_absolute() || canon != rootfs {
        return Err(e(
            Code::InvalidArgument,
            "rootfs must be a canonical absolute path",
        ));
    }
    let (Ok(r), Ok(host)) = (fs::metadata(&canon), fs::metadata("/")) else {
        return Err(e(Code::Internal, "failed to stat rootfs"));
    };
    if (r.dev(), r.ino()) == (host.dev(), host.ino()) {
        return Err(e(
            Code::FailedPrecondition,
            "rootfs is the host root (already pivoted or not separated)",
        ));
    }
    let mut text = String::new();
    File::open("/proc/thread-self/mountinfo")
        .and_then(|f| {
            f.take(CDI_HOOK_MAX_MOUNTINFO_BYTES as u64 + 1)
                .read_to_string(&mut text)
        })
        .map_err(|_| e(Code::Internal, "failed to read mountinfo"))?;
    let root = std::str::from_utf8(canon.as_os_str().as_bytes())
        .map_err(|_| e(Code::InvalidArgument, "rootfs is not valid UTF-8"))?;
    check_hook_stage_mountinfo(root, &text)?;
    Ok(CdiHookStage {
        rootfs: canon,
        pid: std::process::id(),
        mnt_ns: current_mnt_ns()?,
        recheck_mounts: true,
        #[cfg(test)]
        poisoned: std::sync::atomic::AtomicBool::new(false),
    })
}

/// フックへ渡す OCI state の材料。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdiHookState {
    id: String,
    pid: i32,
}

impl CdiHookState {
    /// `id` は `[A-Za-z0-9_.-]` の 1〜256 バイト、`pid` は正。`CLONE_NEWPID` 内の `getpid()` は 1 になるため、
    /// 呼び出し元がホストから見た pid を与える（PoC-14 の記録）。
    pub fn new(id: &str, pid: i32) -> Result<Self, CdiApplyError> {
        let ok = !id.is_empty()
            && id.len() <= 256
            && id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'));
        if !ok || pid <= 0 {
            return Err(e(Code::InvalidArgument, "invalid hook state id or pid"));
        }
        Ok(Self {
            id: id.to_string(),
            pid,
        })
    }
}

/// 1 フックの結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CdiHookReport {
    /// 入力での添字。
    pub index: usize,
    /// 終了コード（0 のみ成功として報告に残る）。
    pub exit_code: i32,
    /// 実行時間。
    pub elapsed: Duration,
    /// stderr の先頭（最大 `CDI_HOOK_STDERR_CAP` バイト。UTF-8 は損失変換）。
    pub stderr: String,
}

/// フックの異常な終了状態。非ゼロの終了コードとシグナル終了を区別して持つ（REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CdiHookExit {
    /// 非ゼロの終了コード。
    Code(i32),
    /// シグナル番号による終了。
    Signal(i32),
}

/// フック失敗。何件目かと、診断用の stderr の先頭を持つ。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CdiHookError {
    /// 失敗したフックの添字。
    pub index: usize,
    /// 分類と固定文言。
    pub error: CdiApplyError,
    /// stderr の先頭（取れた場合）。
    pub stderr: String,
    /// 失敗までに成功したフックの報告。
    pub completed: Vec<CdiHookReport>,
    /// kill 後も回収できなかった子の pid（あれば。追跡・手動回収用。REPAIR-5）。
    pub unreaped_pid: Option<u32>,
    /// bundle（`config.json`）の後始末に失敗したか。真なら `error` は元の失敗理由のまま、作業ディレクトリに
    /// 残留が有りうる（手動回収の対象。REPAIR-4）。
    pub bundle_cleanup_failed: bool,
    /// フックが終了した場合の終了状態（非ゼロの終了コード、またはシグナル）。起動拒否・タイムアウト等では `None`。
    pub exit: Option<CdiHookExit>,
}

impl std::fmt::Display for CdiHookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hook {}: {}", self.index, self.error)
    }
}

impl std::error::Error for CdiHookError {}

/// 全フックの結果。
pub type CdiHookResult = Result<Vec<CdiHookReport>, CdiHookError>;

/// JSON 文字列リテラルとしてエスケープする（`"`・`\`・制御文字）。
fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                o.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn config_json(rootfs: &str) -> String {
    format!(
        "{{\"ociVersion\":\"{OCI_VERSION}\",\"root\":{{\"path\":{}}}}}",
        json_str(rootfs)
    )
}

fn state_json(st: &CdiHookState, bundle: &str) -> String {
    format!(
        "{{\"ociVersion\":\"{OCI_VERSION}\",\"id\":{},\"status\":\"creating\",\"pid\":{},\"bundle\":{}}}",
        json_str(&st.id),
        st.pid,
        json_str(bundle)
    )
}

static SEQ: AtomicU64 = AtomicU64::new(0);

/// bundle の作成先として検証し、ディレクトリ fd で固定した作業ディレクトリ（SEC-1・GPU-2）。
///
/// パスは `/` から 1 要素ずつ `O_NOFOLLOW` で辿り（`.` / `..` / symlink は拒否）、辿った各ディレクトリを
/// fd に対して検査する。祖先は所有者が root かこのプロセスの uid で、group / other 書き込み不可
/// （sticky 付きは可）、作成先自身は所有者が信用でき group / other 書き込み不可であること。以降の bundle の
/// 作成・書き込み・削除はこの fd 起点で行い、パスの再解決による差し替え（改名・symlink 化）を受けない。
///
/// rootless では user namespace に入ると、ホスト root 所有の祖先が overflow uid に見えて所有者検査が正規の
/// 経路まで拒否する。そのため [`open_hook_work_dir`] を namespace に入る前（[`open_hook_executables`] と
/// 同じ時点）に呼んで検証・固定し、この fd を実行側へ渡す。overflow uid を許可して検査を緩めることはしない。
#[derive(Debug)]
pub struct CdiHookWorkDir {
    fd: OwnedFd,
    /// 辿った正規のパス（hook の state に載せる表示用。操作には使わない）。
    path: PathBuf,
}

impl CdiHookWorkDir {
    fn open(path: &Path) -> Result<Self, CdiApplyError> {
        use std::path::Component;
        let denied = || {
            e(
                Code::PermissionDenied,
                "work_dir is not a trusted directory",
            )
        };
        let missing = || {
            e(
                Code::InvalidArgument,
                "work_dir must be an existing absolute path without symlinks",
            )
        };
        if !path.is_absolute() {
            return Err(e(
                Code::InvalidArgument,
                "work_dir must be an absolute path",
            ));
        }
        let me = self_uid();
        let mut names = Vec::new();
        for c in path.components() {
            match c {
                Component::RootDir => {}
                Component::Normal(n) => {
                    names.push(CString::new(n.as_bytes()).map_err(|_| missing())?)
                }
                _ => return Err(missing()),
            }
        }
        let mut cur = OwnedFd::from(File::open("/").map_err(|_| missing())?);
        let check = |fd: &OwnedFd, last: bool| -> Result<(), CdiApplyError> {
            let m = File::from(fd.try_clone().map_err(|_| denied())?)
                .metadata()
                .map_err(|_| denied())?;
            let ok = if last {
                trusted_uid(m.uid(), me) && m.mode() & 0o022 == 0
            } else {
                dir_is_safe(m.uid(), m.mode(), me)
            };
            if m.is_dir() && ok {
                Ok(())
            } else {
                Err(denied())
            }
        };
        let total = names.len();
        if total == 0 {
            check(&cur, true)?;
        } else {
            check(&cur, false)?;
        }
        for (i, name) in names.iter().enumerate() {
            cur = sys::open_dir_nofollow_at(cur.as_fd(), name).map_err(|_| missing())?;
            check(&cur, i + 1 == total)?;
        }
        Ok(Self {
            fd: cur,
            path: path.to_path_buf(),
        })
    }

    /// 試験専用: 祖先の所有者検査を行わずにディレクトリ fd だけで固定する。
    ///
    /// rootless の user namespace 内では `/` などホスト root 所有の祖先が overflow uid に見えて
    /// [`Self::open`] が正規の経路まで拒否する（検査は namespace に入る前に行う設計。上記参照）。
    /// namespace 内で bundle の削除経路だけを試験するために使い、製品コードからは呼ばない（GPU-2・SEC-1）。
    #[cfg(test)]
    fn open_unchecked_for_test(path: &Path) -> Self {
        let fd = File::open(path).expect("open test work dir");
        Self {
            fd: OwnedFd::from(fd),
            path: path.to_path_buf(),
        }
    }
}

/// フック 1 件分の最小 bundle（`config.json` のみ）。作成・削除は [`CdiHookWorkDir`] の fd 起点。全経路で削除する。
struct Bundle<'a> {
    work: &'a CdiHookWorkDir,
    name: CString,
    /// bundle ディレクトリ自身の fd（`O_PATH`）。`config.json` の作成と中身の削除はこの fd 起点で行う。
    fd: OwnedFd,
    dir: PathBuf,
    removed: bool,
}

/// 削除時に辿る最大の深さ（フックが深い木を作っても有界にする）。
const REMOVE_MAX_DEPTH: usize = 16;
/// 1 回の削除で扱う最大のエントリ数。残存した孫プロセスがエントリを作り続けても削除が終わるようにする。
const REMOVE_MAX_ENTRIES: usize = 20_000;
/// 1 回の削除の期限。
const REMOVE_DEADLINE: Duration = Duration::from_secs(3);

#[cfg(test)]
thread_local! {
    /// 試験用: 削除のエントリ数の上限を小さくする（0 は既定）。
    static TEST_REMOVE_ENTRY_LIMIT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// 削除全体で共有する期限と件数の予算（REPAIR-5）。超過は `ETIMEDOUT` 相当の失敗として返す。
struct RemoveBudget {
    deadline: Instant,
    left: usize,
}

impl RemoveBudget {
    fn new() -> Self {
        Self {
            deadline: Instant::now() + REMOVE_DEADLINE,
            left: Self::entry_limit(),
        }
    }

    fn entry_limit() -> usize {
        #[cfg(test)]
        {
            let l = TEST_REMOVE_ENTRY_LIMIT.with(std::cell::Cell::get);
            if l != 0 {
                return l;
            }
        }
        REMOVE_MAX_ENTRIES
    }

    /// 1 エントリ分を消費する。期限切れ・件数超過はエラー。
    fn charge(&mut self) -> Result<(), sys::SysError> {
        if self.left == 0 || Instant::now() >= self.deadline {
            return Err(sys::SysError::Os(110)); // ETIMEDOUT
        }
        self.left -= 1;
        Ok(())
    }
}

/// fdinfo の最大読み取りバイト数（無制限確保を避ける）。超過は切り捨てず拒否する。
/// core の `FDINFO_MAX_BYTES`・net の `MAX_FDINFO_READ` と同値（実装は依存方向のため共有しない。#3025。判断は
/// `docs/design/fdinfo-mnt-id-parsing.md`・#3140 で、一致は共有 fixture の `repair1_gpu2_fdinfo_mnt_id_shared_cases` が照合する）。
const FDINFO_MAX_BYTES: u64 = 64 * 1024;

/// fdinfo からの `mnt_id` 取得の失敗理由（core の `FdinfoMountIdError`・net と同じ区別。SEC-1・GPU-2・REPAIR-2）。
///
/// 理由はこの型で保ち、呼び出し側へは `fdinfo_error_errno` で errno に写して返す。
#[derive(Debug)]
enum FdinfoMountIdError {
    /// open・read の失敗、または UTF-8 でない本文。
    Read(std::io::Error),
    /// 本文が `FDINFO_MAX_BYTES` を超えた（切り捨てると誤った値を採りうるため拒否する）。
    TooLarge,
    /// 行頭が `mnt_id:` の行が無い。
    Missing,
    /// 行頭が `mnt_id:` の行が 2 つ以上ある（値が同じでも拒否する。fail-closed）。
    Duplicate,
    /// `mnt_id:` の値が u64 として解釈できない（空・非数値・負数・桁あふれ）。
    Invalid,
}

/// `/proc/thread-self/fdinfo/<n>` の本文から `mnt_id` を取り出す。重複・欠落・不正値は理由つきで拒否する。
fn parse_fdinfo_mnt_id(text: &str) -> Result<u64, FdinfoMountIdError> {
    let mut found = text.lines().filter_map(|l| l.strip_prefix("mnt_id:"));
    let first = found.next().ok_or(FdinfoMountIdError::Missing)?;
    if found.next().is_some() {
        return Err(FdinfoMountIdError::Duplicate);
    }
    first
        .trim()
        .parse::<u64>()
        .map_err(|_| FdinfoMountIdError::Invalid)
}

/// fdinfo を上限 + 1 バイトまで読み、上限超過は `TooLarge` として拒否する（確保量は上限 + 1 で頭打ち）。
fn read_fdinfo_bounded(r: impl Read) -> Result<String, FdinfoMountIdError> {
    let mut text = String::new();
    r.take(FDINFO_MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(FdinfoMountIdError::Read)?;
    if text.len() as u64 > FDINFO_MAX_BYTES {
        return Err(FdinfoMountIdError::TooLarge);
    }
    Ok(text)
}

/// `fd` の fdinfo を読んで `mnt_id` を理由つきの型で返す。
fn read_fd_mnt_id(fd: &OwnedFd) -> Result<u64, FdinfoMountIdError> {
    let f = File::open(format!("/proc/thread-self/fdinfo/{}", fd.as_raw_fd()))
        .map_err(FdinfoMountIdError::Read)?;
    parse_fdinfo_mnt_id(&read_fdinfo_bounded(f)?)
}

/// 失敗理由を errno に写す。`Read` は OS の errno（無ければ EIO）、それ以外は EIO。
/// 呼び出し側（`remove_children`・`Bundle::remove`）は失敗を fail-closed（配下に入らず後始末失敗）で扱い、
/// errno の値には依存しない。理由の区別は `FdinfoMountIdError` の型で保ち、errno から読み戻さない。
fn fdinfo_error_errno(err: &FdinfoMountIdError) -> sys::SysError {
    match err {
        FdinfoMountIdError::Read(e) => sys::SysError::Os(e.raw_os_error().unwrap_or(5)),
        FdinfoMountIdError::TooLarge
        | FdinfoMountIdError::Missing
        | FdinfoMountIdError::Duplicate
        | FdinfoMountIdError::Invalid => sys::SysError::Os(5),
    }
}

/// `fd` が属するマウントの ID。同一ファイルシステム内の bind mount も別の ID になるため、`st_dev` の比較では
/// 検出できない横断をこれで検出する（core の `fd_mount_id`・net と同じ判定。SEC-1・GPU-2。#3025）。
fn fd_mnt_id(fd: &OwnedFd) -> Result<u64, sys::SysError> {
    read_fd_mnt_id(fd).map_err(|e| fdinfo_error_errno(&e))
}

/// 親と子のマウント ID が同じことを要求する。違えば `EXDEV` 相当の失敗（配下は削除しない）。
fn require_same_mount(parent: u64, child: u64) -> Result<(), sys::SysError> {
    if parent == child {
        Ok(())
    } else {
        Err(sys::SysError::Os(18)) // EXDEV
    }
}

/// `fd` 直下を再帰的に消す（fd 起点。symlink は辿らず unlink する）。深さ・件数・時間に上限があり、
/// 開いたディレクトリが親と別のマウント（フックが bind mount した先）なら、中へ入らず失敗にする。
/// `mnt_id` は `fd` 自身のマウント ID。
fn remove_children(
    fd: &OwnedFd,
    mnt_id: u64,
    depth: usize,
    budget: &mut RemoveBudget,
) -> Result<(), sys::SysError> {
    let rd = fs::read_dir(format!("/proc/thread-self/fd/{}", fd.as_raw_fd()))
        .map_err(|err| sys::SysError::Os(err.raw_os_error().unwrap_or(5)))?;
    for ent in rd {
        budget.charge()?;
        let ent = ent.map_err(|err| sys::SysError::Os(err.raw_os_error().unwrap_or(5)))?;
        let name = CString::new(ent.file_name().as_bytes()).map_err(|_| sys::SysError::Os(22))?;
        let is_dir = ent.file_type().is_ok_and(|t| t.is_dir());
        if is_dir {
            if depth >= REMOVE_MAX_DEPTH {
                return Err(sys::SysError::Os(39)); // ENOTEMPTY
            }
            // `O_PATH` で開いた実体そのものについてマウント ID を確かめてから中へ入る（開く前後の差し替えを避ける）。
            let child = sys::open_dir_nofollow_at(fd.as_fd(), &name)?;
            let child_mnt = fd_mnt_id(&child)?;
            require_same_mount(mnt_id, child_mnt)?;
            remove_children(&child, child_mnt, depth + 1, budget)?;
            sys::unlink_at(fd.as_fd(), &name, true)?;
        } else {
            // マウントポイントの unlink は EBUSY で失敗し、重なった先には触れない。
            sys::unlink_at(fd.as_fd(), &name, false)?;
        }
    }
    Ok(())
}

impl<'a> Bundle<'a> {
    fn create(work: &'a CdiHookWorkDir, rootfs: &str) -> Result<Self, (CdiApplyError, bool)> {
        let err = || e(Code::Internal, "failed to prepare hook bundle");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let name = format!(
            "fandhe-cdi-hook-{}-{}-{nanos}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let cname = CString::new(name.as_bytes()).map_err(|_| (err(), false))?;
        sys::mkdir_at(work.fd.as_fd(), &cname, 0o700).map_err(|_| (err(), false))?;
        let fd = match sys::open_dir_nofollow_at(work.fd.as_fd(), &cname) {
            Ok(fd) => fd,
            Err(_) => {
                let cleanup_failed = sys::unlink_at(work.fd.as_fd(), &cname, true).is_err();
                return Err((err(), cleanup_failed));
            }
        };
        let b = Self {
            work,
            name: cname,
            fd,
            dir: work.path.join(name),
            removed: false,
        };
        let mut b = b;
        // `O_PATH` のディレクトリ fd は /proc/thread-self/fd 経由で辿れる。パスを再解決せず固定した bundle に作る。
        let written = (|| {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(sys::consts::O_NOFOLLOW)
                .open(format!(
                    "/proc/thread-self/fd/{}/config.json",
                    b.fd.as_raw_fd()
                ))?;
            f.write_all(config_json(rootfs).as_bytes())
        })();
        if written.is_err() {
            // 作りかけの bundle を消す。消せなければ呼び出し側へ伝える。
            let cleanup_failed = b.remove().is_err();
            return Err((err(), cleanup_failed));
        }
        Ok(b)
    }

    /// 削除する。成功したときだけ `removed` を立て、失敗時は `Drop` が再試行する（config.json の残留を避ける）。
    fn remove(&mut self) -> Result<(), sys::SysError> {
        // `Drop` の再試行も同じ有界の予算で行う（呼ぶたびに新しい予算）。
        let r = fd_mnt_id(&self.fd)
            .and_then(|m| remove_children(&self.fd, m, 0, &mut RemoveBudget::new()))
            .and_then(|()| sys::unlink_at(self.work.fd.as_fd(), &self.name, true));
        if r.is_ok() {
            self.removed = true;
        }
        r
    }
}

impl Drop for Bundle<'_> {
    fn drop(&mut self) {
        if !self.removed {
            let _ = self.remove();
        }
    }
}

fn map_io(err: &std::io::Error) -> CdiApplyError {
    let r = match err.kind() {
        ErrorKind::NotFound => e(Code::NotFound, "hook executable not found"),
        ErrorKind::PermissionDenied => e(Code::PermissionDenied, "hook executable not permitted"),
        _ => e(Code::Internal, "failed to start hook"),
    };
    match err.raw_os_error() {
        Some(n) => r.with_errno(n),
        None => r,
    }
}

/// 所有者として信用する uid か（root、またはこのプロセスの uid）。
fn trusted_uid(uid: u32, me: u32) -> bool {
    uid == 0 || uid == me
}

/// このプロセスの実効 uid。`/proc/self` の所有者は non-dumpable なプロセスで root になるため使わず、
/// `geteuid(2)` を使う（SEC-1・GPU-2）。
fn self_uid() -> u32 {
    sys::geteuid()
}

/// ディレクトリ 1 段の検査。所有者が信用でき、group / other の書き込み不可であること。
/// sticky 付き（`/tmp` 等）は、直下の要素が別途所有者検査を受けるため書き込み可を許す。
fn dir_is_safe(uid: u32, mode: u32, me: u32) -> bool {
    trusted_uid(uid, me) && (mode & 0o022 == 0 || mode & 0o1000 != 0)
}

/// 実行ファイルを検査して開き、検査した実体の fd を返す（A08・GPU-2）。
///
/// 通常ファイル・実行ビット・group / other 書き込み不可・所有者が root かこのプロセスの uid、
/// 祖先ディレクトリがすべて同条件、であることを要求する。検査は open 済みの fd に対して行い、
/// 呼び出し側はこの fd を `/proc/self/fd/<n>` 経由で exec してパスの再解決による差し替えを防ぐ。
/// shebang スクリプトは fd 経由の exec で解釈器が fd を開けず失敗するため拒否する（CDI フックは実行ファイル）。
fn open_trusted_executable(path: &str) -> Result<File, CdiApplyError> {
    let denied = || {
        e(
            Code::PermissionDenied,
            "hook executable is not a safe regular file",
        )
    };
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(denied());
    }
    // まず O_PATH で実体を固定する。O_PATH は中身を開かないので、デバイスならドライバの open は走らず、
    // FIFO でも塞がらない（REPAIR-5）。最終要素の symlink は辿る（update-alternatives 等）が、種別は固定した
    // fd の fstat で通常ファイルだけに絞り、下で正規化先との同一性も確かめる（SEC-1・GPU-2）。
    let pinned = OpenOptions::new()
        .read(true)
        .custom_flags(sys::consts::O_PATH)
        .open(p)
        .map_err(|err| map_io(&err))?;
    let pm = pinned.metadata().map_err(|err| map_io(&err))?;
    if !pm.is_file() {
        return Err(denied());
    }
    // 通常ファイルと確認できた同じ実体を読み取り用に開き直す。O_NOCTTY で制御端末の取得を避け、
    // O_NONBLOCK は通常ファイルでは読み書きに影響しない。
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(sys::consts::O_NOCTTY | sys::consts::O_NONBLOCK)
        .open(format!("/proc/thread-self/fd/{}", pinned.as_raw_fd()))
        .map_err(|err| map_io(&err))?;
    drop(pinned);
    let m = f.metadata().map_err(|err| map_io(&err))?;
    if (m.dev(), m.ino()) != (pm.dev(), pm.ino()) {
        return Err(denied());
    }
    let me = self_uid();
    if !m.is_file() || m.mode() & 0o111 == 0 || m.mode() & 0o022 != 0 || !trusted_uid(m.uid(), me) {
        return Err(denied());
    }
    // 開いた実体が、パスを正規化した先と同一であること（open 後の差し替えの検出）。
    let canon = fs::canonicalize(p).map_err(|err| map_io(&err))?;
    let cm = fs::metadata(&canon).map_err(|err| map_io(&err))?;
    if (cm.dev(), cm.ino()) != (m.dev(), m.ino()) {
        return Err(denied());
    }
    for dir in canon.ancestors().skip(1) {
        let dm = fs::metadata(dir).map_err(|err| map_io(&err))?;
        if !dm.is_dir() || !dir_is_safe(dm.uid(), dm.mode(), me) {
            return Err(denied());
        }
    }
    let mut magic = [0u8; 2];
    if f.read_exact(&mut magic).is_ok() && &magic == b"#!" {
        return Err(e(
            Code::PermissionDenied,
            "hook executable must not be a script",
        ));
    }
    Ok(f)
}

const REAP_GRACE: Duration = Duration::from_secs(5);
/// 1 回の `pump` で読む最大チャンク数（読み続けて期限を超えないための上限）。
const PUMP_MAX_CHUNKS: usize = 64;
/// 子の終了後の最終回収で読む最大チャンク数。これで EOF に達しなければ孫が pipe を保持しているとみなす。
const FINAL_DRAIN_CHUNKS: usize = 256;

/// 子の stdin / stderr をスレッド無しで回す入出力。pipe は non-blocking で、呼び出し側のループが
/// `pump` を呼ぶたびに進める。保持するのは stderr の先頭 `CDI_HOOK_STDERR_CAP` バイトだけ（以降は読み捨て）。
/// スレッドを持たないので、全経路で停止・回収の問題が生じない（REPAIR-5）。
struct ChildIo {
    stdin: Option<std::process::ChildStdin>,
    payload: Vec<u8>,
    written: usize,
    stderr: Option<std::process::ChildStderr>,
    buf: Vec<u8>,
}

impl ChildIo {
    fn new(child: &mut std::process::Child, payload: Vec<u8>) -> Result<Self, CdiApplyError> {
        let err = || e(Code::Internal, "failed to set hook pipes non-blocking");
        let stdin = child.stdin.take();
        let stderr = child.stderr.take();
        if let Some(s) = &stdin {
            sys::set_nonblocking(s.as_fd()).map_err(|_| err())?;
        }
        if let Some(s) = &stderr {
            sys::set_nonblocking(s.as_fd()).map_err(|_| err())?;
        }
        Ok(Self {
            stdin,
            payload,
            written: 0,
            stderr,
            buf: Vec::new(),
        })
    }

    /// 書ける分だけ state を送り、読める分だけ stderr を読む。塞がらない。
    fn pump(&mut self, max_chunks: usize) {
        if let Some(stdin) = self.stdin.as_mut() {
            let mut close = false;
            while let Some(rest) = self.payload.get(self.written..) {
                if rest.is_empty() {
                    close = true;
                    break;
                }
                match stdin.write(rest) {
                    Ok(0) => close = true,
                    Ok(n) => {
                        self.written += n;
                        continue;
                    }
                    Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                    // BrokenPipe（フックが読まずに終了）等。成否は終了コードで判定する。
                    Err(_) => close = true,
                }
                break;
            }
            if close {
                self.stdin = None;
            }
        }
        if let Some(pipe) = self.stderr.as_mut() {
            let mut chunk = [0u8; 4096];
            let mut eof = false;
            for _ in 0..max_chunks {
                match pipe.read(&mut chunk) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(n) => {
                        let room = CDI_HOOK_STDERR_CAP.saturating_sub(self.buf.len());
                        if let Some(head) = chunk.get(..n.min(room)) {
                            self.buf.extend_from_slice(head);
                        }
                    }
                    Err(err) if err.kind() == ErrorKind::Interrupted => {}
                    Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => {
                        eof = true;
                        break;
                    }
                }
            }
            if eof {
                self.stderr = None;
            }
        }
    }

    /// 子の終了後に呼ぶ最終回収。(stderr の先頭, 全 pipe が閉じたか)。閉じていなければ孫が保持している。
    fn finish(&mut self) -> (String, bool) {
        self.pump(FINAL_DRAIN_CHUNKS);
        let closed = self.stderr.is_none();
        // 子が終わった後は state を読む者がいない。stdin を閉じて残りを捨てる。
        self.stdin = None;
        (String::from_utf8_lossy(&self.buf).into_owned(), closed)
    }
}

/// 子を kill して有限の猶予内に回収する。kill の失敗も回収不能もエラー（未回収の pid は呼び出し側が保持する）。
fn kill_and_reap(child: &mut std::process::Child) -> Result<(), CdiApplyError> {
    let killed = child.kill().is_ok();
    let until = Instant::now() + REAP_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < until => std::thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                return Err(e(
                    Code::Internal,
                    "hook process could not be reaped after kill",
                ));
            }
            Err(_) => return Err(e(Code::Internal, "failed to reap hook process")),
        }
    }
    if killed {
        Ok(())
    } else {
        Err(e(Code::Internal, "failed to kill hook process"))
    }
}

/// `run_one` の失敗: (分類, stderr 先頭, 未回収の子の pid, bundle の後始末に失敗したか)。
type RunFail = (
    CdiApplyError,
    String,
    Option<u32>,
    bool,
    Option<CdiHookExit>,
);

fn rf(error: CdiApplyError, stderr: String, pid: Option<u32>) -> RunFail {
    (error, stderr, pid, false, None)
}

/// 1 フックを実行する。bundle は成功・失敗のどの経路でもここで削除し、削除の失敗は元の失敗理由を保ったまま
/// 4 番目の要素（`bundle_cleanup_failed`）に反映する（握りつぶさない。REPAIR-4・SEC-1）。
fn run_one(
    stage: &CdiHookStage,
    st: &CdiHookState,
    h: &CdiCreateContainerHook,
    work_dir: &CdiHookWorkDir,
    index: usize,
    exe: &File,
) -> Result<CdiHookReport, RunFail> {
    let bare = |x| rf(x, String::new(), None);
    // 検査した実体の fd を保持し、そのまま exec する（パスの再解決による差し替えを防ぐ）。
    // `try_clone` は F_DUPFD_CLOEXEC で fd 3 以上を返す。子の stdin / stdout / stderr（fd 0〜2）の付け替えで
    // 実行ファイルの fd が上書きされ、pipe や /dev/null を exec してしまうのを防ぐ。
    let exe = exe
        .try_clone()
        .map_err(|_| bare(e(Code::Internal, "failed to duplicate hook executable fd")))?;
    if exe.as_raw_fd() < 3 {
        return Err(bare(e(
            Code::Internal,
            "hook executable fd is not above stdio",
        )));
    }
    let rootfs = std::str::from_utf8(stage.rootfs.as_os_str().as_bytes())
        .map_err(|_| bare(e(Code::InvalidArgument, "rootfs is not valid UTF-8")))?;
    let mut bundle = Bundle::create(work_dir, rootfs)
        .map_err(|(err, cleanup_failed)| (err, String::new(), None, cleanup_failed, None))?;
    let result = run_in_bundle(h, st, index, exe, &bundle);
    let cleaned = bundle.remove().is_ok();
    match (result, cleaned) {
        (Ok(report), true) => Ok(report),
        (Ok(report), false) => Err((
            e(Code::Internal, "failed to remove hook bundle"),
            report.stderr,
            None,
            true,
            None,
        )),
        (Err((error, stderr, pid, _, exit)), cleaned) => Err((error, stderr, pid, !cleaned, exit)),
    }
}

/// 作成済みの bundle でフックを起動して終了まで回す（bundle の削除は呼び出し側）。
fn run_in_bundle(
    h: &CdiCreateContainerHook,
    st: &CdiHookState,
    index: usize,
    exe: File,
    bundle: &Bundle<'_>,
) -> Result<CdiHookReport, RunFail> {
    let bare = |x| rf(x, String::new(), None);
    let bundle_str = std::str::from_utf8(bundle.dir.as_os_str().as_bytes())
        .map_err(|_| bare(e(Code::InvalidArgument, "work_dir is not valid UTF-8")))?
        .to_string();
    let state = state_json(st, &bundle_str);
    if state.len() > MAX_STATE_BYTES {
        return Err(bare(e(Code::ResourceExhausted, "hook state is too large")));
    }

    // フックへ渡す `bundle` はパスの文字列。bundle は保持した fd 起点で作ってあるため、パスが今も同じ実体を
    // 指すこと（改名・overmount・祖先の差し替えが無いこと）を起動直前に確かめ、食い違えば起動しない。
    let held = File::from(
        bundle
            .fd
            .try_clone()
            .map_err(|_| bare(e(Code::Internal, "failed to duplicate bundle fd")))?,
    )
    .metadata()
    .map_err(|_| bare(e(Code::Internal, "failed to stat hook bundle")))?;
    match fs::metadata(&bundle.dir) {
        Ok(m) if (m.dev(), m.ino()) == (held.dev(), held.ino()) => {}
        _ => {
            return Err(bare(e(
                Code::FailedPrecondition,
                "hook bundle path no longer matches the pinned directory",
            )));
        }
    }

    let (arg0, rest) = h
        .args
        .split_first()
        .ok_or_else(|| bare(e(Code::InvalidArgument, "CDI hook args must not be empty")))?;
    // `exe` は O_CLOEXEC で、exec 時に子のパス解決が終わってから閉じる（fork 後・exec 前は有効）。
    let mut cmd = Command::new(format!("/proc/self/fd/{}", exe.as_raw_fd()));
    cmd.arg0(arg0)
        .args(rest)
        .env_clear()
        .envs(h.env.iter().map(|(k, v)| (k, v)))
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let spawned = cmd.spawn();
    drop(cmd);
    drop(exe);
    let mut child = match spawned {
        Ok(c) => c,
        Err(err) => return Err(bare(map_io(&err))),
    };
    let pid = child.id();

    // 起動後の失敗は必ず子を kill して回収してから返す。回収できなければ pid を報告する。
    let abort = |child: &mut std::process::Child, err: CdiApplyError, tail: String| -> RunFail {
        match kill_and_reap(child) {
            Ok(()) => rf(err, tail, None),
            Err(reap) => rf(reap, tail, Some(pid)),
        }
    };

    // stdin / stderr はスレッド無しの non-blocking I/O で回す。フックが読まなくても呼び出し側は塞がらず、
    // 孫が pipe を保持しても取り残すスレッドが無い（REPAIR-5）。
    let mut io = match ChildIo::new(&mut child, state.into_bytes()) {
        Ok(io) => io,
        Err(err) => return Err(abort(&mut child, err, String::new())),
    };

    let deadline = Duration::from_secs(h.timeout_secs);
    let status = loop {
        io.pump(PUMP_MAX_CHUNKS);
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {
                if started.elapsed() >= deadline {
                    let reaped = kill_and_reap(&mut child);
                    let (tail, _) = io.finish();
                    return Err(match reaped {
                        Ok(()) => rf(e(Code::Timeout, "hook timed out"), tail, None),
                        Err(err) => rf(err, tail, Some(pid)),
                    });
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => {
                let r = abort(
                    &mut child,
                    e(Code::Internal, "failed to wait for hook"),
                    String::new(),
                );
                let _ = io.finish();
                return Err(r);
            }
        }
    };
    let elapsed = started.elapsed();
    let (stderr, io_closed) = io.finish();
    if !io_closed {
        return Err(rf(
            e(
                Code::Internal,
                "hook stderr pipe is still open (a descendant holds it)",
            ),
            stderr,
            None,
        ));
    }
    match status.code() {
        Some(0) => Ok(CdiHookReport {
            index,
            exit_code: 0,
            elapsed,
            stderr,
        }),
        Some(code) => Err((
            e(Code::FailedPrecondition, "hook exited with failure"),
            stderr,
            None,
            false,
            Some(CdiHookExit::Code(code)),
        )),
        None => Err((
            e(Code::FailedPrecondition, "hook was terminated by a signal"),
            stderr,
            None,
            false,
            std::os::unix::process::ExitStatusExt::signal(&status).map(CdiHookExit::Signal),
        )),
    }
}

/// 事前に検査して開いた実行ファイルの fd 群。[`open_hook_executables`] が発行する。
///
/// rootless では user namespace の内側からはホスト root 所有のファイルが overflow uid に見え、所有者検査が
/// 正規のフックまで拒否する。namespace を作る前にホスト側の資格情報で検査して fd を保持し、その fd を
/// [`run_create_container_hooks_with_recorder`] へ渡すことで、所有者の信頼を保ったまま実行できる（GPU-2・SEC-5）。
#[derive(Debug)]
pub struct CdiHookExecutables {
    entries: Vec<CdiHookExecutable>,
}

/// 検査時のフック定義と、その `path` から開いた実行ファイルの fd の組。定義と fd を分離させず、
/// 実行時に渡されたフック定義との一致を確かめる（別集合・順序違いの受理を防ぐ。REPAIR-2・GPU-2）。
#[derive(Debug)]
struct CdiHookExecutable {
    definition: CdiCreateContainerHook,
    file: File,
}

impl CdiHookExecutables {
    /// 保持する実行ファイルの件数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 件数が 0 か。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// bundle の作成先を（呼び出したプロセスの資格情報で）検証して fd で固定する。
/// rootless では `unshare` / `clone` で user namespace に入る前に呼ぶ（GPU-2・SEC-1・SEC-5）。
pub fn open_hook_work_dir(path: &Path) -> Result<CdiHookWorkDir, CdiApplyError> {
    CdiHookWorkDir::open(path)
}

/// 各フックの実行ファイルを（呼び出したプロセスの資格情報で）検査して開く。
/// rootless では `unshare` / `clone` で user namespace に入る前に呼ぶ。失敗時はその時点のフックの添字つき。
pub fn open_hook_executables(
    hooks: &[CdiCreateContainerHook],
) -> Result<CdiHookExecutables, CdiHookError> {
    let mut entries = Vec::with_capacity(hooks.len());
    for (index, h) in hooks.iter().enumerate() {
        match open_trusted_executable(h.path()) {
            Ok(file) => entries.push(CdiHookExecutable {
                definition: h.clone(),
                file,
            }),
            Err(error) => {
                return Err(CdiHookError {
                    index,
                    error,
                    stderr: String::new(),
                    completed: Vec::new(),
                    unreaped_pid: None,
                    bundle_cleanup_failed: false,
                    exit: None,
                });
            }
        }
    }
    Ok(CdiHookExecutables { entries })
}

/// フック 1 回の試行の計測値（REPAIR-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CdiHookRunSample {
    /// フックの添字（実行前の共通ゲートの失敗は 0）。
    pub index: usize,
    /// 失敗の分類（成功なら `None`）。
    pub error_code: Option<Code>,
    /// 終了コード（フックが終了コードを返した場合。非ゼロの失敗も含む）。
    pub exit_code: Option<i32>,
    /// シグナル終了の場合のシグナル番号。
    pub signal: Option<i32>,
    /// 試行に要した時間（起動拒否・タイムアウトを含む）。
    pub latency: Duration,
}

/// [`run_create_container_hooks_with_recorder`] の計測先。成功・失敗（起動拒否・タイムアウトを含む）の
/// 全経路で、試行したフックごとに 1 回呼ぶ。
pub trait CdiHookRunRecorder {
    /// 1 回の試行を記録する。
    fn record(&self, sample: CdiHookRunSample);
}

struct NoopRecorder;

impl CdiHookRunRecorder for NoopRecorder {
    fn record(&self, _sample: CdiHookRunSample) {}
}

/// 検証済みフックを集計順に直列実行する。最初の失敗で中止し、後続は起動しない（fail-closed）。
/// `work_dir` は bundle を作る既存の絶対パスのディレクトリ（呼び出し元の一時領域。状態ルート配下を推奨）。
/// symlink を含まず、作成先は所有者が root かこのプロセスの uid で group / other 書き込み不可、祖先も同様
/// （sticky 付きは可）であること。満たさなければ実行前に拒否する（SEC-1）。
/// ホストの環境変数は継承せず、フック指定の env だけを渡す。
/// 実行ファイルはここで（呼び出しプロセスの資格情報で）検査する。rootless では
/// [`open_hook_executables`] と [`run_create_container_hooks_with_recorder`] を使う。
pub fn run_create_container_hooks(
    stage: &CdiHookStage,
    hooks: &[CdiCreateContainerHook],
    state: &CdiHookState,
    work_dir: &Path,
) -> CdiHookResult {
    let work = match CdiHookWorkDir::open(work_dir) {
        Ok(w) => w,
        Err(error) => {
            return Err(CdiHookError {
                index: 0,
                error,
                stderr: String::new(),
                completed: Vec::new(),
                unreaped_pid: None,
                bundle_cleanup_failed: false,
                exit: None,
            });
        }
    };
    run_create_container_hooks_with_recorder(stage, hooks, None, state, &work, &NoopRecorder)
}

/// `work` は [`open_hook_work_dir`] で事前に検証・固定した作成先（rootless では namespace 参加前に開く）。
/// [`run_create_container_hooks`] に計測（REPAIR-4）と事前検査済みの実行ファイル（`exes`）を付けたもの。
/// `exes` が `Some` の場合は、検査時のフック定義が `hooks` と添字ごとに完全一致している必要がある（不一致は実行前に拒否）。
pub fn run_create_container_hooks_with_recorder(
    stage: &CdiHookStage,
    hooks: &[CdiCreateContainerHook],
    exes: Option<&CdiHookExecutables>,
    state: &CdiHookState,
    work: &CdiHookWorkDir,
    recorder: &dyn CdiHookRunRecorder,
) -> CdiHookResult {
    let mut done = Vec::with_capacity(hooks.len());
    let gate_fail = |error: CdiApplyError, started: Instant| {
        recorder.record(CdiHookRunSample {
            index: 0,
            error_code: Some(error.code()),
            exit_code: None,
            signal: None,
            latency: started.elapsed(),
        });
        CdiHookError {
            index: 0,
            error,
            stderr: String::new(),
            completed: Vec::new(),
            unreaped_pid: None,
            bundle_cleanup_failed: false,
            exit: None,
        }
    };
    let gate_started = Instant::now();
    if exes.is_some_and(|x| {
        x.entries.len() != hooks.len()
            || x.entries
                .iter()
                .zip(hooks)
                .any(|(en, h)| en.definition != *h)
    }) {
        return Err(gate_fail(
            e(Code::InvalidArgument, "hook executables do not match hooks"),
            gate_started,
        ));
    }
    // 証跡を作成元のプロセス・mount namespace に結び付け、実行直前に前提状態を再検証する（GPU-2・REPAIR-2）。
    if let Err(error) = stage.recheck() {
        return Err(gate_fail(error, gate_started));
    }
    for (index, h) in hooks.iter().enumerate() {
        let started = Instant::now();
        // 先行フックが mount を変える・隠す場合があるため、前提状態を各フックの起動直前に確かめ直す。
        // 崩れていたらその添字で中断し、完了済みの報告を保つ（GPU-2・REPAIR-2）。
        if let Err(error) = stage.recheck() {
            recorder.record(CdiHookRunSample {
                index,
                error_code: Some(error.code()),
                exit_code: None,
                signal: None,
                latency: started.elapsed(),
            });
            return Err(CdiHookError {
                index,
                error,
                stderr: String::new(),
                completed: done,
                unreaped_pid: None,
                bundle_cleanup_failed: false,
                exit: None,
            });
        }
        let mut opened: Option<File> = None;
        let exe = match exes.and_then(|x| x.entries.get(index)) {
            Some(en) => Ok(&en.file),
            None => open_trusted_executable(h.path()).map(|f| &*opened.insert(f)),
        };
        let outcome = match exe {
            Ok(f) => run_one(stage, state, h, work, index, f),
            Err(err) => Err(rf(err, String::new(), None)),
        };
        match outcome {
            Ok(r) => {
                recorder.record(CdiHookRunSample {
                    index,
                    error_code: None,
                    exit_code: Some(r.exit_code),
                    signal: None,
                    latency: started.elapsed(),
                });
                done.push(r);
            }
            Err((error, stderr, unreaped_pid, bundle_cleanup_failed, exit)) => {
                recorder.record(CdiHookRunSample {
                    index,
                    error_code: Some(error.code()),
                    exit_code: match exit {
                        Some(CdiHookExit::Code(c)) => Some(c),
                        _ => None,
                    },
                    signal: match exit {
                        Some(CdiHookExit::Signal(n)) => Some(n),
                        _ => None,
                    },
                    latency: started.elapsed(),
                });
                return Err(CdiHookError {
                    index,
                    error,
                    stderr,
                    completed: done,
                    unreaped_pid,
                    bundle_cleanup_failed,
                    exit,
                });
            }
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdi_apply::hooks::validate_create_container_hooks;
    use crate::cdi_spec::{EnvList, Hook};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    /// テスト用の一時ディレクトリ（`std::env::temp_dir` 配下に一意名。終了時に削除）。
    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "fandhe-gpu-hooks-{tag}-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
        fn script(&self, name: &str, body: &str) -> String {
            let p = self.0.join(name);
            fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
            p.to_str().unwrap().to_string()
        }
        fn work(&self) -> PathBuf {
            let w = self.0.join("work");
            let _ = fs::DirBuilder::new().mode(0o700).create(&w);
            w
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mk(path: &str, args: &[&str], env: &[&str], timeout: Option<i64>) -> Hook {
        Hook {
            hook_name: "createContainer".into(),
            path: path.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: EnvList::from_entries(env.iter().map(|s| s.to_string()).collect()),
            timeout,
        }
    }

    /// `/bin/sh -c <body>` で動くフック定義を作る。`args[0]` は argv[0]（`$0`）。
    /// 書き込み直後のスクリプトを exec すると、並列の別試験の fork が書き込み fd を
    /// 持ち越す間に ETXTBSY（Text file busy）で間欠失敗するため、ファイルを作らない（REPAIR-12）。
    fn mk_sh(body: &str, args: &[&str], env: &[&str], timeout: Option<i64>) -> Hook {
        let a0 = args.first().copied().unwrap_or("h");
        let mut v: Vec<&str> = vec![a0, "-c", body, a0];
        v.extend(args.iter().skip(1).copied());
        mk("/bin/sh", &v, env, timeout)
    }

    fn state() -> CdiHookState {
        CdiHookState::new("c1", 4242).unwrap()
    }

    /// GPU-2: argv[0]・引数・stdin の state・bundle の config.json・env を具体値で照合する。
    #[test]
    fn hook_receives_argv_state_and_env() {
        let t = Tmp::new("ok");
        let out = t.0.join("out.txt");
        let body = format!(
            "echo \"$1|$2\" > {o}\ncat >> {o}\necho >> {o}\ncat \"$(sed -n 's/.*\"bundle\":\"\\([^\"]*\\)\".*/\\1/p' {o} | head -1)/config.json\" >> {o}\nenv > {e}",
            o = out.display(),
            e = t.0.join("env.txt").display()
        );
        let hooks = validate_create_container_hooks(&[mk_sh(
            &body,
            &["nvidia-cdi-hook", "create-symlinks", "--x"],
            &["FOO=bar baz"],
            Some(10),
        )])
        .unwrap();
        let rootfs = t.0.join("rootfs");
        let stage = CdiHookStage::for_test(&rootfs);
        let reports = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].exit_code, 0);
        let got = fs::read_to_string(&out).unwrap();
        let mut lines = got.lines();
        assert_eq!(lines.next(), Some("create-symlinks|--x"));
        let st_line = lines.next().unwrap();
        assert!(st_line.starts_with(
            "{\"ociVersion\":\"1.2.0\",\"id\":\"c1\",\"status\":\"creating\",\"pid\":4242,\"bundle\":\""
        ));
        assert!(got.contains(&format!(
            "{{\"ociVersion\":\"1.2.0\",\"root\":{{\"path\":\"{}\"}}}}",
            rootfs.display()
        )));
        let mut envs: Vec<String> = fs::read_to_string(t.0.join("env.txt"))
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        envs.sort();
        // ホストの環境変数（PATH 等）を継承しない。sh が足す PWD 等を除き、指定分が入っている。
        assert!(envs.contains(&"FOO=bar baz".to_string()), "{envs:?}");
        assert!(!envs.iter().any(|l| l.starts_with("PATH=")), "{envs:?}");
        assert!(!envs.iter().any(|l| l.starts_with("HOME=")), "{envs:?}");
        // bundle は全経路で消える。
        assert_eq!(fs::read_dir(t.work()).unwrap().count(), 0);
    }

    /// GPU-2: `args[0]` が argv[0] になり、引数が重複しない（stderr 経由で /proc の cmdline を観測する）。
    #[test]
    fn args0_becomes_argv0() {
        let t = Tmp::new("argv0");
        let hooks = validate_create_container_hooks(&[mk(
            "/bin/sh",
            &["custom0", "-c", "tr '\\0' '|' < /proc/$$/cmdline >&2"],
            &[],
            None,
        )])
        .unwrap();
        let stage = CdiHookStage::for_test(&t.0);
        let r = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap();
        assert_eq!(
            r[0].stderr,
            "custom0|-c|tr '\\0' '|' < /proc/$$/cmdline >&2|"
        );
    }

    /// GPU-2: 最初の失敗で中止し、後続のフックは起動しない。
    #[test]
    fn stops_at_first_failure() {
        let t = Tmp::new("fail");
        let m1 = t.0.join("m1");
        let m3 = t.0.join("m3");
        let hooks = validate_create_container_hooks(&[
            mk_sh(&format!("touch {}", m1.display()), &["h1"], &[], None),
            mk_sh("echo boom >&2; exit 1", &["h2"], &[], None),
            mk_sh(&format!("touch {}", m3.display()), &["h3"], &[], None),
        ])
        .unwrap();
        let stage = CdiHookStage::for_test(&t.0);
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        assert_eq!(err.index, 1);
        assert_eq!(err.error.code(), Code::FailedPrecondition);
        assert_eq!(err.error.message(), "hook exited with failure");
        assert_eq!(err.stderr, "boom\n");
        assert_eq!(err.completed.len(), 1);
        assert!(m1.exists());
        assert!(!m3.exists());
        assert_eq!(fs::read_dir(t.work()).unwrap().count(), 0);
    }

    /// GPU-2・REPAIR-5: timeout で kill され Timeout になり、bundle も消える。
    #[test]
    fn times_out() {
        let t = Tmp::new("to");
        let hooks =
            validate_create_container_hooks(&[mk_sh("exec sleep 30", &["slow"], &[], Some(1))])
                .unwrap();
        let stage = CdiHookStage::for_test(&t.0);
        let start = Instant::now();
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        assert_eq!(err.error.code(), Code::Timeout);
        assert!(start.elapsed() < Duration::from_secs(10));
        assert_eq!(fs::read_dir(t.work()).unwrap().count(), 0);
    }

    /// GPU-2・REPAIR-5: stdin を読まず stderr を大量に出すフックでも、保存量は上限で、期限内に戻る。
    #[test]
    fn stderr_is_capped_and_unread_stdin_does_not_block() {
        let t = Tmp::new("flood");
        let hooks = validate_create_container_hooks(&[mk_sh(
            "head -c 200000 /dev/zero | tr '\\0' x >&2; exit 3",
            &["flood"],
            &[],
            Some(5),
        )])
        .unwrap();
        let stage = CdiHookStage::for_test(&t.0);
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        assert_eq!(err.error.code(), Code::FailedPrecondition);
        assert_eq!(err.stderr.len(), CDI_HOOK_STDERR_CAP);
        assert_eq!(fs::read_dir(t.work()).unwrap().count(), 0);
    }

    /// GPU-2: 存在しない実行ファイルは NotFound、group 書き込み可は PermissionDenied。
    #[test]
    fn executable_checks() {
        let t = Tmp::new("exe");
        let stage = CdiHookStage::for_test(&t.0);
        let missing = t.0.join("nope").to_str().unwrap().to_string();
        let hooks = validate_create_container_hooks(&[mk(&missing, &["x"], &[], None)]).unwrap();
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        assert_eq!(err.error.code(), Code::NotFound);
        let sh = t.script("w.sh", "exit 0");
        fs::set_permissions(&sh, fs::Permissions::from_mode(0o775)).unwrap();
        let hooks = validate_create_container_hooks(&[mk(&sh, &["x"], &[], None)]).unwrap();
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        assert_eq!(err.error.code(), Code::PermissionDenied);
        assert_eq!(fs::read_dir(t.work()).unwrap().count(), 0);
    }

    /// GPU-2・A08: 祖先ディレクトリが group 書き込み可なら実行ファイルが安全でも拒否し、shebang は拒否する。
    #[test]
    fn untrusted_ancestor_and_script_are_rejected() {
        let t = Tmp::new("anc");
        let stage = CdiHookStage::for_test(&t.0);
        let dir = t.0.join("shared");
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let bin = dir.join("hook");
        fs::copy("/bin/true", &bin).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o770)).unwrap();
        let p = bin.to_str().unwrap();
        let hooks = validate_create_container_hooks(&[mk(p, &["x"], &[], None)]).unwrap();
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        assert_eq!(err.error.code(), Code::PermissionDenied);
        assert_eq!(
            err.error.message(),
            "hook executable is not a safe regular file"
        );
        let sh = t.script("s.sh", "exit 0");
        let hooks = validate_create_container_hooks(&[mk(&sh, &["x"], &[], None)]).unwrap();
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        assert_eq!(err.error.message(), "hook executable must not be a script");
        assert_eq!(fs::read_dir(t.work()).unwrap().count(), 0);
    }

    /// A08: 所有者・ディレクトリの判定を具体値で照合する（他 UID の所有は拒否）。
    #[test]
    fn owner_and_dir_rules() {
        assert!(trusted_uid(0, 1000));
        assert!(trusted_uid(1000, 1000));
        assert!(!trusted_uid(1001, 1000));
        assert!(dir_is_safe(0, 0o755, 1000));
        assert!(!dir_is_safe(1001, 0o755, 1000));
        assert!(!dir_is_safe(0, 0o775, 1000));
        assert!(!dir_is_safe(0, 0o757, 1000));
        assert!(dir_is_safe(0, 0o1777, 1000));
    }

    /// REPAIR-5: remove が失敗しても `removed` を立てず、Drop が再試行してバンドルを残さない。
    #[test]
    fn bundle_drop_retries_after_failed_remove() {
        let t = Tmp::new("bundle");
        let wd = CdiHookWorkDir::open(&t.work()).unwrap();
        let mut b = Bundle::create(&wd, "/r").unwrap();
        let dir = b.dir.clone();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        let failed = b.remove().is_err();
        assert_eq!(b.removed, !failed);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        drop(b);
        assert!(!dir.exists());
    }

    /// GPU-2: 前提を満たさない状態ではゲートが失敗し、フックは起動されない。
    #[test]
    fn gate_failure_never_runs_hooks() {
        let t = Tmp::new("gate");
        let marker = t.0.join("ran");
        let sh = t.script("h.sh", &format!("touch {}", marker.display()));
        let hooks = validate_create_container_hooks(&[mk(&sh, &["h"], &[], None)]).unwrap();
        let canon = fs::canonicalize(&t.0).unwrap();
        let res = verify_hook_stage(&canon).and_then(|s| {
            run_create_container_hooks(&s, &hooks, &state(), &t.work()).map_err(|x| x.error)
        });
        assert_eq!(res.unwrap_err().code(), Code::FailedPrecondition);
        assert!(!marker.exists());
        assert_eq!(
            verify_hook_stage(Path::new("/")).unwrap_err().code(),
            Code::FailedPrecondition
        );
    }

    /// GPU-2・REPAIR-2: 別プロセス・別 mount namespace で発行された証跡では実行せず、フックも起動しない。
    #[test]
    fn foreign_stage_is_rejected_before_running() {
        let t = Tmp::new("foreign");
        let marker = t.0.join("ran");
        let hooks = validate_create_container_hooks(&[mk_sh(
            &format!("touch {}", marker.display()),
            &["h"],
            &[],
            None,
        )])
        .unwrap();
        let mut stage = CdiHookStage::for_test(&t.0);
        stage.pid = stage.pid.wrapping_add(1);
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        assert_eq!(err.error.code(), Code::FailedPrecondition);
        assert_eq!(
            err.error.message(),
            "hook stage was issued by another process"
        );
        let mut stage = CdiHookStage::for_test(&t.0);
        stage.mnt_ns = "mnt:[1]".into();
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        assert_eq!(
            err.error.message(),
            "hook stage was issued in another mount namespace"
        );
        assert!(!marker.exists());
    }

    /// REPAIR-5: 孫が stderr の pipe を保持して残る場合は、成功終了でも明示的にエラーにする。
    #[test]
    fn lingering_descendant_is_reported() {
        let t = Tmp::new("linger");
        let hooks = validate_create_container_hooks(&[mk_sh(
            "sleep 3 & exit 0",
            &["linger"],
            &[],
            Some(5),
        )])
        .unwrap();
        let stage = CdiHookStage::for_test(&t.0);
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        assert_eq!(err.error.code(), Code::Internal);
        assert_eq!(
            err.error.message(),
            "hook stderr pipe is still open (a descendant holds it)"
        );
        assert_eq!(fs::read_dir(t.work()).unwrap().count(), 0);
    }

    /// JSON エスケープを具体文字列で照合する。
    #[test]
    fn json_escape() {
        assert_eq!(
            json_str("a\"b\\c\nd\u{1}"),
            "\"a\\\"b\\\\c\\u000ad\\u0001\""
        );
    }

    /// state の id・pid の検証。
    #[test]
    fn state_validation() {
        assert!(CdiHookState::new("a_b.c-1", 1).is_ok());
        for (id, pid) in [("", 1), ("a b", 1), ("a\"b", 1), ("ok", 0), ("ok", -3)] {
            assert_eq!(
                CdiHookState::new(id, pid).unwrap_err().code(),
                Code::InvalidArgument,
                "{id:?} {pid}"
            );
        }
    }

    /// REPAIR-5・GPU-2: 書き手のいない FIFO を指すパスは open で塞がらず、通常ファイルでないとして即拒否する。
    #[test]
    fn fifo_path_is_rejected_without_blocking() {
        let t = Tmp::new("fifo");
        let fifo = t.0.join("fifo");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let started = Instant::now();
        let err = open_trusted_executable(fifo.to_str().unwrap()).unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// SEC-1・GPU-2: group 書き込み可の作成先、他者書き込み可（非 sticky）の祖先、symlink の作成先と祖先は
    /// 実行前に拒否し、フックを起動せず bundle も作らない。
    #[test]
    fn untrusted_work_dir_is_rejected() {
        let t = Tmp::new("wd");
        let stage = CdiHookStage::for_test(&t.0);
        let hooks = validate_create_container_hooks(&[mk_sh("exit 0", &["x"], &[], None)]).unwrap();
        let run = |w: &Path| run_create_container_hooks(&stage, &hooks, &state(), w);

        let loose = t.0.join("loose");
        fs::DirBuilder::new().mode(0o700).create(&loose).unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            run(&loose).unwrap_err().error.code(),
            Code::PermissionDenied
        );

        let ancestor = t.0.join("anc");
        let inner = ancestor.join("inner");
        fs::DirBuilder::new().mode(0o700).create(&ancestor).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&inner).unwrap();
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            run(&inner).unwrap_err().error.code(),
            Code::PermissionDenied
        );
        assert_eq!(fs::read_dir(&inner).unwrap().count(), 0);

        let real = t.work();
        let link = t.0.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(run(&link).unwrap_err().error.code(), Code::InvalidArgument);
        assert_eq!(
            run(&link.join("work")).unwrap_err().error.code(),
            Code::InvalidArgument
        );
        assert_eq!(
            run(&t.0.join("work/../work")).unwrap_err().error.code(),
            Code::InvalidArgument
        );
        assert_eq!(
            run(Path::new("relative")).unwrap_err().error.message(),
            "work_dir must be an absolute path"
        );
        assert_eq!(fs::read_dir(&real).unwrap().count(), 0);
    }

    /// SEC-1・GPU-2: 作成した bundle は固定した fd 起点で書かれ、作成後に作業ディレクトリのパスを別の場所へ
    /// 差し替えても、元の bundle の削除は固定した実体に対して行われる。
    #[test]
    fn bundle_is_pinned_to_work_dir_fd() {
        let t = Tmp::new("pin");
        let wd = CdiHookWorkDir::open(&t.work()).unwrap();
        let mut b = Bundle::create(&wd, "/r").unwrap();
        let moved = t.0.join("moved");
        fs::rename(t.work(), &moved).unwrap();
        let decoy = t.work();
        assert_eq!(fs::read_dir(&decoy).unwrap().count(), 0);
        b.remove().unwrap();
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 0);
    }

    /// REPAIR-2・GPU-2: 事前検査済みの fd は検査時のフック定義と一体で、別集合・順序違いの定義へは使えない。
    #[test]
    fn executables_must_match_hook_definitions() {
        let t = Tmp::new("bind");
        let stage = CdiHookStage::for_test(&t.0);
        let a = validate_create_container_hooks(&[
            mk("/bin/true", &["t"], &[], None),
            mk("/bin/false", &["f"], &[], None),
        ])
        .unwrap();
        let exes = open_hook_executables(&a).unwrap();
        let run = |hooks: &[CdiCreateContainerHook]| {
            run_create_container_hooks_with_recorder(
                &stage,
                hooks,
                Some(&exes),
                &state(),
                &open_hook_work_dir(&t.work()).unwrap(),
                &NoopRecorder,
            )
        };
        let swapped: Vec<_> = a.iter().rev().cloned().collect();
        let err = run(&swapped).unwrap_err();
        assert_eq!(err.error.code(), Code::InvalidArgument);
        assert_eq!(err.error.message(), "hook executables do not match hooks");
        let other = validate_create_container_hooks(&[
            mk("/bin/true", &["t"], &[], None),
            mk("/bin/true", &["f"], &[], None),
        ])
        .unwrap();
        assert_eq!(run(&other).unwrap_err().error.code(), Code::InvalidArgument);
        let err = run(&a).unwrap_err();
        assert_eq!(err.index, 1);
        assert_eq!(err.error.code(), Code::FailedPrecondition);
        assert_eq!(fs::read_dir(t.work()).unwrap().count(), 0);
    }

    /// SEC-1・GPU-2: デバイスノードを指すパスは読み取り用に開かず（O_PATH で固定して種別を見る）拒否する。
    #[test]
    fn device_path_is_rejected() {
        for dev in ["/dev/null", "/dev/zero", "/dev/tty"] {
            if Path::new(dev).exists() {
                let err = open_trusted_executable(dev).unwrap_err();
                assert_eq!(err.code(), Code::PermissionDenied, "{dev}");
            }
        }
    }

    /// GPU-2・SEC-1: namespace 識別子は呼び出しスレッドのもの（`/proc/thread-self`）で、別 namespace の証跡は
    /// 再検証で拒否される。
    #[test]
    fn stage_is_bound_to_thread_mount_namespace() {
        let t = Tmp::new("thns");
        let own = CdiHookStage::for_test(&t.0);
        own.recheck().unwrap();
        let mut foreign = CdiHookStage::for_test(&t.0);
        foreign.mnt_ns = "mnt:[1]".to_string();
        let err = foreign.recheck().unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(
            err.message(),
            "hook stage was issued in another mount namespace"
        );
        // 別スレッドでは `/proc/thread-self` がそのスレッドの task を指す。
        let tid_link = std::thread::spawn(|| fs::read_link("/proc/thread-self").unwrap())
            .join()
            .unwrap();
        let main_link = fs::read_link("/proc/thread-self").unwrap();
        assert_ne!(tid_link, main_link);
    }

    /// GPU-2・SEC-1: 呼び出しスレッドだけ `unshare(CLONE_NEWNS)` すると、移す前に発行した証跡の再検証は
    /// そのスレッドで通らず、元のスレッドでは通る。
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN (e.g. `unshare -rm`) for unshare(CLONE_NEWNS)"]
    fn stage_recheck_fails_after_unshare_in_thread() {
        let t = Tmp::new("unsh");
        let stage = CdiHookStage::for_test(&t.0);
        std::thread::scope(|sc| {
            sc.spawn(|| {
                stage.recheck().unwrap();
                sys::unshare_mount_ns().unwrap();
                let err = stage.recheck().unwrap_err();
                assert_eq!(err.code(), Code::FailedPrecondition);
                println!("stage_recheck_fails_after_unshare_in_thread: ok");
            })
            .join()
            .unwrap();
        });
        stage.recheck().unwrap();
    }

    /// フックが bundle 内に消せない木（中身ありの 0500 ディレクトリ）を作る sh の前置き。
    const STICKY_BUNDLE: &str = r#"IFS= read -r s; b=${s#*\"bundle\":\"}; b=${b%%\"*}; mkdir "$b/d"; : > "$b/d/f"; chmod 500 "$b/d"; "#;

    /// 作った消せない木を戻して一時領域ごと消せるようにする。
    fn unstick(t: &Tmp) {
        for ent in fs::read_dir(t.work()).unwrap().flatten() {
            let d = ent.path().join("d");
            let _ = fs::set_permissions(&d, fs::Permissions::from_mode(0o700));
        }
    }

    /// REPAIR-4・SEC-1: タイムアウト・異常終了・正常終了のどの経路でも、bundle の削除失敗は握りつぶさず
    /// `bundle_cleanup_failed` に反映し、元の失敗理由（Timeout 等）は保つ。
    #[test]
    fn bundle_cleanup_failure_is_reported_on_every_path() {
        if self_uid() == 0 {
            return; // root は 0500 でも消せるため、この観測は非 root 前提（root 前提の環境では対象外）。
        }
        let cases: [(&str, Option<i64>, Code); 3] = [
            ("exec sleep 30", Some(1), Code::Timeout),
            ("exit 3", None, Code::FailedPrecondition),
            ("exit 0", None, Code::Internal),
        ];
        for (tail, timeout, code) in cases {
            let t = Tmp::new("cleanup");
            let body = format!("{STICKY_BUNDLE}{tail}");
            let hooks =
                validate_create_container_hooks(&[mk_sh(&body, &["h"], &[], timeout)]).unwrap();
            let stage = CdiHookStage::for_test(&t.0);
            let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
            assert_eq!(err.error.code(), code, "{tail}");
            assert!(err.bundle_cleanup_failed, "{tail}");
            unstick(&t);
        }
        // 後始末に成功する通常の失敗では立たない。
        let t = Tmp::new("cleanup-ok");
        let hooks = validate_create_container_hooks(&[mk_sh("exit 3", &["h"], &[], None)]).unwrap();
        let stage = CdiHookStage::for_test(&t.0);
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        assert!(!err.bundle_cleanup_failed);
    }

    /// GPU-2・REPAIR-2: 先行フックが前提を壊した（証跡が無効になった）場合、後続フックは起動されず、
    /// その添字で中断し、完了済みの報告を保つ。
    #[test]
    fn stage_is_rechecked_before_every_hook() {
        struct Poison<'a>(&'a CdiHookStage);
        impl CdiHookRunRecorder for Poison<'_> {
            fn record(&self, _sample: CdiHookRunSample) {
                self.0.poisoned.store(true, Ordering::SeqCst);
            }
        }
        let t = Tmp::new("recheck");
        let marker = t.0.join("second-ran");
        let second = format!("touch {}", marker.display());
        let hooks = validate_create_container_hooks(&[
            mk_sh("exit 0", &["h1"], &[], None),
            mk_sh(&second, &["h2"], &[], None),
        ])
        .unwrap();
        let stage = CdiHookStage::for_test(&t.0);
        let err = run_create_container_hooks_with_recorder(
            &stage,
            &hooks,
            None,
            &state(),
            &open_hook_work_dir(&t.work()).unwrap(),
            &Poison(&stage),
        )
        .unwrap_err();
        assert_eq!(err.index, 1);
        assert_eq!(err.error.code(), Code::FailedPrecondition);
        assert_eq!(err.completed.len(), 1);
        assert_eq!(err.completed[0].index, 0);
        assert!(!marker.exists());
    }

    /// REPAIR-5: 削除の件数・期限の予算を超えたら無期限に続けず失敗を返し、`removed` は立てない。
    #[test]
    fn bundle_remove_is_bounded_by_budget() {
        let t = Tmp::new("budget");
        let wd = CdiHookWorkDir::open(&t.work()).unwrap();
        let mut b = Bundle::create(&wd, "/r").unwrap();
        for i in 0..10 {
            fs::write(b.dir.join(format!("f{i}")), b"x").unwrap();
        }
        let mut over = RemoveBudget::new();
        over.left = 3;
        assert_eq!(
            remove_children(&b.fd, fd_mnt_id(&b.fd).unwrap(), 0, &mut over),
            Err(sys::SysError::Os(110))
        );
        let mut late = RemoveBudget::new();
        late.deadline = Instant::now();
        assert_eq!(
            remove_children(&b.fd, fd_mnt_id(&b.fd).unwrap(), 0, &mut late),
            Err(sys::SysError::Os(110))
        );
        assert!(!b.removed);
        // 予算内なら残りも含めて消せる。
        b.remove().unwrap();
        assert!(b.removed);
    }

    /// REPAIR-5・GPU-2: フックが（残存する子を含め）多数のエントリを bundle に作って終了しても、削除は件数の
    /// 予算で打ち切られ、`bundle_cleanup_failed` を立てて期限内に返る。
    #[test]
    fn runaway_entries_end_with_cleanup_failed() {
        TEST_REMOVE_ENTRY_LIMIT.with(|l| l.set(50));
        let t = Tmp::new("runaway");
        let body = format!(
            "{} i=0; while [ $i -lt 400 ]; do : > \"$b/f$i\"; i=$((i+1)); done; exit 0",
            r#"IFS= read -r s; b=${s#*\"bundle\":\"}; b=${b%%\"*};"#
        );
        let hooks = validate_create_container_hooks(&[mk_sh(&body, &["h"], &[], None)]).unwrap();
        let stage = CdiHookStage::for_test(&t.0);
        let start = Instant::now();
        let err = run_create_container_hooks(&stage, &hooks, &state(), &t.work()).unwrap_err();
        TEST_REMOVE_ENTRY_LIMIT.with(|l| l.set(0));
        assert!(start.elapsed() < Duration::from_secs(10));
        assert!(err.bundle_cleanup_failed);
        assert_eq!(err.error.code(), Code::Internal);
        // 後始末（予算を戻して回収）。
        let dir = fs::read_dir(t.work())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::remove_dir_all(dir).unwrap();
    }

    /// GPU-2・SEC-1: 事前に開いた作業ディレクトリが改名されると、state の bundle パスが別の場所を指すため、
    /// フックを起動せずに拒否する。
    #[test]
    fn renamed_work_dir_is_rejected_before_launch() {
        let t = Tmp::new("renamed");
        let marker = t.0.join("ran");
        let body = format!("touch {}", marker.display());
        let hooks = validate_create_container_hooks(&[mk_sh(&body, &["h"], &[], None)]).unwrap();
        let stage = CdiHookStage::for_test(&t.0);
        let wd = open_hook_work_dir(&t.work()).unwrap();
        let moved = t.0.join("moved");
        fs::rename(t.work(), &moved).unwrap();
        let err = run_create_container_hooks_with_recorder(
            &stage,
            &hooks,
            None,
            &state(),
            &wd,
            &NoopRecorder,
        )
        .unwrap_err();
        assert_eq!(err.error.code(), Code::FailedPrecondition);
        assert_eq!(
            err.error.message(),
            "hook bundle path no longer matches the pinned directory"
        );
        assert!(!err.bundle_cleanup_failed);
        assert!(!marker.exists());
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 0);
    }

    /// SEC-1・GPU-2: fdinfo の `mnt_id` の読み取りと、親子のマウント ID の不一致判定を具体値で固定する。
    #[test]
    fn mount_id_parse_and_boundary_decision() {
        assert_eq!(
            parse_fdinfo_mnt_id("pos:\t0\nflags:\t012010000\nmnt_id:\t412\nino:\t5\n").ok(),
            Some(412)
        );
        assert!(matches!(
            parse_fdinfo_mnt_id("pos:\t0\nino:\t5\n"),
            Err(FdinfoMountIdError::Missing)
        ));
        assert!(matches!(
            parse_fdinfo_mnt_id("mnt_id:\tabc\n"),
            Err(FdinfoMountIdError::Invalid)
        ));
        assert_eq!(require_same_mount(7, 7), Ok(()));
        assert_eq!(require_same_mount(7, 8), Err(sys::SysError::Os(18)));
        // 実在の fd では取得できる。
        let t = Tmp::new("mntid");
        let a = CdiHookWorkDir::open(&t.work()).unwrap();
        assert!(fd_mnt_id(&a.fd).unwrap() > 0);
    }

    /// GPU-2・SEC-1・REPAIR-1・#3140: core の fixture（`crates/core/testdata/fdinfo_mnt_id_cases.txt`）の全事例で、解析結果が期待と完全一致する。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair1_gpu2_fdinfo_mnt_id_shared_cases() {
        use std::io::Cursor;
        const CASES: &str = include_str!("../../../../core/testdata/fdinfo_mnt_id_cases.txt");

        fn hex(s: &str) -> Vec<u8> {
            if s == "-" {
                return Vec::new();
            }
            assert!(s.len().is_multiple_of(2), "odd hex: {s}");
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
                .collect()
        }

        let classify = |bytes: &[u8]| -> String {
            match read_fdinfo_bounded(Cursor::new(bytes)).and_then(|t| parse_fdinfo_mnt_id(&t)) {
                Ok(n) => format!("ok:{n}"),
                Err(FdinfoMountIdError::Read(_)) => "read".into(),
                Err(FdinfoMountIdError::TooLarge) => "too_large".into(),
                Err(FdinfoMountIdError::Missing) => "missing".into(),
                Err(FdinfoMountIdError::Duplicate) => "duplicate".into(),
                Err(FdinfoMountIdError::Invalid) => "invalid".into(),
            }
        };
        let mut max_bytes = None;
        let mut seen = std::collections::BTreeSet::new();
        let mut count = 0usize;
        for line in CASES
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f[0] == "max_bytes" {
                max_bytes = Some(f[1].parse::<u64>().expect("max_bytes"));
                continue;
            }
            let bytes = hex(f[1]);
            let shared = f[2];
            // 第 4 列の `net=` は net 側だけの上書き期待なので、この試験では読み飛ばす。
            // 解析部・fixture の形式は crates/core・net・gpu の 3 か所の試験で同じ形に保つ（変更時は 3 か所を同期する。REPAIR-1）。
            let want = shared;
            let got = classify(&bytes);
            assert_eq!(
                got,
                want,
                "case {}: input {:?}",
                f[0],
                String::from_utf8_lossy(&bytes)
            );
            seen.insert(shared.split(':').next().unwrap().to_string());
            count += 1;
        }
        assert!(count >= 16, "fixture is too small: {count}");
        for k in ["ok", "missing", "duplicate", "invalid", "read"] {
            assert!(seen.contains(k), "fixture has no {k} case");
        }
        let max = max_bytes.expect("max_bytes line");
        assert_eq!(max, FDINFO_MAX_BYTES, "limit constant differs from fixture");
        let n = usize::try_from(max).unwrap();
        assert_eq!(classify(&vec![b'a'; n]), "missing");
        assert_eq!(classify(&vec![b'a'; n + 1]), "too_large");
    }

    /// SEC-1・GPU-2・REPAIR-2（#3025）: `mnt_id:` の重複・欠落・不正値を理由つきで拒否する（core・net と同じ表）。
    #[test]
    fn sec1_gpu2_parse_fdinfo_mnt_id_rejects_duplicate_missing_invalid() {
        let ok: &[(&str, u64)] = &[
            ("pos:\t0\nflags:\t012600000\nmnt_id:\t52\nino:\t1\n", 52),
            ("fanotify mnt_id:\t9\nmnt_id:\t7\n", 7),
            ("mnt_id:\t18446744073709551615\n", u64::MAX),
        ];
        for (input, want) in ok {
            let got = parse_fdinfo_mnt_id(input);
            assert_eq!(got.as_ref().ok(), Some(want), "input={input:?} got={got:?}");
        }
        for input in ["pos:\t0\nflags:\t0\n", ""] {
            let got = parse_fdinfo_mnt_id(input);
            assert!(
                matches!(got, Err(FdinfoMountIdError::Missing)),
                "input={input:?} got={got:?}"
            );
        }
        for input in [
            "mnt_id:\t52\nmnt_id:\t53\n",
            "mnt_id:\t52\nmnt_id:\t52\n",
            "mnt_id:\tx\nmnt_id:\t7\n",
        ] {
            let got = parse_fdinfo_mnt_id(input);
            assert!(
                matches!(got, Err(FdinfoMountIdError::Duplicate)),
                "input={input:?} got={got:?}"
            );
        }
        for input in [
            "mnt_id:\tx\n",
            "mnt_id:\t-1\n",
            "mnt_id:\t\n",
            "mnt_id:\t18446744073709551616\n",
        ] {
            let got = parse_fdinfo_mnt_id(input);
            assert!(
                matches!(got, Err(FdinfoMountIdError::Invalid)),
                "input={input:?} got={got:?}"
            );
        }
    }

    /// REPAIR-5・SEC-1（#3025）: 上限ちょうどは通り、1 バイト超過は切り捨てず拒否する。非 UTF-8 は `Read`。
    #[test]
    fn sec1_gpu2_read_fdinfo_bounded_limit() {
        let n = FDINFO_MAX_BYTES as usize;
        let at = read_fdinfo_bounded(std::io::Cursor::new(vec![b'a'; n])).unwrap();
        assert_eq!(at.len(), n);
        for over in [n + 1, n + 2, n * 2] {
            let got = read_fdinfo_bounded(std::io::Cursor::new(vec![b'a'; over]));
            assert!(
                matches!(got, Err(FdinfoMountIdError::TooLarge)),
                "len={over} got={got:?}"
            );
        }
        let got = read_fdinfo_bounded(std::io::Cursor::new(b"mnt_id:\t\xff\n".to_vec()));
        assert!(
            matches!(got, Err(FdinfoMountIdError::Read(_))),
            "got={got:?}"
        );
    }

    /// SEC-1・GPU-2（#3025）: 失敗理由の errno への写像を具体値で固定する。
    #[test]
    fn sec1_gpu2_fdinfo_error_maps_to_errno() {
        let read_enoent = FdinfoMountIdError::Read(std::io::Error::from_raw_os_error(2));
        assert_eq!(fdinfo_error_errno(&read_enoent), sys::SysError::Os(2));
        let read_other = FdinfoMountIdError::Read(std::io::Error::new(ErrorKind::InvalidData, "x"));
        assert_eq!(fdinfo_error_errno(&read_other), sys::SysError::Os(5));
        for e in [
            FdinfoMountIdError::TooLarge,
            FdinfoMountIdError::Missing,
            FdinfoMountIdError::Duplicate,
            FdinfoMountIdError::Invalid,
        ] {
            assert_eq!(fdinfo_error_errno(&e), sys::SysError::Os(5), "e={e:?}");
        }
    }

    /// REPAIR-4: 非ゼロで終了したフックの終了コードは `CdiHookError` と計測値に残り、シグナル終了は区別される。
    #[test]
    fn exit_code_and_signal_are_preserved() {
        let t = Tmp::new("exit");
        let stage = CdiHookStage::for_test(&t.0);
        for (body, want, code, sig) in [
            ("exit 7", CdiHookExit::Code(7), Some(7), None),
            ("kill -9 $$", CdiHookExit::Signal(9), None, Some(9)),
        ] {
            let hooks = validate_create_container_hooks(&[mk_sh(body, &["h"], &[], None)]).unwrap();
            let rec = Rec(Default::default());
            let err = run_create_container_hooks_with_recorder(
                &stage,
                &hooks,
                None,
                &state(),
                &open_hook_work_dir(&t.work()).unwrap(),
                &rec,
            )
            .unwrap_err();
            assert_eq!(err.exit, Some(want), "{body}");
            let got = rec.0.lock().unwrap();
            assert_eq!((got[0].exit_code, got[0].signal), (code, sig), "{body}");
        }
    }

    /// SEC-1・GPU-2: bundle 内へ既存ディレクトリを bind mount されても、削除はその中へ入らず
    /// 元のファイルを消さず、後始末の失敗として返す。user + mount namespace を作れる環境（`unshare -rm`）が前提。
    /// 外側の実行では自分自身を `unshare` の下で再実行し、内側（`FANDHE_GPU_NS_INNER=1`）で本体を行う。
    #[test]
    #[ignore = "needs unprivileged user + mount namespaces (unshare -rm) and mount(8)"]
    fn bundle_remove_refuses_bind_mount_boundary() {
        if std::env::var("FANDHE_GPU_NS_INNER").is_err() {
            let exe = std::env::current_exe().unwrap();
            let st = Command::new("unshare")
                .args(["-r", "-m", "--"])
                .arg(exe)
                .args([
                    "--exact",
                    "cdi_apply::hooks::run::tests::bundle_remove_refuses_bind_mount_boundary",
                    "--ignored",
                    "--nocapture",
                ])
                .env("FANDHE_GPU_NS_INNER", "1")
                .status()
                .unwrap();
            assert!(st.success());
            return;
        }
        let t = Tmp::new("bindmnt");
        // namespace 内では祖先が overflow uid に見えるため、所有者検査つきの open は使えない。
        let wd = CdiHookWorkDir::open_unchecked_for_test(&t.work());
        let mut b = Bundle::create(&wd, "/r").unwrap();
        let victim = t.0.join("victim");
        fs::create_dir(&victim).unwrap();
        fs::write(victim.join("keep"), b"x").unwrap();
        let mp = b.dir.join("m");
        fs::create_dir(&mp).unwrap();
        let ok = Command::new("mount")
            .arg("--bind")
            .arg(&victim)
            .arg(&mp)
            .status()
            .unwrap()
            .success();
        assert!(ok, "mount --bind failed");
        assert!(b.remove().is_err());
        assert!(!b.removed);
        assert!(victim.join("keep").exists());
        println!("bundle_remove_refuses_bind_mount_boundary: ok");
        let _ = Command::new("umount").arg(&mp).status();
    }

    struct Rec(std::sync::Mutex<Vec<CdiHookRunSample>>);
    impl CdiHookRunRecorder for Rec {
        fn record(&self, sample: CdiHookRunSample) {
            self.0.lock().unwrap().push(sample);
        }
    }

    /// REPAIR-4: 成功・失敗・起動拒否の各経路で、結果コードと所要時間が 1 試行ごとに通知される。
    /// 事前検査済みの fd（`open_hook_executables`）経由でも同じ結果になる。
    #[test]
    fn recorder_sees_success_failure_and_refusal() {
        let t = Tmp::new("rec");
        let hooks = validate_create_container_hooks(&[
            mk_sh("exit 0", &["h1"], &[], None),
            mk_sh("exit 3", &["h2"], &[], None),
        ])
        .unwrap();
        let stage = CdiHookStage::for_test(&t.0);
        let exes = open_hook_executables(&hooks).unwrap();
        assert_eq!(exes.len(), 2);
        let rec = Rec(Default::default());
        let err = run_create_container_hooks_with_recorder(
            &stage,
            &hooks,
            Some(&exes),
            &state(),
            &open_hook_work_dir(&t.work()).unwrap(),
            &rec,
        )
        .unwrap_err();
        assert_eq!(err.index, 1);
        let got = rec.0.lock().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(
            (got[0].index, got[0].error_code, got[0].exit_code),
            (0, None, Some(0))
        );
        assert_eq!(
            (got[1].index, got[1].error_code, got[1].exit_code),
            (1, Some(Code::FailedPrecondition), Some(3))
        );
        drop(got);

        let rec = Rec(Default::default());
        let err = run_create_container_hooks_with_recorder(
            &stage,
            &hooks,
            Some(&open_hook_executables(&hooks[..1]).unwrap()),
            &state(),
            &open_hook_work_dir(&t.work()).unwrap(),
            &rec,
        )
        .unwrap_err();
        assert_eq!(err.error.code(), Code::InvalidArgument);
        let got = rec.0.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].error_code, Some(Code::InvalidArgument));
    }
}
