//! fork / exec による子プロセス起動（CORE-1・TASK-27.4.1・#831・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! `crate::exec` の最小実行フロー第 5 段。namespace 分離済み（`isolate` /
//! `isolate_rootful_host_root` の後）の親から [`spawn_container`] で子を fork し、子（新しい PID
//! namespace の PID 1）が次を順に行う。呼び出し元は TASK-29 の `oci_runtime`（`create` / `start`）と
//! supervisor（TASK-157）を想定する。
//!
//! ```text
//! spawn_container(rootfs, &entry)                      // 親: fork して ContainerChild を返す
//!   子: MountIsolation::establish()
//!       -> prepare_rootfs(&isolation, rootfs)
//!       -> pivot_root(&isolation, prepared)            -> PivotReport
//!       -> exec_entrypoint(&isolation, &report, &entry) // execve。成功時は戻らない
//! 親: ContainerChild::wait_timeout(timeout)            // waitpid（期限超過で SIGKILL + 回収）
//! ```
//!
//! # 契約
//!
//! - **最小構成（フック無し）**: 本 PR の範囲は fork と exec まで。**capability 削減・
//!   `PR_SET_NO_NEW_PRIVS`・seccomp・Landlock・基本デバイスノード・cgroup 参加は未適用**で、
//!   ステージ列（#832・#833・#834、TASK-37〜40）が `child_main` の pivot 後・exec 前に差し込む。
//!   そのため rootful 経路（`isolate_rootful_host_root`）のようにホスト root 権限のままの子は、
//!   `exec_entrypoint` が `PermissionDenied` で exec を拒否する（SEC-1・CORE-5。制限を適用できる
//!   ようになるまで fail-closed。REPAIR-3: 実装済みを装わない）
//! - **エントリポイントは fd に固定して `execveat` する**: 検査（`/proc/self/exe` との同一性）と実行の
//!   間にパスが差し替わる TOCTOU を防ぐ。読み取り権限のない実行専用バイナリは開けず拒否される
//! - **fork の健全性は `sys::fork_single_threaded` が強制する**: 呼び出し元が `Threads: 1`
//!   でなければ fork せず `FailedPrecondition` で返す。子はクロージャの結果で必ず `_exit(2)` し、
//!   呼び出し元のスタックへ戻らない
//! - **子の失敗の通知は終了コードと stderr**: 段の失敗は stderr に英語 1 行を出し、
//!   [`EXIT_SETUP_FAILED`]（125: exec 前までの失敗・子の panic）・[`EXIT_EXEC_NOT_EXECUTABLE`]
//!   （126: exec の失敗のうち不在以外）・[`EXIT_EXEC_NOT_FOUND`]（127: エントリポイント不在）で
//!   分類する（docker / runc の慣例）。親子間の同期・構造化エラーパイプ（子の [`ExecError`] を構造の
//!   まま親へ返す）は未実装で、TASK-29/30（OCI `create` / `start` の分離）で扱う
//! - **親の待ちには必ずタイムアウトを設ける**（REPAIR-5）: [`ContainerChild::wait_timeout`] のみを
//!   提供する。`Drop` では kill / wait しない（コンテナの寿命を親ハンドルに暗黙で縛らない）ため、
//!   回収の責任は呼び出し元にある
//! - **exec は絶対パスのみ**: PATH 探索・cwd・OCI `process` からの組み立て・`preserve_fds`・
//!   `LISTEN_FDS` の受け渡しは TASK-29/30 の範囲
//!
//! # 単体テストの安全策
//!
//! libtest はマルチスレッドで、`execve` を呼ぶとテストランナーが置き換わるため、`execve`・
//! `close_range`・`signal` は `cfg(test)` では呼び出し順を記録するだけの dry-run に差し替わる
//! （`rootfs.rs` の `bind_syscall` と同じ流儀）。実 fork / exec の挙動は結合試験
//! `tests/fork_exec_isolation.rs`（`-- --ignored`）で確認する。

use std::convert::Infallible;
use std::ffi::{CString, OsStr};
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::sys::{self, Signal, SysError};
use crate::traits::types::ErrorCode;

use super::{
    ExecError, IsolationStage, MountIsolation, PivotReport, ViolationReason, describe, fd_mount_id,
    pivot_root, prepare_rootfs,
};

/// argv の要素数の上限（アロケーション前に検証する）。
pub const ENTRYPOINT_MAX_ARGS: usize = 4096;
/// env の要素数の上限。
pub const ENTRYPOINT_MAX_ENV: usize = 4096;
/// 1 要素の上限（NUL を含む。Linux の `MAX_ARG_STRLEN` = 32 ページ = 131072）。
pub const ENTRYPOINT_MAX_STRING_BYTES: usize = 131_072;
/// path + argv + env の合計上限（NUL を含む）。
pub const ENTRYPOINT_MAX_TOTAL_BYTES: usize = 1 << 20;

/// exec 前までの段の失敗・子の panic の終了コード（runc の慣例）。
pub const EXIT_SETUP_FAILED: i32 = 125;
/// exec の失敗のうちエントリポイント不在以外（権限・形式不正・引数過大等）の終了コード。
pub const EXIT_EXEC_NOT_EXECUTABLE: i32 = 126;
/// エントリポイント不在の終了コード。
pub const EXIT_EXEC_NOT_FOUND: i32 = 127;

/// 検証済みのエントリポイント（コンテナ内の絶対パス・argv・env）。
///
/// 外部入力（イメージ設定・CLI・CRI）の値を `execve` へ渡す前の唯一の入口で、NUL・書式・件数・
/// バイト数を検証済みの `CString` 群として保持する（壊れた値を表現できない型。REPAIR-2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entrypoint {
    path: CString,
    argv: Vec<CString>,
    env: Vec<CString>,
}

impl Entrypoint {
    /// 検証して作る。
    ///
    /// - `path` は空でない絶対パスで NUL を含まない
    /// - `args`（argv）は 1 件以上で、各要素は NUL を含まない
    /// - `env` の各要素は `KEY=VALUE` 形式で、KEY は空でなく、NUL を含まない
    /// - 件数・1 要素・合計のバイト数が上限内（上限の検証は `CString` 化より前に行う）
    ///
    /// 違反はすべて `ErrorCode::InvalidArgument`・`IsolationStage::Validate`（分離違反ではないため
    /// 違反記録なし）。
    pub fn new<P, A, E>(path: P, args: A, env: E) -> Result<Self, ExecError>
    where
        P: AsRef<Path>,
        A: IntoIterator,
        A::Item: AsRef<OsStr>,
        E: IntoIterator,
        E::Item: AsRef<OsStr>,
    {
        let invalid =
            |msg: &str| ExecError::new(ErrorCode::InvalidArgument, IsolationStage::Validate, msg);
        let path = path.as_ref();
        if path.as_os_str().is_empty() || !path.is_absolute() {
            return Err(invalid(
                "the entrypoint path must be a non-empty absolute path",
            ));
        }
        let mut total = 0usize;
        let path = to_cstring(path.as_os_str(), &mut total, "entrypoint path")?;
        let argv = collect_cstrings(args, ENTRYPOINT_MAX_ARGS, &mut total, "argv")?;
        if argv.is_empty() {
            return Err(invalid("argv must contain at least one element"));
        }
        let env = collect_cstrings(env, ENTRYPOINT_MAX_ENV, &mut total, "env")?;
        for entry in &env {
            // KEY は空でなく、`=` を境に KEY と VALUE が分かれること。
            if !matches!(entry.to_bytes().iter().position(|b| *b == b'='), Some(i) if i > 0) {
                return Err(invalid(
                    "each env element must be KEY=VALUE with a non-empty KEY",
                ));
            }
        }
        Ok(Self { path, argv, env })
    }

    /// コンテナ内の絶対パス。
    pub fn path(&self) -> &Path {
        Path::new(OsStr::from_bytes(self.path.to_bytes()))
    }
}

/// 1 要素を検証して `CString` にする。`total` に NUL 込みのバイト数を加算する。
fn to_cstring(value: &OsStr, total: &mut usize, what: &str) -> Result<CString, ExecError> {
    let invalid =
        |msg: String| ExecError::new(ErrorCode::InvalidArgument, IsolationStage::Validate, msg);
    let bytes = value.as_bytes();
    // NUL 終端ぶんの 1 バイトを含めて上限と比べる（CString 化・確保より前）。
    let size = bytes.len().saturating_add(1);
    if size > ENTRYPOINT_MAX_STRING_BYTES {
        return Err(invalid(format!(
            "an element of {what} exceeds {ENTRYPOINT_MAX_STRING_BYTES} bytes"
        )));
    }
    *total = total.saturating_add(size);
    if *total > ENTRYPOINT_MAX_TOTAL_BYTES {
        return Err(invalid(format!(
            "the entrypoint exceeds {ENTRYPOINT_MAX_TOTAL_BYTES} bytes in total"
        )));
    }
    CString::new(bytes).map_err(|_| invalid(format!("{what} must not contain NUL")))
}

/// 件数を `max` 以下に制限しながら `CString` 群にする（`max + 1` 件目を見た時点で拒否し、
/// 無制限のイテレータからも確保しない）。
fn collect_cstrings<I>(
    items: I,
    max: usize,
    total: &mut usize,
    what: &str,
) -> Result<Vec<CString>, ExecError>
where
    I: IntoIterator,
    I::Item: AsRef<OsStr>,
{
    let mut out = Vec::new();
    for item in items {
        if out.len() >= max {
            return Err(ExecError::new(
                ErrorCode::InvalidArgument,
                IsolationStage::Validate,
                format!("{what} has more than {max} elements"),
            ));
        }
        out.push(to_cstring(item.as_ref(), total, what)?);
    }
    Ok(out)
}

/// 子の終了状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChildExit {
    /// `exit` した（終了コード 0〜255）。
    Exited(i32),
    /// シグナルで終了した（シグナル番号）。
    Signaled(i32),
}

/// `waitpid` の status を解釈する（純関数）。stopped / continued は `None`（WUNTRACED を渡さない
/// ため通常は到達せず、呼び出し側が fail-closed でエラーにする）。
fn decode_wait_status(status: i32) -> Option<ChildExit> {
    let low = status & 0x7f;
    if low == 0 {
        Some(ChildExit::Exited((status >> 8) & 0xff))
    } else if low != 0x7f {
        Some(ChildExit::Signaled(low))
    } else {
        None
    }
}

/// exec の errno を `ErrorCode` に写す（純関数）。`ENOENT`/`ENOTDIR` → `NotFound`、
/// `EACCES`/`EPERM` → `PermissionDenied`、`ENOEXEC`/`E2BIG` → `InvalidArgument`、その他 → `Internal`。
fn exec_errno_to_code(err: SysError) -> ErrorCode {
    match err {
        SysError::Os(e) if e == sys::ENOENT || e == sys::ENOTDIR => ErrorCode::NotFound,
        SysError::Os(e) if e == sys::EACCES || e == sys::EPERM => ErrorCode::PermissionDenied,
        SysError::Os(e) if e == sys::ENOEXEC || e == sys::E2BIG => ErrorCode::InvalidArgument,
        SysError::Unsupported => ErrorCode::Unimplemented,
        _ => ErrorCode::Internal,
    }
}

/// 子の終了コード（純関数）。`Exec` 段の `NotFound` → 127、`Exec` 段のそれ以外 → 126、他の段 → 125。
fn exit_code_for(err: &ExecError) -> i32 {
    match (err.stage, err.code) {
        (IsolationStage::Exec, ErrorCode::NotFound) => EXIT_EXEC_NOT_FOUND,
        (IsolationStage::Exec, _) => EXIT_EXEC_NOT_EXECUTABLE,
        _ => EXIT_SETUP_FAILED,
    }
}

/// rootful 経路のホスト root 権限（実効 uid 0 かつ初期 user namespace の恒等写像）を判定する純関数。
///
/// `uid_map` は `/proc/self/uid_map`。恒等の全域写像（`0 0 4294967295`）が唯一の行なら初期 user
/// namespace であり、ここで uid 0 ならホストの root である。user namespace 内の uid 0（rootless）は
/// 写像がこの形にならないため該当しない。
fn is_host_root(euid: u32, uid_map: &str) -> bool {
    if euid != 0 {
        return false;
    }
    let mut lines = uid_map.lines().filter(|l| !l.trim().is_empty());
    match (lines.next(), lines.next()) {
        (Some(line), None) => {
            let f: Vec<&str> = line.split_whitespace().collect();
            f == ["0", "0", "4294967295"]
        }
        _ => false,
    }
}

/// ホスト root 権限のままの exec を拒否する（SEC-1・CORE-5。fail-closed）。
///
/// capability 削減・`PR_SET_NO_NEW_PRIVS`・seccomp・Landlock は #832・#833 まで未適用のため、
/// `isolate_rootful_host_root` 経路の子は特権を落とせない。制限を適用できるようになるまで、この
/// 経路からの exec を拒否する。`uid_map` を読めない場合も判定できないため拒否する。
fn deny_host_root_exec() -> Result<(), ExecError> {
    let deny = |msg: &str| ExecError::new(ErrorCode::PermissionDenied, IsolationStage::Exec, msg);
    let uid_map = std::fs::read_to_string("/proc/self/uid_map")
        .map_err(|_| deny("cannot read /proc/self/uid_map to verify the privilege model"))?;
    if is_host_root(sys::effective_uid(), &uid_map) {
        return Err(deny(
            "refusing to exec with host root privileges: capability drop, no_new_privs, seccomp and Landlock are not applied yet",
        ));
    }
    Ok(())
}

/// pivot 済みの PID 1 から、エントリポイントへ `execve` する（成功時は戻らないため戻り値の
/// `Ok` は到達不能）。
///
/// [`MountIsolation::establish`]・[`prepare_rootfs`]・[`pivot_root`] と同じスレッドから呼ぶ。
/// 失敗しても状態は戻せないため、呼び出し元はプロセスを破棄する（子の `child_main` は終了コードで
/// 終わる）。手順は [`exec_entrypoint_verified`] を参照。
pub fn exec_entrypoint(
    isolation: &MountIsolation,
    pivot: &PivotReport,
    entry: &Entrypoint,
) -> Result<Infallible, ExecError> {
    isolation.verify_caller(IsolationStage::Exec)?;
    deny_host_root_exec()?;
    exec_entrypoint_verified(pivot.new_root_mnt_id, entry)
}

/// [`exec_entrypoint`] の証跡検証後の本体。`execve`・`close_range`・`signal` は `cfg(test)` では
/// dry-run（単体テストは証跡を偽造せずに直接呼ぶ）。手順（順序固定）:
///
/// 1. `/` のマウント ID が pivot 直後の新 root と一致する（pivot 後に root が入れ替わっていない）
/// 2. エントリポイントを新 root 内で `open` し、その fd を `fstat` する（不在なら `NotFound`）。`/proc/self/exe`
///    （ランタイム自身のホスト側バイナリ）と `(st_dev, st_ino)` が同じなら拒否する
///    （CVE-2019-5736 型の多層防御。検査した fd をそのまま `execveat(AT_EMPTY_PATH)` で実行し、
///    検査から実行までの間のパス差し替え〔TOCTOU〕を防ぐ。memfd による自己複製は後続の課題）
/// 3. fd 3 以上を `CLOEXEC` にする（CVE-2024-21626 型の fd 漏えい対策。カーネル 5.11 未満は
///    `ENOSYS`/`EINVAL` で fail-closed）
/// 4. `SIGPIPE` を `SIG_DFL` へ戻す（Rust ランタイムが設定した ignore は `execve` を越えて継承される）
/// 5. `execveat`（開いた fd を実行。実行権限がなければ `EACCES`）。戻ってきたら失敗
fn exec_entrypoint_verified(
    pivot_mnt_id: u64,
    entry: &Entrypoint,
) -> Result<Infallible, ExecError> {
    const STAGE: IsolationStage = IsolationStage::Exec;
    let root = sys::open_dir_path_nofollow(None, c"/")
        .map_err(|e| ExecError::from_sys(e, STAGE, "openat(/)"))?;
    if fd_mount_id(&root, STAGE)? != pivot_mnt_id {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            "/ is not the root prepared by pivot_root",
        ));
    }
    drop::<OwnedFd>(root);

    // 検査と実行を同じ fd に固定する（パスを再解決する execve では、検査後に差し替えられうる）。
    let file = open_entrypoint(entry)?;
    let meta = file.metadata().map_err(|e| io_exec_error(&e, entry))?;
    if !meta.is_file() {
        return Err(ExecError::new(
            ErrorCode::PermissionDenied,
            STAGE,
            format!("the entrypoint {:?} is not a regular file", entry.path()),
        ));
    }
    let exe = std::fs::metadata("/proc/self/exe").map_err(|e| io_exec_error(&e, entry))?;
    if (meta.dev(), meta.ino()) == (exe.dev(), exe.ino()) {
        return Err(ExecError::from_violation_at(
            ViolationReason::EntrypointIsRuntimeBinary,
            Some(entry.path()),
            STAGE,
        ));
    }
    // シェバン付きスクリプトは fd が CLOEXEC だと execveat が ENOENT になるため、その場合だけ
    // mark_fds_cloexec の後に fd を継承させる（読み取り専用の同一ファイルの fd のみが漏れる）。
    let mut magic = [0u8; 2];
    let is_script = matches!((&file).read(&mut magic), Ok(2)) && &magic == b"#!";

    mark_fds_cloexec()?;
    reset_sigpipe()?;
    if is_script {
        sys::set_cloexec(file.as_fd(), false)
            .map_err(|e| ExecError::from_sys(e, STAGE, "fcntl(F_SETFD)"))?;
    }
    let err = do_execve(entry, &file);
    Err(ExecError::new(
        exec_errno_to_code(err),
        STAGE,
        format!("execve({:?}) failed: {}", entry.path(), describe(err)),
    ))
}

/// fd 3 以上を `CLOEXEC` にする。本番ビルドの実装。
#[cfg(not(test))]
fn mark_fds_cloexec() -> Result<(), ExecError> {
    sys::mark_fds_cloexec_from(3).map_err(|e| {
        let mut err = ExecError::from_sys(e, IsolationStage::Exec, "close_range(CLOEXEC)");
        // Linux 5.11 未満は close_range が無い（ENOSYS）。fd を漏らしたまま exec しない（fail-closed）。
        if e == SysError::Os(sys::ENOSYS) {
            err.code = ErrorCode::FailedPrecondition;
        }
        err
    })
}

/// テストビルドの dry-run 差し込み点。呼ばれたことだけを記録する。
#[cfg(test)]
fn mark_fds_cloexec() -> Result<(), ExecError> {
    tests::record("close_range(3)".to_string());
    Ok(())
}

/// `SIGPIPE` を `SIG_DFL` へ戻す。本番ビルドの実装。
#[cfg(not(test))]
fn reset_sigpipe() -> Result<(), ExecError> {
    sys::reset_sigpipe_default()
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Exec, "signal(SIGPIPE, SIG_DFL)"))
}

/// テストビルドの dry-run 差し込み点。呼ばれたことだけを記録する。
#[cfg(test)]
fn reset_sigpipe() -> Result<(), ExecError> {
    tests::record("signal(SIGPIPE,SIG_DFL)".to_string());
    Ok(())
}

/// エントリポイントを開く。失敗は errno を `ErrorCode` に写す（不在 → `NotFound`）。
fn open_entrypoint(entry: &Entrypoint) -> Result<std::fs::File, ExecError> {
    sys::open_file_read(&entry.path)
        .map(std::fs::File::from)
        .map_err(|e| {
            ExecError::new(
                exec_errno_to_code(e),
                IsolationStage::Exec,
                format!(
                    "open of the entrypoint {:?} failed: {}",
                    entry.path(),
                    describe(e)
                ),
            )
        })
}

/// `std::io::Error` を `Exec` 段の `ExecError` に写す。
fn io_exec_error(e: &std::io::Error, entry: &Entrypoint) -> ExecError {
    let err = SysError::Os(e.raw_os_error().unwrap_or(0));
    ExecError::new(
        exec_errno_to_code(err),
        IsolationStage::Exec,
        format!(
            "stat of the entrypoint {:?} failed: {}",
            entry.path(),
            describe(err)
        ),
    )
}

/// 開いた fd を `execveat` する。本番ビルドの実装（戻ってきたら失敗の errno）。
#[cfg(not(test))]
fn do_execve(entry: &Entrypoint, file: &std::fs::File) -> SysError {
    sys::exec_fd(file.as_fd(), &entry.argv, &entry.env)
}

/// テストビルドの dry-run 差し込み点。`execveat` を呼ばず、渡された引数を記録して `EINTR`（`Internal` に写る）を返す。
#[cfg(test)]
fn do_execve(entry: &Entrypoint, _file: &std::fs::File) -> SysError {
    let show = |v: &[CString]| {
        v.iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    };
    tests::record(format!("execve({})", entry.path().display()));
    tests::record(format!("argv={}", show(&entry.argv)));
    tests::record(format!("env={}", show(&entry.env)));
    SysError::Os(sys::EINTR)
}

/// 子のメイン。`establish` → `prepare_rootfs` → `pivot_root` → `exec_entrypoint` を通し、失敗したら
/// stderr に英語 1 行を出して終了コードを返す（戻り値は `_exit` に渡される）。
///
/// ステージ列（capability 削減・`PR_SET_NO_NEW_PRIVS`・Landlock・seccomp。#832・#833）と基本デバイス
/// ノード（#834）の差し込み位置は、pivot 後・exec 前（`exec_entrypoint` の直前）を想定する。
/// デバイスノードを pivot の前後どちらで作るかは #834 で決める（本 PR では決めない）。
fn child_main(rootfs: &Path, entry: &Entrypoint) -> i32 {
    match run_child(rootfs, entry) {
        Ok(never) => match never {},
        Err(err) => {
            // env の値は message に含めない（パスと errno のみ）。stderr が閉じていても panic しない。
            let _ = writeln!(std::io::stderr(), "fandhe-container: {err}");
            exit_code_for(&err)
        }
    }
}

fn run_child(rootfs: &Path, entry: &Entrypoint) -> Result<Infallible, ExecError> {
    let isolation = MountIsolation::establish()?;
    let prepared = prepare_rootfs(&isolation, rootfs)?;
    let report = pivot_root(&isolation, prepared)?;
    exec_entrypoint(&isolation, &report, entry)
}

/// 分離済み（`isolate` / `isolate_rootful_host_root` の後）の親から子を fork し、子で
/// `establish` → `prepare_rootfs` → `pivot_root` → `exec_entrypoint` を行う。
///
/// 親が分離済みであることは、子の `establish` が実行時に検証する（PID 1・入れ子の PID
/// namespace・シングルスレッド）。親がシングルスレッドでなければ fork せず `FailedPrecondition`。
/// 戻り値の [`ContainerChild`] は [`ContainerChild::wait_timeout`] で回収する。`unshare(CLONE_NEWPID)`
/// の最初の子だけが PID 1 になり、それが終わると namespace は以後 fork できないため、分離した親からの
/// `spawn_container` は 1 回だけ成功する。
pub fn spawn_container(rootfs: &Path, entry: &Entrypoint) -> Result<ContainerChild, ExecError> {
    let pid = sys::fork_single_threaded(|| child_main(rootfs, entry), EXIT_SETUP_FAILED)
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "fork"))?;
    Ok(ContainerChild { pid })
}

/// 待ちのポーリング間隔。
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);
/// `wait_timeout` に渡せる最大値（`Instant` の加算オーバーフローを避けるための丸め）。
const WAIT_TIMEOUT_MAX: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// `SIGKILL` 後に回収を待つ上限。
const KILL_REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// fork した子（コンテナの PID 1）のハンドル。
///
/// `Drop` では kill / wait しない。回収の責任は呼び出し元にあり、放置すると子はゾンビとして残る。
#[must_use]
#[derive(Debug)]
pub struct ContainerChild {
    pid: u32,
}

impl ContainerChild {
    /// 子のプロセス ID（親の PID namespace での値）。
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// 子の終了を `timeout` まで待つ（REPAIR-5）。
    ///
    /// 期限を超えたら `SIGKILL` を送って回収し、`ErrorCode::Timeout`（段は `Wait`）で返す。
    /// ハンドルを消費しない（`&self`）ため、`kill` / `waitpid` が一時的に失敗しても呼び出し元は再試行できる。
    /// 回収済みの子に再度呼ぶと `waitpid` の `ECHILD` が `ExecError` として返る。
    /// `waitpid(WNOHANG)` を 10ms 間隔でポーリングする。`timeout` は 7 日に丸める。
    pub fn wait_timeout(&self, timeout: Duration) -> Result<ChildExit, ExecError> {
        const STAGE: IsolationStage = IsolationStage::Wait;
        let deadline = Instant::now() + timeout.min(WAIT_TIMEOUT_MAX);
        if let Some(exit) = self.poll_until(deadline)? {
            return Ok(exit);
        }
        // 期限超過: SIGKILL を送り、回収まで有限時間だけ待つ。ESRCH は既に終了済み（回収待ち）。
        match sys::kill_pid(self.pid, Signal::Kill) {
            Ok(()) => {}
            Err(SysError::Os(e)) if e == sys::ESRCH => {}
            Err(e) => return Err(ExecError::from_sys(e, STAGE, "kill(SIGKILL)")),
        }
        match self.poll_until(Instant::now() + KILL_REAP_TIMEOUT)? {
            Some(_) => Err(ExecError::new(
                ErrorCode::Timeout,
                STAGE,
                format!("the container process did not exit within {timeout:?}; killed"),
            )),
            None => Err(ExecError::new(
                ErrorCode::Internal,
                STAGE,
                "the container process did not exit after SIGKILL",
            )),
        }
    }

    /// `deadline` まで `waitpid(WNOHANG)` でポーリングする。回収できれば `Some`、期限なら `None`。
    fn poll_until(&self, deadline: Instant) -> Result<Option<ChildExit>, ExecError> {
        const STAGE: IsolationStage = IsolationStage::Wait;
        loop {
            match sys::wait_pid_nohang(self.pid) {
                Ok(Some(status)) => {
                    return decode_wait_status(status).map(Some).ok_or_else(|| {
                        ExecError::new(
                            ErrorCode::Internal,
                            STAGE,
                            "the container process changed state without exiting",
                        )
                    });
                }
                Ok(None) => {}
                // シグナル割り込みでも期限は必ず確認する（連続 EINTR で期限超過・SIGKILL 未到達を防ぐ）。
                Err(SysError::Os(e)) if e == sys::EINTR => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    continue;
                }
                Err(e) => return Err(ExecError::from_sys(e, STAGE, "waitpid")),
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(WAIT_POLL_INTERVAL);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::process::{Command, Stdio};

    use super::*;

    thread_local! {
        /// dry-run が記録した呼び出し（テストスレッドごと）。
        static DRY_RUN_CALLS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn record(call: String) {
        DRY_RUN_CALLS.with(|c| c.borrow_mut().push(call));
    }

    /// 記録を取り出して空にする（ワーカースレッド再利用で前のテストの記録が漏れないように）。
    fn take_calls() -> Vec<String> {
        DRY_RUN_CALLS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    /// `/` のマウント ID（dry-run 本体へ渡す「pivot 直後の新 root」の代わり）。
    fn current_root_mnt_id() -> u64 {
        let root = sys::open_dir_path_nofollow(None, c"/").unwrap();
        fd_mount_id(&root, IsolationStage::Exec).unwrap()
    }

    fn validate_err(r: Result<Entrypoint, ExecError>) -> ExecError {
        let err = r.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::Validate);
        assert_eq!(err.violation, None);
        err
    }

    /// CORE-1（TASK-27.4.1）: 正常な入力は具体値で保持される。
    #[test]
    fn core1_entrypoint_accepts_valid_input() {
        let e = Entrypoint::new("/bin/app", ["app", "--flag"], ["A=1", "B="]).unwrap();
        assert_eq!(e.path(), Path::new("/bin/app"));
        assert_eq!(
            e.argv,
            vec![
                CString::new("app").unwrap(),
                CString::new("--flag").unwrap()
            ]
        );
        assert_eq!(
            e.env,
            vec![CString::new("A=1").unwrap(), CString::new("B=").unwrap()]
        );
    }

    /// CORE-1（TASK-27.4.1）: 相対・空パス、NUL、argv 0 件、`=` の無い/KEY の空な env は拒否する。
    #[test]
    fn core1_entrypoint_rejects_malformed_input() {
        let none: [&str; 0] = [];
        validate_err(Entrypoint::new("bin/app", ["a"], none));
        validate_err(Entrypoint::new("", ["a"], none));
        validate_err(Entrypoint::new("/bin/a\0pp", ["a"], none));
        validate_err(Entrypoint::new("/bin/app", ["a\0b"], none));
        validate_err(Entrypoint::new("/bin/app", none, none));
        validate_err(Entrypoint::new("/bin/app", ["a"], ["A\0=1"]));
        validate_err(Entrypoint::new("/bin/app", ["a"], ["NOEQUALS"]));
        validate_err(Entrypoint::new("/bin/app", ["a"], ["=VALUE"]));
    }

    /// CORE-1（TASK-27.4.1）: 件数・1 要素・合計の上限を超える入力は拒否する（境界値は許可）。
    #[test]
    fn core1_entrypoint_enforces_limits() {
        let none: [&str; 0] = [];
        let ok_args = vec!["a"; ENTRYPOINT_MAX_ARGS];
        assert!(Entrypoint::new("/bin/app", &ok_args, none).is_ok());
        let too_many = vec!["a"; ENTRYPOINT_MAX_ARGS + 1];
        validate_err(Entrypoint::new("/bin/app", &too_many, none));
        let too_many_env = vec!["A=1"; ENTRYPOINT_MAX_ENV + 1];
        validate_err(Entrypoint::new("/bin/app", ["a"], &too_many_env));

        // NUL を含めて上限ちょうどは許可、1 バイト超過は拒否。
        let at_limit = "x".repeat(ENTRYPOINT_MAX_STRING_BYTES - 1);
        assert!(Entrypoint::new("/bin/app", [at_limit.as_str()], none).is_ok());
        let over = "x".repeat(ENTRYPOINT_MAX_STRING_BYTES);
        validate_err(Entrypoint::new("/bin/app", [over.as_str()], none));

        // 1 要素は上限内でも合計が超えれば拒否（131071 バイト × 9 > 1 MiB）。
        let big = vec![at_limit.as_str(); 9];
        validate_err(Entrypoint::new("/bin/app", &big, none));
    }

    /// CORE-1（TASK-27.4.1）: `waitpid` status の解釈。
    #[test]
    fn core1_decode_wait_status_is_exact() {
        assert_eq!(decode_wait_status(0x2a00), Some(ChildExit::Exited(42)));
        assert_eq!(decode_wait_status(0x0000), Some(ChildExit::Exited(0)));
        assert_eq!(decode_wait_status(0x0009), Some(ChildExit::Signaled(9)));
        assert_eq!(decode_wait_status(0x137f), None);
        assert_eq!(decode_wait_status(0xffff), None);
    }

    /// CORE-1（TASK-27.4.1）: exec の errno の写像。
    #[test]
    fn core1_exec_errno_to_code_is_exact() {
        assert_eq!(
            exec_errno_to_code(SysError::Os(sys::ENOENT)),
            ErrorCode::NotFound
        );
        assert_eq!(
            exec_errno_to_code(SysError::Os(sys::ENOTDIR)),
            ErrorCode::NotFound
        );
        assert_eq!(
            exec_errno_to_code(SysError::Os(sys::EACCES)),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            exec_errno_to_code(SysError::Os(sys::ENOEXEC)),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            exec_errno_to_code(SysError::Os(sys::E2BIG)),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            exec_errno_to_code(SysError::Os(sys::EINTR)),
            ErrorCode::Internal
        );
    }

    /// CORE-1（TASK-27.4.1）: 子の終了コードの分類（125 / 126 / 127）。
    #[test]
    fn core1_exit_code_for_is_exact() {
        let e = |stage, code| ExecError::new(code, stage, "x");
        assert_eq!(
            exit_code_for(&e(IsolationStage::Exec, ErrorCode::NotFound)),
            127
        );
        assert_eq!(
            exit_code_for(&e(IsolationStage::Exec, ErrorCode::PermissionDenied)),
            126
        );
        assert_eq!(
            exit_code_for(&e(IsolationStage::PivotRoot, ErrorCode::NotFound)),
            125
        );
        assert_eq!(
            exit_code_for(&e(IsolationStage::PrepareRootfs, ErrorCode::Internal)),
            125
        );
    }

    /// SEC-1・CORE-5: ホスト root（euid 0 かつ初期 user namespace の恒等写像）だけを拒否する。
    #[test]
    fn sec1_is_host_root_is_exact() {
        let identity = "         0          0 4294967295\n";
        assert!(is_host_root(0, identity));
        assert!(!is_host_root(1000, identity));
        // rootless: 自 ID をコンテナ内 0 へ写す単一 ID 写像。
        assert!(!is_host_root(0, "         0       1000          1\n"));
        // 複数行・空・不正は host root 扱いにしない（判定不能は呼び出し側が別途拒否する）。
        assert!(!is_host_root(0, ""));
        assert!(!is_host_root(0, "0 0 4294967295\n1 1 1\n"));
    }

    /// CORE-1（TASK-27.4.1）: dry-run で exec 前の処理が固定順に呼ばれ、`execve` に argv・env が
    /// そのまま渡る。dry-run の `execve` は `EINTR` を返すので `Internal` の `Exec` 段エラーになる。
    #[test]
    fn core1_exec_runs_steps_in_fixed_order() {
        let dir = std::env::temp_dir().join(format!("fandhe-exec-order-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("probe");
        std::fs::write(&bin, b"").unwrap();
        let entry = Entrypoint::new(&bin, ["probe", "-x"], ["K=V"]).unwrap();
        let _ = take_calls();
        let err = exec_entrypoint_verified(current_root_mnt_id(), &entry).unwrap_err();
        let calls = take_calls();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(err.stage, IsolationStage::Exec);
        assert_eq!(err.code, ErrorCode::Internal);
        assert_eq!(
            calls,
            vec![
                "close_range(3)".to_string(),
                "signal(SIGPIPE,SIG_DFL)".to_string(),
                format!("execve({})", bin.display()),
                "argv=probe -x".to_string(),
                "env=K=V".to_string(),
            ]
        );
    }

    /// CORE-1（TASK-27.4.1）: `/` が pivot 直後の新 root でなければ何も呼ばず拒否する。
    #[test]
    fn core1_exec_rejects_unexpected_root() {
        let entry = Entrypoint::new("/proc/self/exe", ["x"], [] as [&str; 0]).unwrap();
        let _ = take_calls();
        let err = exec_entrypoint_verified(current_root_mnt_id() + 1, &entry).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::Exec);
        assert_eq!(take_calls(), Vec::<String>::new());
    }

    /// CORE-1（TASK-27.4.1）: ランタイム自身の実行ファイル（`/proc/self/exe` と同一 inode）は、
    /// 実パスでも `/proc/self/exe` 経由でも違反として拒否し、`execve` は呼ばない。
    #[test]
    fn core1_exec_rejects_runtime_binary() {
        let exe = std::env::current_exe().unwrap();
        for path in [exe.as_path(), Path::new("/proc/self/exe")] {
            let entry = Entrypoint::new(path, ["x"], [] as [&str; 0]).unwrap();
            let _ = take_calls();
            let err = exec_entrypoint_verified(current_root_mnt_id(), &entry).unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied, "{path:?}");
            assert_eq!(err.stage, IsolationStage::Exec, "{path:?}");
            let v = err.violation.expect("violation record");
            assert_eq!(v.reason, ViolationReason::EntrypointIsRuntimeBinary);
            assert_eq!(v.behavior_id, "CORE-1");
            assert_eq!(take_calls(), Vec::<String>::new(), "{path:?}");
        }
    }

    /// CORE-1（TASK-27.4.1）: 不在のエントリポイントは `NotFound`（終了コード 127 に対応）。
    #[test]
    fn core1_exec_reports_missing_entrypoint() {
        let entry = Entrypoint::new("/no/such/entrypoint", ["x"], [] as [&str; 0]).unwrap();
        let _ = take_calls();
        let err = exec_entrypoint_verified(current_root_mnt_id(), &entry).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert_eq!(err.stage, IsolationStage::Exec);
        assert_eq!(exit_code_for(&err), EXIT_EXEC_NOT_FOUND);
        assert_eq!(take_calls(), Vec::<String>::new());
    }

    /// `sh -c script` を起動してその pid を返す。std の `Child` は wait せず、回収は被試験対象の
    /// `ContainerChild::wait_timeout` が行う（二重回収を避けるため）。
    #[allow(clippy::zombie_processes)]
    fn spawn_sh(script: &str) -> u32 {
        Command::new("sh")
            .args(["-c", script])
            .stdin(Stdio::null())
            .spawn()
            .unwrap()
            .id()
    }

    /// CORE-1（TASK-27.4.1）: 終了した子を回収し、終了コードを返す。
    #[test]
    fn core1_wait_timeout_returns_exit_code() {
        let handle = ContainerChild {
            pid: spawn_sh("exit 3"),
        };
        assert_eq!(
            handle.wait_timeout(Duration::from_secs(10)).unwrap(),
            ChildExit::Exited(3)
        );
    }

    /// CORE-1・REPAIR-5（TASK-27.4.1）: 期限内に終わらない子は `Timeout` で返し、`SIGKILL` で
    /// 回収済み（`/proc/<pid>` が残らない）にする。
    #[test]
    fn core1_wait_timeout_kills_and_reaps_on_expiry() {
        let pid = spawn_sh("exec sleep 30");
        let handle = ContainerChild { pid };
        let err = handle.wait_timeout(Duration::from_millis(200)).unwrap_err();
        assert_eq!(err.code, ErrorCode::Timeout);
        assert_eq!(err.stage, IsolationStage::Wait);
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }
}
