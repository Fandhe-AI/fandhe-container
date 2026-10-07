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
//! 親: ContainerChild::wait_timeout(timeout)            // waitpid（期限超過で未回収に限り SIGKILL + 回収）
//! ```
//!
//! # 契約
//!
//! - **最小構成（フック無し）**: 子はステージ列（[`StagePipeline`]。#832）を `run_child` の pivot 後・
//!   exec 前で固定順に実行する。組み込みの `PR_SET_NO_NEW_PRIVS`（#833）は空のパイプラインでも適用される
//!   が、**Landlock は `with_landlock` 指定時のみ適用（本番 launcher からの指定は後続）、cgroup 参加は呼び出し側が `cgroups::CgroupJoin` を登録した場合のみ適用**（rootless の実体は TASK-40 が差し込む。capability 削減は #173、seccomp は #178 で組み込み済み）。
//!   そのため制限が未適用の子（rootful 経路のホスト root 権限のままの子を含む）は、
//!   `exec_entrypoint` が `PermissionDenied` で exec を拒否する（SEC-1・CORE-5。制限を適用できる
//!   ようになるまで fail-closed。REPAIR-3: 実装済みを装わない）
//! - **rootless 経路も同様に拒否する**: 制限ステージの適用証跡が無い限り exec しない。
//!   `/proc/self/status` の `NoNewPrivs`・`Seccomp`・`CapEff` は親から継承した制限と区別できず、
//!   seccomp の内容も確認できないため証跡にしない。残りのステージの実体（TASK-37〜39）が証跡型を返すように
//!   なるまで常に `PermissionDenied`（`NO_NEW_PRIVS` 単独は証跡にしない。SEC-1・CORE-5）。したがって現時点では実 exec は成功せず、
//!   成功経路は dry-run の単体テストで検証する
//! - **継承 fd は開く前に閉じる**: エントリポイントを開く前に fd 3 以上をすべて閉じ、fd 0〜2 と同一の
//!   実体（rootfs 内の `/proc/self/fd/N` 経由）は拒否する（fd 0〜2 の実体を確認できなければ拒否）。
//!   継承したホスト fd の実体を開く経路を断つ
//! - **セッションと制御端末を切り離す**（SUP-6・SEC-1・TASK-163 追補・#1456）: 子は継承 fd を閉じた直後に
//!   `setsid` で新しいセッションのリーダーになり、呼び出し側のセッション・制御端末を引き継がない（端末から
//!   起動された場合に、コンテナ内のコマンドが `/dev/tty` 経由でホスト側の端末へ読み書き・`ioctl` できない）。
//!   失敗したら `execve` へ進まない。launch 経路の子（新しい PID namespace の PID 1）と稼働中コンテナへの exec の子の
//!   両方に掛かる（`exec_checked_entrypoint` を共有する。変更前はどちらも `setsid` していなかった）。実プロセスでの
//!   照合は `tests/exec_child_setup.rs`（既定のテスト集合）
//! - **標準入出力は `/dev/null` へ置換する**: 呼び出し元の fd 0〜2 の実体は渡さない。`/dev/null` が
//!   無い rootfs は拒否する。端末・パイプの受け渡しは TASK-29/30 の範囲。`/dev/null` は **開く前に検証する**
//!   （TASK-163 追補・#1459）: 照合済みの `/` を起点に `O_PATH|O_NOFOLLOW` で固定し、`fstat` で文字デバイス
//!   1:3 を確かめてから、procfs の magic link 経由で `O_RDWR|O_NOCTTY` に開き直す。稼働中のコンテナ
//!   （`CAP_MKNOD` を持つ）が symlink・別のデバイスノードへ差し替えていても、差し替え先を開かずに違反
//!   `stdio_null_not_null_device` で拒否する。launch・exec の両経路に掛かる
//! - **インタープリタ経由でランタイム自身を実行させない**（SUP-6・SEC-1・CORE-5・TASK-163 追補・#1458）:
//!   エントリポイント本体に加えて、シェバンの連鎖と ELF の `PT_INTERP` の解決先を `/proc/self/exe` の実体と
//!   照合し、一致すれば違反 `entrypoint_interpreter_is_runtime_binary` で拒否する（`#!/proc/self/exe` 等）。
//!   Landlock に依存しない層だが、検査と `execve` の間の差し替え（TOCTOU）は残る。方式の比較と限界は
//!   `exec/interpreter.rs`。launch・exec の両経路に掛かる
//! - **エントリポイントは fd に固定して `execveat` する**: 検査（`/proc/self/exe` との同一性）と実行の
//!   間にパスが差し替わる TOCTOU を防ぐ。読み取り権限のない実行専用バイナリは開けず拒否される。
//!   fd は 3 以上に置く。シェバン付きスクリプトは、インタープリタが開き直す新 root の `/dev/fd/N` が
//!   同じ実体を指さなければ `FailedPrecondition` で拒否する（`/dev/fd` の用意は #834 の範囲）
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
//! - **回収済みの pid へ kill しない**: 回収と期限超過の `SIGKILL` は `ContainerChild` 内の `Mutex`
//!   の下で回収状態を確認して行い、並行に待っても回収後（pid 再利用され得る）に `SIGKILL` を送らない。
//!   待機が `Err` で戻ってもハンドルは残り、再試行で kill・回収できる
//! - **exec は絶対パスのみ**: PATH 探索・cwd・OCI `process` からの組み立て・`preserve_fds`・
//!   `LISTEN_FDS` の受け渡しは TASK-29/30 の範囲
//! - **環境変数と補助グループ**（SUP-6・SEC-1・SEC-5・TASK-163 追補・#1457）: `execveat` へは [`Entrypoint`] が持つ
//!   env だけを envp として明示的に渡し、呼び出しプロセスの環境は引き継がない（既定値の補完もしない）。launch は
//!   `config.json` の `process.env` から [`Entrypoint`] を組み立て、稼働中コンテナへの exec は同じ出所と 1 件ずつの
//!   明示の上書きだけから作る型（`ExecCommand` / `ContainerEnv`。ホスト環境の列をまとめて渡す式は書けない。
//!   `exec/container_env.rs`）でしか受け取らない。補助グループは、launch（組み込みの capability 削減段）・exec
//!   （`reapply_restrictions`）とも同じ関数が空にする（`setgroups(0)`。`exec/capabilities.rs` の
//!   `SupplementaryGroups`）。本モジュールの子の手順は資格情報を変更しない（uid / gid は呼び出しプロセスのもの）
//! - **`execve` 前の失敗を親へ知らせる**（REPAIR-3・TASK-163 追補・#1460）: 稼働中コンテナへの exec の子は、
//!   close-on-exec の pipe で「手順を終えた」「失敗した（終了コードと違反の理由）」を親へ返し、親は
//!   「コマンドが起動して終了した」のか「起動していない」のかを [`ExecExit`] で区別する（終了コード 125〜127 は
//!   コマンド自身も返し得るため）。launch 経路は従来どおり終了コードと stderr のみ（下記）
//!
//! # 単体テストの安全策
//!
//! libtest はマルチスレッドで、`execve` を呼ぶとテストランナーが置き換わるため、`execve`・
//! `close_range`・`signal` は `cfg(test)` では呼び出し順を記録するだけの dry-run に差し替わる
//! （`rootfs.rs` の `bind_syscall` と同じ流儀）。実 fork / exec の挙動は結合試験
//! `tests/fork_exec_isolation.rs`（`-- --ignored`）で確認する。

use std::convert::Infallible;
use std::ffi::{CString, OsStr};
use std::io::Write as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::sys::{self, Signal, SysError};
use crate::traits::types::ErrorCode;

use super::interpreter::reject_runtime_interpreter;
use super::{
    CapabilityReport, ExecError, IsolationStage, MountIsolation, PivotReport, StagePipeline,
    ViolationReason, describe, fd_mount_id, pivot_root, prepare_rootfs,
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
#[derive(Clone, PartialEq, Eq)]
pub struct Entrypoint {
    path: CString,
    argv: Vec<CString>,
    env: Vec<CString>,
}

// env の値は秘密情報を含み得るため、`Debug` には KEY だけを出す（これを包む `ExecCommand` の `Debug` も同じ出力に
// なる。supervisor の `EnvVar`・core の `ContainerEnv` と同じ方針。TASK-163 追補・#1457）。
impl std::fmt::Debug for Entrypoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<std::borrow::Cow<'_, str>> = self
            .env
            .iter()
            .map(|var| {
                let bytes = var.to_bytes();
                let key = bytes.split(|b| *b == b'=').next().unwrap_or(bytes);
                String::from_utf8_lossy(key)
            })
            .collect();
        f.debug_struct("Entrypoint")
            .field("path", &self.path)
            .field("argv", &self.argv)
            .field("env_keys", &keys)
            .finish()
    }
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

/// 制限ステージの適用証跡が無いままの exec を拒否する（SEC-1・CORE-5。fail-closed）。
///
/// `/proc/self/status` の `NoNewPrivs`・`Seccomp`・`CapEff` は、親から継承した制限と子のステージが
/// 適用した制限を区別できず、seccomp フィルタの中身も確認できないため、証跡として扱わない。
/// `PR_SET_NO_NEW_PRIVS` は #833 で組み込みステージとして実装済みだが単独では証跡にせず、
/// capability 削減は #173（TASK-37.2）で組み込み段になり、その [`CapabilityReport`] を引数で受け取る
/// が、制限適用の証跡配線（Landlock の適用は #184 の `with_landlock` で差し込み可能だが証跡型が未確定。後続作業）が未実装の間は引数の有無によらず
/// 常に `PermissionDenied` を返す。seccomp は #178（TASK-38.3）で組み込み段として適用されるが、
/// 証跡型が未確定のため本関数へは配線しない（Landlock も同様。確定と配線は後続作業）。ステージ実装時は、各ステージが
/// 適用完了を示す証跡型（形は TASK-38・TASK-39 で決める）を返し、それを本関数の引数に取って
/// 初めて許可する形へ置き換える（REPAIR-3: 実装済みを装わない）。
fn require_restriction_evidence(
    _capability_report: Option<&CapabilityReport>,
) -> Result<(), ExecError> {
    Err(ExecError::new(
        ErrorCode::PermissionDenied,
        IsolationStage::Exec,
        "refusing to exec: no evidence that the isolation restrictions were applied (wiring of restriction-applied evidence into exec is not implemented yet)",
    ))
}

/// pivot 済みの PID 1 から、エントリポイントへ `execve` する（成功時は戻らないため戻り値の
/// `Ok` は到達不能）。
///
/// [`MountIsolation::establish`]・[`prepare_rootfs`]・[`pivot_root`] と同じスレッドから呼ぶ。
/// 失敗しても状態は戻せないため、呼び出し元はプロセスを破棄する（子の `child_main` は終了コードで
/// 終わる）。手順は非公開の `exec_entrypoint_verified` を参照。
pub fn exec_entrypoint(
    isolation: &MountIsolation,
    pivot: &PivotReport,
    entry: &Entrypoint,
) -> Result<Infallible, ExecError> {
    isolation.verify_caller(IsolationStage::Exec)?;
    require_restriction_evidence(None)?;
    exec_entrypoint_verified(pivot.new_root_mnt_id, entry)
}

/// [`exec_entrypoint`] の証跡検証後の本体。`execve`・`close_range`・`signal` は `cfg(test)` では
/// dry-run（単体テストは証跡を偽造せずに直接呼ぶ）。手順（順序固定）:
///
/// 1. `/` のマウント ID が pivot 直後の新 root と一致する（pivot 後に root が入れ替わっていない）
/// 2. fd 3 以上をすべて閉じ（継承 fd の実体を `/proc/self/fd/N` 経由で開かれない）、`setsid` で呼び出し側の
///    セッション・制御端末を切り離し（#1456。以後に開くファイルを制御端末にしない順序）、エントリポイントを新 root 内で `open` し、その fd を `fstat` する（不在なら `NotFound`）。`/proc/self/exe`
///    （ランタイム自身のホスト側バイナリ）と `(st_dev, st_ino)` が同じなら拒否する
///    （CVE-2019-5736 型の多層防御。検査した fd をそのまま `execveat(AT_EMPTY_PATH)` で実行し、
///    検査から実行までの間のパス差し替え〔TOCTOU〕を防ぐ。memfd による自己複製は後続の課題）。シェバンの連鎖・
///    `PT_INTERP` の解決先がランタイムのバイナリなら同じく拒否する（#1458。`interpreter.rs`）
/// 3. 開いたエントリポイントが fd 0〜2 と同一 inode なら拒否する（`/proc/self/fd/{0,1,2}` 経由の参照対策。
///    fd 0〜2 の実体を確認できなければ拒否。エントリポイントの fd は 3 以上に置く）。
///    シェバン付きスクリプトは新 root の `/dev/fd/N` が同じ実体に解決することを確認する（できなければ拒否）。
///    fd 3 以上を `CLOEXEC` にする（CVE-2024-21626 型の fd 漏えい対策。カーネル 5.11 未満は
///    `ENOSYS`/`EINVAL` で fail-closed）
/// 4. `SIGPIPE` を `SIG_DFL` へ戻す（Rust ランタイムが設定した ignore は `execve` を越えて継承される）
/// 5. fd 0〜2 を新 root の `/dev/null`（開く前に `O_PATH` で固定して 1:3 を検証し、`O_NOCTTY` つきで開き直す。
///    #1459）へ置換する（継承されたホスト側の標準入出力を渡さない）
/// 6. `execveat`（開いた fd を実行。実行権限がなければ `EACCES`）。戻ってきたら失敗
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
    exec_checked_entrypoint(entry)
}

/// `exec_entrypoint_verified` の手順 2 以降（fd 3 以上の close → エントリポイントの検査 → 標準入出力の置換 →
/// `execveat`）。launch 経路（pivot 直後の mount ID 照合の後）と、稼働中コンテナへの exec
/// （`exec_command::spawn_exec_command` の子。参加後の `/` の照合は `reapply_restrictions` が済ませている。
/// SUP-6・TASK-163.4）が共有する。呼び出し元は「`/` が正しい root であること」を事前に保証すること。
pub(super) fn exec_checked_entrypoint(entry: &Entrypoint) -> Result<Infallible, ExecError> {
    let file = prepare_exec_child(entry, None)?;
    Err(execve_checked(entry, &file))
}

/// 検査済みの fd を `execveat` する。成功すると戻らず、戻ったら失敗（errno を `Exec` 段のエラーへ写す）。
fn execve_checked(entry: &Entrypoint, file: &std::fs::File) -> ExecError {
    let err = do_execve(entry, file);
    ExecError::new(
        exec_errno_to_code(err),
        IsolationStage::Exec,
        format!("execve({:?}) failed: {}", entry.path(), describe(err)),
    )
}

/// [`exec_checked_entrypoint`] の `execveat` より前の全手順。戻り値は検査済みで実行に使う fd。
///
/// 手順を 1 か所に置くことで、本番の子（直後に `execveat`）と、結合試験用の観測
/// （`observe_exec_child_setup`。`execveat` の代わりに子自身の状態を報告する）が同じ処理を通る。
///
/// `keep` は、fd の後始末で 1 本だけ残す fd（稼働中コンテナへの exec の子が、`execve` 前の失敗を親へ知らせる
/// pipe の書き込み側。close-on-exec で、`execveat` が成功すれば閉じる。#1460）。launch 経路は `None`。
fn prepare_exec_child(
    entry: &Entrypoint,
    keep: Option<BorrowedFd<'_>>,
) -> Result<std::fs::File, ExecError> {
    const STAGE: IsolationStage = IsolationStage::Exec;
    // 継承したホスト側の fd 3 以上を開く前に閉じる（rootfs 内の /proc/self/fd/N 経由で実体を開かれない）。
    close_inherited_fds(keep)?;
    // 呼び出し側のセッション・制御端末を切り離す（以後に開くファイルを制御端末にしない順序。#1456）。
    detach_session()?;
    // 呼び出し元が照合を済ませた `/`（launch は pivot 直後のマウント ID、exec は固定した rootfs との一致。exec の
    // 子の cwd も同じディレクトリ）と、その procfs。ランタイムの同一性の基準・固定した fd の開き直しの起点にする。
    // どちらも標準入出力の置換まで保持するため、番号を 3 以上へ置く（呼び出し元の fd 0〜2 が閉じていると
    // `openat` はその番号を返し、置換（`dup2`）した `/dev/null` を、この関数の終わりの close が閉じてしまう）。
    let root = sys::open_dir_path_nofollow(None, c"/")
        .map_err(|e| ExecError::from_sys(e, STAGE, "openat(/)"))
        .and_then(keep_above_stdio)?;
    let procfs = open_root_procfs(root.as_fd()).and_then(keep_above_stdio)?;
    // 検査と実行を同じ fd に固定する（パスを再解決する execve では、検査後に差し替えられうる）。
    let file = open_entrypoint(entry)?;
    let meta = file.metadata().map_err(|e| io_exec_error(&e, entry))?;
    if matches_any_identity((meta.dev(), meta.ino()), &inherited_stdio_identities()?) {
        return Err(ExecError::new(
            ErrorCode::PermissionDenied,
            STAGE,
            format!(
                "the entrypoint {:?} resolves to an inherited standard stream",
                entry.path()
            ),
        ));
    }
    if !meta.is_file() {
        return Err(ExecError::new(
            ErrorCode::PermissionDenied,
            STAGE,
            format!("the entrypoint {:?} is not a regular file", entry.path()),
        ));
    }
    let runtime = runtime_identity(procfs.as_fd())?;
    if (meta.dev(), meta.ino()) == runtime {
        return Err(ExecError::from_violation_at(
            ViolationReason::EntrypointIsRuntimeBinary,
            Some(entry.path()),
            STAGE,
        ));
    }
    // シェバン・`PT_INTERP` の解決先がランタイム自身でないことも確かめる（本体の照合だけでは
    // `#!/proc/self/exe` を通してしまう。#1458。契約と限界は `interpreter.rs`）。
    reject_runtime_interpreter(&file, entry.path(), runtime, procfs.as_fd())?;
    // シェバン付きスクリプトは fd が CLOEXEC だと execveat が ENOENT になるため、その場合だけ
    // mark_fds_cloexec の後に fd を継承させる（読み取り専用の同一ファイルの fd のみが漏れる）。
    let mut magic = [0u8; 2];
    let is_script = matches!(file.read_at(&mut magic, 0), Ok(2)) && &magic == b"#!";
    if is_script {
        // インタープリタは `/dev/fd/N` を開き直すため、新 root 内でそれが同じ実体を指すことを確認する。
        verify_script_fd_path(Path::new("/dev/fd"), &file, &meta, entry)?;
    }

    mark_fds_cloexec()?;
    reset_sigpipe()?;
    if is_script {
        sys::set_cloexec(file.as_fd(), false)
            .map_err(|e| ExecError::from_sys(e, STAGE, "fcntl(F_SETFD)"))?;
    }
    // 最後に標準入出力を置換する（以降の execve 失敗の診断は stderr へ出せず、終了コードのみで通知）。
    redirect_stdio_to_null(root.as_fd(), procfs.as_fd())?;
    Ok(file)
}

/// ランタイム自身のバイナリの `(st_dev, st_ino)`。検証済みの procfs（`proc_dir`）の `self/exe` を `O_PATH` で
/// 開いて `fstat` する（`/proc` というパスを引き直さない。`/proc` に別の実体が置かれた rootfs で、基準を
/// すり替えられない）。確認できなければ照合の基準が無いため拒否する（fail-closed）。
fn runtime_identity(proc_dir: BorrowedFd<'_>) -> Result<(u64, u64), ExecError> {
    const STAGE: IsolationStage = IsolationStage::Exec;
    let exe = sys::open_path_follow_at(proc_dir, c"self/exe")
        .map_err(|e| ExecError::from_sys(e, STAGE, "open of the runtime executable"))?;
    let meta = std::fs::File::from(exe)
        .metadata()
        .map_err(|e| ExecError::from_io(&e, STAGE, "stat the runtime executable"))?;
    Ok((meta.dev(), meta.ino()))
}

/// シェバン付きスクリプトを `execveat(AT_EMPTY_PATH)` で実行するときの前提を確認する。
///
/// カーネルはインタープリタへスクリプトのパスとして `/dev/fd/N`（N は実行用 fd）を渡し、
/// インタープリタはそれを開き直す。`dev_fd_dir`（本番は新 root の `/dev/fd`）の下の `N` が開いた fd と
/// 同じ `(st_dev, st_ino)` に解決できなければ、スクリプトは起動できないため `FailedPrecondition`
/// （段は `Exec`・終了コード 126）で明示的に拒否する。`/dev/fd`（`/proc/self/fd` への symlink）を
/// rootfs に用意するのはデバイス準備の範囲（#834・TASK-27.6）で、本関数は作らず検証だけを行う。
fn verify_script_fd_path(
    dev_fd_dir: &Path,
    file: &std::fs::File,
    meta: &std::fs::Metadata,
    entry: &Entrypoint,
) -> Result<(), ExecError> {
    use std::os::fd::AsRawFd as _;
    let path = dev_fd_dir.join(file.as_raw_fd().to_string());
    match std::fs::metadata(&path) {
        Ok(m) if (m.dev(), m.ino()) == (meta.dev(), meta.ino()) => Ok(()),
        _ => Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Exec,
            format!(
                "the entrypoint {:?} is a shebang script, but {} does not resolve to it in the new root; shebang scripts require /dev/fd (a symlink to /proc/self/fd)",
                entry.path(),
                path.display()
            ),
        )),
    }
}

/// fd 3 以上をすべて閉じる（`keep` があればその 1 本だけ残す）。本番ビルドの実装。
#[cfg(not(test))]
fn close_inherited_fds(keep: Option<BorrowedFd<'_>>) -> Result<(), ExecError> {
    let closed = match keep {
        Some(keep) => sys::close_fds_from_except(3, keep),
        None => sys::close_fds_from(3),
    };
    closed.map_err(|e| {
        let mut err = ExecError::from_sys(e, IsolationStage::Exec, "close_range(close)");
        // Linux 5.11 未満は close_range が無い（ENOSYS）。継承 fd を残したまま進めない（fail-closed）。
        if e == SysError::Os(sys::ENOSYS) {
            err.code = ErrorCode::FailedPrecondition;
        }
        err
    })
}

/// テストビルドの dry-run 差し込み点。呼ばれたことだけを記録する。
#[cfg(test)]
fn close_inherited_fds(_keep: Option<BorrowedFd<'_>>) -> Result<(), ExecError> {
    tests::record("close_range(3,close)".to_string());
    Ok(())
}

/// 新しいセッションを作り、呼び出し側のセッションと制御端末から切り離す（SUP-6・SEC-1・TASK-163 追補・#1456）。
/// 本番ビルドの実装。
///
/// `setsid` をしないと、コンテナ内のコマンドは呼び出し側（端末から起動した CLI 等）のセッションに残り、
/// `/dev/tty` 経由でホスト側の端末を読み書き・`ioctl`（`TIOCSTI` による入力の注入等）できる。Landlock の
/// ルールで塞がる場合もあるが、それに依存しない。fork 後の子でしか意味を持たないため子で呼ぶ（syscall 1 回。
/// アロケーション・ロックなし）。失敗は段 `Spawn`（終了コード [`EXIT_SETUP_FAILED`]）で、`execve` へ進まない
/// （fail-closed）。launch 経路の子（新しい PID namespace の PID 1）と exec の子が同じ扱いになる。
#[cfg(not(test))]
fn detach_session() -> Result<(), ExecError> {
    sys::new_session()
        .map(drop)
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "setsid"))
}

/// テストビルドの dry-run 差し込み点（libtest のプロセスのセッションは変えない）。呼ばれたことだけを記録する。
#[cfg(test)]
fn detach_session() -> Result<(), ExecError> {
    tests::record("setsid".to_string());
    Ok(())
}

/// fd 0〜2 の実体（継承した標準入出力）の `(st_dev, st_ino)` を集める。開いたエントリポイントと
/// 照合し、`/proc/self/fd/{0,1,2}` 経由でホスト側の実体を開いた場合を検出する（fd 3 以上は閉じ済み）。
///
/// 閉じている番号（複製が `EBADF`）は `/proc/self/fd/N` として参照できる実体が無いので除く。それ以外の
/// 複製・`fstat` の失敗は同一性を確認できないため、検査を通さず fail-closed で拒否する（SEC-1）。
fn inherited_stdio_identities() -> Result<Vec<(u64, u64)>, ExecError> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut ids = Vec::with_capacity(3);
    for (n, fd) in [(0, stdin.as_fd()), (1, stdout.as_fd()), (2, stderr.as_fd())] {
        let probe = fd
            .try_clone_to_owned()
            .and_then(|owned| std::fs::File::from(owned).metadata())
            .map(|m| (m.dev(), m.ino()));
        if let Some(id) = classify_stdio_probe(n, probe)? {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// 標準 fd 1 本の確認結果を分類する（純関数）。取得できた実体は `Some`、閉じている（`EBADF`）なら
/// `None`、それ以外の失敗は `PermissionDenied`（段は `Exec`）で拒否する。
fn classify_stdio_probe(
    n: i32,
    probe: std::io::Result<(u64, u64)>,
) -> Result<Option<(u64, u64)>, ExecError> {
    match probe {
        Ok(id) => Ok(Some(id)),
        Err(e) if e.raw_os_error() == Some(sys::EBADF) => Ok(None),
        Err(e) => Err(ExecError::new(
            ErrorCode::PermissionDenied,
            IsolationStage::Exec,
            format!("cannot verify the inherited standard stream fd {n} ({e}); refusing to exec"),
        )),
    }
}

/// `(st_dev, st_ino)` が `ids` のいずれかと一致するか（純関数）。
fn matches_any_identity(id: (u64, u64), ids: &[(u64, u64)]) -> bool {
    ids.contains(&id)
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

/// fd 0〜2 を新 root の `/dev/null` へ置き換える。本番ビルドの実装。
///
/// 呼び出し元が引き継いだ 0〜2 番の実体（ホストのファイル・ソケット）をコンテナのエントリポイントへ
/// 渡さない（CVE-2024-21626 型・fd 3 以上は `mark_fds_cloexec` が担当）。置換先は [`open_verified_null`] が
/// 検証してから開いた `/dev/null` で、存在しない・`null` デバイス（1:3）でない場合は、別の実体を標準入出力に
/// しないため fail-closed で拒否する。標準入出力の受け渡し（端末・パイプ）は TASK-29/30 の範囲（未実装）。
#[cfg(not(test))]
fn redirect_stdio_to_null(root: BorrowedFd<'_>, procfs: BorrowedFd<'_>) -> Result<(), ExecError> {
    let null = open_verified_null(root, procfs)?;
    sys::redirect_stdio_to(null)
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Exec, "dup2(/dev/null)"))
}

/// `root` 配下の `dev/null` を、**開く前に** 検証してから読み書きで開く（SUP-6・SEC-1・TASK-163 追補・#1459）。
///
/// OCI 既定の capability には `CAP_MKNOD` が含まれ、稼働中のコンテナは自分の `/dev/null` を symlink や別の
/// デバイスノードへ差し替えられる。パスを直接 `open` してから種別を調べる方式では、拒否する前に差し替え先の
/// デバイスを 1 回開いてしまう（開くだけで副作用を持つデバイスがある）。そこで次の順にする。
///
/// 1. `root` から `dev` を `O_PATH|O_DIRECTORY|O_NOFOLLOW` で開く（symlink・非ディレクトリは `ENOTDIR`）
/// 2. `dev` から `null` を `O_PATH|O_NOFOLLOW` で開く（`O_PATH` はドライバの `open` を呼ばない。symlink は
///    辿らず symlink 自体を指す fd になる）
/// 3. その fd を `fstat` し、文字デバイス 1:3 でなければ違反 `stdio_null_not_null_device` で拒否する
///    （SEC-4。ここまで対象を開いていない）
/// 4. `procfs`（`root` の `proc`。本物の procfs であることを [`open_root_procfs`] が `fstatfs` で確認済み）の
///    `thread-self/fd/N`（magic link。パスを再解決せず 2 の inode そのものを指す）経由で `O_RDWR|O_NOCTTY` に
///    開き直す
/// 5. 開いた fd をもう一度 `fstat` し、文字デバイス 1:3 であることを確かめる（開き直しの経路の多層防御）
///
/// `/proc` が procfs でない rootfs は開き直せないため、呼び出し元が先に拒否する（launch 経路は `prepare_rootfs` が
/// マウント済み、exec 経路はコンテナの procfs。fail-closed）。fork 後の子から呼ぶため、成功経路はアロケーションを
/// 伴わない。
fn open_verified_null(root: BorrowedFd<'_>, procfs: BorrowedFd<'_>) -> Result<OwnedFd, ExecError> {
    const STAGE: IsolationStage = IsolationStage::Exec;
    let dev = sys::open_dir_path_nofollow(Some(root), c"dev").map_err(|e| {
        ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!("cannot open /dev as a directory: {}", describe(e)),
        )
    })?;
    let pinned = pin_null_device(dev.as_fd(), c"null")?;
    reopen_null_device(procfs, pinned.as_fd())
}

/// `root` 配下の `proc` を開き、本物の procfs であることを確かめる（`fstatfs`。symlink・非ディレクトリ・別の
/// ファイルシステムは `FailedPrecondition`）。固定した fd の開き直し（magic link）の起点にする。
fn open_root_procfs(root: BorrowedFd<'_>) -> Result<OwnedFd, ExecError> {
    sys::open_dir_path_nofollow(Some(root), c"proc")
        .ok()
        .filter(|dir| sys::fs_type(dir.as_fd()) == Ok(sys::PROC_MAGIC))
        .ok_or_else(|| {
            ExecError::new(
                ErrorCode::FailedPrecondition,
                IsolationStage::Exec,
                "/proc in the new root is not procfs; cannot reopen a verified file",
            )
        })
}

/// `dev`（ディレクトリの fd）配下の `name` を開かずに固定し、文字デバイス 1:3 であることを確かめる
/// （[`open_verified_null`] の手順 2・3）。返す fd は `O_PATH`（検証済みの inode の固定用）。
///
/// symlink・通常ファイル・別のデバイスノード（1:3 以外）は違反 `stdio_null_not_null_device`
/// （`PermissionDenied`・段 `Exec`）で、対象を開かずに拒否する。不在は `FailedPrecondition`。
fn pin_null_device(dev: BorrowedFd<'_>, name: &std::ffi::CStr) -> Result<OwnedFd, ExecError> {
    const STAGE: IsolationStage = IsolationStage::Exec;
    let pinned = sys::open_path_nofollow(dev, name).map_err(|e| {
        ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!("cannot find /dev/null in the new root: {}", describe(e)),
        )
    })?;
    if !is_null_device(pinned.as_fd())? {
        return Err(ExecError::from_violation_at(
            ViolationReason::StdioNullNotNullDevice,
            Some(Path::new("/dev/null")),
            STAGE,
        ));
    }
    Ok(pinned)
}

/// 検証済みの `pinned` を読み書きで開き直し、開いた実体をもう一度確かめる（[`open_verified_null`] の手順 4・5）。
fn reopen_null_device(
    proc_dir: BorrowedFd<'_>,
    pinned: BorrowedFd<'_>,
) -> Result<OwnedFd, ExecError> {
    const STAGE: IsolationStage = IsolationStage::Exec;
    #[cfg(test)]
    tests::record("reopen(/dev/null)".to_string());
    let null = sys::reopen_pinned_rdwr_noctty(proc_dir, pinned)
        .map_err(|e| ExecError::from_sys(e, STAGE, "reopen of the verified /dev/null"))?;
    if !is_null_device(null.as_fd())? {
        return Err(ExecError::from_violation_at(
            ViolationReason::StdioNullNotNullDevice,
            Some(Path::new("/dev/null")),
            STAGE,
        ));
    }
    Ok(null)
}

/// `fd` の実体が文字デバイス 1:3（`null`）か。`fstat` できなければ確認できないため拒否する（fail-closed）。
fn is_null_device(fd: BorrowedFd<'_>) -> Result<bool, ExecError> {
    use std::os::unix::fs::FileTypeExt as _;
    // `O_PATH` の fd への fstat（パスを再解決しない）。複製は同じ open file description を指す。
    let meta = fd
        .try_clone_to_owned()
        .and_then(|owned| std::fs::File::from(owned).metadata())
        .map_err(|_| {
            ExecError::new(
                ErrorCode::PermissionDenied,
                IsolationStage::Exec,
                "cannot stat /dev/null to verify the stdio target",
            )
        })?;
    Ok(meta.file_type().is_char_device() && meta.rdev() == sys::makedev(1, 3))
}

/// テストビルドの dry-run 差し込み点。呼ばれたことだけを記録する。
#[cfg(test)]
fn redirect_stdio_to_null(_root: BorrowedFd<'_>, _procfs: BorrowedFd<'_>) -> Result<(), ExecError> {
    tests::record("stdio->/dev/null".to_string());
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
///
/// 返す fd は必ず 3 以上（[`keep_above_stdio`]）。呼び出し元の fd 0〜2 が閉じていると `openat` は
/// その番号を返し、後段の標準入出力の置換（`dup2`）で実行用の fd が潰されるため。
fn open_entrypoint(entry: &Entrypoint) -> Result<std::fs::File, ExecError> {
    let fd = sys::open_file_read(&entry.path).map_err(|e| {
        ExecError::new(
            exec_errno_to_code(e),
            IsolationStage::Exec,
            format!(
                "open of the entrypoint {:?} failed: {}",
                entry.path(),
                describe(e)
            ),
        )
    })?;
    keep_above_stdio(fd).map(std::fs::File::from)
}

/// fd が 0〜2 なら 3 以上へ複製して元を閉じる（3 以上ならそのまま返す）。
///
/// 標準入出力の置換（`dup2`）をまたいで保持する fd はすべてこれを通す: エントリポイント・照合済みの `/`・
/// procfs・状態を返す pipe の両端（置換で潰される、または置換後の `/dev/null` を close で閉じてしまうため）。
/// 置換より前に閉じる一時的な fd（`/dev`・固定用の `O_PATH`・インタープリタ）は対象外。
///
/// 複製は `sys::dup_fd_at_least(fd, 3)`（`F_DUPFD_CLOEXEC` に下限 3 を明示。カーネルが 3 以上を
/// 保証するため、標準 fd が複数閉じていても 0〜2 には戻らない）。
pub(super) fn keep_above_stdio(fd: OwnedFd) -> Result<OwnedFd, ExecError> {
    use std::os::fd::AsRawFd as _;
    if fd.as_raw_fd() > 2 {
        return Ok(fd);
    }
    let moved = sys::dup_fd_at_least(fd.as_fd(), 3)
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Exec, "fcntl(F_DUPFD_CLOEXEC)"))?;
    drop(fd);
    Ok(moved)
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

/// 稼働中コンテナへの exec の結果（SUP-6・REPAIR-3・TASK-163 追補・#1460）。
///
/// `execve` より前に子が失敗した場合の終了コード（125 / 126 / 127）は、実行されたコマンド自身も返し得る値で、
/// 終了コードだけでは「コマンドが失敗した」のか「コマンドは起動していない」のかを区別できない（healthcheck の
/// 判定は前者を不健全、後者を実行基盤側の失敗として扱う必要がある）。子が親へ pipe で知らせた内容で区別する
/// （`exec/process.rs` の `ExecStatusPipe`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExecExit {
    /// コマンドが起動し（`execveat` が成功し）、この状態で終了した。
    Command(ChildExit),
    /// コマンドは起動していない。子が `execveat` より前の手順か `execveat` 自体で失敗した。
    SetupFailed {
        /// 子の終了状態（通常は `Exited(125 | 126 | 127)`。手順の途中でシグナルを受けた場合は `Signaled`）。
        exit: ChildExit,
        /// 分離違反による拒否だった場合の理由（SEC-4。ランタイム自身のバイナリ・インタープリタ経由・
        /// `/dev/null` の差し替え）。違反でない失敗・理由を受け取れなかった場合は `None`。
        violation: Option<ViolationReason>,
    },
}

impl ExecExit {
    /// 子プロセスの終了状態（コマンドが起動したかどうかによらない）。
    pub fn child_exit(self) -> ChildExit {
        match self {
            Self::Command(exit) | Self::SetupFailed { exit, .. } => exit,
        }
    }

    /// コマンドが起動したか（`execveat` が成功したか）。
    pub fn command_started(self) -> bool {
        matches!(self, Self::Command(_))
    }
}

/// 子が「手順を終えて `execveat` を呼ぶ直前」に書く 1 行（[`read_exec_status`] のプロトコル）。
const EXEC_STATUS_READY: &[u8] = b"R\n";

/// 子が親へ返す状態の読み取り上限（バイト。1 行 2 件ぶんより十分大きい）。
const EXEC_STATUS_MAX: usize = 256;

/// 子が違反として報告し得る理由（`execveat` 前の手順が返す違反。[`read_exec_status`] が名前から引き直す）。
const EXEC_CHILD_VIOLATIONS: [ViolationReason; 3] = [
    ViolationReason::EntrypointIsRuntimeBinary,
    ViolationReason::EntrypointInterpreterIsRuntimeBinary,
    ViolationReason::StdioNullNotNullDevice,
];

/// 稼働中コンテナへの exec の子の本体（SUP-6・TASK-163.4。launch の `child_main` と同じ規約: 失敗したら stderr に
/// 英語 1 行を出して終了コードを返す。戻り値は `_exit` に渡される）。
///
/// `status` は親が fork の前に作った pipe の書き込み側（close-on-exec）で、次のプロトコルで使う（#1460）。
///
/// 1. `execveat` より前の全手順（`prepare_exec_child`）が通ったら [`EXEC_STATUS_READY`] を書く
/// 2. `terminal`（本番は `execveat`）を呼ぶ。`execveat` が成功すれば pipe は close-on-exec で閉じ、親は
///    「`R` の 1 行だけ」を読む = コマンドは起動した
/// 3. 手順か `terminal` が失敗したら `<終了コード> <違反の理由コードまたは ->` の 1 行を書く
///
/// 親（[`read_exec_status`]）は、`R` だけなら起動、失敗の行があれば未起動、何も無ければ「手順の途中で子が
/// 終了した」= 未起動と判定する。`R` を書けなければ `execveat` へ進まない（親へ知らせられない状態で実行しない）。
fn run_exec_child(
    entry: &Entrypoint,
    status: BorrowedFd<'_>,
    terminal: impl FnOnce(&Entrypoint, &std::fs::File) -> Result<i32, ExecError>,
) -> i32 {
    let result = prepare_exec_child(entry, Some(status)).and_then(|file| {
        write_exec_status(status, EXEC_STATUS_READY)?;
        terminal(entry, &file)
    });
    match result {
        Ok(code) => code,
        Err(err) => {
            let code = exit_code_for(&err);
            let _ = writeln!(std::io::stderr(), "fandhe-container: {err}");
            let reason = err.violation.as_ref().map_or("-", |v| v.reason.as_str());
            let _ = write_exec_status(status, format!("{code} {reason}\n").as_bytes());
            code
        }
    }
}

/// 子が状態を返す pipe を作る。戻り値は `(読み取り側, 書き込み側)`（両端とも close-on-exec）。
///
/// 両端を 3 以上の番号へ置く: 呼び出しプロセスの fd 0〜2 が閉じていると pipe がその番号を取り、子の標準入出力の
/// 置換（`dup2`）で書き込み側が `/dev/null` に潰される（状態が親へ届かず、起動したコマンドを「起動していない」と
/// 判定してしまう）。
pub(super) fn exec_status_pipe() -> Result<(std::fs::File, OwnedFd), ExecError> {
    let (reader, writer) = std::io::pipe()
        .map_err(|e| ExecError::from_io(&e, IsolationStage::Spawn, "create the status pipe"))?;
    let reader = keep_above_stdio(OwnedFd::from(reader))?;
    let writer = keep_above_stdio(OwnedFd::from(writer))?;
    Ok((std::fs::File::from(reader), writer))
}

/// `status`（pipe の書き込み側）へ `line` を書く。失敗は `Internal`（段 `Exec`）。
fn write_exec_status(status: BorrowedFd<'_>, line: &[u8]) -> Result<(), ExecError> {
    // 借用した fd を複製して書く（複製は同じ pipe を指し、ここで閉じても元の fd は残る）。
    status
        .try_clone_to_owned()
        .and_then(|owned| std::fs::File::from(owned).write_all(line))
        .map_err(|e| ExecError::from_io(&e, IsolationStage::Exec, "report the exec status"))
}

/// 稼働中コンテナへの exec の子のメイン（[`run_exec_child`] の終端を `execveat` にしたもの）。
pub(super) fn exec_child_main(entry: &Entrypoint, status: BorrowedFd<'_>) -> i32 {
    run_exec_child(entry, status, |entry, file| {
        Err(execve_checked(entry, file))
    })
}

/// 終了した子が pipe（`status` = 読み取り側）へ残した状態から、コマンドが起動したかどうかを判定する
/// （[`run_exec_child`] のプロトコル。#1460）。子が終了した **後** に呼ぶこと。
///
/// 書き込み側を持つのは子だけ（親は fork の直後に閉じ、実行されたコマンドには close-on-exec で渡らない）なので、
/// 子の終了後は読み取りが待たされない。それでも書き込み側が開いたままなら（想定外）、待たずに `Internal` で
/// 返す（REPAIR-5。起動したかどうかを推測しない）。解釈できない内容は未起動として扱う（fail-closed）。
pub(super) fn read_exec_status(
    status: &std::fs::File,
    exit: ChildExit,
) -> Result<ExecExit, ExecError> {
    use std::io::Read as _;
    let internal = |what: &str| ExecError::new(ErrorCode::Internal, IsolationStage::Wait, what);
    let mut buf = [0u8; EXEC_STATUS_MAX];
    let mut filled = 0usize;
    loop {
        // データが有るか、書き込み側がすべて閉じている（EOF）ときだけ読む。
        match sys::poll_readable(status.as_fd(), 0) {
            Ok(true) => {}
            Ok(false) => return Err(internal("the exec status pipe is still open after exit")),
            Err(_) => return Err(internal("cannot poll the exec status pipe")),
        }
        let Some(rest) = buf.get_mut(filled..).filter(|r| !r.is_empty()) else {
            break;
        };
        match (&*status).read(rest) {
            Ok(0) => break,
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(internal("cannot read the exec status pipe")),
        }
    }
    Ok(classify_exec_status(buf.get(..filled).unwrap_or(&[]), exit))
}

/// pipe の内容 `status` と子の終了状態から結果を決める（純関数。規則は [`run_exec_child`]）。
fn classify_exec_status(status: &[u8], exit: ChildExit) -> ExecExit {
    if status == EXEC_STATUS_READY {
        return ExecExit::Command(exit);
    }
    // 失敗の行（`R` の後、または単独）の 2 つ目の語が違反の理由コード。
    let violation = status
        .strip_prefix(EXEC_STATUS_READY)
        .unwrap_or(status)
        .split(|b| *b == b'\n')
        .next()
        .and_then(|line| line.split(|b| *b == b' ').nth(1))
        .and_then(|name| {
            EXEC_CHILD_VIOLATIONS
                .into_iter()
                .find(|reason| reason.as_str().as_bytes() == name)
        });
    ExecExit::SetupFailed { exit, violation }
}

/// [`observe_exec_child_setup`] の観測結果（結合試験専用。SUP-6・SEC-1・TASK-163 追補・#1456）。
#[cfg(all(feature = "exec-test-support", not(test)))]
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecChildSetupObservation {
    /// 本番と同じ pipe のプロトコルで判定した結果。`execveat` 前の手順が通れば `Command(Exited(0))`
    /// （`execveat` を呼ぶ直前まで到達した）、拒否されれば `SetupFailed`（終了コード 125 / 126 / 127 と違反の理由）。
    pub exit: ExecExit,
    /// 手順が通った子が、`execveat` の直前の自分の状態を書いた報告。拒否された場合は `None`。
    pub report: Option<ExecChildSetupReport>,
}

/// `execveat` の直前の子の状態（結合試験専用）。
#[cfg(all(feature = "exec-test-support", not(test)))]
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecChildSetupReport {
    /// 子の pid。
    pub pid: u32,
    /// 子のセッション ID（`/proc/self/stat` の `session`）。`setsid` 後は `pid` と一致する。
    pub session_id: u32,
    /// 子のプロセスグループ ID（`pgrp`）。`setsid` 後は `pid` と一致する。
    pub process_group: u32,
    /// 子の制御端末のデバイス番号（`tty_nr`）。制御端末なしは 0。
    pub tty_nr: i64,
    /// `/dev/tty` を開いた結果の errno（制御端末なしは `ENXIO` = 6。開けた場合は `None`）。
    pub dev_tty_errno: Option<i32>,
    /// fd 0〜2 の実体の `(文字デバイスか, st_rdev)`。`/dev/null` は `(true, makedev(1, 3))`。
    pub stdio: [(bool, u64); 3],
    /// `execveat` に渡す環境変数（`KEY=VALUE`。`ExecCommand` が持つ値そのもので、envp はこの列だけから作る）。
    pub env: Vec<String>,
    /// 子に残っている fd 3 以上の `(番号, /proc/self/fd のリンク先)`（一覧の読み取りに使った fd は除く）。
    /// 状態を返す pipe と、検査済みのエントリポイントの 2 本だけが残る。
    pub open_fds: Vec<(i32, String)>,
}

/// 結合試験専用: exec の子の `execveat` より前の全手順を実プロセスで通し、`execveat` の代わりに子自身の状態を
/// 報告させる（SUP-6・SEC-1・TASK-163 追補・#1456）。
///
/// 呼び出し文脈は `tests/exec_child_setup.rs`（単一スレッドの `main`。root・実コンテナ不要で、既定のテスト集合で
/// 動く）。本番の子（`exec_checked_entrypoint`）と同じ `prepare_exec_child` を fork した子で実行するため、
/// `setsid`・fd の後始末・エントリポイントの検査・`/dev/null` の検証と置換が、dry-run ではなく実 syscall で走る。
///
/// - **`execveat` は呼ばない**。エントリポイントは開いて検査するだけで実行しない。したがって制限適用の証跡
///   （`ExecReady`・`require_restriction_evidence`）を迂回してコマンドを実行する経路にはならない（SEC-1）。
///   namespace への参加・制限の適用も行わず、呼び出しプロセス自身の namespace と `/` に対して手順を通す
/// - 子は手順が通れば `report`（呼び出し側が用意した、存在しないパス）へ状態を `create_new` で書いて 0 で終わる。
///   拒否された場合は本番と同じ規約（stderr の英語 1 行と終了コード 125 / 126 / 127）で終わり、報告は無い
/// - `execve` 前の失敗を親へ知らせる pipe（#1460）も本番と同じものを通す: 子は fd の後始末で pipe の書き込み側
///   だけを残し、結果は本番と同じ [`read_exec_status`] が判定する
/// - 呼び出し元は単一スレッドであること（満たさなければ fork せず `FailedPrecondition`）。`timeout` を過ぎたら子を
///   `SIGKILL` して回収し `Timeout`（REPAIR-5）
/// - `exec-test-support` feature を付けたビルドにだけ存在し、既定のビルドの公開 API には含まれない
#[cfg(all(feature = "exec-test-support", not(test)))]
#[doc(hidden)]
pub fn observe_exec_child_setup(
    command: &super::ExecCommand,
    report: &Path,
    timeout: Duration,
) -> Result<ExecChildSetupObservation, ExecError> {
    let entry = command.entrypoint();
    let (status_read, status_write) = exec_status_pipe()?;
    let pid = sys::fork_single_threaded(
        || {
            run_exec_child(entry, status_write.as_fd(), |entry, _file| {
                write_setup_report(entry, report).map(|()| 0)
            })
        },
        EXIT_SETUP_FAILED,
    )
    .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "fork"))?;
    drop(status_write);
    let exit = ContainerChild::new(pid).wait_timeout(timeout)?;
    let exit = read_exec_status(&status_read, exit)?;
    let report = match std::fs::read_to_string(report) {
        Ok(text) => Some(parse_setup_report(&text).ok_or_else(|| {
            ExecError::new(
                ErrorCode::Internal,
                IsolationStage::Wait,
                "the exec child wrote a malformed setup report",
            )
        })?),
        Err(_) => None,
    };
    Ok(ExecChildSetupObservation { exit, report })
}

/// 観測の子: `execveat` の直前の自分の状態を `report` へ 1 行ずつ書く（[`observe_exec_child_setup`] 専用）。
#[cfg(all(feature = "exec-test-support", not(test)))]
fn write_setup_report(entry: &Entrypoint, report: &Path) -> Result<(), ExecError> {
    use std::os::unix::fs::FileTypeExt as _;
    let fail = |what: &str| ExecError::new(ErrorCode::Internal, IsolationStage::Exec, what);
    let stat = std::fs::read_to_string("/proc/self/stat").map_err(|_| fail("read own stat"))?;
    // `comm` は括弧・空白を含み得るため、最後の `)` より後ろを読む（state ppid pgrp session tty_nr ...）。
    let rest = stat
        .rfind(')')
        .and_then(|i| stat.get(i + 1..))
        .ok_or_else(|| fail("parse own stat"))?;
    let mut fields = rest.split_whitespace().skip(2);
    let mut next = || fields.next().ok_or_else(|| fail("own stat is too short"));
    let (pgrp, session, tty_nr) = (next()?, next()?, next()?);
    let dev_tty = match std::fs::File::open("/dev/tty") {
        Ok(_) => "open".to_owned(),
        Err(e) => e.raw_os_error().unwrap_or(-1).to_string(),
    };
    let mut text = format!(
        "pid={}\nsession={session}\npgrp={pgrp}\ntty_nr={tty_nr}\ndev_tty={dev_tty}\n",
        std::process::id()
    );
    let (stdin, stdout, stderr) = (std::io::stdin(), std::io::stdout(), std::io::stderr());
    for fd in [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()] {
        let meta = fd
            .try_clone_to_owned()
            .and_then(|owned| std::fs::File::from(owned).metadata())
            .map_err(|_| fail("stat a standard stream"))?;
        text.push_str(&format!(
            "stdio={} {}\n",
            u8::from(meta.file_type().is_char_device()),
            meta.rdev()
        ));
    }
    for var in &entry.env {
        text.push_str(&format!("env={}\n", var.to_string_lossy()));
    }
    // 残っている fd（3 以上）。一覧の読み取りに使うディレクトリの fd は、リンク先が fd ディレクトリ自身になる。
    let own_fd_dir = format!("/proc/{}/fd", std::process::id());
    let mut open: Vec<(i32, String)> = std::fs::read_dir("/proc/self/fd")
        .map_err(|_| fail("list own fds"))?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .filter(|fd| *fd >= 3)
        .filter_map(|fd| {
            let target = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
            Some((fd, target.to_string_lossy().into_owned()))
        })
        .filter(|(_, target)| *target != own_fd_dir)
        .collect();
    open.sort();
    for (fd, target) in open {
        text.push_str(&format!("fd={fd} {target}\n"));
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(report)
        .map_err(|_| fail("create the setup report"))?;
    file.write_all(text.as_bytes())
        .map_err(|_| fail("write the setup report"))
}

/// [`write_setup_report`] の逆変換。形式に合わなければ `None`（呼び出し側が失敗にする）。
#[cfg(all(feature = "exec-test-support", not(test)))]
fn parse_setup_report(text: &str) -> Option<ExecChildSetupReport> {
    let single = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
    };
    let stdio: Vec<(bool, u64)> = text
        .lines()
        .filter_map(|l| l.strip_prefix("stdio="))
        .map(|v| {
            let (kind, rdev) = v.split_once(' ')?;
            Some((kind == "1", rdev.parse().ok()?))
        })
        .collect::<Option<_>>()?;
    Some(ExecChildSetupReport {
        pid: single("pid")?.parse().ok()?,
        session_id: single("session")?.parse().ok()?,
        process_group: single("pgrp")?.parse().ok()?,
        tty_nr: single("tty_nr")?.parse().ok()?,
        dev_tty_errno: match single("dev_tty")? {
            "open" => None,
            errno => Some(errno.parse().ok()?),
        },
        stdio: stdio.try_into().ok()?,
        env: text
            .lines()
            .filter_map(|l| l.strip_prefix("env="))
            .map(str::to_owned)
            .collect(),
        open_fds: text
            .lines()
            .filter_map(|l| l.strip_prefix("fd="))
            .map(|v| {
                let (fd, target) = v.split_once(' ')?;
                Some((fd.parse().ok()?, target.to_owned()))
            })
            .collect::<Option<_>>()?,
    })
}

/// 子のメイン。`establish` → `prepare_rootfs` → `pivot_root` → `exec_entrypoint` を通し、失敗したら
/// stderr に英語 1 行を出して終了コードを返す（戻り値は `_exit` に渡される）。
///
/// ステージ列（#832。`run_child` が pivot 後・exec 前に呼ぶ）と基本デバイス
/// ノード（#834）の差し込み位置は、pivot 後・exec 前（`exec_entrypoint` の直前）を想定する。
/// デバイスノードを pivot の前後どちらで作るかは #834 で決める（本 PR では決めない）。
fn child_main(rootfs: &Path, entry: &Entrypoint, stages: StagePipeline) -> i32 {
    match run_child(rootfs, entry, stages) {
        Ok(never) => match never {},
        Err(err) => {
            // env の値は message に含めない（パスと errno のみ）。stderr が閉じていても panic しない。
            let _ = writeln!(std::io::stderr(), "fandhe-container: {err}");
            exit_code_for(&err)
        }
    }
}

fn run_child(
    rootfs: &Path,
    entry: &Entrypoint,
    stages: StagePipeline,
) -> Result<Infallible, ExecError> {
    run_child_then(rootfs, stages, |isolation, report, capability_report| {
        // `exec_entrypoint` と同じ検証を、capability 削減の結果を添えて行う。
        isolation.verify_caller(IsolationStage::Exec)?;
        require_restriction_evidence(capability_report)?;
        exec_entrypoint_verified(report.new_root_mnt_id, entry)
    })
}

/// 子の前段（`establish` → `prepare_rootfs` → `pivot_root` → ステージ列）を共通化した本体。
///
/// 終端 `terminal` は組み込みステージ（capability 削減・`NO_NEW_PRIVS`・seccomp）の通過後にだけ呼ばれる。
/// 本番の `run_child` は exec を、結合試験専用の [`spawn_container_seccomp_probe`] は exec の代わりに
/// プローブを渡す。exec を呼べるのは `run_child` の終端だけで、fail-closed（`require_restriction_evidence`）
/// は変わらない。
fn run_child_then<T>(
    rootfs: &Path,
    stages: StagePipeline,
    terminal: impl FnOnce(
        &MountIsolation,
        &PivotReport,
        Option<&CapabilityReport>,
    ) -> Result<T, ExecError>,
) -> Result<T, ExecError> {
    let isolation = MountIsolation::establish()?;
    let prepared = prepare_rootfs(&isolation, rootfs)?;
    let report = pivot_root(&isolation, prepared)?;
    // pivot 後・終端前にステージ列を固定順で実行する。
    stages.run_then(|_stage_report, capability_report| {
        terminal(&isolation, &report, capability_report)
    })
}

/// 子のメイン（プローブ版）。失敗は `child_main` と同じ規約で stderr へ 1 行出して終了コードにする。
fn child_main_probe(rootfs: &Path, stages: StagePipeline) -> i32 {
    let result = run_child_then(rootfs, stages, |_isolation, _report, _caps| {
        let record = super::seccomp::probe_denied_syscalls()?;
        publish_probe_record(&record.render())
    });
    match result {
        Ok(()) => 0,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "fandhe-container: {err}");
            exit_code_for(&err)
        }
    }
}

/// 記録を pivot 後の `/seccomp-probe.tmp` へ `create_new` で書き、`/seccomp-probe` へハードリンクして
/// から一時名を消す（`link` は宛先が存在すれば `EEXIST` で失敗するため、既存ファイル・symlink を
/// 上書き・追従しない。`rename` は宛先を黙って置換するため使わない。親はリンク後の完成品だけを読む）。
fn publish_probe_record(text: &str) -> Result<(), ExecError> {
    let fail = |e: std::io::Error| {
        ExecError::new(
            ErrorCode::Internal,
            IsolationStage::Seccomp,
            format!("failed to publish seccomp probe record: {e}"),
        )
    };
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open("/seccomp-probe.tmp")
        .map_err(fail)?;
    f.write_all(text.as_bytes()).map_err(fail)?;
    drop(f);
    let linked = std::fs::hard_link("/seccomp-probe.tmp", "/seccomp-probe");
    // 一時名は成否に関わらず片付ける（リンク失敗を優先して報告する）。
    let removed = std::fs::remove_file("/seccomp-probe.tmp");
    linked.map_err(fail)?;
    removed.map_err(fail)
}

/// 結合試験専用: exec の代わりに禁止 syscall のプローブを実行する子を fork する（CORE-5・TASK-38.4・#179）。
///
/// 呼び出し文脈は `tests/seccomp.rs` のシナリオ（`isolate` 済みの親）。`spawn_container_with_stages` と
/// 同じ前段（pivot 済み・capability 削減・`NO_NEW_PRIVS`・組み込み seccomp）を通した後、終端で
/// `<rootfs>/seccomp-probe` へ記録を書いて終了コード 0 で終わる。exec は呼ばないため、権限は
/// `spawn_container` と同じで昇格経路は増えない。通常の利用者は呼ばない。
///
/// # 将来仕様（記録のみ）
///
/// exec が許可されたら（証跡配線後。後続作業）、エントリポイント内のプローブへ移して本関数は廃止する（REPAIR-3）。
#[doc(hidden)]
pub fn spawn_container_seccomp_probe(
    rootfs: &Path,
    stages: StagePipeline,
) -> Result<ContainerChild, ExecError> {
    let pid = sys::fork_single_threaded(|| child_main_probe(rootfs, stages), EXIT_SETUP_FAILED)
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "fork"))?;
    Ok(ContainerChild::new(pid))
}

/// 結合試験専用: exec の代わりに任意の攻撃プローブを実行する子を fork する（SEC-2・TASK-42.1・#199）。
///
/// 呼び出し文脈は `tests/escape_suite.rs` のシナリオ（`isolate` 済みの親）。`spawn_container_with_stages`
/// と同じ前段（pivot 済み・capability 削減・`NO_NEW_PRIVS`・Landlock〔登録時〕・組み込み seccomp）を
/// 通した**後**にだけ `probe` を呼ぶ。exec は呼ばず `require_restriction_evidence` も迂回しないため、
/// 権限・昇格経路は増えない。前段が失敗した場合は `probe` に到達しない（fail-closed）。通常の利用者は呼ばない。
///
/// # 制限適用証跡の例外（SEC-1・REPAIR-3）
///
/// 本番の `run_child` は終端で `verify_caller` と `require_restriction_evidence` を行うが、後者は証跡型が
/// 未確定の間は常に拒否するため、本関数では `verify_caller` のみ行い `require_restriction_evidence` は
/// 呼ばない（呼ぶとプローブが永久に実行できない）。これは exec を伴わない検証専用経路に限った明示的な例外で、
/// 本関数の成功（終了コード 0）は「制限が適用された証跡」ではなく、本番経路の成功判定・exec 許可の根拠に
/// 使ってはならない。攻撃が拒否されたことの判定は probe 側の観測（fd 経由の結果）だけで行う。
/// 証跡配線後は `require_restriction_evidence` を呼ぶ形へ置き換える。
///
/// # 契約
///
/// - 終了コード: `probe` が正常に戻れば 0、前段失敗は既存規約（`exit_code_for`）、`probe` の panic は
///   `EXIT_SETUP_FAILED`（`fork_single_threaded` の `catch_unwind`）
/// - probe の結果は終了コードではなく、呼び出し側が fork 前に用意した fd（pipe 等）で受け渡す
/// - 単体テストは置かない（fork と分離環境を要するため `tests/escape_suite.rs` の結合試験でカバーする）
///
/// # 将来仕様（記録のみ）
///
/// exec が許可されたら（証跡配線後。後続作業）、エントリポイント内の攻撃プローブへ移して本関数は
/// 廃止する（REPAIR-3）。
///
/// 任意クロージャを分離後の子で実行できるため、cargo feature `escape-probe`（結合試験用に dev-dependency の
/// 自己参照で有効化。通常ビルドには含まれない）でのみ公開する。
#[cfg(feature = "escape-probe")]
#[doc(hidden)]
pub fn spawn_container_probe<F>(
    rootfs: &Path,
    stages: StagePipeline,
    probe: F,
) -> Result<ContainerChild, ExecError>
where
    F: FnOnce(),
{
    let pid = sys::fork_single_threaded(
        move || {
            let result = run_child_then(rootfs, stages, |isolation, _report, _caps| {
                // 本番 `run_child` と同じ呼び出し元検証（PID 1・入れ子 PID namespace・シングルスレッド）を
                // プローブ実行前に行う。`require_restriction_evidence` は意図的に呼ばない（下記の例外）。
                isolation.verify_caller(IsolationStage::Exec)?;
                probe();
                Ok(())
            });
            match result {
                Ok(()) => 0,
                Err(err) => {
                    let _ = writeln!(std::io::stderr(), "fandhe-container: {err}");
                    exit_code_for(&err)
                }
            }
        },
        EXIT_SETUP_FAILED,
    )
    .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "fork"))?;
    Ok(ContainerChild::new(pid))
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
    spawn_container_with_stages(rootfs, entry, StagePipeline::new())
}

/// [`spawn_container`] にステージ列（#832・TASK-27.4.2）を渡す版。
///
/// `stages` は親（fork 前）で構築し、fork で子へコピーされて子の pivot 後・exec 前に固定順で
/// 実行される。フックの失敗・panic では exec に進まず `EXIT_SETUP_FAILED` で終わる。フック無し・
/// ダミーフックでも制限適用の証跡にはならず、exec は引き続き拒否される（fail-closed）。
pub fn spawn_container_with_stages(
    rootfs: &Path,
    entry: &Entrypoint,
    stages: StagePipeline,
) -> Result<ContainerChild, ExecError> {
    let pid = sys::fork_single_threaded(|| child_main(rootfs, entry, stages), EXIT_SETUP_FAILED)
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "fork"))?;
    Ok(ContainerChild::new(pid))
}

/// 待ちのポーリング間隔。
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);
/// `wait_timeout` に渡せる最大値（`Instant` の加算オーバーフローを避けるための丸め）。
const WAIT_TIMEOUT_MAX: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// `SIGKILL` 後に回収を待つ上限。
const KILL_REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// 子の回収状態（[`ContainerChild`] の `Mutex` が保護する）。
///
/// 遷移は `Running` → `Killed` → `Reaped`、`Running` → `Reaped`、または `Running` / `Killed` → `Lost` の
/// 一方向のみ。`Reaped` と `Lost` の後は pid がカーネルに返却済みで別プロセスへ再利用され得るため、
/// `kill` も `waitpid` も呼ばない（終端状態）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReapState {
    /// 未回収で、期限超過の `SIGKILL` もまだ送っていない。
    Running,
    /// 期限超過で `SIGKILL` を送った（または送る前に消えていた）が未回収。`SIGKILL` を二重に送らない。
    Killed,
    /// 回収済み。`killed` は期限超過の `SIGKILL` の後に回収したか（`Timeout` の判定に使う）。
    Reaped { exit: ChildExit, killed: bool },
    /// 契約外の回収者に回収された（`waitpid` が `ECHILD`、または `kill` が `ESRCH`）。終了状態は失われ、
    /// pid は再利用され得るため以後 `kill` も `waitpid` も呼ばない終端状態。
    Lost,
}

/// [`ContainerChild::send_signal`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignalDelivery {
    /// 未回収の子へシグナルを送った（終了は待たない）。
    Delivered,
    /// 既に回収済みのため送らなかった（記録済みの終了状態）。
    AlreadyExited(ChildExit),
    /// 子が既に存在しなかった（`ESRCH`。契約外の回収者による回収）ため送らなかった。
    Gone,
}

/// `Mutex` の中身。`kills_sent` は実際に送った `SIGKILL` の回数（高々 1。テストの照合用）。
#[derive(Debug)]
struct ReapCell {
    state: ReapState,
    kills_sent: u32,
}

/// 回収を観測した結果（終了状態と、期限超過の `SIGKILL` の後だったか）。
type Observed = (ChildExit, bool);

/// fork した子（コンテナの PID 1）のハンドル。
///
/// # 回収と kill の排他（PID 再利用対策。CORE-1・REPAIR-5）
///
/// `waitpid` による回収と期限超過の `SIGKILL` は、どちらも内部の `Mutex` を取った 1 ステップの中で
/// 回収状態（`ReapState`）を確認・更新して行う。回収済み（`Reaped`）なら `kill` を送らないため、
/// 複数スレッドが同じハンドルで並行に待っても、回収後に解放・再利用された pid へ `SIGKILL` が届く
/// ことはない（回収前はゾンビが pid を保持するので再利用されない）。ロックは 1 回の
/// `waitpid(WNOHANG)` / `kill` の間だけ持ち、ポーリングの sleep 中は持たない（各呼び出し元の期限を
/// 守る）。この保証は「このハンドルが当該 pid の唯一の回収者」であることを前提とし、同じプロセスの
/// 他所での `waitpid(-1)`・`SIGCHLD` の `SIG_IGN` / `SA_NOCLDWAIT` による自動回収は契約外。
/// 契約外の回収との競合に備え、シグナルは fork 直後に開いた pidfd 経由で送る（`pidfd_send_signal`。
/// 回収・pid 再利用後は `ESRCH` になり無関係なプロセスへ届かない）。pidfd を開けない環境（Linux 5.3 未満・
/// seccomp 等）でのみ `kill(2)` へ退避し、その場合は上記の前提に依存する。
///
/// `Drop` では kill / wait しない（コンテナの寿命を親ハンドルに暗黙で縛らない）。回収の責任は
/// 呼び出し元にあり、放置すると子はゾンビとして残る。
#[must_use]
#[derive(Debug)]
pub struct ContainerChild {
    pid: u32,
    /// fork 直後に開いた pidfd（プロセス同一性の保持。開けない環境では `None` で `kill(2)` へ退避）。
    pidfd: Option<OwnedFd>,
    reap: Mutex<ReapCell>,
}

impl ContainerChild {
    /// fork 直後の未回収の子のハンドルを作る（`exec` の rootless mapper の回収にも使う）。
    pub(super) fn new(pid: u32) -> Self {
        Self {
            pid,
            // 回収前（fork 直後）に開くので、以後 pid が再利用されても元のプロセスを指し続ける。
            // 未対応カーネル・seccomp 等で開けなければ `None`（`signal_child` が `kill(2)` へ退避）。
            pidfd: sys::pidfd_open(pid).ok(),
            reap: Mutex::new(ReapCell {
                state: ReapState::Running,
                kills_sent: 0,
            }),
        }
    }

    /// 任意の pid からハンドルを作る（crate 内テスト専用。`oci_runtime` のアダプタの試験に使う）。
    #[cfg(test)]
    pub(crate) fn from_pid_for_test(pid: u32) -> Self {
        Self::new(pid)
    }

    /// 子のプロセス ID（親の PID namespace での値）。回収済みなら別プロセスに再利用され得る。
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// 子の終了を `timeout` まで待つ（REPAIR-5）。
    ///
    /// - 期限内に終われば終了状態を返す（別スレッドの待機が回収した場合も同じ値を返す）
    /// - 期限を超えたら、未回収に限り `SIGKILL` を 1 回だけ送って回収し、`ErrorCode::Timeout`
    ///   （段は `Wait`）で返す。自分の期限内に別スレッドの `SIGKILL` で回収された場合は
    ///   `Ok(ChildExit::Signaled(9))` になる
    /// - 回収済みのハンドルに再度呼ぶと、`waitpid` / `kill` を呼ばずに記録済みの終了状態を `Ok` で返す
    ///   （期限超過で kill した後なら `Signaled(9)`）。`Timeout` になるのは、その呼び出し自身の期限が
    ///   終了の観測より先に切れた場合だけ（最初の観測は期限の確認より前に行うため、期限 0 でも回収済みなら `Ok`）
    /// - ハンドルを消費しない（`&self`）。`waitpid` / `kill` が失敗して `Err` で戻っても回収状態は
    ///   変わらず、呼び出し元は同じハンドルで再試行（kill・回収）できる
    ///
    /// `waitpid(WNOHANG)` を 10ms 間隔でポーリングする（`EINTR` でも毎回期限を確認する）。
    /// `timeout` は 7 日に丸める。
    pub fn wait_timeout(&self, timeout: Duration) -> Result<ChildExit, ExecError> {
        const STAGE: IsolationStage = IsolationStage::Wait;
        let timed_out = || {
            ExecError::new(
                ErrorCode::Timeout,
                STAGE,
                format!("the container process did not exit within {timeout:?}; killed"),
            )
        };
        let deadline = Instant::now() + timeout.min(WAIT_TIMEOUT_MAX);
        // 期限内に観測できた。期限切れの別スレッドが kill した結果でも、自分の期限内なので `Ok`。
        if let Some((exit, _)) = self.poll_until(deadline)? {
            return Ok(exit);
        }
        // 期限超過: 未回収なら SIGKILL（ロック下で状態を確認して送る。回収済みなら送らない）。
        if let Some((exit, killed)) = self.kill_if_unreaped()? {
            return if killed { Err(timed_out()) } else { Ok(exit) };
        }
        match self.poll_until(Instant::now() + KILL_REAP_TIMEOUT)? {
            Some(_) => Err(timed_out()),
            None => Err(ExecError::new(
                ErrorCode::Internal,
                STAGE,
                "the container process did not exit after SIGKILL",
            )),
        }
    }

    /// 子の終了を `timeout` まで待つが、期限を過ぎても kill しない（監視用。REPAIR-5・CORE-1）。
    ///
    /// start から起動済みプロセスのハンドルを引き取った所有者（supervisor 等）が、コンテナの終了を
    /// 監視・回収するために使う（`oci_runtime::ContainerChildProcess` の `LaunchedProcess::wait`）。
    /// [`Self::wait_timeout`] と同じ回収状態の排他（`poll_until`）で回収する。
    ///
    /// - 期限内に終われば回収して `Ok(Some(終了状態))`（回収済みなら `waitpid` せず記録を返す）
    /// - 期限までに終わらなければ `Ok(None)`。子はそのまま動き続け、同じハンドルで再び待てる
    ///
    /// `timeout` は 7 日に丸める。
    pub fn wait_for_exit(&self, timeout: Duration) -> Result<Option<ChildExit>, ExecError> {
        let deadline = Instant::now() + timeout.min(WAIT_TIMEOUT_MAX);
        Ok(self.poll_until(deadline)?.map(|(exit, _)| exit))
    }

    /// 子を待たずに終了させ、`timeout` まで回収を待つ（REPAIR-5。状態記録に失敗した起動の後始末用）。
    ///
    /// `oci_runtime` の start が起動後の状態記録に失敗したとき、`LaunchedProcess::terminate` の実装
    /// （`oci_runtime::ContainerChildProcess`）から呼ばれる。[`Self::wait_timeout`] と同じ回収状態の
    /// 排他（`kill_if_unreaped` → `poll_until`）を使うため、回収済み（pid 再利用され得る）の子へは
    /// `SIGKILL` を送らない。
    ///
    /// - 回収済みなら `kill` せず `Ok`（記録済みの終了状態）
    /// - 未回収なら `SIGKILL` を 1 回だけ送り、`timeout` までに回収できれば `Ok`
    /// - `timeout` までに回収できなければ `ErrorCode::Timeout`。回収状態は `Killed` のまま残り、
    ///   同じハンドルで再試行（回収）できる
    ///
    /// [`Self::wait_timeout`] の `KILL_REAP_TIMEOUT`（固定 5 秒）ではなく呼び出し側の `timeout` を使う
    /// （呼び出し側の上限を超えて待たない）。`timeout` は 7 日に丸める。
    pub fn kill_and_reap(&self, timeout: Duration) -> Result<ChildExit, ExecError> {
        let deadline = Instant::now() + timeout.min(WAIT_TIMEOUT_MAX);
        if let Some((exit, _)) = self.kill_if_unreaped()? {
            return Ok(exit);
        }
        match self.poll_until(deadline)? {
            Some((exit, _)) => Ok(exit),
            None => Err(ExecError::new(
                ErrorCode::Timeout,
                IsolationStage::Wait,
                format!("the container process was not reaped within {timeout:?} after SIGKILL"),
            )),
        }
    }

    /// 未回収の子へシグナルを 1 つ送る（`oci_runtime::kill` の `ContainerChildProcess::signal` から呼ばれる。
    /// CORE-2・OCI-6・TASK-30.1）。
    ///
    /// 回収状態のロック下で状態を確認してから `kill` するため、回収済みの pid（別プロセスへ再利用され得る）
    /// には送らない（[`Self::kill_and_reap`] と同じ排他。CORE-1）。回収済みなら送らずに
    /// [`SignalDelivery::AlreadyExited`]、契約外の回収者に回収されていた（`ESRCH`）場合も送らずに
    /// 終了済み扱いで [`SignalDelivery::Gone`] を返す（回収状態は終端の `Lost` へ進め、以後 `waitpid` も `kill` も行わない）。終了済みで未回収
    /// （ゾンビ）の子は、ここで `waitpid(WNOHANG)` で回収して [`SignalDelivery::AlreadyExited`] を返す
    /// （`kill(2)` はゾンビにも成功するが効かないため `Delivered` と誤報しない）。終了は待たない。
    pub fn send_signal(&self, number: std::num::NonZeroU8) -> Result<SignalDelivery, ExecError> {
        let mut cell = self.lock();
        self.send_signal_locked(&mut cell, number)
    }

    /// [`Self::send_signal`] に送信期限 `deadline` を付けた版（REPAIR-5・TASK-30.1）。
    ///
    /// ロック待ちが `deadline` を超えた場合、またはロック取得時点で期限切れの場合は、呼び出し側が既に
    /// `Timeout` を観測済みのため送信を抑止して `Timeout` を返す（期限後にシグナルが届かない）。
    pub fn send_signal_until(
        &self,
        number: std::num::NonZeroU8,
        deadline: Instant,
    ) -> Result<SignalDelivery, ExecError> {
        const STAGE: IsolationStage = IsolationStage::Wait;
        let expired = || {
            ExecError::new(
                ErrorCode::Timeout,
                STAGE,
                "the signal was not sent before the deadline",
            )
        };
        let mut cell = loop {
            match self.reap.try_lock() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::Poisoned(p)) => break p.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(expired());
                    }
                    std::thread::sleep(Duration::from_millis(1).min(deadline - now));
                }
            }
        };
        if Instant::now() >= deadline {
            return Err(expired());
        }
        self.send_signal_locked(&mut cell, number)
    }

    /// 子へシグナルを送る。pidfd があれば `pidfd_send_signal` で送り、回収後に再利用された pid へ
    /// 届かないようにする（契約外の回収者との競合でも `ESRCH` になる。CORE-1）。pidfd が無い環境では
    /// `kill(2)` へ退避する（この場合は「唯一の回収者」前提が残る）。
    fn signal_child(&self, sig: Signal) -> Result<(), SysError> {
        match &self.pidfd {
            Some(fd) => sys::pidfd_send_signal(fd.as_fd(), sig),
            None => sys::kill_pid(self.pid, sig),
        }
    }

    /// ロックを保持した状態での送信本体。未回収でも終了済み（ゾンビ）の子には送らず、ここで回収する
    /// （ゾンビへの `kill(2)` は成功するがシグナルは効かないため、`Delivered` と誤報しない）。
    fn send_signal_locked(
        &self,
        cell: &mut ReapCell,
        number: std::num::NonZeroU8,
    ) -> Result<SignalDelivery, ExecError> {
        match cell.state {
            ReapState::Reaped { exit, .. } => return Ok(SignalDelivery::AlreadyExited(exit)),
            ReapState::Lost => return Ok(SignalDelivery::Gone),
            ReapState::Running | ReapState::Killed => {}
        }
        let polled = sys::wait_pid_nohang(self.pid);
        if matches!(polled, Err(SysError::Os(e)) if e == sys::ECHILD) {
            // 契約外の回収者が既に回収していた（`waitpid` が `ECHILD`）。pid が再利用され得るため
            // `kill` は送らず、`ESRCH` と同じく以後の送信・回収を行わない終端状態（`Lost`）へ進める。
            cell.state = ReapState::Lost;
            return Ok(SignalDelivery::Gone);
        }
        if let Some((exit, _)) = Self::apply_wait(cell, polled)? {
            return Ok(SignalDelivery::AlreadyExited(exit));
        }
        match self.signal_child(Signal::Number(number)) {
            Ok(()) => Ok(SignalDelivery::Delivered),
            Err(SysError::Os(e)) if e == sys::ESRCH => {
                // 契約外の回収者に回収された。pid が再利用され得るため、以後の送信・回収を
                // 行わない終端状態（`Lost`）へ進める（`kill_if_unreaped` と同じ扱い）。
                cell.state = ReapState::Lost;
                Ok(SignalDelivery::Gone)
            }
            Err(e) => Err(ExecError::from_sys(e, IsolationStage::Wait, "kill(signal)")),
        }
    }

    /// 回収状態のロックを取る。
    ///
    /// ロック中の処理（`waitpid` / `kill` のラッパーと状態の単一代入）は panic しないため、poison
    /// されても中身は整合している。ライブラリで panic させないよう poison は中身を取り出して続行する。
    fn lock(&self) -> MutexGuard<'_, ReapCell> {
        self.reap.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// ロック下で 1 回だけ回収を試みる。回収済みなら `waitpid` せず記録を返す。未終了・`EINTR` は
    /// `Ok(None)`（呼び出し側が期限を確認する）。失敗しても状態は変えない（再試行できる）。
    fn try_reap(&self) -> Result<Option<Observed>, ExecError> {
        let mut cell = self.lock();
        self.reap_locked(&mut cell)
    }

    /// ロック保持中に 1 回だけ回収を試みる（[`Self::try_reap`] の本体）。
    fn reap_locked(&self, cell: &mut ReapCell) -> Result<Option<Observed>, ExecError> {
        match cell.state {
            ReapState::Reaped { exit, killed } => return Ok(Some((exit, killed))),
            ReapState::Lost => {
                return Err(ExecError::new(
                    ErrorCode::Internal,
                    IsolationStage::Wait,
                    "the container process was already reaped by another party",
                ));
            }
            ReapState::Running | ReapState::Killed => {}
        }
        Self::apply_wait(cell, sys::wait_pid_nohang(self.pid))
    }

    /// `waitpid(WNOHANG)` の結果を回収状態へ反映する（[`Self::reap_locked`] の本体。ロック保持中）。
    fn apply_wait(
        cell: &mut ReapCell,
        polled: Result<Option<i32>, SysError>,
    ) -> Result<Option<Observed>, ExecError> {
        const STAGE: IsolationStage = IsolationStage::Wait;
        match polled {
            Ok(Some(status)) => {
                // stopped / continued は回収ではない（pid は保持されたまま）ので状態を変えずにエラー。
                let exit = decode_wait_status(status).ok_or_else(|| {
                    ExecError::new(
                        ErrorCode::Internal,
                        STAGE,
                        "the container process changed state without exiting",
                    )
                })?;
                let killed = cell.state == ReapState::Killed;
                cell.state = ReapState::Reaped { exit, killed };
                Ok(Some((exit, killed)))
            }
            Ok(None) => Ok(None),
            Err(SysError::Os(e)) if e == sys::EINTR => Ok(None),
            Err(e) => Err(ExecError::from_sys(e, STAGE, "waitpid")),
        }
    }

    /// ロック下で、未回収かつ未 kill のときだけ `SIGKILL` を送る。回収済みなら送らずに記録を返す。
    /// `kill` の失敗（`ESRCH` 以外）は状態を `Running` のまま返す（呼び出し元が再試行できる）。
    fn kill_if_unreaped(&self) -> Result<Option<Observed>, ExecError> {
        let mut cell = self.lock();
        match cell.state {
            ReapState::Reaped { exit, killed } => return Ok(Some((exit, killed))),
            ReapState::Killed | ReapState::Lost => return Ok(None),
            ReapState::Running => {}
        }
        match self.signal_child(Signal::Kill) {
            Ok(()) => cell.kills_sent = cell.kills_sent.saturating_add(1),
            // 未回収の子が ESRCH になるのは契約外の回収者に回収された場合のみ。以後 kill しない。
            Err(SysError::Os(e)) if e == sys::ESRCH => {
                cell.state = ReapState::Lost;
                return Ok(None);
            }
            Err(e) => {
                return Err(ExecError::from_sys(
                    e,
                    IsolationStage::Wait,
                    "kill(SIGKILL)",
                ));
            }
        }
        cell.state = ReapState::Killed;
        Ok(None)
    }

    /// `deadline` まで回収をポーリングする。観測できれば `Some`、期限なら `None`。
    fn poll_until(&self, deadline: Instant) -> Result<Option<Observed>, ExecError> {
        loop {
            if let Some(observed) = self.try_reap()? {
                return Ok(Some(observed));
            }
            // シグナル割り込み（EINTR）でも期限は必ず確認する（連続 EINTR で SIGKILL 未到達を防ぐ）。
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            std::thread::sleep(WAIT_POLL_INTERVAL.min(deadline - now));
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

    /// テスト用の一時ディレクトリ（drop で削除）。
    ///
    /// 共有 temp 配下の予測可能な名前への事前配置（symlink 差し替え）を防ぐため、名前に時刻と連番を
    /// 混ぜ、`mkdir`（既存なら失敗・リンクを辿らない）で排他的に作る。中のファイルは呼び出し側が
    /// `create_new`（`O_EXCL`）で作る。
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn create(label: &str) -> Self {
            static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let base = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "fandhe-{label}-{}-{nanos}-{seq}",
                    std::process::id()
                ));
            std::fs::create_dir(&base).unwrap();
            Self(base)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// std の `Child` を kill して期限付きで回収する（REPAIR-5。期限内に回収できなければ失敗）。
    fn kill_and_reap(child: &mut std::process::Child) {
        let _ = child.kill();
        let deadline = Instant::now() + KILL_REAP_TIMEOUT;
        while child.try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "the child was not reaped after SIGKILL"
            );
            std::thread::sleep(WAIT_POLL_INTERVAL);
        }
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

    /// SEC-1・CORE-5: 制限ステージの証跡が無い間は、継承された制限の有無にかかわらず exec を拒否する。
    #[test]
    fn sec1_exec_is_denied_without_restriction_evidence() {
        let err = require_restriction_evidence(None).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.stage, IsolationStage::Exec);
        assert_eq!(exit_code_for(&err), EXIT_EXEC_NOT_EXECUTABLE);
    }

    /// CORE-1・TASK-27.4.2: ステージの失敗（各段）は子の終了コード 125 になる。
    #[test]
    fn core1_failed_stage_maps_to_setup_exit_code() {
        for stage in [
            IsolationStage::CgroupJoin,
            IsolationStage::CapabilityDrop,
            IsolationStage::NoNewPrivs,
            IsolationStage::Landlock,
            IsolationStage::Seccomp,
        ] {
            let err = ExecError::new(ErrorCode::Internal, stage, "x");
            assert_eq!(exit_code_for(&err), EXIT_SETUP_FAILED);
        }
    }

    /// CORE-1・SEC-1（TASK-27.4.2）: 全段のダミーフックが `Ok` でも、exec の拒否（証跡要求）は解除されない。
    #[test]
    fn core1_stage_report_is_not_restriction_evidence() {
        use crate::exec::StageKind;
        let mut p = StagePipeline::new();
        for kind in StageKind::ORDER.iter().copied().filter(|k| !k.is_builtin()) {
            p = p.with_hook(kind, || Ok(())).unwrap();
        }
        let err = p
            .run_then(|_report, caps| require_restriction_evidence(caps))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.stage, IsolationStage::Exec);
    }

    /// CORE-1・SEC-1: 継承した標準入出力と同一 inode の判定は `(dev, ino)` の完全一致だけを真にする。
    #[test]
    fn core1_matches_any_identity_is_exact() {
        assert!(matches_any_identity((1, 2), &[(3, 4), (1, 2)]));
        assert!(!matches_any_identity((1, 2), &[(1, 3), (2, 2)]));
        assert!(!matches_any_identity((1, 2), &[]));
    }

    /// SEC-1・CORE-1（TASK-27.4.1）: 標準 fd の確認結果の分類。取得できた実体は照合対象、閉じている
    /// 番号（`EBADF`）は除外、それ以外の失敗（`EMFILE`・`EIO`）は確認できないため exec を拒否する。
    #[test]
    fn sec1_classify_stdio_probe_is_fail_closed() {
        assert_eq!(classify_stdio_probe(0, Ok((7, 11))).unwrap(), Some((7, 11)));
        assert_eq!(
            classify_stdio_probe(1, Err(std::io::Error::from_raw_os_error(sys::EBADF))).unwrap(),
            None
        );
        for errno in [24, 5] {
            let err =
                classify_stdio_probe(2, Err(std::io::Error::from_raw_os_error(errno))).unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied, "errno {errno}");
            assert_eq!(err.stage, IsolationStage::Exec, "errno {errno}");
            assert_eq!(
                exit_code_for(&err),
                EXIT_EXEC_NOT_EXECUTABLE,
                "errno {errno}"
            );
        }
    }

    /// SEC-1・CORE-1（TASK-27.4.1）: 開いている標準 fd（`/proc/self/fd/{0,1,2}` が存在する番号）は
    /// すべて照合対象になり、確認失敗が無ければ欠けない。
    #[test]
    fn sec1_inherited_stdio_identities_cover_open_streams() {
        let open = (0..3)
            .filter(|n| std::fs::symlink_metadata(format!("/proc/self/fd/{n}")).is_ok())
            .count();
        assert_eq!(inherited_stdio_identities().unwrap().len(), open);
    }

    /// CORE-1（TASK-27.4.1）: 3 以上の fd は番号を変えずに返す。0〜2 の fd の移動は、テストプロセスの
    /// 標準 fd を閉じられないため結合試験の範囲。
    #[test]
    fn core1_keep_above_stdio_keeps_high_fd() {
        use std::os::fd::AsRawFd as _;
        let fd = std::io::stdin().as_fd().try_clone_to_owned().unwrap();
        let raw = fd.as_raw_fd();
        assert!(raw > 2, "std dup starts at 3; got {raw}");
        assert_eq!(keep_above_stdio(fd).unwrap().as_raw_fd(), raw);
    }

    /// 実 `/` の procfs（検証済み）。
    fn real_procfs() -> OwnedFd {
        open_root_procfs(dir_fd(Path::new("/")).as_fd()).unwrap()
    }

    fn dir_fd(path: &Path) -> OwnedFd {
        OwnedFd::from(std::fs::File::open(path).unwrap())
    }

    /// 違反 `stdio_null_not_null_device`（`PermissionDenied`・段 `Exec`・SEC-1）であることを照合する。
    fn assert_null_violation(err: &ExecError) {
        assert_eq!(
            (err.code, err.stage),
            (ErrorCode::PermissionDenied, IsolationStage::Exec)
        );
        let v = err.violation.as_ref().expect("violation record");
        assert_eq!(v.reason, ViolationReason::StdioNullNotNullDevice);
        assert_eq!(v.reason.as_str(), "stdio_null_not_null_device");
        assert_eq!(v.behavior_id, "SEC-1");
        assert_eq!(exit_code_for(err), EXIT_EXEC_NOT_EXECUTABLE);
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1459）: 実 `/dev/null` は検証を通り、開き直した fd は読み書きできる
    /// 文字デバイス 1:3。開き直しは検証の後に 1 回だけ起きる。
    #[test]
    fn sup6_sec1_task163_verified_null_is_reopened_read_write() {
        use std::io::Read as _;
        use std::os::unix::fs::FileTypeExt as _;
        let _ = take_calls();
        let null =
            open_verified_null(dir_fd(Path::new("/")).as_fd(), real_procfs().as_fd()).unwrap();
        assert_eq!(take_calls(), vec!["reopen(/dev/null)".to_string()]);
        let mut file = std::fs::File::from(null);
        let meta = file.metadata().unwrap();
        assert!(meta.file_type().is_char_device());
        assert_eq!(meta.rdev(), sys::makedev(1, 3));
        assert_eq!(file.write(b"discarded").unwrap(), 9);
        let mut buf = [0u8; 4];
        assert_eq!(file.read(&mut buf).unwrap(), 0);
    }

    /// SUP-6・SEC-1・SEC-4・TASK-163 追補（#1459）: `/dev/null` が symlink・通常ファイル・別のデバイスノードへ
    /// 差し替えられていたら、対象を開かずに（開き直しに進まずに）違反として拒否する。
    #[test]
    fn sup6_sec1_task163_replaced_null_is_rejected_without_opening_it() {
        let dir = TempDir::create("dev-null");
        let dev = dir.0.join("dev");
        std::fs::create_dir(&dev).unwrap();
        let _ = take_calls();

        // symlink（本物の null デバイスを指していても、symlink 自体を拒否する）。
        for target in ["/dev/zero", "/dev/null"] {
            std::os::unix::fs::symlink(target, dev.join("null")).unwrap();
            let err = pin_null_device(dir_fd(&dev).as_fd(), c"null").unwrap_err();
            assert_null_violation(&err);
            let err =
                open_verified_null(dir_fd(&dir.0).as_fd(), real_procfs().as_fd()).unwrap_err();
            assert_null_violation(&err);
            std::fs::remove_file(dev.join("null")).unwrap();
        }

        // 通常ファイル。
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dev.join("null"))
            .unwrap();
        let err = open_verified_null(dir_fd(&dir.0).as_fd(), real_procfs().as_fd()).unwrap_err();
        assert_null_violation(&err);

        // 別のデバイスノード（実 `/dev` の `zero` = 1:5 を `null` の名前の代わりに検査する。非特権では
        // デバイスノードを作れないため、名前を差し替えて同じ検査を通す）。
        let err = pin_null_device(dir_fd(Path::new("/dev")).as_fd(), c"zero").unwrap_err();
        assert_null_violation(&err);
        // 対照: 同じ検査が本物の `null` は通す。
        pin_null_device(dir_fd(Path::new("/dev")).as_fd(), c"null").unwrap();

        // どの拒否でも開き直しには進んでいない（対象を開いていない）。
        assert_eq!(take_calls(), Vec::<String>::new());
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1459）: `/dev` が symlink・`/dev/null` が不在・`/proc` が procfs でない
    /// rootfs は `FailedPrecondition` で拒否する（fail-closed。別の実体を標準入出力にしない）。
    #[test]
    fn sup6_sec1_task163_null_requires_real_dev_and_procfs() {
        let dir = TempDir::create("dev-null-pre");
        let _ = take_calls();
        // `/dev` が無い。
        let err = open_verified_null(dir_fd(&dir.0).as_fd(), real_procfs().as_fd()).unwrap_err();
        assert_eq!(
            (err.code, err.stage),
            (ErrorCode::FailedPrecondition, IsolationStage::Exec)
        );
        // `/dev` が symlink（本物の `/dev` を指していても辿らない）。
        std::os::unix::fs::symlink("/dev", dir.0.join("dev")).unwrap();
        let err = open_verified_null(dir_fd(&dir.0).as_fd(), real_procfs().as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(err.message.starts_with("cannot open /dev as a directory"));
        std::fs::remove_file(dir.0.join("dev")).unwrap();
        // `/dev/null` が不在。
        std::fs::create_dir(dir.0.join("dev")).unwrap();
        let err = open_verified_null(dir_fd(&dir.0).as_fd(), real_procfs().as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(err.message.starts_with("cannot find /dev/null"));
        assert_eq!(take_calls(), Vec::<String>::new());

        // `/proc` が無い・procfs でない（通常のディレクトリ）・symlink の rootfs は、開き直しの起点にしない。
        let rejected = |root: &Path| {
            let err = open_root_procfs(dir_fd(root).as_fd()).unwrap_err();
            assert_eq!(
                (err.code, err.stage),
                (ErrorCode::FailedPrecondition, IsolationStage::Exec)
            );
            assert_eq!(
                err.message,
                "/proc in the new root is not procfs; cannot reopen a verified file"
            );
        };
        rejected(&dir.0);
        std::fs::create_dir(dir.0.join("proc")).unwrap();
        rejected(&dir.0);
        std::fs::remove_dir(dir.0.join("proc")).unwrap();
        std::os::unix::fs::symlink("/proc", dir.0.join("proc")).unwrap();
        rejected(&dir.0);
        // 対照: 本物の procfs は起点にでき、固定した fd を開き直せる。
        let procfs = open_root_procfs(dir_fd(Path::new("/")).as_fd()).unwrap();
        let pinned = pin_null_device(dir_fd(Path::new("/dev")).as_fd(), c"null").unwrap();
        reopen_null_device(procfs.as_fd(), pinned.as_fd()).unwrap();
    }

    /// CORE-1（TASK-27.4.1）: シェバン付きスクリプトの `/dev/fd/N` の検証。`N` が開いた fd と同じ実体に
    /// 解決すれば許可し、存在しない・別の実体なら `FailedPrecondition`（終了コード 126）で拒否する。
    #[test]
    fn core1_verify_script_fd_path_requires_same_file() {
        use std::os::fd::AsRawFd as _;
        let dir = TempDir::create("script-fd");
        let script = dir.0.join("script");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&script)
            .unwrap();
        let file = std::fs::File::open(&script).unwrap();
        let meta = file.metadata().unwrap();
        let entry = Entrypoint::new(&script, ["script"], [] as [&str; 0]).unwrap();

        // /proc/self/fd は /dev/fd の参照先で、N は開いた fd 自身に解決する。
        verify_script_fd_path(Path::new("/proc/self/fd"), &file, &meta, &entry).unwrap();

        // /dev/fd の無い rootfs（空ディレクトリ）は拒否する。
        let empty = dir.0.join("empty");
        std::fs::create_dir(&empty).unwrap();
        let err = verify_script_fd_path(&empty, &file, &meta, &entry).unwrap_err();
        assert_eq!(
            (err.code, err.stage),
            (ErrorCode::FailedPrecondition, IsolationStage::Exec)
        );
        assert_eq!(exit_code_for(&err), EXIT_EXEC_NOT_EXECUTABLE);

        // 同じ番号が別の実体を指す場合も拒否する。
        let other = dir.0.join("other");
        std::fs::create_dir(&other).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(other.join(file.as_raw_fd().to_string()))
            .unwrap();
        let err = verify_script_fd_path(&other, &file, &meta, &entry).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
    }

    /// CORE-1（TASK-27.4.1）: dry-run で exec 前の処理が固定順に呼ばれ、`execve` に argv・env が
    /// そのまま渡る。dry-run の `execve` は `EINTR` を返すので `Internal` の `Exec` 段エラーになる。
    #[test]
    fn core1_exec_runs_steps_in_fixed_order() {
        let dir = TempDir::create("exec-order");
        let bin = dir.0.join("probe");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&bin)
            .unwrap();
        let entry = Entrypoint::new(&bin, ["probe", "-x"], ["K=V"]).unwrap();
        let _ = take_calls();
        let err = exec_entrypoint_verified(current_root_mnt_id(), &entry).unwrap_err();
        let calls = take_calls();
        drop(dir);
        assert_eq!(err.stage, IsolationStage::Exec);
        assert_eq!(err.code, ErrorCode::Internal);
        assert_eq!(
            calls,
            vec![
                "close_range(3,close)".to_string(),
                "setsid".to_string(),
                "close_range(3)".to_string(),
                "signal(SIGPIPE,SIG_DFL)".to_string(),
                "stdio->/dev/null".to_string(),
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
            assert_eq!(
                take_calls(),
                vec!["close_range(3,close)".to_string(), "setsid".to_string()],
                "{path:?}"
            );
        }
    }

    /// SUP-6・SEC-1・SEC-4・TASK-163 追補（#1458）: インタープリタがランタイム自身に解決されるスクリプト
    /// （`#!/proc/self/exe`）は、エントリポイント本体が別のファイルでも違反として拒否し、`execve` は呼ばない
    /// （launch と exec が共有する手順の中で拒否される。終了コードは 126）。
    #[test]
    fn sup6_sec1_task163_exec_rejects_script_interpreted_by_runtime_binary() {
        let dir = TempDir::create("exec-interp");
        let script = dir.0.join("script");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&script)
            .unwrap()
            .write_all(b"#!/proc/self/exe\n")
            .unwrap();
        let entry = Entrypoint::new(&script, ["script"], [] as [&str; 0]).unwrap();
        let _ = take_calls();
        let err = exec_entrypoint_verified(current_root_mnt_id(), &entry).unwrap_err();
        assert_eq!(
            (err.code, err.stage),
            (ErrorCode::PermissionDenied, IsolationStage::Exec)
        );
        assert_eq!(exit_code_for(&err), EXIT_EXEC_NOT_EXECUTABLE);
        let v = err.violation.expect("violation record");
        assert_eq!(
            v.reason,
            ViolationReason::EntrypointInterpreterIsRuntimeBinary
        );
        assert_eq!(v.behavior_id, "SEC-1");
        assert_eq!(
            take_calls(),
            vec!["close_range(3,close)".to_string(), "setsid".to_string()]
        );
    }

    /// SUP-6・REPAIR-3・TASK-163 追補（#1460）: 子が pipe へ残した内容からの判定の具体値。`R` の 1 行だけなら
    /// コマンドは起動した（終了コードが 125〜127 でも「コマンド自身の終了コード」）。失敗の行があるか、何も
    /// 無ければ起動していない。違反の理由コードは `execveat` 前の手順が返すものだけを引き直す。
    #[test]
    fn sup6_task163_classify_exec_status_is_exact() {
        let failed = |exit, violation| ExecExit::SetupFailed { exit, violation };
        for code in [0, 1, 125, 126, 127] {
            let exit = ChildExit::Exited(code);
            assert_eq!(classify_exec_status(b"R\n", exit), ExecExit::Command(exit));
            // 手順の途中で終了した（何も書いていない）。
            assert_eq!(classify_exec_status(b"", exit), failed(exit, None));
        }
        let signaled = ChildExit::Signaled(15);
        assert_eq!(
            classify_exec_status(b"R\n", signaled),
            ExecExit::Command(signaled)
        );
        assert_eq!(classify_exec_status(b"", signaled), failed(signaled, None));

        let exit = ChildExit::Exited(126);
        assert_eq!(classify_exec_status(b"126 -\n", exit), failed(exit, None));
        // `execveat` 自体の失敗（`R` の後に失敗の行）。
        assert_eq!(
            classify_exec_status(b"R\n126 -\n", exit),
            failed(exit, None)
        );
        for reason in EXEC_CHILD_VIOLATIONS {
            let line = format!("126 {}\n", reason.as_str());
            assert_eq!(
                classify_exec_status(line.as_bytes(), exit),
                failed(exit, Some(reason))
            );
            assert_eq!(reason.kind().as_str(), "entrypoint");
        }
        assert_eq!(
            classify_exec_status(b"126 entrypoint_interpreter_is_runtime_binary\n", exit),
            failed(
                exit,
                Some(ViolationReason::EntrypointInterpreterIsRuntimeBinary)
            )
        );
        // 解釈できない内容・子が返さないはずの理由コード・切れた行は、起動していない扱い（理由なし）。
        for garbage in [
            &b"R"[..],
            b"RR\n",
            b"\n",
            b"garbage",
            b"126 rootfs_is_host_root\n",
            b"126",
            b"R\nR\n",
        ] {
            assert_eq!(
                classify_exec_status(garbage, exit),
                failed(exit, None),
                "{garbage:?}"
            );
        }
        assert!(ExecExit::Command(exit).command_started());
        assert!(!failed(exit, None).command_started());
        assert_eq!(failed(exit, None).child_exit(), exit);
        assert_eq!(ExecExit::Command(signaled).child_exit(), signaled);
    }

    /// SUP-6・REPAIR-5・TASK-163 追補（#1460）: 実 pipe からの読み取り。書き込み側が閉じていれば内容（または
    /// 空）で判定し、開いたままなら待たずに `Internal`（起動したかどうかを推測しない）。上限を超える内容は
    /// 読み切らずに打ち切り、起動していない扱いにする。
    #[test]
    fn sup6_task163_read_exec_status_never_blocks() {
        let exit = ChildExit::Exited(127);
        // libtest では他のテストスレッドが子プロセスを fork し得て、その子が `execve` までの間 pipe の書き込み側の
        // 複製を持つと「書き込み側が開いたまま」（判定不能）になる。その回は pipe を作り直して読み直す
        // （本番の exec 専用プロセスは単一スレッドで、この重なりは起きない）。
        let read = |content: &[u8]| {
            (0..200)
                .find_map(|_| {
                    let (reader, mut writer) = std::io::pipe().unwrap();
                    writer.write_all(content).unwrap();
                    drop(writer);
                    read_exec_status(&std::fs::File::from(OwnedFd::from(reader)), exit).ok()
                })
                .expect("the status pipe must become readable")
        };
        assert_eq!(read(b"R\n"), ExecExit::Command(exit));
        assert_eq!(
            read(b""),
            ExecExit::SetupFailed {
                exit,
                violation: None
            }
        );
        assert_eq!(
            read(b"127 stdio_null_not_null_device\n"),
            ExecExit::SetupFailed {
                exit,
                violation: Some(ViolationReason::StdioNullNotNullDevice)
            }
        );
        assert_eq!(
            read(&[b'R'; 4096]),
            ExecExit::SetupFailed {
                exit,
                violation: None
            }
        );

        // 書き込み側が開いたまま（データなし）。
        let (reader, writer) = std::io::pipe().unwrap();
        let err = read_exec_status(&std::fs::File::from(OwnedFd::from(reader)), exit).unwrap_err();
        assert_eq!(
            (err.code, err.stage),
            (ErrorCode::Internal, IsolationStage::Wait)
        );
        assert_eq!(err.message, "the exec status pipe is still open after exit");
        drop(writer);
    }

    /// SUP-6・TASK-163 追補（#1457）: `Debug` 出力は env の KEY だけを出し、値を出さない（秘密情報を診断ログへ
    /// 漏らさない）。exec 用の `ExecCommand` の `Debug` も同じ。
    #[test]
    fn sup6_task163_entrypoint_debug_hides_env_values() {
        let entry = Entrypoint::new("/bin/app", ["app"], ["TOKEN=s3cr3t-value", "EMPTY="]).unwrap();
        let shown = format!("{entry:?}");
        assert_eq!(
            shown,
            r#"Entrypoint { path: "/bin/app", argv: ["app"], env_keys: ["TOKEN", "EMPTY"] }"#
        );
        let env = crate::exec::ContainerEnv::empty()
            .with_var("TOKEN", "s3cr3t-value")
            .unwrap();
        let command = crate::exec::ExecCommand::new("/bin/app", ["app"], &env).unwrap();
        let shown = format!("{command:?}");
        assert!(!shown.contains("s3cr3t"), "{shown}");
        assert!(shown.contains(r#"env_keys: ["TOKEN"]"#), "{shown}");
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
        assert_eq!(
            take_calls(),
            vec!["close_range(3,close)".to_string(), "setsid".to_string()]
        );
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
        let handle = ContainerChild::new(spawn_sh("exit 3"));
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
        let handle = ContainerChild::new(pid);
        let err = handle.wait_timeout(Duration::from_millis(200)).unwrap_err();
        assert_eq!(err.code, ErrorCode::Timeout);
        assert_eq!(err.stage, IsolationStage::Wait);
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    /// REPAIR-5・CORE-1（TASK-29.3）: `kill_and_reap` は未回収の子へ `SIGKILL` を 1 回だけ送って上限内に
    /// 回収し、回収済みのハンドルへの再呼び出しでは `kill` しない（回収状態の排他を共有する）。
    #[test]
    fn repair5_kill_and_reap_kills_once_and_reaps() {
        let pid = spawn_sh("exec sleep 30");
        let handle = ContainerChild::new(pid);
        assert_eq!(
            handle.kill_and_reap(Duration::from_secs(10)).unwrap(),
            ChildExit::Signaled(9)
        );
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        assert_eq!(
            handle.kill_and_reap(Duration::ZERO).unwrap(),
            ChildExit::Signaled(9)
        );
        assert_eq!(
            reap_snapshot(&handle),
            (
                ReapState::Reaped {
                    exit: ChildExit::Signaled(9),
                    killed: true
                },
                1
            )
        );
    }

    /// REPAIR-5（TASK-29.3）: 既に終了して回収済みの子には `kill_and_reap` が `SIGKILL` を送らない。
    #[test]
    fn repair5_kill_and_reap_skips_kill_after_reap() {
        let handle = ContainerChild::new(spawn_sh("exit 4"));
        assert_eq!(
            handle.wait_timeout(Duration::from_secs(10)).unwrap(),
            ChildExit::Exited(4)
        );
        assert_eq!(
            handle.kill_and_reap(Duration::from_secs(1)).unwrap(),
            ChildExit::Exited(4)
        );
        assert_eq!(reap_snapshot(&handle).1, 0);
    }

    /// CORE-1・REPAIR-5（TASK-29.3）: `wait_for_exit` は期限を過ぎても kill せず `None` を返し、終了後は
    /// 回収して終了状態を返す。
    #[test]
    fn core1_wait_for_exit_polls_without_kill() {
        let pid = spawn_sh("exec sleep 30");
        let handle = ContainerChild::new(pid);
        assert_eq!(
            handle.wait_for_exit(Duration::from_millis(100)).unwrap(),
            None
        );
        assert!(Path::new(&format!("/proc/{pid}")).exists());
        assert_eq!(reap_snapshot(&handle), (ReapState::Running, 0));
        assert_eq!(
            handle.kill_and_reap(Duration::from_secs(10)).unwrap(),
            ChildExit::Signaled(9)
        );
        let handle = ContainerChild::new(spawn_sh("exit 6"));
        assert_eq!(
            handle.wait_for_exit(Duration::from_secs(10)).unwrap(),
            Some(ChildExit::Exited(6))
        );
        assert_eq!(reap_snapshot(&handle).1, 0);
    }

    /// CORE-2・OCI-6（TASK-30.1）: 未回収の子へ SIGTERM を送ると `Delivered`、子は `Signaled(15)` で回収され、
    /// 回収後の送信は `kill` せず `AlreadyExited` を返す。
    #[test]
    fn core2_send_signal_delivers_then_reports_already_exited() {
        let handle = ContainerChild::new(spawn_sh("exec sleep 30"));
        let term = std::num::NonZeroU8::new(15).unwrap();
        assert_eq!(handle.send_signal(term).unwrap(), SignalDelivery::Delivered);
        assert_eq!(
            handle.wait_timeout(Duration::from_secs(10)).unwrap(),
            ChildExit::Signaled(15)
        );
        assert_eq!(
            handle.send_signal(term).unwrap(),
            SignalDelivery::AlreadyExited(ChildExit::Signaled(15))
        );
    }

    /// CORE-2・OCI-6（TASK-30.1）: 終了済みで未回収（ゾンビ）の子へは送らず、回収して `AlreadyExited` を返す。
    #[test]
    fn core2_send_signal_reports_zombie_as_already_exited() {
        let handle = ContainerChild::new(spawn_sh("exit 4"));
        let zombie_proc = format!("/proc/{}/stat", handle.pid());
        let deadline = Instant::now() + Duration::from_secs(10);
        while !std::fs::read_to_string(&zombie_proc).is_ok_and(|t| t.contains(") Z")) {
            assert!(Instant::now() < deadline, "child did not become a zombie");
            std::thread::sleep(Duration::from_millis(5));
        }
        let term = std::num::NonZeroU8::new(15).unwrap();
        assert_eq!(
            handle.send_signal(term).unwrap(),
            SignalDelivery::AlreadyExited(ChildExit::Exited(4))
        );
    }

    /// REPAIR-5・CORE-2（TASK-30.1）: 期限切れの `send_signal_until` は送らず `Timeout` を返し、子は生きたまま。
    #[test]
    fn repair5_send_signal_until_suppresses_after_deadline() {
        let handle = ContainerChild::new(spawn_sh("exec sleep 30"));
        let term = std::num::NonZeroU8::new(15).unwrap();
        let err = handle
            .send_signal_until(term, Instant::now())
            .expect_err("expired");
        assert_eq!(err.code, ErrorCode::Timeout);
        assert_eq!(
            handle.wait_for_exit(Duration::from_millis(100)).unwrap(),
            None
        );
        assert_eq!(
            handle.kill_and_reap(Duration::from_secs(10)).unwrap(),
            ChildExit::Signaled(9)
        );
    }

    /// CORE-2・CORE-1（TASK-30.1）: 回収済みのハンドルの pid が別プロセスに再利用されていても、
    /// `send_signal` はそのプロセスへ送らない。
    #[test]
    fn core2_send_signal_never_signals_reused_pid() {
        let mut unrelated = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let handle = ContainerChild::new(unrelated.id());
        handle.lock().state = ReapState::Reaped {
            exit: ChildExit::Exited(3),
            killed: false,
        };
        let result = handle.send_signal(std::num::NonZeroU8::new(9).unwrap());
        let alive = unrelated.try_wait().unwrap();
        kill_and_reap(&mut unrelated);
        assert_eq!(
            result.unwrap(),
            SignalDelivery::AlreadyExited(ChildExit::Exited(3))
        );
        assert_eq!(alive, None, "the unrelated process must not be signaled");
        assert_eq!(reap_snapshot(&handle).1, 0);
    }

    /// CORE-2・CORE-1（TASK-30.1）: 契約外の回収者が先に回収済み（`waitpid` が `ECHILD`）の pid へは
    /// `kill` せず、`Internal` ではなく `Gone` を返し、以後の送信も行わない。
    #[test]
    fn core2_send_signal_reports_gone_when_already_reaped_externally() {
        let mut external = Command::new("sh")
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let handle = ContainerChild::new(external.id());
        external.wait().unwrap();
        let term = std::num::NonZeroU8::new(15).unwrap();
        assert_eq!(handle.send_signal(term).unwrap(), SignalDelivery::Gone);
        assert_eq!(reap_snapshot(&handle), (ReapState::Lost, 0));
        assert_eq!(handle.send_signal(term).unwrap(), SignalDelivery::Gone);
        // 終端状態のため 2 回目以降も `waitpid` / `kill` を行わず状態は変わらない。
        assert_eq!(reap_snapshot(&handle), (ReapState::Lost, 0));
    }

    /// CORE-1・CORE-2（TASK-30.1）: pidfd を保持していれば、契約外の回収者が子を回収した後の
    /// シグナル送信は pid ではなくプロセス同一性で判定され、`ESRCH` になる（再利用 pid へ届かない）。
    #[test]
    fn core1_pidfd_signal_after_external_reap_is_esrch() {
        let mut external = Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let handle = ContainerChild::new(external.id());
        // pidfd_open 未対応のカーネルでは `kill(2)` 退避のため本検証の対象外。
        if handle.pidfd.is_none() {
            external.kill().unwrap();
            external.wait().unwrap();
            return;
        }
        external.kill().unwrap();
        external.wait().unwrap();
        let term = Signal::Number(std::num::NonZeroU8::new(15).unwrap());
        assert_eq!(handle.signal_child(term), Err(SysError::Os(sys::ESRCH)));
    }

    /// 回収状態と送った `SIGKILL` の回数を取り出す。
    fn reap_snapshot(handle: &ContainerChild) -> (ReapState, u32) {
        let cell = handle.lock();
        (cell.state, cell.kills_sent)
    }

    /// CORE-1・REPAIR-5（TASK-27.4.1）: 同じハンドルを 2 スレッドで並行に待つと、どちらも同じ
    /// 終了状態を受け取り、`SIGKILL` は送らない（回収は 1 回だけ）。
    #[test]
    fn core1_concurrent_waiters_share_exit_without_kill() {
        let handle = ContainerChild::new(spawn_sh("sleep 0.2; exit 3"));
        let (a, b) = std::thread::scope(|s| {
            let a = s.spawn(|| handle.wait_timeout(Duration::from_secs(10)));
            let b = s.spawn(|| handle.wait_timeout(Duration::from_secs(10)));
            (a.join().unwrap(), b.join().unwrap())
        });
        assert_eq!(a.unwrap(), ChildExit::Exited(3));
        assert_eq!(b.unwrap(), ChildExit::Exited(3));
        assert_eq!(
            reap_snapshot(&handle),
            (
                ReapState::Reaped {
                    exit: ChildExit::Exited(3),
                    killed: false
                },
                0
            )
        );
    }

    /// CORE-1・REPAIR-5（TASK-27.4.1）: 回収済みのハンドルへの再呼び出しは、期限 0 でも `kill` せず
    /// 記録済みの終了状態を返す。
    #[test]
    fn core1_wait_after_reap_returns_recorded_exit_without_kill() {
        let handle = ContainerChild::new(spawn_sh("exit 5"));
        assert_eq!(
            handle.wait_timeout(Duration::from_secs(10)).unwrap(),
            ChildExit::Exited(5)
        );
        assert_eq!(
            handle.wait_timeout(Duration::ZERO).unwrap(),
            ChildExit::Exited(5)
        );
        assert_eq!(reap_snapshot(&handle).1, 0);
    }

    /// CORE-1・REPAIR-5（TASK-27.4.1）: 回収済みのハンドルの pid が別プロセスに再利用されていても、
    /// 期限 0 の待機でそのプロセスへ `SIGKILL` を送らない（再利用を生きた別プロセスで模擬する）。
    #[test]
    fn core1_reaped_handle_never_signals_reused_pid() {
        let mut unrelated = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let handle = ContainerChild::new(unrelated.id());
        handle.lock().state = ReapState::Reaped {
            exit: ChildExit::Exited(7),
            killed: false,
        };
        let result = handle.wait_timeout(Duration::ZERO);
        let alive = unrelated.try_wait().unwrap();
        kill_and_reap(&mut unrelated);
        assert_eq!(result.unwrap(), ChildExit::Exited(7));
        assert_eq!(alive, None, "the unrelated process must not be signaled");
        assert_eq!(reap_snapshot(&handle).1, 0);
    }

    /// CORE-1・REPAIR-5（TASK-27.4.1）: 期限の短い待機が `SIGKILL` した子を、期限内の別スレッドの
    /// 待機は `Signaled(9)` として受け取る。`SIGKILL` は 1 回だけで、子は回収済み。
    #[test]
    fn core1_timeout_kill_is_shared_with_concurrent_waiter() {
        let pid = spawn_sh("exec sleep 30");
        let handle = ContainerChild::new(pid);
        let (short, long) = std::thread::scope(|s| {
            let short = s.spawn(|| handle.wait_timeout(Duration::from_millis(200)));
            let long = s.spawn(|| handle.wait_timeout(Duration::from_secs(60)));
            (short.join().unwrap(), long.join().unwrap())
        });
        let err = short.unwrap_err();
        assert_eq!(
            (err.code, err.stage),
            (ErrorCode::Timeout, IsolationStage::Wait)
        );
        assert_eq!(long.unwrap(), ChildExit::Signaled(9));
        assert_eq!(
            reap_snapshot(&handle),
            (
                ReapState::Reaped {
                    exit: ChildExit::Signaled(9),
                    killed: true
                },
                1
            )
        );
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        // 回収済みの後の再呼び出しは kill せず、記録済みの終了状態（`Signaled(9)`）を返す。
        assert_eq!(
            handle.wait_timeout(Duration::ZERO).unwrap(),
            ChildExit::Signaled(9)
        );
        assert_eq!(reap_snapshot(&handle).1, 1);
    }

    /// CORE-1・REPAIR-5（TASK-27.4.1）: 同じ期限で並行に期限切れしても `SIGKILL` は 1 回だけ。
    /// kill したスレッドは必ず `Timeout`、もう一方は観測の順序により `Timeout` か `Signaled(9)`。
    #[test]
    fn core1_simultaneous_timeouts_send_single_kill() {
        let pid = spawn_sh("exec sleep 30");
        let handle = ContainerChild::new(pid);
        let results = std::thread::scope(|s| {
            let a = s.spawn(|| handle.wait_timeout(Duration::from_millis(200)));
            let b = s.spawn(|| handle.wait_timeout(Duration::from_millis(200)));
            [a.join().unwrap(), b.join().unwrap()]
        });
        let timeouts = results
            .iter()
            .filter(|r| matches!(r, Err(e) if e.code == ErrorCode::Timeout))
            .count();
        let signaled = results
            .iter()
            .filter(|r| matches!(r, Ok(ChildExit::Signaled(9))))
            .count();
        assert!(timeouts >= 1, "{results:?}");
        assert_eq!(timeouts + signaled, 2, "{results:?}");
        assert_eq!(reap_snapshot(&handle).1, 1);
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    /// CORE-1・REPAIR-5（TASK-27.4.1）: `waitpid` が失敗して `Err` で戻っても回収状態は `Running`
    /// のままで `kill` も送らず、呼び出し元は同じハンドルで再試行できる（自プロセスは自分の子では
    /// ないため `waitpid` が `ECHILD` になる）。
    #[test]
    fn core1_wait_error_keeps_handle_retryable() {
        let handle = ContainerChild::new(std::process::id());
        for _ in 0..2 {
            let err = handle.wait_timeout(Duration::ZERO).unwrap_err();
            assert_eq!(err.stage, IsolationStage::Wait);
            assert_eq!(err.code, ErrorCode::Internal);
            assert_eq!(reap_snapshot(&handle), (ReapState::Running, 0));
        }
    }
}
