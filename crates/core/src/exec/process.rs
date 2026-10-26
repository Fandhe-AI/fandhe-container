//! fork / exec による子プロセス起動（CORE-1・TASK-27.4.1・#831・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! `crate::exec` の最小実行フロー第 5 段。namespace 分離済み（`isolate` /
//! `isolate_rootful_host_root` の後）の親から [`spawn_container`] で子を fork し、子（新しい PID
//! namespace の PID 1）が次を順に行う。製品コードの呼び出し元は本番 launcher
//! （`ProductionLauncher`）の `spawn_container_via_intermediate` で、最小入口 `spawn_container` は結合試験だけが呼ぶ（#2700）。
//!
//! ```text
//! spawn_container(rootfs, &entry)                      // 親: fork して ContainerChild を返す
//!   子: MountIsolation::establish()
//!       -> prepare_rootfs(&isolation, rootfs)
//!       -> (apply_sysctls)  // `linux.sysctl` の指定時のみ。verify_pinned の直後・mount_sysfs の前（CRI-2・CORE-3・#2670）
//!       -> (create_default_devices -> mount_tmpfs -> inject_files -> mount_binds)   // 起動設定 `setup` の指定時のみ（bind mount は `binds` の指定時のみ。#1914）
//!       -> apply_readonly_paths(&isolation, &prepared, config)  // 読み取り専用パスの固定集合 + config の追加分。固定集合は常に適用（SEC-2・#1850・#1852）
//!       -> apply_masked_paths(&isolation, &prepared, &null, config) // 覆うパスの固定集合 + config の追加分。`setup` 指定時のみ（SEC-2・#1851・#1852）
//!       -> pivot_root(&isolation, prepared)            -> PivotReport
//!       -> enter_working_dir(&report, &cwd)            // process.cwd が `/` 以外のときだけ（pivot 直後・ステージ列の前。OCI-1・TASK-29）
//!       -> exec_entrypoint(&isolation, &report, &entry) // execve。成功時は戻らない
//! 親: ContainerChild::wait_timeout(timeout)            // waitpid（期限超過で未回収に限り SIGKILL + 回収）
//! ```
//!
//! # 契約
//!
//! - **最小構成（フック無し）**: 子はステージ列（[`StagePipeline`]。#832）を `run_child` の pivot 後・
//!   exec 前で固定順に実行する。組み込みの `PR_SET_NO_NEW_PRIVS`（#833）は空のパイプラインでも適用される
//!   が、**Landlock は `with_landlock` 指定時のみ適用（本番 launcher からの指定は後続）、cgroup 参加は呼び出し側が `cgroups::CgroupJoin` を登録した場合のみ適用**（rootless の実体は TASK-40 が差し込む。capability 削減は #173、seccomp は #178 で組み込み済み）。
//!   Landlock を載せない構成では制限適用の証跡 `LaunchReady`（#1714）が作られないため、`run_child` の終端と
//!   `exec_entrypoint` は `PermissionDenied` で exec を拒否する（SEC-1・CORE-5。fail-closed）。`with_landlock` を載せた
//!   `spawn_container_with_stages` は全段の成功で exec へ進む（挙動の変更: 従来は常に拒否）
//! - **rootless 経路も同様**: 制限ステージの適用証跡（`LaunchReady`）が無い限り exec しない。
//!   `/proc/self/status` の `NoNewPrivs`・`Seccomp`・`CapEff` は親から継承した制限と区別できず、
//!   seccomp の内容も確認できないため証跡にしない（`NO_NEW_PRIVS` 単独も証跡にしない。SEC-1・CORE-5）。
//!   成功経路の実 exec は root の実機が要るため、単体テストは証跡の検査（`require_restriction_evidence`）と dry-run で検証する
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
//!   fd は 3 以上に置く。稼働中コンテナへの exec の子は、照合した本体を封印した memfd へ複製し
//!   （`sealed_copy.rs`。TASK-163 追補・#1531）、解析・照合・実行を複製に対して行う（launch は複製しない。常駐するワークロードのメモリ増を避ける設計判断。CORE-7〜9。launch に適用しない判断は `docs/design/launch-sealed-copy.md`・#2687）。
//!   上限超過・封印の検証失敗は違反で拒否する。シェバン付きスクリプトは、インタープリタが開き直す新 root の
//!   `/dev/fd/N` が同じ実体を指さなければ `FailedPrecondition` で拒否する（`/dev/fd` は `create_default_devices`〔#834・#1297〕が用意する。本番の launch 経路は呼ぶ。最小入口 `spawn_container` は呼ばない。配線しない判断は #2700）
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
//! - **exec は絶対パスのみ（launch は名前の `PATH` 探索も可）**: 稼働中コンテナへの exec は [`Entrypoint::new`] の絶対パスのみ。launch は
//!   名前だけの `args[0]` を [`Entrypoint::search_path`] で pivot 後に `process.env` の `PATH` から解決する（OCI-1・#2314。
//!   契約は `path_lookup.rs`）。`/` を含む相対パスは [`Entrypoint::cwd_relative`] で pivot と cwd の適用後に cwd 起点で解決する（OCI-1・OCI-4・#2432。
//!   `..` は拒否）。（cwd は launch の `setup.working_dir` で pivot 直後に適用。OCI-1）・OCI `process` からの組み立て・`preserve_fds`・
//!   `LISTEN_FDS` の受け渡しは TASK-29/30 の範囲
//! - **環境変数と補助グループ**（SUP-6・SEC-1・SEC-5・TASK-163 追補・#1457）: `execveat` へは [`Entrypoint`] が持つ
//!   env だけを envp として明示的に渡し、呼び出しプロセスの環境は引き継がない（既定値の補完もしない）。launch は
//!   `config.json` の `process.env` から [`Entrypoint`] を組み立て、稼働中コンテナへの exec は同じ出所と 1 件ずつの
//!   明示の上書きだけから作る型（`ExecCommand` / `ContainerEnv`。ホスト環境の列をまとめて渡す式は書けない。
//!   `exec/container_env.rs`）でしか受け取らない。補助グループは、launch（組み込みの capability 削減段）・exec
//!   （`reapply_restrictions`）とも同じ関数が空にする（`setgroups(0)`。`exec/capabilities.rs` の
//!   `SupplementaryGroups`）。本モジュールの子の手順は資格情報を変更しない（uid / gid は呼び出しプロセスのもの）
//! - **`execve` 前の失敗を親へ知らせる**（REPAIR-3・TASK-163 追補・#1460）: 稼働中コンテナへの exec の子は、
//!   close-on-exec の pipe で「手順を終えた」「失敗した（終了コード・ERR-1 コード・違反の理由）」を親へ返し、
//!   親は「コマンドが起動して終了した」のか「起動していない」のかを [`ExecExit`] で区別する（終了コード
//!   125〜127 はコマンド自身も返し得るため）。`R` の後の `execveat` の失敗も同じ形式の失敗の行で返り、
//!   ERR-1 コードは launch の `X <CODE>` と同じ errno の写像になる（#2763）。launch 経路の状態 pipe は
//!   `launch_status.rs`（`R` / `X`）
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

use crate::audit_log::AuditedRejection;
use crate::rlimits::{Rlimit, Rlimits};
use crate::sys::{self, SealedReadOnlyCopy, Signal, SysError};
use crate::traits::types::ErrorCode;

use super::devices::{NullNodeSource, create_default_devices_with_null_source};
use super::entrypoint_mode::EntrypointExecMode;
use super::interpreter::reject_runtime_interpreter;
use super::launch_status::{
    PrePivotFailure, PrePivotStep, report_exec_failure, report_exec_ready, report_exec_returned,
    report_failure, report_ready,
};
use super::masked_paths;
use super::path_lookup::{self, CandidateKind};
use super::path_masks;
use super::rlimits::apply_rlimits;
use super::rootfs::PreparedRootfs;
use super::sealed_copy::{SealPolicy, check_not_on_noexec_mount, seal_entrypoint_copy};
use super::stages::{LaunchNotReady, LaunchReady};
use super::sysctls::{self, SysctlPlan};
use super::{
    DeviceReport, DevptsGidSource, ExecError, IsolationStage, MountIsolation, PivotReport,
    StagePipeline, SysfsReport, ViolationReason, describe, enter_working_dir, fd_mount_id,
    inject_files, mount_sysfs, mount_tmpfs, pivot_root, prepare_rootfs,
};
use crate::dev_mounts::ImplicitDevMount;
use crate::injected_files::InjectedFileSet;
use crate::landlock::{MountedBy, MountedTarget, MountedTargets};
use crate::oci_runtime::{BindMountSet, ContainerWorkingDir, SysfsMountSpec};
use crate::path_masks::ProtectedPath;
use crate::tmpfs::TmpfsMountSet;

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
    /// 絶対パス。[`Entrypoint::search_path`] で作ったときは探索する名前（`/` を含まない）、
    /// [`Entrypoint::cwd_relative`] で作ったときは渡された相対パス（表示用）。
    path: CString,
    argv: Vec<CString>,
    env: Vec<CString>,
    /// `path` の解決方式（fork 前に検証済み）。
    resolution: Resolution,
}

/// [`Entrypoint`] の実行ファイルの解決方式（壊れた組み合わせを作れないよう 1 つの型にする。REPAIR-2）。
#[derive(Clone, PartialEq, Eq)]
enum Resolution {
    /// 絶対パス。pivot 後の `/` 起点で開く。
    Absolute,
    /// 名前を `PATH` で探すときの候補列（`<dir>/<name>`）。
    SearchPath(Vec<CString>),
    /// `/` を含む相対パスの要素列（`..`・空・`.` を除いた 1 件以上。`process.cwd` 起点で辿る。#2432）。
    CwdRelative(Vec<CString>),
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

/// 同じ KEY の重複を後勝ちに正規化する（残すのは各 KEY の最後の要素。残った要素の相対順は保つ）。
///
/// runc は `os.Clearenv()` の後に `process.env` を順に `Setenv` し、その環境で exec する（同じ KEY は後勝ちで
/// 1 件）。`PATH` の探索（`path_lookup`）が使う値と、子の `getenv` が見る値を一致させるため、envp も同じ規則で
/// 1 件に揃える（OCI-1・#2314）。KEY は最初の `=` までのバイト列で比べる。件数は入力以下なので上限は保たれる。
fn dedup_env_last_wins(env: Vec<CString>) -> Vec<CString> {
    let key = |c: &CString| -> Vec<u8> {
        let b = c.to_bytes();
        let end = b.iter().position(|x| *x == b'=').unwrap_or(b.len());
        b.get(..end).unwrap_or_default().to_vec()
    };
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<CString> = env
        .into_iter()
        .rev()
        .filter(|c| seen.insert(key(c)))
        .collect();
    out.reverse();
    out
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
        Self::assemble(path, total, args, env)
    }

    /// 名前だけの `process.args[0]` を `process.env` の `PATH` で探すエントリポイントを作る（OCI-1・#2314）。
    ///
    /// 探索は子が `pivot_root` した後に rootfs の中でだけ行う（契約と runc との差は `path_lookup.rs`）。
    /// `name` は空でなく `/`・NUL を含まない（`/` を含む相対パスは [`Entrypoint::cwd_relative`] を使う）。
    /// `env` に使える `PATH` が無ければ `InvalidArgument`（既定値は補わない）。`argv` は変えない（`argv[0]` は
    /// 呼び出し元が渡した名前のまま）。その他の検証と違反の分類は [`Entrypoint::new`] と同じ。
    pub fn search_path<N, A, E>(name: N, args: A, env: E) -> Result<Self, ExecError>
    where
        N: AsRef<OsStr>,
        A: IntoIterator,
        A::Item: AsRef<OsStr>,
        E: IntoIterator,
        E::Item: AsRef<OsStr>,
    {
        let name = name.as_ref();
        path_lookup::validate_name(name)?;
        let mut total = 0usize;
        let path = to_cstring(name, &mut total, "entrypoint name")?;
        let mut entry = Self::assemble(path, total, args, env)?;
        entry.resolution =
            Resolution::SearchPath(path_lookup::candidates_from_env(name, &entry.env)?);
        Ok(entry)
    }

    /// `/` を含む相対パスの `process.args[0]`（`./entrypoint.sh`・`bin/app`）を `process.cwd` 起点で解決する
    /// エントリポイントを作る（OCI-1・OCI-4・#2432）。
    ///
    /// 解決は子が `pivot_root` と cwd の適用を済ませた後に、cwd の fd を起点に 1 要素ずつ行う（`PATH` は引かない）。
    /// `..` 要素・末尾 `/`・絶対パス・`/` を含まない名前は `InvalidArgument`（契約と runc との差は
    /// `path_lookup.rs`）。`argv` は変えない。その他の検証と違反の分類は [`Entrypoint::new`] と同じ。
    pub fn cwd_relative<P, A, E>(path: P, args: A, env: E) -> Result<Self, ExecError>
    where
        P: AsRef<OsStr>,
        A: IntoIterator,
        A::Item: AsRef<OsStr>,
        E: IntoIterator,
        E::Item: AsRef<OsStr>,
    {
        let path = path.as_ref();
        let components = path_lookup::relative_components(path)?;
        let mut total = 0usize;
        let cpath = to_cstring(path, &mut total, "entrypoint path")?;
        let mut entry = Self::assemble(cpath, total, args, env)?;
        entry.resolution = Resolution::CwdRelative(components);
        Ok(entry)
    }

    /// `new`・`search_path`・`cwd_relative` が共有する argv・env の検証と組み立て。
    fn assemble<A, E>(path: CString, mut total: usize, args: A, env: E) -> Result<Self, ExecError>
    where
        A: IntoIterator,
        A::Item: AsRef<OsStr>,
        E: IntoIterator,
        E::Item: AsRef<OsStr>,
    {
        let invalid =
            |msg: &str| ExecError::new(ErrorCode::InvalidArgument, IsolationStage::Validate, msg);
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
        Ok(Self {
            path,
            argv,
            env: dedup_env_last_wins(env),
            resolution: Resolution::Absolute,
        })
    }

    /// コンテナ内の絶対パス。[`Entrypoint::search_path`] で作ったときは探索する名前、
    /// [`Entrypoint::cwd_relative`] で作ったときは渡された相対パス（いずれも解決後のパスではない。
    /// 解決後は `open_entrypoint` が返す）。
    pub fn path(&self) -> &Path {
        Path::new(OsStr::from_bytes(self.path.to_bytes()))
    }

    /// 渡した env を `KEY=VALUE` の文字列で返す(試験専用。launcher が env の上書きを重ねた結果の照合に使う。#2713)。
    #[cfg(test)]
    pub(crate) fn env_for_test(&self) -> Vec<String> {
        self.env
            .iter()
            .map(|e| e.to_string_lossy().into_owned())
            .collect()
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

/// 制限ステージの適用証跡が無いままの exec を拒否する（SEC-1・CORE-5。fail-closed。#1714）。
///
/// `StagePipeline::run_then` が全段の成功後に作る型付きトークン `LaunchReady` を値で受け取ったとき
/// だけ `Ok` を返す。トークンは組み込みの 4 段（rlimit・capability 削減・`NO_NEW_PRIVS`・seccomp）と、
/// `with_landlock` で登録した core の Landlock 適用の成功を束ねたもので、このモジュールからは作れない。
/// 真偽値・`StageReport`・`CapabilityReport` を受け取る入口は作らない（独自フックやダミーフックの
/// `Applied` では exec を許さない）。`CgroupJoin` は条件に入れない（cgroup を使う設定なのに join して
/// いない場合の拒否は本番 launcher が fork 前に `oci_runtime::require_cgroup_join` で行う。#1715・#1814）。
/// `/proc/self/status` の `NoNewPrivs`・`Seccomp`・`CapEff` は、親から継承した制限と子のステージが
/// 適用した制限を区別できず、seccomp フィルタの中身も確認できないため、証跡として扱わない。
fn require_restriction_evidence(
    evidence: Result<LaunchReady, LaunchNotReady>,
) -> Result<(), ExecError> {
    match evidence {
        Ok(_ready) => Ok(()),
        Err(not_ready) => Err(not_ready.into_exec_error()),
    }
}

/// pivot 済みの PID 1 から、エントリポイントへ `execve` する（成功時は戻らないため戻り値の
/// `Ok` は到達不能）。
///
/// [`MountIsolation::establish`]・[`prepare_rootfs`]・[`pivot_root`] と同じスレッドから呼ぶ。
/// 失敗しても状態は戻せないため、呼び出し元はプロセスを破棄する（子の `child_main` は終了コードで
/// 終わる）。手順は非公開の `exec_entrypoint_verified` を参照。
///
/// ステージ列を通さない入口なので制限適用の証跡（`LaunchReady`）が無く、**常に `PermissionDenied`
/// （段 `Exec`）で拒否する**（#1714）。exec を許すのは、`with_landlock` を含む全段が成功した
/// `spawn_container_with_stages` の子（`run_child`）だけ。
pub fn exec_entrypoint(
    isolation: &MountIsolation,
    pivot: &PivotReport,
    entry: &Entrypoint,
) -> Result<Infallible, ExecError> {
    isolation.verify_caller(IsolationStage::Exec)?;
    require_restriction_evidence(Err(LaunchNotReady::pipeline_not_run()))?;
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
///    検査から実行までの間のパス差し替え〔TOCTOU〕を防ぐ。稼働中コンテナへの exec の子〔`EntrypointSource::Switchable`〕
///    は、封印した複製を使える環境なら照合した本体を封印した memfd に複製し〔`sealed_copy.rs`。#1531〕、以降の解析・照合・
///    実行を複製に対して行う〔使えない環境は現行方式で、理由を記録する。オーナー判断 2026-10-09〕。
///    launch は複製しない〔適用しない判断。`docs/design/launch-sealed-copy.md`・#2687〕。ランタイム自身の封印複製の判断記録は `docs/design/runtime-self-sealed-copy.md`〔#2686〕）。シェバンの連鎖・
///    `PT_INTERP` の解決先がランタイムのバイナリなら同じく拒否する（#1458。`interpreter.rs`）
/// 3. 開いたエントリポイントが fd 0〜2 と同一 inode なら拒否する（`/proc/self/fd/{0,1,2}` 経由の参照対策。
///    fd 0〜2 の実体を確認できなければ拒否。エントリポイントの fd は 3 以上に置く）。
///    シェバン付きスクリプトは新 root の `/dev/fd/N` が同じ実体に解決することを確認する（できなければ拒否）。
///    fd 3 以上を `CLOEXEC` にする（CVE-2024-21626 型の fd 漏えい対策。カーネル 5.11 未満は
///    `ENOSYS`/`EINVAL` で fail-closed）
/// 4. `SIGPIPE` を `SIG_DFL` へ戻す（Rust ランタイムが設定した ignore は `execve` を越えて継承される）。
///    stdout / stderr をログ用パイプへ付け替えた場合は逆に `SIG_IGN` にする（#1471・SUP-5）
/// 5. fd 0〜2 を新 root の `/dev/null`（開く前に `O_PATH` で固定して 1:3 を検証し、`O_NOCTTY` つきで開き直す。
///    #1459）へ置換する（継承されたホスト側の標準入出力を渡さない）
/// 6. `execveat`（開いた fd を実行。実行権限がなければ `EACCES`）。戻ってきたら失敗
fn exec_entrypoint_verified(
    pivot_mnt_id: u64,
    entry: &Entrypoint,
) -> Result<Infallible, ExecError> {
    exec_entrypoint_verified_with(pivot_mnt_id, entry, StdioNulling::ALL)
}

/// [`exec_entrypoint_verified`] の、標準入出力のうち `/dev/null` へ置換する範囲を指定できる版
/// （TASK-164 追補・#1471・SUP-7）。`nulling` で外した番号は、子の先頭で [`ChildStdio::install`] が付け替えた
/// ログ用パイプのまま exec へ引き継ぐ。
fn exec_entrypoint_verified_with(
    pivot_mnt_id: u64,
    entry: &Entrypoint,
    nulling: StdioNulling,
) -> Result<Infallible, ExecError> {
    verify_pivot_root(pivot_mnt_id)?;
    exec_checked_entrypoint(entry, nulling)
}

/// `/` のマウント ID が pivot 直後の新 root と一致することを確かめる（`exec_entrypoint_verified` の手順 1）。
fn verify_pivot_root(pivot_mnt_id: u64) -> Result<(), ExecError> {
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
    Ok(())
}

/// launch の PID 1 の終端（`run_child`）。[`exec_entrypoint_verified_with`] の手順に、状態 pipe `status` への
/// 2 行目の報告を足したもの（SEC-4・#2624。ワイヤー形式は `launch_status` の「exec 前の 2 行目」）。
///
/// `status` が `Some` のとき、`execveat` より前の手順が失敗したら `E <CODE> <reason|->` を書いて失敗を返し、全手順が
/// 通ったら `R` を書いてから `execveat` する（`R` を書けなければ `execveat` へ進まない。fail-closed）。`R` の後の
/// `execveat` 自体が errno で失敗したら `X <CODE>`（errno の分類のみ）を書く（`E` は混ぜない。親は `R` の後も
/// EOF まで読み、`X` を起動失敗として扱う。#2716）。状態 pipe は `close_inherited_fds` が 1 本だけ残し、`execveat` の成功で閉じる
/// （close-on-exec）。`status` が `None` なら [`exec_entrypoint_verified_with`] と同じ（何も書かない）。
fn exec_entrypoint_verified_reporting(
    pivot_mnt_id: u64,
    entry: &Entrypoint,
    nulling: StdioNulling,
    status: Option<&std::fs::File>,
) -> Result<Infallible, ExecError> {
    let Some(status) = status else {
        return exec_entrypoint_verified_with(pivot_mnt_id, entry, nulling);
    };
    let prepared = verify_pivot_root(pivot_mnt_id).and_then(|()| {
        prepare_exec_child(
            entry,
            Some(status.as_fd()),
            EntrypointSource::Pinned,
            None,
            nulling,
        )
    });
    match prepared {
        Err(err) => {
            report_exec_failure_best_effort(status, &err);
            Err(err)
        }
        Ok(exe) => {
            report_exec_ready(status)?;
            let err = execve_checked(entry, &exe);
            // `execveat` が戻った（errno 由来の失敗）。親は `R` の後も EOF まで読むため、分類だけを `X` で伝える
            // （#2716）。書けなくても元のエラーを返す（親は EOF を成功と取り違える窓があるが、書けない状況は
            // pipe の破損のみで、PID 1 はこの後すぐ終了する）。
            if report_exec_returned(status, err.code).is_err() {
                let _ = writeln!(
                    std::io::stderr(),
                    "fandhe-container: the execveat failure could not be reported"
                );
            }
            Err(err)
        }
    }
}

/// `execveat` 前の失敗を状態 pipe へ書く。書けなくても元のエラーを返す（親は EOF を起動失敗として扱う）。
fn report_exec_failure_best_effort(status: &std::fs::File, err: &ExecError) {
    if report_exec_failure(status, err).is_err() {
        let _ = writeln!(
            std::io::stderr(),
            "fandhe-container: the exec phase status could not be reported"
        );
    }
}

/// `exec_entrypoint_verified` の手順 2 以降（fd 3 以上の close → エントリポイントの検査 → 標準入出力の置換 →
/// `execveat`）。launch 経路（pivot 直後の mount ID 照合の後）と、稼働中コンテナへの exec
/// （`exec_command::spawn_exec_command` の子。参加後の `/` の照合は `reapply_restrictions` が済ませている。
/// SUP-6・TASK-163.4）が共有する。呼び出し元は「`/` が正しい root であること」を事前に保証すること。
fn exec_checked_entrypoint(
    entry: &Entrypoint,
    nulling: StdioNulling,
) -> Result<Infallible, ExecError> {
    let exe = prepare_exec_child(entry, None, EntrypointSource::Pinned, None, nulling)?;
    Err(execve_checked(entry, &exe))
}

/// 検査済みの fd を `execveat` する。成功すると戻らず、戻ったら失敗（errno を `Exec` 段のエラーへ写す）。
fn execve_checked(entry: &Entrypoint, exe: &ExecutableFd) -> ExecError {
    execve_error(entry.path(), do_execve(entry, exe))
}

/// `execveat` が戻した errno を `Exec` 段のエラーへ写す（純関数。分類は [`exec_errno_to_code`]）。
///
/// launch の `X <CODE>` と稼働中コンテナへの exec の失敗行（[`exec_failure_line`]）が、同じ写像で
/// `R` の後の失敗を分類するための 1 か所（SEC-4・CORE-5・SUP-6。#2763）。
fn execve_error(path: &Path, err: SysError) -> ExecError {
    ExecError::new(
        exec_errno_to_code(err),
        IsolationStage::Exec,
        format!("execve({:?}) failed: {}", path, describe(err)),
    )
}

/// [`exec_checked_entrypoint`] の `execveat` より前の全手順。戻り値は検査済みで実行に使う fd（[`ExecutableFd`]）。
///
/// 手順を 1 か所に置くことで、本番の子（直後に `execveat`）と、結合試験用の観測
/// （`observe_exec_child_setup`。`execveat` の代わりに子自身の状態を報告する）が同じ処理を通る。
///
/// `source` は実行に使う fd の作り方で、launch は [`EntrypointSource::Pinned`]、稼働中コンテナへの exec の子は
/// [`EntrypointSource::Switchable`]（`keep` の有無で暗黙に判定しない）。
///
/// `keep` は、fd の後始末で 1 本だけ残す fd（稼働中コンテナへの exec の子が、`execve` 前の失敗を親へ知らせる
/// pipe の書き込み側。close-on-exec で、`execveat` が成功すれば閉じる。#1460）。launch 経路は `None`。
fn prepare_exec_child(
    entry: &Entrypoint,
    keep: Option<BorrowedFd<'_>>,
    source: EntrypointSource,
    deferred_fsize: Option<Rlimit>,
    nulling: StdioNulling,
) -> Result<ExecutableFd, ExecError> {
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
    // 種別（通常ファイル・標準入出力と別の実体）は開く前に確かめる（`setsid` の後は、端末を開くと制御端末に
    // なるため。#1456）。
    let (file, meta, resolved) = open_entrypoint(entry, root.as_fd(), procfs.as_fd())?;
    let runtime = runtime_identity(procfs.as_fd())?;
    if (meta.dev(), meta.ino()) == runtime {
        return Err(ExecError::from_violation_at(
            ViolationReason::EntrypointIsRuntimeBinary,
            Some(resolved.as_path()),
            STAGE,
        ));
    }
    // 稼働中コンテナへの exec は、判定した方式（`SealPolicy::mode`。オーナー判断 2026-10-09「条件付き切り替え」。
    // TASK-163 追補・#1531）に従う。封印した複製なら照合した本体を複製に置き換え、以降の解析・照合・実行はすべて複製
    // （seal と実体を再照合した `sys::SealedReadOnlyCopy`）に対して行う（元の fd はこの関数を抜けるときに閉じる）。
    // 現行方式なら照合した元の fd をそのまま実行する。どちらの方式でも、元のファイルのマウントの `noexec` は
    // `fstatfs` で判定して違反 `entrypoint_on_noexec_mount` で拒否する（現行方式ではカーネルの `execveat` も拒否するが、
    // 判定と違反記録を両方式で揃える）。
    let (exe, meta) = match source {
        EntrypointSource::Pinned => (ExecutableFd::Pinned(file), meta),
        EntrypointSource::Switchable(policy) => match policy.mode() {
            EntrypointExecMode::SealedCopy => {
                let copy = seal_entrypoint_copy(
                    &file,
                    &meta,
                    procfs.as_fd(),
                    resolved.as_path(),
                    &policy,
                )?;
                drop(file);
                let meta = copy.metadata().clone();
                (ExecutableFd::Sealed(copy), meta)
            }
            // 現行方式では `AT_EXECVE_CHECK` による事前判定をしない: 実行するのは照合した元の fd そのもので、
            // 直後の `execveat` が同じ fd・同じ domain で同じ検査（`noexec`・`MAY_EXEC`・Landlock・LSM）を必ず行うため、
            // 事前判定は保証を増やさず、AppArmor 等の拒否の監査イベントを二重にするだけになる。
            EntrypointExecMode::PinnedInode { .. } => {
                check_not_on_noexec_mount(&file, resolved.as_path())?;
                (ExecutableFd::Pinned(file), meta)
            }
        },
    };
    let file = exe.file();
    // 複製の書き込みが済んだので、持ち越した `RLIMIT_FSIZE` を適用する（複製の前に載せると `RLIMIT_FSIZE` が 0 や
    // バイナリより小さい構成で `SIGXFSZ`・`EFBIG` により起動できない。SUP-12。#1531）。複製の上限と cgroup の
    // メモリ制限は維持される。capability 削減後でも、rlimit を下げる `prlimit` は特権を要さない。
    if let Some(fsize) = deferred_fsize {
        let set = Rlimits::new(vec![fsize]).map_err(|_| {
            ExecError::new(
                ErrorCode::Internal,
                IsolationStage::Rlimits,
                "failed to build the deferred RLIMIT_FSIZE",
            )
        })?;
        apply_rlimits(&set)?;
    }
    // シェバン・`PT_INTERP` の解決先がランタイム自身でないことも確かめる（本体の照合だけでは
    // `#!/proc/self/exe` を通してしまう。#1458。契約と限界は `interpreter.rs`）。
    reject_runtime_interpreter(file, resolved.as_path(), runtime, procfs.as_fd())?;
    // シェバン付きスクリプトは fd が CLOEXEC だと execveat が ENOENT になるため、その場合だけ
    // mark_fds_cloexec の後に fd を継承させる（読み取り専用の同一ファイルの fd のみが漏れる）。
    let mut magic = [0u8; 2];
    let is_script = matches!(file.read_at(&mut magic, 0), Ok(2)) && &magic == b"#!";
    if is_script {
        // インタープリタは `/dev/fd/N` を開き直すため、新 root 内でそれが同じ実体を指すことを確認する。
        verify_script_fd_path(Path::new("/dev/fd"), file, &meta, &resolved)?;
    }

    mark_fds_cloexec()?;
    reset_sigpipe(!nulling.stdout || !nulling.stderr)?;
    if is_script {
        sys::set_cloexec(file.as_fd(), false)
            .map_err(|e| ExecError::from_sys(e, STAGE, "fcntl(F_SETFD)"))?;
    }
    // 最後に標準入出力を置換する（以降の execve 失敗の診断は stderr へ出せず、終了コードのみで通知）。
    // stdout / stderr をログ用パイプへ付け替え済みの番号は置換しない（`nulling` が外す。#1471）。
    redirect_stdio_to_null(root.as_fd(), procfs.as_fd(), nulling)?;
    Ok(exe)
}

/// 検査を終えて `execveat` に渡す fd（[`prepare_exec_child`] の戻り値。TASK-163 追補・#1531）。
///
/// 封印した複製は `sys::SealedReadOnlyCopy`（seal 0x0F と実体を再照合した型）のまま持ち、所有権を取り出さない。
/// 解析・観測には読み取りの借用（[`ExecutableFd::file`]）だけを貸す。
#[derive(Debug)]
enum ExecutableFd {
    /// 照合した元のファイルの fd（launch 経路と、稼働中コンテナへの exec の現行方式）。
    Pinned(std::fs::File),
    /// 封印した複製（稼働中コンテナへの exec）。
    Sealed(SealedReadOnlyCopy),
}

impl ExecutableFd {
    /// 読み取り用の借用（シェバン・`PT_INTERP` の解析・`execveat`）。
    fn file(&self) -> &std::fs::File {
        match self {
            Self::Pinned(file) => file,
            Self::Sealed(copy) => copy.file(),
        }
    }
}

/// 実行に使う fd の作り方（[`prepare_exec_child`] の呼び出し側が明示する。TASK-163 追補・#1531）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum EntrypointSource {
    /// 照合した fd（元の inode）をそのまま `execveat` する。launch 経路（常駐するワークロードのメモリ増を避ける。
    /// 封印した複製は適用しない判断で、理由は `docs/design/launch-sealed-copy.md`・#2687）。
    Pinned,
    /// 稼働中コンテナへの exec。値（`prepare_exec_restrictions` が `setns` の前に作る判定。#1531）の方式に従い、
    /// 封印した memfd に複製して `execveat` するか、照合した元の fd をそのまま `execveat` する（現行方式。#1478）。
    Switchable(SealPolicy),
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
/// rootfs に用意するのはデバイス準備の範囲（`create_default_devices`。#834・#1297）で、本関数は作らず検証だけを行う。
fn verify_script_fd_path(
    dev_fd_dir: &Path,
    file: &std::fs::File,
    meta: &std::fs::Metadata,
    shown: &Path,
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
                shown,
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
/// しないため fail-closed で拒否する。stdout / stderr のパイプ受け渡しは [`ChildStdio`]（#1471）が先に付け替え、`nulling` が外した番号は
/// 置換しない。端末（pty）の受け渡しは TASK-171.2（#537）の範囲（未実装）。
#[cfg(not(test))]
fn redirect_stdio_to_null(
    root: BorrowedFd<'_>,
    procfs: BorrowedFd<'_>,
    nulling: StdioNulling,
) -> Result<(), ExecError> {
    let null = open_verified_null(root, procfs)?;
    sys::redirect_fds_to(null, &nulling.targets())
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
/// マウント済み、exec 経路はコンテナの procfs。fail-closed）。fork 後の子から呼ぶため、この関数の成功経路は
/// ヒープを確保しない（エラーの組み立ては確保する）。
fn open_verified_null(root: BorrowedFd<'_>, procfs: BorrowedFd<'_>) -> Result<OwnedFd, ExecError> {
    const STAGE: IsolationStage = IsolationStage::Exec;
    let dev = sys::open_dir_path_nofollow(Some(root), c"dev").map_err(|e| match e {
        // 存在するがディレクトリでない（symlink・通常ファイル等）のは差し替えで、違反として記録する（SEC-4）。
        SysError::Os(errno) if errno == sys::ENOTDIR => ExecError::from_violation_at(
            ViolationReason::ExecDevNotDirectory,
            Some(Path::new("/dev")),
            STAGE,
        ),
        _ => ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!("cannot open /dev as a directory: {}", describe(e)),
        ),
    })?;
    let pinned = pin_null_device(dev.as_fd(), c"null")?;
    reopen_null_device(procfs, pinned.as_fd())
}

/// `root` 配下の `proc` を開き、本物の procfs であることを確かめる（`fstatfs`。symlink・非ディレクトリ・別の
/// ファイルシステムは `FailedPrecondition`）。固定した fd の開き直し（magic link）の起点にする。
fn open_root_procfs(root: BorrowedFd<'_>) -> Result<OwnedFd, ExecError> {
    const STAGE: IsolationStage = IsolationStage::Exec;
    // 存在するのに procfs でない（symlink・非ディレクトリ・別のファイルシステム）のは差し替えで、違反として
    // 記録する（SEC-4）。不在・その他の失敗は前提の不足として拒否する。
    let not_procfs = || {
        ExecError::from_violation_at(
            ViolationReason::ExecProcNotProcfs,
            Some(Path::new("/proc")),
            STAGE,
        )
    };
    let dir = sys::open_dir_path_nofollow(Some(root), c"proc").map_err(|e| match e {
        SysError::Os(errno) if errno == sys::ENOTDIR => not_procfs(),
        _ => ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!("cannot open /proc in the new root: {}", describe(e)),
        ),
    })?;
    if sys::fs_type(dir.as_fd()) != Ok(sys::PROC_MAGIC) {
        return Err(not_procfs());
    }
    Ok(dir)
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
fn redirect_stdio_to_null(
    _root: BorrowedFd<'_>,
    _procfs: BorrowedFd<'_>,
    nulling: StdioNulling,
) -> Result<(), ExecError> {
    tests::record(if nulling == StdioNulling::ALL {
        "stdio->/dev/null".to_string()
    } else {
        format!("stdio{:?}->/dev/null", nulling.targets())
    });
    Ok(())
}

/// `SIGPIPE` を `SIG_DFL` へ戻す。ログ用パイプ接続時（`piped`）は `SIG_IGN` にする。本番ビルドの実装。
///
/// パイプ接続時に無視へ固定するのは、supervisor が死んで読み取り側が閉じた後の出力 `write` が
/// `SIGPIPE` でコンテナを落とさず `EPIPE` になるようにするため（SUP-5・#1471）。
#[cfg(not(test))]
fn reset_sigpipe(piped: bool) -> Result<(), ExecError> {
    if piped {
        sys::ignore_sigpipe()
            .map_err(|e| ExecError::from_sys(e, IsolationStage::Exec, "signal(SIGPIPE, SIG_IGN)"))
    } else {
        sys::reset_sigpipe_default()
            .map_err(|e| ExecError::from_sys(e, IsolationStage::Exec, "signal(SIGPIPE, SIG_DFL)"))
    }
}

/// テストビルドの dry-run 差し込み点。呼ばれたことだけを記録する。
#[cfg(test)]
fn reset_sigpipe(piped: bool) -> Result<(), ExecError> {
    tests::record(if piped {
        "signal(SIGPIPE,SIG_IGN)".to_string()
    } else {
        "signal(SIGPIPE,SIG_DFL)".to_string()
    });
    Ok(())
}

/// エントリポイントを **開く前に** 固定して種別を確かめ、通常ファイルだけを読み取り専用で開く
/// （SUP-6・SEC-1・TASK-163 追補・#1456）。失敗は errno を `ErrorCode` に写す（不在 → `NotFound`）。
///
/// 直前の `setsid` で子は制御端末を持たないセッションのリーダーになっている。その状態で端末を `O_NOCTTY` なしで
/// 開くと、その端末を制御端末として取得してしまう（コンテナ側が用意した端末・端末を指す symlink を
/// エントリポイントに指定されると、切り離した直後に取得し直す）。パスを直接 `open` してから種別を調べる方式では
/// 遅いため、`/dev/null` と同じ順序にする。
///
/// 1. `root` を起点に `O_PATH`（最終要素の symlink は辿る。`execve` と同じ解決）で固定する（`O_PATH` はドライバの
///    `open` を呼ばず、制御端末も取得しない）
/// 2. `fstat` で、継承した標準入出力と同一の実体・通常ファイル以外（端末・デバイス・FIFO・ディレクトリ）を、
///    開かずに拒否する
/// 3. `procfs` の magic link 経由で `O_RDONLY|O_NONBLOCK|O_NOCTTY` に開き直す（パスを再解決しない）。読み取り権限の
///    無い実行専用バイナリはここで `EACCES`
///
/// 返す fd は必ず 3 以上（[`keep_above_stdio`]。後段の標準入出力の置換〔`dup2`〕で実行用の fd が潰されないように）。
/// 戻り値のメタデータは固定した inode のもの。
fn open_entrypoint(
    entry: &Entrypoint,
    root: BorrowedFd<'_>,
    procfs: BorrowedFd<'_>,
) -> Result<(std::fs::File, std::fs::Metadata, std::path::PathBuf), ExecError> {
    const STAGE: IsolationStage = IsolationStage::Exec;
    let open_error_for = |shown: &Path, e: SysError| {
        ExecError::new(
            exec_errno_to_code(e),
            STAGE,
            format!("open of the entrypoint {:?} failed: {}", shown, describe(e)),
        )
    };
    // 絶対パスなので解決は呼び出しプロセスの root（= 照合済みの `root`）から始まる。
    // 固定用の fd も 3 以上へ置く（呼び出し元の fd 0〜2 が閉じていると `openat` はその番号を返し、直後の
    // 「継承した標準入出力と同一の実体か」の照合が、固定した fd 自身と一致して通常のファイルを誤って拒否する）。
    let (pinned, resolved) = match &entry.resolution {
        Resolution::Absolute => {
            let fd = sys::open_path_follow_at(root, &entry.path)
                .map_err(|e| open_error_for(entry.path(), e))
                .and_then(keep_above_stdio)?;
            (fd, entry.path().to_path_buf())
        }
        // 名前の探索（OCI-1・#2314）。pivot 後の `/` の下で、候補を `O_PATH` で固定して判定する（ドライバの
        // `open` を呼ばず制御端末も取得しない。#1456）。不在・権限・`ELOOP` 等は次の候補へ進む。
        Resolution::CwdRelative(components) => {
            // `process.cwd` 起点の解決（OCI-1・OCI-4・#2432）。cwd の fd は一時的で、固定した実行ファイルの fd を
            // 得たら閉じる（標準入出力の置換をまたがない）。
            let cwd = sys::open_dir_path_nofollow(None, c".")
                .map_err(|e| ExecError::from_sys(e, STAGE, "openat(.)"))?;
            let fd = open_cwd_relative(cwd.as_fd(), components, entry.path())?;
            #[cfg(test)]
            tests::record(format!("lookup(entrypoint)={}", entry.path().display()));
            (fd, entry.path().to_path_buf())
        }
        Resolution::SearchPath(candidates) => {
            let mut chosen: Option<OwnedFd> = None;
            let idx = path_lookup::select_candidate(candidates, |cand| {
                let fd = sys::open_path_follow_at(root, cand)
                    .ok()
                    .and_then(|fd| keep_above_stdio(fd).ok())?;
                let meta = std::fs::File::from(fd.try_clone().ok()?).metadata().ok()?;
                let kind = if !meta.is_file() {
                    CandidateKind::NotRegular
                } else if meta.mode() & 0o111 == 0 {
                    CandidateKind::NotExecutable
                } else {
                    CandidateKind::Executable
                };
                if kind == CandidateKind::Executable {
                    chosen = Some(fd);
                }
                Some(kind)
            })?;
            let fd = chosen.ok_or_else(|| {
                ExecError::new(
                    ErrorCode::Internal,
                    STAGE,
                    "the selected entrypoint candidate was not retained",
                )
            })?;
            let picked = candidates.get(idx).ok_or_else(|| {
                ExecError::new(
                    ErrorCode::Internal,
                    STAGE,
                    "the selected entrypoint candidate index is out of range",
                )
            })?;
            #[cfg(test)]
            tests::record(format!("lookup(entrypoint)={}", picked.to_string_lossy()));
            (
                fd,
                std::path::PathBuf::from(OsStr::from_bytes(picked.to_bytes())),
            )
        }
    };
    let open_error = |e: SysError| open_error_for(&resolved, e);
    let meta = pinned
        .try_clone()
        .and_then(|fd| std::fs::File::from(fd).metadata())
        .map_err(|e| io_exec_error(&e, &resolved))?;
    if matches_any_identity((meta.dev(), meta.ino()), &inherited_stdio_identities()?) {
        return Err(ExecError::new(
            ErrorCode::PermissionDenied,
            STAGE,
            format!(
                "the entrypoint {:?} resolves to an inherited standard stream",
                resolved
            ),
        ));
    }
    if !meta.is_file() {
        return Err(ExecError::new(
            ErrorCode::PermissionDenied,
            STAGE,
            format!("the entrypoint {:?} is not a regular file", resolved),
        ));
    }
    #[cfg(test)]
    tests::record("reopen(entrypoint)".to_string());
    let file = sys::reopen_pinned_read(procfs, pinned.as_fd())
        .map_err(open_error)
        .and_then(keep_above_stdio)
        .map(std::fs::File::from)?;
    // 開き直した実体が、固定して検査した inode そのものであること（開き直しの経路の多層防御）。
    let reopened = file.metadata().map_err(|e| io_exec_error(&e, &resolved))?;
    if (reopened.dev(), reopened.ino()) != (meta.dev(), meta.ino()) {
        return Err(ExecError::new(
            ErrorCode::PermissionDenied,
            STAGE,
            format!(
                "the entrypoint {:?} changed while it was being opened",
                resolved
            ),
        ));
    }
    Ok((file, meta, resolved))
}

/// `cwd` を起点に `components` を 1 要素ずつ辿り、最終要素を `O_PATH` で固定して返す（OCI-1・OCI-4・#2432）。
///
/// 中間要素は symlink を辿らないディレクトリとして開く（symlink・非ディレクトリは `InvalidArgument`、不在は
/// `NotFound`）。最終要素は絶対パスの `args[0]` と同じく symlink を辿って開く（以降の通常ファイル・標準入出力との
/// 同一性・開き直しの照合は呼び出し元の共通経路）。`..` は `Entrypoint::cwd_relative` の字句検証で除いてある。
/// 返す fd は 3 以上（[`keep_above_stdio`]）。`shown` はエラー文言の表示用で、解決には使わない。
fn open_cwd_relative(
    cwd: BorrowedFd<'_>,
    components: &[CString],
    shown: &Path,
) -> Result<OwnedFd, ExecError> {
    const STAGE: IsolationStage = IsolationStage::Exec;
    let (last, dirs) = components.split_last().ok_or_else(|| {
        ExecError::new(
            ErrorCode::InvalidArgument,
            STAGE,
            "the entrypoint path has no file component",
        )
    })?;
    let map_err = |e: SysError, what: &str| {
        let code = match e {
            SysError::Os(n) if n == sys::ENOTDIR || n == sys::ELOOP => ErrorCode::InvalidArgument,
            other => exec_errno_to_code(other),
        };
        ExecError::new(
            code,
            STAGE,
            format!(
                "open of the {what} of the entrypoint {:?} failed: {}",
                shown,
                describe(e)
            ),
        )
    };
    let mut held: Option<OwnedFd> = None;
    for dir in dirs {
        let parent = held.as_ref().map_or(cwd, |fd| fd.as_fd());
        let next =
            sys::open_dir_path_nofollow(Some(parent), dir).map_err(|e| map_err(e, "directory"))?;
        held = Some(next);
    }
    let parent = held.as_ref().map_or(cwd, |fd| fd.as_fd());
    sys::open_path_follow_at(parent, last)
        .map_err(|e| map_err(e, "file"))
        .and_then(keep_above_stdio)
}

/// fd が 0〜2 なら 3 以上へ複製して元を閉じる（3 以上ならそのまま返す）。
///
/// 標準入出力の置換（`dup2`）をまたいで保持する fd はすべてこれを通す: エントリポイント・照合済みの `/`・
/// procfs・状態を返す pipe の両端（置換で潰される、または置換後の `/dev/null` を close で閉じてしまうため）。
/// 継承した標準入出力（fd 0〜2）の実体と照合する前に開く、エントリポイントの固定用の `O_PATH` も通す（0〜2 を
/// 取ると照合が自分自身と一致する）。置換より前に閉じ、標準入出力との照合にも関わらない一時的な fd（`/dev`・
/// `/dev/null` の固定用の `O_PATH`・インタープリタ・cwd・`self/exe`）は対象外。
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
fn io_exec_error(e: &std::io::Error, shown: &Path) -> ExecError {
    let err = SysError::Os(e.raw_os_error().unwrap_or(0));
    ExecError::new(
        exec_errno_to_code(err),
        IsolationStage::Exec,
        format!(
            "stat of the entrypoint {:?} failed: {}",
            shown,
            describe(err)
        ),
    )
}

/// 開いた fd を `execveat` する。本番ビルドの実装（戻ってきたら失敗の errno）。
#[cfg(not(test))]
fn do_execve(entry: &Entrypoint, exe: &ExecutableFd) -> SysError {
    sys::exec_fd(exe.file().as_fd(), &entry.argv, &entry.env)
}

/// テストビルドの dry-run 差し込み点。`execveat` を呼ばず、渡された引数を記録して `EINTR`（`Internal` に写る）を返す。
#[cfg(test)]
fn do_execve(entry: &Entrypoint, _exe: &ExecutableFd) -> SysError {
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
        /// 子が報告した失敗の分類（errno 由来。`R` の後の `execveat` の失敗は launch の `X <CODE>` と同じ
        /// 写像: `ENOENT`/`ENOTDIR` → `NotFound`、`EACCES`/`EPERM` → `PermissionDenied`、`ENOEXEC`/`E2BIG` →
        /// `InvalidArgument`、その他 → `Internal`。#2763）。子が何も書かずに終わった場合と解釈できない内容
        /// のときは `Internal`（起動していない扱いを保つ fail-closed）。
        code: ErrorCode,
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

/// 子が親へ返す状態の読み取り上限（バイト。`R` の行と失敗の行 1 件ぶんより十分大きい）。
const EXEC_STATUS_MAX: usize = 256;

/// 子が違反として報告し得る理由（`execveat` 前の手順が返す違反。[`read_exec_status`] が名前から引き直す）。
///
/// 子が報告し得る違反の SSOT。親の [`classify_exec_status`] はこの一覧にある名前だけを違反として引き直し、
/// 一覧に無い名前は `SetupFailed { violation: None }`（起動していない扱いは保たれるが SEC-4 の違反記録が
/// 欠落する）に落ちる。そのため子の経路（本ファイルと `interpreter.rs` の `mod tests` より前）が作る
/// `ViolationReason` とこの一覧は、テスト `sec4_sup6_task163_exec_child_violations_match_child_path_sources`
/// がソース照合で双方向に突き合わせる（SEC-4・SUP-6・SEC-1・CORE-5。TASK-163 追補・#1533）。
///
/// 違反記録の対象外とする子の失敗（状態には `-` を書くか、何も書かずに終わる）と根拠:
/// - 封印した複製の作成（`sealed_copy.rs`）の、`AT_EXECVE_CHECK` の拒否（`EACCES`・`EPERM`。実行ビット・Landlock の
///   `EXECUTE` 等）・通常ファイルでない複製元・複製中の伸縮による `PermissionDenied`、LSM の環境・`AT_EXECVE_CHECK`
///   未対応（封印した複製を選んだ後の 6.14 未満の `EINVAL`。本番は事前の判定で現行方式になるため通常は起きない）・`fstatfs` の失敗・`memfd_create` の前提不足（`ENOSYS`・`vm.memfd_noexec=2` の
///   `EACCES`・seccomp の `EPERM`）による `FailedPrecondition`: `execve` が元のファイルで返していた通常の拒否、競合、
///   前提不足であり、分離境界の突破試行とは断定できない。マウントの `noexec` は複製が迂回し得る境界のため違反
///   （`entrypoint_on_noexec_mount`）として記録する
/// - `open_entrypoint` の `PermissionDenied`: 入力の種別不正（通常ファイルでない・継承した標準入出力と同一）や
///   開き直しの間の競合による拒否で、分離境界の突破試行とは断定できない
/// - `FailedPrecondition`（`/dev/null`・`/proc`・`/dev/fd` の不在や準備不足）: 差し替えではなく前提不足
/// - `execveat` 自体の失敗（`R` の後）と状態書き込みの失敗: errno 由来のシステムエラー
/// - `bind_to_parent_lifetime` / `join_exec_cgroup` の失敗（`exec_command.rs`。何も書かずに終了）: 親の生存確認と
///   cgroup 参加のシステムエラー
///
/// 照合の限界: 対象は `process.rs`・`interpreter.rs`・`sealed_copy.rs` だけ。`prepare_exec_child` から別ファイルの違反生成
/// ヘルパを呼ぶようになったら、そのファイルを照合対象に加えること（`rootfs.rs`・`setns.rs` 等は子の経路の外の
/// 違反を多数作るため `exec/` 全体は走査しない）。
pub(super) const EXEC_CHILD_VIOLATIONS: [ViolationReason; 8] = [
    ViolationReason::EntrypointIsRuntimeBinary,
    ViolationReason::EntrypointInterpreterIsRuntimeBinary,
    ViolationReason::StdioNullNotNullDevice,
    ViolationReason::ExecDevNotDirectory,
    ViolationReason::ExecProcNotProcfs,
    ViolationReason::EntrypointCopyTooLarge,
    ViolationReason::EntrypointCopySealUnverified,
    ViolationReason::EntrypointOnNoexecMount,
];

/// 子が親へ違反として報告し得る理由の一覧（[`EXEC_CHILD_VIOLATIONS`] の読み取り専用の参照。SEC-4・SUP-6・#1579）。
///
/// 監査ログへ記録する対象の SSOT は `ViolationReason::ENTRYPOINT_REASONS` で、この一覧はその部分集合
/// （本ファイルの単体テストが固定する。#1595）。supervisor の worker 結果の復号は `ENTRYPOINT_REASONS` で引き直し、
/// supervisor 側の単体テストがこの一覧の全要素が往復できることを確かめるために公開する（通常の利用者は呼ばない）。
#[doc(hidden)]
pub fn exec_child_violation_reasons() -> &'static [ViolationReason] {
    &EXEC_CHILD_VIOLATIONS
}

/// 稼働中コンテナへの exec の子の本体（SUP-6・TASK-163.4。launch の `child_main` と同じ規約: 失敗したら stderr に
/// 英語 1 行を出して終了コードを返す。戻り値は `_exit` に渡される）。
///
/// `status` は親が fork の前に作った pipe の書き込み側（close-on-exec）で、次のプロトコルで使う（#1460）。
///
/// 1. `execveat` より前の全手順（`prepare_exec_child`）が通ったら [`EXEC_STATUS_READY`] を書く
/// 2. `terminal`（本番は `execveat`）を呼ぶ。`execveat` が成功すれば pipe は close-on-exec で閉じ、親は
///    「`R` の 1 行だけ」を読む = コマンドは起動した
/// 3. 手順か `terminal` が失敗したら `<終了コード> <ERR-1 コード> <違反の理由コードまたは ->` の 1 行を書く
///    （`R` の後の `execveat` の失敗も同じ形式で、ERR-1 コードは launch と同じ errno の写像。#2763）
///
/// 親（[`read_exec_status`]）は、`R` だけなら起動、失敗の行があれば未起動、何も無ければ「手順の途中で子が
/// 終了した」= 未起動と判定する。`R` を書けなければ `execveat` へ進まない（親へ知らせられない状態で実行しない）。
fn run_exec_child(
    entry: &Entrypoint,
    status: &std::fs::File,
    deferred_fsize: Option<Rlimit>,
    seal_policy: SealPolicy,
    terminal: impl FnOnce(&Entrypoint, &ExecutableFd) -> Result<i32, ExecError>,
) -> i32 {
    let result = prepare_exec_child(
        entry,
        Some(status.as_fd()),
        EntrypointSource::Switchable(seal_policy),
        deferred_fsize,
        StdioNulling::ALL,
    )
    .and_then(|exe| {
        write_exec_status(status, EXEC_STATUS_READY)?;
        terminal(entry, &exe)
    });
    match result {
        Ok(code) => code,
        Err(err) => {
            let code = exit_code_for(&err);
            let _ = writeln!(std::io::stderr(), "fandhe-container: {err}");
            // 失敗の行を書けなかった場合（`R` を書いた後の `execveat` の失敗で起き得る）、親は「起動した」と
            // 誤判定する。書き込みは fd を複製せず 1 回の `write` で行い（複製の失敗という要因を持たない）、
            // それでも書けなければ stderr に残す（stderr は既に `/dev/null` の場合がある。限界は
            // `exec/exec_command.rs`）。
            if write_exec_status(status, exec_failure_line(&err).as_bytes()).is_err() {
                let _ = writeln!(
                    std::io::stderr(),
                    "fandhe-container: the exec status could not be reported"
                );
            }
            code
        }
    }
}

/// 失敗の行 `<終了コード> <ERR-1 コード> <違反の理由コードまたは ->\n`（純関数。親の
/// [`classify_exec_status`] が復号する唯一の形式。errno の生値・文字列・パスは運ばない。#2763）。
fn exec_failure_line(err: &ExecError) -> String {
    let reason = err.violation.as_ref().map_or("-", |v| v.reason.as_str());
    format!("{} {} {reason}\n", exit_code_for(err), err.code.as_str())
}

/// 子が状態を返す pipe を作る。戻り値は `(読み取り側, 書き込み側)`（両端とも close-on-exec）。
///
/// 両端を 3 以上の番号へ置く: 呼び出しプロセスの fd 0〜2 が閉じていると pipe がその番号を取り、子の標準入出力の
/// 置換（`dup2`）で書き込み側が `/dev/null` に潰される（状態が親へ届かず、起動したコマンドを「起動していない」と
/// 判定してしまう）。
pub(super) fn exec_status_pipe() -> Result<(std::fs::File, std::fs::File), ExecError> {
    let (reader, writer) = std::io::pipe()
        .map_err(|e| ExecError::from_io(&e, IsolationStage::Spawn, "create the status pipe"))?;
    let reader = keep_above_stdio(OwnedFd::from(reader))?;
    let writer = keep_above_stdio(OwnedFd::from(writer))?;
    Ok((std::fs::File::from(reader), std::fs::File::from(writer)))
}

/// `status`（pipe の書き込み側）へ `line` を書く。失敗は `Internal`（段 `Exec`）。
fn write_exec_status(mut status: &std::fs::File, line: &[u8]) -> Result<(), ExecError> {
    // fd を複製せずに直接書く（`&File` は `Write`。失敗要因を `write` だけにする）。
    status
        .write_all(line)
        .map_err(|e| ExecError::from_io(&e, IsolationStage::Exec, "report the exec status"))
}

/// 稼働中コンテナへの exec の子のメイン（[`run_exec_child`] の終端を `execveat` にしたもの）。
pub(super) fn exec_child_main(
    entry: &Entrypoint,
    status: &std::fs::File,
    deferred_fsize: Option<Rlimit>,
    seal_policy: SealPolicy,
) -> i32 {
    run_exec_child(entry, status, deferred_fsize, seal_policy, |entry, exe| {
        Err(execve_checked(entry, exe))
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
    // 解釈できない内容（空・切れた行・旧形式・未知の語・余分なバイト）は、起動していない扱いで
    // 理由なし・`Internal`（fail-closed）。
    let unparsed = ExecExit::SetupFailed {
        exit,
        violation: None,
        code: ErrorCode::Internal,
    };
    // 失敗の行（`R` の後、または単独）は `<終了コード> <ERR-1 コード> <理由|->\n` の 3 語ちょうど。
    let line = status.strip_prefix(EXEC_STATUS_READY).unwrap_or(status);
    let Some(line) = line.strip_suffix(b"\n") else {
        return unparsed;
    };
    let mut words = line.split(|b| *b == b' ');
    let (Some(_exit), Some(code), Some(reason), None) =
        (words.next(), words.next(), words.next(), words.next())
    else {
        return unparsed;
    };
    let Some(code) = std::str::from_utf8(code)
        .ok()
        .and_then(ErrorCode::from_name)
    else {
        return unparsed;
    };
    let violation = if reason == b"-" {
        None
    } else {
        match EXEC_CHILD_VIOLATIONS
            .into_iter()
            .find(|v| v.as_str().as_bytes() == reason)
        {
            Some(v) => Some(v),
            None => return unparsed,
        }
    };
    ExecExit::SetupFailed {
        exit,
        violation,
        code,
    }
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
    /// `execveat` に渡す fd（封印した複製。#1531）の状態。`after_prepare` の後に採取するため、手順の後に
    /// 元のファイルが書き換えられても、この fd の内容が変わらないことを示す。
    pub exec_fd: ExecFdReport,
    /// `execveat` の直前の子の `RLIMIT_FSIZE` の `(soft, hard)`（`getrlimit`。持ち越した値の適用後。SUP-12・#1531）。
    pub fsize: (u64, u64),
}

/// `execveat` に渡す fd の状態（結合試験専用。TASK-163 追補・#1531）。
#[cfg(all(feature = "exec-test-support", not(test)))]
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecFdReport {
    /// fd 番号。
    pub fd: i32,
    /// `F_GET_SEALS` の値（memfd でなければ `None`）。封印した複製は 0x0F ちょうど。
    pub seals: Option<u32>,
    /// `fstat` の `st_size`。
    pub size: u64,
    /// 先頭 [`EXEC_FD_HEAD_BYTES`] バイトまでの内容。
    pub head: Vec<u8>,
    /// `/proc/self/fd/N` のリンク先。封印した複製は `/memfd:fandhe-exec-entrypoint (deleted)`。
    pub link: String,
}

/// [`ExecFdReport::head`] に載せる内容の最大バイト数。
#[cfg(all(feature = "exec-test-support", not(test)))]
#[doc(hidden)]
pub const EXEC_FD_HEAD_BYTES: usize = 4096;

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
    observe_exec_child_setup_with(command, report, || {}, timeout)
}

/// [`observe_exec_child_setup`] に、`after_prepare` の差し込み点を足した版（結合試験専用。TASK-163 追補・#1531）。
///
/// `after_prepare` は子で、`prepare_exec_child` が返った直後（封印と照合をすべて終え、`execveat` の直前に当たる
/// 位置）に 1 回呼ばれ、その後に報告を採取する。照合の後・実行の前にコンテナ側が元のファイルを書き換える
/// 競合を試験が再現するための入口で、実行する fd（封印した複製）の内容がその書き換えの影響を受けないことを
/// 報告の `exec_fd` で照合する。本番の `terminal`（`execveat`）には常時のフックを入れず、既存の `terminal`
/// 引数の仕組みだけで差し込む。`execveat` は呼ばない（制限適用の証跡を迂回する実行経路を作らない）。
/// 複製の方針は `SealPolicy::unrestricted`（LSM の環境判定なし・`AT_EXECVE_CHECK` は 6.14 以降でだけ行う）で、本番の
/// `SealPolicy::probe` より弱い（観測専用。`exec-test-support` feature でだけ作れる）。マウントの `noexec` の拒否は
/// 本番と同じく常に行う。
/// `after_prepare` は fork した単一スレッドの子で動くため、async-signal-safe でない処理を避ける必要は
/// ない一方、panic すると子が 125 で終わる（呼び出し側の試験が失敗として検出する）。
#[cfg(all(feature = "exec-test-support", not(test)))]
#[doc(hidden)]
pub fn observe_exec_child_setup_with(
    command: &super::ExecCommand,
    report: &Path,
    after_prepare: impl FnOnce(),
    timeout: Duration,
) -> Result<ExecChildSetupObservation, ExecError> {
    observe_exec_child_setup_inner(command, report, after_prepare, None, timeout)
}

/// [`observe_exec_child_setup`] に、子へ持ち越す `RLIMIT_FSIZE`（本番の `reapply_restrictions` が worker に載せず
/// 子へ渡す値）を足した版（結合試験専用。SUP-12・SEC-1・TASK-163 追補・#1531）。
///
/// 子は本番と同じ順序で、封印した複製を作り終えた後・`execveat` の前に `fsize` を適用して読み戻す。報告の
/// [`ExecChildSetupReport::fsize`] で適用後の soft・hard を、`exec_fd` で複製の完成（`fsize` より大きい本体でも
/// 複製できること）を照合する。適用に失敗すると子は報告を書かず `SetupFailed`（終了コード 125）で終わる。
/// `fsize` の種別が `RLIMIT_FSIZE` でなければ `InvalidArgument`。報告の書き込みも `fsize` の対象になるため、
/// 報告（先頭 [`EXEC_FD_HEAD_BYTES`] バイトの 16 進表記を含む）より大きい値を渡すこと。
#[cfg(all(feature = "exec-test-support", not(test)))]
#[doc(hidden)]
pub fn observe_exec_child_setup_with_fsize(
    command: &super::ExecCommand,
    report: &Path,
    fsize: Rlimit,
    timeout: Duration,
) -> Result<ExecChildSetupObservation, ExecError> {
    if fsize.kind() != crate::rlimits::RlimitKind::Fsize {
        return Err(ExecError::new(
            ErrorCode::InvalidArgument,
            IsolationStage::Rlimits,
            "the deferred rlimit must be RLIMIT_FSIZE",
        ));
    }
    observe_exec_child_setup_inner(command, report, || {}, Some(fsize), timeout)
}

/// 観測の本体（封印した複製の方針は `SealPolicy::unrestricted`）。
#[cfg(all(feature = "exec-test-support", not(test)))]
fn observe_exec_child_setup_inner(
    command: &super::ExecCommand,
    report: &Path,
    after_prepare: impl FnOnce(),
    deferred_fsize: Option<Rlimit>,
    timeout: Duration,
) -> Result<ExecChildSetupObservation, ExecError> {
    observe_exec_child_setup_policy(
        command,
        report,
        after_prepare,
        deferred_fsize,
        SealPolicy::unrestricted(),
        timeout,
    )
}

/// [`observe_exec_child_setup`] を、封印した複製を使わない判定（現行方式。`reason` はその理由）で通す版（結合試験専用。
/// SUP-6・SEC-1・#1531。オーナー判断 2026-10-09「条件付き切り替え」）。照合した元の fd がそのまま実行に使われること
/// （報告の `exec_fd` が元のファイルを指し seal を持たない）と、現行方式でもマウントの `noexec` が違反
/// `entrypoint_on_noexec_mount` で拒否されることを照合する。
#[cfg(all(feature = "exec-test-support", not(test)))]
#[doc(hidden)]
pub fn observe_exec_child_setup_pinned(
    command: &super::ExecCommand,
    report: &Path,
    reason: super::SealedCopyUnavailable,
    timeout: Duration,
) -> Result<ExecChildSetupObservation, ExecError> {
    observe_exec_child_setup_policy(
        command,
        report,
        || {},
        None,
        SealPolicy::pinned(reason),
        timeout,
    )
}

/// 観測用の入口すべての本体（`policy` は子が従う実行方式の判定）。
#[cfg(all(feature = "exec-test-support", not(test)))]
fn observe_exec_child_setup_policy(
    command: &super::ExecCommand,
    report: &Path,
    after_prepare: impl FnOnce(),
    deferred_fsize: Option<Rlimit>,
    policy: SealPolicy,
    timeout: Duration,
) -> Result<ExecChildSetupObservation, ExecError> {
    let entry = command.entrypoint();
    let (status_read, status_write) = exec_status_pipe()?;
    let pid = sys::fork_single_threaded(
        || {
            // 観測は `execveat` を呼ばず、実環境の LSM（CI の AppArmor 等）で複製の手順が止まらないよう LSM の制約なしに
            // する。`AT_EXECVE_CHECK` は対応カーネル（6.14+）でだけ行い、6.14 未満では省く（`SealPolicy::unrestricted`。
            // 本番の `SealPolicy::probe` は 6.14 未満なら封印した複製を選ばず現行方式にする）。`noexec` の判定は省かない。
            run_exec_child(
                entry,
                &status_write,
                deferred_fsize,
                policy,
                |entry, exe| {
                    after_prepare();
                    write_setup_report(entry, report, exe.file()).map(|()| 0)
                },
            )
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

/// [`close_standard_fds_for_test`] が閉じる標準 fd（結合試験専用。0〜2 に限る型で、任意の fd は閉じられない）。
#[cfg(all(feature = "exec-test-support", not(test)))]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardFd {
    /// fd 0。
    Stdin,
    /// fd 1。
    Stdout,
    /// fd 2。
    Stderr,
}

/// 結合試験専用: 呼び出しプロセスの標準 fd を閉じる（SEC-1・CORE-1・TASK-27.4.1・#1299）。
///
/// 呼び出し文脈は `tests/exec_child_setup.rs` の使い捨ての子と `tests/fork_exec_isolation.rs` のシナリオ
/// プロセス。fd 0〜2 を閉じた呼び出し側から [`observe_exec_child_setup`]・`spawn_container` を起動して、exec の
/// 直前の手順（`keep_above_stdio`）が実行用の fd を 3 以上へ移し、標準入出力を `/dev/null` へ置換することを確かめる。
/// 呼び出しプロセスの fd を不可逆に閉じるため、以後その番号の入出力（panic の診断を含む）は使えない。
/// すでに閉じている番号は前提違反として失敗にする（fail-closed）。`exec-test-support` feature を付けたビルドに
/// だけ存在し、既定のビルドの公開 API には含まれない。
#[cfg(all(feature = "exec-test-support", not(test)))]
#[doc(hidden)]
pub fn close_standard_fds_for_test(fds: &[StandardFd]) -> Result<(), ExecError> {
    for fd in fds {
        let number: u32 = match fd {
            StandardFd::Stdin => 0,
            StandardFd::Stdout => 1,
            StandardFd::Stderr => 2,
        };
        let proc_fd = format!("/proc/self/fd/{number}");
        if !Path::new(&proc_fd).exists() {
            return Err(ExecError::new(
                ErrorCode::FailedPrecondition,
                IsolationStage::Spawn,
                "the standard fd is already closed",
            ));
        }
        sys::close_fd_number(number)
            .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "close a standard fd"))?;
    }
    Ok(())
}

/// 観測の子: `execveat` の直前の自分の状態を `report` へ 1 行ずつ書く（[`observe_exec_child_setup`] 専用）。
#[cfg(all(feature = "exec-test-support", not(test)))]
fn write_setup_report(
    entry: &Entrypoint,
    report: &Path,
    exec_file: &std::fs::File,
) -> Result<(), ExecError> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{FileExt as _, FileTypeExt as _};
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
    // `execveat` に渡す fd の状態（封印の値・サイズ・内容・リンク先）。
    let exec_fd = exec_file.as_raw_fd();
    let seals = sys::get_seals(exec_file.as_fd()).map_or(-1, |s| i64::from(s.bits()));
    let size = exec_file
        .metadata()
        .map_err(|_| fail("stat the exec fd"))?
        .len();
    let mut head = vec![0u8; EXEC_FD_HEAD_BYTES];
    let mut filled = 0usize;
    while let Some(rest) = head.get_mut(filled..).filter(|r| !r.is_empty()) {
        match exec_file.read_at(rest, u64::try_from(filled).unwrap_or(u64::MAX)) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(fail("read the exec fd")),
        }
    }
    head.truncate(filled);
    let head_hex: String = head.iter().map(|b| format!("{b:02x}")).collect();
    let link = std::fs::read_link(format!("/proc/self/fd/{exec_fd}"))
        .map_err(|_| fail("read the exec fd link"))?;
    text.push_str(&format!(
        "exec_fd={exec_fd} {seals} {size} {head_hex} {}\n",
        link.to_string_lossy()
    ));
    let (fsize_soft, fsize_hard) = sys::get_rlimit_self(crate::rlimits::RlimitKind::Fsize)
        .map_err(|_| fail("read own RLIMIT_FSIZE"))?;
    text.push_str(&format!("fsize={fsize_soft} {fsize_hard}\n"));
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
        exec_fd: {
            let v = text.lines().find_map(|l| l.strip_prefix("exec_fd="))?;
            let mut parts = v.splitn(5, ' ');
            let fd = parts.next()?.parse().ok()?;
            let seals: i64 = parts.next()?.parse().ok()?;
            let size = parts.next()?.parse().ok()?;
            let head_hex = parts.next()?;
            let link = parts.next()?.to_owned();
            let head = (0..head_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(head_hex.get(i..i + 2)?, 16).ok())
                .collect::<Option<Vec<u8>>>()?;
            ExecFdReport {
                fd,
                seals: u32::try_from(seals).ok(),
                size,
                head,
                link,
            }
        },
        fsize: {
            let (soft, hard) = single("fsize")?.split_once(' ')?;
            (soft.parse().ok()?, hard.parse().ok()?)
        },
    })
}

/// 子の標準入出力のうち、exec 直前に `/dev/null` へ置換する番号（TASK-164 追補・#1471・SUP-7）。
///
/// fd 0（stdin）は常に置換する（受け渡しは未実装）。stdout / stderr は、ログ用パイプへ付け替え済みなら
/// 置換せずパイプのまま exec へ引き継ぐ（`false`）。[`ChildStdio::install`] が付け替えた結果から作る。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StdioNulling {
    stdout: bool,
    stderr: bool,
}

impl StdioNulling {
    /// 3 本とも置換する（パイプ指定なし。従来どおり）。
    const ALL: Self = Self {
        stdout: true,
        stderr: true,
    };

    /// `/dev/null` へ置換する fd 番号（昇順）。
    fn targets(self) -> Vec<i32> {
        let mut t = vec![0];
        if self.stdout {
            t.push(1);
        }
        if self.stderr {
            t.push(2);
        }
        t
    }
}

/// 子の stdout / stderr へ付け替えるパイプの書き込み側（TASK-164 追補・#1471・SUP-7・SUP-1）。
///
/// 親（launcher）が fork の前に [`ChildStdio::pipes`] で作り、`spawn_container_with_stages_and_stdio` へ渡す。
/// 読み取り側は親に残り、supervisor の行単位捕捉（`LogCapture`）へ `ContainerOutput` として渡る。
/// fork 後の親側のコピーは spawn が drop して書き込み側を閉じるため、子と孫がすべて終了すれば読み取り側は EOF に
/// なる。fd は `pipe()` の close-on-exec のまま保持し、子が `install` で 1・2 へ複製した分だけが
/// exec を越える（それ以外の書き込み側・読み取り側の fd は `close_inherited_fds` が閉じる）。
///
/// # 制限（SUP-5・SUP-8 との関係）
/// パイプ接続時、子は `SIGPIPE` を `SIG_IGN` にして exec する（無視は exec を越えて継承される）。読み取り側
/// （supervisor）が異常終了して閉じても、コンテナの出力 `write` は `SIGPIPE` で致死とならず `EPIPE` を返す
/// ため、SUP-5（supervisor 死亡後も稼働継続）を損なわない。出力は失われる（再接続・re-adopt は SUP-8・TASK-165）。
/// ワークロードが `SIGPIPE` を自前で扱う場合はその設定が優先される。supervisor が生きている間は、sink が失敗しても
/// 読み取りは EOF まで続くため、コンテナの `write` は詰まらない。
#[derive(Debug)]
pub struct ChildStdio {
    stdout: Option<OwnedFd>,
    stderr: Option<OwnedFd>,
}

impl ChildStdio {
    /// stdout・stderr それぞれ別のパイプを作り、書き込み側と読み取り側 2 本を返す。
    ///
    /// stdout と stderr を別のパイプにするのは、ログ行へストリーム名を付けるため（SUP-7）。
    /// 失敗（fd 枯渇等）は `ExecError`（段は `Spawn`）。
    pub fn pipes() -> Result<(Self, std::io::PipeReader, std::io::PipeReader), ExecError> {
        let make = |what: &str| {
            std::io::pipe().map_err(|e| ExecError::from_io(&e, IsolationStage::Spawn, what))
        };
        let (out_r, out_w) = make("pipe(stdout)")?;
        let (err_r, err_w) = make("pipe(stderr)")?;
        Ok((
            Self {
                stdout: Some(OwnedFd::from(out_w)),
                stderr: Some(OwnedFd::from(err_w)),
            },
            out_r,
            err_r,
        ))
    }

    /// パイプ指定なし（stdout / stderr とも従来どおり `/dev/null`）。
    pub fn none() -> Self {
        Self {
            stdout: None,
            stderr: None,
        }
    }

    /// 子の側で fd 1・2 へ付け替える。`prepare_exec_child` の `close_inherited_fds`（fd 3 以上を閉じる）より
    /// 前に呼ぶこと（付け替えた 1・2 は閉じられない）。
    ///
    /// 先に各 fd を 3 以上へ退避してから複製する: パイプの fd 番号が 1・2 と重なると（親が標準 fd を閉じていた
    /// 場合）、片方の複製がもう片方を上書きするため。戻り値は、以後 `/dev/null` へ置換しない番号を除いた範囲。
    fn install(self) -> Result<StdioNulling, ExecError> {
        const STAGE: IsolationStage = IsolationStage::Spawn;
        let lift = |fd: Option<OwnedFd>, what: &str| -> Result<Option<OwnedFd>, ExecError> {
            fd.map(|fd| {
                sys::dup_fd_at_least(fd.as_fd(), 3).map_err(|e| ExecError::from_sys(e, STAGE, what))
            })
            .transpose()
        };
        let stdout = lift(self.stdout, "fcntl(F_DUPFD_CLOEXEC, stdout)")?;
        let stderr = lift(self.stderr, "fcntl(F_DUPFD_CLOEXEC, stderr)")?;
        if let Some(fd) = &stdout {
            sys::dup_onto(fd.as_fd(), 1)
                .map_err(|e| ExecError::from_sys(e, STAGE, "dup2(stdout pipe)"))?;
        }
        if let Some(fd) = &stderr {
            sys::dup_onto(fd.as_fd(), 2)
                .map_err(|e| ExecError::from_sys(e, STAGE, "dup2(stderr pipe)"))?;
        }
        Ok(StdioNulling {
            stdout: stdout.is_none(),
            stderr: stderr.is_none(),
        })
    }
}

/// 子のメイン。`establish` → `prepare_rootfs` → `pivot_root` → `exec_entrypoint` を通し、失敗したら
/// stderr に英語 1 行を出して終了コードを返す（戻り値は `_exit` に渡される）。
///
/// pivot 前の段（専用 `/dev`・tmpfs・注入）は渡された [`PrePivotSetup`] の分だけ、[`run_pre_pivot`] が固定順
/// で行う。`None` なら最小構成（何も載せない）。
///
/// `stdio` は最初に fd 1・2 へ付け替える（#1471）。付け替えの失敗は stderr（付け替え前の継承 fd）へ出す。
/// 副作用: パイプ指定時、これ以降の失敗診断（下の 1 行を含む）は supervisor の stderr ではなくコンテナのログに入る。
pub(super) fn child_main(
    rootfs: &Path,
    entry: &Entrypoint,
    stages: StagePipeline,
    setup: Option<PrePivotSetup<'_>>,
    stdio: ChildStdio,
) -> i32 {
    let nulling = match stdio.install() {
        Ok(n) => n,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "fandhe-container: {err}");
            return exit_code_for(&err);
        }
    };
    match run_child(rootfs, entry, stages, setup, nulling) {
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
    setup: Option<PrePivotSetup<'_>>,
    nulling: StdioNulling,
) -> Result<Infallible, ExecError> {
    // 状態 pipe は pivot 前段の報告（`P`/`F`）に続き、終端でも exec 前の 2 行目（`R`/`E`）に使う（#2624）。
    let status = setup.and_then(|s| s.status);
    run_child_then(rootfs, setup, stages, |isolation, report, evidence| {
        // `exec_entrypoint` と同じ検証を、ステージ列が作った証跡を添えて行う。
        let checked = isolation
            .verify_caller(IsolationStage::Exec)
            .and_then(|()| require_restriction_evidence(evidence));
        if let Err(err) = checked {
            if let Some(status) = status {
                report_exec_failure_best_effort(status, &err);
            }
            return Err(err);
        }
        exec_entrypoint_verified_reporting(report.new_root_mnt_id, entry, nulling, status)
    })
}

/// pivot 前に rootfs へ載せるものの指定（TASK-29 追補・#1715。CORE-1・CORE-5・SEC-1）。
///
/// 本番の launcher（`oci_runtime`）だけが組み立てる。呼び出し側は「何を載せるか」だけを渡し、
/// 「どの順で行うか」は [`run_pre_pivot`] が 1 か所で固定する（順序を変える入口を core の外へ出さない）。
/// 専用 `/dev`（`create_default_devices`）は常に先頭で作る。
#[derive(Clone, Copy)]
pub(crate) struct PrePivotSetup<'a> {
    /// config の `linux.readonlyPaths` / `maskedPaths`（固定集合への追加分。#1852）。
    pub(crate) config_paths: ConfigPaths<'a>,
    /// 専用 `/dev` の devpts の `gid=` の決定元。
    pub(crate) devices: DevptsGidSource<'a>,
    /// `/dev` の後に載せる tmpfs（無ければ載せない）。
    pub(crate) tmpfs: Option<&'a TmpfsMountSet>,
    /// tmpfs の後に注入するファイル（無ければ注入しない）。
    pub(crate) inject: Option<&'a InjectedFileSet>,
    /// 注入の後に載せる bind mount（無ければ載せない。#1914・TASK-29 追補）。呼び出し側（`start` が host_paths・保護パスを、
    /// 本番 launcher が tmpfs を検査済み。#1915）が `check_against_*` を通した集合を渡す。[`run_pre_pivot`] は tmpfs・注入・
    /// 保護パスとの重なりを副作用の前に再検査する（多重防御）。本番の launcher は `LaunchSpec::bind_mounts` が非空のときだけ渡す。
    pub(crate) binds: Option<&'a BindMountSet>,
    /// `verify_pinned` の直後（`create_default_devices` の前）に供給する `/sys` の sysfs（無ければ載せない。
    /// #2020・SEC-2・OCI-4）。procfs を `prepare_rootfs` が載せるのと対の位置で、`readonly_paths` より前に
    /// 載せて、その再帰 bind と読み取り専用化が上に載るようにする。
    pub(crate) sysfs: Option<&'a SysfsMountSpec>,
    /// `verify_pinned` の直後（`mount_sysfs` の前）に適用する namespaced な sysctl（無ければ書かない。`readonly_paths` が
    /// `/proc/sys` を読み取り専用にする前でなければ書けない。実効の名前空間と照合済みの計画だけを渡せる。CRI-2・CORE-3・#2670）。
    pub(crate) sysctls: Option<&'a SysctlPlan<'a>>,
    /// 検証済みの rootfs を固定した fd。あれば `prepare_rootfs` の後、パスから辿り直した実体が同じ
    /// `(st_dev, st_ino)` であることを確かめる（検証後の差し替え対策）。
    pub(crate) pinned_rootfs: Option<BorrowedFd<'a>>,
    /// pivot 前段の結果を親へ返す状態 pipe の書き込み側（#1815。`launch_status` の形式）。あれば `run_child_then` が
    /// 成功（`P`）または失敗（`F ...`）を 1 行書く。`None` なら何も返さない（従来どおり）。子はここ以外で sink に
    /// 触らない。終端（`run_child`）は同じ pipe に exec 前の 2 行目（`R`/`E`。entrypoint 系の違反を親の監査へ届ける。
    /// #2624）も書くため、`close_inherited_fds` はこの 1 本だけ残し、`mark_fds_cloexec` と close-on-exec により
    /// `execveat` の成功で閉じる（workload へ渡らない）。
    pub(crate) status: Option<&'a std::fs::File>,
    /// pivot 後に移る作業ディレクトリ（`process.cwd`。`None` または `Root` なら移らない。OCI-1・TASK-29）。
    /// 違反は状態 pipe の段 `working_dir` で親へ返る。
    pub(crate) working_dir: Option<&'a ContainerWorkingDir>,
}

/// config の `linux.readonlyPaths` / `maskedPaths`（検証済み）。固定集合に**追加**されるだけで、外す・緩める
/// 手段ではない（SEC-2・TASK-29 追補・#1852）。本番の launcher が `OciConfig` から組む。
#[derive(Clone, Copy)]
pub(crate) struct ConfigPaths<'a> {
    /// 読み取り専用にする追加のパス。
    pub(crate) readonly: &'a [ProtectedPath],
    /// 覆う追加のパス。
    pub(crate) masked: &'a [ProtectedPath],
}

impl ConfigPaths<'_> {
    /// 追加なし（固定集合のみ）。
    pub(crate) const NONE: ConfigPaths<'static> = ConfigPaths {
        readonly: &[],
        masked: &[],
    };
}

/// [`run_pre_pivot`] が呼ぶ各段（単体テストが呼び出し順を記録できるよう差し替え可能にした継ぎ目。
/// 本番の実装は [`RealPrePivotOps`] で、既存の公開関数を呼ぶだけ）。
trait PrePivotOps {
    type Isolation;
    type Prepared;
    type Devices;
    type Pivoted;
    /// `mount_sysfs` の成功の証跡。`masked_paths` 段へ渡し、sysfs を供給したときだけ `/sys` 配下を覆う（#2014）。
    type Sysfs;
    /// `binds` に `rslave` があれば、`/` の private 化の前にその元を複製する（#2669）。
    fn establish(&self, binds: Option<&BindMountSet>) -> Result<Self::Isolation, ExecError>;
    fn prepare_rootfs(
        &self,
        isolation: &Self::Isolation,
        rootfs: &Path,
    ) -> Result<Self::Prepared, ExecError>;
    fn verify_pinned(
        &self,
        prepared: &Self::Prepared,
        pinned: BorrowedFd<'_>,
    ) -> Result<(), ExecError>;
    /// namespaced な sysctl の適用（#2670）。`verify_pinned` の直後・`mount_sysfs` の前（`/proc/sys` が読み取り専用になる前）。
    fn apply_sysctls(
        &self,
        isolation: &Self::Isolation,
        prepared: &Self::Prepared,
        plan: &SysctlPlan<'_>,
    ) -> Result<(), ExecError>;
    /// `/sys` への読み取り専用の sysfs の供給（#2020）。procfs と対の位置で、`readonly_paths` より前に載せる。
    fn mount_sysfs(
        &self,
        isolation: &Self::Isolation,
        prepared: &Self::Prepared,
        spec: &SysfsMountSpec,
    ) -> Result<Self::Sysfs, ExecError>;
    fn create_default_devices(
        &self,
        isolation: &Self::Isolation,
        prepared: &Self::Prepared,
        source: DevptsGidSource<'_>,
    ) -> Result<Self::Devices, ExecError>;
    fn mount_tmpfs(
        &self,
        isolation: &Self::Isolation,
        prepared: &Self::Prepared,
        devices: &Self::Devices,
        set: &TmpfsMountSet,
    ) -> Result<(), ExecError>;
    fn inject_files(
        &self,
        isolation: &Self::Isolation,
        prepared: &Self::Prepared,
        set: &InjectedFileSet,
    ) -> Result<(), ExecError>;
    /// 検証済みの bind mount の適用。`/dev` とその配下は宛先にできない（`RESERVED_DESTINATIONS`）ため、
    /// `mount_tmpfs` と違い `/dev` の作成順の証跡（`Devices`）は受けない（#1914）。
    fn mount_binds(
        &self,
        isolation: &Self::Isolation,
        prepared: &Self::Prepared,
        set: &BindMountSet,
    ) -> Result<(), ExecError>;
    fn apply_readonly_paths(
        &self,
        isolation: &Self::Isolation,
        prepared: &Self::Prepared,
        extra: &[ProtectedPath],
    ) -> Result<(), ExecError>;
    fn apply_masked_paths(
        &self,
        isolation: &Self::Isolation,
        prepared: &Self::Prepared,
        devices: &Self::Devices,
        sysfs: Option<&Self::Sysfs>,
        extra: &[ProtectedPath],
    ) -> Result<(), ExecError>;
    fn pivot_root(
        &self,
        isolation: &Self::Isolation,
        prepared: Self::Prepared,
    ) -> Result<Self::Pivoted, ExecError>;
    /// pivot 直後に `process.cwd` へ移る（OCI-1）。
    fn enter_working_dir(
        &self,
        pivoted: &Self::Pivoted,
        working_dir: &ContainerWorkingDir,
    ) -> Result<(), ExecError>;
}

/// `create_default_devices` の結果と、検証済みの `/dev/null`（`masked_paths` 段の複製元。SEC-2・#1851）。
struct DeviceSet {
    report: DeviceReport,
    null: NullNodeSource,
}

/// 本番の段の実装（既存の公開関数への薄い委譲）。
///
/// 各段の成功直後に、その段が載せたマウント先の識別子を `mounted` へ記録する（#2071・CORE-5・SEC-1）。
/// 記録は `run_child_then` が取り出して `StagePipeline::with_mounted_targets` で Landlock 段へ渡し、
/// Mount 由来のルールの対象が pivot 前段の載せたマウントのルートであることの照合に使う。段の事後検証が
/// 自分のマウントを確かめた直後に、同じ fd 起点（`prepared` の新しい mount top）で開き直して観測するため、
/// 以降の段が宛先へ別のマウントを重ねれば、適用時の照合が食い違いとして拒否する。
#[derive(Default)]
struct RealPrePivotOps {
    mounted: std::cell::RefCell<MountedTargets>,
}

impl RealPrePivotOps {
    /// `destination`（コンテナ内の正規化済みパス）の識別子を観測して記録する。観測・記録に失敗したら、
    /// 後段で照合できないまま進まないよう段ごと失敗させる（fail-closed）。
    fn record(
        &self,
        prepared: &PreparedRootfs,
        by: MountedBy,
        destination: &str,
        stage: IsolationStage,
    ) -> Result<(), ExecError> {
        let identity = crate::landlock::observe_mount_beneath(prepared.new_root(), destination)
            .map_err(|e| {
                ExecError::from_sys(e, stage, "observe the identity of a mounted target")
            })?;
        self.mounted
            .borrow_mut()
            .push(MountedTarget {
                by,
                destination: destination.to_string(),
                identity,
            })
            .map_err(|_| {
                ExecError::new(
                    ErrorCode::FailedPrecondition,
                    stage,
                    "too many mounted targets to record",
                )
            })
    }

    /// 記録を取り出す（`run_child_then` が Landlock 段へ渡す）。
    fn into_mounted(self) -> MountedTargets {
        self.mounted.into_inner()
    }
}

impl PrePivotOps for RealPrePivotOps {
    type Isolation = MountIsolation;
    type Prepared = PreparedRootfs;
    type Devices = DeviceSet;
    type Pivoted = PivotReport;
    type Sysfs = SysfsReport;

    fn establish(&self, binds: Option<&BindMountSet>) -> Result<MountIsolation, ExecError> {
        MountIsolation::establish_with(binds)
    }

    fn prepare_rootfs(
        &self,
        isolation: &MountIsolation,
        rootfs: &Path,
    ) -> Result<PreparedRootfs, ExecError> {
        prepare_rootfs(isolation, rootfs)
    }

    fn verify_pinned(
        &self,
        prepared: &PreparedRootfs,
        pinned: BorrowedFd<'_>,
    ) -> Result<(), ExecError> {
        let identity = |fd: BorrowedFd<'_>| -> Result<(u64, u64), ExecError> {
            let owned = fd.try_clone_to_owned().map_err(|e| {
                ExecError::from_io(&e, IsolationStage::PrepareRootfs, "dup(rootfs)")
            })?;
            let meta = std::fs::File::from(owned).metadata().map_err(|e| {
                ExecError::from_io(&e, IsolationStage::PrepareRootfs, "fstat(rootfs)")
            })?;
            Ok((meta.dev(), meta.ino()))
        };
        check_rootfs_identity(identity(pinned)?, identity(prepared.new_root())?)
    }

    fn apply_sysctls(
        &self,
        isolation: &MountIsolation,
        prepared: &PreparedRootfs,
        plan: &SysctlPlan<'_>,
    ) -> Result<(), ExecError> {
        sysctls::apply_sysctls(isolation, prepared, plan)
    }

    fn mount_sysfs(
        &self,
        isolation: &MountIsolation,
        prepared: &PreparedRootfs,
        spec: &SysfsMountSpec,
    ) -> Result<SysfsReport, ExecError> {
        // `/sys` の Landlock ルールは作らない（`landlock::rules` の doc。VFS の ro と `readonly_paths` が書き込みを塞ぐ）ため、
        // `self.record` による識別子の記録はしない。載せたマウントは `readonly_paths` が最上位を入れ替える。
        mount_sysfs(isolation, prepared, spec)
    }

    fn create_default_devices(
        &self,
        isolation: &MountIsolation,
        prepared: &PreparedRootfs,
        source: DevptsGidSource<'_>,
    ) -> Result<DeviceSet, ExecError> {
        let (report, null) = create_default_devices_with_null_source(isolation, prepared, source)?;
        for mount in [ImplicitDevMount::Dev, ImplicitDevMount::DevPts] {
            self.record(
                prepared,
                MountedBy::DefaultDevices(mount),
                mount.destination(),
                IsolationStage::CreateDevices,
            )?;
        }
        Ok(DeviceSet { report, null })
    }

    fn mount_tmpfs(
        &self,
        isolation: &MountIsolation,
        prepared: &PreparedRootfs,
        devices: &DeviceSet,
        set: &TmpfsMountSet,
    ) -> Result<(), ExecError> {
        let report = mount_tmpfs(isolation, prepared, Some(&devices.report), set)?;
        for outcome in &report.mounts {
            self.record(
                prepared,
                MountedBy::Tmpfs,
                &outcome.destination,
                IsolationStage::MountTmpfs,
            )?;
        }
        Ok(())
    }

    fn inject_files(
        &self,
        isolation: &MountIsolation,
        prepared: &PreparedRootfs,
        set: &InjectedFileSet,
    ) -> Result<(), ExecError> {
        let report = inject_files(isolation, prepared, set)?;
        for dir in &report.directories {
            self.record(
                prepared,
                MountedBy::Inject,
                &dir.destination,
                IsolationStage::InjectFiles,
            )?;
        }
        Ok(())
    }

    fn mount_binds(
        &self,
        isolation: &MountIsolation,
        prepared: &PreparedRootfs,
        set: &BindMountSet,
    ) -> Result<(), ExecError> {
        let report = super::mount_binds(isolation, prepared, set)?;
        for outcome in &report.mounts {
            self.record(
                prepared,
                MountedBy::Bind {
                    index: outcome.index,
                },
                &outcome.destination,
                IsolationStage::MountBinds,
            )?;
        }
        Ok(())
    }

    fn apply_readonly_paths(
        &self,
        isolation: &MountIsolation,
        prepared: &PreparedRootfs,
        extra: &[ProtectedPath],
    ) -> Result<(), ExecError> {
        path_masks::apply_readonly_paths(isolation, prepared, extra).map(|_| ())
    }

    fn apply_masked_paths(
        &self,
        isolation: &MountIsolation,
        prepared: &PreparedRootfs,
        devices: &DeviceSet,
        sysfs: Option<&SysfsReport>,
        extra: &[ProtectedPath],
    ) -> Result<(), ExecError> {
        masked_paths::apply_masked_paths(isolation, prepared, &devices.null, sysfs, extra)
            .map(|_| ())
    }

    fn pivot_root(
        &self,
        isolation: &MountIsolation,
        prepared: PreparedRootfs,
    ) -> Result<PivotReport, ExecError> {
        pivot_root(isolation, prepared)
    }

    fn enter_working_dir(
        &self,
        pivoted: &PivotReport,
        working_dir: &ContainerWorkingDir,
    ) -> Result<(), ExecError> {
        enter_working_dir(pivoted, working_dir)
    }
}

/// 固定した rootfs の実体と、`prepare_rootfs` の後に得た mount top の実体が同じか（純関数。fail-closed）。
/// bind mount は同じ superblock・inode を指すため、同じ実体なら `(st_dev, st_ino)` が一致する。
fn check_rootfs_identity(pinned: (u64, u64), prepared: (u64, u64)) -> Result<(), ExecError> {
    if pinned != prepared {
        return Err(ExecError::new(
            ErrorCode::PermissionDenied,
            IsolationStage::PrepareRootfs,
            "rootfs changed after validation",
        ));
    }
    Ok(())
}

/// bind mount の集合が tmpfs・注入・config の保護パスと重ならないことを、副作用の前に再検査する（純関数。
/// 多重防御。`start` 側の早期検査〔#1915〕を置き換えない。rootfs・bundle のホスト側パスはここに無いため
/// `check_against_host_paths` は対象外で、rootfs の実体照合は `mount_binds` が行う。#1914・SEC-1・SEC-2）。
fn check_bind_overlaps(
    set: &BindMountSet,
    tmpfs: Option<&TmpfsMountSet>,
    inject: Option<&InjectedFileSet>,
    config_paths: ConfigPaths<'_>,
) -> Result<(), ExecError> {
    let to_exec = |e: crate::oci_runtime::BindMountError| {
        ExecError::new(e.code(), IsolationStage::MountBinds, e.message())
    };
    if let Some(t) = tmpfs {
        set.check_against_tmpfs(t).map_err(to_exec)?;
    }
    if let Some(i) = inject {
        set.check_against_injected(i).map_err(to_exec)?;
    }
    set.check_against_protected_paths(config_paths.readonly, config_paths.masked)
        .map_err(to_exec)
}

/// pivot までの前段を固定順で実行する（TASK-29 追補・#1715。CORE-1）。順序はここだけが決める:
///
/// `establish` → `prepare_rootfs` → （固定した rootfs との照合）→ `apply_sysctls`（指定時。#2670）→ `mount_sysfs`（指定時）→ `create_default_devices` →
/// `mount_tmpfs`（指定時）→ `inject_files`（指定時）→ `mount_binds`（指定時）→ `readonly_paths`（常時）→
/// `masked_paths`（`setup` 指定時）→ `pivot_root`。
///
/// # bind mount の段の位置（#1914・TASK-29 追補。CORE-1・CORE-5・SEC-1・SEC-2）
///
/// `inject_files` の直後・`readonly_paths` の前に置く。理由:
///
/// 1. 重なりは型と検査で除外済み。宛先は `/`・`/proc`・`/sys`・`/dev` とその配下になれず（`BindMountSet`）、
///    tmpfs・注入・config の保護パスとの同一・祖先・子孫も拒否する（段の先頭の [`check_bind_overlaps`]）。
///    よって tmpfs と bind mount の入れ子は、どちら向きも受けない。
/// 2. rootfs へ作成を伴う段（tmpfs のマウント先・注入の親ディレクトリ）は bind mount より前に置く。逆順で検査漏れが
///    あると、利用者の bind mount の中へホスト側のディレクトリ・ファイルを作ってしまう。この順なら失敗は「隠れる」側に倒れる。
/// 3. 常に効く保護（`readonly_paths`・`masked_paths`）を最後に置き、上流の検査漏れがあっても固定の保護が最後に載る。
/// 4. `/dev` 系は宛先になれないため、`mount_tmpfs` のような `/dev` の作成順の証跡（`DeviceReport`）は要らない。
/// 5. OCI の「`mounts` は列挙順に適用」は、bind 以外を拒否し `mount_binds` が指定順に適用することで守る。他の段とは
///    重ならないため、順序を入れ替えても木は同じになる。
///
/// #1872（`/etc/hosts`・`/etc/resolv.conf`）の段は `inject_files` と同種のため、`inject_files` の後・`mount_binds` の前に
/// 置く想定。その際は `/etc` などの祖先 bind を拒否する重なり検査も要る（本 PR は先取りしない）。
///
/// Landlock との整合: `mount_binds` が付け替え後に自分のマウントを事後検証し、以降の段は `/proc`・`/sys` だけを対象と
/// するため、pivot 時点で宛先の最上位のマウントは bind のまま残る。`RulePath::Beneath(dest)` を辿ると適用した bind の
/// ルートに着く。ルールと bind は同じ `mounts[]` から導く（#1915 で結線済み。`LaunchSpec` が同じ `Arc<OciConfig>` から両方を作る）。
/// 各段が載せたマウントの識別子（`mnt_id`・`st_dev`・`st_ino`）は [`RealPrePivotOps`] が段の成功直後に記録し、
/// `run_child_then` が Landlock 段へ渡す。Landlock の適用時に、Mount 由来のルールの対象がその記録と一致する
/// （宛先の最上位のマウントが載せたもののままである）ことを確かめる（#2071・CORE-5・SEC-1）。なお
/// `readonly_paths` / `masked_paths` の config 由来の追加分が `/dev` 系の宛先と重なる構成では、宛先の最上位のマウントが
/// 入れ替わるため、この照合で拒否される。ただし本番の start は同じ重なりを fork・予約より前に
/// `InvalidArgument` で拒否する（`oci_runtime::start`。#2015）ため、この照合は後ろ盾である。
///
/// デバイスノードと tmpfs は pivot の前に、`PreparedRootfs` の fd を起点に作る（pivot 後は旧 root が
/// 切り離され、ホスト側の `/dev` を再解決できないため）。`setup` が `None` なら
/// `establish` → `prepare_rootfs` → `readonly_paths` → `pivot_root` の最小構成（読み取り専用パスの固定集合は
/// 常に適用する。SEC-2・#1850）。
///
/// `masked_paths`（覆うパスの固定集合。SEC-2・#1851）は、複製元の検証済み `/dev/null` を `create_default_devices` が
/// 作るため `setup` 指定時にだけ走る。本番の起動経路は常に `setup` を渡す（`IntermediateSpec.setup` は `Option` でない）ので
/// 本番では常に適用され、`setup` なしの最小構成だけが飛ばす（ESC スイートは影響を受けない。#1853 で入口を切り替える）。
/// 順序は「読み取り専用化 → 覆う」（読み取り専用化の再帰 bind が覆いの子マウントに `ro` を付け損ねないため）。
///
/// `/proc`・`/sys` との順序（#2005・SEC-2）: procfs は `prepare_rootfs` が `rootfs/proc` にマウント済みで、
/// `readonly_paths`・`masked_paths` はその上に載る。pivot 後にはマウントしない（後からのマウントは保護を覆い隠す）。
/// `mounts[]` の sysfs（`mount_sysfs`。#2020）は `verify_pinned` の直後（`create_default_devices` の前）に載せ、
/// `readonly_paths` の再帰 bind と読み取り専用化がその上に載るようにする。順序は単体テスト
/// `core1_run_pre_pivot_order_is_fixed` が、積み方は結合試験 `readonly_paths`・`masked_paths` が検査する。
fn run_pre_pivot<O: PrePivotOps>(
    ops: &O,
    rootfs: &Path,
    setup: Option<PrePivotSetup<'_>>,
) -> Result<(O::Isolation, O::Pivoted), Box<StepError>> {
    use PrePivotStep as S;
    let isolation = ops
        .establish(setup.as_ref().and_then(|s| s.binds))
        .map_err(StepError::at(S::Establish))?;
    let prepared = ops
        .prepare_rootfs(&isolation, rootfs)
        .map_err(StepError::at(S::PrepareRootfs))?;
    let mut devices = None;
    let mut sysfs = None;
    let config_paths = setup.map_or(ConfigPaths::NONE, |s| s.config_paths);
    if let Some(setup) = setup {
        if let Some(pinned) = setup.pinned_rootfs {
            ops.verify_pinned(&prepared, pinned)
                .map_err(StepError::at(S::VerifyPinned))?;
        }
        if let Some(plan) = setup.sysctls {
            ops.apply_sysctls(&isolation, &prepared, plan)
                .map_err(StepError::at(S::ApplySysctls))?;
        }
        if let Some(spec) = setup.sysfs {
            sysfs = Some(
                ops.mount_sysfs(&isolation, &prepared, spec)
                    .map_err(StepError::at(S::MountSysfs))?,
            );
        }
        let created = ops
            .create_default_devices(&isolation, &prepared, setup.devices)
            .map_err(StepError::at(S::CreateDefaultDevices))?;
        if let Some(set) = setup.tmpfs {
            ops.mount_tmpfs(&isolation, &prepared, &created, set)
                .map_err(StepError::at(S::MountTmpfs))?;
        }
        if let Some(set) = setup.inject {
            ops.inject_files(&isolation, &prepared, set)
                .map_err(StepError::at(S::InjectFiles))?;
        }
        if let Some(set) = setup.binds {
            check_bind_overlaps(set, setup.tmpfs, setup.inject, setup.config_paths)
                .map_err(StepError::at(S::MountBinds))?;
            ops.mount_binds(&isolation, &prepared, set)
                .map_err(StepError::at(S::MountBinds))?;
        }
        devices = Some(created);
    }
    // `setup` の有無によらず常に適用する（外す入口を作らない。SEC-2・#1850）。
    ops.apply_readonly_paths(&isolation, &prepared, config_paths.readonly)
        .map_err(StepError::at(S::ReadonlyPaths))?;
    if let Some(devices) = &devices {
        ops.apply_masked_paths(
            &isolation,
            &prepared,
            devices,
            sysfs.as_ref(),
            config_paths.masked,
        )
        .map_err(StepError::at(S::MaskedPaths))?;
    }
    let pivoted = ops
        .pivot_root(&isolation, prepared)
        .map_err(StepError::at(S::PivotRoot))?;
    // pivot 直後・ステージ列の前に作業ディレクトリへ移る（OCI-1）。根は pivot_root 済みのため省く。
    if let Some(wd) = setup.and_then(|s| s.working_dir).filter(|w| !w.is_root()) {
        ops.enter_working_dir(&pivoted, wd)
            .map_err(StepError::at(S::WorkingDir))?;
    }
    Ok((isolation, pivoted))
}

/// [`run_pre_pivot`] の失敗（どの段で失敗したか＋元のエラー。段は状態 pipe で親へ返す。#1815）。
#[derive(Debug)]
struct StepError {
    step: PrePivotStep,
    error: ExecError,
}

impl StepError {
    fn at(step: PrePivotStep) -> impl FnOnce(ExecError) -> Box<Self> {
        move |error| Box::new(Self { step, error })
    }
}

/// 子の前段（[`run_pre_pivot`] → ステージ列）を共通化した本体。
///
/// 終端 `terminal` は組み込みステージ（capability 削減・`NO_NEW_PRIVS`・seccomp）の通過後にだけ呼ばれる。
/// 本番の `run_child` は exec を、結合試験専用の `spawn_container_probe` 系は exec の代わりに
/// プローブを渡す。exec を呼べるのは `run_child` の終端だけで、fail-closed（`require_restriction_evidence`）
/// は変わらない。
fn run_child_then<T>(
    rootfs: &Path,
    setup: Option<PrePivotSetup<'_>>,
    stages: StagePipeline,
    terminal: impl FnOnce(
        &MountIsolation,
        &PivotReport,
        Result<LaunchReady, LaunchNotReady>,
    ) -> Result<T, ExecError>,
) -> Result<T, ExecError> {
    let status = setup.and_then(|s| s.status);
    let ops = RealPrePivotOps::default();
    let (isolation, report) = match (run_pre_pivot(&ops, rootfs, setup), status) {
        (Ok(done), None) => done,
        (Err(failed), None) => return Err(failed.error),
        // 成功の報告に失敗したら先へ進まない（親が結果を判定できないまま exec しない。fail-closed）。
        (Ok(done), Some(status)) => {
            report_ready(status)?;
            done
        }
        (Err(failed), Some(status)) => {
            let failure = PrePivotFailure::from_exec_error(failed.step, &failed.error);
            if report_failure(status, &failure).is_err() {
                let _ = writeln!(
                    std::io::stderr(),
                    "fandhe-container: the pre-pivot status could not be reported"
                );
            }
            return Err(failed.error);
        }
    };
    // pivot 後・終端前にステージ列を固定順で実行する。pivot 前段が記録したマウントの識別子を Landlock 段へ渡す
    // （Mount 由来のルールの対象がマウントのルートであることの照合。#2071）。
    stages.with_mounted_targets(ops.into_mounted()).run_then(
        |_stage_report, _capability_report, evidence| terminal(&isolation, &report, evidence),
    )
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
/// 本番の `run_child` は終端で `verify_caller` と `require_restriction_evidence` を行うが、本関数では
/// `verify_caller` のみ行い `require_restriction_evidence` は呼ばない。プローブ用の構成（Landlock を載せない
/// `escape_suite` / `fork_exec_isolation` のシナリオ等）では `LaunchReady` がそろわず、呼ぶとプローブが
/// 実行できないため。これは exec を伴わない検証専用経路に限った明示的な例外で、
/// 本関数の成功（終了コード 0）は「制限が適用された証跡」ではなく、本番経路の成功判定・exec 許可の根拠に
/// 使ってはならない。攻撃が拒否されたことの判定は probe 側の観測（fd 経由の結果）だけで行う。
/// プローブにも `LaunchReady` を要求する形への置き換えは、シナリオの構成の見直しと併せて後続で行う（#1714 の範囲外）。
///
/// # 契約
///
/// - 終了コード: `probe` が正常に戻れば 0、前段失敗は既存規約（`exit_code_for`）、`probe` の panic は
///   `EXIT_SETUP_FAILED`（`fork_single_threaded` の `catch_unwind`）
/// - probe の結果は終了コードではなく、呼び出し側が fork 前に用意した fd（pipe 等）で受け渡す
/// - 単体テストは置かない（fork と分離環境を要するため `tests/escape_suite.rs` の結合試験でカバーする）
///
/// # 残す呼び出し元と理由（#2630・REPAIR-3）
///
/// プローブの成功は証跡ではない。`tests/seccomp.rs` はエントリポイント内の観測へ移したため本関数を使わない
/// （#2386・#2543）。残る呼び出し元は `escape_suite`（ESC-03・ESC-06 を含む）・`readonly_paths`・`masked_paths`・
/// `config_paths`・`config_paths_implicit_dev`・`sysfs_mount`・`fork_exec_isolation` で、#2630 で呼び出し元ごとに
/// 判断した結果、いずれも移さず**本関数は廃止しない**（全部移せたときだけ廃止する）。
/// fork 子で観測しても識別性が落ちない根拠: seccomp フィルタ・`NO_NEW_PRIVS`・Landlock のドメイン・
/// マウントの状態は execve をまたいで変わらない。capability は例外で、exec 後の値は `production_launcher` の
/// シナリオ J が照合する。
///
/// - `masked_paths`・`config_paths`・`sysfs_mount`: exec 経路の試験用入口が `config_paths` / `sysfs` を受け取らず、
///   `platform-ci` の `--ignored` 対象でもないため移行後の観測を CI で確かめられない。exec 経路は Landlock が必須で
///   `EACCES` の発生源も増える
/// - `config_paths_implicit_dev`: Landlock なしの exec 層の観測が目的で、exec 経路では対象が変わる
/// - `fork_exec_isolation` の `landlock-apply-*`: Landlock のドメインは execve をまたいで変わらず、exec 側は
///   `landlock-exec` / `landlock-missing` が照合済み
/// - `readonly_paths`: マウントの状態は execve をまたいで変わらず移せる見込みはあるが、`platform-ci` で観測を確かめる
///   前に移すと検証不能な変更になるため、exec 経路の観測の確認（Landlock が書き込み用 `open` の errno を変えないこと）と
///   同時に後続で移す
/// - `escape_suite`: ESC-03 は listener の受け渡しと応答ループを 1 つのハーネスで扱い、exec 後の対応物は `supervisor_bin_real`
///   のシナリオ E と `production_launcher` のシナリオ J。ESC-06 の exec 後の対応物は `tests/seccomp.rs` の `kill-<名前>` と
///   シナリオ K。いずれも移さない
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
            let result = run_child_then(rootfs, None, stages, |isolation, _report, _evidence| {
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

/// [`spawn_container_probe`] に、ERRNO 側の禁止 syscall の拒否を `USER_NOTIF` で受け取る listener を足した版。
/// 結合試験 `tests/escape_suite.rs` の ESC-03 専用（SEC-2・SEC-4・TASK-42・#2028。監査配送 7/7）。
///
/// 子は本番の launch 経路と同じ `Seccomp` 段（`ErrnoDelivery::UserNotif` ＋ `NEW_LISTENER`）で filter を適用し、
/// listener を `SCM_RIGHTS` で親へ渡して ACK を待つ。親は `receive_listener`（`SCM_CREDENTIALS` の pid・fd の種別・
/// `O_CLOEXEC`・fd がちょうど 1 本を検証して ACK を返す本番と同じ検証）を通ってから listener を返す。子は ACK を
/// 受けるまで `probe` に進めないため、呼び出し側が応答者を立てる前に `probe` が拒否対象の syscall を発行して
/// `ENOSYS` になることはない（通知は応答者が読むまでカーネル内で保留される）。
///
/// 戻り値の listener は呼び出し側（試験）が持つ応答者の入力で、応答は `-EPERM` だけにする（許可へ覆さない）。
/// 受け渡せなければ子を期限つきで kill して回収し `Err` を返す（listener 無しで走らせない。fail-closed）。
/// 制限適用証跡の例外・契約・残す理由は [`spawn_container_probe`] と同じ（REPAIR-3）。
/// 呼び出し元は `escape_suite` の ESC-03 だけで、応答ハブ（supervisor の `SeccompNotifyHub`）そのものの試験ではない（hub の通しは `supervisor_bin_real` のシナリオ E が担う。#2482）。
#[cfg(feature = "escape-probe")]
#[doc(hidden)]
pub fn spawn_container_probe_with_seccomp_listener<F>(
    rootfs: &Path,
    stages: StagePipeline,
    probe: F,
) -> Result<(ContainerChild, super::SeccompListener), ExecError>
where
    F: FnOnce(),
{
    use super::seccomp_listener::{ListenerSender, listener_socketpair, receive_listener};
    /// 子が filter を適用して listener を渡すまでの親の待ち上限（REPAIR-5）。
    const HANDOVER_TIMEOUT: Duration = Duration::from_secs(30);
    /// 受け渡し失敗時の子の回収の待ち上限。
    const REAP_TIMEOUT: Duration = Duration::from_secs(5);

    let (parent_end, child_end) = listener_socketpair()?;
    let delivery = crate::seccomp::ErrnoDelivery::UserNotif;
    let stages = stages
        .with_seccomp_delivery(delivery)
        .with_listener_sender(ListenerSender::new(child_end).with_delivery(delivery));
    let child = spawn_container_probe(rootfs, stages, probe)?;
    let deadline = Instant::now() + HANDOVER_TIMEOUT;
    match receive_listener(parent_end.as_fd(), child.pid(), deadline) {
        Ok(listener) => Ok((child, listener)),
        Err(err) => {
            // 受け渡せない子は ACK 待ちか終了済み。回収できなくても元の失敗を返す（孤児化は kill で避ける）。
            let _ = child.kill_and_reap(REAP_TIMEOUT);
            Err(err)
        }
    }
}

/// [`spawn_container_probe`] の `setup` 付き版。子が専用 `/dev`（`create_default_devices`）を作り、続く
/// `masked_paths` 段（覆うパスの固定集合。SEC-2・TASK-29 追補・#1851）まで本番と同じ順序で適用してから、pivot 後に
/// `probe` を実行する。結合試験 `tests/masked_paths.rs` 専用で、本番 launcher には依存しない（`exec_entrypoint` の
/// fail-closed は変えない）。`tmpfs`・`inject`・`pinned_rootfs`・`status` は指定しない。
/// `spawn_container_probe` と同じ制限適用証跡の例外・契約・残す理由に従う（REPAIR-3）。
#[cfg(feature = "escape-probe")]
#[doc(hidden)]
pub fn spawn_container_probe_with_devices<F>(
    rootfs: &Path,
    stages: StagePipeline,
    devices: DevptsGidSource<'_>,
    probe: F,
) -> Result<ContainerChild, ExecError>
where
    F: FnOnce(),
{
    spawn_container_probe_with_config_paths(rootfs, stages, devices, &[], &[], probe)
}

/// [`spawn_container_probe_with_devices`] に config 由来の追加パス（`linux.readonlyPaths` / `maskedPaths` 相当。
/// 固定集合への追加。SEC-2・TASK-29 追補・#1852）を渡す版。結合試験 `tests/config_paths.rs` 専用。
/// 各要素は config と同じ検証（絶対パス必須・`..` 拒否）を通し、不正なら fork せず `InvalidArgument` を返す。
#[cfg(feature = "escape-probe")]
#[doc(hidden)]
pub fn spawn_container_probe_with_config_paths<F>(
    rootfs: &Path,
    stages: StagePipeline,
    devices: DevptsGidSource<'_>,
    readonly: &[&str],
    masked: &[&str],
    probe: F,
) -> Result<ContainerChild, ExecError>
where
    F: FnOnce(),
{
    spawn_container_probe_inner(rootfs, stages, devices, None, readonly, masked, probe)
}

/// [`spawn_container_probe_with_config_paths`] に tmpfs の集合（`/dev/shm` 等）も載せる版。結合試験
/// `tests/config_paths_implicit_dev.rs` 専用（SEC-2・CORE-5・#2015）。`PrePivotSetup.tmpfs` を渡すため、
/// 本番と同じ順序（デバイス -> tmpfs -> readonlyPaths -> maskedPaths -> pivot）で適用する。本番 launcher
/// （Landlock 必須）には依存せず、`exec_entrypoint` の fail-closed は変えない。
#[cfg(feature = "escape-probe")]
#[doc(hidden)]
pub fn spawn_container_probe_with_tmpfs_and_config_paths<F>(
    rootfs: &Path,
    stages: StagePipeline,
    devices: DevptsGidSource<'_>,
    tmpfs: &TmpfsMountSet,
    readonly: &[&str],
    masked: &[&str],
    probe: F,
) -> Result<ContainerChild, ExecError>
where
    F: FnOnce(),
{
    spawn_container_probe_inner(
        rootfs,
        stages,
        devices,
        Some(tmpfs),
        readonly,
        masked,
        probe,
    )
}

/// 上の 2 つの probe の共通本体（`tmpfs` の有無だけが違う）。
#[cfg(feature = "escape-probe")]
fn spawn_container_probe_inner<F>(
    rootfs: &Path,
    stages: StagePipeline,
    devices: DevptsGidSource<'_>,
    tmpfs: Option<&TmpfsMountSet>,
    readonly: &[&str],
    masked: &[&str],
    probe: F,
) -> Result<ContainerChild, ExecError>
where
    F: FnOnce(),
{
    let parse = |list: &[&str]| -> Result<Vec<ProtectedPath>, ExecError> {
        list.iter()
            .map(|p| {
                ProtectedPath::parse(p, crate::oci_runtime::CONFIG_MAX_PATH_BYTES).ok_or_else(
                    || {
                        ExecError::new(
                            ErrorCode::InvalidArgument,
                            IsolationStage::Spawn,
                            "invalid config path for the probe",
                        )
                    },
                )
            })
            .collect()
    };
    let (readonly, masked) = (parse(readonly)?, parse(masked)?);
    let pid = sys::fork_single_threaded(
        move || {
            let setup = PrePivotSetup {
                sysctls: None,
                devices,
                tmpfs,
                inject: None,
                binds: None,
                sysfs: None,
                pinned_rootfs: None,
                config_paths: ConfigPaths {
                    readonly: &readonly,
                    masked: &masked,
                },
                status: None,
                working_dir: None,
            };
            let result = run_child_then(
                rootfs,
                Some(setup),
                stages,
                |isolation, _report, _evidence| {
                    isolation.verify_caller(IsolationStage::Exec)?;
                    probe();
                    Ok(())
                },
            );
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

/// [`spawn_container_probe_with_devices`] に `/sys` の sysfs の供給（`mount_sysfs`。#2020・SEC-2）を足した版。
/// 子は本番と同じ順序（`verify_pinned` の直後に `mount_sysfs` → `create_default_devices` → `readonly_paths` →
/// `masked_paths` → `pivot_root`）で適用してから、pivot 後に `probe` を実行する。結合試験 `tests/sysfs_mount.rs`
/// 専用で、本番 launcher には依存しない。`spawn_container_probe` と同じ制限適用証跡の例外・契約・残す理由に従う（REPAIR-3）。
#[cfg(feature = "escape-probe")]
#[doc(hidden)]
pub fn spawn_container_probe_with_sysfs<F>(
    rootfs: &Path,
    stages: StagePipeline,
    devices: DevptsGidSource<'_>,
    sysfs: &SysfsMountSpec,
    probe: F,
) -> Result<ContainerChild, ExecError>
where
    F: FnOnce(),
{
    let pid = sys::fork_single_threaded(
        move || {
            let setup = PrePivotSetup {
                sysctls: None,
                devices,
                tmpfs: None,
                inject: None,
                binds: None,
                sysfs: Some(sysfs),
                working_dir: None,
                pinned_rootfs: None,
                config_paths: ConfigPaths::NONE,
                status: None,
            };
            let result = run_child_then(
                rootfs,
                Some(setup),
                stages,
                |isolation, _report, _evidence| {
                    isolation.verify_caller(IsolationStage::Exec)?;
                    probe();
                    Ok(())
                },
            );
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
///
/// 専用の `/dev`（`create_default_devices`）は載せない（#2700・CORE-2・SEC-2・REPAIR-3。配線しないと決めた）。
/// 製品コードにこの入口の呼び出し元は無く（結合試験だけ）、本番の起動は `ProductionLauncher` が
/// `spawn_container_via_intermediate` を通す経路で、`PrePivotSetup.devices` から `/dev` を結線済み（#1816）。
/// 配線しない理由は次のとおり。
/// - 本番は常に `setup` を渡すため、ここへ配線しても本番の挙動は変わらない
/// - `StagePipeline::new()`（Landlock 無し）では制限適用の証跡（`LaunchReady`。#1714）が作られず、exec は常に拒否される
///   （fail-closed。`/dev` を足しても観測できる効果が無い）
/// - 配線には `DevptsGidSource` の入力が要り、本番で使わない関数の公開シグネチャを変えることになる
/// - `masked_paths` も適用しない最小構成に `/dev` だけを足すと部分適用になり、実装済みを装う（REPAIR-3）
/// - `/dev` が要る試験には試験専用の入口 `spawn_container_with_stages_and_devices` がある
///
/// 本番の起動にこの入口を使ってはならない（分離が弱くなる）。
pub fn spawn_container(rootfs: &Path, entry: &Entrypoint) -> Result<ContainerChild, ExecError> {
    spawn_container_with_stages(rootfs, entry, StagePipeline::new())
}

/// [`spawn_container`] にステージ列（#832・TASK-27.4.2）を渡す版。
///
/// `stages` は親（fork 前）で構築し、fork で子へコピーされて子の pivot 後・exec 前に固定順で
/// 実行される。フックの失敗・panic では exec に進まず `EXIT_SETUP_FAILED` で終わる。
/// `/dev` は載せない（`spawn_container` と同じ。#2700）。
/// 挙動の変更（#1714）: `stages` に `with_landlock` を載せて全段が成功したときだけ制限適用の証跡
/// （`LaunchReady`）がそろい exec へ進む。Landlock 無し・独自の Landlock フック・ダミーフックだけでは
/// 証跡にならず exec は拒否される（fail-closed）。
/// fork に成功した後、親の側で `dev.tty.legacy_tiocsti` が `1` のときだけ警告 1 行を標準エラーへ待たずに出す
/// （CORE-5・SEC-1・REPAIR-4・REPAIR-5・#1739。出力は `report_legacy_tiocsti_to`。起動の可否は変えない）。
pub fn spawn_container_with_stages(
    rootfs: &Path,
    entry: &Entrypoint,
    stages: StagePipeline,
) -> Result<ContainerChild, ExecError> {
    spawn_container_reporting(
        rootfs,
        entry,
        stages,
        crate::legacy_tiocsti::read_host(),
        std::io::stderr().as_fd(),
    )
    .map(|(child, _report)| child)
}

/// [`spawn_container_with_stages`] に、コンテナの stdout / stderr の付け替え先（[`ChildStdio`]）を足した版
/// （TASK-164 追補・#1471・SUP-7・SUP-1）。
///
/// `stdio` の書き込み側は子が fd 1・2 へ付け替えて exec へ引き継ぎ、親の側のコピーは fork 後に閉じる。読み取り側
/// （[`ChildStdio::pipes`] が返したもの）は呼び出し側が保持し、supervisor の行単位捕捉へ渡す。
/// `ChildStdio::none()` なら [`spawn_container_with_stages`] と同じ（3 本とも `/dev/null`）。
/// 副作用: パイプ指定時、子の setup 失敗診断（`fandhe-container: ...` の 1 行）もコンテナのログに入る。
pub fn spawn_container_with_stages_and_stdio(
    rootfs: &Path,
    entry: &Entrypoint,
    stages: StagePipeline,
    stdio: ChildStdio,
) -> Result<ContainerChild, ExecError> {
    spawn_container_reporting_with_stdio(
        rootfs,
        entry,
        stages,
        crate::legacy_tiocsti::read_host(),
        std::io::stderr().as_fd(),
        stdio,
    )
    .map(|(child, _report)| child)
}

/// `dev.tty.legacy_tiocsti` の警告 1 行の出力結果（CORE-5・SEC-1・REPAIR-4・REPAIR-5・#1739）。
/// 真偽値にせず、将来の状態を足せる形にする（`#[non_exhaustive]`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LegacyTiocstiReport {
    /// 警告の対象ではない（`1` 以外。何も出していない）。
    NotApplicable,
    /// 警告の対象で、`emit_diagnostic_line_to` へ 1 回渡した。結果（送信済み・捨てた理由）を持つ。
    Emitted(super::DiagnosticDelivery),
}

/// 観測結果が `Enabled` なら警告 1 行を `out` へ待たずに出し、結果を返す（CORE-5・SEC-1・REPAIR-4・REPAIR-5・#1739）。
/// 出力は診断ログの共通経路（`emit_diagnostic_line_to`。AF_UNIX の socket 以外へは書かず、満杯でも待たない）の
/// 1 回だけで、成否で起動の可否は変えない。
pub fn report_legacy_tiocsti_to(
    state: crate::legacy_tiocsti::LegacyTiocsti,
    out: BorrowedFd<'_>,
) -> LegacyTiocstiReport {
    match crate::legacy_tiocsti::warning_line(state) {
        Some(line) => LegacyTiocstiReport::Emitted(super::emit_diagnostic_line_to(out, line)),
        None => LegacyTiocstiReport::NotApplicable,
    }
}

/// `spawn_container_with_stages` の本体。観測値 `state` と警告の出力先 `out` を注入できる形にして、起動経路から
/// 警告が出ることを結合試験で照合する（REPAIR-12・#1739）。fork に成功した後、親の側で 1 回だけ報告する
/// （fork 失敗時は出さない）。子は exec 直前に fd 0〜2 を `/dev/null` へ差し替えるため、運用者へ確実に届く親の側で出す。
fn spawn_container_reporting(
    rootfs: &Path,
    entry: &Entrypoint,
    stages: StagePipeline,
    state: crate::legacy_tiocsti::LegacyTiocsti,
    out: BorrowedFd<'_>,
) -> Result<(ContainerChild, LegacyTiocstiReport), ExecError> {
    spawn_container_reporting_with_stdio(rootfs, entry, stages, state, out, ChildStdio::none())
}

/// [`spawn_container_reporting`] に stdout / stderr の付け替え先を足した本体（#1471）。`stdio` は fork 後に
/// 親の側でも drop され、親が持つ書き込み側は閉じる（読み取り側が EOF に達するための条件）。
fn spawn_container_reporting_with_stdio(
    rootfs: &Path,
    entry: &Entrypoint,
    stages: StagePipeline,
    state: crate::legacy_tiocsti::LegacyTiocsti,
    out: BorrowedFd<'_>,
    stdio: ChildStdio,
) -> Result<(ContainerChild, LegacyTiocstiReport), ExecError> {
    let pid = sys::fork_single_threaded(
        move || child_main(rootfs, entry, stages, None, stdio),
        EXIT_SETUP_FAILED,
    )
    .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "fork"))?;
    let report = report_legacy_tiocsti_to(state, out);
    Ok((ContainerChild::spawned(pid), report))
}

/// 結合試験専用: 観測値と警告の出力先を注入して `spawn_container_with_stages` と同じ経路を通す
/// （CORE-5・SEC-1・REPAIR-12・#1739）。通常の利用者は呼ばない。
#[doc(hidden)]
#[cfg(feature = "exec-test-support")]
pub fn spawn_container_with_stages_reporting_for_test(
    rootfs: &Path,
    entry: &Entrypoint,
    stages: StagePipeline,
    state: crate::legacy_tiocsti::LegacyTiocsti,
    out: BorrowedFd<'_>,
) -> Result<(ContainerChild, LegacyTiocstiReport), ExecError> {
    spawn_container_reporting(rootfs, entry, stages, state, out)
}

/// 結合試験専用: `spawn_container_with_stages` に、pivot 前の専用 `/dev`（`create_default_devices`）を足した版
/// （CORE-5・SEC-1・REPAIR-12・#1714）。
///
/// `LaunchReady` がそろった後の `redirect_stdio_to_null` が検証済みの `/dev/null`（文字デバイス 1:3）を開けることを、
/// 実 exec（`execveat`）の成功で照合するための入口。本番の `/dev` は launcher 経路で結線済み（#1816）で、
/// 最小入口 `spawn_container` へは `/dev` を配線しない（#2700）ため、`/dev` が要る試験だけが使う試験専用の入口。
/// 制限適用の証跡の要求（`require_restriction_evidence`）は `spawn_container_with_stages` と同じく行う。
/// 通常の利用者は呼ばない。
#[doc(hidden)]
#[cfg(feature = "exec-test-support")]
pub fn spawn_container_with_stages_and_devices(
    rootfs: &Path,
    entry: &Entrypoint,
    stages: StagePipeline,
    devices: DevptsGidSource<'_>,
) -> Result<ContainerChild, ExecError> {
    let pid = sys::fork_single_threaded(
        || match run_child(
            rootfs,
            entry,
            stages,
            Some(PrePivotSetup {
                sysctls: None,
                devices,
                tmpfs: None,
                inject: None,
                binds: None,
                sysfs: None,
                pinned_rootfs: None,
                config_paths: ConfigPaths::NONE,
                status: None,
                working_dir: None,
            }),
            StdioNulling::ALL,
        ) {
            Ok(never) => match never {},
            Err(err) => {
                let _ = writeln!(std::io::stderr(), "fandhe-container: {err}");
                exit_code_for(&err)
            }
        },
        EXIT_SETUP_FAILED,
    )
    .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "fork"))?;
    Ok(ContainerChild::spawned(pid))
}

/// `spawn_container_via_intermediate`（`exec/launch_intermediate.rs`）が起動に失敗したときの値
/// （CORE-2・REPAIR-5・#1815・#1816）。
///
/// `rejection` が起動失敗の理由（監査の記録結果を含む）。子の回収（`SIGKILL` 後の `waitpid`）が期限内に
/// 終わらなかった場合だけ、`unreaped` に未回収の子（PID 1 または中間プロセス）のハンドルを、`reap_error` に
/// 回収失敗の理由を載せて返す。`ContainerChild` は drop で kill / wait をしないため、呼び出し側（本番 launcher）は
/// `unreaped` を期限付きの `kill_and_reap` で再回収できる所有者へ引き継ぐ責務を負う（孤児化させない）。
#[derive(Debug)]
pub(crate) struct PreparedLaunchFailure {
    /// 起動失敗の理由と監査の記録結果。
    pub(crate) rejection: AuditedRejection<ExecError>,
    /// 回収できなかった子(回収済みなら空。中間プロセスの回収失敗時は PID 1 も未回収なら 2 個になり得る)。
    pub(crate) unreaped: Vec<ContainerChild>,
    /// 回収失敗の理由(最初の失敗)。`unreaped` が空でないとき、または報告前の PID 1 の探索自体ができなかったとき
    /// (`unreaped` は空のまま)に `Some`。どちらも「子が残っている可能性」を表す(CORE-2)。
    pub(crate) reap_error: Option<ExecError>,
    /// 報告前の PID 1 の探索が未完了の起動識別子(探索を skip した・`/proc` の列挙や読み取りに失敗した場合)。
    /// 呼び出し側(launcher の `confirm_no_process`。#1817)が中間プロセスの回収後に再探索する。空なら探索は完了
    /// している。`unreaped` が空でも非空になり得る(CORE-2)。
    pub(crate) rescans: Vec<super::launch_intermediate::LaunchTag>,
}

impl PreparedLaunchFailure {
    /// 子が残らない失敗(回収済み・または子を作る前に拒否した)。
    pub(crate) fn clean(rejection: AuditedRejection<ExecError>) -> Self {
        Self {
            rejection,
            unreaped: Vec::new(),
            reap_error: None,
            rescans: Vec::new(),
        }
    }

    /// 子を回収できなかった失敗(ハンドルごと返す。孤児化させない。CORE-2)。
    pub(crate) fn with_unreaped(
        rejection: AuditedRejection<ExecError>,
        child: ContainerChild,
        reap_error: ExecError,
    ) -> Self {
        Self {
            rejection,
            unreaped: vec![child],
            reap_error: Some(reap_error),
            rescans: Vec::new(),
        }
    }
}

/// 待ちのポーリング間隔。
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);
/// `wait_timeout` に渡せる最大値（`Instant` の加算オーバーフローを避けるための丸め）。
const WAIT_TIMEOUT_MAX: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// `SIGKILL` 後に回収を待つ上限。
pub(super) const KILL_REAP_TIMEOUT: Duration = Duration::from_secs(5);

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
/// # pidfd を開けなかったときの扱い（#1617・SUP-6・SEC-1・REPAIR-4）
///
/// `pidfd_open` の失敗は [`LaunchPidfdUnavailable`] に分類して保持し（[`ContainerChild::pidfd_unavailable`]）、
/// 未対応（`ENOSYS`）以外は [`LaunchPidfdUnavailable::log_line`] で構造化ログ 1 行にできる（`EMFILE`・`ENFILE`・
/// `ENOMEM`・`EPERM` 等を未対応と取り違えない。出力は `spawned` が待たない経路で行う）。`new` 自身は I/O をしない（停止した stderr で
/// ブロックしない。REPAIR-5）。起動自体は失敗させない: `new` は fork の後に呼ばれ、失敗しうる構成にすると全 fork 箇所
/// （`spawn_container*`・各 probe・exec の worker・rootless mapper・`observe_*`）で子の kill と回収が要り、
/// 一時的な `EMFILE` がコンテナの起動まで落とすことになるため。代わりに本番の exec の入口
/// （supervisor の `run_command_with_pidfd`）が pidfd を必須の引数にしており、`pidfd()` が `None` のハンドル
/// からは exec できない（fail-closed が型で強制される）。シグナル送信は `kill(2)` へ退避し、回収済み pid へ
/// 送らない排他は上記の `Mutex` が保つ。
///
/// `Drop` では kill / wait しない（コンテナの寿命を親ハンドルに暗黙で縛らない）。回収の責任は
/// 呼び出し元にあり、放置すると子はゾンビとして残る。
#[must_use]
#[derive(Debug)]
pub struct ContainerChild {
    pid: u32,
    /// fork 直後に開いた pidfd（プロセス同一性の保持。開けない環境では `None` で `kill(2)` へ退避）。
    pidfd: Option<OwnedFd>,
    /// `pidfd` が `None` の理由（`pidfd` が `Some` なら `None`）。
    pidfd_unavailable: Option<LaunchPidfdUnavailable>,
    reap: Mutex<ReapCell>,
}

/// 起動時の `pidfd_open` が失敗した理由の分類（観測用。#1617・SUP-6・SEC-1・REPAIR-4）。
///
/// [`ContainerChild::pidfd_unavailable`] が返す。exec の可否は理由に依らず「pidfd 無し」で同じ（fail-closed）だが、
/// 運用者が原因を追えるよう未対応・拒否・資源枯渇等を区別する。errno 名は固定語彙で、カーネル由来の自由文字列を
/// 持たない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LaunchPidfdUnavailable {
    /// カーネルが `pidfd_open` を知らない（`ENOSYS`。Linux 5.3 未満）。想定内の環境のためログは出さない。
    Unsupported,
    /// `EPERM`。exec worker 自身の seccomp 許可リストは `pidfd_open` を許すため、外側のポリシー（ホスト側
    /// seccomp・LSM）による拒否を意味する。
    Denied,
    /// 上記以外の失敗（`EMFILE`・`ENFILE`・`ENOMEM` 等）。`errno` は既知名か、一覧外は `"other"`。
    Failed {
        /// errno の固定語彙名。
        errno: &'static str,
    },
}

impl LaunchPidfdUnavailable {
    /// ログの `reason` に使う固定語彙。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Denied => "denied",
            Self::Failed { .. } => "failed",
        }
    }

    /// 縮退理由の構造化ログ 1 行（`Unsupported` は想定内なので `None`）。固定語彙のみで、pid・パス・数値を載せない。
    ///
    /// 出力は呼び出し側の責務（`ContainerChild::new` は書かない。#1683 の指摘: 停止した stderr への同期書き込みが
    /// ハンドル返却と期限管理を止めるため。REPAIR-5・REPAIR-4）。
    ///
    /// 本番の spawn 経路では `ContainerChild::spawned` が fork 直後の親で 1 回だけ、待たない出力経路
    /// （`exec::emit_diagnostic_line_to`。AF_UNIX の socket 以外へは書かず、満杯でも待たない）へ出す（#1697）。
    /// spawn から `wait_timeout` までの経路に同期書き込みを置かないため、止まった stderr でも停止しない。
    pub fn log_line(self) -> Option<String> {
        if self == Self::Unsupported {
            return None;
        }
        Some(format!(
            "{{\"component\":\"core.exec\",\"operation\":\"launch_pidfd\",\"outcome\":\"unavailable\",\"reason\":\"{}\",\"errno\":\"{}\"}}",
            self.as_str(),
            self.errno_name()
        ))
    }

    /// ログの `errno` に使う固定語彙名（`Unsupported` は `ENOSYS`）。
    pub fn errno_name(self) -> &'static str {
        match self {
            Self::Unsupported => "ENOSYS",
            Self::Denied => "EPERM",
            Self::Failed { errno } => errno,
        }
    }
}

/// errno を固定語彙名へ写す（ログへカーネル由来の値をそのまま載せない。一覧外は `"other"`）。
fn pidfd_errno_name(errno: i32) -> &'static str {
    match errno {
        e if e == sys::EMFILE => "EMFILE",
        e if e == sys::ENFILE => "ENFILE",
        e if e == sys::ENOMEM => "ENOMEM",
        e if e == sys::EPERM => "EPERM",
        e if e == sys::ENOSYS => "ENOSYS",
        e if e == sys::EINVAL => "EINVAL",
        e if e == sys::ESRCH => "ESRCH",
        e if e == sys::EACCES => "EACCES",
        _ => "other",
    }
}

/// `pidfd_open` の結果を fd か失敗理由に分類する（純関数。`ContainerChild::new` が使う）。
fn classify_pidfd_open(
    result: Result<OwnedFd, SysError>,
) -> Result<OwnedFd, LaunchPidfdUnavailable> {
    match result {
        Ok(fd) => Ok(fd),
        Err(SysError::Unsupported) => Err(LaunchPidfdUnavailable::Unsupported),
        Err(SysError::Os(e)) if e == sys::ENOSYS => Err(LaunchPidfdUnavailable::Unsupported),
        Err(SysError::Os(e)) if e == sys::EPERM => Err(LaunchPidfdUnavailable::Denied),
        Err(SysError::Os(e)) => Err(LaunchPidfdUnavailable::Failed {
            errno: pidfd_errno_name(e),
        }),
        // `pidfd_open` は fork の単一スレッド検査を通らないため到達しない。到達しても理由を捏造しない。
        Err(SysError::MultiThreaded) => Err(LaunchPidfdUnavailable::Failed { errno: "other" }),
    }
}

impl ContainerChild {
    /// fork 直後の未回収の子のハンドルを作る（`exec` の rootless mapper の回収にも使う）。
    pub(super) fn new(pid: u32) -> Self {
        // 回収前（fork 直後）に開くので、以後 pid が再利用されても元のプロセスを指し続ける。
        // 未対応カーネル・seccomp 等で開けなければ `None`（`signal_child` が `kill(2)` へ退避）。
        // 縮退の理由は分類して保持するだけで、ここでは I/O をしない（stderr が満杯 pipe 等で停止していても
        // ハンドルの返却と子の回収を妨げない。REPAIR-5）。通知は `pidfd_unavailable()` を見た呼び出し側が行う。
        Self::from_pidfd_result(pid, sys::pidfd_open(pid))
    }

    /// fork 直後の親で子のハンドルを作り、`pidfd_open` の縮退理由があれば待たない経路で 1 行だけ出す
    /// （#1697・SUP-6・REPAIR-4・REPAIR-5）。本番の spawn 経路（`spawn_container_with_stages`・
    /// `spawn_exec_worker`・`spawn_exec_command`・rootless の id マップ mapper）はこちらを使う。
    ///
    /// 出力は `emit_diagnostic_line`（AF_UNIX の socket 以外へは書かず、満杯でも待たず、再試行しない）の 1 回だけで、
    /// stderr が停止していても返却を妨げない。出力の成否で起動の可否は変えない（最善努力）。`new` は I/O をしない
    /// 契約のまま残し、`spawn_container_probe`・内部の回収（結合試験と内部用）は
    /// `new` を使う（診断ログを出す対象にしない）。
    pub(super) fn spawned(pid: u32) -> Self {
        Self::from_pidfd_result_reported(pid, sys::pidfd_open(pid), std::io::stderr().as_fd()).0
    }

    /// [`ContainerChild::spawned`] の本体。`pidfd_open` の結果と出力先を注入して単体で照合する。
    /// ログを出す縮退（`Denied`・`Failed`）のときだけ出力結果を `Some` で返す（`Unsupported` と pidfd ありは `None`）。
    pub(super) fn from_pidfd_result_reported(
        pid: u32,
        result: Result<OwnedFd, SysError>,
        out: BorrowedFd<'_>,
    ) -> (Self, Option<super::DiagnosticDelivery>) {
        let child = Self::from_pidfd_result(pid, result);
        let delivery = child
            .pidfd_unavailable
            .and_then(LaunchPidfdUnavailable::log_line)
            .map(|line| super::emit_diagnostic_line_to(out, &line));
        (child, delivery)
    }

    /// `pidfd_open` の結果から組み立てる（`new` の本体。結果を注入できるようにして単体で照合する）。
    fn from_pidfd_result(pid: u32, result: Result<OwnedFd, SysError>) -> Self {
        let (pidfd, pidfd_unavailable) = match classify_pidfd_open(result) {
            Ok(fd) => (Some(fd), None),
            Err(reason) => (None, Some(reason)),
        };
        Self {
            pid,
            pidfd,
            pidfd_unavailable,
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

    /// fork 直後（回収前）に開いた pidfd の借用（なければ `None`）。
    ///
    /// 回収前に開いているため、以後 pid が再利用されても元のプロセスを指し続ける。supervisor が exec の
    /// 対象（pid1）をこの pidfd で固定するために使う（記録 pid からの `pidfd_open` や cgroup の所属に
    /// 同一性を依存させない。SUP-6・SEC-1・CORE-1・TASK-163 追補・#1461）。`None` は pidfd を開けなかった環境
    /// （Linux 5.3 未満・seccomp・fd 枯渇等。理由は [`ContainerChild::pidfd_unavailable`]）で、その場合に呼び出し側は
    /// fail-closed にすること。本番の exec の入口（`run_command_with_pidfd`）は pidfd を必須の引数にしており、
    /// `None` のハンドルからは exec できない（#1617）。
    pub fn pidfd(&self) -> Option<BorrowedFd<'_>> {
        self.pidfd.as_ref().map(|fd| fd.as_fd())
    }

    /// [`ContainerChild::pidfd`] が `None` の理由（pidfd を持つなら `None`。#1617・REPAIR-4）。
    pub fn pidfd_unavailable(&self) -> Option<LaunchPidfdUnavailable> {
        self.pidfd_unavailable
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

    /// 未回収の子へ `SIGKILL` を送るが、回収しない（ゾンビの間は pid 番号が解放されない。CORE-6・SEC-5・#2376）。
    ///
    /// rootless の範囲写像の失敗の後始末（`exec::isolate_rootless_subordinate_with`）が、mapper を止めてもその pid
    /// (= mapper のプロセスグループ ID)を保ったまま、グループ宛ての `SIGKILL` で helper を止めるために使う。
    /// [`Self::send_signal`] はゾンビをその場で回収してしまうため使わない。
    ///
    /// 戻り値は「送った（または既に送ってあり）、まだ未回収である」とき `true`。回収済み・契約外の回収者に
    /// 回収された（`Lost`）・送れなかった場合は `false` で、呼び出し側は pid が保たれている前提に立たないこと。
    pub(super) fn kill_keep_unreaped(&self) -> bool {
        if self.kill_if_unreaped().is_err() {
            return false;
        }
        matches!(self.lock().state, ReapState::Killed)
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

    /// SEC-1・CORE-5・#1714: 証跡が無い（ステージ列を通さない）入口は、継承された制限の有無にかかわらず
    /// exec を拒否する。段は `Exec` のまま終了コード 126 で、欠けた段が理由に載る。
    #[test]
    fn sec1_exec_is_denied_without_restriction_evidence() {
        let err =
            require_restriction_evidence(Err(LaunchNotReady::pipeline_not_run())).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.stage, IsolationStage::Exec);
        assert_eq!(exit_code_for(&err), EXIT_EXEC_NOT_EXECUTABLE);
        assert_eq!(
            err.message,
            "refusing to exec: no evidence that the isolation restrictions were applied; missing: rlimits,capability_drop,no_new_privs,landlock,seccomp"
        );
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

    /// CORE-1・SEC-1・CORE-5（TASK-27.4.2・#1714）: 組み込みでない段にダミーフックを全部登録し、Landlock に
    /// 独自フックを載せても、証跡はそろわず exec の拒否は解除されない（欠けるのは `landlock` だけ）。
    #[test]
    fn core1_stage_report_is_not_restriction_evidence() {
        use crate::exec::StageKind;
        let mut p = StagePipeline::new();
        for kind in StageKind::ORDER.iter().copied().filter(|k| !k.is_builtin()) {
            p = p.with_hook(kind, || Ok(())).unwrap();
        }
        let err = p
            .run_then(|_report, _caps, ev| require_restriction_evidence(ev))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.stage, IsolationStage::Exec);
        assert!(
            err.message.ends_with("missing: landlock"),
            "{}",
            err.message
        );
    }

    /// SEC-1・CORE-5・#1714: `with_landlock` を載せた全段の成功で、exec の前段（証跡の検査）を通る。
    /// 単体テストで確かめられるのは証跡の検査までで、`exec_entrypoint_verified` は pivot 直後のマウント ID と
    /// 実際の `/` を要するため呼ばない（dry-run の既存テストが別に担う）。
    #[test]
    fn sec1_core5_full_pipeline_permits_exec_prestage() {
        use crate::landlock::{AccessFs, LandlockRuleset, PathRule, RuleOrigin, RulePath};
        let ruleset = LandlockRuleset::for_observation(
            6,
            vec![PathRule {
                path: RulePath::Root,
                allowed: AccessFs::READ,
                origin: RuleOrigin::Root,
            }],
        );
        let result = StagePipeline::new()
            .with_landlock(ruleset)
            .unwrap()
            .run_then(|_report, _caps, ev| require_restriction_evidence(ev));
        assert!(matches!(result, Ok(())));
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
    /// 標準 fd を閉じられないため結合試験の範囲（`tests/exec_child_setup.rs` の `exec_fd_moves_above_closed_stdio`、
    /// #1299）。
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
        // 存在するのにディレクトリでない `/dev` は差し替えで、違反として記録する（SEC-4）。
        let violation = |err: &ExecError, reason: ViolationReason| {
            assert_eq!(
                (err.code, err.stage),
                (ErrorCode::FailedPrecondition, IsolationStage::Exec)
            );
            let v = err.violation.as_ref().expect("violation record");
            assert_eq!((v.reason, v.behavior_id), (reason, "SEC-1"));
        };
        violation(&err, ViolationReason::ExecDevNotDirectory);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason.as_str()),
            Some("exec_dev_not_directory")
        );
        std::fs::remove_file(dir.0.join("dev")).unwrap();
        // `/dev` が通常ファイル。
        std::fs::write(dir.0.join("dev"), b"").unwrap();
        let err = open_verified_null(dir_fd(&dir.0).as_fd(), real_procfs().as_fd()).unwrap_err();
        violation(&err, ViolationReason::ExecDevNotDirectory);
        std::fs::remove_file(dir.0.join("dev")).unwrap();
        // `/dev/null` が不在。
        std::fs::create_dir(dir.0.join("dev")).unwrap();
        let err = open_verified_null(dir_fd(&dir.0).as_fd(), real_procfs().as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(err.message.starts_with("cannot find /dev/null"));
        assert_eq!(take_calls(), Vec::<String>::new());

        // `/proc` が無い rootfs は前提の不足（違反ではない）。
        let err = open_root_procfs(dir_fd(&dir.0).as_fd()).unwrap_err();
        assert_eq!(
            (err.code, err.stage),
            (ErrorCode::FailedPrecondition, IsolationStage::Exec)
        );
        assert_eq!(err.violation, None);
        assert!(err.message.starts_with("cannot open /proc in the new root"));
        // procfs でない（通常のディレクトリ）・symlink（本物の `/proc` を指していても辿らない）・通常ファイルは
        // 差し替えで、違反 `exec_proc_not_procfs` として記録する（SEC-4）。
        let proc = dir.0.join("proc");
        std::fs::create_dir(&proc).unwrap();
        let err = open_root_procfs(dir_fd(&dir.0).as_fd()).unwrap_err();
        violation(&err, ViolationReason::ExecProcNotProcfs);
        assert_eq!(
            err.message,
            "/proc in the new root is not procfs; cannot reopen a verified file"
        );
        std::fs::remove_dir(&proc).unwrap();
        std::os::unix::fs::symlink("/proc", &proc).unwrap();
        let err = open_root_procfs(dir_fd(&dir.0).as_fd()).unwrap_err();
        violation(&err, ViolationReason::ExecProcNotProcfs);
        std::fs::remove_file(&proc).unwrap();
        std::fs::write(&proc, b"").unwrap();
        let err = open_root_procfs(dir_fd(&dir.0).as_fd()).unwrap_err();
        violation(&err, ViolationReason::ExecProcNotProcfs);
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
        verify_script_fd_path(Path::new("/proc/self/fd"), &file, &meta, entry.path()).unwrap();

        // /dev/fd の無い rootfs（空ディレクトリ）は拒否する。
        let empty = dir.0.join("empty");
        std::fs::create_dir(&empty).unwrap();
        let err = verify_script_fd_path(&empty, &file, &meta, entry.path()).unwrap_err();
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
        let err = verify_script_fd_path(&other, &file, &meta, entry.path()).unwrap_err();
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
                "reopen(entrypoint)".to_string(),
                "close_range(3)".to_string(),
                "signal(SIGPIPE,SIG_DFL)".to_string(),
                "stdio->/dev/null".to_string(),
                format!("execve({})", bin.display()),
                "argv=probe -x".to_string(),
                "env=K=V".to_string(),
            ]
        );
    }

    /// SUP-7・SUP-1（TASK-164 追補・#1471）: stdout / stderr をパイプへ付け替えた場合、exec 直前の置換は fd 0 だけで、
    /// 付け替え済みの 1・2 は `/dev/null` で上書きしない。置換の位置は `execve` の直前のまま変わらない。
    #[test]
    fn sup7_1471_piped_stdout_stderr_are_not_nulled() {
        let dir = TempDir::create("exec-piped");
        let bin = dir.0.join("probe");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&bin)
            .unwrap();
        let entry = Entrypoint::new(&bin, ["probe"], [] as [&str; 0]).unwrap();
        let _ = take_calls();
        let nulling = StdioNulling {
            stdout: false,
            stderr: false,
        };
        let err =
            exec_entrypoint_verified_with(current_root_mnt_id(), &entry, nulling).unwrap_err();
        let calls = take_calls();
        drop(dir);
        assert_eq!(err.stage, IsolationStage::Exec);
        assert_eq!(
            calls,
            vec![
                "close_range(3,close)".to_string(),
                "setsid".to_string(),
                "reopen(entrypoint)".to_string(),
                "close_range(3)".to_string(),
                "signal(SIGPIPE,SIG_IGN)".to_string(),
                "stdio[0]->/dev/null".to_string(),
                format!("execve({})", bin.display()),
                "argv=probe".to_string(),
                "env=".to_string(),
            ]
        );
    }

    /// SUP-7（#1471）: 置換する fd 番号は、パイプ指定なしなら 0・1・2、片方だけなら指定のない側と 0。
    #[test]
    fn sup7_1471_stdio_nulling_targets() {
        assert_eq!(StdioNulling::ALL.targets(), vec![0, 1, 2]);
        let only_err_piped = StdioNulling {
            stdout: true,
            stderr: false,
        };
        assert_eq!(only_err_piped.targets(), vec![0, 1]);
        let only_out_piped = StdioNulling {
            stdout: false,
            stderr: true,
        };
        assert_eq!(only_out_piped.targets(), vec![0, 2]);
    }

    /// SUP-7・SUP-1（#1471）: 親が書き込み側（`ChildStdio`）を閉じると、読み取り側は EOF になる
    /// （`drain` が終わるための条件。閉じ忘れると読み取りが終わらない）。
    #[test]
    fn sup7_1471_reader_reaches_eof_after_child_stdio_dropped() {
        use std::io::Read as _;
        let (stdio, mut out, mut err) = ChildStdio::pipes().unwrap();
        drop(stdio);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        assert_eq!(out.read_to_end(&mut a).unwrap(), 0);
        assert_eq!(err.read_to_end(&mut b).unwrap(), 0);
    }

    /// 付け替えの子役が使う環境変数。
    const STDIO_INSTALL_CHILD_ENV: &str = "FANDHE_TEST_1471_STDIO_INSTALL_CHILD";

    /// 付け替えの子役。`ChildStdio::install` 後に fd 1・2 へ書いた行が、それぞれ別のパイプの読み取り側に届き、
    /// 戻り値の `StdioNulling` が両方「置換しない」であることを確かめる。結果は終了コード（0 = 成功）で返す。
    fn stdio_install_child_main() -> ! {
        use std::io::Read as _;
        let (stdio, mut out, mut err) = ChildStdio::pipes().unwrap();
        let code = match stdio.install() {
            Ok(n) if n.targets() == vec![0] => {
                let _ = std::io::stdout().write_all(b"OUT-LINE\n");
                let _ = std::io::stdout().flush();
                let _ = std::io::stderr().write_all(b"ERR-LINE\n");
                let (mut a, mut b) = ([0u8; 9], [0u8; 9]);
                match (out.read_exact(&mut a), err.read_exact(&mut b)) {
                    (Ok(()), Ok(())) if &a == b"OUT-LINE\n" && &b == b"ERR-LINE\n" => 0,
                    _ => 2,
                }
            }
            _ => 1,
        };
        std::process::exit(code);
    }

    /// SUP-7・SUP-1（#1471）: `install` は stdout を 1 番、stderr を 2 番へ別々に付け替える。テストバイナリ自身を
    /// 再実行した子役で確かめる（自プロセスの fd 1・2 を差し替えない）。
    #[test]
    fn sup7_1471_install_routes_fd1_and_fd2_to_separate_pipes() {
        if std::env::var_os(STDIO_INSTALL_CHILD_ENV).is_some() {
            stdio_install_child_main();
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "exec::process::tests::sup7_1471_install_routes_fd1_and_fd2_to_separate_pipes",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(STDIO_INSTALL_CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // 子役が read_exact で戻らない場合に備え、期限（REPAIR-5）を超えたら kill して回収し失敗させる。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("install child did not finish within 30s");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(0));
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
                vec![
                    "close_range(3,close)".to_string(),
                    "setsid".to_string(),
                    "reopen(entrypoint)".to_string()
                ],
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
            vec![
                "close_range(3,close)".to_string(),
                "setsid".to_string(),
                "reopen(entrypoint)".to_string()
            ]
        );
    }

    /// SUP-6・REPAIR-3・TASK-163 追補（#1460）: 子が pipe へ残した内容からの判定の具体値。`R` の 1 行だけなら
    /// コマンドは起動した（終了コードが 125〜127 でも「コマンド自身の終了コード」）。失敗の行があるか、何も
    /// 無ければ起動していない。違反の理由コードは `execveat` 前の手順が返すものだけを引き直す。
    #[test]
    fn sup6_task163_classify_exec_status_is_exact() {
        let failed = |exit, violation| ExecExit::SetupFailed {
            exit,
            violation,
            code: ErrorCode::Internal,
        };
        let failed_with = |exit, violation, code| ExecExit::SetupFailed {
            exit,
            violation,
            code,
        };
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
        assert_eq!(
            classify_exec_status(b"126 INTERNAL -\n", exit),
            failed(exit, None)
        );
        // `execveat` 自体の失敗（`R` の後に失敗の行）。ERR-1 コードが運ばれる（#2763）。
        for (line, code) in [
            (&b"R\n127 NOT_FOUND -\n"[..], ErrorCode::NotFound),
            (
                &b"R\n126 PERMISSION_DENIED -\n"[..],
                ErrorCode::PermissionDenied,
            ),
            (
                &b"R\n126 INVALID_ARGUMENT -\n"[..],
                ErrorCode::InvalidArgument,
            ),
            (&b"R\n126 INTERNAL -\n"[..], ErrorCode::Internal),
        ] {
            assert_eq!(
                classify_exec_status(line, exit),
                failed_with(exit, None, code),
                "{line:?}"
            );
        }
        for reason in EXEC_CHILD_VIOLATIONS {
            let line = format!("126 PERMISSION_DENIED {}\n", reason.as_str());
            assert_eq!(
                classify_exec_status(line.as_bytes(), exit),
                failed_with(exit, Some(reason), ErrorCode::PermissionDenied)
            );
            assert_eq!(reason.kind().as_str(), "entrypoint");
        }
        assert_eq!(
            classify_exec_status(
                b"126 PERMISSION_DENIED entrypoint_interpreter_is_runtime_binary\n",
                exit
            ),
            failed_with(
                exit,
                Some(ViolationReason::EntrypointInterpreterIsRuntimeBinary),
                ErrorCode::PermissionDenied
            )
        );
        // 封印した複製の拒否（#1531）の理由コードは、子から親へ違反として運ばれる。
        for (line, reason) in [
            (
                &b"126 PERMISSION_DENIED entrypoint_copy_too_large\n"[..],
                ViolationReason::EntrypointCopyTooLarge,
            ),
            (
                &b"126 PERMISSION_DENIED entrypoint_copy_seal_unverified\n"[..],
                ViolationReason::EntrypointCopySealUnverified,
            ),
            (
                &b"126 PERMISSION_DENIED entrypoint_on_noexec_mount\n"[..],
                ViolationReason::EntrypointOnNoexecMount,
            ),
        ] {
            assert_eq!(
                classify_exec_status(line, exit),
                failed_with(exit, Some(reason), ErrorCode::PermissionDenied)
            );
        }
        // 解釈できない内容・子が返さないはずの理由コード・切れた行は、起動していない扱い（理由なし）。
        for garbage in [
            &b"R"[..],
            b"RR\n",
            b"\n",
            b"garbage",
            b"126 rootfs_is_host_root\n",
            b"126",
            b"R\nR\n",
            // 旧形式（2 語）・未知の ERR-1 コード・未知の理由・語数の過不足・改行なし・余分な行。
            b"R\n126 -\n",
            b"126 entrypoint_is_runtime_binary\n",
            b"126 BOGUS -\n",
            b"126 not_found -\n",
            b"126 NOT_FOUND bogus_reason\n",
            b"126 NOT_FOUND - extra\n",
            b"126 NOT_FOUND\n",
            b"126 NOT_FOUND -",
            b"126 NOT_FOUND -\nx",
            b"R\n126 NOT_FOUND -\n126 NOT_FOUND -\n",
            b"126  NOT_FOUND -\n",
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

    /// SEC-4・CORE-5・SUP-6・REPAIR-12（#2763）: `R` の後の `execveat` の errno は、launch と同じ写像で
    /// ERR-1 コードの失敗行になり（`NOT_FOUND` は 127、他は 126）、親の復号が同じ値に戻す。errno の生値・
    /// 文字列・パスは行に載らない。
    #[test]
    fn sec4_2763_execveat_errno_roundtrips_as_code_line() {
        let path = Path::new("/secret/dir/app");
        let exit_of = |n| ChildExit::Exited(n);
        for (errno, line, code, exit) in [
            (sys::ENOENT, "127 NOT_FOUND -\n", ErrorCode::NotFound, 127),
            (
                sys::EACCES,
                "126 PERMISSION_DENIED -\n",
                ErrorCode::PermissionDenied,
                126,
            ),
            (
                sys::ENOEXEC,
                "126 INVALID_ARGUMENT -\n",
                ErrorCode::InvalidArgument,
                126,
            ),
            (sys::EINTR, "126 INTERNAL -\n", ErrorCode::Internal, 126),
        ] {
            let err = execve_error(path, SysError::Os(errno));
            assert_eq!((err.code, err.stage), (code, IsolationStage::Exec));
            let written = exec_failure_line(&err);
            assert_eq!(written, line, "errno {errno}");
            assert!(!written.contains("secret"), "{written}");
            let status = format!("R\n{written}");
            assert_eq!(
                classify_exec_status(status.as_bytes(), exit_of(exit)),
                ExecExit::SetupFailed {
                    exit: exit_of(exit),
                    violation: None,
                    code
                }
            );
        }
        // 違反を伴う失敗は理由コードも載る。
        let violation = ExecError::from_violation(ViolationReason::EntrypointIsRuntimeBinary, None);
        assert_eq!(
            exec_failure_line(&violation),
            format!(
                "126 {} entrypoint_is_runtime_binary\n",
                violation.code.as_str()
            )
        );
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
                violation: None,
                code: ErrorCode::Internal
            }
        );
        assert_eq!(
            read(b"127 PERMISSION_DENIED stdio_null_not_null_device\n"),
            ExecExit::SetupFailed {
                exit,
                violation: Some(ViolationReason::StdioNullNotNullDevice),
                code: ErrorCode::PermissionDenied
            }
        );
        // `R` の後の `execveat` の失敗（#2763）。
        assert_eq!(
            read(b"R\n127 NOT_FOUND -\n"),
            ExecExit::SetupFailed {
                exit,
                violation: None,
                code: ErrorCode::NotFound
            }
        );
        assert_eq!(
            read(&[b'R'; 4096]),
            ExecExit::SetupFailed {
                exit,
                violation: None,
                code: ErrorCode::Internal
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

    /// SUP-6・SEC-1・TASK-163 追補（#1456）: `setsid` の後は、端末を `O_NOCTTY` なしで開くと制御端末として取得して
    /// しまう。エントリポイントが端末・デバイス・ディレクトリ・それらを指す symlink のときは、開き直しに進まずに
    /// （対象を開かずに）拒否する。通常ファイルを指す symlink は従来どおり辿って開く。
    #[test]
    fn sup6_sec1_task163_non_regular_entrypoint_is_rejected_without_opening_it() {
        let dir = TempDir::create("entry-kind");
        for (i, target) in ["/dev/tty", "/dev/ptmx", "/dev/null", "/proc"]
            .iter()
            .enumerate()
        {
            let link = dir.0.join(format!("link{i}"));
            std::os::unix::fs::symlink(target, &link).unwrap();
            for path in [Path::new(target), link.as_path()] {
                let entry = Entrypoint::new(path, ["x"], [] as [&str; 0]).unwrap();
                let _ = take_calls();
                let err = exec_entrypoint_verified(current_root_mnt_id(), &entry).unwrap_err();
                assert_eq!(
                    (err.code, err.stage),
                    (ErrorCode::PermissionDenied, IsolationStage::Exec),
                    "{path:?}"
                );
                assert!(
                    err.message.ends_with("is not a regular file")
                        || err
                            .message
                            .ends_with("resolves to an inherited standard stream"),
                    "{path:?}: {}",
                    err.message
                );
                assert_eq!(exit_code_for(&err), EXIT_EXEC_NOT_EXECUTABLE);
                // 開き直し（= 実際の open）には進んでいない。
                assert_eq!(
                    take_calls(),
                    vec!["close_range(3,close)".to_string(), "setsid".to_string()],
                    "{path:?}"
                );
            }
        }
        // 対照: 通常ファイルを指す symlink は辿って開く（`/bin/sh` 等の symlink を拒否しない）。
        let file = dir.0.join("regular");
        std::fs::write(&file, b"data").unwrap();
        let link = dir.0.join("link-regular");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let root = dir_fd(Path::new("/"));
        let _ = take_calls();
        let (opened, meta, _) = open_entrypoint(
            &Entrypoint::new(&link, ["x"], [] as [&str; 0]).unwrap(),
            root.as_fd(),
            real_procfs().as_fd(),
        )
        .unwrap();
        assert_eq!(take_calls(), vec!["reopen(entrypoint)".to_string()]);
        let want = std::fs::metadata(&file).unwrap();
        assert_eq!((meta.dev(), meta.ino()), (want.dev(), want.ino()));
        let mut head = [0u8; 4];
        assert_eq!(opened.read_at(&mut head, 0).unwrap(), 4);
        assert_eq!(&head, b"data");
        use std::os::fd::AsRawFd as _;
        assert!(opened.as_raw_fd() > 2);
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

    /// OCI-1（#2314）: 名前だけの `args[0]`（redis:alpine の `docker-entrypoint.sh`）を `PATH` で解決する。
    /// 実行ビットの無い前方の候補は飛ばし、2 件目を採る。argv[0] は名前のまま。
    #[test]
    fn oci1_exec_resolves_bare_name_via_path() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::create("oci1-path");
        let sbin = dir.0.join("usr/local/sbin");
        let bin = dir.0.join("usr/local/bin");
        std::fs::create_dir_all(&sbin).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        let skipped = sbin.join("docker-entrypoint.sh");
        let target = bin.join("docker-entrypoint.sh");
        std::fs::write(&skipped, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&skipped, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&target, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path_env = format!("PATH={}:{}:/nonexistent", sbin.display(), bin.display());
        let entry = Entrypoint::search_path(
            "docker-entrypoint.sh",
            ["docker-entrypoint.sh", "redis-server"],
            [path_env.as_str()],
        )
        .unwrap();
        let _ = take_calls();
        // dry-run の execve は EINTR を返すので Err になる。記録で解決結果を照合する。
        let _ = exec_entrypoint_verified(current_root_mnt_id(), &entry);
        assert_eq!(
            take_calls(),
            vec![
                "close_range(3,close)".to_string(),
                "setsid".to_string(),
                format!("lookup(entrypoint)={}", target.display()),
                "reopen(entrypoint)".to_string(),
                "close_range(3)".to_string(),
                "signal(SIGPIPE,SIG_DFL)".to_string(),
                "stdio->/dev/null".to_string(),
                // 実行は固定した fd で行う。記録の名前は `Entrypoint::path()`（探索した名前）。
                "execve(docker-entrypoint.sh)".to_string(),
                "argv=docker-entrypoint.sh redis-server".to_string(),
                format!("env={path_env}"),
            ]
        );
    }

    /// OCI-1（#2314）: 重複 KEY は後勝ちの 1 件に正規化され、探索と子へ渡す環境が同じ `PATH` を指す。
    #[test]
    fn oci1_duplicate_env_keys_are_last_wins() {
        let entry = Entrypoint::new(
            "/bin/app",
            ["app"],
            ["PATH=/old", "A=1", "PATH=/new", "B=2", "A=3"],
        )
        .unwrap();
        let got: Vec<String> = entry
            .env
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();
        assert_eq!(got, vec!["PATH=/new", "B=2", "A=3"]);
        let dir = TempDir::create("oci1-dup");
        let old = format!("PATH={}/old", dir.0.display());
        let new = format!("PATH={}/new", dir.0.display());
        let entry =
            Entrypoint::search_path("x", ["x"], [old.as_str(), "K=v", new.as_str()]).unwrap();
        let got: Vec<String> = entry
            .env
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();
        assert_eq!(got, vec!["K=v".to_string(), new.clone()]);
        assert_eq!(
            match &entry.resolution {
                Resolution::SearchPath(c) => c[0].to_string_lossy(),
                _ => panic!("expected SearchPath"),
            },
            format!("{}/new/x", dir.0.display())
        );
    }

    /// OCI-1（#2314）: `PATH` のどこにも無い名前は `NotFound`（終了コード 127）で、`execve` しない。
    #[test]
    fn oci1_exec_bare_name_not_found_in_path() {
        let dir = TempDir::create("oci1-nf");
        let path_env = format!("PATH={}", dir.0.display());
        let entry = Entrypoint::search_path("nope.sh", ["nope.sh"], [path_env.as_str()]).unwrap();
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

    /// OCI-1・CORE-1（#2314）: 名前の探索で当たった候補が既存の検査を通る
    /// （`PATH=/proc/self` の `exe` はランタイム自身で、違反として拒否する）。
    #[test]
    fn oci1_core1_exec_bare_name_resolving_to_runtime_binary_is_rejected() {
        let entry = Entrypoint::search_path("exe", ["exe"], ["PATH=/proc/self"]).unwrap();
        let _ = take_calls();
        let err = exec_entrypoint_verified(current_root_mnt_id(), &entry).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        let v = err.violation.expect("violation record");
        assert_eq!(v.reason, ViolationReason::EntrypointIsRuntimeBinary);
    }

    /// OCI-1・OCI-4（#2432）: cwd の fd 起点で `bin/app`・`./x` を解決し、通常ファイルの inode に固定する。
    #[test]
    fn oci1_oci4_open_cwd_relative_resolves_from_cwd_fd() {
        let dir = TempDir::create("oci1-cwdrel");
        std::fs::create_dir_all(dir.0.join("bin")).unwrap();
        std::fs::write(dir.0.join("bin/app"), b"x").unwrap();
        std::fs::write(dir.0.join("x"), b"y").unwrap();
        let cwd = dir_fd(&dir.0);
        for (input, file) in [
            ("bin/app", "bin/app"),
            ("./x", "x"),
            ("./bin/./app", "bin/app"),
        ] {
            let entry = Entrypoint::cwd_relative(input, ["a"], [] as [&str; 0]).unwrap();
            let Resolution::CwdRelative(comps) = &entry.resolution else {
                panic!("expected CwdRelative");
            };
            let fd = open_cwd_relative(cwd.as_fd(), comps, entry.path()).unwrap();
            let got = std::fs::File::from(fd).metadata().unwrap();
            let want = std::fs::metadata(dir.0.join(file)).unwrap();
            assert_eq!((got.dev(), got.ino()), (want.dev(), want.ino()), "{input}");
        }
    }

    /// OCI-1・OCI-4（#2432）: 不在は `NotFound`（127）、中間要素の symlink・非ディレクトリは `InvalidArgument`。
    #[test]
    fn oci1_oci4_open_cwd_relative_failures() {
        let dir = TempDir::create("oci1-cwdrel-err");
        std::fs::create_dir_all(dir.0.join("real")).unwrap();
        std::fs::write(dir.0.join("real/app"), b"x").unwrap();
        std::os::unix::fs::symlink("real", dir.0.join("link")).unwrap();
        std::fs::write(dir.0.join("file"), b"x").unwrap();
        let cwd = dir_fd(&dir.0);
        let run = |input: &str| {
            let entry = Entrypoint::cwd_relative(input, ["a"], [] as [&str; 0]).unwrap();
            let Resolution::CwdRelative(comps) = &entry.resolution else {
                panic!("expected CwdRelative");
            };
            open_cwd_relative(cwd.as_fd(), comps, entry.path()).unwrap_err()
        };
        let err = run("./nope");
        assert_eq!(
            (err.code, err.stage),
            (ErrorCode::NotFound, IsolationStage::Exec)
        );
        assert_eq!(exit_code_for(&err), EXIT_EXEC_NOT_FOUND);
        assert_eq!(run("nodir/app").code, ErrorCode::NotFound);
        assert_eq!(run("link/app").code, ErrorCode::InvalidArgument);
        assert_eq!(run("file/app").code, ErrorCode::InvalidArgument);
    }

    /// OCI-1・OCI-4・SEC-1（#2432）: 最終要素の解決結果も既存の検査を通る（cwd を `/proc/self` にすると `./exe` は
    /// ランタイム自身で違反として拒否する）。`..` は `cwd_relative` が字句で拒否する。
    #[test]
    fn oci1_oci4_cwd_relative_runtime_binary_and_dotdot_rejected() {
        let cwd = dir_fd(Path::new("/proc/self"));
        let entry = Entrypoint::cwd_relative("./exe", ["exe"], [] as [&str; 0]).unwrap();
        let Resolution::CwdRelative(comps) = &entry.resolution else {
            panic!("expected CwdRelative");
        };
        let pinned = open_cwd_relative(cwd.as_fd(), comps, entry.path()).unwrap();
        let meta = std::fs::File::from(pinned).metadata().unwrap();
        assert_eq!(
            (meta.dev(), meta.ino()),
            runtime_identity(real_procfs().as_fd()).unwrap()
        );
        for bad in ["../x", "a/../x", "a/b/"] {
            let err = Entrypoint::cwd_relative(bad, ["x"], [] as [&str; 0]).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{bad}");
            assert_eq!(err.stage, IsolationStage::Validate, "{bad}");
        }
        // 名前だけ・絶対パスはこの経路の対象外。
        for bad in ["x", "/x"] {
            assert!(Entrypoint::cwd_relative(bad, ["x"], [] as [&str; 0]).is_err());
        }
    }

    /// OCI-1（#2314）: `new` と `search_path` は `/` を含む相対パスを従来どおり `InvalidArgument` で拒否する
    /// （相対パスは `cwd_relative` を使う。#2432）。
    #[test]
    fn oci1_entrypoint_relative_with_slash_still_rejected() {
        let err = Entrypoint::new("bin/app", ["x"], [] as [&str; 0]).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        for name in ["./x", "a/b", "bin/app"] {
            let err = Entrypoint::search_path(name, ["x"], ["PATH=/bin"]).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{name}");
            assert_eq!(err.stage, IsolationStage::Validate, "{name}");
        }
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

    /// SUP-6・REPAIR-4（#1617）: `pidfd_open` の失敗は理由ごとに分類される（具体値）。
    #[test]
    fn sup6_rep4_1617_classify_pidfd_open_errno() {
        let cls = |e: SysError| classify_pidfd_open(Err(e)).unwrap_err();
        assert_eq!(
            cls(SysError::Os(sys::EMFILE)),
            LaunchPidfdUnavailable::Failed { errno: "EMFILE" }
        );
        assert_eq!(
            cls(SysError::Os(sys::ENFILE)),
            LaunchPidfdUnavailable::Failed { errno: "ENFILE" }
        );
        assert_eq!(
            cls(SysError::Os(sys::ENOMEM)),
            LaunchPidfdUnavailable::Failed { errno: "ENOMEM" }
        );
        assert_eq!(
            cls(SysError::Os(sys::EPERM)),
            LaunchPidfdUnavailable::Denied
        );
        assert_eq!(
            cls(SysError::Os(sys::ENOSYS)),
            LaunchPidfdUnavailable::Unsupported
        );
        assert_eq!(
            cls(SysError::Unsupported),
            LaunchPidfdUnavailable::Unsupported
        );
        assert_eq!(
            cls(SysError::Os(sys::EBADF)),
            LaunchPidfdUnavailable::Failed { errno: "other" }
        );
    }

    /// SUP-6・REPAIR-4（#1617）: 縮退理由のログ行は固定語彙で、未対応では出さない（バイト一致）。
    #[test]
    fn sup6_rep4_1617_launch_pidfd_log_line_bytes() {
        assert_eq!(
            LaunchPidfdUnavailable::Failed { errno: "EMFILE" }
                .log_line()
                .as_deref(),
            Some(
                "{\"component\":\"core.exec\",\"operation\":\"launch_pidfd\",\"outcome\":\"unavailable\",\"reason\":\"failed\",\"errno\":\"EMFILE\"}"
            )
        );
        assert_eq!(
            LaunchPidfdUnavailable::Denied.log_line().as_deref(),
            Some(
                "{\"component\":\"core.exec\",\"operation\":\"launch_pidfd\",\"outcome\":\"unavailable\",\"reason\":\"denied\",\"errno\":\"EPERM\"}"
            )
        );
        assert_eq!(LaunchPidfdUnavailable::Unsupported.log_line(), None);
    }

    /// SUP-6・REPAIR-4・REPAIR-5（#1617）: `EMFILE` を注入すると pidfd は `None` のまま理由が保持される。
    /// 組み立ては出力先を取らず I/O をしない（停止した stderr でハンドル返却が止まらない。通知は呼び出し側）。
    #[test]
    fn sup6_rep4_1617_pidfd_open_failure_keeps_none_without_io() {
        let child = ContainerChild::from_pidfd_result(1, Err(SysError::Os(sys::EMFILE)));
        assert!(child.pidfd().is_none());
        assert_eq!(
            child.pidfd_unavailable(),
            Some(LaunchPidfdUnavailable::Failed { errno: "EMFILE" })
        );

        let child = ContainerChild::from_pidfd_result(1, Err(SysError::Os(sys::ENOSYS)));
        assert!(child.pidfd().is_none());
        assert_eq!(
            child.pidfd_unavailable(),
            Some(LaunchPidfdUnavailable::Unsupported)
        );

        // 自プロセスの pidfd が開けるカーネルでの成功経路（未対応カーネルでは検証対象外）。
        if let Ok(fd) = sys::pidfd_open(std::process::id()) {
            let child = ContainerChild::from_pidfd_result(1, Ok(fd));
            assert!(child.pidfd().is_some());
            assert_eq!(child.pidfd_unavailable(), None);
        }
    }

    /// 満杯 pipe 試験の子役を選ぶ環境変数（値は任意。親役が付けて自身のテストバイナリを再実行する）。
    const FULL_STDERR_CHILD_ENV: &str = "FANDHE_TEST_1617_FULL_STDERR_CHILD";

    /// 満杯 pipe 試験で `pidfd_open` を確実に失敗させる pid（`pid_max` の上限 4194304 を超え `ESRCH` になる）。
    const FULL_STDERR_MISSING_PID: u32 = 2_147_483_647;

    /// 満杯 pipe 試験の子役の前半: stderr を満杯にして停止させ、対照として旧来の `writeln!(stderr().lock(), ..)` が
    /// 300ms 以内に戻らないこと（stderr が実際に停止していること）を返す。前提が崩れたら終了コード 3・4 で終える。
    fn fill_stderr_until_blocked() -> bool {
        use std::io::Write as _;
        use std::sync::atomic::{AtomicU64, Ordering};

        static WRITTEN: AtomicU64 = AtomicU64::new(0);
        std::thread::spawn(|| {
            let chunk = [b'x'; 4096];
            loop {
                match std::io::stderr().write(&chunk) {
                    Ok(n) => {
                        WRITTEN.fetch_add(u64::try_from(n).unwrap_or(0), Ordering::SeqCst);
                    }
                    // 読み手が閉じた等で満杯にできない（試験の前提が崩れた）。
                    Err(_) => std::process::exit(3),
                }
            }
        });
        let fill_deadline = Instant::now() + Duration::from_secs(5);
        let mut last = WRITTEN.load(Ordering::SeqCst);
        let mut stable_since = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(20));
            let now = WRITTEN.load(Ordering::SeqCst);
            if now != last {
                last = now;
                stable_since = Instant::now();
            } else if now > 0 && stable_since.elapsed() >= Duration::from_millis(300) {
                break;
            }
            if Instant::now() >= fill_deadline {
                std::process::exit(4);
            }
        }

        let (tx, rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let _ = writeln!(std::io::stderr().lock(), "control line");
            let _ = tx.send(());
        });
        rx.recv_timeout(Duration::from_millis(300)).is_err()
    }

    /// 満杯 pipe 試験の子役（親が読まない pipe を stderr に繋いで起動される）。
    ///
    /// 1. 埋め込みスレッドが stderr へ 4096 バイトずつ書き、書けた量が 300ms 増えなくなる（pipe 満杯で
    ///    `write(2)` が止まる）まで待つ（上限 5 秒）。
    /// 2. 対照として、`1471036b` より前の `new` と同じ `writeln!(std::io::stderr().lock(), ..)` を別スレッドで呼び、
    ///    300ms 以内に戻らないこと（stderr が実際に停止していること）を確かめる。
    /// 3. `ContainerChild::new` を存在しない pid で呼び（`pidfd_open` が失敗する縮退経路）、所要時間を測る。
    ///
    /// 結果は stdout の `RESULT ...` 1 行で返し、`process::exit` で終える（止まったスレッドを待たない。
    /// stderr は止まっているので panic のメッセージも出せない。失敗は終了コードで返す）。
    fn full_stderr_child_main() -> ! {
        use std::io::Write as _;
        let control_blocked = fill_stderr_until_blocked();

        let start = Instant::now();
        let handle = ContainerChild::new(FULL_STDERR_MISSING_PID);
        let elapsed = start.elapsed();

        let reason = handle.pidfd_unavailable().map_or_else(
            || "none".to_owned(),
            |r| format!("{}:{}", r.as_str(), r.errno_name()),
        );
        let mut out = std::io::stdout().lock();
        let _ = writeln!(
            out,
            // libtest が改行なしで出す `test <名前> ... ` の後ろに続かないよう、先頭で改行する。
            "\nRESULT control_blocked={control_blocked} pidfd_none={} reason={reason} within_1s={}",
            handle.pidfd().is_none(),
            elapsed < Duration::from_secs(1)
        );
        let _ = out.flush();
        std::process::exit(0);
    }

    /// SUP-6・REPAIR-5・REPAIR-4（#1617・#1683 の Codex P0）: stderr が読み手の止まった満杯 pipe でも、
    /// `pidfd_open` が失敗する縮退経路の `ContainerChild::new` は 1 秒未満で子ハンドルを返す（stderr へ同期
    /// 書き込みせず、呼び出し側の `wait_timeout` による期限管理と回収へ到達できる）。
    ///
    /// テストバイナリ自身を `--exact` で再実行し、子役の stderr を親が読まない pipe にする（自プロセスの
    /// fd 2 を差し替えない）。子役は対照として修正前の書き込み方が実際に止まることも確かめる。親は子役の
    /// 終了を 10 秒の上限で待ち、超えたら kill して回収してから失敗させる（修正前の実装ではここで落ちる）。
    #[test]
    fn sup6_rep5_1617_container_child_new_returns_with_full_stderr_pipe() {
        use std::io::Read as _;

        if std::env::var_os(FULL_STDERR_CHILD_ENV).is_some() {
            full_stderr_child_main();
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "exec::process::tests::sup6_rep5_1617_container_child_new_returns_with_full_stderr_pipe",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(FULL_STDERR_CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            // 読まない（子役の stderr を満杯で止める）。`child` を drop するまで読み端を開いたまま保つ。
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child with a full stderr pipe did not finish within 10s (REPAIR-5)");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut stdout = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        assert_eq!(status.code(), Some(0), "child stdout: {stdout}");
        let result = stdout
            .lines()
            .find(|l| l.starts_with("RESULT "))
            .unwrap_or_else(|| panic!("no RESULT line in child stdout: {stdout}"));
        // `pidfd_open` が使える（自プロセスで開ける）カーネルでは、存在しない pid は `ESRCH` の失敗に分類される
        // （修正前はこの分類でログを stderr へ書いていた）。未対応・拒否される環境では理由の照合だけを外す。
        if sys::pidfd_open(std::process::id()).is_ok() {
            assert_eq!(
                result,
                "RESULT control_blocked=true pidfd_none=true reason=failed:ESRCH within_1s=true"
            );
        } else {
            assert!(
                result.starts_with("RESULT control_blocked=true pidfd_none=true reason="),
                "{result}"
            );
            assert!(result.ends_with(" within_1s=true"), "{result}");
        }
    }

    /// 診断出力の満杯 pipe 試験の子役を選ぶ環境変数（値は任意）。
    const FULL_STDERR_EMIT_CHILD_ENV: &str = "FANDHE_TEST_1697_FULL_STDERR_EMIT_CHILD";

    /// 診断出力の満杯 pipe 試験の子役。stderr を満杯にして停止させ（対照の旧来の書き方が戻らないことも確認）、
    /// 本物の `emit_diagnostic_line`（devpts の gid 省略ログ）と `from_pidfd_result_reported`（`EMFILE` の
    /// 縮退ログ）が 1 秒未満で `Dropped(NotUnixSocket)` を返すことを `RESULT ..` 行で返す。
    fn full_stderr_emit_child_main() -> ! {
        use super::super::{DiagnosticDelivery, DiagnosticDropReason, emit_diagnostic_line};
        use std::io::Write as _;

        let control_blocked = fill_stderr_until_blocked();
        let dropped = Some(DiagnosticDelivery::Dropped(
            DiagnosticDropReason::NotUnixSocket,
        ));

        let start = Instant::now();
        let devpts = emit_diagnostic_line(super::super::devices::devpts_gid_omitted_log_line());
        let devpts_ok = Some(devpts) == dropped && start.elapsed() < Duration::from_secs(1);

        let start = Instant::now();
        let (_child, pidfd) = ContainerChild::from_pidfd_result_reported(
            FULL_STDERR_MISSING_PID,
            Err(SysError::Os(sys::EMFILE)),
            std::io::stderr().as_fd(),
        );
        let pidfd_ok = pidfd == dropped && start.elapsed() < Duration::from_secs(1);

        let mut out = std::io::stdout().lock();
        let _ = writeln!(
            out,
            "\nRESULT control_blocked={control_blocked} devpts_within_1s_dropped={devpts_ok} pidfd_within_1s_dropped={pidfd_ok}"
        );
        let _ = out.flush();
        std::process::exit(0);
    }

    /// REPAIR-5・REPAIR-4・SUP-6（#1697）: stderr が読み手の止まった満杯 pipe でも、診断ログの 2 経路（devpts の
    /// gid 省略・launch pidfd の縮退）は 1 秒未満で戻る。対照として、旧来の `writeln!(stderr().lock(), ..)` は同じ条件で
    /// 戻らない（`control_blocked=true`）。テストバイナリ自身を `--exact` で再実行した子役で照合する。
    #[test]
    fn rep5_1697_diagnostic_emit_returns_with_full_stderr_pipe() {
        use std::io::Read as _;

        if std::env::var_os(FULL_STDERR_EMIT_CHILD_ENV).is_some() {
            full_stderr_emit_child_main();
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "exec::process::tests::rep5_1697_diagnostic_emit_returns_with_full_stderr_pipe",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(FULL_STDERR_EMIT_CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            // 読まない（子役の stderr を満杯で止める）。`child` を drop するまで読み端を開いたまま保つ。
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child with a full stderr pipe did not finish within 10s (REPAIR-5)");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut stdout = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        assert_eq!(status.code(), Some(0), "child stdout: {stdout}");
        let result = stdout
            .lines()
            .find(|l| l.starts_with("RESULT "))
            .unwrap_or_else(|| panic!("no RESULT line in child stdout: {stdout}"));
        assert_eq!(
            result,
            "RESULT control_blocked=true devpts_within_1s_dropped=true pidfd_within_1s_dropped=true"
        );
    }

    /// SUP-6・REPAIR-4（#1697）: `pidfd_open` の縮退ログは `Denied`（`EPERM`）と `Failed`（`EMFILE`）のときだけ
    /// 出力先へ 1 行届き、`Unsupported`（`ENOSYS`・未対応カーネル）と pidfd ありのときは何も出ない。
    #[test]
    fn sup6_rep4_1697_launch_pidfd_log_emitted_only_for_denied_and_failed() {
        use super::super::DiagnosticDelivery;
        use std::io::Read as _;
        use std::os::unix::net::UnixStream;

        fn run(result: Result<OwnedFd, SysError>) -> (Option<DiagnosticDelivery>, Vec<u8>) {
            let (tx, mut rx) = UnixStream::pair().unwrap();
            let (_child, delivery) =
                ContainerChild::from_pidfd_result_reported(1, result, tx.as_fd());
            rx.set_nonblocking(true).unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 1024];
            while let Ok(n @ 1..) = rx.read(&mut buf) {
                got.extend_from_slice(&buf[..n]);
            }
            (delivery, got)
        }

        let (d, got) = run(Err(SysError::Os(sys::EMFILE)));
        assert_eq!(d, Some(DiagnosticDelivery::Sent));
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "{\"component\":\"core.exec\",\"operation\":\"launch_pidfd\",\"outcome\":\"unavailable\",\"reason\":\"failed\",\"errno\":\"EMFILE\"}\n"
        );
        let (d, got) = run(Err(SysError::Os(sys::EPERM)));
        assert_eq!(d, Some(DiagnosticDelivery::Sent));
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "{\"component\":\"core.exec\",\"operation\":\"launch_pidfd\",\"outcome\":\"unavailable\",\"reason\":\"denied\",\"errno\":\"EPERM\"}\n"
        );
        for unsupported in [Err(SysError::Os(sys::ENOSYS)), Err(SysError::Unsupported)] {
            let (d, got) = run(unsupported);
            assert_eq!((d, got), (None, Vec::new()));
        }
        // 自プロセスの pidfd が開けるカーネルでは、pidfd ありの経路で何も出ない（開けない環境は上の
        // `Unsupported` 系と同じ扱いで、既存の `sup6_rep4_1617_*` と同じく照合対象から外れる）。
        if let Ok(own) = sys::pidfd_open(std::process::id()) {
            let (d, got) = run(Ok(own));
            assert_eq!((d, got), (None, Vec::new()));
        }
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
    use crate::exec::violation_scan::{
        violation_list_gaps, violation_names as child_path_violation_names,
    };

    /// 子が返し得る違反はすべて `Entrypoint` 監査イベントに写せる（足し忘れの検出。SEC-4・SUP-6・SEC-1・#1595）。
    #[test]
    fn sec4_sup6_task163_exec_child_violations_are_all_audited() {
        for r in EXEC_CHILD_VIOLATIONS {
            assert!(
                ViolationReason::ENTRYPOINT_REASONS.contains(&r),
                "{} is not in ENTRYPOINT_REASONS",
                r.as_str()
            );
            assert_eq!(
                r.entrypoint_audit_event(),
                Some(crate::audit_log::AuditEvent::Entrypoint {
                    reason: crate::audit_log::AuditReason::new(r.as_str())
                })
            );
            assert_eq!(ViolationReason::from_entrypoint_token(r.as_str()), Some(r));
        }
    }

    /// 子の経路（`process.rs`・`interpreter.rs`・`sealed_copy.rs`）が作る違反理由と `EXEC_CHILD_VIOLATIONS` が一致する
    /// （SEC-4・SUP-6・SEC-1・CORE-5。TASK-163 追補・#1533）。
    ///
    /// 照合対象は 3 ファイルだけ（別ファイルの違反生成ヘルパを子の経路から呼ぶ場合は加えること）。
    #[test]
    fn sec4_sup6_task163_exec_child_violations_match_child_path_sources() {
        let mut found = child_path_violation_names(include_str!("process.rs"));
        found.extend(child_path_violation_names(include_str!("interpreter.rs")));
        found.extend(child_path_violation_names(include_str!("sealed_copy.rs")));
        let (missing, stale) = violation_list_gaps(&found, &EXEC_CHILD_VIOLATIONS);
        assert!(
            missing.is_empty(),
            "child-path violations missing from EXEC_CHILD_VIOLATIONS: {missing:?}"
        );
        assert!(
            stale.is_empty(),
            "EXEC_CHILD_VIOLATIONS entries not produced by child-path sources: {stale:?}"
        );
        assert_eq!(found.len(), 8);
    }

    /// 足し忘れ・余剰・除外規則を合成入力で検出できる（上のテストが実際に失敗を報告する根拠。#1533）。
    #[test]
    fn sec4_sup6_task163_exec_child_violation_scan_detects_omission() {
        let src = "fn f() {\n    ExecError::from_violation_at(ViolationReason::RootfsIsHostRoot, None, S);\n    ExecError::from_violation_at(\n        ViolationReason::ExecProcNotProcfs,\n        None,\n        S,\n    );\n}\n";
        let found = child_path_violation_names(src);
        let names: Vec<&str> = found.iter().map(String::as_str).collect();
        assert_eq!(names, ["ExecProcNotProcfs", "RootfsIsHostRoot"]);

        // 足し忘れ: コードにあって一覧に無い。
        let (missing, stale) = violation_list_gaps(&found, &[ViolationReason::ExecProcNotProcfs]);
        assert_eq!(missing, ["RootfsIsHostRoot"]);
        assert!(stale.is_empty());

        // 余剰: 一覧にあってコードに無い。
        let (missing, stale) = violation_list_gaps(
            &found,
            &[
                ViolationReason::ExecProcNotProcfs,
                ViolationReason::RootfsIsHostRoot,
                ViolationReason::ExecDevNotDirectory,
            ],
        );
        assert!(missing.is_empty());
        assert_eq!(stale, ["ExecDevNotDirectory"]);

        // 除外規則: コメント行・一覧の定義・mod tests 以降は数えない。
        let excluded = "// ViolationReason::InCommentLine\n/// ViolationReason::InDocLine\npub(super) const EXEC_CHILD_VIOLATIONS: [ViolationReason; 1] = [\n    ViolationReason::InList,\n];\nfn g() { let _ = ViolationReason::Real; }\n\n#[cfg(test)]\nmod tests {\n    fn t() { let _ = ViolationReason::InTests; }\n}\n";
        let found = child_path_violation_names(excluded);
        let names: Vec<&str> = found.iter().map(String::as_str).collect();
        assert_eq!(names, ["Real"]);
    }

    /// 段の呼び出しを記録するだけの [`PrePivotOps`]（`fail_at` の段で失敗する）。
    struct RecordingOps {
        fail_at: Option<&'static str>,
    }

    /// 段ごとに異なる `ErrorCode`・違反理由を注入する（#1815。親での復元を具体値で照合するため）。
    fn injected_failure(name: &str) -> ExecError {
        let violation = |reason| ExecError::from_violation(reason, None);
        match name {
            "establish" => violation(ViolationReason::EstablishNotPid1),
            "prepare_rootfs" => violation(ViolationReason::PathMissing),
            "create_default_devices" => violation(ViolationReason::TargetOnSharedMount),
            "pivot_root" => violation(ViolationReason::RootfsIsHostRoot),
            "verify_pinned" => ExecError::new(
                ErrorCode::PermissionDenied,
                IsolationStage::PrepareRootfs,
                "injected failure",
            ),
            "mount_tmpfs" => ExecError::new(
                ErrorCode::NotFound,
                IsolationStage::MountTmpfs,
                "injected failure",
            ),
            "mount_sysfs" => ExecError::new(
                ErrorCode::FailedPrecondition,
                IsolationStage::MountSysfs,
                "injected failure",
            ),
            "mount_binds" => ExecError::from_violation_at(
                ViolationReason::BindSourceNotAccessible,
                None,
                IsolationStage::MountBinds,
            ),
            // 実機の適用失敗と同じ形（errno 由来の分類のまま、適用失敗の理由が付く。#2013）。
            "readonly_paths" => ExecError::new(
                ErrorCode::FailedPrecondition,
                IsolationStage::MountReadonlyPaths,
                "injected failure",
            )
            .or_violation(ViolationReason::ReadonlyPathApplyFailed, None),
            "masked_paths" => ExecError::new(
                ErrorCode::FailedPrecondition,
                IsolationStage::MountMaskedPaths,
                "injected failure",
            )
            .or_violation(ViolationReason::MaskedPathApplyFailed, None),
            "working_dir" => ExecError::new(
                ErrorCode::NotFound,
                IsolationStage::WorkingDir,
                "injected failure",
            ),
            "apply_sysctls" => ExecError::new(
                ErrorCode::InvalidArgument,
                IsolationStage::ApplySysctls,
                "injected failure",
            ),
            _ => ExecError::new(
                ErrorCode::InvalidArgument,
                IsolationStage::InjectFiles,
                "injected failure",
            ),
        }
    }

    thread_local! {
        /// `masked_paths` 段が受けた sysfs の証跡の有無（#2014。呼び出し順の記録とは別に持つ）。
        static SYSFS_PROOF_SEEN: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    }

    impl RecordingOps {
        fn step(&self, name: &'static str) -> Result<(), ExecError> {
            record(name.to_owned());
            if self.fail_at == Some(name) {
                return Err(injected_failure(name));
            }
            Ok(())
        }
    }

    impl PrePivotOps for RecordingOps {
        type Isolation = ();
        type Prepared = ();
        type Devices = ();
        type Pivoted = ();
        type Sysfs = ();
        fn establish(&self, _: Option<&BindMountSet>) -> Result<(), ExecError> {
            self.step("establish")
        }
        fn prepare_rootfs(&self, _: &(), _: &Path) -> Result<(), ExecError> {
            self.step("prepare_rootfs")
        }
        fn verify_pinned(&self, _: &(), _: BorrowedFd<'_>) -> Result<(), ExecError> {
            self.step("verify_pinned")
        }
        fn apply_sysctls(&self, _: &(), _: &(), _: &SysctlPlan<'_>) -> Result<(), ExecError> {
            self.step("apply_sysctls")
        }
        fn mount_sysfs(&self, _: &(), _: &(), _: &SysfsMountSpec) -> Result<(), ExecError> {
            self.step("mount_sysfs")
        }
        fn create_default_devices(
            &self,
            _: &(),
            _: &(),
            _: DevptsGidSource<'_>,
        ) -> Result<(), ExecError> {
            self.step("create_default_devices")
        }
        fn mount_tmpfs(&self, _: &(), _: &(), _: &(), _: &TmpfsMountSet) -> Result<(), ExecError> {
            self.step("mount_tmpfs")
        }
        fn inject_files(&self, _: &(), _: &(), _: &InjectedFileSet) -> Result<(), ExecError> {
            self.step("inject_files")
        }
        fn mount_binds(&self, _: &(), _: &(), _: &BindMountSet) -> Result<(), ExecError> {
            self.step("mount_binds")
        }
        fn apply_readonly_paths(
            &self,
            _: &(),
            _: &(),
            _: &[ProtectedPath],
        ) -> Result<(), ExecError> {
            self.step("readonly_paths")
        }
        fn apply_masked_paths(
            &self,
            _: &(),
            _: &(),
            _: &(),
            sysfs: Option<&()>,
            _: &[ProtectedPath],
        ) -> Result<(), ExecError> {
            SYSFS_PROOF_SEEN.with(|c| c.set(Some(sysfs.is_some())));
            self.step("masked_paths")
        }
        fn pivot_root(&self, _: &(), _: ()) -> Result<(), ExecError> {
            self.step("pivot_root")
        }
        fn enter_working_dir(&self, _: &(), _: &ContainerWorkingDir) -> Result<(), ExecError> {
            self.step("working_dir")
        }
    }

    /// 検証済みの sysfs の指定 1 件（実マウントはしない）。
    fn test_sysfs() -> SysfsMountSpec {
        use crate::oci_runtime::parse_config_bytes;
        let v = serde_json::json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "mounts": [{"destination": "/sys", "type": "sysfs", "options": ["ro"]}],
        });
        let cfg = parse_config_bytes(v.to_string().as_bytes()).expect("valid config");
        SysfsMountSpec::from_mounts(cfg.mounts())
            .expect("valid sysfs")
            .expect("present")
    }

    /// 重なり検査を通る bind 1 件の集合（宛先のみ意味を持つ。実マウントはしない）。
    fn test_binds(dest: &str) -> BindMountSet {
        use crate::oci_runtime::parse_config_bytes;
        let v = serde_json::json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "mounts": [{"destination": dest, "type": "bind", "source": "/data", "options": []}],
        });
        let cfg = parse_config_bytes(v.to_string().as_bytes()).expect("valid config");
        BindMountSet::from_mounts(cfg.mounts()).expect("bind set")
    }

    /// CORE-1・CORE-5（TASK-29 追補・#1715）: pivot 前の段は
    /// `establish` → `prepare_rootfs` → `verify_pinned` → `mount_sysfs` → `create_default_devices` → `mount_tmpfs` →
    /// `inject_files` → `mount_binds` → `readonly_paths` → `masked_paths` → `pivot_root` の固定順で呼ばれる（#1914）。
    /// procfs のマウント（`prepare_rootfs`）が保護の段より前であることの照合を兼ねる（#2005・SEC-2）。
    #[test]
    fn core1_run_pre_pivot_order_is_fixed() {
        let tmpfs = TmpfsMountSet::new();
        let inject = InjectedFileSet::new();
        let binds = test_binds("/mnt/data");
        let sysfs = test_sysfs();
        let sysctl_set = test_sysctl_set();
        let sysctl_plan = SysctlPlan::new(&sysctl_set, crate::exec::NamespaceSet::all())
            .unwrap()
            .unwrap();
        let pinned = std::fs::File::open("/").unwrap();
        let _ = take_calls();
        run_pre_pivot(
            &RecordingOps { fail_at: None },
            Path::new("/rootfs"),
            Some(PrePivotSetup {
                sysctls: Some(&sysctl_plan),
                devices: DevptsGidSource::Rootful,
                tmpfs: Some(&tmpfs),
                inject: Some(&inject),
                binds: Some(&binds),
                sysfs: Some(&sysfs),
                pinned_rootfs: Some(pinned.as_fd()),
                config_paths: ConfigPaths::NONE,
                status: None,
                working_dir: None,
            }),
        )
        .unwrap();
        assert_eq!(
            take_calls(),
            [
                "establish",
                "prepare_rootfs",
                "verify_pinned",
                "apply_sysctls",
                "mount_sysfs",
                "create_default_devices",
                "mount_tmpfs",
                "inject_files",
                "mount_binds",
                "readonly_paths",
                "masked_paths",
                "pivot_root",
            ]
        );
    }

    /// CRI-2・CORE-3（#2670）: sysctl の適用が失敗したら、`readonly_paths` 以降（特に `pivot_root`）へ進まない。
    /// 失敗の段は `ApplySysctls`、符号化した状態行は段名つきで往復する。
    #[test]
    fn cri2_run_pre_pivot_sysctl_failure_stops_before_later_steps() {
        let sysctl_set = test_sysctl_set();
        let plan = SysctlPlan::new(&sysctl_set, crate::exec::NamespaceSet::all())
            .unwrap()
            .unwrap();
        let pinned = std::fs::File::open("/").unwrap();
        let _ = take_calls();
        let err = run_pre_pivot(
            &RecordingOps {
                fail_at: Some("apply_sysctls"),
            },
            Path::new("/rootfs"),
            Some(PrePivotSetup {
                sysctls: Some(&plan),
                devices: DevptsGidSource::Rootful,
                tmpfs: None,
                inject: None,
                binds: None,
                sysfs: None,
                pinned_rootfs: Some(pinned.as_fd()),
                config_paths: ConfigPaths::NONE,
                status: None,
                working_dir: None,
            }),
        )
        .map(|_| ())
        .unwrap_err();
        assert_eq!(err.step, PrePivotStep::ApplySysctls);
        assert_eq!(err.error.stage, IsolationStage::ApplySysctls);
        assert_eq!(err.error.code, ErrorCode::InvalidArgument);
        assert_eq!(
            take_calls(),
            [
                "establish",
                "prepare_rootfs",
                "verify_pinned",
                "apply_sysctls"
            ]
        );
    }

    fn test_sysctl_set() -> crate::sysctl::SysctlSet {
        let mut set = crate::sysctl::SysctlSet::new();
        set.insert(
            crate::sysctl::SysctlKey::parse("kernel.shmmax").unwrap(),
            crate::sysctl::SysctlValue::parse("16384").unwrap(),
        )
        .unwrap();
        set
    }

    /// SEC-2（#2014）: `masked_paths` 段へは `mount_sysfs` の証跡が、sysfs の指定があるときだけ渡る。
    #[test]
    fn sec2_2014_run_pre_pivot_passes_sysfs_proof_only_when_mounted() {
        let sysfs = test_sysfs();
        for (spec, want) in [(Some(&sysfs), Some(true)), (None, Some(false))] {
            SYSFS_PROOF_SEEN.with(|c| c.set(None));
            run_pre_pivot(
                &RecordingOps { fail_at: None },
                Path::new("/rootfs"),
                Some(PrePivotSetup {
                    sysctls: None,
                    devices: DevptsGidSource::Rootful,
                    tmpfs: None,
                    inject: None,
                    binds: None,
                    sysfs: spec,
                    pinned_rootfs: None,
                    config_paths: ConfigPaths::NONE,
                    status: None,
                    working_dir: None,
                }),
            )
            .unwrap();
            assert_eq!(SYSFS_PROOF_SEEN.with(|c| c.get()), want);
        }
        let _ = take_calls();
    }

    /// 指定が無い段は呼ばれず、devices は常に pivot の前に作られる。`None` は最小構成。
    #[test]
    fn core1_run_pre_pivot_skips_unspecified_steps() {
        let _ = take_calls();
        run_pre_pivot(
            &RecordingOps { fail_at: None },
            Path::new("/rootfs"),
            Some(PrePivotSetup {
                sysctls: None,
                devices: DevptsGidSource::Rootful,
                tmpfs: None,
                inject: None,
                binds: None,
                sysfs: None,
                pinned_rootfs: None,
                config_paths: ConfigPaths::NONE,
                status: None,
                working_dir: None,
            }),
        )
        .unwrap();
        assert_eq!(
            take_calls(),
            [
                "establish",
                "prepare_rootfs",
                "create_default_devices",
                "readonly_paths",
                "masked_paths",
                "pivot_root"
            ]
        );
        run_pre_pivot(&RecordingOps { fail_at: None }, Path::new("/rootfs"), None).unwrap();
        assert_eq!(
            take_calls(),
            [
                "establish",
                "prepare_rootfs",
                "readonly_paths",
                "pivot_root"
            ]
        );
    }

    /// OCI-1・TASK-29: `process.cwd` の移動は `pivot_root` の直後に 1 回だけ呼ばれ、`None` と根（`/`）では呼ばれない。
    #[test]
    fn oci1_run_pre_pivot_enters_working_dir_after_pivot() {
        let setup = |wd: Option<&'static ContainerWorkingDir>| PrePivotSetup {
            sysctls: None,
            devices: DevptsGidSource::Rootful,
            tmpfs: None,
            inject: None,
            binds: None,
            sysfs: None,
            pinned_rootfs: None,
            config_paths: ConfigPaths::NONE,
            status: None,
            working_dir: wd,
        };
        let app: &'static ContainerWorkingDir = Box::leak(Box::new(
            ContainerWorkingDir::parse(Path::new("/app")).unwrap(),
        ));
        let root: &'static ContainerWorkingDir = Box::leak(Box::new(
            ContainerWorkingDir::parse(Path::new("/")).unwrap(),
        ));
        let _ = take_calls();
        run_pre_pivot(
            &RecordingOps { fail_at: None },
            Path::new("/rootfs"),
            Some(setup(Some(app))),
        )
        .unwrap();
        let calls = take_calls();
        assert_eq!(
            calls.iter().rev().take(2).cloned().collect::<Vec<_>>(),
            ["working_dir", "pivot_root"]
        );
        for wd in [None, Some(root)] {
            run_pre_pivot(
                &RecordingOps { fail_at: None },
                Path::new("/rootfs"),
                Some(setup(wd)),
            )
            .unwrap();
            assert_eq!(take_calls().last().map(String::as_str), Some("pivot_root"));
        }
        let err = run_pre_pivot(
            &RecordingOps {
                fail_at: Some("working_dir"),
            },
            Path::new("/rootfs"),
            Some(setup(Some(app))),
        )
        .err()
        .unwrap();
        assert_eq!(err.step, PrePivotStep::WorkingDir);
        assert_eq!(err.error.code, ErrorCode::NotFound);
    }

    /// SEC-2（#1850）: 読み取り専用パスの適用が失敗したら `pivot_root` へ進まない。`setup` が `None` の最小構成でも
    /// 適用され、失敗の段は `ReadonlyPaths`・段のエラーは `MountReadonlyPaths`。
    #[test]
    fn sec2_run_pre_pivot_readonly_paths_failure_stops_before_pivot() {
        let _ = take_calls();
        let err = run_pre_pivot(
            &RecordingOps {
                fail_at: Some("readonly_paths"),
            },
            Path::new("/rootfs"),
            None,
        )
        .err()
        .unwrap();
        assert_eq!(err.step, PrePivotStep::ReadonlyPaths);
        assert_eq!(err.error.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.error.stage, IsolationStage::MountReadonlyPaths);
        assert_eq!(
            take_calls(),
            ["establish", "prepare_rootfs", "readonly_paths"]
        );
    }

    /// SEC-2（#1851）: 覆うパスの適用が失敗したら `pivot_root` へ進まない。失敗の段は `MaskedPaths`・段のエラーは
    /// `MountMaskedPaths`。読み取り専用パスの失敗時は覆うパスへ進まない（順序の前提）。
    #[test]
    fn sec2_run_pre_pivot_masked_paths_failure_stops_before_pivot() {
        let setup = || PrePivotSetup {
            sysctls: None,
            devices: DevptsGidSource::Rootful,
            tmpfs: None,
            inject: None,
            binds: None,
            sysfs: None,
            pinned_rootfs: None,
            config_paths: ConfigPaths::NONE,
            status: None,
            working_dir: None,
        };
        let _ = take_calls();
        let err = run_pre_pivot(
            &RecordingOps {
                fail_at: Some("masked_paths"),
            },
            Path::new("/rootfs"),
            Some(setup()),
        )
        .err()
        .unwrap();
        assert_eq!(err.step, PrePivotStep::MaskedPaths);
        assert_eq!(err.error.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.error.stage, IsolationStage::MountMaskedPaths);
        assert_eq!(
            take_calls(),
            [
                "establish",
                "prepare_rootfs",
                "create_default_devices",
                "readonly_paths",
                "masked_paths"
            ]
        );
        let err = run_pre_pivot(
            &RecordingOps {
                fail_at: Some("readonly_paths"),
            },
            Path::new("/rootfs"),
            Some(setup()),
        )
        .err()
        .unwrap();
        assert_eq!(err.step, PrePivotStep::ReadonlyPaths);
        assert_eq!(
            take_calls(),
            [
                "establish",
                "prepare_rootfs",
                "create_default_devices",
                "readonly_paths"
            ]
        );
    }

    /// 途中の段が失敗したら後続の段（特に `pivot_root`）へ進まない（fail-closed）。
    #[test]
    fn core1_run_pre_pivot_stops_at_first_failure() {
        let tmpfs = TmpfsMountSet::new();
        let _ = take_calls();
        let err = run_pre_pivot(
            &RecordingOps {
                fail_at: Some("create_default_devices"),
            },
            Path::new("/rootfs"),
            Some(PrePivotSetup {
                sysctls: None,
                devices: DevptsGidSource::Rootful,
                tmpfs: Some(&tmpfs),
                inject: None,
                binds: None,
                sysfs: None,
                pinned_rootfs: None,
                config_paths: ConfigPaths::NONE,
                status: None,
                working_dir: None,
            }),
        )
        .err()
        .unwrap();
        assert_eq!(err.step, PrePivotStep::CreateDefaultDevices);
        assert_eq!(err.error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            take_calls(),
            ["establish", "prepare_rootfs", "create_default_devices"]
        );
    }

    /// SEC-1（#1914）: bind mount の段が失敗したら `readonly_paths` 以降（特に `pivot_root`）へ進まない。
    #[test]
    fn sec1_run_pre_pivot_mount_binds_failure_stops_before_pivot() {
        let binds = test_binds("/mnt/data");
        let _ = take_calls();
        let err = run_pre_pivot(
            &RecordingOps {
                fail_at: Some("mount_binds"),
            },
            Path::new("/rootfs"),
            Some(PrePivotSetup {
                sysctls: None,
                devices: DevptsGidSource::Rootful,
                tmpfs: None,
                inject: None,
                binds: Some(&binds),
                sysfs: None,
                pinned_rootfs: None,
                config_paths: ConfigPaths::NONE,
                status: None,
                working_dir: None,
            }),
        )
        .err()
        .unwrap();
        assert_eq!(err.step, PrePivotStep::MountBinds);
        assert_eq!(err.error.code, ErrorCode::PermissionDenied);
        assert_eq!(err.error.stage, IsolationStage::MountBinds);
        assert_eq!(
            take_calls(),
            [
                "establish",
                "prepare_rootfs",
                "create_default_devices",
                "mount_binds"
            ]
        );
    }

    /// `binds` が `None` なら段を呼ばない。`setup` が `None` の最小構成でも呼ばない（#1914）。
    #[test]
    fn core1_run_pre_pivot_binds_none_skips_mount_binds() {
        let _ = take_calls();
        run_pre_pivot(&RecordingOps { fail_at: None }, Path::new("/rootfs"), None).unwrap();
        assert!(!take_calls().contains(&"mount_binds".to_owned()));
    }

    /// SEC-1・SEC-2（#1914）: tmpfs・注入・config の保護パスと重なる bind は、副作用（`mount_binds`）の前に
    /// `InvalidArgument` で拒否し、`pivot_root` へ進まない。
    #[test]
    fn sec1_run_pre_pivot_bind_overlap_rejected_before_mount_binds() {
        use crate::injected_files::{InjectedContent, InjectedFileMode, InjectedFileSpec};
        use crate::oci_runtime::parse_config_bytes;
        use crate::tmpfs::TmpfsMountSpec;
        let mut tmpfs = TmpfsMountSet::new();
        tmpfs
            .push(TmpfsMountSpec::new("/scratch", None).unwrap())
            .unwrap();
        let mut inject = InjectedFileSet::new();
        inject
            .push(
                InjectedFileSpec::new(
                    "/run/secrets/a",
                    InjectedContent::from_bytes(b"x".to_vec()).unwrap(),
                    InjectedFileMode::DEFAULT,
                )
                .unwrap(),
            )
            .unwrap();
        let cfg = parse_config_bytes(
            serde_json::json!({
                "ociVersion": "1.2.0",
                "root": {"path": "rootfs"},
                "linux": {"readonlyPaths": ["/data/x"]},
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        for dest in ["/scratch/x", "/run/secrets", "/data"] {
            let binds = test_binds(dest);
            let _ = take_calls();
            let err = run_pre_pivot(
                &RecordingOps { fail_at: None },
                Path::new("/rootfs"),
                Some(PrePivotSetup {
                    sysctls: None,
                    devices: DevptsGidSource::Rootful,
                    tmpfs: Some(&tmpfs),
                    inject: Some(&inject),
                    binds: Some(&binds),
                    sysfs: None,
                    pinned_rootfs: None,
                    config_paths: ConfigPaths {
                        readonly: cfg.readonly_paths(),
                        masked: cfg.masked_paths(),
                    },
                    status: None,
                    working_dir: None,
                }),
            )
            .err()
            .unwrap();
            assert_eq!(err.step, PrePivotStep::MountBinds, "{dest}");
            assert_eq!(err.error.code, ErrorCode::InvalidArgument, "{dest}");
            assert_eq!(err.error.stage, IsolationStage::MountBinds, "{dest}");
            assert_eq!(
                take_calls(),
                [
                    "establish",
                    "prepare_rootfs",
                    "create_default_devices",
                    "mount_tmpfs",
                    "inject_files"
                ],
                "{dest}"
            );
        }
        // 重ならなければ検査は通る。
        let ok = test_binds("/mnt/data");
        assert!(check_bind_overlaps(&ok, Some(&tmpfs), Some(&inject), ConfigPaths::NONE).is_ok());
        assert!(check_bind_overlaps(&ok, None, None, ConfigPaths::NONE).is_ok());
    }

    /// SEC-4・CORE-2（#1815）: 10 個の段のそれぞれの失敗が、状態行の符号化・復号を経て親で段の名前と
    /// `ErrorCode`・違反理由の具体値として復元される。
    #[test]
    fn sec4_1815_every_step_failure_is_restored_by_the_parent() {
        use super::super::launch_status::PrePivotStatus;
        let tmpfs = TmpfsMountSet::new();
        let inject = InjectedFileSet::new();
        let binds = test_binds("/mnt/data");
        let pinned = std::fs::File::open("/").unwrap();
        let expected = [
            (
                "establish",
                ErrorCode::FailedPrecondition,
                Some("establish_not_pid1"),
            ),
            (
                "prepare_rootfs",
                ErrorCode::InvalidArgument,
                Some("path_missing"),
            ),
            ("verify_pinned", ErrorCode::PermissionDenied, None),
            (
                "create_default_devices",
                ErrorCode::FailedPrecondition,
                Some("target_on_shared_mount"),
            ),
            ("mount_tmpfs", ErrorCode::NotFound, None),
            ("inject_files", ErrorCode::InvalidArgument, None),
            (
                "mount_binds",
                ErrorCode::PermissionDenied,
                Some("bind_source_not_accessible"),
            ),
            (
                "readonly_paths",
                ErrorCode::FailedPrecondition,
                Some("readonly_path_apply_failed"),
            ),
            (
                "masked_paths",
                ErrorCode::FailedPrecondition,
                Some("masked_path_apply_failed"),
            ),
            (
                "pivot_root",
                ErrorCode::InvalidArgument,
                Some("rootfs_is_host_root"),
            ),
            ("working_dir", ErrorCode::NotFound, None),
        ];
        let wd = ContainerWorkingDir::parse(Path::new("/app")).unwrap();
        for (name, code, reason) in expected {
            let err = run_pre_pivot(
                &RecordingOps {
                    fail_at: Some(name),
                },
                Path::new("/rootfs"),
                Some(PrePivotSetup {
                    sysctls: None,
                    devices: DevptsGidSource::Rootful,
                    tmpfs: Some(&tmpfs),
                    inject: Some(&inject),
                    binds: Some(&binds),
                    sysfs: None,
                    pinned_rootfs: Some(pinned.as_fd()),
                    config_paths: ConfigPaths::NONE,
                    status: None,
                    working_dir: Some(&wd),
                }),
            )
            .err()
            .unwrap();
            assert_eq!(err.step.as_str(), name);
            let failure = PrePivotFailure::from_exec_error(err.step, &err.error);
            let line = PrePivotStatus::Failed(failure).encode();
            let decoded = PrePivotStatus::decode(line.as_bytes()).unwrap();
            let PrePivotStatus::Failed(f) = decoded else {
                panic!("expected a failure, got {decoded:?}");
            };
            assert_eq!(f.step.as_str(), name);
            assert_eq!(f.code, code);
            assert_eq!(f.violation.map(ViolationReason::as_str), reason);
        }
    }

    /// 固定した rootfs と実体が違えば `PermissionDenied`（固定文言）で拒否する。
    #[test]
    fn core1_check_rootfs_identity_is_exact() {
        assert!(check_rootfs_identity((7, 42), (7, 42)).is_ok());
        for other in [(7, 43), (8, 42)] {
            let err = check_rootfs_identity((7, 42), other).unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied);
            assert!(err.to_string().contains("rootfs changed after validation"));
        }
    }
}
