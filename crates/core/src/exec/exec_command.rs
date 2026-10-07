//! 稼働中コンテナへのコマンド実行の入口（fork → `close_range` → `execve`。SUP-6・TASK-163.4・#503・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! SUP-6 の exec は「pid1 の namespace へ `setns` → cgroup join → 制限の再適用 → コマンド実行」。本モジュールは
//! 最後の「コマンド実行」を担う。`fandhe-container-supervisor` の `exec::run_command` が、`reapply_restrictions`
//! の結果から作った [`ExecReady`] を渡して呼ぶ。
//!
//! ```text
//! reapply_restrictions(..) -> ExecRestrictionReport      // rlimit・capability・NO_NEW_PRIVS・Landlock・seccomp
//!   .into_complete()       -> ExecReady                  // 唯一の証跡（値で渡る）
//! spawn_exec_command(ready, &entry)                      // 親: cwd を照合済み root へ → fork して ContainerChild を返す
//!   子: close_range(3..) -> エントリポイントを fd で検査 -> 標準入出力を /dev/null へ -> execveat
//! 親: ContainerChild::wait_timeout(timeout)              // 期限超過は SIGKILL + 回収（REPAIR-5）
//! ```
//!
//! # 契約
//!
//! - **入口は [`ExecReady`] だけを値で受け取る**（SEC-1）。`ExecRestrictionReport`・真偽値を受け取る入口、
//!   `ExecReady` を作る別経路は無い。制限（`NO_NEW_PRIVS`・Landlock・seccomp・capability の bounding set・
//!   rlimit）は fork / execve を越えて継承されるため、「適用 → fork → execve」の順で子へ載る
//! - **fork の前に cwd を照合済みの root へ置く**: `setns(CLONE_NEWNS)` が付け替えた cwd は検証していないため、
//!   `ExecReady` が持つ照合済みの `/` の fd へ `fchdir` する。コマンドの cwd はコンテナの rootfs の根になる
//! - **fork の健全性**: 子を fork する直前に、`setns` 前に開いた status fd から `Threads: 1` を確認する
//!   （`setns` の後は自プロセスを `/proc/self` で解決できないため、`ProcSelf` は使えない）。満たさなければ
//!   fork せず `FailedPrecondition`。fork は `sys::fork_single_threaded_with` が強制する
//! - **別プロセスからは呼べない**: `ExecReady` を作ったプロセスと異なる pid からの呼び出しは何もせず拒否する
//!   （fork した子の pid は数値が衝突し得るため、best-effort の誤用検知）
//! - **子は launch 経路と同じ手順で exec する**: エントリポイントを開く前に fd 3 以上を `close_range` で閉じ
//!   （cgroup・状態・固定した rootfs・status の fd をコンテナへ渡さない。CVE-2024-21626 型の対策）、標準 fd と同一
//!   実体・ランタイム自身のバイナリを拒否し、シェバンを検証し、標準入出力を新 root の `/dev/null`（1:3 を検証）へ
//!   置換して `execveat` する（`process::exec_checked_entrypoint`）。エントリポイントは絶対パスのみで PATH
//!   探索はしない。子の失敗は stderr の英語 1 行と終了コード（125 / 126 / 127）で伝える
//! - **親の待ちには必ずタイムアウトを設ける**（REPAIR-5）: 戻り値の [`ContainerChild`] は
//!   `wait_timeout` のみを提供する。`Drop` では kill / wait しない
//!
//! # 未実装（REPAIR-3）
//!
//! - 標準入出力の受け渡し（CLI の exec・TASK-161 / SUP-4 の healthcheck の出力取得）。現状は launch と同じく
//!   `/dev/null` へ固定する（ホスト側の端末・ファイルをコンテナへ渡さない。fail-closed）
//! - 環境変数・作業ディレクトリ・ユーザーの指定（OCI `process` からの組み立て）。cwd は rootfs の根で固定
//! - 子の失敗を構造のまま親へ返す同期パイプ（現状は終了コードと stderr）

use std::os::fd::{AsFd as _, BorrowedFd};

use crate::sys;
use crate::traits::types::ErrorCode;

use super::process::{EXIT_SETUP_FAILED, exec_child_main};
use super::reapply::ExecReadyParts;
use super::{ContainerChild, Entrypoint, ExecError, ExecReady, IsolationStage};

/// 証跡 `ready` を消費し、`entry` を稼働中コンテナの namespace・cgroup・制限の下で実行する子を fork する。
///
/// 親（呼び出しプロセス）は子の pid を持つ [`ContainerChild`] を返すだけで、exec しない。単一スレッドの exec
/// 専用プロセスからのみ呼ぶ（契約はモジュール doc）。失敗しても状態は戻せないため、呼び出し側は続行せず終了する。
///
/// `ExecReady` を経由しない入口は無い（`ExecRestrictionReport` は渡せない）:
///
/// ```compile_fail,E0308
/// fn f(
///     report: fandhe_container_core::exec::ExecRestrictionReport,
///     entry: &fandhe_container_core::exec::Entrypoint,
/// ) {
///     let _ = fandhe_container_core::exec::spawn_exec_command(report, entry);
/// }
/// ```
pub fn spawn_exec_command(
    ready: ExecReady,
    entry: &Entrypoint,
) -> Result<ContainerChild, ExecError> {
    let ExecReadyParts {
        root,
        mut threads,
        owner_pid,
    } = ready.into_parts();
    if owner_pid != std::process::id() {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Spawn,
            "exec must be started by the process that applied the restrictions",
        ));
    }
    change_dir_to_verified_root(root.as_fd())?;
    let pid = sys::fork_single_threaded_with(
        || threads.count() == Some(1),
        || exec_child_main(entry),
        EXIT_SETUP_FAILED,
    )
    .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "fork"))?;
    Ok(ContainerChild::new(pid))
}

/// cwd を照合済みの root（`O_PATH` の fd）へ置く。本番ビルドの実装。
#[cfg(not(test))]
fn change_dir_to_verified_root(root: BorrowedFd<'_>) -> Result<(), ExecError> {
    sys::change_dir_fd(root)
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "fchdir(root)"))
}

/// テストビルドの dry-run 差し込み点（libtest はマルチスレッドで、cwd はプロセス全体の状態のため変えない）。
/// 呼ばれたことだけを記録する。
#[cfg(test)]
fn change_dir_to_verified_root(_root: BorrowedFd<'_>) -> Result<(), ExecError> {
    tests::CALLS.with(|c| c.borrow_mut().push("fchdir(root)"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::{Seek as _, Write as _};
    use std::os::fd::OwnedFd;

    use super::*;
    use crate::exec::ThreadCountSource;

    thread_local! {
        pub(super) static CALLS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
    }

    fn take_calls() -> Vec<&'static str> {
        CALLS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    fn root_fd() -> OwnedFd {
        OwnedFd::from(std::fs::File::open("/").expect("open /"))
    }

    /// `Threads:` を固定した使い捨ての status 相当ファイル（名前を残さない）。
    fn status_with_threads(n: u64) -> ThreadCountSource {
        let path = std::env::temp_dir().join(format!(
            "fandhe-exec-command-{}-{n}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("create");
        std::fs::remove_file(&path).expect("unlink");
        write!(f, "Name:\tx\nThreads:\t{n}\n").expect("write");
        f.seek(std::io::SeekFrom::Start(0)).expect("seek");
        ThreadCountSource::PreOpened(f)
    }

    fn entry() -> Entrypoint {
        Entrypoint::new("/bin/true", ["true"], Vec::<String>::new()).expect("entry")
    }

    /// SUP-6・SEC-1・TASK-163.4: `ExecReady` を作ったのと別のプロセスからは、cwd も変えず fork もせずに拒否する。
    #[test]
    fn sup6_task163_4_spawn_rejects_other_process() {
        take_calls();
        let ready = ExecReady::for_test(
            root_fd(),
            status_with_threads(1),
            std::process::id().wrapping_add(1),
        );
        let e = spawn_exec_command(ready, &entry()).expect_err("other process");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::Spawn);
        assert_eq!(
            e.message,
            "exec must be started by the process that applied the restrictions"
        );
        assert_eq!(take_calls(), Vec::<&str>::new());
    }

    /// SUP-6・SEC-1・TASK-163.4: 保持した status fd が単一スレッドでないと示すなら、cwd を照合済み root へ
    /// 置いた後で fork せずに `FailedPrecondition`（段 `Spawn`）。読めない場合も同じ（fail-closed）。
    #[test]
    fn sup6_task163_4_spawn_refuses_fork_when_not_single_threaded() {
        for source in [
            status_with_threads(3),
            ThreadCountSource::PreOpened(std::fs::File::open("/dev/null").expect("null")),
        ] {
            take_calls();
            let ready = ExecReady::for_test(root_fd(), source, std::process::id());
            let e = spawn_exec_command(ready, &entry()).expect_err("multi-threaded");
            assert_eq!(e.code, ErrorCode::FailedPrecondition);
            assert_eq!(e.stage, IsolationStage::Spawn);
            assert_eq!(take_calls(), vec!["fchdir(root)"]);
        }
    }
}
