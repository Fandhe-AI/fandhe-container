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
//! spawn_exec_command(ready, &entry, &child_cgroup)       // 親: non-dumpable を確認 → cwd を照合済み root へ → fork
//!   子: 子 cgroup へ参加 -> close_range(3..) -> setsid -> エントリポイントを fd で検査 -> 標準入出力を /dev/null へ -> execveat
//! 親: ContainerChild::wait_timeout(timeout)              // 期限超過は SIGKILL + 回収（REPAIR-5）
//! ```
//!
//! 上の全体は [`spawn_exec_worker`] が fork した使い捨ての worker の中で行う（worker は開始時に自分を
//! non-dumpable にする。下記「コンテナから見える窓を閉じる」）。
//!
//! # 契約
//!
//! - **コマンドの環境と補助グループ**（SEC-1・SEC-5・TASK-163 追補・#1457）: コマンドは [`ExecCommand`] で受け取り、
//!   環境変数はコンテナ定義由来の `ContainerEnv` の中身だけが `execveat` の envp になる（呼び出しプロセスの環境は
//!   渡らない）。補助グループは `reapply_restrictions` の capability 削減が launch と同じ関数で空にする
//!   （`setgroups(0)`。fork の前に済み、子へ継承される。`setgroups` が `deny` の user namespace では残して記録する）。
//!   uid / gid は変更しない
//! - **入口は [`ExecReady`] だけを値で受け取る**（SEC-1）。`ExecRestrictionReport`・真偽値を受け取る入口、
//!   `ExecReady` を作る別経路は無い。制限（`NO_NEW_PRIVS`・Landlock・seccomp・capability の bounding set・
//!   rlimit）は fork / execve を越えて継承されるため、「適用 → fork → execve」の順で子へ載る
//! - **コンテナから見える窓を閉じる（non-dumpable。SEC-1・CVE-2016-9962 型の対策）**: exec の子は fork した
//!   時点でコンテナの PID namespace に入り、`close_range` が終わるまで（標準入出力は `/dev/null` へ置換する
//!   まで）ホスト側の fd を持ったままコンテナの procfs から見える。launch 経路の子は新しい PID namespace の
//!   PID 1 で、その時点で namespace の中に他のプロセスが居ないため、この窓は exec にしか無い。dumpable の
//!   ままだと、同じ uid のコンテナ内プロセスが `/proc/<pid>/fd`・`/proc/<pid>/mem`（`PTRACE_MODE_*`。Yama の
//!   `ptrace_scope` は読み取り系を制限しない）からホスト側の fd・メモリへ届く。そこで worker は
//!   `setns` より前（開始時）に `PR_SET_DUMPABLE` = 0 にして読み戻し、[`spawn_exec_command`] は fork の直前に
//!   non-dumpable であることを確認して、そうでなければ fork せず `FailedPrecondition` にする（worker の外から
//!   呼ぶ経路を作らない）。フラグは fork で子へ継承され、capability の削減では戻らない。`execve` が成功すると
//!   カーネルが dumpable を 1 へ戻すため、実行されるコマンド自身は launch 経路のプロセスと同じ扱いになる
//! - **子を親の生存に結び付ける（REPAIR-5）**: worker は全体の期限を過ぎると親から `SIGKILL` で止められる。
//!   そのとき worker が待っていたコマンドを孤児として残さないよう、fork した子（[`spawn_exec_worker`] の
//!   worker と [`spawn_exec_command`] のコマンド）は最初に `PR_SET_PDEATHSIG` = `SIGKILL` を設定し、続けて
//!   親が fork の前に開いた自分自身の pidfd で親の生存を確かめる（設定より前に親が終了していた場合は
//!   シグナルが届かないため。親が別の PID namespace にいると `getppid` は常に 0 を返し、判定に使えない）。
//!   親が既に終了していれば子は何もせず終了する。これで「呼び出しプロセスの終了 → worker の停止 →
//!   コマンドの停止」が連鎖する。設定は資格情報の変わらない `execve` を越えて保持されるが、実行された
//!   コマンド自身は `prctl` で解除できる（解除したコマンドと、コマンドがコンテナ内で作った子孫は、コンテナの
//!   cgroup と制限の内側に残る。確実に止めるのは次項の exec 用の子 cgroup と `cgroup.kill`）
//! - **exec 用の子 cgroup と `cgroup.kill`**（SUP-6・SUP-4・REPAIR-5・CORE-4・TASK-163 追補・#1466）: コマンドだけを
//!   コンテナ cgroup 直下の子 cgroup（[`ExecChildCgroup`]。`exec-<nonce>`）へ入れて実行する。fork した子は
//!   `execve` の前（`close_range` の前）に自分を `cgroup.procs` へ `0` で移す。この時点で子孫は存在しないため、
//!   コマンドが `prctl` で親死亡シグナルを解除しても、二重 fork しても、子孫はすべてこの cgroup に入る。
//!   移せなければコマンドを起動しない（fail-closed）。停止は [`ExecChildCgroup::kill_all`]（`cgroup.kill`。子孫ごと
//!   `SIGKILL`）。親 cgroup の `memory.max`・`pids.max` 等は階層的に子孫へ掛かる（この cgroup に controller は
//!   有効化しない）。cgroup の作成・削除はこのモジュールではなく `exec::cgroup_join`（作成は `enter_namespaces` と再適用の前、
//!   削除は制限の掛かっていない呼び出しプロセスが名前から）
//! - **fork の前に cwd を照合済みの root へ置く**: `setns(CLONE_NEWNS)` が付け替えた cwd は検証していないため、
//!   `ExecReady` が持つ照合済みの `/` の fd へ `fchdir` する。コマンドの cwd はコンテナの rootfs の根になる
//! - **fork の健全性**: 子を fork する直前に、`setns` 前に開いた status fd から `Threads: 1` を確認する
//!   （`setns` の後は自プロセスを `/proc/self` で解決できないため、`ProcSelf` は使えない）。満たさなければ
//!   fork せず `FailedPrecondition`。fork は `sys::fork_single_threaded_with` が強制する
//! - **別プロセスからは呼べない**: `ExecReady` を作ったプロセスと異なる pid からの呼び出しは何もせず拒否する
//!   （fork した子の pid は数値が衝突し得るため、best-effort の誤用検知）
//! - **子は launch 経路と同じ手順で exec する**: エントリポイントを開く前に fd 3 以上を `close_range` で閉じ
//!   （cgroup・状態・固定した rootfs・status の fd をコンテナへ渡さない。CVE-2024-21626 型の対策）、`setsid` で
//!   呼び出し側のセッション・制御端末を切り離し（端末から起動した CLI の exec で、コマンドが `/dev/tty` 経由で
//!   ホスト側の端末へ届かない。失敗したら実行しない。TASK-163 追補・#1456）、標準 fd と同一
//!   実体・ランタイム自身のバイナリ（本体に加えて、シェバンの連鎖・`PT_INTERP` の解決先。`#!/proc/self/exe` 等。
//!   #1458）を拒否し、シェバンを検証し、標準入出力を新 root の `/dev/null`（開く前に 1:3 を検証し、`O_NOCTTY`
//!   つきで開き直す。#1459）へ置換して `execveat` する（`process::exec_checked_entrypoint`）。エントリポイントは絶対パスのみで PATH
//!   探索はしない。子の失敗は stderr の英語 1 行・終了コード（125 / 126 / 127）・親への pipe（下記）で伝える
//! - **親の待ちには必ずタイムアウトを設ける**（REPAIR-5）: 戻り値の [`ExecChild`] は
//!   `wait_timeout` のみを提供する。`Drop` では kill / wait しない
//! - **`execve` 前の失敗とコマンドの終了を区別する**（REPAIR-3・TASK-163 追補・#1460）: 子の終了コード 125 / 126 /
//!   127 は実行されたコマンド自身も返し得るため、終了コードでは区別できない。親は fork の前に close-on-exec の
//!   pipe を作り、子は fd の後始末でその書き込み側だけを残して、「手順を終えた（`R`）」「失敗した（終了コードと
//!   違反の理由）」を 1 行で書く。`execveat` が成功すれば pipe は閉じるので、親は子の終了後に「`R` だけ」=
//!   起動した、「失敗の行」または「何も無い」= 起動していない、と判定する（[`ExecExit`]）。**限界**: `R` を
//!   書いた後・`execveat` の完了前にシグナルで終了した子は「起動した」と判定される（窓は syscall 1 回ぶん）。
//!   pipe の書き込み側はコンテナ内の PID namespace から見える子が持つが、子は non-dumpable で、`execveat` の後は
//!   存在しない
//!
//! # 未実装（REPAIR-3）
//!
//! - 標準入出力の受け渡し（CLI の exec・TASK-161 / SUP-4 の healthcheck の出力取得）。現状は launch と同じく
//!   `/dev/null` へ固定する（ホスト側の端末・ファイルをコンテナへ渡さない。fail-closed）
//! - 作業ディレクトリ・ユーザーの指定（OCI `process` からの組み立て）。cwd は rootfs の根で固定。環境変数は
//!   コンテナ定義（`config.json` の `process.env`）と明示の上書きだけを [`ExecCommand`] の `ContainerEnv` で受け取り、
//!   exec を起動したプロセスの環境は引き継がない（TASK-163 追補・#1457。`exec/container_env.rs`）
//! - 子の失敗を構造のまま親へ返すこと（現状は終了コード・違反の理由コード・stderr。段とメッセージは親へ返らない）

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use crate::sys;
use crate::traits::types::ErrorCode;

use super::process::{EXIT_SETUP_FAILED, exec_child_main, exec_status_pipe, read_exec_status};
use super::reapply::ExecReadyParts;
use super::{
    ChildExit, ContainerChild, ExecChildCgroup, ExecCommand, ExecError, ExecExit, ExecReady,
    IsolationStage,
};

/// [`spawn_exec_command`] が fork した、稼働中コンテナ内のコマンドの子（SUP-6・TASK-163 追補・#1460）。
///
/// [`ContainerChild`]（期限つきの待機・`SIGKILL` と回収）に、子が `execve` 前の失敗を知らせる pipe の読み取り側を
/// 足したもの。[`Self::wait_timeout`] は終了状態を [`ExecExit`] で返し、「コマンドが起動して終了した」のか
/// 「コマンドは起動していない（`execve` より前で失敗した）」のかを区別する。`Drop` では kill / wait しない
/// （回収の責任は呼び出し元にある。`ContainerChild` と同じ）。
#[derive(Debug)]
pub struct ExecChild {
    child: ContainerChild,
    /// 子が状態を書く pipe の読み取り側。
    status: std::fs::File,
    /// 判定済みの結果（pipe は 1 回しか読めないため、2 回目以降の待機は記録を返す）。pipe の読み取りから
    /// 記録までをこのロックの下で行い、並行に待つ呼び出しが pipe を取り合わないようにする（一方が `R` を読み、
    /// 他方が EOF を読んで「起動していない」と記録することがない）。
    /// 読み取りに失敗した場合も「判定できなかった」ことを記録する（`Some(None)`。部分的に読んだ後の再読み取りは
    /// EOF になり、起動したコマンドを「起動していない」と誤判定し得るため、読み直さない）。
    outcome: std::sync::Mutex<Option<Option<ExecExit>>>,
}

impl ExecChild {
    /// 子の pid（呼び出しプロセスの PID namespace での値）。
    pub fn pid(&self) -> u32 {
        self.child.pid()
    }

    /// 子の終了を `timeout` まで待ち、コマンドが起動したかどうかを添えて返す（REPAIR-5）。
    ///
    /// 期限を過ぎたら未回収に限り `SIGKILL` して回収し `Timeout`（[`ContainerChild::wait_timeout`] と同じ）。
    /// 終了後に子が残した状態を読めなければ、起動したかどうかを推測せず `Internal` で返す。
    pub fn wait_timeout(&self, timeout: std::time::Duration) -> Result<ExecExit, ExecError> {
        let exit = self.child.wait_timeout(timeout)?;
        self.classify(exit)
    }

    /// 未回収なら `SIGKILL` して回収する（[`ContainerChild::kill_and_reap`]。期限切れ・待機エラー後の後始末用）。
    pub fn kill_and_reap(&self, timeout: std::time::Duration) -> Result<ChildExit, ExecError> {
        self.child.kill_and_reap(timeout)
    }

    fn classify(&self, exit: ChildExit) -> Result<ExecExit, ExecError> {
        // 毒化していても中身は判定の記録だけ（途中状態を持たない）ため、そのまま使う。
        let mut recorded = self
            .outcome
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let outcome = match *recorded {
            Some(outcome) => outcome,
            None => {
                let outcome = read_exec_status(&self.status, exit);
                *recorded = Some(outcome.as_ref().ok().copied());
                Some(outcome?)
            }
        };
        outcome.ok_or_else(|| {
            ExecError::new(
                ErrorCode::Internal,
                IsolationStage::Wait,
                "the exec status could not be read; cannot tell whether the command started",
            )
        })
    }
}

/// 証跡 `ready` を消費し、`entry` を稼働中コンテナの namespace・cgroup・制限の下で実行する子を fork する。
///
/// 親（呼び出しプロセス）は子の pid を持つ [`ContainerChild`] を返すだけで、exec しない。単一スレッドの exec
/// 専用プロセス（[`spawn_exec_worker`] の worker。non-dumpable）からのみ呼ぶ（契約はモジュール doc）。dumpable な
/// プロセスから呼ぶと fork せず `FailedPrecondition`（段 `Spawn`）。失敗しても状態は戻せないため、呼び出し側は
/// 続行せず終了する。
///
/// `ExecReady` を経由しない入口は無い（`ExecRestrictionReport` は渡せない）:
///
/// ```compile_fail,E0308
/// fn f(
///     report: fandhe_container_core::exec::ExecRestrictionReport,
///     command: &fandhe_container_core::exec::ExecCommand,
///     cgroup: &fandhe_container_core::exec::ExecChildCgroup,
/// ) {
///     let _ = fandhe_container_core::exec::spawn_exec_command(report, command, cgroup);
/// }
/// ```
///
/// コマンドは [`ExecCommand`] でしか渡せない（環境変数を任意の文字列の列で渡せる launch 用の `Entrypoint` は
/// 受け取らない。TASK-163 追補・#1457。契約は `exec/container_env.rs`）:
///
/// ```compile_fail,E0308
/// fn f(
///     ready: fandhe_container_core::exec::ExecReady,
///     entry: &fandhe_container_core::exec::Entrypoint,
///     cgroup: &fandhe_container_core::exec::ExecChildCgroup,
/// ) {
///     let _ = fandhe_container_core::exec::spawn_exec_command(ready, entry, cgroup);
/// }
/// ```
pub fn spawn_exec_command(
    ready: ExecReady,
    command: &ExecCommand,
    cgroup: &ExecChildCgroup,
) -> Result<ExecChild, ExecError> {
    let entry = command.entrypoint();
    let ExecReadyParts {
        root,
        mut threads,
        owner_pid,
        deferred_fsize,
    } = ready.into_parts();
    if owner_pid != std::process::id() {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Spawn,
            "exec must be started by the process that applied the restrictions",
        ));
    }
    require_non_dumpable()?;
    // 子が「親（この worker）の生存」を確かめるための、自プロセスの pidfd（fork で子へ継承される）。
    let own = own_pidfd()?;
    change_dir_to_verified_root(root.as_fd())?;
    // 子が `execve` 前の失敗を知らせる pipe（両端とも close-on-exec。`execveat` が成功すれば書き込み側は閉じる）。
    let (status_read, status_write) = exec_status_pipe()?;
    let pid = sys::fork_single_threaded_with(
        || threads.count() == Some(1),
        || match bind_to_parent_lifetime(own.as_fd()).and_then(|()| join_exec_cgroup(cgroup)) {
            Ok(()) => exec_child_main(entry, &status_write, deferred_fsize),
            // 何も書かずに終わる（親は「手順の途中で終了した」= コマンドは起動していない、と判定する）。
            Err(code) => code,
        },
        EXIT_SETUP_FAILED,
    )
    .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "fork"))?;
    // 親の書き込み側を閉じる（子の終了後に読み取りが EOF で終わるようにする）。
    drop(status_write);
    Ok(ExecChild {
        child: ContainerChild::new(pid),
        status: status_read,
        outcome: std::sync::Mutex::new(None),
    })
}

/// fork した子（コマンド）を exec 用の子 cgroup へ移す（#1466。契約はモジュール doc「exec 用の子 cgroup」）。
///
/// `bind_to_parent_lifetime` の後・`close_range` の前（cgroup の書き込み fd が残っている間）に呼ぶ。この時点で
/// 子孫は存在しないため、移した後に作られる子孫はすべて子 cgroup に入る。失敗したら stderr に英語 1 行を出し
/// `EXIT_SETUP_FAILED` を返す（何も書かずに終了 = 親は「コマンドは起動していない」と判定する。fail-closed）。
fn join_exec_cgroup(cgroup: &ExecChildCgroup) -> Result<(), i32> {
    use std::io::Write as _;
    cgroup.join_self().map_err(|_| {
        let _ = writeln!(
            std::io::stderr(),
            "fandhe-container: the exec command could not join its child cgroup; refusing to continue"
        );
        EXIT_SETUP_FAILED
    })
}

/// 呼び出しプロセス自身を指す pidfd を開く（fork する子へ継承させ、親の生存確認に使う。REPAIR-5）。
///
/// `pidfd_open` は pid を呼び出しプロセスの PID namespace で解決する。`setns(CLONE_NEWPID)` は呼び出し
/// プロセス自身の PID namespace を変えないため、参加の後でも自分の pid で開ける。
fn own_pidfd() -> Result<OwnedFd, ExecError> {
    sys::pidfd_open(std::process::id())
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "pidfd_open(self)"))
}

/// fork した子を親の生存に結び付ける（REPAIR-5。契約はモジュール doc「子を親の生存に結び付ける」）。
///
/// 親死亡シグナル（`SIGKILL`）を設定してから、`parent`（親が fork の前に開いた親自身の pidfd）で親が終了して
/// いないことを確かめる。設定・確認に失敗した場合と、親が既に終了していた場合は、stderr に英語 1 行を出して
/// 子の終了コード（`EXIT_SETUP_FAILED`）を返す（呼び出し側は以降の処理を実行しない。fail-closed）。
fn bind_to_parent_lifetime(parent: BorrowedFd<'_>) -> Result<(), i32> {
    use std::io::Write as _;
    // pidfd は対象の終了で読み取り可能になる（タイムアウト 0 で現在の状態だけを見る）。
    let parent_exited =
        sys::set_parent_death_sigkill().and_then(|()| sys::poll_readable(parent, 0));
    if parent_exited == Ok(false) {
        return Ok(());
    }
    let _ = writeln!(
        std::io::stderr(),
        "fandhe-container: the parent of the exec process is gone or cannot be watched; refusing to continue"
    );
    Err(EXIT_SETUP_FAILED)
}

/// 「exec 専用の使い捨て worker の中にいる」ことの証跡（ゼロサイズ。#1532・SUP-6・SEC-1）。
///
/// [`prepare_exec_restrictions`](super::prepare_exec_restrictions) は準備の最後に呼び出しプロセスの補助グループを
/// `setgroups(0)` で消す（不可逆。#1457）。常駐側（supervisor 本体・CLI）が誤って呼ぶとそのプロセスの補助グループが
/// 戻らず失われるため、呼び出しを [`spawn_exec_worker`] の worker の中だけに型で絞る。証跡は [`spawn_exec_worker`] が
/// fork した子の中で、親の死亡シグナルの設定と non-dumpable の確認が成功した **後** にだけ作られ、閉包の引数として
/// 渡される。
///
/// - フィールドは非公開で、crate の外から構造体リテラルでは作れない
/// - `PhantomData<*const ()>` により `!Send` / `!Sync`（別スレッド・別プロセスへ持ち出せない）。`Clone` / `Copy` /
///   `Default` は実装しない
/// - 採用理由: 準備関数は別 crate（supervisor）からも呼ぶため `pub(crate)` への縮小は成立しない。既存の証跡型
///   （`ExecReady`・`MountIsolation`）と同じ流儀で型に委ねる
///
/// ```compile_fail,E0451
/// use fandhe_container_core::exec::ExecWorkerProof;
/// let _forged = ExecWorkerProof { _not_send: std::marker::PhantomData };
/// ```
///
/// ```compile_fail
/// use fandhe_container_core::exec::ExecWorkerProof;
/// fn assert_send<T: Send>() {}
/// assert_send::<ExecWorkerProof>();
/// ```
///
/// 注意: compile_fail は失敗の理由までは確かめない。非 Linux では型が無いため常に通る。
#[must_use]
#[derive(Debug)]
pub struct ExecWorkerProof {
    _not_send: std::marker::PhantomData<*const ()>,
}

impl ExecWorkerProof {
    /// [`spawn_exec_worker`] の fork 子の中だけで呼ぶ。
    fn new() -> Self {
        Self {
            _not_send: std::marker::PhantomData,
        }
    }

    /// 試験専用: worker の外で証跡を作る（`exec-test-support` feature の下のみ。リリースビルドでは feature の
    /// 有効化が `compile_error!` で止まる）。
    ///
    /// 使い捨ての子プロセス専用。これで得た証跡を [`prepare_exec_restrictions`](super::prepare_exec_restrictions)
    /// へ渡すと **呼び出しプロセスの補助グループが不可逆に消える**。
    #[cfg(all(feature = "exec-test-support", not(test)))]
    #[doc(hidden)]
    pub fn assume_for_test() -> Self {
        Self::new()
    }
}

/// 準備から実行までを担う使い捨ての worker プロセスを fork する（REPAIR-5・SUP-6・TASK-163.4・#503）。
///
/// `fandhe-container-supervisor` の `exec::run_command` が、`setns`・cgroup join・制限の再適用といった
/// 割り込めないブロッキング段を **別プロセス** へ隔離し、親が全体の期限で待って期限超過時に worker を
/// `SIGKILL` で止めて回収できるようにするために呼ぶ（単一スレッドのため、段の途中のハングを同一プロセス内の
/// 期限確認では止められない）。
///
/// - 呼び出し元は単一スレッドでなければならない（満たさなければ fork せず `FailedPrecondition`。
///   `sys::fork_single_threaded` が強制する）
/// - `worker` は fork した子で実行され、証跡 [`ExecWorkerProof`] を引数に受け取る。戻り値（0〜255 に丸められる）で `_exit` する。panic は
///   `EXIT_SETUP_FAILED`。呼び出し元のフレームへは戻らない。結果の受け渡しは呼び出し側が fork 前に用意した
///   fd（pipe 等）で行う
/// - worker は `worker` を実行する **前** に、自分を呼び出し元の生存に結び付け（呼び出し元が終了したら
///   `SIGKILL` が届く。モジュール doc「子を親の生存に結び付ける」。REPAIR-5）、自分を non-dumpable にして
///   読み戻して確認する（モジュール doc「コンテナから見える窓を閉じる」。SEC-1）。どちらかの設定・確認に
///   失敗したら `worker` を実行せず `EXIT_SETUP_FAILED` で終了する（fail-closed）。それ以外の制限は適用しない。子へ載る制限は、worker 自身が
///   `reapply_restrictions` で作った [`ExecReady`] 経由でしか exec へ進めない（`ExecReady` は別プロセスへ
///   渡せない。SEC-1）
/// - 戻り値の [`ContainerChild`] は `wait_timeout` で待つこと（`Drop` では kill / wait しない）
pub fn spawn_exec_worker<F: FnOnce(ExecWorkerProof) -> i32>(
    worker: F,
) -> Result<ContainerChild, ExecError> {
    let own = own_pidfd()?;
    let pid = sys::fork_single_threaded(
        || match bind_to_parent_lifetime(own.as_fd()).and_then(|()| make_worker_non_dumpable()) {
            // 上の 2 つが成功した後にだけ証跡を作る（証跡の意味を「親の生存に結合済みで non-dumpable な
            // worker の中にいる」に固定する。#1532）。
            Ok(()) => worker(ExecWorkerProof::new()),
            Err(code) => code,
        },
        EXIT_SETUP_FAILED,
    )
    .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "fork"))?;
    Ok(ContainerChild::new(pid))
}

/// worker（fork した子）を non-dumpable にし、読み戻して確認する。失敗時は stderr に英語 1 行を出し、
/// worker の終了コード（`EXIT_SETUP_FAILED`）を返す（呼び出し側は `worker` を実行しない）。
fn make_worker_non_dumpable() -> Result<(), i32> {
    use std::io::Write as _;
    let outcome = sys::set_non_dumpable().and_then(|()| sys::is_dumpable());
    if outcome == Ok(false) {
        return Ok(());
    }
    let _ = writeln!(
        std::io::stderr(),
        "fandhe-container: the exec worker could not become non-dumpable; refusing to continue"
    );
    Err(EXIT_SETUP_FAILED)
}

/// 呼び出しプロセスが non-dumpable であることを確かめる（fork の直前。SEC-1）。本番ビルドの実装。
///
/// dumpable なら `FailedPrecondition`（段 `Spawn`）。確認できない場合も fork しない（fail-closed）。
#[cfg(not(test))]
fn require_non_dumpable() -> Result<(), ExecError> {
    let dumpable = sys::is_dumpable()
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "prctl(PR_GET_DUMPABLE)"))?;
    reject_dumpable(dumpable)
}

/// テストビルドの差し込み点（libtest のプロセスは dumpable で、プロセス全体の状態のため変えない）。
/// 呼ばれたことを記録し、`tests::DUMPABLE` の値で本番と同じ判定を通す。
#[cfg(test)]
fn require_non_dumpable() -> Result<(), ExecError> {
    tests::CALLS.with(|c| c.borrow_mut().push("prctl(PR_GET_DUMPABLE)"));
    reject_dumpable(tests::DUMPABLE.with(std::cell::Cell::get))
}

/// dumpable なプロセスからの exec を拒否する（判定の本体。本番・テストで共有する）。
fn reject_dumpable(dumpable: bool) -> Result<(), ExecError> {
    if dumpable {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Spawn,
            "exec requires a non-dumpable process; start it from the exec worker",
        ));
    }
    Ok(())
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

    use super::*;
    use crate::exec::ThreadCountSource;

    thread_local! {
        pub(super) static CALLS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
        /// `require_non_dumpable` の差し込み点が返す値（既定は non-dumpable = worker の中）。
        pub(super) static DUMPABLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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

    /// `cgroup.procs` / `cgroup.kill` を置いた使い捨てのディレクトリから作った子 cgroup（fork 前に失敗する試験用）。
    fn child_cgroup() -> ExecChildCgroup {
        let dir = std::env::temp_dir().join(format!(
            "fandhe-exec-command-cg-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("cgroup.procs"), "").expect("procs");
        std::fs::write(dir.join("cgroup.kill"), "").expect("kill");
        let fd = OwnedFd::from(std::fs::File::open(&dir).expect("open dir"));
        let cgroup = ExecChildCgroup::from_dir_for_test(fd);
        let _ = std::fs::remove_dir_all(&dir);
        cgroup
    }

    fn entry() -> ExecCommand {
        ExecCommand::new("/bin/true", ["true"], &crate::exec::ContainerEnv::empty()).expect("entry")
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
        let e = spawn_exec_command(ready, &entry(), &child_cgroup()).expect_err("other process");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::Spawn);
        assert_eq!(
            e.message,
            "exec must be started by the process that applied the restrictions"
        );
        assert_eq!(take_calls(), Vec::<&str>::new());
    }

    /// SUP-6・SEC-1・TASK-163.4: dumpable なプロセス（exec worker の外）からは、cwd も変えず fork もせずに
    /// `FailedPrecondition`（段 `Spawn`）。コンテナの PID namespace に入る子を、コンテナ側から procfs 経由で
    /// 読める状態で作らない（CVE-2016-9962 型）。
    #[test]
    fn sup6_task163_4_spawn_rejects_dumpable_process() {
        take_calls();
        DUMPABLE.with(|d| d.set(true));
        let ready = ExecReady::for_test(root_fd(), status_with_threads(1), std::process::id());
        let result = spawn_exec_command(ready, &entry(), &child_cgroup());
        DUMPABLE.with(|d| d.set(false));
        let e = result.expect_err("dumpable");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::Spawn);
        assert_eq!(
            e.message,
            "exec requires a non-dumpable process; start it from the exec worker"
        );
        assert_eq!(e.violation, None);
        assert_eq!(take_calls(), vec!["prctl(PR_GET_DUMPABLE)"]);
    }

    /// 子が `content` を書いて終了した後の状態を模した `ExecChild`（pid は待機に使わない）。
    fn exec_child_with_status(content: &[u8]) -> (ExecChild, std::fs::File) {
        let (status, writer) = exec_status_pipe().expect("status pipe");
        (&writer).write_all(content).expect("write status");
        let child = ExecChild {
            child: ContainerChild::from_pid_for_test(std::process::id()),
            status,
            outcome: std::sync::Mutex::new(None),
        };
        (child, writer)
    }

    /// SUP-6・REPAIR-3・TASK-163 追補（#1460）: 並行に待つ呼び出しが状態の pipe を取り合っても、全員が同じ判定を
    /// 受け取る（一方が `R` を読み、他方が EOF を読んで「起動していない」と記録することがない）。pipe の両端は
    /// 標準入出力の番号（0〜2）に置かれない。
    #[test]
    fn sup6_task163_concurrent_waiters_share_one_exec_status() {
        use std::os::fd::AsRawFd as _;
        let exit = ChildExit::Exited(126);
        let mut classified = 0usize;
        for _ in 0..50 {
            let (child, writer) = exec_child_with_status(b"R\n");
            assert!(child.status.as_raw_fd() > 2 && writer.as_raw_fd() > 2);
            drop(writer);
            let results: Vec<Option<ExecExit>> = std::thread::scope(|scope| {
                let handles: Vec<_> = (0..8)
                    .map(|_| scope.spawn(|| child.classify(exit).ok()))
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("join"))
                    .collect()
            });
            // 全員が同じ判定を受け取る。libtest では他のテストスレッドが子プロセスを fork し得て、その子が
            // `execve` までの間 pipe の書き込み側の複製を持つと「書き込み側が開いたまま」（判定不能 = `None`）に
            // なる（本番の exec 専用プロセスは単一スレッドで、この重なりは起きない）。その回も全員が判定不能で
            // 揃い、誰も「起動していない」とは判定しない。
            let first = results.first().copied().flatten();
            assert_eq!(results, vec![first; 8]);
            assert!(
                first.is_none() || first == Some(ExecExit::Command(exit)),
                "{first:?}"
            );
            classified += usize::from(first.is_some());
        }
        // 判定不能は他スレッドの fork と重なった回だけで、「起動した」と判定される回が必ずある。
        assert!(classified > 0, "no round was classified");
    }

    /// SUP-6・REPAIR-5・TASK-163 追補（#1460）: 状態を読めなかった判定は記録され、読み直さない（書き込み側が
    /// 後から閉じても、EOF を「起動していない」と解釈し直さない）。
    #[test]
    fn sup6_task163_unreadable_exec_status_is_not_reinterpreted() {
        let exit = ChildExit::Exited(0);
        let (child, writer) = exec_child_with_status(b"");
        // 書き込み側が開いたまま（データなし）: 待たずに `Internal`。
        let first = child.classify(exit).expect_err("still open");
        assert_eq!(
            first.message,
            "the exec status pipe is still open after exit"
        );
        drop(writer);
        let second = child.classify(exit).expect_err("recorded as unreadable");
        assert_eq!(
            (second.code, second.stage),
            (ErrorCode::Internal, IsolationStage::Wait)
        );
        assert_eq!(
            second.message,
            "the exec status could not be read; cannot tell whether the command started"
        );
    }

    /// SUP-6・SEC-1・TASK-163.4: 判定の本体は dumpable のときだけ拒否する。
    #[test]
    fn sup6_task163_4_reject_dumpable_concrete_values() {
        assert!(reject_dumpable(false).is_ok());
        let e = reject_dumpable(true).expect_err("dumpable");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::Spawn);
    }

    /// SUP-6・SEC-1・TASK-163.4: 保持した status fd が単一スレッドでないと示すなら、non-dumpable の確認と
    /// cwd の設定の後で fork せずに `FailedPrecondition`（段 `Spawn`）。読めない場合も同じ（fail-closed）。
    #[test]
    fn sup6_task163_4_spawn_refuses_fork_when_not_single_threaded() {
        for source in [
            status_with_threads(3),
            ThreadCountSource::PreOpened(std::fs::File::open("/dev/null").expect("null")),
        ] {
            take_calls();
            let ready = ExecReady::for_test(root_fd(), source, std::process::id());
            let e =
                spawn_exec_command(ready, &entry(), &child_cgroup()).expect_err("multi-threaded");
            assert_eq!(e.code, ErrorCode::FailedPrecondition);
            assert_eq!(e.stage, IsolationStage::Spawn);
            assert_eq!(take_calls(), vec!["prctl(PR_GET_DUMPABLE)", "fchdir(root)"]);
        }
    }
}
