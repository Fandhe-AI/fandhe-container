//! exec 用の子 cgroup の作成・参加・`cgroup.kill` による停止・削除の fd 操作（SUP-6・SUP-4・TASK-163 追補・#1466・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! exec のコマンドは、実行後に親死亡シグナルを `prctl` で解除でき、二重 fork した子孫には親死亡シグナルが
//! 引き継がれない。そこで exec ごとにコンテナ cgroup の直下へ子 cgroup（`exec-<nonce>`）を作り、コマンドだけを
//! そこへ入れて、停止は `cgroup.kill` で子孫ごと行う（CORE-4: cgroup v2 のみ）。呼び出し元は
//! `exec::cgroup_join`（安全 API）で、その上に supervisor の `exec` モジュールが載る。`unsafe` は持たず、
//! syscall は `crate::sys` の既存ラッパー経由。
//!
//! # 契約
//!
//! - 作成は検証済みのコンテナ cgroup のディレクトリ fd 相対（`mkdirat`。パスの再解決なし。SEC-1）。同名が既に
//!   あれば `AlreadyExists` で失敗し、既存の cgroup を採用しない。作成直後に cgroup2・（非 root なら）所有者が euid・
//!   `cgroup.procs` が空であることを確認し、`cgroup.procs` と `cgroup.kill` の書き込み fd を確保する。
//!   `cgroup.kill`（Linux 5.14 以降）が開けなければ作成を巻き戻して拒否する（fail-closed。親死亡シグナルだけへ縮退しない）
//! - **書き込み fd は制限の再適用の前に確保する**: exec 専用プロセスは再適用後に Landlock が掛かり、cgroupfs への
//!   `open` / `rmdir` はできない。開いた後の fd への `write`（`cgroup.kill` へ `1`・`cgroup.procs` へ `0`）は
//!   Landlock の対象外のため、worker は保持 fd で停止できる。**削除（`rmdir`）は制限の掛かっていない呼び出し
//!   プロセスが名前から開き直して行う**（[`remove_exec_child_cgroup_at`]。冪等）
//! - 参加は子（fork 直後・`exec` 前）が `cgroup.procs` へ `0`（書き手自身）を書く。子孫が存在する前に入るため
//!   競合がない。この cgroup に controller は有効化しない（内部プロセス禁止規則: 親は pid1 を直接持つため
//!   `cgroup.subtree_control` は空のまま）。親 cgroup の `memory.max`・`pids.max` 等は階層的に子孫へ掛かる
//! - 削除は `cgroup.kill` → `cgroup.events` の `populated 0` を上限時間つきで待つ → 保持 fd と同一性を確認して
//!   `rmdir`（`remove_verified_at`）。カーネル応答は上限付きで読み、`unwrap` / 添字アクセスは使わない
//! - **残骸の掃除（#1596）**: 呼び出しプロセスが `SIGKILL` された・後始末が上限を超えた・kill に失敗した場合に残った
//!   `exec-*` を、検証済みのコンテナ cgroup の fd を起点に [`sweep_exec_children_at`] が掃除する（SUP-6・OCI-6・CORE-4）。
//!   時機と対象は 2 つ。**delete 前**（`SweepMode::KillAll`）はコンテナが停止済みなので、直下の `exec-*` すべてに
//!   `cgroup.kill` → `populated 0` を全体で 1 つの期限つきで待つ → 同一性確認つきで `rmdir`。**exec 開始時**
//!   （`SweepMode::UnpopulatedOnly`）は並行する別の exec を壊さないよう `cgroup.kill` を一切書かず、プロセスの
//!   居ない残骸だけを消す（プロセスの居るものは delete 前に回収される。割り切り）。さらに名前の pid の持ち主が
//!   生きているものにも触れない（作成から `join_self` までの空の間の並行 exec を守る）。判定できないときは触れない
//! - 掃除の列挙は `/proc/thread-self/fd/<N>` の `read_dir`（`sys` に `getdents64` ラッパーを足さず新しい `unsafe` を
//!   増やさないため）。**列挙から使うのは名前だけ**で、名前ごとに [`validate_exec_child_name`]・コンテナ fd 相対の
//!   `O_NOFOLLOW|O_DIRECTORY` open・cgroup2 検証・所有者検証を必ず通すため、列挙結果が偽装されても触れる先は
//!   コンテナ fd 直下の検証済みの実体に限られる（SEC-1）。総エントリ数と候補数に上限を設け、超過は `truncated` で返す（REPAIR-5）
//! - 名前指定の `rmdir` は同一性確認と削除の間の差し替えを原理的に塞げない（`DelegatedCgroup` と同じ限界。
//!   削除後に保持 fd 経由で消えたことを確認する）

use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::time::{Duration, Instant};

use super::{
    CgroupError, CgroupStep, PROCS_LIMIT, cstring, io_error, open_cgroup_dir, owner_uid,
    parse_procs, read_iface, remove_verified_at, sys_error, validate_component,
};
use crate::observability::{OpName, OpOutcome, OpRecorder};
use crate::sys;
use crate::traits::ErrorCode;

/// `cgroup.events` の読み取り上限（数行の小さなファイル）。
const EVENTS_LIMIT: u64 = 4096;

/// 子 cgroup 名の最大長（`exec-<pid>-<連番>` は十分に収まる）。
const NAME_MAX_LEN: usize = 64;

/// 空になるまでの待機の再読み取り間隔。
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// exec 用の子 cgroup 名を検証する（`exec-` 接頭辞・`[a-z0-9-]`・長さ上限）。
///
/// コンテナ用の `fc-` 接頭辞と衝突しないため、`Pid1Target` の cgroup 完全一致照合と干渉しない。
pub(crate) fn validate_exec_child_name(name: &str) -> Result<(), CgroupError> {
    let step = CgroupStep::CreateChild;
    validate_component(step, name)?;
    let ok = name.len() <= NAME_MAX_LEN
        && name.starts_with("exec-")
        && name.len() > "exec-".len()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !ok {
        return Err(CgroupError::precondition(
            step,
            "exec child cgroup name is not valid",
        ));
    }
    Ok(())
}

/// `cgroup.events` の `populated` を解析する（`1` は子孫を含めてプロセスが居る）。
///
/// 行が無い・値が `0` / `1` 以外は `FailedPrecondition`（カーネル応答の異常。fail-closed）。
pub(crate) fn parse_populated(text: &str) -> Result<bool, CgroupError> {
    let step = CgroupStep::Cleanup;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("populated ") {
            return match value.trim() {
                "0" => Ok(false),
                "1" => Ok(true),
                _ => Err(CgroupError::precondition(
                    step,
                    "cgroup.events has an unexpected populated value",
                )),
            };
        }
    }
    Err(CgroupError::precondition(
        step,
        "cgroup.events has no populated line",
    ))
}

/// `dir` の `cgroup.events` が `populated 0` になるまで `timeout` を上限に待つ（REPAIR-5）。
///
/// 上限を過ぎても空にならなければ `Timeout`。
fn wait_unpopulated(
    dir: std::os::fd::BorrowedFd<'_>,
    timeout: Duration,
) -> Result<(), CgroupError> {
    let step = CgroupStep::Cleanup;
    let start = Instant::now();
    loop {
        if !parse_populated(&read_iface(step, dir, "cgroup.events", EVENTS_LIMIT)?)? {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(CgroupError::new(
                ErrorCode::Timeout,
                step,
                "exec child cgroup still has processes after cgroup.kill",
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// 非 root のとき、`fd` の所有者が euid であることを確認する（他主体が作った同名の cgroup を採用しない）。
fn require_owned_by_euid(
    step: CgroupStep,
    fd: std::os::fd::BorrowedFd<'_>,
) -> Result<(), CgroupError> {
    let euid = sys::effective_uid();
    if euid == 0 {
        return Ok(());
    }
    let dup = fd
        .try_clone_to_owned()
        .map_err(|e| io_error(step, "dup exec child cgroup", &e))?;
    if owner_uid(step, dup, "stat exec child cgroup")? != euid {
        return Err(CgroupError::new(
            ErrorCode::PermissionDenied,
            step,
            "exec child cgroup is not owned by the effective user",
        ));
    }
    Ok(())
}

/// `cgroup.kill` へ `1` を書く（子孫ごと SIGKILL。冪等）。
fn write_kill(kill_w: &File) -> Result<(), CgroupError> {
    let mut w = kill_w;
    w.write_all(b"1")
        .map_err(|e| io_error(CgroupStep::Cleanup, "cgroup.kill", &e))
}

/// 作成済みの exec 用の子 cgroup の fd 一式（書き込み fd は制限の再適用前に確保済み）。
///
/// すべて `O_CLOEXEC`。コマンドの `execve` 前に子が `close_range` で閉じる（コンテナへ渡さない）。
pub(crate) struct ExecChildCgroupFds {
    procs_w: File,
    kill_w: File,
}

impl std::fmt::Debug for ExecChildCgroupFds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecChildCgroupFds").finish_non_exhaustive()
    }
}

impl ExecChildCgroupFds {
    /// コンテナ cgroup `parent` の直下に `name` の子 cgroup を作り、書き込み fd を確保する。
    ///
    /// 契約はモジュール doc。失敗時は作成した cgroup を巻き戻す（巻き戻せなければ呼び出し側の名前指定の削除が拾う）。
    pub(crate) fn create(
        parent: std::os::fd::BorrowedFd<'_>,
        name: &str,
    ) -> Result<Self, CgroupError> {
        let step = CgroupStep::CreateChild;
        validate_exec_child_name(name)?;
        let c = cstring(step, name)?;
        sys::mkdir_at(parent, &c, 0o755)
            .map_err(|e| sys_error(step, "mkdir exec child cgroup", e))?;
        Self::open_created(parent, name).inspect_err(|_| {
            let _ = sys::remove_dir_at(parent, &c);
        })
    }

    fn open_created(parent: std::os::fd::BorrowedFd<'_>, name: &str) -> Result<Self, CgroupError> {
        let step = CgroupStep::CreateChild;
        let dir: OwnedFd = open_cgroup_dir(step, parent, name)?;
        require_owned_by_euid(step, dir.as_fd())?;
        let procs = read_iface(step, dir.as_fd(), "cgroup.procs", PROCS_LIMIT)?;
        if !parse_procs(step, &procs)?.is_empty() {
            return Err(CgroupError::precondition(
                step,
                "exec child cgroup is not empty right after creation",
            ));
        }
        Self::from_dir(dir)
    }

    fn from_dir(dir: OwnedFd) -> Result<Self, CgroupError> {
        let step = CgroupStep::CreateChild;
        let procs = cstring(step, "cgroup.procs")?;
        let kill = cstring(step, "cgroup.kill")?;
        let procs_w = sys::open_write_at(dir.as_fd(), &procs)
            .map_err(|e| sys_error(step, "cgroup.procs", e))?;
        let kill_w = sys::open_write_at(dir.as_fd(), &kill).map_err(|e| match e {
            sys::SysError::Os(errno) if errno == sys::ENOENT => CgroupError::new(
                ErrorCode::Unimplemented,
                step,
                "cgroup.kill is not available (Linux 5.14 or later is required)",
            ),
            other => sys_error(step, "cgroup.kill", other),
        })?;
        Ok(Self {
            procs_w: File::from(procs_w),
            kill_w: File::from(kill_w),
        })
    }

    /// テスト用: 通常のディレクトリ fd（`cgroup.procs` / `cgroup.kill` を置いたもの）から組み立てる。
    #[cfg(test)]
    pub(crate) fn from_dir_for_test(dir: OwnedFd) -> Result<Self, CgroupError> {
        Self::from_dir(dir)
    }

    /// `cgroup.kill` へ `1` を書き、この cgroup の全プロセス（子孫を含む）を `SIGKILL` する。冪等。
    pub(crate) fn kill(&self) -> Result<(), CgroupError> {
        write_kill(&self.kill_w)
    }

    /// 呼び出しプロセス（fork した子）自身をこの cgroup へ移す（`cgroup.procs` へ `0`）。
    ///
    /// 書き手の PID namespace に依存しない。失敗時は所属が変わっていないため、呼び出し側は実行せず終了する。
    pub(crate) fn join_self(&self) -> Result<(), CgroupError> {
        let mut w = &self.procs_w;
        w.write_all(b"0")
            .map_err(|e| io_error(CgroupStep::JoinContainer, "cgroup.procs", &e))
    }
}

/// [`remove_exec_child_cgroup_at`] の結果（将来拡張できる構造）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecChildRemoval {
    /// 停止して削除した。
    Removed,
    /// 既に存在しなかった（冪等。worker が作る前に失敗した場合など）。
    Absent,
}

/// コンテナ cgroup `container` 直下の `name` を `cgroup.kill` で停止して削除する（冪等）。
///
/// 制限の掛かっていない呼び出しプロセスが、記録から導いたコンテナ cgroup を開き直して呼ぶ。存在しなければ
/// `Absent`。`timeout` は空になるまでの待機の上限（REPAIR-5）。
pub(crate) fn remove_exec_child_cgroup_at(
    container: std::os::fd::BorrowedFd<'_>,
    name: &str,
    timeout: Duration,
) -> Result<ExecChildRemoval, CgroupError> {
    let step = CgroupStep::Cleanup;
    validate_exec_child_name(name)?;
    let entry = match open_cgroup_dir(step, container, name) {
        Ok(fd) => fd,
        Err(e) if e.code == ErrorCode::NotFound => return Ok(ExecChildRemoval::Absent),
        Err(e) => return Err(e),
    };
    require_owned_by_euid(step, entry.as_fd())?;
    kill_wait_remove(container, name, entry.as_fd(), timeout)
}

/// 開いて所有者確認まで済んだ `entry` を `cgroup.kill` で停止し、空になるまで `timeout` を上限に待って、
/// 同一性確認つきで削除する（[`remove_exec_child_cgroup_at`] と delete 前の掃除が共用する）。
fn kill_wait_remove(
    container: std::os::fd::BorrowedFd<'_>,
    name: &str,
    entry: std::os::fd::BorrowedFd<'_>,
    timeout: Duration,
) -> Result<ExecChildRemoval, CgroupError> {
    let step = CgroupStep::Cleanup;
    let kill = cstring(step, "cgroup.kill")?;
    let kill_w = sys::open_write_at(entry, &kill).map_err(|e| sys_error(step, "cgroup.kill", e))?;
    write_kill(&File::from(kill_w))?;
    wait_unpopulated(entry, timeout)?;
    match remove_verified_at(container, name, entry) {
        Ok(()) => Ok(ExecChildRemoval::Removed),
        Err(e) if e.code == ErrorCode::NotFound => Ok(ExecChildRemoval::Absent),
        Err(e) => Err(e),
    }
}

/// 掃除で読むディレクトリエントリ総数の上限（cgroup のインターフェースファイルも数えるため大きめ。REPAIR-5）。
pub(crate) const EXEC_SWEEP_SCAN_LIMIT: usize = 4096;

/// 1 回の掃除で処理する候補（検証を通った名前）数の上限（REPAIR-5）。
pub(crate) const EXEC_SWEEP_CANDIDATE_LIMIT: usize = 256;

/// delete 前の掃除全体で 1 つ持つ、`populated 0` を待つ期限（子ごとに積み重ねない。REPAIR-5）。
pub(crate) const EXEC_SWEEP_DELETE_TIMEOUT: Duration = Duration::from_secs(5);

/// 掃除の方式（時機ごとの対象の違いはモジュール doc）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SweepMode {
    /// delete 前: すべての `exec-*` を `cgroup.kill` で止めて消す。
    KillAll,
    /// exec 開始時: `cgroup.kill` を書かず、持ち主が居ない空の `exec-*` だけを消す。
    UnpopulatedOnly,
}

/// [`sweep_exec_children_at`] の結果（将来拡張できる構造）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ExecChildSweep {
    /// 削除した数。
    pub(crate) removed: usize,
    /// プロセスが居る・削除の直前に参加された等で残した数（`UnpopulatedOnly` のみ）。
    pub(crate) left_populated: usize,
    /// 名前の pid の持ち主が生きている、または判定できず残した数（`UnpopulatedOnly` のみ）。
    pub(crate) left_owner_alive: usize,
    /// 検証・停止・削除に失敗した数。
    pub(crate) failed: usize,
    /// 件数の上限で打ち切った。
    pub(crate) truncated: bool,
    /// 最初の失敗の `code`（`Timeout` が 1 件でもあればそれを優先）。
    pub(crate) first_error: Option<ErrorCode>,
}

impl ExecChildSweep {
    fn record(&mut self, e: &CgroupError) {
        self.failed += 1;
        if self.first_error.is_none() || e.code == ErrorCode::Timeout {
            self.first_error = Some(e.code);
        }
    }
}

/// `container` 直下の `exec-*` の名前を列挙する。戻り値の bool は上限で打ち切ったか。
///
/// 名前だけを使う（`file_type` には頼らない）。[`validate_exec_child_name`] を通る UTF-8 の名前だけを、
/// ソートして返す。
fn list_exec_child_names(
    container: std::os::fd::BorrowedFd<'_>,
) -> Result<(Vec<String>, bool), CgroupError> {
    let step = CgroupStep::Cleanup;
    let path = format!("/proc/thread-self/fd/{}", container.as_raw_fd());
    let entries =
        std::fs::read_dir(path).map_err(|e| io_error(step, "list container cgroup", &e))?;
    let mut names = Vec::new();
    let mut truncated = false;
    for (scanned, entry) in entries.enumerate() {
        if scanned >= EXEC_SWEEP_SCAN_LIMIT {
            truncated = true;
            break;
        }
        let entry = entry.map_err(|e| io_error(step, "list container cgroup", &e))?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if validate_exec_child_name(name).is_err() {
            continue;
        }
        if names.len() >= EXEC_SWEEP_CANDIDATE_LIMIT {
            truncated = true;
            break;
        }
        names.push(name.to_owned());
    }
    names.sort();
    Ok((names, truncated))
}

/// `exec-<pid>-<seq>` の厳密な形から pid を取り出す。形式外・`0`・`i32::MAX` 超は `None`。
fn owner_pid_of(name: &str) -> Option<u32> {
    let rest = name.strip_prefix("exec-")?;
    let (pid, seq) = rest.split_once('-')?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(pid) || !digits(seq) || seq.parse::<u64>().is_err() {
        return None;
    }
    let pid: u32 = pid.parse().ok()?;
    (pid != 0 && i32::try_from(pid).is_ok()).then_some(pid)
}

/// 子 cgroup の持ち主の状態。
enum OwnerState {
    /// 持ち主（または pid を再利用したプロセス）が居る。
    Alive,
    /// 持ち主は居ない（自プロセスの過去の残骸・形式外の名前を含む）。
    Gone,
    /// 判定できない（`pidfd_open` が使えない等）。安全側で触れない。
    Unknown,
}

fn owner_state(name: &str) -> OwnerState {
    let Some(pid) = owner_pid_of(name) else {
        return OwnerState::Gone;
    };
    // 呼び出しプロセスは単一スレッドの exec 専用プロセスで、並行する自分の exec は無い。自分の pid の
    // 子 cgroup は過去の残骸とみなす。
    if pid == std::process::id() {
        return OwnerState::Gone;
    }
    match sys::pidfd_open(pid) {
        Ok(_) => OwnerState::Alive,
        Err(sys::SysError::Os(errno)) if errno == sys::ESRCH => OwnerState::Gone,
        Err(_) => OwnerState::Unknown,
    }
}

/// `container` 直下の `exec-*` を `mode` に従って掃除する（契約はモジュール doc。#1596）。
///
/// 列挙に失敗したときだけ `Err`。個々の失敗は結果の `failed` / `first_error` に数えて次へ進む。`deadline` は
/// `KillAll` の待機の全体の期限（`UnpopulatedOnly` では使わない）。
pub(crate) fn sweep_exec_children_at(
    container: std::os::fd::BorrowedFd<'_>,
    mode: SweepMode,
    deadline: Instant,
) -> Result<ExecChildSweep, CgroupError> {
    let started = Instant::now();
    let result = sweep_exec_children_inner(container, mode, deadline);
    record_sweep(mode, &result, started.elapsed());
    result
}

/// 掃除の方式ごとの記録先の操作名（REPAIR-4）。`OpName` の許容文字だけで作る固定文字列。
fn sweep_op_names(mode: SweepMode) -> (&'static str, &'static str) {
    match mode {
        SweepMode::KillAll => (
            "exec_cgroup_sweep_kill_all",
            "exec_cgroup_sweep_kill_all_cut",
        ),
        SweepMode::UnpopulatedOnly => (
            "exec_cgroup_sweep_unpopulated",
            "exec_cgroup_sweep_unpopulated_cut",
        ),
    }
}

/// 掃除の成否とレイテンシを、プロセス共通の [`exec_cgroup_sweep_recorder`] へ記録する（全終了経路。
/// 列挙失敗の `Err`・個別の失敗・件数上限の打ち切りは失敗として数える。打ち切りは別名の操作にも数える）。
/// 記録の失敗（名前上限・カウンタ飽和）は掃除の結果に影響させない。
fn record_sweep(mode: SweepMode, result: &Result<ExecChildSweep, CgroupError>, elapsed: Duration) {
    let (name, cut_name) = sweep_op_names(mode);
    let recorder = exec_cgroup_sweep_recorder();
    let ok = matches!(result, Ok(v) if v.failed == 0 && !v.truncated);
    let outcome = if ok {
        OpOutcome::Success
    } else {
        OpOutcome::Failure
    };
    if let Ok(n) = OpName::new(name) {
        let _ = recorder.record(&n, outcome, elapsed);
    }
    if matches!(result, Ok(v) if v.truncated)
        && let Ok(n) = OpName::new(cut_name)
    {
        let _ = recorder.record(&n, OpOutcome::Failure, elapsed);
    }
}

/// exec 用の子 cgroup 掃除の観測記録器（REPAIR-4・#1596）。操作名は `exec_cgroup_sweep_kill_all`（delete 前）・
/// `exec_cgroup_sweep_unpopulated`（exec 開始時）と、件数上限で打ち切った回数を数える `*_cut`。
/// 集計は [`crate::observability::OpRecorder::export_json_lines`] で構造化出力できる。
/// delete 前の掃除は `ContainerCgroupRemover::remove` の戻り値に載せられないため、プロセス共通の
/// 記録器へ集約する（スレッドセーフ。長寿命の supervisor でもウィンドウ上限でメモリは増えない）。
pub fn exec_cgroup_sweep_recorder() -> &'static OpRecorder {
    static RECORDER: std::sync::OnceLock<OpRecorder> = std::sync::OnceLock::new();
    RECORDER.get_or_init(OpRecorder::new)
}

fn sweep_exec_children_inner(
    container: std::os::fd::BorrowedFd<'_>,
    mode: SweepMode,
    deadline: Instant,
) -> Result<ExecChildSweep, CgroupError> {
    let step = CgroupStep::Cleanup;
    let (names, truncated) = list_exec_child_names(container)?;
    let mut out = ExecChildSweep {
        truncated,
        ..ExecChildSweep::default()
    };
    for name in &names {
        let entry = match open_cgroup_dir(step, container, name) {
            Ok(fd) => fd,
            // 並行して削除された。
            Err(e) if e.code == ErrorCode::NotFound => continue,
            Err(e) => {
                out.record(&e);
                continue;
            }
        };
        if let Err(e) = require_owned_by_euid(step, entry.as_fd()) {
            out.record(&e);
            continue;
        }
        match mode {
            SweepMode::KillAll => {
                let left = deadline.saturating_duration_since(Instant::now());
                match kill_wait_remove(container, name, entry.as_fd(), left) {
                    Ok(ExecChildRemoval::Removed) => out.removed += 1,
                    Ok(ExecChildRemoval::Absent) => {}
                    Err(e) => out.record(&e),
                }
            }
            SweepMode::UnpopulatedOnly => sweep_one_unpopulated(container, name, &entry, &mut out),
        }
    }
    Ok(out)
}

/// `UnpopulatedOnly` の 1 件分。持ち主が居ない空の子 cgroup だけを消し、それ以外は残す。
fn sweep_one_unpopulated(
    container: std::os::fd::BorrowedFd<'_>,
    name: &str,
    entry: &OwnedFd,
    out: &mut ExecChildSweep,
) {
    let step = CgroupStep::Cleanup;
    if !matches!(owner_state(name), OwnerState::Gone) {
        out.left_owner_alive += 1;
        return;
    }
    let populated = read_iface(step, entry.as_fd(), "cgroup.events", EVENTS_LIMIT)
        .and_then(|text| parse_populated(&text));
    match populated {
        Ok(true) => out.left_populated += 1,
        Ok(false) => match remove_verified_at(container, name, entry.as_fd()) {
            Ok(()) => out.removed += 1,
            Err(e) if e.code == ErrorCode::NotFound => {}
            // 読んでから削除するまでの間に参加された（カーネルが EBUSY / ENOTEMPTY で拒否）。使用中として残す。
            Err(e) if e.code == ErrorCode::FailedPrecondition => out.left_populated += 1,
            Err(e) => out.record(&e),
        },
        Err(e) => out.record(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(label: &str) -> std::path::PathBuf {
        let p =
            std::env::temp_dir().join(format!("fandhe-execkill-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// SUP-6・TASK-163 追補: 子 cgroup 名は `exec-` 接頭辞と `[a-z0-9-]` だけを通す。
    #[test]
    fn sup6_exec_child_name_validation() {
        for ok in ["exec-1-2", "exec-12345-0"] {
            assert!(validate_exec_child_name(ok).is_ok(), "{ok}");
        }
        let long = format!("exec-{}", "1".repeat(NAME_MAX_LEN));
        for bad in [
            "",
            "exec-",
            "exec",
            "fc-c1@7",
            "exec-A",
            "exec-1/2",
            "exec-..",
            "exec-1\0",
            "exec_1",
            long.as_str(),
        ] {
            let err = validate_exec_child_name(bad).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "{bad:?}");
        }
    }

    /// SUP-6・TASK-163 追補: `populated` の解析は具体値で照合し、異常な応答は拒否する。
    #[test]
    fn sup6_parse_populated_concrete_values() {
        assert!(parse_populated("populated 1\nfrozen 0\n").unwrap());
        assert!(!parse_populated("populated 0\nfrozen 0\n").unwrap());
        assert!(!parse_populated("frozen 0\npopulated 0\n").unwrap());
        for bad in [
            "",
            "frozen 0\n",
            "populated 2\n",
            "populated\n",
            "populated x\n",
        ] {
            assert_eq!(
                parse_populated(bad).unwrap_err().code,
                ErrorCode::FailedPrecondition,
                "{bad:?}"
            );
        }
    }

    /// SUP-6・TASK-163 追補: `cgroup.kill` へ `1`、`cgroup.procs` へ `0` が書かれる。
    #[test]
    fn sup6_kill_and_join_write_expected_bytes() {
        let d = tmp("write");
        std::fs::write(d.join("cgroup.procs"), "").unwrap();
        std::fs::write(d.join("cgroup.kill"), "").unwrap();
        let fds =
            ExecChildCgroupFds::from_dir_for_test(OwnedFd::from(File::open(&d).unwrap())).unwrap();
        fds.join_self().unwrap();
        fds.kill().unwrap();
        assert_eq!(
            std::fs::read_to_string(d.join("cgroup.procs")).unwrap(),
            "0"
        );
        assert_eq!(std::fs::read_to_string(d.join("cgroup.kill")).unwrap(), "1");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// SUP-6・TASK-163 追補: `cgroup.kill` が無い（Linux 5.14 未満）構成は `Unimplemented` で拒否する（fail-closed）。
    #[test]
    fn sup6_missing_cgroup_kill_is_unimplemented() {
        let d = tmp("nokill");
        std::fs::write(d.join("cgroup.procs"), "").unwrap();
        let err = ExecChildCgroupFds::from_dir_for_test(OwnedFd::from(File::open(&d).unwrap()))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Unimplemented);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// SUP-6・#1596: 持ち主 pid の解析は `exec-<u32>-<u64>` の厳密な形だけを通す。
    #[test]
    fn sup6_owner_pid_of_parses_only_strict_form() {
        assert_eq!(owner_pid_of("exec-123-4"), Some(123));
        assert_eq!(owner_pid_of("exec-2147483647-0"), Some(2_147_483_647));
        for bad in [
            "exec-stale",
            "exec-0x1-2",
            "exec-123",
            "exec--1",
            "exec-1-",
            "exec-0-1",
            "exec-4294967296-0",
            "exec-2147483648-0",
            "fc-1-1",
        ] {
            assert_eq!(owner_pid_of(bad), None, "{bad}");
        }
    }

    /// 列挙の試験用に、検証を通る名前・通らない名前・symlink・通常ファイルを混在させる。
    fn mixed_dir(label: &str) -> std::path::PathBuf {
        let d = tmp(label);
        for dir in ["exec-1-1", "exec_1", "fc-x@1", "exec-..", "exec-A"] {
            std::fs::create_dir(d.join(dir)).unwrap();
        }
        std::fs::write(d.join("cgroup.procs"), "").unwrap();
        std::fs::write(d.join("exec-2-2"), "").unwrap();
        std::os::unix::fs::symlink(d.join("exec-1-1"), d.join("exec-3-3")).unwrap();
        d
    }

    /// SUP-6・#1596: 列挙は名前の検証を通ったものだけを返す（`exec-` で始まらない・不正文字は除く）。
    #[test]
    fn sup6_list_exec_child_names_returns_only_valid_names() {
        let d = mixed_dir("list");
        let fd = OwnedFd::from(File::open(&d).unwrap());
        let (names, truncated) = list_exec_child_names(fd.as_fd()).unwrap();
        assert_eq!(names, ["exec-1-1", "exec-2-2", "exec-3-3"]);
        assert!(!truncated);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// SUP-6・SEC-1・#1596: 名前の検証を通っても cgroup2 でない・symlink・通常ファイルには触れず、
    /// すべて残して失敗に数える（`KillAll` は他の entry も含めて何も消さない）。
    #[test]
    fn sup6_sweep_does_not_touch_non_cgroup_entries() {
        for mode in [SweepMode::KillAll, SweepMode::UnpopulatedOnly] {
            let d = mixed_dir("sweepmix");
            let fd = OwnedFd::from(File::open(&d).unwrap());
            let deadline = Instant::now() + Duration::from_millis(50);
            let out = sweep_exec_children_at(fd.as_fd(), mode, deadline).unwrap();
            assert_eq!(out.removed, 0, "{mode:?}");
            assert_eq!(out.failed, 3, "{mode:?}");
            assert!(out.first_error.is_some(), "{mode:?}");
            // REPAIR-4: 失敗した掃除が構造化記録に失敗として載る。
            let name = OpName::new(sweep_op_names(mode).0).unwrap();
            let stats = exec_cgroup_sweep_recorder().snapshot_op(&name).unwrap();
            assert!(stats.failure() >= 1, "{mode:?}");
            assert!(stats.latency().is_some(), "{mode:?}");
            for kept in [
                "exec-1-1",
                "exec_1",
                "fc-x@1",
                "exec-..",
                "exec-A",
                "cgroup.procs",
                "exec-2-2",
                "exec-3-3",
            ] {
                assert!(
                    d.join(kept).symlink_metadata().is_ok(),
                    "{kept} must remain ({mode:?})"
                );
            }
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// SUP-6・REPAIR-5・#1596: 候補が上限を超えたら上限件数までを返し、打ち切りを示す。
    #[test]
    fn sup6_list_exec_child_names_truncates_at_limit() {
        let d = tmp("trunc");
        for n in 0..=EXEC_SWEEP_CANDIDATE_LIMIT {
            std::fs::create_dir(d.join(format!("exec-{n}-0"))).unwrap();
        }
        let fd = OwnedFd::from(File::open(&d).unwrap());
        let (names, truncated) = list_exec_child_names(fd.as_fd()).unwrap();
        assert_eq!(names.len(), EXEC_SWEEP_CANDIDATE_LIMIT);
        assert!(truncated);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// SUP-6・TASK-163 追補: 存在しない子 cgroup の後始末は `Absent`（冪等）。cgroup2 でない場所の同名
    /// ディレクトリは cgroup2 検証で拒否し、消さない。
    #[test]
    fn sup6_remove_rejects_non_cgroup2_directory() {
        let d = tmp("remove");
        std::fs::create_dir(d.join("exec-1-1")).unwrap();
        let parent = OwnedFd::from(File::open(&d).unwrap());
        let err =
            remove_exec_child_cgroup_at(parent.as_fd(), "exec-1-1", Duration::from_millis(10))
                .unwrap_err();
        assert_eq!(err.step, CgroupStep::VerifyCgroup2);
        assert!(d.join("exec-1-1").exists());
        let absent =
            remove_exec_child_cgroup_at(parent.as_fd(), "exec-1-2", Duration::from_millis(10));
        assert_eq!(absent.unwrap(), ExecChildRemoval::Absent);
        let _ = std::fs::remove_dir_all(&d);
    }
}
