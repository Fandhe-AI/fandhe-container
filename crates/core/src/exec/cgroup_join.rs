//! exec 対象プロセスの稼働中コンテナ cgroup への参加（SUP-6・TASK-163.2・#501・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! SUP-6 の exec は「pid1 の namespace へ `setns` → コンテナの cgroup へ join → seccomp / Landlock 再適用 →
//! コマンド実行」。本モジュールは cgroup join を担い、`fandhe-container-supervisor` の `exec`
//! （`prepare_cgroup_join` / `join_cgroup`）が薄く配線する。#503 の exec 専用プロセスと TASK-161
//! （healthcheck）が共用する想定。fd 操作の実体は `crate::cgroups::exec_join`（`unsafe` なし）。
//!
//! # 契約
//!
//! - 二段階 API: [`prepare_cgroup_join`] は **`join_namespaces` の前** に呼び、ホスト側の cgroup 関連 fd
//!   （`cgroup.procs` の書き込み fd・自プロセスの所属確認用の `/proc/self/cgroup`）を確保する。
//!   [`join_cgroup`] は準備の後ならいつでも呼べる（supervisor の `run_command` は `setns` の後・制限の再適用の前に呼ぶ）。
//!   参加は fd 相対で完結するため、`setns(CLONE_NEWNS)` の後でも成立する
//! - 公開入口は検証済みの [`Pid1Target`] だけを受ける。期待 cgroup パスは `Pid1Target::open` が記録の型
//!   （`ContainerId`・`CgroupPlacement`）から組み立てたものを使い、文字列で受ける入口は無い（SEC-1）
//! - **開いた cgroup と検証済み pid1 の結び付け（SEC-1）**: 開いたディレクトリの `cgroup.procs` に対象 pid が
//!   載っていることを必須にし、その読み取りの後に pidfd の未終了を確認する（読んだ内容が pidfd の指す
//!   プロセスのものである保証。`setns.rs` と同じ手順）。載っていなければ `exec_target_cgroup_mismatch` の
//!   違反記録つきで拒否する
//! - **参加後の確認**: `cgroup.procs` の読み戻しで自 PID を確認し、さらに保持した `/proc/self/cgroup` の
//!   cgroup v2 行が期待パスと **完全一致** することを確認する。どちらかが失敗したら成功を返さない
//! - 検証失敗時は自プロセスの所属が不定。呼び出し側（exec 専用プロセス）は続行せず終了する（fail-closed。
//!   巻き戻しはしない）
//! - 期待 cgroup パスはレポート・エラーメッセージに載せない（違反記録の対象は `ViolationSubject` の
//!   エスケープ・切り詰めを通す）
//! - 保持 fd はすべて `O_CLOEXEC`。参加で消費して閉じ、`execve` の前には子が `close_range` で fd 3 以上を
//!   閉じる（`exec/exec_command.rs`。#503）
//!
//! # 前提
//!
//! - cgroup v2 の移動は、移動元と移動先の共通祖先の `cgroup.procs` への書き込み権を要する。exec 専用
//!   プロセスは委譲スコープの内側（supervisor と同じ `<scope>/fc-runtime` 等）で動くこと。外から呼ぶと
//!   `EACCES` → `PermissionDenied`（fail-closed）
//! - 呼び出しは exec 専用プロセスからのみ。supervisor 本体から呼ぶと supervisor 自身がコンテナの cgroup へ
//!   移る（`cgroup.procs` はスレッドグループ全体を移す）
//! - 同一性照合の前提（コンテナ内から cgroupfs に書けないこと）は `setns.rs` のモジュール doc と同じ。
//!   cgroup namespace・cgroupfs マウントの導入時は見直す
//!
//! # exec 用の子 cgroup（#1466）
//!
//! コマンドだけをコンテナ cgroup 直下の子 cgroup（[`ExecChildCgroup`]。名前は [`ExecCgroupName`]）へ入れ、
//! `cgroup.kill` で子孫ごと止める。作成は [`ExecCgroupJoin::create_child_cgroup`]（固定済みのコンテナ cgroup の
//! fd 相対・`enter_namespaces` の前）、参加は `spawn_exec_command` の子、停止は [`ExecChildCgroup::kill_all`]、
//! 削除は制限の掛かっていない呼び出しプロセスが [`remove_exec_child_cgroup`] で名前から行う（冪等。再適用後の
//! worker は Landlock で `rmdir` できない）。期待パスは記録の型（`ContainerId`・`CgroupPlacement`）から導き、
//! 文字列で受ける入口は `exec-test-support` だけ。詳細は `crate::cgroups::exec_kill`。
//!
//! # 未実装（REPAIR-3）
//!
//! 残留した `exec-*` の掃除（呼び出しプロセスが `SIGKILL` された場合に残り得る。delete 前・次回 exec 開始時。
//! TASK-30.3・OCI-6・SUP-6）。user namespace 参加（対象が呼び出し側と別の user namespace にいれば `Pid1Target::open` が拒否する）。
//! 制限の再適用は `exec/reapply.rs`（#502・#503）、fork・`close_range`・`execveat` は `exec/exec_command.rs`
//! （#503）で実装済み。

use std::num::NonZeroU32;
use std::os::fd::AsFd as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::setns::{Pid1Target, cgroup_path_matches, container_cgroup_path_for, ensure_not_exited};
use super::{ExecError, IsolationStage, ViolationReason};
use crate::cgroups::{
    ExecChildCgroupFds, ExecChildRemoval, ExecJoinFds, contains_pid, open_cgroup_by_path,
    remove_exec_child_cgroup_at,
};
use crate::traits::types::ErrorCode;
use crate::traits::{CgroupPlacement, ContainerId};

/// [`prepare_cgroup_join`] が確保した参加用の fd 一式。[`join_cgroup`] が消費する。
pub struct ExecCgroupJoin {
    fds: ExecJoinFds,
    expected_cgroup_path: String,
    target_pid: NonZeroU32,
}

impl std::fmt::Debug for ExecCgroupJoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecCgroupJoin")
            .field("target_pid", &self.target_pid)
            .finish_non_exhaustive()
    }
}

/// [`join_cgroup`] の成功結果（将来拡張できる構造）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecCgroupJoinReport {
    /// コンテナの cgroup へ参加した自プロセスの pid（自分の PID namespace から見た値）。
    pub pid: NonZeroU32,
    /// 参加先を決めた検証済み pid1 の pid（呼び出し側の PID namespace から見た値）。
    pub target_pid: NonZeroU32,
}

/// 検証済みの対象 `target` のコンテナ cgroup を開き、参加に必要な fd を確保する。
///
/// `join_namespaces` の **前** に呼ぶ。開いた cgroup の `cgroup.procs` に対象 pid が載っていなければ
/// `FailedPrecondition`（違反記録 `exec_target_cgroup_mismatch`）。cgroup が無ければ `NotFound`、
/// 所有者が違えば `PermissionDenied`。いずれも段は `CgroupJoin`。契約全体はモジュール doc を参照。
pub fn prepare_cgroup_join(target: &Pid1Target) -> Result<ExecCgroupJoin, ExecError> {
    let expected = target.expected_cgroup_path();
    let dir = open_cgroup_by_path(expected).map_err(ExecError::from_cgroup)?;
    let listed = contains_pid(&dir, target.pid().get()).map_err(ExecError::from_cgroup)?;
    // 読み取りの結果が pidfd の指すプロセスのものであることを、未終了の確認で保証する。
    ensure_not_exited(target, "refusing to join its cgroup")
        .map_err(|e| e.at_stage(IsolationStage::CgroupJoin))?;
    if !listed {
        return Err(ExecError::from_violation_at(
            ViolationReason::ExecTargetCgroupMismatch,
            Some(Path::new(expected)),
            IsolationStage::CgroupJoin,
        ));
    }
    let fds = ExecJoinFds::prepare(dir).map_err(ExecError::from_cgroup)?;
    Ok(ExecCgroupJoin {
        fds,
        expected_cgroup_path: expected.to_owned(),
        target_pid: target.pid(),
    })
}

/// 自プロセスをコンテナの cgroup へ参加させ、所属を 2 系統（`cgroup.procs` の読み戻し・`/proc/self/cgroup`）
/// で確認する。値を消費し、二重参加・書き込み fd の残留を型で防ぐ。
///
/// 失敗時は自プロセスの所属が不定のため、呼び出し側は続行せず終了すること（fail-closed）。
pub fn join_cgroup(join: ExecCgroupJoin) -> Result<ExecCgroupJoinReport, ExecError> {
    let ExecCgroupJoin {
        fds,
        expected_cgroup_path,
        target_pid,
    } = join;
    let (pid, self_cgroup) = fds.join().map_err(ExecError::from_cgroup)?;
    if !cgroup_path_matches(&self_cgroup, &expected_cgroup_path) {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::CgroupJoin,
            "own cgroup does not match the container cgroup after the join",
        ));
    }
    let pid = NonZeroU32::new(pid).ok_or_else(|| {
        ExecError::new(
            ErrorCode::Internal,
            IsolationStage::CgroupJoin,
            "own pid is zero",
        )
    })?;
    Ok(ExecCgroupJoinReport { pid, target_pid })
}

/// exec 用の子 cgroup の名前（`exec-<呼び出し pid>-<連番>`。検証済みの 1 要素。#1466）。
///
/// 呼び出しプロセスが exec ごとに [`Self::unique`] で作り、worker（作成）と呼び出しプロセス（名前からの後始末）が
/// 同じ値で同じ cgroup を指す。一意性は `mkdirat` の `EEXIST` 失敗で担保する（既存の同名は採用しない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecCgroupName(String);

impl ExecCgroupName {
    /// 呼び出しプロセスの pid とプロセス内の連番から、一意な名前を作る。
    pub fn unique() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let seq = NEXT.fetch_add(1, Ordering::Relaxed);
        Self(format!("exec-{}-{seq}", std::process::id()))
    }

    /// 検証して名前にする（`exec-` 接頭辞・`[a-z0-9-]`・長さ上限）。不正は `InvalidArgument`。
    pub fn new(name: &str) -> Result<Self, ExecError> {
        crate::cgroups::validate_exec_child_name(name).map_err(|_| {
            ExecError::new(
                ErrorCode::InvalidArgument,
                IsolationStage::CgroupJoin,
                "exec child cgroup name is not valid",
            )
        })?;
        Ok(Self(name.to_owned()))
    }

    /// 名前（cgroup ディレクトリの 1 要素）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// exec のコマンドだけを入れる子 cgroup（コンテナ cgroup 直下の `exec-<nonce>`）の書き込み fd 一式。
///
/// [`ExecCgroupJoin::create_child_cgroup`] が `enter_namespaces` と制限の再適用の **前** に作る。
/// [`spawn_exec_command`](super::spawn_exec_command) は参照で受け取り、fork した子が `execve` の前に自分をここへ移す。
/// 停止は [`Self::kill_all`]（`cgroup.kill`。制限の再適用後も保持 fd への write で成立する）。**削除は行わない**:
/// 再適用後の worker は Landlock で `rmdir` できないため、制限の掛かっていない呼び出しプロセスが
/// [`remove_exec_child_cgroup`] で名前から行う。
#[derive(Debug)]
pub struct ExecChildCgroup {
    fds: ExecChildCgroupFds,
}

impl ExecChildCgroup {
    /// 記録（`id`・`placement`）から導いたコンテナ cgroup の直下に子 cgroup `name` を **呼び出しプロセスで** 作る
    /// （worker を fork する前。#1466）。
    ///
    /// 作成に成功した呼び出し側だけがこの cgroup の所有者で、後始末（[`remove_exec_child_cgroup`]）の対象にしてよい。
    /// 同名が既に存在すれば `mkdirat` が失敗して `Err` になる（既存は採用しない）ため、失敗時は後始末を呼んではならない
    /// （他者・残骸の同名 cgroup を止めない）。fd は fork で worker へ継承される。
    pub fn create(
        id: &ContainerId,
        placement: &CgroupPlacement,
        name: &ExecCgroupName,
    ) -> Result<Self, ExecError> {
        let path = container_cgroup_path_for(id, placement)?;
        let dir = open_cgroup_by_path(&path).map_err(ExecError::from_cgroup)?;
        let fds = ExecChildCgroupFds::create(dir.as_fd(), name.as_str())
            .map_err(ExecError::from_cgroup)?;
        Ok(Self { fds })
    }

    /// この cgroup の全プロセス（コマンドの子孫を含む）を `cgroup.kill` で `SIGKILL` する。冪等。
    pub fn kill_all(&self) -> Result<(), ExecError> {
        self.fds.kill().map_err(ExecError::from_cgroup)
    }

    /// 呼び出しプロセス（fork した子）自身をこの cgroup へ移す。`spawn_exec_command` の子から呼ぶ。
    pub(super) fn join_self(&self) -> Result<(), ExecError> {
        self.fds.join_self().map_err(ExecError::from_cgroup)
    }

    /// 実機結合試験専用の入口: コンテナ cgroup の絶対パスを文字列で受けて子 cgroup を作る（`exec-test-support`。
    /// [`ExecCgroupJoin::create_child_cgroup`] と同じ作成）。期待値を記録から導かないため本番経路には使わない。
    #[cfg(feature = "exec-test-support")]
    pub fn create_in_path_for_test(
        container_cgroup_path: &str,
        name: &ExecCgroupName,
    ) -> Result<Self, ExecError> {
        let dir = open_cgroup_by_path(container_cgroup_path).map_err(ExecError::from_cgroup)?;
        let fds = ExecChildCgroupFds::create(dir.as_fd(), name.as_str())
            .map_err(ExecError::from_cgroup)?;
        Ok(Self { fds })
    }

    /// テスト用: `cgroup.procs` と `cgroup.kill` を置いた通常のディレクトリから組み立てる。
    #[cfg(test)]
    pub(super) fn from_dir_for_test(dir: std::os::fd::OwnedFd) -> Self {
        Self {
            fds: ExecChildCgroupFds::from_dir_for_test(dir).unwrap(),
        }
    }
}

impl ExecCgroupJoin {
    /// コンテナ cgroup の直下に exec 用の子 cgroup `name` を作る（コマンドだけを入れる。#1466）。
    ///
    /// `enter_namespaces` の **前**（[`prepare_cgroup_join`] の後）に呼ぶ。固定済みのコンテナ cgroup の fd 相対で
    /// 作り、`cgroup.kill` が使えない（Linux 5.14 未満）場合は `Unimplemented` で拒否する（fail-closed）。
    pub fn create_child_cgroup(&self, name: &ExecCgroupName) -> Result<ExecChildCgroup, ExecError> {
        let fds = ExecChildCgroupFds::create(self.fds.dir(), name.as_str())
            .map_err(ExecError::from_cgroup)?;
        Ok(ExecChildCgroup { fds })
    }
}

/// [`remove_exec_child_cgroup`] の結果（将来拡張できる構造）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExecCgroupRemoval {
    /// 子孫ごと停止して削除した。
    Removed,
    /// 既に存在しなかった（冪等）。
    Absent,
}

impl From<ExecChildRemoval> for ExecCgroupRemoval {
    fn from(value: ExecChildRemoval) -> Self {
        match value {
            ExecChildRemoval::Removed => Self::Removed,
            ExecChildRemoval::Absent => Self::Absent,
        }
    }
}

/// 記録（`id`・`placement`）から導いたコンテナ cgroup の直下の `name` を、`cgroup.kill` で子孫ごと停止して削除する。
///
/// 制限の掛かっていない呼び出しプロセスが、worker の終了後（正常・期限切れ・異常終了のいずれも）に必ず呼ぶ。
/// 冪等で、存在しなければ [`ExecCgroupRemoval::Absent`]。`timeout` は空になるまでの待機の上限（REPAIR-5。
/// 超過は `Timeout`）。期待パスは記録の型から core が導き、文字列で受ける入口は無い（SEC-1）。
pub fn remove_exec_child_cgroup(
    id: &ContainerId,
    placement: &CgroupPlacement,
    name: &ExecCgroupName,
    timeout: Duration,
) -> Result<ExecCgroupRemoval, ExecError> {
    remove_at_path(&container_cgroup_path_for(id, placement)?, name, timeout)
}

/// 実機結合試験専用の入口: コンテナ cgroup の絶対パスを文字列で受ける（`exec-test-support`。
/// [`remove_exec_child_cgroup`] と同じ後始末）。
#[cfg(feature = "exec-test-support")]
pub fn remove_exec_child_cgroup_in(
    container_cgroup_path: &str,
    name: &ExecCgroupName,
    timeout: Duration,
) -> Result<ExecCgroupRemoval, ExecError> {
    remove_at_path(container_cgroup_path, name, timeout)
}

fn remove_at_path(
    container_cgroup_path: &str,
    name: &ExecCgroupName,
    timeout: Duration,
) -> Result<ExecCgroupRemoval, ExecError> {
    let dir = match open_cgroup_by_path(container_cgroup_path) {
        Ok(dir) => dir,
        // コンテナ cgroup 自体が既に無い（実行中にコンテナが停止した等）なら、配下の子 cgroup も残っていない。
        // 後始末の対象が無いので冪等に `Absent` とし、コマンドの結果をエラーで上書きしない（#1466）。
        Err(e) if e.code == ErrorCode::NotFound => return Ok(ExecCgroupRemoval::Absent),
        Err(e) => return Err(ExecError::from_cgroup(e)),
    };
    remove_exec_child_cgroup_at(dir.as_fd(), name.as_str(), timeout)
        .map(ExecCgroupRemoval::from)
        .map_err(ExecError::from_cgroup)
}

#[cfg(test)]
impl ExecCgroupJoin {
    /// テスト用: 通常のディレクトリ fd と任意の「自プロセスの cgroup」ファイルから組み立てる
    /// （`CgroupJoin::from_dir_for_test` と同じ位置づけ。公開 API・feature は増やさない）。
    fn from_parts_for_test(
        dir: std::os::fd::OwnedFd,
        self_cgroup: std::fs::File,
        expected_cgroup_path: &str,
    ) -> Self {
        Self {
            fds: ExecJoinFds::from_parts_for_test(dir, self_cgroup).unwrap(),
            expected_cgroup_path: expected_cgroup_path.to_owned(),
            target_pid: NonZeroU32::new(1).unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::fd::OwnedFd;

    fn tmp(label: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("fandhe-execcg-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn join_with(d: &Path, self_cgroup: &str, expected: &str) -> ExecCgroupJoin {
        std::fs::write(d.join("cgroup.procs"), "").unwrap();
        std::fs::write(d.join("self"), self_cgroup).unwrap();
        ExecCgroupJoin::from_parts_for_test(
            OwnedFd::from(File::open(d).unwrap()),
            File::open(d.join("self")).unwrap(),
            expected,
        )
    }

    /// SUP-6・TASK-163.2: `cgroup.procs` へ自 PID が書かれ、自プロセスの cgroup が期待パスと一致すれば成功する。
    #[test]
    fn sup6_task163_2_join_writes_own_pid_to_cgroup_procs() {
        let d = tmp("ok");
        let j = join_with(&d, "0::/s/fc-c1@7\n", "/s/fc-c1@7");
        let report = join_cgroup(j).unwrap();
        assert_eq!(report.pid.get(), std::process::id());
        assert_eq!(report.target_pid.get(), 1);
        assert_eq!(
            std::fs::read_to_string(d.join("cgroup.procs")).unwrap(),
            std::process::id().to_string()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// SUP-6・SEC-1・TASK-163.2: 参加後の自プロセスの cgroup が期待と違えば（別・配下・v1・改行なし・複数行）
    /// 成功を返さない。メッセージに期待パスは載せない。
    #[test]
    fn sup6_task163_2_join_rejects_self_cgroup_mismatch() {
        for (i, own) in [
            "0::/s/fc-c2@7\n",
            "0::/s/fc-c1@7/nested\n",
            "1:name=x:/s/fc-c1@7\n",
            "0::/s/fc-c1@7",
            "0::/a\n0::/s/fc-c1@7\n",
        ]
        .iter()
        .enumerate()
        {
            let d = tmp(&format!("mismatch{i}"));
            let err = join_cgroup(join_with(&d, own, "/s/fc-c1@7")).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "{own:?}");
            assert_eq!(err.stage, IsolationStage::CgroupJoin);
            assert_eq!(
                err.message,
                "own cgroup does not match the container cgroup after the join"
            );
            assert!(err.violation.is_none());
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// SUP-6・TASK-163.2: 準備の入口は検証済みの `Pid1Target` を要する。自プロセスは入れ子の PID 1 でない
    /// ため `Pid1Target` が作れず、cgroup には触れない（型による守り）。
    #[test]
    fn sup6_task163_2_prepare_requires_verified_target() {
        let id = crate::traits::ContainerId::new("c1").unwrap();
        let placement = crate::traits::CgroupPlacement::new(
            crate::traits::CgroupScope::new("/s").unwrap(),
            crate::traits::StateRevision::from_raw(1),
        );
        let me = NonZeroU32::new(std::process::id()).unwrap();
        let err = Pid1Target::open(me, &id, &placement).unwrap_err();
        assert_eq!(err.stage, IsolationStage::SetNs);
    }

    /// SUP-6・TASK-163 追補・#1466: コンテナ cgroup 自体が既に無い場合の後始末は `Absent`（エラーにしない）。
    #[test]
    fn sup6_task163_remove_with_missing_container_cgroup_is_absent() {
        let name = ExecCgroupName::unique();
        let out = remove_at_path(
            "/fandhe-nonexistent-container-cgroup-1466",
            &name,
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(out, ExecCgroupRemoval::Absent);
    }
}
