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
//! # 未実装（REPAIR-3）
//!
//! user namespace 参加（対象が呼び出し側と別の user namespace にいれば `Pid1Target::open` が拒否する）。
//! 制限の再適用は `exec/reapply.rs`（#502・#503）、fork・`close_range`・`execveat` は `exec/exec_command.rs`
//! （#503）で実装済み。

use std::num::NonZeroU32;
use std::path::Path;

use super::setns::{Pid1Target, cgroup_path_matches, ensure_not_exited};
use super::{ExecError, IsolationStage, ViolationReason};
use crate::cgroups::{ExecJoinFds, contains_pid, open_cgroup_by_path};
use crate::traits::types::ErrorCode;

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
}
