//! exec 対象プロセスを稼働中コンテナの cgroup へ参加させるための fd 操作（SUP-6・TASK-163.2・#501・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! 起動経路の [`super::CgroupJoin`] は `prepare` が返す `ContainerCgroup` から作るが、exec 経路は別プロセス
//! （exec 専用プロセス）で `state.json` の記録（cgroup 配置）しか持たない。このモジュールは、記録から core が
//! 組み立てた期待 cgroup 絶対パスを `/sys/fs/cgroup` から 1 要素ずつ `O_NOFOLLOW` で辿って開き
//! （[`open_cgroup_by_path`]）、`cgroup.procs` と自プロセスの所属確認用の fd を `setns` の **前** に
//! 確保しておき（[`ExecJoinFds::prepare`]）、参加時に書き込みと読み戻し検証を行う（[`ExecJoinFds::join`]）。
//! 呼び出し元は `exec::cgroup_join`（`prepare_cgroup_join` / `join_cgroup`）で、その上に supervisor の
//! `exec` モジュールが薄く載る。`unsafe` は持たず、syscall は `crate::sys` の既存ラッパー経由。
//!
//! # 契約
//!
//! - 開いたディレクトリは fd で固定し、以後のファイル操作はすべてその fd 相対（パスの再解決なし）。
//!   `openat(dirfd, ..)` と保持済み fd への read / write は mount namespace に依存しないため、`setns` の後でも
//!   成立する
//! - カーネル応答（`cgroup.procs`・`/proc/self/cgroup`）は上限付きで読み、`unwrap` / 添字アクセスは使わない。
//!   パス深さも `MAX_PATH_DEPTH` で上限検証する。待機を伴う処理はない（ファイル I/O のみ）
//! - 非 root では、開いたディレクトリの所有者が euid であることを確認する（他主体が作った同名の cgroup を
//!   採用しない。不一致は `PermissionDenied`）
//! - 参加は自プロセスの TGID（`cgroup.procs` はスレッドグループ全体を移す）を 1 回の `write_all` で書く。
//!   カーネルは書き手の PID namespace で解決する。`setns(CLONE_NEWPID)` は以後の子にだけ効き自分の PID
//!   namespace は変わらないため、参加は `setns` の前後どちらでも自分を指す
//! - 検証失敗時の自プロセスの所属は不定。巻き戻しはせず、呼び出し側（exec 専用プロセス）は続行せず終了する
//!   （fail-closed）
//!
//! # 前提
//!
//! cgroup v2 の移動は、移動元と移動先の共通祖先の `cgroup.procs` への書き込み権を要する。exec 専用プロセスは
//! 委譲スコープの内側で動くこと（外からは `EACCES` → `PermissionDenied`）。supervisor 本体から呼ぶと
//! supervisor 自身がコンテナ cgroup へ移るため、exec 専用プロセスからのみ呼ぶ。

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, OwnedFd};

use super::{
    CgroupError, CgroupStep, MAX_PATH_DEPTH, PROCS_LIMIT, SELF_CGROUP_LIMIT, cstring, io_error,
    open_cgroup_dir, open_cgroup_root, owner_uid, parse_procs, read_iface, sys_error,
    validate_component, verify_joined,
};
use crate::sys;
use crate::traits::ErrorCode;

/// `/` 区切りの cgroup 絶対パスを要素に分ける（`/a/b` → `["a", "b"]`）。
///
/// 相対パス・ルート・空 / `.` / `..` / NUL を含む要素・`MAX_PATH_DEPTH` 超の深さは `FailedPrecondition`。
/// 呼び出し側（`Pid1Target`）も形式検証済みだが、ここでも独立に検証する（多層防御）。
fn split_cgroup_path(step: CgroupStep, path: &str) -> Result<Vec<&str>, CgroupError> {
    let Some(rest) = path.strip_prefix('/') else {
        return Err(CgroupError::precondition(
            step,
            "cgroup path is not absolute",
        ));
    };
    if rest.is_empty() {
        return Err(CgroupError::precondition(
            step,
            "cgroup path must not be the root cgroup",
        ));
    }
    let comps: Vec<&str> = rest.split('/').collect();
    if comps.len() > MAX_PATH_DEPTH {
        return Err(CgroupError::precondition(
            step,
            "cgroup path is deeper than the supported maximum",
        ));
    }
    for comp in &comps {
        validate_component(step, comp)?;
    }
    Ok(comps)
}

/// cgroup 絶対パス（`/sys/fs/cgroup` 起点）を辿って O_PATH ディレクトリ fd を返す。
///
/// 各要素を `O_NOFOLLOW` で開いて cgroup2 を確認する（symlink・別 FS への誘導を拒否）。非 root は所有者が
/// euid であることを確認する。存在しなければ `NotFound`。
pub(crate) fn open_cgroup_by_path(path: &str) -> Result<OwnedFd, CgroupError> {
    let comps = split_cgroup_path(CgroupStep::OpenRoot, path)?;
    let mut cur = open_cgroup_root()?;
    for comp in comps {
        cur = open_cgroup_dir(CgroupStep::OpenRoot, cur.as_fd(), comp)?;
    }
    let euid = sys::effective_uid();
    if euid != 0 {
        let step = CgroupStep::CheckDelegation;
        let dup = cur
            .try_clone()
            .map_err(|e| io_error(step, "dup container cgroup", &e))?;
        if owner_uid(step, dup, "stat container cgroup")? != euid {
            return Err(CgroupError::new(
                ErrorCode::PermissionDenied,
                step,
                "container cgroup is not owned by the effective user",
            ));
        }
    }
    Ok(cur)
}

/// `dir` の `cgroup.procs` に `pid` が載っているか（呼び出し側の PID namespace での値）。
///
/// 開いた cgroup が検証済み pid1 のものであることの結び付けに使う（SEC-1）。
pub(crate) fn contains_pid(dir: &OwnedFd, pid: u32) -> Result<bool, CgroupError> {
    let step = CgroupStep::JoinContainer;
    let text = read_iface(step, dir.as_fd(), "cgroup.procs", PROCS_LIMIT)?;
    Ok(parse_procs(step, &text)?.contains(&pid))
}

/// `setns` の前に確保しておく、参加に必要な fd 一式。
///
/// すべて `O_CLOEXEC`。`execve` の前の `close_range` は #503 の責務。
pub(crate) struct ExecJoinFds {
    dir: OwnedFd,
    procs_w: OwnedFd,
    self_cgroup: File,
}

impl std::fmt::Debug for ExecJoinFds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecJoinFds").finish_non_exhaustive()
    }
}

impl ExecJoinFds {
    /// `dir`（[`open_cgroup_by_path`] の結果）から `cgroup.procs` の書き込み fd を開き、
    /// 参加後の所属確認用に `/proc/self/cgroup` も開いて保持する。
    ///
    /// `setns(CLONE_NEWNS)` の後は `/proc/self` がコンテナ側 procfs になり自プロセスを解決できないため、
    /// 参加前に fd を確保する。
    pub(crate) fn prepare(dir: OwnedFd) -> Result<Self, CgroupError> {
        let step = CgroupStep::JoinContainer;
        let self_cgroup = File::open("/proc/self/cgroup")
            .map_err(|e| io_error(step, "open /proc/self/cgroup", &e))?;
        Self::with_self_cgroup(dir, self_cgroup)
    }

    fn with_self_cgroup(dir: OwnedFd, self_cgroup: File) -> Result<Self, CgroupError> {
        let step = CgroupStep::JoinContainer;
        let procs = cstring(step, "cgroup.procs")?;
        let procs_w = sys::open_write_at(dir.as_fd(), &procs)
            .map_err(|e| sys_error(step, "cgroup.procs", e))?;
        Ok(Self {
            dir,
            procs_w,
            self_cgroup,
        })
    }

    /// 固定済みのコンテナ cgroup ディレクトリ fd（exec 用の子 cgroup の作成 `mkdirat` の起点。#1466）。
    pub(crate) fn dir(&self) -> std::os::fd::BorrowedFd<'_> {
        self.dir.as_fd()
    }

    /// テスト用: 通常のディレクトリ fd と任意の「自プロセスの cgroup」ファイルから組み立てる。
    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        dir: OwnedFd,
        self_cgroup: File,
    ) -> Result<Self, CgroupError> {
        Self::with_self_cgroup(dir, self_cgroup)
    }

    /// 自プロセスの TGID を `cgroup.procs` へ書き、`cgroup.procs` の読み戻しで自 PID の所属を確認し、
    /// 自 PID と自プロセスの cgroup 一覧（`/proc/self/cgroup` の内容）を返す。値を消費し二重参加を型で防ぐ。
    ///
    /// 返した内容が期待パスと完全一致することの照合は呼び出し側が行う（`exec::cgroup_join`）。
    pub(crate) fn join(self) -> Result<(u32, String), CgroupError> {
        let step = CgroupStep::JoinContainer;
        let pid = std::process::id();
        let Self {
            dir,
            procs_w,
            self_cgroup,
        } = self;
        // `File::from` の一時値は文末で drop され、書き込み fd はここで閉じる。
        File::from(procs_w)
            .write_all(pid.to_string().as_bytes())
            .map_err(|e| io_error(step, "cgroup.procs", &e))?;
        verify_joined(
            pid,
            &read_iface(step, dir.as_fd(), "cgroup.procs", PROCS_LIMIT)?,
        )?;
        let mut buf = Vec::new();
        self_cgroup
            .take(SELF_CGROUP_LIMIT + 1)
            .read_to_end(&mut buf)
            .map_err(|e| io_error(step, "read /proc/self/cgroup", &e))?;
        if buf.len() as u64 > SELF_CGROUP_LIMIT {
            return Err(CgroupError::precondition(
                step,
                "kernel response exceeds size limit",
            ));
        }
        let text = String::from_utf8(buf)
            .map_err(|_| CgroupError::precondition(step, "kernel response is not valid UTF-8"))?;
        Ok((pid, text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(label: &str) -> std::path::PathBuf {
        let p =
            std::env::temp_dir().join(format!("fandhe-execjoin-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn dir_fd(p: &std::path::Path) -> OwnedFd {
        OwnedFd::from(File::open(p).unwrap())
    }

    /// SUP-6・TASK-163.2: パス分解は絶対・非ルート・正規化済み・深さ上限内だけを通す。
    #[test]
    fn sup6_task163_2_split_cgroup_path() {
        let step = CgroupStep::OpenRoot;
        assert_eq!(
            split_cgroup_path(step, "/user.slice/x.scope/fc-c1@7").unwrap(),
            vec!["user.slice", "x.scope", "fc-c1@7"]
        );
        let deep = format!("/{}", vec!["a"; MAX_PATH_DEPTH + 1].join("/"));
        let ok_deep = format!("/{}", vec!["a"; MAX_PATH_DEPTH].join("/"));
        assert_eq!(
            split_cgroup_path(step, &ok_deep).unwrap().len(),
            MAX_PATH_DEPTH
        );
        for bad in [
            "",
            "/",
            "a/b",
            "/a//b",
            "/a/../b",
            "/a/./b",
            "/a/b/",
            "/a\0b",
            deep.as_str(),
        ] {
            let err = split_cgroup_path(step, bad).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "{bad:?}");
            assert_eq!(err.step, step);
        }
    }

    /// SUP-6・TASK-163.2: `cgroup.procs` へ自 PID を書いて読み戻し、自プロセスの cgroup 一覧を返す。
    #[test]
    fn sup6_task163_2_join_writes_own_pid_to_cgroup_procs() {
        let d = tmp("ok");
        std::fs::write(d.join("cgroup.procs"), "").unwrap();
        std::fs::write(d.join("self"), "0::/a/b\n").unwrap();
        let fds = ExecJoinFds::from_parts_for_test(dir_fd(&d), File::open(d.join("self")).unwrap())
            .unwrap();
        let (pid, text) = fds.join().unwrap();
        assert_eq!(pid, std::process::id());
        assert_eq!(text, "0::/a/b\n");
        assert_eq!(
            std::fs::read_to_string(d.join("cgroup.procs")).unwrap(),
            std::process::id().to_string()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// SUP-6・TASK-163.2: 読み戻しに自 PID が無い構成は成功扱いにしない（fail-closed）。
    #[test]
    fn sup6_task163_2_join_without_readback_is_failed_precondition() {
        let d = tmp("noreadback");
        std::fs::write(d.join("cgroup.procs"), "").unwrap();
        std::fs::write(d.join("self"), "0::/a\n").unwrap();
        let fds = ExecJoinFds::from_parts_for_test(dir_fd(&d), File::open(d.join("self")).unwrap())
            .unwrap();
        // 書き込み fd を開いた後に別 inode へ差し替える。書き込みは旧 inode に入り、読み戻しは新 inode を読む。
        std::fs::remove_file(d.join("cgroup.procs")).unwrap();
        std::fs::write(d.join("cgroup.procs"), "1\n").unwrap();
        let err = fds.join().unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.step, CgroupStep::JoinContainer);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// SUP-6・TASK-163.2: `cgroup.procs` が無いディレクトリは `NotFound`（段は `JoinContainer`）。
    #[test]
    fn sup6_task163_2_open_missing_procs_is_not_found() {
        let d = tmp("missing");
        let err =
            ExecJoinFds::from_parts_for_test(dir_fd(&d), File::open("/proc/self/cgroup").unwrap())
                .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert_eq!(err.step, CgroupStep::JoinContainer);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// SUP-6・SEC-1・TASK-163.2: `cgroup.procs` に対象 pid が載っているかを判定する。
    #[test]
    fn sup6_task163_2_contains_pid() {
        let d = tmp("contains");
        std::fs::write(d.join("cgroup.procs"), "5\n123\n").unwrap();
        let fd = dir_fd(&d);
        assert!(contains_pid(&fd, 123).unwrap());
        assert!(!contains_pid(&fd, 12).unwrap());
        std::fs::write(d.join("cgroup.procs"), "x\n").unwrap();
        assert_eq!(
            contains_pid(&fd, 1).unwrap_err().code,
            ErrorCode::FailedPrecondition
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
