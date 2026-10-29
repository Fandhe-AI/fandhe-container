//! 状態記録に残した委譲スコープを、検証つきで直接開いてコンテナ cgroup を消す経路（#2096・OCI-6・CORE-3）。
//!
//! # 役割と呼び出し元
//!
//! `oci_runtime::delete` は、記録された配置（`StateRecord::cgroup`）のスコープと、削除側の remover が
//! 検出したスコープ（[`super::DelegatedCgroup`]）が食い違うとき、従来は `FailedPrecondition` で拒否していた
//! （#1314 の決定 3-ii）。#2060 のオーナー決定（2026-10-16・案 B）でこれを変え、記録のスコープを fd 起点で
//! 開いて消せるようにした。本モジュールがその実体で、`DelegatedCgroup` の
//! `ContainerCgroupRemover::remove_recorded` が [`remove_recorded_with`] を呼ぶ（CLI の `delete` は
//! `DetectedCgroupRemover` 経由でここへ届く）。別プロセスからコンテナ cgroup が空かを確かめる #2011 も、
//! 検出スコープとの一致を条件にせず [`RecordedCgroupScope::open`] へ揃え、問い合わせ・停止の経路
//! ([`ensure_no_process_in_recorded`]。下の「別プロセスの残存の確認」) を同じ規則で提供する。
//!
//! # 契約（fail-closed）
//!
//! - 記録のスコープは `state.json` 由来の外部入力として扱う。`/sys/fs/cgroup` から 1 要素ずつ
//!   `O_NOFOLLOW`・O_PATH で開いて cgroup2 を確かめる（symlink・別 FS への誘導を拒否）。要素と深さは
//!   `CgroupScope` の検証とは独立にもう一度検証する（多層防御）。ID だけからパスを組み立てない
//! - 開いたスコープは、検出時と同じ規則（[`super::verify_delegated_scope`]）で委譲を検証する。euid が 0 でなければ
//!   ディレクトリ・`cgroup.procs`・`cgroup.subtree_control` の所有者が euid であること、`cgroup.type` が
//!   `domain` であること。euid 0 では所有者の検証を省く（検出と同じ。root の状態ルートは root 所有という前提）
//! - 消す対象は `fc-<id>@<instance>`（記録された instance から作る名前）だけ。コンテナ cgroup 自身の
//!   `cgroup.procs` が空でなければ何も kill せず `FailedPrecondition` を返す（共用する
//!   `remove_container_cgroup_with` の掃除が確かめる）。待機は `exec-*` の掃除の 5 秒上限だけ（REPAIR-5）
//! - スコープ（または途中の要素）が存在しなければ `Ok(None)`（呼び出し側で `NotPresent`）。他の失敗は
//!   すべてエラーで、何も kill・削除しない。`TraitError` の message は固定文言で、パス・errno を含めない
//!
//! # 別プロセスの残存の確認（#2011・CORE-2・SEC-1）
//!
//! `ProductionLauncher::confirm_no_process_recorded` が、台帳に無い ID（クラッシュした supervisor が起動した
//! 残存）を記録済みの配置から確かめるために呼ぶ。`oci_runtime::start::recover_interrupted_start` が取得済みの
//! レコードの配置を渡す。結果は [`RecordedCgroupOutcome`]:
//!
//! - スコープまたはコンテナ cgroup が無い → `AlreadyAbsent`。cgroup v2 ではプロセスや子 cgroup が居る
//!   cgroup は `rmdir` できないため、無いことはプロセスが居ないことを意味する（PID 1 の死で scope が回収された
//!   場合や、記録の後・mkdir の前に落ちた場合）。`NotFound` 以外の失敗は `Ok` にしない
//! - `cgroup.events` の `populated 0` → `WasEmpty`
//! - `populated 1` → `cgroup.kill` へ書いて期限内に `populated 0` を待つ → `Killed`。delete が空でなければ
//!   拒否する（利用者の停止操作が前提）のと違い、回復は起動権の所有ロックを取れた後（起動者が居ない）にだけ
//!   走り、pid が未記録のため stop・kill では止められない孤児を回収する。届くのは検証済みの
//!   `fc-<id>@<instance>`（子孫を含む）だけ
//!
//! 残余: 記録したパスと同じ cgroup 名前空間から見ていること、コンテナ内のプロセスが cgroup の外へ移った場合は
//! 検出できないこと（delete と同じ限界）。
//!
//! `unsafe` は持たず、syscall は既存の `crate::sys` のラッパー経由（新しい宣言なし）。

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use std::time::Instant;

use super::exec_kill::{EVENTS_LIMIT, parse_populated, wait_unpopulated, write_kill};
use super::{
    CgroupError, CgroupName, CgroupPath, CgroupStep, MAX_PATH_DEPTH, cstring, open_cgroup_dir,
    open_cgroup_root, open_child_with, read_iface, removal_error, remove_container_cgroup_with,
    sys_error, validate_component, verify_delegated_scope,
};
use crate::observability::OpRecorder;
use crate::oci_runtime::CgroupRemoval;
use crate::sys;
use crate::traits::{
    CgroupPlacement, CgroupScope, ContainerId, ErrorCode, StateRevision, TraitError,
};

/// 記録された配置のコンテナ cgroup について、プロセスが居ないことを確かめた結果（#2011・CORE-2）。
///
/// 真偽値にせず列挙型にして、観測（REPAIR-4）や将来の分岐に備える。いずれも「居ない状態に到達済み」を表す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordedCgroupOutcome {
    /// スコープまたはコンテナ cgroup が無い（空でない cgroup は消えないので、プロセスも居ない）。
    AlreadyAbsent,
    /// コンテナ cgroup は在り、`populated 0`（子孫を含めて空）だった。何も kill していない。
    WasEmpty,
    /// プロセスが居たため `cgroup.kill` で止め、期限内に `populated 0` を確かめた。
    Killed,
}

/// 子ディレクトリを開く関数（本番は [`open_cgroup_dir`]。テストだけが tmpfs 向けに差し替える）。
type OpenDir<'a> = &'a dyn Fn(CgroupStep, BorrowedFd<'_>, &str) -> Result<OwnedFd, CgroupError>;

/// 状態記録のスコープを検証つきで開いたハンドル（委譲スコープのディレクトリ fd）。
///
/// [`super::DelegatedCgroup`] と違い自プロセスの所属を表さないため、自プロセスの退避や controller の
/// 有効化は持たない。コンテナ cgroup の削除（[`Self::remove_container`]）だけを提供する。
#[derive(Debug)]
pub struct RecordedCgroupScope {
    path: CgroupPath,
    fd: OwnedFd,
}

impl RecordedCgroupScope {
    /// 記録されたスコープを検証つきで開く。スコープ（または途中の要素）が無ければ `Ok(None)`。
    ///
    /// 検証に失敗した場合（所有者・`cgroup.type`・symlink・別 FS・不正な要素）はエラーで、何にも触れない。
    pub fn open(scope: &CgroupScope) -> Result<Option<Self>, CgroupError> {
        open_with(
            scope.as_str(),
            sys::effective_uid(),
            &open_cgroup_root,
            &open_cgroup_dir,
        )
    }

    /// 開いたスコープのパス（`/sys/fs/cgroup` 起点。例 `/user.slice/x.scope`）。
    pub fn scope(&self) -> String {
        self.path.display()
    }

    /// このスコープ直下の `fc-<id>@<instance>` を、空であることを確かめてから削除する。
    ///
    /// `recorder` があれば残留 `exec-*` の掃除の件数を記録する（REPAIR-4）。コンテナ cgroup が無ければ
    /// [`CgroupRemoval::NotPresent`]。コンテナ cgroup にプロセスが居れば `FailedPrecondition`（何も止めない）。
    pub fn remove_container(
        &self,
        id: &ContainerId,
        instance: StateRevision,
        recorder: Option<&OpRecorder>,
    ) -> Result<CgroupRemoval, TraitError> {
        remove_container_cgroup_with(
            self.fd.as_fd(),
            id,
            instance,
            recorder,
            sys::effective_uid(),
            &open_cgroup_dir,
        )
    }
}

/// 記録された配置のコンテナ cgroup に、プロセスが居ないことを確かめる（居れば止める）。`deadline` まで待つ。
///
/// 本番の入口（`ensure_no_process_with` に実 `/sys/fs/cgroup` と euid を渡す）。#2011・CORE-2・SEC-1。
pub fn ensure_no_process_in_recorded(
    id: &ContainerId,
    placement: &CgroupPlacement,
    deadline: Instant,
) -> Result<RecordedCgroupOutcome, CgroupError> {
    ensure_no_process_with(
        id,
        placement,
        deadline,
        sys::effective_uid(),
        &open_cgroup_root,
        &open_cgroup_dir,
    )
}

/// [`ensure_no_process_in_recorded`] の本体。`euid`・`open_root`・`open_dir` はテストの継ぎ目。
///
/// 順序: スコープを検証つきで開く（無ければ `AlreadyAbsent`）→ `fc-<id>@<instance>` を所有者検証つきで開く
/// （無ければ `AlreadyAbsent`）→ `cgroup.events` を読む → 空なら `WasEmpty` → `cgroup.kill` に `1` を書き
/// `deadline` まで `populated 0` を待つ。`cgroup.kill` が無い（Linux 5.14 未満）ときは `Ok` にせず
/// `Unimplemented`。`deadline` を過ぎていれば kill の前に `Timeout`。待ちはすべて `deadline` で打ち切る（REPAIR-5）。
pub(super) fn ensure_no_process_with(
    id: &ContainerId,
    placement: &CgroupPlacement,
    deadline: Instant,
    euid: u32,
    open_root: &dyn Fn() -> Result<OwnedFd, CgroupError>,
    open_dir: OpenDir<'_>,
) -> Result<RecordedCgroupOutcome, CgroupError> {
    let step = CgroupStep::Cleanup;
    let Some(scope) = open_with(placement.scope().as_str(), euid, open_root, open_dir)? else {
        return Ok(RecordedCgroupOutcome::AlreadyAbsent);
    };
    // 名前を作れない（長さ超過）cgroup は存在し得ない（delete と同じ扱い）。
    let Ok(name) = CgroupName::for_instance(id, placement.instance()) else {
        return Ok(RecordedCgroupOutcome::AlreadyAbsent);
    };
    let Some(child) = open_child_with(scope.fd.as_fd(), &name, euid, open_dir)? else {
        return Ok(RecordedCgroupOutcome::AlreadyAbsent);
    };
    let events = match read_iface(step, child.fd.as_fd(), "cgroup.events", EVENTS_LIMIT) {
        Ok(text) => text,
        // 読む前にコンテナ cgroup が消えた（回収済み）。目的の状態。
        Err(e) if e.code == ErrorCode::NotFound => return Ok(RecordedCgroupOutcome::AlreadyAbsent),
        Err(e) => return Err(e),
    };
    if !parse_populated(&events)? {
        return Ok(RecordedCgroupOutcome::WasEmpty);
    }
    if deadline.saturating_duration_since(Instant::now()).is_zero() {
        return Err(CgroupError::new(
            ErrorCode::Timeout,
            step,
            "deadline passed before the recorded container cgroup could be killed",
        ));
    }
    let kill = cstring(step, "cgroup.kill")?;
    let kill_w = sys::open_write_at(child.fd.as_fd(), &kill).map_err(|e| match e {
        sys::SysError::Os(errno) if errno == sys::ENOENT => CgroupError::new(
            ErrorCode::Unimplemented,
            step,
            "cgroup.kill is not available (Linux 5.14 or later is required)",
        ),
        other => sys_error(step, "cgroup.kill", other),
    })?;
    write_kill(&std::fs::File::from(kill_w))?;
    let left = deadline.saturating_duration_since(Instant::now());
    match wait_unpopulated(child.fd.as_fd(), left) {
        Ok(()) => Ok(RecordedCgroupOutcome::Killed),
        // 待つ間にコンテナ cgroup ごと回収された。
        Err(e) if e.code == ErrorCode::NotFound => Ok(RecordedCgroupOutcome::Killed),
        Err(e) => Err(e),
    }
}

/// 記録された配置を開いて、その instance のコンテナ cgroup を消す（`remove_recorded` の本体）。
///
/// `open_root`・`open_dir`・`euid` はテストの継ぎ目。スコープが無ければ `NotPresent`。失敗は
/// [`removal_error`] で code だけを残した固定文言の `TraitError` にする（パス・errno を載せない）。
pub(super) fn remove_recorded_with(
    id: &ContainerId,
    placement: &CgroupPlacement,
    recorder: Option<&OpRecorder>,
    euid: u32,
    open_root: &dyn Fn() -> Result<OwnedFd, CgroupError>,
    open_dir: OpenDir<'_>,
) -> Result<CgroupRemoval, TraitError> {
    let scope =
        open_with(placement.scope().as_str(), euid, open_root, open_dir).map_err(removal_error)?;
    match scope {
        None => Ok(CgroupRemoval::NotPresent),
        Some(s) => remove_container_cgroup_with(
            s.fd.as_fd(),
            id,
            placement.instance(),
            recorder,
            euid,
            open_dir,
        ),
    }
}

/// `"/a/b"` 形式のスコープを要素に分けて独立に再検証する（ルートは空の要素列）。
fn split_scope(scope: &str) -> Result<CgroupPath, CgroupError> {
    let step = CgroupStep::OpenRoot;
    let Some(rest) = scope.strip_prefix('/') else {
        return Err(CgroupError::precondition(
            step,
            "cgroup scope is not absolute",
        ));
    };
    if rest.is_empty() {
        return Ok(CgroupPath {
            components: Vec::new(),
        });
    }
    let comps: Vec<&str> = rest.split('/').collect();
    if comps.len() > MAX_PATH_DEPTH {
        return Err(CgroupError::precondition(
            step,
            "cgroup scope is deeper than the supported maximum",
        ));
    }
    for comp in &comps {
        validate_component(step, comp)?;
    }
    Ok(CgroupPath {
        components: comps.into_iter().map(str::to_owned).collect(),
    })
}

/// [`RecordedCgroupScope::open`] の本体。
fn open_with(
    scope: &str,
    euid: u32,
    open_root: &dyn Fn() -> Result<OwnedFd, CgroupError>,
    open_dir: OpenDir<'_>,
) -> Result<Option<RecordedCgroupScope>, CgroupError> {
    let path = split_scope(scope)?;
    if path.is_root() && euid != 0 {
        return Err(CgroupError::new(
            ErrorCode::PermissionDenied,
            CgroupStep::CheckDelegation,
            "recorded cgroup scope is the root cgroup and the process is not root",
        ));
    }
    let mut cur = open_root()?;
    for comp in &path.components {
        cur = match open_dir(CgroupStep::OpenRoot, cur.as_fd(), comp) {
            Ok(fd) => fd,
            // スコープが回収済み（systemd による scope の削除等）。目的の状態（cgroup 無し）。
            Err(e) if e.code == ErrorCode::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
    }
    match verify_delegated_scope(&cur, path.is_root(), euid) {
        Ok(()) => Ok(Some(RecordedCgroupScope { path, fd: cur })),
        // 開いた後にスコープが消えた（fd は削除済みディレクトリを指す）。これも cgroup 無し。
        Err(e) if e.code == ErrorCode::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::super::cstring;
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn tmp(label: &str) -> (crate::scratch_root::ScratchDir, std::path::PathBuf) {
        // pid だけの名前を先に消さず、排他作成の `ScratchDir` の子を使う（#3434・REPAIR-12）。
        crate::test_support::scratch_child(&format!("fandhe-recscope-{label}"), "d")
    }

    /// 実 cgroup の代わりに tmpfs を `/sys/fs/cgroup` に見立てるルート。
    fn root_of(dir: &Path) -> impl Fn() -> Result<OwnedFd, CgroupError> + '_ {
        move || {
            let c = cstring(CgroupStep::OpenRoot, dir.to_str().expect("utf8 tmp path"))?;
            sys::open_dir_path_nofollow(None, &c)
                .map_err(|e| super::super::sys_error(CgroupStep::OpenRoot, "tmp root", e))
        }
    }

    /// cgroup2 の確認を省いた子ディレクトリ open（`O_NOFOLLOW`・O_PATH は本番と同じ）。
    fn open_plain(
        step: CgroupStep,
        dir: BorrowedFd<'_>,
        name: &str,
    ) -> Result<OwnedFd, CgroupError> {
        let c = cstring(step, name)?;
        sys::open_dir_path_nofollow(Some(dir), &c)
            .map_err(|e| super::super::sys_error(step, name, e))
    }

    /// 委譲済みスコープ `<root>/user.slice/x.scope` を作る（`cgroup.type` は `ty`）。
    fn make_scope(root: &Path, ty: &str) -> PathBuf {
        let scope = root.join("user.slice").join("x.scope");
        fs::create_dir_all(&scope).expect("mkdir scope");
        fs::write(scope.join("cgroup.procs"), "").expect("procs");
        fs::write(scope.join("cgroup.subtree_control"), "").expect("subtree");
        fs::write(scope.join("cgroup.type"), format!("{ty}\n")).expect("type");
        scope
    }

    const SCOPE: &str = "/user.slice/x.scope";

    fn real_euid() -> u32 {
        sys::effective_uid()
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).expect("id")
    }

    fn placement(scope: &str, instance: u64) -> CgroupPlacement {
        CgroupPlacement::new(
            CgroupScope::new(scope).expect("scope"),
            StateRevision::from_raw(instance),
        )
    }

    fn run(
        root: &Path,
        scope: &str,
        instance: u64,
        euid: u32,
    ) -> Result<CgroupRemoval, TraitError> {
        remove_recorded_with(
            &cid("c1"),
            &placement(scope, instance),
            None,
            euid,
            &root_of(root),
            &open_plain,
        )
    }

    /// OCI-6（#2096）: 記録したスコープの要素が無い場合は `NotPresent`（何も作らない）。
    #[test]
    fn oci6_recorded_scope_absent_is_not_present() {
        let (_scratch, root) = tmp("absent");
        assert_eq!(
            run(&root, SCOPE, 7, real_euid()).expect("absent"),
            CgroupRemoval::NotPresent
        );
        fs::create_dir(root.join("user.slice")).expect("mkdir");
        assert_eq!(
            run(&root, SCOPE, 7, real_euid()).expect("absent leaf"),
            CgroupRemoval::NotPresent
        );
        assert!(!root.join("user.slice").join("x.scope").exists());
    }

    /// SEC-1（#2096）: スコープの所有者が euid と違えば `PermissionDenied` で、何も触れない。
    #[test]
    fn sec1_recorded_scope_owner_mismatch_is_permission_denied() {
        let (_scratch, root) = tmp("owner");
        let scope = make_scope(&root, "domain");
        let ctr = scope.join("fc-c1@7");
        fs::create_dir(&ctr).expect("mkdir ctr");
        fs::create_dir(ctr.join("exec-1-2")).expect("mkdir exec");
        fs::write(ctr.join("exec-1-2").join("cgroup.kill"), "").expect("kill");
        let err = run(&root, SCOPE, 7, real_euid().wrapping_add(1)).expect_err("owner");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(ctr.join("exec-1-2").is_dir());
        assert_eq!(
            fs::read_to_string(ctr.join("exec-1-2").join("cgroup.kill")).expect("read"),
            ""
        );
    }

    /// CORE-3（#2096）: `cgroup.type` が `domain` でなければ `FailedPrecondition` で、何も削除しない。
    #[test]
    fn core3_recorded_scope_wrong_cgroup_type_is_failed_precondition() {
        let (_scratch, root) = tmp("type");
        let scope = make_scope(&root, "threaded");
        let ctr = scope.join("fc-c1@7");
        fs::create_dir(&ctr).expect("mkdir ctr");
        let err = run(&root, SCOPE, 7, real_euid()).expect_err("type");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert!(ctr.is_dir());
    }

    /// OCI-6（#2096）: 記録の instance と名前が違うコンテナ cgroup（`fc-c1@8`）には触れず `NotPresent`。
    #[test]
    fn oci6_recorded_scope_other_instance_is_untouched() {
        let (_scratch, root) = tmp("instance");
        let scope = make_scope(&root, "domain");
        let other = scope.join("fc-c1@8");
        fs::create_dir(&other).expect("mkdir other");
        assert_eq!(
            run(&root, SCOPE, 7, real_euid()).expect("other instance"),
            CgroupRemoval::NotPresent
        );
        assert!(other.is_dir());
    }

    /// OCI-6・CORE-2（#2096）: コンテナ cgroup の `cgroup.procs` が空でなければ `FailedPrecondition` で、
    /// `exec-*` の `cgroup.kill` にも書かず、ディレクトリも残す。
    #[test]
    fn oci6_recorded_scope_nonempty_container_is_refused() {
        let (_scratch, root) = tmp("nonempty");
        let scope = make_scope(&root, "domain");
        let ctr = scope.join("fc-c1@7");
        fs::create_dir(&ctr).expect("mkdir ctr");
        fs::write(ctr.join("cgroup.procs"), "4242\n").expect("procs");
        fs::create_dir(ctr.join("exec-1-2")).expect("mkdir exec");
        fs::write(ctr.join("exec-1-2").join("cgroup.kill"), "").expect("kill");
        let err = run(&root, SCOPE, 7, real_euid()).expect_err("nonempty");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            fs::read_to_string(ctr.join("exec-1-2").join("cgroup.kill")).expect("read"),
            ""
        );
        assert!(ctr.join("exec-1-2").is_dir());
    }

    /// SEC-1（#2096）: ルート cgroup の記録は非 root では `PermissionDenied`、不正な要素・過大な深さは
    /// `FailedPrecondition`（`CgroupScope` を経由せず直接渡して多層防御を確かめる）。
    #[test]
    fn sec1_recorded_scope_rejects_invalid_components_and_non_root_root() {
        let never = || -> Result<OwnedFd, CgroupError> { panic!("must not open the root") };
        let err = open_with("/", 1000, &never, &open_plain).expect_err("root");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        for bad in ["/a/../b", "/a//b", "/./a", "a/b", "/a\0b"] {
            let err = open_with(bad, 0, &never, &open_plain).expect_err(bad);
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "{bad:?}");
        }
        let deep = format!("/{}", vec!["d"; MAX_PATH_DEPTH + 1].join("/"));
        let err = open_with(&deep, 0, &never, &open_plain).expect_err("deep");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
    }

    /// ERR-2（#2096）: `TraitError` の message は固定文言で、tmp のパス・errno の文字列を含まない。
    #[test]
    fn oci6_recorded_scope_errors_hide_paths() {
        let (_scratch, root) = tmp("hide");
        make_scope(&root, "threaded");
        let err = run(&root, SCOPE, 7, real_euid()).expect_err("type");
        assert_eq!(
            err.message(),
            "container cgroup is not empty or changed; retry"
        );
        let root_text = root.to_string_lossy().into_owned();
        assert!(!err.message().contains(&root_text));
        let denied = run(&root, SCOPE, 7, real_euid().wrapping_add(1)).expect_err("owner");
        assert_eq!(
            denied.message(),
            "container cgroup is not owned by the effective user"
        );
    }

    // ---- #2011: 別プロセスの残存の確認（ensure_no_process_with） ----

    fn ensure(
        root: &Path,
        scope: &str,
        instance: u64,
        euid: u32,
        wait: std::time::Duration,
    ) -> Result<RecordedCgroupOutcome, CgroupError> {
        ensure_no_process_with(
            &cid("c1"),
            &placement(scope, instance),
            Instant::now() + wait,
            euid,
            &root_of(root),
            &open_plain,
        )
    }

    const SHORT: std::time::Duration = std::time::Duration::from_millis(50);

    /// 委譲スコープの下に `fc-c1@7` と `cgroup.events` を作る。
    fn make_container(root: &Path, events: &str) -> PathBuf {
        let scope = make_scope(root, "domain");
        let ctr = scope.join("fc-c1@7");
        fs::create_dir(&ctr).expect("mkdir ctr");
        fs::write(ctr.join("cgroup.events"), events).expect("events");
        ctr
    }

    /// CORE-2（#2011）: スコープが無い・コンテナ cgroup が無い・名前を作れない場合は `AlreadyAbsent`。
    #[test]
    fn core2_issue2011_absent_scope_or_container_is_already_absent() {
        let (_scratch, root) = tmp("ens-absent");
        assert_eq!(
            ensure(&root, SCOPE, 7, real_euid(), SHORT).expect("no scope"),
            RecordedCgroupOutcome::AlreadyAbsent
        );
        make_scope(&root, "domain");
        assert_eq!(
            ensure(&root, SCOPE, 7, real_euid(), SHORT).expect("no container"),
            RecordedCgroupOutcome::AlreadyAbsent
        );
    }

    /// CORE-2（#2011）: `populated 0` は `WasEmpty` で、`cgroup.kill` には書かない。
    #[test]
    fn core2_issue2011_unpopulated_is_was_empty_without_kill() {
        let (_scratch, root) = tmp("ens-empty");
        let ctr = make_container(&root, "populated 0\nfrozen 0\n");
        fs::write(ctr.join("cgroup.kill"), "").expect("kill");
        assert_eq!(
            ensure(&root, SCOPE, 7, real_euid(), SHORT).expect("empty"),
            RecordedCgroupOutcome::WasEmpty
        );
        assert_eq!(fs::read_to_string(ctr.join("cgroup.kill")).expect("r"), "");
    }

    /// CORE-2・SEC-1（#2011）: `populated 1` は `cgroup.kill` へ `1` を書き、`populated 0` を確かめて `Killed`。
    #[test]
    fn core2_issue2011_populated_is_killed_and_confirmed() {
        let (_scratch, root) = tmp("ens-kill");
        let ctr = make_container(&root, "populated 1\n");
        fs::write(ctr.join("cgroup.kill"), "").expect("kill");
        let events = ctr.join("cgroup.events");
        let flipper = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(30));
            // 原子的に差し替える（`fs::write` の truncate 中に読まれると空になり、本番では起きない失敗を招く）。
            let tmp = events.with_file_name("cgroup.events.tmp");
            fs::write(&tmp, "populated 0\n").expect("flip tmp");
            fs::rename(&tmp, &events).expect("flip rename");
        });
        let out = ensure(
            &root,
            SCOPE,
            7,
            real_euid(),
            std::time::Duration::from_secs(5),
        )
        .expect("killed");
        flipper.join().expect("join");
        assert_eq!(out, RecordedCgroupOutcome::Killed);
        assert_eq!(fs::read_to_string(ctr.join("cgroup.kill")).expect("r"), "1");
    }

    /// REPAIR-5・CORE-2（#2011）: kill 後も `populated 1` のままなら期限で `Timeout`（`Ok` にしない）。
    #[test]
    fn core2_issue2011_still_populated_after_kill_times_out() {
        let (_scratch, root) = tmp("ens-timeout");
        let ctr = make_container(&root, "populated 1\n");
        fs::write(ctr.join("cgroup.kill"), "").expect("kill");
        let err = ensure(&root, SCOPE, 7, real_euid(), SHORT).expect_err("timeout");
        assert_eq!(err.code, ErrorCode::Timeout);
    }

    /// CORE-2（#2011）: 期限切れで `populated 1` なら kill せずに `Timeout`。
    #[test]
    fn core2_issue2011_expired_deadline_does_not_kill() {
        let (_scratch, root) = tmp("ens-expired");
        let ctr = make_container(&root, "populated 1\n");
        fs::write(ctr.join("cgroup.kill"), "").expect("kill");
        let err =
            ensure(&root, SCOPE, 7, real_euid(), std::time::Duration::ZERO).expect_err("expired");
        assert_eq!(err.code, ErrorCode::Timeout);
        assert_eq!(fs::read_to_string(ctr.join("cgroup.kill")).expect("r"), "");
    }

    /// CORE-2（#2011）: `cgroup.kill` が無ければ `Ok` にせず `Unimplemented`。
    #[test]
    fn core2_issue2011_missing_cgroup_kill_is_unimplemented() {
        let (_scratch, root) = tmp("ens-nokill");
        make_container(&root, "populated 1\n");
        let err = ensure(&root, SCOPE, 7, real_euid(), SHORT).expect_err("no kill");
        assert_eq!(err.code, ErrorCode::Unimplemented);
    }

    /// SEC-1（#2011）: スコープの所有者不一致は `PermissionDenied`、`cgroup.events` の欠落・解析不能は `Ok` にしない。
    #[test]
    fn sec1_issue2011_unverifiable_states_are_errors() {
        let (_scratch, root) = tmp("ens-err");
        let ctr = make_container(&root, "populated 1\n");
        fs::write(ctr.join("cgroup.kill"), "").expect("kill");
        let err = ensure(&root, SCOPE, 7, real_euid().wrapping_add(1), SHORT).expect_err("owner");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(fs::read_to_string(ctr.join("cgroup.kill")).expect("r"), "");
        fs::write(ctr.join("cgroup.events"), "garbage\n").expect("events");
        let err = ensure(&root, SCOPE, 7, real_euid(), SHORT).expect_err("garbage");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        fs::remove_file(ctr.join("cgroup.events")).expect("rm");
        // 読む前に回収された cgroup（`cgroup.events` が ENOENT）は居ない状態。
        assert_eq!(
            ensure(&root, SCOPE, 7, real_euid(), SHORT).expect("gone"),
            RecordedCgroupOutcome::AlreadyAbsent
        );
    }
}
