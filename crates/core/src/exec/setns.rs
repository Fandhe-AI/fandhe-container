//! 稼働中コンテナの pid1 の特定と、その namespace への `setns(2)` 参加（SUP-6・TASK-163.1・#500・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! `fandhe-container-supervisor` の `exec` モジュール（`identify_pid1` / `enter_namespaces`）が、
//! `state.json` の記録 pid を **候補** として、記録のコンテナ ID・cgroup 配置とともに [`Pid1Target::open`] へ
//! 渡し、検証を通った対象に対して [`join_namespaces`] を呼ぶ。`unsafe` はここへは置かず、
//! `crate::sys::setns_pidfd` に閉じ込める。
//!
//! # 契約
//!
//! - **公開する入口**: 既定のビルドで公開するのは、記録の型（`ContainerId`・`CgroupPlacement`）から期待
//!   cgroup パスを core 側で組み立てる [`Pid1Target::open`] と、SUP-6 の 5 種へ固定で参加する
//!   [`join_namespaces`] だけである。期待 cgroup パスを文字列で受ける入口
//!   （`Pid1Target::open_with_cgroup_path`）は `exec-test-support` feature を付けたビルドにだけ存在し
//!   （実機結合試験用）、参加する namespace の部分集合を呼び出し側が選ぶ入口は持たない
//! - **対象の固定（TOCTOU）**: pidfd を **先に** 開いてから `/proc/<pid>` を検証し、読み取りをすべて終えた後に
//!   pidfd の未終了を確認する。未終了なら pid は再利用されていないので、読んだ内容は pidfd の指すプロセスの
//!   ものである。検証後・参加前に対象が終了しても、pidfd は元のプロセスを指し続けるため、再利用された
//!   別プロセスの namespace へは入らない（SEC-1）。[`join_namespaces`] は `setns` の直前にも終了状態と所属
//!   cgroup を再確認し、終了済み・別 cgroup へ移動済みなら拒否する（カーネルが終了済みの対象を `ESRCH` で
//!   拒否する挙動には依存しない。fail-closed）。再確認から `setns` までの窓（syscall 数回分）は残るが、
//!   その間も pidfd の指すプロセスは変わらない
//! - **記録したコンテナとの同一性**: pidfd は「呼び出した時点でその pid にいたプロセス」を固定するだけで、
//!   `state.json` に記録された元のコンテナのプロセスであることまでは証明しない（元のコンテナが終了し、
//!   その pid が別コンテナの PID 1 に再利用されると、NSpid や namespace 差異の検査は通ってしまう）。そこで
//!   期待 cgroup パス（`<委譲スコープ>/fc-<id>@<instance>`。instance はストア全体で再利用されず、コンテナごとに
//!   一意。OCI-6）と、対象の `/proc/<pid>/cgroup` の cgroup v2 行のパスが **全体で完全一致** することを必須に
//!   する。別コンテナの cgroup とは一致しないため、再利用された別コンテナの PID 1 は拒否される（SEC-1）。
//!   パス要素のどこかに名前が現れるだけ・末尾要素が同名なだけでは認めない（別の場所にある同名の cgroup を
//!   取り違えない）。読み取りが上限に達した場合と、改行で終わらない内容（途中で切れた行）は不一致として
//!   拒否する。照合は文字列で行うため、記録した側と同じ cgroup 名前空間から読むことが前提で、食い違えば
//!   不一致として拒否する（`CgroupScope` と同じ前提）
//! - **同一性照合の前提（変更時は見直すこと）**: この照合は「コンテナの中から cgroupfs に書けない」ことに
//!   依存している。rootless ではコンテナ内 root が委譲スコープの所有者と同じ euid に写るため、コンテナから
//!   cgroupfs に書ける構成では、コンテナ内のプロセスが兄弟の `fc-*` cgroup の `cgroup.procs` へ自分を移し、
//!   別コンテナの期待パスに一致させ得る。現在これが成り立たないのは、cgroupfs / sysfs をコンテナへマウント
//!   しておらず、cgroup namespace も導入していないからである。cgroupfs のマウント・`CLONE_NEWCGROUP`・
//!   `/sys/fs/cgroup` の bind mount を導入する変更では、本照合を必ず見直すこと。恒久策は、supervisor が
//!   コンテナの起動時から pidfd を保持し、exec 専用プロセスへ継承または `SCM_RIGHTS` で渡す方式で、本実装の
//!   対象外（未実装）
//! - **対象の限定**: 対象は、呼び出し側の PID namespace に **直接** 入れ子になった PID namespace の PID 1
//!   （`NSpid:` がちょうど 2 要素で末尾が 1）に限り、呼び出し側と同じ pid / mnt namespace へは参加しない。
//!   任意プロセスの namespace へ入る汎用手段にしない。入れ子の PID namespace の取り違え（コンテナの中で
//!   さらに作られた PID namespace の PID 1 を pid1 とみなすこと）は、この `NSpid` の深さの検査と、PID
//!   namespace の終了処理（コンテナの init が終了すると配下のプロセスは入れ子の namespace を含めて回収される
//!   ため、記録 pid が再利用される時点でコンテナ内のプロセスは残っていない）で防いでいる。`NSpid` は
//!   読み取りに使う procfs が属する PID namespace を起点に並ぶので、supervisor 自身が入れ子の PID namespace
//!   で動く構成（自分の `/proc` をマウントしている場合）でも、コンテナの pid1 はちょうど 2 要素になる
//! - **参加の性質**: 参加は **不可逆** で、呼び出しスレッドに作用する。単一スレッドのプロセスからのみ呼べる
//!   （`CLONE_NEWNS` はスレッドが複数あると拒否され、他 namespace もスレッドごとに食い違うため fail-closed で
//!   拒否する）。呼び出すのは exec 専用の単一スレッドプロセスで、logs 捕捉スレッドを持つ supervisor 本体から
//!   直接呼ばない（#503）。pid namespace への参加は **以後に fork した子** にだけ効く（2 段目の fork は #503）
//! - **参加後の root と cwd**: `setns(CLONE_NEWNS)` は呼び出しプロセスの root と cwd を、参加先 mount namespace の
//!   ルート（`mnt_ns->root` に積まれた最上位のマウント）へ付け替える（カーネルの `mntns_install`。pidfd で複数
//!   namespace を一括指定した場合も `commit_nsset` が同じ結果を反映する）。これは対象（pid1）自身の root では
//!   なく、両者が一致するのは launcher が `pivot_root` 済みで、以後 `/` にマウントが重ねられていない場合に
//!   限る。本関数はこの一致を検証しない。参加後の `/` が記録したコンテナの rootfs であることの照合は、制限の
//!   再適用（`exec/reapply.rs`。#502）が何も適用する前に行い、不一致なら拒否する
//! - **違反記録（SEC-4）**: 対象が分離の前提を満たさない拒否（入れ子の PID 1 でない・cgroup 不一致・呼び出し側と
//!   同じ pid / mnt namespace）には `IsolationViolation`（種別 `exec_target`）を付ける。cgroup 不一致の対象
//!   には期待 cgroup パスを、既存のエスケープ・切り詰め（`ViolationSubject`）を通して載せる。対象の終了・
//!   `/proc` の読み取り失敗・syscall 失敗・呼び出し側がマルチスレッドであることはシステムエラー / 呼び出し
//!   文脈の誤りで、違反記録を付けない
//!
//! # 後続（#502〜#503）への必須前提
//!
//! - 順序: ホスト側 fd の確保（cgroup.procs。#501・実装済みの `exec::cgroup_join`）は [`join_namespaces`] の **前**、seccomp / Landlock の
//!   再適用（#502）は **後**（`setns` は seccomp の禁止 syscall に含まれ、適用後は参加できない）
//! - `setns` は uid / gid・capability・補助グループ・`no_new_privs` を **変えない**。rootful では参加後も
//!   全 capability を持つホスト root のままである。`execve` の前に capability 削減と `no_new_privs` の設定が
//!   必要（#502・SEC-1）
//! - 継承した fd は参加後も開いたままである。ホスト側の fd（cgroup.procs・state・ログ等）をコンテナ内の
//!   プロセスへ渡さないよう、`execve` の前に閉じる必要がある（#503。`close_range`）
//!
//! # 未実装（REPAIR-3）
//!
//! - user namespace への参加。本実装は `User` を型に持たず拒否する（SUP-6 の列挙は pid / mnt / uts / ipc /
//!   net）。このため **既定の rootless（コンテナが user namespace を持つ）では、exec 専用プロセスが対象の
//!   user namespace 内の `CAP_SYS_ADMIN` を持たず、`setns` が `EPERM` で失敗する**（fail-closed）。rootless で
//!   exec を成立させるには user namespace への参加が必須で、未実装。実機結合試験（`exec_setns_join`）の
//!   成功は、`nsenter --user` で先に対象の user namespace へ入れた構成でのものである
//! - 違反記録の監査ログ（SEC-4）への保存。`ExecError::violation` に載せて返すところまでで、sink への記録の
//!   配線は TASK-41.5 系（#839）と呼び出し側（#503）で扱う
//! - supervisor が起動時から保持する pidfd による同一性の保証（上記「同一性照合の前提」の恒久策）
//! - 記録 pid が入れ子の PID 1 でない起動経路（rootless の代役 init 等の中間プロセス）の pid1 特定

use std::fs;
use std::io::Read;
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use super::{ExecError, IsolationStage, ViolationReason, errno_to_code, status_threads};
use crate::cgroups::CgroupName;
use crate::sys::{self, NsFlag, SysError};
use crate::traits::types::ErrorCode;
use crate::traits::{CgroupPlacement, CgroupScope, ContainerId};

/// `/proc/<pid>/status`・`/proc/<pid>/cgroup` の読み取り上限（バイト）。通常は 2 KiB 前後で、無制限確保を
/// 避ける。上限を超える内容は切り詰めずにエラーにする（途中で切れた行を照合に使わない）。
const PROC_READ_LIMIT: u64 = 64 * 1024;

/// 期待 cgroup パスの最大バイト数（Linux の `PATH_MAX`）。
const CGROUP_PATH_MAX: usize = 4096;

/// 参加する namespace 種別（SUP-6。user namespace は含まない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum JoinNamespace {
    /// PID namespace（以後に fork した子にだけ効く）。
    Pid,
    /// mount namespace。
    Mount,
    /// UTS namespace。
    Uts,
    /// IPC namespace。
    Ipc,
    /// network namespace。
    Net,
}

impl JoinNamespace {
    /// SUP-6 が固定する参加対象 5 種。
    pub const SUP6_SET: [JoinNamespace; 5] = [
        JoinNamespace::Pid,
        JoinNamespace::Mount,
        JoinNamespace::Uts,
        JoinNamespace::Ipc,
        JoinNamespace::Net,
    ];

    fn flag(self) -> NsFlag {
        match self {
            Self::Pid => NsFlag::Pid,
            Self::Mount => NsFlag::Mount,
            Self::Uts => NsFlag::Uts,
            Self::Ipc => NsFlag::Ipc,
            Self::Net => NsFlag::Net,
        }
    }

    /// `/proc/<pid>/ns/` 配下のエントリ名。
    fn proc_name(self) -> &'static str {
        match self {
            Self::Pid => "pid",
            Self::Mount => "mnt",
            Self::Uts => "uts",
            Self::Ipc => "ipc",
            Self::Net => "net",
        }
    }
}

/// 検証済みの参加対象（pid1）。pidfd でプロセス同一性を固定している。
#[derive(Debug)]
pub struct Pid1Target {
    pid: NonZeroU32,
    pidfd: OwnedFd,
    /// `open` で照合した期待 cgroup パス。[`join_namespaces`] が参加の直前に再照合する。
    expected_cgroup_path: String,
}

impl Pid1Target {
    /// 対象の pid（呼び出し側の PID namespace から見た値）。
    pub fn pid(&self) -> NonZeroU32 {
        self.pid
    }

    /// `open` で照合した期待 cgroup 絶対パス（`exec::cgroup_join` が cgroup を開くために使う）。
    pub(super) fn expected_cgroup_path(&self) -> &str {
        &self.expected_cgroup_path
    }

    /// 対象の mount namespace の識別子（nsfs の `st_dev`・`st_ino`）。制限を exec の対象へ束縛するために
    /// `exec::reapply` が参加の前に記録し、参加後の自プロセスの識別子と照合する（SUP-6・SEC-1・TASK-163.4）。
    ///
    /// 読み取りの後に pidfd の未終了を確認し、読んだ識別子が pidfd の指すプロセスのものであることを保証する。
    pub(super) fn mnt_ns_identity(&self) -> Result<NsIdentity, ExecError> {
        let id = ns_identity(&format!("/proc/{}/ns/mnt", self.pid))
            .map_err(|e| target_proc_error(&e, "read target mount namespace"))?;
        ensure_not_exited(self, "refusing to bind restrictions to it")?;
        Ok(id)
    }

    /// 対象の PID namespace の識別子（nsfs の `st_dev`・`st_ino`）。参加後に子が入る PID namespace
    /// （`ns/pid_for_children`）との照合に使う（SUP-6・SEC-1・TASK-163.4）。読み取りの後に pidfd の未終了を確認する。
    pub(super) fn pid_ns_identity(&self) -> Result<NsIdentity, ExecError> {
        let id = ns_identity(&format!("/proc/{}/ns/pid", self.pid))
            .map_err(|e| target_proc_error(&e, "read target PID namespace"))?;
        ensure_not_exited(self, "refusing to bind restrictions to it")?;
        Ok(id)
    }

    /// 対象の `/proc/<pid>/limits` の内容（上限つきで読む）。コンテナの rlimit の記録上の出所が無いため、
    /// exec プロセスへ同じ値を適用する材料にする（SUP-6・SUP-12・TASK-163.4）。読み取りの後に pidfd の
    /// 未終了を確認する。
    pub(super) fn read_limits(&self) -> Result<String, ExecError> {
        let text = read_bounded(&format!("/proc/{}/limits", self.pid))
            .map_err(|e| target_proc_error(&e, "read target limits"))?;
        ensure_not_exited(self, "refusing to copy its limits")?;
        Ok(text)
    }

    /// `pid` を候補として pid1 を特定し、検証を通ったものだけを対象にする。
    ///
    /// 期待 cgroup パスは、記録のコンテナ ID と cgroup 配置から `<scope>/fc-<id>@<instance>` として
    /// ここで組み立てる（呼び出し側から文字列では受け取らない）。対象の所属 cgroup がこれと完全一致
    /// しなければ、pid が別コンテナに再利用されたものとして拒否する（SEC-1）。
    ///
    /// 手順は順序固定: pidfd で固定 → `NSpid` が直接入れ子の PID 1 → 期待 cgroup に属する →
    /// 自分と同じ pid / mnt namespace でない → pidfd が未終了。対象が前提を満たさなければ
    /// `FailedPrecondition`（違反記録つき）、存在しない pid・検証中に消えた対象は `NotFound`、cgroup 名を
    /// 作れない ID は `InvalidArgument`。
    pub fn open(
        pid: NonZeroU32,
        id: &ContainerId,
        placement: &CgroupPlacement,
    ) -> Result<Self, ExecError> {
        let name = CgroupName::for_instance(id, placement.instance()).map_err(|_| {
            ExecError::new(
                ErrorCode::InvalidArgument,
                IsolationStage::SetNs,
                "container id and instance do not form a valid cgroup name",
            )
        })?;
        Self::open_at(pid, container_cgroup_path(placement.scope(), &name))
    }

    /// 実機結合試験専用の入口: 期待 cgroup 絶対パスを呼び出し側から文字列で受け取る。
    ///
    /// `exec-test-support` feature を付けたビルドにだけ存在し、既定のビルド（リリース成果物を含む）の公開
    /// API には含まれない。コンテナ用 cgroup を作れない試験環境で成功経路を通すためのもので、期待値を
    /// 記録から導かないため「記録したコンテナのプロセスであること」（SEC-1）の照合にはならない。
    #[cfg(feature = "exec-test-support")]
    pub fn open_with_cgroup_path(
        pid: NonZeroU32,
        expected_cgroup_path: &str,
    ) -> Result<Self, ExecError> {
        Self::open_at(pid, expected_cgroup_path.to_owned())
    }

    /// [`Self::open`] の本体。期待 cgroup パスの出所を呼び出し側に委ねるため非公開にしている。
    fn open_at(pid: NonZeroU32, expected_cgroup_path: String) -> Result<Self, ExecError> {
        let stage = IsolationStage::SetNs;
        if !is_valid_cgroup_path(&expected_cgroup_path) {
            return Err(ExecError::new(
                ErrorCode::InvalidArgument,
                stage,
                "expected cgroup path must be an absolute, normalized, non-root cgroup path",
            ));
        }
        let pidfd = sys::pidfd_open(pid.get()).map_err(|e| setns_error(e, "pidfd_open"))?;
        let status = read_bounded(&format!("/proc/{pid}/status"))
            .map_err(|e| target_proc_error(&e, "read target status"))?;
        if !nspid_is_nested_pid1(&status) {
            return Err(ExecError::from_violation(
                ViolationReason::ExecTargetNotNestedPid1,
                None,
            ));
        }
        verify_cgroup_membership(pid, &expected_cgroup_path)?;
        let mut identities = Vec::with_capacity(CALLER_DISTINCT.len());
        for ns in CALLER_DISTINCT {
            let target = ns_identity(&format!("/proc/{pid}/ns/{}", ns.proc_name()))
                .map_err(|e| target_proc_error(&e, "read target namespace"))?;
            let own = ns_identity(&format!("/proc/self/ns/{}", ns.proc_name()))
                .map_err(|e| ExecError::from_io(&e, stage, "read own namespace"))?;
            identities.push((ns, target, own));
        }
        if let Some(reason) = shared_namespace_violation(&identities) {
            return Err(ExecError::from_violation(reason, None));
        }
        let target = Self {
            pid,
            pidfd,
            expected_cgroup_path,
        };
        // 終了後は pid が再利用され得るため、`/proc` の検証結果が pidfd の指すプロセスのものである
        // ことを、未終了の確認で保証する。
        ensure_not_exited(&target, "refusing to use it as the exec target")?;
        Ok(target)
    }
}

/// 呼び出し側と同じであってはならない namespace（対象の限定。モジュール doc「対象の限定」）。
const CALLER_DISTINCT: [JoinNamespace; 2] = [JoinNamespace::Pid, JoinNamespace::Mount];

/// namespace の識別子（nsfs の dev, ino）。
pub(super) type NsIdentity = (u64, u64);

/// `(種別, 対象の識別子, 呼び出し側の識別子)` の並びから、呼び出し側と同じ namespace があれば最初の 1 件の
/// 違反理由を返す（副作用の前に判定するテスト可能な純関数）。pid / mnt 以外の種別は判定対象にしない。
fn shared_namespace_violation(
    identities: &[(JoinNamespace, NsIdentity, NsIdentity)],
) -> Option<ViolationReason> {
    identities
        .iter()
        .find_map(|(ns, target, own)| match (target == own, ns) {
            (true, JoinNamespace::Pid) => Some(ViolationReason::ExecTargetSharesPidNamespace),
            (true, JoinNamespace::Mount) => Some(ViolationReason::ExecTargetSharesMountNamespace),
            _ => None,
        })
}

/// 委譲スコープ（`"/"` または `"/a/b"`）とコンテナ用 cgroup 名から、cgroup v2 ルート起点の絶対パスを作る。
/// cgroup のパスはカーネルが `/` 区切りで返す文字列で、OS のパス区切りとは無関係（Linux 専用モジュール）。
fn container_cgroup_path(scope: &CgroupScope, name: &CgroupName) -> String {
    let scope = scope.as_str();
    if scope == "/" {
        format!("/{}", name.as_str())
    } else {
        format!("{scope}/{}", name.as_str())
    }
}

/// 対象 `pid` の所属 cgroup（`/proc/<pid>/cgroup` の v2 行）が `expected` と完全一致することを確かめる。
///
/// 不一致は `FailedPrecondition`（違反記録 `ExecTargetCgroupMismatch`。対象に期待パスを載せる）。読み取りの
/// 結果が pidfd の指すプロセスのものであることは、呼び出し側がこの後に pidfd の未終了を確認することで
/// 保証する（終了していなければ pid は再利用されていない）。
fn verify_cgroup_membership(pid: NonZeroU32, expected: &str) -> Result<(), ExecError> {
    let cgroup = read_bounded(&format!("/proc/{pid}/cgroup"))
        .map_err(|e| target_proc_error(&e, "read target cgroup"))?;
    if !cgroup_path_matches(&cgroup, expected) {
        return Err(ExecError::from_violation(
            ViolationReason::ExecTargetCgroupMismatch,
            Some(Path::new(expected)),
        ));
    }
    Ok(())
}

/// pidfd の指すプロセスが終了済みなら `FailedPrecondition`（`what` はメッセージの末尾に付ける）。
/// 対象の終了は分離違反の試行ではないため、違反記録は付けない。
pub(super) fn ensure_not_exited(target: &Pid1Target, what: &str) -> Result<(), ExecError> {
    let exited = sys::poll_readable(target.pidfd.as_fd(), 0)
        .map_err(|e| setns_error(e, "poll target pidfd"))?;
    if exited {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::SetNs,
            format!("process {} has already exited; {what}", target.pid),
        ));
    }
    Ok(())
}

/// 参加の直前に、対象が `open` のときと同じ期待 cgroup に属していることを再照合する（SEC-1）。
///
/// `open` から参加までの間に対象が別の cgroup へ移されていれば `FailedPrecondition`。cgroup の読み取りの後に
/// pidfd の未終了を確認し、読んだ内容が pidfd の指すプロセスのものであることを保証する。
fn recheck_cgroup_membership(target: &Pid1Target) -> Result<(), ExecError> {
    verify_cgroup_membership(target.pid, &target.expected_cgroup_path)?;
    ensure_not_exited(target, "refusing to setns")
}

/// [`join_namespaces`] の成功結果（将来拡張できる構造）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NamespaceJoinReport {
    /// 参加した対象の pid（呼び出し側の PID namespace から見た値）。
    pub target_pid: NonZeroU32,
    /// 参加した namespace（[`JoinNamespace::SUP6_SET`] の順）。
    pub joined: Vec<JoinNamespace>,
}

/// 検証済みの対象 `target` の SUP-6 の 5 種（pid / mnt / uts / ipc / net）の namespace へ、1 回の
/// `setns(2)` で参加する。参加する集合は固定で、呼び出し側は部分集合を選べない。
///
/// 参加の直前に対象の終了と所属 cgroup（`open` で照合した期待パスとの完全一致）を再確認し、終了済み・
/// 別 cgroup へ移動済みなら `FailedPrecondition`。
/// 呼び出しスレッドの namespace を不可逆に変える。単一スレッドでなければ `FailedPrecondition`。
/// 契約全体はモジュール doc を参照（SUP-6・TASK-163.1）。
pub fn join_namespaces(target: &Pid1Target) -> Result<NamespaceJoinReport, ExecError> {
    let stage = IsolationStage::SetNs;
    // 検証（`open`）から参加までの間に対象が終了していないか、参加の直前に再確認する。
    ensure_not_exited(target, "refusing to setns")?;
    let own = read_bounded("/proc/self/status")
        .map_err(|e| ExecError::from_io(&e, stage, "read own status"))?;
    if status_threads(&own) != Some(1) {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            stage,
            "the caller is multi-threaded or its thread count is unknown; refusing to setns",
        ));
    }
    // 所属 cgroup の再照合は `setns` の直前に置く（残る窓を最小にする）。
    recheck_cgroup_membership(target)?;
    let flags = JoinNamespace::SUP6_SET.map(JoinNamespace::flag);
    sys::setns_pidfd(target.pidfd.as_fd(), &flags).map_err(|e| setns_error(e, "setns"))?;
    Ok(NamespaceJoinReport {
        target_pid: target.pid,
        joined: JoinNamespace::SUP6_SET.to_vec(),
    })
}

/// syscall 失敗を `SetNs` 段の `ExecError` にする。`ESRCH`（対象の終了）は `NotFound`。
fn setns_error(err: SysError, what: &str) -> ExecError {
    let mut e = ExecError::from_sys(err, IsolationStage::SetNs, what);
    e.code = if err == SysError::Os(sys::ESRCH) {
        ErrorCode::NotFound
    } else {
        errno_to_code(err)
    };
    e
}

/// 対象の `/proc/<pid>` 配下の読み取り失敗を `SetNs` 段の `ExecError` にする。
///
/// pidfd を開いた後に対象が終了・回収されると、`/proc/<pid>` のエントリが消えて `ENOENT`（開いた後の
/// 読み取りでは `ESRCH`）になる。これは内部障害ではなく対象の終了なので、`pidfd_open` / `setns` の
/// `ESRCH` と同じ `NotFound` に揃える。それ以外の errno は通常の分類に従う。
fn target_proc_error(err: &std::io::Error, what: &str) -> ExecError {
    let mut e = ExecError::from_io(err, IsolationStage::SetNs, what);
    if matches!(err.raw_os_error(), Some(n) if n == sys::ENOENT || n == sys::ESRCH) {
        e.code = ErrorCode::NotFound;
    }
    e
}

/// `/proc` のテキストを上限つきで読む（[`read_bounded_from`]）。
fn read_bounded(path: &str) -> std::io::Result<String> {
    read_bounded_from(fs::File::open(path)?, PROC_READ_LIMIT)
}

/// `limit` バイトまでのテキストを読む。`limit` を超える内容は切り詰めずに `InvalidData` で失敗させる
/// （途中で切れた行が照合に使われることを防ぐ。無制限確保もしない）。
pub(super) fn read_bounded_from(reader: impl Read, limit: u64) -> std::io::Result<String> {
    let mut buf = String::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_string(&mut buf)?;
    if u64::try_from(buf.len()).map_or(true, |n| n > limit) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "proc file exceeds the read limit",
        ));
    }
    Ok(buf)
}

/// namespace の識別子（nsfs の dev, ino）。
fn ns_identity(path: &str) -> std::io::Result<NsIdentity> {
    let m = fs::metadata(path)?;
    Ok((m.dev(), m.ino()))
}

/// `NSpid:` の要素がちょうど 2 で、末尾（最も内側の PID namespace での PID）が 1 か。
///
/// 2 要素は「読み取りに使う procfs の PID namespace に直接入れ子になった namespace」を意味する。3 要素以上
/// （コンテナの中でさらに作られた PID namespace の PID 1）は対象にしない。行なし・非数値は fail-closed で
/// `false`。
fn nspid_is_nested_pid1(status: &str) -> bool {
    let Some(rest) = status.lines().find_map(|l| l.strip_prefix("NSpid:")) else {
        return false;
    };
    let mut parsed = Vec::new();
    for tok in rest.split_whitespace() {
        match tok.parse::<u32>() {
            Ok(v) => parsed.push(v),
            Err(_) => return false,
        }
    }
    parsed.len() == 2 && parsed.last() == Some(&1)
}

/// 期待 cgroup パスの形式検証: `/` 始まりの絶対パスで、ルート（`/`）でなく、各要素が空 / `.` / `..` で
/// なく、NUL・改行を含まず、[`CGROUP_PATH_MAX`] 以下。ルートを認めないのは、コンテナ用 cgroup が必ず
/// 委譲スコープの子であり、ルート所属の任意プロセスを対象にさせないため。
fn is_valid_cgroup_path(path: &str) -> bool {
    if path.len() > CGROUP_PATH_MAX || path.contains(['\0', '\n']) {
        return false;
    }
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

/// `/proc/<pid>/cgroup` の cgroup v2 行（`0::<path>`）のパスが `expected` と全体で完全一致するか。
///
/// 内容が改行で終わらない（最終行が途中で切れている可能性がある）・v2 行なし・v2 行が複数・不一致は
/// fail-closed で `false`。部分一致（接頭辞・接尾辞・途中の要素）は認めない。削除済み cgroup に残る
/// プロセスはカーネルが ` (deleted)` を付けるため一致しない。
pub(super) fn cgroup_path_matches(cgroup: &str, expected: &str) -> bool {
    if !cgroup.ends_with('\n') {
        return false;
    }
    let mut v2 = cgroup.lines().filter_map(|l| l.strip_prefix("0::"));
    match (v2.next(), v2.next()) {
        (Some(path), None) => path == expected,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::ViolationKind;
    use crate::traits::StateRevision;

    fn me() -> NonZeroU32 {
        NonZeroU32::new(std::process::id()).unwrap()
    }

    fn placement(scope: &str, instance: u64) -> CgroupPlacement {
        CgroupPlacement::new(
            CgroupScope::new(scope).unwrap(),
            StateRevision::from_raw(instance),
        )
    }

    /// 自プロセスの所属 cgroup（v2 行のパス）。
    fn own_cgroup_path() -> String {
        read_bounded("/proc/self/cgroup")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .expect("cgroup v2 line")
            .to_owned()
    }

    /// SUP-6・SEC-1: cgroup は v2 行のパス全体が完全一致したときだけ一致する。別コンテナ（別 instance・
    /// 別 ID・別スコープ）、配下の子 cgroup、他コンテナ配下に作られた同名の子 cgroup、削除済み、v1 行は
    /// すべて不一致（pid 再利用と偽装の拒否）。
    #[test]
    fn sup6_cgroup_path_exact_match() {
        let want = "/user.slice/x.scope/fc-c1@7";
        assert!(cgroup_path_matches(
            "0::/user.slice/x.scope/fc-c1@7\n",
            want
        ));
        for other in [
            "0::/user.slice/x.scope/fc-c1@8\n",
            "0::/user.slice/x.scope/fc-c2@7\n",
            "0::/user.slice/y.scope/fc-c1@7\n",
            "0::/user.slice/x.scope/fc-c1@7/nested\n",
            "0::/user.slice/x.scope/fc-c2@9/fc-c1@7\n",
            "0::/user.slice/x.scope/fc-c2@9/user.slice/x.scope/fc-c1@7\n",
            "0::/user.slice/x.scope\n",
            "0::/user.slice/x.scope/fc-c1@7 (deleted)\n",
            "0::/user.slice/x.scope/fc-c1@7/\n",
            "1:name=x:/user.slice/x.scope/fc-c1@7\n",
            "0::/a\n0::/user.slice/x.scope/fc-c1@7\n",
            "0::/user.slice/x.scope/fc-c1@7\n0::/user.slice/x.scope/fc-c1@7\n",
            "",
        ] {
            assert!(!cgroup_path_matches(other, want), "{other:?}");
        }
    }

    /// SUP-6・SEC-1: 改行で終わらない内容（最終行が途中で切れた可能性）は、切れた位置までが期待パスと
    /// 一致していても不一致にする。本来の所属は `/user.slice/x.scope/fc-c1@77` かもしれない。
    #[test]
    fn sup6_cgroup_path_rejects_unterminated_last_line() {
        let want = "/user.slice/x.scope/fc-c1@7";
        assert!(!cgroup_path_matches("0::/user.slice/x.scope/fc-c1@7", want));
        assert!(!cgroup_path_matches(
            "1:name=x:/a\n0::/user.slice/x.scope/fc-c1@7",
            want
        ));
        assert!(cgroup_path_matches(
            "1:name=x:/a\n0::/user.slice/x.scope/fc-c1@7\n",
            want
        ));
    }

    /// SUP-6・SEC-1: 上限ちょうどまでは読み、上限を 1 バイトでも超える内容は切り詰めずに InvalidData で
    /// 失敗させる（切り詰めた末尾行を照合に使わない）。
    #[test]
    fn sup6_read_bounded_rejects_content_over_limit() {
        assert_eq!(PROC_READ_LIMIT, 64 * 1024);
        assert_eq!(read_bounded_from(&b"0::/a\n"[..], 6).unwrap(), "0::/a\n");
        let err = read_bounded_from(&b"0::/a\n"[..], 5).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "proc file exceeds the read limit");
        // 上限で切ると期待パスと一致してしまう内容（本来は `fc-c1@77`）も、照合に進まず失敗する。
        let content = b"0::/s/fc-c1@77\n";
        let cut = "0::/s/fc-c1@7".len() as u64;
        let err = read_bounded_from(&content[..], cut).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let err = target_proc_error(&err, "read target cgroup");
        assert_eq!(err.code, ErrorCode::Internal);
        assert_eq!(err.violation, None);
    }

    /// SUP-6: 期待 cgroup パスの形式検証（絶対・正規形・ルート以外）。
    #[test]
    fn sup6_cgroup_path_validation() {
        for ok in ["/fc-c1@7", "/user.slice/x.scope/fc-c1@7"] {
            assert!(is_valid_cgroup_path(ok), "{ok}");
        }
        let too_long = format!("/{}", "a".repeat(CGROUP_PATH_MAX));
        for bad in [
            "",
            "/",
            "fc-c1@7",
            "a/b",
            "/a//b",
            "/a/",
            "/a/./b",
            "/a/../b",
            "/..",
            "/a\0b",
            "/a\n0::/b",
            too_long.as_str(),
        ] {
            assert!(!is_valid_cgroup_path(bad), "{bad:?}");
        }
    }

    /// SUP-6・SEC-1: 期待 cgroup パスは記録の委譲スコープと `fc-<id>@<instance>` の連結（ルートは `/` を
    /// 重ねない）。
    #[test]
    fn sup6_container_cgroup_path_concrete_values() {
        let id = ContainerId::new("c1").unwrap();
        let name = CgroupName::for_instance(&id, StateRevision::from_raw(7)).unwrap();
        assert_eq!(
            container_cgroup_path(&CgroupScope::new("/user.slice/x.scope").unwrap(), &name),
            "/user.slice/x.scope/fc-c1@7"
        );
        assert_eq!(
            container_cgroup_path(&CgroupScope::new("/").unwrap(), &name),
            "/fc-c1@7"
        );
    }

    /// SUP-6: 期待 cgroup パスが不正なら、対象へ触れる前に InvalidArgument（違反記録なし）。
    #[test]
    fn sup6_open_rejects_invalid_cgroup_path() {
        for bad in ["", "/", "fc-c1@7", "/a/../b", "/a//b"] {
            let err = Pid1Target::open_at(me(), bad.to_owned()).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{bad}");
            assert_eq!(err.stage, IsolationStage::SetNs);
            assert_eq!(err.violation, None);
        }
    }

    /// SUP-6: 検証中に対象が消えた（`/proc/<pid>` の ENOENT / ESRCH）場合は Internal ではなく NotFound。
    /// それ以外の errno は通常の分類（EACCES は PermissionDenied）。システムエラーなので違反記録は付かない。
    #[test]
    fn sup6_target_proc_error_maps_vanished_target_to_not_found() {
        for errno in [sys::ENOENT, sys::ESRCH] {
            let io = std::io::Error::from_raw_os_error(errno);
            let err = target_proc_error(&io, "read target status");
            assert_eq!(err.code, ErrorCode::NotFound, "{errno}");
            assert_eq!(err.stage, IsolationStage::SetNs);
            assert_eq!(err.violation, None);
            assert!(
                err.message.starts_with("read target status failed: "),
                "{}",
                err.message
            );
        }
        let io = std::io::Error::from_raw_os_error(sys::EACCES);
        let err = target_proc_error(&io, "read target cgroup");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    /// SUP-6: NSpid の解析。直接入れ子の PID 1（ちょうど 2 要素・末尾 1）のみ許可し、コンテナの中で
    /// さらに作られた PID namespace の PID 1（3 要素以上）は拒否する。
    #[test]
    fn sup6_nspid_parse() {
        assert!(nspid_is_nested_pid1("Name:\tx\nNSpid:\t4242\t1\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t4242\t7\t1\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t4242\t7\t3\t1\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t4242\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t1\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t4242\t7\n"));
        assert!(!nspid_is_nested_pid1("Name:\tx\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t4242\tabc\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t\n"));
    }

    /// SUP-6・SEC-4: 自プロセスは入れ子の PID 1 でないため、違反記録つきで拒否される（記録の型から入る
    /// 公開の入口）。
    #[test]
    fn sup6_open_rejects_self_with_violation() {
        let id = ContainerId::new("x").unwrap();
        let err = Pid1Target::open(me(), &id, &placement("/", 1)).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::SetNs);
        assert_eq!(
            err.message,
            "the exec target is not PID 1 of a directly nested PID namespace"
        );
        let v = err.violation.expect("violation");
        assert_eq!(v.kind, ViolationKind::ExecTarget);
        assert_eq!(v.reason, ViolationReason::ExecTargetNotNestedPid1);
        assert_eq!(v.reason.as_str(), "exec_target_not_nested_pid1");
        assert_eq!(v.behavior_id, "SUP-6");
        assert_eq!(v.subject, None);
    }

    /// SUP-6: PID_MAX_LIMIT 超の pid は存在しない（NotFound。違反記録なし）。
    #[test]
    fn sup6_open_missing_pid_is_not_found() {
        let id = ContainerId::new("x").unwrap();
        let err = Pid1Target::open(NonZeroU32::new(4_194_305).unwrap(), &id, &placement("/", 1))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert_eq!(err.stage, IsolationStage::SetNs);
        assert_eq!(err.violation, None);
    }

    /// SUP-6・SEC-4: 呼び出し側と同じ pid / mnt namespace の対象は、種別ごとの違反理由で拒否する
    /// （pid を先に判定）。別の namespace なら違反なし。uts 等は判定対象にしない。
    #[test]
    fn sup6_shared_namespace_violation_concrete_values() {
        let a: NsIdentity = (4, 4_026_531_836);
        let b: NsIdentity = (4, 4_026_532_500);
        use JoinNamespace::{Mount, Pid, Uts};
        assert_eq!(
            shared_namespace_violation(&[(Pid, b, a), (Mount, b, a)]),
            None
        );
        assert_eq!(
            shared_namespace_violation(&[(Pid, a, a), (Mount, b, a)]),
            Some(ViolationReason::ExecTargetSharesPidNamespace)
        );
        assert_eq!(
            shared_namespace_violation(&[(Pid, b, a), (Mount, a, a)]),
            Some(ViolationReason::ExecTargetSharesMountNamespace)
        );
        assert_eq!(
            shared_namespace_violation(&[(Pid, a, a), (Mount, a, a)]),
            Some(ViolationReason::ExecTargetSharesPidNamespace)
        );
        // 同じ inode 番号でも dev が違えば別の namespace。
        assert_eq!(
            shared_namespace_violation(&[(Pid, (5, a.1), a), (Mount, b, a)]),
            None
        );
        assert_eq!(shared_namespace_violation(&[(Uts, a, a)]), None);
        assert_eq!(shared_namespace_violation(&[]), None);
        let err = ExecError::from_violation(ViolationReason::ExecTargetSharesMountNamespace, None);
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::SetNs);
        assert_eq!(
            err.message,
            "the exec target shares the mount namespace with the caller; refusing to join"
        );
    }

    /// SUP-6・SEC-4: 自プロセス同士の識別子は pid / mnt とも一致し、同一 namespace の拒否に届く
    /// （実際の `/proc/self/ns` の値での照合）。
    #[test]
    fn sup6_shared_namespace_violation_with_real_identities() {
        let mut identities = Vec::new();
        for ns in CALLER_DISTINCT {
            let own = ns_identity(&format!("/proc/self/ns/{}", ns.proc_name())).unwrap();
            let target = ns_identity(&format!("/proc/{}/ns/{}", me(), ns.proc_name())).unwrap();
            identities.push((ns, target, own));
        }
        assert_eq!(
            shared_namespace_violation(&identities),
            Some(ViolationReason::ExecTargetSharesPidNamespace)
        );
        assert_eq!(
            shared_namespace_violation(&identities[1..]),
            Some(ViolationReason::ExecTargetSharesMountNamespace)
        );
    }

    /// SUP-6: マルチスレッドの呼び出し側は FailedPrecondition（呼び出し文脈の誤りで、違反記録なし）。
    #[test]
    fn sup6_join_rejects_multi_threaded_caller() {
        let target = Pid1Target {
            pid: me(),
            pidfd: sys::pidfd_open(me().get()).unwrap(),
            expected_cgroup_path: "/fc-x@1".to_owned(),
        };
        // 別スレッドを生かしたまま呼び、Threads が 2 以上になる状態を作る。
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let helper = std::thread::spawn(move || {
            let _ = rx.recv();
        });
        let err = join_namespaces(&target).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::SetNs);
        assert_eq!(
            err.message,
            "the caller is multi-threaded or its thread count is unknown; refusing to setns"
        );
        assert_eq!(err.violation, None);
        let _ = tx.send(());
        let _ = helper.join();
    }

    /// SUP-6・SEC-1・SEC-4: 参加直前の再照合は、対象の現在の所属 cgroup が `open` 時の期待パスと完全一致する
    /// ときだけ通る。別の cgroup（移動後を想定）なら違反記録つきの FailedPrecondition で、対象には期待パスが
    /// 載る。
    #[test]
    fn sup6_recheck_cgroup_membership_rejects_moved_target() {
        let own_path = own_cgroup_path();
        let target = |path: &str| Pid1Target {
            pid: me(),
            pidfd: sys::pidfd_open(me().get()).unwrap(),
            expected_cgroup_path: path.to_owned(),
        };
        assert_eq!(
            recheck_cgroup_membership(&target(&own_path)).map_err(|e| e.code),
            Ok(())
        );
        let moved = format!("{}/fc-x@1", own_path.trim_end_matches('/'));
        let err = recheck_cgroup_membership(&target(&moved)).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::SetNs);
        assert_eq!(
            err.message,
            "the exec target does not belong to the recorded container cgroup"
        );
        let v = err.violation.expect("violation");
        assert_eq!(v.kind, ViolationKind::ExecTarget);
        assert_eq!(v.reason, ViolationReason::ExecTargetCgroupMismatch);
        assert_eq!(v.behavior_id, "SEC-1");
        assert_eq!(v.subject.as_ref().map(|s| s.as_str()), Some(moved.as_str()));
        assert_eq!(v.mount_audit_event(), None);
    }

    /// SEC-4: cgroup 不一致の違反記録に載せる期待パスは、既存のエスケープ（制御文字・`\\`）と切り詰め
    /// （256 文字）を通る。
    #[test]
    fn sec4_cgroup_mismatch_subject_is_escaped_and_bounded() {
        let err = ExecError::from_violation(
            ViolationReason::ExecTargetCgroupMismatch,
            Some(Path::new("/s/fc-a\u{1b}[31m\\b@1")),
        );
        let v = err.violation.expect("violation");
        let s = v.subject.expect("subject");
        assert_eq!(s.as_str(), "/s/fc-a\\u{1b}[31m\\\\b@1");
        assert!(!s.is_truncated());
        let long = format!("/{}", "a".repeat(1000));
        let err = ExecError::from_violation(
            ViolationReason::ExecTargetCgroupMismatch,
            Some(Path::new(&long)),
        );
        let s = err.violation.expect("violation").subject.expect("subject");
        assert_eq!(s.as_str().chars().count(), 256);
        assert!(s.is_truncated());
    }

    /// SUP-6: 検証後に終了した対象への参加は、setns の前に FailedPrecondition で拒否される（違反記録なし）。
    #[test]
    fn sup6_join_rejects_exited_target() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        let pidfd = sys::pidfd_open(pid).unwrap();
        child.wait().unwrap();
        let target = Pid1Target {
            pid: NonZeroU32::new(pid).unwrap(),
            pidfd,
            expected_cgroup_path: "/fc-x@1".to_owned(),
        };
        let err = join_namespaces(&target).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message,
            format!("process {pid} has already exited; refusing to setns")
        );
        assert_eq!(err.violation, None);
    }
}
